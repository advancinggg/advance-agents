//! /dev Phase-2 Step-1 (reply delivery) — POST /msg ↔ dispatch reply correlation.
//!
//! [`ReplyRegistry`] is a per-process correlation registry (a `oneshot` keyed by
//! agent id) shared between the daemon's `POST /msg` handler and the agent-loop's
//! action dispatcher. [`ReplyRouterSink`] is the production [`OutboundActionSink`]
//! the composition root wires into `build_agent_loop`: when the serving loop's
//! (`serve`) turn dispatches the guest's validated actions, the sink (1) prints a
//! control-char-sanitized `advance: agent reply: <text>` to the daemon stdout and
//! (2) fulfils the oneshot so the awaiting `POST /msg` caller receives the model's
//! answer in the HTTP body.
//!
//! Interim scope (MODULE-006 §3.6 / §3.8 (i), MODULE-001 §3.6): the reply is the
//! FIRST action's raw payload bytes (payload-kind discriminator is future work);
//! correlation is keyed by agent id (the daemon enforces one in-flight POST per
//! turn via the listener's `in_flight` guard — the serving loop processes
//! messages serially, and Phase-2 Step-2's `WatchTurnObserver` clears the guard
//! at each turn boundary); the real channel-adapter
//! outbound (notify-channel `send-raw`, SYS-AC-001) is Step-3.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard};

use tokio::sync::oneshot;

use advance_messaging::{AgentAction, OutboundActionSink};
use advance_scheduler::TurnOutcome;
use advance_shared_types::mailbox::{DispatchError, Message};
use advance_shared_types::outbound::DeliveryReport;
use advance_shared_types::traits::{
    LlmDeltaEvent, LlmDeltaFrame, LlmDeltaSink, LlmDeltaUsage, LlmTerminalReason,
};

use crate::api::log_keys;
use crate::compose_log::LogHandle;

/// Upper bound on the per-turn stdout reply preview. Untrusted model output can
/// be up to `MAX_BATCH_SIZE` (128) actions × `MAX_PAYLOAD_BYTES` (1 MiB) = ~128
/// MiB after the validator; printing all of it synchronously would stall the
/// daemon's current-thread runtime on a slow/undrained stdout. The reply that
/// reaches the `POST /msg` caller is unaffected (the oneshot is fulfilled with
/// the full first-action bytes BEFORE this bounded preview is printed).
const STDOUT_PREVIEW_BYTES: usize = 4096;

/// Reply value carried by a [`ReplyRegistry`] oneshot: `Some(bytes)` when the
/// turn produced at least one action, `None` when it produced none.
type ReplySlot = oneshot::Sender<Option<Vec<u8>>>;

/// The most model calls one message's stream follows; a later call of the same turn is
/// published on its own stream.
const MAX_CALLS_PER_MESSAGE_STREAM: usize = 1024;

/// Stream keys of calls whose message stream has ended, remembered so that what they still
/// publish (a turn-end reap's `Terminal`, say) is dropped instead of reaching the hub. It holds
/// every call of the longest message stream twice over, so one stream's end never forgets
/// its own calls.
const MAX_RETIRED_CALL_KEYS: usize = 2 * MAX_CALLS_PER_MESSAGE_STREAM;

/// The most Client API messages waiting for their turn per agent; past it the oldest is
/// forgotten (its turn, should it still run, then publishes its calls on their own streams).
const MAX_PENDING_MESSAGES_PER_AGENT: usize = 256;

/// The text between the replies of two model calls of one message's stream.
const CALL_SEPARATOR: &str = "\n\n";

/// The most text one delta of a stream of a message's own carries: its reply goes in pieces
/// of at most this, so the hub keeps what fits its window and counts the rest dropped, as it
/// does for a model call's deltas, instead of dropping a large reply whole. The hub holds back
/// a tail that could begin a secret, in whole deltas, until the stream ends (MODULE-020-T24-h);
/// this stream's `Terminal` is complete, so when the hub took every piece and blocked or
/// redacted none, its end-of-stream sweep then releases that tail unless it completes a
/// secret. A reply past the window keeps it held: the hub dropped a piece.
const OWN_STREAM_DELTA_BYTES: usize = 16 * 1024;

/// `text` in pieces of at most `max` bytes (at least one char each), cut at char boundaries.
fn pieces(text: &str, max: usize) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = text;
    while !rest.is_empty() {
        let mut end = max.min(rest.len());
        while !rest.is_char_boundary(end) {
            end -= 1;
        }
        if end == 0 {
            end = rest.chars().next().map_or(rest.len(), char::len_utf8);
        }
        let (piece, tail) = rest.split_at(end);
        out.push(piece);
        rest = tail;
    }
    out
}

/// One model call of the turn that executes a Client API message.
struct MergedCall {
    /// Where the call's delta `seq` 0 lands on the message's stream.
    base: u64,
    /// The base of the call that began after this one: a delta of this call landing there
    /// or later is dropped (it would land where the later call's text is). One landing
    /// below it is routed to its own place (where the hub takes it, or counts it dropped
    /// when its release floor has passed it).
    limit: Option<u64>,
    /// The call has published text: its next delta is not set apart from the earlier
    /// calls' text again.
    seen_text: bool,
    /// The call's own `Terminal`, once published: its reason and settled usage.
    terminal: Option<(LlmTerminalReason, Option<LlmDeltaUsage>)>,
    /// That `Terminal` was complete: the call published its text whole (a buffered
    /// `generate` call whose text went out uncut).
    whole: bool,
}

/// The stream of one Client API message: every model call of the turn that executes it, on
/// the stream key of the turn's first call (the key its status names). The first call's
/// frames pass as they are; a later call's deltas follow on the same key, its text set
/// apart from the earlier text by a blank line; no call's own `Terminal` reaches the hub.
/// The stream's one `Terminal` is published when the turn ends.
struct MessageStream {
    message_id: String,
    /// The agent id the turn's start named: the agent of a stream of the message's own,
    /// when the turn opens none.
    turn_agent: Arc<str>,
    /// The agent id the first call's `Begin` carried (the hub's per-agent bookkeeping).
    agent_id: Option<Arc<str>>,
    /// The stream key of the turn's first call; `None` before it.
    key: Option<Arc<str>>,
    /// The next seq of the message's stream.
    next_seq: u64,
    calls: HashMap<Arc<str>, MergedCall>,
    /// The call that began last.
    latest: Option<Arc<str>>,
    /// The stream shows text already.
    has_text: bool,
    /// The registry dropped text of a call: a delta that landed at or past its limit.
    lost_text: bool,
}

impl MessageStream {
    fn new(message_id: &str, turn_agent: &str) -> Self {
        Self {
            message_id: message_id.to_string(),
            turn_agent: Arc::from(turn_agent),
            agent_id: None,
            key: None,
            next_seq: 0,
            calls: HashMap::new(),
            latest: None,
            has_text: false,
            lost_text: false,
        }
    }

    /// The `Terminal` that ends the stream at the end of its turn: the reason of the call
    /// that began last, and the sum of the calls' settled usage. A call still open (its own
    /// terminal not yet published) ends it `Reaped`, without usage; so does a call that
    /// settled without usage leave the sum out. `None` when no call began.
    fn terminal(&self) -> Option<LlmDeltaEvent> {
        let key = self.key.clone()?;
        let agent_id = self.agent_id.clone()?;
        let settled: Option<Vec<(LlmTerminalReason, Option<LlmDeltaUsage>)>> =
            self.calls.values().map(|call| call.terminal).collect();
        let (reason, usage) = match settled {
            Some(terminals) => {
                let reason = self
                    .latest
                    .as_ref()
                    .and_then(|latest| self.calls.get(latest))
                    .and_then(|call| call.terminal)
                    .map_or(LlmTerminalReason::Completed, |(reason, _)| reason);
                let usage = terminals.iter().try_fold(
                    LlmDeltaUsage {
                        input_tokens: 0,
                        output_tokens: 0,
                        cost_usd: 0.0,
                    },
                    |sum, &(_, usage)| {
                        usage.map(|usage| LlmDeltaUsage {
                            input_tokens: sum.input_tokens.saturating_add(usage.input_tokens),
                            output_tokens: sum.output_tokens.saturating_add(usage.output_tokens),
                            cost_usd: sum.cost_usd + usage.cost_usd,
                        })
                    },
                );
                (reason, usage)
            }
            None => (LlmTerminalReason::Reaped, None),
        };
        // Complete when the stream's text is whole: every call that put text on it ended with
        // a complete terminal of its own (a buffered `generate` call whose text went out
        // uncut), and the registry dropped none of it. Every delta forwarded has a seq below
        // `next_seq`, and the stream's calls are retired with it, so nothing more is forwarded
        // to its key. (The one exception: the stream shares its first call's key, and a frame
        // of that call that comes once `MAX_RETIRED_CALL_KEYS` later keys have pushed it out
        // of the retired set reaches the hub as it came. The hub drops such a delta at or past
        // this seq, and ignores it on a seq it took. On a seq it dropped, the hub may take it,
        // and then scans it in order with the text around it.) A live `stream` call
        // never ends complete, nor does a call still open: a stream that either of them put
        // text on ends as before, its held tail kept back.
        let complete = !self.lost_text
            && self
                .calls
                .values()
                .all(|call| !call.seen_text || call.whole);
        Some(LlmDeltaEvent {
            agent_id,
            stream_key: key,
            frame: LlmDeltaFrame::Terminal {
                seq: self.next_seq,
                reason,
                usage,
                complete,
            },
        })
    }

    /// The frames of a stream of the message's own on the fresh key `key`, for a turn that
    /// opened no model stream: its `Begin`, the turn's dispatched reply (the bytes
    /// `POST /msg` answers with, read as UTF-8) as its deltas when `end` has one, in pieces of
    /// at most [`OWN_STREAM_DELTA_BYTES`], and its `Terminal`, without usage.
    fn unopened(&self, key: &Arc<str>, end: StreamEnd<'_>) -> Vec<LlmDeltaEvent> {
        let event = |frame| LlmDeltaEvent {
            agent_id: Arc::clone(&self.turn_agent),
            stream_key: Arc::clone(key),
            frame,
        };
        let (reason, text) = match end {
            StreamEnd::Replied(reply) => {
                (LlmTerminalReason::Completed, String::from_utf8_lossy(reply))
            }
            StreamEnd::Ended(reason) => (reason, "".into()),
        };
        let mut frames = vec![event(LlmDeltaFrame::Begin {
            run_id: None,
            task_id: None,
        })];
        let mut seq = 0u64;
        for piece in pieces(&text, OWN_STREAM_DELTA_BYTES) {
            frames.push(event(LlmDeltaFrame::Delta {
                seq,
                text: piece.to_string(),
            }));
            seq += 1;
        }
        // Complete: the stream's frames are published together, and nothing follows.
        frames.push(event(LlmDeltaFrame::Terminal {
            seq,
            reason,
            usage: None,
            complete: true,
        }));
        frames
    }
}

/// How a message stream ends when the turn opened no model stream of its own (one its calls
/// opened ends with [`MessageStream::terminal`] either way).
#[derive(Clone, Copy)]
enum StreamEnd<'a> {
    /// The turn dispatched this reply.
    Replied(&'a [u8]),
    /// The turn ended without a reply, or a later turn found its end unreported: the
    /// reason its stream ends with.
    Ended(LlmTerminalReason),
}

/// What the hub receives for one frame of a model call.
enum Routed {
    /// Not a call of a Client API message's turn: the frame as it came.
    AsIs,
    /// The first call of a message's turn: its `Begin` as it came, and the message now has
    /// this stream key.
    Opens(String),
    /// A call of a message's turn: this frame, on the message's stream key.
    Merged(LlmDeltaEvent),
    /// Nothing: a later call's `Begin`, a call's own `Terminal`, an earlier call's delta
    /// landing on a later call's seqs, or a frame of a call whose message stream has ended.
    Nothing,
}

/// The message streams of the agents whose running turn executes a Client API message.
#[derive(Default)]
struct MessageStreams {
    by_slot: HashMap<String, MessageStream>,
    /// The agent slot of every call key of those streams.
    slot_of_call: HashMap<Arc<str>, String>,
    /// Keys of calls whose message stream has ended, oldest first.
    retired: VecDeque<Arc<str>>,
    retired_set: HashSet<Arc<str>>,
}

impl MessageStreams {
    /// The stream of `slot`'s turn, removed with its calls (now retired).
    fn take(&mut self, slot: &str) -> Option<MessageStream> {
        let stream = self.by_slot.remove(slot)?;
        for key in stream.calls.keys() {
            self.slot_of_call.remove(key);
            if self.retired_set.insert(Arc::clone(key)) {
                self.retired.push_back(Arc::clone(key));
            }
        }
        while self.retired.len() > MAX_RETIRED_CALL_KEYS {
            if let Some(old) = self.retired.pop_front() {
                self.retired_set.remove(&old);
            }
        }
        Some(stream)
    }

    fn route(&mut self, slot: &str, event: &LlmDeltaEvent) -> Routed {
        if self.retired_set.contains(&event.stream_key) {
            return Routed::Nothing;
        }
        match &event.frame {
            LlmDeltaFrame::Begin { .. } => {
                let Some(stream) = self.by_slot.get_mut(slot) else {
                    return Routed::AsIs;
                };
                if stream.calls.contains_key(&event.stream_key) {
                    return Routed::Nothing;
                }
                if stream.calls.len() >= MAX_CALLS_PER_MESSAGE_STREAM {
                    return Routed::AsIs;
                }
                let base = if stream.key.is_none() {
                    0
                } else {
                    stream.next_seq
                };
                for call in stream.calls.values_mut() {
                    call.limit.get_or_insert(base);
                }
                let opens = stream.key.is_none();
                stream.calls.insert(
                    Arc::clone(&event.stream_key),
                    MergedCall {
                        base,
                        limit: None,
                        seen_text: false,
                        terminal: None,
                        whole: false,
                    },
                );
                stream.latest = Some(Arc::clone(&event.stream_key));
                self.slot_of_call
                    .insert(Arc::clone(&event.stream_key), slot.to_string());
                if opens {
                    stream.key = Some(Arc::clone(&event.stream_key));
                    stream.agent_id = Some(Arc::clone(&event.agent_id));
                    Routed::Opens(stream.message_id.clone())
                } else {
                    Routed::Nothing
                }
            }
            LlmDeltaFrame::Delta { seq, text } => {
                let Some(stream) = self
                    .slot_of_call
                    .get(&event.stream_key)
                    .and_then(|slot| self.by_slot.get_mut(slot))
                else {
                    return Routed::AsIs;
                };
                let (Some(key), Some(agent_id)) = (stream.key.clone(), stream.agent_id.clone())
                else {
                    return Routed::Nothing;
                };
                let has_text = stream.has_text;
                let Some(call) = stream.calls.get_mut(&event.stream_key) else {
                    return Routed::Nothing;
                };
                let at = call.base.saturating_add(*seq);
                if call.limit.is_some_and(|limit| at >= limit) {
                    // The call's text is cut: the stream does not end complete.
                    if !text.is_empty() {
                        stream.lost_text = true;
                    }
                    return Routed::Nothing;
                }
                let text = if !text.is_empty() && !call.seen_text {
                    call.seen_text = true;
                    if has_text {
                        format!("{CALL_SEPARATOR}{text}")
                    } else {
                        text.clone()
                    }
                } else {
                    text.clone()
                };
                // The hub's rules apply to the stream as to any other. Text no reader has
                // read yet is kept up to its window; a delta past it is dropped and counted
                // in the pages' `dropped_count`, which tells a later reader its text is not
                // whole. Its leak scan blocks text it will not release, one that holds a
                // secret or a hold or scan past its bounds (`rejected_count`), redacts some
                // (`redacted_count`), and holds back a tail that could begin a secret until the
                // stream's `Terminal` has come, complete, and the hub has taken every seq before
                // it: its end-of-stream sweep then releases that tail unless it completes a
                // secret (MODULE-020-T24-h). A stream whose text the hub or the registry dropped,
                // whose text the hub blocked or redacted before that tail, or that a live call put
                // text on, keeps that tail held. Apart from these, the
                // registry's own drop above and the call limit, a reader that keeps up with the
                // stream reads all of its text.
                if !text.trim().is_empty() {
                    stream.has_text = true;
                }
                stream.next_seq = stream.next_seq.max(at.saturating_add(1));
                Routed::Merged(LlmDeltaEvent {
                    agent_id,
                    stream_key: key,
                    frame: LlmDeltaFrame::Delta { seq: at, text },
                })
            }
            LlmDeltaFrame::Terminal {
                reason,
                usage,
                complete,
                ..
            } => {
                let Some(call) = self
                    .slot_of_call
                    .get(&event.stream_key)
                    .and_then(|slot| self.by_slot.get_mut(slot))
                    .and_then(|stream| stream.calls.get_mut(&event.stream_key))
                else {
                    return Routed::AsIs;
                };
                if call.terminal.is_none() {
                    call.terminal = Some((*reason, *usage));
                    call.whole = *complete;
                }
                Routed::Nothing
            }
        }
    }
}

/// A delta sink that keeps nothing: what a [`ReplyRegistry`] without an attached hub
/// publishes.
struct NoDeltaSink;

impl LlmDeltaSink for NoDeltaSink {
    fn is_wired(&self) -> bool {
        false
    }

    fn publish(&self, _event: LlmDeltaEvent) {}
}

/// The kind of an agent's last failed model call while one of its Client API
/// messages is in flight; it becomes a failure class only if the turn then
/// ends without a reply ([`ReplyRegistry::note_turn_end`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ModelFailure {
    /// The call returned the subscription-usage class.
    UsageLimit,
    /// The call returned any other model error.
    Provider,
}

/// One tracked Client API message: its redacted failure class, and whether the turn
/// that executed it has ended (after which the class is final).
#[derive(Default)]
struct TrackedMessage {
    class: Option<&'static str>,
    ended: bool,
}

/// The Client API messages the registry tracks, bounded like the messaging provider's
/// send ledger ([`crate::client_api_adapters::MAX_TRACKED_CLIENT_MESSAGES`]): the
/// oldest message is forgotten first.
#[derive(Default)]
struct MessageFailureClasses {
    by_message: HashMap<String, TrackedMessage>,
    order: VecDeque<String>,
}

impl MessageFailureClasses {
    fn track(&mut self, message_id: &str) {
        if self.by_message.contains_key(message_id) {
            return;
        }
        while self.order.len() >= crate::client_api_adapters::MAX_TRACKED_CLIENT_MESSAGES {
            if let Some(oldest) = self.order.pop_front() {
                self.by_message.remove(&oldest);
            }
        }
        self.order.push_back(message_id.to_string());
        self.by_message
            .insert(message_id.to_string(), TrackedMessage::default());
    }

    fn class(&self, message_id: &str) -> Option<String> {
        self.by_message
            .get(message_id)
            .and_then(|m| m.class)
            .map(str::to_string)
    }

    fn ended(&self, message_id: &str) -> bool {
        self.by_message.get(message_id).is_some_and(|m| m.ended)
    }

    /// The usage class, set while the message's turn is still running.
    fn note_usage_limit(&mut self, message_id: &str) {
        if let Some(m) = self.by_message.get_mut(message_id) {
            if !m.ended {
                m.class = Some(cap_llm::SUBSCRIPTION_USAGE_LIMIT_CLASS);
            }
        }
    }

    /// Withdraw the usage class while the message's turn is still running.
    fn withdraw_usage_limit(&mut self, message_id: &str) {
        if let Some(m) = self.by_message.get_mut(message_id) {
            if !m.ended && m.class == Some(cap_llm::SUBSCRIPTION_USAGE_LIMIT_CLASS) {
                m.class = None;
            }
        }
    }

    /// Forget a message that was never published.
    fn untrack(&mut self, message_id: &str) {
        if self.by_message.remove(message_id).is_some() {
            self.order.retain(|id| id != message_id);
        }
    }

    /// The message's turn ended; `class` lands only when it carries none yet.
    fn end(&mut self, message_id: &str, class: Option<&'static str>) {
        if let Some(m) = self.by_message.get_mut(message_id) {
            m.ended = true;
            if m.class.is_none() {
                m.class = class;
            }
        }
    }
}

/// Correlates a `POST /msg` turn with the reply its dispatch produces.
///
/// The handler [`register`](ReplyRegistry::register)s a oneshot keyed by the
/// agent id BEFORE delivering the inbound message, then awaits the receiver; the
/// dispatcher's [`ReplyRouterSink`] [`fulfill`](ReplyRegistry::fulfill)s it from
/// inside `dispatch`. Keyed by agent id (not message id) — the daemon serves one
/// in-flight POST at a time (single-in-flight enforced upstream; the serving loop
/// is serial), so the key is unambiguous. Message-id keying (concurrent
/// correlation) needs a CONTRACT-051 dispatch-trait change and is Step-3.
pub struct ReplyRegistry {
    /// Colon ⇄ bare alias resolution over the agent tree (`agent:<handle>` ⇄ tree id). `None`
    /// (unit fixtures) ⇒ the mechanical pairing `agent:<x>` ⇄ `x`.
    tree: Option<Arc<dyn advance_shared_types::agent_tree::AgentTreeReader>>,
    inner: Mutex<HashMap<String, ReplySlot>>,
    /// Per-agent "had a produced reply" bit. Never stores payload bytes.
    last_outbound: Mutex<HashMap<String, bool>>,
    /// Last C235 stream_key per agent id (unit-test / no-pending-send path).
    last_stream_key: Mutex<HashMap<String, String>>,
    /// FIFO of Client API message_ids per agent alias; Begin consumes the front.
    pending_message: Mutex<HashMap<String, VecDeque<String>>>,
    /// stream_key stored on a Client API message_id (pointer only, never body).
    keys_by_message: Mutex<HashMap<String, String>>,
    /// Client API messages in flight for each agent alias, oldest first; the last one
    /// is the message a model failure is attributed to. Entered before the message is
    /// published ([`Self::note_pending_message`]) and dropped once its turn has ended
    /// ([`Self::note_turn_end`]) or its publish failed
    /// ([`Self::forget_unpublished_message`]).
    inflight_message: Mutex<HashMap<String, Vec<String>>>,
    /// Redacted failure class of each tracked Client API message: a fixed token only
    /// (`subscription-usage-limit`, `provider-error`, `agent-error`), final once the
    /// message's turn has ended. Bounded.
    failure_by_message: Mutex<MessageFailureClasses>,
    /// Last failed model call per agent slot (`pending_slot`) while one of its Client
    /// API messages is in flight. Taken at the turn's end; a successful call clears it.
    pending_model_failure: Mutex<HashMap<String, ModelFailure>>,
    /// Agent slots (`pending_slot`) whose running turn has delivered a reply
    /// ([`Self::fulfill`] with a payload). Taken at the turn's end: one entry per agent.
    replied_in_turn: Mutex<HashSet<String>>,
    /// The stream of each Client API message whose turn is running: every model call of
    /// that turn, on the key the message's status names. Held while its frames are
    /// published, so the hub gets them in order and the stream's `Terminal` last.
    message_streams: Mutex<MessageStreams>,
    /// The hub the message streams are published to ([`StreamKeyAnnouncer::new`]).
    delta_sink: Mutex<Option<Arc<dyn LlmDeltaSink>>>,
}

impl ReplyRegistry {
    pub fn new() -> Self {
        Self {
            tree: None,
            inner: Mutex::new(HashMap::new()),
            last_outbound: Mutex::new(HashMap::new()),
            last_stream_key: Mutex::new(HashMap::new()),
            pending_message: Mutex::new(HashMap::new()),
            keys_by_message: Mutex::new(HashMap::new()),
            inflight_message: Mutex::new(HashMap::new()),
            failure_by_message: Mutex::new(MessageFailureClasses::default()),
            pending_model_failure: Mutex::new(HashMap::new()),
            replied_in_turn: Mutex::new(HashSet::new()),
            message_streams: Mutex::new(MessageStreams::default()),
            delta_sink: Mutex::new(None),
        }
    }

    /// Resolve aliases through the agent tree: a served key `agent:<handle>` and its tree id
    /// (a UUID in production) name the same agent.
    pub fn with_tree(
        mut self,
        tree: Arc<dyn advance_shared_types::agent_tree::AgentTreeReader>,
    ) -> Self {
        self.tree = Some(tree);
        self
    }

    /// Both spellings of one agent: `[served colon key, bare tree id]`. With a tree, the pair
    /// is `agent:<handle>` ⇄ tree id; without one, the mechanical `agent:<x>` ⇄ `x`.
    fn alias_keys(&self, id: &str) -> Vec<String> {
        if let Some(bare) = id.strip_prefix("agent:") {
            let tree_id = self
                .tree
                .as_ref()
                .and_then(|t| t.id_by_handle(bare))
                .unwrap_or_else(|| bare.to_string());
            return vec![id.to_string(), tree_id];
        }
        let handle = self
            .tree
            .as_ref()
            .and_then(|t| t.handle_of(id))
            .unwrap_or_else(|| id.to_string());
        vec![format!("agent:{handle}"), id.to_string()]
    }

    fn pending_slot(&self, id: &str) -> String {
        self.alias_keys(id)
            .into_iter()
            .next()
            .unwrap_or_else(|| id.to_string())
    }

    /// Start tracking a Client API message for its failure class, so a turn that ends
    /// at once still finds it. [`Self::note_pending_message`] does this too.
    pub fn track_client_message(&self, message_id: &str) {
        self.failure_by_message
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .track(message_id);
    }

    /// A Client API message of `agent_id` is about to be published: track it, queue it
    /// for its stream-key binding and put it in flight, so a turn that runs it before
    /// the sender has returned from publishing is still attributed to it. A message
    /// whose turn already ended is neither pending nor in flight.
    pub fn note_pending_message(&self, agent_id: &str, message_id: &str) {
        {
            let mut ledger = self
                .failure_by_message
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            ledger.track(message_id);
            if ledger.ended(message_id) {
                // Its turn already ran: the message is not pending and not in flight.
                return;
            }
        }
        let slot = self.pending_slot(agent_id);
        {
            let mut pending = self
                .pending_message
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let queue = pending.entry(slot).or_default();
            if !queue.iter().any(|id| id == message_id) {
                queue.push_back(message_id.to_string());
            }
            while queue.len() > MAX_PENDING_MESSAGES_PER_AGENT {
                queue.pop_front();
            }
        }
        let mut inflight = self
            .inflight_message
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for key in self.alias_keys(agent_id) {
            let queue = inflight.entry(key).or_default();
            if !queue.iter().any(|id| id == message_id) {
                queue.push(message_id.to_string());
            }
        }
    }

    /// The message was not published after all (the mailbox refused it): it is not in
    /// flight, not queued for a stream key and not tracked, and whatever message of the
    /// agent was in flight before it stays so.
    pub fn forget_unpublished_message(&self, agent_id: &str, message_id: &str) {
        let slot = self.pending_slot(agent_id);
        if let Some(queue) = self
            .pending_message
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get_mut(&slot)
        {
            queue.retain(|id| id != message_id);
        }
        {
            let mut inflight = self
                .inflight_message
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            for key in self.alias_keys(agent_id) {
                Self::drop_inflight(&mut inflight, &key, message_id);
            }
        }
        self.failure_by_message
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .untrack(message_id);
    }

    fn drop_inflight(inflight: &mut HashMap<String, Vec<String>>, key: &str, message_id: &str) {
        if let Some(queue) = inflight.get_mut(key) {
            queue.retain(|id| id != message_id);
            if queue.is_empty() {
                inflight.remove(key);
            }
        }
    }

    fn inflight_message_id(&self, agent_id: &str) -> Option<String> {
        let inflight = self
            .inflight_message
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for key in self.alias_keys(agent_id) {
            if let Some(id) = inflight.get(&key).and_then(|queue| queue.last()) {
                return Some(id.clone());
            }
        }
        None
    }

    /// Attach the redacted subscription-usage class to the in-flight Client API message.
    /// The stored value is only the fixed token.
    pub fn record_subscription_usage_limit(&self, agent_id: &str) {
        let Some(message_id) = self.inflight_message_id(agent_id) else {
            return;
        };
        self.failure_by_message
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .note_usage_limit(&message_id);
        self.note_pending_model_failure(agent_id, ModelFailure::UsageLimit);
    }

    /// Withdraw the subscription-usage class from the in-flight message after a
    /// successful model call, and forget the agent's pending model failure. A class
    /// recorded at a turn's end is final and stays.
    pub fn clear_recorded_failure_class(&self, agent_id: &str) {
        self.pending_model_failure
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&self.pending_slot(agent_id));
        let Some(message_id) = self.inflight_message_id(agent_id) else {
            return;
        };
        self.failure_by_message
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .withdraw_usage_limit(&message_id);
    }

    /// A model call of `agent_id` returned an error other than the subscription-usage
    /// class to its guest. Only pending: it names the class if the turn then ends
    /// without a reply. Ignored when no Client API message of the agent is in flight.
    pub fn record_model_failure(&self, agent_id: &str) {
        self.note_pending_model_failure(agent_id, ModelFailure::Provider);
    }

    fn note_pending_model_failure(&self, agent_id: &str, failure: ModelFailure) {
        if self.inflight_message_id(agent_id).is_none() {
            return;
        }
        self.pending_model_failure
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(self.pending_slot(agent_id), failure);
    }

    /// The serving loop admitted `message_id` for `agent_id` (any alias) and its turn is
    /// starting. When it is a Client API message waiting for its turn, every model call
    /// the agent makes until the turn's reply is dispatched ([`Self::fulfill`]) or the
    /// turn ends goes on the message's stream ([`Self::route_delta`]); any other
    /// message's calls publish their own streams. A message stream a turn left open (its
    /// end never reported) ends here, `Reaped` when no call opened it.
    pub fn note_turn_start(&self, agent_id: &str, message_id: &str) {
        let slot = self.pending_slot(agent_id);
        let queued = self.take_pending(&slot, message_id);
        let mut streams = self
            .message_streams
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(stale) = streams.take(&slot) {
            self.publish_stream_end(&stale, StreamEnd::Ended(LlmTerminalReason::Reaped));
        }
        if queued {
            streams
                .by_slot
                .insert(slot, MessageStream::new(message_id, agent_id));
        }
    }

    /// Remove `message_id` from `slot`'s queue of Client API messages waiting for their
    /// turn; whether it was there.
    fn take_pending(&self, slot: &str, message_id: &str) -> bool {
        let mut pending = self
            .pending_message
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(queue) = pending.get_mut(slot) else {
            return false;
        };
        let before = queue.len();
        queue.retain(|id| id != message_id);
        let taken = queue.len() != before;
        if queue.is_empty() {
            pending.remove(slot);
        }
        taken
    }

    /// Publish what ends `stream` to the attached hub: the `Terminal` of the stream its
    /// turn's calls opened; or, when they opened none, a stream of the message's own that
    /// ends at once as `end` says, and which the message's status then names — so a client
    /// following the message never waits on a stream that will not come. Without an
    /// attached hub, nothing. Called with the message streams locked, so it follows every
    /// frame of the stream.
    fn publish_stream_end(&self, stream: &MessageStream, end: StreamEnd<'_>) {
        let sink = self
            .delta_sink
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let Some(sink) = sink else {
            return;
        };
        let (frames, own_key) = match stream.terminal() {
            Some(terminal) => (vec![terminal], None),
            None => {
                let key: Arc<str> = Arc::from(format!("st_{}", uuid::Uuid::new_v4().simple()));
                (stream.unopened(&key, end), Some(key))
            }
        };
        // The hub leaves containing a panic to its producers (cap-llm's tee does so for the
        // frames it publishes): these frames are published from the turn end or the
        // dispatch, which a panicking sink must not unwind.
        let published = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            for frame in frames {
                sink.publish(frame);
            }
        }))
        .is_ok();
        if let (true, Some(key)) = (published, own_key) {
            self.keys_by_message
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .entry(stream.message_id.clone())
                .or_insert_with(|| key.to_string());
        }
    }

    /// Route one frame of a model call to `hub` (the [`StreamKeyAnnouncer`] path): a call
    /// of a turn that executes a Client API message goes on the message's stream; any
    /// other frame passes as it came. Every `Begin` becomes the agent's last stream key.
    /// The first call's `Begin` reaches the hub before the message's status names its
    /// key, so a client that subscribes at once does not read it absent — unless the hub
    /// refused the stream at its `Begin` (over its live-stream caps), which it does not say.
    pub(crate) fn route_delta(&self, event: LlmDeltaEvent, hub: &dyn LlmDeltaSink) {
        if matches!(event.frame, LlmDeltaFrame::Begin { .. }) {
            let mut map = self
                .last_stream_key
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            for k in self.alias_keys(&event.agent_id) {
                map.insert(k, event.stream_key.to_string());
            }
        }
        let slot = self.pending_slot(&event.agent_id);
        let mut streams = self
            .message_streams
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match streams.route(&slot, &event) {
            Routed::AsIs => {
                drop(streams);
                hub.publish(event);
            }
            Routed::Opens(message_id) => {
                let key = event.stream_key.to_string();
                hub.publish(event);
                self.keys_by_message
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .entry(message_id)
                    .or_insert(key);
            }
            Routed::Merged(merged) => hub.publish(merged),
            Routed::Nothing => {}
        }
    }

    /// The turn that executed `message_id` for `agent_id` (any alias) has ended.
    ///
    /// The message is no longer in flight and its class is final, so later turns
    /// cannot attach one to it; the agent's pending model failure and reply mark are
    /// consumed. A turn that ended [`TurnOutcome::Failed`] without delivering a reply
    /// marks a tracked Client API message that carries no class yet:
    /// `provider-error` when its last model call failed, `agent-error` when no model
    /// failure was observed, and `subscription-usage-limit` when that call stopped on
    /// the usage window but the class landed on a later in-flight message. A class
    /// already recorded (the usage class, set when the call returned) is never
    /// replaced. A turn that delivered a reply, and a completed turn (a reply or an
    /// empty batch), record nothing.
    pub fn note_turn_end(&self, agent_id: &str, message_id: &str, outcome: TurnOutcome) {
        let slot = self.pending_slot(agent_id);
        let pending = self
            .pending_model_failure
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&slot);
        let replied = self
            .replied_in_turn
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&slot);
        {
            let mut inflight = self
                .inflight_message
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            for key in self.alias_keys(agent_id) {
                Self::drop_inflight(&mut inflight, &key, message_id);
            }
        }
        let class = match (outcome, pending) {
            _ if replied => None,
            (TurnOutcome::Completed, _) => None,
            (TurnOutcome::Failed, Some(ModelFailure::UsageLimit)) => {
                Some(cap_llm::SUBSCRIPTION_USAGE_LIMIT_CLASS)
            }
            (TurnOutcome::Failed, Some(ModelFailure::Provider)) => {
                Some(advance_client_api::FAILURE_CLASS_PROVIDER_ERROR)
            }
            (TurnOutcome::Failed, None) => Some(advance_client_api::FAILURE_CLASS_AGENT_ERROR),
        };
        self.failure_by_message
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .end(message_id, class);
        // A message whose turn ended without starting (refused before its start) waits
        // for no turn any more.
        self.take_pending(&slot, message_id);
        // A message's stream its dispatched reply did not end ends with its turn, after
        // its class is final: a client that reads the status once the stream has ended
        // sees the class. One no call opened ends as the class says.
        let unopened = match class {
            None => LlmTerminalReason::Completed,
            Some(advance_client_api::FAILURE_CLASS_AGENT_ERROR) => LlmTerminalReason::Reaped,
            Some(_) => LlmTerminalReason::ProviderError,
        };
        self.end_message_stream(&slot, Some(message_id), StreamEnd::Ended(unopened));
    }

    /// End the message stream of `slot`'s running turn — only if it is `message_id`'s,
    /// when one is given — publishing what ends it to the attached hub
    /// ([`Self::publish_stream_end`]).
    fn end_message_stream(&self, slot: &str, message_id: Option<&str>, end: StreamEnd<'_>) {
        let mut streams = self
            .message_streams
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let ends = streams
            .by_slot
            .get(slot)
            .is_some_and(|stream| message_id.is_none_or(|id| stream.message_id == id));
        if ends {
            if let Some(stream) = streams.take(slot) {
                self.publish_stream_end(&stream, end);
            }
        }
    }

    /// The redacted failure class of this Client API message, when it has one:
    /// `subscription-usage-limit`, `provider-error` or `agent-error`. Never vendor text.
    pub fn failure_class_for_message(&self, message_id: &str) -> Option<String> {
        self.failure_by_message
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .class(message_id)
    }

    /// A model call of `agent_id` began on stream `key` (a `Begin` frame, published
    /// nowhere): `key` becomes the agent's last stream key, and the stream key of the
    /// Client API message its running turn executes when that turn had none yet. The hub
    /// has no stream `key` this way: a client reading it finds it absent.
    pub fn record_stream_key(&self, agent_id: &str, key: &str) {
        self.route_delta(
            LlmDeltaEvent {
                agent_id: Arc::from(agent_id),
                stream_key: Arc::from(key),
                frame: LlmDeltaFrame::Begin {
                    run_id: None,
                    task_id: None,
                },
            },
            &NoDeltaSink,
        );
    }

    pub fn last_stream_key(&self, agent_id: &str) -> Option<String> {
        let map = self
            .last_stream_key
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for k in self.alias_keys(agent_id) {
            if let Some(v) = map.get(&k) {
                return Some(v.clone());
            }
        }
        None
    }

    pub fn stream_key_for_message(&self, message_id: &str) -> Option<String> {
        self.keys_by_message
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(message_id)
            .cloned()
    }

    /// Register a pending reply slot for `agent_id` and return the receiver to
    /// await. A pre-existing registration for the same key is replaced (its
    /// sender dropped → that waiter resolves to `Err(RecvError)`); the listener's
    /// `in_flight` guard makes this collision unreachable in normal operation.
    pub fn register(&self, agent_id: &str) -> oneshot::Receiver<Option<Vec<u8>>> {
        let (tx, rx) = oneshot::channel();
        self.lock().insert(agent_id.to_string(), tx);
        rx
    }

    /// Fulfil the pending slot for `agent_id`, if any. `reply == Some(bytes)` for
    /// a produced reply, `None` for a turn that produced no action. No-op when no
    /// slot is registered; never panics if the receiver was already dropped
    /// (timeout / client disconnect).
    pub fn fulfill(&self, agent_id: &str, reply: Option<Vec<u8>>) {
        {
            let mut last = self
                .last_outbound
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            last.insert(agent_id.to_string(), reply.is_some());
        }
        if let Some(bytes) = reply.as_deref() {
            let slot = self.pending_slot(agent_id);
            // Dispatch runs inside the agent's turn, so this reply is the running
            // turn's: that turn's end records no failure class.
            self.replied_in_turn
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .insert(slot.clone());
            // The turn's model calls are over (what it does after its dispatch — memory,
            // embeddings — are the host's calls, published nowhere) and its class is final
            // (none): the message's stream ends now, not after those turn-end steps. A turn
            // that opened no model stream gives the message a stream carrying this reply.
            self.end_message_stream(&slot, None, StreamEnd::Replied(bytes));
        }
        if let Some(tx) = self.lock().remove(agent_id) {
            let _ = tx.send(reply);
        }
    }

    /// Last `fulfill` for `agent_id`: `None` never fulfilled; `Some(false)` empty
    /// action batch; `Some(true)` produced a reply. Payload bytes are not retained.
    pub fn last_outbound(&self, agent_id: &str) -> Option<bool> {
        self.last_outbound
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(agent_id)
            .copied()
    }

    /// Drop a recorded fulfill so a new Client API send starts at `reply_state: none`.
    pub fn clear_last_outbound(&self, agent_id: &str) {
        let aliases = self.alias_keys(agent_id);
        {
            let mut last = self
                .last_outbound
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            for k in &aliases {
                last.remove(k);
            }
        }
        let mut keys = self
            .last_stream_key
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for k in &aliases {
            keys.remove(k);
        }
    }

    /// Drop a pending registration without fulfilling it (the deliver-error
    /// path, where no turn will run). No-op when no slot is registered.
    pub fn cancel(&self, agent_id: &str) {
        let _ = self.lock().remove(agent_id);
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<String, ReplySlot>> {
        // Critical sections are tiny and panic-free, so poisoning cannot occur
        // in practice; recover defensively rather than propagate a poison panic.
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl Default for ReplyRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// The gateway's delta sink: routes every frame through the [`ReplyRegistry`] to the hub
/// ([`ReplyRegistry::route_delta`]), so a Client API message's stream follows every model
/// call of its turn, and records each `Begin` as the agent's last stream key.
pub struct StreamKeyAnnouncer {
    inner: Arc<dyn advance_shared_types::traits::LlmDeltaSink>,
    replies: Arc<ReplyRegistry>,
}

impl StreamKeyAnnouncer {
    /// Route into `inner`, which also receives the `Terminal` of each message stream when
    /// its turn ends. One announcer per registry: the registry keeps the hub of the last
    /// announcer built over it for the `Terminal`s.
    pub fn new(
        inner: Arc<dyn advance_shared_types::traits::LlmDeltaSink>,
        replies: Arc<ReplyRegistry>,
    ) -> Self {
        *replies
            .delta_sink
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(Arc::clone(&inner));
        Self { inner, replies }
    }
}

impl cap_llm::FailureClassNote for ReplyRegistry {
    fn note_subscription_usage_limit(&self, agent_id: &str) {
        self.record_subscription_usage_limit(agent_id);
    }

    fn clear_subscription_usage_limit(&self, agent_id: &str) {
        self.clear_recorded_failure_class(agent_id);
    }

    fn note_model_failure(&self, agent_id: &str) {
        self.record_model_failure(agent_id);
    }
}

impl advance_shared_types::traits::LlmDeltaSink for StreamKeyAnnouncer {
    fn is_wired(&self) -> bool {
        self.inner.is_wired()
    }

    fn publish(&self, event: advance_shared_types::traits::LlmDeltaEvent) {
        self.replies.route_delta(event, self.inner.as_ref());
    }
}

/// [`OutboundActionSink`] for the `POST /msg` path: fulfils the [`ReplyRegistry`]
/// oneshot so a waiting `POST /msg` caller gets the model's answer in the HTTP
/// body, and reports a sanitized preview of each reply as a stdout line to its log
/// ([`Self::with_log`]; none by default).
pub struct ReplyRouterSink {
    registry: Arc<ReplyRegistry>,
    log: LogHandle,
}

impl ReplyRouterSink {
    pub fn new(registry: Arc<ReplyRegistry>) -> Self {
        Self {
            registry,
            log: LogHandle::null(),
        }
    }

    /// Report each reply preview to `log`.
    pub fn with_log(mut self, log: LogHandle) -> Self {
        self.log = log;
        self
    }
}

#[async_trait::async_trait]
impl OutboundActionSink for ReplyRouterSink {
    /// Phase-2 Step-3 seam: async + carries the source `Message` + returns a
    /// [`DeliveryReport`]. `ReplyRouterSink` is the POST /msg path — it ignores
    /// `_source` (the shim delivers `origin: None`), fulfils the reply registry,
    /// and returns an empty report (no channel egress happened here; the channel
    /// reply path is the composite [`crate::channel_egress::DaemonOutboundSink`]).
    async fn deliver(
        &self,
        agent_id: &str,
        _source: &Message,
        actions: &[AgentAction],
    ) -> Result<DeliveryReport, DispatchError> {
        // (1) Correlate back to the POST /msg caller FIRST — this is the
        //     load-bearing path and must not be delayed by a backpressured /
        //     undrained stdout. Fulfil with the FIRST action's RAW payload bytes
        //     (the HTTP body is byte-faithful), or None when the turn produced no
        //     action (→ HTTP 202). Single-fulfil-first-action is interim (§3.6).
        let reply = actions.first().map(|a| a.payload.clone());
        self.registry.fulfill(agent_id, reply);
        // (2) Best-effort, BOUNDED observability AFTER the reply is delivered.
        //     Print only the FIRST action's payload, truncated to a small preview,
        //     so untrusted model output can't amplify a turn into a huge
        //     synchronous stdout write that stalls the current-thread runtime
        //     (the validator allows up to ~128 MiB per batch). Sanitized so the
        //     reply can't inject terminal escape sequences or bidi-spoof the
        //     daemon TTY. The log is infallible: a sink that cannot write drops the
        //     line, so a stdout failure never unwinds `dispatch`.
        if let Some(first) = actions.first() {
            let truncated = first.payload.len() > STDOUT_PREVIEW_BYTES;
            let preview = if truncated {
                &first.payload[..STDOUT_PREVIEW_BYTES]
            } else {
                &first.payload[..]
            };
            let mut line = format!("advance: agent reply: {}", sanitize_for_stdout(preview));
            if truncated {
                line.push_str(&format!(
                    " … (+{} more bytes)",
                    first.payload.len() - STDOUT_PREVIEW_BYTES
                ));
            }
            if actions.len() > 1 {
                line.push_str(&format!(" … (+{} more actions)", actions.len() - 1));
            }
            self.log.out(log_keys::REPLY_AGENT_REPLY, line);
        }
        Ok(DeliveryReport::empty())
    }
}

/// Render reply-payload bytes for safe stdout emission. Model output is untrusted
/// and may carry ANSI escapes / C0-C1 control chars / NUL / DEL (terminal-control
/// injection) OR Unicode bidirectional-control + zero-width / format chars (the
/// "Trojan Source" set, CVE-2021-42574) that visually reorder or hide displayed
/// text. Decode lossy UTF-8 and escape every such char via `escape_default`,
/// leaving ordinary printable text (incl. legitimate non-ASCII like CJK/emoji)
/// intact for readability. Mirrors the `start.rs::safe_path` `{:?}`-escape
/// discipline, extended to the bidi/format set.
pub fn sanitize_for_stdout(payload: &[u8]) -> String {
    let text = String::from_utf8_lossy(payload);
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        if ch.is_control() || is_bidi_or_format(ch) {
            out.extend(ch.escape_default());
        } else {
            out.push(ch);
        }
    }
    out
}

/// Unicode bidirectional-control + zero-width / format + line/paragraph-separator
/// characters that are NOT `char::is_control()` but can reorder, hide, or
/// line-break displayed text in a terminal (the "Trojan Source" set + Zl/Zp
/// separators + deprecated/interlinear format chars). Escaped by
/// [`sanitize_for_stdout`] so a model reply can't visually spoof or line-inject
/// the daemon's stdout. Ordinary non-ASCII text (CJK, accents, emoji) is
/// unaffected. (The tag block U+E0000.. is intentionally NOT escaped — it carries
/// legitimate flag-emoji sequences.)
fn is_bidi_or_format(ch: char) -> bool {
    matches!(ch,
        '\u{00AD}'                // SOFT HYPHEN (Cf)
        | '\u{061C}'              // ARABIC LETTER MARK (Cf, bidi)
        | '\u{180E}'              // MONGOLIAN VOWEL SEPARATOR (Cf)
        | '\u{200B}'..='\u{200F}' // ZWSP, ZWNJ, ZWJ, LRM, RLM
        | '\u{2028}'              // LINE SEPARATOR (Zl) — emits a real line break
        | '\u{2029}'              // PARAGRAPH SEPARATOR (Zp)
        | '\u{202A}'..='\u{202E}' // LRE, RLE, PDF, LRO, RLO (bidi overrides)
        | '\u{2060}'..='\u{2064}' // WJ + invisible operators
        | '\u{2066}'..='\u{206F}' // LRI, RLI, FSI, PDI (isolates) + deprecated format
        | '\u{FEFF}'              // ZWNBSP / BOM
        | '\u{FFF9}'..='\u{FFFB}' // interlinear annotation (Cf)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use advance_shared_types::mailbox::MessageKind;

    /// POST /msg source message (origin: None) for the Step-3 deliver seam.
    fn dummy_msg() -> Message {
        Message {
            id: "m".into(),
            kind: MessageKind::User,
            from: "user:http".into(),
            to: "agent:root".into(),
            payload: Vec::new(),
            context: None,
            timestamp: std::time::SystemTime::now(),
            origin: None,
        }
    }

    #[tokio::test]
    async fn register_then_fulfill_some_delivers_payload() {
        let reg = ReplyRegistry::new();
        let rx = reg.register("agent:root");
        reg.fulfill("agent:root", Some(b"hi".to_vec()));
        assert_eq!(rx.await.unwrap(), Some(b"hi".to_vec()));
    }

    #[tokio::test]
    async fn register_then_fulfill_none_delivers_none() {
        let reg = ReplyRegistry::new();
        let rx = reg.register("agent:root");
        reg.fulfill("agent:root", None);
        assert_eq!(rx.await.unwrap(), None);
    }

    #[test]
    fn fulfill_unknown_key_is_noop() {
        let reg = ReplyRegistry::new();
        // No registration for this key — must not panic.
        reg.fulfill("agent:nobody", Some(b"x".to_vec()));
    }

    #[tokio::test]
    async fn cancel_removes_pending_slot() {
        let reg = ReplyRegistry::new();
        let rx = reg.register("agent:root");
        reg.cancel("agent:root");
        // A subsequent fulfill is a no-op (slot already removed) → the receiver
        // resolves to Err (sender dropped by cancel).
        reg.fulfill("agent:root", Some(b"late".to_vec()));
        assert!(rx.await.is_err());
    }

    #[test]
    fn double_fulfill_second_is_noop() {
        let reg = ReplyRegistry::new();
        let _rx = reg.register("agent:root");
        reg.fulfill("agent:root", Some(b"first".to_vec()));
        // Slot already consumed; second fulfill is a no-op and must not panic.
        reg.fulfill("agent:root", Some(b"second".to_vec()));
    }

    #[test]
    fn fulfill_after_receiver_dropped_does_not_panic() {
        let reg = ReplyRegistry::new();
        let rx = reg.register("agent:root");
        drop(rx);
        reg.fulfill("agent:root", Some(b"orphan".to_vec()));
    }

    #[tokio::test]
    async fn router_sink_fulfills_with_first_action_payload() {
        let reg = Arc::new(ReplyRegistry::new());
        let rx = reg.register("agent:root");
        let sink = ReplyRouterSink::new(reg.clone());
        sink.deliver(
            "agent:root",
            &dummy_msg(),
            &[
                AgentAction {
                    payload: b"the reply text".to_vec(),
                },
                AgentAction {
                    payload: b"second-dropped".to_vec(),
                },
            ],
        )
        .await
        .unwrap();
        assert_eq!(rx.await.unwrap(), Some(b"the reply text".to_vec()));
    }

    #[tokio::test]
    async fn router_sink_large_multi_action_fulfills_full_first_payload() {
        // The stdout preview is bounded, but the reply correlation must still
        // carry the FULL first-action bytes (the preview truncation is stdout-only)
        // and must not panic on a large / multi-action batch.
        let reg = Arc::new(ReplyRegistry::new());
        let rx = reg.register("agent:root");
        let sink = ReplyRouterSink::new(reg.clone());
        let big = vec![b'x'; STDOUT_PREVIEW_BYTES * 3]; // larger than the preview cap
        sink.deliver(
            "agent:root",
            &dummy_msg(),
            &[
                AgentAction {
                    payload: big.clone(),
                },
                AgentAction {
                    payload: b"second".to_vec(),
                },
            ],
        )
        .await
        .unwrap();
        assert_eq!(
            rx.await.unwrap(),
            Some(big),
            "registry gets the FULL first payload, not the preview"
        );
    }

    #[tokio::test]
    async fn router_sink_empty_batch_fulfills_none() {
        let reg = Arc::new(ReplyRegistry::new());
        let rx = reg.register("agent:root");
        let sink = ReplyRouterSink::new(reg.clone());
        sink.deliver("agent:root", &dummy_msg(), &[]).await.unwrap();
        assert_eq!(rx.await.unwrap(), None);
    }

    #[test]
    fn sanitize_escapes_control_chars_keeps_text() {
        // ANSI escape + newline + NUL must be escaped; printable text kept.
        let raw = b"hello\x1b[31m\nworld\x00!";
        let s = sanitize_for_stdout(raw);
        assert!(s.contains("hello"));
        assert!(s.contains("world"));
        assert!(s.contains('!'));
        // No raw ESC / newline / NUL survive into the rendered string.
        assert!(!s.contains('\x1b'));
        assert!(!s.contains('\n'));
        assert!(!s.contains('\u{0}'));
    }

    #[test]
    fn sanitize_plain_text_unchanged() {
        assert_eq!(sanitize_for_stdout(b"a normal reply"), "a normal reply");
    }

    #[test]
    fn sanitize_escapes_bidi_and_zero_width() {
        // U+202E RLO (Trojan Source) + U+200B ZWSP must be escaped, not passed.
        let raw = "safe\u{202e}reversed\u{200b}hidden".as_bytes();
        let s = sanitize_for_stdout(raw);
        assert!(!s.contains('\u{202e}'), "RLO must be escaped");
        assert!(!s.contains('\u{200b}'), "ZWSP must be escaped");
        assert!(s.contains("safe") && s.contains("reversed") && s.contains("hidden"));
    }

    #[test]
    fn sanitize_escapes_separators_and_alm() {
        // U+2028/U+2029 (line/paragraph separators — real line breaks, NOT
        // char::is_control) + U+061C (ARABIC LETTER MARK, bidi) must be escaped.
        for ch in ['\u{2028}', '\u{2029}', '\u{061C}'] {
            let raw = format!("a{ch}b");
            let s = sanitize_for_stdout(raw.as_bytes());
            assert!(!s.contains(ch), "{:?} must be escaped", ch);
            assert!(s.contains('a') && s.contains('b'));
        }
    }

    #[test]
    fn sanitize_keeps_legitimate_non_ascii() {
        // Ordinary international text + emoji are NOT escaped (readability).
        let s = sanitize_for_stdout("你好 café 🚀".as_bytes());
        assert_eq!(s, "你好 café 🚀");
    }

    /// The frames a hub received, in order, as `(stream key, frame)`.
    #[derive(Default)]
    struct Hub(Mutex<Vec<(String, LlmDeltaFrame)>>);

    impl LlmDeltaSink for Hub {
        fn publish(&self, event: LlmDeltaEvent) {
            self.0
                .lock()
                .unwrap()
                .push((event.stream_key.to_string(), event.frame));
        }
    }

    impl Hub {
        fn frames(&self) -> Vec<(String, LlmDeltaFrame)> {
            self.0.lock().unwrap().clone()
        }
    }

    /// A registry routing into a recording hub, through the announcer the gateway holds.
    fn routed() -> (Arc<ReplyRegistry>, Arc<Hub>, StreamKeyAnnouncer) {
        let reg = Arc::new(ReplyRegistry::new());
        let hub = Arc::new(Hub::default());
        let sink =
            StreamKeyAnnouncer::new(Arc::clone(&hub) as Arc<dyn LlmDeltaSink>, Arc::clone(&reg));
        (reg, hub, sink)
    }

    fn frame(key: &str, frame: LlmDeltaFrame) -> LlmDeltaEvent {
        LlmDeltaEvent {
            agent_id: Arc::from("root"),
            stream_key: Arc::from(key),
            frame,
        }
    }

    fn begin() -> LlmDeltaFrame {
        LlmDeltaFrame::Begin {
            run_id: None,
            task_id: None,
        }
    }

    fn delta(seq: u64, text: &str) -> LlmDeltaFrame {
        LlmDeltaFrame::Delta {
            seq,
            text: text.to_string(),
        }
    }

    /// A model call's own terminal, as a live stream publishes it (not complete).
    fn end(seq: u64, reason: LlmTerminalReason, usage: Option<LlmDeltaUsage>) -> LlmDeltaFrame {
        LlmDeltaFrame::Terminal {
            seq,
            reason,
            usage,
            complete: false,
        }
    }

    /// A model call's own terminal, as a buffered `generate` call's tee publishes it once
    /// its text went out whole: complete.
    fn generated(
        seq: u64,
        reason: LlmTerminalReason,
        usage: Option<LlmDeltaUsage>,
    ) -> LlmDeltaFrame {
        LlmDeltaFrame::Terminal {
            seq,
            reason,
            usage,
            complete: true,
        }
    }

    /// The terminal the registry ends a message's stream with: complete.
    fn closing(seq: u64, reason: LlmTerminalReason, usage: Option<LlmDeltaUsage>) -> LlmDeltaFrame {
        LlmDeltaFrame::Terminal {
            seq,
            reason,
            usage,
            complete: true,
        }
    }

    fn usage(input_tokens: u64, output_tokens: u64, cost_usd: f64) -> Option<LlmDeltaUsage> {
        Some(LlmDeltaUsage {
            input_tokens,
            output_tokens,
            cost_usd,
        })
    }

    fn on(key: &str, frame: LlmDeltaFrame) -> (String, LlmDeltaFrame) {
        (key.to_string(), frame)
    }

    #[test]
    fn a_message_stream_follows_every_model_call_of_its_turn() {
        let (reg, hub, sink) = routed();
        reg.note_pending_message("agent:root", "cmsg-1");
        reg.note_turn_start("agent:root", "cmsg-1");
        // The first call: its text, then tool calls.
        sink.publish(frame("st_first", begin()));
        assert_eq!(
            reg.stream_key_for_message("cmsg-1").as_deref(),
            Some("st_first")
        );
        sink.publish(frame("st_first", delta(0, "I'll list the files.")));
        sink.publish(frame(
            "st_first",
            generated(1, LlmTerminalReason::Completed, usage(10, 2, 0.25)),
        ));
        // The call after the tool results: the answer.
        sink.publish(frame("st_second", begin()));
        sink.publish(frame("st_second", delta(0, "There are 3 files.")));
        sink.publish(frame(
            "st_second",
            generated(1, LlmTerminalReason::Completed, usage(20, 5, 0.5)),
        ));
        // Until the turn ends: one Begin, both calls' text on the message's key, set apart,
        // and no Terminal — a client reading the stream waits for the answer.
        assert_eq!(
            hub.frames(),
            [
                on("st_first", begin()),
                on("st_first", delta(0, "I'll list the files.")),
                on("st_first", delta(1, "\n\nThere are 3 files.")),
            ]
        );
        reg.note_turn_end("agent:root", "cmsg-1", TurnOutcome::Completed);
        assert_eq!(
            hub.frames().last(),
            Some(&on(
                "st_first",
                closing(2, LlmTerminalReason::Completed, usage(30, 7, 0.75))
            )),
            "the stream ends with its turn, carrying both calls' usage"
        );
        assert_eq!(
            reg.stream_key_for_message("cmsg-1").as_deref(),
            Some("st_first")
        );
        // What the turn's calls still publish (a turn-end reap) never reaches the hub.
        sink.publish(frame("st_second", end(1, LlmTerminalReason::Reaped, None)));
        sink.publish(frame("st_first", delta(5, "late")));
        assert_eq!(hub.frames().len(), 4, "{:?}", hub.frames());
    }

    #[test]
    fn a_dispatched_reply_ends_the_message_stream_before_the_turn_end() {
        let (reg, hub, sink) = routed();
        reg.note_pending_message("agent:root", "cmsg-1");
        reg.note_turn_start("agent:root", "cmsg-1");
        sink.publish(frame("st_first", begin()));
        sink.publish(frame("st_first", delta(0, "I'll check.")));
        sink.publish(frame(
            "st_first",
            generated(1, LlmTerminalReason::Completed, usage(1, 1, 0.5)),
        ));
        sink.publish(frame("st_second", begin()));
        sink.publish(frame("st_second", delta(0, "Done.")));
        sink.publish(frame(
            "st_second",
            generated(1, LlmTerminalReason::Completed, usage(2, 1, 0.25)),
        ));
        // An empty batch leaves the class to the turn's end: the stream stays open.
        reg.fulfill("root", None);
        assert_eq!(hub.frames().len(), 3, "{:?}", hub.frames());
        // The reply is dispatched: the stream ends at once, before the turn-end steps.
        reg.fulfill("root", Some(b"Done.".to_vec()));
        assert_eq!(
            hub.frames().last(),
            Some(&on(
                "st_first",
                closing(2, LlmTerminalReason::Completed, usage(3, 2, 0.75))
            ))
        );
        reg.note_turn_end("agent:root", "cmsg-1", TurnOutcome::Completed);
        assert_eq!(
            hub.frames().len(),
            4,
            "the turn's end publishes nothing more"
        );
        assert!(reg.failure_class_for_message("cmsg-1").is_none());
        // A reply dispatched with no message stream open publishes nothing.
        reg.fulfill("root", Some(b"again".to_vec()));
        assert_eq!(hub.frames().len(), 4);
    }

    #[test]
    fn a_late_delta_of_an_earlier_call_fills_its_place_and_never_the_later_calls() {
        let (reg, hub, sink) = routed();
        reg.note_pending_message("agent:root", "cmsg-1");
        reg.note_turn_start("agent:root", "cmsg-1");
        sink.publish(frame("st_a", begin()));
        sink.publish(frame("st_a", delta(0, "one ")));
        sink.publish(frame("st_a", delta(2, "three")));
        // The next call begins after seq 2: its text starts at 3.
        sink.publish(frame("st_b", begin()));
        sink.publish(frame("st_b", delta(0, "answer")));
        // The earlier call's seq 1 arrives late: it fills its own place.
        sink.publish(frame("st_a", delta(1, "two ")));
        // Its seq 3 would land on the later call's: dropped.
        sink.publish(frame("st_a", delta(3, "late")));
        assert_eq!(
            hub.frames(),
            [
                on("st_a", begin()),
                on("st_a", delta(0, "one ")),
                on("st_a", delta(2, "three")),
                on("st_a", delta(3, "\n\nanswer")),
                on("st_a", delta(1, "two ")),
            ]
        );
    }

    /// The registry passes its calls' text whole, however long: the hub's window, not the
    /// registry, bounds what it keeps for a reader that has not read it yet (a single delta
    /// past the window, the hub drops whole).
    #[test]
    fn a_message_stream_carries_its_text_whole() {
        let (reg, hub, sink) = routed();
        reg.note_pending_message("agent:root", "cmsg-1");
        reg.note_turn_start("agent:root", "cmsg-1");
        let first = "\u{e9}".repeat(150 * 1024);
        let second = "x".repeat(200 * 1024);
        sink.publish(frame("st_a", begin()));
        sink.publish(frame("st_a", delta(0, &first)));
        sink.publish(frame("st_b", begin()));
        sink.publish(frame("st_b", delta(0, &second)));
        sink.publish(frame("st_b", delta(1, "tail")));
        assert_eq!(
            hub.frames(),
            [
                on("st_a", begin()),
                on("st_a", delta(0, &first)),
                on("st_a", delta(1, &format!("{CALL_SEPARATOR}{second}"))),
                on("st_a", delta(2, "tail")),
            ],
            "no delta is cut: 500 KiB of text pass as they came"
        );
    }

    #[test]
    fn pieces_cut_at_char_boundaries_and_keep_every_byte() {
        assert!(pieces("", 4).is_empty());
        assert_eq!(pieces("abcdefghij", 4), ["abcd", "efgh", "ij"]);
        // Two-byte chars: a piece backs off to a char boundary.
        assert_eq!(
            pieces("\u{e9}\u{e9}\u{e9}", 3),
            ["\u{e9}", "\u{e9}", "\u{e9}"]
        );
        // A char wider than the bound goes whole.
        assert_eq!(pieces("\u{1f600}a", 2), ["\u{1f600}", "a"]);
        let long = "\u{e9}".repeat(OWN_STREAM_DELTA_BYTES) + "end";
        let cut = pieces(&long, OWN_STREAM_DELTA_BYTES);
        assert!(cut
            .iter()
            .all(|piece| piece.len() <= OWN_STREAM_DELTA_BYTES));
        assert_eq!(cut.concat(), long);
    }

    #[test]
    fn a_call_without_text_sets_nothing_apart() {
        let (reg, hub, sink) = routed();
        reg.note_pending_message("agent:root", "cmsg-1");
        reg.note_turn_start("agent:root", "cmsg-1");
        sink.publish(frame("st_a", begin()));
        sink.publish(frame("st_a", delta(0, "")));
        sink.publish(frame("st_a", end(1, LlmTerminalReason::Completed, None)));
        sink.publish(frame("st_b", begin()));
        sink.publish(frame("st_b", delta(0, "The answer.")));
        sink.publish(frame("st_b", delta(1, " More.")));
        sink.publish(frame(
            "st_b",
            generated(2, LlmTerminalReason::Completed, usage(1, 1, 0.5)),
        ));
        reg.note_turn_end("agent:root", "cmsg-1", TurnOutcome::Completed);
        assert_eq!(
            hub.frames(),
            [
                on("st_a", begin()),
                on("st_a", delta(0, "")),
                on("st_a", delta(1, "The answer.")),
                on("st_a", delta(2, " More.")),
                // A call that settled without usage leaves the sum out.
                on("st_a", closing(3, LlmTerminalReason::Completed, None)),
            ]
        );
    }

    #[test]
    fn overlapping_sends_bind_each_message_to_its_own_turn() {
        let (reg, hub, sink) = routed();
        reg.note_pending_message("agent:root", "cmsg-1");
        reg.note_pending_message("agent:root", "cmsg-2");
        reg.note_turn_start("agent:root", "cmsg-1");
        sink.publish(frame("st_first", begin()));
        sink.publish(frame(
            "st_first",
            end(0, LlmTerminalReason::Completed, None),
        ));
        sink.publish(frame("st_second", begin()));
        sink.publish(frame("st_second", delta(0, "answer one")));
        sink.publish(frame(
            "st_second",
            generated(1, LlmTerminalReason::Completed, None),
        ));
        assert!(
            reg.stream_key_for_message("cmsg-2").is_none(),
            "a later call of turn 1 never binds message 2"
        );
        reg.note_turn_end("agent:root", "cmsg-1", TurnOutcome::Completed);
        reg.note_turn_start("agent:root", "cmsg-2");
        sink.publish(frame("st_third", begin()));
        sink.publish(frame("st_third", delta(0, "answer two")));
        assert_eq!(
            reg.stream_key_for_message("cmsg-1").as_deref(),
            Some("st_first")
        );
        assert_eq!(
            reg.stream_key_for_message("cmsg-2").as_deref(),
            Some("st_third")
        );
        // Turn 1's first call published no delta: its second call's text starts the stream.
        assert_eq!(
            hub.frames()[1..],
            [
                on("st_first", delta(0, "answer one")),
                on("st_first", closing(1, LlmTerminalReason::Completed, None)),
                on("st_third", begin()),
                on("st_third", delta(0, "answer two")),
            ]
        );
    }

    #[test]
    fn a_turn_that_runs_no_client_api_message_publishes_its_calls_as_they_come() {
        let (reg, hub, sink) = routed();
        // Queued, but the turn now running executes another message (POST /msg, say).
        reg.note_pending_message("agent:root", "cmsg-1");
        reg.note_turn_start("agent:root", "msg-other");
        let calls = [
            frame("st_a", begin()),
            frame("st_a", delta(0, "x")),
            frame("st_a", end(1, LlmTerminalReason::Completed, None)),
            frame("st_b", begin()),
            frame("st_b", end(0, LlmTerminalReason::Completed, None)),
        ];
        for call in calls.clone() {
            sink.publish(call);
        }
        reg.note_turn_end("agent:root", "msg-other", TurnOutcome::Completed);
        assert_eq!(
            hub.frames(),
            calls
                .iter()
                .map(|event| (event.stream_key.to_string(), event.frame.clone()))
                .collect::<Vec<_>>()
        );
        assert!(reg.stream_key_for_message("cmsg-1").is_none());
        assert_eq!(reg.last_stream_key("agent:root").as_deref(), Some("st_b"));
        // The queued message's own turn binds it.
        reg.note_turn_start("agent:root", "cmsg-1");
        sink.publish(frame("st_c", begin()));
        assert_eq!(
            reg.stream_key_for_message("cmsg-1").as_deref(),
            Some("st_c")
        );
    }

    #[test]
    fn a_call_still_open_when_the_turn_ends_ends_the_stream_reaped() {
        let (reg, hub, sink) = routed();
        reg.note_pending_message("agent:root", "cmsg-1");
        reg.note_turn_start("agent:root", "cmsg-1");
        sink.publish(frame("st_first", begin()));
        sink.publish(frame("st_first", delta(0, "partial")));
        reg.note_turn_end("agent:root", "cmsg-1", TurnOutcome::Failed);
        assert_eq!(
            hub.frames().last(),
            Some(&on("st_first", end(1, LlmTerminalReason::Reaped, None))),
            "the open call's text may have gone on: the stream ends not complete"
        );
        // The last call's reason ends a stream whose calls all settled.
        let (reg, hub, sink) = routed();
        reg.note_pending_message("agent:root", "cmsg-2");
        reg.note_turn_start("agent:root", "cmsg-2");
        sink.publish(frame("st_a", begin()));
        sink.publish(frame("st_a", delta(0, "I'll check.")));
        sink.publish(frame(
            "st_a",
            generated(1, LlmTerminalReason::Completed, usage(1, 1, 0.5)),
        ));
        sink.publish(frame("st_b", begin()));
        sink.publish(frame(
            "st_b",
            generated(0, LlmTerminalReason::ProviderError, usage(1, 0, 0.25)),
        ));
        reg.note_turn_end("agent:root", "cmsg-2", TurnOutcome::Failed);
        assert_eq!(
            hub.frames().last(),
            Some(&on(
                "st_a",
                closing(1, LlmTerminalReason::ProviderError, usage(2, 1, 0.75))
            ))
        );
    }

    /// The registry's `Terminal` is complete only when the stream's text is whole: every call
    /// that put text on it ended complete (a buffered `generate` call whose text went out
    /// uncut), and the registry dropped none of it. A call that put no text on it does not
    /// count.
    #[test]
    fn a_message_stream_ends_complete_only_when_its_text_is_whole() {
        let run = |frames: &[LlmDeltaEvent]| {
            let (reg, hub, sink) = routed();
            reg.note_pending_message("agent:root", "cmsg-1");
            reg.note_turn_start("agent:root", "cmsg-1");
            for event in frames {
                sink.publish(event.clone());
            }
            reg.note_turn_end("agent:root", "cmsg-1", TurnOutcome::Completed);
            match hub.frames().last() {
                Some((_, LlmDeltaFrame::Terminal { complete, .. })) => *complete,
                other => panic!("no terminal: {other:?}"),
            }
        };
        // Buffered calls, and a live call that put no text on the stream: complete.
        assert!(run(&[
            frame("st_a", begin()),
            frame("st_a", delta(0, "I'll check.")),
            frame("st_a", generated(1, LlmTerminalReason::Completed, None)),
            frame("st_b", begin()),
            frame("st_b", end(0, LlmTerminalReason::Completed, None)),
            frame("st_c", begin()),
            frame("st_c", delta(0, "Done.")),
            frame("st_c", generated(1, LlmTerminalReason::Completed, None)),
        ]));
        // A live call's text: its terminal claims nothing, so neither does the stream's.
        assert!(!run(&[
            frame("st_a", begin()),
            frame("st_a", delta(0, "I'll check.")),
            frame("st_a", generated(1, LlmTerminalReason::Completed, None)),
            frame("st_b", begin()),
            frame("st_b", delta(0, "Done.")),
            frame("st_b", end(1, LlmTerminalReason::Completed, None)),
        ]));
        // The registry dropped text of the first call: a delta landing on the second's seqs.
        assert!(!run(&[
            frame("st_a", begin()),
            frame("st_a", delta(0, "one ")),
            frame("st_b", begin()),
            frame("st_a", delta(1, "two")),
            frame("st_a", generated(2, LlmTerminalReason::Completed, None)),
            frame("st_b", delta(0, "Done.")),
            frame("st_b", generated(1, LlmTerminalReason::Completed, None)),
        ]));
        // An empty delta dropped there loses no text.
        assert!(run(&[
            frame("st_a", begin()),
            frame("st_a", delta(0, "one ")),
            frame("st_b", begin()),
            frame("st_a", delta(1, "")),
            frame("st_a", generated(2, LlmTerminalReason::Completed, None)),
            frame("st_b", delta(0, "Done.")),
            frame("st_b", generated(1, LlmTerminalReason::Completed, None)),
        ]));
    }

    #[test]
    fn the_start_of_a_turn_ends_a_stream_its_turn_left_open() {
        let (reg, hub, sink) = routed();
        reg.note_pending_message("agent:root", "cmsg-1");
        reg.note_pending_message("agent:root", "cmsg-2");
        reg.note_turn_start("agent:root", "cmsg-1");
        sink.publish(frame("st_first", begin()));
        sink.publish(frame(
            "st_first",
            end(0, LlmTerminalReason::Completed, None),
        ));
        // No end is reported for cmsg-1's turn.
        reg.note_turn_start("agent:root", "cmsg-2");
        assert_eq!(
            hub.frames().last(),
            Some(&on(
                "st_first",
                closing(0, LlmTerminalReason::Completed, None)
            ))
        );
        sink.publish(frame("st_second", begin()));
        assert_eq!(
            reg.stream_key_for_message("cmsg-2").as_deref(),
            Some("st_second")
        );
    }

    /// A turn that opens no model stream gives its message a stream of its own, settled at
    /// once: carrying the reply it dispatched, or empty, ending as the turn's class says.
    #[test]
    fn a_turn_that_opens_no_model_stream_gives_its_message_a_stream_of_its_own() {
        let (reg, hub, _sink) = routed();
        let own = |message: &str| {
            let key = reg
                .stream_key_for_message(message)
                .expect("a key of its own");
            assert!(key.starts_with("st_") && key.len() == 35, "{key}");
            key
        };
        let frames_of = |key: &str| -> Vec<LlmDeltaFrame> {
            hub.frames()
                .into_iter()
                .filter(|(on, _)| on == key)
                .map(|(_, frame)| frame)
                .collect()
        };
        // A dispatched reply: the stream ends at the dispatch, carrying it.
        reg.note_pending_message("agent:root", "cmsg-1");
        reg.note_turn_start("agent:root", "cmsg-1");
        reg.fulfill("agent:root", Some(b"Nothing to look up.".to_vec()));
        let replied = own("cmsg-1");
        reg.note_turn_end("agent:root", "cmsg-1", TurnOutcome::Completed);
        assert_eq!(
            frames_of(&replied),
            [
                begin(),
                delta(0, "Nothing to look up."),
                closing(1, LlmTerminalReason::Completed, None),
            ]
        );
        // No reply: empty, ending with the turn.
        reg.note_pending_message("agent:root", "cmsg-2");
        reg.note_turn_start("agent:root", "cmsg-2");
        reg.fulfill("agent:root", None);
        assert!(reg.stream_key_for_message("cmsg-2").is_none());
        reg.note_turn_end("agent:root", "cmsg-2", TurnOutcome::Completed);
        let quiet = own("cmsg-2");
        assert_eq!(
            frames_of(&quiet),
            [begin(), closing(0, LlmTerminalReason::Completed, None)]
        );
        // A failed turn: as its class says.
        for (message, model_failed, reason) in [
            ("cmsg-3", false, LlmTerminalReason::Reaped),
            ("cmsg-4", true, LlmTerminalReason::ProviderError),
        ] {
            reg.note_pending_message("agent:root", message);
            reg.note_turn_start("agent:root", message);
            if model_failed {
                reg.record_model_failure("agent:root");
            }
            reg.note_turn_end("agent:root", message, TurnOutcome::Failed);
            assert!(reg.failure_class_for_message(message).is_some());
            assert_eq!(
                frames_of(&own(message)),
                [begin(), closing(0, reason, None)]
            );
        }
        // A turn whose end was never reported: the next turn's start ends it.
        reg.note_pending_message("agent:root", "cmsg-5");
        reg.note_turn_start("agent:root", "cmsg-5");
        reg.note_turn_start("agent:root", "other");
        assert_eq!(
            frames_of(&own("cmsg-5")),
            [begin(), closing(0, LlmTerminalReason::Reaped, None)]
        );
        // A long reply goes in pieces, whole.
        let long = "word ".repeat(OWN_STREAM_DELTA_BYTES / 2);
        reg.note_pending_message("agent:root", "cmsg-6");
        reg.note_turn_start("agent:root", "cmsg-6");
        reg.fulfill("agent:root", Some(long.clone().into_bytes()));
        let frames = frames_of(&own("cmsg-6"));
        assert_eq!(frames.len(), 2 + 3, "a Begin, three pieces and a Terminal");
        let mut text = String::new();
        for (at, frame) in frames[1..4].iter().enumerate() {
            let LlmDeltaFrame::Delta { seq, text: piece } = frame else {
                panic!("a delta: {frame:?}");
            };
            assert_eq!(*seq, at as u64);
            assert!(piece.len() <= OWN_STREAM_DELTA_BYTES);
            text.push_str(piece);
        }
        assert_eq!(text, long);
        assert_eq!(frames[4], closing(3, LlmTerminalReason::Completed, None));
    }

    /// A hub wired as in production: the real detector, hold geometry and end-of-stream sweep.
    fn production_hub() -> Arc<advance_client_api::deltas::LlmDeltaHub> {
        let hold: Arc<dyn Fn(&[u8], usize) -> Result<usize, ()> + Send + Sync> =
            Arc::new(|buf: &[u8], max_canonical: usize| {
                cap_http::canonical_facade::decoded_hold_split(buf, max_canonical)
            });
        let sweep: advance_client_api::DeltaCompletedMatchSweep =
            Arc::new(|buf: &[u8], max_canonical: usize| {
                cap_http::canonical_facade::decoded_region_has_completed_match(buf, max_canonical)
            });
        let detector: Arc<dyn advance_shared_types::traits::LeakDetector> =
            Arc::new(cap_http::DefaultLeakDetector::new());
        Arc::new(
            advance_client_api::deltas::LlmDeltaHub::new(
                Some(detector),
                Some(hold),
                Arc::new(advance_client_api::SystemClock),
                None,
            )
            .with_completed_match_sweep(sweep),
        )
    }

    /// The real hub keeps a stream's held tail at its complete end when a step before it lost
    /// the scan's hold on the text (MODULE-020-T24-h). Each stream takes every seq below its
    /// end:
    /// - a step scanned seqs 0, 1 and 3, released the start of a `ghp_` token in seq 0 and held
    ///   the rest; seq 2, sent after that step, fills the gap and completes the token, so
    ///   releasing the tail would complete the token for a reader;
    /// - a step blocked an AWS key and took the start of a second one with it; the next seq
    ///   holds the second key's rest and ends in a held start, so releasing it would give a
    ///   reader that rest.
    #[test]
    fn the_real_hub_keeps_the_tail_of_a_stream_whose_scan_lost_its_hold() {
        let hub = production_hub();
        let send = |key: &str, frame: LlmDeltaFrame| {
            hub.publish(LlmDeltaEvent {
                agent_id: Arc::from("agent:root"),
                stream_key: Arc::from(key),
                frame,
            })
        };
        let begin = |key: &str| {
            send(
                key,
                LlmDeltaFrame::Begin {
                    run_id: Some(format!("run-{key}")),
                    task_id: None,
                },
            )
        };
        let delta = |key: &str, seq: u64, text: &str| {
            send(
                key,
                LlmDeltaFrame::Delta {
                    seq,
                    text: text.to_string(),
                },
            )
        };
        let end = |key: &str, seq: u64| {
            send(
                key,
                LlmDeltaFrame::Terminal {
                    seq,
                    reason: LlmTerminalReason::Completed,
                    usage: None,
                    complete: true,
                },
            )
        };
        // The text read from seq 0, and the page's rejected count.
        let read = |key: &str| {
            let page = hub.read_page(key, 0);
            assert!(!page.page_limit_reached);
            let text: String = page.deltas.iter().map(|i| i.text.as_str()).collect();
            (text, page.rejected_count)
        };

        begin("gap");
        delta("gap", 0, "see ghp_Ab12");
        delta("gap", 1, "Cd34Ef56Hj78Kl90Mn12Op34Qr56sk");
        delta("gap", 3, "-proj-xyz");
        assert_eq!(
            read("gap"),
            ("see ghp_Ab12".to_string(), 0),
            "the step releases seq 0 and holds the rest"
        );
        delta("gap", 2, "Qr");
        end("gap", 4);
        assert_eq!(
            read("gap"),
            ("see ghp_Ab12".to_string(), 0),
            "the tail is held"
        );

        begin("blocked");
        delta("blocked", 0, "first AKIAQ3EGRJ5TXV7WN2LP second AKIAQ3EGRJ");
        assert_eq!(
            read("blocked"),
            (String::new(), 1),
            "the first key is blocked"
        );
        delta("blocked", 1, "5TXV7WN2LP then AKIA");
        end("blocked", 2);
        let (text, _) = read("blocked");
        assert!(!text.contains("5TXV7WN2LP"), "the tail is held");
    }

    /// A stream of the message's own meets the real hub's rules as a model stream does: a reply
    /// within the window reads whole; one past it keeps the window's pieces and names the rest
    /// dropped. A short reply ending in `s`, a tail that could begin a secret, reads whole too:
    /// its terminal is complete, so the hub, wired as in production, sweeps that tail at the
    /// stream's end and releases it (MODULE-020-T24-h). Each time the terminal comes with the
    /// seq after the stream's last piece, so a reader can tell the pieces it did not read.
    #[test]
    fn a_minted_stream_meets_the_real_hubs_window_and_hold() {
        let hub = production_hub();
        let reg = Arc::new(ReplyRegistry::new());
        let _sink =
            StreamKeyAnnouncer::new(Arc::clone(&hub) as Arc<dyn LlmDeltaSink>, Arc::clone(&reg));
        // The reply a client reads: the text, the first page's dropped count, the seq after the
        // last item read, and the terminal's seq.
        let read = |message: &str, reply: &str| {
            reg.note_pending_message("agent:root", message);
            reg.note_turn_start("agent:root", message);
            reg.fulfill("agent:root", Some(reply.as_bytes().to_vec()));
            let key = reg
                .stream_key_for_message(message)
                .expect("a stream of its own");
            let (mut text, mut from, mut dropped, mut terminal) = (String::new(), 0, None, None);
            loop {
                let page = hub.read_page(&key, from);
                assert!(!page.absent, "{message}: the stream is held");
                dropped.get_or_insert(page.dropped_count);
                terminal = terminal.or(page.terminal.as_ref().map(|t| t.seq));
                for item in &page.deltas {
                    text.push_str(&item.text);
                    from = item.to_seq + 1;
                }
                if !page.page_limit_reached {
                    break;
                }
            }
            (text, dropped.unwrap_or(0), from, terminal)
        };
        let (text, dropped, read_to, terminal) = read("cmsg-1", "Done: 3 files.");
        assert_eq!(
            (text.as_str(), dropped, read_to, terminal),
            ("Done: 3 files.", 0, 1, Some(1))
        );

        // `x` begins no Block or Redact pattern, so here the window, not the hold, decides
        // what is kept.
        let long = "x".repeat(300 * 1024);
        let (text, dropped, read_to, terminal) = read("cmsg-2", &long);
        assert_eq!(
            text.len(),
            16 * OWN_STREAM_DELTA_BYTES,
            "the window's pieces"
        );
        assert_eq!(dropped, 3, "the three pieces past the window");
        assert_eq!((read_to, terminal), (16, Some(19)));

        let (text, dropped, read_to, terminal) = read("cmsg-3", "Done: 3 files");
        assert_eq!(
            (text.as_str(), dropped, read_to, terminal),
            ("Done: 3 files", 0, 1, Some(1)),
            "the held tail is released at the stream's end"
        );

        // A reply past the window whose cut falls inside a key: its text went on past the held
        // tail, so the tail is held for good and no part of the key is read.
        let cut = 16 * OWN_STREAM_DELTA_BYTES;
        let keyed = format!(
            "{}AKIAIOSFOD{}",
            "x".repeat(cut - 10),
            "NN7EXAMPLE and more"
        );
        let (text, dropped, read_to, terminal) = read("cmsg-4", &keyed);
        assert_eq!(text, "x".repeat(cut - OWN_STREAM_DELTA_BYTES));
        assert_eq!((dropped, read_to, terminal), (1, 15, Some(17)));

        // A reply past the window whose cut falls just before a key's rest: the hub dropped
        // the piece with the key's start and took the piece after it, which carries the key's
        // rest and ends in a held start. The hub never took the dropped piece, so that tail is
        // held for good and no part of the key is read. (A piece of 3-byte chars is 16 383
        // bytes, so sixteen of them leave the window 16 bytes: room for the last piece, not
        // for the one before it.)
        let wide = OWN_STREAM_DELTA_BYTES / 3;
        let rest = "NN7EXAMPLE sk-";
        let held_from = cap_http::canonical_facade::decoded_hold_split(rest.as_bytes(), 4 << 20)
            .expect("the hold geometry");
        assert!(
            held_from < rest.len(),
            "the last piece ends in a held start"
        );
        let keyed = format!(
            "{}AKIAIOSFOD{rest}",
            "\u{4e2d}".repeat(16 * wide + (OWN_STREAM_DELTA_BYTES - 10) / 3)
        );
        let (text, dropped, read_to, terminal) = read("cmsg-5", &keyed);
        assert_eq!(text, "\u{4e2d}".repeat(16 * wide));
        assert_eq!((dropped, read_to, terminal), (1, 16, Some(18)));
    }

    /// Without an attached hub no stream is made up: the status names none.
    #[test]
    fn without_a_hub_a_turn_that_opens_no_stream_names_none() {
        let reg = ReplyRegistry::new();
        reg.note_pending_message("agent:root", "cmsg-1");
        reg.note_turn_start("agent:root", "cmsg-1");
        reg.fulfill("agent:root", Some(b"hi".to_vec()));
        reg.note_turn_end("agent:root", "cmsg-1", TurnOutcome::Completed);
        assert!(reg.stream_key_for_message("cmsg-1").is_none());
    }

    /// A hub that, at each frame, reads what the registry tells a client: the message's
    /// stream key and its failure class.
    #[derive(Default)]
    struct Witness {
        reg: Mutex<Option<std::sync::Weak<ReplyRegistry>>>,
        seen: Mutex<Vec<(LlmDeltaFrame, Option<String>, Option<String>)>>,
    }

    impl LlmDeltaSink for Witness {
        fn publish(&self, event: LlmDeltaEvent) {
            let reg = self
                .reg
                .lock()
                .unwrap()
                .as_ref()
                .and_then(|reg| reg.upgrade());
            let reg = reg.expect("the registry");
            self.seen.lock().unwrap().push((
                event.frame,
                reg.stream_key_for_message("cmsg-1"),
                reg.failure_class_for_message("cmsg-1"),
            ));
        }
    }

    #[test]
    fn a_client_finds_the_stream_once_the_hub_has_it_and_the_class_once_it_ends() {
        let reg = Arc::new(ReplyRegistry::new());
        let witness = Arc::new(Witness::default());
        *witness.reg.lock().unwrap() = Some(Arc::downgrade(&reg));
        let sink = StreamKeyAnnouncer::new(
            Arc::clone(&witness) as Arc<dyn LlmDeltaSink>,
            Arc::clone(&reg),
        );
        reg.note_pending_message("agent:root", "cmsg-1");
        reg.note_turn_start("agent:root", "cmsg-1");
        sink.publish(frame("st_first", begin()));
        note(&reg).note_model_failure("root");
        reg.note_turn_end("agent:root", "cmsg-1", TurnOutcome::Failed);
        let seen = witness.seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 2, "{seen:?}");
        // The hub had the Begin before the status named the key.
        assert_eq!(seen[0].0, begin());
        assert_eq!(seen[0].1, None);
        // The class was final before the stream ended.
        assert_eq!(seen[1].0, closing(0, LlmTerminalReason::Reaped, None));
        assert_eq!(seen[1].1.as_deref(), Some("st_first"));
        assert_eq!(
            seen[1].2.as_deref(),
            Some(advance_client_api::FAILURE_CLASS_PROVIDER_ERROR)
        );
    }

    #[test]
    fn stream_key_binds_to_pending_message_id() {
        let reg = ReplyRegistry::new();
        reg.note_pending_message("agent:root", "cmsg-1");
        reg.record_stream_key("root", "st_early");
        assert!(
            reg.stream_key_for_message("cmsg-1").is_none(),
            "a call before the message's turn starts is not its"
        );
        reg.note_turn_start("agent:root", "cmsg-1");
        reg.record_stream_key("root", "st_one");
        assert_eq!(
            reg.stream_key_for_message("cmsg-1").as_deref(),
            Some("st_one")
        );
        reg.note_turn_end("agent:root", "cmsg-1", TurnOutcome::Completed);
        reg.note_pending_message("agent:root", "cmsg-2");
        reg.note_turn_start("agent:root", "cmsg-2");
        reg.record_stream_key("root", "st_two");
        assert_eq!(
            reg.stream_key_for_message("cmsg-1").as_deref(),
            Some("st_one")
        );
        assert_eq!(
            reg.stream_key_for_message("cmsg-2").as_deref(),
            Some("st_two")
        );
    }

    #[test]
    fn stream_key_aliases_resolve_through_the_tree() {
        // A tree whose root id is a UUID with handle `root`: recording under either spelling
        // is visible under the other, and the mechanical `agent:<uuid>` is never written.
        struct OneRoot;
        impl advance_shared_types::agent_tree::AgentTreeReader for OneRoot {
            fn parent_of(&self, _: &str) -> Option<String> {
                None
            }
            fn children_of(&self, _: &str) -> Vec<String> {
                Vec::new()
            }
            fn siblings_of(&self, _: &str) -> Vec<String> {
                Vec::new()
            }
            fn agent_exists(&self, id: &str) -> bool {
                id == "11111111-1111-4111-8111-111111111111"
            }
            fn agent_kind(&self, _: &str) -> Option<advance_shared_types::agent_tree::AgentKind> {
                None
            }
            fn capabilities(&self, _: &str) -> Vec<advance_shared_types::agent_tree::Capability> {
                Vec::new()
            }
            fn handle_of(&self, id: &str) -> Option<String> {
                self.agent_exists(id).then(|| "root".to_string())
            }
            fn id_by_handle(&self, handle: &str) -> Option<String> {
                (handle == "root").then(|| "11111111-1111-4111-8111-111111111111".to_string())
            }
        }
        let reg = ReplyRegistry::new().with_tree(Arc::new(OneRoot));
        reg.record_stream_key("11111111-1111-4111-8111-111111111111", "st_uuid");
        assert_eq!(
            reg.last_stream_key("agent:root").as_deref(),
            Some("st_uuid")
        );
        assert!(
            reg.last_stream_key("agent:someone-else").is_none(),
            "an unrelated served key never aliases onto the root"
        );
        reg.record_stream_key("agent:root", "st_colon");
        assert_eq!(
            reg.last_stream_key("11111111-1111-4111-8111-111111111111")
                .as_deref(),
            Some("st_colon")
        );
        reg.clear_last_outbound("agent:root");
        assert!(reg
            .last_stream_key("11111111-1111-4111-8111-111111111111")
            .is_none());
    }

    #[test]
    fn stream_key_aliases_root_pair_not_hyphenated_colon() {
        let reg = ReplyRegistry::new();
        reg.record_stream_key("root", "st_abc");
        assert_eq!(reg.last_stream_key("agent:root").as_deref(), Some("st_abc"));
        assert_eq!(reg.last_stream_key("root").as_deref(), Some("st_abc"));
        assert!(
            reg.last_stream_key("agent:root-agent").is_none(),
            "must not write agent:root-agent"
        );
        reg.record_stream_key("agent:root", "st_def");
        assert_eq!(reg.last_stream_key("root").as_deref(), Some("st_def"));
    }

    #[test]
    fn clear_last_outbound_clears_both_stream_key_spellings() {
        let reg = ReplyRegistry::new();
        reg.record_stream_key("root", "st_abc");
        reg.clear_last_outbound("agent:root");
        assert!(reg.last_stream_key("root").is_none());
        assert!(reg.last_stream_key("agent:root").is_none());
    }

    #[test]
    fn subscription_usage_limit_is_stored_on_the_inflight_message_only() {
        let reg = ReplyRegistry::new();
        reg.note_pending_message("agent:root", "cmsg-1");
        reg.record_subscription_usage_limit("root");
        assert_eq!(
            reg.failure_class_for_message("cmsg-1").as_deref(),
            Some(cap_llm::SUBSCRIPTION_USAGE_LIMIT_CLASS)
        );
        assert!(reg.failure_class_for_message("cmsg-2").is_none());
        let stored = reg.failure_class_for_message("cmsg-1").unwrap();
        assert!(!stored.contains("resets"));
        assert!(!stored.contains('@'));
        assert!(!stored.contains("sk-"));

        reg.note_pending_message("agent:root", "cmsg-2");
        reg.clear_recorded_failure_class("agent:root");
        assert_eq!(
            reg.failure_class_for_message("cmsg-1").as_deref(),
            Some(cap_llm::SUBSCRIPTION_USAGE_LIMIT_CLASS),
            "a later message does not erase the earlier class"
        );
        assert!(reg.failure_class_for_message("cmsg-2").is_none());
    }

    /// The registry as cap-llm's gateway sees it.
    fn note(reg: &ReplyRegistry) -> &dyn cap_llm::FailureClassNote {
        reg
    }

    #[test]
    fn turn_end_after_a_failed_model_call_is_provider_error() {
        let reg = ReplyRegistry::new();
        reg.note_pending_message("agent:root", "cmsg-1");
        note(&reg).note_model_failure("root");
        assert!(
            reg.failure_class_for_message("cmsg-1").is_none(),
            "a failed model call is only pending while the turn runs"
        );
        reg.note_turn_end("agent:root", "cmsg-1", TurnOutcome::Failed);
        assert_eq!(
            reg.failure_class_for_message("cmsg-1").as_deref(),
            Some(advance_client_api::FAILURE_CLASS_PROVIDER_ERROR)
        );
    }

    #[test]
    fn turn_end_without_a_model_failure_is_agent_error() {
        let reg = ReplyRegistry::new();
        reg.note_pending_message("agent:root", "cmsg-1");
        assert!(reg.failure_class_for_message("cmsg-1").is_none());
        reg.note_turn_end("agent:root", "cmsg-1", TurnOutcome::Failed);
        assert_eq!(
            reg.failure_class_for_message("cmsg-1").as_deref(),
            Some(advance_client_api::FAILURE_CLASS_AGENT_ERROR)
        );
    }

    #[test]
    fn a_later_successful_model_call_withdraws_the_pending_failure() {
        let reg = ReplyRegistry::new();
        reg.note_pending_message("agent:root", "cmsg-1");
        note(&reg).note_model_failure("root");
        note(&reg).clear_subscription_usage_limit("root");
        reg.note_turn_end("agent:root", "cmsg-1", TurnOutcome::Failed);
        assert_eq!(
            reg.failure_class_for_message("cmsg-1").as_deref(),
            Some(advance_client_api::FAILURE_CLASS_AGENT_ERROR),
            "the last model call succeeded, so the failure is the agent's"
        );
    }

    #[test]
    fn completed_and_replied_turns_take_no_generic_class() {
        let reg = ReplyRegistry::new();
        // Completed with an empty batch after a failed model call.
        reg.note_pending_message("agent:root", "cmsg-1");
        note(&reg).note_model_failure("root");
        reg.fulfill("agent:root", None);
        reg.note_turn_end("agent:root", "cmsg-1", TurnOutcome::Completed);
        assert!(reg.failure_class_for_message("cmsg-1").is_none());
        // Replied, then the turn still failed (a later dispatch step): no class.
        reg.note_pending_message("agent:root", "cmsg-2");
        note(&reg).note_model_failure("root");
        reg.fulfill("root", Some(b"answer".to_vec()));
        reg.note_turn_end("agent:root", "cmsg-2", TurnOutcome::Failed);
        assert!(reg.failure_class_for_message("cmsg-2").is_none());
        // The reply mark belongs to that turn only.
        reg.note_pending_message("agent:root", "cmsg-3");
        reg.note_turn_end("agent:root", "cmsg-3", TurnOutcome::Failed);
        assert_eq!(
            reg.failure_class_for_message("cmsg-3").as_deref(),
            Some(advance_client_api::FAILURE_CLASS_AGENT_ERROR)
        );
    }

    #[test]
    fn subscription_usage_limit_takes_precedence_at_turn_end() {
        let reg = ReplyRegistry::new();
        reg.note_pending_message("agent:root", "cmsg-1");
        note(&reg).note_subscription_usage_limit("root");
        assert_eq!(
            reg.failure_class_for_message("cmsg-1").as_deref(),
            Some(cap_llm::SUBSCRIPTION_USAGE_LIMIT_CLASS),
            "recorded when the call returns, as before"
        );
        note(&reg).note_model_failure("root");
        reg.note_turn_end("agent:root", "cmsg-1", TurnOutcome::Failed);
        assert_eq!(
            reg.failure_class_for_message("cmsg-1").as_deref(),
            Some(cap_llm::SUBSCRIPTION_USAGE_LIMIT_CLASS),
            "never overwritten by a generic class"
        );

        // Overlapping sends: the usage class lands on the last-sent message (as
        // before), and the turn that hit it still ends with the usage class.
        reg.note_pending_message("agent:root", "cmsg-2");
        reg.note_pending_message("agent:root", "cmsg-3");
        note(&reg).note_subscription_usage_limit("root");
        reg.note_turn_end("agent:root", "cmsg-2", TurnOutcome::Failed);
        assert_eq!(
            reg.failure_class_for_message("cmsg-2").as_deref(),
            Some(cap_llm::SUBSCRIPTION_USAGE_LIMIT_CLASS)
        );
    }

    #[test]
    fn a_class_is_final_once_the_turn_has_ended() {
        let reg = ReplyRegistry::new();
        reg.note_pending_message("agent:root", "cmsg-1");
        reg.note_turn_end("agent:root", "cmsg-1", TurnOutcome::Failed);
        // A later turn of the agent (no Client API message in flight) changes nothing.
        note(&reg).note_subscription_usage_limit("root");
        note(&reg).clear_subscription_usage_limit("root");
        note(&reg).note_model_failure("root");
        reg.note_turn_end("agent:root", "msg-from-elsewhere", TurnOutcome::Failed);
        assert_eq!(
            reg.failure_class_for_message("cmsg-1").as_deref(),
            Some(advance_client_api::FAILURE_CLASS_AGENT_ERROR)
        );
        assert!(
            reg.failure_class_for_message("msg-from-elsewhere")
                .is_none(),
            "only tracked Client API messages take a class"
        );
    }

    #[test]
    fn a_turn_that_ends_before_its_send_returns_keeps_its_class() {
        let reg = ReplyRegistry::new();
        reg.track_client_message("cmsg-1");
        reg.note_turn_end("agent:root", "cmsg-1", TurnOutcome::Failed);
        reg.note_pending_message("agent:root", "cmsg-1");
        assert!(
            reg.inflight_message_id("agent:root").is_none(),
            "an ended message is not in flight"
        );
        note(&reg).note_subscription_usage_limit("root");
        assert_eq!(
            reg.failure_class_for_message("cmsg-1").as_deref(),
            Some(advance_client_api::FAILURE_CLASS_AGENT_ERROR)
        );
    }

    #[test]
    fn a_message_the_mailbox_refused_is_forgotten_and_the_earlier_one_stays_in_flight() {
        let reg = ReplyRegistry::new();
        reg.note_pending_message("agent:root", "cmsg-1");
        reg.note_pending_message("agent:root", "cmsg-2");
        reg.forget_unpublished_message("agent:root", "cmsg-2");
        assert_eq!(
            reg.inflight_message_id("root").as_deref(),
            Some("cmsg-1"),
            "the message sent before it is still the one in flight"
        );
        note(&reg).note_model_failure("root");
        reg.note_turn_end("agent:root", "cmsg-1", TurnOutcome::Failed);
        assert_eq!(
            reg.failure_class_for_message("cmsg-1").as_deref(),
            Some(advance_client_api::FAILURE_CLASS_PROVIDER_ERROR)
        );
        // The forgotten message is not tracked: nothing attaches to it, not even its
        // own turn's end.
        assert!(reg.failure_class_for_message("cmsg-2").is_none());
        reg.note_turn_end("agent:root", "cmsg-2", TurnOutcome::Failed);
        assert!(reg.failure_class_for_message("cmsg-2").is_none());

        // Alone in flight: forgetting it leaves nothing in flight (a failure noted now
        // is nobody's), and the next message takes the stream-key binding.
        let reg = ReplyRegistry::new();
        reg.note_pending_message("agent:root", "cmsg-1");
        reg.forget_unpublished_message("agent:root", "cmsg-1");
        assert!(reg.inflight_message_id("agent:root").is_none());
        note(&reg).note_model_failure("root");
        // Its turn, should it run after all, binds nothing.
        reg.note_turn_start("agent:root", "cmsg-1");
        reg.record_stream_key("root", "st_1");
        reg.note_turn_end("agent:root", "cmsg-1", TurnOutcome::Completed);
        reg.note_pending_message("agent:root", "cmsg-2");
        reg.note_turn_start("agent:root", "cmsg-2");
        reg.record_stream_key("root", "st_2");
        assert!(reg.stream_key_for_message("cmsg-1").is_none());
        assert_eq!(
            reg.stream_key_for_message("cmsg-2").as_deref(),
            Some("st_2")
        );
        reg.note_turn_end("agent:root", "cmsg-2", TurnOutcome::Failed);
        assert_eq!(
            reg.failure_class_for_message("cmsg-2").as_deref(),
            Some(advance_client_api::FAILURE_CLASS_AGENT_ERROR)
        );
    }

    #[test]
    fn turn_end_resolves_the_root_through_any_alias() {
        struct OneRoot;
        impl advance_shared_types::agent_tree::AgentTreeReader for OneRoot {
            fn parent_of(&self, _: &str) -> Option<String> {
                None
            }
            fn children_of(&self, _: &str) -> Vec<String> {
                Vec::new()
            }
            fn siblings_of(&self, _: &str) -> Vec<String> {
                Vec::new()
            }
            fn agent_exists(&self, id: &str) -> bool {
                id == ROOT_ID
            }
            fn agent_kind(&self, _: &str) -> Option<advance_shared_types::agent_tree::AgentKind> {
                None
            }
            fn capabilities(&self, _: &str) -> Vec<advance_shared_types::agent_tree::Capability> {
                Vec::new()
            }
            fn handle_of(&self, id: &str) -> Option<String> {
                self.agent_exists(id).then(|| "root".to_string())
            }
            fn id_by_handle(&self, handle: &str) -> Option<String> {
                (handle == "root").then(|| ROOT_ID.to_string())
            }
        }
        const ROOT_ID: &str = "11111111-1111-4111-8111-111111111111";
        let reg = ReplyRegistry::new().with_tree(Arc::new(OneRoot));
        // Sent to the served key, failed under the tree id, ended under the served key.
        reg.note_pending_message("agent:root", "cmsg-1");
        note(&reg).note_model_failure(ROOT_ID);
        reg.note_turn_end("agent:root", "cmsg-1", TurnOutcome::Failed);
        assert_eq!(
            reg.failure_class_for_message("cmsg-1").as_deref(),
            Some(advance_client_api::FAILURE_CLASS_PROVIDER_ERROR)
        );
        // Ended under the tree id; replied under the served key.
        reg.note_pending_message("agent:root", "cmsg-2");
        note(&reg).note_model_failure("agent:root");
        reg.note_turn_end(ROOT_ID, "cmsg-2", TurnOutcome::Failed);
        assert_eq!(
            reg.failure_class_for_message("cmsg-2").as_deref(),
            Some(advance_client_api::FAILURE_CLASS_PROVIDER_ERROR)
        );
        assert!(reg.inflight_message_id(ROOT_ID).is_none());
        reg.note_pending_message("agent:root", "cmsg-3");
        reg.fulfill("agent:root", Some(b"ok".to_vec()));
        reg.note_turn_end(ROOT_ID, "cmsg-3", TurnOutcome::Failed);
        assert!(reg.failure_class_for_message("cmsg-3").is_none());
    }

    #[test]
    fn failure_classes_are_bounded_like_the_send_ledger() {
        let max = crate::client_api_adapters::MAX_TRACKED_CLIENT_MESSAGES;
        let reg = ReplyRegistry::new();
        reg.note_pending_message("agent:root", "cmsg-0");
        reg.note_turn_end("agent:root", "cmsg-0", TurnOutcome::Failed);
        for i in 1..=max {
            reg.track_client_message(&format!("cmsg-{i}"));
        }
        let ledger = reg.failure_by_message.lock().unwrap();
        assert_eq!(ledger.by_message.len(), max);
        assert_eq!(ledger.order.len(), max);
        drop(ledger);
        assert!(
            reg.failure_class_for_message("cmsg-0").is_none(),
            "the oldest message is forgotten first"
        );
        reg.note_turn_end("agent:root", &format!("cmsg-{max}"), TurnOutcome::Failed);
        assert_eq!(
            reg.failure_class_for_message(&format!("cmsg-{max}"))
                .as_deref(),
            Some(advance_client_api::FAILURE_CLASS_AGENT_ERROR)
        );
    }
}

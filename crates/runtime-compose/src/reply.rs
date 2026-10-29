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
        self.pending_message
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .entry(slot)
            .or_default()
            .push_back(message_id.to_string());
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
    }

    /// The redacted failure class of this Client API message, when it has one:
    /// `subscription-usage-limit`, `provider-error` or `agent-error`. Never vendor text.
    pub fn failure_class_for_message(&self, message_id: &str) -> Option<String> {
        self.failure_by_message
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .class(message_id)
    }

    pub fn record_stream_key(&self, agent_id: &str, key: &str) {
        {
            let mut map = self
                .last_stream_key
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            for k in self.alias_keys(agent_id) {
                map.insert(k, key.to_string());
            }
        }
        let mid = {
            let slot = self.pending_slot(agent_id);
            self.pending_message
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .get_mut(&slot)
                .and_then(|q| q.pop_front())
        };
        if let Some(mid) = mid {
            self.keys_by_message
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .entry(mid)
                .or_insert_with(|| key.to_string());
        }
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
        if reply.is_some() {
            // Dispatch runs inside the agent's turn, so this reply is the running
            // turn's: that turn's end records no failure class.
            self.replied_in_turn
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .insert(self.pending_slot(agent_id));
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

/// Records `Begin.stream_key` onto [`ReplyRegistry`] then forwards to the hub.
pub struct StreamKeyAnnouncer {
    inner: Arc<dyn advance_shared_types::traits::LlmDeltaSink>,
    replies: Arc<ReplyRegistry>,
}

impl StreamKeyAnnouncer {
    pub fn new(
        inner: Arc<dyn advance_shared_types::traits::LlmDeltaSink>,
        replies: Arc<ReplyRegistry>,
    ) -> Self {
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
        let begin_key = matches!(
            event.frame,
            advance_shared_types::traits::LlmDeltaFrame::Begin { .. }
        )
        .then(|| (event.agent_id.to_string(), event.stream_key.to_string()));
        self.inner.publish(event);
        if let Some((agent_id, key)) = begin_key {
            self.replies.record_stream_key(&agent_id, &key);
        }
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

    #[test]
    fn overlapping_sends_fifo_bind_begins_in_order() {
        let reg = ReplyRegistry::new();
        reg.note_pending_message("agent:root", "cmsg-1");
        reg.note_pending_message("agent:root", "cmsg-2");
        reg.record_stream_key("root", "st_first");
        reg.record_stream_key("root", "st_second");
        assert_eq!(
            reg.stream_key_for_message("cmsg-1").as_deref(),
            Some("st_first")
        );
        assert_eq!(
            reg.stream_key_for_message("cmsg-2").as_deref(),
            Some("st_second")
        );
    }

    #[test]
    fn stream_key_binds_to_pending_message_id() {
        let reg = ReplyRegistry::new();
        reg.note_pending_message("agent:root", "cmsg-1");
        reg.record_stream_key("root", "st_one");
        assert_eq!(
            reg.stream_key_for_message("cmsg-1").as_deref(),
            Some("st_one")
        );
        reg.note_pending_message("agent:root", "cmsg-2");
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
        reg.note_pending_message("agent:root", "cmsg-2");
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

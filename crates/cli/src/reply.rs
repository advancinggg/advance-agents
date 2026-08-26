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

use std::collections::{HashMap, VecDeque};
use std::io::Write;
use std::sync::{Arc, Mutex, MutexGuard};

use tokio::sync::oneshot;

use advance_messaging::{AgentAction, OutboundActionSink};
use advance_shared_types::mailbox::{DispatchError, Message};
use advance_shared_types::outbound::DeliveryReport;

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
    inner: Mutex<HashMap<String, ReplySlot>>,
    /// Per-agent "had a produced reply" bit. Never stores payload bytes.
    last_outbound: Mutex<HashMap<String, bool>>,
    /// Last C235 stream_key per agent id (unit-test / no-pending-send path).
    last_stream_key: Mutex<HashMap<String, String>>,
    /// FIFO of Client API message_ids per agent alias; Begin consumes the front.
    pending_message: Mutex<HashMap<String, VecDeque<String>>>,
    /// stream_key stored on a Client API message_id (pointer only, never body).
    keys_by_message: Mutex<HashMap<String, String>>,
}

impl ReplyRegistry {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            last_outbound: Mutex::new(HashMap::new()),
            last_stream_key: Mutex::new(HashMap::new()),
            pending_message: Mutex::new(HashMap::new()),
            keys_by_message: Mutex::new(HashMap::new()),
        }
    }

    /// Root pair is `default-agent` ↔ `agent:default`, not `agent:default-agent`.
    fn alias_keys(id: &str) -> Vec<String> {
        if id == "agent:default" || id == "default-agent" {
            return vec!["agent:default".to_string(), "default-agent".to_string()];
        }
        if let Some(bare) = id.strip_prefix("agent:") {
            if bare == "default-agent" {
                return vec![id.to_string()];
            }
            return vec![id.to_string(), bare.to_string()];
        }
        if id == "default" {
            return vec![id.to_string()];
        }
        vec![format!("agent:{id}"), id.to_string()]
    }

    fn pending_slot(id: &str) -> String {
        Self::alias_keys(id)
            .into_iter()
            .next()
            .unwrap_or_else(|| id.to_string())
    }

    pub fn note_pending_message(&self, agent_id: &str, message_id: &str) {
        let slot = Self::pending_slot(agent_id);
        self.pending_message
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .entry(slot)
            .or_default()
            .push_back(message_id.to_string());
    }

    pub fn record_stream_key(&self, agent_id: &str, key: &str) {
        {
            let mut map = self
                .last_stream_key
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            for k in Self::alias_keys(agent_id) {
                map.insert(k, key.to_string());
            }
        }
        let mid = {
            let slot = Self::pending_slot(agent_id);
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
        for k in Self::alias_keys(agent_id) {
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
        let aliases = Self::alias_keys(agent_id);
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

/// Production [`OutboundActionSink`] for the daemon: prints each reply to stdout
/// (sanitized) and fulfils the [`ReplyRegistry`] oneshot so a waiting `POST /msg`
/// caller gets the model's answer in the HTTP body.
pub struct ReplyRouterSink {
    registry: Arc<ReplyRegistry>,
}

impl ReplyRouterSink {
    pub fn new(registry: Arc<ReplyRegistry>) -> Self {
        Self { registry }
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
        //     daemon TTY. `writeln!` (NOT `println!`) so a stdout write failure
        //     (e.g. broken pipe) returns an error instead of unwinding `dispatch`.
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
            let mut stdout = std::io::stdout().lock();
            let _ = writeln!(stdout, "{line}");
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
            to: "agent:default".into(),
            payload: Vec::new(),
            context: None,
            timestamp: std::time::SystemTime::now(),
            origin: None,
        }
    }

    #[tokio::test]
    async fn register_then_fulfill_some_delivers_payload() {
        let reg = ReplyRegistry::new();
        let rx = reg.register("agent:default");
        reg.fulfill("agent:default", Some(b"hi".to_vec()));
        assert_eq!(rx.await.unwrap(), Some(b"hi".to_vec()));
    }

    #[tokio::test]
    async fn register_then_fulfill_none_delivers_none() {
        let reg = ReplyRegistry::new();
        let rx = reg.register("agent:default");
        reg.fulfill("agent:default", None);
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
        let rx = reg.register("agent:default");
        reg.cancel("agent:default");
        // A subsequent fulfill is a no-op (slot already removed) → the receiver
        // resolves to Err (sender dropped by cancel).
        reg.fulfill("agent:default", Some(b"late".to_vec()));
        assert!(rx.await.is_err());
    }

    #[test]
    fn double_fulfill_second_is_noop() {
        let reg = ReplyRegistry::new();
        let _rx = reg.register("agent:default");
        reg.fulfill("agent:default", Some(b"first".to_vec()));
        // Slot already consumed; second fulfill is a no-op and must not panic.
        reg.fulfill("agent:default", Some(b"second".to_vec()));
    }

    #[test]
    fn fulfill_after_receiver_dropped_does_not_panic() {
        let reg = ReplyRegistry::new();
        let rx = reg.register("agent:default");
        drop(rx);
        reg.fulfill("agent:default", Some(b"orphan".to_vec()));
    }

    #[tokio::test]
    async fn router_sink_fulfills_with_first_action_payload() {
        let reg = Arc::new(ReplyRegistry::new());
        let rx = reg.register("agent:default");
        let sink = ReplyRouterSink::new(reg.clone());
        sink.deliver(
            "agent:default",
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
        let rx = reg.register("agent:default");
        let sink = ReplyRouterSink::new(reg.clone());
        let big = vec![b'x'; STDOUT_PREVIEW_BYTES * 3]; // larger than the preview cap
        sink.deliver(
            "agent:default",
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
        let rx = reg.register("agent:default");
        let sink = ReplyRouterSink::new(reg.clone());
        sink.deliver("agent:default", &dummy_msg(), &[])
            .await
            .unwrap();
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
        reg.note_pending_message("agent:default", "cmsg-1");
        reg.note_pending_message("agent:default", "cmsg-2");
        reg.record_stream_key("default-agent", "st_first");
        reg.record_stream_key("default-agent", "st_second");
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
        reg.note_pending_message("agent:default", "cmsg-1");
        reg.record_stream_key("default-agent", "st_one");
        assert_eq!(
            reg.stream_key_for_message("cmsg-1").as_deref(),
            Some("st_one")
        );
        reg.note_pending_message("agent:default", "cmsg-2");
        reg.record_stream_key("default-agent", "st_two");
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
    fn stream_key_aliases_root_pair_not_hyphenated_colon() {
        let reg = ReplyRegistry::new();
        reg.record_stream_key("default-agent", "st_abc");
        assert_eq!(
            reg.last_stream_key("agent:default").as_deref(),
            Some("st_abc")
        );
        assert_eq!(
            reg.last_stream_key("default-agent").as_deref(),
            Some("st_abc")
        );
        assert!(
            reg.last_stream_key("agent:default-agent").is_none(),
            "must not write agent:default-agent"
        );
        reg.record_stream_key("agent:default", "st_def");
        assert_eq!(
            reg.last_stream_key("default-agent").as_deref(),
            Some("st_def")
        );
    }

    #[test]
    fn clear_last_outbound_clears_both_stream_key_spellings() {
        let reg = ReplyRegistry::new();
        reg.record_stream_key("default-agent", "st_abc");
        reg.clear_last_outbound("agent:default");
        assert!(reg.last_stream_key("default-agent").is_none());
        assert!(reg.last_stream_key("agent:default").is_none());
    }
}

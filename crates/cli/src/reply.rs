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

use std::collections::HashMap;
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
}

impl ReplyRegistry {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
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
        if let Some(tx) = self.lock().remove(agent_id) {
            let _ = tx.send(reply);
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
}

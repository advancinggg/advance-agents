//! Scan-points (NotifyOutbound) witness — MODULE-012-AC-19 NotifyOutbound leg
//! (Wave-20 security lane).
//!
//! Drives the production M006 notify host-fn handlers (`NotifyChannelHandler` +
//! `NotifyAgentHandler`) with a `LeakDetector` injected via the additive
//! `with_leak_detector` builder, and proves the `ScanContext::NotifyOutbound`
//! scan fires on the decoded `payload` BEFORE delivery, with the handler
//! honoring Block (no delivery) / Redact (masked payload delivered) / Clean.
//! Anti-fake-green: scan-off (no detector) vs scan-on.
//!
//! NotifyOutbound is BUILT but DORMANT — the notify host fns are NOT cli-wired
//! (only the system-acceptance SUT registers them), so this is a handler-level
//! witness; MODULE-012-AC-19 stays HELD untested (see MODULE-006/012 §3.6).

use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use advance_runtime::host_registry::{HostCallContext, HostFunctionHandler};
use advance_shared_types::mailbox::{Message, MessageContext, MsgError, NotifyError};
use advance_shared_types::security_validator::{Action, Finding, ScanContext, ScanResult};
use advance_shared_types::traits::LeakDetector;
use wasmtime::component::Val;

use advance_messaging::{
    ChannelNotifier, MailboxDispatcher, NotifyAgentHandler, NotifyChannelHandler,
};

/// Hand-rolled spying detector — records `(text, ScanContext)`; `LEAKME` →
/// Blocked, `MASKME` → Redacted (masked in place), else Clean.
struct SpyingDetector {
    calls: Mutex<Vec<(String, ScanContext)>>,
}
impl SpyingDetector {
    fn new() -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
        }
    }
    fn calls(&self) -> Vec<(String, ScanContext)> {
        self.calls.lock().unwrap().clone()
    }
}
impl LeakDetector for SpyingDetector {
    fn scan(&self, text: &str, context: ScanContext) -> ScanResult {
        self.calls
            .lock()
            .unwrap()
            .push((text.to_string(), context.clone()));
        if text.contains("LEAKME") {
            ScanResult::Blocked {
                findings: vec![Finding {
                    pattern_name: "leakme".into(),
                    offset: 0,
                    length: 0,
                    action: Action::Block,
                }],
            }
        } else if text.contains("MASKME") {
            ScanResult::Redacted {
                redacted: text.replace("MASKME", "[REDACTED]"),
                findings: vec![Finding {
                    pattern_name: "maskme".into(),
                    offset: 0,
                    length: 0,
                    action: Action::Redact,
                }],
            }
        } else {
            ScanResult::Clean
        }
    }
    fn scan_headers(&self, _headers: &[(String, String)]) -> ScanResult {
        ScanResult::Clean
    }
}

/// Recording ChannelNotifier — captures the payload the handler forwards (None
/// when the handler blocked before delivery).
struct RecordingNotifier {
    seen: Mutex<Option<Vec<u8>>>,
}
#[async_trait]
impl ChannelNotifier for RecordingNotifier {
    async fn notify_channel(
        &self,
        _from: &str,
        _channel_id: &str,
        _user_id: &str,
        payload: Vec<u8>,
        _context: Option<MessageContext>,
    ) -> Result<(), NotifyError> {
        *self.seen.lock().unwrap() = Some(payload);
        Ok(())
    }
}

/// Recording MailboxDispatcher — only `notify_agent` is exercised; deliver/reply
/// are inert.
struct RecordingDispatcher {
    seen: Mutex<Option<Vec<u8>>>,
}
#[async_trait]
impl MailboxDispatcher for RecordingDispatcher {
    async fn deliver(&self, _target: &str, _msg: Message) -> Result<(), MsgError> {
        Ok(())
    }
    async fn reply(
        &self,
        _from: &str,
        _to_message_id: &str,
        _payload: Vec<u8>,
    ) -> Result<(), MsgError> {
        Ok(())
    }
    async fn notify_agent(
        &self,
        _from: &str,
        _target: &str,
        payload: Vec<u8>,
        _context: Option<MessageContext>,
    ) -> Result<(), NotifyError> {
        *self.seen.lock().unwrap() = Some(payload);
        Ok(())
    }
}

fn ctx(agent_id: &str) -> HostCallContext {
    HostCallContext {
        agent_id: agent_id.into(),
        trace_id: "t".into(),
        turn_id: None,
        capability: "messaging".into(),
        function: "advance:runtime/notify::notify".into(),
        run_id: None,
        iteration: None,
    }
}

fn list(bytes: &[u8]) -> Val {
    Val::List(bytes.iter().map(|b| Val::U8(*b)).collect())
}

fn channel_params(payload: &[u8]) -> Vec<Val> {
    vec![
        Val::String("telegram-main".into()),
        Val::String("user:bob".into()),
        list(payload),
        Val::Option(None),
    ]
}

fn agent_params(payload: &[u8]) -> Vec<Val> {
    vec![
        Val::String("agent:peer".into()),
        list(payload),
        Val::Option(None),
    ]
}

fn is_result_err(out: &[Val]) -> bool {
    matches!(out, [Val::Result(Err(_))])
}

// ── notify-channel (the user-facing NotifyOutbound carrier) ───────────────────

#[tokio::test]
async fn notify_channel_scan_fires_notifyoutbound_and_blocks_leak() {
    let notifier = Arc::new(RecordingNotifier {
        seen: Mutex::new(None),
    });
    let spy = Arc::new(SpyingDetector::new());
    let handler = NotifyChannelHandler::new(notifier.clone()).with_leak_detector(spy.clone());

    let out = handler
        .call(ctx("user:alice"), channel_params(b"LEAKME-sk"), 0)
        .await
        .unwrap();

    // Scan fired with NotifyOutbound on the decoded payload.
    let calls = spy.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].1, ScanContext::NotifyOutbound);
    assert!(calls[0].0.contains("LEAKME"));
    // Block → NotifyError lowered (Result(Err)), payload NOT delivered.
    assert!(is_result_err(&out), "leak → notify-error, got {out:?}");
    assert!(
        notifier.seen.lock().unwrap().is_none(),
        "blocked payload not delivered"
    );
}

#[tokio::test]
async fn notify_channel_redacts_payload_before_delivery() {
    let notifier = Arc::new(RecordingNotifier {
        seen: Mutex::new(None),
    });
    let spy = Arc::new(SpyingDetector::new());
    let handler = NotifyChannelHandler::new(notifier.clone()).with_leak_detector(spy);

    handler
        .call(ctx("user:alice"), channel_params(b"MASKME-secret"), 0)
        .await
        .unwrap();

    let delivered = notifier.seen.lock().unwrap().clone().expect("delivered");
    let s = String::from_utf8(delivered).unwrap();
    assert!(s.contains("[REDACTED]"), "masked payload delivered: {s}");
    assert!(!s.contains("MASKME"), "raw secret never delivered: {s}");
}

#[tokio::test]
async fn notify_channel_scan_off_delivers_unchanged() {
    // No detector → byte-identical (even a LEAKME payload is delivered raw).
    let notifier = Arc::new(RecordingNotifier {
        seen: Mutex::new(None),
    });
    let handler = NotifyChannelHandler::new(notifier.clone()); // NO with_leak_detector

    handler
        .call(ctx("user:alice"), channel_params(b"LEAKME-sk"), 0)
        .await
        .unwrap();

    let delivered = notifier.seen.lock().unwrap().clone().expect("delivered");
    assert_eq!(delivered, b"LEAKME-sk".to_vec(), "scan-off → raw delivered");
}

// ── notify-agent (same scan_notify_outbound helper, different decoder) ─────────

#[tokio::test]
async fn notify_agent_scan_fires_notifyoutbound_and_blocks_leak() {
    let dispatcher = Arc::new(RecordingDispatcher {
        seen: Mutex::new(None),
    });
    let spy = Arc::new(SpyingDetector::new());
    let handler = NotifyAgentHandler::new(dispatcher.clone()).with_leak_detector(spy.clone());

    let out = handler
        .call(ctx("agent:self"), agent_params(b"LEAKME-sk"), 0)
        .await
        .unwrap();

    let calls = spy.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].1, ScanContext::NotifyOutbound);
    assert!(is_result_err(&out), "leak → notify-error, got {out:?}");
    assert!(
        dispatcher.seen.lock().unwrap().is_none(),
        "blocked payload not delivered"
    );
}

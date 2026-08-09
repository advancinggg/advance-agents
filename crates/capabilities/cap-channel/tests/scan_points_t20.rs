//! T20 — MODULE-012-AC-19 ChannelBidi leg witness (Wave-20 security lane).
//!
//! Drives the production `HttpEgress::send` directly and proves the
//! `ScanContext::ChannelBidi` LeakDetector scan is wired on the PRE-render
//! channel MESSAGE CONTENT (`data`), with the egress honoring Block / Redact /
//! Clean. Anti-fake-green: scan-off (no detector) vs scan-on; a leak-bearing
//! message is withheld; a clean message egresses byte-identical (SYS-J-30
//! happy-path guard). Per cap-channel convention, the LeakDetector is
//! hand-rolled (no cap-http dev-dep) — this witnesses the egress WIRING/seam;
//! real pattern detection is cap-http's AC-07/08 concern.
//!
//! AC-19 stays HELD overall (the NotifyOutbound leg is dormant — see
//! MODULE-012/006 §3.6); this proves the ChannelBidi production leg.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use advance_shared_types::outbound::OutboundTarget;
use advance_shared_types::security_validator::{
    Action, Finding, HttpCapability, HttpError, HttpRequest, HttpResponse, HttpSecurityChain,
    ScanContext, ScanResult,
};
use advance_shared_types::traits::LeakDetector;

use cap_channel::{
    AdapterType, ChannelConfig, HttpEgress, HttpMethod, OutboundConfig, OutboundTransport,
    SubscriptionId, SubscriptionManager,
};

/// Hand-rolled spying detector: records every `(text, ScanContext)` and applies
/// a deterministic rule — `LEAKME` → Blocked, `MASKME` → Redacted (masked in
/// place), else Clean. Lets the test assert BOTH that the scan fired with the
/// ChannelBidi context AND that the egress honors each ScanResult arm.
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

/// Recording chain — captures the rendered request body that REACHES the chain
/// (so the test can assert pre-render redaction propagated through render), and
/// counts invocations (so a Block can be proven to short-circuit BEFORE the chain).
struct RecordingChain {
    bodies: Mutex<Vec<Vec<u8>>>,
}
impl RecordingChain {
    fn new() -> Self {
        Self {
            bodies: Mutex::new(Vec::new()),
        }
    }
    fn calls(&self) -> usize {
        self.bodies.lock().unwrap().len()
    }
    fn last_body(&self) -> Vec<u8> {
        self.bodies
            .lock()
            .unwrap()
            .last()
            .cloned()
            .unwrap_or_default()
    }
}
#[async_trait]
impl HttpSecurityChain for RecordingChain {
    async fn execute(
        &self,
        _agent_id: &str,
        req: HttpRequest,
        _cap: &HttpCapability,
    ) -> Result<HttpResponse, HttpError> {
        self.bodies.lock().unwrap().push(req.body.clone());
        Ok(HttpResponse {
            status: 200,
            headers: vec![],
            body: vec![],
        })
    }
}

fn telegram_sub(mgr: &SubscriptionManager) -> SubscriptionId {
    mgr.subscribe(
        "agent-007",
        ChannelConfig {
            adapter_type: AdapterType::Telegram,
            params: vec![],
            outbound: Some(OutboundConfig {
                method: HttpMethod::Post,
                url_template: "https://api.telegram.org/bot1/sendMessage".to_string(),
                headers: vec![("Content-Type".into(), "application/json".into())],
            }),
        },
    )
    .unwrap()
}

fn target() -> OutboundTarget {
    OutboundTarget::ChatReply {
        conversation_id: "98765".into(),
        reply_address: vec![("chat_id".into(), "98765".into())],
    }
}

#[tokio::test]
async fn t20_channelbidi_scan_fires_and_blocks_leak() {
    // scan-ON: a leak-bearing message is withheld; the chain is NEVER called.
    let mgr = Arc::new(SubscriptionManager::new());
    let id = telegram_sub(&mgr);
    let sub = mgr.lookup(&id).unwrap();
    let spy = Arc::new(SpyingDetector::new());
    let chain = Arc::new(RecordingChain::new());
    let egress = HttpEgress::new(chain.clone()).with_leak_detector(spy.clone());

    let err = egress
        .send(
            "agent-007",
            sub.as_ref(),
            target(),
            b"{\"text\":\"LEAKME-sk\"}",
        )
        .await
        .unwrap_err();

    // Scan fired with ChannelBidi on the PRE-render message content.
    let calls = spy.calls();
    assert_eq!(calls.len(), 1, "exactly one ChannelBidi scan");
    assert_eq!(calls[0].1, ScanContext::ChannelBidi);
    assert!(
        calls[0].0.contains("LEAKME"),
        "scanned the pre-render message data"
    );
    // Block short-circuits BEFORE the chain → no egress.
    assert_eq!(chain.calls(), 0, "chain not invoked on Block");
    assert!(
        matches!(err, cap_channel::ChannelError::OutboundBlocked(_)),
        "leak → OutboundBlocked, got {err:?}"
    );
    // Block error carries NO message bytes (operator-log safety).
    assert!(!format!("{err}").contains("LEAKME"));
}

#[tokio::test]
async fn t20_channelbidi_clean_passthrough_sys_j30_guard() {
    // scan-ON Clean: a normal channel reply egresses byte-identical (the chain
    // receives the rendered original) — guards the SYS-J-30 happy path.
    let mgr = Arc::new(SubscriptionManager::new());
    let id = telegram_sub(&mgr);
    let sub = mgr.lookup(&id).unwrap();
    let spy = Arc::new(SpyingDetector::new());
    let chain = Arc::new(RecordingChain::new());
    let egress = HttpEgress::new(chain.clone()).with_leak_detector(spy.clone());

    egress
        .send(
            "agent-007",
            sub.as_ref(),
            target(),
            b"{\"text\":\"hello world\"}",
        )
        .await
        .unwrap();

    let calls = spy.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].1, ScanContext::ChannelBidi);
    assert_eq!(chain.calls(), 1, "clean message reaches the chain");
    let body = String::from_utf8(chain.last_body()).unwrap();
    assert!(
        body.contains("hello world"),
        "clean body passthrough: {body}"
    );
    assert!(!body.contains("[REDACTED]"));
}

#[tokio::test]
async fn t20_channelbidi_redacts_in_place() {
    // scan-ON Redact: the masked message (not the raw) reaches the chain/network.
    let mgr = Arc::new(SubscriptionManager::new());
    let id = telegram_sub(&mgr);
    let sub = mgr.lookup(&id).unwrap();
    let spy = Arc::new(SpyingDetector::new());
    let chain = Arc::new(RecordingChain::new());
    let egress = HttpEgress::new(chain.clone()).with_leak_detector(spy.clone());

    egress
        .send(
            "agent-007",
            sub.as_ref(),
            target(),
            b"{\"text\":\"MASKME-secret\"}",
        )
        .await
        .unwrap();

    assert_eq!(chain.calls(), 1);
    let body = String::from_utf8(chain.last_body()).unwrap();
    assert!(
        body.contains("[REDACTED]"),
        "redacted body reaches chain: {body}"
    );
    assert!(
        !body.contains("MASKME"),
        "raw secret never reaches chain: {body}"
    );
}

#[tokio::test]
async fn t20_channelbidi_scan_off_no_scan_no_block() {
    // scan-OFF (no detector): byte-identical to the pre-Wave-20 egress — even a
    // LEAKME message passes through (the chain is the only gate). Anti-fake-green
    // discriminator vs the scan-ON block test above.
    let mgr = Arc::new(SubscriptionManager::new());
    let id = telegram_sub(&mgr);
    let sub = mgr.lookup(&id).unwrap();
    let chain = Arc::new(RecordingChain::new());
    let egress = HttpEgress::new(chain.clone()); // NO .with_leak_detector

    egress
        .send(
            "agent-007",
            sub.as_ref(),
            target(),
            b"{\"text\":\"LEAKME-sk\"}",
        )
        .await
        .unwrap();

    assert_eq!(
        chain.calls(),
        1,
        "scan-off → no ChannelBidi block, chain reached"
    );
}

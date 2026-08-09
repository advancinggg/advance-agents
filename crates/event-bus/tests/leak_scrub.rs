//! T-S-B AC-18 LeakDetector wiring tests (LeakDetector half only).
//!
//! Mock LeakDetector implementations test all 4 ScanResult variants per the
//! plan §"LeakDetector wiring algorithm" — Clean / Redacted / Warned / Blocked.
//!
//! Scope: this file tests the AC-18 LeakDetector PATTERN-based half. The
//! complementary `sensitive_params` parameter-name-based scrub (the previously-
//! deferred AC-18 half) was BUILT by the Wave-20 security lane — see the sibling
//! `tests/sensitive_params_redaction.rs` + `src/redact.rs` (production population
//! dormant). AC-18 stays `passed`.

use std::sync::Arc;

use advance_event_bus::{apply_scan_to_outbound, Clock, EventBusConfig, ScrubOutcome};

#[test]
fn t_apply_scan_clean() {
    use advance_shared_types::security_validator::{ScanContext, ScanResult};
    use advance_shared_types::traits::LeakDetector;

    struct CleanDetector;
    impl LeakDetector for CleanDetector {
        fn scan(&self, _: &str, _: ScanContext) -> ScanResult {
            ScanResult::Clean
        }
        fn scan_headers(&self, _: &[(String, String)]) -> ScanResult {
            ScanResult::Clean
        }
    }

    let detector: Arc<dyn LeakDetector> = Arc::new(CleanDetector);
    match apply_scan_to_outbound("hello world", Some(detector.as_ref())) {
        ScrubOutcome::Send(text) => assert_eq!(text, "hello world"),
        ScrubOutcome::Drop => panic!("Clean must Send"),
    }
}

#[test]
fn t_apply_scan_redacted() {
    use advance_shared_types::security_validator::{ScanContext, ScanResult};
    use advance_shared_types::traits::LeakDetector;

    struct RedactDetector;
    impl LeakDetector for RedactDetector {
        fn scan(&self, _text: &str, _: ScanContext) -> ScanResult {
            ScanResult::Redacted {
                redacted: "[REDACTED]".to_string(),
                findings: Vec::new(),
            }
        }
        fn scan_headers(&self, _: &[(String, String)]) -> ScanResult {
            ScanResult::Clean
        }
    }

    let detector: Arc<dyn LeakDetector> = Arc::new(RedactDetector);
    match apply_scan_to_outbound("api_key=sk-test-secret", Some(detector.as_ref())) {
        ScrubOutcome::Send(text) => assert_eq!(text, "[REDACTED]"),
        ScrubOutcome::Drop => panic!("Redacted must Send the redacted string"),
    }
}

#[test]
fn t_apply_scan_warned() {
    use advance_shared_types::security_validator::{ScanContext, ScanResult};
    use advance_shared_types::traits::LeakDetector;

    struct WarnDetector;
    impl LeakDetector for WarnDetector {
        fn scan(&self, _: &str, _: ScanContext) -> ScanResult {
            ScanResult::Warned {
                findings: Vec::new(),
            }
        }
        fn scan_headers(&self, _: &[(String, String)]) -> ScanResult {
            ScanResult::Clean
        }
    }

    let detector: Arc<dyn LeakDetector> = Arc::new(WarnDetector);
    match apply_scan_to_outbound("test text", Some(detector.as_ref())) {
        ScrubOutcome::Send(text) => assert_eq!(text, "test text"),
        ScrubOutcome::Drop => panic!("Warned must Send unchanged"),
    }
}

#[test]
fn t_apply_scan_blocked() {
    use advance_shared_types::security_validator::{ScanContext, ScanResult};
    use advance_shared_types::traits::LeakDetector;

    struct BlockDetector;
    impl LeakDetector for BlockDetector {
        fn scan(&self, _: &str, _: ScanContext) -> ScanResult {
            ScanResult::Blocked {
                findings: Vec::new(),
            }
        }
        fn scan_headers(&self, _: &[(String, String)]) -> ScanResult {
            ScanResult::Clean
        }
    }

    let detector: Arc<dyn LeakDetector> = Arc::new(BlockDetector);
    match apply_scan_to_outbound("test text", Some(detector.as_ref())) {
        ScrubOutcome::Send(_) => panic!("Blocked must Drop"),
        ScrubOutcome::Drop => {}
    }
}

/// MODULE-019-T53 — None LeakDetector path: text passes through.
#[test]
fn t53_none_leak_detector_passes_through() {
    match apply_scan_to_outbound("anything", None) {
        ScrubOutcome::Send(text) => assert_eq!(text, "anything"),
        ScrubOutcome::Drop => panic!("None must Send"),
    }
}

/// MODULE-019-T51 + T52 (functional integration via async EventBus): inject a
/// LeakDetector that redacts; emit an event; assert JSONL line + WS broadcast
/// both contain the redacted string.
///
/// This test covers the E2E LeakDetector wiring through the file_writer actor.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t51_t52_e2e_redaction_jsonl_path() {
    use advance_event_bus::EventBus;
    use advance_shared_types::event::Event;
    use advance_shared_types::security_validator::{ScanContext, ScanResult};
    use advance_shared_types::traits::{EventBusEmit, LeakDetector};
    use chrono::Utc;
    use serde_json::json;

    struct RedactSk;
    impl LeakDetector for RedactSk {
        fn scan(&self, text: &str, _: ScanContext) -> ScanResult {
            if text.contains("sk-") {
                ScanResult::Redacted {
                    redacted: text.replace("sk-test-1234", "[REDACTED]"),
                    findings: Vec::new(),
                }
            } else {
                ScanResult::Clean
            }
        }
        fn scan_headers(&self, _: &[(String, String)]) -> ScanResult {
            ScanResult::Clean
        }
    }

    let temp = tempfile::TempDir::new().unwrap();
    let jsonl_dir = temp.path().join("events");
    let db_path = temp.path().join("events.db");

    let mut cfg = EventBusConfig::new(jsonl_dir.clone(), db_path);
    cfg.websocket_addr = "127.0.0.1:0".parse().unwrap();
    cfg.leak_detector = Some(Arc::new(RedactSk));

    let bus = EventBus::new(cfg).await.expect("bus");

    let event = Event {
        id: "leak-test".into(),
        timestamp: Utc::now(),
        agent_id: "agent-a".into(),
        task_id: None,
        run_id: None,
        execution_id: None,
        trace_id: "tr-1".into(),
        span_id: "s-1".into(),
        parent_span_id: None,
        event_type: "runtime.started".into(),
        payload: json!({"api_key": "sk-test-1234"}),
        duration_ms: None,
    };
    bus.emit(event);

    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    // Verify JSONL output contains [REDACTED] and NOT the raw key.
    let date = Utc::now().date_naive();
    let jsonl_file = jsonl_dir.join(format!("{}.jsonl", date.format("%Y-%m-%d")));
    let content = std::fs::read_to_string(&jsonl_file).expect("jsonl exists");
    assert!(
        content.contains("[REDACTED]"),
        "JSONL should contain [REDACTED], got {}",
        content
    );
    assert!(
        !content.contains("sk-test-1234"),
        "JSONL should NOT contain raw key, got {}",
        content
    );

    bus.shutdown().await;
}

/// Sanity check: SystemClock is Send + Sync + 'static (needed for Arc<dyn Clock>).
#[test]
fn t_system_clock_constructible_as_arc_dyn() {
    use advance_event_bus::SystemClock;
    let _: Arc<dyn Clock> = Arc::new(SystemClock);
}

// ─── Slice C: T55 / T56 E2E coverage extending Slice B's unit-level scans ──

/// T55 E2E — Blocked event is dropped from JSONL AND from WebSocket fan-out;
/// `dropped_count` is NOT incremented (Blocked is a deliberate scrub decision,
/// not a sink failure).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t55_blocked_e2e_no_jsonl_line() {
    use advance_event_bus::EventBus;
    use advance_shared_types::event::Event;
    use advance_shared_types::security_validator::{ScanContext, ScanResult};
    use advance_shared_types::traits::{EventBusEmit, LeakDetector};
    use chrono::Utc;
    use futures::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    struct BlockDetector;
    impl LeakDetector for BlockDetector {
        fn scan(&self, _: &str, _: ScanContext) -> ScanResult {
            ScanResult::Blocked {
                findings: Vec::new(),
            }
        }
        fn scan_headers(&self, _: &[(String, String)]) -> ScanResult {
            ScanResult::Clean
        }
    }

    let temp = tempfile::TempDir::new().unwrap();
    let mut cfg = EventBusConfig::new(temp.path().join("events"), temp.path().join("events.db"));
    cfg.websocket_addr = "127.0.0.1:0".parse().unwrap();
    cfg.leak_detector = Some(Arc::new(BlockDetector));
    let bus = EventBus::new(cfg).await.expect("bus");
    let dropped_before = bus.dropped_count();

    // Subscribe a WS client to confirm Blocked events do not fan out.
    let addr = bus.server_addr().expect("server_addr");
    let url = format!("ws://{addr}/events");
    let (mut ws, _) = tokio_tungstenite::connect_async(&url).await.expect("ws");
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let now = Utc::now();
    bus.emit(Event {
        id: "evt-blocked".to_string(),
        timestamp: now,
        agent_id: "test-agent".to_string(),
        task_id: None,
        run_id: None,
        execution_id: None,
        trace_id: "tr-1".to_string(),
        span_id: "sp-1".to_string(),
        parent_span_id: None,
        event_type: "fs.read".to_string(),
        payload: serde_json::json!({"key": "sk-test-secret"}),
        duration_ms: None,
    });

    // WS client must receive 0 frames within 200ms (Blocked drops broadcast).
    let ws_check = tokio::time::timeout(std::time::Duration::from_millis(200), async {
        loop {
            match ws.next().await {
                Some(Ok(Message::Text(t))) if t.contains("evt-blocked") => {
                    panic!("Blocked event must not reach WebSocket; got: {t}");
                }
                Some(_) | None => {}
            }
        }
    })
    .await;
    assert!(ws_check.is_err(), "expected timeout (no WS frames)");

    let _ = ws.send(Message::Close(None)).await;

    // dropped_count must NOT be incremented — Blocked is a deliberate scrub
    // decision (validate_event_size + try_send all succeed), not a sink failure.
    // Snapshot BEFORE shutdown (which consumes self).
    let dropped_after = bus.dropped_count();
    assert_eq!(
        dropped_after, dropped_before,
        "Blocked must not increment dropped_count (deliberate scrub, not sink failure); before={dropped_before} after={dropped_after}"
    );

    bus.shutdown().await;

    // JSONL file: should NOT contain the event line.
    let today_path = temp
        .path()
        .join("events")
        .join(format!("{}.jsonl", now.date_naive()));
    if today_path.exists() {
        let content = std::fs::read_to_string(&today_path).unwrap();
        assert!(
            !content.contains("evt-blocked"),
            "Blocked event must not reach JSONL; got: {content:?}"
        );
    }
}

/// T56 E2E — Warned event passes through to JSONL + WS verbatim (no redaction).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t56_warned_e2e_jsonl_passthrough() {
    use advance_event_bus::EventBus;
    use advance_shared_types::event::Event;
    use advance_shared_types::security_validator::{ScanContext, ScanResult};
    use advance_shared_types::traits::{EventBusEmit, LeakDetector};
    use chrono::Utc;
    use futures::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    struct WarnDetector;
    impl LeakDetector for WarnDetector {
        fn scan(&self, _: &str, _: ScanContext) -> ScanResult {
            ScanResult::Warned {
                findings: Vec::new(),
            }
        }
        fn scan_headers(&self, _: &[(String, String)]) -> ScanResult {
            ScanResult::Clean
        }
    }

    let temp = tempfile::TempDir::new().unwrap();
    let mut cfg = EventBusConfig::new(temp.path().join("events"), temp.path().join("events.db"));
    cfg.websocket_addr = "127.0.0.1:0".parse().unwrap();
    cfg.leak_detector = Some(Arc::new(WarnDetector));
    let bus = EventBus::new(cfg).await.expect("bus");

    // Subscribe a WS client to verify Warned passes through verbatim.
    let addr = bus.server_addr().expect("server_addr");
    let url = format!("ws://{addr}/events");
    let (mut ws, _) = tokio_tungstenite::connect_async(&url).await.expect("ws");
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let now = Utc::now();
    let event = Event {
        id: "evt-warned".to_string(),
        timestamp: now,
        agent_id: "test-agent".to_string(),
        task_id: None,
        run_id: None,
        execution_id: None,
        trace_id: "tr-1".to_string(),
        span_id: "sp-1".to_string(),
        parent_span_id: None,
        event_type: "fs.read".to_string(),
        payload: serde_json::json!({"info": "warning event"}),
        duration_ms: None,
    };
    let expected_serialized = serde_json::to_string(&event).expect("serialize");
    bus.emit(event);

    // WS client must receive the event verbatim (Warned passes through unchanged).
    let frame = tokio::time::timeout(std::time::Duration::from_secs(3), ws.next())
        .await
        .expect("ws read timeout")
        .expect("ws stream closed")
        .expect("ws frame");
    match frame {
        Message::Text(t) => assert_eq!(
            t.as_str(),
            expected_serialized,
            "Warned must broadcast event verbatim"
        ),
        other => panic!("expected text frame, got {other:?}"),
    }

    let _ = ws.send(Message::Close(None)).await;
    bus.shutdown().await;

    // JSONL file: should contain the event line verbatim (with trailing \n).
    let today_path = temp
        .path()
        .join("events")
        .join(format!("{}.jsonl", now.date_naive()));
    let content = std::fs::read_to_string(&today_path).expect("today's JSONL");
    let expected_line = format!("{expected_serialized}\n");
    assert!(
        content.contains(&expected_line),
        "Warned must write JSONL line verbatim; expected substring: {expected_line:?}\nactual: {content:?}"
    );
}

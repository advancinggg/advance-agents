//! SYS-J-18 — secret-bearing content is blocked before reaching the dashboard or
//! the log. SYS-AC-055: for an event whose payload would carry a secret,
//! `ScanResult::Blocked` drops it — the JSONL line is absent AND WebSocket clients
//! receive zero frames.
//! Chain: MODULE-009 → MODULE-012 → MODULE-019.
//!
//! Witnessed test-local against the REAL async `advance_event_bus::EventBus`
//! (file-writer + db-indexer + ws-broadcaster actors over a real TCP socket — the
//! sys_j41_query_api precedent) with the REAL `cap_http::DefaultLeakDetector`
//! (BUILTIN_PATTERNS engine; canonical `sk-proj-…` openai_api_key pattern) wired as
//! the bus's leak detector — NOT a mock always-Blocked detector: the benign control
//! event passing through the SAME detector proves the discrimination is real.

use std::sync::Arc;
use std::time::Duration;

use advance_event_bus::{EventBus, EventBusConfig};
use advance_shared_types::event::Event;
use advance_shared_types::traits::EventBusEmit;
use cap_http::DefaultLeakDetector;
use chrono::Utc;
use futures::StreamExt;
use tokio_tungstenite::tungstenite::Message as WsMessage;

fn event(id: &str, payload: serde_json::Value) -> Event {
    Event {
        id: id.to_string(),
        timestamp: Utc::now(),
        agent_id: "agent:harness".to_string(),
        task_id: None,
        run_id: None,
        execution_id: None,
        trace_id: "tr-j18".to_string(),
        span_id: "sp-j18".to_string(),
        parent_span_id: None,
        event_type: "fs.read".to_string(),
        payload,
        duration_ms: None,
    }
}

/// SYS-AC-055 — Blocked drops the event: JSONL line absent, WS clients get zero
/// frames; a benign event through the SAME real detector passes (discrimination).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sys_ac_055_blocked_event_absent_from_jsonl_and_ws() {
    let temp = tempfile::TempDir::new().unwrap();
    let jsonl_dir = temp.path().join("events");
    let mut cfg = EventBusConfig::new(jsonl_dir.clone(), temp.path().join("events.db"));
    cfg.websocket_addr = "127.0.0.1:0".parse().unwrap();
    // The REAL production detector — the same BUILTIN_PATTERNS engine the
    // cap-http chain runs (MODULE-012).
    cfg.leak_detector = Some(Arc::new(DefaultLeakDetector::new()));
    let bus = EventBus::new(cfg).await.expect("real async bus");

    // A real WS client on /events.
    let addr = bus.server_addr().expect("ws server bound");
    let url = format!("ws://{addr}/events");
    let (mut ws, _) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("ws connect");
    tokio::time::sleep(Duration::from_millis(100)).await;

    let now = Utc::now();
    // 1. The benign control: passes the SAME detector → JSONL + one WS frame.
    bus.emit(event(
        "evt-benign",
        serde_json::json!({"note": "nothing secret here"}),
    ));
    // 2. The secret-bearing event: canonical openai_api_key pattern → Blocked.
    bus.emit(event(
        "evt-secret",
        serde_json::json!({"leak": "credential sk-proj-abcdefghijklmnop1234ABCD trailer"}),
    ));

    // WS: capture outcomes first, shut the bus down, THEN assert — a failed
    // assertion must not leak the axum server task + listener for the rest of
    // the test binary (adversarial r11; the bus has no Drop impl, only
    // shutdown() stops its server task).
    // Leg 1: wait (bounded) for the benign frame; record any secret frame seen.
    enum BenignOutcome {
        Frame(String),
        SecretLeaked(String),
        Closed,
    }
    let benign_outcome = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match ws.next().await {
                Some(Ok(WsMessage::Text(t))) if t.contains("evt-benign") => {
                    return BenignOutcome::Frame(t.to_string())
                }
                Some(Ok(WsMessage::Text(t))) if t.contains("evt-secret") => {
                    return BenignOutcome::SecretLeaked(t.to_string())
                }
                Some(_) => {}
                None => return BenignOutcome::Closed,
            }
        }
    })
    .await;
    // Leg 2: trailing window — zero frames for the secret event.
    let trailing_secret = tokio::time::timeout(Duration::from_millis(300), async {
        loop {
            if let Some(Ok(WsMessage::Text(t))) = ws.next().await {
                if t.contains("evt-secret") {
                    return t.to_string();
                }
            }
        }
    })
    .await;

    bus.shutdown().await;

    match benign_outcome.expect("benign event reaches the WS client in real time") {
        BenignOutcome::Frame(t) => assert!(t.contains("\"fs.read\"")),
        BenignOutcome::SecretLeaked(t) => {
            panic!("Blocked event reached a WebSocket client: {t}")
        }
        BenignOutcome::Closed => panic!("ws closed before the benign frame"),
    }
    assert!(
        trailing_secret.is_err(),
        "expected timeout — no secret frame; got {trailing_secret:?}"
    );

    // JSONL: the benign line is present; the secret line is ABSENT.
    let today = jsonl_dir.join(format!("{}.jsonl", now.date_naive()));
    let content = std::fs::read_to_string(&today).expect("benign event produced the JSONL file");
    assert!(
        content.contains("evt-benign"),
        "benign line present: {content:?}"
    );
    assert!(
        !content.contains("evt-secret"),
        "Blocked event's JSONL line must be absent: {content:?}"
    );
    assert!(
        !content.contains("sk-proj-"),
        "no secret material anywhere in the log: {content:?}"
    );
}

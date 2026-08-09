//! T-S-B AC-06 WebSocket /events integration test (minimal).
//!
//! Slice B ships a single subscribe-and-receive smoke test. Full WS test plan
//! (T24-T28: subscribe filter / multi-client fan-out / slow-client backpressure /
//! 11th-client rejection) deferred per §3.6 item 9.

use std::path::Path;
use std::sync::Arc;

use advance_event_bus::{Clock, EventBus, EventBusConfig, SystemClock};
use advance_shared_types::event::Event;
use advance_shared_types::traits::EventBusEmit;
use chrono::Utc;
use futures::{SinkExt, StreamExt};
use serde_json::json;
use tokio_tungstenite::tungstenite::Message;

fn cfg(jsonl_dir: &Path, db_path: &Path) -> EventBusConfig {
    let mut c = EventBusConfig::new(jsonl_dir.to_path_buf(), db_path.to_path_buf());
    c.websocket_addr = "127.0.0.1:0".parse().unwrap();
    c.clock = Arc::new(SystemClock) as Arc<dyn Clock>;
    c
}

fn make_event(id: &str, event_type: &str) -> Event {
    Event {
        id: id.into(),
        timestamp: Utc::now(),
        agent_id: "agent-A".into(),
        task_id: None,
        run_id: None,
        execution_id: None,
        trace_id: "tr-1".into(),
        span_id: "s-1".into(),
        parent_span_id: None,
        event_type: event_type.into(),
        payload: json!({}),
        duration_ms: None,
    }
}

/// MODULE-019-T24 — Connect a tokio-tungstenite client to /events; emit
/// `runtime.started`; assert client receives a JSON message containing the
/// event_type. Smoke-coverage for the WS subscribe-and-receive flow.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t24_ws_subscribe_and_receive_smoke() {
    let temp = tempfile::TempDir::new().unwrap();
    let bus = EventBus::new(cfg(
        &temp.path().join("events"),
        &temp.path().join("events.db"),
    ))
    .await
    .expect("bus");
    let addr = bus.server_addr().expect("server_addr");

    // Connect WebSocket client.
    let url = format!("ws://{}/events", addr);
    let (mut ws, _resp) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("ws connect");

    // Give the broadcast subscription a moment to register before emitting.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    bus.emit(make_event("e-1", "runtime.started"));

    // Read one frame with timeout.
    let frame = tokio::time::timeout(std::time::Duration::from_secs(3), ws.next())
        .await
        .expect("ws read timeout")
        .expect("ws stream closed unexpectedly")
        .expect("ws frame");
    match frame {
        Message::Text(t) => {
            assert!(
                t.contains("runtime.started"),
                "expected JSON containing event_type runtime.started, got: {t}"
            );
        }
        other => panic!("expected text frame, got {other:?}"),
    }

    let _ = ws.send(Message::Close(None)).await;
    bus.shutdown().await;
}

/// MODULE-019-T25 — subscribe-filter "accept-but-ignore" MVP regression-lock
/// (per ws_broadcaster.rs:198-202). Client sends a `{event_type_prefix: ["fs."]}`
/// filter; server still sends BOTH events.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t25_subscribe_filter_accepted_but_ignored() {
    let temp = tempfile::TempDir::new().unwrap();
    let bus = EventBus::new(cfg(
        &temp.path().join("events"),
        &temp.path().join("events.db"),
    ))
    .await
    .expect("bus");
    let addr = bus.server_addr().expect("server_addr");

    let url = format!("ws://{}/events", addr);
    let (mut ws, _resp) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("ws connect");
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Send subscribe-filter (server accepts but ignores).
    ws.send(Message::Text(
        r#"{"event_type_prefix": ["fs."]}"#.to_string().into(),
    ))
    .await
    .unwrap();

    bus.emit(make_event("e-fs", "fs.read.entry"));
    bus.emit(make_event("e-rt", "runtime.started"));

    // Client receives BOTH events (filter is no-op MVP).
    let mut received = Vec::new();
    for _ in 0..2 {
        let frame = tokio::time::timeout(std::time::Duration::from_secs(3), ws.next())
            .await
            .expect("ws read timeout")
            .expect("ws stream closed")
            .expect("ws frame");
        if let Message::Text(t) = frame {
            received.push(t.to_string());
        }
    }
    assert_eq!(received.len(), 2);
    assert!(received.iter().any(|t| t.contains("fs.read.entry")));
    assert!(received.iter().any(|t| t.contains("runtime.started")));

    let _ = ws.send(Message::Close(None)).await;
    bus.shutdown().await;
}

/// MODULE-019-T26 — 3 concurrent WS clients all receive a single emit.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t26_three_concurrent_ws_clients_all_receive() {
    let temp = tempfile::TempDir::new().unwrap();
    let bus = EventBus::new(cfg(
        &temp.path().join("events"),
        &temp.path().join("events.db"),
    ))
    .await
    .expect("bus");
    let addr = bus.server_addr().expect("server_addr");

    let url = format!("ws://{}/events", addr);
    let (mut ws1, _) = tokio_tungstenite::connect_async(&url).await.expect("ws1");
    let (mut ws2, _) = tokio_tungstenite::connect_async(&url).await.expect("ws2");
    let (mut ws3, _) = tokio_tungstenite::connect_async(&url).await.expect("ws3");
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    bus.emit(make_event("e-fanout", "runtime.started"));

    for ws in [&mut ws1, &mut ws2, &mut ws3].iter_mut() {
        let frame = tokio::time::timeout(std::time::Duration::from_secs(3), ws.next())
            .await
            .expect("ws read timeout")
            .expect("ws stream closed")
            .expect("ws frame");
        match frame {
            Message::Text(t) => assert!(t.contains("e-fanout")),
            other => panic!("expected text, got {other:?}"),
        }
    }

    let _ = ws1.send(Message::Close(None)).await;
    let _ = ws2.send(Message::Close(None)).await;
    let _ = ws3.send(Message::Close(None)).await;
    bus.shutdown().await;
}

/// MODULE-019-T28 — connect 11th client when max_concurrent_ws_clients=10:
/// 11th connection rejected at pre-upgrade with HTTP 503.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t28_eleventh_client_rejected_pre_upgrade() {
    let temp = tempfile::TempDir::new().unwrap();
    let mut c = cfg(&temp.path().join("events"), &temp.path().join("events.db"));
    c.max_concurrent_ws_clients = 10;
    let bus = EventBus::new(c).await.expect("bus");
    let addr = bus.server_addr().expect("server_addr");
    let url = format!("ws://{}/events", addr);

    // Fill to capacity (10 clients).
    let mut clients: Vec<_> = Vec::new();
    for _ in 0..10 {
        let (ws, _) = tokio_tungstenite::connect_async(&url).await.expect("ws");
        clients.push(ws);
    }
    // Brief pause so admission counter has incremented for all 10.
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    // 11th client: pre-upgrade 503 SERVICE_UNAVAILABLE (per ws_broadcaster.rs:128-135).
    let result = tokio_tungstenite::connect_async(&url).await;
    match result {
        Ok(_) => panic!("11th client must be rejected; got Ok"),
        Err(tokio_tungstenite::tungstenite::Error::Http(resp)) => {
            assert_eq!(
                resp.status(),
                tokio_tungstenite::tungstenite::http::StatusCode::SERVICE_UNAVAILABLE,
                "expected HTTP 503 pre-upgrade rejection, got status {:?}",
                resp.status()
            );
        }
        Err(other) => panic!("expected HTTP 503 error, got {other:?}"),
    }

    for mut ws in clients {
        let _ = ws.send(Message::Close(None)).await;
    }
    bus.shutdown().await;
}

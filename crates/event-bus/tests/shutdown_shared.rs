//! MODULE-001-AC-30 lower-crate witnesses for the EventBus side of the ordered
//! shutdown: `EventBus::shutdown_shared` stops a bus held in an `Arc` (no
//! `Arc::try_unwrap`), closes and joins the upgraded `/events` WebSocket client
//! tasks, and is idempotent; `EventBus::new_without_server` binds no listener while
//! the sinks and the read API keep working.
//!
//! Both tests run on a current-thread runtime and spawn no task of their own (the
//! WebSocket client is polled inline), so `num_alive_tasks` counts only the bus.

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use advance_event_bus::{EventBus, EventBusConfig, EventFilter, ReadNext};
use advance_shared_types::event::Event;
use advance_shared_types::traits::EventBusEmit;
use chrono::Utc;
use futures::StreamExt;
use serde_json::json;
use tokio_tungstenite::tungstenite::Message;

fn cfg(jsonl_dir: &Path, db_path: &Path) -> EventBusConfig {
    let mut c = EventBusConfig::new(jsonl_dir.to_path_buf(), db_path.to_path_buf());
    c.websocket_addr = "127.0.0.1:0".parse().unwrap();
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

fn alive_tasks() -> usize {
    tokio::runtime::Handle::current()
        .metrics()
        .num_alive_tasks()
}

/// Polls (yielding to the runtime) until `num_alive_tasks() == want` or `budget`
/// elapses; returns the last observed count.
async fn settle_alive_tasks(want: usize, budget: Duration) -> usize {
    let deadline = Instant::now() + budget;
    loop {
        let n = alive_tasks();
        if n == want || Instant::now() >= deadline {
            return n;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test(flavor = "current_thread")]
async fn module_001_ac30_eventbus_shutdown_shared_joins_ws_clients_and_is_idempotent() {
    let temp = tempfile::TempDir::new().unwrap();
    let baseline = alive_tasks();
    let bus = Arc::new(
        EventBus::new(cfg(
            &temp.path().join("events"),
            &temp.path().join("events.db"),
        ))
        .await
        .expect("bus"),
    );
    let addr = bus.server_addr().expect("server_addr");

    // Two connected `/events` clients; each proves its server task is live by
    // receiving an emitted event.
    let mut clients = Vec::new();
    for _ in 0..2 {
        let (ws, _resp) = tokio_tungstenite::connect_async(format!("ws://{addr}/events"))
            .await
            .expect("ws connect");
        clients.push(ws);
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    bus.emit(make_event("e-1", "runtime.started"));
    for ws in &mut clients {
        let frame = tokio::time::timeout(Duration::from_secs(3), ws.next())
            .await
            .expect("ws read timeout")
            .expect("ws stream ended before the first event")
            .expect("ws frame");
        assert!(
            matches!(&frame, Message::Text(t) if t.contains("runtime.started")),
            "expected the emitted event, got {frame:?}"
        );
    }
    // Non-vacuity: the bus tasks and the two client tasks are alive.
    let before = alive_tasks();
    assert!(
        before >= baseline + 7,
        "expected sweeper + 5 actors/server + 2 client tasks alive, got {before} (baseline {baseline})"
    );

    // Shut down through a shared handle (the bus stays in its Arc).
    let shared = Arc::clone(&bus);
    tokio::time::timeout(Duration::from_secs(10), shared.shutdown_shared())
        .await
        .expect("shutdown_shared finished");

    // Every client got a Close frame (or its stream ended).
    for ws in &mut clients {
        let next = tokio::time::timeout(Duration::from_secs(2), ws.next())
            .await
            .expect("client saw the shutdown within 2s");
        match next {
            None | Some(Ok(Message::Close(_))) | Some(Err(_)) => {}
            Some(Ok(other)) => panic!("expected Close or end of stream, got {other:?}"),
        }
    }

    // Nothing of the bus is left running: no actor, no server, no client task.
    let after = settle_alive_tasks(baseline, Duration::from_secs(2)).await;
    assert_eq!(after, baseline, "tasks left after shutdown_shared");

    // Idempotent: a second call (here through the other Arc) returns at once.
    tokio::time::timeout(Duration::from_secs(1), bus.shutdown_shared())
        .await
        .expect("second shutdown_shared returned");

    // After shutdown an emit is accepted and only counted as dropped.
    let dropped = bus.dropped_count();
    bus.emit(make_event("e-2", "runtime.started"));
    assert!(
        bus.dropped_count() > dropped,
        "an emit after shutdown is counted as dropped"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn module_001_ac30_eventbus_without_server_binds_nothing() {
    let temp = tempfile::TempDir::new().unwrap();
    // A port that is free right now; the server-less bus must leave it free.
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = probe.local_addr().unwrap();
    drop(probe);

    let baseline = alive_tasks();
    let mut c = cfg(&temp.path().join("events"), &temp.path().join("events.db"));
    c.websocket_addr = addr;
    let bus = Arc::new(EventBus::new_without_server(c).await.expect("bus"));

    assert_eq!(bus.server_addr(), None, "no listener, no address");
    std::net::TcpListener::bind(addr).expect("the configured address stays free");
    // Sweeper + file writer + db indexer + ws actor + stats; no server task.
    assert_eq!(alive_tasks(), baseline + 5);

    // The read API is still served from the same broadcaster and store.
    let read = bus.read_api().expect("read api on the async bus");
    let mut live = read.subscribe(EventFilter::default());
    bus.emit(make_event("e-1", "runtime.started"));
    match tokio::time::timeout(Duration::from_secs(3), live.recv())
        .await
        .expect("live event within 3s")
    {
        ReadNext::Event(ev) => assert_eq!(ev.id, "e-1"),
        _ => panic!("expected the emitted event on the live subscription"),
    }

    bus.shutdown_shared().await;
    let after = settle_alive_tasks(baseline, Duration::from_secs(2)).await;
    assert_eq!(after, baseline, "tasks left after shutdown_shared");

    // The sinks drained before exiting: the event is in the JSONL store.
    let mut jsonl = String::new();
    for entry in std::fs::read_dir(temp.path().join("events")).unwrap() {
        jsonl.push_str(&std::fs::read_to_string(entry.unwrap().path()).unwrap());
    }
    assert!(jsonl.contains("\"e-1\""), "event persisted: {jsonl}");
}

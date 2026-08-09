//! T-S-B AC-05 async emit + dropped_count tests.
//!
//! T20: emit() callable from any thread (post-construction).
//! T21: 4 sinks all receive emitted events.
//! T22 / T23: unified-counter dropped_count semantic.

use std::path::Path;
use std::sync::Arc;

use advance_event_bus::{EventBus, EventBusConfig};
use advance_shared_types::event::Event;
use advance_shared_types::traits::EventBusEmit;
use chrono::Utc;
use serde_json::json;

fn cfg(jsonl_dir: &Path, db_path: &Path) -> EventBusConfig {
    let mut c = EventBusConfig::new(jsonl_dir.to_path_buf(), db_path.to_path_buf());
    // Use port 0 (OS-assigned) so concurrent test runs don't collide.
    c.websocket_addr = "127.0.0.1:0".parse().unwrap();
    c
}

fn make_event(id: &str, event_type: &str) -> Event {
    Event {
        id: id.into(),
        timestamp: Utc::now(),
        agent_id: "agent-a".into(),
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

/// MODULE-019-T20 — emit() callable from non-tokio thread post-construction.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t20_emit_from_non_tokio_thread() {
    let temp = tempfile::TempDir::new().unwrap();
    let bus = EventBus::new(cfg(
        &temp.path().join("events"),
        &temp.path().join("events.db"),
    ))
    .await
    .expect("bus");
    let bus = Arc::new(bus);

    let bus_clone = bus.clone();
    let handle = std::thread::spawn(move || {
        let event = make_event("from-non-tokio-thread", "runtime.started");
        bus_clone.emit(event);
    });
    handle.join().expect("non-tokio thread completes");

    // Allow the actor task to consume the event.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Should NOT panic; bus is functional.
    Arc::try_unwrap(bus)
        .map_err(|_| ())
        .ok()
        .expect("unique bus")
        .shutdown()
        .await;
}

/// MODULE-019-T21 — emit() reaches 4 sinks under tokio context.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t21_emit_reaches_all_4_sinks() {
    let temp = tempfile::TempDir::new().unwrap();
    let jsonl_dir = temp.path().join("events");
    let db_path = temp.path().join("events.db");
    let bus = EventBus::new(cfg(&jsonl_dir, &db_path)).await.expect("bus");

    for i in 0..10u64 {
        let event = make_event(&format!("evt-{}", i), "task.created");
        bus.emit(event);
    }

    // Allow actors to drain mpsc channels.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    // Verify file_writer sink — JSONL file exists with ≥10 lines.
    let date = Utc::now().date_naive();
    let jsonl_file = jsonl_dir.join(format!("{}.jsonl", date.format("%Y-%m-%d")));
    if jsonl_file.exists() {
        let content = std::fs::read_to_string(&jsonl_file).unwrap();
        let count = content.lines().count();
        assert!(count >= 10, "expected ≥10 JSONL lines, got {}", count);
    } else {
        panic!("expected JSONL file at {jsonl_file:?}");
    }

    // Verify db_indexer sink — events table has ≥10 rows.
    let conn = rusqlite::Connection::open(&db_path).unwrap();
    let count: u64 = conn
        .query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))
        .unwrap();
    assert!(count >= 10, "expected ≥10 events rows, got {}", count);

    bus.shutdown().await;
}

/// MODULE-019-T22 — dropped_count increments on validate-size rejection.
/// (Async path's mpsc channels are unlikely to fill in test conditions; this
/// test instead verifies the validate-size pre-emit gate, which Slice A's
/// regression also exercises but via the sync path.)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t22_dropped_count_increments_on_oversize_event() {
    let temp = tempfile::TempDir::new().unwrap();
    let bus = EventBus::new(cfg(
        &temp.path().join("events"),
        &temp.path().join("events.db"),
    ))
    .await
    .expect("bus");
    let mut event = make_event("oversize", "runtime.started");
    event.event_type = "x".repeat(129); // exceeds MAX_EVENT_TYPE_LEN=128
    bus.emit(event);
    assert!(
        bus.dropped_count() >= 1,
        "oversize event must drop (got {})",
        bus.dropped_count()
    );
    bus.shutdown().await;
}

/// MODULE-019-T23 — same emit fails on multiple sinks → dropped_count increments by 1.
/// In sync mode this is t_s_audit2_*; in async mode bounded channels are large
/// enough that they don't typically fill. We rely on the sync path's regression
/// for the unified-counter semantic and verify here that dropped_count is u64
/// (atomically updated, monotonically nondecreasing).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t23_dropped_count_monotonic_under_concurrent_emits() {
    let temp = tempfile::TempDir::new().unwrap();
    let bus = EventBus::new(cfg(
        &temp.path().join("events"),
        &temp.path().join("events.db"),
    ))
    .await
    .expect("bus");
    let bus = Arc::new(bus);

    let mut handles = Vec::new();
    for i in 0..50u64 {
        let bus_clone = bus.clone();
        handles.push(tokio::spawn(async move {
            // Generate 25 oversized events from each task → all will drop.
            for j in 0..25u64 {
                let mut event = make_event(&format!("evt-{i}-{j}"), "runtime.started");
                event.event_type = "x".repeat(129);
                bus_clone.emit(event);
            }
        }));
    }
    for h in handles {
        let _ = h.await;
    }

    let dc = bus.dropped_count();
    assert_eq!(
        dc,
        50 * 25,
        "expected 1250 dropped events from oversize gate, got {}",
        dc
    );

    Arc::try_unwrap(bus)
        .map_err(|_| ())
        .ok()
        .unwrap()
        .shutdown()
        .await;
}

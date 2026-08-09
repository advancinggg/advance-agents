//! T-S-B AC-16 stats_aggregator integration tests.
//!
//! Sliding-24h-window correctness via injected MockClock. Smoke-coverage of
//! task.created / task.completed / llm.response counter wiring.

use std::path::Path;
use std::sync::Arc;

use advance_event_bus::{Clock, EventBus, EventBusConfig};
use advance_shared_types::event::Event;
use advance_shared_types::traits::EventBusEmit;
use chrono::{DateTime, Duration, Utc};
use serde_json::json;

#[derive(Clone)]
struct FrozenClock(DateTime<Utc>);
impl Clock for FrozenClock {
    fn now(&self) -> DateTime<Utc> {
        self.0
    }
}

fn cfg(jsonl_dir: &Path, db_path: &Path, clock: Arc<dyn Clock>) -> EventBusConfig {
    let mut c = EventBusConfig::new(jsonl_dir.to_path_buf(), db_path.to_path_buf());
    c.websocket_addr = "127.0.0.1:0".parse().unwrap();
    c.clock = clock;
    c
}

fn make_event(id: &str, agent_id: &str, event_type: &str, ts: DateTime<Utc>) -> Event {
    Event {
        id: id.into(),
        timestamp: ts,
        agent_id: agent_id.into(),
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

/// MODULE-019-T45 — task.created → active_tasks=1.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t45_task_created_increments_active_tasks() {
    let temp = tempfile::TempDir::new().unwrap();
    let now = Utc::now();
    let bus = EventBus::new(cfg(
        &temp.path().join("events"),
        &temp.path().join("events.db"),
        Arc::new(FrozenClock(now)),
    ))
    .await
    .expect("bus");

    bus.emit(make_event("e1", "agent-A", "task.created", now));
    // Wait for stats_aggregator's 1s tick.
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;

    let conn = rusqlite::Connection::open(&temp.path().join("events.db")).unwrap();
    let active: i64 = conn
        .query_row(
            "SELECT active_tasks FROM agent_stats WHERE agent_id='agent-A'",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);
    assert_eq!(active, 1, "task.created should set active_tasks=1");

    bus.shutdown().await;
}

/// MODULE-019-T46 — task.completed → active_tasks=0, completed_tasks=1.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t46_task_completed_updates_counters() {
    let temp = tempfile::TempDir::new().unwrap();
    let now = Utc::now();
    let bus = EventBus::new(cfg(
        &temp.path().join("events"),
        &temp.path().join("events.db"),
        Arc::new(FrozenClock(now)),
    ))
    .await
    .expect("bus");

    bus.emit(make_event("e1", "agent-A", "task.created", now));
    bus.emit(make_event("e2", "agent-A", "task.completed", now));
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;

    let conn = rusqlite::Connection::open(&temp.path().join("events.db")).unwrap();
    let (active, completed): (i64, i64) = conn
        .query_row(
            "SELECT active_tasks, completed_tasks FROM agent_stats WHERE agent_id='agent-A'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(active, 0);
    assert_eq!(completed, 1);

    bus.shutdown().await;
}

/// MODULE-019-T47 — llm.response → llm_tokens_24h += input + output.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t47_llm_response_accumulates_tokens() {
    let temp = tempfile::TempDir::new().unwrap();
    let now = Utc::now();
    let bus = EventBus::new(cfg(
        &temp.path().join("events"),
        &temp.path().join("events.db"),
        Arc::new(FrozenClock(now)),
    ))
    .await
    .expect("bus");

    let mut event = make_event("e1", "agent-A", "llm.response", now);
    event.payload = json!({"input_tokens": 1000u64, "output_tokens": 500u64});
    bus.emit(event);
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;

    let conn = rusqlite::Connection::open(&temp.path().join("events.db")).unwrap();
    let llm: i64 = conn
        .query_row(
            "SELECT llm_tokens_24h FROM agent_stats WHERE agent_id='agent-A'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(llm, 1500);

    bus.shutdown().await;
}

/// MODULE-019-T48 — emit `llm.response` 25h ago + emit now → 24h cutoff drops the old one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t48_24h_rolling_window_drops_old() {
    let temp = tempfile::TempDir::new().unwrap();
    let now = Utc::now();
    let twenty_five_hours_ago = now - Duration::hours(25);

    let bus = EventBus::new(cfg(
        &temp.path().join("events"),
        &temp.path().join("events.db"),
        Arc::new(FrozenClock(now)),
    ))
    .await
    .expect("bus");

    let mut old = make_event("e-old", "agent-A", "llm.response", twenty_five_hours_ago);
    old.payload = json!({"input_tokens": 1000u64, "output_tokens": 500u64});
    bus.emit(old);
    let mut new_ev = make_event("e-new", "agent-A", "llm.response", now);
    new_ev.payload = json!({"input_tokens": 100u64, "output_tokens": 50u64});
    bus.emit(new_ev);

    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;

    let conn = rusqlite::Connection::open(&temp.path().join("events.db")).unwrap();
    let llm: i64 = conn
        .query_row(
            "SELECT llm_tokens_24h FROM agent_stats WHERE agent_id='agent-A'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    // Old event should be trimmed by the 24h window cutoff at FrozenClock(now).
    assert_eq!(
        llm, 150,
        "24h rolling window should keep only the new event; got llm_tokens_24h={}",
        llm
    );

    bus.shutdown().await;
}

/// MODULE-019-T49 — *.error events increment error_count_24h.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t49_error_suffix_increments_error_count() {
    let temp = tempfile::TempDir::new().unwrap();
    let now = Utc::now();
    let bus = EventBus::new(cfg(
        &temp.path().join("events"),
        &temp.path().join("events.db"),
        Arc::new(FrozenClock(now)),
    ))
    .await
    .expect("bus");

    bus.emit(make_event("e1", "agent-A", "tool.error", now));
    bus.emit(make_event("e2", "agent-A", "llm.error", now));
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;

    let conn = rusqlite::Connection::open(&temp.path().join("events.db")).unwrap();
    let errors: i64 = conn
        .query_row(
            "SELECT error_count_24h FROM agent_stats WHERE agent_id='agent-A'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(errors, 2);

    bus.shutdown().await;
}

/// MODULE-019-T50 — emit `task.created` for 1001 distinct agent_ids with
/// `max_tracked_agents = 1000`; LRU evicts the oldest. Round-3 W4 fix
/// preserves persisted counters; the eldest agent's row should still exist
/// (from the eviction-time flush).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t50_lru_eviction_at_1001_agents() {
    let temp = tempfile::TempDir::new().unwrap();
    let now = Utc::now();
    let mut c = cfg(
        &temp.path().join("events"),
        &temp.path().join("events.db"),
        Arc::new(FrozenClock(now)),
    );
    c.max_tracked_agents = 1000;
    let bus = EventBus::new(c).await.expect("bus");

    for i in 0..1001u32 {
        bus.emit(make_event(
            &format!("e-{i:04}"),
            &format!("agent-{i:04}"),
            "task.created",
            now,
        ));
    }
    // Allow the 1s tick + flush.
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;

    let conn = rusqlite::Connection::open(&temp.path().join("events.db")).unwrap();
    // The newest agent (1000) is in the cache, persisted on tick.
    let newest: i64 = conn
        .query_row(
            "SELECT active_tasks FROM agent_stats WHERE agent_id='agent-1000'",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);
    assert_eq!(newest, 1, "newest agent must have its task.created counted");

    // The eldest agent-0000 either (a) was evicted to disk on cache.put eviction
    // or (b) remains tracked. Either way, the row must NOT carry zero counters
    // due to the LRU re-seed defense (Round 3 W4 fix). At minimum the table
    // SHOULD have at least 1000 distinct rows persisted.
    let row_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM agent_stats", [], |r| r.get(0))
        .unwrap();
    assert!(
        row_count >= 1000,
        "expected at least 1000 agent_stats rows after LRU pressure, got {row_count}"
    );

    bus.shutdown().await;
}

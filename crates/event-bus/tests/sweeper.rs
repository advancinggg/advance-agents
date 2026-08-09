//! Slice C — retention sweeper tests T58-T70 (MODULE-019 AC-19).
//!
//! Test trigger: `bus.sweep_once_for_tests().await` fires exactly ONE sweep
//! iteration deterministically, bypassing the run-loop's timer-wheel.
//!
//! All Async-mode tests use `retention_sweep_interval = 86_400s` (production
//! default) so the spawned run-loop never fires from interval during the test.
//! The single explicit `sweep_once_for_tests()` call is the only sweep that
//! advances `sweep_count`.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use advance_event_bus::{Clock, EventBus, EventBusConfig};
use advance_shared_types::traits::EventBusEmit;
use chrono::{DateTime, Utc};
use rusqlite::{Connection, OpenFlags};

#[derive(Clone)]
struct MockClock {
    fixed: DateTime<Utc>,
}
impl MockClock {
    fn at(s: &str) -> Arc<Self> {
        let fixed = DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc);
        Arc::new(Self { fixed })
    }
}
impl Clock for MockClock {
    fn now(&self) -> DateTime<Utc> {
        self.fixed
    }
}

fn cfg(
    jsonl_dir: &Path,
    db_path: &Path,
    retention_days: u32,
    clock: Arc<MockClock>,
) -> EventBusConfig {
    EventBusConfig {
        sensitive_params_source: None,
        observation_projector: None,
        jsonl_dir: jsonl_dir.to_path_buf(),
        db_path: db_path.to_path_buf(),
        websocket_addr: "127.0.0.1:0".parse().unwrap(),
        max_concurrent_ws_clients: 10,
        max_tracked_agents: 1000,
        leak_detector: None,
        clock,
        jsonl_retention_days: retention_days,
        retention_sweep_interval: Duration::from_secs(86_400),
        // Slice E (m019-slice-e) — new EventBusConfig fields default-initialized.
        trigger_bus_dispatch: None,
        mailbox_delivery_slow_threshold_ms: 1000,
    }
}

fn read_sweeper_state(db_path: &Path) -> (Option<String>, i64, i64, i64) {
    let conn = Connection::open_with_flags(
        db_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("open db");
    conn.query_row(
        "SELECT last_sweep_at, files_removed_total, bytes_freed_total, sweep_count \
         FROM sweeper_state WHERE id = 1",
        [],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
    )
    .expect("read sweeper_state row")
}

fn write_jsonl_file(jsonl_dir: &Path, name: &str, content: &str) -> u64 {
    let p = jsonl_dir.join(name);
    std::fs::write(&p, content).expect("write seed file");
    std::fs::metadata(&p).expect("metadata").len()
}

// T58 — `EventBusConfig::new` retention defaults
#[test]
fn t58_eventbusconfig_new_retention_defaults() {
    let temp = tempfile::TempDir::new().unwrap();
    let cfg = EventBusConfig::new(temp.path().join("events"), temp.path().join("events.db"));
    assert_eq!(cfg.jsonl_retention_days, 30);
    assert_eq!(cfg.retention_sweep_interval, Duration::from_secs(86_400));
}

// T59 — happy-path sweep + filename-parser adversarial-entry coverage +
// WS client receives 0 runtime.warning frames from the sweeper (silent-on-success).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t59_sweep_removes_old_files_keeps_recent_and_adversarial() {
    use futures::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    let temp = tempfile::TempDir::new().unwrap();
    let jsonl_dir = temp.path().join("events");
    let db_path = temp.path().join("events.db");
    let clock = MockClock::at("2026-05-06T12:00:00Z");
    let bus = EventBus::new(cfg(&jsonl_dir, &db_path, 30, clock))
        .await
        .expect("bus");
    let server_addr = bus.server_addr().expect("server_addr");

    // Subscribe a WS client to capture any sweeper-emitted events.
    let url = format!("ws://{server_addr}/events");
    let (mut ws, _) = tokio_tungstenite::connect_async(&url).await.expect("ws");
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Pre-seed canonical files.
    let _old1_size = write_jsonl_file(&jsonl_dir, "2026-03-15.jsonl", "old\n");
    let _old2_size = write_jsonl_file(&jsonl_dir, "2026-04-01.jsonl", "older\n");
    write_jsonl_file(&jsonl_dir, "2026-04-30.jsonl", "kept1\n");
    write_jsonl_file(&jsonl_dir, "2026-05-01.jsonl", "kept2\n");
    write_jsonl_file(&jsonl_dir, "2026-05-05.jsonl", "kept3\n");
    write_jsonl_file(&jsonl_dir, "2026-05-06.jsonl", "today\n");

    // Adversarial entries — all should be ignored by the filename parser.
    write_jsonl_file(&jsonl_dir, ".DS_Store", "{}");
    write_jsonl_file(&jsonl_dir, "2026-04-01.jsonl.tmp", "wrong-ext");
    write_jsonl_file(&jsonl_dir, "not-a-date.jsonl", "non-date stem");
    write_jsonl_file(&jsonl_dir, "2026-4-1.jsonl", "non-zero-padded"); // 8-char stem
    write_jsonl_file(&jsonl_dir, "02026-04-01.jsonl", "11-char stem"); // 11-char stem
    std::fs::create_dir_all(jsonl_dir.join("staging")).unwrap();

    bus.sweep_once_for_tests().await.expect("sweep_once");

    // Removed: 2026-03-15 + 2026-04-01.
    assert!(!jsonl_dir.join("2026-03-15.jsonl").exists());
    assert!(!jsonl_dir.join("2026-04-01.jsonl").exists());

    // Kept (within 30-day cutoff or today, OR adversarial entries skipped).
    for name in [
        "2026-04-30.jsonl",
        "2026-05-01.jsonl",
        "2026-05-05.jsonl",
        "2026-05-06.jsonl",
        ".DS_Store",
        "2026-04-01.jsonl.tmp",
        "not-a-date.jsonl",
        "2026-4-1.jsonl",
        "02026-04-01.jsonl",
    ] {
        assert!(
            jsonl_dir.join(name).exists(),
            "{name} should not have been removed"
        );
    }
    assert!(jsonl_dir.join("staging").is_dir());

    // Silent-on-success: WS client must receive 0 runtime.warning frames during
    // a successful sweep. Brief drain then shutdown — no frame within 200ms.
    let warning_check = tokio::time::timeout(Duration::from_millis(200), async {
        loop {
            match ws.next().await {
                Some(Ok(Message::Text(t))) if t.contains("runtime.warning") => {
                    panic!("sweeper emitted runtime.warning on a clean sweep: {t}");
                }
                Some(_) | None => {}
            }
        }
    })
    .await;
    // Timeout is the success path — no warning frames arrived.
    assert!(
        warning_check.is_err(),
        "expected timeout (no runtime.warning frames)"
    );

    let _ = ws.send(Message::Close(None)).await;
    bus.shutdown().await;
}

// T60 — sweeper_state row updated correctly after T59-style sweep
#[tokio::test]
async fn t60_sweeper_state_row_updated_after_sweep() {
    let temp = tempfile::TempDir::new().unwrap();
    let jsonl_dir = temp.path().join("events");
    let db_path = temp.path().join("events.db");
    let clock = MockClock::at("2026-05-06T12:00:00Z");
    let bus = EventBus::new(cfg(&jsonl_dir, &db_path, 30, clock))
        .await
        .expect("bus");

    let s1 = write_jsonl_file(&jsonl_dir, "2026-03-15.jsonl", "old\n");
    let s2 = write_jsonl_file(&jsonl_dir, "2026-04-01.jsonl", "older\n");

    bus.sweep_once_for_tests().await.expect("sweep_once");
    bus.shutdown().await;

    let (last, files, bytes, count) = read_sweeper_state(&db_path);
    assert!(last.is_some());
    assert_eq!(files, 2);
    assert_eq!(bytes as u64, s1 + s2);
    assert_eq!(count, 1);
}

// T61 — GET /query/sweeper_state returns correct JSON via in-process router
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t61_query_sweeper_state_endpoint() {
    use advance_event_bus::query_api::{query_router, QueryState};
    use axum::body::{to_bytes, Body};
    use axum::extract::ConnectInfo;
    use axum::http::{Request, StatusCode};
    use r2d2::Pool;
    use r2d2_sqlite::SqliteConnectionManager;
    use std::net::SocketAddr;
    use tower::ServiceExt;

    let temp = tempfile::TempDir::new().unwrap();
    let jsonl_dir = temp.path().join("events");
    let db_path = temp.path().join("events.db");
    let clock = MockClock::at("2026-05-06T12:00:00Z");
    let bus = EventBus::new(cfg(&jsonl_dir, &db_path, 30, clock))
        .await
        .expect("bus");

    // Match T59's pre-seed (2 old files removed) so the doc spec
    // `files_removed_total: 2` holds end-to-end.
    write_jsonl_file(&jsonl_dir, "2026-03-15.jsonl", "old\n");
    write_jsonl_file(&jsonl_dir, "2026-04-01.jsonl", "older\n");
    bus.sweep_once_for_tests().await.expect("sweep_once");
    bus.shutdown().await;

    // Open a fresh connection pool against the SAME db_path; schema already migrated.
    let mgr = SqliteConnectionManager::file(&db_path)
        .with_flags(OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX);
    let pool = Arc::new(Pool::builder().max_size(2).build(mgr).unwrap());
    let router = query_router(QueryState { pool });

    let mut request = Request::builder()
        .uri("/sweeper_state")
        .body(Body::empty())
        .unwrap();
    request.extensions_mut().insert(ConnectInfo::<SocketAddr>(
        "127.0.0.1:65000".parse().unwrap(),
    ));
    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 1_000_000).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["files_removed_total"].as_i64().unwrap(), 2);
    assert_eq!(json["sweep_count"].as_i64().unwrap(), 1);
    assert!(json["last_sweep_at"].as_str().is_some());
}

// T62 — retention_days=0 short-circuits sweep_once before sweeper_state write
#[tokio::test]
async fn t62_retention_zero_short_circuits() {
    let temp = tempfile::TempDir::new().unwrap();
    let jsonl_dir = temp.path().join("events");
    let db_path = temp.path().join("events.db");
    let clock = MockClock::at("2026-05-06T12:00:00Z");
    let bus = EventBus::new(cfg(&jsonl_dir, &db_path, 0, clock))
        .await
        .expect("bus");

    write_jsonl_file(&jsonl_dir, "2026-03-15.jsonl", "old\n");

    bus.sweep_once_for_tests().await.expect("sweep_once");
    bus.shutdown().await;

    // Old file NOT removed.
    assert!(jsonl_dir.join("2026-03-15.jsonl").exists());
    let (last, files, bytes, count) = read_sweeper_state(&db_path);
    // Initial seed values preserved (early-return skipped persist_sweep_result).
    assert!(last.is_none());
    assert_eq!(files, 0);
    assert_eq!(bytes, 0);
    assert_eq!(count, 0);
}

// T63 — today's file pinned regardless of retention=1
#[tokio::test]
async fn t63_todays_file_pinned() {
    let temp = tempfile::TempDir::new().unwrap();
    let jsonl_dir = temp.path().join("events");
    let db_path = temp.path().join("events.db");
    let clock = MockClock::at("2026-05-06T12:00:00Z");
    let bus = EventBus::new(cfg(&jsonl_dir, &db_path, 1, clock))
        .await
        .expect("bus");

    write_jsonl_file(&jsonl_dir, "2026-05-06.jsonl", "today\n");
    write_jsonl_file(&jsonl_dir, "2026-05-04.jsonl", "two-days-old\n");

    bus.sweep_once_for_tests().await.expect("sweep_once");
    bus.shutdown().await;

    assert!(jsonl_dir.join("2026-05-06.jsonl").exists());
    assert!(!jsonl_dir.join("2026-05-04.jsonl").exists());
}

// T64 + T65 — chmod 0o500 jsonl_dir blocks remove_file; warnings via events.db
#[cfg(unix)]
#[tokio::test]
async fn t64_t65_permission_denied_warnings_via_events_db() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::TempDir::new().unwrap();
    let jsonl_dir = temp.path().join("events");
    let db_path = temp.path().join("events.db");
    let clock = MockClock::at("2026-05-06T12:00:00Z");
    let bus = EventBus::new(cfg(&jsonl_dir, &db_path, 30, clock))
        .await
        .expect("bus");

    // Pre-seed 2 OLD files (after EventBus::new chmod'd jsonl_dir to 0o700).
    write_jsonl_file(&jsonl_dir, "2026-03-15.jsonl", "old\n");
    write_jsonl_file(&jsonl_dir, "2026-04-01.jsonl", "older\n");

    // Chmod jsonl_dir to 0o500 (read+execute, no write) — blocks remove_file.
    std::fs::set_permissions(&jsonl_dir, std::fs::Permissions::from_mode(0o500)).unwrap();

    bus.sweep_once_for_tests().await.expect("sweep_once");

    // Chmod BACK to 0o700 so file_writer drain succeeds + tempdir cleanup works.
    std::fs::set_permissions(&jsonl_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    bus.shutdown().await;

    // Files NOT removed (PermissionDenied).
    assert!(jsonl_dir.join("2026-03-15.jsonl").exists());
    assert!(jsonl_dir.join("2026-04-01.jsonl").exists());

    // sweeper_state recorded the failed sweep (count=1, files=0, bytes=0).
    let (_, files, bytes, count) = read_sweeper_state(&db_path);
    assert_eq!(count, 1);
    assert_eq!(files, 0);
    assert_eq!(bytes, 0);

    // T65 — events.db is the SOLE deterministic evidence path. SELECT
    // count=2 from runtime.warning rows.
    let conn = Connection::open(&db_path).unwrap();
    let warning_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM events WHERE event_type = 'runtime.warning'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        warning_count, 2,
        "expected exactly 2 runtime.warning rows in events.db"
    );

    // Verify payload structure on each warning row.
    let mut stmt = conn
        .prepare("SELECT payload FROM events WHERE event_type = 'runtime.warning'")
        .unwrap();
    let rows: Vec<String> = stmt
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    for payload_str in rows {
        let payload: serde_json::Value = serde_json::from_str(&payload_str).unwrap();
        let reason = payload["reason"].as_str().expect("reason");
        assert!(
            reason.contains("PermissionDenied") || reason.contains("permission denied"),
            "expected PermissionDenied in reason, got: {reason}"
        );
        assert!(payload["path"].as_str().expect("path").ends_with(".jsonl"));
        assert_eq!(
            payload["source"].as_str().expect("source"),
            "retention_sweeper"
        );
    }
}

// T66 — symlinks rejected on the DELETE path with runtime.warning emit
#[cfg(unix)]
#[tokio::test]
async fn t66_symlink_rejected_with_warning() {
    let temp = tempfile::TempDir::new().unwrap();
    let jsonl_dir = temp.path().join("events");
    let db_path = temp.path().join("events.db");
    let clock = MockClock::at("2026-05-06T12:00:00Z");
    let bus = EventBus::new(cfg(&jsonl_dir, &db_path, 30, clock))
        .await
        .expect("bus");

    // Sentinel target outside jsonl_dir.
    let sentinel = temp.path().join("sentinel-do-not-remove");
    std::fs::write(&sentinel, "DO NOT REMOVE").unwrap();

    // Create symlink at <jsonl_dir>/2026-04-01.jsonl pointing to sentinel.
    let link = jsonl_dir.join("2026-04-01.jsonl");
    std::os::unix::fs::symlink(&sentinel, &link).unwrap();

    bus.sweep_once_for_tests().await.expect("sweep_once");
    bus.shutdown().await;

    // Sentinel UNCHANGED (sweeper did NOT call remove_file on it).
    assert!(sentinel.exists());
    assert_eq!(std::fs::read_to_string(&sentinel).unwrap(), "DO NOT REMOVE");

    // Symlink itself also still present (rejected, not removed).
    let meta = std::fs::symlink_metadata(&link).unwrap();
    assert!(meta.file_type().is_symlink());

    // events.db has 1 runtime.warning row with reason=symlink.
    let conn = Connection::open(&db_path).unwrap();
    let payload_str: String = conn
        .query_row(
            "SELECT payload FROM events WHERE event_type = 'runtime.warning' LIMIT 1",
            [],
            |r| r.get(0),
        )
        .expect("warning row");
    let payload: serde_json::Value = serde_json::from_str(&payload_str).unwrap();
    assert_eq!(payload["reason"].as_str().unwrap(), "symlink");
    assert_eq!(payload["source"].as_str().unwrap(), "retention_sweeper");
}

// T67 — concurrent emit + sweep does not corrupt today's JSONL line count
#[tokio::test]
async fn t67_concurrent_emit_and_sweep() {
    let temp = tempfile::TempDir::new().unwrap();
    let jsonl_dir = temp.path().join("events");
    let db_path = temp.path().join("events.db");
    let clock = MockClock::at("2026-05-06T12:00:00Z");
    let bus = EventBus::new(cfg(&jsonl_dir, &db_path, 30, clock.clone()))
        .await
        .expect("bus");

    // Pre-seed only an old JSONL file (eligible to remove at retention=30).
    // NOT today's file.
    write_jsonl_file(&jsonl_dir, "2026-03-15.jsonl", "old\n");

    // Emit 100 events with timestamp = today.
    let today = clock.now();
    for i in 0..100u32 {
        let event = advance_shared_types::event::Event {
            id: format!("evt-{i:03}"),
            timestamp: today,
            agent_id: "test-agent".to_string(),
            task_id: None,
            run_id: None,
            execution_id: None,
            trace_id: format!("tr-{i:03}"),
            span_id: format!("sp-{i:03}"),
            parent_span_id: None,
            event_type: "runtime.started".to_string(),
            payload: serde_json::json!({"i": i}),
            duration_ms: None,
        };
        bus.emit(event);
    }

    // Trigger one sweep (over 2026-05-04.jsonl).
    bus.sweep_once_for_tests().await.expect("sweep_once");

    // Shutdown — post-cancel drain processes all 100 buffered events.
    bus.shutdown().await;

    // Old file removed.
    assert!(!jsonl_dir.join("2026-03-15.jsonl").exists());

    // Today's file has exactly 100 lines.
    let today_file = jsonl_dir.join("2026-05-06.jsonl");
    assert!(today_file.exists());
    let content = std::fs::read_to_string(&today_file).unwrap();
    let line_count = content.lines().count();
    assert_eq!(
        line_count, 100,
        "expected exactly 100 lines, got {line_count}"
    );
}

// T68 — two consecutive sweep ticks accumulate sweep_count + counters
#[tokio::test]
async fn t68_two_sweeps_accumulate() {
    let temp = tempfile::TempDir::new().unwrap();
    let jsonl_dir = temp.path().join("events");
    let db_path = temp.path().join("events.db");
    let clock = MockClock::at("2026-05-06T12:00:00Z");
    let bus = EventBus::new(cfg(&jsonl_dir, &db_path, 30, clock))
        .await
        .expect("bus");

    let s1 = write_jsonl_file(&jsonl_dir, "2026-03-15.jsonl", "old1\n");
    bus.sweep_once_for_tests().await.expect("sweep #1");

    let s2 = write_jsonl_file(&jsonl_dir, "2026-03-16.jsonl", "old2\n");
    bus.sweep_once_for_tests().await.expect("sweep #2");

    bus.shutdown().await;

    let (_, files, bytes, count) = read_sweeper_state(&db_path);
    assert_eq!(files, 2);
    assert_eq!(bytes as u64, s1 + s2);
    assert_eq!(count, 2);
}

// T69 — empty jsonl_dir sweep advances sweep_count without removing anything
#[tokio::test]
async fn t69_empty_dir_sweep_advances_counter_only() {
    let temp = tempfile::TempDir::new().unwrap();
    let jsonl_dir = temp.path().join("events");
    let db_path = temp.path().join("events.db");
    let clock = MockClock::at("2026-05-06T12:00:00Z");
    let bus = EventBus::new(cfg(&jsonl_dir, &db_path, 30, clock))
        .await
        .expect("bus");

    bus.sweep_once_for_tests().await.expect("sweep_once");
    bus.shutdown().await;

    let (last, files, bytes, count) = read_sweeper_state(&db_path);
    assert!(last.is_some());
    assert_eq!(files, 0);
    assert_eq!(bytes, 0);
    assert_eq!(count, 1);
}

// T70 — shutdown wakes the sweeper run-loop's sleep arm cleanly within 2s
#[tokio::test]
async fn t70_shutdown_wakes_sweeper_within_2s() {
    let temp = tempfile::TempDir::new().unwrap();
    let jsonl_dir = temp.path().join("events");
    let db_path = temp.path().join("events.db");
    let clock = MockClock::at("2026-05-06T12:00:00Z");
    // 24h sleep_interval — the run-loop is sleeping when shutdown fires.
    let bus = EventBus::new(cfg(&jsonl_dir, &db_path, 30, clock))
        .await
        .expect("bus");

    // Do NOT call sweep_once_for_tests. Immediately shutdown.
    let shutdown_fut = bus.shutdown();
    let result = tokio::time::timeout(Duration::from_secs(2), shutdown_fut).await;
    assert!(result.is_ok(), "shutdown timed out after 2s");

    // sweeper_state has only the seed row (no SWEEP iteration occurred).
    let (last, files, bytes, count) = read_sweeper_state(&db_path);
    assert!(last.is_none());
    assert_eq!(files, 0);
    assert_eq!(bytes, 0);
    assert_eq!(count, 0);
}

// T74 — Slice E sweeper cancel-first sequencing (§3.6 item 14 closure).
//
// Drives a sweep iteration that emits a runtime.warning (chmod 0o500 forces
// PermissionDenied) JUST BEFORE bus.shutdown() fires. With the Slice E
// `sweeper_cancel_token` + `sweeper_handle` named-field + 5-step shutdown
// sequence (sweeper_cancel → join → yield_now → main_cancel → join), the
// warning lands in events.db before the durable sinks drain and exit.
//
// Pre-Slice-E (shared cancel_token): the race window allowed the writer
// channels to close before the sweeper's late emit_warning crossed try_send.
// Post-Slice-E: the named-field sweeper_handle is awaited FIRST so all of
// sweep_once's emit_warning calls complete + reach the bounded mpsc channels
// before main_cancel signals the durable sinks.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t74_sweeper_cancel_first_warning_lands_before_shutdown() {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::TempDir::new().unwrap();
    let jsonl_dir = temp.path().join("events");
    let db_path = temp.path().join("events.db");
    let clock = MockClock::at("2026-05-06T12:00:00Z");
    let bus = EventBus::new(cfg(&jsonl_dir, &db_path, 30, clock))
        .await
        .expect("bus");

    // Pre-seed an old file the sweeper will attempt to remove.
    write_jsonl_file(&jsonl_dir, "2026-03-15.jsonl", "{}\n");

    // chmod jsonl_dir read+execute only — sweep_once's remove_file will
    // fail with PermissionDenied, sweep_once emit_warning fires through
    // EmitPipeline into the durable-sink mpsc channels.
    let mut perms = std::fs::metadata(&jsonl_dir).unwrap().permissions();
    perms.set_mode(0o500);
    std::fs::set_permissions(&jsonl_dir, perms).unwrap();

    // Fire the sweep deterministically.
    bus.sweep_once_for_tests().await.expect("sweep_once");

    // Restore perms so tempdir cleanup succeeds + db_indexer can drain.
    let mut perms = std::fs::metadata(&jsonl_dir).unwrap().permissions();
    perms.set_mode(0o700);
    std::fs::set_permissions(&jsonl_dir, perms).unwrap();

    // Shutdown — Slice E 5-step sequence guarantees the sweeper's warning
    // lands in events.db before durable sinks drain.
    let result = tokio::time::timeout(Duration::from_secs(5), bus.shutdown()).await;
    assert!(result.is_ok(), "shutdown must complete within 5s");

    // Verify the runtime.warning row is persisted.
    let conn =
        rusqlite::Connection::open_with_flags(&db_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("open db");
    let warning_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM events WHERE event_type = 'runtime.warning'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(
        warning_count >= 1,
        "expected ≥1 sweeper runtime.warning row in events.db after Slice E cancel-first sequencing; got {warning_count}"
    );
}

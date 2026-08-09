//! T_S A4 / A5 / A6 / A7 / A7b / A7c / A7d / A10 / A11 / A12 — double-write + rotation
//! + adversarial pre-seed (AC-04).

use std::fs;
use std::path::{Path, PathBuf};

use advance_event_bus::error::EventBusError;
use advance_event_bus::{Event, EventBus, EventBusConfig};
use advance_shared_types::traits::EventBusEmit;
use chrono::{DateTime, TimeZone, Utc};
use rusqlite::{Connection, OpenFlags};
use serde_json::json;
use tempfile::TempDir;

fn make_event(id: &str, ts: DateTime<Utc>, event_type: &str, payload: serde_json::Value) -> Event {
    Event {
        id: id.to_string(),
        timestamp: ts,
        agent_id: "agent-A".to_string(),
        task_id: Some("task-A".to_string()),
        run_id: Some("run-A".to_string()),
        execution_id: None,
        trace_id: "trace-A".to_string(),
        span_id: "span-A".to_string(),
        parent_span_id: None,
        event_type: event_type.to_string(),
        payload,
        duration_ms: None,
    }
}

fn cfg(jsonl_dir: &Path, db_path: &Path) -> EventBusConfig {
    EventBusConfig::new(jsonl_dir.to_path_buf(), db_path.to_path_buf())
}

fn count_db_events(db_path: &Path) -> u64 {
    let conn = Connection::open(db_path).expect("open db");
    let count: u64 = conn
        .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
        .expect("count events");
    count
}

fn read_jsonl(path: &Path) -> Vec<Event> {
    let content = fs::read_to_string(path).expect("read jsonl");
    content
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_str(line).expect("parse jsonl line"))
        .collect()
}

fn jsonl_path(dir: &Path, ts: DateTime<Utc>) -> PathBuf {
    dir.join(format!("{}.jsonl", ts.format("%Y-%m-%d")))
}

#[test]
fn t_s_a4_emit_one_event_double_write() {
    let temp = TempDir::new().expect("tempdir");
    let jsonl_dir = temp.path().join("events");
    let db_path = temp.path().join("events.db");
    let bus = EventBus::new_synchronous_for_tests(cfg(&jsonl_dir, &db_path)).expect("bus");

    let ts = Utc.with_ymd_and_hms(2026, 5, 3, 12, 0, 0).single().unwrap();
    let event = make_event(
        "evt-001",
        ts,
        "runtime.started",
        json!({"version": "0.1.0"}),
    );
    bus.emit(event.clone());

    let lines = read_jsonl(&jsonl_path(&jsonl_dir, ts));
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0], event);
    assert_eq!(count_db_events(&db_path), 1);
    assert_eq!(bus.dropped_count(), 0);
}

#[test]
fn t_s_a5_emit_100_events_both_sinks_count_match() {
    let temp = TempDir::new().expect("tempdir");
    let jsonl_dir = temp.path().join("events");
    let db_path = temp.path().join("events.db");
    let bus = EventBus::new_synchronous_for_tests(cfg(&jsonl_dir, &db_path)).expect("bus");

    let base = Utc.with_ymd_and_hms(2026, 5, 3, 12, 0, 0).single().unwrap();
    for i in 0..100 {
        let event = make_event(
            &format!("evt-{i:03}"),
            base + chrono::Duration::milliseconds(i as i64),
            "task.created",
            json!({"i": i}),
        );
        bus.emit(event);
    }

    let lines = read_jsonl(&jsonl_path(&jsonl_dir, base));
    assert_eq!(lines.len(), 100);
    assert_eq!(count_db_events(&db_path), 100);
    assert_eq!(bus.dropped_count(), 0);

    // Verify ordering: each event id must match index sequence.
    for (i, ev) in lines.iter().enumerate() {
        assert_eq!(ev.id, format!("evt-{i:03}"));
    }
}

#[test]
fn t_s_a6_warm_cached_writer_rotates_on_date_boundary() {
    let temp = TempDir::new().expect("tempdir");
    let jsonl_dir = temp.path().join("events");
    let db_path = temp.path().join("events.db");
    let bus = EventBus::new_synchronous_for_tests(cfg(&jsonl_dir, &db_path)).expect("bus");

    let day1 = Utc
        .with_ymd_and_hms(2026, 5, 3, 23, 59, 59)
        .single()
        .unwrap();
    let day2 = Utc.with_ymd_and_hms(2026, 5, 4, 0, 0, 1).single().unwrap();
    bus.emit(make_event("evt-day1", day1, "runtime.started", json!({})));
    bus.emit(make_event("evt-day2", day2, "task.created", json!({})));

    let day1_lines = read_jsonl(&jsonl_path(&jsonl_dir, day1));
    let day2_lines = read_jsonl(&jsonl_path(&jsonl_dir, day2));
    assert_eq!(day1_lines.len(), 1);
    assert_eq!(day2_lines.len(), 1);
    assert_eq!(day1_lines[0].id, "evt-day1");
    assert_eq!(day2_lines[0].id, "evt-day2");
    assert_eq!(count_db_events(&db_path), 2);
}

#[test]
fn t_s_a7_migration_idempotent_on_second_construct() {
    let temp = TempDir::new().expect("tempdir");
    let jsonl_dir = temp.path().join("events");
    let db_path = temp.path().join("events.db");
    let _bus1 = EventBus::new_synchronous_for_tests(cfg(&jsonl_dir, &db_path)).expect("bus1");
    drop(_bus1);
    // Second construct re-opens the pool and re-runs the migration; should be no-op.
    let _bus2 = EventBus::new_synchronous_for_tests(cfg(&jsonl_dir, &db_path)).expect("bus2");

    let conn = Connection::open(&db_path).expect("open db");
    let user_version: u32 = conn
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .expect("query user_version");
    // Slice C bumped SCHEMA_VERSION 2 → 3 (added sweeper_state table).
    assert_eq!(user_version, 3);
}

#[test]
fn t_s_a7b_pre_seeded_events_table_with_user_version_zero_rejected() {
    let temp = TempDir::new().expect("tempdir");
    let jsonl_dir = temp.path().join("events");
    let db_path = temp.path().join("events.db");
    fs::create_dir_all(&jsonl_dir).unwrap();

    // Pre-seed: create an `events` table on the file with user_version still 0.
    {
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let conn = Connection::open_with_flags(&db_path, flags).expect("seed conn");
        conn.execute("CREATE TABLE events (id TEXT)", [])
            .expect("create table");
    }

    let result = EventBus::new_synchronous_for_tests(cfg(&jsonl_dir, &db_path));
    match result.err() {
        Some(EventBusError::PreexistingTable) => {}
        Some(other) => panic!("expected PreexistingTable, got error {other:?}"),
        None => panic!("expected PreexistingTable, got Ok(EventBus)"),
    }
}

// Slice C note: pre-Slice-C, user_version=2 was unrecognized → MigrationVersionMismatch.
// Post-Slice-C, user_version=2 is valid (it triggers the v=2→v=3 upgrade arm) but the
// arm requires all 4 prior tables (events / traces / runs / agent_stats) to exist;
// pre-seeding only `user_version=2` with no tables hits the `if !events_exists ||
// !traces_exists || ... { return MigrationVersionMismatch }` short-circuit. Test name
// preserved for git history.
#[test]
fn t_s_a7c_unknown_user_version_rejected() {
    let temp = TempDir::new().expect("tempdir");
    let jsonl_dir = temp.path().join("events");
    let db_path = temp.path().join("events.db");
    fs::create_dir_all(&jsonl_dir).unwrap();

    {
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let conn = Connection::open_with_flags(&db_path, flags).expect("seed conn");
        conn.pragma_update(None, "user_version", 2u32)
            .expect("set user_version");
    }

    let result = EventBus::new_synchronous_for_tests(cfg(&jsonl_dir, &db_path));
    match result.err() {
        Some(EventBusError::MigrationVersionMismatch) => {}
        Some(other) => panic!("expected MigrationVersionMismatch, got error {other:?}"),
        None => panic!("expected MigrationVersionMismatch, got Ok(EventBus)"),
    }
}

#[test]
fn t_s_a7d_user_version_one_without_events_table_rejected() {
    let temp = TempDir::new().expect("tempdir");
    let jsonl_dir = temp.path().join("events");
    let db_path = temp.path().join("events.db");
    fs::create_dir_all(&jsonl_dir).unwrap();

    {
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let conn = Connection::open_with_flags(&db_path, flags).expect("seed conn");
        // Set user_version=1 without creating the events table → tampered.
        conn.pragma_update(None, "user_version", 1u32)
            .expect("set user_version");
    }

    let result = EventBus::new_synchronous_for_tests(cfg(&jsonl_dir, &db_path));
    match result.err() {
        Some(EventBusError::MigrationVersionMismatch) => {}
        Some(other) => panic!("expected MigrationVersionMismatch, got error {other:?}"),
        None => panic!("expected MigrationVersionMismatch, got Ok(EventBus)"),
    }
}

#[test]
fn t_s_a10_payload_with_nested_json_survives_both_sinks() {
    let temp = TempDir::new().expect("tempdir");
    let jsonl_dir = temp.path().join("events");
    let db_path = temp.path().join("events.db");
    let bus = EventBus::new_synchronous_for_tests(cfg(&jsonl_dir, &db_path)).expect("bus");

    let ts = Utc.with_ymd_and_hms(2026, 5, 3, 12, 0, 0).single().unwrap();
    let payload = json!({
        "outer": {
            "items": [
                {"name": "a", "score": 1.5},
                {"name": "b", "score": 2.5}
            ]
        }
    });
    let event = make_event("evt-nested", ts, "llm.response", payload.clone());
    bus.emit(event.clone());

    let lines = read_jsonl(&jsonl_path(&jsonl_dir, ts));
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0].payload, payload);

    let conn = Connection::open(&db_path).expect("open db");
    let stored_payload: String = conn
        .query_row(
            "SELECT payload FROM events WHERE id = ?1",
            ["evt-nested"],
            |row| row.get(0),
        )
        .expect("query payload");
    let parsed: serde_json::Value = serde_json::from_str(&stored_payload).expect("parse");
    assert_eq!(parsed, payload);
}

#[test]
fn t_s_a11_cold_start_does_not_disturb_prior_day_file() {
    let temp = TempDir::new().expect("tempdir");
    let jsonl_dir = temp.path().join("events");
    fs::create_dir_all(&jsonl_dir).unwrap();
    let db_path = temp.path().join("events.db");

    // Pre-seed yesterday's file with one prior-process event line.
    let prior_path = jsonl_dir.join("2026-05-03.jsonl");
    let prior_bytes = b"{\"id\":\"prior\",\"foo\":1}\n".to_vec();
    fs::write(&prior_path, &prior_bytes).expect("write prior");

    let bus = EventBus::new_synchronous_for_tests(cfg(&jsonl_dir, &db_path)).expect("bus");
    let new_ts = Utc.with_ymd_and_hms(2026, 5, 4, 0, 0, 1).single().unwrap();
    bus.emit(make_event("evt-new", new_ts, "task.created", json!({})));

    // Yesterday's file is byte-equal to its pre-seed (round-3 Info 4 byte-equal pin).
    let prior_after = fs::read(&prior_path).expect("read prior after");
    assert_eq!(prior_after, prior_bytes);

    // Today's file is fresh with only the new event.
    let today_path = jsonl_dir.join("2026-05-04.jsonl");
    let today_lines = read_jsonl(&today_path);
    assert_eq!(today_lines.len(), 1);
    assert_eq!(today_lines[0].id, "evt-new");
}

#[test]
fn t_s_audit1_timestamp_byte_equal_across_jsonl_and_sqlite() {
    // Round-1 audit Diff W2 fix: SQLite stored timestamp string and JSONL line's
    // timestamp string must be byte-identical for downstream raw-string joins.
    // Round-2 audit Diff Info 1 fix: parametric coverage across chrono's 4
    // auto-precision branches (0 nanos / millisecond / microsecond / 9-digit
    // nanos) to lock byte-equality across the full SecondsFormat::AutoSi ladder.
    let cases: &[(&str, i64)] = &[
        ("nano-zero", 0),
        ("nano-millis", 1_000_000),
        ("nano-micros", 1_000),
        ("nano-9digit", 123_456_789),
    ];

    for (label, ns) in cases {
        let temp = TempDir::new().expect("tempdir");
        let jsonl_dir = temp.path().join("events");
        let db_path = temp.path().join("events.db");
        let bus = EventBus::new_synchronous_for_tests(cfg(&jsonl_dir, &db_path)).expect("bus");

        let ts = Utc.with_ymd_and_hms(2026, 5, 3, 12, 0, 0).single().unwrap()
            + chrono::Duration::nanoseconds(*ns);
        let id = format!("evt-{label}");
        bus.emit(make_event(&id, ts, "runtime.started", json!({})));

        let raw_jsonl = fs::read_to_string(jsonl_path(&jsonl_dir, ts)).expect("read jsonl");
        let parsed: serde_json::Value = serde_json::from_str(raw_jsonl.trim()).expect("parse");
        let jsonl_ts_str = parsed["timestamp"]
            .as_str()
            .expect("timestamp str")
            .to_string();

        let conn = Connection::open(&db_path).expect("open db");
        let sql_ts_str: String = conn
            .query_row("SELECT timestamp FROM events WHERE id = ?1", [&id], |row| {
                row.get(0)
            })
            .expect("query timestamp");

        assert_eq!(
            jsonl_ts_str, sql_ts_str,
            "[{label}] JSONL and SQLite timestamp strings must be byte-equal"
        );
    }
}

#[cfg(unix)]
#[test]
fn t_s_audit2_dropped_count_increments_on_writer_failure() {
    // Round-1 audit Diff W1 fix: regression-lock the silent-failure semantics.
    // Round-2 audit Diff Info 4 fix: pre-create today's file then chmod the FILE
    // (not the dir) to read-only — defeats the future-fragility hazard where
    // construction-time pre-warming of the file handle would silently bypass a
    // dir-only EACCES gate.
    // Round-2 audit Diff W1 fix: `#[cfg(unix)]` gate so this test compiles cleanly
    // on Windows where `os::unix::fs::PermissionsExt` does not exist.
    use std::os::unix::fs::PermissionsExt;

    let temp = TempDir::new().expect("tempdir");
    let jsonl_dir = temp.path().join("events");
    fs::create_dir_all(&jsonl_dir).expect("create jsonl_dir");

    // Pre-create today's file so the EventBus file_writer's first emit() opens
    // an EXISTING (not creates a new) file — and we make THAT file unwritable.
    let ts = Utc.with_ymd_and_hms(2026, 5, 3, 12, 0, 0).single().unwrap();
    let today_path = jsonl_dir.join(format!("{}.jsonl", ts.format("%Y-%m-%d")));
    fs::write(&today_path, b"").expect("create today file");
    let mut perms = fs::metadata(&today_path).expect("read perms").permissions();
    perms.set_mode(0o444);
    fs::set_permissions(&today_path, perms).expect("set file readonly");

    let db_path = temp.path().join("events.db");
    let bus = EventBus::new_synchronous_for_tests(cfg(&jsonl_dir, &db_path)).expect("bus");

    bus.emit(make_event("evt-fail", ts, "runtime.started", json!({})));

    // Restore writable so tempdir cleanup works on macOS / Linux file systems
    // that honor the readonly bit at unlink time.
    let mut perms = fs::metadata(&today_path).expect("read perms").permissions();
    perms.set_mode(0o644);
    fs::set_permissions(&today_path, perms).expect("restore writable");

    assert!(
        bus.dropped_count() >= 1,
        "dropped_count must increment when a writer fails (got {})",
        bus.dropped_count()
    );
}

#[test]
fn t_s_a12_same_day_append_does_not_truncate() {
    let temp = TempDir::new().expect("tempdir");
    let jsonl_dir = temp.path().join("events");
    fs::create_dir_all(&jsonl_dir).unwrap();
    let db_path = temp.path().join("events.db");

    let date_str = "2026-05-03";
    let today_path = jsonl_dir.join(format!("{date_str}.jsonl"));
    let prior_event = json!({
        "id": "prior",
        "timestamp": "2026-05-03T11:00:00Z",
        "agent_id": "agent-A",
        "task_id": null,
        "run_id": null,
        "execution_id": null,
        "trace_id": "trace-A",
        "span_id": "span-A",
        "parent_span_id": null,
        "event_type": "runtime.started",
        "payload": null,
        "duration_ms": null
    });
    let mut prior_line = serde_json::to_string(&prior_event).expect("serialize");
    prior_line.push('\n');
    fs::write(&today_path, prior_line.as_bytes()).expect("write prior");

    let bus = EventBus::new_synchronous_for_tests(cfg(&jsonl_dir, &db_path)).expect("bus");
    let new_ts = Utc.with_ymd_and_hms(2026, 5, 3, 12, 0, 0).single().unwrap();
    bus.emit(make_event("evt-new", new_ts, "task.created", json!({})));

    // File must contain both events (prior + new), in insertion order. Append-mode
    // regression lock: a swap to OpenOptions::truncate(true) would lose `prior`.
    let parsed = read_jsonl(&today_path);
    assert_eq!(parsed.len(), 2);
    assert_eq!(parsed[0].id, "prior");
    assert_eq!(parsed[1].id, "evt-new");
}

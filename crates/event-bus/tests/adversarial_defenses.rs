//! Round-1 adversarial defenses regression locks.
//!
//! Each test exercises a specific attack vector that round-1 adversarial review
//! flagged. These are the "did we actually fix it?" gates.

use std::fs;

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
        task_id: None,
        run_id: None,
        execution_id: None,
        trace_id: "trace-A".to_string(),
        span_id: "span-A".to_string(),
        parent_span_id: None,
        event_type: event_type.to_string(),
        payload,
        duration_ms: None,
    }
}

fn cfg(jsonl_dir: &std::path::Path, db_path: &std::path::Path) -> EventBusConfig {
    EventBusConfig::new(jsonl_dir.to_path_buf(), db_path.to_path_buf())
}

#[cfg(unix)]
#[test]
fn t_s_adv_critical_1_symlink_at_jsonl_path_is_rejected() {
    // Round-1 adversarial Critical 1 fix: an attacker pre-stages
    // <jsonl_dir>/<date>.jsonl as a symlink to a sensitive file. Without the
    // O_NOFOLLOW + symlink_metadata pre-check, the EventBus would silently
    // append to the symlinked target. With the fix, the writer must refuse.
    use std::os::unix::fs::symlink;

    let temp = TempDir::new().expect("tempdir");
    let jsonl_dir = temp.path().join("events");
    fs::create_dir_all(&jsonl_dir).unwrap();
    let db_path = temp.path().join("events.db");

    // Stage a file outside the events dir as the "sensitive target".
    let sensitive_target = temp.path().join("sensitive.txt");
    fs::write(&sensitive_target, b"DO NOT TOUCH").unwrap();
    let captured_bytes = fs::read(&sensitive_target).unwrap();

    // Pre-create the daily JSONL path as a symlink to the sensitive target.
    let ts = Utc.with_ymd_and_hms(2026, 5, 3, 12, 0, 0).single().unwrap();
    let jsonl_path = jsonl_dir.join(format!("{}.jsonl", ts.format("%Y-%m-%d")));
    symlink(&sensitive_target, &jsonl_path).expect("create symlink");

    let bus = EventBus::new_synchronous_for_tests(cfg(&jsonl_dir, &db_path)).expect("bus");
    bus.emit(make_event("evt-attacker", ts, "runtime.started", json!({})));

    // Sensitive file MUST be byte-identical (not appended to).
    let after = fs::read(&sensitive_target).unwrap();
    assert_eq!(
        after, captured_bytes,
        "sensitive target must not be modified"
    );
    // Bus must have counted the failure.
    assert!(
        bus.dropped_count() >= 1,
        "dropped_count must increment for symlink rejection (got {})",
        bus.dropped_count()
    );
}

#[test]
fn t_s_adv_critical_2_oversized_event_type_rejected() {
    // Round-1 adversarial Critical 2 fix: Implementer Invariant 2 enforcement.
    // event_type ≤ 128 bytes — a 129-byte event_type must be silently dropped
    // (no panic, dropped_count increments).
    let temp = TempDir::new().expect("tempdir");
    let jsonl_dir = temp.path().join("events");
    let db_path = temp.path().join("events.db");
    let bus = EventBus::new_synchronous_for_tests(cfg(&jsonl_dir, &db_path)).expect("bus");

    let ts = Utc.with_ymd_and_hms(2026, 5, 3, 12, 0, 0).single().unwrap();
    let mut oversize = String::with_capacity(129);
    for _ in 0..129 {
        oversize.push('a');
    }
    bus.emit(make_event("evt-x", ts, &oversize, json!({})));

    assert!(
        bus.dropped_count() >= 1,
        "oversized event_type must be dropped (got dropped_count={})",
        bus.dropped_count()
    );

    // Verify the event did NOT land on either sink.
    let jsonl_path = jsonl_dir.join(format!("{}.jsonl", ts.format("%Y-%m-%d")));
    assert!(
        !jsonl_path.exists() || fs::read_to_string(&jsonl_path).unwrap().is_empty(),
        "oversized event must not appear in JSONL"
    );
    let conn = Connection::open(&db_path).expect("open db");
    let count: u64 = conn
        .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
        .expect("count");
    assert_eq!(count, 0, "oversized event must not appear in SQLite");
}

#[test]
fn t_s_adv_critical_2_oversized_payload_rejected() {
    // 65 KiB payload — Implementer Invariant 2 cap is 64 KiB.
    let temp = TempDir::new().expect("tempdir");
    let jsonl_dir = temp.path().join("events");
    let db_path = temp.path().join("events.db");
    let bus = EventBus::new_synchronous_for_tests(cfg(&jsonl_dir, &db_path)).expect("bus");

    let ts = Utc.with_ymd_and_hms(2026, 5, 3, 12, 0, 0).single().unwrap();
    // Build a string whose JSON-serialized form exceeds 64 KiB.
    let huge: String = "x".repeat(70_000);
    bus.emit(make_event(
        "evt-huge",
        ts,
        "runtime.started",
        json!({ "data": huge }),
    ));

    assert!(
        bus.dropped_count() >= 1,
        "oversized payload must be dropped (got dropped_count={})",
        bus.dropped_count()
    );
    let conn = Connection::open(&db_path).expect("open db");
    let count: u64 = conn
        .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
        .expect("count");
    assert_eq!(count, 0, "oversized payload must not appear in SQLite");
}

#[test]
fn t_s_adv_critical_2_oversized_id_rejected() {
    // 257-byte id — cap is 256.
    let temp = TempDir::new().expect("tempdir");
    let jsonl_dir = temp.path().join("events");
    let db_path = temp.path().join("events.db");
    let bus = EventBus::new_synchronous_for_tests(cfg(&jsonl_dir, &db_path)).expect("bus");

    let ts = Utc.with_ymd_and_hms(2026, 5, 3, 12, 0, 0).single().unwrap();
    let oversize_id = "i".repeat(257);
    bus.emit(make_event(&oversize_id, ts, "runtime.started", json!({})));

    assert!(
        bus.dropped_count() >= 1,
        "oversized id must be dropped (got dropped_count={})",
        bus.dropped_count()
    );
}

#[test]
fn t_s_adv_w3_column_shape_forgery_rejected() {
    // Round-1 adversarial W3 fix: pre-seeded events.db with user_version=1 and
    // an `events` table with WRONG column shape must be rejected at construction.
    let temp = TempDir::new().expect("tempdir");
    let jsonl_dir = temp.path().join("events");
    fs::create_dir_all(&jsonl_dir).unwrap();
    let db_path = temp.path().join("events.db");

    {
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let conn = Connection::open_with_flags(&db_path, flags).expect("seed");
        // Only `id TEXT` — wrong shape. Setting user_version=1 makes this look
        // like a "successful migration" to Slice A's old loose check.
        conn.execute("CREATE TABLE events (id TEXT)", [])
            .expect("create");
        conn.pragma_update(None, "user_version", 1u32)
            .expect("set version");
    }

    let result = EventBus::new_synchronous_for_tests(cfg(&jsonl_dir, &db_path));
    match result.err() {
        Some(EventBusError::InvalidColumnShape { .. }) => {}
        Some(other) => panic!("expected InvalidColumnShape, got {other:?}"),
        None => panic!("expected InvalidColumnShape, got Ok(EventBus)"),
    }
}

#[test]
fn t_s_adv_r3_w1_oversized_agent_id_rejected() {
    // Round-3 adversarial Warning 1 fix: agent_id was previously unbounded.
    let temp = TempDir::new().expect("tempdir");
    let jsonl_dir = temp.path().join("events");
    let db_path = temp.path().join("events.db");
    let bus = EventBus::new_synchronous_for_tests(cfg(&jsonl_dir, &db_path)).expect("bus");

    let ts = Utc.with_ymd_and_hms(2026, 5, 3, 12, 0, 0).single().unwrap();
    let mut event = make_event("evt-x", ts, "runtime.started", json!({}));
    event.agent_id = "a".repeat(257); // exceed MAX_ID_LEN=256
    bus.emit(event);

    assert!(
        bus.dropped_count() >= 1,
        "oversized agent_id must be dropped (got {})",
        bus.dropped_count()
    );
}

#[test]
fn t_s_adv_r3_w1_oversized_optional_ids_rejected() {
    // Round-3 adversarial Warning 1 fix: task_id, run_id, execution_id,
    // parent_span_id were unbounded. Each must be rejected at >256 bytes.
    for (label, mutator) in [
        (
            "task_id",
            Box::new(|e: &mut Event| e.task_id = Some("t".repeat(257))) as Box<dyn Fn(&mut Event)>,
        ),
        (
            "run_id",
            Box::new(|e: &mut Event| e.run_id = Some("r".repeat(257))) as Box<dyn Fn(&mut Event)>,
        ),
        (
            "execution_id",
            Box::new(|e: &mut Event| e.execution_id = Some("x".repeat(257)))
                as Box<dyn Fn(&mut Event)>,
        ),
        (
            "parent_span_id",
            Box::new(|e: &mut Event| e.parent_span_id = Some("p".repeat(257)))
                as Box<dyn Fn(&mut Event)>,
        ),
    ] {
        let temp = TempDir::new().expect("tempdir");
        let jsonl_dir = temp.path().join("events");
        let db_path = temp.path().join("events.db");
        let bus = EventBus::new_synchronous_for_tests(cfg(&jsonl_dir, &db_path)).expect("bus");

        let ts = Utc.with_ymd_and_hms(2026, 5, 3, 12, 0, 0).single().unwrap();
        let mut event = make_event("evt-x", ts, "runtime.started", json!({}));
        mutator(&mut event);
        bus.emit(event);

        assert!(
            bus.dropped_count() >= 1,
            "[{label}] oversized optional ID must be dropped (got dropped_count={})",
            bus.dropped_count()
        );
    }
}

// ---------------------------------------------------------------------------
// MODULE-019-AC-21 acceptance witnesses (Wave-17 Lane 2): MAX_ID_LEN raised
// 64 -> 256 (aligned to MODULE-006 MAX_ID_BYTES), so valid 65..=256-byte ids are
// accepted across ALL 8 id-class fields and the boundary reject holds at 257.
// ---------------------------------------------------------------------------

#[test]
fn t_w17_t79_long_id_and_agent_id_accepted() {
    // MODULE-019-T79 (AC-21): a 65-byte `id` AND a 256-byte `agent_id` are within
    // MAX_ID_LEN=256 — the event MUST be accepted (not dropped) and persisted.
    let temp = TempDir::new().expect("tempdir");
    let jsonl_dir = temp.path().join("events");
    fs::create_dir_all(&jsonl_dir).unwrap();
    let db_path = temp.path().join("events.db");
    let bus = EventBus::new_synchronous_for_tests(cfg(&jsonl_dir, &db_path)).expect("bus");

    let ts = Utc.with_ymd_and_hms(2026, 5, 3, 12, 0, 0).single().unwrap();
    let id_65 = "i".repeat(65);
    let mut event = make_event(&id_65, ts, "runtime.started", json!({}));
    event.agent_id = "a".repeat(256);
    bus.emit(event);

    assert_eq!(
        bus.dropped_count(),
        0,
        "65-byte id + 256-byte agent_id are within MAX_ID_LEN=256 — must NOT be dropped (got dropped_count={})",
        bus.dropped_count()
    );
    drop(bus); // close the pool so a fresh reader sees the committed row

    let conn = Connection::open(&db_path).expect("open db");
    let count: u64 = conn
        .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
        .expect("count");
    assert_eq!(
        count, 1,
        "the accepted long-id event must be present in SQLite"
    );
}

#[test]
fn t_w17_t80_all_id_class_fields_accept_256() {
    // MODULE-019-T80 (AC-21): each remaining id-class field accepts a 256-byte
    // value at the MAX_ID_LEN=256 boundary (the bump covers all 8 id fields, not
    // just `id`/`agent_id`).
    for (label, mutator) in [
        (
            "trace_id",
            Box::new(|e: &mut Event| e.trace_id = "z".repeat(256)) as Box<dyn Fn(&mut Event)>,
        ),
        (
            "span_id",
            Box::new(|e: &mut Event| e.span_id = "z".repeat(256)) as Box<dyn Fn(&mut Event)>,
        ),
        (
            "task_id",
            Box::new(|e: &mut Event| e.task_id = Some("z".repeat(256))) as Box<dyn Fn(&mut Event)>,
        ),
        (
            "run_id",
            Box::new(|e: &mut Event| e.run_id = Some("z".repeat(256))) as Box<dyn Fn(&mut Event)>,
        ),
        (
            "execution_id",
            Box::new(|e: &mut Event| e.execution_id = Some("z".repeat(256)))
                as Box<dyn Fn(&mut Event)>,
        ),
        (
            "parent_span_id",
            Box::new(|e: &mut Event| e.parent_span_id = Some("z".repeat(256)))
                as Box<dyn Fn(&mut Event)>,
        ),
    ] {
        let temp = TempDir::new().expect("tempdir");
        let jsonl_dir = temp.path().join("events");
        fs::create_dir_all(&jsonl_dir).unwrap();
        let db_path = temp.path().join("events.db");
        let bus = EventBus::new_synchronous_for_tests(cfg(&jsonl_dir, &db_path)).expect("bus");

        let ts = Utc.with_ymd_and_hms(2026, 5, 3, 12, 0, 0).single().unwrap();
        let mut event = make_event("evt-ok", ts, "runtime.started", json!({}));
        mutator(&mut event);
        bus.emit(event);

        assert_eq!(
            bus.dropped_count(),
            0,
            "[{label}] a 256-byte id-class field is within MAX_ID_LEN=256 — must NOT be dropped (got {})",
            bus.dropped_count()
        );
    }
}

#[test]
fn t_w17_t81_id_over_256_rejected() {
    // MODULE-019-T81 (AC-21): a 257-byte `id` is one byte over the cap and MUST
    // be dropped + absent from SQLite (the boundary reject is preserved at 256).
    let temp = TempDir::new().expect("tempdir");
    let jsonl_dir = temp.path().join("events");
    let db_path = temp.path().join("events.db");
    let bus = EventBus::new_synchronous_for_tests(cfg(&jsonl_dir, &db_path)).expect("bus");

    let ts = Utc.with_ymd_and_hms(2026, 5, 3, 12, 0, 0).single().unwrap();
    let over = "i".repeat(257);
    bus.emit(make_event(&over, ts, "runtime.started", json!({})));

    assert!(
        bus.dropped_count() >= 1,
        "257-byte id exceeds MAX_ID_LEN=256 — must be dropped (got dropped_count={})",
        bus.dropped_count()
    );
    drop(bus);

    let conn = Connection::open(&db_path).expect("open db");
    let count: u64 = conn
        .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
        .expect("count");
    assert_eq!(
        count, 0,
        "the rejected 257-byte-id event must be absent from SQLite"
    );
}

#[cfg(unix)]
#[test]
fn t_s_adv_w8_db_file_mode_is_0o600() {
    // Round-1 adversarial W8 fix: events.db must be created with 0o600 to
    // prevent world-readable info disclosure on multi-user systems.
    use std::os::unix::fs::PermissionsExt;

    let temp = TempDir::new().expect("tempdir");
    let jsonl_dir = temp.path().join("events");
    let db_path = temp.path().join("events.db");
    let _bus = EventBus::new_synchronous_for_tests(cfg(&jsonl_dir, &db_path)).expect("bus");

    let meta = fs::metadata(&db_path).expect("read db perms");
    let mode = meta.permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "events.db must be 0o600 (got 0o{:o})", mode);
}

#[test]
fn t_s_adv_r2_critical2_counting_sink_rejects_oversize_without_alloc() {
    // Round-2 adversarial Critical 2 fix regression lock: validate_event_size
    // must use a counting writer that bails out at MAX_PAYLOAD_LEN+1, NOT a
    // serialize-to-string-then-check. We verify by sending a payload whose
    // *fully serialized* form would be ~1 MiB but our limit is 64 KiB. If the
    // implementation called serde_json::to_string up-front, the test would
    // still pass on this CI box. The real OOM regression check is harder to
    // unit-test (would need 4 GiB allocation pressure), so this test focuses on
    // a payload that's structurally large but well past 64 KiB to lock the
    // bail-out behavior.
    let temp = TempDir::new().expect("tempdir");
    let jsonl_dir = temp.path().join("events");
    let db_path = temp.path().join("events.db");
    let bus = EventBus::new_synchronous_for_tests(cfg(&jsonl_dir, &db_path)).expect("bus");

    let ts = Utc.with_ymd_and_hms(2026, 5, 3, 12, 0, 0).single().unwrap();
    // ~1 MiB payload — well over 64 KiB but still fits in test memory.
    let arr: Vec<serde_json::Value> = (0..32_000)
        .map(|i| json!({"i": i, "label": "filler-string-of-length-32"}))
        .collect();
    bus.emit(make_event(
        "evt-big",
        ts,
        "runtime.started",
        json!({"arr": arr}),
    ));

    assert!(
        bus.dropped_count() >= 1,
        "1 MiB payload must be rejected (got dropped_count={})",
        bus.dropped_count()
    );
}

#[test]
fn t_s_adv_r2_w1_column_shape_missing_notnull_rejected() {
    // Round-2 adversarial W1 fix: shape-check must include NOT NULL constraints,
    // not only column name + type. Pre-seed events.db with a name+type-correct
    // table that LACKS the NOT NULL constraint on `timestamp` and `event_type`.
    let temp = TempDir::new().expect("tempdir");
    let jsonl_dir = temp.path().join("events");
    fs::create_dir_all(&jsonl_dir).unwrap();
    let db_path = temp.path().join("events.db");

    {
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let conn = Connection::open_with_flags(&db_path, flags).expect("seed");
        // All 12 columns with right names + types but timestamp/event_type
        // are NOT marked NOT NULL.
        conn.execute(
            "CREATE TABLE events (
                id TEXT PRIMARY KEY,
                timestamp TEXT,
                agent_id TEXT,
                task_id TEXT,
                run_id TEXT,
                execution_id TEXT,
                trace_id TEXT,
                span_id TEXT,
                parent_span_id TEXT,
                event_type TEXT,
                payload TEXT,
                duration_ms INTEGER
            )",
            [],
        )
        .expect("create");
        conn.pragma_update(None, "user_version", 1u32)
            .expect("set version");
    }

    let result = EventBus::new_synchronous_for_tests(cfg(&jsonl_dir, &db_path));
    match result.err() {
        Some(EventBusError::InvalidColumnShape { .. }) => {}
        Some(other) => panic!("expected InvalidColumnShape (NOT NULL forgery), got {other:?}"),
        None => panic!("expected InvalidColumnShape, got Ok(EventBus)"),
    }
}

#[test]
fn t_s_adv_r2_w1_column_shape_missing_pk_rejected() {
    // Round-2 adversarial W1 fix: shape-check must include PRIMARY KEY.
    let temp = TempDir::new().expect("tempdir");
    let jsonl_dir = temp.path().join("events");
    fs::create_dir_all(&jsonl_dir).unwrap();
    let db_path = temp.path().join("events.db");

    {
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let conn = Connection::open_with_flags(&db_path, flags).expect("seed");
        // `id` lacks PRIMARY KEY.
        conn.execute(
            "CREATE TABLE events (
                id TEXT,
                timestamp TEXT NOT NULL,
                agent_id TEXT,
                task_id TEXT,
                run_id TEXT,
                execution_id TEXT,
                trace_id TEXT,
                span_id TEXT,
                parent_span_id TEXT,
                event_type TEXT NOT NULL,
                payload TEXT,
                duration_ms INTEGER
            )",
            [],
        )
        .expect("create");
        conn.pragma_update(None, "user_version", 1u32)
            .expect("set version");
    }

    let result = EventBus::new_synchronous_for_tests(cfg(&jsonl_dir, &db_path));
    match result.err() {
        Some(EventBusError::InvalidColumnShape { .. }) => {}
        Some(other) => panic!("expected InvalidColumnShape (PK forgery), got {other:?}"),
        None => panic!("expected InvalidColumnShape, got Ok(EventBus)"),
    }
}

#[cfg(unix)]
#[test]
fn t_s_adv_r2_w3_wal_sidecar_files_are_0o600() {
    // Round-2 adversarial W3 fix: events.db-wal and events.db-shm must also be
    // chmod'd to 0o600 so WAL contents (uncheckpointed events) don't leak.
    use std::ffi::OsString;
    use std::os::unix::fs::PermissionsExt;

    let temp = TempDir::new().expect("tempdir");
    let jsonl_dir = temp.path().join("events");
    let db_path = temp.path().join("events.db");
    let bus = EventBus::new_synchronous_for_tests(cfg(&jsonl_dir, &db_path)).expect("bus");

    // Force a write so WAL/SHM sidecars exist.
    let ts = Utc.with_ymd_and_hms(2026, 5, 3, 12, 0, 0).single().unwrap();
    bus.emit(make_event("evt-wal", ts, "runtime.started", json!({})));
    drop(bus);

    // Re-construct so the sidecar-chmod path runs again with sidecars present.
    let _bus2 = EventBus::new_synchronous_for_tests(cfg(&jsonl_dir, &db_path)).expect("bus2");

    let mut wal_path = OsString::from(db_path.as_os_str());
    wal_path.push("-wal");
    let wal_pb = std::path::PathBuf::from(wal_path);
    if let Ok(meta) = fs::metadata(&wal_pb) {
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "WAL sidecar must be 0o600 (got 0o{:o})", mode);
    }
    // SHM may or may not exist depending on SQLite version; if present, check it.
    let mut shm_path = OsString::from(db_path.as_os_str());
    shm_path.push("-shm");
    let shm_pb = std::path::PathBuf::from(shm_path);
    if let Ok(meta) = fs::metadata(&shm_pb) {
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "SHM sidecar must be 0o600 (got 0o{:o})", mode);
    }
}

#[cfg(unix)]
#[test]
fn t_s_adv_r2_w6_jsonl_dir_mode_is_0o700() {
    // Round-2 adversarial W6 fix: jsonl_dir must be created with 0o700 to
    // prevent world-listing of event filenames (timing/cardinality side channel).
    use std::os::unix::fs::PermissionsExt;

    let temp = TempDir::new().expect("tempdir");
    let jsonl_dir = temp.path().join("events");
    let db_path = temp.path().join("events.db");
    let _bus = EventBus::new_synchronous_for_tests(cfg(&jsonl_dir, &db_path)).expect("bus");

    let meta = fs::metadata(&jsonl_dir).expect("read jsonl_dir perms");
    let mode = meta.permissions().mode() & 0o777;
    assert_eq!(mode, 0o700, "jsonl_dir must be 0o700 (got 0o{:o})", mode);
}

#[cfg(unix)]
#[test]
fn t_s_adv_w8_jsonl_file_mode_is_0o600() {
    // The JSONL file is also created with explicit 0o600 mode via
    // OpenOptionsExt::mode (file_writer.rs round-1 W8 fix).
    use std::os::unix::fs::PermissionsExt;

    let temp = TempDir::new().expect("tempdir");
    let jsonl_dir = temp.path().join("events");
    let db_path = temp.path().join("events.db");
    let bus = EventBus::new_synchronous_for_tests(cfg(&jsonl_dir, &db_path)).expect("bus");

    let ts = Utc.with_ymd_and_hms(2026, 5, 3, 12, 0, 0).single().unwrap();
    bus.emit(make_event("evt-mode", ts, "runtime.started", json!({})));

    let jsonl_path = jsonl_dir.join(format!("{}.jsonl", ts.format("%Y-%m-%d")));
    let meta = fs::metadata(&jsonl_path).expect("read jsonl perms");
    let mode = meta.permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "JSONL file must be 0o600 (got 0o{:o})", mode);
}

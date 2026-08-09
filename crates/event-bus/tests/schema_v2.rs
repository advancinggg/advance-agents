//! T-S-B AC-05 (4 writers active) + AC-09 schema-migration regression tests.
//!
//! Covers the v0 fresh / v1→v2 upgrade / v2 idempotent paths and column-shape
//! verification on the 3 NEW tables.

use std::path::Path;

use advance_event_bus::{EventBus, EventBusConfig, EventBusError};
use rusqlite::{Connection, OpenFlags};

fn cfg(jsonl_dir: &Path, db_path: &Path) -> EventBusConfig {
    EventBusConfig::new(jsonl_dir.to_path_buf(), db_path.to_path_buf())
}

fn open_db(db_path: &Path) -> Connection {
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    Connection::open_with_flags(db_path, flags).expect("open db")
}

/// Slice C v0 fresh path: all 5 tables created (events/traces/runs/agent_stats +
/// the Slice C sweeper_state), user_version=3.
#[test]
fn t_b_schema_v0_fresh_creates_all_4_tables() {
    let temp = tempfile::TempDir::new().unwrap();
    let jsonl_dir = temp.path().join("events");
    let db_path = temp.path().join("events.db");
    let bus = EventBus::new_synchronous_for_tests(cfg(&jsonl_dir, &db_path)).expect("bus");
    drop(bus);

    let conn = open_db(&db_path);
    let v: u32 = conn
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .unwrap();
    assert_eq!(v, 3);

    for table in ["events", "traces", "runs", "agent_stats", "sweeper_state"] {
        let exists: bool = conn
            .query_row(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1",
                [table],
                |r| r.get(0),
            )
            .unwrap_or(false);
        assert!(exists, "table {table} should exist after fresh migration");
    }
}

/// Slice B v1→v2→v3 atomic upgrade preserves existing events rows.
/// Slice C ADVERSARIAL Round 1 Critical fix: schema.rs `apply()` LOOPS
/// until version stabilizes at SCHEMA_VERSION, so a Slice A v=1 file is
/// upgraded all the way to v=3 in a single bus startup (v=1 → v=2 → v=3).
/// This test asserts the events row is preserved across both arms; the
/// final version is now v=3 (was v=2 pre-Round-1-ADVERSARIAL).
#[test]
fn t_b_schema_v1_to_v2_preserves_events_rows() {
    let temp = tempfile::TempDir::new().unwrap();
    let jsonl_dir = temp.path().join("events");
    std::fs::create_dir_all(&jsonl_dir).unwrap();
    let db_path = temp.path().join("events.db");

    // Pre-seed with Slice A schema (user_version=1, events table only) and 1 row.
    {
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let conn = Connection::open_with_flags(&db_path, flags).unwrap();
        conn.execute(
            "CREATE TABLE events (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                agent_id TEXT, task_id TEXT, run_id TEXT, execution_id TEXT,
                trace_id TEXT, span_id TEXT, parent_span_id TEXT,
                event_type TEXT NOT NULL, payload TEXT, duration_ms INTEGER
            )",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO events (id, timestamp, event_type) VALUES ('preexisting', '2026-05-01T00:00:00.000Z', 'runtime.started')",
            [],
        )
        .unwrap();
        conn.pragma_update(None, "user_version", 1u32).unwrap();
    }

    // Open with Slice B's bus — should upgrade to v2 and preserve the row.
    let _bus = EventBus::new_synchronous_for_tests(cfg(&jsonl_dir, &db_path)).expect("bus");

    let conn = open_db(&db_path);
    let v: u32 = conn
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .unwrap();
    // Slice C ADVERSARIAL Round 1 Critical fix: apply() loops until
    // SCHEMA_VERSION; v=1 file is now atomically upgraded to v=3.
    assert_eq!(v, 3);

    let count: u64 = conn
        .query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 1, "v1 row should be preserved");

    // 3 new tables exist + are empty.
    for table in ["traces", "runs", "agent_stats"] {
        let n: u64 = conn
            .query_row(&format!("SELECT COUNT(*) FROM {}", table), [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 0, "table {table} should be empty after fresh upgrade");
    }
}

/// Slice C v3 idempotent re-open: succeeds without re-creating tables.
/// Both opens go through fresh-create v=0 → v=3 (first call) then idempotent
/// v=3 (second call) — both terminate at user_version=3 post-Slice-C.
#[test]
fn t_b_schema_v2_idempotent_reopen() {
    let temp = tempfile::TempDir::new().unwrap();
    let jsonl_dir = temp.path().join("events");
    let db_path = temp.path().join("events.db");

    let _bus1 = EventBus::new_synchronous_for_tests(cfg(&jsonl_dir, &db_path)).expect("bus1");
    drop(_bus1);

    let _bus2 = EventBus::new_synchronous_for_tests(cfg(&jsonl_dir, &db_path)).expect("bus2");

    let conn = open_db(&db_path);
    let v: u32 = conn
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .unwrap();
    assert_eq!(v, 3);
}

/// Slice B v2 idempotent: forged traces table column shape rejected.
#[test]
fn t_b_schema_v2_forged_traces_shape_rejected() {
    let temp = tempfile::TempDir::new().unwrap();
    let jsonl_dir = temp.path().join("events");
    std::fs::create_dir_all(&jsonl_dir).unwrap();
    let db_path = temp.path().join("events.db");

    // Pre-seed: real events + runs + agent_stats, but forged traces (missing columns).
    {
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let conn = Connection::open_with_flags(&db_path, flags).unwrap();
        conn.execute(
            "CREATE TABLE events (
                id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, agent_id TEXT, task_id TEXT,
                run_id TEXT, execution_id TEXT, trace_id TEXT, span_id TEXT,
                parent_span_id TEXT, event_type TEXT NOT NULL, payload TEXT, duration_ms INTEGER
            )",
            [],
        )
        .unwrap();
        // Forged traces: only trace_id column.
        conn.execute("CREATE TABLE traces (trace_id TEXT PRIMARY KEY)", [])
            .unwrap();
        conn.execute(
            "CREATE TABLE runs (
                run_id TEXT PRIMARY KEY, task_id TEXT NOT NULL, controller_agent TEXT,
                status TEXT, token_used INTEGER, cost_usd REAL, last_resume_reason TEXT
            )",
            [],
        )
        .unwrap();
        conn.execute(
            "CREATE TABLE agent_stats (
                agent_id TEXT PRIMARY KEY, active_tasks INTEGER, completed_tasks INTEGER,
                avg_turns_per_task REAL, avg_completion_time_hours REAL, memory_entries INTEGER,
                llm_tokens_24h INTEGER, error_count_24h INTEGER, last_active TEXT
            )",
            [],
        )
        .unwrap();
        conn.pragma_update(None, "user_version", 2u32).unwrap();
    }

    let result = EventBus::new_synchronous_for_tests(cfg(&jsonl_dir, &db_path));
    match result.err() {
        Some(EventBusError::InvalidColumnShape { .. }) => {}
        Some(other) => panic!("expected InvalidColumnShape, got {other:?}"),
        None => panic!("expected InvalidColumnShape, got Ok(EventBus)"),
    }
}

/// Slice B v0 fresh path defensively rejects pre-existing observability tables.
#[test]
fn t_b_schema_v0_with_preseeded_tables_rejected() {
    let temp = tempfile::TempDir::new().unwrap();
    let jsonl_dir = temp.path().join("events");
    std::fs::create_dir_all(&jsonl_dir).unwrap();
    let db_path = temp.path().join("events.db");

    // Pre-seed: a `traces` table with user_version still 0 (corruption-style attack).
    {
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let conn = Connection::open_with_flags(&db_path, flags).unwrap();
        conn.execute("CREATE TABLE traces (trace_id TEXT PRIMARY KEY)", [])
            .unwrap();
    }

    let result = EventBus::new_synchronous_for_tests(cfg(&jsonl_dir, &db_path));
    match result.err() {
        Some(EventBusError::PreexistingTable) => {}
        Some(other) => panic!("expected PreexistingTable, got {other:?}"),
        None => panic!("expected PreexistingTable, got Ok(EventBus)"),
    }
}

/// Unknown user_version rejected.
#[test]
fn t_b_schema_unknown_version_rejected() {
    let temp = tempfile::TempDir::new().unwrap();
    let jsonl_dir = temp.path().join("events");
    std::fs::create_dir_all(&jsonl_dir).unwrap();
    let db_path = temp.path().join("events.db");

    {
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let conn = Connection::open_with_flags(&db_path, flags).unwrap();
        conn.pragma_update(None, "user_version", 99u32).unwrap();
    }

    let result = EventBus::new_synchronous_for_tests(cfg(&jsonl_dir, &db_path));
    match result.err() {
        Some(EventBusError::MigrationVersionMismatch) => {}
        Some(other) => panic!("expected MigrationVersionMismatch, got {other:?}"),
        None => panic!("expected MigrationVersionMismatch, got Ok(EventBus)"),
    }
}

/// Slice C v2→v3 upgrade adds sweeper_state to a complete v=2 file.
#[test]
fn t_c_schema_v2_to_v3_adds_sweeper_state_table() {
    let temp = tempfile::TempDir::new().unwrap();
    let jsonl_dir = temp.path().join("events");
    std::fs::create_dir_all(&jsonl_dir).unwrap();
    let db_path = temp.path().join("events.db");

    // Pre-seed a complete v=2 file with all 4 prior tables (events / traces /
    // runs / agent_stats) using their canonical column shapes.
    {
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let conn = Connection::open_with_flags(&db_path, flags).unwrap();
        conn.execute(
            "CREATE TABLE events (
                id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, agent_id TEXT, task_id TEXT,
                run_id TEXT, execution_id TEXT, trace_id TEXT, span_id TEXT,
                parent_span_id TEXT, event_type TEXT NOT NULL, payload TEXT, duration_ms INTEGER
            )",
            [],
        )
        .unwrap();
        conn.execute(
            "CREATE TABLE traces (
                trace_id TEXT PRIMARY KEY, start_at TEXT NOT NULL, end_at TEXT,
                total_events INTEGER, has_error INTEGER
            )",
            [],
        )
        .unwrap();
        conn.execute(
            "CREATE TABLE runs (
                run_id TEXT PRIMARY KEY, task_id TEXT NOT NULL, controller_agent TEXT,
                status TEXT, token_used INTEGER, cost_usd REAL, last_resume_reason TEXT
            )",
            [],
        )
        .unwrap();
        conn.execute(
            "CREATE TABLE agent_stats (
                agent_id TEXT PRIMARY KEY, active_tasks INTEGER, completed_tasks INTEGER,
                avg_turns_per_task REAL, avg_completion_time_hours REAL, memory_entries INTEGER,
                llm_tokens_24h INTEGER, error_count_24h INTEGER, last_active TEXT
            )",
            [],
        )
        .unwrap();
        conn.pragma_update(None, "user_version", 2u32).unwrap();
    }

    let _bus =
        EventBus::new_synchronous_for_tests(cfg(&jsonl_dir, &db_path)).expect("v2→v3 upgrade");

    let conn = open_db(&db_path);
    let v: u32 = conn
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .unwrap();
    assert_eq!(v, 3, "v=2 file should be upgraded to v=3");

    let exists: bool = conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='sweeper_state'",
            [],
            |r| r.get(0),
        )
        .unwrap_or(false);
    assert!(
        exists,
        "sweeper_state table should be created on v=2→v=3 upgrade"
    );

    // Seed row exists with NULL last_sweep_at and 0 counters.
    let (last_sweep_at, files_removed_total, bytes_freed_total, sweep_count): (
        Option<String>,
        i64,
        i64,
        i64,
    ) = conn
        .query_row(
            "SELECT last_sweep_at, files_removed_total, bytes_freed_total, sweep_count \
             FROM sweeper_state WHERE id = 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .expect("seed row");
    assert!(last_sweep_at.is_none());
    assert_eq!(files_removed_total, 0);
    assert_eq!(bytes_freed_total, 0);
    assert_eq!(sweep_count, 0);
}

/// Slice C ADVERSARIAL Round 1 Critical regression-lock (replaces the prior
/// "v=1 remains v=2" test): a v=1 file must reach v=3 atomically in a single
/// bus startup. `apply()` loops through v=1 → v=2 → v=3 in one call, so
/// `sweeper_state` IS created on first open. This closes the window where the
/// sweeper task could run against an upgrading file without `sweeper_state`.
#[test]
fn t_c_schema_v1_to_v3_atomic_in_one_open() {
    let temp = tempfile::TempDir::new().unwrap();
    let jsonl_dir = temp.path().join("events");
    std::fs::create_dir_all(&jsonl_dir).unwrap();
    let db_path = temp.path().join("events.db");

    {
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let conn = Connection::open_with_flags(&db_path, flags).unwrap();
        conn.execute(
            "CREATE TABLE events (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                agent_id TEXT, task_id TEXT, run_id TEXT, execution_id TEXT,
                trace_id TEXT, span_id TEXT, parent_span_id TEXT,
                event_type TEXT NOT NULL, payload TEXT, duration_ms INTEGER
            )",
            [],
        )
        .unwrap();
        conn.pragma_update(None, "user_version", 1u32).unwrap();
    }

    let _bus = EventBus::new_synchronous_for_tests(cfg(&jsonl_dir, &db_path)).expect("v1→…→v3");

    let conn = open_db(&db_path);
    let v: u32 = conn
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .unwrap();
    assert_eq!(
        v, 3,
        "v=1 file must atomically reach v=3 in a single bus startup"
    );

    // sweeper_state CREATED in the same apply() call (loop's v=2 → v=3 iteration).
    let sweeper_exists: bool = conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='sweeper_state'",
            [],
            |r| r.get(0),
        )
        .unwrap_or(false);
    assert!(
        sweeper_exists,
        "sweeper_state must exist after atomic v=1→v=3 migration"
    );

    // Seed row id=1 present.
    let seed_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM sweeper_state WHERE id=1", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(seed_count, 1, "seed row id=1 must be present");
}

/// Slice C ADVERSARIAL Round 1 Codex W1 regression-lock: a forged v=3 file
/// where `sweeper_state` exists with the correct shape but no row id=1 must
/// be defensively re-seeded on the idempotent path so `/query/sweeper_state`
/// returns a row immediately on first request.
#[test]
fn t_c_schema_v3_idempotent_reseeds_missing_seed_row() {
    let temp = tempfile::TempDir::new().unwrap();
    let jsonl_dir = temp.path().join("events");
    std::fs::create_dir_all(&jsonl_dir).unwrap();
    let db_path = temp.path().join("events.db");

    // Pre-seed a fully-correct v=3 file but DELETE the seed row so the
    // sweeper_state table is empty.
    {
        let _bus = EventBus::new_synchronous_for_tests(cfg(&jsonl_dir, &db_path)).expect("init v3");
    }
    {
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let conn = Connection::open_with_flags(&db_path, flags).unwrap();
        conn.execute("DELETE FROM sweeper_state", []).unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM sweeper_state", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0, "test setup invariant: table empty before re-open");
    }

    // Re-open: idempotent v=3 path should re-seed the row id=1.
    let _bus = EventBus::new_synchronous_for_tests(cfg(&jsonl_dir, &db_path)).expect("re-open");

    let conn = open_db(&db_path);
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM sweeper_state WHERE id=1", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(count, 1, "idempotent path must re-seed missing row id=1");
}

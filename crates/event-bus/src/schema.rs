//! observability events SQLite schema migration (Slice C — v3).
//!
//! Slice A shipped only the `events` table; Slice B extended to 4 tables; Slice C
//! adds `sweeper_state` (single-row counter table for the JSONL retention sweeper)
//! per MODULE-019 §1.3.3 + §1.3.5:
//!
//! - `events`        — Slice A (immutable, append-only)
//! - `traces`        — Slice B (per-trace_id summary)
//! - `runs`          — Slice B (per-run_id summary)
//! - `agent_stats`   — Slice B (per-agent rolling 24h counters)
//! - `sweeper_state` — Slice C (single-row CHECK(id=1) counter table — last_sweep_at
//!                     / files_removed_total / bytes_freed_total / sweep_count;
//!                     exposed via GET /query/sweeper_state)
//!
//! Slice A schema_version was 1; Slice B bumped to 2; Slice C bumps to 3.
//!
//! # Migration branches
//!
//! Defense-in-depth: every migration call wraps the version check + DDL + version
//! write in a `BEGIN IMMEDIATE` transaction (matches M004 `crates/database/src/schema.rs:120`).
//!
//! - `user_version == 0`: fresh database. Defensively verifies that NONE of the 5
//!   observability tables pre-exist. Pre-seeded tables are rejected with
//!   `EventBusError::PreexistingTable`. Then creates all 5 tables + indexes,
//!   seeds `sweeper_state` with row id=1, and bumps to user_version=3.
//!
//! - `user_version == 1`: Slice A → Slice B upgrade path. Verifies the existing
//!   `events` table EXISTS + verifies its column shape; adds the 3 new tables
//!   (`traces`, `runs`, `agent_stats`) + indexes transactionally; bumps to
//!   user_version=2 (HARDCODED `2u32`, NOT SCHEMA_VERSION, so the arm is
//!   independent of the constant). Slice C ADVERSARIAL Round 1 Critical fix:
//!   `apply` LOOPS until `user_version == SCHEMA_VERSION`, so a Slice A v=1
//!   file is atomically upgraded all the way to v=3 in a single bus startup
//!   (v=1 → v=2 first iteration, v=2 → v=3 second iteration). This closes the
//!   window where the sweeper task could run against a v=2 file without the
//!   `sweeper_state` table.
//!
//! - `user_version == 2`: Slice B → Slice C upgrade path. Verifies all 4 prior
//!   tables exist with correct shape + sweeper_state does NOT exist; CREATE
//!   sweeper_state + INSERT seed row; bumps to user_version=3.
//!
//! - `user_version == 3` (`v == SCHEMA_VERSION`): idempotent re-run. Verifies
//!   all 5 tables exist + verifies column shape on all 5; defensively re-seeds
//!   the `sweeper_state` row id=1 via `INSERT OR IGNORE` (Slice C ADVERSARIAL
//!   Round 1 Codex W1 fix — guards against forged-empty-table corruption).
//!
//! - else: returns `EventBusError::MigrationVersionMismatch` (refuse to operate on
//!   a file not authored by this crate).

use rusqlite::{Connection, TransactionBehavior};

use crate::error::EventBusError;

pub(crate) const SCHEMA_VERSION: u32 = 3;

const EVENTS_TABLE_LOOKUP_SQL: &str =
    "SELECT name FROM sqlite_master WHERE type='table' AND name='events' LIMIT 1";
const TRACES_TABLE_LOOKUP_SQL: &str =
    "SELECT name FROM sqlite_master WHERE type='table' AND name='traces' LIMIT 1";
const RUNS_TABLE_LOOKUP_SQL: &str =
    "SELECT name FROM sqlite_master WHERE type='table' AND name='runs' LIMIT 1";
const AGENT_STATS_TABLE_LOOKUP_SQL: &str =
    "SELECT name FROM sqlite_master WHERE type='table' AND name='agent_stats' LIMIT 1";
const SWEEPER_STATE_TABLE_LOOKUP_SQL: &str =
    "SELECT name FROM sqlite_master WHERE type='table' AND name='sweeper_state' LIMIT 1";

const CREATE_EVENTS_SQL: &str = "CREATE TABLE events (
    id TEXT PRIMARY KEY,
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
)";

const CREATE_EVENTS_INDEXES_SQL: &[&str] = &[
    "CREATE INDEX idx_events_trace ON events(trace_id)",
    "CREATE INDEX idx_events_run ON events(run_id)",
    "CREATE INDEX idx_events_agent ON events(agent_id)",
    "CREATE INDEX idx_events_type ON events(event_type)",
    "CREATE INDEX idx_events_timestamp ON events(timestamp)",
];

const CREATE_TRACES_SQL: &str = "CREATE TABLE traces (
    trace_id TEXT PRIMARY KEY,
    start_at TEXT NOT NULL,
    end_at TEXT,
    total_events INTEGER,
    has_error INTEGER
)";

const CREATE_RUNS_SQL: &str = "CREATE TABLE runs (
    run_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL,
    controller_agent TEXT,
    status TEXT,
    token_used INTEGER,
    cost_usd REAL,
    last_resume_reason TEXT
)";

const CREATE_AGENT_STATS_SQL: &str = "CREATE TABLE agent_stats (
    agent_id TEXT PRIMARY KEY,
    active_tasks INTEGER,
    completed_tasks INTEGER,
    avg_turns_per_task REAL,
    avg_completion_time_hours REAL,
    memory_entries INTEGER,
    llm_tokens_24h INTEGER,
    error_count_24h INTEGER,
    last_active TEXT
)";

/// Slice C — single-row counter table for the JSONL retention sweeper.
/// `CHECK(id=1)` enforces single-row invariant; the migration seeds row id=1
/// with NULL last_sweep_at + 0 counters via `INSERT OR IGNORE`.
const CREATE_SWEEPER_STATE_SQL: &str = "CREATE TABLE sweeper_state (
    id INTEGER PRIMARY KEY CHECK(id=1),
    last_sweep_at TEXT,
    files_removed_total INTEGER NOT NULL DEFAULT 0,
    bytes_freed_total INTEGER NOT NULL DEFAULT 0,
    sweep_count INTEGER NOT NULL DEFAULT 0
)";

const INSERT_SWEEPER_STATE_SEED_SQL: &str = "INSERT OR IGNORE INTO sweeper_state(id) VALUES(1)";

/// Expected column shape for each NEW table (Slice B): (name, declared_type, notnull, pk).
/// `events` table column shape verification is preserved as Slice A's deferral
/// (per Round-3 W8 acknowledgment): events `EXPECTED_COLUMNS` lookup happens only
/// on user_version=2 idempotent path. This array describes the NEW tables only.
const EXPECTED_TRACES_COLUMNS: &[(&str, &str, bool, bool)] = &[
    ("trace_id", "TEXT", false, true),
    ("start_at", "TEXT", true, false),
    ("end_at", "TEXT", false, false),
    ("total_events", "INTEGER", false, false),
    ("has_error", "INTEGER", false, false),
];

const EXPECTED_RUNS_COLUMNS: &[(&str, &str, bool, bool)] = &[
    ("run_id", "TEXT", false, true),
    ("task_id", "TEXT", true, false),
    ("controller_agent", "TEXT", false, false),
    ("status", "TEXT", false, false),
    ("token_used", "INTEGER", false, false),
    ("cost_usd", "REAL", false, false),
    ("last_resume_reason", "TEXT", false, false),
];

const EXPECTED_AGENT_STATS_COLUMNS: &[(&str, &str, bool, bool)] = &[
    ("agent_id", "TEXT", false, true),
    ("active_tasks", "INTEGER", false, false),
    ("completed_tasks", "INTEGER", false, false),
    ("avg_turns_per_task", "REAL", false, false),
    ("avg_completion_time_hours", "REAL", false, false),
    ("memory_entries", "INTEGER", false, false),
    ("llm_tokens_24h", "INTEGER", false, false),
    ("error_count_24h", "INTEGER", false, false),
    ("last_active", "TEXT", false, false),
];

/// Slice C — sweeper_state column shape (verified on idempotent v=3 path).
/// `id` is INTEGER PRIMARY KEY but CHECK(id=1) enforces single-row.
/// `last_sweep_at` nullable until first sweep. Counters NOT NULL with DEFAULT 0
/// so the seed row can be inserted via `INSERT OR IGNORE INTO sweeper_state(id) VALUES(1)`.
const EXPECTED_SWEEPER_STATE_COLUMNS: &[(&str, &str, bool, bool)] = &[
    ("id", "INTEGER", false, true),
    ("last_sweep_at", "TEXT", false, false),
    ("files_removed_total", "INTEGER", true, false),
    ("bytes_freed_total", "INTEGER", true, false),
    ("sweep_count", "INTEGER", true, false),
];

const EXPECTED_EVENTS_COLUMNS: &[(&str, &str, bool, bool)] = &[
    ("id", "TEXT", false, true),
    ("timestamp", "TEXT", true, false),
    ("agent_id", "TEXT", false, false),
    ("task_id", "TEXT", false, false),
    ("run_id", "TEXT", false, false),
    ("execution_id", "TEXT", false, false),
    ("trace_id", "TEXT", false, false),
    ("span_id", "TEXT", false, false),
    ("parent_span_id", "TEXT", false, false),
    ("event_type", "TEXT", true, false),
    ("payload", "TEXT", false, false),
    ("duration_ms", "INTEGER", false, false),
];

pub(crate) fn apply(conn: &mut Connection) -> Result<(), EventBusError> {
    // Slice C ADVERSARIAL Round 1 Critical fix: loop until version stabilizes at
    // SCHEMA_VERSION. Each upgrade arm performs ONE step (its own DDL + a
    // user_version bump) inside its own immediate-mode transaction. The loop
    // re-reads user_version after each commit and routes to the next arm. A
    // Slice A v=1 file therefore reaches v=3 atomically in a single
    // `EventBus::new` call (v=1 → v=2 → v=3), eliminating the window where the
    // sweeper task could run against a v=2 file without `sweeper_state`.
    //
    // Bounded loop: each iteration strictly advances version (or terminates via
    // the SCHEMA_VERSION arm or the catch-all rejection); maximum SCHEMA_VERSION
    // iterations from the v=0 starting point.
    let mut iterations: u32 = 0;
    loop {
        iterations += 1;
        // Belt-and-suspenders: reject pathological migration loops (e.g.,
        // future SCHEMA_VERSION values + unforeseen interaction). Current
        // SCHEMA_VERSION=3 needs at most 3 iterations from v=0.
        if iterations > 16 {
            return Err(EventBusError::MigrationVersionMismatch);
        }

        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let version: u32 = tx.pragma_query_value(None, "user_version", |row| row.get(0))?;

        let events_exists = table_exists(&tx, EVENTS_TABLE_LOOKUP_SQL)?;
        let traces_exists = table_exists(&tx, TRACES_TABLE_LOOKUP_SQL)?;
        let runs_exists = table_exists(&tx, RUNS_TABLE_LOOKUP_SQL)?;
        let agent_stats_exists = table_exists(&tx, AGENT_STATS_TABLE_LOOKUP_SQL)?;
        let sweeper_state_exists = table_exists(&tx, SWEEPER_STATE_TABLE_LOOKUP_SQL)?;

        match version {
            0 => {
                // Fresh DB: defensively reject any pre-existing observability tables.
                if events_exists
                    || traces_exists
                    || runs_exists
                    || agent_stats_exists
                    || sweeper_state_exists
                {
                    return Err(EventBusError::PreexistingTable);
                }
                create_all_tables(&tx)?;
                tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
                tx.commit()?;
                // create_all_tables lands directly at SCHEMA_VERSION; no further loop iteration needed.
                return Ok(());
            }
            1 => {
                // Slice A → Slice B upgrade. Events table must exist; the new 3 tables
                // must NOT exist (else mid-upgrade corruption).
                if !events_exists {
                    return Err(EventBusError::MigrationVersionMismatch);
                }
                if traces_exists || runs_exists || agent_stats_exists || sweeper_state_exists {
                    return Err(EventBusError::PreexistingTable);
                }
                // Verify events column shape on the v1→v2 upgrade path.
                verify_table_shape(&tx, "events", EXPECTED_EVENTS_COLUMNS)?;
                // Add the 3 Slice B tables transactionally.
                tx.execute(CREATE_TRACES_SQL, [])?;
                tx.execute(CREATE_RUNS_SQL, [])?;
                tx.execute(CREATE_AGENT_STATS_SQL, [])?;
                // Slice C plan Round 2 Critical fix: hardcode `2u32` (NOT
                // SCHEMA_VERSION). The Slice C ADVERSARIAL Round 1 loop wrapper
                // continues to v=2 → v=3 in the next iteration of this same
                // `apply` call.
                tx.pragma_update(None, "user_version", 2u32)?;
                tx.commit()?;
                continue;
            }
            2 => {
                // Slice B → Slice C upgrade. All 4 prior tables must exist with
                // correct column shape; sweeper_state must NOT exist yet (else
                // mid-upgrade corruption).
                if !events_exists || !traces_exists || !runs_exists || !agent_stats_exists {
                    return Err(EventBusError::MigrationVersionMismatch);
                }
                if sweeper_state_exists {
                    return Err(EventBusError::PreexistingTable);
                }
                verify_table_shape(&tx, "events", EXPECTED_EVENTS_COLUMNS)?;
                verify_table_shape(&tx, "traces", EXPECTED_TRACES_COLUMNS)?;
                verify_table_shape(&tx, "runs", EXPECTED_RUNS_COLUMNS)?;
                verify_table_shape(&tx, "agent_stats", EXPECTED_AGENT_STATS_COLUMNS)?;
                // Add the Slice C sweeper_state table + seed row.
                tx.execute(CREATE_SWEEPER_STATE_SQL, [])?;
                tx.execute(INSERT_SWEEPER_STATE_SEED_SQL, [])?;
                tx.pragma_update(None, "user_version", 3u32)?;
                tx.commit()?;
                continue;
            }
            v if v == SCHEMA_VERSION => {
                // Idempotent re-run on a v3 file. All 5 tables must exist.
                if !events_exists
                    || !traces_exists
                    || !runs_exists
                    || !agent_stats_exists
                    || !sweeper_state_exists
                {
                    return Err(EventBusError::MigrationVersionMismatch);
                }
                verify_table_shape(&tx, "events", EXPECTED_EVENTS_COLUMNS)?;
                verify_table_shape(&tx, "traces", EXPECTED_TRACES_COLUMNS)?;
                verify_table_shape(&tx, "runs", EXPECTED_RUNS_COLUMNS)?;
                verify_table_shape(&tx, "agent_stats", EXPECTED_AGENT_STATS_COLUMNS)?;
                verify_table_shape(&tx, "sweeper_state", EXPECTED_SWEEPER_STATE_COLUMNS)?;
                // Slice C ADVERSARIAL Round 1 Codex W1 fix: defensively re-seed
                // the sweeper_state row id=1. CHECK(id=1) ensures single-row
                // invariant; INSERT OR IGNORE is a no-op if the row exists.
                // Defends against a forged events.db that ships an empty
                // sweeper_state table (correct shape but no row), which would
                // otherwise make /query/sweeper_state return 500 until the
                // first sweep ON CONFLICT-inserts the row.
                tx.execute(INSERT_SWEEPER_STATE_SEED_SQL, [])?;
                tx.commit()?;
                return Ok(());
            }
            _ => return Err(EventBusError::MigrationVersionMismatch),
        }
    }
}

fn create_all_tables(tx: &rusqlite::Transaction<'_>) -> Result<(), EventBusError> {
    tx.execute(CREATE_EVENTS_SQL, [])?;
    for ddl in CREATE_EVENTS_INDEXES_SQL {
        tx.execute(ddl, [])?;
    }
    tx.execute(CREATE_TRACES_SQL, [])?;
    tx.execute(CREATE_RUNS_SQL, [])?;
    tx.execute(CREATE_AGENT_STATS_SQL, [])?;
    // Slice C: sweeper_state + seed row.
    tx.execute(CREATE_SWEEPER_STATE_SQL, [])?;
    tx.execute(INSERT_SWEEPER_STATE_SEED_SQL, [])?;
    Ok(())
}

fn table_exists(tx: &rusqlite::Transaction<'_>, lookup_sql: &str) -> Result<bool, EventBusError> {
    tx.query_row(lookup_sql, [], |row| row.get::<_, String>(0))
        .map(|_| true)
        .or_else(|err| match err {
            rusqlite::Error::QueryReturnedNoRows => Ok(false),
            other => Err(EventBusError::Db(other)),
        })
}

fn verify_table_shape(
    tx: &rusqlite::Transaction<'_>,
    table_name: &str,
    expected: &[(&str, &str, bool, bool)],
) -> Result<(), EventBusError> {
    let pragma_sql = format!("PRAGMA table_info('{}')", table_name);
    let mut stmt = tx.prepare(&pragma_sql)?;
    let rows = stmt.query_map([], |row| {
        let name: String = row.get(1)?;
        let col_type: String = row.get(2)?;
        let notnull: i64 = row.get(3)?;
        let pk: i64 = row.get(5)?;
        Ok((name, col_type, notnull != 0, pk != 0))
    })?;

    let actual: Vec<(String, String, bool, bool)> = rows.collect::<rusqlite::Result<Vec<_>>>()?;

    let fmt = |cols: &[(String, String, bool, bool)]| -> String {
        cols.iter()
            .map(|(n, t, nn, pk)| {
                format!(
                    "{n}:{t}{}{}",
                    if *nn { ":NOT_NULL" } else { "" },
                    if *pk { ":PK" } else { "" }
                )
            })
            .collect::<Vec<_>>()
            .join(",")
    };
    let expected_str: String = expected
        .iter()
        .map(|(n, t, nn, pk)| {
            format!(
                "{n}:{t}{}{}",
                if *nn { ":NOT_NULL" } else { "" },
                if *pk { ":PK" } else { "" }
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let actual_str = fmt(&actual);

    if actual.len() != expected.len() {
        return Err(EventBusError::InvalidColumnShape {
            expected: expected_str,
            got: actual_str,
        });
    }
    for ((exp_name, exp_type, exp_notnull, exp_pk), (act_name, act_type, act_notnull, act_pk)) in
        expected.iter().zip(actual.iter())
    {
        let mismatch = exp_name != act_name
            || !act_type.eq_ignore_ascii_case(exp_type)
            || exp_notnull != act_notnull
            || exp_pk != act_pk;
        if mismatch {
            return Err(EventBusError::InvalidColumnShape {
                expected: expected_str,
                got: actual_str,
            });
        }
    }
    Ok(())
}

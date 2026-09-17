use rusqlite::{Connection, TransactionBehavior};

use crate::error::DbError;

// Schema versioning is anchored on SQLite's `PRAGMA user_version`. `apply()`
// reads the current value first; if 0 (fresh database) it runs CREATE-IF-NOT-EXISTS
// migrations and writes the version, if equal it is a no-op, if anything else
// it returns DbError::SchemaMismatch. This defeats schema-spoofing where a caller
// points at a pre-populated SQLite file with attacker-shaped tables: the absence
// of our user_version sentinel triggers migrations that may fail (table-shape
// mismatches surface as rusqlite errors), and the presence of an unknown version
// is rejected outright. Forward migrations (v2+) will append to MIGRATIONS and
// bump SCHEMA_VERSION; the same gate handles stale-on-disk vs current-in-memory
// version comparisons.
/// v2 (entity-data lane E1) adds the entity projection tables. A v1 database is upgraded in
/// place: the three tables are created and `user_version` moves to 2 (the index is
/// truncate-and-rebuild at boot, so no data migration is needed).
pub(crate) const SCHEMA_VERSION: u32 = 2;

const MIGRATIONS_V2: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS entity_index (
        agent_id TEXT NOT NULL,
        entity_id TEXT NOT NULL,
        path TEXT NOT NULL,
        anchor TEXT,
        parent TEXT,
        kind TEXT NOT NULL,
        type TEXT NOT NULL,
        title TEXT,
        status TEXT,
        due_at TEXT,
        starts_at TEXT,
        ends_at TEXT,
        priority INTEGER,
        fields_json TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        UNIQUE(agent_id, entity_id)
    )",
    "CREATE TABLE IF NOT EXISTS entity_aspect (
        entity_rowid INTEGER NOT NULL,
        agent_id TEXT NOT NULL,
        aspect TEXT NOT NULL
    )",
    "CREATE TABLE IF NOT EXISTS entity_occurrence (
        entity_rowid INTEGER NOT NULL,
        agent_id TEXT NOT NULL,
        starts_at TEXT NOT NULL,
        ends_at TEXT
    )",
    "CREATE INDEX IF NOT EXISTS idx_entity_agent_path ON entity_index(agent_id, path)",
    "CREATE INDEX IF NOT EXISTS idx_entity_agent_parent ON entity_index(agent_id, parent)",
    "CREATE INDEX IF NOT EXISTS idx_entity_agent_status ON entity_index(agent_id, status)",
    "CREATE INDEX IF NOT EXISTS idx_entity_agent_due ON entity_index(agent_id, due_at)",
    "CREATE INDEX IF NOT EXISTS idx_entity_agent_starts ON entity_index(agent_id, starts_at)",
    "CREATE INDEX IF NOT EXISTS idx_entity_aspect_row ON entity_aspect(entity_rowid, aspect)",
    "CREATE INDEX IF NOT EXISTS idx_entity_occurrence_agent_starts ON entity_occurrence(agent_id, starts_at)",
    "CREATE INDEX IF NOT EXISTS idx_entity_occurrence_row ON entity_occurrence(entity_rowid)",
];

/// The version this build upgrades in place (v1: the 11 original tables).
const PREVIOUS_SCHEMA_VERSION: u32 = 1;
/// Every table name the shape checks expect at `SCHEMA_VERSION` (v1's 11 + v2's 3).
const EXPECTED_TABLES: u32 = 14;
const EXPECTED_TABLES_V1: u32 = 11;
/// SQL `IN (…)` bodies, lower-case, for the structural checks.
const V1_TABLE_NAMES: &str = "'meta_index','content_index','content_fts','memory_index',\
    'task_index','turn_index','meta_vec','content_vec','memory_vec','task_vec','turn_vec'";
const V2_TABLE_NAMES: &str = "'entity_index','entity_aspect','entity_occurrence'";
const ALL_TABLE_NAMES: &str = "'meta_index','content_index','content_fts','memory_index',\
    'task_index','turn_index','meta_vec','content_vec','memory_vec','task_vec','turn_vec',\
    'entity_index','entity_aspect','entity_occurrence'";

const MIGRATIONS: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS meta_index (
        id TEXT PRIMARY KEY,
        agent_id TEXT NOT NULL,
        directory TEXT NOT NULL,
        entry_name TEXT NOT NULL,
        description TEXT,
        tags TEXT,
        embedding BLOB,
        updated_at TEXT NOT NULL
    )",
    "CREATE TABLE IF NOT EXISTS content_index (
        id TEXT PRIMARY KEY,
        agent_id TEXT NOT NULL,
        file_path TEXT NOT NULL,
        content_preview TEXT,
        embedding BLOB,
        access_count INTEGER DEFAULT 0,
        last_accessed TEXT,
        last_modified TEXT,
        updated_at TEXT NOT NULL
    )",
    "CREATE VIRTUAL TABLE IF NOT EXISTS content_fts USING fts5(file_path, content_preview, tags)",
    "CREATE TABLE IF NOT EXISTS memory_index (
        id TEXT PRIMARY KEY,
        agent_id TEXT NOT NULL,
        type TEXT NOT NULL,
        content TEXT NOT NULL,
        tags TEXT,
        embedding BLOB,
        created_at TEXT NOT NULL,
        task_origin TEXT,
        superseded_by TEXT,
        is_active BOOLEAN DEFAULT TRUE,
        status TEXT DEFAULT 'active',
        supersession_reason TEXT,
        sources TEXT,
        access_count INTEGER DEFAULT 0,
        last_accessed TEXT
    )",
    "CREATE TABLE IF NOT EXISTS task_index (
        task_id TEXT PRIMARY KEY,
        agent_id TEXT NOT NULL,
        title TEXT NOT NULL,
        brief TEXT,
        status TEXT,
        embedding BLOB,
        last_turn_at TEXT,
        turns_total INTEGER,
        updated_at TEXT
    )",
    "CREATE TABLE IF NOT EXISTS turn_index (
        id TEXT PRIMARY KEY,
        agent_id TEXT NOT NULL,
        task_id TEXT NOT NULL,
        turn INTEGER NOT NULL,
        timestamp TEXT NOT NULL,
        digest TEXT NOT NULL,
        importance TEXT,
        reference_count INTEGER DEFAULT 0,
        has_user_instruction BOOLEAN,
        has_user_correction BOOLEAN,
        has_tool_use BOOLEAN,
        has_decision BOOLEAN,
        embedding BLOB,
        tokens_digest INTEGER,
        tokens_l0_processed INTEGER,
        access_count INTEGER DEFAULT 0,
        last_accessed TEXT
    )",
    "CREATE INDEX IF NOT EXISTS idx_meta_agent_dir ON meta_index(agent_id, directory)",
    "CREATE INDEX IF NOT EXISTS idx_content_agent_path ON content_index(agent_id, file_path)",
    "CREATE INDEX IF NOT EXISTS idx_memory_agent_active ON memory_index(agent_id, is_active, status)",
    "CREATE INDEX IF NOT EXISTS idx_task_agent_status ON task_index(agent_id, status)",
    "CREATE INDEX IF NOT EXISTS idx_turn_task ON turn_index(task_id, turn)",
    "CREATE VIRTUAL TABLE IF NOT EXISTS meta_vec USING vec0(embedding float[768])",
    "CREATE VIRTUAL TABLE IF NOT EXISTS content_vec USING vec0(embedding float[768])",
    "CREATE VIRTUAL TABLE IF NOT EXISTS memory_vec USING vec0(embedding float[768])",
    "CREATE VIRTUAL TABLE IF NOT EXISTS task_vec USING vec0(embedding float[768])",
    "CREATE VIRTUAL TABLE IF NOT EXISTS turn_vec USING vec0(embedding float[768])",
];

pub(crate) fn apply(conn: &mut Connection) -> Result<(), DbError> {
    // Wrap the entire apply() in a transaction so:
    //   (a) Mid-apply crash (SIGKILL, OOM, disk-full at the 10th CREATE) does
    //       NOT leave the file in a half-migrated state — the COMMIT happens
    //       only after every migration statement + the user_version write
    //       succeed, and an aborted transaction rolls back atomically.
    //   (b) Concurrent run_migrations() callers serialize on the database-
    //       level write lock that BEGIN IMMEDIATE acquires, eliminating the
    //       check-then-act CAS race where two callers both see user_version=0
    //       and both run the migration set.
    //   (c) The user_version write happens inside the same transaction as the
    //       DDL, so a reader can never observe "all 16 tables present, but
    //       user_version still 0" or vice versa.
    // BEGIN IMMEDIATE acquires the database-level RESERVED lock at BEGIN
    // time, NOT lazily on first write. This makes the user_version
    // check-then-act CAS sequence below race-free: a second concurrent caller
    // blocks at BEGIN IMMEDIATE until the first transaction commits, then
    // re-reads `user_version = 1` and skips the migration body. The default
    // `conn.transaction()` would use DEFERRED — which lets two readers race
    // past `query_row("PRAGMA user_version")` before either acquires a write
    // lock, defeating the CAS guarantee documented above.
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

    let stored: u32 = tx.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    // v1 → v2 upgrade (entity-data lane E1): a database at the previous version is
    // accepted (after the same structural checks a current-version file gets, over the
    // tables v1 promises) and gains the entity tables; any other foreign version is refused.
    if stored != 0 && stored != SCHEMA_VERSION && stored != PREVIOUS_SCHEMA_VERSION {
        // Rollback is automatic when `tx` drops without commit.
        return Err(DbError::SchemaMismatch {
            stored,
            expected: SCHEMA_VERSION,
        });
    }
    if stored != 0 {
        // user_version matches (or is the upgradable predecessor) but the file may have been
        // pre-seeded with the version marker only — empty (no tables) or attacker-shaped (some
        // expected tables missing, others forged). Defense-in-depth: require
        // ALL expected names of that version to exist as type='table' rows in sqlite_master
        // (FTS5 + vec0 virtual tables both appear under type='table'; their
        // shadow tables get separate rows but are not counted by this filter).
        // Filtering on type='table' specifically defeats round-9's
        // view/index/trigger forgery: 11 forged views (or indexes, or
        // triggers) sharing the expected names would inflate a name-only
        // count to 11 but type='table' rejects them.
        // Full column-shape validation (forged-table-with-matching-shape)
        // remains deferred per §3.6.
        let (name_list, expected) = if stored == PREVIOUS_SCHEMA_VERSION {
            (V1_TABLE_NAMES, EXPECTED_TABLES_V1)
        } else {
            (ALL_TABLE_NAMES, EXPECTED_TABLES)
        };
        let existing: u32 = tx.query_row(
            &format!(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND LOWER(name) IN ({name_list})"
            ),
            [],
            |r| r.get(0),
        )?;
        if existing != expected {
            return Err(DbError::InvalidConfig(format!(
                "user_version={stored} but only {existing}/{expected} expected tables \
                 present (type='table' filter, case-insensitive) — refusing to trust \
                 pre-seeded version marker without the corresponding schema; this likely \
                 indicates a tampered file"
            )));
        }

        // Defense-in-depth (round-10 closure): in SQLite, ordinary tables and
        // virtual tables both appear under `type='table'`. An attacker who
        // plants 11 *ordinary* tables with the expected names — including the
        // 6 names we expect to be virtual (`content_fts` as fts5, `*_vec` as
        // vec0) — would pass the count==11 check above, defeating the
        // existence guard. Verify the 6 virtual-table names CREATE statement
        // contains the expected module token (case-insensitive). This is not
        // full column-shape validation (still deferred per §3.6) but it
        // closes the ordinary-table impersonation of virtual-table names.
        // sqlite_master.sql preserves the CREATE-time SQL text verbatim;
        // `LIKE` with `%fts5%` / `%vec0%` matches the module clause as
        // produced by both bundled SQLite and our migrations.
        let virtuals_ok: u32 = tx.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND ( \
                (LOWER(name) = 'content_fts' AND LOWER(sql) LIKE '%fts5%') OR \
                (LOWER(name) IN ('meta_vec','content_vec','memory_vec','task_vec','turn_vec') \
                 AND LOWER(sql) LIKE '%vec0%') \
             )",
            [],
            |r| r.get(0),
        )?;
        if virtuals_ok != 6 {
            return Err(DbError::InvalidConfig(format!(
                "user_version={stored} but only {virtuals_ok}/6 virtual-table \
                 expected-name rows have the correct module token (fts5/vec0) in their \
                 CREATE SQL — likely an ordinary-table impersonation of FTS5/vec0 \
                 surfaces at one of the expected names"
            )));
        }
        if stored == PREVIOUS_SCHEMA_VERSION {
            // A v1 file must not already carry objects under the v2 names (any object kind,
            // case-insensitive — the same rule the fresh-database check applies): the
            // CREATE-IF-NOT-EXISTS upgrade would otherwise bless a planted shape as v2.
            let planted: u32 = tx.query_row(
                &format!(
                    "SELECT COUNT(*) FROM sqlite_master WHERE LOWER(name) IN ({V2_TABLE_NAMES})"
                ),
                [],
                |r| r.get(0),
            )?;
            if planted > 0 {
                return Err(DbError::InvalidConfig(format!(
                    "user_version={stored} but {planted} object(s) already use the version-\
                     {SCHEMA_VERSION} table names — refusing to upgrade over an unknown shape; \
                     this likely indicates a tampered file"
                )));
            }
        }
    }
    if stored == 0 {
        // A fresh database (user_version = 0) MUST be truly empty. Reject
        // any pre-existing expected tables — if an attacker plants a database
        // file with attacker-shaped tables (or attacker-chosen vec0
        // dimensions, or extra fts5 columns) but leaves user_version=0, the
        // CREATE-IF-NOT-EXISTS migrations would otherwise silently no-op
        // over the forged tables and then write user_version=1, blessing
        // the forgery as version-1 trusted state. This check closes that
        // attack vector at Slice A's trust boundary across ALL expected
        // tables: 5 primary `*_index` + content_fts + 5 vec virtual tables.
        // No `type=...` filter: SQLite has 4 object kinds (table, index, view,
        // trigger). A `CREATE VIEW <expected_name>` planted by an attacker
        // would survive a `type='table'` filter, then silently no-op past
        // `CREATE VIRTUAL TABLE IF NOT EXISTS <expected_name>` (SQLite shares
        // the name namespace across kinds). Empirically reproduced by the
        // round-6 adversarial evaluator. Counting ANY object with one of the
        // expected names closes that bypass for views, triggers, and any
        // future SQLite object kinds.
        // `LOWER(name)` defends against case-variant prepopulation: SQLite
        // preserves the CREATE-time casing in sqlite_master.name (so
        // `CREATE TABLE "Meta_Index"` stores `Meta_Index`), but identifier
        // resolution at query/CREATE-IF-NOT-EXISTS time is case-insensitive.
        // A planted `META_INDEX` / `Content_Fts` would otherwise miss our
        // case-sensitive IN-list. Lowercasing both sides forecloses every
        // case variant the attacker could plant.
        let preexisting: u32 = tx.query_row(
            &format!("SELECT COUNT(*) FROM sqlite_master WHERE LOWER(name) IN ({ALL_TABLE_NAMES})"),
            [],
            |r| r.get(0),
        )?;
        if preexisting > 0 {
            return Err(DbError::InvalidConfig(format!(
                "fresh database (user_version=0) must be empty, but {preexisting} expected \
                 table(s) already exist — refusing to migrate over an unknown shape; this \
                 likely indicates a tampered file or a mis-routed db_path"
            )));
        }
    }
    for stmt in MIGRATIONS {
        tx.execute(stmt, [])?;
    }
    for stmt in MIGRATIONS_V2 {
        tx.execute(stmt, [])?;
    }
    // PRAGMA user_version takes a literal integer, not a bound parameter
    // (SQLite syntax restriction). SCHEMA_VERSION is a compile-time constant —
    // safe to format inline.
    tx.execute_batch(&format!("PRAGMA user_version = {SCHEMA_VERSION}"))?;

    tx.commit()?;
    Ok(())
}

//! `RusqliteSqliteIndex` — durable, on-disk implementation of the cap-memory
//! internal [`SqliteIndex`] seam (slice m011-memory-persist, AC-41).
//!
//! A self-contained `rusqlite` + `r2d2` backend that owns 3 tables
//! (`cap_turn_index` / `cap_task_index` / `cap_memory_index`) and stores
//! embeddings as little-endian f32 BLOBs (NO `sqlite-vec` — the [`SqliteIndex`]
//! trait does key/agent lookups, not vector similarity). It mirrors the
//! connection-pool + PRAGMA pattern of `crates/database/src/handle.rs`
//! (`journal_mode=WAL`, `synchronous=NORMAL`, `busy_timeout=5000`,
//! `case_sensitive_like=1`) WITHOUT depending on `advance-database`.
//!
//! ## Why self-contained (not delegating to MODULE-004 CONTRACT-030)
//! `advance_database::R2d2SqliteIndexHandle::new` hard-runs MODULE-004's
//! 11-table migration + schema-version guard on construction, and its `*_vec`
//! tables are fixed `float[768]` — incompatible with cap-memory's 8-dim stub
//! embeddings; the parallel-slice conflict policy also forbids editing
//! `crates/database`. So the *pattern* is reused, not the crate. The
//! `SqliteIndex` trait is cap-memory-internal (see `sqlite_index.rs`), so this
//! is an internal-seam implementation detail (MODULE-011 §2.1.1 ADR-check
//! Option B; §3.8 note 15(d)). The shared semantic/vector retrieval index that
//! AC-19 ultimately needs remains MODULE-004 CONTRACT-030 and is deferred.
//!
//! ## Error posture
//! [`open`](RusqliteSqliteIndex::open) returns a `Result` (construction +
//! schema creation are fault-surfacing). The [`SqliteIndex`] **trait** methods
//! are infallible by signature (matching the `InMemorySqliteIndex` stub), so on
//! the trait surface per-op SQL/pool errors are best-effort-swallowed (a failed
//! upsert is dropped; `get` returns `None`; `list` returns empty) — which, on a
//! durable backend, is a silent-write-loss mode the in-memory stub cannot have.
//! To avoid relying on that swallow, the SAME operations are exposed as
//! **public, fallible** [`try_upsert_turn`](RusqliteSqliteIndex::try_upsert_turn)
//! / `try_get_*` / `try_list_*` methods returning `Result<_, SqliteIndexError>`;
//! the deferred ③/MODULE-004 runtime-wiring slice that swaps this impl into
//! `Components.sqlite_index` SHOULD drive those (or land a `Result`-returning
//! trait revision) so SQL/pool/disk failures surface instead of vanishing. The
//! infallible trait impl simply delegates to the `try_*` methods and discards
//! their error. (CW3.)
//!
//! The trait methods of the vector catch-up are the exception — the two
//! `list_*_not_of_model`, the two `set_*_embedding` and `forget_agent` return
//! `Result<_, IndexUnavailable>`: there a swallowed failure would read as
//! "nothing left to embed", "the text changed" or "the agent's rows are gone".

use std::path::Path;
use std::sync::OnceLock;

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, OptionalExtension};

use crate::sqlite_index::{
    IndexUnavailable, MemoryIndexRow, SqliteIndex, TaskIndexRow, TurnIndexRow,
};

/// DDL for the 3 cap-memory-owned tables (+ per-agent indexes). `IF NOT EXISTS`
/// so re-`open` over an existing DB is a no-op. A task row is one agent's view of
/// a task, so it is keyed `(agent_id, task_id)` (see [`TaskIndexRow`]); a file
/// created with the older `task_id`-only key is rebuilt by
/// [`ensure_task_rows_per_agent`].
const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS cap_turn_index (
    agent_id        TEXT    NOT NULL,
    task_id         TEXT    NOT NULL,
    turn            INTEGER NOT NULL,
    digest          TEXT    NOT NULL,
    embedding       BLOB    NOT NULL,
    reference_count INTEGER NOT NULL,
    updated_at      TEXT    NOT NULL,
    embedding_model TEXT,
    PRIMARY KEY (agent_id, task_id, turn)
);
CREATE TABLE IF NOT EXISTS cap_task_index (
    task_id         TEXT    NOT NULL,
    agent_id        TEXT    NOT NULL,
    last_turn_at    TEXT    NOT NULL,
    turns_total     INTEGER NOT NULL,
    updated_at      TEXT    NOT NULL,
    brief_snapshot  TEXT    NOT NULL,
    brief_embedding BLOB,
    brief_embedding_model TEXT,
    PRIMARY KEY (agent_id, task_id)
);
CREATE TABLE IF NOT EXISTS cap_memory_index (
    agent_id         TEXT NOT NULL,
    memory_id        TEXT NOT NULL,
    epistemic_status TEXT NOT NULL,
    updated_at       TEXT NOT NULL,
    PRIMARY KEY (agent_id, memory_id)
);
CREATE INDEX IF NOT EXISTS idx_cap_turn_agent   ON cap_turn_index(agent_id);
CREATE INDEX IF NOT EXISTS idx_cap_task_agent   ON cap_task_index(agent_id);
CREATE INDEX IF NOT EXISTS idx_cap_memory_agent ON cap_memory_index(agent_id);
-- The order an agent's turn rows are read in (a recall read, the upkeep of their
-- vectors): its newest rows are found without sorting all of them.
CREATE INDEX IF NOT EXISTS idx_cap_turn_recent
    ON cap_turn_index(agent_id, updated_at DESC, task_id, turn);
";

/// Construction / schema error for [`RusqliteSqliteIndex::open`].
#[derive(Debug)]
pub enum SqliteIndexError {
    Pool(String),
    Sql(String),
    /// Refused a planted symlink leaf at the durable-index path (satB-postproc
    /// adversarial r15 / Codex W1) — opening would let rusqlite write the
    /// database outside the owner-only `.agent/memory` root.
    Rejected(String),
}

impl std::fmt::Display for SqliteIndexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SqliteIndexError::Pool(s) => write!(f, "rusqlite pool error: {s}"),
            SqliteIndexError::Sql(s) => write!(f, "rusqlite sql error: {s}"),
            SqliteIndexError::Rejected(s) => write!(f, "rusqlite index rejected: {s}"),
        }
    }
}

impl std::error::Error for SqliteIndexError {}

/// Per-connection PRAGMA setup, mirroring `database/handle.rs::PragmaCustomizer`.
#[derive(Debug)]
struct PragmaCustomizer;

impl r2d2::CustomizeConnection<rusqlite::Connection, rusqlite::Error> for PragmaCustomizer {
    fn on_acquire(&self, conn: &mut rusqlite::Connection) -> Result<(), rusqlite::Error> {
        conn.execute_batch(
            "PRAGMA journal_mode = WAL; \
             PRAGMA synchronous = NORMAL; \
             PRAGMA busy_timeout = 5000; \
             PRAGMA case_sensitive_like = 1;",
        )
    }
}

/// Durable rusqlite-backed [`SqliteIndex`]. Holds an r2d2 connection pool over
/// an on-disk SQLite file.
pub struct RusqliteSqliteIndex {
    pool: Pool<SqliteConnectionManager>,
}

impl std::fmt::Debug for RusqliteSqliteIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RusqliteSqliteIndex")
            .finish_non_exhaustive()
    }
}

impl RusqliteSqliteIndex {
    /// Open (or create) the SQLite file at `db_path`, build the pool with the
    /// WAL/PRAGMA customizer, and create the 3 tables. Surfaces pool + schema
    /// errors.
    pub fn open(db_path: impl AsRef<Path>) -> Result<Self, SqliteIndexError> {
        let db_path = db_path.as_ref();
        // Hardening (satB-postproc adversarial r15 / Codex W1): refuse to open the
        // durable index through a planted symlink leaf — a symlinked DB file would
        // let rusqlite write the database outside the owner-only `.agent/memory`
        // root. Mirrors the YAML-leaf non-regular-file refusal in
        // `post_processor::read_capped_yaml` + `persistence::atomic_write`'s
        // rename-replace. Non-guest-reachable (0700 tree); defense-in-depth.
        if let Ok(md) = std::fs::symlink_metadata(db_path) {
            if md.file_type().is_symlink() {
                return Err(SqliteIndexError::Rejected(format!(
                    "refusing to open durable index through a symlink: {}",
                    db_path.display()
                )));
            }
        }
        let manager = SqliteConnectionManager::file(db_path);
        let pool = Pool::builder()
            .connection_customizer(Box::new(PragmaCustomizer))
            .build(manager)
            .map_err(|e| SqliteIndexError::Pool(e.to_string()))?;
        let mut conn = pool
            .get()
            .map_err(|e| SqliteIndexError::Pool(e.to_string()))?;
        conn.execute_batch(SCHEMA)
            .map_err(|e| SqliteIndexError::Sql(e.to_string()))?;
        // An index created before vectors were bound to their model lacks the
        // model columns (`CREATE TABLE IF NOT EXISTS` never alters a table) ...
        ensure_text_column(&conn, "cap_turn_index", "embedding_model")?;
        ensure_text_column(&conn, "cap_task_index", "brief_embedding_model")?;
        // ... and one created before task rows were kept per agent still has the
        // `task_id`-only key. Runs after the column exists: the rebuild copies it.
        ensure_task_rows_per_agent(&mut conn)?;
        Ok(Self { pool })
    }

    // ── Public fallible ops (CW3). The infallible trait methods below delegate
    //    to these and discard the error; a caller that needs error-surfacing
    //    (the deferred runtime-wiring slice) calls the `try_*` API directly. ──

    pub fn try_upsert_turn(&self, row: &TurnIndexRow) -> Result<(), SqliteIndexError> {
        let conn = self
            .pool
            .get()
            .map_err(|e| SqliteIndexError::Pool(e.to_string()))?;
        conn.execute(
            "INSERT INTO cap_turn_index
               (agent_id, task_id, turn, digest, embedding, reference_count, updated_at,
                embedding_model)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(agent_id, task_id, turn) DO UPDATE SET
               digest          = excluded.digest,
               embedding       = excluded.embedding,
               reference_count = excluded.reference_count,
               updated_at      = excluded.updated_at,
               embedding_model = excluded.embedding_model",
            params![
                row.agent_id,
                row.task_id,
                row.turn,
                row.digest,
                embedding_to_blob(&row.embedding),
                row.reference_count,
                row.updated_at,
                row.embedding_model,
            ],
        )
        .map_err(|e| SqliteIndexError::Sql(e.to_string()))?;
        Ok(())
    }

    pub fn try_upsert_task(&self, row: &TaskIndexRow) -> Result<(), SqliteIndexError> {
        let conn = self
            .pool
            .get()
            .map_err(|e| SqliteIndexError::Pool(e.to_string()))?;
        let brief_blob: Option<Vec<u8>> =
            row.brief_embedding.as_ref().map(|e| embedding_to_blob(e));
        conn.execute(
            "INSERT INTO cap_task_index
               (task_id, agent_id, last_turn_at, turns_total, updated_at, brief_snapshot,
                brief_embedding, brief_embedding_model)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(agent_id, task_id) DO UPDATE SET
               last_turn_at    = excluded.last_turn_at,
               turns_total     = excluded.turns_total,
               updated_at      = excluded.updated_at,
               brief_snapshot  = excluded.brief_snapshot,
               brief_embedding = excluded.brief_embedding,
               brief_embedding_model = excluded.brief_embedding_model",
            params![
                row.task_id,
                row.agent_id,
                row.last_turn_at,
                row.turns_total,
                row.updated_at,
                row.brief_snapshot,
                brief_blob,
                row.brief_embedding_model,
            ],
        )
        .map_err(|e| SqliteIndexError::Sql(e.to_string()))?;
        Ok(())
    }

    pub fn try_upsert_memory(&self, row: &MemoryIndexRow) -> Result<(), SqliteIndexError> {
        let conn = self
            .pool
            .get()
            .map_err(|e| SqliteIndexError::Pool(e.to_string()))?;
        conn.execute(
            "INSERT INTO cap_memory_index
               (agent_id, memory_id, epistemic_status, updated_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(agent_id, memory_id) DO UPDATE SET
               epistemic_status = excluded.epistemic_status,
               updated_at       = excluded.updated_at",
            params![
                row.agent_id,
                row.memory_id,
                row.epistemic_status,
                row.updated_at
            ],
        )
        .map_err(|e| SqliteIndexError::Sql(e.to_string()))?;
        Ok(())
    }

    pub fn try_get_turn(
        &self,
        agent_id: &str,
        task_id: &str,
        turn: u32,
    ) -> Result<Option<TurnIndexRow>, SqliteIndexError> {
        let conn = self
            .pool
            .get()
            .map_err(|e| SqliteIndexError::Pool(e.to_string()))?;
        conn.query_row(
            "SELECT agent_id, task_id, turn, digest, embedding, reference_count, updated_at,
                    embedding_model
             FROM cap_turn_index WHERE agent_id = ?1 AND task_id = ?2 AND turn = ?3",
            params![agent_id, task_id, turn],
            row_to_turn,
        )
        .optional()
        .map_err(|e| SqliteIndexError::Sql(e.to_string()))
    }

    pub fn try_get_task(
        &self,
        agent_id: &str,
        task_id: &str,
    ) -> Result<Option<TaskIndexRow>, SqliteIndexError> {
        let conn = self
            .pool
            .get()
            .map_err(|e| SqliteIndexError::Pool(e.to_string()))?;
        conn.query_row(
            "SELECT task_id, agent_id, last_turn_at, turns_total, updated_at, brief_snapshot,
                    brief_embedding, brief_embedding_model
             FROM cap_task_index WHERE agent_id = ?1 AND task_id = ?2",
            params![agent_id, task_id],
            row_to_task,
        )
        .optional()
        .map_err(|e| SqliteIndexError::Sql(e.to_string()))
    }

    /// [`SqliteIndex::list_turns_not_of_model`] as one bounded query
    /// ([`TURNS_NOT_OF_MODEL_SQL`]): SQLite picks the window and the rows, so a long
    /// history is not loaded to find the few rows that need a vector.
    pub fn try_list_turns_not_of_model(
        &self,
        agent_id: &str,
        model: &str,
        window: usize,
        limit: usize,
    ) -> Result<Vec<TurnIndexRow>, SqliteIndexError> {
        let conn = self
            .pool
            .get()
            .map_err(|e| SqliteIndexError::Pool(e.to_string()))?;
        let mut stmt = conn
            .prepare(TURNS_NOT_OF_MODEL_SQL)
            .map_err(|e| SqliteIndexError::Sql(e.to_string()))?;
        let rows = stmt
            .query_map(
                params![
                    agent_id,
                    model,
                    row_count(window),
                    row_count(limit),
                    whitespace()
                ],
                row_to_turn,
            )
            .map_err(|e| SqliteIndexError::Sql(e.to_string()))?;
        collect_rows(rows)
    }

    /// How many `rows` of `agent_id` the index holds
    /// ([`SqliteIndex::count_turns_for_agent`]): counted by SQLite, none of them read.
    fn try_count_rows(&self, rows: Rows, agent_id: &str) -> Result<usize, SqliteIndexError> {
        let conn = self
            .pool
            .get()
            .map_err(|e| SqliteIndexError::Pool(e.to_string()))?;
        let sql = match rows {
            Rows::Turns => "SELECT COUNT(*) FROM cap_turn_index WHERE agent_id = ?1",
            Rows::Tasks => "SELECT COUNT(*) FROM cap_task_index WHERE agent_id = ?1",
        };
        let count: i64 = conn
            .query_row(sql, params![agent_id], |row| row.get(0))
            .map_err(|e| SqliteIndexError::Sql(e.to_string()))?;
        Ok(usize::try_from(count).unwrap_or_default())
    }

    /// [`SqliteIndex::list_recent_turns`] as one bounded query: a long history is not
    /// loaded — vectors and all — to read its newest rows.
    pub fn try_list_recent_turns(
        &self,
        agent_id: &str,
        window: usize,
    ) -> Result<Vec<TurnIndexRow>, SqliteIndexError> {
        let conn = self
            .pool
            .get()
            .map_err(|e| SqliteIndexError::Pool(e.to_string()))?;
        let mut stmt = conn
            .prepare(RECENT_TURNS_SQL)
            .map_err(|e| SqliteIndexError::Sql(e.to_string()))?;
        let rows = stmt
            .query_map(params![agent_id, row_count(window)], row_to_turn)
            .map_err(|e| SqliteIndexError::Sql(e.to_string()))?;
        collect_rows(rows)
    }

    /// [`SqliteIndex::list_tasks_not_of_model`] as one bounded query.
    pub fn try_list_tasks_not_of_model(
        &self,
        agent_id: &str,
        model: &str,
        limit: usize,
    ) -> Result<Vec<TaskIndexRow>, SqliteIndexError> {
        let conn = self
            .pool
            .get()
            .map_err(|e| SqliteIndexError::Pool(e.to_string()))?;
        // `trim(brief_snapshot, ?4) != ''`: as for a digest, above.
        let mut stmt = conn
            .prepare(
                "SELECT task_id, agent_id, last_turn_at, turns_total, updated_at, brief_snapshot,
                    brief_embedding, brief_embedding_model
                 FROM cap_task_index
                 WHERE agent_id = ?1
                   AND trim(brief_snapshot, ?4) != ''
                   AND (brief_embedding_model IS NULL OR brief_embedding_model != ?2)
                 ORDER BY updated_at DESC, task_id ASC
                 LIMIT ?3",
            )
            .map_err(|e| SqliteIndexError::Sql(e.to_string()))?;
        let rows = stmt
            .query_map(
                params![agent_id, model, row_count(limit), whitespace()],
                row_to_task,
            )
            .map_err(|e| SqliteIndexError::Sql(e.to_string()))?;
        collect_rows(rows)
    }

    /// [`SqliteIndex::set_task_brief_embedding`] as one `UPDATE`: the brief check
    /// and the write are a single statement, and no other column is rewritten.
    pub fn try_set_task_brief_embedding(
        &self,
        agent_id: &str,
        task_id: &str,
        brief: &str,
        embedding: &[f32],
        model: &str,
    ) -> Result<bool, SqliteIndexError> {
        let conn = self
            .pool
            .get()
            .map_err(|e| SqliteIndexError::Pool(e.to_string()))?;
        let changed = conn
            .execute(
                "UPDATE cap_task_index SET brief_embedding = ?1, brief_embedding_model = ?2
                 WHERE agent_id = ?3 AND task_id = ?4 AND brief_snapshot = ?5",
                params![
                    embedding_to_blob(embedding),
                    model,
                    agent_id,
                    task_id,
                    brief
                ],
            )
            .map_err(|e| SqliteIndexError::Sql(e.to_string()))?;
        Ok(changed > 0)
    }

    /// [`SqliteIndex::set_turn_embedding`] as one `UPDATE`: the digest check and
    /// the write are a single statement, and no other column is rewritten.
    pub fn try_set_turn_embedding(
        &self,
        agent_id: &str,
        task_id: &str,
        turn: u32,
        digest: &str,
        embedding: &[f32],
        model: &str,
    ) -> Result<bool, SqliteIndexError> {
        let conn = self
            .pool
            .get()
            .map_err(|e| SqliteIndexError::Pool(e.to_string()))?;
        let changed = conn
            .execute(
                "UPDATE cap_turn_index SET embedding = ?1, embedding_model = ?2
                 WHERE agent_id = ?3 AND task_id = ?4 AND turn = ?5 AND digest = ?6",
                params![
                    embedding_to_blob(embedding),
                    model,
                    agent_id,
                    task_id,
                    turn,
                    digest
                ],
            )
            .map_err(|e| SqliteIndexError::Sql(e.to_string()))?;
        Ok(changed > 0)
    }

    /// [`SqliteIndex::forget_agent`] as one transaction: the agent's rows of the three
    /// tables go together or not at all.
    pub fn try_forget_agent(&self, agent_id: &str) -> Result<(), SqliteIndexError> {
        let mut conn = self
            .pool
            .get()
            .map_err(|e| SqliteIndexError::Pool(e.to_string()))?;
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|e| SqliteIndexError::Sql(e.to_string()))?;
        for table in ["cap_turn_index", "cap_task_index", "cap_memory_index"] {
            tx.execute(
                &format!("DELETE FROM {table} WHERE agent_id = ?1"),
                params![agent_id],
            )
            .map_err(|e| SqliteIndexError::Sql(e.to_string()))?;
        }
        tx.commit()
            .map_err(|e| SqliteIndexError::Sql(e.to_string()))
    }

    pub fn try_get_memory(
        &self,
        agent_id: &str,
        memory_id: &str,
    ) -> Result<Option<MemoryIndexRow>, SqliteIndexError> {
        let conn = self
            .pool
            .get()
            .map_err(|e| SqliteIndexError::Pool(e.to_string()))?;
        conn.query_row(
            "SELECT agent_id, memory_id, epistemic_status, updated_at
             FROM cap_memory_index WHERE agent_id = ?1 AND memory_id = ?2",
            params![agent_id, memory_id],
            row_to_memory,
        )
        .optional()
        .map_err(|e| SqliteIndexError::Sql(e.to_string()))
    }

    pub fn try_list_turns(&self, agent_id: &str) -> Result<Vec<TurnIndexRow>, SqliteIndexError> {
        let conn = self
            .pool
            .get()
            .map_err(|e| SqliteIndexError::Pool(e.to_string()))?;
        let mut stmt = conn
            .prepare(
                "SELECT agent_id, task_id, turn, digest, embedding, reference_count, updated_at,
                    embedding_model
                 FROM cap_turn_index WHERE agent_id = ?1",
            )
            .map_err(|e| SqliteIndexError::Sql(e.to_string()))?;
        let rows = stmt
            .query_map(params![agent_id], row_to_turn)
            .map_err(|e| SqliteIndexError::Sql(e.to_string()))?;
        collect_rows(rows)
    }

    pub fn try_list_tasks(&self, agent_id: &str) -> Result<Vec<TaskIndexRow>, SqliteIndexError> {
        let conn = self
            .pool
            .get()
            .map_err(|e| SqliteIndexError::Pool(e.to_string()))?;
        let mut stmt = conn
            .prepare(
                "SELECT task_id, agent_id, last_turn_at, turns_total, updated_at, brief_snapshot,
                    brief_embedding, brief_embedding_model
                 FROM cap_task_index WHERE agent_id = ?1",
            )
            .map_err(|e| SqliteIndexError::Sql(e.to_string()))?;
        let rows = stmt
            .query_map(params![agent_id], row_to_task)
            .map_err(|e| SqliteIndexError::Sql(e.to_string()))?;
        collect_rows(rows)
    }

    pub fn try_list_memory(&self, agent_id: &str) -> Result<Vec<MemoryIndexRow>, SqliteIndexError> {
        let conn = self
            .pool
            .get()
            .map_err(|e| SqliteIndexError::Pool(e.to_string()))?;
        let mut stmt = conn
            .prepare(
                "SELECT agent_id, memory_id, epistemic_status, updated_at
                 FROM cap_memory_index WHERE agent_id = ?1",
            )
            .map_err(|e| SqliteIndexError::Sql(e.to_string()))?;
        let rows = stmt
            .query_map(params![agent_id], row_to_memory)
            .map_err(|e| SqliteIndexError::Sql(e.to_string()))?;
        collect_rows(rows)
    }
}

impl SqliteIndex for RusqliteSqliteIndex {
    fn upsert_turn(&self, row: TurnIndexRow) {
        let _ = self.try_upsert_turn(&row);
    }
    fn upsert_task(&self, row: TaskIndexRow) {
        let _ = self.try_upsert_task(&row);
    }
    fn upsert_memory(&self, row: MemoryIndexRow) {
        let _ = self.try_upsert_memory(&row);
    }
    fn get_turn(&self, agent_id: &str, task_id: &str, turn: u32) -> Option<TurnIndexRow> {
        self.try_get_turn(agent_id, task_id, turn).ok().flatten()
    }
    fn get_task(&self, agent_id: &str, task_id: &str) -> Option<TaskIndexRow> {
        self.try_get_task(agent_id, task_id).ok().flatten()
    }
    fn get_memory(&self, agent_id: &str, memory_id: &str) -> Option<MemoryIndexRow> {
        self.try_get_memory(agent_id, memory_id).ok().flatten()
    }
    fn list_turns_for_agent(&self, agent_id: &str) -> Vec<TurnIndexRow> {
        self.try_list_turns(agent_id).unwrap_or_default()
    }
    fn list_tasks_for_agent(&self, agent_id: &str) -> Vec<TaskIndexRow> {
        self.try_list_tasks(agent_id).unwrap_or_default()
    }
    fn list_memory_for_agent(&self, agent_id: &str) -> Vec<MemoryIndexRow> {
        self.try_list_memory(agent_id).unwrap_or_default()
    }
    fn count_turns_for_agent(&self, agent_id: &str) -> usize {
        self.try_count_rows(Rows::Turns, agent_id)
            .unwrap_or_default()
    }
    fn count_tasks_for_agent(&self, agent_id: &str) -> usize {
        self.try_count_rows(Rows::Tasks, agent_id)
            .unwrap_or_default()
    }
    fn list_recent_turns(&self, agent_id: &str, window: usize) -> Vec<TurnIndexRow> {
        self.try_list_recent_turns(agent_id, window)
            .unwrap_or_default()
    }
    fn list_turns_not_of_model(
        &self,
        agent_id: &str,
        model: &str,
        window: usize,
        limit: usize,
    ) -> Result<Vec<TurnIndexRow>, IndexUnavailable> {
        self.try_list_turns_not_of_model(agent_id, model, window, limit)
            .map_err(unavailable)
    }
    fn set_turn_embedding(
        &self,
        agent_id: &str,
        task_id: &str,
        turn: u32,
        digest: &str,
        embedding: &[f32],
        model: &str,
    ) -> Result<bool, IndexUnavailable> {
        self.try_set_turn_embedding(agent_id, task_id, turn, digest, embedding, model)
            .map_err(unavailable)
    }
    fn list_tasks_not_of_model(
        &self,
        agent_id: &str,
        model: &str,
        limit: usize,
    ) -> Result<Vec<TaskIndexRow>, IndexUnavailable> {
        self.try_list_tasks_not_of_model(agent_id, model, limit)
            .map_err(unavailable)
    }
    fn set_task_brief_embedding(
        &self,
        agent_id: &str,
        task_id: &str,
        brief: &str,
        embedding: &[f32],
        model: &str,
    ) -> Result<bool, IndexUnavailable> {
        self.try_set_task_brief_embedding(agent_id, task_id, brief, embedding, model)
            .map_err(unavailable)
    }
    fn forget_agent(&self, agent_id: &str) -> Result<(), IndexUnavailable> {
        self.try_forget_agent(agent_id).map_err(unavailable)
    }
}

/// A failed read or write, as the seam reports it ([`IndexUnavailable`]).
fn unavailable(e: SqliteIndexError) -> IndexUnavailable {
    IndexUnavailable(e.to_string())
}

// ── Row mappers (rusqlite Row → typed row). ──

fn row_to_turn(r: &rusqlite::Row<'_>) -> rusqlite::Result<TurnIndexRow> {
    let blob: Vec<u8> = r.get(4)?;
    Ok(TurnIndexRow {
        agent_id: r.get(0)?,
        task_id: r.get(1)?,
        turn: r.get(2)?,
        digest: r.get(3)?,
        embedding: blob_to_embedding(&blob),
        embedding_model: r.get(7)?,
        reference_count: r.get(5)?,
        updated_at: r.get(6)?,
    })
}

fn row_to_task(r: &rusqlite::Row<'_>) -> rusqlite::Result<TaskIndexRow> {
    let brief_blob: Option<Vec<u8>> = r.get(6)?;
    Ok(TaskIndexRow {
        task_id: r.get(0)?,
        agent_id: r.get(1)?,
        last_turn_at: r.get(2)?,
        turns_total: r.get(3)?,
        updated_at: r.get(4)?,
        brief_snapshot: r.get(5)?,
        brief_embedding: brief_blob.map(|b| blob_to_embedding(&b)),
        brief_embedding_model: r.get(7)?,
    })
}

/// Whether `table` has a column named `column`.
fn has_column(
    conn: &rusqlite::Connection,
    table: &str,
    column: &str,
) -> Result<bool, SqliteIndexError> {
    // `table` is one of this module's own table names, never caller input.
    let mut stmt = conn
        .prepare(&format!("PRAGMA table_info({table})"))
        .map_err(|e| SqliteIndexError::Sql(e.to_string()))?;
    let names = stmt
        .query_map([], |r| r.get::<_, String>(1))
        .map_err(|e| SqliteIndexError::Sql(e.to_string()))?;
    Ok(collect_rows(names)?.iter().any(|name| name == column))
}

/// Add the nullable TEXT `column` to `table` when the table predates it. Rows
/// already there read NULL. Safe against a second opener doing the same.
fn ensure_text_column(
    conn: &rusqlite::Connection,
    table: &str,
    column: &str,
) -> Result<(), SqliteIndexError> {
    if has_column(conn, table, column)? {
        return Ok(());
    }
    add_text_column(conn, table, column)
}

/// Add the nullable TEXT `column` to `table`. Another opener may add it between
/// the caller's look and this statement: finding it there is what was wanted,
/// not a failure.
fn add_text_column(
    conn: &rusqlite::Connection,
    table: &str,
    column: &str,
) -> Result<(), SqliteIndexError> {
    // `table` / `column` are this module's own identifiers, never caller input.
    match conn.execute(&format!("ALTER TABLE {table} ADD COLUMN {column} TEXT"), []) {
        Ok(_) => Ok(()),
        Err(_) if has_column(conn, table, column)? => Ok(()),
        Err(e) => Err(SqliteIndexError::Sql(e.to_string())),
    }
}

/// The primary-key columns of `cap_task_index`, in key order.
fn task_index_key(conn: &rusqlite::Connection) -> Result<Vec<String>, SqliteIndexError> {
    let mut stmt = conn
        .prepare("PRAGMA table_info(cap_task_index)")
        .map_err(|e| SqliteIndexError::Sql(e.to_string()))?;
    // Column 1 is the name; column 5 the 1-based position in the primary key (0
    // for a column that is not part of it).
    let columns = stmt
        .query_map([], |r| Ok((r.get::<_, i64>(5)?, r.get::<_, String>(1)?)))
        .map_err(|e| SqliteIndexError::Sql(e.to_string()))?;
    let mut key: Vec<(i64, String)> = collect_rows(columns)?
        .into_iter()
        .filter(|(position, _)| *position > 0)
        .collect();
    key.sort();
    Ok(key.into_iter().map(|(_, name)| name).collect())
}

/// Whether `cap_task_index` still has the `task_id`-only key of an older file.
fn task_rows_keyed_per_task(conn: &rusqlite::Connection) -> Result<bool, SqliteIndexError> {
    Ok(task_index_key(conn)? == ["task_id"])
}

/// Rebuild a `cap_task_index` that still has the `task_id`-only key of an older
/// index file into the `(agent_id, task_id)` key, keeping every row (each
/// already names the agent it belongs to). SQLite cannot change a primary key in
/// place, so the rows are copied into a new table that then takes the name. One
/// transaction: a reader sees the old table or the new one, never neither, and a
/// second opener that waited for the write lock finds the work done.
fn ensure_task_rows_per_agent(conn: &mut rusqlite::Connection) -> Result<(), SqliteIndexError> {
    if !task_rows_keyed_per_task(conn)? {
        return Ok(());
    }
    let tx = conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|e| SqliteIndexError::Sql(e.to_string()))?;
    // Re-read under the write lock: another opener may have rebuilt it meanwhile.
    if task_rows_keyed_per_task(&tx)? {
        tx.execute_batch(
            "DROP TABLE IF EXISTS cap_task_index_per_agent;
             CREATE TABLE cap_task_index_per_agent (
                 task_id         TEXT    NOT NULL,
                 agent_id        TEXT    NOT NULL,
                 last_turn_at    TEXT    NOT NULL,
                 turns_total     INTEGER NOT NULL,
                 updated_at      TEXT    NOT NULL,
                 brief_snapshot  TEXT    NOT NULL,
                 brief_embedding BLOB,
                 brief_embedding_model TEXT,
                 PRIMARY KEY (agent_id, task_id)
             );
             INSERT INTO cap_task_index_per_agent
                 (task_id, agent_id, last_turn_at, turns_total, updated_at, brief_snapshot,
                  brief_embedding, brief_embedding_model)
             SELECT task_id, agent_id, last_turn_at, turns_total, updated_at, brief_snapshot,
                    brief_embedding, brief_embedding_model
             FROM cap_task_index;
             DROP TABLE cap_task_index;
             ALTER TABLE cap_task_index_per_agent RENAME TO cap_task_index;
             CREATE INDEX IF NOT EXISTS idx_cap_task_agent ON cap_task_index(agent_id);",
        )
        .map_err(|e| SqliteIndexError::Sql(e.to_string()))?;
    }
    tx.commit()
        .map_err(|e| SqliteIndexError::Sql(e.to_string()))
}

fn row_to_memory(r: &rusqlite::Row<'_>) -> rusqlite::Result<MemoryIndexRow> {
    Ok(MemoryIndexRow {
        agent_id: r.get(0)?,
        memory_id: r.get(1)?,
        epistemic_status: r.get(2)?,
        updated_at: r.get(3)?,
    })
}

fn collect_rows<T>(
    rows: impl Iterator<Item = rusqlite::Result<T>>,
) -> Result<Vec<T>, SqliteIndexError> {
    let mut out = Vec::new();
    for r in rows {
        out.push(r.map_err(|e| SqliteIndexError::Sql(e.to_string()))?);
    }
    Ok(out)
}

/// A number of rows as SQLite takes it in `LIMIT`.
fn row_count(n: usize) -> i64 {
    i64::try_from(n).unwrap_or(i64::MAX)
}

/// The rows of an agent [`RusqliteSqliteIndex::try_count_rows`] counts.
#[derive(Clone, Copy)]
enum Rows {
    Turns,
    Tasks,
}

/// An agent's (`?1`) `?2` most recent turn rows, in reading order: most recently written
/// first, ties in time by task then turn ([`SqliteIndex::list_recent_turns`]). Read through
/// `idx_cap_turn_recent`, which holds them in that order.
const RECENT_TURNS_SQL: &str =
    "SELECT agent_id, task_id, turn, digest, embedding, reference_count, updated_at,
        embedding_model
     FROM cap_turn_index WHERE agent_id = ?1
     ORDER BY updated_at DESC, task_id ASC, turn ASC
     LIMIT ?2";

/// Up to `?4` of an agent's (`?1`) rows, among its `?3` most recent — the window
/// [`RECENT_TURNS_SQL`] reads, picked in the same order — that have a text and whose
/// vector is not of the model `?2` ([`SqliteIndex::list_turns_not_of_model`]).
/// `trim(digest, ?5) != ''`: a digest of nothing but whitespace has no text to embed —
/// `?5` is the whitespace `str::trim` removes ([`whitespace`]).
const TURNS_NOT_OF_MODEL_SQL: &str =
    "SELECT agent_id, task_id, turn, digest, embedding, reference_count, updated_at,
        embedding_model
     FROM cap_turn_index
     WHERE rowid IN (
             SELECT rowid FROM cap_turn_index WHERE agent_id = ?1
             ORDER BY updated_at DESC, task_id ASC, turn ASC LIMIT ?3)
       AND trim(digest, ?5) != ''
       AND (embedding_model IS NULL OR embedding_model != ?2)
     ORDER BY updated_at DESC, task_id ASC, turn ASC
     LIMIT ?4";

/// Every character `str::trim` removes, as the set SQLite's `trim(X, Y)` takes
/// for `Y`. With it a text is blank to a query exactly when it is blank to the
/// rest of this crate — the two can never drift apart, whatever a later Unicode
/// version calls whitespace.
fn whitespace() -> &'static str {
    static WHITESPACE: OnceLock<String> = OnceLock::new();
    WHITESPACE.get_or_init(|| {
        (0..=u32::from(char::MAX))
            .filter_map(char::from_u32)
            .filter(|c| c.is_whitespace())
            .collect()
    })
}

/// Encode `&[f32]` as a little-endian byte BLOB.
fn embedding_to_blob(emb: &[f32]) -> Vec<u8> {
    let mut v = Vec::with_capacity(emb.len() * 4);
    for f in emb {
        v.extend_from_slice(&f.to_le_bytes());
    }
    v
}

/// Decode a little-endian f32 BLOB back into a `Vec<f32>` (ignores a trailing
/// partial chunk, which a well-formed BLOB never has).
fn blob_to_embedding(blob: &[u8]) -> Vec<f32> {
    blob.chunks_exact(4)
        .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db(dir: &tempfile::TempDir) -> std::path::PathBuf {
        dir.path().join("index.sqlite3")
    }

    fn turn(agent: &str, task: &str, t: u32) -> TurnIndexRow {
        TurnIndexRow {
            agent_id: agent.into(),
            task_id: task.into(),
            turn: t,
            digest: format!("d-{t}"),
            embedding: vec![0.5_f32, -1.25, 3.0, 0.0, 7.5, 2.0, -4.0, 1.0],
            embedding_model: Some("embed-model-a".into()),
            reference_count: 0,
            updated_at: "2026-06-06T00:00:00Z".into(),
        }
    }

    fn task(task_id: &str, agent: &str) -> TaskIndexRow {
        TaskIndexRow {
            task_id: task_id.into(),
            agent_id: agent.into(),
            last_turn_at: "2026-06-06T00:00:00Z".into(),
            turns_total: 3,
            updated_at: "2026-06-06T00:00:00Z".into(),
            brief_snapshot: "init".into(),
            brief_embedding: Some(vec![1.0_f32, 2.0, 3.0]),
            brief_embedding_model: Some("embed-model-a".into()),
        }
    }

    fn memory(agent: &str, id: &str, status: &str) -> MemoryIndexRow {
        MemoryIndexRow {
            agent_id: agent.into(),
            memory_id: id.into(),
            epistemic_status: status.into(),
            updated_at: "2026-06-06T00:00:00Z".into(),
        }
    }

    #[test]
    fn turn_round_trip_with_embedding() {
        let dir = tempfile::tempdir().unwrap();
        let ix = RusqliteSqliteIndex::open(db(&dir)).unwrap();
        let r = turn("agent:r", "task-001", 7);
        ix.upsert_turn(r.clone());
        assert_eq!(ix.get_turn("agent:r", "task-001", 7), Some(r));
        assert_eq!(ix.get_turn("agent:r", "task-001", 99), None);
    }

    #[test]
    fn task_and_memory_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let ix = RusqliteSqliteIndex::open(db(&dir)).unwrap();
        let t = task("task-001", "agent:r");
        ix.upsert_task(t.clone());
        assert_eq!(ix.get_task("agent:r", "task-001"), Some(t));
        assert_eq!(ix.get_task("agent:s", "task-001"), None);
        let m = memory("agent:r", "mem-1", "contested");
        ix.upsert_memory(m.clone());
        assert_eq!(ix.get_memory("agent:r", "mem-1"), Some(m));
    }

    /// A row keeps the model its vector came from; a row with no known model (or
    /// no vector) keeps `None` — the two are never confused on read.
    #[test]
    fn rows_keep_the_model_their_vector_came_from() {
        let dir = tempfile::tempdir().unwrap();
        let ix = RusqliteSqliteIndex::open(db(&dir)).unwrap();
        let named = turn("agent:r", "task-001", 1);
        let mut unnamed = turn("agent:r", "task-001", 2);
        unnamed.embedding = Vec::new();
        unnamed.embedding_model = None;
        ix.upsert_turn(named.clone());
        ix.upsert_turn(unnamed.clone());
        assert_eq!(ix.get_turn("agent:r", "task-001", 1), Some(named.clone()));
        assert_eq!(ix.get_turn("agent:r", "task-001", 2), Some(unnamed));

        // An upsert under another model replaces vector AND model together.
        let mut moved = named;
        moved.embedding = vec![9.0, 9.0];
        moved.embedding_model = Some("embed-model-b".into());
        ix.upsert_turn(moved.clone());
        assert_eq!(ix.get_turn("agent:r", "task-001", 1), Some(moved));

        let mut t = task("task-001", "agent:r");
        ix.upsert_task(t.clone());
        assert_eq!(ix.get_task("agent:r", "task-001"), Some(t.clone()));
        t.brief_embedding = None;
        t.brief_embedding_model = None;
        ix.upsert_task(t.clone());
        assert_eq!(ix.get_task("agent:r", "task-001"), Some(t));
    }

    // ── what every `SqliteIndex` must do (shared with the in-memory index) ──

    #[test]
    fn task_rows_are_kept_per_agent() {
        let dir = tempfile::tempdir().unwrap();
        let ix = RusqliteSqliteIndex::open(db(&dir)).unwrap();
        crate::sqlite_index::conformance::keeps_task_rows_per_agent(&ix);
    }

    #[test]
    fn list_turns_not_of_model_lists_what_a_query_cannot_use() {
        let dir = tempfile::tempdir().unwrap();
        let ix = RusqliteSqliteIndex::open(db(&dir)).unwrap();
        crate::sqlite_index::conformance::lists_what_a_query_cannot_use(&ix);
    }

    #[test]
    fn turns_of_one_instant_are_ordered_by_task_then_turn() {
        let dir = tempfile::tempdir().unwrap();
        let ix = RusqliteSqliteIndex::open(db(&dir)).unwrap();
        crate::sqlite_index::conformance::breaks_a_tie_in_time_by_task_then_turn(&ix);
    }

    #[test]
    fn the_recent_turns_are_listed_in_reading_order() {
        let dir = tempfile::tempdir().unwrap();
        let ix = RusqliteSqliteIndex::open(db(&dir)).unwrap();
        crate::sqlite_index::conformance::lists_the_recent_turns_in_reading_order(&ix);
    }

    /// The newest rows are read through the index that holds them in reading order:
    /// SQLite neither scans nor sorts all of the agent's rows to find them — not for the
    /// reader (`try_list_recent_turns`), and not for the window the upkeep of vectors
    /// picks its rows from (`try_list_turns_not_of_model`, whose rows, at most a window
    /// of them, may then be sorted).
    #[test]
    fn the_newest_rows_are_found_without_sorting_all_of_them() {
        let dir = tempfile::tempdir().unwrap();
        let ix = RusqliteSqliteIndex::open(db(&dir)).unwrap();
        let conn = ix.pool.get().unwrap();
        // `(id, parent, detail)` of each step, a parent before its children.
        let plan_of = |sql: &str, args: &[&dyn rusqlite::ToSql]| -> Vec<(i64, i64, String)> {
            conn.prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
                .unwrap()
                .query_map(args, |row| Ok((row.get(0)?, row.get(1)?, row.get(3)?)))
                .unwrap()
                .map(Result::unwrap)
                .collect()
        };
        let reads_the_index_unsorted = |steps: &[&str]| {
            assert!(
                steps
                    .iter()
                    .any(|step| step.contains("idx_cap_turn_recent")),
                "{steps:?}"
            );
            assert!(
                !steps.iter().any(|step| step.contains("TEMP B-TREE")),
                "{steps:?}"
            );
        };

        let reader = plan_of(RECENT_TURNS_SQL, &[&"agent:r", &10]);
        reads_the_index_unsorted(
            &reader
                .iter()
                .map(|(_, _, d)| d.as_str())
                .collect::<Vec<_>>(),
        );

        let upkeep = plan_of(
            TURNS_NOT_OF_MODEL_SQL,
            &[&"agent:r", &"embed-a", &10, &10, &whitespace()],
        );
        // The steps of the window's subquery, at any depth under it.
        let (subquery, _, _) = upkeep
            .iter()
            .find(|(_, _, detail)| detail.contains("SUBQUERY"))
            .unwrap_or_else(|| panic!("the window is a subquery: {upkeep:?}"));
        let mut under = vec![*subquery];
        let mut window = Vec::new();
        for (id, parent, detail) in &upkeep {
            if under.contains(parent) {
                under.push(*id);
                window.push(detail.as_str());
            }
        }
        reads_the_index_unsorted(&window);
    }

    #[test]
    fn set_turn_embedding_touches_the_vector_alone() {
        let dir = tempfile::tempdir().unwrap();
        let ix = RusqliteSqliteIndex::open(db(&dir)).unwrap();
        crate::sqlite_index::conformance::sets_the_vector_alone(&ix);
    }

    #[test]
    fn list_tasks_not_of_model_lists_the_tasks_a_query_cannot_use() {
        let dir = tempfile::tempdir().unwrap();
        let ix = RusqliteSqliteIndex::open(db(&dir)).unwrap();
        crate::sqlite_index::conformance::lists_the_tasks_a_query_cannot_use(&ix);
    }

    #[test]
    fn set_task_brief_embedding_touches_the_brief_vector_alone() {
        let dir = tempfile::tempdir().unwrap();
        let ix = RusqliteSqliteIndex::open(db(&dir)).unwrap();
        crate::sqlite_index::conformance::sets_the_brief_vector_alone(&ix);
    }

    #[test]
    fn rows_without_a_text_do_not_use_up_the_limit() {
        let dir = tempfile::tempdir().unwrap();
        let ix = RusqliteSqliteIndex::open(db(&dir)).unwrap();
        crate::sqlite_index::conformance::rows_without_a_text_do_not_use_up_the_limit(&ix);
    }

    #[test]
    fn a_text_is_blank_exactly_when_str_trim_leaves_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let ix = RusqliteSqliteIndex::open(db(&dir)).unwrap();
        crate::sqlite_index::conformance::agrees_with_str_trim_on_what_is_blank(&ix);
    }

    #[test]
    fn forget_agent_drops_one_agents_rows_and_no_others() {
        let dir = tempfile::tempdir().unwrap();
        let ix = RusqliteSqliteIndex::open(db(&dir)).unwrap();
        crate::sqlite_index::conformance::forgets_one_agent_and_no_other(&ix);
        // What is forgotten is gone from the file, not from this handle alone.
        drop(ix);
        let reopened = RusqliteSqliteIndex::open(db(&dir)).unwrap();
        assert_eq!(reopened.list_turns_for_agent("agent:r").len(), 1);
        assert!(reopened.list_tasks_for_agent("agent:r").is_empty());
        assert_eq!(reopened.list_turns_for_agent("agent:s").len(), 3);
    }

    /// An index that cannot be read says so. It must never answer "no rows" (which
    /// would read as "nothing left to embed") or "the text changed".
    #[test]
    fn a_failed_read_or_write_is_an_error_not_an_empty_answer() {
        let dir = tempfile::tempdir().unwrap();
        let ix = RusqliteSqliteIndex::open(db(&dir)).unwrap();
        crate::sqlite_index::conformance::lists_what_a_query_cannot_use(&ix);
        // The tables go away under the open pool.
        let conn = rusqlite::Connection::open(db(&dir)).unwrap();
        conn.execute_batch(
            "DROP TABLE cap_turn_index; DROP TABLE cap_task_index; DROP TABLE cap_memory_index;",
        )
        .unwrap();
        drop(conn);

        assert!(ix
            .list_turns_not_of_model("agent:r", "embed-a", 10, 10)
            .is_err());
        assert!(ix
            .list_tasks_not_of_model("agent:r", "embed-a", 10)
            .is_err());
        assert!(ix
            .set_turn_embedding("agent:r", "task-001", 1, "d-1", &[0.5], "embed-a")
            .is_err());
        assert!(ix
            .set_task_brief_embedding("agent:r", "t-a", "the brief", &[0.5], "embed-a")
            .is_err());
        assert!(ix.forget_agent("agent:r").is_err());
    }

    // ── an index file whose task rows are keyed by `task_id` alone ──

    /// The `cap_task_index` DDL of an index file written before task rows were
    /// kept per agent (`with_model_column`: before or after vectors were bound to
    /// their model).
    fn create_per_task_index(path: &std::path::Path, with_model_column: bool) {
        let conn = rusqlite::Connection::open(path).unwrap();
        let model_column = if with_model_column {
            ", brief_embedding_model TEXT"
        } else {
            ""
        };
        conn.execute_batch(&format!(
            "CREATE TABLE cap_task_index (
                 task_id TEXT NOT NULL PRIMARY KEY, agent_id TEXT NOT NULL,
                 last_turn_at TEXT NOT NULL, turns_total INTEGER NOT NULL,
                 updated_at TEXT NOT NULL, brief_snapshot TEXT NOT NULL,
                 brief_embedding BLOB{model_column});
             CREATE INDEX idx_cap_task_agent ON cap_task_index(agent_id);"
        ))
        .unwrap();
    }

    fn task_key_columns(path: &std::path::Path) -> Vec<String> {
        let conn = rusqlite::Connection::open(path).unwrap();
        task_index_key(&conn).unwrap()
    }

    fn index_names(path: &std::path::Path) -> Vec<String> {
        let conn = rusqlite::Connection::open(path).unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT name FROM sqlite_master
                 WHERE type = 'index' AND tbl_name = 'cap_task_index' AND name NOT LIKE 'sqlite_%'",
            )
            .unwrap();
        let names = stmt.query_map([], |r| r.get::<_, String>(0)).unwrap();
        collect_rows(names).unwrap()
    }

    /// An older file's task rows survive the move to the per-agent key — every
    /// column, the vector and its model included — and afterwards a second agent
    /// can hold the same task id without touching the first one's row.
    #[test]
    fn open_rekeys_an_older_task_table_per_agent_and_keeps_its_rows() {
        let dir = tempfile::tempdir().unwrap();
        let path = db(&dir);
        create_per_task_index(&path, true);
        {
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.execute(
                "INSERT INTO cap_task_index VALUES
                   ('task-001', 'agent:r', 't1', 4, 'u1', 'brief one', ?1, 'embed-a'),
                   ('task-002', 'agent:s', 't2', 9, 'u2', 'brief two', NULL, NULL)",
                params![embedding_to_blob(&[3.0, -1.5])],
            )
            .unwrap();
        }
        assert_eq!(task_key_columns(&path), ["task_id"]);

        let ix = RusqliteSqliteIndex::open(&path).expect("an older index must open");
        assert_eq!(task_key_columns(&path), ["agent_id", "task_id"]);
        assert_eq!(index_names(&path), ["idx_cap_task_agent"]);
        let first = TaskIndexRow {
            task_id: "task-001".into(),
            agent_id: "agent:r".into(),
            last_turn_at: "t1".into(),
            turns_total: 4,
            updated_at: "u1".into(),
            brief_snapshot: "brief one".into(),
            brief_embedding: Some(vec![3.0, -1.5]),
            brief_embedding_model: Some("embed-a".into()),
        };
        assert_eq!(ix.get_task("agent:r", "task-001"), Some(first.clone()));
        let second = ix.get_task("agent:s", "task-002").expect("second row");
        assert_eq!(
            (second.turns_total, second.brief_snapshot.as_str()),
            (9, "brief two")
        );
        assert_eq!(second.brief_embedding, None);
        assert_eq!(ix.list_tasks_for_agent("agent:r").len(), 1);
        assert_eq!(ix.list_tasks_for_agent("agent:s").len(), 1);

        // The same task id under another agent: both rows stand.
        let mut other = task("task-001", "agent:s");
        other.brief_snapshot = "the other agent's brief".into();
        ix.try_upsert_task(&other)
            .expect("a second agent may hold the task id");
        assert_eq!(ix.get_task("agent:s", "task-001"), Some(other));
        assert_eq!(ix.get_task("agent:r", "task-001"), Some(first.clone()));

        // Opening the rebuilt file again changes nothing.
        drop(ix);
        let again = RusqliteSqliteIndex::open(&path).expect("reopen");
        assert_eq!(task_key_columns(&path), ["agent_id", "task_id"]);
        assert_eq!(again.get_task("agent:r", "task-001"), Some(first));
        assert_eq!(again.list_tasks_for_agent("agent:s").len(), 2);
    }

    /// The oldest shape — `task_id`-only key AND no model column — takes both
    /// steps in one open.
    #[test]
    fn open_rekeys_a_task_table_that_also_predates_the_model_column() {
        let dir = tempfile::tempdir().unwrap();
        let path = db(&dir);
        create_per_task_index(&path, false);
        {
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.execute(
                "INSERT INTO cap_task_index VALUES ('task-001', 'agent:r', 't0', 4, 't0', 'old brief', ?1)",
                params![embedding_to_blob(&[3.0])],
            )
            .unwrap();
        }

        let ix = RusqliteSqliteIndex::open(&path).expect("an older index must open");
        assert_eq!(task_key_columns(&path), ["agent_id", "task_id"]);
        let row = ix.get_task("agent:r", "task-001").expect("old task row");
        assert_eq!(row.brief_snapshot, "old brief");
        assert_eq!(row.brief_embedding, Some(vec![3.0]));
        assert_eq!(row.brief_embedding_model, None);
    }

    /// Two openers of one older file: each finds the task table per agent, the
    /// rows are there exactly once, and the table was rebuilt once.
    #[test]
    fn two_openers_of_an_older_file_rekey_it_once() {
        let older_file = |path: &std::path::Path| {
            create_per_task_index(path, true);
            let conn = rusqlite::Connection::open(path).unwrap();
            for n in 0..50 {
                conn.execute(
                    "INSERT INTO cap_task_index VALUES (?1, 'agent:r', 't', 1, 'u', 'brief', NULL, NULL)",
                    params![format!("task-{n:03}")],
                )
                .unwrap();
            }
        };
        // SQLite counts every change of a file's schema: a rebuild run twice moves
        // the count further than one opener alone does.
        let schema_version = |path: &std::path::Path| -> i64 {
            rusqlite::Connection::open(path)
                .unwrap()
                .query_row("PRAGMA schema_version", [], |row| row.get(0))
                .unwrap()
        };
        let alone = tempfile::tempdir().unwrap();
        let alone = db(&alone);
        older_file(&alone);
        let before = schema_version(&alone);
        RusqliteSqliteIndex::open(&alone).unwrap();
        let one_opener = schema_version(&alone) - before;

        let dir = tempfile::tempdir().unwrap();
        let path = db(&dir);
        older_file(&path);
        let before = schema_version(&path);
        let openers: Vec<_> = (0..4)
            .map(|_| {
                let path = path.clone();
                std::thread::spawn(move || RusqliteSqliteIndex::open(&path).map(|_| ()))
            })
            .collect();
        for opener in openers {
            opener.join().unwrap().expect("every opener succeeds");
        }
        assert_eq!(task_key_columns(&path), ["agent_id", "task_id"]);
        assert_eq!(
            schema_version(&path) - before,
            one_opener,
            "rebuilt once, as by one opener alone"
        );
        let ix = RusqliteSqliteIndex::open(&path).unwrap();
        assert_eq!(ix.list_tasks_for_agent("agent:r").len(), 50);
    }

    /// A rebuild that fails half-way leaves the file as it was — the older table
    /// with every row, and no half-built table beside it — and the open says so.
    /// (Here a row the per-agent table cannot take, one naming no agent, stops the
    /// copy after the new table was created.)
    #[test]
    fn a_rekey_that_fails_half_way_leaves_the_older_table_as_it_was() {
        let dir = tempfile::tempdir().unwrap();
        let path = db(&dir);
        {
            let conn = rusqlite::Connection::open(&path).unwrap();
            // An older table without the NOT NULL the per-agent table has on
            // `agent_id` (hand-made: no release wrote this shape).
            conn.execute_batch(
                "CREATE TABLE cap_task_index (
                     task_id TEXT NOT NULL PRIMARY KEY, agent_id TEXT,
                     last_turn_at TEXT NOT NULL, turns_total INTEGER NOT NULL,
                     updated_at TEXT NOT NULL, brief_snapshot TEXT NOT NULL,
                     brief_embedding BLOB, brief_embedding_model TEXT);
                 INSERT INTO cap_task_index VALUES
                     ('task-001', 'agent:r', 't1', 4, 'u1', 'brief one', NULL, NULL),
                     ('task-002', NULL, 't2', 9, 'u2', 'brief two', NULL, NULL);",
            )
            .unwrap();
        }

        assert!(matches!(
            RusqliteSqliteIndex::open(&path),
            Err(SqliteIndexError::Sql(_))
        ));

        let conn = rusqlite::Connection::open(&path).unwrap();
        assert_eq!(task_index_key(&conn).unwrap(), ["task_id"]);
        let count = |sql: &str| -> i64 { conn.query_row(sql, [], |r| r.get(0)).unwrap() };
        assert_eq!(count("SELECT count(*) FROM cap_task_index"), 2);
        assert_eq!(
            count("SELECT count(*) FROM sqlite_master WHERE name = 'cap_task_index_per_agent'"),
            0
        );
    }

    /// Two openers of one file that predates a column both look, both find it
    /// missing and both add it: the second finds it there, which is what it
    /// wanted. A statement that fails for any other reason is still an error.
    #[test]
    fn adding_a_column_another_opener_added_first_is_not_a_failure() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE t (a TEXT)").unwrap();
        add_text_column(&conn, "t", "b").expect("the first opener adds it");
        add_text_column(&conn, "t", "b").expect("the second finds it there");
        assert!(has_column(&conn, "t", "b").unwrap());
        // No such table: the statement fails and the column is not there either.
        assert!(matches!(
            add_text_column(&conn, "missing", "b"),
            Err(SqliteIndexError::Sql(_))
        ));
    }

    /// An index file written before the model columns existed opens, keeps its
    /// rows (model unknown → `None`), and takes model-bound rows afterwards.
    #[test]
    fn open_adds_the_model_columns_to_an_index_that_predates_them() {
        let dir = tempfile::tempdir().unwrap();
        let path = db(&dir);
        {
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE cap_turn_index (
                     agent_id TEXT NOT NULL, task_id TEXT NOT NULL, turn INTEGER NOT NULL,
                     digest TEXT NOT NULL, embedding BLOB NOT NULL,
                     reference_count INTEGER NOT NULL, updated_at TEXT NOT NULL,
                     PRIMARY KEY (agent_id, task_id, turn));
                 CREATE TABLE cap_task_index (
                     task_id TEXT NOT NULL PRIMARY KEY, agent_id TEXT NOT NULL,
                     last_turn_at TEXT NOT NULL, turns_total INTEGER NOT NULL,
                     updated_at TEXT NOT NULL, brief_snapshot TEXT NOT NULL,
                     brief_embedding BLOB);",
            )
            .unwrap();
            conn.execute(
                "INSERT INTO cap_turn_index VALUES ('agent:r', 'task-001', 1, 'old digest', ?1, 2, 't0')",
                params![embedding_to_blob(&[1.0, 2.0])],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO cap_task_index VALUES ('task-001', 'agent:r', 't0', 4, 't0', 'old brief', ?1)",
                params![embedding_to_blob(&[3.0])],
            )
            .unwrap();
        }

        let ix = RusqliteSqliteIndex::open(&path).expect("an older index must open");
        let old_turn = ix.get_turn("agent:r", "task-001", 1).expect("old turn row");
        assert_eq!(old_turn.digest, "old digest");
        assert_eq!(old_turn.embedding, vec![1.0, 2.0]);
        assert_eq!(old_turn.reference_count, 2);
        assert_eq!(old_turn.embedding_model, None);
        let old_task = ix.get_task("agent:r", "task-001").expect("old task row");
        assert_eq!(old_task.brief_snapshot, "old brief");
        assert_eq!(old_task.brief_embedding, Some(vec![3.0]));
        assert_eq!(old_task.brief_embedding_model, None);

        let new_turn = turn("agent:r", "task-001", 2);
        ix.upsert_turn(new_turn.clone());
        assert_eq!(ix.get_turn("agent:r", "task-001", 2), Some(new_turn));
        assert_eq!(ix.list_turns_for_agent("agent:r").len(), 2);

        // A second open of the migrated file is a no-op.
        drop(ix);
        let again = RusqliteSqliteIndex::open(&path).expect("reopen");
        assert_eq!(again.list_turns_for_agent("agent:r").len(), 2);
        assert_eq!(again.list_tasks_for_agent("agent:r").len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn open_refuses_symlinked_db_leaf() {
        // Codex W1 (satB-postproc adversarial r15): a planted symlink at the
        // durable-index path must be REFUSED — opening through it would let
        // rusqlite write the DB outside the owner-only `.agent/memory` root.
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let outside_db = outside.path().join("escaped.sqlite3");
        let link = dir.path().join("index.sqlite3");
        symlink(&outside_db, &link).unwrap();

        match RusqliteSqliteIndex::open(&link) {
            Err(SqliteIndexError::Rejected(_)) => {}
            other => panic!("symlinked db leaf must be rejected, got {other:?}"),
        }
        assert!(
            !outside_db.exists(),
            "must NOT create the DB through the symlink"
        );
    }

    #[test]
    fn upsert_overwrites_same_key() {
        let dir = tempfile::tempdir().unwrap();
        let ix = RusqliteSqliteIndex::open(db(&dir)).unwrap();
        ix.upsert_turn(turn("agent:r", "task-001", 1));
        let mut r2 = turn("agent:r", "task-001", 1);
        r2.reference_count = 3;
        r2.updated_at = "2026-06-07T00:00:00Z".into();
        ix.upsert_turn(r2.clone());
        assert_eq!(ix.get_turn("agent:r", "task-001", 1), Some(r2));
    }

    #[test]
    fn list_filters_by_agent_and_keys_disambiguate() {
        let dir = tempfile::tempdir().unwrap();
        let ix = RusqliteSqliteIndex::open(db(&dir)).unwrap();
        ix.upsert_turn(turn("agent:r", "task-001", 1));
        ix.upsert_turn(turn("agent:r", "task-002", 1));
        ix.upsert_turn(turn("agent:s", "task-001", 1));
        assert_eq!(ix.list_turns_for_agent("agent:r").len(), 2);
        assert_eq!(ix.list_turns_for_agent("agent:s").len(), 1);
        assert!(ix.get_turn("agent:r", "task-001", 1).is_some());
        assert!(ix.get_turn("agent:r", "task-002", 1).is_some());
        ix.upsert_task(task("task-001", "agent:r"));
        ix.upsert_task(task("task-002", "agent:s"));
        assert_eq!(ix.list_tasks_for_agent("agent:r").len(), 1);
        assert_eq!(ix.list_tasks_for_agent("agent:absent").len(), 0);
        ix.upsert_memory(memory("agent:r", "m1", "active"));
        ix.upsert_memory(memory("agent:r", "m2", "orphaned"));
        ix.upsert_memory(memory("agent:s", "m3", "active"));
        assert_eq!(ix.list_memory_for_agent("agent:r").len(), 2);
        assert_eq!(ix.list_memory_for_agent("agent:s").len(), 1);
    }

    #[test]
    fn durable_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = db(&dir);
        {
            let ix = RusqliteSqliteIndex::open(&path).unwrap();
            ix.upsert_turn(turn("agent:r", "task-001", 5));
            ix.upsert_task(task("task-009", "agent:r"));
            ix.upsert_memory(memory("agent:r", "mem-9", "superseded"));
        }
        // Fresh index over the same file sees the rows.
        let ix2 = RusqliteSqliteIndex::open(&path).unwrap();
        assert_eq!(
            ix2.get_turn("agent:r", "task-001", 5),
            Some(turn("agent:r", "task-001", 5))
        );
        assert_eq!(
            ix2.get_task("agent:r", "task-009"),
            Some(task("task-009", "agent:r"))
        );
        assert_eq!(
            ix2.get_memory("agent:r", "mem-9"),
            Some(memory("agent:r", "mem-9", "superseded"))
        );
    }
}

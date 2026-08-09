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

use std::path::Path;

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, OptionalExtension};

use crate::sqlite_index::{MemoryIndexRow, SqliteIndex, TaskIndexRow, TurnIndexRow};

/// DDL for the 3 cap-memory-owned tables (+ per-agent indexes). `IF NOT EXISTS`
/// so re-`open` over an existing DB is a no-op.
const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS cap_turn_index (
    agent_id        TEXT    NOT NULL,
    task_id         TEXT    NOT NULL,
    turn            INTEGER NOT NULL,
    digest          TEXT    NOT NULL,
    embedding       BLOB    NOT NULL,
    reference_count INTEGER NOT NULL,
    updated_at      TEXT    NOT NULL,
    PRIMARY KEY (agent_id, task_id, turn)
);
CREATE TABLE IF NOT EXISTS cap_task_index (
    task_id         TEXT    NOT NULL PRIMARY KEY,
    agent_id        TEXT    NOT NULL,
    last_turn_at    TEXT    NOT NULL,
    turns_total     INTEGER NOT NULL,
    updated_at      TEXT    NOT NULL,
    brief_snapshot  TEXT    NOT NULL,
    brief_embedding BLOB
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
        let conn = pool
            .get()
            .map_err(|e| SqliteIndexError::Pool(e.to_string()))?;
        conn.execute_batch(SCHEMA)
            .map_err(|e| SqliteIndexError::Sql(e.to_string()))?;
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
               (agent_id, task_id, turn, digest, embedding, reference_count, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(agent_id, task_id, turn) DO UPDATE SET
               digest          = excluded.digest,
               embedding       = excluded.embedding,
               reference_count = excluded.reference_count,
               updated_at      = excluded.updated_at",
            params![
                row.agent_id,
                row.task_id,
                row.turn,
                row.digest,
                embedding_to_blob(&row.embedding),
                row.reference_count,
                row.updated_at,
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
               (task_id, agent_id, last_turn_at, turns_total, updated_at, brief_snapshot, brief_embedding)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(task_id) DO UPDATE SET
               agent_id        = excluded.agent_id,
               last_turn_at    = excluded.last_turn_at,
               turns_total     = excluded.turns_total,
               updated_at      = excluded.updated_at,
               brief_snapshot  = excluded.brief_snapshot,
               brief_embedding = excluded.brief_embedding",
            params![
                row.task_id,
                row.agent_id,
                row.last_turn_at,
                row.turns_total,
                row.updated_at,
                row.brief_snapshot,
                brief_blob,
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
            "SELECT agent_id, task_id, turn, digest, embedding, reference_count, updated_at
             FROM cap_turn_index WHERE agent_id = ?1 AND task_id = ?2 AND turn = ?3",
            params![agent_id, task_id, turn],
            row_to_turn,
        )
        .optional()
        .map_err(|e| SqliteIndexError::Sql(e.to_string()))
    }

    pub fn try_get_task(&self, task_id: &str) -> Result<Option<TaskIndexRow>, SqliteIndexError> {
        let conn = self
            .pool
            .get()
            .map_err(|e| SqliteIndexError::Pool(e.to_string()))?;
        conn.query_row(
            "SELECT task_id, agent_id, last_turn_at, turns_total, updated_at, brief_snapshot, brief_embedding
             FROM cap_task_index WHERE task_id = ?1",
            params![task_id],
            row_to_task,
        )
        .optional()
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
                "SELECT agent_id, task_id, turn, digest, embedding, reference_count, updated_at
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
                "SELECT task_id, agent_id, last_turn_at, turns_total, updated_at, brief_snapshot, brief_embedding
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
    fn get_task(&self, task_id: &str) -> Option<TaskIndexRow> {
        self.try_get_task(task_id).ok().flatten()
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
    })
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
        assert_eq!(ix.get_task("task-001"), Some(t));
        let m = memory("agent:r", "mem-1", "contested");
        ix.upsert_memory(m.clone());
        assert_eq!(ix.get_memory("agent:r", "mem-1"), Some(m));
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
        assert_eq!(ix2.get_task("task-009"), Some(task("task-009", "agent:r")));
        assert_eq!(
            ix2.get_memory("agent:r", "mem-9"),
            Some(memory("agent:r", "mem-9", "superseded"))
        );
    }
}

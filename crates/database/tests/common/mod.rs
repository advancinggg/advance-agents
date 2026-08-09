//! Shared deterministic seed helpers for MODULE-004 integration tests.
//!
//! Each helper wraps a multi-table insert in a `BEGIN..COMMIT` transaction and
//! pins rowid alignment between the primary `*_index` table and its sibling
//! FTS5/vec0 virtual tables via `Connection::last_insert_rowid()`. This is the
//! canonical write-path pattern documented in MODULE-004 §3.2 / Slice C plan
//! §"Implementation steps Step 7".
//!
//! All timestamp fields are stored as RFC 3339 strings via
//! `chrono::DateTime::<Utc>::to_rfc3339_opts(SecondsFormat::Millis, true)` so
//! the recall path's row mappers can `parse_from_rfc3339` them back.
//!
//! These helpers live under `tests/common/mod.rs` (Cargo's standard
//! shared-test-utility idiom — files at this path are NOT compiled as separate
//! integration targets, only as modules of each `tests/*.rs` file via `mod common;`).

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use advance_database::{
    DbError, Embedder, EmbedderError, R2d2SqliteIndexHandle, SqliteIndexHandle,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use rusqlite::params;

pub fn now_utc() -> DateTime<Utc> {
    std::time::SystemTime::now().into()
}

pub fn ts_text(dt: &DateTime<Utc>) -> String {
    dt.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

pub fn one_hot(idx: usize) -> Vec<f32> {
    let mut v = vec![0.0_f32; 768];
    if idx < 768 {
        v[idx] = 1.0;
    }
    v
}

pub fn zero_emb() -> Vec<f32> {
    vec![0.0_f32; 768]
}

pub fn embedding_to_blob(e: &[f32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(e.len() * 4);
    for f in e {
        out.extend_from_slice(&f.to_le_bytes());
    }
    out
}

pub fn seed_content(
    handle: &R2d2SqliteIndexHandle,
    id: &str,
    agent_id: &str,
    file_path: &str,
    preview: &str,
    embedding: &[f32],
    access_count: u32,
    last_modified: DateTime<Utc>,
) -> Result<i64, DbError> {
    let mut conn = handle.get_conn()?;
    let tx = conn.transaction()?;
    let now = ts_text(&now_utc());
    let lm = ts_text(&last_modified);
    tx.execute(
        "INSERT INTO content_index(id, agent_id, file_path, content_preview, access_count, \
         last_accessed, last_modified, updated_at) VALUES (?1,?2,?3,?4,?5,NULL,?6,?7)",
        params![
            id,
            agent_id,
            file_path,
            preview,
            access_count as i64,
            lm,
            now
        ],
    )?;
    let rowid = tx.last_insert_rowid();
    tx.execute(
        "INSERT INTO content_fts(rowid, file_path, content_preview, tags) VALUES (?1,?2,?3,?4)",
        params![rowid, file_path, preview, ""],
    )?;
    tx.execute(
        "INSERT INTO content_vec(rowid, embedding) VALUES (?1,?2)",
        params![rowid, embedding_to_blob(embedding)],
    )?;
    tx.commit()?;
    Ok(rowid)
}

pub fn seed_memory(
    handle: &R2d2SqliteIndexHandle,
    id: &str,
    agent_id: &str,
    content: &str,
    embedding: &[f32],
    status: Option<&str>,
    access_count: u32,
) -> Result<i64, DbError> {
    let mut conn = handle.get_conn()?;
    let tx = conn.transaction()?;
    let now = ts_text(&now_utc());
    tx.execute(
        "INSERT INTO memory_index(id, agent_id, type, content, tags, embedding, created_at, \
         task_origin, superseded_by, is_active, status, supersession_reason, sources, \
         access_count, last_accessed) VALUES (?1,?2,'fact',?3,NULL,NULL,?4,NULL,NULL,1,?5,NULL,NULL,?6,NULL)",
        params![id, agent_id, content, &now, status, access_count as i64],
    )?;
    let rowid = tx.last_insert_rowid();
    tx.execute(
        "INSERT INTO memory_vec(rowid, embedding) VALUES (?1,?2)",
        params![rowid, embedding_to_blob(embedding)],
    )?;
    tx.commit()?;
    Ok(rowid)
}

pub fn seed_meta(
    handle: &R2d2SqliteIndexHandle,
    id: &str,
    agent_id: &str,
    directory: &str,
    description: &str,
    embedding: &[f32],
) -> Result<i64, DbError> {
    let mut conn = handle.get_conn()?;
    let tx = conn.transaction()?;
    let now = ts_text(&now_utc());
    tx.execute(
        "INSERT INTO meta_index(id, agent_id, directory, entry_name, description, tags, \
         embedding, updated_at) VALUES (?1,?2,?3,?4,?5,NULL,NULL,?6)",
        params![id, agent_id, directory, directory, description, &now],
    )?;
    let rowid = tx.last_insert_rowid();
    tx.execute(
        "INSERT INTO meta_vec(rowid, embedding) VALUES (?1,?2)",
        params![rowid, embedding_to_blob(embedding)],
    )?;
    tx.commit()?;
    Ok(rowid)
}

pub fn seed_task(
    handle: &R2d2SqliteIndexHandle,
    task_id: &str,
    agent_id: &str,
    title: &str,
    embedding: &[f32],
    last_turn_at: Option<DateTime<Utc>>,
) -> Result<i64, DbError> {
    let mut conn = handle.get_conn()?;
    let tx = conn.transaction()?;
    let now = ts_text(&now_utc());
    let lta = last_turn_at.as_ref().map(ts_text);
    tx.execute(
        "INSERT INTO task_index(task_id, agent_id, title, brief, status, embedding, \
         last_turn_at, turns_total, updated_at) VALUES (?1,?2,?3,'','active',NULL,?4,0,?5)",
        params![task_id, agent_id, title, lta, &now],
    )?;
    let rowid = tx.last_insert_rowid();
    tx.execute(
        "INSERT INTO task_vec(rowid, embedding) VALUES (?1,?2)",
        params![rowid, embedding_to_blob(embedding)],
    )?;
    tx.commit()?;
    Ok(rowid)
}

pub fn seed_turn(
    handle: &R2d2SqliteIndexHandle,
    id: &str,
    agent_id: &str,
    task_id: &str,
    turn: i64,
    digest: &str,
    embedding: &[f32],
    timestamp: DateTime<Utc>,
) -> Result<i64, DbError> {
    let mut conn = handle.get_conn()?;
    let tx = conn.transaction()?;
    let ts = ts_text(&timestamp);
    tx.execute(
        "INSERT INTO turn_index(id, agent_id, task_id, turn, timestamp, digest, importance, \
         reference_count, has_user_instruction, has_user_correction, has_tool_use, has_decision, \
         embedding, tokens_digest, tokens_l0_processed, access_count, last_accessed) \
         VALUES (?1,?2,?3,?4,?5,?6,'normal',0,0,0,0,0,NULL,0,0,0,NULL)",
        params![id, agent_id, task_id, turn, ts, digest],
    )?;
    let rowid = tx.last_insert_rowid();
    tx.execute(
        "INSERT INTO turn_vec(rowid, embedding) VALUES (?1,?2)",
        params![rowid, embedding_to_blob(embedding)],
    )?;
    tx.commit()?;
    Ok(rowid)
}

pub fn read_content_access(
    handle: &R2d2SqliteIndexHandle,
    id: &str,
) -> Result<(u32, Option<DateTime<Utc>>), DbError> {
    let conn = handle.get_conn()?;
    let mut stmt =
        conn.prepare("SELECT access_count, last_accessed FROM content_index WHERE id = ?1")?;
    let row = stmt.query_row([id], |r| {
        let count: i64 = r.get::<_, Option<i64>>(0)?.unwrap_or(0);
        let ts_str: Option<String> = r.get(1)?;
        let ts = match ts_str {
            Some(s) => Some(
                chrono::DateTime::parse_from_rfc3339(&s)
                    .map(|dt| dt.with_timezone(&Utc))
                    .map_err(|e| {
                        rusqlite::Error::FromSqlConversionFailure(
                            1,
                            rusqlite::types::Type::Text,
                            Box::new(e),
                        )
                    })?,
            ),
            None => None,
        };
        Ok((count.max(0) as u32, ts))
    })?;
    Ok(row)
}

pub fn read_memory_access(
    handle: &R2d2SqliteIndexHandle,
    id: &str,
) -> Result<(u32, Option<DateTime<Utc>>), DbError> {
    let conn = handle.get_conn()?;
    let mut stmt =
        conn.prepare("SELECT access_count, last_accessed FROM memory_index WHERE id = ?1")?;
    let row = stmt.query_row([id], |r| {
        let count: i64 = r.get::<_, Option<i64>>(0)?.unwrap_or(0);
        let ts_str: Option<String> = r.get(1)?;
        let ts = match ts_str {
            Some(s) => Some(
                chrono::DateTime::parse_from_rfc3339(&s)
                    .map(|dt| dt.with_timezone(&Utc))
                    .map_err(|e| {
                        rusqlite::Error::FromSqlConversionFailure(
                            1,
                            rusqlite::types::Type::Text,
                            Box::new(e),
                        )
                    })?,
            ),
            None => None,
        };
        Ok((count.max(0) as u32, ts))
    })?;
    Ok(row)
}

// ──────────────────────────────────────────────────────────────────────
// Slice D rebuild test helpers
// ──────────────────────────────────────────────────────────────────────

/// Returns a unit vector whose cosine vs `[1.0, 0.0, ...]` equals
/// `2 * target_sim - 1` — so the recall mapping `(1+cos)/2` yields
/// exactly `target_sim`. Promoted from recall_smoke.rs:24-30 (Slice C
/// canonical primitive for deterministic similarity tests).
pub fn emb_with_sim(target_sim: f32) -> Vec<f32> {
    let cos = (2.0 * target_sim - 1.0).clamp(-1.0, 1.0);
    let mut v = vec![0.0_f32; 768];
    v[0] = cos;
    v[1] = (1.0 - cos * cos).sqrt();
    v
}

/// Slice D test embedder: returns `emb_with_sim(1.0)` (a unit vector
/// `[1, 0, 0, ...]`) when the input text equals the configured target,
/// otherwise `emb_with_sim(0.0)` (the antipodal `[-1, 0, 0, ...]`).
/// Recall path's dense cosine: target↔target = 1.0 → similarity 1.0;
/// non-target↔target = -1.0 → similarity 0.0 (BELOW the 0.3 dense
/// threshold → filtered out at SQL level). Used by T-rebuild-09 for
/// deterministic top-1 ranking.
#[derive(Clone)]
pub struct IdentityEmbedder {
    target: String,
}

impl IdentityEmbedder {
    pub fn new(target: impl Into<String>) -> Self {
        Self {
            target: target.into(),
        }
    }
}

#[async_trait]
impl Embedder for IdentityEmbedder {
    async fn embed(&self, text: &str) -> Result<Vec<f32>, EmbedderError> {
        if text == self.target {
            Ok(emb_with_sim(1.0))
        } else {
            Ok(emb_with_sim(0.0))
        }
    }
}

/// Wrapper that counts embed() invocations. Used by T-rebuild-01..06
/// to assert the AC-08 "embed called once per row" invariant.
#[derive(Clone)]
pub struct CountingEmbedder<E: Embedder + Clone> {
    inner: E,
    count: Arc<AtomicU64>,
}

impl<E: Embedder + Clone> CountingEmbedder<E> {
    pub fn new(inner: E) -> Self {
        Self {
            inner,
            count: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn calls(&self) -> u64 {
        self.count.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl<E: Embedder + Clone> Embedder for CountingEmbedder<E> {
    async fn embed(&self, text: &str) -> Result<Vec<f32>, EmbedderError> {
        self.count.fetch_add(1, Ordering::SeqCst);
        self.inner.embed(text).await
    }
}

/// Always returns `Err(EmbedderError::Failed("test"))`. Used by T-rebuild-15
/// to test the embedder-failure surface.
#[derive(Clone)]
pub struct FailingEmbedder;

#[async_trait]
impl Embedder for FailingEmbedder {
    async fn embed(&self, _text: &str) -> Result<Vec<f32>, EmbedderError> {
        Err(EmbedderError::Failed("test".to_string()))
    }
}

/// Constant embedder: always returns the same vector. Useful for tests
/// that only need embed() to succeed without ranking semantics.
#[derive(Clone)]
pub struct ConstEmbedder {
    v: Vec<f32>,
}

impl ConstEmbedder {
    pub fn new() -> Self {
        Self {
            v: emb_with_sim(0.5),
        }
    }
}

#[async_trait]
impl Embedder for ConstEmbedder {
    async fn embed(&self, _text: &str) -> Result<Vec<f32>, EmbedderError> {
        Ok(self.v.clone())
    }
}

pub fn write_meta_yaml(workspace_root: &Path, dir_relative: &str, contents: &str) {
    let dir = workspace_root.join(dir_relative);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(".meta.yaml"), contents).unwrap();
}

pub fn write_text_file(workspace_root: &Path, rel_path: &str, body: &str) {
    let path = workspace_root.join(rel_path);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(path, body).unwrap();
}

pub fn write_knowledge_jsonl(
    workspace_root: &Path,
    agent_dir_relative: &str,
    entries: &[serde_json::Value],
) {
    let dir = workspace_root
        .join(agent_dir_relative)
        .join(".agent")
        .join("memory");
    std::fs::create_dir_all(&dir).unwrap();
    let mut body = String::new();
    for e in entries {
        body.push_str(&serde_json::to_string(e).unwrap());
        body.push('\n');
    }
    std::fs::write(dir.join("knowledge.jsonl"), body).unwrap();
}

pub fn write_summary_yaml(
    workspace_root: &Path,
    agent_dir_relative: &str,
    task_id: &str,
    yaml_str: &str,
) {
    let dir = workspace_root
        .join(agent_dir_relative)
        .join(".agent")
        .join("tasks")
        .join("active")
        .join(task_id);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("summary.yaml"), yaml_str).unwrap();
}

pub fn write_turn_index_yaml(
    workspace_root: &Path,
    agent_dir_relative: &str,
    task_id: &str,
    yaml_str: &str,
) {
    let dir = workspace_root
        .join(agent_dir_relative)
        .join(".agent")
        .join("tasks")
        .join("active")
        .join(task_id);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("turn-index.yaml"), yaml_str).unwrap();
}

/// Make the workspace_root agent's `.agent/` directory exist (so it counts
/// as an agent territory).
pub fn make_agent_root(workspace_root: &Path, agent_dir_relative: &str) {
    let agent = workspace_root.join(agent_dir_relative).join(".agent");
    std::fs::create_dir_all(&agent).unwrap();
}

pub fn count_rows(handle: &R2d2SqliteIndexHandle, table: &str) -> i64 {
    let conn = handle.get_conn().unwrap();
    conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| {
        r.get::<_, i64>(0)
    })
    .unwrap()
}

pub fn count_rows_where(
    handle: &R2d2SqliteIndexHandle,
    table: &str,
    where_clause: &str,
    binds: &[&dyn rusqlite::ToSql],
) -> i64 {
    let conn = handle.get_conn().unwrap();
    conn.query_row(
        &format!("SELECT COUNT(*) FROM {table} WHERE {where_clause}"),
        binds,
        |r| r.get::<_, i64>(0),
    )
    .unwrap()
}

#[derive(Debug)]
pub struct ContentRowSnapshot {
    pub id: String,
    pub agent_id: String,
    pub file_path: String,
    pub content_preview: Option<String>,
    pub access_count: i64,
    pub last_accessed: Option<String>,
    pub last_modified: Option<String>,
}

pub fn read_content_row(
    handle: &R2d2SqliteIndexHandle,
    file_path: &str,
) -> Option<ContentRowSnapshot> {
    let conn = handle.get_conn().unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT id, agent_id, file_path, content_preview, access_count, last_accessed, last_modified \
             FROM content_index WHERE file_path = ?1",
        )
        .unwrap();
    stmt.query_row([file_path], |r| {
        Ok(ContentRowSnapshot {
            id: r.get(0)?,
            agent_id: r.get(1)?,
            file_path: r.get(2)?,
            content_preview: r.get(3)?,
            access_count: r.get(4)?,
            last_accessed: r.get(5)?,
            last_modified: r.get(6)?,
        })
    })
    .ok()
}

#[derive(Debug)]
pub struct TurnRowSnapshot {
    pub id: String,
    pub access_count: i64,
    pub last_accessed: Option<String>,
}

pub fn read_turn_row(handle: &R2d2SqliteIndexHandle, id: &str) -> Option<TurnRowSnapshot> {
    let conn = handle.get_conn().unwrap();
    let mut stmt = conn
        .prepare("SELECT id, access_count, last_accessed FROM turn_index WHERE id = ?1")
        .unwrap();
    stmt.query_row([id], |r| {
        Ok(TurnRowSnapshot {
            id: r.get(0)?,
            access_count: r.get(1)?,
            last_accessed: r.get(2)?,
        })
    })
    .ok()
}

pub fn seed_turn_with_access(
    handle: &R2d2SqliteIndexHandle,
    id: &str,
    agent_id: &str,
    task_id: &str,
    turn: i64,
    digest: &str,
    timestamp: DateTime<Utc>,
    access_count: u32,
    last_accessed: DateTime<Utc>,
) -> Result<i64, DbError> {
    let mut conn = handle.get_conn()?;
    let tx = conn.transaction()?;
    let ts = ts_text(&timestamp);
    let la = ts_text(&last_accessed);
    tx.execute(
        "INSERT INTO turn_index(id, agent_id, task_id, turn, timestamp, digest, importance, \
         reference_count, has_user_instruction, has_user_correction, has_tool_use, has_decision, \
         embedding, tokens_digest, tokens_l0_processed, access_count, last_accessed) \
         VALUES (?1,?2,?3,?4,?5,?6,'normal',0,0,0,0,0,NULL,0,0,?7,?8)",
        params![
            id,
            agent_id,
            task_id,
            turn,
            ts,
            digest,
            access_count as i64,
            la
        ],
    )?;
    let rowid = tx.last_insert_rowid();
    tx.commit()?;
    Ok(rowid)
}

pub fn tempdir() -> tempfile::TempDir {
    tempfile::TempDir::new().expect("tempdir")
}

#[derive(Debug)]
pub struct MetaRowSnapshot {
    pub id: String,
    pub agent_id: String,
    pub directory: String,
    pub entry_name: String,
    pub description: Option<String>,
    pub tags: Option<String>,
}

pub fn read_meta_row(
    handle: &R2d2SqliteIndexHandle,
    directory: &str,
    entry_name: &str,
) -> Option<MetaRowSnapshot> {
    let conn = handle.get_conn().unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT id, agent_id, directory, entry_name, description, tags \
             FROM meta_index WHERE directory = ?1 AND entry_name = ?2",
        )
        .unwrap();
    stmt.query_row(params![directory, entry_name], |r| {
        Ok(MetaRowSnapshot {
            id: r.get(0)?,
            agent_id: r.get(1)?,
            directory: r.get(2)?,
            entry_name: r.get(3)?,
            description: r.get(4)?,
            tags: r.get(5)?,
        })
    })
    .ok()
}

pub fn db_at(path: &PathBuf) -> R2d2SqliteIndexHandle {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create db parent dir");
    }
    R2d2SqliteIndexHandle::new(path, 1).expect("handle")
}

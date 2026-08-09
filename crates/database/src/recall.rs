//! CONTRACT-031 `Recall` trait + `R2d2RecallImpl` for MODULE-004 Slices C and F.
//!
//! Wraps Slice B's pure-math score primitives behind the dual-path recall
//! pipeline (sqlite-vec dense + FTS5 sparse), directory aggregation with
//! 50/50 propagation across up to RECALL_MAX_DEPTH ancestor directories
//! AND recursive descent into high-scoring meta-known directories
//! (PRD §8.3.4 — both halves of REQ-154; ancestor-walk and descent share the
//! RECALL_MAX_DEPTH cap and DENSE_THRESHOLD threshold for symmetry),
//! post-recall atomic `access_count + 1` + `last_accessed = now` UPDATE,
//! and the `recall_at` deferral surface.
//!
//! The recursive *search descent* half of REQ-154 ships in Slice F as
//! `descend_into_dirs` + `recursive_descent_step`: for every meta-routing
//! result whose similarity ≥ DENSE_THRESHOLD, descend into that directory's
//! direct-child files (`LIKE 'dir/%' AND NOT LIKE 'dir/%/%'`) and recurse
//! into immediate meta-known sub-dirs whose propagated final_score
//! `= sub_meta_sim*0.5 + parent_score*0.5 > DENSE_THRESHOLD`, bounded by
//! RECALL_MAX_DEPTH per chain. See MODULE-004 §1.4.2 + §1.5 AC-20/AC-20b.
//!
//! ## Async semantics
//!
//! Trait methods are `async fn`; bodies wrap the synchronous rusqlite work
//! in `tokio::task::spawn_blocking` so the async executor is not blocked.
//! `JoinError` is mapped to `DbError::Internal` (NOT `DbError::InvalidConfig`
//! — executor panic is not a caller-supplied config error).
//!
//! ## Timestamp encoding
//!
//! All timestamp columns are SQLite `TEXT` storing RFC 3339 strings. The
//! crate explicitly does NOT enable rusqlite's optional `chrono` feature or
//! chrono's `clock` feature (supply-chain hygiene). `DateTime<Utc>` ↔ rusqlite
//! is mediated by [`ts_to_text`] / [`parse_ts`]. Production "now" is obtained
//! via `std::time::SystemTime::now().into()`.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use crate::error::DbError;
use crate::fts_adapter::{build_match_expression, extract_keywords, score_from_fts_rank};
use crate::handle::SqliteIndexHandle;
use crate::score::{
    compute_adjusted_score, rank_task_rows, retention_score, SearchResult, Source, TaskHit,
    TaskIndexRow, TurnDigest,
};
use crate::{default_tunables_provider, embedding_to_blob, Tunables, TunablesProvider};

const DENSE_THRESHOLD: f32 = 0.3;
/// Slice G: kept as the **fallback default** for unit-tested call paths
/// that don't go through the impl method. Production reads from
/// `R2d2RecallImpl::current_tunables().recall_max_depth` per-call and
/// threads the value into `recall_blocking` + `descend_into_dirs`.
#[allow(dead_code)]
const RECALL_MAX_DEPTH: u32 = 3;
const MAX_LIMIT: u32 = 1024;
/// Slice F: per descent-step LIMIT cap on `content_index.file_path LIKE 'dir/%'`
/// queries. Bounds the descent budget across N high-scoring dirs ×
/// RECALL_MAX_DEPTH levels; total descent SQL fan-out is bounded by
/// `N × RECALL_MAX_DEPTH × MAX_DESCENT_FANOUT` rows. `i64` to satisfy
/// rusqlite's `ToSql` for SQLite's `INTEGER` LIMIT bind, mirroring the
/// `MAX_LIMIT as i64` pattern at recall.rs's task-similarity SQL site.
const MAX_DESCENT_FANOUT: i64 = 50;
/// Maximum bytes accepted for the free-text `query` parameter. Round-15
/// (adversarial) finding: extract_keywords scans every byte of the query
/// even when no qualifying tokens exist; capping the input length closes
/// the unbounded-scan surface for misbehaving callers (defense-in-depth
/// over the documented "process-internal trusted code" trust boundary).
const MAX_QUERY_BYTES: usize = 4096;

/// CONTRACT-031 `Recall` trait — wraps Slice B primitives behind dense + sparse
/// + meta routing + post-recall access update. See §2.3 of MODULE-004.
#[async_trait]
pub trait Recall: Send + Sync {
    async fn recall(
        &self,
        agent_id: &str,
        query: &str,
        query_embedding: &[f32],
        limit: u32,
    ) -> Result<Vec<RecallResult>, DbError>;

    async fn recall_at(
        &self,
        agent_id: &str,
        query: &str,
        query_embedding: &[f32],
        timestamp: &str,
        limit: u32,
    ) -> Result<Vec<RecallResult>, DbError>;

    fn retention_score(&self, turn: &TurnDigest, now: DateTime<Utc>) -> f32;

    async fn task_semantic_similarity(
        &self,
        agent_id: &str,
        query_embedding: &[f32],
        limit: u32,
    ) -> Result<Vec<TaskHit>, DbError>;
}

/// One row of `recall()` output. Source-specific columns (`file_path`,
/// `content_preview`, `content_full`, `status`, `directory`) are populated
/// per-source per the MODULE-004 §1.4.3 mapping.
#[derive(Clone, Debug)]
pub struct RecallResult {
    pub id: String,
    pub source: Source,
    pub file_path: Option<String>,
    pub content_preview: Option<String>,
    pub content_full: Option<String>,
    pub similarity: f32,
    pub parent_score: f32,
    pub adjusted_score: f32,
    pub access_count: u32,
    pub last_modified: DateTime<Utc>,
    pub last_accessed: Option<DateTime<Utc>>,
    pub status: Option<String>,
    pub created_at: DateTime<Utc>,
    pub directory: Option<String>,
}

/// Concrete CONTRACT-031 impl backed by an `R2d2SqliteIndexHandle`.
pub struct R2d2RecallImpl<H: SqliteIndexHandle> {
    handle: H,
    /// Slice G: live tunables provider. Plain `Arc<dyn>` (no Mutex) keeps
    /// the impl Clone-able if H is Clone-able and the inner provider reads
    /// through to the watcher's snapshot.
    tunables: Arc<dyn TunablesProvider>,
}

impl<H: SqliteIndexHandle> R2d2RecallImpl<H> {
    pub fn new(handle: H) -> Self {
        Self {
            handle,
            tunables: default_tunables_provider(),
        }
    }

    /// Slice G: production wiring. Threads a live `TunablesProvider`
    /// through the recall pipeline so `recall_max_depth` and
    /// `embedding_dim` hot-reloads have observable behavioral effects on
    /// the next recall call.
    pub fn with_tunables(handle: H, tunables: Arc<dyn TunablesProvider>) -> Self {
        Self { handle, tunables }
    }

    /// Slice G helper: read the current tunables snapshot.
    pub fn current_tunables(&self) -> Tunables {
        self.tunables.current()
    }

    /// Slice G: pub method so `R2d2UnifiedSearchImpl` can plumb the dim
    /// through `validate_query_embedding` without holding its own
    /// tunables field (single-owner model — recall owns the provider;
    /// unified_search delegates).
    pub fn current_embedding_dim(&self) -> usize {
        self.tunables.current().embedding_dim
    }
}

#[async_trait]
impl<H> Recall for R2d2RecallImpl<H>
where
    H: SqliteIndexHandle + Clone + 'static,
{
    async fn recall(
        &self,
        agent_id: &str,
        query: &str,
        query_embedding: &[f32],
        limit: u32,
    ) -> Result<Vec<RecallResult>, DbError> {
        validate_agent_id(agent_id)?;
        validate_query(query)?;
        // Slice G: read tunables snapshot ONCE per call; thread max_depth +
        // expected_dim through to the spawn_blocking closure (free fns
        // recall_blocking + descend_into_dirs cannot access &self).
        let tunables = self.current_tunables();
        validate_query_embedding(query_embedding, tunables.embedding_dim)?;
        let handle = self.handle.clone();
        let agent_id = agent_id.to_string();
        let keywords = extract_keywords(query);
        let q_emb = query_embedding.to_vec();
        let now: DateTime<Utc> = std::time::SystemTime::now().into();

        // limit == 0 → return Ok(vec![]) directly without hitting SQL. Round-11
        // finding W (Codex Doc/Diff): the prior `.max(1)` coercion silently
        // changed caller semantics — `limit = 0` should produce an empty
        // result set, not 1 hit + a stat mutation.
        if limit == 0 {
            return Ok(Vec::new());
        }

        tokio::task::spawn_blocking(move || -> Result<Vec<RecallResult>, DbError> {
            let mut conn = handle.get_conn()?;
            recall_blocking(
                &mut conn,
                &agent_id,
                &keywords,
                &q_emb,
                limit,
                now,
                tunables.recall_max_depth,
            )
        })
        .await
        .map_err(|e| DbError::Internal(format!("recall task panic: {e}")))?
    }

    async fn recall_at(
        &self,
        _agent_id: &str,
        _query: &str,
        _query_embedding: &[f32],
        _timestamp: &str,
        _limit: u32,
    ) -> Result<Vec<RecallResult>, DbError> {
        Err(DbError::Unsupported(
            "recall_at requires the historical-version slice (depends on MODULE-003 git versions)"
                .to_string(),
        ))
    }

    fn retention_score(&self, turn: &TurnDigest, now: DateTime<Utc>) -> f32 {
        retention_score(turn, now)
    }

    async fn task_semantic_similarity(
        &self,
        agent_id: &str,
        query_embedding: &[f32],
        limit: u32,
    ) -> Result<Vec<TaskHit>, DbError> {
        validate_agent_id(agent_id)?;
        validate_query_embedding(query_embedding, self.current_embedding_dim())?;
        let handle = self.handle.clone();
        let agent_id = agent_id.to_string();
        let q_emb = query_embedding.to_vec();
        if limit == 0 {
            return Ok(Vec::new());
        }
        let limit = limit as usize;

        tokio::task::spawn_blocking(move || -> Result<Vec<TaskHit>, DbError> {
            let conn = handle.get_conn()?;
            // Round-14 (adversarial) finding: cap the candidate set to
            // MAX_LIMIT to prevent unbounded fetch on agents with thousands
            // of tasks. The actual top-k truncation happens in
            // rank_task_rows; the SQL LIMIT keeps memory + CPU bounded.
            //
            // Round-15 follow-up: ORDER BY t.rowid DESC biases the
            // candidate window toward the most-recently-inserted tasks when
            // total tasks exceed MAX_LIMIT. Without ORDER BY, SQLite
            // returns rows in implementation-defined order (typically
            // insertion order ascending), so an attacker who can flood
            // task_index with old decoys could push legitimate tasks out of
            // the window. Most-recent bias is the safer default.
            let candidate_cap = MAX_LIMIT as i64;
            let mut stmt = conn.prepare(
                "SELECT t.task_id, tv.embedding, t.last_turn_at \
                 FROM task_index t JOIN task_vec tv ON tv.rowid = t.rowid \
                 WHERE t.agent_id = ?1 \
                 ORDER BY t.rowid DESC \
                 LIMIT ?2",
            )?;
            let rows = stmt
                .query_map(rusqlite::params![&agent_id, candidate_cap], |row| {
                    let task_id: String = row.get(0)?;
                    let blob: Vec<u8> = row.get(1)?;
                    let last_turn_at_str: Option<String> = row.get(2)?;
                    let last_turn_at = match last_turn_at_str {
                        Some(s) => Some(parse_ts(2, &s)?),
                        None => None,
                    };
                    Ok(TaskIndexRow {
                        task_id,
                        embedding: blob_to_embedding(&blob),
                        last_turn_at,
                    })
                })?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(rank_task_rows(&q_emb, &rows, limit))
        })
        .await
        .map_err(|e| DbError::Internal(format!("task_sem task panic: {e}")))?
    }
}

// =============================================================================
// helpers (private)
// =============================================================================

/// Slice G: parameterized on `expected_dim` so the live snapshot value
/// from `Tunables` flows through. Production callsites pass
/// `self.current_tunables().embedding_dim`; unit tests pass a literal.
pub(crate) fn validate_query_embedding(q: &[f32], expected_dim: usize) -> Result<(), DbError> {
    if q.len() != expected_dim {
        return Err(DbError::InvalidConfig(format!(
            "query_embedding length {} != expected dim {}",
            q.len(),
            expected_dim
        )));
    }
    if q.iter().any(|f| !f.is_finite()) {
        return Err(DbError::InvalidConfig(
            "query_embedding contains NaN/Inf".to_string(),
        ));
    }
    // Zero-magnitude vectors produce undefined cosine — sqlite-vec's
    // distance function returns NaN or 1.0 depending on backend; either way
    // ranking semantics break. Fail closed before any SQL runs.
    let mag_sq: f32 = q.iter().map(|x| x * x).sum();
    if !mag_sq.is_finite() || mag_sq == 0.0 {
        return Err(DbError::InvalidConfig(
            "query_embedding has zero magnitude".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_agent_id(agent_id: &str) -> Result<(), DbError> {
    if agent_id.trim().is_empty() {
        return Err(DbError::InvalidConfig(
            "agent_id must be non-empty".to_string(),
        ));
    }
    Ok(())
}

/// Defense-in-depth length cap for the free-text query parameter. Round-15
/// adversarial Info finding: extract_keywords scans the full query in
/// O(N) — capping at [`MAX_QUERY_BYTES`] (= 4 KB) closes the unbounded-
/// scan surface even for misbehaving callers. 4 KB is far more than any
/// natural-language query needs.
pub(crate) fn validate_query(query: &str) -> Result<(), DbError> {
    if query.len() > MAX_QUERY_BYTES {
        return Err(DbError::InvalidConfig(format!(
            "query length {} bytes exceeds MAX_QUERY_BYTES {}",
            query.len(),
            MAX_QUERY_BYTES
        )));
    }
    Ok(())
}

/// Convert `DateTime<Utc>` → RFC 3339 string for SQL TEXT column binds.
pub(crate) fn ts_to_text(dt: &DateTime<Utc>) -> String {
    dt.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// Parse a TEXT timestamp from rusqlite into `DateTime<Utc>`. Errors map to
/// `rusqlite::Error::FromSqlConversionFailure` so they propagate cleanly
/// through `query_map`.
pub(crate) fn parse_ts(idx: usize, s: &str) -> Result<DateTime<Utc>, rusqlite::Error> {
    chrono::DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(idx, rusqlite::types::Type::Text, Box::new(e))
        })
}

// `embedding_to_blob` was hoisted to `crate::embedding_to_blob` in
// m004-slice-e; imported above.

/// Decode a sqlite-vec BLOB (raw little-endian f32 bytes) to a Vec<f32>.
pub(crate) fn blob_to_embedding(blob: &[u8]) -> Vec<f32> {
    blob.chunks_exact(4)
        .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect()
}

/// Epoch (1970-01-01 00:00:00 UTC) — used as a fallback for rows whose
/// `last_modified` column is NULL. Cosmically-old rows score near the decay
/// floor (0.1) rather than crashing the recall worker.
pub(crate) fn epoch_utc() -> DateTime<Utc> {
    chrono::DateTime::<Utc>::from_timestamp(0, 0).expect("epoch is a valid DateTime")
}

/// Compute parent_score for a content row at `file_path` via bottom-up 50/50
/// propagation across up to `max_depth` ancestor directories. Tolerates both
/// `dir` and `dir/` forms in the meta_scores lookup map.
fn parent_score_for_path(
    file_path: &str,
    meta_scores: &HashMap<String, f32>,
    max_depth: u32,
) -> f32 {
    let mut ancestors: Vec<f32> = Vec::with_capacity(max_depth as usize);
    let mut current = file_path.rsplit_once('/').map(|(d, _)| d).unwrap_or("");
    for _ in 0..max_depth {
        if current.is_empty() {
            // Reached root (or file_path had no parent dir at all). Stop —
            // do NOT push a synthetic 0.0 for the root because the fold would
            // otherwise dilute the topmost real ancestor's score. PRD §8.3.4
            // walks named ancestors only.
            break;
        }
        let with_slash = format!("{current}/");
        let s = meta_scores
            .get(current)
            .copied()
            .or_else(|| meta_scores.get(&with_slash).copied())
            .unwrap_or(0.0);
        ancestors.push(s);
        match current.rsplit_once('/') {
            Some((parent, _)) => current = parent,
            None => break, // no further ancestors above this directory
        }
    }
    if ancestors.is_empty() {
        return 0.0;
    }
    let mut p = *ancestors.last().unwrap();
    for &s in ancestors.iter().rev().skip(1) {
        p = s * 0.5 + p * 0.5;
    }
    p
}

// =============================================================================
// Slice F: recursive search descent (PRD §8.3.4 second half)
// =============================================================================

/// Escape SQLite LIKE special chars (`\`, `%`, `_`) in a directory string so
/// it can be safely interpolated into a `LIKE 'dir/%'` pattern. Round-9 audit
/// finding: directory names containing literal `%` or `_` (POSIX legal) were
/// being treated as wildcards by the descent SQL, leaking cross-directory
/// false positives. Pair with `LIKE ?N ESCAPE '\\'` on the SQL side.
pub(crate) fn escape_like(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

/// Slice F driver: for every `meta_scores` dir clearing DENSE_THRESHOLD,
/// invoke `recursive_descent_step` with a SHARED visited-set so sibling
/// descents into nested high-scoring meta dirs (e.g., both `a` and `a/b`)
/// don't redo overlapping subtree work. NO existing-content-path
/// suppression (PRD §8.3.4 has none — descent's purpose is to surface
/// low-sim content the global dense filter missed; suppressing dirs with
/// any global hit would make low-sim siblings unreachable).
///
/// Workspace-root candidates (`dir == ""`) are skipped — every content row
/// sits under root, so descent into `""` would trivially re-execute the
/// global dense_content scan.
fn descend_into_dirs(
    conn: &rusqlite::Connection,
    agent_id: &str,
    q_blob: &[u8],
    max_depth: u32,
    meta_scores: &HashMap<String, f32>,
    discovered: &mut HashMap<String, ContentRow>,
) -> Result<(), DbError> {
    let mut visited: HashSet<String> = HashSet::new();
    let mut candidates: Vec<(&String, f32)> = meta_scores
        .iter()
        .filter(|(d, s)| **s >= DENSE_THRESHOLD && !d.is_empty())
        .map(|(d, s)| (d, *s))
        .collect();
    // Sort by sim DESC for deterministic top-down ordering on non-equal
    // sims; equal-sim tie-break is HashMap-iteration-order — final result
    // is invariant via the shared visited HashSet so the order doesn't
    // affect correctness, only the SQL-call sequence.
    candidates.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    for (dir, sim) in candidates {
        recursive_descent_step(
            conn,
            agent_id,
            q_blob,
            dir,
            sim,
            max_depth,
            meta_scores,
            &mut visited,
            discovered,
        )?;
    }
    Ok(())
}

/// Single descent step: query content_index for files DIRECTLY in `dir`
/// (immediate children, depth 1), then for each meta-known IMMEDIATE
/// sub-directory of `dir` whose propagated `final_score = sub_meta_sim *
/// 0.5 + parent_score * 0.5 > DENSE_THRESHOLD`, recurse with that
/// propagated value as the new parent_score and `depth_remaining - 1`.
///
/// PRD-alignment: matches `db.search_in_directory(agent_id, dir, ...)`
/// + `for child in children { if child.is_dir && final_score > 0.3
/// { recursive_search(child.path, ..., max_depth - 1) } }` — descent
/// proceeds ONE level per call, so RECALL_MAX_DEPTH bounds path
/// depth from the initial driver dir, not arbitrary multi-level
/// jumps.
///
/// `visited` is a HashSet of directory paths shared across the
/// driver's sibling descents — prevents overlapping subtree work
/// when meta_scores has nested high-scoring dirs (e.g., both `a` and
/// `a/b` are top-level descent candidates: whichever runs first
/// recurses through the shared subtree; the second is short-circuited
/// at `recursive_descent_step` entry by the visited check).
fn recursive_descent_step(
    conn: &rusqlite::Connection,
    agent_id: &str,
    q_blob: &[u8],
    dir: &str,
    parent_score: f32,
    depth_remaining: u32,
    meta_scores: &HashMap<String, f32>,
    visited: &mut HashSet<String>,
    discovered: &mut HashMap<String, ContentRow>,
) -> Result<(), DbError> {
    if depth_remaining == 0 {
        // Per-chain depth cap — defense-in-depth bound (T-descent-07).
        return Ok(());
    }
    if dir.is_empty() {
        // Workspace-root skip (rebuild's normalize_workspace_path produces
        // "" for root; every content row sits under root, so descent into
        // "" would trivially re-execute the global dense_content scan).
        return Ok(());
    }
    if !visited.insert(dir.to_string()) {
        // Already visited in a sibling chain — early return BEFORE SQL.
        return Ok(());
    }

    // Direct-children-only SQL (PRD §8.3.4 search_in_directory semantic):
    //   LIKE 'dir/%' picks up everything nested below dir;
    //   AND NOT LIKE 'dir/%/%' restricts to files DIRECTLY in dir.
    // Deeper levels are reached via the sub-dir recursion path below.
    // No similarity-threshold filter on descent SQL — descent's purpose
    // is to surface low-self-similarity content under high-meta-similarity
    // directories that the global dense filter (>= DENSE_THRESHOLD) missed.
    //
    // Round-9 audit fix: escape SQLite LIKE special chars (`\`, `%`, `_`) in
    // `dir` and use `ESCAPE '\'` to prevent wildcard injection from POSIX-
    // legal directory names containing `%` / `_` / `\`. Without this, a dir
    // named e.g. `100%` would expand `100%/%` to a wildcard matching
    // `100abc/file.md` etc. — cross-directory false-positives.
    let dir_esc = escape_like(dir);
    let direct_pattern = format!("{dir_esc}/%");
    let nested_pattern = format!("{dir_esc}/%/%");
    let mut stmt = conn.prepare(
        "SELECT c.id, c.file_path, c.content_preview, c.access_count, \
                c.last_accessed, c.last_modified, \
                (1.0 - vec_distance_cosine(cv.embedding, ?1) / 2.0) AS similarity \
         FROM content_index c JOIN content_vec cv ON cv.rowid = c.rowid \
         WHERE c.agent_id = ?2 \
           AND c.file_path LIKE ?3 ESCAPE '\\' \
           AND c.file_path NOT LIKE ?4 ESCAPE '\\' \
         ORDER BY similarity DESC LIMIT ?5",
    )?;
    let iter = stmt.query_map(
        rusqlite::params![
            q_blob,
            agent_id,
            &direct_pattern,
            &nested_pattern,
            MAX_DESCENT_FANOUT
        ],
        |row| -> rusqlite::Result<ContentRow> {
            let similarity: f64 = row.get(6)?;
            map_content_row(row, similarity as f32)
        },
    )?;
    for r in iter {
        let r = r?;
        discovered
            .entry(r.id.clone())
            .and_modify(|existing| {
                if r.similarity > existing.similarity {
                    existing.similarity = r.similarity;
                }
            })
            .or_insert(r);
    }

    // Recursion gate (PRD §8.3.4 line 2253): for each meta-known IMMEDIATE
    // sub-directory `s` of `dir` (parent_dir(s) == dir), recurse if
    // propagated final_score > DENSE_THRESHOLD.
    for (s, sub_meta_sim) in meta_scores.iter() {
        let parent_of_s = s.rsplit_once('/').map(|(p, _)| p).unwrap_or("");
        if parent_of_s != dir {
            continue;
        }
        let propagated = sub_meta_sim * 0.5 + parent_score * 0.5;
        if propagated > DENSE_THRESHOLD {
            recursive_descent_step(
                conn,
                agent_id,
                q_blob,
                s,
                propagated,
                depth_remaining - 1,
                meta_scores,
                visited,
                discovered,
            )?;
        }
    }

    Ok(())
}

// =============================================================================
// internal merge row (dense + sparse + descent content rows funnel through this type)
// =============================================================================

#[derive(Clone, Debug)]
pub(crate) struct ContentRow {
    pub(crate) id: String,
    pub(crate) file_path: String,
    pub(crate) content_preview: Option<String>,
    pub(crate) access_count: u32,
    pub(crate) last_accessed: Option<DateTime<Utc>>,
    pub(crate) last_modified: DateTime<Utc>,
    pub(crate) similarity: f32, // post merge: max(dense_cosine, fts_score, descent_cosine)
}

/// Map a content_index-shaped result row (cols 0-5) into a `ContentRow`.
/// Unifies the NULL-fallback chain (`last_modified` → `last_accessed` →
/// epoch) across the dense_content + sparse FTS + descent call sites.
///
/// The caller computes `similarity` per-source — col 6 is intentionally NOT
/// read inside this helper since dense and FTS queries have different col-6
/// types (`vec_distance_cosine` produces `f64` similarity directly; FTS
/// `content_fts.rank` is a BM25 `f64` requiring `score_from_fts_rank`
/// transform). All call sites pre-compute `similarity` from col 6 and pass
/// it as a parameter — the helper guarantees the OTHER 6 columns map
/// identically. This satisfies Slice F's "byte-identical row construction
/// for the same id across all callers" invariant (modulo the per-source
/// similarity), so the entry-and-modify dedup pattern preserves first-found
/// timestamps + access counters without decay-term divergence.
pub(crate) fn map_content_row(
    row: &rusqlite::Row<'_>,
    similarity: f32,
) -> rusqlite::Result<ContentRow> {
    let id: String = row.get(0)?;
    let file_path: String = row.get(1)?;
    let content_preview: Option<String> = row.get(2)?;
    let access_count: i64 = row.get::<_, Option<i64>>(3)?.unwrap_or(0);
    let last_accessed_str: Option<String> = row.get(4)?;
    // last_modified is TEXT in schema (no NOT NULL constraint).
    // Per score.rs §1.4.3 mapping: fall back to last_accessed if present,
    // else to epoch (1970-01-01) so corrupt-row recall does not abort.
    let last_modified_str: Option<String> = row.get(5)?;
    let last_accessed = match last_accessed_str.as_deref() {
        Some(s) => Some(parse_ts(4, s)?),
        None => None,
    };
    let last_modified = match last_modified_str.as_deref() {
        Some(s) => parse_ts(5, s)?,
        None => last_accessed.unwrap_or_else(epoch_utc),
    };
    Ok(ContentRow {
        id,
        file_path,
        content_preview,
        access_count: access_count.max(0) as u32,
        last_accessed,
        last_modified,
        similarity,
    })
}

#[derive(Clone, Debug)]
struct MemoryRow {
    id: String,
    content: String,
    similarity: f32,
    access_count: u32,
    last_accessed: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    status: Option<String>,
}

// =============================================================================
// recall_blocking — synchronous body of recall()
// =============================================================================

pub(crate) fn recall_blocking(
    conn: &mut rusqlite::Connection,
    agent_id: &str,
    keywords: &[String],
    query_embedding: &[f32],
    limit: u32,
    now: DateTime<Utc>,
    max_depth: u32,
) -> Result<Vec<RecallResult>, DbError> {
    let q_blob = embedding_to_blob(query_embedding);
    let over_fetch = (limit.saturating_mul(2).min(MAX_LIMIT)) as i64;
    let dense_threshold = DENSE_THRESHOLD as f64;

    // Dense content.
    let mut content_rows: HashMap<String, ContentRow> = HashMap::new();
    {
        let mut stmt = conn.prepare(
            "SELECT c.id, c.file_path, c.content_preview, c.access_count, \
                    c.last_accessed, c.last_modified, \
                    (1.0 - vec_distance_cosine(cv.embedding, ?1) / 2.0) AS similarity \
             FROM content_index c JOIN content_vec cv ON cv.rowid = c.rowid \
             WHERE c.agent_id = ?2 AND similarity >= ?3 \
             ORDER BY similarity DESC LIMIT ?4",
        )?;
        let iter = stmt.query_map(
            rusqlite::params![&q_blob, agent_id, dense_threshold, over_fetch],
            |row| -> rusqlite::Result<ContentRow> {
                let similarity: f64 = row.get(6)?;
                map_content_row(row, similarity as f32)
            },
        )?;
        for r in iter {
            let r = r?;
            content_rows.insert(r.id.clone(), r);
        }
    }

    // Dense memory.
    let mut memory_rows: Vec<MemoryRow> = Vec::new();
    {
        // Round-11 finding C1 (Codex Diff): memory_index recall filters to
        // active rows only — `status='superseded'` and `status='forgotten'`
        // memories MUST NOT be returned (PRD §11.3.2 + §8.3 memory recall
        // contract). The schema's `is_active` column + `status` enum are the
        // load-bearing fields; we filter on both for defense-in-depth (a
        // producer that flips status without is_active or vice versa is still
        // excluded).
        let mut stmt = conn.prepare(
            "SELECT m.id, m.content, m.access_count, m.last_accessed, m.created_at, m.status, \
                    (1.0 - vec_distance_cosine(mv.embedding, ?1) / 2.0) AS similarity \
             FROM memory_index m JOIN memory_vec mv ON mv.rowid = m.rowid \
             WHERE m.agent_id = ?2 \
                   AND COALESCE(m.is_active, 1) = 1 \
                   AND (m.status IS NULL OR m.status NOT IN ('superseded', 'forgotten')) \
                   AND similarity >= ?3 \
             ORDER BY similarity DESC LIMIT ?4",
        )?;
        let iter = stmt.query_map(
            rusqlite::params![&q_blob, agent_id, dense_threshold, over_fetch],
            |row| -> rusqlite::Result<MemoryRow> {
                let id: String = row.get(0)?;
                let content: String = row.get(1)?;
                let access_count: i64 = row.get::<_, Option<i64>>(2)?.unwrap_or(0);
                let last_accessed_str: Option<String> = row.get(3)?;
                let created_at_str: String = row.get(4)?;
                let status: Option<String> = row.get(5)?;
                let similarity: f64 = row.get(6)?;
                Ok(MemoryRow {
                    id,
                    content,
                    similarity: similarity as f32,
                    access_count: access_count.max(0) as u32,
                    last_accessed: match last_accessed_str {
                        Some(s) => Some(parse_ts(3, &s)?),
                        None => None,
                    },
                    created_at: parse_ts(4, &created_at_str)?,
                    status,
                })
            },
        )?;
        for r in iter {
            memory_rows.push(r?);
        }
    }

    // Sparse content via FTS5 — only when keywords non-empty.
    if !keywords.is_empty() {
        let match_expr = build_match_expression(keywords);
        let mut stmt = conn.prepare(
            "SELECT c.id, c.file_path, c.content_preview, c.access_count, \
                    c.last_accessed, c.last_modified, content_fts.rank \
             FROM content_fts JOIN content_index c ON c.rowid = content_fts.rowid \
             WHERE content_fts MATCH ?1 AND c.agent_id = ?2 \
             ORDER BY content_fts.rank LIMIT ?3",
        )?;
        let iter = stmt.query_map(
            rusqlite::params![&match_expr, agent_id, over_fetch],
            |row| -> rusqlite::Result<ContentRow> {
                let rank: f64 = row.get(6)?;
                map_content_row(row, score_from_fts_rank(rank))
            },
        )?;
        for r in iter {
            let r = r?;
            content_rows
                .entry(r.id.clone())
                .and_modify(|existing| {
                    if r.similarity > existing.similarity {
                        existing.similarity = r.similarity;
                    }
                })
                .or_insert(r);
        }
    }

    // Dense meta — directory routing for parent_score lookup.
    let mut meta_scores: HashMap<String, f32> = HashMap::new();
    {
        // Round-14 (adversarial) finding: cap meta routing candidate set to
        // MAX_LIMIT. Other dense queries already cap via over_fetch; meta
        // was the only outlier prior to this fix.
        let meta_cap = MAX_LIMIT as i64;
        let mut stmt = conn.prepare(
            "SELECT m.directory, \
                    (1.0 - vec_distance_cosine(mv.embedding, ?1) / 2.0) AS similarity \
             FROM meta_index m JOIN meta_vec mv ON mv.rowid = m.rowid \
             WHERE m.agent_id = ?2 AND similarity >= ?3 \
             ORDER BY similarity DESC LIMIT ?4",
        )?;
        let iter = stmt.query_map(
            rusqlite::params![&q_blob, agent_id, dense_threshold, meta_cap],
            |row| -> rusqlite::Result<(String, f32)> {
                let dir: String = row.get(0)?;
                let sim: f64 = row.get(1)?;
                Ok((dir, sim as f32))
            },
        )?;
        for r in iter {
            let (dir, sim) = r?;
            // Track the maximum similarity per directory in case the same dir
            // appears multiple times (defensive — meta_index has no UNIQUE on
            // directory but the Slice C seed convention writes one row per dir).
            meta_scores
                .entry(dir)
                .and_modify(|existing| {
                    if sim > *existing {
                        *existing = sim;
                    }
                })
                .or_insert(sim);
        }
    }

    // Slice F: descent into high-scoring meta dirs (PRD §8.3.4 second half).
    // For every meta_scores entry ≥ DENSE_THRESHOLD, pull in direct-child
    // content rows (LIKE 'dir/%' AND NOT LIKE 'dir/%/%') and recurse into
    // immediate meta-known sub-dirs whose propagated final_score
    // = sub_meta_sim*0.5 + parent_score*0.5 > DENSE_THRESHOLD. Discovered
    // rows merge into content_rows via max-similarity dedup and then flow
    // through the existing parent_score_for_path + compute_adjusted_score
    // scoring loop unmodified.
    let mut descended: HashMap<String, ContentRow> = HashMap::new();
    descend_into_dirs(
        &conn,
        agent_id,
        &q_blob,
        max_depth,
        &meta_scores,
        &mut descended,
    )?;
    for (id, row) in descended.into_iter() {
        content_rows
            .entry(id)
            .and_modify(|existing| {
                // Max-similarity wins. Both row-mappers (global + descent)
                // produce byte-identical ContentRow for the same id (modulo
                // similarity) since they call map_content_row uniformly, and
                // no SQL writes intervene between the dense scan and the
                // descent scan — first-found timestamps + access counters
                // are preserved on UPDATE; only similarity is bumped if the
                // new row's sim is strictly greater.
                if row.similarity > existing.similarity {
                    existing.similarity = row.similarity;
                }
            })
            .or_insert(row);
    }

    // Score every hit.
    let mut results: Vec<RecallResult> = Vec::new();

    for (_id, c) in content_rows.into_iter() {
        let parent = parent_score_for_path(&c.file_path, &meta_scores, max_depth);
        let directory = c
            .file_path
            .rsplit_once('/')
            .map(|(d, _)| d.to_string())
            .or(Some(String::new()));
        let sr = SearchResult {
            self_score: c.similarity,
            access_count: c.access_count,
            last_modified: c.last_modified,
            last_accessed: c.last_accessed,
            source: Source::Content,
            status: None,
            // content_index has no `created_at` column; proxy from last_modified
            // per the score.rs per-source mapping rustdoc.
            created_at: c.last_modified,
        };
        let adjusted = compute_adjusted_score(&sr, parent, now);
        results.push(RecallResult {
            id: c.id,
            source: Source::Content,
            file_path: Some(c.file_path),
            content_preview: c.content_preview,
            content_full: None,
            similarity: c.similarity,
            parent_score: parent,
            adjusted_score: adjusted,
            access_count: c.access_count,
            last_modified: c.last_modified,
            last_accessed: c.last_accessed,
            status: None,
            created_at: c.last_modified,
            directory,
        });
    }

    for m in memory_rows.into_iter() {
        let sr = SearchResult {
            self_score: m.similarity,
            access_count: m.access_count,
            last_modified: m.created_at,
            last_accessed: m.last_accessed,
            source: Source::Memory,
            status: m.status.clone(),
            created_at: m.created_at,
        };
        // Memory has no directory hierarchy → parent_score = self_score
        // (collapses base = self*0.5 + parent*0.5 to base = self_score).
        let adjusted = compute_adjusted_score(&sr, m.similarity, now);
        results.push(RecallResult {
            id: m.id,
            source: Source::Memory,
            file_path: None,
            content_preview: None,
            content_full: Some(m.content),
            similarity: m.similarity,
            parent_score: m.similarity,
            adjusted_score: adjusted,
            access_count: m.access_count,
            last_modified: m.created_at,
            last_accessed: m.last_accessed,
            status: m.status,
            created_at: m.created_at,
            directory: None,
        });
    }

    // Sort by adjusted_score DESC; truncate.
    results.sort_by(|a, b| {
        b.adjusted_score
            .partial_cmp(&a.adjusted_score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    results.truncate(limit as usize);

    // Post-recall access update — single transaction over content + memory.
    let content_ids: Vec<&str> = results
        .iter()
        .filter(|r| r.source == Source::Content)
        .map(|r| r.id.as_str())
        .collect();
    let memory_ids: Vec<&str> = results
        .iter()
        .filter(|r| r.source == Source::Memory)
        .map(|r| r.id.as_str())
        .collect();

    if !content_ids.is_empty() || !memory_ids.is_empty() {
        // Renamed from `now_text` to `now_text_str` in m004-slice-e to avoid
        // shadowing the hoisted `crate::now_text` helper at this scope.
        let now_text_str = ts_to_text(&now);
        let tx = conn.transaction()?;
        if !content_ids.is_empty() {
            let placeholders: Vec<&str> = content_ids.iter().map(|_| "?").collect();
            let sql = format!(
                "UPDATE content_index SET access_count = COALESCE(access_count, 0) + 1, last_accessed = ?1 \
                 WHERE agent_id = ?2 AND id IN ({})",
                placeholders.join(",")
            );
            let mut params: Vec<&dyn rusqlite::ToSql> = vec![&now_text_str, &agent_id];
            for id in &content_ids {
                params.push(id);
            }
            tx.execute(&sql, params.as_slice())?;
        }
        if !memory_ids.is_empty() {
            let placeholders: Vec<&str> = memory_ids.iter().map(|_| "?").collect();
            let sql = format!(
                "UPDATE memory_index SET access_count = COALESCE(access_count, 0) + 1, last_accessed = ?1 \
                 WHERE agent_id = ?2 AND id IN ({})",
                placeholders.join(",")
            );
            let mut params: Vec<&dyn rusqlite::ToSql> = vec![&now_text_str, &agent_id];
            for id in &memory_ids {
                params.push(id);
            }
            tx.execute(&sql, params.as_slice())?;
        }
        tx.commit()?;
    }

    // Patch returned access_count + last_accessed to post-update values so
    // callers do not need a second SELECT.
    for r in &mut results {
        r.access_count = r.access_count.saturating_add(1);
        r.last_accessed = Some(now);
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    // `embedding_to_blob` is no longer in `super::*` after m004-slice-e's
    // dedup; import the hoisted helper explicitly.
    use crate::embedding_to_blob;

    fn one_hot(idx: usize) -> Vec<f32> {
        let mut v = vec![0.0_f32; 768];
        v[idx] = 1.0;
        v
    }

    #[test]
    fn validate_query_embedding_rejects_wrong_len() {
        let r = validate_query_embedding(&[], crate::DEFAULT_EMBEDDING_DIM);
        assert!(matches!(r, Err(DbError::InvalidConfig(_))));
        let r = validate_query_embedding(&[0.0; 100], crate::DEFAULT_EMBEDDING_DIM);
        assert!(matches!(r, Err(DbError::InvalidConfig(_))));
    }

    #[test]
    fn validate_query_embedding_rejects_nan() {
        let mut v = one_hot(0);
        v[0] = f32::NAN;
        let r = validate_query_embedding(&v, crate::DEFAULT_EMBEDDING_DIM);
        assert!(matches!(r, Err(DbError::InvalidConfig(_))));
    }

    #[test]
    fn validate_query_embedding_accepts_valid() {
        assert!(validate_query_embedding(&one_hot(0), crate::DEFAULT_EMBEDDING_DIM).is_ok());
    }

    #[test]
    fn ts_roundtrip() {
        let ts = chrono::DateTime::<Utc>::from_timestamp(1735_689_600, 0).unwrap();
        let s = ts_to_text(&ts);
        let parsed = parse_ts(0, &s).unwrap();
        assert_eq!(parsed, ts);
    }

    #[test]
    fn embedding_blob_roundtrip() {
        let v = vec![0.0_f32, 1.0, -1.0, 0.5, f32::MIN_POSITIVE];
        let blob = embedding_to_blob(&v);
        let decoded = blob_to_embedding(&blob);
        assert_eq!(v, decoded);
    }

    #[test]
    fn parent_score_single_level() {
        let mut meta = HashMap::new();
        meta.insert("dir_a".to_string(), 0.8);
        let p = parent_score_for_path("dir_a/file.md", &meta, 3);
        assert!((p - 0.8).abs() < 1e-6);
    }

    #[test]
    fn parent_score_three_level_recursive() {
        let mut meta = HashMap::new();
        meta.insert("dir_a/dir_b/dir_c".to_string(), 0.3);
        meta.insert("dir_a/dir_b".to_string(), 0.5);
        meta.insert("dir_a".to_string(), 0.7);
        let p = parent_score_for_path("dir_a/dir_b/dir_c/leaf.md", &meta, 3);
        // bottom-up: p=0.7; p=0.5*0.5+0.7*0.5=0.6; p=0.3*0.5+0.6*0.5=0.45
        assert!((p - 0.45).abs() < 1e-6);
    }

    #[test]
    fn parent_score_depth_limit_excludes_too_deep() {
        let mut meta = HashMap::new();
        meta.insert("a".to_string(), 0.9);
        meta.insert("a/b/c/d".to_string(), 0.2);
        // file at a/b/c/d/leaf.md; ancestors closest-first:
        //   [a/b/c/d (0.2), a/b/c (0.0), a/b (0.0)] — `a` at depth 4 excluded.
        // Bottom-up fold: p=0.0 → 0.0 → 0.2*0.5 + 0.0*0.5 = 0.1
        let p = parent_score_for_path("a/b/c/d/leaf.md", &meta, 3);
        assert!((p - 0.1).abs() < 1e-6);
    }

    #[test]
    fn parent_score_no_meta_hits() {
        let meta = HashMap::new();
        let p = parent_score_for_path("dir_a/file.md", &meta, 3);
        assert_eq!(p, 0.0);
    }

    #[test]
    fn parent_score_tolerates_trailing_slash() {
        let mut meta = HashMap::new();
        meta.insert("dir_a/".to_string(), 0.6);
        let p = parent_score_for_path("dir_a/file.md", &meta, 3);
        assert!((p - 0.6).abs() < 1e-6);
    }

    /// MODULE-004-T-descent-07 (AC-20b): `recursive_descent_step` early-return
    /// on `depth_remaining == 0`. Indirect proof that no SQL was executed:
    /// `visited` stays empty (the implementation visits BEFORE preparing SQL,
    /// so an empty visited proves the SQL prepare path was not reached).
    #[test]
    fn recursive_descent_step_depth_zero_short_circuit() {
        let h = crate::handle::R2d2SqliteIndexHandle::new_in_memory().expect("handle");
        let conn = h.get_conn().unwrap();
        let q_blob = embedding_to_blob(&one_hot(0));
        let meta_scores: HashMap<String, f32> = HashMap::new();
        let mut visited: HashSet<String> = HashSet::new();
        let mut discovered: HashMap<String, ContentRow> = HashMap::new();
        recursive_descent_step(
            &conn,
            "agent1",
            &q_blob,
            "any_dir",
            0.5_f32,
            0_u32,
            &meta_scores,
            &mut visited,
            &mut discovered,
        )
        .expect("ok");
        assert_eq!(discovered.len(), 0, "depth=0 must NOT discover any rows");
        assert_eq!(
            visited.len(),
            0,
            "depth=0 must early-return BEFORE visited.insert (indirect SQL-not-prepared proof)"
        );
    }
}

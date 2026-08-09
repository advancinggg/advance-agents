//! CONTRACT-033 `IndexRebuild` trait + `R2d2IndexRebuildImpl<H, E>` for
//! MODULE-004 Slice D — rebuild SQLite index tables from the workspace
//! filesystem source-of-truth.
//!
//! Per PRD §8.4 line 2283, runtime startup re-rebuilds the entire index
//! by scanning the workspace's `.meta.yaml` files + content files +
//! per-agent `.agent/memory/knowledge.jsonl` + `.agent/tasks/{active,
//! archived}/<task-id>/{summary,turn-index}.yaml`. `access_count` and
//! `last_accessed` runtime statistics fields are reset to 0 / NULL on
//! every rebuild for the three access-tracked tables (content_index,
//! memory_index, turn_index).
//!
//! ## Embedder injection (dependency inversion)
//!
//! MODULE-004 has no compile-time edge to `cap-llm` (CONTRACT-081). The
//! local [`Embedder`] trait is implemented at composition time by a
//! runtime adapter that maps `LlmGatewayInternal::embed` → `Embedder::embed`.
//! The blanket impl `impl<E: Embedder + ?Sized> Embedder for Arc<E>`
//! lets composers inject either concrete generics or an
//! `Arc<dyn Embedder>` for runtime polymorphism.
//!
//! ## Crash recovery
//!
//! `rebuild_full` is intentionally NOT a single SQL transaction (per-row
//! embed() round-trips would block writes for minutes). Truncate IS
//! transactional, but per-row inserts are not. On hard kill mid-rebuild,
//! the next runtime startup re-runs `rebuild_full`, which truncates
//! again and re-populates from the filesystem. This is the canonical
//! PRD §8.4-blessed recovery mechanism.

use std::ffi::OsStr;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use chrono::{DateTime, SecondsFormat, Utc};
use rusqlite::{params, Connection, ErrorCode, TransactionBehavior};
use serde::Deserialize;
use walkdir::WalkDir;

use crate::error::DbError;
use crate::handle::SqliteIndexHandle;

const MAX_REBUILD_ERRORS: usize = 1024;
const PREVIEW_MAX_CHARS: usize = 2000;
/// Per-error string byte cap. Round-2 adversarial fix: every error
/// message in `RebuildReport.errors` is bounded to this length so a
/// hostile workspace cannot amplify its 1 MB JSONL line into a
/// MAX_REBUILD_ERRORS × 1 MB ≈ 1 GB heap balloon via debug-formatted
/// interpolation of attacker-controlled fields.
const MAX_ERROR_MSG_BYTES: usize = 512;
/// Per-interpolated-field byte cap for user-supplied strings (id,
/// agent_id, status, etc.) before they enter a `format!()` template.
/// Truncated form has a `…(truncated)` suffix so operators can tell
/// the value was longer.
const MAX_FIELD_DISPLAY_BYTES: usize = 80;
/// Hard cap on the raw byte size of any single content file the rebuild
/// scanner reads into memory (Round-1 adversarial C2 fix). Files
/// exceeding this are skipped with an error entry — the rebuild does
/// not abort. 10 MB is generous for any legitimate content file.
const MAX_SOURCE_BYTES: usize = 10 * 1024 * 1024;
/// Hard cap on the raw byte size of any single YAML source file
/// (.meta.yaml / summary.yaml / turn-index.yaml). 1 MB is generous
/// for legitimate metadata (typical .meta.yaml is < 10 KB; even a
/// large turn-index.yaml with hundreds of turns rarely exceeds
/// 100 KB). The tighter cap here vs MAX_SOURCE_BYTES bounds the
/// post-parse `serde_yml::Value` tree memory amplification (Round-3
/// adversarial fix): a deeply-nested `[[[...]]]` payload at 1 MB
/// expands to at most ~30 MB of in-memory Value tree, vs ~300 MB
/// at the 10 MB cap.
const MAX_YAML_BYTES: usize = 1 * 1024 * 1024;
/// Hard cap on a single knowledge.jsonl line. Same rationale —
/// blocks line-level JSON payload bombs.
const MAX_JSONL_LINE_BYTES: usize = 1 * 1024 * 1024;

// ──────────────────────────────────────────────────────────────────────
// Embedder injection trait
// ──────────────────────────────────────────────────────────────────────

/// Slice D embedder injection trait. The runtime composer wires
/// MODULE-009 CONTRACT-081 `LlmGatewayInternal::embed` →
/// `Embedder::embed` at composition time; MODULE-004 has no compile-time
/// dependency on cap-llm. The blanket impl `impl<E: Embedder + ?Sized>
/// Embedder for Arc<E>` lets composers inject either zero-cost generics
/// or `Arc<dyn Embedder>` for runtime polymorphism.
#[async_trait]
pub trait Embedder: Send + Sync {
    async fn embed(&self, text: &str) -> Result<Vec<f32>, EmbedderError>;
}

#[async_trait]
impl<E: Embedder + ?Sized> Embedder for Arc<E> {
    async fn embed(&self, text: &str) -> Result<Vec<f32>, EmbedderError> {
        (**self).embed(text).await
    }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum EmbedderError {
    Failed(String),
}

impl std::fmt::Display for EmbedderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Failed(msg) => write!(f, "embed failed: {msg}"),
        }
    }
}

impl std::error::Error for EmbedderError {}

// ──────────────────────────────────────────────────────────────────────
// Result types
// ──────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Default)]
pub struct RebuildReport {
    pub meta_rows: u64,
    pub content_rows: u64,
    pub memory_rows: u64,
    pub task_rows: u64,
    pub turn_rows: u64,
    pub embed_calls: u64,
    pub elapsed_ms: u64,
    pub errors: Vec<String>,
}

impl RebuildReport {
    fn push_error(&mut self, msg: String) {
        // Round-2 adversarial fix: cap each individual error message
        // BEFORE storing — even the count cap doesn't help if every
        // entry is 1MB.
        let msg = cap_error_msg(msg);
        // Cap: total `errors` length stays at most MAX_REBUILD_ERRORS,
        // INCLUDING any trailing "… N more errors truncated" sentinel.
        // Once we reach MAX_REBUILD_ERRORS - 1 real entries plus 1 sentinel
        // slot, every subsequent push increments the sentinel's N counter.
        if self.errors.len() < MAX_REBUILD_ERRORS - 1 {
            self.errors.push(msg);
            return;
        }
        // We're at MAX_REBUILD_ERRORS - 1 (1023): time to add or update sentinel.
        if self.errors.len() == MAX_REBUILD_ERRORS - 1 {
            self.errors.push("… 1 more errors truncated".to_string());
            return;
        }
        // We're at MAX_REBUILD_ERRORS (1024): update the trailing sentinel count.
        let last = self.errors.last_mut().expect("non-empty");
        let parsed: u64 = last
            .strip_prefix("… ")
            .and_then(|s| s.strip_suffix(" more errors truncated"))
            .and_then(|s| s.parse().ok())
            .unwrap_or(1);
        *last = format!("… {} more errors truncated", parsed + 1);
    }

    fn merge(&mut self, other: ScannerStats) {
        // Bucket-specific row counters set by caller; we only fold embed_calls + errors here.
        self.embed_calls += other.embed_calls;
        for e in other.errors {
            self.push_error(e);
        }
    }
}

/// Per-scanner accumulator. The caller adds `rows_inserted` to the
/// appropriate field of `RebuildReport` based on which scanner ran.
#[derive(Default)]
struct ScannerStats {
    rows_inserted: u64,
    embed_calls: u64,
    errors: ErrorBag,
}

/// Wrapper around `Vec<String>` that caps each entry to
/// `MAX_ERROR_MSG_BYTES` on push. Round-2 adversarial fix —
/// scanner-side mirror of `RebuildReport::push_error`'s cap so the
/// final merge into RebuildReport is double-bounded (per-scanner +
/// per-RebuildReport caps both apply).
#[derive(Default)]
struct ErrorBag(Vec<String>);

impl ErrorBag {
    fn push(&mut self, msg: String) {
        self.0.push(cap_error_msg(msg));
    }
}

impl IntoIterator for ErrorBag {
    type Item = String;
    type IntoIter = std::vec::IntoIter<String>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

// ──────────────────────────────────────────────────────────────────────
// IndexRebuild trait
// ──────────────────────────────────────────────────────────────────────

#[async_trait]
pub trait IndexRebuild: Send + Sync {
    async fn rebuild_full(&self) -> Result<RebuildReport, DbError>;
    async fn rebuild_agent(&self, agent_id: &str) -> Result<RebuildReport, DbError>;
}

pub struct R2d2IndexRebuildImpl<H, E>
where
    H: SqliteIndexHandle + Clone + 'static,
    E: Embedder + Clone + 'static,
{
    handle: H,
    embedder: E,
    workspace_root: PathBuf,
    /// Slice G: live tunables provider. Plain `Arc<dyn>` (no Mutex) so the
    /// struct preserves its existing ownership semantics. The provider
    /// itself reads through to the watcher's snapshot on each `current()`.
    tunables: Arc<dyn crate::TunablesProvider>,
}

impl<H, E> R2d2IndexRebuildImpl<H, E>
where
    H: SqliteIndexHandle + Clone + 'static,
    E: Embedder + Clone + 'static,
{
    pub fn new(handle: H, embedder: E, workspace_root: PathBuf) -> Self {
        Self {
            handle,
            embedder,
            workspace_root,
            tunables: crate::default_tunables_provider(),
        }
    }

    /// Slice G: production wiring with a live `TunablesProvider`. Threads
    /// `tunables.current().embedding_dim` through to `embed_or_skip` so
    /// the rebuild path enforces the live dim on Embedder outputs.
    pub fn with_tunables(
        handle: H,
        embedder: E,
        workspace_root: PathBuf,
        tunables: Arc<dyn crate::TunablesProvider>,
    ) -> Self {
        Self {
            handle,
            embedder,
            workspace_root,
            tunables,
        }
    }
}

#[async_trait]
impl<H, E> IndexRebuild for R2d2IndexRebuildImpl<H, E>
where
    H: SqliteIndexHandle + Clone + 'static,
    E: Embedder + Clone + 'static,
{
    async fn rebuild_full(&self) -> Result<RebuildReport, DbError> {
        let start = Instant::now();
        let mut report = RebuildReport::default();

        // Step 1: single-transaction TRUNCATE of all 11 surfaces.
        truncate_all(&self.handle).await?;

        // Step 2: enumerate agent territories deterministically.
        let territories = agent_dirs(&self.workspace_root)
            .map_err(|e| DbError::Internal(format!("io: agent_dirs: {e}")))?;

        // Slice G: read tunables ONCE per rebuild — embedding_dim is
        // threaded into embed_or_skip so the dim check on Embedder
        // outputs follows the live snapshot.
        let expected_dim = self.tunables.current().embedding_dim;

        // Step 3: per-territory, scanners (a)..(e) sequentially.
        for terr in &territories {
            run_scanners(
                &self.handle,
                &self.embedder,
                &self.workspace_root,
                terr,
                expected_dim,
                &mut report,
            )
            .await?;
        }

        report.elapsed_ms = start.elapsed().as_millis() as u64;
        Ok(report)
    }

    async fn rebuild_agent(&self, agent_id: &str) -> Result<RebuildReport, DbError> {
        let start = Instant::now();
        let mut report = RebuildReport::default();

        truncate_agent(&self.handle, agent_id).await?;

        let territories = agent_dirs(&self.workspace_root)
            .map_err(|e| DbError::Internal(format!("io: agent_dirs: {e}")))?;
        let target = territories
            .into_iter()
            .find(|t| t.agent_id == agent_id)
            .ok_or_else(|| {
                DbError::InvalidConfig(format!("agent_id {agent_id:?} not found in workspace"))
            })?;

        let expected_dim = self.tunables.current().embedding_dim;

        run_scanners(
            &self.handle,
            &self.embedder,
            &self.workspace_root,
            &target,
            expected_dim,
            &mut report,
        )
        .await?;

        report.elapsed_ms = start.elapsed().as_millis() as u64;
        Ok(report)
    }
}

// ──────────────────────────────────────────────────────────────────────
// Truncate orchestration
// ──────────────────────────────────────────────────────────────────────

async fn truncate_all<H: SqliteIndexHandle + Clone + 'static>(handle: &H) -> Result<(), DbError> {
    let h = handle.clone();
    tokio::task::spawn_blocking(move || -> Result<(), DbError> {
        let mut conn = h.get_conn()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        // *_vec / FTS first (rowid-coupled), then primary tables.
        for stmt in [
            "DELETE FROM meta_vec",
            "DELETE FROM content_vec",
            "DELETE FROM memory_vec",
            "DELETE FROM task_vec",
            "DELETE FROM turn_vec",
            "DELETE FROM content_fts",
            "DELETE FROM meta_index",
            "DELETE FROM content_index",
            "DELETE FROM memory_index",
            "DELETE FROM task_index",
            "DELETE FROM turn_index",
        ] {
            tx.execute(stmt, [])?;
        }
        tx.commit()?;
        Ok(())
    })
    .await
    .map_err(|e| DbError::Internal(format!("spawn_blocking: {e}")))?
}

async fn truncate_agent<H: SqliteIndexHandle + Clone + 'static>(
    handle: &H,
    agent_id: &str,
) -> Result<(), DbError> {
    let h = handle.clone();
    let agent = agent_id.to_string();
    tokio::task::spawn_blocking(move || -> Result<(), DbError> {
        let mut conn = h.get_conn()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        // Each *_vec by rowid via JOIN to its primary; then content_fts; then primaries.
        for join_stmt in [
            "DELETE FROM meta_vec WHERE rowid IN (SELECT rowid FROM meta_index WHERE agent_id = ?1)",
            "DELETE FROM content_vec WHERE rowid IN (SELECT rowid FROM content_index WHERE agent_id = ?1)",
            "DELETE FROM memory_vec WHERE rowid IN (SELECT rowid FROM memory_index WHERE agent_id = ?1)",
            "DELETE FROM task_vec WHERE rowid IN (SELECT rowid FROM task_index WHERE agent_id = ?1)",
            "DELETE FROM turn_vec WHERE rowid IN (SELECT rowid FROM turn_index WHERE agent_id = ?1)",
            "DELETE FROM content_fts WHERE rowid IN (SELECT rowid FROM content_index WHERE agent_id = ?1)",
            "DELETE FROM meta_index WHERE agent_id = ?1",
            "DELETE FROM content_index WHERE agent_id = ?1",
            "DELETE FROM memory_index WHERE agent_id = ?1",
            "DELETE FROM task_index WHERE agent_id = ?1",
            "DELETE FROM turn_index WHERE agent_id = ?1",
        ] {
            tx.execute(join_stmt, params![agent])?;
        }
        tx.commit()?;
        Ok(())
    })
    .await
    .map_err(|e| DbError::Internal(format!("spawn_blocking: {e}")))?
}

// ──────────────────────────────────────────────────────────────────────
// Workspace walker + agent enumeration
// ──────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
struct AgentTerritory {
    agent_id: String,
    agent_root: PathBuf,
}

/// Hidden directory names skipped by walkdir. Exact-string equality, NOT
/// prefix match — so `.agent-templates`, `.config`, `.gitlab` stay walkable.
fn is_hidden_dir(name: &OsStr) -> bool {
    matches!(
        name.to_str(),
        Some(".git" | ".runtime" | ".advance" | ".sub" | ".agent")
    )
}

/// Returns workspace-relative path for both directories (via meta_index)
/// and files (via content_index). Workspace root → `""`. Sub-paths get
/// a leading `/`. Forward slashes only. No trailing slash.
fn normalize_workspace_path(workspace_root: &Path, abs_path: &Path) -> String {
    let rel = abs_path.strip_prefix(workspace_root).unwrap_or(abs_path);
    let mut out = String::new();
    for comp in rel.components() {
        if let Component::Normal(s) = comp {
            out.push('/');
            out.push_str(&s.to_string_lossy());
        }
    }
    // out is "" for workspace root, "/research/notes.md" for nested.
    out
}

/// Workspace-relative agent_id encoding per Slice D convention:
/// - root agent (`<root>/.agent/`): `agent_id = "/"`
/// - first-level sub-agent (`<root>/research/.agent/`): `"research"`
/// - deeper sub-agent: slash-joined relative path
///
/// Returns `None` if the relative path contains any non-Normal
/// component (`..`, `.`, `Prefix`, `RootDir`) — Round-1 adversarial
/// C1 fix: rejects path-traversal in agent dir names that would
/// otherwise yield an empty `parts` Vec colliding with the root
/// agent's id encoding.
fn derive_agent_id(workspace_root: &Path, agent_root: &Path) -> Option<String> {
    if agent_root == workspace_root {
        return Some("/".to_string());
    }
    let rel = agent_root.strip_prefix(workspace_root).ok()?;
    let mut parts: Vec<String> = Vec::new();
    for comp in rel.components() {
        match comp {
            Component::Normal(s) => {
                let part = s.to_string_lossy().to_string();
                if !id_component_safe(&part) {
                    return None; // C0 control char in dir name — reject
                }
                parts.push(part);
            }
            // Reject `..`, `.`, drive prefixes, and root-dir markers.
            // These would yield an empty or misleading agent_id.
            _ => return None,
        }
    }
    if parts.is_empty() {
        // Empty Vec means the path was equivalent to workspace_root via
        // non-Normal components — defensively re-encode as None rather
        // than collide with root agent's "/".
        return None;
    }
    Some(parts.join("/"))
}

fn agent_dirs(workspace_root: &Path) -> std::io::Result<Vec<AgentTerritory>> {
    let mut out: Vec<AgentTerritory> = Vec::new();
    // sort_by_file_name() pins enumeration order across platforms.
    for entry in WalkDir::new(workspace_root)
        .follow_links(false)
        .sort_by_file_name()
        .into_iter()
        .filter_entry(|e| {
            // Skip hidden trees at any depth EXCEPT we still want to discover
            // .agent at depth 1 of any directory we visit (so we can record it
            // as a marker), then bail before descending. Since we only look at
            // .agent existence below for territory-marking, just skip hidden at
            // walkdir level — we'll find ".agent/" via direct probe.
            !is_hidden_dir(e.file_name())
        })
    {
        let entry = entry?;
        if entry.file_type().is_dir() {
            // Probe: does this directory contain a .agent/ subdirectory?
            let dot_agent = entry.path().join(".agent");
            if dot_agent.is_dir() {
                if let Some(agent_id) = derive_agent_id(workspace_root, entry.path()) {
                    out.push(AgentTerritory {
                        agent_id,
                        agent_root: entry.path().to_path_buf(),
                    });
                }
                // else: silently skip dirs whose path traversal would
                // collide with the root agent's id encoding (C1 fix).
            }
        }
    }
    Ok(out)
}

// ──────────────────────────────────────────────────────────────────────
// Per-territory orchestration
// ──────────────────────────────────────────────────────────────────────

async fn run_scanners<H, E>(
    handle: &H,
    embedder: &E,
    workspace_root: &Path,
    terr: &AgentTerritory,
    expected_dim: usize,
    report: &mut RebuildReport,
) -> Result<(), DbError>
where
    H: SqliteIndexHandle + Clone + 'static,
    E: Embedder + Clone + 'static,
{
    let m = scan_meta_yaml(handle, embedder, workspace_root, terr, expected_dim).await?;
    report.meta_rows += m.rows_inserted;
    report.merge(m);

    let c = scan_content_files(handle, embedder, workspace_root, terr, expected_dim).await?;
    report.content_rows += c.rows_inserted;
    report.merge(c);

    let k = scan_knowledge_jsonl(handle, embedder, terr, expected_dim).await?;
    report.memory_rows += k.rows_inserted;
    report.merge(k);

    let t = scan_summary_yaml(handle, embedder, terr, expected_dim).await?;
    report.task_rows += t.rows_inserted;
    report.merge(t);

    let u = scan_turn_index_yaml(handle, embedder, terr, expected_dim).await?;
    report.turn_rows += u.rows_inserted;
    report.merge(u);

    Ok(())
}

// ──────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────

fn unit_separator() -> char {
    '\u{1F}'
}

fn make_id(parts: &[&str]) -> String {
    parts.join(&unit_separator().to_string())
}

fn is_pk_collision(err: &rusqlite::Error) -> bool {
    if let rusqlite::Error::SqliteFailure(code, _) = err {
        if code.code == ErrorCode::ConstraintViolation {
            return code.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_PRIMARYKEY;
        }
    }
    false
}

// `now_text` and `embedding_to_blob` live in `crate::*` —
// hoisted in m004-slice-e for crate-wide reuse.
// Slice G: the `EMBEDDING_DIM` constant is no longer referenced from rebuild.rs;
// `embed_or_skip` now accepts `expected_dim` from the live `Tunables` snapshot.
use crate::{embedding_to_blob, now_text};

/// Read a file into memory with a hard size cap. Returns the file body
/// up to the per-call `cap`; if the file exceeds it, returns
/// `Err(SourceReadError::TooLarge)` with the actual size. (Round-1
/// adversarial C2/C3 + Round-3 W1 fix — bounds both raw read AND the
/// downstream parser's working set.)
fn read_capped_with(path: &Path, cap: usize) -> Result<String, SourceReadError> {
    let metadata = std::fs::metadata(path).map_err(SourceReadError::Io)?;
    if metadata.len() as u64 > cap as u64 {
        return Err(SourceReadError::TooLarge(metadata.len()));
    }
    let body = std::fs::read_to_string(path).map_err(SourceReadError::Io)?;
    if body.len() > cap {
        return Err(SourceReadError::TooLarge(body.len() as u64));
    }
    Ok(body)
}

/// Convenience: read a content file capped at MAX_SOURCE_BYTES.
fn read_capped(path: &Path) -> Result<String, SourceReadError> {
    read_capped_with(path, MAX_SOURCE_BYTES)
}

/// Convenience: read a YAML file capped at MAX_YAML_BYTES (tighter
/// than content files to bound `serde_yml::Value` post-parse memory).
fn read_capped_yaml(path: &Path) -> Result<String, SourceReadError> {
    read_capped_with(path, MAX_YAML_BYTES)
}

enum SourceReadError {
    Io(std::io::Error),
    TooLarge(u64),
}

impl std::fmt::Display for SourceReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "io: {e}"),
            Self::TooLarge(n) => write!(
                f,
                "file too large ({n} bytes; cap {MAX_SOURCE_BYTES} bytes)"
            ),
        }
    }
}

/// Reject U+001F (the unit-separator we use as id delimiter) and other
/// C0 control chars in any id component. (Round-1 adversarial W6 fix —
/// blocks PK collision forgery via control-char injection in directory
/// names / YAML keys / file paths.)
fn id_component_safe(s: &str) -> bool {
    !s.chars().any(|c| (c as u32) < 0x20 || c == '\u{7F}')
}

/// Reserved defensive helper: truncate a user-supplied string for safe
/// interpolation into an error message, replacing C0 control chars with
/// U+FFFD so the printed form can't break log parsers. Currently unused
/// because `cap_error_msg` does whole-message bounding; retained for
/// future per-field caps if the cap_error_msg total proves too coarse.
#[allow(dead_code)]
fn display_field(s: &str) -> String {
    let mut out = String::with_capacity(MAX_FIELD_DISPLAY_BYTES + 16);
    let mut bytes = 0;
    for c in s.chars() {
        let safe = if (c as u32) < 0x20 || c == '\u{7F}' {
            '\u{FFFD}'
        } else {
            c
        };
        let ch_len = safe.len_utf8();
        if bytes + ch_len > MAX_FIELD_DISPLAY_BYTES {
            out.push_str("…(truncated)");
            return out;
        }
        out.push(safe);
        bytes += ch_len;
    }
    out
}

/// Final guard: cap whole-error-message length AFTER interpolation
/// in case any individual format!() template produces unexpectedly
/// long output. (Round-2 adversarial fix.)
fn cap_error_msg(mut s: String) -> String {
    if s.len() > MAX_ERROR_MSG_BYTES {
        s.truncate(MAX_ERROR_MSG_BYTES.saturating_sub(12));
        s.push_str("…(truncated)");
    }
    s
}

/// Embed-or-skip: returns `Ok(Some(blob))` when text is non-empty AND embed
/// succeeds AND the returned vector has exactly `expected_dim` components;
/// `Ok(None)` when text is empty (caller skips *_vec write); `Err(DbError::Internal)`
/// on embed failure or dimension mismatch (Round-1 audit DiffW2 fix —
/// surface dim mismatch with an actionable message instead of an opaque
/// sqlite-vec error mid-rebuild).
///
/// Slice G: `expected_dim` is threaded from the live `Tunables` snapshot via
/// `R2d2IndexRebuildImpl::rebuild_full` / `rebuild_agent` (read once per
/// rebuild) and propagated through `run_scanners` + each `scan_*` function
/// to here, so a hot-reload of `embedding-dim` is observed by the next
/// rebuild call.
async fn embed_or_skip<E: Embedder>(
    embedder: &E,
    text: &str,
    expected_dim: usize,
    embed_calls: &mut u64,
) -> Result<Option<Vec<u8>>, DbError> {
    if text.is_empty() {
        return Ok(None);
    }
    *embed_calls += 1;
    match embedder.embed(text).await {
        Ok(v) => {
            if v.len() != expected_dim {
                return Err(DbError::Internal(format!(
                    "embed: returned vector has {} dimensions, expected {expected_dim} (schema constraint)",
                    v.len()
                )));
            }
            // Round-1 adversarial W8 fix: reject NaN / infinity to
            // prevent recall-time ranking poisoning via cosine NaN.
            if v.iter().any(|x| !x.is_finite()) {
                return Err(DbError::Internal(
                    "embed: returned vector contains non-finite values (NaN/inf)".to_string(),
                ));
            }
            Ok(Some(embedding_to_blob(&v)))
        }
        Err(e) => Err(DbError::Internal(format!("embed: {e}"))),
    }
}

// ──────────────────────────────────────────────────────────────────────
// Scanner (a): scan_meta_yaml
// ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Default, Deserialize)]
struct MetaScopeEntry {
    #[serde(default)]
    description: String,
    #[serde(default)]
    tags: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
struct MetaChildEntry {
    #[serde(default)]
    description: String,
    #[serde(default)]
    tags: Vec<String>,
}

async fn scan_meta_yaml<H, E>(
    handle: &H,
    embedder: &E,
    workspace_root: &Path,
    terr: &AgentTerritory,
    expected_dim: usize,
) -> Result<ScannerStats, DbError>
where
    H: SqliteIndexHandle + Clone + 'static,
    E: Embedder + Clone + 'static,
{
    let mut stats = ScannerStats::default();
    // Collect all .meta.yaml paths within this territory (skip hidden + nested .agent).
    let meta_files = collect_meta_files(workspace_root, &terr.agent_root);
    for meta_path in meta_files {
        let body = match read_capped_yaml(&meta_path) {
            Ok(s) => s,
            Err(e) => {
                stats
                    .errors
                    .push(format!("read {}: {e}", meta_path.display()));
                continue;
            }
        };
        let parsed: serde_yml::Value = match serde_yml::from_str(&body) {
            Ok(v) => v,
            Err(e) => {
                stats
                    .errors
                    .push(format!("parse {}: {e}", meta_path.display()));
                continue;
            }
        };
        let directory = normalize_workspace_path(workspace_root, meta_path.parent().unwrap());

        // Iterate over mapping. _scope is special; everything else is a child entry.
        let map = match parsed.as_mapping() {
            Some(m) => m,
            None => {
                stats
                    .errors
                    .push(format!("not a mapping {}", meta_path.display()));
                continue;
            }
        };
        for (k, v) in map.iter() {
            let key = match k.as_str() {
                Some(s) => s,
                None => {
                    stats
                        .errors
                        .push(format!("non-string key in {}", meta_path.display()));
                    continue;
                }
            };
            let entry_name = if key == "_scope" { "_scope" } else { key };
            // Round-1 adversarial W6 fix: reject control chars in YAML keys
            // (would otherwise forge PK collisions via U+001F injection).
            if !id_component_safe(entry_name) {
                stats.errors.push(format!(
                    "{}: entry_name {:?} contains C0 control chars; skipping",
                    meta_path.display(),
                    entry_name
                ));
                continue;
            }
            if !id_component_safe(&directory) {
                stats.errors.push(format!(
                    "{}: directory {:?} contains C0 control chars; skipping",
                    meta_path.display(),
                    directory
                ));
                continue;
            }
            let (description, tags) = if key == "_scope" {
                let scope: MetaScopeEntry = serde_yml::from_value(v.clone()).unwrap_or_default();
                (scope.description, scope.tags)
            } else {
                let child: MetaChildEntry = serde_yml::from_value(v.clone()).unwrap_or_default();
                (child.description, child.tags)
            };
            let id = make_id(&[&terr.agent_id, &directory, entry_name]);
            let tags_json = serde_json::to_string(&tags).unwrap_or_else(|_| "[]".to_string());
            let embedding =
                embed_or_skip(embedder, &description, expected_dim, &mut stats.embed_calls).await?;

            // INSERT meta_index + (optionally) meta_vec.
            let h = handle.clone();
            let id_for_blocking = id.clone();
            let agent_id_for_blocking = terr.agent_id.clone();
            let directory_for_blocking = directory.clone();
            let entry_for_blocking = entry_name.to_string();
            let desc_for_blocking = description.clone();
            let tags_for_blocking = tags_json.clone();
            let now_for_blocking = now_text();
            let result: Result<bool, DbError> =
                tokio::task::spawn_blocking(move || -> Result<bool, DbError> {
                    let mut conn = h.get_conn()?;
                    let tx = conn.transaction()?;
                    let insert = tx.execute(
                        "INSERT INTO meta_index(id, agent_id, directory, entry_name, description, \
                         tags, embedding, updated_at) VALUES (?1,?2,?3,?4,?5,?6,NULL,?7)",
                        params![
                            id_for_blocking,
                            agent_id_for_blocking,
                            directory_for_blocking,
                            entry_for_blocking,
                            if desc_for_blocking.is_empty() {
                                None
                            } else {
                                Some(desc_for_blocking)
                            },
                            tags_for_blocking,
                            now_for_blocking,
                        ],
                    );
                    match insert {
                        Ok(_) => {}
                        Err(e) if is_pk_collision(&e) => {
                            // collision — caller pushes errors entry; do nothing here.
                            return Ok(false);
                        }
                        Err(e) => return Err(DbError::from(e)),
                    }
                    if let Some(blob) = embedding {
                        let rowid = tx.last_insert_rowid();
                        tx.execute(
                            "INSERT INTO meta_vec(rowid, embedding) VALUES (?1, ?2)",
                            params![rowid, blob],
                        )?;
                    }
                    tx.commit()?;
                    Ok(true)
                })
                .await
                .map_err(|e| DbError::Internal(format!("spawn_blocking: {e}")))?;
            match result {
                Ok(true) => stats.rows_inserted += 1,
                Ok(false) => stats.errors.push(format!(
                    "meta_index id collision: {id} already indexed; skipping"
                )),
                Err(e) => return Err(e),
            }
        }
    }
    Ok(stats)
}

fn collect_meta_files(_workspace_root: &Path, agent_root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for entry in WalkDir::new(agent_root)
        .follow_links(false)
        .sort_by_file_name()
        .into_iter()
        .filter_entry(|e| !is_hidden_dir(e.file_name()))
    {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        if entry.file_type().is_file() && entry.file_name() == ".meta.yaml" {
            out.push(entry.path().to_path_buf());
        }
    }
    out
}

// ──────────────────────────────────────────────────────────────────────
// Scanner (b): scan_content_files
// ──────────────────────────────────────────────────────────────────────

/// Walk `terr.agent_root` and emit content_index/content_fts/content_vec
/// rows for every non-hidden file. The walk descends through child
/// directories that are themselves agent territories (e.g., when
/// scanning the root agent's territory, we also descend into
/// `<root>/research/notes.md`). This is INTENTIONAL: the content row
/// is written under THIS territory's `agent_id` (e.g., the root
/// agent's `"/"`), and the child agent's own `scan_content_files`
/// call indexes the same file under its own agent_id (e.g.,
/// `"research"`). Both rows have unique `id` values
/// (`agent_id\u{1F}file_path`) so neither collides; queries that
/// filter on `agent_id` see only the matching rows. The duplication
/// is the cross-territory content visibility model documented in
/// MODULE-004 §3.6 and pinned by T-rebuild-02b for the analogous
/// meta_index case. (Round-1 audit DiffW3 fix: pin the rationale.)
async fn scan_content_files<H, E>(
    handle: &H,
    embedder: &E,
    workspace_root: &Path,
    terr: &AgentTerritory,
    expected_dim: usize,
) -> Result<ScannerStats, DbError>
where
    H: SqliteIndexHandle + Clone + 'static,
    E: Embedder + Clone + 'static,
{
    let mut stats = ScannerStats::default();
    let mut files = Vec::new();
    for entry in WalkDir::new(&terr.agent_root)
        .follow_links(false)
        .sort_by_file_name()
        .into_iter()
        .filter_entry(|e| !is_hidden_dir(e.file_name()))
    {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        if !entry.file_type().is_file() {
            continue;
        }
        if entry.file_name() == ".meta.yaml" {
            continue; // scanner (a)'s domain
        }
        files.push(entry.path().to_path_buf());
    }

    for path in files {
        let body = match read_capped(&path) {
            Ok(s) => s,
            Err(e) => {
                stats
                    .errors
                    .push(format!("read content {}: {e}", path.display()));
                continue;
            }
        };
        let preview: String = body.chars().take(PREVIEW_MAX_CHARS).collect();
        let file_path = normalize_workspace_path(workspace_root, &path);
        if !id_component_safe(&file_path) {
            stats.errors.push(format!(
                "content file path {:?} contains C0 control chars; skipping",
                file_path
            ));
            continue;
        }
        let id = make_id(&[&terr.agent_id, &file_path]);
        let last_modified = std::fs::metadata(&path)
            .and_then(|m| m.modified())
            .ok()
            .map(|t| {
                let dt: DateTime<Utc> = t.into();
                dt.to_rfc3339_opts(SecondsFormat::Millis, true)
            });
        let embedding =
            embed_or_skip(embedder, &preview, expected_dim, &mut stats.embed_calls).await?;

        let h = handle.clone();
        let id_b = id.clone();
        let agent_b = terr.agent_id.clone();
        let path_b = file_path.clone();
        let preview_b = preview.clone();
        let lm_b = last_modified.clone();
        let now_b = now_text();
        let result: Result<bool, DbError> =
            tokio::task::spawn_blocking(move || -> Result<bool, DbError> {
                let mut conn = h.get_conn()?;
                let tx = conn.transaction()?;
                let insert = tx.execute(
                    "INSERT INTO content_index(id, agent_id, file_path, content_preview, \
                     embedding, access_count, last_accessed, last_modified, updated_at) \
                     VALUES (?1,?2,?3,?4,NULL,0,NULL,?5,?6)",
                    params![
                        id_b,
                        agent_b,
                        path_b,
                        if preview_b.is_empty() {
                            None
                        } else {
                            Some(&preview_b)
                        },
                        lm_b,
                        now_b,
                    ],
                );
                match insert {
                    Ok(_) => {}
                    Err(e) if is_pk_collision(&e) => return Ok(false),
                    Err(e) => return Err(DbError::from(e)),
                }
                let rowid = tx.last_insert_rowid();
                // content_fts ALWAYS written (so FTS5 can match by file path tokens).
                tx.execute(
                    "INSERT INTO content_fts(rowid, file_path, content_preview, tags) \
                     VALUES (?1,?2,?3,?4)",
                    params![rowid, path_b, preview_b, ""],
                )?;
                if let Some(blob) = embedding {
                    tx.execute(
                        "INSERT INTO content_vec(rowid, embedding) VALUES (?1,?2)",
                        params![rowid, blob],
                    )?;
                }
                tx.commit()?;
                Ok(true)
            })
            .await
            .map_err(|e| DbError::Internal(format!("spawn_blocking: {e}")))?;
        match result {
            Ok(true) => stats.rows_inserted += 1,
            Ok(false) => stats.errors.push(format!(
                "content_index id collision: {id} already indexed; skipping"
            )),
            Err(e) => return Err(e),
        }
    }
    Ok(stats)
}

// ──────────────────────────────────────────────────────────────────────
// Scanner (c): scan_knowledge_jsonl
// ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Default, Deserialize)]
struct KnowledgeEntry {
    #[serde(default)]
    id: String,
    #[serde(default)]
    agent_id: String,
    #[serde(default, rename = "type")]
    type_: String,
    #[serde(default)]
    content: String,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    created_at: String,
    #[serde(default)]
    task_origin: Option<String>,
    #[serde(default = "default_true")]
    is_active: bool,
    #[serde(default)]
    superseded_by: Option<String>,
    #[serde(default = "default_active_status")]
    status: String,
    #[serde(default)]
    supersession_reason: Option<String>,
    #[allow(dead_code)] // intentionally dropped — schema has no cluster_id column
    #[serde(default)]
    cluster_id: Option<String>,
    #[serde(default)]
    sources: Vec<serde_json::Value>,
}

fn default_true() -> bool {
    true
}

fn default_active_status() -> String {
    "active".to_string()
}

fn validate_status_invariant(is_active: bool, status: &str) -> Result<(), String> {
    let active_set = ["active", "contested", "orphaned"];
    let inactive_set = ["superseded", "forgotten"];
    let in_active = active_set.contains(&status);
    let in_inactive = inactive_set.contains(&status);
    if is_active && !in_active {
        return Err(format!(
            "status invariant: is_active=true requires status ∈ {{active,contested,orphaned}}, got {status}"
        ));
    }
    if !is_active && !in_inactive {
        return Err(format!(
            "status invariant: is_active=false requires status ∈ {{superseded,forgotten}}, got {status}"
        ));
    }
    Ok(())
}

async fn scan_knowledge_jsonl<H, E>(
    handle: &H,
    embedder: &E,
    terr: &AgentTerritory,
    expected_dim: usize,
) -> Result<ScannerStats, DbError>
where
    H: SqliteIndexHandle + Clone + 'static,
    E: Embedder + Clone + 'static,
{
    let mut stats = ScannerStats::default();
    let path = terr
        .agent_root
        .join(".agent")
        .join("memory")
        .join("knowledge.jsonl");
    if !path.is_file() {
        return Ok(stats);
    }
    let body = match read_capped(&path) {
        Ok(s) => s,
        Err(e) => {
            stats.errors.push(format!("read {}: {e}", path.display()));
            return Ok(stats);
        }
    };
    for (line_no, line) in body.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        // Round-1 adversarial W7 fix: cap individual JSONL line length
        // to block stack-overflow / memory-explosion via deeply-nested
        // JSON payloads in a single line.
        if trimmed.len() > MAX_JSONL_LINE_BYTES {
            stats.errors.push(format!(
                "knowledge.jsonl at {} line {}: line too large ({} bytes; cap {MAX_JSONL_LINE_BYTES} bytes)",
                path.display(),
                line_no + 1,
                trimmed.len()
            ));
            continue;
        }
        let entry: KnowledgeEntry = match serde_json::from_str(trimmed) {
            Ok(e) => e,
            Err(e) => {
                stats.errors.push(format!(
                    "knowledge.jsonl at {} line {}: parse error: {e}",
                    path.display(),
                    line_no + 1
                ));
                continue;
            }
        };
        // Required-field validation
        if entry.id.is_empty() {
            stats.errors.push(format!(
                "knowledge.jsonl at {} line {}: empty id",
                path.display(),
                line_no + 1
            ));
            continue;
        }
        if !id_component_safe(&entry.id) {
            stats.errors.push(format!(
                "knowledge.jsonl at {} line {}: id {:?} contains C0 control chars; skipping",
                path.display(),
                line_no + 1,
                entry.id
            ));
            continue;
        }
        if entry.content.is_empty() {
            stats.errors.push(format!(
                "knowledge.jsonl at {} line {}: empty content",
                path.display(),
                line_no + 1
            ));
            continue;
        }
        if entry.created_at.is_empty() {
            stats.errors.push(format!(
                "knowledge.jsonl at {} line {}: empty created_at",
                path.display(),
                line_no + 1
            ));
            continue;
        }
        if entry.type_.is_empty() {
            stats.errors.push(format!(
                "knowledge.jsonl at {} line {}: empty type",
                path.display(),
                line_no + 1
            ));
            continue;
        }
        // Cross-territory verification
        if !entry.agent_id.is_empty() && entry.agent_id != terr.agent_id {
            stats.errors.push(format!(
                "knowledge.jsonl at {} line {}: agent_id mismatch (entry says {:?}, territory is {:?}); skipping",
                path.display(),
                line_no + 1,
                entry.agent_id,
                terr.agent_id,
            ));
            continue;
        }
        // Status invariant
        if let Err(msg) = validate_status_invariant(entry.is_active, &entry.status) {
            stats.errors.push(format!(
                "knowledge.jsonl at {} line {}: id={} {msg}",
                path.display(),
                line_no + 1,
                entry.id
            ));
            continue;
        }
        let tags_json = serde_json::to_string(&entry.tags).unwrap_or_else(|_| "[]".to_string());
        let sources_json =
            serde_json::to_string(&entry.sources).unwrap_or_else(|_| "[]".to_string());
        let embedding = embed_or_skip(
            embedder,
            &entry.content,
            expected_dim,
            &mut stats.embed_calls,
        )
        .await?;

        let h = handle.clone();
        let id_b = entry.id.clone();
        let agent_b = terr.agent_id.clone();
        let result: Result<bool, DbError> =
            tokio::task::spawn_blocking(move || -> Result<bool, DbError> {
                let mut conn = h.get_conn()?;
                let tx = conn.transaction()?;
                let insert = tx.execute(
                    "INSERT INTO memory_index(id, agent_id, type, content, tags, embedding, \
                     created_at, task_origin, superseded_by, is_active, status, \
                     supersession_reason, sources, access_count, last_accessed) \
                     VALUES (?1,?2,?3,?4,?5,NULL,?6,?7,?8,?9,?10,?11,?12,0,NULL)",
                    params![
                        id_b,
                        agent_b,
                        entry.type_,
                        entry.content,
                        tags_json,
                        entry.created_at,
                        entry.task_origin,
                        entry.superseded_by,
                        entry.is_active,
                        entry.status,
                        entry.supersession_reason,
                        sources_json,
                    ],
                );
                match insert {
                    Ok(_) => {}
                    Err(e) if is_pk_collision(&e) => return Ok(false),
                    Err(e) => return Err(DbError::from(e)),
                }
                if let Some(blob) = embedding {
                    let rowid = tx.last_insert_rowid();
                    tx.execute(
                        "INSERT INTO memory_vec(rowid, embedding) VALUES (?1,?2)",
                        params![rowid, blob],
                    )?;
                }
                tx.commit()?;
                Ok(true)
            })
            .await
            .map_err(|e| DbError::Internal(format!("spawn_blocking: {e}")))?;
        match result {
            Ok(true) => stats.rows_inserted += 1,
            Ok(false) => stats.errors.push(format!(
                "memory_index id collision: {} already indexed by another agent's territory; losing agent_id={:?}; skipping",
                entry.id, terr.agent_id
            )),
            Err(e) => return Err(e),
        }
    }
    Ok(stats)
}

// ──────────────────────────────────────────────────────────────────────
// Scanner (d): scan_summary_yaml
// ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Default, Deserialize)]
struct SummaryYaml {
    #[serde(default, rename = "_meta")]
    meta: SummaryMeta,
    #[serde(default)]
    brief: String,
}

#[derive(Debug, Default, Deserialize)]
struct SummaryMeta {
    #[serde(default)]
    task_id: String,
    #[serde(default)]
    agent_id: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    last_turn_at: Option<String>,
    #[serde(default)]
    turns_total: Option<i64>,
}

async fn scan_summary_yaml<H, E>(
    handle: &H,
    embedder: &E,
    terr: &AgentTerritory,
    expected_dim: usize,
) -> Result<ScannerStats, DbError>
where
    H: SqliteIndexHandle + Clone + 'static,
    E: Embedder + Clone + 'static,
{
    let mut stats = ScannerStats::default();
    for (sub, status) in [("active", "active"), ("archived", "archived")] {
        let base = terr.agent_root.join(".agent").join("tasks").join(sub);
        if !base.is_dir() {
            continue;
        }
        let mut task_dirs: Vec<PathBuf> = match std::fs::read_dir(&base) {
            Ok(r) => {
                let mut acc = Vec::new();
                for e in r {
                    match e {
                        Ok(de) => {
                            // Round-3 W2 fix: surface per-entry errors
                            // instead of silently dropping (filter_map
                            // with .ok() loses the audit trail).
                            match de.file_type() {
                                Ok(t) if t.is_dir() => acc.push(de.path()),
                                Ok(_) => {} // not a dir; skip silently
                                Err(err) => stats.errors.push(format!(
                                    "{}: read entry file_type: {err}",
                                    base.display()
                                )),
                            }
                        }
                        Err(err) => stats
                            .errors
                            .push(format!("{}: read_dir entry: {err}", base.display())),
                    }
                }
                acc
            }
            Err(e) => {
                stats.errors.push(format!("read {}: {e}", base.display()));
                continue;
            }
        };
        task_dirs.sort();
        for task_dir in task_dirs {
            let summary_path = task_dir.join("summary.yaml");
            if !summary_path.is_file() {
                continue;
            }
            let task_id = match task_dir.file_name() {
                Some(n) => n.to_string_lossy().to_string(),
                None => continue,
            };
            // Round-1 adversarial W6 fix: reject control chars in task_id.
            if !id_component_safe(&task_id) {
                stats.errors.push(format!(
                    "summary.yaml at {}: task_id contains C0 control chars; skipping",
                    summary_path.display()
                ));
                continue;
            }
            let body = match read_capped_yaml(&summary_path) {
                Ok(s) => s,
                Err(e) => {
                    stats
                        .errors
                        .push(format!("read {}: {e}", summary_path.display()));
                    continue;
                }
            };
            let parsed: SummaryYaml = match serde_yml::from_str(&body) {
                Ok(s) => s,
                Err(e) => {
                    stats
                        .errors
                        .push(format!("parse {}: {e}", summary_path.display()));
                    continue;
                }
            };
            // Cross-territory verification
            if !parsed.meta.agent_id.is_empty() && parsed.meta.agent_id != terr.agent_id {
                stats.errors.push(format!(
                    "summary.yaml at {}: agent_id mismatch (says {:?}, territory is {:?}); skipping",
                    summary_path.display(),
                    parsed.meta.agent_id,
                    terr.agent_id
                ));
                continue;
            }
            // Required-field validation
            if parsed.meta.title.is_empty() {
                stats.errors.push(format!(
                    "summary.yaml at {}: empty/missing _meta.title; skipping",
                    summary_path.display()
                ));
                continue;
            }
            // task_id mismatch (use directory as authoritative)
            if !parsed.meta.task_id.is_empty() && parsed.meta.task_id != task_id {
                stats.errors.push(format!(
                    "summary.yaml at {}: _meta.task_id ({}) does not match directory ({})",
                    summary_path.display(),
                    parsed.meta.task_id,
                    task_id
                ));
                // continue with directory name as authoritative
            }
            let embedding = embed_or_skip(
                embedder,
                &parsed.brief,
                expected_dim,
                &mut stats.embed_calls,
            )
            .await?;
            let h = handle.clone();
            let task_id_b = task_id.clone();
            let agent_b = terr.agent_id.clone();
            let title_b = parsed.meta.title.clone();
            let brief_b = parsed.brief.clone();
            let lta_b = parsed.meta.last_turn_at.clone();
            let tt_b = parsed.meta.turns_total;
            let status_b = status.to_string();
            let now_b = now_text();
            let result: Result<bool, DbError> =
                tokio::task::spawn_blocking(move || -> Result<bool, DbError> {
                    let mut conn = h.get_conn()?;
                    let tx = conn.transaction()?;
                    let insert = tx.execute(
                        "INSERT INTO task_index(task_id, agent_id, title, brief, status, embedding, \
                         last_turn_at, turns_total, updated_at) VALUES (?1,?2,?3,?4,?5,NULL,?6,?7,?8)",
                        params![
                            task_id_b,
                            agent_b,
                            title_b,
                            if brief_b.is_empty() { None } else { Some(brief_b) },
                            status_b,
                            lta_b,
                            tt_b,
                            now_b,
                        ],
                    );
                    match insert {
                        Ok(_) => {}
                        Err(e) if is_pk_collision(&e) => return Ok(false),
                        Err(e) => return Err(DbError::from(e)),
                    }
                    if let Some(blob) = embedding {
                        let rowid = tx.last_insert_rowid();
                        tx.execute(
                            "INSERT INTO task_vec(rowid, embedding) VALUES (?1,?2)",
                            params![rowid, blob],
                        )?;
                    }
                    tx.commit()?;
                    Ok(true)
                })
                .await
                .map_err(|e| DbError::Internal(format!("spawn_blocking: {e}")))?;
            match result {
                Ok(true) => stats.rows_inserted += 1,
                Ok(false) => stats.errors.push(format!(
                    "task_id collision: {task_id} already indexed by another agent's territory; losing agent_id={:?}; skipping",
                    terr.agent_id
                )),
                Err(e) => return Err(e),
            }
        }
    }
    Ok(stats)
}

// ──────────────────────────────────────────────────────────────────────
// Scanner (e): scan_turn_index_yaml
// ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Default, Deserialize)]
struct TurnIndexYaml {
    #[serde(default)]
    turns: Vec<TurnEntry>,
}

#[derive(Debug, Default, Deserialize)]
struct TurnEntry {
    #[serde(default)]
    turn: i64,
    #[serde(default)]
    timestamp: String,
    #[serde(default)]
    agent_id: String,
    #[serde(default)]
    digest: String,
    #[serde(default)]
    importance: Option<String>,
    #[serde(default)]
    reference_count: Option<i64>,
    #[serde(default)]
    has_user_instruction: Option<bool>,
    #[serde(default)]
    has_user_correction: Option<bool>,
    #[serde(default)]
    has_tool_use: Option<bool>,
    #[serde(default)]
    has_decision: Option<bool>,
    #[serde(default)]
    tokens_digest: Option<i64>,
    #[serde(default)]
    tokens_l0_processed: Option<i64>,
    #[serde(default)]
    collapsed_view: String,
}

async fn scan_turn_index_yaml<H, E>(
    handle: &H,
    embedder: &E,
    terr: &AgentTerritory,
    expected_dim: usize,
) -> Result<ScannerStats, DbError>
where
    H: SqliteIndexHandle + Clone + 'static,
    E: Embedder + Clone + 'static,
{
    let mut stats = ScannerStats::default();
    for sub in ["active", "archived"] {
        let base = terr.agent_root.join(".agent").join("tasks").join(sub);
        if !base.is_dir() {
            continue;
        }
        let mut task_dirs: Vec<PathBuf> = match std::fs::read_dir(&base) {
            Ok(r) => {
                let mut acc = Vec::new();
                for e in r {
                    match e {
                        Ok(de) => match de.file_type() {
                            Ok(t) if t.is_dir() => acc.push(de.path()),
                            Ok(_) => {}
                            Err(err) => stats
                                .errors
                                .push(format!("{}: read entry file_type: {err}", base.display())),
                        },
                        Err(err) => stats
                            .errors
                            .push(format!("{}: read_dir entry: {err}", base.display())),
                    }
                }
                acc
            }
            Err(e) => {
                stats.errors.push(format!("read {}: {e}", base.display()));
                continue;
            }
        };
        task_dirs.sort();
        for task_dir in task_dirs {
            let yaml_path = task_dir.join("turn-index.yaml");
            if !yaml_path.is_file() {
                continue;
            }
            let task_id = match task_dir.file_name() {
                Some(n) => n.to_string_lossy().to_string(),
                None => continue,
            };
            if !id_component_safe(&task_id) {
                stats.errors.push(format!(
                    "turn-index.yaml at {}: task_id contains C0 control chars; skipping",
                    yaml_path.display()
                ));
                continue;
            }
            let body = match read_capped_yaml(&yaml_path) {
                Ok(s) => s,
                Err(e) => {
                    stats
                        .errors
                        .push(format!("read {}: {e}", yaml_path.display()));
                    continue;
                }
            };
            let parsed: TurnIndexYaml = match serde_yml::from_str(&body) {
                Ok(s) => s,
                Err(e) => {
                    stats
                        .errors
                        .push(format!("parse {}: {e}", yaml_path.display()));
                    continue;
                }
            };
            for entry in &parsed.turns {
                if !entry.agent_id.is_empty() && entry.agent_id != terr.agent_id {
                    stats.errors.push(format!(
                        "turn-index.yaml at {} turn {}: agent_id mismatch (entry={:?}, territory={:?}); skipping",
                        yaml_path.display(),
                        entry.turn,
                        entry.agent_id,
                        terr.agent_id
                    ));
                    continue;
                }
                if entry.turn == 0 {
                    stats.errors.push(format!(
                        "turn-index.yaml at {}: missing/zero turn; skipping",
                        yaml_path.display()
                    ));
                    continue;
                }
                if entry.timestamp.is_empty() {
                    stats.errors.push(format!(
                        "turn-index.yaml at {} turn {}: empty timestamp; skipping",
                        yaml_path.display(),
                        entry.turn
                    ));
                    continue;
                }
                if entry.digest.is_empty() {
                    stats.errors.push(format!(
                        "turn-index.yaml at {} turn {}: empty digest; skipping",
                        yaml_path.display(),
                        entry.turn
                    ));
                    continue;
                }
                // Slice H (2026-05-24): 3-component agent-prefixed id format
                // `"{agent_id}\u{1F}{task_id}\u{1F}turn-{N}"` (was 2-component
                // `"{task_id}\u{1F}turn-{N}"`). Matches the new incremental
                // write surface (`handle.rs::upsert_turn_index` +
                // `bump_turn_reference`) AND the cap-memory `SqliteIndex`
                // `(agent_id, task_id, turn)` seam key. Cross-agent turn
                // collisions on PK become structurally impossible.
                let id = format!(
                    "{}{}{}{}turn-{}",
                    terr.agent_id,
                    unit_separator(),
                    task_id,
                    unit_separator(),
                    entry.turn
                );
                let embed_source = if entry.collapsed_view.is_empty() {
                    entry.digest.clone()
                } else {
                    format!("{} {}", entry.digest, entry.collapsed_view)
                };
                let embedding = embed_or_skip(
                    embedder,
                    &embed_source,
                    expected_dim,
                    &mut stats.embed_calls,
                )
                .await?;
                let h = handle.clone();
                let id_b = id.clone();
                let agent_b = terr.agent_id.clone();
                let task_b = task_id.clone();
                let turn_b = entry.turn;
                let ts_b = entry.timestamp.clone();
                let dig_b = entry.digest.clone();
                let imp_b = entry.importance.clone();
                let rc_b = entry.reference_count.unwrap_or(0);
                let hui_b = entry.has_user_instruction.unwrap_or(false);
                let huc_b = entry.has_user_correction.unwrap_or(false);
                let htu_b = entry.has_tool_use.unwrap_or(false);
                let hd_b = entry.has_decision.unwrap_or(false);
                let td_b = entry.tokens_digest;
                let tlp_b = entry.tokens_l0_processed;
                let result: Result<bool, DbError> =
                    tokio::task::spawn_blocking(move || -> Result<bool, DbError> {
                        let mut conn = h.get_conn()?;
                        let tx = conn.transaction()?;
                        let insert = tx.execute(
                            "INSERT INTO turn_index(id, agent_id, task_id, turn, timestamp, digest, \
                             importance, reference_count, has_user_instruction, has_user_correction, \
                             has_tool_use, has_decision, embedding, tokens_digest, tokens_l0_processed, \
                             access_count, last_accessed) \
                             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,NULL,?13,?14,0,NULL)",
                            params![
                                id_b, agent_b, task_b, turn_b, ts_b, dig_b, imp_b,
                                rc_b, hui_b, huc_b, htu_b, hd_b, td_b, tlp_b,
                            ],
                        );
                        match insert {
                            Ok(_) => {}
                            Err(e) if is_pk_collision(&e) => return Ok(false),
                            Err(e) => return Err(DbError::from(e)),
                        }
                        if let Some(blob) = embedding {
                            let rowid = tx.last_insert_rowid();
                            tx.execute(
                                "INSERT INTO turn_vec(rowid, embedding) VALUES (?1,?2)",
                                params![rowid, blob],
                            )?;
                        }
                        tx.commit()?;
                        Ok(true)
                    })
                    .await
                    .map_err(|e| DbError::Internal(format!("spawn_blocking: {e}")))?;
                match result {
                    Ok(true) => stats.rows_inserted += 1,
                    Ok(false) => stats.errors.push(format!(
                        "turn_index id collision: {id} already indexed by another agent's territory; losing agent_id={:?}; skipping",
                        terr.agent_id
                    )),
                    Err(e) => return Err(e),
                }
            }
        }
    }
    Ok(stats)
}

// Connection import to satisfy unused-warning if Connection somehow needed.
#[allow(dead_code)]
fn _connection_import(_: &Connection) {}

//! Bridges cap-fs to MODULE-004 CONTRACT-030 `SqliteIndexHandle`.
//!
//! The [`SqliteSync`] trait abstracts the surface so tests can mock without
//! spinning up a real SQLite handle; production wiring uses
//! [`Db030SqliteSync`] which wraps `Arc<dyn advance_database::SqliteIndexHandle>`
//! and dispatches each method to `spawn_blocking` so the async cap-fs hot path
//! does not block its tokio worker on rusqlite.
//!
//! ## Design notes (MODULE-002 §1.4.4)
//!
//! - **Per-leg atomicity**: each `upsert_*` / `delete_*` runs inside a single
//!   `TransactionBehavior::Immediate` transaction at the M004 layer
//!   (`crates/database/src/handle.rs:120-211`). The cap-fs caller chains two
//!   such methods (content + meta) per fs.write/fs.delete; failure of either
//!   surfaces as `runtime.degraded.sqlite_sync_failed` and triggers next-boot
//!   reconciliation recovery (CONTRACT-033 `IndexRebuild::rebuild_full`).
//! - **agent_id encoding parity**: [`agent_id_for_m004`] mirrors M004's
//!   `derive_agent_id` (rebuild.rs:386-413) so incremental hot-path rows and
//!   bulk-rebuild rows share the same `agent_id` keyspace.
//! - **Text-vs-binary policy**: [`is_text_for_sql_index`] mirrors M004's
//!   `read_to_string` text-only filter (rebuild.rs:863). Non-UTF-8 data
//!   skips `content_index` upsert (rebuild would erase it on next reboot
//!   otherwise); `meta_index` is written unconditionally for all writes.

use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;

/// Transparent error surface returned by the [`SqliteSync`] trait. The cap-fs
/// FsWriteHandler / FsDeleteHandler callers wrap this in a
/// `runtime.degraded.sqlite_sync_failed` event payload; fs.write/fs.delete
/// itself returns Ok() because the FS source-of-truth is committed before the
/// SQL leg runs.
#[derive(Debug, Clone)]
pub struct FsSyncError(pub String);

impl std::fmt::Display for FsSyncError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "sqlite sync error: {}", self.0)
    }
}

impl std::error::Error for FsSyncError {}

/// Slice C bridge to MODULE-004 CONTRACT-030 incremental write surface.
///
/// All four methods are async (the production impl dispatches to
/// `spawn_blocking`). Failures return [`FsSyncError`] which the caller logs
/// via `runtime.degraded.sqlite_sync_failed` events; reconciliation
/// (CONTRACT-033) is the recovery mechanism.
#[async_trait]
pub trait SqliteSync: Send + Sync {
    async fn upsert_content(
        &self,
        agent_id: &str,
        file_path: &str,
        preview: &str,
        last_modified: Option<&str>,
    ) -> Result<(), FsSyncError>;

    async fn upsert_meta(
        &self,
        agent_id: &str,
        directory: &str,
        entry_name: &str,
        description: Option<&str>,
        tags_json: Option<&str>,
    ) -> Result<(), FsSyncError>;

    async fn delete_content(&self, agent_id: &str, file_path: &str) -> Result<(), FsSyncError>;

    async fn delete_meta(
        &self,
        agent_id: &str,
        directory: &str,
        entry_name: &str,
    ) -> Result<(), FsSyncError>;
}

/// Production [`SqliteSync`] adapter wrapping `Arc<dyn SqliteIndexHandle>`.
/// Each method dispatches to `tokio::task::spawn_blocking` so the rusqlite
/// transaction runs on the blocking pool, not the async worker.
#[derive(Clone)]
pub struct Db030SqliteSync {
    handle: Arc<dyn advance_database::SqliteIndexHandle>,
}

impl Db030SqliteSync {
    pub fn new(handle: Arc<dyn advance_database::SqliteIndexHandle>) -> Self {
        Self { handle }
    }
}

#[async_trait]
impl SqliteSync for Db030SqliteSync {
    async fn upsert_content(
        &self,
        agent_id: &str,
        file_path: &str,
        preview: &str,
        last_modified: Option<&str>,
    ) -> Result<(), FsSyncError> {
        let handle = Arc::clone(&self.handle);
        let agent_id = agent_id.to_string();
        let file_path = file_path.to_string();
        let preview = preview.to_string();
        let last_modified = last_modified.map(|s| s.to_string());
        tokio::task::spawn_blocking(move || {
            handle.upsert_content_index(
                &agent_id,
                &file_path,
                &preview,
                None,
                last_modified.as_deref(),
            )
        })
        .await
        .map_err(|e| FsSyncError(format!("spawn_blocking: {e}")))?
        .map_err(|e| FsSyncError(format!("{e}")))
    }

    async fn upsert_meta(
        &self,
        agent_id: &str,
        directory: &str,
        entry_name: &str,
        description: Option<&str>,
        tags_json: Option<&str>,
    ) -> Result<(), FsSyncError> {
        let handle = Arc::clone(&self.handle);
        let agent_id = agent_id.to_string();
        let directory = directory.to_string();
        let entry_name = entry_name.to_string();
        let description = description.map(|s| s.to_string());
        let tags_json = tags_json.map(|s| s.to_string());
        tokio::task::spawn_blocking(move || {
            handle.upsert_meta_index(
                &agent_id,
                &directory,
                &entry_name,
                description.as_deref(),
                tags_json.as_deref(),
                None,
            )
        })
        .await
        .map_err(|e| FsSyncError(format!("spawn_blocking: {e}")))?
        .map_err(|e| FsSyncError(format!("{e}")))
    }

    async fn delete_content(&self, agent_id: &str, file_path: &str) -> Result<(), FsSyncError> {
        let handle = Arc::clone(&self.handle);
        let agent_id = agent_id.to_string();
        let file_path = file_path.to_string();
        tokio::task::spawn_blocking(move || handle.delete_content_index_row(&agent_id, &file_path))
            .await
            .map_err(|e| FsSyncError(format!("spawn_blocking: {e}")))?
            .map_err(|e| FsSyncError(format!("{e}")))
    }

    async fn delete_meta(
        &self,
        agent_id: &str,
        directory: &str,
        entry_name: &str,
    ) -> Result<(), FsSyncError> {
        let handle = Arc::clone(&self.handle);
        let agent_id = agent_id.to_string();
        let directory = directory.to_string();
        let entry_name = entry_name.to_string();
        tokio::task::spawn_blocking(move || {
            handle.delete_meta_index_row(&agent_id, &directory, &entry_name)
        })
        .await
        .map_err(|e| FsSyncError(format!("spawn_blocking: {e}")))?
        .map_err(|e| FsSyncError(format!("{e}")))
    }
}

/// Map a cap-fs `HostCallContext.agent_id` (runtime-bound logical id) to the
/// M004 row-id encoding ("/" for root, "<rel>" for sub-agents). Closely
/// parallels M004 `crates/database/src/rebuild.rs::derive_agent_id`
/// (lines 386-413) — same `Component::Normal`-only acceptance rule + same
/// "/"-joined output.
///
/// **Known asymmetry (acknowledged in plan §Risk register, deferred to a
/// future hardening slice)**: M004's `derive_agent_id` additionally calls
/// `id_component_safe(&part)` to reject C0 control characters in directory
/// names; this implementation does NOT. A workspace whose agent dir name
/// embeds `\u{1F}` (or other C0) would be accepted here but rejected at
/// next M004 `rebuild_full`, producing orphan rows that the rebuild then
/// erases. Slice C's pin: this is bounded by the workspace-creation surface
/// (M005 spawn-child), not arbitrary guest input, so the divergence is a
/// hardening gap rather than a security boundary.
///
/// Encoding rules:
/// - `agent_workspace == workspace_root` → `Some("/".to_string())`.
/// - else → `Some(strip_prefix(workspace_root) → join Component::Normal with "/")`.
/// - Returns `None` when `agent_workspace` is not under `workspace_root` OR when
///   the relative path contains non-Normal components (`..`, `.`, drive prefix,
///   `RootDir`). Caller treats `None` as a configuration error and emits
///   `runtime.degraded.sqlite_sync_failed`.
pub fn agent_id_for_m004(workspace_root: &Path, agent_workspace: &Path) -> Option<String> {
    if agent_workspace == workspace_root {
        return Some("/".to_string());
    }
    let rel = agent_workspace.strip_prefix(workspace_root).ok()?;
    let mut parts: Vec<String> = Vec::new();
    for comp in rel.components() {
        match comp {
            Component::Normal(s) => {
                let part = s.to_string_lossy().to_string();
                parts.push(part);
            }
            // Reject `..`, `.`, drive prefixes, root-dir markers — they would
            // yield a misleading agent_id (matches M004 derive_agent_id).
            _ => return None,
        }
    }
    if parts.is_empty() {
        return None;
    }
    Some(parts.join("/"))
}

/// UTF-8 predicate. Mirrors M004's `read_to_string` text-only filter
/// (`crates/database/src/rebuild.rs:863-872`). Non-UTF-8 files are skipped
/// by M004 rebuild scanner; if cap-fs incrementally upserted them, the next
/// rebuild would erase the row.
pub fn is_text_for_sql_index(data: &[u8]) -> bool {
    std::str::from_utf8(data).is_ok()
}

/// Maximum chars (NOT bytes) of UTF-8 preview text written to
/// `content_index.content_preview`. Matches M004's `PREVIEW_MAX_CHARS = 2000`
/// (`crates/database/src/rebuild.rs:46`).
pub const MAX_SQL_PREVIEW_CHARS: usize = 2000;

/// Workspace-relative path encoding. Mirrors M004's
/// `crates/database/src/rebuild.rs::normalize_workspace_path`.
///
/// - Returns `""` for `abs_path == workspace_root`.
/// - Returns `"/research/notes.md"` for nested files (forward slashes only,
///   no trailing slash, leading `/`).
/// - Components other than `Component::Normal` are dropped (matches M004).
pub fn normalize_ws_path(workspace_root: &Path, abs_path: &Path) -> String {
    let rel = abs_path.strip_prefix(workspace_root).unwrap_or(abs_path);
    let mut out = String::new();
    for comp in rel.components() {
        if let Component::Normal(s) = comp {
            out.push('/');
            out.push_str(&s.to_string_lossy());
        }
    }
    out
}

/// Construct a [`PathBuf`] from a workspace-relative path string (`/foo/bar`).
/// Inverse of [`normalize_ws_path`] for cases where reconciler-style code
/// needs to round-trip through the encoded form. (Currently unused — kept as
/// a placeholder for future direct-DB query helpers.)
#[allow(dead_code)]
pub(crate) fn ws_path_to_buf(workspace_root: &Path, ws_path: &str) -> PathBuf {
    let trimmed = ws_path.trim_start_matches('/');
    if trimmed.is_empty() {
        workspace_root.to_path_buf()
    } else {
        workspace_root.join(trimmed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_id_for_m004_root() {
        let root = Path::new("/ws");
        assert_eq!(agent_id_for_m004(root, root), Some("/".to_string()));
    }

    #[test]
    fn agent_id_for_m004_first_level() {
        let root = Path::new("/ws");
        let agent = Path::new("/ws/research");
        assert_eq!(agent_id_for_m004(root, agent), Some("research".to_string()));
    }

    #[test]
    fn agent_id_for_m004_deeper() {
        let root = Path::new("/ws");
        let agent = Path::new("/ws/research/competitor-analysis");
        assert_eq!(
            agent_id_for_m004(root, agent),
            Some("research/competitor-analysis".to_string())
        );
    }

    #[test]
    fn agent_id_for_m004_outside_workspace() {
        let root = Path::new("/ws");
        let outside = Path::new("/other/research");
        assert_eq!(agent_id_for_m004(root, outside), None);
    }

    #[test]
    fn is_text_for_sql_index_utf8() {
        assert!(is_text_for_sql_index(b"hello"));
        assert!(is_text_for_sql_index("中文".as_bytes()));
        assert!(is_text_for_sql_index(b""));
    }

    #[test]
    fn is_text_for_sql_index_binary() {
        // 0xFF is invalid as a leading UTF-8 byte
        assert!(!is_text_for_sql_index(&[0xFF, 0xD8, 0xFF, 0xE0]));
    }

    #[test]
    fn normalize_ws_path_root_is_empty() {
        let root = Path::new("/ws");
        assert_eq!(normalize_ws_path(root, root), "");
    }

    #[test]
    fn normalize_ws_path_nested_file() {
        let root = Path::new("/ws");
        let abs = Path::new("/ws/research/notes.md");
        assert_eq!(normalize_ws_path(root, abs), "/research/notes.md");
    }

    #[test]
    fn normalize_ws_path_outside_workspace_falls_back_to_abs() {
        // strip_prefix fails → use abs_path verbatim. Each Component::Normal
        // contributes a leading "/" segment.
        let root = Path::new("/ws");
        let abs = Path::new("/other/research/notes.md");
        assert_eq!(normalize_ws_path(root, abs), "/other/research/notes.md");
    }

    #[test]
    fn ws_path_to_buf_root() {
        let root = Path::new("/ws");
        assert_eq!(ws_path_to_buf(root, ""), PathBuf::from("/ws"));
    }

    #[test]
    fn ws_path_to_buf_nested() {
        let root = Path::new("/ws");
        assert_eq!(
            ws_path_to_buf(root, "/research/notes.md"),
            PathBuf::from("/ws/research/notes.md")
        );
    }
}

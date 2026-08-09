//! AC-18 `rollback-memory` SPEC contract — Git-tracked path-set declaration.
//!
//! MODULE-011 §1.4 AC-18 wording (line 373):
//! > `rollback-memory` Git-tracked path set includes `knowledge.jsonl` +
//! > `_knowledge_map.yaml` + `syntheses/*.md`; `_knowledge_cursor.yaml` is
//! > non-Git-tracked and reset to initial state (epoch/0/0) rather than
//! > checked out from history.
//!
//! Slice G (m011-slice-g) closes the **cap-memory half** of AC-18:
//!
//! 1. **Path-set SPEC contract** (this module): [`ROLLBACK_GIT_PATHS`] declares
//!    the 3 Git-tracked path patterns that the deferred MODULE-003 git-checkout
//!    slice will consume to restore on-disk state from history.
//! 2. **Cursor-reset companion** ([`crate::l6::L6CursorStore::reset_to_epoch`]):
//!    materializes literal `L6Cursor { last_knowledge_id: None,
//!    last_completed_at: SystemTime::UNIX_EPOCH }` per AC-18 wording
//!    ("epoch/0/0"). The cursor is non-Git-tracked (§2.5), so its reset is
//!    cap-memory-internal — not subject to git-checkout.
//!
//! The cap-memory side does NOT execute git-checkout against these patterns.
//! That lives in MODULE-003 CONTRACT-021 `WorkspaceRollback` — SHIPPED
//! 2026-06-12 (`DefaultWorkspaceRollback::rollback_memory_files_at`,
//! dispatched through the [`MemoryGitRestore`] seam below) with the
//! adjudicated 2-path consumer set: `knowledge.jsonl` is git-TRACKED but
//! store-restored (see the const + seam rustdoc for the division).
//!
//! Slice B's in-process drop-by-`created_at` lives in
//! [`crate::store::MemoryStore::rollback`] (still functional under the
//! `rollback-memory` WIT entry-point; slice G adds the cursor-reset side
//! effect alongside it via [`crate::wit_impl::RollbackMemoryHandler`]).
//! Slice C's `rollback_l6` (journal-based cluster_id rollback) is a separate
//! orthogonal mechanism for L6 mutations and unaffected by slice G.

/// The canonical Git-tracked path set for `rollback-memory`, per AC-18 §1.4
/// (line 373 of `docs/modules/MODULE-011-memory-system.md`).
///
/// **Adjudicated division (2026-06-12 rollback-memory slice; F16 doc
/// reconciliation 2026-06-13)**: this const declares which memory files are
/// GIT-TRACKED (the AC-18 wording), NOT which files the git-restore consumer
/// checks out. The shipped consumer
/// (`DefaultWorkspaceRollback::rollback_memory_files_at`, dispatched via the
/// [`MemoryGitRestore`] seam below) restores ONLY `_knowledge_map.yaml` +
/// `syntheses/*.md`; `knowledge.jsonl` — though git-tracked — is restored
/// IN-PROCESS by [`crate::store::MemoryStore::rollback`] (drop +
/// self-persist), the split-brain-avoiding division the seam rustdoc
/// explains. (The git crate has no cap-memory edge, so the consumer cannot
/// literally import this const; it is the SPEC declaration, the code-level
/// path set lives with the consumer.) The patterns are matched against the
/// agent's `.agent/memory/` directory:
///
/// - `knowledge.jsonl` — exact filename: the source-of-truth knowledge store
/// - `_knowledge_map.yaml` — exact filename: L6-compiled index for Tier 1b ⑨
///   injection
/// - `syntheses/*.md` — glob: all L6-compiled synthesis markdown files
///
/// `_knowledge_cursor.yaml` is NOT in this list because it is non-Git-tracked
/// (per §2.5 and §6.4 rule 6); the AC-18 cursor-reset half is handled
/// separately by [`crate::l6::L6CursorStore::reset_to_epoch`].
pub const ROLLBACK_GIT_PATHS: &[&str; 3] =
    &["knowledge.jsonl", "_knowledge_map.yaml", "syntheses/*.md"];

/// rollback-memory slice (2026-06-12) — the dependency-inverted git-restore
/// seam the MODULE-011 §3.6 "path-set-CONSUMER half" prescribed: cap-memory
/// stays free of any `advance-git` compile-time edge; the composition root
/// injects an adapter that dispatches into MODULE-003 CONTRACT-021
/// (`DefaultWorkspaceRollback::rollback_memory_files_at`).
///
/// **Division of labor (the adjudicated split-brain-avoiding ordering)**:
/// `knowledge.jsonl` is NOT restored through this seam — the
/// [`crate::store::MemoryStore`] owns that file's rollback IN-PROCESS
/// (`MemoryStore::rollback` drops post-timestamp entries and persists the
/// post-rollback set itself, keeping its in-memory buckets and the on-disk
/// file trivially consistent). This seam restores only the files NO runtime
/// component holds in memory — `_knowledge_map.yaml` + `syntheses/*.md` —
/// so a git checkout can never diverge from a live cache, and the store's
/// next persist cannot clobber a just-restored file.
///
/// `restore_at` resolves `timestamp_rfc3339` (the WIT `rollback-memory`
/// param, already shape-validated at the host-fn boundary) to the latest
/// commit at-or-before that wall-clock time and restores the memory files
/// as of that commit. Returns the restored workspace-relative paths
/// (possibly empty — no commit at/before the timestamp, or no memory files
/// in it, are both no-ops, not errors). Errors are stringified at this
/// boundary (no git error types cross into cap-memory).
pub trait MemoryGitRestore: Send + Sync {
    fn restore_at(
        &self,
        agent_id: String,
        timestamp_rfc3339: String,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Vec<String>, String>> + Send + 'static>,
    >;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// AC-18 SPEC contract guard: the path-set value must match
    /// MODULE-011 §1.4 line 373 verbatim.
    ///
    /// If this assertion ever needs to change, the AC-18 §1.4 wording must
    /// be amended first (via `/spec`) — slice-G's `/dev` partition rule does
    /// not own AC criterion text.
    #[test]
    fn path_set_const() {
        assert_eq!(ROLLBACK_GIT_PATHS.len(), 3);
        assert_eq!(
            ROLLBACK_GIT_PATHS,
            &["knowledge.jsonl", "_knowledge_map.yaml", "syntheses/*.md"]
        );
    }
}

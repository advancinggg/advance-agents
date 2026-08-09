//! Bridges cap-fs to MODULE-003 CONTRACT-020 `GitCommitQueue`.
//!
//! Slice D additive — mirrors slice C's `SqliteSync` / `Db030SqliteSync` pattern.
//!
//! [`GitSync`] is a thin abstraction over the CONTRACT-020 surface so cap-fs's
//! [`crate::FsWriteHandler`] / [`crate::FsDeleteHandler`] can submit per-fs-write/
//! fs-delete attribution commits without pulling git2/libgit2 into the test
//! compile graph; [`Adv003GitSync`] is the production adapter wrapping
//! `Arc<dyn advance_git::GitCommitQueue>`. Tests inject a mock implementing
//! [`GitSync`] (see `crates/capabilities/cap-fs/tests/common/mod.rs`'s
//! `MockGitSync`) without bringing libgit2 into scope.
//!
//! ## Design notes (MODULE-002 §1.4.4)
//!
//! - **Per-write commit semantics**: each fs.write/fs.delete produces ONE
//!   `CommitRequest` capturing the data-file path + the parent's `.meta.yaml`
//!   so a single commit covers both legs of the meta-first commit pattern.
//!   Caller is expected to submit AFTER the FS+meta legs commit to disk.
//! - **Await-not-spawn invariant**: callers `await` [`GitSync::submit_fs_commit`]
//!   inline within the handler's async body — NEVER spawn to a detached task.
//!   This guarantees fs.write/fs.delete returns `Ok(())` only after the git
//!   leg has succeeded or surfaced a `runtime.degraded.git_sync_failed` event.
//! - **Best-effort fail-soft**: git failure does NOT block the fs path. The
//!   handler maps `GitSyncError` to a `runtime.degraded.git_sync_failed`
//!   emission and still returns `Ok(())` from fs.write/fs.delete because the
//!   FS source-of-truth is committed before the git leg runs.
//! - **Fold-in invariant**: pure metadata mutations from `update-scope` /
//!   `update-entry-meta` (which do NOT independently submit commits in slice D
//!   per task scope) ride along into the next fs.write/fs.delete commit's
//!   `.meta.yaml` snapshot. See MODULE-002 §3.6 / §3.8 for the gap discussion
//!   and SD-T49 for the verification test.
//! - **Trust boundary delegation**: `agent_id` and `initiator` audit-trail
//!   sanitization (bracket / `<` / `>` / newline / control char → `_`) happens
//!   at the advance-git boundary via `commit_queue.rs::sanitize_audit_field`.
//!   cap-fs adds NO extra sanitization. Path-traversal / symlink-escape
//!   defense lives at advance-git's `normalize_workdir_rel`. See MODULE-002
//!   §1.7.1 clause 5.

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;

/// Transparent error newtype returned by [`GitSync::submit_fs_commit`]. The
/// cap-fs handler wraps the inner string in a
/// `runtime.degraded.git_sync_failed` payload's `error` field. fs.write /
/// fs.delete itself returns `Ok(())` because the FS source-of-truth is
/// committed before the git leg runs.
#[derive(Debug, Clone)]
pub struct GitSyncError(pub String);

impl std::fmt::Display for GitSyncError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "git sync error: {}", self.0)
    }
}

impl std::error::Error for GitSyncError {}

/// Operation kind passed into [`GitSync::submit_fs_commit`]. Influences the
/// commit-message verb (`write` vs `delete`) but otherwise routes through the
/// same CONTRACT-020 `CommitRequest` shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitSyncOp {
    Write,
    Delete,
}

impl GitSyncOp {
    fn message_verb(self) -> &'static str {
        match self {
            GitSyncOp::Write => "write",
            GitSyncOp::Delete => "delete",
        }
    }
}

/// Slice D bridge to MODULE-003 CONTRACT-020 `GitCommitQueue`.
///
/// The single method [`GitSync::submit_fs_commit`] packages a fs.write /
/// fs.delete operation into a `CommitRequest` (commit_type: Turn, initiator:
/// `"agent:<id>"`, message: `"<op> <vpath>"`, affected_paths: `[physical_path,
/// meta_yaml_path]`), submits it to the underlying queue, awaits the oneshot
/// result, and maps:
/// - `Ok(Ok(_oid))` → `Ok(())`
/// - `Ok(Err(e))` → `Err(GitSyncError(format!("{e:?}")))`
/// - `Err(_canceled)` → `Err(GitSyncError("commit queue worker closed (oneshot canceled)"))`
///
/// Implementors must be `Send + Sync` (callers store as `Arc<dyn GitSync>`).
#[async_trait]
pub trait GitSync: Send + Sync {
    async fn submit_fs_commit(
        &self,
        agent_id: &str,
        op: GitSyncOp,
        vpath: &str,
        physical_path: PathBuf,
        meta_yaml_path: PathBuf,
    ) -> Result<(), GitSyncError>;
}

/// Production [`GitSync`] adapter wrapping
/// `Arc<dyn advance_git::GitCommitQueue>`.
///
/// `submit_fs_commit` constructs a `CommitRequest::new(...)` (with
/// `commit_type: Turn`, `initiator: "agent:<id>"`, `message: "<op> <vpath>"`,
/// `affected_paths: [physical, meta_yaml]`), submits to the queue, awaits the
/// oneshot result, and maps to [`GitSyncError`] on failure.
#[derive(Clone)]
pub struct Adv003GitSync {
    queue: Arc<dyn advance_git::GitCommitQueue>,
}

impl Adv003GitSync {
    pub fn new(queue: Arc<dyn advance_git::GitCommitQueue>) -> Self {
        Self { queue }
    }
}

#[async_trait]
impl GitSync for Adv003GitSync {
    async fn submit_fs_commit(
        &self,
        agent_id: &str,
        op: GitSyncOp,
        vpath: &str,
        physical_path: PathBuf,
        meta_yaml_path: PathBuf,
    ) -> Result<(), GitSyncError> {
        let req = advance_git::CommitRequest::new(
            agent_id,
            format!("{} {}", op.message_verb(), vpath),
            vec![physical_path, meta_yaml_path],
            advance_git::CommitType::Turn,
            format!("agent:{agent_id}"),
        );
        let rx = self.queue.submit(req);
        match rx.await {
            Ok(Ok(_oid)) => Ok(()),
            Ok(Err(e)) => Err(GitSyncError(format!("{e:?}"))),
            Err(_) => Err(GitSyncError(
                "commit queue worker closed (oneshot canceled)".into(),
            )),
        }
    }
}

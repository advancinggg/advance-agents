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
use tokio::sync::oneshot;

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

/// A commit that has already been submitted to the queue (R-c / R10).
///
/// [`GitSync::enqueue_fs_commit`] returns this while still holding L1; the
/// caller drops the meta lock and then [`PendingFsCommit::wait`]s.
pub struct PendingFsCommit {
    inner: PendingInner,
}

enum PendingInner {
    Ready(Result<Option<String>, GitSyncError>),
    Rx(oneshot::Receiver<Result<git2::Oid, advance_git::GitError>>),
}

impl PendingFsCommit {
    /// Already finished (the default lazy wrapper).
    pub fn ready(result: Result<(), GitSyncError>) -> Self {
        Self::ready_commit(result.map(|()| None))
    }

    /// Already finished, carrying the commit id when the backend reported one.
    pub fn ready_commit(result: Result<Option<String>, GitSyncError>) -> Self {
        Self {
            inner: PendingInner::Ready(result),
        }
    }

    /// A oneshot from `GitCommitQueue::submit`.
    pub fn from_rx(rx: oneshot::Receiver<Result<git2::Oid, advance_git::GitError>>) -> Self {
        Self {
            inner: PendingInner::Rx(rx),
        }
    }

    /// Await the worker. Safe to call after L1 is released.
    pub async fn wait(self) -> Result<(), GitSyncError> {
        self.wait_commit().await.map(|_| ())
    }

    /// Await the worker and return the commit id when the backend reported one.
    pub async fn wait_commit(self) -> Result<Option<String>, GitSyncError> {
        match self.inner {
            PendingInner::Ready(r) => r,
            PendingInner::Rx(rx) => match rx.await {
                Ok(Ok(oid)) => Ok(Some(format!("{oid}"))),
                Ok(Err(e)) => Err(GitSyncError(format!("{e:?}"))),
                Err(_) => Err(GitSyncError(
                    "commit queue worker closed (oneshot canceled)".into(),
                )),
            },
        }
    }
}

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

    /// Entity-data lane E1: the same commit with a caller-supplied message (the `data`
    /// transaction records `Advance-Data-Op: <op>` as a trailer) over any number of paths,
    /// returning the commit id when the backend reports one. Default: forwards to
    /// [`submit_fs_commit`](Self::submit_fs_commit) for the first two paths and reports no id.
    async fn submit_commit_with_message(
        &self,
        agent_id: &str,
        op: GitSyncOp,
        vpath: &str,
        paths: Vec<PathBuf>,
        message: &str,
    ) -> Result<Option<String>, GitSyncError> {
        let _ = message;
        let mut it = paths.into_iter();
        let (Some(a), Some(b)) = (it.next(), it.next()) else {
            return Ok(None);
        };
        self.submit_fs_commit(agent_id, op, vpath, a, b).await?;
        Ok(None)
    }

    /// R-c / R10: submit the commit **now** (while the caller still holds L1)
    /// and return a waiter. The default is the existing lazy wrapper — it
    /// calls [`submit_fs_commit`] immediately — so `MockGitSync` and Along's
    /// `RepoGitSync` compile unchanged.
    async fn enqueue_fs_commit(
        &self,
        agent_id: &str,
        op: GitSyncOp,
        vpath: &str,
        physical_path: PathBuf,
        meta_yaml_path: PathBuf,
    ) -> Result<PendingFsCommit, GitSyncError> {
        Ok(PendingFsCommit::ready(
            self.submit_fs_commit(agent_id, op, vpath, physical_path, meta_yaml_path)
                .await,
        ))
    }

    /// R-c: submit a caller-supplied message **now** (while the caller still
    /// holds L1) and return a waiter. The default awaits
    /// [`submit_commit_with_message`](Self::submit_commit_with_message).
    async fn enqueue_commit_with_message(
        &self,
        agent_id: &str,
        op: GitSyncOp,
        vpath: &str,
        paths: Vec<PathBuf>,
        message: &str,
    ) -> Result<PendingFsCommit, GitSyncError> {
        Ok(PendingFsCommit::ready_commit(
            self.submit_commit_with_message(agent_id, op, vpath, paths, message)
                .await,
        ))
    }
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
        self.enqueue_fs_commit(agent_id, op, vpath, physical_path, meta_yaml_path)
            .await?
            .wait()
            .await
    }

    async fn enqueue_fs_commit(
        &self,
        agent_id: &str,
        op: GitSyncOp,
        vpath: &str,
        physical_path: PathBuf,
        meta_yaml_path: PathBuf,
    ) -> Result<PendingFsCommit, GitSyncError> {
        let req = advance_git::CommitRequest::new(
            agent_id,
            format!("{} {}", op.message_verb(), vpath),
            vec![physical_path, meta_yaml_path],
            advance_git::CommitType::Turn,
            format!("agent:{agent_id}"),
        );
        Ok(PendingFsCommit::from_rx(self.queue.submit(req)))
    }

    async fn enqueue_commit_with_message(
        &self,
        agent_id: &str,
        _op: GitSyncOp,
        _vpath: &str,
        paths: Vec<PathBuf>,
        message: &str,
    ) -> Result<PendingFsCommit, GitSyncError> {
        let req = advance_git::CommitRequest::new(
            agent_id,
            message.to_string(),
            paths,
            advance_git::CommitType::Turn,
            format!("agent:{agent_id}"),
        );
        Ok(PendingFsCommit::from_rx(self.queue.submit(req)))
    }

    async fn submit_commit_with_message(
        &self,
        agent_id: &str,
        op: GitSyncOp,
        vpath: &str,
        paths: Vec<PathBuf>,
        message: &str,
    ) -> Result<Option<String>, GitSyncError> {
        self.enqueue_commit_with_message(agent_id, op, vpath, paths, message)
            .await?
            .wait_commit()
            .await
    }
}

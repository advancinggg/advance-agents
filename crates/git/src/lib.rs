//! `advance-git` — MODULE-003 git-version.
//!
//! Slice A provides:
//! - [`repo::bootstrap_repo_at`] — single-branch (`main`) Git repository bootstrap +
//!   `.gitignore` installation covering SQLite artifacts and large binaries. Does NOT
//!   return a `git2::Repository` handle; the raw type is a `pub(crate)` implementation
//!   detail so cross-module Git access stays on the CONTRACT-020/021/022 surface
//!   (MODULE-003 §1.1: "No other module imports `git2` directly").
//! - [`commit_queue::GitCommitQueue`] (CONTRACT-020) — serialized commit submission
//!   with typed `commit_type` (`turn` / `micro` / `l6` / `user`) and free-form
//!   `initiator` metadata in the commit message prefix. The trait return type is
//!   `oneshot::Receiver<Result<Oid, GitError>>`, matching MODULE-003 §1.4.1 / §2.3
//!   byte-for-byte. `user` belongs to the user commit lane (ADR 2026-10-15,
//!   CONTRACT-247); `submit` refuses it.
//! - [`commit_queue::DefaultGitCommitQueue`] — the concrete impl used by MODULE-002
//!   and other consumers.
//!
//! The user commit lane (ADR 2026-10-15, CONTRACT-247) adds:
//! - [`user_lane`] — the lane's request/outcome types, [`user_lane::UserActor`], the
//!   signature builders and the [`user_lane::UserCommitLane`] trait;
//! - [`paths::RepoPath`] — user-addressable paths on the shared-types `workspace_path`
//!   grammar;
//! - [`label`] — the deterministic subject + `Advance-*` trailer renderer, its parser and
//!   the label golden;
//! - [`blob::BlobHasher`] — streaming git blob ids without a repository;
//! - [`repo::ensure_lane_policy`] — the repository-wide filter-free policy;
//! - crate-private `tree_edit` (exact trees from the parent tree plus resolved edits),
//!   `safe_fs` (fd-relative, symlink-proof, non-blocking disk reads) and `journal` (the
//!   crash journal healed before every item);
//! - the worker side: [`commit_queue::DefaultGitCommitQueue`] implements
//!   [`user_lane::UserCommitLane`] (`prepare`, `commit_user`, `save_version`, `restore_tree`)
//!   on the same worker, FIFO and coord mutex as CONTRACT-020, through the crate-private
//!   `lane` (commit landing, index and journal discipline), `lane_commit`, `lane_prepare`,
//!   `lane_version` and `lane_restore` modules.
//!
//! # Security posture (module-level)
//!
//! 1. **No subprocess** — every Git operation goes through libgit2 via the `git2`
//!    crate. Subprocess invocation of `git` binaries is never permitted and would
//!    bypass the `commit_type` / `initiator` audit trail.
//! 2. **Single branch** — `main` only. [`repo::bootstrap_repo_at`] enforces this at
//!    init time **and** rejects pre-existing repositories whose HEAD is not
//!    `refs/heads/main` **or** that have any co-existing non-main local branch
//!    (PRD §7.2 "no per-agent branches", MODULE-003 §1.1).
//! 3. **Libgit2 vendored pin** — workspace `Cargo.toml` pins `git2 = "=0.20.4"` with
//!    `vendored-libgit2` and without `ssh` / `https`, removing network-transport
//!    attack surface and system-libgit2 drift.
//! 4. **Audit-trail metadata is not caller-spoofable** — both the
//!    `[<commit_type>] [<initiator>]` commit-message prefix AND the git
//!    Signature author name (`agent:<agent_id>`) are sanitized before
//!    interpolation. Any structural metacharacter (`[`, `]`, `<`, `>`, `"`,
//!    newline, carriage return, control character) in `initiator` or
//!    `agent_id` is replaced with `_`, so callers cannot escape the bracket
//!    boundary, inject an inner bracket pair, or forge the author identity.
//!    The `[commit_type]` shape is further enforced by the typed enum
//!    formatter. The free-form `message` body remains caller-controlled but
//!    cannot spoof the prefix because it lives after the second `] `.
//! 5. **No raw `git2::Repository` crosses the crate boundary** — the module boundary
//!    in MODULE-003 §1.1 requires every external Git access to go through
//!    CONTRACT-020/021/022. Returning a `Repository` would let callers bypass that
//!    boundary. All `pub` surfaces hide the handle.
//! 6. **Path traversal defense** — [`commit_queue::CommitRequest`]'s
//!    `affected_paths` are normalized via canonicalize-then-strip_prefix
//!    checks. Rejected: absolute paths outside workdir, paths containing
//!    `..` (ParentDir), and relative paths whose canonical joined form
//!    resolves (via any symlinked component) outside canonical workdir.
//!    Closes the confused-deputy gap where a symlinked directory component
//!    could route a committed write outside the workspace.
//!
//! # Threading model
//!
//! Commits are serialized through a single worker task spawned on the Tokio
//! blocking-pool (`tokio::task::spawn_blocking`). The worker owns the `git2::Repository`
//! handle (re-opened inside the blocking thread, because git2's Repository is `!Sync`)
//! and consumes queue items (CONTRACT-020 `CommitRequest`s and user-lane requests, in one
//! FIFO) off a `tokio::sync::mpsc::UnboundedReceiver` via `blocking_recv`. Before every item
//! it heals the user lane's crash journal. The worker thread lifetime is tied to the
//! `DefaultGitCommitQueue` value; dropping the queue closes the channel and the worker
//! exits after draining remaining requests. Runs under any Tokio runtime — the
//! blocking pool is available without `rt-multi-thread`.

#![forbid(unsafe_code)]

pub(crate) mod autoignore;
pub mod blob;
pub mod checkpoint;
pub mod commit_queue;
pub mod config;
pub(crate) mod coord;
pub(crate) mod emit;
pub mod error;
pub mod gc;
pub mod git_log;
pub mod history;
pub(crate) mod journal;
pub mod label;
pub(crate) mod lane;
pub(crate) mod lane_commit;
pub(crate) mod lane_prepare;
pub(crate) mod lane_restore;
pub(crate) mod lane_version;
pub mod paths;
pub mod repo;
pub mod rollback;
pub(crate) mod safe_fs;
pub(crate) mod tree_edit;
pub mod user_lane;

pub use blob::{blob_oid_of_bytes, blob_oid_of_file, BlobHasher, BlobLengthMismatch};
pub use checkpoint::{CheckpointEntry, DefaultNamedCheckpoint, NamedCheckpoint};
#[cfg(feature = "test-support")]
pub use commit_queue::{AdoptBudget, LaneTestHooks};
pub use commit_queue::{CommitRequest, CommitType, DefaultGitCommitQueue, GitCommitQueue};
pub use config::{GitConfigProvider, GitConfigSnapshot, StaticGitConfigProvider};
pub use error::{CheckpointError, DeniedReason, GitError, RollbackError, UserOpRefusal};
pub use gc::GcTask;
pub use git_log::{GitLog, GitLogLevel};
pub use history::{
    checkpoints_by_sha, clamp_limit, validate_workspace_path, CheckpointList, CheckpointRecord,
    CommitEntry, CommitFilter, CommitPage, FileAtVersion, FileHistory, FileVersion,
    GitFileHistoryProvider, GitHistoryReader, HistoryError, RepoSummary, DEFAULT_PAGE_LIMIT,
    MAX_BLOB_BYTES, MAX_PAGE_LIMIT,
};
pub use label::CommitLabel;
pub use paths::RepoPath;
pub use repo::{
    bootstrap_repo_at, ensure_lane_policy, ensure_workspace_repo, repo_status, GitRepoStatus,
    LanePolicy, Precompose, LANE_ATTRIBUTES,
};
pub use rollback::{
    DefaultWorkspaceRollback, RestorePlanSummary, RollbackMode, RollbackTarget, WorkspaceRollback,
};
pub use user_lane::{
    AdoptPolicy, BlobSource, ChangeRole, EntryKind, IndexStat, ItemChange, ItemKind, ItemOutcome,
    NotVersioned, PathChange, PathState, PrepareOutcome, PrepareRequest, PrepareTarget, Provenance,
    RestoreOutcome, RestoreScope, RestoreSource, RestoreTreeRequest, SaveVersionOutcome,
    SaveVersionRequest, TreeState, UserActor, UserCommitLane, UserCommitOutcome, UserCommitRequest,
    UserCommitStatus, UserOpKind, ADOPT_INITIATOR, ADOPT_TIME_BUDGET, FILES_CHANGED_EVENT,
    MAX_ADOPT_BYTES, MAX_EVENT_ROWS, MAX_RESTORE_PATHS, MAX_TREE_ADOPT_ENTRIES, MAX_USER_BYTES,
    MAX_USER_CHANGES, RUNTIME_EMAIL, RUNTIME_NAME, USER_EMAIL, USER_NAMESPACE,
};

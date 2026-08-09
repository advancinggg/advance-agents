//! `advance-git` — MODULE-003 git-version.
//!
//! Slice A provides:
//! - [`repo::bootstrap_repo_at`] — single-branch (`main`) Git repository bootstrap +
//!   `.gitignore` installation covering SQLite artifacts and large binaries. Does NOT
//!   return a `git2::Repository` handle; the raw type is a `pub(crate)` implementation
//!   detail so cross-module Git access stays on the CONTRACT-020/021/022 surface
//!   (MODULE-003 §1.1: "No other module imports `git2` directly").
//! - [`commit_queue::GitCommitQueue`] (CONTRACT-020) — serialized commit submission
//!   with typed `commit_type` (`turn` / `micro` / `l6`) and free-form `initiator`
//!   metadata in the commit message prefix. The trait return type is
//!   `oneshot::Receiver<Result<Oid, GitError>>`, matching MODULE-003 §1.4.1 / §2.3
//!   byte-for-byte.
//! - [`commit_queue::DefaultGitCommitQueue`] — the concrete impl used by MODULE-002
//!   and other consumers.
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
//! and consumes `CommitRequest` values off a `tokio::sync::mpsc::UnboundedReceiver`
//! via `blocking_recv`. The worker thread lifetime is tied to the
//! `DefaultGitCommitQueue` value; dropping the queue closes the channel and the worker
//! exits after draining remaining requests. Runs under any Tokio runtime — the
//! blocking pool is available without `rt-multi-thread`.

#![forbid(unsafe_code)]

pub mod blob;
pub mod checkpoint;
pub mod commit_queue;
pub mod config;
pub(crate) mod coord;
pub mod error;
pub mod gc;
pub mod repo;
pub mod rollback;

pub use blob::blob_oid_of_file;
pub use checkpoint::{CheckpointEntry, DefaultNamedCheckpoint, NamedCheckpoint};
pub use commit_queue::{CommitRequest, CommitType, DefaultGitCommitQueue, GitCommitQueue};
pub use config::{GitConfigProvider, GitConfigSnapshot, StaticGitConfigProvider};
pub use error::{CheckpointError, DeniedReason, GitError, RollbackError};
pub use gc::GcTask;
pub use repo::bootstrap_repo_at;
pub use rollback::{DefaultWorkspaceRollback, RollbackMode, RollbackTarget, WorkspaceRollback};

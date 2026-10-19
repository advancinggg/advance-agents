//! The user commit lane's API (ADR 2026-10-15, CONTRACT-247, MODULE-003 §1.4.1 / §2.3).
//!
//! The lane is a second, typed entry point on the **same** worker, FIFO and coord mutex
//! as CONTRACT-020, so ordering against agent commits comes for free. Every
//! request carries a [`UserActor`]; the worker renders the subject and the `Advance-*`
//! trailer block from the typed op ([`crate::label`]) and builds the tree from the parent
//! tree plus exactly the request's resolved edits (the crate-private `tree_edit` module),
//! never from `index.write_tree()`.
//!
//! This module declares the types, the constants and the [`UserCommitLane`] trait;
//! [`crate::commit_queue::DefaultGitCommitQueue`] implements it on its worker (`prepare`,
//! `commit_user`, `save_version` and `restore_tree` through the crate-private `lane_prepare`,
//! `lane_commit`, `lane_version` and `lane_restore` modules). Nothing here talks to a
//! repository except the three signature builders ([`agent_authorship`], [`user_authorship`],
//! [`runtime_authorship`]).
//!
//! # Signatures (MODULE-003 §1.4.1 item 5, AC-26)
//!
//! | Lane | Author | Committer | Prefix |
//! |---|---|---|---|
//! | agent (legacy, unchanged) | `agent:<id> <runtime@advance-agents>` | same | `[turn\|micro\|l6] [<initiator>]` |
//! | user | `user:<handle> <user@advance-agents>` | `runtime <runtime@advance-agents>` | `[user] [user:<handle>]` |
//! | runtime bookkeeping (adopt) | `runtime <runtime@advance-agents>` | same | `[micro] [runtime:adopt]` |
//!
//! In git's convention the author wrote the change and the committer applied it; neither
//! identity is a real email address.
//!
//! Code here can run while the coord mutex is held, so it is panic-free:
//! a panic there poisons coord and stops every later commit.

#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::arithmetic_side_effects
)]

use std::time::{Duration, SystemTime};

use advance_shared_types::FileIdentity;
use git2::Signature;
use tokio::sync::oneshot;

use crate::commit_queue::{sanitize_audit_field, CommitRequest, CommitType};
use crate::error::GitError;
use crate::label::CommitLabel;
use crate::paths::RepoPath;

/// The checkpoint namespace of named user versions and the initiator kind of user
/// commits (`user:<handle>`). Reserved for the operator (MODULE-003 §1.4.3).
pub const USER_NAMESPACE: &str = "user";
/// Author email of user-lane commits.
pub const USER_EMAIL: &str = "user@advance-agents";
/// Committer name of user-lane commits and author/committer of runtime bookkeeping.
pub const RUNTIME_NAME: &str = "runtime";
/// The runtime's email; the agent lane signs with it too.
pub const RUNTIME_EMAIL: &str = "runtime@advance-agents";
/// Initiator of the `[micro]` commit that records uncommitted disk state before a user op.
pub const ADOPT_INITIATOR: &str = "runtime:adopt";
/// The handle a principal id normalizes to when nothing of it is usable.
pub const DEFAULT_HANDLE: &str = "operator";
/// Longest handle, in bytes (the handle grammar is ASCII).
pub const MAX_HANDLE_BYTES: usize = 64;

/// `PathChange` entries per `commit_user` request.
pub const MAX_USER_CHANGES: usize = 10_000;
/// Total `BlobSource::Bytes` per request (== history `MAX_BLOB_BYTES`).
pub const MAX_USER_BYTES: usize = 64 * 1024 * 1024;
/// `files.changed` rows per commit; the `total` leaf carries the full count.
pub const MAX_EVENT_ROWS: usize = 16;
/// Status entries examined per `PrepareTarget::Tree` (past it: `adopt_incomplete`).
pub const MAX_TREE_ADOPT_ENTRIES: usize = 10_000;
/// `restore_tree` plan bound (== rollback `MAX_FULL_DIRECTORY_PATHS`).
pub const MAX_RESTORE_PATHS: usize = 100_000;
/// Bytes one `prepare` or `save_version` item adopts at most (R1); the sum comes from
/// `fstat` before any hashing.
pub const MAX_ADOPT_BYTES: u64 = 256 * 1024 * 1024;
/// Time one `prepare` or `save_version` item spends adopting at most (R1).
pub const ADOPT_TIME_BUDGET: Duration = Duration::from_secs(5);
/// The event type of the per-path change rows the worker emits after a commit. Equals
/// `event_bus::taxonomy::files::CHANGED` (advance-git cannot depend on event-bus).
pub const FILES_CHANGED_EVENT: &str = "files.changed";

/// Which declared client and which session made a user-lane change (MODULE-003 §1.7). Recorded as
/// the `Advance-Client` / `Advance-Session` trailers, kept out of the subject and out of
/// the structured label.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Provenance {
    /// The platform token the client declared at login (`macos`, `ios`, …).
    pub client: String,
    /// A one-way digest of the session id (16 hex).
    pub session: String,
}

/// The operator principal a user-lane request acts for. The id comes from the Client API
/// session, never from a request body.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct UserActor {
    handle: String,
}

impl UserActor {
    /// Normalize a Client API principal id into a handle `[A-Za-z0-9._-]{1,64}`: every
    /// other character becomes `-`, runs of `-` collapse, `-` and `.` are trimmed from both
    /// ends, the result is cut to 64 bytes (and trimmed again), and an empty result is
    /// `operator`.
    pub fn from_principal_id(principal_id: &str) -> Self {
        let mut mapped = String::with_capacity(principal_id.len().min(256));
        for c in principal_id.chars() {
            let c = if is_handle_char(c) { c } else { '-' };
            if c == '-' && mapped.ends_with('-') {
                continue;
            }
            mapped.push(c);
        }
        let trimmed = mapped.trim_matches(|c| c == '-' || c == '.');
        let cut: String = trimmed.chars().take(MAX_HANDLE_BYTES).collect();
        let handle = cut.trim_matches(|c| c == '-' || c == '.');
        let handle = if is_valid_handle(handle) {
            handle.to_string()
        } else {
            DEFAULT_HANDLE.to_string()
        };
        Self { handle }
    }

    /// The normalized handle.
    pub fn handle(&self) -> &str {
        &self.handle
    }

    /// `user:<handle>`: the commit prefix's initiator, the author name and the
    /// `git.commit` / `files.changed` `Event.agent_id`. The handle grammar has no `:`, so
    /// the result passes the projection's agent-id grammar `[A-Za-z0-9_.:-]{1,256}`.
    pub fn initiator(&self) -> String {
        format!("{USER_NAMESPACE}:{}", self.handle)
    }
}

fn is_handle_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-'
}

/// `true` for a handle in the grammar `[A-Za-z0-9._-]{1,64}`.
pub(crate) fn is_valid_handle(handle: &str) -> bool {
    !handle.is_empty() && handle.len() <= MAX_HANDLE_BYTES && handle.chars().all(is_handle_char)
}

/// The signatures, prefix fields and event id of one commit.
pub(crate) struct Authorship {
    pub(crate) author: Signature<'static>,
    pub(crate) committer: Signature<'static>,
    pub(crate) commit_type: CommitType,
    /// Already safe for the `[<initiator>]` prefix.
    pub(crate) initiator: String,
    /// The `Event.agent_id` of the commit's events: the sanitized agent id, `user:<h>` or
    /// `runtime`.
    pub(crate) event_agent_id: String,
}

/// The legacy agent lane's signature, byte-identical to the one `do_commit` always wrote:
/// author == committer == `agent:<sanitized agent_id> <runtime@advance-agents>`, prefix
/// `[<commit_type>] [<sanitized initiator>]`.
pub(crate) fn agent_authorship(
    req: &CommitRequest,
    when: &git2::Time,
) -> Result<Authorship, GitError> {
    let agent_id = sanitize_audit_field(&req.agent_id);
    let signature = Signature::new(&format!("agent:{agent_id}"), RUNTIME_EMAIL, when)?;
    Ok(Authorship {
        author: signature.clone(),
        committer: signature,
        commit_type: req.commit_type,
        initiator: sanitize_audit_field(&req.initiator),
        event_agent_id: agent_id,
    })
}

/// A user-lane commit: author `user:<handle> <user@advance-agents>`, committer
/// `runtime <runtime@advance-agents>`, type `user`, initiator `user:<handle>`.
pub(crate) fn user_authorship(
    actor: &UserActor,
    when: &git2::Time,
) -> Result<Authorship, GitError> {
    let initiator = actor.initiator();
    Ok(Authorship {
        author: Signature::new(&initiator, USER_EMAIL, when)?,
        committer: Signature::new(RUNTIME_NAME, RUNTIME_EMAIL, when)?,
        commit_type: CommitType::User,
        initiator: initiator.clone(),
        event_agent_id: initiator,
    })
}

/// Runtime bookkeeping (the adopt commit): author == committer ==
/// `runtime <runtime@advance-agents>`, type `micro`, event id `runtime`.
pub(crate) fn runtime_authorship(
    initiator: &'static str,
    when: &git2::Time,
) -> Result<Authorship, GitError> {
    let signature = Signature::new(RUNTIME_NAME, RUNTIME_EMAIL, when)?;
    Ok(Authorship {
        author: signature.clone(),
        committer: signature,
        commit_type: CommitType::Micro,
        initiator: initiator.to_string(),
        event_agent_id: RUNTIME_NAME.to_string(),
    })
}

/// The commit time every lane signs with: now, UTC offset 0 (the legacy lane's choice).
pub(crate) fn signature_time_now() -> git2::Time {
    let seconds = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0);
    git2::Time::new(seconds, 0)
}

/// What a user op means (D2: one gesture, one commit). The token is the label's `op`
/// (MODULE-003 §1.4.1, R6 `copy`); `adopt` is runtime-only and has no variant here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserOpKind {
    Edit,
    Create,
    /// `mkdir`, `parents: true` included: one marker `Put` per new level.
    CreateFolder,
    /// One item that keeps its parent.
    Rename,
    Move,
    /// R6: copy and duplicate.
    Copy,
    Delete,
    Restore(RestoreSource),
    Upload,
    /// `files:commit-external` (exactly one `Put{Disk}` or `Remove`).
    EditExternal,
}

impl UserOpKind {
    /// The `Advance-Op` / `git.commit.op` / `ClientGitCommitLabel.op` token.
    pub fn as_token(&self) -> &'static str {
        match self {
            UserOpKind::Edit => crate::label::OP_EDIT,
            UserOpKind::Create => crate::label::OP_CREATE,
            UserOpKind::CreateFolder => crate::label::OP_CREATE_FOLDER,
            UserOpKind::Rename => crate::label::OP_RENAME,
            UserOpKind::Move => crate::label::OP_MOVE,
            UserOpKind::Copy => crate::label::OP_COPY,
            UserOpKind::Delete => crate::label::OP_DELETE,
            UserOpKind::Restore(_) => crate::label::OP_RESTORE,
            UserOpKind::Upload => crate::label::OP_UPLOAD,
            UserOpKind::EditExternal => crate::label::OP_EDIT_EXTERNAL,
        }
    }
}

/// What a restore reads from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestoreSource {
    /// A commit, 40 hex.
    Commit(String),
    /// A named user version (`checkpoint/user/<label>` peeling to a user marker).
    Version(String),
    /// A generic checkpoint tag `checkpoint/<agent_id>/<label>`.
    Checkpoint { agent_id: String, label: String },
}

/// Who maintains a `Put` / `Remove` path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChangeRole {
    /// The user's own change (labelled, counted, evented).
    Primary,
    /// A runtime-maintained `<dir>/.meta.yaml`: rides along, never labelled, never counts
    /// as a change on its own.
    Sidecar,
}

/// Where a `Put`'s bytes come from.
#[derive(Clone, PartialEq, Eq)]
pub enum BlobSource {
    /// The exact bytes the caller wrote (or is about to write) at the path.
    Bytes(Vec<u8>),
    /// The file on disk. `oid` is the git blob id the caller computed; the worker reads
    /// the file once, fd-relative, and fails with `ContentChanged` on a mismatch.
    Disk { oid: String },
}

impl std::fmt::Debug for BlobSource {
    // Never print content: a request can carry up to MAX_USER_BYTES.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BlobSource::Bytes(bytes) => write!(f, "Bytes({} bytes)", bytes.len()),
            BlobSource::Disk { oid } => f.debug_struct("Disk").field("oid", oid).finish(),
        }
    }
}

/// `fstat` of the published inode, captured by the provider on the fd it wrote. The worker
/// records it in the index only when its own `fstatat` matches on `(dev, ino, size, mtime,
/// ctime)`; otherwise the entry is smudged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IndexStat {
    pub ctime_s: i64,
    pub ctime_ns: u32,
    pub mtime_s: i64,
    pub mtime_ns: u32,
    pub dev: u64,
    pub ino: u64,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
}

/// One change of a user commit. Paths are [`RepoPath`]s, so `.agent/**`, `.gitignore` and
/// every hidden name are unreachable as operands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathChange {
    /// Write a file. `executable: None` keeps the parent tree's mode (`100644` /
    /// `100755`), else `100644`.
    Put {
        path: RepoPath,
        content: BlobSource,
        role: ChangeRole,
        executable: Option<bool>,
        stat: Option<IndexStat>,
    },
    /// Remove a file (an untracked one only changes the disk).
    Remove { path: RepoPath, role: ChangeRole },
    /// `oid` = HEAD blob at `from` as `prepare` reported it (`None` = untracked); used for
    /// post-state idempotence.
    Move {
        from: RepoPath,
        to: RepoPath,
        oid: Option<String>,
    },
    /// R6: a copied file reuses the source blob.
    Copy {
        from: RepoPath,
        to: RepoPath,
        oid: Option<String>,
    },
    /// Remove a folder and everything under it.
    RemoveTree { dir: RepoPath },
    /// `oid` = HEAD subtree oid at `from` as `prepare` reported it.
    MoveTree {
        from: RepoPath,
        to: RepoPath,
        oid: Option<String>,
    },
    /// R6: a clean tracked folder reuses its subtree oid.
    CopyTree {
        from: RepoPath,
        to: RepoPath,
        oid: Option<String>,
    },
}

/// One user-lane commit request (D2: one gesture).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserCommitRequest {
    pub actor: UserActor,
    pub op: UserOpKind,
    pub changes: Vec<PathChange>,
    /// The Client API request id or the files op id; it reaches the `git.commit` payload.
    pub correlation_id: Option<String>,
    pub provenance: Option<Provenance>,
}

/// Whether a user item made a commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UserCommitStatus {
    Committed,
    /// Nothing versioned changed (no commit object, no `git.commit`).
    Unchanged,
}

/// A row's kind: a file, or a folder (folder ops give one row).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ItemKind {
    File,
    Dir,
}

/// The user-visible effect of an item. For a not-versioned item this is the disk effect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ItemChange {
    Added,
    Modified,
    Deleted,
    Renamed { from: String },
    Unchanged,
}

/// Why an item is not versioned (MODULE-003-AC-34, R1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NotVersioned {
    /// Over the tracked-size threshold.
    TooLarge,
    /// Untracked and matched by an ignore rule.
    Ignored,
    /// Moved or copied content that was past the adopt budget and stays untracked (R1).
    Untracked,
}

impl NotVersioned {
    /// The `versioned_reason` wire value.
    pub fn as_token(self) -> &'static str {
        match self {
            NotVersioned::TooLarge => "too_large",
            NotVersioned::Ignored => "ignored",
            NotVersioned::Untracked => "untracked",
        }
    }
}

/// One primary item of a user commit, in request order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemOutcome {
    /// Tree spelling; no trailing `/` (`kind` says `Dir`).
    pub path: String,
    pub kind: ItemKind,
    pub change: ItemChange,
    /// The blob after the op (versioned files that exist).
    pub oid: Option<String>,
    /// The HEAD blob before the op (diagnostic: should equal the client's base).
    pub parent_oid: Option<String>,
    pub versioned: bool,
    /// Present iff `versioned` is `false`.
    pub versioned_reason: Option<NotVersioned>,
    pub size: Option<u64>,
}

/// What `commit_user` answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserCommitOutcome {
    pub status: UserCommitStatus,
    /// Some iff `Committed`.
    pub sha: Option<String>,
    /// The `main` tip after the item.
    pub head_sha: Option<String>,
    /// The canonical subject (on `Unchanged`: what it would have read).
    pub subject: String,
    pub label: CommitLabel,
    /// One per primary item, request order.
    pub items: Vec<ItemOutcome>,
    /// The tracked-size threshold the item ran under.
    pub max_tracked_bytes: u64,
}

/// When `prepare` records a target's uncommitted disk state as `[micro] [runtime:adopt]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdoptPolicy {
    /// Never; only report.
    Never,
    /// When the disk holds this oid and HEAD does not (edit, edit-external).
    IfDiskIs(String),
    /// When the disk path is absent but HEAD has it (create, upload-new, destinations).
    IfDiskAbsent,
    /// When the disk differs from HEAD, an untracked file included (every delete, move,
    /// rename and copy source; every sidecar the op will write, R9).
    Always,
}

/// One `prepare` target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrepareTarget {
    File {
        path: RepoPath,
        adopt: AdoptPolicy,
    },
    /// A folder (or the vault root): status walk, always adopting, recursive.
    Tree {
        dir: RepoPath,
    },
}

/// The FIFO barrier plus adopt step that precedes a user op's disk mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrepareRequest {
    pub targets: Vec<PrepareTarget>,
    pub correlation_id: Option<String>,
}

/// What a path is, in HEAD or on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EntryKind {
    File,
    Symlink,
    Dir,
    /// FIFO, socket, device: never read.
    Other,
}

/// One `File` target's state after any adopt, request order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathState {
    pub path: String,
    pub head_oid: Option<String>,
    pub head_kind: Option<EntryKind>,
    /// Filter-free; `None` if absent or oversize.
    pub disk_oid: Option<String>,
    pub disk_kind: Option<EntryKind>,
    /// `fstat` identity of the regular file that was hashed: the caller re-checks it
    /// under its lock before publishing.
    pub identity: Option<FileIdentity>,
    pub tracked: bool,
    pub ignored: bool,
    pub oversize: bool,
    pub size: Option<u64>,
}

/// One `Tree` target's HEAD subtree after any adopt: the caller passes it as
/// `MoveTree.oid` / `CopyTree.oid` (post-state idempotence).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeState {
    pub dir: String,
    pub head_tree_oid: Option<String>,
}

/// What `prepare` answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrepareOutcome {
    pub head_sha: Option<String>,
    /// The `[micro] [runtime:adopt]` commit, if any.
    pub adopted_sha: Option<String>,
    /// At most 64.
    pub adopted_paths: Vec<String>,
    pub adopted_count: u32,
    /// One per `File` target, request order.
    pub states: Vec<PathState>,
    /// One per `Tree` target, request order.
    pub tree_states: Vec<TreeState>,
    /// At most 64: ignored, private, unrepresentable, nested-repo entries, and content
    /// past the adopt budget.
    pub unversioned: Vec<String>,
    pub unversioned_count: u32,
    /// `fstat` bytes of the counted unversioned content (the delete confirmation's
    /// `bytes:<n>`).
    pub unversioned_bytes: u64,
    /// A `Tree` target holds `.agent` (HEAD or disk).
    pub agent_territory: bool,
    /// A `Tree` target exceeded `MAX_TREE_ADOPT_ENTRIES`, or adoption stopped at
    /// `MAX_ADOPT_BYTES` / `ADOPT_TIME_BUDGET` (R1).
    pub adopt_incomplete: bool,
}

/// A named user version: a marker commit plus `checkpoint/user/<label>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SaveVersionRequest {
    pub actor: UserActor,
    /// Normalized by the worker (`label::normalize_title`).
    pub title: String,
    /// `None` = the whole vault (tag message `{}`).
    pub paths: Option<Vec<RepoPath>>,
    /// Adopt first (R1: tracked changes, and untracked content only under `paths`).
    pub adopt: bool,
    /// The version label's clock; tests inject it.
    pub at: Option<SystemTime>,
    pub correlation_id: Option<String>,
    pub provenance: Option<Provenance>,
}

/// What `save_version` answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SaveVersionOutcome {
    /// The marker commit.
    pub sha: String,
    /// The version label `YYYYMMDD-HHMMSS[-slug][-n]`.
    pub label: String,
    /// `checkpoint/user/<label>`.
    pub tag: String,
    pub title: String,
    pub paths: Option<Vec<String>>,
    pub adopted_sha: Option<String>,
    pub adopt_incomplete: bool,
    /// Content the adopt counted but did not record (R1).
    pub unversioned_count: u32,
}

/// What a `restore_tree` covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestoreScope {
    /// The scope the tag records (Checkpoint and Version sources only).
    CheckpointDomain,
    /// Files or folders; at most `MAX_USER_CHANGES` entries.
    Paths(Vec<RepoPath>),
    /// Every user-visible tracked path.
    Vault,
}

/// One forward restore commit (operator checkpoint rollback, folder and vault restores).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreTreeRequest {
    pub actor: UserActor,
    pub source: RestoreSource,
    pub scope: RestoreScope,
    pub correlation_id: Option<String>,
    pub provenance: Option<Provenance>,
}

/// What `restore_tree` answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreOutcome {
    pub status: UserCommitStatus,
    pub sha: Option<String>,
    pub head_sha: Option<String>,
    pub adopted_sha: Option<String>,
    pub subject: String,
    pub label: CommitLabel,
    /// At most 64.
    pub restored: Vec<String>,
    pub restored_count: u32,
    pub removed_count: u32,
    /// Ignored files the checkout replaced (at most 64).
    pub unversioned_overwritten: Vec<String>,
    pub unversioned_overwritten_count: u32,
}

/// CONTRACT-247: the user commit lane. Every method is one queue item on the same worker,
/// FIFO and coord as CONTRACT-020 (`GitCommitQueue::submit`), so it orders behind every
/// earlier submission. A closed channel answers `GitError::WorkerClosed`.
pub trait UserCommitLane: Send + Sync {
    /// The FIFO barrier: HEAD and disk blob ids for the caller's compare-and-swap, plus one
    /// `[micro] [runtime:adopt]` commit of the targets' uncommitted state.
    fn prepare(&self, req: PrepareRequest) -> oneshot::Receiver<Result<PrepareOutcome, GitError>>;
    /// One exact-content user commit.
    fn commit_user(
        &self,
        req: UserCommitRequest,
    ) -> oneshot::Receiver<Result<UserCommitOutcome, GitError>>;
    /// A named version (marker commit + annotated tag, atomically under coord).
    fn save_version(
        &self,
        req: SaveVersionRequest,
    ) -> oneshot::Receiver<Result<SaveVersionOutcome, GitError>>;
    /// One forward restore commit.
    fn restore_tree(
        &self,
        req: RestoreTreeRequest,
    ) -> oneshot::Receiver<Result<RestoreOutcome, GitError>>;
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    // MODULE-003-AC-26: the handle grammar always holds, and the documented mappings.
    #[test]
    fn user_actor_handle_normalization() {
        let handle = |id: &str| UserActor::from_principal_id(id).handle().to_string();
        assert_eq!(handle("advance"), "advance");
        assert_eq!(handle("John Smith"), "John-Smith");
        assert_eq!(handle(""), "operator");
        assert_eq!(handle("--..--"), "operator");
        assert_eq!(handle("张三"), "operator");
        assert_eq!(handle("a  b@@c"), "a-b-c");
        assert_eq!(handle(".hidden."), "hidden");
        assert_eq!(handle(&"x".repeat(100)), "x".repeat(64));
        // A cut that ends on a separator is trimmed again.
        assert_eq!(handle(&format!("{}-tail", "y".repeat(63))), "y".repeat(63));
        for id in [
            "advance",
            "John Smith",
            "",
            "张三",
            "a:b",
            "user:advance",
            "\u{0}\u{1}",
            &"é".repeat(70),
            &"a.b_c-d".repeat(20),
        ] {
            let h = handle(id);
            assert!(is_valid_handle(&h), "{id:?} → {h:?}");
            assert!(!h.contains(':'));
        }
        assert_eq!(
            UserActor::from_principal_id("advance").initiator(),
            "user:advance"
        );
    }

    // ADR 2026-10-15 (MODULE-003-AC-26): the three signature shapes; the agent lane's is
    // byte-identical to the legacy `do_commit` signature.
    #[test]
    fn authorship_signatures() {
        let when = git2::Time::new(1_700_000_000, 0);
        let mut req = CommitRequest::new(
            "res[ea]rch",
            "write",
            vec![PathBuf::from("a.md")],
            CommitType::Turn,
            "agent:res\nearch",
        );
        req.correlation_id = Some("c".into());
        let agent = agent_authorship(&req, &when).unwrap();
        assert_eq!(agent.author.name(), Some("agent:res_ea_rch"));
        assert_eq!(agent.author.email(), Some("runtime@advance-agents"));
        assert_eq!(agent.committer.name(), agent.author.name());
        assert_eq!(agent.committer.email(), agent.author.email());
        assert_eq!(agent.author.when().seconds(), 1_700_000_000);
        assert_eq!(agent.commit_type, CommitType::Turn);
        assert_eq!(agent.initiator, "agent:res_earch");
        assert_eq!(agent.event_agent_id, "res_ea_rch");

        let actor = UserActor::from_principal_id("advance");
        let user = user_authorship(&actor, &when).unwrap();
        assert_eq!(user.author.name(), Some("user:advance"));
        assert_eq!(user.author.email(), Some(USER_EMAIL));
        assert_eq!(user.committer.name(), Some(RUNTIME_NAME));
        assert_eq!(user.committer.email(), Some(RUNTIME_EMAIL));
        assert_eq!(user.commit_type, CommitType::User);
        assert_eq!(user.initiator, "user:advance");
        assert_eq!(user.event_agent_id, "user:advance");

        let runtime = runtime_authorship(ADOPT_INITIATOR, &when).unwrap();
        assert_eq!(runtime.author.name(), Some(RUNTIME_NAME));
        assert_eq!(runtime.author.email(), Some(RUNTIME_EMAIL));
        assert_eq!(runtime.committer.name(), Some(RUNTIME_NAME));
        assert_eq!(runtime.committer.email(), Some(RUNTIME_EMAIL));
        assert_eq!(runtime.commit_type, CommitType::Micro);
        assert_eq!(runtime.initiator, "runtime:adopt");
        assert_eq!(runtime.event_agent_id, "runtime");

        assert!(signature_time_now().seconds() > 1_700_000_000);
    }

    // MODULE-003 §1.4.1 (R6), R1: the lane's tokens are the label registry's.
    #[test]
    fn op_kind_tokens_match_label_registry() {
        let ops = [
            UserOpKind::Edit,
            UserOpKind::Create,
            UserOpKind::CreateFolder,
            UserOpKind::Rename,
            UserOpKind::Move,
            UserOpKind::Copy,
            UserOpKind::Delete,
            UserOpKind::Restore(RestoreSource::Commit("a".repeat(40))),
            UserOpKind::Upload,
            UserOpKind::EditExternal,
        ];
        let tokens: std::collections::HashSet<&str> = ops.iter().map(|op| op.as_token()).collect();
        assert_eq!(tokens.len(), ops.len());
        for token in &tokens {
            assert!(crate::label::OP_TOKENS.contains(token), "{token}");
        }
        assert!(!tokens.contains(crate::label::OP_ADOPT));
        assert!(!tokens.contains(crate::label::OP_SAVE_VERSION));
        assert_eq!(UserOpKind::EditExternal.as_token(), "edit-external");
        assert_eq!(UserOpKind::CreateFolder.as_token(), "create-folder");
        assert_eq!(NotVersioned::TooLarge.as_token(), "too_large");
        assert_eq!(NotVersioned::Ignored.as_token(), "ignored");
        assert_eq!(NotVersioned::Untracked.as_token(), "untracked");
        assert_eq!(
            format!("{:?}", BlobSource::Bytes(vec![0; 3])),
            "Bytes(3 bytes)"
        );
    }
}

//! Read-only workspace history (git-family PR-2 / PR-3) — the MODULE-003 public
//! READ surface the Client API `git` family and cap-fs's history host fns consume.
//!
//! [`GitHistoryReader`] opens the repository per call, read-only, and NEVER takes
//! the per-repo coord mutex (`coord.rs`): a page walk must not stall the commit
//! queue, and libgit2's object/ref reads are safe next to its own lock-file ref
//! updates (a reader sees the ref before or after an update, never a torn one).
//! Every read is bounded ([`MAX_PAGE_LIMIT`], [`MAX_SCAN_PER_PAGE`],
//! [`MAX_COUNTED_COMMITS`], [`MAX_CHECKPOINT_REFS`], [`MAX_FILE_HISTORY`],
//! [`MAX_BLOB_BYTES`]). libgit2 reads loose and packed objects alike, so a future
//! gc that persists its pack needs no reader change.
//!
//! # Honesty posture
//!
//! A workspace without a repository, one whose HEAD is off `main`, or one libgit2
//! cannot read is a STATUS, not an error: every page carries the
//! [`GitRepoStatus`] it was read under (`repo`), and an unreadable repository yields
//! an empty page tagged `Unreadable` instead of a failure. The only `Err`s are the
//! caller's: a cursor / sha naming no commit, or a refused path.
//!
//! # Threading
//!
//! Every method is synchronous libgit2 work. Callers on an async runtime dispatch
//! through `tokio::task::spawn_blocking` — the Client API transport already runs
//! `ClientApi::handle()` on the blocking pool, and cap-fs wraps its five history
//! host fns the same way.

use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};

use git2::{ObjectType, Oid, Repository, Sort};

use crate::checkpoint::parse_tag_message;
use crate::commit_queue::CommitType;
use crate::label::{label_of, CommitLabel, OP_SAVE_VERSION};
use crate::repo::{repo_status, GitRepoStatus};
use crate::user_lane::USER_NAMESPACE;

/// Hard cap on one commits page (`limit` above it is clamped, never refused).
pub const MAX_PAGE_LIMIT: usize = 200;
/// Page size when the caller names none.
pub const DEFAULT_PAGE_LIMIT: usize = 50;
/// Commits scanned (filter matched or not) before a page is cut with a cursor.
pub const MAX_SCAN_PER_PAGE: usize = 5_000;
/// Commits counted by [`GitHistoryReader::summary`] before `commit_count` is `None`.
pub const MAX_COUNTED_COMMITS: usize = 100_000;
/// `refs/tags/checkpoint/*` refs read before the listing is cut.
pub const MAX_CHECKPOINT_REFS: usize = 10_000;
/// Most-recent-first versions one file history returns (older ones are cut).
pub const MAX_FILE_HISTORY: usize = 1_000;
/// Commits a file history walks before it stops (bounds a path that changed rarely
/// in a long history).
pub const MAX_FILE_HISTORY_SCAN: usize = 50_000;
/// Largest blob `read_file_at` returns — cap-fs's `MAX_READ_BYTES` (64 MiB).
pub const MAX_BLOB_BYTES: usize = 64 * 1024 * 1024;

const MAIN_REF: &str = "refs/heads/main";
const CHECKPOINT_GLOB: &str = "refs/tags/checkpoint/*";
const CHECKPOINT_PREFIX: &str = "refs/tags/checkpoint/";
const AGENT_AUTHOR_PREFIX: &str = "agent:";

/// One commit of the linear `main` history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitEntry {
    /// 40-char lowercase hex.
    pub sha: String,
    /// Committer time, milliseconds since the Unix epoch (0 for a pre-1970 clock).
    pub committed_at_ms: u64,
    /// Parsed from the `[<type>] [<initiator>] <subject>` prefix the commit queue
    /// writes; `None` when the message does not carry it.
    pub commit_type: Option<CommitType>,
    /// The `[<initiator>]` prefix token (`agent:<id>`, `runtime:l6`, …); `None`
    /// when the prefix is absent.
    pub initiator: Option<String>,
    /// The agent the commit is attributed to: the author name `agent:<id>` the
    /// queue signs with, stripped of its prefix. `None` for a foreign author.
    pub agent_id: Option<String>,
    /// The free-form message after the prefix (the whole first line when there is
    /// no prefix).
    pub subject: String,
    /// Paths the commit changed against its first parent (every path for a root
    /// commit).
    pub affected_paths_count: u32,
    /// Parsed only from commits that carry the lane signatures (`label_of`).
    pub label: Option<CommitLabel>,
}

/// Which commits a page keeps. Every dimension is an exact match; `None` keeps all.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CommitFilter {
    /// Keep commits whose [`CommitEntry::agent_id`] is this id.
    pub agent_id: Option<String>,
    pub commit_type: Option<CommitType>,
    /// Keep commits whose [`CommitEntry::initiator`] is exactly this token
    /// (`agent:<id>`, `user:<handle>`, `runtime:adopt`, …; ADR 2026-10-15).
    pub initiator: Option<String>,
}

impl CommitFilter {
    fn keeps(&self, entry: &CommitEntry) -> bool {
        if let Some(agent) = &self.agent_id {
            if entry.agent_id.as_deref() != Some(agent.as_str()) {
                return false;
            }
        }
        if let Some(kind) = self.commit_type {
            if entry.commit_type != Some(kind) {
                return false;
            }
        }
        if let Some(initiator) = &self.initiator {
            if entry.initiator.as_deref() != Some(initiator.as_str()) {
                return false;
            }
        }
        true
    }
}

/// One `refs/tags/checkpoint/{agent}/{label}` tag, as the client sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointRecord {
    pub agent_id: String,
    pub label: String,
    /// The commit the tag (peeled) points at.
    pub sha: String,
    /// Tagger time (annotated) or the pointed commit's time (lightweight), ms.
    pub tagged_at_ms: u64,
    /// `None` = full-directory checkpoint; `Some` = path-scoped (verbatim from the
    /// tag message). Always `None` when `valid` is `false`.
    pub paths: Option<Vec<String>>,
    /// `false` for a tag whose message violates the strict JSON schema or whose
    /// ref grammar is off (`a/b/c` label, a non-commit target). Such tags are
    /// LISTED, never dropped — the client shows them as corrupt.
    pub valid: bool,
    /// The marker's `Advance-Title` when this tag is a user version
    /// (`checkpoint/user/<label>` peeling to a lane-signed `save-version` commit).
    /// `None` for agent checkpoints, including a legacy agent named `user`.
    pub title: Option<String>,
}

/// One page of [`GitHistoryReader::commits`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitPage {
    /// The repository state the page was read under. `Missing` / `Unreadable`
    /// pages are empty.
    pub repo: GitRepoStatus,
    pub items: Vec<CommitEntry>,
    /// The sha to pass as `after` for the next page; `None` once `main` is
    /// exhausted. Also set when [`MAX_SCAN_PER_PAGE`] cut a filtered walk short.
    pub next_after: Option<String>,
}

/// The result of [`GitHistoryReader::checkpoints`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointList {
    pub repo: GitRepoStatus,
    /// Sorted by agent id, then label.
    pub items: Vec<CheckpointRecord>,
}

/// The result of [`GitHistoryReader::summary`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoSummary {
    pub status: GitRepoStatus,
    /// The tip of `refs/heads/main` (`None` while unborn, missing or unreadable).
    pub head_sha: Option<String>,
    /// Commits reachable from `main` along first parents; `None` when unknown
    /// (no repository) or above [`MAX_COUNTED_COMMITS`].
    pub commit_count: Option<u64>,
    /// `refs/tags/checkpoint/*` refs; `None` when unknown or above
    /// [`MAX_CHECKPOINT_REFS`].
    pub checkpoint_count: Option<u64>,
}

/// One version of a file (PR-3), most-recent-first in a history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileVersion {
    /// The commit that introduced this version of the path.
    pub sha: String,
    pub committed_at_ms: u64,
    pub commit_type: Option<CommitType>,
    pub initiator: Option<String>,
    pub agent_id: Option<String>,
    pub subject: String,
    /// `true` when the commit deleted the path (no blob to read at this version).
    pub deleted: bool,
    /// Parsed only from commits that carry the lane signatures (`label_of`).
    pub label: Option<CommitLabel>,
}

/// The result of [`GitHistoryReader::file_history`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileHistory {
    pub repo: GitRepoStatus,
    pub items: Vec<FileVersion>,
    /// `true` when [`MAX_FILE_HISTORY`] or [`MAX_FILE_HISTORY_SCAN`] cut the walk.
    pub truncated: bool,
}

/// The result of [`GitHistoryReader::read_file_at`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileAtVersion {
    pub sha: String,
    pub bytes: Vec<u8>,
}

/// Why a read was refused. Repository state is never an error (see the module
/// docs) — these are the caller's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HistoryError {
    /// `after` / `sha` is not 40 lowercase-or-uppercase hex chars.
    MalformedSha(String),
    /// The sha names no commit in this repository.
    UnknownCommit(String),
    /// The path is not a plain workspace-relative file path (absolute, `..`,
    /// `.git`, `.agent/`, control chars, empty).
    InvalidPath { path: String, reason: &'static str },
    /// The path is not a blob in the named commit's tree.
    PathNotFound { path: String, sha: String },
    /// The blob is larger than [`MAX_BLOB_BYTES`].
    BlobTooLarge { path: String, size: u64 },
    /// The repository is missing or unreadable (reads that need a commit cannot
    /// answer with a status).
    Repo(GitRepoStatus),
}

impl std::fmt::Display for HistoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MalformedSha(s) => write!(f, "malformed sha {s:?}"),
            Self::UnknownCommit(s) => write!(f, "unknown commit {s}"),
            Self::InvalidPath { path, reason } => write!(f, "invalid path {path:?}: {reason}"),
            Self::PathNotFound { path, sha } => write!(f, "{path:?} is not in commit {sha}"),
            Self::BlobTooLarge { path, size } => {
                write!(f, "{path:?} is {size} bytes (max {MAX_BLOB_BYTES})")
            }
            Self::Repo(status) => write!(f, "repository {status}"),
        }
    }
}

impl std::error::Error for HistoryError {}

/// The read-only history reader. Cheap to construct (stores the workspace path);
/// every method opens the repository afresh.
#[derive(Debug, Clone)]
pub struct GitHistoryReader {
    workspace: PathBuf,
}

impl GitHistoryReader {
    /// `workspace` is the repository root (the directory holding `.git`). It need
    /// not exist yet: every read reports [`GitRepoStatus::Missing`] until it does.
    pub fn new(workspace: PathBuf) -> Self {
        Self { workspace }
    }

    pub fn workspace(&self) -> &Path {
        &self.workspace
    }

    /// [`repo_status`] of the workspace — the cheap probe (`/client/health`).
    pub fn status(&self) -> GitRepoStatus {
        repo_status(&self.workspace)
    }

    /// Status plus the `main` tip and bounded counts (`/client/git/status`).
    pub fn summary(&self) -> RepoSummary {
        let (repo, status) = match self.open() {
            Ok(opened) => opened,
            Err(status) => {
                return RepoSummary {
                    status,
                    head_sha: None,
                    commit_count: None,
                    checkpoint_count: None,
                }
            }
        };
        let head = main_tip(&repo);
        let commit_count = match head {
            Some(tip) => match count_first_parent(&repo, tip) {
                Ok(Some(n)) => Some(n),
                Ok(None) => None,
                Err(_) => None,
            },
            None => Some(0),
        };
        let checkpoint_count = count_checkpoint_refs(&repo).unwrap_or_default();
        RepoSummary {
            status,
            head_sha: head.map(|oid| oid.to_string()),
            commit_count,
            checkpoint_count,
        }
    }

    /// One page of `main`, newest first along first parents.
    ///
    /// `after`: resume below this commit (the `next_after` of the previous page);
    /// `None` starts at the tip. `limit` is clamped to `1..=MAX_PAGE_LIMIT`
    /// (`0` → [`DEFAULT_PAGE_LIMIT`]). A filtered walk scans at most
    /// [`MAX_SCAN_PER_PAGE`] commits before cutting the page with a cursor.
    pub fn commits(
        &self,
        after: Option<&str>,
        limit: usize,
        filter: &CommitFilter,
    ) -> Result<CommitPage, HistoryError> {
        let limit = clamp_limit(limit);
        let (repo, status) = match self.open() {
            Ok(opened) => opened,
            Err(status) => {
                return Ok(CommitPage {
                    repo: status,
                    items: Vec::new(),
                    next_after: None,
                })
            }
        };
        let start = match after {
            Some(sha) => {
                let oid = parse_sha(sha)?;
                if repo.find_commit(oid).is_err() {
                    return Err(HistoryError::UnknownCommit(sha.to_string()));
                }
                Some(oid)
            }
            None => main_tip(&repo),
        };
        let Some(start) = start else {
            // Unborn `main`: no history yet.
            return Ok(CommitPage {
                repo: status,
                items: Vec::new(),
                next_after: None,
            });
        };
        match walk_page(&repo, start, after.is_some(), limit, filter) {
            Ok((items, next_after)) => Ok(CommitPage {
                repo: status,
                items,
                next_after,
            }),
            Err(e) => Ok(CommitPage {
                repo: GitRepoStatus::Unreadable {
                    reason: e.message().to_string(),
                },
                items: Vec::new(),
                next_after: None,
            }),
        }
    }

    /// Every `refs/tags/checkpoint/{agent}/{label}` tag (of one agent when
    /// `agent_id` is given), corrupt ones included with `valid: false`.
    pub fn checkpoints(&self, agent_id: Option<&str>) -> CheckpointList {
        let (repo, status) = match self.open() {
            Ok(opened) => opened,
            Err(status) => {
                return CheckpointList {
                    repo: status,
                    items: Vec::new(),
                }
            }
        };
        match list_checkpoints(&repo, agent_id) {
            Ok(items) => CheckpointList {
                repo: status,
                items,
            },
            Err(e) => CheckpointList {
                repo: GitRepoStatus::Unreadable {
                    reason: e.message().to_string(),
                },
                items: Vec::new(),
            },
        }
    }

    /// The commits that changed `path` (workspace-relative), newest first along
    /// first parents (PR-3). A version whose commit removed the path is
    /// `deleted: true`.
    pub fn file_history(&self, path: &str) -> Result<FileHistory, HistoryError> {
        let rel = validate_workspace_path(path)?;
        let (repo, status) = match self.open() {
            Ok(opened) => opened,
            Err(status) => {
                return Ok(FileHistory {
                    repo: status,
                    items: Vec::new(),
                    truncated: false,
                })
            }
        };
        let Some(tip) = main_tip(&repo) else {
            return Ok(FileHistory {
                repo: status,
                items: Vec::new(),
                truncated: false,
            });
        };
        match walk_file_history(&repo, tip, &rel) {
            Ok((items, truncated)) => Ok(FileHistory {
                repo: status,
                items,
                truncated,
            }),
            Err(e) => Ok(FileHistory {
                repo: GitRepoStatus::Unreadable {
                    reason: e.message().to_string(),
                },
                items: Vec::new(),
                truncated: false,
            }),
        }
    }

    /// The bytes of `path` in commit `sha` (PR-3), at most [`MAX_BLOB_BYTES`].
    pub fn read_file_at(&self, path: &str, sha: &str) -> Result<FileAtVersion, HistoryError> {
        let rel = validate_workspace_path(path)?;
        let oid = parse_sha(sha)?;
        let (repo, _status) = self.open().map_err(HistoryError::Repo)?;
        let commit = repo
            .find_commit(oid)
            .map_err(|_| HistoryError::UnknownCommit(sha.to_string()))?;
        let tree = commit.tree().map_err(|e| {
            HistoryError::Repo(GitRepoStatus::Unreadable {
                reason: e.message().to_string(),
            })
        })?;
        let entry = tree
            .get_path(&rel)
            .map_err(|_| HistoryError::PathNotFound {
                path: path.to_string(),
                sha: commit.id().to_string(),
            })?;
        if entry.kind() != Some(ObjectType::Blob) {
            return Err(HistoryError::PathNotFound {
                path: path.to_string(),
                sha: commit.id().to_string(),
            });
        }
        let blob = repo
            .find_blob(entry.id())
            .map_err(|_| HistoryError::PathNotFound {
                path: path.to_string(),
                sha: commit.id().to_string(),
            })?;
        let size = blob.size() as u64;
        if size > MAX_BLOB_BYTES as u64 {
            return Err(HistoryError::BlobTooLarge {
                path: path.to_string(),
                size,
            });
        }
        Ok(FileAtVersion {
            sha: commit.id().to_string(),
            bytes: blob.content().to_vec(),
        })
    }

    /// Open read-only. `Ok((repo, Ready | NotMain))`; `Err(Missing | Unreadable)`.
    fn open(&self) -> Result<(Repository, GitRepoStatus), GitRepoStatus> {
        match repo_status(&self.workspace) {
            status @ (GitRepoStatus::Missing | GitRepoStatus::Unreadable { .. }) => Err(status),
            status => match Repository::open(&self.workspace) {
                Ok(repo) => Ok((repo, status)),
                Err(e) => Err(GitRepoStatus::Unreadable {
                    reason: e.message().to_string(),
                }),
            },
        }
    }
}

/// Clamp a caller-provided page size into `1..=MAX_PAGE_LIMIT` (`0` → default).
pub fn clamp_limit(limit: usize) -> usize {
    match limit {
        0 => DEFAULT_PAGE_LIMIT,
        n => n.min(MAX_PAGE_LIMIT),
    }
}

/// Parse the `[<type>] [<initiator>] <subject>` prefix the commit queue writes.
/// Returns `(commit_type, initiator, subject)`; a message without the exact prefix
/// (or with a type token that is not `turn` / `micro` / `l6` / `user`) yields
/// `(None, None, first_line)`. Only the first line is read, so a user-lane commit's
/// `Advance-*` trailer block never reaches the subject.
pub fn parse_commit_subject(message: &str) -> (Option<CommitType>, Option<String>, String) {
    let first_line = message.lines().next().unwrap_or("").trim_end();
    let parsed = (|| {
        let rest = first_line.strip_prefix('[')?;
        let end = rest.find(']')?;
        let kind = CommitType::parse_token(&rest[..end])?;
        let rest = rest[end + 1..].strip_prefix(" [")?;
        let end = rest.find(']')?;
        let initiator = rest[..end].to_string();
        let subject = rest[end + 1..].trim_start().to_string();
        Some((Some(kind), Some(initiator), subject))
    })();
    parsed.unwrap_or_else(|| (None, None, first_line.to_string()))
}

/// Reject anything but a plain workspace-relative file path: absolute, `..`, a
/// `.git` or `.agent` component (the runtime's private areas), empty, NUL /
/// control characters, or a trailing slash.
pub fn validate_workspace_path(path: &str) -> Result<PathBuf, HistoryError> {
    let refuse = |reason: &'static str| HistoryError::InvalidPath {
        path: path.to_string(),
        reason,
    };
    let stripped = path.strip_prefix("./").unwrap_or(path);
    if stripped.is_empty() {
        return Err(refuse("empty path"));
    }
    if stripped.chars().any(|c| c.is_control()) {
        return Err(refuse("control character"));
    }
    if stripped.contains('\\') {
        return Err(refuse("backslash separator"));
    }
    if stripped.ends_with('/') {
        return Err(refuse("trailing slash"));
    }
    let p = Path::new(stripped);
    if p.is_absolute() || p.has_root() {
        return Err(refuse("absolute path"));
    }
    let mut out = PathBuf::new();
    for component in p.components() {
        match component {
            Component::Normal(name) => {
                let name = name.to_string_lossy();
                if name.eq_ignore_ascii_case(".git") {
                    return Err(refuse(".git component"));
                }
                if name.eq_ignore_ascii_case(".agent") {
                    return Err(refuse(".agent component"));
                }
                out.push(name.as_ref());
            }
            Component::CurDir => {}
            Component::ParentDir => return Err(refuse("parent-directory traversal")),
            Component::RootDir | Component::Prefix(_) => return Err(refuse("absolute path")),
        }
    }
    if out.as_os_str().is_empty() {
        return Err(refuse("empty path"));
    }
    Ok(out)
}

fn parse_sha(sha: &str) -> Result<Oid, HistoryError> {
    if sha.len() != 40 || !sha.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(HistoryError::MalformedSha(sha.to_string()));
    }
    Oid::from_str(sha).map_err(|_| HistoryError::MalformedSha(sha.to_string()))
}

fn main_tip(repo: &Repository) -> Option<Oid> {
    repo.find_reference(MAIN_REF).ok().and_then(|r| r.target())
}

fn first_parent_walk(repo: &Repository, start: Oid) -> Result<git2::Revwalk<'_>, git2::Error> {
    let mut walk = repo.revwalk()?;
    walk.set_sorting(Sort::NONE)?;
    walk.simplify_first_parent()?;
    walk.push(start)?;
    Ok(walk)
}

fn count_first_parent(repo: &Repository, start: Oid) -> Result<Option<u64>, git2::Error> {
    let walk = first_parent_walk(repo, start)?;
    let mut n: u64 = 0;
    for oid in walk {
        oid?;
        n += 1;
        if n as usize > MAX_COUNTED_COMMITS {
            return Ok(None);
        }
    }
    Ok(Some(n))
}

fn count_checkpoint_refs(repo: &Repository) -> Result<Option<u64>, git2::Error> {
    let mut n: u64 = 0;
    for r in repo.references_glob(CHECKPOINT_GLOB)? {
        r?;
        n += 1;
        if n as usize > MAX_CHECKPOINT_REFS {
            return Ok(None);
        }
    }
    Ok(Some(n))
}

fn to_ms(seconds: i64) -> u64 {
    u64::try_from(seconds.max(0))
        .unwrap_or(0)
        .saturating_mul(1000)
}

fn agent_of(commit: &git2::Commit<'_>) -> Option<String> {
    commit
        .author()
        .name()
        .and_then(|name| name.strip_prefix(AGENT_AUTHOR_PREFIX))
        .filter(|id| !id.is_empty())
        .map(str::to_string)
}

fn commit_entry(repo: &Repository, commit: &git2::Commit<'_>) -> Result<CommitEntry, git2::Error> {
    let (commit_type, initiator, subject) = parse_commit_subject(commit.message().unwrap_or(""));
    let tree = commit.tree()?;
    let parent_tree = match commit.parent(0) {
        Ok(parent) => Some(parent.tree()?),
        Err(_) => None,
    };
    let diff = repo.diff_tree_to_tree(parent_tree.as_ref(), Some(&tree), None)?;
    Ok(CommitEntry {
        sha: commit.id().to_string(),
        committed_at_ms: to_ms(commit.time().seconds()),
        commit_type,
        initiator,
        agent_id: agent_of(commit),
        subject,
        affected_paths_count: u32::try_from(diff.deltas().len()).unwrap_or(u32::MAX),
        label: label_of(commit),
    })
}

/// Walk from `start` (skipping it when `skip_start`), keeping filter matches, until
/// `limit` items, `MAX_SCAN_PER_PAGE` scanned commits, or the end of history.
fn walk_page(
    repo: &Repository,
    start: Oid,
    skip_start: bool,
    limit: usize,
    filter: &CommitFilter,
) -> Result<(Vec<CommitEntry>, Option<String>), git2::Error> {
    let mut walk = first_parent_walk(repo, start)?.peekable();
    if skip_start {
        if let Some(first) = walk.next() {
            first?;
        }
    }
    let mut items = Vec::new();
    let mut scanned = 0usize;
    let mut last_scanned: Option<Oid> = None;
    let exhausted = loop {
        if items.len() >= limit || scanned >= MAX_SCAN_PER_PAGE {
            break walk.peek().is_none();
        }
        let Some(next) = walk.next() else {
            break true;
        };
        let oid = next?;
        scanned += 1;
        last_scanned = Some(oid);
        let commit = repo.find_commit(oid)?;
        let entry = commit_entry(repo, &commit)?;
        if filter.keeps(&entry) {
            items.push(entry);
        }
    };
    let next_after = if exhausted {
        None
    } else {
        last_scanned.map(|oid| oid.to_string())
    };
    Ok((items, next_after))
}

fn list_checkpoints(
    repo: &Repository,
    agent_id: Option<&str>,
) -> Result<Vec<CheckpointRecord>, git2::Error> {
    let mut items = Vec::new();
    for (i, r) in repo.references_glob(CHECKPOINT_GLOB)?.enumerate() {
        if i >= MAX_CHECKPOINT_REFS {
            break;
        }
        let r = r?;
        let Some(suffix) = r.name().and_then(|n| n.strip_prefix(CHECKPOINT_PREFIX)) else {
            continue;
        };
        // `checkpoint/{agent}/{label}`: a ref without the separator is not a
        // checkpoint by grammar (a hand-made `checkpoint/foo` tag) and is skipped;
        // extra separators keep the record with `valid: false` (the label is not
        // round-trippable, as `DefaultNamedCheckpoint::list` reports it).
        let Some((agent, label)) = suffix.split_once('/') else {
            continue;
        };
        if agent.is_empty() || label.is_empty() {
            continue;
        }
        if let Some(wanted) = agent_id {
            if agent != wanted {
                continue;
            }
        }
        let grammar_ok = !label.contains('/');
        let (sha, tagged_at_ms, valid, paths) = match r.peel_to_tag() {
            Ok(tag) => {
                let (valid, paths) = parse_tag_message(tag.message_bytes().unwrap_or(&[]));
                let commit = tag.target().ok().and_then(|o| o.peel_to_commit().ok());
                let when = tag
                    .tagger()
                    .map(|t| t.when().seconds())
                    .or_else(|| commit.as_ref().map(|c| c.time().seconds()))
                    .unwrap_or(0);
                match commit {
                    Some(c) => (c.id().to_string(), to_ms(when), valid, paths),
                    // An annotated tag pointing at a blob / tree: not a checkpoint
                    // target; keep it, flagged.
                    None => (tag.target_id().to_string(), to_ms(when), false, None),
                }
            }
            Err(_) => match r.peel_to_commit() {
                // Lightweight tag: the legacy empty message → `{}` (full directory).
                Ok(c) => (c.id().to_string(), to_ms(c.time().seconds()), true, None),
                Err(_) => (
                    r.target().map(|o| o.to_string()).unwrap_or_default(),
                    0,
                    false,
                    None,
                ),
            },
        };
        let valid = valid && grammar_ok;
        let title = user_version_title(repo, agent, &sha);
        items.push(CheckpointRecord {
            agent_id: agent.to_string(),
            label: label.to_string(),
            sha,
            tagged_at_ms,
            paths: if valid {
                paths.map(|ps| {
                    ps.into_iter()
                        .map(|p| p.to_string_lossy().into_owned())
                        .collect()
                })
            } else {
                None
            },
            valid,
            title,
        });
    }
    items.sort_by(|a, b| (&a.agent_id, &a.label).cmp(&(&b.agent_id, &b.label)));
    Ok(items)
}

/// A `checkpoint/user/<label>` tag is a user version iff it peels to a commit
/// whose `label_of` is `op: save-version` (MODULE-003 §1.4.3).
fn user_version_title(repo: &Repository, agent: &str, sha: &str) -> Option<String> {
    if !agent.eq_ignore_ascii_case(USER_NAMESPACE) {
        return None;
    }
    let oid = Oid::from_str(sha).ok()?;
    let commit = repo.find_commit(oid).ok()?;
    match label_of(&commit) {
        Some(label) if label.op == OP_SAVE_VERSION => label.title,
        _ => None,
    }
}

/// Production file-history adapter (PR-3). Wraps [`GitHistoryReader`] and maps a
/// physical workspace path onto the workspace-relative grammar the reader accepts.
#[derive(Debug, Clone)]
pub struct GitFileHistoryProvider {
    reader: GitHistoryReader,
}

impl GitFileHistoryProvider {
    pub fn new(workspace: PathBuf) -> Self {
        Self {
            reader: GitHistoryReader::new(workspace),
        }
    }

    pub fn reader(&self) -> &GitHistoryReader {
        &self.reader
    }

    /// Strip `workspace` from an absolute physical path (or accept an already
    /// relative one) and run [`validate_workspace_path`].
    pub fn relativize(&self, physical: &Path) -> Result<String, HistoryError> {
        let ws = self.reader.workspace();
        let rel = if physical.is_absolute() {
            match physical.strip_prefix(ws) {
                Ok(rel) => rel,
                Err(_) => {
                    return Err(HistoryError::InvalidPath {
                        path: physical.display().to_string(),
                        reason: "outside workspace",
                    });
                }
            }
        } else {
            physical
        };
        let as_str = rel.to_string_lossy();
        validate_workspace_path(&as_str)?;
        Ok(as_str.replace('\\', "/"))
    }

    pub fn history_for_physical(&self, physical: &Path) -> Result<FileHistory, HistoryError> {
        let rel = self.relativize(physical)?;
        self.reader.file_history(&rel)
    }

    pub fn read_physical_at(
        &self,
        physical: &Path,
        sha: &str,
    ) -> Result<FileAtVersion, HistoryError> {
        let rel = self.relativize(physical)?;
        self.reader.read_file_at(&rel, sha)
    }
}

/// Index checkpoints by the commit they point at (for inlining into commit pages).
pub fn checkpoints_by_sha(items: Vec<CheckpointRecord>) -> HashMap<String, Vec<CheckpointRecord>> {
    let mut map: HashMap<String, Vec<CheckpointRecord>> = HashMap::new();
    for item in items {
        map.entry(item.sha.clone()).or_default().push(item);
    }
    map
}

/// Blob id of `rel` in `tree` (`None` when absent or not a blob).
fn blob_at(tree: &git2::Tree<'_>, rel: &Path) -> Option<Oid> {
    let entry = tree.get_path(rel).ok()?;
    (entry.kind() == Some(ObjectType::Blob)).then(|| entry.id())
}

fn walk_file_history(
    repo: &Repository,
    tip: Oid,
    rel: &Path,
) -> Result<(Vec<FileVersion>, bool), git2::Error> {
    let walk = first_parent_walk(repo, tip)?;
    let mut items = Vec::new();
    let mut truncated = false;
    for (scanned, oid) in walk.enumerate() {
        if items.len() >= MAX_FILE_HISTORY || scanned >= MAX_FILE_HISTORY_SCAN {
            truncated = true;
            break;
        }
        let oid = oid?;
        let commit = repo.find_commit(oid)?;
        let tree = commit.tree()?;
        let now = blob_at(&tree, rel);
        let before = match commit.parent(0) {
            Ok(parent) => blob_at(&parent.tree()?, rel),
            Err(_) => None,
        };
        if now == before {
            continue;
        }
        let (commit_type, initiator, subject) =
            parse_commit_subject(commit.message().unwrap_or(""));
        items.push(FileVersion {
            sha: commit.id().to_string(),
            committed_at_ms: to_ms(commit.time().seconds()),
            commit_type,
            initiator,
            agent_id: agent_of(&commit),
            subject,
            deleted: now.is_none(),
            label: label_of(&commit),
        });
    }
    Ok((items, truncated))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_parse_round_trips_the_queue_format() {
        let (kind, initiator, subject) = parse_commit_subject("[turn] [agent:abc] write a.md");
        assert_eq!(kind, Some(CommitType::Turn));
        assert_eq!(initiator.as_deref(), Some("agent:abc"));
        assert_eq!(subject, "write a.md");
        let (kind, initiator, subject) =
            parse_commit_subject("[l6] [runtime:l6] L6 consolidation batch 7\n\nbody");
        assert_eq!(kind, Some(CommitType::L6));
        assert_eq!(initiator.as_deref(), Some("runtime:l6"));
        assert_eq!(subject, "L6 consolidation batch 7");
        let (kind, initiator, subject) = parse_commit_subject("[micro] [runtime:rollback] ");
        assert_eq!(kind, Some(CommitType::Micro));
        assert_eq!(initiator.as_deref(), Some("runtime:rollback"));
        assert_eq!(subject, "");
    }

    // ADR 2026-10-15 (MODULE-003-AC-26): a user-lane message parses like the queue's own,
    // and the trailer block stays out of the subject.
    #[test]
    fn prefix_parse_round_trips_user_type() {
        let (kind, initiator, subject) =
            parse_commit_subject("[user] [user:advance] Edit a.md (+1 −0)\n\nAdvance-Op: edit");
        assert_eq!(kind, Some(CommitType::User));
        assert_eq!(initiator.as_deref(), Some("user:advance"));
        assert_eq!(subject, "Edit a.md (+1 −0)");
    }

    // ADR 2026-10-15 (the git family's `?initiator=`): an exact match, combined with
    // the other dimensions.
    #[test]
    fn commit_filter_initiator_exact_match() {
        let entry = |initiator: Option<&str>, kind: Option<CommitType>| CommitEntry {
            sha: "a".repeat(40),
            committed_at_ms: 0,
            commit_type: kind,
            initiator: initiator.map(str::to_string),
            agent_id: None,
            subject: String::new(),
            affected_paths_count: 0,
            label: None,
        };
        let user = entry(Some("user:advance"), Some(CommitType::User));
        let adopt = entry(Some("runtime:adopt"), Some(CommitType::Micro));
        let foreign = entry(None, None);

        let all = CommitFilter::default();
        assert!(all.keeps(&user) && all.keeps(&adopt) && all.keeps(&foreign));

        let by_user = CommitFilter {
            initiator: Some("user:advance".into()),
            ..Default::default()
        };
        assert!(by_user.keeps(&user));
        assert!(!by_user.keeps(&adopt));
        assert!(!by_user.keeps(&foreign));
        for near in ["user:advanc", "user:advance ", "USER:advance", "user"] {
            let filter = CommitFilter {
                initiator: Some(near.into()),
                ..Default::default()
            };
            assert!(!filter.keeps(&user), "{near:?} must not match user:advance");
        }

        let combined = CommitFilter {
            initiator: Some("runtime:adopt".into()),
            commit_type: Some(CommitType::User),
            ..Default::default()
        };
        assert!(!combined.keeps(&adopt), "every dimension must match");
        let combined = CommitFilter {
            initiator: Some("runtime:adopt".into()),
            commit_type: Some(CommitType::Micro),
            ..Default::default()
        };
        assert!(combined.keeps(&adopt));
    }

    #[test]
    fn prefix_parse_rejects_foreign_shapes() {
        for raw in [
            "seed",
            "[Turn] [agent:a] x",
            "[turn][agent:a] x",
            "[turn] agent:a x",
            "[fix] [agent:a] x",
            "",
        ] {
            let (kind, initiator, subject) = parse_commit_subject(raw);
            assert_eq!(kind, None, "{raw:?}");
            assert_eq!(initiator, None, "{raw:?}");
            assert_eq!(subject, raw.lines().next().unwrap_or(""), "{raw:?}");
        }
    }

    #[test]
    fn workspace_path_grammar() {
        assert_eq!(
            validate_workspace_path("data/report.md").unwrap(),
            PathBuf::from("data/report.md")
        );
        assert_eq!(
            validate_workspace_path("./a/./b.txt").unwrap(),
            PathBuf::from("a/b.txt")
        );
        for bad in [
            "",
            "./",
            "/etc/passwd",
            "../x",
            "a/../b",
            ".git/config",
            "a/.GIT/x",
            ".agent/memory/k.jsonl",
            "sub/.agent/config.yaml",
            "a\\b",
            "a\nb",
            "dir/",
        ] {
            assert!(
                matches!(
                    validate_workspace_path(bad),
                    Err(HistoryError::InvalidPath { .. })
                ),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn limit_clamps() {
        assert_eq!(clamp_limit(0), DEFAULT_PAGE_LIMIT);
        assert_eq!(clamp_limit(1), 1);
        assert_eq!(clamp_limit(MAX_PAGE_LIMIT + 1), MAX_PAGE_LIMIT);
    }

    #[test]
    fn file_history_provider_relativize() {
        let td = tempfile::TempDir::new().unwrap();
        let root = std::fs::canonicalize(td.path()).unwrap();
        let provider = GitFileHistoryProvider::new(root.clone());
        assert_eq!(
            provider.relativize(&root.join("data/a.md")).unwrap(),
            "data/a.md"
        );
        assert!(provider.relativize(&root.join(".git/config")).is_err());
        assert!(provider.relativize(Path::new("/etc/passwd")).is_err());
    }

    #[test]
    fn sha_grammar() {
        assert!(parse_sha(&"a".repeat(40)).is_ok());
        assert!(matches!(
            parse_sha("abc"),
            Err(HistoryError::MalformedSha(_))
        ));
        assert!(matches!(
            parse_sha(&"g".repeat(40)),
            Err(HistoryError::MalformedSha(_))
        ));
    }
}

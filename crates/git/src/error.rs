//! `GitError` — MODULE-003 Slice A public error surface.
//!
//! Matches the `Result<Oid, GitError>` signature byte-for-byte with MODULE-003
//! §1.4.1 line 110 (`CommitRequest.reply`) and §2.3 line 509 (`GitCommitQueue::submit`).
//!
//! All variants are intentionally opaque: no raw `git2::Error` / `git2::ErrorCode`
//! appear in the public type surface, preserving the MODULE-003 §1.1 invariant
//! that no other module imports `git2` directly.

use std::fmt;
use std::path::PathBuf;

/// Slice B rollback + checkpoint shared discrimination enum.
///
/// Carried inside `RollbackError::PermissionDenied` and
/// `CheckpointError::InvalidPath` so callers can programmatically discriminate
/// between the path-rejection reasons defined in MODULE-003 §2.8 + §3.8.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeniedReason {
    /// `..` (ParentDir) component anywhere in the path.
    ParentDirTraversal,
    /// Hidden runtime path target — `.git/**`, `.meta.yaml`, `*.sqlite*`,
    /// `.runtime/**`, `.advance/**`, `.sub/**`.
    HiddenRuntimePath,
    /// `.agent/` path at `NamedCheckpoint::create` (always rejected) OR at
    /// `rollback(PathScoped)` outside the memory-rollback subtree
    /// (`.agent/{agent_id}/memory/**`). Memory-rollback paths are accepted.
    DotAgentOutsideMemoryRollback,
    /// Path resolves inside another agent's territory (directory containing
    /// a `.agent/` marker subdirectory under the caller's root).
    ChildTerritoryOverlap,
    /// Absolute path, Windows backslash separator, or otherwise outside the
    /// agent's writable domain.
    NotWritableDomain,
    /// Non-UTF8 bytes OR ASCII control character (`\n\r\t\0`, < 0x20) in
    /// the path string.
    Encoding,
}

impl fmt::Display for DeniedReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ParentDirTraversal => "parent-directory traversal",
            Self::HiddenRuntimePath => "hidden runtime path",
            Self::DotAgentOutsideMemoryRollback => ".agent/ outside memory-rollback subtree",
            Self::ChildTerritoryOverlap => "child-territory overlap",
            Self::NotWritableDomain => "not in writable domain",
            Self::Encoding => "path encoding (non-UTF8 or control char)",
        })
    }
}

/// CONTRACT-021 WorkspaceRollback public error surface.
///
/// Mirrors MODULE-003 §2.8 Error Handling table (Slice B additions).
/// All variants are intentionally opaque: no raw `git2::Error` appears in
/// the type surface, preserving §1.1 "No other module imports `git2`".
#[derive(Debug)]
pub enum RollbackError {
    /// I/O failure during agent_id → agent_root scan, child-territory
    /// detection, or `memory_rollback_paths` enumeration.
    Io(std::io::Error),
    /// libgit2 returned an error — opaque `(code, message)` stringified at
    /// the `From<git2::Error>` boundary.
    Libgit2 { code: String, message: String },
    /// Path-scoped rollback input fails validation; carries `DeniedReason`
    /// for programmatic discrimination.
    PermissionDenied { path: PathBuf, reason: DeniedReason },
    /// Target commit/checkpoint missing, declared path absent from target
    /// commit tree, or unresolvable `agent_id` (no matching
    /// `.agent/config.yaml` in workspace).
    NotFound { what: String },
    /// Wraps `CheckpointError::InvalidState` at the `rollback_to_checkpoint`
    /// boundary so §1.4.3 line 411-413's "surface as
    /// `CheckpointError::InvalidState`" is preserved inside the trait's
    /// `Result<_, RollbackError>` return type.
    Checkpoint(CheckpointError),
    /// Malformed hex in `RollbackTarget::Commit(String)` OR unresolvable
    /// label in `RollbackTarget::Checkpoint(String)` (distinct from
    /// tag-present-but-invalid-message, which routes through
    /// `::Checkpoint(InvalidState)`).
    InvalidTarget { target: String, reason: String },
}

impl fmt::Display for RollbackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "rollback i/o error: {e}"),
            Self::Libgit2 { code, message } => {
                write!(f, "rollback libgit2 error (code={code}): {message}")
            }
            Self::PermissionDenied { path, reason } => {
                write!(
                    f,
                    "rollback permission-denied on {}: {reason}",
                    path.display()
                )
            }
            Self::NotFound { what } => write!(f, "rollback not-found: {what}"),
            Self::Checkpoint(e) => write!(f, "rollback wraps checkpoint error: {e}"),
            Self::InvalidTarget { target, reason } => {
                write!(f, "rollback invalid-target {target}: {reason}")
            }
        }
    }
}

impl std::error::Error for RollbackError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Checkpoint(e) => Some(e),
            _ => None,
        }
    }
}

impl From<git2::Error> for RollbackError {
    fn from(e: git2::Error) -> Self {
        Self::Libgit2 {
            code: format!("{:?}", e.code()),
            message: e.message().to_string(),
        }
    }
}

impl From<std::io::Error> for RollbackError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<CheckpointError> for RollbackError {
    fn from(e: CheckpointError) -> Self {
        Self::Checkpoint(e)
    }
}

impl From<GitError> for RollbackError {
    fn from(e: GitError) -> Self {
        match e {
            GitError::Libgit2 { code, message } => Self::Libgit2 { code, message },
            GitError::Io(err) => Self::Io(err),
            GitError::NotSingleBranch { observed } => Self::InvalidTarget {
                target: observed.clone(),
                reason: "repository is not single-branch".to_string(),
            },
            GitError::PathOutsideWorkdir { path } => Self::PermissionDenied {
                path,
                reason: DeniedReason::NotWritableDomain,
            },
            GitError::WorkerClosed => Self::Io(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "git commit worker closed",
            )),
            // Slice C+D: propagate out-of-bounds config as InvalidTarget so
            // callers pattern-matching on `RollbackError` see a typed
            // discriminant rather than an opaque Io/Libgit2 surface.
            GitError::InvalidConfig {
                field,
                value,
                reason,
            } => Self::InvalidTarget {
                target: format!("{field}={value}"),
                reason,
            },
            // User lane (ADR 2026-10-15, MODULE-003 §2.8): the refusal token is the
            // reason; the target names the refused path when there is one.
            GitError::InvalidUserOp { reason, path } => Self::InvalidTarget {
                target: user_op_target(path.as_deref()),
                reason: reason.as_token().to_string(),
            },
            GitError::ContentChanged { .. } => Self::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                e.to_string(),
            )),
            GitError::HeadMoved { .. } => Self::Libgit2 {
                code: HEAD_MOVED_CODE.to_string(),
                message: e.to_string(),
            },
        }
    }
}

impl From<GitError> for CheckpointError {
    fn from(e: GitError) -> Self {
        match e {
            GitError::Libgit2 { code, message } => Self::Libgit2 { code, message },
            GitError::Io(err) => Self::Io(err),
            // NotSingleBranch is a branch-policy violation, not a tag-message
            // schema violation. Surface as `Libgit2` (opaque code/message
            // pair) rather than misusing `InvalidState`, which is reserved
            // for corrupt tag messages per §2.8 and §1.4.3.
            GitError::NotSingleBranch { observed } => Self::Libgit2 {
                code: "NotSingleBranch".to_string(),
                message: format!("repository is not single-branch (observed {observed})"),
            },
            GitError::PathOutsideWorkdir { path } => Self::InvalidPath {
                path,
                reason: DeniedReason::NotWritableDomain,
            },
            GitError::WorkerClosed => Self::Io(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "git commit worker closed",
            )),
            // Slice C+D: out-of-bounds config surfaces through the checkpoint
            // boundary as `InvalidLabel` — closest semantic fit since the
            // config value is a structural parameter of the checkpoint impl's
            // construction, not a tag message or path. Callers will see the
            // offending `field=value` as the InvalidLabel's `label` field.
            GitError::InvalidConfig {
                field,
                value,
                reason,
            } => Self::InvalidLabel {
                label: format!("{field}={value}"),
                reason,
            },
            // User lane (ADR 2026-10-15, MODULE-003 §2.8): same mapping shape as the
            // rollback boundary above.
            GitError::InvalidUserOp { reason, path } => Self::InvalidLabel {
                label: user_op_target(path.as_deref()),
                reason: reason.as_token().to_string(),
            },
            GitError::ContentChanged { .. } => Self::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                e.to_string(),
            )),
            GitError::HeadMoved { .. } => Self::Libgit2 {
                code: HEAD_MOVED_CODE.to_string(),
                message: e.to_string(),
            },
        }
    }
}

/// The `code` a [`GitError::HeadMoved`] carries across the rollback and checkpoint
/// boundaries (MODULE-003 §2.8).
const HEAD_MOVED_CODE: &str = "HeadMoved";

/// The `target` / `label` of a converted [`GitError::InvalidUserOp`]: the refused path,
/// or `user-lane` when the refusal names none.
fn user_op_target(path: Option<&std::path::Path>) -> String {
    path.map_or_else(|| "user-lane".to_string(), |p| p.display().to_string())
}

/// Why the user commit lane refused a request (ADR 2026-10-15, CONTRACT-247,
/// MODULE-003 §2.8). A closed set of tokens that never carry user content.
///
/// The Client API maps five of them to their own registry entries (MODULE-020 §2.8):
/// `TargetExists` → `already_exists ["target_exists"]`, `PrivatePath` → `not_found`,
/// `ReadOnlyPath` → `forbidden ["read_only","reason:agent_system|vcs_control"]`,
/// `AgentTerritory` → `forbidden ["read_only","reason:contains_territory"]`,
/// `ReservedNamespace` → `invalid_request ["reserved_namespace"]`. Any other reason is a
/// provider bug on the files routes and `invalid_request [<token>]` on the git rollback
/// route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UserOpRefusal {
    /// The op's changes do not have the op's shape (MODULE-003 §1.4.1), or a user-lane-only
    /// commit type reached the legacy `submit`.
    OpShape,
    /// A path failed the shared-types `workspace_path` grammar.
    InvalidPath,
    /// A path is Private or Junk (never addressable by the user).
    PrivatePath,
    /// A path is read-only for the user (`.agent/**`, `.gitignore`, `.gitattributes`,
    /// `.gitmodules`).
    ReadOnlyPath,
    /// A version title is empty or longer than 80 scalars after normalization.
    InvalidTitle,
    /// More than `MAX_USER_CHANGES` changes in one request.
    TooManyChanges,
    /// More than `MAX_USER_BYTES` of `Bytes` content in one request.
    TooManyBytes,
    /// The same tree path appears twice.
    DuplicatePath,
    /// A change sits under a folder the same request removes, moves or copies.
    NestedChange,
    /// Two paths fold equal under `core.ignorecase`.
    CaseCollision,
    /// A file would replace a folder (or the reverse) without the explicit form.
    TypeConflict,
    /// A create or destination path already exists.
    TargetExists,
    /// A source path does not exist.
    SourceMissing,
    /// A symbolic link sits where the op writes.
    Symlink,
    /// A folder op would carry an agent territory (`.agent`).
    AgentTerritory,
    /// A tree walk or plan exceeded its bound.
    TreeTooLarge,
    /// The `user` checkpoint namespace is reserved.
    ReservedNamespace,
    /// A `checkpoint/user/*` tag that is not a user version.
    NotAUserVersion,
    /// Every version label candidate up to `-99` is taken.
    VersionLabelExhausted,
    /// A restore source names no commit, version or checkpoint.
    UnknownRestoreSource,
    /// A version was requested on an unborn `main`.
    NothingToVersion,
}

impl UserOpRefusal {
    /// Every refusal, in registry order.
    pub const ALL: [UserOpRefusal; 21] = [
        UserOpRefusal::OpShape,
        UserOpRefusal::InvalidPath,
        UserOpRefusal::PrivatePath,
        UserOpRefusal::ReadOnlyPath,
        UserOpRefusal::InvalidTitle,
        UserOpRefusal::TooManyChanges,
        UserOpRefusal::TooManyBytes,
        UserOpRefusal::DuplicatePath,
        UserOpRefusal::NestedChange,
        UserOpRefusal::CaseCollision,
        UserOpRefusal::TypeConflict,
        UserOpRefusal::TargetExists,
        UserOpRefusal::SourceMissing,
        UserOpRefusal::Symlink,
        UserOpRefusal::AgentTerritory,
        UserOpRefusal::TreeTooLarge,
        UserOpRefusal::ReservedNamespace,
        UserOpRefusal::NotAUserVersion,
        UserOpRefusal::VersionLabelExhausted,
        UserOpRefusal::UnknownRestoreSource,
        UserOpRefusal::NothingToVersion,
    ];

    /// The stable snake_case token (MODULE-003 §2.8).
    pub const fn as_token(self) -> &'static str {
        match self {
            UserOpRefusal::OpShape => "op_shape",
            UserOpRefusal::InvalidPath => "invalid_path",
            UserOpRefusal::PrivatePath => "private_path",
            UserOpRefusal::ReadOnlyPath => "read_only_path",
            UserOpRefusal::InvalidTitle => "invalid_title",
            UserOpRefusal::TooManyChanges => "too_many_changes",
            UserOpRefusal::TooManyBytes => "too_many_bytes",
            UserOpRefusal::DuplicatePath => "duplicate_path",
            UserOpRefusal::NestedChange => "nested_change",
            UserOpRefusal::CaseCollision => "case_collision",
            UserOpRefusal::TypeConflict => "type_conflict",
            UserOpRefusal::TargetExists => "target_exists",
            UserOpRefusal::SourceMissing => "source_missing",
            UserOpRefusal::Symlink => "symlink",
            UserOpRefusal::AgentTerritory => "agent_territory",
            UserOpRefusal::TreeTooLarge => "tree_too_large",
            UserOpRefusal::ReservedNamespace => "reserved_namespace",
            UserOpRefusal::NotAUserVersion => "not_a_user_version",
            UserOpRefusal::VersionLabelExhausted => "version_label_exhausted",
            UserOpRefusal::UnknownRestoreSource => "unknown_restore_source",
            UserOpRefusal::NothingToVersion => "nothing_to_version",
        }
    }
}

impl fmt::Display for UserOpRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_token())
    }
}

/// CONTRACT-022 NamedCheckpoint public error surface.
///
/// Mirrors MODULE-003 §2.8 Error Handling table (Slice B additions).
/// All variants opaque per §1.1.
#[derive(Debug)]
pub enum CheckpointError {
    /// I/O failure reading tag reference, message blob, or composed-name probe.
    Io(std::io::Error),
    /// libgit2 returned an error — opaque.
    Libgit2 { code: String, message: String },
    /// Label or `agent_id` fails Git ref-name grammar (composed as
    /// `checkpoint/{agent_id}/{label}` and probed via `Tag::is_valid_name`),
    /// OR contains NUL / ASCII control characters (rejected before git2 call).
    InvalidLabel { label: String, reason: String },
    /// Per-path input to `create()` fails validation; carries `DeniedReason`
    /// for programmatic discrimination.
    InvalidPath { path: PathBuf, reason: DeniedReason },
    /// Corrupt or schema-violating tag message (non-object, extra keys,
    /// null `paths`, non-array `paths`, non-string member, BOM-prefixed).
    /// Fail-closed per PRD §7.2.
    InvalidState { label: String, reason: String },
    /// Checkpoint label already exists.
    Conflict { label: String },
    /// Tag absent at `list`/`delete`/resolve time.
    NotFound { label: String },
}

impl fmt::Display for CheckpointError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "checkpoint i/o error: {e}"),
            Self::Libgit2 { code, message } => {
                write!(f, "checkpoint libgit2 error (code={code}): {message}")
            }
            Self::InvalidLabel { label, reason } => {
                write!(f, "checkpoint invalid-label {label:?}: {reason}")
            }
            Self::InvalidPath { path, reason } => {
                write!(f, "checkpoint invalid-path {}: {reason}", path.display())
            }
            Self::InvalidState { label, reason } => {
                write!(f, "checkpoint invalid-state {label:?}: {reason}")
            }
            Self::Conflict { label } => write!(f, "checkpoint conflict: {label:?} already exists"),
            Self::NotFound { label } => write!(f, "checkpoint not-found: {label:?}"),
        }
    }
}

impl std::error::Error for CheckpointError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<git2::Error> for CheckpointError {
    fn from(e: git2::Error) -> Self {
        Self::Libgit2 {
            code: format!("{:?}", e.code()),
            message: e.message().to_string(),
        }
    }
}

impl From<std::io::Error> for CheckpointError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

#[derive(Debug)]
pub enum GitError {
    /// libgit2 returned an error. Opaque — code/message stringified from
    /// `git2::Error` at the `From` boundary; no raw git2 types exposed.
    Libgit2 { code: String, message: String },
    /// I/O error reaching the repository directory, `.gitignore`, or a caller-
    /// supplied path that isn't encodable as UTF-8.
    Io(std::io::Error),
    /// Repository on disk has a HEAD that is not `refs/heads/main` OR there exists
    /// a co-existing non-main local branch (PRD §7.2 "no per-agent branches").
    /// `observed` is a Git ref name (ASCII), not user content.
    NotSingleBranch { observed: String },
    /// A commit request's path resolved outside the repository workdir — either
    /// an absolute path outside the workdir, or a relative path containing a `..`
    /// (ParentDir) component (PRD §7.2 path rules).
    PathOutsideWorkdir { path: std::path::PathBuf },
    /// Commit worker panicked or the channel was closed before returning a result.
    /// Produced via three paths (see `commit_queue` rustdoc): sanity open failure,
    /// channel close during send, or `catch_unwind` catching a panic inside
    /// `do_commit`.
    WorkerClosed,
    /// Slice C+D: config argument out of bounds. Produced by
    /// [`crate::config::StaticGitConfigProvider::new`] when
    /// `gc_interval_hours ∉ (0, 8760]` or `max_tracked_file_mb ∉ (0, 4096]`
    /// (mirrors MODULE-001 `RuntimeConfig::validate_config` bounds).
    InvalidConfig {
        field: &'static str,
        value: u64,
        reason: String,
    },
    /// A user-lane request broke the lane grammar (ADR 2026-10-15, MODULE-003 §2.8), or a
    /// [`crate::commit_queue::CommitType::User`] request reached the legacy `submit`. The
    /// reason is a closed token; `path` names the refused operand when there is one.
    InvalidUserOp {
        reason: UserOpRefusal,
        path: Option<PathBuf>,
    },
    /// A `BlobSource::Disk { oid }` (or an adopt read) did not hash to `expected`, or the
    /// path was not a plain file reached without symlinks. `actual` is the oid read, `None`
    /// when no regular file was there.
    ContentChanged {
        path: PathBuf,
        expected: String,
        actual: Option<String>,
    },
    /// `main` moved between building a user-lane tree and the ref compare-and-swap, three
    /// times in a row (MODULE-003 §1.4.1 item 3). `None` stands for an unborn `main`.
    HeadMoved {
        expected: Option<String>,
        actual: Option<String>,
    },
}

impl fmt::Display for GitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Libgit2 { code, message } => {
                write!(f, "libgit2 error (code={code}): {message}")
            }
            Self::Io(e) => write!(f, "i/o error: {e}"),
            Self::NotSingleBranch { observed } => {
                write!(f, "repository is not single-branch: observed {observed}")
            }
            Self::PathOutsideWorkdir { path } => {
                write!(
                    f,
                    "path outside workdir or contains '..': {}",
                    path.display()
                )
            }
            Self::WorkerClosed => {
                write!(f, "commit worker closed before reply was sent")
            }
            Self::InvalidConfig {
                field,
                value,
                reason,
            } => write!(f, "git invalid-config {field}={value}: {reason}"),
            Self::InvalidUserOp { reason, path } => match path {
                Some(path) => write!(
                    f,
                    "user-lane request refused ({reason}): {}",
                    path.display()
                ),
                None => write!(f, "user-lane request refused ({reason})"),
            },
            Self::ContentChanged {
                path,
                expected,
                actual,
            } => write!(
                f,
                "content of {} changed: expected {expected}, found {}",
                path.display(),
                actual.as_deref().unwrap_or("no regular file")
            ),
            Self::HeadMoved { expected, actual } => write!(
                f,
                "main moved during a user-lane commit: expected {}, found {}",
                expected.as_deref().unwrap_or("unborn"),
                actual.as_deref().unwrap_or("unborn")
            ),
        }
    }
}

impl std::error::Error for GitError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<git2::Error> for GitError {
    fn from(e: git2::Error) -> Self {
        Self::Libgit2 {
            code: format!("{:?}", e.code()),
            message: e.message().to_string(),
        }
    }
}

impl From<std::io::Error> for GitError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    // ADR 2026-10-15 (MODULE-003 §2.8): the refusal set is closed and snake_case, and the
    // three user-lane variants render and cross the rollback / checkpoint boundaries
    // as typed values.
    #[test]
    fn user_lane_errors_display_and_convert() {
        let tokens: HashSet<&str> = UserOpRefusal::ALL.iter().map(|r| r.as_token()).collect();
        assert_eq!(tokens.len(), UserOpRefusal::ALL.len(), "tokens are unique");
        for token in &tokens {
            assert!(
                token.chars().all(|c| c.is_ascii_lowercase() || c == '_')
                    && !token.starts_with('_')
                    && !token.ends_with('_'),
                "snake_case token: {token}"
            );
        }
        assert_eq!(UserOpRefusal::OpShape.as_token(), "op_shape");
        assert_eq!(UserOpRefusal::OpShape.to_string(), "op_shape");
        assert_eq!(
            UserOpRefusal::NotAUserVersion.as_token(),
            "not_a_user_version"
        );

        let refused = GitError::InvalidUserOp {
            reason: UserOpRefusal::TargetExists,
            path: Some(PathBuf::from("notes/a.md")),
        };
        assert_eq!(
            refused.to_string(),
            "user-lane request refused (target_exists): notes/a.md"
        );
        match RollbackError::from(refused) {
            RollbackError::InvalidTarget { target, reason } => {
                assert_eq!(target, "notes/a.md");
                assert_eq!(reason, "target_exists");
            }
            other => panic!("expected InvalidTarget, got {other:?}"),
        }
        let shape = GitError::InvalidUserOp {
            reason: UserOpRefusal::OpShape,
            path: None,
        };
        assert_eq!(shape.to_string(), "user-lane request refused (op_shape)");
        match CheckpointError::from(shape) {
            CheckpointError::InvalidLabel { label, reason } => {
                assert_eq!(label, "user-lane");
                assert_eq!(reason, "op_shape");
            }
            other => panic!("expected InvalidLabel, got {other:?}"),
        }

        let changed = || GitError::ContentChanged {
            path: PathBuf::from("a.md"),
            expected: "e".repeat(40),
            actual: None,
        };
        assert!(changed().to_string().contains("found no regular file"));
        match RollbackError::from(changed()) {
            RollbackError::Io(e) => assert_eq!(e.kind(), std::io::ErrorKind::InvalidData),
            other => panic!("expected Io(InvalidData), got {other:?}"),
        }
        match CheckpointError::from(changed()) {
            CheckpointError::Io(e) => assert_eq!(e.kind(), std::io::ErrorKind::InvalidData),
            other => panic!("expected Io(InvalidData), got {other:?}"),
        }

        let moved = || GitError::HeadMoved {
            expected: None,
            actual: Some("a".repeat(40)),
        };
        assert!(moved().to_string().contains("expected unborn"));
        match RollbackError::from(moved()) {
            RollbackError::Libgit2 { code, .. } => assert_eq!(code, "HeadMoved"),
            other => panic!("expected Libgit2, got {other:?}"),
        }
        match CheckpointError::from(moved()) {
            CheckpointError::Libgit2 { code, .. } => assert_eq!(code, "HeadMoved"),
            other => panic!("expected Libgit2, got {other:?}"),
        }
    }
}

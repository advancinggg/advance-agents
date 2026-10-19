//! `commit_user`: one exact-content user commit (ADR 2026-10-15, CONTRACT-247; MODULE-003 §1.4.1
//! items 1–4, AC-27, AC-28, AC-36, AC-38).
//!
//! The item runs in the commit worker with the coord mutex held:
//!
//! 1. **Validation**: the bounds (`MAX_USER_CHANGES`, `MAX_USER_BYTES`), the op's shape
//!    (MODULE-003 §1.4.1 "Labels" table: which changes each op carries; sidecars ride along in
//!    every op), no tree path twice, no two paths that fold equal under `core.ignorecase` (a
//!    case-only rename's own pair excepted), and no change below a folder the request removes,
//!    moves or copies (the explicit type-change forms excepted).
//! 2. **Content plan**: `Bytes` are hashed in memory; a `Disk { oid }` source is opened through
//!    `safe_fs` (a regular file reached without symlinks, else `ContentChanged`) and planned at
//!    its claimed id. Content over the tracked-size threshold is neither hashed nor read (it is
//!    saved but not versioned).
//! 3. Up to three attempts: resolve every change against the `main` tip's tree (a path's
//!    existing spelling, post-state idempotence, `TargetExists` / `SourceMissing` /
//!    `TypeConflict`, the agent-territory and case-collision guards; MODULE-003 §1.4.1 items 1
//!    and 4, AC-36), then either answer `Unchanged` (no primary change differs from the tip; the
//!    index is still normalized for the touched paths) or write the planned blobs (filter-free;
//!    a `Disk` source is read once and must hash to its id, else `ContentChanged`), build the
//!    tree from the tip tree plus exactly these edits and land it (`lane::land`). A tip moved by
//!    a writer outside the queue is re-resolved; the third time is `GitError::HeadMoved`.
//!
//! So nothing is written into the object store before every guard has passed (oss-git §4.2), and
//! a refused request leaves no object behind.
//!
//! The label is rendered from the typed op (`label`), never from caller text.
//!
//! Panic-free: it runs while the coord mutex is held.

#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::arithmetic_side_effects
)]

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use git2::{ObjectType, Oid, Patch, Repository, Tree};

use crate::autoignore;
use crate::checkpoint::validate_ref_component;
use crate::commit_queue::branch_guard;
use crate::emit::EmitPlan;
use crate::error::{GitError, UserOpRefusal};
use crate::git_log::Swept;
use crate::label::{
    self, CommitLabel, CHANGE_ADDED, CHANGE_DELETED, CHANGE_MODIFIED, CHANGE_REPLACED,
    MAX_LABEL_PATHS, MAX_STAT_BYTES, OP_SAVE_VERSION,
};
use crate::lane::{
    entry_at, gitignore_rider, head_kind, holds_agent_territory, land, main_state, normalize_index,
    parent_of, refuse, CollisionGuard, HeadKind, Landed, Landing, LaneCtx, Spellings, StatFix,
    Touched, MAX_ATTEMPTS,
};
use crate::paths::{collision_fold, RepoPath};
use crate::safe_fs::{stream_blob, DiskEntry, OpenFile};
use crate::tree_edit::{self, EntryMode, TreeEdit};
use crate::user_lane::{
    signature_time_now, user_authorship, BlobSource, ChangeRole, ItemChange, ItemKind, ItemOutcome,
    NotVersioned, PathChange, RestoreSource, UserCommitOutcome, UserCommitRequest,
    UserCommitStatus, UserOpKind, MAX_USER_BYTES, USER_NAMESPACE,
};

/// One `commit_user` item's answer plus the events and logs the worker emits after L2.
pub(crate) struct UserItemResult {
    pub outcome: UserCommitOutcome,
    pub emit: EmitPlan,
    pub swept: Option<Swept>,
    pub refresh_repo: bool,
}

/// Run one `commit_user` item (see the module docs).
pub(crate) fn exec_commit_user(
    ctx: &LaneCtx<'_>,
    req: &UserCommitRequest,
) -> Result<UserItemResult, GitError> {
    validate(ctx, req)?;
    let restore = match &req.op {
        UserOpKind::Restore(source) => Some(restore_facts(ctx.repo, source)?),
        _ => None,
    };
    let (contents, mut unwritten) = plan_contents(ctx, req)?;
    let mut refresh_repo = false;
    let mut gitignore_dirty = false;
    for (change, content) in req.changes.iter().zip(contents.iter()) {
        if let (PathChange::Put { path, .. }, Some(Content::Blob { .. })) = (change, content) {
            let p = path.tree_spelling(ctx.facts.precompose);
            if autoignore::contains(ctx.repo, p)? && autoignore::shrink(ctx.repo, p)? {
                refresh_repo = true;
                gitignore_dirty = true;
            }
        }
    }
    let owned = if refresh_repo {
        Some(Repository::open(&ctx.workdir)?)
    } else {
        None
    };
    let ignore_repo = owned.as_ref().unwrap_or(ctx.repo);
    let initiator = req.actor.initiator();
    let mut moved: (Option<Oid>, Option<Oid>) = (None, None);
    let mut attempts = 0u32;
    for _ in 0..MAX_ATTEMPTS {
        attempts = attempts.saturating_add(1);
        branch_guard(ctx.repo)?;
        let (tip, base) = main_state(ctx.repo)?;
        let mut plan = resolve(ctx, req, &contents, base.as_ref(), ignore_repo)?;
        if gitignore_dirty || plan.gitignore_dirty {
            refresh_repo = true;
            stage_gitignore(ctx, &mut plan)?;
        }
        if !plan.primary_changed {
            let label = build_label(ctx.repo, &req.op, &plan.label_items, restore.as_ref())?;
            let subject = label::render_subject(&label).ok_or_else(op_shape)?;
            let head = normalize_index(ctx, &plan.touched, &plan.stats)?;
            let outcome = outcome(
                ctx,
                UserCommitStatus::Unchanged,
                None,
                head,
                subject,
                label,
                plan.items,
            );
            let emit = EmitPlan::user(
                UserCommitStatus::Unchanged,
                &initiator,
                &initiator,
                &outcome.label.op,
                &outcome.subject,
                None,
                req.correlation_id.as_deref(),
                &outcome.items,
            );
            let swept = if attempts > 1 {
                tip.map(|oid| Swept {
                    sha: oid.to_string(),
                    attempts,
                })
            } else {
                None
            };
            return Ok(UserItemResult {
                outcome,
                emit,
                swept,
                refresh_repo,
            });
        }
        store_contents(ctx, &mut unwritten)?;
        let label = build_label(ctx.repo, &req.op, &plan.label_items, restore.as_ref())?;
        let subject = label::render_subject(&label).ok_or_else(op_shape)?;
        gitignore_rider(ctx, base.as_ref(), &mut plan.edits, &mut plan.touched)?;
        let tree = tree_edit::build_tree(ctx.repo, base.as_ref(), &plan.edits)?;
        if base.as_ref().map(Tree::id) == Some(tree) {
            let head = normalize_index(ctx, &plan.touched, &plan.stats)?;
            let outcome = outcome(
                ctx,
                UserCommitStatus::Unchanged,
                None,
                head,
                subject,
                label,
                plan.items,
            );
            let emit = EmitPlan::user(
                UserCommitStatus::Unchanged,
                &initiator,
                &initiator,
                &outcome.label.op,
                &outcome.subject,
                None,
                req.correlation_id.as_deref(),
                &outcome.items,
            );
            return Ok(UserItemResult {
                outcome,
                emit,
                swept: None,
                refresh_repo,
            });
        }
        let message = label::render_message(&label, &initiator, req.provenance.as_ref())
            .ok_or_else(op_shape)?;
        let authorship = user_authorship(&req.actor, &signature_time_now())?;
        let landing = Landing {
            parent: tip,
            tree,
            message: &message,
            subject: &subject,
            authorship: &authorship,
            touched: &plan.touched,
            stats: &plan.stats,
        };
        match land(ctx, &landing)? {
            Landed::Committed(sha) => {
                let outcome = outcome(
                    ctx,
                    UserCommitStatus::Committed,
                    Some(sha),
                    Some(sha),
                    subject,
                    label,
                    plan.items,
                );
                let emit = EmitPlan::user(
                    UserCommitStatus::Committed,
                    &authorship.event_agent_id,
                    &authorship.initiator,
                    &outcome.label.op,
                    &outcome.subject,
                    Some(&sha.to_string()),
                    req.correlation_id.as_deref(),
                    &outcome.items,
                );
                return Ok(UserItemResult {
                    outcome,
                    emit,
                    swept: None,
                    refresh_repo,
                });
            }
            Landed::HeadMoved(now) => moved = (tip, now),
        }
    }
    Err(GitError::HeadMoved {
        expected: moved.0.map(|oid| oid.to_string()),
        actual: moved.1.map(|oid| oid.to_string()),
    })
}

fn op_shape() -> GitError {
    GitError::InvalidUserOp {
        reason: UserOpRefusal::OpShape,
        path: None,
    }
}

fn outcome(
    ctx: &LaneCtx<'_>,
    status: UserCommitStatus,
    sha: Option<Oid>,
    head: Option<Oid>,
    subject: String,
    label: CommitLabel,
    items: Vec<ItemOutcome>,
) -> UserCommitOutcome {
    UserCommitOutcome {
        status,
        sha: sha.map(|oid| oid.to_string()),
        head_sha: head.map(|oid| oid.to_string()),
        subject,
        label,
        items,
        max_tracked_bytes: ctx.max_tracked,
    }
}

// ── validation ────────────────────────────────────────────────────────────────────────

/// What a change does, for the shape rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Kind {
    Put,
    Remove,
    Move,
    Copy,
    RemoveTree,
    MoveTree,
    CopyTree,
}

fn kind_of(change: &PathChange) -> Kind {
    match change {
        PathChange::Put { .. } => Kind::Put,
        PathChange::Remove { .. } => Kind::Remove,
        PathChange::Move { .. } => Kind::Move,
        PathChange::Copy { .. } => Kind::Copy,
        PathChange::RemoveTree { .. } => Kind::RemoveTree,
        PathChange::MoveTree { .. } => Kind::MoveTree,
        PathChange::CopyTree { .. } => Kind::CopyTree,
    }
}

/// Primary changes are the user's own (labelled, counted); sidecars ride along.
fn is_primary(change: &PathChange) -> bool {
    match change {
        PathChange::Put { role, .. } | PathChange::Remove { role, .. } => {
            *role == ChangeRole::Primary
        }
        _ => true,
    }
}

/// A git object id as the lane accepts it: 40 hex digits.
pub(crate) fn is_oid(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn parse_oid(value: &str) -> Result<Oid, GitError> {
    if !is_oid(value) {
        return Err(op_shape());
    }
    Oid::from_str(value).map_err(|_| op_shape())
}

fn tree_path(ctx: &LaneCtx<'_>, path: &RepoPath) -> String {
    path.tree_spelling(ctx.facts.precompose).to_string()
}

fn validate(ctx: &LaneCtx<'_>, req: &UserCommitRequest) -> Result<(), GitError> {
    if req.changes.len() > ctx.limits.max_user_changes {
        return Err(GitError::InvalidUserOp {
            reason: UserOpRefusal::TooManyChanges,
            path: None,
        });
    }
    let mut bytes = 0usize;
    for change in &req.changes {
        if let PathChange::Put {
            content: BlobSource::Bytes(content),
            ..
        } = change
        {
            bytes = bytes.saturating_add(content.len());
        }
    }
    if bytes > MAX_USER_BYTES {
        return Err(GitError::InvalidUserOp {
            reason: UserOpRefusal::TooManyBytes,
            path: None,
        });
    }
    for change in &req.changes {
        check_change(ctx, &req.op, change)?;
    }
    check_op_shape(ctx, req)?;
    check_paths(ctx, req)
}

/// One change on its own: no vault-root operand, sidecar roles on sidecar paths only, a
/// primary marker only for `CreateFolder`, `Disk` content for `EditExternal`, well-formed oids.
fn check_change(ctx: &LaneCtx<'_>, op: &UserOpKind, change: &PathChange) -> Result<(), GitError> {
    let shape = |path: &RepoPath| refuse(UserOpRefusal::OpShape, &tree_path(ctx, path));
    let no_root = |path: &RepoPath| {
        if path.is_root() {
            Err(refuse(UserOpRefusal::InvalidPath, ""))
        } else {
            Ok(())
        }
    };
    match change {
        PathChange::Put {
            path,
            content,
            role,
            ..
        } => {
            no_root(path)?;
            let marker_op = matches!(op, UserOpKind::CreateFolder);
            let sidecar_ok = match role {
                ChangeRole::Sidecar => path.is_sidecar(),
                ChangeRole::Primary => path.is_sidecar() == marker_op,
            };
            if !sidecar_ok {
                return Err(shape(path));
            }
            match content {
                BlobSource::Disk { oid } => {
                    parse_oid(oid).map_err(|_| shape(path))?;
                }
                BlobSource::Bytes(_) => {
                    if *role == ChangeRole::Primary && matches!(op, UserOpKind::EditExternal) {
                        return Err(shape(path));
                    }
                }
            }
        }
        PathChange::Remove { path, role } => {
            no_root(path)?;
            if path.is_sidecar() != (*role == ChangeRole::Sidecar) {
                return Err(shape(path));
            }
        }
        PathChange::Move { from, to, oid }
        | PathChange::Copy { from, to, oid }
        | PathChange::MoveTree { from, to, oid }
        | PathChange::CopyTree { from, to, oid } => {
            no_root(from)?;
            no_root(to)?;
            if from.is_sidecar() || to.is_sidecar() {
                return Err(shape(from));
            }
            if let Some(oid) = oid {
                parse_oid(oid).map_err(|_| shape(from))?;
            }
        }
        PathChange::RemoveTree { dir } => {
            no_root(dir)?;
            if dir.is_sidecar() {
                return Err(shape(dir));
            }
        }
    }
    Ok(())
}

/// The `(from, to)` of a move or copy.
fn endpoints(change: &PathChange) -> Option<(&RepoPath, &RepoPath)> {
    match change {
        PathChange::Move { from, to, .. }
        | PathChange::Copy { from, to, .. }
        | PathChange::MoveTree { from, to, .. }
        | PathChange::CopyTree { from, to, .. } => Some((from, to)),
        _ => None,
    }
}

/// The op's primary changes (MODULE-003 §1.4.1): how many, of which kinds, and for rename,
/// move and copy one destination folder; `CreateFolder` markers form one chain of new levels.
fn check_op_shape(ctx: &LaneCtx<'_>, req: &UserCommitRequest) -> Result<(), GitError> {
    let primaries: Vec<&PathChange> = req.changes.iter().filter(|c| is_primary(c)).collect();
    let n = primaries.len();
    let only = |kinds: &[Kind]| primaries.iter().all(|c| kinds.contains(&kind_of(c)));
    let destinations: HashSet<String> = primaries
        .iter()
        .filter_map(|c| endpoints(c))
        .map(|(_, to)| parent_of(&tree_path(ctx, to)).to_string())
        .collect();
    let ok = match &req.op {
        UserOpKind::Edit | UserOpKind::Create => n == 1 && only(&[Kind::Put]),
        UserOpKind::CreateFolder => {
            n >= 1 && only(&[Kind::Put]) && is_marker_chain(ctx, &primaries)
        }
        UserOpKind::Rename => {
            n == 1
                && only(&[Kind::Move, Kind::MoveTree])
                && primaries
                    .iter()
                    .filter_map(|c| endpoints(c))
                    .all(|(from, to)| {
                        parent_of(&tree_path(ctx, from)) == parent_of(&tree_path(ctx, to))
                    })
        }
        UserOpKind::Move => {
            n >= 1 && only(&[Kind::Move, Kind::MoveTree]) && destinations.len() == 1
        }
        UserOpKind::Copy => {
            n >= 1 && only(&[Kind::Copy, Kind::CopyTree]) && destinations.len() == 1
        }
        UserOpKind::Delete => n >= 1 && only(&[Kind::Remove, Kind::RemoveTree]),
        UserOpKind::Restore(_) => n >= 1 && only(&[Kind::Put, Kind::Remove]),
        UserOpKind::Upload => n >= 1 && only(&[Kind::Put]),
        UserOpKind::EditExternal => n == 1 && only(&[Kind::Put, Kind::Remove]),
    };
    if ok {
        Ok(())
    } else {
        Err(op_shape())
    }
}

/// `CreateFolder` markers (`<level>/.meta.yaml`, MODULE-003 §1.4.1 `create-folder` row): the new
/// levels, each the parent of the next; none at the vault root.
fn is_marker_chain(ctx: &LaneCtx<'_>, primaries: &[&PathChange]) -> bool {
    let mut levels: Vec<String> = primaries
        .iter()
        .filter_map(|c| match c {
            PathChange::Put { path, .. } => Some(parent_of(&tree_path(ctx, path)).to_string()),
            _ => None,
        })
        .collect();
    levels.sort_by_key(|level| level.split('/').count());
    if levels.iter().any(String::is_empty) {
        return false;
    }
    levels
        .windows(2)
        .all(|pair| matches!(pair, [upper, lower] if parent_of(lower) == upper.as_str()))
}

/// How a request touches one tree path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Use {
    Write(Kind),
    /// Moved away (a `Move` / `MoveTree` source).
    Vacate(Kind),
    /// Read only (a `Copy` / `CopyTree` source).
    Read(Kind),
}

/// No tree path twice; no two paths folding equal under `core.ignorecase` (a move's own pair
/// excepted); nothing below a folder the request removes, moves or copies; nothing below a file
/// the request writes, except a `Put` below a removed file (the explicit file → folder form).
fn check_paths(ctx: &LaneCtx<'_>, req: &UserCommitRequest) -> Result<(), GitError> {
    let mut uses: Vec<(String, Use, usize)> = Vec::new();
    for (index, change) in req.changes.iter().enumerate() {
        let kind = kind_of(change);
        match change {
            PathChange::Put { path, .. } | PathChange::Remove { path, .. } => {
                uses.push((tree_path(ctx, path), Use::Write(kind), index));
            }
            PathChange::RemoveTree { dir } => {
                uses.push((tree_path(ctx, dir), Use::Write(kind), index))
            }
            PathChange::Move { from, to, .. } | PathChange::MoveTree { from, to, .. } => {
                uses.push((tree_path(ctx, from), Use::Vacate(kind), index));
                uses.push((tree_path(ctx, to), Use::Write(kind), index));
            }
            PathChange::Copy { from, to, .. } | PathChange::CopyTree { from, to, .. } => {
                uses.push((tree_path(ctx, from), Use::Read(kind), index));
                uses.push((tree_path(ctx, to), Use::Write(kind), index));
            }
        }
    }
    let mut by_path: HashMap<&str, Vec<(Use, usize)>> = HashMap::new();
    for (path, use_, index) in &uses {
        by_path
            .entry(path.as_str())
            .or_default()
            .push((*use_, *index));
    }
    for (path, list) in &by_path {
        let copy_sources_only = list.iter().all(|(use_, _)| matches!(use_, Use::Read(_)));
        let dir_to_file = list.len() == 2
            && list.iter().any(|(u, _)| *u == Use::Write(Kind::RemoveTree))
            && list.iter().any(|(u, _)| *u == Use::Write(Kind::Put));
        if list.len() > 1 && !copy_sources_only && !dir_to_file {
            return Err(refuse(UserOpRefusal::DuplicatePath, path));
        }
    }
    if ctx.facts.ignorecase {
        let mut folds: HashMap<String, (&str, usize)> = HashMap::new();
        for (path, use_, index) in &uses {
            if matches!(use_, Use::Read(_)) {
                continue;
            }
            match folds.get(&collision_fold(path)) {
                Some((other, other_index)) if *other != path.as_str() && *other_index != *index => {
                    return Err(refuse(UserOpRefusal::CaseCollision, path));
                }
                Some(_) => {}
                None => {
                    folds.insert(collision_fold(path), (path.as_str(), *index));
                }
            }
        }
    }
    // Folders whose contents the request carries as a whole, and files it writes.
    let mut folders: HashSet<&str> = HashSet::new();
    let mut files: HashMap<&str, Kind> = HashMap::new();
    for (path, use_, _) in &uses {
        match use_ {
            Use::Write(Kind::RemoveTree | Kind::MoveTree | Kind::CopyTree)
            | Use::Vacate(Kind::MoveTree)
            | Use::Read(Kind::CopyTree) => {
                folders.insert(path.as_str());
            }
            Use::Write(kind) | Use::Vacate(kind) => {
                files.insert(path.as_str(), *kind);
            }
            Use::Read(_) => {}
        }
    }
    for (path, use_, _) in &uses {
        for ancestor in crate::lane::ancestors(path) {
            if folders.contains(ancestor) {
                return Err(refuse(UserOpRefusal::NestedChange, path));
            }
            if let Some(kind) = files.get(ancestor) {
                let file_to_folder = *kind == Kind::Remove && *use_ == Use::Write(Kind::Put);
                if !file_to_folder {
                    return Err(refuse(UserOpRefusal::NestedChange, path));
                }
            }
        }
    }
    Ok(())
}

// ── content ───────────────────────────────────────────────────────────────────────────

/// A `Put`'s planned content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Content {
    /// Versioned as this blob (filter-free): hashed in memory, or a `Disk` source's claimed id.
    /// The object is written only once a commit needs it ([`store_contents`]).
    Blob { oid: Oid, size: u64 },
    /// Over the tracked-size threshold: saved on disk, not versioned, never stored.
    Oversize { size: u64 },
}

impl Content {
    fn size(self) -> u64 {
        match self {
            Content::Blob { size, .. } | Content::Oversize { size } => size,
        }
    }
}

/// A planned blob not yet written into the object store.
enum Unwritten<'r> {
    Bytes(&'r [u8]),
    /// A `Disk { oid }` source, opened (not read) when it was planned.
    Disk {
        path: &'r RepoPath,
        expected: &'r str,
        opened: OpenFile,
    },
}

/// Plan every `Put`'s content without writing an object: `Bytes` are hashed in memory; a
/// `Disk { oid }` source is opened once through `safe_fs` (a regular file reached without
/// symlinks, else `ContentChanged`) and planned at its claimed id, to be read and verified when
/// a commit needs it. Content over the threshold is neither hashed nor read.
fn plan_contents<'r>(
    ctx: &LaneCtx<'_>,
    req: &'r UserCommitRequest,
) -> Result<(Vec<Option<Content>>, Vec<Unwritten<'r>>), GitError> {
    let mut contents = Vec::with_capacity(req.changes.len());
    let mut unwritten = Vec::new();
    for change in &req.changes {
        let content = match change {
            PathChange::Put { path, content, .. } => Some(match content {
                BlobSource::Bytes(bytes) => {
                    let size = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
                    if size > ctx.max_tracked {
                        Content::Oversize { size }
                    } else {
                        unwritten.push(Unwritten::Bytes(bytes));
                        Content::Blob {
                            oid: Oid::hash_object(ObjectType::Blob, bytes)?,
                            size,
                        }
                    }
                }
                BlobSource::Disk { oid } => {
                    let DiskEntry::File(opened) = ctx.open(path.given())? else {
                        return Err(content_changed(path, oid, None));
                    };
                    let size = opened.len;
                    if size > ctx.max_tracked {
                        Content::Oversize { size }
                    } else {
                        let planned = parse_oid(oid)?;
                        unwritten.push(Unwritten::Disk {
                            path,
                            expected: oid,
                            opened,
                        });
                        Content::Blob { oid: planned, size }
                    }
                }
            }),
            _ => None,
        };
        contents.push(content);
    }
    Ok((contents, unwritten))
}

fn content_changed(path: &RepoPath, expected: &str, actual: Option<String>) -> GitError {
    GitError::ContentChanged {
        path: PathBuf::from(path.nfc()),
        expected: expected.to_string(),
        actual,
    }
}

/// Write the planned blobs (once per item; later attempts find none left). A `Disk` source is
/// read once through its descriptor and must hash to its claimed id (`ContentChanged`
/// otherwise, nothing visible).
fn store_contents(ctx: &LaneCtx<'_>, unwritten: &mut Vec<Unwritten<'_>>) -> Result<(), GitError> {
    for blob in unwritten.drain(..) {
        match blob {
            Unwritten::Bytes(bytes) => {
                ctx.repo.blob(bytes)?;
            }
            Unwritten::Disk {
                path,
                expected,
                mut opened,
            } => match stream_blob(ctx.repo, &mut opened) {
                Ok(oid) if oid.to_string().eq_ignore_ascii_case(expected) => {}
                Ok(oid) => return Err(content_changed(path, expected, Some(oid.to_string()))),
                Err(GitError::Io(e)) if e.kind() == std::io::ErrorKind::InvalidData => {
                    return Err(content_changed(path, expected, None))
                }
                Err(e) => return Err(e),
            },
        }
    }
    Ok(())
}

// ── resolution ────────────────────────────────────────────────────────────────────────

/// What one primary item contributes to the label.
#[derive(Debug, Clone)]
struct LabelItem {
    /// Tree path of the item (the destination for moves and copies).
    path: String,
    /// Tree path of the source (moves and copies).
    from: Option<String>,
    dir: bool,
    /// The parent tree's blob at `path` before the op.
    old: Option<Oid>,
    /// The blob after the op (versioned puts).
    new: Option<Oid>,
    size: Option<u64>,
    versioned: bool,
    change: ItemChange,
}

/// One attempt's resolution against a parent tree.
#[derive(Default)]
struct Plan {
    edits: Vec<TreeEdit>,
    /// A primary change differs from the parent tree (sidecar differences do not count).
    primary_changed: bool,
    items: Vec<ItemOutcome>,
    label_items: Vec<LabelItem>,
    touched: Touched,
    stats: Vec<StatFix>,
    gitignore_dirty: bool,
}

impl Plan {
    fn edit(&mut self, primary: bool, edit: TreeEdit) {
        self.primary_changed |= primary;
        self.edits.push(edit);
    }

    fn item(
        &mut self,
        path: &str,
        kind: ItemKind,
        change: ItemChange,
        oid: Option<Oid>,
        parent: Option<Oid>,
        not_versioned: Option<NotVersioned>,
        size: Option<u64>,
        from: Option<&str>,
    ) {
        self.items.push(ItemOutcome {
            path: path.to_string(),
            kind,
            change: change.clone(),
            oid: oid.map(|o| o.to_string()),
            parent_oid: parent.map(|o| o.to_string()),
            versioned: not_versioned.is_none(),
            versioned_reason: not_versioned,
            size,
        });
        self.label_items.push(LabelItem {
            path: path.to_string(),
            from: from.map(str::to_string),
            dir: kind == ItemKind::Dir,
            old: parent,
            new: oid,
            size,
            versioned: not_versioned.is_none(),
            change,
        });
    }
}

fn file_mode(kind: HeadKind) -> Option<EntryMode> {
    match kind {
        HeadKind::File { executable: true } => Some(EntryMode::Executable),
        HeadKind::File { executable: false } => Some(EntryMode::File),
        HeadKind::Link => Some(EntryMode::Link),
        HeadKind::Tree | HeadKind::Gitlink => None,
    }
}

fn ignored(repo: &Repository, path: &str) -> Result<bool, GitError> {
    Ok(repo.status_should_ignore(Path::new(path))?)
}

fn stage_gitignore(ctx: &LaneCtx<'_>, plan: &mut Plan) -> Result<(), GitError> {
    const GITIGNORE: &str = ".gitignore";
    let DiskEntry::File(mut opened) = ctx.open(GITIGNORE)? else {
        return Ok(());
    };
    if opened.len > ctx.max_tracked {
        return Ok(());
    }
    let Ok(oid) = stream_blob(ctx.repo, &mut opened) else {
        return Ok(());
    };
    plan.edits.retain(|edit| edit.path() != GITIGNORE);
    plan.edit(
        true,
        TreeEdit::Upsert {
            path: GITIGNORE.to_string(),
            oid,
            mode: EntryMode::File,
        },
    );
    plan.touched.file(GITIGNORE);
    Ok(())
}

/// Resolve every change against `base` (MODULE-003 §1.4.1 items 1 and 4). Every operand is
/// looked up, edited and reset at the spelling `base` holds for it (`lane::Spellings`).
fn resolve(
    ctx: &LaneCtx<'_>,
    req: &UserCommitRequest,
    contents: &[Option<Content>],
    base: Option<&Tree<'_>>,
    ignore_repo: &Repository,
) -> Result<Plan, GitError> {
    let repo = ctx.repo;
    let mut plan = Plan::default();
    let mut guard = CollisionGuard::default();
    let mut spellings = Spellings::default();
    let mut spell = |path: &RepoPath| spellings.resolve(ctx, base, &tree_path(ctx, path));
    let mut removed_trees: HashSet<String> = HashSet::new();
    let mut vacated: HashSet<String> = HashSet::new();
    for change in &req.changes {
        match change {
            PathChange::RemoveTree { dir } => {
                removed_trees.insert(spell(dir)?);
            }
            PathChange::Move { from, .. } | PathChange::MoveTree { from, .. } => {
                vacated.insert(spell(from)?);
            }
            _ => {}
        }
    }
    let mut new_path = |plan_base: Option<&Tree<'_>>, path: &str| -> Result<(), GitError> {
        if ctx.facts.ignorecase {
            guard.check(repo, plan_base, path, &vacated)?;
        }
        Ok(())
    };
    let limit = ctx.limits.max_restore_paths;
    // `create` and `create-folder` make their primary paths: a path the parent tree holds
    // already is refused unless it holds exactly this content (post-state idempotence).
    let creates = matches!(req.op, UserOpKind::Create | UserOpKind::CreateFolder);
    for (change, content) in req.changes.iter().zip(contents) {
        let primary = is_primary(change);
        match change {
            PathChange::Put {
                path,
                executable,
                stat,
                ..
            } => {
                let p = spell(path)?;
                let content = content.ok_or_else(op_shape)?;
                let existing = match entry_at(base, &p)? {
                    None => None,
                    Some(entry) => match head_kind(&entry) {
                        HeadKind::Tree if removed_trees.contains(&p) => None,
                        HeadKind::Tree | HeadKind::Gitlink => {
                            return Err(refuse(UserOpRefusal::TypeConflict, &p))
                        }
                        HeadKind::Link => return Err(refuse(UserOpRefusal::Symlink, &p)),
                        HeadKind::File { executable } => Some((entry.id(), executable)),
                    },
                };
                let exec = executable.unwrap_or_else(|| existing.is_some_and(|(_, x)| x));
                if primary && creates && existing.is_some() {
                    let same = matches!(content, Content::Blob { oid, .. }
                        if existing == Some((oid, exec)));
                    if !same {
                        return Err(refuse(UserOpRefusal::TargetExists, &p));
                    }
                }
                if existing.is_none() {
                    new_path(base, &p)?;
                }
                let fresh = if existing.is_some() {
                    ItemChange::Modified
                } else {
                    ItemChange::Added
                };
                let (change, oid, not_versioned) = match content {
                    Content::Oversize { .. } => {
                        // Saved but not versioned; a tracked file leaves the tree (MODULE-003
                        // §1.4.1 "Threshold"). The `.gitignore` auto-entry and registry ride
                        // in this commit as a primary change.
                        if existing.is_some() {
                            plan.edit(primary, TreeEdit::Remove { path: p.clone() });
                        }
                        if autoignore::append(ctx.repo, Path::new(&p))? {
                            plan.gitignore_dirty = true;
                        }
                        (fresh, None, Some(NotVersioned::TooLarge))
                    }
                    Content::Blob { oid, .. } => {
                        if existing.is_none() && ignored(ignore_repo, &p)? {
                            (fresh, None, Some(NotVersioned::Ignored))
                        } else if existing == Some((oid, exec)) {
                            (ItemChange::Unchanged, Some(oid), None)
                        } else {
                            let mode = if exec {
                                EntryMode::Executable
                            } else {
                                EntryMode::File
                            };
                            plan.edit(
                                primary,
                                TreeEdit::Upsert {
                                    path: p.clone(),
                                    oid,
                                    mode,
                                },
                            );
                            (fresh, Some(oid), None)
                        }
                    }
                };
                if let (Some(oid), Some(stat)) = (oid, stat) {
                    plan.stats.push(StatFix {
                        tree_path: p.clone(),
                        disk_path: path.given().to_string(),
                        oid,
                        stat: *stat,
                    });
                }
                plan.touched.file(&p);
                if primary {
                    // A `CreateFolder` marker reports its folder (MODULE-003 §1.4.1, X20).
                    let (item_path, kind) = if matches!(req.op, UserOpKind::CreateFolder) {
                        (parent_of(&p), ItemKind::Dir)
                    } else {
                        (p.as_str(), ItemKind::File)
                    };
                    plan.item(
                        item_path,
                        kind,
                        change,
                        oid,
                        existing.map(|(o, _)| o),
                        not_versioned,
                        Some(content.size()),
                        None,
                    );
                }
            }
            PathChange::Remove { path, .. } => {
                let p = spell(path)?;
                let (change, parent, not_versioned) = match entry_at(base, &p)? {
                    Some(entry) => match head_kind(&entry) {
                        HeadKind::File { .. } | HeadKind::Link => {
                            plan.edit(primary, TreeEdit::Remove { path: p.clone() });
                            (ItemChange::Deleted, Some(entry.id()), None)
                        }
                        HeadKind::Tree | HeadKind::Gitlink => {
                            return Err(refuse(UserOpRefusal::TypeConflict, &p))
                        }
                    },
                    None => {
                        let reason = if ignored(ignore_repo, &p)? {
                            NotVersioned::Ignored
                        } else {
                            NotVersioned::Untracked
                        };
                        (ItemChange::Deleted, None, Some(reason))
                    }
                };
                if autoignore::drop_exact(ctx.repo, &p)? {
                    plan.gitignore_dirty = true;
                }
                plan.touched.file(&p);
                if primary {
                    plan.item(
                        &p,
                        ItemKind::File,
                        change,
                        None,
                        parent,
                        not_versioned,
                        None,
                        None,
                    );
                }
            }
            PathChange::Move { from, to, oid } | PathChange::Copy { from, to, oid } => {
                let moving = matches!(change, PathChange::Move { .. });
                let (f, t) = (spell(from)?, spell(to)?);
                let want = oid.as_deref().map(parse_oid).transpose()?;
                let source = entry_at(base, &f)?;
                let target = entry_at(base, &t)?;
                let applied = if moving {
                    ItemChange::Renamed { from: f.clone() }
                } else {
                    ItemChange::Added
                };
                let source_gone = source.is_none();
                let (change, new, parent, not_versioned) = match (source, target) {
                    (_, Some(target))
                        if want == Some(target.id())
                            && (!moving || source_gone)
                            && file_mode(head_kind(&target)).is_some() =>
                    {
                        // Already applied (post-state idempotence).
                        (ItemChange::Unchanged, Some(target.id()), None, None)
                    }
                    (Some(source), None) => {
                        let Some(mode) = file_mode(head_kind(&source)) else {
                            return Err(refuse(UserOpRefusal::TypeConflict, &f));
                        };
                        if want.is_some_and(|w| w != source.id()) {
                            return Err(refuse(UserOpRefusal::SourceMissing, &f));
                        }
                        new_path(base, &t)?;
                        if moving {
                            plan.edit(true, TreeEdit::Remove { path: f.clone() });
                        }
                        plan.edit(
                            true,
                            TreeEdit::Upsert {
                                path: t.clone(),
                                oid: source.id(),
                                mode,
                            },
                        );
                        (applied, Some(source.id()), Some(source.id()), None)
                    }
                    (None, None) if want.is_none() => {
                        // Untracked content moved or copied on disk only (R1).
                        (applied, None, None, Some(NotVersioned::Untracked))
                    }
                    (_, Some(_)) => return Err(refuse(UserOpRefusal::TargetExists, &t)),
                    (None, None) => return Err(refuse(UserOpRefusal::SourceMissing, &f)),
                };
                if moving {
                    if autoignore::rewrite_move(ctx.repo, &f, &t, false)? {
                        plan.gitignore_dirty = true;
                    }
                    plan.touched.file(&f);
                }
                plan.touched.file(&t);
                plan.item(
                    &t,
                    ItemKind::File,
                    change,
                    new,
                    parent,
                    not_versioned,
                    None,
                    Some(&f),
                );
            }
            PathChange::RemoveTree { dir } => {
                let d = spell(dir)?;
                let (change, not_versioned) = match entry_at(base, &d)? {
                    Some(entry) if head_kind(&entry) == HeadKind::Tree => {
                        if holds_agent_territory(repo, entry.id(), limit, &d)? {
                            return Err(refuse(UserOpRefusal::AgentTerritory, &d));
                        }
                        plan.edit(true, TreeEdit::Remove { path: d.clone() });
                        (ItemChange::Deleted, None)
                    }
                    Some(_) => return Err(refuse(UserOpRefusal::TypeConflict, &d)),
                    None => (ItemChange::Deleted, Some(NotVersioned::Untracked)),
                };
                if autoignore::drop_tree(ctx.repo, &d)? {
                    plan.gitignore_dirty = true;
                }
                plan.touched.dir(&d);
                plan.item(
                    &d,
                    ItemKind::Dir,
                    change,
                    None,
                    None,
                    not_versioned,
                    None,
                    None,
                );
            }
            PathChange::MoveTree { from, to, oid } | PathChange::CopyTree { from, to, oid } => {
                let moving = matches!(change, PathChange::MoveTree { .. });
                let (f, t) = (spell(from)?, spell(to)?);
                let want = oid.as_deref().map(parse_oid).transpose()?;
                let source = entry_at(base, &f)?;
                let target = entry_at(base, &t)?;
                let applied = if moving {
                    ItemChange::Renamed { from: f.clone() }
                } else {
                    ItemChange::Added
                };
                let (change, not_versioned) = match (source, target) {
                    (source, Some(target))
                        if want == Some(target.id())
                            && head_kind(&target) == HeadKind::Tree
                            && (!moving || source.is_none()) =>
                    {
                        (ItemChange::Unchanged, None)
                    }
                    (Some(source), None) => {
                        if head_kind(&source) != HeadKind::Tree {
                            return Err(refuse(UserOpRefusal::TypeConflict, &f));
                        }
                        if want.is_some_and(|w| w != source.id()) {
                            return Err(refuse(UserOpRefusal::SourceMissing, &f));
                        }
                        if holds_agent_territory(repo, source.id(), limit, &f)? {
                            return Err(refuse(UserOpRefusal::AgentTerritory, &f));
                        }
                        new_path(base, &t)?;
                        if moving {
                            plan.edit(true, TreeEdit::Remove { path: f.clone() });
                        }
                        plan.edit(
                            true,
                            TreeEdit::Upsert {
                                path: t.clone(),
                                oid: source.id(),
                                mode: EntryMode::Tree,
                            },
                        );
                        (applied, None)
                    }
                    (None, None) if want.is_none() => (applied, Some(NotVersioned::Untracked)),
                    (_, Some(_)) => return Err(refuse(UserOpRefusal::TargetExists, &t)),
                    (None, None) => return Err(refuse(UserOpRefusal::SourceMissing, &f)),
                };
                if moving {
                    if autoignore::rewrite_move(ctx.repo, &f, &t, true)? {
                        plan.gitignore_dirty = true;
                    }
                    plan.touched.dir(&f);
                }
                plan.touched.dir(&t);
                plan.item(
                    &t,
                    ItemKind::Dir,
                    change,
                    None,
                    None,
                    not_versioned,
                    None,
                    Some(&f),
                );
            }
        }
    }
    Ok(plan)
}

// ── labels ────────────────────────────────────────────────────────────────────────────

fn display(path: &str, dir: bool) -> String {
    if dir {
        format!("{path}/")
    } else {
        path.to_string()
    }
}

/// The folder a path sits in, as labels show it (`/` for the vault root).
fn folder_display(path: &str) -> String {
    match parent_of(path) {
        "" => "/".to_string(),
        dir => format!("{dir}/"),
    }
}

/// The deepest folder every path sits in, as labels show it.
fn common_folder(paths: &[&str]) -> String {
    let mut common: Option<Vec<&str>> = None;
    for path in paths {
        let parts: Vec<&str> = parent_of(path)
            .split('/')
            .filter(|p| !p.is_empty())
            .collect();
        common = Some(match common {
            None => parts,
            Some(prefix) => prefix
                .iter()
                .zip(&parts)
                .take_while(|(a, b)| a == b)
                .map(|(a, _)| *a)
                .collect(),
        });
    }
    match common {
        Some(parts) if !parts.is_empty() => format!("{}/", parts.join("/")),
        _ => "/".to_string(),
    }
}

/// `(+a, −d)` of a text change; `None` when a side is binary or over `MAX_STAT_BYTES`
/// (the size is shown instead).
fn line_stat(
    repo: &Repository,
    old: Option<Oid>,
    new: Oid,
) -> Result<Option<(u64, u64)>, GitError> {
    let fits = |blob: &git2::Blob<'_>| {
        u64::try_from(blob.size()).is_ok_and(|size| size <= MAX_STAT_BYTES) && !blob.is_binary()
    };
    let new_blob = repo.find_blob(new)?;
    if !fits(&new_blob) {
        return Ok(None);
    }
    let patch = match old {
        Some(old) => {
            let old_blob = repo.find_blob(old)?;
            if !fits(&old_blob) {
                return Ok(None);
            }
            Patch::from_blobs(&old_blob, None, &new_blob, None, None)?
        }
        None => Patch::from_buffers(&[], None, new_blob.content(), None, None)?,
    };
    let (_, added, removed) = patch.line_stats()?;
    Ok(Some((
        u64::try_from(added).unwrap_or(u64::MAX),
        u64::try_from(removed).unwrap_or(u64::MAX),
    )))
}

/// The commit a restore reads from, and how its label names it.
pub(crate) struct RestoreFacts {
    pub from_sha: String,
    pub title: Option<String>,
    pub checkpoint: Option<String>,
}

fn unknown_source() -> GitError {
    GitError::InvalidUserOp {
        reason: UserOpRefusal::UnknownRestoreSource,
        path: None,
    }
}

/// A checkpoint ref component (the Client API grammar plus git's ref rules).
fn is_ref_component(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        && validate_ref_component(value, "restore source").is_ok()
}

/// The commit a tag peels to; `None` when the tag does not exist or names no commit.
fn tag_commit<'r>(repo: &'r Repository, name: &str) -> Result<Option<git2::Commit<'r>>, GitError> {
    match repo.find_reference(name) {
        Ok(reference) => Ok(reference.peel_to_commit().ok()),
        Err(e) if e.code() == git2::ErrorCode::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Resolve a restore source (MODULE-003 §1.4.1): an existing commit (a user-version marker
/// lends its title), a user version (a `checkpoint/user/<label>` tag whose commit carries the
/// lane's signatures and `op: save-version`), or an agent checkpoint (`user` is reserved).
pub(crate) fn restore_facts(
    repo: &Repository,
    source: &RestoreSource,
) -> Result<RestoreFacts, GitError> {
    match source {
        RestoreSource::Commit(sha) => {
            let oid = parse_oid(sha).map_err(|_| unknown_source())?;
            let commit = match repo.find_commit(oid) {
                Ok(commit) => commit,
                Err(e) if e.code() == git2::ErrorCode::NotFound => return Err(unknown_source()),
                Err(e) => return Err(e.into()),
            };
            let (title, checkpoint) = match label::label_of(&commit) {
                Some(marker) if marker.op == OP_SAVE_VERSION => (marker.title, marker.checkpoint),
                _ => (None, None),
            };
            Ok(RestoreFacts {
                from_sha: commit.id().to_string(),
                title,
                checkpoint,
            })
        }
        RestoreSource::Version(name) => {
            if !is_ref_component(name) {
                return Err(unknown_source());
            }
            let tag = format!("refs/tags/checkpoint/{USER_NAMESPACE}/{name}");
            let commit = tag_commit(repo, &tag)?.ok_or_else(unknown_source)?;
            match label::label_of(&commit) {
                Some(marker) if marker.op == OP_SAVE_VERSION => Ok(RestoreFacts {
                    from_sha: commit.id().to_string(),
                    title: marker.title,
                    checkpoint: Some(format!("{USER_NAMESPACE}/{name}")),
                }),
                _ => Err(GitError::InvalidUserOp {
                    reason: UserOpRefusal::NotAUserVersion,
                    path: None,
                }),
            }
        }
        RestoreSource::Checkpoint { agent_id, label } => {
            if agent_id.eq_ignore_ascii_case(USER_NAMESPACE) {
                return Err(GitError::InvalidUserOp {
                    reason: UserOpRefusal::ReservedNamespace,
                    path: None,
                });
            }
            if !is_ref_component(agent_id) || !is_ref_component(label) {
                return Err(unknown_source());
            }
            let tag = format!("refs/tags/checkpoint/{agent_id}/{label}");
            let commit = tag_commit(repo, &tag)?.ok_or_else(unknown_source)?;
            Ok(RestoreFacts {
                from_sha: commit.id().to_string(),
                title: None,
                checkpoint: Some(format!("{agent_id}/{label}")),
            })
        }
    }
}

/// The structured label of a user op (MODULE-003 §1.4.1 "Labels"; field conventions on
/// `CommitLabel`).
fn build_label(
    repo: &Repository,
    op: &UserOpKind,
    items: &[LabelItem],
    restore: Option<&RestoreFacts>,
) -> Result<CommitLabel, GitError> {
    let count = u32::try_from(items.len()).unwrap_or(u32::MAX);
    let mut label = CommitLabel {
        op: op.as_token().to_string(),
        count,
        ..CommitLabel::default()
    };
    let paths = |pick: &dyn Fn(&LabelItem) -> String| -> Vec<String> {
        items.iter().take(MAX_LABEL_PATHS).map(pick).collect()
    };
    let own = |item: &LabelItem| display(&item.path, item.dir);
    let source = |item: &LabelItem| display(item.from.as_deref().unwrap_or(&item.path), item.dir);
    let first = items.first();
    let not_versioned = |label: &mut CommitLabel, item: &LabelItem| {
        label.size_bytes = item.size;
        label.versioned = Some(false);
    };
    match op {
        UserOpKind::Edit => {
            label.paths = paths(&own);
            if let Some(item) = first {
                match item.new {
                    Some(new) if item.versioned => match line_stat(repo, item.old, new)? {
                        Some((added, removed)) => {
                            label.lines_added = Some(added);
                            label.lines_removed = Some(removed);
                        }
                        None => label.size_bytes = item.size,
                    },
                    _ => not_versioned(&mut label, item),
                }
            }
        }
        UserOpKind::Create => {
            label.paths = paths(&own);
            if let Some(item) = first.filter(|item| !item.versioned) {
                not_versioned(&mut label, item);
            }
        }
        UserOpKind::CreateFolder => {
            let deepest = items
                .iter()
                .max_by_key(|item| item.path.split('/').count())
                .map(own);
            label.paths = deepest.into_iter().collect();
        }
        UserOpKind::Rename => {
            label.paths = paths(&source);
            label.to = first.map(own);
        }
        UserOpKind::Move => {
            label.paths = paths(&source);
            label.to = first.map(|item| folder_display(&item.path));
        }
        UserOpKind::Copy => {
            label.paths = paths(&source);
            label.to = match items {
                [item] => Some(own(item)),
                _ => first.map(|item| folder_display(&item.path)),
            };
            label.change = Some(CHANGE_ADDED.to_string());
        }
        UserOpKind::Delete => label.paths = paths(&own),
        UserOpKind::Restore(_) => {
            label.paths = paths(&own);
            if let Some(facts) = restore {
                label.from_sha = Some(facts.from_sha.clone());
                label.title = facts.title.clone();
                label.checkpoint = facts.checkpoint.clone();
            }
            if let [item] = items {
                if !item.dir {
                    label.change = Some(
                        match item.change {
                            ItemChange::Deleted => CHANGE_DELETED,
                            ItemChange::Added => CHANGE_ADDED,
                            _ => CHANGE_MODIFIED,
                        }
                        .to_string(),
                    );
                }
            }
        }
        UserOpKind::Upload => {
            label.paths = paths(&own);
            match items {
                [item] => {
                    label.size_bytes = item.size;
                    let replaced = item.old.is_some();
                    label.change = Some(
                        if replaced {
                            CHANGE_REPLACED
                        } else {
                            CHANGE_ADDED
                        }
                        .to_string(),
                    );
                    if !item.versioned {
                        label.versioned = Some(false);
                    }
                }
                _ => {
                    let all: Vec<&str> = items.iter().map(|item| item.path.as_str()).collect();
                    label.to = Some(common_folder(&all));
                    label.size_bytes = Some(
                        items
                            .iter()
                            .fold(0u64, |sum, item| sum.saturating_add(item.size.unwrap_or(0))),
                    );
                    label.change = Some(CHANGE_ADDED.to_string());
                }
            }
        }
        UserOpKind::EditExternal => {
            label.paths = paths(&own);
            if let Some(item) = first {
                if item.change == ItemChange::Deleted {
                    label.change = Some(CHANGE_DELETED.to_string());
                } else {
                    let added = item.old.is_none();
                    label.change =
                        Some(if added { CHANGE_ADDED } else { CHANGE_MODIFIED }.to_string());
                    match item.new {
                        Some(new) if item.versioned && !added => {
                            match line_stat(repo, item.old, new)? {
                                Some((plus, minus)) => {
                                    label.lines_added = Some(plus);
                                    label.lines_removed = Some(minus);
                                }
                                None => label.size_bytes = item.size,
                            }
                        }
                        _ if item.versioned => label.size_bytes = item.size,
                        _ => not_versioned(&mut label, item),
                    }
                }
            }
        }
    }
    Ok(label)
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
    use crate::config::GitConfigSnapshot;
    use crate::lane::LaneOverrides;
    use crate::user_lane::UserActor;
    use std::sync::Mutex;
    use tempfile::TempDir;

    fn path(p: &str) -> RepoPath {
        RepoPath::parse(p).unwrap()
    }

    fn put(p: &str, bytes: &[u8]) -> PathChange {
        PathChange::Put {
            path: path(p),
            content: BlobSource::Bytes(bytes.to_vec()),
            role: ChangeRole::Primary,
            executable: None,
            stat: None,
        }
    }

    fn request(op: UserOpKind, changes: Vec<PathChange>) -> UserCommitRequest {
        UserCommitRequest {
            actor: UserActor::from_principal_id("advance"),
            op,
            changes,
            correlation_id: None,
            provenance: None,
        }
    }

    fn refusal(result: Result<(), GitError>) -> UserOpRefusal {
        match result {
            Err(GitError::InvalidUserOp { reason, .. }) => reason,
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    // MODULE-003-AC-27 / AC-36: the request grammar is enforced before any object is written.
    #[test]
    fn request_validation_refusals() {
        let td = TempDir::new().unwrap();
        let repo = Repository::init(td.path()).unwrap();
        repo.config()
            .unwrap()
            .set_bool("core.ignorecase", true)
            .unwrap();
        let overrides = Mutex::new(LaneOverrides {
            max_user_changes: Some(3),
            ..LaneOverrides::default()
        });
        let ctx = LaneCtx::new(&repo, &GitConfigSnapshot::DEFAULTS, &overrides).unwrap();
        let check =
            |op: UserOpKind, changes: Vec<PathChange>| validate(&ctx, &request(op, changes));

        assert!(check(UserOpKind::Edit, vec![put("a.md", b"x")]).is_ok());
        // Shape: counts and kinds per op.
        assert_eq!(
            refusal(check(UserOpKind::Edit, vec![])),
            UserOpRefusal::OpShape
        );
        assert_eq!(
            refusal(check(
                UserOpKind::Edit,
                vec![put("a.md", b"x"), put("b.md", b"y")]
            )),
            UserOpRefusal::OpShape
        );
        assert_eq!(
            refusal(check(UserOpKind::Delete, vec![put("a.md", b"x")])),
            UserOpRefusal::OpShape
        );
        // A primary `.meta.yaml` only as a CreateFolder marker; markers form one chain.
        let marker = |p: &str| PathChange::Put {
            path: RepoPath::parse_sidecar(p).unwrap(),
            content: BlobSource::Bytes(b"m".to_vec()),
            role: ChangeRole::Primary,
            executable: None,
            stat: None,
        };
        assert!(check(
            UserOpKind::CreateFolder,
            vec![marker("a/.meta.yaml"), marker("a/b/.meta.yaml")]
        )
        .is_ok());
        assert_eq!(
            refusal(check(
                UserOpKind::CreateFolder,
                vec![marker("a/.meta.yaml"), marker("c/b/.meta.yaml")]
            )),
            UserOpRefusal::OpShape
        );
        assert_eq!(
            refusal(check(UserOpKind::Edit, vec![marker("a/.meta.yaml")])),
            UserOpRefusal::OpShape
        );
        // EditExternal takes disk content only.
        assert_eq!(
            refusal(check(UserOpKind::EditExternal, vec![put("a.md", b"x")])),
            UserOpRefusal::OpShape
        );
        // Malformed oids.
        let moved = |from: &str, to: &str, oid: Option<&str>| PathChange::Move {
            from: path(from),
            to: path(to),
            oid: oid.map(str::to_string),
        };
        assert_eq!(
            refusal(check(
                UserOpKind::Rename,
                vec![moved("a.md", "b.md", Some("xyz"))]
            )),
            UserOpRefusal::OpShape
        );
        // Rename keeps the parent; move has one destination folder.
        assert_eq!(
            refusal(check(
                UserOpKind::Rename,
                vec![moved("a.md", "d/b.md", None)]
            )),
            UserOpRefusal::OpShape
        );
        assert_eq!(
            refusal(check(
                UserOpKind::Move,
                vec![moved("a.md", "d/a.md", None), moved("b.md", "e/b.md", None)]
            )),
            UserOpRefusal::OpShape
        );
        // Bounds.
        assert_eq!(
            refusal(check(
                UserOpKind::Upload,
                vec![put("a", b""), put("b", b""), put("c", b""), put("d", b"")]
            )),
            UserOpRefusal::TooManyChanges
        );
        let big = vec![0u8; MAX_USER_BYTES / 2 + 1];
        assert_eq!(
            refusal(check(
                UserOpKind::Upload,
                vec![put("a", &big), put("b", &big)]
            )),
            UserOpRefusal::TooManyBytes
        );
        // Duplicates, folds and nesting.
        assert_eq!(
            refusal(check(
                UserOpKind::Upload,
                vec![put("a.md", b"x"), put("a.md", b"y")]
            )),
            UserOpRefusal::DuplicatePath
        );
        assert_eq!(
            refusal(check(
                UserOpKind::Upload,
                vec![put("a.md", b"x"), put("A.md", b"y")]
            )),
            UserOpRefusal::CaseCollision
        );
        assert!(check(UserOpKind::Rename, vec![moved("a.md", "A.md", None)]).is_ok());
        assert_eq!(
            refusal(check(
                UserOpKind::Delete,
                vec![
                    PathChange::RemoveTree { dir: path("d") },
                    PathChange::Remove {
                        path: path("d/x.md"),
                        role: ChangeRole::Primary
                    },
                ]
            )),
            UserOpRefusal::NestedChange
        );
        assert_eq!(
            refusal(check(
                UserOpKind::Upload,
                vec![put("a.md", b"x"), put("a.md/x", b"y")]
            )),
            UserOpRefusal::NestedChange
        );
        // The explicit file → folder form is allowed.
        assert!(check(
            UserOpKind::Restore(RestoreSource::Commit("a".repeat(40))),
            vec![
                PathChange::Remove {
                    path: path("a.md"),
                    role: ChangeRole::Primary
                },
                put("a.md/x", b"y"),
            ]
        )
        .is_ok());
        // A vault-root operand is never a change.
        assert_eq!(
            refusal(check(
                UserOpKind::Delete,
                vec![PathChange::RemoveTree {
                    dir: RepoPath::root()
                }]
            )),
            UserOpRefusal::InvalidPath
        );
    }

    #[test]
    fn label_folders() {
        assert_eq!(folder_display("a.md"), "/");
        assert_eq!(folder_display("archive/a.md"), "archive/");
        assert_eq!(common_folder(&["r/a.pdf", "r/b.pdf", "r/c/d.pdf"]), "r/");
        assert_eq!(common_folder(&["a.pdf", "r/b.pdf"]), "/");
        assert!(is_oid(&"a".repeat(40)));
        assert!(!is_oid("abc"));
    }
}

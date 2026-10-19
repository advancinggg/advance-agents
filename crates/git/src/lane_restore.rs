//! `restore_tree`: plan from trees → validate `MAX_RESTORE_PATHS` → adopt →
//! one forward restore commit (ADR 2026-10-15, CONTRACT-247; MODULE-003-AC-32,
//! AC-37).
//!
//! The plan is validated before any disk write or adopt (T57). Adoption of
//! dirty plan paths happens after that. The restore commit is attributed to
//! the operator; a Checkpoint source also emits `git.rollback` with
//! `initiator user:<h>`.
//!
//! Panic-free: it runs while the coord mutex is held.

#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::arithmetic_side_effects
)]

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::{Path, PathBuf};

use git2::{ObjectType, Oid, Repository, Tree};

use crate::checkpoint::parse_tag_message;
use crate::commit_queue::branch_guard;
use crate::emit::{EmitPlan, RestoreRollback};
use crate::error::{GitError, RollbackError, UserOpRefusal};
use crate::label::{self, CommitLabel, OP_RESTORE};
use crate::lane::{
    entry_at, head_kind, main_state, normalize_index, publish, refuse, HeadKind, Landed, Landing,
    LaneCtx, Spellings, Touched, MAX_ATTEMPTS,
};
use crate::lane_commit::restore_facts;
use crate::lane_prepare;
use crate::paths::RepoPath;
use crate::rollback::{
    apply_rollback, is_excluded_from_writable_domain, plan_rollback, resolve_checkpoint,
    RestorePlanSummary, RollbackMode, RollbackPlan, RollbackTarget,
};
use crate::tree_edit::{self, EntryMode, TreeEdit};
use crate::user_lane::{
    signature_time_now, user_authorship, RestoreOutcome, RestoreScope, RestoreSource,
    RestoreTreeRequest, UserCommitStatus, USER_NAMESPACE,
};

const MAX_LISTED: usize = 64;
const ROOT_GITIGNORE: &str = ".gitignore";

/// One `restore_tree` item's answer plus the events the worker emits after L2.
pub(crate) struct RestoreItemResult {
    pub outcome: RestoreOutcome,
    pub emit: Vec<EmitPlan>,
    pub refresh_repo: bool,
}

struct PlannedFile {
    path: String,
    oid: Oid,
    mode: EntryMode,
}

struct Planned {
    facts: crate::lane_commit::RestoreFacts,
    checkout: Vec<PlannedFile>,
    removals: Vec<String>,
    shape_prefixes: Vec<String>,
    apply: RollbackPlan,
    /// Checkpoint source: `(agent_id, label)` for `git.rollback`.
    checkpoint: Option<(String, String)>,
}

impl Planned {
    fn path_count(&self) -> usize {
        self.checkout.len().saturating_add(self.removals.len())
    }

    fn blob_bytes(&self, repo: &Repository) -> u64 {
        let mut total = 0u64;
        for file in &self.checkout {
            if let Ok(blob) = repo.find_blob(file.oid) {
                total = total.saturating_add(u64::try_from(blob.size()).unwrap_or(u64::MAX));
            }
        }
        total
    }

    fn summary(&self, repo: &Repository) -> RestorePlanSummary {
        RestorePlanSummary {
            path_count: self.path_count(),
            blob_bytes: self.blob_bytes(repo),
        }
    }

    fn adopt_paths(&self) -> Vec<String> {
        let mut paths: Vec<String> = self.checkout.iter().map(|f| f.path.clone()).collect();
        paths.extend(self.removals.iter().cloned());
        paths.extend(self.shape_prefixes.iter().cloned());
        paths.sort();
        paths.dedup();
        paths
    }
}

fn vault_apply_plan(
    ctx: &LaneCtx<'_>,
    target_oid: Oid,
    checkout: &[PlannedFile],
    removals: &[String],
) -> Result<RollbackPlan, GitError> {
    let canonical = std::fs::canonicalize(&ctx.workdir)?;
    Ok(RollbackPlan {
        target_oid,
        checkout_paths: checkout.iter().map(|f| PathBuf::from(&f.path)).collect(),
        removal_paths: removals.iter().map(PathBuf::from).collect(),
        workdir: canonical.clone(),
        agent_root_abs: canonical,
        agent_root_rel: String::new(),
        child_territories_rel: Vec::new(),
        ignorecase: ctx.facts.ignorecase,
    })
}

/// Tree-read plan totals (no disk). Used by [`DefaultWorkspaceRollback::plan_restore`].
pub(crate) fn summarize_restore(
    repo: &Repository,
    canonical: &Path,
    req: &RestoreTreeRequest,
) -> Result<RestorePlanSummary, GitError> {
    let snapshot = crate::config::GitConfigProvider::snapshot(
        &crate::config::StaticGitConfigProvider::defaults(),
    );
    let overrides = std::sync::Mutex::new(crate::lane::LaneOverrides::default());
    let ctx = LaneCtx::new(repo, &snapshot, &overrides)?;
    let planned = build_plan(&ctx, canonical, req)?;
    Ok(planned.summary(repo))
}

/// Run one `restore_tree` item (see the module docs).
pub(crate) fn exec_restore_tree(
    ctx: &LaneCtx<'_>,
    req: &RestoreTreeRequest,
) -> Result<RestoreItemResult, GitError> {
    branch_guard(ctx.repo)?;
    let canonical = std::fs::canonicalize(&ctx.workdir)?;
    let planned = build_plan(ctx, &canonical, req)?;
    if planned.path_count() > ctx.limits.max_restore_paths {
        return Err(refuse(UserOpRefusal::TreeTooLarge, ""));
    }

    let mut emit = Vec::new();
    let mut unversioned_overwritten = Vec::new();
    let mut adopt_paths = Vec::new();
    for path in planned.adopt_paths() {
        if ignored(ctx, &path)? && planned.checkout.iter().any(|f| f.path == path) {
            if unversioned_overwritten.len() < MAX_LISTED {
                unversioned_overwritten.push(path);
            }
            continue;
        }
        adopt_paths.push(path);
    }
    let unversioned_overwritten_count =
        u32::try_from(unversioned_overwritten.len()).unwrap_or(u32::MAX);
    let adopted =
        lane_prepare::adopt_named_paths(ctx, &adopt_paths, req.correlation_id.as_deref())?;
    let adopted_sha = adopted.sha_hex();
    let adopt_emit = adopted.emit(req.correlation_id.as_deref());
    if !adopt_emit.is_empty() {
        emit.push(adopt_emit);
    }

    let label = restore_label(&planned)?;
    let subject = label::render_subject(&label).ok_or_else(op_shape)?;
    let message = label::render_message(&label, &req.actor.initiator(), req.provenance.as_ref())
        .ok_or_else(op_shape)?;
    let authorship = user_authorship(&req.actor, &signature_time_now())?;

    let mut last_moved: Option<(Option<Oid>, Option<Oid>)> = None;
    let mut committed: Option<(Oid, Oid, Option<Oid>, Touched)> = None;
    let mut disk_applied = false;
    for _ in 0..MAX_ATTEMPTS {
        last_moved = None;
        let (tip, base) = main_state(ctx.repo)?;
        let (edits, touched) = forward_edits(ctx, base.as_ref(), &planned)?;
        let new_tree = tree_edit::build_tree(ctx.repo, base.as_ref(), &edits)?;
        let parent_tree = base.as_ref().map(Tree::id);
        if Some(new_tree) == parent_tree {
            let _ = normalize_index(ctx, &touched, &[])?;
            return Ok(RestoreItemResult {
                outcome: RestoreOutcome {
                    status: UserCommitStatus::Unchanged,
                    sha: None,
                    head_sha: tip.map(|oid| oid.to_string()),
                    adopted_sha,
                    subject,
                    label,
                    restored: Vec::new(),
                    restored_count: 0,
                    removed_count: 0,
                    unversioned_overwritten,
                    unversioned_overwritten_count,
                },
                emit,
                refresh_repo: false,
            });
        }
        let parent_commit = match tip {
            Some(oid) => Some(ctx.repo.find_commit(oid)?),
            None => None,
        };
        let parents: Vec<&git2::Commit<'_>> = parent_commit.iter().collect();
        let tree = ctx.repo.find_tree(new_tree)?;
        let sha = ctx.repo.commit(
            None,
            &authorship.author,
            &authorship.committer,
            &message,
            &tree,
            &parents,
        )?;
        if !disk_applied {
            apply_rollback(ctx.repo, &planned.apply, false).map_err(from_rollback)?;
            disk_applied = true;
        }
        let landing = Landing {
            parent: tip,
            tree: new_tree,
            message: &message,
            subject: &subject,
            authorship: &authorship,
            touched: &touched,
            stats: &[],
        };
        match publish(ctx, &landing, sha)? {
            Landed::Committed(_) => {
                committed = Some((sha, new_tree, parent_tree, touched));
                break;
            }
            Landed::HeadMoved(now) => last_moved = Some((tip, now)),
        }
    }
    if let Some((expected, actual)) = last_moved {
        return Err(GitError::HeadMoved {
            expected: expected.map(|oid| oid.to_string()),
            actual: actual.map(|oid| oid.to_string()),
        });
    }
    let (sha, new_tree, parent_tree, _touched) =
        committed.ok_or_else(|| refuse(UserOpRefusal::OpShape, ""))?;

    let restored: Vec<String> = planned
        .checkout
        .iter()
        .map(|f| f.path.clone())
        .take(MAX_LISTED)
        .collect();
    let restored_count = u32::try_from(planned.checkout.len()).unwrap_or(u32::MAX);
    let removed_count = u32::try_from(planned.removals.len()).unwrap_or(u32::MAX);
    let rollback = planned.checkpoint.as_ref().map(|(agent, label)| {
        let mut affected: Vec<String> = planned.checkout.iter().map(|f| f.path.clone()).collect();
        affected.extend(planned.removals.iter().cloned());
        RestoreRollback {
            agent_id: agent.clone(),
            target_ref: label.clone(),
            target_kind: "checkpoint",
            affected_paths: affected,
            initiator: req.actor.initiator(),
        }
    });
    emit.push(EmitPlan::restore(
        &authorship.event_agent_id,
        &authorship.initiator,
        &subject,
        &sha.to_string(),
        req.correlation_id.as_deref(),
        planned.checkout.iter().map(|f| f.path.clone()).collect(),
        parent_tree,
        new_tree,
        rollback,
    ));
    Ok(RestoreItemResult {
        outcome: RestoreOutcome {
            status: UserCommitStatus::Committed,
            sha: Some(sha.to_string()),
            head_sha: Some(sha.to_string()),
            adopted_sha,
            subject,
            label,
            restored,
            restored_count,
            removed_count,
            unversioned_overwritten,
            unversioned_overwritten_count,
        },
        emit,
        refresh_repo: false,
    })
}

fn build_plan(
    ctx: &LaneCtx<'_>,
    canonical: &Path,
    req: &RestoreTreeRequest,
) -> Result<Planned, GitError> {
    let facts = restore_facts(ctx.repo, &req.source)?;
    let target_oid = Oid::from_str(&facts.from_sha).map_err(|_| unknown_source())?;
    let target = ctx.repo.find_commit(target_oid)?.tree()?;
    let (_, head) = main_state(ctx.repo)?;
    let scope = match (&req.scope, &req.source) {
        (RestoreScope::CheckpointDomain, RestoreSource::Version(label)) => {
            version_scope(ctx.repo, label)?
        }
        (RestoreScope::CheckpointDomain, RestoreSource::Checkpoint { agent_id, label }) => {
            return checkpoint_plan(ctx, canonical, req, facts, agent_id, label);
        }
        (RestoreScope::CheckpointDomain, RestoreSource::Commit(_)) => RestoreScope::Vault,
        (other, _) => other.clone(),
    };
    let (checkout, removals) = match scope {
        RestoreScope::Vault => vault_plan(ctx, head.as_ref(), &target)?,
        RestoreScope::Paths(paths) => paths_plan(ctx, head.as_ref(), &target, &paths)?,
        RestoreScope::CheckpointDomain => vault_plan(ctx, head.as_ref(), &target)?,
    };
    let checkout_paths: Vec<PathBuf> = checkout.iter().map(|f| PathBuf::from(&f.path)).collect();
    let shape_prefixes = shape_prefixes_on_disk(&ctx.workdir, &checkout_paths);
    let apply = vault_apply_plan(ctx, target_oid, &checkout, &removals)?;
    let checkpoint = match &req.source {
        RestoreSource::Checkpoint { agent_id, label } => Some((agent_id.clone(), label.clone())),
        _ => None,
    };
    Ok(Planned {
        facts,
        checkout,
        removals,
        shape_prefixes,
        apply,
        checkpoint,
    })
}

fn checkpoint_plan(
    ctx: &LaneCtx<'_>,
    canonical: &Path,
    req: &RestoreTreeRequest,
    facts: crate::lane_commit::RestoreFacts,
    agent_id: &str,
    label: &str,
) -> Result<Planned, GitError> {
    let (valid, paths) = resolve_checkpoint(ctx.repo, agent_id, label).map_err(from_rollback)?;
    if !valid {
        return Err(unknown_source());
    }
    let mode = match paths {
        None => RollbackMode::FullDirectory,
        Some(v) if v.is_empty() => RollbackMode::FullDirectory,
        Some(v) => RollbackMode::PathScoped(v),
    };
    let plan = plan_rollback(
        ctx.repo,
        canonical,
        agent_id,
        RollbackTarget::Checkpoint(label.to_string()),
        mode,
    )
    .map_err(from_rollback)?;
    let target = ctx.repo.find_commit(plan.target_oid)?.tree()?;
    let mut checkout = Vec::new();
    for p in &plan.checkout_paths {
        let rel = p.to_string_lossy();
        if excluded(&rel) {
            continue;
        }
        if let Some(file) = file_at(&target, ctx.repo, &rel)? {
            checkout.push(file);
        }
    }
    let mut removals: Vec<String> = plan
        .removal_paths
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .filter(|p| !excluded(p))
        .collect();
    removals.sort();
    let shape_prefixes = plan
        .shape_prefixes(&ctx.workdir)
        .into_iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect();
    let mut apply = plan;
    apply.checkout_paths = checkout.iter().map(|f| PathBuf::from(&f.path)).collect();
    apply.removal_paths = removals.iter().map(PathBuf::from).collect();
    let _ = req;
    Ok(Planned {
        facts,
        checkout,
        removals,
        shape_prefixes,
        apply,
        checkpoint: Some((agent_id.to_string(), label.to_string())),
    })
}

fn version_scope(repo: &Repository, label: &str) -> Result<RestoreScope, GitError> {
    let tag = format!("refs/tags/checkpoint/{USER_NAMESPACE}/{label}");
    let reference = repo.find_reference(&tag).map_err(|_| unknown_source())?;
    let (valid, paths) = match reference.peel_to_tag() {
        Ok(tag) => parse_tag_message(tag.message_bytes().unwrap_or(&[])),
        Err(_) => (true, None),
    };
    if !valid {
        return Err(unknown_source());
    }
    match paths {
        None => Ok(RestoreScope::Vault),
        Some(ps) if ps.is_empty() => Ok(RestoreScope::Vault),
        Some(ps) => {
            let mut parsed = Vec::new();
            for p in ps {
                let rel = p.to_string_lossy();
                match RepoPath::parse(&rel) {
                    Ok(path) => parsed.push(path),
                    Err(_) => {}
                }
            }
            Ok(RestoreScope::Paths(parsed))
        }
    }
}

fn vault_plan(
    ctx: &LaneCtx<'_>,
    head: Option<&Tree<'_>>,
    target: &Tree<'_>,
) -> Result<(Vec<PlannedFile>, Vec<String>), GitError> {
    let checkout = blobs_under(ctx.repo, target, "", ctx.limits.max_restore_paths)?;
    let head_blobs = match head {
        Some(tree) => blobs_under(ctx.repo, tree, "", ctx.limits.max_restore_paths)?,
        None => BTreeMap::new(),
    };
    let checkout_set: HashSet<&str> = checkout.keys().map(String::as_str).collect();
    let mut removals = Vec::new();
    for path in head_blobs.keys() {
        if !checkout_set.contains(path.as_str()) && !excluded(path) {
            removals.push(path.clone());
        }
    }
    let files = checkout.into_values().collect();
    Ok((files, removals))
}

fn paths_plan(
    ctx: &LaneCtx<'_>,
    head: Option<&Tree<'_>>,
    target: &Tree<'_>,
    paths: &[RepoPath],
) -> Result<(Vec<PlannedFile>, Vec<String>), GitError> {
    let mut spellings = Spellings::default();
    let mut checkout: BTreeMap<String, PlannedFile> = BTreeMap::new();
    let mut removals: BTreeSet<String> = BTreeSet::new();
    for path in paths {
        if path.is_root() {
            let (files, extra) = vault_plan(ctx, head, target)?;
            for f in files {
                checkout.insert(f.path.clone(), f);
            }
            removals.extend(extra);
            continue;
        }
        let given = path.tree_spelling(ctx.facts.precompose);
        let target_path = spellings.resolve(ctx, Some(target), given)?;
        let head_path = spellings.resolve(ctx, head, given)?;
        if let Some(entry) = entry_at(Some(target), &target_path)? {
            match head_kind(&entry) {
                HeadKind::Tree => {
                    let subtree = ctx.repo.find_tree(entry.id())?;
                    for (rel, file) in blobs_under(
                        ctx.repo,
                        &subtree,
                        &target_path,
                        ctx.limits.max_restore_paths,
                    )? {
                        checkout.insert(rel, file);
                    }
                    if let Some(head_tree) = head {
                        if let Some(head_entry) = entry_at(Some(head_tree), &head_path)? {
                            if head_kind(&head_entry) == HeadKind::Tree {
                                let old = ctx.repo.find_tree(head_entry.id())?;
                                for rel in blobs_under(
                                    ctx.repo,
                                    &old,
                                    &head_path,
                                    ctx.limits.max_restore_paths,
                                )?
                                .keys()
                                {
                                    if !checkout.contains_key(rel) && !excluded(rel) {
                                        removals.insert(rel.clone());
                                    }
                                }
                            }
                        }
                    }
                }
                HeadKind::Gitlink => {}
                _ => {
                    if let Some(file) = file_at(target, ctx.repo, &target_path)? {
                        checkout.insert(file.path.clone(), file);
                    }
                }
            }
        } else if entry_at(head, &head_path)?.is_some() && !excluded(&head_path) {
            if let Some(entry) = entry_at(head, &head_path)? {
                if head_kind(&entry) == HeadKind::Tree {
                    let old = ctx.repo.find_tree(entry.id())?;
                    for rel in
                        blobs_under(ctx.repo, &old, &head_path, ctx.limits.max_restore_paths)?
                            .keys()
                    {
                        if !excluded(rel) {
                            removals.insert(rel.clone());
                        }
                    }
                } else {
                    removals.insert(head_path);
                }
            }
        }
    }
    Ok((
        checkout.into_values().collect(),
        removals.into_iter().collect(),
    ))
}

fn blobs_under(
    repo: &Repository,
    tree: &Tree<'_>,
    prefix: &str,
    max: usize,
) -> Result<BTreeMap<String, PlannedFile>, GitError> {
    let mut out = BTreeMap::new();
    let mut stack: Vec<(String, Oid)> = vec![(prefix.to_string(), tree.id())];
    while let Some((dir, oid)) = stack.pop() {
        let listing = repo.find_tree(oid)?;
        for entry in listing.iter() {
            let Some(name) = entry.name() else {
                continue;
            };
            let full = if dir.is_empty() {
                name.to_string()
            } else {
                format!("{dir}/{name}")
            };
            if excluded(&full) {
                continue;
            }
            match entry.kind() {
                Some(ObjectType::Tree) => stack.push((full, entry.id())),
                Some(ObjectType::Blob) => {
                    let Some(mode) = mode_of(&entry) else {
                        continue;
                    };
                    // `|plan| > MAX` only: dirs and excluded names must not refuse
                    // a walk that already holds exactly `max` versionable blobs.
                    if out.len() >= max {
                        return Err(refuse(UserOpRefusal::TreeTooLarge, full.as_str()));
                    }
                    out.insert(
                        full.clone(),
                        PlannedFile {
                            path: full,
                            oid: entry.id(),
                            mode,
                        },
                    );
                }
                _ => {}
            }
        }
    }
    Ok(out)
}

fn file_at(
    tree: &Tree<'_>,
    repo: &Repository,
    path: &str,
) -> Result<Option<PlannedFile>, GitError> {
    let Ok(entry) = tree.get_path(Path::new(path)) else {
        return Ok(None);
    };
    if entry.kind() != Some(ObjectType::Blob) {
        return Ok(None);
    }
    let Some(mode) = mode_of(&entry) else {
        return Ok(None);
    };
    let _ = repo;
    Ok(Some(PlannedFile {
        path: path.to_string(),
        oid: entry.id(),
        mode,
    }))
}

fn mode_of(entry: &git2::TreeEntry<'_>) -> Option<EntryMode> {
    match head_kind(entry) {
        HeadKind::File { executable: true } => Some(EntryMode::Executable),
        HeadKind::File { executable: false } => Some(EntryMode::File),
        HeadKind::Link => Some(EntryMode::Link),
        HeadKind::Tree | HeadKind::Gitlink => None,
    }
}

fn excluded(path: &str) -> bool {
    if path == ROOT_GITIGNORE {
        return true;
    }
    is_excluded_from_writable_domain(path, "", &[], false)
}

fn shape_prefixes_on_disk(workdir: &Path, checkout_paths: &[PathBuf]) -> Vec<String> {
    let mut out = Vec::new();
    for p in checkout_paths {
        let mut prefix = PathBuf::new();
        let comps: Vec<_> = p.components().collect();
        for (idx, comp) in comps.iter().enumerate() {
            prefix.push(comp.as_os_str());
            if idx.saturating_add(1) == comps.len() {
                break;
            }
            let abs = workdir.join(&prefix);
            match std::fs::symlink_metadata(&abs) {
                Ok(meta) if meta.file_type().is_file() || meta.file_type().is_symlink() => {
                    out.push(prefix.to_string_lossy().into_owned());
                }
                _ => {}
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

fn forward_edits(
    ctx: &LaneCtx<'_>,
    base: Option<&Tree<'_>>,
    planned: &Planned,
) -> Result<(Vec<TreeEdit>, Touched), GitError> {
    let mut spellings = Spellings::default();
    let mut edits = Vec::new();
    let mut touched = Touched::default();
    let mut seen: HashSet<String> = HashSet::new();
    for prefix in &planned.shape_prefixes {
        let spelled = spellings.resolve(ctx, base, prefix)?;
        if seen.insert(spelled.clone()) && entry_at(base, &spelled)?.is_some() {
            edits.push(TreeEdit::Remove {
                path: spelled.clone(),
            });
            touched.file(&spelled);
        }
    }
    for path in &planned.removals {
        let spelled = spellings.resolve(ctx, base, path)?;
        if seen.insert(spelled.clone()) && entry_at(base, &spelled)?.is_some() {
            edits.push(TreeEdit::Remove {
                path: spelled.clone(),
            });
            touched.file(&spelled);
        }
    }
    for file in &planned.checkout {
        let spelled = spellings.resolve(ctx, base, &file.path)?;
        seen.insert(spelled.clone());
        edits.push(TreeEdit::Upsert {
            path: spelled.clone(),
            oid: file.oid,
            mode: file.mode,
        });
        touched.file(&spelled);
    }
    Ok((edits, touched))
}

fn restore_label(planned: &Planned) -> Result<CommitLabel, GitError> {
    let count = u32::try_from(planned.path_count()).unwrap_or(u32::MAX);
    Ok(CommitLabel {
        op: OP_RESTORE.to_string(),
        paths: Vec::new(),
        count,
        from_sha: Some(planned.facts.from_sha.clone()),
        title: planned.facts.title.clone(),
        checkpoint: planned.facts.checkpoint.clone(),
        ..CommitLabel::default()
    })
}

fn ignored(ctx: &LaneCtx<'_>, path: &str) -> Result<bool, GitError> {
    Ok(ctx.repo.status_should_ignore(Path::new(path))?)
}

fn from_rollback(err: RollbackError) -> GitError {
    match err {
        RollbackError::Io(e) => GitError::Io(e),
        RollbackError::Libgit2 { code, message } => GitError::Libgit2 { code, message },
        RollbackError::InvalidTarget { reason, .. } if reason.contains("forward commits") => {
            refuse(UserOpRefusal::ReservedNamespace, "")
        }
        RollbackError::NotFound { .. } => unknown_source(),
        other => GitError::Io(std::io::Error::other(other.to_string())),
    }
}

fn unknown_source() -> GitError {
    GitError::InvalidUserOp {
        reason: UserOpRefusal::UnknownRestoreSource,
        path: None,
    }
}

fn op_shape() -> GitError {
    GitError::InvalidUserOp {
        reason: UserOpRefusal::OpShape,
        path: None,
    }
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
    use git2::FileMode;
    use tempfile::TempDir;

    fn blob_tree(files: &[(&str, &[u8])]) -> (TempDir, Repository, Oid) {
        let td = TempDir::new().unwrap();
        let repo = Repository::init(td.path()).unwrap();
        let empty_oid = repo.treebuilder(None).unwrap().write().unwrap();
        let tid = {
            let empty = repo.find_tree(empty_oid).unwrap();
            let mut builder = git2::build::TreeUpdateBuilder::new();
            for (path, bytes) in files {
                let oid = repo.blob(bytes).unwrap();
                builder.upsert(*path, oid, FileMode::Blob);
            }
            builder.create_updated(&repo, &empty).unwrap()
        };
        (td, repo, tid)
    }

    #[test]
    fn blobs_under_exact_max_allows_trailing_excluded_and_dir() {
        let (_td, repo, tid) = blob_tree(&[
            ("a.md", b"a\n"),
            ("b.md", b"b\n"),
            ("z.sqlite", b"db"),
            ("zz/.meta.yaml", b"m\n"),
        ]);
        let tree = repo.find_tree(tid).unwrap();
        let out = blobs_under(&repo, &tree, "", 2).unwrap();
        assert_eq!(out.len(), 2);
        assert!(out.contains_key("a.md"));
        assert!(out.contains_key("b.md"));
        assert!(!out.contains_key("z.sqlite"));
        assert!(!out.contains_key("zz/.meta.yaml"));
    }

    #[test]
    fn blobs_under_refuses_when_a_versionable_blob_would_exceed_max() {
        let (_td, repo, tid) = blob_tree(&[("a.md", b"a\n"), ("b.md", b"b\n"), ("c.md", b"c\n")]);
        let tree = repo.find_tree(tid).unwrap();
        match blobs_under(&repo, &tree, "", 2) {
            Err(GitError::InvalidUserOp {
                reason: UserOpRefusal::TreeTooLarge,
                ..
            }) => {}
            Err(e) => panic!("{e:?}"),
            Ok(out) => panic!("expected TreeTooLarge, got {} blobs", out.len()),
        }
    }
}

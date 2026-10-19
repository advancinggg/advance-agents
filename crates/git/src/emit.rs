//! `files.changed` and lane `git.commit` emission (INTEGRATED §3.4, AC-33).
//!
//! Events are assembled as data under L2 ([`EmitPlan`]) and dispatched after the
//! coord guard drops, before the oneshot reply: `git.commit` first, then rows
//! ordered by `path`. The commit worker is the only producer.
//!
//! Leaf names follow INTEGRATED X4 (`blob_oid`, `seq`, `total`). Row visibility
//! follows X6 (Normal and ReadOnly, including non-`_` `.agent/**` and VcsControl;
//! never Private or Junk). `<dir>/.meta.yaml` added or deleted becomes one `dir`
//! row; a modified sidecar is omitted.
//!
//! Building the plan runs under coord and is panic-free. `emit_plan` runs after
//! the guard drops (tree objects are immutable) and may use `serde_json`.

#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::arithmetic_side_effects
)]

use std::path::Path;

use advance_shared_types::event::Event;
use advance_shared_types::traits::EventBusEmit;
use advance_shared_types::workspace_path::{classify_lexical, META_SIDECAR_NAME};
use git2::{Delta, DiffOptions, FileMode, Oid, Repository};
use serde_json::{Map, Value};

use crate::commit_queue::{sanitize_audit_field, CommitRequest, CommitType};
use crate::lane::parent_of;
use crate::rollback::MAX_EVENT_AFFECTED_PATHS;
use crate::user_lane::{
    ItemChange, ItemKind, ItemOutcome, UserCommitStatus, FILES_CHANGED_EVENT, MAX_EVENT_ROWS,
};

const GIT_COMMIT: &str = "git.commit";
const GIT_ROLLBACK: &str = "git.rollback";
const GIT_COMMIT_EVENT_MAX_PATHS: usize = 64;
const GIT_COMMIT_EVENT_MAX_PATH_BYTES: usize = 256;

/// Data assembled under L2 and emitted after the guard drops.
#[derive(Debug, Clone, Default)]
pub(crate) struct EmitPlan {
    agent_id: String,
    initiator: String,
    git_commit: Option<GitCommitSpec>,
    rows: Vec<RowSpec>,
    parent_tree: Option<Oid>,
    new_tree: Option<Oid>,
    /// Legacy request paths that were auto-ignored (not in the tree diff).
    autoignored: Vec<AutoIgnored>,
    rollback: Option<RollbackSpec>,
}

#[derive(Debug, Clone)]
struct GitCommitSpec {
    agent_id: String,
    commit_type: CommitType,
    initiator: String,
    message: String,
    sha: String,
    affected_paths: Vec<String>,
    correlation_id: Option<String>,
    op: Option<String>,
}

#[derive(Debug, Clone)]
struct RowSpec {
    path: String,
    kind: &'static str,
    change: &'static str,
    from_path: Option<String>,
    blob_oid: Option<String>,
    versioned: bool,
}

#[derive(Debug, Clone)]
struct AutoIgnored {
    path: String,
    parent_had: bool,
}

#[derive(Debug, Clone)]
struct RollbackSpec {
    agent_id: String,
    target_ref: String,
    target_kind: &'static str,
    affected_paths: Vec<String>,
    initiator: String,
}

impl EmitPlan {
    pub(crate) fn none() -> Self {
        Self::default()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.git_commit.is_none()
            && self.rows.is_empty()
            && self.new_tree.is_none()
            && self.rollback.is_none()
    }

    pub(crate) fn legacy(
        req: &CommitRequest,
        oid: Oid,
        staged: &[String],
        parent_tree: Option<Oid>,
        new_tree: Oid,
        autoignored: Vec<(String, bool)>,
    ) -> Self {
        let agent_id = sanitize_audit_field(&req.agent_id);
        let initiator = sanitize_audit_field(&req.initiator);
        Self {
            agent_id: agent_id.clone(),
            initiator: initiator.clone(),
            git_commit: Some(GitCommitSpec {
                agent_id,
                commit_type: req.commit_type,
                initiator,
                message: sanitize_audit_field(&req.message),
                sha: oid.to_string(),
                affected_paths: staged.to_vec(),
                correlation_id: req.correlation_id.as_deref().map(sanitize_audit_field),
                op: None,
            }),
            rows: Vec::new(),
            parent_tree,
            new_tree: Some(new_tree),
            autoignored: autoignored
                .into_iter()
                .map(|(path, parent_had)| AutoIgnored { path, parent_had })
                .collect(),
            rollback: None,
        }
    }

    pub(crate) fn user(
        status: UserCommitStatus,
        agent_id: &str,
        initiator: &str,
        op: &str,
        message: &str,
        sha: Option<&str>,
        correlation_id: Option<&str>,
        items: &[ItemOutcome],
    ) -> Self {
        let agent_id = sanitize_audit_field(agent_id);
        let initiator = sanitize_audit_field(initiator);
        let rows = rows_from_items(items);
        let git_commit = match status {
            UserCommitStatus::Committed => sha.map(|sha| GitCommitSpec {
                agent_id: agent_id.clone(),
                commit_type: CommitType::User,
                initiator: initiator.clone(),
                message: sanitize_audit_field(message),
                sha: sha.to_string(),
                affected_paths: items.iter().map(|item| item.path.clone()).collect(),
                correlation_id: correlation_id.map(sanitize_audit_field),
                op: Some(op.to_string()),
            }),
            UserCommitStatus::Unchanged => None,
        };
        Self {
            agent_id,
            initiator,
            git_commit,
            rows,
            parent_tree: None,
            new_tree: None,
            autoignored: Vec::new(),
            rollback: None,
        }
    }

    pub(crate) fn adopt(
        agent_id: &str,
        initiator: &str,
        message: &str,
        sha: &str,
        correlation_id: Option<&str>,
        affected_paths: Vec<String>,
        parent_tree: Option<Oid>,
        new_tree: Oid,
    ) -> Self {
        let agent_id = sanitize_audit_field(agent_id);
        let initiator = sanitize_audit_field(initiator);
        Self {
            agent_id: agent_id.clone(),
            initiator: initiator.clone(),
            git_commit: Some(GitCommitSpec {
                agent_id,
                commit_type: CommitType::Micro,
                initiator,
                message: sanitize_audit_field(message),
                sha: sha.to_string(),
                affected_paths,
                correlation_id: correlation_id.map(sanitize_audit_field),
                op: Some("adopt".to_string()),
            }),
            rows: Vec::new(),
            parent_tree,
            new_tree: Some(new_tree),
            autoignored: Vec::new(),
            rollback: None,
        }
    }

    /// A save-version marker: `git.commit {op: save-version}` and no `files.changed` rows
    /// (the tree equals the parent).
    pub(crate) fn save_version(
        agent_id: &str,
        initiator: &str,
        message: &str,
        sha: &str,
        correlation_id: Option<&str>,
        affected_paths: Vec<String>,
    ) -> Self {
        let agent_id = sanitize_audit_field(agent_id);
        let initiator = sanitize_audit_field(initiator);
        Self {
            agent_id: agent_id.clone(),
            initiator: initiator.clone(),
            git_commit: Some(GitCommitSpec {
                agent_id,
                commit_type: CommitType::User,
                initiator,
                message: sanitize_audit_field(message),
                sha: sha.to_string(),
                affected_paths,
                correlation_id: correlation_id.map(sanitize_audit_field),
                op: Some("save-version".to_string()),
            }),
            rows: Vec::new(),
            parent_tree: None,
            new_tree: None,
            autoignored: Vec::new(),
            rollback: None,
        }
    }

    /// A forward restore commit: `git.commit {op: restore}` plus tree-diff rows, and
    /// optionally `git.rollback` (Checkpoint source, initiator `user:<h>`).
    pub(crate) fn restore(
        agent_id: &str,
        initiator: &str,
        message: &str,
        sha: &str,
        correlation_id: Option<&str>,
        affected_paths: Vec<String>,
        parent_tree: Option<Oid>,
        new_tree: Oid,
        rollback: Option<RestoreRollback>,
    ) -> Self {
        let agent_id = sanitize_audit_field(agent_id);
        let initiator = sanitize_audit_field(initiator);
        Self {
            agent_id: agent_id.clone(),
            initiator: initiator.clone(),
            git_commit: Some(GitCommitSpec {
                agent_id,
                commit_type: CommitType::User,
                initiator,
                message: sanitize_audit_field(message),
                sha: sha.to_string(),
                affected_paths,
                correlation_id: correlation_id.map(sanitize_audit_field),
                op: Some("restore".to_string()),
            }),
            rows: Vec::new(),
            parent_tree,
            new_tree: Some(new_tree),
            autoignored: Vec::new(),
            rollback: rollback.map(|rb| RollbackSpec {
                agent_id: sanitize_audit_field(&rb.agent_id),
                target_ref: rb.target_ref,
                target_kind: rb.target_kind,
                affected_paths: rb.affected_paths,
                initiator: sanitize_audit_field(&rb.initiator),
            }),
        }
    }
}

/// The `git.rollback` payload a Checkpoint-source `restore_tree` emits after the
/// restore commit (MODULE-003-AC-32).
#[derive(Debug, Clone)]
pub(crate) struct RestoreRollback {
    pub agent_id: String,
    pub target_ref: String,
    pub target_kind: &'static str,
    pub affected_paths: Vec<String>,
    pub initiator: String,
}

/// Dispatch `git.commit` then `files.changed` (tree-diff rows filled here, after L2).
pub(crate) fn emit_plan(bus: &dyn EventBusEmit, repo: &Repository, plan: EmitPlan) {
    let mut rows = plan.rows;
    if let Some(new_tree) = plan.new_tree {
        rows.extend(rows_from_tree_diff(
            repo,
            plan.parent_tree,
            new_tree,
            &plan.autoignored,
        ));
    }
    rows.sort_by(|a, b| a.path.cmp(&b.path));
    let total = u32::try_from(rows.len()).unwrap_or(u32::MAX);
    if let Some(commit) = &plan.git_commit {
        emit_git_commit(bus, commit);
    }
    let sha = plan.git_commit.as_ref().map(|c| c.sha.as_str());
    let commit_type = plan.git_commit.as_ref().map(|c| c.commit_type);
    for (seq, row) in rows.into_iter().take(MAX_EVENT_ROWS).enumerate() {
        let seq = u32::try_from(seq).unwrap_or(u32::MAX);
        emit_row(
            bus,
            &plan.agent_id,
            &plan.initiator,
            sha,
            commit_type,
            seq,
            total,
            row,
        );
    }
    if let Some(rollback) = plan.rollback {
        emit_rollback(bus, rollback);
    }
}

/// Dispatch every plan in order (adopt then the marker / restore).
pub(crate) fn emit_plans(bus: &dyn EventBusEmit, repo: &Repository, plans: Vec<EmitPlan>) {
    for plan in plans {
        emit_plan(bus, repo, plan);
    }
}

fn emit_rollback(bus: &dyn EventBusEmit, spec: RollbackSpec) {
    let affected: Vec<Value> = spec
        .affected_paths
        .iter()
        .take(MAX_EVENT_AFFECTED_PATHS)
        .map(|p| Value::String(p.clone()))
        .collect();
    let mut payload = Map::new();
    payload.insert("agent_id".into(), Value::String(spec.agent_id.clone()));
    payload.insert("target_ref".into(), Value::String(spec.target_ref));
    payload.insert(
        "target_kind".into(),
        Value::String(spec.target_kind.to_string()),
    );
    payload.insert("affected_paths".into(), Value::Array(affected));
    payload.insert("initiator".into(), Value::String(spec.initiator));
    bus.emit(Event::observability(
        GIT_ROLLBACK,
        spec.agent_id,
        Value::Object(payload),
        None,
    ));
}

fn emit_git_commit(bus: &dyn EventBusEmit, spec: &GitCommitSpec) {
    let paths: Vec<Value> = spec
        .affected_paths
        .iter()
        .take(GIT_COMMIT_EVENT_MAX_PATHS)
        .map(|p| {
            Value::String(truncate_on_char_boundary(p, GIT_COMMIT_EVENT_MAX_PATH_BYTES).to_string())
        })
        .collect();
    let mut payload = Map::new();
    payload.insert("agent_id".into(), Value::String(spec.agent_id.clone()));
    payload.insert(
        "commit_type".into(),
        Value::String(spec.commit_type.to_string()),
    );
    payload.insert("initiator".into(), Value::String(spec.initiator.clone()));
    payload.insert("message".into(), Value::String(spec.message.clone()));
    payload.insert("sha".into(), Value::String(spec.sha.clone()));
    payload.insert("affected_paths".into(), Value::Array(paths));
    payload.insert(
        "affected_paths_count".into(),
        Value::from(spec.affected_paths.len()),
    );
    payload.insert(
        "files_changed".into(),
        Value::from(spec.affected_paths.len()),
    );
    if let Some(cid) = &spec.correlation_id {
        payload.insert("correlation_id".into(), Value::String(cid.clone()));
    }
    if let Some(op) = &spec.op {
        payload.insert("op".into(), Value::String(op.clone()));
    }
    bus.emit(Event::observability(
        GIT_COMMIT,
        spec.agent_id.clone(),
        Value::Object(payload),
        None,
    ));
}

fn emit_row(
    bus: &dyn EventBusEmit,
    agent_id: &str,
    initiator: &str,
    sha: Option<&str>,
    commit_type: Option<CommitType>,
    seq: u32,
    total: u32,
    row: RowSpec,
) {
    let mut payload = Map::new();
    payload.insert("path".into(), Value::String(row.path));
    payload.insert("kind".into(), Value::String(row.kind.to_string()));
    payload.insert("change".into(), Value::String(row.change.to_string()));
    if let Some(from) = row.from_path {
        payload.insert("from_path".into(), Value::String(from));
    }
    if let Some(oid) = row.blob_oid {
        payload.insert("blob_oid".into(), Value::String(oid));
    }
    payload.insert(
        "versioned".into(),
        Value::String(if row.versioned { "yes" } else { "no" }.to_string()),
    );
    if let Some(sha) = sha {
        payload.insert("sha".into(), Value::String(sha.to_string()));
        if let Some(kind) = commit_type {
            payload.insert("commit_type".into(), Value::String(kind.to_string()));
        }
    }
    if !initiator.is_empty() {
        payload.insert("initiator".into(), Value::String(initiator.to_string()));
    }
    payload.insert("seq".into(), Value::from(seq));
    payload.insert("total".into(), Value::from(total));
    bus.emit(Event::observability(
        FILES_CHANGED_EVENT,
        agent_id.to_string(),
        Value::Object(payload),
        None,
    ));
}

fn rows_from_items(items: &[ItemOutcome]) -> Vec<RowSpec> {
    let mut rows = Vec::new();
    for item in items {
        if item.change == ItemChange::Unchanged {
            continue;
        }
        let Some(change) = change_token(&item.change) else {
            continue;
        };
        let from_path = match &item.change {
            ItemChange::Renamed { from } => Some(from.clone()),
            _ => None,
        };
        let kind = match item.kind {
            ItemKind::File => "file",
            ItemKind::Dir => "dir",
        };
        let blob_oid = if item.versioned && kind == "file" && change != "deleted" {
            item.oid.clone()
        } else {
            None
        };
        if let Some(row) = visible_row(
            item.path.clone(),
            kind,
            change,
            from_path,
            blob_oid,
            item.versioned,
        ) {
            rows.push(row);
        }
    }
    rows
}

fn rows_from_tree_diff(
    repo: &Repository,
    parent: Option<Oid>,
    new_tree: Oid,
    autoignored: &[AutoIgnored],
) -> Vec<RowSpec> {
    let mut rows = Vec::new();
    let parent_tree = parent.and_then(|oid| repo.find_tree(oid).ok());
    let new = match repo.find_tree(new_tree) {
        Ok(tree) => tree,
        Err(_) => return rows,
    };
    let mut opts = DiffOptions::new();
    let diff = match repo.diff_tree_to_tree(parent_tree.as_ref(), Some(&new), Some(&mut opts)) {
        Ok(d) => d,
        Err(_) => return rows,
    };
    for delta in diff.deltas() {
        if let Some(row) = row_from_delta(&delta) {
            rows.push(row);
        }
    }
    let listed: Vec<String> = rows.iter().map(|r| r.path.clone()).collect();
    for ignored in autoignored {
        if listed.iter().any(|p| p == &ignored.path) {
            continue;
        }
        let change = if ignored.parent_had {
            "modified"
        } else {
            "added"
        };
        if let Some(row) = visible_row(ignored.path.clone(), "file", change, None, None, false) {
            rows.push(row);
        }
    }
    rows
}

fn row_from_delta(delta: &git2::DiffDelta<'_>) -> Option<RowSpec> {
    let (change, path, from_path) = match delta.status() {
        Delta::Added => ("added", path_of(delta.new_file().path())?, None),
        Delta::Deleted => ("deleted", path_of(delta.old_file().path())?, None),
        Delta::Modified | Delta::Typechange => {
            ("modified", path_of(delta.new_file().path())?, None)
        }
        Delta::Renamed => (
            "renamed",
            path_of(delta.new_file().path())?,
            path_of(delta.old_file().path()),
        ),
        _ => return None,
    };
    let is_dir = delta.new_file().mode() == FileMode::Tree
        || (change == "deleted" && delta.old_file().mode() == FileMode::Tree);
    let kind = if is_dir { "dir" } else { "file" };
    let blob_oid = if kind == "file" && change != "deleted" {
        let id = delta.new_file().id();
        if id.is_zero() {
            None
        } else {
            Some(id.to_string())
        }
    } else {
        None
    };
    visible_row(path, kind, change, from_path, blob_oid, true)
}

fn path_of(path: Option<&Path>) -> Option<String> {
    path.and_then(|p| p.to_str()).map(str::to_string)
}

fn visible_row(
    path: String,
    kind: &'static str,
    change: &'static str,
    from_path: Option<String>,
    blob_oid: Option<String>,
    versioned: bool,
) -> Option<RowSpec> {
    if is_meta_sidecar(&path) {
        if change == "modified" {
            return None;
        }
        let dir = parent_of(&path).to_string();
        return Some(RowSpec {
            path: dir,
            kind: "dir",
            change,
            from_path: None,
            blob_oid: None,
            versioned: true,
        });
    }
    if classify_lexical(&path).access.is_hidden() {
        return None;
    }
    Some(RowSpec {
        path,
        kind,
        change,
        from_path,
        blob_oid,
        versioned,
    })
}

fn is_meta_sidecar(path: &str) -> bool {
    path == META_SIDECAR_NAME
        || path
            .rsplit_once('/')
            .is_some_and(|(_, name)| name == META_SIDECAR_NAME)
}

fn change_token(change: &ItemChange) -> Option<&'static str> {
    match change {
        ItemChange::Added => Some("added"),
        ItemChange::Modified => Some("modified"),
        ItemChange::Deleted => Some("deleted"),
        ItemChange::Renamed { .. } => Some("renamed"),
        ItemChange::Unchanged => None,
    }
}

#[allow(clippy::string_slice)]
fn truncate_on_char_boundary(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    s.get(..end).unwrap_or("")
}

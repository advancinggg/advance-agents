//! Slice C — task decomposition protocol (MODULE-005 AC-13/14/15, REQ-050).
//!
//! Sync API mirroring the PRD §9.5 `submit-decomposition` /
//! `update-subtask-status` / `get-decomposition` WIT surface. Persists a
//! `decomposition-state`-shaped YAML at
//! `{caller.workspace_path}/.agent/tasks/active/{task-id}/decomposition.yaml`.
//!
//! Value/enum types follow **PRD §9.5** (the frozen WIT contract). MODULE-005
//! §1.3.4 was reconciled to §9.5 (Slice C, /dev §2.1.2 Option C).
//!
//! subtask-id strategy: `st-{uuid-v4}` — content-independent. Re-submitting
//! the same `title` WITHOUT an `existing-id` yields a FRESH id (PRD
//! §4.2.2:539-540). The ONLY continuity mechanism across re-submits is
//! `existing-id`; a stale `existing-id` → `SubtaskNotFound` (never silently
//! treated as new).

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use advance_shared_types::agent_tree::AgentId;
use serde::{Deserialize, Serialize};

use crate::error::DecompositionError;
use crate::identifier::{sub_uuid_v4, validate_agent_id};
use crate::tree::AgentTreeStore;
use crate::workspace::symlink_check;

/// Max subtasks accepted in one `submit`.
pub const MAX_DECOMPOSITION_SUBTASKS: usize = 256;
/// Max rendered YAML doc size (matches `MAX_TEMPLATE_TOTAL_BYTES` = 1 MiB;
/// coherent with 256 subtasks × ≤16 KiB prompts).
pub const MAX_DECOMPOSITION_DOC_BYTES: usize = 1024 * 1024;
/// Max bytes for a subtask `title`.
pub const MAX_SUBTASK_TITLE_BYTES: usize = 256;
/// Max bytes for a subtask `prompt`.
pub const MAX_SUBTASK_PROMPT_BYTES: usize = 16 * 1024;
/// Max bytes for `task_id`.
pub const MAX_TASK_ID_BYTES: usize = 128;
/// Max bytes for an `assignee`.
pub const MAX_ASSIGNEE_BYTES: usize = 128;

// ─────────────────────────────────────────────────────────────────────────
// Value types — PRD §9.5 shape
// ─────────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq)]
pub struct DecompositionPlan {
    pub goal: String,
    pub strategy: DecompositionStrategy,
    pub subtasks: Vec<SubtaskSpec>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecompositionStrategy {
    SelfExecute,
    Decompose,
    DelegateSingle(DelegationTarget),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DelegationTarget {
    pub assignee: String,
    pub template_ref: Option<String>,
    pub prompt: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SubtaskSpec {
    pub existing_id: Option<String>,
    pub title: String,
    pub assignee: String,
    pub template_ref: Option<String>,
    pub prompt: String,
    /// At submit time these are `title` references; the runtime resolves
    /// them to subtask-ids.
    pub depends_on: Vec<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DecompositionReceipt {
    pub subtask_ids: Vec<SubtaskIdMapping>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SubtaskIdMapping {
    pub title: String,
    pub subtask_id: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SubtaskStatus {
    Pending,
    InProgress,
    Completed,
    Failed,
    Skipped,
}

/// Persisted (and returned-by-`get`) decomposition state — PRD §9.5
/// `decomposition-state` shape `{goal, strategy, subtasks}`. (The owning
/// `task-id` is encoded in the on-disk path, not the document body.)
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DecompositionState {
    pub goal: String,
    pub strategy: DecompositionStrategy,
    pub subtasks: Vec<SubtaskState>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SubtaskState {
    pub subtask_id: String,
    pub title: String,
    pub assignee: String,
    /// Resolved subtask-ids (NOT titles) — PRD §9.5 `depends-on`.
    pub depends_on: Vec<String>,
    pub status: SubtaskStatus,
    pub outcome: Option<String>,
    pub orphaned: bool,
}

// ─────────────────────────────────────────────────────────────────────────
// Trait + default impl
// ─────────────────────────────────────────────────────────────────────────

pub trait DecompositionStore: Send + Sync {
    fn submit(
        &self,
        caller_id: &str,
        task_id: &str,
        plan: DecompositionPlan,
    ) -> Result<DecompositionReceipt, DecompositionError>;

    /// Mutate a subtask's status + outcome, returning the **previous**
    /// `SubtaskStatus` (so the WIT handler can emit a `task.subtask_updated`
    /// old→new transition event without a redundant second read). The old
    /// status is captured atomically inside the single read-modify-write.
    fn update_subtask_status(
        &self,
        caller_id: &str,
        task_id: &str,
        subtask_id: &str,
        status: SubtaskStatus,
        outcome: Option<String>,
    ) -> Result<SubtaskStatus, DecompositionError>;

    fn get(
        &self,
        caller_id: &str,
        task_id: &str,
    ) -> Result<Option<DecompositionState>, DecompositionError>;
}

#[derive(Clone)]
pub struct DefaultDecompositionStore {
    tree: AgentTreeStore,
}

impl DefaultDecompositionStore {
    pub fn new(tree: AgentTreeStore) -> Self {
        Self { tree }
    }

    /// Resolve the caller's `.agent/tasks/active/{task_id}/` directory.
    /// `PermissionDenied` if the caller is not a registered tree node
    /// (it is therefore not the owner of any task workspace).
    fn task_dir(&self, caller_id: &str, task_id: &str) -> Result<PathBuf, DecompositionError> {
        if validate_agent_id(caller_id).is_err() {
            return Err(DecompositionError::PermissionDenied(format!(
                "invalid caller id: {caller_id}"
            )));
        }
        validate_task_id(task_id)?;
        let node = self
            .tree
            .get_node(&AgentId(caller_id.to_string()))
            .ok_or_else(|| {
                DecompositionError::PermissionDenied(format!(
                    "caller {caller_id} is not a registered agent"
                ))
            })?;
        Ok(node
            .workspace_path
            .join(".agent")
            .join("tasks")
            .join("active")
            .join(task_id))
    }
}

impl DecompositionStore for DefaultDecompositionStore {
    fn submit(
        &self,
        caller_id: &str,
        task_id: &str,
        plan: DecompositionPlan,
    ) -> Result<DecompositionReceipt, DecompositionError> {
        let dir = self.task_dir(caller_id, task_id)?;

        if plan.subtasks.len() > MAX_DECOMPOSITION_SUBTASKS {
            return Err(DecompositionError::InvalidConfig(format!(
                "subtasks {} > MAX_DECOMPOSITION_SUBTASKS {}",
                plan.subtasks.len(),
                MAX_DECOMPOSITION_SUBTASKS
            )));
        }
        validate_strategy(&plan.strategy)?;

        // Per-subtask field validation + within-submit duplicate detection.
        let mut seen_titles: HashSet<&str> = HashSet::new();
        let mut seen_existing: HashSet<&str> = HashSet::new();
        for st in &plan.subtasks {
            if st.title.is_empty() || st.title.len() > MAX_SUBTASK_TITLE_BYTES {
                return Err(DecompositionError::InvalidConfig(format!(
                    "title length {} invalid (1..={MAX_SUBTASK_TITLE_BYTES})",
                    st.title.len()
                )));
            }
            if st.assignee.is_empty() || st.assignee.len() > MAX_ASSIGNEE_BYTES {
                return Err(DecompositionError::InvalidConfig(format!(
                    "assignee length {} invalid (1..={MAX_ASSIGNEE_BYTES})",
                    st.assignee.len()
                )));
            }
            if st.prompt.len() > MAX_SUBTASK_PROMPT_BYTES {
                return Err(DecompositionError::InvalidConfig(format!(
                    "prompt length {} > {MAX_SUBTASK_PROMPT_BYTES}",
                    st.prompt.len()
                )));
            }
            // A subtask in an ≤MAX_DECOMPOSITION_SUBTASKS-node plan can
            // meaningfully depend on at most MAX-1 others; cap the declared
            // depends_on COUNT here (before dependency resolution + cycle
            // detection allocate/iterate per edge) so a caller — Rust API or the
            // WIT lift — cannot amplify graph/serialize work with a pathological
            // dependency list (defence-in-depth alongside the WIT descriptor cap).
            if st.depends_on.len() > MAX_DECOMPOSITION_SUBTASKS {
                return Err(DecompositionError::InvalidConfig(format!(
                    "subtask {:?} depends_on {} > MAX_DECOMPOSITION_SUBTASKS {}",
                    st.title,
                    st.depends_on.len(),
                    MAX_DECOMPOSITION_SUBTASKS
                )));
            }
            if let Some(eid) = st.existing_id.as_deref() {
                if !is_valid_subtask_id(eid) {
                    return Err(DecompositionError::InvalidConfig(format!(
                        "existing-id {eid:?} not of form st-<uuid-v4>"
                    )));
                }
                if !seen_existing.insert(eid) {
                    return Err(DecompositionError::DuplicateExistingId(eid.to_string()));
                }
            }
            if !seen_titles.insert(st.title.as_str()) {
                return Err(DecompositionError::DuplicateTitle(st.title.clone()));
            }
        }

        // Read prior plan (if any) for existing-id continuity.
        let prior = read_state(&dir)?;
        let prior_id_set: HashSet<String> = prior
            .as_ref()
            .map(|p| p.subtasks.iter().map(|s| s.subtask_id.clone()).collect())
            .unwrap_or_default();

        // Assign subtask-ids; build title→id map for dependency resolution.
        let mut title_to_id: HashMap<String, String> = HashMap::new();
        let mut assigned: Vec<(String, &SubtaskSpec)> = Vec::with_capacity(plan.subtasks.len());
        for st in &plan.subtasks {
            let id = match st.existing_id.as_deref() {
                Some(eid) => {
                    if !prior_id_set.contains(eid) {
                        return Err(DecompositionError::SubtaskNotFound(eid.to_string()));
                    }
                    eid.to_string()
                }
                None => format!("st-{}", sub_uuid_v4()),
            };
            title_to_id.insert(st.title.clone(), id.clone());
            assigned.push((id, st));
        }

        // Resolve depends-on titles → ids.
        let mut new_states: Vec<SubtaskState> = Vec::with_capacity(assigned.len());
        for (id, st) in &assigned {
            let mut dep_ids = Vec::with_capacity(st.depends_on.len());
            for dep_title in &st.depends_on {
                let dep_id = title_to_id
                    .get(dep_title)
                    .ok_or_else(|| DecompositionError::UnresolvedDependency(dep_title.clone()))?;
                dep_ids.push(dep_id.clone());
            }
            // Preserve prior status/outcome when the id is carried over.
            let (status, outcome) = prior
                .as_ref()
                .and_then(|p| p.subtasks.iter().find(|s| &s.subtask_id == id))
                .map(|s| (s.status, s.outcome.clone()))
                .unwrap_or((SubtaskStatus::Pending, None));
            new_states.push(SubtaskState {
                subtask_id: id.clone(),
                title: st.title.clone(),
                assignee: st.assignee.clone(),
                depends_on: dep_ids,
                status,
                outcome,
                orphaned: false,
            });
        }

        // Cycle detection over subtask-id → depends-on edges.
        detect_cycle(&new_states)?;

        // Orphan computation: prior subtask ids not in the new id-set.
        // Orphan computation (PRD §4.2.2 / §1.3.4 merge rules — STATUS
        // CONDITIONAL): a prior subtask dropped from the new plan is
        //   - retained with `orphaned: true` ONLY if it was `Completed` or
        //     `InProgress` (work was done / in flight — preserve the trace);
        //   - REMOVED entirely if it was `Pending` / `Skipped` / `Failed`
        //     (no completed work to preserve).
        // Collect owned ids first so the immutable borrow ends before the
        // subsequent `new_states.push`.
        let new_id_set: HashSet<String> = new_states.iter().map(|s| s.subtask_id.clone()).collect();
        if let Some(p) = &prior {
            for s in &p.subtasks {
                if !new_id_set.contains(&s.subtask_id)
                    && matches!(
                        s.status,
                        SubtaskStatus::Completed | SubtaskStatus::InProgress
                    )
                {
                    new_states.push(SubtaskState {
                        orphaned: true,
                        ..s.clone()
                    });
                }
            }
        }

        let state = DecompositionState {
            goal: plan.goal,
            strategy: plan.strategy,
            subtasks: new_states,
        };

        write_state(&self.tree, &dir, &state)?;

        Ok(DecompositionReceipt {
            subtask_ids: state
                .subtasks
                .iter()
                .filter(|s| !s.orphaned)
                .map(|s| SubtaskIdMapping {
                    title: s.title.clone(),
                    subtask_id: s.subtask_id.clone(),
                })
                .collect(),
        })
    }

    fn update_subtask_status(
        &self,
        caller_id: &str,
        task_id: &str,
        subtask_id: &str,
        status: SubtaskStatus,
        outcome: Option<String>,
    ) -> Result<SubtaskStatus, DecompositionError> {
        let dir = self.task_dir(caller_id, task_id)?;
        let mut state = read_state(&dir)?
            .ok_or_else(|| DecompositionError::TaskNotFound(task_id.to_string()))?;
        let st = state
            .subtasks
            .iter_mut()
            .find(|s| s.subtask_id == subtask_id)
            .ok_or_else(|| DecompositionError::SubtaskNotFound(subtask_id.to_string()))?;
        // Capture the prior status BEFORE overwriting so the caller can emit
        // an old→new transition event (single read-modify-write — no TOCTOU).
        let old_status = st.status;
        st.status = status;
        st.outcome = outcome;
        write_state(&self.tree, &dir, &state)?;
        Ok(old_status)
    }

    fn get(
        &self,
        caller_id: &str,
        task_id: &str,
    ) -> Result<Option<DecompositionState>, DecompositionError> {
        let dir = self.task_dir(caller_id, task_id)?;
        read_state(&dir)
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────

fn validate_task_id(task_id: &str) -> Result<(), DecompositionError> {
    if task_id.is_empty() || task_id.len() > MAX_TASK_ID_BYTES {
        return Err(DecompositionError::InvalidConfig(format!(
            "task_id length {} invalid (1..={MAX_TASK_ID_BYTES})",
            task_id.len()
        )));
    }
    if !task_id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(DecompositionError::InvalidConfig(format!(
            "task_id {task_id:?} must match ^[A-Za-z0-9_-]+$"
        )));
    }
    // `..` cannot occur given the charset above (no '.'), but assert for clarity.
    if task_id.contains("..") {
        return Err(DecompositionError::InvalidConfig(
            "task_id must not contain '..'".to_string(),
        ));
    }
    Ok(())
}

fn is_valid_subtask_id(id: &str) -> bool {
    // `st-` + a CANONICAL hyphenated UUID **v4**. The `len() == 36` gate
    // rejects `uuid::parse_str`'s non-canonical accepted forms (braced
    // `{…}` = 38, `urn:uuid:…`, hyphenless 32-char); the version check
    // rejects nil / v1 / v3 / v5. Self-generated ids are always canonical
    // hyphenated v4 (`format!("st-{}", sub_uuid_v4())`), so this exactly
    // matches the "st-<uuid-v4>" contract — NOT merely 36 hex/hyphen chars.
    match id.strip_prefix("st-") {
        Some(rest) => {
            rest.len() == 36
                && uuid::Uuid::parse_str(rest)
                    .map(|u| u.get_version() == Some(uuid::Version::Random))
                    .unwrap_or(false)
        }
        None => false,
    }
}

fn validate_strategy(s: &DecompositionStrategy) -> Result<(), DecompositionError> {
    if let DecompositionStrategy::DelegateSingle(t) = s {
        if t.assignee.is_empty() || t.assignee.len() > MAX_ASSIGNEE_BYTES {
            return Err(DecompositionError::InvalidConfig(
                "delegate-single assignee empty or too long".to_string(),
            ));
        }
        if t.prompt.len() > MAX_SUBTASK_PROMPT_BYTES {
            return Err(DecompositionError::InvalidConfig(
                "delegate-single prompt too long".to_string(),
            ));
        }
    }
    Ok(())
}

/// Iterative DFS 3-color cycle detection over subtask-id → depends-on edges.
fn detect_cycle(states: &[SubtaskState]) -> Result<(), DecompositionError> {
    let adj: HashMap<&str, &Vec<String>> = states
        .iter()
        .map(|s| (s.subtask_id.as_str(), &s.depends_on))
        .collect();
    #[derive(Clone, Copy, PartialEq)]
    enum Color {
        White,
        Gray,
        Black,
    }
    let mut color: HashMap<&str, Color> = states
        .iter()
        .map(|s| (s.subtask_id.as_str(), Color::White))
        .collect();
    for s in states {
        if color[s.subtask_id.as_str()] != Color::White {
            continue;
        }
        // Explicit stack: (node, child-index). Enter→Gray, exhausted→Black.
        let mut stack: Vec<(&str, usize)> = vec![(s.subtask_id.as_str(), 0)];
        if let Some(c) = color.get_mut(s.subtask_id.as_str()) {
            *c = Color::Gray;
        }
        while let Some(&(node, idx)) = stack.last() {
            let deps = adj.get(node).copied();
            match deps.and_then(|d| d.get(idx)) {
                Some(next) => {
                    stack.last_mut().unwrap().1 += 1;
                    let next = next.as_str();
                    match color.get(next).copied() {
                        Some(Color::Gray) => {
                            return Err(DecompositionError::DependencyCycle(format!(
                                "{node} → {next}"
                            )));
                        }
                        Some(Color::White) => {
                            if let Some(c) = color.get_mut(next) {
                                *c = Color::Gray;
                            }
                            stack.push((next, 0));
                        }
                        // Black = fully explored; unknown dep id is ignored
                        // here (depends-on were resolved to real ids upstream
                        // in `submit`, so an unknown id cannot occur).
                        _ => {}
                    }
                }
                None => {
                    if let Some(c) = color.get_mut(node) {
                        *c = Color::Black;
                    }
                    stack.pop();
                }
            }
        }
    }
    Ok(())
}

fn state_path(dir: &Path) -> PathBuf {
    dir.join("decomposition.yaml")
}

fn read_state(dir: &Path) -> Result<Option<DecompositionState>, DecompositionError> {
    let path = state_path(dir);
    match std::fs::read(&path) {
        Ok(bytes) => {
            let st: DecompositionState = serde_yml::from_slice(&bytes)
                .map_err(|e| DecompositionError::ParseError(format!("{path:?}: {e}")))?;
            Ok(Some(st))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(DecompositionError::IoFailure(format!("read {path:?}: {e}"))),
    }
}

/// Local atomic write supporting up to `MAX_DECOMPOSITION_DOC_BYTES` (1 MiB)
/// — the crate's `atomic::atomic_write` caps at 64 KiB and does NOT
/// `create_dir_all`, both unsuitable for decomposition docs. Ordering
/// (matches the `init_child_workspace` / `init_child_workspace_files`
/// discipline): `symlink_check` anchored at the tree's workspace_root
/// BEFORE `create_dir_all` (catch a pre-existing symlinked ancestor before
/// any directory is materialized through it), then a defence-in-depth
/// `symlink_check` re-check, then write-tmp + `std::fs::rename`.
fn write_state(
    tree: &AgentTreeStore,
    dir: &Path,
    state: &DecompositionState,
) -> Result<(), DecompositionError> {
    let yaml = serde_yml::to_string(state)
        .map_err(|e| DecompositionError::ParseError(format!("serialize: {e}")))?;
    if yaml.len() > MAX_DECOMPOSITION_DOC_BYTES {
        return Err(DecompositionError::InvalidConfig(format!(
            "decomposition doc {} > {MAX_DECOMPOSITION_DOC_BYTES} (1 MiB) cap",
            yaml.len()
        )));
    }
    // symlink-ancestor defense anchored at the canonical workspace_root,
    // BEFORE create_dir_all (matches the Slice-A `init_child_workspace` /
    // Slice-C `init_child_workspace_files` discipline — a pre-existing
    // symlinked ancestor must be caught before any directory is
    // materialized through it, else create_dir_all would create dirs
    // OUTSIDE workspace_root), then a defence-in-depth re-check before the
    // write.
    symlink_check(tree.workspace_root(), dir).map_err(|e| {
        DecompositionError::IoFailure(format!("symlink_check (pre-mkdir) {dir:?}: {e}"))
    })?;
    std::fs::create_dir_all(dir)
        .map_err(|e| DecompositionError::IoFailure(format!("mkdir {dir:?}: {e}")))?;
    symlink_check(tree.workspace_root(), dir).map_err(|e| {
        DecompositionError::IoFailure(format!("symlink_check (pre-write) {dir:?}: {e}"))
    })?;
    let path = state_path(dir);
    let tmp = dir.join(format!(".decomposition.{}.tmp", sub_uuid_v4()));
    std::fs::write(&tmp, yaml.as_bytes())
        .map_err(|e| DecompositionError::IoFailure(format!("write {tmp:?}: {e}")))?;
    std::fs::rename(&tmp, &path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        DecompositionError::IoFailure(format!("rename {tmp:?} → {path:?}: {e}"))
    })?;
    Ok(())
}

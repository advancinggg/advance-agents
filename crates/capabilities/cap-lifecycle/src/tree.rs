//! In-memory AgentTree data model (Slice A).
//!
//! Two public types:
//! - [`AgentTreeStore`] — live workspace_root-aware store. Implements BOTH
//!   `AgentTreeReader` and `AgentTreeSnapshot` (the supertrait bound
//!   `AgentTreeSnapshot: AgentTreeReader` forces both). The direct
//!   `AgentTreeReader` impl uses fresh per-call read-locks (best-effort).
//! - [`SnapshotReader`] — per-turn wrapper over a captured
//!   `AgentTreeSnapshotData`. Recommended pattern for CONTRACT-040
//!   Implementer Invariant 2 (per-turn consistency).
//!
//! Invariants enforced at insert time:
//! - AgentId charset/length via `validate_agent_id`.
//! - `capabilities.len() <= 64`.
//! - `node.workspace_path` is absolute + exists + canonicalized + free of
//!   `..` / hidden-name components / depth > 32 + under `workspace_root`.
//! - `insert_root` forces `node.parent = None` (rejects mismatching
//!   caller-supplied value).
//! - `insert_child(parent, node)` forces `node.parent = Some(parent.clone())`
//!   (rejects mismatching).
//! - `insert_root` rejects if a Root already exists.
//! - `remove(id)` rejects if id has children.
//! - `revision` monotonically increments on every mutation.

use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, RwLock};

use advance_shared_types::agent_tree::{
    AgentId, AgentKind, AgentNode, AgentStatus, AgentTreeReader, AgentTreeSnapshot,
    AgentTreeSnapshotData, Capability,
};

use crate::error::SpawnError;
use crate::identifier::{is_workspace_hidden_name, validate_agent_id};
use crate::workspace::MAX_PATH_DEPTH;

const MAX_CAPABILITIES: usize = 64;

/// Soft cap on AgentTreeStore size — per shared-types
/// `AgentTreeSnapshotData` Implementer Invariant
/// ("recommended ≤ 1024 agents per workspace"). Slice A enforces this as a
/// hard rejection on `insert_root` / `insert_child` to bound memory growth
/// against a buggy or compromised caller spawning agents in a tight loop.
pub const MAX_AGENTS_PER_STORE: usize = 1024;

#[derive(Debug, Default)]
struct AgentTreeInner {
    nodes: HashMap<AgentId, AgentNode>,
    children_by_parent: HashMap<AgentId, Vec<AgentId>>,
    revision: u64,
}

#[derive(Clone)]
pub struct AgentTreeStore {
    inner: Arc<RwLock<AgentTreeInner>>,
    workspace_root: PathBuf,
}

impl AgentTreeStore {
    /// Construct with canonicalized workspace_root (must exist + be a directory).
    pub fn new(workspace_root: PathBuf) -> Result<Self, SpawnError> {
        let workspace_root = workspace_root
            .canonicalize()
            .map_err(|e| SpawnError::InvalidConfig(format!("workspace_root canonicalize: {e}")))?;
        if !workspace_root.is_dir() {
            return Err(SpawnError::InvalidConfig(format!(
                "workspace_root not a directory after canonicalize: {}",
                workspace_root.display()
            )));
        }
        Ok(Self {
            inner: Arc::new(RwLock::new(AgentTreeInner::default())),
            workspace_root,
        })
    }

    /// Canonicalized workspace_root captured at construction.
    pub fn workspace_root(&self) -> &Path {
        &self.workspace_root
    }

    /// Current monotonic revision counter.
    pub fn revision(&self) -> u64 {
        self.inner.read().expect("poisoned").revision
    }

    /// `true` if `id` is registered.
    pub fn contains(&self, id: &AgentId) -> bool {
        self.inner.read().expect("poisoned").nodes.contains_key(id)
    }

    /// Clone the AgentNode if registered (used by spawner for parent territory).
    pub fn get_node(&self, id: &AgentId) -> Option<AgentNode> {
        self.inner.read().expect("poisoned").nodes.get(id).cloned()
    }

    /// Current node count (R2 adversarial W2: spawners pre-check before FS work
    /// to avoid wasted materialization at cap saturation).
    pub fn len(&self) -> usize {
        self.inner.read().expect("poisoned").nodes.len()
    }

    /// `true` if the tree has zero registered agents.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Insert the (single) Root agent. Rejects if a Root already exists.
    pub fn insert_root(&self, mut node: AgentNode) -> Result<(), SpawnError> {
        if let Some(p) = node.parent.as_ref() {
            return Err(SpawnError::InvalidConfig(format!(
                "insert_root expects node.parent == None; got Some({:?})",
                p
            )));
        }
        node.parent = None; // belt-and-suspenders
        Self::validate_node_common(&node, &self.workspace_root)?;
        let canonical_workspace = canonicalize_workspace_path(&node.workspace_path)?;
        check_workspace_path_constraints(&canonical_workspace, &self.workspace_root)?;
        node.workspace_path = canonical_workspace;
        let mut inner = self.inner.write().expect("poisoned");
        // Single-root topology in Slice A.
        if inner.nodes.values().any(|n| n.kind == AgentKind::Root) {
            return Err(SpawnError::TreeStateInvalid(
                "a Root agent is already registered".to_string(),
            ));
        }
        if inner.nodes.contains_key(&node.id) {
            return Err(SpawnError::AlreadyExists(format!("agent id {:?}", node.id)));
        }
        if inner.nodes.len() >= MAX_AGENTS_PER_STORE {
            return Err(SpawnError::TreeStateInvalid(format!(
                "tree at MAX_AGENTS_PER_STORE={MAX_AGENTS_PER_STORE} cap"
            )));
        }
        let id = node.id.clone();
        inner.nodes.insert(id.clone(), node);
        inner.children_by_parent.entry(id).or_default(); // empty children list
        inner.revision = inner.revision.saturating_add(1);
        Ok(())
    }

    /// Insert a Child or Sub agent under `parent`.
    pub fn insert_child(&self, parent: &AgentId, mut node: AgentNode) -> Result<(), SpawnError> {
        // Enforce parent_of consistency: force the parent field.
        if let Some(p) = node.parent.as_ref() {
            if p != parent {
                return Err(SpawnError::InvalidConfig(format!(
                    "insert_child(parent={:?}) but node.parent={:?}",
                    parent, p
                )));
            }
        } else {
            return Err(SpawnError::InvalidConfig(
                "insert_child requires node.parent = Some(parent_id)".to_string(),
            ));
        }
        node.parent = Some(parent.clone());
        Self::validate_node_common(&node, &self.workspace_root)?;
        let canonical_workspace = canonicalize_workspace_path(&node.workspace_path)?;
        check_workspace_path_constraints(&canonical_workspace, &self.workspace_root)?;
        node.workspace_path = canonical_workspace;
        let mut inner = self.inner.write().expect("poisoned");
        let parent_node = inner
            .nodes
            .get(parent)
            .ok_or_else(|| SpawnError::ParentNotFound(format!("{:?}", parent)))?;
        // Slice C terminate↔spawn race closure: reject inserting under a
        // parent that is mid-teardown. `set_status` and `insert_child` both
        // take `inner.write()`, so this check is ATOMIC with terminate's
        // top-down-freeze `set_status(parent, Terminated)` — there is no
        // window where a spawn observes a stale `Active` parent then inserts
        // after the parent was frozen. (MODULE-005 §2.7 terminate-child Flow.)
        if matches!(
            parent_node.status,
            AgentStatus::Terminated | AgentStatus::Failed
        ) {
            return Err(SpawnError::TreeStateInvalid(format!(
                "parent {:?} is {:?}; cannot spawn into a terminating/failed subtree",
                parent, parent_node.status
            )));
        }
        // Data-model-level Sub-cannot-nest enforcement (R2 adversarial W1 fix).
        // DefaultSpawner enforces this at the spawner edge too, but the store
        // is the strict authority — any direct caller (Slice B WIT host, test
        // fixture, future tooling) hitting insert_child cannot bypass it.
        if parent_node.kind == AgentKind::Sub {
            return Err(SpawnError::TreeStateInvalid(format!(
                "cannot insert child under Sub parent {:?} (MODULE-005 §1.2 'Can nest: No' for Sub)",
                parent
            )));
        }
        if inner.nodes.contains_key(&node.id) {
            return Err(SpawnError::AlreadyExists(format!("agent id {:?}", node.id)));
        }
        // Adversarial round-1 Warning fix (workspace_path uniqueness):
        // canonical workspace_path must not collide with an existing agent's
        // canonical workspace_path. Closes the race window where two
        // concurrent spawns target the same on-disk directory (incl. the
        // macOS/Windows case-insensitive FS bypass where the spawner's
        // lexical-join optimistic check gives false negatives but
        // canonicalize collapses to the on-disk form). insert_child is the
        // strict authority — DefaultSpawner / auto-bootstrap's optimistic
        // checks are advisory.
        for existing in inner.nodes.values() {
            if existing.workspace_path == node.workspace_path {
                return Err(SpawnError::AlreadyExists(format!(
                    "workspace_path {} already owned by agent {:?}",
                    node.workspace_path.display(),
                    existing.id
                )));
            }
        }
        if inner.nodes.len() >= MAX_AGENTS_PER_STORE {
            return Err(SpawnError::TreeStateInvalid(format!(
                "tree at MAX_AGENTS_PER_STORE={MAX_AGENTS_PER_STORE} cap"
            )));
        }
        let id = node.id.clone();
        inner.nodes.insert(id.clone(), node);
        inner
            .children_by_parent
            .entry(parent.clone())
            .or_default()
            .push(id.clone());
        inner.children_by_parent.entry(id).or_default();
        inner.revision = inner.revision.saturating_add(1);
        Ok(())
    }

    /// Remove a leaf agent (rejects if id has children).
    pub fn remove(&self, id: &AgentId) -> Result<AgentNode, SpawnError> {
        let mut inner = self.inner.write().expect("poisoned");
        let node = inner
            .nodes
            .get(id)
            .cloned()
            .ok_or_else(|| SpawnError::TreeStateInvalid(format!("not found: {:?}", id)))?;
        if let Some(children) = inner.children_by_parent.get(id) {
            if !children.is_empty() {
                return Err(SpawnError::TreeStateInvalid(format!(
                    "agent {:?} has {} children; remove them first",
                    id,
                    children.len()
                )));
            }
        }
        inner.nodes.remove(id);
        inner.children_by_parent.remove(id);
        if let Some(parent) = node.parent.as_ref() {
            if let Some(siblings) = inner.children_by_parent.get_mut(parent) {
                siblings.retain(|c| c != id);
            }
        }
        inner.revision = inner.revision.saturating_add(1);
        Ok(node)
    }

    /// Slice C — flip an existing node's `status` in place.
    ///
    /// Additive mutator mirroring the revision-bump discipline of
    /// `insert_root` / `insert_child` / `remove` (CONTRACT-040 Implementer
    /// Invariant: `revision` increments on every tree mutation, so snapshot
    /// consumers correctly invalidate caches). Absent id →
    /// `SpawnError::TreeStateInvalid` (same not-found style as `remove`) — its
    /// SOLE error path. The terminate-cascade top-down freeze TOLERATES this
    /// (a concurrently-removed leaf: skip, no recurse); `handle_crash`
    /// translates it to `LifecycleError::NotFound`. Used by the
    /// terminate-cascade top-down live-tree freeze (freeze a node before
    /// reading its children) and `handle_crash` (flip to `Failed`).
    pub fn set_status(&self, id: &AgentId, status: AgentStatus) -> Result<(), SpawnError> {
        let mut inner = self.inner.write().expect("poisoned");
        let node = inner
            .nodes
            .get_mut(id)
            .ok_or_else(|| SpawnError::TreeStateInvalid(format!("not found: {:?}", id)))?;
        node.status = status;
        inner.revision = inner.revision.saturating_add(1);
        Ok(())
    }

    fn validate_node_common(node: &AgentNode, workspace_root: &Path) -> Result<(), SpawnError> {
        validate_agent_id(&node.id.0)?;
        if node.capabilities.len() > MAX_CAPABILITIES {
            return Err(SpawnError::InvalidConfig(format!(
                "capabilities.len() {} > {}",
                node.capabilities.len(),
                MAX_CAPABILITIES
            )));
        }
        if !node.workspace_path.is_absolute() {
            return Err(SpawnError::InvalidConfig(format!(
                "node.workspace_path must be absolute: {}",
                node.workspace_path.display()
            )));
        }
        // workspace_root is a sentinel that must remain canonical post-insert; this
        // helper does not modify the workspace_path itself (caller of this helper
        // performs canonicalize). We keep the workspace_root reference for future
        // expansion (e.g., per-tenant boundaries).
        let _ = workspace_root;
        Ok(())
    }
}

fn canonicalize_workspace_path(path: &Path) -> Result<PathBuf, SpawnError> {
    path.canonicalize().map_err(|e| {
        SpawnError::InvalidConfig(format!(
            "workspace_path canonicalize ({}) — does it exist on disk? : {e}",
            path.display()
        ))
    })
}

fn check_workspace_path_constraints(
    canonical_path: &Path,
    workspace_root: &Path,
) -> Result<(), SpawnError> {
    // Components must not contain `..` (canonicalize removed these) or hidden names.
    let mut depth: usize = 0;
    for comp in canonical_path.components() {
        if let Component::Normal(s) = comp {
            let s = s.to_string_lossy();
            if is_workspace_hidden_name(&s) {
                return Err(SpawnError::InvalidConfig(format!(
                    "workspace_path contains hidden-name component {s:?}: {}",
                    canonical_path.display()
                )));
            }
            depth += 1;
        }
    }
    if depth > MAX_PATH_DEPTH {
        return Err(SpawnError::InvalidConfig(format!(
            "workspace_path depth {} > MAX_PATH_DEPTH {}",
            depth, MAX_PATH_DEPTH
        )));
    }
    if !canonical_path.starts_with(workspace_root) {
        return Err(SpawnError::InvalidConfig(format!(
            "workspace_path {} is outside workspace_root {}",
            canonical_path.display(),
            workspace_root.display()
        )));
    }
    Ok(())
}

impl AgentTreeReader for AgentTreeStore {
    fn parent_of(&self, agent_id: &str) -> Option<String> {
        if validate_agent_id(agent_id).is_err() {
            return None;
        }
        let inner = self.inner.read().expect("poisoned");
        let id = AgentId(agent_id.to_string());
        inner
            .nodes
            .get(&id)
            .and_then(|n| n.parent.as_ref().map(|p| p.0.clone()))
    }

    fn children_of(&self, agent_id: &str) -> Vec<String> {
        if validate_agent_id(agent_id).is_err() {
            return Vec::new();
        }
        let inner = self.inner.read().expect("poisoned");
        let id = AgentId(agent_id.to_string());
        inner
            .children_by_parent
            .get(&id)
            .map(|v| v.iter().map(|c| c.0.clone()).collect())
            .unwrap_or_default()
    }

    fn siblings_of(&self, agent_id: &str) -> Vec<String> {
        if validate_agent_id(agent_id).is_err() {
            return Vec::new();
        }
        let inner = self.inner.read().expect("poisoned");
        let id = AgentId(agent_id.to_string());
        match inner.nodes.get(&id).and_then(|n| n.parent.clone()) {
            Some(parent) => inner
                .children_by_parent
                .get(&parent)
                .map(|v| {
                    v.iter()
                        .filter(|c| **c != id)
                        .map(|c| c.0.clone())
                        .collect()
                })
                .unwrap_or_default(),
            None => Vec::new(),
        }
    }

    fn agent_exists(&self, agent_id: &str) -> bool {
        if validate_agent_id(agent_id).is_err() {
            return false;
        }
        let inner = self.inner.read().expect("poisoned");
        inner.nodes.contains_key(&AgentId(agent_id.to_string()))
    }

    fn agent_kind(&self, agent_id: &str) -> Option<AgentKind> {
        if validate_agent_id(agent_id).is_err() {
            return None;
        }
        let inner = self.inner.read().expect("poisoned");
        inner
            .nodes
            .get(&AgentId(agent_id.to_string()))
            .map(|n| n.kind.clone())
    }

    fn capabilities(&self, agent_id: &str) -> Vec<Capability> {
        if validate_agent_id(agent_id).is_err() {
            return Vec::new();
        }
        let inner = self.inner.read().expect("poisoned");
        inner
            .nodes
            .get(&AgentId(agent_id.to_string()))
            .map(|n| n.capabilities.clone())
            .unwrap_or_default()
    }
}

impl AgentTreeSnapshot for AgentTreeStore {
    fn snapshot(&self) -> AgentTreeSnapshotData {
        // SINGLE read-lock for the entire snapshot — atomic.
        let inner = self.inner.read().expect("poisoned");
        // Build parent_of from inner.nodes.
        let mut parent_of: HashMap<AgentId, Option<AgentId>> = HashMap::new();
        for (id, node) in inner.nodes.iter() {
            parent_of.insert(id.clone(), node.parent.clone());
        }
        // children_of: clone with sorted-by-AgentId for determinism.
        let mut children_of: HashMap<AgentId, Vec<AgentId>> = HashMap::new();
        for (p, kids) in inner.children_by_parent.iter() {
            let mut sorted = kids.clone();
            sorted.sort_by(|a, b| a.0.cmp(&b.0));
            children_of.insert(p.clone(), sorted);
        }
        // peer_slug_map: per-agent caller_id keyed; slug = shared template_ref.
        let peer_slug_map = build_peer_slug_map(&inner.nodes, &children_of, &parent_of);
        // nodes: preorder DFS (parent-before-children), sorted-by-AgentId children.
        let nodes = build_preorder_nodes(&inner.nodes, &children_of, &parent_of);
        AgentTreeSnapshotData {
            nodes,
            parent_of,
            children_of,
            peer_slug_map,
            revision: inner.revision,
        }
    }
}

fn build_peer_slug_map(
    nodes: &HashMap<AgentId, AgentNode>,
    children_of: &HashMap<AgentId, Vec<AgentId>>,
    parent_of: &HashMap<AgentId, Option<AgentId>>,
) -> HashMap<AgentId, HashMap<String, AgentId>> {
    let mut peer_slug_map = HashMap::new();
    for (a_id, a_node) in nodes.iter() {
        let parent = match parent_of.get(a_id).and_then(|p| p.clone()) {
            Some(p) => p,
            None => continue, // Root has no siblings
        };
        let a_template = match a_node.template_ref.as_deref() {
            Some(t) => t,
            None => continue, // no template_ref → no peer slug entries
        };
        let siblings = match children_of.get(&parent) {
            Some(v) => v,
            None => continue,
        };
        let mut peer_map: HashMap<String, AgentId> = HashMap::new();
        // siblings is already sorted (children_of clone above); iteration order
        // is deterministic last-wins.
        for s_id in siblings {
            if s_id == a_id {
                continue;
            }
            if let Some(s_node) = nodes.get(s_id) {
                if let Some(s_template) = s_node.template_ref.as_deref() {
                    if s_template == a_template {
                        peer_map.insert(a_template.to_string(), s_id.clone());
                    }
                }
            }
        }
        if !peer_map.is_empty() {
            peer_slug_map.insert(a_id.clone(), peer_map);
        }
    }
    peer_slug_map
}

fn build_preorder_nodes(
    nodes_map: &HashMap<AgentId, AgentNode>,
    children_of: &HashMap<AgentId, Vec<AgentId>>,
    parent_of: &HashMap<AgentId, Option<AgentId>>,
) -> Vec<AgentNode> {
    // Find Root(s) by parent_of[_] == None.
    let mut roots: Vec<AgentId> = parent_of
        .iter()
        .filter_map(|(id, p)| if p.is_none() { Some(id.clone()) } else { None })
        .collect();
    roots.sort_by(|a, b| a.0.cmp(&b.0));
    let mut out: Vec<AgentNode> = Vec::with_capacity(nodes_map.len());
    for root in roots {
        push_preorder(&root, nodes_map, children_of, &mut out);
    }
    out
}

fn push_preorder(
    id: &AgentId,
    nodes_map: &HashMap<AgentId, AgentNode>,
    children_of: &HashMap<AgentId, Vec<AgentId>>,
    out: &mut Vec<AgentNode>,
) {
    if let Some(node) = nodes_map.get(id) {
        out.push(node.clone());
    }
    if let Some(kids) = children_of.get(id) {
        // kids already sorted in build_peer_slug_map's prep; clone-sort defensively.
        let mut sorted = kids.clone();
        sorted.sort_by(|a, b| a.0.cmp(&b.0));
        for child in sorted {
            push_preorder(&child, nodes_map, children_of, out);
        }
    }
}

/// Per-turn `AgentTreeReader` over a captured `AgentTreeSnapshotData`.
///
/// Recommended pattern for CONTRACT-040 Implementer Invariant 2 ("per-turn
/// read consistency"). Consumers call `store.snapshot()` once at turn-entry,
/// wrap in `SnapshotReader::new(snap)`, and use that as `&dyn AgentTreeReader`
/// for the rest of the turn.
pub struct SnapshotReader {
    data: AgentTreeSnapshotData,
}

impl SnapshotReader {
    pub fn new(data: AgentTreeSnapshotData) -> Self {
        Self { data }
    }

    pub fn data(&self) -> &AgentTreeSnapshotData {
        &self.data
    }
}

impl AgentTreeReader for SnapshotReader {
    fn parent_of(&self, agent_id: &str) -> Option<String> {
        if validate_agent_id(agent_id).is_err() {
            return None;
        }
        let id = AgentId(agent_id.to_string());
        self.data.parent_of.get(&id).cloned().flatten().map(|p| p.0)
    }

    fn children_of(&self, agent_id: &str) -> Vec<String> {
        if validate_agent_id(agent_id).is_err() {
            return Vec::new();
        }
        let id = AgentId(agent_id.to_string());
        self.data
            .children_of
            .get(&id)
            .map(|v| v.iter().map(|c| c.0.clone()).collect())
            .unwrap_or_default()
    }

    fn siblings_of(&self, agent_id: &str) -> Vec<String> {
        if validate_agent_id(agent_id).is_err() {
            return Vec::new();
        }
        let id = AgentId(agent_id.to_string());
        match self.data.parent_of.get(&id).cloned().flatten() {
            Some(parent) => self
                .data
                .children_of
                .get(&parent)
                .map(|v| {
                    v.iter()
                        .filter(|c| **c != id)
                        .map(|c| c.0.clone())
                        .collect()
                })
                .unwrap_or_default(),
            None => Vec::new(),
        }
    }

    fn agent_exists(&self, agent_id: &str) -> bool {
        if validate_agent_id(agent_id).is_err() {
            return false;
        }
        let id = AgentId(agent_id.to_string());
        self.data.parent_of.contains_key(&id)
    }

    fn agent_kind(&self, agent_id: &str) -> Option<AgentKind> {
        if validate_agent_id(agent_id).is_err() {
            return None;
        }
        self.data
            .nodes
            .iter()
            .find(|n| n.id.0 == agent_id)
            .map(|n| n.kind.clone())
    }

    fn capabilities(&self, agent_id: &str) -> Vec<Capability> {
        if validate_agent_id(agent_id).is_err() {
            return Vec::new();
        }
        self.data
            .nodes
            .iter()
            .find(|n| n.id.0 == agent_id)
            .map(|n| n.capabilities.clone())
            .unwrap_or_default()
    }
}

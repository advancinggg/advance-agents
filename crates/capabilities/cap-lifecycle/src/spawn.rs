//! Slice-A spawn API: spawn-child + spawn-sub.
//!
//! Synchronous Rust API. Slice A ships NO library-side SubsetGate impl;
//! tests define `AlwaysOkGate` / `AlwaysFailGate` in the test crate.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use advance_shared_types::agent_tree::{AgentId, AgentKind, AgentNode, AgentStatus, Capability};

use crate::error::SpawnError;
use crate::identifier::{sub_uuid_v4, validate_agent_id};
use crate::templates::{apply_template, TemplateError, TemplateResolver};
use crate::tree::{AgentTreeStore, MAX_AGENTS_PER_STORE};
use crate::workspace::{init_child_workspace, resolve_under_parent, symlink_check};

const MAX_CAPABILITIES: usize = 64;

/// Wave-23 seam (a): upper bound on a materialized child driver binary. Generous
/// (a real component is typically < a few MiB) but bounded so a compromised
/// caller cannot spray arbitrarily-large workspace writes.
const MAX_CHILD_BINARY: usize = 32 * 1024 * 1024;
/// Wasm binary magic (`\0asm`) — shared by core modules and components.
const WASM_MAGIC: [u8; 4] = [0x00, 0x61, 0x73, 0x6d];

/// Wave-23 seam (a): materialize a spawned child's driver bytes to
/// `<target_dir>/.agent/behavior.component.wasm` so the daemon loader
/// (`resolve_driver_component_bytes`) can load + serve it. Policy: empty → skip
/// (no driver); size-capped; wasm-magic-validated BEFORE any write (garbage is
/// never recorded as a live driver); atomic (temp + rename); symlink-guarded. On
/// any failure the workspace is rolled back (conditional on `target_pre_existed`)
/// so a half-written driver never survives.
fn materialize_child_behavior(
    target_dir: &Path,
    bytes: &[u8],
    target_pre_existed: bool,
    workspace_root: &Path,
) -> Result<(), SpawnError> {
    if bytes.is_empty() {
        return Ok(());
    }
    if bytes.len() > MAX_CHILD_BINARY {
        rollback_target_dir(target_dir, target_pre_existed, workspace_root);
        return Err(SpawnError::InvalidConfig(format!(
            "child binary {} bytes exceeds MAX_CHILD_BINARY={MAX_CHILD_BINARY}",
            bytes.len()
        )));
    }
    if bytes.len() < 8 || bytes[0..4] != WASM_MAGIC {
        rollback_target_dir(target_dir, target_pre_existed, workspace_root);
        return Err(SpawnError::InvalidConfig(
            "child binary is not a wasm module/component (bad magic)".to_string(),
        ));
    }
    let agent_dir = target_dir.join(".agent");
    // Defense-in-depth: reject an attacker-planted symlink on the child `.agent`
    // path before writing (mirrors rollback_target_dir's posture).
    if symlink_check(workspace_root, &agent_dir).is_err() {
        rollback_target_dir(target_dir, target_pre_existed, workspace_root);
        return Err(SpawnError::PathTraversal(
            "symlink on child .agent path — refusing to write behavior".to_string(),
        ));
    }
    let final_path = agent_dir.join("behavior.component.wasm");
    let tmp_path = agent_dir.join(".behavior.component.wasm.tmp");
    if let Err(e) = std::fs::write(&tmp_path, bytes) {
        let _ = std::fs::remove_file(&tmp_path);
        rollback_target_dir(target_dir, target_pre_existed, workspace_root);
        return Err(SpawnError::WorkspaceIoFailure(format!(
            "write child behavior temp: {e}"
        )));
    }
    if let Err(e) = std::fs::rename(&tmp_path, &final_path) {
        let _ = std::fs::remove_file(&tmp_path);
        rollback_target_dir(target_dir, target_pre_existed, workspace_root);
        return Err(SpawnError::WorkspaceIoFailure(format!(
            "rename child behavior: {e}"
        )));
    }
    Ok(())
}

/// Per-variant `TemplateError → SpawnError` mapping. Preserves
/// `PathTraversal` to avoid info loss; routes NotFound + InvalidContent
/// as `InvalidConfig` (template-config issues); routes
/// MaterializationFailure as `WorkspaceIoFailure` (real IO).
fn map_template_err(e: TemplateError) -> SpawnError {
    match e {
        TemplateError::NotFound(name) => {
            SpawnError::InvalidConfig(format!("template '{name}' not found"))
        }
        TemplateError::InvalidContent(msg) => {
            SpawnError::InvalidConfig(format!("template content invalid: {msg}"))
        }
        TemplateError::PathTraversal(msg) => SpawnError::PathTraversal(msg),
        TemplateError::MaterializationFailure(msg) => {
            SpawnError::WorkspaceIoFailure(format!("apply_template: {msg}"))
        }
    }
}

/// Roll back the target_dir created by init_child_workspace iff it did
/// not exist before this spawn call. Mirrors Slice A's
/// `target_pre_existed` discipline (workspace.rs:178/236) so a caller's
/// pre-existing directory is never wiped.
///
/// Adversarial round-1 Warning fix (TOCTOU on rollback): re-run
/// `symlink_check` from the canonical `workspace_root` to `target_dir`
/// before any `remove_dir_all` so a workspace-local race attacker who
/// plants `target_dir` or ANY of its ancestors inside the workspace as
/// a symlink between init_child_workspace's check and this rollback
/// cannot redirect the removal outside the workspace. Adversarial
/// round-4 Warning fix: anchor the symlink walk at `workspace_root`
/// (was `target_dir.parent()`), matching apply_template's
/// symlink_check call site, so attacker-planted symlinks at any
/// ancestor above target_dir.parent() are also caught.
fn rollback_target_dir(target_dir: &Path, target_pre_existed: bool, workspace_root: &Path) {
    use crate::workspace::symlink_check;
    if let Ok(meta) = std::fs::symlink_metadata(target_dir) {
        if meta.file_type().is_symlink() {
            // target_dir itself is now a symlink — abort rollback to
            // prevent traversing an attacker-planted link target.
            return;
        }
    }
    // Walk component-wise from the canonical workspace_root. Any
    // attacker-planted symlink in the workspace path → abort rollback.
    if symlink_check(workspace_root, target_dir).is_err() {
        return;
    }
    let _ = std::fs::remove_dir_all(target_dir.join(".agent"));
    if !target_pre_existed {
        let _ = std::fs::remove_dir_all(target_dir);
    }
}

/// Apply a template overlay to a freshly-materialized target_dir; on
/// failure, conditionally roll back per `target_pre_existed` (the
/// Slice A `tree.insert_child` rollback only fires on insert_child
/// failure, so the apply_template-failure window needs its own
/// rollback branch).
fn apply_template_with_rollback(
    target_dir: &Path,
    target_pre_existed: bool,
    template_ref: &str,
    resolver: &dyn TemplateResolver,
    kind: AgentKind,
    workspace_root: &Path,
) -> Result<(), SpawnError> {
    let template = match resolver.resolve(template_ref) {
        Ok(t) => t,
        Err(e) => {
            rollback_target_dir(target_dir, target_pre_existed, workspace_root);
            return Err(map_template_err(e));
        }
    };
    if let Err(e) = apply_template(target_dir, &template, kind, workspace_root) {
        rollback_target_dir(target_dir, target_pre_existed, workspace_root);
        return Err(map_template_err(e));
    }
    Ok(())
}

/// CONTRACT-122 subset-gate seam. Slice A shipped the trait only; tests
/// provide their own impls inside the `tests/` crate. Slice E
/// (m013-slice-e, 2026-05-23) added the production `CapGrantSubsetAdapter`
/// impl in `cap_grant_adapter.rs`, which wraps cap-grant's Capability-first
/// `validate_capability_subset` entry (fail-closed projection from
/// `shared_types::Capability` into the cap-grant internal model).
pub trait SpawnerSubsetGate: Send + Sync {
    /// Returns `Err(SpawnError::SubsetViolation(_))` on violation.
    fn check(&self, parent: &[Capability], child: &[Capability]) -> Result<(), SpawnError>;
}

pub struct SpawnChildConfig {
    pub parent_id: AgentId,
    pub child_id: AgentId,
    /// Relative to parent's workspace_path. Absolute paths are rejected.
    pub child_workspace_path: PathBuf,
    pub capabilities: Vec<Capability>,
    pub template_ref: Option<String>,
    /// Wave-23 `perchild-daemon-1` seam (a): the child's component/core wasm bytes
    /// (the WIT `child-agent-config.binary`). When `Some(non-empty)`, `spawn_child`
    /// materializes `<child_ws>/.agent/behavior.component.wasm` so the daemon's
    /// `resolve_driver_component_bytes(child_ws)` finds a loadable driver → the
    /// child becomes a LIVE served agent. `None`/empty → no driver written (a
    /// template/preset-sourced child, or a driverless node) — byte-identical to
    /// pre-Wave-23 spawn behaviour.
    pub binary: Option<Vec<u8>>,
}

pub struct SpawnSubConfig {
    pub parent_id: AgentId,
    pub capabilities: Vec<Capability>,
    pub template_ref: Option<String>,
}

pub trait Spawner: Send + Sync {
    fn spawn_child(&self, cfg: SpawnChildConfig) -> Result<AgentId, SpawnError>;
    fn spawn_sub(&self, cfg: SpawnSubConfig) -> Result<AgentId, SpawnError>;
}

/// Wave-23 `perchild-daemon-1` seam (b): a spawn→daemon observer the composition
/// root registers so it learns of a newly-inserted child `AgentTreeStore` node.
/// [`DefaultSpawner::spawn_child`] stays pure tree+fs — the observer is an ADDITIVE
/// post-commit hook (fired ONCE after a successful `insert_child`, so a spawn that
/// fails never notifies). The impl lives in the cli composition root (MODULE-001)
/// and drives per-child driver load + serve-loop registration + dynamic routing +
/// grant delegation; cap-lifecycle only declares the seam. Must not panic (it runs
/// inside the sync spawn path); a slow/failing observer must fail-soft.
pub trait SpawnObserver: Send + Sync {
    /// Invoked once, post-`insert_child`, with the newly-live child's BARE
    /// `parent`/`child` ids and its materialized `workspace` path.
    fn on_child_spawned(&self, parent: &AgentId, child: &AgentId, workspace: &Path);
}

#[derive(Clone)]
pub struct DefaultSpawner {
    tree: AgentTreeStore,
    subset_gate: Arc<dyn SpawnerSubsetGate>,
    resolver: Option<Arc<dyn TemplateResolver>>,
    /// Wave-23 seam (b): optional spawn→daemon observer. `None` (default) → no
    /// notification (byte-identical to pre-Wave-23). Set via the CHAINABLE
    /// [`DefaultSpawner::with_spawn_observer`] so it composes WITH
    /// [`DefaultSpawner::with_template_resolver`] rather than replacing it.
    spawn_observer: Option<Arc<dyn SpawnObserver>>,
}

impl DefaultSpawner {
    /// Infallible — workspace_root canonicalization is performed by
    /// `AgentTreeStore::new`; DefaultSpawner inherits via `tree.workspace_root()`.
    /// `resolver = None`: spawns with `template_ref: Some(_)` will surface
    /// `SpawnError::InvalidConfig`. Use [`Self::with_template_resolver`]
    /// to opt into template materialization.
    pub fn new(tree: AgentTreeStore, subset_gate: Arc<dyn SpawnerSubsetGate>) -> Self {
        Self {
            tree,
            subset_gate,
            resolver: None,
            spawn_observer: None,
        }
    }

    /// Slice B additive constructor: opt in to template materialization.
    /// Spawns with `template_ref: Some(name)` will resolve via `resolver`
    /// and call `apply_template` on the freshly-materialized target_dir.
    pub fn with_template_resolver(
        tree: AgentTreeStore,
        subset_gate: Arc<dyn SpawnerSubsetGate>,
        resolver: Arc<dyn TemplateResolver>,
    ) -> Self {
        Self {
            tree,
            subset_gate,
            resolver: Some(resolver),
            spawn_observer: None,
        }
    }

    /// Wave-23 seam (b): CHAINABLE — attach a [`SpawnObserver`] while preserving
    /// any previously-configured resolver. `spawner.with_template_resolver(..).with_spawn_observer(obs)`
    /// keeps template materialization working AND fires the observer post-spawn.
    pub fn with_spawn_observer(mut self, observer: Arc<dyn SpawnObserver>) -> Self {
        self.spawn_observer = Some(observer);
        self
    }

    pub fn tree(&self) -> &AgentTreeStore {
        &self.tree
    }

    fn apply_template_if_configured(
        &self,
        target_dir: &Path,
        target_pre_existed: bool,
        template_ref: Option<&str>,
        kind: AgentKind,
    ) -> Result<(), SpawnError> {
        match (template_ref, self.resolver.as_ref()) {
            (None, _) => Ok(()),
            (Some(_), None) => {
                rollback_target_dir(target_dir, target_pre_existed, self.tree.workspace_root());
                Err(SpawnError::InvalidConfig(
                    "template_ref set but no TemplateResolver configured on spawner".to_string(),
                ))
            }
            (Some(name), Some(resolver)) => apply_template_with_rollback(
                target_dir,
                target_pre_existed,
                name,
                resolver.as_ref(),
                kind,
                self.tree.workspace_root(),
            ),
        }
    }
}

impl Spawner for DefaultSpawner {
    fn spawn_child(&self, cfg: SpawnChildConfig) -> Result<AgentId, SpawnError> {
        validate_agent_id(&cfg.parent_id.0)?;
        if !self.tree.contains(&cfg.parent_id) {
            return Err(SpawnError::ParentNotFound(format!("{:?}", cfg.parent_id)));
        }
        validate_agent_id(&cfg.child_id.0)?;
        if self.tree.contains(&cfg.child_id) {
            return Err(SpawnError::AlreadyExists(format!("{:?}", cfg.child_id)));
        }
        if cfg.capabilities.len() > MAX_CAPABILITIES {
            return Err(SpawnError::InvalidConfig(format!(
                "capabilities.len() {} > {MAX_CAPABILITIES}",
                cfg.capabilities.len()
            )));
        }
        let parent = self
            .tree
            .get_node(&cfg.parent_id)
            .ok_or_else(|| SpawnError::ParentNotFound(format!("{:?}", cfg.parent_id)))?;
        if parent.kind == AgentKind::Sub {
            return Err(SpawnError::InvalidConfig(
                "Sub agents cannot have children (MODULE-005 §1.2 'Can nest: No' for Sub)"
                    .to_string(),
            ));
        }
        // Slice A territory guard: spawn_child must not materialize inside the
        // `.sub/` ephemeral namespace owned by spawn_sub, NOR inside the `.agent/`
        // hidden namespace owned by M005's per-agent skeleton. is_workspace_hidden_name
        // intentionally does NOT block `.sub` or `.agent` (spawn_sub needs `.sub`;
        // init_child_workspace creates `.agent/` itself). We enforce the separation
        // here in the spawn_child code path only.
        //
        // Case-insensitive match (matches identifier::is_workspace_hidden_name posture)
        // — defends against `.SUB` / `.Agent` / etc. on HFS+ / APFS-case-insensitive /
        // NTFS where the filesystem treats them as the same directory.
        for comp in cfg.child_workspace_path.components() {
            if let std::path::Component::Normal(s) = comp {
                let s = s.to_string_lossy();
                if s.eq_ignore_ascii_case(".sub") {
                    return Err(SpawnError::PathTraversal(
                        "child_workspace_path cannot contain `.sub` component (reserved for spawn_sub)"
                            .to_string(),
                    ));
                }
                if s.eq_ignore_ascii_case(".agent") {
                    return Err(SpawnError::PathTraversal(
                        "child_workspace_path cannot contain `.agent` component (reserved for M005 hidden namespace)"
                            .to_string(),
                    ));
                }
            }
        }
        self.subset_gate
            .check(&parent.capabilities, &cfg.capabilities)?;
        // Pre-flight cap check (R2 adversarial W2 fix): reject before any FS work
        // so a buggy/compromised caller spamming spawn at cap saturation does not
        // churn the filesystem. The authoritative cap check stays in
        // AgentTreeStore::insert_child for race-safe rejection.
        if self.tree.len() >= MAX_AGENTS_PER_STORE {
            return Err(SpawnError::TreeStateInvalid(format!(
                "tree at MAX_AGENTS_PER_STORE={MAX_AGENTS_PER_STORE} cap (pre-flight)"
            )));
        }
        let target_dir = resolve_under_parent(
            &parent.workspace_path,
            &cfg.child_workspace_path,
            self.tree.workspace_root(),
        )?;
        // Capture pre-existence so rollback respects the caller's tree.
        let target_pre_existed = target_dir.exists();
        init_child_workspace(&target_dir, AgentKind::Child, self.tree.workspace_root())?;
        self.apply_template_if_configured(
            &target_dir,
            target_pre_existed,
            cfg.template_ref.as_deref(),
            AgentKind::Child,
        )?;
        // Wave-23 seam (a): materialize the child's driver so it is RUNNABLE
        // (before the tree commit, so a driver-write failure rolls back cleanly
        // and the node is never inserted for an un-materializable child).
        if let Some(bytes) = cfg.binary.as_deref() {
            materialize_child_behavior(
                &target_dir,
                bytes,
                target_pre_existed,
                self.tree.workspace_root(),
            )?;
        }
        let node = AgentNode {
            id: cfg.child_id.clone(),
            kind: AgentKind::Child,
            parent: Some(cfg.parent_id.clone()),
            workspace_path: target_dir.clone(),
            capabilities: cfg.capabilities,
            template_ref: cfg.template_ref,
            status: AgentStatus::Active,
        };
        if let Err(insert_err) = self.tree.insert_child(&cfg.parent_id, node) {
            // best-effort rollback of materialization, conditional on
            // target_pre_existed so a caller's pre-existing directory survives.
            rollback_target_dir(&target_dir, target_pre_existed, self.tree.workspace_root());
            return Err(SpawnError::TreeStateInvalid(format!(
                "insert_child failed: {insert_err}; rollback attempted on {}",
                target_dir.display()
            )));
        }
        // Wave-23 seam (b): fire the spawn→daemon observer ONCE, post-commit, so
        // the composition root can load + serve the child + register routing +
        // delegate the grant. `spawn_child` itself stays pure tree+fs.
        if let Some(observer) = &self.spawn_observer {
            observer.on_child_spawned(&cfg.parent_id, &cfg.child_id, &target_dir);
        }
        Ok(cfg.child_id)
    }

    fn spawn_sub(&self, cfg: SpawnSubConfig) -> Result<AgentId, SpawnError> {
        validate_agent_id(&cfg.parent_id.0)?;
        if !self.tree.contains(&cfg.parent_id) {
            return Err(SpawnError::ParentNotFound(format!("{:?}", cfg.parent_id)));
        }
        let parent = self
            .tree
            .get_node(&cfg.parent_id)
            .ok_or_else(|| SpawnError::ParentNotFound(format!("{:?}", cfg.parent_id)))?;
        if parent.kind == AgentKind::Sub {
            return Err(SpawnError::InvalidConfig(
                "Sub agents cannot spawn children (MODULE-005 §1.2 'Can nest: No' for Sub)"
                    .to_string(),
            ));
        }
        if cfg.capabilities.len() > MAX_CAPABILITIES {
            return Err(SpawnError::InvalidConfig(format!(
                "capabilities.len() {} > {MAX_CAPABILITIES}",
                cfg.capabilities.len()
            )));
        }
        self.subset_gate
            .check(&parent.capabilities, &cfg.capabilities)?;
        // Pre-flight cap check (R2 adversarial W2 fix): same as spawn_child.
        if self.tree.len() >= MAX_AGENTS_PER_STORE {
            return Err(SpawnError::TreeStateInvalid(format!(
                "tree at MAX_AGENTS_PER_STORE={MAX_AGENTS_PER_STORE} cap (pre-flight)"
            )));
        }
        // Generate UUID for sub_id; up to 4 attempts total (1 initial + 3 retries).
        // Collision space is 2^122; effectively unreachable, but bounded for sanity.
        const MAX_UUID_ATTEMPTS: usize = 4;
        let mut sub_id_str = String::new();
        let mut attempts = 0;
        for _ in 0..MAX_UUID_ATTEMPTS {
            attempts += 1;
            sub_id_str = sub_uuid_v4();
            if !self.tree.contains(&AgentId(sub_id_str.clone())) {
                break;
            }
        }
        let sub_id = AgentId(sub_id_str.clone());
        if self.tree.contains(&sub_id) {
            return Err(SpawnError::AlreadyExists(format!(
                "exhausted {attempts} UUID v4 attempts",
            )));
        }
        // Derive sub_target via resolve_under_parent for territory containment.
        let rel_sub = PathBuf::from(".sub").join(&sub_id_str);
        // .sub is NOT a hidden name per is_workspace_hidden_name; resolve will accept it.
        // BUT resolve_under_parent walks components for is_workspace_hidden_name; .sub passes.
        // sub_uuid_v4 output also passes (alphanumeric + hyphen).
        let sub_target =
            resolve_under_parent(&parent.workspace_path, &rel_sub, self.tree.workspace_root())?;
        // Capture pre-existence so rollback respects the caller's tree.
        let sub_target_pre_existed = sub_target.exists();
        init_child_workspace(&sub_target, AgentKind::Sub, self.tree.workspace_root())?;
        self.apply_template_if_configured(
            &sub_target,
            sub_target_pre_existed,
            cfg.template_ref.as_deref(),
            AgentKind::Sub,
        )?;
        let node = AgentNode {
            id: sub_id.clone(),
            kind: AgentKind::Sub,
            parent: Some(cfg.parent_id.clone()),
            workspace_path: sub_target.clone(),
            capabilities: cfg.capabilities,
            template_ref: cfg.template_ref,
            status: AgentStatus::Active,
        };
        if let Err(insert_err) = self.tree.insert_child(&cfg.parent_id, node) {
            rollback_target_dir(
                &sub_target,
                sub_target_pre_existed,
                self.tree.workspace_root(),
            );
            return Err(SpawnError::TreeStateInvalid(format!(
                "insert_child failed: {insert_err}; rollback attempted on {}",
                sub_target.display()
            )));
        }
        Ok(sub_id)
    }
}

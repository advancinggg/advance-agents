//! PACK-GAP-CLOSURE P2 (§3.4, #10) — production implementations of the
//! pack-manager seams that had only test doubles:
//!
//! - [`SecretStore`] → [`CapSecretsSecretStore`] over the daemon's cap-secrets
//!   store (master-key-encrypted `<ws>/.advance/secrets.json`), plus
//!   [`ClosureSecretStore`] for tests / embedders;
//! - [`DependencyResolver`] → [`LocalDirDependencyResolver`] (a directory of
//!   `{name}@{version}/` pack sources) and [`RegistryDependencyResolver`]
//!   (`RegistryClient::list_versions`); both pick the HIGHEST stable
//!   (non-pre-release) version satisfying the range, fail-closed to
//!   `DependencyNotFound`;
//! - [`WorkflowExecutor`] → [`SchedulerWorkflowExecutor`]: `spawn-child` through
//!   the production `Spawner` (the same template-resolving `DefaultSpawner` the
//!   guest `spawn-child` host-fn uses), `submit-component` through the
//!   scheduler's `ComponentSubmitApi` (admission rules, quota, subset gate),
//!   `register-mcp-server` through the `PackMcpBridge` (trust + secrets) into an
//!   [`McpEntrySink`], and the §3.5 compensations `terminate_child` (tree node +
//!   workspace) / `withdraw_component` (`kill_component`).
//!
//! The boot-time `PackWiring` is built BEFORE the spawner, the scheduler API and
//! the secret store exist (they depend on the template resolver / master key it
//! provides), so the materializer is composed over [`LateBoundWorkflowExecutor`] /
//! [`LateBoundSecretStore`] — one-shot slots the composition root fills once the
//! real objects exist. Until then every leg fails closed (`NotImplemented` /
//! no secret), exactly as P1's unwired stubs did; nothing silently succeeds.

use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, OnceLock};

use advance_pack_manager::{
    DependencyResolver, McpServerId, PackError, PackRegistry, RegistryClient, SecretStore,
    SecretValue, SourceRef, WorkflowExecutor, WorkflowTrigger,
};
use advance_scheduler::types::{ComponentSubmitConfig, TriggerConfig, TriggerSubscription};
use advance_scheduler::ComponentSubmitApi;
use advance_shared_types::agent_tree::AgentId;
use advance_shared_types::component::ComponentType;
use async_trait::async_trait;
use cap_lifecycle::{
    validate_agent_id, AgentTreeStore, SpawnChildConfig, Spawner, TerminateController,
};
use secrecy::ExposeSecret;

use crate::pack_bridges::{McpEntrySink, PackBridgeError, PackMcpBridge};

// ───────────────────────────── SecretStore ─────────────────────────────

/// `SecretStore` over a closure — tests and embedders that already hold their
/// secrets elsewhere.
pub struct ClosureSecretStore(Box<dyn Fn(&str) -> Option<String> + Send + Sync>);

impl ClosureSecretStore {
    pub fn new(f: impl Fn(&str) -> Option<String> + Send + Sync + 'static) -> Self {
        Self(Box::new(f))
    }
}

impl SecretStore for ClosureSecretStore {
    fn get(&self, key: &str) -> Option<SecretValue> {
        (self.0)(key).map(SecretValue::new)
    }
}

/// `SecretStore` over the daemon's cap-secrets store: `get(key)` resolves and
/// decrypts `key`; any failure (absent, undecryptable, storage error) is `None`
/// — the pack layer then reports `MissingSecret` for the key, never the cause.
pub struct CapSecretsSecretStore {
    store: Arc<cap_secrets::SecretStore>,
}

impl CapSecretsSecretStore {
    pub fn new(store: Arc<cap_secrets::SecretStore>) -> Self {
        Self { store }
    }
}

impl SecretStore for CapSecretsSecretStore {
    fn get(&self, key: &str) -> Option<SecretValue> {
        self.store
            .resolve(key)
            .ok()
            .map(|s| SecretValue::new(s.expose_secret().as_str()))
    }
}

/// Returned by the late-bound slots when `bind` is called twice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AlreadyBound;

impl std::fmt::Display for AlreadyBound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("slot already bound")
    }
}

impl std::error::Error for AlreadyBound {}

/// One-shot `SecretStore` slot: resolves nothing until [`bind`](Self::bind).
#[derive(Default)]
pub struct LateBoundSecretStore {
    inner: OnceLock<Arc<dyn SecretStore>>,
}

impl LateBoundSecretStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn bind(&self, store: Arc<dyn SecretStore>) -> Result<(), AlreadyBound> {
        self.inner.set(store).map_err(|_| AlreadyBound)
    }

    pub fn is_bound(&self) -> bool {
        self.inner.get().is_some()
    }
}

impl SecretStore for LateBoundSecretStore {
    fn get(&self, key: &str) -> Option<SecretValue> {
        self.inner.get().and_then(|s| s.get(key))
    }
}

/// One-shot `WorkflowExecutor` slot: every leg is `NotImplemented` until
/// [`bind`](Self::bind) installs the production executor.
#[derive(Default)]
pub struct LateBoundWorkflowExecutor {
    inner: OnceLock<Arc<dyn WorkflowExecutor>>,
}

impl LateBoundWorkflowExecutor {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn bind(&self, executor: Arc<dyn WorkflowExecutor>) -> Result<(), AlreadyBound> {
        self.inner.set(executor).map_err(|_| AlreadyBound)
    }

    pub fn is_bound(&self) -> bool {
        self.inner.get().is_some()
    }

    fn bound(&self) -> Result<&Arc<dyn WorkflowExecutor>, PackError> {
        self.inner.get().ok_or(PackError::NotImplemented(
            "workflow executor not bound: the composition root has not installed the \
             production SchedulerWorkflowExecutor (lifecycle/scheduler not wired)",
        ))
    }
}

impl WorkflowExecutor for LateBoundWorkflowExecutor {
    fn spawn_child(
        &self,
        template_ref: &str,
        target_path: &Path,
        config: &BTreeMap<String, serde_yml::Value>,
    ) -> Result<(), PackError> {
        self.bound()?.spawn_child(template_ref, target_path, config)
    }

    fn submit_component(
        &self,
        component_ref: &str,
        trigger: &WorkflowTrigger,
    ) -> Result<(), PackError> {
        self.bound()?.submit_component(component_ref, trigger)
    }

    fn register_mcp_server(
        &self,
        config_ref: &str,
        resolved_secrets: &BTreeMap<String, SecretValue>,
    ) -> Result<McpServerId, PackError> {
        self.bound()?
            .register_mcp_server(config_ref, resolved_secrets)
    }

    fn terminate_child(&self, target_path: &Path) -> Result<(), PackError> {
        self.bound()?.terminate_child(target_path)
    }

    fn withdraw_component(&self, component_ref: &str) -> Result<(), PackError> {
        self.bound()?.withdraw_component(component_ref)
    }
}

// ─────────────────────────── DependencyResolver ────────────────────────

/// Highest stable version in `versions` satisfying `req` (pre-releases never
/// match — a dependency range must not be satisfied by a preview build).
fn pick_highest_stable(
    versions: impl IntoIterator<Item = semver::Version>,
    req: &semver::VersionReq,
) -> Option<semver::Version> {
    versions
        .into_iter()
        .filter(|v| v.pre.is_empty() && req.matches(v))
        .max()
}

/// Resolves `name` to `{root}/{name}@{version}/` (a directory of pack sources,
/// e.g. a vendored bundle) → `SourceRef::Local`.
pub struct LocalDirDependencyResolver {
    root: PathBuf,
}

impl LocalDirDependencyResolver {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
}

#[async_trait]
impl DependencyResolver for LocalDirDependencyResolver {
    async fn resolve(&self, name: &str, req: &semver::VersionReq) -> Result<SourceRef, PackError> {
        let not_found = || PackError::DependencyNotFound {
            name: name.to_string(),
            version_req: req.to_string(),
        };
        let read_dir = match std::fs::read_dir(&self.root) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(not_found()),
            Err(e) => {
                return Err(PackError::Io {
                    path: self.root.clone(),
                    source: e,
                })
            }
        };
        let mut candidates: Vec<(semver::Version, PathBuf)> = Vec::new();
        for entry in read_dir {
            let entry = entry.map_err(|e| PackError::Io {
                path: self.root.clone(),
                source: e,
            })?;
            // Real directories only — a symlinked `{name}@{ver}` is not a source.
            match std::fs::symlink_metadata(entry.path()) {
                Ok(md) if md.is_dir() => {}
                _ => continue,
            }
            let Some(file_name) = entry.file_name().to_str().map(str::to_string) else {
                continue;
            };
            let Some((n, v)) = file_name.rsplit_once('@') else {
                continue;
            };
            if n != name {
                continue;
            }
            if let Ok(version) = semver::Version::parse(v) {
                candidates.push((version, entry.path()));
            }
        }
        let best = pick_highest_stable(candidates.iter().map(|(v, _)| v.clone()), req)
            .ok_or_else(not_found)?;
        let path = candidates
            .into_iter()
            .find(|(v, _)| *v == best)
            .map(|(_, p)| p)
            .ok_or_else(not_found)?;
        Ok(SourceRef::Local(path))
    }
}

/// Resolves through `RegistryClient::list_versions` → `SourceRef::Registry`.
pub struct RegistryDependencyResolver {
    client: Arc<dyn RegistryClient>,
}

impl RegistryDependencyResolver {
    pub fn new(client: Arc<dyn RegistryClient>) -> Self {
        Self { client }
    }
}

#[async_trait]
impl DependencyResolver for RegistryDependencyResolver {
    async fn resolve(&self, name: &str, req: &semver::VersionReq) -> Result<SourceRef, PackError> {
        let versions = self.client.list_versions(name).await?;
        let best =
            pick_highest_stable(versions, req).ok_or_else(|| PackError::DependencyNotFound {
                name: name.to_string(),
                version_req: req.to_string(),
            })?;
        Ok(SourceRef::Registry {
            name: name.to_string(),
            version: best.to_string(),
        })
    }
}

// ─────────────────────────── WorkflowExecutor ──────────────────────────

/// The production `WorkflowExecutor` (see the module docs).
///
/// `spawn-child`: the workflow's `target-path` (validated by the applier
/// against `WorkflowContext::target_workspace`) is taken RELATIVE to the parent
/// agent's workspace (a leading `/` is stripped); its last component is the
/// child's agent id. The child gets the template by FQ ref, NO capabilities
/// (grants are a separate, admin-visible step) and no driver binary. A
/// non-empty `config:` is refused — the production spawner has no config slot
/// and a silently dropped config would be a lie.
///
/// `submit-component`: the component's `component.yaml` is resolved through the
/// registry (`resolve_pack_component`: runnable-kind constraint + binary +
/// capability requests) and submitted under the FQ ref as the scheduler
/// component id; a `trigger-event` `filter` string has no scheduler
/// representation and is refused.
///
/// Scheduler calls are async; the executor bridges from the applier's sync
/// context by driving them on a scoped helper thread over the captured runtime
/// handle (safe from within a worker of a multi-thread runtime).
pub struct SchedulerWorkflowExecutor {
    spawner: Arc<dyn Spawner>,
    tree: Arc<AgentTreeStore>,
    parent: AgentId,
    /// The lifecycle terminate cascade (loop abort, run cancel, mailbox flush,
    /// grant revoke, tree removal) — set by the composition root once it exists
    /// ([`Self::set_terminate_controller`]); absent → `terminate_child` falls
    /// back to a bare tree removal (test rigs / lifecycle-less boots).
    terminator: OnceLock<Arc<dyn TerminateController>>,
    submit: Arc<dyn ComponentSubmitApi>,
    submitter: String,
    registry: Arc<dyn PackRegistry>,
    secrets: Arc<dyn SecretStore>,
    mcp: PackMcpBridge,
    mcp_sink: Arc<dyn McpEntrySink>,
    handle: tokio::runtime::Handle,
}

impl SchedulerWorkflowExecutor {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        spawner: Arc<dyn Spawner>,
        tree: Arc<AgentTreeStore>,
        parent: AgentId,
        submit: Arc<dyn ComponentSubmitApi>,
        submitter: impl Into<String>,
        registry: Arc<dyn PackRegistry>,
        secrets: Arc<dyn SecretStore>,
        mcp_sink: Arc<dyn McpEntrySink>,
        handle: tokio::runtime::Handle,
    ) -> Self {
        Self {
            spawner,
            tree,
            parent,
            terminator: OnceLock::new(),
            submit,
            submitter: submitter.into(),
            mcp: PackMcpBridge::new(Arc::clone(&registry)),
            registry,
            secrets,
            mcp_sink,
            handle,
        }
    }

    /// Install the production terminate cascade for [`WorkflowExecutor::terminate_child`]
    /// (one-shot; the composition root builds the controller after the executor
    /// because the controller needs the same tree + the messaging/run stores).
    pub fn set_terminate_controller(
        &self,
        controller: Arc<dyn TerminateController>,
    ) -> Result<(), AlreadyBound> {
        self.terminator.set(controller).map_err(|_| AlreadyBound)
    }

    pub fn has_terminate_controller(&self) -> bool {
        self.terminator.get().is_some()
    }

    /// `(child agent id, child workspace path relative to the parent)` from a
    /// workflow `target-path`.
    fn child_identity(target_path: &Path) -> Result<(AgentId, PathBuf), PackError> {
        let mut rel = PathBuf::new();
        for comp in target_path.components() {
            match comp {
                Component::RootDir | Component::Prefix(_) | Component::CurDir => {}
                Component::Normal(seg) => rel.push(seg),
                Component::ParentDir => {
                    return Err(PackError::InvalidWorkflow(format!(
                        "spawn-child target-path {} contains `..`",
                        target_path.display()
                    )))
                }
            }
        }
        let id = rel
            .file_name()
            .and_then(|s| s.to_str())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                PackError::InvalidWorkflow(format!(
                    "spawn-child target-path {} has no final component to name the child",
                    target_path.display()
                ))
            })?
            .to_string();
        validate_agent_id(&id).map_err(|e| {
            PackError::InvalidWorkflow(format!(
                "spawn-child target-path {}: child id {id:?} rejected: {e}",
                target_path.display()
            ))
        })?;
        Ok((AgentId(id), rel))
    }

    /// Drive `fut` to completion from the applier's sync context.
    fn block_on<F>(&self, fut: F) -> Result<F::Output, PackError>
    where
        F: std::future::Future + Send,
        F::Output: Send,
    {
        let handle = self.handle.clone();
        std::thread::scope(|s| {
            s.spawn(move || handle.block_on(fut))
                .join()
                .map_err(|_| PackError::InvalidWorkflow("scheduler call panicked".into()))
        })
    }

    fn component_type(raw: &str) -> Result<ComponentType, PackError> {
        Ok(match raw {
            "task" => ComponentType::Task,
            "cron" => ComponentType::Cron,
            "watcher" => ComponentType::Watcher,
            "daemon" => ComponentType::Daemon,
            other => {
                return Err(PackError::ConstraintViolation {
                    reason: format!(
                        "submit-component: component-type {other:?} cannot be submitted \
                         (task / cron / watcher / daemon)"
                    ),
                })
            }
        })
    }
}

fn bridge_to_pack(e: PackBridgeError) -> PackError {
    match e {
        PackBridgeError::Pack(e) => e,
        PackBridgeError::TrustDenied { pack, reason } => PackError::ConstraintViolation {
            reason: format!("pack {pack}: {reason}"),
        },
        other => PackError::InvalidWorkflow(other.to_string()),
    }
}

impl WorkflowExecutor for SchedulerWorkflowExecutor {
    fn spawn_child(
        &self,
        template_ref: &str,
        target_path: &Path,
        config: &BTreeMap<String, serde_yml::Value>,
    ) -> Result<(), PackError> {
        if !config.is_empty() {
            return Err(PackError::InvalidWorkflow(format!(
                "spawn-child {}: `config` ({} keys) is not supported by the production \
                 spawner (SpawnChildConfig has no config slot); remove it or apply the \
                 configuration through the template",
                target_path.display(),
                config.len()
            )));
        }
        let (child_id, rel) = Self::child_identity(target_path)?;
        self.spawner
            .spawn_child(SpawnChildConfig {
                parent_id: self.parent.clone(),
                child_id,
                child_workspace_path: rel,
                capabilities: Vec::new(),
                template_ref: Some(template_ref.to_string()),
                binary: None,
            })
            .map(|_| ())
            .map_err(|e| {
                PackError::InvalidWorkflow(format!(
                    "spawn-child {} ({template_ref}): {e}",
                    target_path.display()
                ))
            })
    }

    fn submit_component(
        &self,
        component_ref: &str,
        trigger: &WorkflowTrigger,
    ) -> Result<(), PackError> {
        let resolved = self.registry.resolve_pack_component(component_ref)?;
        let component_type = Self::component_type(&resolved.manifest.component_type)?;
        let trigger = match trigger {
            WorkflowTrigger::Schedule(s) => TriggerConfig::Schedule(s.clone()),
            WorkflowTrigger::TriggerEvent {
                event_type,
                filter: None,
            } => TriggerConfig::TriggerEvent(TriggerSubscription {
                event_type: event_type.clone(),
                filter: None,
                debounce_ms: None,
            }),
            WorkflowTrigger::TriggerEvent {
                filter: Some(_), ..
            } => {
                return Err(PackError::InvalidWorkflow(format!(
                    "submit-component {component_ref}: a trigger-event `filter` string has no \
                     scheduler representation (TriggerFilter is structured); drop it"
                )))
            }
        };
        if component_ref.len() > advance_scheduler::types::MAX_COMPONENT_ID_LEN {
            return Err(PackError::InvalidWorkflow(format!(
                "submit-component: ref exceeds the scheduler component-id cap ({} bytes)",
                advance_scheduler::types::MAX_COMPONENT_ID_LEN
            )));
        }
        let cfg = ComponentSubmitConfig {
            id: component_ref.to_string(),
            component_type,
            binary: resolved.binary,
            capabilities: resolved.capabilities,
            output_dir: Some(resolved.output_dir.display().to_string()),
            trigger: Some(trigger),
            restart_policy: None,
            delay: None,
            initial_grants: None,
            preset: None,
            retry: None,
            sensitive_params: Vec::new(),
        };
        self.block_on(self.submit.submit_component(&self.submitter, cfg))?
            .map(|_| ())
            .map_err(|e| {
                PackError::InvalidWorkflow(format!("submit-component {component_ref}: {e:?}"))
            })
    }

    fn register_mcp_server(
        &self,
        config_ref: &str,
        resolved_secrets: &BTreeMap<String, SecretValue>,
    ) -> Result<McpServerId, PackError> {
        let entry = self
            .mcp
            .entry_with_env(config_ref, &*self.secrets, resolved_secrets)
            .map_err(bridge_to_pack)?;
        let id = entry.server_id.clone();
        self.mcp_sink.register(entry).map_err(bridge_to_pack)?;
        Ok(McpServerId(id))
    }

    /// Compensation for an earlier `spawn_child`. With a terminate controller
    /// installed, the child goes through the lifecycle cascade the guest
    /// `terminate-child` uses (serve-loop abort, run cancel, mailbox flush, grant
    /// revoke, tree removal — parent-checked); without one, the bare tree node is
    /// removed. Either way the child WORKSPACE the spawn created is removed
    /// afterwards (the cascade keeps `Child` territories on terminate; an undo
    /// must not), guarded to a real directory under the tree's workspace root.
    fn terminate_child(&self, target_path: &Path) -> Result<(), PackError> {
        let (child_id, _) = Self::child_identity(target_path)?;
        let ws = self.tree.get_node(&child_id).map(|n| n.workspace_path);
        match self.terminator.get() {
            Some(controller) => controller
                .terminate_child(&self.parent.0, &child_id.0)
                .map_err(|e| {
                    PackError::InvalidWorkflow(format!(
                        "terminate-child {} (lifecycle cascade): {e}",
                        target_path.display()
                    ))
                })?,
            None => {
                self.tree.remove(&child_id).map_err(|e| {
                    PackError::InvalidWorkflow(format!(
                        "terminate-child {}: {e}",
                        target_path.display()
                    ))
                })?;
            }
        }
        let Some(ws) = ws else {
            return Ok(());
        };
        if !ws.starts_with(self.tree.workspace_root()) {
            return Err(PackError::InvalidWorkflow(format!(
                "terminate-child {}: child workspace {} is outside the workspace root; \
                 agent terminated, directory left in place",
                target_path.display(),
                ws.display()
            )));
        }
        match std::fs::symlink_metadata(&ws) {
            Ok(md) if md.is_dir() => std::fs::remove_dir_all(&ws).map_err(|e| PackError::Io {
                path: ws.clone(),
                source: e,
            }),
            Ok(_) => Err(PackError::InvalidWorkflow(format!(
                "terminate-child {}: child workspace {} is not a real directory; agent \
                 terminated, path left in place",
                target_path.display(),
                ws.display()
            ))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(PackError::Io {
                path: ws,
                source: e,
            }),
        }
    }

    /// Compensation: `kill_component` under the same FQ-ref id.
    fn withdraw_component(&self, component_ref: &str) -> Result<(), PackError> {
        self.block_on(self.submit.kill_component(component_ref))?
            .map_err(|e| {
                PackError::InvalidWorkflow(format!("withdraw-component {component_ref}: {e:?}"))
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn highest_stable_excludes_prereleases_and_out_of_range() {
        let vs = ["1.0.0", "1.2.0", "1.3.0-beta.1", "2.0.0"]
            .iter()
            .map(|v| semver::Version::parse(v).unwrap());
        let req = semver::VersionReq::parse("^1.0").unwrap();
        assert_eq!(
            pick_highest_stable(vs, &req),
            Some(semver::Version::parse("1.2.0").unwrap())
        );
    }

    #[test]
    fn child_identity_strips_root_and_names_by_last_segment() {
        let (id, rel) =
            SchedulerWorkflowExecutor::child_identity(Path::new("/research-assistant")).unwrap();
        assert_eq!(id.0, "research-assistant");
        assert_eq!(rel, PathBuf::from("research-assistant"));
        let (id, rel) =
            SchedulerWorkflowExecutor::child_identity(Path::new("/team/analyst")).unwrap();
        assert_eq!(id.0, "analyst");
        assert_eq!(rel, PathBuf::from("team/analyst"));
        assert!(SchedulerWorkflowExecutor::child_identity(Path::new("/")).is_err());
        assert!(SchedulerWorkflowExecutor::child_identity(Path::new("/a/../b")).is_err());
    }

    #[test]
    fn late_bound_slots_fail_closed_until_bound() {
        let ex = LateBoundWorkflowExecutor::new();
        assert!(!ex.is_bound());
        assert!(matches!(
            ex.spawn_child("t", Path::new("/x"), &BTreeMap::new()),
            Err(PackError::NotImplemented(_))
        ));
        assert!(matches!(
            ex.terminate_child(Path::new("/x")),
            Err(PackError::NotImplemented(_))
        ));
        let secrets = LateBoundSecretStore::new();
        assert!(secrets.get("k").is_none());
        secrets
            .bind(Arc::new(ClosureSecretStore::new(|k| {
                (k == "k").then(|| "v".to_string())
            })))
            .unwrap();
        assert_eq!(
            secrets.get("k").map(|v| v.expose_secret().to_string()),
            Some("v".into())
        );
        assert_eq!(
            secrets.bind(Arc::new(ClosureSecretStore::new(|_| None))),
            Err(AlreadyBound)
        );
    }
}

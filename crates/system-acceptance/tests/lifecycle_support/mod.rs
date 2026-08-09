//! Lifecycle-harvest (2026-06-12) — the shared test-local **Cap::Lifecycle
//! driving primitive** for system-acceptance witnesses (SYS-J-54 decomp +
//! SYS-J-49 terminate-event legs).
//!
//! This is the sys_j44 bundle-ctor crib promoted to a reusable `#[path]`
//! support module (the `step4b_support` / `e_support` / `h_loopback`
//! mechanism): a REAL `register_agent_lifecycle` chain — real
//! `AgentTreeStore` (TempDir-rooted workspaces), real
//! `DefaultDecompositionStore` (real `decomposition.yaml` persistence +
//! cycle/oversize validation), real `DefaultSpawner` /
//! `DefaultTerminateController` / checkpoint / rollback / stats controllers —
//! with only the cross-module cascade ports stubbed Ok (grant/mailbox/run/
//! workspace cascades: M013/M006/M008/M002 seams, exactly the sys_j44
//! posture) and a capturing `EventBusEmit` so taxonomy events are assertable.
//!
//! Witness-fidelity caveat (same as the harness `call_host_fn` rustdoc): the
//! driver invokes the registered handlers DIRECTLY (the standard harness
//! guest stand-in), bypassing the production grant gate — faithful for
//! everything below the handler boundary (dispatch, controllers, store,
//! emission), NOT a witness for grant-gate authorization.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use advance_runtime::host_registry::{
    HostCallContext, HostCallError, HostFunctionHandler, HostRegistry, InMemoryHostRegistry,
};
use advance_shared_types::agent_tree::{
    AgentId, AgentKind, AgentNode, AgentStatus, AgentTreeSnapshot,
};
use advance_shared_types::event::Event;
use advance_shared_types::traits::EventBusEmit;
use cap_lifecycle::templates::{BuiltinTemplateRegistry, TemplateResolver};
use cap_lifecycle::{
    register_agent_lifecycle, AgentLifecycleBundle, AgentStats, AgentStatsReader, AgentTreeStore,
    CheckpointEntry, ComponentInfo, ComponentState, ComponentSubmitConfig, ComponentSubmitGate,
    DefaultCheckpointController, DefaultDecompositionStore, DefaultRollbackController,
    DefaultSpawner, DefaultStatsController, DefaultTerminateController, LifecycleError,
    NamedCheckpointGate, RollbackModeSpec, RollbackTargetSpec, SpawnError, SpawnerSubsetGate,
    WorkspaceCleanup, WorkspaceRollbackGate, AGENT_LIFECYCLE_CAPABILITY,
};
use cap_lifecycle::{GrantCascadeRevoke, MailboxCascade, RunCascade};
use tempfile::TempDir;
use wasmtime::component::Val;

// ── Ok-stubs for the cross-module cascade ports (sys_j44 posture) ──────────

struct OkGate;
impl SpawnerSubsetGate for OkGate {
    fn check(
        &self,
        _: &[advance_shared_types::agent_tree::Capability],
        _: &[advance_shared_types::agent_tree::Capability],
    ) -> Result<(), SpawnError> {
        Ok(())
    }
}

struct OkCascade;
impl GrantCascadeRevoke for OkCascade {
    fn revoke_for_agent(&self, _: &str) -> Result<(), LifecycleError> {
        Ok(())
    }
}
impl MailboxCascade for OkCascade {
    fn flush_mailbox(&self, _: &str) -> Result<(), LifecycleError> {
        Ok(())
    }
    fn notify_parent_crash(&self, _: &str, _: &str, _: &str) -> Result<(), LifecycleError> {
        Ok(())
    }
}
impl RunCascade for OkCascade {
    fn ensure_run(&self, _: &str) -> Result<(), LifecycleError> {
        Ok(())
    }
    fn cancel_run(&self, _: &str) -> Result<(), LifecycleError> {
        Ok(())
    }
}
impl WorkspaceCleanup for OkCascade {
    fn remove_sub_workspace(&self, _: &std::path::Path) -> Result<(), LifecycleError> {
        Ok(())
    }
}

struct OkRollbackGate;
impl WorkspaceRollbackGate for OkRollbackGate {
    fn rollback(
        &self,
        _: &str,
        _: RollbackTargetSpec,
        _: RollbackModeSpec,
    ) -> Result<Vec<PathBuf>, LifecycleError> {
        Ok(vec![])
    }
    fn rollback_to_checkpoint(&self, _: &str, _: &str) -> Result<Vec<PathBuf>, LifecycleError> {
        Ok(vec![])
    }
}

struct OkCkptGate;
impl NamedCheckpointGate for OkCkptGate {
    fn create(&self, _: &str, _: &str, _: Option<Vec<PathBuf>>) -> Result<(), LifecycleError> {
        Ok(())
    }
    fn list(&self, _: &str) -> Result<Vec<CheckpointEntry>, LifecycleError> {
        Ok(vec![])
    }
}

struct OkStats;
impl AgentStatsReader for OkStats {
    fn read_stats(&self, _: &str) -> Result<AgentStats, LifecycleError> {
        Ok(AgentStats {
            active_tasks: 0,
            completed_tasks: 0,
            avg_turns_per_task: 0.0,
            avg_completion_time_hours: 0.0,
            memory_entries: 0,
            llm_tokens_24h: 0,
            error_count_24h: 0,
            last_active: "x".into(),
        })
    }
}

struct StubSubmit;
#[async_trait::async_trait]
impl ComponentSubmitGate for StubSubmit {
    async fn submit_component(
        &self,
        _: &str,
        _: ComponentSubmitConfig,
    ) -> Result<cap_lifecycle::ComponentId, SpawnError> {
        Err(SpawnError::InvalidConfig("not wired".into()))
    }
    async fn kill_component(&self, _: &str) -> Result<(), SpawnError> {
        Ok(())
    }
    async fn component_status(&self, _: &str) -> Result<ComponentState, SpawnError> {
        Ok(ComponentState::Pending)
    }
    async fn list_components(&self) -> Vec<ComponentInfo> {
        vec![]
    }
}

struct CapturingBus(Arc<Mutex<Vec<Event>>>);
impl EventBusEmit for CapturingBus {
    fn emit(&self, e: Event) {
        self.0.lock().unwrap().push(e);
    }
}

/// The wired Cap::Lifecycle fixture: a real `register_agent_lifecycle` chain
/// over a TempDir-rooted real tree, with event capture.
pub struct LifecycleFixture {
    registry: InMemoryHostRegistry,
    events: Arc<Mutex<Vec<Event>>>,
    pub tree: AgentTreeStore,
    /// The SAME real `DefaultDecompositionStore` instance the registered WIT
    /// handlers dispatch into — exposed so the sys_j54 witnesses can corroborate
    /// the wired-WIT read-back against the persisted on-disk/state. (Both
    /// SYS-AC-171 legs — existing-id continuity + the status read-back — are now
    /// reachable through the WIT surface itself: the lift carries an optional
    /// existing-id and `get-decomposition` projects the full `decomposition-state`
    /// record; this handle is corroboration, not the primary path.)
    #[allow(dead_code)]
    // corroboration handle per the doc comment above; not every witness binary reads it
    pub decomp: Arc<DefaultDecompositionStore>,
    _tmp: TempDir,
}

#[allow(dead_code)]
impl LifecycleFixture {
    /// Real tree + root node `root_id` (bare id — cap-lifecycle
    /// `validate_agent_id` rejects colons) + full real bundle + registration.
    pub fn new_with_root(root_id: &str) -> Self {
        Self::new_with_root_and_resolver(root_id, None)
    }

    /// As [`Self::new_with_root`], but wires the bundle's `spawner` to a
    /// `DefaultSpawner::with_template_resolver(tree, OkGate, resolver)` when a
    /// `resolver` is supplied — so a witness can drive the REAL
    /// `spawn-agent-from-template` WIT host-fn over a caller-injected
    /// `TemplateResolver` (e.g. a `PackTemplateResolver` backed by a real
    /// `PackRegistry`). `None` keeps the default `DefaultSpawner::new`
    /// (`resolver: None`) posture used by every other lifecycle witness.
    pub fn new_with_root_and_resolver(
        root_id: &str,
        resolver: Option<Arc<dyn TemplateResolver>>,
    ) -> Self {
        let tmp = TempDir::new().expect("lifecycle fixture tempdir");
        let tree = AgentTreeStore::new(tmp.path().to_path_buf()).expect("tree");
        let root_ws = tree.workspace_root().join(root_id);
        std::fs::create_dir_all(&root_ws).expect("root workspace dir");
        tree.insert_root(AgentNode {
            id: AgentId(root_id.into()),
            kind: AgentKind::Root,
            parent: None,
            workspace_path: root_ws,
            capabilities: Vec::new(),
            template_ref: None,
            status: AgentStatus::Active,
        })
        .expect("insert root");

        let events = Arc::new(Mutex::new(Vec::new()));
        let decomposition = Arc::new(DefaultDecompositionStore::new(tree.clone()));
        let decomp_handle = Arc::clone(&decomposition);
        let spawner: Arc<DefaultSpawner> = match resolver {
            Some(r) => Arc::new(DefaultSpawner::with_template_resolver(
                tree.clone(),
                Arc::new(OkGate),
                r,
            )),
            None => Arc::new(DefaultSpawner::new(tree.clone(), Arc::new(OkGate))),
        };
        let bundle = AgentLifecycleBundle {
            tree: tree.clone(),
            spawner,
            rollback: Arc::new(DefaultRollbackController::new(
                tree.clone(),
                Arc::new(OkRollbackGate),
            )),
            checkpoint: Arc::new(DefaultCheckpointController::new(
                tree.clone(),
                Arc::new(OkCkptGate),
                Arc::new(OkRollbackGate),
            )),
            terminate: Arc::new(DefaultTerminateController::new(
                tree.clone(),
                Arc::new(OkCascade),
                Arc::new(OkCascade),
                Arc::new(OkCascade),
                Arc::new(OkCascade),
            )),
            decomposition,
            stats: Arc::new(DefaultStatsController::new(tree.clone(), Arc::new(OkStats))),
            templates: Arc::new(BuiltinTemplateRegistry::new()),
            submit_gate: Arc::new(StubSubmit),
            event_bus: Arc::new(CapturingBus(events.clone())),
        };
        let registry = InMemoryHostRegistry::new();
        register_agent_lifecycle(&registry, bundle);
        Self {
            registry,
            events,
            tree,
            decomp: decomp_handle,
            _tmp: tmp,
        }
    }

    /// Insert a child/sub node under `parent` with a real workspace dir.
    pub fn add_node(&self, parent: &str, id: &str, kind: AgentKind) {
        let parent_ws = self
            .tree
            .snapshot()
            .nodes
            .iter()
            .find(|n| n.id.0 == parent)
            .expect("parent node exists")
            .workspace_path
            .clone();
        let ws = match kind {
            AgentKind::Sub => parent_ws.join(".sub").join(id),
            _ => parent_ws.join(id),
        };
        std::fs::create_dir_all(&ws).expect("node workspace dir");
        self.tree
            .insert_child(
                &AgentId(parent.into()),
                AgentNode {
                    id: AgentId(id.into()),
                    kind,
                    parent: Some(AgentId(parent.into())),
                    workspace_path: ws,
                    capabilities: Vec::new(),
                    template_ref: None,
                    status: AgentStatus::Active,
                },
            )
            .expect("insert child");
    }

    /// The agent's real workspace path (for on-disk assertions, e.g.
    /// `decomposition.yaml` under `.agent/tasks/active/{task}/`).
    pub fn workspace_of(&self, id: &str) -> PathBuf {
        self.tree
            .snapshot()
            .nodes
            .iter()
            .find(|n| n.id.0 == id)
            .expect("node exists")
            .workspace_path
            .clone()
    }

    /// Drive a registered agent-lifecycle host fn through the production
    /// dispatch (results_len = 1 — every lifecycle handler returns one
    /// `Val::Result`).
    pub async fn call(
        &self,
        caller: &str,
        op: &str,
        params: Vec<Val>,
    ) -> Result<Vec<Val>, HostCallError> {
        let specs = self.registry.lookup(AGENT_LIFECYCLE_CAPABILITY);
        let h = &specs
            .iter()
            .find(|s| s.name == op)
            .unwrap_or_else(|| panic!("op {op} registered"))
            .handler;
        let ctx = HostCallContext {
            agent_id: caller.into(),
            trace_id: "trace-harness".into(),
            turn_id: None,
            capability: "lifecycle".into(),
            function: format!("advance:runtime/agent-lifecycle::{op}"),
            run_id: None,
            iteration: None,
        };
        HostFunctionHandler::call(h.as_ref(), ctx, params, 1).await
    }

    /// Captured taxonomy events (clone).
    pub fn events(&self) -> Vec<Event> {
        self.events.lock().unwrap().clone()
    }
}

/// `Val::Result(Err(Some(Variant)))` → the variant case name.
#[allow(dead_code)]
pub fn err_variant_name(v: &Val) -> String {
    let Val::Result(Err(Some(b))) = v else {
        panic!("expected Val::Result(Err(Some(variant))), got {v:?}")
    };
    let Val::Variant(case, _) = b.as_ref() else {
        panic!("expected Val::Variant, got {b:?}")
    };
    case.clone()
}

/// `Val::Result(Ok(Some(List(String...))))` → the receipt strings.
#[allow(dead_code)]
pub fn ok_string_list(v: &Val) -> Vec<String> {
    let Val::Result(Ok(Some(b))) = v else {
        panic!("expected Val::Result(Ok(Some(list))), got {v:?}")
    };
    let Val::List(items) = b.as_ref() else {
        panic!("expected Val::List, got {b:?}")
    };
    items
        .iter()
        .map(|i| {
            let Val::String(s) = i else {
                panic!("expected Val::String, got {i:?}")
            };
            s.clone()
        })
        .collect()
}

/// Build the `submit-decomposition` WIT params: descriptors are
/// `"title|assignee|prompt|dep1,dep2,..."` wire-shape strings.
#[allow(dead_code)]
pub fn submit_params(task: &str, goal: &str, strategy: &str, subtasks: &[String]) -> Vec<Val> {
    vec![
        Val::String(task.into()),
        Val::String(goal.into()),
        Val::String(strategy.into()),
        Val::List(subtasks.iter().map(|s| Val::String(s.clone())).collect()),
    ]
}

//! AC-01 — agent-lifecycle WIT registration + dispatch (REQ-179).

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use advance_runtime::host_registry::{HostRegistry, InMemoryHostRegistry};
use advance_shared_types::agent_tree::{AgentId, AgentKind, AgentNode, AgentStatus};
use advance_shared_types::event::Event;
use advance_shared_types::traits::EventBusEmit;
use cap_lifecycle::templates::BuiltinTemplateRegistry;
use cap_lifecycle::{
    register_agent_lifecycle, AgentLifecycleBundle, AgentStats, AgentStatsReader, AgentTreeStore,
    CheckpointEntry, ComponentInfo, ComponentState, ComponentSubmitConfig, ComponentSubmitGate,
    DecompositionError, DecompositionPlan, DecompositionReceipt, DecompositionState,
    DecompositionStore, DefaultCheckpointController, DefaultDecompositionStore,
    DefaultRollbackController, DefaultSpawner, DefaultStatsController, DefaultTerminateController,
    GrantCascadeRevoke, LifecycleError, MailboxCascade, NamedCheckpointGate, RollbackModeSpec,
    RollbackTargetSpec, RunCascade, SpawnError, SpawnerSubsetGate, SubtaskStatus, WorkspaceCleanup,
    WorkspaceRollbackGate, AGENT_LIFECYCLE_CAPABILITY,
};
use tempfile::TempDir;
use wasmtime::component::Val;

fn component_submit_v2(id: &str, binary: Vec<u8>, sensitive: Vec<&str>) -> Val {
    Val::Record(vec![
        ("id".into(), Val::String(id.into())),
        ("component-type".into(), Val::Variant("task".into(), None)),
        (
            "binary".into(),
            Val::List(binary.into_iter().map(Val::U8).collect()),
        ),
        ("capabilities".into(), Val::List(Vec::new())),
        ("output-dir".into(), Val::Option(None)),
        ("trigger".into(), Val::Option(None)),
        ("restart-policy".into(), Val::Option(None)),
        ("delay".into(), Val::Option(None)),
        ("initial-grants".into(), Val::Option(None)),
        ("preset".into(), Val::Option(None)),
        ("retry".into(), Val::Option(None)),
        (
            "sensitive-params".into(),
            Val::List(
                sensitive
                    .into_iter()
                    .map(|name| Val::String(name.to_owned()))
                    .collect(),
            ),
        ),
    ])
}

// ── stubs ──────────────────────────────────────────────────────────────────
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
struct NoopBus;
impl EventBusEmit for NoopBus {
    fn emit(&self, _e: Event) {}
}
/// Records every emitted event so decomposition emit tests can assert on
/// event_type + payload.
struct CapturingBus(Arc<Mutex<Vec<Event>>>);
impl EventBusEmit for CapturingBus {
    fn emit(&self, e: Event) {
        self.0.lock().unwrap().push(e);
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
        Err(SpawnError::InvalidConfig(
            "ComponentSubmitGate not wired".into(),
        ))
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

/// Recording decomposition store — captures the caller_id it was passed so
/// the test can assert it came from ctx.agent_id (not a guest param).
struct RecDecomp(Arc<Mutex<Vec<String>>>);
impl DecompositionStore for RecDecomp {
    fn submit(
        &self,
        caller_id: &str,
        _t: &str,
        _p: DecompositionPlan,
    ) -> Result<DecompositionReceipt, DecompositionError> {
        self.0.lock().unwrap().push(caller_id.to_string());
        Ok(DecompositionReceipt {
            subtask_ids: vec![],
        })
    }
    fn update_subtask_status(
        &self,
        caller_id: &str,
        _: &str,
        _: &str,
        _: SubtaskStatus,
        _: Option<String>,
    ) -> Result<SubtaskStatus, DecompositionError> {
        self.0.lock().unwrap().push(caller_id.to_string());
        Ok(SubtaskStatus::Pending)
    }
    fn get(
        &self,
        caller_id: &str,
        _: &str,
    ) -> Result<Option<DecompositionState>, DecompositionError> {
        self.0.lock().unwrap().push(caller_id.to_string());
        Ok(None)
    }
}

/// Decomposition stub that always returns an infra `IoFailure` — used to
/// verify the §2.8 taxonomy: decomposition-infra → host trap, NOT a typed
/// `task-not-found` domain lie.
struct InfraDecomp;
impl DecompositionStore for InfraDecomp {
    fn submit(
        &self,
        _: &str,
        _: &str,
        _: DecompositionPlan,
    ) -> Result<DecompositionReceipt, DecompositionError> {
        Err(DecompositionError::IoFailure("disk full".into()))
    }
    fn update_subtask_status(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: SubtaskStatus,
        _: Option<String>,
    ) -> Result<SubtaskStatus, DecompositionError> {
        Err(DecompositionError::IoFailure("disk full".into()))
    }
    fn get(&self, _: &str, _: &str) -> Result<Option<DecompositionState>, DecompositionError> {
        Err(DecompositionError::IoFailure("disk full".into()))
    }
}

fn bundle_with(decomp: Arc<dyn DecompositionStore>) -> AgentLifecycleBundle {
    let tmp = Box::leak(Box::new(TempDir::new().unwrap()));
    let tree = AgentTreeStore::new(tmp.path().to_path_buf()).unwrap();
    let rws = tree.workspace_root().join("root");
    std::fs::create_dir_all(&rws).unwrap();
    tree.insert_root(AgentNode {
        id: AgentId("agent-1".into()),
        kind: AgentKind::Root,
        parent: None,
        workspace_path: rws,
        capabilities: Vec::new(),
        template_ref: None,
        status: AgentStatus::Active,
    })
    .unwrap();
    AgentLifecycleBundle {
        tree: tree.clone(),
        spawner: Arc::new(DefaultSpawner::new(tree.clone(), Arc::new(OkGate))),
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
        decomposition: decomp,
        stats: Arc::new(DefaultStatsController::new(tree.clone(), Arc::new(OkStats))),
        templates: Arc::new(BuiltinTemplateRegistry::new()),
        submit_gate: Arc::new(StubSubmit),
        event_bus: Arc::new(NoopBus),
    }
}

fn bundle(rec: Arc<Mutex<Vec<String>>>) -> AgentLifecycleBundle {
    bundle_with(Arc::new(RecDecomp(rec)))
}

/// Bundle whose spawner is wired with a real template resolver
/// (`with_template_resolver`) — required so a `kind=child`
/// `spawn-agent-from-template` actually resolves + materializes (the default
/// `bundle_with` uses `DefaultSpawner::new` with `resolver: None`). Returns a
/// `tree.clone()` so the test can inspect the landed node after dispatch (the
/// store is `Arc<RwLock<..>>`-backed; the clone sees the same mutations).
/// sat/template-materialization 2026-06-13.
fn bundle_with_resolver_spawner() -> (AgentLifecycleBundle, AgentTreeStore) {
    let tmp = Box::leak(Box::new(TempDir::new().unwrap()));
    let tree = AgentTreeStore::new(tmp.path().to_path_buf()).unwrap();
    let rws = tree.workspace_root().join("root");
    std::fs::create_dir_all(&rws).unwrap();
    tree.insert_root(AgentNode {
        id: AgentId("agent-1".into()),
        kind: AgentKind::Root,
        parent: None,
        workspace_path: rws,
        capabilities: Vec::new(),
        template_ref: None,
        status: AgentStatus::Active,
    })
    .unwrap();
    let bundle = AgentLifecycleBundle {
        tree: tree.clone(),
        spawner: Arc::new(DefaultSpawner::with_template_resolver(
            tree.clone(),
            Arc::new(OkGate),
            Arc::new(BuiltinTemplateRegistry::new()),
        )),
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
        decomposition: Arc::new(RecDecomp(Arc::new(Mutex::new(vec![])))),
        stats: Arc::new(DefaultStatsController::new(tree.clone(), Arc::new(OkStats))),
        templates: Arc::new(BuiltinTemplateRegistry::new()),
        submit_gate: Arc::new(StubSubmit),
        event_bus: Arc::new(NoopBus),
    };
    (bundle, tree)
}

fn lifecycle_ctx() -> advance_runtime::host_registry::HostCallContext {
    advance_runtime::host_registry::HostCallContext {
        agent_id: "agent-1".into(),
        trace_id: "t".into(),
        turn_id: None,
        capability: "lifecycle".into(),
        function: "f".into(),
        run_id: None,
        iteration: None,
    }
}

#[test]
fn ac01_spawn_from_template_kind_child_lands_child_node() {
    use advance_runtime::host_registry::HostFunctionHandler;
    // kind-aware dispatch: kind=child must land a CHILD at the target path,
    // NOT a Sub (the pre-fix arm ignored `kind` and always called spawn_sub).
    let (bundle, tree) = bundle_with_resolver_spawner();
    let reg = InMemoryHostRegistry::new();
    register_agent_lifecycle(&reg, bundle);
    let specs = reg.lookup(AGENT_LIFECYCLE_CAPABILITY);
    let h = &specs
        .iter()
        .find(|s| s.name == "spawn-agent-from-template")
        .unwrap()
        .handler;
    // kind passed as the real WIT wire shape Val::Variant.
    let params = vec![
        Val::Variant("child".to_string(), None),
        Val::String("explorer".to_string()),
        Val::Option(Some(Box::new(Val::String("agents/foo".to_string())))),
        Val::Option(None),
    ];
    let rt = tokio::runtime::Runtime::new().unwrap();
    let res = rt
        .block_on(HostFunctionHandler::call(
            h.as_ref(),
            lifecycle_ctx(),
            params,
            1,
        ))
        .unwrap();
    // Ok(agent-id) == "foo" (child_id derived from the target-path leaf).
    match &res[0] {
        Val::Result(Ok(Some(b))) => match b.as_ref() {
            Val::String(id) => assert_eq!(id, "foo"),
            other => panic!("expected agent-id string, got {other:?}"),
        },
        other => panic!("expected Ok(agent-id), got {other:?}"),
    }
    let node = tree
        .get_node(&AgentId("foo".into()))
        .expect("child node 'foo' must be in the tree");
    assert_eq!(
        node.kind,
        AgentKind::Child,
        "kind=child must spawn a Child, not a Sub"
    );
    assert_eq!(node.template_ref.as_deref(), Some("explorer"));
    assert!(
        node.workspace_path.ends_with("agents/foo"),
        "child workspace at target path, got {:?}",
        node.workspace_path
    );
}

#[test]
fn ac01_spawn_from_template_kind_sub_lands_sub_node() {
    use advance_runtime::host_registry::HostFunctionHandler;
    // kind=sub passed as Val::String("sub") — exercises the string-shape lift
    // branch of lift_agent_kind and the sub routing.
    let (bundle, tree) = bundle_with_resolver_spawner();
    let reg = InMemoryHostRegistry::new();
    register_agent_lifecycle(&reg, bundle);
    let specs = reg.lookup(AGENT_LIFECYCLE_CAPABILITY);
    let h = &specs
        .iter()
        .find(|s| s.name == "spawn-agent-from-template")
        .unwrap()
        .handler;
    let params = vec![
        Val::String("sub".to_string()),
        Val::String("planner".to_string()),
        Val::Option(None),
        Val::Option(None),
    ];
    let rt = tokio::runtime::Runtime::new().unwrap();
    let res = rt
        .block_on(HostFunctionHandler::call(
            h.as_ref(),
            lifecycle_ctx(),
            params,
            1,
        ))
        .unwrap();
    let sub_id = match &res[0] {
        Val::Result(Ok(Some(b))) => match b.as_ref() {
            Val::String(id) => id.clone(),
            other => panic!("expected agent-id string, got {other:?}"),
        },
        other => panic!("expected Ok(agent-id), got {other:?}"),
    };
    let node = tree
        .get_node(&AgentId(sub_id))
        .expect("sub node must be in the tree");
    assert_eq!(node.kind, AgentKind::Sub, "kind=sub must spawn a Sub");
}

#[test]
fn ac01_spawn_from_template_kind_child_missing_target_path_invalid_config() {
    use advance_runtime::host_registry::HostFunctionHandler;
    // kind=child with NO target-path → spawn-error::invalid-config (the handler
    // needs a target-path to derive the child workspace + child_id).
    let (bundle, _tree) = bundle_with_resolver_spawner();
    let reg = InMemoryHostRegistry::new();
    register_agent_lifecycle(&reg, bundle);
    let specs = reg.lookup(AGENT_LIFECYCLE_CAPABILITY);
    let h = &specs
        .iter()
        .find(|s| s.name == "spawn-agent-from-template")
        .unwrap()
        .handler;
    let params = vec![
        Val::Variant("child".to_string(), None),
        Val::String("explorer".to_string()),
        Val::Option(None),
        Val::Option(None),
    ];
    let rt = tokio::runtime::Runtime::new().unwrap();
    let res = rt
        .block_on(HostFunctionHandler::call(
            h.as_ref(),
            lifecycle_ctx(),
            params,
            1,
        ))
        .unwrap();
    match &res[0] {
        Val::Result(Err(Some(b))) => match b.as_ref() {
            Val::Variant(case, _) => assert_eq!(case, "invalid-config"),
            other => panic!("expected invalid-config variant, got {other:?}"),
        },
        other => panic!("expected typed Err(invalid-config), got {other:?}"),
    }
}

#[test]
fn ac01_spawn_from_template_kind_child_no_leaf_invalid_config() {
    use advance_runtime::host_registry::HostFunctionHandler;
    // kind=child with a target-path that has no final component ("" → file_name()
    // is None) → child_id cannot be derived → spawn-error::invalid-config before
    // any spawn. Exercises the riskiest new line (child-id-from-leaf derivation).
    let (bundle, _tree) = bundle_with_resolver_spawner();
    let reg = InMemoryHostRegistry::new();
    register_agent_lifecycle(&reg, bundle);
    let specs = reg.lookup(AGENT_LIFECYCLE_CAPABILITY);
    let h = &specs
        .iter()
        .find(|s| s.name == "spawn-agent-from-template")
        .unwrap()
        .handler;
    let params = vec![
        Val::Variant("child".to_string(), None),
        Val::String("explorer".to_string()),
        Val::Option(Some(Box::new(Val::String(String::new())))),
        Val::Option(None),
    ];
    let rt = tokio::runtime::Runtime::new().unwrap();
    let res = rt
        .block_on(HostFunctionHandler::call(
            h.as_ref(),
            lifecycle_ctx(),
            params,
            1,
        ))
        .unwrap();
    match &res[0] {
        Val::Result(Err(Some(b))) => match b.as_ref() {
            Val::Variant(case, _) => assert_eq!(case, "invalid-config"),
            other => panic!("expected invalid-config variant, got {other:?}"),
        },
        other => panic!("expected typed Err(invalid-config), got {other:?}"),
    }
}

#[test]
fn ac01_spawn_from_template_unknown_kind_is_host_trap() {
    use advance_runtime::host_registry::HostFunctionHandler;
    // An unknown agent-kind ("root" is not a valid {sub,child} case) →
    // lift_agent_kind returns HandlerError → host trap (§2.8 cat-1), never a
    // silent mis-spawn. Witnesses the `bad =>` arm of lift_agent_kind.
    let (bundle, _tree) = bundle_with_resolver_spawner();
    let reg = InMemoryHostRegistry::new();
    register_agent_lifecycle(&reg, bundle);
    let specs = reg.lookup(AGENT_LIFECYCLE_CAPABILITY);
    let h = &specs
        .iter()
        .find(|s| s.name == "spawn-agent-from-template")
        .unwrap()
        .handler;
    let params = vec![
        Val::String("root".to_string()),
        Val::String("explorer".to_string()),
        Val::Option(None),
        Val::Option(None),
    ];
    let rt = tokio::runtime::Runtime::new().unwrap();
    let res = rt.block_on(HostFunctionHandler::call(
        h.as_ref(),
        lifecycle_ctx(),
        params,
        1,
    ));
    assert!(
        res.is_err(),
        "unknown agent-kind must be a host trap, got {res:?}"
    );
}

const EXPECTED: &[&str] = &[
    "spawn-child",
    "spawn-sub",
    "init-child-workspace",
    "rollback-child",
    "rollback-child-to-checkpoint",
    "list-child-checkpoints",
    "terminate-child",
    "submit-component",
    "component-status",
    "kill-component",
    "list-components",
    "checkpoint",
    "rollback-to-checkpoint",
    "list-checkpoints",
    "self-stats",
    "child-stats",
    "spawn-agent-from-template",
    "list-agent-templates",
    "terminate-agent",
    "submit-decomposition",
    "update-subtask-status",
    "get-decomposition",
];

#[test]
fn ac01_registers_22_methods() {
    let reg = InMemoryHostRegistry::new();
    register_agent_lifecycle(&reg, bundle(Arc::new(Mutex::new(vec![]))));
    let specs = reg.lookup(AGENT_LIFECYCLE_CAPABILITY);
    assert_eq!(specs.len(), 22, "exactly 22 host functions");
}

#[test]
fn ac01_all_names_present_and_unique() {
    let reg = InMemoryHostRegistry::new();
    register_agent_lifecycle(&reg, bundle(Arc::new(Mutex::new(vec![]))));
    let specs = reg.lookup(AGENT_LIFECYCLE_CAPABILITY);
    let mut names: Vec<String> = specs.iter().map(|s| s.name.clone()).collect();
    names.sort();
    let mut uniq = names.clone();
    uniq.dedup();
    assert_eq!(names.len(), uniq.len(), "(namespace,name) uniqueness");
    for e in EXPECTED {
        assert!(specs.iter().any(|s| s.name == *e), "missing {e}");
        assert!(specs
            .iter()
            .all(|s| s.namespace == "advance:runtime/agent-lifecycle@0.2.0"));
    }
}

#[test]
fn ac01_idempotent_flags_8_true_14_false() {
    let reg = InMemoryHostRegistry::new();
    register_agent_lifecycle(&reg, bundle(Arc::new(Mutex::new(vec![]))));
    let specs = reg.lookup(AGENT_LIFECYCLE_CAPABILITY);
    let t = specs.iter().filter(|s| s.idempotent).count();
    let f = specs.iter().filter(|s| !s.idempotent).count();
    assert_eq!(t, 8, "8 idempotent read-only");
    assert_eq!(f, 14, "14 mutating");
    for ro in [
        "component-status",
        "list-components",
        "list-child-checkpoints",
        "list-checkpoints",
        "self-stats",
        "child-stats",
        "list-agent-templates",
        "get-decomposition",
    ] {
        assert!(
            specs.iter().find(|s| s.name == ro).unwrap().idempotent,
            "{ro} idempotent"
        );
    }
}

#[test]
fn ac01_caller_id_sourced_from_ctx_agent_id() {
    use advance_runtime::host_registry::{HostCallContext, HostFunctionHandler};
    let rec = Arc::new(Mutex::new(vec![]));
    let reg = InMemoryHostRegistry::new();
    register_agent_lifecycle(&reg, bundle(rec.clone()));
    let specs = reg.lookup(AGENT_LIFECYCLE_CAPABILITY);
    let h = &specs
        .iter()
        .find(|s| s.name == "get-decomposition")
        .unwrap()
        .handler;
    let ctx = HostCallContext {
        agent_id: "agent-1".into(),
        trace_id: "t".into(),
        turn_id: None,
        capability: "lifecycle".into(),
        function: "advance:runtime/agent-lifecycle::get-decomposition".into(),
        run_id: None,
        iteration: None,
    };
    let rt = tokio::runtime::Runtime::new().unwrap();
    let fut = HostFunctionHandler::call(h.as_ref(), ctx, vec![Val::String("task-x".into())], 1);
    let res = rt.block_on(fut);
    assert!(res.is_ok(), "dispatch ok: {res:?}");
    // The controller recorded the caller it received — must be ctx.agent_id,
    // NOT the guest-supplied "task-x" param.
    assert_eq!(rec.lock().unwrap().as_slice(), &["agent-1".to_string()]);
}

#[test]
fn ac01_submit_component_returns_typed_not_wired() {
    use advance_runtime::host_registry::{HostCallContext, HostFunctionHandler};
    let reg = InMemoryHostRegistry::new();
    register_agent_lifecycle(&reg, bundle(Arc::new(Mutex::new(vec![]))));
    let specs = reg.lookup(AGENT_LIFECYCLE_CAPABILITY);
    let h = &specs
        .iter()
        .find(|s| s.name == "submit-component")
        .unwrap()
        .handler;
    let ctx = HostCallContext {
        agent_id: "agent-1".into(),
        trace_id: "t".into(),
        turn_id: None,
        capability: "lifecycle".into(),
        function: "f".into(),
        run_id: None,
        iteration: None,
    };
    let rt = tokio::runtime::Runtime::new().unwrap();
    let res = rt
        .block_on(HostFunctionHandler::call(
            h.as_ref(),
            ctx,
            vec![component_submit_v2("c1", Vec::new(), Vec::new())],
            1,
        ))
        .unwrap();
    // Typed spawn-error::invalid-config from the compatibility stub. The v0.2
    // record is fully lifted; its empty extended fields can be represented by
    // the legacy Rust-only gate, which then returns the expected error.
    match &res[0] {
        Val::Result(Err(Some(b))) => match b.as_ref() {
            Val::Variant(case, _) => assert_eq!(case, "invalid-config"),
            other => panic!("unexpected err payload {other:?}"),
        },
        other => panic!("expected typed Err, got {other:?}"),
    }
}

#[test]
fn ac01_decomposition_infra_failure_is_host_trap_not_domain_lie() {
    // §2.8 R4-C2 taxonomy: decomposition-error has NO neutral variant, so an
    // infra failure (IoFailure) lowers to a HostCallError host trap — NEVER a
    // false typed `task-not-found`/`permission-denied` domain claim.
    use advance_runtime::host_registry::{HostCallContext, HostCallError, HostFunctionHandler};
    let reg = InMemoryHostRegistry::new();
    register_agent_lifecycle(&reg, bundle_with(Arc::new(InfraDecomp)));
    let specs = reg.lookup(AGENT_LIFECYCLE_CAPABILITY);
    let h = &specs
        .iter()
        .find(|s| s.name == "get-decomposition")
        .unwrap()
        .handler;
    let ctx = HostCallContext {
        agent_id: "agent-1".into(),
        trace_id: "t".into(),
        turn_id: None,
        capability: "lifecycle".into(),
        function: "f".into(),
        run_id: None,
        iteration: None,
    };
    let rt = tokio::runtime::Runtime::new().unwrap();
    let res = rt.block_on(HostFunctionHandler::call(
        h.as_ref(),
        ctx,
        vec![Val::String("task-x".into())],
        1,
    ));
    match res {
        Err(HostCallError::HandlerError(msg)) => {
            assert!(
                msg.contains("internal-error"),
                "opaque internal-error, never raw {{e}}: {msg}"
            );
            assert!(
                !msg.contains("task-not-found") && !msg.contains("disk full"),
                "must NOT leak a false domain claim or raw error: {msg}"
            );
        }
        other => panic!("infra failure must be a host trap, got {other:?}"),
    }
}

#[test]
fn ac01_malformed_strategy_is_host_trap() {
    // §2.8 taxonomy category 1: a malformed/unknown strategy is a Val→typed
    // lift failure (this is where the reconciled-away `invalid-strategy`
    // lands) → HostCallError::HandlerError, NOT a typed decomposition-error.
    use advance_runtime::host_registry::{HostCallContext, HostCallError, HostFunctionHandler};
    let reg = InMemoryHostRegistry::new();
    register_agent_lifecycle(&reg, bundle(Arc::new(Mutex::new(vec![]))));
    let specs = reg.lookup(AGENT_LIFECYCLE_CAPABILITY);
    let h = &specs
        .iter()
        .find(|s| s.name == "submit-decomposition")
        .unwrap()
        .handler;
    let ctx = HostCallContext {
        agent_id: "agent-1".into(),
        trace_id: "t".into(),
        turn_id: None,
        capability: "lifecycle".into(),
        function: "f".into(),
        run_id: None,
        iteration: None,
    };
    let rt = tokio::runtime::Runtime::new().unwrap();
    // params: [task_id, goal, strategy-tag, subtask-list, ...]
    let res = rt.block_on(HostFunctionHandler::call(
        h.as_ref(),
        ctx,
        vec![
            Val::String("task-1".into()),
            Val::String("goal".into()),
            Val::String("bogus-strategy".into()),
            Val::List(vec![]),
        ],
        1,
    ));
    assert!(
        matches!(res, Err(HostCallError::HandlerError(_))),
        "malformed strategy must be a host trap, got {res:?}"
    );
}

// ── Decomposition observability emission + WIT depends-on lift (T37) ─────────
//
// Drive the WIT dispatch over a REAL `DefaultDecompositionStore` + a recording
// `CapturingBus`, then assert on the emitted `task.*` events and (for the
// depends-on lift) inspect the persisted state directly via the store handle.
// These are crate-level WIT-dispatch tests; the e2e/system witnesses for SYS-J-54
// (SYS-AC-170/171/242/243) live in the system-acceptance harness (`.with_decomposition()`
// axis) and are all `passed`.

use advance_runtime::host_registry::{HostCallContext, HostCallError, HostFunctionHandler};

/// Build a host registry with the lifecycle bundle wired to a REAL
/// decomposition store + a capturing event bus. Returns the registry, a handle
/// to the store (to inspect persisted state), and the captured-events vec.
fn real_decomp_dispatch() -> (
    InMemoryHostRegistry,
    Arc<DefaultDecompositionStore>,
    Arc<Mutex<Vec<Event>>>,
) {
    let tmp = Box::leak(Box::new(TempDir::new().unwrap()));
    let tree = AgentTreeStore::new(tmp.path().to_path_buf()).unwrap();
    let rws = tree.workspace_root().join("root");
    std::fs::create_dir_all(&rws).unwrap();
    tree.insert_root(AgentNode {
        id: AgentId("agent-1".into()),
        kind: AgentKind::Root,
        parent: None,
        workspace_path: rws,
        capabilities: Vec::new(),
        template_ref: None,
        status: AgentStatus::Active,
    })
    .unwrap();
    let store = Arc::new(DefaultDecompositionStore::new(tree.clone()));
    let events = Arc::new(Mutex::new(Vec::new()));
    let bundle = AgentLifecycleBundle {
        tree: tree.clone(),
        spawner: Arc::new(DefaultSpawner::new(tree.clone(), Arc::new(OkGate))),
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
        decomposition: store.clone(),
        stats: Arc::new(DefaultStatsController::new(tree.clone(), Arc::new(OkStats))),
        templates: Arc::new(BuiltinTemplateRegistry::new()),
        submit_gate: Arc::new(StubSubmit),
        event_bus: Arc::new(CapturingBus(events.clone())),
    };
    let reg = InMemoryHostRegistry::new();
    register_agent_lifecycle(&reg, bundle);
    (reg, store, events)
}

fn call_op(
    reg: &InMemoryHostRegistry,
    name: &str,
    params: Vec<Val>,
) -> Result<Vec<Val>, HostCallError> {
    let specs = reg.lookup(AGENT_LIFECYCLE_CAPABILITY);
    let h = &specs.iter().find(|s| s.name == name).unwrap().handler;
    let ctx = HostCallContext {
        agent_id: "agent-1".into(),
        trace_id: "t".into(),
        turn_id: None,
        capability: "lifecycle".into(),
        function: "f".into(),
        run_id: None,
        iteration: None,
    };
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(HostFunctionHandler::call(h.as_ref(), ctx, params, 1))
}

fn submit_params(task: &str, strategy: &str, subtasks: &[&str]) -> Vec<Val> {
    vec![
        Val::String(task.into()),
        Val::String("goal".into()),
        Val::String(strategy.into()),
        Val::List(subtasks.iter().map(|s| Val::String((*s).into())).collect()),
    ]
}

#[test]
fn t37_submit_emits_task_decomposed_with_payload() {
    let (reg, _store, events) = real_decomp_dispatch();
    let res = call_op(
        &reg,
        "submit-decomposition",
        submit_params("task-1", "decompose", &["a|_self|do", "b|_self|do|a"]),
    )
    .expect("dispatch ok");
    assert!(matches!(res[0], Val::Result(Ok(_))), "submit ok: {res:?}");
    let evs = events.lock().unwrap();
    assert_eq!(evs.len(), 1, "exactly one event on success");
    let e = &evs[0];
    assert_eq!(e.event_type, "task.decomposed");
    assert_eq!(e.agent_id, "agent-1", "agent from ctx, not a guest param");
    assert_eq!(e.task_id.as_deref(), Some("task-1"));
    assert_eq!(e.payload["strategy"].as_str(), Some("decompose"));
    assert_eq!(e.payload["subtask_count"].as_u64(), Some(2));
    let assignees = e.payload["assignees"].as_array().expect("assignees array");
    assert!(assignees.iter().any(|v| v.as_str() == Some("_self")));
}

#[test]
fn t37_submit_delegate_single_renders_bare_kebab_tag() {
    let (reg, _store, events) = real_decomp_dispatch();
    // delegate-single reads assignee at param 4, prompt at param 5.
    let params = vec![
        Val::String("task-dl".into()),
        Val::String("goal".into()),
        Val::String("delegate-single".into()),
        Val::List(vec![]),
        Val::String("research".into()),
        Val::String("analyze".into()),
    ];
    let res = call_op(&reg, "submit-decomposition", params).expect("dispatch ok");
    assert!(matches!(res[0], Val::Result(Ok(_))), "submit ok: {res:?}");
    let evs = events.lock().unwrap();
    assert_eq!(evs.len(), 1);
    // Bare family tag (inner target dropped) — NOT serde snake_case
    // `delegate_single`.
    assert_eq!(evs[0].payload["strategy"].as_str(), Some("delegate-single"));
    assert_eq!(evs[0].payload["subtask_count"].as_u64(), Some(0));
}

#[test]
fn t37_update_emits_task_subtask_updated_old_to_new() {
    let (reg, store, events) = real_decomp_dispatch();
    call_op(
        &reg,
        "submit-decomposition",
        submit_params("task-2", "decompose", &["a|_self|do"]),
    )
    .expect("submit ok");
    // Read back the minted subtask-id from the persisted state.
    let st = store.get("agent-1", "task-2").unwrap().unwrap();
    let sid = st.subtasks[0].subtask_id.clone();
    let res = call_op(
        &reg,
        "update-subtask-status",
        vec![
            Val::String("task-2".into()),
            Val::String(sid.clone()),
            Val::String("completed".into()),
            Val::String("done".into()),
        ],
    )
    .expect("dispatch ok");
    assert!(matches!(res[0], Val::Result(Ok(_))), "update ok: {res:?}");
    let evs = events.lock().unwrap();
    // [0] = task.decomposed (submit), [1] = task.subtask_updated (update).
    assert_eq!(evs.len(), 2);
    let e = &evs[1];
    assert_eq!(e.event_type, "task.subtask_updated");
    assert_eq!(e.task_id.as_deref(), Some("task-2"));
    assert_eq!(e.payload["subtask_id"].as_str(), Some(sid.as_str()));
    assert_eq!(e.payload["old_status"].as_str(), Some("pending"));
    assert_eq!(e.payload["new_status"].as_str(), Some("completed"));
}

#[test]
fn t37_cycle_via_wit_rejected_and_no_event() {
    // depends_on is now lifted through the WIT path (4th `|`-field), so a
    // cyclic plan submitted through the host-fn is rejected with a typed
    // dependency-cycle variant — and NO task.decomposed is emitted on failure.
    let (reg, _store, events) = real_decomp_dispatch();
    let res = call_op(
        &reg,
        "submit-decomposition",
        submit_params("task-cyc", "decompose", &["a|_self|do|b", "b|_self|do|a"]),
    )
    .expect("dispatch ok (typed domain err, not host trap)");
    match &res[0] {
        Val::Result(Err(Some(b))) => match b.as_ref() {
            Val::Variant(case, _) => assert_eq!(case, "dependency-cycle"),
            other => panic!("unexpected err payload {other:?}"),
        },
        other => panic!("expected typed dependency-cycle Err, got {other:?}"),
    }
    assert_eq!(events.lock().unwrap().len(), 0, "no event on failed submit");
}

#[test]
fn t37_oversized_descriptor_is_host_trap() {
    // A subtask descriptor whose 4th `|`-field is a pathological multi-hundred-KB
    // dependency run exceeds MAX_DESCRIPTOR_BYTES (128 KiB) → call-shape host
    // trap, bounded BEFORE any depends_on amplification, and no event emitted.
    let (reg, _store, events) = real_decomp_dispatch();
    let big = format!("a|_self|do|{}", "x,".repeat(200_000)); // ~400 KB > 128 KiB
    let res = call_op(
        &reg,
        "submit-decomposition",
        submit_params("task-big", "decompose", &[big.as_str()]),
    );
    assert!(
        matches!(res, Err(HostCallError::HandlerError(_))),
        "oversized descriptor must be a host trap, got {res:?}"
    );
    assert_eq!(
        events.lock().unwrap().len(),
        0,
        "no event on rejected submit"
    );
}

#[test]
fn t37_oversized_descriptor_list_is_host_trap() {
    // A descriptor LIST longer than MAX_DECOMPOSITION_SUBTASKS (256) is bounded
    // BEFORE lifting all of them — host trap, no event (adversarial r8 W1).
    let (reg, _store, events) = real_decomp_dispatch();
    let descriptors: Vec<String> = (0..257).map(|i| format!("t{i}|_self|do")).collect();
    let refs: Vec<&str> = descriptors.iter().map(String::as_str).collect();
    let res = call_op(
        &reg,
        "submit-decomposition",
        submit_params("task-many", "decompose", &refs),
    );
    assert!(
        matches!(res, Err(HostCallError::HandlerError(_))),
        "over-long descriptor list must be a host trap, got {res:?}"
    );
    assert_eq!(events.lock().unwrap().len(), 0);
}

#[test]
fn t37_wit_lift_carries_depends_on() {
    // A valid DAG submitted through the WIT path persists resolved-id deps —
    // proving the lift no longer drops depends_on.
    let (reg, store, _events) = real_decomp_dispatch();
    call_op(
        &reg,
        "submit-decomposition",
        submit_params("task-dag", "decompose", &["a|_self|do", "b|_self|do|a"]),
    )
    .expect("submit ok");
    let st = store.get("agent-1", "task-dag").unwrap().unwrap();
    let a_id = st
        .subtasks
        .iter()
        .find(|s| s.title == "a")
        .unwrap()
        .subtask_id
        .clone();
    let b = st.subtasks.iter().find(|s| s.title == "b").unwrap();
    assert_eq!(
        b.depends_on,
        vec![a_id],
        "WIT lift must carry depends_on (resolved title→id)"
    );
}

// ── harvest-obs (2026-06-10): stats wire-shape pins ─────────────────────────

/// Rich (non-zero) stats reader so every lowered field is distinguishable.
struct RichStats;
impl AgentStatsReader for RichStats {
    fn read_stats(&self, _: &str) -> Result<AgentStats, LifecycleError> {
        Ok(AgentStats {
            active_tasks: 2,
            completed_tasks: 9,
            avg_turns_per_task: 1.5,
            avg_completion_time_hours: 0.25,
            memory_entries: 11,
            llm_tokens_24h: 4242,
            error_count_24h: 3,
            last_active: "2026-06-10T00:00:00Z".into(),
        })
    }
}

/// Bundle with a caller-controlled stats reader (tree shared via clone).
fn bundle_with_stats(reader: Arc<dyn AgentStatsReader>) -> AgentLifecycleBundle {
    let mut b = bundle_with(Arc::new(RecDecomp(Arc::new(Mutex::new(vec![])))));
    b.stats = Arc::new(DefaultStatsController::new(b.tree.clone(), reader));
    b
}

fn stats_ctx(caller: &str, op: &str) -> advance_runtime::host_registry::HostCallContext {
    advance_runtime::host_registry::HostCallContext {
        agent_id: caller.into(),
        trace_id: "t".into(),
        turn_id: None,
        capability: "lifecycle".into(),
        function: format!("advance:runtime/agent-lifecycle::{op}"),
        run_id: None,
        iteration: None,
    }
}

/// harvest-obs wire-shape pin: `self-stats` lowers the FULL `agent-stats`
/// record per CONTRACT-041 (`result<agent-stats, lifecycle-error>`), not a
/// bare string (the pre-2026-06-10 bug). Field names + order pinned verbatim
/// to `wit/agent-lifecycle.wit` `record agent-stats`.
#[test]
fn t_self_stats_lowers_full_agent_stats_record() {
    use advance_runtime::host_registry::HostFunctionHandler;
    let reg = InMemoryHostRegistry::new();
    register_agent_lifecycle(&reg, bundle_with_stats(Arc::new(RichStats)));
    let specs = reg.lookup(AGENT_LIFECYCLE_CAPABILITY);
    let h = &specs
        .iter()
        .find(|s| s.name == "self-stats")
        .unwrap()
        .handler;
    let rt = tokio::runtime::Runtime::new().unwrap();
    let res = rt
        .block_on(HostFunctionHandler::call(
            h.as_ref(),
            stats_ctx("agent-1", "self-stats"),
            vec![],
            1,
        ))
        .expect("self-stats dispatch ok");
    assert_eq!(res.len(), 1);
    let Val::Result(Ok(Some(rec))) = &res[0] else {
        panic!("expected Val::Result(Ok(Some(_))), got {:?}", res[0])
    };
    let Val::Record(fields) = rec.as_ref() else {
        panic!("expected Val::Record (the agent-stats record), got {rec:?}")
    };
    let expected: Vec<(&str, Val)> = vec![
        ("active-tasks", Val::U32(2)),
        ("completed-tasks", Val::U32(9)),
        ("avg-turns-per-task", Val::Float32(1.5)),
        ("avg-completion-time-hours", Val::Float32(0.25)),
        ("memory-entries", Val::U32(11)),
        ("llm-tokens-24h", Val::U64(4242)),
        ("error-count-24h", Val::U32(3)),
        ("last-active", Val::String("2026-06-10T00:00:00Z".into())),
    ];
    assert_eq!(fields.len(), 8, "agent-stats has exactly 8 fields");
    for (i, (name, val)) in expected.iter().enumerate() {
        assert_eq!(
            fields[i].0.as_str(),
            *name,
            "field {i} name (WIT order pinned)"
        );
        assert_eq!(&fields[i].1, val, "field {i} value");
    }
}

/// harvest-obs discrimination pin at the WIT boundary: child-stats lowers the
/// full record on the happy leg, and DISTINCT `lifecycle-error` variants for
/// non-child-existing (`permission-denied`) vs absent (`not-found`).
#[test]
fn t_child_stats_record_and_error_variants_distinct() {
    use advance_runtime::host_registry::HostFunctionHandler;
    let b = bundle_with_stats(Arc::new(RichStats));
    let cws = b.tree.workspace_root().join("root/c1");
    std::fs::create_dir_all(&cws).unwrap();
    b.tree
        .insert_child(
            &AgentId("agent-1".into()),
            AgentNode {
                id: AgentId("c1".into()),
                kind: AgentKind::Child,
                parent: Some(AgentId("agent-1".into())),
                workspace_path: cws,
                capabilities: Vec::new(),
                template_ref: None,
                status: AgentStatus::Active,
            },
        )
        .unwrap();
    let reg = InMemoryHostRegistry::new();
    register_agent_lifecycle(&reg, b);
    let specs = reg.lookup(AGENT_LIFECYCLE_CAPABILITY);
    let h = &specs
        .iter()
        .find(|s| s.name == "child-stats")
        .unwrap()
        .handler;
    let rt = tokio::runtime::Runtime::new().unwrap();

    // Happy leg: parent agent-1 queries child c1 → full record.
    let ok = rt
        .block_on(HostFunctionHandler::call(
            h.as_ref(),
            stats_ctx("agent-1", "child-stats"),
            vec![Val::String("c1".into())],
            1,
        ))
        .expect("child-stats happy dispatch ok");
    let Val::Result(Ok(Some(rec))) = &ok[0] else {
        panic!("expected ok-record, got {:?}", ok[0])
    };
    assert!(
        matches!(rec.as_ref(), Val::Record(f) if f.len() == 8),
        "child-stats happy leg lowers the 8-field record, got {rec:?}"
    );

    // Non-child EXISTING agent (caller c1 → agent-1) → permission-denied.
    let pd = rt
        .block_on(HostFunctionHandler::call(
            h.as_ref(),
            stats_ctx("c1", "child-stats"),
            vec![Val::String("agent-1".into())],
            1,
        ))
        .expect("child-stats non-child dispatch ok");
    let Val::Result(Err(Some(v))) = &pd[0] else {
        panic!("expected err-variant, got {:?}", pd[0])
    };
    let Val::Variant(case, _) = v.as_ref() else {
        panic!("expected Val::Variant, got {v:?}")
    };
    assert_eq!(case, "permission-denied", "non-child existing agent");

    // Absent agent → not-found (distinct from permission-denied; SYS-AC-232's
    // module-level discrimination).
    let nf = rt
        .block_on(HostFunctionHandler::call(
            h.as_ref(),
            stats_ctx("agent-1", "child-stats"),
            vec![Val::String("ghost-z".into())],
            1,
        ))
        .expect("child-stats absent dispatch ok");
    let Val::Result(Err(Some(v))) = &nf[0] else {
        panic!("expected err-variant, got {:?}", nf[0])
    };
    let Val::Variant(case, _) = v.as_ref() else {
        panic!("expected Val::Variant, got {v:?}")
    };
    assert_eq!(case, "not-found", "absent agent id");
}

// ── MODULE-005-T38 — terminate-event emission (AC-28, lifecycle-harvest) ───

/// Real tree (root agent-1 → child-a → grand-1[Sub]) + real
/// DefaultTerminateController + CapturingBus, driven through the WIT dispatch.
fn terminate_fixture() -> (InMemoryHostRegistry, Arc<Mutex<Vec<Event>>>) {
    let tmp = Box::leak(Box::new(TempDir::new().unwrap()));
    let tree = AgentTreeStore::new(tmp.path().to_path_buf()).unwrap();
    let root_ws = tree.workspace_root().join("root");
    let child_ws = root_ws.join("child-a");
    let grand_ws = child_ws.join(".sub").join("grand-1");
    std::fs::create_dir_all(&grand_ws).unwrap();
    tree.insert_root(AgentNode {
        id: AgentId("agent-1".into()),
        kind: AgentKind::Root,
        parent: None,
        workspace_path: root_ws,
        capabilities: Vec::new(),
        template_ref: None,
        status: AgentStatus::Active,
    })
    .unwrap();
    tree.insert_child(
        &AgentId("agent-1".into()),
        AgentNode {
            id: AgentId("child-a".into()),
            kind: AgentKind::Child,
            parent: Some(AgentId("agent-1".into())),
            workspace_path: child_ws,
            capabilities: Vec::new(),
            template_ref: None,
            status: AgentStatus::Active,
        },
    )
    .unwrap();
    tree.insert_child(
        &AgentId("child-a".into()),
        AgentNode {
            id: AgentId("grand-1".into()),
            kind: AgentKind::Sub,
            parent: Some(AgentId("child-a".into())),
            workspace_path: grand_ws,
            capabilities: Vec::new(),
            template_ref: None,
            status: AgentStatus::Active,
        },
    )
    .unwrap();
    let events = Arc::new(Mutex::new(Vec::new()));
    let bundle = AgentLifecycleBundle {
        tree: tree.clone(),
        spawner: Arc::new(DefaultSpawner::new(tree.clone(), Arc::new(OkGate))),
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
        decomposition: Arc::new(RecDecomp(Arc::new(Mutex::new(vec![])))),
        stats: Arc::new(DefaultStatsController::new(tree.clone(), Arc::new(OkStats))),
        templates: Arc::new(BuiltinTemplateRegistry::new()),
        submit_gate: Arc::new(StubSubmit),
        event_bus: Arc::new(CapturingBus(events.clone())),
    };
    let reg = InMemoryHostRegistry::new();
    register_agent_lifecycle(&reg, bundle);
    (reg, events)
}

fn call_op_as(
    reg: &InMemoryHostRegistry,
    caller: &str,
    name: &str,
    params: Vec<Val>,
) -> Result<Vec<Val>, HostCallError> {
    use advance_runtime::host_registry::{HostCallContext, HostFunctionHandler};
    let specs = reg.lookup(AGENT_LIFECYCLE_CAPABILITY);
    let h = &specs.iter().find(|s| s.name == name).unwrap().handler;
    let ctx = HostCallContext {
        agent_id: caller.into(),
        trace_id: "t".into(),
        turn_id: None,
        capability: "lifecycle".into(),
        function: "f".into(),
        run_id: None,
        iteration: None,
    };
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(HostFunctionHandler::call(h.as_ref(), ctx, params, 1))
}

#[test]
fn t38_terminate_child_emits_root_event_plus_cascade() {
    let (reg, events) = terminate_fixture();
    let res = call_op_as(
        &reg,
        "agent-1",
        "terminate-child",
        vec![Val::String("child-a".into())],
    )
    .expect("dispatch ok");
    assert!(
        matches!(&res[0], Val::Result(Ok(None))),
        "terminate-child ok: {:?}",
        res[0]
    );

    let evs = events.lock().unwrap();
    assert_eq!(
        evs.len(),
        2,
        "terminate_child(root) + terminate_agent(cascade): {evs:?}"
    );
    let root = &evs[0];
    assert_eq!(root.event_type, "lifecycle.terminate_child");
    assert_eq!(root.payload["initiator"], "agent-1");
    assert_eq!(root.payload["child_id"], "child-a");
    assert_eq!(root.payload["reason"], "terminate-child");
    assert_eq!(
        root.payload.as_object().unwrap().len(),
        3,
        "exactly 3 payload keys"
    );
    let casc = &evs[1];
    assert_eq!(casc.event_type, "lifecycle.terminate_agent");
    assert_eq!(casc.payload["initiator"], "agent-1");
    assert_eq!(casc.payload["agent_id"], "grand-1");
    assert_eq!(casc.payload["agent_kind"], "sub");
    assert_eq!(casc.payload["reason"], "cascade");
    assert_eq!(
        casc.payload.as_object().unwrap().len(),
        4,
        "exactly 4 payload keys"
    );
    // Redaction: no workspace path material in either payload.
    for e in evs.iter() {
        let dump = serde_json::to_string(&e.payload).unwrap();
        assert!(
            !dump.contains(".sub"),
            "no workspace paths in payload: {dump}"
        );
        assert!(!dump.contains("/"), "no path separators in payload: {dump}");
    }
}

#[test]
fn t38_terminate_agent_emits_target_event_plus_cascade() {
    let (reg, events) = terminate_fixture();
    let res = call_op_as(
        &reg,
        "agent-1",
        "terminate-agent",
        vec![Val::String("child-a".into())],
    )
    .expect("dispatch ok");
    assert!(
        matches!(&res[0], Val::Result(Ok(None))),
        "terminate-agent ok: {:?}",
        res[0]
    );

    let evs = events.lock().unwrap();
    assert_eq!(
        evs.len(),
        2,
        "terminate_agent(target) + terminate_agent(cascade): {evs:?}"
    );
    let target = &evs[0];
    assert_eq!(target.event_type, "lifecycle.terminate_agent");
    assert_eq!(target.payload["agent_id"], "child-a");
    assert_eq!(target.payload["agent_kind"], "child");
    assert_eq!(target.payload["reason"], "terminate-agent");
    let casc = &evs[1];
    assert_eq!(casc.event_type, "lifecycle.terminate_agent");
    assert_eq!(casc.payload["agent_id"], "grand-1");
    assert_eq!(casc.payload["agent_kind"], "sub");
    assert_eq!(casc.payload["reason"], "cascade");
}

#[test]
fn t38_terminate_errors_emit_nothing() {
    // Non-parent caller → typed permission-denied, zero events.
    let (reg, events) = terminate_fixture();
    let res = call_op_as(
        &reg,
        "intruder",
        "terminate-child",
        vec![Val::String("child-a".into())],
    )
    .expect("dispatch ok (typed domain error)");
    let Val::Result(Err(Some(v))) = &res[0] else {
        panic!("expected err-variant, got {:?}", res[0])
    };
    let Val::Variant(case, _) = v.as_ref() else {
        panic!("expected variant")
    };
    assert_eq!(case, "permission-denied");
    assert_eq!(
        events.lock().unwrap().len(),
        0,
        "no emit on PermissionDenied"
    );

    // Absent target → not-found, zero events.
    let (reg2, events2) = terminate_fixture();
    let res2 = call_op_as(
        &reg2,
        "agent-1",
        "terminate-child",
        vec![Val::String("ghost".into())],
    )
    .expect("dispatch ok (typed domain error)");
    let Val::Result(Err(Some(v2))) = &res2[0] else {
        panic!("expected err-variant, got {:?}", res2[0])
    };
    let Val::Variant(case2, _) = v2.as_ref() else {
        panic!("expected variant")
    };
    assert_eq!(case2, "not-found");
    assert_eq!(events2.lock().unwrap().len(), 0, "no emit on NotFound");
}

/// AC-28 BFS-transitivity witness (adversarial r8 coverage-gap close): the
/// cascade set is the target's FULL pre-snapshot subtree, not just direct
/// children. Tree: agent-1 → child-a → grand-1 → ggc-1 (3 levels under the
/// target). terminate-child on child-a must emit a cascade
/// `lifecycle.terminate_agent` for BOTH grand-1 AND the great-grandchild ggc-1.
#[test]
fn t38_terminate_child_cascade_is_transitive_to_great_grandchild() {
    let tmp = Box::leak(Box::new(TempDir::new().unwrap()));
    let tree = AgentTreeStore::new(tmp.path().to_path_buf()).unwrap();
    let root_ws = tree.workspace_root().join("root");
    let child_ws = root_ws.join("child-a");
    let grand_ws = child_ws.join("grand-1");
    let ggc_ws = grand_ws.join("ggc-1");
    std::fs::create_dir_all(&ggc_ws).unwrap();
    tree.insert_root(AgentNode {
        id: AgentId("agent-1".into()),
        kind: AgentKind::Root,
        parent: None,
        workspace_path: root_ws,
        capabilities: Vec::new(),
        template_ref: None,
        status: AgentStatus::Active,
    })
    .unwrap();
    for (parent, id, ws) in [
        ("agent-1", "child-a", &child_ws),
        ("child-a", "grand-1", &grand_ws),
        ("grand-1", "ggc-1", &ggc_ws),
    ] {
        tree.insert_child(
            &AgentId(parent.into()),
            AgentNode {
                id: AgentId(id.into()),
                kind: AgentKind::Child,
                parent: Some(AgentId(parent.into())),
                workspace_path: ws.clone(),
                capabilities: Vec::new(),
                template_ref: None,
                status: AgentStatus::Active,
            },
        )
        .unwrap();
    }
    let events = Arc::new(Mutex::new(Vec::new()));
    let bundle = AgentLifecycleBundle {
        tree: tree.clone(),
        spawner: Arc::new(DefaultSpawner::new(tree.clone(), Arc::new(OkGate))),
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
        decomposition: Arc::new(RecDecomp(Arc::new(Mutex::new(vec![])))),
        stats: Arc::new(DefaultStatsController::new(tree.clone(), Arc::new(OkStats))),
        templates: Arc::new(BuiltinTemplateRegistry::new()),
        submit_gate: Arc::new(StubSubmit),
        event_bus: Arc::new(CapturingBus(events.clone())),
    };
    let reg = InMemoryHostRegistry::new();
    register_agent_lifecycle(&reg, bundle);

    let res = call_op_as(
        &reg,
        "agent-1",
        "terminate-child",
        vec![Val::String("child-a".into())],
    )
    .expect("dispatch ok");
    assert!(matches!(&res[0], Val::Result(Ok(None))), "ok: {:?}", res[0]);

    let evs = events.lock().unwrap();
    // 1 terminate_child(child-a) + 2 cascade terminate_agent (grand-1, ggc-1).
    assert_eq!(
        evs.len(),
        3,
        "transitive cascade through 2 descendant levels: {evs:?}"
    );
    assert_eq!(evs[0].event_type, "lifecycle.terminate_child");
    assert_eq!(evs[0].payload["child_id"], "child-a");
    let cascade_ids: Vec<&str> = evs[1..]
        .iter()
        .map(|e| {
            assert_eq!(e.event_type, "lifecycle.terminate_agent");
            assert_eq!(e.payload["reason"], "cascade");
            e.payload["agent_id"].as_str().unwrap()
        })
        .collect();
    assert!(
        cascade_ids.contains(&"grand-1"),
        "direct child cascaded: {cascade_ids:?}"
    );
    assert!(
        cascade_ids.contains(&"ggc-1"),
        "GREAT-grandchild cascaded (BFS transitivity): {cascade_ids:?}"
    );
}

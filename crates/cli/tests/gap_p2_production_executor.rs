//! Pack lane P2 — the PRODUCTION `WorkflowExecutor`
//! end to end: `SchedulerWorkflowExecutor` over a real template-resolving
//! `DefaultSpawner` (cap-lifecycle agent tree + pack template), the real
//! scheduler `InMemoryComponentSubmitApi`, the trust-gated MCP bridge and the
//! in-memory MCP entry sink, driven by `DefaultMaterializer::apply_workflow`.
//!
//! - success path: spawn-child materializes the child from the pack template,
//!   submit-component admits the pack's task component under its FQ ref,
//!   register-mcp-server (http) lands in the sink;
//! - failure path: an untrusted pack's stdio mcp-server is refused at step 2
//!   → the step-1 spawn is COMPENSATED for real: tree node gone, child
//!   workspace gone, `WorkflowStepFailed` names the compensation.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use advance_cli::pack_bridges::InMemoryMcpEntrySink;
use advance_cli::pack_production::{ClosureSecretStore, SchedulerWorkflowExecutor};
use advance_pack_manager::{
    AutoApprove, DefaultMaterializer, InMemoryPackRegistry, Installer, MaterializeAction,
    PackError, PackRegistry, SecretStore, WorkflowContext, WorkflowExecutor,
};
use advance_scheduler::{ComponentSubmitApi, InMemoryComponentSubmitApi};
use advance_shared_types::agent_tree::{AgentId, AgentKind, AgentNode, AgentStatus};
use cap_lifecycle::pack_template_resolver::PackTemplateResolver;
use cap_lifecycle::templates::TemplateResolver;
use cap_lifecycle::{
    AgentTreeStore, CapGrantSubsetAdapter, DefaultSpawner, LifecycleError, Spawner,
    TerminateController,
};

const TEMPLATE_YAML: &str = "name: researcher\nversion: 1.0.0\ndescription: Research template\nbehavior:\n  type: embedded\n  binary: behavior.wasm\ndefault-model: sonnet\n";
const COMPONENT_YAML: &str = "component-type: task\nbinary: ./nightly.wasm\ncapabilities: []\n";
const MCP_HTTP: &str = "server-id: remote-tools\ndescription: http server\ntransport:\n  kind: http\n  endpoint-url: https://mcp.example.com/sse\n";
const MCP_STDIO: &str =
    "server-id: local-tools\ntransport:\n  kind: stdio\n  command: /usr/bin/true\n";
const WF_OK: &str = "name: ok\nsteps:\n  - type: spawn-child\n    template: p@1.0.0/agent-templates/researcher\n    target-path: /research-assistant\n  - type: submit-component\n    ref: p@1.0.0/components/nightly\n    schedule: \"0 3 * * *\"\n  - type: register-mcp-server\n    config-ref: p@1.0.0/mcp-servers/remote\n";
const WF_FAIL: &str = "name: fail\nsteps:\n  - type: spawn-child\n    template: p@1.0.0/agent-templates/researcher\n    target-path: /doomed-assistant\n  - type: register-mcp-server\n    config-ref: p@1.0.0/mcp-servers/local\n";

fn write_pack(root: &Path) -> PathBuf {
    let dir = root.join("p-src");
    let t = dir.join("agent-templates/researcher");
    std::fs::create_dir_all(&t).unwrap();
    std::fs::write(t.join("template.yaml"), TEMPLATE_YAML).unwrap();
    std::fs::write(t.join("AGENTS.md"), "# researcher\n").unwrap();
    std::fs::write(t.join("behavior.wasm"), b"\0asm\x01\0\0\0").unwrap();
    let c = dir.join("components/nightly");
    std::fs::create_dir_all(&c).unwrap();
    std::fs::write(c.join("component.yaml"), COMPONENT_YAML).unwrap();
    std::fs::write(c.join("nightly.wasm"), b"\0asm\x01\0\0\0").unwrap();
    std::fs::create_dir_all(dir.join("mcp-servers")).unwrap();
    std::fs::write(dir.join("mcp-servers/remote.yaml"), MCP_HTTP).unwrap();
    std::fs::write(dir.join("mcp-servers/local.yaml"), MCP_STDIO).unwrap();
    std::fs::create_dir_all(dir.join("workflows")).unwrap();
    std::fs::write(dir.join("workflows/ok.yaml"), WF_OK).unwrap();
    std::fs::write(dir.join("workflows/fail.yaml"), WF_FAIL).unwrap();
    std::fs::write(
        dir.join("pack.yaml"),
        "name: p\nversion: 1.0.0\nruntime-version: \">=0.1.0\"\ntrust-level: untrusted\nprovides:\n  agent-templates:\n    - researcher\n  components:\n    - nightly\n  mcp-servers:\n    - remote\n    - local\n  workflows:\n    - ok\n    - fail\nchecksums:\n  algo: sha256\n  files: {}\n",
    )
    .unwrap();
    dir
}

struct Rig {
    tree: Arc<AgentTreeStore>,
    submit: Arc<InMemoryComponentSubmitApi>,
    sink: Arc<InMemoryMcpEntrySink>,
    executor: Arc<SchedulerWorkflowExecutor>,
    materializer: DefaultMaterializer,
    workspace: PathBuf,
}

async fn rig(tmp: &Path) -> Rig {
    let workspace = tmp.join("ws");
    std::fs::create_dir_all(&workspace).unwrap();
    let packs = tmp.join("packs");
    let registry = Arc::new(InMemoryPackRegistry::new(packs.clone()));
    Installer::new(&packs, registry.clone(), "0.1.0", Arc::new(AutoApprove))
        .install(write_pack(tmp).to_str().unwrap())
        .await
        .expect("install");
    let registry_dyn: Arc<dyn PackRegistry> = registry;

    let tree = Arc::new(AgentTreeStore::new(workspace.clone()).unwrap());
    tree.insert_root(AgentNode {
        id: AgentId("root".into()),
        kind: AgentKind::Root,
        parent: None,
        workspace_path: workspace.canonicalize().unwrap(),
        capabilities: Vec::new(),
        template_ref: None,
        status: AgentStatus::Active,
    })
    .unwrap();
    let resolver: Arc<dyn TemplateResolver> =
        Arc::new(PackTemplateResolver::new(registry_dyn.clone()));
    let spawner: Arc<dyn Spawner> = Arc::new(DefaultSpawner::with_template_resolver(
        (*tree).clone(),
        Arc::new(CapGrantSubsetAdapter::new()),
        resolver,
    ));
    let submit = Arc::new(InMemoryComponentSubmitApi::new());
    let sink = Arc::new(InMemoryMcpEntrySink::new());
    let secrets: Arc<dyn SecretStore> = Arc::new(ClosureSecretStore::new(|_| None));
    let executor = Arc::new(SchedulerWorkflowExecutor::new(
        spawner,
        Arc::clone(&tree),
        AgentId("root".into()),
        Arc::clone(&submit) as Arc<dyn ComponentSubmitApi>,
        "root",
        registry_dyn.clone(),
        Arc::clone(&secrets),
        Arc::clone(&sink) as Arc<dyn advance_cli::pack_bridges::McpEntrySink>,
        tokio::runtime::Handle::current(),
    ));
    let materializer = DefaultMaterializer::new(
        registry_dyn,
        Arc::clone(&executor) as Arc<dyn WorkflowExecutor>,
        secrets,
    );
    Rig {
        tree,
        submit,
        sink,
        executor,
        materializer,
        workspace,
    }
}

/// A recording stand-in for the lifecycle cascade: removes the leaf like the
/// real controller's last step and records `(caller, child)`.
struct RecordingTerminator {
    tree: Arc<AgentTreeStore>,
    calls: std::sync::Mutex<Vec<(String, String)>>,
}

impl TerminateController for RecordingTerminator {
    fn terminate_child(&self, caller_id: &str, child_id: &str) -> Result<(), LifecycleError> {
        self.calls
            .lock()
            .unwrap()
            .push((caller_id.to_string(), child_id.to_string()));
        self.tree
            .remove(&AgentId(child_id.to_string()))
            .map(|_| ())
            .map_err(|e| LifecycleError::NotFound(format!("{e}")))
    }
    fn terminate_agent(&self, _: &str, _: &str) -> Result<(), LifecycleError> {
        unreachable!("not used by the executor")
    }
    fn handle_crash(&self, _: &str, _: &str) -> Result<(), LifecycleError> {
        unreachable!("not used by the executor")
    }
}

/// Absolute `target-path`s need an explicit containment root (the applier's
/// existing `validate_target_path` gate); `/` = admin-driven local install.
fn ctx() -> WorkflowContext {
    WorkflowContext {
        admin_id: "admin".into(),
        target_workspace: PathBuf::from("/"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pe_01_success_path_spawns_submits_and_registers() {
    let tmp = tempfile::TempDir::new().unwrap();
    let r = rig(tmp.path()).await;

    let report = r
        .materializer
        .apply_workflow("p@1.0.0/workflows/ok", ctx())
        .expect("all three production legs succeed");
    assert_eq!(
        report.steps_executed,
        vec![
            "spawn-child".to_string(),
            "submit-component".to_string(),
            "register-mcp-server".to_string()
        ]
    );

    // spawn-child: a real child node under the root, materialized from the
    // pack template into `<ws>/research-assistant/.agent/`.
    let child = r
        .tree
        .get_node(&AgentId("research-assistant".into()))
        .expect("child node inserted");
    assert_eq!(child.parent, Some(AgentId("root".into())));
    assert_eq!(
        child.template_ref.as_deref(),
        Some("p@1.0.0/agent-templates/researcher")
    );
    assert!(child.workspace_path.join(".agent/AGENTS.md").is_file());

    // submit-component: admitted under the FQ ref as the scheduler id.
    let listed = r.submit.list_components().await;
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id.as_str(), "p@1.0.0/components/nightly");

    // register-mcp-server: the http entry reached the sink.
    assert_eq!(r.sink.server_ids(), vec!["remote-tools".to_string()]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pe_02_trust_refusal_compensates_the_real_spawn() {
    let tmp = tempfile::TempDir::new().unwrap();
    let r = rig(tmp.path()).await;

    let err = r
        .materializer
        .apply_workflow("p@1.0.0/workflows/fail", ctx())
        .expect_err("stdio from an untrusted pack is refused");
    match err {
        PackError::WorkflowStepFailed {
            step,
            source,
            compensated,
            compensation_failures,
        } => {
            assert!(step.contains("register-mcp-server"), "{step}");
            assert!(
                matches!(*source, PackError::ConstraintViolation { .. }),
                "trust refusal surfaces as the step error: {source:?}"
            );
            assert_eq!(
                compensated,
                vec!["spawn-child:/doomed-assistant".to_string()]
            );
            assert!(
                compensation_failures.is_empty(),
                "{compensation_failures:?}"
            );
        }
        other => panic!("expected WorkflowStepFailed, got {other:?}"),
    }
    // The compensation was REAL: no tree node, no workspace directory.
    assert!(r
        .tree
        .get_node(&AgentId("doomed-assistant".into()))
        .is_none());
    assert!(!r.workspace.join("doomed-assistant").exists());
    assert!(r.sink.is_empty());
    assert!(r.submit.list_components().await.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pe_03_spawn_config_and_filter_strings_are_refused_not_dropped() {
    let tmp = tempfile::TempDir::new().unwrap();
    let r = rig(tmp.path()).await;
    let exec: &dyn WorkflowExecutor = &*r.materializer.executor;

    let mut config = std::collections::BTreeMap::new();
    config.insert("model".to_string(), serde_yml::Value::from("opus"));
    let err = exec
        .spawn_child(
            "p@1.0.0/agent-templates/researcher",
            Path::new("/x"),
            &config,
        )
        .unwrap_err();
    assert!(matches!(err, PackError::InvalidWorkflow(m) if m.contains("config")));
    assert!(r.tree.get_node(&AgentId("x".into())).is_none());

    let err = exec
        .submit_component(
            "p@1.0.0/components/nightly",
            &advance_pack_manager::WorkflowTrigger::TriggerEvent {
                event_type: "task.completed".into(),
                filter: Some("agent=x".into()),
            },
        )
        .unwrap_err();
    assert!(matches!(err, PackError::InvalidWorkflow(m) if m.contains("filter")));
    assert!(r.submit.list_components().await.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pe_04_compensation_goes_through_the_lifecycle_cascade_when_installed() {
    let tmp = tempfile::TempDir::new().unwrap();
    let r = rig(tmp.path()).await;
    let terminator = Arc::new(RecordingTerminator {
        tree: Arc::clone(&r.tree),
        calls: std::sync::Mutex::new(Vec::new()),
    });
    assert!(!r.executor.has_terminate_controller());
    r.executor
        .set_terminate_controller(Arc::clone(&terminator) as Arc<dyn TerminateController>)
        .unwrap();
    assert!(
        r.executor
            .set_terminate_controller(Arc::clone(&terminator) as Arc<dyn TerminateController>)
            .is_err(),
        "one-shot slot"
    );

    let err = r
        .materializer
        .apply_workflow("p@1.0.0/workflows/fail", ctx())
        .expect_err("stdio from an untrusted pack is refused");
    assert!(
        matches!(err, PackError::WorkflowStepFailed { .. }),
        "{err:?}"
    );
    // The cascade was invoked with the executor's parent as caller …
    assert_eq!(
        terminator.calls.lock().unwrap().clone(),
        vec![("root".to_string(), "doomed-assistant".to_string())]
    );
    // … and the workspace the spawn created is gone too (the cascade keeps
    // Child territories; the undo must not).
    assert!(r
        .tree
        .get_node(&AgentId("doomed-assistant".into()))
        .is_none());
    assert!(!r.workspace.join("doomed-assistant").exists());
}

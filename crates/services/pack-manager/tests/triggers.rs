//! AC-09 — five materialization triggers (T42-T46).
//!
//! AC-09 enumerates five triggers from MODULE-018 §1.3.3 that each route to
//! a `MaterializeAction` method:
//!  - spawn-sub template → `materialize_template` (target = sub workspace)
//!  - spawn-child template → `materialize_template` (target = child workspace)
//!  - submit-component → `materialize_component` (returns runtime-internal path)
//!  - workflow apply → `apply_workflow` (delegates to WorkflowApplier)
//!  - CLI materialize → `materialize_skill` (target = admin-supplied path)
//!
//! Each test exercises the corresponding code path with a representative
//! target. Triggers T42 and T43 use the same `materialize_template` method
//! but different target-path semantics matching §1.3.3 rows 1-2.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use advance_pack_manager::{
    AutoApprove, DefaultMaterializer, InMemoryPackRegistry, Installer, MaterializeAction,
    McpServerId, PackError, PackRegistry, RecordingTraceSink, SecretStore, SecretValue,
    WorkflowContext, WorkflowExecutor, WorkflowTrigger,
};

fn build_pack_with_template_skill_component_workflow(root: &Path, name: &str) -> PathBuf {
    let pack_dir = root.join(format!("source-{name}"));
    std::fs::create_dir_all(&pack_dir).unwrap();
    // Required artifacts.
    std::fs::create_dir_all(pack_dir.join("agent-templates").join("researcher")).unwrap();
    std::fs::write(
        pack_dir
            .join("agent-templates")
            .join("researcher")
            .join("AGENTS.md"),
        b"# template",
    )
    .unwrap();
    std::fs::create_dir_all(pack_dir.join("skills").join("web-search")).unwrap();
    std::fs::write(
        pack_dir.join("skills").join("web-search").join("SKILL.md"),
        b"# skill",
    )
    .unwrap();
    std::fs::create_dir_all(pack_dir.join("components").join("daily-summary")).unwrap();
    std::fs::write(
        pack_dir
            .join("components")
            .join("daily-summary")
            .join("component.yaml"),
        b"id: daily-summary",
    )
    .unwrap();
    std::fs::create_dir_all(pack_dir.join("workflows")).unwrap();
    std::fs::write(
        pack_dir.join("workflows").join("auto-research.yaml"),
        format!(
            r#"name: auto-research
steps:
  - type: spawn-child
    template: {name}@1.0.0/agent-templates/researcher
    target-path: /research-assistant
"#
        ),
    )
    .unwrap();
    std::fs::write(
        pack_dir.join("pack.yaml"),
        format!(
            r#"name: {name}
version: 1.0.0
runtime-version: ">=0.0.1"
dependencies: []
provides:
  agent-templates: [researcher]
  skills: [web-search]
  components: [daily-summary]
  workflows: [auto-research]
required-capabilities: []
trust-level: untrusted
checksums:
  algo: sha256
  files: {{}}
"#
        ),
    )
    .unwrap();
    pack_dir
}

async fn install(name: &str) -> (tempfile::TempDir, Arc<InMemoryPackRegistry>) {
    let dir = tempfile::TempDir::new().unwrap();
    let pack_src = build_pack_with_template_skill_component_workflow(dir.path(), name);
    let packs_dir = dir.path().join("packs");
    let registry = Arc::new(InMemoryPackRegistry::new(packs_dir.clone()));
    let sink = Arc::new(RecordingTraceSink::new());
    let installer = Installer {
        packs_dir,
        registry: registry.clone(),
        current_runtime_version: "0.5.0".into(),
        approval: Arc::new(AutoApprove),
        trace_sink: sink,
        dep_resolver: None,
        event_bus: None,
        registry_client: None,
        fetch_timeout: None,
    };
    installer
        .install(pack_src.to_string_lossy().as_ref())
        .await
        .expect("install fixture");
    (dir, registry)
}

#[derive(Default)]
struct MockExecutor {
    calls: Mutex<Vec<String>>,
}
impl WorkflowExecutor for MockExecutor {
    fn spawn_child(
        &self,
        template_ref: &str,
        _target_path: &Path,
        _config: &BTreeMap<String, serde_yml::Value>,
    ) -> Result<(), PackError> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("spawn-child:{template_ref}"));
        Ok(())
    }
    fn submit_component(
        &self,
        component_ref: &str,
        _trigger: &WorkflowTrigger,
    ) -> Result<(), PackError> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("submit-component:{component_ref}"));
        Ok(())
    }
    fn register_mcp_server(
        &self,
        config_ref: &str,
        _resolved_secrets: &BTreeMap<String, SecretValue>,
    ) -> Result<McpServerId, PackError> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("register-mcp-server:{config_ref}"));
        Ok(McpServerId("mock".into()))
    }
}

#[derive(Default)]
struct MockSecretStore;
impl SecretStore for MockSecretStore {
    fn get(&self, _key: &str) -> Option<SecretValue> {
        Some(SecretValue::new("mock"))
    }
}

fn make_materializer(
    registry: Arc<InMemoryPackRegistry>,
) -> (Arc<MockExecutor>, DefaultMaterializer) {
    let executor_inner = Arc::new(MockExecutor::default());
    let executor: Arc<dyn WorkflowExecutor> = executor_inner.clone();
    let secret_store: Arc<dyn SecretStore> = Arc::new(MockSecretStore);
    let registry_dyn: Arc<dyn PackRegistry> = registry;
    (
        executor_inner,
        DefaultMaterializer::new(registry_dyn, executor, secret_store),
    )
}

#[tokio::test]
async fn t42_spawn_sub_trigger_materializes_template_to_sub_workspace() {
    let (_dir, registry) = install("packA").await;
    let (_, mat) = make_materializer(registry);
    let target_dir = tempfile::TempDir::new().unwrap();
    let sub_target = target_dir.path().join(".sub-uuid-xyz").join(".agent");
    // Caller pre-creates the parent dir; copy_dir_no_symlinks owns the
    // final dst creation (non-recursive `create_dir`).
    std::fs::create_dir_all(sub_target.parent().unwrap()).unwrap();
    mat.materialize_template("packA@1.0.0/agent-templates/researcher", &sub_target)
        .unwrap();
    assert!(sub_target.exists());
    assert!(sub_target.join("AGENTS.md").exists());
}

#[tokio::test]
async fn t43_spawn_child_trigger_materializes_template_to_child_workspace() {
    let (_dir, registry) = install("packB").await;
    let (_, mat) = make_materializer(registry);
    let target_dir = tempfile::TempDir::new().unwrap();
    let child_target = target_dir.path().join("research-assistant").join(".agent");
    std::fs::create_dir_all(child_target.parent().unwrap()).unwrap();
    mat.materialize_template("packB@1.0.0/agent-templates/researcher", &child_target)
        .unwrap();
    assert!(child_target.join("AGENTS.md").exists());
}

#[tokio::test]
async fn t44_submit_component_trigger_returns_runtime_internal_path() {
    let (_dir, registry) = install("packC").await;
    let (_, mat) = make_materializer(registry);
    let dummy_target = PathBuf::from("/ignored");
    let path = mat
        .materialize_component("packC@1.0.0/components/daily-summary", &dummy_target)
        .unwrap();
    assert!(path.ends_with("components/daily-summary"));
    assert!(path.exists());
}

#[tokio::test]
async fn t45_workflow_apply_trigger_drives_workflow_steps() {
    let (_dir, registry) = install("packD").await;
    let (executor_inner, mat) = make_materializer(registry);
    let ctx = WorkflowContext {
        admin_id: "admin".into(),
        target_workspace: PathBuf::from("/"),
    };
    let report = mat
        .apply_workflow("packD@1.0.0/workflows/auto-research", ctx)
        .unwrap();
    assert_eq!(report.steps_executed, vec!["spawn-child".to_string()]);
    let calls = executor_inner.calls.lock().unwrap().clone();
    assert_eq!(calls.len(), 1);
    assert!(calls[0].starts_with("spawn-child:packD@1.0.0/agent-templates/researcher"));
}

#[tokio::test]
async fn t46_cli_materialize_skill_trigger_copies_skill_tree() {
    let (_dir, registry) = install("packE").await;
    let (_, mat) = make_materializer(registry);
    let target_dir = tempfile::TempDir::new().unwrap();
    let target = target_dir.path().join("admin-supplied-skill-target");
    mat.materialize_skill("packE@1.0.0/skills/web-search", &target)
        .unwrap();
    assert!(target.join("SKILL.md").exists());
}

//! DefaultMaterializer integration tests (Slice B, AC-02).
//!
//! T32 — 10-content-types manifest + trait surface
//! T34 — materialize_template copies tree
//! T35 — materialize_skill copies tree
//! T36 — materialize_component returns local path
//! T37 — register_mcp_server returns deterministic id (pre-resolved pass-through)
//! T31b — apply_workflow CONTRACT-171 delegation to WorkflowApplier

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use advance_pack_manager::{
    AutoApprove, DefaultMaterializer, InMemoryPackRegistry, Installer, MaterializeAction,
    McpServerId, PackError, PackManifest, PackRegistry, RecordingTraceSink, SecretStore,
    SecretValue, WorkflowContext, WorkflowExecutor, WorkflowTrigger,
};

// ───── helpers ──────────────────────────────────────────────────────

fn build_pack_with_all_10_provides(root: &Path, name: &str, version: &str) -> PathBuf {
    let pack_dir = root.join(format!("source-{name}"));
    std::fs::create_dir_all(&pack_dir).unwrap();

    // File-backed kinds: behavior-binaries/*.wasm, mcp-servers/*.yaml,
    // presets/*.yaml, workflows/*.yaml, memory-seeds/*.jsonl,
    // meta-schema-extensions/*.yaml
    std::fs::create_dir_all(pack_dir.join("behavior-binaries")).unwrap();
    std::fs::write(
        pack_dir.join("behavior-binaries").join("researcher.wasm"),
        b"",
    )
    .unwrap();
    std::fs::create_dir_all(pack_dir.join("mcp-servers")).unwrap();
    std::fs::write(
        pack_dir.join("mcp-servers").join("brave.yaml"),
        b"name: brave",
    )
    .unwrap();
    std::fs::create_dir_all(pack_dir.join("presets")).unwrap();
    std::fs::write(
        pack_dir.join("presets").join("research-auto.yaml"),
        b"caps: []",
    )
    .unwrap();
    std::fs::create_dir_all(pack_dir.join("workflows")).unwrap();
    std::fs::write(
        pack_dir.join("workflows").join("auto-research.yaml"),
        WORKFLOW_YAML_FIXTURE,
    )
    .unwrap();
    std::fs::create_dir_all(pack_dir.join("memory-seeds")).unwrap();
    std::fs::write(
        pack_dir.join("memory-seeds").join("researcher-seed.jsonl"),
        b"{}",
    )
    .unwrap();
    std::fs::create_dir_all(pack_dir.join("meta-schema-extensions")).unwrap();
    std::fs::write(
        pack_dir
            .join("meta-schema-extensions")
            .join("research-meta.yaml"),
        b"ext: {}",
    )
    .unwrap();

    // Directory-backed kinds: agent-templates/{name}/, skills/{name}/,
    // components/{name}/, channel-adapters/{name}/
    std::fs::create_dir_all(pack_dir.join("agent-templates").join("researcher")).unwrap();
    std::fs::write(
        pack_dir
            .join("agent-templates")
            .join("researcher")
            .join("AGENTS.md"),
        b"# Researcher template",
    )
    .unwrap();
    std::fs::create_dir_all(pack_dir.join("skills").join("web-search")).unwrap();
    std::fs::write(
        pack_dir.join("skills").join("web-search").join("SKILL.md"),
        b"# Web search skill",
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
    std::fs::create_dir_all(pack_dir.join("channel-adapters").join("telegram-adapter")).unwrap();
    std::fs::write(
        pack_dir
            .join("channel-adapters")
            .join("telegram-adapter")
            .join("adapter.yaml"),
        b"name: telegram",
    )
    .unwrap();

    let pack_yaml = format!(
        r#"name: {name}
version: {version}
runtime-version: ">=0.0.1"
dependencies: []
provides:
  behavior-binaries: [researcher]
  agent-templates: [researcher]
  skills: [web-search]
  components: [daily-summary]
  channel-adapters: [telegram-adapter]
  mcp-servers: [brave]
  presets: [research-auto]
  workflows: [auto-research]
  memory-seeds: [researcher-seed]
  meta-schema-extensions: [research-meta]
required-capabilities: []
trust-level: untrusted
checksums:
  algo: sha256
  files: {{}}
"#
    );
    std::fs::write(pack_dir.join("pack.yaml"), pack_yaml).unwrap();
    pack_dir
}

// A workflow file deliberately uses the same pack's components (consistent FQ
// refs). All steps go through MockExecutor in T31b.
const WORKFLOW_YAML_FIXTURE: &[u8] = br#"name: auto-research
steps:
  - type: spawn-child
    template: bigpack@1.0.0/agent-templates/researcher
    target-path: /research-assistant
  - type: submit-component
    ref: bigpack@1.0.0/components/daily-summary
    schedule: "0 9 * * *"
  - type: register-mcp-server
    config-ref: bigpack@1.0.0/mcp-servers/brave
    secret-refs:
      api-key: brave-api-key
"#;

// MockExecutor / MockSecretStore for materialize T31b
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
        Some(SecretValue::new("mock-secret"))
    }
}

// Install a pack into a real on-disk registry + return registry.
async fn install_fixture_pack(
    name: &str,
    version: &str,
) -> (tempfile::TempDir, Arc<InMemoryPackRegistry>) {
    let dir = tempfile::TempDir::new().unwrap();
    let pack_src = build_pack_with_all_10_provides(dir.path(), name, version);
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

// ───── T32 — 10 content types parsed + trait surface ──────────────────

#[tokio::test]
async fn t32_manifest_parses_all_10_provides_kinds() {
    let yaml = r#"name: bigpack
version: 1.0.0
runtime-version: ">=0.0.1"
dependencies: []
provides:
  behavior-binaries: [researcher]
  agent-templates: [researcher]
  skills: [web-search]
  components: [daily-summary]
  channel-adapters: [telegram-adapter]
  mcp-servers: [brave]
  presets: [research-auto]
  workflows: [auto-research]
  memory-seeds: [researcher-seed]
  meta-schema-extensions: [research-meta]
required-capabilities: []
trust-level: untrusted
checksums:
  algo: sha256
  files: {}
"#;
    let m = PackManifest::from_yaml(yaml).unwrap();
    assert_eq!(m.provides.behavior_binaries.len(), 1);
    assert_eq!(m.provides.agent_templates.len(), 1);
    assert_eq!(m.provides.skills.len(), 1);
    assert_eq!(m.provides.components.len(), 1);
    assert_eq!(m.provides.channel_adapters.len(), 1);
    assert_eq!(m.provides.mcp_servers.len(), 1);
    assert_eq!(m.provides.presets.len(), 1);
    assert_eq!(m.provides.workflows.len(), 1);
    assert_eq!(m.provides.memory_seeds.len(), 1);
    assert_eq!(m.provides.meta_schema_extensions.len(), 1);
}

#[tokio::test]
async fn t32_materialize_action_trait_has_10_methods() {
    // The 10 method names must exist on `dyn MaterializeAction`. Use a struct
    // stub to assert compile-time presence of each signature. If a method is
    // renamed or removed, this test fails to compile.
    struct StubMaterializer;
    impl MaterializeAction for StubMaterializer {
        fn materialize_binary(&self, _: &str, _: &Path) -> Result<PathBuf, PackError> {
            Ok(PathBuf::new())
        }
        fn materialize_template(&self, _: &str, _: &Path) -> Result<(), PackError> {
            Ok(())
        }
        fn materialize_skill(&self, _: &str, _: &Path) -> Result<(), PackError> {
            Ok(())
        }
        fn materialize_component(&self, _: &str, _: &Path) -> Result<PathBuf, PackError> {
            Ok(PathBuf::new())
        }
        fn materialize_channel_adapter(&self, _: &str, _: &Path) -> Result<PathBuf, PackError> {
            Ok(PathBuf::new())
        }
        fn register_mcp_server(
            &self,
            _: &str,
            _: &HashMap<String, String>,
        ) -> Result<McpServerId, PackError> {
            Ok(McpServerId("x".into()))
        }
        fn apply_preset(
            &self,
            _: &str,
            _: &str,
        ) -> Result<Vec<advance_pack_manager::GrantId>, PackError> {
            Ok(vec![])
        }
        fn apply_workflow(
            &self,
            _: &str,
            _: WorkflowContext,
        ) -> Result<advance_pack_manager::WorkflowReport, PackError> {
            Ok(Default::default())
        }
        fn copy_memory_seed(&self, _: &str, _: &Path) -> Result<(), PackError> {
            Ok(())
        }
        fn merge_meta_schema_extension(&self, _: &str, _: &Path) -> Result<(), PackError> {
            Ok(())
        }
        // AC-17 (m018-rescap): the 11th method — added so the stub compiles against
        // the widened trait. This test's assertions below stay AC-02 scope (the 10
        // §19.3 methods); the 11th method's behaviour is covered by the AC-17 suite.
        fn register_resource_capability(
            &self,
            _: &str,
        ) -> Result<advance_pack_manager::ResourceCapabilityId, PackError> {
            Ok(advance_pack_manager::ResourceCapabilityId("x".into()))
        }
    }
    let m: Box<dyn MaterializeAction> = Box::new(StubMaterializer);
    // Confirm dynamic dispatch routes to all 10 methods at runtime (compile-time
    // check is the strict assertion; this is the runtime sanity).
    let _: Result<PathBuf, _> = m.materialize_binary("x", Path::new("/tmp"));
    let _ = m.materialize_template("x", Path::new("/tmp"));
    let _ = m.materialize_skill("x", Path::new("/tmp"));
    let _ = m.materialize_component("x", Path::new("/tmp"));
    let _ = m.materialize_channel_adapter("x", Path::new("/tmp"));
    let _ = m.register_mcp_server("x", &HashMap::new());
    let _ = m.apply_preset("x", "agent-id");
    let _ = m.apply_workflow("x", WorkflowContext::default());
    let _ = m.copy_memory_seed("x", Path::new("/tmp"));
    let _ = m.merge_meta_schema_extension("x", Path::new("/tmp"));
}

/// Slice C — function name retained for git-diff readability; body
/// rewritten from `NotImplemented` assertions to `MaterializeMissingProvide`
/// defense-in-depth coverage. Each of the 5 newly-concrete methods is
/// called with an FQ ref of the WRONG kind and must surface
/// `MaterializeMissingProvide`. Positive happy-path coverage for all 5
/// methods is in T59-T63 below.
#[tokio::test]
async fn t32_default_materializer_non_impl_methods_return_not_implemented() {
    let (_dir, registry) = install_fixture_pack("bigpack", "1.0.0").await;
    let registry_dyn: Arc<dyn PackRegistry> = registry.clone();
    let executor: Arc<dyn WorkflowExecutor> = Arc::new(MockExecutor::default());
    let secret_store: Arc<dyn SecretStore> = Arc::new(MockSecretStore);
    let mat = DefaultMaterializer::new(registry_dyn, executor, secret_store);

    let target = tempfile::TempDir::new().unwrap();
    // materialize_binary expects Binary kind — feed it AgentTemplate.
    assert!(matches!(
        mat.materialize_binary("bigpack@1.0.0/agent-templates/researcher", target.path()),
        Err(PackError::MaterializeMissingProvide { .. })
    ));
    // materialize_channel_adapter expects ChannelAdapter — feed it Skill.
    assert!(matches!(
        mat.materialize_channel_adapter("bigpack@1.0.0/skills/web-search", target.path()),
        Err(PackError::MaterializeMissingProvide { .. })
    ));
    // apply_preset expects Preset — feed it MemorySeed.
    assert!(matches!(
        mat.apply_preset("bigpack@1.0.0/memory-seeds/researcher-seed", "agent-id"),
        Err(PackError::MaterializeMissingProvide { .. })
    ));
    // copy_memory_seed expects MemorySeed — feed it Preset.
    assert!(matches!(
        mat.copy_memory_seed(
            "bigpack@1.0.0/presets/research-auto",
            &target.path().join("seed.jsonl")
        ),
        Err(PackError::MaterializeMissingProvide { .. })
    ));
    // merge_meta_schema_extension expects MetaSchemaExtension — feed it Workflow.
    assert!(matches!(
        mat.merge_meta_schema_extension(
            "bigpack@1.0.0/workflows/auto-research",
            &target.path().join("merged-schema.yaml")
        ),
        Err(PackError::MaterializeMissingProvide { .. })
    ));
}

// ───── T34 — materialize_template copies tree ────────────────────────

#[tokio::test]
async fn t34_materialize_template_copies_tree() {
    let (_dir, registry) = install_fixture_pack("bigpack", "1.0.0").await;
    let registry_dyn: Arc<dyn PackRegistry> = registry.clone();
    let executor: Arc<dyn WorkflowExecutor> = Arc::new(MockExecutor::default());
    let secret_store: Arc<dyn SecretStore> = Arc::new(MockSecretStore);
    let mat = DefaultMaterializer::new(registry_dyn, executor, secret_store);

    let target_dir = tempfile::TempDir::new().unwrap();
    let target = target_dir.path().join("dst-template");
    mat.materialize_template("bigpack@1.0.0/agent-templates/researcher", &target)
        .unwrap();
    assert!(target.exists());
    assert!(target.join("AGENTS.md").exists());
}

// ───── T35 — materialize_skill copies tree ────────────────────────────

#[tokio::test]
async fn t35_materialize_skill_copies_tree() {
    let (_dir, registry) = install_fixture_pack("bigpack", "1.0.0").await;
    let registry_dyn: Arc<dyn PackRegistry> = registry.clone();
    let executor: Arc<dyn WorkflowExecutor> = Arc::new(MockExecutor::default());
    let secret_store: Arc<dyn SecretStore> = Arc::new(MockSecretStore);
    let mat = DefaultMaterializer::new(registry_dyn, executor, secret_store);

    let target_dir = tempfile::TempDir::new().unwrap();
    let target = target_dir.path().join("dst-skill");
    mat.materialize_skill("bigpack@1.0.0/skills/web-search", &target)
        .unwrap();
    assert!(target.exists());
    assert!(target.join("SKILL.md").exists());
}

// ───── T36 — materialize_component returns runtime-internal path ──────

#[tokio::test]
async fn t36_materialize_component_returns_local_path() {
    let (_dir, registry) = install_fixture_pack("bigpack", "1.0.0").await;
    let registry_dyn: Arc<dyn PackRegistry> = registry.clone();
    let executor: Arc<dyn WorkflowExecutor> = Arc::new(MockExecutor::default());
    let secret_store: Arc<dyn SecretStore> = Arc::new(MockSecretStore);
    let mat = DefaultMaterializer::new(registry_dyn, executor, secret_store);

    let dummy_target = PathBuf::from("/ignored-by-component-materializer");
    let path = mat
        .materialize_component("bigpack@1.0.0/components/daily-summary", &dummy_target)
        .unwrap();
    assert!(
        path.ends_with("components/daily-summary"),
        "expected install_path/components/daily-summary, got {path:?}"
    );
    assert!(path.exists(), "returned path must point at installed pack");
}

// ───── T37 — register_mcp_server returns deterministic id ─────────────

#[tokio::test]
async fn t37_register_mcp_server_returns_deterministic_id() {
    let (_dir, registry) = install_fixture_pack("bigpack", "1.0.0").await;
    let registry_dyn: Arc<dyn PackRegistry> = registry.clone();
    let executor: Arc<dyn WorkflowExecutor> = Arc::new(MockExecutor::default());
    let secret_store: Arc<dyn SecretStore> = Arc::new(MockSecretStore);
    let mat = DefaultMaterializer::new(registry_dyn, executor, secret_store);

    let mut pre_resolved = HashMap::new();
    pre_resolved.insert("api-key".to_string(), "pre-resolved-secret".to_string());
    let id = mat
        .register_mcp_server("bigpack@1.0.0/mcp-servers/brave", &pre_resolved)
        .unwrap();
    assert_eq!(id.0, "bigpack@1.0.0/brave");
}

// ───── T31b — apply_workflow CONTRACT-171 entry delegates to WorkflowApplier ──

#[tokio::test]
async fn t31b_apply_workflow_delegates_to_workflow_applier() {
    let (_dir, registry) = install_fixture_pack("bigpack", "1.0.0").await;
    let registry_dyn: Arc<dyn PackRegistry> = registry.clone();
    let executor_inner = Arc::new(MockExecutor::default());
    let executor: Arc<dyn WorkflowExecutor> = executor_inner.clone();
    let secret_store: Arc<dyn SecretStore> = Arc::new(MockSecretStore);
    let mat = DefaultMaterializer::new(registry_dyn, executor, secret_store);

    // target_workspace = "/" → absolute paths allowed under root (the fixture's
    // /research-assistant target-path passes validation).
    let ctx = WorkflowContext {
        admin_id: "admin".into(),
        target_workspace: PathBuf::from("/"),
    };
    let report = mat
        .apply_workflow("bigpack@1.0.0/workflows/auto-research", ctx)
        .unwrap();
    assert_eq!(
        report.steps_executed,
        vec![
            "spawn-child".to_string(),
            "submit-component".to_string(),
            "register-mcp-server".to_string()
        ]
    );
    let calls = executor_inner.calls.lock().unwrap().clone();
    assert_eq!(calls.len(), 3);
}

// ───── Adversarial round 1 regression: workflow-file symlink + size cap ───

#[tokio::test]
#[cfg(unix)]
async fn apply_workflow_rejects_post_install_symlink_swap() {
    let (dir, registry) = install_fixture_pack("bigpack", "1.0.0").await;
    let registry_dyn: Arc<dyn PackRegistry> = registry.clone();
    let executor: Arc<dyn WorkflowExecutor> = Arc::new(MockExecutor::default());
    let secret_store: Arc<dyn SecretStore> = Arc::new(MockSecretStore);
    let mat = DefaultMaterializer::new(registry_dyn, executor, secret_store);

    // Simulate post-install tampering: replace the workflow file with a symlink
    // pointing at /etc/hosts (or any out-of-pack file). The apply_workflow
    // entrypoint must reject before reading.
    let wf_path = dir
        .path()
        .join("packs")
        .join("bigpack@1.0.0")
        .join("workflows")
        .join("auto-research.yaml");
    let bait_path = dir.path().join("bait.yaml");
    std::fs::write(&bait_path, b"name: evil\nsteps: []\n").unwrap();
    std::fs::remove_file(&wf_path).unwrap();
    std::os::unix::fs::symlink(&bait_path, &wf_path).unwrap();

    let ctx = WorkflowContext {
        admin_id: "admin".into(),
        target_workspace: PathBuf::from("/"),
    };
    match mat.apply_workflow("bigpack@1.0.0/workflows/auto-research", ctx) {
        Err(PackError::InvalidWorkflow(msg)) => assert!(
            msg.contains("symlink"),
            "expected symlink rejection, got: {msg}"
        ),
        other => panic!("expected InvalidWorkflow(symlink), got {other:?}"),
    }
}

#[tokio::test]
async fn apply_workflow_rejects_oversized_yaml() {
    let (dir, registry) = install_fixture_pack("bigpack", "1.0.0").await;
    let registry_dyn: Arc<dyn PackRegistry> = registry.clone();
    let executor: Arc<dyn WorkflowExecutor> = Arc::new(MockExecutor::default());
    let secret_store: Arc<dyn SecretStore> = Arc::new(MockSecretStore);
    let mat = DefaultMaterializer::new(registry_dyn, executor, secret_store);

    // Overwrite the workflow file with a 1 MiB + 1 byte payload — exceeds
    // the materialize-time cap (MAX_WORKFLOW_YAML_BYTES_AT_MATERIALIZE = 1 MiB).
    let wf_path = dir
        .path()
        .join("packs")
        .join("bigpack@1.0.0")
        .join("workflows")
        .join("auto-research.yaml");
    let oversized = vec![b'a'; (1024 * 1024) + 1];
    std::fs::write(&wf_path, &oversized).unwrap();

    let ctx = WorkflowContext {
        admin_id: "admin".into(),
        target_workspace: PathBuf::from("/"),
    };
    match mat.apply_workflow("bigpack@1.0.0/workflows/auto-research", ctx) {
        Err(PackError::InvalidWorkflow(msg)) => assert!(
            msg.contains("exceeds max"),
            "expected size-cap rejection, got: {msg}"
        ),
        other => panic!("expected InvalidWorkflow(size cap), got {other:?}"),
    }
}

// ───── Cross-check: existing AC-13 cross-pack namespace still works ───
// (no new test needed — registry T13/T14/T29-T32 cover this; this file's
// tests don't require new namespace-collision coverage.)

// ───── Slice C AC-02 收尾 happy paths (T59-T63) ───────────────────────

#[tokio::test]
async fn t59_materialize_binary_copies_to_target_dir_with_wasm_extension() {
    let (_dir, registry) = install_fixture_pack("bigpackT59", "1.0.0").await;
    let registry_dyn: Arc<dyn PackRegistry> = registry.clone();
    let executor: Arc<dyn WorkflowExecutor> = Arc::new(MockExecutor::default());
    let secret_store: Arc<dyn SecretStore> = Arc::new(MockSecretStore);
    let mat = DefaultMaterializer::new(registry_dyn, executor, secret_store);

    let target_root = tempfile::TempDir::new().unwrap();
    let target_dir = target_root.path();
    let dest = mat
        .materialize_binary("bigpackT59@1.0.0/behavior-binaries/researcher", target_dir)
        .unwrap();
    assert_eq!(dest, target_dir.join("researcher.wasm"));
    assert!(dest.is_file(), "binary should be copied to target");
}

#[tokio::test]
async fn t60_materialize_channel_adapter_copies_directory_tree() {
    let (_dir, registry) = install_fixture_pack("bigpackT60", "1.0.0").await;
    let registry_dyn: Arc<dyn PackRegistry> = registry.clone();
    let executor: Arc<dyn WorkflowExecutor> = Arc::new(MockExecutor::default());
    let secret_store: Arc<dyn SecretStore> = Arc::new(MockSecretStore);
    let mat = DefaultMaterializer::new(registry_dyn, executor, secret_store);

    let target_root = tempfile::TempDir::new().unwrap();
    let target = target_root.path().join("dest-adapter");
    let returned = mat
        .materialize_channel_adapter(
            "bigpackT60@1.0.0/channel-adapters/telegram-adapter",
            &target,
        )
        .unwrap();
    assert_eq!(returned, target);
    assert!(target.join("adapter.yaml").is_file());
}

#[tokio::test]
async fn t61_apply_preset_validates_target_agent_id_and_returns_empty_grants() {
    let (_dir, registry) = install_fixture_pack("bigpackT61", "1.0.0").await;
    let registry_dyn: Arc<dyn PackRegistry> = registry.clone();
    let executor: Arc<dyn WorkflowExecutor> = Arc::new(MockExecutor::default());
    let secret_store: Arc<dyn SecretStore> = Arc::new(MockSecretStore);
    let mat = DefaultMaterializer::new(registry_dyn, executor, secret_store);

    // Happy path: ASCII agent-id, real preset kind → Ok(vec![]).
    let grants = mat
        .apply_preset("bigpackT61@1.0.0/presets/research-auto", "agent-123")
        .unwrap();
    assert!(grants.is_empty(), "Slice C placeholder returns no grants");

    // Empty target_agent_id → ConstraintViolation.
    match mat.apply_preset("bigpackT61@1.0.0/presets/research-auto", "") {
        Err(PackError::ConstraintViolation { reason }) => {
            assert!(reason.contains("non-empty"));
        }
        other => panic!("expected ConstraintViolation on empty id, got {other:?}"),
    }

    // Non-ASCII target_agent_id → ConstraintViolation.
    match mat.apply_preset("bigpackT61@1.0.0/presets/research-auto", "agent\u{1F4A9}") {
        Err(PackError::ConstraintViolation { reason }) => {
            assert!(reason.contains("ASCII"));
        }
        other => panic!("expected ConstraintViolation on non-ASCII id, got {other:?}"),
    }
}

#[tokio::test]
async fn t62_copy_memory_seed_writes_to_target_file() {
    let (_dir, registry) = install_fixture_pack("bigpackT62", "1.0.0").await;
    let registry_dyn: Arc<dyn PackRegistry> = registry.clone();
    let executor: Arc<dyn WorkflowExecutor> = Arc::new(MockExecutor::default());
    let secret_store: Arc<dyn SecretStore> = Arc::new(MockSecretStore);
    let mat = DefaultMaterializer::new(registry_dyn, executor, secret_store);

    let target_root = tempfile::TempDir::new().unwrap();
    let target_file = target_root.path().join("memory-seed.jsonl");
    mat.copy_memory_seed(
        "bigpackT62@1.0.0/memory-seeds/researcher-seed",
        &target_file,
    )
    .unwrap();
    assert!(target_file.is_file());

    // Re-run → fresh-destination invariant rejects pre-existing target.
    match mat.copy_memory_seed(
        "bigpackT62@1.0.0/memory-seeds/researcher-seed",
        &target_file,
    ) {
        Err(PackError::InvalidManifest(msg)) => assert!(msg.contains("must not pre-exist")),
        other => panic!("expected fresh-destination rejection, got {other:?}"),
    }
}

#[tokio::test]
async fn t63_merge_meta_schema_extension_appends_with_newline_normalization() {
    let (_dir, registry) = install_fixture_pack("bigpackT63", "1.0.0").await;
    let registry_dyn: Arc<dyn PackRegistry> = registry.clone();
    let executor: Arc<dyn WorkflowExecutor> = Arc::new(MockExecutor::default());
    let secret_store: Arc<dyn SecretStore> = Arc::new(MockSecretStore);
    let mat = DefaultMaterializer::new(registry_dyn, executor, secret_store);

    let target_root = tempfile::TempDir::new().unwrap();

    // (a) Target absent → copy source verbatim (ensure trailing newline).
    let target_a = target_root.path().join("schema-a.yaml");
    mat.merge_meta_schema_extension(
        "bigpackT63@1.0.0/meta-schema-extensions/research-meta",
        &target_a,
    )
    .unwrap();
    let body_a = std::fs::read(&target_a).unwrap();
    assert!(!body_a.is_empty());
    assert_eq!(*body_a.last().unwrap(), b'\n', "trailing newline ensured");

    // (b) Target exists WITH trailing newline → append `---\n` + source.
    let target_b = target_root.path().join("schema-b.yaml");
    std::fs::write(&target_b, b"existing: value\n").unwrap();
    mat.merge_meta_schema_extension(
        "bigpackT63@1.0.0/meta-schema-extensions/research-meta",
        &target_b,
    )
    .unwrap();
    let body_b = std::fs::read_to_string(&target_b).unwrap();
    assert!(body_b.starts_with("existing: value\n---\n"));
    assert!(body_b.contains("ext: {}"));

    // (c) Target exists WITHOUT trailing newline → newline normalised
    // before separator.
    let target_c = target_root.path().join("schema-c.yaml");
    std::fs::write(&target_c, b"existing: value").unwrap();
    mat.merge_meta_schema_extension(
        "bigpackT63@1.0.0/meta-schema-extensions/research-meta",
        &target_c,
    )
    .unwrap();
    let body_c = std::fs::read_to_string(&target_c).unwrap();
    assert!(
        body_c.starts_with("existing: value\n---\n"),
        "missing trailing newline must be normalised before separator: {body_c:?}"
    );
}

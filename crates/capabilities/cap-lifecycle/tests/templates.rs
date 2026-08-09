//! Integration tests for Slice B template materialization:
//! AC-07 (template structure), AC-08 (materialization onto spawn target),
//! AC-09 (memory-seed only when kind=child), AC-10 (4 built-in templates),
//! AC-19 (AGENTS.md Self-Improvement Guidelines marker).
//!
//! Also covers the spawn-side integration guards:
//! - template_ref set + resolver missing → InvalidConfig
//! - resolver returns NotFound → InvalidConfig + target_dir rollback
//! - template skill path traversal → PathTraversal (preserved across boundary)

use std::path::{Path, PathBuf};
use std::sync::Arc;

use advance_shared_types::agent_tree::{AgentId, AgentKind, AgentNode, AgentStatus, Capability};
use cap_lifecycle::{
    AgentTreeStore, BuiltinTemplateRegistry, DefaultSpawner, SpawnChildConfig, SpawnError,
    SpawnSubConfig, Spawner, SpawnerSubsetGate, TemplateContent, TemplateError, TemplateResolver,
    TemplateSkillEntry,
};
use tempfile::TempDir;

struct AlwaysOkGate;
impl SpawnerSubsetGate for AlwaysOkGate {
    fn check(&self, _p: &[Capability], _c: &[Capability]) -> Result<(), SpawnError> {
        Ok(())
    }
}

fn canon(p: &Path) -> PathBuf {
    p.canonicalize().expect("canonicalize")
}

fn setup_with_resolver(
    resolver: Arc<dyn TemplateResolver>,
) -> (TempDir, AgentTreeStore, DefaultSpawner) {
    let tmp = TempDir::new().unwrap();
    let workspace_root = canon(tmp.path());
    let tree = AgentTreeStore::new(workspace_root.clone()).unwrap();
    let root_ws = workspace_root.join("root_ws");
    std::fs::create_dir_all(&root_ws).unwrap();
    tree.insert_root(AgentNode {
        id: AgentId("root".to_string()),
        kind: AgentKind::Root,
        parent: None,
        workspace_path: root_ws,
        capabilities: Vec::new(),
        template_ref: None,
        status: AgentStatus::Active,
    })
    .unwrap();
    let spawner =
        DefaultSpawner::with_template_resolver(tree.clone(), Arc::new(AlwaysOkGate), resolver);
    (tmp, tree, spawner)
}

fn setup_no_resolver() -> (TempDir, AgentTreeStore, DefaultSpawner) {
    let tmp = TempDir::new().unwrap();
    let workspace_root = canon(tmp.path());
    let tree = AgentTreeStore::new(workspace_root.clone()).unwrap();
    let root_ws = workspace_root.join("root_ws");
    std::fs::create_dir_all(&root_ws).unwrap();
    tree.insert_root(AgentNode {
        id: AgentId("root".to_string()),
        kind: AgentKind::Root,
        parent: None,
        workspace_path: root_ws,
        capabilities: Vec::new(),
        template_ref: None,
        status: AgentStatus::Active,
    })
    .unwrap();
    let spawner = DefaultSpawner::new(tree.clone(), Arc::new(AlwaysOkGate));
    (tmp, tree, spawner)
}

#[test]
fn ti_t26_builtin_registry_lists_four_names() {
    let r = BuiltinTemplateRegistry::new();
    let names = r.list();
    assert_eq!(names.len(), 4);
    assert!(names.contains(&"explorer".to_string()));
    assert!(names.contains(&"planner".to_string()));
    assert!(names.contains(&"reviewer".to_string()));
    assert!(names.contains(&"general-purpose".to_string()));
}

#[test]
fn ti_t07_builtin_template_structure_present() {
    let r = BuiltinTemplateRegistry::new();
    for name in ["explorer", "planner", "reviewer", "general-purpose"] {
        let t = r.resolve(name).unwrap();
        assert!(
            !t.manifest_yaml.is_empty(),
            "manifest_yaml empty for {name}"
        );
        assert!(!t.agents_md.is_empty(), "agents_md empty for {name}");
        assert!(
            t.memory_seed_jsonl.is_some(),
            "memory_seed missing for {name}"
        );
    }
}

#[test]
fn ti_t19_agents_md_self_improvement_marker() {
    let r = BuiltinTemplateRegistry::new();
    for name in ["explorer", "planner", "reviewer", "general-purpose"] {
        let t = r.resolve(name).unwrap();
        assert!(
            t.agents_md.contains("Self-Improvement Guidelines"),
            "{name} agents_md missing marker: {}",
            t.agents_md
        );
    }
}

#[test]
fn ti_t08_spawn_child_with_template_overlays_files() {
    let (_tmp, tree, spawner) = setup_with_resolver(Arc::new(BuiltinTemplateRegistry::new()));
    spawner
        .spawn_child(SpawnChildConfig {
            parent_id: AgentId("root".to_string()),
            child_id: AgentId("foo".to_string()),
            child_workspace_path: PathBuf::from("agents/foo"),
            capabilities: Vec::new(),
            template_ref: Some("explorer".to_string()),
            binary: None,
        })
        .unwrap();
    let foo = tree.get_node(&AgentId("foo".to_string())).unwrap();
    let agent = foo.workspace_path.join(".agent");
    let config = std::fs::read_to_string(agent.join("config.yaml")).unwrap();
    assert!(config.contains("name: \"explorer\""));
    let agents_md = std::fs::read_to_string(agent.join("AGENTS.md")).unwrap();
    assert!(agents_md.contains("Self-Improvement Guidelines"));
    let knowledge = std::fs::read_to_string(agent.join("memory/knowledge.jsonl")).unwrap();
    assert!(
        knowledge.is_empty(),
        "child memory seed expected to be empty"
    );
}

#[test]
fn ti_t08_spawn_sub_with_template_overlays_files_no_memory() {
    let (_tmp, _tree, spawner) = setup_with_resolver(Arc::new(BuiltinTemplateRegistry::new()));
    let sub_id = spawner
        .spawn_sub(SpawnSubConfig {
            parent_id: AgentId("root".to_string()),
            capabilities: Vec::new(),
            template_ref: Some("planner".to_string()),
        })
        .unwrap();
    let sub = spawner.tree().get_node(&sub_id).unwrap();
    let agent = sub.workspace_path.join(".agent");
    assert!(agent.join("config.yaml").exists());
    assert!(agent.join("AGENTS.md").exists());
    assert!(
        !agent.join("memory").exists(),
        "sub must NOT get memory subtree"
    );
}

struct SubMemorySeedingResolver;

impl TemplateResolver for SubMemorySeedingResolver {
    fn resolve(&self, template_ref: &str) -> Result<TemplateContent, TemplateError> {
        if template_ref == "seed-sub" {
            Ok(TemplateContent {
                name: "seed-sub".to_string(),
                manifest_yaml: "name: seed-sub\n".to_string(),
                agents_md: "# Self-Improvement Guidelines\n".to_string(),
                skills: Vec::new(),
                memory_seed_jsonl: Some("{\"key\": \"value\"}\n".to_string()),
                behavior_wasm: None,
            })
        } else {
            Err(TemplateError::NotFound(template_ref.to_string()))
        }
    }

    fn list(&self) -> Vec<String> {
        vec!["seed-sub".to_string()]
    }
}

#[test]
fn ti_t09_spawn_sub_with_template_carrying_seed_does_not_write_memory() {
    let (_tmp, _tree, spawner) = setup_with_resolver(Arc::new(SubMemorySeedingResolver));
    let sub_id = spawner
        .spawn_sub(SpawnSubConfig {
            parent_id: AgentId("root".to_string()),
            capabilities: Vec::new(),
            template_ref: Some("seed-sub".to_string()),
        })
        .unwrap();
    let sub = spawner.tree().get_node(&sub_id).unwrap();
    let memory = sub.workspace_path.join(".agent").join("memory");
    assert!(
        !memory.exists(),
        "sub must NEVER get memory written even when template carries seed (AC-09)"
    );
}

#[test]
fn ti_template_ref_without_resolver_errors() {
    let (_tmp, _tree, spawner) = setup_no_resolver();
    let err = spawner
        .spawn_child(SpawnChildConfig {
            parent_id: AgentId("root".to_string()),
            child_id: AgentId("foo".to_string()),
            child_workspace_path: PathBuf::from("agents/foo"),
            capabilities: Vec::new(),
            template_ref: Some("explorer".to_string()),
            binary: None,
        })
        .unwrap_err();
    assert!(matches!(err, SpawnError::InvalidConfig(_)), "got {err:?}");
}

#[test]
fn ti_template_ref_unknown_errors_with_rollback() {
    let (_tmp, tree, spawner) = setup_with_resolver(Arc::new(BuiltinTemplateRegistry::new()));
    let parent_workspace = tree
        .get_node(&AgentId("root".to_string()))
        .unwrap()
        .workspace_path;
    let expected_target_dir = parent_workspace.join("agents").join("foo");
    let err = spawner
        .spawn_child(SpawnChildConfig {
            parent_id: AgentId("root".to_string()),
            child_id: AgentId("foo".to_string()),
            child_workspace_path: PathBuf::from("agents/foo"),
            capabilities: Vec::new(),
            template_ref: Some("nonexistent".to_string()),
            binary: None,
        })
        .unwrap_err();
    assert!(matches!(err, SpawnError::InvalidConfig(_)), "got {err:?}");
    assert!(
        !expected_target_dir.exists(),
        "target_dir must be rolled back when template resolution fails"
    );
}

struct BigManifestResolver;

impl TemplateResolver for BigManifestResolver {
    fn resolve(&self, _template_ref: &str) -> Result<TemplateContent, TemplateError> {
        Ok(TemplateContent {
            name: "big".to_string(),
            manifest_yaml: "x".repeat(cap_lifecycle::MAX_BYTES + 1),
            agents_md: String::new(),
            skills: Vec::new(),
            memory_seed_jsonl: None,
            behavior_wasm: None,
        })
    }
    fn list(&self) -> Vec<String> {
        vec!["big".to_string()]
    }
}

#[test]
fn ti_template_apply_failure_rolls_back_target_dir() {
    let (_tmp, tree, spawner) = setup_with_resolver(Arc::new(BigManifestResolver));
    let parent_workspace = tree
        .get_node(&AgentId("root".to_string()))
        .unwrap()
        .workspace_path;
    let expected_target_dir = parent_workspace.join("agents").join("bar");
    let err = spawner
        .spawn_child(SpawnChildConfig {
            parent_id: AgentId("root".to_string()),
            child_id: AgentId("bar".to_string()),
            child_workspace_path: PathBuf::from("agents/bar"),
            capabilities: Vec::new(),
            template_ref: Some("big".to_string()),
            binary: None,
        })
        .unwrap_err();
    assert!(matches!(err, SpawnError::InvalidConfig(_)), "got {err:?}");
    assert!(
        !expected_target_dir.exists(),
        "target_dir must be rolled back when apply_template fails"
    );
}

struct TraversalSkillResolver;

impl TemplateResolver for TraversalSkillResolver {
    fn resolve(&self, _template_ref: &str) -> Result<TemplateContent, TemplateError> {
        Ok(TemplateContent {
            name: "trav".to_string(),
            manifest_yaml: "name: trav\n".to_string(),
            agents_md: "# Self-Improvement Guidelines\n".to_string(),
            skills: vec![TemplateSkillEntry {
                relative_path: PathBuf::from("../escape.md"),
                content: b"oops".to_vec(),
            }],
            memory_seed_jsonl: None,
            behavior_wasm: None,
        })
    }
    fn list(&self) -> Vec<String> {
        vec!["trav".to_string()]
    }
}

#[test]
fn ti_template_skill_path_traversal_surfaces_as_path_traversal() {
    let (_tmp, _tree, spawner) = setup_with_resolver(Arc::new(TraversalSkillResolver));
    let err = spawner
        .spawn_child(SpawnChildConfig {
            parent_id: AgentId("root".to_string()),
            child_id: AgentId("baz".to_string()),
            child_workspace_path: PathBuf::from("agents/baz"),
            capabilities: Vec::new(),
            template_ref: Some("trav".to_string()),
            binary: None,
        })
        .unwrap_err();
    assert!(matches!(err, SpawnError::PathTraversal(_)), "got {err:?}");
}

// sat/template-materialization (2026-06-13): behavior.wasm materializes under the
// child workspace end-to-end via DefaultSpawner::with_template_resolver (AC-08).
struct BehaviorWasmResolver;

impl TemplateResolver for BehaviorWasmResolver {
    fn resolve(&self, _template_ref: &str) -> Result<TemplateContent, TemplateError> {
        Ok(TemplateContent {
            name: "behave".to_string(),
            manifest_yaml: "name: behave\n".to_string(),
            agents_md: "# Self-Improvement Guidelines\n".to_string(),
            skills: Vec::new(),
            memory_seed_jsonl: None,
            behavior_wasm: Some(b"\0asm\x01\0\0\0".to_vec()),
        })
    }
    fn list(&self) -> Vec<String> {
        vec!["behave".to_string()]
    }
}

#[test]
fn ti_bw_spawn_child_materializes_behavior_wasm() {
    let (_tmp, tree, spawner) = setup_with_resolver(Arc::new(BehaviorWasmResolver));
    spawner
        .spawn_child(SpawnChildConfig {
            parent_id: AgentId("root".to_string()),
            child_id: AgentId("bw".to_string()),
            child_workspace_path: PathBuf::from("agents/bw"),
            capabilities: Vec::new(),
            template_ref: Some("behave".to_string()),
            binary: None,
        })
        .unwrap();
    let node = tree.get_node(&AgentId("bw".to_string())).unwrap();
    let behavior = node.workspace_path.join(".agent").join("behavior.wasm");
    let bytes = std::fs::read(&behavior).expect("behavior.wasm materialized under child workspace");
    assert_eq!(bytes, b"\0asm\x01\0\0\0");
}

//! Integration tests for spawn_child + AC-02 + AC-22 coverage.

use std::path::PathBuf;
use std::sync::Arc;

use advance_shared_types::agent_tree::{
    AgentId, AgentKind, AgentNode, AgentStatus, AgentTreeReader, Capability,
};
use cap_lifecycle::{
    AgentTreeStore, DefaultSpawner, SpawnChildConfig, SpawnError, Spawner, SpawnerSubsetGate,
};
use tempfile::TempDir;

struct AlwaysOkGate;
impl SpawnerSubsetGate for AlwaysOkGate {
    fn check(&self, _p: &[Capability], _c: &[Capability]) -> Result<(), SpawnError> {
        Ok(())
    }
}

struct AlwaysFailGate;
impl SpawnerSubsetGate for AlwaysFailGate {
    fn check(&self, _p: &[Capability], _c: &[Capability]) -> Result<(), SpawnError> {
        Err(SpawnError::SubsetViolation("test deny".to_string()))
    }
}

fn setup() -> (TempDir, AgentTreeStore, DefaultSpawner) {
    let tmp = TempDir::new().unwrap();
    let workspace_root = tmp.path().to_path_buf();
    let tree = AgentTreeStore::new(workspace_root.clone()).expect("AgentTreeStore::new");
    // Pre-create a root workspace dir on disk; insert_root canonicalizes.
    let root_ws = tree.workspace_root().join("root_ws");
    std::fs::create_dir_all(&root_ws).unwrap();
    let root_node = AgentNode {
        id: AgentId("root".to_string()),
        kind: AgentKind::Root,
        parent: None,
        workspace_path: root_ws,
        capabilities: Vec::new(),
        template_ref: None,
        status: AgentStatus::Active,
    };
    tree.insert_root(root_node).expect("insert_root");
    let spawner = DefaultSpawner::new(tree.clone(), Arc::new(AlwaysOkGate));
    (tmp, tree, spawner)
}

#[test]
fn ti01_happy_path_creates_agent_skeleton() {
    let (_tmp, tree, spawner) = setup();
    let id = spawner
        .spawn_child(SpawnChildConfig {
            parent_id: AgentId("root".to_string()),
            child_id: AgentId("foo".to_string()),
            child_workspace_path: PathBuf::from("agents/foo"),
            capabilities: Vec::new(),
            template_ref: None,
            binary: None,
        })
        .expect("spawn_child");
    assert_eq!(id, AgentId("foo".to_string()));
    let foo = tree.get_node(&AgentId("foo".to_string())).unwrap();
    assert!(foo.workspace_path.is_dir());
    assert!(foo.workspace_path.join(".agent").is_dir());
}

#[test]
fn ti02_tree_indices_after_spawn() {
    let (_tmp, tree, spawner) = setup();
    spawner
        .spawn_child(SpawnChildConfig {
            parent_id: AgentId("root".to_string()),
            child_id: AgentId("foo".to_string()),
            child_workspace_path: PathBuf::from("agents/foo"),
            capabilities: Vec::new(),
            template_ref: None,
            binary: None,
        })
        .unwrap();
    assert_eq!(tree.children_of("root"), vec!["foo".to_string()]);
    assert_eq!(tree.parent_of("foo"), Some("root".to_string()));
    assert_eq!(tree.revision(), 2); // insert_root + insert_child
}

#[test]
fn ti03_agent_skeleton_files_readable() {
    let (_tmp, tree, spawner) = setup();
    spawner
        .spawn_child(SpawnChildConfig {
            parent_id: AgentId("root".to_string()),
            child_id: AgentId("foo".to_string()),
            child_workspace_path: PathBuf::from("agents/foo"),
            capabilities: Vec::new(),
            template_ref: None,
            binary: None,
        })
        .unwrap();
    let foo = tree.get_node(&AgentId("foo".to_string())).unwrap();
    let agent = foo.workspace_path.join(".agent");
    let cfg = std::fs::read_to_string(agent.join("config.yaml")).unwrap();
    assert!(cfg.contains("kind:"));
    let md = std::fs::read_to_string(agent.join("AGENTS.md")).unwrap();
    assert!(md.contains("Self-Improvement"));
    assert!(agent.join("skills").is_dir());
    let know = std::fs::metadata(agent.join("memory/knowledge.jsonl")).unwrap();
    assert_eq!(know.len(), 0);
}

#[test]
fn ti04_parent_not_in_tree_rejected() {
    let (_tmp, _tree, spawner) = setup();
    let err = spawner
        .spawn_child(SpawnChildConfig {
            parent_id: AgentId("missing".to_string()),
            child_id: AgentId("foo".to_string()),
            child_workspace_path: PathBuf::from("agents/foo"),
            capabilities: Vec::new(),
            template_ref: None,
            binary: None,
        })
        .unwrap_err();
    assert!(matches!(err, SpawnError::ParentNotFound(_)));
}

#[test]
fn ti05_traversal_rejected_no_fs_effect() {
    let (_tmp, _tree, spawner) = setup();
    let err = spawner
        .spawn_child(SpawnChildConfig {
            parent_id: AgentId("root".to_string()),
            child_id: AgentId("foo".to_string()),
            child_workspace_path: PathBuf::from("../escape"),
            capabilities: Vec::new(),
            template_ref: None,
            binary: None,
        })
        .unwrap_err();
    assert!(matches!(err, SpawnError::PathTraversal(_)));
}

#[test]
fn ti06_duplicate_child_id_rejected() {
    let (_tmp, _tree, spawner) = setup();
    spawner
        .spawn_child(SpawnChildConfig {
            parent_id: AgentId("root".to_string()),
            child_id: AgentId("foo".to_string()),
            child_workspace_path: PathBuf::from("agents/foo"),
            capabilities: Vec::new(),
            template_ref: None,
            binary: None,
        })
        .unwrap();
    let err = spawner
        .spawn_child(SpawnChildConfig {
            parent_id: AgentId("root".to_string()),
            child_id: AgentId("foo".to_string()),
            child_workspace_path: PathBuf::from("agents/foo2"),
            capabilities: Vec::new(),
            template_ref: None,
            binary: None,
        })
        .unwrap_err();
    assert!(matches!(err, SpawnError::AlreadyExists(_)));
}

#[test]
fn ti07_absolute_child_path_rejected() {
    let (_tmp, _tree, spawner) = setup();
    let err = spawner
        .spawn_child(SpawnChildConfig {
            parent_id: AgentId("root".to_string()),
            child_id: AgentId("foo".to_string()),
            child_workspace_path: PathBuf::from("/etc/passwd"),
            capabilities: Vec::new(),
            template_ref: None,
            binary: None,
        })
        .unwrap_err();
    assert!(matches!(err, SpawnError::PathTraversal(_)));
}

#[test]
fn ti08_subset_gate_violation_blocks_spawn() {
    let tmp = TempDir::new().unwrap();
    let tree = AgentTreeStore::new(tmp.path().to_path_buf()).unwrap();
    let root_ws = tree.workspace_root().join("root_ws");
    std::fs::create_dir_all(&root_ws).unwrap();
    let root_node = AgentNode {
        id: AgentId("root".to_string()),
        kind: AgentKind::Root,
        parent: None,
        workspace_path: root_ws,
        capabilities: Vec::new(),
        template_ref: None,
        status: AgentStatus::Active,
    };
    tree.insert_root(root_node).unwrap();
    let spawner = DefaultSpawner::new(tree.clone(), Arc::new(AlwaysFailGate));
    let err = spawner
        .spawn_child(SpawnChildConfig {
            parent_id: AgentId("root".to_string()),
            child_id: AgentId("foo".to_string()),
            child_workspace_path: PathBuf::from("agents/foo"),
            capabilities: Vec::new(),
            template_ref: None,
            binary: None,
        })
        .unwrap_err();
    assert!(matches!(err, SpawnError::SubsetViolation(_)));
    // No materialization: tree.workspace_root()/root_ws/agents/foo does not exist.
    assert!(!tree.workspace_root().join("root_ws/agents/foo").exists());
}

#[test]
fn ti08b_workspace_root_with_dotdot_canonicalizes() {
    let tmp = TempDir::new().unwrap();
    // Create tmp/x on disk so canonicalize(tmp/x/../x) resolves to tmp/x.
    let real = tmp.path().join("x");
    std::fs::create_dir_all(&real).unwrap();
    let weird = tmp.path().join("x").join("..").join("x");
    let tree = AgentTreeStore::new(weird).expect("AgentTreeStore::new with .. path");
    // workspace_root should canonicalize to real (= tmp/x → canonicalize).
    let canonical_real = real.canonicalize().unwrap();
    assert_eq!(tree.workspace_root(), canonical_real.as_path());
}

#[cfg(unix)]
#[test]
fn ti08c_workspace_root_symlink_resolves() {
    use std::os::unix::fs::symlink;
    let tmp = TempDir::new().unwrap();
    let real = tmp.path().join("real_root");
    std::fs::create_dir_all(&real).unwrap();
    let link = tmp.path().join("link_root");
    symlink(&real, &link).unwrap();
    let tree = AgentTreeStore::new(link).expect("AgentTreeStore::new with symlink");
    let canonical_real = real.canonicalize().unwrap();
    assert_eq!(tree.workspace_root(), canonical_real.as_path());
}

#[test]
fn ti08d_insert_child_with_mismatched_parent_rejected() {
    let (_tmp, tree, _spawner) = setup();
    let inner = tree.workspace_root().join("root_ws").join("a");
    std::fs::create_dir_all(&inner).unwrap();
    // Caller passes node with wrong parent.
    let node = AgentNode {
        id: AgentId("foo".to_string()),
        kind: AgentKind::Child,
        parent: Some(AgentId("wrong-parent".to_string())),
        workspace_path: inner,
        capabilities: Vec::new(),
        template_ref: None,
        status: AgentStatus::Active,
    };
    let err = tree
        .insert_child(&AgentId("root".to_string()), node)
        .unwrap_err();
    assert!(matches!(err, SpawnError::InvalidConfig(_)));
}

#[test]
fn ti08f_spawn_child_rejects_dot_sub_component() {
    let (_tmp, _tree, spawner) = setup();
    let err = spawner
        .spawn_child(SpawnChildConfig {
            parent_id: AgentId("root".to_string()),
            child_id: AgentId("imposter".to_string()),
            child_workspace_path: PathBuf::from(".sub/imposter"),
            capabilities: Vec::new(),
            template_ref: None,
            binary: None,
        })
        .unwrap_err();
    assert!(matches!(err, SpawnError::PathTraversal(_)));
}

#[test]
fn ti08h_spawn_child_rejects_dot_agent_component() {
    let (_tmp, _tree, spawner) = setup();
    for (idx, variant) in [".agent/x", ".AGENT/x", ".Agent/x"].iter().enumerate() {
        let err = spawner
            .spawn_child(SpawnChildConfig {
                parent_id: AgentId("root".to_string()),
                child_id: AgentId(format!("im-{idx}")),
                child_workspace_path: PathBuf::from(variant),
                capabilities: Vec::new(),
                template_ref: None,
                binary: None,
            })
            .unwrap_err();
        assert!(
            matches!(err, SpawnError::PathTraversal(_)),
            "variant {variant} not rejected ({err:?})"
        );
    }
}

#[test]
fn ti08g_spawn_child_dot_sub_case_insensitive() {
    let (_tmp, _tree, spawner) = setup();
    for (idx, variant) in [".SUB/x", ".Sub/x", ".sUb/x"].iter().enumerate() {
        let err = spawner
            .spawn_child(SpawnChildConfig {
                parent_id: AgentId("root".to_string()),
                child_id: AgentId(format!("imp-{idx}")),
                child_workspace_path: PathBuf::from(variant),
                capabilities: Vec::new(),
                template_ref: None,
                binary: None,
            })
            .unwrap_err();
        assert!(
            matches!(err, SpawnError::PathTraversal(_)),
            "variant {variant} not rejected (got {err:?})"
        );
    }
}

#[test]
fn ti08e_macos_tempfile_prefix_mismatch_regression() {
    // workspace_root = tempfile::TempDir's raw path (on macOS this is /var/...
    // symlinked to /private/var/...). insert_root pre-creates root_ws on disk.
    // spawn_child must succeed because AgentTreeStore canonicalizes both ends.
    let (_tmp, _tree, spawner) = setup();
    let id = spawner
        .spawn_child(SpawnChildConfig {
            parent_id: AgentId("root".to_string()),
            child_id: AgentId("foo".to_string()),
            child_workspace_path: PathBuf::from("agents/foo"),
            capabilities: Vec::new(),
            template_ref: None,
            binary: None,
        })
        .expect("spawn_child on macOS tempfile");
    assert_eq!(id, AgentId("foo".to_string()));
}

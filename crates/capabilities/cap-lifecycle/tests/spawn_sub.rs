//! Integration tests for spawn_sub (functional; AC-03 verification deferred to Slice C).

use std::sync::Arc;

use advance_shared_types::agent_tree::{
    AgentId, AgentKind, AgentNode, AgentStatus, AgentTreeReader, Capability,
};
use cap_lifecycle::{
    AgentTreeStore, DefaultSpawner, SpawnError, SpawnSubConfig, Spawner, SpawnerSubsetGate,
};
use tempfile::TempDir;

struct AlwaysOkGate;
impl SpawnerSubsetGate for AlwaysOkGate {
    fn check(&self, _p: &[Capability], _c: &[Capability]) -> Result<(), SpawnError> {
        Ok(())
    }
}

fn setup() -> (TempDir, AgentTreeStore, DefaultSpawner) {
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
    let spawner = DefaultSpawner::new(tree.clone(), Arc::new(AlwaysOkGate));
    (tmp, tree, spawner)
}

#[test]
fn ti09_happy_path_creates_sub() {
    let (_tmp, tree, spawner) = setup();
    let sub_id = spawner
        .spawn_sub(SpawnSubConfig {
            parent_id: AgentId("root".to_string()),
            capabilities: Vec::new(),
            template_ref: None,
        })
        .unwrap();
    let node = tree.get_node(&sub_id).unwrap();
    assert_eq!(node.kind, AgentKind::Sub);
    // sub workspace under root_ws/.sub/{uuid}
    assert!(node
        .workspace_path
        .starts_with(tree.workspace_root().join("root_ws/.sub")));
    assert!(node.workspace_path.join(".agent").is_dir());
}

#[test]
fn ti10_sub_node_distinguishable() {
    let (_tmp, tree, spawner) = setup();
    let sub_id = spawner
        .spawn_sub(SpawnSubConfig {
            parent_id: AgentId("root".to_string()),
            capabilities: Vec::new(),
            template_ref: None,
        })
        .unwrap();
    assert_eq!(tree.agent_kind(&sub_id.0), Some(AgentKind::Sub));
}

#[test]
fn ti11_sub_no_memory_subtree() {
    let (_tmp, tree, spawner) = setup();
    let sub_id = spawner
        .spawn_sub(SpawnSubConfig {
            parent_id: AgentId("root".to_string()),
            capabilities: Vec::new(),
            template_ref: None,
        })
        .unwrap();
    let node = tree.get_node(&sub_id).unwrap();
    let agent = node.workspace_path.join(".agent");
    assert!(agent.join("config.yaml").is_file());
    assert!(agent.join("AGENTS.md").is_file());
    assert!(agent.join("skills").is_dir());
    assert!(!agent.join("memory").exists());
}

#[test]
fn ti12_unique_uuids() {
    let (_tmp, _tree, spawner) = setup();
    let a = spawner
        .spawn_sub(SpawnSubConfig {
            parent_id: AgentId("root".to_string()),
            capabilities: Vec::new(),
            template_ref: None,
        })
        .unwrap();
    let b = spawner
        .spawn_sub(SpawnSubConfig {
            parent_id: AgentId("root".to_string()),
            capabilities: Vec::new(),
            template_ref: None,
        })
        .unwrap();
    let c = spawner
        .spawn_sub(SpawnSubConfig {
            parent_id: AgentId("root".to_string()),
            capabilities: Vec::new(),
            template_ref: None,
        })
        .unwrap();
    assert_ne!(a, b);
    assert_ne!(b, c);
    assert_ne!(a, c);
}

#[test]
fn ti13_parent_not_in_tree_rejected() {
    let (_tmp, _tree, spawner) = setup();
    let err = spawner
        .spawn_sub(SpawnSubConfig {
            parent_id: AgentId("missing".to_string()),
            capabilities: Vec::new(),
            template_ref: None,
        })
        .unwrap_err();
    assert!(matches!(err, SpawnError::ParentNotFound(_)));
}

#[test]
fn ti13b_parent_workspace_outside_workspace_root_rejected_at_insert() {
    // AgentTreeStore::insert_root enforces workspace_root containment at the
    // tree level (R5 Codex Critical #1 fix). A test trying to insert a Root
    // with workspace_path outside workspace_root will fail at insert_root.
    let tmp_root = TempDir::new().unwrap();
    let tree = AgentTreeStore::new(tmp_root.path().to_path_buf()).unwrap();
    // Create a directory OUTSIDE workspace_root on disk.
    let outer = TempDir::new().unwrap();
    let rogue = outer.path().join("rogue_root");
    std::fs::create_dir_all(&rogue).unwrap();
    let rogue_node = AgentNode {
        id: AgentId("rogue".to_string()),
        kind: AgentKind::Root,
        parent: None,
        workspace_path: rogue,
        capabilities: Vec::new(),
        template_ref: None,
        status: AgentStatus::Active,
    };
    let err = tree.insert_root(rogue_node).unwrap_err();
    assert!(matches!(err, SpawnError::InvalidConfig(_)));
}

#[test]
fn ti14_remove_sub_clears_tree() {
    let (_tmp, tree, spawner) = setup();
    let sub_id = spawner
        .spawn_sub(SpawnSubConfig {
            parent_id: AgentId("root".to_string()),
            capabilities: Vec::new(),
            template_ref: None,
        })
        .unwrap();
    assert!(tree.contains(&sub_id));
    let removed = tree.remove(&sub_id).unwrap();
    assert_eq!(removed.kind, AgentKind::Sub);
    assert!(!tree.contains(&sub_id));
    assert_eq!(tree.children_of("root"), Vec::<String>::new());
}

#[test]
fn tu37b_spawn_sub_with_sub_parent_rejected() {
    let (_tmp, tree, spawner) = setup();
    // Create a Sub agent first.
    let sub_a = spawner
        .spawn_sub(SpawnSubConfig {
            parent_id: AgentId("root".to_string()),
            capabilities: Vec::new(),
            template_ref: None,
        })
        .unwrap();
    // Try to spawn another Sub with sub_a as parent → rejected.
    assert_eq!(tree.agent_kind(&sub_a.0), Some(AgentKind::Sub));
    let err = spawner
        .spawn_sub(SpawnSubConfig {
            parent_id: sub_a,
            capabilities: Vec::new(),
            template_ref: None,
        })
        .unwrap_err();
    assert!(matches!(err, SpawnError::InvalidConfig(_)));
}

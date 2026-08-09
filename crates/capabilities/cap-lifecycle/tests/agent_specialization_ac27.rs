//! MODULE-005-AC-27 — agent specialization (tree-identity facet) witness.
//!
//! Wave-18 Lane 1. The AC-27 criterion: "spawning yields a node with identity
//! + state slot + capability set". This witness binds, on a REAL spawned node,
//! the facets that live in cap-lifecycle's purview:
//!   (i)   identity        — a stable `agent_id`, distinct from the spawner's;
//!   (ii)  parent linkage  — `AgentNode.parent == spawner` + the tree edge;
//!   (iii) capability set  — the granted caps are value-bound onto the node
//!                           (`spawn.rs` copies `cfg.capabilities`);
//!   (iv)  state slot       — the per-agent state-skeleton (`.agent/memory/`)
//!                           is provisioned by `init-child-workspace`.
//!
//! The cross-module facets are delegated per the §1.5 criterion's own pattern
//! (which already delegates "Mailbox facet -> MODULE-006-AC-16; memory facet
//! -> MODULE-011-AC-39"):
//!   * mailbox isolation          -> MODULE-006-AC-16  (passed)
//!   * persistent per-agent memory -> MODULE-011-AC-39 (passed)
//!   * opaque actor-state round-trip across turns (`new_state`)
//!                                 -> SYS-AC-263/264 via SYS-J-64 (passed)
//! cap-lifecycle owns no opaque actor-state field on `AgentNode`, so the
//! round-trip BEHAVIOR is delegated (not re-witnessed here).

use std::path::PathBuf;
use std::sync::Arc;

use advance_shared_types::agent_tree::{
    AgentId, AgentKind, AgentNode, AgentStatus, AgentTreeReader, Capability,
};
use advance_shared_types::capability::{CapParams, CapabilityId};
use cap_lifecycle::{
    AgentTreeStore, DefaultSpawner, SpawnChildConfig, SpawnError, Spawner, SpawnerSubsetGate,
};
use serde_json::json;
use tempfile::TempDir;

/// Permissive subset gate — AC-27 witnesses specialization facets, NOT subset
/// enforcement (that is MODULE-005-AC-06 / `subset_enforcement.rs`).
struct AlwaysOkGate;
impl SpawnerSubsetGate for AlwaysOkGate {
    fn check(&self, _p: &[Capability], _c: &[Capability]) -> Result<(), SpawnError> {
        Ok(())
    }
}

fn cap(id: &str, params: serde_json::Value) -> Capability {
    Capability {
        id: CapabilityId::from(id),
        params: CapParams::new(params),
    }
}

fn setup() -> (TempDir, AgentTreeStore, DefaultSpawner) {
    let tmp = TempDir::new().unwrap();
    let tree = AgentTreeStore::new(tmp.path().to_path_buf()).expect("AgentTreeStore::new");
    let root_ws = tree.workspace_root().join("root_ws");
    std::fs::create_dir_all(&root_ws).unwrap();
    let root = AgentNode {
        id: AgentId("root".to_string()),
        kind: AgentKind::Root,
        parent: None,
        workspace_path: root_ws,
        capabilities: Vec::new(),
        template_ref: None,
        status: AgentStatus::Active,
    };
    tree.insert_root(root).expect("insert_root");
    let spawner = DefaultSpawner::new(tree.clone(), Arc::new(AlwaysOkGate));
    (tmp, tree, spawner)
}

#[test]
fn ac27_spawned_node_binds_identity_parent_caps_and_state_slot() {
    let (_tmp, tree, spawner) = setup();

    // A NON-EMPTY, distinctly-valued capability set so the binding assertion is
    // value-bound (anti-fake-green: an empty/default vec could trivially match).
    let granted = vec![
        cap("fs", json!({"read-paths": "/tmp/specialized"})),
        cap("tools", json!({"ids": ["search"]})),
    ];

    let parent_id = AgentId("root".to_string());
    let child_id = AgentId("specialized-child".to_string());

    let returned = spawner
        .spawn_child(SpawnChildConfig {
            parent_id: parent_id.clone(),
            child_id: child_id.clone(),
            child_workspace_path: PathBuf::from("agents/specialized-child"),
            capabilities: granted.clone(),
            template_ref: None,
            binary: None,
        })
        .expect("spawn_child");

    // (i) identity — stable agent_id, distinct from the spawner's.
    assert_eq!(returned, child_id, "spawn returns the child's stable id");
    assert_ne!(
        child_id, parent_id,
        "child identity is distinct from parent"
    );
    let node = tree
        .get_node(&child_id)
        .expect("spawned node is present in the tree");
    assert_eq!(node.id, child_id, "node carries its own stable agent_id");
    assert_eq!(
        node.kind,
        AgentKind::Child,
        "spawned node is an agent (Child)"
    );
    assert_eq!(node.status, AgentStatus::Active);

    // (ii) parent linkage — both the node field and the tree edge.
    assert_eq!(
        node.parent,
        Some(parent_id.clone()),
        "node.parent links to the spawner"
    );
    assert_eq!(
        tree.parent_of("specialized-child"),
        Some("root".to_string()),
        "tree edge: child -> parent"
    );
    assert!(
        tree.children_of("root")
            .contains(&"specialized-child".to_string()),
        "tree edge: parent -> child"
    );

    // (iii) capability set — value-bound onto the node (not empty, exact match).
    assert!(
        !node.capabilities.is_empty(),
        "specialized node carries caps"
    );
    assert_eq!(
        node.capabilities, granted,
        "the granted capability set is value-bound onto the spawned node"
    );

    // (iv) state slot — the per-agent state-skeleton (`.agent/memory/`) is
    // provisioned. The opaque actor-state ROUND-TRIP (new_state across turns)
    // is delegated to SYS-AC-263/264 (SYS-J-64, passed); cap-lifecycle owns no
    // actor-state field, so this asserts the state LOCATION is materialized.
    let agent_dir = node.workspace_path.join(".agent");
    assert!(agent_dir.is_dir(), ".agent control dir materialized");
    let knowledge = agent_dir.join("memory").join("knowledge.jsonl");
    assert!(
        knowledge.is_file(),
        "per-agent state-skeleton provisioned: {}",
        knowledge.display()
    );
    // A freshly-spawned agent starts empty (parity with MODULE-011-AC-39).
    assert_eq!(
        std::fs::metadata(&knowledge).unwrap().len(),
        0,
        "freshly-spawned agent state starts empty"
    );

    // Cross-module facets (mailbox -> M006-AC-16, memory -> M011-AC-39,
    // round-trip -> SYS-AC-263/264) are delegated, not re-witnessed here.
}

#[test]
fn ac27_two_spawned_nodes_have_distinct_identities_and_caps() {
    // Strengthen the identity facet: two siblings under the same parent get
    // distinct identities and independently-bound capability sets.
    let (_tmp, tree, spawner) = setup();

    let caps_a = vec![cap("fs", json!({"read-paths": "/tmp/a"}))];
    let caps_b = vec![cap("tools", json!({"ids": ["b-only"]}))];

    spawner
        .spawn_child(SpawnChildConfig {
            parent_id: AgentId("root".to_string()),
            child_id: AgentId("child-a".to_string()),
            child_workspace_path: PathBuf::from("agents/child-a"),
            capabilities: caps_a.clone(),
            template_ref: None,
            binary: None,
        })
        .unwrap();
    spawner
        .spawn_child(SpawnChildConfig {
            parent_id: AgentId("root".to_string()),
            child_id: AgentId("child-b".to_string()),
            child_workspace_path: PathBuf::from("agents/child-b"),
            capabilities: caps_b.clone(),
            template_ref: None,
            binary: None,
        })
        .unwrap();

    let a = tree.get_node(&AgentId("child-a".to_string())).unwrap();
    let b = tree.get_node(&AgentId("child-b".to_string())).unwrap();
    assert_ne!(a.id, b.id, "siblings have distinct identities");
    assert_eq!(a.capabilities, caps_a, "child-a caps value-bound");
    assert_eq!(b.capabilities, caps_b, "child-b caps value-bound");
    assert_ne!(
        a.capabilities, b.capabilities,
        "each node binds its OWN capability set (no cross-leak)"
    );
}

//! AC-04 / AC-05 — M005↔M002 boundary via real cap-fs integration
//! (REQ-005 / REQ-027 / REQ-245 M005-side).
//!
//! M005 provides the `AgentTreeSnapshot` data; MODULE-002's
//! `VirtualPathResolver` (cap-fs) owns the enforcement (M002 AC-15 / AC-14,
//! passed 2026-05-08). These tests exercise the boundary end-to-end.

use std::sync::Arc;

use advance_shared_types::agent_tree::{
    AgentId, AgentKind, AgentNode, AgentStatus, AgentTreeSnapshot,
};
use cap_fs::resolver::{DefaultVirtualPathResolver, VirtualPathResolver};
use cap_lifecycle::AgentTreeStore;
use tempfile::TempDir;

fn setup() -> (TempDir, Arc<AgentTreeStore>) {
    let tmp = TempDir::new().unwrap();
    let tree = Arc::new(AgentTreeStore::new(tmp.path().to_path_buf()).unwrap());
    let root_ws = tree.workspace_root().join("root");
    std::fs::create_dir_all(&root_ws).unwrap();
    tree.insert_root(AgentNode {
        id: AgentId("root".into()),
        kind: AgentKind::Root,
        parent: None,
        workspace_path: root_ws.clone(),
        capabilities: Vec::new(),
        template_ref: None,
        status: AgentStatus::Active,
    })
    .unwrap();
    // Child territory is a subdir of root's territory.
    let child_ws = root_ws.join("child");
    std::fs::create_dir_all(&child_ws).unwrap();
    std::fs::write(child_ws.join("memo.txt"), b"child data").unwrap();
    tree.insert_child(
        &AgentId("root".into()),
        AgentNode {
            id: AgentId("child".into()),
            kind: AgentKind::Child,
            parent: Some(AgentId("root".into())),
            workspace_path: child_ws,
            capabilities: Vec::new(),
            template_ref: None,
            status: AgentStatus::Active,
        },
    )
    .unwrap();
    (tmp, tree)
}

fn resolver(tree: Arc<AgentTreeStore>) -> DefaultVirtualPathResolver {
    let root = tree.workspace_root().to_path_buf();
    DefaultVirtualPathResolver::new(root, tree as Arc<dyn AgentTreeSnapshot>)
}

#[test]
fn ac04_parent_cannot_write_child_workspace() {
    let (_t, tree) = setup();
    let r = resolver(tree);
    // Root tries to write into the child's territory → M002 Rule 2 →
    // permission-denied (M002 AC-15 enforcement; M005-provided tree data).
    let res = r.resolve_write("root", "child/memo.txt");
    assert!(
        res.is_err(),
        "parent writing child territory must be rejected: {res:?}"
    );
}

#[test]
fn ac05_parent_can_read_child_workspace() {
    let (_t, tree) = setup();
    let r = resolver(tree);
    // Parent reads its direct child's territory read-only (M002 AC-14;
    // M005-provided parent_of/children_of data).
    let res = r.resolve_child_read("root", "child", "memo.txt");
    assert!(res.is_ok(), "parent read-child must succeed: {res:?}");
}

#[test]
fn ac05_non_parent_read_child_rejected() {
    let (_t, tree) = setup();
    let r = resolver(tree);
    // A non-parent (the child itself) reading via read-child for a
    // non-existent topology → rejected (anti-fingerprinting NotFound).
    let res = r.resolve_child_read("child", "root", "anything");
    assert!(res.is_err(), "non-parent read-child must be rejected");
}

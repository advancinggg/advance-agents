//! AC-01 facet — init-child-workspace real file materialization (REQ-179).
//!
//! Parent-permission is enforced: only the direct parent may materialize
//! files into a child's territory (matches the discipline of every other
//! `child-*` operation; closes the cross-agent privilege-escalation vector
//! flagged by the adversarial evaluator).

use advance_shared_types::agent_tree::{AgentId, AgentKind, AgentNode, AgentStatus};
use cap_lifecycle::{
    init_child_workspace_files, AgentTreeStore, LifecycleError, MAX_INIT_FILE_BYTES,
};
use tempfile::TempDir;

/// Three-agent topology: `root` (parent of `child`), `child` (parent of
/// `gc`), and `peer` (a sibling Child under `root`, NOT a parent of `child`
/// — used to drive the cross-agent privilege-escalation rejection test).
fn setup() -> (TempDir, AgentTreeStore) {
    let tmp = TempDir::new().unwrap();
    let tree = AgentTreeStore::new(tmp.path().to_path_buf()).unwrap();
    let rws = tree.workspace_root().join("root");
    std::fs::create_dir_all(&rws).unwrap();
    tree.insert_root(AgentNode {
        id: AgentId("root".into()),
        kind: AgentKind::Root,
        parent: None,
        workspace_path: rws,
        capabilities: Vec::new(),
        template_ref: None,
        status: AgentStatus::Active,
    })
    .unwrap();
    let cws = tree.workspace_root().join("root/child");
    std::fs::create_dir_all(&cws).unwrap();
    tree.insert_child(
        &AgentId("root".into()),
        AgentNode {
            id: AgentId("child".into()),
            kind: AgentKind::Child,
            parent: Some(AgentId("root".into())),
            workspace_path: cws,
            capabilities: Vec::new(),
            template_ref: None,
            status: AgentStatus::Active,
        },
    )
    .unwrap();
    let pws = tree.workspace_root().join("root/peer");
    std::fs::create_dir_all(&pws).unwrap();
    tree.insert_child(
        &AgentId("root".into()),
        AgentNode {
            id: AgentId("peer".into()),
            kind: AgentKind::Child,
            parent: Some(AgentId("root".into())),
            workspace_path: pws,
            capabilities: Vec::new(),
            template_ref: None,
            status: AgentStatus::Active,
        },
    )
    .unwrap();
    (tmp, tree)
}

#[test]
fn happy_parent_writes_files_under_child_workspace() {
    let (_t, tree) = setup();
    init_child_workspace_files(
        &tree,
        "root",
        "child",
        &[
            ("notes/a.txt".into(), b"alpha".to_vec()),
            ("b.txt".into(), b"beta".to_vec()),
        ],
    )
    .unwrap();
    let cws = tree
        .get_node(&AgentId("child".into()))
        .unwrap()
        .workspace_path;
    assert_eq!(std::fs::read(cws.join("notes/a.txt")).unwrap(), b"alpha");
    assert_eq!(std::fs::read(cws.join("b.txt")).unwrap(), b"beta");
}

#[test]
fn non_parent_caller_permission_denied() {
    // Adversarial finding: a peer agent (not the parent) must NOT be able
    // to materialize files into another agent's workspace. Closes the
    // cross-agent privilege-escalation vector (PRD §1.2
    // parent-write-child-blocked enforced at the WIT side channel).
    let (_t, tree) = setup();
    let e = init_child_workspace_files(
        &tree,
        "peer",
        "child",
        &[("AGENTS.md".into(), b"malicious".to_vec())],
    )
    .unwrap_err();
    assert!(
        matches!(e, LifecycleError::PermissionDenied(_)),
        "non-parent must be denied, got {e:?}"
    );
    // Confirm NO write side-effect on the victim's workspace.
    let cws = tree
        .get_node(&AgentId("child".into()))
        .unwrap()
        .workspace_path;
    assert!(!cws.join("AGENTS.md").exists(), "no file should land");
}

#[test]
fn grandparent_is_not_parent_rejected() {
    // Root is the GRANDPARENT of `gc` (via `child`), not the direct parent.
    // The parent-only check must reject the grandparent too.
    let (_t, tree) = setup();
    let gws = tree.workspace_root().join("root/child/gc");
    std::fs::create_dir_all(&gws).unwrap();
    tree.insert_child(
        &AgentId("child".into()),
        AgentNode {
            id: AgentId("gc".into()),
            kind: AgentKind::Child,
            parent: Some(AgentId("child".into())),
            workspace_path: gws,
            capabilities: Vec::new(),
            template_ref: None,
            status: AgentStatus::Active,
        },
    )
    .unwrap();
    let e = init_child_workspace_files(
        &tree,
        "root", // grandparent, not parent
        "gc",
        &[("x.txt".into(), b"x".to_vec())],
    )
    .unwrap_err();
    assert!(matches!(e, LifecycleError::PermissionDenied(_)));
}

#[test]
fn missing_child_not_found() {
    let (_t, tree) = setup();
    let e = init_child_workspace_files(&tree, "root", "ghost", &[]).unwrap_err();
    assert!(matches!(e, LifecycleError::NotFound(_)));
}

#[test]
fn per_file_cap_rejected() {
    let (_t, tree) = setup();
    let big = vec![0u8; MAX_INIT_FILE_BYTES + 1];
    let e =
        init_child_workspace_files(&tree, "root", "child", &[("big.bin".into(), big)]).unwrap_err();
    assert!(matches!(e, LifecycleError::InvalidTarget(_)));
}

#[test]
fn file_count_cap_rejected() {
    let (_t, tree) = setup();
    let files: Vec<_> = (0..300)
        .map(|i| (format!("f{i}.txt"), b"x".to_vec()))
        .collect();
    let e = init_child_workspace_files(&tree, "root", "child", &files).unwrap_err();
    assert!(matches!(e, LifecycleError::InvalidTarget(_)));
}

#[test]
fn aggregate_cap_rejected() {
    let (_t, tree) = setup();
    // 80 files × 60 KiB ≈ 4.7 MiB > 4 MiB aggregate.
    let chunk = vec![0u8; 60 * 1024];
    let files: Vec<_> = (0..80)
        .map(|i| (format!("f{i}.bin"), chunk.clone()))
        .collect();
    let e = init_child_workspace_files(&tree, "root", "child", &files).unwrap_err();
    assert!(matches!(e, LifecycleError::InvalidTarget(_)));
}

#[test]
fn path_traversal_rejected() {
    let (_t, tree) = setup();
    let e = init_child_workspace_files(
        &tree,
        "root",
        "child",
        &[("../escape.txt".into(), b"x".to_vec())],
    )
    .unwrap_err();
    assert!(matches!(e, LifecycleError::InvalidTarget(_)));
}

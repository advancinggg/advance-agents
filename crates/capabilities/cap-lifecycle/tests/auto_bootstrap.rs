//! Integration tests for Slice B auto-bootstrap:
//! AC-11 (idempotent), AC-12 (kind=sub rejected).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use advance_shared_types::agent_tree::{
    AgentId, AgentKind, AgentNode, AgentStatus, AgentTreeReader, Capability,
};
use cap_lifecycle::{
    apply_auto_bootstrap, parse_auto_bootstrap, AgentTreeStore, BootstrapEntry, BootstrapError,
    BootstrapEvent, BootstrapKind, BuiltinTemplateRegistry, DefaultSpawner, SpawnError,
    SpawnerSubsetGate,
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

fn setup() -> (TempDir, AgentTreeStore, DefaultSpawner, AgentId) {
    let tmp = TempDir::new().unwrap();
    let root = canon(tmp.path());
    let tree = AgentTreeStore::new(root.clone()).unwrap();
    let root_ws = root.join("root_ws");
    std::fs::create_dir_all(&root_ws).unwrap();
    let parent_id = AgentId("root".to_string());
    tree.insert_root(AgentNode {
        id: parent_id.clone(),
        kind: AgentKind::Root,
        parent: None,
        workspace_path: root_ws,
        capabilities: Vec::new(),
        template_ref: None,
        status: AgentStatus::Active,
    })
    .unwrap();
    let spawner = DefaultSpawner::with_template_resolver(
        tree.clone(),
        Arc::new(AlwaysOkGate),
        Arc::new(BuiltinTemplateRegistry::new()),
    );
    (tmp, tree, spawner, parent_id)
}

fn entry(template: &str, kind: BootstrapKind, target: &str, alias: &str) -> BootstrapEntry {
    let yaml = format!(
        "- template: {template}\n  kind: {}\n  target-path: {target}\n  alias: {alias}\n  ensure: present\n",
        match kind {
            BootstrapKind::Child => "child",
            BootstrapKind::Sub => "sub",
        }
    );
    parse_auto_bootstrap(&yaml).unwrap().pop().unwrap()
}

#[test]
fn ti_t11_apply_bootstrap_idempotent_no_op_second_run() {
    let (_tmp, tree, spawner, parent_id) = setup();
    let entries = vec![
        entry("explorer", BootstrapKind::Child, "agents/scout", "scout"),
        entry("planner", BootstrapKind::Child, "agents/plan", "plan"),
    ];
    let report1 = apply_auto_bootstrap(&entries, &parent_id, &spawner, &tree).unwrap();
    assert_eq!(report1.spawned.len(), 2);
    assert!(report1.skipped.is_empty());

    let report2 = apply_auto_bootstrap(&entries, &parent_id, &spawner, &tree).unwrap();
    assert!(
        report2.spawned.is_empty(),
        "second run must not spawn: {report2:?}"
    );
    assert_eq!(report2.skipped.len(), 2);
    assert!(report2.skipped.contains(&AgentId("scout".to_string())));
    assert!(report2.skipped.contains(&AgentId("plan".to_string())));
}

#[test]
fn ti_t11_apply_bootstrap_conflict_event_when_template_differs() {
    let (_tmp, tree, spawner, parent_id) = setup();
    let first = vec![entry("explorer", BootstrapKind::Child, "agents/foo", "foo")];
    apply_auto_bootstrap(&first, &parent_id, &spawner, &tree).unwrap();

    let second = vec![entry("planner", BootstrapKind::Child, "agents/foo", "foo")];
    let report = apply_auto_bootstrap(&second, &parent_id, &spawner, &tree).unwrap();
    assert!(report.spawned.is_empty());
    assert!(report.skipped.is_empty());
    assert_eq!(report.conflicts.len(), 1);
    match &report.conflicts[0] {
        BootstrapEvent::Conflict { alias, reason } => {
            assert_eq!(alias, &AgentId("foo".to_string()));
            assert!(reason.contains("template_ref mismatch"));
        }
    }
}

#[test]
fn ti_t11_apply_bootstrap_alias_path_mismatch_errors() {
    let (_tmp, tree, spawner, parent_id) = setup();
    let first = vec![entry("explorer", BootstrapKind::Child, "agents/a", "name")];
    apply_auto_bootstrap(&first, &parent_id, &spawner, &tree).unwrap();

    let second = vec![entry("explorer", BootstrapKind::Child, "agents/b", "name")];
    let err = apply_auto_bootstrap(&second, &parent_id, &spawner, &tree).unwrap_err();
    assert!(
        matches!(err, BootstrapError::AliasPathMismatch { .. }),
        "got {err:?}"
    );
}

#[test]
fn ti_t12_apply_bootstrap_rejects_kind_sub() {
    let (_tmp, tree, spawner, parent_id) = setup();
    let entries = vec![entry("explorer", BootstrapKind::Sub, "agents/sub", "sub")];
    let err = apply_auto_bootstrap(&entries, &parent_id, &spawner, &tree).unwrap_err();
    assert!(
        matches!(err, BootstrapError::SubKindRejected { .. }),
        "got {err:?}"
    );
}

#[test]
fn ti_apply_bootstrap_rejects_target_path_collision() {
    let (_tmp, tree, spawner, parent_id) = setup();
    let first = vec![entry("explorer", BootstrapKind::Child, "agents/x", "first")];
    apply_auto_bootstrap(&first, &parent_id, &spawner, &tree).unwrap();

    let second = vec![entry(
        "explorer",
        BootstrapKind::Child,
        "agents/x",
        "second",
    )];
    let err = apply_auto_bootstrap(&second, &parent_id, &spawner, &tree).unwrap_err();
    assert!(
        matches!(err, BootstrapError::TargetPathOccupied { .. }),
        "got {err:?}"
    );
}

#[test]
fn ti_apply_bootstrap_rejects_target_path_with_traversal() {
    let (_tmp, tree, spawner, parent_id) = setup();
    let yaml = "- template: explorer\n  kind: child\n  target-path: ../escape\n  alias: e\n  ensure: present\n";
    let entries = parse_auto_bootstrap(yaml).unwrap();
    let err = apply_auto_bootstrap(&entries, &parent_id, &spawner, &tree).unwrap_err();
    assert!(
        matches!(err, BootstrapError::InvalidTargetPath { .. }),
        "got {err:?}"
    );
}

#[test]
fn ti_apply_bootstrap_rejects_unknown_parent() {
    let (_tmp, tree, spawner, _root_id) = setup();
    let entries = vec![entry("explorer", BootstrapKind::Child, "agents/x", "x")];
    let err =
        apply_auto_bootstrap(&entries, &AgentId("ghost".to_string()), &spawner, &tree).unwrap_err();
    assert!(
        matches!(err, BootstrapError::ParentNotFound(_)),
        "got {err:?}"
    );
}

#[test]
fn ti_apply_bootstrap_spawned_children_are_in_tree() {
    let (_tmp, tree, spawner, parent_id) = setup();
    let entries = vec![entry(
        "explorer",
        BootstrapKind::Child,
        "agents/scout",
        "scout",
    )];
    apply_auto_bootstrap(&entries, &parent_id, &spawner, &tree).unwrap();
    let kids = tree.children_of("root");
    assert!(kids.contains(&"scout".to_string()));
}

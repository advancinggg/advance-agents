//! Integration tests for Slice B rollback-child (AC-24):
//! parent-child validation + delegation to WorkspaceRollbackGate.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use advance_shared_types::agent_tree::{
    AgentId, AgentKind, AgentNode, AgentStatus, AgentTreeReader, Capability,
};
use cap_lifecycle::{
    AgentTreeStore, DefaultRollbackController, DefaultSpawner, LifecycleError, RollbackController,
    RollbackModeSpec, RollbackTargetSpec, SpawnChildConfig, SpawnError, SpawnSubConfig, Spawner,
    SpawnerSubsetGate, WorkspaceRollbackGate,
};
use tempfile::TempDir;

struct AlwaysOkGate;
impl SpawnerSubsetGate for AlwaysOkGate {
    fn check(&self, _p: &[Capability], _c: &[Capability]) -> Result<(), SpawnError> {
        Ok(())
    }
}

#[derive(Debug, Clone)]
enum RecordedCall {
    Rollback {
        agent_id: String,
        target: RollbackTargetSpec,
        mode: RollbackModeSpec,
    },
    RollbackToCheckpoint {
        agent_id: String,
        label: String,
    },
}

#[derive(Default)]
struct RecorderGate {
    calls: Mutex<Vec<RecordedCall>>,
}

impl WorkspaceRollbackGate for RecorderGate {
    fn rollback(
        &self,
        agent_id: &str,
        target: RollbackTargetSpec,
        mode: RollbackModeSpec,
    ) -> Result<Vec<PathBuf>, LifecycleError> {
        self.calls.lock().unwrap().push(RecordedCall::Rollback {
            agent_id: agent_id.to_string(),
            target,
            mode,
        });
        Ok(vec![PathBuf::from("a.md")])
    }

    fn rollback_to_checkpoint(
        &self,
        agent_id: &str,
        label: &str,
    ) -> Result<Vec<PathBuf>, LifecycleError> {
        self.calls
            .lock()
            .unwrap()
            .push(RecordedCall::RollbackToCheckpoint {
                agent_id: agent_id.to_string(),
                label: label.to_string(),
            });
        Ok(vec![PathBuf::from("b.md")])
    }
}

struct FailGate;
impl WorkspaceRollbackGate for FailGate {
    fn rollback(
        &self,
        _agent_id: &str,
        _target: RollbackTargetSpec,
        _mode: RollbackModeSpec,
    ) -> Result<Vec<PathBuf>, LifecycleError> {
        Err(LifecycleError::IoFailure("simulated".to_string()))
    }

    fn rollback_to_checkpoint(
        &self,
        _agent_id: &str,
        _label: &str,
    ) -> Result<Vec<PathBuf>, LifecycleError> {
        Err(LifecycleError::IoFailure("simulated".to_string()))
    }
}

fn canon(p: &Path) -> PathBuf {
    p.canonicalize().expect("canonicalize")
}

/// Setup a tree with root → child("foo"), root → sub("sub"). Returns the tree
/// and the recorder gate. The DefaultSpawner is dropped after setup.
fn setup() -> (TempDir, AgentTreeStore, Arc<RecorderGate>) {
    let tmp = TempDir::new().unwrap();
    let root = canon(tmp.path());
    let tree = AgentTreeStore::new(root.clone()).unwrap();
    let root_ws = root.join("root_ws");
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
    spawner
        .spawn_sub(SpawnSubConfig {
            parent_id: AgentId("root".to_string()),
            capabilities: Vec::new(),
            template_ref: None,
        })
        .unwrap();
    let recorder = Arc::new(RecorderGate::default());
    (tmp, tree, recorder)
}

#[test]
fn ti_t28_rollback_child_happy_path_delegates_to_gate() {
    let (_tmp, tree, recorder) = setup();
    let controller = DefaultRollbackController::new(tree, recorder.clone());
    let commit = "0".repeat(40);
    let paths = controller
        .rollback_child(
            &AgentId("root".to_string()),
            &AgentId("foo".to_string()),
            commit.clone(),
        )
        .unwrap();
    assert_eq!(paths, vec![PathBuf::from("a.md")]);
    let calls = recorder.calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    match &calls[0] {
        RecordedCall::Rollback {
            agent_id,
            target,
            mode,
        } => {
            assert_eq!(agent_id, "foo");
            assert!(matches!(target, RollbackTargetSpec::Commit(c) if c == &commit));
            assert!(matches!(mode, RollbackModeSpec::FullDirectory));
        }
        other => panic!("wrong recorded call: {other:?}"),
    }
}

#[test]
fn ti_t28_rollback_child_accepts_uppercase_hex_normalizes_to_lower() {
    let (_tmp, tree, recorder) = setup();
    let controller = DefaultRollbackController::new(tree, recorder.clone());
    let upper = "A".repeat(40);
    controller
        .rollback_child(
            &AgentId("root".to_string()),
            &AgentId("foo".to_string()),
            upper,
        )
        .unwrap();
    let calls = recorder.calls.lock().unwrap();
    match &calls[0] {
        RecordedCall::Rollback { target, .. } => match target {
            RollbackTargetSpec::Commit(c) => assert_eq!(c, &"a".repeat(40)),
            _ => panic!("expected Commit variant"),
        },
        _ => panic!("wrong recorded call"),
    }
}

#[test]
fn ti_t28_rollback_child_rejects_non_parent() {
    let (_tmp, tree, recorder) = setup();
    let spawner = DefaultSpawner::new(tree.clone(), Arc::new(AlwaysOkGate));
    spawner
        .spawn_child(SpawnChildConfig {
            parent_id: AgentId("root".to_string()),
            child_id: AgentId("sibling".to_string()),
            child_workspace_path: PathBuf::from("agents/sibling"),
            capabilities: Vec::new(),
            template_ref: None,
            binary: None,
        })
        .unwrap();
    let controller = DefaultRollbackController::new(tree, recorder);
    let err = controller
        .rollback_child(
            &AgentId("sibling".to_string()),
            &AgentId("foo".to_string()),
            "0".repeat(40),
        )
        .unwrap_err();
    assert!(
        matches!(err, LifecycleError::PermissionDenied(_)),
        "got {err:?}"
    );
}

#[test]
fn ti_t28_rollback_child_rejects_unknown_child() {
    let (_tmp, tree, recorder) = setup();
    let controller = DefaultRollbackController::new(tree, recorder);
    let err = controller
        .rollback_child(
            &AgentId("root".to_string()),
            &AgentId("ghost".to_string()),
            "0".repeat(40),
        )
        .unwrap_err();
    assert!(matches!(err, LifecycleError::NotFound(_)), "got {err:?}");
}

#[test]
fn ti_t28_rollback_child_rejects_unknown_caller() {
    let (_tmp, tree, recorder) = setup();
    let controller = DefaultRollbackController::new(tree, recorder);
    let err = controller
        .rollback_child(
            &AgentId("ghost".to_string()),
            &AgentId("foo".to_string()),
            "0".repeat(40),
        )
        .unwrap_err();
    assert!(matches!(err, LifecycleError::NotFound(_)), "got {err:?}");
}

#[test]
fn ti_t28_rollback_child_rejects_sub_target() {
    let (_tmp, tree, recorder) = setup();
    let sub_id_str = tree
        .children_of("root")
        .into_iter()
        .find(|c| tree.get_node(&AgentId(c.clone())).unwrap().kind == AgentKind::Sub)
        .expect("sub must be present");
    let controller = DefaultRollbackController::new(tree, recorder);
    let err = controller
        .rollback_child(
            &AgentId("root".to_string()),
            &AgentId(sub_id_str),
            "0".repeat(40),
        )
        .unwrap_err();
    assert!(
        matches!(err, LifecycleError::PermissionDenied(_)),
        "got {err:?}"
    );
}

#[test]
fn ti_t28_rollback_child_rejects_invalid_commit_hash() {
    let (_tmp, tree, recorder) = setup();
    let controller = DefaultRollbackController::new(tree, recorder);
    let err = controller
        .rollback_child(
            &AgentId("root".to_string()),
            &AgentId("foo".to_string()),
            "not-hex".to_string(),
        )
        .unwrap_err();
    assert!(
        matches!(err, LifecycleError::InvalidTarget(_)),
        "got {err:?}"
    );
}

#[test]
fn ti_t28_rollback_child_propagates_gate_error() {
    let (_tmp, tree, _recorder) = setup();
    let controller = DefaultRollbackController::new(tree, Arc::new(FailGate));
    let err = controller
        .rollback_child(
            &AgentId("root".to_string()),
            &AgentId("foo".to_string()),
            "0".repeat(40),
        )
        .unwrap_err();
    assert!(
        matches!(err, LifecycleError::RollbackGate(_)),
        "got {err:?}"
    );
}

#[test]
fn ti_t28_rollback_child_to_checkpoint_delegates_to_gate() {
    let (_tmp, tree, recorder) = setup();
    let controller = DefaultRollbackController::new(tree, recorder.clone());
    controller
        .rollback_child_to_checkpoint(
            &AgentId("root".to_string()),
            &AgentId("foo".to_string()),
            "task-1".to_string(),
        )
        .unwrap();
    let calls = recorder.calls.lock().unwrap();
    match &calls[0] {
        RecordedCall::RollbackToCheckpoint { agent_id, label } => {
            assert_eq!(agent_id, "foo");
            assert_eq!(label, "task-1");
        }
        other => panic!("wrong recorded call: {other:?}"),
    }
}

#[test]
fn ti_t28_rollback_child_to_checkpoint_validates_label_traversal() {
    let (_tmp, tree, recorder) = setup();
    let controller = DefaultRollbackController::new(tree, recorder);
    let err = controller
        .rollback_child_to_checkpoint(
            &AgentId("root".to_string()),
            &AgentId("foo".to_string()),
            "foo/../bar".to_string(),
        )
        .unwrap_err();
    assert!(
        matches!(err, LifecycleError::InvalidTarget(_)),
        "got {err:?}"
    );
}

#[test]
fn ti_t28_rollback_child_to_checkpoint_accepts_git_ref_chars() {
    let (_tmp, tree, recorder) = setup();
    let controller = DefaultRollbackController::new(tree, recorder.clone());
    controller
        .rollback_child_to_checkpoint(
            &AgentId("root".to_string()),
            &AgentId("foo".to_string()),
            "auto:iter-3".to_string(),
        )
        .unwrap();
    let calls = recorder.calls.lock().unwrap();
    match &calls[0] {
        RecordedCall::RollbackToCheckpoint { label, .. } => {
            assert_eq!(label, "auto:iter-3");
        }
        _ => panic!("wrong recorded call"),
    }
}

#[test]
fn ti_t28_rollback_child_forwards_full_directory_mode_default() {
    let (_tmp, tree, recorder) = setup();
    let controller = DefaultRollbackController::new(tree, recorder.clone());
    controller
        .rollback_child(
            &AgentId("root".to_string()),
            &AgentId("foo".to_string()),
            "0".repeat(40),
        )
        .unwrap();
    let calls = recorder.calls.lock().unwrap();
    match &calls[0] {
        RecordedCall::Rollback { mode, .. } => {
            assert!(matches!(mode, RollbackModeSpec::FullDirectory));
        }
        _ => panic!("wrong recorded call"),
    }
}

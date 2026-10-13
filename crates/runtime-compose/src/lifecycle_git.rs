//! Production gates that bind CONTRACT-022 / CONTRACT-021 onto cap-lifecycle's
//! [`NamedCheckpointGate`] / [`WorkspaceRollbackGate`] so
//! [`cap_lifecycle::DefaultCheckpointController`] can run in compose (git-family PR-4).

use std::path::PathBuf;
use std::sync::Arc;

use advance_git::{
    DefaultNamedCheckpoint, DefaultWorkspaceRollback, NamedCheckpoint, RollbackMode,
    RollbackTarget, WorkspaceRollback,
};
use cap_lifecycle::{
    CheckpointEntry, LifecycleError, NamedCheckpointGate, RollbackModeSpec, RollbackTargetSpec,
    WorkspaceRollbackGate,
};

/// [`NamedCheckpointGate`] over [`DefaultNamedCheckpoint`].
pub struct NamedCheckpointAdapter {
    inner: DefaultNamedCheckpoint,
}

impl NamedCheckpointAdapter {
    pub fn new(inner: DefaultNamedCheckpoint) -> Self {
        Self { inner }
    }
}

impl NamedCheckpointGate for NamedCheckpointAdapter {
    fn create(
        &self,
        agent_id: &str,
        label: &str,
        paths: Option<Vec<PathBuf>>,
    ) -> Result<(), LifecycleError> {
        self.inner
            .create(agent_id, label, paths)
            .map_err(|e| LifecycleError::InvalidTarget(e.to_string()))
    }

    fn list(&self, agent_id: &str) -> Result<Vec<CheckpointEntry>, LifecycleError> {
        self.inner
            .list(agent_id)
            .map(|entries| {
                entries
                    .into_iter()
                    .map(|e| CheckpointEntry {
                        label: e.label,
                        agent: e.agent,
                        timestamp: e.timestamp,
                        paths: e.paths,
                        valid: e.valid,
                    })
                    .collect()
            })
            .map_err(|e| LifecycleError::InvalidTarget(e.to_string()))
    }
}

/// [`WorkspaceRollbackGate`] over [`DefaultWorkspaceRollback`].
///
/// The gate is sync; the git surface is async. Called from a tokio worker via
/// `block_in_place` so the inner `spawn_blocking` can run.
pub struct WorkspaceRollbackAdapter {
    inner: Arc<DefaultWorkspaceRollback>,
}

impl WorkspaceRollbackAdapter {
    pub fn new(inner: DefaultWorkspaceRollback) -> Self {
        Self {
            inner: Arc::new(inner),
        }
    }
}

fn map_target(target: RollbackTargetSpec) -> RollbackTarget {
    match target {
        RollbackTargetSpec::Commit(sha) => RollbackTarget::Commit(sha),
        RollbackTargetSpec::Checkpoint(label) => RollbackTarget::Checkpoint(label),
    }
}

fn map_mode(mode: RollbackModeSpec) -> RollbackMode {
    match mode {
        RollbackModeSpec::FullDirectory => RollbackMode::FullDirectory,
        RollbackModeSpec::PathScoped(paths) => RollbackMode::PathScoped(paths),
    }
}

fn map_rollback_err(e: advance_git::RollbackError) -> LifecycleError {
    match e {
        advance_git::RollbackError::NotFound { what } => LifecycleError::NotFound(what),
        advance_git::RollbackError::PermissionDenied { .. } => {
            LifecycleError::PermissionDenied("rollback denied".into())
        }
        other => LifecycleError::InvalidTarget(other.to_string()),
    }
}

impl WorkspaceRollbackGate for WorkspaceRollbackAdapter {
    fn rollback(
        &self,
        agent_id: &str,
        target: RollbackTargetSpec,
        mode: RollbackModeSpec,
    ) -> Result<Vec<PathBuf>, LifecycleError> {
        let inner = Arc::clone(&self.inner);
        let agent = agent_id.to_string();
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(inner.rollback(
                &agent,
                map_target(target),
                map_mode(mode),
            ))
        })
        .map_err(map_rollback_err)
    }

    fn rollback_to_checkpoint(
        &self,
        agent_id: &str,
        label: &str,
    ) -> Result<Vec<PathBuf>, LifecycleError> {
        let inner = Arc::clone(&self.inner);
        let agent = agent_id.to_string();
        let label = label.to_string();
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(inner.rollback_to_checkpoint(&agent, &label))
        })
        .map_err(map_rollback_err)
    }
}

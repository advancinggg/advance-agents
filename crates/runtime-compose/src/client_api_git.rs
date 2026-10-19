//! Production `GitHistoryProvider` over [`GitHistoryReaderProvider`] plus gated
//! operator checkpoint rollback (OSS-6).
//!
//! History reads stay on [`GitHistoryReaderProvider`]. Checkpoint rollback plans
//! outside MetaMaintainer L1, refuses over-budget restores (`10_000` paths /
//! `256 MiB` → `invalid_state ["too_many_entries"]`), then holds L1 across
//! `restore_tree` (sidecars ride the tree as `ChangeRole::Sidecar`).

use std::path::PathBuf;
use std::sync::Arc;

use advance_client_api::git::{
    ClientGitCheckpointEntry, ClientGitCheckpointList, ClientGitCommitPage,
    ClientGitCreateCheckpointRequest, ClientGitFileAt, ClientGitFileHistory,
    ClientGitRollbackResult, ClientGitStatus, GitHistoryReaderProvider, ValidatedGitCommitQuery,
};
use advance_client_api::session::Principal;
use advance_client_api::{GitHistoryProvider, ProviderError, TOO_MANY_ENTRIES_DETAIL};
use advance_git::{
    DefaultWorkspaceRollback, GitError, RestoreOutcome, RestorePlanSummary, RestoreScope,
    RestoreSource, RestoreTreeRequest, UserActor, UserCommitLane, UserOpRefusal, MAX_ADOPT_BYTES,
    MAX_USER_CHANGES,
};
use cap_fs::MetaMaintainer;

/// Tree-read planner used by operator rollback. Production uses
/// [`DefaultWorkspaceRollback::plan_restore`]; tests inject an over-budget summary
/// so L1 is never acquired.
pub trait RestorePlanner: Send + Sync {
    fn plan(&self, req: &RestoreTreeRequest) -> Result<RestorePlanSummary, GitError>;
}

/// True when the restore plan exceeds the OSS-6 operator cap (10 000 paths /
/// 256 MiB). Checked outside L1.
pub fn operator_rollback_over_cap(summary: &RestorePlanSummary) -> bool {
    summary.path_count > MAX_USER_CHANGES || summary.blob_bytes > MAX_ADOPT_BYTES
}

/// Production git-family adapter.
pub struct WiredGitHistoryProvider {
    inner: GitHistoryReaderProvider,
    workspace: PathBuf,
    meta: Option<Arc<MetaMaintainer>>,
    lane: Option<Arc<dyn UserCommitLane>>,
    planner: Option<Arc<dyn RestorePlanner>>,
}

impl WiredGitHistoryProvider {
    pub fn new(
        workspace: PathBuf,
        meta: Option<Arc<MetaMaintainer>>,
        lane: Option<Arc<dyn UserCommitLane>>,
    ) -> Self {
        Self {
            inner: GitHistoryReaderProvider::new(workspace.clone()),
            workspace,
            meta,
            lane,
            planner: None,
        }
    }

    /// Test seam: inject a restore plan so an over-budget summary does not
    /// require 10 000 files on disk.
    pub fn with_planner(mut self, planner: Arc<dyn RestorePlanner>) -> Self {
        self.planner = Some(planner);
        self
    }

    fn block_on<F>(fut: F) -> Result<F::Output, ProviderError>
    where
        F: std::future::Future + Send,
        F::Output: Send,
    {
        std::thread::scope(|s| {
            s.spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| {
                        ProviderError::Unavailable(format!(
                            "git rollback: failed to build the owned runtime: {e}"
                        ))
                    })?;
                Ok(runtime.block_on(fut))
            })
            .join()
            .map_err(|_| ProviderError::Unavailable("git rollback panicked".into()))?
        })
    }
}

impl GitHistoryProvider for WiredGitHistoryProvider {
    fn status(&self) -> Result<ClientGitStatus, ProviderError> {
        self.inner.status()
    }

    fn commits(
        &self,
        query: &ValidatedGitCommitQuery,
    ) -> Result<ClientGitCommitPage, ProviderError> {
        self.inner.commits(query)
    }

    fn checkpoints(
        &self,
        agent_id: Option<&str>,
    ) -> Result<ClientGitCheckpointList, ProviderError> {
        self.inner.checkpoints(agent_id)
    }

    fn file_history(&self, path: &str) -> Result<ClientGitFileHistory, ProviderError> {
        self.inner.file_history(path)
    }

    fn file_at(&self, path: &str, sha: &str) -> Result<ClientGitFileAt, ProviderError> {
        self.inner.file_at(path, sha)
    }

    fn create_checkpoint(
        &self,
        request: &ClientGitCreateCheckpointRequest,
    ) -> Result<ClientGitCheckpointEntry, ProviderError> {
        self.inner.create_checkpoint(request)
    }

    fn rollback_to_checkpoint(
        &self,
        agent_id: &str,
        label: &str,
        principal: &Principal,
    ) -> Result<ClientGitRollbackResult, ProviderError> {
        let req = RestoreTreeRequest {
            actor: UserActor::from_principal_id(&principal.id),
            source: RestoreSource::Checkpoint {
                agent_id: agent_id.to_string(),
                label: label.to_string(),
            },
            scope: RestoreScope::CheckpointDomain,
            correlation_id: None,
            provenance: None,
        };
        let planner = self.planner.clone();
        let workspace = self.workspace.clone();
        let meta = self.meta.clone();
        let lane = self.lane.clone();
        let outcome =
            Self::block_on(
                async move { rollback_gated(planner, workspace, meta, lane, req).await },
            )??;
        Ok(ClientGitRollbackResult {
            agent_id: agent_id.to_string(),
            label: label.to_string(),
            restored_path_count: outcome.restored_count,
            commit_sha: outcome.sha,
        })
    }
}

async fn rollback_gated(
    planner: Option<Arc<dyn RestorePlanner>>,
    workspace: PathBuf,
    meta: Option<Arc<MetaMaintainer>>,
    lane: Option<Arc<dyn UserCommitLane>>,
    req: RestoreTreeRequest,
) -> Result<RestoreOutcome, ProviderError> {
    let summary = match planner {
        Some(planner) => planner.plan(&req).map_err(map_git_err)?,
        None => DefaultWorkspaceRollback::new(workspace.clone())
            .map_err(|e| ProviderError::Unavailable(e.to_string()))?
            .plan_restore(&req)
            .map_err(map_git_err)?,
    };
    if operator_rollback_over_cap(&summary) {
        return Err(ProviderError::InvalidState(TOO_MANY_ENTRIES_DETAIL.into()));
    }
    let _guard = match meta.as_ref() {
        Some(maintainer) => Some(maintainer.acquire().await),
        None => None,
    };
    if let Some(lane) = lane {
        return lane
            .restore_tree(req)
            .await
            .map_err(|_| ProviderError::Unavailable("git worker".into()))?
            .map_err(map_git_err);
    }
    DefaultWorkspaceRollback::new(workspace)
        .map_err(|e| ProviderError::Unavailable(e.to_string()))?
        .restore_committed(req, None)
        .await
        .map_err(map_git_err)
}

fn map_git_err(err: GitError) -> ProviderError {
    match err {
        GitError::InvalidUserOp {
            reason: UserOpRefusal::UnknownRestoreSource,
            ..
        } => ProviderError::NotFound("checkpoint".into()),
        GitError::InvalidUserOp {
            reason: UserOpRefusal::ReservedNamespace,
            ..
        } => ProviderError::InvalidRequest("checkpoint".into()),
        GitError::InvalidUserOp {
            reason: UserOpRefusal::PrivatePath,
            ..
        } => ProviderError::NotFound("path".into()),
        GitError::InvalidUserOp {
            reason:
                UserOpRefusal::TreeTooLarge
                | UserOpRefusal::TooManyChanges
                | UserOpRefusal::TooManyBytes,
            ..
        } => ProviderError::InvalidState(TOO_MANY_ENTRIES_DETAIL.into()),
        GitError::NotSingleBranch { .. } => ProviderError::InvalidState("not_main".into()),
        GitError::WorkerClosed => ProviderError::Unavailable("git worker".into()),
        other => ProviderError::Unavailable(other.to_string()),
    }
}

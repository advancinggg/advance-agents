//! Scheduler-layer per-iteration rollback orchestration (AC-11).
//!
//! Wraps MODULE-003's CONTRACT-021 [`WorkspaceRollback`] in `FullDirectory`
//! mode targeting the iteration's checkpoint tag. The `.agent/**` exclusion
//! (PRD §7.2) is enforced inside MODULE-003's `FullDirectory` expansion —
//! slice A delegates and verifies it (see `tests/checkpoint_rollback.rs`).
//!
//! **AC-11 slice-A scope**: the rollback MECHANISM (workspace restore from a
//! checkpoint tree, `.agent/` exclusion, error on missing checkpoint) is
//! verified here. The discard/crash/guardrail-fail TRIGGERS that decide
//! *when* to roll back are the iteration-close protocol (§4.7.7) — the
//! deferred real loop (AC-12). `rollback_iteration` is the operation that
//! loop will invoke.

use std::sync::Arc;

use advance_git::{RollbackMode, RollbackTarget, WorkspaceRollback};
use async_trait::async_trait;

use crate::checkpoint::iteration_label;
use crate::error::AutoLoopError;

/// Scheduler-layer rollback surface used by the AutoLoopDriver.
#[async_trait]
pub trait IterationRollback: Send + Sync {
    /// Roll the workspace back to iteration `n`'s checkpoint
    /// (full-directory; `.agent/**` excluded by MODULE-003).
    async fn rollback_iteration(&self, agent_id: &str, n: u32) -> Result<(), AutoLoopError>;
}

/// Default impl delegating to a CONTRACT-021 [`WorkspaceRollback`]. The
/// underlying `rollback` is already async (MODULE-003 wraps its sync
/// libgit2 work in `spawn_blocking` internally) — no extra wrapper needed.
pub struct DefaultIterationRollback {
    inner: Arc<dyn WorkspaceRollback>,
}

impl DefaultIterationRollback {
    pub fn new(inner: Arc<dyn WorkspaceRollback>) -> Self {
        Self { inner }
    }
}

#[async_trait]
impl IterationRollback for DefaultIterationRollback {
    async fn rollback_iteration(&self, agent_id: &str, n: u32) -> Result<(), AutoLoopError> {
        // Discard the affected-paths Vec — the iteration-rollback surface
        // only needs success/failure. `.agent/` exclusion is MODULE-003's
        // FullDirectory responsibility (PRD §7.2).
        self.inner
            .rollback(
                agent_id,
                RollbackTarget::Checkpoint(iteration_label(n)),
                RollbackMode::FullDirectory,
            )
            .await
            .map(|_paths| ())
            .map_err(AutoLoopError::from)
    }
}

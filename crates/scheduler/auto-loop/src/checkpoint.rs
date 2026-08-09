//! Scheduler-layer per-iteration checkpoint orchestration (AC-10).
//!
//! Wraps MODULE-003's CONTRACT-022 [`NamedCheckpoint`] with the auto-loop
//! label convention. Per PRD §4.7.7 the AutoLoopDriver creates checkpoints
//! at the scheduler layer (NOT via a WASM guest `checkpoint()` call).
//!
//! **Label format**: PRD §4.7.7 / §1.3.4 notate the checkpoint as
//! `auto:iter-{n}` / `auto:baseline`. libgit2's `Tag::is_valid_name`
//! (MODULE-003's hardened `validate_ref_component`) rejects `:` in ref
//! names, so the on-disk git tag uses the hyphen form `auto-iter-{n}` /
//! `auto-baseline`. See MODULE-015 §2.11 + §3.8 note 1.

use std::sync::Arc;

use advance_git::NamedCheckpoint;
use async_trait::async_trait;

use crate::error::AutoLoopError;

/// Baseline checkpoint git-tag label (hyphen form — see module docs).
pub const BASELINE_LABEL: &str = "auto-baseline";

/// Per-iteration checkpoint git-tag label for iteration `n`.
pub fn iteration_label(n: u32) -> String {
    format!("auto-iter-{n}")
}

/// Scheduler-layer checkpoint surface used by the AutoLoopDriver. Slice A
/// creates full-directory checkpoints (`paths = None` → tag message `{}`).
#[async_trait]
pub trait IterationCheckpoint: Send + Sync {
    async fn checkpoint_baseline(&self, agent_id: &str) -> Result<(), AutoLoopError>;
    async fn checkpoint_iteration(&self, agent_id: &str, n: u32) -> Result<(), AutoLoopError>;
}

/// Default impl delegating to a CONTRACT-022 [`NamedCheckpoint`]. The
/// underlying `create` is synchronous (libgit2 under a `std::sync::Mutex`);
/// calls are wrapped in `spawn_blocking` so they don't stall the async
/// scheduler runtime.
pub struct DefaultIterationCheckpoint {
    inner: Arc<dyn NamedCheckpoint>,
}

impl DefaultIterationCheckpoint {
    pub fn new(inner: Arc<dyn NamedCheckpoint>) -> Self {
        Self { inner }
    }

    async fn create_full_directory(
        &self,
        agent_id: &str,
        label: String,
    ) -> Result<(), AutoLoopError> {
        let inner = Arc::clone(&self.inner);
        let agent_id = agent_id.to_string();
        // `NamedCheckpoint::create` is sync libgit2 work; offload to the
        // blocking pool. `Arc<dyn NamedCheckpoint>: Send + Sync` so the
        // clone moves into the closure safely; `CheckpointError: Send`.
        let join = tokio::task::spawn_blocking(move || inner.create(&agent_id, &label, None)).await;
        match join {
            Ok(inner_result) => inner_result.map_err(AutoLoopError::from),
            Err(join_err) => Err(AutoLoopError::CheckpointJoin(join_err.to_string())),
        }
    }
}

#[async_trait]
impl IterationCheckpoint for DefaultIterationCheckpoint {
    async fn checkpoint_baseline(&self, agent_id: &str) -> Result<(), AutoLoopError> {
        self.create_full_directory(agent_id, BASELINE_LABEL.to_string())
            .await
    }

    async fn checkpoint_iteration(&self, agent_id: &str, n: u32) -> Result<(), AutoLoopError> {
        self.create_full_directory(agent_id, iteration_label(n))
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn baseline_label_is_hyphen_form() {
        assert_eq!(BASELINE_LABEL, "auto-baseline");
        assert!(!BASELINE_LABEL.contains(':'));
    }

    #[test]
    fn iteration_label_is_hyphen_form() {
        assert_eq!(iteration_label(0), "auto-iter-0");
        assert_eq!(iteration_label(42), "auto-iter-42");
        assert!(!iteration_label(7).contains(':'));
    }
}

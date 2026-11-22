//! AC-02 — `unified_search()` coordinator (§1.3.1 / §11.3.1).
//!
//! Runtime-internal (NOT exposed to WASM guests). Coordinator value-add over
//! a pure port pass-through:
//!
//! 1. Pre-computes the query embedding via [`EmbeddingPort`] (MODULE-004 does
//!    NOT call `embed()` on the read path — the consumer supplies it). An
//!    embed error OR a non-finite/empty vector → `AssemblyError::EmbeddingFailed`
//!    per the §2.8 contract.
//! 2. Calls [`UnifiedSearchPort`] (CONTRACT-032 stand-in). A port error →
//!    `AssemblyError::MemoryStoreFailure`.
//! 3. **Enforces the §1.3.1 cross-task invariant**: `UnifiedSearchResult.turns`
//!    is documented "cross-task only (task_id != current)". The coordinator asks
//!    the port for other tasks' entries ([`UnifiedSearchPort::search_other_tasks`],
//!    which a port that can leave the task out before it cuts its lists
//!    overrides; CONTRACT-032's `search` takes no `current_task_id`), and still
//!    drops any returned turn whose `task_id == current_task_id`, and the current
//!    task itself from the related tasks (§11.3.1 L5: briefs of "非目标 task"
//!    only).
//!    Contents/memories pass through source-separated (the 4 typed fields ARE
//!    the source separation).
//!
//! Tier 2 ⑮ assembly-wiring of the result into the prompt (with CONTRACT-114
//! Layer-2 boundary marking) is a tracked §3.6 future-slice deferral —
//! AC-02's §1.4 criterion is satisfied by the coordinator + source separation
//! alone.

use std::sync::Arc;

use advance_shared_types::context::AssemblyError;

use crate::assembler::INPUT_VALIDATION_PREFIX;
use crate::ports::{EmbeddingPort, UnifiedSearchPort, UnifiedSearchResult};
use crate::warning_queue::is_valid_agent_id;

/// AC-02 coordinator. Holds the two ports it drives (the embedding port is
/// shared with `TaskRouter` via the same `Arc`).
pub struct UnifiedSearchCoordinator {
    embedding: Arc<dyn EmbeddingPort>,
    search: Arc<dyn UnifiedSearchPort>,
}

impl UnifiedSearchCoordinator {
    pub fn new(embedding: Arc<dyn EmbeddingPort>, search: Arc<dyn UnifiedSearchPort>) -> Self {
        Self { embedding, search }
    }

    /// Run a unified search for `agent_id` / `query`. `current_task_id` is the
    /// task the agent is currently on (if any) — turns from THAT task are
    /// dropped to honor the §1.3.1 cross-task-only invariant, and the task is
    /// no related task of itself.
    pub async fn unified_search(
        &self,
        agent_id: &str,
        query: &str,
        current_task_id: Option<&str>,
    ) -> Result<UnifiedSearchResult, AssemblyError> {
        // Round-10 ADVERSARIAL Warning 3 — defensive `agent_id` whitelist guard.
        // The in-tree caller (`assembler.rs::assemble`) validates per CONTRACT-090
        // invariant 4, but this method is `pub` on a `pub` struct constructible
        // by any consumer of the crate. Defense-in-depth: fail-closed with the
        // shared `INPUT_VALIDATION_PREFIX` payload so telemetry can distinguish
        // input rejection from a genuine M004 store outage (same convention as
        // Slice-A `assembler.rs`).
        if !is_valid_agent_id(agent_id) {
            return Err(AssemblyError::MemoryStoreFailure(format!(
                "{INPUT_VALIDATION_PREFIX}: invalid agent_id"
            )));
        }
        // 1. Pre-compute the query embedding. Map BOTH a hard error and a
        //    non-finite/empty vector to EmbeddingFailed (§2.8 contract; same
        //    finite-value discipline as TaskRouter).
        let q = self
            .embedding
            .embed(query)
            .await
            .map_err(|e| AssemblyError::EmbeddingFailed(e.0))?;
        if q.is_empty() || q.iter().any(|c| !c.is_finite()) {
            return Err(AssemblyError::EmbeddingFailed(
                "non-finite or empty query embedding".to_string(),
            ));
        }

        // 2. Delegate to the CONTRACT-032 stand-in.
        let mut result: UnifiedSearchResult = self
            .search
            .search_other_tasks(agent_id, query, &q, current_task_id)
            .await
            .map_err(|e| AssemblyError::MemoryStoreFailure(e.0))?;

        // 3. Enforce the §1.3.1 cross-task invariant on `turns` (the
        //    coordinator's owned value-add — the port may legitimately return
        //    same-task turns), and keep the current task out of the related
        //    tasks. Contents/memories untouched.
        if let Some(cur) = current_task_id {
            result.turns.retain(|t| t.task_id != cur);
            result.tasks.retain(|t| t.task_id != cur);
        }

        Ok(result)
    }
}

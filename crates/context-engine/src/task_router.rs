//! AC-03 / AC-04 — CONTRACT-091 `TaskRouter` (internal to unified_search).
//!
//! `route_task` decides whether an inbound message starts a NEW task or
//! continues an EXISTING one, using pure embedding cosine similarity
//! (semantic_similarity, NOT adjusted_score) over a task index, with an
//! ambiguity tie-break.
//!
//! **`TaskRoutingDecision` + `ContextError` are §1.3.2-named but
//! upstream-undefined** (category B2, MODULE-010 §3.6): §2.3 / shared-types
//! declare no shape for them; Slice B materializes them locally. A future
//! slice that formalizes CONTRACT-091 in shared-types replaces these.
//!
//! **Finite-value hardening** (MODULE-010 §3.8): an `embed()` error OR a
//! successful-but-non-finite/empty query vector → `Err(EmbeddingFailed)` —
//! NOT a fabricated `NewTask`. Rust `f32` NaN comparisons are always `false`,
//! so a NaN similarity would otherwise fail *open* through the
//! `< threshold` gate. Per-hit non-finite `similarity` is dropped before
//! ranking (strictly stronger than upstream `rank_task_rows`' NaN-only
//! filter). The §2.8 `EmbeddingFailed`→keyword-only re-route itself is a
//! tracked §3.6 deferral; Slice B propagates the error faithfully.

use std::sync::Arc;
use std::time::SystemTime;

use crate::ports::{EmbeddingPort, LightLlmFallbackPort, TaskHit, TaskIndexPort};
use crate::warning_queue::is_valid_agent_id;

/// Semantic-similarity cutoff: below this, no existing task is a confident
/// match → new task. MODULE-010 §1.3.2 / §2.10 `context.task_match_threshold`.
pub const TASK_MATCH_THRESHOLD: f32 = 0.5;

/// Ambiguity window: `top1 - top2 < AMBIGUITY_GAP` triggers the tie-break.
pub const AMBIGUITY_GAP: f32 = 0.1;

/// Top-N pulled from the task index before filtering/ranking.
pub const TASK_INDEX_FANOUT: usize = 5;

/// Routing outcome. §1.3.2-named, upstream-undefined (B2) — locally
/// materialized.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TaskRoutingDecision {
    /// No confident existing match — caller starts a new task.
    NewTask,
    /// Continue this existing task.
    Existing(String),
}

/// Routing failure surface. §1.3.2-named, upstream-undefined (B2). The
/// variant typing is preserved for direct callers of [`TaskRouter::route_task`]
/// who want to discriminate. The Slice-B `assembler.rs::assemble` integration
/// (the only in-tree caller today) collapses ALL `Err` variants to a graceful
/// degraded outcome (`is_new_task = true`, the safe default when no task_id
/// was supplied) rather than aborting tier assembly — see §2.8 intent ("fall
/// back to keyword-only routing", not "abort"). The keyword-only re-route
/// itself is a tracked §3.6 future-slice deferral. A future direct consumer
/// of `route_task` can still pattern-match on the variants.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContextError {
    /// `embed()` failed OR returned a non-finite/empty vector. Takes the §2.8
    /// keyword-only-routing degraded path (re-route itself deferred, §3.6).
    EmbeddingFailed(String),
    /// The task-index port failed.
    TaskIndex(String),
    /// The light-LLM ambiguity-fallback port failed.
    Fallback(String),
}

impl std::fmt::Display for ContextError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ContextError::EmbeddingFailed(m) => write!(f, "embedding failed: {m}"),
            ContextError::TaskIndex(m) => write!(f, "task index failed: {m}"),
            ContextError::Fallback(m) => write!(f, "ambiguity fallback failed: {m}"),
        }
    }
}

impl std::error::Error for ContextError {}

/// CONTRACT-091 task router. Holds the three ports it drives. Constructed by
/// `assembler.rs` from the same `Arc<dyn …>` deps injected into
/// `ContextAssemblerImpl::new`.
pub struct TaskRouter {
    embedding: Arc<dyn EmbeddingPort>,
    task_index: Arc<dyn TaskIndexPort>,
    light_llm: Arc<dyn LightLlmFallbackPort>,
}

impl TaskRouter {
    pub fn new(
        embedding: Arc<dyn EmbeddingPort>,
        task_index: Arc<dyn TaskIndexPort>,
        light_llm: Arc<dyn LightLlmFallbackPort>,
    ) -> Self {
        Self {
            embedding,
            task_index,
            light_llm,
        }
    }

    /// Route `query` for `agent_id`. See module docs for the finite-value
    /// hardening contract.
    pub async fn route_task(
        &self,
        agent_id: &str,
        query: &str,
    ) -> Result<TaskRoutingDecision, ContextError> {
        // Round-10 ADVERSARIAL Warning 3 — defensive `agent_id` whitelist guard.
        // The in-tree caller (`assembler.rs::assemble`) validates per
        // CONTRACT-090 invariant 4 before invoking the router; this guard is
        // defense-in-depth for direct external callers (TaskRouter::new is
        // `pub`). An invalid `agent_id` cannot match any registered task,
        // so the safe degraded outcome is `NewTask` (no panic, no propagation
        // of an unvalidated id into the `TaskIndexPort`).
        if !is_valid_agent_id(agent_id) {
            return Ok(TaskRoutingDecision::NewTask);
        }
        // 1. Embed. A hard error propagates as EmbeddingFailed (§1.3.2 `?`,
        //    §2.8 keyword-only path) — NOT NewTask.
        let q = self
            .embedding
            .embed(query)
            .await
            .map_err(|e| ContextError::EmbeddingFailed(e.0))?;

        // 2. Finite-value hardening: an empty or non-finite embedding is not
        //    a *usable* embedding → same EmbeddingFailed degraded path, NOT
        //    the NaN<threshold fail-open footgun.
        if q.is_empty() || q.iter().any(|c| !c.is_finite()) {
            return Err(ContextError::EmbeddingFailed(
                "non-finite or empty query embedding".to_string(),
            ));
        }

        // 3. Fan out to the task index.
        let hits = self
            .task_index
            .top_n_by_similarity(agent_id, &q, TASK_INDEX_FANOUT)
            .await
            .map_err(|e| ContextError::TaskIndex(e.0))?;

        // 4. Drop non-finite similarities (defends the same footgun on the
        //    hit side) and the `auto:` namespace (REQ-069).
        let mut hits: Vec<TaskHit> = hits
            .into_iter()
            .filter(|h| h.similarity.is_finite() && !h.task_id.starts_with("auto:"))
            .collect();

        // 5. Sort by similarity desc (stable; total order is safe — all
        //    finite after step 4).
        hits.sort_by(|a, b| {
            b.similarity
                .partial_cmp(&a.similarity)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        // No confident match → new task. (The ONLY legitimate NewTask path.)
        if hits.is_empty() || hits[0].similarity < TASK_MATCH_THRESHOLD {
            return Ok(TaskRoutingDecision::NewTask);
        }

        // 6. Ambiguity: top1 - top2 < AMBIGUITY_GAP → tie-break.
        if hits.len() >= 2 && (hits[0].similarity - hits[1].similarity) < AMBIGUITY_GAP {
            let max_sim = hits[0].similarity;
            let cands: Vec<&TaskHit> = hits
                .iter()
                .filter(|h| (max_sim - h.similarity) < AMBIGUITY_GAP)
                .collect();

            // Tie-break by last_turn_at, "Some precedes None", newer first.
            let best_key = cands
                .iter()
                .map(|h| time_key(&h.last_turn_at))
                .max()
                .expect("cands non-empty: ambiguity requires >=2 hits");
            let tied: Vec<&&TaskHit> = cands
                .iter()
                .filter(|h| time_key(&h.last_turn_at) == best_key)
                .collect();

            if tied.len() >= 2 {
                // Residual tie (equal/all-None last_turn_at) → light-LLM.
                let ids: Vec<String> = tied.iter().map(|h| h.task_id.clone()).collect();
                let picked = self
                    .light_llm
                    .pick_one(query, &ids)
                    .await
                    .map_err(|e| ContextError::Fallback(e.0))?;
                return Ok(TaskRoutingDecision::Existing(picked));
            }
            return Ok(TaskRoutingDecision::Existing(tied[0].task_id.clone()));
        }

        // 7. Unambiguous top hit.
        Ok(TaskRoutingDecision::Existing(hits[0].task_id.clone()))
    }
}

/// Total-order key for `Option<SystemTime>` tie-break: `Some(t)` always
/// outranks `None` ("Some precedes None"); among `Some`, newer outranks
/// older. `(has_time, since_epoch_nanos)` — `None` → `(0, 0)`, `Some(t)` →
/// `(1, nanos)`. Comparing the tuple gives the desired total order and lets
/// "≥2 share the identical max key" detect the residual-tie / all-None case.
///
/// `pub(crate)` (data-port pre-build, 2026-06-08) so the real `TaskIndexPort`
/// impl `crate::vector_search::CosineTaskIndex` reuses the IDENTICAL tie-break
/// rather than a divergent copy. Visibility-only widening — body unchanged.
pub(crate) fn time_key(t: &Option<SystemTime>) -> (u8, u128) {
    match t {
        None => (0, 0),
        Some(st) => {
            let nanos = st
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            (1, nanos)
        }
    }
}

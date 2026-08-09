//! MODULE-019 CostTracker — CONTRACT-181 first declaration + first impl.
//!
//! Per MODULE-019 §1.3.4 (lines 281-321), `CostTracker` subscribes to `llm.response`
//! events emitted via the EventBus and folds the payload's `input_tokens` /
//! `output_tokens` / `cost_usd` / `iteration` fields into two aggregates:
//!
//! - `by_run`: keyed by `Run.run_id` — total cost for the entire Run.
//! - `by_run_iteration`: keyed by `(run_id, iteration)` — per-iteration cost for Auto
//!   mode budget enforcement (REQ-077).
//!
//! # Wiring
//!
//! `EventBus` (in `advance-event-bus`) holds an `Arc<CostTracker>`, calls
//! `tracker.observe(&event)` SYNCHRONOUSLY inside the `EventBus::emit` body, AFTER
//! the 4 bounded-channel `try_send`s. `observe` is a synchronous method (no `await`)
//! to keep `emit`'s NFR p99 < 10 µs achievable — only `RwLock::write` + `HashMap`
//! insert.
//!
//! `EventBus` exposes `cost_tracker_query() -> Arc<dyn CostTrackerQuery>` so
//! downstream consumers (MODULE-008 run-manager, MODULE-015 auto-mode) can lookup
//! aggregates without compile-time edges to `advance-event-bus`.
//!
//! # Implementer Invariants for `observe`
//!
//! 1. **Non-`llm.response` events ignored**: filter on `event.event_type` first.
//! 2. **Missing `payload.iteration`**: defaults to 0 (per spec §1.3.4 reference impl).
//! 3. **Missing `payload.input_tokens` / `output_tokens` / `cost_usd`**: each defaults
//!    to 0 / 0 / 0.0 (saturation; never panics).
//! 4. **Missing/empty `event.run_id`**: retained by the EventBus/global audit
//!    path, but skipped by these per-run folds.  CONTRACT-216 detached work must
//!    never manufacture an empty-run budget bucket.
//! 5. **Synchronous, non-blocking**: no `await`, no I/O. Lock acquisition is the
//!    only potentially-blocking primitive (microsecond-scale on uncontended writes).
//! 6. **Two locks acquired sequentially**: `by_run` first, then `by_run_iteration`.
//!    Never reverse — the canonical lock order avoids deadlock if any future code
//!    holds both simultaneously.
//! 7. **CostTracker counts emit-attempts, not durable persistence** (Slice B AUDIT
//!    diff Warning 7 acknowledgment): when an `EventBus::emit` call experiences
//!    backpressure (any of the 4 mpsc channels returns `try_send` Err), the
//!    `dropped_count` increments AND the cost is still aggregated here. This is
//!    intentional: the per-run / per-iteration budget enforced by MODULE-008 +
//!    MODULE-015 should reflect "tokens spent talking to the LLM API", which is
//!    the emit-attempt count — not "tokens that survived the durability fan-out".
//!    Rebuild from JSONL reconstructs `runs.token_used` from the JSONL truth (a
//!    SUBSET of attempts when drops occurred), so post-rebuild aggregates may be
//!    LOWER than the live in-memory CostTracker. Both views are correct for their
//!    respective purposes. Document explicitly so M008/M015 implementers don't
//!    expect strict equivalence between live tracker and rebuilt-from-JSONL runs row.

use std::collections::HashMap;
use std::sync::RwLock;

use advance_shared_types::cost::RunCost;
use advance_shared_types::event::Event;
use advance_shared_types::traits::CostTrackerQuery;

/// CostTracker — MODULE-019 §1.3.4 implementation of CONTRACT-181.
#[derive(Debug, Default)]
pub struct CostTracker {
    by_run: RwLock<HashMap<String, RunCost>>,
    by_run_iteration: RwLock<HashMap<(String, u32), RunCost>>,
}

impl CostTracker {
    /// Construct an empty tracker. Same as `Default::default()`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Observe one `Event`. Folds into both aggregates if the event is an
    /// `llm.response`; ignores otherwise.
    ///
    /// See module-level rustdoc for the full implementer invariants.
    pub fn observe(&self, event: &Event) {
        if event.event_type != "llm.response" {
            return;
        }
        let Some(run_id) = event.run_id.as_deref().filter(|run_id| !run_id.is_empty()) else {
            return;
        };
        let run_id = run_id.to_owned();
        let iteration = event
            .payload
            .get("iteration")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;
        let tokens_in = event
            .payload
            .get("input_tokens")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let tokens_out = event
            .payload
            .get("output_tokens")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        // Adversarial Round-1 W1 fix: clamp cost_usd at 0.0. Negative values from
        // adversarial / corrupted payloads must NOT subtract from the budget
        // aggregate (Auto-mode budget enforcement reads cost_usd; negative input
        // would let an attacker reset the cumulative cost back below the limit).
        // NaN / NEG_INFINITY become 0.0 via the same clamp path.
        let cost = event
            .payload
            .get("cost_usd")
            .and_then(|v| v.as_f64())
            .filter(|v| v.is_finite() && *v >= 0.0)
            .unwrap_or(0.0);

        // Lock order: by_run first, then by_run_iteration. Never reverse.
        // Use saturating_add for u64 fields to avoid overflow panic under
        // adversarial / corrupted upstream `usage` payloads.
        //
        // Round-1 AUDIT diff Critical 4 fix: recover from poisoned RwLock
        // instead of panicking. EventBusEmit Implementer Invariant 2 ("never
        // panic on event content") propagates from emit → observe; if a prior
        // panic on another thread poisoned the lock, swallowing the poison
        // (via `into_inner` of the PoisonError guard) preserves the invariant.
        {
            let mut r = match self.by_run.write() {
                Ok(g) => g,
                Err(poison) => poison.into_inner(),
            };
            let entry = r.entry(run_id.clone()).or_default();
            entry.tokens_in = entry.tokens_in.saturating_add(tokens_in);
            entry.tokens_out = entry.tokens_out.saturating_add(tokens_out);
            // Saturate cost_usd at f64::MAX to avoid INFINITY accumulation
            // (Round-1 AUDIT diff Warning 3 acknowledgment).
            let next = entry.cost_usd + cost;
            entry.cost_usd = if next.is_finite() { next } else { f64::MAX };
            entry.request_count = entry.request_count.saturating_add(1);
        }
        {
            let mut ri = match self.by_run_iteration.write() {
                Ok(g) => g,
                Err(poison) => poison.into_inner(),
            };
            let entry = ri.entry((run_id, iteration)).or_default();
            entry.tokens_in = entry.tokens_in.saturating_add(tokens_in);
            entry.tokens_out = entry.tokens_out.saturating_add(tokens_out);
            let next = entry.cost_usd + cost;
            entry.cost_usd = if next.is_finite() { next } else { f64::MAX };
            entry.request_count = entry.request_count.saturating_add(1);
        }
    }
}

impl CostTrackerQuery for CostTracker {
    fn query_run(&self, run_id: &str) -> Option<RunCost> {
        if run_id.is_empty() {
            return None;
        }
        let g = match self.by_run.read() {
            Ok(g) => g,
            Err(poison) => poison.into_inner(),
        };
        g.get(run_id).cloned()
    }

    fn query_iteration(&self, run_id: &str, iteration: u32) -> Option<RunCost> {
        if run_id.is_empty() {
            return None;
        }
        let g = match self.by_run_iteration.read() {
            Ok(g) => g,
            Err(poison) => poison.into_inner(),
        };
        g.get(&(run_id.to_string(), iteration)).cloned()
    }
}

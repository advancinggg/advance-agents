//! `RunCost` payload for CONTRACT-181 `CostTrackerQuery` (MODULE-019 §1.3.4).
//!
//! Per-run / per-iteration cost aggregate produced by MODULE-019 `CostTracker` from
//! `llm.response` events. Returned by `CostTrackerQuery::query_run` and
//! `CostTrackerQuery::query_iteration`.
//!
//! Slice m019-B (2026-05-04): first canonical declaration. Consumed by MODULE-008
//! run-manager (per-run budget check) and MODULE-015 auto-mode (per-iteration budget
//! check) per ARCHITECTURE.md §6.1 CONTRACT-181 line 608.

use serde::{Deserialize, Serialize};

/// Aggregate cost numbers for a Run or (Run, iteration) tuple.
///
/// All four fields are monotonically nondecreasing across `CostTracker::observe`
/// calls. Values are denominated in:
/// - `tokens_in` / `tokens_out`: raw LLM API token counts (pre-cache).
/// - `cost_usd`: USD cost per the LLM provider's per-million-token rates.
/// - `request_count`: number of `llm.response` events folded into this aggregate.
///
/// `Default` returns the zero aggregate — used for `or_default` pattern in the
/// HashMap entry path inside `CostTracker::observe`.
///
/// `PartialEq` (not `Eq`) because `cost_usd: f64` does not impl `Eq` (NaN
/// inequality). Aggregator code never produces NaN since the inputs are
/// `serde_json::Value::as_f64` filtered values.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunCost {
    pub tokens_in: u64,
    pub tokens_out: u64,
    pub cost_usd: f64,
    pub request_count: u32,
}

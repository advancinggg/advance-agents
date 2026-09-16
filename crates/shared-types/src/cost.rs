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

// ── Durable cost attribution (agent / provider ledger) ─────────────────────────
//
// Lane cost-attribution (2026-09-16). `RunCost` above is the in-memory per-run
// aggregate; the types below describe the DURABLE attribution view computed from
// the persisted `events` table (`llm.response` rows), which survives a daemon
// restart. Consumed by MODULE-020 client-api (`/client/costs/*`) through the
// `CostLedgerQuery` port in `traits.rs`; produced by MODULE-019 event-bus.

/// A half-open time window `[since, until)` over event timestamps. `None` on
/// either side means unbounded. Bounds are honoured at SECOND granularity:
/// `since` is floored and `until` is ceiled to the whole second, so a window can
/// only ever include MORE rows than requested, never fewer.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CostWindow {
    pub since: Option<chrono::DateTime<chrono::Utc>>,
    pub until: Option<chrono::DateTime<chrono::Utc>>,
}

impl CostWindow {
    /// The unbounded window (all retained history).
    pub const ALL: CostWindow = CostWindow {
        since: None,
        until: None,
    };

    /// `true` iff `since <= until` (or either side is unbounded).
    pub fn is_ordered(&self) -> bool {
        match (self.since, self.until) {
            (Some(s), Some(u)) => s <= u,
            _ => true,
        }
    }
}

/// One attribution row: an agent id or a provider id together with its totals.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttributedCost {
    /// The attribution key — an `Event.agent_id`, or the `payload.provider` id
    /// of an `llm.response` (`"unknown"` for rows recorded before the provider id
    /// was carried on the event).
    pub id: String,
    pub cost: RunCost,
}

/// Failure of a durable ledger read. Never carries row contents.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CostLedgerError {
    /// The ledger has no durable store to read (e.g. a bus without SQLite).
    Unavailable(String),
    /// The store rejected the query (pool exhaustion, I/O, SQL error).
    Query(String),
}

impl std::fmt::Display for CostLedgerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CostLedgerError::Unavailable(s) => write!(f, "cost ledger unavailable: {s}"),
            CostLedgerError::Query(s) => write!(f, "cost ledger query failed: {s}"),
        }
    }
}

impl std::error::Error for CostLedgerError {}

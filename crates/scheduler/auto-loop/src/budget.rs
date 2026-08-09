//! Per-iteration budget primitive (PRD §4.7.8 / MODULE-015 §1.3 / AC-13/AC-23
//! foundation — verification deferred to the integrated §4.7.7 loop slice).
//!
//! Stateless pure-function design — no `BudgetTracker` struct. The driver-level
//! `DefaultAutoLoopDriver::check_per_iteration_budget` orchestrates: reads the
//! per-session `PerIterationBudget` off `AutoState.criteria.per_iteration_budget`,
//! fetches `RunCost` via the stored `Arc<dyn CostTrackerQuery>` (CONTRACT-181 —
//! canonical from `advance_shared_types`), and calls `check_budget`.
//!
//! Limit-check order is documented as Tokens > Cost > WallTime: tokens are the
//! cheapest signal to compute (already aggregated in `RunCost`), cost is the
//! user's primary economic limit, wall-time is the catch-all timeout. First
//! breach short-circuits; remaining limits are not checked.
//!
//! Slice-D adds [`budget_breach_to_fail_fast_trigger`] — the bridge that maps a
//! [`BudgetBreach`] to a [`crate::fail_fast::FailFastOutcome::Trigger`],
//! satisfying AC-23's "any limit breach triggers iteration_end via fail-fast
//! path" at the composition layer.

use std::time::Instant;

use serde::{Deserialize, Serialize};

use advance_shared_types::cost::RunCost;

use crate::fail_fast::FailFastOutcome;

/// `auto-loop.per_iteration_budget` config block (PRD §4.7.8). All three
/// limits are optional; absent means "no limit on that dimension". A
/// `PerIterationBudget` with all three None is functionally equivalent to
/// passing `budget: None` to `check_budget`.
#[derive(Clone, Debug, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct PerIterationBudget {
    #[serde(default)]
    pub max_tokens: Option<u64>,
    #[serde(default)]
    pub max_wall_time_sec: Option<u64>,
    #[serde(default)]
    pub max_cost_usd: Option<f64>,
}

/// Outcome of a budget check.
#[derive(Clone, Debug, PartialEq)]
pub enum BudgetStatus {
    Ok,
    Breach(BudgetBreach),
}

/// Which limit was breached and by how much. Tokens/WallTime use `u64`;
/// Cost uses `f64`. `PartialEq` only (no `Eq`) because of `f64`.
#[derive(Clone, Debug, PartialEq)]
pub enum BudgetBreach {
    Tokens { observed: u64, limit: u64 },
    WallTime { observed_sec: u64, limit_sec: u64 },
    Cost { observed_usd: f64, limit_usd: f64 },
}

/// Pure budget check. Independent of the global safety valve (PRD §4.7.6) —
/// callers compose this with the global `max_cost_usd` check separately.
///
/// Defense-in-depth semantics:
/// - `budget == None` → `Ok` (no limits configured).
/// - `cost == None` → tokens/cost-usd treated as 0 (no cost rows yet).
/// - `now < started_at` (clock skew) → elapsed treated as 0.
/// - `tokens_in.saturating_add(tokens_out)` → no u64 overflow panic.
///
/// Order: Tokens > Cost > WallTime. First breach short-circuits.
pub fn check_budget(
    budget: Option<&PerIterationBudget>,
    cost: Option<&RunCost>,
    started_at: Instant,
    now: Instant,
) -> BudgetStatus {
    let Some(budget) = budget else {
        return BudgetStatus::Ok;
    };

    // Tokens (cheapest signal — RunCost already aggregates).
    if let Some(limit) = budget.max_tokens {
        let observed = cost
            .map(|c| c.tokens_in.saturating_add(c.tokens_out))
            .unwrap_or(0);
        if observed > limit {
            return BudgetStatus::Breach(BudgetBreach::Tokens { observed, limit });
        }
    }

    // Cost (user's economic limit).
    if let Some(limit) = budget.max_cost_usd {
        let observed = cost.map(|c| c.cost_usd).unwrap_or(0.0);
        if observed > limit {
            return BudgetStatus::Breach(BudgetBreach::Cost {
                observed_usd: observed,
                limit_usd: limit,
            });
        }
    }

    // WallTime (catch-all timeout). Saturating against clock skew.
    if let Some(limit_sec) = budget.max_wall_time_sec {
        let elapsed = if now >= started_at {
            now.duration_since(started_at).as_secs()
        } else {
            0
        };
        if elapsed > limit_sec {
            return BudgetStatus::Breach(BudgetBreach::WallTime {
                observed_sec: elapsed,
                limit_sec,
            });
        }
    }

    BudgetStatus::Ok
}

/// Bridge a [`BudgetBreach`] to a [`FailFastOutcome::Trigger`] (slice-D / AC-23).
///
/// This is the M015-side composition primitive establishing that a per-iteration
/// budget breach feeds the fail-fast path (PRD §4.7.8 "超预算时：…按 §4.7.7
/// crash/timeout 路径处理"). The integrated-loop slice composes the full chain:
/// `check_per_iteration_budget` → [`BudgetStatus::Breach`] →
/// `budget_breach_to_fail_fast_trigger` → [`FailFastOutcome::Trigger`] →
/// rollback + crash-row (the same crash sequence exercised by
/// `tests/iteration_close_sequence.rs::fail_fast_trigger_to_crash_path_sequence`).
///
/// The reason string is stable per breach variant:
/// - `"fail-fast: per-iteration budget breach: tokens observed={N} limit={N}"`
/// - `"fail-fast: per-iteration budget breach: cost observed_usd={f} limit_usd={f}"`
/// - `"fail-fast: per-iteration budget breach: wall-time observed_sec={N} limit_sec={N}"`
pub fn budget_breach_to_fail_fast_trigger(breach: &BudgetBreach) -> FailFastOutcome {
    let reason = match breach {
        BudgetBreach::Tokens { observed, limit } => format!(
            "fail-fast: per-iteration budget breach: tokens observed={observed} limit={limit}"
        ),
        BudgetBreach::Cost {
            observed_usd,
            limit_usd,
        } => format!(
            "fail-fast: per-iteration budget breach: cost observed_usd={observed_usd} limit_usd={limit_usd}"
        ),
        BudgetBreach::WallTime {
            observed_sec,
            limit_sec,
        } => format!(
            "fail-fast: per-iteration budget breach: wall-time observed_sec={observed_sec} limit_sec={limit_sec}"
        ),
    };
    FailFastOutcome::Trigger { reason }
}

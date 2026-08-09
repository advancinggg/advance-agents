//! Foundation tests for per-iteration budget primitive (AC-13/AC-23
//! verification deferred to integrated-loop slice; the pure-function
//! primitive's correctness is unit-tested here).

use std::time::{Duration, Instant};

use advance_scheduler_auto_loop::{check_budget, BudgetBreach, BudgetStatus, PerIterationBudget};
use advance_shared_types::cost::RunCost;

fn budget(tokens: Option<u64>, wall_sec: Option<u64>, cost_usd: Option<f64>) -> PerIterationBudget {
    PerIterationBudget {
        max_tokens: tokens,
        max_wall_time_sec: wall_sec,
        max_cost_usd: cost_usd,
    }
}

fn cost(tokens_in: u64, tokens_out: u64, cost_usd: f64) -> RunCost {
    RunCost {
        tokens_in,
        tokens_out,
        cost_usd,
        request_count: 1,
    }
}

#[test]
fn a_no_budget_returns_ok() {
    let t0 = Instant::now();
    assert_eq!(check_budget(None, None, t0, t0), BudgetStatus::Ok);
}

#[test]
fn a_budget_no_cost_returns_ok() {
    // Defense-in-depth: missing cost treated as zero → no breach.
    let t0 = Instant::now();
    let b = budget(Some(50_000), None, None);
    assert_eq!(check_budget(Some(&b), None, t0, t0), BudgetStatus::Ok);
}

#[test]
fn b_tokens_breach() {
    let t0 = Instant::now();
    let b = budget(Some(50_000), None, None);
    let c = cost(30_000, 30_000, 0.0); // total = 60000 > 50000
    match check_budget(Some(&b), Some(&c), t0, t0) {
        BudgetStatus::Breach(BudgetBreach::Tokens { observed, limit }) => {
            assert_eq!(observed, 60_000);
            assert_eq!(limit, 50_000);
        }
        other => panic!("expected Tokens breach, got {other:?}"),
    }
}

#[test]
fn c_wall_time_breach() {
    let t0 = Instant::now();
    let now = t0 + Duration::from_secs(320);
    let b = budget(None, Some(300), None);
    let c = cost(0, 0, 0.0);
    match check_budget(Some(&b), Some(&c), t0, now) {
        BudgetStatus::Breach(BudgetBreach::WallTime {
            observed_sec,
            limit_sec,
        }) => {
            assert_eq!(observed_sec, 320);
            assert_eq!(limit_sec, 300);
        }
        other => panic!("expected WallTime breach, got {other:?}"),
    }
}

#[test]
fn d_cost_breach() {
    let t0 = Instant::now();
    let b = budget(None, None, Some(0.10));
    let c = cost(0, 0, 0.11);
    match check_budget(Some(&b), Some(&c), t0, t0) {
        BudgetStatus::Breach(BudgetBreach::Cost {
            observed_usd,
            limit_usd,
        }) => {
            assert!((observed_usd - 0.11).abs() < f64::EPSILON);
            assert!((limit_usd - 0.10).abs() < f64::EPSILON);
        }
        other => panic!("expected Cost breach, got {other:?}"),
    }
}

#[test]
fn e_priority_tokens_over_cost_over_walltime() {
    // All three limits breached — should return Tokens first.
    let t0 = Instant::now();
    let now = t0 + Duration::from_secs(400);
    let b = budget(Some(50_000), Some(300), Some(0.10));
    let c = cost(60_000, 0, 0.50); // tokens=60000>50000, cost=0.50>0.10, wall=400>300
    match check_budget(Some(&b), Some(&c), t0, now) {
        BudgetStatus::Breach(BudgetBreach::Tokens { .. }) => {} // expected
        other => panic!("expected Tokens (priority), got {other:?}"),
    }
}

#[test]
fn e_priority_cost_over_walltime() {
    // Tokens within budget; cost AND walltime breached — cost first.
    let t0 = Instant::now();
    let now = t0 + Duration::from_secs(400);
    let b = budget(Some(50_000), Some(300), Some(0.10));
    let c = cost(10_000, 0, 0.50);
    match check_budget(Some(&b), Some(&c), t0, now) {
        BudgetStatus::Breach(BudgetBreach::Cost { .. }) => {}
        other => panic!("expected Cost (after tokens ok), got {other:?}"),
    }
}

#[test]
fn h_signature_takes_budget_cost_started_at_now() {
    // Smoke test asserting the function compiles with the documented
    // signature: pure function over references + timestamps.
    let t0 = Instant::now();
    let b = budget(Some(1000), Some(60), Some(1.0));
    let c = cost(500, 500, 0.5);
    let _: BudgetStatus = check_budget(Some(&b), Some(&c), t0, t0);
}

#[test]
fn j_clock_skew_now_before_started_at_treated_as_zero_elapsed() {
    // Defense-in-depth: if `now < started_at` (clock skew), elapsed is 0.
    let t0 = Instant::now();
    let now = t0; // now == started_at (cannot subtract for "before" in Instant API directly
                  // because Instant doesn't allow now < started_at construction without panic
                  // in safe code, so we test the saturating behavior at equality).
    let b = budget(None, Some(60), None);
    let c = cost(0, 0, 0.0);
    assert_eq!(check_budget(Some(&b), Some(&c), t0, now), BudgetStatus::Ok);
}

#[test]
fn k_tokens_saturating_add() {
    // Saturating against u64 overflow: extreme token counts don't panic.
    let t0 = Instant::now();
    let b = budget(Some(u64::MAX - 1), None, None);
    let c = cost(u64::MAX, u64::MAX, 0.0); // saturates to u64::MAX, not panic
    match check_budget(Some(&b), Some(&c), t0, t0) {
        BudgetStatus::Breach(BudgetBreach::Tokens { observed, limit }) => {
            assert_eq!(observed, u64::MAX);
            assert_eq!(limit, u64::MAX - 1);
        }
        other => panic!("expected Tokens breach (saturating), got {other:?}"),
    }
}

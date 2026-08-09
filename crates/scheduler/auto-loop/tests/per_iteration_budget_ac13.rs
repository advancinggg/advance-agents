//! AC-13 (M015-side closure): per-iteration budget enforcement via
//! `CostTrackerQuery` (CONTRACT-181 / MODULE-019) and a wall-time timer,
//! verified through the DRIVER-LEVEL orchestrator
//! `DefaultAutoLoopDriver::check_per_iteration_budget` (not just the pure
//! `check_budget` helper that `tests/budget.rs` covers).
//!
//! Cross-module deferred (MODULE-015 §3.6): the call-site constructing the
//! concrete `Arc<dyn CostTrackerQuery>` from M019's CostTracker + the
//! per-iteration wall-time anchor reset on `auto.iteration_started`.

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use advance_scheduler_auto_loop::{
    config::{MetricSource, Objective, Op, Predicate, Role, SuccessCriteria},
    AutoLoopDriver, BudgetBreach, BudgetStatus, DefaultAutoLoopDriver, PerIterationBudget,
};
use advance_shared_types::cost::RunCost;

use common::{MockCostTracker, NoopIterationCheckpoint, NoopIterationRollback};

fn criteria_with_budget(budget: Option<PerIterationBudget>) -> SuccessCriteria {
    SuccessCriteria {
        evaluator: None,
        objectives: vec![Objective {
            name: "val-bpb".to_string(),
            role: Role::Primary,
            metric_source: MetricSource::File {
                path: "metrics/bpb.json".to_string(),
                key: "val_bpb".to_string(),
            },
            predicate: Predicate {
                op: Op::Lt,
                threshold: None,
            },
        }],
        per_iteration_budget: budget,
        fail_fast: None,
        safety_valve: None,
    }
}

fn driver_with_cost(cost: MockCostTracker) -> DefaultAutoLoopDriver {
    DefaultAutoLoopDriver::new(
        Arc::new(NoopIterationCheckpoint),
        Arc::new(NoopIterationRollback),
    )
    .with_cost_tracker(Arc::new(cost))
}

fn run_cost(tokens_in: u64, tokens_out: u64, cost_usd: f64) -> RunCost {
    RunCost {
        tokens_in,
        tokens_out,
        cost_usd,
        request_count: 1,
    }
}

// MODULE-015-T13-slD.a — Tokens breach via CostTrackerQuery::query_iteration.
#[tokio::test]
async fn driver_tokens_breach_via_cost_tracker() {
    let cost = MockCostTracker::new().with_cost("run-a", 0, run_cost(40_000, 30_000, 0.0));
    let driver = driver_with_cost(cost);
    driver
        .start(
            "alice",
            criteria_with_budget(Some(PerIterationBudget {
                max_tokens: Some(50_000),
                max_wall_time_sec: None,
                max_cost_usd: None,
            })),
        )
        .await
        .expect("start");

    let t0 = Instant::now();
    match driver.check_per_iteration_budget("alice", "run-a", 0, t0, t0) {
        BudgetStatus::Breach(BudgetBreach::Tokens { observed, limit }) => {
            assert_eq!(observed, 70_000, "tokens_in + tokens_out aggregation");
            assert_eq!(limit, 50_000);
        }
        other => panic!("expected Tokens breach via CostTrackerQuery; got {other:?}"),
    }
}

// MODULE-015-T13-slD.b — WallTime breach via Instant-based timer (strict `>`).
#[tokio::test]
async fn driver_walltime_breach_via_timer() {
    // Zero token/cost so only wall-time can breach.
    let cost = MockCostTracker::new().with_cost("run-a", 0, run_cost(0, 0, 0.0));
    let driver = driver_with_cost(cost);
    driver
        .start(
            "alice",
            criteria_with_budget(Some(PerIterationBudget {
                max_tokens: None,
                max_wall_time_sec: Some(300),
                max_cost_usd: None,
            })),
        )
        .await
        .expect("start");

    let t0 = Instant::now();
    // now = started_at + (limit + 20)s → strict `>` breach per budget.rs:94.
    let now = t0 + Duration::from_secs(320);
    match driver.check_per_iteration_budget("alice", "run-a", 0, t0, now) {
        BudgetStatus::Breach(BudgetBreach::WallTime {
            observed_sec,
            limit_sec,
        }) => {
            assert!(
                observed_sec > limit_sec,
                "wall-time breach must be strict greater: observed={observed_sec} limit={limit_sec}"
            );
            assert_eq!(observed_sec, 320);
            assert_eq!(limit_sec, 300);
        }
        other => panic!("expected WallTime breach; got {other:?}"),
    }
}

// MODULE-015-T13-slD.c — Cost breach via CostTrackerQuery cost_usd field.
#[tokio::test]
async fn driver_cost_breach_via_cost_tracker() {
    let cost = MockCostTracker::new().with_cost("run-a", 0, run_cost(0, 0, 0.11));
    let driver = driver_with_cost(cost);
    driver
        .start(
            "alice",
            criteria_with_budget(Some(PerIterationBudget {
                max_tokens: None,
                max_wall_time_sec: None,
                max_cost_usd: Some(0.10),
            })),
        )
        .await
        .expect("start");

    let t0 = Instant::now();
    match driver.check_per_iteration_budget("alice", "run-a", 0, t0, t0) {
        BudgetStatus::Breach(BudgetBreach::Cost {
            observed_usd,
            limit_usd,
        }) => {
            assert!((observed_usd - 0.11).abs() < 1e-9);
            assert!((limit_usd - 0.10).abs() < 1e-9);
        }
        other => panic!("expected Cost breach; got {other:?}"),
    }
}

// MODULE-015-T13-slD.d — all three limits configured, none breached → Ok.
#[tokio::test]
async fn driver_within_all_limits_ok() {
    let cost = MockCostTracker::new().with_cost("run-a", 0, run_cost(10, 10, 0.01));
    let driver = driver_with_cost(cost);
    driver
        .start(
            "alice",
            criteria_with_budget(Some(PerIterationBudget {
                max_tokens: Some(50_000),
                max_wall_time_sec: Some(300),
                max_cost_usd: Some(0.10),
            })),
        )
        .await
        .expect("start");

    let t0 = Instant::now();
    assert_eq!(
        driver.check_per_iteration_budget("alice", "run-a", 0, t0, t0),
        BudgetStatus::Ok
    );
}

// MODULE-015-T13-slD.e — agent not started (no AutoState) → defense-in-depth Ok.
#[tokio::test]
async fn driver_no_session_ok() {
    let cost = MockCostTracker::new().with_cost("run-a", 0, run_cost(99_999, 99_999, 9.9));
    let driver = driver_with_cost(cost);
    // No `start` for "ghost".
    let t0 = Instant::now();
    assert_eq!(
        driver.check_per_iteration_budget("ghost", "run-a", 0, t0, t0),
        BudgetStatus::Ok,
        "missing AutoState is defense-in-depth Ok per docstring"
    );
}

// MODULE-015-T13-slD.f — no cost tracker attached + budget configured → Ok.
#[tokio::test]
async fn driver_no_cost_tracker_ok() {
    // Driver WITHOUT with_cost_tracker.
    let driver = DefaultAutoLoopDriver::new(
        Arc::new(NoopIterationCheckpoint),
        Arc::new(NoopIterationRollback),
    );
    driver
        .start(
            "alice",
            criteria_with_budget(Some(PerIterationBudget {
                max_tokens: Some(1),
                max_wall_time_sec: None,
                max_cost_usd: None,
            })),
        )
        .await
        .expect("start");

    let t0 = Instant::now();
    assert_eq!(
        driver.check_per_iteration_budget("alice", "run-a", 0, t0, t0),
        BudgetStatus::Ok,
        "no cost tracker → cost treated as absent → no token/cost breach"
    );
}

// MODULE-015-T13-slD.g — no per_iteration_budget in criteria (None) → Ok.
#[tokio::test]
async fn driver_no_budget_in_criteria_ok() {
    let cost = MockCostTracker::new().with_cost("run-a", 0, run_cost(99_999, 99_999, 9.9));
    let driver = driver_with_cost(cost);
    driver
        .start("alice", criteria_with_budget(None))
        .await
        .expect("start");

    let t0 = Instant::now();
    assert_eq!(
        driver.check_per_iteration_budget("alice", "run-a", 0, t0, t0),
        BudgetStatus::Ok,
        "per_iteration_budget None → nothing to check"
    );
}

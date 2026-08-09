//! AC-23 (M015-side closure): per-iteration budget — ALL THREE limits checked
//! per tick (`max_tokens` via CostTrackerQuery, `max_cost_usd`, `max_wall_time_sec`),
//! and any breach feeds the fail-fast path via
//! `budget_breach_to_fail_fast_trigger`.
//!
//! Cross-module deferred (MODULE-015 §3.6): the every-tick scheduling cadence
//! (`dispatch_tick`, MODULE-014).

mod common;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use advance_git::{DefaultNamedCheckpoint, DefaultWorkspaceRollback};
use advance_scheduler_auto_loop::{
    budget_breach_to_fail_fast_trigger,
    config::{MetricSource, Objective, Op, Predicate, Role, SuccessCriteria},
    AutoLoopDriver, BudgetBreach, BudgetStatus, DefaultAutoLoopDriver, DefaultIterationCheckpoint,
    DefaultIterationRollback, FailFastOutcome, IterationResult, IterationStatus,
    PerIterationBudget, ResultsWriter,
};
use advance_shared_types::cost::RunCost;

use common::{
    bootstrap_repo_with_initial_commit, commit_file, MockCostTracker, NoopIterationCheckpoint,
    NoopIterationRollback,
};

fn criteria_all_three(
    max_tokens: Option<u64>,
    max_wall: Option<u64>,
    max_cost: Option<f64>,
) -> SuccessCriteria {
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
        per_iteration_budget: Some(PerIterationBudget {
            max_tokens,
            max_wall_time_sec: max_wall,
            max_cost_usd: max_cost,
        }),
        fail_fast: None,
        safety_valve: None,
    }
}

fn run_cost(tokens_in: u64, tokens_out: u64, cost_usd: f64) -> RunCost {
    RunCost {
        tokens_in,
        tokens_out,
        cost_usd,
        request_count: 1,
    }
}

fn driver_with_cost(cost: MockCostTracker) -> DefaultAutoLoopDriver {
    DefaultAutoLoopDriver::new(
        Arc::new(NoopIterationCheckpoint),
        Arc::new(NoopIterationRollback),
    )
    .with_cost_tracker(Arc::new(cost))
}

// MODULE-015-T23-slD.a — all 3 limits configured, only Tokens breached.
#[tokio::test]
async fn all_three_only_tokens_breached() {
    // tokens 60k > 50k; cost 0.0 < 0.10; wall 0 < 300.
    let cost = MockCostTracker::new().with_cost("run-a", 0, run_cost(60_000, 0, 0.0));
    let driver = driver_with_cost(cost);
    driver
        .start("a", criteria_all_three(Some(50_000), Some(300), Some(0.10)))
        .await
        .expect("start");
    let t0 = Instant::now();
    match driver.check_per_iteration_budget("a", "run-a", 0, t0, t0) {
        BudgetStatus::Breach(BudgetBreach::Tokens { .. }) => {}
        other => panic!("expected Tokens breach (only-tokens); got {other:?}"),
    }
}

// MODULE-015-T23-slD.b — all 3 configured, only Cost breached.
#[tokio::test]
async fn all_three_only_cost_breached() {
    // tokens 10 < 50k; cost 0.50 > 0.10; wall 0 < 300.
    let cost = MockCostTracker::new().with_cost("run-a", 0, run_cost(10, 0, 0.50));
    let driver = driver_with_cost(cost);
    driver
        .start("a", criteria_all_three(Some(50_000), Some(300), Some(0.10)))
        .await
        .expect("start");
    let t0 = Instant::now();
    match driver.check_per_iteration_budget("a", "run-a", 0, t0, t0) {
        BudgetStatus::Breach(BudgetBreach::Cost { .. }) => {}
        other => panic!("expected Cost breach (only-cost); got {other:?}"),
    }
}

// MODULE-015-T23-slD.c — all 3 configured, only WallTime breached.
#[tokio::test]
async fn all_three_only_walltime_breached() {
    // tokens 10 < 50k; cost 0.0 < 0.10; wall 320 > 300.
    let cost = MockCostTracker::new().with_cost("run-a", 0, run_cost(10, 0, 0.0));
    let driver = driver_with_cost(cost);
    driver
        .start("a", criteria_all_three(Some(50_000), Some(300), Some(0.10)))
        .await
        .expect("start");
    let t0 = Instant::now();
    let now = t0 + Duration::from_secs(320);
    match driver.check_per_iteration_budget("a", "run-a", 0, t0, now) {
        BudgetStatus::Breach(BudgetBreach::WallTime { .. }) => {}
        other => panic!("expected WallTime breach (only-walltime); got {other:?}"),
    }
}

// MODULE-015-T23-slD.d — bridge maps Tokens breach → fail-fast Trigger.
#[test]
fn bridge_tokens_breach_to_trigger() {
    let outcome = budget_breach_to_fail_fast_trigger(&BudgetBreach::Tokens {
        observed: 60_000,
        limit: 50_000,
    });
    match outcome {
        FailFastOutcome::Trigger { reason } => {
            assert!(reason.contains("fail-fast:"), "{reason}");
            assert!(reason.contains("per-iteration budget breach:"), "{reason}");
            assert!(reason.contains("tokens"), "{reason}");
            assert!(reason.contains("60000"), "{reason}");
            assert!(reason.contains("50000"), "{reason}");
        }
        FailFastOutcome::Pass => panic!("expected Trigger; got Pass"),
    }
}

// MODULE-015-T23-slD.e — bridge maps Cost breach → fail-fast Trigger.
#[test]
fn bridge_cost_breach_to_trigger() {
    let outcome = budget_breach_to_fail_fast_trigger(&BudgetBreach::Cost {
        observed_usd: 0.11,
        limit_usd: 0.10,
    });
    match outcome {
        FailFastOutcome::Trigger { reason } => {
            assert!(reason.contains("fail-fast:"), "{reason}");
            assert!(reason.contains("cost"), "{reason}");
            assert!(reason.contains("observed_usd=0.11"), "{reason}");
            // f64 Display of 0.10 → "0.1" (trailing-zero suppression).
            assert!(reason.contains("limit_usd=0.1"), "{reason}");
        }
        FailFastOutcome::Pass => panic!("expected Trigger; got Pass"),
    }
}

// MODULE-015-T23-slD.f — bridge maps WallTime breach → fail-fast Trigger.
#[test]
fn bridge_walltime_breach_to_trigger() {
    let outcome = budget_breach_to_fail_fast_trigger(&BudgetBreach::WallTime {
        observed_sec: 320,
        limit_sec: 300,
    });
    match outcome {
        FailFastOutcome::Trigger { reason } => {
            assert!(reason.contains("fail-fast:"), "{reason}");
            assert!(reason.contains("wall-time"), "{reason}");
            assert!(reason.contains("320"), "{reason}");
            assert!(reason.contains("300"), "{reason}");
        }
        FailFastOutcome::Pass => panic!("expected Trigger; got Pass"),
    }
}

// MODULE-015-T23-slD.g — end-to-end: driver Breach → bridge → Trigger →
// rollback → crash row written. The "any limit breach triggers iteration_end
// via fail-fast path" composition at the M015 surface.
#[tokio::test]
async fn breach_to_failfast_to_crash_row_composition() {
    let temp = tempfile::tempdir().unwrap();
    bootstrap_repo_with_initial_commit(temp.path());
    commit_file(temp.path(), "work.txt", b"baseline");

    let ckpt = DefaultNamedCheckpoint::new(temp.path().to_path_buf()).expect("ckpt");
    let rb = DefaultWorkspaceRollback::new(temp.path().to_path_buf()).expect("rb");
    let cost = MockCostTracker::new().with_cost("run-a", 1, run_cost(60_000, 0, 0.0));
    let driver = DefaultAutoLoopDriver::new(
        Arc::new(DefaultIterationCheckpoint::new(Arc::new(ckpt))),
        Arc::new(DefaultIterationRollback::new(Arc::new(rb))),
    )
    .with_cost_tracker(Arc::new(cost));
    driver
        .start(
            "root",
            criteria_all_three(Some(50_000), Some(300), Some(0.10)),
        )
        .await
        .expect("start");

    // Checkpoint iteration 1, mutate post-checkpoint.
    driver
        .checkpoint_iteration("root", 1)
        .await
        .expect("checkpoint");
    commit_file(temp.path(), "work.txt", b"mutated");

    // 1) Driver-level budget check observes the Tokens breach.
    let t0 = Instant::now();
    let status = driver.check_per_iteration_budget("root", "run-a", 1, t0, t0);
    let breach = match status {
        BudgetStatus::Breach(b) => b,
        BudgetStatus::Ok => panic!("expected a breach"),
    };

    // 2) Bridge the breach into a fail-fast Trigger.
    let outcome = budget_breach_to_fail_fast_trigger(&breach);
    let reason = match outcome {
        FailFastOutcome::Trigger { reason } => reason,
        FailFastOutcome::Pass => panic!("expected Trigger"),
    };
    assert!(reason.starts_with("fail-fast: per-iteration budget breach:"));

    // 3) Crash path: rollback iteration 1 → workspace restored to baseline.
    driver
        .rollback_iteration("root", 1)
        .await
        .expect("rollback");
    assert_eq!(
        std::fs::read(temp.path().join("work.txt")).unwrap(),
        b"baseline",
        "work.txt rolled back to baseline on crash path"
    );

    // 4) Crash row appended to results.jsonl.
    let writer = ResultsWriter::new(temp.path().to_path_buf());
    let crash_row = IterationResult {
        iter: 1,
        checkpoint: "auto-iter-1".to_string(),
        metric: BTreeMap::new(),
        status: IterationStatus::Crash,
        cost_usd: 0.0,
        wall_time_sec: 1,
        summary: Some(reason),
    };
    writer.append(&crash_row).await.expect("append crash row");
    let content = tokio::fs::read_to_string(writer.jsonl_path())
        .await
        .unwrap();
    let parsed: serde_json::Value = serde_json::from_str(content.lines().next().unwrap()).unwrap();
    assert_eq!(parsed["status"], "crash");
    assert_eq!(parsed["iter"], 1);
}

// MODULE-015-T23-slD.h — all 3 breached simultaneously → priority Tokens > Cost
// > WallTime observed at the driver orchestrator (matches check_budget order).
#[tokio::test]
async fn all_three_breached_priority_tokens_first() {
    // tokens 60k > 50k AND cost 0.50 > 0.10 AND wall 400 > 300.
    let cost = MockCostTracker::new().with_cost("run-a", 0, run_cost(60_000, 0, 0.50));
    let driver = driver_with_cost(cost);
    driver
        .start("a", criteria_all_three(Some(50_000), Some(300), Some(0.10)))
        .await
        .expect("start");
    let t0 = Instant::now();
    let now = t0 + Duration::from_secs(400);
    match driver.check_per_iteration_budget("a", "run-a", 0, t0, now) {
        BudgetStatus::Breach(BudgetBreach::Tokens { .. }) => {} // priority
        other => panic!("expected Tokens (priority) when all 3 breach; got {other:?}"),
    }
}

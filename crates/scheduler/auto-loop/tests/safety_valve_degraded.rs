//! MODULE-015-AC-24: Degraded-state entry + recovery + the safety-valve Halt
//! detector + non-finite cost-limit rejection (Stage-D).
//!
//! (a) N consecutive no-progress rounds → Degraded + reduced cadence (observable
//!     skip) + `auto.degraded` + degrade notification;
//! (b) M consecutive LLM errors → Degraded + exponential backoff;
//! (c) recovery Degraded→Active on progress, resetting counters;
//! plus the safety-valve Halted path (`auto.halted`) and admission-time
//! rejection of a non-finite cost limit (fail-CLOSED).

mod common;

use std::collections::BTreeMap;
use std::sync::Arc;

use advance_scheduler::{SchedulerExtension, SchedulerTick};
use advance_scheduler_auto_loop::{
    budget::PerIterationBudget,
    config::{MetricSource, Objective, Op, Predicate, Role, SafetyValve, SuccessCriteria},
    event_sink::event_type,
    AutoLoopDriver, AutoLoopError, AutoStateReader, AutoStatus, DefaultAutoLoopDriver,
    IterationCloseCtx,
};
use advance_shared_types::capability::BudgetDecision;

use common::{
    NoopIterationCheckpoint, NoopIterationRollback, RecordingIterationEventSink,
    RecordingNotifySink,
};

fn criteria(sv: Option<SafetyValve>) -> SuccessCriteria {
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
        per_iteration_budget: None,
        fail_fast: None,
        safety_valve: sv,
    }
}

fn close_ctx(agent: &str, iter: u32, primary: f64) -> IterationCloseCtx {
    let mut metrics = BTreeMap::new();
    metrics.insert("val_bpb".to_string(), primary);
    IterationCloseCtx {
        agent_id: agent.to_string(),
        run_id: Some(format!("run-{agent}")),
        iteration: iter,
        checkpoint_label: format!("auto-iter-{iter}"),
        primary_metric: Some(primary),
        metrics,
        crashed: false,
        crash_reason: None,
        summary: None,
        cost_usd: 0.0,
        wall_time_sec: 1,
    }
}

fn driver_with_sinks(
    sink: Arc<RecordingIterationEventSink>,
    notify: Arc<RecordingNotifySink>,
) -> DefaultAutoLoopDriver {
    DefaultAutoLoopDriver::new(
        Arc::new(NoopIterationCheckpoint),
        Arc::new(NoopIterationRollback),
    )
    .with_iteration_event_sink(sink)
    .with_notify_sink(notify)
}

// AC-24 (a): N consecutive no-progress rounds → Degraded + reduced cadence +
// auto.degraded + a degrade notification. Reduced cadence is OBSERVABLE: ticks
// within the backoff window are SKIPPED (cadence_skip grows); a tick past the
// window is NOT skipped (count unchanged).
#[tokio::test]
async fn ac24_no_progress_degrades_with_observable_reduced_cadence() {
    let sink = Arc::new(RecordingIterationEventSink::new());
    let notify = Arc::new(RecordingNotifySink::new());
    let driver = driver_with_sinks(sink.clone(), notify.clone());

    let sv = SafetyValve {
        consecutive_no_progress_limit: Some(2),
        ..Default::default()
    };
    driver.start("alice", criteria(Some(sv))).await.unwrap();

    // keep (baseline), then 2 non-improving discards → consecutive_no_progress=2.
    driver
        .close_iteration(close_ctx("alice", 1, 0.5))
        .await
        .unwrap();
    driver
        .close_iteration(close_ctx("alice", 2, 0.9))
        .await
        .unwrap();
    driver
        .close_iteration(close_ctx("alice", 3, 0.9))
        .await
        .unwrap();

    // Cadence tick at t=1000ms → no-progress detector fires → Degraded.
    driver.on_tick(SchedulerTick::new(1000)).await;
    assert_eq!(driver.status("alice").await, Some(AutoStatus::Degraded));
    assert!(sink.event_types().contains(&event_type::DEGRADED));
    let notes = notify.calls();
    assert_eq!(notes.len(), 1, "exactly one degrade notification");
    assert_eq!(notes[0].0, "alice");
    assert!(notes[0].1.contains("degraded"));

    // Backoff window opened (base default 60s = 60_000ms → until = 61_000).
    assert_eq!(driver.degraded_backoff_until_ms("alice"), Some(61_000));
    assert_eq!(driver.cadence_skip("alice"), Some(0));

    // Ticks WITHIN the window are skipped (reduced cadence) → cadence_skip grows.
    driver.on_tick(SchedulerTick::new(2000)).await;
    assert_eq!(driver.cadence_skip("alice"), Some(1));
    driver.on_tick(SchedulerTick::new(3000)).await;
    assert_eq!(driver.cadence_skip("alice"), Some(2));

    // A tick PAST the window is NOT skipped (work resumes) → count unchanged.
    driver.on_tick(SchedulerTick::new(70_000)).await;
    assert_eq!(
        driver.cadence_skip("alice"),
        Some(2),
        "past-window tick must not be skipped (proves throttle is window-bounded)"
    );
    // No duplicate degrade event from the within/past-window ticks.
    assert_eq!(
        sink.event_types()
            .iter()
            .filter(|e| **e == event_type::DEGRADED)
            .count(),
        1
    );
}

// AC-24 (b): M consecutive LLM errors → Degraded + exponential backoff
// (2^n * base, capped at max). Fed via the dedicated record_llm_error ingress
// (NOT ComponentEvent::Failed).
#[tokio::test]
async fn ac24_llm_errors_degrade_with_exponential_backoff() {
    let sink = Arc::new(RecordingIterationEventSink::new());
    let notify = Arc::new(RecordingNotifySink::new());
    let driver = driver_with_sinks(sink.clone(), notify.clone());

    let sv = SafetyValve {
        consecutive_llm_errors_limit: Some(2),
        llm_error_backoff_base_sec: Some(60),
        llm_error_backoff_max_sec: Some(3600),
        ..Default::default()
    };
    driver.start("alice", criteria(Some(sv))).await.unwrap();

    assert_eq!(driver.record_llm_error("alice"), 1);
    assert_eq!(driver.record_llm_error("alice"), 2);

    driver.on_tick(SchedulerTick::new(1000)).await;
    assert_eq!(driver.status("alice").await, Some(AutoStatus::Degraded));
    assert!(sink.event_types().contains(&event_type::DEGRADED));
    // n = 2 → delay = 60s*2^2 = 240s = 240_000ms → until = 1000 + 240_000.
    assert_eq!(driver.degraded_backoff_until_ms("alice"), Some(241_000));
}

// AC-24 (c): recovery — record_progress flips Degraded→Active, resets the
// llm-error counter, and clears the backoff throttle.
#[tokio::test]
async fn ac24_recovery_resets_to_active() {
    let sink = Arc::new(RecordingIterationEventSink::new());
    let notify = Arc::new(RecordingNotifySink::new());
    let driver = driver_with_sinks(sink, notify);

    let sv = SafetyValve {
        consecutive_llm_errors_limit: Some(1),
        ..Default::default()
    };
    driver.start("alice", criteria(Some(sv))).await.unwrap();
    driver.record_llm_error("alice");
    driver.on_tick(SchedulerTick::new(1000)).await;
    assert_eq!(driver.status("alice").await, Some(AutoStatus::Degraded));

    // Recovery.
    let after = driver.record_progress("alice");
    assert_eq!(after, Some(AutoStatus::Active));
    assert_eq!(driver.status("alice").await, Some(AutoStatus::Active));
    assert_eq!(driver.degraded_backoff_until_ms("alice"), None);
    // A subsequent llm error starts the streak fresh from 1 (counter reset).
    assert_eq!(driver.record_llm_error("alice"), 1);
}

// Safety valve → Halted + auto.halted (product code for SYS-AC-258; harvest
// verifies e2e — this satellite flips ZERO SYS-AC).
#[tokio::test]
async fn safety_valve_halts_on_max_iterations() {
    let sink = Arc::new(RecordingIterationEventSink::new());
    let notify = Arc::new(RecordingNotifySink::new());
    let driver = driver_with_sinks(sink.clone(), notify.clone());

    let sv = SafetyValve {
        max_iterations: Some(1),
        ..Default::default()
    };
    driver.start("alice", criteria(Some(sv))).await.unwrap();
    // close iter 1 → AutoState.iteration = 1.
    driver
        .close_iteration(close_ctx("alice", 1, 0.5))
        .await
        .unwrap();

    driver.on_tick(SchedulerTick::new(1000)).await;
    assert_eq!(driver.status("alice").await, Some(AutoStatus::Halted));
    assert!(sink.event_types().contains(&event_type::HALTED));
    assert_eq!(notify.calls().len(), 1);
    assert!(notify.calls()[0].1.contains("halted"));
}

// Audit-r7 W2: a hard safety-valve breach Halts even while the session is
// Degraded INSIDE its reduced-cadence throttle window (the throttle must never
// delay a hard stop).
#[tokio::test]
async fn safety_valve_halts_even_while_degraded_and_throttled() {
    let sink = Arc::new(RecordingIterationEventSink::new());
    let notify = Arc::new(RecordingNotifySink::new());
    let driver = driver_with_sinks(sink.clone(), notify);

    let sv = SafetyValve {
        consecutive_llm_errors_limit: Some(1),
        max_cost_usd: Some(1.0),
        ..Default::default()
    };
    driver.start("alice", criteria(Some(sv))).await.unwrap();

    // Enter Degraded via an LLM error (cost still 0 < cap, so no halt yet).
    driver.record_llm_error("alice");
    driver.on_tick(SchedulerTick::new(1000)).await;
    assert_eq!(driver.status("alice").await, Some(AutoStatus::Degraded));
    let until = driver.degraded_backoff_until_ms("alice").unwrap();

    // Now push cumulative cost over the cap via a close (total 5.0 > 1.0).
    driver
        .close_iteration(close_ctx("alice", 1, 0.5))
        .await
        .unwrap();
    // close_ctx has cost 0.0; do an explicit over-cost close:
    let mut over = close_ctx("alice", 2, 0.4);
    over.cost_usd = 5.0;
    driver.close_iteration(over).await.unwrap();

    // A tick STILL inside the throttle window must HALT (not skip) — safety valve first.
    let inside = until - 1;
    driver.on_tick(SchedulerTick::new(inside)).await;
    assert_eq!(
        driver.status("alice").await,
        Some(AutoStatus::Halted),
        "hard cost breach must Halt even while throttled"
    );
    assert!(sink.event_types().contains(&event_type::HALTED));
}

// Audit-r7 W3: a negative (or non-finite) close cost is IGNORED — it can never
// LOWER total_cost_usd back under the safety-valve cost cap (fail-CLOSED).
#[tokio::test]
async fn negative_close_cost_does_not_lower_total() {
    let sv = SafetyValve {
        max_cost_usd: Some(10.0),
        ..Default::default()
    };
    let driver = DefaultAutoLoopDriver::new(
        Arc::new(NoopIterationCheckpoint),
        Arc::new(NoopIterationRollback),
    );
    driver.start("alice", criteria(Some(sv))).await.unwrap();

    let mut c1 = close_ctx("alice", 1, 0.5);
    c1.cost_usd = 8.0;
    driver.close_iteration(c1).await.unwrap();
    let mut c2 = close_ctx("alice", 2, 0.4);
    c2.cost_usd = 8.0; // total now 16.0 > cap 10.0
    driver.close_iteration(c2).await.unwrap();
    // fallback budget_decision (no RunBudgetSource) Denies on the cost breach.
    assert!(matches!(
        driver.budget_decision("run-a", "alice"),
        BudgetDecision::Deny(_)
    ));

    // A negative-cost close must NOT lower the accumulated total back under the cap.
    let mut neg = close_ctx("alice", 3, 0.3);
    neg.cost_usd = -100.0;
    driver.close_iteration(neg).await.unwrap();
    assert!(
        matches!(
            driver.budget_decision("run-a", "alice"),
            BudgetDecision::Deny(_)
        ),
        "negative close cost must not slip the run back under the cost cap"
    );
}

// Non-finite cost limits are rejected at admission (start → validate),
// fail-CLOSED — a NaN/Inf limit must not silently disable the cost cap.
#[tokio::test]
async fn nonfinite_cost_limit_rejected_at_start() {
    let driver = DefaultAutoLoopDriver::new(
        Arc::new(NoopIterationCheckpoint),
        Arc::new(NoopIterationRollback),
    );

    // safety_valve.max_cost_usd = NaN.
    let sv_nan = SafetyValve {
        max_cost_usd: Some(f64::NAN),
        ..Default::default()
    };
    let err = driver.start("a", criteria(Some(sv_nan))).await.unwrap_err();
    assert!(matches!(
        err,
        AutoLoopError::NonFiniteCostLimit("safety_valve.max_cost_usd")
    ));

    // per_iteration_budget.max_cost_usd = +Inf.
    let mut c = criteria(None);
    c.per_iteration_budget = Some(PerIterationBudget {
        max_tokens: None,
        max_wall_time_sec: None,
        max_cost_usd: Some(f64::INFINITY),
    });
    let err = driver.start("b", c).await.unwrap_err();
    assert!(matches!(
        err,
        AutoLoopError::NonFiniteCostLimit("per_iteration_budget.max_cost_usd")
    ));
}

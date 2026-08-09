//! Stage-D `impl AutoStateReader for DefaultAutoLoopDriver` (the deferred
//! slice-C bridge): run_id↔agent_id mapping, last_iteration_status slot, and
//! the fail-CLOSED budget_decision — plus the end-to-end proof that the driver
//! is now constructible as the `AutoLoopRoundAdvancer`'s reader.

mod common;

use std::collections::BTreeMap;
use std::sync::Arc;

use advance_scheduler_auto_loop::{
    config::{MetricSource, Objective, Op, Predicate, Role, SafetyValve, SuccessCriteria},
    AutoLoopDriver, AutoLoopRoundAdvancer, AutoStateReader, DefaultAutoLoopDriver,
    IterationCloseCtx, IterationStatus,
};
use advance_shared_types::capability::BudgetDecision;
use advance_shared_types::run::{RoundAdvancer, RoundDecision, RoundResult};

use common::{MockRunBudgetSource, NoopIterationCheckpoint, NoopIterationRollback};

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

fn keep_ctx(agent: &str, iter: u32, m: f64) -> IterationCloseCtx {
    let mut metrics = BTreeMap::new();
    metrics.insert("val_bpb".to_string(), m);
    IterationCloseCtx {
        agent_id: agent.to_string(),
        run_id: Some(format!("run-{agent}")),
        iteration: iter,
        checkpoint_label: format!("auto-iter-{iter}"),
        primary_metric: Some(m),
        metrics,
        crashed: false,
        crash_reason: None,
        summary: None,
        cost_usd: 0.0,
        wall_time_sec: 1,
    }
}

fn noop_driver() -> DefaultAutoLoopDriver {
    DefaultAutoLoopDriver::new(
        Arc::new(NoopIterationCheckpoint),
        Arc::new(NoopIterationRollback),
    )
}

#[tokio::test]
async fn reader_maps_run_to_agent_and_unknown_is_none() {
    let driver = noop_driver();
    driver.register_run("run-a", "alice").unwrap();
    driver.register_run("run-b", "bob").unwrap();
    assert_eq!(driver.agent_id_for_run("run-a").as_deref(), Some("alice"));
    assert_eq!(driver.agent_id_for_run("run-b").as_deref(), Some("bob"));
    assert_eq!(driver.agent_id_for_run("run-ghost"), None);
}

#[tokio::test]
async fn reader_last_iteration_status_set_by_close() {
    let driver = noop_driver();
    driver.start("alice", criteria(None)).await.unwrap();
    assert_eq!(driver.last_iteration_status("alice"), None);
    driver
        .close_iteration(keep_ctx("alice", 1, 0.5))
        .await
        .unwrap();
    assert_eq!(
        driver.last_iteration_status("alice"),
        Some(IterationStatus::Keep)
    );
    assert_eq!(driver.last_iteration_status("ghost"), None);
}

#[tokio::test]
async fn budget_decision_run_budget_source_wins() {
    let driver = noop_driver().with_run_budget_source(Arc::new(MockRunBudgetSource::deny("nope")));
    driver.start("alice", criteria(None)).await.unwrap();
    match driver.budget_decision("run-a", "alice") {
        BudgetDecision::Deny(r) => assert_eq!(r, "nope"),
        other => panic!("expected Deny, got {other:?}"),
    }
}

#[tokio::test]
async fn budget_decision_fallback_allows_within_limits() {
    let driver = noop_driver(); // no RunBudgetSource
    driver.start("alice", criteria(None)).await.unwrap();
    assert_eq!(
        driver.budget_decision("run-a", "alice"),
        BudgetDecision::Allow,
        "live session within default safety-valve limits → Allow"
    );
}

#[tokio::test]
async fn budget_decision_fallback_denies_unknown_session() {
    let driver = noop_driver(); // no RunBudgetSource, no session
    match driver.budget_decision("run-x", "ghost") {
        BudgetDecision::Deny(_) => {}
        other => panic!("unknown session must fail-CLOSED to Deny, got {other:?}"),
    }
}

#[tokio::test]
async fn budget_decision_fallback_denies_over_iteration_cap() {
    let sv = SafetyValve {
        max_iterations: Some(1),
        ..Default::default()
    };
    let driver = noop_driver();
    driver.start("alice", criteria(Some(sv))).await.unwrap();
    // close iter 1 → AutoState.iteration = 1 >= max_iterations(1).
    driver
        .close_iteration(keep_ctx("alice", 1, 0.5))
        .await
        .unwrap();
    match driver.budget_decision("run-a", "alice") {
        BudgetDecision::Deny(r) => assert!(r.contains("max_iterations")),
        other => panic!("over-cap must Deny, got {other:?}"),
    }
}

// Audit-r7 W1: stop() purges the run_id→agent_id mapping (and state) so no
// stale mapping survives a restart and the auxiliary maps cannot grow unbounded.
#[tokio::test]
async fn stop_purges_run_mapping_and_state() {
    let driver = noop_driver();
    driver.start("alice", criteria(None)).await.unwrap();
    driver.register_run("auto:alice:run-1", "alice").unwrap();
    driver.register_component("comp-1", "alice").unwrap();
    assert_eq!(
        driver.agent_id_for_run("auto:alice:run-1").as_deref(),
        Some("alice")
    );
    assert_eq!(
        driver.agent_for_component("comp-1").as_deref(),
        Some("alice")
    );

    driver.stop("alice").await.unwrap();

    assert_eq!(driver.status("alice").await, None, "state purged");
    assert_eq!(
        driver.agent_id_for_run("auto:alice:run-1"),
        None,
        "run mapping purged"
    );
    assert_eq!(
        driver.agent_for_component("comp-1"),
        None,
        "component mapping purged"
    );
}

// End-to-end: the driver is now constructible as the AutoLoopRoundAdvancer's
// reader (the slice-C deferred goal). Normal path → ContinueAllowed.
#[tokio::test]
async fn driver_is_constructible_as_round_advancer_reader() {
    let driver = Arc::new(noop_driver());
    driver.start("alice", criteria(None)).await.unwrap();
    driver.register_run("run-a", "alice").unwrap();

    let reader: Arc<dyn AutoStateReader> = driver.clone();
    let advancer = AutoLoopRoundAdvancer::new(reader);

    let decision = advancer
        .on_complete_round(
            "run-a",
            RoundResult {
                summary: None,
                metrics: Vec::new(),
            },
        )
        .await
        .expect("normal round-advance");
    assert_eq!(decision, RoundDecision::ContinueAllowed);
}

// End-to-end: a complete-cycle request makes the advancer compose the terminal
// Blocked("completed: ...") decision via the driver-as-reader.
#[tokio::test]
async fn round_advancer_complete_cycle_via_driver_reader() {
    use advance_scheduler_auto_loop::CompletionSummary;
    let driver = Arc::new(noop_driver());
    driver.start("alice", criteria(None)).await.unwrap();
    driver.register_run("run-a", "alice").unwrap();
    // record a complete-cycle request + a last_iteration_status (via a keep close).
    driver
        .close_iteration(keep_ctx("alice", 1, 0.5))
        .await
        .unwrap();
    driver
        .record_complete_cycle_request(
            "alice",
            CompletionSummary {
                outcome: "research-converged".to_string(),
                final_metrics: Vec::new(),
            },
        )
        .unwrap();

    let reader: Arc<dyn AutoStateReader> = driver.clone();
    let advancer = AutoLoopRoundAdvancer::new(reader);
    let decision = advancer
        .on_complete_round(
            "run-a",
            RoundResult {
                summary: None,
                metrics: Vec::new(),
            },
        )
        .await
        .unwrap();
    match decision {
        RoundDecision::Blocked(s) => {
            assert!(s.starts_with("completed: research-converged"), "got: {s}");
            assert!(s.contains("final_status: keep"));
        }
        other => panic!("expected Blocked(completed:...), got {other:?}"),
    }
}

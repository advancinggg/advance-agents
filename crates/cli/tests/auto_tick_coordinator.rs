//! SLICE 1 — auto-mode terminal-settle coordinator (`AutoTickCoordinator`).
//!
//! PRODUCT-UNIT/INTEGRATION witnesses for the cli coordinator that bridges the auto
//! advancer's terminal decision (which `RunManager::complete_round` discards) to the
//! REAL `RunManager` settle methods. These flip **ZERO SYS-AC** and verify **ZERO new
//! MODULE AC** — the SYS-AC-183/185 e2e witnesses (`sys_j59_auto_complete.rs`, real
//! wired daemon) stay `#[ignore]`d until the harvest. Here a REAL `RunManager` + REAL
//! `DefaultAutoLoopDriver` are driven through the PRODUCT coordinator: the test NEVER
//! calls `complete_run`/`cancel_run_for_agent`/`transition_status` itself — the
//! coordinator does — and asserts the resulting `TaskRunStatus` + `run.completed` /
//! `run.cancelled` bus events (the witness-floor for 183/185).

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use advance_cli::crash_coordinator::{
    run_guarded_iteration, AutoTickCoordinator, AutoTickError, GuardedIterationInputs,
    TerminalSettle,
};
use advance_run_manager::{RunConfig, RunManager};
use advance_scheduler_auto_loop::config::{
    MetricSource, Objective, Op, Predicate, Role, SuccessCriteria,
};
use advance_scheduler_auto_loop::{
    AutoLoopDriver, AutoLoopError, AutoStatus, CompletionSummary, ComponentMetricReader,
    DefaultAutoLoopDriver, IterationCheckpoint, IterationRollback, MetricReadError,
};
use advance_shared_types::event::Event;
use advance_shared_types::run::TaskRunStatus;
use advance_shared_types::traits::EventBusEmit;
use async_trait::async_trait;

// ── doubles ──────────────────────────────────────────────────────────────────

#[derive(Default)]
struct MockBus {
    events: Mutex<Vec<Event>>,
}
impl MockBus {
    fn count(&self, ty: &str) -> usize {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.event_type == ty)
            .count()
    }
}
impl EventBusEmit for MockBus {
    fn emit(&self, event: Event) {
        self.events.lock().unwrap().push(event);
    }
}

struct NoopCkpt;
#[async_trait]
impl IterationCheckpoint for NoopCkpt {
    async fn checkpoint_baseline(&self, _agent_id: &str) -> Result<(), AutoLoopError> {
        Ok(())
    }
    async fn checkpoint_iteration(&self, _agent_id: &str, _n: u32) -> Result<(), AutoLoopError> {
        Ok(())
    }
}
struct NoopRb;
#[async_trait]
impl IterationRollback for NoopRb {
    async fn rollback_iteration(&self, _agent_id: &str, _n: u32) -> Result<(), AutoLoopError> {
        Ok(())
    }
}

/// A guardrail metric reader that is never consulted (the criteria has no
/// `Role::Guardrail` objective) — returns an error to make any accidental call loud.
struct UnusedReader;
impl ComponentMetricReader for UnusedReader {
    fn read_component_metric(&self, output_key: &str) -> Result<f64, MetricReadError> {
        Err(MetricReadError::NotFound(format!(
            "UnusedReader must not be called (output_key={output_key})"
        )))
    }
}

// ── helpers ──────────────────────────────────────────────────────────────────

/// Primary-only criteria (no guardrail → `UnusedReader` never called; no
/// per-iteration budget → no breach). First-iteration `primary_metric: Some(_)` keeps.
fn primary_only_criteria() -> SuccessCriteria {
    SuccessCriteria {
        evaluator: None,
        objectives: vec![Objective {
            name: "val-bpb".to_string(),
            role: Role::Primary,
            metric_source: MetricSource::File {
                path: "m.json".to_string(),
                key: "v".to_string(),
            },
            predicate: Predicate {
                op: Op::Lt,
                threshold: None,
            },
        }],
        per_iteration_budget: None,
        fail_fast: None,
        safety_valve: None,
    }
}

fn keep_inputs(agent_id: &str, run_id: &str) -> GuardedIterationInputs {
    GuardedIterationInputs {
        agent_id: agent_id.to_string(),
        run_id: run_id.to_string(),
        iteration: 1,
        checkpoint_label: "auto-iter-1".to_string(),
        primary_metric: Some(0.5), // first iteration + finite → Keep
        metrics: BTreeMap::new(),
        cost_usd: 0.0,
        wall_time_sec: 0,
        summary: None,
        started_at: Instant::now(),
        now: Instant::now(),
    }
}

fn completion_summary(outcome: &str) -> CompletionSummary {
    CompletionSummary {
        outcome: outcome.to_string(),
        final_metrics: vec![],
    }
}

/// Build (recording bus, RunManager, driver, coordinator) sharing the same driver Arc.
fn setup() -> (
    Arc<MockBus>,
    Arc<RunManager>,
    Arc<DefaultAutoLoopDriver>,
    AutoTickCoordinator,
) {
    let bus = Arc::new(MockBus::default());
    let mgr = Arc::new(RunManager::new(Arc::clone(&bus) as Arc<dyn EventBusEmit>));
    let driver = Arc::new(DefaultAutoLoopDriver::new(
        Arc::new(NoopCkpt),
        Arc::new(NoopRb),
    ));
    let coord = AutoTickCoordinator::new(Arc::clone(&driver), Arc::clone(&mgr));
    (bus, mgr, driver, coord)
}

// ── T-ATC-1 — complete-cycle settle → run.completed + driver Completed (183) ─────
#[tokio::test]
async fn complete_cycle_settles_run_completed_and_driver_completed() {
    let (bus, mgr, driver, coord) = setup();
    // Mint a REAL auto Run; CAPTURE its minted RunId (run-{uuid}, colon-free).
    let rid = mgr
        .ensure_run("auto:agent", "agent", RunConfig::default())
        .unwrap();
    driver
        .start("agent", primary_only_criteria())
        .await
        .unwrap();
    // The agent records a complete-cycle request (out-of-band, during its turn).
    driver
        .record_complete_cycle_request("agent", completion_summary("research-converged"))
        .unwrap();

    // run_iteration does the keep-close (sets last_iteration_status) THEN settle.
    let (_close, settle) = coord
        .run_iteration(
            &primary_only_criteria(),
            &UnusedReader,
            keep_inputs("agent", rid.as_ref()),
        )
        .await
        .expect("run_iteration ok");

    assert_eq!(settle, TerminalSettle::Completed);
    // Driver AutoState terminated (loop stops).
    assert_eq!(driver.status("agent").await, Some(AutoStatus::Completed));
    // RunManager Run flipped Active → Completed.
    assert!(matches!(
        mgr.run_status(&rid).unwrap().status,
        TaskRunStatus::Completed
    ));
    // run.completed fired exactly once (183 observable) — the coordinator emitted it,
    // NOT the test.
    assert_eq!(bus.count("run.completed"), 1, "run.completed once");
    assert_eq!(
        bus.count("run.round_completed"),
        0,
        "auto stays buffer-only"
    );
}

// ── T-ATC-2 — manual cancel settle → run.cancelled + driver Cancelled (185) ──────
#[tokio::test]
async fn manual_cancel_settles_run_cancelled_and_driver_cancelled() {
    let (bus, mgr, driver, coord) = setup();
    let rid = mgr
        .ensure_run("auto:agent", "agent", RunConfig::default())
        .unwrap();
    driver
        .start("agent", primary_only_criteria())
        .await
        .unwrap();

    coord.cancel("agent", "ops-cancel").expect("cancel ok");

    assert_eq!(driver.status("agent").await, Some(AutoStatus::Cancelled));
    assert!(matches!(
        mgr.run_status(&rid).unwrap().status,
        TaskRunStatus::Cancelled(_)
    ));
    assert_eq!(bus.count("run.cancelled"), 1, "run.cancelled once");
    assert_eq!(bus.count("run.completed"), 0);
}

// ── T-ATC-3 — no complete-cycle request → Continued (settle no-op) ───────────────
#[tokio::test]
async fn no_complete_cycle_request_continues() {
    let (bus, mgr, driver, coord) = setup();
    let rid = mgr
        .ensure_run("auto:agent", "agent", RunConfig::default())
        .unwrap();
    driver
        .start("agent", primary_only_criteria())
        .await
        .unwrap();

    let (_close, settle) = coord
        .run_iteration(
            &primary_only_criteria(),
            &UnusedReader,
            keep_inputs("agent", rid.as_ref()),
        )
        .await
        .expect("run_iteration ok");

    assert_eq!(settle, TerminalSettle::Continued);
    assert_eq!(driver.status("agent").await, Some(AutoStatus::Active));
    assert!(matches!(
        mgr.run_status(&rid).unwrap().status,
        TaskRunStatus::Active
    ));
    assert_eq!(bus.count("run.completed"), 0);
}

// ── T-ATC-4 — complete-cycle but no last_iteration_status → fail-CLOSED, nothing settled
#[tokio::test]
async fn complete_cycle_without_last_status_fails_closed() {
    let (bus, mgr, driver, coord) = setup();
    let rid = mgr
        .ensure_run("auto:agent", "agent", RunConfig::default())
        .unwrap();
    driver
        .start("agent", primary_only_criteria())
        .await
        .unwrap();
    // Record the request but run NO iteration close → last_iteration_status stays None.
    driver
        .record_complete_cycle_request("agent", completion_summary("x"))
        .unwrap();

    let err = coord
        .settle_completed("agent", rid.as_ref())
        .await
        .expect_err("must fail-CLOSED on missing last_iteration_status");
    assert!(matches!(err, AutoTickError::BadInput(_)));
    // Nothing settled: Run stays Active, driver stays Active.
    assert!(matches!(
        mgr.run_status(&rid).unwrap().status,
        TaskRunStatus::Active
    ));
    assert_eq!(driver.status("agent").await, Some(AutoStatus::Active));
    assert_eq!(bus.count("run.completed"), 0);
}

// ── T-ATC-5 — idempotent cancel (already-terminal driver + Run) ──────────────────
#[tokio::test]
async fn cancel_is_idempotent_on_already_terminal() {
    let (bus, mgr, driver, coord) = setup();
    let rid = mgr
        .ensure_run("auto:agent", "agent", RunConfig::default())
        .unwrap();
    driver
        .start("agent", primary_only_criteria())
        .await
        .unwrap();

    coord.cancel("agent", "first").expect("first cancel ok");
    // Second cancel: driver already Cancelled (TerminalState idempotent) + Run terminal
    // (cancel_run_for_agent 0-live → Ok no-op).
    coord
        .cancel("agent", "second")
        .expect("second cancel idempotent ok");

    assert_eq!(driver.status("agent").await, Some(AutoStatus::Cancelled));
    assert!(matches!(
        mgr.run_status(&rid).unwrap().status,
        TaskRunStatus::Cancelled(_)
    ));
    // Exactly one run.cancelled (the second is a no-op, no re-emit).
    assert_eq!(bus.count("run.cancelled"), 1);
}

// ── T-ATC-6 — complete-cycle while Degraded → Err (IllegalTransition), nothing settled
#[tokio::test]
async fn complete_cycle_while_degraded_fails_closed_no_half_settle() {
    let (bus, mgr, driver, coord) = setup();
    let rid = mgr
        .ensure_run("auto:agent", "agent", RunConfig::default())
        .unwrap();
    driver
        .start("agent", primary_only_criteria())
        .await
        .unwrap();
    // Drive the driver Active → Degraded (3 consecutive LLM errors ≥ default limit 3).
    driver.record_llm_error("agent");
    driver.record_llm_error("agent");
    driver.record_llm_error("agent");
    driver.run_cadence_pass(1_000).await;
    assert_eq!(driver.status("agent").await, Some(AutoStatus::Degraded));

    // Set last_iteration_status (a close is allowed from Degraded) + the request.
    run_guarded_iteration(
        &driver,
        &primary_only_criteria(),
        &UnusedReader,
        keep_inputs("agent", rid.as_ref()),
    )
    .await
    .expect("degraded close ok");
    driver
        .record_complete_cycle_request("agent", completion_summary("y"))
        .unwrap();

    let err = coord
        .settle_completed("agent", rid.as_ref())
        .await
        .expect_err("CompleteCycle is Active-only → Degraded must fail-CLOSED");
    assert!(matches!(err, AutoTickError::Driver(_)));
    // Driver-first ordering means the Run was NEVER settled (no half-state).
    assert!(matches!(
        mgr.run_status(&rid).unwrap().status,
        TaskRunStatus::Active
    ));
    assert_eq!(driver.status("agent").await, Some(AutoStatus::Degraded));
    assert_eq!(
        bus.count("run.completed"),
        0,
        "no run.completed on fail-CLOSED"
    );
}

// ── T-ATC-7 — Run moved off Active independently → pre-check refuses, no half-settle
// The INVERSE of T-ATC-6 (audit r1 W1): the driver is Active but the RUN was moved off
// Active by an independent path. The Run-Active pre-check refuses BEFORE the irreversible
// driver transition, so there is NO driver-terminal / Run-unsettled half-state.
#[tokio::test]
async fn complete_cycle_when_run_left_active_refuses_before_driver_touch() {
    let (bus, mgr, driver, coord) = setup();
    let rid = mgr
        .ensure_run("auto:agent", "agent", RunConfig::default())
        .unwrap();
    driver
        .start("agent", primary_only_criteria())
        .await
        .unwrap();
    // Set last_iteration_status (keep close) + the complete-cycle request.
    run_guarded_iteration(
        &driver,
        &primary_only_criteria(),
        &UnusedReader,
        keep_inputs("agent", rid.as_ref()),
    )
    .await
    .expect("keep close ok");
    driver
        .record_complete_cycle_request("agent", completion_summary("z"))
        .unwrap();
    // Independently move the Run off Active (a real terminal flip via fail_run — stands in
    // for an operator pause / await-suspend that the decoupled Run state machine allows).
    mgr.fail_run(&rid, "external-failure".to_string()).unwrap();

    let err = coord
        .settle_completed("agent", rid.as_ref())
        .await
        .expect_err("Run not Active → pre-check refuses");
    assert!(matches!(err, AutoTickError::BadInput(_)));
    // Driver NOT transitioned (pre-check bailed before the irreversible flip).
    assert_eq!(driver.status("agent").await, Some(AutoStatus::Active));
    // Run unchanged (still Failed from the external flip), no spurious run.completed.
    assert!(matches!(
        mgr.run_status(&rid).unwrap().status,
        TaskRunStatus::Failed(_)
    ));
    assert_eq!(bus.count("run.completed"), 0);
}

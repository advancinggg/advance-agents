//! T-ATE — production tick caller (`AutoTickExtension`) for the auto-mode
//! terminal-settle coordinator (Wave-7 Lane B, 2026-06-22).
//!
//! PRODUCT-UNIT witnesses that the cli `SchedulerExtension` drives the
//! `AutoTickCoordinator`'s settle/cancel on each production tick (`on_tick`), and
//! that the driver's degrade cadence pass runs inside `on_tick`. These flip
//! **ZERO SYS-AC** and verify **ZERO new MODULE AC** — they are unit tests of the
//! tick caller, NOT the wired-daemon e2e (the SYS-AC-183/185 witnesses on a real
//! daemon stay `#[ignore]`d until the harvest). The TEST NEVER calls
//! `complete_run` / `cancel_run_for_agent` / `settle_completed` itself — the
//! EXTENSION's `on_tick` → the coordinator does — and asserts the resulting
//! `TaskRunStatus` + `run.completed`/`run.cancelled` bus events.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use advance_cli::auto_tick_extension::AutoTickExtension;
use advance_cli::crash_coordinator::{
    run_guarded_iteration, AutoTickCoordinator, GuardedIterationInputs,
};
use advance_run_manager::{RunConfig, RunManager};
use advance_scheduler::{SchedulerExtension, SchedulerTick};
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

// ── doubles (mirroring auto_tick_coordinator.rs) ───────────────────────────────

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

/// Guardrail reader never consulted (criteria has no `Role::Guardrail`); errors
/// loudly if accidentally called.
struct UnusedReader;
impl ComponentMetricReader for UnusedReader {
    fn read_component_metric(&self, output_key: &str) -> Result<f64, MetricReadError> {
        Err(MetricReadError::NotFound(format!(
            "UnusedReader must not be called (output_key={output_key})"
        )))
    }
}

// ── helpers ────────────────────────────────────────────────────────────────────

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
        primary_metric: Some(0.5),
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

/// (recording bus, RunManager, driver, EXTENSION) — coordinator owns the SAME
/// driver + run_manager; the extension owns the SAME driver + the coordinator.
fn setup_ext() -> (
    Arc<MockBus>,
    Arc<RunManager>,
    Arc<DefaultAutoLoopDriver>,
    Arc<AutoTickExtension>,
) {
    let bus = Arc::new(MockBus::default());
    let mgr = Arc::new(RunManager::new(Arc::clone(&bus) as Arc<dyn EventBusEmit>));
    let driver = Arc::new(DefaultAutoLoopDriver::new(
        Arc::new(NoopCkpt),
        Arc::new(NoopRb),
    ));
    let coord = Arc::new(AutoTickCoordinator::new(
        Arc::clone(&driver),
        Arc::clone(&mgr),
    ));
    let ext = Arc::new(AutoTickExtension::new(Arc::clone(&driver), coord));
    (bus, mgr, driver, ext)
}

// ── T-ATE-1 — complete-cycle: the TICK settles the run Completed (183) ───────────
#[tokio::test]
async fn tick_settles_completed_run_via_extension() {
    let (bus, mgr, driver, ext) = setup_ext();
    let rid = mgr
        .ensure_run("auto:agent", "agent", RunConfig::default())
        .unwrap();
    driver
        .start("agent", primary_only_criteria())
        .await
        .unwrap();
    // Agent records a complete-cycle, then the product per-iteration close runs
    // (sets last_iteration_status; does NOT settle the run).
    driver
        .record_complete_cycle_request("agent", completion_summary("research-converged"))
        .unwrap();
    run_guarded_iteration(
        &driver,
        &primary_only_criteria(),
        &UnusedReader,
        keep_inputs("agent", rid.as_ref()),
    )
    .await
    .expect("keep close ok");
    ext.register_session("agent", rid.as_ref());
    assert_eq!(ext.session_count(), 1);

    // Drive the PRODUCTION tick entry — the extension settles via the coordinator.
    ext.on_tick(SchedulerTick::new(1_000)).await;

    // The TEST never called complete_run / settle_completed — the tick did.
    assert!(matches!(
        mgr.run_status(&rid).unwrap().status,
        TaskRunStatus::Completed
    ));
    assert_eq!(driver.status("agent").await, Some(AutoStatus::Completed));
    assert_eq!(
        bus.count("run.completed"),
        1,
        "run.completed once, by the tick"
    );
    assert_eq!(
        bus.count("run.round_completed"),
        0,
        "auto stays buffer-only"
    );
    // Terminal → deregistered (no re-poll of the never-cleared complete_cycle PEEK).
    assert_eq!(ext.session_count(), 0, "completed session deregistered");
}

// ── T-ATE-2 — request_cancel: the TICK settles the run Cancelled (185) ───────────
#[tokio::test]
async fn tick_settles_cancelled_run_via_request_cancel() {
    let (bus, mgr, driver, ext) = setup_ext();
    let rid = mgr
        .ensure_run("auto:agent", "agent", RunConfig::default())
        .unwrap();
    driver
        .start("agent", primary_only_criteria())
        .await
        .unwrap();
    ext.register_session("agent", rid.as_ref());
    ext.request_cancel("agent", "ops-cancel");

    ext.on_tick(SchedulerTick::new(1_000)).await;

    assert_eq!(driver.status("agent").await, Some(AutoStatus::Cancelled));
    assert!(matches!(
        mgr.run_status(&rid).unwrap().status,
        TaskRunStatus::Cancelled(_)
    ));
    assert_eq!(
        bus.count("run.cancelled"),
        1,
        "run.cancelled once, by the tick"
    );
    assert_eq!(bus.count("run.completed"), 0);
    assert_eq!(ext.session_count(), 0, "cancelled session deregistered");
}

// ── T-ATE-3 — no request: the tick is a settle no-op, session stays registered ───
#[tokio::test]
async fn tick_no_request_keeps_run_active_and_registered() {
    let (bus, mgr, driver, ext) = setup_ext();
    let rid = mgr
        .ensure_run("auto:agent", "agent", RunConfig::default())
        .unwrap();
    driver
        .start("agent", primary_only_criteria())
        .await
        .unwrap();
    run_guarded_iteration(
        &driver,
        &primary_only_criteria(),
        &UnusedReader,
        keep_inputs("agent", rid.as_ref()),
    )
    .await
    .expect("keep close ok");
    ext.register_session("agent", rid.as_ref());

    ext.on_tick(SchedulerTick::new(1_000)).await;

    assert!(matches!(
        mgr.run_status(&rid).unwrap().status,
        TaskRunStatus::Active
    ));
    assert_eq!(driver.status("agent").await, Some(AutoStatus::Active));
    assert_eq!(bus.count("run.completed"), 0);
    assert_eq!(
        ext.session_count(),
        1,
        "Continued → session stays registered until terminal"
    );
}

// ── T-ATE-4 — loud-fail preserved: Degraded → settle Err, no half-settle, session
//    LEFT registered (never silently swallowed) ───────────────────────────────────
#[tokio::test]
async fn tick_loud_fails_on_degraded_no_half_settle() {
    let (bus, mgr, driver, ext) = setup_ext();
    let rid = mgr
        .ensure_run("auto:agent", "agent", RunConfig::default())
        .unwrap();
    driver
        .start("agent", primary_only_criteria())
        .await
        .unwrap();
    // Drive the driver Active → Degraded (3 LLM errors ≥ default limit 3).
    driver.record_llm_error("agent");
    driver.record_llm_error("agent");
    driver.record_llm_error("agent");
    driver.run_cadence_pass(1_000).await;
    assert_eq!(driver.status("agent").await, Some(AutoStatus::Degraded));
    // A close from Degraded sets last_iteration_status; record the complete-cycle.
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
    ext.register_session("agent", rid.as_ref());

    // The tick's settle hits the coordinator fail-CLOSED (CompleteCycle is Active-only).
    ext.on_tick(SchedulerTick::new(2_000)).await;

    // No half-settle: the Run was NEVER settled (driver-first ordering).
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
    // Err → session LEFT registered for a later retry / operator action.
    assert_eq!(ext.session_count(), 1, "errored session left registered");
}

// ── T-ATE-5 — the wrapper preserves the driver cadence pass: on_tick degrades a
//    session with N consecutive LLM errors (proves on_tick runs run_cadence_pass) ──
#[tokio::test]
async fn tick_runs_cadence_pass_degrade_detection() {
    let (_bus, _mgr, driver, ext) = setup_ext();
    driver
        .start("agent", primary_only_criteria())
        .await
        .unwrap();
    // Record 3 consecutive LLM errors (≥ default limit 3) but DO NOT run a cadence
    // pass directly — the extension's on_tick must run it.
    driver.record_llm_error("agent");
    driver.record_llm_error("agent");
    driver.record_llm_error("agent");
    assert_eq!(
        driver.status("agent").await,
        Some(AutoStatus::Active),
        "still Active before the tick (errors recorded, cadence not yet run)"
    );

    ext.on_tick(SchedulerTick::new(1_000)).await;

    assert_eq!(
        driver.status("agent").await,
        Some(AutoStatus::Degraded),
        "on_tick ran run_cadence_pass → the session degraded"
    );
}

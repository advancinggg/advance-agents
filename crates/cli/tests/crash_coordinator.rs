//! SLICE 1 — per-iteration crash coordinator (`run_guarded_iteration`).
//!
//! PRODUCT-UNIT/INTEGRATION witnesses for the cli crash-decision coordinator. These
//! prove the coordinator LOGIC (real per-iteration-budget breach → crash; guardrail
//! Component-metric breach → crash via the `ComponentMetricReader` trait; no breach →
//! normal keep/discard). They flip **ZERO SYS-AC** and verify **ZERO new MODULE AC**
//! — the SYS-AC-201/202 e2e witnesses (`sys_j11_auto_iteration.rs`) stay `#[ignore]`d
//! until the harvest, and the concrete evaluator-executing `ComponentMetricReader` is
//! a harvest hand-off (a reader DOUBLE here is legitimate product-unit-testing).
//!
//! The crash arm's REAL-git rollback is covered by the auto-loop crate's
//! `tests/integrated_loop.rs::close_crash_rolls_back_real_git`; this file uses Noop
//! checkpoint/rollback doubles to keep the coordinator-decision tests deterministic.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use advance_cli::crash_coordinator::{run_guarded_iteration, GuardedIterationInputs};
use advance_scheduler_auto_loop::config::{
    MetricSource, Objective, Op, Predicate, Role, SuccessCriteria,
};
use advance_scheduler_auto_loop::{
    AutoEventSinkError, AutoIterationEventPayload, AutoIterationEventSink, AutoLoopDriver,
    AutoLoopError, ComponentMetricReader, DefaultAutoLoopDriver, IterationCheckpoint,
    IterationOutcome, IterationRollback, IterationStatus, MetricReadError, PerIterationBudget,
    ResultsWriter,
};
use advance_shared_types::cost::RunCost;
use advance_shared_types::traits::CostTrackerQuery;
use async_trait::async_trait;

// ── cli-side test doubles ────────────────────────────────────────────────────

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

/// `CostTrackerQuery` double returning a fixed `RunCost` for one (run_id, iteration).
struct FixedCost {
    run_id: String,
    iteration: u32,
    cost: RunCost,
}
impl FixedCost {
    fn new(run_id: &str, iteration: u32, cost: RunCost) -> Self {
        Self {
            run_id: run_id.to_string(),
            iteration,
            cost,
        }
    }
}
impl CostTrackerQuery for FixedCost {
    fn query_run(&self, run_id: &str) -> Option<RunCost> {
        (run_id == self.run_id).then(|| self.cost.clone())
    }
    fn query_iteration(&self, run_id: &str, iteration: u32) -> Option<RunCost> {
        (run_id == self.run_id && iteration == self.iteration).then(|| self.cost.clone())
    }
}

/// `ComponentMetricReader` double returning a fixed reading or error.
struct FixedReader {
    result: Result<f64, MetricReadError>,
}
impl FixedReader {
    fn ok(v: f64) -> Self {
        Self { result: Ok(v) }
    }
    fn err() -> Self {
        Self {
            result: Err(MetricReadError::NotFound("score".to_string())),
        }
    }
}
impl ComponentMetricReader for FixedReader {
    fn read_component_metric(&self, _output_key: &str) -> Result<f64, MetricReadError> {
        self.result.clone()
    }
}

#[derive(Default)]
struct RecordingIterSink {
    events: Mutex<Vec<AutoIterationEventPayload>>,
}
impl RecordingIterSink {
    fn events(&self) -> Vec<AutoIterationEventPayload> {
        self.events.lock().unwrap().clone()
    }
    /// The reason carried by the first `auto.iteration_crashed`, if any.
    fn crash_reason(&self) -> Option<String> {
        self.events().into_iter().find_map(|e| match e {
            AutoIterationEventPayload::Crashed { reason, .. } => Some(reason),
            _ => None,
        })
    }
}
#[async_trait]
impl AutoIterationEventSink for RecordingIterSink {
    async fn emit(&self, payload: AutoIterationEventPayload) -> Result<(), AutoEventSinkError> {
        self.events.lock().unwrap().push(payload);
        Ok(())
    }
}

// ── helpers ──────────────────────────────────────────────────────────────────

fn run_cost(tokens_in: u64, tokens_out: u64, cost_usd: f64) -> RunCost {
    RunCost {
        tokens_in,
        tokens_out,
        cost_usd,
        request_count: 1,
    }
}

/// Criteria: a primary File objective (op Lt) + an optional guardrail Component
/// objective + an optional per-iteration token budget. (A Component objective forces
/// `evaluator: Some(..)` per AC-05.)
fn criteria(max_tokens: Option<u64>, guardrail: Option<(Op, f64)>) -> SuccessCriteria {
    let mut objectives = vec![Objective {
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
    }];
    if let Some((op, threshold)) = guardrail {
        objectives.push(Objective {
            name: "guard".to_string(),
            role: Role::Guardrail,
            metric_source: MetricSource::Component {
                output_key: "score".to_string(),
            },
            predicate: Predicate {
                op,
                threshold: Some(threshold),
            },
        });
    }
    SuccessCriteria {
        evaluator: guardrail.map(|_| "pack@1.0.0/eval".to_string()),
        objectives,
        per_iteration_budget: max_tokens.map(|t| PerIterationBudget {
            max_tokens: Some(t),
            max_wall_time_sec: None,
            max_cost_usd: None,
        }),
        fail_fast: None,
        safety_valve: None,
    }
}

struct Harness {
    driver: DefaultAutoLoopDriver,
    writer: Arc<ResultsWriter>,
    sink: Arc<RecordingIterSink>,
    _tmp: tempfile::TempDir,
}

fn harness(cost: FixedCost) -> Harness {
    let tmp = tempfile::tempdir().unwrap();
    let writer = Arc::new(ResultsWriter::new(tmp.path().to_path_buf()));
    let sink = Arc::new(RecordingIterSink::default());
    let driver = DefaultAutoLoopDriver::new(Arc::new(NoopCkpt), Arc::new(NoopRb))
        .with_cost_tracker(Arc::new(cost))
        .with_results_writer(writer.clone())
        .with_iteration_event_sink(sink.clone());
    Harness {
        driver,
        writer,
        sink,
        _tmp: tmp,
    }
}

fn inputs(primary_metric: Option<f64>) -> GuardedIterationInputs {
    let t0 = Instant::now();
    GuardedIterationInputs {
        agent_id: "root".to_string(),
        run_id: "run-a".to_string(),
        iteration: 1,
        checkpoint_label: "auto-iter-1".to_string(),
        primary_metric,
        metrics: BTreeMap::new(),
        cost_usd: 0.0,
        wall_time_sec: 1,
        summary: None,
        started_at: t0,
        now: t0,
    }
}

async fn crash_row_status(writer: &ResultsWriter) -> serde_json::Value {
    let content = tokio::fs::read_to_string(writer.jsonl_path())
        .await
        .unwrap();
    serde_json::from_str(content.lines().next().expect("a results row")).unwrap()
}

// ── T-CC-1 — budget breach → crash (witness-floor: product-decided) ──────────
#[tokio::test]
async fn budget_breach_drives_crash_via_coordinator() {
    // 60k tokens > 50k limit → a REAL Breach computed by check_per_iteration_budget.
    let h = harness(FixedCost::new("run-a", 1, run_cost(60_000, 0, 0.0)));
    let crit = criteria(Some(50_000), Some((Op::Gt, 0.3)));
    h.driver.start("root", crit.clone()).await.expect("start");

    // The reader would also breach the guardrail (0.5 > 0.3), but budget wins.
    let outcome = run_guarded_iteration(&h.driver, &crit, &FixedReader::ok(0.5), inputs(Some(0.1)))
        .await
        .expect("guarded iteration");

    match outcome {
        IterationOutcome::Continue { status, .. } => assert_eq!(status, IterationStatus::Crash),
        other => panic!("expected Continue{{Crash}}, got {other:?}"),
    }
    // status:crash row.
    let row = crash_row_status(&h.writer).await;
    assert_eq!(row["status"], "crash");
    assert_eq!(row["iter"], 1);
    // The crash reason is the PRODUCT-computed budget breach (not a guardrail reason,
    // not a hand-set crashed flag).
    let reason = h
        .sink
        .crash_reason()
        .expect("auto.iteration_crashed emitted");
    assert!(
        reason.contains("per-iteration budget breach: tokens"),
        "expected budget-breach reason, got: {reason}"
    );
    assert!(
        reason.contains("60000") && reason.contains("50000"),
        "{reason}"
    );
}

// ── T-CC-2 — guardrail Component-metric breach → crash ───────────────────────
#[tokio::test]
async fn guardrail_breach_drives_crash_via_coordinator() {
    // No budget → guardrail predicate (Gt 0.3) breaches on reader value 0.5.
    let h = harness(FixedCost::new("run-a", 1, run_cost(10, 0, 0.0)));
    let crit = criteria(None, Some((Op::Gt, 0.3)));
    h.driver.start("root", crit.clone()).await.expect("start");

    let outcome = run_guarded_iteration(&h.driver, &crit, &FixedReader::ok(0.5), inputs(Some(0.1)))
        .await
        .expect("guarded iteration");

    match outcome {
        IterationOutcome::Continue { status, .. } => assert_eq!(status, IterationStatus::Crash),
        other => panic!("expected Continue{{Crash}}, got {other:?}"),
    }
    assert_eq!(crash_row_status(&h.writer).await["status"], "crash");
    let reason = h
        .sink
        .crash_reason()
        .expect("auto.iteration_crashed emitted");
    assert!(reason.contains("guardrail breach"), "{reason}");
    assert!(reason.contains("guard"), "{reason}");
}

// ── T-CC-3 — no breach → normal keep ─────────────────────────────────────────
#[tokio::test]
async fn no_breach_keeps_iteration() {
    // No budget; guardrail (Gt 0.9) does NOT breach on reader value 0.5.
    let h = harness(FixedCost::new("run-a", 1, run_cost(10, 0, 0.0)));
    let crit = criteria(None, Some((Op::Gt, 0.9)));
    h.driver.start("root", crit.clone()).await.expect("start");

    // First iteration with a finite primary (op Lt) → improvement → Keep.
    let outcome = run_guarded_iteration(&h.driver, &crit, &FixedReader::ok(0.5), inputs(Some(0.1)))
        .await
        .expect("guarded iteration");

    match outcome {
        IterationOutcome::Continue { status, .. } => assert_eq!(status, IterationStatus::Keep),
        other => panic!("expected Continue{{Keep}}, got {other:?}"),
    }
    assert!(h.sink.crash_reason().is_none(), "no crash expected");
    assert_eq!(crash_row_status(&h.writer).await["status"], "keep");
}

// ── T-CC-3b — no breach, no primary reading → discard ────────────────────────
#[tokio::test]
async fn no_breach_no_primary_discards_iteration() {
    let h = harness(FixedCost::new("run-a", 1, run_cost(10, 0, 0.0)));
    let crit = criteria(None, Some((Op::Gt, 0.9)));
    h.driver.start("root", crit.clone()).await.expect("start");

    let outcome = run_guarded_iteration(&h.driver, &crit, &FixedReader::ok(0.5), inputs(None))
        .await
        .expect("guarded iteration");

    match outcome {
        IterationOutcome::Continue { status, .. } => assert_eq!(status, IterationStatus::Discard),
        other => panic!("expected Continue{{Discard}}, got {other:?}"),
    }
}

// ── T-CC-4 — guardrail read error → fail-CLOSED crash ────────────────────────
#[tokio::test]
async fn guardrail_read_error_fails_closed_to_crash() {
    let h = harness(FixedCost::new("run-a", 1, run_cost(10, 0, 0.0)));
    let crit = criteria(None, Some((Op::Gt, 0.3)));
    h.driver.start("root", crit.clone()).await.expect("start");

    let outcome = run_guarded_iteration(&h.driver, &crit, &FixedReader::err(), inputs(Some(0.1)))
        .await
        .expect("guarded iteration");

    match outcome {
        IterationOutcome::Continue { status, .. } => assert_eq!(status, IterationStatus::Crash),
        other => panic!("expected Continue{{Crash}}, got {other:?}"),
    }
    let reason = h
        .sink
        .crash_reason()
        .expect("auto.iteration_crashed emitted");
    assert!(reason.contains("guardrail metric read failed"), "{reason}");
}

// ── T-CC-5 — budget breach takes precedence over guardrail breach ────────────
#[tokio::test]
async fn budget_breach_precedes_guardrail() {
    // Both would breach: budget (60k>50k) AND guardrail (0.5>0.3). Budget wins.
    let h = harness(FixedCost::new("run-a", 1, run_cost(60_000, 0, 0.0)));
    let crit = criteria(Some(50_000), Some((Op::Gt, 0.3)));
    h.driver.start("root", crit.clone()).await.expect("start");

    let _ = run_guarded_iteration(&h.driver, &crit, &FixedReader::ok(0.5), inputs(Some(0.1)))
        .await
        .expect("guarded iteration");

    let reason = h
        .sink
        .crash_reason()
        .expect("auto.iteration_crashed emitted");
    assert!(
        reason.contains("per-iteration budget breach"),
        "budget must take precedence, got: {reason}"
    );
    assert!(!reason.contains("guardrail breach"), "{reason}");
}

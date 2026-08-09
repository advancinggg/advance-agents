//! Wave-22 (autoloop-integ) — integrated witnesses that PIN THE PRODUCTION
//! COMPOSITION: the real `build_auto_loop_driver` + `install_auto_loop_integration`
//! augment (real `CostTrackerQuery` + `ResultsWriter`) over a REAL git workspace,
//! plus the real `mint_auto_run` minter + the real `DefaultFileMetricReader`,
//! driving `run_guarded_iteration_with_file_reader`.
//!
//! These close the AC-02 (REQ-069) + AC-14 (REQ-078) cross-module legs the
//! slice-C honesty override held back, at the drive-prod-fn level:
//! - IT-1  : AC-02 — real `auto:{agent}` Run mint + real `CostTrackerQuery`
//!           per-iteration budget breach → crash (discriminator: the
//!           `cost_tracker=None` production baseline can only return `Ok`).
//! - IT-1b : AC-02 — per-`run_id` budget isolation (a 2nd auto Run, same cap).
//! - IT-2a : AC-14 — Component `fail_fast` breach → crash path.
//! - IT-2b : AC-14 — File `fail_fast` breach via the REAL `DefaultFileMetricReader`
//!           → crash path (results.jsonl crash row + rollback).
//! - IT-3  : AC-14 (neg) — a passing File + a passing Component `fail_fast`
//!           metric (both resolved) → normal close, no crash (the resolved
//!           subset reaches `check_with_readings` with matched lengths).
//! - IT-3b : AC-14 — a File `fail_fast` metric with NO wired reader in the call
//!           → fail-CLOSED crash (a safety control is never silently skipped).
//! - UT-2  : AC-14 — fail_fast branch resolution — every source that cannot be
//!           soundly evaluated FAIL-CLOSES: under-specified threshold (no
//!           predicate OR no threshold), File read-error, and Event-source
//!           (reader deferred). None silently fail-OPENs.
//! - UT-4  : AC-02 — minter `register_run` AtCapacity → `driver.stop`
//!           compensation → no live-state half-state.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use advance_cli::auto_wiring::{
    build_auto_loop_driver, install_auto_loop_integration, mint_auto_run, AutoMintError,
};
use advance_cli::crash_coordinator::{
    run_guarded_iteration_with_file_reader, GuardedIterationInputs,
};
use advance_cost_tracker::CostTracker;
use advance_run_manager::{RunConfig, RunManager};
use advance_scheduler_auto_loop::config::{
    MetricSource, Objective, Op, Predicate, Role, SuccessCriteria,
};
use advance_scheduler_auto_loop::{
    ComponentMetricReader, DefaultAutoLoopDriver, DefaultFileMetricReader, FailFastMetric,
    IterationOutcome, IterationStatus, MetricReadError, PerIterationBudget,
};
use advance_shared_types::event::Event;
use advance_shared_types::traits::{CostTrackerQuery, EventBusEmit};
use git2::{Repository, Signature};

// ── doubles + helpers ────────────────────────────────────────────────────────

struct NoopBus;
impl EventBusEmit for NoopBus {
    fn emit(&self, _event: Event) {}
}

/// A `ComponentMetricReader` returning a fixed reading or error (a reader DOUBLE
/// — legitimate product-unit-testing of the coordinator's fail_fast Component
/// branch, distinct from the SYS-AC-201 real-`ExecutingComponentMetricReader`
/// witness of the guardrail branch; the fail_fast branch uses the SAME trait the
/// same way).
struct FixedComp(Result<f64, MetricReadError>);
impl ComponentMetricReader for FixedComp {
    fn read_component_metric(&self, _output_key: &str) -> Result<f64, MetricReadError> {
        self.0.clone()
    }
}

/// A `ComponentMetricReader` that never resolves (fail_fast tests with no
/// Component metric still pass a reader; it must not be consulted).
struct UnusedComp;
impl ComponentMetricReader for UnusedComp {
    fn read_component_metric(&self, output_key: &str) -> Result<f64, MetricReadError> {
        Err(MetricReadError::NotFound(format!("unused: {output_key}")))
    }
}

/// A real single-branch git repo with an empty-tree initial commit + one
/// committed file (so `NamedCheckpoint::create` has a born HEAD to tag).
fn git_ws() -> tempfile::TempDir {
    let tmp = tempfile::tempdir().expect("tempdir");
    advance_git::bootstrap_repo_at(tmp.path()).expect("bootstrap_repo_at");
    let repo = Repository::open(tmp.path()).expect("open repo");
    let sig = Signature::now("wave22", "wave22@advance").expect("sig");
    let tree_oid = {
        let mut idx = repo.index().expect("index");
        idx.write_tree().expect("write empty tree")
    };
    let tree = repo.find_tree(tree_oid).expect("find tree");
    repo.commit(
        Some("refs/heads/main"),
        &sig,
        &sig,
        "initial commit",
        &tree,
        &[],
    )
    .expect("initial commit");
    repo.set_head("refs/heads/main").expect("set_head");
    repo.checkout_head(None).expect("checkout_head");
    tmp
}

/// The PRODUCTION composition: real `build_auto_loop_driver` (real M003
/// checkpoint/rollback over the git repo) + the `install_auto_loop_integration`
/// augment (real cost tracker + results writer). Returns the augmented Arc.
fn prod_driver(ws: &Path, cost_tracker: Arc<dyn CostTrackerQuery>) -> Arc<DefaultAutoLoopDriver> {
    let bus: Arc<dyn EventBusEmit> = Arc::new(NoopBus);
    let driver = build_auto_loop_driver(ws, bus).expect("git workspace → auto driver");
    install_auto_loop_integration(driver, cost_tracker, ws).expect("augment on unique Arc")
}

/// An `llm.response` cost event the `CostTracker` folds into
/// `by_run_iteration[(run_id, iteration)]` (mirrors `budget_wiring.rs`).
fn cost_event(run_id: &str, iteration: u32, input_tokens: u64) -> Event {
    serde_json::from_value(serde_json::json!({
        "id": "evt-w22",
        "timestamp": "2026-07-05T00:00:00Z",
        "agent_id": "root",
        "task_id": null,
        "run_id": run_id,
        "execution_id": null,
        "trace_id": "t",
        "span_id": "s",
        "parent_span_id": null,
        "event_type": "llm.response",
        "payload": { "cost_usd": 0.0, "input_tokens": input_tokens, "output_tokens": 0, "iteration": iteration },
        "duration_ms": 5
    }))
    .expect("cost event deserializes")
}

fn inputs(run_id: &str, iteration: u32, primary: Option<f64>) -> GuardedIterationInputs {
    let t0 = Instant::now();
    GuardedIterationInputs {
        agent_id: "root".to_string(),
        run_id: run_id.to_string(),
        iteration,
        checkpoint_label: format!("auto-iter-{iteration}"),
        primary_metric: primary,
        metrics: BTreeMap::new(),
        cost_usd: 0.0,
        wall_time_sec: 1,
        summary: None,
        started_at: t0,
        now: t0,
    }
}

/// The `status` field of the first `results.jsonl` row (or `None` if no file).
fn results_status(ws: &Path) -> Option<String> {
    let path = ws.join(".agent").join("auto").join("results.jsonl");
    let content = std::fs::read_to_string(path).ok()?;
    let row: serde_json::Value = serde_json::from_str(content.lines().next()?).ok()?;
    row.get("status")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

fn primary_file_objective() -> Objective {
    Objective {
        name: "primary".to_string(),
        role: Role::Primary,
        metric_source: MetricSource::File {
            path: "primary.json".to_string(),
            key: "loss".to_string(),
        },
        // No threshold → keep/discard vs previous_best (not a guardrail predicate).
        predicate: Predicate {
            op: Op::Lt,
            threshold: None,
        },
    }
}

/// Criteria with a per-iteration token budget (AC-02 witness).
fn budget_criteria(max_tokens: u64) -> SuccessCriteria {
    SuccessCriteria {
        evaluator: None,
        objectives: vec![primary_file_objective()],
        per_iteration_budget: Some(PerIterationBudget {
            max_tokens: Some(max_tokens),
            max_wall_time_sec: None,
            max_cost_usd: None,
        }),
        fail_fast: None,
        safety_valve: None,
    }
}

fn ff_metric(source: MetricSource, op: Op, threshold: f64) -> FailFastMetric {
    FailFastMetric {
        metric_source: source,
        predicate: Some(Predicate {
            op,
            threshold: Some(threshold),
        }),
    }
}

/// Criteria with a `fail_fast` list (+ an evaluator when a Component source is
/// present, per AC-05 admission).
fn ff_criteria(fail_fast: Vec<FailFastMetric>) -> SuccessCriteria {
    let has_component = fail_fast
        .iter()
        .any(|m| matches!(m.metric_source, MetricSource::Component { .. }));
    SuccessCriteria {
        evaluator: has_component.then(|| "pack@1.0.0/eval".to_string()),
        objectives: vec![primary_file_objective()],
        per_iteration_budget: None,
        fail_fast: Some(fail_fast),
        safety_valve: None,
    }
}

// ─────────────────────────── IT-1: AC-02 / REQ-069 ───────────────────────────

#[tokio::test]
async fn it1_real_auto_run_and_cost_tracker_budget_breach_crashes() {
    let ws = git_ws();
    // Real CostTracker fed a real llm.response; the SAME Arc install feeds the driver.
    let cost = Arc::new(CostTracker::new());
    let driver = prod_driver(ws.path(), cost.clone() as Arc<dyn CostTrackerQuery>);
    let run_manager = RunManager::new(Arc::new(NoopBus));

    // (a) mint the auto Run under the auto:{agent} bucket with an independent budget.
    let crit = budget_criteria(50_000);
    let run_id = mint_auto_run(
        &driver,
        &run_manager,
        "root",
        crit.clone(),
        RunConfig {
            token_limit: Some(123_456),
            ..RunConfig::default()
        },
    )
    .await
    .expect("mint auto run");
    assert_eq!(
        run_manager.task_owner_if_live("auto:root").as_deref(),
        Some("root"),
        "the Run must live under the `auto:{{agent}}` bucket"
    );
    assert!(
        !run_id.as_ref().contains(':'),
        "the minted run_id is the colon-free run-uuid, not the auto: task id"
    );

    // (c) a real llm.response accrues 60k tokens on THIS run_id/iteration.
    cost.observe(&cost_event(run_id.as_ref(), 1, 60_000));

    // open iteration 1 (checkpoints auto-iter-1 for the crash rollback).
    driver
        .iteration_start("root", Some(run_id.to_string()), 1)
        .await
        .expect("iteration_start");

    let outcome = run_guarded_iteration_with_file_reader(
        &driver,
        &crit,
        &UnusedComp,
        None,
        inputs(run_id.as_ref(), 1, None),
    )
    .await
    .expect("guarded iteration");

    assert!(
        matches!(
            outcome,
            IterationOutcome::Continue {
                status: IterationStatus::Crash,
                ..
            }
        ),
        "60k tokens > 50k limit (real folded cost) → crash: {outcome:?}"
    );
    assert_eq!(
        results_status(ws.path()).as_deref(),
        Some("crash"),
        "the production-composed ResultsWriter must write the crash row"
    );

    // DISCRIMINATOR: the same inputs through a driver WITHOUT the cost-tracker
    // install (the production baseline `cost_tracker == None`) cannot breach → no crash.
    let ws2 = git_ws();
    let bare: Arc<DefaultAutoLoopDriver> = {
        let d = build_auto_loop_driver(ws2.path(), Arc::new(NoopBus)).expect("driver");
        // No install_auto_loop_integration → no cost tracker, no results writer.
        d
    };
    let rm2 = RunManager::new(Arc::new(NoopBus));
    let rid2 = mint_auto_run(&bare, &rm2, "root", crit.clone(), RunConfig::default())
        .await
        .expect("mint");
    bare.iteration_start("root", Some(rid2.to_string()), 1)
        .await
        .expect("iteration_start");
    let base = run_guarded_iteration_with_file_reader(
        &bare,
        &crit,
        &UnusedComp,
        None,
        inputs(rid2.as_ref(), 1, None),
    )
    .await
    .expect("guarded iteration (baseline)");
    assert!(
        !matches!(
            base,
            IterationOutcome::Continue {
                status: IterationStatus::Crash,
                ..
            }
        ),
        "cost_tracker=None baseline must NOT crash: {base:?}"
    );
}

#[tokio::test]
async fn it1b_per_run_id_budget_isolation() {
    // A 2nd auto Run (auto:beta) with the SAME cap: cost folded on A only → A
    // breaches while B stays within caps. Proves per-run_id isolation, not just
    // per-run config application.
    let ws = git_ws();
    let cost = Arc::new(CostTracker::new());
    let driver = prod_driver(ws.path(), cost.clone() as Arc<dyn CostTrackerQuery>);
    let run_manager = RunManager::new(Arc::new(NoopBus));

    let crit = budget_criteria(50_000);
    let run_a = mint_auto_run(
        &driver,
        &run_manager,
        "alpha",
        crit.clone(),
        RunConfig::default(),
    )
    .await
    .expect("mint A");
    let run_b = mint_auto_run(
        &driver,
        &run_manager,
        "beta",
        crit.clone(),
        RunConfig::default(),
    )
    .await
    .expect("mint B");
    assert_ne!(run_a.as_ref(), run_b.as_ref(), "distinct auto Runs");

    // Fold 60k tokens on A's run_id only.
    cost.observe(&cost_event(run_a.as_ref(), 1, 60_000));

    // A over the cap → Breach; B has no accrued cost → Ok.
    assert!(
        matches!(
            driver.check_per_iteration_budget(
                "alpha",
                run_a.as_ref(),
                1,
                Instant::now(),
                Instant::now()
            ),
            advance_scheduler_auto_loop::BudgetStatus::Breach(_)
        ),
        "alpha breaches (cost isolated to its run_id)"
    );
    assert!(
        matches!(
            driver.check_per_iteration_budget(
                "beta",
                run_b.as_ref(),
                1,
                Instant::now(),
                Instant::now()
            ),
            advance_scheduler_auto_loop::BudgetStatus::Ok
        ),
        "beta stays within caps (no cost folded on its run_id)"
    );
}

// ─────────────────────────── IT-2: AC-14 / REQ-078 ───────────────────────────

#[tokio::test]
async fn it2a_component_fail_fast_breach_crashes() {
    let ws = git_ws();
    let driver = prod_driver(ws.path(), Arc::new(CostTracker::new()));
    let run_manager = RunManager::new(Arc::new(NoopBus));

    let crit = ff_criteria(vec![ff_metric(
        MetricSource::Component {
            output_key: "unsafe_score".to_string(),
        },
        Op::Gt,
        0.8,
    )]);
    let run_id = mint_auto_run(
        &driver,
        &run_manager,
        "root",
        crit.clone(),
        RunConfig::default(),
    )
    .await
    .expect("mint");
    driver
        .iteration_start("root", Some(run_id.to_string()), 1)
        .await
        .expect("iteration_start");

    // 0.95 > 0.8 → breach → crash.
    let outcome = run_guarded_iteration_with_file_reader(
        &driver,
        &crit,
        &FixedComp(Ok(0.95)),
        None,
        inputs(run_id.as_ref(), 1, None),
    )
    .await
    .expect("guarded iteration");
    assert!(
        matches!(
            outcome,
            IterationOutcome::Continue {
                status: IterationStatus::Crash,
                ..
            }
        ),
        "Component fail_fast breach → crash: {outcome:?}"
    );
    assert_eq!(results_status(ws.path()).as_deref(), Some("crash"));
}

#[tokio::test]
async fn it2b_file_fail_fast_breach_via_real_reader_crashes() {
    let ws = git_ws();
    let driver = prod_driver(ws.path(), Arc::new(CostTracker::new()));
    let run_manager = RunManager::new(Arc::new(NoopBus));

    // Write a breaching metric FILE the REAL DefaultFileMetricReader reads.
    std::fs::write(ws.path().join("ff.json"), br#"{"err_rate": 0.9}"#).unwrap();
    let file_reader = DefaultFileMetricReader::new(ws.path());

    let crit = ff_criteria(vec![ff_metric(
        MetricSource::File {
            path: "ff.json".to_string(),
            key: "err_rate".to_string(),
        },
        Op::Gt,
        0.2,
    )]);
    let run_id = mint_auto_run(
        &driver,
        &run_manager,
        "root",
        crit.clone(),
        RunConfig::default(),
    )
    .await
    .expect("mint");
    driver
        .iteration_start("root", Some(run_id.to_string()), 1)
        .await
        .expect("iteration_start");

    // 0.9 > 0.2 → the REAL File reader drives a real fail-fast Trigger → crash.
    let outcome = run_guarded_iteration_with_file_reader(
        &driver,
        &crit,
        &UnusedComp,
        Some(&file_reader),
        inputs(run_id.as_ref(), 1, None),
    )
    .await
    .expect("guarded iteration");
    assert!(
        matches!(
            outcome,
            IterationOutcome::Continue {
                status: IterationStatus::Crash,
                ..
            }
        ),
        "File fail_fast breach (real reader) → crash: {outcome:?}"
    );
    assert_eq!(results_status(ws.path()).as_deref(), Some("crash"));
}

#[tokio::test]
async fn it3_passing_file_and_component_no_crash() {
    let ws = git_ws();
    let driver = prod_driver(ws.path(), Arc::new(CostTracker::new()));
    let run_manager = RunManager::new(Arc::new(NoopBus));

    // A passing File metric file (0.1 < 0.5 threshold → not breached).
    std::fs::write(ws.path().join("ff.json"), br#"{"e": 0.1}"#).unwrap();
    let file_reader = DefaultFileMetricReader::new(ws.path());

    // A passing File + a passing Component (both resolved → the FILTERED subset is
    // both; check_with_readings gets matched lengths → no short-readings crash).
    let crit = ff_criteria(vec![
        ff_metric(
            MetricSource::File {
                path: "ff.json".to_string(),
                key: "e".to_string(),
            },
            Op::Gt,
            0.5,
        ),
        ff_metric(
            MetricSource::Component {
                output_key: "safe".to_string(),
            },
            Op::Gt,
            0.9,
        ),
    ]);
    let run_id = mint_auto_run(
        &driver,
        &run_manager,
        "root",
        crit.clone(),
        RunConfig::default(),
    )
    .await
    .expect("mint");
    driver
        .iteration_start("root", Some(run_id.to_string()), 1)
        .await
        .expect("iteration_start");

    // File 0.1 (not > 0.5) + Component 0.3 (not > 0.9) → NO crash.
    let outcome = run_guarded_iteration_with_file_reader(
        &driver,
        &crit,
        &FixedComp(Ok(0.3)),
        Some(&file_reader),
        inputs(run_id.as_ref(), 1, None),
    )
    .await
    .expect("guarded iteration");
    assert!(
        !matches!(
            outcome,
            IterationOutcome::Continue {
                status: IterationStatus::Crash,
                ..
            }
        ),
        "all fail_fast metrics pass → NO crash: {outcome:?}"
    );
    assert_ne!(
        results_status(ws.path()).as_deref(),
        Some("crash"),
        "no crash row on a passing fail_fast pass"
    );
}

#[tokio::test]
async fn it3b_file_none_reader_is_fail_closed() {
    // The `file_reader: None` path (the dormant delegate/tick shim): a File
    // `fail_fast` metric cannot be evaluated (no reader wired in this call) → the
    // branch FAIL-CLOSES (audit-r2 Claude-Diff-W1) rather than silently skipping a
    // safety control. Uniform with the Event / under-specified fail-close posture.
    let ws = git_ws();
    let driver = prod_driver(ws.path(), Arc::new(CostTracker::new()));
    let run_manager = RunManager::new(Arc::new(NoopBus));

    let crit = ff_criteria(vec![
        ff_metric(
            MetricSource::File {
                path: "ff.json".to_string(),
                key: "e".to_string(),
            },
            Op::Gt,
            0.5,
        ),
        ff_metric(
            MetricSource::Component {
                output_key: "safe".to_string(),
            },
            Op::Gt,
            0.9,
        ),
    ]);
    let run_id = mint_auto_run(
        &driver,
        &run_manager,
        "root",
        crit.clone(),
        RunConfig::default(),
    )
    .await
    .expect("mint");
    driver
        .iteration_start("root", Some(run_id.to_string()), 1)
        .await
        .expect("iteration_start");

    // file_reader None → the File `fail_fast` metric can't be evaluated → fail-CLOSED
    // crash (even though the Component would pass — the File source is checked first
    // and fail-closes; a File safety control is never silently skipped).
    let outcome = run_guarded_iteration_with_file_reader(
        &driver,
        &crit,
        &FixedComp(Ok(0.3)),
        None,
        inputs(run_id.as_ref(), 1, None),
    )
    .await
    .expect("guarded iteration");
    assert!(
        matches!(
            outcome,
            IterationOutcome::Continue {
                status: IterationStatus::Crash,
                ..
            }
        ),
        "File fail_fast with no wired reader → fail-closed crash: {outcome:?}"
    );
}

// ─────────────────────────── UT-2: fail_fast branch resolution ───────────────

#[tokio::test]
async fn ut2_predicate_none_threshold_source_fail_closed() {
    // A File fail_fast metric with NO predicate is a fail-CLOSED Trigger.
    let ws = git_ws();
    let driver = prod_driver(ws.path(), Arc::new(CostTracker::new()));
    let rm = RunManager::new(Arc::new(NoopBus));
    let crit = SuccessCriteria {
        evaluator: None,
        objectives: vec![primary_file_objective()],
        per_iteration_budget: None,
        fail_fast: Some(vec![FailFastMetric {
            metric_source: MetricSource::File {
                path: "ff.json".to_string(),
                key: "e".to_string(),
            },
            predicate: None,
        }]),
        safety_valve: None,
    };
    let run_id = mint_auto_run(&driver, &rm, "root", crit.clone(), RunConfig::default())
        .await
        .expect("mint");
    driver
        .iteration_start("root", Some(run_id.to_string()), 1)
        .await
        .expect("iteration_start");
    let file_reader = DefaultFileMetricReader::new(ws.path());
    let outcome = run_guarded_iteration_with_file_reader(
        &driver,
        &crit,
        &UnusedComp,
        Some(&file_reader),
        inputs(run_id.as_ref(), 1, None),
    )
    .await
    .expect("guarded iteration");
    assert!(
        matches!(
            outcome,
            IterationOutcome::Continue {
                status: IterationStatus::Crash,
                ..
            }
        ),
        "predicate-None threshold source → fail-closed crash: {outcome:?}"
    );
}

#[tokio::test]
async fn ut2_file_read_error_fail_closed() {
    // A File fail_fast metric whose file is ABSENT → read NotFound → fail-CLOSED.
    let ws = git_ws();
    let driver = prod_driver(ws.path(), Arc::new(CostTracker::new()));
    let rm = RunManager::new(Arc::new(NoopBus));
    let crit = ff_criteria(vec![ff_metric(
        MetricSource::File {
            path: "absent.json".to_string(),
            key: "e".to_string(),
        },
        Op::Gt,
        0.5,
    )]);
    let run_id = mint_auto_run(&driver, &rm, "root", crit.clone(), RunConfig::default())
        .await
        .expect("mint");
    driver
        .iteration_start("root", Some(run_id.to_string()), 1)
        .await
        .expect("iteration_start");
    let file_reader = DefaultFileMetricReader::new(ws.path());
    let outcome = run_guarded_iteration_with_file_reader(
        &driver,
        &crit,
        &UnusedComp,
        Some(&file_reader),
        inputs(run_id.as_ref(), 1, None),
    )
    .await
    .expect("guarded iteration");
    assert!(
        matches!(
            outcome,
            IterationOutcome::Continue {
                status: IterationStatus::Crash,
                ..
            }
        ),
        "unreadable File fail_fast metric → fail-closed crash: {outcome:?}"
    );
}

#[tokio::test]
async fn ut2_event_fail_fast_is_fail_closed() {
    // An Event-source fail_fast metric: its reader is deferred (unbuilt), so the
    // branch FAIL-CLOSES (crash) rather than silently fail-OPENing a safety
    // control (audit-r1 Claude-Diff-W1).
    let ws = git_ws();
    let driver = prod_driver(ws.path(), Arc::new(CostTracker::new()));
    let rm = RunManager::new(Arc::new(NoopBus));
    let crit = SuccessCriteria {
        evaluator: None,
        objectives: vec![primary_file_objective()],
        per_iteration_budget: None,
        fail_fast: Some(vec![FailFastMetric {
            metric_source: MetricSource::Event {
                event_type: "custom.signal".to_string(),
                payload_key: None,
                filter: None,
            },
            predicate: None,
        }]),
        safety_valve: None,
    };
    let run_id = mint_auto_run(&driver, &rm, "root", crit.clone(), RunConfig::default())
        .await
        .expect("mint");
    driver
        .iteration_start("root", Some(run_id.to_string()), 1)
        .await
        .expect("iteration_start");
    let outcome = run_guarded_iteration_with_file_reader(
        &driver,
        &crit,
        &UnusedComp,
        None,
        inputs(run_id.as_ref(), 1, None),
    )
    .await
    .expect("guarded iteration");
    assert!(
        matches!(
            outcome,
            IterationOutcome::Continue {
                status: IterationStatus::Crash,
                ..
            }
        ),
        "Event-source fail_fast (reader deferred) → fail-closed crash: {outcome:?}"
    );
}

#[tokio::test]
async fn ut2_threshold_source_without_threshold_is_fail_closed() {
    // A threshold-source (File) fail_fast metric with a predicate that has an op
    // but NO threshold: `predicate_breached` returns false on a None threshold, so
    // it would silently PASS → the branch fail-CLOSES (audit-r1 Codex-Diff-W3).
    let ws = git_ws();
    let driver = prod_driver(ws.path(), Arc::new(CostTracker::new()));
    let rm = RunManager::new(Arc::new(NoopBus));
    let crit = SuccessCriteria {
        evaluator: None,
        objectives: vec![primary_file_objective()],
        per_iteration_budget: None,
        fail_fast: Some(vec![FailFastMetric {
            metric_source: MetricSource::File {
                path: "ff.json".to_string(),
                key: "e".to_string(),
            },
            // predicate present but threshold absent → under-specified.
            predicate: Some(Predicate {
                op: Op::Gt,
                threshold: None,
            }),
        }]),
        safety_valve: None,
    };
    // Even with a breaching file present, the under-specified predicate must
    // fail-close BEFORE the read (never silently pass).
    std::fs::write(ws.path().join("ff.json"), br#"{"e": 999.0}"#).unwrap();
    let file_reader = DefaultFileMetricReader::new(ws.path());
    let run_id = mint_auto_run(&driver, &rm, "root", crit.clone(), RunConfig::default())
        .await
        .expect("mint");
    driver
        .iteration_start("root", Some(run_id.to_string()), 1)
        .await
        .expect("iteration_start");
    let outcome = run_guarded_iteration_with_file_reader(
        &driver,
        &crit,
        &UnusedComp,
        Some(&file_reader),
        inputs(run_id.as_ref(), 1, None),
    )
    .await
    .expect("guarded iteration");
    assert!(
        matches!(
            outcome,
            IterationOutcome::Continue {
                status: IterationStatus::Crash,
                ..
            }
        ),
        "threshold source with no threshold → fail-closed crash: {outcome:?}"
    );
}

// ─────────────────────────── UT-4: minter compensation ──────────────────────

#[tokio::test]
async fn ut4_minter_register_at_capacity_stops_and_no_half_state() {
    // Fill the driver's run-mapping map to MAX_AUTO_ID_MAPPINGS (8192) with
    // distinct dummy run_ids so the minter's register_run trips AtCapacity AFTER
    // a successful start — witnessing the driver.stop compensation.
    let driver =
        DefaultAutoLoopDriver::new(Arc::new(NoopCkptForCapacity), Arc::new(NoopRbForCapacity));
    for i in 0..8192 {
        driver
            .register_run(&format!("run-fill-{i}"), "filler")
            .expect("prefill register_run");
    }
    let rm = RunManager::new(Arc::new(NoopBus));
    let crit = SuccessCriteria {
        evaluator: None,
        objectives: vec![primary_file_objective()],
        per_iteration_budget: None,
        fail_fast: None,
        safety_valve: None,
    };
    let res = mint_auto_run(&driver, &rm, "root", crit, RunConfig::default()).await;
    assert!(
        matches!(res, Err(AutoMintError::Register(_))),
        "register_run AtCapacity → Register error, got {res:?}"
    );
    assert!(
        driver.status("root").await.is_none(),
        "the started session must be rolled back by driver.stop → no half-state"
    );
}

// Noop checkpoint/rollback for the capacity test (no git needed — the minter
// never reaches an iteration).
use advance_scheduler_auto_loop::{
    AutoLoopDriver, AutoLoopError, IterationCheckpoint, IterationRollback,
};
use async_trait::async_trait;
struct NoopCkptForCapacity;
#[async_trait]
impl IterationCheckpoint for NoopCkptForCapacity {
    async fn checkpoint_baseline(&self, _a: &str) -> Result<(), AutoLoopError> {
        Ok(())
    }
    async fn checkpoint_iteration(&self, _a: &str, _n: u32) -> Result<(), AutoLoopError> {
        Ok(())
    }
}
struct NoopRbForCapacity;
#[async_trait]
impl IterationRollback for NoopRbForCapacity {
    async fn rollback_iteration(&self, _a: &str, _n: u32) -> Result<(), AutoLoopError> {
        Ok(())
    }
}

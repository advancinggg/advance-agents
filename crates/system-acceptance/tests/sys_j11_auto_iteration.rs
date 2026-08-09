//! SYS-J-11 (auto iteration: checkpoint → run → score → keep/rollback → results)
//! system-acceptance witnesses. Drives the PRODUCTION cli auto-loop composition
//! (`build_auto_loop_driver`) over a REAL git workspace; `auto.*` events land on
//! a REAL capturing EventBus. The coordinator-invocation seam (driving
//! `iteration_start`/`close_iteration`) is harness-supplied per MODULE-015 §3.6.
//!
//! Flips: SYS-AC-031 / 032 / 033 / 201 / 202. (SYS-AC-201 added Wave-14 Lane B:
//! the production `ExecutingComponentMetricReader` now REALLY RUNS a committed
//! evaluator fixture → its returned metric drives the guardrail predicate →
//! crash + rollback + `auto.iteration_crashed`; see the 201 witnesses below.)
//!
//! SYS-AC-202 (MAINLINE Wave-5 harvest 2026-06-21): the prior deferral
//! ("breach→crash causation harness-stitched via a caller-set `crashed` flag")
//! is STALE — the Stage-F/autotail `crash_coordinator::run_guarded_iteration`
//! (cli) now computes the per-iteration `Breach` (`check_per_iteration_budget`)
//! and sets `crashed:true` INTERNALLY (`close_crashed`). The harness supplies
//! ONLY the cost INPUT + the iteration facts and calls the production coordinator
//! fn — it never sets the crash flag (the product DECIDES). Same "harness drives
//! a production composition fn (no production tick-loop caller yet)" precedent as
//! the flipped SYS-AC-098/101/109.

mod stepd_auto_support;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;

use advance_cli::crash_coordinator::{run_guarded_iteration, GuardedIterationInputs};
use advance_scheduler_auto_loop::config::Op;
use advance_scheduler_auto_loop::{
    AutoLoopDriver, BudgetStatus, ComponentMetricReader, IterationOutcome, IterationStatus,
    MetricReadError, PerIterationBudget,
};

use stepd_auto_support::{
    build_executing_evaluator_reader, close_ctx, commit_file, criteria_with_budget,
    criteria_with_component_guardrail, primary_criteria, run_cost, tag_exists,
    try_build_evaluator_reader_with_caps, AutoWired, MockCostTracker, WireOpts,
};

// Wave-14 Lane B (SYS-AC-201) — two DISTINCT committed evaluator fixtures. The
// score lives ONLY inside each compiled WASM core module (hi=0.95, lo=0.40); a
// reader that didn't execute the binary cannot know it (value-binding floor).
const EVAL_HI_CORE: &[u8] = include_bytes!("fixtures/guest-rust-evaluator-hi.core.wasm");
const EVAL_LO_CORE: &[u8] = include_bytes!("fixtures/guest-rust-evaluator-lo.core.wasm");

// SYS-AC-031: each auto iteration first creates a Git checkpoint tag
// (checkpoint/{agent-id}/auto-iter-N) BEFORE running the agent. Witnessed by the
// iteration_start PRE-RUN hook: the real M003 tag exists + auto.iteration_started
// is emitted, ordered before any close event.
#[tokio::test]
async fn sys_ac_031_iteration_start_creates_checkpoint_before_run() {
    let w = AutoWired::build(WireOpts::default());
    w.driver
        .start("root", primary_criteria(Op::Lt))
        .await
        .expect("start");

    w.driver
        .iteration_start("root", Some("run-root".to_string()), 1)
        .await
        .expect("iteration_start");

    // Real M003 checkpoint tag created at iteration-start (the pre-run hook).
    assert!(
        tag_exists(w.ws(), &w.tag("root", 1)),
        "auto-iter-1 checkpoint tag must exist after iteration_start"
    );
    assert_eq!(
        w.bus.event_count("auto.iteration_started"),
        1,
        "exactly one auto.iteration_started on the real bus"
    );

    // Close keep → the started event precedes the close (pre-run position).
    let out = w
        .driver
        .close_iteration(close_ctx("root", 1, Some(0.5), false))
        .await
        .expect("close");
    assert!(matches!(
        out,
        IterationOutcome::Continue {
            status: IterationStatus::Keep,
            ..
        }
    ));
    let started = w
        .bus
        .first_index_of("auto.iteration_started")
        .expect("started index");
    let kept = w
        .bus
        .first_index_of("auto.iteration_kept")
        .expect("kept index");
    assert!(
        started < kept,
        "checkpoint/started must precede the iteration close"
    );
}

// SYS-AC-032: a kept iteration emits auto.iteration_kept; a non-improving
// iteration emits auto.iteration_discarded AND rolls back to the prior
// checkpoint (real M003). Keep-then-discard proves previous_best was updated.
#[tokio::test]
async fn sys_ac_032_keep_then_discard_emits_events_and_rolls_back() {
    let w = AutoWired::build(WireOpts::default());
    w.driver
        .start("root", primary_criteria(Op::Lt))
        .await
        .expect("start");

    // iter 1: baseline 0.5 → keep (sets previous_best = 0.5).
    w.driver
        .iteration_start("root", Some("run-root".to_string()), 1)
        .await
        .expect("is1");
    let o1 = w
        .driver
        .close_iteration(close_ctx("root", 1, Some(0.5), false))
        .await
        .expect("c1");
    assert!(matches!(
        o1,
        IterationOutcome::Continue {
            status: IterationStatus::Keep,
            ..
        }
    ));

    // iter 2: checkpoint, mutate post-checkpoint, then non-improving 0.9 →
    // discard + rollback to the iter-2 checkpoint.
    w.driver
        .iteration_start("root", Some("run-root".to_string()), 2)
        .await
        .expect("is2");
    commit_file(w.ws(), "work.txt", b"mutated");
    let o2 = w
        .driver
        .close_iteration(close_ctx("root", 2, Some(0.9), false))
        .await
        .expect("c2");
    assert!(
        matches!(
            o2,
            IterationOutcome::Continue {
                status: IterationStatus::Discard,
                ..
            }
        ),
        "0.9 is NOT < previous_best 0.5 → discard (proves previous_best updated on keep)"
    );

    assert_eq!(w.bus.event_count("auto.iteration_kept"), 1);
    assert_eq!(w.bus.event_count("auto.iteration_discarded"), 1);

    // Real M003 rollback reverted work.txt to the iter-2 checkpoint baseline.
    let content = std::fs::read(w.ws().join("work.txt")).expect("read work.txt");
    assert_eq!(
        content, b"baseline",
        "discard must roll work.txt back to the iter-2 checkpoint"
    );
}

// SYS-AC-033: every iteration appends one record to .agent/auto/results.jsonl
// with status in {keep,discard,crash} plus metric/cost/wall_time fields.
#[tokio::test]
async fn sys_ac_033_each_iteration_appends_one_results_row() {
    let w = AutoWired::build(WireOpts {
        results: true,
        ..Default::default()
    });
    w.driver
        .start("root", primary_criteria(Op::Lt))
        .await
        .expect("start");

    // keep (0.5 baseline), discard (0.9), keep (0.4 improves).
    for (i, m) in [0.5_f64, 0.9, 0.4].iter().enumerate() {
        let n = (i + 1) as u32;
        w.driver
            .iteration_start("root", Some("run-root".to_string()), n)
            .await
            .expect("is");
        w.driver
            .close_iteration(close_ctx("root", n, Some(*m), false))
            .await
            .expect("c");
    }

    let content = std::fs::read_to_string(w.ws().join(".agent/auto/results.jsonl"))
        .expect("read results.jsonl");
    let lines: Vec<&str> = content.lines().collect();
    assert_eq!(lines.len(), 3, "exactly 3 results rows (one per iteration)");

    let statuses: Vec<String> = lines
        .iter()
        .map(|l| {
            serde_json::from_str::<serde_json::Value>(l).unwrap()["status"]
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect();
    assert_eq!(statuses, vec!["keep", "discard", "keep"]);

    for l in &lines {
        let v: serde_json::Value = serde_json::from_str(l).unwrap();
        for f in [
            "iter",
            "checkpoint",
            "metric",
            "status",
            "cost_usd",
            "wall_time_sec",
            "summary",
        ] {
            assert!(v.get(f).is_some(), "results row missing field `{f}`");
        }
        assert!(
            v["metric"]
                .as_object()
                .map(|o| !o.is_empty())
                .unwrap_or(false),
            "metric object must be populated (ctx.metrics), not empty {{}}"
        );
    }
}

// A trivial guardrail metric reader — the budget branch fires FIRST in
// run_guarded_iteration, and criteria_with_budget has no Guardrail objectives, so
// this is never actually read; it only satisfies the coordinator's signature.
struct PassingReader;
impl ComponentMetricReader for PassingReader {
    fn read_component_metric(&self, _output_key: &str) -> Result<f64, MetricReadError> {
        Ok(0.0)
    }
}

// SYS-AC-202 — an iteration breaching a per-iteration budget limit is force-ended
// via the PRODUCT crash coordinator: rolled back + appended to results.jsonl with
// status:crash + auto.iteration_crashed (reason = the product-computed breach).
#[tokio::test]
async fn sys_ac_202_per_iteration_budget_breach_to_crash_row() {
    // The cost INPUT (60k tokens) the harness supplies — NOT the crash decision.
    let cost = Arc::new(MockCostTracker::new().with_cost("run-root", 1, run_cost(60_000, 0, 0.0)));
    let w = AutoWired::build(WireOpts {
        results: true,
        cost: Some(cost),
        ..Default::default()
    });
    // The budget config is driver-authoritative (check_per_iteration_budget reads
    // AutoState.criteria.per_iteration_budget); the SAME criteria is passed to the
    // coordinator (the trust contract — same config the session started with).
    let criteria = criteria_with_budget(PerIterationBudget {
        max_tokens: Some(50_000),
        max_wall_time_sec: None,
        max_cost_usd: None,
    });
    w.driver
        .start("root", criteria.clone())
        .await
        .expect("start");
    w.driver
        .iteration_start("root", Some("run-root".to_string()), 1)
        .await
        .expect("is");
    commit_file(w.ws(), "work.txt", b"mutated");

    // Pre-check: the REAL product budget check observes the Tokens breach (60k > 50k).
    let t0 = Instant::now();
    assert!(
        matches!(
            w.driver
                .check_per_iteration_budget("root", "run-root", 1, t0, t0),
            BudgetStatus::Breach(_)
        ),
        "the per-iteration token budget is really breached (60k > 50k)"
    );

    // THE PRODUCT-DECIDED CRASH: run_guarded_iteration computes the Breach and sets
    // `crashed:true` INTERNALLY (close_crashed). The harness passes ONLY inputs
    // (cost facts + iteration ids) — never `crashed`.
    let inputs = GuardedIterationInputs {
        agent_id: "root".to_string(),
        run_id: "run-root".to_string(),
        iteration: 1,
        checkpoint_label: "auto-iter-1".to_string(),
        primary_metric: None,
        metrics: BTreeMap::new(),
        cost_usd: 0.0,
        wall_time_sec: 1,
        summary: None,
        started_at: t0,
        now: t0,
    };
    let out = run_guarded_iteration(w.driver.as_ref(), &criteria, &PassingReader, inputs)
        .await
        .expect("guarded iteration");

    // (1) the product returned a Crash close (the breach was force-ended).
    assert!(
        matches!(
            out,
            IterationOutcome::Continue {
                status: IterationStatus::Crash,
                ..
            }
        ),
        "the budget breach is force-ended via the crash path"
    );
    // (2) auto.iteration_crashed carries the PRODUCT-COMPUTED breach reason — the
    // load-bearing discriminator: a harness-set flag could not produce this exact
    // breach string ("...per-iteration budget breach: tokens observed=60000 ...").
    let crashed = w.bus.events_of("auto.iteration_crashed");
    assert_eq!(crashed.len(), 1, "exactly one auto.iteration_crashed");
    let reason = crashed[0]
        .payload
        .get("reason")
        .and_then(|r| r.as_str())
        .unwrap_or_default();
    assert!(
        reason.contains("per-iteration budget breach"),
        "crash reason is the product-computed breach, not a harness flag; got {reason:?}"
    );
    // (3) REAL git rollback to the iter-1 checkpoint (workspace restored).
    assert_eq!(
        std::fs::read(w.ws().join("work.txt")).unwrap(),
        b"baseline",
        "crash rolled the workspace back to the iter-1 checkpoint"
    );
    // (4) results.jsonl status:crash row.
    let content = std::fs::read_to_string(w.ws().join(".agent/auto/results.jsonl"))
        .expect("read results.jsonl");
    let row: serde_json::Value =
        serde_json::from_str(content.lines().next().expect("one row")).unwrap();
    assert_eq!(row["status"], "crash");
}

// SYS-AC-201 — an iteration whose Pack guardrail metric FAILS its threshold is
// recorded status:crash, rolled back to the prior checkpoint, and emits
// auto.iteration_crashed (distinct from the non-improving discard path). The
// metric is produced by a REAL evaluator-component run via the PRODUCTION
// `ExecutingComponentMetricReader` (NOT a hand-fed value, NOT a caller-set
// `crashed` flag) — the witness-floor that kept 201 deferred is now satisfied.
// The harness drives the PRODUCTION `run_guarded_iteration` with the REAL reader
// (the SYS-AC-202/098/101/109 "drive-prod-fn, no-production-caller-yet" precedent).
#[tokio::test]
async fn sys_ac_201_guardrail_component_metric_crash() {
    let w = AutoWired::build(WireOpts {
        results: true,
        ..Default::default()
    });
    // Guardrail BREACH-predicate: score > 0.8 → breach → crash. The committed hi
    // fixture's run() returns {"score":0.95}; 0.95 > 0.8 breaches.
    let criteria = criteria_with_component_guardrail("score", Op::Gt, 0.8);
    w.driver
        .start("root", criteria.clone())
        .await
        .expect("start");
    w.driver
        .iteration_start("root", Some("run-root".to_string()), 1)
        .await
        .expect("iteration_start");
    // Post-checkpoint mutation to prove the crash rollback reverts the workspace.
    commit_file(w.ws(), "work.txt", b"mutated");

    // THE WITNESS-FLOOR ORACLE: the production reader REALLY instantiates + runs
    // the committed evaluator WASM and parses its returned {"score":0.95}.
    let reader = build_executing_evaluator_reader(EVAL_HI_CORE).await;

    let t0 = Instant::now();
    let inputs = GuardedIterationInputs {
        agent_id: "root".to_string(),
        run_id: "run-root".to_string(),
        iteration: 1,
        checkpoint_label: "auto-iter-1".to_string(),
        primary_metric: None,
        metrics: BTreeMap::new(),
        cost_usd: 0.0,
        wall_time_sec: 1,
        summary: None,
        started_at: t0,
        now: t0,
    };
    // PRODUCT-DECIDED CRASH: run_guarded_iteration reads the guardrail metric via
    // the REAL reader → predicate_breached → close_crashed. The harness never sets
    // `crashed` and never feeds the metric.
    let out = run_guarded_iteration(w.driver.as_ref(), &criteria, &reader, inputs)
        .await
        .expect("guarded iteration");

    // (1) the product returned a Crash close (the guardrail breach was force-ended).
    assert!(
        matches!(
            out,
            IterationOutcome::Continue {
                status: IterationStatus::Crash,
                ..
            }
        ),
        "the guardrail-metric breach is force-ended via the crash path"
    );
    // (2) auto.iteration_crashed carries the PRODUCT-COMPUTED guardrail breach
    // reason embedding the REAL evaluator metric 0.95 — the load-bearing
    // discriminator: a stub reader (or a hand-fed value) could not produce this
    // exact metric from a real component run.
    let crashed = w.bus.events_of("auto.iteration_crashed");
    assert_eq!(crashed.len(), 1, "exactly one auto.iteration_crashed");
    let reason = crashed[0]
        .payload
        .get("reason")
        .and_then(|r| r.as_str())
        .unwrap_or_default();
    assert!(
        reason.contains("guardrail breach"),
        "crash reason is the product-computed guardrail breach; got {reason:?}"
    );
    assert!(
        reason.contains("0.95"),
        "crash reason embeds the REAL evaluator metric 0.95 read from the WASM run; got {reason:?}"
    );
    // (3) REAL git rollback to the iter-1 checkpoint (workspace restored).
    assert_eq!(
        std::fs::read(w.ws().join("work.txt")).unwrap(),
        b"baseline",
        "crash rolled the workspace back to the iter-1 checkpoint"
    );
    // (4) results.jsonl status:crash row.
    let content = std::fs::read_to_string(w.ws().join(".agent/auto/results.jsonl"))
        .expect("read results.jsonl");
    let row: serde_json::Value =
        serde_json::from_str(content.lines().next().expect("one row")).unwrap();
    assert_eq!(row["status"], "crash");
}

// SYS-AC-201 discriminator (DISTINCT binary): the SAME breach-predicate (score >
// 0.8) over the lo fixture (returns {"score":0.40}) → 0.40 > 0.8 is false → NO
// breach → normal keep/discard close, ZERO auto.iteration_crashed. Using a
// distinct compiled binary (not merely a different threshold) binds the outcome
// to the real per-component metric — defeats a constant-returning fake-green.
#[tokio::test]
async fn sys_ac_201_passing_component_metric_no_crash() {
    let w = AutoWired::build(WireOpts {
        results: true,
        ..Default::default()
    });
    let criteria = criteria_with_component_guardrail("score", Op::Gt, 0.8);
    w.driver
        .start("root", criteria.clone())
        .await
        .expect("start");
    w.driver
        .iteration_start("root", Some("run-root".to_string()), 1)
        .await
        .expect("iteration_start");

    let reader = build_executing_evaluator_reader(EVAL_LO_CORE).await;

    let t0 = Instant::now();
    let inputs = GuardedIterationInputs {
        agent_id: "root".to_string(),
        run_id: "run-root".to_string(),
        iteration: 1,
        checkpoint_label: "auto-iter-1".to_string(),
        primary_metric: None,
        metrics: BTreeMap::new(),
        cost_usd: 0.0,
        wall_time_sec: 1,
        summary: None,
        started_at: t0,
        now: t0,
    };
    let out = run_guarded_iteration(w.driver.as_ref(), &criteria, &reader, inputs)
        .await
        .expect("guarded iteration");

    // Non-breaching metric → NOT a crash (do not pin Keep vs Discard — that's
    // decided by close_iteration's primary_metric/previous_best logic).
    assert!(
        matches!(
            out,
            IterationOutcome::Continue {
                status: IterationStatus::Keep | IterationStatus::Discard,
                ..
            }
        ),
        "0.40 does not breach Gt 0.8 → no crash"
    );
    assert_eq!(
        w.bus.event_count("auto.iteration_crashed"),
        0,
        "a non-breaching guardrail metric produces NO crash event"
    );
}

// SYS-AC-201 value-binding (anti-fake-green): the SAME production reader returns
// 0.95 over the hi binary and 0.40 over the lo binary. A reader that didn't
// actually execute each WASM cannot produce BOTH — this is the floor that
// distinguishes a real evaluator run from a constant-returning stub.
#[tokio::test]
async fn sys_ac_201_reader_reads_distinct_real_component_outputs() {
    let hi = build_executing_evaluator_reader(EVAL_HI_CORE).await;
    let lo = build_executing_evaluator_reader(EVAL_LO_CORE).await;
    assert_eq!(
        hi.read_component_metric("score").expect("hi score"),
        0.95,
        "hi fixture's real run yields 0.95"
    );
    assert_eq!(
        lo.read_component_metric("score").expect("lo score"),
        0.40,
        "lo fixture's real run yields 0.40"
    );
    assert!(
        matches!(
            hi.read_component_metric("missing"),
            Err(MetricReadError::NotFound(_))
        ),
        "an absent output_key fails-CLOSED as NotFound"
    );
}

// SYS-AC-201 capability trust boundary (adversarial round-8 W3): the no-caps
// reader rejects a cap-bearing evaluator fail-CLOSED with a clear error, rather
// than relying on an opaque LinkerTypecheck trap.
#[tokio::test]
async fn sys_ac_201_reader_rejects_cap_bearing_evaluator() {
    use advance_shared_types::capability::{CapRequest, CapabilityId};
    let result = try_build_evaluator_reader_with_caps(
        EVAL_HI_CORE,
        vec![CapRequest {
            capability: CapabilityId::from("fs"),
        }],
    )
    .await;
    assert!(
        matches!(result, Err(MetricReadError::Parse(_))),
        "a cap-bearing evaluator must be rejected fail-CLOSED on the no-caps execution path"
    );
}

// SYS-AC-201 fixture sanity: the committed core modules encode to valid
// Components (guards a corrupt checked-in .core.wasm before the e2e relies on it).
#[test]
fn sys_ac_201_fixture_core_modules_encode_to_components() {
    for core in [EVAL_HI_CORE, EVAL_LO_CORE] {
        let component = build_agent::encode_core_to_component(core)
            .expect("fixture core encodes to a Component");
        assert_eq!(&component[0..4], b"\0asm", "WASM magic");
        assert_eq!(
            component[4], 0x0d,
            "component-model version byte (0x0d), not core-module 0x01"
        );
    }
}

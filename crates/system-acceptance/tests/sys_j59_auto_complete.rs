//! SYS-J-59 (complete-cycle ends the Auto loop; cancel transitions to Cancelled)
//! system-acceptance witnesses.
//!
//! Flips: SYS-AC-184 (after completion the loop schedules zero further iterations —
//! the terminal guard refuses the next iteration_start; the DRIVER's OWN internal
//! terminal property), and — Wave-8 Lane A — SYS-AC-183 / 185, now PRODUCT-driven.
//!
//! 183/185 re-point (Wave-8 Lane A, 2026-06-22): the Wave-7 Lane B autotick lane MERGED the
//! production auto tick caller — `start.rs:333-344` constructs the `AutoTickCoordinator`
//! (Wave-6 Lane C) + the `AutoTickExtension`, registers ONLY the extension on a `Scheduler`,
//! and spawns `run_scheduler_tick_loop`, so on each tick the PRODUCT coordinator makes the
//! load-bearing `RunManager::complete_run` (183) / `cancel_run_for_agent` (185) call. The ONLY
//! un-wired seams are `AutoTickExtension::register_session` / `request_cancel` (the dormant
//! `advance auto start` / `cancel` boot install points, zero production caller). These
//! witnesses play exactly that un-called caller (the 098/101/109 no-production-caller
//! precedent) via `AutoWired::auto_tick_extension()` + `register_session` / `request_cancel` +
//! `on_tick`; the PRODUCT settles the run. Materially different from the 3× prior defer, where
//! the witness ITSELF called `complete_run` / `cancel_run_for_agent` (harness-supplied
//! cross-component settlement). The witnesses MUST NOT call those run-manager ops directly.

mod stepd_auto_support;

use std::sync::Arc;

use advance_cli::auto_wiring::build_auto_round_advancer;
use advance_scheduler::{SchedulerExtension, SchedulerTick};
use advance_scheduler_auto_loop::config::Op;
use advance_scheduler_auto_loop::{
    AutoLoopDriver, AutoLoopError, AutoStatus, CompletionSummary, IterationOutcome,
    IterationStatus, Transition,
};
use advance_shared_types::run::{RoundDecision, RoundResult, TaskRunStatus};

use stepd_auto_support::{auto_iter_tag_count, close_ctx, primary_criteria, AutoWired, WireOpts};

// SYS-AC-184: after completion the AutoLoopDriver schedules zero further
// iterations (no new auto-iter-N checkpoint). Non-degenerate: run a REAL
// iteration first, then complete-cycle, then prove the terminal guard refuses
// the next iteration_start (the positive halt witness) + the tag/event counts
// are unchanged.
#[tokio::test]
async fn sys_ac_184_no_iterations_after_completion() {
    let w = AutoWired::build(WireOpts {
        results: true,
        ..Default::default()
    });
    w.driver
        .start("root", primary_criteria(Op::Lt))
        .await
        .expect("start");

    // A real iteration runs (the loop genuinely ran).
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
    let tags_before = auto_iter_tag_count(w.ws(), "root");
    assert_eq!(tags_before, 1, "one iteration ran");
    let started_before = w.bus.event_count("auto.iteration_started");

    // Complete-cycle terminal transition.
    let st = w
        .driver
        .transition_status("root", Transition::CompleteCycle)
        .expect("transition CompleteCycle");
    assert_eq!(st, AutoStatus::Completed);
    assert_eq!(w.driver.status("root").await, Some(AutoStatus::Completed));

    // The next iteration_start is REFUSED by the terminal guard, BEFORE creating
    // a checkpoint (driver.rs:477).
    let err = w
        .driver
        .iteration_start("root", Some("run-root".to_string()), 2)
        .await
        .expect_err("iteration_start must be refused on a Completed session");
    assert!(
        matches!(err, AutoLoopError::NotIterating(_, AutoStatus::Completed)),
        "got {err:?}"
    );

    // Zero further iterations scheduled: no new auto-iter tag, no new started event.
    assert_eq!(
        auto_iter_tag_count(w.ws(), "root"),
        tags_before,
        "no new auto-iter checkpoint after completion"
    );
    assert_eq!(
        w.bus.event_count("auto.iteration_started"),
        started_before,
        "no new auto.iteration_started after completion"
    );
}

// SYS-AC-183 — FLIPPED (Wave-8 Lane A, PRODUCT-driven settle). An agent's complete-cycle(summary)
// ends the Auto loop: the iteration is scored (exactly one results.jsonl row) and the Auto run
// transitions to Completed via `RunManager::complete_run` (run.completed), with the advancer's
// RETURNED `Blocked("completed: …")` decision the buffer-only observable (no `run.round_completed`
// — auto-mode `complete_round` is buffer-only per PRD A.24, asserted == 0).
//
// Witness-floor: the witness supplies the AGENT-side inputs — the keep iteration +
// `record_complete_cycle_request` (the agent's recorded complete-cycle INTENT; it has no
// guest-WASM-in-auto-loop production caller, so the agent side is harness-driven for EVERY auto
// witness, incl. the passed 184/256/258) — and plays the dormant `register_session` caller. The
// PRODUCT `AutoTickExtension::on_tick` → `run_settle_pass` → `AutoTickCoordinator::settle_completed`
// makes the load-bearing CROSS-COMPONENT `complete_run` call. THAT cross-component settle is the
// 3×-deferred gap (the advancer only COMPOSED `Blocked("completed")`; no production coordinator
// bridged it to `complete_run`), now closed by the merged Wave-7 Lane B tick caller. The witness
// MUST NOT call complete_run / settle_completed, and MUST NOT pre-transition the driver (that would
// be AlreadySettled → no complete_run, a half-real green).
#[tokio::test]
async fn sys_ac_183_complete_cycle() {
    let w = AutoWired::build(WireOpts {
        results: true,
        ..Default::default()
    });
    w.driver
        .start("root", primary_criteria(Op::Lt))
        .await
        .expect("start");
    // Mint the PRODUCT run_id (run-{uuid}, colon-free) + register run_id->agent. settle_completed
    // peeks the complete-cycle by AGENT but settles the Run by RUN_ID, so this binding (and the
    // record_complete_cycle_request below) are BOTH load-bearing.
    let rid = w.mint_auto_run("root");

    // One real iteration (keep) — sets last_iteration_status=Keep + one results row.
    w.driver
        .iteration_start("root", Some(rid.to_string()), 1)
        .await
        .expect("is");
    w.driver
        .close_iteration(close_ctx("root", 1, Some(0.5), false))
        .await
        .expect("c");

    // Agent records complete-cycle (the never-cleared PEEK the coordinator's settle gate reads
    // by agent_id — must be present before the tick).
    w.driver
        .record_complete_cycle_request(
            "root",
            CompletionSummary {
                outcome: "research-converged".to_string(),
                final_metrics: vec![],
            },
        )
        .expect("record_complete_cycle_request");

    // The advancer's RETURNED decision carries the completed reason (buffer-only — it does NOT
    // settle the run or clear the peek; the criterion's "advancer's RETURNED Blocked decision").
    let advancer = build_auto_round_advancer(Arc::clone(&w.driver));
    let dec = advancer
        .on_complete_round(
            rid.as_ref(),
            RoundResult {
                summary: None,
                metrics: vec![],
            },
        )
        .await
        .expect("on_complete_round");
    assert!(
        matches!(dec, RoundDecision::Blocked(ref s) if s.contains("completed") && s.contains("keep")),
        "advancer decision must carry the completed/blocked reason; got {dec:?}"
    );

    // ── PRODUCT-DRIVEN SETTLE ── the witness registers the session on the production extension
    // and ticks it. run_settle_pass runs the (progress-clean) cadence pass first, drains no
    // cancels, then settles the registered session → coordinator.settle_completed → driver
    // CompleteCycle (Active→Completed) → complete_run. The witness calls NEITHER complete_run
    // NOR settle_completed itself, and never pre-transitions the driver.
    let ext = w.auto_tick_extension();
    ext.register_session("root", rid.to_string());
    ext.on_tick(SchedulerTick::new(1_000)).await;

    // The PRODUCT tick drove the driver Active→Completed (not the witness).
    assert_eq!(
        w.driver.status("root").await,
        Some(AutoStatus::Completed),
        "the production tick transitioned the driver Active→Completed"
    );
    // run-status → Completed via the coordinator's complete_run (run.completed, NOT
    // run.round_completed — proving the buffer-only nuance honestly).
    assert!(matches!(
        w.rm.snapshot_status_for_test(&rid),
        Some(TaskRunStatus::Completed)
    ));
    assert_eq!(w.bus.event_count("run.completed"), 1);
    assert_eq!(
        w.bus.event_count("run.round_completed"),
        0,
        "auto-mode complete_round is buffer-only — no run.round_completed event"
    );

    // Terminal settle deregistered the session (no re-poll of the never-cleared peek).
    assert_eq!(ext.session_count(), 0, "settled session deregistered");

    // Exactly one results row.
    let content = std::fs::read_to_string(w.ws().join(".agent/auto/results.jsonl")).unwrap();
    assert_eq!(content.lines().count(), 1);
}

// SYS-AC-185 — FLIPPED (Wave-8 Lane A, PRODUCT-driven). An operator cancel against the Auto run
// transitions it to Cancelled (distinct from Completed) and halts iteration: `run.cancelled` +
// driver `AutoStatus::Cancelled` + a subsequent `iteration_start` returning `NotIterating`. The
// settlement is PRODUCT-driven: the witness sets up the agent-side run (start + one iteration) and
// plays the dormant `register_session`/`request_cancel` callers; the PRODUCT
// `AutoTickExtension::on_tick` → `run_settle_pass` drains the cancel → `AutoTickCoordinator::cancel`
// → `handle_manual_cancel` (driver→Cancelled) + the load-bearing CROSS-COMPONENT
// `cancel_run_for_agent` (agent-scoped → run.cancelled). The witness MUST NOT call
// cancel_run_for_agent itself, and keeps the 1-agent-1-run contract (one `auto:root` Run —
// cancel_run_for_agent is agent-scoped, InvalidState on >1).
#[tokio::test]
async fn sys_ac_185_cancel() {
    let w = AutoWired::build(WireOpts::default());
    w.driver
        .start("root", primary_criteria(Op::Lt))
        .await
        .expect("start");
    let rid = w.mint_auto_run("root");
    w.driver
        .iteration_start("root", Some(rid.to_string()), 1)
        .await
        .expect("is");

    // ── PRODUCT-DRIVEN CANCEL ── register the session + enqueue the operator cancel on the
    // production extension, then tick it: run_settle_pass runs the (clean) cadence pass, drains
    // the pending cancel → coordinator.cancel → handle_manual_cancel (driver→Cancelled) +
    // cancel_run_for_agent (run.cancelled), then deregisters the agent.
    let ext = w.auto_tick_extension();
    ext.register_session("root", rid.to_string());
    ext.request_cancel("root", "user-stop");
    ext.on_tick(SchedulerTick::new(1_000)).await;

    // Driver-side → AutoStatus::Cancelled (distinct enum), product-driven.
    assert_eq!(w.driver.status("root").await, Some(AutoStatus::Cancelled));
    // run-status → Cancelled + run.cancelled (the coordinator's cancel_run_for_agent settle).
    assert!(matches!(
        w.rm.snapshot_status_for_test(&rid),
        Some(TaskRunStatus::Cancelled(_))
    ));
    assert_eq!(w.bus.event_count("run.cancelled"), 1);
    // The agent-scoped cancel deregistered the agent's session.
    assert_eq!(ext.session_count(), 0, "cancelled agent deregistered");

    // Iteration halted: the terminal guard refuses the next iteration_start.
    let err = w
        .driver
        .iteration_start("root", Some(rid.to_string()), 2)
        .await
        .expect_err("halted");
    assert!(matches!(
        err,
        AutoLoopError::NotIterating(_, AutoStatus::Cancelled)
    ));
}

//! Stage-D integrated §4.7.7 loop: `iteration_start` + `close_iteration`
//! orchestrators — keep/discard/crash decision, `previous_best` update
//! (proven by keep→discard chaining), rollback on crash (real git), skill
//! apply_discard fail-CLOSED vs recording, and `auto.iteration_*` emission.

mod common;

use std::collections::BTreeMap;
use std::sync::Arc;

use advance_git::{DefaultNamedCheckpoint, DefaultWorkspaceRollback};
use advance_scheduler_auto_loop::{
    config::{MetricSource, Objective, Op, Predicate, Role, SuccessCriteria},
    event_sink::event_type,
    AutoLoopDriver, DefaultAutoLoopDriver, DefaultIterationCheckpoint, DefaultIterationRollback,
    IterationCloseCtx, IterationOutcome, IterationStatus, ResultsWriter,
};

use common::{
    bootstrap_repo_with_initial_commit, commit_file, NoopIterationCheckpoint,
    NoopIterationRollback, RecordedCall, RecordingIterationEventSink, RecordingSkillRollback,
};

/// Primary-only `success_criteria` with `op` (lower-better = Lt).
fn primary_criteria(op: Op) -> SuccessCriteria {
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
                op,
                threshold: None,
            },
        }],
        per_iteration_budget: None,
        fail_fast: None,
        safety_valve: None,
    }
}

fn ctx(agent: &str, iter: u32, primary: Option<f64>, crashed: bool) -> IterationCloseCtx {
    let mut metrics = BTreeMap::new();
    if let Some(m) = primary {
        metrics.insert("val_bpb".to_string(), m);
    }
    IterationCloseCtx {
        agent_id: agent.to_string(),
        run_id: Some(format!("run-{agent}")),
        iteration: iter,
        checkpoint_label: format!("auto-iter-{iter}"),
        primary_metric: primary,
        metrics,
        crashed,
        crash_reason: if crashed {
            Some("boom".to_string())
        } else {
            None
        },
        summary: None,
        cost_usd: 0.0,
        wall_time_sec: 1,
    }
}

// close_iteration keep (first iter, baseline) → then discard (non-improving) →
// proves previous_best is updated on keep. Verifies emitted events + results
// rows. Uses Noop checkpoint/rollback (no git needed for the decision path).
#[tokio::test]
async fn close_keep_then_discard_updates_previous_best() {
    let temp = tempfile::tempdir().unwrap();
    let sink = Arc::new(RecordingIterationEventSink::new());
    let driver = DefaultAutoLoopDriver::new(
        Arc::new(NoopIterationCheckpoint),
        Arc::new(NoopIterationRollback),
    )
    .with_iteration_event_sink(sink.clone())
    .with_results_writer(Arc::new(ResultsWriter::new(temp.path().to_path_buf())));

    driver
        .start("alice", primary_criteria(Op::Lt))
        .await
        .expect("start");

    // iter 1: metric 0.5, no previous_best → keep (baseline).
    let out1 = driver
        .close_iteration(ctx("alice", 1, Some(0.5), false))
        .await
        .unwrap();
    assert!(matches!(
        out1,
        IterationOutcome::Continue {
            status: IterationStatus::Keep,
            ..
        }
    ));

    // iter 2: metric 0.6 — NOT < 0.5 → discard (proves previous_best=0.5 stuck).
    let out2 = driver
        .close_iteration(ctx("alice", 2, Some(0.6), false))
        .await
        .unwrap();
    assert!(matches!(
        out2,
        IterationOutcome::Continue {
            status: IterationStatus::Discard,
            ..
        }
    ));

    // iter 3: metric 0.4 — < 0.5 → keep again (improves the baseline).
    let out3 = driver
        .close_iteration(ctx("alice", 3, Some(0.4), false))
        .await
        .unwrap();
    assert!(matches!(
        out3,
        IterationOutcome::Continue {
            status: IterationStatus::Keep,
            ..
        }
    ));

    // Events: kept, completed, discarded, completed, kept, completed.
    assert_eq!(
        sink.event_types(),
        vec![
            event_type::ITERATION_KEPT,
            event_type::ITERATION_COMPLETED,
            event_type::ITERATION_DISCARDED,
            event_type::ITERATION_COMPLETED,
            event_type::ITERATION_KEPT,
            event_type::ITERATION_COMPLETED,
        ]
    );

    // results.jsonl has 3 rows: keep, discard, keep.
    let content = tokio::fs::read_to_string(temp.path().join(".agent/auto/results.jsonl"))
        .await
        .unwrap();
    let statuses: Vec<String> = content
        .lines()
        .map(|l| {
            serde_json::from_str::<serde_json::Value>(l).unwrap()["status"]
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect();
    assert_eq!(statuses, vec!["keep", "discard", "keep"]);
}

// close_iteration crash → real git rollback restores the workspace + crash
// event + crash results row.
#[tokio::test]
async fn close_crash_rolls_back_real_git() {
    let temp = tempfile::tempdir().unwrap();
    bootstrap_repo_with_initial_commit(temp.path());
    commit_file(temp.path(), "work.txt", b"baseline");

    let ckpt = DefaultNamedCheckpoint::new(temp.path().to_path_buf()).unwrap();
    let rb = DefaultWorkspaceRollback::new(temp.path().to_path_buf()).unwrap();
    let sink = Arc::new(RecordingIterationEventSink::new());
    let driver = DefaultAutoLoopDriver::new(
        Arc::new(DefaultIterationCheckpoint::new(Arc::new(ckpt))),
        Arc::new(DefaultIterationRollback::new(Arc::new(rb))),
    )
    .with_iteration_event_sink(sink.clone())
    .with_results_writer(Arc::new(ResultsWriter::new(temp.path().to_path_buf())));

    driver
        .start("root", primary_criteria(Op::Lt))
        .await
        .unwrap();

    // iteration_start checkpoints iter-1 + emits started.
    driver
        .iteration_start("root", Some("run-root".to_string()), 1)
        .await
        .unwrap();
    commit_file(temp.path(), "work.txt", b"mutated");

    // crash close → rollback to the iter-1 checkpoint (baseline).
    let out = driver
        .close_iteration(ctx("root", 1, None, true))
        .await
        .unwrap();
    assert!(matches!(
        out,
        IterationOutcome::Continue {
            status: IterationStatus::Crash,
            ..
        }
    ));
    assert_eq!(
        std::fs::read(temp.path().join("work.txt")).unwrap(),
        b"baseline",
        "crash must roll the workspace back to the iter-1 checkpoint"
    );
    assert_eq!(
        sink.event_types(),
        vec![
            event_type::ITERATION_STARTED,
            event_type::ITERATION_CRASHED,
            event_type::ITERATION_COMPLETED,
        ]
    );
}

// Discard with recorded skill pre-state + a recording SkillRollback → the
// tracker dispatches the rollback for the recorded skill.
#[tokio::test]
async fn discard_dispatches_skill_rollback() {
    let recorder = Arc::new(RecordingSkillRollback::new());
    let driver = DefaultAutoLoopDriver::new(
        Arc::new(NoopIterationCheckpoint),
        Arc::new(NoopIterationRollback),
    )
    .with_skill_rollback(recorder.clone());

    driver
        .start("alice", primary_criteria(Op::Lt))
        .await
        .unwrap();
    // baseline keep so iter 2 can discard.
    driver
        .close_iteration(ctx("alice", 1, Some(0.5), false))
        .await
        .unwrap();
    // record a skill activated during iter 2 (was at version 2).
    driver.record_skill_pre_activation("alice", "reified-skill", Some(2));

    let out = driver
        .close_iteration(ctx("alice", 2, Some(0.9), false))
        .await
        .unwrap();
    assert!(matches!(
        out,
        IterationOutcome::Continue {
            status: IterationStatus::Discard,
            ..
        }
    ));
    assert_eq!(
        recorder.calls(),
        vec![RecordedCall::Rollback {
            agent_id: "alice".to_string(),
            skill_id: "reified-skill".to_string(),
            target_version: 2,
        }]
    );
}

// Adversarial-r11 W1': record_skill_pre_activation is gated on session-existence
// — a record for an agent with NO live session is a no-op (so the skill_trackers
// map can't grow from synthesized non-session agent_ids). Proven by: a
// pre-session record leaves no tracker entry, so a later discard dispatches NO
// rollback (if the gate were absent, the persisted pre-state would dispatch one).
#[tokio::test]
async fn record_skill_pre_activation_gated_on_session() {
    let recorder = Arc::new(RecordingSkillRollback::new());
    let driver = DefaultAutoLoopDriver::new(
        Arc::new(NoopIterationCheckpoint),
        Arc::new(NoopIterationRollback),
    )
    .with_skill_rollback(recorder.clone());

    // No live session yet → this record must be dropped (gated).
    driver.record_skill_pre_activation("alice", "reified-skill", Some(2));

    driver
        .start("alice", primary_criteria(Op::Lt))
        .await
        .unwrap();
    driver
        .close_iteration(ctx("alice", 1, Some(0.5), false))
        .await
        .unwrap(); // keep baseline
    driver
        .close_iteration(ctx("alice", 2, Some(0.9), false))
        .await
        .unwrap(); // discard
    assert!(
        recorder.calls().is_empty(),
        "a pre-session skill record must be gated → no tracker entry → no rollback dispatched on discard"
    );
}

// Discard with recorded skill pre-state but NO SkillRollback wired →
// fail-CLOSED (SkillRollbackUnwired), NOT a silent Noop-success.
#[tokio::test]
async fn discard_fails_closed_without_skill_rollback() {
    use advance_scheduler_auto_loop::AutoLoopError;
    let driver = DefaultAutoLoopDriver::new(
        Arc::new(NoopIterationCheckpoint),
        Arc::new(NoopIterationRollback),
    ); // NO with_skill_rollback

    driver
        .start("alice", primary_criteria(Op::Lt))
        .await
        .unwrap();
    driver
        .close_iteration(ctx("alice", 1, Some(0.5), false))
        .await
        .unwrap();
    driver.record_skill_pre_activation("alice", "reified-skill", Some(2));

    let err = driver
        .close_iteration(ctx("alice", 2, Some(0.9), false))
        .await
        .expect_err("discard needing skill restoration with no rollback must fail-closed");
    match err {
        AutoLoopError::SkillRollbackUnwired(a) => assert_eq!(a, "alice"),
        other => panic!("expected SkillRollbackUnwired, got {other:?}"),
    }
}

// Adversarial-r10 W2: close_iteration + iteration_start are rejected on a
// terminal (non-iterating) session — a stale/duplicate Finished after the
// session completes must NOT re-roll-back or re-emit.
#[tokio::test]
async fn iteration_ops_rejected_on_terminal_session() {
    use advance_scheduler_auto_loop::{AutoLoopError, Transition};
    let driver = DefaultAutoLoopDriver::new(
        Arc::new(NoopIterationCheckpoint),
        Arc::new(NoopIterationRollback),
    );
    driver
        .start("alice", primary_criteria(Op::Lt))
        .await
        .unwrap();
    // Transition to Completed (terminal).
    driver
        .transition_status("alice", Transition::CompleteCycle)
        .unwrap();

    let err = driver
        .close_iteration(ctx("alice", 1, Some(0.5), false))
        .await
        .expect_err("close on a terminal session must be rejected");
    assert!(matches!(err, AutoLoopError::NotIterating(a, _) if a == "alice"));

    let err2 = driver
        .iteration_start("alice", None, 1)
        .await
        .expect_err("iteration_start on a terminal session must be rejected");
    assert!(matches!(err2, AutoLoopError::NotIterating(_, _)));
}

// Adversarial-r11 W2' / r12-Info: an ERRORED close_iteration (phase-2 ?-exit)
// must clear the close_in_progress flag — a subsequent close must NOT be wedged
// into ConcurrentClose (no self-DoS). Guards against a future refactor moving a
// `?` out of the always-clear async block.
#[tokio::test]
async fn errored_close_does_not_wedge_session() {
    use advance_scheduler_auto_loop::AutoLoopError;
    let driver = DefaultAutoLoopDriver::new(
        Arc::new(NoopIterationCheckpoint),
        Arc::new(NoopIterationRollback),
    ); // NO skill_rollback wired

    driver
        .start("alice", primary_criteria(Op::Lt))
        .await
        .unwrap();
    driver
        .close_iteration(ctx("alice", 1, Some(0.5), false))
        .await
        .unwrap(); // keep baseline
    driver.record_skill_pre_activation("alice", "reified-skill", Some(2));

    // iter2 discard → phase-2 errors (SkillRollbackUnwired) → the async block's
    // `?` returns into `result`; the flag MUST still be cleared afterwards.
    let err = driver
        .close_iteration(ctx("alice", 2, Some(0.9), false))
        .await
        .expect_err("discard with skills but no rollback fails-closed");
    assert!(matches!(err, AutoLoopError::SkillRollbackUnwired(_)));

    // A subsequent close must NOT be rejected with ConcurrentClose (flag cleared)
    // and should succeed (0.4 < the still-0.5 baseline → keep; the errored iter2
    // never reached phase-3, so previous_best is unchanged).
    let out = driver
        .close_iteration(ctx("alice", 3, Some(0.4), false))
        .await;
    assert!(
        !matches!(out, Err(AutoLoopError::ConcurrentClose(_))),
        "an errored close must clear close_in_progress — no self-DoS wedge"
    );
    assert!(matches!(
        out,
        Ok(IterationOutcome::Continue {
            status: IterationStatus::Keep,
            ..
        })
    ));
}

// close_iteration on an unknown agent → NotStarted.
#[tokio::test]
async fn close_iteration_unknown_agent_errors() {
    use advance_scheduler_auto_loop::AutoLoopError;
    let driver = DefaultAutoLoopDriver::new(
        Arc::new(NoopIterationCheckpoint),
        Arc::new(NoopIterationRollback),
    );
    let err = driver
        .close_iteration(ctx("ghost", 1, Some(0.1), false))
        .await
        .unwrap_err();
    assert!(matches!(err, AutoLoopError::NotStarted(a) if a == "ghost"));
}

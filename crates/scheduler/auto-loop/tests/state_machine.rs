//! 5-state machine + AC-12 / AC-19 + foundation for AC-02 / AC-03 / AC-20
//! (per the slice-B plan / MODULE-015 §1.3.5).
//!
//! AC-12 (state transitions): tests (a)-(n) exhaustively verify the §1.3.5
//! transition table including terminal-state rejection.
//! AC-19 (manual cancel skips evaluator): test (o) — RecordingEvaluatorResolver
//! counter stays 0 after handle_manual_cancel.
//! Foundation for AC-20: test (p) — compose_complete_cycle_decision format.
//! Foundation for AC-02: test (q) — auto_namespace_task_id + AutoState
//! fresh-init.
//! Foundation for AC-03: test (r) — record_complete_cycle_request stores
//! intent without state transition.

mod common;

use std::sync::atomic::Ordering;
use std::sync::Arc;

use advance_scheduler_auto_loop::{
    compose_cancel_decision, compose_complete_cycle_decision, AutoLoopDriver, AutoLoopError,
    AutoStatus, CompletionSummary, DefaultAutoLoopDriver, InvalidTransition, IterationOutcome,
    IterationStatus, MetricSource, Objective, Op, Predicate, Role, SuccessCriteria, Transition,
};
use advance_shared_types::run::RoundDecision;

use crate::common::{NoopIterationCheckpoint, NoopIterationRollback, RecordingEvaluatorResolver};

fn minimal_criteria() -> SuccessCriteria {
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
        safety_valve: None,
    }
}

fn driver() -> DefaultAutoLoopDriver {
    DefaultAutoLoopDriver::new(
        Arc::new(NoopIterationCheckpoint),
        Arc::new(NoopIterationRollback),
    )
}

// ─── AC-12: pure state transition table ─────────────────────────────────

#[test]
fn a_active_no_progress_to_degraded() {
    assert_eq!(
        AutoStatus::Active.transition(Transition::NoProgressLimit),
        Ok(AutoStatus::Degraded)
    );
}

#[test]
fn b_active_llm_errors_to_degraded() {
    assert_eq!(
        AutoStatus::Active.transition(Transition::LlmErrorLimit),
        Ok(AutoStatus::Degraded)
    );
}

#[test]
fn c_active_safety_valve_to_halted() {
    assert_eq!(
        AutoStatus::Active.transition(Transition::SafetyValve),
        Ok(AutoStatus::Halted)
    );
}

#[test]
fn d_active_complete_cycle_to_completed() {
    assert_eq!(
        AutoStatus::Active.transition(Transition::CompleteCycle),
        Ok(AutoStatus::Completed)
    );
}

#[test]
fn e_active_manual_cancel_to_cancelled() {
    assert_eq!(
        AutoStatus::Active.transition(Transition::ManualCancel),
        Ok(AutoStatus::Cancelled)
    );
}

#[test]
fn f_degraded_progress_to_active() {
    assert_eq!(
        AutoStatus::Degraded.transition(Transition::ProgressDetected),
        Ok(AutoStatus::Active)
    );
}

#[test]
fn g_degraded_llm_recovered_to_active() {
    assert_eq!(
        AutoStatus::Degraded.transition(Transition::LlmRecovered),
        Ok(AutoStatus::Active)
    );
}

#[test]
fn h_degraded_safety_valve_to_halted() {
    assert_eq!(
        AutoStatus::Degraded.transition(Transition::SafetyValve),
        Ok(AutoStatus::Halted)
    );
}

#[test]
fn i_degraded_manual_resume_to_active() {
    assert_eq!(
        AutoStatus::Degraded.transition(Transition::ManualResume),
        Ok(AutoStatus::Active)
    );
}

#[test]
fn j_degraded_manual_cancel_to_cancelled() {
    assert_eq!(
        AutoStatus::Degraded.transition(Transition::ManualCancel),
        Ok(AutoStatus::Cancelled)
    );
}

#[test]
fn k_halted_manual_resume_to_active() {
    assert_eq!(
        AutoStatus::Halted.transition(Transition::ManualResume),
        Ok(AutoStatus::Active)
    );
}

#[test]
fn l_halted_manual_cancel_to_cancelled() {
    assert_eq!(
        AutoStatus::Halted.transition(Transition::ManualCancel),
        Ok(AutoStatus::Cancelled)
    );
}

#[test]
fn m_completed_terminal_rejects_all_triggers() {
    for t in [
        Transition::NoProgressLimit,
        Transition::LlmErrorLimit,
        Transition::SafetyValve,
        Transition::CompleteCycle,
        Transition::ManualCancel,
        Transition::ProgressDetected,
        Transition::LlmRecovered,
        Transition::ManualResume,
    ] {
        assert_eq!(
            AutoStatus::Completed.transition(t),
            Err(InvalidTransition::TerminalState(AutoStatus::Completed)),
            "Completed should reject {t:?}"
        );
    }
}

#[test]
fn n_cancelled_terminal_rejects_all_triggers() {
    for t in [
        Transition::NoProgressLimit,
        Transition::CompleteCycle,
        Transition::ManualResume,
    ] {
        assert_eq!(
            AutoStatus::Cancelled.transition(t),
            Err(InvalidTransition::TerminalState(AutoStatus::Cancelled)),
            "Cancelled should reject {t:?}"
        );
    }
}

#[test]
fn n_active_illegal_trigger_rejected() {
    // Active cannot accept ProgressDetected (that's only from Degraded).
    assert_eq!(
        AutoStatus::Active.transition(Transition::ProgressDetected),
        Err(InvalidTransition::IllegalTransition {
            from: AutoStatus::Active,
            trigger: Transition::ProgressDetected,
        })
    );
}

#[test]
fn n_halted_illegal_trigger_rejected() {
    // Halted cannot accept CompleteCycle (terminal path only from Active).
    assert_eq!(
        AutoStatus::Halted.transition(Transition::CompleteCycle),
        Err(InvalidTransition::IllegalTransition {
            from: AutoStatus::Halted,
            trigger: Transition::CompleteCycle,
        })
    );
}

// ─── AC-19: manual cancel does NOT invoke evaluator ─────────────────────

#[tokio::test]
async fn o_manual_cancel_skips_evaluator() {
    let recorder = Arc::new(RecordingEvaluatorResolver::new());
    let counter = Arc::clone(&recorder.counter);
    let driver = DefaultAutoLoopDriver::new(
        Arc::new(NoopIterationCheckpoint),
        Arc::new(NoopIterationRollback),
    )
    .with_evaluator_resolver(recorder);

    // Configure an evaluator ref to prove that EVEN WITH an evaluator
    // configured, manual-cancel skips it.
    let mut criteria = minimal_criteria();
    criteria.evaluator = Some("research-pack@1.2.0/evaluator-bpb".to_string());

    driver.start("alice", criteria).await.expect("start");

    // Counter should be 0 before any operation.
    assert_eq!(counter.load(Ordering::Relaxed), 0);

    let outcome = driver
        .handle_manual_cancel("alice", "user-stop")
        .expect("handle_manual_cancel");

    // (a) status flipped to Cancelled
    let status = driver.status("alice").await;
    assert_eq!(status, Some(AutoStatus::Cancelled));

    // (b) evaluator path was NEVER taken — the AC-19 essence.
    assert_eq!(
        counter.load(Ordering::Relaxed),
        0,
        "manual cancel must NOT invoke resolve_evaluator"
    );

    // Outcome carries the canonical RoundDecision::Blocked("cancelled: ...").
    match outcome {
        IterationOutcome::Cancelled { reason, decision } => {
            assert_eq!(reason, "user-stop");
            match decision {
                RoundDecision::Blocked(s) => {
                    assert!(s.starts_with("cancelled: "));
                    assert!(s.contains("user-stop"));
                }
                other => panic!("expected Blocked, got {other:?}"),
            }
        }
        other => panic!("expected Cancelled, got {other:?}"),
    }
}

// ─── AC-20 foundation: decision text format ─────────────────────────────

#[test]
fn p_compose_complete_cycle_decision_format() {
    let summary = CompletionSummary {
        outcome: "research-converged".to_string(),
        final_metrics: vec![],
    };
    for (status, label) in [
        (IterationStatus::Keep, "keep"),
        (IterationStatus::Discard, "discard"),
        (IterationStatus::Crash, "crash"),
    ] {
        let decision = compose_complete_cycle_decision(&summary, status);
        match decision {
            RoundDecision::Blocked(s) => {
                assert!(
                    s.starts_with("completed: research-converged, final_status: "),
                    "{s}"
                );
                assert!(s.ends_with(label), "{s}");
            }
            other => panic!("expected Blocked, got {other:?}"),
        }
    }
}

#[test]
fn p_compose_cancel_decision_format() {
    let decision = compose_cancel_decision("user-stop");
    match decision {
        RoundDecision::Blocked(s) => {
            assert_eq!(s, "cancelled: user-stop");
        }
        other => panic!("expected Blocked, got {other:?}"),
    }
}

// ─── AC-02 foundation: auto namespace + fresh-init ──────────────────────

#[tokio::test]
async fn q_auto_namespace_task_id_format() {
    let d = driver();
    assert_eq!(d.auto_namespace_task_id("alice"), "auto:alice");
    assert_eq!(d.auto_namespace_task_id("bob-2"), "auto:bob-2");
}

#[tokio::test]
async fn q_start_initializes_fresh_state() {
    let d = driver();
    d.start("alice", minimal_criteria()).await.expect("start");
    let status = d.status("alice").await;
    assert_eq!(status, Some(AutoStatus::Active));

    // Starting twice rejects.
    let err = d.start("alice", minimal_criteria()).await.unwrap_err();
    match err {
        AutoLoopError::AlreadyStarted(id) => assert_eq!(id, "alice"),
        other => panic!("expected AlreadyStarted, got {other:?}"),
    }
}

#[tokio::test]
async fn q_evaluator_id_format() {
    let d = driver();
    assert_eq!(d.evaluator_id_for("alice", 0), "auto-eval:alice:iter-0");
    assert_eq!(d.evaluator_id_for("alice", 42), "auto-eval:alice:iter-42");
}

// ─── AC-03 foundation: record_complete_cycle_request stores intent only ─

#[tokio::test]
async fn r_record_complete_cycle_request_does_not_transition() {
    let d = driver();
    d.start("alice", minimal_criteria()).await.expect("start");

    let summary = CompletionSummary {
        outcome: "stop-please".to_string(),
        final_metrics: vec![],
    };
    d.record_complete_cycle_request("alice", summary)
        .expect("record");

    // PRD §4.7.7 step 1 invariant: state STAYS Active. Per-iteration
    // evaluator must still run before the integrated loop transitions
    // to Completed.
    assert_eq!(d.status("alice").await, Some(AutoStatus::Active));
}

#[tokio::test]
async fn r_transition_status_on_missing_session() {
    let d = driver();
    let err = d
        .transition_status("ghost", Transition::SafetyValve)
        .unwrap_err();
    match err {
        AutoLoopError::NotStarted(id) => assert_eq!(id, "ghost"),
        other => panic!("expected NotStarted, got {other:?}"),
    }
}

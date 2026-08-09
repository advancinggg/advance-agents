//! AC-17 (M015-side closure): `RoundAdvancer` trait impl consumable through the
//! `Arc<dyn RoundAdvancer>` boundary MODULE-008's complete-round handler uses.
//!
//! M015's CONTRACT-141 obligation is to PRODUCE the correct `RoundDecision`
//! from `on_complete_round`. M008's actual consumption — `RunManager::complete_round`
//! currently observes-but-DISCARDS the decision (run-manager/src/run.rs:669) — is
//! M008's contract, NOT M015's. These tests verify ONLY the M015-side production:
//! decision values propagate byte-for-byte across the trait-object call.
//!
//! Cross-module deferred (MODULE-015 §3.6): M008's actual decision consumption.

mod common;

use std::sync::Arc;

use advance_scheduler_auto_loop::{AutoLoopRoundAdvancer, CompletionSummary, IterationStatus};
use advance_shared_types::capability::BudgetDecision;
use advance_shared_types::run::{RoundAdvancer, RoundDecision, RoundResult, RunError};

use common::MockAutoStateReader;

/// Stand-in for MODULE-008's RunManager: holds the advancer as the same
/// `Option<Arc<dyn RoundAdvancer>>` trait-object shape M008 stores
/// (run-manager/src/run.rs:279). The dyn dispatch goes through M015's impl.
struct M008StyleConsumer {
    round_advancer: Option<Arc<dyn RoundAdvancer>>,
}

impl M008StyleConsumer {
    fn with_advancer(advancer: Arc<dyn RoundAdvancer>) -> Self {
        Self {
            round_advancer: Some(advancer),
        }
    }

    /// Canonical M008 call shape: `advancer.on_complete_round(run_id, RoundResult)`.
    async fn complete_round(
        &self,
        run_id: &str,
        result: RoundResult,
    ) -> Result<RoundDecision, RunError> {
        let advancer = self
            .round_advancer
            .as_ref()
            .expect("auto-mode consumer must hold a round_advancer");
        advancer.on_complete_round(run_id, result).await
    }
}

fn empty_result() -> RoundResult {
    RoundResult {
        summary: None,
        metrics: Vec::new(),
    }
}

fn summary(outcome: &str) -> CompletionSummary {
    CompletionSummary {
        outcome: outcome.to_string(),
        final_metrics: Vec::new(),
    }
}

// MODULE-015-T17-slD.a — ContinueAllowed propagates through the dyn boundary.
#[tokio::test]
async fn dyn_boundary_continue_allowed() {
    let reader = MockAutoStateReader::new()
        .with_agent_for_run("run-a", "alice")
        .with_budget("run-a", BudgetDecision::Allow);
    let advancer: Arc<dyn RoundAdvancer> = Arc::new(AutoLoopRoundAdvancer::new(Arc::new(reader)));
    let consumer = M008StyleConsumer::with_advancer(advancer);

    let decision = consumer
        .complete_round("run-a", empty_result())
        .await
        .expect("ContinueAllowed");
    assert_eq!(decision, RoundDecision::ContinueAllowed);
}

// MODULE-015-T17-slD.b — complete-cycle Blocked text propagates verbatim.
#[tokio::test]
async fn dyn_boundary_complete_cycle_blocked() {
    let reader = MockAutoStateReader::new()
        .with_agent_for_run("run-a", "alice")
        .with_budget("run-a", BudgetDecision::Allow)
        .with_complete_cycle("alice", summary("research-converged"))
        .with_status("alice", IterationStatus::Keep);
    let advancer: Arc<dyn RoundAdvancer> = Arc::new(AutoLoopRoundAdvancer::new(Arc::new(reader)));
    let consumer = M008StyleConsumer::with_advancer(advancer);

    let decision = consumer
        .complete_round("run-a", empty_result())
        .await
        .expect("Blocked");
    assert_eq!(
        decision,
        RoundDecision::Blocked("completed: research-converged, final_status: keep".to_string()),
        "complete-cycle decision text must propagate byte-for-byte through dyn dispatch"
    );
}

// MODULE-015-T17-slD.c — budget Deny reason propagates verbatim.
#[tokio::test]
async fn dyn_boundary_budget_deny_blocked() {
    let reader = MockAutoStateReader::new()
        .with_agent_for_run("run-a", "alice")
        .with_budget(
            "run-a",
            BudgetDecision::Deny("budget-exceeded-tokens".to_string()),
        );
    let advancer: Arc<dyn RoundAdvancer> = Arc::new(AutoLoopRoundAdvancer::new(Arc::new(reader)));
    let consumer = M008StyleConsumer::with_advancer(advancer);

    let decision = consumer
        .complete_round("run-a", empty_result())
        .await
        .expect("Blocked");
    assert_eq!(
        decision,
        RoundDecision::Blocked("budget-exceeded-tokens".to_string()),
        "budget Deny reason must propagate verbatim through dyn dispatch"
    );
}

// MODULE-015-T17-slD.d — unmapped run_id → RunError::InvalidState propagated as
// the canonical M008-typed error with the exact message.
#[tokio::test]
async fn dyn_boundary_invalid_state_propagation() {
    let reader = MockAutoStateReader::new(); // empty maps
    let advancer: Arc<dyn RoundAdvancer> = Arc::new(AutoLoopRoundAdvancer::new(Arc::new(reader)));
    let consumer = M008StyleConsumer::with_advancer(advancer);

    let err = consumer
        .complete_round("run-unknown", empty_result())
        .await
        .expect_err("expected InvalidState");
    match err {
        RunError::InvalidState(reason) => {
            assert!(
                reason.contains("auto-loop: no agent_id mapping for run_id"),
                "exact InvalidState message must propagate; got: {reason}"
            );
        }
        other => panic!("expected RunError::InvalidState, got {other:?}"),
    }
}

// MODULE-015-T17-slD.e — decision value preserved byte-for-byte across the
// trait-object call (NOT M008 consumption behavior — M008 discards the value).
#[tokio::test]
async fn dyn_boundary_decision_value_preserved() {
    // Produce a Blocked(discard) decision and confirm the inner String survives
    // the dyn dispatch unchanged (the property M015 owns; what M008 does with it
    // is M008's contract).
    let reader = MockAutoStateReader::new()
        .with_agent_for_run("run-a", "alice")
        .with_budget("run-a", BudgetDecision::Allow)
        .with_complete_cycle("alice", summary("primary-regressed"))
        .with_status("alice", IterationStatus::Discard);
    let advancer: Arc<dyn RoundAdvancer> = Arc::new(AutoLoopRoundAdvancer::new(Arc::new(reader)));
    let consumer = M008StyleConsumer::with_advancer(advancer);

    let decision = consumer
        .complete_round("run-a", empty_result())
        .await
        .expect("Blocked");
    match decision {
        RoundDecision::Blocked(s) => {
            assert_eq!(s, "completed: primary-regressed, final_status: discard");
        }
        other => panic!("expected Blocked(completed:…discard); got {other:?}"),
    }
}

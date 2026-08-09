//! BC-01..04 — per-resolver witness for the REAL `BudgetCheckResolver`
//! budget-exhausted Deny (MODULE-013-AC-22 / PRD §5.7.3 "预算阈值内 abstain，
//! 超出时 deny").
//!
//! WITNESS-FLOOR NOTE: these bind an INDEPENDENT oracle — a REAL
//! `advance_run_manager::InMemoryRunBudget` (CONTRACT-073) driven to GENUINE
//! rounds-exhaustion — so the `Deny` is produced by real rounds-gate arithmetic
//! (`rounds_used >= rounds_limit`), NOT injected by a canned mock (which would
//! be vacuous: the resolver forwards the budget's reason verbatim). They prove
//! the Deny logic directly; CLI builder and SYS-J-13 witnesses cover the
//! production-reachable path that injects the live run budget.

mod common;

use std::sync::Arc;

use advance_run_manager::{RunConfig, RunId, RunManager};
use advance_shared_types::run::RoundResult;
use advance_shared_types::traits::{EventBusEmit, RunBudget};
use cap_grant::data::{ChainDecision, GrantRequest, GrantTtl, ResolverOutcome};
use cap_grant::resolver::{
    AutoDenyResolver, BudgetCheckResolver, Resolver, ResolverChain, ResolverContext,
    SubsetAutoApproveResolver,
};
use cap_grant::subset::SubsetValidatorImpl;

use crate::common::{make_store, RecordingBus};

fn req(caller: &str, capability: &str) -> GrantRequest {
    GrantRequest {
        caller: caller.to_string(),
        capability: capability.to_string(),
        params: None,
        ttl: GrantTtl::Once,
        justification: None,
    }
}

/// A REAL `InMemoryRunBudget` over a run driven to GENUINE rounds-exhaustion:
/// `rounds_limit = 1` then exactly one `complete_round` advances `rounds_used`
/// to 1, so the inclusive rounds gate (`rounds_used >= rounds_limit`) denies any
/// further activity. The returned budget holds its own `Arc` to the run store
/// (independent of the dropped `RunManager`), so the run survives.
async fn exhausted_budget() -> (Arc<dyn RunBudget>, RunId) {
    let bus: Arc<dyn EventBusEmit> = RecordingBus::new();
    let rm = RunManager::new(bus);
    let run_id = rm
        .ensure_run(
            "budget-witness-exhausted",
            "agent-witness",
            RunConfig {
                rounds_limit: Some(1),
                ..Default::default()
            },
        )
        .expect("ensure_run");
    rm.complete_round(
        &run_id,
        RoundResult {
            summary: None,
            metrics: vec![],
        },
    )
    .await
    .expect("complete_round advances rounds_used to the limit");
    let budget: Arc<dyn RunBudget> = Arc::new(rm.budget());
    (budget, run_id)
}

/// A REAL `InMemoryRunBudget` over a fresh Active run with headroom
/// (`rounds_limit = 10`, no `complete_round` → `rounds_used = 0 < 10`, token
/// headroom). The `check(run_id, 0, 0.0)` probe → `Allow`.
fn headroom_budget() -> (Arc<dyn RunBudget>, RunId) {
    let bus: Arc<dyn EventBusEmit> = RecordingBus::new();
    let rm = RunManager::new(bus);
    let run_id = rm
        .ensure_run(
            "budget-witness-headroom",
            "agent-witness",
            RunConfig {
                rounds_limit: Some(10),
                token_limit: Some(1000),
                ..Default::default()
            },
        )
        .expect("ensure_run");
    let budget: Arc<dyn RunBudget> = Arc::new(rm.budget());
    (budget, run_id)
}

// ── BC-01 — REAL exhausted budget → the resolver Denies ──
#[tokio::test]
async fn bc_01_real_exhausted_budget_denies() {
    let (budget, run_id) = exhausted_budget().await;
    let resolver = BudgetCheckResolver::with_budget(budget);
    let outcome = resolver.resolve(
        &req("alice", "fs"),
        &ResolverContext {
            parent_grants: &[],
            run_id: Some(run_id.as_ref()),
        },
    );
    let ResolverOutcome::Deny(reason) = outcome else {
        panic!("exhausted run budget → Deny, got {outcome:?}");
    };
    // The Deny is computed by the budget's real rounds gate, not injected — the
    // reason is the budget's invariant exhaustion code.
    assert_eq!(
        reason, "budget-exceeded-rounds",
        "Deny carries the real exhaustion code, got {reason:?}"
    );
}

// ── BC-02 — REAL budget WITH HEADROOM → Abstain (discriminator vs BC-01) ──
#[test]
fn bc_02_real_headroom_budget_abstains() {
    let (budget, run_id) = headroom_budget();
    let resolver = BudgetCheckResolver::with_budget(budget);
    let outcome = resolver.resolve(
        &req("alice", "fs"),
        &ResolverContext {
            parent_grants: &[],
            run_id: Some(run_id.as_ref()),
        },
    );
    // Same REAL oracle, opposite state → opposite outcome. A stub that always
    // Abstained would pass BC-02 but FAIL BC-01 — that's the discriminator.
    assert!(
        matches!(outcome, ResolverOutcome::Abstain),
        "headroom run budget → Abstain, got {outcome:?}"
    );
}

// ── BC-03 — compatibility `new()` (no budget) → Abstain ──
#[test]
fn bc_03_no_budget_default_abstains() {
    // Compatibility construction for callers with no run-budget source.
    let resolver = BudgetCheckResolver::new();
    let outcome = resolver.resolve(
        &req("alice", "fs"),
        &ResolverContext {
            parent_grants: &[],
            // Even with a run_id present, a None budget never consults it.
            run_id: Some("run-some-active"),
        },
    );
    assert!(
        matches!(outcome, ResolverOutcome::Abstain),
        "no injected budget → Abstain (production default), got {outcome:?}"
    );
}

// ── BC-04 — chain integration: exhausted BudgetCheck denies the chain ──
#[tokio::test]
async fn bc_04_chain_exhausted_budget_denies() {
    let (budget, run_id) = exhausted_budget().await;
    let (store, bus, _h) = make_store();
    let bus_dyn: Arc<dyn EventBusEmit> = bus.clone();
    // Production-shaped prefix: SubsetAutoApprove (abstains with no parent
    // grants) → BudgetCheck (the exhausted budget) → AutoDeny (terminal).
    let chain = ResolverChain::new(vec![
        Box::new(SubsetAutoApproveResolver::new(Arc::new(
            SubsetValidatorImpl::new(),
        ))),
        Box::new(BudgetCheckResolver::with_budget(budget)),
        Box::new(AutoDenyResolver::new()),
    ]);
    let result = chain.evaluate(
        req("alice", "fs"),
        ResolverContext {
            parent_grants: &[],
            run_id: Some(run_id.as_ref()),
        },
        &store,
        &bus_dyn,
    );
    let ChainDecision::Denied(reason) = result else {
        panic!("exhausted BudgetCheck → chain Denied, got {result:?}");
    };
    // Assert the EXHAUSTION code, NOT just any Denied — this discriminates a
    // real BudgetCheck-Deny from AutoDeny's terminal "no resolver matched".
    assert_eq!(
        reason, "budget-exceeded-rounds",
        "BudgetCheck (not AutoDeny) decided; reason {reason:?}"
    );
}

//! Phase-3 kickoff (2026-06-06) — MODULE-009-AC-19 + MODULE-008-AC-20: the
//! production budget mechanism the cli composition root wires (`wiring.rs`),
//! exercised on the SAME component graph (real `RunManager` + EventBus
//! `CostTracker` cost gate + rounds gate + the session-run producer cell).
//!
//! The through-the-gateway + provider-suppression e2e is sys_j36 (already
//! passed). These unit/integration tests pin the cli-specific wiring:
//! `run_config_from` mapping, the cost/rounds preflight Deny, and the
//! `RunManagerBootstrap` → `OnceLock` cell → `ComponentCtx.run_id` producer.

use std::sync::{Arc, OnceLock};

use advance_cli::agent_loop::{RunManagerBootstrap, SessionRunCell};
use advance_cli::wiring::run_config_from;
use advance_cost_tracker::CostTracker;
use advance_run_manager::{RunConfig, RunId, RunManager};
use advance_runtime::config::RunBudgetConfig;
use advance_runtime::ComponentCtx;
use advance_scheduler::hook::RunBootstrap;
use advance_shared_types::capability::BudgetDecision;
use advance_shared_types::event::Event;
use advance_shared_types::run::{RoundDecision, RoundResult};
use advance_shared_types::traits::{CostTrackerQuery, EventBusEmit, RunBudget};

/// No-op EventBus for `RunManager::new` (these tests assert budget state, not
/// run.* events).
struct NoopBus;
impl EventBusEmit for NoopBus {
    fn emit(&self, _event: Event) {}
}

/// An `llm.response` cost event the `CostTracker` folds into `by_run[run_id]`
/// (mirrors sys_j36's `cost_event`).
fn cost_event(run_id: &str, cost_usd: f64) -> Event {
    serde_json::from_value(serde_json::json!({
        "id": "evt-seed",
        "timestamp": "2026-06-06T00:00:00Z",
        "agent_id": "default-agent",
        "task_id": null,
        "run_id": run_id,
        "execution_id": null,
        "trace_id": "t",
        "span_id": "s",
        "parent_span_id": null,
        "event_type": "llm.response",
        "payload": { "cost_usd": cost_usd, "input_tokens": 100, "output_tokens": 100 },
        "duration_ms": 5
    }))
    .expect("seed event deserializes")
}

#[test]
fn run_config_from_maps_caps() {
    let cfg = RunBudgetConfig {
        default_token_limit: Some(1000),
        default_cost_limit_usd: Some(5.0),
        default_rounds_limit: Some(3),
    };
    let rc = run_config_from(&cfg);
    assert_eq!(rc.token_limit, Some(1000));
    assert_eq!(rc.cost_usd_limit, Some(5.0));
    assert_eq!(rc.rounds_limit, Some(3));

    // Absent block → all-None (no caps; prior behaviour).
    let none = run_config_from(&RunBudgetConfig::default());
    assert_eq!(none.token_limit, None);
    assert_eq!(none.cost_usd_limit, None);
    assert_eq!(none.rounds_limit, None);
}

#[test]
fn prod_budget_cost_deny_before_provider() {
    // The exact production component graph: RunManager wired to a CostTracker; the
    // cost gate reads the tracker's per-run aggregate (CONTRACT-181).
    let cost_tracker = Arc::new(CostTracker::new());
    let rm = RunManager::new(Arc::new(NoopBus))
        .with_cost_tracker(cost_tracker.clone() as Arc<dyn CostTrackerQuery>);
    let rid = rm
        .ensure_run(
            "default-agent",
            "default-agent",
            run_config_from(&RunBudgetConfig {
                default_cost_limit_usd: Some(5.0),
                ..RunBudgetConfig::default()
            }),
        )
        .expect("ensure_run");

    // A prior turn's llm.response accrued 9.0 of cost under this run_id.
    cost_tracker.observe(&cost_event(rid.as_ref(), 9.0));

    // The gateway's run_id-gated preflight is exactly check(rid, 0, 0.0).
    let budget: Arc<dyn RunBudget> = Arc::new(rm.budget());
    match budget.check(rid.as_ref(), 0, 0.0) {
        BudgetDecision::Deny(reason) => assert_eq!(reason, "budget-exceeded-cost"),
        other => panic!("expected Deny(budget-exceeded-cost), got {other:?}"),
    }
}

#[tokio::test]
async fn prod_budget_rounds_deny_after_complete_round() {
    let rm = RunManager::new(Arc::new(NoopBus));
    let rid = rm
        .ensure_run(
            "default-agent",
            "default-agent",
            run_config_from(&RunBudgetConfig {
                default_rounds_limit: Some(1),
                ..RunBudgetConfig::default()
            }),
        )
        .expect("ensure_run");

    // One guest-reaching turn completes a round.
    let decision = rm
        .complete_round(
            &rid,
            RoundResult {
                summary: None,
                metrics: vec![],
            },
        )
        .await
        .expect("complete_round");
    assert_eq!(decision, RoundDecision::ContinueAllowed);

    // The next turn's preflight is now blocked: rounds_used(1) >= limit(1).
    let budget: Arc<dyn RunBudget> = Arc::new(rm.budget());
    match budget.check(rid.as_ref(), 0, 0.0) {
        BudgetDecision::Deny(reason) => assert_eq!(reason, "budget-exceeded-rounds"),
        other => panic!("expected Deny(budget-exceeded-rounds), got {other:?}"),
    }
}

#[tokio::test]
async fn session_producer_publishes_cell_and_sets_run_id() {
    // The driver-side RunManagerBootstrap mints the session run and publishes its
    // RunId into the shared cell; the handler reads the cell in `init` and sets
    // ComponentCtx.run_id BEFORE instantiation. This pins that hand-off.
    let rm = Arc::new(RunManager::new(Arc::new(NoopBus)));
    let cell: SessionRunCell = Arc::new(OnceLock::new());
    let bootstrap = RunManagerBootstrap {
        run_manager: rm.clone(),
        run_config: RunConfig::default(),
        session_agent: "default-agent".to_string(),
        cell: cell.clone(),
    };

    // The driver passes the colon messaging id; the bootstrap IGNORES it and keys
    // on the bare cap id.
    let returned = bootstrap
        .ensure_run("agent:default")
        .await
        .expect("ensure_run");

    let published: &RunId = cell.get().expect("cell published");
    assert_eq!(published.as_ref(), returned, "cell holds the minted run id");

    // The producer step (as `init` does): set ComponentCtx.run_id from the cell.
    let mut ctx = ComponentCtx::new("default-agent".into(), "trace".into(), Vec::new());
    ctx.run_id = cell.get().map(|r| r.as_ref().to_string());
    assert_eq!(ctx.run_id.as_deref(), Some(returned.as_str()));

    // A second ensure_run on the SAME bare task id is idempotent (same run).
    let again = bootstrap
        .ensure_run("agent:default")
        .await
        .expect("idempotent");
    assert_eq!(again, returned, "ensure_run idempotent on the bare cap id");
}

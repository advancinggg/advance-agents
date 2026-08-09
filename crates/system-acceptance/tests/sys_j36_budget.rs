//! SYS-J-36 — a run advances rounds and is blocked when its token/cost/round budget
//! is exceeded, returning a budget error before the next LLM/tool call.
//! Chain: MODULE-008 run-manager → MODULE-009 cap-llm → MODULE-019 cost-tracker.
//!
//! Witnessed test-local against the REAL `advance_run_manager::{RunManager,
//! InMemoryRunBudget}` + the REAL `cap_llm::LlmGateway` (whose budget preflight
//! runs `RunBudget::check` BEFORE dialing the provider) + the REAL
//! `advance_cost_tracker::CostTracker` — only the external LLM provider is the
//! loopback mock (never reached on a budget-deny). See `tests/h_loopback/mod.rs`.

#[path = "h_loopback/mod.rs"]
mod h_loopback;
use h_loopback::{boot, CapturingBus, GatewayDeps, ScriptedResponse};

use std::sync::Arc;

use advance_cost_tracker::CostTracker;
use advance_run_manager::{RepetitionAction, RepetitionGuard, RunConfig, RunManager};
use advance_shared_types::event::Event;
use advance_shared_types::run::{RoundDecision, RoundResult};
use advance_shared_types::traits::{CostTrackerQuery, RepetitionGuardCheck, RunBudget};
use cap_llm::{ChatMessage, ChatParams, ChatRole, LlmError, LLM_REQUEST};

const AGENT: &str = "agent:harness";

fn user_msg() -> Vec<ChatMessage> {
    vec![ChatMessage {
        role: ChatRole::User,
        content: "hi".into(),
    }]
}

/// A benign repetition guard (never trips for these budget journeys).
fn benign_guard() -> Arc<dyn RepetitionGuardCheck> {
    Arc::new(RepetitionGuard::new(64, 100, RepetitionAction::WarnOnly))
}

/// Seed a `llm.response` cost event for `run_id` carrying `cost_usd` so a real
/// `CostTracker` folds it into its `by_run` aggregate (CONTRACT-181).
fn cost_event(run_id: &str, cost_usd: f64) -> Event {
    serde_json::from_value(serde_json::json!({
        "id": "evt-seed-cost",
        "timestamp": "2026-06-03T00:00:00Z",
        "agent_id": AGENT,
        "task_id": null,
        "run_id": run_id,
        "execution_id": null,
        "trace_id": "trace-seed",
        "span_id": "span-seed",
        "parent_span_id": null,
        "event_type": "llm.response",
        "payload": { "cost_usd": cost_usd, "input_tokens": 100, "output_tokens": 100 },
        "duration_ms": 5
    }))
    .expect("seed event deserializes")
}

/// SYS-AC-115: a run whose rounds budget is already exhausted gets `RunBudget::check`
/// Deny, surfaced as a budget error BEFORE the next call.
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_115_budget_deny_before_next_call() {
    let run_bus = Arc::new(CapturingBus::new());
    let rm = RunManager::new(run_bus.clone());
    let run_id = rm
        .ensure_run(
            "task-h-115",
            AGENT,
            RunConfig {
                rounds_limit: Some(0),
                ..Default::default()
            },
        )
        .expect("ensure_run");

    let budget: Arc<dyn RunBudget> = Arc::new(rm.budget());
    let llm_bus = Arc::new(CapturingBus::new());
    let harness = boot(
        vec![ScriptedResponse::ok_chat("never reached", 1, 1)],
        GatewayDeps {
            run_budget: budget,
            repetition_guard: benign_guard(),
            event_bus: llm_bus.clone(),
            default_agent_id: AGENT.into(),
        },
    )
    .await;

    let res = harness
        .gateway
        .chat_for_run(user_msg(), ChatParams::default(), run_id.to_string())
        .await;
    match res {
        Err(LlmError::BudgetExceeded(reason)) => {
            assert_eq!(
                reason, "budget-exceeded-rounds",
                "rounds budget deny reason"
            );
        }
        other => panic!("expected BudgetExceeded(budget-exceeded-rounds), got {other:?}"),
    }
}

/// SYS-AC-116: the budget-blocked call never reaches the provider — no `llm.request`
/// is emitted and the loopback mock observes zero requests.
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_116_denied_call_never_dials_provider() {
    let run_bus = Arc::new(CapturingBus::new());
    let rm = RunManager::new(run_bus);
    let run_id = rm
        .ensure_run(
            "task-h-116",
            AGENT,
            RunConfig {
                rounds_limit: Some(0),
                ..Default::default()
            },
        )
        .expect("ensure_run");

    let budget: Arc<dyn RunBudget> = Arc::new(rm.budget());
    let llm_bus = Arc::new(CapturingBus::new());
    let harness = boot(
        vec![ScriptedResponse::ok_chat("never reached", 1, 1)],
        GatewayDeps {
            run_budget: budget,
            repetition_guard: benign_guard(),
            event_bus: llm_bus.clone(),
            default_agent_id: AGENT.into(),
        },
    )
    .await;

    let res = harness
        .gateway
        .chat_for_run(user_msg(), ChatParams::default(), run_id.to_string())
        .await;
    assert!(
        matches!(res, Err(LlmError::BudgetExceeded(_))),
        "call denied"
    );

    assert_eq!(
        llm_bus.count(LLM_REQUEST),
        0,
        "no llm.request emitted for the denied call"
    );
    assert_eq!(
        harness.server.recorder().chat_request_count(),
        0,
        "the loopback provider was never dialed"
    );
}

/// SYS-AC-117: under budget, `complete_round` advances the round counter and emits
/// `run.round_completed`; exceeding the rounds limit returns Deny(budget-exceeded-rounds).
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_117_complete_round_advances_then_rounds_deny() {
    let run_bus = Arc::new(CapturingBus::new());
    let rm = RunManager::new(run_bus.clone());
    let run_id = rm
        .ensure_run(
            "task-h-117",
            AGENT,
            RunConfig {
                rounds_limit: Some(1),
                ..Default::default()
            },
        )
        .expect("ensure_run");

    // One round completes (Normal mode → no RoundAdvancer needed).
    let decision = rm
        .complete_round(
            &run_id,
            RoundResult {
                summary: None,
                metrics: vec![],
            },
        )
        .await
        .expect("complete_round");
    assert_eq!(
        decision,
        RoundDecision::ContinueAllowed,
        "round 1 within budget"
    );

    let round_events = run_bus.events_named("run.round_completed");
    assert_eq!(
        round_events.len(),
        1,
        "exactly one run.round_completed emitted"
    );
    assert_eq!(
        round_events[0]
            .payload
            .get("iteration")
            .and_then(|v| v.as_u64()),
        Some(1),
        "round counter advanced to 1"
    );

    // The next LLM call is now blocked: rounds_used(1) >= limit(1).
    let budget: Arc<dyn RunBudget> = Arc::new(rm.budget());
    let llm_bus = Arc::new(CapturingBus::new());
    let harness = boot(
        vec![ScriptedResponse::ok_chat("never reached", 1, 1)],
        GatewayDeps {
            run_budget: budget,
            repetition_guard: benign_guard(),
            event_bus: llm_bus,
            default_agent_id: AGENT.into(),
        },
    )
    .await;
    let res = harness
        .gateway
        .chat_for_run(user_msg(), ChatParams::default(), run_id.to_string())
        .await;
    match res {
        Err(LlmError::BudgetExceeded(reason)) => assert_eq!(reason, "budget-exceeded-rounds"),
        other => panic!("expected BudgetExceeded(budget-exceeded-rounds), got {other:?}"),
    }
}

/// SYS-AC-118: `RunBudget::check` reads the current cost_usd aggregate per run_id
/// from `CostTrackerQuery` (CONTRACT-181) before comparing against the cost limit.
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_118_cost_gate_consults_cost_tracker() {
    let run_bus = Arc::new(CapturingBus::new());
    let cost_tracker = Arc::new(CostTracker::new());
    let rm = RunManager::new(run_bus)
        .with_cost_tracker(cost_tracker.clone() as Arc<dyn CostTrackerQuery>);
    // cost limit 5.0; local committed cost is 0.0 — the only source of an over-limit
    // aggregate is the CostTracker (proving check() consulted it).
    let run_id = rm
        .ensure_run(
            "task-h-118",
            AGENT,
            RunConfig {
                cost_usd_limit: Some(5.0),
                ..Default::default()
            },
        )
        .expect("ensure_run");
    cost_tracker.observe(&cost_event(&run_id.to_string(), 9.0));

    let budget: Arc<dyn RunBudget> = Arc::new(rm.budget());
    let llm_bus = Arc::new(CapturingBus::new());
    let harness = boot(
        vec![ScriptedResponse::ok_chat("never reached", 1, 1)],
        GatewayDeps {
            run_budget: budget,
            repetition_guard: benign_guard(),
            event_bus: llm_bus,
            default_agent_id: AGENT.into(),
        },
    )
    .await;
    let res = harness
        .gateway
        .chat_for_run(user_msg(), ChatParams::default(), run_id.to_string())
        .await;
    match res {
        Err(LlmError::BudgetExceeded(reason)) => assert_eq!(
            reason, "budget-exceeded-cost",
            "cost gate denied using the tracker's 9.0 > limit 5.0 (local cost is 0.0)"
        ),
        other => panic!("expected BudgetExceeded(budget-exceeded-cost), got {other:?}"),
    }
}

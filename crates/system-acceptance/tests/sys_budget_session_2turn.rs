//! Phase-3 kickoff (2026-06-06) — MODULE-009-AC-19 cross-turn e2e: the production
//! budget mechanism (RunManager + the EventBus-baked CostTracker) denies the NEXT
//! turn's LLM call BEFORE the provider once a session run's accrued cost crosses
//! the cap. Unlike sys_j36 (which hand-seeds a cost event), this drives the REAL
//! gateway across TWO turns: turn-1's `llm.response` accrues cost via the SAME
//! `EventBus` the `RunManager` queries, then turn-2 denies and never dials the
//! loopback provider.
//!
//! Built from `run_config_from` (the cli composition-root helper), so it pins the
//! config→RunConfig→budget→gateway→deny path. The session-run PRODUCER
//! (`RunManagerBootstrap` → `OnceLock` cell → `ComponentCtx.run_id`) is witnessed
//! separately by `advance-cli`'s `budget_wiring` integration tests; the
//! guest→host_fn→gateway leg by `mode_llm_guest_turn`.

#[path = "h_loopback/mod.rs"]
mod h_loopback;
use h_loopback::{boot, GatewayDeps, ScriptedResponse};

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use advance_cli::wiring::run_config_from;
use advance_event_bus::{EventBus, EventBusConfig};
use advance_run_manager::{RepetitionAction, RepetitionGuard, RunManager};
use advance_runtime::config::RunBudgetConfig;
use advance_shared_types::traits::{EventBusEmit, RepetitionGuardCheck, RunBudget};
use cap_llm::{ChatMessage, ChatParams, ChatRole, LlmError};

const AGENT: &str = "default-agent";

fn user_msg() -> Vec<ChatMessage> {
    vec![ChatMessage {
        role: ChatRole::User,
        content: "hi".into(),
    }]
}

fn benign_guard() -> Arc<dyn RepetitionGuardCheck> {
    Arc::new(RepetitionGuard::new(64, 100, RepetitionAction::WarnOnly))
}

/// A real synchronous `EventBus` (its baked-in `CostTracker` folds `llm.response`
/// cost on emit) over a unique temp dir.
fn real_bus() -> Arc<EventBus> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let base = std::env::temp_dir().join(format!("adv-budget2turn-{nanos}"));
    std::fs::create_dir_all(&base).unwrap();
    let cfg = EventBusConfig::new(base.join("jsonl"), base.join("events.db"));
    Arc::new(EventBus::new_synchronous_for_tests(cfg).expect("sync event bus"))
}

#[tokio::test(flavor = "multi_thread")]
async fn budget_session_2turn_cost_deny_before_provider() {
    // Real EventBus → its CostTracker is what the RunManager's cost gate reads.
    let bus = real_bus();
    let bus_dyn: Arc<dyn EventBusEmit> = bus.clone();
    let rm = RunManager::new(bus_dyn.clone()).with_cost_tracker(bus.cost_tracker_query());

    // Caps from a RuntimeConfig.run-budget block via the production helper.
    let cfg = run_config_from(&RunBudgetConfig {
        default_cost_limit_usd: Some(5.0),
        ..RunBudgetConfig::default()
    });
    let run_id = rm.ensure_run(AGENT, AGENT, cfg).expect("ensure_run");

    // The gateway shares the budget (rm.budget()) + the SAME EventBus, so its
    // turn-1 llm.response feeds the tracker the gate consults on turn-2.
    let budget: Arc<dyn RunBudget> = Arc::new(rm.budget());
    let harness = boot(
        vec![
            // turn 1: 100 in + 600_000 out → cost = 0.00025 + 6.0 = 6.00025 > 5.0.
            ScriptedResponse::ok_chat("turn-1-reply", 100, 600_000),
            // turn 2: never reached (preflight denies before dialing).
            ScriptedResponse::ok_chat("turn-2-never", 1, 1),
        ],
        GatewayDeps {
            run_budget: budget,
            repetition_guard: benign_guard(),
            event_bus: bus_dyn,
            default_agent_id: AGENT.into(),
        },
    )
    .await;

    // Turn 1 — under budget; the real gateway dials the loopback, emits
    // llm.response, the CostTracker accrues 6.00025 under run_id.
    harness
        .gateway
        .chat_for_run(user_msg(), ChatParams::default(), run_id.to_string())
        .await
        .expect("turn 1 under budget");
    assert_eq!(
        harness.server.recorder().chat_request_count(),
        1,
        "turn 1 dialed the provider once"
    );

    // Turn 2 — preflight check(rid,0,0.0) reads the tracker (6.00025 > 5.0) and
    // Denies BEFORE the provider.
    let res = harness
        .gateway
        .chat_for_run(user_msg(), ChatParams::default(), run_id.to_string())
        .await;
    match res {
        Err(LlmError::BudgetExceeded(reason)) => assert_eq!(reason, "budget-exceeded-cost"),
        other => panic!("expected BudgetExceeded(budget-exceeded-cost), got {other:?}"),
    }
    assert_eq!(
        harness.server.recorder().chat_request_count(),
        1,
        "turn 2 was denied BEFORE the provider (still 1 dial total)"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn budget_session_rounds_deny_before_provider() {
    // Rounds variant: one complete_round + rounds_limit 1 → next turn denied.
    let bus = real_bus();
    let bus_dyn: Arc<dyn EventBusEmit> = bus.clone();
    let rm = RunManager::new(bus_dyn.clone()).with_cost_tracker(bus.cost_tracker_query());
    let cfg = run_config_from(&RunBudgetConfig {
        default_rounds_limit: Some(1),
        ..RunBudgetConfig::default()
    });
    let run_id = rm.ensure_run(AGENT, AGENT, cfg).expect("ensure_run");

    rm.complete_round(
        &run_id,
        advance_shared_types::run::RoundResult {
            summary: None,
            metrics: vec![],
        },
    )
    .await
    .expect("complete_round");

    let budget: Arc<dyn RunBudget> = Arc::new(rm.budget());
    let harness = boot(
        vec![ScriptedResponse::ok_chat("never", 1, 1)],
        GatewayDeps {
            run_budget: budget,
            repetition_guard: benign_guard(),
            event_bus: bus_dyn,
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
    assert_eq!(
        harness.server.recorder().chat_request_count(),
        0,
        "rounds-denied before any provider dial"
    );
}

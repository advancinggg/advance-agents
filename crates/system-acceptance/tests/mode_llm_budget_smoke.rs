//! HF-2 builder smoke — `.budget()` threads a real `RunBudget` into the shipped loopback
//! gateway: a budget-exhausted run errors with `BudgetExceeded` BEFORE the provider is
//! dialed (the gateway's `RunBudget::check` preflight runs before any HTTP). Proves the
//! shipped `SystemUnderTest::builder().budget()` knob wires through (the journey witness
//! SYS-J-36 uses the separate test-local `h_loopback` helper; this is the builder-path
//! witness it will eventually migrate onto).

use std::sync::Arc;

use advance_run_manager::{RunConfig, RunManager};
use advance_shared_types::event::Event;
use advance_shared_types::traits::{EventBusEmit, RunBudget};
use cap_llm::{ChatMessage, ChatParams, ChatRole, LlmError};
use system_acceptance::llm_loopback::ScriptedResponse;
use system_acceptance::{Cap, LlmMode, SystemUnderTest};

const CORE_BYTES: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-j01-skeleton.core.wasm");
const AGENT: &str = "agent:harness";

/// A throwaway sink for `RunManager` lifecycle events — this smoke asserts on the
/// gateway's events via the harness bus, not on run-lifecycle events.
struct NullBus;
impl EventBusEmit for NullBus {
    fn emit(&self, _event: Event) {}
}

#[tokio::test(flavor = "multi_thread")]
async fn budget_knob_denies_before_dialing_provider() {
    // A run whose rounds budget is already exhausted (rounds_limit 0) → the gateway's
    // budget preflight denies with `budget-exceeded-rounds`.
    let rm = RunManager::new(Arc::new(NullBus));
    let run_id = rm
        .ensure_run(
            "task-budget-smoke",
            AGENT,
            RunConfig {
                rounds_limit: Some(0),
                ..Default::default()
            },
        )
        .expect("ensure_run");
    let budget: Arc<dyn RunBudget> = Arc::new(rm.budget());

    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Fs, Cap::Llm])
        .budget(budget)
        .llm(LlmMode::LoopbackScripted(vec![ScriptedResponse::ok_chat(
            "never reached",
            1,
            1,
        )]))
        .build(CORE_BYTES)
        .await;

    let res = sut
        .llm_gateway()
        .expect("loopback gateway registered")
        .chat_for_run(
            vec![ChatMessage {
                role: ChatRole::User,
                content: "hi".into(),
            }],
            ChatParams::default(),
            run_id.to_string(),
        )
        .await;

    match res {
        Err(LlmError::BudgetExceeded(reason)) => {
            assert_eq!(
                reason, "budget-exceeded-rounds",
                "rounds-budget deny reason"
            );
        }
        other => panic!("expected BudgetExceeded(budget-exceeded-rounds), got {other:?}"),
    }

    // The denied call never reached the provider, and no llm.request was emitted.
    assert_eq!(
        sut.llm_chat_request_count(),
        0,
        "provider never dialed on a budget deny"
    );
    assert!(
        !sut.events().iter().any(|e| e.event_type == "llm.request"),
        "no llm.request emitted for the denied call"
    );
}

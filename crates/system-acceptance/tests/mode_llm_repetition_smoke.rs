//! HF-2 builder smoke — `.repetition()` threads a real `RepetitionGuard` into the shipped
//! loopback gateway: a repeated identical LLM output trips `Terminate`. Proves the shipped
//! `SystemUnderTest::builder().repetition()` knob wires through (the journey witness
//! SYS-J-38 uses the separate test-local `h_loopback` helper with `WarnThenTerminate`;
//! this builder-path smoke deliberately uses `Terminate` for a minimal 2-call witness).

use std::sync::Arc;

use advance_run_manager::{RepetitionAction, RepetitionGuard};
use advance_shared_types::traits::RepetitionGuardCheck;
use cap_llm::{ChatMessage, ChatParams, ChatRole, LlmError, LlmGatewayInternal};
use system_acceptance::llm_loopback::ScriptedResponse;
use system_acceptance::{Cap, LlmMode, SystemUnderTest};

const CORE_BYTES: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-j01-skeleton.core.wasm");

fn user_msg() -> Vec<ChatMessage> {
    vec![ChatMessage {
        role: ChatRole::User,
        content: "hi".into(),
    }]
}

#[tokio::test(flavor = "multi_thread")]
async fn repetition_knob_terminates_on_repeated_output() {
    // Terminate on the 2nd identical output (threshold 2). The single scripted (non-
    // whitespace) reply replays for every call → identical output hash each turn; the
    // gateway records output ONCE per generate at terminal success.
    let guard: Arc<dyn RepetitionGuardCheck> =
        Arc::new(RepetitionGuard::new(8, 2, RepetitionAction::Terminate));

    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Fs, Cap::Llm])
        .repetition(guard)
        .llm(LlmMode::LoopbackScripted(vec![ScriptedResponse::ok_chat(
            "the identical answer",
            1,
            1,
        )]))
        .build(CORE_BYTES)
        .await;

    let gateway = sut.llm_gateway().expect("loopback gateway registered");

    // Call 1 (run-length 1 < 2) → Pass → Ok.
    let first = gateway.chat(user_msg(), ChatParams::default()).await;
    assert!(
        first.is_ok(),
        "first identical output passes the guard: {first:?}"
    );

    // Call 2 (run-length 2 ≥ 2, action Terminate) → Terminate → Err(RepetitionTerminated).
    let second = gateway.chat(user_msg(), ChatParams::default()).await;
    assert!(
        matches!(second, Err(LlmError::RepetitionTerminated(_))),
        "2nd identical output trips Terminate through the supplied guard, got {second:?}"
    );
}

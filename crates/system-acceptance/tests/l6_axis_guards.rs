//! Wave-7 Lane A — fail-loud composition guards for the L6-classifier injection axes
//! (`.with_recording_l6()` / `.with_failing_l6_gateway()`). Each guard panics in `build()`
//! BEFORE the guest is instantiated, so a misconfigured harness fails loudly rather than
//! SILENTLY skipping the live-PP attach (and building a never-driven second L6 gateway).

use system_acceptance::llm_loopback::ScriptedResponse;
use system_acceptance::{Cap, LlmMode, SystemUnderTest};

const HELLO_LLM_CORE: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-hello-llm.core.wasm");

fn llm() -> LlmMode {
    LlmMode::LoopbackScripted(vec![ScriptedResponse::ok_chat("reply", 1, 1)])
}

/// recording axis without `.with_live_memory()` → panic (the L6 dispatch attaches to the
/// live post-processor).
#[tokio::test]
#[should_panic(expected = "require with_live_memory")]
async fn recording_l6_requires_live_memory() {
    let _ = SystemUnderTest::builder()
        .caps(&[Cap::Memory, Cap::Llm])
        .llm(llm())
        .with_recording_l6()
        .build(HELLO_LLM_CORE)
        .await;
}

/// recording axis without `Cap::Memory` → panic (no shared store ⇒ no live post-processor).
#[tokio::test]
#[should_panic(expected = "require Cap::Memory")]
async fn recording_l6_requires_cap_memory() {
    let _ = SystemUnderTest::builder()
        .caps(&[Cap::Llm])
        .llm(llm())
        .with_live_memory()
        .with_recording_l6()
        .build(HELLO_LLM_CORE)
        .await;
}

/// failing-gateway axis without a main loopback LLM → panic (the live post-processor is never
/// installed, so the second L6 gateway would be built but never driven).
#[tokio::test]
#[should_panic(expected = "require a loopback LLM")]
async fn failing_l6_gateway_requires_loopback() {
    let _ = SystemUnderTest::builder()
        .caps(&[Cap::Memory])
        .with_live_memory()
        .with_failing_l6_gateway()
        .build(HELLO_LLM_CORE)
        .await;
}

/// the recording + failing-gateway axes are mutually exclusive → panic.
#[tokio::test]
#[should_panic(expected = "mutually exclusive")]
async fn recording_and_failing_gateway_are_mutually_exclusive() {
    let _ = SystemUnderTest::builder()
        .caps(&[Cap::Memory, Cap::Llm])
        .llm(llm())
        .with_live_memory()
        .with_recording_l6()
        .with_failing_l6_gateway()
        .build(HELLO_LLM_CORE)
        .await;
}

/// the failing-gateway + failing-committer fault axes are mutually exclusive → panic.
#[tokio::test]
#[should_panic(expected = "mutually exclusive")]
async fn failing_gateway_and_failing_committer_are_mutually_exclusive() {
    let _ = SystemUnderTest::builder()
        .caps(&[Cap::Memory, Cap::Llm])
        .llm(llm())
        .with_live_memory()
        .with_failing_l6_gateway()
        .with_failing_l6_committer()
        .build(HELLO_LLM_CORE)
        .await;
}

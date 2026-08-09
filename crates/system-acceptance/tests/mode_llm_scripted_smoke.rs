//! HF-2 builder smokes — the scriptable FIFO backend (`LlmMode::LoopbackScripted`) +
//! gateway-event exposure through the shipped `SystemUnderTest`:
//!  - a scripted `429-then-200` is retried by the REAL gateway retry loop (the mock
//!    returns the scripted HTTP status; the real OpenAI adapter maps 429→RateLimited);
//!  - the gateway's `llm.*` events now surface through the harness `events()` sink
//!    (previously a private bus), incl. the cost-bearing `llm.response` (J-42 cost witness
//!    at the event level).
//!
//! These run under `#[tokio::test(flavor = "multi_thread")]` (real-TCP loopback + a real
//! ~1s backoff sleep on the retry — the same proven shape as `sys_j40_retry.rs`).

use cap_llm::{
    ChatMessage, ChatParams, ChatRole, LlmGatewayInternal, LLM_REQUEST, LLM_RESPONSE, LLM_RETRY,
};
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

fn retry_then_ok() -> Vec<ScriptedResponse> {
    vec![
        ScriptedResponse::err(429, r#"{"error":{"message":"rate limited"}}"#),
        ScriptedResponse::ok_chat("recovered", 3, 4),
    ]
}

/// RETRY-SMOKE: the scripted FIFO serves 429 then 200; the gateway retries and returns Ok,
/// and the loopback mock observed exactly two chat requests.
#[tokio::test(flavor = "multi_thread")]
async fn scripted_backend_retries_429_then_succeeds() {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Fs, Cap::Llm])
        .llm(LlmMode::LoopbackScripted(retry_then_ok()))
        .build(CORE_BYTES)
        .await;

    let res = sut
        .llm_gateway()
        .expect("loopback gateway registered")
        .chat(user_msg(), ChatParams::default())
        .await;

    assert!(res.is_ok(), "429 retried then 200 returned Ok: {res:?}");
    assert_eq!(
        res.unwrap().text,
        "recovered",
        "the trailing 200 reply reached the caller"
    );
    assert_eq!(
        sut.llm_chat_request_count(),
        2,
        "429 then 200 = two upstream requests"
    );
}

/// EVENT-EXPOSURE-SMOKE: the loopback gateway's `llm.*` events surface through the harness
/// `events()` sink, with exactly one cost-bearing `llm.response` at terminal success.
#[tokio::test(flavor = "multi_thread")]
async fn gateway_events_surface_through_harness_sink() {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Fs, Cap::Llm])
        .llm(LlmMode::LoopbackScripted(retry_then_ok()))
        .build(CORE_BYTES)
        .await;

    sut.llm_gateway()
        .expect("loopback gateway registered")
        .chat(user_msg(), ChatParams::default())
        .await
        .expect("retry succeeds");

    let events = sut.events();
    assert!(
        events.iter().any(|e| e.event_type == LLM_REQUEST),
        "llm.request surfaced through the harness sink"
    );
    assert!(
        events.iter().any(|e| e.event_type == LLM_RETRY),
        "llm.retry surfaced (the 429 was retried)"
    );

    let responses: Vec<_> = events
        .iter()
        .filter(|e| e.event_type == LLM_RESPONSE)
        .collect();
    assert_eq!(
        responses.len(),
        1,
        "exactly one llm.response at terminal success"
    );

    // The J-42 cost-event witness at the event level: llm.response carries cost_usd + tokens.
    let payload = &responses[0].payload;
    assert!(
        payload.get("cost_usd").and_then(|v| v.as_f64()).is_some(),
        "llm.response payload carries cost_usd"
    );
    assert!(
        payload
            .get("input_tokens")
            .and_then(|v| v.as_u64())
            .is_some(),
        "llm.response payload carries input_tokens"
    );
    assert!(
        payload
            .get("output_tokens")
            .and_then(|v| v.as_u64())
            .is_some(),
        "llm.response payload carries output_tokens"
    );
}

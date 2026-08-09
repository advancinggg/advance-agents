//! SYS-J-40 — a rate-limited or schema-invalid LLM call is retried with exponential
//! backoff and structured-output re-validation, ultimately returning a valid result
//! with retry events emitted.
//! Chain: MODULE-009 cap-llm → MODULE-012 cap-http → MODULE-019 observability.
//!
//! Witnessed test-local against the REAL `cap_llm::LlmGateway` retry loop + REAL
//! `cap_http::DefaultHttpSecurityChain`, with a scripted loopback backend (the sole
//! allowed mock) returning the SCRIPTED HTTP status so the REAL OpenAI adapter does
//! the 429→RateLimited / 401→ProviderError mapping. The structured-output cases drive
//! the PUBLIC `AgentLlmGenerateHandler` host-fn surface (the only public path that
//! sets `output_schema=Some`).
//!
//! SYS-AC-129 (successive llm.retry delays increasing/exponential) is witnessed
//! since the small-witness slice (2026-06-11): the public agent-tier knob
//! (`cap_llm::PartialRetry` + `with_retry_overrides`, jitter=false base=100)
//! makes the delay_ms sequence deterministically [100, 200, 400].

#[path = "h_loopback/mod.rs"]
mod h_loopback;
use h_loopback::{boot, CapturingBus, GatewayDeps, ScriptedResponse};

use std::sync::Arc;

use advance_run_manager::{RepetitionAction, RepetitionGuard, RunManager};
use advance_runtime::host_registry::{HostCallContext, HostFunctionHandler};
use advance_shared_types::traits::{RepetitionGuardCheck, RunBudget};
use cap_llm::host_fn::AgentLlmGenerateHandler;
use cap_llm::{
    ChatMessage, ChatParams, ChatRole, LlmError, LlmGatewayInternal, LLM_ERROR, LLM_REQUEST,
    LLM_RESPONSE, LLM_RETRY,
};
use wasmtime::component::Val;

const AGENT: &str = "agent:harness";
/// `{ x: integer }` — content `{"x":42}` validates; `{"x":"not an int"}` fails.
const SCHEMA: &str = r#"{"type":"object","properties":{"x":{"type":"integer"}},"required":["x"]}"#;

fn user_msg() -> Vec<ChatMessage> {
    vec![ChatMessage {
        role: ChatRole::User,
        content: "hi".into(),
    }]
}
fn benign_guard() -> Arc<dyn RepetitionGuardCheck> {
    Arc::new(RepetitionGuard::new(8, 100, RepetitionAction::WarnOnly))
}
fn unused_real_budget() -> Arc<dyn RunBudget> {
    Arc::new(RunManager::new(Arc::new(CapturingBus::new())).budget())
}
fn host_ctx() -> HostCallContext {
    HostCallContext {
        agent_id: AGENT.into(),
        trace_id: "trace-h40".into(),
        turn_id: None,
        capability: "llm".into(),
        function: "agent-llm::generate".into(),
        run_id: None,
        iteration: None,
    }
}
/// The WIT `llm-request` record arg (the first `Val` MUST be a Record carrying
/// `output-schema`; a bare `Val::String` leaves output_schema=None).
fn structured_request(prompt: &str, schema: &str) -> Val {
    Val::Record(vec![
        ("prompt".into(), Val::String(prompt.into())),
        (
            "output-schema".into(),
            Val::Option(Some(Box::new(Val::String(schema.into())))),
        ),
        ("params".into(), Val::Option(None)),
    ])
}

/// SYS-AC-128: a generate call that first hits a rate-limited response ultimately
/// returns a valid llm-response, with ≥1 llm.retry event then one llm.response.
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_128_rate_limited_then_success_emits_retry() {
    let llm_bus = Arc::new(CapturingBus::new());
    let harness = boot(
        vec![
            ScriptedResponse::err(429, r#"{"error":{"message":"rate limited"}}"#),
            ScriptedResponse::ok_chat("recovered answer", 3, 4),
        ],
        GatewayDeps {
            run_budget: unused_real_budget(),
            repetition_guard: benign_guard(),
            event_bus: llm_bus.clone(),
            default_agent_id: AGENT.into(),
        },
    )
    .await;

    let res = harness
        .gateway
        .chat(user_msg(), ChatParams::default())
        .await;
    assert!(
        res.is_ok(),
        "the 429 was retried and the 200 returned Ok: {res:?}"
    );

    // Exactly the [request, retry, response] sequence — one retry, one final response.
    assert_eq!(
        llm_bus.event_type_sequence(),
        vec![
            LLM_REQUEST.to_string(),
            LLM_RETRY.to_string(),
            LLM_RESPONSE.to_string()
        ],
        "request → retry → response"
    );
    assert_eq!(
        harness.server.recorder().chat_request_count(),
        2,
        "429 then 200"
    );
}

/// SYS-AC-230: a non-transport provider failure (HTTP 401) is classified
/// non-retryable and returned WITHOUT emitting any llm.retry event.
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_230_non_transport_4xx_is_not_retried() {
    let llm_bus = Arc::new(CapturingBus::new());
    let harness = boot(
        vec![ScriptedResponse::err(
            401,
            r#"{"error":{"message":"bad key"}}"#,
        )],
        GatewayDeps {
            run_budget: unused_real_budget(),
            repetition_guard: benign_guard(),
            event_bus: llm_bus.clone(),
            default_agent_id: AGENT.into(),
        },
    )
    .await;

    let res = harness
        .gateway
        .chat(user_msg(), ChatParams::default())
        .await;
    assert!(
        matches!(res, Err(LlmError::ProviderError(_))),
        "401 maps to a non-retryable provider error, got {res:?}"
    );
    assert_eq!(
        llm_bus.count(LLM_RETRY),
        0,
        "no llm.retry for a non-transport 4xx"
    );
    assert_eq!(
        llm_bus.event_type_sequence(),
        vec![LLM_REQUEST.to_string(), LLM_ERROR.to_string()],
        "request → error (no retry)"
    );
    assert_eq!(
        harness.server.recorder().chat_request_count(),
        1,
        "exactly one attempt"
    );
}

/// SYS-AC-130: a structured-output call whose first response fails schema validation
/// is re-validated after retry (≤2 structured retries) and returns schema-valid
/// parsed-output.
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_130_structured_output_revalidated_after_retry() {
    let llm_bus = Arc::new(CapturingBus::new());
    let harness = boot(
        vec![
            ScriptedResponse::ok_chat(r#"{"x":"not an int"}"#, 1, 1), // fails schema
            ScriptedResponse::ok_chat(r#"{"x":42}"#, 1, 1),           // passes schema
        ],
        GatewayDeps {
            run_budget: unused_real_budget(),
            repetition_guard: benign_guard(),
            event_bus: llm_bus.clone(),
            default_agent_id: AGENT.into(),
        },
    )
    .await;

    let handler = AgentLlmGenerateHandler {
        gateway: harness.gateway.clone(),
        turn_cost: None,
    };
    let out = handler
        .call(host_ctx(), vec![structured_request("give me x", SCHEMA)], 1)
        .await
        .expect("handler call ok");

    assert_eq!(out.len(), 1);
    match &out[0] {
        Val::Result(Ok(Some(boxed))) => match boxed.as_ref() {
            Val::Record(fields) => {
                let parsed = fields
                    .iter()
                    .find(|(n, _)| n == "parsed-output")
                    .map(|(_, v)| v)
                    .expect("parsed-output field present");
                assert!(
                    matches!(parsed, Val::Option(Some(_))),
                    "parsed-output is Some (schema re-validated to valid after retry)"
                );
            }
            other => panic!("expected llm-response record, got {other:?}"),
        },
        other => panic!("expected Result::Ok(Some(record)), got {other:?}"),
    }
    assert_eq!(
        harness.server.recorder().chat_request_count(),
        2,
        "invalid then valid (1 retry)"
    );
    let responses = llm_bus.events_named(LLM_RESPONSE);
    assert_eq!(
        responses.len(),
        1,
        "exactly one llm.response at terminal success"
    );
    assert_eq!(
        responses[0]
            .payload
            .get("structured_retry_attempt")
            .and_then(|v| v.as_u64()),
        Some(1),
        "one structured retry occurred"
    );
}

/// SYS-AC-229: a structured-output call whose response still fails schema validation
/// after the retry cap is exhausted returns llm-error::structured-output-failed
/// (terminal, non-retryable) rather than retrying indefinitely.
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_229_structured_output_terminal_after_cap() {
    let llm_bus = Arc::new(CapturingBus::new());
    // One schema-failing envelope, replayed for every attempt.
    let harness = boot(
        vec![ScriptedResponse::ok_chat(
            r#"{"x":"still not an int"}"#,
            1,
            1,
        )],
        GatewayDeps {
            run_budget: unused_real_budget(),
            repetition_guard: benign_guard(),
            event_bus: llm_bus.clone(),
            default_agent_id: AGENT.into(),
        },
    )
    .await;

    let handler = AgentLlmGenerateHandler {
        gateway: harness.gateway.clone(),
        turn_cost: None,
    };
    let out = handler
        .call(host_ctx(), vec![structured_request("give me x", SCHEMA)], 1)
        .await
        .expect("handler call ok");

    assert_eq!(out.len(), 1);
    match &out[0] {
        Val::Result(Err(Some(boxed))) => match boxed.as_ref() {
            Val::Variant(case, _) => assert_eq!(
                case, "structured-output-failed",
                "terminal structured-output-failed after the retry cap"
            ),
            other => panic!("expected llm-error variant, got {other:?}"),
        },
        other => panic!("expected Result::Err(Some(variant)), got {other:?}"),
    }
    // ≤2 structured retries → 3 upstream attempts then terminal (not indefinite).
    assert_eq!(
        harness.server.recorder().chat_request_count(),
        3,
        "3 attempts then terminal"
    );
}

/// SYS-AC-129 — successive llm.retry events show increasing backoff delay
/// (exponential, per retry-overrides). The small-witness slice (2026-06-11)
/// shipped the public agent-tier knob (`cap_llm::PartialRetry` +
/// `LlmGateway::with_retry_overrides`), so with `jitter: Some(false)` +
/// `base_delay_ms: Some(100)` the emitted delay_ms sequence is fully
/// deterministic `min(base·2^(n−1), max_delay)` = [100, 200, 400] — strictly
/// increasing, ratio exactly 2. Witnessed through the REAL gateway + REAL
/// cap-http chain against a scripted `[429,429,429,200]` loopback (the real
/// OpenAI adapter does the 429→RateLimited mapping). Total real sleep ≈0.7s.
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_129_successive_retries_show_increasing_backoff() {
    let llm_bus = Arc::new(CapturingBus::new());
    let harness = h_loopback::boot_with_retry_overrides(
        vec![
            ScriptedResponse::err(429, r#"{"error":{"message":"slow down"}}"#),
            ScriptedResponse::err(429, r#"{"error":{"message":"slow down"}}"#),
            ScriptedResponse::err(429, r#"{"error":{"message":"slow down"}}"#),
            ScriptedResponse::ok_chat("finally", 2, 3),
        ],
        GatewayDeps {
            run_budget: unused_real_budget(),
            repetition_guard: benign_guard(),
            event_bus: llm_bus.clone(),
            default_agent_id: AGENT.into(),
        },
        cap_llm::PartialRetry {
            max_retries: Some(3),
            base_delay_ms: Some(100),
            max_delay_ms: None,
            jitter: Some(false),
        },
    )
    .await;

    let resp = harness
        .gateway
        .chat(user_msg(), ChatParams::default())
        .await
        .expect("3×429 then 200 recovers");
    assert_eq!(resp.text, "finally");

    // Exactly 4 upstream attempts (3 retries + terminal success).
    assert_eq!(harness.server.recorder().chat_request_count(), 4);

    // The witness: successive llm.retry delay_ms are EXACTLY [100, 200, 400] —
    // monotonic exponential per the installed retry-overrides, no jitter.
    let delays: Vec<u64> = llm_bus
        .events_named(LLM_RETRY)
        .iter()
        .map(|e| {
            e.payload
                .get("delay_ms")
                .and_then(|v| v.as_u64())
                .expect("llm.retry carries delay_ms")
        })
        .collect();
    assert_eq!(
        delays,
        vec![100, 200, 400],
        "deterministic exponential backoff"
    );
    assert!(
        delays.windows(2).all(|w| w[1] == w[0] * 2),
        "each delay is exactly double the previous"
    );
}

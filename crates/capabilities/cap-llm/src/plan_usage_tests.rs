//! Gateway-level witnesses for a provider entry whose credential is a Sign in with ChatGPT
//! session (`auth-source: chatgpt-oauth`).
//!
//! Every test drives the REAL `LlmGateway` request paths (`generate`, `stream_begin`,
//! `stream_begin_live`, `embed`) or the real VLM extractor with a scripted
//! `MockHttpSecurityChain`, a recording credential source and a recording bus, and asserts on
//! what actually left the gateway (which transport, which bytes), on the typed outcome, and
//! on the events and budget entries left behind.

#![cfg(test)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use advance_shared_types::security_validator::{
    HttpError, HttpResponse, HttpSecurityChain, HttpStreamingChain,
};
use advance_shared_types::traits::{EventBusEmit, RepetitionGuardCheck, RunBudget};
use async_trait::async_trait;

use crate::cost::{compute_cost, CacheUsage};
use crate::credential::{CredentialFailure, ProviderCredentialSource};
use crate::gateway::{
    is_embedding_capable, plan_usage_status_error, select_embedding_provider, ChatMessage,
    ChatParams, ChatResponse, ChatRole, LlmGateway, LlmGatewayInternal, LlmRequestContext,
};
use crate::stream::{PollOutcome, StreamRegistry};
use crate::test_support::{
    fixture_runtime_config, MockEventBusEmit, MockHttpSecurityChain, MockRunBudget,
    MockRuntimeConfigProvider,
};
use crate::vlm::{FileContent, LlmGatewayVlm, VlmExtractor};
use crate::{LlmError, LLM_ERROR, LLM_REQUEST, LLM_RESPONSE, LLM_RETRY};

// ── fixtures ─────────────────────────────────────────────────────────────────────────────────

const PLAN_ID: &str = "openai-plan";
const PLAN_SECRET: &str = "openai-plan-token";
const RESPONSES_URL: &str = "https://api.openai.com/v1/responses";

/// The streamed request a ChatGPT sign-in entry sends for [`ctx`]: `store: false`,
/// `stream: true`, `include` kept, and neither the caller's `temperature` nor `max_tokens`.
const PLAN_STREAM_BODY: &str = r#"{"include":["reasoning.encrypted_content"],"input":[{"content":"hi","role":"user"}],"model":"gpt-5","store":false,"stream":true}"#;

/// The unstreamed request an API-key `openai-responses` entry sends for [`ctx`].
const KEYED_BUFFERED_BODY: &str = r#"{"include":["reasoning.encrypted_content"],"input":[{"content":"hi","role":"user"}],"max_output_tokens":128,"model":"gpt-5","store":false,"temperature":0.5}"#;

const USAGE_LIMIT_CODE: &str = "subscription_sharing_usage_limit_exceeded";
const INVALID_USER_CODE: &str = "subscription_sharing_invalid_user";

const SIGN_IN_REJECTED: &str = "chatgpt-plan: sign-in rejected";
const USAGE_LIMIT_REACHED: &str = "chatgpt-plan: usage limit reached";

/// `openai-plan` (aliases `plan`, `shared`) signs in with ChatGPT; `openai-key` (alias
/// `keyed`) is the same dialect and endpoint on an API key; `fallback` (alias `shared`) is
/// an API-key chat-completions entry on another host, the next candidate after
/// `openai-plan` for `shared`.
fn plan_config() -> advance_runtime::config::RuntimeConfig {
    let mut cfg = fixture_runtime_config();
    cfg.llm_providers = serde_yml::from_str(
        r#"
- id: openai-plan
  endpoint: https://api.openai.com
  api-key-secret: openai-plan-token
  auth-source: chatgpt-oauth
  model-aliases:
    plan: gpt-5
    shared: gpt-5
  cost-per-mtoken-in: 1.25
  cost-per-mtoken-out: 10.0
- id: openai-key
  endpoint: https://api.openai.com
  api-key-secret: openai-api-key
  backend: openai-responses
  model-aliases:
    keyed: gpt-5
  cost-per-mtoken-in: 1.25
  cost-per-mtoken-out: 10.0
- id: fallback
  endpoint: https://fallback.example.com
  api-key-secret: fallback-api-key
  model-aliases:
    shared: fb-model
  cost-per-mtoken-in: 1.0
  cost-per-mtoken-out: 2.0
"#,
    )
    .expect("provider entries must parse");
    cfg
}

/// Records every call with the number of events and upstream requests that existed when it
/// was made; answers `ensure_fresh` with the scripted failure, if any, or never (`stall`).
/// Each refusal report also records the events emitted and the budget commits made before it.
struct RecordingSource {
    failure: Mutex<Option<CredentialFailure>>,
    stall: Mutex<bool>,
    fresh: Mutex<Vec<(String, String, usize, usize)>>,
    rejected: Mutex<Vec<(String, String)>>,
    rejected_after: Mutex<Vec<(Vec<String>, usize)>>,
    bus: Arc<MockEventBusEmit>,
    chain: Arc<MockHttpSecurityChain>,
    budget: Arc<MockRunBudget>,
}

impl RecordingSource {
    fn fail_with(&self, failure: Option<CredentialFailure>) {
        *self.failure.lock().unwrap() = failure;
    }
    fn stall(&self) {
        *self.stall.lock().unwrap() = true;
    }
    fn fresh_calls(&self) -> Vec<(String, String, usize, usize)> {
        self.fresh.lock().unwrap().clone()
    }
    fn rejected_calls(&self) -> Vec<(String, String)> {
        self.rejected.lock().unwrap().clone()
    }
    /// For each refusal report: the event types emitted and the budget commits made by then.
    fn rejected_after(&self) -> Vec<(Vec<String>, usize)> {
        self.rejected_after.lock().unwrap().clone()
    }
}

#[async_trait]
impl ProviderCredentialSource for RecordingSource {
    async fn ensure_fresh(
        &self,
        provider_id: &str,
        secret_name: &str,
    ) -> Result<(), CredentialFailure> {
        self.fresh.lock().unwrap().push((
            provider_id.to_string(),
            secret_name.to_string(),
            self.bus.snapshot().len(),
            self.chain.call_log.lock().unwrap().len(),
        ));
        if *self.stall.lock().unwrap() {
            std::future::pending::<()>().await;
        }
        match *self.failure.lock().unwrap() {
            Some(failure) => Err(failure),
            None => Ok(()),
        }
    }

    async fn credential_rejected(&self, provider_id: &str, secret_name: &str) {
        self.rejected
            .lock()
            .unwrap()
            .push((provider_id.to_string(), secret_name.to_string()));
        let events = self
            .bus
            .snapshot()
            .iter()
            .map(|e| e.event_type.clone())
            .collect();
        let commits = self.budget.commits.lock().unwrap().len();
        self.rejected_after.lock().unwrap().push((events, commits));
    }
}

struct Rig {
    gateway: Arc<LlmGateway>,
    chain: Arc<MockHttpSecurityChain>,
    budget: Arc<MockRunBudget>,
    bus: Arc<MockEventBusEmit>,
    source: Arc<RecordingSource>,
    registry: Arc<StreamRegistry>,
}

impl Rig {
    fn event_types(&self) -> Vec<String> {
        self.bus
            .snapshot()
            .iter()
            .map(|e| e.event_type.clone())
            .collect()
    }

    fn event_count(&self, event_type: &str) -> usize {
        self.bus
            .snapshot()
            .iter()
            .filter(|e| e.event_type == event_type)
            .count()
    }

    /// How many upstream requests were made, over both transports.
    fn requests(&self) -> usize {
        self.chain.call_log.lock().unwrap().len()
    }

    fn streamed_urls(&self) -> Vec<String> {
        self.chain.streamed_urls.lock().unwrap().clone()
    }
}

/// A gateway over [`plan_config`]. `live_streaming` wires the streaming chain and the decoded
/// detector; `generate_timeout` shortens the hop budget of `generate`.
fn build_rig(
    install_source: bool,
    live_streaming: bool,
    generate_timeout: Option<Duration>,
) -> Rig {
    let chain = Arc::new(MockHttpSecurityChain::default());
    let budget = Arc::new(MockRunBudget::default());
    let bus = Arc::new(MockEventBusEmit::default());
    let source = Arc::new(RecordingSource {
        failure: Mutex::new(None),
        stall: Mutex::new(false),
        fresh: Mutex::new(Vec::new()),
        rejected: Mutex::new(Vec::new()),
        rejected_after: Mutex::new(Vec::new()),
        bus: Arc::clone(&bus),
        chain: Arc::clone(&chain),
        budget: Arc::clone(&budget),
    });
    let mut gateway = LlmGateway::new(
        Arc::new(MockRuntimeConfigProvider::new(plan_config())),
        Arc::clone(&chain) as Arc<dyn HttpSecurityChain>,
        Arc::clone(&budget) as Arc<dyn RunBudget>,
        Arc::clone(&bus) as Arc<dyn EventBusEmit>,
        crate::test_support::no_op_repetition_guard() as Arc<dyn RepetitionGuardCheck>,
        "test-agent".into(),
    );
    if live_streaming {
        gateway = gateway.with_live_streaming(
            Arc::clone(&chain) as Arc<dyn HttpStreamingChain>,
            Arc::new(cap_http::DefaultLeakDetector::default()),
        );
    }
    if install_source {
        gateway = gateway
            .with_credential_source(Arc::clone(&source) as Arc<dyn ProviderCredentialSource>);
    }
    if let Some(timeout) = generate_timeout {
        gateway = gateway.with_generate_timeout(timeout);
    }
    Rig {
        gateway: Arc::new(gateway),
        chain,
        budget,
        bus,
        source,
        registry: Arc::new(StreamRegistry::new()),
    }
}

fn rig(install_source: bool) -> Rig {
    build_rig(install_source, true, None)
}

fn ctx(alias: &str) -> LlmRequestContext {
    LlmRequestContext {
        agent_id: "test-agent".into(),
        run_id: Some("run-1".into()),
        messages: vec![ChatMessage {
            role: ChatRole::User,
            content: "hi".into(),
        }],
        params: ChatParams {
            model: Some(alias.into()),
            temperature: Some(0.5),
            max_tokens: Some(128),
            ..ChatParams::default()
        },
        ..LlmRequestContext::default()
    }
}

/// The error of each dispatch site for one request on `alias`: buffered generate, the
/// buffered stream fallback, the live stream.
async fn errors_at_every_site(rig: &Rig, alias: &str) -> [LlmError; 3] {
    let generate = rig
        .gateway
        .generate(ctx(alias))
        .await
        .expect_err("generate must fail");
    let buffered = buffered_stream(rig, alias)
        .await
        .expect_err("stream_begin must fail");
    let live = rig
        .gateway
        .stream_begin_live(ctx(alias), &rig.registry)
        .await
        .expect_err("stream_begin_live must fail");
    [generate, buffered, live]
}

/// The buffered stream site end to end: `stream_begin`, then the done poll's
/// `stream_finish`.
async fn buffered_stream(rig: &Rig, alias: &str) -> Result<ChatResponse, LlmError> {
    let ready = rig.gateway.stream_begin(ctx(alias)).await?;
    Ok(rig.gateway.stream_finish(ready))
}

/// Nothing left the host and nothing is owed: no event, no upstream request, no
/// reservation, no commit.
fn assert_nothing_dispatched(rig: &Rig) {
    assert!(rig.bus.snapshot().is_empty(), "no event may be emitted");
    assert_eq!(rig.requests(), 0, "no upstream request may be made");
    assert!(
        rig.budget
            .checks
            .lock()
            .unwrap()
            .iter()
            .all(|(_, tokens, _)| *tokens == 0),
        "no budget may be reserved"
    );
    assert!(rig.budget.commits.lock().unwrap().is_empty());
}

/// A static reason never carries what the upstream sent.
fn assert_static(err: &LlmError) {
    assert!(!err.to_string().contains("LEAK"), "{err}");
}

fn plan_err(reason: &str) -> LlmError {
    LlmError::ProviderError(reason.into())
}

fn responses_stream(frames: &[(&str, &str)]) -> Vec<Result<Vec<u8>, HttpError>> {
    frames
        .iter()
        .map(|(event, data)| Ok(format!("event: {event}\ndata: {data}\n\n").into_bytes()))
        .collect()
}

const DELTA_HELLO: (&str, &str) = (
    "response.output_text.delta",
    r#"{"type":"response.output_text.delta","delta":"hello"}"#,
);
const COMPLETED_3_2: (&str, &str) = (
    "response.completed",
    r#"{"type":"response.completed","response":{"usage":{"input_tokens":3,"output_tokens":2}}}"#,
);

/// "hello", 3 input and 2 output tokens.
fn completed_stream() -> Vec<Result<Vec<u8>, HttpError>> {
    responses_stream(&[DELTA_HELLO, COMPLETED_3_2])
}

/// A refused answer's body naming an upstream error code.
fn coded_body(code: &str) -> Vec<Result<Vec<u8>, HttpError>> {
    vec![Ok(format!(
        r#"{{"error":{{"code":"{code}","message":"LEAK","type":"invalid_request_error"}}}}"#
    )
    .into_bytes())]
}

/// A refused answer's body without any error code.
fn uncoded_body() -> Vec<Result<Vec<u8>, HttpError>> {
    vec![Ok(br#"{"detail":"LEAK"}"#.to_vec())]
}

/// An unstreamed Responses answer: `text`, 3 input and 2 output tokens.
fn buffered_responses_answer(text: &str) -> HttpResponse {
    let body = serde_json::json!({
        "status": "completed",
        "model": "gpt-5",
        "output": [{"type": "message", "content": [{"type": "output_text", "text": text}]}],
        "usage": {"input_tokens": 3, "output_tokens": 2},
    });
    HttpResponse {
        status: 200,
        headers: vec![],
        body: serde_json::to_vec(&body).unwrap(),
    }
}

/// An unstreamed chat-completions answer.
fn chat_completions_answer(text: &str) -> HttpResponse {
    let body = serde_json::json!({
        "choices": [{"message": {"content": text}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 5, "completion_tokens": 7},
        "model": "fb-model",
    });
    HttpResponse {
        status: 200,
        headers: vec![],
        body: serde_json::to_vec(&body).unwrap(),
    }
}

/// Poll a live stream to its terminal outcome.
async fn terminal(rig: &Rig, handle: u64) -> PollOutcome {
    loop {
        let outcome = tokio::time::timeout(
            Duration::from_secs(5),
            rig.registry.poll_live(handle, "test-agent"),
        )
        .await
        .expect("the stream must reach a terminal outcome");
        if !matches!(outcome, PollOutcome::Delta(_)) {
            // Let the owner task run to its end.
            for _ in 0..8 {
                tokio::task::yield_now().await;
            }
            return outcome;
        }
    }
}

// ── the credential source at the three dispatch sites ────────────────────────────────────────

#[test]
fn credential_source_builder_and_witness() {
    assert!(!rig(false).gateway.has_credential_source());
    assert!(rig(true).gateway.has_credential_source());
}

/// Without a source a ChatGPT sign-in entry fails closed with a fixed reason at all three
/// dispatch sites, before anything is emitted, reserved or sent.
#[tokio::test]
async fn sign_in_entry_without_a_source_fails_closed_at_every_site() {
    let rig = rig(false);
    for err in errors_at_every_site(&rig, "plan").await {
        assert_eq!(err, plan_err("chatgpt-plan: credential source not wired"));
    }
    assert_nothing_dispatched(&rig);
}

/// The source is asked with the entry's id and secret name before dispatch at all three
/// sites; each failure becomes its fixed reason and leaves nothing behind.
#[tokio::test]
async fn freshness_failure_is_typed_and_leaves_no_event_and_no_reservation() {
    let rig = rig(true);
    for (failure, reason) in [
        (
            CredentialFailure::NotSignedIn,
            "chatgpt-plan: not signed in",
        ),
        (
            CredentialFailure::NotAuthorized,
            "chatgpt-plan: plan usage not authorized",
        ),
        (
            CredentialFailure::RefreshUnavailable,
            "chatgpt-plan: credential refresh unavailable",
        ),
        (
            CredentialFailure::Unavailable,
            "chatgpt-plan: credential source not wired",
        ),
    ] {
        rig.source.fail_with(Some(failure));
        for err in errors_at_every_site(&rig, "plan").await {
            assert_eq!(err, plan_err(reason));
        }
    }
    let calls = rig.source.fresh_calls();
    assert_eq!(calls.len(), 12, "one freshness check per request per site");
    for call in calls {
        assert_eq!(call, (PLAN_ID.to_string(), PLAN_SECRET.to_string(), 0, 0));
    }
    assert!(rig.source.rejected_calls().is_empty());
    assert_nothing_dispatched(&rig);
}

/// A freshness check that never answers is bounded by each site's own deadline — the hop
/// budget of `generate`, the buffered executor's default timeout at `stream_begin`, the stream
/// handle's lifetime at `stream_begin_live` — and ends as `deadline-exceeded` with nothing
/// emitted, sent or reserved.
#[tokio::test(start_paused = true)]
async fn a_freshness_check_that_never_answers_is_bounded_by_the_site_deadline() {
    let deadline = plan_err("deadline-exceeded");

    let rig = build_rig(true, true, Some(Duration::from_secs(2)));
    rig.source.stall();
    let started = tokio::time::Instant::now();
    assert_eq!(
        rig.gateway.generate(ctx("plan")).await,
        Err(deadline.clone())
    );
    let waited = started.elapsed();
    assert!(
        waited >= Duration::from_secs(2) && waited < Duration::from_secs(3),
        "{waited:?}"
    );
    assert_nothing_dispatched(&rig);

    let rig = self::rig(true);
    rig.source.stall();
    let started = tokio::time::Instant::now();
    assert_eq!(buffered_stream(&rig, "plan").await, Err(deadline.clone()));
    let waited = started.elapsed();
    assert!(
        waited >= Duration::from_secs(25) && waited <= cap_http::DEFAULT_TIMEOUT,
        "{waited:?}"
    );
    assert_nothing_dispatched(&rig);

    let rig = self::rig(true);
    rig.source.stall();
    let started = tokio::time::Instant::now();
    assert_eq!(
        rig.gateway
            .stream_begin_live(ctx("plan"), &rig.registry)
            .await,
        Err(deadline)
    );
    let waited = started.elapsed();
    assert!(
        waited >= Duration::from_secs(290) && waited <= crate::host_fn::STREAM_HANDLE_TTL,
        "{waited:?}"
    );
    assert_nothing_dispatched(&rig);
    assert_eq!(rig.source.fresh_calls().len(), 1);
}

/// With a fresh credential the live request is dispatched after the freshness check, shaped
/// for the plan route; an API-key entry of the same dialect never consults the source and
/// keeps its request fields.
#[tokio::test]
async fn fresh_credential_dispatches_the_shaped_request_and_api_key_entries_skip_the_source() {
    let rig = rig(true);
    rig.chain
        .set_stream_results("/v1/responses", completed_stream());
    let handle = rig
        .gateway
        .stream_begin_live(ctx("plan"), &rig.registry)
        .await
        .expect("a fresh credential must reach dispatch");
    assert!(matches!(terminal(&rig, handle).await, PollOutcome::Done(_)));
    // Asked exactly once, before the request event and before the upstream request.
    assert_eq!(
        rig.source.fresh_calls(),
        vec![(PLAN_ID.to_string(), PLAN_SECRET.to_string(), 0, 0)]
    );
    {
        let log = rig.chain.call_log.lock().unwrap();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].url, RESPONSES_URL);
        assert_eq!(String::from_utf8_lossy(&log[0].body), PLAN_STREAM_BODY);
        assert!(log[0]
            .headers
            .iter()
            .any(|(n, v)| n == "Authorization" && v == "Bearer {openai-plan-token}"));
    }

    rig.chain
        .set_stream_results("/v1/responses", completed_stream());
    let handle = rig
        .gateway
        .stream_begin_live(ctx("keyed"), &rig.registry)
        .await
        .expect("the API-key entry must dispatch");
    assert!(matches!(terminal(&rig, handle).await, PollOutcome::Done(_)));
    assert_eq!(rig.source.fresh_calls().len(), 1, "API-key entry: no check");
    assert!(rig.source.rejected_calls().is_empty());
    let log = rig.chain.call_log.lock().unwrap();
    assert_eq!(log.len(), 2);
    let body: serde_json::Value = serde_json::from_slice(&log[1].body).unwrap();
    assert_eq!(body["max_output_tokens"], serde_json::json!(128));
    assert_eq!(body["temperature"], serde_json::json!(0.5));
    assert!(log[1]
        .headers
        .iter()
        .any(|(n, v)| n == "Authorization" && v == "Bearer {openai-api-key}"));
}

// ── buffered calls served by a streamed upstream ─────────────────────────────────────────────

/// Three text fragments around an ignorable item event, then the terminal event with usage
/// (11 input tokens of which 4 cached, 7 output tokens).
fn hello_world_stream() -> Vec<Result<Vec<u8>, HttpError>> {
    responses_stream(&[
        ("response.created", r#"{"type":"response.created"}"#),
        (
            "response.output_text.delta",
            r#"{"type":"response.output_text.delta","delta":"Hel"}"#,
        ),
        (
            "response.output_item.added",
            r#"{"type":"response.output_item.added"}"#,
        ),
        (
            "response.output_text.delta",
            r#"{"type":"response.output_text.delta","delta":"lo "}"#,
        ),
        (
            "response.output_text.delta",
            r#"{"type":"response.output_text.delta","delta":"world"}"#,
        ),
        (
            "response.completed",
            r#"{"type":"response.completed","response":{"usage":{"input_tokens":11,"output_tokens":7,"input_tokens_details":{"cached_tokens":4}}}}"#,
        ),
    ])
}

/// The cost of [`hello_world_stream`] on the sign-in entry, cached share included.
fn hello_world_cost() -> f64 {
    let resolved = crate::provider::make_resolved(&plan_config().llm_providers[0], "gpt-5".into());
    compute_cost(
        &resolved,
        11,
        7,
        CacheUsage {
            read_tokens: 4,
            write_tokens: 0,
            write_1h_tokens: 0,
        },
    )
}

/// The one request a buffered call on the sign-in entry sent: streamed, to the Responses
/// route, shaped for the plan route, carrying the entry's own credential placeholder.
fn assert_one_streamed_plan_request(rig: &Rig) {
    assert_eq!(rig.streamed_urls(), vec![RESPONSES_URL.to_string()]);
    let log = rig.chain.call_log.lock().unwrap();
    assert_eq!(log.len(), 1, "exactly one upstream request");
    assert_eq!(log[0].url, RESPONSES_URL);
    assert_eq!(String::from_utf8_lossy(&log[0].body), PLAN_STREAM_BODY);
    assert_eq!(
        log[0].headers,
        vec![
            (
                "Authorization".to_string(),
                "Bearer {openai-plan-token}".to_string()
            ),
            ("Content-Type".to_string(), "application/json".to_string()),
            ("Accept".to_string(), "text/event-stream".to_string()),
        ]
    );
}

fn assert_hello_world(response: &ChatResponse) {
    assert_eq!(response.text, "Hello world");
    assert_eq!(response.model, "gpt-5");
    assert_eq!(response.input_tokens, 11);
    assert_eq!(response.output_tokens, 7);
    assert_eq!(response.finish_reason, "stop");
}

/// The single `llm.response` of a buffered call on the sign-in entry: attributed to the
/// entry, with the usage the stream reported and the cost it implies.
fn assert_hello_world_response_event(rig: &Rig) {
    let events = rig.bus.snapshot();
    let response = events
        .iter()
        .find(|e| e.event_type == LLM_RESPONSE)
        .expect("llm.response");
    assert_eq!(response.payload["provider"], serde_json::json!(PLAN_ID));
    assert_eq!(response.payload["model"], serde_json::json!("gpt-5"));
    assert_eq!(response.payload["input_tokens"], serde_json::json!(11));
    assert_eq!(response.payload["output_tokens"], serde_json::json!(7));
    assert_eq!(
        response.payload["cost_usd"],
        serde_json::json!(hello_world_cost())
    );
}

/// A buffered `generate` on a ChatGPT sign-in entry is served by ONE streamed request —
/// after the freshness check, nothing unstreamed — and returns the assembled text with the
/// usage of the terminal event.
#[tokio::test]
async fn buffered_generate_is_served_by_one_streamed_request() {
    let rig = rig(true);
    rig.chain
        .push_stream("/v1/responses", 200, hello_world_stream());
    let response = rig
        .gateway
        .generate(ctx("plan"))
        .await
        .expect("the streamed answer must be returned whole");
    assert_hello_world(&response);

    assert_eq!(
        rig.source.fresh_calls(),
        vec![(PLAN_ID.to_string(), PLAN_SECRET.to_string(), 0, 0)],
        "asked once, before the request event and before the upstream request"
    );
    assert!(rig.source.rejected_calls().is_empty());
    assert_one_streamed_plan_request(&rig);
    assert_eq!(rig.event_types(), vec![LLM_REQUEST, LLM_RESPONSE]);
    assert_hello_world_response_event(&rig);
    assert_eq!(
        *rig.budget.commits.lock().unwrap(),
        vec![("run-1".to_string(), 18, hello_world_cost())]
    );
}

/// The buffered stream site is served the same way: one streamed request after the
/// freshness check, the whole text and its usage at the done poll, where the single
/// `llm.response` is emitted.
#[tokio::test]
async fn buffered_stream_begin_is_served_by_one_streamed_request() {
    let rig = rig(true);
    rig.chain
        .push_stream("/v1/responses", 200, hello_world_stream());
    let ready = match rig.gateway.stream_begin(ctx("plan")).await {
        Ok(ready) => ready,
        Err(err) => panic!("the streamed answer must be returned whole: {err}"),
    };
    assert_eq!(rig.event_types(), vec![LLM_REQUEST]);
    let response = rig.gateway.stream_finish(ready);
    assert_hello_world(&response);

    assert_eq!(
        rig.source.fresh_calls(),
        vec![(PLAN_ID.to_string(), PLAN_SECRET.to_string(), 0, 0)]
    );
    assert_one_streamed_plan_request(&rig);
    assert_eq!(rig.event_types(), vec![LLM_REQUEST, LLM_RESPONSE]);
    assert_hello_world_response_event(&rig);
    assert_eq!(
        *rig.budget.commits.lock().unwrap(),
        vec![("run-1".to_string(), 18, hello_world_cost())]
    );
}

/// A stream that ends without its terminal event is a failure at both buffered sites, not
/// a short answer: nothing is returned, nothing is committed, the request is not repeated.
#[tokio::test]
async fn stream_without_its_terminal_event_fails() {
    let eof = plan_err("stream eof before terminal");
    let text_only = || responses_stream(&[DELTA_HELLO]);

    let rig_generate = rig(true);
    rig_generate
        .chain
        .push_stream("/v1/responses", 200, text_only());
    assert_eq!(
        rig_generate.gateway.generate(ctx("plan")).await,
        Err(eof.clone())
    );

    let rig_stream = rig(true);
    rig_stream
        .chain
        .push_stream("/v1/responses", 200, text_only());
    assert_eq!(buffered_stream(&rig_stream, "plan").await, Err(eof.clone()));

    for rig in [&rig_generate, &rig_stream] {
        assert_eq!(rig.requests(), 1, "no retry");
        assert_eq!(rig.event_types(), vec![LLM_REQUEST, LLM_ERROR]);
        assert!(rig.budget.commits.lock().unwrap().is_empty());
    }

    // The live path refuses the same stream.
    let rig = self::rig(true);
    rig.chain.push_stream("/v1/responses", 200, text_only());
    let handle = rig
        .gateway
        .stream_begin_live(ctx("plan"), &rig.registry)
        .await
        .expect("the head is a 200");
    match terminal(&rig, handle).await {
        PollOutcome::Failed(LlmError::ProviderError(msg)) => {
            assert!(msg.ends_with("stream eof before terminal"), "{msg}")
        }
        _ => panic!("expected a failed stream"),
    }
}

/// The streamed answer is held to the unstreamed parser's shape rules: both usage counters
/// and some text are required.
#[tokio::test]
async fn streamed_answer_needs_usage_and_text_like_the_unstreamed_parser() {
    let invalid = plan_err("invalid response shape");
    for frames in [
        // No usage at all.
        vec![
            DELTA_HELLO,
            (
                "response.completed",
                r#"{"type":"response.completed","response":{}}"#,
            ),
        ],
        // Only one of the two counters.
        vec![
            DELTA_HELLO,
            (
                "response.completed",
                r#"{"type":"response.completed","response":{"usage":{"input_tokens":3}}}"#,
            ),
        ],
        // Usage, but no text part.
        vec![COMPLETED_3_2],
    ] {
        let rig = rig(true);
        rig.chain
            .push_stream("/v1/responses", 200, responses_stream(&frames));
        assert_eq!(
            rig.gateway.generate(ctx("plan")).await,
            Err(invalid.clone())
        );
        assert_eq!(rig.requests(), 1);
        assert!(rig.budget.commits.lock().unwrap().is_empty());
    }
}

/// `response.incomplete` with each reason the upstream may give.
fn incomplete_streams() -> Vec<Vec<Result<Vec<u8>, HttpError>>> {
    ["max_output_tokens", "content_filter", "server_limit"]
        .iter()
        .map(|reason| {
            let data = format!(
                r#"{{"type":"response.incomplete","response":{{"incomplete_details":{{"reason":"{reason}"}},"usage":{{"input_tokens":3,"output_tokens":2}}}}}}"#
            );
            responses_stream(&[DELTA_HELLO, ("response.incomplete", data.as_str())])
        })
        .collect()
}

/// The cost of 3 input and 2 output tokens on the sign-in entry.
fn cost_3_2() -> f64 {
    let resolved = crate::provider::make_resolved(&plan_config().llm_providers[0], "gpt-5".into());
    compute_cost(&resolved, 3, 2, CacheUsage::NONE)
}

/// Only a completed response is an answer on a ChatGPT sign-in entry: an incomplete one (a
/// server-side limit, a content filter) fails at both buffered sites — fixed reason, not
/// retried, nothing returned, the usage it reported committed to the run budget — and fails
/// the live stream after its partial text, billed the same. An API-key entry keeps returning
/// a truncated answer with its finish reason.
#[tokio::test]
async fn an_incomplete_response_is_a_failure_on_a_sign_in_entry() {
    let incomplete = plan_err("upstream response incomplete");
    let owed = ("run-1".to_string(), 5, cost_3_2());
    for stream in incomplete_streams() {
        let rig = rig(true);
        rig.chain.push_stream("/v1/responses", 200, stream.clone());
        assert_eq!(
            rig.gateway.generate(ctx("plan")).await,
            Err(incomplete.clone())
        );
        assert_eq!(
            *rig.budget.commits.lock().unwrap(),
            vec![owed.clone()],
            "generate commits the reported usage"
        );
        rig.chain.push_stream("/v1/responses", 200, stream.clone());
        assert_eq!(buffered_stream(&rig, "plan").await, Err(incomplete.clone()));
        assert_eq!(
            *rig.budget.commits.lock().unwrap(),
            vec![owed.clone(), owed.clone()],
            "stream_begin commits the reported usage"
        );
        assert_eq!(rig.requests(), 2, "never retried");
        assert_eq!(rig.event_count(LLM_RESPONSE), 0);
        assert_eq!(
            rig.event_types(),
            vec![LLM_REQUEST, LLM_ERROR, LLM_REQUEST, LLM_ERROR]
        );
        assert!(!crate::retry::classify_retryable(&incomplete));

        rig.chain.push_stream("/v1/responses", 200, stream.clone());
        let handle = rig
            .gateway
            .stream_begin_live(ctx("plan"), &rig.registry)
            .await
            .expect("the head is a 200");
        match terminal(&rig, handle).await {
            PollOutcome::Failed(LlmError::ProviderError(msg)) => {
                assert!(msg.ends_with("upstream response incomplete"), "{msg}")
            }
            _ => panic!("expected a failed stream"),
        }
        assert_eq!(rig.event_count(LLM_RESPONSE), 0);
        let commits = rig.budget.commits.lock().unwrap().clone();
        assert_eq!(commits.len(), 3);
        assert_eq!(commits[2].1, owed.1, "the live path bills the same usage");

        // The API-key entry of the same dialect, live: the truncated answer is done.
        rig.chain.push_stream("/v1/responses", 200, stream);
        let handle = rig
            .gateway
            .stream_begin_live(ctx("keyed"), &rig.registry)
            .await
            .expect("the head is a 200");
        match terminal(&rig, handle).await {
            PollOutcome::Done(done) => assert_ne!(done.response.finish_reason, "stop"),
            _ => panic!("expected a done stream"),
        }
    }
}

/// A live answer far longer than the reservation, never reaching its terminal event.
fn endless_text_stream(deltas: usize) -> Vec<Result<Vec<u8>, HttpError>> {
    let delta = serde_json::json!({
        "type": "response.output_text.delta",
        "delta": "x".repeat(100),
    })
    .to_string();
    (0..deltas)
        .map(|_| Ok(format!("event: response.output_text.delta\ndata: {delta}\n\n").into_bytes()))
        .collect()
}

/// The upstream of a ChatGPT sign-in entry is sent no output ceiling, so the live path holds
/// the answer to the reservation itself: once the decoded output reaches about four bytes per
/// reserved token the answer ends as a capped one (finish reason `length`, billed at the
/// reservation), where the fail-closed byte guard would cut it at sixteen. The API-key entry,
/// whose upstream enforces the ceiling, keeps the fail-closed guard.
#[tokio::test]
async fn a_live_answer_longer_than_the_reservation_ends_capped_on_a_sign_in_entry() {
    // max_tokens 128: the local ceiling is 512 bytes, the fail-closed guard 2048.
    let rig = rig(true);
    rig.chain
        .push_stream("/v1/responses", 200, endless_text_stream(30));
    let handle = rig
        .gateway
        .stream_begin_live(ctx("plan"), &rig.registry)
        .await
        .expect("the head is a 200");
    match terminal(&rig, handle).await {
        PollOutcome::Done(done) => {
            assert_eq!(done.response.finish_reason, "length");
            assert_eq!(
                done.response.output_tokens, 128,
                "billed at the reservation"
            );
        }
        _ => panic!("expected a capped answer"),
    }
    let commits = rig.budget.commits.lock().unwrap().clone();
    assert_eq!(commits.len(), 1);
    assert!(rig.event_count(LLM_RESPONSE) == 1 && rig.event_count(LLM_ERROR) == 0);

    let rig = self::rig(true);
    rig.chain
        .push_stream("/v1/responses", 200, endless_text_stream(30));
    let handle = rig
        .gateway
        .stream_begin_live(ctx("keyed"), &rig.registry)
        .await
        .expect("the head is a 200");
    match terminal(&rig, handle).await {
        PollOutcome::Failed(LlmError::ProviderError(msg)) => {
            assert!(msg.ends_with("stream budget ceiling exceeded"), "{msg}")
        }
        _ => panic!("expected the fail-closed guard"),
    }
}

/// The terminal usage of a sign-in entry's live answer is billed as reported, even above the
/// output reservation the upstream never saw (reasoning tokens, a long answer); the API-key
/// entry stays clamped to its reservation.
#[tokio::test]
async fn a_sign_in_entry_live_answer_is_billed_its_reported_output() {
    let over = (
        "response.completed",
        r#"{"type":"response.completed","response":{"usage":{"input_tokens":3,"output_tokens":900}}}"#,
    );
    let rig = rig(true);
    rig.chain
        .push_stream("/v1/responses", 200, responses_stream(&[DELTA_HELLO, over]));
    let handle = rig
        .gateway
        .stream_begin_live(ctx("plan"), &rig.registry)
        .await
        .expect("the head is a 200");
    match terminal(&rig, handle).await {
        PollOutcome::Done(done) => assert_eq!(done.response.output_tokens, 900),
        _ => panic!("expected a done stream"),
    }
    let response = rig
        .bus
        .snapshot()
        .into_iter()
        .find(|e| e.event_type == LLM_RESPONSE)
        .expect("llm.response");
    assert_eq!(response.payload["output_tokens"], serde_json::json!(900));
    let commits = rig.budget.commits.lock().unwrap().clone();
    assert_eq!(commits.len(), 1);
    assert_eq!(commits[0].1, 3 + 900);

    let rig = self::rig(true);
    rig.chain
        .push_stream("/v1/responses", 200, responses_stream(&[DELTA_HELLO, over]));
    let handle = rig
        .gateway
        .stream_begin_live(ctx("keyed"), &rig.registry)
        .await
        .expect("the head is a 200");
    match terminal(&rig, handle).await {
        PollOutcome::Done(done) => assert_eq!(done.response.output_tokens, 128),
        _ => panic!("expected a done stream"),
    }
}

/// Without a streaming chain and decoded detector the buffered sites fail closed for a
/// ChatGPT sign-in entry with the live path's fixed reason: no unstreamed request is ever
/// sent with the entry's token. An API-key entry on the same gateway is served as before.
#[tokio::test]
async fn gateway_without_a_streaming_transport_fails_closed_for_a_sign_in_entry() {
    let rig = build_rig(true, false, None);
    let not_wired = plan_err("streaming transport not wired");
    // Scripted so that an unstreamed request, if one were sent, would be answered.
    rig.chain
        .push_response("/v1/responses", Ok(buffered_responses_answer("unstreamed")));

    assert_eq!(
        rig.gateway.generate(ctx("plan")).await,
        Err(not_wired.clone())
    );
    assert_eq!(buffered_stream(&rig, "plan").await, Err(not_wired.clone()));
    assert_eq!(
        rig.gateway
            .stream_begin_live(ctx("plan"), &rig.registry)
            .await,
        Err(not_wired)
    );
    assert_eq!(rig.requests(), 0, "nothing may be sent");
    assert_eq!(rig.event_count(LLM_RESPONSE), 0);
    assert!(rig.budget.commits.lock().unwrap().is_empty());

    let response = rig.gateway.generate(ctx("keyed")).await.expect("API key");
    assert_eq!(response.text, "unstreamed");
    assert_eq!(rig.requests(), 1);
}

/// The text of a streamed answer passes the decoded-layer scan before it is returned: a
/// credential assembled across two fragments fails the call closed and is never handed
/// back, while ordinary text of the same shape is returned.
#[tokio::test]
async fn streamed_text_passes_the_decoded_scan() {
    let key = format!("sk-ant-api{}", "A".repeat(95));
    let (head, tail) = key.split_at(40);
    let fragments = |first: &str, second: &str| {
        let delta = |text: &str| {
            serde_json::json!({"type": "response.output_text.delta", "delta": text}).to_string()
        };
        let (first, second) = (delta(first), delta(second));
        responses_stream(&[
            ("response.output_text.delta", first.as_str()),
            ("response.output_text.delta", second.as_str()),
            COMPLETED_3_2,
        ])
    };

    let rig = rig(true);
    rig.chain.push_stream(
        "/v1/responses",
        200,
        fragments(&format!("prose before {head}"), tail),
    );
    match rig.gateway.generate(ctx("plan")).await {
        Err(LlmError::ProviderError(msg)) => {
            assert!(!msg.contains("sk-ant"), "{msg}");
            assert!(!crate::plan_usage::is_plan_usage_error(&msg), "{msg}");
        }
        Err(other) => panic!("expected a provider error, got {other}"),
        Ok(response) => panic!("a credential must never be returned: {}", response.text),
    }
    assert!(rig.budget.commits.lock().unwrap().is_empty());

    rig.chain.push_stream(
        "/v1/responses",
        200,
        fragments("prose before ", "and prose after"),
    );
    let response = rig.gateway.generate(ctx("plan")).await.expect("clean text");
    assert_eq!(response.text, "prose before and prose after");
}

/// The hop budget of `generate` bounds the streamed attempt, and the buffered stream site —
/// which has no deadline for an unstreamed request — bounds it by the buffered executor's
/// default total timeout. A stream that stops making progress ends as `deadline-exceeded`
/// and is not retried.
#[tokio::test(start_paused = true)]
async fn streamed_attempt_honours_the_site_deadline() {
    let deadline = plan_err("deadline-exceeded");

    let rig = build_rig(true, true, Some(Duration::from_secs(2)));
    rig.chain
        .push_stalled_stream("/v1/responses", 200, responses_stream(&[DELTA_HELLO]));
    let started = tokio::time::Instant::now();
    assert_eq!(
        rig.gateway.generate(ctx("plan")).await,
        Err(deadline.clone())
    );
    assert!(started.elapsed() <= Duration::from_secs(2));
    assert_eq!(rig.requests(), 1, "no retry");
    assert_eq!(rig.event_types(), vec![LLM_REQUEST, LLM_ERROR]);

    let rig = self::rig(true);
    rig.chain
        .push_stalled_stream("/v1/responses", 200, responses_stream(&[DELTA_HELLO]));
    let started = tokio::time::Instant::now();
    assert_eq!(buffered_stream(&rig, "plan").await, Err(deadline));
    let waited = started.elapsed();
    assert!(
        waited > Duration::from_secs(25) && waited <= cap_http::DEFAULT_TIMEOUT,
        "{waited:?}"
    );
    assert_eq!(rig.requests(), 1, "no retry");
    assert_eq!(rig.event_types(), vec![LLM_REQUEST, LLM_ERROR]);
}

/// The streamed attempt is bounded like the live path in no-progress frames and like the
/// unstreamed executor in bytes.
#[tokio::test]
async fn no_progress_and_size_bounds_end_a_streamed_attempt() {
    const IGNORABLE: &str =
        "event: response.output_item.added\ndata: {\"type\":\"response.output_item.added\"}\n\n";

    // 1024 consecutive ignorable frames are tolerated ...
    let rig = rig(true);
    let mut script = vec![Ok(IGNORABLE.repeat(1024).into_bytes())];
    script.extend(completed_stream());
    rig.chain.push_stream("/v1/responses", 200, script);
    let response = rig.gateway.generate(ctx("plan")).await.expect("tolerated");
    assert_eq!(response.text, "hello");

    // ... one more is a flood.
    let mut script = vec![Ok(IGNORABLE.repeat(1025).into_bytes())];
    script.extend(completed_stream());
    rig.chain.push_stream("/v1/responses", 200, script);
    assert_eq!(
        rig.gateway.generate(ctx("plan")).await,
        Err(plan_err("stream ignore flood"))
    );

    // More wire bytes than the unstreamed executor would accept for one response.
    let comment_block = format!(":{}\n\n", "x".repeat(400_000)).into_bytes();
    let blocks = cap_http::DEFAULT_MAX_RESPONSE_BYTES / comment_block.len() + 1;
    let mut script: Vec<Result<Vec<u8>, HttpError>> =
        (0..blocks).map(|_| Ok(comment_block.clone())).collect();
    script.extend(completed_stream());
    rig.chain.push_stream("/v1/responses", 200, script);
    assert_eq!(
        rig.gateway.generate(ctx("plan")).await,
        Err(plan_err("stream response exceeds size limit"))
    );
    assert_eq!(rig.budget.commits.lock().unwrap().len(), 1);
}

// ── typed refusals ───────────────────────────────────────────────────────────────────────────

/// A 429 that names the usage-limit code is the fixed plan-usage reason, not a rate limit:
/// it is not retried at either buffered site, and in `generate` it moves on to the next
/// candidate. The same status without the code stays an ordinary rate limit and IS retried.
#[tokio::test(start_paused = true)]
async fn usage_limit_429_is_typed_not_retried_and_fails_over() {
    // Not retried: one request, no `llm.retry`, the fixed reason.
    let rig = rig(true);
    rig.chain
        .push_stream("/v1/responses", 429, coded_body(USAGE_LIMIT_CODE));
    let err = rig.gateway.generate(ctx("plan")).await.unwrap_err();
    assert_eq!(err, plan_err(USAGE_LIMIT_REACHED));
    assert_static(&err);
    assert_eq!(rig.requests(), 1);
    assert_eq!(rig.event_types(), vec![LLM_REQUEST, LLM_ERROR]);

    rig.chain
        .push_stream("/v1/responses", 429, coded_body(USAGE_LIMIT_CODE));
    let err = buffered_stream(&rig, "plan").await.unwrap_err();
    assert_eq!(err, plan_err(USAGE_LIMIT_REACHED));
    assert_eq!(rig.requests(), 2);
    assert_eq!(rig.event_count(LLM_RETRY), 0);
    assert!(rig.source.rejected_calls().is_empty(), "not a rejection");

    // A failover trigger: the next candidate for the alias answers.
    let rig = self::rig(true);
    rig.chain
        .push_stream("/v1/responses", 429, coded_body(USAGE_LIMIT_CODE));
    rig.chain.push_response(
        "/v1/chat/completions",
        Ok(chat_completions_answer("from the fallback")),
    );
    let response = rig.gateway.generate(ctx("shared")).await.expect("failover");
    assert_eq!(response.text, "from the fallback");
    {
        let log = rig.chain.call_log.lock().unwrap();
        assert_eq!(log.len(), 2, "one refused request, one fallback request");
        assert_eq!(log[0].url, RESPONSES_URL);
        assert_eq!(
            log[1].url,
            "https://fallback.example.com/v1/chat/completions"
        );
    }
    assert_eq!(rig.streamed_urls(), vec![RESPONSES_URL.to_string()]);
    assert_eq!(
        rig.event_types(),
        vec![LLM_REQUEST, LLM_ERROR, LLM_REQUEST, LLM_RESPONSE]
    );
    let events = rig.bus.snapshot();
    assert_eq!(events[3].payload["provider"], serde_json::json!("fallback"));

    // Control: without the code a 429 is a rate limit, retried on the same entry.
    let rig = self::rig(true);
    rig.chain
        .push_stream("/v1/responses", 429, coded_body("rate_limit_exceeded"));
    rig.chain
        .push_stream("/v1/responses", 200, completed_stream());
    let response = rig.gateway.generate(ctx("plan")).await.expect("retried");
    assert_eq!(response.text, "hello");
    assert_eq!(rig.requests(), 2);
    assert_eq!(rig.event_count(LLM_RETRY), 1);
    assert_eq!(
        rig.source.fresh_calls().len(),
        1,
        "one freshness check per dispatch, not per attempt"
    );
}

/// A bare 401 on a buffered call of a ChatGPT sign-in entry is a rejected sign-in: fixed
/// reason, exactly one report to the credential source per rejected request, no retry. A
/// bare 403 and a code that selects another reason are typed and not reported; an API-key
/// entry keeps its reason and reports nothing.
#[tokio::test]
async fn bare_401_is_a_rejected_sign_in_reported_exactly_once() {
    let plan_report = (PLAN_ID.to_string(), PLAN_SECRET.to_string());

    let rig = rig(true);
    rig.chain.push_stream("/v1/responses", 401, uncoded_body());
    let err = rig.gateway.generate(ctx("plan")).await.unwrap_err();
    assert_eq!(err, plan_err(SIGN_IN_REJECTED));
    assert_static(&err);
    assert_eq!(rig.source.rejected_calls(), vec![plan_report.clone()]);
    assert_eq!(rig.requests(), 1, "no in-request retry");
    assert_eq!(rig.event_types(), vec![LLM_REQUEST, LLM_ERROR]);

    rig.chain.push_stream("/v1/responses", 401, uncoded_body());
    let err = buffered_stream(&rig, "plan").await.unwrap_err();
    assert_eq!(err, plan_err(SIGN_IN_REJECTED));
    assert_eq!(
        rig.source.rejected_calls(),
        vec![plan_report.clone(), plan_report.clone()]
    );
    assert_eq!(rig.requests(), 2);

    // The code for an invalid user is the same outcome, reported the same way.
    rig.chain
        .push_stream("/v1/responses", 403, coded_body(INVALID_USER_CODE));
    let err = rig.gateway.generate(ctx("plan")).await.unwrap_err();
    assert_eq!(err, plan_err(SIGN_IN_REJECTED));
    assert_eq!(rig.source.rejected_calls().len(), 3);

    // Typed, but not a rejected sign-in: nothing is reported.
    for (status, body, reason) in [
        (403, uncoded_body(), "chatgpt-plan: request not permitted"),
        (
            401,
            coded_body("chatpass_v2_scope_not_authorized"),
            "chatgpt-plan: plan usage not authorized",
        ),
        (
            403,
            coded_body("subscription_sharing_user_not_eligible"),
            "chatgpt-plan: account not eligible",
        ),
    ] {
        rig.chain.push_stream("/v1/responses", status, body.clone());
        let err = rig.gateway.generate(ctx("plan")).await.unwrap_err();
        assert_eq!(err, plan_err(reason));
        assert_static(&err);
        rig.chain.push_stream("/v1/responses", status, body);
        assert_eq!(
            buffered_stream(&rig, "plan").await.unwrap_err(),
            plan_err(reason)
        );
    }
    assert_eq!(rig.source.rejected_calls().len(), 3);
    assert_eq!(rig.requests(), 9, "one request per call");
    assert_eq!(rig.event_count(LLM_RETRY), 0);

    // The API-key entry: unstreamed, the ordinary reason, no report.
    rig.chain.push_response(
        "/v1/responses",
        Ok(HttpResponse {
            status: 401,
            headers: vec![],
            body: br#"{"detail":"LEAK"}"#.to_vec(),
        }),
    );
    let err = rig.gateway.generate(ctx("keyed")).await.unwrap_err();
    assert_eq!(err, plan_err("auth failed"));
    assert_eq!(rig.source.rejected_calls().len(), 3);
    assert_eq!(rig.streamed_urls().len(), 9);
}

/// Typed errors inside the stream of a buffered call: a failed-response or error event
/// naming a plan-usage code is that fixed reason; a rejected sign-in among them is reported
/// once; an event without a code keeps its static reason.
#[tokio::test]
async fn in_band_errors_of_a_buffered_call_are_typed() {
    let rig = rig(true);
    let failed = |code: &str| {
        format!(
            r#"{{"type":"response.failed","response":{{"error":{{"code":"{code}","message":"LEAK"}}}}}}"#
        )
    };

    let data = failed(USAGE_LIMIT_CODE);
    rig.chain.push_stream(
        "/v1/responses",
        200,
        responses_stream(&[DELTA_HELLO, ("response.failed", data.as_str())]),
    );
    let err = rig.gateway.generate(ctx("plan")).await.unwrap_err();
    assert_eq!(err, plan_err(USAGE_LIMIT_REACHED));
    assert_static(&err);
    assert!(rig.source.rejected_calls().is_empty());

    rig.chain.push_stream(
        "/v1/responses",
        200,
        responses_stream(&[(
            "error",
            r#"{"type":"error","code":"subscription_sharing_invalid_user","message":"LEAK"}"#,
        )]),
    );
    let err = buffered_stream(&rig, "plan").await.unwrap_err();
    assert_eq!(err, plan_err(SIGN_IN_REJECTED));
    assert_eq!(
        rig.source.rejected_calls(),
        vec![(PLAN_ID.to_string(), PLAN_SECRET.to_string())]
    );

    let data = failed("server_error");
    rig.chain.push_stream(
        "/v1/responses",
        200,
        responses_stream(&[("response.failed", data.as_str())]),
    );
    let err = rig.gateway.generate(ctx("plan")).await.unwrap_err();
    assert_eq!(err, plan_err("upstream response failed"));
    assert_static(&err);

    assert_eq!(rig.source.rejected_calls().len(), 1);
    assert_eq!(rig.requests(), 3, "no retry");
    assert!(rig.budget.commits.lock().unwrap().is_empty());
}

/// A refused live head on a ChatGPT sign-in entry is typed by status — 401 is a rejected
/// sign-in, reported to the source exactly once; 403 is a refused request, not reported.
/// The same statuses on an API-key entry keep their reason and report nothing.
#[tokio::test]
async fn refused_live_head_is_typed_and_a_rejected_sign_in_is_reported_once() {
    let rig = rig(true);
    for status in [401, 403] {
        rig.chain.push_response(
            "/v1/responses",
            Ok(HttpResponse {
                status,
                headers: vec![],
                body: br#"{"detail":"LEAK"}"#.to_vec(),
            }),
        );
    }
    let err = rig
        .gateway
        .stream_begin_live(ctx("plan"), &rig.registry)
        .await
        .expect_err("401");
    assert_eq!(err, plan_err(SIGN_IN_REJECTED));
    assert_eq!(
        rig.source.rejected_calls(),
        vec![(PLAN_ID.to_string(), PLAN_SECRET.to_string())]
    );
    // Reported once the refused head was settled (it bills nothing) and its `llm.error` emitted.
    assert_eq!(
        rig.source.rejected_after(),
        vec![(vec![LLM_REQUEST.to_string(), LLM_ERROR.to_string()], 0)]
    );

    let err = rig
        .gateway
        .stream_begin_live(ctx("plan"), &rig.registry)
        .await
        .expect_err("403");
    assert_eq!(err, plan_err("chatgpt-plan: request not permitted"));

    let err = rig
        .gateway
        .stream_begin_live(ctx("keyed"), &rig.registry)
        .await
        .expect_err("403 on the API-key entry");
    assert_eq!(err, plan_err("stream auth rejected"));

    assert_eq!(rig.source.rejected_calls().len(), 1, "exactly one report");
    assert_eq!(rig.source.fresh_calls().len(), 2);
    // No in-request retry: one upstream request per call.
    assert_eq!(rig.requests(), 3);
    assert_eq!(rig.event_count(LLM_REQUEST), 3);
}

/// The body of a refused live head is read on a ChatGPT sign-in entry, so its error code
/// selects the fixed reason: a usage limit is no longer a rate limit. An API-key entry
/// answered with the very same body is classified by status alone.
#[tokio::test]
async fn refused_live_head_error_code_selects_the_plan_usage_reason() {
    let rig = rig(true);
    let live = |alias: &'static str| {
        let (gateway, registry) = (Arc::clone(&rig.gateway), Arc::clone(&rig.registry));
        async move {
            gateway
                .stream_begin_live(ctx(alias), &registry)
                .await
                .expect_err("a refused head")
        }
    };

    for (status, code, reason) in [
        (429, USAGE_LIMIT_CODE, USAGE_LIMIT_REACHED),
        (
            403,
            "subscription_sharing_user_not_eligible",
            "chatgpt-plan: account not eligible",
        ),
        (
            400,
            "subscription_sharing_unsupported_capability",
            "chatgpt-plan: unsupported capability",
        ),
        (
            403,
            "chatpass_v2_invalid_authorization_context",
            "chatgpt-plan: plan usage not authorized",
        ),
    ] {
        rig.chain
            .push_stream("/v1/responses", status, coded_body(code));
        let err = live("plan").await;
        assert_eq!(err, plan_err(reason), "{status} {code}");
        assert_static(&err);
    }
    assert!(rig.source.rejected_calls().is_empty());

    // The code for an invalid user is a rejected sign-in whatever the status: reported once.
    rig.chain
        .push_stream("/v1/responses", 403, coded_body(INVALID_USER_CODE));
    assert_eq!(live("plan").await, plan_err(SIGN_IN_REJECTED));
    assert_eq!(
        rig.source.rejected_calls(),
        vec![(PLAN_ID.to_string(), PLAN_SECRET.to_string())]
    );

    // An unknown code selects nothing: the status decides, as before.
    rig.chain
        .push_stream("/v1/responses", 429, coded_body("rate_limit_exceeded"));
    assert_eq!(
        live("plan").await,
        LlmError::RateLimited("stream rate limited".into())
    );

    // The API-key entry never has its refused body read.
    rig.chain
        .push_stream("/v1/responses", 429, coded_body(USAGE_LIMIT_CODE));
    assert_eq!(
        live("keyed").await,
        LlmError::RateLimited("stream rate limited".into())
    );

    assert_eq!(rig.requests(), 7, "one request per call, never a retry");
    assert_eq!(rig.event_count(LLM_REQUEST), 7);
    assert_eq!(rig.event_count(LLM_ERROR), 7);
    assert!(rig.budget.commits.lock().unwrap().iter().all(|c| c.1 == 0));
}

/// The read of a refused body is bounded in time and in size: a body that never arrives
/// costs the short bound and then the status decides, and a code beyond the first 64 KiB
/// is not looked for. A code within the bound is found across chunk boundaries.
#[tokio::test(start_paused = true)]
async fn refused_body_read_is_bounded_in_time_and_size() {
    let rate_limited = LlmError::RateLimited("stream rate limited".into());
    let padded = |pad: usize| -> Vec<Result<Vec<u8>, HttpError>> {
        vec![
            Ok(format!(r#"{{"pad":"{}","#, "x".repeat(pad)).into_bytes()),
            Ok(format!(r#""error":{{"code":"{USAGE_LIMIT_CODE}"}}}}"#).into_bytes()),
        ]
    };

    let rig = rig(true);
    rig.chain
        .push_stalled_stream("/v1/responses", 429, Vec::new());
    let started = tokio::time::Instant::now();
    let err = rig
        .gateway
        .stream_begin_live(ctx("plan"), &rig.registry)
        .await
        .expect_err("a refused head");
    assert_eq!(err, rate_limited);
    let waited = started.elapsed();
    assert!(
        waited >= Duration::from_secs(5) && waited < Duration::from_secs(6),
        "{waited:?}"
    );

    rig.chain.push_stream("/v1/responses", 429, padded(1024));
    let err = rig
        .gateway
        .stream_begin_live(ctx("plan"), &rig.registry)
        .await
        .expect_err("a refused head");
    assert_eq!(err, plan_err(USAGE_LIMIT_REACHED));

    rig.chain
        .push_stream("/v1/responses", 429, padded(70 * 1024));
    let err = rig
        .gateway
        .stream_begin_live(ctx("plan"), &rig.registry)
        .await
        .expect_err("a refused head");
    assert_eq!(err, rate_limited);

    // The buffered sites read the refused body under the same bounds.
    rig.chain
        .push_stalled_stream("/v1/responses", 403, Vec::new());
    let started = tokio::time::Instant::now();
    let err = rig.gateway.generate(ctx("plan")).await.unwrap_err();
    assert_eq!(err, plan_err("chatgpt-plan: request not permitted"));
    let waited = started.elapsed();
    assert!(
        waited >= Duration::from_secs(5) && waited < Duration::from_secs(6),
        "{waited:?}"
    );
    rig.chain
        .push_stream("/v1/responses", 403, padded(70 * 1024));
    let err = rig.gateway.generate(ctx("plan")).await.unwrap_err();
    assert_eq!(err, plan_err("chatgpt-plan: request not permitted"));
}

/// A rejected sign-in that arrives in-band (a failed-response event after a 200 head) is
/// reported once after the stream settled; a usage limit is typed but not reported.
#[tokio::test]
async fn in_band_rejected_sign_in_is_reported_once_after_settlement() {
    let rig = rig(true);
    rig.chain.set_stream_results(
        "/v1/responses",
        responses_stream(&[(
            "response.failed",
            r#"{"type":"response.failed","response":{"error":{"code":"subscription_sharing_invalid_user","message":"LEAK"}}}"#,
        )]),
    );
    let handle = rig
        .gateway
        .stream_begin_live(ctx("plan"), &rig.registry)
        .await
        .expect("the head is a 200");
    match terminal(&rig, handle).await {
        PollOutcome::Failed(err) => assert_eq!(err, plan_err(SIGN_IN_REJECTED)),
        _ => panic!("expected a failed stream"),
    }
    assert_eq!(
        rig.source.rejected_calls(),
        vec![(PLAN_ID.to_string(), PLAN_SECRET.to_string())]
    );
    // When the report was made the stream was already settled: its budget commit made and its
    // terminal `llm.error` emitted.
    assert_eq!(
        rig.source.rejected_after(),
        vec![(vec![LLM_REQUEST.to_string(), LLM_ERROR.to_string()], 1)]
    );

    rig.chain.set_stream_results(
        "/v1/responses",
        responses_stream(&[(
            "response.failed",
            r#"{"type":"response.failed","response":{"error":{"code":"subscription_sharing_usage_limit_exceeded","message":"LEAK"}}}"#,
        )]),
    );
    let handle = rig
        .gateway
        .stream_begin_live(ctx("plan"), &rig.registry)
        .await
        .expect("the head is a 200");
    match terminal(&rig, handle).await {
        PollOutcome::Failed(err) => assert_eq!(err, plan_err(USAGE_LIMIT_REACHED)),
        _ => panic!("expected a failed stream"),
    }
    assert_eq!(rig.source.rejected_calls().len(), 1);
}

/// The status rewrite applies only to a ChatGPT sign-in entry, only to 401 / 403, and never
/// replaces a reason an error code already selected.
#[test]
fn refused_status_rewrite_is_scoped_to_sign_in_entries() {
    let auth_failed = || plan_err("auth failed");
    assert_eq!(
        plan_usage_status_error(true, 401, auth_failed()),
        plan_err(SIGN_IN_REJECTED)
    );
    assert_eq!(
        plan_usage_status_error(true, 403, auth_failed()),
        plan_err("chatgpt-plan: request not permitted")
    );
    let eligible = plan_err("chatgpt-plan: account not eligible");
    assert_eq!(
        plan_usage_status_error(true, 403, eligible.clone()),
        eligible
    );
    let limited = LlmError::RateLimited("rate limited".into());
    assert_eq!(plan_usage_status_error(true, 429, limited.clone()), limited);
    let upstream = plan_err("upstream 503");
    assert_eq!(
        plan_usage_status_error(true, 503, upstream.clone()),
        upstream
    );
    for status in [401, 403] {
        assert_eq!(
            plan_usage_status_error(false, status, auth_failed()),
            auth_failed()
        );
    }
}

// ── routes the sign-in token never reaches ───────────────────────────────────────────────────

/// A ChatGPT sign-in entry is never an embedding provider: both selection filters skip it,
/// so its token is never sent to `/v1/embeddings` and the source is not consulted.
#[tokio::test]
async fn sign_in_entry_is_never_selected_for_embeddings() {
    let cfg = plan_config();
    let plan = cfg.llm_providers[0].clone();
    let key = cfg.llm_providers[1].clone();
    assert!(!is_embedding_capable(&plan));
    assert!(is_embedding_capable(&key));
    assert_eq!(
        select_embedding_provider(&cfg.llm_providers).unwrap().id,
        "openai-key"
    );
    assert_eq!(
        select_embedding_provider(std::slice::from_ref(&plan)).unwrap_err(),
        LlmError::ModelNotAvailable("no embedding-capable provider configured".into())
    );

    // Every entry configured: the embed request goes to the API-key entry.
    let rig = rig(true);
    rig.chain.push_response(
        "/v1/embeddings",
        Ok(HttpResponse {
            status: 200,
            headers: vec![],
            body: br#"{"data":[{"embedding":[0.5,0.25]}]}"#.to_vec(),
        }),
    );
    assert_eq!(rig.gateway.embed("text").await.unwrap(), vec![0.5, 0.25]);
    {
        let log = rig.chain.call_log.lock().unwrap();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].url, "https://api.openai.com/v1/embeddings");
        assert!(log[0]
            .headers
            .iter()
            .any(|(n, v)| n == "Authorization" && v == "Bearer {openai-api-key}"));
    }
    assert!(rig.source.fresh_calls().is_empty());

    // Only the sign-in entry configured: nothing is sent at all.
    let only_plan = self::rig(true);
    let mut cfg = plan_config();
    cfg.llm_providers.truncate(1);
    let gateway = LlmGateway::new(
        Arc::new(MockRuntimeConfigProvider::new(cfg)),
        Arc::clone(&only_plan.chain) as Arc<dyn HttpSecurityChain>,
        Arc::clone(&only_plan.budget) as Arc<dyn RunBudget>,
        Arc::clone(&only_plan.bus) as Arc<dyn EventBusEmit>,
        crate::test_support::no_op_repetition_guard() as Arc<dyn RepetitionGuardCheck>,
        "test-agent".into(),
    )
    .with_credential_source(Arc::clone(&only_plan.source) as Arc<dyn ProviderCredentialSource>);
    assert_eq!(
        gateway.embed("text").await.unwrap_err(),
        LlmError::ModelNotAvailable("no embedding-capable provider configured".into())
    );
    assert_nothing_dispatched(&only_plan);
    assert!(only_plan.source.fresh_calls().is_empty());
}

/// A ChatGPT sign-in entry is never used for image extraction: listed first, it is skipped
/// in favour of the next image-capable entry; alone, the extraction is refused before any
/// request is built. Its token never reaches `/v1/chat/completions`.
#[tokio::test]
async fn sign_in_entry_is_never_used_for_image_extraction() {
    let image = || FileContent::Image {
        bytes: vec![0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a],
        mime: "image/png".into(),
    };
    let extractor = |cfg: advance_runtime::config::RuntimeConfig| {
        let chain = Arc::new(MockHttpSecurityChain::default());
        chain.push_response(
            "/v1/chat/completions",
            Ok(chat_completions_answer("described")),
        );
        let vlm = LlmGatewayVlm::new(
            Arc::new(MockRuntimeConfigProvider::new(cfg)),
            Arc::clone(&chain) as Arc<dyn HttpSecurityChain>,
            Arc::new(MockEventBusEmit::default()),
            "test-agent".into(),
        );
        (vlm, chain)
    };

    let (vlm, chain) = extractor(plan_config());
    assert_eq!(
        vlm.extract_description(&image()).await.expect("next entry"),
        "described"
    );
    {
        let log = chain.call_log.lock().unwrap();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].url, "https://api.openai.com/v1/chat/completions");
        assert!(log[0]
            .headers
            .iter()
            .any(|(n, v)| n == "Authorization" && v == "Bearer {openai-api-key}"));
        assert!(!log[0].headers.iter().any(|(_, v)| v.contains(PLAN_SECRET)));
    }

    let mut cfg = plan_config();
    cfg.llm_providers.truncate(1);
    let (vlm, chain) = extractor(cfg);
    assert_eq!(
        vlm.extract_description(&image()).await.unwrap_err(),
        plan_err("unsupported capability: image")
    );
    assert!(chain.call_log.lock().unwrap().is_empty());
}

// ── API-key entries ──────────────────────────────────────────────────────────────────────────

/// An API-key `openai-responses` entry is unchanged at both buffered sites: one UNSTREAMED
/// request with the same bytes and headers as before, the caller's `temperature` and
/// `max_tokens` included, parsed by the unstreamed parser; the credential source is never
/// consulted.
#[tokio::test]
async fn api_key_responses_entry_is_byte_for_byte_unchanged() {
    let rig = rig(true);
    for _ in 0..2 {
        rig.chain
            .push_response("/v1/responses", Ok(buffered_responses_answer("unstreamed")));
    }
    let generated = rig.gateway.generate(ctx("keyed")).await.expect("generate");
    let streamed = buffered_stream(&rig, "keyed").await.expect("stream_begin");
    for response in [&generated, &streamed] {
        assert_eq!(response.text, "unstreamed");
        assert_eq!(response.model, "gpt-5");
        assert_eq!((response.input_tokens, response.output_tokens), (3, 2));
    }

    assert!(rig.streamed_urls().is_empty(), "nothing may be streamed");
    let log = rig.chain.call_log.lock().unwrap();
    assert_eq!(log.len(), 2, "one request per call");
    for request in log.iter() {
        assert_eq!(request.url, RESPONSES_URL);
        assert_eq!(String::from_utf8_lossy(&request.body), KEYED_BUFFERED_BODY);
        assert_eq!(
            request.headers,
            vec![
                (
                    "Authorization".to_string(),
                    "Bearer {openai-api-key}".to_string()
                ),
                ("Content-Type".to_string(), "application/json".to_string()),
            ]
        );
    }
    assert!(rig.source.fresh_calls().is_empty());
    assert!(rig.source.rejected_calls().is_empty());
    assert_eq!(
        rig.event_types(),
        vec![LLM_REQUEST, LLM_RESPONSE, LLM_REQUEST, LLM_RESPONSE]
    );
}

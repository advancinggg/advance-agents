//! Gateway-level witnesses for OpenAI-compatible reasoning models: answers that carry only
//! reasoning output, an entry's own `generate-timeout-secs`, and its `reasoning-effort`.
//!
//! Every test drives the REAL `LlmGateway` request paths (`generate`, `stream_begin`,
//! `stream_begin_live`, `embed`), the first-open `chat_preflight` or the real image / PDF
//! extractor over a scripted `MockHttpSecurityChain` (a recording inference port for a local
//! entry), and asserts on what left the gateway — the request bytes and the HTTP layer's
//! request timeout in scope — and on the typed outcome. Paused tokio time stands in for a slow
//! upstream: the mock chain and the port sleep on the tokio clock, and every hop bound of the
//! gateway is a tokio timer.

#![cfg(test)]

use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use advance_runtime::config::RuntimeConfig;
use advance_shared_types::inference::{
    InferenceBackendError, InferenceBackendPort, InferenceBackendRegistry, InferenceChatRequest,
    InferenceChatResponse, InferenceEmbedRequest, InferenceEmbedResponse, InferenceStream,
    InferenceStreamHead,
};
use advance_shared_types::security_validator::{
    HttpError, HttpResponse, HttpSecurityChain, HttpStreamingChain,
};
use async_trait::async_trait;
use serde_json::{json, Value};

use crate::credential::{CredentialFailure, ProviderCredentialSource};
use crate::gateway::{
    ChatMessage, ChatParams, ChatResponse, ChatRole, LlmGateway, LlmGatewayInternal,
    LlmRequestContext,
};
use crate::stream::{PollOutcome, StreamRegistry};
use crate::test_support::{
    fixture_runtime_config, no_op_repetition_guard, MockEventBusEmit, MockHttpSecurityChain,
    MockRunBudget, MockRuntimeConfigProvider,
};
use crate::vlm::{FileContent, LlmGatewayVlm, VlmExtractor};
use crate::{chat_preflight, DiscardEventBus, LlmError, StaticConfig};

// ── fixtures ─────────────────────────────────────────────────────────────────────────────────

const CHAT_PATH: &str = "/v1/chat/completions";
const RESPONSES_PATH: &str = "/v1/responses";
const EMBEDDINGS_PATH: &str = "/v1/embeddings";

/// Longer than the default budget of a hop, shorter than the entry budget the tests set.
const SLOW: Duration = Duration::from_secs(45);
const ENTRY_SECS: u64 = 120;

/// More frames without text than the gateway's 1024-frame no-progress bound.
const LONG_REASONING: usize = 1_100;

/// What the gateway sends for [`ctx`] to an entry without `reasoning-effort` (as before the key
/// existed), unstreamed and streamed.
const CHAT_BODY: &str = r#"{"max_tokens":128,"messages":[{"content":"hi","role":"user"}],"model":"reasoner-large","temperature":0.5}"#;
const STREAM_BODY: &str = r#"{"max_tokens":128,"messages":[{"content":"hi","role":"user"}],"model":"reasoner-large","stream":true,"stream_options":{"include_usage":true},"temperature":0.5}"#;
/// The first-open preflight request of the same entry.
const PREFLIGHT_BODY: &str =
    r#"{"max_tokens":16,"messages":[{"content":"ping","role":"user"}],"model":"reasoner-large"}"#;

/// A cloud-http chat-completions entry `reasoner` (alias `think`); `extra` holds more keys of the
/// entry, each line indented by two spaces.
fn reasoner(extra: &str) -> String {
    format!(
        "- id: reasoner\n  endpoint: https://api.example.test\n  api-key-secret: reasoner-api-key\n{extra}  model-aliases:\n    think: reasoner-large\n  cost-per-mtoken-in: 1.0\n  cost-per-mtoken-out: 2.0\n"
    )
}

/// The same entry on the Responses dialect.
fn responses_reasoner(extra: &str) -> String {
    reasoner(&format!("  backend: openai-responses\n{extra}"))
}

/// A local entry `local-reasoner` (alias `llama`) served by an inference port.
fn local_reasoner(extra: &str) -> String {
    format!(
        "- id: local-reasoner\n  backend-class: local\n  api-key-secret: local-key\n{extra}  model-aliases:\n    llama: llama\n  cost-per-mtoken-in: 0.0\n  cost-per-mtoken-out: 0.0\n"
    )
}

fn entry_timeout() -> String {
    format!("  generate-timeout-secs: {ENTRY_SECS}\n")
}

/// The chat-completions URLs of the two entries of [`two_entries`].
const FIRST_URL: &str = "https://first.example.test/v1/chat/completions";
const SECOND_URL: &str = "https://second.example.test/v1/chat/completions";

/// Two cloud-http chat-completions entries that both serve alias `think`, walked in this order:
/// `first` (host `first.example.test`, more keys in `first_extra`) then `second` (host
/// `second.example.test`, `second_extra`); each extra line is indented by two spaces.
fn two_entries(first_extra: &str, second_extra: &str) -> String {
    let entry = |id: &str, extra: &str| {
        format!(
            "- id: {id}\n  endpoint: https://{id}.example.test\n  api-key-secret: {id}-api-key\n{extra}  model-aliases:\n    think: reasoner-large\n  cost-per-mtoken-in: 1.0\n  cost-per-mtoken-out: 2.0\n"
        )
    };
    format!(
        "{}{}",
        entry("first", first_extra),
        entry("second", second_extra)
    )
}

/// One retry, without a noticeable backoff.
const RETRY_ONCE: &str =
    "  retry-default:\n    max-retries: 1\n    base-delay-ms: 1\n    max-delay-ms: 1\n";

/// A cloud-http entry `signed-in` (alias `signed`) whose credential comes from a ChatGPT sign-in
/// (`auth-source: chatgpt-oauth`): every request of it is a streamed Responses exchange.
fn signed_in(extra: &str) -> String {
    format!(
        "- id: signed-in\n  endpoint: https://api.openai.com\n  api-key-secret: signed-in-token\n  auth-source: chatgpt-oauth\n{extra}  model-aliases:\n    signed: gpt-5\n  cost-per-mtoken-in: 1.25\n  cost-per-mtoken-out: 10.0\n"
    )
}

/// A credential source that always holds a fresh credential.
struct FreshCredential;

#[async_trait]
impl ProviderCredentialSource for FreshCredential {
    async fn ensure_fresh(
        &self,
        _provider_id: &str,
        _secret_name: &str,
    ) -> Result<(), CredentialFailure> {
        Ok(())
    }
}

/// A completed streamed Responses answer `text`, 3 input and 2 output tokens.
fn responses_stream_answer(text: &str) -> Vec<Result<Vec<u8>, HttpError>> {
    [
        (
            "response.output_text.delta",
            json!({"type": "response.output_text.delta", "delta": text}).to_string(),
        ),
        (
            "response.completed",
            json!({"type": "response.completed", "response": {"usage": {"input_tokens": 3, "output_tokens": 2}}})
                .to_string(),
        ),
    ]
    .iter()
    .map(|(event, data)| Ok(format!("event: {event}\ndata: {data}\n\n").into_bytes()))
    .collect()
}

/// The image / PDF extractor over `entries`, sending through `rig`'s chain.
fn extractor(rig: &Rig, entries: &str) -> LlmGatewayVlm {
    LlmGatewayVlm::new(
        Arc::new(MockRuntimeConfigProvider::new(config(entries))),
        Arc::clone(&rig.chain) as Arc<dyn HttpSecurityChain>,
        Arc::new(MockEventBusEmit::default()),
        "test-agent".into(),
    )
}

fn image() -> FileContent {
    FileContent::Image {
        bytes: vec![0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a],
        mime: "image/png".into(),
    }
}

fn config(entries: &str) -> RuntimeConfig {
    let mut cfg = fixture_runtime_config();
    cfg.llm_providers = serde_yml::from_str(entries).expect("provider entries must parse");
    cfg
}

struct Rig {
    gateway: Arc<LlmGateway>,
    chain: Arc<MockHttpSecurityChain>,
    registry: Arc<StreamRegistry>,
}

impl Rig {
    fn bodies(&self) -> Vec<String> {
        self.chain
            .call_log
            .lock()
            .unwrap()
            .iter()
            .map(|req| String::from_utf8(req.body.clone()).unwrap())
            .collect()
    }

    fn request_timeouts(&self) -> Vec<Option<Duration>> {
        self.chain.request_timeouts.lock().unwrap().clone()
    }

    fn slow_upstream(&self) {
        *self.chain.execute_delay.lock().unwrap() = Some(SLOW);
    }
}

fn rig(entries: &str) -> Rig {
    rig_with_ports(entries, InferenceBackendRegistry::new())
}

fn rig_with_ports(entries: &str, ports: InferenceBackendRegistry) -> Rig {
    build_rig(entries, ports, false)
}

/// A rig over one entry that signs in ([`signed_in`]), with a credential source that always
/// answers fresh.
fn signed_in_rig(extra: &str) -> Rig {
    build_rig(&signed_in(extra), InferenceBackendRegistry::new(), true)
}

fn build_rig(entries: &str, ports: InferenceBackendRegistry, credential_source: bool) -> Rig {
    let chain = Arc::new(MockHttpSecurityChain::default());
    let mut gateway = LlmGateway::new(
        Arc::new(MockRuntimeConfigProvider::new(config(entries))),
        Arc::clone(&chain) as Arc<dyn HttpSecurityChain>,
        Arc::new(MockRunBudget::default()),
        Arc::new(MockEventBusEmit::default()),
        no_op_repetition_guard(),
        "test-agent".into(),
    )
    .with_inference_backends(ports)
    .with_live_streaming(
        Arc::clone(&chain) as Arc<dyn HttpStreamingChain>,
        Arc::new(cap_http::DefaultLeakDetector::default()),
    );
    if credential_source {
        gateway = gateway
            .with_credential_source(Arc::new(FreshCredential) as Arc<dyn ProviderCredentialSource>);
    }
    Rig {
        gateway: Arc::new(gateway),
        chain,
        registry: Arc::new(StreamRegistry::new()),
    }
}

fn ctx(alias: &str) -> LlmRequestContext {
    LlmRequestContext {
        agent_id: "test-agent".into(),
        run_id: Some("run-1".into()),
        messages: vec![ChatMessage {
            role: ChatRole::User,
            content: "hi".into(),
            tool_call_id: None,
            tool_calls: Vec::new(),
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

fn http(body: Value) -> HttpResponse {
    HttpResponse {
        status: 200,
        headers: vec![],
        body: serde_json::to_vec(&body).unwrap(),
    }
}

/// The unstreamed answer of a reasoning model that spent its whole output budget reasoning:
/// `content` null, the reasoning under `field`, cut at the length limit.
fn reasoning_only_answer(field: &str) -> HttpResponse {
    let mut message = json!({"role": "assistant", "content": null});
    message[field] = json!("The user says ping, so I should answer");
    http(json!({
        "choices": [{"index": 0, "message": message, "finish_reason": "length"}],
        "usage": {"prompt_tokens": 9, "completion_tokens": 16, "total_tokens": 25},
        "model": "reasoner-large",
    }))
}

fn text_answer(text: &str) -> HttpResponse {
    http(json!({
        "choices": [{"message": {"content": text}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 3, "completion_tokens": 2},
        "model": "reasoner-large",
    }))
}

fn responses_text_answer(text: &str) -> HttpResponse {
    http(json!({
        "status": "completed",
        "model": "reasoner-large",
        "output": [{"type": "message", "content": [{"type": "output_text", "text": text}]}],
        "usage": {"input_tokens": 3, "output_tokens": 2},
    }))
}

fn sse(data: &str) -> Result<Vec<u8>, HttpError> {
    Ok(format!("data: {data}\n\n").into_bytes())
}

fn reasoning_frame(field: &str, text: &str) -> Result<Vec<u8>, HttpError> {
    sse(&json!({"choices": [{"index": 0, "delta": {field: text}}]}).to_string())
}

fn content_frame(text: &str) -> Result<Vec<u8>, HttpError> {
    sse(&json!({"choices": [{"index": 0, "delta": {"content": text}}]}).to_string())
}

fn finish_frames(reason: &str) -> Vec<Result<Vec<u8>, HttpError>> {
    vec![
        sse(&json!({
            "choices": [{"index": 0, "delta": {}, "finish_reason": reason}],
            "usage": {"prompt_tokens": 3, "completion_tokens": 2},
        })
        .to_string()),
        sse("[DONE]"),
    ]
}

/// A chat-completions stream that reasons for [`LONG_REASONING`] frames (both spellings) before
/// it answers `answer` (no content frame at all when `answer` is `None`).
fn long_reasoning_stream(answer: Option<&str>, finish: &str) -> Vec<Result<Vec<u8>, HttpError>> {
    let mut frames: Vec<_> = (0..LONG_REASONING)
        .map(|i| {
            let field = if i % 2 == 0 {
                "reasoning_content"
            } else {
                "reasoning"
            };
            reasoning_frame(field, "step ")
        })
        .collect();
    if let Some(text) = answer {
        frames.push(content_frame(text));
    }
    frames.extend(finish_frames(finish));
    frames
}

/// Poll a live stream to its end: the text released on the way and the terminal outcome.
async fn drain(rig: &Rig, handle: u64) -> (String, PollOutcome) {
    let mut released = String::new();
    loop {
        let outcome = tokio::time::timeout(
            Duration::from_secs(5),
            rig.registry.poll_live(handle, "test-agent"),
        )
        .await
        .expect("the stream must reach a terminal outcome");
        match outcome {
            PollOutcome::Delta(delta) => released.push_str(&delta),
            other => return (released, other),
        }
    }
}

async fn buffered_stream(rig: &Rig, alias: &str) -> Result<ChatResponse, LlmError> {
    let ready = rig.gateway.stream_begin(ctx(alias)).await?;
    Ok(rig.gateway.stream_finish(ready))
}

async fn preflight(rig: &Rig, entries: &str) -> Result<(), LlmError> {
    chat_preflight(
        Arc::new(StaticConfig(Arc::new(config(entries)))),
        Arc::clone(&rig.chain) as Arc<dyn HttpSecurityChain>,
        Arc::new(DiscardEventBus),
        &AtomicBool::new(false),
    )
    .await
}

fn deadline_exceeded() -> LlmError {
    LlmError::ProviderError("deadline-exceeded".into())
}

/// A local entry's backend: records the budget it is given (`deadline` minus now) and the
/// reasoning setting of every request, then answers `local` after `delay`.
struct RecordingPort {
    delay: Duration,
    seen: Mutex<Vec<(Duration, Option<String>)>>,
}

impl RecordingPort {
    fn new(delay: Duration) -> Arc<Self> {
        Arc::new(Self {
            delay,
            seen: Mutex::new(Vec::new()),
        })
    }

    fn record(&self, req: &InferenceChatRequest) {
        self.seen.lock().unwrap().push((
            req.deadline.saturating_duration_since(Instant::now()),
            req.reasoning_effort.clone(),
        ));
    }

    fn seen(&self) -> Vec<(Duration, Option<String>)> {
        self.seen.lock().unwrap().clone()
    }
}

#[async_trait]
impl InferenceBackendPort for RecordingPort {
    async fn chat(
        &self,
        req: InferenceChatRequest,
    ) -> Result<InferenceChatResponse, InferenceBackendError> {
        self.record(&req);
        tokio::time::sleep(self.delay).await;
        Ok(InferenceChatResponse {
            text: "local".into(),
            model: "llama".into(),
            input_tokens: 1,
            output_tokens: 1,
            finish_reason: "stop".into(),
        })
    }

    async fn embed(
        &self,
        _req: InferenceEmbedRequest,
    ) -> Result<InferenceEmbedResponse, InferenceBackendError> {
        Err(InferenceBackendError::Unwired)
    }

    async fn start_stream(
        &self,
        req: InferenceChatRequest,
    ) -> Result<(InferenceStreamHead, Box<dyn InferenceStream>), InferenceBackendError> {
        self.record(&req);
        Err(InferenceBackendError::Unwired)
    }

    fn is_wired(&self) -> bool {
        true
    }
}

fn local_rig(extra: &str, port: &Arc<RecordingPort>) -> Rig {
    let mut ports = InferenceBackendRegistry::new();
    ports.insert(
        "local-reasoner",
        Arc::clone(port) as Arc<dyn InferenceBackendPort>,
    );
    rig_with_ports(&local_reasoner(extra), ports)
}

/// `budget` is what an entry's hop was given: at most `expected`, and not more than a second
/// of real time below it.
fn assert_budget(budget: Duration, expected: Duration) {
    assert!(
        budget <= expected && budget > expected - Duration::from_secs(1),
        "budget {budget:?}, expected {expected:?}"
    );
}

/// `waited` (paused tokio time) is a cut at `budget`, and before `later`. The gateway measures a
/// hop's budget on the wall clock while the paused clock only moves when the runtime idles, so
/// the cut may come up to a second (of real time spent before it) early, never late.
fn assert_cut_at(waited: Duration, budget: Duration, later: Duration) {
    assert!(
        waited > budget - Duration::from_secs(1) && waited < later,
        "cut at {budget:?}, waited {waited:?}"
    );
}

// ── answers that carry only reasoning output ─────────────────────────────────────────────────

/// A chat-completions answer with `content: null` and only reasoning output (either spelling)
/// is an answer with empty text, its usage and finish reason kept, on `generate` and on the
/// buffered stream.
#[tokio::test]
async fn a_reasoning_only_answer_is_an_empty_reply_on_generate_and_the_buffered_stream() {
    for field in ["reasoning_content", "reasoning"] {
        let rig = rig(&reasoner(""));
        rig.chain
            .push_response(CHAT_PATH, Ok(reasoning_only_answer(field)));
        let generated = rig
            .gateway
            .generate(ctx("think"))
            .await
            .unwrap_or_else(|e| panic!("{field}: a reasoning-only answer is an answer: {e}"));
        assert_eq!(generated.text, "", "{field}");
        assert_eq!(generated.finish_reason, "length", "{field}");
        assert_eq!(
            (generated.input_tokens, generated.output_tokens),
            (9, 16),
            "{field}"
        );
        assert!(generated.tool_calls.is_empty());

        let streamed = buffered_stream(&rig, "think")
            .await
            .unwrap_or_else(|e| panic!("{field}: buffered stream: {e}"));
        assert_eq!(streamed.text, "", "{field}");
        assert_eq!(streamed.finish_reason, "length", "{field}");
        assert_eq!(rig.chain.call_log.lock().unwrap().len(), 2, "no retry");
    }
}

/// `content: null` without reasoning output or tool calls is still a malformed answer.
#[tokio::test]
async fn a_null_answer_without_reasoning_or_tool_calls_is_still_invalid() {
    let rig = rig(&reasoner(""));
    rig.chain.push_response(
        CHAT_PATH,
        Ok(http(json!({
            "choices": [{"message": {"role": "assistant", "content": null, "reasoning_content": ""}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 9, "completion_tokens": 0},
        }))),
    );
    assert_eq!(
        rig.gateway.generate(ctx("think")).await,
        Err(LlmError::ProviderError("invalid response shape".into()))
    );
}

/// The 16-token first-open preflight passes against a reasoning model whose whole budget goes
/// to reasoning (`content: null`, `finish_reason: "length"`), and sends the request it always
/// sent.
#[tokio::test]
async fn the_first_open_preflight_passes_against_a_reasoning_only_answer() {
    let entries = reasoner("");
    for field in ["reasoning_content", "reasoning"] {
        let rig = rig(&entries);
        rig.chain
            .push_response(CHAT_PATH, Ok(reasoning_only_answer(field)));
        preflight(&rig, &entries)
            .await
            .unwrap_or_else(|e| panic!("{field}: the preflight must pass: {e}"));
        assert_eq!(rig.bodies(), vec![PREFLIGHT_BODY.to_string()]);
    }
}

/// A live stream that reasons for more frames than the no-progress bound before its first text
/// delta completes, and releases only the text: reasoning is never released.
#[tokio::test]
async fn a_live_stream_that_reasons_at_length_before_answering_completes_with_only_the_text() {
    let rig = rig(&reasoner(""));
    rig.chain
        .push_stream(CHAT_PATH, 200, long_reasoning_stream(Some("pong"), "stop"));
    let handle = rig
        .gateway
        .stream_begin_live(ctx("think"), &rig.registry)
        .await
        .expect("the head is a 200");
    let (released, outcome) = drain(&rig, handle).await;
    assert_eq!(released, "pong");
    match outcome {
        PollOutcome::Done(done) => {
            assert_eq!(done.response.text, "pong");
            assert_eq!(done.response.finish_reason, "stop");
            assert_eq!(
                (done.response.input_tokens, done.response.output_tokens),
                (3, 2)
            );
        }
        PollOutcome::Failed(err) => panic!("the stream must complete: {err}"),
        _ => panic!("the stream must complete"),
    }
}

/// A live stream that only reasons completes with empty text and its usage.
#[tokio::test]
async fn a_live_stream_with_only_reasoning_completes_empty() {
    let rig = rig(&reasoner(""));
    rig.chain
        .push_stream(CHAT_PATH, 200, long_reasoning_stream(None, "length"));
    let handle = rig
        .gateway
        .stream_begin_live(ctx("think"), &rig.registry)
        .await
        .expect("the head is a 200");
    let (released, outcome) = drain(&rig, handle).await;
    assert_eq!(released, "");
    match outcome {
        PollOutcome::Done(done) => {
            assert_eq!(done.response.text, "");
            assert_eq!(done.response.finish_reason, "length");
        }
        PollOutcome::Failed(err) => panic!("the stream must complete: {err}"),
        _ => panic!("the stream must complete"),
    }
}

/// The no-progress bound still holds for frames that carry nothing: an empty reasoning field
/// is not reasoning output.
#[tokio::test]
async fn a_flood_of_frames_without_reasoning_output_is_still_cut() {
    let rig = rig(&reasoner(""));
    let mut frames: Vec<_> = (0..LONG_REASONING)
        .map(|_| reasoning_frame("reasoning_content", ""))
        .collect();
    frames.extend(finish_frames("stop"));
    rig.chain.push_stream(CHAT_PATH, 200, frames);
    let handle = rig
        .gateway
        .stream_begin_live(ctx("think"), &rig.registry)
        .await
        .expect("the head is a 200");
    match drain(&rig, handle).await.1 {
        PollOutcome::Failed(LlmError::ProviderError(msg)) => {
            assert!(msg.ends_with("stream ignore flood"), "{msg}")
        }
        PollOutcome::Failed(err) => panic!("expected the ignore flood, got {err}"),
        _ => panic!("expected the ignore flood"),
    }
}

// ── an entry's own generate budget ───────────────────────────────────────────────────────────

/// With `generate-timeout-secs` a slow upstream (45 s) is not cut at the 30 s default on the
/// buffered path, and the request runs under the entry's budget as the HTTP layer's own
/// timeout.
#[tokio::test(start_paused = true)]
async fn an_entry_timeout_lets_a_slow_buffered_answer_finish_past_the_default_budget() {
    let rig = rig(&reasoner(&entry_timeout()));
    rig.slow_upstream();
    rig.chain
        .push_response(CHAT_PATH, Ok(text_answer("late but whole")));
    let started = tokio::time::Instant::now();
    let answer = rig
        .gateway
        .generate(ctx("think"))
        .await
        .expect("the entry allows 120 s");
    assert_eq!(answer.text, "late but whole");
    assert!(started.elapsed() >= SLOW);
    assert_eq!(
        rig.request_timeouts(),
        vec![Some(Duration::from_secs(ENTRY_SECS))]
    );
}

/// Without the key the same slow upstream is cut at the 30 s default, and the request runs
/// under the executor's configured timeout, as before.
#[tokio::test(start_paused = true)]
async fn without_an_entry_timeout_a_slow_buffered_answer_is_cut_at_the_default_budget() {
    let rig = rig(&reasoner(""));
    rig.slow_upstream();
    rig.chain
        .push_response(CHAT_PATH, Ok(text_answer("too late")));
    let started = tokio::time::Instant::now();
    assert_eq!(
        rig.gateway.generate(ctx("think")).await,
        Err(deadline_exceeded())
    );
    assert_cut_at(started.elapsed(), cap_http::DEFAULT_TIMEOUT, SLOW);
    assert_eq!(rig.request_timeouts(), vec![None]);
    assert_eq!(rig.chain.call_log.lock().unwrap().len(), 1, "not retried");
}

/// The entry's budget replaces the default in both directions: a 5 s entry is cut at 5 s.
#[tokio::test(start_paused = true)]
async fn an_entry_timeout_below_the_default_cuts_the_hop_at_its_own_budget() {
    let rig = rig(&reasoner("  generate-timeout-secs: 5\n"));
    rig.slow_upstream();
    rig.chain.push_response(CHAT_PATH, Ok(text_answer("late")));
    let started = tokio::time::Instant::now();
    assert_eq!(
        rig.gateway.generate(ctx("think")).await,
        Err(deadline_exceeded())
    );
    assert_cut_at(
        started.elapsed(),
        Duration::from_secs(5),
        cap_http::DEFAULT_TIMEOUT,
    );
    assert_eq!(rig.request_timeouts(), vec![Some(Duration::from_secs(5))]);
}

/// The first-open preflight of an entry with its own budget is not cut at the default either;
/// without the key it still is.
#[tokio::test(start_paused = true)]
async fn the_preflight_of_an_entry_with_its_own_timeout_is_not_cut_at_the_default_budget() {
    let entries = reasoner(&entry_timeout());
    let rig = rig(&entries);
    rig.slow_upstream();
    rig.chain
        .push_response(CHAT_PATH, Ok(reasoning_only_answer("reasoning_content")));
    preflight(&rig, &entries)
        .await
        .expect("the entry allows 120 s");
    assert_eq!(
        rig.request_timeouts(),
        vec![Some(Duration::from_secs(ENTRY_SECS))]
    );

    let entries = reasoner("");
    let rig = self::rig(&entries);
    rig.slow_upstream();
    rig.chain
        .push_response(CHAT_PATH, Ok(reasoning_only_answer("reasoning_content")));
    assert_eq!(preflight(&rig, &entries).await, Err(deadline_exceeded()));
    assert_eq!(rig.request_timeouts(), vec![None]);
}

/// The buffered stream and the live stream send their request under the entry's budget as
/// the HTTP layer's own timeout (the bound of an unstreamed request, the head and idle bound
/// of a streamed one); without the key they run under the executor's configured timeout.
#[tokio::test]
async fn both_stream_paths_send_their_request_under_the_entry_timeout() {
    for (extra, expected) in [
        (entry_timeout(), Some(Duration::from_secs(ENTRY_SECS))),
        (String::new(), None),
    ] {
        let rig = rig(&reasoner(&extra));
        rig.chain.push_response(CHAT_PATH, Ok(text_answer("whole")));
        let streamed = buffered_stream(&rig, "think")
            .await
            .expect("buffered stream");
        assert_eq!(streamed.text, "whole");

        rig.chain.push_stream(
            CHAT_PATH,
            200,
            vec![content_frame("live")]
                .into_iter()
                .chain(finish_frames("stop"))
                .collect(),
        );
        let handle = rig
            .gateway
            .stream_begin_live(ctx("think"), &rig.registry)
            .await
            .expect("the head is a 200");
        let (released, outcome) = drain(&rig, handle).await;
        assert_eq!(released, "live");
        assert!(matches!(outcome, PollOutcome::Done(_)));

        assert_eq!(
            rig.request_timeouts(),
            vec![expected, expected],
            "{extra:?}"
        );
        assert_eq!(rig.chain.streamed_urls.lock().unwrap().len(), 1);
    }
}

/// A buffered stream with a slow upstream is not cut by the gateway: its request is bounded
/// by the HTTP layer, under the entry's budget.
#[tokio::test(start_paused = true)]
async fn a_slow_buffered_stream_of_an_entry_with_its_own_timeout_completes() {
    let rig = rig(&reasoner(&entry_timeout()));
    rig.slow_upstream();
    rig.chain
        .push_response(CHAT_PATH, Ok(text_answer("late but whole")));
    let streamed = buffered_stream(&rig, "think")
        .await
        .expect("the entry allows 120 s");
    assert_eq!(streamed.text, "late but whole");
    assert_eq!(
        rig.request_timeouts(),
        vec![Some(Duration::from_secs(ENTRY_SECS))]
    );
}

/// A local entry's budget is the deadline its backend is given, on `generate` and on the
/// buffered stream, and a slow local answer within it completes; without the key the backend
/// gets the 30 s default and is cut there.
#[tokio::test(start_paused = true)]
async fn a_local_entry_timeout_is_the_deadline_its_backend_is_given() {
    let port = RecordingPort::new(SLOW);
    let rig = local_rig(&entry_timeout(), &port);
    let answer = rig
        .gateway
        .generate(ctx("llama"))
        .await
        .expect("the entry allows 120 s");
    assert_eq!(answer.text, "local");
    let streamed = buffered_stream(&rig, "llama")
        .await
        .expect("buffered stream");
    assert_eq!(streamed.text, "local");
    let seen = port.seen();
    assert_eq!(seen.len(), 2);
    for (budget, _) in seen {
        assert_budget(budget, Duration::from_secs(ENTRY_SECS));
    }

    let port = RecordingPort::new(SLOW);
    let rig = local_rig("", &port);
    assert_eq!(
        rig.gateway.generate(ctx("llama")).await,
        Err(deadline_exceeded())
    );
    assert_eq!(
        buffered_stream(&rig, "llama").await.map(|r| r.text),
        Err(deadline_exceeded())
    );
    let seen = port.seen();
    assert_eq!(seen.len(), 2);
    for (budget, _) in seen {
        assert_budget(budget, cap_http::DEFAULT_TIMEOUT);
    }
}

/// An explicit test hop budget still wins over the entry's own.
#[tokio::test(start_paused = true)]
async fn the_test_hop_budget_still_wins_over_the_entry_timeout() {
    let chain = Arc::new(MockHttpSecurityChain::default());
    *chain.execute_delay.lock().unwrap() = Some(SLOW);
    chain.push_response(CHAT_PATH, Ok(text_answer("late")));
    let gateway = LlmGateway::new(
        Arc::new(MockRuntimeConfigProvider::new(config(&reasoner(
            &entry_timeout(),
        )))),
        Arc::clone(&chain) as Arc<dyn HttpSecurityChain>,
        Arc::new(MockRunBudget::default()),
        Arc::new(MockEventBusEmit::default()),
        no_op_repetition_guard(),
        "test-agent".into(),
    )
    .with_generate_timeout(Duration::from_secs(2));
    let started = tokio::time::Instant::now();
    assert_eq!(
        gateway.generate(ctx("think")).await,
        Err(deadline_exceeded())
    );
    assert!(started.elapsed() < Duration::from_secs(3));
}

// ── an entry's reasoning setting ─────────────────────────────────────────────────────────────

/// `reasoning-effort` reaches every chat request of a chat-completions entry top-level —
/// `generate`, the buffered stream, the live stream and the first-open preflight — and never
/// its embedding request; without the key every body is the one sent before the key existed.
#[tokio::test]
async fn the_reasoning_effort_reaches_every_chat_request_and_never_an_embedding() {
    for (extra, effort) in [("  reasoning-effort: low\n", Some("low")), ("", None)] {
        let entries = reasoner(extra);
        let rig = rig(&entries);
        rig.chain.push_response(CHAT_PATH, Ok(text_answer("ok")));
        rig.gateway.generate(ctx("think")).await.expect("generate");
        buffered_stream(&rig, "think").await.expect("stream_begin");
        rig.chain.push_stream(
            CHAT_PATH,
            200,
            vec![content_frame("ok")]
                .into_iter()
                .chain(finish_frames("stop"))
                .collect(),
        );
        let handle = rig
            .gateway
            .stream_begin_live(ctx("think"), &rig.registry)
            .await
            .expect("the head is a 200");
        assert!(matches!(drain(&rig, handle).await.1, PollOutcome::Done(_)));
        preflight(&rig, &entries).await.expect("preflight");
        rig.chain.push_response(
            EMBEDDINGS_PATH,
            Ok(HttpResponse {
                status: 200,
                headers: vec![],
                body: br#"{"data":[{"embedding":[0.5,0.25]}]}"#.to_vec(),
            }),
        );
        assert_eq!(rig.gateway.embed("text").await.unwrap(), vec![0.5, 0.25]);

        let with = |body: &str| match effort {
            Some(effort) => body.replacen(
                r#","stream":"#,
                &format!(r#","reasoning_effort":"{effort}","stream":"#),
                1,
            ),
            None => body.to_string(),
        };
        let chat = match effort {
            Some(effort) => CHAT_BODY.replacen(
                r#","temperature""#,
                &format!(r#","reasoning_effort":"{effort}","temperature""#),
                1,
            ),
            None => CHAT_BODY.to_string(),
        };
        let preflight_body = match effort {
            Some(effort) => format!(
                r#"{},"reasoning_effort":"{effort}"}}"#,
                PREFLIGHT_BODY.strip_suffix('}').unwrap()
            ),
            None => PREFLIGHT_BODY.to_string(),
        };
        let bodies = rig.bodies();
        assert_eq!(bodies.len(), 5);
        assert_eq!(bodies[0], chat, "generate");
        assert_eq!(bodies[1], chat, "buffered stream");
        assert_eq!(bodies[2], with(STREAM_BODY), "live stream");
        assert_eq!(bodies[3], preflight_body, "preflight");
        assert!(!bodies[4].contains("reasoning"), "embedding: {}", bodies[4]);
    }
}

/// A Responses entry sends its setting as `reasoning.effort`.
#[tokio::test]
async fn a_responses_entry_sends_its_reasoning_effort_as_the_reasoning_object() {
    let rig = rig(&responses_reasoner("  reasoning-effort: high\n"));
    rig.chain
        .push_response(RESPONSES_PATH, Ok(responses_text_answer("ok")));
    rig.gateway.generate(ctx("think")).await.expect("generate");
    let body: Value = serde_json::from_str(&rig.bodies()[0]).unwrap();
    assert_eq!(body["reasoning"], json!({"effort": "high"}));
    assert!(body.get("reasoning_effort").is_none());

    let rig = self::rig(&responses_reasoner(""));
    rig.chain
        .push_response(RESPONSES_PATH, Ok(responses_text_answer("ok")));
    rig.gateway.generate(ctx("think")).await.expect("generate");
    assert!(
        !rig.bodies()[0].contains("reasoning\":{"),
        "{}",
        rig.bodies()[0]
    );
}

/// A local entry's setting reaches its backend with every chat request (generate, buffered
/// stream, live stream); without the key the backend sees none.
#[tokio::test]
async fn a_local_entry_hands_its_reasoning_effort_to_its_backend() {
    for (extra, effort) in [("  reasoning-effort: high\n", Some("high")), ("", None)] {
        let port = RecordingPort::new(Duration::ZERO);
        let rig = local_rig(extra, &port);
        rig.gateway.generate(ctx("llama")).await.expect("generate");
        buffered_stream(&rig, "llama").await.expect("stream_begin");
        let _ = rig
            .gateway
            .stream_begin_live(ctx("llama"), &rig.registry)
            .await;
        let seen = port.seen();
        assert_eq!(seen.len(), 3, "{extra:?}");
        for (_, sent) in seen {
            assert_eq!(sent.as_deref(), effort, "{extra:?}");
        }
    }
}

// ── entries with different budgets in one request ────────────────────────────────────────────

fn urls(rig: &Rig) -> Vec<String> {
    rig.chain
        .call_log
        .lock()
        .unwrap()
        .iter()
        .map(|req| req.url.clone())
        .collect()
}

fn upstream_503() -> HttpResponse {
    HttpResponse {
        status: 503,
        headers: vec![],
        body: b"{}".to_vec(),
    }
}

/// A long hop under an entry's own budget hands its failure on: `first` (120 s) answers 503
/// after 40 s on both of its attempts, each sent under its budget, so its hop ends after about
/// 80 s with a failure that spent no token, and `second` (no budget of its own) is tried. The
/// gateway's deadlines run on the real clock, which this paused test does not move; the
/// arithmetic that keeps those 80 s off the shared default is covered by
/// `an_entry_budget_bounds_its_own_hop_and_is_credited_to_the_shared_bounds`.
#[tokio::test(start_paused = true)]
async fn a_long_hop_under_its_own_budget_hands_its_failure_on_to_the_next_entry() {
    let rig = rig(&two_entries(
        &format!("{}{RETRY_ONCE}", entry_timeout()),
        "",
    ));
    rig.chain
        .url_delays
        .lock()
        .unwrap()
        .push((FIRST_URL.into(), Duration::from_secs(40)));
    rig.chain.push_response(FIRST_URL, Ok(upstream_503()));
    rig.chain
        .push_response(SECOND_URL, Ok(text_answer("from the next entry")));
    let started = tokio::time::Instant::now();
    let answer = rig
        .gateway
        .generate(ctx("think"))
        .await
        .expect("the next entry still has its own budget");
    assert_eq!(answer.text, "from the next entry");
    assert!(started.elapsed() >= Duration::from_secs(80));
    assert_eq!(urls(&rig), [FIRST_URL, FIRST_URL, SECOND_URL]);
    let entry = Some(Duration::from_secs(ENTRY_SECS));
    assert_eq!(rig.request_timeouts(), vec![entry, entry, None]);
}

/// An entry with its own budget gets all of it when it is tried after an earlier hop: `first`
/// (the shared default) fails after about 2 s, and `second` (5 s) answers 4 s into its own hop,
/// about 6 s after the request began. Real time, since the gateway's deadlines run on the real
/// clock.
#[tokio::test]
async fn an_entry_tried_after_an_earlier_hop_gets_its_whole_budget() {
    let rig = rig(&two_entries(RETRY_ONCE, "  generate-timeout-secs: 5\n"));
    rig.chain.url_delays.lock().unwrap().extend([
        (FIRST_URL.to_string(), Duration::from_secs(1)),
        (SECOND_URL.to_string(), Duration::from_secs(4)),
    ]);
    rig.chain.push_response(FIRST_URL, Ok(upstream_503()));
    rig.chain
        .push_response(SECOND_URL, Ok(text_answer("within its own budget")));
    let started = std::time::Instant::now();
    let answer = rig
        .gateway
        .generate(ctx("think"))
        .await
        .expect("the entry's budget runs from the start of its own hop");
    assert_eq!(answer.text, "within its own budget");
    assert!(
        started.elapsed() > Duration::from_secs(5),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(urls(&rig), [FIRST_URL, FIRST_URL, SECOND_URL]);
    assert_eq!(
        rig.request_timeouts(),
        vec![None, None, Some(Duration::from_secs(5))]
    );
}

/// An entry whose own budget runs out before it answers hands the request on, like a transport
/// timeout: `first` (10 s) does not answer in time, `second` (300 s) does.
#[tokio::test(start_paused = true)]
async fn a_hop_that_runs_out_its_own_budget_fails_over_to_the_next_entry() {
    let rig = rig(&two_entries(
        "  generate-timeout-secs: 10\n",
        "  generate-timeout-secs: 300\n",
    ));
    rig.chain
        .url_delays
        .lock()
        .unwrap()
        .push((FIRST_URL.into(), SLOW));
    rig.chain
        .push_response(FIRST_URL, Ok(text_answer("too late")));
    rig.chain
        .push_response(SECOND_URL, Ok(text_answer("from the next entry")));
    let started = tokio::time::Instant::now();
    let answer = rig
        .gateway
        .generate(ctx("think"))
        .await
        .expect("the next entry answers");
    assert_eq!(answer.text, "from the next entry");
    assert_cut_at(started.elapsed(), Duration::from_secs(10), SLOW);
    assert_eq!(urls(&rig), [FIRST_URL, SECOND_URL]);
    assert_eq!(
        rig.request_timeouts(),
        vec![
            Some(Duration::from_secs(10)),
            Some(Duration::from_secs(300))
        ]
    );
}

/// The shared 30 s default running out still ends the request, as before, even when a later
/// entry has a budget of its own.
#[tokio::test(start_paused = true)]
async fn the_shared_default_running_out_still_ends_the_request() {
    let rig = rig(&two_entries("", &entry_timeout()));
    rig.chain
        .url_delays
        .lock()
        .unwrap()
        .push((FIRST_URL.into(), SLOW));
    rig.chain
        .push_response(FIRST_URL, Ok(text_answer("too late")));
    rig.chain
        .push_response(SECOND_URL, Ok(text_answer("never asked")));
    assert_eq!(
        rig.gateway.generate(ctx("think")).await,
        Err(deadline_exceeded())
    );
    assert_eq!(urls(&rig), [FIRST_URL], "the next entry is not tried");
}

// ── an entry that signs in ───────────────────────────────────────────────────────────────────

/// A signed-in entry keeps its own generate budget. Every request of such an entry is a streamed
/// exchange: one that takes 45 s to answer completes within the entry's 120 s on `generate` and
/// on the buffered stream, each sent under that budget as the HTTP layer's own timeout; without
/// the key the same exchange is cut at the 30 s default on both.
#[tokio::test(start_paused = true)]
async fn a_signed_in_entry_keeps_its_own_generate_budget_at_both_buffered_sites() {
    let rig = signed_in_rig(&entry_timeout());
    *rig.chain.stream_delay.lock().unwrap() = Some(SLOW);
    for _ in 0..2 {
        rig.chain.push_stream(
            RESPONSES_PATH,
            200,
            responses_stream_answer("late but whole"),
        );
    }
    let generated = rig
        .gateway
        .generate(ctx("signed"))
        .await
        .expect("the entry allows 120 s");
    assert_eq!(generated.text, "late but whole");
    let streamed = buffered_stream(&rig, "signed")
        .await
        .expect("the entry allows 120 s");
    assert_eq!(streamed.text, "late but whole");
    assert_eq!(
        rig.chain.streamed_urls.lock().unwrap().len(),
        2,
        "both requests were streamed exchanges"
    );
    let entry = Some(Duration::from_secs(ENTRY_SECS));
    assert_eq!(rig.request_timeouts(), vec![entry, entry]);

    let rig = signed_in_rig("");
    *rig.chain.stream_delay.lock().unwrap() = Some(SLOW);
    for _ in 0..2 {
        rig.chain
            .push_stream(RESPONSES_PATH, 200, responses_stream_answer("too late"));
    }
    let started = tokio::time::Instant::now();
    assert_eq!(
        rig.gateway.generate(ctx("signed")).await,
        Err(deadline_exceeded())
    );
    assert_cut_at(started.elapsed(), cap_http::DEFAULT_TIMEOUT, SLOW);
    assert_eq!(
        buffered_stream(&rig, "signed").await.map(|r| r.text),
        Err(deadline_exceeded())
    );
    assert_eq!(rig.request_timeouts(), vec![None, None]);
}

/// The longest generate budget a signed-in entry may set is the lifetime of one streamed
/// exchange, the only kind of request such an entry makes.
#[test]
fn the_signed_in_budget_ceiling_is_the_streamed_exchange_lifetime() {
    assert_eq!(
        Duration::from_secs(u64::from(
            advance_runtime::config::MAX_SIGN_IN_GENERATE_TIMEOUT_SECS
        )),
        cap_http::executor::MAX_STREAM_DURATION
    );
}

// ── the image / PDF extractor ────────────────────────────────────────────────────────────────

/// The image / PDF extractor sends the entry's reasoning setting top-level and runs its request
/// under the entry's own budget as the HTTP layer's timeout; without the keys its request is
/// the one it always sent, under the executor's configured timeout.
#[tokio::test]
async fn the_image_extractor_applies_the_entry_settings() {
    for (extra, effort, timeout) in [
        (
            format!("  reasoning-effort: low\n{}", entry_timeout()),
            Some("low"),
            Some(Duration::from_secs(ENTRY_SECS)),
        ),
        (String::new(), None, None),
    ] {
        let entries = reasoner(&extra);
        let rig = rig(&entries);
        rig.chain.push_response(CHAT_PATH, Ok(text_answer("a cat")));
        let described = extractor(&rig, &entries)
            .extract_description(&image())
            .await
            .expect("described");
        assert_eq!(described, "a cat");
        let bodies = rig.bodies();
        assert_eq!(bodies.len(), 1);
        let body: Value = serde_json::from_str(&bodies[0]).unwrap();
        match effort {
            Some(effort) => assert_eq!(body["reasoning_effort"], effort),
            None => assert!(body.get("reasoning_effort").is_none(), "{body}"),
        }
        assert_eq!(rig.request_timeouts(), vec![timeout], "{extra:?}");
    }
}

/// A reasoning-only answer is an empty description (which the indexer skips), as on the chat
/// path; a null answer without reasoning output stays malformed.
#[tokio::test]
async fn the_image_extractor_takes_a_reasoning_only_answer_as_an_empty_description() {
    let entries = reasoner("");
    for field in ["reasoning_content", "reasoning"] {
        let rig = rig(&entries);
        rig.chain
            .push_response(CHAT_PATH, Ok(reasoning_only_answer(field)));
        assert_eq!(
            extractor(&rig, &entries)
                .extract_description(&image())
                .await
                .unwrap_or_else(|e| panic!("{field}: {e}")),
            ""
        );
    }
    for message in [
        json!({"role": "assistant", "content": null}),
        json!({"role": "assistant", "content": null, "reasoning_content": ""}),
    ] {
        let rig = rig(&entries);
        rig.chain.push_response(
            CHAT_PATH,
            Ok(http(json!({"choices": [{"message": message}]}))),
        );
        assert_eq!(
            extractor(&rig, &entries)
                .extract_description(&image())
                .await,
            Err(LlmError::ProviderError("invalid response shape".into()))
        );
    }
}

//! Lane agent-llm-policy — gateway-level witnesses for the per-agent `llm:` policy port.
//!
//! Every test drives the REAL `LlmGateway` request paths (`generate`, `stream_begin_live`,
//! `stream_begin`) with a scripted `MockHttpSecurityChain` / in-process inference port and a
//! recording bus, and asserts on what actually left the gateway (the request URL / port hit)
//! and on the `llm.request` / `llm.response` payloads the durable cost ledger attributes by.

#![cfg(test)]

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use advance_runtime::config::{InferenceBackendClass, LlmProviderConfig, ProviderBackend};
use advance_shared_types::inference::{
    InferenceBackendError, InferenceBackendPort, InferenceBackendRegistry, InferenceChatRequest,
    InferenceChatResponse, InferenceEmbedRequest, InferenceEmbedResponse, InferenceStream,
    InferenceStreamHead,
};
use advance_shared_types::security_validator::HttpResponse;
use advance_shared_types::traits::HttpStreamingChain;
use async_trait::async_trait;
use cap_http::DefaultLeakDetector;

use crate::gateway::{
    ChatMessage, ChatParams, ChatRole, LlmGateway, LlmGatewayInternal, LlmRequestContext,
};
use crate::placement::{EndpointTelemetry, PlacementTelemetry, UserHardConstraint};
use crate::policy::{AgentLlmPolicy, AgentLlmPolicySource, LlmPolicySource};
use crate::stream::{PollOutcome, StreamRegistry};
use crate::test_support::{
    fixture_runtime_config, no_op_repetition_guard, MockEventBusEmit, MockHttpSecurityChain,
    MockRunBudget, MockRuntimeConfigProvider,
};
use crate::{LlmError, LLM_REQUEST, LLM_RESPONSE};

// ── fixtures ─────────────────────────────────────────────────────────────────────────────────

/// A source answering the same policy for every agent, recording the ids it was asked about.
struct StaticPolicy {
    policy: Option<AgentLlmPolicy>,
    asked: Mutex<Vec<String>>,
}

impl StaticPolicy {
    fn new(policy: Option<AgentLlmPolicy>) -> Arc<Self> {
        Arc::new(Self {
            policy,
            asked: Mutex::new(Vec::new()),
        })
    }
}

impl AgentLlmPolicySource for StaticPolicy {
    fn policy_for(&self, agent_id: &str) -> Option<AgentLlmPolicy> {
        self.asked.lock().unwrap().push(agent_id.to_string());
        self.policy.clone()
    }
}

fn cloud(id: &str, endpoint: &str, aliases: &[(&str, &str)]) -> LlmProviderConfig {
    LlmProviderConfig {
        id: id.into(),
        endpoint: endpoint.into(),
        api_key_secret: format!("{id}-api-key"),
        model_aliases: aliases
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        cost_per_mtoken_in: 2.5,
        cost_per_mtoken_out: 10.0,
        cost_per_mtoken_cache_read: None,
        cost_per_mtoken_cache_write: None,
        cost_per_mtoken_cache_write_1h: None,
        rate_limit: None,
        retry_default: None,
        backend: Some(ProviderBackend::OpenAiChat),
        auth_scheme: None,
        backend_class: InferenceBackendClass::CloudHttp,
        embedding_model: None,
        sidecar: None,
        profile_id: None,
        device_id: None,
        agent_cli: None,
        auth_source: advance_runtime::config::ProviderAuthSource::ApiKey,
        generate_timeout_secs: None,
        reasoning_effort: None,
        system_messages: None,
    }
}

fn local(id: &str, model: &str) -> LlmProviderConfig {
    let mut p = cloud(id, "", &[(model, model)]);
    p.backend_class = InferenceBackendClass::Local;
    p
}

fn ok_chat_response(content: &str) -> HttpResponse {
    let body = serde_json::json!({
        "choices": [{"message": {"content": content}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 7, "completion_tokens": 3},
        "model": "gpt-4o-mini",
    });
    HttpResponse {
        status: 200,
        headers: vec![],
        body: serde_json::to_vec(&body).unwrap(),
    }
}

fn user(content: &str) -> ChatMessage {
    ChatMessage {
        role: ChatRole::User,
        content: content.into(),
        tool_call_id: None,
        tool_calls: Vec::new(),
    }
}

fn ctx(model: Option<&str>) -> LlmRequestContext {
    LlmRequestContext {
        agent_id: "test-agent".into(),
        messages: vec![user("hi")],
        params: ChatParams {
            model: model.map(str::to_string),
            ..Default::default()
        },
        ..Default::default()
    }
}

struct Harness {
    gateway: LlmGateway,
    chain: Arc<MockHttpSecurityChain>,
    bus: Arc<MockEventBusEmit>,
}

fn harness(providers: Vec<LlmProviderConfig>, policy: Option<Arc<StaticPolicy>>) -> Harness {
    let mut cfg = fixture_runtime_config();
    cfg.llm_providers = providers;
    let chain = Arc::new(MockHttpSecurityChain::default());
    let bus = Arc::new(MockEventBusEmit::default());
    let mut gateway = LlmGateway::new(
        Arc::new(MockRuntimeConfigProvider::new(cfg)),
        chain.clone(),
        Arc::new(MockRunBudget::default()),
        bus.clone(),
        no_op_repetition_guard(),
        "test-agent".into(),
    )
    .with_live_streaming(
        chain.clone() as Arc<dyn HttpStreamingChain>,
        Arc::new(DefaultLeakDetector::default()),
    );
    if let Some(policy) = policy {
        gateway = gateway.with_agent_policy(policy);
    }
    Harness {
        gateway,
        chain,
        bus,
    }
}

fn two_clouds() -> Vec<LlmProviderConfig> {
    vec![
        cloud(
            "openai",
            "https://api.openai.com",
            &[("gpt4o", "gpt-4o-2024-08-06"), ("mini", "gpt-4o-mini")],
        ),
        cloud(
            "openai-eu",
            "https://eu.openai.example",
            &[("gpt4o", "gpt-4o-eu")],
        ),
    ]
}

fn requests(bus: &MockEventBusEmit) -> Vec<advance_shared_types::event::Event> {
    bus.snapshot()
        .into_iter()
        .filter(|e| e.event_type == LLM_REQUEST)
        .collect()
}

fn urls(chain: &MockHttpSecurityChain) -> Vec<String> {
    chain
        .call_log
        .lock()
        .unwrap()
        .iter()
        .map(|r| r.url.clone())
        .collect()
}

/// A chat-only local inference port that answers a fixed text and counts calls.
struct LocalPort {
    text: String,
    chats: AtomicU32,
}

#[async_trait]
impl InferenceBackendPort for LocalPort {
    async fn chat(
        &self,
        _req: InferenceChatRequest,
    ) -> Result<InferenceChatResponse, InferenceBackendError> {
        self.chats.fetch_add(1, Ordering::SeqCst);
        Ok(InferenceChatResponse {
            text: self.text.clone(),
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
        _req: InferenceChatRequest,
    ) -> Result<(InferenceStreamHead, Box<dyn InferenceStream>), InferenceBackendError> {
        Err(InferenceBackendError::Unwired)
    }
    fn is_wired(&self) -> bool {
        true
    }
}

/// Fixed per-endpoint predicted TTFT so the unconstrained placement is deterministic.
struct Ttft(HashMap<String, u64>);

impl PlacementTelemetry for Ttft {
    fn snapshot(&self, endpoint_id: &str) -> Option<EndpointTelemetry> {
        self.0
            .get(endpoint_id)
            .copied()
            .map(|queue_ms| EndpointTelemetry {
                queue_ms,
                ..EndpointTelemetry::default()
            })
    }
    fn device_id(&self, _endpoint_id: &str) -> Option<String> {
        None
    }
}

// ── provider pin ─────────────────────────────────────────────────────────────────────────────

/// A pinned provider that is not configured fails CLOSED before any placement / dispatch:
/// no HTTP request leaves, no `llm.request` is emitted, and the gateway never falls back to the
/// head entry. All three request paths behave the same.
#[tokio::test]
async fn pin_to_unknown_provider_fails_closed_on_every_path() {
    let policy = StaticPolicy::new(Some(AgentLlmPolicy {
        provider: Some("local".into()),
        ..Default::default()
    }));
    let h = harness(two_clouds(), Some(policy.clone()));
    h.chain
        .push_response("/v1/chat/completions", Ok(ok_chat_response("never")));

    let err = h.gateway.generate(ctx(None)).await.unwrap_err();
    match &err {
        LlmError::ModelNotAvailable(msg) => {
            assert_eq!(msg, "provider local not configured for agent test-agent")
        }
        other => panic!("expected ModelNotAvailable, got {other:?}"),
    }
    let registry = Arc::new(StreamRegistry::new());
    assert!(matches!(
        h.gateway.stream_begin_live(ctx(None), &registry).await,
        Err(LlmError::ModelNotAvailable(_))
    ));
    assert!(matches!(
        h.gateway.stream_begin(ctx(None)).await,
        Err(LlmError::ModelNotAvailable(_))
    ));
    assert!(urls(&h.chain).is_empty(), "nothing may leave the gateway");
    assert!(
        requests(&h.bus).is_empty(),
        "no llm.request for a refused request"
    );
    assert_eq!(
        policy.asked.lock().unwrap().len(),
        3,
        "policy consulted per request"
    );
}

/// A pin to the SECOND configured provider routes there: the request URL, the
/// `llm.request.provider_id` and the `llm.response.provider` attribution key all name it.
#[tokio::test]
async fn pin_to_second_provider_routes_and_attributes_there() {
    let policy = StaticPolicy::new(Some(AgentLlmPolicy {
        provider: Some("openai-eu".into()),
        ..Default::default()
    }));
    let h = harness(two_clouds(), Some(policy));
    h.chain
        .push_response("/v1/chat/completions", Ok(ok_chat_response("eu-hit")));

    let resp = h
        .gateway
        .generate(ctx(None))
        .await
        .expect("pinned generate");
    assert_eq!(resp.text, "eu-hit");
    let urls = urls(&h.chain);
    assert_eq!(urls.len(), 1);
    assert!(
        urls[0].starts_with("https://eu.openai.example"),
        "request must go to the pinned provider: {urls:?}"
    );
    let reqs = requests(&h.bus);
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].payload["provider_id"], "openai-eu");
    assert_eq!(reqs[0].payload["endpoint_id"], "openai-eu");
    assert_eq!(reqs[0].payload["policy_source"], "agent");
    assert_eq!(reqs[0].payload["model"], "gpt-4o-eu");
    let resp_evt = h
        .bus
        .snapshot()
        .into_iter()
        .find(|e| e.event_type == LLM_RESPONSE)
        .expect("llm.response");
    assert_eq!(
        resp_evt.payload["provider"], "openai-eu",
        "cost attribution follows the pinned provider"
    );
}

/// Without a pin the SAME config routes to the head provider (the control for the test above).
#[tokio::test]
async fn unpinned_request_uses_the_head_provider() {
    let h = harness(two_clouds(), None);
    h.chain
        .push_response("/v1/chat/completions", Ok(ok_chat_response("head")));
    h.gateway.generate(ctx(None)).await.expect("generate");
    let urls = urls(&h.chain);
    assert!(urls[0].starts_with("https://api.openai.com"), "{urls:?}");
    let reqs = requests(&h.bus);
    assert_eq!(reqs[0].payload["provider_id"], "openai");
    assert_eq!(reqs[0].payload["policy_source"], "default");
}

// ── model precedence ─────────────────────────────────────────────────────────────────────────

/// Effective model: an explicit per-call `params.model` beats the policy's default model, which
/// beats today's default (the lexicographically first alias of the head provider).
#[tokio::test]
async fn model_precedence_call_param_then_policy_then_default() {
    let providers = vec![cloud(
        "openai",
        "https://api.openai.com",
        &[("gpt4o", "gpt-4o-2024-08-06"), ("mini", "gpt-4o-mini")],
    )];
    // policy: default model = mini
    let policy = StaticPolicy::new(Some(AgentLlmPolicy {
        model: Some("mini".into()),
        ..Default::default()
    }));
    let h = harness(providers.clone(), Some(policy));
    h.chain
        .push_response("/v1/chat/completions", Ok(ok_chat_response("ok")));
    h.gateway.generate(ctx(None)).await.expect("policy model");
    h.gateway
        .generate(ctx(Some("gpt4o")))
        .await
        .expect("call-param model");
    let reqs = requests(&h.bus);
    assert_eq!(reqs.len(), 2);
    assert_eq!(
        reqs[0].payload["model"], "gpt-4o-mini",
        "policy default applies"
    );
    assert_eq!(reqs[0].payload["policy_source"], "agent");
    assert_eq!(
        reqs[1].payload["model"], "gpt-4o-2024-08-06",
        "an explicit call parameter wins over the policy"
    );
    assert_eq!(
        reqs[1].payload["policy_source"], "default",
        "nothing of the policy applied to the explicit-model call"
    );

    // no policy at all → today's default (smallest alias key: gpt4o < mini)
    let h = harness(providers, None);
    h.chain
        .push_response("/v1/chat/completions", Ok(ok_chat_response("ok")));
    h.gateway.generate(ctx(None)).await.expect("default model");
    let reqs = requests(&h.bus);
    assert_eq!(reqs[0].payload["model"], "gpt-4o-2024-08-06");
    assert_eq!(reqs[0].payload["policy_source"], "default");
}

// ── constraint ───────────────────────────────────────────────────────────────────────────────

/// `always-local` from the policy excludes the cloud candidate even when telemetry prefers it:
/// the local port serves the request and the HTTP chain is never touched.
#[tokio::test]
async fn always_local_constraint_excludes_cloud_candidates() {
    let port = Arc::new(LocalPort {
        text: "local-hit".into(),
        chats: AtomicU32::new(0),
    });
    let mut registry = InferenceBackendRegistry::new();
    registry.insert("local", port.clone());
    let providers = vec![
        cloud("cloud", "https://api.example.test", &[("llama", "llama")]),
        local("local", "llama"),
    ];
    let telemetry = Arc::new(Ttft(HashMap::from([
        ("cloud".to_string(), 1u64),
        ("local".to_string(), 5000u64),
    ])));

    // Control: no policy → the faster cloud endpoint wins.
    let h = harness(providers.clone(), None);
    let gw = h
        .gateway
        .with_inference_backends({
            let mut r = InferenceBackendRegistry::new();
            r.insert("local", port.clone());
            r
        })
        .with_placement_telemetry(telemetry.clone());
    h.chain
        .push_response("/v1/chat/completions", Ok(ok_chat_response("cloud-hit")));
    let resp = gw.generate(ctx(Some("llama"))).await.expect("cloud");
    assert_eq!(resp.text, "cloud-hit");
    assert_eq!(port.chats.load(Ordering::SeqCst), 0);
    assert_eq!(urls(&h.chain).len(), 1);

    // Policy constraint: always-local → the local port, chain untouched.
    let policy = StaticPolicy::new(Some(AgentLlmPolicy {
        constraint: Some(UserHardConstraint::AlwaysLocal),
        ..Default::default()
    }));
    let h = harness(providers, Some(policy));
    let gw = h
        .gateway
        .with_inference_backends(registry)
        .with_placement_telemetry(telemetry);
    let resp = gw.generate(ctx(Some("llama"))).await.expect("local");
    assert_eq!(resp.text, "local-hit");
    assert_eq!(port.chats.load(Ordering::SeqCst), 1);
    assert!(
        urls(&h.chain).is_empty(),
        "the cloud chain must not be called"
    );
    let reqs = requests(&h.bus);
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].payload["provider_id"], "local");
    assert_eq!(reqs[0].payload["policy_source"], "agent");
}

// ── byte-compat ──────────────────────────────────────────────────────────────────────────────

/// A wired source answering an EMPTY policy, and no source at all, both leave the request on
/// today's path: `policy_source = "default"`, `provider_id` mirrors `endpoint_id`, and the
/// remaining `llm.request` keys are exactly the pre-lane set.
#[tokio::test]
async fn empty_or_absent_policy_is_byte_compatible() {
    for policy in [
        None,
        Some(StaticPolicy::new(Some(AgentLlmPolicy::default()))),
    ] {
        let h = harness(two_clouds(), policy);
        h.chain
            .push_response("/v1/chat/completions", Ok(ok_chat_response("ok")));
        h.gateway.generate(ctx(None)).await.expect("generate");
        let reqs = requests(&h.bus);
        assert_eq!(reqs.len(), 1);
        let payload = reqs[0].payload.as_object().unwrap();
        let mut keys: Vec<&str> = payload.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec![
                "endpoint_id",
                "input_tokens",
                "model",
                "model_revision",
                "placement_reason",
                "policy_source",
                "provider_id",
            ]
        );
        assert_eq!(payload["policy_source"], "default");
        assert_eq!(payload["provider_id"], payload["endpoint_id"]);
        assert!(!h.gateway.has_agent_policy() || payload["policy_source"] == "default");
    }
    assert!(!harness(two_clouds(), None).gateway.has_agent_policy());
    assert!(harness(two_clouds(), Some(StaticPolicy::new(None)))
        .gateway
        .has_agent_policy());
}

#[test]
fn policy_source_default_is_default() {
    assert_eq!(
        LlmRequestContext::default().policy_source,
        LlmPolicySource::Default
    );
}

// ── embedding follows the agent's chat provider ──────────────────────────────────────────────

/// A source answering a different policy per agent; the policies can change while the
/// gateway runs.
#[derive(Default)]
struct PerAgentPolicy(Mutex<HashMap<String, AgentLlmPolicy>>);

impl PerAgentPolicy {
    fn set(&self, agent_id: &str, policy: AgentLlmPolicy) {
        self.0.lock().unwrap().insert(agent_id.into(), policy);
    }
}

impl AgentLlmPolicySource for PerAgentPolicy {
    fn policy_for(&self, agent_id: &str) -> Option<AgentLlmPolicy> {
        self.0.lock().unwrap().get(agent_id).cloned()
    }
}

fn pin(provider: &str) -> AgentLlmPolicy {
    AgentLlmPolicy {
        provider: Some(provider.into()),
        ..Default::default()
    }
}

struct EmbedRig {
    gateway: LlmGateway,
    chain: Arc<MockHttpSecurityChain>,
    bus: Arc<MockEventBusEmit>,
    config: Arc<MockRuntimeConfigProvider>,
    policy: Arc<PerAgentPolicy>,
}

fn embed_rig(providers: Vec<LlmProviderConfig>) -> EmbedRig {
    let mut cfg = fixture_runtime_config();
    cfg.llm_providers = providers;
    let config = Arc::new(MockRuntimeConfigProvider::new(cfg));
    let chain = Arc::new(MockHttpSecurityChain::default());
    let bus = Arc::new(MockEventBusEmit::default());
    let policy = Arc::new(PerAgentPolicy::default());
    let gateway = LlmGateway::new(
        config.clone(),
        chain.clone(),
        Arc::new(MockRunBudget::default()),
        bus.clone(),
        no_op_repetition_guard(),
        "root".into(),
    )
    .with_agent_policy(policy.clone());
    EmbedRig {
        gateway,
        chain,
        bus,
        config,
        policy,
    }
}

fn ok_embed_response(values: &[f32]) -> HttpResponse {
    HttpResponse {
        status: 200,
        headers: vec![],
        body: serde_json::to_vec(&serde_json::json!({ "data": [{ "embedding": values }] }))
            .unwrap(),
    }
}

/// `[openai (first-party), eu (names an embedding model), chat-only (names none)]`.
fn three_clouds() -> Vec<LlmProviderConfig> {
    let mut eu = cloud("eu", "https://eu.openai.example", &[("gpt4o", "gpt-4o-eu")]);
    eu.embedding_model = Some("eu-embed".into());
    vec![
        cloud(
            "openai",
            "https://api.openai.com",
            &[("gpt4o", "gpt-4o-2024-08-06")],
        ),
        eu,
        cloud(
            "chat-only",
            "https://chat-only.example",
            &[("fast", "fast-chat")],
        ),
    ]
}

fn route(provider_id: &str, model: &str) -> crate::EmbeddingRoute {
    crate::EmbeddingRoute {
        provider_id: provider_id.into(),
        model: model.into(),
    }
}

/// A request of `agent_id`'s own guest — the only kind that says where an agent chats.
fn own_request(agent_id: &str, model: Option<&str>) -> LlmRequestContext {
    LlmRequestContext {
        agent_id: agent_id.into(),
        caller: crate::gateway::Caller::AgentGuest,
        ..ctx(model)
    }
}

/// Have `agent_id`'s own guest send one request naming `model`; the scripted reply is
/// served by whichever entry placement picks. Returns the URL it went to.
async fn serve_own_request(rig: &EmbedRig, agent_id: &str, model: Option<&str>) -> String {
    rig.chain
        .push_response("/v1/chat/completions", Ok(ok_chat_response("served")));
    rig.gateway
        .generate(own_request(agent_id, model))
        .await
        .expect("the agent's own request is served");
    urls(&rig.chain)
        .pop()
        .expect("one request left the gateway")
}

const NOT_SERVED_YET: Result<crate::EmbeddingRoute, crate::EmbeddingUnavailable> =
    Err(crate::EmbeddingUnavailable::ChatProviderUnknown);

/// Each agent's text is embedded by the provider THAT agent chats with, with that
/// provider's embedding model — and the events name the agent the text belongs to. Two
/// agents on two providers never share an embedding endpoint.
#[tokio::test]
async fn each_agent_embeds_on_its_own_chat_provider() {
    let rig = embed_rig(three_clouds());
    rig.policy.set("researcher", pin("eu"));
    // `root` has no policy, so any of the three entries may serve it: the one it chats
    // with is the one that served its own request (here the head entry).
    assert_eq!(rig.gateway.embedding_route_for("root"), NOT_SERVED_YET);
    assert_eq!(
        serve_own_request(&rig, "root", Some("gpt4o")).await,
        "https://api.openai.com/v1/chat/completions"
    );
    assert_eq!(
        rig.gateway.embedding_route_for("root"),
        Ok(route("openai", "text-embedding-3-small"))
    );
    // A pinned agent's entry is known from its policy alone.
    assert_eq!(
        rig.gateway.embedding_route_for("researcher"),
        Ok(route("eu", "eu-embed"))
    );
    let (chat_requests, chat_events) = (urls(&rig.chain).len(), rig.bus.snapshot().len());

    rig.chain
        .push_response("/v1/embeddings", Ok(ok_embed_response(&[0.25, 0.5])));
    let pinned = rig
        .gateway
        .embed_for_agent("researcher", "researcher text")
        .await
        .expect("embed")
        .expect("eu embeds");
    assert_eq!(pinned.vector, vec![0.25, 0.5]);
    assert_eq!(pinned.provider_id, "eu");
    assert_eq!(pinned.model, "eu-embed");

    let head = rig
        .gateway
        .embed_for_agent("root", "root text")
        .await
        .expect("embed")
        .expect("openai embeds");
    assert_eq!(head.provider_id, "openai");
    assert_eq!(head.model, "text-embedding-3-small");

    {
        let log = rig.chain.call_log.lock().unwrap();
        let log = &log[chat_requests..];
        assert_eq!(log.len(), 2);
        assert_eq!(log[0].url, "https://eu.openai.example/v1/embeddings");
        let body: serde_json::Value = serde_json::from_slice(&log[0].body).unwrap();
        assert_eq!(body["model"], "eu-embed");
        assert_eq!(body["input"], "researcher text");
        assert!(log[0]
            .headers
            .iter()
            .any(|(n, v)| n == "Authorization" && v == "Bearer {eu-api-key}"));
        assert_eq!(log[1].url, "https://api.openai.com/v1/embeddings");
        let body: serde_json::Value = serde_json::from_slice(&log[1].body).unwrap();
        assert_eq!(body["model"], "text-embedding-3-small");
        assert_eq!(body["input"], "root text");
    }

    let events = rig.bus.snapshot().split_off(chat_events);
    let summary: Vec<(&str, &str, &str)> = events
        .iter()
        .map(|e| {
            (
                e.event_type.as_str(),
                e.agent_id.as_str(),
                e.payload["model"].as_str().unwrap_or_default(),
            )
        })
        .collect();
    assert_eq!(
        summary,
        vec![
            (LLM_REQUEST, "researcher", "eu-embed"),
            (LLM_RESPONSE, "researcher", "eu-embed"),
            (LLM_REQUEST, "root", "text-embedding-3-small"),
            (LLM_RESPONSE, "root", "text-embedding-3-small"),
        ]
    );
    assert_eq!(events[0].payload["provider_id"], "eu");
    assert_eq!(events[0].payload["policy_source"], "agent");
    assert_eq!(events[1].payload["provider"], "eu");
    assert_eq!(events[2].payload["provider_id"], "openai");
    assert_eq!(events[2].payload["policy_source"], "default");
    assert_eq!(events[3].payload["provider"], "openai");
    // The request says how its entry is known, and names the embedding model it carries.
    assert_eq!(events[0].payload["placement_reason"], "follows-chat:policy");
    assert_eq!(events[0].payload["model_revision"], "eu-embed");
    assert_eq!(events[2].payload["placement_reason"], "follows-chat:served");
    assert_eq!(
        events[2].payload["model_revision"],
        "text-embedding-3-small"
    );
}

/// An agent whose policy admits several entries has no entry to follow until one of them
/// has served a request of its OWN. Until then nothing is sent on its behalf — no
/// embedding, no host-side call — and a request the host makes under its own name, a
/// provider check, or a call made for another agent tells nothing about where it chats.
#[tokio::test]
async fn an_unpinned_agent_is_followed_only_once_its_own_request_was_served() {
    use futures::StreamExt;

    let EmbedRig {
        gateway,
        chain,
        bus,
        policy,
        config,
    } = embed_rig(three_clouds());
    let gateway = Arc::new(gateway);
    let rig = EmbedRigRef {
        gateway: &gateway,
        chain: &chain,
    };
    assert_eq!(gateway.embedding_route_for("writer"), NOT_SERVED_YET);
    assert_eq!(gateway.embed_for_agent("writer", "private").await, Ok(None));
    let as_writer = gateway.for_agent("writer");
    let not_served = LlmError::ModelNotAvailable(
        "agent writer: none of the providers open to this agent has served it yet".into(),
    );
    assert_eq!(
        as_writer
            .chat(vec![user("private")], ChatParams::default())
            .await
            .map(|reply| reply.text),
        Err(not_served.clone())
    );
    assert_eq!(
        as_writer
            .stream(vec![user("private")], ChatParams::default())
            .await
            .err(),
        Some(not_served.clone())
    );
    assert_eq!(
        as_writer.embed("private").await,
        Err(LlmError::ModelNotAvailable(
            "embedding unavailable: none of the providers open to this agent has served it yet"
                .into()
        ))
    );
    assert!(urls(&chain).is_empty(), "nothing may leave the gateway");
    assert!(bus.snapshot().is_empty(), "no event without a request");

    // The host's own surface, in the writer's name or not, is placed like any request and
    // is not where the writer chats; neither is another agent's own request.
    chain.push_response("/v1/chat/completions", Ok(ok_chat_response("host")));
    gateway
        .generate(LlmRequestContext {
            agent_id: "writer".into(),
            ..ctx(Some("gpt4o"))
        })
        .await
        .expect("a host request in the writer's name");
    chain.push_response("/v1/chat/completions", Ok(ok_chat_response("host")));
    gateway
        .chat(vec![user("hi")], ChatParams::default())
        .await
        .expect("the bare CONTRACT-081 surface");
    rig.serve_own("someone-else", Some("gpt4o")).await;
    assert_eq!(gateway.embedding_route_for("writer"), NOT_SERVED_YET);
    assert_eq!(gateway.embed_for_agent("writer", "private").await, Ok(None));

    // The writer's own request names a model only `eu` and `openai` serve; placement puts
    // it on the head of those. From here on the writer is followed there.
    assert_eq!(
        rig.serve_own("writer", Some("gpt4o")).await,
        "https://api.openai.com/v1/chat/completions"
    );
    assert_eq!(
        gateway.embedding_route_for("writer"),
        Ok(route("openai", "text-embedding-3-small"))
    );
    let before = urls(&chain).len();
    chain.push_response("/v1/chat/completions", Ok(ok_chat_response("extracted")));
    chain.push_response("/v1/chat/completions", Ok(ok_chat_response("streamed")));
    chain.push_response("/v1/embeddings", Ok(ok_embed_response(&[0.5])));
    assert_eq!(
        as_writer
            .chat(vec![user("private")], ChatParams::default())
            .await
            .map(|reply| reply.text),
        Ok("extracted".into())
    );
    let mut stream = as_writer
        .stream(vec![user("private")], ChatParams::default())
        .await
        .expect("stream");
    assert!(stream.next().await.expect("one delta").is_ok());
    assert_eq!(as_writer.embed("private").await, Ok(vec![0.5]));
    assert_eq!(
        urls(&chain)[before..],
        [
            "https://api.openai.com/v1/chat/completions",
            "https://api.openai.com/v1/chat/completions",
            "https://api.openai.com/v1/embeddings",
        ]
    );
    // A call the host made for the writer is not the writer chatting: the entry stays.
    assert_eq!(
        gateway.embedding_route_for("writer"),
        Ok(route("openai", "text-embedding-3-small"))
    );

    // The entry that served the writer leaves the configuration: with two entries left
    // there is again nothing to follow until one of them serves the writer.
    let mut cfg = fixture_runtime_config();
    cfg.llm_providers = three_clouds().split_off(1);
    config.set_config(cfg);
    assert_eq!(gateway.embedding_route_for("writer"), NOT_SERVED_YET);
    assert_eq!(
        as_writer
            .chat(vec![user("private")], ChatParams::default())
            .await
            .map(|reply| reply.text),
        Err(not_served)
    );
    // ... and a policy that now admits a single entry is followed at once.
    policy.set("writer", pin("eu"));
    assert_eq!(
        gateway.embedding_route_for("writer"),
        Ok(route("eu", "eu-embed"))
    );
}

/// The gateway and chain of an [`EmbedRig`] whose gateway moved behind an `Arc`.
struct EmbedRigRef<'a> {
    gateway: &'a LlmGateway,
    chain: &'a MockHttpSecurityChain,
}

impl EmbedRigRef<'_> {
    /// See [`serve_own_request`].
    async fn serve_own(&self, agent_id: &str, model: Option<&str>) -> String {
        self.chain
            .push_response("/v1/chat/completions", Ok(ok_chat_response("served")));
        self.gateway
            .generate(own_request(agent_id, model))
            .await
            .expect("the agent's own request is served");
        urls(self.chain)
            .pop()
            .expect("one request left the gateway")
    }
}

/// The entry is the one the agent's request was REALLY served by, not the one a request
/// naming no model would be placed on: an agent whose guest names a model another entry
/// serves chats there, and its text — embeddings, host-side calls — goes there and to no
/// other entry. When its next request is served elsewhere, everything moves with it.
#[tokio::test]
async fn what_is_sent_for_an_agent_follows_the_entry_that_served_its_own_request() {
    let EmbedRig {
        gateway,
        chain,
        bus,
        ..
    } = embed_rig(three_clouds());
    let gateway = Arc::new(gateway);
    let rig = EmbedRigRef {
        gateway: &gateway,
        chain: &chain,
    };
    // `fast` is served by `chat-only` alone, the LAST entry of the three.
    assert_eq!(
        rig.serve_own("writer", Some("fast")).await,
        "https://chat-only.example/v1/chat/completions"
    );
    assert_eq!(
        gateway.embedding_route_for("writer"),
        Err(crate::EmbeddingUnavailable::ProviderCannotEmbed {
            provider_id: "chat-only".into(),
            reason: crate::EmbeddingIncapable::NoEmbeddingModel,
        }),
        "the entry that serves the writer names no embedding model"
    );
    let before = urls(&chain).len();
    chain.push_response("/v1/embeddings", Ok(ok_embed_response(&[9.0])));
    assert_eq!(gateway.embed_for_agent("writer", "private").await, Ok(None));
    // A host-side call for the writer that names no model is sent with the model the
    // writer's own request named — to the entry that served it.
    chain.push_response("/v1/chat/completions", Ok(ok_chat_response("extracted")));
    let as_writer = gateway.for_agent("writer");
    as_writer
        .chat(vec![user("private")], ChatParams::default())
        .await
        .expect("served on the writer's entry");
    {
        let log = chain.call_log.lock().unwrap();
        let log = &log[before..];
        assert_eq!(log.len(), 1, "the embedding was sent nowhere");
        assert_eq!(log[0].url, "https://chat-only.example/v1/chat/completions");
        let body: serde_json::Value = serde_json::from_slice(&log[0].body).unwrap();
        assert_eq!(body["model"], "fast-chat");
    }
    // A model the call itself names wins over the one the writer named — and is still
    // confined to the writer's entry: naming a model other entries serve is not a way out
    // of it (the name goes to the writer's entry as written).
    chain.push_response("/v1/chat/completions", Ok(ok_chat_response("extracted")));
    as_writer
        .chat(
            vec![user("private")],
            ChatParams {
                model: Some("gpt4o".into()),
                ..Default::default()
            },
        )
        .await
        .expect("served on the writer's entry");
    {
        let log = chain.call_log.lock().unwrap();
        let log = &log[before..];
        assert_eq!(log.len(), 2);
        assert_eq!(log[1].url, "https://chat-only.example/v1/chat/completions");
        let body: serde_json::Value = serde_json::from_slice(&log[1].body).unwrap();
        assert_eq!(body["model"], "gpt4o");
    }

    // The writer's next request names a model `openai` serves: everything follows.
    assert_eq!(
        rig.serve_own("writer", Some("gpt4o")).await,
        "https://api.openai.com/v1/chat/completions"
    );
    assert_eq!(
        gateway.embedding_route_for("writer"),
        Ok(route("openai", "text-embedding-3-small"))
    );
    let before = urls(&chain).len();
    chain.push_response("/v1/embeddings", Ok(ok_embed_response(&[0.5, 0.25])));
    chain.push_response("/v1/chat/completions", Ok(ok_chat_response("extracted")));
    let embedded = gateway
        .embed_for_agent("writer", "private")
        .await
        .expect("embed")
        .expect("openai embeds");
    assert_eq!(embedded.provider_id, "openai");
    as_writer
        .chat(vec![user("private")], ChatParams::default())
        .await
        .expect("served on the writer's entry");
    {
        let log = chain.call_log.lock().unwrap();
        let log = &log[before..];
        assert_eq!(log[0].url, "https://api.openai.com/v1/embeddings");
        assert_eq!(log[1].url, "https://api.openai.com/v1/chat/completions");
        let body: serde_json::Value = serde_json::from_slice(&log[1].body).unwrap();
        assert_eq!(body["model"], "gpt-4o-2024-08-06");
    }
    assert!(
        urls(&chain)
            .iter()
            .all(|url| !url.starts_with("https://eu.openai.example")),
        "the entry that never served the writer received nothing"
    );
    // Every request made for the writer is reported as the writer's.
    assert!(requests(&bus).iter().all(|e| e.agent_id == "writer"));
}

/// A host-side call that names no model is sent with the model the owner configured —
/// the agent's policy model, else the entry's default — and never with a model the
/// agent's guest named in a request of its own: no run budget covers a host-side call, so
/// the guest must not be able to choose what it costs.
#[tokio::test]
async fn a_call_made_for_an_agent_is_never_sent_with_a_model_its_guest_chose() {
    let EmbedRig {
        gateway,
        chain,
        policy,
        ..
    } = embed_rig(two_clouds());
    let gateway = Arc::new(gateway);
    let rig = EmbedRigRef {
        gateway: &gateway,
        chain: &chain,
    };
    // `openai` serves `gpt4o` (its default: the first alias) and `mini`.
    let pinned_with = |model: Option<&str>| AgentLlmPolicy {
        provider: Some("openai".into()),
        model: model.map(str::to_string),
        ..Default::default()
    };
    policy.set("writer", pinned_with(Some("mini")));
    let as_writer = gateway.for_agent("writer");
    let sent_model = |index: usize| -> String {
        let log = chain.call_log.lock().unwrap();
        let body: serde_json::Value = serde_json::from_slice(&log[index].body).unwrap();
        body["model"].as_str().unwrap_or_default().to_string()
    };
    let host_side_call = || async {
        chain.push_response("/v1/chat/completions", Ok(ok_chat_response("extracted")));
        as_writer
            .chat(vec![user("private")], ChatParams::default())
            .await
            .expect("served on the writer's entry");
        sent_model(urls(&chain).len() - 1)
    };

    // Nothing served yet: the pinned entry is known from the policy, whose model applies.
    assert_eq!(host_side_call().await, "gpt-4o-mini");
    // The writer's guest names the entry's other model for a request of its own. That
    // request is sent with it; a call the host makes for the writer still is not.
    rig.serve_own("writer", Some("gpt4o")).await;
    assert_eq!(sent_model(urls(&chain).len() - 1), "gpt-4o-2024-08-06");
    assert_eq!(host_side_call().await, "gpt-4o-mini");
    // Nor with a name no entry lists, which its own request is sent with as it stands.
    rig.serve_own("writer", Some("some-costly-model")).await;
    assert_eq!(sent_model(urls(&chain).len() - 1), "some-costly-model");
    assert_eq!(host_side_call().await, "gpt-4o-mini");
    // A policy that names no model leaves the entry's default, whatever the guest named.
    policy.set("writer", pinned_with(None));
    rig.serve_own("writer", Some("mini")).await;
    assert_eq!(sent_model(urls(&chain).len() - 1), "gpt-4o-mini");
    assert_eq!(host_side_call().await, "gpt-4o-2024-08-06");
    // A model the host itself names is the one sent.
    chain.push_response("/v1/chat/completions", Ok(ok_chat_response("extracted")));
    as_writer
        .chat(
            vec![user("private")],
            ChatParams {
                model: Some("mini".into()),
                ..Default::default()
            },
        )
        .await
        .expect("served on the writer's entry");
    assert_eq!(sent_model(urls(&chain).len() - 1), "gpt-4o-mini");
    // After a re-pin the other entry's default applies.
    policy.set("writer", pin("openai-eu"));
    assert_eq!(host_side_call().await, "gpt-4o-eu");
    assert_eq!(
        urls(&chain).last().map(String::as_str),
        Some("https://eu.openai.example/v1/chat/completions")
    );
}

/// An agent free to chat on several entries chats on the one its own last request
/// reached, and its guest may name a model of another entry than the one its policy's
/// model is on. A call made for it then gets the default of the entry it chats on —
/// not the policy's model, which that entry does not serve and would refuse. Where the
/// entry does serve the policy's model, the policy's model is sent.
#[tokio::test]
async fn a_call_made_for_an_agent_gets_a_model_its_chat_entry_serves() {
    // An entry that lists no models takes any name as it stands; first, so a request
    // naming a model no entry lists is placed on it. The policy's model is on
    // `chat-only`, whose default (its first alias by name) is another model.
    let mut providers = vec![cloud("plain", "https://plain.example", &[])];
    providers.extend(three_clouds());
    providers[3] = cloud(
        "chat-only",
        "https://chat-only.example",
        &[("a-cheap", "cheap-chat"), ("fast", "fast-chat")],
    );
    let EmbedRig {
        gateway,
        chain,
        policy,
        ..
    } = embed_rig(providers);
    let gateway = Arc::new(gateway);
    let rig = EmbedRigRef {
        gateway: &gateway,
        chain: &chain,
    };
    // No pin: every entry is admitted. The policy's model is on `chat-only`.
    policy.set(
        "writer",
        AgentLlmPolicy {
            model: Some("fast".into()),
            ..Default::default()
        },
    );
    let as_writer = gateway.for_agent("writer");
    let last_request = || -> (String, String) {
        let log = chain.call_log.lock().unwrap();
        let sent = log.last().expect("a request left the gateway");
        let body: serde_json::Value = serde_json::from_slice(&sent.body).unwrap();
        (
            sent.url.clone(),
            body["model"].as_str().unwrap_or_default().to_string(),
        )
    };
    let host_side_call = || async {
        chain.push_response("/v1/chat/completions", Ok(ok_chat_response("extracted")));
        as_writer
            .chat(vec![user("private")], ChatParams::default())
            .await
            .expect("served on the writer's entry");
        last_request()
    };

    // The guest names `openai`'s model: the writer chats on `openai`, which lists models
    // but not `fast`.
    rig.serve_own("writer", Some("gpt4o")).await;
    assert_eq!(
        host_side_call().await,
        (
            "https://api.openai.com/v1/chat/completions".to_string(),
            "gpt-4o-2024-08-06".to_string()
        )
    );
    // A request of its own that names no model gets the policy's model, on the entry
    // that serves it: a call made for it follows, with that model — not the entry's
    // default.
    rig.serve_own("writer", None).await;
    assert_eq!(
        last_request(),
        (
            "https://chat-only.example/v1/chat/completions".to_string(),
            "fast-chat".to_string()
        )
    );
    assert_eq!(
        host_side_call().await,
        (
            "https://chat-only.example/v1/chat/completions".to_string(),
            "fast-chat".to_string()
        )
    );
    // The guest names a model no entry lists: it is placed on `plain`, which lists none.
    // There the policy's model goes as it stands, like any request placed on it.
    rig.serve_own("writer", Some("unlisted")).await;
    assert_eq!(
        last_request(),
        (
            "https://plain.example/v1/chat/completions".to_string(),
            "unlisted".to_string()
        )
    );
    assert_eq!(
        host_side_call().await,
        (
            "https://plain.example/v1/chat/completions".to_string(),
            "fast".to_string()
        )
    );
}

/// A policy's model that no entry lists: a request of the agent's own naming it is placed
/// on the first entry it may chat on, which is sent the name as it stands. A call made for
/// the agent on that entry gets the policy's model the same way — not the entry's default
/// — and on any other entry it chats on, that entry's default.
#[tokio::test]
async fn a_call_made_for_an_agent_gets_the_policys_model_where_its_own_requests_do() {
    let EmbedRig {
        gateway,
        chain,
        policy,
        ..
    } = embed_rig(three_clouds());
    let gateway = Arc::new(gateway);
    let rig = EmbedRigRef {
        gateway: &gateway,
        chain: &chain,
    };
    policy.set(
        "writer",
        AgentLlmPolicy {
            model: Some("house-model".into()),
            ..Default::default()
        },
    );
    let as_writer = gateway.for_agent("writer");
    let last_request = || -> (String, String) {
        let log = chain.call_log.lock().unwrap();
        let sent = log.last().expect("a request left the gateway");
        let body: serde_json::Value = serde_json::from_slice(&sent.body).unwrap();
        (
            sent.url.clone(),
            body["model"].as_str().unwrap_or_default().to_string(),
        )
    };
    let host_side_call = || async {
        chain.push_response("/v1/chat/completions", Ok(ok_chat_response("extracted")));
        as_writer
            .chat(vec![user("private")], ChatParams::default())
            .await
            .expect("served on the writer's entry");
        last_request()
    };

    // Its own request that names no model: the policy's model, on the first entry.
    rig.serve_own("writer", None).await;
    let on_openai = (
        "https://api.openai.com/v1/chat/completions".to_string(),
        "house-model".to_string(),
    );
    assert_eq!(last_request(), on_openai);
    assert_eq!(host_side_call().await, on_openai);
    // Its guest names `chat-only`'s model: there a request naming the policy's model
    // would not go, so the entry's default is sent.
    rig.serve_own("writer", Some("fast")).await;
    assert_eq!(
        host_side_call().await,
        (
            "https://chat-only.example/v1/chat/completions".to_string(),
            "fast-chat".to_string()
        )
    );
}

/// The first entry takes a request naming a model NO entry lists — not one naming a model
/// another entry lists. An agent whose guest names the first entry's model, while its
/// policy's model is another entry's, chats on the first entry: a call made for it gets
/// that entry's default, since a request of its own naming the policy's model would go to
/// the other entry.
#[tokio::test]
async fn a_call_made_for_an_agent_on_the_first_entry_gets_its_default_if_another_serves_the_policys_model(
) {
    let EmbedRig {
        gateway,
        chain,
        policy,
        ..
    } = embed_rig(three_clouds());
    let gateway = Arc::new(gateway);
    let rig = EmbedRigRef {
        gateway: &gateway,
        chain: &chain,
    };
    // The policy's model is on `chat-only`, the last entry.
    policy.set(
        "writer",
        AgentLlmPolicy {
            model: Some("fast".into()),
            ..Default::default()
        },
    );
    // Its guest names `openai`'s model: the writer chats on `openai`, the first entry.
    assert_eq!(
        rig.serve_own("writer", Some("gpt4o")).await,
        "https://api.openai.com/v1/chat/completions"
    );
    chain.push_response("/v1/chat/completions", Ok(ok_chat_response("extracted")));
    gateway
        .for_agent("writer")
        .chat(vec![user("private")], ChatParams::default())
        .await
        .expect("served on the writer's entry");
    let log = chain.call_log.lock().unwrap();
    let sent = log.last().expect("a request left the gateway");
    let body: serde_json::Value = serde_json::from_slice(&sent.body).unwrap();
    assert_eq!(sent.url, "https://api.openai.com/v1/chat/completions");
    assert_eq!(body["model"], "gpt-4o-2024-08-06");
}

/// The same holds on the two streaming paths: the entry a stream of the agent's own
/// guest was opened on is the entry the agent chats on.
#[tokio::test]
async fn a_stream_of_the_agents_own_guest_says_where_it_chats() {
    // The buffered path.
    let rig = embed_rig(three_clouds());
    rig.chain
        .push_response("/v1/chat/completions", Ok(ok_chat_response("buffered")));
    rig.gateway
        .stream_begin(own_request("writer", Some("fast")))
        .await
        .expect("buffered stream");
    assert_eq!(
        rig.gateway.embedding_route_for("writer"),
        Err(crate::EmbeddingUnavailable::ProviderCannotEmbed {
            provider_id: "chat-only".into(),
            reason: crate::EmbeddingIncapable::NoEmbeddingModel,
        })
    );
    // A host request on the same path leaves the record alone.
    rig.chain
        .push_response("/v1/chat/completions", Ok(ok_chat_response("buffered")));
    rig.gateway
        .stream_begin(LlmRequestContext {
            agent_id: "writer".into(),
            ..ctx(Some("gpt4o"))
        })
        .await
        .expect("buffered stream");
    assert!(matches!(
        rig.gateway.embedding_route_for("writer"),
        Err(crate::EmbeddingUnavailable::ProviderCannotEmbed { .. })
    ));

    // The live path: the entry is known once the stream has ended well, as on the
    // buffered paths — so what the end of the turn sends for the agent finds it ...
    let live = harness(three_clouds(), None);
    assert_eq!(live.gateway.embedding_route_for("writer"), NOT_SERVED_YET);
    live.chain.push_stream(
        "/v1/chat/completions",
        200,
        vec![Ok(sse_delta("hi")), Ok(b"data: [DONE]\n\n".to_vec())],
    );
    let registry = Arc::new(StreamRegistry::new());
    let handle = live
        .gateway
        .stream_begin_live(own_request("writer", Some("gpt4o")), &registry)
        .await
        .expect("live stream");
    let end = read_to_the_end(&registry, handle, "writer").await;
    assert!(matches!(end, PollOutcome::Done(_)), "the stream ends well");
    assert_eq!(
        live.gateway.embedding_route_for("writer"),
        Ok(route("openai", "text-embedding-3-small"))
    );

    // ... and not while the stream is open, when it may still fail.
    let open = harness(three_clouds(), None);
    open.chain
        .push_stalled_stream("/v1/chat/completions", 200, vec![Ok(sse_delta("hi"))]);
    let registry = Arc::new(StreamRegistry::new());
    open.gateway
        .stream_begin_live(own_request("writer", Some("gpt4o")), &registry)
        .await
        .expect("live stream");
    assert_eq!(open.gateway.embedding_route_for("writer"), NOT_SERVED_YET);
}

fn sse_delta(text: &str) -> Vec<u8> {
    format!("data: {{\"choices\":[{{\"delta\":{{\"content\":\"{text}\"}}}}]}}\n\n").into_bytes()
}

/// Read a live stream of `agent_id` to its end: the terminal outcome.
async fn read_to_the_end(registry: &StreamRegistry, handle: u64, agent_id: &str) -> PollOutcome {
    loop {
        let next = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            registry.poll_live(handle, agent_id),
        )
        .await
        .expect("the stream ends");
        if !matches!(next, PollOutcome::Delta(_)) {
            return next;
        }
    }
}

/// Only a request that was SERVED says where the agent chats. One that fails — on every
/// entry it is tried on, before a stream opens, or while a stream is read — changes
/// nothing: nothing is known when nothing was, and the entry that served the agent
/// before stays the one it chats on.
#[tokio::test]
async fn a_request_that_fails_says_nothing_about_where_the_agent_chats() {
    let too_long = || {
        Ok(HttpResponse {
            status: 400,
            headers: vec![],
            body: br#"{"error":{"type":"context_length_exceeded","message":"too long"}}"#.to_vec(),
        })
    };

    // The buffered paths, with nothing known before.
    let rig = embed_rig(three_clouds());
    rig.chain.push_response("/v1/chat/completions", too_long());
    let err = rig
        .gateway
        .generate(own_request("writer", Some("gpt4o")))
        .await
        .expect_err("every entry refuses");
    assert!(matches!(err, LlmError::ContextTooLong(_)), "{err:?}");
    assert!(rig
        .gateway
        .stream_begin(own_request("writer", Some("gpt4o")))
        .await
        .is_err());
    assert!(!urls(&rig.chain).is_empty(), "the requests did leave");
    assert_eq!(rig.gateway.embedding_route_for("writer"), NOT_SERVED_YET);

    // With an entry known: `chat-only` served the writer, then a request fails elsewhere.
    let rig = embed_rig(three_clouds());
    serve_own_request(&rig, "writer", Some("fast")).await;
    let on_chat_only = Err(crate::EmbeddingUnavailable::ProviderCannotEmbed {
        provider_id: "chat-only".into(),
        reason: crate::EmbeddingIncapable::NoEmbeddingModel,
    });
    assert_eq!(rig.gateway.embedding_route_for("writer"), on_chat_only);
    rig.chain.push_response("/v1/chat/completions", too_long());
    rig.gateway
        .generate(own_request("writer", Some("gpt4o")))
        .await
        .expect_err("refused");
    assert_eq!(rig.gateway.embedding_route_for("writer"), on_chat_only);

    // The live path: a head that is refused ...
    let refused = harness(three_clouds(), None);
    refused.chain.push_stream(
        "/v1/chat/completions",
        500,
        vec![Ok(br#"{"error":{"message":"down"}}"#.to_vec())],
    );
    let registry = Arc::new(StreamRegistry::new());
    assert!(refused
        .gateway
        .stream_begin_live(own_request("writer", Some("gpt4o")), &registry)
        .await
        .is_err());
    assert_eq!(
        refused.gateway.embedding_route_for("writer"),
        NOT_SERVED_YET
    );

    // ... and a stream that opens and then breaks while it is read.
    let broken = harness(three_clouds(), None);
    broken.chain.push_stream(
        "/v1/chat/completions",
        200,
        vec![
            Ok(sse_delta("hi")),
            Err(
                advance_shared_types::security_validator::HttpError::Transport(
                    advance_shared_types::security_validator::TransportErrorKind::Other,
                ),
            ),
        ],
    );
    let registry = Arc::new(StreamRegistry::new());
    let handle = broken
        .gateway
        .stream_begin_live(own_request("writer", Some("gpt4o")), &registry)
        .await
        .expect("the stream opens");
    let end = read_to_the_end(&registry, handle, "writer").await;
    assert!(
        matches!(end, PollOutcome::Failed(_)),
        "the stream ends with an error"
    );
    assert_eq!(broken.gateway.embedding_route_for("writer"), NOT_SERVED_YET);
}

/// A call the host makes for an agent stays on the agent's chat entry also when it fails
/// in a way that makes an agent's own request try another entry: the other entries its
/// policy admits receive nothing.
#[tokio::test]
async fn a_failed_call_made_for_an_agent_is_not_tried_on_another_entry() {
    let EmbedRig { gateway, chain, .. } = embed_rig(three_clouds());
    let gateway = Arc::new(gateway);
    let rig = EmbedRigRef {
        gateway: &gateway,
        chain: &chain,
    };
    // The writer may chat on all three entries; its own request was served by `eu`'s
    // neighbour `openai`, which also serves `gpt4o`.
    assert_eq!(
        rig.serve_own("writer", Some("gpt4o")).await,
        "https://api.openai.com/v1/chat/completions"
    );
    chain.push_response(
        "/v1/chat/completions",
        Ok(HttpResponse {
            status: 400,
            headers: vec![],
            body: br#"{"error":{"type":"context_length_exceeded","message":"too long"}}"#.to_vec(),
        }),
    );
    let before = urls(&chain).len();

    let err = gateway
        .for_agent("writer")
        .chat(vec![user("private")], ChatParams::default())
        .await
        .map(|reply| reply.text)
        .expect_err("the writer's entry refuses");

    assert!(matches!(err, LlmError::ContextTooLong(_)), "{err:?}");
    let sent = urls(&chain)[before..].to_vec();
    assert!(!sent.is_empty(), "the call did leave");
    assert!(
        sent.iter()
            .all(|url| url == "https://api.openai.com/v1/chat/completions"),
        "only the writer's entry may receive the call: {sent:?}"
    );
}

/// An agent whose chat provider serves no embeddings has NO embedding. Nothing is sent —
/// in particular not to the other configured entries that could embed — and no `llm.*`
/// event is emitted.
#[tokio::test]
async fn an_agent_on_a_provider_that_cannot_embed_sends_its_text_nowhere() {
    let rig = embed_rig(three_clouds());
    rig.policy.set("writer", pin("chat-only"));
    rig.chain
        .push_response("/v1/embeddings", Ok(ok_embed_response(&[9.0])));

    assert_eq!(
        rig.gateway.embedding_route_for("writer"),
        Err(crate::EmbeddingUnavailable::ProviderCannotEmbed {
            provider_id: "chat-only".into(),
            reason: crate::EmbeddingIncapable::NoEmbeddingModel,
        })
    );
    assert_eq!(
        rig.gateway.embed_for_agent("writer", "private text").await,
        Ok(None)
    );
    assert!(urls(&rig.chain).is_empty(), "nothing may leave the gateway");
    assert!(rig.bus.snapshot().is_empty(), "no event without a request");
    assert_eq!(
        LlmError::from(rig.gateway.embedding_route_for("writer").unwrap_err()),
        LlmError::ModelNotAvailable(
            "embedding unavailable: chat provider chat-only has no embedding-model configured"
                .into()
        )
    );
}

/// A pin to an entry that is not configured leaves the agent without a chat provider, so
/// without an embedding: the gateway never falls back to the head entry.
#[tokio::test]
async fn a_pin_to_an_unconfigured_provider_has_no_embedding_route() {
    let rig = embed_rig(three_clouds());
    rig.policy.set("writer", pin("gone"));
    assert_eq!(
        rig.gateway.embedding_route_for("writer"),
        Err(crate::EmbeddingUnavailable::NoChatProvider(
            LlmError::ModelNotAvailable("provider gone not configured for agent writer".into())
        ))
    );
    assert_eq!(
        rig.gateway.embed_for_agent("writer", "text").await,
        Ok(None)
    );
    assert!(urls(&rig.chain).is_empty());
    assert!(rig.bus.snapshot().is_empty());
}

/// The route follows the agent's WHOLE chat policy, not only a pin. A hard constraint that
/// leaves one entry names it; a default model does not — the agent's guest may name another
/// model on any request — so such an agent is followed to the entry that served it.
#[tokio::test]
async fn the_route_honors_the_agents_constraint_and_default_model() {
    let mut on_device = local("on-device", "llama");
    on_device.embedding_model = Some("nomic-embed".into());
    let mut on_phone = local("on-phone", "llama");
    on_phone.embedding_model = Some("phone-embed".into());
    on_phone.device_id = Some("phone".into());
    let mut providers = three_clouds();
    providers.push(on_device);
    let rig = embed_rig(providers.clone());

    // always-local: the agent's chat can only be placed on the one local entry.
    rig.policy.set(
        "private",
        AgentLlmPolicy {
            constraint: Some(UserHardConstraint::AlwaysLocal),
            ..Default::default()
        },
    );
    assert_eq!(
        rig.gateway.embedding_route_for("private"),
        Ok(route("on-device", "nomic-embed"))
    );
    // never-cloud leaves the same single entry.
    rig.policy.set(
        "offline",
        AgentLlmPolicy {
            constraint: Some(UserHardConstraint::NeverCloud),
            ..Default::default()
        },
    );
    assert_eq!(
        rig.gateway.embedding_route_for("offline"),
        Ok(route("on-device", "nomic-embed"))
    );
    assert!(
        urls(&rig.chain).is_empty(),
        "resolving a route sends nothing"
    );

    // A default model only `chat-only` serves: the policy admits all four entries, so the
    // agent is followed once its own request — which names no model — was served there.
    rig.policy.set(
        "quick",
        AgentLlmPolicy {
            model: Some("fast".into()),
            ..Default::default()
        },
    );
    assert_eq!(rig.gateway.embedding_route_for("quick"), NOT_SERVED_YET);
    assert_eq!(
        serve_own_request(&rig, "quick", None).await,
        "https://chat-only.example/v1/chat/completions"
    );
    assert_eq!(
        rig.gateway.embedding_route_for("quick"),
        Err(crate::EmbeddingUnavailable::ProviderCannotEmbed {
            provider_id: "chat-only".into(),
            reason: crate::EmbeddingIncapable::NoEmbeddingModel,
        })
    );
    // The policy changes under an agent that was served: a constraint its entry does not
    // satisfy moves it, at once, to the one entry the new policy admits.
    rig.policy.set(
        "quick",
        AgentLlmPolicy {
            constraint: Some(UserHardConstraint::AlwaysLocal),
            ..Default::default()
        },
    );
    assert_eq!(
        rig.gateway.embedding_route_for("quick"),
        Ok(route("on-device", "nomic-embed"))
    );

    // A device pin: an entry declaring another device is out, one declaring that device is
    // in, and one declaring none may turn out to run there. With the declared entry alone
    // matching, that is the agent's entry.
    let pin_to = |device: &str| AgentLlmPolicy {
        constraint: Some(UserHardConstraint::DevicePin(device.into())),
        ..Default::default()
    };
    let mut declared = three_clouds();
    for (index, entry) in declared.iter_mut().enumerate() {
        entry.device_id = Some(format!("server-{index}"));
    }
    declared.push(on_phone);
    let pinned = embed_rig(declared);
    pinned.policy.set("on-the-phone", pin_to("phone"));
    assert_eq!(
        pinned.gateway.embedding_route_for("on-the-phone"),
        Ok(route("on-phone", "phone-embed"))
    );
    // A device no entry declares: no chat provider, no embedding.
    pinned.policy.set("nowhere", pin_to("no-such-device"));
    assert_eq!(
        pinned.gateway.embedding_route_for("nowhere"),
        Err(crate::EmbeddingUnavailable::NoChatProvider(
            LlmError::ModelNotAvailable("no endpoints after constraints".into())
        ))
    );
    // Entries that declare no device may each be the one: nothing to follow, nothing sent.
    rig.policy.set("pinned-device", pin_to("no-such-device"));
    assert_eq!(
        rig.gateway.embedding_route_for("pinned-device"),
        NOT_SERVED_YET
    );
    assert_eq!(
        rig.gateway.embed_for_agent("pinned-device", "text").await,
        Ok(None)
    );
    // ... and a single such entry is the agent's chat entry, which placement refuses
    // while the device is not the one it runs on: nothing is sent, and the reason
    // names the entry.
    let alone = embed_rig(vec![providers[1].clone()]);
    alone.policy.set("pinned-device", pin_to("no-such-device"));
    let lone_entry = providers[1].id.clone();
    assert_eq!(
        alone.gateway.embedding_route_for("pinned-device"),
        Err(crate::EmbeddingUnavailable::ChatProviderNotUsable {
            provider_id: lone_entry.clone(),
        })
    );
    assert_eq!(
        alone.gateway.embed_for_agent("pinned-device", "text").await,
        Ok(None)
    );
    assert_eq!(
        alone
            .gateway
            .chat_for_agent("pinned-device", vec![user("text")], ChatParams::default())
            .await
            .map(|reply| reply.text),
        Err(LlmError::ModelNotAvailable(format!(
            "agent pinned-device: chat provider {lone_entry} is not usable at the moment \
             (not authorized, or not on the device this agent is pinned to)"
        )))
    );
    assert!(urls(&pinned.chain).is_empty() && urls(&alone.chain).is_empty());
}

/// The route is resolved on every call from the live config and policy: re-pinning an
/// agent, or configuring an embedding model on its provider, applies to the next request
/// without rebuilding the gateway.
#[tokio::test]
async fn the_route_follows_policy_and_config_changes_at_call_time() {
    let rig = embed_rig(three_clouds());
    rig.policy.set("writer", pin("chat-only"));
    assert!(rig.gateway.embedding_route_for("writer").is_err());

    // The agent is re-pinned to an entry that embeds.
    rig.policy.set("writer", pin("eu"));
    assert_eq!(
        rig.gateway.embedding_route_for("writer"),
        Ok(route("eu", "eu-embed"))
    );

    // Back on `chat-only`; then that entry gets an embedding model.
    rig.policy.set("writer", pin("chat-only"));
    assert!(rig.gateway.embedding_route_for("writer").is_err());
    let mut cfg = fixture_runtime_config();
    let mut providers = three_clouds();
    providers[2].embedding_model = Some("chat-only-embed".into());
    cfg.llm_providers = providers;
    rig.config.set_config(cfg);
    assert_eq!(
        rig.gateway.embedding_route_for("writer"),
        Ok(route("chat-only", "chat-only-embed"))
    );
    rig.chain
        .push_response("/v1/embeddings", Ok(ok_embed_response(&[1.0])));
    let embedded = rig
        .gateway
        .embed_for_agent("writer", "text")
        .await
        .expect("embed")
        .expect("route exists now");
    assert_eq!(embedded.model, "chat-only-embed");
    assert_eq!(
        urls(&rig.chain),
        vec!["https://chat-only.example/v1/embeddings"]
    );
}

/// A failed request to the agent's own provider is an error for that agent — it is never
/// retried on another entry.
#[tokio::test]
async fn a_failed_embedding_is_not_retried_on_another_provider() {
    let rig = embed_rig(three_clouds());
    rig.policy.set("researcher", pin("eu"));
    rig.chain.push_response(
        "/v1/embeddings",
        Ok(HttpResponse {
            status: 400,
            headers: vec![],
            body: br#"{"error":{"type":"context_length_exceeded","message":"too long"}}"#.to_vec(),
        }),
    );
    let err = rig
        .gateway
        .embed_for_agent("researcher", "text")
        .await
        .expect_err("the provider refused");
    assert!(matches!(err, LlmError::ContextTooLong(_)), "{err:?}");
    assert_eq!(
        urls(&rig.chain),
        vec!["https://eu.openai.example/v1/embeddings"],
        "exactly one request, to the agent's own provider"
    );
    let types: Vec<String> = rig
        .bus
        .snapshot()
        .iter()
        .map(|e| e.event_type.clone())
        .collect();
    assert_eq!(types, vec![LLM_REQUEST, crate::LLM_ERROR]);
}

/// A model id is never guessed: without `embedding-model` only OpenAI's own API keeps the
/// first-party default; everywhere else — OpenAI-compatible third parties, look-alike hosts,
/// local entries — the entry has no embedding model. Anthropic and sign-in entries never
/// embed, whatever they name.
#[test]
fn only_openais_own_api_embeds_without_an_explicit_model() {
    use crate::gateway::embedding_model_for;
    use crate::EmbeddingIncapable::{NoEmbeddingModel, NoEmbeddingsApi, SignInEntry};

    let at = |endpoint: &str| cloud("p", endpoint, &[("m", "m")]);
    for endpoint in [
        "https://api.openai.com",
        "https://api.openai.com/",
        "https://api.openai.com/v1",
        "https://API.OPENAI.COM",
        "https://api.openai.com:443",
    ] {
        assert_eq!(
            embedding_model_for(&at(endpoint)).as_deref(),
            Ok("text-embedding-3-small"),
            "{endpoint}"
        );
    }
    for endpoint in [
        "https://api.deepseek.com",
        "https://cloud-api.near.ai",
        "http://api.openai.com",
        "https://api.openai.com:8443",
        "https://api.openai.com.evil.example",
        "https://evil.example/api.openai.com",
        "https://api.openai.com@evil.example",
        "https://user@api.openai.com",
        "https://xapi.openai.com",
        "http://127.0.0.1:11434",
        "not a url",
        "",
    ] {
        assert_eq!(
            embedding_model_for(&at(endpoint)),
            Err(NoEmbeddingModel),
            "{endpoint}"
        );
    }

    // An explicit model is used as written (trimmed) on any OpenAI-compatible entry;
    // a blank one counts as absent.
    let mut third_party = at("https://api.deepseek.com");
    third_party.embedding_model = Some("  their-embed  ".into());
    assert_eq!(
        embedding_model_for(&third_party).as_deref(),
        Ok("their-embed")
    );
    third_party.embedding_model = Some("   ".into());
    assert_eq!(embedding_model_for(&third_party), Err(NoEmbeddingModel));
    let mut first_party = at("https://api.openai.com");
    first_party.embedding_model = Some("text-embedding-3-large".into());
    assert_eq!(
        embedding_model_for(&first_party).as_deref(),
        Ok("text-embedding-3-large")
    );

    // A local entry never gets the cloud default, with or without an endpoint.
    let mut on_device = local("on-device", "llama");
    assert_eq!(embedding_model_for(&on_device), Err(NoEmbeddingModel));
    on_device.endpoint = "https://api.openai.com".into();
    assert_eq!(embedding_model_for(&on_device), Err(NoEmbeddingModel));
    on_device.embedding_model = Some("nomic-embed".into());
    assert_eq!(
        embedding_model_for(&on_device).as_deref(),
        Ok("nomic-embed")
    );

    // Anthropic and a vendor agent CLI have no embeddings endpoint — a configured model
    // changes nothing; a sign-in entry never embeds.
    let mut anthropic = at("https://api.anthropic.com");
    anthropic.backend = Some(ProviderBackend::AnthropicMessages);
    anthropic.embedding_model = Some("voyage-3".into());
    assert_eq!(embedding_model_for(&anthropic), Err(NoEmbeddingsApi));
    let mut vendor_cli = at("");
    vendor_cli.backend_class = InferenceBackendClass::AgentCli;
    assert_eq!(embedding_model_for(&vendor_cli), Err(NoEmbeddingsApi));
    vendor_cli.embedding_model = Some("text-embedding-3-small".into());
    assert_eq!(embedding_model_for(&vendor_cli), Err(NoEmbeddingsApi));
    let mut sign_in = at("https://api.openai.com");
    sign_in.auth_source = advance_runtime::config::ProviderAuthSource::ChatGptOAuth;
    assert_eq!(embedding_model_for(&sign_in), Err(SignInEntry));
}

// ── a host-side call is made as the agent it is for ──────────────────────────────────────────

/// A model call the host makes for an agent ([`LlmGateway::for_agent`]) is placed under
/// THAT agent's policy and reported as its request — chat, stream and embedding alike —
/// while the gateway's own CONTRACT-081 surface stays the default agent's.
#[tokio::test]
async fn a_call_made_for_an_agent_goes_where_that_agent_chats() {
    use futures::StreamExt;

    let EmbedRig {
        gateway,
        chain,
        bus,
        policy,
        ..
    } = embed_rig(three_clouds());
    let gateway = Arc::new(gateway);
    policy.set("researcher", pin("eu"));
    for reply in ["for the researcher", "streamed", "for the root"] {
        chain.push_response("/v1/chat/completions", Ok(ok_chat_response(reply)));
    }
    chain.push_response("/v1/embeddings", Ok(ok_embed_response(&[0.5, 0.25])));

    let as_researcher = gateway.for_agent("researcher");
    assert_eq!(as_researcher.agent_id(), "researcher");
    let reply = as_researcher
        .chat(vec![user("the researcher's turn")], ChatParams::default())
        .await
        .expect("chat");
    assert_eq!(reply.text, "for the researcher");
    let mut stream = as_researcher
        .stream(vec![user("the researcher's turn")], ChatParams::default())
        .await
        .expect("stream");
    assert!(stream.next().await.expect("one delta").is_ok());
    assert_eq!(
        as_researcher.embed("the researcher's text").await,
        Ok(vec![0.5, 0.25])
    );
    let reply = gateway
        .chat(vec![user("the root's turn")], ChatParams::default())
        .await
        .expect("chat");
    assert_eq!(reply.text, "for the root");

    assert_eq!(
        urls(&chain),
        [
            "https://eu.openai.example/v1/chat/completions",
            "https://eu.openai.example/v1/chat/completions",
            "https://eu.openai.example/v1/embeddings",
            "https://api.openai.com/v1/chat/completions",
        ]
    );
    let requests = requests(&bus);
    let summary: Vec<(&str, &str, &str)> = requests
        .iter()
        .map(|e| {
            (
                e.agent_id.as_str(),
                e.payload["provider_id"].as_str().unwrap_or_default(),
                e.payload["policy_source"].as_str().unwrap_or_default(),
            )
        })
        .collect();
    assert_eq!(
        summary,
        vec![
            ("researcher", "eu", "agent"),
            ("researcher", "eu", "agent"),
            ("researcher", "eu", "agent"),
            ("root", "openai", "default"),
        ]
    );
}

/// A call made for an agent whose policy admits no entry fails closed: it is not sent to
/// the entry the default agent — or an agent without a policy — would have reached.
#[tokio::test]
async fn a_call_made_for_an_agent_without_a_provider_is_sent_nowhere() {
    let EmbedRig {
        gateway,
        chain,
        bus,
        policy,
        ..
    } = embed_rig(three_clouds());
    let gateway = Arc::new(gateway);
    policy.set("writer", pin("not-configured"));
    chain.push_response("/v1/chat/completions", Ok(ok_chat_response("never")));
    chain.push_response("/v1/embeddings", Ok(ok_embed_response(&[9.0])));

    let as_writer = gateway.for_agent("writer");
    let refused = LlmError::ModelNotAvailable(
        "provider not-configured not configured for agent writer".into(),
    );
    assert_eq!(
        as_writer
            .chat(vec![user("private")], ChatParams::default())
            .await
            .map(|reply| reply.text),
        Err(refused.clone())
    );
    assert!(matches!(
        as_writer
            .stream(vec![user("private")], ChatParams::default())
            .await,
        Err(LlmError::ModelNotAvailable(_))
    ));
    assert!(matches!(
        as_writer.embed("private").await,
        Err(LlmError::ModelNotAvailable(_))
    ));
    assert!(urls(&chain).is_empty(), "nothing may leave the gateway");
    assert!(bus.snapshot().is_empty(), "no event without a request");
}

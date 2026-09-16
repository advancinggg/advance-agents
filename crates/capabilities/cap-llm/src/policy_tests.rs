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

use crate::gateway::{ChatMessage, ChatParams, ChatRole, LlmGateway, LlmRequestContext};
use crate::placement::{EndpointTelemetry, PlacementTelemetry, UserHardConstraint};
use crate::policy::{AgentLlmPolicy, AgentLlmPolicySource, LlmPolicySource};
use crate::stream::StreamRegistry;
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

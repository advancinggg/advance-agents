use super::*;
use std::collections::HashMap;
use std::sync::atomic::AtomicUsize;
use std::sync::Mutex;

use advance_runtime::config::{InferenceBackendClass, ProviderBackend};
use advance_shared_types::inference::{
    InferenceBackendError, InferenceBackendRegistry, InferenceChatRequest, InferenceChatResponse,
    InferenceEmbedRequest, InferenceEmbedResponse, InferenceMessage, InferenceStream,
    InferenceStreamHead,
};
use async_trait::async_trait;

use crate::events::{LLM_REQUEST, LLM_RESPONSE};
use crate::policy::{AgentLlmPolicy, AgentLlmPolicySource};
use crate::test_support::{
    fixture_runtime_config, no_op_repetition_guard, MockEventBusEmit, MockHttpSecurityChain,
    MockRunBudget, MockRuntimeConfigProvider,
};
use crate::LlmError;

struct RecordingPort {
    calls: AtomicUsize,
    last: Mutex<Option<InferenceChatRequest>>,
}

#[async_trait]
impl InferenceBackendPort for RecordingPort {
    async fn chat(
        &self,
        req: InferenceChatRequest,
    ) -> Result<InferenceChatResponse, InferenceBackendError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        *self.last.lock().unwrap() = Some(req);
        Ok(InferenceChatResponse {
            text: "pong".into(),
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

struct PinCloudX;

impl AgentLlmPolicySource for PinCloudX {
    fn policy_for(&self, agent_id: &str) -> Option<AgentLlmPolicy> {
        if agent_id == "test-agent" {
            Some(AgentLlmPolicy {
                provider: Some("cloud-x".into()),
                ..Default::default()
            })
        } else {
            None
        }
    }
}

fn provider(id: &str, class: InferenceBackendClass) -> LlmProviderConfig {
    let mut aliases = HashMap::new();
    aliases.insert("llama".into(), "llama".into());
    LlmProviderConfig {
        id: id.into(),
        endpoint: if class == InferenceBackendClass::CloudHttp {
            "https://example.invalid".into()
        } else {
            String::new()
        },
        api_key_secret: format!("{id}-api-key"),
        model_aliases: aliases,
        cost_per_mtoken_in: 0.001,
        cost_per_mtoken_out: 0.001,
        cost_per_mtoken_cache_read: None,
        cost_per_mtoken_cache_write: None,
        cost_per_mtoken_cache_write_1h: None,
        rate_limit: None,
        retry_default: None,
        backend: Some(ProviderBackend::OpenAiChat),
        auth_scheme: None,
        backend_class: class,
        embedding_model: None,
        sidecar: None,
        profile_id: None,
        device_id: None,
        agent_cli: None,
        auth_source: advance_runtime::config::ProviderAuthSource::ApiKey,
    }
}

struct Harness {
    gateway: LlmGateway,
    port: Arc<RecordingPort>,
    budget: Arc<MockRunBudget>,
    bus: Arc<MockEventBusEmit>,
}

fn harness(policy: Option<Arc<dyn AgentLlmPolicySource>>) -> Harness {
    let port = Arc::new(RecordingPort {
        calls: AtomicUsize::new(0),
        last: Mutex::new(None),
    });
    let mut registry = InferenceBackendRegistry::new();
    registry.insert(
        "local-a",
        Arc::clone(&port) as Arc<dyn InferenceBackendPort>,
    );
    let mut cfg = fixture_runtime_config();
    cfg.llm_providers = vec![
        provider("cloud-x", InferenceBackendClass::CloudHttp),
        provider("local-a", InferenceBackendClass::Local),
    ];
    let budget = Arc::new(MockRunBudget::default());
    let bus = Arc::new(MockEventBusEmit::default());
    let mut gateway = LlmGateway::new(
        Arc::new(MockRuntimeConfigProvider::new(cfg)),
        Arc::new(MockHttpSecurityChain::default()),
        Arc::clone(&budget) as Arc<dyn RunBudget>,
        Arc::clone(&bus) as Arc<dyn EventBusEmit>,
        no_op_repetition_guard(),
        "test-agent".into(),
    )
    .with_inference_backends(registry);
    if let Some(policy) = policy {
        gateway = gateway.with_agent_policy(policy);
    }
    Harness {
        gateway,
        port,
        budget,
        bus,
    }
}

fn ping_messages() -> Vec<InferenceMessage> {
    vec![InferenceMessage {
        role: "user".into(),
        content: "ping".into(),
    }]
}

#[tokio::test]
async fn preflight_provider_dispatches_the_pinned_port_once_without_budget() {
    let h = harness(None);
    h.gateway
        .preflight_provider("local-a", &AtomicBool::new(false))
        .await
        .expect("preflight of a wired local entry");
    assert_eq!(h.port.calls.load(Ordering::SeqCst), 1);
    let last = h
        .port
        .last
        .lock()
        .unwrap()
        .clone()
        .expect("port saw a chat");
    assert_eq!(last.messages, ping_messages());
    assert_eq!(last.max_tokens, Some(16));
    assert!(h.budget.checks.lock().unwrap().is_empty());
    assert!(h.budget.commits.lock().unwrap().is_empty());
    let events = h.bus.snapshot();
    let reqs: Vec<_> = events
        .iter()
        .filter(|e| e.event_type == LLM_REQUEST)
        .collect();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].payload["provider_id"], "local-a");
    assert!(reqs[0].run_id.is_none());
    assert!(events.iter().any(|e| e.event_type == LLM_RESPONSE));
}

#[tokio::test]
async fn preflight_provider_ignores_the_agent_policy_pin() {
    let h = harness(Some(Arc::new(PinCloudX)));
    h.gateway
        .preflight_provider("local-a", &AtomicBool::new(false))
        .await
        .expect("pin to local-a ignores the agent policy");
    assert_eq!(h.port.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn preflight_provider_unknown_id_is_model_not_available() {
    let h = harness(None);
    let err = h
        .gateway
        .preflight_provider("nope", &AtomicBool::new(false))
        .await
        .expect_err("unknown id");
    match err {
        LlmError::ModelNotAvailable(msg) => {
            assert_eq!(msg, "provider nope not configured");
        }
        other => panic!("expected ModelNotAvailable, got {other:?}"),
    }
    assert_eq!(h.port.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn preflight_provider_cancelled_before_dispatch_never_calls_the_port() {
    let h = harness(None);
    let err = h
        .gateway
        .preflight_provider("local-a", &AtomicBool::new(true))
        .await
        .expect_err("cancelled");
    match err {
        LlmError::ProviderError(msg) => assert_eq!(msg, "cancelled"),
        other => panic!("expected ProviderError, got {other:?}"),
    }
    assert_eq!(h.port.calls.load(Ordering::SeqCst), 0);
}

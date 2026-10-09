use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use advance_runtime::config::RuntimeConfig;
use advance_shared_types::security_validator::{
    HttpCapability, HttpError, HttpRequest, HttpResponse, HttpResponseHead, HttpStreamingChain,
    LeakDetector, ScanContext, ScanResult, TransportErrorKind,
};
use advance_shared_types::traits::{EventBusEmit, LlmDeltaSink, RepetitionGuardCheck, RunBudget};
use async_trait::async_trait;
use cap_llm::{LlmError, LlmGateway, StaticConfig};

use super::{build_llm_gateway, build_llm_gateway_with, GatewayInference};

const CONFIG_YAML: &str = r#"
wasm:
  max_memory_pages: 1024
  epoch_interruption_ms: 100
  fuel_enabled: false
llm-providers:
  - id: local-a
    endpoint: ""
    api-key-secret: local-a-api-key
    model-aliases:
      llama: llama
    cost-per-mtoken-in: 0.001
    cost-per-mtoken-out: 0.001
    backend-class: local
  - id: mesh-r
    endpoint: ""
    api-key-secret: mesh-r-api-key
    model-aliases:
      llama: llama
    cost-per-mtoken-in: 0.001
    cost-per-mtoken-out: 0.001
    backend-class: mesh-remote
    device-id: peer-b
cron:
  max_jitter_ratio: 0.1
git:
  gc_interval_hours: 24
  max_tracked_file_mb: 10
circuit-breakers: []
secrets:
  master-key-source: keychain
  env-var-name: SECRETS_MASTER_KEY
users: []
post-processor:
  llm-model: sonnet-light
  llm-failure-cooldown-seconds: 600
"#;

struct StubChain;

#[async_trait]
impl advance_shared_types::security_validator::HttpSecurityChain for StubChain {
    async fn execute(
        &self,
        _agent_id: &str,
        _req: HttpRequest,
        _cap: &HttpCapability,
    ) -> Result<HttpResponse, HttpError> {
        Err(HttpError::Transport(TransportErrorKind::Other))
    }
}

#[async_trait]
impl HttpStreamingChain for StubChain {
    async fn execute_streaming(
        &self,
        _agent_id: &str,
        _req: HttpRequest,
        _cap: &HttpCapability,
    ) -> Result<
        (
            HttpResponseHead,
            Box<dyn advance_shared_types::security_validator::HttpBodyStream>,
        ),
        HttpError,
    > {
        Err(HttpError::Transport(TransportErrorKind::Other))
    }
}

struct StubLeak;

impl LeakDetector for StubLeak {
    fn scan(&self, _text: &str, _context: ScanContext) -> ScanResult {
        ScanResult::Clean
    }
    fn scan_headers(&self, _headers: &[(String, String)]) -> ScanResult {
        ScanResult::Clean
    }
}

fn boot() -> Arc<RuntimeConfig> {
    Arc::new(serde_yml::from_str(CONFIG_YAML).expect("fixture RuntimeConfig parses"))
}

fn build_with(inference: GatewayInference) -> Arc<LlmGateway> {
    let chain = Arc::new(StubChain);
    build_llm_gateway_with(
        Arc::new(StaticConfig(boot())),
        chain.clone(),
        chain,
        Arc::new(StubLeak),
        Arc::new(cap_llm::PreflightAllowBudget),
        Arc::new(cap_llm::DiscardEventBus) as Arc<dyn EventBusEmit>,
        Arc::new(cap_llm::NoopRepetition) as Arc<dyn RepetitionGuardCheck>,
        "root".into(),
        Arc::new(advance_shared_types::traits::NotWiredDeltaSink) as Arc<dyn LlmDeltaSink>,
        None,
        None,
        inference,
    )
}

async fn assert_unwired_empty(gw: &LlmGateway) {
    let cancel = AtomicBool::new(false);
    match gw.preflight_provider("local-a", &cancel).await {
        Err(LlmError::ProviderError(msg)) => {
            assert_eq!(msg, "local transport: not wired");
        }
        other => panic!("local no-sidecar must be not wired, got {other:?}"),
    }
    match gw.preflight_provider("mesh-r", &cancel).await {
        Err(LlmError::ProviderError(msg)) => {
            assert_eq!(msg, "mesh-remote: not wired");
        }
        other => panic!("mesh-remote must be not wired, got {other:?}"),
    }
    assert!(
        gw.catalog().default_id().is_err(),
        "catalog is empty without an extension"
    );
}

#[tokio::test]
async fn module_001_ac31_build_llm_gateway_shim_matches_internal_builder() {
    let chain = Arc::new(StubChain);
    let shim = build_llm_gateway(
        Arc::new(StaticConfig(boot())),
        chain.clone(),
        chain,
        Arc::new(StubLeak),
        Arc::new(cap_llm::PreflightAllowBudget) as Arc<dyn RunBudget>,
        Arc::new(cap_llm::DiscardEventBus) as Arc<dyn EventBusEmit>,
        Arc::new(cap_llm::NoopRepetition) as Arc<dyn RepetitionGuardCheck>,
        "root".into(),
        Arc::new(advance_shared_types::traits::NotWiredDeltaSink) as Arc<dyn LlmDeltaSink>,
        None,
        None,
    );
    let none = build_with(GatewayInference::none());
    let shared = Arc::new(cap_llm::ModelProfileCatalog::new());
    let call_site = build_with(GatewayInference {
        catalog: Arc::clone(&shared),
        snapshot: Some(boot()),
        ..GatewayInference::none()
    });

    assert_unwired_empty(&shim).await;
    assert_unwired_empty(&none).await;
    assert_unwired_empty(&call_site).await;
    assert!(
        Arc::ptr_eq(&call_site.catalog(), &shared),
        "the call-site catalog is the Arc handed to the builder"
    );
}

const LOCAL_ONLY_YAML: &str = r#"
wasm:
  max_memory_pages: 1024
  epoch_interruption_ms: 100
  fuel_enabled: false
llm-providers:
  - id: local-a
    endpoint: ""
    api-key-secret: local-a-api-key
    model-aliases:
      llama: llama
    cost-per-mtoken-in: 0.001
    cost-per-mtoken-out: 0.001
    backend-class: local
cron:
  max_jitter_ratio: 0.1
git:
  gc_interval_hours: 24
  max_tracked_file_mb: 10
circuit-breakers: []
secrets:
  master-key-source: keychain
  env-var-name: SECRETS_MASTER_KEY
users: []
post-processor:
  llm-model: sonnet-light
  llm-failure-cooldown-seconds: 600
"#;

const MESH_ONLY_YAML: &str = r#"
wasm:
  max_memory_pages: 1024
  epoch_interruption_ms: 100
  fuel_enabled: false
llm-providers:
  - id: mesh-r
    endpoint: ""
    api-key-secret: mesh-r-api-key
    model-aliases:
      llama: llama
    cost-per-mtoken-in: 0.001
    cost-per-mtoken-out: 0.001
    backend-class: mesh-remote
    device-id: peer-b
cron:
  max_jitter_ratio: 0.1
git:
  gc_interval_hours: 24
  max_tracked_file_mb: 10
circuit-breakers: []
secrets:
  master-key-source: keychain
  env-var-name: SECRETS_MASTER_KEY
users: []
post-processor:
  llm-model: sonnet-light
  llm-failure-cooldown-seconds: 600
"#;

fn boot_yaml(yaml: &str) -> Arc<RuntimeConfig> {
    Arc::new(serde_yml::from_str(yaml).expect("fixture RuntimeConfig parses"))
}

fn build_cfg(cfg: Arc<RuntimeConfig>, inference: GatewayInference) -> Arc<LlmGateway> {
    let chain = Arc::new(StubChain);
    build_llm_gateway_with(
        Arc::new(StaticConfig(cfg)),
        chain.clone(),
        chain,
        Arc::new(StubLeak),
        Arc::new(cap_llm::PreflightAllowBudget),
        Arc::new(cap_llm::DiscardEventBus) as Arc<dyn EventBusEmit>,
        Arc::new(cap_llm::NoopRepetition) as Arc<dyn RepetitionGuardCheck>,
        "root".into(),
        Arc::new(advance_shared_types::traits::NotWiredDeltaSink) as Arc<dyn LlmDeltaSink>,
        None,
        None,
        inference,
    )
}

struct RecordingPort {
    calls: std::sync::atomic::AtomicUsize,
}

#[async_trait]
impl advance_shared_types::inference::InferenceBackendPort for RecordingPort {
    async fn chat(
        &self,
        _req: advance_shared_types::inference::InferenceChatRequest,
    ) -> Result<
        advance_shared_types::inference::InferenceChatResponse,
        advance_shared_types::inference::InferenceBackendError,
    > {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(advance_shared_types::inference::InferenceChatResponse {
            text: "pong".into(),
            model: "llama".into(),
            input_tokens: 1,
            output_tokens: 1,
            finish_reason: "stop".into(),
        })
    }
    async fn embed(
        &self,
        _req: advance_shared_types::inference::InferenceEmbedRequest,
    ) -> Result<
        advance_shared_types::inference::InferenceEmbedResponse,
        advance_shared_types::inference::InferenceBackendError,
    > {
        Err(advance_shared_types::inference::InferenceBackendError::Unwired)
    }
    async fn start_stream(
        &self,
        _req: advance_shared_types::inference::InferenceChatRequest,
    ) -> Result<
        (
            advance_shared_types::inference::InferenceStreamHead,
            Box<dyn advance_shared_types::inference::InferenceStream>,
        ),
        advance_shared_types::inference::InferenceBackendError,
    > {
        Err(advance_shared_types::inference::InferenceBackendError::Unwired)
    }
    fn is_wired(&self) -> bool {
        true
    }
}

struct RecordingDispatch {
    calls: std::sync::atomic::AtomicUsize,
}

#[async_trait]
impl advance_shared_types::inference::MeshInferenceDispatch for RecordingDispatch {
    async fn dispatch_chat(
        &self,
        _req: advance_shared_types::inference::InferenceChatRequest,
        _invocation_id: &str,
        _target_device_id: &str,
    ) -> Result<
        advance_shared_types::inference::InferenceChatResponse,
        advance_shared_types::inference::MeshInferenceDispatchError,
    > {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(advance_shared_types::inference::InferenceChatResponse {
            text: "mesh-pong".into(),
            model: "llama".into(),
            input_tokens: 1,
            output_tokens: 1,
            finish_reason: "stop".into(),
        })
    }
    async fn dispatch_embed(
        &self,
        _req: advance_shared_types::inference::InferenceEmbedRequest,
        _invocation_id: &str,
        _target_device_id: &str,
    ) -> Result<
        advance_shared_types::inference::InferenceEmbedResponse,
        advance_shared_types::inference::MeshInferenceDispatchError,
    > {
        Err(advance_shared_types::inference::MeshInferenceDispatchError::Unwired)
    }
    async fn start_stream(
        &self,
        _req: advance_shared_types::inference::InferenceChatRequest,
        _invocation_id: &str,
        _target_device_id: &str,
    ) -> Result<
        (
            advance_shared_types::inference::InferenceStreamHead,
            Box<dyn advance_shared_types::inference::InferenceStream>,
            advance_shared_types::inference::MeshCarrier,
        ),
        advance_shared_types::inference::MeshInferenceDispatchError,
    > {
        Err(advance_shared_types::inference::MeshInferenceDispatchError::Unwired)
    }
    fn is_wired(&self) -> bool {
        true
    }
}

#[tokio::test]
async fn module_001_ac31_claimed_port_and_mesh_dispatch_reach_the_registry() {
    use cap_llm::{ChatMessage, ChatParams, ChatRole, LlmGatewayInternal};

    let local_port = Arc::new(RecordingPort {
        calls: std::sync::atomic::AtomicUsize::new(0),
    });
    let mut claims = std::collections::BTreeMap::new();
    claims.insert(
        "local-a".to_string(),
        Arc::clone(&local_port) as Arc<dyn advance_shared_types::inference::InferenceBackendPort>,
    );
    let local_gw = build_cfg(
        boot_yaml(LOCAL_ONLY_YAML),
        GatewayInference {
            claims,
            ..GatewayInference::none()
        },
    );
    let local = LlmGatewayInternal::chat(
        local_gw.as_ref(),
        vec![ChatMessage {
            role: ChatRole::User,
            content: "hi".into(),
        }],
        ChatParams {
            model: Some("llama".into()),
            max_tokens: Some(16),
            ..Default::default()
        },
    )
    .await
    .expect("claimed local chat");
    assert_eq!(local.text, "pong");
    assert_eq!(
        local_port.calls.load(std::sync::atomic::Ordering::SeqCst),
        1
    );

    let mesh_dispatch = Arc::new(RecordingDispatch {
        calls: std::sync::atomic::AtomicUsize::new(0),
    });
    let mesh_gw = build_cfg(
        boot_yaml(MESH_ONLY_YAML),
        GatewayInference {
            mesh_dispatch: Some(Arc::clone(&mesh_dispatch)
                as Arc<dyn advance_shared_types::inference::MeshInferenceDispatch>),
            ..GatewayInference::none()
        },
    );
    let mesh = LlmGatewayInternal::chat(
        mesh_gw.as_ref(),
        vec![ChatMessage {
            role: ChatRole::User,
            content: "hi".into(),
        }],
        ChatParams {
            model: Some("llama".into()),
            max_tokens: Some(16),
            ..Default::default()
        },
    )
    .await
    .expect("claimed mesh chat");
    assert_eq!(mesh.text, "mesh-pong");
    assert_eq!(
        mesh_dispatch
            .calls
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );
}

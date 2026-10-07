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
async fn build_llm_gateway_shim_matches_internal_builder() {
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

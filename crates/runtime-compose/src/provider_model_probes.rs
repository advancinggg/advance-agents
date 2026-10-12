//! Production constructor for the providers-family admin: today's builder chain
//! plus live model-catalog probes.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Arc;

use advance_home::provider_admin::{
    ProcessCloudHttpModelsProbe, ProviderReferenceCheck, WiredProviderAdmin, MODELS_LIST_TIMEOUT,
};
use advance_home::{ChatGptSignInPort, PreflightPort};
use advance_runtime::config::RuntimeConfigProvider;
use advance_shared_types::process_policy::ProcessPolicy;
use advance_shared_types::traits::EventBusEmit;
use cap_http::DefaultHttpSecurityChain;
use cap_llm::backend_cli::{AgentCliEnv, ProcessModelsProbe};
use cap_llm::LlmGateway;
use cap_secrets::SecretStore;

use crate::inference::{ClaimedPreflightStopper, ComposedClaimedPreflight};

/// Inputs the current wiring site already has.
pub(crate) struct ProviderAdminCompose {
    pub home: PathBuf,
    pub config: Arc<dyn RuntimeConfigProvider>,
    pub store: Option<Arc<SecretStore>>,
    pub preflight: Arc<dyn PreflightPort>,
    pub references: Arc<dyn ProviderReferenceCheck>,
    pub processes: ProcessPolicy,
    pub hot_reload: bool,
    pub chatgpt_sign_in: Option<Arc<dyn ChatGptSignInPort>>,
    pub inference_marks_claimable: bool,
    pub llm_gateway: Option<Arc<LlmGateway>>,
    pub inference_claimed: BTreeSet<String>,
    pub event_bus: Arc<dyn EventBusEmit>,
}

pub(crate) fn attach_live_model_probes(
    admin: WiredProviderAdmin,
    event_bus: Arc<dyn EventBusEmit>,
    config: Arc<dyn RuntimeConfigProvider>,
) -> WiredProviderAdmin {
    let env = AgentCliEnv::from_process_env().with_process_policy(admin.process_policy());
    let admin = admin.with_process_agent_cli_models_probe(Arc::new(ProcessModelsProbe { env }));
    match admin.key_store() {
        Ok(store) => {
            let (leak, ssrf, rate) =
                crate::channels_boot::live_security_components(Some(Arc::clone(&config)));
            let executor = crate::channels_boot::live_executor(Some(config));
            let chain =
                DefaultHttpSecurityChain::new(Arc::clone(&store), leak, ssrf, rate, executor)
                    .with_event_bus(event_bus);
            admin.with_process_cloud_http_models_probe(Arc::new(ProcessCloudHttpModelsProbe::new(
                Arc::new(chain),
                store,
                MODELS_LIST_TIMEOUT,
            )))
        }
        Err(_) => admin,
    }
}

pub(crate) fn compose_provider_admin(
    input: ProviderAdminCompose,
) -> (WiredProviderAdmin, Option<ClaimedPreflightStopper>) {
    let mut admin = WiredProviderAdmin::new(
        input.home,
        Arc::clone(&input.config),
        input.store,
        input.preflight,
        input.references,
    )
    .with_process_policy(input.processes)
    .with_hot_reload(input.hot_reload);
    if let Some(sign_in) = input.chatgpt_sign_in {
        admin = admin.with_chatgpt_sign_in(sign_in);
    }
    if input.inference_marks_claimable {
        admin = admin.with_claimable_local_entries(true);
    }
    if let Some(gateway) = input.llm_gateway.as_ref() {
        admin = admin
            .with_local_sidecar_binder(Arc::clone(gateway) as Arc<dyn cap_llm::LocalSidecarBinder>);
    }
    let mut stopper = None;
    if let (Some(gateway), false) = (
        input.llm_gateway.as_ref(),
        input.inference_claimed.is_empty(),
    ) {
        let (port, stop) = ComposedClaimedPreflight::new(gateway, input.inference_claimed);
        stopper = Some(stop);
        admin = admin.with_claimed_preflight(Arc::new(port));
    }
    let admin = attach_live_model_probes(admin, input.event_bus, input.config);
    (admin, stopper)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Mutex;
    use std::time::Duration;

    use advance_home::chatgpt_sign_in::STATE_SIGNED_OUT;
    use advance_home::provider_admin::{ModelProbeInstallation, NoReferences};
    use advance_home::{
        CancelToken, ChatGptSignInPort, PreflightFail, PreflightPort, SecretBytes, SignInRefusal,
        SignInStarted, SignInStatus, SignOutOutcome, VerifyOutcome,
    };
    use advance_runtime::config::RuntimeConfig;
    use advance_shared_types::inference::{
        InferenceBackendError, InferenceBackendPort, InferenceChatRequest, InferenceChatResponse,
        InferenceEmbedRequest, InferenceEmbedResponse, InferenceStream, InferenceStreamHead,
    };
    use advance_shared_types::security_validator::{
        HttpCapability, HttpError, HttpRequest, HttpResponse, HttpResponseHead, HttpStreamingChain,
        LeakDetector, ScanContext, ScanResult, TransportErrorKind,
    };
    use advance_shared_types::traits::{EventBusEmit, LlmDeltaSink, RepetitionGuardCheck};
    use async_trait::async_trait;
    use cap_llm::{LlmGateway, StaticConfig};
    use cap_secrets::{InMemorySecretStorage, SecretStore};
    use zeroize::Zeroizing;

    use crate::wiring::{build_llm_gateway_with, GatewayInference};

    const HOME_YAML: &str = r#"
wasm:
  max_memory_pages: 1024
  epoch_interruption_ms: 100
  fuel_enabled: false
llm-providers:
  - id: openai
    endpoint: https://api.openai.com
    api-key-secret: openai-api-key
    model-aliases:
      gpt: gpt-4o
    cost-per-mtoken-in: 2.50
    cost-per-mtoken-out: 10.00
    rate-limit:
      requests-per-minute: 1000
      tokens-per-minute: 400000
cron:
  max_jitter_ratio: 0.1
git:
  gc_interval_hours: 24
  max_tracked_file_mb: 10
circuit-breakers: []
secrets:
  master-key-source: env-var
  env-var-name: ADV_MODELS_COMPOSE_MK
users: []
post-processor:
  llm-model: sonnet-light
  llm-failure-cooldown-seconds: 600
"#;

    struct PassPreflight;
    impl PreflightPort for PassPreflight {
        fn preflight(
            &self,
            _home: &std::path::Path,
            _provider: &advance_runtime::config::LlmProviderConfig,
            _key: &SecretBytes,
            _cancel: &CancelToken,
        ) -> Result<(), PreflightFail> {
            Ok(())
        }
    }

    struct StubSignIn;
    impl ChatGptSignInPort for StubSignIn {
        fn host_id(&self) -> Result<String, SignInRefusal> {
            Ok("urn:uuid:0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d".into())
        }
        fn start(&self, _secret_name: &str) -> Result<SignInStarted, SignInRefusal> {
            Err(SignInRefusal("unavailable"))
        }
        fn status(&self, _secret_name: &str) -> SignInStatus {
            SignInStatus {
                state: STATE_SIGNED_OUT,
                reason: None,
                account: None,
                plan_usage: None,
                expires_at_ms: None,
                models: Vec::new(),
            }
        }
        fn cancel(&self, secret_name: &str) -> SignInStatus {
            self.status(secret_name)
        }
        fn sign_out(&self, _secret_name: &str) -> SignOutOutcome {
            SignOutOutcome {
                signed_out: true,
                revocation_confirmed: false,
            }
        }
        fn verify(&self, _secret_name: &str) -> VerifyOutcome {
            VerifyOutcome {
                ok: false,
                reason: Some("not-signed-in"),
                models: Vec::new(),
            }
        }
        fn forget(&self, _secret_name: &str) {}
    }

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

    struct RecordingPort {
        calls: AtomicUsize,
    }
    #[async_trait]
    impl InferenceBackendPort for RecordingPort {
        async fn chat(
            &self,
            _req: InferenceChatRequest,
        ) -> Result<InferenceChatResponse, InferenceBackendError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
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
        ) -> Result<(InferenceStreamHead, Box<dyn InferenceStream>), InferenceBackendError>
        {
            Err(InferenceBackendError::Unwired)
        }
        fn is_wired(&self) -> bool {
            true
        }
    }

    fn store() -> Arc<SecretStore> {
        Arc::new(SecretStore::new(
            Zeroizing::new([9u8; 32]),
            Arc::new(InMemorySecretStorage::default()),
        ))
    }

    fn home() -> (tempfile::TempDir, PathBuf, Arc<StaticConfig>) {
        let dir = tempfile::tempdir().expect("tempdir");
        let home = dir.path().to_path_buf();
        std::fs::create_dir_all(home.join(".advance")).unwrap();
        std::fs::write(home.join(".advance/runtime-config.yaml"), HOME_YAML).unwrap();
        let cfg: RuntimeConfig =
            serde_yml::from_str(HOME_YAML).expect("fixture RuntimeConfig parses");
        (dir, home, Arc::new(StaticConfig(Arc::new(cfg))))
    }

    fn gateway() -> Arc<LlmGateway> {
        let mut claims = BTreeMap::new();
        claims.insert(
            "local-a".to_string(),
            Arc::new(RecordingPort {
                calls: AtomicUsize::new(0),
            }) as Arc<dyn InferenceBackendPort>,
        );
        let chain = Arc::new(StubChain);
        let (_dir, _home, cfg) = home();
        build_llm_gateway_with(
            cfg,
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
            GatewayInference {
                claims,
                ..GatewayInference::none()
            },
        )
    }

    #[tokio::test]
    async fn am_t21_compose_sets_process_probes_and_stopper() {
        let (_dir, path, cfg) = home();
        let store = store();
        let (admin, stopper) = compose_provider_admin(ProviderAdminCompose {
            home: path.clone(),
            config: Arc::clone(&cfg) as Arc<dyn RuntimeConfigProvider>,
            store: Some(Arc::clone(&store)),
            preflight: Arc::new(PassPreflight),
            references: Arc::new(NoReferences),
            processes: ProcessPolicy::Allow,
            hot_reload: true,
            chatgpt_sign_in: Some(Arc::new(StubSignIn) as Arc<dyn ChatGptSignInPort>),
            inference_marks_claimable: true,
            llm_gateway: Some(gateway()),
            inference_claimed: BTreeSet::from(["local-a".to_string()]),
            event_bus: Arc::new(cap_llm::DiscardEventBus) as Arc<dyn EventBusEmit>,
        });
        assert_eq!(
            admin.model_probe_installation(),
            (
                ModelProbeInstallation::Process,
                ModelProbeInstallation::Process
            )
        );
        assert!(admin.has_chatgpt_sign_in());
        assert!(stopper.is_some());

        let (admin2, stopper2) = compose_provider_admin(ProviderAdminCompose {
            home: path,
            config: cfg,
            store: None,
            preflight: Arc::new(PassPreflight),
            references: Arc::new(NoReferences),
            processes: ProcessPolicy::Allow,
            hot_reload: true,
            chatgpt_sign_in: Some(Arc::new(StubSignIn) as Arc<dyn ChatGptSignInPort>),
            inference_marks_claimable: false,
            llm_gateway: None,
            inference_claimed: BTreeSet::new(),
            event_bus: Arc::new(cap_llm::DiscardEventBus) as Arc<dyn EventBusEmit>,
        });
        assert_eq!(
            admin2.model_probe_installation().0,
            ModelProbeInstallation::Process
        );
        assert!(admin2.has_chatgpt_sign_in());
        assert!(stopper2.is_none());

        let bare = WiredProviderAdmin::new(
            tempfile::tempdir().unwrap().path().to_path_buf(),
            Arc::new(StaticConfig(Arc::new(
                serde_yml::from_str(HOME_YAML).unwrap(),
            ))),
            None,
            Arc::new(PassPreflight),
            Arc::new(NoReferences),
        );
        assert_eq!(
            bare.model_probe_installation(),
            (ModelProbeInstallation::Noop, ModelProbeInstallation::Noop)
        );
        let _ = AtomicBool::new(false);
        let _ = Mutex::new(());
        let _ = Duration::from_millis(1);
    }
}

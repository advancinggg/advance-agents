#![cfg(test)]

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use advance_runtime::config::{
    InferenceBackendClass, LlmProviderConfig, ProviderBackend, RetryDefaults,
};
use advance_shared_types::inference::{
    InferenceBackendError, InferenceBackendPort, InferenceBackendRegistry, InferenceChatRequest,
    InferenceChatResponse, InferenceEmbedRequest, InferenceEmbedResponse, InferenceMessage,
    InferenceStream, InferenceStreamClass, InferenceStreamHead, InferenceTextDelta, MeshCarrier,
    MeshInferenceDispatch, MeshInferenceDispatchError,
};
use advance_shared_types::security_validator::{
    HttpError, HttpResponse, TransportErrorKind,
};
use advance_shared_types::traits::{
    HttpStreamingChain, LlmDeltaEvent, LlmDeltaFrame, LlmDeltaSink, LlmTerminalReason,
};
use async_trait::async_trait;
use cap_http::DefaultLeakDetector;

use crate::backend_local::FailedSpawnBackend;
use crate::backend_mesh::MeshRemoteAdapter;
use crate::catalog::{CatalogTier, ModelProfile, ModelProfileCatalog, ProfileKey};
use crate::gateway::{
    ChatMessage, ChatParams, ChatRole, LlmGateway, LlmGatewayInternal, LlmRequestContext,
};
use crate::placement::{EndpointTelemetry, PlacementTelemetry, UserHardConstraint};
use crate::retry::PartialRetry;
use crate::stream::{PollOutcome, StreamRegistry};
use crate::test_support::{
    fixture_runtime_config, no_op_repetition_guard, MockEventBusEmit, MockHttpSecurityChain,
    MockRunBudget, MockRuntimeConfigProvider,
};
use crate::LlmError;

fn provider(
    id: &str,
    class: InferenceBackendClass,
    model: &str,
    profile_id: Option<&str>,
) -> LlmProviderConfig {
    let mut aliases = HashMap::new();
    aliases.insert(model.into(), model.into());
    LlmProviderConfig {
        id: id.into(),
        endpoint: if class == InferenceBackendClass::CloudHttp {
            "https://api.example.test".into()
        } else {
            String::new()
        },
        api_key_secret: "dummy".into(),
        model_aliases: aliases,
        cost_per_mtoken_in: 0.001,
        cost_per_mtoken_out: 0.001,
        rate_limit: None,
        retry_default: None,
        backend: Some(ProviderBackend::OpenAiChat),
        auth_scheme: None,
        backend_class: class,
        embedding_model: None,
        sidecar: None,
        profile_id: profile_id.map(str::to_string),
        device_id: None,
    }
}

fn profile(id: &str, tier: CatalogTier) -> (String, ModelProfile) {
    (
        id.into(),
        ModelProfile {
            key: ProfileKey {
                model_version: id.into(),
                quantization: "q4".into(),
                backend: "llama".into(),
                chat_template: "t".into(),
                tool_parser: id.into(),
            },
            tier,
            licence: "MIT".into(),
            benchmark_provenance: None,
            quirks: crate::catalog::ProfileQuirks::default(),
            capabilities: crate::capability::CapabilityDescriptor::unbound_local(false),
        },
    )
}

struct MapTel {
    ttft: HashMap<String, u64>,
}

impl PlacementTelemetry for MapTel {
    fn snapshot(&self, endpoint_id: &str) -> Option<EndpointTelemetry> {
        self.ttft
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

struct AuthTel {
    ttft: HashMap<String, u64>,
    deny: HashSet<String>,
}

impl PlacementTelemetry for AuthTel {
    fn snapshot(&self, endpoint_id: &str) -> Option<EndpointTelemetry> {
        self.ttft
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
    fn authorized(&self, endpoint_id: &str) -> bool {
        !self.deny.contains(endpoint_id)
    }
}

struct ScriptedPort {
    chats: AtomicU32,
    embeds: AtomicU32,
    results: Mutex<VecDeque<Result<InferenceChatResponse, InferenceBackendError>>>,
    deadlines: Mutex<Vec<Instant>>,
    streams: AtomicU32,
    stream_script: Mutex<StreamScript>,
    seen_messages: Mutex<Vec<Vec<InferenceMessage>>>,
    chat_delay: Mutex<Option<Duration>>,
    embed_ok: Mutex<Option<Vec<f32>>>,
}

#[derive(Clone, Copy)]
enum StreamScript {
    None,
    BreakHello,
    BreakEmpty,
    PanicHop,
}

impl ScriptedPort {
    fn chat_only(results: Vec<Result<InferenceChatResponse, InferenceBackendError>>) -> Self {
        Self {
            chats: AtomicU32::new(0),
            embeds: AtomicU32::new(0),
            results: Mutex::new(results.into()),
            deadlines: Mutex::new(Vec::new()),
            streams: AtomicU32::new(0),
            stream_script: Mutex::new(StreamScript::None),
            seen_messages: Mutex::new(Vec::new()),
            chat_delay: Mutex::new(None),
            embed_ok: Mutex::new(None),
        }
    }

    fn allow_embed(&self, vector: Vec<f32>) {
        *self.embed_ok.lock().unwrap() = Some(vector);
    }

    fn ok(text: &str) -> InferenceChatResponse {
        Self::ok_usage(text, 1, 1)
    }

    fn ok_usage(text: &str, input_tokens: u64, output_tokens: u64) -> InferenceChatResponse {
        InferenceChatResponse {
            text: text.into(),
            model: "llama".into(),
            input_tokens,
            output_tokens,
            finish_reason: "stop".into(),
        }
    }
}

#[async_trait]
impl InferenceBackendPort for ScriptedPort {
    async fn chat(
        &self,
        req: InferenceChatRequest,
    ) -> Result<InferenceChatResponse, InferenceBackendError> {
        self.chats.fetch_add(1, Ordering::SeqCst);
        self.deadlines.lock().unwrap().push(req.deadline);
        self.seen_messages.lock().unwrap().push(req.messages.clone());
        let delay = *self.chat_delay.lock().unwrap();
        if let Some(d) = delay {
            tokio::time::sleep(d).await;
        }
        let mut q = self.results.lock().unwrap();
        if q.len() == 1 {
            q[0].clone()
        } else {
            q.pop_front()
                .unwrap_or_else(|| Err(InferenceBackendError::Provider("script empty".into())))
        }
    }
    async fn embed(
        &self,
        _req: InferenceEmbedRequest,
    ) -> Result<InferenceEmbedResponse, InferenceBackendError> {
        self.embeds.fetch_add(1, Ordering::SeqCst);
        match self.embed_ok.lock().unwrap().clone() {
            Some(vector) => Ok(InferenceEmbedResponse {
                vector,
                model: "nomic-embed".into(),
            }),
            None => Err(InferenceBackendError::Unwired),
        }
    }
    async fn start_stream(
        &self,
        _req: InferenceChatRequest,
    ) -> Result<(InferenceStreamHead, Box<dyn InferenceStream>), InferenceBackendError> {
        self.streams.fetch_add(1, Ordering::SeqCst);
        match *self.stream_script.lock().unwrap() {
            StreamScript::None => Err(InferenceBackendError::Unwired),
            StreamScript::BreakHello => Ok((
                InferenceStreamHead {
                    class: InferenceStreamClass::Success,
                    snapshot_only: false,
                },
                Box::new(BreakAfterText {
                    text: Some("hello".into()),
                    done: false,
                }) as Box<dyn InferenceStream>,
            )),
            StreamScript::BreakEmpty => Ok((
                InferenceStreamHead {
                    class: InferenceStreamClass::Success,
                    snapshot_only: false,
                },
                Box::new(BreakAfterText {
                    text: None,
                    done: false,
                }) as Box<dyn InferenceStream>,
            )),
            StreamScript::PanicHop => panic!("live stream must not hop"),
        }
    }
    fn is_wired(&self) -> bool {
        true
    }
}

struct BreakAfterText {
    text: Option<String>,
    done: bool,
}

#[async_trait]
impl InferenceStream for BreakAfterText {
    async fn next_chunk(&mut self) -> Option<Result<InferenceTextDelta, InferenceBackendError>> {
        if let Some(text) = self.text.take() {
            return Some(Ok(InferenceTextDelta {
                text,
                usage: None,
                terminal: false,
                finish_reason: None,
            }));
        }
        if !self.done {
            self.done = true;
            return Some(Err(InferenceBackendError::Provider(
                "stream eof before terminal".into(),
            )));
        }
        None
    }
    fn cancel(&mut self) {}
}

#[derive(Default)]
struct FrameRec {
    events: Mutex<Vec<LlmDeltaEvent>>,
}

impl LlmDeltaSink for FrameRec {
    fn publish(&self, event: LlmDeltaEvent) {
        self.events.lock().unwrap().push(event);
    }
}

impl FrameRec {
    fn frames(&self) -> Vec<LlmDeltaFrame> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .map(|e| e.frame.clone())
            .collect()
    }
}

fn user_msg(s: &str) -> ChatMessage {
    ChatMessage {
        role: ChatRole::User,
        content: s.into(),
    }
}

fn ctx_for(
    model: &str,
    run_id: Option<&str>,
    constraints: Vec<UserHardConstraint>,
    hard: bool,
    schema: Option<&str>,
    tee_live: bool,
) -> LlmRequestContext {
    LlmRequestContext {
        agent_id: "test-agent".into(),
        run_id: run_id.map(str::to_string),
        messages: vec![user_msg("hi")],
        params: ChatParams {
            model: Some(model.into()),
            ..Default::default()
        },
        output_schema: schema.map(str::to_string),
        tee_live,
        user_constraints: constraints,
        hard_task_class: hard,
        ..Default::default()
    }
}

fn gateway(
    providers: Vec<LlmProviderConfig>,
    registry: InferenceBackendRegistry,
    tel: MapTel,
    catalog: ModelProfileCatalog,
    sink: Option<Arc<dyn LlmDeltaSink>>,
) -> (
    LlmGateway,
    Arc<MockHttpSecurityChain>,
    Arc<MockRunBudget>,
    Arc<MockEventBusEmit>,
) {
    let mut cfg = fixture_runtime_config();
    cfg.llm_providers = providers;
    let chain = Arc::new(MockHttpSecurityChain::default());
    let budget = Arc::new(MockRunBudget::default());
    let bus = Arc::new(MockEventBusEmit::default());
    let mut gw = LlmGateway::new(
        Arc::new(MockRuntimeConfigProvider::new(cfg)),
        chain.clone(),
        budget.clone(),
        bus.clone(),
        no_op_repetition_guard(),
        "test-agent".into(),
    )
    .with_inference_backends(registry)
    .with_catalog(catalog)
    .with_placement_telemetry(Arc::new(tel));
    if let Some(s) = sink {
        gw = gw.with_delta_sink(s);
    }
    (gw, chain, budget, bus)
}

const SCHEMA: &str = r#"{"type":"object","properties":{"x":{"type":"integer"}},"required":["x"]}"#;

#[tokio::test]
async fn t133_record_immutable_and_on_llm_request() {
    let port = Arc::new(ScriptedPort::chat_only(vec![Ok(ScriptedPort::ok("pong"))]));
    let mut registry = InferenceBackendRegistry::new();
    registry.insert("local", port.clone());
    let (gw, _, _, bus) = gateway(
        vec![provider(
            "local",
            InferenceBackendClass::Local,
            "llama",
            None,
        )],
        registry,
        MapTel {
            ttft: HashMap::from([("local".into(), 7)]),
        },
        ModelProfileCatalog::new(),
        None,
    );
    gw.generate(ctx_for("llama", Some("rid"), vec![], false, None, false))
        .await
        .expect("ok");
    let reqs: Vec<_> = bus
        .snapshot()
        .into_iter()
        .filter(|e| e.event_type == crate::LLM_REQUEST)
        .collect();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].payload["endpoint_id"], "local");
    assert_eq!(reqs[0].payload["model_revision"], "llama");
    let reason = reqs[0].payload["placement_reason"].as_str().unwrap();
    assert!(reason.contains("ttft:7"), "{reason}");
}

#[tokio::test]
async fn t133_hard_constraint_never_overridden() {
    let local = Arc::new(ScriptedPort::chat_only(vec![Ok(ScriptedPort::ok(
        "local-hit",
    ))]));
    let mut registry = InferenceBackendRegistry::new();
    registry.insert("local", local.clone());
    let (gw, chain, _, _) = gateway(
        vec![
            provider("cloud", InferenceBackendClass::CloudHttp, "llama", None),
            provider("local", InferenceBackendClass::Local, "llama", None),
        ],
        registry,
        MapTel {
            ttft: HashMap::from([("cloud".into(), 1), ("local".into(), 5000)]),
        },
        ModelProfileCatalog::new(),
        None,
    );
    let resp = gw
        .generate(ctx_for(
            "llama",
            None,
            vec![UserHardConstraint::AlwaysLocal],
            false,
            None,
            false,
        ))
        .await
        .expect("ok");
    assert_eq!(resp.text, "local-hit");
    assert_eq!(local.chats.load(Ordering::SeqCst), 1);
    assert!(chain.call_log.lock().unwrap().is_empty());

    let mut phone_cfg = provider("phone", InferenceBackendClass::Local, "llama", None);
    phone_cfg.device_id = Some("phone".into());
    let mut mac_cfg = provider("mac", InferenceBackendClass::Local, "llama", None);
    mac_cfg.device_id = Some("mac".into());
    let phone = Arc::new(ScriptedPort::chat_only(vec![Ok(ScriptedPort::ok(
        "pinned",
    ))]));
    let mac = Arc::new(ScriptedPort::chat_only(vec![Ok(ScriptedPort::ok("mac"))]));
    let mut registry = InferenceBackendRegistry::new();
    registry.insert("phone", phone.clone());
    registry.insert("mac", mac.clone());
    let (gw, _, _, _) = gateway(
        vec![mac_cfg, phone_cfg],
        registry,
        MapTel {
            ttft: HashMap::from([("mac".into(), 1), ("phone".into(), 5000)]),
        },
        ModelProfileCatalog::new(),
        None,
    );
    let resp = gw
        .generate(ctx_for(
            "llama",
            None,
            vec![UserHardConstraint::DevicePin("phone".into())],
            false,
            None,
            false,
        ))
        .await
        .expect("pin");
    assert_eq!(resp.text, "pinned");
    assert_eq!(phone.chats.load(Ordering::SeqCst), 1);
    assert_eq!(mac.chats.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn t133_unauthorized_endpoint_never_dispatched() {
    let denied = Arc::new(ScriptedPort::chat_only(vec![Ok(ScriptedPort::ok(
        "denied",
    ))]));
    let ok = Arc::new(ScriptedPort::chat_only(vec![Ok(ScriptedPort::ok("ok"))]));
    let mut registry = InferenceBackendRegistry::new();
    registry.insert("fast", denied.clone());
    registry.insert("slow", ok.clone());
    let mut cfg = fixture_runtime_config();
    cfg.llm_providers = vec![
        provider("fast", InferenceBackendClass::Local, "llama", None),
        provider("slow", InferenceBackendClass::Local, "llama", None),
    ];
    let gw = LlmGateway::new(
        Arc::new(MockRuntimeConfigProvider::new(cfg)),
        Arc::new(MockHttpSecurityChain::default()),
        Arc::new(MockRunBudget::default()),
        Arc::new(MockEventBusEmit::default()),
        no_op_repetition_guard(),
        "test-agent".into(),
    )
    .with_inference_backends(registry)
    .with_placement_telemetry(Arc::new(AuthTel {
        ttft: HashMap::from([("fast".into(), 1), ("slow".into(), 80)]),
        deny: HashSet::from(["fast".into()]),
    }));
    let resp = gw
        .generate(ctx_for("llama", None, vec![], false, None, false))
        .await
        .expect("authorized hop");
    assert_eq!(resp.text, "ok");
    assert_eq!(denied.chats.load(Ordering::SeqCst), 0);
    assert_eq!(ok.chats.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn t133_embed_empty_alias_skips_unauthorized() {
    let denied = Arc::new(ScriptedPort::chat_only(vec![]));
    denied.allow_embed(vec![9.0]);
    let ok = Arc::new(ScriptedPort::chat_only(vec![]));
    ok.allow_embed(vec![0.1, 0.2]);
    let mut registry = InferenceBackendRegistry::new();
    registry.insert("fast", denied.clone());
    registry.insert("slow", ok.clone());
    let mut cfg = fixture_runtime_config();
    let mut fast = provider("fast", InferenceBackendClass::Local, "llama", None);
    fast.model_aliases.clear();
    fast.embedding_model = Some("nomic-embed".into());
    let mut slow = provider("slow", InferenceBackendClass::Local, "llama", None);
    slow.model_aliases.clear();
    slow.embedding_model = Some("nomic-embed".into());
    cfg.llm_providers = vec![fast, slow];
    let gw = LlmGateway::new(
        Arc::new(MockRuntimeConfigProvider::new(cfg)),
        Arc::new(MockHttpSecurityChain::default()),
        Arc::new(MockRunBudget::default()),
        Arc::new(MockEventBusEmit::default()),
        no_op_repetition_guard(),
        "test-agent".into(),
    )
    .with_inference_backends(registry)
    .with_placement_telemetry(Arc::new(AuthTel {
        ttft: HashMap::from([("fast".into(), 1), ("slow".into(), 80)]),
        deny: HashSet::from(["fast".into()]),
    }));
    let vec = gw.embed("hi").await.expect("authorized embed");
    assert_eq!(vec, vec![0.1, 0.2]);
    assert_eq!(
        denied.embeds.load(Ordering::SeqCst),
        0,
        "denied empty-alias embed provider must not receive text"
    );
    assert_eq!(ok.embeds.load(Ordering::SeqCst), 1);
}

struct CountingMesh {
    chats: AtomicU32,
}

#[async_trait]
impl MeshInferenceDispatch for CountingMesh {
    async fn dispatch_chat(
        &self,
        _req: InferenceChatRequest,
        _invocation_id: &str,
        _target_device_id: &str,
    ) -> Result<InferenceChatResponse, MeshInferenceDispatchError> {
        self.chats.fetch_add(1, Ordering::SeqCst);
        Ok(InferenceChatResponse {
            text: "mesh-pong".into(),
            model: "llama".into(),
            input_tokens: 1,
            output_tokens: 1,
            finish_reason: "stop".into(),
        })
    }
    async fn dispatch_embed(
        &self,
        _req: InferenceEmbedRequest,
        _invocation_id: &str,
        _target_device_id: &str,
    ) -> Result<InferenceEmbedResponse, MeshInferenceDispatchError> {
        Err(MeshInferenceDispatchError::Unwired)
    }
    async fn start_stream(
        &self,
        req: InferenceChatRequest,
        invocation_id: &str,
        target: &str,
    ) -> Result<
        (
            InferenceStreamHead,
            Box<dyn InferenceStream>,
            MeshCarrier,
        ),
        MeshInferenceDispatchError,
    > {
        self.dispatch_chat(req, invocation_id, target).await?;
        unreachable!()
    }
    fn is_wired(&self) -> bool {
        true
    }
}

fn mesh_provider(id: &str) -> LlmProviderConfig {
    let mut c = provider(id, InferenceBackendClass::MeshRemote, "llama", None);
    c.device_id = Some("peer-b".into());
    c
}

#[tokio::test]
async fn t133_always_local_excludes_mesh_remote() {
    let local = Arc::new(ScriptedPort::chat_only(vec![Ok(ScriptedPort::ok(
        "local-hit",
    ))]));
    let mesh = Arc::new(CountingMesh {
        chats: AtomicU32::new(0),
    });
    let mut registry = InferenceBackendRegistry::new();
    registry.insert("local", local.clone());
    registry.insert(
        "mesh",
        Arc::new(MeshRemoteAdapter {
            dispatch: mesh.clone(),
            provider_id: "mesh".into(),
            embedding_model: None,
            target_device_id: "peer-b".into(),
        }),
    );
    let mut cfg = fixture_runtime_config();
    cfg.llm_providers = vec![
        provider("local", InferenceBackendClass::Local, "llama", None),
        mesh_provider("mesh"),
    ];
    let gw = LlmGateway::new(
        Arc::new(MockRuntimeConfigProvider::new(cfg)),
        Arc::new(MockHttpSecurityChain::default()),
        Arc::new(MockRunBudget::default()),
        Arc::new(MockEventBusEmit::default()),
        no_op_repetition_guard(),
        "test-agent".into(),
    )
    .with_inference_backends(registry)
    .with_placement_telemetry(Arc::new(MapTel {
        ttft: HashMap::from([("mesh".into(), 1), ("local".into(), 80)]),
    }));
    let resp = gw
        .generate(ctx_for(
            "llama",
            None,
            vec![UserHardConstraint::AlwaysLocal],
            false,
            None,
            false,
        ))
        .await
        .expect("always local");
    assert_eq!(resp.text, "local-hit");
    assert_eq!(local.chats.load(Ordering::SeqCst), 1);
    assert_eq!(mesh.chats.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn t133_never_cloud_allows_mesh_remote() {
    let mesh = Arc::new(CountingMesh {
        chats: AtomicU32::new(0),
    });
    let mut registry = InferenceBackendRegistry::new();
    registry.insert(
        "mesh",
        Arc::new(MeshRemoteAdapter {
            dispatch: mesh.clone(),
            provider_id: "mesh".into(),
            embedding_model: None,
            target_device_id: "peer-b".into(),
        }),
    );
    let chain = Arc::new(MockHttpSecurityChain::default());
    let mut cfg = fixture_runtime_config();
    cfg.llm_providers = vec![
        provider("cloud", InferenceBackendClass::CloudHttp, "llama", None),
        mesh_provider("mesh"),
    ];
    let gw = LlmGateway::new(
        Arc::new(MockRuntimeConfigProvider::new(cfg)),
        chain.clone(),
        Arc::new(MockRunBudget::default()),
        Arc::new(MockEventBusEmit::default()),
        no_op_repetition_guard(),
        "test-agent".into(),
    )
    .with_inference_backends(registry)
    .with_placement_telemetry(Arc::new(MapTel {
        ttft: HashMap::from([("cloud".into(), 1), ("mesh".into(), 80)]),
    }));
    let resp = gw
        .generate(ctx_for(
            "llama",
            None,
            vec![UserHardConstraint::NeverCloud],
            false,
            None,
            false,
        ))
        .await
        .expect("never cloud");
    assert_eq!(resp.text, "mesh-pong");
    assert_eq!(mesh.chats.load(Ordering::SeqCst), 1);
    assert!(chain.call_log.lock().unwrap().is_empty());
}

#[tokio::test]
async fn t133_rank_is_ttft_not_device_class() {
    let mac = Arc::new(ScriptedPort::chat_only(vec![Ok(ScriptedPort::ok("mac"))]));
    let phone = Arc::new(ScriptedPort::chat_only(vec![Ok(ScriptedPort::ok("phone"))]));
    let mut registry = InferenceBackendRegistry::new();
    registry.insert("mac", mac.clone());
    registry.insert("phone", phone.clone());
    let (gw, _, _, _) = gateway(
        vec![
            provider("mac", InferenceBackendClass::Local, "llama", None),
            provider("phone", InferenceBackendClass::Local, "llama", None),
        ],
        registry,
        MapTel {
            ttft: HashMap::from([("mac".into(), 5000), ("phone".into(), 10)]),
        },
        ModelProfileCatalog::new(),
        None,
    );
    let resp = gw
        .generate(ctx_for("llama", None, vec![], false, None, false))
        .await
        .expect("ok");
    assert_eq!(resp.text, "phone");
    assert_eq!(phone.chats.load(Ordering::SeqCst), 1);
    assert_eq!(mac.chats.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn t133_failover_pre_first_token_gateway() {
    let fast = Arc::new(ScriptedPort::chat_only(vec![Err(
        InferenceBackendError::Provider("connection refused".into()),
    )]));
    let slow = Arc::new(ScriptedPort::chat_only(vec![Ok(ScriptedPort::ok(
        "slow-ok",
    ))]));
    let mut registry = InferenceBackendRegistry::new();
    registry.insert("fast", fast.clone());
    registry.insert("slow", slow.clone());
    let mut cat = ModelProfileCatalog::new();
    let (id_a, p_a) = profile("p-fast", CatalogTier::Stable);
    let (id_b, p_b) = profile("p-slow", CatalogTier::Experimental);
    cat.insert(id_a, p_a).unwrap();
    cat.insert(id_b, p_b).unwrap();
    let (gw, _, _, bus) = gateway(
        vec![
            provider(
                "fast",
                InferenceBackendClass::Local,
                "llama",
                Some("p-fast"),
            ),
            provider(
                "slow",
                InferenceBackendClass::Local,
                "llama",
                Some("p-slow"),
            ),
        ],
        registry,
        MapTel {
            ttft: HashMap::from([("fast".into(), 1), ("slow".into(), 90)]),
        },
        cat,
        None,
    );
    let resp = gw
        .generate(ctx_for("llama", Some("rid"), vec![], false, None, false))
        .await
        .expect("failover");
    assert_eq!(resp.text, "slow-ok");
    assert_eq!(fast.chats.load(Ordering::SeqCst), 1);
    assert_eq!(slow.chats.load(Ordering::SeqCst), 1);
    let reqs: Vec<_> = bus
        .snapshot()
        .into_iter()
        .filter(|e| e.event_type == crate::LLM_REQUEST)
        .collect();
    assert_eq!(reqs.len(), 2);
    assert_eq!(reqs[0].payload["endpoint_id"], "fast");
    assert_eq!(reqs[1].payload["endpoint_id"], "slow");
    let d1 = fast.deadlines.lock().unwrap()[0];
    let d2 = slow.deadlines.lock().unwrap()[0];
    assert_eq!(d1, d2, "req.deadline must not refresh per hop");
}

#[tokio::test]
async fn t133_deadline_not_refreshed_per_hop() {
    let a = Arc::new(ScriptedPort::chat_only(vec![Err(
        InferenceBackendError::Provider("connection refused".into()),
    )]));
    *a.chat_delay.lock().unwrap() = Some(Duration::from_millis(80));
    let b = Arc::new(ScriptedPort::chat_only(vec![Ok(ScriptedPort::ok("b"))]));
    let mut registry = InferenceBackendRegistry::new();
    registry.insert("a", a.clone());
    registry.insert("b", b.clone());
    let (gw, _, _, _) = gateway(
        vec![
            provider("a", InferenceBackendClass::Local, "llama", None),
            provider("b", InferenceBackendClass::Local, "llama", None),
        ],
        registry,
        MapTel {
            ttft: HashMap::from([("a".into(), 1), ("b".into(), 50)]),
        },
        ModelProfileCatalog::new(),
        None,
    );
    gw.generate(ctx_for("llama", None, vec![], false, None, false))
        .await
        .expect("ok");
    let d1 = a.deadlines.lock().unwrap()[0];
    let d2 = b.deadlines.lock().unwrap()[0];
    assert_eq!(d1, d2, "req.deadline must be the same Instant after a delayed first hop");
}

#[tokio::test(start_paused = true)]
async fn t133_rate_limited_does_not_failover() {
    let h_chain = Arc::new(MockHttpSecurityChain::default());
    h_chain.push_response(
        "/v1/chat/completions",
        Err(HttpError::RateLimited { retry_after_ms: 0 }),
    );
    h_chain.push_response(
        "/v1/chat/completions",
        Ok({
            let body = serde_json::json!({
                "choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1},
                "model": "gpt-4o-mini",
            });
            advance_shared_types::security_validator::HttpResponse {
                status: 200,
                headers: vec![],
                body: serde_json::to_vec(&body).unwrap(),
            }
        }),
    );
    let cfg = fixture_runtime_config();
    let budget = Arc::new(MockRunBudget::default());
    let bus = Arc::new(MockEventBusEmit::default());
    let gw = LlmGateway::new(
        Arc::new(MockRuntimeConfigProvider::new(cfg)),
        h_chain.clone(),
        budget,
        bus.clone(),
        no_op_repetition_guard(),
        "test-agent".into(),
    );
    let gw = Arc::new(gw);
    let task = tokio::spawn({
        let gw = Arc::clone(&gw);
        async move { gw.chat(vec![user_msg("hi")], ChatParams::default()).await }
    });
    tokio::time::advance(Duration::from_millis(
        crate::executor::MAX_DELAY_MS_HARD_CAP + 1,
    ))
    .await;
    assert!(task.await.unwrap().is_ok());
    let reqs = bus
        .snapshot()
        .into_iter()
        .filter(|e| e.event_type == crate::LLM_REQUEST)
        .count();
    assert_eq!(reqs, 1, "rate-limited must inner-retry, not hop");
    assert_eq!(h_chain.call_log.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn t133_cascade_structured_output_to_stronger() {
    let fast = Arc::new(ScriptedPort::chat_only(vec![Ok(ScriptedPort::ok(
        r#"{"x":"no"}"#,
    ))]));
    let mid = Arc::new(ScriptedPort::chat_only(vec![Ok(ScriptedPort::ok(
        r#"{"x":1}"#,
    ))]));
    let slow = Arc::new(ScriptedPort::chat_only(vec![Ok(ScriptedPort::ok(
        r#"{"x":2}"#,
    ))]));
    let mut registry = InferenceBackendRegistry::new();
    registry.insert("fast", fast.clone());
    registry.insert("mid", mid.clone());
    registry.insert("slow", slow.clone());
    let mut cat = ModelProfileCatalog::new();
    let (a, pa) = profile("p-fast", CatalogTier::Experimental);
    let (b, pb) = profile("p-mid", CatalogTier::Experimental);
    let (c, pc) = profile("p-slow", CatalogTier::Stable);
    cat.insert(a, pa).unwrap();
    cat.insert(b, pb).unwrap();
    cat.insert(c, pc).unwrap();
    let (gw, _, budget, _) = gateway(
        vec![
            provider(
                "fast",
                InferenceBackendClass::Local,
                "llama",
                Some("p-fast"),
            ),
            provider("mid", InferenceBackendClass::Local, "llama", Some("p-mid")),
            provider(
                "slow",
                InferenceBackendClass::Local,
                "llama",
                Some("p-slow"),
            ),
        ],
        registry,
        MapTel {
            ttft: HashMap::from([("fast".into(), 1), ("mid".into(), 2), ("slow".into(), 100)]),
        },
        cat,
        None,
    );
    let resp = gw
        .generate(ctx_for(
            "llama",
            Some("rid"),
            vec![],
            false,
            Some(SCHEMA),
            false,
        ))
        .await
        .expect("cascade");
    assert_eq!(resp.text, r#"{"x":2}"#);
    assert_eq!(
        fast.chats.load(Ordering::SeqCst),
        3,
        "inner structured repair then exhaust before cascade"
    );
    assert_eq!(
        mid.chats.load(Ordering::SeqCst),
        0,
        "weaker-equal must not hop"
    );
    assert_eq!(slow.chats.load(Ordering::SeqCst), 1);
    let slow_msgs = slow.seen_messages.lock().unwrap();
    assert_eq!(slow_msgs.len(), 1);
    assert!(
        slow_msgs[0]
            .iter()
            .all(|m| !m.content.contains("schema validation")),
        "inner schema-repair User turns must not leak into the next hop, got {:?}",
        slow_msgs[0]
    );
    assert_eq!(
        budget.commits.lock().unwrap().len(),
        2,
        "schema-fail hop commits as error-terminal; winner commits once"
    );
}

#[tokio::test]
async fn t133_schema_then_transport_does_not_failover() {
    let fast = Arc::new(ScriptedPort::chat_only(vec![
        Ok(ScriptedPort::ok(r#"{"x":"no"}"#)),
        Err(InferenceBackendError::Provider("connection refused".into())),
    ]));
    let slow = Arc::new(ScriptedPort::chat_only(vec![Ok(ScriptedPort::ok(
        r#"{"x":2}"#,
    ))]));
    let mut registry = InferenceBackendRegistry::new();
    registry.insert("fast", fast.clone());
    registry.insert("slow", slow.clone());
    let mut cat = ModelProfileCatalog::new();
    let (a, pa) = profile("p-fast", CatalogTier::Experimental);
    let (b, pb) = profile("p-slow", CatalogTier::Stable);
    cat.insert(a, pa).unwrap();
    cat.insert(b, pb).unwrap();
    let (gw, _, budget, _) = gateway(
        vec![
            provider(
                "fast",
                InferenceBackendClass::Local,
                "llama",
                Some("p-fast"),
            ),
            provider(
                "slow",
                InferenceBackendClass::Local,
                "llama",
                Some("p-slow"),
            ),
        ],
        registry,
        MapTel {
            ttft: HashMap::from([("fast".into(), 1), ("slow".into(), 80)]),
        },
        cat,
        None,
    );
    let err = gw
        .generate(ctx_for(
            "llama",
            Some("rid"),
            vec![],
            false,
            Some(SCHEMA),
            false,
        ))
        .await
        .expect_err("must not hop after in-hop tokens");
    let s = err.to_string();
    assert!(
        s.contains("connection refused"),
        "expected the in-hop transport error, got {s}"
    );
    assert_eq!(fast.chats.load(Ordering::SeqCst), 2);
    assert_eq!(
        slow.chats.load(Ordering::SeqCst),
        0,
        "tokens already released on this hop; transport must not pre-token failover"
    );
    assert_eq!(
        budget.commits.lock().unwrap().len(),
        1,
        "released tokens must commit on the transport terminal"
    );
}

#[tokio::test]
async fn t133_schema_zero_usage_then_transport_does_not_failover() {
    let fast = Arc::new(ScriptedPort::chat_only(vec![
        Ok(ScriptedPort::ok_usage(r#"{"x":"no"}"#, 0, 0)),
        Err(InferenceBackendError::Provider("connection refused".into())),
    ]));
    let slow = Arc::new(ScriptedPort::chat_only(vec![Ok(ScriptedPort::ok(
        r#"{"x":2}"#,
    ))]));
    let mut registry = InferenceBackendRegistry::new();
    registry.insert("fast", fast.clone());
    registry.insert("slow", slow.clone());
    let mut cat = ModelProfileCatalog::new();
    let (a, pa) = profile("p-fast", CatalogTier::Experimental);
    let (b, pb) = profile("p-slow", CatalogTier::Stable);
    cat.insert(a, pa).unwrap();
    cat.insert(b, pb).unwrap();
    let (gw, _, _, _) = gateway(
        vec![
            provider(
                "fast",
                InferenceBackendClass::Local,
                "llama",
                Some("p-fast"),
            ),
            provider(
                "slow",
                InferenceBackendClass::Local,
                "llama",
                Some("p-slow"),
            ),
        ],
        registry,
        MapTel {
            ttft: HashMap::from([("fast".into(), 1), ("slow".into(), 80)]),
        },
        cat,
        None,
    );
    let err = gw
        .generate(ctx_for(
            "llama",
            Some("rid"),
            vec![],
            false,
            Some(SCHEMA),
            false,
        ))
        .await
        .expect_err("zero-usage completion is still past first token");
    assert!(err.to_string().contains("connection refused"));
    assert_eq!(fast.chats.load(Ordering::SeqCst), 2);
    assert_eq!(
        slow.chats.load(Ordering::SeqCst),
        0,
        "a completed (invalid) hop must not pre-token failover even when usage is 0"
    );
}

#[tokio::test]
async fn t133_failed_spawn_does_not_skip_as_unwired() {
    let mut registry = InferenceBackendRegistry::new();
    registry.insert(
        "fast",
        Arc::new(FailedSpawnBackend {
            reason: "spawn: handshake timeout".into(),
        }),
    );
    let chain = Arc::new(MockHttpSecurityChain::default());
    chain.push_response("/v1/chat/completions", Ok(openai_chat_http("cloud-hit")));
    let mut cfg = fixture_runtime_config();
    cfg.llm_providers = vec![
        provider("fast", InferenceBackendClass::Local, "llama", None),
        provider("slow", InferenceBackendClass::CloudHttp, "llama", None),
    ];
    let bus = Arc::new(MockEventBusEmit::default());
    let gw = LlmGateway::new(
        Arc::new(MockRuntimeConfigProvider::new(cfg)),
        chain.clone(),
        Arc::new(MockRunBudget::default()),
        bus.clone(),
        no_op_repetition_guard(),
        "test-agent".into(),
    )
    .with_inference_backends(registry)
    .with_placement_telemetry(Arc::new(MapTel {
        ttft: HashMap::from([("fast".into(), 1), ("slow".into(), 80)]),
    }));
    let err = gw
        .generate(ctx_for("llama", Some("rid"), vec![], false, None, false))
        .await
        .expect_err("FailedSpawn must fail-closed, not hop as not-wired");
    let s = err.to_string();
    assert!(
        s.contains("handshake timeout") || s.contains("spawn:"),
        "must surface the spawn reason, got {s}"
    );
    assert!(
        !s.contains("not wired"),
        "must not rewrite FailedSpawn into not-wired, got {s}"
    );
    assert_eq!(
        chain.call_log.lock().unwrap().len(),
        0,
        "must not fail-open onto CloudHttp"
    );
}

fn openai_chat_http(content: &str) -> HttpResponse {
    openai_chat_http_usage(content, 1, 1)
}

fn openai_chat_http_usage(content: &str, in_tok: u64, out_tok: u64) -> HttpResponse {
    let body = serde_json::json!({
        "choices": [{"message": {"content": content}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": in_tok, "completion_tokens": out_tok},
        "model": "gpt-4o-mini",
    });
    HttpResponse {
        status: 200,
        headers: vec![],
        body: serde_json::to_vec(&body).unwrap(),
    }
}

#[tokio::test]
async fn t133_cloud_http_schema_then_transport_does_not_failover() {
    let chain = Arc::new(MockHttpSecurityChain::default());
    chain.push_response("/v1/chat/completions", Ok(openai_chat_http(r#"{"x":"no"}"#)));
    chain.push_response(
        "/v1/chat/completions",
        Err(HttpError::Transport(TransportErrorKind::ConnectionRefused)),
    );
    chain.push_response("/v1/chat/completions", Ok(openai_chat_http(r#"{"x":2}"#)));
    let one_retry = Some(RetryDefaults {
        max_retries: 1,
        base_delay_ms: 1,
        max_delay_ms: 2,
    });
    let mut fast = provider(
        "fast",
        InferenceBackendClass::CloudHttp,
        "llama",
        None,
    );
    let mut slow = provider(
        "slow",
        InferenceBackendClass::CloudHttp,
        "llama",
        None,
    );
    fast.retry_default = one_retry.clone();
    slow.retry_default = one_retry;
    let mut cfg = fixture_runtime_config();
    cfg.llm_providers = vec![fast, slow];
    let budget = Arc::new(MockRunBudget::default());
    let gw = LlmGateway::new(
        Arc::new(MockRuntimeConfigProvider::new(cfg)),
        chain.clone(),
        budget.clone(),
        Arc::new(MockEventBusEmit::default()),
        no_op_repetition_guard(),
        "test-agent".into(),
    )
    .with_placement_telemetry(Arc::new(MapTel {
        ttft: HashMap::from([("fast".into(), 1), ("slow".into(), 80)]),
    }));
    let err = gw
        .generate(ctx_for(
            "llama",
            Some("rid"),
            vec![],
            false,
            Some(SCHEMA),
            false,
        ))
        .await
        .expect_err("must not hop after CloudHttp in-hop tokens");
    let s = err.to_string();
    assert!(
        s.contains("connection refused"),
        "expected the in-hop transport error, got {s}"
    );
    assert_eq!(
        chain.call_log.lock().unwrap().len(),
        2,
        "schema then transport on the first CloudHttp hop; second endpoint must not execute"
    );
    assert_eq!(
        budget.commits.lock().unwrap().len(),
        1,
        "released CloudHttp tokens must commit on the transport terminal"
    );
}

#[tokio::test]
async fn t133_cloud_http_schema_zero_usage_then_transport_does_not_failover() {
    let chain = Arc::new(MockHttpSecurityChain::default());
    chain.push_response(
        "/v1/chat/completions",
        Ok(openai_chat_http_usage(r#"{"x":"no"}"#, 0, 0)),
    );
    chain.push_response(
        "/v1/chat/completions",
        Err(HttpError::Transport(TransportErrorKind::ConnectionRefused)),
    );
    chain.push_response("/v1/chat/completions", Ok(openai_chat_http(r#"{"x":2}"#)));
    let one_retry = Some(RetryDefaults {
        max_retries: 1,
        base_delay_ms: 1,
        max_delay_ms: 2,
    });
    let mut fast = provider("fast", InferenceBackendClass::CloudHttp, "llama", None);
    let mut slow = provider("slow", InferenceBackendClass::CloudHttp, "llama", None);
    fast.retry_default = one_retry.clone();
    slow.retry_default = one_retry;
    let mut cfg = fixture_runtime_config();
    cfg.llm_providers = vec![fast, slow];
    let gw = LlmGateway::new(
        Arc::new(MockRuntimeConfigProvider::new(cfg)),
        chain.clone(),
        Arc::new(MockRunBudget::default()),
        Arc::new(MockEventBusEmit::default()),
        no_op_repetition_guard(),
        "test-agent".into(),
    )
    .with_placement_telemetry(Arc::new(MapTel {
        ttft: HashMap::from([("fast".into(), 1), ("slow".into(), 80)]),
    }));
    let err = gw
        .generate(ctx_for(
            "llama",
            Some("rid"),
            vec![],
            false,
            Some(SCHEMA),
            false,
        ))
        .await
        .expect_err("zero-usage CloudHttp completion is still past first token");
    assert!(err.to_string().contains("connection refused"));
    assert_eq!(
        chain.call_log.lock().unwrap().len(),
        2,
        "must not hop after a zero-usage schema completion"
    );
}

#[tokio::test]
async fn t133_cloud_http_schema_then_budget_deny_commits() {
    let chain = Arc::new(MockHttpSecurityChain::default());
    chain.push_response("/v1/chat/completions", Ok(openai_chat_http(r#"{"x":"no"}"#)));
    chain.push_response("/v1/chat/completions", Ok(openai_chat_http(r#"{"x":2}"#)));
    let mut cfg = fixture_runtime_config();
    cfg.llm_providers = vec![
        provider("fast", InferenceBackendClass::CloudHttp, "llama", None),
        provider("slow", InferenceBackendClass::CloudHttp, "llama", None),
    ];
    let budget = Arc::new(MockRunBudget::default());
    budget.deny_when_tokens_positive("rid", "cap");
    let gw = LlmGateway::new(
        Arc::new(MockRuntimeConfigProvider::new(cfg)),
        chain.clone(),
        budget.clone(),
        Arc::new(MockEventBusEmit::default()),
        no_op_repetition_guard(),
        "test-agent".into(),
    )
    .with_placement_telemetry(Arc::new(MapTel {
        ttft: HashMap::from([("fast".into(), 1), ("slow".into(), 80)]),
    }));
    let err = gw
        .generate(ctx_for(
            "llama",
            Some("rid"),
            vec![],
            false,
            Some(SCHEMA),
            false,
        ))
        .await
        .expect_err("budget deny after billed schema-repair");
    let s = err.to_string();
    assert!(
        s.contains("BudgetExceeded") || s.contains("cost cap") || s.contains("cap"),
        "expected BudgetExceeded, got {s}"
    );
    assert_eq!(
        chain.call_log.lock().unwrap().len(),
        1,
        "must not hop after billed tokens on budget deny"
    );
    assert_eq!(
        budget.commits.lock().unwrap().len(),
        1,
        "CloudHttp budget-deny after schema tokens must commit"
    );
}

#[tokio::test]
async fn t133_cloud_http_schema_then_deadline_is_deadline_not_cascade() {
    let chain = Arc::new(MockHttpSecurityChain::default());
    chain.push_response("/v1/chat/completions", Ok(openai_chat_http(r#"{"x":"no"}"#)));
    chain.push_response("/v1/chat/completions", Ok(openai_chat_http(r#"{"x":2}"#)));
    *chain.execute_delay.lock().unwrap() = Some(Duration::from_secs(5));
    *chain.execute_delay_from_call.lock().unwrap() = Some(2);
    let mut cfg = fixture_runtime_config();
    cfg.llm_providers = vec![
        provider("fast", InferenceBackendClass::CloudHttp, "llama", None),
        provider("slow", InferenceBackendClass::CloudHttp, "llama", None),
    ];
    let budget = Arc::new(MockRunBudget::default());
    let gw = LlmGateway::new(
        Arc::new(MockRuntimeConfigProvider::new(cfg)),
        chain.clone(),
        budget.clone(),
        Arc::new(MockEventBusEmit::default()),
        no_op_repetition_guard(),
        "test-agent".into(),
    )
    .with_generate_timeout(Duration::from_millis(80))
    .with_placement_telemetry(Arc::new(MapTel {
        ttft: HashMap::from([("fast".into(), 1), ("slow".into(), 80)]),
    }));
    let err = gw
        .generate(ctx_for(
            "llama",
            Some("rid"),
            vec![],
            false,
            Some(SCHEMA),
            false,
        ))
        .await
        .expect_err("deadline after billed schema-repair");
    let s = err.to_string();
    assert!(
        s.contains("deadline-exceeded"),
        "timeout after schema tokens must stay deadline-exceeded, not cascade SOF, got {s}"
    );
    assert!(
        !s.contains("StructuredOutputFailed") && !s.contains("schema"),
        "must not masquerade timeout as schema cascade, got {s}"
    );
    assert_eq!(
        chain.call_log.lock().unwrap().len(),
        2,
        "second CloudHttp endpoint must not run after deadline"
    );
    assert_eq!(
        budget.commits.lock().unwrap().len(),
        1,
        "deadline after billed CloudHttp tokens must commit"
    );
}

#[tokio::test]
async fn t133_hard_class_escalates_to_stronger() {
    let fast = Arc::new(ScriptedPort::chat_only(vec![Ok(ScriptedPort::ok("low"))]));
    let mid = Arc::new(ScriptedPort::chat_only(vec![Ok(ScriptedPort::ok("mid"))]));
    let slow = Arc::new(ScriptedPort::chat_only(vec![Ok(ScriptedPort::ok("high"))]));
    let mut registry = InferenceBackendRegistry::new();
    registry.insert("fast", fast.clone());
    registry.insert("mid", mid.clone());
    registry.insert("slow", slow.clone());
    let mut cat = ModelProfileCatalog::new();
    let (a, pa) = profile("p-fast", CatalogTier::Experimental);
    let (b, pb) = profile("p-mid", CatalogTier::Experimental);
    let (c, pc) = profile("p-slow", CatalogTier::Stable);
    cat.insert(a, pa).unwrap();
    cat.insert(b, pb).unwrap();
    cat.insert(c, pc).unwrap();
    let (gw, _, budget, _) = gateway(
        vec![
            provider(
                "fast",
                InferenceBackendClass::Local,
                "llama",
                Some("p-fast"),
            ),
            provider("mid", InferenceBackendClass::Local, "llama", Some("p-mid")),
            provider(
                "slow",
                InferenceBackendClass::Local,
                "llama",
                Some("p-slow"),
            ),
        ],
        registry,
        MapTel {
            ttft: HashMap::from([("fast".into(), 1), ("mid".into(), 2), ("slow".into(), 100)]),
        },
        cat,
        None,
    );
    let resp = gw
        .generate(ctx_for("llama", Some("rid"), vec![], true, None, false))
        .await
        .expect("hard-class");
    assert_eq!(resp.text, "high");
    assert_eq!(fast.chats.load(Ordering::SeqCst), 1);
    assert_eq!(mid.chats.load(Ordering::SeqCst), 0);
    assert_eq!(slow.chats.load(Ordering::SeqCst), 1);
    assert_eq!(budget.commits.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn t133_single_provider_schema_exhaust_keeps_typed_error() {
    let port = Arc::new(ScriptedPort::chat_only(vec![Ok(ScriptedPort::ok(
        r#"{"x":"no"}"#,
    ))]));
    let mut registry = InferenceBackendRegistry::new();
    registry.insert("only", port);
    let (gw, _, budget, _) = gateway(
        vec![provider(
            "only",
            InferenceBackendClass::Local,
            "llama",
            None,
        )],
        registry,
        MapTel {
            ttft: HashMap::from([("only".into(), 1)]),
        },
        ModelProfileCatalog::new(),
        None,
    );
    let err = gw
        .generate(ctx_for(
            "llama",
            Some("rid"),
            vec![],
            false,
            Some(SCHEMA),
            false,
        ))
        .await
        .expect_err("exhaust");
    assert!(
        matches!(err, LlmError::StructuredOutputFailed(_)),
        "got {err:?}"
    );
    assert!(!matches!(err, LlmError::ModelNotAvailable(_)));
    assert_eq!(budget.commits.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn t133_failover_tee_one_begin_winner_completed() {
    let rec = Arc::new(FrameRec::default());
    let fast = Arc::new(ScriptedPort::chat_only(vec![Err(
        InferenceBackendError::Provider("connection refused".into()),
    )]));
    let slow = Arc::new(ScriptedPort::chat_only(vec![Ok(ScriptedPort::ok(
        "winner-text",
    ))]));
    let mut registry = InferenceBackendRegistry::new();
    registry.insert("fast", fast);
    registry.insert("slow", slow);
    let (gw, _, _, _) = gateway(
        vec![
            provider("fast", InferenceBackendClass::Local, "llama", None),
            provider("slow", InferenceBackendClass::Local, "llama", None),
        ],
        registry,
        MapTel {
            ttft: HashMap::from([("fast".into(), 1), ("slow".into(), 50)]),
        },
        ModelProfileCatalog::new(),
        Some(rec.clone()),
    );
    let resp = gw
        .generate(ctx_for("llama", None, vec![], false, None, true))
        .await
        .expect("ok");
    assert_eq!(resp.text, "winner-text");
    let frames = rec.frames();
    let begins = frames
        .iter()
        .filter(|f| matches!(f, LlmDeltaFrame::Begin { .. }))
        .count();
    assert_eq!(begins, 1, "{frames:?}");
    let concat: String = frames
        .iter()
        .filter_map(|f| match f {
            LlmDeltaFrame::Delta { text, .. } => Some(text.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(concat, "winner-text");
    assert!(
        matches!(
            frames.last(),
            Some(LlmDeltaFrame::Terminal {
                reason: LlmTerminalReason::Completed,
                ..
            })
        ),
        "{frames:?}"
    );
    assert!(
        !frames.iter().any(|f| matches!(
            f,
            LlmDeltaFrame::Terminal {
                reason: LlmTerminalReason::ProviderError,
                ..
            }
        )),
        "refused hop must not publish ProviderError terminal, got {frames:?}"
    );
}

#[tokio::test]
async fn t133_hard_class_tee_winner_only() {
    let rec = Arc::new(FrameRec::default());
    let fast = Arc::new(ScriptedPort::chat_only(vec![Ok(ScriptedPort::ok("low"))]));
    let mid = Arc::new(ScriptedPort::chat_only(vec![Ok(ScriptedPort::ok("mid"))]));
    let slow = Arc::new(ScriptedPort::chat_only(vec![Ok(ScriptedPort::ok("high"))]));
    let mut registry = InferenceBackendRegistry::new();
    registry.insert("fast", fast);
    registry.insert("mid", mid.clone());
    registry.insert("slow", slow);
    let mut cat = ModelProfileCatalog::new();
    let (a, pa) = profile("p-fast", CatalogTier::Experimental);
    let (b, pb) = profile("p-mid", CatalogTier::Experimental);
    let (c, pc) = profile("p-slow", CatalogTier::Stable);
    cat.insert(a, pa).unwrap();
    cat.insert(b, pb).unwrap();
    cat.insert(c, pc).unwrap();
    let (gw, _, _, _) = gateway(
        vec![
            provider(
                "fast",
                InferenceBackendClass::Local,
                "llama",
                Some("p-fast"),
            ),
            provider("mid", InferenceBackendClass::Local, "llama", Some("p-mid")),
            provider(
                "slow",
                InferenceBackendClass::Local,
                "llama",
                Some("p-slow"),
            ),
        ],
        registry,
        MapTel {
            ttft: HashMap::from([("fast".into(), 1), ("mid".into(), 2), ("slow".into(), 100)]),
        },
        cat,
        Some(rec.clone()),
    );
    let resp = gw
        .generate(ctx_for("llama", None, vec![], true, None, true))
        .await
        .expect("ok");
    assert_eq!(resp.text, "high");
    assert_eq!(mid.chats.load(Ordering::SeqCst), 0);
    let frames = rec.frames();
    let begins = frames
        .iter()
        .filter(|f| matches!(f, LlmDeltaFrame::Begin { .. }))
        .count();
    assert_eq!(begins, 1, "{frames:?}");
    let concat: String = frames
        .iter()
        .filter_map(|f| match f {
            LlmDeltaFrame::Delta { text, .. } => Some(text.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(concat, "high");
    assert!(matches!(
        frames.last(),
        Some(LlmDeltaFrame::Terminal {
            reason: LlmTerminalReason::Completed,
            ..
        })
    ));
}

#[tokio::test]
async fn t133_mid_stream_break_is_partial_not_splice() {
    let port = Arc::new(ScriptedPort::chat_only(vec![]));
    *port.stream_script.lock().unwrap() = StreamScript::BreakHello;
    let second = Arc::new(ScriptedPort::chat_only(vec![]));
    *second.stream_script.lock().unwrap() = StreamScript::PanicHop;
    let mut registry = InferenceBackendRegistry::new();
    registry.insert("fast", port.clone());
    registry.insert("slow", second);
    let chain = Arc::new(MockHttpSecurityChain::default());
    let bus = Arc::new(MockEventBusEmit::default());
    let mut cfg = fixture_runtime_config();
    cfg.llm_providers = vec![
        provider("fast", InferenceBackendClass::Local, "llama", None),
        provider("slow", InferenceBackendClass::Local, "llama", None),
    ];
    let gw = LlmGateway::new(
        Arc::new(MockRuntimeConfigProvider::new(cfg)),
        chain.clone(),
        Arc::new(MockRunBudget::default()),
        bus.clone(),
        no_op_repetition_guard(),
        "test-agent".into(),
    )
    .with_inference_backends(registry)
    .with_placement_telemetry(Arc::new(MapTel {
        ttft: HashMap::from([("fast".into(), 1), ("slow".into(), 90)]),
    }))
    .with_live_streaming(
        chain as Arc<dyn HttpStreamingChain>,
        Arc::new(DefaultLeakDetector::default()),
    );
    let streams = Arc::new(StreamRegistry::new());
    let handle = gw
        .stream_begin_live(ctx_for("llama", None, vec![], false, None, false), &streams)
        .await
        .expect("begin");
    let mut visible = String::new();
    let terminal = loop {
        match tokio::time::timeout(
            Duration::from_secs(5),
            streams.poll_live(handle, "test-agent"),
        )
        .await
        .expect("poll")
        {
            PollOutcome::Delta(d) => visible.push_str(&d),
            PollOutcome::Done(_) => {
                panic!("expected Failed after released bytes, visible={visible}")
            }
            PollOutcome::Failed(e) => break e,
            PollOutcome::Unknown => panic!("unknown handle"),
        }
    };
    let msg = terminal.to_string();
    assert!(
        msg.contains("stream-partial:"),
        "expected stream-partial after released bytes, got {msg} visible={visible:?}"
    );
    let reqs = bus
        .snapshot()
        .into_iter()
        .filter(|e| e.event_type == crate::LLM_REQUEST)
        .count();
    assert_eq!(reqs, 1, "live stream places once");
    assert_eq!(port.streams.load(Ordering::SeqCst), 1);
}

#[test]
fn t133_wrap_stream_partial_only_after_released_bytes() {
    let bare = crate::gateway::wrap_stream_partial(
        LlmError::ProviderError("stream eof before terminal".into()),
        0,
    );
    assert!(
        !bare.to_string().contains("stream-partial:"),
        "zero released bytes must keep the bare S4 error, got {bare}"
    );
    let prefixed = crate::gateway::wrap_stream_partial(
        LlmError::ProviderError("stream eof before terminal".into()),
        5,
    );
    assert!(
        prefixed.to_string().contains("stream-partial:"),
        "released_bytes>0 must prefix stream-partial, got {prefixed}"
    );
}

#[tokio::test]
async fn t133_mid_stream_break_zero_release_is_bare_error() {
    let port = Arc::new(ScriptedPort::chat_only(vec![]));
    *port.stream_script.lock().unwrap() = StreamScript::BreakEmpty;
    let mut registry = InferenceBackendRegistry::new();
    registry.insert("fast", port.clone());
    let chain = Arc::new(MockHttpSecurityChain::default());
    let mut cfg = fixture_runtime_config();
    cfg.llm_providers = vec![provider(
        "fast",
        InferenceBackendClass::Local,
        "llama",
        None,
    )];
    let gw = LlmGateway::new(
        Arc::new(MockRuntimeConfigProvider::new(cfg)),
        chain.clone(),
        Arc::new(MockRunBudget::default()),
        Arc::new(MockEventBusEmit::default()),
        no_op_repetition_guard(),
        "test-agent".into(),
    )
    .with_inference_backends(registry)
    .with_live_streaming(
        chain as Arc<dyn HttpStreamingChain>,
        Arc::new(DefaultLeakDetector::default()),
    );
    let streams = Arc::new(StreamRegistry::new());
    let handle = gw
        .stream_begin_live(ctx_for("llama", None, vec![], false, None, false), &streams)
        .await
        .expect("begin");
    let terminal = loop {
        match tokio::time::timeout(
            Duration::from_secs(5),
            streams.poll_live(handle, "test-agent"),
        )
        .await
        .expect("poll")
        {
            PollOutcome::Delta(d) => panic!("zero-release must not emit a delta, got {d:?}"),
            PollOutcome::Done(_) => panic!("expected Failed with no released bytes"),
            PollOutcome::Failed(e) => break e,
            PollOutcome::Unknown => panic!("unknown handle"),
        }
    };
    let msg = terminal.to_string();
    assert!(
        !msg.contains("stream-partial:"),
        "zero released bytes must not wrap stream-partial, got {msg}"
    );
}

#[tokio::test]
async fn t133_cloud_http_inner_retry_aborts_at_hop_deadline() {
    let chain = Arc::new(MockHttpSecurityChain::default());
    *chain.execute_delay.lock().unwrap() = Some(Duration::from_secs(5));
    chain.push_response(
        "/v1/chat/completions",
        Err(HttpError::Transport(
            advance_shared_types::security_validator::TransportErrorKind::Other,
        )),
    );
    let mut cfg = fixture_runtime_config();
    cfg.llm_providers = vec![
        provider("a", InferenceBackendClass::CloudHttp, "llama", None),
        provider("b", InferenceBackendClass::CloudHttp, "llama", None),
    ];
    let gw = LlmGateway::new(
        Arc::new(MockRuntimeConfigProvider::new(cfg)),
        chain.clone(),
        Arc::new(MockRunBudget::default()),
        Arc::new(MockEventBusEmit::default()),
        no_op_repetition_guard(),
        "test-agent".into(),
    )
    .with_generate_timeout(Duration::from_millis(80))
    .with_placement_telemetry(Arc::new(MapTel {
        ttft: HashMap::from([("a".into(), 1), ("b".into(), 50)]),
    }));
    let started = Instant::now();
    let err = gw
        .generate(ctx_for("llama", None, vec![], false, None, false))
        .await
        .expect_err("hop deadline");
    let elapsed = started.elapsed();
    let s = err.to_string();
    assert!(
        s.contains("deadline-exceeded"),
        "CloudHttp AC-06 must abort at the generate hop deadline, got {s}"
    );
    assert_eq!(
        chain.call_log.lock().unwrap().len(),
        1,
        "must not start another CloudHttp attempt after hop deadline"
    );
    assert!(
        elapsed < Duration::from_millis(500),
        "execute remaining timeout must abort well before the 5s mock delay, elapsed={elapsed:?}"
    );
}

#[tokio::test]
async fn t133_cloud_http_ac06_sleep_clamped_to_hop_deadline() {
    let chain = Arc::new(MockHttpSecurityChain::default());
    chain.push_response(
        "/v1/chat/completions",
        Err(HttpError::Transport(
            advance_shared_types::security_validator::TransportErrorKind::Other,
        )),
    );
    let mut cfg = fixture_runtime_config();
    cfg.llm_providers = vec![provider(
        "a",
        InferenceBackendClass::CloudHttp,
        "llama",
        None,
    )];
    let gw = LlmGateway::new(
        Arc::new(MockRuntimeConfigProvider::new(cfg)),
        chain.clone(),
        Arc::new(MockRunBudget::default()),
        Arc::new(MockEventBusEmit::default()),
        no_op_repetition_guard(),
        "test-agent".into(),
    )
    .with_generate_timeout(Duration::from_millis(80))
    .with_retry_overrides(PartialRetry {
        max_retries: Some(3),
        base_delay_ms: Some(5_000),
        max_delay_ms: Some(5_000),
        jitter: Some(false),
    });
    let started = Instant::now();
    let err = gw
        .generate(ctx_for("llama", None, vec![], false, None, false))
        .await
        .expect_err("hop deadline");
    let elapsed = started.elapsed();
    let s = err.to_string();
    assert!(
        s.contains("deadline-exceeded") || s.contains("transport error"),
        "clamped AC-06 sleep must abort without waiting the 5s base delay, got {s}"
    );
    assert_eq!(
        chain.call_log.lock().unwrap().len(),
        1,
        "must not start a second CloudHttp attempt after clamped sleep"
    );
    assert!(
        elapsed < Duration::from_millis(500),
        "AC-06 sleep must clamp to remaining hop budget, not the 5s base delay, elapsed={elapsed:?}"
    );
}

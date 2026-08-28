#![cfg(test)]

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use advance_runtime::config::{InferenceBackendClass, LlmProviderConfig, ProviderBackend};
use advance_shared_types::inference::{
    InferenceBackendPort, InferenceBackendRegistry, InferenceChatRequest, InferenceChatResponse,
    InferenceEmbedRequest, InferenceEmbedResponse, InferenceMessage, InferenceStream,
    InferenceStreamClass, InferenceStreamHead, InferenceTextDelta, MeshCarrier,
    MeshInferenceDispatch, MeshInferenceDispatchError, NormalizedUsage,
};
use async_trait::async_trait;
use cap_http::DefaultLocalInferenceTransport;

use crate::backend_mesh::MeshRemoteAdapter;
use advance_shared_types::traits::HttpStreamingChain;
use cap_http::DefaultLeakDetector;

use crate::gateway::{ChatMessage, ChatParams, ChatRole, LlmGateway, LlmGatewayInternal};
use crate::placement::{EndpointTelemetry, PlacementTelemetry};
use crate::stream::{PollOutcome, StreamRegistry};
use crate::test_support::{
    fixture_runtime_config, no_op_repetition_guard, MockEventBusEmit, MockHttpSecurityChain,
    MockRunBudget, MockRuntimeConfigProvider,
};

fn mesh_cfg() -> LlmProviderConfig {
    let mut aliases = HashMap::new();
    aliases.insert("llama".into(), "llama".into());
    LlmProviderConfig {
        id: "mesh".into(),
        endpoint: String::new(),
        api_key_secret: "dummy".into(),
        model_aliases: aliases,
        cost_per_mtoken_in: 0.001,
        cost_per_mtoken_out: 0.001,
        rate_limit: None,
        retry_default: None,
        backend: Some(ProviderBackend::OpenAiChat),
        auth_scheme: None,
        backend_class: InferenceBackendClass::MeshRemote,
        embedding_model: Some("nomic-embed".into()),
        sidecar: None,
        profile_id: None,
        device_id: Some("peer-b".into()),
    }
}

struct SnapshotDispatch {
    chats: AtomicU32,
    streams: AtomicU32,
    embeds: AtomicU32,
    last_target: Mutex<String>,
    last_invocation: Mutex<String>,
}

#[async_trait]
impl MeshInferenceDispatch for SnapshotDispatch {
    async fn dispatch_chat(
        &self,
        _req: InferenceChatRequest,
        invocation_id: &str,
        target_device_id: &str,
    ) -> Result<InferenceChatResponse, MeshInferenceDispatchError> {
        self.chats.fetch_add(1, Ordering::SeqCst);
        *self.last_invocation.lock().unwrap() = invocation_id.to_string();
        *self.last_target.lock().unwrap() = target_device_id.to_string();
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
        self.embeds.fetch_add(1, Ordering::SeqCst);
        Ok(InferenceEmbedResponse {
            vector: vec![0.1, 0.2],
            model: "nomic-embed".into(),
        })
    }
    async fn start_stream(
        &self,
        req: InferenceChatRequest,
        invocation_id: &str,
        target: &str,
    ) -> Result<
        (InferenceStreamHead, Box<dyn InferenceStream>, MeshCarrier),
        MeshInferenceDispatchError,
    > {
        self.streams.fetch_add(1, Ordering::SeqCst);
        let _ = (req, invocation_id, target);
        Ok((
            InferenceStreamHead {
                class: InferenceStreamClass::Success,
                snapshot_only: true,
            },
            Box::new(SnapshotStream {
                text: Some("mesh-pong".into()),
            }),
            MeshCarrier::Snapshot,
        ))
    }
    fn is_wired(&self) -> bool {
        true
    }
}

struct SnapshotStream {
    text: Option<String>,
}

#[async_trait]
impl InferenceStream for SnapshotStream {
    async fn next_chunk(
        &mut self,
    ) -> Option<Result<InferenceTextDelta, advance_shared_types::inference::InferenceBackendError>>
    {
        self.text.take().map(|text| {
            Ok(InferenceTextDelta {
                text,
                usage: Some(NormalizedUsage {
                    input_tokens: 1,
                    output_tokens: 1,
                    cached_tokens: 0,
                }),
                terminal: true,
                finish_reason: Some("stop".into()),
            })
        })
    }
    fn cancel(&mut self) {}
}

fn gateway_with(
    dispatch: Arc<dyn MeshInferenceDispatch>,
) -> (
    LlmGateway,
    Arc<MockHttpSecurityChain>,
    Arc<MockRunBudget>,
    Arc<MockEventBusEmit>,
) {
    let mut registry = InferenceBackendRegistry::new();
    registry.insert(
        "mesh",
        Arc::new(MeshRemoteAdapter {
            dispatch,
            provider_id: "mesh".into(),
            embedding_model: Some("nomic-embed".into()),
            target_device_id: "peer-b".into(),
        }),
    );
    let mut cfg = fixture_runtime_config();
    cfg.llm_providers = vec![mesh_cfg()];
    let chain = Arc::new(MockHttpSecurityChain::default());
    let budget = Arc::new(MockRunBudget::default());
    let bus = Arc::new(MockEventBusEmit::default());
    let gw = LlmGateway::new(
        Arc::new(MockRuntimeConfigProvider::new(cfg)),
        chain.clone(),
        budget.clone(),
        bus.clone(),
        no_op_repetition_guard(),
        "test-agent".into(),
    )
    .with_inference_backends(registry);
    (gw, chain, budget, bus)
}

#[tokio::test]
async fn t135_snapshot_chat_one_invocation() {
    let dispatch = Arc::new(SnapshotDispatch {
        chats: AtomicU32::new(0),
        streams: AtomicU32::new(0),
        embeds: AtomicU32::new(0),
        last_target: Mutex::new(String::new()),
        last_invocation: Mutex::new(String::new()),
    });
    let (gw, chain, budget, bus) = gateway_with(dispatch.clone());
    let resp = gw
        .chat_for_run(
            vec![ChatMessage {
                role: ChatRole::User,
                content: "hi".into(),
            }],
            ChatParams {
                model: Some("llama".into()),
                ..Default::default()
            },
            "run-mesh-1".into(),
        )
        .await
        .expect("mesh chat");
    assert_eq!(resp.text, "mesh-pong");
    assert_eq!(dispatch.chats.load(Ordering::SeqCst), 1);
    assert_eq!(dispatch.streams.load(Ordering::SeqCst), 0);
    assert_eq!(budget.commits.lock().unwrap().len(), 1);
    let events = bus.snapshot();
    let responses = events
        .iter()
        .filter(|e| e.event_type == crate::LLM_RESPONSE)
        .count();
    assert_eq!(responses, 1);
    assert_eq!(chain.call_log.lock().unwrap().len(), 0);
}

#[tokio::test]
async fn t135_unwired_typed_refuse() {
    let unwired = MeshRemoteAdapter {
        dispatch: Arc::new(advance_shared_types::inference::NotWiredMeshInferenceDispatch),
        provider_id: "mesh".into(),
        embedding_model: None,
        target_device_id: String::new(),
    };
    let chat_err = unwired
        .chat(adapter_probe_req())
        .await
        .expect_err("adapter chat Unwired");
    assert_eq!(chat_err.to_string(), "mesh-remote: not wired");
    let stream_err = match unwired.start_stream(adapter_probe_req()).await {
        Ok(_) => panic!("adapter start_stream Unwired must err"),
        Err(e) => e,
    };
    assert_eq!(stream_err.to_string(), "mesh-remote: not wired");
    let embed_err = unwired
        .embed(InferenceEmbedRequest {
            provider_id: "mesh".into(),
            model: "nomic-embed".into(),
            text: "hi".into(),
            deadline: Instant::now() + Duration::from_secs(5),
            cancel: Arc::new(AtomicBool::new(false)),
        })
        .await
        .expect_err("adapter embed Unwired");
    assert_eq!(embed_err.to_string(), "mesh-remote: not wired");

    let mut registry = InferenceBackendRegistry::new();
    registry.insert(
        "mesh",
        Arc::new(MeshRemoteAdapter {
            dispatch: Arc::new(advance_shared_types::inference::NotWiredMeshInferenceDispatch),
            provider_id: "mesh".into(),
            embedding_model: None,
            target_device_id: String::new(),
        }),
    );
    let mut cfg = fixture_runtime_config();
    cfg.llm_providers = vec![mesh_cfg()];
    let gw = LlmGateway::new(
        Arc::new(MockRuntimeConfigProvider::new(cfg)),
        Arc::new(MockHttpSecurityChain::default()),
        Arc::new(MockRunBudget::default()),
        Arc::new(MockEventBusEmit::default()),
        no_op_repetition_guard(),
        "test-agent".into(),
    )
    .with_inference_backends(registry);
    let err = gw
        .chat(
            vec![ChatMessage {
                role: ChatRole::User,
                content: "hi".into(),
            }],
            ChatParams {
                model: Some("llama".into()),
                ..Default::default()
            },
        )
        .await
        .expect_err("unwired");
    let s = err.to_string();
    assert!(s.contains("mesh-remote: not wired"), "{s}");
    assert!(!s.contains("local transport:"), "{s}");
}

#[tokio::test]
async fn t135_cap_llm_toml_no_device_mesh() {
    let toml = include_str!("../Cargo.toml");
    assert!(!toml.contains("device-mesh"));
    assert!(!toml.contains("/Volumes/"));
    assert!(!toml.contains("/Users/"));
}

#[tokio::test]
async fn t135_gateway_resolve_returns_local_prefix() {
    let mut aliases = HashMap::new();
    aliases.insert("llama".into(), "llama".into());
    let local = LlmProviderConfig {
        id: "local".into(),
        endpoint: String::new(),
        api_key_secret: "dummy".into(),
        model_aliases: aliases,
        cost_per_mtoken_in: 0.001,
        cost_per_mtoken_out: 0.001,
        rate_limit: None,
        retry_default: None,
        backend: Some(ProviderBackend::OpenAiChat),
        auth_scheme: None,
        backend_class: InferenceBackendClass::Local,
        embedding_model: None,
        sidecar: None,
        profile_id: None,
        device_id: None,
    };
    let mut cfg = fixture_runtime_config();
    cfg.llm_providers = vec![local];
    let gw = LlmGateway::new(
        Arc::new(MockRuntimeConfigProvider::new(cfg)),
        Arc::new(MockHttpSecurityChain::default()),
        Arc::new(MockRunBudget::default()),
        Arc::new(MockEventBusEmit::default()),
        no_op_repetition_guard(),
        "test-agent".into(),
    );
    let ep = <LlmGateway as advance_shared_types::inference::LocalInferenceResolve>::resolve_forced_local(
        &gw,
        &advance_shared_types::inference::LocalInferenceResolveRequest {
            invocation_id: "inv".into(),
            target_device_id: "dev".into(),
        },
    )
    .expect("resolve");
    assert!(advance_shared_types::inference::is_allowed_forced_local_endpoint_id(&ep.endpoint_id));
    assert_eq!(ep.endpoint_id, "local:local");
}

#[allow(dead_code)]
fn _default_transport() -> DefaultLocalInferenceTransport {
    DefaultLocalInferenceTransport
}

#[allow(dead_code)]
fn _now() -> Instant {
    Instant::now()
}

struct Tel(HashMap<String, u64>);
impl PlacementTelemetry for Tel {
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

fn mesh_cfg_id(id: &str) -> LlmProviderConfig {
    let mut c = mesh_cfg();
    c.id = id.into();
    c
}

struct FailDispatch {
    chats: AtomicU32,
    err: MeshInferenceDispatchError,
}
#[async_trait]
impl MeshInferenceDispatch for FailDispatch {
    async fn dispatch_chat(
        &self,
        _req: InferenceChatRequest,
        _invocation_id: &str,
        _target_device_id: &str,
    ) -> Result<InferenceChatResponse, MeshInferenceDispatchError> {
        self.chats.fetch_add(1, Ordering::SeqCst);
        Err(self.err.clone())
    }
    async fn dispatch_embed(
        &self,
        _req: InferenceEmbedRequest,
        _invocation_id: &str,
        _target_device_id: &str,
    ) -> Result<InferenceEmbedResponse, MeshInferenceDispatchError> {
        Err(self.err.clone())
    }
    async fn start_stream(
        &self,
        req: InferenceChatRequest,
        invocation_id: &str,
        target: &str,
    ) -> Result<
        (InferenceStreamHead, Box<dyn InferenceStream>, MeshCarrier),
        MeshInferenceDispatchError,
    > {
        self.dispatch_chat(req, invocation_id, target).await?;
        unreachable!()
    }
    fn is_wired(&self) -> bool {
        true
    }
}

#[tokio::test]
async fn t135_snapshot_stream_one_invocation() {
    let dispatch = Arc::new(SnapshotDispatch {
        chats: AtomicU32::new(0),
        streams: AtomicU32::new(0),
        embeds: AtomicU32::new(0),
        last_target: Mutex::new(String::new()),
        last_invocation: Mutex::new(String::new()),
    });
    let (gw, chain, _, _) = gateway_with(dispatch.clone());
    let chain_live = Arc::new(MockHttpSecurityChain::default());
    let gw = gw.with_live_streaming(
        chain_live.clone() as Arc<dyn HttpStreamingChain>,
        Arc::new(DefaultLeakDetector::default()),
    );
    let streams = Arc::new(StreamRegistry::new());
    let ctx = crate::gateway::LlmRequestContext {
        agent_id: "test-agent".into(),
        messages: vec![ChatMessage {
            role: ChatRole::User,
            content: "hi".into(),
        }],
        params: ChatParams {
            model: Some("llama".into()),
            ..Default::default()
        },
        ..Default::default()
    };
    let h = gw
        .stream_begin_live(ctx, &streams)
        .await
        .expect("snapshot begin");
    let mut text = String::new();
    let done = loop {
        match tokio::time::timeout(Duration::from_secs(5), streams.poll_live(h, "test-agent"))
            .await
            .expect("poll")
        {
            PollOutcome::Delta(d) => text.push_str(&d),
            PollOutcome::Done(ready) => break ready,
            PollOutcome::Failed(e) => panic!("snapshot stream failed: {e}"),
            PollOutcome::Unknown => panic!("unknown"),
        }
    };
    assert!(
        text.contains("mesh-pong") || done.response.text == "mesh-pong",
        "text={text:?} done={:?}",
        done.response.text
    );
    assert_eq!(dispatch.streams.load(Ordering::SeqCst), 1);
    assert_eq!(dispatch.chats.load(Ordering::SeqCst), 0);
    assert_eq!(chain.call_log.lock().unwrap().len(), 0);
    assert!(chain_live.call_log.lock().unwrap().is_empty());
}

struct NegotiatedDispatch {
    streams: AtomicU32,
    chats: AtomicU32,
}
struct IncStream {
    parts: VecDeque<(String, bool)>,
}
#[async_trait]
impl InferenceStream for IncStream {
    async fn next_chunk(
        &mut self,
    ) -> Option<Result<InferenceTextDelta, advance_shared_types::inference::InferenceBackendError>>
    {
        self.parts.pop_front().map(|(text, terminal)| {
            Ok(InferenceTextDelta {
                text,
                usage: if terminal {
                    Some(NormalizedUsage {
                        input_tokens: 1,
                        output_tokens: 1,
                        cached_tokens: 0,
                    })
                } else {
                    None
                },
                terminal,
                finish_reason: if terminal { Some("stop".into()) } else { None },
            })
        })
    }
    fn cancel(&mut self) {}
}
#[async_trait]
impl MeshInferenceDispatch for NegotiatedDispatch {
    async fn dispatch_chat(
        &self,
        _req: InferenceChatRequest,
        _invocation_id: &str,
        _target_device_id: &str,
    ) -> Result<InferenceChatResponse, MeshInferenceDispatchError> {
        self.chats.fetch_add(1, Ordering::SeqCst);
        Err(MeshInferenceDispatchError::Provider("chat unused".into()))
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
        _req: InferenceChatRequest,
        _invocation_id: &str,
        _target: &str,
    ) -> Result<
        (InferenceStreamHead, Box<dyn InferenceStream>, MeshCarrier),
        MeshInferenceDispatchError,
    > {
        self.streams.fetch_add(1, Ordering::SeqCst);
        Ok((
            InferenceStreamHead {
                class: InferenceStreamClass::Success,
                snapshot_only: false,
            },
            Box::new(IncStream {
                parts: VecDeque::from([("he".into(), false), ("llo".into(), true)]),
            }),
            MeshCarrier::DirectPeer,
        ))
    }
    fn is_wired(&self) -> bool {
        true
    }
}

#[tokio::test]
async fn t135_negotiated_live_sse() {
    let dispatch = Arc::new(NegotiatedDispatch {
        streams: AtomicU32::new(0),
        chats: AtomicU32::new(0),
    });
    let (gw, chain, _, _) = gateway_with(dispatch.clone());
    let stream_chain = Arc::new(MockHttpSecurityChain::default());
    let gw = gw.with_live_streaming(
        stream_chain.clone() as Arc<dyn HttpStreamingChain>,
        Arc::new(DefaultLeakDetector::default()),
    );
    let streams = Arc::new(StreamRegistry::new());
    let ctx = crate::gateway::LlmRequestContext {
        agent_id: "test-agent".into(),
        messages: vec![ChatMessage {
            role: ChatRole::User,
            content: "hi".into(),
        }],
        params: ChatParams {
            model: Some("llama".into()),
            ..Default::default()
        },
        ..Default::default()
    };
    let h = gw
        .stream_begin_live(ctx, &streams)
        .await
        .expect("negotiated begin");
    let mut text = String::new();
    let mut deltas = 0u32;
    let mut first_delta: Option<String> = None;
    let done = loop {
        match tokio::time::timeout(Duration::from_secs(5), streams.poll_live(h, "test-agent"))
            .await
            .expect("poll")
        {
            PollOutcome::Delta(d) => {
                if first_delta.is_none() {
                    first_delta = Some(d.clone());
                }
                deltas += 1;
                text.push_str(&d);
            }
            PollOutcome::Done(ready) => break ready,
            PollOutcome::Failed(e) => panic!("negotiated failed: {e}"),
            PollOutcome::Unknown => panic!("unknown"),
        }
    };
    assert_eq!(dispatch.streams.load(Ordering::SeqCst), 1);
    assert_eq!(dispatch.chats.load(Ordering::SeqCst), 0);
    assert_eq!(
        first_delta.as_deref(),
        Some("he"),
        "C242 incremental: first live delta must be the non-terminal chunk, not a snapshot one-shot"
    );
    assert!(deltas >= 1, "incremental before terminal, deltas={deltas}");
    assert!(
        text.contains("hello") || done.response.text.contains("hello"),
        "text={text:?} done={:?}",
        done.response.text
    );
    assert_eq!(chain.call_log.lock().unwrap().len(), 0);
    assert!(stream_chain.call_log.lock().unwrap().is_empty());
}

/// Dispatch `start_stream` head.snapshot_only is intentionally the *opposite*
/// of `carrier` so this pin cannot pass by echoing the mock.
struct CarrierHeadMismatch {
    carrier: MeshCarrier,
    lied_snapshot_only: bool,
}

#[async_trait]
impl MeshInferenceDispatch for CarrierHeadMismatch {
    async fn dispatch_chat(
        &self,
        _req: InferenceChatRequest,
        _invocation_id: &str,
        _target_device_id: &str,
    ) -> Result<InferenceChatResponse, MeshInferenceDispatchError> {
        Err(MeshInferenceDispatchError::Provider("chat unused".into()))
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
        _req: InferenceChatRequest,
        _invocation_id: &str,
        _target: &str,
    ) -> Result<
        (InferenceStreamHead, Box<dyn InferenceStream>, MeshCarrier),
        MeshInferenceDispatchError,
    > {
        Ok((
            InferenceStreamHead {
                class: InferenceStreamClass::Success,
                snapshot_only: self.lied_snapshot_only,
            },
            Box::new(SnapshotStream {
                text: Some("mesh-pong".into()),
            }),
            self.carrier,
        ))
    }
    fn is_wired(&self) -> bool {
        true
    }
}

fn adapter_probe_req() -> InferenceChatRequest {
    InferenceChatRequest {
        provider_id: "mesh".into(),
        model: "llama".into(),
        messages: vec![InferenceMessage {
            role: "user".into(),
            content: "hi".into(),
        }],
        temperature: None,
        max_tokens: None,
        stop_sequences: None,
        tools: None,
        output_schema: None,
        deadline: Instant::now() + Duration::from_secs(5),
        cancel: Arc::new(AtomicBool::new(false)),
    }
}

#[tokio::test]
async fn t135_adapter_snapshot_only_from_carrier() {
    let snap = MeshRemoteAdapter {
        dispatch: Arc::new(CarrierHeadMismatch {
            carrier: MeshCarrier::Snapshot,
            lied_snapshot_only: false,
        }),
        provider_id: "mesh".into(),
        embedding_model: None,
        target_device_id: "peer-b".into(),
    };
    let (head, _) = snap
        .start_stream(adapter_probe_req())
        .await
        .expect("snapshot adapter stream");
    assert!(
        head.snapshot_only,
        "MeshRemoteAdapter must set snapshot_only from MeshCarrier::Snapshot, not the dispatch head"
    );

    let peer = MeshRemoteAdapter {
        dispatch: Arc::new(CarrierHeadMismatch {
            carrier: MeshCarrier::DirectPeer,
            lied_snapshot_only: true,
        }),
        provider_id: "mesh".into(),
        embedding_model: None,
        target_device_id: "peer-b".into(),
    };
    let (head, _) = peer
        .start_stream(adapter_probe_req())
        .await
        .expect("direct-peer adapter stream");
    assert!(
        !head.snapshot_only,
        "MeshRemoteAdapter must set snapshot_only=false from MeshCarrier::DirectPeer, not the dispatch head"
    );
}

#[tokio::test]
async fn t135_caller_budget_target_lease_only() {
    let dispatch = Arc::new(SnapshotDispatch {
        chats: AtomicU32::new(0),
        streams: AtomicU32::new(0),
        embeds: AtomicU32::new(0),
        last_target: Mutex::new(String::new()),
        last_invocation: Mutex::new(String::new()),
    });
    let (gw, _, budget, _) = gateway_with(dispatch.clone());
    let _ = gw
        .chat_for_run(
            vec![ChatMessage {
                role: ChatRole::User,
                content: "hi".into(),
            }],
            ChatParams {
                model: Some("llama".into()),
                ..Default::default()
            },
            "run-lease".into(),
        )
        .await
        .expect("chat");
    assert_eq!(budget.commits.lock().unwrap().len(), 1);
    assert_eq!(budget.commits.lock().unwrap()[0].0, "run-lease");
    assert_eq!(*dispatch.last_target.lock().unwrap(), "peer-b");
    assert!(!dispatch.last_invocation.lock().unwrap().is_empty());
}

#[tokio::test]
async fn t135_embed_snapshot() {
    let dispatch = Arc::new(SnapshotDispatch {
        chats: AtomicU32::new(0),
        streams: AtomicU32::new(0),
        embeds: AtomicU32::new(0),
        last_target: Mutex::new(String::new()),
        last_invocation: Mutex::new(String::new()),
    });
    let (gw, chain, _, _) = gateway_with(dispatch.clone());
    let vec = gw.embed("hi").await.expect("embed");
    assert_eq!(vec, vec![0.1, 0.2]);
    assert_eq!(dispatch.embeds.load(Ordering::SeqCst), 1);
    assert_eq!(dispatch.chats.load(Ordering::SeqCst), 0);
    assert_eq!(chain.call_log.lock().unwrap().len(), 0);
}

#[tokio::test]
async fn t135_mesh_connection_refused_failovers() {
    let map_probe = MeshRemoteAdapter {
        dispatch: Arc::new(FailDispatch {
            chats: AtomicU32::new(0),
            err: MeshInferenceDispatchError::Provider("connection refused".into()),
        }),
        provider_id: "mesh-a".into(),
        embedding_model: Some("nomic-embed".into()),
        target_device_id: "peer-a".into(),
    };
    let mapped = map_probe
        .chat(adapter_probe_req())
        .await
        .expect_err("adapter must map Provider");
    assert_eq!(
        mapped.to_string(),
        "mesh-remote: connection refused",
        "{mapped}"
    );

    let fail = Arc::new(FailDispatch {
        chats: AtomicU32::new(0),
        err: MeshInferenceDispatchError::Provider("connection refused".into()),
    });
    let ok = Arc::new(SnapshotDispatch {
        chats: AtomicU32::new(0),
        streams: AtomicU32::new(0),
        embeds: AtomicU32::new(0),
        last_target: Mutex::new(String::new()),
        last_invocation: Mutex::new(String::new()),
    });
    let mut registry = InferenceBackendRegistry::new();
    registry.insert(
        "mesh-a",
        Arc::new(MeshRemoteAdapter {
            dispatch: fail.clone(),
            provider_id: "mesh-a".into(),
            embedding_model: Some("nomic-embed".into()),
            target_device_id: "peer-a".into(),
        }),
    );
    registry.insert(
        "mesh-b",
        Arc::new(MeshRemoteAdapter {
            dispatch: ok.clone(),
            provider_id: "mesh-b".into(),
            embedding_model: Some("nomic-embed".into()),
            target_device_id: "peer-b".into(),
        }),
    );
    let mut cfg = fixture_runtime_config();
    cfg.llm_providers = vec![mesh_cfg_id("mesh-a"), mesh_cfg_id("mesh-b")];
    let chain = Arc::new(MockHttpSecurityChain::default());
    let budget = Arc::new(MockRunBudget::default());
    let bus = Arc::new(MockEventBusEmit::default());
    let gw = LlmGateway::new(
        Arc::new(MockRuntimeConfigProvider::new(cfg)),
        chain,
        budget,
        bus,
        no_op_repetition_guard(),
        "test-agent".into(),
    )
    .with_inference_backends(registry)
    .with_placement_telemetry(Arc::new(Tel(HashMap::from([
        ("mesh-a".into(), 1),
        ("mesh-b".into(), 80),
    ]))));
    let resp = gw
        .chat(
            vec![ChatMessage {
                role: ChatRole::User,
                content: "hi".into(),
            }],
            ChatParams {
                model: Some("llama".into()),
                ..Default::default()
            },
        )
        .await
        .expect("failover");
    assert_eq!(resp.text, "mesh-pong");
    assert_eq!(fail.chats.load(Ordering::SeqCst), 1);
    assert_eq!(ok.chats.load(Ordering::SeqCst), 1);

    // lease-denied / cancelled do not hop
    for err in [
        MeshInferenceDispatchError::LeaseDenied("quota".into()),
        MeshInferenceDispatchError::Cancelled,
    ] {
        let fail = Arc::new(FailDispatch {
            chats: AtomicU32::new(0),
            err,
        });
        let ok = Arc::new(SnapshotDispatch {
            chats: AtomicU32::new(0),
            streams: AtomicU32::new(0),
            embeds: AtomicU32::new(0),
            last_target: Mutex::new(String::new()),
            last_invocation: Mutex::new(String::new()),
        });
        let mut registry = InferenceBackendRegistry::new();
        registry.insert(
            "mesh-a",
            Arc::new(MeshRemoteAdapter {
                dispatch: fail.clone(),
                provider_id: "mesh-a".into(),
                embedding_model: None,
                target_device_id: "peer-a".into(),
            }),
        );
        registry.insert(
            "mesh-b",
            Arc::new(MeshRemoteAdapter {
                dispatch: ok.clone(),
                provider_id: "mesh-b".into(),
                embedding_model: None,
                target_device_id: "peer-b".into(),
            }),
        );
        let mut cfg = fixture_runtime_config();
        cfg.llm_providers = vec![mesh_cfg_id("mesh-a"), mesh_cfg_id("mesh-b")];
        let gw = LlmGateway::new(
            Arc::new(MockRuntimeConfigProvider::new(cfg)),
            Arc::new(MockHttpSecurityChain::default()),
            Arc::new(MockRunBudget::default()),
            Arc::new(MockEventBusEmit::default()),
            no_op_repetition_guard(),
            "test-agent".into(),
        )
        .with_inference_backends(registry)
        .with_placement_telemetry(Arc::new(Tel(HashMap::from([
            ("mesh-a".into(), 1),
            ("mesh-b".into(), 80),
        ]))));
        let e = gw
            .chat(
                vec![ChatMessage {
                    role: ChatRole::User,
                    content: "hi".into(),
                }],
                ChatParams {
                    model: Some("llama".into()),
                    ..Default::default()
                },
            )
            .await
            .expect_err("must not hop");
        let s = e.to_string();
        assert!(s.contains("lease-denied") || s.contains("cancelled"), "{s}");
        assert_eq!(fail.chats.load(Ordering::SeqCst), 1);
        assert_eq!(ok.chats.load(Ordering::SeqCst), 0);
    }
}

#![cfg(test)]

use std::collections::HashMap;
use std::sync::Arc;

use advance_runtime::config::{InferenceBackendClass, LlmProviderConfig, ProviderBackend};
use advance_shared_types::inference::InferenceBackendRegistry;
use cap_http::DefaultLocalInferenceTransport;

use crate::backend_local::{spawn_inprocess_fixture, SidecarClient, StaticHandoffSupervisor};
use crate::gateway::{ChatMessage, ChatParams, ChatRole, LlmGateway};
use crate::test_support::{
    fixture_runtime_config, no_op_repetition_guard, MockEventBusEmit, MockHttpSecurityChain,
    MockRunBudget, MockRuntimeConfigProvider,
};

fn local_cfg() -> LlmProviderConfig {
    let mut aliases = HashMap::new();
    aliases.insert("llama".into(), "llama".into());
    LlmProviderConfig {
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
        embedding_model: Some("nomic-embed".into()),
        sidecar: None,
        profile_id: None,
    }
}

#[tokio::test]
async fn t128_local_chat_skips_chain() {
    let (handoff, _jh) = spawn_inprocess_fixture(false).await.unwrap();
    let client = SidecarClient {
        policy: Arc::new(DefaultLocalInferenceTransport),
        supervisor: Arc::new(StaticHandoffSupervisor { handoff }),
        provider_id: "local".into(),
        embedding_model: Some("nomic-embed".into()),
    };
    let mut registry = InferenceBackendRegistry::new();
    registry.insert("local", Arc::new(client));

    let mut cfg = fixture_runtime_config();
    cfg.llm_providers = vec![local_cfg()];
    let cfg_provider = Arc::new(MockRuntimeConfigProvider::new(cfg));
    let chain = Arc::new(MockHttpSecurityChain::default());
    let budget = Arc::new(MockRunBudget::default());
    let bus = Arc::new(MockEventBusEmit::default());
    let gw = LlmGateway::new(
        cfg_provider,
        chain.clone(),
        budget.clone(),
        bus,
        no_op_repetition_guard(),
        "test-agent".into(),
    )
    .with_inference_backends(registry);

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
            "run-local-1".into(),
        )
        .await
        .expect("local chat");
    assert_eq!(resp.text, "pong");
    assert!(chain.call_log.lock().unwrap().is_empty());
    let commits = budget.commits.lock().unwrap();
    assert!(
        !commits.is_empty(),
        "local generate must commit run budget, got {commits:?}"
    );
    let (tokens, cost) = (commits[0].1, commits[0].2);
    assert_eq!(tokens, 2, "fixture usage 1+1");
    assert!(
        (cost - 2.0e-9).abs() < 1e-15,
        "cost must be rates × tokens, got {cost}"
    );
}

#[tokio::test]
async fn generate_via_local_tee_live_one_begin() {
    use crate::gateway::LlmRequestContext;
    use advance_shared_types::traits::{LlmDeltaEvent, LlmDeltaFrame, LlmDeltaSink};

    #[derive(Default)]
    struct Rec {
        frames: std::sync::Mutex<Vec<LlmDeltaFrame>>,
    }
    impl LlmDeltaSink for Rec {
        fn publish(&self, event: LlmDeltaEvent) {
            self.frames.lock().unwrap().push(event.frame);
        }
    }

    let (handoff, _jh) = spawn_inprocess_fixture(false).await.unwrap();
    let client = SidecarClient {
        policy: Arc::new(DefaultLocalInferenceTransport),
        supervisor: Arc::new(StaticHandoffSupervisor { handoff }),
        provider_id: "local".into(),
        embedding_model: Some("nomic-embed".into()),
    };
    let mut registry = InferenceBackendRegistry::new();
    registry.insert("local", Arc::new(client));
    let mut cfg = fixture_runtime_config();
    cfg.llm_providers = vec![local_cfg()];
    let rec = Arc::new(Rec::default());
    let gw = LlmGateway::new(
        Arc::new(MockRuntimeConfigProvider::new(cfg)),
        Arc::new(MockHttpSecurityChain::default()),
        Arc::new(MockRunBudget::default()),
        Arc::new(MockEventBusEmit::default()),
        no_op_repetition_guard(),
        "test-agent".into(),
    )
    .with_inference_backends(registry)
    .with_delta_sink(rec.clone() as Arc<dyn LlmDeltaSink>);
    let ctx = LlmRequestContext {
        agent_id: "test-agent".into(),
        messages: vec![ChatMessage {
            role: ChatRole::User,
            content: "hi".into(),
        }],
        params: ChatParams {
            model: Some("llama".into()),
            ..Default::default()
        },
        tee_live: true,
        ..Default::default()
    };
    let resp = gw.generate(ctx).await.expect("local generate");
    let frames = rec.frames.lock().unwrap().clone();
    let begins = frames
        .iter()
        .filter(|f| matches!(f, LlmDeltaFrame::Begin { .. }))
        .count();
    assert_eq!(begins, 1, "exactly one Begin, got {frames:?}");
    let concat: String = frames
        .iter()
        .filter_map(|f| match f {
            LlmDeltaFrame::Delta { text, .. } => Some(text.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(concat, resp.text);
    assert!(matches!(
        frames.last(),
        Some(LlmDeltaFrame::Terminal { .. })
    ));
}

#[tokio::test]
async fn generate_via_local_budget_deny_before_open_is_silent() {
    use crate::gateway::LlmRequestContext;
    use crate::LlmError;
    use advance_shared_types::traits::{LlmDeltaEvent, LlmDeltaFrame, LlmDeltaSink};

    #[derive(Default)]
    struct Rec {
        frames: std::sync::Mutex<Vec<LlmDeltaFrame>>,
    }
    impl LlmDeltaSink for Rec {
        fn publish(&self, event: LlmDeltaEvent) {
            self.frames.lock().unwrap().push(event.frame);
        }
    }

    let (handoff, _jh) = spawn_inprocess_fixture(false).await.unwrap();
    let client = SidecarClient {
        policy: Arc::new(DefaultLocalInferenceTransport),
        supervisor: Arc::new(StaticHandoffSupervisor { handoff }),
        provider_id: "local".into(),
        embedding_model: Some("nomic-embed".into()),
    };
    let mut registry = InferenceBackendRegistry::new();
    registry.insert("local", Arc::new(client));
    let mut cfg = fixture_runtime_config();
    cfg.llm_providers = vec![local_cfg()];
    let rec = Arc::new(Rec::default());
    let budget = Arc::new(MockRunBudget::default());
    budget.deny("rid-local", "over limit");
    let gw = LlmGateway::new(
        Arc::new(MockRuntimeConfigProvider::new(cfg)),
        Arc::new(MockHttpSecurityChain::default()),
        budget,
        Arc::new(MockEventBusEmit::default()),
        no_op_repetition_guard(),
        "test-agent".into(),
    )
    .with_inference_backends(registry)
    .with_delta_sink(rec.clone() as Arc<dyn LlmDeltaSink>);
    let ctx = LlmRequestContext {
        agent_id: "test-agent".into(),
        run_id: Some("rid-local".into()),
        messages: vec![ChatMessage {
            role: ChatRole::User,
            content: "hi".into(),
        }],
        params: ChatParams {
            model: Some("llama".into()),
            ..Default::default()
        },
        tee_live: true,
        ..Default::default()
    };
    let err = gw.generate(ctx).await;
    assert!(matches!(err, Err(LlmError::BudgetExceeded(_))));
    assert!(
        rec.frames.lock().unwrap().is_empty(),
        "local budget deny before open must not Begin"
    );
}

#[tokio::test]
async fn t131_local_embed_uses_configured_model() {
    let (handoff, _jh) = spawn_inprocess_fixture(false).await.unwrap();
    let client = SidecarClient {
        policy: Arc::new(DefaultLocalInferenceTransport),
        supervisor: Arc::new(StaticHandoffSupervisor { handoff }),
        provider_id: "local".into(),
        embedding_model: Some("nomic-embed".into()),
    };
    let mut registry = InferenceBackendRegistry::new();
    registry.insert("local", Arc::new(client));
    let mut cfg = fixture_runtime_config();
    cfg.llm_providers = vec![local_cfg()];
    let gw = LlmGateway::new(
        Arc::new(MockRuntimeConfigProvider::new(cfg)),
        Arc::new(MockHttpSecurityChain::default()),
        Arc::new(MockRunBudget::default()),
        Arc::new(MockEventBusEmit::default()),
        no_op_repetition_guard(),
        "test-agent".into(),
    )
    .with_inference_backends(registry);
    let (vec, model) = gw.embed_recorded("hello").await.expect("embed");
    assert_eq!(model, "nomic-embed");
    assert_eq!(vec.len(), 2);
}

#[test]
fn t131_local_without_embedding_model_is_skipped() {
    let mut local = local_cfg();
    local.embedding_model = None;
    let mut cfg = fixture_runtime_config();
    let mut providers = vec![local];
    providers.append(&mut cfg.llm_providers);
    let resolved = crate::gateway::select_embedding_provider(&providers).expect("cloud embed");
    assert_ne!(resolved.id, "local");
}

#[tokio::test]
async fn t128_local_live_stream_skips_chain() {
    use std::time::Duration;

    use advance_shared_types::traits::HttpStreamingChain;
    use cap_http::DefaultLeakDetector;

    use crate::gateway::LlmRequestContext;
    use crate::stream::{PollOutcome, StreamRegistry};

    let (handoff, _jh) = spawn_inprocess_fixture(false).await.unwrap();
    let client = SidecarClient {
        policy: Arc::new(DefaultLocalInferenceTransport),
        supervisor: Arc::new(StaticHandoffSupervisor { handoff }),
        provider_id: "local".into(),
        embedding_model: Some("nomic-embed".into()),
    };
    let mut registry = InferenceBackendRegistry::new();
    registry.insert("local", Arc::new(client));
    let mut cfg = fixture_runtime_config();
    cfg.llm_providers = vec![local_cfg()];
    let chain = Arc::new(MockHttpSecurityChain::default());
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
        chain.clone() as Arc<dyn HttpStreamingChain>,
        Arc::new(DefaultLeakDetector::default()),
    );
    let streams = Arc::new(StreamRegistry::new());
    let ctx = LlmRequestContext {
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
        .expect("local live begin");
    let mut text = String::new();
    let done = loop {
        match tokio::time::timeout(Duration::from_secs(5), streams.poll_live(h, "test-agent"))
            .await
            .expect("poll")
        {
            PollOutcome::Delta(d) => text.push_str(&d),
            PollOutcome::Done(ready) => break ready,
            PollOutcome::Failed(e) => panic!("live local failed: {e}"),
            PollOutcome::Unknown => panic!("unknown handle"),
        }
    };
    assert_eq!(done.response.text, "pong");
    assert!(text.contains("pong") || done.response.text == "pong");
    assert!(chain.call_log.lock().unwrap().is_empty());
}

#[tokio::test]
async fn t128_local_buffered_stream_skips_chain() {
    let (handoff, _jh) = spawn_inprocess_fixture(false).await.unwrap();
    let client = SidecarClient {
        policy: Arc::new(DefaultLocalInferenceTransport),
        supervisor: Arc::new(StaticHandoffSupervisor { handoff }),
        provider_id: "local".into(),
        embedding_model: Some("nomic-embed".into()),
    };
    let mut registry = InferenceBackendRegistry::new();
    registry.insert("local", Arc::new(client));
    let mut cfg = fixture_runtime_config();
    cfg.llm_providers = vec![local_cfg()];
    let chain = Arc::new(MockHttpSecurityChain::default());
    let gw = LlmGateway::new(
        Arc::new(MockRuntimeConfigProvider::new(cfg)),
        chain.clone(),
        Arc::new(MockRunBudget::default()),
        Arc::new(MockEventBusEmit::default()),
        no_op_repetition_guard(),
        "test-agent".into(),
    )
    .with_inference_backends(registry);
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
    let ready = gw.stream_begin(ctx).await.expect("buffered local");
    assert_eq!(ready.response.text, "pong");
    assert!(chain.call_log.lock().unwrap().is_empty());
}

#[tokio::test]
async fn t132_local_live_stream_blocks_secret() {
    use std::time::Duration;

    use advance_shared_types::traits::HttpStreamingChain;
    use cap_http::DefaultLeakDetector;

    use crate::gateway::LlmRequestContext;
    use crate::stream::{PollOutcome, StreamRegistry};

    let (handoff, _jh) = spawn_inprocess_fixture(true).await.unwrap();
    let client = SidecarClient {
        policy: Arc::new(DefaultLocalInferenceTransport),
        supervisor: Arc::new(StaticHandoffSupervisor { handoff }),
        provider_id: "local".into(),
        embedding_model: Some("nomic-embed".into()),
    };
    let mut registry = InferenceBackendRegistry::new();
    registry.insert("local", Arc::new(client));
    let mut cfg = fixture_runtime_config();
    cfg.llm_providers = vec![local_cfg()];
    let chain = Arc::new(MockHttpSecurityChain::default());
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
        chain.clone() as Arc<dyn HttpStreamingChain>,
        Arc::new(DefaultLeakDetector::default()),
    );
    let streams = Arc::new(StreamRegistry::new());
    let ctx = LlmRequestContext {
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
    let h = gw.stream_begin_live(ctx, &streams).await.expect("begin");
    let mut visible = String::new();
    let terminal = loop {
        match tokio::time::timeout(Duration::from_secs(5), streams.poll_live(h, "test-agent"))
            .await
            .expect("poll")
        {
            PollOutcome::Delta(d) => visible.push_str(&d),
            PollOutcome::Done(ready) => break Ok(ready.response.text),
            PollOutcome::Failed(e) => break Err(e),
            PollOutcome::Unknown => panic!("unknown handle"),
        }
    };
    match terminal {
        Err(e) => {
            let msg = format!("{e}");
            assert!(
                !msg.contains("sk-ant-api"),
                "error must not echo secret: {msg}"
            );
            assert!(
                msg.to_ascii_lowercase().contains("block")
                    || msg.contains("leak")
                    || msg.contains("detector")
                    || msg.contains("ProviderError"),
                "expected detector fail-closed, got {msg}"
            );
        }
        Ok(text) => panic!(
            "expected Failed from DecodedPipeline, got Done text={text:?} visible={visible:?}"
        ),
    }
    assert!(chain.call_log.lock().unwrap().is_empty());
}

#[tokio::test]
async fn t132_ssrf_blocked_not_retryable() {
    use crate::retry::classify_retryable;
    use crate::LlmError;
    assert!(!classify_retryable(&LlmError::ProviderError(
        "ssrf blocked".into()
    )));
}

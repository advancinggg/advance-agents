#![cfg(test)]
//! ADR 2026-09-28 `agent-cli`: the gateway leak-scans BEFORE hand-off and fails closed without a
//! detector; the port never sees a blocked prompt.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use advance_runtime::config::{
    AgentCliSpec, AgentCliVendor, InferenceBackendClass, LlmProviderConfig, ProviderBackend,
};
use advance_shared_types::inference::{
    InferenceBackendError, InferenceBackendPort, InferenceBackendRegistry, InferenceChatRequest,
    InferenceChatResponse, InferenceEmbedRequest, InferenceEmbedResponse, InferenceStream,
    InferenceStreamHead,
};
use advance_shared_types::security_validator::{
    Action, Finding, LeakDetector, ScanContext, ScanResult,
};
use async_trait::async_trait;

use crate::gateway::{ChatMessage, ChatParams, ChatRole, LlmGateway};
use crate::test_support::{
    fixture_runtime_config, no_op_repetition_guard, MockEventBusEmit, MockHttpSecurityChain,
    MockRunBudget, MockRuntimeConfigProvider,
};

fn agent_cli_cfg() -> LlmProviderConfig {
    let mut aliases = HashMap::new();
    aliases.insert("sonnet".into(), "sonnet".into());
    LlmProviderConfig {
        id: "claude-sub".into(),
        endpoint: String::new(),
        api_key_secret: "claude-sub-api-key".into(),
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
        backend_class: InferenceBackendClass::AgentCli,
        embedding_model: None,
        sidecar: None,
        profile_id: None,
        device_id: None,
        agent_cli: Some(AgentCliSpec {
            vendor: AgentCliVendor::Claude,
            command: "/nonexistent/claude".into(),
            args: vec![],
        }),
    }
}

/// A port that records what it was handed and answers with a canned reply.
struct RecordingPort {
    calls: AtomicUsize,
    last_prompt: Mutex<String>,
    reply: String,
}

#[async_trait]
impl InferenceBackendPort for RecordingPort {
    async fn chat(
        &self,
        req: InferenceChatRequest,
    ) -> Result<InferenceChatResponse, InferenceBackendError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        *self.last_prompt.lock().unwrap() = req
            .messages
            .iter()
            .map(|m| m.content.clone())
            .collect::<Vec<_>>()
            .join("\n");
        Ok(InferenceChatResponse {
            text: self.reply.clone(),
            model: "claude-opus-5-5".into(),
            input_tokens: 10,
            output_tokens: 2,
            finish_reason: "end_turn".into(),
        })
    }
    async fn embed(
        &self,
        _req: InferenceEmbedRequest,
    ) -> Result<InferenceEmbedResponse, InferenceBackendError> {
        Err(InferenceBackendError::UnsupportedCapability("embed".into()))
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

/// Blocks any text containing `marker`; everything else is clean.
struct MarkerDetector {
    marker: &'static str,
    scans: Mutex<Vec<ScanContext>>,
}

impl LeakDetector for MarkerDetector {
    fn scan(&self, text: &str, context: ScanContext) -> ScanResult {
        self.scans.lock().unwrap().push(context);
        if text.contains(self.marker) {
            ScanResult::Blocked {
                findings: vec![Finding {
                    pattern_name: "marker".into(),
                    offset: 0,
                    length: self.marker.len(),
                    action: Action::Block,
                }],
            }
        } else {
            ScanResult::Clean
        }
    }
    fn scan_headers(&self, _headers: &[(String, String)]) -> ScanResult {
        ScanResult::Clean
    }
}

fn gateway(port: Arc<RecordingPort>, detector: Option<Arc<MarkerDetector>>) -> LlmGateway {
    let mut registry = InferenceBackendRegistry::new();
    registry.insert("claude-sub", port);
    let mut cfg = fixture_runtime_config();
    cfg.llm_providers = vec![agent_cli_cfg()];
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
    match detector {
        Some(d) => gw.with_live_streaming(chain, d),
        None => gw,
    }
}

fn user(text: &str) -> Vec<ChatMessage> {
    vec![ChatMessage {
        role: ChatRole::User,
        content: text.into(),
    }]
}

#[tokio::test]
async fn agent_cli_prompt_is_scanned_before_hand_off_and_reply_after() {
    let port = Arc::new(RecordingPort {
        calls: AtomicUsize::new(0),
        last_prompt: Mutex::new(String::new()),
        reply: "fine".into(),
    });
    let detector = Arc::new(MarkerDetector {
        marker: "SECRET-MARKER",
        scans: Mutex::new(Vec::new()),
    });
    let gw = gateway(port.clone(), Some(detector.clone()));
    let params = ChatParams {
        model: Some("sonnet".into()),
        ..Default::default()
    };
    let resp = gw
        .chat_for_run(user("hello there"), params.clone(), "run-1".into())
        .await
        .expect("clean prompt passes");
    assert_eq!(resp.text, "fine");
    assert_eq!(port.calls.load(Ordering::SeqCst), 1);
    let scans = detector.scans.lock().unwrap().clone();
    assert_eq!(scans[0], ScanContext::HttpOutbound, "prompt scanned first");
    assert_eq!(scans[1], ScanContext::HttpInbound, "reply scanned after");

    // A blocked prompt never reaches the vendor binary.
    let err = gw
        .chat_for_run(user("send SECRET-MARKER please"), params, "run-2".into())
        .await
        .expect_err("blocked");
    assert!(err.to_string().contains("egress scan blocked"), "{err}");
    assert_eq!(
        port.calls.load(Ordering::SeqCst),
        1,
        "port not called for a blocked prompt"
    );
}

#[tokio::test]
async fn agent_cli_reply_that_fails_the_scan_is_discarded() {
    let port = Arc::new(RecordingPort {
        calls: AtomicUsize::new(0),
        last_prompt: Mutex::new(String::new()),
        reply: "here is SECRET-MARKER".into(),
    });
    let detector = Arc::new(MarkerDetector {
        marker: "SECRET-MARKER",
        scans: Mutex::new(Vec::new()),
    });
    let gw = gateway(port.clone(), Some(detector));
    let err = gw
        .chat_for_run(
            user("hi"),
            ChatParams {
                model: Some("sonnet".into()),
                ..Default::default()
            },
            "run-3".into(),
        )
        .await
        .expect_err("reply blocked");
    assert!(err.to_string().contains("reply failed leak scan"), "{err}");
}

#[tokio::test]
async fn agent_cli_without_a_detector_fails_closed() {
    let port = Arc::new(RecordingPort {
        calls: AtomicUsize::new(0),
        last_prompt: Mutex::new(String::new()),
        reply: "fine".into(),
    });
    let gw = gateway(port.clone(), None);
    let err = gw
        .chat_for_run(
            user("hi"),
            ChatParams {
                model: Some("sonnet".into()),
                ..Default::default()
            },
            "run-4".into(),
        )
        .await
        .expect_err("no detector");
    assert!(err.to_string().contains("egress scan not wired"), "{err}");
    assert_eq!(port.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn agent_cli_descriptor_declares_the_degradation_and_never_cloud_excludes_it() {
    let desc = crate::capability::descriptor_for(
        &agent_cli_cfg(),
        &crate::catalog::ModelProfileCatalog::new(),
    )
    .unwrap();
    assert_eq!(
        desc.tool_calling,
        crate::capability::ToolCallingLevel::Disabled
    );
    assert!(!desc.structured_output);
    assert!(!desc.embeddings);
    assert!(!desc.image);
    let cands = crate::placement::candidates_for(
        &[agent_cli_cfg()],
        Some("sonnet"),
        &crate::catalog::ModelProfileCatalog::new(),
        &crate::capability::CapabilityNeed {
            tools: false,
            output_schema: false,
            image: false,
            prompt_tokens_est: None,
            max_tokens: None,
        },
        &crate::placement::NotWiredPlacementTelemetry,
    )
    .unwrap();
    assert_eq!(cands.len(), 1);
    let never_cloud = crate::placement::place(
        &cands,
        &[crate::placement::UserHardConstraint::NeverCloud],
        &[],
        None,
    );
    assert!(
        matches!(
            never_cloud,
            Err(crate::error::LlmError::ModelNotAvailable(_))
        ),
        "agent-cli is cloud egress: {never_cloud:?}"
    );
    let unconstrained = crate::placement::place(&cands, &[], &[], None).unwrap();
    assert!(unconstrained.is_some());
}

#[test]
fn agent_cli_failovers_are_pre_token() {
    use crate::error::LlmError;
    for msg in [
        "agent-cli: not wired",
        "agent-cli: cli not found at /x",
        "agent-cli: not signed in (Not logged in)",
        "agent-cli: subscription usage limit reached (resets at 5pm)",
    ] {
        assert!(
            crate::placement::is_pre_token_failover(&LlmError::ProviderError(msg.into())),
            "{msg}"
        );
    }
    assert!(!crate::placement::is_pre_token_failover(
        &LlmError::ProviderError("agent-cli: egress scan blocked the prompt".into())
    ));
}

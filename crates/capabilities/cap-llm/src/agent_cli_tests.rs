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
        auth_source: advance_runtime::config::ProviderAuthSource::ApiKey,
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

// ─────────────────────────────────────────────────────────────────────────────────────────────
// Usage probe parsers (fixtures = the vendor CLIs' live answers, 2026-09-29)
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn claude_usage_text_yields_session_week_and_per_model_windows() {
    let text = "You are currently using your subscription to power your Claude Code usage\n\n\
Current session: 60% used · resets Sep 29 at 11pm (America/Los_Angeles)\n\
Current week (all models): 69% used · resets Sep 30 at 3pm (America/Los_Angeles)\n\
Current week (Fable): 79% used · resets Sep 30 at 3pm (America/Los_Angeles)\n\n\
What's contributing to your limits usage?\nLast 24h · 2312 requests · 4 sessions\n  99% of your usage came from subagent-heavy sessions\n";
    let windows = crate::backend_cli::parse_claude_usage_text(text);
    assert_eq!(windows.len(), 3, "{windows:?}");
    assert_eq!(windows[0].kind, "session");
    assert_eq!(windows[0].used_percent, 60.0);
    assert_eq!(
        windows[0].resets_label.as_deref(),
        Some("Sep 29 at 11pm (America/Los_Angeles)")
    );
    assert_eq!(windows[1].kind, "week");
    assert_eq!(windows[1].label, "Current week (all models)");
    assert_eq!(windows[1].used_percent, 69.0);
    assert_eq!(windows[2].kind, "week-model");
    assert_eq!(windows[2].model.as_deref(), Some("Fable"));
    assert_eq!(windows[2].used_percent, 79.0);
    assert!(windows.iter().all(|w| w.resets_at_ms.is_none()));
    assert!(crate::backend_cli::parse_claude_usage_text("Not logged in").is_empty());
}

#[test]
fn codex_usage_reads_account_and_both_windows_and_names_signed_out() {
    let ok = vec![
        serde_json::json!({"id":1,"result":{"userAgent":"x"}}),
        serde_json::json!({"id":2,"result":{"account":{"type":"chatgpt","email":"me@example.com","planType":"plus"},"requiresOpenaiAuth":false}}),
        serde_json::json!({"id":3,"result":{"rateLimits":{"limitId":"codex","planType":"plus","primary":{"usedPercent":12,"windowDurationMins":300,"resetsAt":1790700000},"secondary":{"usedPercent":30,"windowDurationMins":10080,"resetsAt":1791200000}},"rateLimitsByLimitId":null}}),
    ];
    let probe = crate::backend_cli::codex_usage_from_responses(&ok);
    assert!(probe.ok, "{probe:?}");
    assert_eq!(probe.plan.as_deref(), Some("plus"));
    assert_eq!(probe.account.as_deref(), Some("me@example.com"));
    assert_eq!(probe.windows.len(), 2);
    assert_eq!(probe.windows[0].kind, "primary");
    assert_eq!(probe.windows[0].label, "5-hour");
    assert_eq!(probe.windows[0].used_percent, 12.0);
    assert_eq!(probe.windows[0].resets_at_ms, Some(1_790_700_000_000));
    assert_eq!(probe.windows[0].window_minutes, Some(300));
    assert_eq!(probe.windows[1].label, "Weekly");
    assert_eq!(probe.windows[1].used_percent, 30.0);

    // The live signed-out answer of codex-cli 0.144.1.
    let signed_out = vec![
        serde_json::json!({"id":1,"result":{"userAgent":"x"}}),
        serde_json::json!({"id":2,"result":{"account":null,"requiresOpenaiAuth":true}}),
        serde_json::json!({"error":{"code":-32600,"message":"codex account authentication required to read rate limits"},"id":3}),
    ];
    let probe = crate::backend_cli::codex_usage_from_responses(&signed_out);
    assert!(!probe.ok);
    assert_eq!(probe.detail, "not-signed-in");
    assert!(probe.windows.is_empty());

    let nothing = crate::backend_cli::codex_usage_from_responses(&[]);
    assert_eq!(nothing.detail, "unparsed");
}

#[test]
fn grok_usage_reads_tier_account_and_the_weekly_pool() {
    // The live answers of grok 1.0.41 (email redacted).
    let ok = vec![
        serde_json::json!({"id":1,"result":{"protocolVersion":1}}),
        serde_json::json!({"id":2,"result":{"_meta":{"email":"me@example.com","auth_mode":"Oidc","subscription_tier":"supergrok_heavy","backend_billed":false}}}),
        serde_json::json!({"id":3,"result":{"config":{"creditUsagePercent":11.0,"currentPeriod":{"type":"USAGE_PERIOD_TYPE_WEEKLY","start":"2026-09-28T01:32:38.043435+00:00","end":"2026-10-05T01:32:38.043435+00:00"},"onDemandCap":{"val":0},"prepaidBalance":{"val":0},"isUnifiedBillingUser":true}}}),
    ];
    let probe = crate::backend_cli::grok_usage_from_responses(&ok);
    assert!(probe.ok, "{probe:?}");
    assert_eq!(probe.plan.as_deref(), Some("supergrok_heavy"));
    assert_eq!(probe.account.as_deref(), Some("me@example.com"));
    assert_eq!(probe.windows.len(), 1);
    let w = &probe.windows[0];
    assert_eq!(w.kind, "period");
    assert_eq!(w.label, "Weekly limit");
    assert_eq!(w.used_percent, 11.0);
    assert_eq!(w.resets_at_ms, Some(1_791_163_958_043));
    assert_eq!(w.window_minutes, Some(7 * 24 * 60));

    let signed_out = vec![
        serde_json::json!({"id":1,"result":{"protocolVersion":1}}),
        serde_json::json!({"id":2,"error":{"code":-32000,"message":"Authentication required"}}),
    ];
    let probe = crate::backend_cli::grok_usage_from_responses(&signed_out);
    assert_eq!(probe.detail, "not-signed-in");

    let billing_refused = vec![
        serde_json::json!({"id":2,"result":{"_meta":{"subscription_tier":"free"}}}),
        serde_json::json!({"id":3,"error":{"code":-32000,"message":"Authentication required to fetch billing data","data":"Billing data requires auth with grok.com. Run `grok login` to authenticate."}}),
    ];
    let probe = crate::backend_cli::grok_usage_from_responses(&billing_refused);
    assert_eq!(probe.detail, "not-signed-in");
}

#[test]
fn usage_probe_refuses_a_missing_cli_before_spawning() {
    let spec = AgentCliSpec {
        vendor: AgentCliVendor::Claude,
        command: "/definitely/not/here/claude".into(),
        args: Vec::new(),
    };
    let env = crate::backend_cli::AgentCliEnv::from_process_env();
    let probe = crate::backend_cli::probe_usage(&spec, &env);
    assert!(!probe.ok);
    assert_eq!(probe.detail, "cli-not-found");
}

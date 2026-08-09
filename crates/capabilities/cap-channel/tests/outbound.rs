//! Integration tests for outbound dispatch (AC-09).
//!
//! T09 verifies the AC-09 invariants — every `send-raw` via the WIT handler
//! results in exactly one `security_chain.execute` call with the propagated
//! `agent_id`, host-authoritative allowlist (preset, not config), and pinned
//! `component_id = "cap-channel:{adapter_type}"`.

use std::sync::{Arc, Mutex};

use advance_runtime::host_registry::{
    HostCallContext, HostFunctionHandler, HostRegistry, InMemoryHostRegistry,
};
use advance_shared_types::security_validator::{
    HttpCapability, HttpError, HttpMethod as SharedHttpMethod, HttpRequest, HttpResponse,
    HttpSecurityChain,
};
use async_trait::async_trait;
use cap_channel::{
    register_channel_host, AdapterType, ChannelConfig, ChannelHostBundle, HttpMethod,
    OutboundConfig, OutboundDispatcher, SubscriptionManager, CHANNEL_HOST_CAPABILITY,
};
use wasmtime::component::Val;

#[derive(Clone, Debug)]
struct ExecuteCall {
    agent_id: String,
    url: String,
    method: SharedHttpMethod,
    component_id: String,
    allowlist_patterns: Vec<String>,
}

struct RecordingChain {
    calls: Mutex<Vec<ExecuteCall>>,
    fail_with: Option<HttpError>,
}

impl RecordingChain {
    fn new() -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            fail_with: None,
        }
    }

    fn rejecting(err: HttpError) -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            fail_with: Some(err),
        }
    }

    fn calls(&self) -> Vec<ExecuteCall> {
        self.calls.lock().unwrap().clone()
    }
}

#[async_trait]
impl HttpSecurityChain for RecordingChain {
    async fn execute(
        &self,
        agent_id: &str,
        req: HttpRequest,
        cap: &HttpCapability,
    ) -> Result<HttpResponse, HttpError> {
        self.calls.lock().unwrap().push(ExecuteCall {
            agent_id: agent_id.to_string(),
            url: req.url.clone(),
            method: req.method.clone(),
            component_id: cap.component_id.clone(),
            allowlist_patterns: cap.allowlist.patterns.clone(),
        });
        if let Some(ref err) = self.fail_with {
            return Err(clone_http_error(err));
        }
        Ok(HttpResponse {
            status: 200,
            headers: vec![],
            body: vec![],
        })
    }
}

fn clone_http_error(err: &HttpError) -> HttpError {
    match err {
        HttpError::AllowlistBlocked(s) => HttpError::AllowlistBlocked(s.clone()),
        _ => HttpError::AllowlistBlocked("unsupported test variant".to_string()),
    }
}

fn test_ctx(agent_id: &str, function: &str) -> HostCallContext {
    HostCallContext {
        agent_id: agent_id.to_string(),
        trace_id: "trace-test".to_string(),
        turn_id: None,
        capability: CHANNEL_HOST_CAPABILITY.to_string(),
        function: function.to_string(),
        run_id: None,
        iteration: None,
    }
}

fn telegram_subscription_for(mgr: &SubscriptionManager, agent_id: &str) -> String {
    mgr.subscribe(
        agent_id,
        ChannelConfig {
            adapter_type: AdapterType::Telegram,
            params: vec![],
            outbound: Some(OutboundConfig {
                method: HttpMethod::Post,
                url_template: "https://api.telegram.org/bot/sendMessage".to_string(),
                headers: vec![("Content-Type".into(), "application/json".into())],
            }),
        },
    )
    .unwrap()
    .0
}

fn telegram_subscription(mgr: &SubscriptionManager) -> String {
    telegram_subscription_for(mgr, "agent-007")
}

fn handler_for(registry: &InMemoryHostRegistry, name: &str) -> Arc<dyn HostFunctionHandler> {
    let specs = registry.lookup(CHANNEL_HOST_CAPABILITY);
    let spec = specs.iter().find(|s| s.name == name).unwrap();
    spec.handler.clone()
}

/// T09 (AC-09): send-raw goes through HttpSecurityChain exactly once per call,
/// with propagated agent_id, preset-sourced allowlist, and pinned
/// `component_id = "cap-channel:{adapter_type}"`.
#[tokio::test]
async fn t09_send_raw_goes_through_security_chain() {
    let registry = InMemoryHostRegistry::new();
    let manager = Arc::new(SubscriptionManager::new());
    let chain = Arc::new(RecordingChain::new());
    let chain_dyn: Arc<dyn HttpSecurityChain> = chain.clone();
    let outbound = Arc::new(OutboundDispatcher::new(chain_dyn, manager.clone()));
    register_channel_host(
        &registry,
        ChannelHostBundle {
            manager: manager.clone(),
            outbound,
        },
    );

    let sub_id = telegram_subscription(&manager);
    let send_raw = handler_for(&registry, "send-raw");

    let data_val = Val::List(b"{\"text\":\"hi\"}".iter().map(|b| Val::U8(*b)).collect());
    send_raw
        .call(
            test_ctx("agent-007", "send-raw"),
            vec![Val::String(sub_id), data_val],
            1,
        )
        .await
        .unwrap();

    let calls = chain.calls();
    // (a) Chain called exactly once per send-raw.
    assert_eq!(calls.len(), 1, "expected exactly 1 chain call");
    // (b) agent_id is the WIT caller's, not the adapter's.
    assert_eq!(calls[0].agent_id, "agent-007");
    assert_ne!(calls[0].agent_id, "telegram");
    // (c) URL matches OutboundConfig.url_template.
    assert_eq!(calls[0].url, "https://api.telegram.org/bot/sendMessage");
    // (c.i) Method is POST.
    assert_eq!(calls[0].method, SharedHttpMethod::Post);
    // (e) component_id pinned with adapter type.
    assert_eq!(calls[0].component_id, "cap-channel:telegram");
    // (d) Allowlist sourced from host-authoritative preset.
    assert_eq!(
        calls[0].allowlist_patterns,
        vec!["https://api.telegram.org/".to_string()]
    );
}

/// T09 (AC-09): HttpError::AllowlistBlocked lowers to ChannelError::OutboundBlocked
/// which lowers to WIT `connection-failed` at the WIT boundary.
#[tokio::test]
async fn t09_allowlist_blocked_lowers_to_connection_failed() {
    let registry = InMemoryHostRegistry::new();
    let manager = Arc::new(SubscriptionManager::new());
    let chain = Arc::new(RecordingChain::rejecting(HttpError::AllowlistBlocked(
        "https://evil.example/".to_string(),
    )));
    let chain_dyn: Arc<dyn HttpSecurityChain> = chain.clone();
    let outbound = Arc::new(OutboundDispatcher::new(chain_dyn, manager.clone()));
    register_channel_host(
        &registry,
        ChannelHostBundle {
            manager: manager.clone(),
            outbound,
        },
    );

    // Owner = "agent-007" via telegram_subscription default; test_ctx
    // matches so ownership check passes and AllowlistBlocked surfaces.
    let sub_id = telegram_subscription(&manager);
    let send_raw = handler_for(&registry, "send-raw");

    let data_val = Val::List(b"x".iter().map(|b| Val::U8(*b)).collect());
    let result = send_raw
        .call(
            test_ctx("agent-007", "send-raw"),
            vec![Val::String(sub_id), data_val],
            1,
        )
        .await
        .unwrap();

    // result is Val::Result(Err(Some(Variant("connection-failed", _)))).
    match &result[0] {
        Val::Result(Err(Some(boxed))) => match boxed.as_ref() {
            Val::Variant(name, _) => assert_eq!(name, "connection-failed"),
            other => panic!("expected Variant, got {other:?}"),
        },
        other => panic!("expected Err arm, got {other:?}"),
    }
}

/// Plan Eval R4 Warning #4: allowlist source is host-authoritative preset,
/// NOT subscribe-time config — assert by driving through the public WIT
/// SendRawHandler with two different subscriptions of the same adapter type
/// and observing that the recorded allowlist is identical across both
/// (sourced from the same preset).
///
/// Note: this test deliberately routes through SendRawHandler (the public
/// path) rather than calling OutboundDispatcher::dispatch directly, because
/// `dispatch` is `pub(crate)` — that visibility narrowing is itself part of
/// AC-09's invariant enforcement (see plan §7).
#[tokio::test]
async fn allowlist_source_is_preset_not_config() {
    let registry = InMemoryHostRegistry::new();
    let manager = Arc::new(SubscriptionManager::new());
    let chain = Arc::new(RecordingChain::new());
    let chain_dyn: Arc<dyn HttpSecurityChain> = chain.clone();
    let outbound = Arc::new(OutboundDispatcher::new(chain_dyn, manager.clone()));
    register_channel_host(
        &registry,
        ChannelHostBundle {
            manager: manager.clone(),
            outbound,
        },
    );

    // Each subscription is owned by the agent that will drive send-raw
    // against it (so ownership check passes).
    let sub_a = telegram_subscription_for(&manager, "agent-1");
    let sub_b = telegram_subscription_for(&manager, "agent-2");
    let send_raw = handler_for(&registry, "send-raw");

    for (agent, sub) in [("agent-1", sub_a), ("agent-2", sub_b)] {
        let data_val = Val::List(b"x".iter().map(|b| Val::U8(*b)).collect());
        send_raw
            .call(
                test_ctx(agent, "send-raw"),
                vec![Val::String(sub), data_val],
                1,
            )
            .await
            .unwrap();
    }

    let calls = chain.calls();
    assert_eq!(calls.len(), 2);
    // Both calls have identical allowlist (sourced from same preset).
    assert_eq!(calls[0].allowlist_patterns, calls[1].allowlist_patterns);
    assert_eq!(
        calls[0].allowlist_patterns,
        vec!["https://api.telegram.org/".to_string()]
    );
}

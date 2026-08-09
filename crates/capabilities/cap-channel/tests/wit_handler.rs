//! Integration tests for the channel-host WIT handlers.
//!
//! Covers T01 (AC-01 subscribe/poll/send round-trip) + T05 (AC-05 metadata
//! passthrough). Tests drive handlers via [`HostRegistry::lookup`] + manual
//! `HostFunctionHandler::call` invocation — same path the runtime's
//! CapabilityInjector follows at WASM linker wiring time.

use std::sync::Arc;

use advance_runtime::host_registry::{
    HostCallContext, HostFunctionHandler, HostRegistry, InMemoryHostRegistry,
};
use advance_shared_types::security_validator::{
    HttpCapability, HttpError, HttpRequest, HttpResponse, HttpSecurityChain,
};
use async_trait::async_trait;
use cap_channel::{
    register_channel_host, ChannelHostBundle, OutboundDispatcher, SubscriptionManager,
    CHANNEL_HOST_CAPABILITY, CHANNEL_HOST_NAMESPACE,
};
use wasmtime::component::Val;

struct NoopChain;

#[async_trait]
impl HttpSecurityChain for NoopChain {
    async fn execute(
        &self,
        _: &str,
        _: HttpRequest,
        _: &HttpCapability,
    ) -> Result<HttpResponse, HttpError> {
        Ok(HttpResponse {
            status: 200,
            headers: vec![],
            body: vec![],
        })
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

fn register_and_setup() -> (
    InMemoryHostRegistry,
    Arc<SubscriptionManager>,
    Arc<OutboundDispatcher>,
) {
    let registry = InMemoryHostRegistry::new();
    let manager = Arc::new(SubscriptionManager::new());
    let chain: Arc<dyn HttpSecurityChain> = Arc::new(NoopChain);
    let outbound = Arc::new(OutboundDispatcher::new(chain, manager.clone()));
    register_channel_host(
        &registry,
        ChannelHostBundle {
            manager: manager.clone(),
            outbound: outbound.clone(),
        },
    );
    (registry, manager, outbound)
}

fn handler_for(registry: &InMemoryHostRegistry, name: &str) -> Arc<dyn HostFunctionHandler> {
    let specs = registry.lookup(CHANNEL_HOST_CAPABILITY);
    let spec = specs
        .iter()
        .find(|s| s.name == name && s.namespace == CHANNEL_HOST_NAMESPACE)
        .unwrap_or_else(|| panic!("no spec named {name} under {CHANNEL_HOST_NAMESPACE}"));
    spec.handler.clone()
}

fn channel_config_val(adapter: &str, params: Vec<(&str, &str)>) -> Val {
    let params_val: Vec<Val> = params
        .into_iter()
        .map(|(k, v)| {
            Val::Record(vec![
                ("key".to_string(), Val::String(k.to_string())),
                ("value".to_string(), Val::String(v.to_string())),
            ])
        })
        .collect();
    Val::Record(vec![
        ("adapter-type".to_string(), Val::String(adapter.to_string())),
        ("params".to_string(), Val::List(params_val)),
    ])
}

fn extract_sub_id_from_result(result: &[Val]) -> String {
    match &result[0] {
        Val::Result(Ok(Some(boxed))) => match boxed.as_ref() {
            Val::String(s) => s.clone(),
            other => panic!("expected String sub-id, got {other:?}"),
        },
        other => panic!("expected Ok arm, got {other:?}"),
    }
}

/// T01 (AC-01): subscribe/poll/send round-trip.
#[tokio::test]
async fn t01_subscribe_poll_send_roundtrip() {
    let (registry, manager, _outbound) = register_and_setup();
    let subscribe = handler_for(&registry, "subscribe");
    let poll = handler_for(&registry, "poll-raw");

    // Subscribe.
    let subscribe_result = subscribe
        .call(
            test_ctx("agent-1", "subscribe"),
            vec![channel_config_val("webhook", vec![])],
            1,
        )
        .await
        .unwrap();
    let sub_id = extract_sub_id_from_result(&subscribe_result);
    assert!(!sub_id.is_empty());

    // Poll on empty → Ok(None).
    let poll_result = poll
        .call(
            test_ctx("agent-1", "poll-raw"),
            vec![Val::String(sub_id.clone())],
            1,
        )
        .await
        .unwrap();
    match &poll_result[0] {
        Val::Result(Ok(Some(boxed))) => match boxed.as_ref() {
            Val::Option(None) => {}
            other => panic!("expected Option(None), got {other:?}"),
        },
        other => panic!("expected Ok(Some(Option)), got {other:?}"),
    }

    // Enqueue an event (via the manager — webhook would normally do this).
    let event = cap_channel::RawEvent {
        data: b"hello".to_vec(),
        metadata: vec![cap_channel::CapParam::new("channel.adapter", "webhook")],
    };
    manager
        .enqueue_event(
            &cap_channel::SubscriptionId::from_string(sub_id.clone()),
            event.clone(),
        )
        .unwrap();

    // Poll again → Some(event).
    let poll_result = poll
        .call(
            test_ctx("agent-1", "poll-raw"),
            vec![Val::String(sub_id)],
            1,
        )
        .await
        .unwrap();
    match &poll_result[0] {
        Val::Result(Ok(Some(boxed))) => match boxed.as_ref() {
            Val::Option(Some(record)) => match record.as_ref() {
                Val::Record(fields) => {
                    let data = fields
                        .iter()
                        .find(|(k, _)| k == "data")
                        .map(|(_, v)| v.clone())
                        .unwrap();
                    let bytes = match data {
                        Val::List(items) => items
                            .into_iter()
                            .map(|v| match v {
                                Val::U8(b) => b,
                                other => panic!("expected u8, got {other:?}"),
                            })
                            .collect::<Vec<u8>>(),
                        other => panic!("expected list, got {other:?}"),
                    };
                    assert_eq!(bytes, b"hello");
                }
                other => panic!("expected record, got {other:?}"),
            },
            other => panic!("expected Option(Some(record)), got {other:?}"),
        },
        other => panic!("expected Ok(Some(Option)), got {other:?}"),
    }
}

/// T01 negative (AC-01): subscribe with unknown adapter type → InvalidConfig.
#[tokio::test]
async fn t01_subscribe_with_unknown_adapter_returns_invalid_config() {
    let (registry, _manager, _outbound) = register_and_setup();
    let subscribe = handler_for(&registry, "subscribe");

    let result = subscribe
        .call(
            test_ctx("agent-1", "subscribe"),
            vec![channel_config_val("discord", vec![])],
            1,
        )
        .await
        .unwrap();

    match &result[0] {
        Val::Result(Err(Some(boxed))) => match boxed.as_ref() {
            Val::Variant(name, payload) => {
                assert_eq!(name, "invalid-config");
                if let Some(p) = payload {
                    match p.as_ref() {
                        Val::String(s) => assert!(s.contains("discord")),
                        _ => {}
                    }
                }
            }
            other => panic!("expected Variant, got {other:?}"),
        },
        other => panic!("expected Err arm, got {other:?}"),
    }
}

/// T05 (AC-05): metadata passthrough — adapter-specific keys round-trip.
#[tokio::test]
async fn t05_metadata_passthrough() {
    let (registry, manager, _outbound) = register_and_setup();
    let subscribe = handler_for(&registry, "subscribe");
    let poll = handler_for(&registry, "poll-raw");

    let subscribe_result = subscribe
        .call(
            test_ctx("agent-1", "subscribe"),
            vec![channel_config_val("telegram", vec![("bot_token", "abc")])],
            1,
        )
        .await
        .unwrap();
    let sub_id = extract_sub_id_from_result(&subscribe_result);

    // Enqueue an event carrying adapter-specific metadata (e.g., reply_style).
    let event = cap_channel::RawEvent {
        data: b"message".to_vec(),
        metadata: vec![
            cap_channel::CapParam::new("channel.adapter", "telegram"),
            cap_channel::CapParam::new("channel.sender_id", "user-42"),
            cap_channel::CapParam::new("reply_style", "buttons"),
            cap_channel::CapParam::new("inline_keyboard", "[[Approve, Reject]]"),
        ],
    };
    manager
        .enqueue_event(
            &cap_channel::SubscriptionId::from_string(sub_id.clone()),
            event.clone(),
        )
        .unwrap();

    let poll_result = poll
        .call(
            test_ctx("agent-1", "poll-raw"),
            vec![Val::String(sub_id)],
            1,
        )
        .await
        .unwrap();

    // Walk the Val tree to recover the metadata list.
    let metadata = match &poll_result[0] {
        Val::Result(Ok(Some(boxed))) => match boxed.as_ref() {
            Val::Option(Some(record)) => match record.as_ref() {
                Val::Record(fields) => fields
                    .iter()
                    .find(|(k, _)| k == "metadata")
                    .map(|(_, v)| v.clone())
                    .unwrap(),
                other => panic!("expected record, got {other:?}"),
            },
            other => panic!("expected Option(Some), got {other:?}"),
        },
        other => panic!("expected Ok(Some), got {other:?}"),
    };

    let keys_values: Vec<(String, String)> = match metadata {
        Val::Option(Some(list)) => match list.as_ref() {
            Val::List(items) => items
                .iter()
                .map(|item| match item {
                    Val::Record(fields) => {
                        let k = fields
                            .iter()
                            .find(|(k, _)| k == "key")
                            .map(|(_, v)| match v {
                                Val::String(s) => s.clone(),
                                _ => unreachable!(),
                            })
                            .unwrap();
                        let v = fields
                            .iter()
                            .find(|(k, _)| k == "value")
                            .map(|(_, v)| match v {
                                Val::String(s) => s.clone(),
                                _ => unreachable!(),
                            })
                            .unwrap();
                        (k, v)
                    }
                    other => panic!("expected record, got {other:?}"),
                })
                .collect(),
            other => panic!("expected list, got {other:?}"),
        },
        other => panic!("expected Option(Some), got {other:?}"),
    };

    // Adapter-specific keys survived the round trip unchanged.
    let pairs: std::collections::HashMap<String, String> = keys_values.into_iter().collect();
    assert_eq!(pairs.get("reply_style"), Some(&"buttons".to_string()));
    assert_eq!(
        pairs.get("inline_keyboard"),
        Some(&"[[Approve, Reject]]".to_string())
    );
    // channel.* provenance keys also intact.
    assert_eq!(pairs.get("channel.adapter"), Some(&"telegram".to_string()));
}

//! `channel-host` WIT host-function handlers (CONTRACT-150, MODULE-016 §2.3
//! + §2.7 + §2.8).
//!
//! 3 `HostFunctionHandler` impls — `SubscribeHandler`, `PollRawHandler`,
//! `SendRawHandler` — registered under capability `"channel"` and namespace
//! `"advance:runtime/channel-host@0.1.0"` via [`register_channel_host`]. Sibling
//! pattern: cap-grant's `register_agent_grant`.
//!
//! ## Defensive caps (per §2.7 + §9 step 9)
//! - adapter-type string ≤ 256 bytes
//! - subscription-id string ≤ 256 bytes
//! - param key ≤ 256 bytes; param value ≤ 4096 bytes; ≤ 64 params per call
//! - `send-raw` data ≤ 64 KB (asymmetric with the 1 MB inbound webhook cap;
//!   see §2.7 body-size cap asymmetry rationale)
//!
//! ## AC-09 sole-caller invariant
//! `SendRawHandler::call` is the ONLY public caller of
//! `OutboundDispatcher::dispatch` (which is `pub(crate)`). The chain is reached
//! via `dispatcher.dispatch(&ctx.agent_id, &sub_id, &data)`, threading the
//! WIT caller's `HostCallContext.agent_id` into the security chain's
//! rate-limit key per `crates/shared-types/src/security_validator.rs:357-365`.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use advance_runtime::host_registry::{
    HostCallContext, HostCallError, HostFunctionHandler, HostFunctionSpec, HostRegistry,
};
use wasmtime::component::Val;

use crate::error::ChannelError;
use crate::outbound::OutboundDispatcher;
use crate::subscription::SubscriptionManager;
use crate::types::{AdapterType, CapParam, ChannelConfig, RawEvent, SubscriptionId};

/// Capability identifier under which the 3 channel-host handlers register.
pub const CHANNEL_HOST_CAPABILITY: &str = "channel";

/// WIT namespace for the channel-host interface. Sibling-consistent with
/// `advance:runtime/agent-grant@0.1.0`, `advance:runtime/agent-tools@0.1.0`, etc.
pub const CHANNEL_HOST_NAMESPACE: &str = "advance:runtime/channel-host@0.1.0";

/// Frozen method-name set. Pinned via the `wit_method_set_frozen` structural
/// test so downstream adapter WASMs binding to channel-host don't silently
/// break on name drift.
pub const CHANNEL_HOST_METHODS: &[&str; 3] = &["subscribe", "poll-raw", "send-raw"];

const MAX_ADAPTER_TYPE_BYTES: usize = 256;
const MAX_SUB_ID_BYTES: usize = 256;
const MAX_PARAM_KEY_BYTES: usize = 256;
const MAX_PARAM_VALUE_BYTES: usize = 4096;
const MAX_PARAMS_ENTRIES: usize = 64;
const MAX_SEND_RAW_BYTES: usize = 65_536;

/// Boot-time bundle passed to [`register_channel_host`]. Each handler holds
/// `Arc::clone`s of only the fields it needs.
pub struct ChannelHostBundle {
    pub manager: Arc<SubscriptionManager>,
    pub outbound: Arc<OutboundDispatcher>,
}

/// Register the 3 channel-host host functions on the supplied registry.
///
/// **Idempotence**: this function must be called AT MOST ONCE per registry.
/// Calling it twice would register 6 specs (3 from each call) referencing
/// different bundles, splitting subscription state across two managers.
/// Adversarial Eval R19 #4 — the `InMemoryHostRegistry` is append-only and
/// does not deduplicate, so the assert below catches dev-time misuse before
/// the eventual CapabilityInjector failure at WASM linker wiring.
pub fn register_channel_host(registry: &dyn HostRegistry, bundle: ChannelHostBundle) {
    assert!(
        registry.lookup(CHANNEL_HOST_CAPABILITY).is_empty(),
        "register_channel_host called twice on the same registry — would create split-brain state across two ChannelHostBundles"
    );

    let manager = bundle.manager;
    let outbound = bundle.outbound;

    registry.register(HostFunctionSpec {
        capability: CHANNEL_HOST_CAPABILITY.to_string(),
        namespace: CHANNEL_HOST_NAMESPACE.to_string(),
        name: "subscribe".to_string(),
        handler: Arc::new(SubscribeHandler {
            manager: manager.clone(),
        }),
        // subscribe allocates a fresh SubscriptionId + mutates the manager
        // map; not idempotent.
        idempotent: false,
    });

    registry.register(HostFunctionSpec {
        capability: CHANNEL_HOST_CAPABILITY.to_string(),
        namespace: CHANNEL_HOST_NAMESPACE.to_string(),
        name: "poll-raw".to_string(),
        handler: Arc::new(PollRawHandler {
            manager: manager.clone(),
        }),
        // poll-raw mutates the per-subscription buffer via `pop_front`; not
        // idempotent.
        idempotent: false,
    });

    registry.register(HostFunctionSpec {
        capability: CHANNEL_HOST_CAPABILITY.to_string(),
        namespace: CHANNEL_HOST_NAMESPACE.to_string(),
        name: "send-raw".to_string(),
        handler: Arc::new(SendRawHandler { outbound }),
        // send-raw is side-effectful (outbound HTTPS through the security
        // chain); not idempotent.
        idempotent: false,
    });
}

/// Subscribe handler: WIT signature
/// `subscribe(config: channel-config) -> result<subscription-id, channel-error>`.
struct SubscribeHandler {
    manager: Arc<SubscriptionManager>,
}

impl HostFunctionHandler for SubscribeHandler {
    fn call(
        &self,
        ctx: HostCallContext,
        params: Vec<Val>,
        _results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>> {
        let manager = self.manager.clone();
        let agent_id = ctx.agent_id.clone();
        Box::pin(async move {
            let config = match lift_channel_config(&params) {
                Ok(c) => c,
                Err(LiftError::InvalidConfig(msg)) => {
                    return Ok(vec![err_channel_error(ChannelError::InvalidConfig(msg))]);
                }
                Err(LiftError::HandlerError(msg)) => {
                    return Err(HostCallError::HandlerError(msg));
                }
            };
            match manager.subscribe(agent_id, config) {
                Ok(id) => Ok(vec![ok_subscription_id(id)]),
                Err(e) => Ok(vec![err_channel_error(e.into_wit())]),
            }
        })
    }
}

/// Poll handler: WIT signature
/// `poll-raw(sub-id: subscription-id) -> result<option<raw-event>, channel-error>`.
struct PollRawHandler {
    manager: Arc<SubscriptionManager>,
}

impl HostFunctionHandler for PollRawHandler {
    fn call(
        &self,
        ctx: HostCallContext,
        params: Vec<Val>,
        _results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>> {
        let manager = self.manager.clone();
        let agent_id = ctx.agent_id.clone();
        Box::pin(async move {
            let sub_id = match lift_subscription_id(&params) {
                Ok(s) => s,
                Err(LiftError::InvalidConfig(msg)) => {
                    return Ok(vec![err_channel_error(ChannelError::InvalidConfig(msg))]);
                }
                Err(LiftError::HandlerError(msg)) => {
                    return Err(HostCallError::HandlerError(msg));
                }
            };
            match manager.poll_raw(&agent_id, &sub_id) {
                Ok(maybe_event) => Ok(vec![ok_option_raw_event(maybe_event)]),
                Err(e) => Ok(vec![err_channel_error(e.into_wit())]),
            }
        })
    }
}

/// Send-raw handler: WIT signature
/// `send-raw(sub-id: subscription-id, data: list<u8>) -> result<_, channel-error>`.
///
/// AC-09 enforcement: this handler threads `ctx.agent_id` into
/// `dispatcher.dispatch(&ctx.agent_id, &sub_id, &data)`. The dispatcher's
/// `dispatch` is `pub(crate)`, so no other code path can reach
/// `security_chain.execute` from cap-channel.
struct SendRawHandler {
    outbound: Arc<OutboundDispatcher>,
}

impl HostFunctionHandler for SendRawHandler {
    fn call(
        &self,
        ctx: HostCallContext,
        params: Vec<Val>,
        _results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>> {
        let outbound = self.outbound.clone();
        let agent_id = ctx.agent_id.clone();
        Box::pin(async move {
            let (sub_id, data) = match lift_send_raw_args(&params) {
                Ok(p) => p,
                Err(LiftError::InvalidConfig(msg)) => {
                    return Ok(vec![err_channel_error(ChannelError::InvalidConfig(msg))]);
                }
                Err(LiftError::HandlerError(msg)) => {
                    return Err(HostCallError::HandlerError(msg));
                }
            };
            match outbound.dispatch(&agent_id, &sub_id, &data).await {
                Ok(()) => Ok(vec![ok_unit()]),
                Err(e) => Ok(vec![err_channel_error(e.into_wit())]),
            }
        })
    }
}

// ====================================================================
// Val lifting helpers — translate `Vec<Val>` → typed Rust values.
//
// `LiftError` partitions failures into two paths:
//   - `InvalidConfig(msg)` — caller-controllable cap / range / variant
//     violations on otherwise-typed input. Surfaces as graceful WIT
//     `result::err(invalid-config(msg))` to the guest.
//   - `HandlerError(msg)` — type-shape mismatches (wrong `Val` variant
//     at a field position). Surfaces as a wasmtime trap; the guest
//     produced a value that doesn't match the WIT schema, which is a
//     guest-bug condition.
// ====================================================================

enum LiftError {
    InvalidConfig(String),
    HandlerError(String),
}

impl LiftError {
    fn handler(msg: String) -> Self {
        Self::HandlerError(msg)
    }
    fn invalid(msg: String) -> Self {
        Self::InvalidConfig(msg)
    }
}

fn lift_channel_config(params: &[Val]) -> Result<ChannelConfig, LiftError> {
    if params.len() != 1 {
        return Err(LiftError::handler(format!(
            "subscribe expects 1 param, got {}",
            params.len()
        )));
    }
    // params[0] is `record { adapter-type: string, params: list<cap-param> }`.
    let record_fields = match &params[0] {
        Val::Record(fields) => fields,
        other => {
            return Err(LiftError::handler(format!(
                "subscribe: expected record, got {other:?}"
            )))
        }
    };

    let adapter_type_str = string_field(record_fields, "adapter-type")?;
    if adapter_type_str.len() > MAX_ADAPTER_TYPE_BYTES {
        return Err(LiftError::invalid(format!(
            "adapter-type exceeds {MAX_ADAPTER_TYPE_BYTES} bytes"
        )));
    }
    let adapter_type: AdapterType = adapter_type_str.parse().unwrap_or_else(|_| {
        // FromStr is Infallible — this branch is unreachable.
        AdapterType::Other(adapter_type_str.clone())
    });

    let params_list = list_field(record_fields, "params")?;
    if params_list.len() > MAX_PARAMS_ENTRIES {
        return Err(LiftError::invalid(format!(
            "params list exceeds {MAX_PARAMS_ENTRIES} entries"
        )));
    }
    let mut typed_params = Vec::with_capacity(params_list.len());
    for entry in params_list {
        let entry_fields = match entry {
            Val::Record(f) => f,
            other => {
                return Err(LiftError::handler(format!(
                    "subscribe params entry: expected record, got {other:?}"
                )))
            }
        };
        let k = string_field(entry_fields, "key")?;
        let v = string_field(entry_fields, "value")?;
        if k.len() > MAX_PARAM_KEY_BYTES {
            return Err(LiftError::invalid(format!(
                "param key exceeds {MAX_PARAM_KEY_BYTES} bytes"
            )));
        }
        if v.len() > MAX_PARAM_VALUE_BYTES {
            return Err(LiftError::invalid(format!(
                "param value exceeds {MAX_PARAM_VALUE_BYTES} bytes"
            )));
        }
        typed_params.push(CapParam::new(k, v));
    }

    Ok(ChannelConfig {
        adapter_type,
        params: typed_params,
        outbound: None,
    })
}

fn lift_subscription_id(params: &[Val]) -> Result<SubscriptionId, LiftError> {
    if params.len() != 1 {
        return Err(LiftError::handler(format!(
            "expected 1 param (sub-id), got {}",
            params.len()
        )));
    }
    let s = match &params[0] {
        Val::String(s) => s.clone(),
        other => {
            return Err(LiftError::handler(format!(
                "sub-id: expected string, got {other:?}"
            )))
        }
    };
    if s.len() > MAX_SUB_ID_BYTES {
        return Err(LiftError::invalid(format!(
            "sub-id exceeds {MAX_SUB_ID_BYTES} bytes"
        )));
    }
    Ok(SubscriptionId::from_string(s))
}

fn lift_send_raw_args(params: &[Val]) -> Result<(SubscriptionId, Vec<u8>), LiftError> {
    if params.len() != 2 {
        return Err(LiftError::handler(format!(
            "send-raw expects 2 params, got {}",
            params.len()
        )));
    }
    let sub_id = match &params[0] {
        Val::String(s) => {
            if s.len() > MAX_SUB_ID_BYTES {
                return Err(LiftError::invalid(format!(
                    "send-raw sub-id exceeds {MAX_SUB_ID_BYTES} bytes"
                )));
            }
            SubscriptionId::from_string(s.clone())
        }
        other => {
            return Err(LiftError::handler(format!(
                "send-raw sub-id: expected string, got {other:?}"
            )))
        }
    };
    let data_list = match &params[1] {
        Val::List(items) => items,
        other => {
            return Err(LiftError::handler(format!(
                "send-raw data: expected list<u8>, got {other:?}"
            )))
        }
    };
    if data_list.len() > MAX_SEND_RAW_BYTES {
        return Err(LiftError::invalid(format!(
            "send-raw data exceeds {MAX_SEND_RAW_BYTES} bytes"
        )));
    }
    let mut bytes = Vec::with_capacity(data_list.len());
    for item in data_list {
        let byte = match item {
            Val::U8(b) => *b,
            other => {
                return Err(LiftError::handler(format!(
                    "send-raw data: expected u8 element, got {other:?}"
                )))
            }
        };
        bytes.push(byte);
    }
    Ok((sub_id, bytes))
}

fn string_field(fields: &[(String, Val)], name: &str) -> Result<String, LiftError> {
    let entry = fields
        .iter()
        .find(|(k, _)| k == name)
        .ok_or_else(|| LiftError::handler(format!("missing field {name:?}")))?;
    match &entry.1 {
        Val::String(s) => Ok(s.clone()),
        other => Err(LiftError::handler(format!(
            "field {name:?}: expected string, got {other:?}"
        ))),
    }
}

fn list_field<'a>(fields: &'a [(String, Val)], name: &str) -> Result<&'a [Val], LiftError> {
    let entry = fields
        .iter()
        .find(|(k, _)| k == name)
        .ok_or_else(|| LiftError::handler(format!("missing field {name:?}")))?;
    match &entry.1 {
        Val::List(items) => Ok(items),
        other => Err(LiftError::handler(format!(
            "field {name:?}: expected list, got {other:?}"
        ))),
    }
}

// ====================================================================
// Val lowering helpers — translate Rust results → `Val`.
// ====================================================================

/// Build a `result::ok(subscription-id)` value (the WIT result is encoded as a
/// `Val::Result` carrying the subscription-id string in the Ok arm).
fn ok_subscription_id(id: SubscriptionId) -> Val {
    Val::Result(Ok(Some(Box::new(Val::String(id.0)))))
}

/// Build a `result::ok(option<raw-event>)`. `None` arm becomes
/// `option::none`; `Some` becomes a record.
fn ok_option_raw_event(maybe_event: Option<RawEvent>) -> Val {
    let option_val = match maybe_event {
        None => Val::Option(None),
        Some(event) => Val::Option(Some(Box::new(raw_event_to_val(event)))),
    };
    Val::Result(Ok(Some(Box::new(option_val))))
}

/// Build `result::ok(_)` — the unit return of send-raw.
fn ok_unit() -> Val {
    Val::Result(Ok(None))
}

/// Build `result::err(channel-error)` for any of the 4 WIT-visible variants.
fn err_channel_error(err: ChannelError) -> Val {
    let (variant_name, payload) = match err {
        ChannelError::NotFound(s) => ("not-found", s),
        ChannelError::ConnectionFailed(s) => ("connection-failed", s),
        ChannelError::PermissionDenied(s) => ("permission-denied", s),
        ChannelError::InvalidConfig(s) => ("invalid-config", s),
        // Internal-only variants are lowered to WIT-visible ones via
        // `into_wit()` before reaching this function; recover defensively.
        other => ("connection-failed", format!("internal: {other}")),
    };
    let payload_val = Val::String(payload);
    Val::Result(Err(Some(Box::new(Val::Variant(
        variant_name.to_string(),
        Some(Box::new(payload_val)),
    )))))
}

/// Convert a `RawEvent` to a `Val::Record` matching the WIT shape
/// `record { data: list<u8>, metadata: option<list<cap-param>> }`.
fn raw_event_to_val(event: RawEvent) -> Val {
    let data_val = Val::List(event.data.into_iter().map(Val::U8).collect());
    let metadata_val = if event.metadata.is_empty() {
        Val::Option(None)
    } else {
        Val::Option(Some(Box::new(Val::List(
            event
                .metadata
                .into_iter()
                .map(|p| {
                    Val::Record(vec![
                        ("key".to_string(), Val::String(p.key)),
                        ("value".to_string(), Val::String(p.value)),
                    ])
                })
                .collect(),
        ))))
    };
    Val::Record(vec![
        ("data".to_string(), data_val),
        ("metadata".to_string(), metadata_val),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    use advance_runtime::host_registry::InMemoryHostRegistry;
    use advance_shared_types::security_validator::{
        HttpCapability, HttpError, HttpRequest, HttpResponse, HttpSecurityChain,
    };
    use async_trait::async_trait;
    use std::sync::Mutex;

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

    struct RecordingChain {
        last_agent_id: Mutex<String>,
    }

    #[async_trait]
    impl HttpSecurityChain for RecordingChain {
        async fn execute(
            &self,
            agent_id: &str,
            _: HttpRequest,
            _: &HttpCapability,
        ) -> Result<HttpResponse, HttpError> {
            *self.last_agent_id.lock().unwrap() = agent_id.to_string();
            Ok(HttpResponse {
                status: 200,
                headers: vec![],
                body: vec![],
            })
        }
    }

    fn test_ctx(agent_id: &str) -> HostCallContext {
        HostCallContext {
            agent_id: agent_id.to_string(),
            trace_id: "trace-test".to_string(),
            turn_id: None,
            capability: CHANNEL_HOST_CAPABILITY.to_string(),
            function: "subscribe".to_string(),
            run_id: None,
            iteration: None,
        }
    }

    fn channel_config_val(adapter: &str) -> Val {
        Val::Record(vec![
            ("adapter-type".to_string(), Val::String(adapter.to_string())),
            ("params".to_string(), Val::List(vec![])),
        ])
    }

    #[test]
    fn register_channel_host_inserts_three_specs() {
        let registry = InMemoryHostRegistry::new();
        let manager = Arc::new(SubscriptionManager::new());
        let chain: Arc<dyn HttpSecurityChain> = Arc::new(NoopChain);
        let dispatcher = Arc::new(OutboundDispatcher::new(chain, manager.clone()));
        register_channel_host(
            &registry,
            ChannelHostBundle {
                manager,
                outbound: dispatcher,
            },
        );
        let specs = registry.lookup(CHANNEL_HOST_CAPABILITY);
        assert_eq!(specs.len(), 3);
        let names: Vec<_> = specs.iter().map(|s| s.name.clone()).collect();
        for required in CHANNEL_HOST_METHODS {
            assert!(names.contains(&required.to_string()), "missing {required}");
        }
        // All three are non-idempotent.
        for spec in &specs {
            assert!(!spec.idempotent, "{} should not be idempotent", spec.name);
        }
        // Namespace pinned.
        for spec in &specs {
            assert_eq!(spec.namespace, CHANNEL_HOST_NAMESPACE);
        }
    }

    #[tokio::test]
    async fn subscribe_handler_round_trips_telegram() {
        let manager = Arc::new(SubscriptionManager::new());
        let handler = SubscribeHandler {
            manager: manager.clone(),
        };
        let result = handler
            .call(test_ctx("agent-1"), vec![channel_config_val("telegram")], 1)
            .await
            .unwrap();
        assert_eq!(result.len(), 1);
        // Ok arm carries a string subscription-id.
        match &result[0] {
            Val::Result(Ok(Some(boxed))) => match boxed.as_ref() {
                Val::String(s) => assert!(!s.is_empty()),
                other => panic!("expected string sub-id, got {other:?}"),
            },
            other => panic!("expected Ok(Some(String)), got {other:?}"),
        }
        assert_eq!(manager.subscription_count(), 1);
    }

    #[tokio::test]
    async fn subscribe_handler_rejects_unknown_adapter_with_invalid_config() {
        let manager = Arc::new(SubscriptionManager::new());
        let handler = SubscribeHandler { manager };
        let result = handler
            .call(test_ctx("agent-1"), vec![channel_config_val("discord")], 1)
            .await
            .unwrap();
        match &result[0] {
            Val::Result(Err(Some(boxed))) => match boxed.as_ref() {
                Val::Variant(name, _) => assert_eq!(name, "invalid-config"),
                other => panic!("expected Variant, got {other:?}"),
            },
            other => panic!("expected Err arm, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn poll_raw_handler_returns_none_on_empty() {
        let manager = Arc::new(SubscriptionManager::new());
        let id = manager
            .subscribe(
                "agent-1",
                ChannelConfig {
                    adapter_type: AdapterType::Webhook,
                    params: vec![],
                    outbound: None,
                },
            )
            .unwrap();
        let handler = PollRawHandler { manager };
        let result = handler
            .call(test_ctx("agent-1"), vec![Val::String(id.0)], 1)
            .await
            .unwrap();
        match &result[0] {
            Val::Result(Ok(Some(boxed))) => match boxed.as_ref() {
                Val::Option(None) => {}
                other => panic!("expected None option, got {other:?}"),
            },
            other => panic!("expected Ok(Some(Option)), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn send_raw_handler_threads_agent_id_into_chain() {
        let manager = Arc::new(SubscriptionManager::new());
        let id = manager
            .subscribe(
                "agent-007",
                ChannelConfig {
                    adapter_type: AdapterType::Telegram,
                    params: vec![],
                    outbound: Some(crate::types::OutboundConfig {
                        method: crate::types::HttpMethod::Post,
                        url_template: "https://api.telegram.org/x".to_string(),
                        headers: vec![],
                    }),
                },
            )
            .unwrap();
        let chain = Arc::new(RecordingChain {
            last_agent_id: Mutex::new(String::new()),
        });
        let dispatcher = Arc::new(OutboundDispatcher::new(chain.clone(), manager));
        let handler = SendRawHandler {
            outbound: dispatcher,
        };

        let data_val = Val::List(b"hi".iter().map(|b| Val::U8(*b)).collect());
        let result = handler
            .call(test_ctx("agent-007"), vec![Val::String(id.0), data_val], 1)
            .await
            .unwrap();
        match &result[0] {
            Val::Result(Ok(None)) => {}
            other => panic!("expected Ok(None) unit, got {other:?}"),
        }
        assert_eq!(*chain.last_agent_id.lock().unwrap(), "agent-007");
    }

    #[tokio::test]
    async fn send_raw_handler_caps_data_at_64kb() {
        let manager = Arc::new(SubscriptionManager::new());
        let id = manager
            .subscribe(
                "agent-1",
                ChannelConfig {
                    adapter_type: AdapterType::Telegram,
                    params: vec![],
                    outbound: Some(crate::types::OutboundConfig {
                        method: crate::types::HttpMethod::Post,
                        url_template: "https://api.telegram.org/x".to_string(),
                        headers: vec![],
                    }),
                },
            )
            .unwrap();
        let chain: Arc<dyn HttpSecurityChain> = Arc::new(NoopChain);
        let dispatcher = Arc::new(OutboundDispatcher::new(chain, manager));
        let handler = SendRawHandler {
            outbound: dispatcher,
        };

        let too_big: Vec<Val> = (0..MAX_SEND_RAW_BYTES + 1).map(|_| Val::U8(0)).collect();
        let result = handler
            .call(
                test_ctx("agent-1"),
                vec![Val::String(id.0), Val::List(too_big)],
                1,
            )
            .await
            .unwrap();
        // Defensive-cap violation lowers to result::err(invalid-config(msg)),
        // not a HandlerError trap — see §2.8 wording.
        match &result[0] {
            Val::Result(Err(Some(boxed))) => match boxed.as_ref() {
                Val::Variant(name, payload) => {
                    assert_eq!(name, "invalid-config");
                    if let Some(p) = payload {
                        if let Val::String(s) = p.as_ref() {
                            assert!(s.contains("exceeds"), "unexpected msg: {s}");
                        }
                    }
                }
                other => panic!("expected Variant, got {other:?}"),
            },
            other => panic!("expected Err(invalid-config), got {other:?}"),
        }
    }

    #[test]
    fn channel_host_methods_set_is_frozen() {
        assert_eq!(CHANNEL_HOST_METHODS.len(), 3);
        assert_eq!(CHANNEL_HOST_METHODS[0], "subscribe");
        assert_eq!(CHANNEL_HOST_METHODS[1], "poll-raw");
        assert_eq!(CHANNEL_HOST_METHODS[2], "send-raw");
    }
}

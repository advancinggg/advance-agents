//! Outbound HTTPS dispatcher — the SOLE path from `send-raw` to the runtime's
//! `HttpSecurityChain` (CONTRACT-111).
//!
//! AC-09 invariant: every `send-raw` WIT handler invocation results in
//! exactly one `security_chain.execute(...)` call with the production chain.
//! Structural enforcement layers:
//!
//! 1. `OutboundDispatcher::dispatch` is `pub(crate)`, so external Rust
//!    callers cannot drive arbitrary `HttpRequest`s through the dispatcher.
//! 2. The WIT `SendRawHandler::call` (in `wit_impl.rs`) is the only public
//!    caller of `dispatch`. Adapter WASM guests reach outbound only through
//!    that WIT path.
//! 3. The HTTPS chain receives `caller_agent_id` from the WIT call frame's
//!    `HostCallContext::agent_id` — never the subscription's adapter type.
//! 4. The synthetic `HttpCapability` is built host-authoritatively:
//!    - `allowlist` from [`crate::sandbox::AdapterCapabilitySet`] preset.
//!    - `component_id` = `format!("cap-channel:{adapter_type}")`.
//!    - `credentials` empty for Slice B; grant-config-sourced credentials are
//!      a later slice.
//! 5. HTTP method restricted to `{POST, PUT, PATCH, GET}`; destructive verbs
//!    rejected with `InvalidConfig` BEFORE the chain is invoked.
//!
//! See MODULE-016 §2.7 send-raw flow + §3.6 Known-Gap entries.

use std::sync::Arc;

use advance_shared_types::outbound::OutboundTarget;
use advance_shared_types::security_validator::HttpSecurityChain;
use advance_shared_types::traits::EventBusEmit;

use crate::egress::{HttpEgress, OutboundTransport};
use crate::error::ChannelError;
use crate::subscription::SubscriptionManager;
use crate::types::SubscriptionId;

/// Outbound dispatcher — the WIT `send-raw` entry point. Phase-2 Step-3
/// generalizes the egress behind [`HttpEgress`] / [`OutboundTransport`]: this
/// dispatcher is now a **thin delegator** that looks up the subscription and
/// forwards to `HttpEgress::send`. The `HttpSecurityChain` call site moved into
/// `egress.rs` (the AC-09 single-consumer invariant is re-established there;
/// this module no longer contains `security_chain.execute`).
pub struct OutboundDispatcher {
    egress: Arc<HttpEgress>,
    manager: Arc<SubscriptionManager>,
}

impl OutboundDispatcher {
    pub fn new(
        security_chain: Arc<dyn HttpSecurityChain>,
        manager: Arc<SubscriptionManager>,
    ) -> Self {
        Self {
            egress: Arc::new(HttpEgress::new(security_chain)),
            manager,
        }
    }

    /// Lifecycle-harvest (2026-06-12) opt-in ctor — thread an observability
    /// sink into the dispatcher's internal [`HttpEgress`] so guest `send-raw`
    /// chain passes emit `channel.raw_sent` (MODULE-016-AC-12 payload +
    /// redaction contract; the emit site stays `HttpEgress::send`). Additive:
    /// `new()` callers keep the bus-less egress and emit nothing.
    pub fn new_with_event_bus(
        security_chain: Arc<dyn HttpSecurityChain>,
        manager: Arc<SubscriptionManager>,
        event_bus: Arc<dyn EventBusEmit>,
    ) -> Self {
        Self {
            egress: Arc::new(HttpEgress::new(security_chain).with_event_bus(event_bus)),
            manager,
        }
    }

    /// Dispatch a `send-raw` payload through the security chain (via `HttpEgress`).
    ///
    /// **`caller_agent_id`** is the WIT caller's identity (sourced from the WIT
    /// host-call frame's `HostCallContext.agent_id`). The WIT `send-raw` path has
    /// no per-message target, so it uses a passthrough `ChatReply` with an empty
    /// `conversation_id` — `HttpEgress`'s renderer then emits the raw `data` body
    /// against the preset `url_template`, byte-identical to the pre-Step-3 path.
    ///
    /// `pub(crate)` so external Rust callers can't bypass the chain. The single
    /// `HttpSecurityChain::execute` call site lives in `egress.rs::HttpEgress::send`.
    pub(crate) async fn dispatch(
        &self,
        caller_agent_id: &str,
        sub_id: &SubscriptionId,
        data: &[u8],
    ) -> Result<(), ChannelError> {
        // 1. Lookup subscription (NotFound stays here, in the delegator).
        let sub = self
            .manager
            .lookup(sub_id)
            .ok_or_else(|| ChannelError::NotFound(format!("subscription {}", sub_id.as_str())))?;

        // 2. WIT send-raw has no per-message routing → passthrough target. The
        //    ownership check, missing-outbound-config, method/CRLF guards, and the
        //    chain call all live in HttpEgress::send.
        let target = OutboundTarget::ChatReply {
            conversation_id: String::new(),
            reply_address: vec![],
        };
        self.egress
            .send(caller_agent_id, sub.as_ref(), target, data)
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Mutex;

    use advance_shared_types::security_validator::{
        HttpCapability, HttpError, HttpMethod as SharedHttpMethod, HttpRequest, HttpResponse,
        HttpSecurityChain,
    };
    use async_trait::async_trait;

    use crate::sandbox::AdapterCapabilitySet;
    use crate::types::{AdapterType, ChannelConfig, HttpMethod, OutboundConfig};

    /// MockHttpSecurityChain — records every `execute` call.
    struct MockChain {
        calls: Mutex<Vec<MockCall>>,
        fail_with: Option<HttpError>,
    }

    #[derive(Clone, Debug)]
    struct MockCall {
        agent_id: String,
        url: String,
        method: SharedHttpMethod,
        component_id: String,
        allowlist_patterns: Vec<String>,
    }

    impl MockChain {
        fn new() -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                fail_with: None,
            }
        }

        fn rejecting_with(err: HttpError) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                fail_with: Some(err),
            }
        }

        fn calls(&self) -> Vec<MockCall> {
            self.calls.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl HttpSecurityChain for MockChain {
        async fn execute(
            &self,
            agent_id: &str,
            req: HttpRequest,
            cap: &HttpCapability,
        ) -> Result<HttpResponse, HttpError> {
            self.calls.lock().unwrap().push(MockCall {
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
        // HttpError is not Clone; spell out the common variant we use in tests.
        match err {
            HttpError::AllowlistBlocked(s) => HttpError::AllowlistBlocked(s.clone()),
            _ => HttpError::AllowlistBlocked("unsupported test variant".to_string()),
        }
    }

    fn telegram_subscription(mgr: &SubscriptionManager) -> SubscriptionId {
        mgr.subscribe(
            "agent-007",
            ChannelConfig {
                adapter_type: AdapterType::Telegram,
                params: vec![],
                outbound: Some(OutboundConfig {
                    method: HttpMethod::Post,
                    url_template: "https://api.telegram.org/bot123/sendMessage".to_string(),
                    headers: vec![("Content-Type".into(), "application/json".into())],
                }),
            },
        )
        .unwrap()
    }

    #[tokio::test]
    async fn dispatch_invokes_chain_once_with_propagated_agent_id() {
        let mgr = Arc::new(SubscriptionManager::new());
        let id = telegram_subscription(&mgr);
        let chain = Arc::new(MockChain::new());
        let dispatcher = OutboundDispatcher::new(chain.clone(), mgr);

        dispatcher
            .dispatch("agent-007", &id, b"{\"text\":\"hi\"}")
            .await
            .unwrap();

        let calls = chain.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].agent_id, "agent-007");
        assert_eq!(calls[0].url, "https://api.telegram.org/bot123/sendMessage");
        assert_eq!(calls[0].method, SharedHttpMethod::Post);
    }

    #[tokio::test]
    async fn dispatch_sources_allowlist_from_preset_not_config() {
        let mgr = Arc::new(SubscriptionManager::new());
        let id = telegram_subscription(&mgr);
        let chain = Arc::new(MockChain::new());
        let dispatcher = OutboundDispatcher::new(chain.clone(), mgr);

        dispatcher.dispatch("agent-007", &id, b"x").await.unwrap();
        let calls = chain.calls();
        assert_eq!(
            calls[0].allowlist_patterns,
            vec!["https://api.telegram.org/".to_string()]
        );
    }

    #[tokio::test]
    async fn dispatch_pins_component_id_with_adapter_type() {
        let mgr = Arc::new(SubscriptionManager::new());
        let id = telegram_subscription(&mgr);
        let chain = Arc::new(MockChain::new());
        let dispatcher = OutboundDispatcher::new(chain.clone(), mgr);

        dispatcher.dispatch("agent-007", &id, b"x").await.unwrap();
        let calls = chain.calls();
        assert_eq!(calls[0].component_id, "cap-channel:telegram");
        assert!(!calls[0].component_id.is_empty());
    }

    #[tokio::test]
    async fn dispatch_lowers_allowlist_blocked_to_outbound_blocked() {
        let mgr = Arc::new(SubscriptionManager::new());
        let id = telegram_subscription(&mgr);
        let chain = Arc::new(MockChain::rejecting_with(HttpError::AllowlistBlocked(
            "https://evil.example/".to_string(),
        )));
        let dispatcher = OutboundDispatcher::new(chain, mgr);
        let err = dispatcher
            .dispatch("agent-007", &id, b"x")
            .await
            .unwrap_err();
        assert!(matches!(err, ChannelError::OutboundBlocked(_)));
        // And lowers to ConnectionFailed at the WIT boundary.
        assert!(matches!(err.into_wit(), ChannelError::ConnectionFailed(_)));
    }

    #[tokio::test]
    async fn dispatch_missing_subscription_returns_not_found() {
        let mgr = Arc::new(SubscriptionManager::new());
        let phantom = SubscriptionId::new();
        let chain = Arc::new(MockChain::new());
        let dispatcher = OutboundDispatcher::new(chain, mgr);
        let err = dispatcher.dispatch("a", &phantom, b"x").await.unwrap_err();
        assert!(matches!(err, ChannelError::NotFound(_)));
    }

    #[tokio::test]
    async fn dispatch_missing_outbound_config_returns_invalid_config() {
        let mgr = Arc::new(SubscriptionManager::new());
        let id = mgr
            .subscribe(
                "agent-1",
                ChannelConfig {
                    adapter_type: AdapterType::Webhook,
                    params: vec![],
                    outbound: None,
                },
            )
            .unwrap();
        let chain = Arc::new(MockChain::new());
        let dispatcher = OutboundDispatcher::new(chain.clone(), mgr);
        let err = dispatcher.dispatch("agent-1", &id, b"x").await.unwrap_err();
        assert!(matches!(err, ChannelError::InvalidConfig(_)));
        // Chain not invoked.
        assert_eq!(chain.calls().len(), 0);
    }

    #[test]
    fn http_method_enum_excludes_delete_head_options() {
        // The Slice B HttpMethod enum has only Get/Post/Put/Patch variants;
        // Delete/Head/Options are deliberately absent (type-system-level
        // enforcement of the method allowlist).
        // This test documents the invariant — if a future contributor adds
        // Delete to the enum, this test won't compile.
        fn exhaustive(m: HttpMethod) -> &'static str {
            match m {
                HttpMethod::Get => "get",
                HttpMethod::Post => "post",
                HttpMethod::Put => "put",
                HttpMethod::Patch => "patch",
            }
        }
        assert_eq!(exhaustive(HttpMethod::Get), "get");
    }

    #[tokio::test]
    async fn allowlist_for_webhook_adapter_is_empty() {
        // Defense-in-depth: webhook subscription with outbound config still
        // has empty allowlist (denies all outbound). HttpSecurityChain would
        // typically reject; we verify the empty patterns reach the chain.
        let mgr = Arc::new(SubscriptionManager::new());
        let id = mgr
            .subscribe(
                "agent-1",
                ChannelConfig {
                    adapter_type: AdapterType::Webhook,
                    params: vec![],
                    outbound: Some(OutboundConfig {
                        method: HttpMethod::Post,
                        url_template: "https://anything.example/".to_string(),
                        headers: vec![],
                    }),
                },
            )
            .unwrap();
        let chain = Arc::new(MockChain::new());
        let dispatcher = OutboundDispatcher::new(chain.clone(), mgr);
        dispatcher.dispatch("agent-1", &id, b"x").await.unwrap();
        let calls = chain.calls();
        assert!(calls[0].allowlist_patterns.is_empty());
    }

    #[tokio::test]
    async fn dispatch_for_other_adapter_uses_default_deny_allowlist() {
        // Even though `subscribe()` rejects Other(*), this exercises the
        // defense-in-depth path: if a subscription somehow ends up with an
        // Other(*) adapter type, the allowlist resolves via `preset_default_deny`
        // to empty patterns.
        let mgr = Arc::new(SubscriptionManager::new());
        let preset = AdapterCapabilitySet::preset_for(&AdapterType::Other("discord".into()));
        assert!(preset.outbound_allowlist.patterns.is_empty());
        // Smoke test the dispatcher's behaviour against a Telegram sub
        // owned by the calling agent (avoid panicking constructors).
        let id = telegram_subscription(&mgr);
        let chain = Arc::new(MockChain::new());
        let dispatcher = OutboundDispatcher::new(chain, mgr);
        dispatcher.dispatch("agent-007", &id, b"x").await.unwrap();
    }

    #[tokio::test]
    async fn dispatch_cross_agent_returns_permission_denied() {
        // Adversarial Eval R19 #2: agent B cannot drive send-raw against a
        // subscription owned by agent A.
        let mgr = Arc::new(SubscriptionManager::new());
        let id = telegram_subscription(&mgr); // owner = "agent-007"
        let chain = Arc::new(MockChain::new());
        let dispatcher = OutboundDispatcher::new(chain.clone(), mgr);
        let err = dispatcher
            .dispatch("agent-666", &id, b"x")
            .await
            .unwrap_err();
        assert!(matches!(err, ChannelError::PermissionDenied(_)));
        // Chain not invoked — rejection happens before chain dispatch.
        assert_eq!(chain.calls().len(), 0);
    }

    /// Lifecycle-harvest (MODULE-016-AC-12 guest-path coverage): a dispatcher
    /// built with `new_with_event_bus` emits a redacted `channel.raw_sent`
    /// after a successful send-raw chain pass.
    struct RecordingBus(Mutex<Vec<advance_shared_types::event::Event>>);
    impl advance_shared_types::traits::EventBusEmit for RecordingBus {
        fn emit(&self, event: advance_shared_types::event::Event) {
            self.0.lock().unwrap().push(event);
        }
    }

    #[tokio::test]
    async fn dispatch_with_event_bus_emits_redacted_raw_sent() {
        let mgr = Arc::new(SubscriptionManager::new());
        let id = telegram_subscription(&mgr);
        let chain = Arc::new(MockChain::new());
        let bus = Arc::new(RecordingBus(Mutex::new(Vec::new())));
        let dispatcher = OutboundDispatcher::new_with_event_bus(chain, mgr, bus.clone());

        let payload: &[u8] = b"{\"text\":\"secret-body\"}";
        dispatcher
            .dispatch("agent-007", &id, payload)
            .await
            .unwrap();

        let events = bus.0.lock().unwrap();
        assert_eq!(events.len(), 1, "exactly one event on success");
        let e = &events[0];
        assert_eq!(e.event_type, "channel.raw_sent");
        assert_eq!(e.payload["adapter"], "telegram");
        assert_eq!(e.payload["body_bytes"], payload.len());
        // Redaction: no body bytes, no target/url material in the event dump.
        let dump = serde_json::to_string(&e.payload).unwrap();
        assert!(!dump.contains("secret-body"));
        assert!(!dump.contains("api.telegram.org"));
    }

    #[tokio::test]
    async fn dispatch_without_event_bus_emits_nothing_and_failed_send_emits_nothing() {
        // Plain `new` keeps the bus-less egress (existing behaviour preserved).
        let mgr = Arc::new(SubscriptionManager::new());
        let id = telegram_subscription(&mgr);
        let chain = Arc::new(MockChain::new());
        let dispatcher = OutboundDispatcher::new(chain, mgr);
        dispatcher.dispatch("agent-007", &id, b"x").await.unwrap();
        // No panic = no emit path taken; nothing to observe (no bus exists).

        // Failed chain pass on a bus-wired dispatcher emits nothing.
        let mgr2 = Arc::new(SubscriptionManager::new());
        let id2 = telegram_subscription(&mgr2);
        let chain2 = Arc::new(MockChain::rejecting_with(HttpError::AllowlistBlocked(
            "blocked".to_string(),
        )));
        let bus2 = Arc::new(RecordingBus(Mutex::new(Vec::new())));
        let dispatcher2 = OutboundDispatcher::new_with_event_bus(chain2, mgr2, bus2.clone());
        let err = dispatcher2
            .dispatch("agent-007", &id2, b"x")
            .await
            .unwrap_err();
        assert!(matches!(err, ChannelError::OutboundBlocked(_)));
        assert_eq!(
            bus2.0.lock().unwrap().len(),
            0,
            "no emit on failed chain pass"
        );
    }
}

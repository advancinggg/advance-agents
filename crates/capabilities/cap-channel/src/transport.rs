//! L0 transport (wire) layer — Phase-2 Step-3 (ADR `2026-06-05` L0).
//!
//! The transport is the wire mechanism (webhook-push / connection-pull /
//! local-bridge). Step-3 ships only the **webhook** transport: a route on one
//! shared bound listener (no per-subscription task). A [`TransportSupervisor`]
//! owns the route ↔ `SubscriptionId` + `InboundVerifier` lifecycle and converts
//! an inbound HTTP request into a normalized [`RawEvent`] pushed through the
//! [`RawEventSink`] (which wraps `enqueue_event` — the single, frozen, HTTP-free
//! inbound sink). Pull clients (long-poll / ws / sse) are designed-for-deferred;
//! they would own a per-subscription task with cursor + heartbeat + reconnect.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use advance_shared_types::event::Event;
use advance_shared_types::traits::EventBusEmit;

use crate::error::ChannelError;
use crate::subscription::SubscriptionManager;
use crate::types::{AdapterType, RawEvent, SubscriptionId};
use crate::webhook::{build_raw_event_from_outcome, InboundVerifier, Reject, WebhookResponse};

/// The L0 inbound sink — wraps `SubscriptionManager::enqueue_event`, the single
/// transport-agnostic, HTTP-free inbound sink. A `RawEventSink` is what a
/// [`TransportClient`] hands inbound events to.
#[derive(Clone)]
pub struct RawEventSink {
    manager: Arc<SubscriptionManager>,
}

impl RawEventSink {
    pub fn new(manager: Arc<SubscriptionManager>) -> Self {
        Self { manager }
    }

    /// Deliver a normalized event into a subscription's buffer (honours
    /// `BufferOverflow` backpressure).
    pub fn deliver(&self, sub_id: &SubscriptionId, event: RawEvent) -> Result<(), ChannelError> {
        self.manager.enqueue_event(sub_id, event)
    }
}

/// Transport liveness (ADR L0 `healthy`). Webhook is push, so it is `Healthy`
/// once its route is registered and `Stopped` after `stop`; pull clients
/// override with cursor/heartbeat-derived state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportState {
    Healthy,
    Stopped,
}

/// L0 transport client seam (ADR). Webhook = a route on one shared listener (no
/// task); a future pull client owns a per-subscription task. `healthy`/`stop`
/// default to the push (no-task) behavior.
pub trait TransportClient: Send + Sync {
    /// Begin driving inbound for a subscription against `sink`. For webhook this
    /// registers the route on the supervisor's shared listener; for pull it
    /// spawns the per-subscription task.
    fn start(&self, sink: &RawEventSink) -> TransportState;
    fn healthy(&self) -> TransportState {
        TransportState::Healthy
    }
    fn stop(&self) {}
}

/// One registered webhook route: which subscription it feeds, the channel
/// verifier that normalizes its payload, and the adapter string stamped into
/// `channel.adapter`.
struct WebhookRoute {
    sub_id: SubscriptionId,
    adapter: String,
    verifier: Arc<dyn InboundVerifier>,
}

/// Owns the route ↔ `SubscriptionId` lifecycle for the shared webhook listener
/// (ADR L0 `TransportSupervisor`). The daemon's `/hooks/{path}` listener calls
/// [`Self::dispatch_inbound`]; bootstrap registers routes via
/// [`Self::register_webhook`]. Webhook routes need no task — the supervisor is
/// the single owner so the buffer is drained by exactly one consumer (the host
/// pump) per the L0 single-owner rule.
pub struct TransportSupervisor {
    routes: RwLock<HashMap<String, WebhookRoute>>,
    sink: RawEventSink,
    /// Phase-3 kickoff (2026-06-06): optional observability sink + the owning
    /// agent id. `None` (default) → no emit. The daemon opts in via
    /// [`Self::with_event_bus`] → emits `channel.raw_received` after a
    /// successful inbound enqueue (MODULE-016-AC-12).
    event_bus: Option<Arc<dyn EventBusEmit>>,
    owner_agent_id: String,
}

impl TransportSupervisor {
    pub fn new(manager: Arc<SubscriptionManager>) -> Self {
        Self {
            routes: RwLock::new(HashMap::new()),
            sink: RawEventSink::new(manager),
            event_bus: None,
            owner_agent_id: String::new(),
        }
    }

    /// Phase-3 kickoff opt-in builder — wire an observability sink + the owning
    /// agent id (the daemon's serving agent, from `build_channel_runtime`). A
    /// successful inbound dispatch then emits `channel.raw_received`. Additive;
    /// existing `new()` callers emit nothing.
    pub fn with_event_bus(
        mut self,
        bus: Arc<dyn EventBusEmit>,
        owner_agent_id: impl Into<String>,
    ) -> Self {
        self.event_bus = Some(bus);
        self.owner_agent_id = owner_agent_id.into();
        self
    }

    /// Register a `/hooks/{path}` route → `(sub_id, adapter, verifier)`.
    ///
    /// Audit r6 Warning: a DUPLICATE `path` is rejected (`InvalidConfig`) rather
    /// than silently overwriting the prior route — two channels configured with
    /// the same `route` would otherwise both boot while only the last is
    /// reachable. Fail the boot loudly instead.
    pub fn register_webhook(
        &self,
        path: impl Into<String>,
        sub_id: SubscriptionId,
        adapter: AdapterType,
        verifier: Arc<dyn InboundVerifier>,
    ) -> Result<(), ChannelError> {
        let path = path.into();
        let mut routes = self.routes.write().unwrap_or_else(|e| e.into_inner());
        if routes.contains_key(&path) {
            return Err(ChannelError::InvalidConfig(format!(
                "duplicate webhook route {path:?} — two channels cannot share a /hooks route"
            )));
        }
        routes.insert(
            path,
            WebhookRoute {
                sub_id,
                adapter: adapter.as_str().to_string(),
                verifier,
            },
        );
        Ok(())
    }

    /// Number of registered routes (test/diagnostic).
    pub fn route_count(&self) -> usize {
        self.routes.read().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// The core inbound path: resolve the `/hooks/{path}` route, run its
    /// channel verifier, build the normalized `RawEvent` (real `conversation_id`
    /// + `channel.reply_address.*`), and enqueue it through the sink. Returns the
    /// HTTP response the listener echoes back to the sender:
    /// - unknown path → 404; verifier `Unauthorized` → 401; `BadRequest` → 400;
    ///   buffer overflow → 503; success → 200.
    pub fn dispatch_inbound(
        &self,
        path: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> WebhookResponse {
        // Snapshot the route data under the read lock, then drop it before the
        // (potentially slower) verify + enqueue.
        let (sub_id, adapter, verifier) = {
            let routes = self.routes.read().unwrap_or_else(|e| e.into_inner());
            match routes.get(path) {
                Some(r) => (r.sub_id.clone(), r.adapter.clone(), r.verifier.clone()),
                None => return WebhookResponse::NOT_FOUND,
            }
        };
        match verifier.process(headers, body) {
            Ok(outcome) => {
                let event = build_raw_event_from_outcome(&adapter, body, &outcome, &sub_id);
                match self.sink.deliver(&sub_id, event) {
                    Ok(()) => {
                        // channel.raw_received (Phase-3 kickoff) — the inbound
                        // webhook was verified + enqueued. Payload carries ONLY
                        // adapter + sub_id + the inbound byte count: NEVER the raw
                        // body, conversation_id, or reply tokens.
                        if let Some(bus) = &self.event_bus {
                            bus.emit(Event::observability(
                                "channel.raw_received",
                                self.owner_agent_id.clone(),
                                serde_json::json!({
                                    "adapter": adapter,
                                    "sub_id": sub_id.as_str(),
                                    "body_bytes": body.len(),
                                }),
                                None,
                            ));
                        }
                        WebhookResponse::OK
                    }
                    // Buffer at cap → backpressure → 503 (the pull/push source
                    // must slow down; it never advances past unconsumed events).
                    Err(_) => WebhookResponse::SERVICE_UNAVAILABLE,
                }
            }
            Err(Reject::Unauthorized) => WebhookResponse::UNAUTHORIZED,
            Err(Reject::BadRequest) => WebhookResponse::BAD_REQUEST,
        }
    }
}

/// The webhook transport client (ADR L0). Webhook needs no task — `start`
/// reports `Healthy` once the supervisor route is registered. It is a thin
/// marker that satisfies the `TransportClient` seam so a future pull client is
/// an additive impl behind the same trait.
pub struct WebhookTransport;

impl TransportClient for WebhookTransport {
    fn start(&self, _sink: &RawEventSink) -> TransportState {
        // Webhook registers its route on the shared listener (no task to spawn);
        // route registration is done via `TransportSupervisor::register_webhook`.
        TransportState::Healthy
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ChannelConfig;
    use crate::webhook::{InboundOutcome, InboundVerifier};

    /// A stub verifier that always returns a fixed outcome (or a fixed reject).
    struct StubVerifier {
        outcome: Result<InboundOutcome, Reject>,
    }
    impl InboundVerifier for StubVerifier {
        fn process(&self, _h: &[(String, String)], _b: &[u8]) -> Result<InboundOutcome, Reject> {
            self.outcome.clone()
        }
    }

    fn host_pump_sub(mgr: &SubscriptionManager) -> SubscriptionId {
        mgr.subscribe_host_pump(
            "agent:default",
            ChannelConfig {
                adapter_type: AdapterType::Telegram,
                params: vec![],
                outbound: None,
            },
        )
        .unwrap()
    }

    #[test]
    fn dispatch_inbound_unknown_path_404() {
        let mgr = Arc::new(SubscriptionManager::new());
        let sup = TransportSupervisor::new(mgr);
        let resp = sup.dispatch_inbound("/hooks/nope", &[], b"{}");
        assert_eq!(resp.status, 404);
    }

    #[test]
    fn dispatch_inbound_ok_enqueues_event_drainable_by_host_pump() {
        let mgr = Arc::new(SubscriptionManager::new());
        let sub = host_pump_sub(&mgr);
        let sup = TransportSupervisor::new(mgr.clone());
        let verifier = Arc::new(StubVerifier {
            outcome: Ok(InboundOutcome {
                sender_id: "111".into(),
                conversation_id: "222".into(),
                reply_address: vec![("chat_id".into(), "222".into())],
                ack: None,
                extra: vec![],
                timestamp: Some(1700000000),
            }),
        });
        sup.register_webhook("/hooks/tg", sub.clone(), AdapterType::Telegram, verifier)
            .unwrap();
        assert_eq!(sup.route_count(), 1);
        let resp = sup.dispatch_inbound("/hooks/tg", &[], b"{}");
        assert_eq!(resp.status, 200);
        // The host pump drains the enqueued event; its metadata carries the real
        // conversation id + the reply_address family.
        let ev = mgr.poll_host_pump(&sub).unwrap().expect("event enqueued");
        let kv: std::collections::HashMap<_, _> = ev
            .metadata
            .iter()
            .map(|p| (p.key.clone(), p.value.clone()))
            .collect();
        assert_eq!(kv["channel.conversation_id"], "222");
        assert_eq!(kv["channel.reply_address.chat_id"], "222");
        assert_eq!(kv["channel.adapter"], "telegram");
        assert_eq!(kv["channel.timestamp"], "1700000000");
    }

    // ─── Phase-3 kickoff (2026-06-06) — MODULE-016-AC-12: channel.raw_received ──
    #[derive(Default)]
    struct RecBus(std::sync::Mutex<Vec<Event>>);
    impl EventBusEmit for RecBus {
        fn emit(&self, e: Event) {
            self.0.lock().unwrap().push(e);
        }
    }

    #[test]
    fn dispatch_inbound_ok_emits_channel_raw_received_redacted() {
        let mgr = Arc::new(SubscriptionManager::new());
        let sub = host_pump_sub(&mgr);
        let bus = Arc::new(RecBus::default());
        let sup = TransportSupervisor::new(mgr.clone()).with_event_bus(bus.clone(), "agent-owner");
        let verifier = Arc::new(StubVerifier {
            outcome: Ok(InboundOutcome {
                sender_id: "111".into(),
                conversation_id: "222".into(),
                reply_address: vec![("chat_id".into(), "222".into())],
                ack: None,
                extra: vec![],
                timestamp: Some(1700000000),
            }),
        });
        sup.register_webhook("/hooks/tg", sub, AdapterType::Telegram, verifier)
            .unwrap();
        let body = br#"{"update_id":1,"message":{"text":"hi"}}"#;
        let resp = sup.dispatch_inbound("/hooks/tg", &[], body);
        assert_eq!(resp.status, 200);

        let events = bus.0.lock().unwrap();
        let rec: Vec<_> = events
            .iter()
            .filter(|e| e.event_type == "channel.raw_received")
            .collect();
        assert_eq!(rec.len(), 1, "exactly one channel.raw_received");
        assert_eq!(rec[0].agent_id, "agent-owner");
        let p = &rec[0].payload;
        assert_eq!(p["adapter"], "telegram");
        assert_eq!(p["body_bytes"], body.len());
        assert!(p["sub_id"].as_str().is_some());
        // Redaction: no raw body / conversation_id in the payload.
        let dump = serde_json::to_string(&*events).unwrap();
        assert!(!dump.contains("222"), "conversation id leaked: {dump}");
        assert!(!dump.contains("update_id"), "raw body leaked: {dump}");
    }

    #[test]
    fn dispatch_inbound_unauthorized_401() {
        let mgr = Arc::new(SubscriptionManager::new());
        let sub = host_pump_sub(&mgr);
        let sup = TransportSupervisor::new(mgr);
        sup.register_webhook(
            "/hooks/tg",
            sub,
            AdapterType::Telegram,
            Arc::new(StubVerifier {
                outcome: Err(Reject::Unauthorized),
            }),
        )
        .unwrap();
        assert_eq!(sup.dispatch_inbound("/hooks/tg", &[], b"{}").status, 401);
    }

    #[test]
    fn register_webhook_rejects_duplicate_route() {
        let mgr = Arc::new(SubscriptionManager::new());
        let sub = host_pump_sub(&mgr);
        let sup = TransportSupervisor::new(mgr);
        let verifier = || {
            Arc::new(StubVerifier {
                outcome: Err(Reject::BadRequest),
            })
        };
        sup.register_webhook("/hooks/tg", sub.clone(), AdapterType::Telegram, verifier())
            .unwrap();
        // Audit r6: a second channel on the same route is rejected, not silently
        // overwritten.
        let err = sup
            .register_webhook("/hooks/tg", sub, AdapterType::Telegram, verifier())
            .unwrap_err();
        assert!(matches!(err, ChannelError::InvalidConfig(_)));
        assert_eq!(sup.route_count(), 1);
    }

    #[test]
    fn webhook_transport_start_is_healthy() {
        let mgr = Arc::new(SubscriptionManager::new());
        let sink = RawEventSink::new(mgr);
        assert_eq!(WebhookTransport.start(&sink), TransportState::Healthy);
        assert_eq!(WebhookTransport.healthy(), TransportState::Healthy);
        WebhookTransport.stop();
    }
}

//! /dev Phase-2 Step-3 — in-host channel reply egress (ADR L5/L6 keystone).
//!
//! [`DaemonOutboundSink`] is the daemon's composite [`OutboundActionSink`]. It
//! routes on the source message's origin:
//! - **channel-sourced** (`source.origin.is_some()` + channel wiring present) →
//!   build an [`OutboundTarget`] from `MessageOrigin.channel_metadata`
//!   (`channel.conversation_id` + the `channel.reply_address.*` family), look up
//!   the originating [`SubscriptionId`] (`channel.subscription_id`), and drive
//!   `OutboundTransport::send` **in-host** (NO `ChannelDelivery` / notify-channel
//!   round-trip).
//! - **POST /msg** (`source.origin.is_none()`) → fulfil the [`ReplyRegistry`]
//!   (the existing shim path), exactly as [`crate::reply::ReplyRouterSink`].
//!
//! Shim disposition: when channels are configured the daemon does NOT bind the
//! `POST /msg` shim listener (the `/hooks` listener replaces it — see
//! `commands::start`), so the channel path and the shim never share the serving
//! loop and the agent-id-keyed POST↔channel reply-slot mis-correlation cannot
//! occur. The shim is kept only when no channels are configured (local-dev
//! ingress); its full removal is an ADR 📌-open follow-up.

use std::sync::Arc;

use advance_messaging::{
    AgentAction, OutboundActionSink, ProgressRouteDelivery, RoutedOutboundActionSink,
};
use advance_shared_types::mailbox::{DispatchError, Message, MessageOrigin, MsgError};
use advance_shared_types::outbound::{
    DeliveryReport, OutboundEncoding, OutboundRoute, OutboundTarget, RoutedOutboundMessage,
};
use advance_shared_types::progress_card::{OutboundRouteRefKind, ProgressCardKey};

use cap_channel::{OutboundTransport, SubscriptionId, SubscriptionManager};

use crate::reply::ReplyRegistry;

/// The channel reply path: an `OutboundTransport` (the host-authoritative
/// `HttpEgress`) + the shared `SubscriptionManager` to resolve the originating
/// subscription per message.
pub struct ChannelEgress {
    transport: Arc<dyn OutboundTransport>,
    subscriptions: Arc<SubscriptionManager>,
}

impl ChannelEgress {
    pub fn new(
        transport: Arc<dyn OutboundTransport>,
        subscriptions: Arc<SubscriptionManager>,
    ) -> Self {
        Self {
            transport,
            subscriptions,
        }
    }

    /// Egress a channel reply: build the per-message `OutboundTarget` from the
    /// inbound origin's `channel_metadata` and drive `OutboundTransport::send`.
    async fn egress(
        &self,
        agent_id: &str,
        origin: &MessageOrigin,
        actions: &[AgentAction],
    ) -> Result<DeliveryReport, DispatchError> {
        // Audit r2 Warning: a no-action turn (empty validated batch — the
        // dispatcher invokes deliver even for an empty batch) must NOT egress a
        // spurious empty `text:""` reply to the channel. No reply → no outbound.
        if actions.is_empty() {
            return Ok(DeliveryReport::empty());
        }
        let meta = &origin.channel_metadata;
        let conversation_id = meta
            .get("channel.conversation_id")
            .cloned()
            .unwrap_or_default();
        // Collect the whole `channel.reply_address.*` family into the bag.
        let reply_address: Vec<(String, String)> = meta
            .iter()
            .filter_map(|(k, v)| {
                k.strip_prefix("channel.reply_address.")
                    .map(|tok| (tok.to_string(), v.clone()))
            })
            .collect();
        let target = OutboundTarget::ChatReply {
            conversation_id,
            reply_address,
        };

        // Resolve the originating subscription (the egress preset/host owner).
        let sub_id_str = meta.get("channel.subscription_id").ok_or_else(|| {
            DispatchError::TargetNotFound("channel.subscription_id missing in origin".into())
        })?;
        let sub_id = SubscriptionId::from_string(sub_id_str.clone());
        let sub = self.subscriptions.lookup(&sub_id).ok_or_else(|| {
            DispatchError::TargetNotFound(format!("subscription {} not found", sub_id.as_str()))
        })?;

        // Interim: the reply is the first validated action's raw payload bytes
        // (payload-kind discriminator is future work — MODULE-006 §3.6).
        let data = actions.first().map(|a| a.payload.as_slice()).unwrap_or(&[]);

        self.transport
            .send(agent_id, sub.as_ref(), target, data)
            .await
            .map_err(|e| {
                DispatchError::DeliveryFailed(MsgError::InvalidTarget(format!("egress: {e}")))
            })
    }
}

/// The daemon's composite outbound sink — routes channel-sourced replies to the
/// in-host egress and POST /msg replies to the reply registry.
pub struct DaemonOutboundSink {
    registry: Arc<ReplyRegistry>,
    channel: Option<ChannelEgress>,
}

impl DaemonOutboundSink {
    /// POST /msg only (no channels configured) — behaves exactly like
    /// `ReplyRouterSink` (origin is always `None` on the shim path).
    pub fn registry_only(registry: Arc<ReplyRegistry>) -> Self {
        Self {
            registry,
            channel: None,
        }
    }

    /// POST /msg + channel egress.
    pub fn with_channel(registry: Arc<ReplyRegistry>, channel: ChannelEgress) -> Self {
        Self {
            registry,
            channel: Some(channel),
        }
    }
}

#[async_trait::async_trait]
impl OutboundActionSink for DaemonOutboundSink {
    async fn deliver(
        &self,
        agent_id: &str,
        source: &Message,
        actions: &[AgentAction],
    ) -> Result<DeliveryReport, DispatchError> {
        // Channel-sourced inbound (origin present + channel egress wired) → in-host
        // egress through the security chain.
        if let (Some(origin), Some(ch)) = (&source.origin, &self.channel) {
            return ch.egress(agent_id, origin, actions).await;
        }
        // POST /msg path: fulfil the reply registry with the first action's raw
        // payload (or None for an empty batch → HTTP 202).
        let reply = actions.first().map(|a| a.payload.clone());
        self.registry.fulfill(agent_id, reply);
        Ok(DeliveryReport::empty())
    }
}

/// Fully staged CONTRACT-215 channel branch.  The route authority and renderer
/// remain separate factory products; this holder merely coordinates one
/// already-decoded message between them.
struct RoutedChannelEgress {
    legacy: ChannelEgress,
    typed: Arc<dyn OutboundTransport>,
    routes: Arc<ProgressRouteDelivery>,
}

impl RoutedChannelEgress {
    fn subscription_for(
        &self,
        message: &RoutedOutboundMessage,
    ) -> Result<Arc<cap_channel::Subscription>, DispatchError> {
        let OutboundRoute::Channel {
            subscription_id, ..
        } = &message.route
        else {
            return Err(DispatchError::TargetNotFound(
                "channel route required".into(),
            ));
        };
        let sub_id = SubscriptionId::from_string(subscription_id.clone());
        self.legacy.subscriptions.lookup(&sub_id).ok_or_else(|| {
            DispatchError::TargetNotFound(format!("subscription {} not found", sub_id.as_str()))
        })
    }

    async fn deliver_legacy(
        &self,
        agent_id: &str,
        message: &RoutedOutboundMessage,
    ) -> Result<DeliveryReport, DispatchError> {
        let sub = self.subscription_for(message)?;
        self.typed
            .send_typed(agent_id, sub.as_ref(), message, None)
            .await
            .map_err(channel_dispatch_error)
    }

    async fn deliver_progress(
        &self,
        agent_id: &str,
        message: &RoutedOutboundMessage,
    ) -> Result<DeliveryReport, DispatchError> {
        let sub = self.subscription_for(message)?;
        let key = progress_key(message)?;
        let lease = self
            .routes
            .prepare(&key, agent_id, OutboundRouteRefKind::Action)
            .map_err(progress_lifecycle_dispatch_error)?;
        let rendered = self
            .typed
            .send_typed(agent_id, sub.as_ref(), message, Some(lease.route_ref()))
            .await;
        let settled = self.routes.settle(lease);
        if let Err(error) = settled {
            return Err(progress_lifecycle_dispatch_error(error));
        }
        rendered.map_err(channel_dispatch_error)
    }
}

/// Routed sink staged before the joint C215/C216 publication barrier.  It has
/// no public activation method; only the dispatcher can publish it by consuming
/// the move-only joint authority.
pub struct StagedRoutedOutboundSink {
    registry: Arc<ReplyRegistry>,
    channel: Option<RoutedChannelEgress>,
}

impl StagedRoutedOutboundSink {
    pub fn registry_only(registry: Arc<ReplyRegistry>) -> Arc<Self> {
        Arc::new(Self {
            registry,
            channel: None,
        })
    }

    pub fn with_channel(
        registry: Arc<ReplyRegistry>,
        legacy: ChannelEgress,
        typed: Arc<dyn OutboundTransport>,
        routes: Arc<ProgressRouteDelivery>,
    ) -> Arc<Self> {
        Arc::new(Self {
            registry,
            channel: Some(RoutedChannelEgress {
                legacy,
                typed,
                routes,
            }),
        })
    }
}

#[async_trait::async_trait]
impl RoutedOutboundActionSink for StagedRoutedOutboundSink {
    async fn deliver_routed(
        &self,
        agent_id: &str,
        _source: &Message,
        messages: &[RoutedOutboundMessage],
    ) -> Result<DeliveryReport, DispatchError> {
        if messages.is_empty() {
            self.registry.fulfill(agent_id, None);
            return Ok(DeliveryReport::empty());
        }

        let has_progress = messages
            .iter()
            .any(|message| message.encoding == OutboundEncoding::ProgressV1);
        if !has_progress {
            // Preserve the legacy sink's established first-action semantics.
            let first = &messages[0];
            return match (&first.route, &self.channel) {
                (OutboundRoute::Channel { .. }, Some(channel)) => {
                    channel.deliver_legacy(agent_id, first).await
                }
                (OutboundRoute::Channel { .. }, None) => Err(DispatchError::TargetNotFound(
                    "channel egress unavailable".into(),
                )),
                (OutboundRoute::DirectReply, _) => {
                    self.registry.fulfill(agent_id, Some(first.body.clone()));
                    Ok(DeliveryReport::empty())
                }
            };
        }

        let channel = self.channel.as_ref().ok_or_else(|| {
            DispatchError::TargetNotFound("progress channel egress unavailable".into())
        })?;
        if messages
            .iter()
            .any(|message| !matches!(message.route, OutboundRoute::Channel { .. }))
        {
            return Err(DispatchError::TargetNotFound(
                "progress direct reply unsupported".into(),
            ));
        }

        let mut report = DeliveryReport::empty();
        for message in messages {
            let delivered = match message.encoding {
                OutboundEncoding::LegacyRaw => channel.deliver_legacy(agent_id, message).await?,
                OutboundEncoding::ProgressV1 => channel.deliver_progress(agent_id, message).await?,
            };
            report.outcomes.extend(delivered.outcomes);
        }
        Ok(report)
    }
}

fn progress_key(message: &RoutedOutboundMessage) -> Result<ProgressCardKey, DispatchError> {
    let OutboundRoute::Channel {
        adapter_id,
        subscription_id,
        conversation_id,
        ..
    } = &message.route
    else {
        return Err(DispatchError::TargetNotFound(
            "progress channel route required".into(),
        ));
    };
    Ok(ProgressCardKey {
        adapter_id: adapter_id.clone(),
        subscription_id: subscription_id.clone(),
        conversation_id: conversation_id.clone(),
        source_message_id: message.source_message_id.clone(),
    })
}

fn channel_dispatch_error(error: cap_channel::ChannelError) -> DispatchError {
    DispatchError::DeliveryFailed(MsgError::InvalidTarget(format!("egress: {error}")))
}

fn progress_lifecycle_dispatch_error(
    error: advance_messaging::ProgressSourceLifecycleError,
) -> DispatchError {
    DispatchError::DeliveryFailed(MsgError::InvalidTarget(format!("progress egress: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, HashMap};
    use std::sync::Mutex;

    use advance_shared_types::mailbox::MessageKind;
    use cap_channel::error::ChannelError;
    use cap_channel::{AdapterType, ChannelConfig, HttpMethod, OutboundConfig, Subscription};

    /// Recording transport double — captures (agent_id, conversation_id, data).
    struct RecordingTransport {
        calls: Mutex<Vec<(String, String, Vec<u8>)>>,
    }
    #[async_trait::async_trait]
    impl OutboundTransport for RecordingTransport {
        async fn send(
            &self,
            agent_id: &str,
            sub: &Subscription,
            target: OutboundTarget,
            data: &[u8],
        ) -> Result<DeliveryReport, ChannelError> {
            // Mirror the ownership check so the test exercises it.
            if sub.owner_agent_id != agent_id {
                return Err(ChannelError::PermissionDenied("not owner".into()));
            }
            let conv = target.conversation_id().unwrap_or("").to_string();
            self.calls
                .lock()
                .unwrap()
                .push((agent_id.to_string(), conv, data.to_vec()));
            Ok(DeliveryReport::delivered())
        }
    }

    fn channel_origin(sub_id: &str, conversation_id: &str) -> MessageOrigin {
        let mut meta = HashMap::new();
        meta.insert("channel.subscription_id".to_string(), sub_id.to_string());
        meta.insert(
            "channel.conversation_id".to_string(),
            conversation_id.to_string(),
        );
        meta.insert(
            "channel.reply_address.chat_id".to_string(),
            conversation_id.to_string(),
        );
        meta.insert("channel.adapter".to_string(), "telegram".to_string());
        MessageOrigin {
            message_id: "m".into(),
            original_channel: "telegram".into(),
            original_sender: "telegram:1".into(),
            adapter_id: "telegram".into(),
            channel_metadata: meta,
            received_at: advance_shared_types::chrono::Utc::now(),
            context: None,
        }
    }

    fn channel_message(origin: MessageOrigin) -> Message {
        Message {
            id: "m".into(),
            kind: MessageKind::User,
            from: "user:alice".into(),
            to: "agent:default".into(),
            payload: b"hi".to_vec(),
            context: None,
            timestamp: std::time::SystemTime::now(),
            origin: Some(origin),
        }
    }

    fn direct_routed(body: Vec<u8>) -> RoutedOutboundMessage {
        RoutedOutboundMessage {
            encoding: OutboundEncoding::LegacyRaw,
            body,
            metadata: BTreeMap::new(),
            source_message_id: "m".into(),
            route: OutboundRoute::DirectReply,
        }
    }

    #[tokio::test]
    async fn channel_origin_routes_to_egress_with_conversation_target() {
        let mgr = Arc::new(SubscriptionManager::new());
        let sub_id = mgr
            .subscribe_host_pump(
                "agent:default",
                ChannelConfig {
                    adapter_type: AdapterType::Telegram,
                    params: vec![],
                    outbound: Some(OutboundConfig {
                        method: HttpMethod::Post,
                        url_template: "https://api.telegram.org/bot1/sendMessage".into(),
                        headers: vec![],
                    }),
                },
            )
            .unwrap();
        let transport = Arc::new(RecordingTransport {
            calls: Mutex::new(vec![]),
        });
        let sink = DaemonOutboundSink::with_channel(
            Arc::new(ReplyRegistry::new()),
            ChannelEgress::new(transport.clone(), mgr.clone()),
        );
        let msg = channel_message(channel_origin(sub_id.as_str(), "98765"));
        sink.deliver(
            "agent:default",
            &msg,
            &[AgentAction {
                payload: b"the reply".to_vec(),
            }],
        )
        .await
        .unwrap();
        let calls = transport.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "agent:default");
        assert_eq!(
            calls[0].1, "98765",
            "conversation target from channel_metadata"
        );
        assert_eq!(calls[0].2, b"the reply");
    }

    #[tokio::test]
    async fn channel_no_action_turn_does_not_egress() {
        // Audit r2: a channel-sourced turn with an EMPTY action batch must not
        // egress a spurious empty reply.
        let mgr = Arc::new(SubscriptionManager::new());
        let sub_id = mgr
            .subscribe_host_pump(
                "agent:default",
                ChannelConfig {
                    adapter_type: AdapterType::Telegram,
                    params: vec![],
                    outbound: Some(OutboundConfig {
                        method: HttpMethod::Post,
                        url_template: "https://api.telegram.org/bot1/sendMessage".into(),
                        headers: vec![],
                    }),
                },
            )
            .unwrap();
        let transport = Arc::new(RecordingTransport {
            calls: Mutex::new(vec![]),
        });
        let sink = DaemonOutboundSink::with_channel(
            Arc::new(ReplyRegistry::new()),
            ChannelEgress::new(transport.clone(), mgr.clone()),
        );
        let msg = channel_message(channel_origin(sub_id.as_str(), "98765"));
        sink.deliver("agent:default", &msg, &[]).await.unwrap();
        assert_eq!(
            transport.calls.lock().unwrap().len(),
            0,
            "no action → no outbound egress"
        );
    }

    #[tokio::test]
    async fn post_msg_origin_none_fulfills_registry_not_egress() {
        let mgr = Arc::new(SubscriptionManager::new());
        let transport = Arc::new(RecordingTransport {
            calls: Mutex::new(vec![]),
        });
        let registry = Arc::new(ReplyRegistry::new());
        let rx = registry.register("agent:default");
        let sink = DaemonOutboundSink::with_channel(
            registry.clone(),
            ChannelEgress::new(transport.clone(), mgr),
        );
        // origin: None → POST /msg path.
        let msg = Message {
            id: "m".into(),
            kind: MessageKind::User,
            from: "user:http".into(),
            to: "agent:default".into(),
            payload: vec![],
            context: None,
            timestamp: std::time::SystemTime::now(),
            origin: None,
        };
        sink.deliver(
            "agent:default",
            &msg,
            &[AgentAction {
                payload: b"registry reply".to_vec(),
            }],
        )
        .await
        .unwrap();
        assert_eq!(rx.await.unwrap(), Some(b"registry reply".to_vec()));
        assert_eq!(
            transport.calls.lock().unwrap().len(),
            0,
            "egress NOT used for POST /msg"
        );
    }

    #[tokio::test]
    async fn staged_routed_legacy_reply_is_byte_identical_and_first_only() {
        let registry = Arc::new(ReplyRegistry::new());
        let rx = registry.register("agent:default");
        let sink = StagedRoutedOutboundSink::registry_only(registry);
        let source = Message {
            id: "m".into(),
            kind: MessageKind::User,
            from: "user:http".into(),
            to: "agent:default".into(),
            payload: vec![],
            context: None,
            timestamp: std::time::SystemTime::now(),
            origin: None,
        };
        let exact = vec![0, 0xff, b'\r', b'\n', 0x80, b'x'];
        sink.deliver_routed(
            "agent:default",
            &source,
            &[
                direct_routed(exact.clone()),
                direct_routed(b"ignored".to_vec()),
            ],
        )
        .await
        .unwrap();
        assert_eq!(rx.await.unwrap(), Some(exact));
    }

    #[tokio::test]
    async fn staged_routed_empty_batch_fulfils_no_reply() {
        let registry = Arc::new(ReplyRegistry::new());
        let rx = registry.register("agent:default");
        let sink = StagedRoutedOutboundSink::registry_only(registry);
        let source = Message {
            id: "m".into(),
            kind: MessageKind::User,
            from: "user:http".into(),
            to: "agent:default".into(),
            payload: vec![],
            context: None,
            timestamp: std::time::SystemTime::now(),
            origin: None,
        };
        sink.deliver_routed("agent:default", &source, &[])
            .await
            .unwrap();
        assert_eq!(rx.await.unwrap(), None);
    }
}

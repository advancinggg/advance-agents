//! Phase-2 Step-3 outbound egress contract shapes
//! (ADR `2026-06-05-extensible-channel-adapter-abstraction`).
//!
//! These types are the **settled-now** seam between MODULE-006's post-validation
//! `OutboundActionSink` / `AgentActionDispatcher::dispatch` and MODULE-016's
//! `OutboundTransport` egress. They live in `shared-types` (the dependency-
//! inversion home both `advance-messaging` and `cap-channel` already depend on)
//! so naming them in the dispatch seam introduces no MODULE-006 ↔ MODULE-016
//! cycle and preserves cap-channel's AC-08 zero-edge to messaging.
//!
//! Only `OutboundTarget::ChatReply` + `TargetOutcome::Delivered` ship in Step-3
//! (via `HttpEgress`); the other variants are a deliberate, minimal "design-
//! ahead" shape so a second non-HTTP channel does not re-type the seam.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// CONTRACT-215 host-decoded outbound payload classification.
///
/// `LegacyRaw` means the action payload was outside the reserved `ADVPRG\0`
/// framing family and therefore remains byte-identical. `ProgressV1` means the
/// complete framing and metadata validation succeeded.  Consumers must never
/// infer this value from guest-supplied metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum OutboundEncoding {
    LegacyRaw,
    ProgressV1,
}

/// Host-trusted route stamped from the source [`crate::mailbox::Message`].
///
/// The channel variant is intentionally separate from [`OutboundTarget`]: it
/// preserves the subscription and adapter identity needed by CONTRACT-215's
/// one-card correlation, while `OutboundTarget` remains the transport-facing
/// legacy seam. No field is populated from the ADVPRG envelope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum OutboundRoute {
    Channel {
        adapter_id: String,
        subscription_id: String,
        conversation_id: String,
        reply_address: Vec<(String, String)>,
    },
    DirectReply,
}

/// Strictly decoded outbound action plus host-stamped correlation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutedOutboundMessage {
    pub encoding: OutboundEncoding,
    pub body: Vec<u8>,
    pub metadata: BTreeMap<String, String>,
    pub source_message_id: String,
    pub route: OutboundRoute,
}

/// Per-message outbound routing, built from `MessageOrigin.channel_metadata`
/// (NOT a static subscribe-time URL template). `reply_address` is a key/value
/// bag (the `channel.reply_address.*` family) — the structural equivalent of
/// the ADR's `Vec<CapParam>`, kept as `Vec<(String, String)>` here so the type
/// stays in `shared-types` without coupling to any one crate's `CapParam` clone.
/// Multi-token reply addresses (e.g. WeChat `openid` + `app_context`) are
/// genuinely additive (add a tuple), not a re-typing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum OutboundTarget {
    /// A reply addressed to a conversation/thread (implemented via `HttpEgress`
    /// now — Telegram `chat_id`, Discord `channel_id`, …).
    ChatReply {
        conversation_id: String,
        reply_address: Vec<(String, String)>,
    },
    /// A native-client reply (defined; `LocalProcessEgress` later —
    /// iMessage / Signal-local).
    Native {
        reply_address: Vec<(String, String)>,
        kind: String,
    },
    /// A push fan-out (defined; `PushNotify` later — APNs / FCM, with the live
    /// `Pruned`/`Retry` receipt semantics).
    PushTokens {
        provider: String,
        tokens: Vec<String>,
        topic: Option<String>,
    },
}

impl OutboundTarget {
    /// Accessor helpers used by egress renderers + tests.
    pub fn conversation_id(&self) -> Option<&str> {
        match self {
            Self::ChatReply {
                conversation_id, ..
            } => Some(conversation_id.as_str()),
            _ => None,
        }
    }

    pub fn reply_address(&self) -> &[(String, String)] {
        match self {
            Self::ChatReply { reply_address, .. } | Self::Native { reply_address, .. } => {
                reply_address
            }
            Self::PushTokens { .. } => &[],
        }
    }
}

/// The structured receipt a single outbound delivery returns. `HttpEgress`
/// returns a single `Delivered`; `Pruned`/`Retry` are push-era (APNs 410 prune,
/// transient-retry) and defined-but-unused in Step-3.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TargetOutcome {
    Delivered,
    Pruned { token: String },
    Retry,
}

/// The structured report propagated up through the `OutboundActionSink` /
/// `AgentActionDispatcher::dispatch` seam. An empty report is the gate-only /
/// no-sink case (a turn that produced no outbound delivery).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct DeliveryReport {
    pub outcomes: Vec<TargetOutcome>,
}

impl DeliveryReport {
    /// The gate-only / no-outbound-wired report (no delivery happened).
    pub fn empty() -> Self {
        Self {
            outcomes: Vec::new(),
        }
    }

    /// A single successful delivery (the `HttpEgress` happy path).
    pub fn delivered() -> Self {
        Self {
            outcomes: vec![TargetOutcome::Delivered],
        }
    }

    pub fn is_empty(&self) -> bool {
        self.outcomes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chat_reply_accessors() {
        let t = OutboundTarget::ChatReply {
            conversation_id: "12345".into(),
            reply_address: vec![("chat_id".into(), "12345".into())],
        };
        assert_eq!(t.conversation_id(), Some("12345"));
        assert_eq!(t.reply_address().len(), 1);
    }

    #[test]
    fn delivery_report_helpers() {
        assert!(DeliveryReport::empty().is_empty());
        assert_eq!(
            DeliveryReport::delivered().outcomes,
            vec![TargetOutcome::Delivered]
        );
    }

    #[test]
    fn outbound_target_serde_round_trips_all_variants() {
        for t in [
            OutboundTarget::ChatReply {
                conversation_id: "c".into(),
                reply_address: vec![("k".into(), "v".into())],
            },
            OutboundTarget::Native {
                reply_address: vec![],
                kind: "imessage".into(),
            },
            OutboundTarget::PushTokens {
                provider: "apns".into(),
                tokens: vec!["tok".into()],
                topic: Some("t".into()),
            },
        ] {
            let s = serde_json::to_string(&t).unwrap();
            let back: OutboundTarget = serde_json::from_str(&s).unwrap();
            assert_eq!(t, back);
        }
    }
}

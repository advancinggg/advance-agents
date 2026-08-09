//! `cap-channel` — host-side implementation of CONTRACT-150 (`channel-host` WIT)
//! for MODULE-016 channel-system.
//!
//! Slice m016-B (this slice) lands the WIT impl, `SubscriptionManager`, webhook
//! handler (pure logic; no TCP bind), per-adapter sandbox declarations,
//! outbound HTTPS dispatcher via CONTRACT-111, structured progress helper, and
//! the `notify-error` policy table (AC-10).
//!
//! See `docs/modules/MODULE-016-channel-system.md` §1.4.2 + §2.5 + §2.7 + §3.2
//! for the spec.

#![forbid(unsafe_code)]

pub mod egress;
pub mod error;
pub mod notify_policy;
pub mod outbound;
pub mod progress;
mod progress_card;
pub mod sandbox;
pub mod subscription;
pub mod transport;
pub mod types;
pub mod webhook;
pub mod wit_impl;

pub use egress::{stage_typed_outbound_transport, HttpEgress, OutboundTransport};
pub use error::ChannelError;
pub use notify_policy::{recommend_action, AdapterAction, AdapterPolicy, NotifyError};
pub use outbound::OutboundDispatcher;
pub use progress::{
    build_progress_metadata, is_progress_key, parse_progress, validate_metadata_boundary,
    ProgressBoundaryError, ProgressPhase, PROGRESS_PHASE, PROGRESS_PREFIX, PROGRESS_SUMMARY,
    PROGRESS_VALUE,
};
pub use progress_card::{
    stage_progress_card_provider, ProgressAttemptOutcomeAttester, ProgressCardProviderParts,
    ProgressCardRenderer,
};
pub use sandbox::{preset_default_deny, AdapterCapabilitySet, EgressKind};
pub use subscription::{
    Consumer, SecretBytes, Subscription, SubscriptionManager, DEFAULT_BUFFER_CAP,
    MAX_SUBSCRIPTIONS, MIN_WEBHOOK_SECRET_BYTES,
};
pub use transport::{
    RawEventSink, TransportClient, TransportState, TransportSupervisor, WebhookTransport,
};
pub use types::{
    AdapterType, CapParam, ChannelConfig, HttpMethod, OutboundConfig, RawEvent, SubscriptionId,
};
pub use webhook::{
    build_raw_event_from_outcome, InboundOutcome, InboundVerifier, Reject, TelegramVerifier,
    WebhookReceiver, WebhookResponse, DEFAULT_MAX_BODY_BYTES, MAX_WEBHOOK_PATH_BYTES,
};
pub use wit_impl::{
    register_channel_host, ChannelHostBundle, CHANNEL_HOST_CAPABILITY, CHANNEL_HOST_METHODS,
    CHANNEL_HOST_NAMESPACE,
};

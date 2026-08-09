//! Cap-channel egress `NotifySink` (cli composition root) — the SYS-AC-257
//! product seam.
//!
//! [`CapChannelNotifySink`] binds the MODULE-015 auto-loop degrade/halt
//! [`NotifySink`] (driven by `DefaultAutoLoopDriver::run_cadence_pass`) to the
//! cap-channel OUTBOUND egress: `notify(agent_id, message)` routes the
//! human-facing degrade/halt notification through `OutboundTransport::send`
//! ([`cap_channel::HttpEgress`]), so the criterion event **`channel.raw_sent`**
//! fires on a successful `HttpSecurityChain` pass. This is the cap-channel
//! egress path mandated by ADR `2026-06-05-extensible-channel-adapter-abstraction`
//! (in-host egress calls `OutboundTransport::send` directly) — NOT the mailbox
//! `notify_channel` (which emits `msg.received`, a different event; see MODULE-015
//! §3.8 note 10 + event_sink.rs:176-183).
//!
//! Installation: the sink is wired into the driver via the EXISTING
//! `DefaultAutoLoopDriver::with_notify_sink` builder (replacing the best-effort
//! `EventBusNotifySink`). The harvest installs it on the production
//! `build_auto_loop_driver` driver via the established augment pattern
//! (`Arc::try_unwrap(build_auto_loop_driver(..)).with_notify_sink(CapChannelNotifySink::new(..))`,
//! exactly as cost-tracker / results-writer / skill-rollback are augmented in the
//! system-acceptance harness). `build_auto_loop_driver` keeps its
//! `EventBusNotifySink` default until a notify-channel config (transport + a
//! standalone outbound notify [`Subscription`] + an [`OutboundTarget`]) is sourced
//! on the wired daemon — that config-sourcing + the real `HttpSecurityChain` pass
//! + the SYS-AC-257 e2e witness are harvest hand-offs (MODULE-016 §3.7).

use std::sync::Arc;

use async_trait::async_trait;

use advance_runtime::config::NotifyChannelConfig;
use advance_scheduler_auto_loop::{sanitize_for_audit, NotifySink, NotifySinkError};
use advance_shared_types::outbound::OutboundTarget;
use cap_channel::{
    AdapterType, ChannelConfig, Consumer, HttpMethod, OutboundConfig, OutboundTransport,
    Subscription, SubscriptionId,
};

/// Defense-in-depth bounds on the notify body components (applied BEFORE the
/// `format!`/`sanitize_for_audit` allocation, ahead of cap-channel's 64 KiB egress
/// cap which rejects only at `send` time). `agent_id` is already validated upstream
/// (MODULE-005 charset) and `message` is loop-constructed from fixed reason strings,
/// so these caps are a transient-allocation backstop, not a functional limit.
const MAX_NOTIFY_AGENT_BYTES: usize = 256;
const MAX_NOTIFY_MESSAGE_BYTES: usize = 8 * 1024;

/// Truncate `s` to at most `max_bytes`, snapping down to the nearest UTF-8 char
/// boundary so a multi-byte split never panics.
fn truncate_at_char_boundary(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// A `NotifySink` that delivers a degrade/halt notification through cap-channel
/// OUTBOUND egress (→ `channel.raw_sent`).
///
/// Holds a standalone OUTBOUND notify [`Subscription`] (owner-agent-bound — a
/// degrade notification has no inbound to reply to) + the configured
/// [`OutboundTarget`] (the operator notify destination). The `send` ownership
/// check requires `owner_agent_id == subscription.owner_agent_id`; the sink drives
/// egress on behalf of that owner agent (the daemon's serving agent), while the
/// affected auto-loop `agent_id` is conveyed in the message body.
pub struct CapChannelNotifySink {
    transport: Arc<dyn OutboundTransport>,
    owner_agent_id: String,
    subscription: Subscription,
    target: OutboundTarget,
}

impl CapChannelNotifySink {
    /// Construct a notify sink over `transport` (an event-bus-wired `HttpEgress`)
    /// using a standalone outbound notify `subscription` (must be owned by
    /// `owner_agent_id`) and the configured `target`.
    pub fn new(
        transport: Arc<dyn OutboundTransport>,
        owner_agent_id: impl Into<String>,
        subscription: Subscription,
        target: OutboundTarget,
    ) -> Self {
        Self {
            transport,
            owner_agent_id: owner_agent_id.into(),
            subscription,
            target,
        }
    }
}

#[async_trait]
impl NotifySink for CapChannelNotifySink {
    async fn notify(&self, agent_id: &str, message: &str) -> Result<(), NotifySinkError> {
        // Prefix the affected agent so a single operator notify-channel can
        // disambiguate which auto session degraded/halted. `agent_id` is sanitized
        // (control / bidi-override stripping) before it enters the wire body —
        // same posture as `EventBusNotifySink` (auto_wiring.rs). The `message`
        // text is loop-constructed (driver degrade/halt reason), not user input.
        // Adversarial fix: bound both components BEFORE the format allocation
        // (defense-in-depth ahead of the egress 64 KiB cap — a transient-alloc
        // backstop against an oversized agent_id/message).
        let agent = sanitize_for_audit(truncate_at_char_boundary(agent_id, MAX_NOTIFY_AGENT_BYTES));
        let body = format!(
            "[{agent}] {}",
            truncate_at_char_boundary(message, MAX_NOTIFY_MESSAGE_BYTES)
        );
        self.transport
            .send(
                &self.owner_agent_id,
                &self.subscription,
                self.target.clone(),
                body.as_bytes(),
            )
            .await
            .map(|_report| ())
            // Best-effort: the driver's `run_cadence_pass` ignores the Err (degrade
            // notification is observability, not a correctness gate). Map to the
            // NotifySink error so a transport/chain failure surfaces, not a panic.
            .map_err(|e| NotifySinkError::NotifyFailed(format!("cap-channel egress: {e}")))
    }
}

/// Wave-6 Lane C (2026-06-21) — build a [`CapChannelNotifySink`] from a
/// `channels.notify` config block ([`NotifyChannelConfig`]) over the wired channel
/// `transport` (the daemon's `ChannelRuntime.transport` — the event-bus-wired
/// `HttpEgress`). Sources a standalone OUTBOUND notify [`Subscription`]
/// (`Consumer::HostPump`, owner-bound, carrying the config's outbound preset) + the
/// [`OutboundTarget::ChatReply`] (operator `conversation_id` + the `reply_address`
/// bag). Telegram is the only send-capable adapter in Step-3 — any other adapter is
/// rejected loudly (mirrors `channels_boot`). `owner_agent_id` is the daemon's serving
/// messaging id (the egress ownership check matches it against the subscription owner).
///
/// This is the 257 config-sourcing seam: the cli daemon-boot path passes the parsed
/// `config.channels.notify` here, then installs the result on the auto driver via
/// [`crate::auto_wiring::build_auto_loop_driver_with_channel_notify`] /
/// [`crate::auto_wiring::install_notify_sink`].
pub fn build_channel_notify_sink(
    transport: Arc<dyn OutboundTransport>,
    owner_agent_id: &str,
    notify: &NotifyChannelConfig,
) -> Result<CapChannelNotifySink, String> {
    // `AdapterType::from_str` is infallible (unknown → `Other`); reject non-Telegram
    // BEFORE building the subscription so an unsupported outbound channel fails loudly
    // at boot rather than at the first degrade notify.
    let adapter: AdapterType = notify
        .adapter
        .parse()
        .expect("AdapterType::from_str infallible");
    if adapter != AdapterType::Telegram {
        return Err(format!(
            "channels.notify: adapter {} is not a supported outbound notify channel in Step-3 \
             (only telegram)",
            adapter.as_str()
        ));
    }
    // A blank/NUL `url-template` has no usable egress target (mirrors channels_boot).
    if notify.url_template.trim().is_empty() || notify.url_template.contains('\0') {
        return Err(
            "channels.notify: `url-template` is empty or contains NUL (no usable outbound egress \
             target)"
                .to_string(),
        );
    }
    // A blank/NUL `conversation_id` would hit the Telegram renderer's raw-passthrough
    // fallback and still egress (→ `channel.raw_sent`) to an UNDETERMINED target — a
    // misdelivered degrade/halt notify that masquerades as a passing SYS-AC-257 witness.
    // Reject loudly at boot (mirrors the `url-template` guard above; Wave-7 Lane B).
    if notify.conversation_id.trim().is_empty() || notify.conversation_id.contains('\0') {
        return Err(
            "channels.notify: `conversation_id` is empty/whitespace or contains NUL (the outbound \
             notify target would be undetermined)"
                .to_string(),
        );
    }
    let outbound = OutboundConfig {
        method: HttpMethod::Post,
        url_template: notify.url_template.clone(),
        headers: vec![("Content-Type".into(), "application/json".into())],
    };
    let sub_config = ChannelConfig {
        adapter_type: adapter,
        params: vec![],
        outbound: Some(outbound),
    };
    // Standalone OUTBOUND notify subscription — owner-bound HostPump (no guest); a
    // degrade notification has no inbound to reply to. Distinct from the per-inbound
    // reply subscription resolved in `channel_egress`.
    let subscription = Subscription::new_with_consumer(
        SubscriptionId::new(),
        owner_agent_id,
        sub_config,
        Consumer::HostPump,
    );
    let reply_address: Vec<(String, String)> = notify
        .reply_address
        .iter()
        .map(|p| (p.key.clone(), p.value.clone()))
        .collect();
    let target = OutboundTarget::ChatReply {
        conversation_id: notify.conversation_id.clone(),
        reply_address,
    };
    Ok(CapChannelNotifySink::new(
        transport,
        owner_agent_id,
        subscription,
        target,
    ))
}

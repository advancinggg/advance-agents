//! `MailboxDispatcher` trait + concrete impl.
//!
//! Slice B extends the trait to the **MODULE-006 §2.3:296-302 canonical
//! 3-method shape**: `deliver` (slice A) + `reply` + `notify_agent`.
//! `notify_channel` is an **inherent** method on `MailboxDispatcherImpl`
//! (deliberately NOT a trait method) so the CONTRACT-051 trait surface stays
//! byte-aligned with §2.3 — no silent contract expansion.
//!
//! See MODULE-006 §3.8 for the reply trust model, the NotifyError 4-variant
//! mapping rationale, and the reply-vs-notify_channel origin handling split.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use advance_runtime::circuit_breaker::CircuitBreakerBus;
use advance_shared_types::agent_tree::AgentTreeReader;
use advance_shared_types::await_session::SessionId;
use advance_shared_types::event::Event;
use advance_shared_types::mailbox::{
    ChannelDelivery, Message, MessageContext, MessageKind, MsgError, NotifyError,
};
use advance_shared_types::traits::EventBusEmit;

use crate::channel_registry::{ChannelAdapterRegistry, EmptyChannelAdapterRegistry};
use crate::hierarchy::validate_routing;
use crate::id_bridge::AgentIdBridge;
use crate::id_validation::{is_safe_id, MAX_ID_BYTES};
use crate::mailbox::{
    validate_message_context, MailboxStore, PreparedTurnBatch, TurnMailboxDelivery,
    MAX_PAYLOAD_BYTES,
};

/// Slice-D AC-09: event_type literal for the successful-delivery event
/// emitted by all three target-reaching dispatcher entry points
/// (`deliver`/`reply`/`deliver_notify`) after successful `mb.deliver(...)`.
///
/// **Cross-module note**: MODULE-019's EventBus
/// (`crates/event-bus/src/lib.rs::EmitPipeline::emit_breach_mirror`,
/// shipped by m019-slice-e / M019-AC-10) synthesizes the `mailbox.delivery_slow`
/// breach mirror downstream from this event's `delivery_latency_ms` payload
/// field when it exceeds `eventbus.mailbox_delivery_slow_threshold_ms`
/// (default 1000ms). MODULE-006 deliberately does NOT emit
/// `mailbox.delivery_slow` itself — double-publishing would be incorrect.
/// See MODULE-006 §3.8 (h) for the ownership-split rationale.
pub const EVENT_MSG_RECEIVED: &str = "msg.received";

/// Reserved headroom (bytes) for the `ChannelDelivery` JSON skeleton plus
/// the `channel_id` + `user_id` string fields when computing the
/// notify-channel raw-payload pre-cap. The skeleton
/// (`{"channel_id":"","user_id":"","body":[]}`) is ~40 bytes; `channel_id`
/// and `user_id` are each bounded at `MAX_ID_BYTES` (256) and serde_json
/// may escape string bytes (≤ 2×). 4096 is a generous over-estimate of the
/// true worst case (~40 + 2×256 + 2×256 ≈ 1064).
const NOTIFY_CHANNEL_ENVELOPE_OVERHEAD: usize = 4096;

/// notify-channel raw-`payload` FAST-PATH pre-cap. `serde_json` encodes
/// `Vec<u8>` as a JSON decimal-number array — worst case `[255,255,…]` is
/// `4N + 1` chars for `N` bytes. With `channel_id`/`user_id` bounded at
/// `MAX_ID_BYTES` and `NOTIFY_CHANNEL_ENVELOPE_OVERHEAD` reserved for the
/// skeleton + (possibly-escaped) id strings, a raw payload ≤ this bound is
/// *guaranteed* to encode to ≤ `MAX_PAYLOAD_BYTES`. This pre-cap is a
/// fast-path that rejects gross over-size before the encode (no ~4×
/// transient-allocation amplification); a **post-encode exact
/// `envelope.len() > MAX_PAYLOAD_BYTES` check** in `notify_channel` is the
/// hard correctness guarantee and the clear `payload_too_large` error
/// source (Adversarial r2 fix — the bare `MAX_PAYLOAD_BYTES/4` of r1 was
/// off-by-one: it omitted the skeleton + id-string overhead).
pub const MAX_NOTIFY_CHANNEL_PAYLOAD_BYTES: usize =
    (MAX_PAYLOAD_BYTES - NOTIFY_CHANNEL_ENVELOPE_OVERHEAD) / 4;
use crate::trace::MessageTrace;

/// MODULE-006 §2.3:296-302 canonical 3-method dispatcher contract
/// (CONTRACT-051). `deliver` is the slice-A method; `reply` + `notify_agent`
/// are added in slice B. `notify_channel` is intentionally NOT on this trait
/// (inherent on the impl) so the trait == §2.3 canonical.
#[async_trait]
pub trait MailboxDispatcher: Send + Sync {
    /// Hierarchy-validated agent→agent delivery (slice A).
    async fn deliver(&self, target: &str, msg: Message) -> Result<(), MsgError>;

    /// Reply to a previously-recorded inbound message. Routes back to the
    /// originating channel adapter (`origin.adapter_id`), inherits the
    /// original message context, and is authorized by `from == recipient`
    /// (only the agent the inbound was delivered to may reply). See
    /// MODULE-006 §3.8 (b)/(d) for the trust + no-adjacency rationale.
    async fn reply(
        &self,
        from: &str,
        to_message_id: &str,
        payload: Vec<u8>,
    ) -> Result<(), MsgError>;

    /// Hierarchy-bypassing agent/system→agent notification (notify ≠ send;
    /// only `send`/`deliver` enforce hierarchy). Errors map onto the §2.3
    /// canonical 4-variant [`NotifyError`] (see MODULE-006 §3.8 (c)).
    async fn notify_agent(
        &self,
        from: &str,
        target: &str,
        payload: Vec<u8>,
        context: Option<MessageContext>,
    ) -> Result<(), NotifyError>;
}

/// Additive C216 producer surface. Preparation performs all reservation,
/// invisible staging, confirmation, and hierarchy/breaker validation while
/// retaining every registered handle in the returned batch. Publication is a
/// separate synchronous linearization step so the session owner can store the
/// batch before any protected entry is dequeue-visible.
pub trait TurnMailboxDispatchPort: Send + Sync {
    fn prepare_turn_batch(&self, deliveries: Vec<TurnMailboxDelivery>) -> PreparedTurnBatch;
    fn publish_prepared(&self, batch: &mut PreparedTurnBatch) -> Result<(), MsgError>;
    fn detach_turn_batch(
        &self,
        session_id: &SessionId,
        batch: &mut PreparedTurnBatch,
    ) -> Result<(), MsgError>;
}

/// Narrow injected port for the `notify-channel` host-fn handler
/// (Wave-18 Lane-3, MODULE-006-AC-02 infra).
///
/// `notify_channel` is an **inherent** method on [`MailboxDispatcherImpl`]
/// (deliberately kept OFF the [`MailboxDispatcher`] trait so CONTRACT-051 stays
/// the §2.3 canonical 3-method surface), but
/// [`crate::host_fn::NotifyChannelHandler`] needs a `dyn`-able surface to invoke
/// it. `ChannelNotifier` is that **additive** surface — it is NOT part of
/// CONTRACT-051 and adding it does not widen the dispatcher contract. Its sole
/// production impl is [`MailboxDispatcherImpl`], which delegates to the inherent
/// method (see the impl's non-recursion doc-lock).
#[async_trait]
pub trait ChannelNotifier: Send + Sync {
    /// Hierarchy-bypassing channel notification — full contract +
    /// validation are documented on [`MailboxDispatcherImpl::notify_channel`].
    async fn notify_channel(
        &self,
        from: &str,
        channel_id: &str,
        user_id: &str,
        payload: Vec<u8>,
        context: Option<MessageContext>,
    ) -> Result<(), NotifyError>;
}

/// Concrete dispatcher. Slice B adds the `trace` + `channel_registry` fields
/// backing `reply` / `notify_channel`. Slice C adds the `cb_bus` field (opt-in
/// via [`Self::with_circuit_breaker_bus`]) backing the Layer-1 circuit-breaker
/// query on `deliver` / `reply` / `notify_agent` / `notify_channel` paths per
/// MODULE-001 §1.4.4 line 632-637 per-surface error mapping; see MODULE-006
/// §3.8 (f) for the two-layer rationale.
pub struct MailboxDispatcherImpl {
    store: Arc<MailboxStore>,
    tree: Arc<dyn AgentTreeReader>,
    trace: Arc<MessageTrace>,
    channel_registry: Arc<dyn ChannelAdapterRegistry>,
    cb_bus: Option<Arc<dyn CircuitBreakerBus>>,
    /// Slice-D AC-09: optional EventBus emitter wired via
    /// [`Self::with_event_bus`]. When `Some`, every successful
    /// `mb.deliver(...)` on the deliver/reply/deliver_notify paths emits
    /// exactly ONE `msg.received` Event with `delivery_latency_ms` payload.
    /// `None` by default → slice-A/B/C callers stay at zero hot-path cost.
    event_bus: Option<Arc<dyn EventBusEmit>>,
    /// Wave-19 Lane-2: optional colon/bare id-bridge wired via
    /// [`Self::with_id_bridge`]. When `Some`, `deliver_notify` resolves a
    /// known colon/bare equivalence-class target to its bare tree-membership
    /// key + canonical mailbox key (both via ONE `resolve()`); when `None`
    /// (the default), `deliver_notify` uses the target verbatim — BYTE-IDENTICAL
    /// to pre-Wave-19. Only the notify path consults it (`deliver`/`reply` are
    /// untouched). See `crate::id_bridge` + MODULE-006 §3.8 (k).
    id_bridge: Option<Arc<AgentIdBridge>>,
}

impl MailboxDispatcherImpl {
    /// Wave-20 seam (a) — map a sender id to its CANONICAL colon form via the
    /// id-bridge, so a production-stamped BARE `ctx.agent_id` (e.g.
    /// `default-agent`) passes the `is_safe_id(from)` gate on the notify ingress.
    /// Returns the canonical `mailbox_key` (e.g. `agent:default`) when `from` is
    /// a bridge member; otherwise returns `from` unchanged — so with no bridge
    /// (default), an already-colon id, or `system`, the behaviour is
    /// byte-identical. NEVER mutates `ctx.agent_id` (this is local to the notify
    /// `from`); used only for the gate + the `msg.from` stamp + kind
    /// classification, never for tree membership keying.
    fn normalize_sender(&self, from: &str) -> String {
        // Wave-23 seam (e): `resolve_owned` so a runtime-`register`ed spawned
        // child's BARE `from` normalizes to its canonical colon too (the seed
        // root still resolves identically). Byte-identical with no bridge / an
        // already-colon id / `system`.
        self.id_bridge
            .as_ref()
            .and_then(|b| b.resolve_owned(from).map(|(_, mailbox_key)| mailbox_key))
            .unwrap_or_else(|| from.to_string())
    }

    /// Slice-A-compatible constructor. Builds with a fresh empty
    /// [`MessageTrace`] + [`EmptyChannelAdapterRegistry`]. `reply()` on this
    /// returns `InvalidTarget("trace_miss")` (an empty trace genuinely has
    /// no entries — correct, not a footgun); `notify_channel` returns
    /// `InvalidTarget("channel_unknown")`. Slice-A callers only use
    /// `deliver`, which is unaffected. `cb_bus` initializes to `None` —
    /// the slice-C Layer-1 gate is opt-in via
    /// [`Self::with_circuit_breaker_bus`].
    pub fn new(store: Arc<MailboxStore>, tree: Arc<dyn AgentTreeReader>) -> Self {
        Self {
            store,
            tree,
            trace: Arc::new(MessageTrace::new()),
            channel_registry: Arc::new(EmptyChannelAdapterRegistry),
            cb_bus: None,
            event_bus: None,
            id_bridge: None,
        }
    }

    /// Slice-B full constructor — inject the shared trace + channel registry.
    /// `cb_bus` initializes to `None` — the slice-C Layer-1 gate is opt-in via
    /// [`Self::with_circuit_breaker_bus`]. `event_bus` initializes to `None`
    /// — the slice-D AC-09 emit path is opt-in via [`Self::with_event_bus`].
    pub fn new_full(
        store: Arc<MailboxStore>,
        tree: Arc<dyn AgentTreeReader>,
        trace: Arc<MessageTrace>,
        channel_registry: Arc<dyn ChannelAdapterRegistry>,
    ) -> Self {
        Self {
            store,
            tree,
            trace,
            channel_registry,
            cb_bus: None,
            event_bus: None,
            id_bridge: None,
        }
    }

    /// Slice-C opt-in builder — wire the [`CircuitBreakerBus`] for Layer-1
    /// agent-scope query before delivery. Reuses CONTRACT-002 from MODULE-001
    /// (`crates/runtime/src/circuit_breaker.rs`) without modifying the bus
    /// trait or types. When wired:
    /// - `deliver` rejects with `MsgError::CircuitBreakerOpen(reason)` if
    ///   `is_open_agent(target)` returns Some AND `msg.kind != MessageKind::Control`
    ///   (admin bypass per MODULE-001 §1.4.4 lines 644-650).
    /// - `reply` rejects with `MsgError::CircuitBreakerOpen(reason)` if open
    ///   (no admin bypass; reply hard-codes `MessageKind::Agent`).
    /// - `deliver_notify` (covering `notify_agent` + `notify_channel`) rejects
    ///   with `NotifyError::CapabilityDenied("breaker_open")` if open — direct
    ///   construction, no breaker reason exposed across the notify mapping
    ///   boundary per MODULE-006 §3.8 (c) PII discipline.
    ///
    /// Layer 4 (`Mailbox::recv`/`poll` consult `is_frozen()`) is independent
    /// of this builder — its trigger is the future BreakerEvent subscriber
    /// task (see MODULE-006 §3.6 / §3.8 (f) (iii)).
    pub fn with_circuit_breaker_bus(mut self, bus: Arc<dyn CircuitBreakerBus>) -> Self {
        self.cb_bus = Some(bus);
        self
    }

    /// Slice-D opt-in builder — wire the [`EventBusEmit`] emitter for AC-09
    /// latency event emission. When wired, every successful `mb.deliver(...)`
    /// on the `deliver` / `reply` / `deliver_notify` paths emits exactly ONE
    /// `msg.received` Event with `delivery_latency_ms` payload field via
    /// [`emit_delivery_event`].
    ///
    /// **Backward-compat**: callers that don't wire this builder pay zero
    /// hot-path cost — the call-site capture pattern conditionally clones
    /// `msg` metadata only when `event_bus.is_some()`.
    ///
    /// **Cross-module note**: MODULE-019 EventBus owns the
    /// `mailbox.delivery_slow` breach mirror (M019-AC-10 already-passed);
    /// MODULE-006 emits ONLY `msg.received`. See MODULE-006 §3.8 (h).
    pub fn with_event_bus(mut self, emitter: Arc<dyn EventBusEmit>) -> Self {
        self.event_bus = Some(emitter);
        self
    }

    /// Wave-19 Lane-2 opt-in builder — wire the colon/bare [`AgentIdBridge`].
    /// When wired, `deliver_notify` (covering `notify_agent` + `notify_channel`)
    /// resolves a known equivalence-class target to its bare tree-membership key
    /// + canonical mailbox key. When NOT wired (`None` default), the notify path
    /// uses the target verbatim — BYTE-IDENTICAL to pre-Wave-19. The bridge does
    /// NOT touch the `deliver`/`reply` paths (notify-only; see `crate::id_bridge`
    /// + MODULE-006 §3.8 (k)).
    ///
    /// **Wired in production** (Wave-23 `perchild-daemon-1`): the cli composition
    /// root now injects a shared bridge (seeded with the root pair, extended per
    /// spawn by the `PerChildLoopManager`) so a runtime-registered child resolves.
    /// The `notify`-path membership residual (MODULE-006 §3.6 AC-02 row) is a
    /// separate complete-notify slice.
    pub fn with_id_bridge(mut self, bridge: Arc<AgentIdBridge>) -> Self {
        self.id_bridge = Some(bridge);
        self
    }

    /// Accessor for the backing trace — used by tests and the future
    /// authenticated inbound host_fn to call `record()`.
    pub fn trace(&self) -> &MessageTrace {
        &self.trace
    }

    /// notify-channel outbound (MODULE-006-AC-14). Resolves `channel_id` to
    /// the adapter agent id via the registry, wraps `(channel_id, user_id,
    /// payload)` in a [`ChannelDelivery`] envelope, and delivers it to the
    /// adapter's agent-style mailbox. **Inherent, not a trait method** (keeps
    /// CONTRACT-051 == §2.3 canonical). `Message.origin == None` — no
    /// provenance spoofing (the routing data is in the envelope, not a
    /// forged `MessageOrigin`); see MODULE-006 §3.8 (b).
    ///
    /// **`user_id` domain contract**: `user_id` is the **unified** identity
    /// (`user:alice` form), symmetric with [`crate::IdentityResolver`]'s
    /// inbound normalization (channel-native → unified). It is NOT a
    /// channel-native handle (`telegram:1234567`) — the receiving channel
    /// adapter reverse-resolves the unified id to its channel-native
    /// recipient. `is_safe_id(user_id)` is therefore the correct validator
    /// (it accepts `user:<body>`), and it also defeats newline/null/Unicode
    /// splice into the envelope + downstream adapter logs. See MODULE-006
    /// §3.8 (b) for the unified-form rationale.
    pub async fn notify_channel(
        &self,
        from: &str,
        channel_id: &str,
        user_id: &str,
        payload: Vec<u8>,
        context: Option<MessageContext>,
    ) -> Result<(), NotifyError> {
        // Wave-20 seam (a) — sender canonical-colon normalization (see
        // `notify_agent`). Local to the notify `from`.
        let from = self.normalize_sender(from);
        let from = from.as_str();
        if !is_safe_id(from) {
            return Err(NotifyError::InvalidTarget("invalid_id".into()));
        }
        if channel_id.is_empty() {
            return Err(NotifyError::InvalidTarget("channel_id_empty".into()));
        }
        // Bound channel_id so the envelope-overhead reservation is provable
        // (channel_id is a channel name, not an agent id, so a plain length
        // bound — not is_safe_id — is the right check). Adversarial r2 fix.
        if channel_id.len() > MAX_ID_BYTES {
            return Err(NotifyError::InvalidTarget("channel_id_too_large".into()));
        }
        // user_id flows into the envelope (and downstream adapter logs).
        // Enforce the documented UNIFIED-form contract: it must be a
        // `user:<body>` id (NOT `agent:`/`system` — a channel delivery's
        // recipient is a user, symmetric with IdentityResolver's inbound
        // normalization). `is_safe_id` additionally defeats
        // newline/null/Unicode splice (R-class hardening) and bounds the
        // length at MAX_ID_BYTES.
        if !is_safe_id(user_id) || !user_id.starts_with("user:") {
            return Err(NotifyError::InvalidTarget("user_id_invalid".into()));
        }
        // FAST-PATH pre-cap: reject gross over-size BEFORE the
        // expansion-prone serde_json encode, avoiding the ~4× transient
        // allocation. With channel_id/user_id ≤ MAX_ID_BYTES and the
        // reserved envelope overhead, anything passing this bound is
        // guaranteed to encode ≤ MAX_PAYLOAD_BYTES (Adversarial r2 fix).
        if payload.len() > MAX_NOTIFY_CHANNEL_PAYLOAD_BYTES {
            return Err(NotifyError::InvalidTarget("payload_too_large".into()));
        }
        let adapter = self
            .channel_registry
            .resolve(channel_id)
            .ok_or_else(|| NotifyError::InvalidTarget("channel_unknown".into()))?;
        let envelope = serde_json::to_vec(&ChannelDelivery {
            channel_id: channel_id.to_string(),
            user_id: user_id.to_string(),
            body: payload,
        })
        .map_err(|_| NotifyError::InvalidTarget("envelope_encode_failed".into()))?;
        // HARD correctness guarantee (Adversarial r2 fix): an exact
        // post-encode check. The fast-path pre-cap should make this
        // unreachable for valid bounded inputs, but this is the actual
        // invariant — the envelope delivered to the mailbox can NEVER
        // exceed MAX_PAYLOAD_BYTES, and the caller gets the CLEAR
        // `payload_too_large` here rather than a confusing post-deliver
        // `InvalidTarget("payload")` from `map_msg_to_notify`.
        if envelope.len() > MAX_PAYLOAD_BYTES {
            return Err(NotifyError::InvalidTarget("payload_too_large".into()));
        }
        self.deliver_notify(from, &adapter, envelope, context).await
    }

    /// Shared notify delivery path for `notify_agent` + `notify_channel`:
    /// context byte-caps, target existence, message-kind classification,
    /// `origin: None` construction, deliver, and the `MsgError → NotifyError`
    /// 4-variant mapping (MODULE-006 §3.8 (c)).
    async fn deliver_notify(
        &self,
        from: &str,
        target: &str,
        payload: Vec<u8>,
        context: Option<MessageContext>,
    ) -> Result<(), NotifyError> {
        // Slice-D AC-09: capture start at FUNCTION ENTRY so `delivery_latency_ms`
        // covers the full dispatcher pipeline (CB query + context validation +
        // tree lookup + store lookup + mailbox enqueue).
        let start = tokio::time::Instant::now();
        // Wave-19 Lane-2: the colon/bare id-bridge. When an `AgentIdBridge` is
        // wired AND `target` is a known equivalence-class member, resolve it to
        // the BARE tree-membership key + the CANONICAL mailbox key — both via the
        // SAME `resolve()`, so there is no membership-passes / mailbox-orphans
        // split. When no bridge is wired (or `target` is not a member), use
        // `target` verbatim → BYTE-IDENTICAL to pre-Wave-19.
        // Wave-23 seam (e): `resolve_owned` so a runtime-`register`ed spawned
        // child resolves too (the seed root resolves identically). Owned because
        // the runtime overflow map lives behind a lock; `&str` views below keep
        // the downstream keying byte-identical.
        let (membership_owned, mailbox_owned): (String, String) = match self
            .id_bridge
            .as_ref()
            .and_then(|b| b.resolve_owned(target))
        {
            Some((bare, mailbox)) => (bare, mailbox),
            None => (target.to_string(), target.to_string()),
        };
        let (membership_key, mailbox_key): (&str, &str) = (&membership_owned, &mailbox_owned);
        // Slice-C Layer-1 CB query — first check, before context validation /
        // tree lookup. The query uses the bridge-resolved membership key so the
        // production bare tree id and notify's canonical mailbox id cannot split
        // CB behavior. Direct NotifyError construction (no `MsgError →
        // map_msg_to_notify` round-trip) honors PII discipline — the breaker
        // reason is NOT carried across the notify mapping boundary per §3.8 (c)
        // precedent. notify is hierarchy-bypassing by design (no admin-Control
        // branch here — notify-paths derive MessageKind from `from` prefix AFTER
        // this gate, see §3.8 (e); admin-bypass is the `deliver` path's concern).
        if let Some(bus) = &self.cb_bus {
            if bus.is_open_agent(membership_key).is_some() {
                return Err(NotifyError::CapabilityDenied("breaker_open".into()));
            }
        }
        if let Some(ctx) = &context {
            validate_message_context(ctx)
                .map_err(|_| NotifyError::InvalidTarget("context_field_too_large".into()))?;
        }
        if !self.tree.agent_exists(membership_key) {
            return Err(NotifyError::InvalidTarget("target_unknown".into()));
        }
        let kind = if from == "system" {
            MessageKind::System
        } else if from.starts_with("user:") {
            MessageKind::User
        } else {
            // agent: senders (and anything else routed here) → Agent.
            MessageKind::Agent
        };
        let msg = Message {
            id: uuid::Uuid::new_v4().to_string(),
            kind,
            from: from.to_string(),
            // `to` == the canonical mailbox key (== `target` when unbridged), so
            // the recorded recipient address and the mailbox the message lands in
            // never diverge.
            to: mailbox_key.to_string(),
            payload,
            context,
            timestamp: std::time::SystemTime::now(),
            origin: None,
        };
        let mb = self
            .store
            .get_or_create(mailbox_key)
            .map_err(map_msg_to_notify)?;
        // Slice-D AC-09: conditional metadata capture (hot-path zero-cost when
        // event_bus is None — slice-A/B/C callers unaffected). Captures BEFORE
        // the mb.deliver(msg) move so we can pass refs to emit_delivery_event
        // on success.
        let event_bus = self.event_bus.clone();
        let captured = event_bus.as_ref().map(|_| {
            (
                msg.id.clone(),
                msg.from.clone(),
                msg.kind.clone(),
                msg.context.clone(),
                mailbox_key.to_string(),
            )
        });
        mb.deliver(msg).map_err(map_msg_to_notify)?;
        if let (Some(bus), Some((id, from_s, kind, ctx, to))) = (event_bus, captured) {
            emit_delivery_event(
                &*bus,
                &id,
                &from_s,
                &to,
                kind,
                ctx.as_ref(),
                start.elapsed(),
            );
        }
        Ok(())
    }
}

/// MODULE-006 §3.8 (c) — collapse the 5-variant `MsgError` onto the §2.3
/// canonical 4-variant `NotifyError`. Reason strings are invariant
/// identifiers (PII discipline); `IdentityUnknown` is never produced here
/// (reserved for inbound identity-resolution failure — a future host_fn
/// concern).
fn map_msg_to_notify(e: MsgError) -> NotifyError {
    match e {
        MsgError::MailboxFull => NotifyError::MailboxFull,
        MsgError::CapabilityDenied(r) => NotifyError::CapabilityDenied(r),
        MsgError::CircuitBreakerOpen(_) => NotifyError::CapabilityDenied("breaker_open".into()),
        MsgError::InvalidTarget(_) => NotifyError::InvalidTarget("delivery".into()),
        MsgError::InvalidPayload(_) => NotifyError::InvalidTarget("payload".into()),
    }
}

impl TurnMailboxDispatchPort for MailboxDispatcherImpl {
    fn prepare_turn_batch(&self, deliveries: Vec<TurnMailboxDelivery>) -> PreparedTurnBatch {
        let gated = deliveries
            .into_iter()
            .map(|delivery| {
                if delivery.target != delivery.message.to
                    || delivery.target != delivery.spec.expected_agent
                    || delivery.message.id != delivery.spec.turn_id
                    || delivery.message.from != delivery.spec.parent_agent
                {
                    return Err(MsgError::InvalidTarget("turn-route-mismatch".into()));
                }
                let routing_from = self
                    .id_bridge
                    .as_ref()
                    .and_then(|bridge| {
                        bridge
                            .resolve_owned(&delivery.message.from)
                            .map(|(_, canonical_mailbox)| canonical_mailbox)
                    })
                    .unwrap_or_else(|| delivery.message.from.clone());
                let routing_target = self
                    .id_bridge
                    .as_ref()
                    .and_then(|bridge| {
                        bridge
                            .resolve_owned(&delivery.target)
                            .map(|(_, canonical_mailbox)| canonical_mailbox)
                    })
                    .unwrap_or_else(|| delivery.target.clone());
                validate_routing(&*self.tree, &routing_from, &routing_target)?;
                if !matches!(delivery.message.kind, MessageKind::Control) {
                    if self
                        .cb_bus
                        .as_ref()
                        .is_some_and(|bus| bus.is_open_agent(&routing_target).is_some())
                    {
                        return Err(MsgError::CircuitBreakerOpen("agent".into()));
                    }
                }
                Ok(delivery)
            })
            .collect();
        self.store.prepare_gated_turn_batch(gated)
    }

    fn publish_prepared(&self, batch: &mut PreparedTurnBatch) -> Result<(), MsgError> {
        self.store.publish_prepared(batch)
    }

    fn detach_turn_batch(
        &self,
        session_id: &SessionId,
        batch: &mut PreparedTurnBatch,
    ) -> Result<(), MsgError> {
        self.store.detach_turn_batch(session_id, batch)
    }
}

#[async_trait]
impl MailboxDispatcher for MailboxDispatcherImpl {
    async fn deliver(&self, target: &str, msg: Message) -> Result<(), MsgError> {
        // Slice-D AC-09: capture start at FUNCTION ENTRY so `delivery_latency_ms`
        // covers the full dispatcher pipeline (validate_routing + CB query +
        // store lookup + mailbox enqueue).
        let start = tokio::time::Instant::now();
        // Slice-A trust-boundary note: `msg.from` is authoritative at this
        // layer; the caller stamps it from authenticated context. Slice-A
        // defense-in-depth runs `is_safe_id` on both `from` and `target`
        // inside `validate_routing`.
        validate_routing(&*self.tree, &msg.from, target)?;
        // Slice-C Layer-1 CB query — agent-scope breaker gate per MODULE-001
        // §1.4.4 line 635 ("send / reply → msg-error::circuit-breaker-open").
        // Skip on `MessageKind::Control` per §1.4.4 lines 644-650 admin-bypass
        // — terminate-child / cancel-run / pause-run / run.interrupted MUST
        // bypass the breaker so an operator can still pause a broken agent.
        //
        // PII discipline (Adversarial R1 Critical fix): we deliberately
        // DROP the bus's operator-supplied reason and return the invariant
        // identifier `"agent"` (slice-A §1.3.2 reference-impl precedent —
        // `Err(MsgError::CircuitBreakerOpen("agent".into()))` — never the
        // bus's free-form reason). The bus's reason is operator metadata
        // (up to MAX_REASON_LEN bytes) that may carry PII; propagating it
        // verbatim into a guest-visible MsgError would be an information-
        // disclosure vector against adjacent agents. The host-side
        // observability stack (BreakerEvent emit + operator dashboards)
        // is the correct surface for the reason, not the typed error.
        //
        // Kind-trust caveat (Adversarial R1 Critical, deferred): `msg.kind`
        // is caller-stamped at the dispatcher boundary, same trust model as
        // `msg.from` (slice-A note above). A guest-reachable host_fn that
        // forwards a guest-built `Message` verbatim could stamp `kind=Control`
        // to bypass this gate. The future WIT host_fn slice (AC-01/AC-02)
        // MUST scrub `kind` from guest input — see §3.8 (f) (ix) for the
        // deferred defense-in-depth note. There is no in-dispatcher check
        // because the legitimate Control-from-agent case (parent agent
        // sending pause-run to child) does exist; the defense belongs at
        // the WIT lift, not here.
        if !matches!(msg.kind, MessageKind::Control) {
            if let Some(bus) = &self.cb_bus {
                if bus.is_open_agent(target).is_some() {
                    return Err(MsgError::CircuitBreakerOpen("agent".into()));
                }
            }
        }
        let mb = self.store.get_or_create(target)?;
        // Slice-D AC-09: conditional metadata capture for `msg.received` emit
        // on successful delivery. Hot-path zero-cost when event_bus is None.
        let event_bus = self.event_bus.clone();
        let captured = event_bus.as_ref().map(|_| {
            (
                msg.id.clone(),
                msg.from.clone(),
                msg.kind.clone(),
                msg.context.clone(),
                target.to_string(),
            )
        });
        mb.deliver(msg)?;
        if let (Some(bus), Some((id, from_s, kind, ctx, to))) = (event_bus, captured) {
            emit_delivery_event(
                &*bus,
                &id,
                &from_s,
                &to,
                kind,
                ctx.as_ref(),
                start.elapsed(),
            );
        }
        Ok(())
    }

    async fn reply(
        &self,
        from: &str,
        to_message_id: &str,
        payload: Vec<u8>,
    ) -> Result<(), MsgError> {
        // Slice-D AC-09: capture start at FUNCTION ENTRY so `delivery_latency_ms`
        // covers the full reply pipeline (id check + payload cap + trace lookup
        // + authz + tree check + CB query + store lookup + mailbox enqueue).
        let start = tokio::time::Instant::now();
        if !is_safe_id(from) {
            return Err(MsgError::InvalidTarget("invalid_id".into()));
        }
        if payload.len() > MAX_PAYLOAD_BYTES {
            return Err(MsgError::InvalidPayload("payload_too_large".into()));
        }
        let (origin, recipient) = self
            .trace
            .lookup_full(to_message_id)
            .ok_or_else(|| MsgError::InvalidTarget("trace_miss".into()))?;
        // Authorization (MODULE-006 §3.8 (b)): only the agent the inbound was
        // delivered to may reply to it. The trace is host-internal (§1.6);
        // `recipient` is host-stamped at record().
        if from != recipient {
            return Err(MsgError::InvalidTarget("reply_not_authorized".into()));
        }
        let target = origin.adapter_id.clone();
        // No hierarchy-adjacency check: the target is trace-derived +
        // recipient-authorized, not caller-chosen (§3.8 (d)). Still enforce
        // id shape + existence.
        if !is_safe_id(&target) || !self.tree.agent_exists(&target) {
            return Err(MsgError::InvalidTarget("adapter_unknown".into()));
        }
        // Slice-C Layer-1 CB query — agent-scope breaker gate per MODULE-001
        // §1.4.4 line 635 ("send / reply → msg-error::circuit-breaker-open").
        // Reply hard-codes `MessageKind::Agent` (see the `kind` field a few
        // lines below) — admin-bypass via Control kind is moot here and the
        // gate fires unconditionally on open.
        //
        // PII discipline (Adversarial R1 Critical fix, mirror of `deliver`):
        // drop the bus's operator-supplied reason and return the invariant
        // identifier `"agent"`. The operator-side observability stack is the
        // correct surface for the reason, not the guest-visible MsgError.
        if let Some(bus) = &self.cb_bus {
            if bus.is_open_agent(&target).is_some() {
                return Err(MsgError::CircuitBreakerOpen("agent".into()));
            }
        }
        // Inherit the original context verbatim (task/run/execution/trace/
        // correlation — AC-07); stamp a fresh `in_reply_to`, overwriting any
        // inherited value.
        let mut ctx = origin.context.clone().unwrap_or(MessageContext {
            task_id: None,
            run_id: None,
            execution_id: None,
            trace_id: None,
            in_reply_to: None,
            correlation_id: None,
        });
        ctx.in_reply_to = Some(to_message_id.to_string());
        // Carry the GENUINE original MessageOrigin through verbatim — §2.3
        // "channel_metadata … passed through on reply"; adapter_id "Used for
        // reply routing back to the originating adapter". This is the
        // documented reply passthrough, NOT the notify_channel origin-spoof
        // concern (reply has a real inbound origin; §3.8 (b)).
        let msg = Message {
            id: uuid::Uuid::new_v4().to_string(),
            kind: MessageKind::Agent,
            from: from.to_string(),
            to: target.clone(),
            payload,
            context: Some(ctx),
            timestamp: std::time::SystemTime::now(),
            origin: Some(origin),
        };
        let mb = self.store.get_or_create(&target)?;
        // Slice-D AC-09: conditional metadata capture (Round-2 Critical #1 fix:
        // reply path is NOT exempt from msg.received emission; all 3 deliver-
        // terminating dispatcher paths must instrument).
        let event_bus = self.event_bus.clone();
        let captured = event_bus.as_ref().map(|_| {
            (
                msg.id.clone(),
                msg.from.clone(),
                msg.kind.clone(),
                msg.context.clone(),
                target.clone(),
            )
        });
        mb.deliver(msg)?;
        if let (Some(bus), Some((id, from_s, kind, ctx, to))) = (event_bus, captured) {
            emit_delivery_event(
                &*bus,
                &id,
                &from_s,
                &to,
                kind,
                ctx.as_ref(),
                start.elapsed(),
            );
        }
        Ok(())
    }

    async fn notify_agent(
        &self,
        from: &str,
        target: &str,
        payload: Vec<u8>,
        context: Option<MessageContext>,
    ) -> Result<(), NotifyError> {
        // Wave-20 seam (a) — sender canonical-colon normalization. A production
        // component's `ctx.agent_id` is stamped BARE (e.g. `default-agent`,
        // load-bearing for cap-grant keying); the bare form fails
        // `is_safe_id(from)`. Map it to its CANONICAL colon form via the
        // id-bridge BEFORE the gate (no bridge / non-member / already-colon /
        // `system` → unchanged → byte-identical). This is local to the notify
        // `from` (never mutates `ctx.agent_id`).
        let from = self.normalize_sender(from);
        if !is_safe_id(&from) || !is_safe_id(target) {
            return Err(NotifyError::InvalidTarget("invalid_id".into()));
        }
        // Hierarchy-bypassing by design (notify ≠ send). The `from == system`
        // path is the AC-15 cron/daemon bypass mechanism (REQ-032).
        self.deliver_notify(&from, target, payload, context).await
    }
}

#[async_trait]
impl ChannelNotifier for MailboxDispatcherImpl {
    /// Delegates to the **inherent** [`MailboxDispatcherImpl::notify_channel`].
    ///
    /// **Non-recursive (DOC-LOCK):** the call below is fully-qualified to the
    /// inherent method (`MailboxDispatcherImpl::notify_channel(self, …)`). Rust
    /// resolves `Type::method` to an inherent method in preference to a
    /// trait method of the same name, so this is a single hop into the real
    /// implementation, NOT infinite recursion. Do NOT remove the inherent
    /// `notify_channel` method — doing so would silently rebind this call to the
    /// trait method and recurse. The SUT witness `tnc_01_*` in
    /// `crates/system-acceptance/tests/sys_j30_notify_channel.rs` drives this trait
    /// method end-to-end and guards the delegation (a recursive impl would
    /// stack-overflow the test).
    async fn notify_channel(
        &self,
        from: &str,
        channel_id: &str,
        user_id: &str,
        payload: Vec<u8>,
        context: Option<MessageContext>,
    ) -> Result<(), NotifyError> {
        MailboxDispatcherImpl::notify_channel(self, from, channel_id, user_id, payload, context)
            .await
    }
}

/// Slice-D AC-09 helper — emit exactly ONE `msg.received` Event.
///
/// Called by all three target-reaching dispatcher entry points
/// (`deliver`/`reply`/`deliver_notify`) AFTER successful `mb.deliver(...)`.
/// The Event uses the 12-field shape per `shared-types/src/event.rs:71-84`:
///
/// - `agent_id` = `to` (RECEIVER-anchored; matches MODULE-019 mirror's
///   `source.agent_id.clone()` propagation at `event-bus/src/lib.rs:298+310`)
/// - `task_id`/`run_id`/`execution_id` propagated from `context` when present
/// - `trace_id` chain-preserved from `context.trace_id` when present, fresh
///   UUID otherwise (M019 mirror clones this into its own envelope at
///   `event-bus/src/lib.rs:314`)
/// - `span_id` is a fresh UUID (M019 mirror uses this as `parent_span_id` at
///   `event-bus/src/lib.rs:316` for breach lineage)
/// - `event_type` = [`EVENT_MSG_RECEIVED`]
/// - `payload` = `{message_id, from, to, kind, delivery_latency_ms}`; `kind`
///   is the lowercase variant name (explicit match — `MessageKind` derives
///   `Serialize` which capitalizes variant names; tests assert lowercase)
/// - `duration_ms` = `Some(latency.as_millis() as u64)` (top-level mirror of
///   payload field for dashboard correlation)
///
/// PII discipline: `from`/`to`/`message_id` are stable id forms (slice-A
/// `is_safe_id`-validated). NO message-payload bytes echoed into Event.
/// Mirror slice-C §3.8 (iv).
///
/// MODULE-006 deliberately does NOT emit `mailbox.delivery_slow` — MODULE-019
/// EventBus's `EmitPipeline::emit_breach_mirror` (event-bus/src/lib.rs:295-323,
/// M019-AC-10 already-passed) synthesizes it downstream from this event's
/// `delivery_latency_ms`. See MODULE-006 §3.8 (h).
pub fn emit_delivery_event(
    emitter: &dyn EventBusEmit,
    message_id: &str,
    from: &str,
    to: &str,
    kind: MessageKind,
    context: Option<&MessageContext>,
    latency: Duration,
) {
    // Explicit lowercase mapping — MessageKind's Serialize derive produces
    // capitalized variant names ("User"/"Agent"/...); tests assert lowercase
    // for downstream operator-dashboard consistency.
    let kind_str = match kind {
        MessageKind::User => "user",
        MessageKind::Agent => "agent",
        MessageKind::Control => "control",
        MessageKind::Auto => "auto",
        MessageKind::System => "system",
    };
    let latency_ms = latency.as_millis() as u64;

    let trace_id = context
        .and_then(|c| c.trace_id.clone())
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    let event = Event {
        id: uuid::Uuid::new_v4().to_string(),
        timestamp: chrono::Utc::now(),
        agent_id: to.to_string(),
        task_id: context.and_then(|c| c.task_id.clone()),
        run_id: context.and_then(|c| c.run_id.clone()),
        execution_id: context.and_then(|c| c.execution_id.clone()),
        trace_id,
        span_id: uuid::Uuid::new_v4().to_string(),
        parent_span_id: None,
        event_type: EVENT_MSG_RECEIVED.to_string(),
        payload: serde_json::json!({
            "message_id": message_id,
            "from": from,
            "to": to,
            "kind": kind_str,
            "delivery_latency_ms": latency_ms,
        }),
        duration_ms: Some(latency_ms),
    };
    emitter.emit(event);
}

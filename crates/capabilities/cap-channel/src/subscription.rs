//! Subscription state + manager (MODULE-016 §1.4.2 + §2.5).
//!
//! Slice B's `Subscription` is a struct (indexed by `AdapterType`) rather than
//! the enum sketch shown in MODULE-016 §1.4.2; see the illustrative-reference
//! note in §1.4.2 and §2.5 for rationale. The transport-specific clients
//! (`long_poll.rs`, `ws.rs`, `sse.rs`) attach to a `Subscription` in later slices
//! without disturbing this storage layout.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, RwLock};

use secrecy::{ExposeSecret, Secret};

use crate::error::ChannelError;
use crate::types::{ChannelConfig, RawEvent, SubscriptionId};

/// Default per-subscription buffer capacity (MODULE-016 §2.10).
pub const DEFAULT_BUFFER_CAP: usize = 1000;

/// Hard cap on the number of concurrent subscriptions held by a single
/// `SubscriptionManager`. Bounds the per-process resource footprint:
/// 1024 subscriptions × (1000-event buffer × 1 MB body cap) = ~1 GB worst-case
/// memory. Combined with the per-`subscribe()` defensive caps in
/// `wit_impl.rs::lift_channel_config`, this rejects an adapter WASM that
/// attempts to flood `subscribe` calls to exhaust host memory.
///
/// Adversarial Eval R17 #1: a malicious adapter holding `channel` capability
/// can otherwise call `subscribe` in a tight loop with no upper bound.
pub const MAX_SUBSCRIPTIONS: usize = 1024;

/// Minimum HMAC-SHA256 key length (16 bytes / 128 bits). Shorter keys are
/// rejected at construction time — RFC 2104 recommends ≥ digest output length
/// (32 bytes for SHA-256) for hash equivalence, but 16 bytes is the floor
/// below which we refuse outright. An empty key here would let an attacker
/// forge signatures since `HMAC-SHA256("", body)` is a deterministic,
/// attacker-known value.
pub const MIN_WEBHOOK_SECRET_BYTES: usize = 16;

/// Which single consumer drains a subscription's buffer (Phase-2 Step-3,
/// ADR `2026-06-05` L0/L3 single-owner-per-subscription rule). A subscription is
/// drained by EXACTLY ONE path — never both — so the host pump and a WASM adapter
/// never double-drain the same FIFO:
/// - [`Consumer::WasmGuest`] — drained by the WIT `poll-raw` (a WASM adapter
///   guest). The default for `subscribe` (the existing WIT subscribe path).
/// - [`Consumer::HostPump`] — drained by the host-internal [`SubscriptionManager::poll_host_pump`]
///   (the daemon's in-host pump). Set via [`SubscriptionManager::subscribe_host_pump`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Consumer {
    /// Drained by the WIT `poll-raw` (WASM adapter guest).
    WasmGuest,
    /// Drained by the host-internal `poll_host_pump` (daemon pump).
    HostPump,
}

/// HMAC-SHA256 webhook secret wrapped in `secrecy::Secret` — Debug-redacted,
/// zeroed on drop via `Secret`'s `Drop` impl. The internal `Vec<u8>` is treated
/// as opaque by callers; use `expose_secret_bytes` to obtain the slice for
/// HMAC computation inside the webhook handler only.
///
/// Not `Clone` — `secrecy::Secret<Vec<u8>>` requires `u8: CloneableSecret`
/// which is not implemented for primitive types. Callers move the secret in
/// once via `SubscriptionManager::set_webhook_secret`; no internal path clones.
pub struct SecretBytes(Secret<Vec<u8>>);

impl SecretBytes {
    /// Construct a `SecretBytes` from raw key material. Returns
    /// `ChannelError::InvalidConfig` if `bytes.len() < MIN_WEBHOOK_SECRET_BYTES`
    /// — empty or short keys defeat HMAC signature verification.
    pub fn new(bytes: Vec<u8>) -> Result<Self, ChannelError> {
        if bytes.len() < MIN_WEBHOOK_SECRET_BYTES {
            return Err(ChannelError::InvalidConfig(format!(
                "webhook secret must be at least {MIN_WEBHOOK_SECRET_BYTES} bytes (got {})",
                bytes.len()
            )));
        }
        Ok(Self(Secret::new(bytes)))
    }

    /// Borrow the secret for HMAC computation. Only the webhook handler should
    /// call this; callers must not log, copy, or otherwise persist the bytes.
    pub fn expose_secret_bytes(&self) -> &[u8] {
        self.0.expose_secret()
    }
}

impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[REDACTED_SECRET]")
    }
}

/// Slice B `Subscription` struct (per §2.5 illustrative-reference note).
///
/// `buffer` is non-public — all event push/pop traffic must go through
/// [`Self::push_event`] / [`Self::pop_event`] so the bounded-buffer cap
/// (`buffer_cap`) is enforced. `webhook_secret` is behind an `RwLock` so
/// secrets can be rotated without invalidating shared `Arc<Subscription>`
/// references (avoids the stale-Arc data-loss race that would arise from
/// reconstructing the Arc on each secret update).
///
/// Manual `Debug` impl summarizes the buffer as `[BUFFERED_EVENTS={N}]`
/// rather than dumping every buffered `RawEvent` (whose `data` would
/// likely include PII / OAuth tokens). Per Adversarial Eval R19 #1.
pub struct Subscription {
    pub id: SubscriptionId,
    pub config: ChannelConfig,
    /// Originating agent id — the `HostCallContext.agent_id` of the WIT
    /// caller that issued `subscribe`. Used by `poll_raw` / `dispatch` to
    /// enforce per-agent ownership: another agent cannot read events from
    /// or send through a subscription it did not create. Per Adversarial
    /// Eval R19 #2 (cross-agent lateral-movement defense).
    pub owner_agent_id: String,
    /// The single buffer consumer (Phase-2 Step-3 single-owner rule). Set at
    /// registration; asserted by `poll_raw` (rejects `HostPump`) and
    /// `poll_host_pump` (rejects `WasmGuest`).
    pub consumer: Consumer,
    buffer: Mutex<VecDeque<RawEvent>>,
    pub buffer_cap: usize,
    webhook_secret: RwLock<Option<SecretBytes>>,
}

impl std::fmt::Debug for Subscription {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let buffered = self
            .buffer
            .lock()
            .map(|b| b.len())
            .unwrap_or_else(|e| e.into_inner().len());
        f.debug_struct("Subscription")
            .field("id", &self.id)
            .field("config", &self.config)
            .field("owner_agent_id", &self.owner_agent_id)
            .field("buffer", &format_args!("[BUFFERED_EVENTS={buffered}]"))
            .field("buffer_cap", &self.buffer_cap)
            .field("webhook_secret", &"<RwLock<Option<SecretBytes>>>")
            .finish()
    }
}

impl Subscription {
    /// Construct a subscription with the default buffer cap and no webhook
    /// secret (the webhook receiver attaches a secret via
    /// [`SubscriptionManager::set_webhook_secret`] after `subscribe`).
    pub fn new(
        id: SubscriptionId,
        owner_agent_id: impl Into<String>,
        config: ChannelConfig,
    ) -> Self {
        // The WIT `subscribe` path → WasmGuest consumer (the default).
        Self::new_with_consumer(id, owner_agent_id, config, Consumer::WasmGuest)
    }

    /// Construct a subscription with an explicit [`Consumer`] (Phase-2 Step-3).
    /// The host pump path uses `Consumer::HostPump`.
    pub fn new_with_consumer(
        id: SubscriptionId,
        owner_agent_id: impl Into<String>,
        config: ChannelConfig,
        consumer: Consumer,
    ) -> Self {
        Self {
            id,
            owner_agent_id: owner_agent_id.into(),
            consumer,
            config,
            buffer: Mutex::new(VecDeque::new()),
            buffer_cap: DEFAULT_BUFFER_CAP,
            webhook_secret: RwLock::new(None),
        }
    }

    /// Pop the next event from the per-subscription buffer (FIFO).
    pub fn pop_event(&self) -> Option<RawEvent> {
        let mut buf = self.buffer.lock().unwrap_or_else(|e| e.into_inner());
        buf.pop_front()
    }

    /// Push an event into the bounded buffer; returns `BufferOverflow` if the
    /// buffer is at `buffer_cap` capacity.
    pub fn push_event(&self, event: RawEvent) -> Result<(), ChannelError> {
        let mut buf = self.buffer.lock().unwrap_or_else(|e| e.into_inner());
        if buf.len() >= self.buffer_cap {
            return Err(ChannelError::BufferOverflow(self.id.as_str().to_string()));
        }
        buf.push_back(event);
        Ok(())
    }

    /// Run a closure with the webhook secret (if any) under a read lock. The
    /// secret slice is borrowed for the duration of the closure; do not
    /// persist the slice past the closure boundary.
    pub fn with_webhook_secret<R>(&self, f: impl FnOnce(Option<&SecretBytes>) -> R) -> R {
        let guard = self
            .webhook_secret
            .read()
            .unwrap_or_else(|e| e.into_inner());
        f(guard.as_ref())
    }

    /// True iff a webhook secret is currently registered.
    pub fn has_webhook_secret(&self) -> bool {
        self.webhook_secret
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
    }

    /// Replace the webhook secret in-place. Holders of an `Arc<Subscription>`
    /// see the new secret on next `with_webhook_secret` call.
    fn set_webhook_secret_inner(&self, secret: SecretBytes) {
        let mut guard = self
            .webhook_secret
            .write()
            .unwrap_or_else(|e| e.into_inner());
        *guard = Some(secret);
    }
}

/// In-memory subscription registry. Bare `RwLock<HashMap>` is sufficient for
/// Slice B — the per-subscription state is moved into `Arc<Subscription>` so
/// readers (poll / send-raw / webhook) can drop the outer lock immediately.
#[derive(Default)]
pub struct SubscriptionManager {
    subs: RwLock<HashMap<SubscriptionId, Arc<Subscription>>>,
}

impl SubscriptionManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Allocate a new subscription. Rejects `AdapterType::Other(*)` with
    /// `InvalidConfig` per MODULE-016 §1.4.2:97. Rejects with
    /// `InvalidConfig` if `subscription_count() >= MAX_SUBSCRIPTIONS` (DoS
    /// defense — Adversarial Eval R17 #1).
    ///
    /// `owner_agent_id` is the WIT caller's `HostCallContext.agent_id`. It
    /// is bound to the subscription at creation time; subsequent `poll_raw`
    /// / `dispatch` calls reject if their `caller_agent_id` does not match.
    /// Adversarial Eval R19 #2 — closes the cross-agent lateral-movement
    /// attack where agent B with sub_id_A could read A's inbound events or
    /// send through A's outbound configuration.
    pub fn subscribe(
        &self,
        owner_agent_id: impl Into<String>,
        config: ChannelConfig,
    ) -> Result<SubscriptionId, ChannelError> {
        if let crate::types::AdapterType::Other(ref raw) = config.adapter_type {
            return Err(ChannelError::InvalidConfig(format!(
                "unknown adapter: {raw}"
            )));
        }

        let mut subs = self.subs.write().unwrap_or_else(|e| e.into_inner());
        if subs.len() >= MAX_SUBSCRIPTIONS {
            return Err(ChannelError::InvalidConfig(format!(
                "subscription cap reached ({MAX_SUBSCRIPTIONS})"
            )));
        }
        let id = SubscriptionId::new();
        let sub = Arc::new(Subscription::new(id.clone(), owner_agent_id, config));
        subs.insert(id.clone(), sub);
        Ok(id)
    }

    /// Poll the next event for a subscription. Missing subscription →
    /// `NotFound`. `caller_agent_id` mismatch → `PermissionDenied` (closes
    /// cross-agent lateral-movement attack). No event → `Ok(None)`.
    pub fn poll_raw(
        &self,
        caller_agent_id: &str,
        sub_id: &SubscriptionId,
    ) -> Result<Option<RawEvent>, ChannelError> {
        let sub = self
            .lookup(sub_id)
            .ok_or_else(|| ChannelError::NotFound(format!("subscription {}", sub_id.as_str())))?;
        if sub.owner_agent_id != caller_agent_id {
            return Err(ChannelError::PermissionDenied(format!(
                "subscription {} not owned by caller",
                sub_id.as_str()
            )));
        }
        // Phase-2 Step-3 single-owner rule: a host-pump-consumed subscription is
        // drained by the daemon's `poll_host_pump`, NOT the WIT `poll-raw`. A WASM
        // guest must not double-drain it.
        if sub.consumer != Consumer::WasmGuest {
            return Err(ChannelError::PermissionDenied(format!(
                "subscription {} is host-pump-consumed; not WIT-pollable",
                sub_id.as_str()
            )));
        }
        Ok(sub.pop_event())
    }

    /// Register a HOST-PUMP subscription (Phase-2 Step-3) — drained by the
    /// daemon's in-host pump via [`Self::poll_host_pump`], never by the WIT
    /// `poll-raw`. Same `Other(*)`-reject + `MAX_SUBSCRIPTIONS` cap as
    /// [`Self::subscribe`]. `owner_agent_id` is the serving agent id whose
    /// outbound egress ownership check must match.
    pub fn subscribe_host_pump(
        &self,
        owner_agent_id: impl Into<String>,
        config: ChannelConfig,
    ) -> Result<SubscriptionId, ChannelError> {
        if let crate::types::AdapterType::Other(ref raw) = config.adapter_type {
            return Err(ChannelError::InvalidConfig(format!(
                "unknown adapter: {raw}"
            )));
        }
        let mut subs = self.subs.write().unwrap_or_else(|e| e.into_inner());
        if subs.len() >= MAX_SUBSCRIPTIONS {
            return Err(ChannelError::InvalidConfig(format!(
                "subscription cap reached ({MAX_SUBSCRIPTIONS})"
            )));
        }
        let id = SubscriptionId::new();
        let sub = Arc::new(Subscription::new_with_consumer(
            id.clone(),
            owner_agent_id,
            config,
            Consumer::HostPump,
        ));
        subs.insert(id.clone(), sub);
        Ok(id)
    }

    /// Host-internal drain (Phase-2 Step-3) — the daemon's in-host pump path.
    /// Missing subscription → `NotFound`. A `WasmGuest`-consumed subscription →
    /// `PermissionDenied` (single-owner rule: the host pump must not drain a
    /// guest-polled buffer). **No agent-ownership gate** — this is host-trusted
    /// code reached only via the daemon composition root (mirrors
    /// [`Self::enqueue_event`]'s no-gate trust model). `pub` so the daemon + the
    /// system-acceptance harness (separate crates) can drive it; it is NOT a WIT
    /// method, so a WASM guest cannot reach it (the frozen 3-method WIT).
    pub fn poll_host_pump(
        &self,
        sub_id: &SubscriptionId,
    ) -> Result<Option<RawEvent>, ChannelError> {
        let sub = self
            .lookup(sub_id)
            .ok_or_else(|| ChannelError::NotFound(format!("subscription {}", sub_id.as_str())))?;
        if sub.consumer != Consumer::HostPump {
            return Err(ChannelError::PermissionDenied(format!(
                "subscription {} is guest-consumed; not host-pumpable",
                sub_id.as_str()
            )));
        }
        Ok(sub.pop_event())
    }

    /// Push an event into a subscription's buffer. Missing subscription →
    /// `NotFound`. Buffer at cap → `BufferOverflow`.
    pub fn enqueue_event(
        &self,
        sub_id: &SubscriptionId,
        event: RawEvent,
    ) -> Result<(), ChannelError> {
        let sub = self
            .lookup(sub_id)
            .ok_or_else(|| ChannelError::NotFound(format!("subscription {}", sub_id.as_str())))?;
        sub.push_event(event)
    }

    /// Look up the `Arc<Subscription>` for a subscription id. Outer lock is
    /// dropped on return.
    pub fn lookup(&self, sub_id: &SubscriptionId) -> Option<Arc<Subscription>> {
        let subs = self.subs.read().unwrap_or_else(|e| e.into_inner());
        subs.get(sub_id).cloned()
    }

    /// Number of registered subscriptions (testing helper).
    pub fn subscription_count(&self) -> usize {
        self.subs.read().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// Attach (or replace) the HMAC webhook secret for a subscription. The
    /// webhook handler consults this when verifying inbound signatures.
    /// Missing subscription → `NotFound`. The mutation is in-place via the
    /// subscription's internal `RwLock<Option<SecretBytes>>`; holders of an
    /// `Arc<Subscription>` see the new secret on next `with_webhook_secret`
    /// call — no Arc swap, no stale-Arc data-loss race.
    pub fn set_webhook_secret(
        &self,
        sub_id: &SubscriptionId,
        secret: SecretBytes,
    ) -> Result<(), ChannelError> {
        let sub = self
            .lookup(sub_id)
            .ok_or_else(|| ChannelError::NotFound(format!("subscription {}", sub_id.as_str())))?;
        sub.set_webhook_secret_inner(secret);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AdapterType, ChannelConfig};

    fn config_for(adapter: AdapterType) -> ChannelConfig {
        ChannelConfig {
            adapter_type: adapter,
            params: vec![],
            outbound: None,
        }
    }

    #[test]
    fn subscribe_returns_fresh_id_per_call() {
        let mgr = SubscriptionManager::new();
        let a = mgr
            .subscribe("test-agent", config_for(AdapterType::Telegram))
            .unwrap();
        let b = mgr
            .subscribe("test-agent", config_for(AdapterType::Telegram))
            .unwrap();
        assert_ne!(a, b);
        assert_eq!(mgr.subscription_count(), 2);
    }

    #[test]
    fn subscribe_rejects_at_max_subscriptions_cap() {
        let mgr = SubscriptionManager::new();
        for _ in 0..MAX_SUBSCRIPTIONS {
            mgr.subscribe("test-agent", config_for(AdapterType::Webhook))
                .unwrap();
        }
        // The (MAX_SUBSCRIPTIONS+1)th subscribe must be rejected.
        let err = mgr
            .subscribe("test-agent", config_for(AdapterType::Webhook))
            .unwrap_err();
        match err {
            ChannelError::InvalidConfig(msg) => {
                assert!(msg.contains("subscription cap"));
            }
            other => panic!("expected InvalidConfig at cap, got {other:?}"),
        }
        assert_eq!(mgr.subscription_count(), MAX_SUBSCRIPTIONS);
    }

    #[test]
    fn subscribe_rejects_unknown_adapter_with_invalid_config() {
        let mgr = SubscriptionManager::new();
        let err = mgr
            .subscribe(
                "test-agent",
                config_for(AdapterType::Other("discord".into())),
            )
            .unwrap_err();
        match err {
            ChannelError::InvalidConfig(msg) => assert!(msg.contains("discord")),
            other => panic!("expected InvalidConfig, got {other:?}"),
        }
        assert_eq!(mgr.subscription_count(), 0);
    }

    #[test]
    fn poll_raw_returns_none_on_empty() {
        let mgr = SubscriptionManager::new();
        let id = mgr
            .subscribe("test-agent", config_for(AdapterType::Webhook))
            .unwrap();
        assert!(mgr.poll_raw("test-agent", &id).unwrap().is_none());
    }

    #[test]
    fn enqueue_then_poll_round_trips_event() {
        let mgr = SubscriptionManager::new();
        let id = mgr
            .subscribe("test-agent", config_for(AdapterType::Webhook))
            .unwrap();
        let event = RawEvent {
            data: b"hello".to_vec(),
            metadata: vec![],
        };
        mgr.enqueue_event(&id, event.clone()).unwrap();
        assert_eq!(mgr.poll_raw("test-agent", &id).unwrap(), Some(event));
        // FIFO drained.
        assert!(mgr.poll_raw("test-agent", &id).unwrap().is_none());
    }

    #[test]
    fn enqueue_unknown_subscription_returns_not_found() {
        let mgr = SubscriptionManager::new();
        let phantom = SubscriptionId::new();
        let err = mgr
            .enqueue_event(
                &phantom,
                RawEvent {
                    data: vec![],
                    metadata: vec![],
                },
            )
            .unwrap_err();
        assert!(matches!(err, ChannelError::NotFound(_)));
    }

    #[test]
    fn buffer_overflow_returned_at_cap() {
        let mgr = SubscriptionManager::new();
        let id = mgr
            .subscribe("test-agent", config_for(AdapterType::Webhook))
            .unwrap();
        // Fill the buffer to cap via the public push API (bounded path).
        for _ in 0..DEFAULT_BUFFER_CAP {
            mgr.enqueue_event(
                &id,
                RawEvent {
                    data: vec![],
                    metadata: vec![],
                },
            )
            .unwrap();
        }
        let err = mgr
            .enqueue_event(
                &id,
                RawEvent {
                    data: vec![],
                    metadata: vec![],
                },
            )
            .unwrap_err();
        assert!(matches!(err, ChannelError::BufferOverflow(_)));
    }

    #[test]
    fn secret_bytes_debug_is_redacted() {
        let s = SecretBytes::new(b"highly-secret-32-byte-padding-ok".to_vec()).unwrap();
        let dbg = format!("{s:?}");
        assert!(!dbg.contains("highly"));
        assert!(dbg.contains("REDACTED"));
    }

    #[test]
    fn secret_bytes_rejects_short_keys() {
        let err = SecretBytes::new(vec![]).unwrap_err();
        assert!(matches!(err, ChannelError::InvalidConfig(_)));
        let err = SecretBytes::new(b"too-short".to_vec()).unwrap_err();
        assert!(matches!(err, ChannelError::InvalidConfig(_)));
    }

    #[test]
    fn set_webhook_secret_preserves_buffered_events() {
        let mgr = SubscriptionManager::new();
        let id = mgr
            .subscribe("test-agent", config_for(AdapterType::Webhook))
            .unwrap();
        let event = RawEvent {
            data: b"pre-secret".to_vec(),
            metadata: vec![],
        };
        mgr.enqueue_event(&id, event.clone()).unwrap();
        mgr.set_webhook_secret(
            &id,
            SecretBytes::new(b"hunter2-padded-to-min-len-OK".to_vec()).unwrap(),
        )
        .unwrap();
        // Pre-existing event should survive secret attachment.
        assert_eq!(mgr.poll_raw("test-agent", &id).unwrap(), Some(event));
        // Secret is now attached.
        let sub = mgr.lookup(&id).unwrap();
        assert!(sub.has_webhook_secret());
    }

    // ── Phase-2 Step-3 two-drain single-owner (T6) ──

    #[test]
    fn wasmguest_sub_is_wit_pollable_not_host_pumpable() {
        let mgr = SubscriptionManager::new();
        let id = mgr
            .subscribe("a", config_for(AdapterType::Webhook))
            .unwrap();
        assert_eq!(mgr.lookup(&id).unwrap().consumer, Consumer::WasmGuest);
        // WIT poll_raw allowed; poll_host_pump rejected.
        assert!(mgr.poll_raw("a", &id).unwrap().is_none());
        let err = mgr.poll_host_pump(&id).unwrap_err();
        assert!(matches!(err, ChannelError::PermissionDenied(_)));
    }

    #[test]
    fn hostpump_sub_is_host_pumpable_not_wit_pollable() {
        let mgr = SubscriptionManager::new();
        let id = mgr
            .subscribe_host_pump("agent:default", config_for(AdapterType::Telegram))
            .unwrap();
        assert_eq!(mgr.lookup(&id).unwrap().consumer, Consumer::HostPump);
        // poll_host_pump allowed; WIT poll_raw rejected (single-owner).
        assert!(mgr.poll_host_pump(&id).unwrap().is_none());
        let err = mgr.poll_raw("agent:default", &id).unwrap_err();
        assert!(matches!(err, ChannelError::PermissionDenied(_)));
    }

    #[test]
    fn host_pump_drains_enqueued_event_without_ownership_gate() {
        let mgr = SubscriptionManager::new();
        let id = mgr
            .subscribe_host_pump("agent:default", config_for(AdapterType::Telegram))
            .unwrap();
        let ev = RawEvent {
            data: b"in".to_vec(),
            metadata: vec![],
        };
        mgr.enqueue_event(&id, ev.clone()).unwrap();
        // No caller_agent_id arg — host-trusted drain.
        assert_eq!(mgr.poll_host_pump(&id).unwrap(), Some(ev));
        assert!(mgr.poll_host_pump(&id).unwrap().is_none());
    }

    #[test]
    fn poll_host_pump_unknown_subscription_returns_not_found() {
        let mgr = SubscriptionManager::new();
        let phantom = SubscriptionId::new();
        assert!(matches!(
            mgr.poll_host_pump(&phantom).unwrap_err(),
            ChannelError::NotFound(_)
        ));
    }

    #[test]
    fn set_webhook_secret_no_arc_swap() {
        // A cloned Arc<Subscription> held BEFORE set_webhook_secret should
        // see the new secret AFTER the call — proves no Arc replacement,
        // no stale-Arc race.
        let mgr = SubscriptionManager::new();
        let id = mgr
            .subscribe("test-agent", config_for(AdapterType::Webhook))
            .unwrap();
        let early_arc = mgr.lookup(&id).unwrap();
        assert!(!early_arc.has_webhook_secret());
        mgr.set_webhook_secret(
            &id,
            SecretBytes::new(b"hunter2-padded-to-min-len-OK".to_vec()).unwrap(),
        )
        .unwrap();
        assert!(
            early_arc.has_webhook_secret(),
            "stale Arc must see the new secret (no Arc swap)"
        );
    }
}

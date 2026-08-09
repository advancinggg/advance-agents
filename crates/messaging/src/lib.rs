//! MODULE-006 messaging — slice A + slice B + slice C + slice D surface.
//!
//! Slice A ships:
//! - `Mailbox` bounded queue + `MailboxStore` registry (per-process)
//! - `MailboxDispatcherImpl` with hierarchy validation via `AgentTreeReader`
//!   (CONTRACT-040)
//! - `AgentActionDispatcherImpl` with `ActionValidator` gate (CONTRACT-113)
//!   + `EventBusRejectionSink` production emit adapter for AC-11
//!   `security.action_rejected` (CONTRACT-180)
//! - WIT 2-method `agent-messaging` interface declaration
//!
//! Slice B adds (AC-05/06/07/14):
//! - `MailboxDispatcher` extended to the §2.3 canonical 3 methods
//!   (`deliver`/`reply`/`notify_agent`); inherent `notify_channel`
//! - `IdentityResolver` (CONTRACT-151) + `UserChannelMapping` DTO
//! - `MessageTrace` (recipient-bound reply routing) + genuine
//!   `MessageOrigin` reply passthrough
//! - `NotifyError` (§2.3 canonical 4-variant) + `ChannelDelivery` hoisted
//!   to shared-types; `notify` WIT interface declared (host_fn deferred)
//! - `progress.rs` boundary helper + constants (helper/test tripwire only; AC-08 not claimed — gap is absent outbound agent-metadata carrier, not a flexible message-context map)
//! - `ChannelAdapterRegistry` internal seam
//!
//! Slice C adds (AC-13 infrastructure, AC stays untested):
//! - `MailboxDispatcherImpl::with_circuit_breaker_bus(bus)` opt-in builder +
//!   Layer-1 dispatcher CB query (CONTRACT-002 from MODULE-001) on all four
//!   target-reaching paths: `deliver` (with `MessageKind::Control` admin-
//!   bypass per M001 §1.4.4), `reply` (no bypass), and `deliver_notify`
//!   (covering `notify_agent` + `notify_channel`; PII-disciplined direct
//!   `NotifyError::CapabilityDenied("breaker_open")` construction)
//! - Layer-4 `Mailbox::recv`/`poll` freeze-flag consultation +
//!   `Mailbox::unfreeze` `notify_one` wake; `Mailbox::deliver` deliberately
//!   freeze-blind (preserves slice-A `t_a03c_freeze_toggle_observable`
//!   regression-lock)
//! - AC-13 (M006 circuit-breaker freeze): **passed** (Slice D BreakerSubscriber landed; historical 'STAYS untested' SUPERSEDED)
//!   (consume `CircuitBreakerBus::subscribe()` → match `BreakerEvent` records
//!   with `new_state == BreakerState::Open` / `Closed` and route per-agent
//!   to `Mailbox::freeze` / `unfreeze`). Layer 1 + Layer 4 mechanisms
//!   are production-eligible (pending caller integration). See MODULE-006
//!   §3.8 (f) for the two-layer rationale.
//!
//! Slice D adds (AC-09 + AC-13 end-to-end closure):
//! - `MailboxDispatcherImpl::with_event_bus(emitter: Arc<dyn EventBusEmit>)`
//!   opt-in builder + `pub fn emit_delivery_event(...)` free helper. ALL three
//!   target-reaching dispatcher entry points (`deliver`/`reply`/`deliver_notify`)
//!   capture `start = tokio::time::Instant::now()` at function entry and emit
//!   exactly ONE `msg.received` Event with `delivery_latency_ms` payload after
//!   successful `mb.deliver(...)`. M006 deliberately does NOT emit
//!   `mailbox.delivery_slow` — MODULE-019 EventBus owns the breach mirror per
//!   M019-AC-10 (already passed). See MODULE-006 §3.8 (h).
//! - `BreakerSubscriber::spawn(bus, store)` production driver consuming
//!   `CircuitBreakerBus::subscribe()`'s BreakerEvent stream with a three-state
//!   routing matrix (Open→freeze, Closed→unfreeze, HalfOpen→unfreeze for
//!   dispatcher-alignment). `impl Drop` aborts the spawned task on drop.
//!   Closes AC-13 end-to-end together with the slice-C Layer-1 gate. See
//!   MODULE-006 §3.8 (g).
//!
//! notify-agent host-fn slice (2026-06-13) adds:
//! - `host_fn.rs` — `NotifyAgentHandler` (`impl HostFunctionHandler`) bridging the
//!   WIT `notify-agent` call to `MailboxDispatcherImpl::notify_agent`, the
//!   `encode_notify_error` 4-variant lowering, bounded Val decoders, and
//!   `register_notify_host_fns` (capability `messaging`, namespace
//!   `advance:runtime/notify@0.1.0`, `idempotent: false`). Data-layer
//!   `HostRegistry` registration only — no WIT-world `import notify` (T42 intact).
//!   AC-02/AC-15 later **passed** (notify21 / Wave-20 production composition; historical untested SUPERSEDED): the wired e2e WIT witness (cli composition-root
//!   linker + `ctx.agent_id="system"` stamping) is a mainline-harvest follow-up.
//!
//! notify-channel host-fn (Wave-18 Lane-3, 2026-06-26) adds:
//! - `host_fn.rs` — `NotifyChannelHandler` + `register_notify_channel_host_fn`
//!   over the NEW narrow `ChannelNotifier` port (`dispatcher.rs`; additive,
//!   CONTRACT-051 byte-identical). Same data-layer-only registration posture as
//!   notify-agent. **production-wired** in cli (notify21; historical NOT-wired SUPERSEDED) — production notify
//!   was undeliverable under the colon/bare id residual historically; MODULE-006-AC-02 later
//!   **passed** (notify21; SUPERSEDED); proven callable + delivering in production + SUT
//!   (`crates/system-acceptance/tests/sys_j30_notify_channel.rs`).
//!
//! id-bridge building block (Wave-19 Lane-2, 2026-06-26) adds:
//! - `id_bridge.rs` — `AgentIdBridge`, an opt-in colon/bare equivalence-class
//!   resolver wired into `MailboxDispatcherImpl::deliver_notify` via
//!   `with_id_bridge` (default `None` → byte-identical). It closes the *membership*
//!   leg of the colon/bare residual (witnessed against the REAL `AgentTreeStore`),
//!   was DORMANT historically; production-wired later — MODULE-006-AC-02 **passed** (SUPERSEDED).
//!
//! **Deferred (historical — many items SUPERSEDED post-notify21 / Wave-20):**
//! - cli production wiring of notify: **LANDED** (notify21 / wiring.rs registers notify
//!   host_fns; AC-02/AC-15 **passed**). Remaining future work is unrelated polish only.
//! - WIT host_fn registration for agent-messaging `send`: **LANDED** (await-leg B-3;
//!   AC-01 callable **passed**)
//! - `await-replies` delegation + MODULE-007 reply-tracker host_fn: **LANDED** (AC-12 **passed**)
//! - IdentityResolver runtime-config bootstrap: **LANDED** (channels_boot production wiring)
//! - `MailboxReader` trait impl (invariant 3 restart persistence)
//! - AC-08: absent agent-authored outbound reply/action metadata carrier + zero production parse_progress callers (NOT a flexible message-context / WIT-ingress map — killed vs PRD §10.6)

pub mod action_dispatcher;
pub mod breaker_subscriber;
pub mod channel_registry;
pub mod dispatcher;
pub mod dynamic_routing;
pub mod error;
pub mod hierarchy;
pub mod host_fn;
pub mod id_bridge;
pub mod id_validation;
pub mod identity;
pub mod mailbox;
pub mod progress;
pub mod progress_envelope;
pub mod progress_source_lifecycle;
pub mod run_interrupt_sink;
pub mod trace;
pub mod turn_execution_boundary;

pub use action_dispatcher::{
    AgentActionDispatcherImpl, EventBusRejectionSink, OutboundActionSink, RejectionSink,
    RoutedOutboundActionSink, MAX_BATCH_SIZE,
};
pub use breaker_subscriber::BreakerSubscriber;
pub use channel_registry::{
    ChannelAdapterRegistry, EmptyChannelAdapterRegistry, StaticChannelAdapterRegistry,
    MAX_CHANNEL_ADAPTERS,
};
pub use dispatcher::{
    emit_delivery_event, ChannelNotifier, MailboxDispatcher, MailboxDispatcherImpl,
    TurnMailboxDispatchPort, EVENT_MSG_RECEIVED, MAX_NOTIFY_CHANNEL_PAYLOAD_BYTES,
};
pub use dynamic_routing::DynamicRouting;
pub use error::{DispatchError, MsgError, SecurityError};
pub use hierarchy::validate_routing;
pub use host_fn::{
    register_notify_channel_host_fn, register_notify_channel_host_fn_with_leak_detector,
    register_notify_host_fns, register_notify_host_fns_with_leak_detector, NotifyAgentHandler,
    NotifyChannelHandler, NOTIFY_CAPABILITY, NOTIFY_NAMESPACE,
};
pub use id_bridge::{AgentIdBridge, Resolved};
pub use id_validation::{is_safe_id, MAX_ID_BYTES};
pub use identity::{
    IdentityResolver, IdentityResolverError, UserChannelMapping, MAX_IDENTITY_MAPPINGS,
};
pub use mailbox::{
    Mailbox, MailboxStore, PreparedTurnBatch, TurnMailboxDelivery, DEFAULT_CAPACITY, MAX_MAILBOXES,
    MAX_METADATA_ENTRIES, MAX_METADATA_ENTRY_BYTES, MAX_PAYLOAD_BYTES,
};
pub use progress::{
    is_progress_key, validate_metadata_boundary, ProgressBoundaryError, PROGRESS_PHASE,
    PROGRESS_PREFIX, PROGRESS_SUMMARY, PROGRESS_VALUE,
};
pub use progress_envelope::{
    decode_routed_outbound, MAX_PROGRESS_BODY_BYTES, MAX_PROGRESS_ENVELOPE_BYTES,
    MAX_PROGRESS_METADATA_AGGREGATE_BYTES, MAX_PROGRESS_METADATA_ENTRIES,
    MAX_PROGRESS_METADATA_KEY_BYTES, MAX_PROGRESS_METADATA_VALUE_BYTES,
    PROGRESS_ENVELOPE_HEADER_BYTES, PROGRESS_ENVELOPE_MAGIC, PROGRESS_ENVELOPE_VERSION,
};
pub use progress_source_lifecycle::{
    stage_progress_route_provider, ProgressRouteDelivery, ProgressRouteDeliveryLease,
    ProgressRouteProviderParts, ProgressSourceCloser, ProgressSourceLifecycleError,
    MAX_PROGRESS_ROUTE_LIFECYCLES, MAX_PROGRESS_ROUTE_REFS_PER_SOURCE,
};
pub use run_interrupt_sink::MailboxRunInterruptSink;
pub use trace::{MessageTrace, DEFAULT_TRACE_TTL, MAX_TRACE_ENTRIES};
pub use turn_execution_boundary::{ProtectedTurnExecutionBoundary, TurnExecutionBoundaryImpl};

// Convenience re-exports from shared-types — consumers can pick these up
// from the messaging crate without a second use-statement.
// `MailboxReader` trait is NOT re-exported here; callers wanting it
// import from shared-types directly until a later slice ships the impl.
pub use advance_shared_types::mailbox::{
    AgentAction, AgentActionDispatcher, ChannelDelivery, Message, MessageContext, MessageKind,
    MessageOrigin, NotifyError,
};
pub use advance_shared_types::security_validator::ActionValidator;

//! `AwaitSessionManager` trait (CONTRACT-060) + concrete
//! `AwaitSessionManagerImpl`.
//!
//! Scope: admission + per-slot dispatch + oneshot-driven resolution
//! (slice m007-A), plus **AC-09 deadlock detection** and the **AC-10
//! per-session idle monitor** with a sync-`on_heartbeat` idle-clock reset
//! (this slice, m007-B). CONTRACT-060's trait surface is byte-identical to
//! slice-A — `on_heartbeat` stays sync with the same signature; the new
//! state lives on the struct + [`ManagerOptions`], not on the trait.
//!
//! **Wave-15 Lane A (2026-06-24)**: the manager emits `orchestration.*` events
//! via the optional injected [`ManagerOptions::event_emitter`]
//! (`EventBusEmit`): `deadlock_rejected` from the admission some-but-not-all
//! cycle triage (SYS-AC-169), and — via the spawned `idle_monitor_task` —
//! `await_idle_timeout` on the `ReturnPartial` idle resolution (SYS-AC-252).
//! These emit from async paths with NO `HostCallContext`, so they carry an
//! EMPTY `trace_id` + a session-stable envelope (caller `agent_id` +
//! `caller_run_id` + `SessionId`) — the `Event::observability()` precedent,
//! PRD §15.2-consistent (§15.2 forbids *conflating* trace_id with run_id across
//! an await span, NOT an empty trace_id). See MODULE-007 §3.8. `on_heartbeat`
//! itself still resets the idle clock with **no emit** (the `await_progress`
//! emit lives in the `HeartbeatHandler` host-fn boundary). **Wave-20: the other
//! 4 orchestration.* events (`await_started`/`await_satisfied`/
//! `await_session_closed`/`reply_late`) are now ALSO emitted from this manager
//! (admission / Completed-terminal / `close` / `on_reply` orphan paths), so all
//! 7 events emit in-boundary; AC-17 flips at SUMMARY.** When `event_emitter` is
//! `None` (the default) NO event is emitted (exact prior behavior).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::SystemTime;

use async_trait::async_trait;
use chrono::Utc;
use tokio::sync::{oneshot, Mutex, RwLock};

use advance_messaging::{
    is_safe_id, AgentIdBridge, MailboxDispatcher, PreparedTurnBatch, TurnMailboxDelivery,
    TurnMailboxDispatchPort,
};
use advance_shared_types::agent_tree::AgentTreeSnapshot;
use advance_shared_types::await_session::{
    AwaitMode, AwaitOptions, AwaitRequest, AwaitResult, AwaitSessionStatus, AwaitTreeSummary,
    OrchestrationError, ReplyResult, ReplyStatus, SessionId, SessionSummary,
};
// await-leg B-3 (2026-06-22): the `send` ingress (`handle_send`) builds an M006
// `Message` for the plain agent→agent fallback delivery + maps onto WIT `msg-error`.
use advance_shared_types::mailbox::{Message, MessageContext, MessageKind, MsgError};
use advance_shared_types::turn_attribution::{
    ActiveReplyClaimToken, ExactReplyRoute, QueuedTurnSpec, TurnCompletionOwner, TurnReplyError,
    TurnReplyRoutingPort,
};
// Wave-15 Lane A (2026-06-24): the in-boundary `orchestration.deadlock_rejected`
// emit sink (SYS-AC-169) + the idle-monitor's `await_idle_timeout` emitter.
use advance_shared_types::traits::EventBusEmit;

use crate::deadlock::{cycle_path, forms_cycle};
use crate::dispatch::dispatch_slots;
use crate::error::{
    classify_admission, classify_dispatch, format_per_slot_reason, AdmissionError,
    DispatchSlotError,
};
use crate::idle::idle_monitor_task;
#[cfg(any(test, feature = "test-helpers"))]
use crate::idle::resolve_idle;
use crate::session::{AwaitSession, RecordReplyError};
use crate::session_context::{compute_depth_in_map, SessionContextProvider};

tokio::task_local! {
    static CLAIMED_REPLY_SETTLEMENT: Arc<ClaimedReplySettlement>;
}

/// Cancellation-safe bridge between SendHandler's owned claim and the exact
/// AwaitSession mutation. The task-local scope ensures an unrelated concurrent
/// `on_reply` cannot settle this claim.
pub(crate) struct ClaimedReplySettlement {
    port: Arc<dyn TurnReplyRoutingPort>,
    token: std::sync::Mutex<Option<ActiveReplyClaimToken>>,
    delivery_started: std::sync::atomic::AtomicBool,
    slot_recorded: std::sync::atomic::AtomicBool,
    settled: std::sync::atomic::AtomicBool,
}

impl ClaimedReplySettlement {
    pub(crate) fn new(
        port: Arc<dyn TurnReplyRoutingPort>,
        token: ActiveReplyClaimToken,
    ) -> Arc<Self> {
        Arc::new(Self {
            port,
            token: std::sync::Mutex::new(Some(token)),
            delivery_started: std::sync::atomic::AtomicBool::new(false),
            slot_recorded: std::sync::atomic::AtomicBool::new(false),
            settled: std::sync::atomic::AtomicBool::new(false),
        })
    }

    pub(crate) fn begin_delivery(&self) -> Result<(), TurnReplyError> {
        let mut token = self
            .token
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let claim = token.as_ref().ok_or(TurnReplyError::AlreadyConsumed)?;
        match self.port.begin_reply_delivery(claim) {
            Ok(()) => {
                self.delivery_started
                    .store(true, std::sync::atomic::Ordering::Release);
                Ok(())
            }
            Err(error) => {
                if self
                    .port
                    .abort_reply(
                        claim,
                        advance_shared_types::turn_attribution::ReplyAbortProof::BeforeDelivery,
                    )
                    .is_ok()
                {
                    self.settled
                        .store(true, std::sync::atomic::Ordering::Release);
                    token.take();
                }
                Err(error)
            }
        }
    }

    fn mark_recorded_and_settle(&self) -> Result<(), TurnReplyError> {
        self.slot_recorded
            .store(true, std::sync::atomic::Ordering::Release);
        let token = self
            .token
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let token = token.as_ref().ok_or(TurnReplyError::AlreadyConsumed)?;
        self.port.settle_reply_accepted(token)?;
        self.settled
            .store(true, std::sync::atomic::Ordering::Release);
        Ok(())
    }

    pub(crate) fn settle_definite_rejection(&self) -> Result<(), TurnReplyError> {
        if self
            .slot_recorded
            .load(std::sync::atomic::Ordering::Acquire)
        {
            return Err(TurnReplyError::InvalidSettlement);
        }
        let token = self
            .token
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let token = token.as_ref().ok_or(TurnReplyError::AlreadyConsumed)?;
        self.port.settle_reply_not_accepted(token)?;
        self.settled
            .store(true, std::sync::atomic::Ordering::Release);
        Ok(())
    }

    pub(crate) fn slot_was_recorded(&self) -> bool {
        self.slot_recorded
            .load(std::sync::atomic::Ordering::Acquire)
    }

    /// Returns false only when exact cleanup could not be committed and this
    /// settlement must remain in a bounded host-owned retry latch.
    pub(crate) fn abandon(&self) -> bool {
        let mut token = self
            .token
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(claim) = token.as_ref() else {
            return true;
        };
        if self.settled.load(std::sync::atomic::Ordering::Acquire) {
            token.take();
            return true;
        }
        let cleanup = if self
            .delivery_started
            .load(std::sync::atomic::Ordering::Acquire)
        {
            self.port.abandon_reply(claim).map(|_| ())
        } else {
            self.port
                .abort_reply(
                    claim,
                    advance_shared_types::turn_attribution::ReplyAbortProof::BeforeDelivery,
                )
                .map(|_| ())
        };
        if cleanup.is_ok() {
            token.take();
            true
        } else {
            false
        }
    }
}

/// Per-caller in-flight session cap (default). Overridable per-call by
/// [`CapabilityConfig::max_inflight`]; absent that, this constant applies.
pub const MAX_INFLIGHT: usize = 3;

/// Default idle timeout (seconds) when `AwaitOptions.idle_timeout_secs` is
/// `None`. Matches PRD §9.2 / MODULE-007 §2.10 `await.idle_timeout_default_sec`.
pub const MAX_IDLE_TIMEOUT_DEFAULT_SEC: u32 = 600;

/// Maximum requests-list length per `start()` call (Adversarial round 1 C2).
/// Bounds the session's `expected.len()` / `received.len()`. Per PRD §9.2 the
/// typical fan-out is single-digit; 32 is a generous over-cap that prevents
/// multi-MB allocations from a single call.
pub const MAX_FANOUT: usize = 32;

/// Maximum `AwaitOptions.idle_timeout_secs` upper bound (Adversarial round 1 C3).
/// 3600 s = 1 h matches the §2.10 documented `await.idle_timeout_default_sec`
/// scale (default 600 s) and the AC-10 idle-monitor tick (5 s) — gives 720
/// monitor ticks before fire even at the max. Higher caps would allow a
/// caller to pin a session for arbitrary durations. A
/// [`CapabilityConfig::max_idle_timeout_secs`] knob can tighten this further
/// per-call (with a distinct discriminator reason).
pub const MAX_IDLE_TIMEOUT_SECS_CAP: u32 = 3600;

/// Global session cap across all callers (Adversarial round 1 W6). Belt-and-
/// suspenders defense in case caller-string-bypass (Adversarial C1) is
/// partially circumvented by some future code path. 1024 is high enough for
/// legitimate fan-out workloads (32 callers × 3 sessions × ~10× margin) and
/// low enough to bound memory under hostile load.
pub const MAX_SESSIONS_GLOBAL: usize = 1024;

/// Maximum payload bytes per `AgentAwaitRequest` slot (Adversarial round 3
/// C2). Bounds memory consumption when combined with
/// `MAX_FANOUT × MAX_INFLIGHT × MAX_SESSIONS_GLOBAL`. PRD §9.2 typical
/// agent-request payloads are kilobytes (JSON / binary), not megabytes; 64
/// KiB is a generous cap and matches MODULE-006 `MAX_PAYLOAD_BYTES`
/// precedent.
pub const MAX_PAYLOAD_BYTES: usize = 64 * 1024;

/// Maximum correlation_id / component_id / context-string length
/// (Adversarial round 3 W3/W4). Bounds string fields embedded into log
/// lines + WIT projection payloads. Matches `MAX_ID_BYTES` (256) from
/// MODULE-006 id_validation.
pub const MAX_OPAQUE_ID_BYTES: usize = 256;

/// Fine-grained `await-replies` capability admission knobs (PRD §1088-1112
/// `await-replies` capability YAML). Four in-boundary admission knobs are
/// honored this slice (REQ-092 code-progress); the 5th capability knob
/// `max-depth` needs the deferred nested-tree (AC-16, slice C) and is not
/// represented here. All-`None` (the [`Default`]) is fully unrestricted —
/// exact slice-A behavior. A `targets` membership check applies only to
/// **well-formed** targets (strip the `agent:` prefix → bare name; compare
/// against this bare-name allowlist); a malformed target (one that fails
/// `is_safe_id`) is NOT whole-call-denied — it falls through to the existing
/// per-slot dispatch invalid-target path (AC-07 preserved).
#[derive(Clone, Default)]
pub struct CapabilityConfig {
    /// Bare-name allowlist (`agent:` prefix stripped before compare). `None`
    /// → any target permitted. A well-formed target outside the list →
    /// whole-call `Err(CapabilityDenied)`.
    pub targets: Option<Vec<String>>,
    /// Maximum number of slots per `start()` call. `None` → only the
    /// crate-wide `MAX_FANOUT` security cap applies.
    pub max_fanout: Option<usize>,
    /// Per-caller concurrent-session cap; overrides
    /// [`ManagerOptions::max_inflight`] for this call when `Some`.
    pub max_inflight: Option<usize>,
    /// Tightens the accepted `AwaitOptions.idle_timeout_secs` ceiling below
    /// the crate-wide `MAX_IDLE_TIMEOUT_SECS_CAP`. A request exceeding this
    /// is rejected with the distinct discriminator reason
    /// `"capability:max-idle-timeout-exceeded"`.
    pub max_idle_timeout_secs: Option<u32>,
    /// **Slice-C addition (AC-18 5th knob)**: maximum allowed depth of the
    /// new session in the nested AwaitSession tree. The effective depth is
    /// computed as `compute_depth_in_map(sessions.read(), parent_session)
    /// + 1` (or 1 if no parent). A request whose prospective depth exceeds
    /// this cap is rejected with `OrchestrationError::CapabilityDenied(
    /// "capability:max-depth-exceeded")`. `None` → no depth limit (slice-B
    /// 4-knob behavior preserved). `Some(0)` is degenerate (rejects every
    /// session since the minimum depth is 1) — intentional pin behavior.
    ///
    /// **Adversarial round 2 W1 — compound DoS guidance**: a deployment with
    /// `max_depth = None` AND `max_inflight = Some(large_N)` (or `None`,
    /// taking the default `MAX_INFLIGHT=3`) leaves the in-boundary
    /// `compute_depth_in_map` parent-chain walk uncapped under
    /// `sessions.read()`. Under hostile load with a deep linked chain
    /// (ultimately bounded by `MAX_SESSIONS_GLOBAL=1024`), each admission
    /// walks the chain while holding the read lock, queuing terminal
    /// writers (`on_reply`/`close`/`resolve_idle`). For multi-tenant
    /// deployments, set `max_depth` to a small bound (e.g., 8-16)
    /// alongside `max_inflight` — they are complementary caps, not
    /// substitutes. See MODULE-007 §3.6 transient-dangling-parent +
    /// best-effort-max_depth residual entry.
    pub max_depth: Option<u32>,
}

/// Manager construction options. All-Arc fields so [`ManagerOptions`] is
/// `Clone`-able and can be shared across async paths. The added
/// `agent_tree` / `capability` fields default to "absent / unrestricted" so
/// `ManagerOptions::default()` preserves exact slice-A behavior.
#[derive(Clone)]
pub struct ManagerOptions {
    pub max_inflight: usize,
    pub idle_timeout_default_sec: u32,
    /// Coarse capability gate for `start()` admission. Returns `true` by
    /// default (`ManagerOptions::default()`); tests may inject a closure that
    /// returns `false` to exercise the [`AdmissionError::CapabilityDenied`]
    /// path. The finer-grained [`CapabilityConfig`] knobs run alongside this.
    pub cap_check: Arc<dyn Fn(&str) -> bool + Send + Sync>,
    /// Pluggable session-id factory. Default: `SessionId(uuid::Uuid::new_v4().to_string())`.
    /// Tests can inject deterministic factories.
    pub session_id_factory: Arc<dyn Fn() -> SessionId + Send + Sync>,
    /// Read-only agent-tree snapshot source for AC-09 deadlock detection.
    /// `None` (the default) → the deadlock gate is skipped entirely (exact
    /// slice-A behavior). When `Some`, `start()` runs the `parent_of`
    /// ancestry walk per agent target before any lock is acquired.
    pub agent_tree: Option<Arc<dyn AgentTreeSnapshot>>,
    /// Fine-grained `await-replies` capability config. Default: all-`None`
    /// (unrestricted) — exact slice-A admission behavior.
    pub capability: CapabilityConfig,
    /// **Slice-C addition (AC-16)**: dependency-inverted seam over M008
    /// `RunStateSync::current_session(caller_run_id)`. `None` (the default)
    /// → no parent_session linkage (slice-A/B behavior preserved — new
    /// sessions admit as roots). When `Some`, `start_with_run` queries
    /// this provider for the (caller_run_id) lookup and sets the new
    /// session's `parent_session` accordingly (with ghost-parent
    /// strict-promotion to None if the looked-up SessionId is not present in
    /// `sessions`).
    pub session_context: Option<Arc<dyn SessionContextProvider>>,
    /// **Wave-15 Lane A addition**: optional `EventBusEmit` sink for the
    /// in-boundary `orchestration.*` events emitted from the manager admission
    /// path (`deadlock_rejected`, SYS-AC-169) and the idle monitor
    /// (`await_idle_timeout`, SYS-AC-252). `None` (the default) → no event is
    /// emitted (exact prior behavior — every in-tree construction uses
    /// `..ManagerOptions::default()`, so this field is additive-safe). When
    /// `Some`, the manager clones it into the spawned `idle_monitor_task` and
    /// emits the deadlock event after admission. Sync `emit` (no `.await`), so
    /// no emit-under-lock hazard.
    pub event_emitter: Option<Arc<dyn EventBusEmit>>,
    /// **Wave-23 `perchild-daemon-1` (C1 fix)**: the colon/bare
    /// [`AgentIdBridge`] used SOLELY to stamp a genuine-send's `from` as the
    /// sender's CANONICAL colon id (see `AwaitSessionManagerImpl::canonical_sender`).
    /// `None` (the default) → the `from` stamp is the mechanical `agent:{source}`
    /// prefix (exact prior behavior). It is REQUIRED for a correct root→child send:
    /// the root is the sole special pair (`default-agent` ↔ `agent:default`), so the
    /// mechanical prefix would mis-stamp its `from` as `agent:default-agent` and fail
    /// the parent→child adjacency check in `validate_routing`. Every other agent's
    /// bare→colon mapping IS mechanical, so this is a no-op for them.
    pub id_bridge: Option<Arc<AgentIdBridge>>,
}

impl Default for ManagerOptions {
    fn default() -> Self {
        Self {
            max_inflight: MAX_INFLIGHT,
            idle_timeout_default_sec: MAX_IDLE_TIMEOUT_DEFAULT_SEC,
            cap_check: Arc::new(|_caller: &str| true),
            session_id_factory: Arc::new(|| SessionId(uuid::Uuid::new_v4().to_string())),
            agent_tree: None,
            capability: CapabilityConfig::default(),
            session_context: None,
            event_emitter: None,
            id_bridge: None,
        }
    }
}

/// CONTRACT-060 — the await-session manager surface. Concrete impl:
/// [`AwaitSessionManagerImpl`]. Consumed by the M006 `agent-messaging` host-fn
/// handlers (`AwaitRepliesHandler` / `HeartbeatHandler`, slice-E, in `host_fn.rs`)
/// and by MODULE-008 via the AwaitSessionRef read-only trait in shared-types.
#[async_trait]
pub trait AwaitSessionManager: Send + Sync {
    /// Admission + dispatch + await — returns when the session resolves.
    async fn start(
        &self,
        caller: &str,
        requests: Vec<AwaitRequest>,
        options: AwaitOptions,
    ) -> Result<AwaitResult, OrchestrationError>;

    /// Heartbeat from the WASM guest. Resets the session's idle clock (the
    /// in-boundary half of AC-10/§1.3.3) — locates the `liveness` record and
    /// refreshes `last_activity`; a no-op if the session is absent
    /// (already resolved/closed). **`on_heartbeat` itself emits no event** —
    /// the `orchestration.await_progress` emit lives in the `HeartbeatHandler`
    /// host-fn (slice-E, in-boundary; AC-12 passed — see MODULE-007 §1.5/§3.8).
    /// Sync because callers
    /// may invoke from hot paths (the `liveness` std-Mutex is held only for
    /// the O(1) reset, never across an `.await`).
    fn on_heartbeat(&self, session_id: &SessionId, agent_id: &str, progress: Option<String>);

    /// External close (cascade from pause-run / cancel-run / parent close).
    /// Idempotent: a closed session returns `Err(NotFound)` on the second
    /// call.
    async fn close(&self, session_id: &SessionId, reason: &str) -> Result<(), OrchestrationError>;

    /// Reply arrived from MODULE-006 for slot `slot` of `session_id`. Records
    /// the reply and, if `is_complete()`, resolves the session's oneshot.
    async fn on_reply(
        &self,
        session_id: &SessionId,
        slot: u32,
        reply: ReplyResult,
    ) -> Result<(), OrchestrationError>;
}

/// Internal session map value: the session itself plus the oneshot that
/// `start()` is awaiting. `pub(crate)` so the AC-10 idle module
/// ([`crate::idle`]) can name the shared `sessions` map type.
pub(crate) type SessionEntry = (
    AwaitSession,
    oneshot::Sender<Result<AwaitResult, OrchestrationError>>,
);

/// AC-10 per-session idle-clock record, held in the manager's `liveness`
/// index (a `std::sync::Mutex`-guarded map keyed by [`SessionId`]).
///
/// `last_activity` is a [`tokio::time::Instant`] (NOT `std::time::Instant`):
/// the idle monitor's `tokio::time::sleep` is virtual under tokio
/// `start_paused`, and `tokio::time::Instant::elapsed()` is likewise
/// clock-aware (real time in prod; driven by `tokio::time::advance()` under
/// `start_paused`), so the monitor tick and the elapsed comparison stay
/// virtual-time-consistent. (Slice-A `AwaitSession.created_at`/
/// `last_activity` stay `std::time::Instant` per MODULE-007 §2.5 —
/// record-only; the idle monitor does not read them; this `liveness` index
/// is the authoritative idle clock. There is **no `trace_id` field** — the
/// Wave-15 in-boundary orchestration emits carry an EMPTY `trace_id` (no
/// per-session trace stored; correlation is via session_id/run_id — see
/// `events.rs` + MODULE-007 §3.8), so the idle clock needs none.)
pub(crate) struct LivenessRec {
    pub(crate) last_activity: tokio::time::Instant,
    pub(crate) idle_timeout_secs: u32,
}

/// Helper: decrement `per_caller_count[caller]`; remove the entry entirely
/// when count reaches 0 (Adversarial round 2 W5 — prevents unbounded
/// HashMap growth in long-running deployments with sliding-window caller
/// ids). `pub(crate)` so [`crate::idle::resolve_idle`] (the promoted
/// idle-resolution body) shares this one decrement implementation.
pub(crate) async fn decrement_caller_count(
    map: &tokio::sync::Mutex<std::collections::HashMap<String, usize>>,
    caller: &str,
) {
    let mut counts = map.lock().await;
    let should_remove = match counts.get_mut(caller) {
        Some(n) if *n <= 1 => true,
        Some(n) => {
            *n -= 1;
            false
        }
        None => false,
    };
    if should_remove {
        counts.remove(caller);
    }
}

/// Validate that an opaque id (correlation_id, component_id) is safe for
/// embedding into log lines + WIT projection payloads (Adversarial round 3
/// W3/W4). Rules:
/// - non-empty
/// - length ≤ `MAX_OPAQUE_ID_BYTES` (256)
/// - ASCII alphanumeric + `_-.` (matches MODULE-006 `is_safe_id` body charset
///   plus `.` which is common in correlation ids like `2026-05-18T22:30.001`)
fn is_safe_opaque_id(s: &str) -> bool {
    if s.is_empty() || s.len() > MAX_OPAQUE_ID_BYTES {
        return false;
    }
    s.bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}

/// Strip a leading canonical `agent:` prefix, yielding the bare agent-name
/// body used as the `parent_of` / capability-allowlist key. A string without
/// the prefix is returned unchanged (callers only invoke this on targets
/// already validated by `is_safe_id`, so the only well-formed shapes are
/// `agent:<body>` or — for the caller — a bare body).
fn bare_agent_name(id: &str) -> &str {
    id.strip_prefix("agent:").unwrap_or(id)
}

/// Sanitize a caller-controlled string for embedding into an
/// `OrchestrationError::InvalidRequest` reason (Adversarial round 3 W5).
/// Strips ASCII control chars + bounds length at `MAX_REASON_LEN` (256
/// chars). Matches the discipline applied by `format_per_slot_reason`.
fn sanitize_for_error(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_ascii_control())
        .take(crate::error::MAX_REASON_LEN)
        .collect()
}

/// Canonical kebab form of an [`AwaitMode`] for the Wave-20 `await_started` /
/// `await_satisfied` event payloads (`"all-of"` / `"any-of"`).
fn await_mode_kebab(mode: AwaitMode) -> &'static str {
    match mode {
        AwaitMode::AllOf => "all-of",
        AwaitMode::AnyOf => "any-of",
    }
}

/// AC-13 rule (1) winner task-id (Wave-20; NOT PRD rule 1): the task-id under which a slot was
/// awaited — read from the originating `AgentAwaitRequest.context.task_id`.
/// `ComponentFinished` slots carry no context, so they have no task-id. Used at
/// the `on_reply` chokepoint to preserve the winner's task-id on its recorded
/// `ReplyResult` (host-internal preservation; Wave-23 wit-widening also exposes it
/// guest-side via the WIT `reply-result.task-id` — MODULE-007 §3.6/§3.7).
fn await_request_task_id(req: &AwaitRequest) -> Option<String> {
    match req {
        AwaitRequest::AgentRequest(r) => r.context.as_ref().and_then(|c| c.task_id.clone()),
        AwaitRequest::ComponentFinished(_) => None,
    }
}

/// Concrete CONTRACT-060 implementation. Implements admission + per-slot
/// dispatch + oneshot resolution (slice-A), AC-09 deadlock detection, and
/// the AC-10 per-session idle monitor with a sync-`on_heartbeat` idle-clock
/// reset. Fiber path later **passed** Wave-16 (AC-08/14); historical 'future slice' SUPERSEDED. **Wave-15 Lane A**: when
/// [`ManagerOptions::event_emitter`] is `Some`, the admission path emits
/// `orchestration.deadlock_rejected` (SYS-AC-169) and the spawned idle monitor
/// emits `orchestration.await_idle_timeout` (SYS-AC-252); `None` (default) →
/// no emit (see the module doc + MODULE-007 §3.8).
///
/// `sessions` / `per_caller_count` are `Arc`-wrapped so the spawned
/// `idle_monitor_task` can hold cloned handles without an `Arc<Self>`
/// (`start(&self)` has none); the `Arc` derefs transparently so slice-A
/// bodies are unchanged. `liveness` is the authoritative AC-10 idle clock.
pub struct AwaitSessionManagerImpl {
    sessions: Arc<RwLock<HashMap<SessionId, SessionEntry>>>,
    dispatcher: Arc<dyn MailboxDispatcher>,
    options: ManagerOptions,
    per_caller_count: Arc<Mutex<HashMap<String, usize>>>,
    turn_mailbox_dispatch: Option<Arc<dyn TurnMailboxDispatchPort>>,
    turn_batches: Arc<std::sync::Mutex<HashMap<SessionId, PreparedTurnBatch>>>,
    /// AC-10 idle clock. `std::sync::Mutex` (not `tokio::sync::Mutex`)
    /// because `on_heartbeat` is sync; held only for O(1) map ops, never
    /// across an `.await`. Poison-tolerant at every lock site.
    liveness: Arc<std::sync::Mutex<HashMap<SessionId, LivenessRec>>>,
    /// Wave-24 `req270-sink` — test-only counter of `resolve_component_finished`
    /// ENTRIES. Witnesses the `ComponentResolutionSink::on_run_completed` colon
    /// short-circuit: a colon `task_id` never enters the resolver (0), a colon-free
    /// non-match spawns + enters it (1). cfg-gated, so a production build carries
    /// neither the field nor its increment (zero cost).
    #[cfg(any(test, feature = "test-helpers"))]
    resolve_attempts: std::sync::atomic::AtomicUsize,
}

impl AwaitSessionManagerImpl {
    pub fn new(dispatcher: Arc<dyn MailboxDispatcher>, options: ManagerOptions) -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            dispatcher,
            options,
            per_caller_count: Arc::new(Mutex::new(HashMap::new())),
            turn_mailbox_dispatch: None,
            turn_batches: Arc::new(std::sync::Mutex::new(HashMap::new())),
            liveness: Arc::new(std::sync::Mutex::new(HashMap::new())),
            #[cfg(any(test, feature = "test-helpers"))]
            resolve_attempts: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    pub fn with_turn_mailbox_dispatch(
        mut self,
        turn_mailbox_dispatch: Arc<dyn TurnMailboxDispatchPort>,
    ) -> Self {
        self.turn_mailbox_dispatch = Some(turn_mailbox_dispatch);
        self
    }

    /// AC-10: evict a session's idle-clock record. Called on EVERY terminal
    /// path (on_reply is_complete, early_resolve, all_failed, close,
    /// resolve_idle) so `absence ⟺ resolved/closed` — the spawned
    /// `idle_monitor_task` exits on the next tick when the id is absent.
    /// Poison-tolerant; `remove` is idempotent (no-op if already gone, e.g.
    /// the monitor's claim already removed it). No `.await` inside.
    fn evict_liveness(&self, sid: &SessionId) {
        self.liveness
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(sid);
    }

    /// AC-10: reset a session's idle clock to "now" if the record is still
    /// present (a no-op when absent — the session already resolved/closed).
    /// Shared by `on_heartbeat` and `on_reply`'s open-keeping path. **No
    /// event is emitted.** Poison-tolerant; no `.await` inside.
    fn reset_liveness(&self, sid: &SessionId) {
        if let Some(rec) = self
            .liveness
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_mut(sid)
        {
            rec.last_activity = tokio::time::Instant::now();
        }
    }

    /// Wave-23 `perchild-daemon-1` (C1 fix): stamp a genuine-send's `from` as the
    /// sender's CANONICAL colon id. For every agent whose bare→colon mapping is
    /// mechanical this is exactly `agent:{source}` (byte-identical to the pre-fix
    /// prefix). The ROOT is the sole special pair — bare `default-agent` ↔ colon
    /// `agent:default` (NOT `agent:default-agent`) — so a naive prefix would
    /// mis-stamp the root's `from` and break the parent→child adjacency check in
    /// `validate_routing` (the child's registered colon parent is `agent:default`).
    /// When an [`AgentIdBridge`] is injected AND `source` is a member (the root seed
    /// pair + every runtime-registered child), resolve to its canonical
    /// `mailbox_key`; otherwise fall back to the mechanical prefix (no bridge / a
    /// non-member → identical to prior behavior).
    fn canonical_sender(&self, source: &str) -> String {
        self.options
            .id_bridge
            .as_ref()
            .and_then(|b| b.resolve_owned(source).map(|(_, mailbox)| mailbox))
            .unwrap_or_else(|| {
                if source.starts_with("agent:") || source == "system" {
                    source.to_string()
                } else {
                    format!("agent:{source}")
                }
            })
    }

    fn canonical_turn_target(&self, target: &str) -> Option<String> {
        self.options
            .id_bridge
            .as_ref()
            .and_then(|bridge| bridge.resolve_owned(target).map(|(_, mailbox)| mailbox))
            .or_else(|| target.starts_with("agent:").then(|| target.to_string()))
    }

    fn dispatch_protected_slots(
        &self,
        port: &dyn TurnMailboxDispatchPort,
        caller: &str,
        requests: &[AwaitRequest],
        session_id: &SessionId,
        deadlock_slots: &std::collections::HashSet<usize>,
    ) -> Vec<Result<(), DispatchSlotError>> {
        let parent_agent = self.canonical_sender(caller);
        let mut results: Vec<Option<Result<(), DispatchSlotError>>> =
            std::iter::repeat_with(|| None)
                .take(requests.len())
                .collect();
        let mut delivery_slots = Vec::new();
        let mut deliveries = Vec::new();
        for (slot, request) in requests.iter().enumerate() {
            match request {
                AwaitRequest::ComponentFinished(_) => results[slot] = Some(Ok(())),
                AwaitRequest::AgentRequest(request) if deadlock_slots.contains(&slot) => {
                    results[slot] = Some(Err(DispatchSlotError::Deadlock(request.target.clone())));
                }
                AwaitRequest::AgentRequest(request) if !is_safe_id(&request.target) => {
                    results[slot] = Some(Err(DispatchSlotError::InvalidTarget(
                        request.target.clone(),
                    )));
                }
                AwaitRequest::AgentRequest(request) => {
                    let Some(canonical_target) = self.canonical_turn_target(&request.target) else {
                        results[slot] = Some(Err(DispatchSlotError::InvalidTarget(
                            request.target.clone(),
                        )));
                        continue;
                    };
                    let turn_id = format!("session:{}:slot:{slot}", session_id.0);
                    let context = MessageContext {
                        task_id: request.context.as_ref().and_then(|ctx| ctx.task_id.clone()),
                        run_id: request.context.as_ref().and_then(|ctx| ctx.run_id.clone()),
                        execution_id: request
                            .context
                            .as_ref()
                            .and_then(|ctx| ctx.execution_id.clone()),
                        trace_id: request
                            .context
                            .as_ref()
                            .and_then(|ctx| ctx.trace_id.clone()),
                        in_reply_to: Some(turn_id.clone()),
                        correlation_id: Some(request.correlation_id.clone()),
                    };
                    deliveries.push(TurnMailboxDelivery {
                        target: canonical_target.clone(),
                        message: Message {
                            id: turn_id.clone(),
                            kind: MessageKind::Agent,
                            from: parent_agent.clone(),
                            to: canonical_target.clone(),
                            payload: request.payload.clone(),
                            context: Some(context.clone()),
                            timestamp: SystemTime::now(),
                            origin: None,
                        },
                        spec: QueuedTurnSpec {
                            turn_id,
                            expected_agent: canonical_target,
                            parent_agent: parent_agent.clone(),
                            session_id: session_id.clone(),
                            slot: slot as u32,
                            completion_owner: TurnCompletionOwner::AwaitSession,
                            original_task_id: context.task_id,
                            original_run_id: context.run_id,
                            original_reply_to: Some(parent_agent.clone()),
                        },
                    });
                    delivery_slots.push(slot);
                }
            }
        }

        if deliveries.is_empty() {
            return results
                .into_iter()
                .map(|result| {
                    result.unwrap_or_else(|| {
                        Err(DispatchSlotError::CapabilityDenied(
                            "turn-state-conflict".into(),
                        ))
                    })
                })
                .collect();
        }

        let batch = port.prepare_turn_batch(deliveries);
        for (delivery_index, outcome) in batch.outcomes().iter().enumerate() {
            let slot = delivery_slots[delivery_index];
            let target = match &requests[slot] {
                AwaitRequest::AgentRequest(request) => request.target.as_str(),
                AwaitRequest::ComponentFinished(_) => "component",
            };
            results[slot] = Some(
                outcome
                    .clone()
                    .map_err(|error| classify_dispatch(error, target)),
            );
        }
        if batch.registered_turns().is_empty() {
            return results
                .into_iter()
                .map(|result| {
                    result.unwrap_or_else(|| {
                        Err(DispatchSlotError::CapabilityDenied(
                            "turn-state-conflict".into(),
                        ))
                    })
                })
                .collect();
        }
        let mut batches = self
            .turn_batches
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if batches.contains_key(session_id) {
            for slot in delivery_slots.iter().copied() {
                if results[slot].as_ref().is_some_and(Result::is_ok) {
                    results[slot] = Some(Err(DispatchSlotError::CapabilityDenied(
                        "turn-state-conflict".into(),
                    )));
                }
            }
            return results
                .into_iter()
                .map(|result| {
                    result.unwrap_or_else(|| {
                        Err(DispatchSlotError::CapabilityDenied(
                            "turn-state-conflict".into(),
                        ))
                    })
                })
                .collect();
        }
        batches.insert(session_id.clone(), batch);
        let publish_error = {
            let batch = batches.get_mut(session_id).expect("batch inserted");
            port.publish_prepared(batch).err()
        };
        if let Some(error) = publish_error {
            for slot in delivery_slots.iter().copied() {
                if results[slot].as_ref().is_some_and(Result::is_ok) {
                    let target = match &requests[slot] {
                        AwaitRequest::AgentRequest(request) => request.target.as_str(),
                        AwaitRequest::ComponentFinished(_) => "component",
                    };
                    results[slot] = Some(Err(classify_dispatch(error.clone(), target)));
                }
            }
            let failed_batch = batches.remove(session_id);
            drop(batches);
            drop(failed_batch);
        }
        results
            .into_iter()
            .map(|result| {
                result.unwrap_or_else(|| {
                    Err(DispatchSlotError::CapabilityDenied(
                        "turn-state-conflict".into(),
                    ))
                })
            })
            .collect()
    }

    fn detach_session_turns(&self, session_id: &SessionId) {
        let Some(port) = self.turn_mailbox_dispatch.as_ref() else {
            return;
        };
        let batch = self
            .turn_batches
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(session_id);
        if let Some(mut batch) = batch {
            // Any failure is retained by PreparedTurnBatch's bounded RAII
            // recovery latch when this local owner drops.
            let _result = port.detach_turn_batch(session_id, &mut batch);
        }
    }

    /// Backbone Step 4b (2026-06-08) — BEST-EFFORT sync existence query backing
    /// the production `AwaitSessionRef::exists` impl (in `await_session_ref.rs`).
    /// `sessions` is an async `tokio::RwLock` but `AwaitSessionRef::exists` is a
    /// SYNC trait method, so this uses `try_read()`: under writer contention it
    /// returns `false` conservatively (the faithful sync-shadow-index design is
    /// deferred — see MODULE-007 §3.6). NOT on any witnessed path (only
    /// `RunManager::run_status`'s await-tree projection consumes it, best-effort
    /// during a live suspension). Keeps `sessions` private to this module.
    pub(crate) fn exists_best_effort(&self, sid: &SessionId) -> bool {
        match self.sessions.try_read() {
            Ok(map) => map.contains_key(sid),
            Err(_) => false,
        }
    }

    /// Backbone Step 4b (2026-06-08) — BEST-EFFORT sync tree summary backing the
    /// production `AwaitSessionRef::walk_tree` impl. Returns `None` when the
    /// session is absent OR under writer contention (`try_read` fails). Best-
    /// effort, single-session summary (the full subtree walk is the deferred
    /// faithful sync-shadow-index design — MODULE-007 §3.6); NOT on any witnessed
    /// path.
    pub(crate) fn walk_tree_best_effort(&self, sid: &SessionId) -> Option<AwaitTreeSummary> {
        let map = self.sessions.try_read().ok()?;
        let (session, _) = map.get(sid)?;
        let received = session.received.iter().filter(|r| r.is_some()).count() as u32;
        let expected = session.expected.len() as u32;
        let summary = SessionSummary {
            session_id: session.id.0.clone(),
            parent_session_id: session.parent_session.as_ref().map(|p| p.0.clone()),
            agent_id: session.agent_id.clone(),
            mode: match session.options.mode {
                AwaitMode::AllOf => "all-of".to_string(),
                AwaitMode::AnyOf => "any-of".to_string(),
            },
            expected,
            received,
            status: match session.status {
                crate::session::SessionStatus::Open => "open",
                crate::session::SessionStatus::Completed => "completed",
                crate::session::SessionStatus::TimedOut => "timed-out",
                crate::session::SessionStatus::Cancelled => "cancelled",
            }
            .to_string(),
        };
        Some(AwaitTreeSummary {
            depth: 1,
            total_sessions: 1,
            pending_replies: expected.saturating_sub(received),
            sessions: vec![summary],
        })
    }

    /// Test-only: returns the SessionId of the single currently-open session.
    /// Panics if zero or >1 sessions are open. Used by T02c to obtain the
    /// id of a session spawned in a `tokio::spawn` task.
    ///
    /// **Adversarial round 2 C2/W6 fix**: gated behind the `test-helpers`
    /// feature flag so this method does NOT ship in release builds. Cargo
    /// test enables the feature via `required-features = ["test-helpers"]`
    /// on each integration test target.
    #[doc(hidden)]
    #[cfg(any(test, feature = "test-helpers"))]
    pub async fn first_open_session_id_for_test(&self) -> SessionId {
        let sessions = self.sessions.read().await;
        assert_eq!(
            sessions.len(),
            1,
            "first_open_session_id_for_test expects exactly 1 open session, found {}",
            sessions.len()
        );
        sessions.keys().next().cloned().expect("non-empty")
    }

    /// Test-only: simulate the idle-monitor's call into the manager when the
    /// idle timeout elapses. Retained as a thin wrapper delegating to the
    /// promoted real [`crate::idle::resolve_idle`] body so slice-A
    /// `tests/timeout_policy.rs` (T05a/T05b) stays byte-green — liveness
    /// eviction inside `resolve_idle` is remove-tolerant, so the slice-A
    /// observable behavior (ReturnPartial → `Ok(PartialTimeout)`; Fail →
    /// `Err(IdleTimeoutExceeded)`) is identical.
    ///
    /// **Adversarial round 2 C2 fix**: gated behind the `test-helpers`
    /// feature flag so this method does NOT ship in release builds.
    #[doc(hidden)]
    #[cfg(any(test, feature = "test-helpers"))]
    pub async fn on_idle_timeout_for_test(&self, session_id: &SessionId) {
        // Wave-15 Lane A: read the effective idle timeout from the liveness rec
        // (still present until `resolve_idle` evicts it) for the
        // `await_idle_timeout` event's `idle_seconds` payload; pass the manager's
        // emitter so the test hook exercises the same emit path as the monitor.
        let idle_secs = self
            .liveness
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(session_id)
            .map(|r| r.idle_timeout_secs)
            .unwrap_or(0);
        resolve_idle(
            Arc::clone(&self.sessions),
            Arc::clone(&self.per_caller_count),
            Arc::clone(&self.liveness),
            self.turn_mailbox_dispatch.clone(),
            Arc::clone(&self.turn_batches),
            session_id.clone(),
            self.options.event_emitter.clone(),
            idle_secs,
        )
        .await;
    }

    /// Slice-C non-trait entry point for nested AwaitSession tree linkage
    /// (AC-16). CONTRACT-060::start delegates to `start_with_run(caller,
    /// None, ...)`, preserving slice-A/B admission-time-root behavior. The
    /// M006 `await-replies` host-fn handler (slice-E/await-leg B-2) calls this
    /// (via `start_with_run_and_session`) with the actual `caller_run_id` from
    /// the Wasmtime store / host-fn state — Wave-15 also uses that `caller_run_id`
    /// for the `await_idle_timeout` event envelope.
    ///
    /// **Parent_session resolution (slice-C, AC-16)**: when both
    /// [`ManagerOptions::session_context`] is `Some` AND `caller_run_id`
    /// is `Some`, the provider is queried for `current_session(run_id)`.
    /// If the returned SessionId is present in `sessions`, it becomes the
    /// new session's `parent_session`. **Ghost-parent strict-promotion**:
    /// if the lookup yields a SessionId NOT present in `sessions` (e.g.,
    /// the parent terminated concurrently), the new session is admitted as
    /// a top-level root (`parent_session=None`) rather than carrying a
    /// dangling reference.
    ///
    /// **`max_depth` admission gate (slice-C, AC-18)**: when
    /// [`CapabilityConfig::max_depth`] is `Some(d)`, the prospective new
    /// depth (= `compute_depth_in_map(sessions.read(), parent_session) + 1`,
    /// or 1 if no parent) is checked against `d`; an exceeding request is
    /// rejected with `OrchestrationError::CapabilityDenied(
    /// "capability:max-depth-exceeded")`.
    pub async fn start_with_run(
        &self,
        caller: &str,
        caller_run_id: Option<&str>,
        requests: Vec<AwaitRequest>,
        options: AwaitOptions,
    ) -> Result<AwaitResult, OrchestrationError> {
        // Slice-A/B/C/D/E surface preserved byte-identical: delegate to the
        // Backbone Step-4b inner with NO pre-minted session id and NO on_park
        // hook (exact prior behaviour — the factory mints the id, no suspend).
        self.start_with_run_inner(None, None, caller, caller_run_id, requests, options)
            .await
    }

    /// Backbone Step 4b (2026-06-08) — run-scoped entry that accepts a
    /// CALLER-MINTED `SessionId` and an `on_park` hook. The await-replies
    /// host-fn (`AwaitRepliesHandler`) uses this to suspend the M008 Run at the
    /// genuine park point: it mints the session id (so it can `suspend_run` with
    /// it BEFORE this call parks), then passes an `on_park` closure that fires
    /// `RunManager::suspend_run` immediately before the `rx.await` park — ONLY on
    /// the genuine-park path (after the synchronous `early_resolve`/`all_failed`
    /// fast-path returns are ruled out), so no phantom `run.suspended` fires on a
    /// fan-out that resolves without parking. Non-trait (CONTRACT-060::start +
    /// `start_with_run` surfaces stay byte-identical). `modified_contracts = []`.
    pub async fn start_with_run_and_session(
        &self,
        session_id: SessionId,
        caller: &str,
        caller_run_id: Option<&str>,
        requests: Vec<AwaitRequest>,
        options: AwaitOptions,
        on_park: Option<Box<dyn FnOnce() + Send>>,
    ) -> Result<AwaitResult, OrchestrationError> {
        self.start_with_run_inner(
            Some(session_id),
            on_park,
            caller,
            caller_run_id,
            requests,
            options,
        )
        .await
    }

    /// Backbone Step 4b inner: the slice-A..E `start_with_run` body, generalized
    /// over an optional pre-minted `session_id_override` (None → the
    /// `session_id_factory` mints, as before) and an optional `on_park` hook
    /// fired immediately before the genuine `rx.await` park.
    async fn start_with_run_inner(
        &self,
        session_id_override: Option<SessionId>,
        on_park: Option<Box<dyn FnOnce() + Send>>,
        caller: &str,
        caller_run_id: Option<&str>,
        requests: Vec<AwaitRequest>,
        options: AwaitOptions,
    ) -> Result<AwaitResult, OrchestrationError> {
        // ── Admission ────────────────────────────────────────────────
        // (Adversarial round 1 fixes C1, C2, C3, W6, W8.)

        // C1: validate caller is a safe id-body. The runtime stamps caller as
        // a bare name (`"researcher"`); we validate by prepending `agent:` and
        // running `is_safe_id`. This rejects empty / multi-colon / non-ASCII /
        // newline-injection / oversize caller strings that would otherwise
        // partition `per_caller_count` indefinitely.
        if !is_safe_id(&format!("agent:{caller}")) {
            return Err(classify_admission(AdmissionError::InvalidRequest(
                "caller is not a safe agent id body".to_string(),
            )));
        }
        if requests.is_empty() {
            return Err(classify_admission(AdmissionError::InvalidRequest(
                "empty requests".to_string(),
            )));
        }
        // C2: bound the fan-out so a single call can't allocate gigabytes via
        // a multi-million-slot requests vec.
        if requests.len() > MAX_FANOUT {
            return Err(classify_admission(AdmissionError::InvalidRequest(format!(
                "requests.len() > MAX_FANOUT ({MAX_FANOUT})"
            ))));
        }
        // **Adversarial round 3 C2/W3/W4 fix**: per-request size + id-charset
        // validation. Bounds payload memory amplification and prevents
        // newline / control-char injection into log lines via opaque ids.
        for (idx, req) in requests.iter().enumerate() {
            match req {
                AwaitRequest::AgentRequest(agent_req) => {
                    if agent_req.payload.len() > MAX_PAYLOAD_BYTES {
                        return Err(classify_admission(AdmissionError::InvalidRequest(format!(
                            "slot {idx} payload.len() > MAX_PAYLOAD_BYTES ({MAX_PAYLOAD_BYTES})"
                        ))));
                    }
                    if !is_safe_opaque_id(&agent_req.correlation_id) {
                        return Err(classify_admission(AdmissionError::InvalidRequest(format!(
                            "slot {idx} correlation_id is not a safe opaque id"
                        ))));
                    }
                }
                AwaitRequest::ComponentFinished(comp_req) => {
                    if !is_safe_opaque_id(&comp_req.component_id) {
                        return Err(classify_admission(AdmissionError::InvalidRequest(format!(
                            "slot {idx} component_id is not a safe opaque id"
                        ))));
                    }
                    if !is_safe_opaque_id(&comp_req.correlation_id) {
                        return Err(classify_admission(AdmissionError::InvalidRequest(format!(
                            "slot {idx} correlation_id is not a safe opaque id"
                        ))));
                    }
                }
            }
        }
        // C2b — single-pending-target constraint (await-leg B-4a, 2026-06-22):
        // the code-mandated B-4 ACTIVATION prerequisite (see the `try_route_reply`
        // residual rustdoc) closing the B-3 routing ambiguity. A child's `send`
        // reply carries NO correlation-id, so an owner holding ≥2 OPEN slots for the
        // SAME source agent could mis-route the deterministic oldest/lowest pick.
        // Reject an admission whose AgentRequest slots DUPLICATE a bare-agent target.
        // Gated to the EXACT `try_route_reply` population (`is_safe_id(target) &&
        // target.starts_with("agent:")`): malformed / `user:` / `system` /
        // `ComponentFinished` slots are NOT compared — preserving the AC-07 malformed
        // per-slot fall-through. The `agent:`-prefix gate (NOT `bare_agent_name`, which
        // strips ONLY `agent:`) is what prevents a false `user:x` == `agent:x`
        // collision: a `user:`/`system` target never enters the dedup set, so it is
        // never compared against an `agent:x` slot. This closes the
        // INTRA-call case structurally; the CROSS-session same-source case is
        // unreachable on the activated single-controller serve path (`on_reply`
        // removes a session before firing its resume oneshot, so a fiber advances to
        // its next await only after the prior session is gone — see MODULE-007 §2.7).
        {
            let mut seen_targets: std::collections::HashSet<&str> =
                std::collections::HashSet::new();
            for req in &requests {
                if let AwaitRequest::AgentRequest(a) = req {
                    if is_safe_id(&a.target) && a.target.starts_with("agent:") {
                        let bare = bare_agent_name(&a.target);
                        if !seen_targets.insert(bare) {
                            return Err(classify_admission(AdmissionError::InvalidRequest(
                                format!(
                                    "single-pending-target constraint: duplicate await target \
                                 'agent:{bare}' - a send reply has no correlation-id to \
                                 disambiguate two pending slots for the same agent"
                                ),
                            )));
                        }
                    }
                }
            }
        }
        // C3: bound the idle timeout — u32::MAX = 136 years is not a valid
        // pin period. The AC-10 idle monitor (this slice) reads this
        // value verbatim.
        if let Some(secs) = options.idle_timeout_secs {
            if secs > MAX_IDLE_TIMEOUT_SECS_CAP {
                return Err(classify_admission(AdmissionError::InvalidRequest(format!(
                    "idle_timeout_secs > MAX_IDLE_TIMEOUT_SECS_CAP ({MAX_IDLE_TIMEOUT_SECS_CAP})"
                ))));
            }
        }
        if !(self.options.cap_check)(caller) {
            return Err(classify_admission(AdmissionError::CapabilityDenied(
                caller.to_string(),
            )));
        }

        // ── CapabilityConfig 4-knob admission gate (REQ-092 code-progress) ──
        // Pure, pre-lock (runs before the `sessions.read()` global-cap
        // window below). 4 of the 5 PRD §1088-1112 `await-replies`
        // capability knobs are honored here; `max-depth` needs the deferred
        // nested-tree (AC-16, slice C) and is not represented. All-`None`
        // (the default) ⇒ this whole block is inert ⇒ exact slice-A
        // behavior.
        {
            let cap = &self.options.capability;

            // (1) `targets` allowlist — membership-check ONLY well-formed
            // targets (strip `agent:` → bare; compare to the bare-name
            // allowlist per the PRD YAML). A MALFORMED target (fails
            // `is_safe_id`) is NOT whole-call-denied here — it falls through
            // to the existing per-slot dispatch invalid-target path so AC-07
            // is preserved (T18f). ComponentFinished slots have no agent id
            // and are not allowlist-checked.
            if let Some(allow) = &cap.targets {
                for req in &requests {
                    if let AwaitRequest::AgentRequest(agent_req) = req {
                        if !is_safe_id(&agent_req.target) {
                            // Malformed → defer to per-slot invalid-target.
                            continue;
                        }
                        let bare = bare_agent_name(&agent_req.target);
                        if !allow.iter().any(|a| a == bare) {
                            return Err(classify_admission(AdmissionError::CapabilityDenied(
                                format!("target {} not in capability allowlist", agent_req.target),
                            )));
                        }
                    }
                }
            }

            // (2) `max_fanout` — tighter than the crate-wide `MAX_FANOUT`
            // security cap.
            if let Some(max_fanout) = cap.max_fanout {
                if requests.len() > max_fanout {
                    return Err(classify_admission(AdmissionError::InvalidRequest(format!(
                        "requests.len() ({}) > capability max_fanout ({max_fanout})",
                        requests.len()
                    ))));
                }
            }

            // (3) `max_idle_timeout_secs` — tightens the accepted idle
            // timeout ceiling below `MAX_IDLE_TIMEOUT_SECS_CAP`. Distinct
            // discriminator reason so T18d can attribute the rejection to
            // THIS gate (vs slice-A's
            // `"idle_timeout_secs > MAX_IDLE_TIMEOUT_SECS_CAP"`).
            if let (Some(max_idle), Some(req_idle)) =
                (cap.max_idle_timeout_secs, options.idle_timeout_secs)
            {
                if req_idle > max_idle {
                    return Err(classify_admission(AdmissionError::InvalidRequest(
                        "capability:max-idle-timeout-exceeded".to_string(),
                    )));
                }
            }

            // (4) `max_inflight` — overrides the slice-A `max_inflight`
            // const for THIS call's per-caller cap. Applied at the
            // per-caller increment window further below via
            // `effective_max_inflight`.
        }

        // ── AC-09 deadlock gate (§1.3.4 triage) ──────────────────────
        // Pure + pre-lock: `agent_tree.as_ref().map(|t| t.snapshot())` is
        // sync + owned and runs before any lock is acquired (pins the gate
        // ahead of the slice-A global-cap TOCTOU window). For each
        // WELL-FORMED `AgentRequest` slot (passes `is_safe_id`), strip the
        // canonical `agent:` prefix → bare body and run the `parent_of`
        // ancestry walk (`forms_cycle`):
        //   - ALL well-formed agent targets cyclic → whole-call
        //     `Err(OrchestrationError::DeadlockDetected)`.
        //   - SOME-but-not-all cyclic → the cyclic slots are recorded
        //     `ReplyStatus::Failed("deadlock:{target}")` via the EXISTING
        //     slice-A per-slot dispatch-error recording path (see
        //     `deadlock_slots` consumed in the dispatch-recording block);
        //     non-cyclic slots dispatch normally.
        //   - MALFORMED target (fails `is_safe_id`) → NOT deadlock-evaluated,
        //     NOT counted toward `agent_slot_count`; falls through to the
        //     per-slot dispatch invalid-target path (AC-07-preserving — the
        //     frozen "malformed→AC-07 fall-through" rule; mirrors the
        //     CapabilityConfig `targets` gate).
        //   - `agent_tree = None` (default) → skipped (slice-A unchanged).
        // ComponentFinished slots have no agent id and are not checked.
        // **Wave-15 Lane A**: the SOME-but-not-all case ALSO emits one
        // `orchestration.deadlock_rejected` event (SYS-AC-169) post-admission
        // (collected here as `deadlock_emit` while `snapshot` is in scope; see
        // the emit site after the idle-monitor spawn). The ALL-cycle whole-call
        // rejection returns before session mint and emits nothing (SYS-AC-168
        // carries no event requirement).
        let mut deadlock_slots: std::collections::HashSet<usize> = std::collections::HashSet::new();
        // Wave-15 Lane A (SYS-AC-169): collect the rejected cyclic targets +
        // their cycle paths HERE (while `snapshot` is in scope) for the
        // `orchestration.deadlock_rejected` event emitted post-admission below.
        // (target canonical `agent:<name>`, cycle `[caller, …, target]`.)
        let mut deadlock_emit: Vec<(String, Vec<String>)> = Vec::new();
        if let Some(tree) = self.options.agent_tree.as_ref() {
            let snapshot = tree.snapshot();
            let mut agent_slot_count = 0usize;
            for (slot_idx, req) in requests.iter().enumerate() {
                if let AwaitRequest::AgentRequest(agent_req) = req {
                    // Only a CANONICAL AGENT target (`is_safe_id` AND the
                    // `agent:` prefix) is deadlock-evaluable: deadlock
                    // detection is an agent-tree `parent_of` ancestry walk,
                    // and only `agent:`-prefixed ids are agents with tree
                    // ancestry. A target that is malformed OR a non-agent
                    // kind is NOT deadlock-evaluated and is NOT counted
                    // toward `agent_slot_count` — it is invisible to this
                    // gate and falls through to the existing per-slot
                    // dispatch invalid-target path so AC-07 is preserved
                    // (frozen plan §"Deadlock design":
                    // "malformed→AC-07 fall-through").
                    //
                    // **AUDIT round W1**: the bare/malformed self-await case
                    // (caller "a" + target "a") would otherwise hit
                    // `forms_cycle`'s self-await branch and wrongly escalate
                    // to a whole-call `DeadlockDetected`.
                    //
                    // **Adversarial round W2**: `is_safe_id` ALSO accepts the
                    // non-agent kinds `user:<body>` and `system`
                    // (MODULE-006 id grammar = `system | agent:body |
                    // user:body`). Without the `agent:`-prefix requirement a
                    // caller could pad an otherwise all-cyclic request with a
                    // `user:`/`system` slot: `bare_agent_name` leaves it
                    // unchanged, `forms_cycle` cannot match it (it is not in
                    // `parent_of`), yet it would inflate `agent_slot_count`
                    // so `deadlock_slots.len() == agent_slot_count` fails and
                    // the whole-call `DeadlockDetected` is suppressed (an
                    // all-cycle admission-triage bypass). Requiring the
                    // `agent:` prefix here closes that — non-agent kinds are
                    // skipped (not counted) and fall through to per-slot
                    // dispatch, exactly like malformed targets.
                    if !is_safe_id(&agent_req.target) || !agent_req.target.starts_with("agent:") {
                        continue;
                    }
                    agent_slot_count += 1;
                    let target_bare = bare_agent_name(&agent_req.target);
                    if forms_cycle(&snapshot, caller, target_bare) {
                        deadlock_slots.insert(slot_idx);
                        deadlock_emit.push((
                            agent_req.target.clone(),
                            cycle_path(&snapshot, caller, target_bare),
                        ));
                    }
                }
            }
            // All agent targets cyclic (and at least one agent target
            // present) → whole-call DeadlockDetected.
            if agent_slot_count > 0 && deadlock_slots.len() == agent_slot_count {
                return Err(classify_admission(AdmissionError::DeadlockAll(
                    "all targets would create an AwaitSession cycle".to_string(),
                )));
            }
        }

        // **Adversarial round 2 C1 fix — lock-ordering invariant** (extended
        // for the AC-10 `liveness` index): the TOTAL lock order is
        //   `sessions` → {`per_caller_count`, `liveness`}
        // i.e. `sessions` (read or write) is acquired FIRST; the latter two
        // are never co-held with each other. The `liveness` std-Mutex is
        // held only for O(1) map ops and is NEVER held across an `.await`.
        // `on_reply`'s open-keeping path takes `liveness` while still holding
        // the `sessions.write()` guard — that is the `sessions → liveness`
        // ORDER, never inverted. Paths needing only `liveness`
        // (`on_heartbeat`, the idle-monitor tick) acquire it WITHOUT holding
        // `sessions`. Releasing each lock as soon as possible. Acquiring in
        // the reverse order would create an async-deadlock between `start()`
        // and `on_reply()`/`close()`. This block restructures the previous
        // round-1 single-block admission gate into two sequential
        // lock-acquire windows (sessions → per_caller_count) to honor the
        // invariant. No emit-under-lock concern exists this slice (no
        // events).
        //
        // Step 1: global cap check via brief sessions.read() (acquire +
        // drop before per_caller_count). TOCTOU window is bounded — the
        // worst case is briefly exceeding MAX_SESSIONS_GLOBAL by a small
        // number of concurrent racers, which is acceptable for slice A.
        {
            let sessions_now = self.sessions.read().await.len();
            if sessions_now >= MAX_SESSIONS_GLOBAL {
                return Err(classify_admission(AdmissionError::SessionLimitExceeded(
                    format!("global cap {MAX_SESSIONS_GLOBAL} reached"),
                )));
            }
        }
        // The AC-09 deadlock gate ran in the pure pre-lock region above
        // (whole-call `Err(DeadlockDetected)` on all-cycle; the
        // some-but-not-all-cycle slots are carried in `deadlock_slots` and
        // recorded as per-slot `ReplyStatus::Failed("deadlock:{target}")`
        // alongside the dispatch errors below). `agent_tree = None` ⇒ that
        // gate is inert (exact slice-A behavior).

        // ── AC-16 parent_session resolution + AC-18 max_depth gate (slice-C) ──
        // **Adversarial round 1 F6 fix**: runs BEFORE the session_id_factory
        // call so a max_depth rejection does NOT consume a session id (a
        // finite-supply factory was otherwise wasting ids on rejected
        // admissions).
        //
        // Sources:
        //   - SessionContextProvider lookup with caller_run_id → raw candidate
        //   - Ghost-parent filter: candidate's id absent OR resolved to a
        //     session owned by a DIFFERENT caller → strict-promotion to
        //     root (parent_session=None, depth=1). Closes AC-16 tree-
        //     integrity gap, AC-18 max-depth fail-open, and Adversarial
        //     round 1 F3 (cross-caller parent linkage; the in-boundary
        //     same-caller check defense-in-depths the trust boundary
        //     against a buggy or compromised SessionContextProvider).
        // Then the prospective new session depth = parent_depth + 1 (or 1
        // if no resolved parent). max_depth gate (only when
        // CapabilityConfig.max_depth is Some) rejects with discriminator
        // reason "capability:max-depth-exceeded".
        //
        // **Adversarial round 1 F2 fix**: validate `caller_run_id` length +
        // charset symmetric with `caller` (the host-fn handler is
        // authoritative but defense-in-depth at the trusted-inner-core
        // boundary refuses control-char / oversize ids that would
        // partition the provider's lookup table or leak into log lines).
        if let Some(run_id) = caller_run_id {
            if !is_safe_opaque_id(run_id) {
                return Err(classify_admission(AdmissionError::InvalidRequest(
                    "caller_run_id is not a safe opaque id".to_string(),
                )));
            }
        }
        let raw_parent: Option<SessionId> =
            match (self.options.session_context.as_ref(), caller_run_id) {
                (Some(provider), Some(run_id)) => provider.current_session(run_id),
                _ => None,
            };
        let (parent_session, prospective_depth): (Option<SessionId>, u32) = {
            let map = self.sessions.read().await;
            match &raw_parent {
                Some(p) => match map.get(p) {
                    // F3 fix: same-caller check. Only accept the parent if
                    // the session is present AND owned by the SAME caller.
                    // Cross-caller / cross-tenant linkage is silently
                    // demoted to root.
                    Some((s, _)) if s.agent_id == caller => {
                        let parent_depth = compute_depth_in_map(&*map, p);
                        (Some(p.clone()), parent_depth.saturating_add(1))
                    }
                    // Ghost parent (absent) OR different caller's session
                    // → root.
                    _ => (None, 1u32),
                },
                None => (None, 1u32),
            }
        };
        if let Some(max_d) = self.options.capability.max_depth {
            if prospective_depth > max_d {
                return Err(classify_admission(AdmissionError::CapabilityDenied(
                    "capability:max-depth-exceeded".to_string(),
                )));
            }
        }

        // ── Create + validate session id BEFORE per_caller_count increment ──
        // **Adversarial round 2 W9/I10 fix**: validate session_id factory
        // output BEFORE incrementing per_caller_count, so a failed
        // validation doesn't leave a stale increment if the factory panics
        // after the increment.
        // Backbone Step 4b: a caller-minted `session_id_override` (the
        // await-replies host-fn mints a uuid v4 so it can `suspend_run` with the
        // id before this call parks) is used verbatim; else the factory mints.
        // Validation below applies to BOTH paths.
        let id = session_id_override.unwrap_or_else(|| (self.options.session_id_factory)());
        // I12: validate session-id (factory- OR caller-minted) to prevent
        // newline/control-char injection into Message.id and WIT projection
        // payloads.
        if !is_safe_id(&format!("agent:{}", &id.0)) {
            return Err(classify_admission(AdmissionError::InvalidRequest(
                "session_id_factory produced a non-safe id".to_string(),
            )));
        }

        // **Adversarial round 3 W7 fix**: perform ALL panic-prone allocations
        // (AwaitSession::new clones the requests Vec; oneshot::channel
        // allocates) BEFORE incrementing `per_caller_count`. If any of these
        // panic, no `per_caller_count` leak occurs because the increment
        // hasn't happened. Step 2 below is the increment-and-insert critical
        // section where both maps are mutated as close as possible to each
        // other.
        let mode = options.mode;
        let mut session =
            AwaitSession::new(id.clone(), caller.to_string(), options, requests.clone());
        session.parent_session = parent_session; // AC-16 (slice-C)
                                                 // Wave-15 Lane A: capture the caller's run id for the session-stable
                                                 // `orchestration.await_idle_timeout` envelope (read by `resolve_idle`).
        session.caller_run_id = caller_run_id.map(|s| s.to_string());
        let (tx, rx) = oneshot::channel::<Result<AwaitResult, OrchestrationError>>();

        // Step 2: per-caller cap check + increment under the SAME lock —
        // closes the W8 TOCTOU race where K concurrent start()s from the
        // same caller could bypass the per-caller cap. Followed immediately
        // by sessions.write().insert() to bound the leak-window in case
        // sessions.write() itself panics (extremely unlikely under tokio's
        // RwLock — only if the map insert OOMs). The effective cap is the
        // CapabilityConfig `max_inflight` knob when set, otherwise the
        // slice-A `options.max_inflight` (default `MAX_INFLIGHT`).
        let effective_max_inflight = self
            .options
            .capability
            .max_inflight
            .unwrap_or(self.options.max_inflight);
        {
            let mut counts = self.per_caller_count.lock().await;
            let cur = counts.get(caller).copied().unwrap_or(0);
            if cur >= effective_max_inflight {
                return Err(classify_admission(AdmissionError::SessionLimitExceeded(
                    caller.to_string(),
                )));
            }
            *counts.entry(caller.to_string()).or_insert(0) += 1;
        }

        // Resolve the effective idle timeout for this session: the request's
        // `idle_timeout_secs` (an explicit over-cap value was already
        // hard-rejected at the CapabilityConfig gate above with
        // `"capability:max-idle-timeout-exceeded"`), else the manager default.
        //
        // **AUDIT round 16 W2 fix**: the CapabilityConfig
        // `max_idle_timeout_secs` gate above only fires when the caller
        // supplied `idle_timeout_secs` (`Some`). A caller that OMITS the
        // field would otherwise fall back to `idle_timeout_default_sec`,
        // which can EXCEED `max_idle_timeout_secs` and silently bypass the
        // capability ceiling. The capability cap is an upper bound on the
        // EFFECTIVE idle timeout regardless of how it was derived, so clamp
        // the resolved value to the ceiling when set. The explicit-over-cap
        // path still hard-rejects at the gate above (it returns before this
        // point, so T18d is unaffected); this only bounds the
        // omitted/default path. `min(v, cap) == v` whenever `v ≤ cap`, so
        // in-cap requests and the no-capability default are unchanged.
        let mut idle_timeout_secs = session
            .options
            .idle_timeout_secs
            .unwrap_or(self.options.idle_timeout_default_sec);
        if let Some(cap_max) = self.options.capability.max_idle_timeout_secs {
            idle_timeout_secs = idle_timeout_secs.min(cap_max);
        }

        {
            let mut sessions = self.sessions.write().await;
            // **Adversarial round 4 W1 — close the TOCTOU**: a concurrent
            // `close()` (or `on_reply` is_complete terminal path) could have
            // removed the parent between the slice-C `sessions.read()` parent
            // validation above and this `sessions.write()`. Re-verify under
            // the write guard: if the parent is now absent OR owned by a
            // different caller, demote `parent_session` to `None`. This is
            // strictly more restrictive than the prior pre-acquired value:
            // the max_depth gate already passed at the earlier depth, and
            // demoting can only DECREASE the effective depth (1 instead of
            // parent_depth+1), so the gate's invariant is preserved. Closes
            // the dangling-parent residual that earlier slice-C drafts had
            // documented as an accepted residual; the §3.6 entry now
            // reflects a tighter bound (only the panic-window between
            // session construction and write-lock-acquire — extremely
            // unlikely under tokio's RwLock).
            if let Some(p) = session.parent_session.as_ref() {
                let still_valid = matches!(sessions.get(p), Some((s, _)) if s.agent_id == caller);
                if !still_valid {
                    session.parent_session = None;
                }
            }
            sessions.insert(id.clone(), (session, tx));
        }

        // ── AC-10: register the idle clock + spawn the per-session monitor ──
        // AFTER the sessions-insert critical section (so the monitor never
        // observes a half-registered session). The `liveness` std-Mutex is
        // taken alone here (the `sessions` write guard above was already
        // dropped) — consistent with the `sessions → liveness` total order.
        //
        // **Adversarial rounds W3 / R20-W1 / R21-F1 (final corrected
        // design).** The monitor is spawned HERE — BEFORE
        // `dispatch_slots().await` — so a hanging or very-slow
        // `MailboxDispatcher::deliver()` is still idle-guarded: the monitor
        // idle-times-out the stuck session via `resolve_idle` (removing it
        // from `sessions`, evicting `liveness`, decrementing
        // `per_caller_count`, sending the oneshot) even though `start()` is
        // parked on the hung dispatch await and never reaches `rx.await`.
        // (Spawning it lazily after dispatch — a prior W3 attempt —
        // defeated the AC-10 guarantee for exactly that hostile path:
        // R20-W1.)
        //
        // The `JoinHandle` is intentionally NOT captured and the monitor is
        // NEVER `.abort()`ed: `resolve_idle` is NOT cancellation-safe (it
        // does an irreversible `sessions.remove` then `.await`s the
        // `per_caller_count` lock before decrementing — see `idle.rs`), so a
        // mid-flight `abort()` could remove the session but leak the
        // per-caller count permanently (R21-F1, a persistent
        // `SessionLimitExceeded` DoS). Instead the monitor self-terminates
        // safely at its OWN next tick: on the `early_resolve`/`all_failed`
        // fast paths below `liveness` is evicted, so the monitor's
        // claim-under-`liveness`-lock fails and it returns having done
        // NOTHING (no `sessions` touch, no decrement, no send) — at most a
        // single ≤`IDLE_TICK` sleeping no-op task that then exits. That
        // residual (R19-W3) is bounded, self-healing, harmless, and
        // inherent to the frozen periodic-monitor design; trading it for an
        // unsafe `abort()` is a strictly worse deal (R21-F1). See
        // MODULE-007 §3.6.
        {
            self.liveness
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(
                    id.clone(),
                    LivenessRec {
                        last_activity: tokio::time::Instant::now(),
                        idle_timeout_secs,
                    },
                );
        }
        tokio::spawn(idle_monitor_task(
            Arc::clone(&self.sessions),
            Arc::clone(&self.per_caller_count),
            Arc::clone(&self.liveness),
            self.turn_mailbox_dispatch.clone(),
            Arc::clone(&self.turn_batches),
            id.clone(),
            // Wave-15 Lane A: the idle monitor emits `await_idle_timeout` on the
            // ReturnPartial resolution (SYS-AC-252); `None` ⇒ no emit. The
            // effective idle timeout is the event's `idle_seconds` payload.
            self.options.event_emitter.clone(),
            idle_timeout_secs,
        ));

        // ── Wave-15 Lane A: orchestration.deadlock_rejected (SYS-AC-169) ──
        // Some-but-not-all-cycle admission triage: emit ONE event recording the
        // rejected cyclic target(s). Fires here (post-insert, lock-free) for an
        // admitted session even though the overall call may later resolve `Ok`
        // (the cyclic slot is rejected per-slot via `Failed("deadlock:…")` in
        // the dispatch-recording block below; a valid sibling completes via
        // `on_reply`). `deadlock_emit` was collected in the pre-lock gate while
        // the agent-tree `snapshot` was in scope. Empty when `agent_tree=None`
        // or no cyclic slot. The all-cycle whole-call rejection returned earlier
        // (no session id); SYS-AC-168 carries no event requirement.
        if !deadlock_emit.is_empty() {
            if let Some(emitter) = self.options.event_emitter.as_ref() {
                let targets: Vec<String> = deadlock_emit.iter().map(|(t, _)| t.clone()).collect();
                let cycle = deadlock_emit[0].1.clone();
                emitter.emit(crate::events::build_deadlock_rejected_event(
                    caller,
                    caller_run_id,
                    &targets,
                    &cycle,
                ));
            }
        }

        // ── Wave-20: orchestration.await_started (AC-17) ──
        // Emitted once per admitted session (post-insert, lock-free), reusing the
        // session-stable empty-trace_id envelope. `mode`/`requests` captured above
        // (the `session` was moved into the map). No `agent_tree` consulted.
        if let Some(emitter) = self.options.event_emitter.as_ref() {
            emitter.emit(crate::events::build_await_started_event(
                caller,
                caller_run_id,
                &id,
                await_mode_kebab(mode),
                requests.len(),
            ));
        }

        // ── Dispatch slots ───────────────────────────────────────────
        // `deadlock_slots` (AC-09 some-but-not-all-cycle) are skipped by
        // `dispatch_slots` (no `deliver`) and surface as
        // `DispatchSlotError::Deadlock` so the recording block below writes
        // the canonical per-slot `ReplyStatus::Failed("deadlock:{target}")`.
        let slot_results = if let Some(port) = self.turn_mailbox_dispatch.as_ref() {
            self.dispatch_protected_slots(&**port, caller, &requests, &id, &deadlock_slots)
        } else {
            dispatch_slots(&*self.dispatcher, caller, &requests, &id, &deadlock_slots).await
        };

        // ── Record per-slot errors + fast-path all-failed ────────────
        //
        // **Adversarial round 2 W8 fix**: after recording dispatch errors,
        // check `is_complete()` and resolve the session if the recording
        // closes the AllOf/AnyOf criterion. Previously a fast `on_reply`
        // arriving between session-insert and error-recording could resolve
        // slot 0 with Completed, leaving the AllOf is_complete check false;
        // when this block later recorded slot 1+2's dispatch errors the
        // session became "all slots filled" but no `tx.send` fired,
        // hanging the start() future. Now we re-check after error
        // recording and resolve via `early_resolve` flag if applicable.
        let mut all_failed = true;
        let mut any_success = false;
        let mut early_resolve: Option<AwaitResult> = None;
        // **R21-F2**: distinguishes "session still present when we recorded"
        // from "session already removed by a concurrent terminal path
        // (monitor `resolve_idle` / `close` / `on_reply`) DURING dispatch".
        // In the latter case that path already sent the oneshot, so `start()`
        // must fall through to `rx.await` for the correct result — it must
        // NEVER synthesize `Err(NotFound)` for its own post-insert session
        // (which would discard a buffered `PartialTimeout`/`IdleTimeoutExceeded`
        // result — the silent result-corruption R21-F2).
        let mut session_present = false;
        let now = Utc::now();
        {
            let mut sessions = self.sessions.write().await;
            if let Some((session, _)) = sessions.get_mut(&id) {
                session_present = true;
                for (slot_idx, r) in slot_results.iter().enumerate() {
                    match r {
                        Ok(()) => {
                            all_failed = false;
                            any_success = true;
                        }
                        Err(slot_err) => {
                            let reason = format_per_slot_reason(slot_err);
                            let target_source = match &requests[slot_idx] {
                                AwaitRequest::AgentRequest(req) => req.target.clone(),
                                AwaitRequest::ComponentFinished(req) => {
                                    format!("component:{}", req.component_id)
                                }
                            };
                            // R2 W4 + R2 W8: record_reply now returns
                            // Result. AlreadyRecorded means a concurrent
                            // on_reply already filled this slot (rare —
                            // dispatch failed so no recipient should send,
                            // but defensively handle). OutOfBounds is
                            // impossible here (slot_idx < requests.len()).
                            // In both cases we don't override the existing
                            // reply.
                            let _ = session.record_reply(
                                slot_idx as u32,
                                ReplyResult {
                                    slot: slot_idx as u32,
                                    source: target_source,
                                    payload: Vec::new(),
                                    status: ReplyStatus::Failed(reason),
                                    received_at: now,
                                    task_id: None, // dispatch-failure loser (AC-13 rule 2 deferred)
                                },
                            );
                        }
                    }
                }
                // Post-recording: did the new errors close is_complete?
                // (W8 fix.) If so, resolve here to avoid hanging start().
                if !all_failed && session.is_complete() {
                    // `now` (the dispatch-loop timestamp, also used for `ended_at`
                    // below) timestamps any Wave-24 materialized detached losers.
                    // For this dispatch-early-resolve path the AnyOf mode is inert
                    // (dispatch records only Failed/None, never Completed → AnyOf
                    // is_complete is false here) and AllOf is all-Some, so no
                    // materialization actually occurs — but the timestamp is passed
                    // for a single, deterministic snapshot contract.
                    let replies = session.snapshot_replies(now);
                    early_resolve = Some(AwaitResult {
                        session_id: id.0.clone(),
                        mode,
                        replies,
                        status: AwaitSessionStatus::Completed,
                        ended_at: now,
                    });
                }
            }
        }

        // `any_success` is computed alongside `all_failed` for symmetry but
        // only `all_failed` gates the fast-path; tame the unused-binding
        // warning (resolution is driven by the oneshot / idle monitor).
        let _ = any_success;

        if let Some(result) = early_resolve {
            // Race-resolved by post-error is_complete check (W8).
            let mut sessions = self.sessions.write().await;
            if let Some((_session, tx)) = sessions.remove(&id) {
                drop(sessions);
                self.detach_session_turns(&id);
                // Synchronous terminal path → evict the AC-10 idle clock.
                // The monitor is NOT aborted (R21-F1: `abort()` on a
                // possibly-in-flight `resolve_idle` leaks `per_caller_count`);
                // `liveness` is now absent so the monitor's next tick fails
                // its claim and exits having done nothing (≤`IDLE_TICK`
                // no-op — R19-W3, documented in §3.6).
                self.evict_liveness(&id);
                decrement_caller_count(&self.per_caller_count, caller).await;
                // ── Wave-20: orchestration.await_satisfied (AC-17) ──
                // Emitted INSIDE this `remove`-success block (exactly-once guard
                // for the early-resolve / on_reply race): this `Completed`
                // terminal won the `sessions.remove`, so a concurrent on_reply
                // could not have also resolved+emitted. The fall-through below
                // (session removed by another path) emits nothing here.
                if let Some(emitter) = self.options.event_emitter.as_ref() {
                    emitter.emit(crate::events::build_await_satisfied_event(
                        caller,
                        caller_run_id,
                        &id,
                        await_mode_kebab(mode),
                        result.replies.len(),
                    ));
                }
                let _ = tx.send(Ok(result.clone()));
                return Ok(result);
            }
            // Session was removed by another path (close/on_reply/monitor)
            // between our is_complete check and the remove — that path sent
            // the oneshot. Fall through to rx.await for its result (R21-F2:
            // never Err(NotFound) for our own post-insert session). The
            // monitor (if still running) self-exits on its next tick when
            // that path's `liveness` eviction is observed.
        }

        // **R21-F2**: gate the all-failed fast path on `session_present`.
        // If the session was removed during dispatch by a concurrent
        // terminal path, `all_failed` is still its init `true` but we must
        // NOT treat that as a dispatch failure — fall through to rx.await.
        if session_present && all_failed {
            // All slots failed dispatch — return Ok with FailedDispatch
            // status (PRD §9.2 "all-failed dispatch returns Ok").
            //
            // The monitor is NOT aborted (R21-F1: `abort()` on an in-flight
            // `resolve_idle` would remove the session but leak
            // `per_caller_count`). It self-terminates safely: `liveness` is
            // evicted below, so its next tick fails the claim and it exits
            // having done nothing (≤`IDLE_TICK` no-op — R19-W3, §3.6).
            let mut sessions = self.sessions.write().await;
            if let Some((session, tx)) = sessions.remove(&id) {
                drop(sessions);
                self.detach_session_turns(&id);
                // Terminal path → evict the AC-10 idle clock.
                self.evict_liveness(&id);
                decrement_caller_count(&self.per_caller_count, caller).await;
                let replies = session.snapshot_replies_all();
                let result = AwaitResult {
                    session_id: id.0.clone(),
                    mode,
                    replies,
                    status: AwaitSessionStatus::FailedDispatch,
                    ended_at: now,
                };
                let _ = tx.send(Ok(result.clone()));
                return Ok(result);
            }
            // Session vanished between recording and here — a concurrent
            // terminal path (monitor `resolve_idle` / `close` / `on_reply`)
            // already removed it and sent the oneshot. Fall through to
            // rx.await for that result; NEVER synthesize Err(NotFound) for
            // our own post-insert session (R21-F2).
        }

        // ── Await oneshot resolution ─────────────────────────────────
        // We reached here in one of two ways: (a) the session genuinely
        // waits (not all-failed, not early-resolved) — the pre-dispatch
        // monitor runs and resolves it on idle / `on_reply` / `close`; or
        // (b) a concurrent terminal path removed the session DURING dispatch
        // and already sent the oneshot (R21-F2 fall-through) — `rx` delivers
        // that result. Either way `start()` returns the oneshot value (or
        // `SessionClosed` if `tx` was dropped) — it never synthesizes
        // `Err(NotFound)` for its own post-insert session. The monitor was
        // spawned before dispatch (so a hung/slow `deliver()` is still
        // idle-guarded — R20-W1) and self-terminates safely via `liveness`
        // eviction (never `abort()`ed — R21-F1).
        //
        // Backbone Step 4b: fire `on_park` at the GENUINE park point — reached
        // ONLY here, after `sessions.insert` AND after both synchronous fast-path
        // returns (`early_resolve` / `session_present && all_failed` above) are
        // ruled out. The await-replies host-fn passes a hook that `suspend_run`s
        // the M008 Run + emits `run.suspended` here, so a fan-out that resolves
        // without parking never emits a phantom suspend. No `sessions` /
        // `per_caller_count` / `liveness` lock is held at this point. The closure
        // is sync (suspend_run is sync); calling it before the `.await` is fine.
        if let Some(on_park) = on_park {
            on_park();
        }
        match rx.await {
            Ok(res) => res,
            Err(_) => Err(OrchestrationError::SessionClosed(
                "oneshot dropped".to_string(),
            )),
        }
    }

    /// Test-only: read the `parent_session` field of a single session.
    /// Returns `None` when the session is absent OR present with
    /// `parent_session=None`. Used by T16a/T16c/T16f/T16h to verify
    /// in-boundary parent linkage.
    #[doc(hidden)]
    #[cfg(any(test, feature = "test-helpers"))]
    pub async fn session_parent_for_test(&self, sid: &SessionId) -> Option<SessionId> {
        self.sessions
            .read()
            .await
            .get(sid)
            .and_then(|(s, _)| s.parent_session.clone())
    }

    /// Test-only: total count of currently-open sessions across all callers.
    #[doc(hidden)]
    #[cfg(any(test, feature = "test-helpers"))]
    pub async fn session_count_for_test(&self) -> usize {
        self.sessions.read().await.len()
    }

    /// Slice E (2026-05-24) AC-11: heartbeat-from-target lookup.
    ///
    /// Returns the SessionId list of OPEN sessions where `caller_agent_id`
    /// (the agent calling `heartbeat()` from WASM) appears in `expected[*]`
    /// as an `AwaitRequest::AgentRequest` target. For each returned id, this
    /// method calls `on_heartbeat(&id, &normalized_caller, progress.clone())`
    /// (which resets the `liveness` index per slice-B). The caller
    /// (`HeartbeatHandler` in `host_fn.rs`) uses the returned `Vec<SessionId>`
    /// to know how many `orchestration.await_progress` events to emit.
    ///
    /// # Agent-id normalization
    ///
    /// `AgentAwaitRequest.target` stores canonical `agent:<name>` form (per
    /// slice-A §2.3 doc — `target` validated by `is_safe_id` in dispatch).
    /// `caller_agent_id` here comes from `HostCallContext.agent_id`, whose
    /// convention is not yet pinned by the deferred CapabilityInjector
    /// (AC-08/AC-14 — fiber wiring). This method normalizes defensively: if
    /// the arg lacks the `agent:` prefix, one is prepended for comparison.
    /// Single-pass normalization — `caller_agent_id` is never round-tripped
    /// through this normalizer.
    ///
    /// # From-target authorization (AC-11 §3.6 slice-E refinement)
    ///
    /// Sender→session authorization is enforced by THIS METHOD's enumeration
    /// scope: only sessions where the caller appears in `expected[*]` as an
    /// `AgentRequest` target are touched. Cross-caller leakage is impossible
    /// by construction. Slice-D's authorization-by-design rationale (the
    /// reply-tracker crate is the trusted inner core; the host-fn layer is
    /// authoritative for caller authentication) holds — slice-E adds the
    /// session-scope authorization explicitly via target-of-await enumeration.
    ///
    /// # Concurrency
    ///
    /// Holds `sessions.read().await` only across the `iter().filter()` walk;
    /// the resulting `Vec<SessionId>` is materialized + the read guard is
    /// dropped BEFORE the synchronous `on_heartbeat` calls. A concurrent
    /// `close()`/`resolve_idle` removing a session between the drop and the
    /// `on_heartbeat` call is benign: `reset_liveness` is a no-op for absent
    /// session ids (manager.rs `reset_liveness` impl).
    ///
    /// # Component-finished slots
    ///
    /// `AwaitRequest::ComponentFinished` slots are excluded from enumeration
    /// — heartbeat is agent-only per AC-11. ComponentFinished resolution
    /// goes through M019 `run.completed` events + M002 output-dir read,
    /// not heartbeat.
    pub async fn heartbeat_for_target(
        &self,
        caller_agent_id: &str,
        progress: Option<String>,
    ) -> Vec<SessionId> {
        let needle: String = if caller_agent_id.starts_with("agent:") {
            caller_agent_id.to_string()
        } else {
            format!("agent:{}", caller_agent_id)
        };
        let matching: Vec<SessionId> = {
            let sessions = self.sessions.read().await;
            sessions
                .iter()
                .filter(|(_, (s, _))| {
                    matches!(s.status, crate::session::SessionStatus::Open)
                        && s.expected.iter().any(|req| match req {
                            AwaitRequest::AgentRequest(a) => a.target == needle,
                            AwaitRequest::ComponentFinished(_) => false,
                        })
                })
                .map(|(id, _)| id.clone())
                .collect()
        };
        for id in &matching {
            self.on_heartbeat(id, &needle, progress.clone());
        }
        matching
    }

    /// Wave-19 Lane 3 (AC-19, CONTRACT-184 provider side) — resolve a
    /// `ComponentFinished` await slot when its component's run completes.
    ///
    /// The MODULE-007 §2.3 component-finished resolution path: on `run.completed`
    /// (driven here by the `RunCompletionSink`/`ComponentResolutionSink`), scan
    /// OPEN sessions for a not-yet-resolved `ComponentFinished` slot whose
    /// `component_id` matches, and mark it **`ReplyStatus::Completed` STATUS-ONLY
    /// with an EMPTY payload** (PRD §9.2 — the `completed` variant carries no
    /// payload; the component output is NOT delivered through the AwaitSession,
    /// the caller reads `output-dir/result.bin` directly via MODULE-002). The
    /// resolution flows through the EXISTING [`AwaitSessionManager::on_reply`]
    /// path, which fires the session oneshot when the session becomes complete.
    ///
    /// `outcome` is `run.completed`'s outcome label — event/log context ONLY.
    /// `complete_run` is the Active→Completed *success* terminal, so the slot is
    /// marked `completed` unconditionally; the failed-component path
    /// (`fail_run`→`run.failed`) is outside §2.3's "resolves via run.completed"
    /// contract and is not handled here.
    ///
    /// Returns the resolved [`SessionId`] when a matching open slot was found and
    /// `on_reply` accepted it; `None` otherwise (no match, or a benign
    /// read-drop→write race where the session vanished — `on_reply` returns
    /// `NotFound`, logged and ignored; best-effort, never panics).
    pub async fn resolve_component_finished(
        &self,
        component_id: &str,
        _outcome: &str,
    ) -> Option<SessionId> {
        // Wave-24 `req270-sink` — test-only witness that the sink actually SPAWNED
        // + entered the resolver (vs the `on_run_completed` colon short-circuit,
        // which returns before any spawn). cfg-gated → zero production cost.
        #[cfg(any(test, feature = "test-helpers"))]
        self.resolve_attempts
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        // Collect the matching (session_id, slot) under a READ guard, then DROP
        // it BEFORE `on_reply` (which takes the `sessions` WRITE lock — tokio
        // RwLock is NOT reentrant, so holding read across it would deadlock).
        let target: Option<(SessionId, u32)> = {
            let sessions = self.sessions.read().await;
            let mut found: Option<(SessionId, u32)> = None;
            'outer: for (sid, (session, _)) in sessions.iter() {
                if !matches!(session.status, crate::session::SessionStatus::Open) {
                    continue;
                }
                for (idx, req) in session.expected.iter().enumerate() {
                    if let AwaitRequest::ComponentFinished(c) = req {
                        if c.component_id == component_id
                            // only an UNRESOLVED slot (no double-resolve)
                            && !matches!(session.received.get(idx), Some(Some(_)))
                        {
                            found = Some((sid.clone(), idx as u32));
                            break 'outer;
                        }
                    }
                }
            }
            found
        };
        let (sid, slot) = target?;
        let reply = ReplyResult {
            slot,
            source: format!("component:{component_id}"),
            payload: Vec::new(), // EMPTY per §2.3 (status-only; caller reads result.bin)
            status: ReplyStatus::Completed,
            received_at: Utc::now(),
            task_id: None, // on_reply overrides from expected[slot]; ComponentFinished has no context
        };
        if let Err(e) = self.on_reply(&sid, slot, reply).await {
            eprintln!(
                "resolve_component_finished: on_reply for session {} slot {slot} returned non-fatal error: {e:?}",
                sid.0
            );
            return None;
        }
        Some(sid)
    }

    /// Wave-24 `req270-sink` — test-only: how many times
    /// [`Self::resolve_component_finished`] was ENTERED. Used by the
    /// component-finished witness to prove the `on_run_completed` colon
    /// short-circuit skips the spawn (a colon `task_id` yields 0 entries; a
    /// colon-free non-match yields 1).
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn resolve_attempts_for_test(&self) -> usize {
        self.resolve_attempts
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// await-leg B-3 (2026-06-22) — production WASM `send` ingress.
    ///
    /// A child agent's `send(target, payload, context)` is EITHER a reply to a
    /// parked parent's `await-replies` slot OR a plain agent→agent message. The
    /// host cannot tell from the WIT `message-context` (3 fields — no
    /// correlation-id / in-reply-to), so it infers correlation from
    /// `(target = the awaiting owner, source = the host-fn caller)`:
    ///   - if `target` owns an OPEN await session with a pending slot whose
    ///     `AgentRequest.target` is `source` → route into MODULE-007
    ///     [`AwaitSessionManager::on_reply`] (the B-3 net-new ingress);
    ///   - else → genuine M006 mailbox delivery via the manager's dispatcher.
    ///
    /// The two paths are mutually exclusive (route on match, deliver only on
    /// `NoMatch`) — a reply is never ALSO dumped into the mailbox. The payload
    /// is already bounded at the M006 cap by the host-fn decoder
    /// (`decode_send_params`); this validates the target id shape and routes.
    /// Inherent (NOT a CONTRACT-060 trait method) — `modified_contracts=[]`.
    ///
    /// Wave-10 B-4a (2026-06-22) ACTIVATED the guest-driven path: `"messaging"` is
    /// now in `agent_config::KNOWN_CAPABILITIES`, so a `messaging`-declaring guest
    /// links + drives this ingress. STILL DORMANT for SHIPPED agents (no shipped
    /// guest imports `agent-messaging`; no shipped `.agent/config.yaml` declares
    /// `messaging:true`) — reachable only for an opt-in messaging agent.
    pub async fn handle_send(
        &self,
        source: &str,
        target: &str,
        payload: Vec<u8>,
        context: Option<MessageContext>,
    ) -> Result<(), MsgError> {
        // Validate the target id shape up front so a reply route gets the right
        // WIT `msg-error` variant. The dispatcher's `deliver` re-validates on the
        // fallback path (defense-in-depth), but failing fast here is cheaper than
        // building the `Message` envelope for a malformed target.
        if !is_safe_id(target) {
            return Err(MsgError::InvalidTarget(
                "target is not a safe agent id".to_string(),
            ));
        }
        match self
            .try_route_reply(bare_agent_name(target), source, &payload)
            .await
        {
            // Routed into `on_reply` (or a benign post-match race — still a reply,
            // never a plain message → do NOT also mailbox-deliver).
            RouteOutcome::Routed => Ok(()),
            // No open await slot for `(target, source)` → genuine M006 send.
            RouteOutcome::NoMatch => {
                let msg = Message {
                    id: format!("send:{}", uuid::Uuid::new_v4()),
                    kind: MessageKind::Agent,
                    from: self.canonical_sender(source),
                    to: target.to_string(),
                    payload,
                    context,
                    timestamp: std::time::SystemTime::now(),
                    origin: None,
                };
                self.dispatcher.deliver(target, msg).await
            }
        }
    }

    /// Deliver a C216 provider-claimed reply to the exact session/slot route.
    /// Unlike the legacy heuristic lookup, this never aliases a stale child
    /// send onto a newer same-source session.
    pub(crate) async fn route_claimed_reply(
        &self,
        route: &ExactReplyRoute,
        payload: Vec<u8>,
        settlement: Arc<ClaimedReplySettlement>,
    ) -> Result<(), OrchestrationError> {
        let source = {
            let sessions = self.sessions.read().await;
            let (session, _) = sessions
                .get(&route.session_id)
                .ok_or_else(|| OrchestrationError::NotFound(route.session_id.0.clone()))?;
            match session.expected.get(route.slot as usize) {
                Some(AwaitRequest::AgentRequest(request)) => request.target.clone(),
                _ => {
                    return Err(OrchestrationError::InvalidRequest(
                        "claimed reply route is not an agent-request slot".to_string(),
                    ))
                }
            }
        };
        CLAIMED_REPLY_SETTLEMENT
            .scope(
                settlement,
                self.on_reply(
                    &route.session_id,
                    route.slot,
                    ReplyResult {
                        slot: route.slot,
                        source,
                        payload,
                        status: ReplyStatus::Completed,
                        received_at: Utc::now(),
                        task_id: None,
                    },
                ),
            )
            .await
    }

    /// Record the one production late-reply outcome claimed by CONTRACT-216.
    /// The registry's opaque late-disposition token is the exactly-once gate;
    /// this method owns only EventBus emission and cannot route or reopen a
    /// session.  `source`/`target`/`turn_id` are host-authenticated values from
    /// the send handler and are sanitized/bounded before projection.
    pub(crate) fn emit_detached_reply_late(&self, source: &str, target: &str, turn_id: &str) {
        if let Some(emitter) = self.options.event_emitter.as_ref() {
            emitter.emit(crate::events::build_detached_reply_late_event(
                &sanitize_for_error(source),
                &sanitize_for_error(target),
                &sanitize_for_error(turn_id),
            ));
        }
    }

    /// await-leg B-3 — find the deterministic-minimum `(created_at, slot)` OPEN
    /// await slot owned by `owner` that expects agent `source`, and route the
    /// `send` payload into [`AwaitSessionManager::on_reply`].
    ///
    /// Returns [`RouteOutcome::NoMatch`] when no such slot exists (the caller
    /// falls back to mailbox delivery). On a match, ALL `on_reply` errors map to
    /// [`RouteOutcome::Routed`]: `expected` is immutable, `slot` is in-bounds,
    /// and `reply.source` is taken verbatim from `expected[slot].target`, so the
    /// only reachable post-lookup errors are `NotFound` (the session
    /// resolved/closed in the read→write lock gap) and `InvalidRequest`
    /// (`AlreadyRecorded` — a concurrent reply filled the slot). Both mean the
    /// reply is moot/duplicate — benign, and never surfaced as a guest-visible
    /// `msg-error` (the reply WAS a reply, so it never falls through to the
    /// mailbox either). Honors the `sessions → liveness` lock order (the read
    /// guard is dropped before `on_reply` takes its write lock).
    ///
    /// **Routing residual — CLOSED for activation by await-leg B-4a (2026-06-22):**
    /// when one owner has >1 pending slot for the SAME source, the WIT shape carries
    /// no correlation-id to disambiguate; the deterministic oldest-session/lowest-slot
    /// pick MAY satisfy the wrong slot. B-4a (the activation) added the
    /// **single-pending-target admission constraint** in `start_with_run_inner`
    /// (reject an admission whose `agent:`-targeted slots duplicate a bare-agent
    /// target), so the INTRA-call same-source ambiguity is now structurally
    /// unadmittable. The CROSS-session same-source case is unreachable on the
    /// activated single-controller serve path: a guest fiber advances past an await
    /// ONLY after its session is removed — `on_reply`'s complete path removes the
    /// session from the map BEFORE firing the resume oneshot (close/idle terminate
    /// before resume too) — so an owner never holds two Open same-source sessions
    /// concurrently. CAVEAT: the manager does NOT itself forbid two Open sessions per
    /// owner; a future multi-run-per-owner design would need an explicit cross-session
    /// guard. A richer per-reply correlation channel (a WIT/CONTRACT change) remains
    /// the long-term fix if the WIT `send` shape ever gains a correlation-id.
    ///
    /// **Sequential post-remove late-send (AC-13 rule 4 / PRD rule 4 — still unrealized):**
    /// residual-CLOSED above is about *concurrent* dual-Open sessions. After an AnyOf
    /// keep-losers session is removed, a *later* OPEN same-source await on the same owner
    /// can still receive a stale detached loser's `send` (or, if none exists, `NoMatch`
    /// mailbox-delivers to the parent). Neither outcome emits `reply_late`. Concurrent
    /// residual remains CLOSED; sequential late-send aliasing is a separate hazard.
    async fn try_route_reply(&self, owner: &str, source: &str, payload: &[u8]) -> RouteOutcome {
        let source_bare = bare_agent_name(source);
        // Deterministic min-(created_at, slot) lookup under a brief read guard.
        let found: Option<(SessionId, u32, String)> = {
            let sessions = self.sessions.read().await;
            let mut best: Option<(std::time::Instant, u32, SessionId, String)> = None;
            for (sid, (session, _)) in sessions.iter() {
                if !matches!(session.status, crate::session::SessionStatus::Open)
                    || session.agent_id != owner
                {
                    continue;
                }
                for (i, req) in session.expected.iter().enumerate() {
                    if let AwaitRequest::AgentRequest(a) = req {
                        // Agent-only match: `source` (the host-fn caller) is always
                        // a bare AGENT id, so a `user:`/`system` expected target
                        // legitimately never matches a `send`-sourced reply.
                        if a.target.starts_with("agent:")
                            && bare_agent_name(&a.target) == source_bare
                            && session.received[i].is_none()
                        {
                            let key = (session.created_at, i as u32);
                            let is_better = match &best {
                                Some((bt, bs, _, _)) => key < (*bt, *bs),
                                None => true,
                            };
                            if is_better {
                                best = Some((
                                    session.created_at,
                                    i as u32,
                                    sid.clone(),
                                    a.target.clone(),
                                ));
                            }
                        }
                    }
                }
            }
            best.map(|(_, slot, sid, target)| (sid, slot, target))
        };
        let Some((sid, slot, expected_target)) = found else {
            return RouteOutcome::NoMatch;
        };
        // `reply.source` is taken VERBATIM from `expected[slot].target` so
        // `on_reply`'s `reply.source == expected[slot].target` defense-in-depth
        // check passes exactly; `reply.slot == slot` so its slot self-check passes.
        let reply = ReplyResult {
            slot,
            source: expected_target,
            payload: payload.to_vec(),
            status: ReplyStatus::Completed,
            received_at: Utc::now(),
            task_id: None, // on_reply overrides with the winner's preserved task-id (AC-13 rule 1)
        };
        match self.on_reply(&sid, slot, reply).await {
            Ok(()) => RouteOutcome::Routed,
            // Benign post-match race (NotFound / AlreadyRecorded) — see the
            // method rustdoc. Never surface a guest-visible error; never fall
            // through to the mailbox (it WAS a reply).
            Err(_e) => RouteOutcome::Routed,
        }
    }
}

/// await-leg B-3 — outcome of [`AwaitSessionManagerImpl::try_route_reply`].
enum RouteOutcome {
    /// The `send` matched an open await slot and was delivered to `on_reply`
    /// (including a benign post-match race where the reply turned out moot).
    Routed,
    /// No open await slot matched `(owner, source)` — fall back to mailbox.
    NoMatch,
}

#[async_trait]
impl AwaitSessionManager for AwaitSessionManagerImpl {
    /// CONTRACT-060::start — admission-time root entry. Delegates to
    /// [`AwaitSessionManagerImpl::start_with_run`] with `caller_run_id=None`
    /// → no parent_session linkage (slice-A/B behavior preserved). Slice-C
    /// nested-tree linkage is exercised via the non-trait `start_with_run`
    /// directly. See [`AwaitSessionManagerImpl::start_with_run`] for the
    /// full admission flow.
    async fn start(
        &self,
        caller: &str,
        requests: Vec<AwaitRequest>,
        options: AwaitOptions,
    ) -> Result<AwaitResult, OrchestrationError> {
        self.start_with_run(caller, None, requests, options).await
    }

    fn on_heartbeat(&self, session_id: &SessionId, _agent_id: &str, _progress: Option<String>) {
        // AC-10 in-boundary half (§1.3.3): reset the idle clock so an
        // actively-heartbeating session is not idle-timed-out. No-op if the
        // session is absent (already resolved/closed). **`on_heartbeat` itself
        // emits no event** — the `orchestration.await_progress` emit lives in
        // the `HeartbeatHandler` host-fn (slice-E, in-boundary; AC-12 passed).
        // `_agent_id`/`_progress` are part of the CONTRACT-060 signature but
        // are not needed for the idle-clock reset (they feed the slice-C
        // event payload).
        //
        // **TRUST BOUNDARY (Adversarial round W1; MODULE-007 §3.6 + state.json
        // `waived_scope` entry AC-11/REQ-171).** This in-boundary method does
        // NOT authorize the heartbeat sender against the session: it does not
        // verify `_agent_id` is the session owner or a participant/target of
        // `session_id`, so any caller able to reach this API with a known
        // `SessionId` can refresh that session's idle clock. This is BY
        // DESIGN for this slice's reply-tracker crate boundary, not an
        // oversight:
        //   - `on_heartbeat`'s `_agent_id` is a host-fn-authenticated id,
        //     stamped by the M006 `heartbeat()` WIT host-fn handler exactly
        //     as `start()`'s `caller` is stamped (see `is_safe_id` module
        //     rustdoc: the WIT host-fn layer is authoritative for caller
        //     authentication; this crate is the trusted inner core the
        //     host-fn layer calls AFTER authenticating + capability-checking
        //     the wasm caller). The reply-tracker crate is not directly
        //     reachable by untrusted wasm/agent code.
        //   - Heartbeat sender→session participation/authorization is part
        //     of the `heartbeat()` WIT host-fn dispatch surface = AC-11
        //     (REQ-171, cross-module M006+M007), which is OUTSIDE this
        //     slice's crate boundary and FORMALLY DEFERRED to slice C (the
        //     `waived_scope` AC-11/REQ-171 entry — a formal waiver, not a
        //     prose carve-out). The slice-C M006 heartbeat host-fn handler
        //     MUST perform the sender/participation authorization before
        //     calling this method.
        self.reset_liveness(session_id);
    }

    async fn close(&self, session_id: &SessionId, reason: &str) -> Result<(), OrchestrationError> {
        let (entry_session, tx) = {
            let mut sessions = self.sessions.write().await;
            match sessions.remove(session_id) {
                Some(entry) => entry,
                None => {
                    return Err(OrchestrationError::NotFound(session_id.0.clone()));
                }
            }
        };
        // Terminal path → evict the AC-10 idle clock (the spawned monitor
        // exits on its next tick when the id is absent).
        self.evict_liveness(session_id);
        self.detach_session_turns(session_id);
        let caller = entry_session.agent_id.clone();
        decrement_caller_count(&self.per_caller_count, &caller).await;
        // ── Wave-20: orchestration.await_session_closed (AC-17) ──
        // Emitted once per close, after the owning `remove` succeeded above.
        // `reason` is host-internal (cascade close / cancel-run / pause-run).
        if let Some(emitter) = self.options.event_emitter.as_ref() {
            emitter.emit(crate::events::build_await_session_closed_event(
                &caller,
                entry_session.caller_run_id.as_deref(),
                session_id,
                reason,
            ));
        }
        // Send SessionClosed to the awaiting start() future.
        let _ = tx.send(Err(OrchestrationError::SessionClosed(reason.to_string())));
        Ok(())
    }

    async fn on_reply(
        &self,
        session_id: &SessionId,
        slot: u32,
        mut reply: ReplyResult,
    ) -> Result<(), OrchestrationError> {
        // **Trust boundary note (Adversarial R1 W5 + R2 W3)**: slice-A
        // `on_reply` is an INTERNAL surface — only the runtime / slice-C
        // M006 host-fn handler should invoke it. That handler is
        // responsible for authorizing that the caller is the actual target
        // of `slot` (e.g., by validating against `MessageContext
        // .correlation_id` or the session's `expected[slot].target`).
        //
        // R2 W3 hardening: slice-A foundation now performs a
        // **defense-in-depth source validation**: if `reply.source` doesn't
        // match `session.expected[slot].target` (for `AgentRequest` slots)
        // or `format!("component:{component_id}")` (for `ComponentFinished`
        // slots), reject the reply as InvalidRequest. This blocks
        // confused-deputy spoofing where a caller forges
        // `ReplyResult { source: "agent:victim" }` while the actual target
        // was a different agent.
        let mut sessions = self.sessions.write().await;
        let Some(entry) = sessions.get_mut(session_id) else {
            // ── Wave-20: orchestration.reply_late (AC-17 event path ONLY) ──
            // A reply arrived for an already-resolved / closed session (the
            // direct `on_reply` orphan/miss path). This is AC-17 event-mechanism
            // evidence — NOT production AC-13 rule 4 / PRD rule 4 for child `send`
            // (that path goes SendHandler→handle_send→try_route_reply and either
            // aliases a later OPEN same-source slot or NoMatch→mailbox).
            // Record as `reply_late` and do NOT route it back to any AwaitSession.
            // `reply.source` is
            // caller-controlled at this branch (it precedes the source-match
            // validation below), so sanitize before emit to bound
            // log-amplification. Drop the sessions guard first (the get_mut
            // borrow already ended on the None arm); `emitter.emit` is sync.
            drop(sessions);
            if let Some(emitter) = self.options.event_emitter.as_ref() {
                emitter.emit(crate::events::build_reply_late_event(
                    &sanitize_for_error(&reply.source),
                    None,
                    session_id,
                    slot,
                ));
            }
            return Err(OrchestrationError::NotFound(session_id.0.clone()));
        };
        let (session, _) = entry;

        // **Adversarial round 3 C1 fix**: validate `reply.slot` matches the
        // `slot` function parameter. Previously the caller-controlled
        // `reply.slot` field was recorded verbatim, allowing a slice-C
        // caller (or future host-fn handler bug) to forge a slot index in
        // the inner struct that disagrees with the routing index.
        if reply.slot != slot {
            return Err(OrchestrationError::InvalidRequest(format!(
                "reply.slot ({}) does not match function slot parameter ({slot})",
                reply.slot
            )));
        }

        // R2 W3 + R3 W5: defense-in-depth source validation. Reject with a
        // SANITIZED error message — the caller-controlled `reply.source`
        // would otherwise leak control chars into the operator log via the
        // documented WIT projection rule.
        let slot_idx = slot as usize;
        if let Some(expected_req) = session.expected.get(slot_idx) {
            let expected_source = match expected_req {
                AwaitRequest::AgentRequest(req) => req.target.clone(),
                AwaitRequest::ComponentFinished(req) => format!("component:{}", req.component_id),
            };
            if reply.source != expected_source {
                return Err(OrchestrationError::InvalidRequest(format!(
                    "reply.source '{}' does not match expected '{}' for slot {slot}",
                    sanitize_for_error(&reply.source),
                    sanitize_for_error(&expected_source),
                )));
            }
        }

        // ── Wave-24 `req270-sink` (INTEGRITY, MODULE-007 §3.6:1100 prereq 6) ──
        // Defense-in-depth status-only enforcement for a `ComponentFinished` slot.
        // §2.3 makes a component reply STATUS-ONLY: an EMPTY payload (the caller
        // reads `output-dir/result.bin`). The producer
        // `resolve_component_finished` constructs `payload: Vec::new()`, but
        // `on_reply` is an INTERNAL surface — a direct caller could forge
        // `source == "component:{id}"` (passing the source-match above) WITH a
        // payload. Reject a non-empty payload for a ComponentFinished target slot.
        // The legit resolver sends empty, so the happy path is untouched; an
        // `AgentRequest` slot carries its reply payload and is NOT gated.
        if let Some(AwaitRequest::ComponentFinished(_)) = session.expected.get(slot_idx) {
            if !reply.payload.is_empty() {
                return Err(OrchestrationError::InvalidRequest(format!(
                    "ComponentFinished slot {slot} must be status-only (empty payload); got {} bytes",
                    reply.payload.len()
                )));
            }
        }

        // ── Wave-20 AC-13 rule 1 (host-internal): winner task-id preservation ──
        // Override the recorded reply's `task_id` with the authoritative task-id
        // from the originating await-request's context (the task under which this
        // slot was awaited). This is the single internal chokepoint every
        // recorded reply — winner included — passes through, so the resolved
        // `AwaitResult.replies[winner].task_id` carries the preserved task-id.
        // `None` when the request had no context task-id or is a ComponentFinished
        // slot. (Wave-23 wit-widening exposes this guest-side via WIT
        // `reply-result.task-id` — MODULE-007 §3.6/§3.7.)
        reply.task_id = session
            .expected
            .get(slot_idx)
            .and_then(await_request_task_id);

        // W4 + R2 W4 fix: record_reply now returns Result. OutOfBounds and
        // AlreadyRecorded both surface as InvalidRequest so a flood of
        // bogus on_reply calls (or attempted overwrite of an earlier slot
        // reply) surfaces an error to the caller rather than being silent.
        if let Err(e) = session.record_reply(slot, reply) {
            let reason = match e {
                RecordReplyError::OutOfBounds => {
                    format!("slot {slot} out of bounds for session {}", session_id.0)
                }
                RecordReplyError::AlreadyRecorded => format!(
                    "slot {slot} already has a recorded reply for session {} (overwrite forbidden)",
                    session_id.0
                ),
            };
            return Err(OrchestrationError::InvalidRequest(reason));
        }
        // C216 acceptance linearizes synchronously with the slot write,
        // before any later await (notably caller-count cleanup). Cancellation
        // after this point therefore observes an accepted provider marker and
        // recovery never invokes `on_reply` a second time.
        if let Ok(result) =
            CLAIMED_REPLY_SETTLEMENT.try_with(|claim| claim.mark_recorded_and_settle())
        {
            result.map_err(|error| OrchestrationError::Downstream(error.code().to_string()))?;
        }
        session.last_activity = std::time::Instant::now();

        let complete = session.is_complete();
        if complete {
            let mode = session.options.mode;
            let session_id_str = session.id.0.clone();
            // Single deterministic resolution timestamp — used both for any
            // Wave-24 materialized detached losers' `received_at` (AnyOf +
            // keep_losers=true; AC-13 rule 2 / PRD §9.2 rule 1 observable half) and the
            // AwaitResult `ended_at` below, so they never disagree.
            let now = Utc::now();
            let replies = session.snapshot_replies(now);
            let caller = session.agent_id.clone();
            // Wave-20: capture the session-stable run id for the await_satisfied
            // envelope BEFORE the session is moved out by `remove`.
            let caller_run_id = session.caller_run_id.clone();
            // Remove from map BEFORE sending to oneshot so the start()
            // future doesn't race a second on_reply.
            let (_session, tx) = sessions
                .remove(session_id)
                .expect("entry exists; just got it above");
            // Terminal path → evict the AC-10 idle clock. Taken while still
            // holding the `sessions` write guard — the allowed
            // `sessions → liveness` order (never inverted). No `.await` and
            // no event under the `liveness` lock.
            self.evict_liveness(session_id);
            drop(sessions);
            self.detach_session_turns(session_id);

            decrement_caller_count(&self.per_caller_count, &caller).await;

            let result = AwaitResult {
                session_id: session_id_str,
                mode,
                replies,
                status: AwaitSessionStatus::Completed,
                ended_at: now,
            };
            // ── Wave-20: orchestration.await_satisfied (AC-17) ──
            // This `on_reply` terminal owns the `remove` above (infallible
            // `.expect`), so it is the unique resolver for this session — emit
            // exactly-once here.
            if let Some(emitter) = self.options.event_emitter.as_ref() {
                emitter.emit(crate::events::build_await_satisfied_event(
                    &caller,
                    caller_run_id.as_deref(),
                    session_id,
                    await_mode_kebab(mode),
                    result.replies.len(),
                ));
            }
            let _ = tx.send(Ok(result));
        } else {
            // Open-keeping reply (AllOf with slots still pending; or an
            // AnyOf non-winning reply): reset the idle clock so a session
            // making reply progress without heartbeats is not falsely
            // idle-timed-out (mirrors the `session.last_activity` reset just
            // above). Taken while still holding the `sessions` write guard
            // — the allowed `sessions → liveness` order. **No event.**
            self.reset_liveness(session_id);
        }
        Ok(())
    }
}

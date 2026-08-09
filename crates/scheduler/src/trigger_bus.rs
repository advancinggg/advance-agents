//! `TriggerBusDispatch` (CONTRACT-131) impl + admission helpers.
//!
//! Slice A shipped:
//! - `TriggerBusDispatchImpl` with reverse-indexed storage so
//!   `unsubscribe(SubscriptionId)` is O(1) lookup + O(log n) HashSet
//!   removal with empty-bucket reclamation.
//! - `subscribe()` calls `validate_subscription` internally and returns
//!   `SubscriptionId::REJECTED` (`u64::MAX` sentinel) on admission failure
//!   under the canonical `-> SubscriptionId` signature.
//! - `WHITELIST` constant locked to PRD §3.8 exact 12 events.
//! - `is_event_whitelisted` and `validate_subscription` pure helpers.
//! - `dispatch()` was `unimplemented!()`.
//!
//! Slice B adds:
//! - `dispatch()` real fan-out: whitelist gate, chain-id extraction
//!   (from `event.payload.trigger_chain_id` or `event.id` fallback),
//!   depth extraction (from `event.payload.chain_depth` or default 0),
//!   per-subscriber atomic cap-check + visited-set insert via a single
//!   `Mutex<VisitedSetState>` (closes the Round-1 Critical-2 TOCTOU race
//!   between split RwLocks).
//! - `pending_by_sub: RwLock<HashMap<SubscriptionId, VecDeque<DispatchedEntry>>>`
//!   per-subscription queue (closes Round-1 Warning-1 multi-watcher stealing).
//! - `cycle_rejected_log` diagnostic side-channel with 6 variants.
//! - `unsubscribe()` extended to also evict `pending_by_sub[sub_id]`
//!   (closes Round-7 Warning-1 orphaned-queue leak).
//! - `clear_visited_state()` + `clear_chain(chain_id)` eviction surface
//!   (closes Round-7 Critical-1 unbounded accumulation).
//! - `Event` wrapped in `Arc<Event>` once at top of `dispatch()` so
//!   per-subscriber fan-out costs O(N) Arc clones rather than O(N ×
//!   payload_size) (closes Round-4 Warning-1).
//!
//! **Chain-propagation payload convention**: `event.payload.trigger_chain_id`
//! (string) and `event.payload.chain_depth` (u64-fits-u32) are READ from
//! event.payload by `dispatch()` if present. Emitters that want their
//! Trigger Bus events to propagate trigger-chain context MUST populate
//! these keys when re-emitting from a triggered context. The cycle gate
//! is correct + verified by unit tests today (synthetic payloads); the
//! production-path emitter discipline that drives this convention from
//! re-emitted events is part of the submit-component admission integration
//! declared in `waived_scope` (`.dev-state/state.json`).

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use advance_shared_types::event::Event;

use crate::contracts::TriggerBusDispatch;
use crate::types::{
    EventType, SpawnError, SubscriptionId, SubscriptionIdCounter, TriggerChainId,
    TriggerSubscription, MAX_CHAIN_DEPTH_HARD_CAP, MAX_COMPONENT_ID_LEN, MAX_EVENT_TYPES,
    MAX_EVENT_TYPE_LEN, MAX_SUBSCRIPTIONS_PER_EVENT_TYPE, MAX_TOTAL_SUBSCRIPTIONS,
};

/// PRD §3.8 Trigger Bus whitelist — exact 12 events.
pub const WHITELIST: &[&str] = &[
    "component.spawned",
    "component.finished",
    "component.error",
    "run.round_completed",
    "run.completed",
    "grant.issued",
    "grant.revoked",
    "git.commit",
    "trigger.fired",
    "auto.iteration_kept",
    "auto.iteration_crashed",
    "memory.l6_consolidation_due",
];

/// Slice B default for `TriggerBusDispatchImpl::max_chain_depth`. Equal to PRD
/// §3.8 default; the per-impl builder `with_max_chain_depth()` accepts an
/// override clamped to `MAX_CHAIN_DEPTH_HARD_CAP`.
pub const DEFAULT_MAX_CHAIN_DEPTH: u32 = 10;

/// Slice B aggregate cap on visited-set entries across all chains. Defends
/// against unbounded memory growth — production callers MUST periodically
/// invoke `clear_visited_state()` (or `clear_chain()` on chain completion).
pub const VISITED_SET_AGGREGATE_CAP: usize = 100_000;

/// Slice B cap on the `cycle_rejected_log` diagnostic buffer. Audit Round-3
/// Diff-Warning-1 fix — was unbounded; a malicious/buggy emitter calling
/// `dispatch(non_whitelisted_event)` in a loop would grow memory without
/// bound. The log is FIFO; when full, the oldest entry is evicted before
/// pushing the new one. Operators reading the log via
/// `cycle_rejected_log()` see at most this many recent rejections.
pub const CYCLE_REJECTED_LOG_CAP: usize = 4_096;

/// Adversarial Round-1 W3 fix: cap the size of any attacker-controlled
/// string that gets stored in a `CycleRejection` log entry. With the log
/// itself capped at `CYCLE_REJECTED_LOG_CAP` entries, this bounds the
/// total byte footprint of the rejection log to roughly
/// `CYCLE_REJECTED_LOG_CAP * REJECTION_LOGGED_STRING_MAX` bytes
/// (≈ 256 KiB worst case), regardless of the event_type length the
/// caller provides. Prior to this cap, `dispatch(event_type =
/// "x".repeat(10_000_000))` could amplify each log entry by 10 MB.
pub const REJECTION_LOGGED_STRING_MAX: usize = 64;

/// Adversarial Round-4 W1 fix: per-subscription queue cap as a fairness
/// governor on top of the aggregate visited-set cap.
///
/// Without this cap, a single wedged subscriber (watcher hook stalled
/// on an external service, slow consumer, cancelled but not yet
/// dropped) could accumulate up to `VISITED_SET_AGGREGATE_CAP =
/// 100_000` entries in its own per-sub queue — monopolizing the
/// entire aggregate budget and denying service to every other
/// subscription. The per-sub cap partitions the budget so any
/// single misbehaving sub is bounded; the aggregate cap remains the
/// global ceiling.
///
/// 10 000 matches the per-event-type subscription cap
/// (`MAX_SUBSCRIPTIONS_PER_EVENT_TYPE`) so up to ~10 simultaneously
/// saturated subscribers fit under the 100 000 aggregate ceiling.
pub const PENDING_QUEUE_PER_SUB_CAP: usize = 10_000;

/// Truncate `s` to at most `cap` UTF-8 bytes at a char boundary,
/// appending `"…"` if truncated. Used when storing attacker-controlled
/// strings into `CycleRejection` log entries.
fn truncate_for_log(s: &str, cap: usize) -> String {
    if s.len() <= cap {
        return s.to_string();
    }
    let mut end = cap;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = String::with_capacity(end + 3);
    out.push_str(&s[..end]);
    out.push_str("…");
    out
}

/// Pure whitelist check.
pub fn is_event_whitelisted(event_type: &str) -> bool {
    WHITELIST.contains(&event_type)
}

/// Caller-side admission validation — pure helper.
///
/// **Why this exists as a separate helper**: the canonical CONTRACT-131
/// `subscribe()` signature has no `Result` channel, so admission
/// errors cannot be returned to the caller directly. Slice A's
/// `subscribe()` calls this helper internally and silently no-ops on
/// rejection. The helper stays public so callers wanting explicit
/// error reporting can pre-check. Slice B widens the trait to
/// `Result<SubscriptionId, SpawnError>` via /spec.
///
/// **`is_new_event_type_bucket`**: pass `true` when this subscription
/// would create a new entry in `by_event_type` (i.e. no existing
/// subscriptions for this event type). Splitting the predicate ensures
/// the distinct-event-type cap is only enforced when actually adding
/// a new bucket — existing-bucket subscriptions keep working even at
/// the distinct-type ceiling.
pub fn validate_subscription(
    sub: &TriggerSubscription,
    current_subscriptions_for_event: usize,
    distinct_event_types: usize,
    is_new_event_type_bucket: bool,
    total_subscriptions: usize,
) -> Result<(), SpawnError> {
    if sub.event_type.len() > MAX_EVENT_TYPE_LEN {
        return Err(SpawnError::InvalidConfig(format!(
            "event_type length {} exceeds MAX_EVENT_TYPE_LEN {}",
            sub.event_type.len(),
            MAX_EVENT_TYPE_LEN
        )));
    }
    if !is_event_whitelisted(&sub.event_type) {
        return Err(SpawnError::InvalidConfig(format!(
            "event_type {:?} not in PRD §3.8 whitelist",
            sub.event_type
        )));
    }
    if current_subscriptions_for_event >= MAX_SUBSCRIPTIONS_PER_EVENT_TYPE {
        return Err(SpawnError::ResourceLimit(format!(
            "per-event subscription cap {} reached for {:?}",
            MAX_SUBSCRIPTIONS_PER_EVENT_TYPE, sub.event_type
        )));
    }
    if is_new_event_type_bucket && distinct_event_types >= MAX_EVENT_TYPES {
        return Err(SpawnError::ResourceLimit(format!(
            "distinct event-type cap {} reached",
            MAX_EVENT_TYPES
        )));
    }
    // Aggregate cap across the entire bus (adversarial Round 2
    // finding W3). Prevents the cartesian product
    // MAX_SUBSCRIPTIONS_PER_EVENT_TYPE × MAX_EVENT_TYPES = 10M
    // subscriptions from being reached — tightens the bus-wide ceiling
    // to 100K subscriptions.
    if total_subscriptions >= MAX_TOTAL_SUBSCRIPTIONS {
        return Err(SpawnError::ResourceLimit(format!(
            "total-subscription cap {} reached across the entire bus",
            MAX_TOTAL_SUBSCRIPTIONS
        )));
    }
    Ok(())
}

/// Slice A canonical-store record. Holds the event_type alongside the
/// full subscription so `unsubscribe(SubscriptionId)` can locate the
/// `by_event_type` bucket without re-scanning.
#[derive(Debug)]
pub struct SubscriptionRecord {
    pub event_type: EventType,
    pub subscription: TriggerSubscription,
}

/// Slice B dispatched-entry record stored in `pending_by_sub[sub_id]`.
///
/// `event: Arc<Event>` (Round-4 Warning-1 fix) so per-subscriber fan-out
/// costs O(N) Arc clones rather than O(N × payload_size) full-Event clones.
/// Particularly important when `payload` is large (multi-KiB JSON) and the
/// per-event subscription cap is 10 000.
///
/// **Public field surface**: `pub` fields enable test + diagnostic
/// inspection via `drain_for_subscription` / `cycle_rejected_log`. Exposing
/// `Arc<Event>` is acceptable — `Arc` is std-prelude; callers can clone the
/// pointer or `try_unwrap` to take ownership when they hold the unique
/// reference. `chain_id` is included on every entry so consumers (the
/// watcher poll loop, `drain_for_subscription`) can reclaim visited-set
/// slots when an entry is drained.
#[derive(Debug, Clone)]
pub struct DispatchedEntry {
    pub subscription_id: SubscriptionId,
    pub event: Arc<Event>,
    pub chain_id: TriggerChainId,
    pub next_depth: u32,
}

impl DispatchedEntry {
    /// sched-harvest 1B (SYS-AC-101): project this dispatched entry into the
    /// PRD §3.3 `trigger-context` the runnable's `run(config)` receives — the
    /// chain-propagation half the Slice-C drain loops deferred
    /// ("trigger_context derived from _entry.event payload is a follow-up").
    ///
    /// Field mapping:
    /// - `event_type`: the triggering event's type. Inherently bounded — only
    ///   the 12-entry `WHITELIST` members ever dispatch, so no length gate is
    ///   needed here.
    /// - `timestamp`: the event's wall-clock stamp as epoch milliseconds
    ///   (pre-epoch clamps to 0 — `u64` wire shape).
    /// - `payload`: the event's JSON payload serialized to bytes. Bounded
    ///   echo: a payload whose serialization exceeds `MAX_WIRE_BYTES_LEN` is
    ///   ELIDED (empty vec) rather than truncated — truncated JSON would hand
    ///   the guest undecodable bytes (fail-closed, the
    ///   `ERROR_MESSAGE_ECHO_MAX` bounded-echo discipline).
    /// - `trigger_chain_id` / `chain_depth`: the visited-set chain id and the
    ///   ADVANCED depth (`next_depth`) — what the runnable must carry into any
    ///   chained emission of its own (the payload-key convention documented on
    ///   `dispatch`).
    pub fn to_trigger_context(&self) -> crate::types::TriggerContext {
        let payload = serde_json::to_vec(&self.event.payload).unwrap_or_default();
        let payload = if payload.len() > crate::types::MAX_WIRE_BYTES_LEN {
            Vec::new()
        } else {
            payload
        };
        crate::types::TriggerContext {
            event_type: self.event.event_type.clone(),
            timestamp: self.event.timestamp.timestamp_millis().max(0) as u64,
            payload,
            trigger_chain_id: self.chain_id.0.clone(),
            chain_depth: self.next_depth,
        }
    }
}

/// Slice B rejection-log variant set.
///
/// Maintained as a forensic-inspection side-channel (not the
/// high-throughput observability surface). The log is FIFO with a
/// `CYCLE_REJECTED_LOG_CAP` ceiling and is protected by a single
/// `RwLock` — adequate for low-frequency rejection inspection. For
/// flood-resistant per-variant counts (e.g. when a malicious emitter
/// produces many rejections per second), operators read
/// `rejection_counts()` instead, which uses lock-free atomic counters
/// that always advance regardless of log saturation or contention.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CycleRejection {
    MaxDepthExceeded {
        chain_id: TriggerChainId,
        depth: u32,
        subscription_id: SubscriptionId,
    },
    AlreadyVisited {
        chain_id: TriggerChainId,
        subscription_id: SubscriptionId,
    },
    VisitedSetCapExceeded {
        chain_id: TriggerChainId,
    },
    EventTypeNotWhitelisted {
        event_type: String,
    },
    EventTypeTooLong {
        event_type_len: usize,
        cap: usize,
    },
    /// Distinct from `EventTypeTooLong` so operators inspecting
    /// `cycle_rejected_log` aren't misled into thinking the event_type
    /// was the offender when in fact the chain_id violated the length
    /// cap (Round-1 Warning-6 fix).
    ChainIdTooLong {
        chain_id_len: usize,
        cap: usize,
    },
    /// Audit Round-5 Warning-B fix: empty chain_id (the `event.id`
    /// fallback was empty AND no `payload.trigger_chain_id` was set).
    /// Using an empty chain_id as a HashMap key would collide unrelated
    /// dispatches; reject instead so the operator sees the malformed
    /// emitter rather than silent dedupe.
    ChainIdEmpty,
    /// Adversarial Round-4 W1: the per-subscription pending queue has
    /// reached `PENDING_QUEUE_PER_SUB_CAP`. A wedged or slow consumer
    /// can no longer accumulate further entries until it drains. The
    /// dispatch's visited-set increment is rolled back so the entry
    /// does not become a ghost slot toward the aggregate cap.
    PendingQueueCapExceeded {
        subscription_id: SubscriptionId,
        cap: usize,
    },
}

/// Adversarial Round-1 W2 fix: per-variant atomic counters as the
/// flood-resistant observability surface. Every rejection bumps the
/// corresponding counter (lock-free) in addition to optionally being
/// pushed to `cycle_rejected_log` (the bounded forensic buffer). Under
/// high-rate adversarial load, operators read these counters instead of
/// the log to get accurate volume metrics without contending the log's
/// RwLock.
#[derive(Debug, Default)]
pub struct RejectionCounters {
    pub max_depth_exceeded: AtomicU64,
    pub already_visited: AtomicU64,
    pub visited_set_cap_exceeded: AtomicU64,
    pub event_type_not_whitelisted: AtomicU64,
    pub event_type_too_long: AtomicU64,
    pub chain_id_too_long: AtomicU64,
    pub chain_id_empty: AtomicU64,
    pub pending_queue_cap_exceeded: AtomicU64,
}

/// Plain-data snapshot of the atomic counters at a point in time. Returned
/// by `rejection_counts()` for ergonomic operator inspection.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RejectionCountsSnapshot {
    pub max_depth_exceeded: u64,
    pub already_visited: u64,
    pub visited_set_cap_exceeded: u64,
    pub event_type_not_whitelisted: u64,
    pub event_type_too_long: u64,
    pub chain_id_too_long: u64,
    pub chain_id_empty: u64,
    pub pending_queue_cap_exceeded: u64,
}

/// Slice B visited-set state. Collapsed under a single `Mutex` so cap-check
/// + insert is atomic per dispatch iteration (Round-1 Critical-2 fix —
/// closes the split-RwLock TOCTOU window where two threads could each
/// observe `total < cap` and both insert, producing `total > cap`).
#[derive(Debug, Default)]
pub struct VisitedSetState {
    pub sets: HashMap<TriggerChainId, HashSet<SubscriptionId>>,
    pub total: usize,
}

/// Slice B `TriggerBusDispatch` impl.
///
/// **Default impl is explicit** (Round-4 Critical-1 fix): derived `Default`
/// would initialize `max_chain_depth: u32` to `0`, which makes the depth
/// gate `next_depth > effective_max_depth` true for every dispatch
/// (`next_depth >= 1` always exceeds `0`) — every dispatch would reject
/// as `MaxDepthExceeded`. The explicit impl sets `max_chain_depth:
/// DEFAULT_MAX_CHAIN_DEPTH`.
pub struct TriggerBusDispatchImpl {
    /// Canonical store: SubscriptionId → record.
    subscriptions: RwLock<HashMap<SubscriptionId, SubscriptionRecord>>,
    /// Fan-out index: event-type → set of SubscriptionIds.
    by_event_type: RwLock<HashMap<EventType, HashSet<SubscriptionId>>>,
    /// SubscriptionId counter.
    next_id: SubscriptionIdCounter,
    /// Slice B addition: atomic cap + per-chain visited-set under one Mutex.
    visited_set_state: Mutex<VisitedSetState>,
    /// Slice B addition: per-subscription pending queue. Each watcher drains
    /// only its own queue via `drain_for_subscription`.
    pending_by_sub: RwLock<HashMap<SubscriptionId, VecDeque<DispatchedEntry>>>,
    /// Slice B addition: diagnostic rejection log (operator-facing post-hoc
    /// inspection; NOT part of the hot dispatch path).
    cycle_rejected_log: RwLock<VecDeque<CycleRejection>>,
    /// Adversarial Round-1 W2 fix: per-variant atomic counters for
    /// flood-resistant observability. Always bumped on rejection,
    /// regardless of whether `cycle_rejected_log` is full or contended.
    rejection_counts: RejectionCounters,
    /// Slice B addition: configurable max chain depth (default 10 per PRD §3.8).
    max_chain_depth: u32,
}

impl Default for TriggerBusDispatchImpl {
    fn default() -> Self {
        Self {
            subscriptions: RwLock::new(HashMap::new()),
            by_event_type: RwLock::new(HashMap::new()),
            next_id: SubscriptionIdCounter::new(),
            visited_set_state: Mutex::new(VisitedSetState::default()),
            pending_by_sub: RwLock::new(HashMap::new()),
            cycle_rejected_log: RwLock::new(VecDeque::new()),
            rejection_counts: RejectionCounters::default(),
            // Round-4 Critical-1 fix: explicit non-zero default.
            max_chain_depth: DEFAULT_MAX_CHAIN_DEPTH,
        }
    }
}

impl TriggerBusDispatchImpl {
    pub fn new() -> Self {
        Self::default()
    }

    /// Builder: override `max_chain_depth`. Clamped to
    /// `MAX_CHAIN_DEPTH_HARD_CAP` (1000) to defend against caller passing
    /// `u32::MAX`. Values of `0` are accepted but make every dispatch fail
    /// `MaxDepthExceeded` — caller responsibility.
    pub fn with_max_chain_depth(mut self, d: u32) -> Self {
        self.max_chain_depth = d.min(MAX_CHAIN_DEPTH_HARD_CAP);
        self
    }

    /// Test/debug accessor — number of distinct event types currently
    /// stored.
    #[doc(hidden)]
    pub fn distinct_event_types(&self) -> usize {
        self.by_event_type
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .len()
    }

    /// Test/debug accessor — total active subscriptions.
    #[doc(hidden)]
    pub fn total_subscriptions(&self) -> usize {
        self.subscriptions
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .len()
    }

    /// Test/debug accessor — subscription count for a specific event
    /// type.
    #[doc(hidden)]
    pub fn subscriptions_for_event(&self, event_type: &str) -> usize {
        self.by_event_type
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .get(event_type)
            .map(|s| s.len())
            .unwrap_or(0)
    }

    /// Drain all pending entries for a specific subscription. The watcher
    /// driver calls this from its poll loop.
    ///
    /// **Per-subscription queue isolation** (Round-1 Warning-1 fix): each
    /// SubscriptionId has its own VecDeque, so concurrent watchers do NOT
    /// steal each other's entries.
    ///
    /// **Visited-set slot reclamation** (Adversarial Round-1 W1 fix):
    /// each drained `(chain_id, sub_id)` pair is also removed from
    /// `visited_set_state.sets`, decrementing `visited_set_state.total`.
    /// This makes the 100K aggregate cap reusable across non-overlapping
    /// chains rather than monotonically consumed. The semantic is
    /// "AlreadyVisited == an entry is currently pending in the queue
    /// for this (chain, sub) pair"; the `chain_depth` gate provides
    /// independent cycle-defense across propagations.
    ///
    /// **Atomic queue-pop + visited-decrement** (Adversarial Round-3 W1
    /// fix, reverting Round-2 W3's two-phase split): `visited_set_state`
    /// is held across BOTH the `pending_by_sub.write()` queue pop and
    /// the per-entry visited-set decrement. The Round-2 split
    /// (release `pending_by_sub`, then take `visited_set_state`)
    /// opened a lost-event race window — a concurrent `dispatch()`
    /// in the gap would observe the still-present visited entry and
    /// spuriously reject as `AlreadyVisited` even though the queue
    /// had been consumed. Atomicity is required to preserve the
    /// invariant. The throughput cost is bounded: per-entry work is
    /// O(1) HashMap ops, so the visited_set_state hold is O(N) for
    /// an N-entry queue. Typical watcher poll cadence is 25 ms, so
    /// N is small in steady state; worst case at 100K is ~1ms
    /// blocking window for concurrent dispatch.
    ///
    /// Poison-safe (Adversarial Round-1 W4 + Round-2 W1):
    /// `unwrap_or_else(into_inner)` on both locks so a panic that
    /// poisons either does not propagate as a process abort.
    pub fn drain_for_subscription(&self, sub_id: SubscriptionId) -> Vec<DispatchedEntry> {
        // Acquire visited_set_state FIRST (matches dispatch's lock
        // order: visited_set_state → pending_by_sub) and hold through
        // the entire operation.
        let mut state = self
            .visited_set_state
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let queue = {
            let mut map = self
                .pending_by_sub
                .write()
                .unwrap_or_else(|p| p.into_inner());
            match map.remove(&sub_id) {
                Some(q) => q,
                None => return Vec::new(),
            }
        };
        let entries: Vec<DispatchedEntry> = queue.into_iter().collect();
        for entry in &entries {
            // Capture flags from the per-chain mutable borrow before
            // touching `state.total` (avoids double-mutable-borrow).
            let (removed_sub, chain_now_empty) = match state.sets.get_mut(&entry.chain_id) {
                Some(set) => (set.remove(&sub_id), set.is_empty()),
                None => (false, false),
            };
            if removed_sub {
                state.total = state.total.saturating_sub(1);
            }
            if chain_now_empty {
                state.sets.remove(&entry.chain_id);
            }
        }
        entries
    }

    /// Total pending entries across all subscriptions (diagnostic).
    #[doc(hidden)]
    pub fn pending_total(&self) -> usize {
        self.pending_by_sub
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .values()
            .map(|q| q.len())
            .sum()
    }

    /// Snapshot the rejection log (for test inspection and operator
    /// post-hoc analysis).
    pub fn cycle_rejected_log(&self) -> Vec<CycleRejection> {
        self.cycle_rejected_log
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .cloned()
            .collect()
    }

    /// Audit Round-3 Diff-Warning-1 fix: append a rejection to the
    /// diagnostic log, evicting the oldest entry if the FIFO buffer is
    /// already at `CYCLE_REJECTED_LOG_CAP`. Bounded memory cost.
    ///
    /// Adversarial Round-1 W2 follow-on: always bump the corresponding
    /// per-variant atomic counter (lock-free) so operators retain
    /// accurate volume metrics even when the log RwLock is contended or
    /// the FIFO has wrapped.
    ///
    /// **Counter-vs-log invariant** (Adversarial Round-5 W1):
    /// - `rejection_counts.<variant>` is the **monotonic cumulative**
    ///   total since bus construction; FIFO eviction does NOT
    ///   decrement it, and `clear_rejected_log()` does NOT reset it.
    /// - `cycle_rejected_log()` is a **bounded forensic window**
    ///   (most-recent ≤ `CYCLE_REJECTED_LOG_CAP` entries).
    /// - Therefore: `rejection_counts.<variant>` ≥ count of <variant>
    ///   entries observed in `cycle_rejected_log()`. The gap
    ///   represents entries evicted by FIFO or cleared by
    ///   `clear_rejected_log`.
    /// - The counter for the new entry is bumped BEFORE the FIFO
    ///   pop-front, so the evicted entry's counter is NOT
    ///   decremented (it stays in the cumulative total — that's the
    ///   point of "cumulative since construction").
    fn append_rejection(&self, r: CycleRejection) {
        self.bump_rejection_counter(&r);
        let mut log = self
            .cycle_rejected_log
            .write()
            .unwrap_or_else(|p| p.into_inner());
        if log.len() >= CYCLE_REJECTED_LOG_CAP {
            log.pop_front();
        }
        log.push_back(r);
    }

    /// Lock-free per-variant counter bump. Called by `append_rejection`
    /// before the log push so the counter always advances regardless of
    /// log contention or saturation. Uses `Ordering::Relaxed` because
    /// per-variant counts have no cross-variant or cross-thread ordering
    /// dependency — operators read them as eventually-consistent metrics.
    fn bump_rejection_counter(&self, r: &CycleRejection) {
        let c = &self.rejection_counts;
        match r {
            CycleRejection::MaxDepthExceeded { .. } => {
                c.max_depth_exceeded.fetch_add(1, Ordering::Relaxed);
            }
            CycleRejection::AlreadyVisited { .. } => {
                c.already_visited.fetch_add(1, Ordering::Relaxed);
            }
            CycleRejection::VisitedSetCapExceeded { .. } => {
                c.visited_set_cap_exceeded.fetch_add(1, Ordering::Relaxed);
            }
            CycleRejection::EventTypeNotWhitelisted { .. } => {
                c.event_type_not_whitelisted.fetch_add(1, Ordering::Relaxed);
            }
            CycleRejection::EventTypeTooLong { .. } => {
                c.event_type_too_long.fetch_add(1, Ordering::Relaxed);
            }
            CycleRejection::ChainIdTooLong { .. } => {
                c.chain_id_too_long.fetch_add(1, Ordering::Relaxed);
            }
            CycleRejection::ChainIdEmpty => {
                c.chain_id_empty.fetch_add(1, Ordering::Relaxed);
            }
            CycleRejection::PendingQueueCapExceeded { .. } => {
                c.pending_queue_cap_exceeded.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Snapshot the per-variant rejection counters. Lock-free; useful for
    /// flood-resistant observability when `cycle_rejected_log` is full
    /// or contended.
    pub fn rejection_counts(&self) -> RejectionCountsSnapshot {
        let c = &self.rejection_counts;
        RejectionCountsSnapshot {
            max_depth_exceeded: c.max_depth_exceeded.load(Ordering::Relaxed),
            already_visited: c.already_visited.load(Ordering::Relaxed),
            visited_set_cap_exceeded: c.visited_set_cap_exceeded.load(Ordering::Relaxed),
            event_type_not_whitelisted: c.event_type_not_whitelisted.load(Ordering::Relaxed),
            event_type_too_long: c.event_type_too_long.load(Ordering::Relaxed),
            chain_id_too_long: c.chain_id_too_long.load(Ordering::Relaxed),
            chain_id_empty: c.chain_id_empty.load(Ordering::Relaxed),
            pending_queue_cap_exceeded: c.pending_queue_cap_exceeded.load(Ordering::Relaxed),
        }
    }

    /// Clear the rejection log (production callers may invoke this
    /// periodically, e.g. after exporting to telemetry). Returns the
    /// number of entries removed. The atomic counters in
    /// `rejection_counts` are intentionally NOT reset — they represent
    /// cumulative volume since bus construction and are the canonical
    /// monotonic metric surface.
    pub fn clear_rejected_log(&self) -> usize {
        let mut log = self
            .cycle_rejected_log
            .write()
            .unwrap_or_else(|p| p.into_inner());
        let n = log.len();
        log.clear();
        n
    }

    /// Current total entries in the visited-set (across all chains).
    pub fn visited_set_total(&self) -> usize {
        self.visited_set_state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .total
    }

    /// Reset all accumulated visited-set state. Production callers may
    /// invoke this periodically to release residual chains that were
    /// not drained (e.g. a watcher that unsubscribed without consuming
    /// its queue). The steady-state reclaim path is
    /// `drain_for_subscription`, which decrements the visited set as
    /// queues are drained; this surface covers the residual-chain
    /// case and is also the operator override for the 100K aggregate
    /// cap. Returns the number of `(chain_id, sub_id)` entries removed
    /// for telemetry.
    pub fn clear_visited_state(&self) -> usize {
        let mut state = self
            .visited_set_state
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let removed = state.total;
        state.sets.clear();
        state.total = 0;
        removed
    }

    /// Targeted variant: remove a specific chain's visited-set. Use when
    /// an emitter knows a chain has completed (no more downstream events
    /// will propagate this chain_id). Returns the number of sub-entries
    /// removed.
    ///
    /// **Visited-set reclaim surfaces** (Adversarial Round-1 W1 +
    /// Round-2 W2 fixes): the visited set is reclaimed automatically
    /// by three paths and explicitly by this one:
    /// - `drain_for_subscription`: each drained `DispatchedEntry`
    ///   decrements `(chain_id, sub_id)` (steady-state reclaim for
    ///   pending chains the consumer actually processes).
    /// - `unsubscribe`: the per-subscription evicted queue is
    ///   iterated and each entry's `(chain_id, sub_id)` is
    ///   decremented before the queue is dropped (so unsubscribe
    ///   before drain does not leak slots).
    /// - dispatch's in-flight rollback: when the post-Mutex
    ///   subscriber-existence re-check fails (concurrent
    ///   unsubscribe), the visited-set increment is rolled back.
    /// - this operator-facing surface (`clear_chain` /
    ///   `clear_visited_state`): a last-resort manual override for
    ///   any residual chain entries an operator wants to release.
    pub fn clear_chain(&self, chain_id: &TriggerChainId) -> usize {
        let mut state = self
            .visited_set_state
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if let Some(set) = state.sets.remove(chain_id) {
            let n = set.len();
            state.total = state.total.saturating_sub(n);
            n
        } else {
            0
        }
    }

    /// Test-only setter (gated under `#[cfg(test)]`). Used by the
    /// aggregate-cap test in `tests/trigger_bus_dispatch.rs` to pre-inflate
    /// the counter without allocating 100K real entries.
    #[doc(hidden)]
    #[cfg(test)]
    pub fn set_total_for_test(&self, n: usize) {
        let mut state = self
            .visited_set_state
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        state.total = n;
    }
}

/// Extract `trigger_chain_id` from event.payload if present and well-formed,
/// otherwise fall back to `event.id`. Returns `Err` if the resulting chain
/// id exceeds the length cap or is empty.
///
/// Audit Round-5 Warning-B fix: reject empty chain_id (would otherwise
/// collide unrelated dispatches via empty-string HashMap key).
///
/// Adversarial Round-3 W2 fix: borrow-then-check-then-allocate. The
/// shared-types `Event.id: String` and `event.payload.trigger_chain_id`
/// are structurally unbounded — MODULE-019 emitters are expected to
/// enforce size limits but the type system does not. Prior to this
/// fix, an attacker-controlled (or buggy-emitter) 10 MiB string would
/// be cloned via `.to_string()` into `raw` BEFORE the length check
/// ran, amplifying per-dispatch transient memory. The current path
/// borrows the source as `&str`, checks length, and only allocates
/// up to `MAX_COMPONENT_ID_LEN` bytes after the cap is verified.
fn extract_chain_id(event: &Event) -> Result<TriggerChainId, CycleRejection> {
    let raw_ref: &str = event
        .payload
        .get("trigger_chain_id")
        .and_then(|v| v.as_str())
        .unwrap_or(&event.id);
    if raw_ref.is_empty() {
        return Err(CycleRejection::ChainIdEmpty);
    }
    let len = raw_ref.len();
    if len > MAX_COMPONENT_ID_LEN {
        return Err(CycleRejection::ChainIdTooLong {
            chain_id_len: len,
            cap: MAX_COMPONENT_ID_LEN,
        });
    }
    // Length verified — now allocate (bounded to at most
    // MAX_COMPONENT_ID_LEN bytes).
    TriggerChainId::new(raw_ref.to_string()).map_err(|_| {
        // Defense-in-depth: TriggerChainId::new should not fail
        // after the length check, but if its validation ever adds
        // further constraints, the rejection variant remains
        // ChainIdTooLong rather than silently dropping the dispatch.
        CycleRejection::ChainIdTooLong {
            chain_id_len: len,
            cap: MAX_COMPONENT_ID_LEN,
        }
    })
}

/// Extract `chain_depth` from event.payload if present and well-formed.
/// Returns 0 as the safe default for events without chain context;
/// attacker/buggy emitter providing a malformed value (negative, float,
/// string, out-of-u32-range u64) triggers the fail-closed branch (returns
/// max+1 so the depth gate rejects).
///
/// Audit Round-1 Critical-1 fix: split missing-key path from
/// present-but-out-of-range path.
///
/// Audit Round-5 Warning-A fix: distinguish "key absent" (returns 0) from
/// "key present but not a positive u64" (returns max+1). Previously
/// `as_u64()` returning `None` for negative / float / string values fell
/// through to "missing → 0", letting a chained payload `{"chain_depth":
/// -1}` or `{"chain_depth": "10"}` reset the depth counter. Now any
/// non-positive-integer present value fails closed.
fn extract_chain_depth(event: &Event, max_chain_depth: u32) -> u32 {
    match event.payload.get("chain_depth") {
        // Missing → fresh chain at depth 0.
        None => 0,
        Some(v) => match v.as_u64() {
            // Present but non-positive-integer (negative, float, string,
            // bool, null, array, object) → fail-closed.
            None => max_chain_depth.saturating_add(1),
            // Present and valid u64 → use the value (fail-closed if out of
            // u32 range).
            Some(n) => u32::try_from(n).unwrap_or_else(|_| max_chain_depth.saturating_add(1)),
        },
    }
}

impl TriggerBusDispatch for TriggerBusDispatchImpl {
    /// Subscribe to a Trigger Bus event.
    ///
    /// Slice A admission flow:
    /// 1. Take **both** locks atomically in canonical order
    ///    (`by_event_type` first, then `subscriptions`) to avoid the
    ///    classic two-lock deadlock scenario across `subscribe` /
    ///    `unsubscribe` / `dispatch`.
    /// 2. Run `validate_subscription` against the snapshot.
    /// 3. On `Ok`: mint a fresh `SubscriptionId` and insert into both
    ///    indices.
    /// 4. On `Err`: silently no-op (return `SubscriptionId::REJECTED`).
    ///
    /// **Phantom-ID caveat**: the canonical CONTRACT-131 signature
    /// has no `Result` channel. Slice A returns
    /// `SubscriptionId::REJECTED` (u64::MAX) on rejection — callers
    /// MUST check for that sentinel before relying on the returned ID.
    /// Slice B widens via /spec.
    ///
    /// The counter is only incremented on `Ok` so rejected calls do
    /// not consume IDs.
    fn subscribe(&self, sub: TriggerSubscription) -> SubscriptionId {
        // Adversarial Round-2 W1: poison-safe lock acquisition. A panic
        // in any prior hot-path call site (dispatch, append_rejection,
        // drain) could poison these locks; without the
        // `unwrap_or_else(into_inner)` pattern, subscribe would abort
        // the process on poisoned-state recovery.
        let mut by_event = self
            .by_event_type
            .write()
            .unwrap_or_else(|p| p.into_inner());
        let mut subs = self
            .subscriptions
            .write()
            .unwrap_or_else(|p| p.into_inner());
        let current_for_event = by_event.get(&sub.event_type).map(|s| s.len()).unwrap_or(0);
        let is_new_bucket = !by_event.contains_key(&sub.event_type);
        let distinct = by_event.len();
        let total = subs.len();
        match validate_subscription(&sub, current_for_event, distinct, is_new_bucket, total) {
            Ok(()) => {
                let new_id = self.next_id.next();
                by_event
                    .entry(sub.event_type.clone())
                    .or_default()
                    .insert(new_id);
                subs.insert(
                    new_id,
                    SubscriptionRecord {
                        event_type: sub.event_type.clone(),
                        subscription: sub,
                    },
                );
                new_id
            }
            Err(_) => SubscriptionId::REJECTED,
        }
    }

    /// Remove a subscription by ID.
    ///
    /// Slice B extension (Round-7 Warning-1 fix): also evicts the
    /// per-subscription pending queue at `pending_by_sub[sub_id]`. The
    /// Slice A code left those entries orphaned in memory.
    ///
    /// Lock acquisition order: `by_event_type` → `subscriptions` →
    /// `pending_by_sub` (canonical declaration order; matches `subscribe`'s
    /// two-lock pattern with `pending_by_sub` appended at the tail — no
    /// circular-wait risk because `dispatch()` acquires
    /// `by_event_type` (read-only snapshot) → `visited_set_state` (Mutex)
    /// → `pending_by_sub` (write), which is a prefix of the same order).
    ///
    /// **Adversarial Round-1 W4 fix — poison-safe**: every RwLock
    /// acquisition uses `unwrap_or_else(|p| p.into_inner())` rather than
    /// `unwrap()`. This matters because `unsubscribe` is called from
    /// `UnsubscribeOnDrop::drop` in `watcher.rs`. If a hook panics and
    /// poisons one of these locks (e.g. via a prior dispatch panic),
    /// `.unwrap()` on a poisoned lock would itself panic — and a panic
    /// during stack-unwinding via `Drop` aborts the process.
    /// `into_inner()` extracts the guarded value regardless of poison
    /// state, letting cleanup proceed gracefully.
    fn unsubscribe(&self, id: SubscriptionId) {
        if id == SubscriptionId::REJECTED {
            return;
        }
        let evicted_queue = {
            let mut by_event = self
                .by_event_type
                .write()
                .unwrap_or_else(|p| p.into_inner());
            let mut subs = self
                .subscriptions
                .write()
                .unwrap_or_else(|p| p.into_inner());
            let mut pending = self
                .pending_by_sub
                .write()
                .unwrap_or_else(|p| p.into_inner());
            if let Some(record) = subs.remove(&id) {
                if let Some(set) = by_event.get_mut(&record.event_type) {
                    set.remove(&id);
                    if set.is_empty() {
                        by_event.remove(&record.event_type);
                    }
                }
            }
            pending.remove(&id) // Slice B: evict queued entries.
        };
        // Adversarial Round-2 W2 extension: reclaim visited-set entries
        // for the evicted queue. Without this, a `dispatch + unsubscribe
        // (before drain)` sequence leaves orphan `(chain_id, sub_id)`
        // entries that consume aggregate-cap slots which the drain
        // reclaim path can never see. Released the unsubscribe locks
        // first to avoid holding visited_set_state alongside the other
        // three RwLocks (preserves the canonical lock-order).
        if let Some(queue) = evicted_queue {
            if !queue.is_empty() {
                let mut state = self
                    .visited_set_state
                    .lock()
                    .unwrap_or_else(|p| p.into_inner());
                for entry in &queue {
                    let (removed_sub, chain_now_empty) = match state.sets.get_mut(&entry.chain_id) {
                        Some(set) => (set.remove(&id), set.is_empty()),
                        None => (false, false),
                    };
                    if removed_sub {
                        state.total = state.total.saturating_sub(1);
                    }
                    if chain_now_empty {
                        state.sets.remove(&entry.chain_id);
                    }
                }
            }
        }
    }

    /// Real fan-out dispatch (Slice B).
    ///
    /// **Lock-ordering throughput trade-off** (Audit Round-1 Warning-3
    /// acknowledgment): the per-subscriber loop acquires
    /// `visited_set_state` Mutex + `pending_by_sub` RwLock + (on reject)
    /// `cycle_rejected_log` RwLock once per iteration. Under heavy
    /// concurrent dispatch with many subscribers per event (cap is 10 000),
    /// this serializes against concurrent `subscribe` / `unsubscribe` /
    /// `drain_for_subscription` calls. The Mutex around `visited_set_state`
    /// is required for atomic cap-check-and-insert (Round-1 Critical-2
    /// fix) — splitting it into per-chain finer-grained locks would
    /// reintroduce the TOCTOU window. The throughput cost is bounded
    /// because the per-subscriber critical section is two HashMap
    /// operations (~O(1)).
    ///
    /// Algorithm:
    /// 1. Whitelist gate (cheap, fail-closed). Non-whitelisted event_type
    ///    → log `EventTypeNotWhitelisted`, return.
    /// 2. Length gate. event_type > MAX_EVENT_TYPE_LEN → log
    ///    `EventTypeTooLong`, return.
    /// 3. Chain-id extraction (event.payload.trigger_chain_id || event.id).
    ///    On length-cap violation → log `ChainIdTooLong`, return.
    /// 4. Depth extraction (event.payload.chain_depth || 0, saturated at
    ///    max+1).
    /// 5. Wrap `event` in `Arc<Event>` ONCE (cheap pointer copy ×
    ///    subscribers).
    /// 6. Snapshot the SubscriptionId list for this event_type.
    /// 7. Per-subscriber atomic cap-check + visited-set insert under a
    ///    single Mutex (Round-1 Critical-2 fix).
    /// 8. On Allow: enqueue `DispatchedEntry { Arc::clone(&event), ... }`
    ///    into `pending_by_sub[sub_id]`.
    /// 9. On Reject: append to `cycle_rejected_log`.
    fn dispatch(&self, event: Event) {
        // 1. Length gate FIRST — capping the bytes before any clone
        //    happens (Adversarial Round-1 W3 fix). Defense-in-depth
        //    relative to subscribe (which also enforces). Prevents
        //    `dispatch(event_type = "x".repeat(10_000_000))` from
        //    cloning a 10MB string into either branch's rejection log
        //    entry. `EventTypeTooLong` only stores the length (a usize),
        //    not the offending string, so it is already bounded.
        if event.event_type.len() > MAX_EVENT_TYPE_LEN {
            self.append_rejection(CycleRejection::EventTypeTooLong {
                event_type_len: event.event_type.len(),
                cap: MAX_EVENT_TYPE_LEN,
            });
            return;
        }
        // 2. Whitelist gate. The cloned `event_type` is additionally
        //    capped to `REJECTION_LOGGED_STRING_MAX` bytes inside the
        //    rejection log entry — `truncate_for_log` bounds the
        //    per-entry footprint even for inputs that pass the length
        //    gate above (e.g. a 1024-byte non-whitelisted event_type).
        if !is_event_whitelisted(&event.event_type) {
            self.append_rejection(CycleRejection::EventTypeNotWhitelisted {
                event_type: truncate_for_log(&event.event_type, REJECTION_LOGGED_STRING_MAX),
            });
            return;
        }
        // 3. Chain-id extraction
        let chain_id = match extract_chain_id(&event) {
            Ok(c) => c,
            Err(rejection) => {
                self.append_rejection(rejection);
                return;
            }
        };
        // 4. Depth extraction
        let depth = extract_chain_depth(&event, self.max_chain_depth);
        let effective_max_depth = self.max_chain_depth.min(MAX_CHAIN_DEPTH_HARD_CAP);
        let next_depth = depth.saturating_add(1);

        // 5. Wrap in Arc once
        let event = Arc::new(event);

        // 6. Snapshot subscribers for this event_type.
        // Adversarial Round-2 W1: poison-safe acquisition.
        let sub_ids: Vec<SubscriptionId> = {
            let by_event = self.by_event_type.read().unwrap_or_else(|p| p.into_inner());
            by_event
                .get(event.event_type.as_str())
                .map(|set| set.iter().copied().collect())
                .unwrap_or_default()
        };

        // 7+8+9. Per-subscriber loop
        for sub_id in sub_ids {
            // Atomic cap-check + visited-set insert under single Mutex.
            // Adversarial Round-2 W1: poison-safe.
            let action = {
                let mut state = self
                    .visited_set_state
                    .lock()
                    .unwrap_or_else(|p| p.into_inner());
                if next_depth > effective_max_depth {
                    DispatchAction::Reject(CycleRejection::MaxDepthExceeded {
                        chain_id: chain_id.clone(),
                        depth: next_depth,
                        subscription_id: sub_id,
                    })
                } else if state.total >= VISITED_SET_AGGREGATE_CAP {
                    DispatchAction::Reject(CycleRejection::VisitedSetCapExceeded {
                        chain_id: chain_id.clone(),
                    })
                } else {
                    let set = state.sets.entry(chain_id.clone()).or_default();
                    if !set.insert(sub_id) {
                        DispatchAction::Reject(CycleRejection::AlreadyVisited {
                            chain_id: chain_id.clone(),
                            subscription_id: sub_id,
                        })
                    } else {
                        state.total += 1;
                        DispatchAction::Enqueue
                    }
                }
            };
            match action {
                DispatchAction::Reject(r) => {
                    self.append_rejection(r);
                }
                DispatchAction::Enqueue => {
                    // Audit Round-4 Diff-Warning-1: hold `subscriptions`
                    // read + `pending_by_sub` write atomically so a
                    // concurrent `unsubscribe(sub_id)` cannot insert a
                    // ghost queue entry for an already-removed
                    // subscription.
                    // Adversarial Round-2 W1: poison-safe acquisition.
                    let subs = self.subscriptions.read().unwrap_or_else(|p| p.into_inner());
                    let mut pending = self
                        .pending_by_sub
                        .write()
                        .unwrap_or_else(|p| p.into_inner());
                    if !subs.contains_key(&sub_id) {
                        // Adversarial Round-2 W2 fix: roll back the
                        // visited-set increment so the entry does not
                        // become an unreclaimable ghost slot. The
                        // earlier visited_set_state lock-release window
                        // means a concurrent `unsubscribe(sub_id)` can
                        // have removed the subscriber between the
                        // visited insert and this membership re-check.
                        // Without rollback, the (chain_id, sub_id)
                        // entry would consume one of the 100K aggregate
                        // cap slots permanently — the drain reclaim
                        // path can't see it (queue was never populated)
                        // and unsubscribe doesn't scan all chains.
                        // Rollback releases pending+subs first, then
                        // re-acquires visited_set_state in the canonical
                        // order to avoid lock-order inversion.
                        drop(pending);
                        drop(subs);
                        let mut state = self
                            .visited_set_state
                            .lock()
                            .unwrap_or_else(|p| p.into_inner());
                        let (removed_sub, chain_now_empty) = match state.sets.get_mut(&chain_id) {
                            Some(set) => (set.remove(&sub_id), set.is_empty()),
                            None => (false, false),
                        };
                        if removed_sub {
                            state.total = state.total.saturating_sub(1);
                        }
                        if chain_now_empty {
                            state.sets.remove(&chain_id);
                        }
                        continue;
                    }
                    // Adversarial Round-4 W1 fix: per-subscription
                    // queue cap (`PENDING_QUEUE_PER_SUB_CAP`) prevents
                    // a single wedged subscriber from monopolizing the
                    // 100 K aggregate visited-set budget. Without this
                    // cap, one slow consumer that never drains could
                    // accumulate up to the full aggregate cap,
                    // denying service to every other subscription.
                    // Roll back the visited-set increment so the entry
                    // does not become a ghost slot.
                    let queue = pending.entry(sub_id).or_default();
                    if queue.len() >= PENDING_QUEUE_PER_SUB_CAP {
                        drop(pending);
                        drop(subs);
                        let mut state = self
                            .visited_set_state
                            .lock()
                            .unwrap_or_else(|p| p.into_inner());
                        let (removed_sub, chain_now_empty) = match state.sets.get_mut(&chain_id) {
                            Some(set) => (set.remove(&sub_id), set.is_empty()),
                            None => (false, false),
                        };
                        if removed_sub {
                            state.total = state.total.saturating_sub(1);
                        }
                        if chain_now_empty {
                            state.sets.remove(&chain_id);
                        }
                        drop(state);
                        self.append_rejection(CycleRejection::PendingQueueCapExceeded {
                            subscription_id: sub_id,
                            cap: PENDING_QUEUE_PER_SUB_CAP,
                        });
                        continue;
                    }
                    queue.push_back(DispatchedEntry {
                        subscription_id: sub_id,
                        event: Arc::clone(&event),
                        chain_id: chain_id.clone(),
                        next_depth,
                    });
                }
            }
        }
    }
}

enum DispatchAction {
    Reject(CycleRejection),
    Enqueue,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sub(event_type: &str) -> TriggerSubscription {
        TriggerSubscription {
            event_type: event_type.into(),
            filter: None,
            debounce_ms: None,
        }
    }

    #[test]
    fn whitelist_has_exactly_twelve_entries() {
        assert_eq!(WHITELIST.len(), 12);
    }

    #[test]
    fn whitelist_contains_canonical_events() {
        for evt in [
            "component.spawned",
            "component.finished",
            "component.error",
            "run.round_completed",
            "run.completed",
            "grant.issued",
            "grant.revoked",
            "git.commit",
            "trigger.fired",
            "auto.iteration_kept",
            "auto.iteration_crashed",
            "memory.l6_consolidation_due",
        ] {
            assert!(is_event_whitelisted(evt), "{evt} should be whitelisted");
        }
    }

    #[test]
    fn whitelist_rejects_non_canonical() {
        assert!(!is_event_whitelisted("fs.write"));
        assert!(!is_event_whitelisted("llm.response"));
        assert!(!is_event_whitelisted(""));
    }

    #[test]
    fn validate_subscription_accepts_whitelisted_under_caps() {
        let s = sub("git.commit");
        assert!(validate_subscription(&s, 0, 0, true, 0).is_ok());
    }

    #[test]
    fn validate_subscription_rejects_non_whitelisted() {
        let s = sub("fs.write");
        let err = validate_subscription(&s, 0, 0, true, 0).unwrap_err();
        assert!(matches!(err, SpawnError::InvalidConfig(_)));
    }

    #[test]
    fn validate_subscription_rejects_per_event_over_cap() {
        let s = sub("git.commit");
        let err =
            validate_subscription(&s, MAX_SUBSCRIPTIONS_PER_EVENT_TYPE, 10, false, 0).unwrap_err();
        assert!(matches!(err, SpawnError::ResourceLimit(_)));
    }

    #[test]
    fn validate_subscription_rejects_new_bucket_at_event_type_cap() {
        let s = sub("git.commit");
        let err = validate_subscription(&s, 0, MAX_EVENT_TYPES, true, 0).unwrap_err();
        assert!(matches!(err, SpawnError::ResourceLimit(_)));
    }

    #[test]
    fn validate_subscription_existing_bucket_ok_at_event_type_cap() {
        let s = sub("git.commit");
        assert!(validate_subscription(&s, 0, MAX_EVENT_TYPES, false, 0).is_ok());
    }

    #[test]
    fn validate_subscription_rejects_oversize_event_type() {
        let long = "x".repeat(MAX_EVENT_TYPE_LEN + 1);
        let s = sub(&long);
        let err = validate_subscription(&s, 0, 0, true, 0).unwrap_err();
        assert!(matches!(err, SpawnError::InvalidConfig(_)));
    }

    #[test]
    fn validate_subscription_rejects_total_over_cap() {
        let s = sub("git.commit");
        let err = validate_subscription(&s, 0, 0, true, MAX_TOTAL_SUBSCRIPTIONS).unwrap_err();
        assert!(matches!(err, SpawnError::ResourceLimit(_)));
    }

    #[test]
    fn subscribe_adds_entry_to_both_indices() {
        let bus = TriggerBusDispatchImpl::new();
        let _id = bus.subscribe(sub("git.commit"));
        assert_eq!(bus.total_subscriptions(), 1);
        assert_eq!(bus.distinct_event_types(), 1);
        assert_eq!(bus.subscriptions_for_event("git.commit"), 1);
    }

    #[test]
    fn unsubscribe_removes_from_both_indices() {
        let bus = TriggerBusDispatchImpl::new();
        let id = bus.subscribe(sub("git.commit"));
        bus.unsubscribe(id);
        assert_eq!(bus.total_subscriptions(), 0);
        assert_eq!(bus.distinct_event_types(), 0);
        assert_eq!(bus.subscriptions_for_event("git.commit"), 0);
    }

    #[test]
    fn subscribe_returns_rejected_sentinel_on_non_whitelisted() {
        let bus = TriggerBusDispatchImpl::new();
        let id = bus.subscribe(sub("fs.write"));
        assert_eq!(id, SubscriptionId::REJECTED);
        assert_eq!(bus.total_subscriptions(), 0);
        assert_eq!(bus.distinct_event_types(), 0);
    }

    #[test]
    fn subscribe_returns_rejected_sentinel_on_oversize_event_type() {
        let bus = TriggerBusDispatchImpl::new();
        let long = "x".repeat(MAX_EVENT_TYPE_LEN + 1);
        let id = bus.subscribe(sub(&long));
        assert_eq!(id, SubscriptionId::REJECTED);
        assert_eq!(bus.total_subscriptions(), 0);
    }

    #[test]
    fn subscribe_accepts_returns_non_sentinel_id() {
        let bus = TriggerBusDispatchImpl::new();
        let id = bus.subscribe(sub("git.commit"));
        assert_ne!(id, SubscriptionId::REJECTED);
    }

    #[test]
    fn unsubscribe_rejected_sentinel_is_safe_noop() {
        let bus = TriggerBusDispatchImpl::new();
        bus.unsubscribe(SubscriptionId::REJECTED);
        assert_eq!(bus.total_subscriptions(), 0);
    }

    #[test]
    fn multiple_subscriptions_to_same_event_share_bucket() {
        let bus = TriggerBusDispatchImpl::new();
        let _a = bus.subscribe(sub("git.commit"));
        let _b = bus.subscribe(sub("git.commit"));
        assert_eq!(bus.total_subscriptions(), 2);
        assert_eq!(bus.distinct_event_types(), 1);
        assert_eq!(bus.subscriptions_for_event("git.commit"), 2);
    }

    #[test]
    fn unsubscribe_keeps_bucket_when_others_remain() {
        let bus = TriggerBusDispatchImpl::new();
        let a = bus.subscribe(sub("git.commit"));
        let _b = bus.subscribe(sub("git.commit"));
        bus.unsubscribe(a);
        assert_eq!(bus.total_subscriptions(), 1);
        assert_eq!(bus.distinct_event_types(), 1);
        assert_eq!(bus.subscriptions_for_event("git.commit"), 1);
    }

    #[test]
    fn with_max_chain_depth_clamps_above_hard_cap() {
        let bus = TriggerBusDispatchImpl::new().with_max_chain_depth(u32::MAX);
        assert_eq!(bus.max_chain_depth, MAX_CHAIN_DEPTH_HARD_CAP);
    }

    #[test]
    fn default_max_chain_depth_is_ten() {
        let bus = TriggerBusDispatchImpl::new();
        assert_eq!(bus.max_chain_depth, DEFAULT_MAX_CHAIN_DEPTH);
    }

    #[test]
    fn clear_visited_state_resets_total() {
        let bus = TriggerBusDispatchImpl::new();
        bus.set_total_for_test(50);
        let removed = bus.clear_visited_state();
        assert_eq!(removed, 50);
        assert_eq!(bus.visited_set_total(), 0);
    }

    #[test]
    fn clear_chain_decrements_total_by_chain_size() {
        let bus = TriggerBusDispatchImpl::new();
        // Insert via dispatch (uses the real path).
        let _id = bus.subscribe(sub("git.commit"));
        let event = make_event("git.commit", "evt-1");
        bus.dispatch(event);
        assert_eq!(bus.visited_set_total(), 1);
        let removed = bus.clear_chain(&TriggerChainId::new("evt-1".into()).unwrap());
        assert_eq!(removed, 1);
        assert_eq!(bus.visited_set_total(), 0);
    }

    fn make_event(event_type: &str, id: &str) -> Event {
        Event {
            id: id.into(),
            timestamp: advance_shared_types::chrono::Utc::now(),
            agent_id: "test-agent".into(),
            task_id: None,
            run_id: None,
            execution_id: None,
            trace_id: "trace-1".into(),
            span_id: "span-1".into(),
            parent_span_id: None,
            event_type: event_type.into(),
            payload: serde_json::Value::Object(serde_json::Map::new()),
            duration_ms: None,
        }
    }

    #[test]
    fn dispatch_non_whitelisted_event_logs_rejection() {
        let bus = TriggerBusDispatchImpl::new();
        let event = make_event("fs.write", "evt-x");
        bus.dispatch(event);
        let log = bus.cycle_rejected_log();
        assert_eq!(log.len(), 1);
        assert!(matches!(
            &log[0],
            CycleRejection::EventTypeNotWhitelisted { .. }
        ));
        assert_eq!(bus.pending_total(), 0);
    }

    #[test]
    fn dispatch_whitelisted_with_no_subscribers_is_noop() {
        let bus = TriggerBusDispatchImpl::new();
        let event = make_event("git.commit", "evt-a");
        bus.dispatch(event);
        assert_eq!(bus.cycle_rejected_log().len(), 0);
        assert_eq!(bus.pending_total(), 0);
    }

    #[test]
    fn dispatch_enqueues_for_subscriber() {
        let bus = TriggerBusDispatchImpl::new();
        let sub_id = bus.subscribe(sub("git.commit"));
        let event = make_event("git.commit", "evt-b");
        bus.dispatch(event);
        let drained = bus.drain_for_subscription(sub_id);
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].subscription_id, sub_id);
        assert_eq!(drained[0].next_depth, 1);
    }

    #[test]
    fn dispatch_already_visited_skips_second_call() {
        let bus = TriggerBusDispatchImpl::new();
        let sub_id = bus.subscribe(sub("git.commit"));
        let event = make_event("git.commit", "evt-c");
        bus.dispatch(event.clone());
        bus.dispatch(event);
        assert_eq!(bus.pending_total(), 1); // only first enqueue
        let log = bus.cycle_rejected_log();
        assert!(log
            .iter()
            .any(|r| matches!(r, CycleRejection::AlreadyVisited { subscription_id, .. } if *subscription_id == sub_id)));
        // Cleanup: drain leftover pending so test isolation.
        let _ = bus.drain_for_subscription(sub_id);
    }

    #[test]
    fn dispatch_max_depth_exceeded() {
        let bus = TriggerBusDispatchImpl::new();
        let _sub_id = bus.subscribe(sub("git.commit"));
        let mut event = make_event("git.commit", "evt-d");
        // Inject chain_depth = 10 → next_depth = 11 > max=10 → reject.
        event.payload = serde_json::json!({ "chain_depth": 10 });
        bus.dispatch(event);
        let log = bus.cycle_rejected_log();
        assert!(log
            .iter()
            .any(|r| matches!(r, CycleRejection::MaxDepthExceeded { depth: 11, .. })));
        assert_eq!(bus.pending_total(), 0);
    }

    #[test]
    fn dispatch_at_depth_boundary_is_allowed() {
        let bus = TriggerBusDispatchImpl::new();
        let sub_id = bus.subscribe(sub("git.commit"));
        let mut event = make_event("git.commit", "evt-e");
        // chain_depth = 9 → next_depth = 10 == max → allowed (gate is strict >).
        event.payload = serde_json::json!({ "chain_depth": 9 });
        bus.dispatch(event);
        let drained = bus.drain_for_subscription(sub_id);
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].next_depth, 10);
    }

    #[test]
    fn dispatch_aggregate_cap_blocks_via_test_setter() {
        let bus = TriggerBusDispatchImpl::new();
        let _sub_id = bus.subscribe(sub("git.commit"));
        bus.set_total_for_test(VISITED_SET_AGGREGATE_CAP);
        let event = make_event("git.commit", "evt-cap");
        bus.dispatch(event);
        let log = bus.cycle_rejected_log();
        assert!(log
            .iter()
            .any(|r| matches!(r, CycleRejection::VisitedSetCapExceeded { .. })));
        assert_eq!(bus.pending_total(), 0);
    }

    #[test]
    fn unsubscribe_evicts_pending_queue() {
        let bus = TriggerBusDispatchImpl::new();
        let sub_id = bus.subscribe(sub("git.commit"));
        let event = make_event("git.commit", "evt-evict");
        bus.dispatch(event);
        assert_eq!(bus.pending_total(), 1);
        bus.unsubscribe(sub_id);
        assert_eq!(bus.pending_total(), 0);
    }
}

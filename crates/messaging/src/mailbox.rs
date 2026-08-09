//! `Mailbox` per-agent bounded queue + `MailboxStore` registry.
//!
//! Slice A storage primitive backing `MailboxDispatcher::deliver`. The
//! `Mailbox` itself supports priority ordering (`MessageKind::User` and
//! `MessageKind::Control` route to the high-priority queue; everything
//! else routes to the normal queue).
//!
//! # Capacity accounting (Adversarial-R13 redesign)
//!
//! Capacity is enforced by holding BOTH queue locks during the
//! check-and-push critical section. This eliminates:
//! - The CAS-counter + DepthGuard race (R13 W3 + W4) where producers
//!   could observe stale "full" state during a consumer's
//!   pop-then-decrement window.
//! - The unbounded spin loop blocking the tokio executor under heavy
//!   contention.
//! - The need for `std::sync::atomic` depth_counter at all.
//!
//! Lock order: `high_priority` first, then `queue`. `recv` / `poll` only
//! hold one at a time, so no deadlock with deliver.
//!
//! `MailboxStore` is the per-process registry of mailboxes keyed by
//! agent id. Slice A uses lazy creation (`get_or_create`) so the
//! `MailboxDispatcher::deliver` path doesn't need an explicit
//! registration step.
//!
//! # Slice A scope (with slice-C Layer-4 freeze-gate retrofit)
//!
//! - `freeze` / `unfreeze` / `is_frozen` are atomic toggles. Slice A
//!   shipped them as observable-only (the `deliver` path NEVER consults
//!   `frozen`). Slice C adds the Layer-4 recv-side gate: `Mailbox::recv`
//!   and `Mailbox::poll` consult `is_frozen()` and hold/None-return while
//!   set; `unfreeze()` calls `self.notify.notify_one()` to wake the
//!   waiting recv. **`Mailbox::deliver` deliberately remains freeze-blind**
//!   — Layer 1 (rejecting NEW deliveries when the breaker is open) is the
//!   dispatcher's job (`MailboxDispatcherImpl::deliver` queries
//!   CONTRACT-002 `CircuitBreakerBus::is_open_agent` before reaching the
//!   mailbox). Slice-A regression-lock `t_a03c_freeze_toggle_observable`
//!   in `tests/mailbox_capacity.rs` is preserved verbatim by this split.
//!   See MODULE-006 §3.8 (f) for the two-layer rationale.
//! - The Layer-4 production driver — a BreakerEvent subscriber task that
//!   consumes `CircuitBreakerBus::subscribe()` and matches `BreakerEvent`
//!   records with `new_state == BreakerState::Open` / `Closed` for
//!   `BreakerScope::Agent`, routing to per-agent `Mailbox::freeze` /
//!   `unfreeze` — is the next slice's work. Slice C ships the recv/poll
//!   mechanism; the trigger is deferred.
//! - No `MailboxReader` trait impl; a later slice will add it with the
//!   state-store persistence required by invariant 3.

use std::collections::{HashMap, VecDeque};
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use advance_shared_types::await_session::SessionId;
use advance_shared_types::mailbox::{
    DequeuedTurnGuard, DequeuedTurnRecoveryLatch, MailboxTurnEnvelope, MailboxTurnIdentity,
    Message, MessageContext, MessageKind, MsgError,
};
use advance_shared_types::turn_attribution::{
    ConfirmedAdmissionCleanupToken, DequeuedTurnHandle, MailboxAdmissionIssuer,
    MailboxAdmissionReceipt, MailboxDequeueIssuer, MailboxDequeueReceipt, MailboxEntryFacts,
    MailboxPublishPermit, MailboxPublishVerifier, MailboxRemovalAuthority, MailboxRemovalIssuer,
    QueuedTurnSpec, RecordedDequeueHandoff, RegisteredTurnHandle, TurnCompletionOwner,
    TurnDispatchLifecyclePort, TurnExecutionLifecyclePort, TurnMailboxError,
    TurnMailboxLifecyclePort, VerifiedMailboxPublish,
};

use crate::id_validation::MAX_ID_BYTES;

/// Returns Err if any `Option<String>` field in `ctx` exceeds `MAX_ID_BYTES`.
/// Adversarial-R14 W1 fix — close the unbounded-MessageContext-field DoS.
///
/// `pub(crate)` (slice B): `dispatcher.rs`'s `notify_agent` / `notify_channel`
/// reuse this exact context-byte-cap check rather than duplicating it (keeps
/// the slice-A bound authoritative in one place). No behavior change.
pub(crate) fn validate_message_context(ctx: &MessageContext) -> Result<(), MsgError> {
    let too_large =
        |s: &Option<String>| -> bool { s.as_ref().is_some_and(|v| v.len() > MAX_ID_BYTES) };
    if too_large(&ctx.task_id)
        || too_large(&ctx.run_id)
        || too_large(&ctx.execution_id)
        || too_large(&ctx.trace_id)
        || too_large(&ctx.in_reply_to)
        || too_large(&ctx.correlation_id)
    {
        return Err(MsgError::InvalidPayload("context_field_too_large".into()));
    }
    Ok(())
}

/// Default per-mailbox capacity (MODULE-006 §2.10 `mailbox.capacity`).
pub const DEFAULT_CAPACITY: NonZeroUsize = match NonZeroUsize::new(100) {
    Some(n) => n,
    None => unreachable!(),
};

/// Hard upper bound on the per-process registry size — operational
/// guarantee. `AgentTreeSnapshot` invariant 2 caps the tree at 1024
/// agents; 10K is ~10× that. Adversarial-R11 fix: returning the cap
/// is a typed `MsgError::CapabilityDenied("registry_full")` rather
/// than an `assert!` panic — see `MailboxStore::get_or_create`.
pub const MAX_MAILBOXES: usize = 10_000;

/// Per-message payload upper bound — defense-in-depth at the
/// dispatcher boundary (the shared-types rustdoc recommends ≤ 1 MiB
/// at the deserialize layer; slice A re-enforces at the in-process
/// queue boundary). Returns `MsgError::InvalidPayload("payload_too_large")`
/// on violation. Adversarial-R11 fix.
pub const MAX_PAYLOAD_BYTES: usize = 1_048_576;

/// Per-message `MessageOrigin.channel_metadata` entry-count upper bound —
/// shared-types-recommended ≤ 32. Slice-A defense-in-depth check in
/// `Mailbox::deliver`. Returns `MsgError::InvalidPayload("metadata_oversize")`.
/// Adversarial-R11 fix.
pub const MAX_METADATA_ENTRIES: usize = 32;

/// Per-entry `MessageOrigin.channel_metadata` key + value byte cap —
/// shared-types-recommended ≤ 256 bytes per value. Slice A also bounds
/// keys at the same limit. Returns `MsgError::InvalidPayload(
/// "metadata_entry_too_large")`. Adversarial-R14 fix.
pub const MAX_METADATA_ENTRY_BYTES: usize = 256;

/// One host-owned protected delivery request. `spec.turn_id` must equal the
/// message id; callers synthesize parent/session/slot from authenticated host
/// routing state, never from guest payload bytes.
pub struct TurnMailboxDelivery {
    pub target: String,
    pub message: Message,
    pub spec: QueuedTurnSpec,
}

/// Opaque prepared batch retained by the await/session owner before any entry
/// becomes dequeue-visible. Registered handles stay here until terminal detach.
pub struct PreparedTurnBatch {
    store: Arc<MailboxStore>,
    session_id: Option<SessionId>,
    completion_owner: Option<TurnCompletionOwner>,
    entries: Vec<PreparedTurnEntry>,
    registered: Vec<RegisteredTurnHandle>,
    outcomes: Vec<Result<(), MsgError>>,
    barrier: Arc<AtomicBool>,
    published: bool,
    detached: bool,
}

struct FailedBatchRecovery {
    session_id: Option<SessionId>,
    completion_owner: Option<TurnCompletionOwner>,
    entries: Vec<PreparedTurnEntry>,
    registered: Vec<RegisteredTurnHandle>,
    barrier: Arc<AtomicBool>,
    published: bool,
}

struct QueuedRemovalRecovery {
    cleanup: advance_shared_types::turn_attribution::QueuedDetachCleanupToken,
    guard: Option<ExactRemovalGuard>,
}

struct NeverAdmittedRecovery {
    mailbox: std::sync::Weak<Mailbox>,
    physical_entry_expected: bool,
    reservation: advance_shared_types::turn_attribution::QueuedTurnReservation,
    facts: MailboxEntryFacts,
}

impl Drop for PreparedTurnBatch {
    fn drop(&mut self) {
        if self.detached || self.entries.is_empty() {
            return;
        }
        let store = Arc::clone(&self.store);
        let result = if self.published {
            match (&self.completion_owner, self.session_id.clone()) {
                (Some(TurnCompletionOwner::AwaitSession), Some(session_id)) => {
                    store.detach_turn_batch(&session_id, self)
                }
                // ExecutionBoundary publication transfers lifetime authority
                // to the protected mailbox entry and then its dequeue/start
                // guard. Producer-scope Drop must not synthesize an await
                // detach and remove a turn before the scheduler can execute it.
                (Some(TurnCompletionOwner::ExecutionBoundary), _) => return,
                _ => Err(MsgError::CapabilityDenied("turn-state-conflict".into())),
            }
        } else {
            store.rollback_prepared(self)
        };
        if result.is_err() && !self.detached {
            store.latch_failed_batch(self);
        }
    }
}

impl PreparedTurnBatch {
    pub fn outcomes(&self) -> &[Result<(), MsgError>] {
        &self.outcomes
    }

    pub fn registered_turns(&self) -> &[RegisteredTurnHandle] {
        &self.registered
    }

    pub fn completion_owner(&self) -> Option<&TurnCompletionOwner> {
        self.completion_owner.as_ref()
    }
}

struct PreparedTurnEntry {
    mailbox: Arc<Mailbox>,
    staged_entry_id: [u8; 16],
    publish: Option<MailboxPublishPermit>,
    cleanup: Option<ConfirmedAdmissionCleanupToken>,
    outcome_index: usize,
}

struct TurnMailboxAuthority {
    admission: Mutex<MailboxAdmissionIssuer>,
    removal: Mutex<MailboxRemovalIssuer>,
    dequeue: Mutex<MailboxDequeueIssuer>,
    publish: Mutex<MailboxPublishVerifier>,
    dispatch: Arc<dyn TurnDispatchLifecyclePort>,
    lifecycle: Arc<dyn TurnMailboxLifecyclePort>,
    execution: Arc<dyn TurnExecutionLifecyclePort>,
    before_start_recovery: Mutex<Vec<DequeuedTurnHandle>>,
    dequeue_recovery: Mutex<Vec<LatchedMailboxDequeue>>,
}

// `protected`/`recorded` are custody-not-read: holding them keeps the latched
// dequeue's role values alive and single-provider until recovery replays them.
#[allow(dead_code)]
struct LatchedMailboxDequeue {
    protected: ProtectedTurnEntry,
    receipt: MailboxDequeueReceipt,
    recorded: RecordedDequeueHandoff,
}

impl DequeuedTurnRecoveryLatch for TurnMailboxAuthority {
    fn latch_before_start(&self, handle: DequeuedTurnHandle) {
        let mut pending = self
            .before_start_recovery
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // The provider's global entry cap is 4096 and this Vec is allocated to
        // that bound at composition, so a live handle always has one slot.
        assert!(pending.len() < MAX_TURN_RECOVERY_LATCHES);
        pending.push(handle);
    }
}

const MAX_TURN_RECOVERY_LATCHES: usize = 4096;

struct StagedTurnEntry {
    message: Message,
    facts: MailboxEntryFacts,
    admission: Option<MailboxAdmissionReceipt>,
}

struct ProtectedTurnEntry {
    message: Message,
    facts: MailboxEntryFacts,
    admission: MailboxAdmissionReceipt,
    published: VerifiedMailboxPublish,
    dispatch_barrier: Arc<AtomicBool>,
    dispatch_barrier_lease_digest: [u8; 32],
}

enum MailboxEntry {
    Legacy(Message),
    Protected(ProtectedTurnEntry),
}

#[derive(Clone, Copy)]
enum QueuePriority {
    High,
    Normal,
}

struct TakenMailboxEntry {
    priority: QueuePriority,
    index: usize,
    entry: MailboxEntry,
}

enum ExactRemovalLocation {
    Staged([u8; 16]),
    Queued {
        priority: QueuePriority,
        index: usize,
    },
}

enum ExactRemovedEntry {
    Staged(StagedTurnEntry),
    Queued(MailboxEntry),
}

/// Physical exact-take authority. The entry is removed before a provider
/// transition is attempted; failure/unwind restores it at the same logical
/// location, while success explicitly discards it.
struct ExactRemovalGuard {
    mailbox: Arc<Mailbox>,
    location: ExactRemovalLocation,
    entry: Option<ExactRemovedEntry>,
    receipt: Option<advance_shared_types::turn_attribution::MailboxRemovalReceipt>,
}

impl ExactRemovalGuard {
    fn attach_receipt(
        &mut self,
        receipt: advance_shared_types::turn_attribution::MailboxRemovalReceipt,
    ) {
        debug_assert!(self.receipt.is_none());
        self.receipt = Some(receipt);
    }

    fn receipt(&self) -> &advance_shared_types::turn_attribution::MailboxRemovalReceipt {
        self.receipt.as_ref().expect("sealed exact-removal guard")
    }

    fn removal_facts(&self) -> (&MailboxEntryFacts, Option<&MailboxAdmissionReceipt>) {
        match self.entry.as_ref().expect("live exact-removal guard") {
            ExactRemovedEntry::Staged(entry) => (&entry.facts, entry.admission.as_ref()),
            ExactRemovedEntry::Queued(MailboxEntry::Protected(entry)) => {
                (&entry.facts, Some(&entry.admission))
            }
            ExactRemovedEntry::Queued(MailboxEntry::Legacy(_)) => {
                unreachable!("legacy entry cannot carry turn-removal authority")
            }
        }
    }

    fn discard(mut self) {
        self.entry.take();
    }
}

impl Drop for ExactRemovalGuard {
    fn drop(&mut self) {
        let Some(entry) = self.entry.take() else {
            return;
        };
        // Exact restoration cannot fail from transient contention: this is a
        // synchronous std mutex with one global queue lock order. Poison is
        // recovered because preserving a removed linear entry is safer than
        // silently dropping it.
        match (&self.location, entry) {
            (ExactRemovalLocation::Staged(staged_entry_id), ExactRemovedEntry::Staged(entry)) => {
                let mut staged = self
                    .mailbox
                    .staged
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                assert!(staged.insert(*staged_entry_id, entry).is_none());
            }
            (
                ExactRemovalLocation::Queued { priority, index },
                ExactRemovedEntry::Queued(entry),
            ) => {
                let queue = match priority {
                    QueuePriority::High => &self.mailbox.high_priority,
                    QueuePriority::Normal => &self.mailbox.queue,
                };
                let mut queue = queue
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                let restore_index = (*index).min(queue.len());
                queue.insert(restore_index, entry);
                self.mailbox.notify.notify_one();
            }
            _ => unreachable!("exact-removal location/entry mismatch"),
        }
    }
}

enum ProtectedCompletionError {
    Restore(TurnMailboxError, ProtectedTurnEntry),
    Discard(TurnMailboxError),
    Latched(TurnMailboxError),
}

impl MailboxEntry {
    fn is_legacy(&self) -> bool {
        matches!(self, Self::Legacy(_))
    }

    fn is_dequeue_visible(&self) -> bool {
        match self {
            Self::Legacy(_) => true,
            Self::Protected(entry) => entry.dispatch_barrier.load(Ordering::Acquire),
        }
    }
}

fn validate_message(msg: &Message) -> Result<(), MsgError> {
    if msg.payload.len() > MAX_PAYLOAD_BYTES {
        return Err(MsgError::InvalidPayload("payload_too_large".into()));
    }
    if msg.id.len() > MAX_ID_BYTES || msg.from.len() > MAX_ID_BYTES || msg.to.len() > MAX_ID_BYTES {
        return Err(MsgError::InvalidPayload("header_too_large".into()));
    }
    if let Some(origin) = &msg.origin {
        if origin.channel_metadata.len() > MAX_METADATA_ENTRIES {
            return Err(MsgError::InvalidPayload("metadata_oversize".into()));
        }
        if origin.message_id.len() > MAX_ID_BYTES
            || origin.original_channel.len() > MAX_ID_BYTES
            || origin.original_sender.len() > MAX_ID_BYTES
            || origin.adapter_id.len() > MAX_ID_BYTES
        {
            return Err(MsgError::InvalidPayload("origin_header_too_large".into()));
        }
        for (key, value) in &origin.channel_metadata {
            if key.len() > MAX_METADATA_ENTRY_BYTES || value.len() > MAX_METADATA_ENTRY_BYTES {
                return Err(MsgError::InvalidPayload("metadata_entry_too_large".into()));
            }
        }
        if let Some(context) = &origin.context {
            validate_message_context(context)?;
        }
    }
    if let Some(context) = &msg.context {
        validate_message_context(context)?;
    }
    Ok(())
}

/// Per-agent bounded queue with priority ordering. See module rustdoc
/// for slice-A scope.
pub struct Mailbox {
    capacity: NonZeroUsize,
    queue: Mutex<VecDeque<MailboxEntry>>,
    high_priority: Mutex<VecDeque<MailboxEntry>>,
    staged: Mutex<HashMap<[u8; 16], StagedTurnEntry>>,
    incarnation: [u8; 16],
    turn_authority: Option<Arc<TurnMailboxAuthority>>,
    frozen: AtomicBool,
    notify: tokio::sync::Notify,
}

impl Mailbox {
    pub fn new(capacity: NonZeroUsize) -> Self {
        Self::new_inner(capacity, None)
    }

    fn new_inner(
        capacity: NonZeroUsize,
        turn_authority: Option<Arc<TurnMailboxAuthority>>,
    ) -> Self {
        Self {
            capacity,
            queue: Mutex::new(VecDeque::new()),
            high_priority: Mutex::new(VecDeque::new()),
            staged: Mutex::new(HashMap::new()),
            incarnation: *uuid::Uuid::new_v4().as_bytes(),
            turn_authority,
            frozen: AtomicBool::new(false),
            notify: tokio::sync::Notify::new(),
        }
    }

    /// Sync deliver — capacity check is exact (both queue locks held
    /// during check + push). No CAS spin, no atomic counter race.
    ///
    /// Defense-in-depth (Adversarial-R11/R13): reject oversized payload,
    /// oversized origin metadata, and oversized header strings BEFORE
    /// taking any queue lock. The shared-types rustdoc recommends ≤ 256
    /// bytes for id/from/to/origin string fields at the deserialize
    /// boundary; slice A re-enforces here as defense-in-depth.
    pub fn deliver(&self, msg: Message) -> Result<(), MsgError> {
        validate_message(&msg)?;
        let cap = self.capacity.get();
        let is_high = matches!(msg.kind, MessageKind::User | MessageKind::Control);
        // `staged -> high_priority -> queue` is the sole multi-lock order.
        // Counting hidden staging prevents legacy deliveries racing the
        // reservation path above the configured capacity.
        let staged = self.staged.lock().expect("staged mutex poisoned");
        let mut hp = self.high_priority.lock().expect("hp mutex poisoned");
        let mut q = self.queue.lock().expect("queue mutex poisoned");
        if staged.len() + hp.len() + q.len() >= cap {
            return Err(MsgError::MailboxFull);
        }
        if is_high {
            hp.push_back(MailboxEntry::Legacy(msg));
        } else {
            q.push_back(MailboxEntry::Legacy(msg));
        }
        drop(q);
        drop(hp);
        drop(staged);
        self.notify.notify_one();
        Ok(())
    }

    fn facts_for(&self, msg: &Message, spec: &QueuedTurnSpec) -> MailboxEntryFacts {
        MailboxEntryFacts {
            turn_id: spec.turn_id.clone(),
            expected_agent: spec.expected_agent.clone(),
            message_id: msg.id.clone(),
            mailbox_incarnation: self.incarnation,
            staged_entry_id: *uuid::Uuid::new_v4().as_bytes(),
        }
    }

    fn stage_reserved(
        &self,
        msg: Message,
        spec: &QueuedTurnSpec,
        facts: MailboxEntryFacts,
    ) -> Result<(), MsgError> {
        validate_message(&msg)?;
        spec.validate()
            .map_err(|error| MsgError::CapabilityDenied(error.code().to_string()))?;
        if msg.id != spec.turn_id || msg.to != spec.expected_agent {
            return Err(MsgError::CapabilityDenied("turn-invalid".into()));
        }
        let staged_entry_id = facts.staged_entry_id;
        let mut staged = self.staged.lock().expect("staged mutex poisoned");
        let hp = self.high_priority.lock().expect("hp mutex poisoned");
        let q = self.queue.lock().expect("queue mutex poisoned");
        if staged.len() + hp.len() + q.len() >= self.capacity.get() {
            return Err(MsgError::MailboxFull);
        }
        staged.insert(
            staged_entry_id,
            StagedTurnEntry {
                message: msg,
                facts: facts.clone(),
                admission: None,
            },
        );
        Ok(())
    }

    fn attach_admission(
        &self,
        staged_entry_id: [u8; 16],
        admission: MailboxAdmissionReceipt,
    ) -> Result<(), TurnMailboxError> {
        let mut staged = self.staged.lock().map_err(|_| TurnMailboxError::Busy)?;
        let entry = staged
            .get_mut(&staged_entry_id)
            .ok_or(TurnMailboxError::StateConflict)?;
        if entry.admission.is_some() {
            return Err(TurnMailboxError::Replayed);
        }
        entry.admission = Some(admission);
        Ok(())
    }

    #[allow(dead_code)] // designed staging-abort surface; the producing failure path is wired in a later slice
    fn discard_staged(&self, staged_entry_id: [u8; 16]) {
        if let Ok(mut staged) = self.staged.lock() {
            staged.remove(&staged_entry_id);
        }
    }

    fn publish_staged(
        &self,
        staged_entry_id: [u8; 16],
        permit: MailboxPublishPermit,
        barrier: Arc<AtomicBool>,
        barrier_digest: [u8; 32],
    ) -> Result<(), TurnMailboxError> {
        let authority = self
            .turn_authority
            .as_ref()
            .ok_or(TurnMailboxError::StateConflict)?;
        let mut staged = self.staged.lock().map_err(|_| TurnMailboxError::Busy)?;
        let entry = staged
            .get(&staged_entry_id)
            .ok_or(TurnMailboxError::StateConflict)?;
        let admission = entry
            .admission
            .as_ref()
            .ok_or(TurnMailboxError::StateConflict)?;
        let published = authority
            .publish
            .lock()
            .map_err(|_| TurnMailboxError::Busy)?
            .verify_publish(permit, admission, &entry.facts)?;
        let mut hp = self
            .high_priority
            .lock()
            .map_err(|_| TurnMailboxError::Busy)?;
        let mut q = self.queue.lock().map_err(|_| TurnMailboxError::Busy)?;
        let staged_entry = staged
            .remove(&staged_entry_id)
            .ok_or(TurnMailboxError::StateConflict)?;
        let protected = MailboxEntry::Protected(ProtectedTurnEntry {
            message: staged_entry.message,
            facts: staged_entry.facts,
            admission: staged_entry
                .admission
                .ok_or(TurnMailboxError::StateConflict)?,
            published,
            dispatch_barrier: barrier,
            dispatch_barrier_lease_digest: barrier_digest,
        });
        if matches!(
            &protected,
            MailboxEntry::Protected(entry)
                if matches!(entry.message.kind, MessageKind::User | MessageKind::Control)
        ) {
            hp.push_back(protected);
        } else {
            q.push_back(protected);
        }
        Ok(())
    }

    /// Tokio Notify lossless pattern: register the Notified future BEFORE
    /// checking queues so any concurrent `notify_one` is either delivered
    /// to this future or recorded as a permit consumed by the subsequent
    /// `notified.await`.
    ///
    /// Slice-C Layer-4 freeze gate: after the lossless pre-registration but
    /// BEFORE the queue pops, consult `is_frozen()`. When frozen, await the
    /// next `notify_one` (delivered either by a producer's `deliver` or by
    /// `unfreeze`) and continue the loop — the next iteration re-checks
    /// `is_frozen()`. No mid-queue traversal, no pop-then-push-front. Holds
    /// ALL kinds during freeze (admin-bypass for Control is Layer 1's job at
    /// the dispatcher; close-recovery naturally drains high-priority first
    /// because slice-A's pop order is `high_priority` → normal). See
    /// MODULE-006 §3.8 (f) (i)/(ii)/(vii) for the layer split + ordering.
    pub async fn recv(&self) -> Message {
        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.is_frozen() {
                notified.await;
                continue;
            }
            {
                let mut hp = self.high_priority.lock().expect("hp mutex poisoned");
                if let Some(index) = hp.iter().position(MailboxEntry::is_legacy) {
                    if let Some(MailboxEntry::Legacy(message)) = hp.remove(index) {
                        return message;
                    }
                }
            }
            {
                let mut q = self.queue.lock().expect("queue mutex poisoned");
                if let Some(index) = q.iter().position(MailboxEntry::is_legacy) {
                    if let Some(MailboxEntry::Legacy(message)) = q.remove(index) {
                        return message;
                    }
                }
            }
            notified.await;
        }
    }

    /// C216-aware receive. A protected entry is removed, recorded, and handed
    /// off under one synchronous guard; every failure restores the exact queue
    /// position before the typed error escapes.
    pub async fn recv_turn(&self) -> Result<MailboxTurnEnvelope, TurnMailboxError> {
        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.is_frozen() {
                notified.await;
                continue;
            }
            if let Some(taken) = self.take_visible_entry(false)? {
                return self.complete_taken(taken);
            }
            notified.await;
        }
    }

    /// Sync, non-blocking poll using try_lock semantics. Contention →
    /// returns None even if a message is present (caller treats as "no
    /// message available right now"). Satisfies shared-types
    /// `MailboxReader` invariant 1 for future MailboxReader integration.
    ///
    /// Slice-C Layer-4 freeze gate: returns `None` unconditionally when
    /// frozen, regardless of kind. The slice-A `try_lock` semantics are
    /// preserved verbatim for the unfrozen case. See MODULE-006 §3.8 (f)
    /// (viii) for the unfrozen-vs-frozen split.
    pub fn poll(&self) -> Option<Message> {
        if self.is_frozen() {
            return None;
        }
        if let Ok(mut hp) = self.high_priority.try_lock() {
            if let Some(index) = hp.iter().position(MailboxEntry::is_legacy) {
                if let Some(MailboxEntry::Legacy(message)) = hp.remove(index) {
                    return Some(message);
                }
            }
        }
        if let Ok(mut q) = self.queue.try_lock() {
            if let Some(index) = q.iter().position(MailboxEntry::is_legacy) {
                if let Some(MailboxEntry::Legacy(message)) = q.remove(index) {
                    return Some(message);
                }
            }
        }
        None
    }

    pub fn poll_turn(&self) -> Result<Option<MailboxTurnEnvelope>, TurnMailboxError> {
        if self.is_frozen() {
            return Ok(None);
        }
        self.take_visible_entry(true)?
            .map(|taken| self.complete_taken(taken))
            .transpose()
    }

    fn take_visible_entry(
        &self,
        nonblocking: bool,
    ) -> Result<Option<TakenMailboxEntry>, TurnMailboxError> {
        let take = |queue: &mut VecDeque<MailboxEntry>, priority| {
            let index = queue.iter().position(MailboxEntry::is_dequeue_visible)?;
            queue.remove(index).map(|entry| TakenMailboxEntry {
                priority,
                index,
                entry,
            })
        };
        if nonblocking {
            if let Ok(mut hp) = self.high_priority.try_lock() {
                if let Some(entry) = take(&mut hp, QueuePriority::High) {
                    return Ok(Some(entry));
                }
            }
            if let Ok(mut q) = self.queue.try_lock() {
                if let Some(entry) = take(&mut q, QueuePriority::Normal) {
                    return Ok(Some(entry));
                }
            }
            return Ok(None);
        }
        {
            let mut hp = self
                .high_priority
                .lock()
                .map_err(|_| TurnMailboxError::Busy)?;
            if let Some(entry) = take(&mut hp, QueuePriority::High) {
                return Ok(Some(entry));
            }
        }
        let mut q = self.queue.lock().map_err(|_| TurnMailboxError::Busy)?;
        Ok(take(&mut q, QueuePriority::Normal))
    }

    fn complete_taken(
        &self,
        taken: TakenMailboxEntry,
    ) -> Result<MailboxTurnEnvelope, TurnMailboxError> {
        let TakenMailboxEntry {
            priority,
            index,
            entry,
        } = taken;
        match entry {
            MailboxEntry::Legacy(message) => Ok(MailboxTurnEnvelope::legacy(message)),
            MailboxEntry::Protected(protected) => match self.complete_protected(protected) {
                Ok(envelope) => Ok(envelope),
                Err(ProtectedCompletionError::Restore(error, protected)) => {
                    self.restore_entry(priority, index, MailboxEntry::Protected(protected))?;
                    Err(error)
                }
                Err(
                    ProtectedCompletionError::Discard(error)
                    | ProtectedCompletionError::Latched(error),
                ) => Err(error),
            },
        }
    }

    fn complete_protected(
        &self,
        protected: ProtectedTurnEntry,
    ) -> Result<MailboxTurnEnvelope, ProtectedCompletionError> {
        let Some(authority) = self.turn_authority.as_ref() else {
            return Err(ProtectedCompletionError::Restore(
                TurnMailboxError::StateConflict,
                protected,
            ));
        };
        let prepared = match authority
            .dequeue
            .lock()
            .map_err(|_| TurnMailboxError::Busy)
            .and_then(|mut issuer| {
                issuer.prepare_visible_dequeue(
                    &protected.published,
                    &protected.facts,
                    protected.dispatch_barrier_lease_digest,
                )
            }) {
            Ok(prepared) => prepared,
            Err(error) => return Err(ProtectedCompletionError::Restore(error, protected)),
        };
        let receipt = prepared.commit_exact_take();
        let recorded = match authority.lifecycle.record_dequeued(&receipt) {
            Ok(recorded) => recorded,
            Err(error) => return Err(ProtectedCompletionError::Restore(error, protected)),
        };
        let dequeued = match authority
            .lifecycle
            .complete_dequeue_handoff(&receipt, &recorded)
        {
            Ok(dequeued) => dequeued,
            Err(error) => {
                if authority.lifecycle.abandon_dequeuing(&receipt).is_ok() {
                    return Err(ProtectedCompletionError::Discard(error));
                }
                let mut pending = authority
                    .dequeue_recovery
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                assert!(pending.len() < MAX_TURN_RECOVERY_LATCHES);
                pending.push(LatchedMailboxDequeue {
                    protected,
                    receipt,
                    recorded,
                });
                return Err(ProtectedCompletionError::Latched(error));
            }
        };
        let identity = MailboxTurnIdentity {
            turn_id: protected.facts.turn_id.clone(),
            expected_agent: protected.facts.expected_agent.clone(),
        };
        let recovery: Arc<dyn DequeuedTurnRecoveryLatch> = authority.clone();
        let guard =
            DequeuedTurnGuard::from_mailbox(dequeued, Arc::clone(&authority.execution), recovery);
        Ok(MailboxTurnEnvelope::protected(
            protected.message,
            identity,
            guard,
        ))
    }

    fn restore_entry(
        &self,
        priority: QueuePriority,
        index: usize,
        entry: MailboxEntry,
    ) -> Result<(), TurnMailboxError> {
        let queue = match priority {
            QueuePriority::High => &self.high_priority,
            QueuePriority::Normal => &self.queue,
        };
        let mut queue = queue.lock().map_err(|_| TurnMailboxError::Busy)?;
        let restore_index = index.min(queue.len());
        queue.insert(restore_index, entry);
        self.notify.notify_one();
        Ok(())
    }

    fn take_never_admitted_removal(
        self: &Arc<Self>,
        reservation: &advance_shared_types::turn_attribution::QueuedTurnReservation,
        facts: &MailboxEntryFacts,
        authority: &TurnMailboxAuthority,
    ) -> Result<ExactRemovalGuard, MsgError> {
        let mut staged = self
            .staged
            .lock()
            .map_err(|_| MsgError::CapabilityDenied("turn-busy".into()))?;
        let entry = staged
            .remove(&facts.staged_entry_id)
            .ok_or_else(|| map_turn_mailbox(TurnMailboxError::StateConflict))?;
        // Install restoration authority immediately after the physical take,
        // before receipt issuance or any other fallible/provider code.
        let mut guard = ExactRemovalGuard {
            mailbox: Arc::clone(self),
            location: ExactRemovalLocation::Staged(facts.staged_entry_id),
            entry: Some(ExactRemovedEntry::Staged(entry)),
            receipt: None,
        };
        drop(staged);
        if guard.removal_facts().0 != facts {
            return Err(map_turn_mailbox(TurnMailboxError::ReceiptRejected));
        }
        let receipt = authority
            .removal
            .lock()
            .map_err(|_| map_turn_mailbox(TurnMailboxError::Busy))
            .and_then(|mut issuer| {
                issuer
                    .seal_exact_removal(
                        MailboxRemovalAuthority::NeverAdmitted(reservation),
                        None,
                        facts,
                    )
                    .map_err(map_turn_mailbox)
            });
        match receipt {
            Ok(receipt) => {
                guard.attach_receipt(receipt);
                Ok(guard)
            }
            Err(error) => Err(error),
        }
    }

    fn take_confirmed_removal(
        self: &Arc<Self>,
        staged_entry_id: [u8; 16],
        cleanup: &ConfirmedAdmissionCleanupToken,
        authority: &TurnMailboxAuthority,
    ) -> Result<ExactRemovalGuard, MsgError> {
        {
            let mut staged = self
                .staged
                .lock()
                .map_err(|_| map_turn_mailbox(TurnMailboxError::Busy))?;
            if let Some(entry) = staged.remove(&staged_entry_id) {
                let mut guard = ExactRemovalGuard {
                    mailbox: Arc::clone(self),
                    location: ExactRemovalLocation::Staged(staged_entry_id),
                    entry: Some(ExactRemovedEntry::Staged(entry)),
                    receipt: None,
                };
                drop(staged);
                let receipt = guard
                    .removal_facts()
                    .1
                    .ok_or_else(|| map_turn_mailbox(TurnMailboxError::StateConflict))
                    .and_then(|admission| {
                        let facts = guard.removal_facts().0;
                        authority
                            .removal
                            .lock()
                            .map_err(|_| map_turn_mailbox(TurnMailboxError::Busy))?
                            .seal_exact_removal(
                                MailboxRemovalAuthority::Confirmed(cleanup),
                                Some(admission),
                                facts,
                            )
                            .map_err(map_turn_mailbox)
                    });
                return match receipt {
                    Ok(receipt) => {
                        guard.attach_receipt(receipt);
                        Ok(guard)
                    }
                    Err(error) => Err(error),
                };
            }
        }
        for (priority, queue) in [
            (QueuePriority::High, &self.high_priority),
            (QueuePriority::Normal, &self.queue),
        ] {
            let mut queue = queue
                .lock()
                .map_err(|_| map_turn_mailbox(TurnMailboxError::Busy))?;
            let Some(index) = queue.iter().position(|entry| {
                matches!(entry, MailboxEntry::Protected(protected)
                    if protected.facts.staged_entry_id == staged_entry_id
                        && !protected.dispatch_barrier.load(Ordering::Acquire))
            }) else {
                continue;
            };
            let entry = queue
                .remove(index)
                .ok_or_else(|| map_turn_mailbox(TurnMailboxError::StateConflict))?;
            let mut guard = ExactRemovalGuard {
                mailbox: Arc::clone(self),
                location: ExactRemovalLocation::Queued { priority, index },
                entry: Some(ExactRemovedEntry::Queued(entry)),
                receipt: None,
            };
            drop(queue);
            let (facts, admission) = guard.removal_facts();
            let Some(admission) = admission else {
                return Err(map_turn_mailbox(TurnMailboxError::StateConflict));
            };
            let receipt = authority
                .removal
                .lock()
                .map_err(|_| map_turn_mailbox(TurnMailboxError::Busy))?
                .seal_exact_removal(
                    MailboxRemovalAuthority::Confirmed(cleanup),
                    Some(admission),
                    facts,
                )
                .map_err(map_turn_mailbox);
            return match receipt {
                Ok(receipt) => {
                    guard.attach_receipt(receipt);
                    Ok(guard)
                }
                Err(error) => Err(error),
            };
        }
        Err(map_turn_mailbox(TurnMailboxError::StateConflict))
    }

    fn rollback_confirmed_in_place(
        self: &Arc<Self>,
        staged_entry_id: [u8; 16],
        cleanup: &ConfirmedAdmissionCleanupToken,
        authority: &TurnMailboxAuthority,
    ) -> Result<(), MsgError> {
        let guard = self.take_confirmed_removal(staged_entry_id, cleanup, authority)?;
        authority
            .dispatch
            .abort_confirmed_admission(cleanup, guard.receipt())
            .map_err(map_turn_dispatch)?;
        guard.discard();
        Ok(())
    }

    fn take_queued_removal(
        self: &Arc<Self>,
        cleanup: &advance_shared_types::turn_attribution::QueuedDetachCleanupToken,
        authority: &TurnMailboxAuthority,
    ) -> Result<Option<ExactRemovalGuard>, TurnMailboxError> {
        for (priority, queue) in [
            (QueuePriority::High, &self.high_priority),
            (QueuePriority::Normal, &self.queue),
        ] {
            let mut search_from = 0;
            loop {
                let mut guard =
                    {
                        let mut queue = queue.lock().map_err(|_| TurnMailboxError::Busy)?;
                        let Some(index) = queue.iter().enumerate().skip(search_from).find_map(
                            |(index, entry)| {
                                matches!(entry, MailboxEntry::Protected(_)).then_some(index)
                            },
                        ) else {
                            break;
                        };
                        let entry = queue.remove(index).ok_or(TurnMailboxError::StateConflict)?;
                        ExactRemovalGuard {
                            mailbox: Arc::clone(self),
                            location: ExactRemovalLocation::Queued { priority, index },
                            entry: Some(ExactRemovedEntry::Queued(entry)),
                            receipt: None,
                        }
                    };
                let (facts, admission) = guard.removal_facts();
                let Some(admission) = admission else {
                    return Err(TurnMailboxError::StateConflict);
                };
                let receipt = authority
                    .removal
                    .lock()
                    .map_err(|_| TurnMailboxError::Busy)
                    .and_then(|mut issuer| {
                        issuer.seal_exact_removal(
                            MailboxRemovalAuthority::QueuedDetach(cleanup),
                            Some(admission),
                            facts,
                        )
                    });
                match receipt {
                    Ok(receipt) => {
                        guard.attach_receipt(receipt);
                        return Ok(Some(guard));
                    }
                    Err(TurnMailboxError::TokenRejected | TurnMailboxError::ReceiptRejected) => {
                        let next = match &guard.location {
                            ExactRemovalLocation::Queued { index, .. } => *index + 1,
                            ExactRemovalLocation::Staged(_) => unreachable!(),
                        };
                        drop(guard);
                        search_from = next;
                    }
                    Err(error) => return Err(error),
                }
            }
        }
        Ok(None)
    }

    fn wake_turn_reader(&self) {
        self.notify.notify_one();
    }

    /// Sync, non-blocking — uses `try_lock` per shared-types invariant 1
    /// (try-lock semantics; contention or no lock → returns 0). Returns
    /// the EXACT combined queue length when uncontended.
    pub fn depth(&self) -> usize {
        let hp_len = self
            .high_priority
            .try_lock()
            .map(|hp| hp.len())
            .unwrap_or(0);
        let q_len = self.queue.try_lock().map(|q| q.len()).unwrap_or(0);
        hp_len + q_len
    }

    /// Slice-C Layer-4 freeze flag. **`Mailbox::deliver` deliberately does
    /// NOT consult this flag** — Layer 1 (rejecting NEW deliveries when the
    /// breaker is open) is the dispatcher's job at
    /// `MailboxDispatcherImpl::deliver` / `reply` / `deliver_notify`, which
    /// query CONTRACT-002 `CircuitBreakerBus::is_open_agent` before reaching
    /// the mailbox. The freeze flag drives Layer 4 (holding OLD already-queued
    /// messages until close): `Mailbox::recv` awaits `notify_one` while
    /// frozen, and `Mailbox::poll` returns `None`. The slice-A regression-lock
    /// test `t_a03c_freeze_toggle_observable` is preserved by keeping
    /// `deliver` freeze-blind.
    ///
    /// In production, the future BreakerEvent subscriber slice consumes
    /// `CircuitBreakerBus::subscribe()` and matches `BreakerEvent` records
    /// with `new_state == BreakerState::Open` / `Closed` to route per-agent
    /// `freeze`/`unfreeze`. Until then, `freeze` is reachable only by tests
    /// + admin tooling (no automatic CB→freeze trigger).
    pub fn freeze(&self) {
        self.frozen.store(true, Ordering::Release);
    }

    /// Slice-C Layer-4: wakes any `recv` blocked on the freeze flag via
    /// `notify_one`. The next `recv` loop iteration re-checks `is_frozen()`
    /// (now false) and proceeds to pop. `notify_one` (not `notify_waiters`)
    /// is sufficient under the single-recv-per-agent design — see MODULE-006
    /// §3.8 (f) (vi).
    pub fn unfreeze(&self) {
        self.frozen.store(false, Ordering::Release);
        self.notify.notify_one();
    }

    pub fn is_frozen(&self) -> bool {
        self.frozen.load(Ordering::Acquire)
    }
}

/// Multi-agent mailbox registry keyed by agent id. Slice A uses lazy
/// creation gated upstream by `validate_routing`.
pub struct MailboxStore {
    mailboxes: RwLock<HashMap<String, Arc<Mailbox>>>,
    default_capacity: NonZeroUsize,
    turn_authority: Option<Arc<TurnMailboxAuthority>>,
    failed_batches: Mutex<Vec<FailedBatchRecovery>>,
    queued_removal_recovery: Mutex<Vec<QueuedRemovalRecovery>>,
    never_admitted_recovery: Mutex<Vec<NeverAdmittedRecovery>>,
}

impl MailboxStore {
    pub fn new(default_capacity: NonZeroUsize) -> Self {
        Self {
            mailboxes: RwLock::new(HashMap::new()),
            default_capacity,
            turn_authority: None,
            failed_batches: Mutex::new(Vec::with_capacity(MAX_TURN_RECOVERY_LATCHES)),
            queued_removal_recovery: Mutex::new(Vec::with_capacity(MAX_TURN_RECOVERY_LATCHES)),
            never_admitted_recovery: Mutex::new(Vec::with_capacity(MAX_TURN_RECOVERY_LATCHES)),
        }
    }

    /// Composition-only C216 constructor. Every protected producer, mailbox
    /// dequeue, queued detach, and rollback shares this single least-privilege
    /// authority bundle; legacy `deliver` remains available for explicitly
    /// unprotected control/run-interrupt traffic.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_turn_attribution(
        default_capacity: NonZeroUsize,
        admission: MailboxAdmissionIssuer,
        removal: MailboxRemovalIssuer,
        dequeue: MailboxDequeueIssuer,
        publish: MailboxPublishVerifier,
        dispatch: Arc<dyn TurnDispatchLifecyclePort>,
        lifecycle: Arc<dyn TurnMailboxLifecyclePort>,
        execution: Arc<dyn TurnExecutionLifecyclePort>,
    ) -> Self {
        Self {
            mailboxes: RwLock::new(HashMap::new()),
            default_capacity,
            turn_authority: Some(Arc::new(TurnMailboxAuthority {
                admission: Mutex::new(admission),
                removal: Mutex::new(removal),
                dequeue: Mutex::new(dequeue),
                publish: Mutex::new(publish),
                dispatch,
                lifecycle,
                execution,
                before_start_recovery: Mutex::new(Vec::with_capacity(MAX_TURN_RECOVERY_LATCHES)),
                dequeue_recovery: Mutex::new(Vec::with_capacity(MAX_TURN_RECOVERY_LATCHES)),
            })),
            failed_batches: Mutex::new(Vec::with_capacity(MAX_TURN_RECOVERY_LATCHES)),
            queued_removal_recovery: Mutex::new(Vec::with_capacity(MAX_TURN_RECOVERY_LATCHES)),
            never_admitted_recovery: Mutex::new(Vec::with_capacity(MAX_TURN_RECOVERY_LATCHES)),
        }
    }

    pub(crate) fn prepare_turn_batch(
        self: &Arc<Self>,
        deliveries: Vec<TurnMailboxDelivery>,
    ) -> PreparedTurnBatch {
        self.prepare_gated_turn_batch(deliveries.into_iter().map(Ok).collect())
    }

    /// Authenticated host ingress for a single POST/channel/root turn. This
    /// deliberately does not expose or reuse the agent-to-agent hierarchy
    /// dispatcher: the composition root has already authenticated the
    /// external producer, while this boundary verifies the exact canonical
    /// target/message/spec identity and always requires ExecutionBoundary
    /// ownership before reserving any authority.
    pub fn publish_execution_turn(
        self: &Arc<Self>,
        delivery: TurnMailboxDelivery,
    ) -> Result<(), MsgError> {
        delivery
            .spec
            .validate()
            .map_err(|error| MsgError::CapabilityDenied(error.code().into()))?;
        if delivery.spec.completion_owner != TurnCompletionOwner::ExecutionBoundary
            || delivery.spec.slot != 0
            || !delivery.spec.session_id.0.starts_with("exec_")
            || !delivery.target.starts_with("agent:")
            || delivery.target != delivery.message.to
            || delivery.target != delivery.spec.expected_agent
            || delivery.message.id != delivery.spec.turn_id
            || delivery.message.from != delivery.spec.parent_agent
        {
            return Err(MsgError::CapabilityDenied("turn-invalid".into()));
        }
        let mut batch = self.prepare_turn_batch(vec![delivery]);
        match batch.outcomes() {
            [Ok(())] => self.publish_prepared(&mut batch),
            [Err(error)] => Err(error.clone()),
            _ => Err(MsgError::CapabilityDenied("turn-state-conflict".into())),
        }
    }

    pub(crate) fn prepare_gated_turn_batch(
        self: &Arc<Self>,
        deliveries: Vec<Result<TurnMailboxDelivery, MsgError>>,
    ) -> PreparedTurnBatch {
        let shape = deliveries.iter().find_map(|delivery| {
            delivery.as_ref().ok().map(|delivery| {
                (
                    delivery.spec.session_id.clone(),
                    delivery.spec.completion_owner.clone(),
                )
            })
        });
        let shape_is_consistent = shape.as_ref().is_none_or(|(session_id, owner)| {
            deliveries
                .iter()
                .filter_map(|delivery| delivery.as_ref().ok())
                .all(|delivery| {
                    delivery.spec.session_id == *session_id
                        && delivery.spec.completion_owner == *owner
                })
        });
        let (session_id, completion_owner) = shape
            .map(|(session_id, owner)| (Some(session_id), Some(owner)))
            .unwrap_or((None, None));
        let barrier = Arc::new(AtomicBool::new(false));
        let mut batch = PreparedTurnBatch {
            store: Arc::clone(self),
            session_id,
            completion_owner,
            entries: Vec::with_capacity(deliveries.len()),
            registered: Vec::with_capacity(deliveries.len()),
            outcomes: Vec::with_capacity(deliveries.len()),
            barrier,
            published: false,
            detached: false,
        };
        if !shape_is_consistent {
            batch.outcomes = deliveries
                .iter()
                .map(|delivery| match delivery {
                    Ok(_) => Err(MsgError::CapabilityDenied("turn-state-conflict".into())),
                    Err(error) => Err(error.clone()),
                })
                .collect();
            return batch;
        }
        let Some(authority) = self.turn_authority.as_ref() else {
            batch.outcomes.resize_with(deliveries.len(), || {
                Err(MsgError::CapabilityDenied("turn-unavailable".into()))
            });
            return batch;
        };

        for (outcome_index, delivery) in deliveries.into_iter().enumerate() {
            let delivery = match delivery {
                Ok(delivery) => delivery,
                Err(error) => {
                    batch.outcomes.push(Err(error));
                    continue;
                }
            };
            let result = self.prepare_one_turn(authority, delivery, outcome_index);
            match result {
                Ok((entry, registered)) => {
                    batch.entries.push(entry);
                    batch.registered.push(registered);
                    batch.outcomes.push(Ok(()));
                }
                Err(error) => batch.outcomes.push(Err(error)),
            }
        }
        batch
    }

    fn prepare_one_turn(
        &self,
        authority: &Arc<TurnMailboxAuthority>,
        delivery: TurnMailboxDelivery,
        outcome_index: usize,
    ) -> Result<(PreparedTurnEntry, RegisteredTurnHandle), MsgError> {
        let mailbox = self.get_or_create(&delivery.target)?;
        let facts = mailbox.facts_for(&delivery.message, &delivery.spec);
        let reservation = authority
            .dispatch
            .reserve_queued(delivery.spec.clone())
            .map_err(map_turn_dispatch)?;
        if let Err(error) = mailbox.stage_reserved(delivery.message, &delivery.spec, facts.clone())
        {
            self.cleanup_never_or_latch(authority, &mailbox, reservation, facts.clone(), false)?;
            return Err(error);
        }
        let admission = match authority
            .admission
            .lock()
            .map_err(|_| MsgError::CapabilityDenied("turn-busy".into()))
            .and_then(|mut issuer| {
                issuer
                    .seal_staged_admission(&reservation, &facts)
                    .map_err(map_turn_mailbox)
            }) {
            Ok(admission) => admission,
            Err(error) => {
                self.cleanup_never_or_latch(authority, &mailbox, reservation, facts.clone(), true)?;
                return Err(error);
            }
        };
        let retained_admission = match authority
            .admission
            .lock()
            .map_err(|_| MsgError::CapabilityDenied("turn-busy".into()))
            .and_then(|mut issuer| {
                issuer
                    .duplicate_for_mailbox_owner(&admission)
                    .map_err(map_turn_mailbox)
            }) {
            Ok(retained) => retained,
            Err(error) => {
                self.cleanup_never_or_latch(authority, &mailbox, reservation, facts.clone(), true)?;
                return Err(error);
            }
        };
        if let Err(error) = mailbox.attach_admission(facts.staged_entry_id, retained_admission) {
            self.cleanup_never_or_latch(authority, &mailbox, reservation, facts.clone(), true)?;
            return Err(map_turn_mailbox(error));
        }
        let confirmed = match authority
            .dispatch
            .confirm_mailbox_admission(&reservation, &admission)
        {
            Ok(confirmed) => confirmed,
            Err(error) => {
                self.cleanup_never_or_latch(authority, &mailbox, reservation, facts.clone(), true)?;
                return Err(map_turn_dispatch(error));
            }
        };
        let (registered, publish, cleanup) = confirmed.into_parts();
        Ok((
            PreparedTurnEntry {
                mailbox,
                staged_entry_id: facts.staged_entry_id,
                publish: Some(publish),
                cleanup: Some(cleanup),
                outcome_index,
            },
            registered,
        ))
    }

    fn cleanup_never_or_latch(
        &self,
        authority: &TurnMailboxAuthority,
        mailbox: &Arc<Mailbox>,
        reservation: advance_shared_types::turn_attribution::QueuedTurnReservation,
        facts: MailboxEntryFacts,
        physical_entry_expected: bool,
    ) -> Result<(), MsgError> {
        let settled = if physical_entry_expected {
            abort_never_admitted(authority, mailbox, &reservation, &facts)
        } else {
            settle_absent_never_admitted(authority, &reservation, &facts)
        };
        match settled {
            Ok(()) => Ok(()),
            Err(error) => {
                let mut pending = self
                    .never_admitted_recovery
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                assert!(pending.len() < MAX_TURN_RECOVERY_LATCHES);
                pending.push(NeverAdmittedRecovery {
                    mailbox: Arc::downgrade(mailbox),
                    physical_entry_expected,
                    reservation,
                    facts,
                });
                Err(error)
            }
        }
    }

    pub(crate) fn publish_prepared(&self, batch: &mut PreparedTurnBatch) -> Result<(), MsgError> {
        if batch.published || batch.detached || batch.entries.is_empty() {
            return Err(MsgError::CapabilityDenied("turn-state-conflict".into()));
        }
        for index in 0..batch.entries.len() {
            let digest = dispatch_barrier_digest();
            let result = {
                let entry = &mut batch.entries[index];
                let permit = entry
                    .publish
                    .take()
                    .ok_or_else(|| MsgError::CapabilityDenied("turn-state-conflict".into()))?;
                entry
                    .mailbox
                    .publish_staged(
                        entry.staged_entry_id,
                        permit,
                        Arc::clone(&batch.barrier),
                        digest,
                    )
                    .map_err(map_turn_mailbox)
            };
            if let Err(error) = result {
                let outcome_index = batch.entries[index].outcome_index;
                batch.outcomes[outcome_index] = Err(error.clone());
                self.rollback_prepared(batch)?;
                return Err(error);
            }
        }
        // Linearization point: all handles are retained in `batch.registered`
        // and all protected entries are installed before one shared release.
        batch.barrier.store(true, Ordering::Release);
        for entry in &mut batch.entries {
            entry.cleanup.take();
            entry.mailbox.wake_turn_reader();
        }
        batch.published = true;
        Ok(())
    }

    fn rollback_prepared(&self, batch: &mut PreparedTurnBatch) -> Result<(), MsgError> {
        let Some(authority) = self.turn_authority.as_ref() else {
            return Err(MsgError::CapabilityDenied("turn-unavailable".into()));
        };
        for entry in &mut batch.entries {
            let Some(cleanup) = entry.cleanup.as_ref() else {
                continue;
            };
            entry
                .mailbox
                .rollback_confirmed_in_place(entry.staged_entry_id, cleanup, authority)?;
            entry.cleanup.take();
        }
        batch.detached = true;
        Ok(())
    }

    pub(crate) fn detach_turn_batch(
        self: &Arc<Self>,
        session_id: &SessionId,
        batch: &mut PreparedTurnBatch,
    ) -> Result<(), MsgError> {
        if !batch.published || batch.detached {
            return Err(MsgError::CapabilityDenied("turn-state-conflict".into()));
        }
        if batch.completion_owner != Some(TurnCompletionOwner::AwaitSession) {
            return Err(MsgError::CapabilityDenied("turn-state-conflict".into()));
        }
        let authority = self
            .turn_authority
            .as_ref()
            .ok_or_else(|| MsgError::CapabilityDenied("turn-unavailable".into()))?;
        let detached = authority
            .dispatch
            .batch_detach(session_id, &batch.registered)
            .map_err(map_turn_dispatch)?;
        for cleanup in detached.into_queued_cleanup() {
            self.remove_detached_queued(authority, cleanup)?;
        }
        batch.detached = true;
        Ok(())
    }

    fn remove_detached_queued(
        self: &Arc<Self>,
        authority: &TurnMailboxAuthority,
        cleanup: advance_shared_types::turn_attribution::QueuedDetachCleanupToken,
    ) -> Result<(), MsgError> {
        let guard = self.try_take_detached_queued(authority, &cleanup)?;
        let Some(guard) = guard else {
            // A consumer may have physically taken the entry immediately
            // before batch_detach and will restore it when record_dequeued sees
            // the new Detached state. Retain the cleanup token and retry the
            // mailbox exact-take; never replay the already-committed batch.
            let mut pending = self
                .queued_removal_recovery
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            assert!(pending.len() < MAX_TURN_RECOVERY_LATCHES);
            pending.push(QueuedRemovalRecovery {
                cleanup,
                guard: None,
            });
            return Ok(());
        };
        if let Err(_error) = authority
            .lifecycle
            .settle_removed_queued(&cleanup, guard.receipt())
        {
            let mut pending = self
                .queued_removal_recovery
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            assert!(pending.len() < MAX_TURN_RECOVERY_LATCHES);
            pending.push(QueuedRemovalRecovery {
                cleanup,
                guard: Some(guard),
            });
            // Physical entry remains held by the guard and the authority
            // remains in the bounded latch; terminal detach is durable
            // even though immediate settlement could not complete.
            return Ok(());
        }
        guard.discard();
        Ok(())
    }

    fn try_take_detached_queued(
        &self,
        authority: &TurnMailboxAuthority,
        cleanup: &advance_shared_types::turn_attribution::QueuedDetachCleanupToken,
    ) -> Result<Option<ExactRemovalGuard>, MsgError> {
        let mailboxes: Vec<Arc<Mailbox>> = self
            .mailboxes
            .read()
            .map_err(|_| MsgError::CapabilityDenied("turn-busy".into()))?
            .values()
            .cloned()
            .collect();
        for mailbox in mailboxes {
            let Some(guard) = mailbox
                .take_queued_removal(cleanup, authority)
                .map_err(map_turn_mailbox)?
            else {
                continue;
            };
            return Ok(Some(guard));
        }
        Ok(None)
    }

    fn latch_failed_batch(&self, batch: &mut PreparedTurnBatch) {
        let mut pending = self
            .failed_batches
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert!(pending.len() < MAX_TURN_RECOVERY_LATCHES);
        pending.push(FailedBatchRecovery {
            session_id: batch.session_id.take(),
            completion_owner: batch.completion_owner.take(),
            entries: std::mem::take(&mut batch.entries),
            registered: std::mem::take(&mut batch.registered),
            barrier: Arc::clone(&batch.barrier),
            published: batch.published,
        });
        batch.detached = true;
    }

    /// Retry every bounded cleanup/handoff latch. Failed records remain owned
    /// by the store; the returned count is the number still pending.
    pub fn recover_turn_latches(self: &Arc<Self>) -> usize {
        if let Some(authority) = self.turn_authority.as_ref() {
            let never_admitted = {
                let mut pending = self
                    .never_admitted_recovery
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                std::mem::take(&mut *pending)
            };
            let mut never_still_pending = Vec::new();
            for recovery in never_admitted {
                let recovered = match (recovery.physical_entry_expected, recovery.mailbox.upgrade())
                {
                    (true, Some(mailbox)) => abort_never_admitted(
                        authority,
                        &mailbox,
                        &recovery.reservation,
                        &recovery.facts,
                    )
                    .is_ok(),
                    // Mailbox destruction is itself exact proof that its
                    // staged physical entry cannot remain visible. Retained
                    // reservation+facts still let the removal role seal the
                    // NeverAdmitted receipt and retire the provider journal.
                    (false, _) | (true, None) => settle_absent_never_admitted(
                        authority,
                        &recovery.reservation,
                        &recovery.facts,
                    )
                    .is_ok(),
                };
                if !recovered {
                    never_still_pending.push(recovery);
                }
            }
            self.never_admitted_recovery
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .extend(never_still_pending);
            {
                let mut pending = authority
                    .before_start_recovery
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                pending.retain(|handle| authority.execution.abandon_before_start(handle).is_err());
            }
            {
                let mut pending = authority
                    .dequeue_recovery
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                pending.retain(|latched| {
                    authority
                        .lifecycle
                        .abandon_dequeuing(&latched.receipt)
                        .is_err()
                });
            }

            let queued = {
                let mut pending = self
                    .queued_removal_recovery
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                std::mem::take(&mut *pending)
            };
            let mut still_pending = Vec::new();
            for mut recovery in queued {
                if recovery.guard.is_none() {
                    match self.try_take_detached_queued(authority, &recovery.cleanup) {
                        Ok(Some(guard)) => recovery.guard = Some(guard),
                        Ok(None) | Err(_) => {
                            still_pending.push(recovery);
                            continue;
                        }
                    }
                }
                let guard = recovery.guard.take().expect("queued recovery guard");
                if authority
                    .lifecycle
                    .settle_removed_queued(&recovery.cleanup, guard.receipt())
                    .is_ok()
                {
                    guard.discard();
                } else {
                    recovery.guard = Some(guard);
                    still_pending.push(recovery);
                }
            }
            self.queued_removal_recovery
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .extend(still_pending);
        }

        let records = {
            let mut pending = self
                .failed_batches
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            std::mem::take(&mut *pending)
        };
        for record in records {
            let mut batch = PreparedTurnBatch {
                store: Arc::clone(self),
                session_id: record.session_id,
                completion_owner: record.completion_owner,
                entries: record.entries,
                registered: record.registered,
                outcomes: Vec::new(),
                barrier: record.barrier,
                published: record.published,
                detached: false,
            };
            let result = if batch.published {
                match (&batch.completion_owner, batch.session_id.clone()) {
                    (Some(TurnCompletionOwner::AwaitSession), Some(session_id)) => {
                        self.detach_turn_batch(&session_id, &mut batch)
                    }
                    (Some(TurnCompletionOwner::ExecutionBoundary), _) => Ok(()),
                    _ => Err(MsgError::CapabilityDenied("turn-state-conflict".into())),
                }
            } else {
                self.rollback_prepared(&mut batch)
            };
            if result.is_ok() {
                batch.detached = true;
            }
            // On failure, `PreparedTurnBatch::drop` re-latches every authority.
        }
        let batch_pending = self
            .failed_batches
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len();
        let (before_start, dequeue) = self
            .turn_authority
            .as_ref()
            .map(|authority| {
                (
                    authority
                        .before_start_recovery
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .len(),
                    authority
                        .dequeue_recovery
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .len(),
                )
            })
            .unwrap_or((0, 0));
        let queued_removal = self
            .queued_removal_recovery
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len();
        let never_admitted = self
            .never_admitted_recovery
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len();
        batch_pending + before_start + dequeue + queued_removal + never_admitted
    }

    /// Blocking lazy registration. Adversarial-R11 fix: returns
    /// `Err(MsgError::CapabilityDenied("registry_full"))` instead of
    /// panicking when the registry would exceed `MAX_MAILBOXES`. This
    /// turns a process-killing `assert!` into a graceful per-call
    /// rejection that the dispatcher propagates back to the caller.
    pub fn get_or_create(&self, agent_id: &str) -> Result<Arc<Mailbox>, MsgError> {
        if let Some(mb) = self
            .mailboxes
            .read()
            .expect("rwlock poisoned")
            .get(agent_id)
        {
            return Ok(Arc::clone(mb));
        }
        let mut w = self.mailboxes.write().expect("rwlock poisoned");
        if let Some(mb) = w.get(agent_id) {
            return Ok(Arc::clone(mb));
        }
        if w.len() >= MAX_MAILBOXES {
            return Err(MsgError::CapabilityDenied("registry_full".into()));
        }
        let mb = Arc::new(Mailbox::new_inner(
            self.default_capacity,
            self.turn_authority.clone(),
        ));
        w.insert(agent_id.to_string(), Arc::clone(&mb));
        Ok(mb)
    }

    /// Blocking read-lock probe — returns the registered mailbox if any.
    /// Does NOT lazy-create. Used by tests + future-slice readers that
    /// don't want lazy-create semantics.
    pub fn get(&self, agent_id: &str) -> Option<Arc<Mailbox>> {
        self.mailboxes
            .read()
            .expect("rwlock poisoned")
            .get(agent_id)
            .cloned()
    }
}

fn map_turn_dispatch(error: advance_shared_types::turn_attribution::TurnDispatchError) -> MsgError {
    MsgError::CapabilityDenied(error.code().to_string())
}

fn map_turn_mailbox(error: TurnMailboxError) -> MsgError {
    MsgError::CapabilityDenied(error.code().to_string())
}

fn abort_never_admitted(
    authority: &TurnMailboxAuthority,
    mailbox: &Arc<Mailbox>,
    reservation: &advance_shared_types::turn_attribution::QueuedTurnReservation,
    facts: &MailboxEntryFacts,
) -> Result<(), MsgError> {
    let guard = mailbox.take_never_admitted_removal(reservation, facts, authority)?;
    authority
        .dispatch
        .abort_non_admitted(reservation, guard.receipt())
        .map_err(map_turn_dispatch)?;
    guard.discard();
    Ok(())
}

fn settle_absent_never_admitted(
    authority: &TurnMailboxAuthority,
    reservation: &advance_shared_types::turn_attribution::QueuedTurnReservation,
    facts: &MailboxEntryFacts,
) -> Result<(), MsgError> {
    let receipt = authority
        .removal
        .lock()
        .map_err(|_| MsgError::CapabilityDenied("turn-busy".into()))?
        .seal_exact_removal(
            MailboxRemovalAuthority::NeverAdmitted(reservation),
            None,
            facts,
        )
        .map_err(map_turn_mailbox)?;
    authority
        .dispatch
        .abort_non_admitted(reservation, &receipt)
        .map_err(map_turn_dispatch)?;
    Ok(())
}

fn dispatch_barrier_digest() -> [u8; 32] {
    let first = *uuid::Uuid::new_v4().as_bytes();
    let second = *uuid::Uuid::new_v4().as_bytes();
    let mut digest = [0; 32];
    digest[..16].copy_from_slice(&first);
    digest[16..].copy_from_slice(&second);
    digest
}

#[cfg(test)]
mod exact_removal_guard_tests {
    use super::*;
    use advance_shared_types::progress_lifecycle_recovery::{
        ProgressLifecycleRecoveryJournal, RecoveryJournalConfig,
    };
    use advance_shared_types::turn_attribution::{
        ConfirmedTurnAdmission, DetachBatchOutcome, MailboxRemovalDisposition,
        MailboxRemovalReceipt, ReplyRecoverySummary, StoreQuiescenceProof,
        TurnAttributionAuthorityFactory, TurnAttributionAuthorityParts, TurnAttributionVerifier,
        TurnDispatchError, TurnExecutionError, TurnFinishResult, TurnRegistryBinding,
        TurnRegistryIssuer, TurnStartOutcome,
    };
    use std::num::NonZeroU32;
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
    use zeroize::Zeroizing;

    struct FlakyNeverAdmittedDispatch {
        issuer: Mutex<TurnRegistryIssuer>,
        verifier: Mutex<TurnAttributionVerifier>,
        binding: Mutex<Option<TurnRegistryBinding>>,
        abort_calls: AtomicUsize,
    }

    impl TurnDispatchLifecyclePort for FlakyNeverAdmittedDispatch {
        fn reserve_queued(
            &self,
            spec: QueuedTurnSpec,
        ) -> Result<advance_shared_types::turn_attribution::QueuedTurnReservation, TurnDispatchError>
        {
            spec.validate()?;
            let issued = self
                .issuer
                .lock()
                .unwrap()
                .reserve_turn(&spec.turn_id, &spec.expected_agent)?;
            let (reservation, binding) = issued.into_parts();
            *self.binding.lock().unwrap() = Some(binding);
            Ok(reservation)
        }

        fn confirm_mailbox_admission(
            &self,
            _reservation: &advance_shared_types::turn_attribution::QueuedTurnReservation,
            _receipt: &MailboxAdmissionReceipt,
        ) -> Result<ConfirmedTurnAdmission, TurnDispatchError> {
            Err(TurnDispatchError::StateConflict)
        }

        fn abort_non_admitted(
            &self,
            reservation: &advance_shared_types::turn_attribution::QueuedTurnReservation,
            receipt: &MailboxRemovalReceipt,
        ) -> Result<(), TurnDispatchError> {
            let mut verifier = self.verifier.lock().unwrap();
            verifier
                .verify_removal(receipt)
                .map_err(|_| TurnDispatchError::ReceiptRejected)?;
            let claims = verifier
                .reservation_claims(reservation)
                .ok_or(TurnDispatchError::ReservationRejected)?;
            if !verifier.removal_matches(receipt, &claims, MailboxRemovalDisposition::NeverAdmitted)
            {
                return Err(TurnDispatchError::ReceiptRejected);
            }
            if self.abort_calls.fetch_add(1, AtomicOrdering::AcqRel) == 0 {
                return Err(TurnDispatchError::RecoveryJournalUnavailable);
            }
            let binding = self
                .binding
                .lock()
                .unwrap()
                .take()
                .ok_or(TurnDispatchError::ReservationReplayed)?;
            self.issuer.lock().unwrap().retire_unbound_source(&binding)
        }

        fn abort_confirmed_admission(
            &self,
            _cleanup: &ConfirmedAdmissionCleanupToken,
            _receipt: &MailboxRemovalReceipt,
        ) -> Result<(), TurnDispatchError> {
            Err(TurnDispatchError::StateConflict)
        }

        fn batch_detach(
            &self,
            _session_id: &SessionId,
            _turns: &[RegisteredTurnHandle],
        ) -> Result<DetachBatchOutcome, TurnDispatchError> {
            Err(TurnDispatchError::StateConflict)
        }

        fn recover_abandoned_claims(&self) -> Result<ReplyRecoverySummary, TurnDispatchError> {
            Ok(ReplyRecoverySummary::default())
        }
    }

    struct UnusedLifecycle;

    impl TurnMailboxLifecyclePort for UnusedLifecycle {
        fn record_dequeued(
            &self,
            _receipt: &MailboxDequeueReceipt,
        ) -> Result<RecordedDequeueHandoff, TurnMailboxError> {
            Err(TurnMailboxError::Busy)
        }

        fn complete_dequeue_handoff(
            &self,
            _receipt: &MailboxDequeueReceipt,
            _recorded: &RecordedDequeueHandoff,
        ) -> Result<DequeuedTurnHandle, TurnMailboxError> {
            Err(TurnMailboxError::Busy)
        }

        fn abandon_dequeuing(
            &self,
            _receipt: &MailboxDequeueReceipt,
        ) -> Result<(), TurnMailboxError> {
            Err(TurnMailboxError::Busy)
        }

        fn settle_removed_queued(
            &self,
            _cleanup: &advance_shared_types::turn_attribution::QueuedDetachCleanupToken,
            _receipt: &MailboxRemovalReceipt,
        ) -> Result<(), TurnMailboxError> {
            Err(TurnMailboxError::Busy)
        }
    }

    impl TurnExecutionLifecyclePort for UnusedLifecycle {
        fn start_turn(
            &self,
            _dequeued: &DequeuedTurnHandle,
        ) -> Result<TurnStartOutcome, TurnExecutionError> {
            Err(TurnExecutionError::Busy)
        }

        fn abandon_before_start(
            &self,
            _dequeued: &DequeuedTurnHandle,
        ) -> Result<(), TurnExecutionError> {
            Err(TurnExecutionError::Busy)
        }

        fn finish_turn(
            &self,
            _proof: StoreQuiescenceProof,
        ) -> Result<TurnFinishResult, TurnExecutionError> {
            Err(TurnExecutionError::Busy)
        }
    }

    fn message(id: &str) -> Message {
        Message {
            id: id.to_string(),
            kind: MessageKind::Agent,
            from: "agent:parent".into(),
            to: "agent:child".into(),
            payload: Vec::new(),
            context: None,
            timestamp: std::time::SystemTime::UNIX_EPOCH,
            origin: None,
        }
    }

    #[test]
    fn panic_between_staged_take_and_receipt_seal_restores_entry() {
        let mailbox = Arc::new(Mailbox::new(NonZeroUsize::new(4).unwrap()));
        let staged_entry_id = [0x21; 16];
        let entry = StagedTurnEntry {
            message: message("turn-staged-panic"),
            facts: MailboxEntryFacts {
                turn_id: "turn-staged-panic".into(),
                expected_agent: "agent:child".into(),
                message_id: "turn-staged-panic".into(),
                mailbox_incarnation: mailbox.incarnation,
                staged_entry_id,
            },
            admission: None,
        };
        mailbox
            .staged
            .lock()
            .unwrap()
            .insert(staged_entry_id, entry);
        let entry = mailbox
            .staged
            .lock()
            .unwrap()
            .remove(&staged_entry_id)
            .unwrap();
        let guard = ExactRemovalGuard {
            mailbox: Arc::clone(&mailbox),
            location: ExactRemovalLocation::Staged(staged_entry_id),
            entry: Some(ExactRemovedEntry::Staged(entry)),
            receipt: None,
        };

        assert!(catch_unwind(AssertUnwindSafe(move || {
            let _guard = guard;
            panic!("receipt issuer failpoint");
        }))
        .is_err());
        assert!(mailbox
            .staged
            .lock()
            .unwrap()
            .contains_key(&staged_entry_id));
    }

    #[test]
    fn panic_between_queue_take_and_receipt_seal_restores_exact_position() {
        let mailbox = Arc::new(Mailbox::new(NonZeroUsize::new(4).unwrap()));
        {
            let mut queue = mailbox.queue.lock().unwrap();
            queue.push_back(MailboxEntry::Legacy(message("before")));
            queue.push_back(MailboxEntry::Legacy(message("taken")));
            queue.push_back(MailboxEntry::Legacy(message("after")));
        }
        let entry = mailbox.queue.lock().unwrap().remove(1).unwrap();
        let guard = ExactRemovalGuard {
            mailbox: Arc::clone(&mailbox),
            location: ExactRemovalLocation::Queued {
                priority: QueuePriority::Normal,
                index: 1,
            },
            entry: Some(ExactRemovedEntry::Queued(entry)),
            receipt: None,
        };

        assert!(catch_unwind(AssertUnwindSafe(move || {
            let _guard = guard;
            panic!("receipt issuer failpoint");
        }))
        .is_err());
        let ids: Vec<String> = mailbox
            .queue
            .lock()
            .unwrap()
            .iter()
            .map(|entry| match entry {
                MailboxEntry::Legacy(message) => message.id.clone(),
                MailboxEntry::Protected(_) => unreachable!(),
            })
            .collect();
        assert_eq!(ids, ["before", "taken", "after"]);
    }

    #[test]
    fn execution_ingress_rejects_await_owner_nonzero_slot_and_non_exec_session() {
        let store = Arc::new(MailboxStore::new(NonZeroUsize::new(4).unwrap()));
        let delivery = |session: &str, slot: u32, completion_owner| TurnMailboxDelivery {
            target: "agent:child".into(),
            message: Message {
                id: "turn-ingress-shape".into(),
                kind: MessageKind::User,
                from: "user:alice".into(),
                to: "agent:child".into(),
                payload: Vec::new(),
                context: None,
                timestamp: std::time::SystemTime::UNIX_EPOCH,
                origin: None,
            },
            spec: QueuedTurnSpec {
                turn_id: "turn-ingress-shape".into(),
                expected_agent: "agent:child".into(),
                parent_agent: "user:alice".into(),
                session_id: SessionId(session.into()),
                slot,
                completion_owner,
                original_task_id: None,
                original_run_id: None,
                original_reply_to: Some("user:alice".into()),
            },
        };
        for invalid in [
            delivery("exec_owner", 0, TurnCompletionOwner::AwaitSession),
            delivery("exec_slot", 1, TurnCompletionOwner::ExecutionBoundary),
            delivery(
                "session_looks_await",
                0,
                TurnCompletionOwner::ExecutionBoundary,
            ),
        ] {
            assert_eq!(
                store.publish_execution_turn(invalid),
                Err(MsgError::CapabilityDenied("turn-invalid".into()))
            );
        }
    }

    #[test]
    fn never_admitted_recovery_retires_authority_after_mailbox_owner_drops() {
        let journal_root = tempfile::tempdir().expect("journal root");
        let config = RecoveryJournalConfig::new_at_composition(
            journal_root.path().join("journal"),
            journal_root.path().join("anchor").join("root.anchor"),
            NonZeroU32::new(1).unwrap(),
            Zeroizing::new([0x45; 32]),
        )
        .expect("recovery config");
        let journal = ProgressLifecycleRecoveryJournal::open_at_composition(config)
            .expect("open recovery journal");
        let (turn_recovery, _progress_recovery) = journal.split_at_composition();
        let TurnAttributionAuthorityParts {
            activation_staging: _,
            registry_issuer,
            mailbox_admission_issuer,
            mailbox_removal_issuer,
            mailbox_dequeue_issuer,
            mailbox_publish_verifier,
            store_quiescence_issuer: _,
            source_quiescence_recovery_issuer: _,
            source_quiescence_verifier: _,
            verifier,
        } = TurnAttributionAuthorityFactory::new_at_composition(
            &mut rand::rngs::OsRng,
            turn_recovery,
        )
        .expect("turn authority");
        let dispatch = Arc::new(FlakyNeverAdmittedDispatch {
            issuer: Mutex::new(registry_issuer),
            verifier: Mutex::new(verifier),
            binding: Mutex::new(None),
            abort_calls: AtomicUsize::new(0),
        });
        let lifecycle = Arc::new(UnusedLifecycle);
        let store = Arc::new(MailboxStore::new_with_turn_attribution(
            NonZeroUsize::new(1).unwrap(),
            mailbox_admission_issuer,
            mailbox_removal_issuer,
            mailbox_dequeue_issuer,
            mailbox_publish_verifier,
            dispatch.clone(),
            lifecycle.clone(),
            lifecycle,
        ));
        let target = "agent:child";
        let mailbox = store.get_or_create(target).expect("mailbox");
        mailbox.deliver(message("capacity-occupant")).unwrap();

        let mut external_message = message("turn-owner-drop");
        external_message.from = "user:alice".into();
        let result = store.publish_execution_turn(TurnMailboxDelivery {
            target: target.into(),
            message: external_message,
            spec: QueuedTurnSpec {
                turn_id: "turn-owner-drop".into(),
                expected_agent: target.into(),
                parent_agent: "user:alice".into(),
                session_id: SessionId("exec_owner_drop".into()),
                slot: 0,
                completion_owner: TurnCompletionOwner::ExecutionBoundary,
                original_task_id: None,
                original_run_id: None,
                original_reply_to: Some("user:alice".into()),
            },
        });
        assert!(result.is_err(), "first provider abort is failpointed");
        assert_eq!(dispatch.abort_calls.load(AtomicOrdering::Acquire), 1);

        // Simulate the physical mailbox owner disappearing before retry. The
        // retained Weak can no longer upgrade, so recovery must seal from the
        // retained absence facts and retire the ActiveSource authority anyway.
        drop(mailbox);
        drop(store.mailboxes.write().unwrap().remove(target));
        assert_eq!(store.recover_turn_latches(), 0);
        assert_eq!(dispatch.abort_calls.load(AtomicOrdering::Acquire), 2);
        assert!(dispatch.binding.lock().unwrap().is_none());
    }
}

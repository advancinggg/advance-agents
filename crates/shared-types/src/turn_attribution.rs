//! CONTRACT-216 host-only turn attribution capabilities and least-privilege ports.
//!
//! The concrete registry is owned by `advance-reply-tracker`.  This module
//! intentionally exposes only five object-safe facades plus move-only opaque
//! capabilities.  None of the capabilities implement `Clone`, serde, or a
//! data-bearing `Debug` implementation.

use crate::progress_card::{progress_expected_agent_digest, progress_source_message_id_digest};
use crate::progress_lifecycle_recovery::{
    TurnActiveSourceInput, TurnJournalWriteError, TurnQuiescedSourceRecord,
    TurnRecoveryJournalRole, TurnSourceExpectation, TurnStoreEvidence,
};
use crate::SessionId;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fmt;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

pub const DEFAULT_TURN_ATTRIBUTION_MAX_ENTRIES: usize = 4096;
pub const MAX_TURN_ATTRIBUTION_MAX_ENTRIES: usize = 4096;
pub const MAX_TURN_ID_BYTES: usize = 256;
pub const MAX_TURN_AGENT_ID_BYTES: usize = 256;
pub const MAX_TURN_ROUTE_ID_BYTES: usize = 256;

const TOKEN_DOMAIN: &[u8] = b"advance.contract216.token.v1\0";
const FACTS_DOMAIN: &[u8] = b"advance.contract216.mailbox-facts.v1\0";
const REMOVAL_DOMAIN: &[u8] = b"advance.contract216.removal.v1\0";
const KEY_REGISTRY: &[u8] = b"advance.contract216.registry-key.v1\0";
const KEY_ADMISSION: &[u8] = b"advance.contract216.admission-key.v1\0";
const KEY_REMOVAL: &[u8] = b"advance.contract216.removal-key.v1\0";
const KEY_DEQUEUE: &[u8] = b"advance.contract216.dequeue-key.v1\0";
const KEY_STORE: &[u8] = b"advance.contract216.store-key.v1\0";
const KEY_SOURCE_QUIESCENCE: &[u8] = b"advance.contract216.source-quiescence-key.v1\0";
const RUNTIME_PROVIDER_BINDING_DOMAIN: &[u8] = b"advance.contract216.runtime-provider-binding.v1\0";
const SOURCE_QUIESCENCE_DOMAIN: &[u8] = b"advance.contract216.source-quiescence.v1\0";
const MAX_SOURCE_RECEIPT_LIFETIME_MS: u64 = 15 * 60 * 1000;
const MAX_NONZERO_ENTROPY_ATTEMPTS: usize = 8;

macro_rules! opaque_debug {
    ($($name:ty),+ $(,)?) => {$(
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "(<opaque>)"))
            }
        }
    )+ };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DetachOrigin {
    Queued,
    DequeuedPendingStart,
    Running,
    FinishedNoReply,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NonCallableTurnPhase {
    Queued,
    FinishedNoReply,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CostTurnState {
    Active,
    Detached {
        from: DetachOrigin,
        execution_finished: bool,
    },
    NonCallable(NonCallableTurnPhase),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CostAttributionSnapshot {
    pub original_task_id: Option<String>,
    pub original_run_id: Option<String>,
    pub state: CostTurnState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CostAttributionLookup {
    Tracked(CostAttributionSnapshot),
    Untracked,
    IdentityMismatch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendTurnClassification {
    ActiveParent,
    DetachedParent,
    DetachedUnrelated,
    NonCallable(NonCallableTurnPhase),
    Untracked,
    IdentityMismatch,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExactReplyRoute {
    pub parent_agent: String,
    pub session_id: SessionId,
    pub slot: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TurnCompletionOwner {
    AwaitSession,
    ExecutionBoundary,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueuedTurnSpec {
    pub turn_id: String,
    pub expected_agent: String,
    pub parent_agent: String,
    pub session_id: SessionId,
    pub slot: u32,
    pub completion_owner: TurnCompletionOwner,
    pub original_task_id: Option<String>,
    pub original_run_id: Option<String>,
    pub original_reply_to: Option<String>,
}

impl QueuedTurnSpec {
    pub fn validate(&self) -> Result<(), TurnDispatchError> {
        if !valid_id(&self.turn_id, MAX_TURN_ID_BYTES)
            || !valid_id(&self.expected_agent, MAX_TURN_AGENT_ID_BYTES)
            || !valid_id(&self.parent_agent, MAX_TURN_ROUTE_ID_BYTES)
            || !valid_session_id(&self.session_id)
            || self.expected_agent == self.parent_agent
            || self
                .original_task_id
                .as_deref()
                .is_some_and(|value| !valid_optional_id(value))
            || self
                .original_run_id
                .as_deref()
                .is_some_and(|value| !valid_optional_id(value))
            || self
                .original_reply_to
                .as_deref()
                .is_some_and(|value| !valid_optional_id(value))
        {
            return Err(TurnDispatchError::InvalidIdentity);
        }
        Ok(())
    }
}

fn valid_id(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && !value.chars().any(char::is_control)
        && !value.chars().any(char::is_whitespace)
}

fn valid_optional_id(value: &str) -> bool {
    value.len() <= MAX_TURN_ROUTE_ID_BYTES && !value.chars().any(char::is_control)
}

fn valid_session_id(value: &SessionId) -> bool {
    !value.0.is_empty()
        && value.0.len() <= 64
        && value
            .0
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

macro_rules! fixed_error {
    ($name:ident { $($variant:ident => $code:literal),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum $name { $($variant),+ }

        impl $name {
            pub const fn code(self) -> &'static str {
                match self { $(Self::$variant => $code),+ }
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.code())
            }
        }

        impl std::error::Error for $name {}
    };
}

fixed_error!(TurnAuthorityInitError {
    EntropyUnavailable => "turn-authority-init-failed",
    RecoveryKeyUnavailable => "turn-recovery-unavailable",
    RecoveryJournalCorrupt => "turn-recovery-unavailable",
    RecoveryCapacityInvalid => "turn-recovery-unavailable",
    AnchorUnavailable => "turn-recovery-unavailable",
    AnchorMismatch => "turn-recovery-rollback",
    RollbackDetected => "turn-recovery-rollback",
    SequenceExhausted => "turn-recovery-rollback",
});

fixed_error!(TurnDispatchError {
    CapacityExhausted => "turn-capacity",
    RecoveryCapacityExhausted => "turn-capacity",
    DuplicateTurn => "turn-duplicate",
    InvalidIdentity => "turn-invalid",
    InvalidRoute => "turn-invalid",
    ReservationRejected => "turn-authority-rejected",
    ReceiptRejected => "turn-authority-rejected",
    CleanupTokenRejected => "turn-authority-rejected",
    ReservationReplayed => "turn-authority-replayed",
    CleanupTokenReplayed => "turn-authority-replayed",
    BatchInvalid => "turn-state-conflict",
    StateConflict => "turn-state-conflict",
    GenerationExhausted => "turn-generation-exhausted",
    RecoveryJournalUnavailable => "turn-recovery-unavailable",
    AnchorUnavailable => "turn-recovery-unavailable",
    AnchorConflict => "turn-recovery-rollback",
    RollbackDetected => "turn-recovery-rollback",
});

fixed_error!(TurnExecutionError {
    IdentityMismatch => "turn-identity-mismatch",
    NonCallable => "turn-not-callable",
    ProofRejected => "turn-authority-rejected",
    ProofReplayed => "turn-authority-replayed",
    RecoveryBindingRejected => "turn-authority-rejected",
    StateConflict => "turn-state-conflict",
    Busy => "turn-busy",
    RecoveryCapacityExhausted => "turn-capacity",
    RecoveryJournalUnavailable => "turn-recovery-unavailable",
    AnchorUnavailable => "turn-recovery-unavailable",
    AnchorConflict => "turn-recovery-rollback",
    RollbackDetected => "turn-recovery-rollback",
});

fixed_error!(TurnReplyError {
    IdentityMismatch => "turn-identity-mismatch",
    NonCallable => "turn-not-callable",
    InProgress => "reply-in-progress",
    RecoveryPending => "reply-recovery-pending",
    AlreadyConsumed => "reply-already-consumed",
    TokenRejected => "reply-authority-rejected",
    ReceiptRejected => "reply-authority-rejected",
    StaleClaim => "reply-authority-rejected",
    TokenReplayed => "reply-authority-replayed",
    InvalidSettlement => "reply-state-conflict",
    StateConflict => "reply-state-conflict",
});

fixed_error!(TurnMailboxError {
    ReceiptRejected => "turn-authority-rejected",
    TokenRejected => "turn-authority-rejected",
    Replayed => "turn-authority-replayed",
    StateConflict => "turn-state-conflict",
    Busy => "turn-busy",
});

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CredentialKind {
    Reservation = 1,
    Registered = 2,
    RecordedDequeue = 3,
    Dequeued = 4,
    QueuedCleanup = 5,
    ConfirmedCleanup = 6,
    PublishPermit = 7,
    ActiveClaim = 8,
    LateDisposition = 9,
    ReplyAccepted = 10,
    ReplyNotAccepted = 11,
    MailboxAdmission = 12,
    MailboxRemoval = 13,
    VerifiedPublish = 14,
    MailboxDequeue = 15,
    StoreQuiescence = 16,
}

struct CredentialSeal {
    authority_id: [u8; 16],
    kind: CredentialKind,
    turn_digest: [u8; 32],
    agent_digest: [u8; 32],
    generation: u64,
    lineage: [u8; 16],
    context: [u8; 32],
    nonce: [u8; 16],
    mac: [u8; 32],
}

impl CredentialSeal {
    fn issue<R: RngCore + ?Sized>(
        authority_id: [u8; 16],
        kind: CredentialKind,
        turn_digest: [u8; 32],
        agent_digest: [u8; 32],
        generation: u64,
        lineage: [u8; 16],
        context: [u8; 32],
        key: &[u8; 32],
        rng: &mut R,
    ) -> Self {
        let mut nonce = [0; 16];
        rng.fill_bytes(&mut nonce);
        let mac = credential_mac(
            key,
            authority_id,
            kind,
            turn_digest,
            agent_digest,
            generation,
            lineage,
            context,
            nonce,
        );
        Self {
            authority_id,
            kind,
            turn_digest,
            agent_digest,
            generation,
            lineage,
            context,
            nonce,
            mac,
        }
    }

    fn verify(&self, authority_id: &[u8; 16], kind: CredentialKind, key: &[u8; 32]) -> bool {
        if self.kind != kind || !bool::from(self.authority_id.ct_eq(authority_id)) {
            return false;
        }
        let expected = credential_mac(
            key,
            self.authority_id,
            self.kind,
            self.turn_digest,
            self.agent_digest,
            self.generation,
            self.lineage,
            self.context,
            self.nonce,
        );
        bool::from(self.mac.ct_eq(&expected))
    }

    fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(TOKEN_DOMAIN);
        hasher.update(self.authority_id);
        hasher.update([self.kind as u8]);
        hasher.update(self.turn_digest);
        hasher.update(self.agent_digest);
        hasher.update(self.generation.to_be_bytes());
        hasher.update(self.lineage);
        hasher.update(self.context);
        hasher.update(self.nonce);
        hasher.update(self.mac);
        hasher.finalize().into()
    }

    fn duplicate_for_role(&self) -> Self {
        Self {
            authority_id: self.authority_id,
            kind: self.kind,
            turn_digest: self.turn_digest,
            agent_digest: self.agent_digest,
            generation: self.generation,
            lineage: self.lineage,
            context: self.context,
            nonce: self.nonce,
            mac: self.mac,
        }
    }
}

fn credential_mac(
    key: &[u8; 32],
    authority_id: [u8; 16],
    kind: CredentialKind,
    turn_digest: [u8; 32],
    agent_digest: [u8; 32],
    generation: u64,
    lineage: [u8; 16],
    context: [u8; 32],
    nonce: [u8; 16],
) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts a 32-byte key");
    mac.update(TOKEN_DOMAIN);
    mac.update(&authority_id);
    mac.update(&[kind as u8]);
    mac.update(&turn_digest);
    mac.update(&agent_digest);
    mac.update(&generation.to_be_bytes());
    mac.update(&lineage);
    mac.update(&context);
    mac.update(&nonce);
    mac.finalize().into_bytes().into()
}

fn text_digest(domain: &[u8], value: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
    hasher.finalize().into()
}

fn facts_digest(facts: &MailboxEntryFacts) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(FACTS_DOMAIN);
    for value in [&facts.turn_id, &facts.expected_agent, &facts.message_id] {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value.as_bytes());
    }
    hasher.update(facts.mailbox_incarnation);
    hasher.update(facts.staged_entry_id);
    hasher.finalize().into()
}

fn removal_context(
    authority_digest: [u8; 32],
    admission_digest: Option<[u8; 32]>,
    facts_digest: [u8; 32],
    disposition: MailboxRemovalDisposition,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(REMOVAL_DOMAIN);
    hasher.update(authority_digest);
    hasher.update(admission_digest.unwrap_or([0; 32]));
    hasher.update(facts_digest);
    hasher.update([match disposition {
        MailboxRemovalDisposition::NeverAdmitted => 1,
        MailboxRemovalDisposition::RemovedBeforeDequeue => 2,
    }]);
    hasher.finalize().into()
}

macro_rules! opaque_token {
    ($name:ident) => {
        pub struct $name {
            seal: CredentialSeal,
        }
        opaque_debug!($name);
    };
}

opaque_token!(QueuedTurnReservation);
opaque_token!(RegisteredTurnHandle);
opaque_token!(RecordedDequeueHandoff);
opaque_token!(DequeuedTurnHandle);
opaque_token!(QueuedDetachCleanupToken);
opaque_token!(ConfirmedAdmissionCleanupToken);
opaque_token!(MailboxPublishPermit);
opaque_token!(ActiveReplyClaimToken);
opaque_token!(LateReplyDispositionToken);
opaque_token!(ReplyAcceptedReceipt);
opaque_token!(ReplyNotAcceptedReceipt);

/// Provider-retained move-only authority for one registry row.  Generation,
/// lineage and admission binding never cross this type boundary.
pub struct TurnRegistryBinding {
    turn_digest: [u8; 32],
    agent_digest: [u8; 32],
    generation: u64,
    lineage: [u8; 16],
    admission_digest: Option<[u8; 32]>,
    registered_digest: Option<[u8; 32]>,
    journal: TurnJournalBinding,
}

/// Provider-retained binding to the exact anchored source row.  Its hidden
/// generation is fixed at source creation and does not advance on detach.
pub struct TurnJournalBinding {
    source_digest: [u8; 32],
    expected_agent_digest: [u8; 32],
    generation: u64,
}

impl TurnJournalBinding {
    fn expectation(&self) -> TurnSourceExpectation {
        TurnSourceExpectation {
            source_digest: self.source_digest,
            expected_agent_digest: self.expected_agent_digest,
            generation: self.generation,
        }
    }
}

pub struct IssuedQueuedTurn {
    reservation: QueuedTurnReservation,
    binding: TurnRegistryBinding,
}

impl IssuedQueuedTurn {
    pub fn into_parts(self) -> (QueuedTurnReservation, TurnRegistryBinding) {
        (self.reservation, self.binding)
    }
}

opaque_debug!(TurnRegistryBinding, TurnJournalBinding, IssuedQueuedTurn);

pub struct ClaimedActiveReply {
    route: ExactReplyRoute,
    token: ActiveReplyClaimToken,
}

impl ClaimedActiveReply {
    pub fn route(&self) -> &ExactReplyRoute {
        &self.route
    }

    pub fn into_parts(self) -> (ExactReplyRoute, ActiveReplyClaimToken) {
        (self.route, self.token)
    }

    pub(crate) fn from_provider(route: ExactReplyRoute, token: ActiveReplyClaimToken) -> Self {
        Self { route, token }
    }
}

impl fmt::Debug for ClaimedActiveReply {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClaimedActiveReply")
            .field("route", &self.route)
            .field("token", &"<opaque>")
            .finish()
    }
}

pub struct ConfirmedTurnAdmission {
    registered: RegisteredTurnHandle,
    publish: MailboxPublishPermit,
    rollback: ConfirmedAdmissionCleanupToken,
}

impl ConfirmedTurnAdmission {
    pub fn into_parts(
        self,
    ) -> (
        RegisteredTurnHandle,
        MailboxPublishPermit,
        ConfirmedAdmissionCleanupToken,
    ) {
        (self.registered, self.publish, self.rollback)
    }

    pub(crate) fn from_provider(
        registered: RegisteredTurnHandle,
        publish: MailboxPublishPermit,
        rollback: ConfirmedAdmissionCleanupToken,
    ) -> Self {
        Self {
            registered,
            publish,
            rollback,
        }
    }
}

opaque_debug!(ConfirmedTurnAdmission);

pub struct DetachBatchOutcome {
    queued_cleanup: Vec<QueuedDetachCleanupToken>,
}

impl DetachBatchOutcome {
    pub fn into_queued_cleanup(self) -> Vec<QueuedDetachCleanupToken> {
        self.queued_cleanup
    }

    pub(crate) fn from_provider(queued_cleanup: Vec<QueuedDetachCleanupToken>) -> Self {
        Self { queued_cleanup }
    }
}

opaque_debug!(DetachBatchOutcome);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MailboxEntryFacts {
    pub turn_id: String,
    pub expected_agent: String,
    pub message_id: String,
    pub mailbox_incarnation: [u8; 16],
    pub staged_entry_id: [u8; 16],
}

impl MailboxEntryFacts {
    fn validate(&self) -> Result<(), TurnMailboxError> {
        if self.turn_id != self.message_id
            || !valid_id(&self.turn_id, MAX_TURN_ID_BYTES)
            || !valid_id(&self.expected_agent, MAX_TURN_AGENT_ID_BYTES)
            || self.mailbox_incarnation == [0; 16]
            || self.staged_entry_id == [0; 16]
        {
            return Err(TurnMailboxError::ReceiptRejected);
        }
        Ok(())
    }
}

pub struct MailboxAdmissionReceipt {
    seal: CredentialSeal,
    facts_digest: [u8; 32],
}

pub struct VerifiedMailboxPublish {
    seal: CredentialSeal,
    admission_digest: [u8; 32],
    facts_digest: [u8; 32],
}

pub struct PreparedMailboxDequeue {
    receipt: MailboxDequeueReceipt,
}

impl PreparedMailboxDequeue {
    pub fn commit_exact_take(self) -> MailboxDequeueReceipt {
        self.receipt
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MailboxRemovalDisposition {
    NeverAdmitted,
    RemovedBeforeDequeue,
}

pub enum MailboxRemovalAuthority<'a> {
    NeverAdmitted(&'a QueuedTurnReservation),
    Confirmed(&'a ConfirmedAdmissionCleanupToken),
    QueuedDetach(&'a QueuedDetachCleanupToken),
}

pub struct MailboxRemovalReceipt {
    seal: CredentialSeal,
    authority_token_digest: [u8; 32],
    admission_digest: Option<[u8; 32]>,
    facts_digest: [u8; 32],
    disposition: MailboxRemovalDisposition,
}

pub struct MailboxDequeueReceipt {
    seal: CredentialSeal,
    registered_turn_digest: [u8; 32],
    admission_digest: [u8; 32],
    facts_digest: [u8; 32],
    dispatch_barrier_lease_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreQuiescenceKind {
    Drained { store_epoch: u64 },
    StoreDestroyed { store_incarnation: [u8; 16] },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoreQuiescenceFacts {
    pub turn_id: String,
    pub expected_agent: String,
    pub store_incarnation: [u8; 16],
}

pub struct StoreQuiescenceProof {
    seal: CredentialSeal,
    store_incarnation: [u8; 16],
    kind: StoreQuiescenceKind,
}

/// Boot-authority receipt issued only after the C216 provider has committed
/// the exact source/key quiescence fact.  Durable storage and reissuance are
/// deliberately outside this carrier.
pub struct SourceTurnQuiescedReceipt {
    authority_id: [u8; 16],
    origin_runtime: [u8; 16],
    source_message_id_digest: [u8; 32],
    progress_key_digest: [u8; 32],
    expected_agent_digest: [u8; 32],
    store_incarnation: [u8; 16],
    quiescence_evidence_digest: [u8; 32],
    turn_generation: u64,
    issued_at_ms: u64,
    expires_at_ms: u64,
    nonce: [u8; 16],
    mac: [u8; 32],
}

pub struct VerifiedSourceTurnQuiescence {
    receipt_digest: [u8; 32],
    source_message_id_digest: [u8; 32],
    progress_key_digest: [u8; 32],
    issued_at_ms: u64,
    expires_at_ms: u64,
    turn_generation: u64,
}

impl SourceTurnQuiescedReceipt {
    /// Opaque durable progress binding used by provider implementations for
    /// bounded maps. This is a one-way digest, not a reconstructible card key.
    pub fn progress_key_digest(&self) -> [u8; 32] {
        self.progress_key_digest
    }

    pub(crate) fn digest_for_progress(&self) -> [u8; 32] {
        source_receipt_digest(self)
    }

    pub(crate) fn source_message_id_digest_for_progress(&self) -> [u8; 32] {
        self.source_message_id_digest
    }

    pub(crate) fn progress_key_digest_for_progress(&self) -> [u8; 32] {
        self.progress_key_digest
    }
}

impl VerifiedSourceTurnQuiescence {
    pub fn receipt_digest(&self) -> [u8; 32] {
        self.receipt_digest
    }

    pub fn source_message_id_digest(&self) -> [u8; 32] {
        self.source_message_id_digest
    }

    pub fn progress_key_digest(&self) -> [u8; 32] {
        self.progress_key_digest
    }

    pub fn issued_at_ms(&self) -> u64 {
        self.issued_at_ms
    }

    pub fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }

    pub fn turn_generation(&self) -> u64 {
        self.turn_generation
    }
}

opaque_debug!(
    MailboxAdmissionReceipt,
    VerifiedMailboxPublish,
    PreparedMailboxDequeue,
    MailboxRemovalReceipt,
    MailboxDequeueReceipt,
    StoreQuiescenceProof,
    SourceTurnQuiescedReceipt,
    VerifiedSourceTurnQuiescence,
);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplySettlement {
    Consumed,
    Reopened,
    FinishedNoReply,
    Detached,
}

pub enum ReplyAbortProof {
    BeforeDelivery,
    DefinitelyNotAccepted(ReplyNotAcceptedReceipt),
}

pub enum LateReplyClaim {
    Claimed(LateReplyDispositionToken),
    AlreadyHandled,
}

pub enum ReplyRouteClaim {
    Active(ClaimedActiveReply),
    DetachedLate(LateReplyDispositionToken),
    AlreadyHandled,
}

opaque_debug!(ReplyAbortProof, LateReplyClaim, ReplyRouteClaim);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TurnStartOutcome {
    Execute,
    DoNotExecute,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TurnFinishOutcome {
    Removed,
    FinishedNoReply,
    DetachedRetained,
    DetachedRemoved,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReplyRecoverySummary {
    pub recovered_accepted: usize,
    pub recovered_not_accepted: usize,
    pub recovered_detached: usize,
    pub pending: usize,
}

pub struct TurnFinishResult {
    pub outcome: TurnFinishOutcome,
    source_quiesced: Option<SourceTurnQuiescedReceipt>,
}

impl TurnFinishResult {
    pub fn from_provider(
        outcome: TurnFinishOutcome,
        source_quiesced: Option<SourceTurnQuiescedReceipt>,
    ) -> Self {
        Self {
            outcome,
            source_quiesced,
        }
    }

    pub fn into_source_quiesced(self) -> Option<SourceTurnQuiescedReceipt> {
        self.source_quiesced
    }
}

pub struct VerifiedTurnCredential {
    turn_digest: [u8; 32],
    agent_digest: [u8; 32],
    generation: u64,
    lineage: [u8; 16],
    context: [u8; 32],
    credential_digest: [u8; 32],
}

impl VerifiedTurnCredential {
    pub fn matches_identity(&self, turn_id: &str, expected_agent: &str) -> bool {
        bool::from(self.turn_digest.ct_eq(&text_digest(b"turn\0", turn_id)))
            && bool::from(
                self.agent_digest
                    .ct_eq(&text_digest(b"agent\0", expected_agent)),
            )
    }

    /// Non-authorizing local correlation only; possession of this digest
    /// cannot mint, settle, or verify any CONTRACT-216 capability.
    pub fn correlation_digest(&self) -> [u8; 32] {
        self.credential_digest
    }
}

opaque_debug!(VerifiedTurnCredential);

/// Read-only, move-independent identity of the exact C216 registry issuer
/// staged into the runtime provider.  Its fields are intentionally private:
/// composition may compare it through the joint C215/C216 authority, but
/// cannot synthesize or rewrite either the factory identity or role binding.
pub struct TurnRuntimeProviderBinding {
    authority_id: [u8; 16],
    binding: [u8; 32],
}

pub struct TurnRegistryIssuer {
    authority_id: [u8; 16],
    key: Zeroizing<[u8; 32]>,
    admission_key: Zeroizing<[u8; 32]>,
    dequeue_key: Zeroizing<[u8; 32]>,
    store_key: Zeroizing<[u8; 32]>,
    source_key: Zeroizing<[u8; 32]>,
    journal: Arc<TurnJournalAuthority>,
    next_generation: u64,
}

struct TurnJournalAuthority {
    recovery: TurnRecoveryJournalRole,
}

pub struct MailboxAdmissionIssuer {
    authority_id: [u8; 16],
    registry_key: Zeroizing<[u8; 32]>,
    admission_key: Zeroizing<[u8; 32]>,
}

pub struct MailboxRemovalIssuer {
    authority_id: [u8; 16],
    registry_key: Zeroizing<[u8; 32]>,
    admission_key: Zeroizing<[u8; 32]>,
    removal_key: Zeroizing<[u8; 32]>,
}

pub struct MailboxDequeueIssuer {
    authority_id: [u8; 16],
    admission_key: Zeroizing<[u8; 32]>,
    dequeue_key: Zeroizing<[u8; 32]>,
}

pub struct MailboxPublishVerifier {
    authority_id: [u8; 16],
    registry_key: Zeroizing<[u8; 32]>,
    admission_key: Zeroizing<[u8; 32]>,
}

pub struct StoreQuiescenceIssuer {
    authority_id: [u8; 16],
    store_key: Zeroizing<[u8; 32]>,
}

pub struct SourceQuiescenceRecoveryIssuer {
    authority_id: [u8; 16],
    source_key: Zeroizing<[u8; 32]>,
    journal: Arc<TurnJournalAuthority>,
}

pub struct SourceTurnQuiescenceVerifier {
    authority_id: [u8; 16],
    source_key: Zeroizing<[u8; 32]>,
}

pub struct TurnAttributionVerifier {
    authority_id: [u8; 16],
    registry_key: Zeroizing<[u8; 32]>,
    admission_key: Zeroizing<[u8; 32]>,
    removal_key: Zeroizing<[u8; 32]>,
    dequeue_key: Zeroizing<[u8; 32]>,
    store_key: Zeroizing<[u8; 32]>,
}

opaque_debug!(
    TurnRuntimeProviderBinding,
    TurnRegistryIssuer,
    MailboxAdmissionIssuer,
    MailboxRemovalIssuer,
    MailboxDequeueIssuer,
    MailboxPublishVerifier,
    StoreQuiescenceIssuer,
    SourceQuiescenceRecoveryIssuer,
    SourceTurnQuiescenceVerifier,
    TurnAttributionVerifier,
);

impl TurnRegistryIssuer {
    /// Return an opaque read-only binding for the one runtime provider that
    /// will consume this issuer.  The issuer itself remains linear and is not
    /// cloned or weakened by taking this witness.
    pub fn runtime_provider_binding(&self) -> TurnRuntimeProviderBinding {
        TurnRuntimeProviderBinding {
            authority_id: self.authority_id,
            binding: runtime_provider_binding_digest(self.authority_id, &self.key),
        }
    }

    fn issue_from_binding(
        &mut self,
        kind: CredentialKind,
        binding: &TurnRegistryBinding,
        context: [u8; 32],
    ) -> CredentialSeal {
        CredentialSeal::issue(
            self.authority_id,
            kind,
            binding.turn_digest,
            binding.agent_digest,
            binding.generation,
            binding.lineage,
            context,
            &self.key,
            &mut rand::rngs::OsRng,
        )
    }

    /// Allocate the hidden generation and lineage inside the issuer.  No
    /// caller-selected sequence, nonce or authority fact is accepted.
    pub fn reserve_turn(
        &mut self,
        turn_id: &str,
        expected_agent: &str,
    ) -> Result<IssuedQueuedTurn, TurnDispatchError> {
        if !valid_id(turn_id, MAX_TURN_ID_BYTES)
            || !valid_id(expected_agent, MAX_TURN_AGENT_ID_BYTES)
        {
            return Err(TurnDispatchError::InvalidIdentity);
        }
        let next_generation = self
            .next_generation
            .checked_add(1)
            .ok_or(TurnDispatchError::GenerationExhausted)?;
        let mut lineage = [0; 16];
        if !fill_nonzero(&mut rand::rngs::OsRng, &mut lineage) {
            return Err(TurnDispatchError::RecoveryJournalUnavailable);
        }
        let turn_digest = text_digest(b"turn\0", turn_id);
        let agent_digest = text_digest(b"agent\0", expected_agent);
        // The C216 credential namespace and the C215 durable ActiveSource
        // namespace are intentionally distinct. Credential seals retain the
        // private CONTRACT-216 digests, while the journal binding uses the
        // normative progress-lifecycle KAT domains consumed by C215.
        let source_digest = progress_source_message_id_digest(turn_id)
            .map_err(|_| TurnDispatchError::InvalidIdentity)?;
        let expected_agent_digest = progress_expected_agent_digest(expected_agent)
            .map_err(|_| TurnDispatchError::InvalidIdentity)?;
        let journal = TurnJournalBinding {
            source_digest,
            expected_agent_digest,
            generation: next_generation,
        };
        let created_at_ms =
            now_unix_ms().map_err(|_| TurnDispatchError::RecoveryJournalUnavailable)?;
        let binding = TurnRegistryBinding {
            turn_digest,
            agent_digest,
            generation: next_generation,
            lineage,
            admission_digest: None,
            registered_digest: None,
            journal,
        };
        let reservation = QueuedTurnReservation {
            seal: self.issue_from_binding(CredentialKind::Reservation, &binding, [0; 32]),
        };
        // The durable insertion is deliberately the final fallible operation.
        // The provider pre-reserves its in-memory map before calling this
        // method, so a successful journal insert cannot be followed by an
        // allocation error that leaks an unbound ActiveSource row.
        self.journal
            .recovery
            .insert_active_source(TurnActiveSourceInput {
                source_digest,
                expected_agent_digest,
                generation: next_generation,
                created_at_ms,
            })
            .map_err(map_journal_dispatch)?;
        self.next_generation = next_generation;
        Ok(IssuedQueuedTurn {
            reservation,
            binding,
        })
    }

    /// Anchored-retire the exact source row only while it remains unbound.
    /// Registry erasure must happen strictly after this method succeeds.
    pub fn retire_unbound_source(
        &mut self,
        binding: &TurnRegistryBinding,
    ) -> Result<(), TurnDispatchError> {
        self.journal
            .recovery
            .retire_unbound_source(binding.journal.expectation())
            .map_err(map_journal_dispatch)
    }

    /// Consume the exact Store proof and commit the anchored source terminal
    /// transition before any in-memory registry row can retire.
    pub fn commit_store_quiescence(
        &mut self,
        binding: &TurnRegistryBinding,
        proof: &StoreQuiescenceProof,
    ) -> Result<Option<SourceTurnQuiescedReceipt>, TurnExecutionError> {
        let claims = verify_seal(
            &proof.seal,
            &self.authority_id,
            CredentialKind::StoreQuiescence,
            &self.store_key,
        )
        .ok_or(TurnExecutionError::ProofRejected)?;
        if !bool::from(claims.turn_digest.ct_eq(&binding.turn_digest))
            || !bool::from(claims.agent_digest.ct_eq(&binding.agent_digest))
            || claims.lineage != proof.store_incarnation
        {
            return Err(TurnExecutionError::ProofRejected);
        }
        let evidence_digest = store_evidence_digest(proof, claims.credential_digest);
        let evidence = match proof.kind {
            StoreQuiescenceKind::Drained { store_epoch } => TurnStoreEvidence::Drained {
                store_incarnation: proof.store_incarnation,
                store_epoch,
                evidence_digest,
            },
            StoreQuiescenceKind::StoreDestroyed { store_incarnation }
                if store_incarnation == proof.store_incarnation =>
            {
                TurnStoreEvidence::StoreDestroyed {
                    store_incarnation,
                    evidence_digest,
                }
            }
            StoreQuiescenceKind::StoreDestroyed { .. } => {
                return Err(TurnExecutionError::ProofRejected)
            }
        };
        let issued_at_ms = now_unix_ms()?;
        let record = self
            .journal
            .recovery
            .commit_store_quiescence(binding.journal.expectation(), evidence, issued_at_ms)
            .map_err(map_journal_execution)?;
        record
            .map(|record| {
                issue_source_receipt(self.authority_id, &self.source_key, record, issued_at_ms)
            })
            .transpose()
    }

    /// Verify and bind the exact mailbox admission, then issue the complete
    /// confirmation triple from the provider-held binding.
    pub fn confirm_admission(
        &mut self,
        binding: &mut TurnRegistryBinding,
        receipt: &MailboxAdmissionReceipt,
    ) -> Result<ConfirmedTurnAdmission, TurnDispatchError> {
        let admission = verify_seal(
            &receipt.seal,
            &self.authority_id,
            CredentialKind::MailboxAdmission,
            &self.admission_key,
        )
        .ok_or(TurnDispatchError::ReceiptRejected)?;
        if !credential_matches_binding(&admission, binding, true)
            || binding.admission_digest.is_some()
        {
            return Err(TurnDispatchError::ReceiptRejected);
        }
        let admission_digest = admission.correlation_digest();
        binding.admission_digest = Some(admission_digest);
        let registered = RegisteredTurnHandle {
            seal: self.issue_from_binding(CredentialKind::Registered, binding, admission_digest),
        };
        binding.registered_digest = Some(registered.seal.digest());
        let publish = MailboxPublishPermit {
            seal: self.issue_from_binding(CredentialKind::PublishPermit, binding, admission_digest),
        };
        let rollback = ConfirmedAdmissionCleanupToken {
            seal: self.issue_from_binding(
                CredentialKind::ConfirmedCleanup,
                binding,
                admission_digest,
            ),
        };
        Ok(ConfirmedTurnAdmission::from_provider(
            registered, publish, rollback,
        ))
    }

    pub fn record_dequeue(
        &mut self,
        binding: &TurnRegistryBinding,
        receipt: &MailboxDequeueReceipt,
    ) -> Result<RecordedDequeueHandoff, TurnMailboxError> {
        let claims = verify_seal(
            &receipt.seal,
            &self.authority_id,
            CredentialKind::MailboxDequeue,
            &self.dequeue_key,
        )
        .ok_or(TurnMailboxError::ReceiptRejected)?;
        if !credential_matches_binding(&claims, binding, true) {
            return Err(TurnMailboxError::ReceiptRejected);
        }
        Ok(RecordedDequeueHandoff {
            seal: self.issue_from_binding(
                CredentialKind::RecordedDequeue,
                binding,
                claims.correlation_digest(),
            ),
        })
    }

    pub fn complete_dequeue(
        &mut self,
        binding: &TurnRegistryBinding,
        receipt: &MailboxDequeueReceipt,
        recorded: &RecordedDequeueHandoff,
    ) -> Result<DequeuedTurnHandle, TurnMailboxError> {
        let receipt_claims = verify_seal(
            &receipt.seal,
            &self.authority_id,
            CredentialKind::MailboxDequeue,
            &self.dequeue_key,
        )
        .ok_or(TurnMailboxError::ReceiptRejected)?;
        let recorded_claims = verify_seal(
            &recorded.seal,
            &self.authority_id,
            CredentialKind::RecordedDequeue,
            &self.key,
        )
        .ok_or(TurnMailboxError::TokenRejected)?;
        if !credential_matches_binding(&receipt_claims, binding, true)
            || !credential_matches_binding(&recorded_claims, binding, true)
            || recorded_claims.context != receipt_claims.correlation_digest()
        {
            return Err(TurnMailboxError::TokenRejected);
        }
        Ok(DequeuedTurnHandle {
            seal: self.issue_from_binding(
                CredentialKind::Dequeued,
                binding,
                receipt_claims.correlation_digest(),
            ),
        })
    }

    /// Advance the hidden generation exactly once for terminal detach.  A
    /// queued row receives its distinct cleanup capability from the old
    /// admission lineage before the generation advances.
    pub fn advance_detach(
        &mut self,
        binding: &mut TurnRegistryBinding,
        queued: bool,
    ) -> Result<Option<QueuedDetachCleanupToken>, TurnDispatchError> {
        let cleanup = if queued {
            let admission_digest = binding
                .admission_digest
                .ok_or(TurnDispatchError::StateConflict)?;
            Some(QueuedDetachCleanupToken {
                seal: self.issue_from_binding(
                    CredentialKind::QueuedCleanup,
                    binding,
                    admission_digest,
                ),
            })
        } else {
            None
        };
        binding.generation = binding
            .generation
            .checked_add(1)
            .ok_or(TurnDispatchError::GenerationExhausted)?;
        Ok(cleanup)
    }

    pub fn validate_detach(
        &self,
        binding: &TurnRegistryBinding,
        queued: bool,
    ) -> Result<(), TurnDispatchError> {
        if queued && binding.admission_digest.is_none() {
            return Err(TurnDispatchError::StateConflict);
        }
        binding
            .generation
            .checked_add(1)
            .map(|_| ())
            .ok_or(TurnDispatchError::GenerationExhausted)
    }

    pub fn claim_active(&mut self, binding: &TurnRegistryBinding) -> ActiveReplyClaimToken {
        ActiveReplyClaimToken {
            seal: self.issue_from_binding(CredentialKind::ActiveClaim, binding, random_context()),
        }
    }

    pub fn claim_late(&mut self, binding: &TurnRegistryBinding) -> LateReplyDispositionToken {
        LateReplyDispositionToken {
            seal: self.issue_from_binding(
                CredentialKind::LateDisposition,
                binding,
                random_context(),
            ),
        }
    }

    pub fn issue_reply_accepted_for(
        &mut self,
        binding: &TurnRegistryBinding,
        token: &ActiveReplyClaimToken,
    ) -> Result<ReplyAcceptedReceipt, TurnReplyError> {
        let claim = verify_seal(
            &token.seal,
            &self.authority_id,
            CredentialKind::ActiveClaim,
            &self.key,
        )
        .ok_or(TurnReplyError::TokenRejected)?;
        if !credential_matches_binding(&claim, binding, false) {
            return Err(TurnReplyError::StaleClaim);
        }
        Ok(ReplyAcceptedReceipt {
            seal: CredentialSeal::issue(
                self.authority_id,
                CredentialKind::ReplyAccepted,
                claim.turn_digest,
                claim.agent_digest,
                claim.generation,
                claim.lineage,
                claim.credential_digest,
                &self.key,
                &mut rand::rngs::OsRng,
            ),
        })
    }

    pub fn issue_reply_not_accepted_for(
        &mut self,
        binding: &TurnRegistryBinding,
        token: &ActiveReplyClaimToken,
    ) -> Result<ReplyNotAcceptedReceipt, TurnReplyError> {
        let claim = verify_seal(
            &token.seal,
            &self.authority_id,
            CredentialKind::ActiveClaim,
            &self.key,
        )
        .ok_or(TurnReplyError::TokenRejected)?;
        if !credential_matches_binding(&claim, binding, false) {
            return Err(TurnReplyError::StaleClaim);
        }
        Ok(ReplyNotAcceptedReceipt {
            seal: CredentialSeal::issue(
                self.authority_id,
                CredentialKind::ReplyNotAccepted,
                claim.turn_digest,
                claim.agent_digest,
                claim.generation,
                claim.lineage,
                claim.credential_digest,
                &self.key,
                &mut rand::rngs::OsRng,
            ),
        })
    }

    pub fn assemble_confirmed_admission(
        &mut self,
        registered: RegisteredTurnHandle,
        publish: MailboxPublishPermit,
        rollback: ConfirmedAdmissionCleanupToken,
    ) -> ConfirmedTurnAdmission {
        ConfirmedTurnAdmission::from_provider(registered, publish, rollback)
    }

    pub fn assemble_claimed_active_reply(
        &mut self,
        route: ExactReplyRoute,
        token: ActiveReplyClaimToken,
    ) -> ClaimedActiveReply {
        ClaimedActiveReply::from_provider(route, token)
    }

    pub fn assemble_detach_outcome(
        &mut self,
        queued_cleanup: Vec<QueuedDetachCleanupToken>,
    ) -> DetachBatchOutcome {
        DetachBatchOutcome::from_provider(queued_cleanup)
    }
}

impl MailboxAdmissionIssuer {
    pub fn seal_staged_admission(
        &mut self,
        reservation: &QueuedTurnReservation,
        facts: &MailboxEntryFacts,
    ) -> Result<MailboxAdmissionReceipt, TurnMailboxError> {
        facts.validate()?;
        let claims = verify_seal(
            &reservation.seal,
            &self.authority_id,
            CredentialKind::Reservation,
            &self.registry_key,
        )
        .ok_or(TurnMailboxError::TokenRejected)?;
        if !claims.matches_identity(&facts.turn_id, &facts.expected_agent) {
            return Err(TurnMailboxError::TokenRejected);
        }
        let digest = facts_digest(facts);
        Ok(MailboxAdmissionReceipt {
            seal: CredentialSeal::issue(
                self.authority_id,
                CredentialKind::MailboxAdmission,
                claims.turn_digest,
                claims.agent_digest,
                claims.generation,
                claims.lineage,
                digest,
                &self.admission_key,
                &mut rand::rngs::OsRng,
            ),
            facts_digest: digest,
        })
    }

    /// Produce the exact second owner copy needed because confirmation
    /// consumes one receipt while publish/removal remains under the same
    /// mailbox-owner role.  The carrier itself deliberately has no `Clone`.
    pub fn duplicate_for_mailbox_owner(
        &mut self,
        receipt: &MailboxAdmissionReceipt,
    ) -> Result<MailboxAdmissionReceipt, TurnMailboxError> {
        verify_seal(
            &receipt.seal,
            &self.authority_id,
            CredentialKind::MailboxAdmission,
            &self.admission_key,
        )
        .ok_or(TurnMailboxError::ReceiptRejected)?;
        Ok(MailboxAdmissionReceipt {
            seal: receipt.seal.duplicate_for_role(),
            facts_digest: receipt.facts_digest,
        })
    }
}

impl MailboxPublishVerifier {
    pub fn verify_publish(
        &mut self,
        permit: MailboxPublishPermit,
        admission: &MailboxAdmissionReceipt,
        facts: &MailboxEntryFacts,
    ) -> Result<VerifiedMailboxPublish, TurnMailboxError> {
        facts.validate()?;
        let permit_claims = verify_seal(
            &permit.seal,
            &self.authority_id,
            CredentialKind::PublishPermit,
            &self.registry_key,
        )
        .ok_or(TurnMailboxError::TokenRejected)?;
        let admission_claims = verify_seal(
            &admission.seal,
            &self.authority_id,
            CredentialKind::MailboxAdmission,
            &self.admission_key,
        )
        .ok_or(TurnMailboxError::ReceiptRejected)?;
        let expected_facts = facts_digest(facts);
        if !same_lineage(&permit_claims, &admission_claims)
            || !bool::from(permit_claims.context.ct_eq(&admission.seal.digest()))
            || !bool::from(admission.facts_digest.ct_eq(&expected_facts))
        {
            return Err(TurnMailboxError::ReceiptRejected);
        }
        let admission_digest = admission.seal.digest();
        Ok(VerifiedMailboxPublish {
            seal: CredentialSeal::issue(
                self.authority_id,
                CredentialKind::VerifiedPublish,
                permit_claims.turn_digest,
                permit_claims.agent_digest,
                permit_claims.generation,
                permit_claims.lineage,
                admission_digest,
                &self.admission_key,
                &mut rand::rngs::OsRng,
            ),
            admission_digest,
            facts_digest: expected_facts,
        })
    }
}

impl MailboxRemovalIssuer {
    pub fn seal_exact_removal(
        &mut self,
        authority: MailboxRemovalAuthority<'_>,
        admission: Option<&MailboxAdmissionReceipt>,
        facts: &MailboxEntryFacts,
    ) -> Result<MailboxRemovalReceipt, TurnMailboxError> {
        facts.validate()?;
        let (authority_seal, kind, disposition) = match authority {
            MailboxRemovalAuthority::NeverAdmitted(token) => (
                &token.seal,
                CredentialKind::Reservation,
                MailboxRemovalDisposition::NeverAdmitted,
            ),
            MailboxRemovalAuthority::Confirmed(token) => (
                &token.seal,
                CredentialKind::ConfirmedCleanup,
                MailboxRemovalDisposition::RemovedBeforeDequeue,
            ),
            MailboxRemovalAuthority::QueuedDetach(token) => (
                &token.seal,
                CredentialKind::QueuedCleanup,
                MailboxRemovalDisposition::RemovedBeforeDequeue,
            ),
        };
        let authority_claims =
            verify_seal(authority_seal, &self.authority_id, kind, &self.registry_key)
                .ok_or(TurnMailboxError::TokenRejected)?;
        if !authority_claims.matches_identity(&facts.turn_id, &facts.expected_agent) {
            return Err(TurnMailboxError::TokenRejected);
        }
        let admission_digest = match (disposition, admission) {
            (MailboxRemovalDisposition::NeverAdmitted, None) => None,
            (MailboxRemovalDisposition::RemovedBeforeDequeue, Some(receipt)) => {
                let claims = verify_seal(
                    &receipt.seal,
                    &self.authority_id,
                    CredentialKind::MailboxAdmission,
                    &self.admission_key,
                )
                .ok_or(TurnMailboxError::ReceiptRejected)?;
                if !same_lineage(&authority_claims, &claims)
                    || !bool::from(authority_claims.context.ct_eq(&receipt.seal.digest()))
                    || !bool::from(receipt.facts_digest.ct_eq(&facts_digest(facts)))
                {
                    return Err(TurnMailboxError::ReceiptRejected);
                }
                Some(receipt.seal.digest())
            }
            _ => return Err(TurnMailboxError::ReceiptRejected),
        };
        let authority_token_digest = authority_seal.digest();
        let facts_digest = facts_digest(facts);
        let context = removal_context(
            authority_token_digest,
            admission_digest,
            facts_digest,
            disposition,
        );
        Ok(MailboxRemovalReceipt {
            seal: CredentialSeal::issue(
                self.authority_id,
                CredentialKind::MailboxRemoval,
                authority_claims.turn_digest,
                authority_claims.agent_digest,
                authority_claims.generation,
                authority_claims.lineage,
                context,
                &self.removal_key,
                &mut rand::rngs::OsRng,
            ),
            authority_token_digest,
            admission_digest,
            facts_digest,
            disposition,
        })
    }
}

impl MailboxDequeueIssuer {
    pub fn prepare_visible_dequeue(
        &mut self,
        published: &VerifiedMailboxPublish,
        facts: &MailboxEntryFacts,
        dispatch_barrier_lease_digest: [u8; 32],
    ) -> Result<PreparedMailboxDequeue, TurnMailboxError> {
        facts.validate()?;
        if dispatch_barrier_lease_digest == [0; 32] {
            return Err(TurnMailboxError::ReceiptRejected);
        }
        let claims = verify_seal(
            &published.seal,
            &self.authority_id,
            CredentialKind::VerifiedPublish,
            &self.admission_key,
        )
        .ok_or(TurnMailboxError::TokenRejected)?;
        let expected_facts = facts_digest(facts);
        if !claims.matches_identity(&facts.turn_id, &facts.expected_agent)
            || !bool::from(published.facts_digest.ct_eq(&expected_facts))
        {
            return Err(TurnMailboxError::ReceiptRejected);
        }
        let registered_turn_digest = claims.context;
        let mut context_hasher = Sha256::new();
        context_hasher.update(published.admission_digest);
        context_hasher.update(expected_facts);
        context_hasher.update(dispatch_barrier_lease_digest);
        let context: [u8; 32] = context_hasher.finalize().into();
        Ok(PreparedMailboxDequeue {
            receipt: MailboxDequeueReceipt {
                seal: CredentialSeal::issue(
                    self.authority_id,
                    CredentialKind::MailboxDequeue,
                    claims.turn_digest,
                    claims.agent_digest,
                    claims.generation,
                    claims.lineage,
                    context,
                    &self.dequeue_key,
                    &mut rand::rngs::OsRng,
                ),
                registered_turn_digest,
                admission_digest: published.admission_digest,
                facts_digest: expected_facts,
                dispatch_barrier_lease_digest,
            },
        })
    }
}

impl StoreQuiescenceIssuer {
    pub fn issue_drained(
        &mut self,
        facts: &StoreQuiescenceFacts,
        store_epoch: u64,
    ) -> Result<StoreQuiescenceProof, TurnExecutionError> {
        self.issue(facts, StoreQuiescenceKind::Drained { store_epoch })
    }

    pub fn issue_store_destroyed(
        &mut self,
        facts: &StoreQuiescenceFacts,
    ) -> Result<StoreQuiescenceProof, TurnExecutionError> {
        self.issue(
            facts,
            StoreQuiescenceKind::StoreDestroyed {
                store_incarnation: facts.store_incarnation,
            },
        )
    }

    fn issue(
        &mut self,
        facts: &StoreQuiescenceFacts,
        kind: StoreQuiescenceKind,
    ) -> Result<StoreQuiescenceProof, TurnExecutionError> {
        if !valid_id(&facts.turn_id, MAX_TURN_ID_BYTES)
            || !valid_id(&facts.expected_agent, MAX_TURN_AGENT_ID_BYTES)
            || facts.store_incarnation == [0; 16]
        {
            return Err(TurnExecutionError::ProofRejected);
        }
        let mut context_hasher = Sha256::new();
        context_hasher.update(facts.store_incarnation);
        match kind {
            StoreQuiescenceKind::Drained { store_epoch } => {
                context_hasher.update([1]);
                context_hasher.update(store_epoch.to_be_bytes());
            }
            StoreQuiescenceKind::StoreDestroyed { store_incarnation } => {
                context_hasher.update([2]);
                context_hasher.update(store_incarnation);
            }
        }
        Ok(StoreQuiescenceProof {
            seal: CredentialSeal::issue(
                self.authority_id,
                CredentialKind::StoreQuiescence,
                text_digest(b"turn\0", &facts.turn_id),
                text_digest(b"agent\0", &facts.expected_agent),
                0,
                facts.store_incarnation,
                context_hasher.finalize().into(),
                &self.store_key,
                &mut rand::rngs::OsRng,
            ),
            store_incarnation: facts.store_incarnation,
            kind,
        })
    }
}

impl SourceQuiescenceRecoveryIssuer {
    /// Re-sign every exact unconsumed quiesced source discovered at boot.
    /// The returned opaque receipts carry the durable source→progress-key
    /// binding; no caller needs to persist or reconstruct a raw card key.
    pub fn reissue_pending_progress_sources(
        &mut self,
    ) -> Result<Vec<SourceTurnQuiescedReceipt>, TurnExecutionError> {
        let records = self
            .journal
            .recovery
            .read_pending_quiesced_sources()
            .map_err(map_journal_execution)?;
        let issued_at_ms = now_unix_ms()?;
        let mut receipts = Vec::new();
        receipts
            .try_reserve_exact(records.len())
            .map_err(|_| TurnExecutionError::RecoveryCapacityExhausted)?;
        for record in records {
            receipts.push(issue_source_receipt(
                self.authority_id,
                &self.source_key,
                record,
                issued_at_ms,
            )?);
        }
        Ok(receipts)
    }
}

fn issue_source_receipt(
    authority_id: [u8; 16],
    source_key: &[u8; 32],
    record: TurnQuiescedSourceRecord,
    issued_at_ms: u64,
) -> Result<SourceTurnQuiescedReceipt, TurnExecutionError> {
    if record.origin_runtime == [0; 16]
        || record.source_digest == [0; 32]
        || record.progress_key_digest == [0; 32]
        || record.expected_agent_digest == [0; 32]
        || record.evidence_digest == [0; 32]
        || record.generation == 0
    {
        return Err(TurnExecutionError::RecoveryBindingRejected);
    }
    let expires_at_ms = issued_at_ms
        .checked_add(MAX_SOURCE_RECEIPT_LIFETIME_MS)
        .ok_or(TurnExecutionError::RecoveryBindingRejected)?;
    let mut nonce = [0; 16];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let mac = source_receipt_mac(
        source_key,
        authority_id,
        record.origin_runtime,
        record.source_digest,
        record.progress_key_digest,
        record.expected_agent_digest,
        record.store_incarnation,
        record.evidence_digest,
        record.generation,
        issued_at_ms,
        expires_at_ms,
        nonce,
    );
    Ok(SourceTurnQuiescedReceipt {
        authority_id,
        origin_runtime: record.origin_runtime,
        source_message_id_digest: record.source_digest,
        progress_key_digest: record.progress_key_digest,
        expected_agent_digest: record.expected_agent_digest,
        store_incarnation: record.store_incarnation,
        quiescence_evidence_digest: record.evidence_digest,
        turn_generation: record.generation,
        issued_at_ms,
        expires_at_ms,
        nonce,
        mac,
    })
}

impl SourceTurnQuiescenceVerifier {
    pub(crate) fn belongs_to_activation_authority(&self, authority_id: &[u8; 16]) -> bool {
        bool::from(self.authority_id.ct_eq(authority_id))
    }

    pub fn verify_for_progress(
        &mut self,
        receipt: &SourceTurnQuiescedReceipt,
        expected_source_digest: [u8; 32],
        expected_key_digest: [u8; 32],
        now_ms: u64,
    ) -> Result<VerifiedSourceTurnQuiescence, TurnExecutionError> {
        if !bool::from(receipt.authority_id.ct_eq(&self.authority_id))
            || !bool::from(
                receipt
                    .source_message_id_digest
                    .ct_eq(&expected_source_digest),
            )
            || !bool::from(receipt.progress_key_digest.ct_eq(&expected_key_digest))
            || receipt.expires_at_ms <= receipt.issued_at_ms
            || receipt.expires_at_ms.saturating_sub(receipt.issued_at_ms)
                > MAX_SOURCE_RECEIPT_LIFETIME_MS
            || now_ms < receipt.issued_at_ms
            || now_ms > receipt.expires_at_ms
        {
            return Err(TurnExecutionError::RecoveryBindingRejected);
        }
        let expected_mac = source_receipt_mac(
            &self.source_key,
            receipt.authority_id,
            receipt.origin_runtime,
            receipt.source_message_id_digest,
            receipt.progress_key_digest,
            receipt.expected_agent_digest,
            receipt.store_incarnation,
            receipt.quiescence_evidence_digest,
            receipt.turn_generation,
            receipt.issued_at_ms,
            receipt.expires_at_ms,
            receipt.nonce,
        );
        if !bool::from(receipt.mac.ct_eq(&expected_mac)) {
            return Err(TurnExecutionError::RecoveryBindingRejected);
        }
        Ok(VerifiedSourceTurnQuiescence {
            receipt_digest: source_receipt_digest(receipt),
            source_message_id_digest: receipt.source_message_id_digest,
            progress_key_digest: receipt.progress_key_digest,
            issued_at_ms: receipt.issued_at_ms,
            expires_at_ms: receipt.expires_at_ms,
            turn_generation: receipt.turn_generation,
        })
    }
}

#[allow(clippy::too_many_arguments)]
fn source_receipt_mac(
    key: &[u8; 32],
    authority_id: [u8; 16],
    origin_runtime: [u8; 16],
    source_message_id_digest: [u8; 32],
    progress_key_digest: [u8; 32],
    expected_agent_digest: [u8; 32],
    store_incarnation: [u8; 16],
    quiescence_evidence_digest: [u8; 32],
    turn_generation: u64,
    issued_at_ms: u64,
    expires_at_ms: u64,
    nonce: [u8; 16],
) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts a 32-byte key");
    mac.update(SOURCE_QUIESCENCE_DOMAIN);
    mac.update(&authority_id);
    mac.update(&origin_runtime);
    mac.update(&source_message_id_digest);
    mac.update(&progress_key_digest);
    mac.update(&expected_agent_digest);
    mac.update(&store_incarnation);
    mac.update(&quiescence_evidence_digest);
    mac.update(&turn_generation.to_be_bytes());
    mac.update(&issued_at_ms.to_be_bytes());
    mac.update(&expires_at_ms.to_be_bytes());
    mac.update(&nonce);
    mac.finalize().into_bytes().into()
}

fn source_receipt_digest(receipt: &SourceTurnQuiescedReceipt) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SOURCE_QUIESCENCE_DOMAIN);
    hasher.update(receipt.authority_id);
    hasher.update(receipt.origin_runtime);
    hasher.update(receipt.source_message_id_digest);
    hasher.update(receipt.progress_key_digest);
    hasher.update(receipt.expected_agent_digest);
    hasher.update(receipt.store_incarnation);
    hasher.update(receipt.quiescence_evidence_digest);
    hasher.update(receipt.turn_generation.to_be_bytes());
    hasher.update(receipt.issued_at_ms.to_be_bytes());
    hasher.update(receipt.expires_at_ms.to_be_bytes());
    hasher.update(receipt.nonce);
    hasher.update(receipt.mac);
    hasher.finalize().into()
}

impl TurnAttributionVerifier {
    fn registry_claims(
        &self,
        seal: &CredentialSeal,
        kind: CredentialKind,
    ) -> Option<VerifiedTurnCredential> {
        verify_seal(seal, &self.authority_id, kind, &self.registry_key)
    }

    pub fn reservation_claims(
        &self,
        value: &QueuedTurnReservation,
    ) -> Option<VerifiedTurnCredential> {
        self.registry_claims(&value.seal, CredentialKind::Reservation)
    }

    pub fn reservation_matches_binding(
        &self,
        value: &QueuedTurnReservation,
        binding: &TurnRegistryBinding,
    ) -> bool {
        self.reservation_claims(value)
            .is_some_and(|claims| credential_matches_binding(&claims, binding, true))
    }

    pub fn registered_claims(
        &self,
        value: &RegisteredTurnHandle,
    ) -> Option<VerifiedTurnCredential> {
        self.registry_claims(&value.seal, CredentialKind::Registered)
    }

    pub fn registered_matches_binding(
        &self,
        value: &RegisteredTurnHandle,
        binding: &TurnRegistryBinding,
    ) -> bool {
        self.registered_claims(value).is_some_and(|claims| {
            credential_matches_binding(&claims, binding, true)
                && binding.registered_digest == Some(claims.correlation_digest())
        })
    }

    pub fn recorded_dequeue_claims(
        &self,
        value: &RecordedDequeueHandoff,
    ) -> Option<VerifiedTurnCredential> {
        self.registry_claims(&value.seal, CredentialKind::RecordedDequeue)
    }

    pub fn dequeued_claims(&self, value: &DequeuedTurnHandle) -> Option<VerifiedTurnCredential> {
        self.registry_claims(&value.seal, CredentialKind::Dequeued)
    }

    pub fn queued_cleanup_claims(
        &self,
        value: &QueuedDetachCleanupToken,
    ) -> Option<VerifiedTurnCredential> {
        self.registry_claims(&value.seal, CredentialKind::QueuedCleanup)
    }

    pub fn queued_cleanup_matches_binding(
        &self,
        value: &QueuedDetachCleanupToken,
        binding: &TurnRegistryBinding,
    ) -> bool {
        self.queued_cleanup_claims(value).is_some_and(|claims| {
            credential_matches_binding(&claims, binding, false)
                && binding.admission_digest == Some(claims.context)
        })
    }

    pub fn confirmed_cleanup_claims(
        &self,
        value: &ConfirmedAdmissionCleanupToken,
    ) -> Option<VerifiedTurnCredential> {
        self.registry_claims(&value.seal, CredentialKind::ConfirmedCleanup)
    }

    pub fn confirmed_cleanup_matches_binding(
        &self,
        value: &ConfirmedAdmissionCleanupToken,
        binding: &TurnRegistryBinding,
    ) -> bool {
        self.confirmed_cleanup_claims(value).is_some_and(|claims| {
            credential_matches_binding(&claims, binding, true)
                && binding.admission_digest == Some(claims.context)
        })
    }

    pub fn active_claim_claims(
        &self,
        value: &ActiveReplyClaimToken,
    ) -> Option<VerifiedTurnCredential> {
        self.registry_claims(&value.seal, CredentialKind::ActiveClaim)
    }

    pub fn late_disposition_claims(
        &self,
        value: &LateReplyDispositionToken,
    ) -> Option<VerifiedTurnCredential> {
        self.registry_claims(&value.seal, CredentialKind::LateDisposition)
    }

    pub fn reply_accepted_claims(
        &self,
        value: &ReplyAcceptedReceipt,
    ) -> Option<VerifiedTurnCredential> {
        self.registry_claims(&value.seal, CredentialKind::ReplyAccepted)
    }

    pub fn reply_not_accepted_claims(
        &self,
        value: &ReplyNotAcceptedReceipt,
    ) -> Option<VerifiedTurnCredential> {
        self.registry_claims(&value.seal, CredentialKind::ReplyNotAccepted)
    }

    pub fn admission_claims(
        &self,
        value: &MailboxAdmissionReceipt,
    ) -> Option<VerifiedTurnCredential> {
        verify_seal(
            &value.seal,
            &self.authority_id,
            CredentialKind::MailboxAdmission,
            &self.admission_key,
        )
    }

    pub fn removal_claims(&self, value: &MailboxRemovalReceipt) -> Option<VerifiedTurnCredential> {
        verify_seal(
            &value.seal,
            &self.authority_id,
            CredentialKind::MailboxRemoval,
            &self.removal_key,
        )
    }

    pub fn dequeue_receipt_claims(
        &self,
        value: &MailboxDequeueReceipt,
    ) -> Option<VerifiedTurnCredential> {
        verify_seal(
            &value.seal,
            &self.authority_id,
            CredentialKind::MailboxDequeue,
            &self.dequeue_key,
        )
    }

    pub fn store_proof_claims(
        &self,
        value: &StoreQuiescenceProof,
    ) -> Option<VerifiedTurnCredential> {
        verify_seal(
            &value.seal,
            &self.authority_id,
            CredentialKind::StoreQuiescence,
            &self.store_key,
        )
    }

    pub fn credential_matches_binding_stable(
        &self,
        credential: &VerifiedTurnCredential,
        binding: &TurnRegistryBinding,
    ) -> bool {
        credential_matches_binding(credential, binding, false)
    }

    /// Closed provider-side comparison for two already verified credentials.
    /// Hidden generation and lineage never leave shared types.
    pub fn same_verified_lineage(
        &self,
        left: &VerifiedTurnCredential,
        right: &VerifiedTurnCredential,
    ) -> bool {
        same_lineage(left, right)
    }

    /// Closed provider-side check for an exact correlation binding.  This
    /// exposes no raw context, generation, lineage, nonce, or MAC fact.
    pub fn verified_context_matches(
        &self,
        credential: &VerifiedTurnCredential,
        expected_correlation: [u8; 32],
    ) -> bool {
        bool::from(credential.context.ct_eq(&expected_correlation))
    }

    pub fn dequeue_matches_binding(
        &self,
        receipt: &MailboxDequeueReceipt,
        binding: &TurnRegistryBinding,
    ) -> bool {
        let Some(admission_digest) = binding.admission_digest else {
            return false;
        };
        self.dequeue_receipt_claims(receipt).is_some_and(|claims| {
            credential_matches_binding(&claims, binding, true)
                && self.dequeue_matches(receipt, admission_digest, admission_digest)
        })
    }

    pub fn verify_admission(
        &mut self,
        reservation: &QueuedTurnReservation,
        receipt: &MailboxAdmissionReceipt,
    ) -> Result<(), TurnDispatchError> {
        let reservation = self
            .reservation_claims(reservation)
            .ok_or(TurnDispatchError::ReservationRejected)?;
        let receipt = self
            .admission_claims(receipt)
            .ok_or(TurnDispatchError::ReceiptRejected)?;
        if !same_lineage(&reservation, &receipt) {
            return Err(TurnDispatchError::ReceiptRejected);
        }
        Ok(())
    }

    pub fn verify_removal(
        &mut self,
        receipt: &MailboxRemovalReceipt,
    ) -> Result<(), TurnMailboxError> {
        let claims = self
            .removal_claims(receipt)
            .ok_or(TurnMailboxError::ReceiptRejected)?;
        let context = removal_context(
            receipt.authority_token_digest,
            receipt.admission_digest,
            receipt.facts_digest,
            receipt.disposition,
        );
        if !bool::from(claims.context.ct_eq(&context)) {
            return Err(TurnMailboxError::ReceiptRejected);
        }
        Ok(())
    }

    pub fn removal_matches(
        &self,
        receipt: &MailboxRemovalReceipt,
        authority: &VerifiedTurnCredential,
        expected_disposition: MailboxRemovalDisposition,
    ) -> bool {
        receipt.disposition == expected_disposition
            && bool::from(
                receipt
                    .authority_token_digest
                    .ct_eq(&authority.credential_digest),
            )
            && same_lineage(
                authority,
                &VerifiedTurnCredential {
                    turn_digest: receipt.seal.turn_digest,
                    agent_digest: receipt.seal.agent_digest,
                    generation: receipt.seal.generation,
                    lineage: receipt.seal.lineage,
                    context: receipt.seal.context,
                    credential_digest: receipt.seal.digest(),
                },
            )
    }

    pub fn verify_dequeue(
        &mut self,
        receipt: &MailboxDequeueReceipt,
    ) -> Result<(), TurnMailboxError> {
        let claims = self
            .dequeue_receipt_claims(receipt)
            .ok_or(TurnMailboxError::ReceiptRejected)?;
        let mut context_hasher = Sha256::new();
        context_hasher.update(receipt.admission_digest);
        context_hasher.update(receipt.facts_digest);
        context_hasher.update(receipt.dispatch_barrier_lease_digest);
        let context: [u8; 32] = context_hasher.finalize().into();
        if !bool::from(claims.context.ct_eq(&context)) {
            return Err(TurnMailboxError::ReceiptRejected);
        }
        Ok(())
    }

    pub fn dequeue_matches(
        &self,
        receipt: &MailboxDequeueReceipt,
        registered_digest: [u8; 32],
        admission_digest: [u8; 32],
    ) -> bool {
        bool::from(receipt.registered_turn_digest.ct_eq(&registered_digest))
            && bool::from(receipt.admission_digest.ct_eq(&admission_digest))
    }

    pub fn verify_store(&mut self, proof: &StoreQuiescenceProof) -> Result<(), TurnExecutionError> {
        let claims = self
            .store_proof_claims(proof)
            .ok_or(TurnExecutionError::ProofRejected)?;
        if claims.lineage != proof.store_incarnation {
            return Err(TurnExecutionError::ProofRejected);
        }
        match proof.kind {
            StoreQuiescenceKind::Drained { .. } => {}
            StoreQuiescenceKind::StoreDestroyed { store_incarnation }
                if store_incarnation == proof.store_incarnation => {}
            StoreQuiescenceKind::StoreDestroyed { .. } => {
                return Err(TurnExecutionError::ProofRejected)
            }
        }
        Ok(())
    }
}

fn verify_seal(
    seal: &CredentialSeal,
    authority_id: &[u8; 16],
    kind: CredentialKind,
    key: &[u8; 32],
) -> Option<VerifiedTurnCredential> {
    seal.verify(authority_id, kind, key)
        .then(|| VerifiedTurnCredential {
            turn_digest: seal.turn_digest,
            agent_digest: seal.agent_digest,
            generation: seal.generation,
            lineage: seal.lineage,
            context: seal.context,
            credential_digest: seal.digest(),
        })
}

fn same_lineage(left: &VerifiedTurnCredential, right: &VerifiedTurnCredential) -> bool {
    left.generation == right.generation
        && bool::from(left.turn_digest.ct_eq(&right.turn_digest))
        && bool::from(left.agent_digest.ct_eq(&right.agent_digest))
        && bool::from(left.lineage.ct_eq(&right.lineage))
}

fn credential_matches_binding(
    credential: &VerifiedTurnCredential,
    binding: &TurnRegistryBinding,
    require_current_generation: bool,
) -> bool {
    (!require_current_generation || credential.generation == binding.generation)
        && bool::from(credential.turn_digest.ct_eq(&binding.turn_digest))
        && bool::from(credential.agent_digest.ct_eq(&binding.agent_digest))
        && bool::from(credential.lineage.ct_eq(&binding.lineage))
}

fn random_context() -> [u8; 32] {
    let mut context = [0; 32];
    rand::rngs::OsRng.fill_bytes(&mut context);
    context
}

fn now_unix_ms() -> Result<u64, TurnExecutionError> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| TurnExecutionError::RecoveryJournalUnavailable)?
        .as_millis();
    u64::try_from(millis).map_err(|_| TurnExecutionError::RecoveryJournalUnavailable)
}

fn store_evidence_digest(proof: &StoreQuiescenceProof, credential_digest: [u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"advance.contract216.store-quiescence-evidence.v1\0");
    hasher.update(credential_digest);
    hasher.update(proof.store_incarnation);
    match proof.kind {
        StoreQuiescenceKind::Drained { store_epoch } => {
            hasher.update([1]);
            hasher.update(store_epoch.to_be_bytes());
        }
        StoreQuiescenceKind::StoreDestroyed { store_incarnation } => {
            hasher.update([2]);
            hasher.update(store_incarnation);
        }
    }
    hasher.finalize().into()
}

fn map_journal_dispatch(error: TurnJournalWriteError) -> TurnDispatchError {
    match error {
        TurnJournalWriteError::Capacity => TurnDispatchError::RecoveryCapacityExhausted,
        TurnJournalWriteError::Conflict => TurnDispatchError::StateConflict,
        TurnJournalWriteError::Unavailable => TurnDispatchError::RecoveryJournalUnavailable,
        TurnJournalWriteError::Rollback | TurnJournalWriteError::Corrupt => {
            TurnDispatchError::RollbackDetected
        }
    }
}

fn map_journal_execution(error: TurnJournalWriteError) -> TurnExecutionError {
    match error {
        TurnJournalWriteError::Capacity => TurnExecutionError::RecoveryCapacityExhausted,
        TurnJournalWriteError::Conflict => TurnExecutionError::StateConflict,
        TurnJournalWriteError::Unavailable => TurnExecutionError::RecoveryJournalUnavailable,
        TurnJournalWriteError::Rollback | TurnJournalWriteError::Corrupt => {
            TurnExecutionError::RollbackDetected
        }
    }
}

fn map_journal_init(error: TurnJournalWriteError) -> TurnAuthorityInitError {
    match error {
        TurnJournalWriteError::Capacity => TurnAuthorityInitError::RecoveryCapacityInvalid,
        TurnJournalWriteError::Conflict | TurnJournalWriteError::Corrupt => {
            TurnAuthorityInitError::RecoveryJournalCorrupt
        }
        TurnJournalWriteError::Unavailable => TurnAuthorityInitError::AnchorUnavailable,
        TurnJournalWriteError::Rollback => TurnAuthorityInitError::RollbackDetected,
    }
}

/// Move-only proof that the CONTRACT-216 authority was staged successfully.
/// It is consumed by the CONTRACT-215 factory before either contract may be
/// published.  No ordinary caller can construct, clone, or deserialize it.
pub struct Contract216ActivationStaging {
    authority_id: [u8; 16],
    runtime_provider_binding: [u8; 32],
}

pub(crate) struct Contract216JointActivationBinding {
    pub(crate) authority_id: [u8; 16],
    pub(crate) runtime_provider_binding: [u8; 32],
}

impl Contract216ActivationStaging {
    /// Crate-internal handoff into the C215 joint-publication authority.
    pub(crate) fn consume_for_joint_activation(self) -> Contract216JointActivationBinding {
        Contract216JointActivationBinding {
            authority_id: self.authority_id,
            runtime_provider_binding: self.runtime_provider_binding,
        }
    }
}

opaque_debug!(Contract216ActivationStaging);

pub struct TurnAttributionAuthorityParts {
    pub activation_staging: Contract216ActivationStaging,
    pub registry_issuer: TurnRegistryIssuer,
    pub mailbox_admission_issuer: MailboxAdmissionIssuer,
    pub mailbox_removal_issuer: MailboxRemovalIssuer,
    pub mailbox_dequeue_issuer: MailboxDequeueIssuer,
    pub mailbox_publish_verifier: MailboxPublishVerifier,
    pub store_quiescence_issuer: StoreQuiescenceIssuer,
    pub source_quiescence_recovery_issuer: SourceQuiescenceRecoveryIssuer,
    pub source_quiescence_verifier: SourceTurnQuiescenceVerifier,
    pub verifier: TurnAttributionVerifier,
}

opaque_debug!(TurnAttributionAuthorityParts);

pub struct TurnAttributionAuthorityFactory;

impl TurnAttributionAuthorityFactory {
    pub fn new_at_composition<R: RngCore + CryptoRng>(
        rng: &mut R,
        recovery: TurnRecoveryJournalRole,
    ) -> Result<TurnAttributionAuthorityParts, TurnAuthorityInitError> {
        let mut authority_id = [0; 16];
        let mut root = Zeroizing::new([0; 32]);
        if !fill_nonzero(rng, &mut authority_id) || !fill_nonzero(rng, &mut *root) {
            return Err(TurnAuthorityInitError::EntropyUnavailable);
        }
        let registry_key = derive_key(&root, authority_id, KEY_REGISTRY)?;
        let admission_key = derive_key(&root, authority_id, KEY_ADMISSION)?;
        let removal_key = derive_key(&root, authority_id, KEY_REMOVAL)?;
        let dequeue_key = derive_key(&root, authority_id, KEY_DEQUEUE)?;
        let store_key = derive_key(&root, authority_id, KEY_STORE)?;
        let source_key = derive_key(&root, authority_id, KEY_SOURCE_QUIESCENCE)?;
        recovery
            .current_runtime_incarnation()
            .map_err(map_journal_init)?;
        let journal = Arc::new(TurnJournalAuthority { recovery });
        Ok(TurnAttributionAuthorityParts {
            activation_staging: Contract216ActivationStaging {
                authority_id,
                runtime_provider_binding: runtime_provider_binding_digest(
                    authority_id,
                    &registry_key,
                ),
            },
            registry_issuer: TurnRegistryIssuer {
                authority_id,
                key: Zeroizing::new(registry_key),
                admission_key: Zeroizing::new(admission_key),
                dequeue_key: Zeroizing::new(dequeue_key),
                store_key: Zeroizing::new(store_key),
                source_key: Zeroizing::new(source_key),
                journal: Arc::clone(&journal),
                next_generation: 0,
            },
            mailbox_admission_issuer: MailboxAdmissionIssuer {
                authority_id,
                registry_key: Zeroizing::new(registry_key),
                admission_key: Zeroizing::new(admission_key),
            },
            mailbox_removal_issuer: MailboxRemovalIssuer {
                authority_id,
                registry_key: Zeroizing::new(registry_key),
                admission_key: Zeroizing::new(admission_key),
                removal_key: Zeroizing::new(removal_key),
            },
            mailbox_dequeue_issuer: MailboxDequeueIssuer {
                authority_id,
                admission_key: Zeroizing::new(admission_key),
                dequeue_key: Zeroizing::new(dequeue_key),
            },
            mailbox_publish_verifier: MailboxPublishVerifier {
                authority_id,
                registry_key: Zeroizing::new(registry_key),
                admission_key: Zeroizing::new(admission_key),
            },
            store_quiescence_issuer: StoreQuiescenceIssuer {
                authority_id,
                store_key: Zeroizing::new(store_key),
            },
            source_quiescence_recovery_issuer: SourceQuiescenceRecoveryIssuer {
                authority_id,
                source_key: Zeroizing::new(source_key),
                journal,
            },
            source_quiescence_verifier: SourceTurnQuiescenceVerifier {
                authority_id,
                source_key: Zeroizing::new(source_key),
            },
            verifier: TurnAttributionVerifier {
                authority_id,
                registry_key: Zeroizing::new(registry_key),
                admission_key: Zeroizing::new(admission_key),
                removal_key: Zeroizing::new(removal_key),
                dequeue_key: Zeroizing::new(dequeue_key),
                store_key: Zeroizing::new(store_key),
            },
        })
    }
}

opaque_debug!(TurnAttributionAuthorityFactory);

fn fill_nonzero<R: RngCore + ?Sized, const N: usize>(rng: &mut R, out: &mut [u8; N]) -> bool {
    for _ in 0..MAX_NONZERO_ENTROPY_ATTEMPTS {
        rng.fill_bytes(out);
        if out.iter().any(|byte| *byte != 0) {
            return true;
        }
    }
    false
}

fn derive_key(
    root: &[u8; 32],
    authority_id: [u8; 16],
    info: &[u8],
) -> Result<[u8; 32], TurnAuthorityInitError> {
    let hkdf = Hkdf::<Sha256>::new(Some(&authority_id), root);
    let mut out = [0; 32];
    hkdf.expand(info, &mut out)
        .map_err(|_| TurnAuthorityInitError::EntropyUnavailable)?;
    Ok(out)
}

fn runtime_provider_binding_digest(authority_id: [u8; 16], key: &[u8; 32]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts 32-byte keys");
    mac.update(RUNTIME_PROVIDER_BINDING_DOMAIN);
    mac.update(&authority_id);
    mac.finalize().into_bytes().into()
}

impl TurnRuntimeProviderBinding {
    pub(crate) fn matches(&self, authority_id: &[u8; 16], binding: &[u8; 32]) -> bool {
        bool::from(self.authority_id.ct_eq(authority_id)) && bool::from(self.binding.ct_eq(binding))
    }
}

pub trait TurnDispatchLifecyclePort: Send + Sync {
    fn reserve_queued(
        &self,
        spec: QueuedTurnSpec,
    ) -> Result<QueuedTurnReservation, TurnDispatchError>;

    fn confirm_mailbox_admission(
        &self,
        reservation: &QueuedTurnReservation,
        receipt: &MailboxAdmissionReceipt,
    ) -> Result<ConfirmedTurnAdmission, TurnDispatchError>;

    fn abort_non_admitted(
        &self,
        reservation: &QueuedTurnReservation,
        receipt: &MailboxRemovalReceipt,
    ) -> Result<(), TurnDispatchError>;

    fn abort_confirmed_admission(
        &self,
        cleanup: &ConfirmedAdmissionCleanupToken,
        receipt: &MailboxRemovalReceipt,
    ) -> Result<(), TurnDispatchError>;

    fn batch_detach(
        &self,
        session_id: &SessionId,
        turns: &[RegisteredTurnHandle],
    ) -> Result<DetachBatchOutcome, TurnDispatchError>;

    fn recover_abandoned_claims(&self) -> Result<ReplyRecoverySummary, TurnDispatchError>;
}

pub trait TurnExecutionLifecyclePort: Send + Sync {
    fn start_turn(
        &self,
        dequeued: &DequeuedTurnHandle,
    ) -> Result<TurnStartOutcome, TurnExecutionError>;

    fn abandon_before_start(&self, dequeued: &DequeuedTurnHandle)
        -> Result<(), TurnExecutionError>;

    fn finish_turn(
        &self,
        proof: StoreQuiescenceProof,
    ) -> Result<TurnFinishResult, TurnExecutionError>;
}

pub trait TurnReplyRoutingPort: Send + Sync {
    fn classify_send(
        &self,
        turn_id: &str,
        expected_agent: &str,
        destination: &str,
    ) -> SendTurnClassification;

    fn claim_active_reply(
        &self,
        turn_id: &str,
        expected_agent: &str,
        destination: &str,
    ) -> Result<ReplyRouteClaim, TurnReplyError>;

    fn begin_reply_delivery(&self, token: &ActiveReplyClaimToken) -> Result<(), TurnReplyError>;

    /// Commit a definitely accepted delivery.  The provider mints and
    /// records its recovery marker internally before consuming the claim;
    /// the consumer never receives a generic receipt issuer.
    fn settle_reply_accepted(
        &self,
        token: &ActiveReplyClaimToken,
    ) -> Result<ReplySettlement, TurnReplyError>;

    /// Roll back a delivery that is definitely known not to have been
    /// accepted.  Unknown outcomes must use `abandon_reply` instead.
    fn settle_reply_not_accepted(
        &self,
        token: &ActiveReplyClaimToken,
    ) -> Result<ReplySettlement, TurnReplyError>;

    fn complete_reply(
        &self,
        token: &ActiveReplyClaimToken,
        receipt: ReplyAcceptedReceipt,
    ) -> Result<ReplySettlement, TurnReplyError>;

    fn abort_reply(
        &self,
        token: &ActiveReplyClaimToken,
        proof: ReplyAbortProof,
    ) -> Result<ReplySettlement, TurnReplyError>;

    fn abandon_reply(&self, token: &ActiveReplyClaimToken) -> Result<(), TurnReplyError>;

    fn claim_reply_late(
        &self,
        turn_id: &str,
        expected_agent: &str,
        destination: &str,
    ) -> Result<LateReplyClaim, TurnReplyError>;

    fn complete_reply_late(&self, token: LateReplyDispositionToken) -> Result<(), TurnReplyError>;
}

pub trait TurnMailboxLifecyclePort: Send + Sync {
    fn record_dequeued(
        &self,
        receipt: &MailboxDequeueReceipt,
    ) -> Result<RecordedDequeueHandoff, TurnMailboxError>;

    fn complete_dequeue_handoff(
        &self,
        receipt: &MailboxDequeueReceipt,
        recorded: &RecordedDequeueHandoff,
    ) -> Result<DequeuedTurnHandle, TurnMailboxError>;

    fn abandon_dequeuing(&self, receipt: &MailboxDequeueReceipt) -> Result<(), TurnMailboxError>;

    fn settle_removed_queued(
        &self,
        cleanup: &QueuedDetachCleanupToken,
        receipt: &MailboxRemovalReceipt,
    ) -> Result<(), TurnMailboxError>;
}

pub trait TurnCostAttributionReadPort: Send + Sync {
    fn cost_attribution(&self, turn_id: &str, expected_agent: &str) -> CostAttributionLookup;
}

/// Validate that a batch contains no duplicate credential.  Kept here so the
/// provider can perform the check without exposing any token field.
pub fn registered_batch_is_unique(
    verifier: &TurnAttributionVerifier,
    turns: &[RegisteredTurnHandle],
) -> bool {
    let mut seen = HashSet::with_capacity(turns.len());
    turns.iter().all(|turn| {
        verifier
            .registered_claims(turn)
            .is_some_and(|claims| seen.insert(claims.correlation_digest()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Error;

    struct ScriptedRng {
        zero_fills_remaining: usize,
        fills: usize,
    }

    impl RngCore for ScriptedRng {
        fn next_u32(&mut self) -> u32 {
            0
        }

        fn next_u64(&mut self) -> u64 {
            0
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            self.fills += 1;
            if self.zero_fills_remaining == 0 {
                dest.fill(0xa5);
            } else {
                self.zero_fills_remaining -= 1;
                dest.fill(0);
            }
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    impl CryptoRng for ScriptedRng {}

    #[test]
    fn turn_lineage_entropy_rejects_a_bounded_deterministic_zero_rng() {
        let mut rng = ScriptedRng {
            zero_fills_remaining: usize::MAX,
            fills: 0,
        };
        let mut lineage = [0; 16];

        assert!(!fill_nonzero(&mut rng, &mut lineage));
        assert_eq!(lineage, [0; 16]);
        assert_eq!(rng.fills, MAX_NONZERO_ENTROPY_ATTEMPTS);
    }

    #[test]
    fn turn_lineage_entropy_accepts_the_last_bounded_retry() {
        let mut rng = ScriptedRng {
            zero_fills_remaining: MAX_NONZERO_ENTROPY_ATTEMPTS - 1,
            fills: 0,
        };
        let mut lineage = [0; 16];

        assert!(fill_nonzero(&mut rng, &mut lineage));
        assert_eq!(lineage, [0xa5; 16]);
        assert_eq!(rng.fills, MAX_NONZERO_ENTROPY_ATTEMPTS);
    }
}

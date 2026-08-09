//! CONTRACT-215 shared progress-card values.
//!
//! These values carry only host-trusted correlation and bounded enums. The
//! concrete card coordinator remains MODULE-016-owned; MODULE-006 and the host
//! reconciler receive separate authority ports added below rather than a
//! monolithic coordinator facade.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::progress_lifecycle_recovery::{
    ProgressAttemptCommit, ProgressAttemptKind, ProgressAuthorityEnvelope,
    ProgressAuthorityExpectation, ProgressAuthorityRow, ProgressAuthorityState,
    ProgressAuthorityTerminal, ProgressCloseSnapshot, ProgressCloseTargetKind,
    ProgressJournalError, ProgressLiveSnapshot, ProgressProtectedCardRow,
    ProgressRecoveryJournalRole, ProgressRouteArmInput, ProgressRouteExpectation,
    ProgressRouteRefExpectation, ProgressRouteRefKind, ProgressRouteSealInput,
    ProgressSealedRouteRecord, ProgressSourceCloseCommit,
};
use crate::turn_attribution::{
    Contract216ActivationStaging, SourceTurnQuiescedReceipt, SourceTurnQuiescenceVerifier,
    TurnExecutionError, TurnRuntimeProviderBinding,
};

pub const MAX_PROGRESS_CARD_KEY_COMPONENT_BYTES: usize = 256;
pub const MAX_PROGRESS_CARD_KEY_RAW_BYTES: usize = 1_024;

/// Host-stamped one-card key. No component may be sourced from ADVPRG metadata.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ProgressCardKey {
    pub adapter_id: String,
    pub subscription_id: String,
    pub conversation_id: String,
    pub source_message_id: String,
}

impl ProgressCardKey {
    /// Validate canonical raw components and return the CONTRACT-215 digest.
    pub fn digest(&self) -> Result<[u8; 32], ProgressCardKeyError> {
        let parts = [
            self.adapter_id.as_bytes(),
            self.subscription_id.as_bytes(),
            self.conversation_id.as_bytes(),
            self.source_message_id.as_bytes(),
        ];
        let mut aggregate = 0usize;
        for part in parts {
            if part.is_empty()
                || part.len() > MAX_PROGRESS_CARD_KEY_COMPONENT_BYTES
                || part.iter().any(|byte| matches!(*byte, 0 | b'\r' | b'\n'))
            {
                return Err(ProgressCardKeyError);
            }
            aggregate = aggregate
                .checked_add(part.len())
                .ok_or(ProgressCardKeyError)?;
        }
        if aggregate > MAX_PROGRESS_CARD_KEY_RAW_BYTES {
            return Err(ProgressCardKeyError);
        }

        let mut hasher = Sha256::new();
        hasher.update(b"advance.contract215.progress-card-key.v1");
        hasher.update([0]);
        for part in parts {
            hasher.update((part.len() as u32).to_be_bytes());
            hasher.update(part);
        }
        Ok(hasher.finalize().into())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProgressCardKeyError;

impl std::fmt::Display for ProgressCardKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("progress-key-invalid")
    }
}

impl std::error::Error for ProgressCardKeyError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum ProgressPhase {
    Ack = 0,
    Progress = 1,
    Result = 2,
    Error = 3,
}

impl ProgressPhase {
    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "ack" => Self::Ack,
            "progress" => Self::Progress,
            "result" => Self::Result,
            "error" => Self::Error,
            _ => return None,
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ack => "ack",
            Self::Progress => "progress",
            Self::Result => "result",
            Self::Error => "error",
        }
    }

    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Result | Self::Error)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum IndeterminateAttemptKind {
    InitialSend,
    Edit { prior_message_id: i64 },
    FallbackSend { definitively_lost_message_id: i64 },
}

/// Durable protected card image owned by the shared anti-rollback journal.
/// Process-local `Live` state is intentionally absent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DurableProgressCardRecord {
    TerminalTombstone {
        terminal_fingerprint: [u8; 32],
        delivered_at_ms: u64,
    },
    IndeterminateSend {
        attempt_id: [u8; 16],
        delivery_fingerprint: [u8; 32],
        phase: ProgressPhase,
        attempt_kind: IndeterminateAttemptKind,
        first_attempted_at_ms: u64,
    },
    FallbackExhausted {
        delivery_fingerprint: [u8; 32],
        definitively_lost_message_id: i64,
        reconciled_at_ms: u64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DurableProgressCardEntry {
    pub generation: u64,
    pub record: DurableProgressCardRecord,
}

/// Provider-supplied process-local card image used only to bind a close
/// challenge to the journal's current runtime and lifecycle row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProgressLiveCardSnapshot {
    pub generation: u64,
    pub telegram_message_id: i64,
}

pub const SOURCE_CLOSE_CHALLENGE_LIFETIME_MS: u64 = 5 * 60 * 1_000;
pub const SOURCE_CLOSE_RECEIPT_LIFETIME_MS: u64 = 15 * 60 * 1_000;
pub const ATTEMPT_RECONCILIATION_LIFETIME_MS: u64 = 15 * 60 * 1_000;
const AUTHORITY_RETAIN_MS: u64 = 24 * 60 * 60 * 1_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum OutboundRouteRefKind {
    Action = 0,
    Retry = 1,
    Replay = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ProtectedRecordKind {
    NoCard = 0,
    Live = 1,
    TerminalTombstone = 2,
    IndeterminateSend = 3,
    FallbackExhausted = 4,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ReconciledAttemptOutcome {
    Delivered = 0,
    DefinitelyNotDelivered = 1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ReconciliationEvidenceSource {
    LateHttpCompletion = 0,
    DurableTransportReceipt = 1,
}

pub struct OutboundRouteBinding {
    authority_id: [u8; 16],
    key_digest: [u8; 32],
    source_message_id_digest: [u8; 32],
    lifecycle_generation: u64,
    nonce: [u8; 16],
    mac: [u8; 32],
}

pub struct OutboundRouteRef {
    authority_id: [u8; 16],
    key_digest: [u8; 32],
    source_message_id_digest: [u8; 32],
    lifecycle_generation: u64,
    ref_id: [u8; 16],
    kind: OutboundRouteRefKind,
    mac: [u8; 32],
}

pub struct OutboundRoutesSealedReceipt {
    authority_id: [u8; 16],
    key_digest: [u8; 32],
    source_message_id_digest: [u8; 32],
    source_quiesced_receipt_digest: [u8; 32],
    route_seal_generation: u64,
    action_refs: u32,
    retry_refs: u32,
    replay_refs: u32,
    issued_at_ms: u64,
    expires_at_ms: u64,
    nonce: [u8; 16],
    mac: [u8; 32],
}

pub struct SourceCloseChallenge {
    authority_id: [u8; 16],
    key_digest: [u8; 32],
    source_message_id_digest: [u8; 32],
    record_generation: u64,
    record_kind: ProtectedRecordKind,
    record_fingerprint: [u8; 32],
    issued_at_ms: u64,
    expires_at_ms: u64,
    nonce: [u8; 16],
    mac: [u8; 32],
}

pub struct SourceLifecycleCloseAttestation {
    authority_id: [u8; 16],
    challenge_digest: [u8; 32],
    key_digest: [u8; 32],
    source_message_id_digest: [u8; 32],
    source_quiesced_receipt_digest: [u8; 32],
    outbound_routes_sealed_receipt_digest: [u8; 32],
    issued_at_ms: u64,
    expires_at_ms: u64,
    nonce: [u8; 16],
    mac: [u8; 32],
    route_authority: ProgressAuthorityRow,
}

pub struct AttemptReconciliationChallenge {
    authority_id: [u8; 16],
    key_digest: [u8; 32],
    record_generation: u64,
    attempt_id: [u8; 16],
    attempt_kind: IndeterminateAttemptKind,
    delivery_fingerprint: [u8; 32],
    phase: ProgressPhase,
    issued_at_ms: u64,
    expires_at_ms: u64,
    nonce: [u8; 16],
    mac: [u8; 32],
}

pub struct TrustedAttemptOutcomeReceipt {
    authority_id: [u8; 16],
    challenge_digest: [u8; 32],
    key_digest: [u8; 32],
    record_generation: u64,
    attempt_id: [u8; 16],
    attempt_kind: IndeterminateAttemptKind,
    delivery_fingerprint: [u8; 32],
    outcome: ReconciledAttemptOutcome,
    telegram_message_id: Option<i64>,
    evidence_source: ReconciliationEvidenceSource,
    evidence_id: [u8; 16],
    evidence_digest: [u8; 32],
    issued_at_ms: u64,
    expires_at_ms: u64,
    nonce: [u8; 16],
    mac: [u8; 32],
}

pub struct AttemptReconciliationProof {
    authority_id: [u8; 16],
    challenge_digest: [u8; 32],
    key_digest: [u8; 32],
    record_generation: u64,
    attempt_id: [u8; 16],
    attempt_kind: IndeterminateAttemptKind,
    delivery_fingerprint: [u8; 32],
    outcome: ReconciledAttemptOutcome,
    telegram_message_id: Option<i64>,
    evidence_source: ReconciliationEvidenceSource,
    evidence_id: [u8; 16],
    evidence_digest: [u8; 32],
    issued_at_ms: u64,
    expires_at_ms: u64,
    nonce: [u8; 16],
    mac: [u8; 32],
}

macro_rules! opaque_debug {
    ($($ty:ty),+ $(,)?) => {$ (
        impl std::fmt::Debug for $ty {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(concat!(stringify!($ty), "([opaque])"))
            }
        }
    )+ };
}

opaque_debug!(
    OutboundRouteBinding,
    OutboundRouteRef,
    OutboundRoutesSealedReceipt,
    SourceCloseChallenge,
    SourceLifecycleCloseAttestation,
    AttemptReconciliationChallenge,
    TrustedAttemptOutcomeReceipt,
    AttemptReconciliationProof,
);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProgressCardAuthorityError {
    InvalidInput,
    WrongAuthority,
    InvalidMac,
    BindingMismatch,
    WrongOrder,
    RoutesNotQuiescent,
    Expired,
    Replayed,
    CapacityExhausted,
    GenerationExhausted,
    JournalUnavailable,
    IntegrityFailure,
}

impl std::fmt::Display for ProgressCardAuthorityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Expired => "authority-expired",
            Self::Replayed => "authority-replayed",
            Self::CapacityExhausted => "progress-card-capacity",
            Self::GenerationExhausted => "progress-generation-exhausted",
            Self::JournalUnavailable => "progress-journal-unavailable",
            Self::IntegrityFailure => "progress-integrity-failure",
            _ => "authority-rejected",
        })
    }
}

impl std::error::Error for ProgressCardAuthorityError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProgressCardAuthorityInitError {
    EntropyUnavailable,
    KeyDerivationFailed,
    JournalUnavailable,
    JournalIntegrityFailure,
    C216ProviderMismatch,
}

impl std::fmt::Display for ProgressCardAuthorityInitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::EntropyUnavailable => "progress-authority-entropy-unavailable",
            Self::KeyDerivationFailed => "progress-authority-key-derivation-failed",
            Self::JournalUnavailable => "progress-journal-unavailable",
            Self::JournalIntegrityFailure => "progress-integrity-failure",
            Self::C216ProviderMismatch => "joint-activation-c216-provider-mismatch",
        })
    }
}

impl std::error::Error for ProgressCardAuthorityInitError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProgressCardCoordinatorError {
    InvalidKey,
    Missing,
    NotIndeterminate,
    StaleChallenge,
    BindingMismatch,
    Expired,
    Replayed,
    AuthorityInProgress,
    Busy,
    CapacityExhausted,
    GenerationExhausted,
    JournalUnavailable,
    IntegrityFailure,
}

impl std::fmt::Display for ProgressCardCoordinatorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidKey => "progress-key-invalid",
            Self::Missing => "progress-record-unavailable",
            Self::NotIndeterminate => "reconciliation-unavailable",
            Self::StaleChallenge | Self::BindingMismatch => "progress-authority-mismatch",
            Self::Expired => "progress-authority-expired",
            Self::Replayed => "progress-authority-replayed",
            Self::AuthorityInProgress => "progress-authority-in-progress",
            Self::Busy => "progress-record-busy",
            Self::CapacityExhausted => "progress-card-capacity",
            Self::GenerationExhausted => "progress-generation-exhausted",
            Self::JournalUnavailable => "progress-journal-unavailable",
            Self::IntegrityFailure => "progress-integrity-failure",
        })
    }
}

impl std::error::Error for ProgressCardCoordinatorError {}

pub trait ProgressSourceLifecyclePort: Send + Sync {
    fn begin_source_close(
        &self,
        source: &SourceTurnQuiescedReceipt,
    ) -> Result<SourceCloseChallenge, ProgressCardCoordinatorError>;
    fn close_source(
        &self,
        source: &SourceTurnQuiescedReceipt,
        challenge: &SourceCloseChallenge,
        attestation: &SourceLifecycleCloseAttestation,
    ) -> Result<(), ProgressCardCoordinatorError>;
    fn cancel_source_close(
        &self,
        source: &SourceTurnQuiescedReceipt,
        challenge: &SourceCloseChallenge,
    ) -> Result<(), ProgressCardCoordinatorError>;
}

pub trait ProgressAttemptReconciliationPort: Send + Sync {
    fn begin_attempt_reconciliation(
        &self,
        key: &ProgressCardKey,
    ) -> Result<AttemptReconciliationChallenge, ProgressCardCoordinatorError>;
    fn reconcile_attempt(
        &self,
        key: &ProgressCardKey,
        challenge: &AttemptReconciliationChallenge,
        proof: &AttemptReconciliationProof,
    ) -> Result<ReconciledAttemptOutcome, ProgressCardCoordinatorError>;
    fn cancel_attempt_reconciliation(
        &self,
        key: &ProgressCardKey,
        challenge: &AttemptReconciliationChallenge,
    ) -> Result<(), ProgressCardCoordinatorError>;
}

pub struct ProgressCardAuthorityFactory;

pub struct ProgressCardAuthorityParts {
    pub protected_state_issuer: ProgressProtectedStateIssuer,
    pub coordinator_challenge_issuer: ProgressCardChallengeIssuer,
    pub outbound_route_seal_issuer: OutboundRouteSealIssuer,
    pub source_close_attestation_issuer: SourceCloseAttestationIssuer,
    pub transport_outcome_receipt_issuer: TrustedTransportOutcomeReceiptIssuer,
    pub reconciliation_proof_issuer: AttemptReconciliationIssuer,
    pub verifier: ProgressCardAuthorityVerifier,
    pub joint_activation_authority: JointC215C216ActivationAuthority,
}

/// Linear publication permit emitted only after the C215 factory has consumed
/// C216 staging authority. Product composition moves this into the dispatcher
/// only after every role injection succeeds.
pub struct JointC215C216ActivationAuthority {
    contract216_authority_id: [u8; 16],
    contract215_authority_id: [u8; 16],
    expected_runtime_provider_binding: [u8; 32],
    expected_route_provider_binding: [u8; 32],
    publication_nonce: [u8; 16],
}

/// Opaque read-only identity of the exact C215 route issuer consumed by the
/// staged route provider.  It is neither cloneable nor serializable and has
/// no public constructor.
pub struct OutboundRouteProviderBinding {
    authority_id: [u8; 16],
    binding: [u8; 32],
}

/// Linear permit minted only after one joint authority verifies both the
/// C216 runtime-provider binding and C215 route-provider binding from its own
/// factories.
pub struct JointC215C216PublicationPermit {
    binding: [u8; 32],
}

/// Nonzero binding retained by the dispatcher after consuming the linear
/// permit.  Possession is the routed-publication guard; its bytes never leave
/// shared types.
pub struct JointC215C216PublicationBinding {
    binding: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JointC215C216BindingError {
    C216RuntimeProviderMismatch,
    C215RouteProviderMismatch,
    InvalidPublicationPermit,
}

impl std::fmt::Display for JointC215C216BindingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::C216RuntimeProviderMismatch => "joint-activation-c216-runtime-provider-mismatch",
            Self::C215RouteProviderMismatch => "joint-activation-c215-route-provider-mismatch",
            Self::InvalidPublicationPermit => "joint-activation-publication-permit-invalid",
        })
    }
}

impl std::error::Error for JointC215C216BindingError {}

pub struct ProgressCardChallengeIssuer {
    authority_id: [u8; 16],
    key: Zeroizing<[u8; 32]>,
    journal: Arc<ProgressRecoveryJournalRole>,
}

pub struct OutboundRouteSealIssuer {
    authority_id: [u8; 16],
    key: Zeroizing<[u8; 32]>,
    journal: Arc<ProgressRecoveryJournalRole>,
}

/// Narrow protected-card state role consumed only by MODULE-016's private
/// coordinator. It exposes typed compare-and-replace transitions, never the
/// raw journal role or generic row operations.
pub struct ProgressProtectedStateIssuer {
    journal: Arc<ProgressRecoveryJournalRole>,
}

pub struct SourceCloseAttestationIssuer {
    authority_id: [u8; 16],
    challenge_key: Zeroizing<[u8; 32]>,
    route_key: Zeroizing<[u8; 32]>,
    close_key: Zeroizing<[u8; 32]>,
    source_verifier: SourceTurnQuiescenceVerifier,
    journal: Arc<ProgressRecoveryJournalRole>,
}

pub struct TrustedTransportOutcomeReceiptIssuer {
    authority_id: [u8; 16],
    challenge_key: Zeroizing<[u8; 32]>,
    key: Zeroizing<[u8; 32]>,
    journal: Arc<ProgressRecoveryJournalRole>,
}

pub struct AttemptReconciliationIssuer {
    authority_id: [u8; 16],
    challenge_key: Zeroizing<[u8; 32]>,
    transport_key: Zeroizing<[u8; 32]>,
    key: Zeroizing<[u8; 32]>,
    journal: Arc<ProgressRecoveryJournalRole>,
}

pub struct ProgressCardAuthorityVerifier {
    authority_id: [u8; 16],
    challenge_key: Zeroizing<[u8; 32]>,
    route_key: Zeroizing<[u8; 32]>,
    close_key: Zeroizing<[u8; 32]>,
    reconciliation_key: Zeroizing<[u8; 32]>,
    journal: Arc<ProgressRecoveryJournalRole>,
}

opaque_debug!(
    ProgressCardChallengeIssuer,
    ProgressProtectedStateIssuer,
    OutboundRouteSealIssuer,
    SourceCloseAttestationIssuer,
    TrustedTransportOutcomeReceiptIssuer,
    AttemptReconciliationIssuer,
    ProgressCardAuthorityVerifier,
    JointC215C216ActivationAuthority,
    OutboundRouteProviderBinding,
    JointC215C216PublicationPermit,
    JointC215C216PublicationBinding,
);

impl JointC215C216ActivationAuthority {
    /// Consume this one-shot authority and bind publication to the exact C216
    /// runtime provider plus exact C215 route provider staged from the same
    /// two factories.  Crossed witnesses fail before a permit exists.
    pub fn bind_runtime_and_route_providers(
        self,
        runtime: &TurnRuntimeProviderBinding,
        route: &OutboundRouteProviderBinding,
    ) -> Result<JointC215C216PublicationPermit, JointC215C216BindingError> {
        if !runtime.matches(
            &self.contract216_authority_id,
            &self.expected_runtime_provider_binding,
        ) {
            return Err(JointC215C216BindingError::C216RuntimeProviderMismatch);
        }
        if !route.matches(
            &self.contract215_authority_id,
            &self.expected_route_provider_binding,
        ) {
            return Err(JointC215C216BindingError::C215RouteProviderMismatch);
        }
        let mut hasher = Sha256::new();
        hasher.update(b"advance.contract215-216.joint-publication-permit.v1\0");
        hasher.update(self.contract216_authority_id);
        hasher.update(self.contract215_authority_id);
        hasher.update(self.expected_runtime_provider_binding);
        hasher.update(self.expected_route_provider_binding);
        hasher.update(self.publication_nonce);
        let binding: [u8; 32] = hasher.finalize().into();
        if binding == [0; 32] {
            return Err(JointC215C216BindingError::InvalidPublicationPermit);
        }
        Ok(JointC215C216PublicationPermit { binding })
    }
}

impl JointC215C216PublicationPermit {
    /// Linear conversion performed by the dispatcher at the sole visibility
    /// barrier.  The retained type cannot be produced from a zero binding.
    pub fn consume_for_publication(
        self,
    ) -> Result<JointC215C216PublicationBinding, JointC215C216BindingError> {
        if self.binding == [0; 32] {
            return Err(JointC215C216BindingError::InvalidPublicationPermit);
        }
        Ok(JointC215C216PublicationBinding {
            binding: self.binding,
        })
    }
}

impl JointC215C216PublicationBinding {
    pub fn authorizes_routed_publication(&self) -> bool {
        self.binding != [0; 32]
    }
}

impl OutboundRouteProviderBinding {
    fn matches(&self, authority_id: &[u8; 16], binding: &[u8; 32]) -> bool {
        bool::from(self.authority_id.ct_eq(authority_id)) && bool::from(self.binding.ct_eq(binding))
    }
}

impl ProgressCardAuthorityFactory {
    /// Product/test composition convenience for consumers that do not expose
    /// `rand` in their own dependency surface.
    pub fn new_with_os_rng_at_composition(
        c216_staging: Contract216ActivationStaging,
        source_verifier: SourceTurnQuiescenceVerifier,
        recovery: ProgressRecoveryJournalRole,
    ) -> Result<ProgressCardAuthorityParts, ProgressCardAuthorityInitError> {
        let mut rng = rand::rngs::OsRng;
        Self::new_at_composition(&mut rng, c216_staging, source_verifier, recovery)
    }

    pub fn new_at_composition(
        rng: &mut (impl RngCore + CryptoRng),
        c216_staging: Contract216ActivationStaging,
        source_verifier: SourceTurnQuiescenceVerifier,
        recovery: ProgressRecoveryJournalRole,
    ) -> Result<ProgressCardAuthorityParts, ProgressCardAuthorityInitError> {
        let contract216 = c216_staging.consume_for_joint_activation();
        if !source_verifier.belongs_to_activation_authority(&contract216.authority_id) {
            return Err(ProgressCardAuthorityInitError::C216ProviderMismatch);
        }
        let mut root = Zeroizing::new([0u8; 32]);
        let mut authority_id = [0u8; 16];
        rng.fill_bytes(root.as_mut());
        rng.fill_bytes(&mut authority_id);
        if root.iter().all(|byte| *byte == 0) || authority_id == [0; 16] {
            return Err(ProgressCardAuthorityInitError::EntropyUnavailable);
        }
        let challenge = derive_role_key(
            &root,
            authority_id,
            b"advance.contract215.role.challenge.v1",
        )
        .map_err(|_| ProgressCardAuthorityInitError::KeyDerivationFailed)?;
        let route = derive_role_key(
            &root,
            authority_id,
            b"advance.contract215.role.route-seal.v1",
        )
        .map_err(|_| ProgressCardAuthorityInitError::KeyDerivationFailed)?;
        let close = derive_role_key(
            &root,
            authority_id,
            b"advance.contract215.role.source-close-attestation.v1",
        )
        .map_err(|_| ProgressCardAuthorityInitError::KeyDerivationFailed)?;
        let transport = derive_role_key(
            &root,
            authority_id,
            b"advance.contract215.role.transport-outcome.v1",
        )
        .map_err(|_| ProgressCardAuthorityInitError::KeyDerivationFailed)?;
        let reconciliation = derive_role_key(
            &root,
            authority_id,
            b"advance.contract215.role.attempt-reconciliation.v1",
        )
        .map_err(|_| ProgressCardAuthorityInitError::KeyDerivationFailed)?;
        let publication_nonce =
            random_nonce().map_err(|_| ProgressCardAuthorityInitError::EntropyUnavailable)?;
        recovery
            .load_protected_cards()
            .map_err(map_journal_init_error)?;
        let journal = Arc::new(recovery);
        Ok(ProgressCardAuthorityParts {
            protected_state_issuer: ProgressProtectedStateIssuer {
                journal: Arc::clone(&journal),
            },
            coordinator_challenge_issuer: ProgressCardChallengeIssuer {
                authority_id,
                key: Zeroizing::new(challenge),
                journal: Arc::clone(&journal),
            },
            outbound_route_seal_issuer: OutboundRouteSealIssuer {
                authority_id,
                key: Zeroizing::new(route),
                journal: Arc::clone(&journal),
            },
            source_close_attestation_issuer: SourceCloseAttestationIssuer {
                authority_id,
                challenge_key: Zeroizing::new(challenge),
                route_key: Zeroizing::new(route),
                close_key: Zeroizing::new(close),
                source_verifier,
                journal: Arc::clone(&journal),
            },
            transport_outcome_receipt_issuer: TrustedTransportOutcomeReceiptIssuer {
                authority_id,
                challenge_key: Zeroizing::new(challenge),
                key: Zeroizing::new(transport),
                journal: Arc::clone(&journal),
            },
            reconciliation_proof_issuer: AttemptReconciliationIssuer {
                authority_id,
                challenge_key: Zeroizing::new(challenge),
                transport_key: Zeroizing::new(transport),
                key: Zeroizing::new(reconciliation),
                journal: Arc::clone(&journal),
            },
            verifier: ProgressCardAuthorityVerifier {
                authority_id,
                challenge_key: Zeroizing::new(challenge),
                route_key: Zeroizing::new(route),
                close_key: Zeroizing::new(close),
                reconciliation_key: Zeroizing::new(reconciliation),
                journal,
            },
            joint_activation_authority: JointC215C216ActivationAuthority {
                contract216_authority_id: contract216.authority_id,
                contract215_authority_id: authority_id,
                expected_runtime_provider_binding: contract216.runtime_provider_binding,
                expected_route_provider_binding: route_provider_binding_digest(
                    authority_id,
                    &route,
                ),
                publication_nonce,
            },
        })
    }
}

impl ProgressProtectedStateIssuer {
    pub fn load(
        &self,
    ) -> Result<BTreeMap<[u8; 32], DurableProgressCardEntry>, ProgressCardCoordinatorError> {
        self.journal
            .load_protected_cards()
            .map_err(map_journal_coordinator_error)?
            .into_iter()
            .map(|(key, row)| public_card_from_journal(row).map(|entry| (key, entry)))
            .collect()
    }

    /// Compare-and-replace one exact durable card image. No generic journal
    /// key/tag/value operation is exposed.
    pub fn replace(
        &self,
        key_digest: [u8; 32],
        expected: Option<&DurableProgressCardEntry>,
        next: Option<&DurableProgressCardEntry>,
    ) -> Result<(), ProgressCardCoordinatorError> {
        let expected = expected.map(journal_card_from_public).transpose()?;
        let next = next.map(journal_card_from_public).transpose()?;
        self.journal
            .replace_protected_card(key_digest, expected, next)
            .map_err(map_journal_coordinator_error)
    }
}

impl OutboundRouteSealIssuer {
    /// Return the opaque identity of the exact route provider that will
    /// consume this linear issuer.  This does not expose route keys or grant
    /// any arm/ref/settle authority.
    pub fn route_provider_binding(&self) -> OutboundRouteProviderBinding {
        OutboundRouteProviderBinding {
            authority_id: self.authority_id,
            binding: route_provider_binding_digest(self.authority_id, &self.key),
        }
    }

    /// Test-support witness hook. Production dependants cannot enable this
    /// surface; it exists only to exercise durable settlement failure paths.
    #[cfg(feature = "test-support")]
    pub fn test_fail_next_journal_transaction_after_prepared_fsync(
        &self,
    ) -> Result<(), ProgressCardAuthorityError> {
        self.journal
            .test_fail_next_transaction_after_prepared_fsync()
            .map_err(map_journal_authority_error)
    }

    /// Atomically bind the current C216 ActiveSource to this key and insert (or
    /// re-read) the exact journal-backed OpenRoutes lifecycle before any card
    /// state or HTTP is reachable.
    pub fn arm_before_progress(
        &mut self,
        key: &ProgressCardKey,
        expected_agent: &str,
    ) -> Result<OutboundRouteBinding, ProgressCardAuthorityError> {
        let key_digest = key
            .digest()
            .map_err(|_| ProgressCardAuthorityError::InvalidInput)?;
        let source_message_id_digest = progress_source_message_id_digest(&key.source_message_id)
            .map_err(|_| ProgressCardAuthorityError::InvalidInput)?;
        let expected_agent_digest = progress_expected_agent_digest(expected_agent)
            .map_err(|_| ProgressCardAuthorityError::InvalidInput)?;
        let record = self
            .journal
            .arm_source_routes(ProgressRouteArmInput {
                key_digest,
                source_digest: source_message_id_digest,
                expected_agent_digest,
                armed_at_ms: current_unix_ms()?,
            })
            .map_err(map_journal_authority_error)?;
        self.binding_from_record(&record)
    }

    fn binding_from_record(
        &self,
        record: &crate::progress_lifecycle_recovery::ProgressRouteBindingRecord,
    ) -> Result<OutboundRouteBinding, ProgressCardAuthorityError> {
        let nonce = random_nonce()?;
        let payload = route_binding_payload(
            self.authority_id,
            record.key_digest,
            record.source_digest,
            record.lifecycle_generation,
            nonce,
        );
        Ok(OutboundRouteBinding {
            authority_id: self.authority_id,
            key_digest: record.key_digest,
            source_message_id_digest: record.source_digest,
            lifecycle_generation: record.lifecycle_generation,
            nonce,
            mac: token_mac(
                &self.key,
                b"advance.contract215.token.route-binding.v1",
                &payload,
            ),
        })
    }

    pub fn acquire_route_ref(
        &mut self,
        binding: &OutboundRouteBinding,
        kind: OutboundRouteRefKind,
    ) -> Result<OutboundRouteRef, ProgressCardAuthorityError> {
        self.verify_binding(binding)?;
        let record = self
            .journal
            .acquire_route_ref(
                ProgressRouteExpectation {
                    key_digest: binding.key_digest,
                    source_digest: binding.source_message_id_digest,
                    lifecycle_generation: binding.lifecycle_generation,
                },
                journal_route_kind(kind),
            )
            .map_err(map_journal_authority_error)?;
        let payload = route_ref_payload(
            self.authority_id,
            record.binding.key_digest,
            record.binding.source_digest,
            record.binding.lifecycle_generation,
            record.ref_id,
            kind,
        );
        Ok(OutboundRouteRef {
            authority_id: self.authority_id,
            key_digest: record.binding.key_digest,
            source_message_id_digest: record.binding.source_digest,
            lifecycle_generation: record.binding.lifecycle_generation,
            ref_id: record.ref_id,
            kind,
            mac: token_mac(
                &self.key,
                b"advance.contract215.token.route-ref.v1",
                &payload,
            ),
        })
    }

    pub fn settle_route_ref(
        &mut self,
        route_ref: &OutboundRouteRef,
    ) -> Result<(), ProgressCardAuthorityError> {
        verify_route_ref_token(self.authority_id, &self.key, route_ref)?;
        self.journal
            .settle_route_ref(ProgressRouteRefExpectation {
                key_digest: route_ref.key_digest,
                source_digest: route_ref.source_message_id_digest,
                ref_id: route_ref.ref_id,
                kind: journal_route_kind(route_ref.kind),
            })
            .map_err(map_journal_authority_error)?;
        Ok(())
    }

    /// Seal from the opaque C216 terminal receipt alone.  The receipt carries
    /// the durable source→key digests, so M001 never needs to reconstruct a
    /// canonical progress key after `finish_turn`.
    pub fn seal_and_issue_for_source(
        &mut self,
        source: &SourceTurnQuiescedReceipt,
    ) -> Result<OutboundRoutesSealedReceipt, ProgressCardAuthorityError> {
        let issued_at_ms = current_unix_ms()?;
        let record = self
            .journal
            .seal_routes(ProgressRouteSealInput {
                key_digest: source.progress_key_digest_for_progress(),
                source_digest: source.source_message_id_digest_for_progress(),
                source_receipt_digest: source.digest_for_progress(),
                sealed_at_ms: issued_at_ms,
            })
            .map_err(map_journal_authority_error)?;
        self.route_receipt_from_record(&record, issued_at_ms)
    }

    pub fn reissue_sealed_for_source(
        &mut self,
        source: &SourceTurnQuiescedReceipt,
    ) -> Result<OutboundRoutesSealedReceipt, ProgressCardAuthorityError> {
        let record = self
            .journal
            .reissue_sealed_routes(
                source.progress_key_digest_for_progress(),
                source.source_message_id_digest_for_progress(),
                source.digest_for_progress(),
            )
            .map_err(map_journal_authority_error)?;
        self.route_receipt_from_record(&record, current_unix_ms()?)
    }

    pub fn cancel_sealed_receipt(
        &mut self,
        receipt: &OutboundRoutesSealedReceipt,
    ) -> Result<(), ProgressCardAuthorityError> {
        verify_route_receipt(self.authority_id, &self.key, receipt, current_unix_ms()?)?;
        self.journal
            .consume_or_cancel_authority(
                ProgressAuthorityExpectation {
                    expected: route_authority_row(receipt)?,
                },
                ProgressAuthorityTerminal::Cancelled {
                    at_ms: current_unix_ms()?,
                },
            )
            .map_err(map_journal_authority_error)
    }

    fn route_receipt_from_record(
        &self,
        record: &ProgressSealedRouteRecord,
        issued_at_ms: u64,
    ) -> Result<OutboundRoutesSealedReceipt, ProgressCardAuthorityError> {
        let expires_at_ms = issued_at_ms
            .checked_add(SOURCE_CLOSE_RECEIPT_LIFETIME_MS)
            .ok_or(ProgressCardAuthorityError::InvalidInput)?;
        let nonce = random_nonce()?;
        let payload = route_receipt_payload(
            self.authority_id,
            record.binding.key_digest,
            record.binding.source_digest,
            record.source_receipt_digest,
            record.binding.route_seal_generation,
            issued_at_ms,
            expires_at_ms,
            nonce,
        );
        let receipt = OutboundRoutesSealedReceipt {
            authority_id: self.authority_id,
            key_digest: record.binding.key_digest,
            source_message_id_digest: record.binding.source_digest,
            source_quiesced_receipt_digest: record.source_receipt_digest,
            route_seal_generation: record.binding.route_seal_generation,
            action_refs: 0,
            retry_refs: 0,
            replay_refs: 0,
            issued_at_ms,
            expires_at_ms,
            nonce,
            mac: token_mac(
                &self.key,
                b"advance.contract215.token.route-seal-receipt.v1",
                &payload,
            ),
        };
        self.journal
            .insert_authority(route_authority_row(&receipt)?)
            .map_err(map_journal_authority_error)?;
        Ok(receipt)
    }

    fn verify_binding(
        &self,
        binding: &OutboundRouteBinding,
    ) -> Result<(), ProgressCardAuthorityError> {
        if binding.authority_id != self.authority_id {
            return Err(ProgressCardAuthorityError::WrongAuthority);
        }
        verify_mac(
            &self.key,
            b"advance.contract215.token.route-binding.v1",
            &route_binding_payload(
                binding.authority_id,
                binding.key_digest,
                binding.source_message_id_digest,
                binding.lifecycle_generation,
                binding.nonce,
            ),
            binding.mac,
        )
    }
}

impl ProgressCardChallengeIssuer {
    pub fn issue_source_close_for_source(
        &mut self,
        source: &SourceTurnQuiescedReceipt,
        live: Option<ProgressLiveCardSnapshot>,
    ) -> Result<SourceCloseChallenge, ProgressCardCoordinatorError> {
        let key_digest = source.progress_key_digest_for_progress();
        let snapshot = self
            .journal
            .read_close_snapshot(
                key_digest,
                live.map(|snapshot| ProgressLiveSnapshot {
                    generation: snapshot.generation,
                    telegram_message_id: snapshot.telegram_message_id,
                }),
            )
            .map_err(map_journal_coordinator_error)?;
        if snapshot.source_digest != source.source_message_id_digest_for_progress() {
            return Err(ProgressCardCoordinatorError::BindingMismatch);
        }
        self.issue_source_close_from_snapshot(snapshot)
    }

    fn issue_source_close_from_snapshot(
        &mut self,
        snapshot: ProgressCloseSnapshot,
    ) -> Result<SourceCloseChallenge, ProgressCardCoordinatorError> {
        let key_digest = snapshot.key_digest;
        let record_kind = public_close_kind(snapshot.target_kind);
        let issued_at_ms = current_unix_ms().map_err(map_authority_error)?;
        let expires_at_ms = issued_at_ms
            .checked_add(SOURCE_CLOSE_CHALLENGE_LIFETIME_MS)
            .ok_or(ProgressCardCoordinatorError::GenerationExhausted)?;
        let nonce = random_nonce().map_err(map_authority_error)?;
        let payload = challenge_payload(
            self.authority_id,
            key_digest,
            snapshot.source_digest,
            snapshot.lifecycle_generation,
            record_kind,
            snapshot.target_fingerprint,
            issued_at_ms,
            expires_at_ms,
            nonce,
        );
        let challenge = SourceCloseChallenge {
            authority_id: self.authority_id,
            key_digest,
            source_message_id_digest: snapshot.source_digest,
            record_generation: snapshot.lifecycle_generation,
            record_kind,
            record_fingerprint: snapshot.target_fingerprint,
            issued_at_ms,
            expires_at_ms,
            nonce,
            mac: token_mac(
                &self.key,
                b"advance.contract215.token.source-close-challenge.v1",
                &payload,
            ),
        };
        self.journal
            .insert_authority(
                source_challenge_authority_row(&challenge).map_err(map_authority_error)?,
            )
            .map_err(map_journal_coordinator_error)?;
        Ok(challenge)
    }

    pub fn issue_attempt_reconciliation(
        &mut self,
        key: &ProgressCardKey,
    ) -> Result<AttemptReconciliationChallenge, ProgressCardCoordinatorError> {
        let key_digest = key
            .digest()
            .map_err(|_| ProgressCardCoordinatorError::InvalidKey)?;
        let row = self
            .journal
            .load_protected_cards()
            .map_err(map_journal_coordinator_error)?
            .remove(&key_digest)
            .ok_or(ProgressCardCoordinatorError::NotIndeterminate)?;
        let ProgressProtectedCardRow::IndeterminateSend {
            generation: record_generation,
            attempt_id,
            delivery_fingerprint,
            phase,
            attempt_kind,
            ..
        } = row
        else {
            return Err(ProgressCardCoordinatorError::NotIndeterminate);
        };
        let attempt_kind = public_attempt_kind(attempt_kind)?;
        let phase = public_phase(phase)?;
        let issued_at_ms = current_unix_ms().map_err(map_authority_error)?;
        let expires_at_ms = issued_at_ms
            .checked_add(ATTEMPT_RECONCILIATION_LIFETIME_MS)
            .ok_or(ProgressCardCoordinatorError::GenerationExhausted)?;
        let nonce = random_nonce().map_err(map_authority_error)?;
        let payload = attempt_challenge_payload(
            self.authority_id,
            key_digest,
            record_generation,
            attempt_id,
            &attempt_kind,
            delivery_fingerprint,
            phase,
            issued_at_ms,
            expires_at_ms,
            nonce,
        );
        let challenge = AttemptReconciliationChallenge {
            authority_id: self.authority_id,
            key_digest,
            record_generation,
            attempt_id,
            attempt_kind,
            delivery_fingerprint,
            phase,
            issued_at_ms,
            expires_at_ms,
            nonce,
            mac: token_mac(
                &self.key,
                b"advance.contract215.token.attempt-reconciliation-challenge.v1",
                &payload,
            ),
        };
        self.journal
            .insert_authority(
                attempt_challenge_authority_row(&challenge).map_err(map_authority_error)?,
            )
            .map_err(map_journal_coordinator_error)?;
        Ok(challenge)
    }
}

impl TrustedTransportOutcomeReceiptIssuer {
    #[allow(clippy::too_many_arguments)]
    pub fn issue_outcome(
        &mut self,
        challenge: &AttemptReconciliationChallenge,
        outcome: ReconciledAttemptOutcome,
        telegram_message_id: Option<i64>,
        evidence_source: ReconciliationEvidenceSource,
        evidence_id: [u8; 16],
        evidence_digest: [u8; 32],
        now_ms: u64,
    ) -> Result<TrustedAttemptOutcomeReceipt, ProgressCardAuthorityError> {
        verify_attempt_challenge(self.authority_id, &self.challenge_key, challenge, now_ms)?;
        validate_reconciliation_outcome(outcome, telegram_message_id, evidence_source)?;
        if evidence_id == [0; 16] || evidence_digest == [0; 32] {
            return Err(ProgressCardAuthorityError::InvalidInput);
        }
        let expires_at_ms = now_ms
            .checked_add(ATTEMPT_RECONCILIATION_LIFETIME_MS)
            .ok_or(ProgressCardAuthorityError::InvalidInput)?
            .min(challenge.expires_at_ms);
        let challenge_digest = attempt_challenge_digest(challenge);
        let nonce = random_nonce()?;
        let payload = attempt_outcome_payload(
            self.authority_id,
            challenge_digest,
            challenge.key_digest,
            challenge.record_generation,
            challenge.attempt_id,
            &challenge.attempt_kind,
            challenge.delivery_fingerprint,
            outcome,
            telegram_message_id,
            evidence_source,
            evidence_id,
            evidence_digest,
            now_ms,
            expires_at_ms,
            nonce,
        );
        let receipt = TrustedAttemptOutcomeReceipt {
            authority_id: self.authority_id,
            challenge_digest,
            key_digest: challenge.key_digest,
            record_generation: challenge.record_generation,
            attempt_id: challenge.attempt_id,
            attempt_kind: challenge.attempt_kind.clone(),
            delivery_fingerprint: challenge.delivery_fingerprint,
            outcome,
            telegram_message_id,
            evidence_source,
            evidence_id,
            evidence_digest,
            issued_at_ms: now_ms,
            expires_at_ms,
            nonce,
            mac: token_mac(
                &self.key,
                b"advance.contract215.token.transport-outcome-receipt.v1",
                &payload,
            ),
        };
        self.journal
            .insert_authority(transport_outcome_authority_row(&receipt)?)
            .map_err(map_journal_authority_error)?;
        Ok(receipt)
    }
}

impl AttemptReconciliationIssuer {
    pub fn attest_attempt(
        &mut self,
        challenge: &AttemptReconciliationChallenge,
        receipt: &TrustedAttemptOutcomeReceipt,
        now_ms: u64,
    ) -> Result<AttemptReconciliationProof, ProgressCardAuthorityError> {
        verify_attempt_challenge(self.authority_id, &self.challenge_key, challenge, now_ms)?;
        verify_attempt_outcome_receipt(self.authority_id, &self.transport_key, receipt, now_ms)?;
        if receipt.challenge_digest != attempt_challenge_digest(challenge)
            || receipt.key_digest != challenge.key_digest
            || receipt.record_generation != challenge.record_generation
            || receipt.attempt_id != challenge.attempt_id
            || receipt.attempt_kind != challenge.attempt_kind
            || receipt.delivery_fingerprint != challenge.delivery_fingerprint
            || receipt.issued_at_ms < challenge.issued_at_ms
        {
            return Err(ProgressCardAuthorityError::BindingMismatch);
        }
        let expires_at_ms = receipt.expires_at_ms.min(challenge.expires_at_ms);
        if now_ms > expires_at_ms {
            return Err(ProgressCardAuthorityError::Expired);
        }
        let nonce = random_nonce()?;
        let payload = attempt_outcome_payload(
            self.authority_id,
            receipt.challenge_digest,
            receipt.key_digest,
            receipt.record_generation,
            receipt.attempt_id,
            &receipt.attempt_kind,
            receipt.delivery_fingerprint,
            receipt.outcome,
            receipt.telegram_message_id,
            receipt.evidence_source,
            receipt.evidence_id,
            receipt.evidence_digest,
            now_ms,
            expires_at_ms,
            nonce,
        );
        let proof = AttemptReconciliationProof {
            authority_id: self.authority_id,
            challenge_digest: receipt.challenge_digest,
            key_digest: receipt.key_digest,
            record_generation: receipt.record_generation,
            attempt_id: receipt.attempt_id,
            attempt_kind: receipt.attempt_kind.clone(),
            delivery_fingerprint: receipt.delivery_fingerprint,
            outcome: receipt.outcome,
            telegram_message_id: receipt.telegram_message_id,
            evidence_source: receipt.evidence_source,
            evidence_id: receipt.evidence_id,
            evidence_digest: receipt.evidence_digest,
            issued_at_ms: now_ms,
            expires_at_ms,
            nonce,
            mac: token_mac(
                &self.key,
                b"advance.contract215.token.attempt-reconciliation-proof.v1",
                &payload,
            ),
        };
        self.journal
            .replace_authority_with(
                ProgressAuthorityExpectation {
                    expected: transport_outcome_authority_row(receipt)?,
                },
                reconciliation_proof_authority_row(&proof)?,
                now_ms,
            )
            .map_err(map_journal_authority_error)?;
        Ok(proof)
    }
}

impl SourceCloseAttestationIssuer {
    pub fn attest_source_close(
        &mut self,
        challenge: &SourceCloseChallenge,
        source: &SourceTurnQuiescedReceipt,
        outbound: &OutboundRoutesSealedReceipt,
        now_ms: u64,
    ) -> Result<SourceLifecycleCloseAttestation, ProgressCardAuthorityError> {
        verify_challenge(self.authority_id, &self.challenge_key, challenge, now_ms)?;
        verify_route_receipt(self.authority_id, &self.route_key, outbound, now_ms)?;
        if outbound.action_refs != 0 || outbound.retry_refs != 0 || outbound.replay_refs != 0 {
            return Err(ProgressCardAuthorityError::RoutesNotQuiescent);
        }
        let verified = self
            .source_verifier
            .verify_for_progress(
                source,
                challenge.source_message_id_digest,
                challenge.key_digest,
                now_ms,
            )
            .map_err(map_turn_error)?;
        if outbound.key_digest != challenge.key_digest
            || outbound.source_message_id_digest != challenge.source_message_id_digest
            || outbound.source_quiesced_receipt_digest != verified.receipt_digest()
            || verified.issued_at_ms() > outbound.issued_at_ms
            || outbound.issued_at_ms > challenge.issued_at_ms
        {
            return Err(ProgressCardAuthorityError::WrongOrder);
        }
        let challenge_digest = challenge_digest(challenge);
        let route_digest = route_receipt_digest(outbound);
        let expires_at_ms = verified
            .expires_at_ms()
            .min(outbound.expires_at_ms)
            .min(challenge.expires_at_ms);
        if now_ms > expires_at_ms {
            return Err(ProgressCardAuthorityError::Expired);
        }
        let nonce = random_nonce()?;
        let payload = attestation_payload(
            self.authority_id,
            challenge_digest,
            challenge.key_digest,
            challenge.source_message_id_digest,
            verified.receipt_digest(),
            route_digest,
            now_ms,
            expires_at_ms,
            nonce,
        );
        let attestation = SourceLifecycleCloseAttestation {
            authority_id: self.authority_id,
            challenge_digest,
            key_digest: challenge.key_digest,
            source_message_id_digest: challenge.source_message_id_digest,
            source_quiesced_receipt_digest: verified.receipt_digest(),
            outbound_routes_sealed_receipt_digest: route_digest,
            issued_at_ms: now_ms,
            expires_at_ms,
            nonce,
            mac: token_mac(
                &self.close_key,
                b"advance.contract215.token.source-close-attestation.v1",
                &payload,
            ),
            route_authority: route_authority_row(outbound)?,
        };
        self.journal
            .insert_authority(source_attestation_authority_row(&attestation)?)
            .map_err(map_journal_authority_error)?;
        Ok(attestation)
    }

    /// Cancel one exact live attestation retained by a failed final close.
    /// The token is authenticated before its durable authority row is moved
    /// terminal, so retry never leaves a second live close authority behind.
    pub fn cancel_attestation(
        &mut self,
        attestation: &SourceLifecycleCloseAttestation,
    ) -> Result<(), ProgressCardAuthorityError> {
        if attestation.authority_id != self.authority_id
            || attestation.expires_at_ms < attestation.issued_at_ms
        {
            return Err(ProgressCardAuthorityError::WrongAuthority);
        }
        verify_mac(
            &self.close_key,
            b"advance.contract215.token.source-close-attestation.v1",
            &attestation_payload(
                attestation.authority_id,
                attestation.challenge_digest,
                attestation.key_digest,
                attestation.source_message_id_digest,
                attestation.source_quiesced_receipt_digest,
                attestation.outbound_routes_sealed_receipt_digest,
                attestation.issued_at_ms,
                attestation.expires_at_ms,
                attestation.nonce,
            ),
            attestation.mac,
        )?;
        let cancelled_at_ms =
            current_unix_ms()?.clamp(attestation.issued_at_ms, attestation.expires_at_ms);
        self.journal
            .consume_or_cancel_authority(
                ProgressAuthorityExpectation {
                    expected: source_attestation_authority_row(attestation)?,
                },
                ProgressAuthorityTerminal::Cancelled {
                    at_ms: cancelled_at_ms,
                },
            )
            .map_err(map_journal_authority_error)
    }
}

impl ProgressCardAuthorityVerifier {
    /// Test-support witness hook for final-close cancellation recovery. The
    /// production surface cannot arm journal failpoints.
    #[cfg(feature = "test-support")]
    pub fn test_fail_next_journal_transaction_after_prepared_fsync(
        &self,
    ) -> Result<(), ProgressCardAuthorityError> {
        self.journal
            .test_fail_next_transaction_after_prepared_fsync()
            .map_err(map_journal_authority_error)
    }

    /// Test-support witness that boot retirement and recovery left no live
    /// challenge, route, attestation, or attempt authority for this source.
    #[cfg(feature = "test-support")]
    pub fn test_live_authority_count_for_source(
        &self,
        source: &SourceTurnQuiescedReceipt,
    ) -> Result<usize, ProgressCardAuthorityError> {
        self.journal
            .test_live_authority_count_for_key(source.progress_key_digest())
            .map_err(map_journal_authority_error)
    }

    pub fn verify_route_ref_for_delivery(
        &self,
        route_ref: &OutboundRouteRef,
        expected_key_digest: [u8; 32],
        expected_source_digest: [u8; 32],
    ) -> Result<u64, ProgressCardAuthorityError> {
        if route_ref.authority_id != self.authority_id
            || route_ref.key_digest != expected_key_digest
            || route_ref.source_message_id_digest != expected_source_digest
        {
            return Err(ProgressCardAuthorityError::BindingMismatch);
        }
        verify_route_ref_token(self.authority_id, &self.route_key, route_ref)?;
        let binding = self
            .journal
            .verify_route_ref_live(ProgressRouteRefExpectation {
                key_digest: route_ref.key_digest,
                source_digest: route_ref.source_message_id_digest,
                ref_id: route_ref.ref_id,
                kind: journal_route_kind(route_ref.kind),
            })
            .map_err(map_journal_authority_error)?;
        Ok(binding.lifecycle_generation)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn verify_attempt_challenge_snapshot(
        &self,
        challenge: &AttemptReconciliationChallenge,
        expected_key_digest: [u8; 32],
        record_generation: u64,
        attempt_id: [u8; 16],
        attempt_kind: &IndeterminateAttemptKind,
        delivery_fingerprint: [u8; 32],
        phase: ProgressPhase,
        now_ms: u64,
    ) -> Result<[u8; 32], ProgressCardAuthorityError> {
        verify_attempt_challenge(self.authority_id, &self.challenge_key, challenge, now_ms)?;
        if challenge.key_digest != expected_key_digest
            || challenge.record_generation != record_generation
            || challenge.attempt_id != attempt_id
            || challenge.attempt_kind != *attempt_kind
            || challenge.delivery_fingerprint != delivery_fingerprint
            || challenge.phase != phase
        {
            return Err(ProgressCardAuthorityError::BindingMismatch);
        }
        Ok(attempt_challenge_digest(challenge))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn verify_attempt_reconciliation(
        &self,
        challenge: &AttemptReconciliationChallenge,
        proof: &AttemptReconciliationProof,
        expected_key_digest: [u8; 32],
        record_generation: u64,
        attempt_id: [u8; 16],
        attempt_kind: &IndeterminateAttemptKind,
        delivery_fingerprint: [u8; 32],
        phase: ProgressPhase,
        now_ms: u64,
    ) -> Result<VerifiedAttemptReconciliation, ProgressCardAuthorityError> {
        let expected_challenge_digest = self.verify_attempt_challenge_snapshot(
            challenge,
            expected_key_digest,
            record_generation,
            attempt_id,
            attempt_kind,
            delivery_fingerprint,
            phase,
            now_ms,
        )?;
        if proof.authority_id != self.authority_id
            || proof.challenge_digest != expected_challenge_digest
            || proof.key_digest != expected_key_digest
            || proof.record_generation != record_generation
            || proof.attempt_id != attempt_id
            || proof.attempt_kind != *attempt_kind
            || proof.delivery_fingerprint != delivery_fingerprint
            || now_ms < proof.issued_at_ms
            || now_ms > proof.expires_at_ms
        {
            return Err(ProgressCardAuthorityError::BindingMismatch);
        }
        validate_reconciliation_outcome(
            proof.outcome,
            proof.telegram_message_id,
            proof.evidence_source,
        )?;
        if proof.evidence_id == [0; 16] || proof.evidence_digest == [0; 32] {
            return Err(ProgressCardAuthorityError::InvalidInput);
        }
        verify_mac(
            &self.reconciliation_key,
            b"advance.contract215.token.attempt-reconciliation-proof.v1",
            &attempt_outcome_payload(
                proof.authority_id,
                proof.challenge_digest,
                proof.key_digest,
                proof.record_generation,
                proof.attempt_id,
                &proof.attempt_kind,
                proof.delivery_fingerprint,
                proof.outcome,
                proof.telegram_message_id,
                proof.evidence_source,
                proof.evidence_id,
                proof.evidence_digest,
                proof.issued_at_ms,
                proof.expires_at_ms,
                proof.nonce,
            ),
            proof.mac,
        )?;
        Ok(VerifiedAttemptReconciliation {
            outcome: proof.outcome,
            telegram_message_id: proof.telegram_message_id,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn verify_source_challenge_snapshot(
        &self,
        challenge: &SourceCloseChallenge,
        expected_key_digest: [u8; 32],
        expected_source_digest: [u8; 32],
        record_generation: u64,
        record_kind: ProtectedRecordKind,
        record_fingerprint: [u8; 32],
        now_ms: u64,
    ) -> Result<[u8; 32], ProgressCardAuthorityError> {
        verify_challenge(self.authority_id, &self.challenge_key, challenge, now_ms)?;
        if challenge.key_digest != expected_key_digest
            || challenge.source_message_id_digest != expected_source_digest
            || challenge.record_generation != record_generation
            || challenge.record_kind != record_kind
            || challenge.record_fingerprint != record_fingerprint
        {
            return Err(ProgressCardAuthorityError::BindingMismatch);
        }
        Ok(challenge_digest(challenge))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn verify_source_close(
        &self,
        challenge: &SourceCloseChallenge,
        attestation: &SourceLifecycleCloseAttestation,
        expected_key_digest: [u8; 32],
        expected_source_digest: [u8; 32],
        record_generation: u64,
        record_kind: ProtectedRecordKind,
        record_fingerprint: [u8; 32],
        now_ms: u64,
    ) -> Result<VerifiedSourceClose, ProgressCardAuthorityError> {
        verify_challenge(self.authority_id, &self.challenge_key, challenge, now_ms)?;
        if challenge.key_digest != expected_key_digest
            || challenge.source_message_id_digest != expected_source_digest
            || challenge.record_generation != record_generation
            || challenge.record_kind != record_kind
            || challenge.record_fingerprint != record_fingerprint
        {
            return Err(ProgressCardAuthorityError::BindingMismatch);
        }
        if attestation.authority_id != self.authority_id
            || attestation.challenge_digest != challenge_digest(challenge)
            || attestation.key_digest != expected_key_digest
            || attestation.source_message_id_digest != expected_source_digest
            || now_ms < attestation.issued_at_ms
            || now_ms > attestation.expires_at_ms
        {
            return Err(ProgressCardAuthorityError::BindingMismatch);
        }
        verify_mac(
            &self.close_key,
            b"advance.contract215.token.source-close-attestation.v1",
            &attestation_payload(
                attestation.authority_id,
                attestation.challenge_digest,
                attestation.key_digest,
                attestation.source_message_id_digest,
                attestation.source_quiesced_receipt_digest,
                attestation.outbound_routes_sealed_receipt_digest,
                attestation.issued_at_ms,
                attestation.expires_at_ms,
                attestation.nonce,
            ),
            attestation.mac,
        )?;
        Ok(VerifiedSourceClose {
            challenge_digest: attestation.challenge_digest,
            source_receipt_digest: attestation.source_quiesced_receipt_digest,
            route_receipt_digest: attestation.outbound_routes_sealed_receipt_digest,
        })
    }

    pub fn cancel_source_close_for_source(
        &self,
        source: &SourceTurnQuiescedReceipt,
        live: Option<ProgressLiveCardSnapshot>,
        challenge: &SourceCloseChallenge,
    ) -> Result<(), ProgressCardCoordinatorError> {
        let snapshot = self.close_snapshot_for_source(source, live)?;
        let now_ms = current_unix_ms().map_err(map_authority_error)?;
        self.verify_source_challenge_snapshot(
            challenge,
            snapshot.key_digest,
            snapshot.source_digest,
            snapshot.lifecycle_generation,
            public_close_kind(snapshot.target_kind),
            snapshot.target_fingerprint,
            now_ms,
        )
        .map_err(map_authority_error)?;
        self.journal
            .consume_or_cancel_authority(
                ProgressAuthorityExpectation {
                    expected: source_challenge_authority_row(challenge)
                        .map_err(map_authority_error)?,
                },
                ProgressAuthorityTerminal::Cancelled { at_ms: now_ms },
            )
            .map_err(map_journal_coordinator_error)
    }

    pub fn commit_source_close_for_source(
        &self,
        source: &SourceTurnQuiescedReceipt,
        live: Option<ProgressLiveCardSnapshot>,
        challenge: &SourceCloseChallenge,
        attestation: &SourceLifecycleCloseAttestation,
    ) -> Result<(), ProgressCardCoordinatorError> {
        let snapshot = self.close_snapshot_for_source(source, live)?;
        let now_ms = current_unix_ms().map_err(map_authority_error)?;
        let verified = self
            .verify_source_close(
                challenge,
                attestation,
                snapshot.key_digest,
                snapshot.source_digest,
                snapshot.lifecycle_generation,
                public_close_kind(snapshot.target_kind),
                snapshot.target_fingerprint,
                now_ms,
            )
            .map_err(map_authority_error)?;
        let retain_until_ms = now_ms
            .checked_add(AUTHORITY_RETAIN_MS)
            .ok_or(ProgressCardCoordinatorError::GenerationExhausted)?;
        self.journal
            .commit_source_close(ProgressSourceCloseCommit {
                expected_snapshot: snapshot,
                source_receipt_digest: verified.source_receipt_digest,
                route_receipt_digest: verified.route_receipt_digest,
                route_authority: ProgressAuthorityExpectation {
                    expected: attestation.route_authority.clone(),
                },
                challenge_authority: ProgressAuthorityExpectation {
                    expected: source_challenge_authority_row(challenge)
                        .map_err(map_authority_error)?,
                },
                attestation_authority: ProgressAuthorityExpectation {
                    expected: source_attestation_authority_row(attestation)
                        .map_err(map_authority_error)?,
                },
                committed_at_ms: now_ms,
                retain_until_ms,
            })
            .map_err(map_journal_coordinator_error)
    }

    pub fn cancel_attempt_reconciliation(
        &self,
        key: &ProgressCardKey,
        challenge: &AttemptReconciliationChallenge,
    ) -> Result<(), ProgressCardCoordinatorError> {
        let current = self.current_indeterminate(key)?;
        let now_ms = current_unix_ms().map_err(map_authority_error)?;
        self.verify_attempt_challenge_snapshot(
            challenge,
            current.0,
            current.1.generation,
            current.2,
            &current.3,
            current.4,
            current.5,
            now_ms,
        )
        .map_err(map_authority_error)?;
        self.journal
            .consume_or_cancel_authority(
                ProgressAuthorityExpectation {
                    expected: attempt_challenge_authority_row(challenge)
                        .map_err(map_authority_error)?,
                },
                ProgressAuthorityTerminal::Cancelled { at_ms: now_ms },
            )
            .map_err(map_journal_coordinator_error)
    }

    pub fn commit_attempt_reconciliation(
        &self,
        key: &ProgressCardKey,
        challenge: &AttemptReconciliationChallenge,
        proof: &AttemptReconciliationProof,
        next: Option<&DurableProgressCardEntry>,
    ) -> Result<VerifiedAttemptReconciliation, ProgressCardCoordinatorError> {
        let (key_digest, current, attempt_id, attempt_kind, fingerprint, phase) =
            self.current_indeterminate(key)?;
        let now_ms = current_unix_ms().map_err(map_authority_error)?;
        let verified = self
            .verify_attempt_reconciliation(
                challenge,
                proof,
                key_digest,
                current.generation,
                attempt_id,
                &attempt_kind,
                fingerprint,
                phase,
                now_ms,
            )
            .map_err(map_authority_error)?;
        if let Some(next) = next {
            let expected_generation = current
                .generation
                .checked_add(1)
                .ok_or(ProgressCardCoordinatorError::GenerationExhausted)?;
            if next.generation != expected_generation {
                return Err(ProgressCardCoordinatorError::BindingMismatch);
            }
        }
        self.journal
            .commit_attempt_reconciliation(ProgressAttemptCommit {
                key_digest,
                expected_indeterminate: journal_card_from_public(&current)?,
                next_card: next.map(journal_card_from_public).transpose()?,
                challenge: ProgressAuthorityExpectation {
                    expected: attempt_challenge_authority_row(challenge)
                        .map_err(map_authority_error)?,
                },
                proof: ProgressAuthorityExpectation {
                    expected: reconciliation_proof_authority_row(proof)
                        .map_err(map_authority_error)?,
                },
                committed_at_ms: now_ms,
            })
            .map_err(map_journal_coordinator_error)?;
        Ok(verified)
    }

    fn close_snapshot_for_source(
        &self,
        source: &SourceTurnQuiescedReceipt,
        live: Option<ProgressLiveCardSnapshot>,
    ) -> Result<ProgressCloseSnapshot, ProgressCardCoordinatorError> {
        let snapshot = self
            .journal
            .read_close_snapshot(
                source.progress_key_digest_for_progress(),
                live.map(|snapshot| ProgressLiveSnapshot {
                    generation: snapshot.generation,
                    telegram_message_id: snapshot.telegram_message_id,
                }),
            )
            .map_err(map_journal_coordinator_error)?;
        if snapshot.source_digest != source.source_message_id_digest_for_progress() {
            return Err(ProgressCardCoordinatorError::BindingMismatch);
        }
        Ok(snapshot)
    }

    #[allow(clippy::type_complexity)]
    fn current_indeterminate(
        &self,
        key: &ProgressCardKey,
    ) -> Result<
        (
            [u8; 32],
            DurableProgressCardEntry,
            [u8; 16],
            IndeterminateAttemptKind,
            [u8; 32],
            ProgressPhase,
        ),
        ProgressCardCoordinatorError,
    > {
        let key_digest = key
            .digest()
            .map_err(|_| ProgressCardCoordinatorError::InvalidKey)?;
        let row = self
            .journal
            .load_protected_cards()
            .map_err(map_journal_coordinator_error)?
            .remove(&key_digest)
            .ok_or(ProgressCardCoordinatorError::NotIndeterminate)?;
        let entry = public_card_from_journal(row)?;
        let DurableProgressCardRecord::IndeterminateSend {
            attempt_id,
            delivery_fingerprint,
            phase,
            attempt_kind,
            ..
        } = &entry.record
        else {
            return Err(ProgressCardCoordinatorError::NotIndeterminate);
        };
        Ok((
            key_digest,
            entry.clone(),
            *attempt_id,
            attempt_kind.clone(),
            *delivery_fingerprint,
            *phase,
        ))
    }
}

pub struct VerifiedAttemptReconciliation {
    outcome: ReconciledAttemptOutcome,
    telegram_message_id: Option<i64>,
}

impl VerifiedAttemptReconciliation {
    pub fn outcome(&self) -> ReconciledAttemptOutcome {
        self.outcome
    }

    pub fn telegram_message_id(&self) -> Option<i64> {
        self.telegram_message_id
    }
}

opaque_debug!(VerifiedAttemptReconciliation);

pub struct VerifiedSourceClose {
    challenge_digest: [u8; 32],
    source_receipt_digest: [u8; 32],
    route_receipt_digest: [u8; 32],
}

impl VerifiedSourceClose {
    pub fn challenge_digest(&self) -> [u8; 32] {
        self.challenge_digest
    }
    pub fn source_receipt_digest(&self) -> [u8; 32] {
        self.source_receipt_digest
    }
    pub fn route_receipt_digest(&self) -> [u8; 32] {
        self.route_receipt_digest
    }
}

opaque_debug!(VerifiedSourceClose);

pub fn progress_source_message_id_digest(source: &str) -> Result<[u8; 32], ProgressCardKeyError> {
    if source.is_empty()
        || source.len() > MAX_PROGRESS_CARD_KEY_COMPONENT_BYTES
        || source.bytes().any(|byte| matches!(byte, 0 | b'\r' | b'\n'))
    {
        return Err(ProgressCardKeyError);
    }
    let mut hasher = Sha256::new();
    hasher.update(b"advance.progress-lifecycle.source-message-id.v1");
    hasher.update([0]);
    hasher.update((source.len() as u32).to_be_bytes());
    hasher.update(source.as_bytes());
    Ok(hasher.finalize().into())
}

pub fn progress_expected_agent_digest(agent: &str) -> Result<[u8; 32], ProgressCardKeyError> {
    if agent.is_empty()
        || agent.len() > MAX_PROGRESS_CARD_KEY_COMPONENT_BYTES
        || agent.bytes().any(|byte| matches!(byte, 0 | b'\r' | b'\n'))
    {
        return Err(ProgressCardKeyError);
    }
    let mut hasher = Sha256::new();
    hasher.update(b"advance.progress-lifecycle.expected-agent.v1");
    hasher.update([0]);
    hasher.update((agent.len() as u32).to_be_bytes());
    hasher.update(agent.as_bytes());
    Ok(hasher.finalize().into())
}

fn current_unix_ms() -> Result<u64, ProgressCardAuthorityError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ProgressCardAuthorityError::JournalUnavailable)?;
    u64::try_from(elapsed.as_millis()).map_err(|_| ProgressCardAuthorityError::GenerationExhausted)
}

fn map_journal_init_error(error: ProgressJournalError) -> ProgressCardAuthorityInitError {
    match error {
        ProgressJournalError::Unavailable => ProgressCardAuthorityInitError::JournalUnavailable,
        ProgressJournalError::Capacity
        | ProgressJournalError::Conflict
        | ProgressJournalError::Rollback
        | ProgressJournalError::Corrupt
        | ProgressJournalError::GenerationExhausted => {
            ProgressCardAuthorityInitError::JournalIntegrityFailure
        }
    }
}

fn map_journal_authority_error(error: ProgressJournalError) -> ProgressCardAuthorityError {
    match error {
        ProgressJournalError::Capacity => ProgressCardAuthorityError::CapacityExhausted,
        ProgressJournalError::GenerationExhausted => {
            ProgressCardAuthorityError::GenerationExhausted
        }
        ProgressJournalError::Unavailable => ProgressCardAuthorityError::JournalUnavailable,
        ProgressJournalError::Conflict => ProgressCardAuthorityError::BindingMismatch,
        ProgressJournalError::Rollback | ProgressJournalError::Corrupt => {
            ProgressCardAuthorityError::IntegrityFailure
        }
    }
}

fn map_journal_coordinator_error(error: ProgressJournalError) -> ProgressCardCoordinatorError {
    match error {
        ProgressJournalError::Capacity => ProgressCardCoordinatorError::CapacityExhausted,
        ProgressJournalError::GenerationExhausted => {
            ProgressCardCoordinatorError::GenerationExhausted
        }
        ProgressJournalError::Unavailable => ProgressCardCoordinatorError::JournalUnavailable,
        ProgressJournalError::Conflict => ProgressCardCoordinatorError::BindingMismatch,
        ProgressJournalError::Rollback | ProgressJournalError::Corrupt => {
            ProgressCardCoordinatorError::IntegrityFailure
        }
    }
}

fn map_authority_error(error: ProgressCardAuthorityError) -> ProgressCardCoordinatorError {
    match error {
        ProgressCardAuthorityError::Expired => ProgressCardCoordinatorError::Expired,
        ProgressCardAuthorityError::Replayed => ProgressCardCoordinatorError::Replayed,
        ProgressCardAuthorityError::CapacityExhausted => {
            ProgressCardCoordinatorError::CapacityExhausted
        }
        ProgressCardAuthorityError::GenerationExhausted => {
            ProgressCardCoordinatorError::GenerationExhausted
        }
        ProgressCardAuthorityError::JournalUnavailable => {
            ProgressCardCoordinatorError::JournalUnavailable
        }
        ProgressCardAuthorityError::IntegrityFailure => {
            ProgressCardCoordinatorError::IntegrityFailure
        }
        _ => ProgressCardCoordinatorError::BindingMismatch,
    }
}

fn journal_attempt_kind(kind: &IndeterminateAttemptKind) -> ProgressAttemptKind {
    match kind {
        IndeterminateAttemptKind::InitialSend => ProgressAttemptKind::InitialSend,
        IndeterminateAttemptKind::Edit { prior_message_id } => {
            ProgressAttemptKind::Edit(*prior_message_id)
        }
        IndeterminateAttemptKind::FallbackSend {
            definitively_lost_message_id,
        } => ProgressAttemptKind::FallbackSend(*definitively_lost_message_id),
    }
}

fn public_attempt_kind(
    kind: ProgressAttemptKind,
) -> Result<IndeterminateAttemptKind, ProgressCardCoordinatorError> {
    let result = match kind {
        ProgressAttemptKind::InitialSend => IndeterminateAttemptKind::InitialSend,
        ProgressAttemptKind::Edit(prior_message_id) if prior_message_id > 0 => {
            IndeterminateAttemptKind::Edit { prior_message_id }
        }
        ProgressAttemptKind::FallbackSend(definitively_lost_message_id)
            if definitively_lost_message_id > 0 =>
        {
            IndeterminateAttemptKind::FallbackSend {
                definitively_lost_message_id,
            }
        }
        _ => return Err(ProgressCardCoordinatorError::IntegrityFailure),
    };
    Ok(result)
}

fn public_phase(value: u8) -> Result<ProgressPhase, ProgressCardCoordinatorError> {
    match value {
        0 => Ok(ProgressPhase::Ack),
        1 => Ok(ProgressPhase::Progress),
        2 => Ok(ProgressPhase::Result),
        3 => Ok(ProgressPhase::Error),
        _ => Err(ProgressCardCoordinatorError::IntegrityFailure),
    }
}

fn journal_card_from_public(
    entry: &DurableProgressCardEntry,
) -> Result<ProgressProtectedCardRow, ProgressCardCoordinatorError> {
    if entry.generation == 0 {
        return Err(ProgressCardCoordinatorError::IntegrityFailure);
    }
    Ok(match &entry.record {
        DurableProgressCardRecord::TerminalTombstone {
            terminal_fingerprint,
            delivered_at_ms,
        } => ProgressProtectedCardRow::TerminalTombstone {
            generation: entry.generation,
            terminal_fingerprint: *terminal_fingerprint,
            delivered_at_ms: *delivered_at_ms,
        },
        DurableProgressCardRecord::IndeterminateSend {
            attempt_id,
            delivery_fingerprint,
            phase,
            attempt_kind,
            first_attempted_at_ms,
        } => ProgressProtectedCardRow::IndeterminateSend {
            generation: entry.generation,
            attempt_id: *attempt_id,
            delivery_fingerprint: *delivery_fingerprint,
            phase: *phase as u8,
            attempt_kind: journal_attempt_kind(attempt_kind),
            first_attempted_at_ms: *first_attempted_at_ms,
        },
        DurableProgressCardRecord::FallbackExhausted {
            delivery_fingerprint,
            definitively_lost_message_id,
            reconciled_at_ms,
        } => ProgressProtectedCardRow::FallbackExhausted {
            generation: entry.generation,
            delivery_fingerprint: *delivery_fingerprint,
            definitively_lost_message_id: *definitively_lost_message_id,
            reconciled_at_ms: *reconciled_at_ms,
        },
    })
}

fn public_card_from_journal(
    row: ProgressProtectedCardRow,
) -> Result<DurableProgressCardEntry, ProgressCardCoordinatorError> {
    let (generation, record) = match row {
        ProgressProtectedCardRow::TerminalTombstone {
            generation,
            terminal_fingerprint,
            delivered_at_ms,
        } => (
            generation,
            DurableProgressCardRecord::TerminalTombstone {
                terminal_fingerprint,
                delivered_at_ms,
            },
        ),
        ProgressProtectedCardRow::IndeterminateSend {
            generation,
            attempt_id,
            delivery_fingerprint,
            phase,
            attempt_kind,
            first_attempted_at_ms,
        } => (
            generation,
            DurableProgressCardRecord::IndeterminateSend {
                attempt_id,
                delivery_fingerprint,
                phase: public_phase(phase)?,
                attempt_kind: public_attempt_kind(attempt_kind)?,
                first_attempted_at_ms,
            },
        ),
        ProgressProtectedCardRow::FallbackExhausted {
            generation,
            delivery_fingerprint,
            definitively_lost_message_id,
            reconciled_at_ms,
        } => (
            generation,
            DurableProgressCardRecord::FallbackExhausted {
                delivery_fingerprint,
                definitively_lost_message_id,
                reconciled_at_ms,
            },
        ),
    };
    if generation == 0 {
        return Err(ProgressCardCoordinatorError::IntegrityFailure);
    }
    Ok(DurableProgressCardEntry { generation, record })
}

fn journal_route_kind(kind: OutboundRouteRefKind) -> ProgressRouteRefKind {
    match kind {
        OutboundRouteRefKind::Action => ProgressRouteRefKind::Action,
        OutboundRouteRefKind::Retry => ProgressRouteRefKind::Retry,
        OutboundRouteRefKind::Replay => ProgressRouteRefKind::Replay,
    }
}

fn public_close_kind(kind: ProgressCloseTargetKind) -> ProtectedRecordKind {
    match kind {
        ProgressCloseTargetKind::NoCard => ProtectedRecordKind::NoCard,
        ProgressCloseTargetKind::Live => ProtectedRecordKind::Live,
        ProgressCloseTargetKind::TerminalTombstone => ProtectedRecordKind::TerminalTombstone,
        ProgressCloseTargetKind::IndeterminateSend => ProtectedRecordKind::IndeterminateSend,
        ProgressCloseTargetKind::FallbackExhausted => ProtectedRecordKind::FallbackExhausted,
    }
}

fn authority_envelope(
    authority_id: [u8; 16],
    issued_ms: u64,
    expires_ms: u64,
    mac: [u8; 32],
) -> Result<ProgressAuthorityEnvelope, ProgressCardAuthorityError> {
    let retain_until_ms = expires_ms
        .checked_add(AUTHORITY_RETAIN_MS)
        .ok_or(ProgressCardAuthorityError::GenerationExhausted)?;
    Ok(ProgressAuthorityEnvelope {
        state: ProgressAuthorityState::Live,
        authority_id,
        issued_ms,
        expires_ms,
        retain_until_ms,
        mac,
    })
}

fn route_authority_row(
    receipt: &OutboundRoutesSealedReceipt,
) -> Result<ProgressAuthorityRow, ProgressCardAuthorityError> {
    Ok(ProgressAuthorityRow::RouteSealReceipt {
        key_digest: receipt.key_digest,
        nonce: receipt.nonce,
        source_digest: receipt.source_message_id_digest,
        source_quiesced_receipt_digest: receipt.source_quiesced_receipt_digest,
        route_seal_generation: receipt.route_seal_generation,
        action_refs: receipt.action_refs,
        retry_refs: receipt.retry_refs,
        replay_refs: receipt.replay_refs,
        envelope: authority_envelope(
            receipt.authority_id,
            receipt.issued_at_ms,
            receipt.expires_at_ms,
            receipt.mac,
        )?,
    })
}

fn source_challenge_authority_row(
    challenge: &SourceCloseChallenge,
) -> Result<ProgressAuthorityRow, ProgressCardAuthorityError> {
    Ok(ProgressAuthorityRow::SourceCloseChallenge {
        key_digest: challenge.key_digest,
        nonce: challenge.nonce,
        source_digest: challenge.source_message_id_digest,
        record_generation: challenge.record_generation,
        record_kind: match challenge.record_kind {
            ProtectedRecordKind::NoCard => ProgressCloseTargetKind::NoCard,
            ProtectedRecordKind::Live => ProgressCloseTargetKind::Live,
            ProtectedRecordKind::TerminalTombstone => ProgressCloseTargetKind::TerminalTombstone,
            ProtectedRecordKind::IndeterminateSend => ProgressCloseTargetKind::IndeterminateSend,
            ProtectedRecordKind::FallbackExhausted => ProgressCloseTargetKind::FallbackExhausted,
        },
        record_fingerprint: challenge.record_fingerprint,
        envelope: authority_envelope(
            challenge.authority_id,
            challenge.issued_at_ms,
            challenge.expires_at_ms,
            challenge.mac,
        )?,
    })
}

fn source_attestation_authority_row(
    attestation: &SourceLifecycleCloseAttestation,
) -> Result<ProgressAuthorityRow, ProgressCardAuthorityError> {
    Ok(ProgressAuthorityRow::SourceCloseAttestation {
        challenge_digest: attestation.challenge_digest,
        nonce: attestation.nonce,
        key_digest: attestation.key_digest,
        source_digest: attestation.source_message_id_digest,
        source_receipt_digest: attestation.source_quiesced_receipt_digest,
        route_receipt_digest: attestation.outbound_routes_sealed_receipt_digest,
        envelope: authority_envelope(
            attestation.authority_id,
            attestation.issued_at_ms,
            attestation.expires_at_ms,
            attestation.mac,
        )?,
    })
}

fn attempt_challenge_authority_row(
    challenge: &AttemptReconciliationChallenge,
) -> Result<ProgressAuthorityRow, ProgressCardAuthorityError> {
    Ok(ProgressAuthorityRow::AttemptReconciliationChallenge {
        key_digest: challenge.key_digest,
        nonce: challenge.nonce,
        record_generation: challenge.record_generation,
        attempt_id: challenge.attempt_id,
        attempt_kind: journal_attempt_kind(&challenge.attempt_kind),
        delivery_fingerprint: challenge.delivery_fingerprint,
        phase: challenge.phase as u8,
        envelope: authority_envelope(
            challenge.authority_id,
            challenge.issued_at_ms,
            challenge.expires_at_ms,
            challenge.mac,
        )?,
    })
}

fn transport_outcome_authority_row(
    receipt: &TrustedAttemptOutcomeReceipt,
) -> Result<ProgressAuthorityRow, ProgressCardAuthorityError> {
    Ok(ProgressAuthorityRow::TrustedAttemptOutcomeReceipt {
        challenge_digest: receipt.challenge_digest,
        nonce: receipt.nonce,
        key_digest: receipt.key_digest,
        record_generation: receipt.record_generation,
        attempt_id: receipt.attempt_id,
        attempt_kind: journal_attempt_kind(&receipt.attempt_kind),
        delivery_fingerprint: receipt.delivery_fingerprint,
        delivered_message_id: receipt.telegram_message_id,
        evidence_source: receipt.evidence_source as u8,
        evidence_id: receipt.evidence_id,
        evidence_digest: receipt.evidence_digest,
        envelope: authority_envelope(
            receipt.authority_id,
            receipt.issued_at_ms,
            receipt.expires_at_ms,
            receipt.mac,
        )?,
    })
}

fn reconciliation_proof_authority_row(
    proof: &AttemptReconciliationProof,
) -> Result<ProgressAuthorityRow, ProgressCardAuthorityError> {
    Ok(ProgressAuthorityRow::AttemptReconciliationProof {
        challenge_digest: proof.challenge_digest,
        nonce: proof.nonce,
        key_digest: proof.key_digest,
        record_generation: proof.record_generation,
        attempt_id: proof.attempt_id,
        attempt_kind: journal_attempt_kind(&proof.attempt_kind),
        delivery_fingerprint: proof.delivery_fingerprint,
        delivered_message_id: proof.telegram_message_id,
        evidence_source: proof.evidence_source as u8,
        evidence_id: proof.evidence_id,
        evidence_digest: proof.evidence_digest,
        envelope: authority_envelope(
            proof.authority_id,
            proof.issued_at_ms,
            proof.expires_at_ms,
            proof.mac,
        )?,
    })
}

fn verify_route_ref_token(
    authority_id: [u8; 16],
    key: &[u8; 32],
    route_ref: &OutboundRouteRef,
) -> Result<(), ProgressCardAuthorityError> {
    if route_ref.authority_id != authority_id {
        return Err(ProgressCardAuthorityError::WrongAuthority);
    }
    verify_mac(
        key,
        b"advance.contract215.token.route-ref.v1",
        &route_ref_payload(
            route_ref.authority_id,
            route_ref.key_digest,
            route_ref.source_message_id_digest,
            route_ref.lifecycle_generation,
            route_ref.ref_id,
            route_ref.kind,
        ),
        route_ref.mac,
    )
}

fn derive_role_key(
    root: &[u8; 32],
    authority_id: [u8; 16],
    label: &[u8],
) -> Result<[u8; 32], ProgressCardAuthorityError> {
    let hkdf = Hkdf::<Sha256>::new(Some(&authority_id), root);
    let mut info = Vec::with_capacity(label.len() + 17);
    info.extend_from_slice(label);
    info.push(0);
    info.extend_from_slice(&authority_id);
    let mut output = [0; 32];
    hkdf.expand(&info, &mut output)
        .map_err(|_| ProgressCardAuthorityError::InvalidInput)?;
    Ok(output)
}

fn random_nonce() -> Result<[u8; 16], ProgressCardAuthorityError> {
    let mut nonce = [0; 16];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    (nonce != [0; 16])
        .then_some(nonce)
        .ok_or(ProgressCardAuthorityError::InvalidInput)
}

fn route_provider_binding_digest(authority_id: [u8; 16], key: &[u8; 32]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts 32-byte key");
    mac.update(b"advance.contract215.route-provider-binding.v1\0");
    mac.update(&authority_id);
    mac.finalize().into_bytes().into()
}

fn token_mac(key: &[u8; 32], domain: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts 32-byte key");
    mac.update(domain);
    mac.update(&[0]);
    mac.update(payload);
    mac.finalize().into_bytes().into()
}

fn verify_mac(
    key: &[u8; 32],
    domain: &[u8],
    payload: &[u8],
    actual: [u8; 32],
) -> Result<(), ProgressCardAuthorityError> {
    let expected = token_mac(key, domain, payload);
    if bool::from(expected.ct_eq(&actual)) {
        Ok(())
    } else {
        Err(ProgressCardAuthorityError::InvalidMac)
    }
}

fn route_binding_payload(
    authority: [u8; 16],
    key: [u8; 32],
    source: [u8; 32],
    generation: u64,
    nonce: [u8; 16],
) -> Vec<u8> {
    [
        authority.as_slice(),
        key.as_slice(),
        source.as_slice(),
        &generation.to_be_bytes(),
        nonce.as_slice(),
    ]
    .concat()
}

fn route_ref_payload(
    authority: [u8; 16],
    key: [u8; 32],
    source: [u8; 32],
    generation: u64,
    ref_id: [u8; 16],
    kind: OutboundRouteRefKind,
) -> Vec<u8> {
    [
        authority.as_slice(),
        key.as_slice(),
        source.as_slice(),
        &generation.to_be_bytes(),
        ref_id.as_slice(),
        &[kind as u8],
    ]
    .concat()
}

fn route_receipt_payload(
    authority: [u8; 16],
    key: [u8; 32],
    source: [u8; 32],
    source_receipt: [u8; 32],
    generation: u64,
    issued: u64,
    expires: u64,
    nonce: [u8; 16],
) -> Vec<u8> {
    [
        authority.as_slice(),
        key.as_slice(),
        source.as_slice(),
        source_receipt.as_slice(),
        &generation.to_be_bytes(),
        &0u32.to_be_bytes(),
        &0u32.to_be_bytes(),
        &0u32.to_be_bytes(),
        &issued.to_be_bytes(),
        &expires.to_be_bytes(),
        nonce.as_slice(),
    ]
    .concat()
}

#[allow(clippy::too_many_arguments)]
fn challenge_payload(
    authority: [u8; 16],
    key: [u8; 32],
    source: [u8; 32],
    generation: u64,
    kind: ProtectedRecordKind,
    fingerprint: [u8; 32],
    issued: u64,
    expires: u64,
    nonce: [u8; 16],
) -> Vec<u8> {
    [
        authority.as_slice(),
        key.as_slice(),
        source.as_slice(),
        &generation.to_be_bytes(),
        &[kind as u8],
        fingerprint.as_slice(),
        &issued.to_be_bytes(),
        &expires.to_be_bytes(),
        nonce.as_slice(),
    ]
    .concat()
}

fn validate_attempt_kind(
    attempt_kind: &IndeterminateAttemptKind,
) -> Result<(), ProgressCardAuthorityError> {
    match attempt_kind {
        IndeterminateAttemptKind::InitialSend => Ok(()),
        IndeterminateAttemptKind::Edit { prior_message_id }
        | IndeterminateAttemptKind::FallbackSend {
            definitively_lost_message_id: prior_message_id,
        } if *prior_message_id > 0 => Ok(()),
        _ => Err(ProgressCardAuthorityError::InvalidInput),
    }
}

fn attempt_kind_bytes(attempt_kind: &IndeterminateAttemptKind) -> Vec<u8> {
    match attempt_kind {
        IndeterminateAttemptKind::InitialSend => vec![0],
        IndeterminateAttemptKind::Edit { prior_message_id } => {
            let mut bytes = Vec::with_capacity(9);
            bytes.push(1);
            bytes.extend_from_slice(&prior_message_id.to_be_bytes());
            bytes
        }
        IndeterminateAttemptKind::FallbackSend {
            definitively_lost_message_id,
        } => {
            let mut bytes = Vec::with_capacity(9);
            bytes.push(2);
            bytes.extend_from_slice(&definitively_lost_message_id.to_be_bytes());
            bytes
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn attempt_challenge_payload(
    authority: [u8; 16],
    key: [u8; 32],
    generation: u64,
    attempt_id: [u8; 16],
    attempt_kind: &IndeterminateAttemptKind,
    delivery_fingerprint: [u8; 32],
    phase: ProgressPhase,
    issued: u64,
    expires: u64,
    nonce: [u8; 16],
) -> Vec<u8> {
    let attempt_kind = attempt_kind_bytes(attempt_kind);
    [
        authority.as_slice(),
        key.as_slice(),
        &generation.to_be_bytes(),
        attempt_id.as_slice(),
        attempt_kind.as_slice(),
        delivery_fingerprint.as_slice(),
        &[phase as u8],
        &issued.to_be_bytes(),
        &expires.to_be_bytes(),
        nonce.as_slice(),
    ]
    .concat()
}

fn option_i64_bytes(value: Option<i64>) -> Vec<u8> {
    match value {
        None => vec![0],
        Some(value) => {
            let mut bytes = Vec::with_capacity(9);
            bytes.push(1);
            bytes.extend_from_slice(&value.to_be_bytes());
            bytes
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn attempt_outcome_payload(
    authority: [u8; 16],
    challenge: [u8; 32],
    key: [u8; 32],
    generation: u64,
    attempt_id: [u8; 16],
    attempt_kind: &IndeterminateAttemptKind,
    delivery_fingerprint: [u8; 32],
    outcome: ReconciledAttemptOutcome,
    telegram_message_id: Option<i64>,
    evidence_source: ReconciliationEvidenceSource,
    evidence_id: [u8; 16],
    evidence_digest: [u8; 32],
    issued: u64,
    expires: u64,
    nonce: [u8; 16],
) -> Vec<u8> {
    let attempt_kind = attempt_kind_bytes(attempt_kind);
    let telegram_message_id = option_i64_bytes(telegram_message_id);
    [
        authority.as_slice(),
        challenge.as_slice(),
        key.as_slice(),
        &generation.to_be_bytes(),
        attempt_id.as_slice(),
        attempt_kind.as_slice(),
        delivery_fingerprint.as_slice(),
        &[outcome as u8],
        telegram_message_id.as_slice(),
        &[evidence_source as u8],
        evidence_id.as_slice(),
        evidence_digest.as_slice(),
        &issued.to_be_bytes(),
        &expires.to_be_bytes(),
        nonce.as_slice(),
    ]
    .concat()
}

fn validate_reconciliation_outcome(
    outcome: ReconciledAttemptOutcome,
    telegram_message_id: Option<i64>,
    evidence_source: ReconciliationEvidenceSource,
) -> Result<(), ProgressCardAuthorityError> {
    match (outcome, telegram_message_id, evidence_source) {
        (ReconciledAttemptOutcome::Delivered, Some(message_id), _) if message_id > 0 => Ok(()),
        (
            ReconciledAttemptOutcome::DefinitelyNotDelivered,
            None,
            ReconciliationEvidenceSource::DurableTransportReceipt,
        ) => Ok(()),
        _ => Err(ProgressCardAuthorityError::InvalidInput),
    }
}

#[allow(clippy::too_many_arguments)]
fn attestation_payload(
    authority: [u8; 16],
    challenge: [u8; 32],
    key: [u8; 32],
    source: [u8; 32],
    source_receipt: [u8; 32],
    route_receipt: [u8; 32],
    issued: u64,
    expires: u64,
    nonce: [u8; 16],
) -> Vec<u8> {
    [
        authority.as_slice(),
        challenge.as_slice(),
        key.as_slice(),
        source.as_slice(),
        source_receipt.as_slice(),
        route_receipt.as_slice(),
        &issued.to_be_bytes(),
        &expires.to_be_bytes(),
        nonce.as_slice(),
    ]
    .concat()
}

fn verify_challenge(
    authority: [u8; 16],
    key: &[u8; 32],
    challenge: &SourceCloseChallenge,
    now_ms: u64,
) -> Result<(), ProgressCardAuthorityError> {
    if challenge.authority_id != authority {
        return Err(ProgressCardAuthorityError::WrongAuthority);
    }
    if now_ms < challenge.issued_at_ms || now_ms > challenge.expires_at_ms {
        return Err(ProgressCardAuthorityError::Expired);
    }
    verify_mac(
        key,
        b"advance.contract215.token.source-close-challenge.v1",
        &challenge_payload(
            challenge.authority_id,
            challenge.key_digest,
            challenge.source_message_id_digest,
            challenge.record_generation,
            challenge.record_kind,
            challenge.record_fingerprint,
            challenge.issued_at_ms,
            challenge.expires_at_ms,
            challenge.nonce,
        ),
        challenge.mac,
    )
}

fn verify_attempt_challenge(
    authority: [u8; 16],
    key: &[u8; 32],
    challenge: &AttemptReconciliationChallenge,
    now_ms: u64,
) -> Result<(), ProgressCardAuthorityError> {
    if challenge.authority_id != authority {
        return Err(ProgressCardAuthorityError::WrongAuthority);
    }
    if now_ms < challenge.issued_at_ms || now_ms > challenge.expires_at_ms {
        return Err(ProgressCardAuthorityError::Expired);
    }
    validate_attempt_kind(&challenge.attempt_kind)?;
    verify_mac(
        key,
        b"advance.contract215.token.attempt-reconciliation-challenge.v1",
        &attempt_challenge_payload(
            challenge.authority_id,
            challenge.key_digest,
            challenge.record_generation,
            challenge.attempt_id,
            &challenge.attempt_kind,
            challenge.delivery_fingerprint,
            challenge.phase,
            challenge.issued_at_ms,
            challenge.expires_at_ms,
            challenge.nonce,
        ),
        challenge.mac,
    )
}

fn verify_attempt_outcome_receipt(
    authority: [u8; 16],
    key: &[u8; 32],
    receipt: &TrustedAttemptOutcomeReceipt,
    now_ms: u64,
) -> Result<(), ProgressCardAuthorityError> {
    if receipt.authority_id != authority {
        return Err(ProgressCardAuthorityError::WrongAuthority);
    }
    if now_ms < receipt.issued_at_ms || now_ms > receipt.expires_at_ms {
        return Err(ProgressCardAuthorityError::Expired);
    }
    validate_attempt_kind(&receipt.attempt_kind)?;
    validate_reconciliation_outcome(
        receipt.outcome,
        receipt.telegram_message_id,
        receipt.evidence_source,
    )?;
    if receipt.evidence_id == [0; 16] || receipt.evidence_digest == [0; 32] {
        return Err(ProgressCardAuthorityError::InvalidInput);
    }
    verify_mac(
        key,
        b"advance.contract215.token.transport-outcome-receipt.v1",
        &attempt_outcome_payload(
            receipt.authority_id,
            receipt.challenge_digest,
            receipt.key_digest,
            receipt.record_generation,
            receipt.attempt_id,
            &receipt.attempt_kind,
            receipt.delivery_fingerprint,
            receipt.outcome,
            receipt.telegram_message_id,
            receipt.evidence_source,
            receipt.evidence_id,
            receipt.evidence_digest,
            receipt.issued_at_ms,
            receipt.expires_at_ms,
            receipt.nonce,
        ),
        receipt.mac,
    )
}

fn verify_route_receipt(
    authority: [u8; 16],
    key: &[u8; 32],
    receipt: &OutboundRoutesSealedReceipt,
    now_ms: u64,
) -> Result<(), ProgressCardAuthorityError> {
    if receipt.authority_id != authority {
        return Err(ProgressCardAuthorityError::WrongAuthority);
    }
    if now_ms < receipt.issued_at_ms || now_ms > receipt.expires_at_ms {
        return Err(ProgressCardAuthorityError::Expired);
    }
    verify_mac(
        key,
        b"advance.contract215.token.route-seal-receipt.v1",
        &route_receipt_payload(
            receipt.authority_id,
            receipt.key_digest,
            receipt.source_message_id_digest,
            receipt.source_quiesced_receipt_digest,
            receipt.route_seal_generation,
            receipt.issued_at_ms,
            receipt.expires_at_ms,
            receipt.nonce,
        ),
        receipt.mac,
    )
}

fn challenge_digest(challenge: &SourceCloseChallenge) -> [u8; 32] {
    let mut bytes = challenge_payload(
        challenge.authority_id,
        challenge.key_digest,
        challenge.source_message_id_digest,
        challenge.record_generation,
        challenge.record_kind,
        challenge.record_fingerprint,
        challenge.issued_at_ms,
        challenge.expires_at_ms,
        challenge.nonce,
    );
    bytes.extend_from_slice(&challenge.mac);
    token_digest(
        b"advance.contract215.token.source-close-challenge.v1",
        &bytes,
    )
}

fn attempt_challenge_digest(challenge: &AttemptReconciliationChallenge) -> [u8; 32] {
    let mut bytes = attempt_challenge_payload(
        challenge.authority_id,
        challenge.key_digest,
        challenge.record_generation,
        challenge.attempt_id,
        &challenge.attempt_kind,
        challenge.delivery_fingerprint,
        challenge.phase,
        challenge.issued_at_ms,
        challenge.expires_at_ms,
        challenge.nonce,
    );
    bytes.extend_from_slice(&challenge.mac);
    token_digest(
        b"advance.contract215.token.attempt-reconciliation-challenge.v1",
        &bytes,
    )
}

fn route_receipt_digest(receipt: &OutboundRoutesSealedReceipt) -> [u8; 32] {
    let mut bytes = route_receipt_payload(
        receipt.authority_id,
        receipt.key_digest,
        receipt.source_message_id_digest,
        receipt.source_quiesced_receipt_digest,
        receipt.route_seal_generation,
        receipt.issued_at_ms,
        receipt.expires_at_ms,
        receipt.nonce,
    );
    bytes.extend_from_slice(&receipt.mac);
    token_digest(b"advance.contract215.token.route-seal-receipt.v1", &bytes)
}

fn token_digest(domain: &[u8], token: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"advance.contract215.token-digest.v1");
    hasher.update([0]);
    hasher.update((domain.len() as u32).to_be_bytes());
    hasher.update(domain);
    hasher.update((token.len() as u32).to_be_bytes());
    hasher.update(token);
    hasher.finalize().into()
}

fn map_turn_error(_: TurnExecutionError) -> ProgressCardAuthorityError {
    ProgressCardAuthorityError::BindingMismatch
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use crate::progress_lifecycle_recovery::{
        ProgressLifecycleRecoveryJournal, RecoveryJournalConfig,
    };
    use crate::turn_attribution::{StoreQuiescenceFacts, TurnAttributionAuthorityFactory};
    use rand::Error as RandError;
    use tempfile::TempDir;
    use zeroize::Zeroizing;

    use super::*;

    fn recovery_roles() -> (
        TempDir,
        crate::progress_lifecycle_recovery::TurnRecoveryJournalRole,
        crate::progress_lifecycle_recovery::ProgressRecoveryJournalRole,
    ) {
        let root = tempfile::tempdir().expect("journal root");
        let config = RecoveryJournalConfig::new_at_composition(
            root.path().join("journal"),
            root.path().join("anchor").join("root.anchor"),
            NonZeroU32::new(1).expect("non-zero epoch"),
            Zeroizing::new([0x42; 32]),
        )
        .expect("valid journal config");
        let journal =
            ProgressLifecycleRecoveryJournal::open_at_composition(config).expect("journal opens");
        let (turn, progress) = journal.split_at_composition();
        (root, turn, progress)
    }

    struct CountingRng {
        fills: usize,
    }

    impl RngCore for CountingRng {
        fn next_u32(&mut self) -> u32 {
            0
        }

        fn next_u64(&mut self) -> u64 {
            0
        }

        fn fill_bytes(&mut self, destination: &mut [u8]) {
            self.fills += 1;
            destination.fill(0xa5);
        }

        fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), RandError> {
            self.fill_bytes(destination);
            Ok(())
        }
    }

    impl CryptoRng for CountingRng {}

    #[test]
    fn crossed_c216_staging_and_source_verifier_reject_before_factory_work() {
        let (_root_a, turn_recovery_a, progress_recovery_a) = recovery_roles();
        let (_root_b, turn_recovery_b, _progress_recovery_b) = recovery_roles();
        let c216_a = TurnAttributionAuthorityFactory::new_at_composition(
            &mut rand::rngs::OsRng,
            turn_recovery_a,
        )
        .unwrap();
        let c216_b = TurnAttributionAuthorityFactory::new_at_composition(
            &mut rand::rngs::OsRng,
            turn_recovery_b,
        )
        .unwrap();
        let mut rng = CountingRng { fills: 0 };

        let error = ProgressCardAuthorityFactory::new_at_composition(
            &mut rng,
            c216_a.activation_staging,
            c216_b.source_quiescence_verifier,
            progress_recovery_a,
        )
        .err()
        .expect("crossed C216 factory roles must reject");

        assert_eq!(error, ProgressCardAuthorityInitError::C216ProviderMismatch);
        assert_eq!(error.to_string(), "joint-activation-c216-provider-mismatch");
        assert_eq!(rng.fills, 0, "wrong-factory rejection must precede entropy");
    }

    #[test]
    fn canonical_key_digest_matches_contract_vector() {
        let key = ProgressCardKey {
            adapter_id: "telegram".into(),
            subscription_id: "sub-1".into(),
            conversation_id: "chat-42".into(),
            source_message_id: "msg-99".into(),
        };
        assert_eq!(
            hex(&key.digest().unwrap()),
            "2d4dbebe01754a0bc82c1515caf6b330e8e266932cacfb491c71be03069af777"
        );
    }

    #[test]
    fn key_rejects_empty_controls_and_component_overflow() {
        let base = ProgressCardKey {
            adapter_id: "telegram".into(),
            subscription_id: "sub".into(),
            conversation_id: "chat".into(),
            source_message_id: "msg".into(),
        };
        for bad in ["", "x\0y", "x\ry", "x\ny"] {
            let mut key = base.clone();
            key.conversation_id = bad.into();
            assert!(key.digest().is_err());
        }
        let mut key = base;
        key.source_message_id = "x".repeat(MAX_PROGRESS_CARD_KEY_COMPONENT_BYTES + 1);
        assert!(key.digest().is_err());
    }

    #[test]
    fn ordered_close_cancel_replay_and_exact_retry_are_terminal() {
        let (_journal_root, turn_recovery, progress_recovery) = recovery_roles();
        let mut turn = TurnAttributionAuthorityFactory::new_at_composition(
            &mut rand::rngs::OsRng,
            turn_recovery,
        )
        .unwrap();
        let source_digest = progress_source_message_id_digest("msg-99").unwrap();
        let key = ProgressCardKey {
            adapter_id: "telegram".into(),
            subscription_id: "sub-1".into(),
            conversation_id: "chat-42".into(),
            source_message_id: "msg-99".into(),
        };
        let key_digest = key.digest().unwrap();
        let (_, turn_binding) = turn
            .registry_issuer
            .reserve_turn("msg-99", "agent:default")
            .unwrap()
            .into_parts();
        let mut rng = rand::rngs::OsRng;
        let mut authority = ProgressCardAuthorityFactory::new_at_composition(
            &mut rng,
            turn.activation_staging,
            turn.source_quiescence_verifier,
            progress_recovery,
        )
        .unwrap();
        authority
            .outbound_route_seal_issuer
            .arm_before_progress(&key, "agent:default")
            .unwrap();
        let store_facts = StoreQuiescenceFacts {
            turn_id: "msg-99".into(),
            expected_agent: "agent:default".into(),
            store_incarnation: [1; 16],
        };
        let store_proof = turn
            .store_quiescence_issuer
            .issue_drained(&store_facts, 1)
            .unwrap();
        let source = turn
            .registry_issuer
            .commit_store_quiescence(&turn_binding, &store_proof)
            .unwrap()
            .expect("bound progress source produces quiescence receipt");
        let route = authority
            .outbound_route_seal_issuer
            .seal_and_issue_for_source(&source)
            .unwrap();
        let challenge = authority
            .coordinator_challenge_issuer
            .issue_source_close_for_source(&source, None)
            .unwrap();
        let now_ms = current_unix_ms().unwrap();
        let attestation = authority
            .source_close_attestation_issuer
            .attest_source_close(&challenge, &source, &route, now_ms)
            .unwrap();
        let verified = authority
            .verifier
            .verify_source_close(
                &challenge,
                &attestation,
                key_digest,
                source_digest,
                challenge.record_generation,
                challenge.record_kind,
                challenge.record_fingerprint,
                now_ms,
            )
            .unwrap();
        assert_ne!(verified.challenge_digest(), [0; 32]);
        assert_eq!(
            verified.source_receipt_digest(),
            source.digest_for_progress()
        );

        authority
            .source_close_attestation_issuer
            .cancel_attestation(&attestation)
            .unwrap();
        authority
            .verifier
            .cancel_source_close_for_source(&source, None, &challenge)
            .unwrap();
        authority
            .outbound_route_seal_issuer
            .cancel_sealed_receipt(&route)
            .unwrap();
        assert!(authority
            .source_close_attestation_issuer
            .cancel_attestation(&attestation)
            .is_err());
        assert!(authority
            .verifier
            .cancel_source_close_for_source(&source, None, &challenge)
            .is_err());
        assert!(authority
            .outbound_route_seal_issuer
            .cancel_sealed_receipt(&route)
            .is_err());

        let retry_route = authority
            .outbound_route_seal_issuer
            .reissue_sealed_for_source(&source)
            .unwrap();
        let retry_challenge = authority
            .coordinator_challenge_issuer
            .issue_source_close_for_source(&source, None)
            .unwrap();
        let retry_attestation = authority
            .source_close_attestation_issuer
            .attest_source_close(
                &retry_challenge,
                &source,
                &retry_route,
                current_unix_ms().unwrap(),
            )
            .unwrap();
        authority
            .verifier
            .commit_source_close_for_source(&source, None, &retry_challenge, &retry_attestation)
            .unwrap();
        assert!(authority
            .verifier
            .commit_source_close_for_source(&source, None, &retry_challenge, &retry_attestation,)
            .is_err());
    }

    #[test]
    fn attempt_reconciliation_requires_transport_evidence_and_exact_snapshot() {
        let (_journal_root, turn_recovery, progress_recovery) = recovery_roles();
        let mut turn = TurnAttributionAuthorityFactory::new_at_composition(
            &mut rand::rngs::OsRng,
            turn_recovery,
        )
        .unwrap();
        let _source = turn
            .registry_issuer
            .reserve_turn("msg-99", "agent:default")
            .unwrap();
        let mut authority = ProgressCardAuthorityFactory::new_with_os_rng_at_composition(
            turn.activation_staging,
            turn.source_quiescence_verifier,
            progress_recovery,
        )
        .unwrap();
        let key = ProgressCardKey {
            adapter_id: "telegram".into(),
            subscription_id: "sub-1".into(),
            conversation_id: "chat-42".into(),
            source_message_id: "msg-99".into(),
        };
        let key_digest = key.digest().unwrap();
        authority
            .outbound_route_seal_issuer
            .arm_before_progress(&key, "agent:default")
            .unwrap();
        let attempt_id = [4; 16];
        let attempt_kind = IndeterminateAttemptKind::FallbackSend {
            definitively_lost_message_id: 41,
        };
        let delivery_fingerprint = [5; 32];
        let durable = DurableProgressCardEntry {
            generation: 7,
            record: DurableProgressCardRecord::IndeterminateSend {
                attempt_id,
                delivery_fingerprint,
                phase: ProgressPhase::Result,
                attempt_kind: attempt_kind.clone(),
                first_attempted_at_ms: 100,
            },
        };
        authority
            .protected_state_issuer
            .replace(key_digest, None, Some(&durable))
            .unwrap();
        let challenge = authority
            .coordinator_challenge_issuer
            .issue_attempt_reconciliation(&key)
            .unwrap();
        let now_ms = current_unix_ms().unwrap();
        assert!(authority
            .transport_outcome_receipt_issuer
            .issue_outcome(
                &challenge,
                ReconciledAttemptOutcome::DefinitelyNotDelivered,
                None,
                ReconciliationEvidenceSource::LateHttpCompletion,
                [6; 16],
                [7; 32],
                now_ms,
            )
            .is_err());
        let receipt = authority
            .transport_outcome_receipt_issuer
            .issue_outcome(
                &challenge,
                ReconciledAttemptOutcome::Delivered,
                Some(42),
                ReconciliationEvidenceSource::LateHttpCompletion,
                [6; 16],
                [7; 32],
                now_ms,
            )
            .unwrap();
        let proof = authority
            .reconciliation_proof_issuer
            .attest_attempt(&challenge, &receipt, now_ms)
            .unwrap();
        let verified = authority
            .verifier
            .verify_attempt_reconciliation(
                &challenge,
                &proof,
                key_digest,
                7,
                attempt_id,
                &attempt_kind,
                delivery_fingerprint,
                ProgressPhase::Result,
                now_ms,
            )
            .unwrap();
        assert_eq!(verified.outcome(), ReconciledAttemptOutcome::Delivered);
        assert_eq!(verified.telegram_message_id(), Some(42));
    }

    #[test]
    fn role_key_derivation_matches_contract_kats() {
        let root: [u8; 32] = std::array::from_fn(|index| index as u8);
        let authority: [u8; 16] = std::array::from_fn(|index| 0xa0 + index as u8);
        assert_eq!(
            hex(
                &derive_role_key(&root, authority, b"advance.contract215.role.challenge.v1")
                    .unwrap()
            ),
            "de645cb6036e9c7a2498050be06a50257e63be385b3313303b00a66c599c3cfd"
        );
        assert_eq!(
            hex(
                &derive_role_key(&root, authority, b"advance.contract215.role.route-seal.v1")
                    .unwrap()
            ),
            "831420ec212f47d1a070b0a7cc1135ff5750d636960d928d969526fc067b4822"
        );
        assert_eq!(
            hex(&derive_role_key(
                &root,
                authority,
                b"advance.contract215.role.transport-outcome.v1"
            )
            .unwrap()),
            "282690cd482fc9f3e05753ddb0553a201ca1283c4fe06a884cb5b5edfab93c60"
        );
        assert_eq!(
            hex(&derive_role_key(
                &root,
                authority,
                b"advance.contract215.role.attempt-reconciliation.v1"
            )
            .unwrap()),
            "1638ebc3c6d6ce48883e8c2cecc63414db238b6391845ac5e74833102da1743a"
        );
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}

//! CONTRACT-218 provider foundation over the live [`ComponentRegistry`].
//!
//! The provider owns one revisioned in-memory view, but no database or catalog
//! of its own: all durable rows live in the registry's existing SQLite
//! connection.  Every provider mutation is serialized by the registry's one
//! mutation lock and coordinated through the scheduler-owned external anchor
//! typestate before the view is published.

use std::collections::BTreeMap;
use std::io::Read;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
#[cfg(any(test, feature = "test-support"))]
use std::sync::OnceLock;
use std::sync::{Arc, Mutex, RwLock};
use subtle::ConstantTimeEq;

use advance_shared_types::contract218_previsible::{
    termination_member_set_digest as contract123_termination_member_set_digest,
    AgentReadyVerification, C123Purpose2ZeroToken, ComponentReadyVerification,
    PersistedIdentityKeyringBinding, PersistedIdentityKeyringRole, PersistedKeyRetirementChallenge,
    PersistedKeyRetirementScanSet, PrevisibleActivationKind, PrevisibleProofVerifierRole,
    ProviderActivationRecord, RetainedTombstoneGcChallenge, RetainedTombstoneGcChallengeMetadata,
    RetainedTombstoneGcReceiptSet, TerminationCleanupReceiptVerifierRole,
    TerminationFinalizeCommitAck, TerminationFinalizeInputVerification,
    TerminationGrantSubjectDrainReceiptSet, TerminationOperationRecord,
    TerminationSourceEmissionQuiesceReceiptSet, TerminationStateMachineRole,
    VerifiedPersistedKeyRetirementScanSet, VerifiedPrevisibleProofKind,
    VerifiedPrevisibleProofMetadata, VerifiedRetainedTombstoneGcSet,
    VerifiedTerminationFinalizeJournalMetadata, VerifiedTerminationPrepareReceiptSet,
};
use advance_shared_types::observation_identity::{
    AgentAbortBundle, AgentObservationIdentityRegistrar, AgentPublicationRecoveryHandle,
    AgentPublicationResult, AuthenticatedObservationSourceHandle, CommittedComponentSourceReceipt,
    CompletedIdentityHydrationReceipt, ComponentAbortBundle, ComponentObservationSourceIssuer,
    ComponentPublicationRecoveryHandle, ComponentPublicationResult, DeclarationDigest,
    HostEmitterId, HostObservationIdentityRegistrar, IssuedObservationSourceHandle,
    ObservationIdentityAuthority, ObservationIdentityClaims, ObservationIdentityClass,
    ObservationIdentityPersistenceSealer, PersistedObservationBinding,
    PersistedObservationIdentity, PrevisibleActivationReadyProof, PrevisibleObservationActivation,
    SensitiveParamCatalog, SensitiveParamCatalogError, SensitiveParamDeclaration,
    SensitiveParamSnapshot, SourceBindingDigest, TerminationCleanupCompleteReceipt,
    TerminationFinalizeRecoveryHandle, TerminationFinalizeResult, TerminationPrepareCommitAck,
    TerminationPrepareFailure, TerminationPrepareRecoveryHandle, TrustedObservationIdentity,
    VerifiedGrantSubjectDrainToken, VerifiedSourceEmissionQuiesceReceipt,
};
use rusqlite::types::ValueRef;
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::sync::watch;

use crate::observation_anchor::{
    authenticated_persisted_keyring_projection, classify_recovery,
    legacy_marker_anchor_lease_binding, prepare_legacy_complete_marker_mutation,
    prepare_legacy_installed_marker_mutation, PersistedKeyringEntryProjection,
    PersistedKeyringProjection, PersistedKeyringStatus, PreparedLegacyMarkerMutation,
    PreparedLegacyRegistryMigration, PreparedPersistedKeyringMutation,
    PreparedRoleAllocationMutation, RegistryAnchorError, RegistryAnchorMutation,
    RegistryAnchorTransaction, RegistryAnchorTuple, RegistryAnchorWorld,
    RegistryDatabaseCommitProofIssuer, RegistryHeadContext, RegistryRecoveryCapability,
    RegistryRecoveryDecision, RetainedRoleDependencyReceipt,
    VerifiedLegacyRegistryMigrationGenesis, ZeroRoleDependencyReceipt,
};
use crate::registry::{
    activate_observation_component_schema, checkpoint_and_sync_registry,
    create_observation_foundation_schema, migrate_legacy_component_schema,
    redact_webhook_secrets_in_trigger, verify_observation_schema_fingerprint, ComponentRegistry,
    RegistryError, MAX_SUBMITTER_LEN, MIN_RECURRING_INTERVAL_MS,
};
use crate::registry_codec::{
    capture as capture_registry_snapshot, state_root as canonical_state_root,
    validate_operation_effects, write_set_digest as canonical_write_set_digest,
};
use crate::types::{ComponentId, ComponentSubmitConfig};

const GENESIS_DOMAIN: &[u8] = b"advance.contract218.registry-genesis.v1\0";
const MIGRATION_DIGEST_DOMAIN: &[u8] = b"advance.contract218.registry-migration-digest.v1\0";
const MARKER_ROOT_DOMAIN: &[u8] = b"advance.contract218.registry-marker-root.v1\0";
const LEGACY_INVENTORY_DOMAIN: &[u8] = b"advance.contract218.legacy-registry-inventory.v1\0";
const LEGACY_PROJECTION_DOMAIN: &[u8] = b"advance.contract218.legacy-registry-projection.v1\0";
const AUDIT_CHECKPOINT_WITNESS_DOMAIN: &[u8] = b"advance.contract218.audit-checkpoint-witness.v1\0";
const PREVISIBLE_TOTAL_BYTES: i64 = 4_096;
const AUDIT_CHECKPOINT_BYTES: i64 = 8;
const MAX_PREVISIBLE_ROWS: i64 = 65_536;
const MAX_PREVISIBLE_COMBINED_BYTES: i64 = 16_777_216;
const TERMINATION_FINALIZE_TOTAL_BYTES: i64 = 2_048;
const MAX_TERMINATION_FINALIZE_ROWS: i64 = 65_536;
const MAX_TERMINATION_FINALIZE_COMBINED_BYTES: i64 = 67_108_864;
const MAX_CARRIER_MIGRATION_ROWS: u64 = 4_194_304;
const CARRIER_MIGRATION_ROW_RESERVATION_BYTES: u64 = 2_048;
const MAX_CARRIER_MIGRATION_COMBINED_BYTES: u64 = 8_589_934_592;
const COMPLETE_UTC_DAY_MS: u64 = 24 * 60 * 60 * 1_000;

/// Closed crash boundaries for the anchored SQLite/anchor transaction runner.
/// The arming API is compiled only for tests/test-support builds; production
/// callers cannot install an injector or select a raw storage boundary.
#[cfg(any(test, feature = "test-support"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservationMutationFailpointStage {
    BeforeMutation,
    AfterMutationBeforeValidation,
    AfterValidationBeforeAnchorPrepare,
    AfterAnchorPrepareBeforeDatabaseCommit,
    AfterDatabaseCommitBeforeSync,
    AfterSyncBeforeAnchorCommit,
    AfterAnchorCommitBeforeSelect,
    AfterSelectBeforeCompact,
    AfterCompact,
}

/// Fixture-only effective combined-byte boundary for the next termination
/// finalization reservation.  The database counters remain canonical; this
/// narrows the next admission limit without exposing or mutating raw rows.
#[cfg(any(test, feature = "test-support"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminationFinalizeCapacityBoundary {
    CapMinusOne,
    AtCap,
    CapPlusOne,
}

/// Closed fixture boundaries for proving that tag-1/tag-2 admission reserves
/// the eventual tag-3 journal row and its complete 4096-byte envelope.  The
/// fixture only narrows production limits around the durable counters; it
/// never manufactures rows or edits accounting state.
#[cfg(any(test, feature = "test-support"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrevisibleAdmissionCapacityBoundary {
    OneRowRemaining,
    OneReservationRemaining,
}

/// Closed, one-shot schema adversary stages for the greenfield transaction.
/// They exist only to prove both lock-local fingerprint gates; production has
/// no callback or raw-SQL injection surface.
#[cfg(any(test, feature = "test-support"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GreenfieldSchemaAdversaryStage {
    BeforeLockedPreimageValidation,
    BeforeFinalPostimageValidation,
}

#[cfg(any(test, feature = "test-support"))]
static GREENFIELD_SCHEMA_ADVERSARY: OnceLock<
    Mutex<Option<([u8; 16], GreenfieldSchemaAdversaryStage)>>,
> = OnceLock::new();

#[cfg(any(test, feature = "test-support"))]
static MARKER_RETRY_SCHEMA_ADVERSARY: OnceLock<Mutex<Option<([u8; 16], usize)>>> = OnceLock::new();

/// Read-only durable capacity projection used by exact restart witnesses.
#[cfg(any(test, feature = "test-support"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObservationCapacitySnapshot {
    pub previsible_rows: u64,
    pub previsible_actual_bytes: u64,
    pub previsible_future_bytes: u64,
    pub finalization_rows: u64,
    pub finalization_actual_bytes: u64,
    pub finalization_future_bytes: u64,
}

/// Closed adversarial mutations used to prove operation-tag field ownership.
/// The enum and injector do not exist in production builds.
#[cfg(any(test, feature = "test-support"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationEffectAdversary {
    NonGcTagChangesGcFields,
    GcTagSkipsFirstGeneration,
    CompactionTagChangesNonCheckpointField,
}

#[derive(Clone, Copy)]
struct AdmissionCapacityLimits {
    identities: u64,
    authorities: u64,
    active_operations: u64,
    operations: u64,
    members: u64,
}

impl Default for AdmissionCapacityLimits {
    fn default() -> Self {
        Self {
            identities: MAX_LIVE_RETAINED_IDENTITIES,
            authorities: MAX_AUTHORITY_ROWS,
            active_operations: MAX_ACTIVE_IDENTITY_OPERATIONS,
            operations: MAX_COMMITTED_IDENTITY_OPERATIONS,
            members: MAX_COMMITTED_IDENTITY_MEMBERS,
        }
    }
}

#[derive(Clone, Copy)]
struct PrevisibleCapacityLimits {
    rows: i64,
    combined_bytes: i64,
}

impl Default for PrevisibleCapacityLimits {
    fn default() -> Self {
        Self {
            rows: MAX_PREVISIBLE_ROWS,
            combined_bytes: MAX_PREVISIBLE_COMBINED_BYTES,
        }
    }
}

#[derive(Clone, Copy)]
struct AuditCheckpointCapacityLimits {
    previsible_combined_bytes: i64,
    finalization_combined_bytes: i64,
}

impl Default for AuditCheckpointCapacityLimits {
    fn default() -> Self {
        Self {
            previsible_combined_bytes: MAX_PREVISIBLE_COMBINED_BYTES,
            finalization_combined_bytes: MAX_TERMINATION_FINALIZE_COMBINED_BYTES,
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
#[derive(Default)]
struct ObservationMutationTestControls {
    next_failpoint: Mutex<Option<ObservationMutationFailpointStage>>,
    next_termination_finalize_limit: AtomicU64,
    admission_limits: Mutex<AdmissionCapacityLimits>,
    previsible_limits: Mutex<PrevisibleCapacityLimits>,
    checkpoint_limits: Mutex<AuditCheckpointCapacityLimits>,
}

#[cfg(any(test, feature = "test-support"))]
impl ObservationMutationTestControls {
    fn hit(
        &self,
        stage: ObservationMutationFailpointStage,
    ) -> Result<(), ObservationProviderError> {
        let mut armed = self.next_failpoint.lock().map_err(|_| {
            ObservationProviderError::RecoveryRequired(
                "observation mutation failpoint fixture lock is poisoned".to_owned(),
            )
        })?;
        if armed.as_ref() == Some(&stage) {
            *armed = None;
            return Err(ObservationProviderError::RecoveryRequired(format!(
                "fixture interrupted anchored mutation at closed stage {stage:?}"
            )));
        }
        Ok(())
    }

    fn take_termination_finalize_limit(&self) -> i64 {
        let value = self
            .next_termination_finalize_limit
            .swap(0, Ordering::AcqRel);
        if value == 0 {
            MAX_TERMINATION_FINALIZE_COMBINED_BYTES
        } else {
            i64::try_from(value).unwrap_or(MAX_TERMINATION_FINALIZE_COMBINED_BYTES)
        }
    }
}

pub const MAX_LIVE_RETAINED_IDENTITIES: u64 = 65_536;
pub const MAX_ACTIVE_IDENTITY_OPERATIONS: u64 = 4_096;
pub const MAX_AUTHORITY_ROWS: u64 = 262_144;
pub const MAX_COMMITTED_IDENTITY_OPERATIONS: u64 = 65_536;
pub const MAX_COMMITTED_IDENTITY_MEMBERS: u64 = 262_144;
pub const OBSERVATION_RETENTION_HORIZON_MS: u64 = 30 * 24 * 60 * 60 * 1_000;

/// Move-only proof that an external audit owner authenticated one checkpoint
/// and its covered registry high-water. Production exposes no raw constructor;
/// a future owner port must verify its carrier before producing this value.
pub struct AuthenticatedAuditCheckpointWitness {
    registry_instance: [u8; 16],
    checkpoint_sequence: u64,
    covered_registry_sequence: u64,
    verified_at_ms: u64,
    commitment: [u8; 32],
}

impl std::fmt::Debug for AuthenticatedAuditCheckpointWitness {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AuthenticatedAuditCheckpointWitness(<opaque>)")
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AuditCompactionOutcome {
    pub checkpointed_journals: u64,
    pub compacted_operations: u64,
    pub compacted_members: u64,
    pub compacted_journals: u64,
}

/// Move-only external half of one authenticated persisted-keyring file
/// replacement.  It retains custody of the already-fsynced pending file until
/// the scheduler has committed the exact SQLite/anchor successor, then alone
/// can promote that file to current.
pub trait PreparedPersistedKeyringCustodyMutation: Send {
    fn previous_binding(&self) -> PersistedIdentityKeyringBinding;

    fn next_binding(&self) -> PersistedIdentityKeyringBinding;

    fn take_scheduler_preparation(
        &mut self,
    ) -> Result<PreparedPersistedKeyringMutation, RegistryAnchorError>;

    fn promote_after_anchor(
        self: Box<Self>,
        anchored: &RegistryAnchorTuple,
    ) -> Result<(), RegistryAnchorError>;
}

/// Object-safe host custody used by the scheduler's synchronous carrier port.
/// Complete authenticated files and raw key material never cross this seam;
/// only one pending whole-file replacement and the shared typed carrier
/// capabilities can exist for a given current root.
pub trait PersistedKeyringCustody: Send + Sync {
    fn authenticated_current_file(
        &self,
        expected_registry_instance: [u8; 16],
    ) -> Result<Vec<u8>, RegistryAnchorError>;

    fn prepare_last_issued_replacement(
        &self,
        key_id: u32,
        issued_at_ms: u64,
        head_context: RegistryHeadContext,
    ) -> Result<Box<dyn PreparedPersistedKeyringCustodyMutation>, RegistryAnchorError>;

    fn prepare_signing_rotation(
        &self,
        new_signing_master_key_epoch: u32,
        head_context: RegistryHeadContext,
    ) -> Result<Box<dyn PreparedPersistedKeyringCustodyMutation>, RegistryAnchorError>;

    fn prepare_retirement(
        &self,
        verified_scans: VerifiedPersistedKeyRetirementScanSet,
        head_context: RegistryHeadContext,
    ) -> Result<Box<dyn PreparedPersistedKeyringCustodyMutation>, RegistryAnchorError>;
}

/// Provider construction parameters supplied by the composition root after it
/// has acquired the platform anchor and role-root custody.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservationProviderConfig {
    pub registry_instance: [u8; 16],
    pub boot: [u8; 16],
    pub role_allocation_root: [u8; 32],
    /// Complete MAC-authenticated canonical persisted-keyring file selected by
    /// the external bundle.  SQLite stores only a query projection; this file
    /// is the sole source of `keyring_root`.
    pub authenticated_persisted_keyring_file: Vec<u8>,
    pub migration_digest: [u8; 32],
    pub signing_key_id: u32,
    pub master_key_epoch: u32,
    /// Epoch authenticating the external registry manifest.  It is not the
    /// persisted-key entry epoch above and not the role-allocation manifest's
    /// independently encoded header epoch.
    pub registry_manifest_key_epoch: u32,
    /// Exact marker root under which only the stopped carrier-migration
    /// protocol may run. Normal catalog visibility remains gated until the
    /// complete root below is durably selected.
    migration_installed_marker_root: Option<[u8; 32]>,
    migration_marker_root: Option<[u8; 32]>,
}

impl ObservationProviderConfig {
    pub fn greenfield(
        registry_instance: [u8; 16],
        boot: [u8; 16],
        role_allocation_root: [u8; 32],
        authenticated_persisted_keyring_file: Vec<u8>,
    ) -> Result<Self, ObservationProviderError> {
        if registry_instance == [0; 16] || boot == [0; 16] || role_allocation_root == [0; 32] {
            return Err(ObservationProviderError::InvalidInput(
                "registry instance, boot, and role-allocation root must be nonzero".to_owned(),
            ));
        }
        Ok(Self {
            registry_instance,
            boot,
            role_allocation_root,
            authenticated_persisted_keyring_file,
            migration_digest: greenfield_migration_digest(),
            signing_key_id: 1,
            master_key_epoch: 1,
            registry_manifest_key_epoch: 1,
            migration_installed_marker_root: None,
            migration_marker_root: None,
        })
    }

    pub fn authenticated_legacy_migration(
        boot: [u8; 16],
        migration: &PreparedLegacyRegistryMigration,
        authenticated_persisted_keyring_file: Vec<u8>,
    ) -> Result<Self, ObservationProviderError> {
        let (keyring_root, projection) = authenticated_persisted_keyring_projection(
            &authenticated_persisted_keyring_file,
            migration.registry_instance(),
        )?;
        let signing = projection
            .entries
            .iter()
            .find(|entry| entry.status == PersistedKeyringStatus::Signing)
            .ok_or_else(|| {
                ObservationProviderError::InvalidInput(
                    "authenticated migration keyring has no signing entry".to_owned(),
                )
            })?;
        if keyring_root != migration.target_keyring_root()
            || projection.manifest_key_epoch != migration.manifest_key_epoch()
        {
            return Err(ObservationProviderError::InvalidInput(
                "authenticated migration keyring does not match its target block".to_owned(),
            ));
        }
        let config = Self {
            registry_instance: migration.registry_instance(),
            boot,
            role_allocation_root: migration.target_role_allocation_root(),
            authenticated_persisted_keyring_file,
            migration_digest: migration.migration_digest(),
            signing_key_id: signing.key_id,
            master_key_epoch: signing.master_key_epoch,
            registry_manifest_key_epoch: migration.manifest_key_epoch(),
            migration_installed_marker_root: Some(migration.installed_marker_root()),
            migration_marker_root: Some(migration.complete_marker_root()),
        };
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), ObservationProviderError> {
        if self.registry_instance == [0; 16]
            || self.boot == [0; 16]
            || self.role_allocation_root == [0; 32]
            || self.authenticated_persisted_keyring_file.is_empty()
            || match (
                self.migration_installed_marker_root,
                self.migration_marker_root,
            ) {
                (None, None) => self.migration_digest != greenfield_migration_digest(),
                (Some(installed), Some(complete)) => {
                    installed == [0; 32]
                        || complete == [0; 32]
                        || installed == complete
                        || self.migration_digest == greenfield_migration_digest()
                }
                _ => true,
            }
            || self.signing_key_id == 0
            || self.master_key_epoch == 0
            || self.registry_manifest_key_epoch == 0
        {
            return Err(ObservationProviderError::InvalidInput(
                "invalid zero-valued provider construction field".to_owned(),
            ));
        }
        Ok(())
    }
}

fn greenfield_migration_digest() -> [u8; 32] {
    let mut migration = Sha256::new();
    migration.update(MIGRATION_DIGEST_DOMAIN);
    migration.update([1]);
    migration.update(0_u16.to_be_bytes());
    migration.finalize().into()
}

fn greenfield_marker_root() -> [u8; 32] {
    let mut marker = Sha256::new();
    marker.update(MARKER_ROOT_DOMAIN);
    marker.update(0_u32.to_be_bytes());
    marker.finalize().into()
}

#[derive(Debug, Error)]
pub enum ObservationProviderError {
    #[error("invalid observation provider input: {0}")]
    InvalidInput(String),
    #[error("observation identity already exists or conflicts")]
    IdentityConflict,
    #[error("observation identity was not found")]
    UnknownIdentity,
    #[error("observation identity capacity exceeded: {0}")]
    CapacityExceeded(String),
    #[error("observation identity is not eligible for this transition: {0}")]
    InvalidState(String),
    #[error("observation identity recovery required: {0}")]
    RecoveryRequired(String),
    #[error("observation provider is busy; retry through the typed recovery path")]
    Busy,
    #[error("observation mutation was rejected before external prepare/SQLite commit: {0}")]
    DefiniteRollback(Box<ObservationProviderError>),
    #[error(transparent)]
    Registry(#[from] RegistryError),
    #[error(transparent)]
    Sql(#[from] rusqlite::Error),
    #[error(transparent)]
    Anchor(#[from] RegistryAnchorError),
    #[error(transparent)]
    Catalog(#[from] SensitiveParamCatalogError),
    #[error("observation provider blocking task failed: {0}")]
    Join(String),
}

impl ObservationProviderError {
    fn gates_provider(&self) -> bool {
        matches!(
            self,
            Self::RecoveryRequired(_)
                | Self::Registry(_)
                | Self::Sql(_)
                | Self::Anchor(_)
                | Self::Catalog(SensitiveParamCatalogError::RecoveryRequired)
                | Self::Catalog(SensitiveParamCatalogError::StorageUnavailable)
                | Self::Join(_)
        )
    }

    fn as_catalog_error(&self) -> SensitiveParamCatalogError {
        match self {
            Self::UnknownIdentity => SensitiveParamCatalogError::UnknownIdentity,
            Self::CapacityExceeded(_) => SensitiveParamCatalogError::CapacityExceeded,
            Self::RecoveryRequired(_) => SensitiveParamCatalogError::RecoveryRequired,
            Self::InvalidInput(_) | Self::IdentityConflict | Self::InvalidState(_) => {
                SensitiveParamCatalogError::InvalidIdentity
            }
            Self::DefiniteRollback(error) => error.as_catalog_error(),
            Self::Busy | Self::Registry(_) | Self::Sql(_) | Self::Anchor(_) | Self::Join(_) => {
                SensitiveParamCatalogError::StorageUnavailable
            }
            Self::Catalog(error) => *error,
        }
    }
}

fn definite_rollback(error: ObservationProviderError) -> ObservationProviderError {
    if matches!(error, ObservationProviderError::DefiniteRollback(_)) || !error.gates_provider() {
        error
    } else {
        ObservationProviderError::DefiniteRollback(Box::new(error))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IdentityLifecycle {
    Pending,
    Live,
    Terminating,
    Tombstoned,
    Permanent,
}

impl IdentityLifecycle {
    fn parse(value: &str) -> Result<Self, ObservationProviderError> {
        match value {
            "pending" => Ok(Self::Pending),
            "live" => Ok(Self::Live),
            "terminating" => Ok(Self::Terminating),
            "tombstoned" => Ok(Self::Tombstoned),
            "permanent" => Ok(Self::Permanent),
            _ => Err(ObservationProviderError::RecoveryRequired(
                "unknown persisted identity lifecycle".to_owned(),
            )),
        }
    }

    fn permits_live_authority(self) -> bool {
        matches!(self, Self::Live | Self::Permanent)
    }

    fn permits_replay(self) -> bool {
        matches!(
            self,
            Self::Live | Self::Terminating | Self::Tombstoned | Self::Permanent
        )
    }
}

#[derive(Clone)]
struct IdentityViewRow {
    snapshot: SensitiveParamSnapshot,
    lifecycle: IdentityLifecycle,
}

enum TombstoneGcChallengePlan {
    Existing {
        record: TerminationOperationRecord,
        tombstone_state_root: [u8; 32],
        gc_generation: u64,
        challenge_nonce: [u8; 32],
    },
    Prepare {
        record: TerminationOperationRecord,
        tombstone_state_root: [u8; 32],
        gc_generation: u64,
        previous_phase: String,
        previous_generation: u64,
        member_count: usize,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CarrierMigrationPlanMetadata {
    migration_id: [u8; 16],
    registry_instance: [u8; 16],
    m019_ledger_instance: [u8; 16],
    cross_owner_key_epoch: u32,
    source_m019_sequence: u64,
    source_m019_head: [u8; 32],
    source_m019_state_root: [u8; 32],
    target_m019_sequence: u64,
    target_m019_head: [u8; 32],
    target_m019_state_root: [u8; 32],
    sqlite_store_instance_digest: [u8; 32],
    sqlite_retained_high_water: u64,
    sqlite_source_root: [u8; 32],
    sqlite_target_root: [u8; 32],
    jsonl_store_instance_digest: [u8; 32],
    jsonl_retained_high_water: u64,
    jsonl_source_inventory_root: [u8; 32],
    jsonl_target_inventory_root: [u8; 32],
    frozen_row_set_digest: [u8; 32],
    owner_plan_digest: [u8; 32],
    freeze_receipt_digest: [u8; 32],
    planned_row_count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CarrierMigrationRowMetadata {
    ordinal: u64,
    store_kind: u8,
    event_key_digest: [u8; 32],
    event_cursor_digest: [u8; 32],
    receipt_nonce: [u8; 32],
    legacy_receipt: Vec<u8>,
    owner_intent_digest: [u8; 32],
    owner_preimage_digest: [u8; 32],
    owner_postimage_digest: [u8; 32],
}

/// Opaque, composition-issued complete carrier-migration plan.  No field,
/// digest, row, or owner tuple is caller-readable.  The production M019/M009
/// role wiring that constructs this value remains intentionally deferred.
pub struct CarrierMigrationPlan {
    metadata: Arc<CarrierMigrationPlanMetadata>,
}

/// Opaque durable reservation for one exact plan.  It can only be returned by
/// this provider after the header and its complete worst-case capacity have
/// been anchored.
pub struct CarrierMigrationReservation {
    metadata: Arc<CarrierMigrationPlanMetadata>,
}

/// Closed owner-store selection used by typed migration roles.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CarrierMigrationStore {
    Sqlite,
    Jsonl,
}

impl CarrierMigrationStore {
    #[cfg(any(test, feature = "test-support"))]
    fn tag(self) -> u8 {
        match self {
            Self::Sqlite => 1,
            Self::Jsonl => 2,
        }
    }
}

/// Opaque M014 input produced only from a frozen owner record and its retained
/// legacy receipt.  Borrowing it for prepare preserves the typed input on a
/// definite precommit rejection.
pub struct CarrierMigrationPreparedOwnerIntent {
    plan: Arc<CarrierMigrationPlanMetadata>,
    row: CarrierMigrationRowMetadata,
}

/// Opaque committed M014 row intent released only after the exact row is
/// rooted.  The owner receives no database handle or digest-only constructor.
pub struct CarrierMigrationPreparedIntent {
    plan: Arc<CarrierMigrationPlanMetadata>,
    row: CarrierMigrationRowMetadata,
    committed: RegistryAnchorTuple,
}

/// Opaque receipt issued by the owner only after its named postimage is
/// anchored.  M014 accepts no raw owner sequence/head/root parameters.
pub struct CarrierMigrationOwnerCommitReceipt {
    plan: Arc<CarrierMigrationPlanMetadata>,
    row: CarrierMigrationRowMetadata,
    prepared_registry_sequence: u64,
    prepared_registry_head: [u8; 32],
    prepared_registry_state_root: [u8; 32],
    receipt_digest: [u8; 32],
}

/// Opaque fresh whole-owner target verification supplied after every planned
/// row is committed.  This is distinct from a per-row owner receipt.
pub struct CarrierMigrationOwnerFinalizedReceipt {
    plan: Arc<CarrierMigrationPlanMetadata>,
    verification_digest: [u8; 32],
}

/// Opaque acknowledgement that one prepared row was finalized in M014.
#[allow(dead_code)]
pub struct CarrierMigrationRowFinalizedAck {
    plan: Arc<CarrierMigrationPlanMetadata>,
    row: CarrierMigrationRowMetadata,
}

/// Opaque acknowledgement that the complete typed owner target was verified.
#[allow(dead_code)]
pub struct CarrierMigrationFinalizedAck {
    metadata: Arc<CarrierMigrationPlanMetadata>,
}

/// Opaque proof that the stopped legacy registry target and its sequence-zero
/// ledger were committed, checkpointed, and re-read with the exact Prepared
/// marker context.  It is nested in the later anchor-installed witness so a
/// caller cannot substitute a boolean or tuple.
pub struct VerifiedLegacyDatabaseInstalled {
    plan_binding: [u8; 32],
    tuple: RegistryAnchorTuple,
}

/// Opaque proof that the exact Prepared marker plus target keyring/role files
/// are selected in a clean sequence-zero external anchor after the database
/// installation above.
pub struct VerifiedLegacyAnchorInstalled {
    database: VerifiedLegacyDatabaseInstalled,
}

impl VerifiedLegacyAnchorInstalled {
    pub fn verify_for(
        &self,
        migration: &PreparedLegacyRegistryMigration,
    ) -> Result<&RegistryAnchorTuple, RegistryAnchorError> {
        if self.database.plan_binding != migration.plan_binding_digest()
            || self.database.tuple.registry_instance != migration.registry_instance()
            || self.database.tuple.sequence != 0
            || self.database.tuple.state_root != migration.target_state_root()
            || self.database.tuple.keyring_root != migration.target_keyring_root()
            || self.database.tuple.role_allocation_root != migration.target_role_allocation_root()
            || self.database.tuple.migration_digest != migration.migration_digest()
        {
            return Err(RegistryAnchorError::AuthenticationFailed);
        }
        Ok(&self.database.tuple)
    }

    pub fn database_witness(&self) -> &VerifiedLegacyDatabaseInstalled {
        &self.database
    }

    /// Derive the only legal Prepared→Installed tag-13 mutation from this
    /// witness and the real selected anchor.  No caller supplies a tuple,
    /// marker root, epoch, or head context.
    pub fn prepare_installed_marker_transition(
        &self,
        anchor: &dyn RegistryAnchorTransaction,
        migration: &PreparedLegacyRegistryMigration,
    ) -> Result<PreparedLegacyMarkerMutation, RegistryAnchorError> {
        let witnessed = self.verify_for(migration)?;
        let observed = match anchor.observe()? {
            RegistryAnchorWorld::CompactCurrent { current, .. } if &current == witnessed => current,
            _ => return Err(RegistryAnchorError::AuthenticationFailed),
        };
        let context = RegistryHeadContext {
            previous_marker_root: migration.prepared_marker_root(),
            next_marker_root: migration.installed_marker_root(),
            manifest_key_epoch: migration.manifest_key_epoch(),
            next_manifest_key_epoch: migration.manifest_key_epoch(),
        };
        prepare_legacy_installed_marker_mutation(anchor, migration, observed, context)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn fixture_for_test(migration: &PreparedLegacyRegistryMigration) -> Self {
        Self {
            database: VerifiedLegacyDatabaseInstalled {
                plan_binding: migration.plan_binding_digest(),
                tuple: migration_target_tuple(migration),
            },
        }
    }
}

impl std::fmt::Debug for VerifiedLegacyDatabaseInstalled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VerifiedLegacyDatabaseInstalled(<opaque>)")
    }
}

impl std::fmt::Debug for VerifiedLegacyAnchorInstalled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VerifiedLegacyAnchorInstalled(<opaque>)")
    }
}

/// Opaque proof that one exact Prepared→Installed or Installed→Complete
/// synthetic tag-13 transition committed in SQLite and the external anchor.
pub struct VerifiedLegacyMarkerTransitionCommitted {
    plan_binding: [u8; 32],
    next: RegistryAnchorTuple,
    previous_marker_root: [u8; 32],
    next_marker_root: [u8; 32],
    next_phase: u8,
    anchor_lease_challenge: [u8; 32],
    anchor_lease_tag: [u8; 32],
}

impl VerifiedLegacyMarkerTransitionCommitted {
    pub fn verify_installed_for(
        &self,
        migration: &PreparedLegacyRegistryMigration,
    ) -> Result<&RegistryAnchorTuple, RegistryAnchorError> {
        self.verify_for(migration, 2)?;
        Ok(&self.next)
    }

    pub fn verify_complete_for(
        &self,
        migration: &PreparedLegacyRegistryMigration,
    ) -> Result<&RegistryAnchorTuple, RegistryAnchorError> {
        self.verify_for(migration, 3)?;
        Ok(&self.next)
    }

    /// Re-bind this committed transition to the concrete live custody owner
    /// immediately before its physical pending marker is promoted.
    pub fn verify_anchor_lease(
        &self,
        anchor: &dyn RegistryAnchorTransaction,
    ) -> Result<(), RegistryAnchorError> {
        let observed = anchor.anchor_lease_tag(self.anchor_lease_challenge)?;
        if observed == [0; 32] || !bool::from(observed.ct_eq(&self.anchor_lease_tag)) {
            return Err(RegistryAnchorError::AuthenticationFailed);
        }
        Ok(())
    }

    fn verify_for(
        &self,
        migration: &PreparedLegacyRegistryMigration,
        expected_phase: u8,
    ) -> Result<(), RegistryAnchorError> {
        let (previous_root, next_root) = if expected_phase == 2 {
            (
                migration.prepared_marker_root(),
                migration.installed_marker_root(),
            )
        } else {
            (
                migration.installed_marker_root(),
                migration.complete_marker_root(),
            )
        };
        if self.plan_binding != migration.plan_binding_digest()
            || self.next_phase != expected_phase
            || self.next.registry_instance != migration.registry_instance()
            || self.next.migration_digest != migration.migration_digest()
            || self.previous_marker_root != previous_root
            || self.next_marker_root != next_root
        {
            return Err(RegistryAnchorError::AuthenticationFailed);
        }
        if (expected_phase == 2
            && (self.next.sequence != 1
                || self.next.state_root != migration.target_state_root()
                || self.next.keyring_root != migration.target_keyring_root()
                || self.next.role_allocation_root != migration.target_role_allocation_root()))
            || (expected_phase == 3 && self.next.sequence < 2)
        {
            return Err(RegistryAnchorError::AuthenticationFailed);
        }
        Ok(())
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn installed_fixture_for_test(
        anchor: &dyn RegistryAnchorTransaction,
        migration: &PreparedLegacyRegistryMigration,
        _previous: RegistryAnchorTuple,
        next: RegistryAnchorTuple,
    ) -> Result<Self, RegistryAnchorError> {
        let (anchor_lease_challenge, anchor_lease_tag) =
            legacy_marker_anchor_lease_binding(anchor, migration, &next, 2)?;
        Ok(Self {
            plan_binding: migration.plan_binding_digest(),
            next,
            previous_marker_root: migration.prepared_marker_root(),
            next_marker_root: migration.installed_marker_root(),
            next_phase: 2,
            anchor_lease_challenge,
            anchor_lease_tag,
        })
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn complete_fixture_for_test(
        anchor: &dyn RegistryAnchorTransaction,
        migration: &PreparedLegacyRegistryMigration,
        _previous: RegistryAnchorTuple,
        next: RegistryAnchorTuple,
    ) -> Result<Self, RegistryAnchorError> {
        let (anchor_lease_challenge, anchor_lease_tag) =
            legacy_marker_anchor_lease_binding(anchor, migration, &next, 3)?;
        Ok(Self {
            plan_binding: migration.plan_binding_digest(),
            next,
            previous_marker_root: migration.installed_marker_root(),
            next_marker_root: migration.complete_marker_root(),
            next_phase: 3,
            anchor_lease_challenge,
            anchor_lease_tag,
        })
    }
}

impl std::fmt::Debug for VerifiedLegacyMarkerTransitionCommitted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VerifiedLegacyMarkerTransitionCommitted(<opaque>)")
    }
}

/// Opaque scheduler proof that the exact carrier migration reached its
/// durable `verified` phase and is bound to this legacy marker plan.
pub struct VerifiedLegacyMigrationComplete {
    plan_binding: [u8; 32],
    registry_instance: [u8; 16],
    migration_id: [u8; 16],
}

impl VerifiedLegacyMigrationComplete {
    pub fn verify_for(
        &self,
        migration: &PreparedLegacyRegistryMigration,
    ) -> Result<(), RegistryAnchorError> {
        if self.plan_binding != migration.plan_binding_digest()
            || self.registry_instance != migration.registry_instance()
            || self.migration_id != migration.migration_id()
        {
            return Err(RegistryAnchorError::AuthenticationFailed);
        }
        Ok(())
    }

    /// Derive the only legal Installed→Complete tag-13 mutation after the
    /// scheduler has verified the complete carrier-migration owner target.
    pub fn prepare_complete_marker_transition(
        &self,
        anchor: &dyn RegistryAnchorTransaction,
        migration: &PreparedLegacyRegistryMigration,
    ) -> Result<PreparedLegacyMarkerMutation, RegistryAnchorError> {
        self.verify_for(migration)?;
        let current = match anchor.observe()? {
            RegistryAnchorWorld::CompactCurrent { current, .. }
                if current.registry_instance == migration.registry_instance()
                    && current.migration_digest == migration.migration_digest()
                    && current.sequence >= 1 =>
            {
                current
            }
            _ => return Err(RegistryAnchorError::AuthenticationFailed),
        };
        let context = RegistryHeadContext {
            previous_marker_root: migration.installed_marker_root(),
            next_marker_root: migration.complete_marker_root(),
            manifest_key_epoch: migration.manifest_key_epoch(),
            next_manifest_key_epoch: migration.manifest_key_epoch(),
        };
        prepare_legacy_complete_marker_mutation(anchor, migration, current, context)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn fixture_for_test(migration: &PreparedLegacyRegistryMigration) -> Self {
        Self {
            plan_binding: migration.plan_binding_digest(),
            registry_instance: migration.registry_instance(),
            migration_id: migration.migration_id(),
        }
    }
}

impl std::fmt::Debug for VerifiedLegacyMigrationComplete {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VerifiedLegacyMigrationComplete(<opaque>)")
    }
}

/// Minimal recovery projection.  It exposes no counts, rows, digests, owner
/// coordinates, or mutable storage handles.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CarrierMigrationRecoveryPhase {
    Issuing,
    OwnerReady,
    Verifying,
    Verified,
}

/// Test-only typed role stand-in.  It creates the same opaque production
/// inputs without granting raw database/digest construction authority.
#[cfg(any(test, feature = "test-support"))]
pub struct CarrierMigrationTestFixture {
    metadata: Arc<CarrierMigrationPlanMetadata>,
}

#[cfg(any(test, feature = "test-support"))]
impl CarrierMigrationTestFixture {
    pub fn plan(&self) -> CarrierMigrationPlan {
        CarrierMigrationPlan {
            metadata: Arc::clone(&self.metadata),
        }
    }

    pub fn prepared_owner_intent(
        &self,
        reservation: &CarrierMigrationReservation,
        ordinal: u64,
        store: CarrierMigrationStore,
    ) -> Result<CarrierMigrationPreparedOwnerIntent, ObservationProviderError> {
        if self.metadata.as_ref() != reservation.metadata.as_ref()
            || ordinal >= self.metadata.planned_row_count
        {
            return Err(ObservationProviderError::InvalidInput(
                "carrier-migration fixture row is outside its opaque reservation".to_owned(),
            ));
        }
        Ok(CarrierMigrationPreparedOwnerIntent {
            plan: Arc::clone(&self.metadata),
            row: carrier_migration_fixture_row(&self.metadata, ordinal, store),
        })
    }

    pub fn owner_commit(
        &self,
        prepared: &CarrierMigrationPreparedIntent,
    ) -> Result<CarrierMigrationOwnerCommitReceipt, ObservationProviderError> {
        if self.metadata.as_ref() != prepared.plan.as_ref() {
            return Err(ObservationProviderError::InvalidInput(
                "carrier-migration prepared intent belongs to another typed fixture".to_owned(),
            ));
        }
        let receipt_digest = carrier_migration_owner_commit_digest(
            &self.metadata,
            &prepared.row,
            &prepared.committed,
        );
        Ok(CarrierMigrationOwnerCommitReceipt {
            plan: Arc::clone(&self.metadata),
            row: prepared.row.clone(),
            prepared_registry_sequence: prepared.committed.sequence,
            prepared_registry_head: prepared.committed.head,
            prepared_registry_state_root: prepared.committed.state_root,
            receipt_digest,
        })
    }

    pub fn owner_finalized(
        &self,
        reservation: &CarrierMigrationReservation,
    ) -> Result<CarrierMigrationOwnerFinalizedReceipt, ObservationProviderError> {
        if self.metadata.as_ref() != reservation.metadata.as_ref() {
            return Err(ObservationProviderError::InvalidInput(
                "carrier-migration finalized proof belongs to another reservation".to_owned(),
            ));
        }
        Ok(CarrierMigrationOwnerFinalizedReceipt {
            plan: Arc::clone(&self.metadata),
            verification_digest: carrier_migration_owner_finalized_digest(&self.metadata),
        })
    }
}

/// Move-only Installed-phase coordinator. It deliberately has no `Deref`,
/// catalog/view/revision subscription, registry accessor, identity authority,
/// registrar, or conversion into [`RegistrySensitiveParamProvider`]. The only
/// exit is consuming a durable finalized acknowledgement into the opaque
/// completion witness, after which the caller must publish the Complete marker
/// and perform a fresh normal provider open.
///
/// ```compile_fail
/// use advance_scheduler::sensitive_params::InstalledCarrierMigrationCoordinator;
/// fn normal_surfaces_are_absent(coordinator: InstalledCarrierMigrationCoordinator) {
///     let _ = coordinator.subscribe();
///     let _ = coordinator.registry();
///     let _ = coordinator.lookup("component");
/// }
/// ```
///
/// ```compile_fail
/// use advance_scheduler::sensitive_params::InstalledCarrierMigrationCoordinator;
/// fn requires_clone<T: Clone>() {}
/// requires_clone::<InstalledCarrierMigrationCoordinator>();
/// ```
///
/// ```compile_fail
/// use advance_scheduler::sensitive_params::InstalledCarrierMigrationCoordinator;
/// fn requires_serialize<T: serde::Serialize>() {}
/// requires_serialize::<InstalledCarrierMigrationCoordinator>();
/// ```
///
/// ```compile_fail
/// use advance_scheduler::sensitive_params::InstalledCarrierMigrationCoordinator;
/// fn requires_deserialize<T: for<'de> serde::Deserialize<'de>>() {}
/// requires_deserialize::<InstalledCarrierMigrationCoordinator>();
/// ```
///
/// ```compile_fail
/// use advance_scheduler::sensitive_params::InstalledCarrierMigrationCoordinator;
/// fn requires_deref<T: std::ops::Deref>() {}
/// requires_deref::<InstalledCarrierMigrationCoordinator>();
/// ```
///
/// ```compile_fail
/// use advance_scheduler::sensitive_params::InstalledCarrierMigrationCoordinator;
/// use advance_shared_types::observation_identity::ComponentObservationSourceIssuer;
/// fn requires_component_issuer<T: ComponentObservationSourceIssuer>() {}
/// requires_component_issuer::<InstalledCarrierMigrationCoordinator>();
/// ```
///
/// ```compile_fail
/// use advance_scheduler::sensitive_params::InstalledCarrierMigrationCoordinator;
/// use advance_shared_types::observation_identity::ObservationIdentityPersistenceSealer;
/// fn requires_persistence_sealer<T: ObservationIdentityPersistenceSealer>() {}
/// requires_persistence_sealer::<InstalledCarrierMigrationCoordinator>();
/// ```
pub struct InstalledCarrierMigrationCoordinator {
    engine: InstalledCarrierMigrationEngine,
}

/// Installed-only execution engine.  This is intentionally a separate type
/// from the normal provider: it owns no catalog view, watch revision,
/// identity/registrar roles, or conversion path into the public provider.
struct InstalledCarrierMigrationEngine {
    registry: Arc<ComponentRegistry>,
    anchor: Arc<dyn RegistryAnchorTransaction>,
    config: ObservationProviderConfig,
    ready: AtomicBool,
    #[cfg(any(test, feature = "test-support"))]
    test_controls: Arc<ObservationMutationTestControls>,
}

/// One Complete/greenfield provider view over one `Arc<ComponentRegistry>`.
pub struct RegistrySensitiveParamProvider {
    registry: Arc<ComponentRegistry>,
    anchor: Arc<dyn RegistryAnchorTransaction>,
    config: ObservationProviderConfig,
    verifier: PrevisibleProofVerifierRole,
    persisted_keyring: Mutex<Option<PersistedIdentityKeyringRole>>,
    persisted_keyring_custody: Arc<dyn PersistedKeyringCustody>,
    termination_state: TerminationStateMachineRole,
    cleanup_verifier: TerminationCleanupReceiptVerifierRole,
    view: RwLock<BTreeMap<String, IdentityViewRow>>,
    revision: AtomicU64,
    revision_tx: watch::Sender<u64>,
    ready: AtomicBool,
    #[cfg(any(test, feature = "test-support"))]
    test_controls: Arc<ObservationMutationTestControls>,
}

/// Cancellation-safe ownership transfer for the registry's unique provider
/// slot.  The guard exists before normal-provider construction; therefore an
/// Installed rejection cannot leave either a provider value or a leaked slot.
struct ObservationProviderClaimGuard {
    registry: Arc<ComponentRegistry>,
    armed: bool,
}

impl ObservationProviderClaimGuard {
    fn acquire(registry: Arc<ComponentRegistry>) -> Result<Self, ObservationProviderError> {
        registry.claim_observation_provider()?;
        Ok(Self {
            registry,
            armed: true,
        })
    }

    fn transfer_to_provider(&mut self) {
        self.armed = false;
    }
}

impl Drop for ObservationProviderClaimGuard {
    fn drop(&mut self) {
        if self.armed {
            self.registry.release_observation_provider();
        }
    }
}

impl InstalledCarrierMigrationCoordinator {
    pub async fn open(
        registry: Arc<ComponentRegistry>,
        anchor: Arc<dyn RegistryAnchorTransaction>,
        config: ObservationProviderConfig,
        verifier: PrevisibleProofVerifierRole,
        persisted_keyring: PersistedIdentityKeyringRole,
        persisted_keyring_custody: Arc<dyn PersistedKeyringCustody>,
        termination_state: TerminationStateMachineRole,
        cleanup_verifier: TerminationCleanupReceiptVerifierRole,
    ) -> Result<Self, ObservationProviderError> {
        config.validate()?;
        verifier.verify_provider_binding(config.registry_instance, config.boot)?;
        let (keyring_root, _) = authenticated_persisted_keyring_projection(
            &config.authenticated_persisted_keyring_file,
            config.registry_instance,
        )?;
        let custody_file =
            persisted_keyring_custody.authenticated_current_file(config.registry_instance)?;
        if custody_file != config.authenticated_persisted_keyring_file {
            return Err(ObservationProviderError::RecoveryRequired(
                "carrier coordinator keyring custody does not retain the authenticated construction file"
                    .to_owned(),
            ));
        }
        persisted_keyring.verify_provider_binding(config.registry_instance, keyring_root)?;
        termination_state.verify_provider_binding(config.registry_instance, config.boot)?;
        cleanup_verifier.verify_provider_binding(config.registry_instance, config.boot)?;

        registry.claim_observation_provider()?;
        let engine = InstalledCarrierMigrationEngine {
            registry,
            anchor,
            config,
            ready: AtomicBool::new(false),
            #[cfg(any(test, feature = "test-support"))]
            test_controls: Arc::new(ObservationMutationTestControls::default()),
        };
        engine.initialize_or_recover().await?;
        engine.ready.store(true, Ordering::Release);
        Ok(Self { engine })
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn carrier_migration_test_fixture(
        &self,
        seed: u64,
        planned_row_count: u64,
    ) -> Result<CarrierMigrationTestFixture, ObservationProviderError> {
        self.engine
            .carrier_migration_test_fixture(seed, planned_row_count)
    }

    pub fn reserve_carrier_migration(
        &self,
        plan: &CarrierMigrationPlan,
    ) -> Result<CarrierMigrationReservation, ObservationProviderError> {
        self.engine.reserve_carrier_migration(plan)
    }

    pub fn prepare_carrier_migration_row(
        &self,
        reservation: &CarrierMigrationReservation,
        owner_intent: &CarrierMigrationPreparedOwnerIntent,
    ) -> Result<CarrierMigrationPreparedIntent, ObservationProviderError> {
        self.engine
            .prepare_carrier_migration_row(reservation, owner_intent)
    }

    pub fn finalize_carrier_migration_row(
        &self,
        prepared: &CarrierMigrationPreparedIntent,
        owner_commit: &CarrierMigrationOwnerCommitReceipt,
    ) -> Result<CarrierMigrationRowFinalizedAck, ObservationProviderError> {
        self.engine
            .finalize_carrier_migration_row(prepared, owner_commit)
    }

    pub fn recover_carrier_migration(
        &self,
        reservation: &CarrierMigrationReservation,
    ) -> Result<CarrierMigrationRecoveryPhase, ObservationProviderError> {
        self.engine.recover_carrier_migration(reservation)
    }

    pub fn verify_carrier_migration_owner_finalized(
        &self,
        reservation: &CarrierMigrationReservation,
        owner_finalized: &CarrierMigrationOwnerFinalizedReceipt,
    ) -> Result<CarrierMigrationFinalizedAck, ObservationProviderError> {
        self.engine
            .verify_carrier_migration_owner_finalized(reservation, owner_finalized)
    }

    pub fn authorize_legacy_migration_completion(
        self,
        migration: &PreparedLegacyRegistryMigration,
        finalized: CarrierMigrationFinalizedAck,
    ) -> Result<VerifiedLegacyMigrationComplete, ObservationProviderError> {
        self.engine
            .authorize_legacy_migration_completion(migration, finalized)
    }
}

impl InstalledCarrierMigrationEngine {
    async fn initialize_or_recover(&self) -> Result<(), ObservationProviderError> {
        let _mutation_guard = self.registry.observation_mutation_lock.lock().await;
        let conn = Arc::clone(&self.registry.conn);
        let db_path = self.registry.database_path().to_path_buf();
        let anchor = Arc::clone(&self.anchor);
        let config = self.config.clone();
        tokio::task::spawn_blocking(move || -> Result<(), ObservationProviderError> {
            let mut conn = conn.blocking_lock();
            activate_observation_component_schema(&conn)?;
            verify_observation_schema_fingerprint(&conn)?;
            let (authenticated_keyring_root, keyring_projection) =
                authenticated_persisted_keyring_projection(
                    &config.authenticated_persisted_keyring_file,
                    config.registry_instance,
                )?;
            let ledger = read_ledger(&conn)?.ok_or_else(|| {
                ObservationProviderError::RecoveryRequired(
                    "Installed carrier coordinator requires an existing durable ledger".to_owned(),
                )
            })?;
            if ledger.registry_instance != config.registry_instance
                || ledger.keyring_root != authenticated_keyring_root
                || ledger.role_allocation_root != config.role_allocation_root
                || ledger.migration_digest != config.migration_digest
            {
                return Err(ObservationProviderError::RecoveryRequired(
                    "carrier coordinator construction roots do not match the durable ledger"
                        .to_owned(),
                ));
            }
            verify_keyring_configuration(&conn, &config, &keyring_projection)?;
            let context = read_head_context(&conn)?;
            match (
                config.migration_installed_marker_root,
                config.migration_marker_root,
            ) {
                (Some(installed), Some(complete))
                    if installed != complete && context.previous_marker_root == installed => {}
                _ => {
                    return Err(ObservationProviderError::RecoveryRequired(
                        "carrier coordinator requires the exact durable Installed marker state"
                            .to_owned(),
                    ))
                }
            }
            if context.manifest_key_epoch != config.registry_manifest_key_epoch {
                return Err(ObservationProviderError::RecoveryRequired(
                    "carrier coordinator manifest epoch does not match durable head context"
                        .to_owned(),
                ));
            }
            reconcile_external_anchor(anchor.as_ref(), &ledger)?;
            verify_complete_roots(&conn, &ledger)?;
            validate_durable_invariants(&conn)?;
            recover_durable_inflight_rows(
                &mut conn,
                &db_path,
                anchor.as_ref(),
                config.registry_instance,
                config.boot,
            )?;
            let recovered = read_ledger(&conn)?.ok_or_else(|| {
                ObservationProviderError::RecoveryRequired(
                    "carrier recovery removed the durable ledger".to_owned(),
                )
            })?;
            let recovered_context = read_head_context(&conn)?;
            if recovered.registry_instance != config.registry_instance
                || recovered.migration_digest != config.migration_digest
                || recovered_context.previous_marker_root
                    != config.migration_installed_marker_root.ok_or_else(|| {
                        ObservationProviderError::RecoveryRequired(
                            "carrier coordinator lost its Installed marker binding".to_owned(),
                        )
                    })?
            {
                return Err(ObservationProviderError::RecoveryRequired(
                    "carrier recovery left the exact Installed world".to_owned(),
                ));
            }
            reconcile_external_anchor(anchor.as_ref(), &recovered)?;
            verify_complete_roots(&conn, &recovered)?;
            validate_durable_invariants(&conn)
        })
        .await
        .map_err(|error| ObservationProviderError::Join(error.to_string()))?
    }

    #[cfg(any(test, feature = "test-support"))]
    fn carrier_migration_test_fixture(
        &self,
        seed: u64,
        planned_row_count: u64,
    ) -> Result<CarrierMigrationTestFixture, ObservationProviderError> {
        if seed == 0 {
            return Err(ObservationProviderError::InvalidInput(
                "carrier-migration fixture seed must be nonzero".to_owned(),
            ));
        }
        Ok(CarrierMigrationTestFixture {
            metadata: Arc::new(carrier_migration_fixture_plan(
                self.config.registry_instance,
                seed,
                planned_row_count,
            )),
        })
    }

    fn reserve_carrier_migration(
        &self,
        plan: &CarrierMigrationPlan,
    ) -> Result<CarrierMigrationReservation, ObservationProviderError> {
        validate_carrier_migration_plan(&self.config, &plan.metadata)?;
        if self.read_carrier_migration_phase(&plan.metadata)?.is_some() {
            return Ok(CarrierMigrationReservation {
                metadata: Arc::clone(&plan.metadata),
            });
        }
        let metadata = Arc::clone(&plan.metadata);
        let discriminator = metadata.migration_id;
        self.anchored_carrier_mutation_sync(&discriminator, move |transaction| {
            reserve_carrier_migration_operation(transaction, &metadata)
        })?;
        Ok(CarrierMigrationReservation {
            metadata: Arc::clone(&plan.metadata),
        })
    }

    fn prepare_carrier_migration_row(
        &self,
        reservation: &CarrierMigrationReservation,
        owner_intent: &CarrierMigrationPreparedOwnerIntent,
    ) -> Result<CarrierMigrationPreparedIntent, ObservationProviderError> {
        if reservation.metadata.as_ref() != owner_intent.plan.as_ref() {
            return Err(ObservationProviderError::InvalidInput(
                "carrier-migration owner intent crosses an opaque reservation".to_owned(),
            ));
        }
        validate_carrier_migration_plan(&self.config, &reservation.metadata)?;
        validate_carrier_migration_row(&owner_intent.row)?;
        if let Some(committed) =
            self.read_carrier_migration_prepared_row(&reservation.metadata, &owner_intent.row)?
        {
            return Ok(CarrierMigrationPreparedIntent {
                plan: Arc::clone(&reservation.metadata),
                row: owner_intent.row.clone(),
                committed,
            });
        }
        let plan = Arc::clone(&reservation.metadata);
        let row = owner_intent.row.clone();
        let discriminator = row.event_key_digest;
        self.anchored_carrier_mutation_sync(&discriminator, move |transaction| {
            prepare_carrier_migration_row_operation(transaction, &plan, &row)
        })?;
        let committed = self
            .read_carrier_migration_prepared_row(&reservation.metadata, &owner_intent.row)?
            .ok_or_else(|| {
                ObservationProviderError::RecoveryRequired(
                    "anchored carrier-migration prepared row cannot be rehydrated".to_owned(),
                )
            })?;
        Ok(CarrierMigrationPreparedIntent {
            plan: Arc::clone(&reservation.metadata),
            row: owner_intent.row.clone(),
            committed,
        })
    }

    fn finalize_carrier_migration_row(
        &self,
        prepared: &CarrierMigrationPreparedIntent,
        owner_commit: &CarrierMigrationOwnerCommitReceipt,
    ) -> Result<CarrierMigrationRowFinalizedAck, ObservationProviderError> {
        if prepared.plan.as_ref() != owner_commit.plan.as_ref()
            || prepared.row != owner_commit.row
            || prepared.committed.sequence != owner_commit.prepared_registry_sequence
            || prepared.committed.head != owner_commit.prepared_registry_head
            || prepared.committed.state_root != owner_commit.prepared_registry_state_root
            || carrier_migration_owner_commit_digest(
                &prepared.plan,
                &prepared.row,
                &prepared.committed,
            ) != owner_commit.receipt_digest
        {
            return Err(ObservationProviderError::InvalidInput(
                "carrier-migration owner commit is not bound to the prepared row".to_owned(),
            ));
        }
        validate_carrier_migration_plan(&self.config, &prepared.plan)?;
        if self.carrier_migration_row_is_finalized(
            &prepared.plan,
            &prepared.row,
            owner_commit.receipt_digest,
        )? {
            return Ok(CarrierMigrationRowFinalizedAck {
                plan: Arc::clone(&prepared.plan),
                row: prepared.row.clone(),
            });
        }
        let plan = Arc::clone(&prepared.plan);
        let row = prepared.row.clone();
        let receipt_digest = owner_commit.receipt_digest;
        let discriminator = row.receipt_nonce;
        self.anchored_carrier_mutation_sync(&discriminator, move |transaction| {
            finalize_carrier_migration_row_operation(transaction, &plan, &row, receipt_digest)
        })?;
        Ok(CarrierMigrationRowFinalizedAck {
            plan: Arc::clone(&prepared.plan),
            row: prepared.row.clone(),
        })
    }

    fn verify_carrier_migration_owner_finalized(
        &self,
        reservation: &CarrierMigrationReservation,
        owner_finalized: &CarrierMigrationOwnerFinalizedReceipt,
    ) -> Result<CarrierMigrationFinalizedAck, ObservationProviderError> {
        if reservation.metadata.as_ref() != owner_finalized.plan.as_ref()
            || owner_finalized.verification_digest
                != carrier_migration_owner_finalized_digest(&reservation.metadata)
        {
            return Err(ObservationProviderError::InvalidInput(
                "carrier-migration owner-finalized receipt crosses its opaque plan".to_owned(),
            ));
        }
        match self.read_carrier_migration_phase(&reservation.metadata)? {
            Some(CarrierMigrationRecoveryPhase::Verified) => {
                return Ok(CarrierMigrationFinalizedAck {
                    metadata: Arc::clone(&reservation.metadata),
                })
            }
            Some(CarrierMigrationRecoveryPhase::Verifying) => {}
            _ => {
                return Err(ObservationProviderError::InvalidState(
                    "carrier migration is not ready for complete owner verification".to_owned(),
                ))
            }
        }
        let metadata = Arc::clone(&reservation.metadata);
        let discriminator = owner_finalized.verification_digest;
        self.anchored_carrier_mutation_sync(&discriminator, move |transaction| {
            verify_carrier_migration_owner_finalized_operation(transaction, &metadata)
        })?;
        Ok(CarrierMigrationFinalizedAck {
            metadata: Arc::clone(&reservation.metadata),
        })
    }

    fn authorize_legacy_migration_completion(
        &self,
        migration: &PreparedLegacyRegistryMigration,
        finalized: CarrierMigrationFinalizedAck,
    ) -> Result<VerifiedLegacyMigrationComplete, ObservationProviderError> {
        if finalized.metadata.migration_id != migration.migration_id()
            || finalized.metadata.registry_instance != migration.registry_instance()
            || self.config.registry_instance != migration.registry_instance()
            || self.config.migration_digest != migration.migration_digest()
        {
            return Err(ObservationProviderError::InvalidInput(
                "carrier-migration completion crosses its authenticated legacy plan".to_owned(),
            ));
        }
        if self.read_carrier_migration_phase(&finalized.metadata)?
            != Some(CarrierMigrationRecoveryPhase::Verified)
        {
            return Err(ObservationProviderError::InvalidState(
                "carrier migration is not durably verified".to_owned(),
            ));
        }
        let conn = self.registry.conn.blocking_lock();
        let ledger = verify_carrier_migration_read_world(self.anchor.as_ref(), &conn)?;
        let context = read_head_context(&conn)?;
        if ledger.registry_instance != migration.registry_instance()
            || ledger.migration_digest != migration.migration_digest()
            || context.previous_marker_root != migration.installed_marker_root()
            || context.manifest_key_epoch != migration.manifest_key_epoch()
        {
            return Err(ObservationProviderError::RecoveryRequired(
                "verified carrier migration is not anchored under the Installed marker".to_owned(),
            ));
        }
        Ok(VerifiedLegacyMigrationComplete {
            plan_binding: migration.plan_binding_digest(),
            registry_instance: migration.registry_instance(),
            migration_id: migration.migration_id(),
        })
    }

    fn recover_carrier_migration(
        &self,
        reservation: &CarrierMigrationReservation,
    ) -> Result<CarrierMigrationRecoveryPhase, ObservationProviderError> {
        self.read_carrier_migration_phase(&reservation.metadata)?
            .ok_or_else(|| {
                ObservationProviderError::InvalidState(
                    "carrier-migration reservation is not durable".to_owned(),
                )
            })
    }

    fn read_carrier_migration_phase(
        &self,
        metadata: &CarrierMigrationPlanMetadata,
    ) -> Result<Option<CarrierMigrationRecoveryPhase>, ObservationProviderError> {
        self.require_ready()?;
        let _mutation_guard = self
            .registry
            .observation_mutation_lock
            .try_lock()
            .map_err(|_| ObservationProviderError::Busy)?;
        let conn = self
            .registry
            .conn
            .try_lock()
            .map_err(|_| ObservationProviderError::Busy)?;
        verify_carrier_migration_read_world(self.anchor.as_ref(), &conn)?;
        read_carrier_migration_phase_exact(&conn, metadata)
    }

    fn read_carrier_migration_prepared_row(
        &self,
        metadata: &CarrierMigrationPlanMetadata,
        row: &CarrierMigrationRowMetadata,
    ) -> Result<Option<RegistryAnchorTuple>, ObservationProviderError> {
        self.require_ready()?;
        let _mutation_guard = self
            .registry
            .observation_mutation_lock
            .try_lock()
            .map_err(|_| ObservationProviderError::Busy)?;
        let conn = self
            .registry
            .conn
            .try_lock()
            .map_err(|_| ObservationProviderError::Busy)?;
        let ledger = verify_carrier_migration_read_world(self.anchor.as_ref(), &conn)?;
        if carrier_migration_prepared_row_matches(&conn, metadata, row)? {
            Ok(Some(ledger))
        } else {
            Ok(None)
        }
    }

    fn carrier_migration_row_is_finalized(
        &self,
        metadata: &CarrierMigrationPlanMetadata,
        row: &CarrierMigrationRowMetadata,
        receipt_digest: [u8; 32],
    ) -> Result<bool, ObservationProviderError> {
        self.require_ready()?;
        let _mutation_guard = self
            .registry
            .observation_mutation_lock
            .try_lock()
            .map_err(|_| ObservationProviderError::Busy)?;
        let conn = self
            .registry
            .conn
            .try_lock()
            .map_err(|_| ObservationProviderError::Busy)?;
        verify_carrier_migration_read_world(self.anchor.as_ref(), &conn)?;
        carrier_migration_finalized_row_matches(&conn, metadata, row, receipt_digest)
    }

    fn require_ready(&self) -> Result<(), ObservationProviderError> {
        if self.ready.load(Ordering::Acquire) {
            Ok(())
        } else {
            Err(ObservationProviderError::RecoveryRequired(
                "Installed carrier coordinator is not ready".to_owned(),
            ))
        }
    }

    fn anchored_carrier_mutation_sync<T, F>(
        &self,
        write_discriminator: &[u8],
        mutation: F,
    ) -> Result<T, ObservationProviderError>
    where
        F: FnOnce(&Transaction<'_>) -> Result<T, ObservationProviderError>,
    {
        self.require_ready()?;
        let _mutation_guard = self
            .registry
            .observation_mutation_lock
            .try_lock()
            .map_err(|_| ObservationProviderError::Busy)?;
        let mut conn = self
            .registry
            .conn
            .try_lock()
            .map_err(|_| ObservationProviderError::Busy)?;
        let result = run_anchored_mutation_on_connection(
            &mut conn,
            self.registry.database_path(),
            self.anchor.as_ref(),
            6,
            write_discriminator,
            #[cfg(any(test, feature = "test-support"))]
            Some(self.test_controls.as_ref()),
            mutation,
        );
        if let Err(error) = &result {
            if error.gates_provider() {
                self.ready.store(false, Ordering::Release);
            }
        }
        result
    }
}

impl Drop for InstalledCarrierMigrationEngine {
    fn drop(&mut self) {
        self.ready.store(false, Ordering::Release);
        self.registry.release_observation_provider();
    }
}

impl RegistrySensitiveParamProvider {
    /// Perform the one authenticated stopped migration for an exact nonempty
    /// nine-column legacy component registry.  Runtime/workspace exclusivity
    /// is supplied by the composition root; this method additionally holds
    /// the registry mutation lock, independently rehashes the source
    /// projection and file inventory, installs the exact target/backfill, and
    /// initializes or forward-recovers the migrated external anchor before a
    /// normal provider open is allowed.
    pub async fn migrate_legacy_registry(
        registry: Arc<ComponentRegistry>,
        anchor: Arc<dyn RegistryAnchorTransaction>,
        config: ObservationProviderConfig,
        migration: PreparedLegacyRegistryMigration,
    ) -> Result<VerifiedLegacyAnchorInstalled, ObservationProviderError> {
        config.validate()?;
        if config.migration_installed_marker_root != Some(migration.installed_marker_root())
            || config.migration_marker_root != Some(migration.complete_marker_root())
            || config.registry_instance != migration.registry_instance()
            || config.migration_digest != migration.migration_digest()
            || config.role_allocation_root != migration.target_role_allocation_root()
        {
            return Err(ObservationProviderError::InvalidInput(
                "provider migration config does not match authenticated migration artifacts"
                    .to_owned(),
            ));
        }
        let _mutation_guard = registry.observation_mutation_lock.lock().await;
        let conn = Arc::clone(&registry.conn);
        let db_path = registry.database_path().to_path_buf();
        tokio::task::spawn_blocking(move || {
            let mut conn = conn.blocking_lock();
            install_or_recover_legacy_migration(
                &mut conn,
                &db_path,
                anchor.as_ref(),
                &config,
                migration,
            )
        })
        .await
        .map_err(|error| ObservationProviderError::Join(error.to_string()))?
    }

    /// Commit one witness-derived legacy marker transition.  The opaque
    /// preparation is borrowed so an acknowledgement lost after the durable
    /// commit can be recovered by replaying the exact same staged plan.
    pub async fn commit_legacy_marker_transition(
        registry: Arc<ComponentRegistry>,
        anchor: Arc<dyn RegistryAnchorTransaction>,
        prepared: &PreparedLegacyMarkerMutation,
    ) -> Result<VerifiedLegacyMarkerTransitionCommitted, ObservationProviderError> {
        let registry_identity = Arc::as_ptr(&registry) as usize;
        let _mutation_guard = registry.observation_mutation_lock.lock().await;
        let mut conn = registry.conn.lock().await;
        commit_legacy_marker_transition_on_connection(
            &mut conn,
            registry.database_path(),
            anchor.as_ref(),
            prepared,
            registry_identity,
        )
    }

    pub async fn recover_legacy_installed_marker_transition(
        registry: Arc<ComponentRegistry>,
        anchor: Arc<dyn RegistryAnchorTransaction>,
        migration: &PreparedLegacyRegistryMigration,
    ) -> Result<VerifiedLegacyMarkerTransitionCommitted, ObservationProviderError> {
        let registry_identity = Arc::as_ptr(&registry) as usize;
        let _mutation_guard = registry.observation_mutation_lock.lock().await;
        let mut conn = registry.conn.lock().await;
        recover_committed_legacy_marker_transition_on_connection(
            &mut conn,
            anchor.as_ref(),
            migration,
            2,
            registry_identity,
        )
    }

    pub async fn recover_legacy_complete_marker_transition(
        registry: Arc<ComponentRegistry>,
        anchor: Arc<dyn RegistryAnchorTransaction>,
        migration: &PreparedLegacyRegistryMigration,
    ) -> Result<VerifiedLegacyMarkerTransitionCommitted, ObservationProviderError> {
        let registry_identity = Arc::as_ptr(&registry) as usize;
        let _mutation_guard = registry.observation_mutation_lock.lock().await;
        let mut conn = registry.conn.lock().await;
        recover_committed_legacy_marker_transition_on_connection(
            &mut conn,
            anchor.as_ref(),
            migration,
            3,
            registry_identity,
        )
    }

    /// Open/recover the anchored provider and hydrate the sole view before
    /// returning.  A nonempty legacy registry without its authenticated
    /// migration marker is recovery-required; this foundation never
    /// re-baselines it as greenfield.
    pub async fn open(
        registry: Arc<ComponentRegistry>,
        anchor: Arc<dyn RegistryAnchorTransaction>,
        config: ObservationProviderConfig,
        verifier: PrevisibleProofVerifierRole,
        persisted_keyring: PersistedIdentityKeyringRole,
        persisted_keyring_custody: Arc<dyn PersistedKeyringCustody>,
        termination_state: TerminationStateMachineRole,
        cleanup_verifier: TerminationCleanupReceiptVerifierRole,
    ) -> Result<Arc<Self>, ObservationProviderError> {
        config.validate()?;
        verifier.verify_provider_binding(config.registry_instance, config.boot)?;
        let (keyring_root, _) = authenticated_persisted_keyring_projection(
            &config.authenticated_persisted_keyring_file,
            config.registry_instance,
        )?;
        let custody_file =
            persisted_keyring_custody.authenticated_current_file(config.registry_instance)?;
        if custody_file != config.authenticated_persisted_keyring_file {
            return Err(ObservationProviderError::RecoveryRequired(
                "provider keyring custody does not retain the authenticated construction file"
                    .to_owned(),
            ));
        }
        persisted_keyring.verify_provider_binding(config.registry_instance, keyring_root)?;
        termination_state.verify_provider_binding(config.registry_instance, config.boot)?;
        cleanup_verifier.verify_provider_binding(config.registry_instance, config.boot)?;

        let mut claim = ObservationProviderClaimGuard::acquire(Arc::clone(&registry))?;
        Self::initialize_or_recover_normal_provider(
            Arc::clone(&registry),
            Arc::clone(&anchor),
            config.clone(),
        )
        .await?;
        let (revision_tx, _) = watch::channel(0);
        let provider = Arc::new(Self {
            registry,
            anchor,
            config,
            verifier,
            persisted_keyring: Mutex::new(Some(persisted_keyring)),
            persisted_keyring_custody,
            termination_state,
            cleanup_verifier,
            view: RwLock::new(BTreeMap::new()),
            revision: AtomicU64::new(0),
            revision_tx,
            ready: AtomicBool::new(false),
            #[cfg(any(test, feature = "test-support"))]
            test_controls: Arc::new(ObservationMutationTestControls::default()),
        });
        claim.transfer_to_provider();
        if let Err(error) = provider.reload_view().await {
            provider.ready.store(false, Ordering::Release);
            return Err(error);
        }
        provider.ready.store(true, Ordering::Release);
        Ok(provider)
    }

    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }

    #[cfg(feature = "test-support")]
    pub fn registry(&self) -> &Arc<ComponentRegistry> {
        &self.registry
    }

    /// Arm one closed schema mutation inside the next matching greenfield
    /// transaction. The injected DDL is fixed and rolls back with the failed
    /// transaction; callers cannot supply SQL or target an existing ledger.
    #[cfg(any(test, feature = "test-support"))]
    pub fn inject_next_greenfield_schema_adversary(
        registry_instance: [u8; 16],
        stage: GreenfieldSchemaAdversaryStage,
    ) -> Result<(), ObservationProviderError> {
        if registry_instance == [0; 16] {
            return Err(ObservationProviderError::InvalidInput(
                "greenfield schema adversary requires a nonzero registry instance".to_owned(),
            ));
        }
        let slot = GREENFIELD_SCHEMA_ADVERSARY.get_or_init(|| Mutex::new(None));
        let mut armed = slot.lock().map_err(|_| {
            ObservationProviderError::RecoveryRequired(
                "greenfield schema adversary fixture lock is poisoned".to_owned(),
            )
        })?;
        if armed.is_some() {
            return Err(ObservationProviderError::Busy);
        }
        *armed = Some((registry_instance, stage));
        Ok(())
    }

    /// Arm a fixed, rollback-only DDL mutation inside the next exact marker
    /// retry's `BEGIN IMMEDIATE` boundary. The process-local registry identity
    /// prevents parallel fixtures that share a durable registry ID from
    /// consuming one another's adversary. No caller supplies SQL.
    #[cfg(any(test, feature = "test-support"))]
    pub fn inject_next_marker_retry_schema_adversary(
        registry: &Arc<ComponentRegistry>,
        registry_instance: [u8; 16],
    ) -> Result<(), ObservationProviderError> {
        if registry_instance == [0; 16] {
            return Err(ObservationProviderError::InvalidInput(
                "marker retry schema adversary requires a nonzero registry instance".to_owned(),
            ));
        }
        let slot = MARKER_RETRY_SCHEMA_ADVERSARY.get_or_init(|| Mutex::new(None));
        let mut armed = slot.lock().map_err(|_| {
            ObservationProviderError::RecoveryRequired(
                "marker retry schema adversary fixture lock is poisoned".to_owned(),
            )
        })?;
        if armed.is_some() {
            return Err(ObservationProviderError::Busy);
        }
        *armed = Some((registry_instance, Arc::as_ptr(registry) as usize));
        Ok(())
    }

    /// Arm one closed crash boundary for the next anchored mutation.  The
    /// stage is consumed exactly once.  This fixture exists only in
    /// test-support builds and carries no row, digest, SQL, or anchor payload.
    #[cfg(any(test, feature = "test-support"))]
    pub fn inject_next_observation_mutation_failpoint(
        &self,
        stage: ObservationMutationFailpointStage,
    ) -> Result<(), ObservationProviderError> {
        if !self.is_ready() {
            return Err(ObservationProviderError::RecoveryRequired(
                "provider is not ready".to_owned(),
            ));
        }
        let mut armed = self.test_controls.next_failpoint.lock().map_err(|_| {
            ObservationProviderError::RecoveryRequired(
                "observation mutation failpoint fixture lock is poisoned".to_owned(),
            )
        })?;
        if armed.is_some() {
            return Err(ObservationProviderError::Busy);
        }
        *armed = Some(stage);
        Ok(())
    }

    /// Narrow the effective combined-byte cap for the next termination
    /// prepare to one byte below, exactly at, or one byte above its complete
    /// terminal reservation.  Durable counters are read and left untouched.
    #[cfg(any(test, feature = "test-support"))]
    pub fn seed_next_termination_finalize_capacity_boundary(
        &self,
        boundary: TerminationFinalizeCapacityBoundary,
    ) -> Result<(), ObservationProviderError> {
        if !self.is_ready() {
            return Err(ObservationProviderError::RecoveryRequired(
                "provider is not ready".to_owned(),
            ));
        }
        let _mutation_guard = self
            .registry
            .observation_mutation_lock
            .try_lock()
            .map_err(|_| ObservationProviderError::Busy)?;
        let conn = self
            .registry
            .conn
            .try_lock()
            .map_err(|_| ObservationProviderError::Busy)?;
        let (actual, future): (i64, i64) = conn.query_row(
            "SELECT actual_encoded_bytes,future_reserved_bytes
             FROM observation_termination_finalize_capacity WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let used = actual.checked_add(future).ok_or_else(|| {
            ObservationProviderError::RecoveryRequired(
                "termination finalization capacity fixture overflow".to_owned(),
            )
        })?;
        let adjustment = match boundary {
            TerminationFinalizeCapacityBoundary::CapMinusOne => -1,
            TerminationFinalizeCapacityBoundary::AtCap => 0,
            TerminationFinalizeCapacityBoundary::CapPlusOne => 1,
        };
        let effective = used
            .checked_add(TERMINATION_FINALIZE_TOTAL_BYTES)
            .and_then(|value| value.checked_add(adjustment))
            .filter(|value| *value > 0 && *value <= MAX_TERMINATION_FINALIZE_COMBINED_BYTES)
            .ok_or_else(|| {
                ObservationProviderError::InvalidState(
                    "requested termination finalization boundary is outside the real cap"
                        .to_owned(),
                )
            })?;
        self.test_controls
            .next_termination_finalize_limit
            .store(effective as u64, Ordering::Release);
        Ok(())
    }

    #[cfg(any(test, feature = "test-support"))]
    fn take_termination_finalize_capacity_limit(&self) -> i64 {
        self.test_controls.take_termination_finalize_limit()
    }

    #[cfg(not(any(test, feature = "test-support")))]
    fn take_termination_finalize_capacity_limit(&self) -> i64 {
        MAX_TERMINATION_FINALIZE_COMBINED_BYTES
    }

    /// Narrow tag-1/tag-2 admission around the real durable counters while
    /// leaving either one row slot or one complete 4096-byte reservation.
    /// Subsequent calls still execute the ordinary anchored mutations.
    #[cfg(any(test, feature = "test-support"))]
    pub fn seed_previsible_admission_capacity_boundary(
        &self,
        boundary: PrevisibleAdmissionCapacityBoundary,
    ) -> Result<(), ObservationProviderError> {
        if !self.is_ready() {
            return Err(ObservationProviderError::RecoveryRequired(
                "provider is not ready".to_owned(),
            ));
        }
        let _mutation_guard = self
            .registry
            .observation_mutation_lock
            .try_lock()
            .map_err(|_| ObservationProviderError::Busy)?;
        let conn = self
            .registry
            .conn
            .try_lock()
            .map_err(|_| ObservationProviderError::Busy)?;
        let (rows, actual, future): (i64, i64, i64) = conn.query_row(
            "SELECT row_count,actual_encoded_bytes,future_reserved_bytes
             FROM observation_previsible_capacity WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        let combined = actual.checked_add(future).ok_or_else(|| {
            ObservationProviderError::RecoveryRequired(
                "previsible capacity fixture overflow".to_owned(),
            )
        })?;
        let (row_delta, byte_delta) = match boundary {
            PrevisibleAdmissionCapacityBoundary::OneRowRemaining => (1, PREVISIBLE_TOTAL_BYTES * 2),
            PrevisibleAdmissionCapacityBoundary::OneReservationRemaining => {
                (2, PREVISIBLE_TOTAL_BYTES)
            }
        };
        let limits = PrevisibleCapacityLimits {
            rows: rows
                .checked_add(row_delta)
                .filter(|value| *value <= MAX_PREVISIBLE_ROWS)
                .ok_or_else(|| {
                    ObservationProviderError::InvalidState(
                        "requested previsible row boundary exceeds the production cap".to_owned(),
                    )
                })?,
            combined_bytes: combined
                .checked_add(byte_delta)
                .filter(|value| *value <= MAX_PREVISIBLE_COMBINED_BYTES)
                .ok_or_else(|| {
                    ObservationProviderError::InvalidState(
                        "requested previsible byte boundary exceeds the production cap".to_owned(),
                    )
                })?,
        };
        *self.test_controls.previsible_limits.lock().map_err(|_| {
            ObservationProviderError::RecoveryRequired(
                "previsible capacity fixture lock is poisoned".to_owned(),
            )
        })? = limits;
        Ok(())
    }

    #[cfg(any(test, feature = "test-support"))]
    fn previsible_capacity_limits(
        &self,
    ) -> Result<PrevisibleCapacityLimits, ObservationProviderError> {
        self.test_controls
            .previsible_limits
            .lock()
            .map(|limits| *limits)
            .map_err(|_| {
                ObservationProviderError::RecoveryRequired(
                    "previsible capacity fixture lock is poisoned".to_owned(),
                )
            })
    }

    #[cfg(not(any(test, feature = "test-support")))]
    fn previsible_capacity_limits(
        &self,
    ) -> Result<PrevisibleCapacityLimits, ObservationProviderError> {
        Ok(PrevisibleCapacityLimits::default())
    }

    /// Set the next tag-7 effective limits to the exact durable combined-byte
    /// usage. A checkpoint can therefore succeed only by moving its reserved
    /// eight bytes from future to actual accounting without increasing total
    /// usage.
    #[cfg(any(test, feature = "test-support"))]
    pub fn seed_audit_checkpoint_capacity_at_current_usage(
        &self,
    ) -> Result<(), ObservationProviderError> {
        if !self.is_ready() {
            return Err(ObservationProviderError::RecoveryRequired(
                "provider is not ready".to_owned(),
            ));
        }
        let _mutation_guard = self
            .registry
            .observation_mutation_lock
            .try_lock()
            .map_err(|_| ObservationProviderError::Busy)?;
        let conn = self
            .registry
            .conn
            .try_lock()
            .map_err(|_| ObservationProviderError::Busy)?;
        let (previsible_actual, previsible_future): (i64, i64) = conn.query_row(
            "SELECT actual_encoded_bytes,future_reserved_bytes
             FROM observation_previsible_capacity WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let (finalization_actual, finalization_future): (i64, i64) = conn.query_row(
            "SELECT actual_encoded_bytes,future_reserved_bytes
             FROM observation_termination_finalize_capacity WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let limits = AuditCheckpointCapacityLimits {
            previsible_combined_bytes: previsible_actual
                .checked_add(previsible_future)
                .ok_or_else(|| {
                    ObservationProviderError::RecoveryRequired(
                        "previsible checkpoint capacity fixture overflow".to_owned(),
                    )
                })?,
            finalization_combined_bytes: finalization_actual
                .checked_add(finalization_future)
                .ok_or_else(|| {
                    ObservationProviderError::RecoveryRequired(
                        "finalization checkpoint capacity fixture overflow".to_owned(),
                    )
                })?,
        };
        *self.test_controls.checkpoint_limits.lock().map_err(|_| {
            ObservationProviderError::RecoveryRequired(
                "audit checkpoint capacity fixture lock is poisoned".to_owned(),
            )
        })? = limits;
        Ok(())
    }

    #[cfg(any(test, feature = "test-support"))]
    fn audit_checkpoint_capacity_limits(
        &self,
    ) -> Result<AuditCheckpointCapacityLimits, ObservationProviderError> {
        self.test_controls
            .checkpoint_limits
            .lock()
            .map(|limits| *limits)
            .map_err(|_| {
                ObservationProviderError::RecoveryRequired(
                    "audit checkpoint capacity fixture lock is poisoned".to_owned(),
                )
            })
    }

    #[cfg(not(any(test, feature = "test-support")))]
    fn audit_checkpoint_capacity_limits(
        &self,
    ) -> Result<AuditCheckpointCapacityLimits, ObservationProviderError> {
        Ok(AuditCheckpointCapacityLimits::default())
    }

    /// Read the canonical capacity singletons without exposing a write seam.
    #[cfg(any(test, feature = "test-support"))]
    pub fn observation_capacity_test_fixture(
        &self,
    ) -> Result<ObservationCapacitySnapshot, ObservationProviderError> {
        if !self.is_ready() {
            return Err(ObservationProviderError::RecoveryRequired(
                "provider is not ready".to_owned(),
            ));
        }
        let _mutation_guard = self
            .registry
            .observation_mutation_lock
            .try_lock()
            .map_err(|_| ObservationProviderError::Busy)?;
        let conn = self
            .registry
            .conn
            .try_lock()
            .map_err(|_| ObservationProviderError::Busy)?;
        let previsible: (i64, i64, i64) = conn.query_row(
            "SELECT row_count,actual_encoded_bytes,future_reserved_bytes
             FROM observation_previsible_capacity WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        let finalization: (i64, i64, i64) = conn.query_row(
            "SELECT row_count,actual_encoded_bytes,future_reserved_bytes
             FROM observation_termination_finalize_capacity WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        Ok(ObservationCapacitySnapshot {
            previsible_rows: sqlite_u64(previsible.0, "previsible capacity rows")?,
            previsible_actual_bytes: sqlite_u64(previsible.1, "previsible capacity actual")?,
            previsible_future_bytes: sqlite_u64(previsible.2, "previsible capacity future")?,
            finalization_rows: sqlite_u64(finalization.0, "finalization capacity rows")?,
            finalization_actual_bytes: sqlite_u64(finalization.1, "finalization capacity actual")?,
            finalization_future_bytes: sqlite_u64(finalization.2, "finalization capacity future")?,
        })
    }

    /// Fixture-only proof that termination does not consume identity or
    /// authority capacity. The configured limits equal the current durable
    /// counts and remain narrowed for subsequent operations in this provider.
    #[cfg(any(test, feature = "test-support"))]
    pub fn seed_identity_and_authority_at_capacity(&self) -> Result<(), ObservationProviderError> {
        let (identities, authorities, _, _, _) = self.admission_capacity_counts()?;
        let mut limits = self.test_controls.admission_limits.lock().map_err(|_| {
            ObservationProviderError::RecoveryRequired(
                "admission-capacity fixture lock is poisoned".to_owned(),
            )
        })?;
        limits.identities = identities;
        limits.authorities = authorities;
        Ok(())
    }

    /// Fixture-only authority ceiling used to prove that an existing textual
    /// id can advance its incarnation without allocating another authority.
    #[cfg(any(test, feature = "test-support"))]
    pub fn seed_authority_at_capacity(&self) -> Result<(), ObservationProviderError> {
        let (_, authorities, _, _, _) = self.admission_capacity_counts()?;
        self.test_controls
            .admission_limits
            .lock()
            .map_err(|_| {
                ObservationProviderError::RecoveryRequired(
                    "admission-capacity fixture lock is poisoned".to_owned(),
                )
            })?
            .authorities = authorities;
        Ok(())
    }

    /// Fixture-only active-operation ceiling. Host registration has zero
    /// active-operation delta and therefore remains available at this bound.
    #[cfg(any(test, feature = "test-support"))]
    pub fn seed_active_operation_at_capacity(&self) -> Result<(), ObservationProviderError> {
        let (_, _, active, _, _) = self.admission_capacity_counts()?;
        self.test_controls
            .admission_limits
            .lock()
            .map_err(|_| {
                ObservationProviderError::RecoveryRequired(
                    "admission-capacity fixture lock is poisoned".to_owned(),
                )
            })?
            .active_operations = active;
        Ok(())
    }

    /// Fixture-only bounded committed-history ceiling. It changes no row and
    /// exposes no production configuration seam; callers can fill exactly
    /// `additional_rows` operation/member slots and prove the next rejection.
    #[cfg(any(test, feature = "test-support"))]
    pub fn seed_committed_history_capacity_remaining(
        &self,
        additional_rows: u64,
    ) -> Result<(), ObservationProviderError> {
        let (_, _, _, operations, members) = self.admission_capacity_counts()?;
        let operation_limit = operations.checked_add(additional_rows).ok_or_else(|| {
            ObservationProviderError::InvalidInput(
                "committed-operation fixture capacity overflow".to_owned(),
            )
        })?;
        let member_limit = members.checked_add(additional_rows).ok_or_else(|| {
            ObservationProviderError::InvalidInput(
                "committed-member fixture capacity overflow".to_owned(),
            )
        })?;
        if operation_limit > MAX_COMMITTED_IDENTITY_OPERATIONS
            || member_limit > MAX_COMMITTED_IDENTITY_MEMBERS
        {
            return Err(ObservationProviderError::InvalidInput(
                "committed-history fixture exceeds the production ceiling".to_owned(),
            ));
        }
        let mut limits = self.test_controls.admission_limits.lock().map_err(|_| {
            ObservationProviderError::RecoveryRequired(
                "admission-capacity fixture lock is poisoned".to_owned(),
            )
        })?;
        limits.operations = operation_limit;
        limits.members = member_limit;
        Ok(())
    }

    #[cfg(any(test, feature = "test-support"))]
    fn admission_capacity_counts(
        &self,
    ) -> Result<(u64, u64, u64, u64, u64), ObservationProviderError> {
        if !self.is_ready() {
            return Err(ObservationProviderError::RecoveryRequired(
                "provider is not ready".to_owned(),
            ));
        }
        let _mutation_guard = self
            .registry
            .observation_mutation_lock
            .try_lock()
            .map_err(|_| ObservationProviderError::Busy)?;
        let conn = self
            .registry
            .conn
            .try_lock()
            .map_err(|_| ObservationProviderError::Busy)?;
        let counts: (i64, i64, i64, i64, i64) = conn.query_row(
            "SELECT
                (SELECT COUNT(*) FROM observation_identities),
                (SELECT COUNT(*) FROM observation_identity_authority),
                (SELECT COUNT(*) FROM observation_identity_operations WHERE is_active=1),
                (SELECT COUNT(*) FROM observation_identity_operations),
                (SELECT COUNT(*) FROM observation_identity_operation_members)",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )?;
        Ok((
            sqlite_u64(counts.0, "fixture identity count")?,
            sqlite_u64(counts.1, "fixture authority count")?,
            sqlite_u64(counts.2, "fixture active-operation count")?,
            sqlite_u64(counts.3, "fixture committed-operation count")?,
            sqlite_u64(counts.4, "fixture committed-member count")?,
        ))
    }

    #[cfg(any(test, feature = "test-support"))]
    fn admission_capacity_limits(
        &self,
    ) -> Result<AdmissionCapacityLimits, ObservationProviderError> {
        self.test_controls
            .admission_limits
            .lock()
            .map(|limits| *limits)
            .map_err(|_| {
                ObservationProviderError::RecoveryRequired(
                    "admission-capacity fixture lock is poisoned".to_owned(),
                )
            })
    }

    #[cfg(not(any(test, feature = "test-support")))]
    fn admission_capacity_limits(
        &self,
    ) -> Result<AdmissionCapacityLimits, ObservationProviderError> {
        Ok(AdmissionCapacityLimits::default())
    }

    /// Build an opaque, provider-bound stand-in for an externally verified
    /// audit checkpoint. This mint exists only with test-support enabled.
    #[cfg(any(test, feature = "test-support"))]
    pub fn audit_checkpoint_test_fixture(
        &self,
        verified_at_ms: u64,
    ) -> Result<AuthenticatedAuditCheckpointWitness, ObservationProviderError> {
        if verified_at_ms == 0 || verified_at_ms > i64::MAX as u64 {
            return Err(ObservationProviderError::InvalidInput(
                "audit checkpoint fixture time is outside canonical range".to_owned(),
            ));
        }
        let _mutation_guard = self
            .registry
            .observation_mutation_lock
            .try_lock()
            .map_err(|_| ObservationProviderError::Busy)?;
        let conn = self
            .registry
            .conn
            .try_lock()
            .map_err(|_| ObservationProviderError::Busy)?;
        let ledger = read_ledger(&conn)?.ok_or_else(|| {
            ObservationProviderError::RecoveryRequired("missing identity ledger".to_owned())
        })?;
        if ledger.sequence == 0 {
            return Err(ObservationProviderError::InvalidState(
                "audit checkpoint fixture requires a committed mutation".to_owned(),
            ));
        }
        Ok(authenticated_audit_checkpoint_witness(
            ledger.registry_instance,
            ledger.sequence,
            ledger.sequence,
            verified_at_ms,
        ))
    }

    /// Install an authenticated audit checkpoint, or on a later invocation
    /// compact the oldest whole eligible operation prefix. The witness is
    /// opaque and move-only; no raw sequence/time overload exists.
    pub fn compact_checkpointed_terminal_prefix(
        &self,
        witness: AuthenticatedAuditCheckpointWitness,
    ) -> Result<AuditCompactionOutcome, ObservationProviderError> {
        verify_audit_checkpoint_witness(&witness, self.config.registry_instance)?;
        let discriminator = witness.commitment;
        let capacity_limits = self.audit_checkpoint_capacity_limits()?;
        self.anchored_mutation_sync(7, &discriminator, move |transaction| {
            apply_audit_checkpoint_or_compaction(transaction, &witness, capacity_limits)
        })
    }

    /// Execute one closed malformed write and require the ordinary anchored
    /// operation-effect validator to reject it before commit.
    #[cfg(any(test, feature = "test-support"))]
    pub fn operation_effect_adversary_test_fixture(
        &self,
        operation_id: &str,
        adversary: OperationEffectAdversary,
    ) -> Result<(), ObservationProviderError> {
        validate_operation_id(operation_id)?;
        let operation_id = operation_id.to_owned();
        let (tag, discriminator) = match adversary {
            OperationEffectAdversary::NonGcTagChangesGcFields => (3, [0x73; 32]),
            OperationEffectAdversary::GcTagSkipsFirstGeneration => (8, [0x78; 32]),
            OperationEffectAdversary::CompactionTagChangesNonCheckpointField => (7, [0x77; 32]),
        };
        self.anchored_mutation_sync(tag, &discriminator, move |transaction| {
            let changed = match adversary {
                OperationEffectAdversary::NonGcTagChangesGcFields
                | OperationEffectAdversary::GcTagSkipsFirstGeneration => {
                    let generation = if matches!(
                        adversary,
                        OperationEffectAdversary::GcTagSkipsFirstGeneration
                    ) {
                        2_i64
                    } else {
                        1_i64
                    };
                    transaction.execute(
                        "UPDATE observation_identity_operation_members
                         SET gc_phase='prepared',gc_generation=?1,
                             gc_registry_sequence=?2,gc_challenge_nonce=?3,
                             gc_tombstone_state_root=?4,gc_operation_boot=?5
                         WHERE operation_id=?6 AND gc_phase='idle'",
                        params![
                            generation,
                            next_registry_sequence(transaction)? as i64,
                            [0x31_u8; 32].as_slice(),
                            [0x32_u8; 32].as_slice(),
                            [0x33_u8; 16].as_slice(),
                            operation_id,
                        ],
                    )?
                }
                OperationEffectAdversary::CompactionTagChangesNonCheckpointField => transaction
                    .execute(
                        "UPDATE observation_previsible_activations
                         SET updated_sequence=updated_sequence+1
                         WHERE operation_id=?1 AND phase IN ('published','aborted')",
                        params![operation_id],
                    )?,
            };
            if changed != 1 {
                return Err(ObservationProviderError::InvalidState(
                    "operation-effect adversary did not select one exact row".to_owned(),
                ));
            }
            Ok(())
        })
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn operation_history_test_fixture(
        &self,
        operation_id: &str,
    ) -> Result<bool, ObservationProviderError> {
        validate_operation_id(operation_id)?;
        if !self.is_ready() {
            return Err(ObservationProviderError::RecoveryRequired(
                "provider is not ready".to_owned(),
            ));
        }
        let _mutation_guard = self
            .registry
            .observation_mutation_lock
            .try_lock()
            .map_err(|_| ObservationProviderError::Busy)?;
        let conn = self
            .registry
            .conn
            .try_lock()
            .map_err(|_| ObservationProviderError::Busy)?;
        validate_durable_invariants(&conn)?;
        conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM observation_identity_operations
                           WHERE operation_id=?1)",
            params![operation_id],
            |row| row.get(0),
        )
        .map_err(ObservationProviderError::from)
    }

    pub async fn current_anchor_tuple(
        &self,
    ) -> Result<RegistryAnchorTuple, ObservationProviderError> {
        if !self.is_ready() {
            return Err(ObservationProviderError::RecoveryRequired(
                "provider is not ready".to_owned(),
            ));
        }
        let _mutation_guard = self.registry.observation_mutation_lock.lock().await;
        let conn = Arc::clone(&self.registry.conn);
        let anchor = Arc::clone(&self.anchor);
        let result = tokio::task::spawn_blocking(
            move || -> Result<RegistryAnchorTuple, ObservationProviderError> {
                let conn = conn.blocking_lock();
                let ledger = read_ledger(&conn)?.ok_or_else(|| {
                    ObservationProviderError::RecoveryRequired("missing identity ledger".to_owned())
                })?;
                reconcile_external_anchor(anchor.as_ref(), &ledger)?;
                verify_complete_roots(&conn, &ledger)?;
                validate_durable_invariants(&conn)?;
                Ok(ledger)
            },
        )
        .await
        .map_err(|error| ObservationProviderError::Join(error.to_string()))?;
        if let Err(error) = &result {
            if error.gates_provider() {
                self.ready.store(false, Ordering::Release);
            }
        }
        result
    }

    /// Read the authenticated current marker/root epoch needed to prepare a
    /// role-allocation replacement.  Commit re-reads this singleton under the
    /// same global mutation lock, so this read-only snapshot is never itself
    /// an authorization and a stale snapshot fails closed.
    pub async fn role_allocation_head_context(
        &self,
    ) -> Result<RegistryHeadContext, ObservationProviderError> {
        if !self.is_ready() {
            return Err(ObservationProviderError::RecoveryRequired(
                "provider is not ready".to_owned(),
            ));
        }
        let _mutation_guard = self.registry.observation_mutation_lock.lock().await;
        let conn = Arc::clone(&self.registry.conn);
        let anchor = Arc::clone(&self.anchor);
        let result = tokio::task::spawn_blocking(
            move || -> Result<RegistryHeadContext, ObservationProviderError> {
                let conn = conn.blocking_lock();
                let ledger = read_ledger(&conn)?.ok_or_else(|| {
                    ObservationProviderError::RecoveryRequired("missing identity ledger".to_owned())
                })?;
                reconcile_external_anchor(anchor.as_ref(), &ledger)?;
                verify_complete_roots(&conn, &ledger)?;
                validate_durable_invariants(&conn)?;
                read_head_context(&conn)
            },
        )
        .await
        .map_err(|error| ObservationProviderError::Join(error.to_string()))?;
        if let Err(error) = &result {
            if error.gates_provider() {
                self.ready.store(false, Ordering::Release);
            }
        }
        result
    }

    /// Read the exact current marker/manifest-epoch context used to prepare
    /// an authenticated persisted-keyring file replacement.  Commit performs
    /// the authoritative re-read under the global mutation lock.
    pub async fn persisted_keyring_head_context(
        &self,
    ) -> Result<RegistryHeadContext, ObservationProviderError> {
        self.role_allocation_head_context().await
    }

    /// Rotate the persisted-identity signing entry through one complete
    /// custody-prepared file replacement.  The old Signing entry becomes
    /// VerifyOnly, the external file is promoted only after SQLite/anchor
    /// commit, and the move-only keyring role advances to that exact
    /// generation before this method returns.
    pub fn rotate_persisted_identity_signing_key(
        &self,
        new_signing_master_key_epoch: u32,
    ) -> Result<RegistryAnchorTuple, ObservationProviderError> {
        self.commit_explicit_keyring_update(
            None,
            |custody, context| {
                custody.prepare_signing_rotation(new_signing_master_key_epoch, context)
            },
            |prepared, _, _| prepared.verify_exact_signing_rotation(),
        )
    }

    /// Issue the only retirement challenge accepted by this provider.  The
    /// arbitrary key id is first narrowed by the current keyring role to an
    /// opaque VerifyOnly candidate, then bound to the exact anchored root and
    /// keyring generation by the shared verifier.
    pub fn issue_persisted_identity_key_retirement_challenge(
        &self,
        operation_id: String,
        key_id: u32,
        migration_generation: u64,
    ) -> Result<PersistedKeyRetirementChallenge, ObservationProviderError> {
        validate_operation_id(&operation_id)?;
        if !self.is_ready() {
            return Err(ObservationProviderError::RecoveryRequired(
                "provider is not ready".to_owned(),
            ));
        }
        let _mutation_guard = self
            .registry
            .observation_mutation_lock
            .try_lock()
            .map_err(|_| ObservationProviderError::Busy)?;
        let conn = self
            .registry
            .conn
            .try_lock()
            .map_err(|_| ObservationProviderError::Busy)?;
        let role_slot = self.persisted_keyring.lock().map_err(|_| {
            ObservationProviderError::RecoveryRequired(
                "persisted-keyring role lock is poisoned".to_owned(),
            )
        })?;
        let ledger = read_ledger(&conn)?.ok_or_else(|| {
            ObservationProviderError::RecoveryRequired("missing identity ledger".to_owned())
        })?;
        reconcile_external_anchor(self.anchor.as_ref(), &ledger)?;
        verify_complete_roots(&conn, &ledger)?;
        validate_durable_invariants(&conn)?;
        require_sql_key_status(&conn, key_id, false)?;
        let role = role_slot.as_ref().ok_or_else(|| {
            ObservationProviderError::RecoveryRequired(
                "persisted-keyring role is unavailable".to_owned(),
            )
        })?;
        role.verify_provider_binding(self.config.registry_instance, ledger.keyring_root)?;
        let candidate = role.persisted_key_retirement_candidate(key_id)?;
        self.verifier
            .issue_persisted_key_retirement_challenge(
                operation_id,
                &candidate,
                migration_generation,
            )
            .map_err(ObservationProviderError::from)
    }

    /// Retire one VerifyOnly carrier key only after the shared verifier has
    /// consumed an exact three-owner typed scan set.  The authenticated file
    /// projection must encode exactly the verified SQLite/JSONL scan fields;
    /// arbitrary watermarks or digest structs never enter this API.
    pub fn retire_persisted_identity_key(
        &self,
        challenge: PersistedKeyRetirementChallenge,
        scans: PersistedKeyRetirementScanSet,
    ) -> Result<RegistryAnchorTuple, ObservationProviderError> {
        let verified_scans = self
            .verifier
            .verify_persisted_key_retirement_scan_set(challenge, scans)?;
        let metadata = verified_scans.metadata().clone();
        if metadata.registry_instance != self.config.registry_instance
            || metadata.boot != self.config.boot
        {
            return Err(ObservationProviderError::InvalidInput(
                "persisted-key retirement scans belong to another provider".to_owned(),
            ));
        }
        let scan = crate::observation_anchor::PersistedKeyringScanProjection {
            sqlite_scan_sequence: metadata.sqlite.high_water,
            jsonl_inventory_digest: metadata.jsonl.inventory_digest,
            jsonl_segment_count: metadata.jsonl.segment_count,
            jsonl_byte_count: metadata.jsonl.byte_count,
            retention_high_water_ms: metadata.jsonl.retention_high_water,
        };
        let key_id = metadata.key_id;
        let expected_root = metadata.keyring_root;
        let expected_generation = metadata.keyring_generation;
        let mut scans = Some(verified_scans);
        self.commit_explicit_keyring_update(
            Some((expected_root, key_id)),
            |custody, context| {
                custody.prepare_retirement(
                    scans.take().ok_or_else(|| {
                        RegistryAnchorError::RecoveryRequired(
                            "typed retirement scan set was already consumed".to_owned(),
                        )
                    })?,
                    context,
                )
            },
            move |prepared, previous, _| {
                if previous.keyring_root() != expected_root
                    || previous.keyring_generation() != expected_generation
                {
                    return Err(RegistryAnchorError::RecoveryRequired(
                        "retirement scans are stale for the prepared keyring generation".to_owned(),
                    ));
                }
                prepared.verify_exact_retirement(key_id, scan)
            },
        )
    }

    /// Test-support composition stand-in for the not-yet-wired M019 owner
    /// roles.  Production builds expose no constructor for carrier-migration
    /// plans, prepared owner intents, or owner receipts.
    #[cfg(any(test, feature = "test-support"))]
    pub fn carrier_migration_test_fixture(
        &self,
        seed: u64,
        planned_row_count: u64,
    ) -> Result<CarrierMigrationTestFixture, ObservationProviderError> {
        if seed == 0 {
            return Err(ObservationProviderError::InvalidInput(
                "carrier-migration fixture seed must be nonzero".to_owned(),
            ));
        }
        Ok(CarrierMigrationTestFixture {
            metadata: Arc::new(carrier_migration_fixture_plan(
                self.config.registry_instance,
                seed,
                planned_row_count,
            )),
        })
    }

    /// Root one opaque cross-owner plan and reserve every planned row at its
    /// complete 2,048-byte terminal shape before any prepared intent can
    /// escape.  Zero rows take the only legal direct path to `verified`.
    pub fn reserve_carrier_migration(
        &self,
        plan: &CarrierMigrationPlan,
    ) -> Result<CarrierMigrationReservation, ObservationProviderError> {
        validate_carrier_migration_plan(&self.config, &plan.metadata)?;
        if let Some(_) = self.read_carrier_migration_phase(&plan.metadata)? {
            return Ok(CarrierMigrationReservation {
                metadata: Arc::clone(&plan.metadata),
            });
        }
        let metadata = Arc::clone(&plan.metadata);
        let discriminator = metadata.migration_id;
        self.anchored_mutation_sync(6, &discriminator, move |transaction| {
            reserve_carrier_migration_operation(transaction, &metadata)
        })?;
        Ok(CarrierMigrationReservation {
            metadata: Arc::clone(&plan.metadata),
        })
    }

    /// Commit one canonical-prefix prepared row under an already-rooted full
    /// reservation.  The opaque owner input is borrowed, so a definite
    /// precommit rejection never consumes it.  Retrying after a lost
    /// acknowledgement rehydrates the same committed intent.
    pub fn prepare_carrier_migration_row(
        &self,
        reservation: &CarrierMigrationReservation,
        owner_intent: &CarrierMigrationPreparedOwnerIntent,
    ) -> Result<CarrierMigrationPreparedIntent, ObservationProviderError> {
        if reservation.metadata.as_ref() != owner_intent.plan.as_ref() {
            return Err(ObservationProviderError::InvalidInput(
                "carrier-migration owner intent crosses an opaque reservation".to_owned(),
            ));
        }
        validate_carrier_migration_plan(&self.config, &reservation.metadata)?;
        validate_carrier_migration_row(&owner_intent.row)?;
        if let Some(committed) =
            self.read_carrier_migration_prepared_row(&reservation.metadata, &owner_intent.row)?
        {
            return Ok(CarrierMigrationPreparedIntent {
                plan: Arc::clone(&reservation.metadata),
                row: owner_intent.row.clone(),
                committed,
            });
        }
        let plan = Arc::clone(&reservation.metadata);
        let row = owner_intent.row.clone();
        let discriminator = row.event_key_digest;
        self.anchored_mutation_sync(6, &discriminator, move |transaction| {
            prepare_carrier_migration_row_operation(transaction, &plan, &row)
        })?;
        let committed = self
            .read_carrier_migration_prepared_row(&reservation.metadata, &owner_intent.row)?
            .ok_or_else(|| {
                ObservationProviderError::RecoveryRequired(
                    "anchored carrier-migration prepared row cannot be rehydrated".to_owned(),
                )
            })?;
        Ok(CarrierMigrationPreparedIntent {
            plan: Arc::clone(&reservation.metadata),
            row: owner_intent.row.clone(),
            committed,
        })
    }

    /// Consume one opaque target-postimage receipt and finalize exactly its
    /// prepared row.  No receipt digest or owner tuple can be supplied through
    /// this API.  Exact retries are side-effect free.
    pub fn finalize_carrier_migration_row(
        &self,
        prepared: &CarrierMigrationPreparedIntent,
        owner_commit: &CarrierMigrationOwnerCommitReceipt,
    ) -> Result<CarrierMigrationRowFinalizedAck, ObservationProviderError> {
        if prepared.plan.as_ref() != owner_commit.plan.as_ref()
            || prepared.row != owner_commit.row
            || prepared.committed.sequence != owner_commit.prepared_registry_sequence
            || prepared.committed.head != owner_commit.prepared_registry_head
            || prepared.committed.state_root != owner_commit.prepared_registry_state_root
            || carrier_migration_owner_commit_digest(
                &prepared.plan,
                &prepared.row,
                &prepared.committed,
            ) != owner_commit.receipt_digest
        {
            return Err(ObservationProviderError::InvalidInput(
                "carrier-migration owner commit is not bound to the prepared row".to_owned(),
            ));
        }
        validate_carrier_migration_plan(&self.config, &prepared.plan)?;
        if self.carrier_migration_row_is_finalized(
            &prepared.plan,
            &prepared.row,
            owner_commit.receipt_digest,
        )? {
            return Ok(CarrierMigrationRowFinalizedAck {
                plan: Arc::clone(&prepared.plan),
                row: prepared.row.clone(),
            });
        }
        let plan = Arc::clone(&prepared.plan);
        let row = prepared.row.clone();
        let receipt_digest = owner_commit.receipt_digest;
        let discriminator = row.receipt_nonce;
        self.anchored_mutation_sync(6, &discriminator, move |transaction| {
            finalize_carrier_migration_row_operation(transaction, &plan, &row, receipt_digest)
        })?;
        Ok(CarrierMigrationRowFinalizedAck {
            plan: Arc::clone(&prepared.plan),
            row: prepared.row.clone(),
        })
    }

    /// Verify the exact complete owner target after all per-row commits.  A
    /// digest-only or caller-assembled scan cannot enter this seam.
    pub fn verify_carrier_migration_owner_finalized(
        &self,
        reservation: &CarrierMigrationReservation,
        owner_finalized: &CarrierMigrationOwnerFinalizedReceipt,
    ) -> Result<CarrierMigrationFinalizedAck, ObservationProviderError> {
        if reservation.metadata.as_ref() != owner_finalized.plan.as_ref()
            || owner_finalized.verification_digest
                != carrier_migration_owner_finalized_digest(&reservation.metadata)
        {
            return Err(ObservationProviderError::InvalidInput(
                "carrier-migration owner-finalized receipt crosses its opaque plan".to_owned(),
            ));
        }
        match self.read_carrier_migration_phase(&reservation.metadata)? {
            Some(CarrierMigrationRecoveryPhase::Verified) => {
                return Ok(CarrierMigrationFinalizedAck {
                    metadata: Arc::clone(&reservation.metadata),
                })
            }
            Some(CarrierMigrationRecoveryPhase::Verifying) => {}
            _ => {
                return Err(ObservationProviderError::InvalidState(
                    "carrier migration is not ready for complete owner verification".to_owned(),
                ))
            }
        }
        let metadata = Arc::clone(&reservation.metadata);
        let discriminator = owner_finalized.verification_digest;
        self.anchored_mutation_sync(6, &discriminator, move |transaction| {
            verify_carrier_migration_owner_finalized_operation(transaction, &metadata)
        })?;
        Ok(CarrierMigrationFinalizedAck {
            metadata: Arc::clone(&reservation.metadata),
        })
    }

    /// Convert the exact durable carrier-migration `verified` acknowledgement
    /// into the only production authority for staging Installed→Complete.
    pub fn authorize_legacy_migration_completion(
        &self,
        migration: &PreparedLegacyRegistryMigration,
        finalized: CarrierMigrationFinalizedAck,
    ) -> Result<VerifiedLegacyMigrationComplete, ObservationProviderError> {
        if finalized.metadata.migration_id != migration.migration_id()
            || finalized.metadata.registry_instance != migration.registry_instance()
            || self.config.registry_instance != migration.registry_instance()
            || self.config.migration_digest != migration.migration_digest()
        {
            return Err(ObservationProviderError::InvalidInput(
                "carrier-migration completion crosses its authenticated legacy plan".to_owned(),
            ));
        }
        if self.read_carrier_migration_phase(&finalized.metadata)?
            != Some(CarrierMigrationRecoveryPhase::Verified)
        {
            return Err(ObservationProviderError::InvalidState(
                "carrier migration is not durably verified".to_owned(),
            ));
        }
        let conn = self.registry.conn.blocking_lock();
        let ledger = verify_carrier_migration_read_world(self.anchor.as_ref(), &conn)?;
        let context = read_head_context(&conn)?;
        if ledger.registry_instance != migration.registry_instance()
            || ledger.migration_digest != migration.migration_digest()
            || context.previous_marker_root != migration.installed_marker_root()
            || context.manifest_key_epoch != migration.manifest_key_epoch()
        {
            return Err(ObservationProviderError::RecoveryRequired(
                "verified carrier migration is not anchored under the Installed marker".to_owned(),
            ));
        }
        Ok(VerifiedLegacyMigrationComplete {
            plan_binding: migration.plan_binding_digest(),
            registry_instance: migration.registry_instance(),
            migration_id: migration.migration_id(),
        })
    }

    pub fn recover_carrier_migration(
        &self,
        reservation: &CarrierMigrationReservation,
    ) -> Result<CarrierMigrationRecoveryPhase, ObservationProviderError> {
        self.read_carrier_migration_phase(&reservation.metadata)?
            .ok_or_else(|| {
                ObservationProviderError::InvalidState(
                    "carrier-migration reservation is not durable".to_owned(),
                )
            })
    }

    fn read_carrier_migration_phase(
        &self,
        metadata: &CarrierMigrationPlanMetadata,
    ) -> Result<Option<CarrierMigrationRecoveryPhase>, ObservationProviderError> {
        if !self.ready.load(Ordering::Acquire) {
            return Err(ObservationProviderError::RecoveryRequired(
                "carrier-migration provider is not internally ready".to_owned(),
            ));
        }
        let _mutation_guard = self
            .registry
            .observation_mutation_lock
            .try_lock()
            .map_err(|_| ObservationProviderError::Busy)?;
        let conn = self
            .registry
            .conn
            .try_lock()
            .map_err(|_| ObservationProviderError::Busy)?;
        verify_carrier_migration_read_world(self.anchor.as_ref(), &conn)?;
        read_carrier_migration_phase_exact(&conn, metadata)
    }

    fn read_carrier_migration_prepared_row(
        &self,
        metadata: &CarrierMigrationPlanMetadata,
        row: &CarrierMigrationRowMetadata,
    ) -> Result<Option<RegistryAnchorTuple>, ObservationProviderError> {
        if !self.ready.load(Ordering::Acquire) {
            return Err(ObservationProviderError::RecoveryRequired(
                "carrier-migration provider is not internally ready".to_owned(),
            ));
        }
        let _mutation_guard = self
            .registry
            .observation_mutation_lock
            .try_lock()
            .map_err(|_| ObservationProviderError::Busy)?;
        let conn = self
            .registry
            .conn
            .try_lock()
            .map_err(|_| ObservationProviderError::Busy)?;
        let ledger = verify_carrier_migration_read_world(self.anchor.as_ref(), &conn)?;
        if carrier_migration_prepared_row_matches(&conn, metadata, row)? {
            Ok(Some(ledger))
        } else {
            Ok(None)
        }
    }

    fn carrier_migration_row_is_finalized(
        &self,
        metadata: &CarrierMigrationPlanMetadata,
        row: &CarrierMigrationRowMetadata,
        receipt_digest: [u8; 32],
    ) -> Result<bool, ObservationProviderError> {
        if !self.ready.load(Ordering::Acquire) {
            return Err(ObservationProviderError::RecoveryRequired(
                "carrier-migration provider is not internally ready".to_owned(),
            ));
        }
        let _mutation_guard = self
            .registry
            .observation_mutation_lock
            .try_lock()
            .map_err(|_| ObservationProviderError::Busy)?;
        let conn = self
            .registry
            .conn
            .try_lock()
            .map_err(|_| ObservationProviderError::Busy)?;
        verify_carrier_migration_read_world(self.anchor.as_ref(), &conn)?;
        carrier_migration_finalized_row_matches(&conn, metadata, row, receipt_digest)
    }

    /// Scheduler-owned Component retirement seam.  Live authority, both
    /// typed prepare receipt families, and the complete six-owner cleanup
    /// receipt remain opaque; no aggregate registrar or raw digest API is
    /// introduced.
    pub fn prepare_component_termination(
        &self,
        operation_id: &str,
        component: &TrustedObservationIdentity,
        retain_until_ms: u64,
        subject_drains: Vec<VerifiedGrantSubjectDrainToken>,
        emission_drains: Vec<VerifiedSourceEmissionQuiesceReceipt>,
    ) -> Result<TerminationPrepareCommitAck, TerminationPrepareFailure> {
        let request_sequence = self.current_registry_sequence_sync().unwrap_or(0);
        let claims = component.claims_for_persistence();
        let request_ids = vec![claims.exact_id.clone()];
        let request_digest = termination_request_digest(operation_id, &request_ids);
        let now_ms = u64::try_from(crate::types::now_unix_ms().max(0)).unwrap_or(0);
        if retain_until_ms > i64::MAX as u64
            || retain_until_ms < now_ms
            || self.verify(component).is_err()
        {
            return Err(self.termination_state.reject_invalid_prepare_request(
                operation_id,
                request_digest,
                request_sequence,
            ));
        }
        let (record, members) =
            match self.load_component_termination_candidate(operation_id, &claims) {
                Ok(candidate) => candidate,
                Err(_) => {
                    return Err(self.termination_state.reject_invalid_prepare_request(
                        operation_id,
                        request_digest,
                        request_sequence,
                    ))
                }
            };
        let receipt_set = match self
            .termination_state
            .verify_termination_prepare_receipt_sets(
                &record,
                &members,
                TerminationGrantSubjectDrainReceiptSet::new(subject_drains),
                TerminationSourceEmissionQuiesceReceiptSet::new(emission_drains),
            ) {
            Ok(receipt_set) => receipt_set,
            Err(_) => return Err(self.termination_rejected(record)),
        };
        let prepared = match self.termination_state.prepare_committed(record.clone()) {
            Ok(prepared) => prepared,
            Err(_) => return Err(self.termination_rejected(record)),
        };
        let prepare_ack_digest = match self.termination_state.prepare_ack_digest(&prepared) {
            Ok(digest) => digest,
            Err(_) => return Err(self.termination_rejected(record)),
        };
        let prepare_ack_nonce = match self.termination_state.prepare_ack_nonce(&prepared) {
            Ok(nonce) => nonce,
            Err(_) => return Err(self.termination_rejected(record)),
        };
        let discriminator = record.operation_id.as_bytes().to_vec();
        let record_for_tx = record.clone();
        let config = self.config.clone();
        let finalize_capacity_limit = self.take_termination_finalize_capacity_limit();
        let admission_limits = match self.admission_capacity_limits() {
            Ok(limits) => limits,
            Err(error) if error.gates_provider() => {
                return Err(self.termination_unknown(record));
            }
            Err(_) => return Err(self.termination_rejected(record)),
        };
        match self.anchored_mutation_sync(4, &discriminator, move |transaction| {
            prepare_termination_operation(
                transaction,
                &record_for_tx,
                &members,
                retain_until_ms,
                &receipt_set,
                prepare_ack_digest,
                prepare_ack_nonce,
                config.registry_instance,
                config.boot,
                "terminate-component",
                ObservationIdentityClass::Component,
                finalize_capacity_limit,
                admission_limits,
            )
        }) {
            Ok(()) => Ok(prepared),
            Err(error) if error.gates_provider() => Err(self.termination_unknown(record)),
            Err(_) => Err(self.termination_rejected(record)),
        }
    }

    pub fn finalize_component_termination(
        &self,
        prepared: TerminationPrepareCommitAck,
        cleanup: TerminationCleanupCompleteReceipt,
    ) -> TerminationFinalizeResult {
        let record = match self.termination_state.verify_prepare_ack(&prepared) {
            Ok(record) => record,
            Err(_) => return TerminationFinalizeResult::Rejected { prepared, cleanup },
        };
        let verified = match self.termination_state.verify_finalize_inputs(
            prepared,
            cleanup,
            &self.cleanup_verifier,
        ) {
            TerminationFinalizeInputVerification::Verified(verified) => verified,
            TerminationFinalizeInputVerification::Rejected { prepared, cleanup } => {
                return TerminationFinalizeResult::Rejected { prepared, cleanup };
            }
        };
        let metadata = match self
            .termination_state
            .finalize_journal_metadata(&verified, &self.cleanup_verifier)
        {
            Ok(metadata) => metadata,
            Err(_) => return self.termination_state.finalize_rejected(verified),
        };
        let discriminator = record.operation_id.as_bytes().to_vec();
        let record_for_tx = record.clone();
        let config = self.config.clone();
        match self.anchored_mutation_sync(5, &discriminator, move |transaction| {
            finalize_termination_operation(
                transaction,
                &record_for_tx,
                &metadata,
                config.registry_instance,
                config.boot,
                "terminate-component",
                ObservationIdentityClass::Component,
            )
        }) {
            Ok(()) => self.termination_state.finalize_committed(verified),
            Err(error) if error.gates_provider() => {
                self.termination_state.finalize_outcome_unknown(verified)
            }
            Err(_) => self.termination_state.finalize_rejected(verified),
        }
    }

    /// Rehydrate an exact scheduler-owned Component termination prepare
    /// acknowledgement after an outcome-unknown return.  The durable
    /// operation kind and every member class are checked before the opaque
    /// acknowledgement is reissued.
    pub fn recover_component_termination_prepare(
        &self,
        recovery: TerminationPrepareRecoveryHandle,
    ) -> Result<TerminationPrepareCommitAck, TerminationPrepareFailure> {
        let record = match self.termination_state.inspect_prepare_recovery(&recovery) {
            Ok(record) => record,
            Err(_) => return Err(TerminationPrepareFailure::OutcomeUnknown(recovery)),
        };
        match self.recover_termination_prepare_ack(
            &record,
            "terminate-component",
            ObservationIdentityClass::Component,
        ) {
            Ok(Some(prepared)) => Ok(prepared),
            Ok(None) => {
                let resumed = self.termination_state.resume_prepare(recovery);
                Err(self.termination_rejected(resumed))
            }
            Err(_) => Err(TerminationPrepareFailure::OutcomeUnknown(recovery)),
        }
    }

    /// Recover an exact scheduler-owned Component finalization.  Recovery is
    /// class-closed: an Agent operation, or any mixed member projection, can
    /// never satisfy this path.
    pub fn recover_component_termination(
        &self,
        recovery: TerminationFinalizeRecoveryHandle,
    ) -> TerminationFinalizeResult {
        let record = match self.termination_state.inspect_finalize_recovery(&recovery) {
            Ok(record) => record,
            Err(_) => return TerminationFinalizeResult::OutcomeUnknown(recovery),
        };
        let metadata = match self
            .termination_state
            .inspect_finalize_recovery_journal_metadata(&recovery, &self.cleanup_verifier)
        {
            Ok(metadata) => metadata,
            Err(_) => return TerminationFinalizeResult::OutcomeUnknown(recovery),
        };
        if self
            .recover_termination_operation(
                &record,
                "terminate-component",
                ObservationIdentityClass::Component,
            )
            .is_err()
        {
            return TerminationFinalizeResult::OutcomeUnknown(recovery);
        }
        let committed = self
            .termination_finalization_is_committed(
                &record,
                &metadata,
                "terminate-component",
                ObservationIdentityClass::Component,
            )
            .unwrap_or(false);
        let verified = self.termination_state.resume_finalize(recovery);
        if committed {
            self.termination_state.finalize_committed(verified)
        } else {
            self.termination_state.finalize_rejected(verified)
        }
    }

    /// Prepare or exactly rehydrate the retained-tombstone challenge bound to
    /// one authenticated finalize acknowledgement.  Generation, sequence,
    /// root, and nonce are selected internally and rooted before the opaque
    /// challenge escapes.
    pub fn prepare_retained_tombstone_gc(
        &self,
        finalized: &TerminationFinalizeCommitAck,
    ) -> Result<RetainedTombstoneGcChallenge, ObservationProviderError> {
        if !self.is_ready() {
            return Err(ObservationProviderError::RecoveryRequired(
                "provider is not ready".to_owned(),
            ));
        }
        let finalized_record = self.termination_state.verify_finalize_ack(finalized)?;
        match self.load_tombstone_gc_challenge_plan(&finalized_record)? {
            TombstoneGcChallengePlan::Existing {
                record,
                tombstone_state_root,
                gc_generation,
                challenge_nonce,
            } => self
                .verifier
                .rehydrate_retained_tombstone_gc_challenge(
                    record,
                    tombstone_state_root,
                    gc_generation,
                    challenge_nonce,
                )
                .map_err(ObservationProviderError::from),
            TombstoneGcChallengePlan::Prepare {
                record,
                tombstone_state_root,
                gc_generation,
                previous_phase,
                previous_generation,
                member_count,
            } => {
                let challenge = self.verifier.issue_retained_tombstone_gc_challenge(
                    record.clone(),
                    tombstone_state_root,
                    gc_generation,
                )?;
                let metadata = self
                    .verifier
                    .inspect_retained_tombstone_gc_challenge(&challenge)?;
                let discriminator = metadata.challenge_nonce;
                let operation_boot = self.config.boot;
                self.anchored_mutation_sync(8, &discriminator, move |transaction| {
                    prepare_tombstone_gc_operation(
                        transaction,
                        &metadata,
                        &previous_phase,
                        previous_generation,
                        member_count,
                        operation_boot,
                    )
                })?;
                Ok(challenge)
            }
        }
    }

    /// Consume one exact purpose-2 zero token plus the five closed owner scan
    /// receipts.  Only their shared verified projection can authorize tag-8
    /// deletion; identity authority high-water and operation history remain.
    pub fn collect_retained_tombstone_gc(
        &self,
        challenge: RetainedTombstoneGcChallenge,
        purpose2: C123Purpose2ZeroToken,
        receipts: RetainedTombstoneGcReceiptSet,
    ) -> Result<(), ObservationProviderError> {
        let verified = self
            .verifier
            .verify_retained_tombstone_gc_set(challenge, purpose2, receipts)?;
        let discriminator = verified.metadata().challenge_nonce;
        let config = self.config.clone();
        self.anchored_mutation_sync(8, &discriminator, move |transaction| {
            collect_tombstone_gc_operation(
                transaction,
                &verified,
                config.registry_instance,
                config.boot,
            )
        })
    }

    fn load_tombstone_gc_challenge_plan(
        &self,
        finalized: &TerminationOperationRecord,
    ) -> Result<TombstoneGcChallengePlan, ObservationProviderError> {
        let _mutation_guard = self
            .registry
            .observation_mutation_lock
            .try_lock()
            .map_err(|_| ObservationProviderError::Busy)?;
        let conn = self.registry.conn.try_lock().map_err(|_| {
            ObservationProviderError::Catalog(SensitiveParamCatalogError::StorageUnavailable)
        })?;
        let ledger = read_ledger(&conn)?.ok_or_else(|| {
            ObservationProviderError::RecoveryRequired("missing identity ledger".to_owned())
        })?;
        reconcile_external_anchor(self.anchor.as_ref(), &ledger)?;
        verify_complete_roots(&conn, &ledger)?;
        validate_durable_invariants(&conn)?;
        let exact_finalized: i64 = conn.query_row(
            "SELECT COUNT(*)
             FROM observation_identity_operations o
             JOIN observation_termination_finalizations f
               ON f.operation_id=o.operation_id
             WHERE o.operation_id=?1
               AND o.kind IN ('terminate-agents','terminate-component')
               AND o.phase='committed' AND o.is_active=0
               AND f.phase='finalized' AND f.member_set_digest=?2",
            params![
                finalized.operation_id,
                finalized.member_set_digest.as_slice(),
            ],
            |row| row.get(0),
        )?;
        if exact_finalized != 1 {
            return Err(ObservationProviderError::InvalidState(
                "GC input does not name one exact finalized termination".to_owned(),
            ));
        }
        struct MemberGcRow {
            identity_id: String,
            phase: String,
            generation: i64,
            registry_sequence: Option<i64>,
            challenge_nonce: Option<Vec<u8>>,
            tombstone_state_root: Option<Vec<u8>>,
            operation_boot: Option<Vec<u8>>,
        }
        let mut stmt = conn.prepare(
            "SELECT identity_id,gc_phase,gc_generation,gc_registry_sequence,
                    gc_challenge_nonce,gc_tombstone_state_root,gc_operation_boot
             FROM observation_identity_operation_members
             WHERE operation_id=?1 ORDER BY identity_id COLLATE BINARY",
        )?;
        let rows = stmt
            .query_map(params![finalized.operation_id], |row| {
                Ok(MemberGcRow {
                    identity_id: row.get(0)?,
                    phase: row.get(1)?,
                    generation: row.get(2)?,
                    registry_sequence: row.get(3)?,
                    challenge_nonce: row.get(4)?,
                    tombstone_state_root: row.get(5)?,
                    operation_boot: row.get(6)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        drop(stmt);
        if rows.is_empty() || rows.iter().any(|row| row.phase != rows[0].phase) {
            return Err(ObservationProviderError::RecoveryRequired(
                "GC operation members do not share one durable phase".to_owned(),
            ));
        }
        if rows[0].phase == "collected" {
            return Err(ObservationProviderError::InvalidState(
                "retained tombstones are already collected".to_owned(),
            ));
        }
        let now_ms = crate::types::now_unix_ms().max(0);
        let mut claims = Vec::with_capacity(rows.len());
        for row in &rows {
            let member = read_identity_claims(&conn, &row.identity_id)?.ok_or_else(|| {
                ObservationProviderError::RecoveryRequired(
                    "GC retained identity is missing before collection".to_owned(),
                )
            })?;
            let eligible: i64 = conn.query_row(
                "SELECT COUNT(*) FROM observation_identities
                 WHERE id=?1 AND incarnation=?2 AND declaration_digest=?3
                   AND lifecycle_state='tombstoned' AND catalog_visible=1
                   AND operation_id=?4 AND tombstoned_at_ms IS NOT NULL
                   AND retain_until_ms IS NOT NULL AND retain_until_ms<=?5",
                params![
                    member.exact_id,
                    member.incarnation as i64,
                    member.declaration_digest.as_bytes().as_slice(),
                    finalized.operation_id,
                    now_ms,
                ],
                |row| row.get(0),
            )?;
            if eligible != 1 {
                return Err(ObservationProviderError::InvalidState(
                    "retained tombstone has not reached its collection deadline".to_owned(),
                ));
            }
            claims.push(member);
        }
        if termination_member_set_digest(&claims)? != finalized.member_set_digest {
            return Err(ObservationProviderError::RecoveryRequired(
                "GC retained member set differs from finalized termination".to_owned(),
            ));
        }
        let previous_generation = u64::try_from(rows[0].generation).map_err(|_| {
            ObservationProviderError::RecoveryRequired("invalid GC generation".to_owned())
        })?;
        if rows
            .iter()
            .any(|row| u64::try_from(row.generation).ok() != Some(previous_generation))
        {
            return Err(ObservationProviderError::RecoveryRequired(
                "GC member generations differ".to_owned(),
            ));
        }
        if rows[0].phase == "prepared" {
            let sequence = rows[0].registry_sequence.ok_or_else(|| {
                ObservationProviderError::RecoveryRequired(
                    "Prepared GC sequence is missing".to_owned(),
                )
            })?;
            let nonce = rows[0].challenge_nonce.clone().ok_or_else(|| {
                ObservationProviderError::RecoveryRequired(
                    "Prepared GC challenge nonce is missing".to_owned(),
                )
            })?;
            let root = rows[0].tombstone_state_root.clone().ok_or_else(|| {
                ObservationProviderError::RecoveryRequired(
                    "Prepared GC tombstone root is missing".to_owned(),
                )
            })?;
            let boot = rows[0].operation_boot.clone().ok_or_else(|| {
                ObservationProviderError::RecoveryRequired(
                    "Prepared GC operation boot is missing".to_owned(),
                )
            })?;
            if rows.iter().any(|row| {
                row.registry_sequence != Some(sequence)
                    || row.challenge_nonce.as_deref() != Some(nonce.as_slice())
                    || row.tombstone_state_root.as_deref() != Some(root.as_slice())
                    || row.operation_boot.as_deref() != Some(boot.as_slice())
            }) {
                return Err(ObservationProviderError::RecoveryRequired(
                    "Prepared GC members disagree on challenge metadata".to_owned(),
                ));
            }
            if boot.as_slice() == self.config.boot.as_slice() {
                return Ok(TombstoneGcChallengePlan::Existing {
                    record: TerminationOperationRecord {
                        operation_id: finalized.operation_id.clone(),
                        member_set_digest: finalized.member_set_digest,
                        registry_sequence: u64::try_from(sequence).map_err(|_| {
                            ObservationProviderError::RecoveryRequired(
                                "Prepared GC sequence is invalid".to_owned(),
                            )
                        })?,
                    },
                    tombstone_state_root: exact_previsible_array(root, "GC tombstone root")?,
                    gc_generation: previous_generation,
                    challenge_nonce: exact_previsible_array(nonce, "GC challenge nonce")?,
                });
            }
        }
        let gc_generation = previous_generation
            .checked_add(1)
            .filter(|generation| *generation <= i64::MAX as u64)
            .ok_or_else(|| {
                ObservationProviderError::CapacityExceeded("GC generation exhausted".to_owned())
            })?;
        let registry_sequence = ledger
            .sequence
            .checked_add(1)
            .filter(|sequence| *sequence <= i64::MAX as u64)
            .ok_or_else(|| {
                ObservationProviderError::CapacityExceeded("registry sequence exhausted".to_owned())
            })?;
        Ok(TombstoneGcChallengePlan::Prepare {
            record: TerminationOperationRecord {
                operation_id: finalized.operation_id.clone(),
                member_set_digest: finalized.member_set_digest,
                registry_sequence,
            },
            tombstone_state_root: ledger.state_root,
            gc_generation,
            previous_phase: rows[0].phase.clone(),
            previous_generation,
            member_count: rows.len(),
        })
    }

    fn commit_explicit_keyring_update<P, V>(
        &self,
        expected_current: Option<([u8; 32], u32)>,
        prepare: P,
        validate: V,
    ) -> Result<RegistryAnchorTuple, ObservationProviderError>
    where
        P: FnOnce(
            &dyn PersistedKeyringCustody,
            RegistryHeadContext,
        )
            -> Result<Box<dyn PreparedPersistedKeyringCustodyMutation>, RegistryAnchorError>,
        V: FnOnce(
            &PreparedPersistedKeyringMutation,
            PersistedIdentityKeyringBinding,
            PersistedIdentityKeyringBinding,
        ) -> Result<(), RegistryAnchorError>,
    {
        if !self.is_ready() {
            return Err(ObservationProviderError::RecoveryRequired(
                "provider is not ready".to_owned(),
            ));
        }
        let _mutation_guard = self
            .registry
            .observation_mutation_lock
            .try_lock()
            .map_err(|_| ObservationProviderError::Busy)?;
        let mut conn = self
            .registry
            .conn
            .try_lock()
            .map_err(|_| ObservationProviderError::Busy)?;
        let mut role_slot = self.persisted_keyring.lock().map_err(|_| {
            ObservationProviderError::RecoveryRequired(
                "persisted-keyring role lock is poisoned".to_owned(),
            )
        })?;
        let result: Result<RegistryAnchorTuple, ObservationProviderError> = (|| {
            let ledger = read_ledger(&conn)?.ok_or_else(|| {
                ObservationProviderError::RecoveryRequired("missing identity ledger".to_owned())
            })?;
            reconcile_external_anchor(self.anchor.as_ref(), &ledger)?;
            verify_complete_roots(&conn, &ledger)?;
            validate_durable_invariants(&conn)?;
            if let Some((expected_root, key_id)) = expected_current {
                if ledger.keyring_root != expected_root {
                    return Err(ObservationProviderError::Catalog(
                        SensitiveParamCatalogError::StaleIdentity,
                    ));
                }
                require_sql_key_status(&conn, key_id, false)?;
            }
            let role = role_slot.as_ref().ok_or_else(|| {
                ObservationProviderError::RecoveryRequired(
                    "persisted-keyring role is unavailable".to_owned(),
                )
            })?;
            role.verify_provider_binding(self.config.registry_instance, ledger.keyring_root)?;
            let context = read_head_context(&conn)?;
            let prepared_custody = prepare(self.persisted_keyring_custody.as_ref(), context)?;
            commit_custody_keyring_update_on_connection(
                &mut conn,
                self.registry.database_path(),
                self.anchor.as_ref(),
                &mut role_slot,
                prepared_custody,
                validate,
            )
        })();
        if let Err(error) = &result {
            if error.gates_provider() {
                self.ready.store(false, Ordering::Release);
            }
        }
        result
    }

    fn seal_or_reseal_with_custody(
        &self,
        live_identity: Option<&TrustedObservationIdentity>,
        existing: Option<&PersistedObservationIdentity>,
        binding: &PersistedObservationBinding,
    ) -> Result<PersistedObservationIdentity, ObservationProviderError> {
        if !self.is_ready() {
            return Err(ObservationProviderError::RecoveryRequired(
                "provider is not ready".to_owned(),
            ));
        }
        if live_identity.is_some() == existing.is_some() {
            return Err(ObservationProviderError::InvalidInput(
                "carrier custody requires exactly one seal or reseal input".to_owned(),
            ));
        }
        binding.validate()?;
        let _mutation_guard = self
            .registry
            .observation_mutation_lock
            .try_lock()
            .map_err(|_| ObservationProviderError::Busy)?;
        let mut conn = self
            .registry
            .conn
            .try_lock()
            .map_err(|_| ObservationProviderError::Busy)?;
        let mut role_slot = self.persisted_keyring.lock().map_err(|_| {
            ObservationProviderError::RecoveryRequired(
                "persisted-keyring role lock is poisoned".to_owned(),
            )
        })?;
        let result: Result<PersistedObservationIdentity, ObservationProviderError> = (|| {
            let ledger = read_ledger(&conn)?.ok_or_else(|| {
                ObservationProviderError::RecoveryRequired("missing identity ledger".to_owned())
            })?;
            reconcile_external_anchor(self.anchor.as_ref(), &ledger)?;
            verify_complete_roots(&conn, &ledger)?;
            validate_durable_invariants(&conn)?;
            let role = role_slot.as_ref().ok_or_else(|| {
                ObservationProviderError::RecoveryRequired(
                    "persisted-keyring role is unavailable".to_owned(),
                )
            })?;
            role.verify_provider_binding(self.config.registry_instance, ledger.keyring_root)?;
            let signing = role.signing_key_capability()?;

            let carrier = match (live_identity, existing) {
                (Some(live), None) => {
                    let claims = live.claims_for_persistence();
                    require_exact_catalog_claims(&conn, &claims, true)?;
                    role.seal_persisted_identity(&signing, live, binding)?
                }
                (None, Some(persisted)) => {
                    require_sql_key_status(&conn, persisted.key_id(), false)?;
                    let verification = role.verification_key_capability(persisted.key_id())?;
                    let rehydrated = role.rehydrate_persisted_identity(&verification, persisted)?;
                    let claims = rehydrated.claims_for_persistence();
                    require_exact_catalog_claims(&conn, &claims, false)?;
                    role.reseal_persisted_identity(&signing, &verification, persisted, binding)?
                }
                _ => unreachable!("exactly one carrier input was checked above"),
            };

            require_sql_key_status(&conn, carrier.key_id(), true)?;
            let last_issued: i64 = conn.query_row(
                "SELECT last_issued_at_ms FROM observation_persisted_keyring_entries
                 WHERE key_id=?1 AND status='signing'",
                params![i64::from(carrier.key_id())],
                |row| row.get(0),
            )?;
            let last_issued = u64::try_from(last_issued).map_err(|_| {
                ObservationProviderError::RecoveryRequired(
                    "persisted signing-key issuance high-water is invalid".to_owned(),
                )
            })?;
            let wall_clock = u64::try_from(crate::types::now_unix_ms()).map_err(|_| {
                ObservationProviderError::RecoveryRequired(
                    "system clock is before the persisted carrier epoch".to_owned(),
                )
            })?;
            let issued_at_ms = wall_clock.max(last_issued.checked_add(1).ok_or_else(|| {
                ObservationProviderError::CapacityExceeded(
                    "persisted signing-key issuance high-water exhausted".to_owned(),
                )
            })?);
            let context = read_head_context(&conn)?;
            let prepared_custody = self
                .persisted_keyring_custody
                .prepare_last_issued_replacement(carrier.key_id(), issued_at_ms, context)?;
            let validate_key_id = carrier.key_id();
            commit_custody_keyring_update_on_connection(
                &mut conn,
                self.registry.database_path(),
                self.anchor.as_ref(),
                &mut role_slot,
                prepared_custody,
                move |prepared, _, _| {
                    prepared.verify_exact_last_issued_replacement(validate_key_id, issued_at_ms)
                },
            )?;
            Ok(carrier)
        })();
        if let Err(error) = &result {
            if error.gates_provider() {
                self.ready.store(false, Ordering::Release);
            }
        }
        result
    }

    /// Commit one scheduler-prepared role-allocation manifest replacement.
    ///
    /// This is the sole public tag-6 role-root mutation seam.  Callers cannot
    /// supply a role root, head, write-set digest, or raw anchor mutation: the
    /// opaque value has already recomputed them from both complete manifest
    /// files, and this method binds its previous context to the durable
    /// SQLite tuple/marker/epoch under the registry's global mutation lock.
    pub async fn commit_role_allocation_mutation(
        &self,
        prepared: PreparedRoleAllocationMutation,
    ) -> Result<RegistryAnchorTuple, ObservationProviderError> {
        if !self.is_ready() {
            return Err(ObservationProviderError::RecoveryRequired(
                "provider is not ready".to_owned(),
            ));
        }
        let _mutation_guard = self.registry.observation_mutation_lock.lock().await;
        let conn = Arc::clone(&self.registry.conn);
        let db_path = self.registry.database_path().to_path_buf();
        let anchor = Arc::clone(&self.anchor);
        let result = tokio::task::spawn_blocking(
            move || -> Result<RegistryAnchorTuple, ObservationProviderError> {
                let mut conn = conn.blocking_lock();
                commit_prepared_role_allocation_on_connection(
                    &mut conn,
                    &db_path,
                    anchor.as_ref(),
                    prepared,
                )
            },
        )
        .await
        .map_err(|error| ObservationProviderError::Join(error.to_string()))?;
        if let Err(error) = &result {
            if error.gates_provider() {
                self.ready.store(false, Ordering::Release);
            }
        }
        result
    }

    pub async fn issue_completed_hydration_receipt(
        &self,
    ) -> Result<CompletedIdentityHydrationReceipt, ObservationProviderError> {
        if !self.is_ready() {
            return Err(ObservationProviderError::RecoveryRequired(
                "provider is not ready".to_owned(),
            ));
        }
        let ledger = self.current_anchor_tuple().await?;
        self.verifier
            .issue_completed_hydration_receipt(ledger.sequence, ledger.state_root)
            .map_err(ObservationProviderError::from)
    }

    /// Prove from the complete rooted replay journals that an old boot still
    /// needs its sealed lifecycle role family.  The receipt is move-only and
    /// bound to the exact anchored scan high-water.
    pub async fn issue_retained_role_dependency_receipt(
        &self,
        boot: [u8; 16],
        family_version: u16,
    ) -> Result<RetainedRoleDependencyReceipt, ObservationProviderError> {
        let (ledger, retained_rows) = self.scan_role_dependencies(boot, family_version).await?;
        if retained_rows == 0 {
            return Err(ObservationProviderError::InvalidState(
                "no retained role dependency exists for the requested boot".to_owned(),
            ));
        }
        RetainedRoleDependencyReceipt::from_full_scan(
            &ledger,
            boot,
            family_version,
            ledger.sequence,
        )
        .map_err(ObservationProviderError::from)
    }

    /// Prove from the complete rooted replay journals that no row still names
    /// one old boot before role-root erasure is attempted.
    pub async fn issue_zero_role_dependency_receipt(
        &self,
        boot: [u8; 16],
        family_version: u16,
    ) -> Result<ZeroRoleDependencyReceipt, ObservationProviderError> {
        let (ledger, retained_rows) = self.scan_role_dependencies(boot, family_version).await?;
        if retained_rows != 0 {
            return Err(ObservationProviderError::InvalidState(
                "retained replay rows still depend on the requested boot".to_owned(),
            ));
        }
        ZeroRoleDependencyReceipt::from_full_scan(&ledger, boot, family_version, ledger.sequence)
            .map_err(ObservationProviderError::from)
    }

    async fn scan_role_dependencies(
        &self,
        boot: [u8; 16],
        family_version: u16,
    ) -> Result<(RegistryAnchorTuple, u64), ObservationProviderError> {
        if !self.is_ready() {
            return Err(ObservationProviderError::RecoveryRequired(
                "provider is not ready".to_owned(),
            ));
        }
        if boot == [0; 16] || family_version != 1 {
            return Err(ObservationProviderError::InvalidInput(
                "role dependency scan requires a nonzero boot and family version 1".to_owned(),
            ));
        }
        let _mutation_guard = self.registry.observation_mutation_lock.lock().await;
        let conn = Arc::clone(&self.registry.conn);
        let anchor = Arc::clone(&self.anchor);
        let result = tokio::task::spawn_blocking(
            move || -> Result<(RegistryAnchorTuple, u64), ObservationProviderError> {
                let conn = conn.blocking_lock();
                let ledger = read_ledger(&conn)?.ok_or_else(|| {
                    ObservationProviderError::RecoveryRequired("missing identity ledger".to_owned())
                })?;
                reconcile_external_anchor(anchor.as_ref(), &ledger)?;
                verify_complete_roots(&conn, &ledger)?;
                validate_durable_invariants(&conn)?;
                let retained_rows: i64 = conn.query_row(
                    "SELECT
                    (SELECT COUNT(*) FROM observation_previsible_activations
                     WHERE boot_id=?1)
                  + (SELECT COUNT(*) FROM observation_termination_finalizations
                     WHERE operation_boot_id=?1)",
                    params![boot.as_slice()],
                    |row| row.get(0),
                )?;
                let retained_rows = u64::try_from(retained_rows).map_err(|_| {
                    ObservationProviderError::RecoveryRequired(
                        "negative role dependency scan count".to_owned(),
                    )
                })?;
                Ok((ledger, retained_rows))
            },
        )
        .await
        .map_err(|error| ObservationProviderError::Join(error.to_string()))?;
        if let Err(error) = &result {
            if error.gates_provider() {
                self.ready.store(false, Ordering::Release);
            }
        }
        result
    }

    /// Foundation admission path for a component that remains hidden until
    /// [`ComponentObservationSourceIssuer::publish_component_source`] commits
    /// the ready-proof-gated tag-3 transition.
    pub async fn commit_component_unpublished(
        &self,
        operation_id: String,
        submitter: String,
        config: ComponentSubmitConfig,
        interval_ms: Option<i64>,
    ) -> Result<CommittedComponentSourceReceipt, ObservationProviderError> {
        validate_operation_id(&operation_id)?;
        validate_ordinary_identity_id(&config.id)?;
        ComponentId::new(config.id.clone()).map_err(|_| {
            ObservationProviderError::InvalidInput("invalid component id".to_owned())
        })?;
        if submitter.len() > MAX_SUBMITTER_LEN {
            return Err(ObservationProviderError::InvalidInput(
                "component submitter exceeds the registry bound".to_owned(),
            ));
        }
        if interval_ms.is_some_and(|value| value < MIN_RECURRING_INTERVAL_MS) {
            return Err(ObservationProviderError::InvalidInput(
                "component recurring interval is below the registry floor".to_owned(),
            ));
        }
        if config.component_type == advance_shared_types::component::ComponentType::Agent {
            return Err(ObservationProviderError::InvalidInput(
                "agent component types use the agent identity registrar".to_owned(),
            ));
        }
        let declaration = validated_component_declaration(config.sensitive_params.clone())?;
        let declaration_names = declaration.names();
        let sensitive_params_tail = canonical_sensitive_param_tail(declaration_names.as_ref())?;
        let mut stored_config = config.clone();
        stored_config.sensitive_params = declaration_names.to_vec();
        redact_webhook_secrets_in_trigger(&mut stored_config.trigger, 0)?;
        let stored_json = serde_json::to_string(&stored_config)
            .map_err(|error| RegistryError::Serde(error.to_string()))?;
        let id = config.id.clone();
        let component_type = config.component_type.as_str().to_owned();
        let submitted_at_ms = crate::types::now_unix_ms();
        let discriminator = operation_id.as_bytes().to_vec();
        let receipt_operation_id = operation_id.clone();
        let admission_limits = self.admission_capacity_limits()?;
        let previsible_limits = self.previsible_capacity_limits()?;
        let claims = self
            .anchored_mutation(1, discriminator, move |transaction| {
                if operation_exists(transaction, &operation_id)?
                    || read_identity_claims(transaction, &id)?.is_some()
                {
                    return Err(ObservationProviderError::IdentityConflict);
                }
                let authority_delta = u64::from(!authority_row_exists(transaction, &id)?);
                enforce_admission_capacity(
                    transaction,
                    1,
                    authority_delta,
                    1,
                    1,
                    1,
                    admission_limits,
                )?;
                reserve_previsible_operation_capacity(transaction, previsible_limits)?;
                let incarnation = allocate_incarnation(
                    transaction,
                    &id,
                    ObservationIdentityClass::Component,
                    None,
                )?;
                let digest = declaration.digest_for(
                    &id,
                    ObservationIdentityClass::Component,
                    incarnation,
                )?;
                transaction.execute(
                    "INSERT INTO observation_identity_operations
                        (operation_id,kind,phase,is_active,retain_until_ms,
                         termination_emission_receipt_set_digest)
                     VALUES (?1,'register-component','prepared',1,NULL,NULL)",
                    params![operation_id],
                )?;
                insert_authority_and_identity(
                    transaction,
                    &id,
                    ObservationIdentityClass::Component,
                    incarnation,
                    digest,
                    "pending",
                    false,
                    Some(&operation_id),
                    None,
                    None,
                )?;
                transaction.execute(
                    "INSERT INTO observation_identity_operation_members
                        (operation_id,identity_id,identity_class,identity_incarnation,
                         declaration_digest,gc_phase,gc_generation,
                         gc_challenge_consumed,is_active)
                     VALUES (?1,?2,'component',?3,?4,'idle',0,0,1)",
                    params![
                        operation_id,
                        id,
                        incarnation as i64,
                        digest.as_bytes().as_slice(),
                    ],
                )?;
                transaction.execute(
                    "INSERT INTO components
                        (id,component_type,submit_config_json,submitter,submitted_at_ms,
                         interval_ms,expected_next_fire_at_ms,last_fire_at_ms,
                         sensitive_params,identity_incarnation,declaration_digest,
                         lifecycle_state,catalog_visible,operation_id,tombstoned_at_ms,
                         retain_until_ms)
                     VALUES (?1,?2,?3,?4,?5,?6,NULL,NULL,?7,?8,?9,'live',0,?10,NULL,NULL)",
                    params![
                        id,
                        component_type,
                        stored_json,
                        submitter,
                        submitted_at_ms,
                        interval_ms,
                        sensitive_params_tail,
                        incarnation as i64,
                        digest.as_bytes().as_slice(),
                        operation_id,
                    ],
                )?;
                Ok(ObservationIdentityClaims {
                    exact_id: id,
                    expected_class: ObservationIdentityClass::Component,
                    incarnation,
                    declaration_digest: digest,
                })
            })
            .await?;
        let ledger = self.current_anchor_tuple().await?;
        self.verifier
            .issue_committed_component_receipt(claims, receipt_operation_id, ledger.sequence)
            .map_err(ObservationProviderError::from)
    }

    fn begin_agent_registration_journaled(
        &self,
        operation_id: &str,
        exact_agent_id: &str,
    ) -> Result<(), ObservationProviderError> {
        validate_operation_id(operation_id)?;
        validate_ordinary_identity_id(exact_agent_id)?;
        let operation_id = operation_id.to_owned();
        let exact_agent_id = exact_agent_id.to_owned();
        let discriminator = operation_id.as_bytes().to_vec();
        let admission_limits = self.admission_capacity_limits()?;
        let previsible_limits = self.previsible_capacity_limits()?;
        self.anchored_mutation_sync(2, &discriminator, move |transaction| {
            if operation_exists(transaction, &operation_id)?
                || read_identity_claims(transaction, &exact_agent_id)?.is_some()
            {
                return Err(ObservationProviderError::IdentityConflict);
            }
            let authority_delta = u64::from(!authority_row_exists(transaction, &exact_agent_id)?);
            enforce_admission_capacity(transaction, 1, authority_delta, 1, 1, 1, admission_limits)?;
            reserve_previsible_operation_capacity(transaction, previsible_limits)?;
            let incarnation = allocate_incarnation(
                transaction,
                &exact_agent_id,
                ObservationIdentityClass::Agent,
                None,
            )?;
            let digest = SensitiveParamDeclaration::agent_known_empty().digest_for(
                &exact_agent_id,
                ObservationIdentityClass::Agent,
                incarnation,
            )?;
            transaction.execute(
                "INSERT INTO observation_identity_operations
                    (operation_id,kind,phase,is_active,retain_until_ms,
                     termination_emission_receipt_set_digest)
                 VALUES (?1,'register-agent','prepared',1,NULL,NULL)",
                params![operation_id],
            )?;
            insert_authority_and_identity(
                transaction,
                &exact_agent_id,
                ObservationIdentityClass::Agent,
                incarnation,
                digest,
                "pending",
                false,
                Some(&operation_id),
                None,
                None,
            )?;
            transaction.execute(
                "INSERT INTO observation_identity_operation_members
                    (operation_id,identity_id,identity_class,identity_incarnation,
                     declaration_digest,gc_phase,gc_generation,
                     gc_challenge_consumed,is_active)
                 VALUES (?1,?2,'agent',?3,?4,'idle',0,0,1)",
                params![
                    operation_id,
                    exact_agent_id,
                    incarnation as i64,
                    digest.as_bytes().as_slice(),
                ],
            )?;
            Ok(())
        })
    }

    fn activate_agent_registration(
        &self,
        operation_id: &str,
    ) -> Result<PrevisibleObservationActivation, ObservationProviderError> {
        validate_operation_id(operation_id)?;
        let (claims, registry_sequence) = {
            let conn = self.registry.conn.try_lock().map_err(|_| {
                ObservationProviderError::Catalog(SensitiveParamCatalogError::StorageUnavailable)
            })?;
            let id: String = conn
                .query_row(
                    "SELECT m.identity_id
                     FROM observation_identity_operations o
                     JOIN observation_identity_operation_members m
                       ON m.operation_id=o.operation_id
                     JOIN observation_identities i ON i.id=m.identity_id
                     WHERE o.operation_id=?1 AND o.kind='register-agent'
                       AND o.phase='prepared' AND o.is_active=1
                       AND m.identity_class='agent' AND m.is_active=1
                       AND i.lifecycle_state='pending' AND i.catalog_visible=0",
                    params![operation_id],
                    |row| row.get(0),
                )
                .optional()?
                .ok_or(ObservationProviderError::UnknownIdentity)?;
            let claims = read_identity_claims(&conn, &id)?
                .ok_or(ObservationProviderError::UnknownIdentity)?;
            let registry_sequence = read_ledger(&conn)?
                .ok_or_else(|| {
                    ObservationProviderError::RecoveryRequired("missing ledger".to_owned())
                })?
                .sequence;
            (claims, registry_sequence)
        };
        let activation = self.verifier.begin_agent_activation(
            operation_id.to_owned(),
            claims,
            registry_sequence,
        )?;
        let record = self.verifier.inspect_agent_activation(&activation)?;
        if let Some(prepared) = self.find_prepared_previsible_activation(&record)? {
            return self
                .verifier
                .rehydrate_agent_activation(&prepared)
                .map_err(ObservationProviderError::from);
        }
        let discriminator = record.activation_nonce;
        let config = self.config.clone();
        self.anchored_mutation_sync(3, &discriminator, move |transaction| {
            persist_previsible_activation(
                transaction,
                &record,
                config.registry_instance,
                config.boot,
            )
        })?;
        Ok(activation)
    }

    async fn initialize_or_recover_normal_provider(
        registry: Arc<ComponentRegistry>,
        anchor: Arc<dyn RegistryAnchorTransaction>,
        config: ObservationProviderConfig,
    ) -> Result<(), ObservationProviderError> {
        let registry_for_initialization = Arc::clone(&registry);
        let _mutation_guard = registry.observation_mutation_lock.lock().await;
        let conn = Arc::clone(&registry.conn);
        let db_path = registry.database_path().to_path_buf();
        tokio::task::spawn_blocking(move || -> Result<(), ObservationProviderError> {
            let mut conn = conn.blocking_lock();
            // The external custody world is authoritative over whether this
            // database may take the greenfield path.  Probe it before schema
            // activation (or any other SQLite write): an initialized anchor
            // without its exact durable ledger is recovery-required, never a
            // fresh database.
            let initial_anchor = anchor.observe();
            let existing_ledger = if sqlite_table_exists(&conn, "observation_identity_ledger")? {
                read_ledger(&conn)?
            } else {
                None
            };
            match (&initial_anchor, &existing_ledger) {
                (Ok(_), None) => {
                    return Err(ObservationProviderError::RecoveryRequired(
                        "initialized external anchor has no matching durable SQLite ledger"
                            .to_owned(),
                    ));
                }
                (Err(RegistryAnchorError::Uninitialized), _) | (Ok(_), Some(_)) => {}
                (Err(error), _) => return Err(error.clone().into()),
            }
            activate_observation_component_schema(&conn)?;
            verify_observation_schema_fingerprint(&conn)?;
            let (authenticated_keyring_root, keyring_projection) =
                authenticated_persisted_keyring_projection(
                    &config.authenticated_persisted_keyring_file,
                    config.registry_instance,
                )?;
            if let Some(ledger) = existing_ledger {
                if ledger.registry_instance != config.registry_instance
                    || ledger.keyring_root != authenticated_keyring_root
                    || ledger.role_allocation_root != config.role_allocation_root
                    || ledger.migration_digest != config.migration_digest
                {
                    return Err(ObservationProviderError::RecoveryRequired(
                        "provider construction roots do not match the durable ledger".to_owned(),
                    ));
                }
                verify_keyring_configuration(&conn, &config, &keyring_projection)?;
                let context = read_head_context(&conn)?;
                match (
                    config.migration_installed_marker_root,
                    config.migration_marker_root,
                ) {
                    (None, None)
                        if context.previous_marker_root == greenfield_marker_root() =>
                    {}
                    (Some(installed), Some(_))
                        if context.previous_marker_root == installed =>
                    {
                        return Err(ObservationProviderError::RecoveryRequired(
                            "Installed legacy state requires the move-only carrier coordinator; a normal provider is not constructed"
                                .to_owned(),
                        ));
                    }
                    (Some(_), Some(complete))
                        if context.previous_marker_root == complete =>
                    {}
                    _ => {
                        return Err(ObservationProviderError::RecoveryRequired(
                            "normal provider construction marker does not match greenfield or Complete durable head context"
                                .to_owned(),
                        ))
                    }
                };
                if context.manifest_key_epoch != config.registry_manifest_key_epoch {
                    return Err(ObservationProviderError::RecoveryRequired(
                        "provider construction marker/manifest epoch does not match durable head context"
                            .to_owned(),
                    ));
                }
                reconcile_external_anchor(anchor.as_ref(), &ledger)?;
                verify_complete_roots(&conn, &ledger)?;
                validate_durable_invariants(&conn)?;
                recover_durable_inflight_rows(
                    &mut conn,
                    &db_path,
                    anchor.as_ref(),
                    config.registry_instance,
                    config.boot,
                )?;
                validate_durable_invariants(&conn)?;
                return Ok(());
            }

            if config.migration_marker_root.is_some() {
                return Err(ObservationProviderError::RecoveryRequired(
                    "authenticated legacy migration must install its exact target before provider open"
                        .to_owned(),
                ));
            }

            let transaction = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            #[cfg(any(test, feature = "test-support"))]
            apply_greenfield_schema_adversary_if_armed(
                &transaction,
                config.registry_instance,
                GreenfieldSchemaAdversaryStage::BeforeLockedPreimageValidation,
            )?;
            // The outer probe is only an early diagnostic. Re-establish the
            // exact schema and empty durable invariants after BEGIN IMMEDIATE
            // owns the write boundary, before the first greenfield write.
            verify_observation_schema_fingerprint(&transaction)?;
            validate_durable_invariants(&transaction)?;
            if keyring_projection.manifest_key_epoch != config.registry_manifest_key_epoch {
                return Err(ObservationProviderError::RecoveryRequired(
                    "greenfield keyring and registry manifest epochs differ".to_owned(),
                ));
            }
            apply_keyring_projection(&transaction, &keyring_projection)?;
            verify_keyring_configuration(&transaction, &config, &keyring_projection)?;
            let state_root = compute_state_root(&transaction)?;
            let keyring_root = authenticated_keyring_root;
            let head = genesis_head(
                config.registry_instance,
                state_root,
                keyring_root,
                config.role_allocation_root,
                config.migration_digest,
            );
            let genesis = RegistryAnchorTuple {
                registry_instance: config.registry_instance,
                sequence: 0,
                head,
                state_root,
                keyring_root,
                role_allocation_root: config.role_allocation_root,
                migration_digest: config.migration_digest,
            };
            let removed_keys = transaction.execute(
                "DELETE FROM observation_persisted_keyring_entries",
                [],
            )?;
            if removed_keys != keyring_projection.entries.len() {
                return Err(ObservationProviderError::RecoveryRequired(
                    "failed to restore the empty pre-genesis keyring".to_owned(),
                ));
            }
            let witness = registry_for_initialization
                .issue_verified_empty_genesis(&transaction, genesis.clone())?;
            apply_keyring_projection(&transaction, &keyring_projection)?;
            write_head_context(
                &transaction,
                greenfield_marker_root(),
                config.registry_manifest_key_epoch,
            )?;
            write_ledger(&transaction, &genesis)?;
            #[cfg(any(test, feature = "test-support"))]
            apply_greenfield_schema_adversary_if_armed(
                &transaction,
                config.registry_instance,
                GreenfieldSchemaAdversaryStage::BeforeFinalPostimageValidation,
            )?;
            // Pin the exact final schema and full rooted postimage while the
            // same IMMEDIATE transaction still excludes concurrent writers.
            verify_observation_schema_fingerprint(&transaction)?;
            validate_durable_invariants(&transaction)?;
            verify_complete_roots(&transaction, &genesis)?;
            transaction.commit()?;
            checkpoint_and_sync_registry(&conn, &db_path)?;
            anchor.initialize_compact(witness)?;
            let external = anchor.observe()?;
            if classify_recovery(&external, &genesis)? != RegistryRecoveryDecision::Clean {
                return Err(ObservationProviderError::RecoveryRequired(
                    "greenfield anchor did not settle in compact-current".to_owned(),
                ));
            }
            Ok(())
        })
        .await
        .map_err(|error| ObservationProviderError::Join(error.to_string()))?
    }

    async fn reload_view(&self) -> Result<(), ObservationProviderError> {
        let conn = Arc::clone(&self.registry.conn);
        let revision = self.next_revision()?;
        let rows = tokio::task::spawn_blocking(move || load_view_rows(&conn, revision))
            .await
            .map_err(|error| ObservationProviderError::Join(error.to_string()))??;
        self.publish_view(rows, revision)
    }

    fn next_revision(&self) -> Result<u64, ObservationProviderError> {
        self.revision
            .load(Ordering::Acquire)
            .checked_add(1)
            .ok_or_else(|| {
                ObservationProviderError::RecoveryRequired("watch revision exhausted".to_owned())
            })
    }

    fn publish_view(
        &self,
        rows: BTreeMap<String, IdentityViewRow>,
        revision: u64,
    ) -> Result<(), ObservationProviderError> {
        let mut view = self.view.write().map_err(|_| {
            ObservationProviderError::RecoveryRequired("catalog view lock poisoned".to_owned())
        })?;
        let unchanged = view.len() == rows.len()
            && view
                .iter()
                .zip(rows.iter())
                .all(|((left_key, left), (right_key, right))| {
                    left_key == right_key
                        && left.lifecycle == right.lifecycle
                        && left.snapshot.canonical_component_id
                            == right.snapshot.canonical_component_id
                        && left.snapshot.identity_class == right.snapshot.identity_class
                        && left.snapshot.incarnation == right.snapshot.incarnation
                        && left.snapshot.declaration_digest == right.snapshot.declaration_digest
                        && left.snapshot.names == right.snapshot.names
                });
        if unchanged {
            return Ok(());
        }
        *view = rows;
        self.revision.store(revision, Ordering::Release);
        self.revision_tx.send_replace(revision);
        Ok(())
    }

    async fn anchored_mutation<T, F>(
        &self,
        operation_tag: u8,
        write_discriminator: Vec<u8>,
        mutation: F,
    ) -> Result<T, ObservationProviderError>
    where
        T: Send + 'static,
        F: FnOnce(&Transaction<'_>) -> Result<T, ObservationProviderError> + Send + 'static,
    {
        if !self.is_ready() {
            return Err(ObservationProviderError::RecoveryRequired(
                "provider is not ready".to_owned(),
            ));
        }
        let _mutation_guard = self.registry.observation_mutation_lock.lock().await;
        let conn = Arc::clone(&self.registry.conn);
        let db_path = self.registry.database_path().to_path_buf();
        let anchor = Arc::clone(&self.anchor);
        #[cfg(any(test, feature = "test-support"))]
        let test_controls = Arc::clone(&self.test_controls);
        let result = tokio::task::spawn_blocking(move || -> Result<T, ObservationProviderError> {
            let mut conn = conn.blocking_lock();
            run_anchored_mutation_on_connection(
                &mut conn,
                &db_path,
                anchor.as_ref(),
                operation_tag,
                &write_discriminator,
                #[cfg(any(test, feature = "test-support"))]
                Some(test_controls.as_ref()),
                mutation,
            )
        })
        .await
        .map_err(|error| ObservationProviderError::Join(error.to_string()))?;

        if let Err(error) = &result {
            if error.gates_provider() {
                self.ready.store(false, Ordering::Release);
            }
            return result;
        }
        if let Err(error) = self.reload_view().await {
            self.ready.store(false, Ordering::Release);
            return Err(error);
        }
        result
    }

    /// Synchronous twin used only by the object-safe host ports, whose ratified
    /// signatures are synchronous.  It never blocks a Tokio worker waiting for
    /// another registry user: concurrent ownership is rejected as unavailable
    /// and callers retry through their typed recovery path.
    fn anchored_mutation_sync<T, F>(
        &self,
        operation_tag: u8,
        write_discriminator: &[u8],
        mutation: F,
    ) -> Result<T, ObservationProviderError>
    where
        F: FnOnce(&Transaction<'_>) -> Result<T, ObservationProviderError>,
    {
        if !self.ready.load(Ordering::Acquire) {
            return Err(ObservationProviderError::RecoveryRequired(
                "provider is not ready".to_owned(),
            ));
        }
        let _mutation_guard = self
            .registry
            .observation_mutation_lock
            .try_lock()
            .map_err(|_| ObservationProviderError::Busy)?;
        let mut conn = self
            .registry
            .conn
            .try_lock()
            .map_err(|_| ObservationProviderError::Busy)?;
        let result = run_anchored_mutation_on_connection(
            &mut conn,
            self.registry.database_path(),
            self.anchor.as_ref(),
            operation_tag,
            write_discriminator,
            #[cfg(any(test, feature = "test-support"))]
            Some(self.test_controls.as_ref()),
            mutation,
        );
        if let Err(error) = &result {
            if error.gates_provider() {
                self.ready.store(false, Ordering::Release);
            }
            return result;
        }
        let revision = match self.next_revision() {
            Ok(revision) => revision,
            Err(error) => {
                self.ready.store(false, Ordering::Release);
                return Err(error);
            }
        };
        let rows = match load_view_rows_from_connection(&conn, revision) {
            Ok(rows) => rows,
            Err(error) => {
                self.ready.store(false, Ordering::Release);
                return Err(error);
            }
        };
        if let Err(error) = self.publish_view(rows, revision) {
            self.ready.store(false, Ordering::Release);
            return Err(error);
        }
        result
    }

    fn require_persisted_key_status(
        &self,
        key_id: u32,
        signing_required: bool,
    ) -> Result<(), SensitiveParamCatalogError> {
        if !self.is_ready() {
            return Err(SensitiveParamCatalogError::RecoveryRequired);
        }
        let _mutation_guard = self
            .registry
            .observation_mutation_lock
            .try_lock()
            .map_err(|_| SensitiveParamCatalogError::StorageUnavailable)?;
        let conn = self
            .registry
            .conn
            .try_lock()
            .map_err(|_| SensitiveParamCatalogError::StorageUnavailable)?;
        let result = (|| -> Result<(), ObservationProviderError> {
            let ledger = read_ledger(&conn)?.ok_or_else(|| {
                ObservationProviderError::RecoveryRequired("missing identity ledger".to_owned())
            })?;
            reconcile_external_anchor(self.anchor.as_ref(), &ledger)?;
            verify_complete_roots(&conn, &ledger)?;
            validate_durable_invariants(&conn)?;
            let status: Option<String> = conn
                .query_row(
                    "SELECT status FROM observation_persisted_keyring_entries WHERE key_id=?1",
                    params![i64::from(key_id)],
                    |row| row.get(0),
                )
                .optional()?;
            match (signing_required, status.as_deref()) {
                (true, Some("signing")) | (false, Some("signing" | "verify-only")) => Ok(()),
                _ => Err(ObservationProviderError::Catalog(
                    SensitiveParamCatalogError::InvalidCarrier,
                )),
            }
        })();
        if let Err(error) = &result {
            if error.gates_provider() {
                self.ready.store(false, Ordering::Release);
            }
        }
        result.map_err(|error| error.as_catalog_error())
    }

    fn recover_previsible_phase(
        &self,
        record: &ProviderActivationRecord,
        metadata: &ReadyProofJournalMetadata,
    ) -> Result<String, SensitiveParamCatalogError> {
        let _mutation_guard = self
            .registry
            .observation_mutation_lock
            .try_lock()
            .map_err(|_| SensitiveParamCatalogError::StorageUnavailable)?;
        let conn = self
            .registry
            .conn
            .try_lock()
            .map_err(|_| SensitiveParamCatalogError::StorageUnavailable)?;
        let result = (|| -> Result<String, ObservationProviderError> {
            let ledger = read_ledger(&conn)?.ok_or_else(|| {
                ObservationProviderError::RecoveryRequired("missing identity ledger".to_owned())
            })?;
            reconcile_external_anchor(self.anchor.as_ref(), &ledger)?;
            verify_complete_roots(&conn, &ledger)?;
            validate_durable_invariants(&conn)?;
            let persisted: (
                String,
                Option<Vec<u8>>,
                Option<Vec<u8>>,
                Option<Vec<u8>>,
                Option<Vec<u8>>,
                Option<Vec<u8>>,
            ) = conn
                .query_row(
                    "SELECT phase,subject_receipt_digest,table_receipt_digest,
                            lifecycle_receipt_digest,ready_proof_nonce,recovery_nonce
                     FROM observation_previsible_activations
                     WHERE activation_nonce=?1 AND operation_id=?2 AND identity_id=?3
                       AND identity_class=?4 AND identity_incarnation=?5
                       AND declaration_digest=?6",
                    params![
                        record.activation_nonce.as_slice(),
                        record.operation_id,
                        record.claims.exact_id,
                        class_to_sql(record.claims.expected_class),
                        record.claims.incarnation as i64,
                        record.claims.declaration_digest.as_bytes().as_slice(),
                    ],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                            row.get(5)?,
                        ))
                    },
                )
                .optional()?
                .ok_or_else(|| {
                    ObservationProviderError::RecoveryRequired(
                        "previsible recovery row is missing".to_owned(),
                    )
                })?;
            let (phase, subject, table, lifecycle, proof_nonce, recovery_nonce) = persisted;
            if phase != "prepared"
                && (subject.as_deref() != Some(metadata.subject_receipt_digest.as_slice())
                    || table.as_deref() != Some(metadata.table_receipt_digest.as_slice())
                    || lifecycle.as_deref() != Some(metadata.lifecycle_receipt_digest.as_slice())
                    || proof_nonce.as_deref() != Some(metadata.proof_nonce.as_slice())
                    || recovery_nonce.as_deref() != Some(metadata.recovery_nonce.as_slice()))
            {
                return Err(ObservationProviderError::RecoveryRequired(
                    "typed publication recovery metadata differs from the durable journal"
                        .to_owned(),
                ));
            }
            let revision = self.next_revision()?;
            let rows = load_view_rows_from_connection(&conn, revision)?;
            self.publish_view(rows, revision)?;
            Ok(phase)
        })();
        if let Err(error) = &result {
            if error.gates_provider() {
                self.ready.store(false, Ordering::Release);
            }
        }
        result.map_err(|error| error.as_catalog_error())
    }

    /// Locate the exact durable hidden activation for an idempotent issuer
    /// retry.  Only Prepared can be rehydrated: later phases are owned by the
    /// typed publication/abort recovery paths.
    fn find_prepared_previsible_activation(
        &self,
        expected: &ProviderActivationRecord,
    ) -> Result<Option<ProviderActivationRecord>, ObservationProviderError> {
        let _mutation_guard = self
            .registry
            .observation_mutation_lock
            .try_lock()
            .map_err(|_| ObservationProviderError::Busy)?;
        let conn = self.registry.conn.try_lock().map_err(|_| {
            ObservationProviderError::Catalog(SensitiveParamCatalogError::StorageUnavailable)
        })?;
        let ledger = read_ledger(&conn)?.ok_or_else(|| {
            ObservationProviderError::RecoveryRequired("missing identity ledger".to_owned())
        })?;
        reconcile_external_anchor(self.anchor.as_ref(), &ledger)?;
        verify_complete_roots(&conn, &ledger)?;
        validate_durable_invariants(&conn)?;
        let row: Option<(Vec<u8>, i64, String, i64, Vec<u8>, Vec<u8>)> = conn
            .query_row(
                "SELECT activation_nonce,registry_sequence,phase,role,
                        registry_instance_id,boot_id
                 FROM observation_previsible_activations
                 WHERE operation_id=?1 AND identity_id=?2 AND identity_class=?3
                   AND identity_incarnation=?4 AND declaration_digest=?5",
                params![
                    expected.operation_id,
                    expected.claims.exact_id,
                    class_to_sql(expected.claims.expected_class),
                    expected.claims.incarnation as i64,
                    expected.claims.declaration_digest.as_bytes().as_slice(),
                ],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .optional()?;
        let Some((nonce, sequence, phase, role, registry_instance, boot)) = row else {
            return Ok(None);
        };
        let expected_role = expected.kind as i64;
        if phase != "prepared"
            || role != expected_role
            || registry_instance.as_slice() != self.config.registry_instance
            || boot.as_slice() != self.config.boot
        {
            return Err(ObservationProviderError::RecoveryRequired(
                "existing previsible activation is not an exact rehydratable Prepared row"
                    .to_owned(),
            ));
        }
        let activation_nonce: [u8; 32] = nonce.try_into().map_err(|_| {
            ObservationProviderError::RecoveryRequired(
                "prepared previsible activation nonce has invalid width".to_owned(),
            )
        })?;
        let registry_sequence = u64::try_from(sequence).map_err(|_| {
            ObservationProviderError::RecoveryRequired(
                "prepared previsible activation sequence is invalid".to_owned(),
            )
        })?;
        Ok(Some(ProviderActivationRecord {
            kind: expected.kind,
            activation_nonce,
            operation_id: expected.operation_id.clone(),
            claims: expected.claims.clone(),
            registry_sequence,
        }))
    }

    fn current_registry_sequence_sync(&self) -> Result<u64, ObservationProviderError> {
        let conn = self.registry.conn.try_lock().map_err(|_| {
            ObservationProviderError::Catalog(SensitiveParamCatalogError::StorageUnavailable)
        })?;
        Ok(read_ledger(&conn)?
            .ok_or_else(|| {
                ObservationProviderError::RecoveryRequired("missing identity ledger".to_owned())
            })?
            .sequence)
    }

    fn load_agent_termination_candidate(
        &self,
        operation_id: &str,
        exact_agent_ids: &[String],
    ) -> Result<
        (TerminationOperationRecord, Vec<ObservationIdentityClaims>),
        ObservationProviderError,
    > {
        validate_operation_id(operation_id)?;
        if exact_agent_ids.is_empty() || exact_agent_ids.len() > 4096 {
            return Err(ObservationProviderError::InvalidInput(
                "termination member set must contain 1..=4096 agents".to_owned(),
            ));
        }
        let _mutation_guard = self
            .registry
            .observation_mutation_lock
            .try_lock()
            .map_err(|_| ObservationProviderError::Busy)?;
        let conn = self.registry.conn.try_lock().map_err(|_| {
            ObservationProviderError::Catalog(SensitiveParamCatalogError::StorageUnavailable)
        })?;
        let ledger = read_ledger(&conn)?.ok_or_else(|| {
            ObservationProviderError::RecoveryRequired("missing identity ledger".to_owned())
        })?;
        reconcile_external_anchor(self.anchor.as_ref(), &ledger)?;
        verify_complete_roots(&conn, &ledger)?;
        validate_durable_invariants(&conn)?;
        if operation_exists(&conn, operation_id)? {
            return Err(ObservationProviderError::IdentityConflict);
        }
        let mut members = Vec::with_capacity(exact_agent_ids.len());
        let mut previous_id: Option<&[u8]> = None;
        let mut ordered_ids = exact_agent_ids.iter().collect::<Vec<_>>();
        ordered_ids.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        for id in ordered_ids {
            validate_ordinary_identity_id(id)?;
            if previous_id == Some(id.as_bytes()) {
                return Err(ObservationProviderError::InvalidInput(
                    "termination member set contains a duplicate id".to_owned(),
                ));
            }
            previous_id = Some(id.as_bytes());
            let claims = read_identity_claims(&conn, id)?
                .ok_or(ObservationProviderError::UnknownIdentity)?;
            let exact: i64 = conn.query_row(
                "SELECT COUNT(*) FROM observation_identities
                 WHERE id=?1 AND class='agent' AND incarnation=?2
                   AND declaration_digest=?3 AND lifecycle_state='live'
                   AND catalog_visible=1 AND operation_id IS NULL",
                params![
                    claims.exact_id,
                    claims.incarnation as i64,
                    claims.declaration_digest.as_bytes().as_slice(),
                ],
                |row| row.get(0),
            )?;
            if claims.expected_class != ObservationIdentityClass::Agent || exact != 1 {
                return Err(ObservationProviderError::InvalidState(
                    "termination member is not one exact live agent".to_owned(),
                ));
            }
            members.push(claims);
        }
        let registry_sequence = ledger
            .sequence
            .checked_add(1)
            .filter(|sequence| *sequence <= i64::MAX as u64)
            .ok_or_else(|| {
                ObservationProviderError::CapacityExceeded("registry sequence exhausted".to_owned())
            })?;
        Ok((
            TerminationOperationRecord {
                operation_id: operation_id.to_owned(),
                member_set_digest: termination_member_set_digest(&members)?,
                registry_sequence,
            },
            members,
        ))
    }

    fn load_component_termination_candidate(
        &self,
        operation_id: &str,
        expected: &ObservationIdentityClaims,
    ) -> Result<
        (TerminationOperationRecord, Vec<ObservationIdentityClaims>),
        ObservationProviderError,
    > {
        validate_operation_id(operation_id)?;
        if expected.expected_class != ObservationIdentityClass::Component {
            return Err(ObservationProviderError::InvalidInput(
                "component termination requires Component authority".to_owned(),
            ));
        }
        let _mutation_guard = self
            .registry
            .observation_mutation_lock
            .try_lock()
            .map_err(|_| ObservationProviderError::Busy)?;
        let conn = self.registry.conn.try_lock().map_err(|_| {
            ObservationProviderError::Catalog(SensitiveParamCatalogError::StorageUnavailable)
        })?;
        let ledger = read_ledger(&conn)?.ok_or_else(|| {
            ObservationProviderError::RecoveryRequired("missing identity ledger".to_owned())
        })?;
        reconcile_external_anchor(self.anchor.as_ref(), &ledger)?;
        verify_complete_roots(&conn, &ledger)?;
        validate_durable_invariants(&conn)?;
        if operation_exists(&conn, operation_id)? {
            return Err(ObservationProviderError::IdentityConflict);
        }
        require_exact_catalog_claims(&conn, expected, true)?;
        let exact_component: i64 = conn.query_row(
            "SELECT COUNT(*) FROM components
             WHERE id=?1 AND identity_incarnation=?2 AND declaration_digest=?3
               AND lifecycle_state='live' AND catalog_visible=1
               AND operation_id IS NULL",
            params![
                expected.exact_id,
                expected.incarnation as i64,
                expected.declaration_digest.as_bytes().as_slice(),
            ],
            |row| row.get(0),
        )?;
        if exact_component != 1 {
            return Err(ObservationProviderError::InvalidState(
                "component termination target is not exact live".to_owned(),
            ));
        }
        let registry_sequence = ledger
            .sequence
            .checked_add(1)
            .filter(|sequence| *sequence <= i64::MAX as u64)
            .ok_or_else(|| {
                ObservationProviderError::CapacityExceeded("registry sequence exhausted".to_owned())
            })?;
        let members = vec![expected.clone()];
        Ok((
            TerminationOperationRecord {
                operation_id: operation_id.to_owned(),
                member_set_digest: termination_member_set_digest(&members)?,
                registry_sequence,
            },
            members,
        ))
    }

    fn termination_rejected(
        &self,
        record: TerminationOperationRecord,
    ) -> TerminationPrepareFailure {
        self.termination_state
            .prepare_rejected(record.clone())
            .unwrap_or_else(|_| {
                self.termination_state.reject_invalid_prepare_request(
                    &record.operation_id,
                    record.member_set_digest,
                    record.registry_sequence.saturating_sub(1),
                )
            })
    }

    fn termination_unknown(&self, record: TerminationOperationRecord) -> TerminationPrepareFailure {
        self.termination_state
            .prepare_outcome_unknown(record.clone())
            .unwrap_or_else(|_| {
                self.termination_state.reject_invalid_prepare_request(
                    &record.operation_id,
                    record.member_set_digest,
                    record.registry_sequence.saturating_sub(1),
                )
            })
    }

    fn recover_termination_prepare_ack(
        &self,
        record: &TerminationOperationRecord,
        operation_kind: &str,
        expected_class: ObservationIdentityClass,
    ) -> Result<Option<TerminationPrepareCommitAck>, ObservationProviderError> {
        let _mutation_guard = self
            .registry
            .observation_mutation_lock
            .try_lock()
            .map_err(|_| ObservationProviderError::Busy)?;
        let conn = self.registry.conn.try_lock().map_err(|_| {
            ObservationProviderError::Catalog(SensitiveParamCatalogError::StorageUnavailable)
        })?;
        let ledger = read_ledger(&conn)?.ok_or_else(|| {
            ObservationProviderError::RecoveryRequired("missing identity ledger".to_owned())
        })?;
        reconcile_external_anchor(self.anchor.as_ref(), &ledger)?;
        verify_complete_roots(&conn, &ledger)?;
        validate_durable_invariants(&conn)?;
        let row: Option<(String, i64, String, Vec<u8>, Vec<u8>, i64, Vec<u8>)> = conn
            .query_row(
                "SELECT o.phase,o.is_active,f.phase,f.prepare_ack_digest,
                        f.prepare_ack_nonce,f.prepare_sequence,f.member_set_digest
                 FROM observation_identity_operations o
                 JOIN observation_termination_finalizations f
                   ON f.operation_id=o.operation_id
                 WHERE o.operation_id=?1 AND o.kind=?2
                   AND f.operation_kind=?2
                   AND f.registry_instance_id=?3 AND f.operation_boot_id=?4",
                params![
                    record.operation_id,
                    operation_kind,
                    self.config.registry_instance.as_slice(),
                    self.config.boot.as_slice(),
                ],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                    ))
                },
            )
            .optional()?;
        let Some((
            operation_phase,
            active,
            finalization_phase,
            stored_digest,
            nonce,
            sequence,
            member_digest,
        )) = row
        else {
            return Ok(None);
        };
        let claims = load_operation_member_claims(&conn, &record.operation_id)?;
        if claims.is_empty()
            || claims
                .iter()
                .any(|claims| claims.expected_class != expected_class)
            || termination_member_set_digest(&claims)? != record.member_set_digest
            || member_digest.as_slice() != record.member_set_digest
            || u64::try_from(sequence).ok() != Some(record.registry_sequence)
        {
            return Err(ObservationProviderError::RecoveryRequired(
                "termination prepare recovery record differs from durable operation".to_owned(),
            ));
        }
        if operation_phase != "prepared" || active != 1 || finalization_phase != "prepared" {
            return Ok(None);
        }
        let nonce: [u8; 32] = nonce.try_into().map_err(|_| {
            ObservationProviderError::RecoveryRequired(
                "termination prepare acknowledgement nonce has invalid width".to_owned(),
            )
        })?;
        let prepared = self
            .termination_state
            .rehydrate_prepare_ack(record.clone(), nonce)?;
        let digest = self.termination_state.prepare_ack_digest(&prepared)?;
        if stored_digest.as_slice() != digest {
            return Err(ObservationProviderError::RecoveryRequired(
                "rehydrated termination prepare acknowledgement differs from journal".to_owned(),
            ));
        }
        Ok(Some(prepared))
    }

    fn recover_termination_operation(
        &self,
        record: &TerminationOperationRecord,
        operation_kind: &str,
        expected_class: ObservationIdentityClass,
    ) -> Result<(), SensitiveParamCatalogError> {
        let _mutation_guard = self
            .registry
            .observation_mutation_lock
            .try_lock()
            .map_err(|_| SensitiveParamCatalogError::StorageUnavailable)?;
        let conn = self
            .registry
            .conn
            .try_lock()
            .map_err(|_| SensitiveParamCatalogError::StorageUnavailable)?;
        let result = (|| -> Result<(), ObservationProviderError> {
            let ledger = read_ledger(&conn)?.ok_or_else(|| {
                ObservationProviderError::RecoveryRequired("missing identity ledger".to_owned())
            })?;
            reconcile_external_anchor(self.anchor.as_ref(), &ledger)?;
            verify_complete_roots(&conn, &ledger)?;
            validate_durable_invariants(&conn)?;
            let exists: i64 = conn.query_row(
                "SELECT COUNT(*) FROM observation_identity_operations o
                 WHERE o.operation_id=?1 AND o.kind=?2
                   AND (SELECT COUNT(*)
                        FROM observation_identity_operation_members m
                        WHERE m.operation_id=o.operation_id
                          AND m.identity_class=?3) > 0
                   AND NOT EXISTS (
                        SELECT 1 FROM observation_identity_operation_members m
                        WHERE m.operation_id=o.operation_id
                          AND m.identity_class<>?3)",
                params![
                    record.operation_id,
                    operation_kind,
                    class_to_sql(expected_class)
                ],
                |row| row.get(0),
            )?;
            if exists != 1 {
                return Err(ObservationProviderError::Catalog(
                    SensitiveParamCatalogError::StaleIdentity,
                ));
            }
            let revision = self.next_revision()?;
            let rows = load_view_rows_from_connection(&conn, revision)?;
            self.publish_view(rows, revision)?;
            Ok(())
        })();
        if let Err(error) = &result {
            if error.gates_provider() {
                self.ready.store(false, Ordering::Release);
            }
        }
        result.map_err(|error| error.as_catalog_error())
    }

    fn termination_finalization_is_committed(
        &self,
        record: &TerminationOperationRecord,
        metadata: &VerifiedTerminationFinalizeJournalMetadata,
        operation_kind: &str,
        expected_class: ObservationIdentityClass,
    ) -> Result<bool, ObservationProviderError> {
        let conn = self.registry.conn.try_lock().map_err(|_| {
            ObservationProviderError::Catalog(SensitiveParamCatalogError::StorageUnavailable)
        })?;
        let claims = load_operation_member_claims(&conn, &record.operation_id)?;
        if claims.is_empty()
            || claims
                .iter()
                .any(|claims| claims.expected_class != expected_class)
            || termination_member_set_digest(&claims)? != record.member_set_digest
        {
            return Err(ObservationProviderError::RecoveryRequired(
                "termination recovery member set differs from typed record".to_owned(),
            ));
        }
        let prepared: i64 = conn.query_row(
            "SELECT COUNT(*)
             FROM observation_identity_operations o
             JOIN observation_termination_finalizations f
               ON f.operation_id=o.operation_id
             WHERE o.operation_id=?1 AND o.kind=?2
               AND o.phase='prepared' AND o.is_active=1
               AND f.operation_kind=?2 AND f.phase='prepared'
               AND f.registry_instance_id=?3 AND f.operation_boot_id=?4
               AND f.prepare_ack_digest=?5 AND f.prepare_ack_nonce=?6
               AND f.prepare_sequence=?7 AND f.member_set_digest=?8",
            params![
                record.operation_id,
                operation_kind,
                self.config.registry_instance.as_slice(),
                self.config.boot.as_slice(),
                metadata.prepare_ack_digest.as_slice(),
                metadata.prepare_ack_nonce.as_slice(),
                record.registry_sequence as i64,
                record.member_set_digest.as_slice(),
            ],
            |row| row.get(0),
        )?;
        if prepared == 1 {
            return Ok(false);
        }
        let finalized: i64 = conn.query_row(
            "SELECT COUNT(*)
             FROM observation_identity_operations o
             JOIN observation_termination_finalizations f
               ON f.operation_id=o.operation_id
             WHERE o.operation_id=?1 AND o.kind=?2
               AND o.phase='committed' AND o.is_active=0
               AND f.operation_kind=?2 AND f.phase='finalized'
               AND f.registry_instance_id=?3 AND f.operation_boot_id=?4
               AND f.prepare_ack_digest=?5 AND f.prepare_ack_nonce=?6
               AND f.prepare_sequence=?7 AND f.member_set_digest=?8
               AND f.cleanup_receipt_digest=?9
               AND f.cleanup_high_water_digest=?10
               AND f.cleanup_receipt_set_digest=?11 AND f.cleanup_nonce=?12
               AND f.finalize_recovery_nonce=?13 AND f.finalize_sequence>?7
               AND f.finalize_ack_digest=?14",
            params![
                record.operation_id,
                operation_kind,
                self.config.registry_instance.as_slice(),
                self.config.boot.as_slice(),
                metadata.prepare_ack_digest.as_slice(),
                metadata.prepare_ack_nonce.as_slice(),
                record.registry_sequence as i64,
                record.member_set_digest.as_slice(),
                metadata.cleanup_receipt_digest.as_slice(),
                metadata.cleanup_high_water_digest.as_slice(),
                metadata.cleanup_receipt_set_digest.as_slice(),
                metadata.cleanup_nonce.as_slice(),
                metadata.finalize_recovery_nonce.as_slice(),
                metadata.finalize_ack_digest.as_slice(),
            ],
            |row| row.get(0),
        )?;
        if finalized == 1 {
            Ok(true)
        } else {
            Err(ObservationProviderError::RecoveryRequired(
                "termination finalization recovery metadata does not match a durable phase"
                    .to_owned(),
            ))
        }
    }
}

impl Drop for RegistrySensitiveParamProvider {
    fn drop(&mut self) {
        self.ready.store(false, Ordering::Release);
        self.registry.release_observation_provider();
    }
}

#[derive(Clone, Debug)]
struct LegacyComponentMigrationRow {
    seq: u64,
    id: String,
    component_type: String,
    submit_config_json: String,
    submitter: String,
    submitted_at_ms: u64,
    interval_ms: Option<u64>,
    expected_next_fire_at_ms: Option<u64>,
    last_fire_at_ms: Option<u64>,
    sensitive_params: Vec<u8>,
    declaration_digest: DeclarationDigest,
}

fn install_or_recover_legacy_migration(
    conn: &mut Connection,
    db_path: &std::path::Path,
    anchor: &dyn RegistryAnchorTransaction,
    config: &ObservationProviderConfig,
    migration: PreparedLegacyRegistryMigration,
) -> Result<VerifiedLegacyAnchorInstalled, ObservationProviderError> {
    // Reauthenticate with the concrete anchor used by this provider before
    // reading or mutating SQLite.  An opaque plan minted by another (possibly
    // permissive) implementation is never trusted across this boundary.
    migration.authenticate_with(anchor)?;
    let initial_anchor = anchor.observe();
    let plan_binding = migration.plan_binding_digest();
    let existing_ledger = if sqlite_table_exists(conn, "observation_identity_ledger")? {
        read_ledger(conn)?
    } else {
        None
    };
    match (&initial_anchor, &existing_ledger) {
        (Ok(_), None) => {
            return Err(ObservationProviderError::RecoveryRequired(
                "initialized migration anchor has no matching durable SQLite ledger".to_owned(),
            ));
        }
        (Err(RegistryAnchorError::Uninitialized), _) | (Ok(_), Some(_)) => {}
        (Err(error), _) => return Err(error.clone().into()),
    }
    if let Some(ledger) = existing_ledger {
        let expected = migration_target_tuple(&migration);
        if ledger != expected {
            return Err(ObservationProviderError::RecoveryRequired(
                "installed legacy migration ledger differs from authenticated target".to_owned(),
            ));
        }
        let (keyring_root, keyring_projection) = authenticated_persisted_keyring_projection(
            &config.authenticated_persisted_keyring_file,
            config.registry_instance,
        )?;
        if keyring_root != ledger.keyring_root {
            return Err(ObservationProviderError::RecoveryRequired(
                "installed migration keyring differs from authenticated target".to_owned(),
            ));
        }
        verify_keyring_configuration(conn, config, &keyring_projection)?;
        verify_complete_roots(conn, &ledger)?;
        validate_durable_invariants(conn)?;
        let context = read_head_context(conn)?;
        if context.previous_marker_root != migration.prepared_marker_root()
            || context.manifest_key_epoch != migration.manifest_key_epoch()
        {
            return Err(ObservationProviderError::RecoveryRequired(
                "installed migration marker context differs from authenticated target".to_owned(),
            ));
        }
        let database = VerifiedLegacyDatabaseInstalled {
            plan_binding,
            tuple: ledger.clone(),
        };
        match initial_anchor {
            Ok(_) => reconcile_external_anchor(anchor, &ledger)?,
            Err(RegistryAnchorError::Uninitialized) => {
                let witness =
                    verified_legacy_migration_witness(&migration, ledger.clone(), db_path)?;
                anchor.initialize_migrated_compact(witness, migration)?;
            }
            Err(error) => return Err(error.into()),
        }
        let observed = anchor.observe()?;
        if classify_recovery(&observed, &ledger)? != RegistryRecoveryDecision::Clean {
            return Err(ObservationProviderError::RecoveryRequired(
                "migrated anchor did not settle in compact-current".to_owned(),
            ));
        }
        return Ok(VerifiedLegacyAnchorInstalled { database });
    }

    // The source file digest is taken only after a FULL checkpoint/durability
    // barrier.  The authenticated block must have been prepared from that
    // same stopped snapshot; any byte drift fails before schema mutation.
    checkpoint_and_sync_registry(conn, db_path)?;
    let file_identity_digest = legacy_registry_file_identity_digest(db_path)?;
    if file_identity_digest != migration.legacy_file_identity_digest() {
        return Err(ObservationProviderError::RecoveryRequired(
            "legacy registry file inventory differs from authenticated migration block".to_owned(),
        ));
    }
    let (projection_root, rows) = scan_exact_legacy_component_projection(conn)?;
    if projection_root != migration.legacy_projection_root() {
        return Err(ObservationProviderError::RecoveryRequired(
            "legacy component projection differs from authenticated migration block".to_owned(),
        ));
    }

    let (_, keyring_projection) = authenticated_persisted_keyring_projection(
        &config.authenticated_persisted_keyring_file,
        config.registry_instance,
    )?;
    let transaction = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let (locked_projection_root, locked_rows) =
        scan_exact_legacy_component_projection(&transaction)?;
    if locked_projection_root != projection_root || !legacy_rows_equal(&locked_rows, &rows) {
        return Err(ObservationProviderError::RecoveryRequired(
            "legacy component projection changed while migration lock was acquired".to_owned(),
        ));
    }
    create_observation_foundation_schema(&transaction)?;
    migrate_legacy_component_schema(&transaction)?;
    install_migrated_component_rows(&transaction, &rows)?;
    apply_keyring_projection(&transaction, &keyring_projection)?;
    verify_keyring_configuration(&transaction, config, &keyring_projection)?;

    let state_root = compute_state_root(&transaction)?;
    if state_root != migration.target_state_root() {
        return Err(ObservationProviderError::RecoveryRequired(
            "migrated target state root differs from authenticated migration block".to_owned(),
        ));
    }
    let target = migration_target_tuple(&migration);
    write_head_context(
        &transaction,
        migration.prepared_marker_root(),
        migration.manifest_key_epoch(),
    )?;
    write_ledger(&transaction, &target)?;
    verify_complete_roots(&transaction, &target)?;
    validate_durable_invariants(&transaction)?;
    transaction.commit()?;
    checkpoint_and_sync_registry(conn, db_path)?;

    // Re-read all durable postconditions after the checkpoint before issuing
    // the first opaque phase witness.
    let durable = read_ledger(conn)?.ok_or_else(|| {
        ObservationProviderError::RecoveryRequired(
            "migration database commit lost its identity ledger".to_owned(),
        )
    })?;
    let durable_context = read_head_context(conn)?;
    if durable != target
        || durable_context.previous_marker_root != migration.prepared_marker_root()
        || durable_context.manifest_key_epoch != migration.manifest_key_epoch()
    {
        return Err(ObservationProviderError::RecoveryRequired(
            "migration database post-check differs from the authenticated Prepared target"
                .to_owned(),
        ));
    }
    verify_complete_roots(conn, &durable)?;
    validate_durable_invariants(conn)?;
    let database = VerifiedLegacyDatabaseInstalled {
        plan_binding,
        tuple: durable.clone(),
    };

    let witness = verified_legacy_migration_witness(&migration, target.clone(), db_path)?;
    anchor.initialize_migrated_compact(witness, migration)?;
    let observed = anchor.observe()?;
    if classify_recovery(&observed, &target)? != RegistryRecoveryDecision::Clean {
        return Err(ObservationProviderError::RecoveryRequired(
            "migrated anchor did not settle in compact-current".to_owned(),
        ));
    }
    Ok(VerifiedLegacyAnchorInstalled { database })
}

fn migration_target_tuple(migration: &PreparedLegacyRegistryMigration) -> RegistryAnchorTuple {
    let mut tuple = RegistryAnchorTuple {
        registry_instance: migration.registry_instance(),
        sequence: 0,
        head: [0; 32],
        state_root: migration.target_state_root(),
        keyring_root: migration.target_keyring_root(),
        role_allocation_root: migration.target_role_allocation_root(),
        migration_digest: migration.migration_digest(),
    };
    tuple.head = genesis_head(
        tuple.registry_instance,
        tuple.state_root,
        tuple.keyring_root,
        tuple.role_allocation_root,
        tuple.migration_digest,
    );
    tuple
}

/// Test-support composition helper for constructing an exact stopped legacy
/// block from a real nine-column database and real initial owner files.  It
/// executes the target install only inside a rolled-back shadow transaction;
/// production migration never accepts this helper or a caller-selected root.
#[cfg(feature = "test-support")]
pub fn legacy_migration_block_fixture_for_test(
    db_path: &std::path::Path,
    migration_id: [u8; 16],
    registry_instance: [u8; 16],
    initial_keyring_file: &[u8],
    target_role_allocation_root: [u8; 32],
    operator_principal_digest: [u8; 32],
) -> Result<[u8; 228], ObservationProviderError> {
    if migration_id == [0; 16]
        || registry_instance == [0; 16]
        || operator_principal_digest == [0; 32]
    {
        return Err(ObservationProviderError::InvalidInput(
            "legacy migration fixture identities must be nonzero".to_owned(),
        ));
    }
    let mut conn = Connection::open(db_path)?;
    checkpoint_and_sync_registry(&conn, db_path)?;
    let (projection_root, rows) = scan_exact_legacy_component_projection(&conn)?;
    let (target_keyring_root, keyring_projection) =
        authenticated_persisted_keyring_projection(initial_keyring_file, registry_instance)?;
    let transaction = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    create_observation_foundation_schema(&transaction)?;
    migrate_legacy_component_schema(&transaction)?;
    install_migrated_component_rows(&transaction, &rows)?;
    apply_keyring_projection(&transaction, &keyring_projection)?;
    let target_state_root = compute_state_root(&transaction)?;
    transaction.rollback()?;
    checkpoint_and_sync_registry(&conn, db_path)?;
    let file_identity_digest = legacy_registry_file_identity_digest(db_path)?;
    let (rechecked_projection, _) = scan_exact_legacy_component_projection(&conn)?;
    if rechecked_projection != projection_root {
        return Err(ObservationProviderError::RecoveryRequired(
            "legacy fixture projection changed during shadow target derivation".to_owned(),
        ));
    }
    let mut block = [0u8; 228];
    block[0..16].copy_from_slice(&migration_id);
    block[16..32].copy_from_slice(&registry_instance);
    block[32..64].copy_from_slice(&file_identity_digest);
    block[64..96].copy_from_slice(&projection_root);
    block[96..100].copy_from_slice(&1u32.to_be_bytes());
    block[100..132].copy_from_slice(&target_state_root);
    block[132..164].copy_from_slice(&target_keyring_root);
    block[164..196].copy_from_slice(&target_role_allocation_root);
    block[196..228].copy_from_slice(&operator_principal_digest);
    Ok(block)
}

fn verified_legacy_migration_witness(
    migration: &PreparedLegacyRegistryMigration,
    tuple: RegistryAnchorTuple,
    db_path: &std::path::Path,
) -> Result<VerifiedLegacyRegistryMigrationGenesis, ObservationProviderError> {
    let workspace = db_path.parent().ok_or_else(|| {
        ObservationProviderError::RecoveryRequired(
            "migration registry has no workspace parent".to_owned(),
        )
    })?;
    VerifiedLegacyRegistryMigrationGenesis::from_verified_legacy_migration(
        tuple,
        migration.prepared_marker_root(),
        migration.manifest_key_epoch(),
        migration.migration_id(),
        workspace,
        db_path,
    )
    .map_err(ObservationProviderError::from)
}

fn sqlite_table_exists(conn: &Connection, table: &str) -> Result<bool, ObservationProviderError> {
    let exists: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
        params![table],
        |row| row.get(0),
    )?;
    Ok(exists == 1)
}

fn legacy_registry_file_identity_digest(
    db_path: &std::path::Path,
) -> Result<[u8; 32], ObservationProviderError> {
    let metadata = std::fs::symlink_metadata(db_path).map_err(|error| {
        ObservationProviderError::RecoveryRequired(format!(
            "inspect legacy registry file identity: {error}"
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ObservationProviderError::RecoveryRequired(
            "legacy registry inventory entry is not a confined regular file".to_owned(),
        ));
    }
    let file_name = db_path
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .ok_or_else(|| {
            ObservationProviderError::RecoveryRequired(
                "legacy registry inventory path is not canonical UTF-8".to_owned(),
            )
        })?;
    if file_name.is_empty() {
        return Err(ObservationProviderError::RecoveryRequired(
            "legacy registry inventory path is empty".to_owned(),
        ));
    }

    let mut file = std::fs::File::open(db_path).map_err(|error| {
        ObservationProviderError::RecoveryRequired(format!(
            "open legacy registry inventory entry: {error}"
        ))
    })?;
    let mut exact_bytes = Sha256::new();
    let mut observed_len = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer).map_err(|error| {
            ObservationProviderError::RecoveryRequired(format!(
                "read legacy registry inventory entry: {error}"
            ))
        })?;
        if count == 0 {
            break;
        }
        observed_len = observed_len.checked_add(count as u64).ok_or_else(|| {
            ObservationProviderError::RecoveryRequired(
                "legacy registry inventory length overflow".to_owned(),
            )
        })?;
        exact_bytes.update(&buffer[..count]);
    }
    if observed_len != metadata.len() {
        return Err(ObservationProviderError::RecoveryRequired(
            "legacy registry inventory entry changed while it was hashed".to_owned(),
        ));
    }

    let path_len = u32::try_from(file_name.len()).map_err(|_| {
        ObservationProviderError::RecoveryRequired(
            "legacy registry inventory path is too long".to_owned(),
        )
    })?;
    let mut inventory = Sha256::new();
    inventory.update(LEGACY_INVENTORY_DOMAIN);
    inventory.update(1_u32.to_be_bytes());
    inventory.update(path_len.to_be_bytes());
    inventory.update(file_name.as_bytes());
    inventory.update(observed_len.to_be_bytes());
    inventory.update(exact_bytes.finalize());
    Ok(inventory.finalize().into())
}

fn scan_exact_legacy_component_projection(
    conn: &Connection,
) -> Result<([u8; 32], Vec<LegacyComponentMigrationRow>), ObservationProviderError> {
    const COLUMNS: [(&str, &str, i64, i64); 9] = [
        ("seq", "INTEGER", 0, 1),
        ("id", "TEXT", 1, 0),
        ("component_type", "TEXT", 1, 0),
        ("submit_config_json", "TEXT", 1, 0),
        ("submitter", "TEXT", 1, 0),
        ("submitted_at_ms", "INTEGER", 1, 0),
        ("interval_ms", "INTEGER", 0, 0),
        ("expected_next_fire_at_ms", "INTEGER", 0, 0),
        ("last_fire_at_ms", "INTEGER", 0, 0),
    ];

    let mut schema = conn.prepare("PRAGMA table_xinfo(components)")?;
    let observed = schema
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get_ref(4)?.data_type(),
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    if observed.len() != COLUMNS.len()
        || observed.iter().zip(COLUMNS).enumerate().any(
            |(
                index,
                ((cid, name, kind, not_null, default_kind, primary_key, hidden), expected),
            )| {
                *cid != index as i64
                    || (name.as_str(), kind.as_str(), *not_null, *primary_key) != expected
                    || *default_kind != rusqlite::types::Type::Null
                    || *hidden != 0
            },
        )
    {
        return Err(ObservationProviderError::RecoveryRequired(
            "legacy components table does not have the exact nine-column schema".to_owned(),
        ));
    }
    drop(schema);

    let has_autoincrement: i64 = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_sequence WHERE name='components')",
        [],
        |row| row.get(0),
    )?;
    if has_autoincrement != 1 || !legacy_components_has_exact_unique_id(conn)? {
        return Err(ObservationProviderError::RecoveryRequired(
            "legacy components table lacks AUTOINCREMENT or exact id uniqueness".to_owned(),
        ));
    }

    let mut statement = conn.prepare(
        "SELECT seq,id,component_type,submit_config_json,submitter,submitted_at_ms,
                interval_ms,expected_next_fire_at_ms,last_fire_at_ms
         FROM components",
    )?;
    let mut cursor = statement.query([])?;
    let mut canonical = BTreeMap::<Vec<u8>, (Vec<u8>, LegacyComponentMigrationRow)>::new();
    while let Some(row) = cursor.next()? {
        let seq = legacy_required_positive_integer(row.get_ref(0)?, "seq")?;
        let id = legacy_required_text(row.get_ref(1)?, "id")?;
        let component_type = legacy_required_text(row.get_ref(2)?, "component_type")?;
        let source_json = legacy_required_text(row.get_ref(3)?, "submit_config_json")?;
        let submitter = legacy_required_text(row.get_ref(4)?, "submitter")?;
        let submitted_at_ms =
            legacy_required_nonnegative_integer(row.get_ref(5)?, "submitted_at_ms")?;
        let interval_ms = legacy_optional_nonnegative_integer(row.get_ref(6)?, "interval_ms")?;
        let expected_next_fire_at_ms =
            legacy_optional_nonnegative_integer(row.get_ref(7)?, "expected_next_fire_at_ms")?;
        let last_fire_at_ms =
            legacy_optional_nonnegative_integer(row.get_ref(8)?, "last_fire_at_ms")?;

        validate_ordinary_identity_id(&id)?;
        ComponentId::new(id.clone()).map_err(|_| {
            ObservationProviderError::RecoveryRequired(
                "legacy component id violates the canonical identifier bound".to_owned(),
            )
        })?;
        if submitter.len() > MAX_SUBMITTER_LEN {
            return Err(ObservationProviderError::RecoveryRequired(
                "legacy component submitter exceeds the canonical bound".to_owned(),
            ));
        }
        if interval_ms.is_some_and(|value| value < MIN_RECURRING_INTERVAL_MS as u64) {
            return Err(ObservationProviderError::RecoveryRequired(
                "legacy component recurring interval is below the canonical floor".to_owned(),
            ));
        }
        if !matches!(
            component_type.as_str(),
            "cron" | "watcher" | "daemon" | "task"
        ) {
            return Err(ObservationProviderError::RecoveryRequired(
                "legacy component kind is not a canonical non-agent kind".to_owned(),
            ));
        }

        let mut stored_config: ComponentSubmitConfig =
            serde_json::from_str(&source_json).map_err(|error| {
                ObservationProviderError::RecoveryRequired(format!(
                    "legacy component configuration is invalid: {error}"
                ))
            })?;
        if stored_config.id != id || stored_config.component_type.as_str() != component_type {
            return Err(ObservationProviderError::RecoveryRequired(
                "legacy component row and embedded configuration disagree".to_owned(),
            ));
        }
        let declaration = validated_component_declaration(stored_config.sensitive_params.clone())?;
        let names = declaration.names();
        stored_config.sensitive_params = names.to_vec();
        redact_webhook_secrets_in_trigger(&mut stored_config.trigger, 0)?;
        let target_json = serde_json::to_string(&stored_config)
            .map_err(|error| RegistryError::Serde(error.to_string()))?;
        let sensitive_params = canonical_sensitive_param_tail(names.as_ref())?;
        let declaration_digest =
            declaration.digest_for(&id, ObservationIdentityClass::Component, 1)?;

        let mut encoded = Vec::new();
        encoded.extend_from_slice(&seq.to_be_bytes());
        encode_text(&mut encoded, &id)?;
        encode_text(&mut encoded, &component_type)?;
        encode_text(&mut encoded, &source_json)?;
        encode_text(&mut encoded, &submitter)?;
        encoded.extend_from_slice(&submitted_at_ms.to_be_bytes());
        encode_legacy_optional_integer(&mut encoded, interval_ms);
        encode_legacy_optional_integer(&mut encoded, expected_next_fire_at_ms);
        encode_legacy_optional_integer(&mut encoded, last_fire_at_ms);

        let key = id.as_bytes().to_vec();
        let migrated = LegacyComponentMigrationRow {
            seq,
            id,
            component_type,
            submit_config_json: target_json,
            submitter,
            submitted_at_ms,
            interval_ms,
            expected_next_fire_at_ms,
            last_fire_at_ms,
            sensitive_params,
            declaration_digest,
        };
        if canonical.insert(key, (encoded, migrated)).is_some() {
            return Err(ObservationProviderError::RecoveryRequired(
                "legacy component projection contains a duplicate id".to_owned(),
            ));
        }
    }
    drop(cursor);
    drop(statement);
    if canonical.is_empty() {
        return Err(ObservationProviderError::RecoveryRequired(
            "authenticated legacy migration requires a nonempty component registry".to_owned(),
        ));
    }

    let mut projection = Sha256::new();
    projection.update(LEGACY_PROJECTION_DOMAIN);
    projection.update([1_u8]);
    projection.update([1_u8]);
    projection.update((canonical.len() as u64).to_be_bytes());
    let mut migrated_rows = Vec::with_capacity(canonical.len());
    for (key, (encoded, migrated)) in canonical {
        let key_len = u32::try_from(key.len()).map_err(|_| {
            ObservationProviderError::RecoveryRequired(
                "legacy projection key exceeds the canonical length framing".to_owned(),
            )
        })?;
        let row_len = u32::try_from(encoded.len()).map_err(|_| {
            ObservationProviderError::RecoveryRequired(
                "legacy projection row exceeds the canonical length framing".to_owned(),
            )
        })?;
        projection.update(key_len.to_be_bytes());
        projection.update(&key);
        projection.update(row_len.to_be_bytes());
        projection.update(&encoded);
        migrated_rows.push(migrated);
    }
    Ok((projection.finalize().into(), migrated_rows))
}

fn legacy_components_has_exact_unique_id(
    conn: &Connection,
) -> Result<bool, ObservationProviderError> {
    let mut indices = conn.prepare("PRAGMA index_list(components)")?;
    let names = indices
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    drop(indices);
    let mut exact_unique = 0_u8;
    for (name, unique, origin, partial) in names {
        if unique != 1 || origin != "u" || partial != 0 {
            continue;
        }
        let escaped = name.replace('"', "\"\"");
        let pragma = format!("PRAGMA index_xinfo(\"{escaped}\")");
        let mut columns = conn.prepare(&pragma)?;
        let key_columns = columns
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, i64>(5)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        if key_columns
            .iter()
            .filter(|(_, _, _, key)| *key == 1)
            .map(|(seq, cid, name, _)| (*seq, *cid, name.as_deref()))
            .eq([(0, 1, Some("id"))])
        {
            exact_unique = exact_unique.saturating_add(1);
        }
    }
    Ok(exact_unique == 1)
}

fn legacy_required_text(
    value: ValueRef<'_>,
    label: &str,
) -> Result<String, ObservationProviderError> {
    let ValueRef::Text(bytes) = value else {
        return Err(ObservationProviderError::RecoveryRequired(format!(
            "legacy {label} has the wrong SQLite value type"
        )));
    };
    std::str::from_utf8(bytes).map(str::to_owned).map_err(|_| {
        ObservationProviderError::RecoveryRequired(format!("legacy {label} is not canonical UTF-8"))
    })
}

fn legacy_required_positive_integer(
    value: ValueRef<'_>,
    label: &str,
) -> Result<u64, ObservationProviderError> {
    match value {
        ValueRef::Integer(value) if value > 0 => Ok(value as u64),
        _ => Err(ObservationProviderError::RecoveryRequired(format!(
            "legacy {label} is not a positive SQLite integer"
        ))),
    }
}

fn legacy_required_nonnegative_integer(
    value: ValueRef<'_>,
    label: &str,
) -> Result<u64, ObservationProviderError> {
    match value {
        ValueRef::Integer(value) if value >= 0 => Ok(value as u64),
        _ => Err(ObservationProviderError::RecoveryRequired(format!(
            "legacy {label} is not a nonnegative SQLite integer"
        ))),
    }
}

fn legacy_optional_nonnegative_integer(
    value: ValueRef<'_>,
    label: &str,
) -> Result<Option<u64>, ObservationProviderError> {
    match value {
        ValueRef::Null => Ok(None),
        ValueRef::Integer(value) if value >= 0 => Ok(Some(value as u64)),
        _ => Err(ObservationProviderError::RecoveryRequired(format!(
            "legacy {label} is neither NULL nor a nonnegative SQLite integer"
        ))),
    }
}

fn encode_legacy_optional_integer(out: &mut Vec<u8>, value: Option<u64>) {
    match value {
        None => out.push(0),
        Some(value) => {
            out.push(1);
            out.extend_from_slice(&value.to_be_bytes());
        }
    }
}

fn install_migrated_component_rows(
    conn: &Connection,
    rows: &[LegacyComponentMigrationRow],
) -> Result<(), ObservationProviderError> {
    if rows.is_empty() || rows.len() > MAX_LIVE_RETAINED_IDENTITIES as usize {
        return Err(ObservationProviderError::CapacityExceeded(
            "legacy migrated component identities".to_owned(),
        ));
    }
    for row in rows {
        insert_authority_and_identity(
            conn,
            &row.id,
            ObservationIdentityClass::Component,
            1,
            row.declaration_digest,
            "live",
            true,
            None,
            None,
            None,
        )?;
        conn.execute(
            "INSERT INTO components
                (seq,id,component_type,submit_config_json,submitter,submitted_at_ms,
                 interval_ms,expected_next_fire_at_ms,last_fire_at_ms,sensitive_params,
                 identity_incarnation,declaration_digest,lifecycle_state,catalog_visible,
                 operation_id,tombstoned_at_ms,retain_until_ms)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,1,?11,'live',1,NULL,NULL,NULL)",
            params![
                row.seq as i64,
                row.id,
                row.component_type,
                row.submit_config_json,
                row.submitter,
                row.submitted_at_ms as i64,
                row.interval_ms.map(|value| value as i64),
                row.expected_next_fire_at_ms.map(|value| value as i64),
                row.last_fire_at_ms.map(|value| value as i64),
                row.sensitive_params,
                row.declaration_digest.as_bytes().as_slice(),
            ],
        )?;
    }
    Ok(())
}

fn legacy_rows_equal(
    left: &[LegacyComponentMigrationRow],
    right: &[LegacyComponentMigrationRow],
) -> bool {
    left.len() == right.len()
        && left.iter().zip(right).all(|(left, right)| {
            left.seq == right.seq
                && left.id == right.id
                && left.component_type == right.component_type
                && left.submit_config_json == right.submit_config_json
                && left.submitter == right.submitter
                && left.submitted_at_ms == right.submitted_at_ms
                && left.interval_ms == right.interval_ms
                && left.expected_next_fire_at_ms == right.expected_next_fire_at_ms
                && left.last_fire_at_ms == right.last_fire_at_ms
        })
}

fn commit_legacy_marker_transition_on_connection(
    conn: &mut Connection,
    db_path: &std::path::Path,
    anchor: &dyn RegistryAnchorTransaction,
    prepared: &PreparedLegacyMarkerMutation,
    _registry_identity: usize,
) -> Result<VerifiedLegacyMarkerTransitionCommitted, ObservationProviderError> {
    let plan_binding = prepared.plan_binding_digest();
    let next_phase = prepared.next_phase();
    let previous_marker_root = prepared.previous_marker_root();
    let next_marker_root = prepared.next_marker_root();
    let preauthenticated = prepared.authenticated_mutation(anchor)?;
    preauthenticated.mutation().validate()?;
    let operation_tag = preauthenticated.mutation().operation_tag();
    let previous = preauthenticated.mutation().previous().clone();
    let next = preauthenticated.mutation().next().clone();
    let head_context = preauthenticated.mutation().head_context().clone();
    if operation_tag != 6
        || !matches!(next_phase, 2 | 3)
        || previous.state_root != next.state_root
        || previous.keyring_root != next.keyring_root
        || previous.role_allocation_root != next.role_allocation_root
        || previous.migration_digest != next.migration_digest
        || previous_marker_root == next_marker_root
    {
        return Err(ObservationProviderError::InvalidInput(
            "opaque legacy marker mutation is not an exact synthetic tag-13 replacement".to_owned(),
        ));
    }
    let transaction = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

    // Exact retry after a lost acknowledgement: the durable ledger/anchor may
    // already equal the postimage while marker.pending still awaits owner
    // promotion. Reissue only the same bound witness, with every database
    // postcondition pinned inside the same BEGIN IMMEDIATE boundary.
    if read_ledger(&transaction)?.as_ref() == Some(&next) {
        #[cfg(any(test, feature = "test-support"))]
        apply_marker_retry_schema_adversary_if_armed(
            &transaction,
            next.registry_instance,
            _registry_identity,
        )?;
        verify_observation_schema_fingerprint(&transaction)?;
        verify_complete_roots(&transaction, &next)?;
        validate_durable_invariants(&transaction)?;
        let context = read_head_context(&transaction)?;
        if context.previous_marker_root != next_marker_root
            || context.manifest_key_epoch != head_context.next_manifest_key_epoch
        {
            return Err(ObservationProviderError::RecoveryRequired(
                "committed marker retry has a divergent head context".to_owned(),
            ));
        }
        // The lock-free preauthentication rejects bad requests without
        // occupying SQLite.  Rebuild the exact physical marker and both
        // concrete custody leases again inside BEGIN IMMEDIATE so a changed
        // current/pending pair or lease cannot inherit the earlier witness.
        let locked = prepared.authenticated_mutation(anchor)?;
        locked.mutation().validate()?;
        if !locked.exactly_matches(&preauthenticated) {
            return Err(ObservationProviderError::RecoveryRequired(
                "committed marker retry changed after preauthentication".to_owned(),
            ));
        }
        let locked_next = locked.mutation().next().clone();
        let observed = anchor.observe()?;
        if classify_recovery(&observed, &locked_next)? != RegistryRecoveryDecision::Clean {
            return Err(ObservationProviderError::RecoveryRequired(
                "committed marker retry has a divergent external anchor".to_owned(),
            ));
        }
        let (_, anchor_lease_challenge, anchor_lease_tag) = locked.into_parts();
        transaction.commit()?;
        return Ok(VerifiedLegacyMarkerTransitionCommitted {
            plan_binding,
            next: locked_next,
            previous_marker_root,
            next_marker_root,
            next_phase,
            anchor_lease_challenge,
            anchor_lease_tag,
        });
    }

    let durable = read_ledger(&transaction)?.ok_or_else(|| {
        ObservationProviderError::RecoveryRequired("missing identity ledger".to_owned())
    })?;
    if durable != previous {
        return Err(ObservationProviderError::RecoveryRequired(
            "prepared marker transition does not descend from the exact durable tuple".to_owned(),
        ));
    }
    let durable_context = read_head_context(&transaction)?;
    if durable_context.previous_marker_root != previous_marker_root
        || durable_context.manifest_key_epoch != head_context.manifest_key_epoch
    {
        return Err(ObservationProviderError::RecoveryRequired(
            "prepared marker transition reports stale marker or epoch context".to_owned(),
        ));
    }
    verify_complete_roots(&transaction, &durable)?;
    validate_durable_invariants(&transaction)?;

    // Initial commit uses the same locked reconstruction.  The first
    // authentication is only an admission check; it never substitutes for
    // the physical/lease evidence used to write or issue the witness.
    let locked = prepared.authenticated_mutation(anchor)?;
    locked.mutation().validate()?;
    if !locked.exactly_matches(&preauthenticated) {
        return Err(ObservationProviderError::RecoveryRequired(
            "prepared marker transition changed after preauthentication".to_owned(),
        ));
    }
    let (mutation, anchor_lease_challenge, anchor_lease_tag) = locked.into_parts();
    let next = mutation.next().clone();
    let head_context = mutation.head_context().clone();
    write_ledger(&transaction, &next)?;
    write_head_context(
        &transaction,
        next_marker_root,
        head_context.next_manifest_key_epoch,
    )?;
    verify_observation_schema_fingerprint(&transaction)?;
    verify_complete_roots(&transaction, &next)?;
    validate_durable_invariants(&transaction)?;
    let proof_issuer = RegistryDatabaseCommitProofIssuer::for_mutation(anchor, &mutation)?;
    let anchored = anchor.prepare_current(mutation)?;
    transaction.commit()?;
    checkpoint_and_sync_registry(conn, db_path)?;
    let durable_next = read_ledger(conn)?.ok_or_else(|| {
        ObservationProviderError::RecoveryRequired(
            "committed marker ledger disappeared after checkpoint".to_owned(),
        )
    })?;
    let proof = proof_issuer.from_durable_reread(anchor, durable_next)?;
    let committed = anchored.database_committed(proof)?;
    let selected = committed.select_next()?;
    let compacted = selected.compact()?;
    if compacted.current() != &next {
        return Err(ObservationProviderError::RecoveryRequired(
            "compacted marker anchor differs from the committed SQLite tuple".to_owned(),
        ));
    }
    let observed = anchor.observe()?;
    if classify_recovery(&observed, &next)? != RegistryRecoveryDecision::Clean {
        return Err(ObservationProviderError::RecoveryRequired(
            "marker transition did not finish in compact-current".to_owned(),
        ));
    }
    verify_observation_schema_fingerprint(conn)?;
    verify_complete_roots(conn, &next)?;
    validate_durable_invariants(conn)?;
    Ok(VerifiedLegacyMarkerTransitionCommitted {
        plan_binding,
        next,
        previous_marker_root,
        next_marker_root,
        next_phase,
        anchor_lease_challenge,
        anchor_lease_tag,
    })
}

fn recover_committed_legacy_marker_transition_on_connection(
    conn: &mut Connection,
    anchor: &dyn RegistryAnchorTransaction,
    migration: &PreparedLegacyRegistryMigration,
    next_phase: u8,
    _registry_identity: usize,
) -> Result<VerifiedLegacyMarkerTransitionCommitted, ObservationProviderError> {
    let (previous_marker, next_marker, previous_marker_root, next_marker_root) = match next_phase {
        2 => (
            migration.prepared_marker_bytes(),
            migration.installed_marker_bytes(),
            migration.prepared_marker_root(),
            migration.installed_marker_root(),
        ),
        3 => (
            migration.installed_marker_bytes(),
            migration.complete_marker_bytes(),
            migration.installed_marker_root(),
            migration.complete_marker_root(),
        ),
        _ => {
            return Err(ObservationProviderError::InvalidInput(
                "unknown legacy marker recovery phase".to_owned(),
            ))
        }
    };
    let transaction = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    verify_observation_schema_fingerprint(&transaction)?;
    let first = read_committed_legacy_marker_recovery_snapshot(
        &transaction,
        anchor,
        migration,
        next_phase,
        previous_marker,
        next_marker,
        previous_marker_root,
        next_marker_root,
    )?;
    #[cfg(any(test, feature = "test-support"))]
    apply_marker_retry_schema_adversary_if_armed(
        &transaction,
        migration.registry_instance(),
        _registry_identity,
    )?;
    // Re-pin the schema, ledger/context, complete rooted postimage, external
    // world, physical marker pair, and concrete anchor lease.  Both public
    // recovery entry points use this same locked two-read path.
    verify_observation_schema_fingerprint(&transaction)?;
    let second = read_committed_legacy_marker_recovery_snapshot(
        &transaction,
        anchor,
        migration,
        next_phase,
        previous_marker,
        next_marker,
        previous_marker_root,
        next_marker_root,
    )?;
    verify_observation_schema_fingerprint(&transaction)?;
    if first != second {
        return Err(ObservationProviderError::RecoveryRequired(
            "committed marker recovery changed during its locked exact retry".to_owned(),
        ));
    }
    transaction.commit()?;
    let (next, _, _, anchor_lease_challenge, anchor_lease_tag) = second;
    Ok(VerifiedLegacyMarkerTransitionCommitted {
        plan_binding: migration.plan_binding_digest(),
        next,
        previous_marker_root,
        next_marker_root,
        next_phase,
        anchor_lease_challenge,
        anchor_lease_tag,
    })
}

fn read_committed_legacy_marker_recovery_snapshot(
    conn: &Connection,
    anchor: &dyn RegistryAnchorTransaction,
    migration: &PreparedLegacyRegistryMigration,
    next_phase: u8,
    previous_marker: &[u8],
    next_marker: &[u8],
    previous_marker_root: [u8; 32],
    next_marker_root: [u8; 32],
) -> Result<
    (
        RegistryAnchorTuple,
        RegistryHeadContext,
        RegistryAnchorWorld,
        [u8; 32],
        [u8; 32],
    ),
    ObservationProviderError,
> {
    let next = read_ledger(conn)?.ok_or_else(|| {
        ObservationProviderError::RecoveryRequired("missing identity ledger".to_owned())
    })?;
    let context = read_head_context(conn)?;
    if next.registry_instance != migration.registry_instance()
        || next.migration_digest != migration.migration_digest()
        || context.previous_marker_root != next_marker_root
        || context.manifest_key_epoch != migration.manifest_key_epoch()
        || (next_phase == 2 && next.sequence != 1)
        || (next_phase == 3 && next.sequence < 2)
    {
        return Err(ObservationProviderError::RecoveryRequired(
            "durable registry is not the requested committed marker transition".to_owned(),
        ));
    }
    let observed = anchor.observe()?;
    if classify_recovery(&observed, &next)? != RegistryRecoveryDecision::Clean {
        return Err(ObservationProviderError::RecoveryRequired(
            "external anchor is not the requested committed marker transition".to_owned(),
        ));
    }
    verify_complete_roots(conn, &next)?;
    validate_durable_invariants(conn)?;

    // The previous head is intentionally unavailable after compacting the
    // external bundle.  File custody's committed-world branch compares only
    // the exact selected postimage plus physical current/pending marker pair.
    let mut unavailable_previous = next.clone();
    unavailable_previous.sequence = next.sequence.saturating_sub(1);
    let transition_context = RegistryHeadContext {
        previous_marker_root,
        next_marker_root,
        manifest_key_epoch: migration.manifest_key_epoch(),
        next_manifest_key_epoch: migration.manifest_key_epoch(),
    };
    anchor.authenticate_legacy_marker_transition_artifacts(
        &unavailable_previous,
        &next,
        &transition_context,
        previous_marker,
        next_marker,
    )?;
    let (anchor_lease_challenge, anchor_lease_tag) =
        legacy_marker_anchor_lease_binding(anchor, migration, &next, next_phase)?;
    Ok((
        next,
        context,
        observed,
        anchor_lease_challenge,
        anchor_lease_tag,
    ))
}

fn commit_prepared_role_allocation_on_connection(
    conn: &mut Connection,
    db_path: &std::path::Path,
    anchor: &dyn RegistryAnchorTransaction,
    prepared: PreparedRoleAllocationMutation,
) -> Result<RegistryAnchorTuple, ObservationProviderError> {
    let mutation = prepared.into_mutation_authenticated(anchor)?;
    mutation.validate()?;
    let previous = mutation.previous().clone();
    let next = mutation.next().clone();
    let head_context = mutation.head_context().clone();
    if mutation.operation_tag() != 6
        || previous.state_root != next.state_root
        || previous.keyring_root != next.keyring_root
        || previous.migration_digest != next.migration_digest
        || previous.role_allocation_root == next.role_allocation_root
    {
        return Err(ObservationProviderError::InvalidInput(
            "opaque role mutation is not an exact tag-6 role-artifact replacement".to_owned(),
        ));
    }

    let transaction = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let durable = read_ledger(&transaction)?.ok_or_else(|| {
        ObservationProviderError::RecoveryRequired("missing identity ledger".to_owned())
    })?;
    if durable != previous {
        return Err(ObservationProviderError::RecoveryRequired(
            "prepared role mutation does not descend from the exact durable tuple".to_owned(),
        ));
    }
    let durable_context = read_head_context(&transaction)?;
    if durable_context.previous_marker_root != head_context.previous_marker_root
        || durable_context.manifest_key_epoch != head_context.manifest_key_epoch
    {
        return Err(ObservationProviderError::RecoveryRequired(
            "prepared role mutation reports stale marker or manifest-epoch context".to_owned(),
        ));
    }
    verify_complete_roots(&transaction, &durable)?;
    validate_durable_invariants(&transaction)?;
    write_ledger(&transaction, &next)?;
    write_head_context(
        &transaction,
        head_context.next_marker_root,
        head_context.next_manifest_key_epoch,
    )?;
    let proof_issuer = RegistryDatabaseCommitProofIssuer::for_mutation(anchor, &mutation)?;
    let anchored = anchor.prepare_current(mutation)?;
    transaction.commit()?;
    checkpoint_and_sync_registry(conn, db_path)?;
    let durable_next = read_ledger(conn)?.ok_or_else(|| {
        ObservationProviderError::RecoveryRequired(
            "committed role ledger disappeared after checkpoint".to_owned(),
        )
    })?;
    let proof = proof_issuer.from_durable_reread(anchor, durable_next)?;
    let committed = anchored.database_committed(proof)?;
    let selected = committed.select_next()?;
    let compacted = selected.compact()?;
    if compacted.current() != &next {
        return Err(ObservationProviderError::RecoveryRequired(
            "compacted role anchor tuple differs from committed SQLite tuple".to_owned(),
        ));
    }
    let observed = anchor.observe()?;
    if classify_recovery(&observed, &next)? != RegistryRecoveryDecision::Clean {
        return Err(ObservationProviderError::RecoveryRequired(
            "role mutation did not finish in the compact-current world".to_owned(),
        ));
    }
    Ok(next)
}

fn commit_prepared_keyring_on_connection(
    conn: &mut Connection,
    db_path: &std::path::Path,
    anchor: &dyn RegistryAnchorTransaction,
    prepared: PreparedPersistedKeyringMutation,
) -> Result<RegistryAnchorTuple, ObservationProviderError> {
    let (mutation, previous_projection, next_projection) =
        prepared.into_parts_authenticated(anchor)?;
    mutation.validate()?;
    let previous = mutation.previous().clone();
    let next = mutation.next().clone();
    let head_context = mutation.head_context().clone();
    if mutation.operation_tag() != 6
        || previous.state_root != next.state_root
        || previous.role_allocation_root != next.role_allocation_root
        || previous.migration_digest != next.migration_digest
        || previous.keyring_root == next.keyring_root
        || previous_projection.manifest_key_epoch != head_context.manifest_key_epoch
        || next_projection.manifest_key_epoch != head_context.next_manifest_key_epoch
    {
        return Err(ObservationProviderError::InvalidInput(
            "opaque keyring mutation is not an exact tag-6 keyring-artifact replacement".to_owned(),
        ));
    }

    let transaction = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let durable = read_ledger(&transaction)?.ok_or_else(|| {
        ObservationProviderError::RecoveryRequired("missing identity ledger".to_owned())
    })?;
    if durable != previous {
        return Err(ObservationProviderError::RecoveryRequired(
            "prepared keyring mutation does not descend from the exact durable tuple".to_owned(),
        ));
    }
    let durable_context = read_head_context(&transaction)?;
    if durable_context.previous_marker_root != head_context.previous_marker_root
        || durable_context.manifest_key_epoch != head_context.manifest_key_epoch
    {
        return Err(ObservationProviderError::RecoveryRequired(
            "prepared keyring mutation reports stale marker or manifest-epoch context".to_owned(),
        ));
    }
    verify_complete_roots(&transaction, &durable)?;
    validate_durable_invariants(&transaction)?;
    verify_keyring_projection(&transaction, &previous_projection)?;
    apply_keyring_projection(&transaction, &next_projection)?;
    verify_keyring_projection(&transaction, &next_projection)?;
    write_ledger(&transaction, &next)?;
    write_head_context(
        &transaction,
        head_context.next_marker_root,
        head_context.next_manifest_key_epoch,
    )?;
    let proof_issuer = RegistryDatabaseCommitProofIssuer::for_mutation(anchor, &mutation)?;
    let anchored = anchor.prepare_current(mutation)?;
    transaction.commit()?;
    checkpoint_and_sync_registry(conn, db_path)?;
    let durable_next = read_ledger(conn)?.ok_or_else(|| {
        ObservationProviderError::RecoveryRequired(
            "committed keyring ledger disappeared after checkpoint".to_owned(),
        )
    })?;
    let proof = proof_issuer.from_durable_reread(anchor, durable_next)?;
    let committed = anchored.database_committed(proof)?;
    let selected = committed.select_next()?;
    let compacted = selected.compact()?;
    if compacted.current() != &next {
        return Err(ObservationProviderError::RecoveryRequired(
            "compacted keyring anchor tuple differs from committed SQLite tuple".to_owned(),
        ));
    }
    let observed = anchor.observe()?;
    if classify_recovery(&observed, &next)? != RegistryRecoveryDecision::Clean {
        return Err(ObservationProviderError::RecoveryRequired(
            "keyring mutation did not finish in the compact-current world".to_owned(),
        ));
    }
    Ok(next)
}

fn commit_custody_keyring_update_on_connection<V>(
    conn: &mut Connection,
    db_path: &std::path::Path,
    anchor: &dyn RegistryAnchorTransaction,
    role_slot: &mut Option<PersistedIdentityKeyringRole>,
    mut custody_update: Box<dyn PreparedPersistedKeyringCustodyMutation>,
    validate: V,
) -> Result<RegistryAnchorTuple, ObservationProviderError>
where
    V: FnOnce(
        &PreparedPersistedKeyringMutation,
        PersistedIdentityKeyringBinding,
        PersistedIdentityKeyringBinding,
    ) -> Result<(), RegistryAnchorError>,
{
    let previous_binding = custody_update.previous_binding();
    let next_binding = custody_update.next_binding();
    if previous_binding.registry_instance() != next_binding.registry_instance()
        || previous_binding.keyring_root() == next_binding.keyring_root()
        || previous_binding.keyring_generation().checked_add(1)
            != Some(next_binding.keyring_generation())
    {
        return Err(ObservationProviderError::RecoveryRequired(
            "custody returned a non-successor keyring binding".to_owned(),
        ));
    }
    let prepared = custody_update.take_scheduler_preparation()?;
    if prepared.previous().registry_instance != previous_binding.registry_instance()
        || prepared.previous_keyring_root() != previous_binding.keyring_root()
        || prepared.next_keyring_root() != next_binding.keyring_root()
    {
        return Err(ObservationProviderError::RecoveryRequired(
            "custody bindings do not name the scheduler-parsed keyring replacement".to_owned(),
        ));
    }
    validate(&prepared, previous_binding, next_binding)?;
    let committed = commit_prepared_keyring_on_connection(conn, db_path, anchor, prepared)?;
    custody_update.promote_after_anchor(&committed)?;

    let old_role = role_slot.take().ok_or_else(|| {
        ObservationProviderError::RecoveryRequired(
            "persisted-keyring role disappeared during committed replacement".to_owned(),
        )
    })?;
    let advanced = old_role
        .advance_authenticated_binding(previous_binding, next_binding)
        .map_err(|_| {
            ObservationProviderError::RecoveryRequired(
                "persisted-keyring role could not advance to the promoted custody binding"
                    .to_owned(),
            )
        })?;
    advanced.verify_provider_binding(committed.registry_instance, committed.keyring_root)?;
    *role_slot = Some(advanced);
    Ok(committed)
}

fn run_anchored_mutation_on_connection<T, F>(
    conn: &mut Connection,
    db_path: &std::path::Path,
    anchor: &dyn RegistryAnchorTransaction,
    operation_tag: u8,
    _write_discriminator: &[u8],
    #[cfg(any(test, feature = "test-support"))] test_controls: Option<
        &ObservationMutationTestControls,
    >,
    mutation: F,
) -> Result<T, ObservationProviderError>
where
    F: FnOnce(&Transaction<'_>) -> Result<T, ObservationProviderError>,
{
    if !(1..=8).contains(&operation_tag) {
        return Err(ObservationProviderError::InvalidInput(
            "unknown registry operation tag".to_owned(),
        ));
    }
    let transaction = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let previous = read_ledger(&transaction)?.ok_or_else(|| {
        ObservationProviderError::RecoveryRequired("missing identity ledger".to_owned())
    })?;
    let head_context = read_head_context(&transaction)?;
    verify_complete_roots(&transaction, &previous)?;
    validate_durable_invariants(&transaction)?;
    let before_snapshot = capture_registry_snapshot(&transaction).map_err(codec_error)?;

    #[cfg(any(test, feature = "test-support"))]
    if let Some(controls) = test_controls {
        controls
            .hit(ObservationMutationFailpointStage::BeforeMutation)
            .map_err(definite_rollback)?;
    }

    let output = mutation(&transaction).map_err(definite_rollback)?;
    #[cfg(any(test, feature = "test-support"))]
    if let Some(controls) = test_controls {
        controls
            .hit(ObservationMutationFailpointStage::AfterMutationBeforeValidation)
            .map_err(definite_rollback)?;
    }
    validate_durable_invariants(&transaction).map_err(definite_rollback)?;
    let after_snapshot = capture_registry_snapshot(&transaction)
        .map_err(codec_error)
        .map_err(definite_rollback)?;
    validate_operation_effects(operation_tag, &before_snapshot, &after_snapshot)
        .map_err(codec_error)
        .map_err(definite_rollback)?;
    let state_root = canonical_state_root(&after_snapshot)
        .map_err(codec_error)
        .map_err(definite_rollback)?;
    // The canonical persisted-keyring root belongs to the authenticated
    // external complete file and changes only through the opaque tag-12 seam.
    // Ordinary rooted SQLite mutations must preserve it byte-for-byte.
    let keyring_root = previous.keyring_root;
    let sequence = previous
        .sequence
        .checked_add(1)
        .filter(|value| *value <= i64::MAX as u64)
        .ok_or_else(|| {
            ObservationProviderError::CapacityExceeded("registry sequence exhausted".to_owned())
        })
        .map_err(definite_rollback)?;
    let write_set_digest = canonical_write_set_digest(&before_snapshot, &after_snapshot)
        .map_err(codec_error)
        .map_err(definite_rollback)?;
    let next_postimage = RegistryAnchorTuple {
        registry_instance: previous.registry_instance,
        sequence,
        head: [0; 32],
        state_root,
        keyring_root,
        role_allocation_root: previous.role_allocation_root,
        migration_digest: previous.migration_digest,
    };
    let anchor_mutation = RegistryAnchorMutation::from_scheduler_postimage(
        anchor,
        previous,
        next_postimage,
        head_context,
        operation_tag,
        write_set_digest,
    )
    .map_err(ObservationProviderError::from)
    .map_err(definite_rollback)?;
    let next = anchor_mutation.next().clone();
    write_ledger(&transaction, &next).map_err(definite_rollback)?;
    #[cfg(any(test, feature = "test-support"))]
    if let Some(controls) = test_controls {
        controls
            .hit(ObservationMutationFailpointStage::AfterValidationBeforeAnchorPrepare)
            .map_err(definite_rollback)?;
    }
    let proof_issuer = RegistryDatabaseCommitProofIssuer::for_mutation(anchor, &anchor_mutation)?;
    let anchored = anchor.prepare_current(anchor_mutation)?;
    #[cfg(any(test, feature = "test-support"))]
    if let Some(controls) = test_controls {
        controls.hit(ObservationMutationFailpointStage::AfterAnchorPrepareBeforeDatabaseCommit)?;
    }
    transaction.commit()?;
    #[cfg(any(test, feature = "test-support"))]
    if let Some(controls) = test_controls {
        controls.hit(ObservationMutationFailpointStage::AfterDatabaseCommitBeforeSync)?;
    }
    checkpoint_and_sync_registry(conn, db_path)?;
    #[cfg(any(test, feature = "test-support"))]
    if let Some(controls) = test_controls {
        controls.hit(ObservationMutationFailpointStage::AfterSyncBeforeAnchorCommit)?;
    }
    let durable_next = read_ledger(conn)?.ok_or_else(|| {
        ObservationProviderError::RecoveryRequired(
            "committed mutation ledger disappeared after checkpoint".to_owned(),
        )
    })?;
    let database_proof = proof_issuer.from_durable_reread(anchor, durable_next)?;
    let committed = anchored.database_committed(database_proof)?;
    #[cfg(any(test, feature = "test-support"))]
    if let Some(controls) = test_controls {
        controls.hit(ObservationMutationFailpointStage::AfterAnchorCommitBeforeSelect)?;
    }
    let selected = committed.select_next()?;
    #[cfg(any(test, feature = "test-support"))]
    if let Some(controls) = test_controls {
        controls.hit(ObservationMutationFailpointStage::AfterSelectBeforeCompact)?;
    }
    let compacted = selected.compact()?;
    #[cfg(any(test, feature = "test-support"))]
    if let Some(controls) = test_controls {
        controls.hit(ObservationMutationFailpointStage::AfterCompact)?;
    }
    if compacted.current() != &next {
        return Err(ObservationProviderError::RecoveryRequired(
            "compacted anchor tuple differs from committed SQLite tuple".to_owned(),
        ));
    }
    let observed = anchor.observe()?;
    if classify_recovery(&observed, &next)? != RegistryRecoveryDecision::Clean {
        return Err(ObservationProviderError::RecoveryRequired(
            "mutation did not finish in the compact-current world".to_owned(),
        ));
    }
    Ok(output)
}

#[cfg(any(test, feature = "test-support"))]
fn apply_greenfield_schema_adversary_if_armed(
    conn: &Connection,
    registry_instance: [u8; 16],
    stage: GreenfieldSchemaAdversaryStage,
) -> Result<(), ObservationProviderError> {
    let slot = GREENFIELD_SCHEMA_ADVERSARY.get_or_init(|| Mutex::new(None));
    let mut armed = slot.lock().map_err(|_| {
        ObservationProviderError::RecoveryRequired(
            "greenfield schema adversary fixture lock is poisoned".to_owned(),
        )
    })?;
    if armed.as_ref() != Some(&(registry_instance, stage)) {
        return Ok(());
    }
    *armed = None;
    drop(armed);
    conn.execute_batch(
        "CREATE TRIGGER __test_greenfield_schema_boundary_tamper
         AFTER UPDATE ON observation_identity_authority
         BEGIN SELECT 1; END;",
    )?;
    Ok(())
}

#[cfg(any(test, feature = "test-support"))]
fn apply_marker_retry_schema_adversary_if_armed(
    conn: &Connection,
    registry_instance: [u8; 16],
    registry_identity: usize,
) -> Result<(), ObservationProviderError> {
    let slot = MARKER_RETRY_SCHEMA_ADVERSARY.get_or_init(|| Mutex::new(None));
    let mut armed = slot.lock().map_err(|_| {
        ObservationProviderError::RecoveryRequired(
            "marker retry schema adversary fixture lock is poisoned".to_owned(),
        )
    })?;
    if armed.as_ref() != Some(&(registry_instance, registry_identity)) {
        return Ok(());
    }
    *armed = None;
    drop(armed);
    conn.execute_batch(
        "CREATE TRIGGER __test_marker_retry_schema_boundary_tamper
         AFTER UPDATE ON observation_identity_authority
         BEGIN SELECT 1; END;",
    )?;
    Ok(())
}

fn reserve_previsible_operation_capacity(
    conn: &Connection,
    limits: PrevisibleCapacityLimits,
) -> Result<(), ObservationProviderError> {
    if limits.rows <= 0
        || limits.rows > MAX_PREVISIBLE_ROWS
        || limits.combined_bytes <= 0
        || limits.combined_bytes > MAX_PREVISIBLE_COMBINED_BYTES
    {
        return Err(ObservationProviderError::InvalidState(
            "previsible capacity limits are outside production bounds".to_owned(),
        ));
    }
    let changed = conn.execute(
        "UPDATE observation_previsible_capacity
         SET row_count=row_count+1,
             future_reserved_bytes=future_reserved_bytes+?1
         WHERE singleton=1 AND row_count < ?2
           AND actual_encoded_bytes+future_reserved_bytes+?1 <= ?3",
        params![PREVISIBLE_TOTAL_BYTES, limits.rows, limits.combined_bytes],
    )?;
    if changed != 1 {
        return Err(ObservationProviderError::CapacityExceeded(
            "previsible operation-linked row/byte reservation".to_owned(),
        ));
    }
    Ok(())
}

fn consume_previsible_operation_reservation(
    conn: &Connection,
    encoded_bytes: i64,
    future_reserved_bytes: i64,
) -> Result<(), ObservationProviderError> {
    if encoded_bytes <= 0
        || encoded_bytes
            .checked_add(future_reserved_bytes)
            .is_none_or(|total| total != PREVISIBLE_TOTAL_BYTES)
    {
        return Err(ObservationProviderError::RecoveryRequired(
            "previsible tag-3 reservation transfer is malformed".to_owned(),
        ));
    }
    let changed = conn.execute(
        "UPDATE observation_previsible_capacity
         SET actual_encoded_bytes=actual_encoded_bytes+?1,
             future_reserved_bytes=future_reserved_bytes-?1
         WHERE singleton=1 AND row_count>0
           AND future_reserved_bytes>=?1
           AND actual_encoded_bytes+?1<=?2",
        params![encoded_bytes, MAX_PREVISIBLE_COMBINED_BYTES],
    )?;
    if changed != 1 {
        return Err(ObservationProviderError::RecoveryRequired(
            "previsible tag-3 did not consume one operation-linked reservation".to_owned(),
        ));
    }
    Ok(())
}

fn persist_previsible_activation(
    conn: &Connection,
    record: &ProviderActivationRecord,
    registry_instance: [u8; 16],
    boot: [u8; 16],
) -> Result<(), ObservationProviderError> {
    let (expected_kind, expected_role, expected_class) = match record.kind {
        advance_shared_types::contract218_previsible::PrevisibleActivationKind::Component => (
            "register-component",
            1_i64,
            ObservationIdentityClass::Component,
        ),
        advance_shared_types::contract218_previsible::PrevisibleActivationKind::Agent => {
            ("register-agent", 2_i64, ObservationIdentityClass::Agent)
        }
    };
    if record.claims.expected_class != expected_class || record.activation_nonce == [0; 32] {
        return Err(ObservationProviderError::InvalidInput(
            "activation kind, class, or nonce is invalid".to_owned(),
        ));
    }
    let current = read_ledger(conn)?.ok_or_else(|| {
        ObservationProviderError::RecoveryRequired("missing identity ledger".to_owned())
    })?;
    if current.registry_instance != registry_instance
        || record.registry_sequence == 0
        || record.registry_sequence > current.sequence
    {
        return Err(ObservationProviderError::InvalidState(
            "activation receipt sequence is not committed".to_owned(),
        ));
    }
    let exact_member: i64 = conn.query_row(
        "SELECT COUNT(*)
         FROM observation_identity_operations o
         JOIN observation_identity_operation_members m ON m.operation_id=o.operation_id
         JOIN observation_identities i ON i.id=m.identity_id
         WHERE o.operation_id=?1 AND o.kind=?2 AND o.phase='prepared' AND o.is_active=1
           AND m.identity_id=?3 AND m.identity_class=?4 AND m.identity_incarnation=?5
           AND m.declaration_digest=?6 AND m.is_active=1
           AND i.class=m.identity_class AND i.incarnation=m.identity_incarnation
           AND i.declaration_digest=m.declaration_digest AND i.lifecycle_state='pending'
           AND i.catalog_visible=0 AND i.operation_id=o.operation_id",
        params![
            record.operation_id,
            expected_kind,
            record.claims.exact_id,
            class_to_sql(record.claims.expected_class),
            record.claims.incarnation as i64,
            record.claims.declaration_digest.as_bytes().as_slice(),
        ],
        |row| row.get(0),
    )?;
    if exact_member != 1 {
        return Err(ObservationProviderError::InvalidState(
            "activation does not name one exact hidden operation member".to_owned(),
        ));
    }
    let existing_activation: i64 = conn.query_row(
        "SELECT COUNT(*) FROM observation_previsible_activations
         WHERE operation_id=?1 AND identity_id=?2",
        params![record.operation_id, record.claims.exact_id],
        |row| row.get(0),
    )?;
    if existing_activation != 0 {
        return Err(ObservationProviderError::InvalidState(
            "the hidden operation already has a previsible activation".to_owned(),
        ));
    }
    if expected_class == ObservationIdentityClass::Component {
        let exact_component: i64 = conn.query_row(
            "SELECT COUNT(*) FROM components
             WHERE id=?1 AND identity_incarnation=?2 AND declaration_digest=?3
               AND lifecycle_state='live' AND catalog_visible=0 AND operation_id=?4",
            params![
                record.claims.exact_id,
                record.claims.incarnation as i64,
                record.claims.declaration_digest.as_bytes().as_slice(),
                record.operation_id,
            ],
            |row| row.get(0),
        )?;
        if exact_component != 1 {
            return Err(ObservationProviderError::InvalidState(
                "component activation projection is incomplete".to_owned(),
            ));
        }
    }
    let encoded_bytes = previsible_encoded_bytes(record, 0, false, false)?;
    let future_reserved_bytes = PREVISIBLE_TOTAL_BYTES
        .checked_sub(encoded_bytes)
        .ok_or_else(|| {
            ObservationProviderError::CapacityExceeded(
                "previsible initial encoding exceeds terminal reservation".to_owned(),
            )
        })?;
    consume_previsible_operation_reservation(conn, encoded_bytes, future_reserved_bytes)?;
    conn.execute(
        "INSERT INTO observation_previsible_activations
            (activation_nonce,boot_id,registry_instance_id,role,operation_id,
             operation_kind,identity_id,identity_class,identity_incarnation,
             declaration_digest,registry_sequence,phase,ready_proof_nonce,
             abort_proof_nonce,recovery_nonce,updated_sequence,terminal_at_ms,
             audit_checkpoint_sequence,encoded_bytes,future_reserved_bytes)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,'prepared',
                 NULL,NULL,NULL,?11,NULL,NULL,?12,?13)",
        params![
            record.activation_nonce.as_slice(),
            boot.as_slice(),
            registry_instance.as_slice(),
            expected_role,
            record.operation_id,
            expected_kind,
            record.claims.exact_id,
            class_to_sql(record.claims.expected_class),
            record.claims.incarnation as i64,
            record.claims.declaration_digest.as_bytes().as_slice(),
            record.registry_sequence as i64,
            encoded_bytes,
            future_reserved_bytes,
        ],
    )?;
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ReadyProofJournalMetadata {
    subject_receipt_digest: [u8; 32],
    table_receipt_digest: [u8; 32],
    lifecycle_receipt_digest: [u8; 32],
    proof_nonce: [u8; 32],
    recovery_nonce: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AbortProofJournalMetadata {
    subject_absence_digest: [u8; 32],
    table_absence_digest: [u8; 32],
    lifecycle_absence_digest: [u8; 32],
    proof_nonce: [u8; 32],
    recovery_nonce: [u8; 32],
}

fn require_nonzero_previsible_metadata(
    metadata: &VerifiedPrevisibleProofMetadata,
) -> Result<(), ObservationProviderError> {
    if metadata.subject_receipt_digest == [0; 32]
        || metadata.table_receipt_digest == [0; 32]
        || metadata.lifecycle_receipt_digest == [0; 32]
        || metadata.proof_nonce == [0; 32]
        || metadata.proof_digest == [0; 32]
        || metadata.recovery_nonce == [0; 32]
    {
        return Err(ObservationProviderError::InvalidState(
            "verified previsible proof metadata contains a zero field".to_owned(),
        ));
    }
    Ok(())
}

fn ready_journal_metadata(
    metadata: &VerifiedPrevisibleProofMetadata,
) -> Result<ReadyProofJournalMetadata, ObservationProviderError> {
    require_nonzero_previsible_metadata(metadata)?;
    if metadata.kind != VerifiedPrevisibleProofKind::Ready
        || !matches!(metadata.rejection_nonce, Some(nonce) if nonce != [0; 32])
    {
        return Err(ObservationProviderError::InvalidState(
            "publication requires exact Ready proof metadata".to_owned(),
        ));
    }
    Ok(ReadyProofJournalMetadata {
        subject_receipt_digest: metadata.subject_receipt_digest,
        table_receipt_digest: metadata.table_receipt_digest,
        lifecycle_receipt_digest: metadata.lifecycle_receipt_digest,
        proof_nonce: metadata.proof_nonce,
        recovery_nonce: metadata.recovery_nonce,
    })
}

fn abort_journal_metadata(
    metadata: &VerifiedPrevisibleProofMetadata,
) -> Result<AbortProofJournalMetadata, ObservationProviderError> {
    require_nonzero_previsible_metadata(metadata)?;
    if metadata.kind != VerifiedPrevisibleProofKind::Abort || metadata.rejection_nonce.is_some() {
        return Err(ObservationProviderError::InvalidState(
            "abort requires exact Abort proof metadata".to_owned(),
        ));
    }
    Ok(AbortProofJournalMetadata {
        subject_absence_digest: metadata.subject_receipt_digest,
        table_absence_digest: metadata.table_receipt_digest,
        lifecycle_absence_digest: metadata.lifecycle_receipt_digest,
        proof_nonce: metadata.proof_nonce,
        recovery_nonce: metadata.recovery_nonce,
    })
}

fn next_registry_sequence(conn: &Connection) -> Result<u64, ObservationProviderError> {
    read_ledger(conn)?
        .ok_or_else(|| ObservationProviderError::RecoveryRequired("missing ledger".to_owned()))?
        .sequence
        .checked_add(1)
        .filter(|sequence| *sequence <= i64::MAX as u64)
        .ok_or_else(|| ObservationProviderError::CapacityExceeded("sequence exhausted".to_owned()))
}

fn mark_previsible_ready(
    conn: &Connection,
    record: &ProviderActivationRecord,
    metadata: &ReadyProofJournalMetadata,
) -> Result<(), ObservationProviderError> {
    let next_sequence = next_registry_sequence(conn)?;
    let (old_phase, old_encoded, old_future) = previsible_accounting(conn, record)?;
    if old_phase != "prepared" {
        return Err(ObservationProviderError::InvalidState(
            "previsible Ready transition is stale or already consumed".to_owned(),
        ));
    }
    let encoded_bytes = previsible_encoded_bytes(record, 5, false, false)?;
    let future_reserved_bytes = PREVISIBLE_TOTAL_BYTES - encoded_bytes;
    let changed = conn.execute(
        "UPDATE observation_previsible_activations
         SET phase='ready',updated_sequence=?1,
             subject_receipt_digest=?2,table_receipt_digest=?3,
             lifecycle_receipt_digest=?4,ready_proof_nonce=?5,
             recovery_nonce=?6,encoded_bytes=?7,future_reserved_bytes=?8
         WHERE activation_nonce=?9 AND operation_id=?10 AND identity_id=?11
           AND identity_class=?12 AND identity_incarnation=?13
           AND declaration_digest=?14 AND phase='prepared'",
        params![
            next_sequence as i64,
            metadata.subject_receipt_digest.as_slice(),
            metadata.table_receipt_digest.as_slice(),
            metadata.lifecycle_receipt_digest.as_slice(),
            metadata.proof_nonce.as_slice(),
            metadata.recovery_nonce.as_slice(),
            encoded_bytes,
            future_reserved_bytes,
            record.activation_nonce.as_slice(),
            record.operation_id,
            record.claims.exact_id,
            class_to_sql(record.claims.expected_class),
            record.claims.incarnation as i64,
            record.claims.declaration_digest.as_bytes().as_slice(),
        ],
    )?;
    if changed != 1 {
        return Err(ObservationProviderError::InvalidState(
            "previsible Ready transition is stale or mismatched".to_owned(),
        ));
    }
    adjust_previsible_capacity(
        conn,
        old_encoded,
        old_future,
        encoded_bytes,
        future_reserved_bytes,
    )
}

fn mark_previsible_publishing(
    conn: &Connection,
    record: &ProviderActivationRecord,
    metadata: &ReadyProofJournalMetadata,
) -> Result<(), ObservationProviderError> {
    let next_sequence = next_registry_sequence(conn)?;
    let (old_phase, _, _) = previsible_accounting(conn, record)?;
    if old_phase != "ready" {
        return Err(ObservationProviderError::InvalidState(
            "previsible Publishing transition is stale or already consumed".to_owned(),
        ));
    }
    let changed = conn.execute(
        "UPDATE observation_previsible_activations
         SET phase='publishing',updated_sequence=?1
         WHERE activation_nonce=?2 AND operation_id=?3 AND identity_id=?4
           AND identity_class=?5 AND identity_incarnation=?6
           AND declaration_digest=?7 AND phase='ready'
           AND subject_receipt_digest=?8 AND table_receipt_digest=?9
           AND lifecycle_receipt_digest=?10 AND ready_proof_nonce=?11
           AND recovery_nonce=?12 AND rejection_nonce IS NULL",
        params![
            next_sequence as i64,
            record.activation_nonce.as_slice(),
            record.operation_id,
            record.claims.exact_id,
            class_to_sql(record.claims.expected_class),
            record.claims.incarnation as i64,
            record.claims.declaration_digest.as_bytes().as_slice(),
            metadata.subject_receipt_digest.as_slice(),
            metadata.table_receipt_digest.as_slice(),
            metadata.lifecycle_receipt_digest.as_slice(),
            metadata.proof_nonce.as_slice(),
            metadata.recovery_nonce.as_slice(),
        ],
    )?;
    if changed != 1 {
        return Err(ObservationProviderError::InvalidState(
            "previsible Publishing transition metadata mismatch".to_owned(),
        ));
    }
    Ok(())
}

fn complete_previsible_publication(
    conn: &Connection,
    record: &ProviderActivationRecord,
    metadata: &ReadyProofJournalMetadata,
) -> Result<(), ObservationProviderError> {
    let next_sequence = next_registry_sequence(conn)?;
    let now_ms = crate::types::now_unix_ms().max(0);
    let (old_phase, old_encoded, old_future) = previsible_accounting(conn, record)?;
    if old_phase != "publishing" {
        return Err(ObservationProviderError::InvalidState(
            "previsible publication is stale or already consumed".to_owned(),
        ));
    }
    let encoded_bytes = previsible_encoded_bytes(record, 5, true, false)?;
    let changed = conn.execute(
        "UPDATE observation_previsible_activations
         SET phase='published',updated_sequence=?1,terminal_at_ms=?2,
             encoded_bytes=?3,future_reserved_bytes=?4
         WHERE activation_nonce=?5 AND operation_id=?6 AND identity_id=?7
           AND identity_class=?8 AND identity_incarnation=?9
           AND declaration_digest=?10 AND phase='publishing'
           AND subject_receipt_digest=?11 AND table_receipt_digest=?12
           AND lifecycle_receipt_digest=?13 AND ready_proof_nonce=?14
           AND recovery_nonce=?15 AND rejection_nonce IS NULL",
        params![
            next_sequence as i64,
            now_ms,
            encoded_bytes,
            AUDIT_CHECKPOINT_BYTES,
            record.activation_nonce.as_slice(),
            record.operation_id,
            record.claims.exact_id,
            class_to_sql(record.claims.expected_class),
            record.claims.incarnation as i64,
            record.claims.declaration_digest.as_bytes().as_slice(),
            metadata.subject_receipt_digest.as_slice(),
            metadata.table_receipt_digest.as_slice(),
            metadata.lifecycle_receipt_digest.as_slice(),
            metadata.proof_nonce.as_slice(),
            metadata.recovery_nonce.as_slice(),
        ],
    )?;
    if changed != 1 {
        return Err(ObservationProviderError::InvalidState(
            "previsible publication is stale or already consumed".to_owned(),
        ));
    }
    let identity_changed = conn.execute(
        "UPDATE observation_identities
         SET lifecycle_state='live',catalog_visible=1,operation_id=NULL
         WHERE id=?1 AND class=?2 AND incarnation=?3 AND declaration_digest=?4
           AND operation_id=?5 AND lifecycle_state='pending' AND catalog_visible=0",
        params![
            record.claims.exact_id,
            class_to_sql(record.claims.expected_class),
            record.claims.incarnation as i64,
            record.claims.declaration_digest.as_bytes().as_slice(),
            record.operation_id,
        ],
    )?;
    if identity_changed != 1 {
        return Err(ObservationProviderError::InvalidState(
            "hidden identity publication projection is incomplete".to_owned(),
        ));
    }
    if record.claims.expected_class == ObservationIdentityClass::Component {
        let component_changed = conn.execute(
            "UPDATE components
             SET catalog_visible=1,operation_id=NULL
             WHERE id=?1 AND identity_incarnation=?2 AND declaration_digest=?3
               AND operation_id=?4 AND lifecycle_state='live' AND catalog_visible=0",
            params![
                record.claims.exact_id,
                record.claims.incarnation as i64,
                record.claims.declaration_digest.as_bytes().as_slice(),
                record.operation_id,
            ],
        )?;
        if component_changed != 1 {
            return Err(ObservationProviderError::InvalidState(
                "hidden component publication projection is incomplete".to_owned(),
            ));
        }
    }
    finish_registration_operation(conn, record)?;
    adjust_previsible_capacity(
        conn,
        old_encoded,
        old_future,
        encoded_bytes,
        AUDIT_CHECKPOINT_BYTES,
    )?;
    Ok(())
}

fn begin_previsible_abort(
    conn: &Connection,
    record: &ProviderActivationRecord,
    metadata: &AbortProofJournalMetadata,
) -> Result<(), ObservationProviderError> {
    let next_sequence = next_registry_sequence(conn)?;
    let (old_phase, old_encoded, old_future) = previsible_accounting(conn, record)?;
    let present_fields = match old_phase.as_str() {
        "prepared" => 5,
        "ready" => 9,
        "rejected" => 10,
        _ => {
            return Err(ObservationProviderError::InvalidState(
                "previsible abort is stale or already consumed".to_owned(),
            ))
        }
    };
    let encoded_bytes = previsible_encoded_bytes(record, present_fields, false, false)?;
    let future_reserved_bytes = PREVISIBLE_TOTAL_BYTES - encoded_bytes;
    let changed = conn.execute(
        "UPDATE observation_previsible_activations
         SET phase='aborting',updated_sequence=?1,
             subject_absence_digest=?2,table_absence_digest=?3,
             lifecycle_absence_digest=?4,abort_proof_nonce=?5,
             recovery_nonce=?6,encoded_bytes=?7,future_reserved_bytes=?8
         WHERE activation_nonce=?9 AND operation_id=?10 AND identity_id=?11
           AND identity_class=?12 AND identity_incarnation=?13
           AND declaration_digest=?14 AND phase=?15",
        params![
            next_sequence as i64,
            metadata.subject_absence_digest.as_slice(),
            metadata.table_absence_digest.as_slice(),
            metadata.lifecycle_absence_digest.as_slice(),
            metadata.proof_nonce.as_slice(),
            metadata.recovery_nonce.as_slice(),
            encoded_bytes,
            future_reserved_bytes,
            record.activation_nonce.as_slice(),
            record.operation_id,
            record.claims.exact_id,
            class_to_sql(record.claims.expected_class),
            record.claims.incarnation as i64,
            record.claims.declaration_digest.as_bytes().as_slice(),
            old_phase,
        ],
    )?;
    if changed != 1 {
        return Err(ObservationProviderError::InvalidState(
            "previsible abort is stale or already consumed".to_owned(),
        ));
    }
    adjust_previsible_capacity(
        conn,
        old_encoded,
        old_future,
        encoded_bytes,
        future_reserved_bytes,
    )
}

fn complete_previsible_abort(
    conn: &Connection,
    record: &ProviderActivationRecord,
    metadata: &AbortProofJournalMetadata,
) -> Result<(), ObservationProviderError> {
    let next_sequence = next_registry_sequence(conn)?;
    let now_ms = crate::types::now_unix_ms().max(0);
    let (old_phase, old_encoded, old_future) = previsible_accounting(conn, record)?;
    if old_phase != "aborting" {
        return Err(ObservationProviderError::InvalidState(
            "previsible abort completion is stale or already consumed".to_owned(),
        ));
    }
    let encoded_bytes = old_encoded.checked_add(8).ok_or_else(|| {
        ObservationProviderError::CapacityExceeded("previsible abort terminal encoding".to_owned())
    })?;
    let changed = conn.execute(
        "UPDATE observation_previsible_activations
         SET phase='aborted',updated_sequence=?1,terminal_at_ms=?2,
             encoded_bytes=?3,future_reserved_bytes=?4
         WHERE activation_nonce=?5 AND operation_id=?6 AND identity_id=?7
           AND identity_class=?8 AND identity_incarnation=?9
           AND declaration_digest=?10 AND phase='aborting'
           AND subject_absence_digest=?11 AND table_absence_digest=?12
           AND lifecycle_absence_digest=?13 AND abort_proof_nonce=?14
           AND recovery_nonce=?15",
        params![
            next_sequence as i64,
            now_ms,
            encoded_bytes,
            AUDIT_CHECKPOINT_BYTES,
            record.activation_nonce.as_slice(),
            record.operation_id,
            record.claims.exact_id,
            class_to_sql(record.claims.expected_class),
            record.claims.incarnation as i64,
            record.claims.declaration_digest.as_bytes().as_slice(),
            metadata.subject_absence_digest.as_slice(),
            metadata.table_absence_digest.as_slice(),
            metadata.lifecycle_absence_digest.as_slice(),
            metadata.proof_nonce.as_slice(),
            metadata.recovery_nonce.as_slice(),
        ],
    )?;
    if changed != 1 {
        return Err(ObservationProviderError::InvalidState(
            "previsible abort completion metadata mismatch".to_owned(),
        ));
    }
    if record.claims.expected_class == ObservationIdentityClass::Component {
        let component_deleted = conn.execute(
            "DELETE FROM components
             WHERE id=?1 AND identity_incarnation=?2 AND declaration_digest=?3
               AND operation_id=?4 AND lifecycle_state='live' AND catalog_visible=0",
            params![
                record.claims.exact_id,
                record.claims.incarnation as i64,
                record.claims.declaration_digest.as_bytes().as_slice(),
                record.operation_id,
            ],
        )?;
        if component_deleted != 1 {
            return Err(ObservationProviderError::InvalidState(
                "hidden component abort projection is incomplete".to_owned(),
            ));
        }
    }
    let identity_deleted = conn.execute(
        "DELETE FROM observation_identities
         WHERE id=?1 AND class=?2 AND incarnation=?3 AND declaration_digest=?4
           AND operation_id=?5 AND lifecycle_state='pending' AND catalog_visible=0",
        params![
            record.claims.exact_id,
            class_to_sql(record.claims.expected_class),
            record.claims.incarnation as i64,
            record.claims.declaration_digest.as_bytes().as_slice(),
            record.operation_id,
        ],
    )?;
    if identity_deleted != 1 {
        return Err(ObservationProviderError::InvalidState(
            "hidden identity abort projection is incomplete".to_owned(),
        ));
    }
    finish_registration_operation(conn, record)?;
    adjust_previsible_capacity(
        conn,
        old_encoded,
        old_future,
        encoded_bytes,
        AUDIT_CHECKPOINT_BYTES,
    )?;
    Ok(())
}

fn finish_registration_operation(
    conn: &Connection,
    record: &ProviderActivationRecord,
) -> Result<(), ObservationProviderError> {
    let member_changed = conn.execute(
        "UPDATE observation_identity_operation_members SET is_active=0
         WHERE operation_id=?1 AND identity_id=?2 AND identity_class=?3
           AND identity_incarnation=?4 AND declaration_digest=?5 AND is_active=1",
        params![
            record.operation_id,
            record.claims.exact_id,
            class_to_sql(record.claims.expected_class),
            record.claims.incarnation as i64,
            record.claims.declaration_digest.as_bytes().as_slice(),
        ],
    )?;
    let operation_changed = conn.execute(
        "UPDATE observation_identity_operations SET phase='committed',is_active=0
         WHERE operation_id=?1 AND phase='prepared' AND is_active=1",
        params![record.operation_id],
    )?;
    if member_changed != 1 || operation_changed != 1 {
        return Err(ObservationProviderError::InvalidState(
            "registration operation terminal projection is incomplete".to_owned(),
        ));
    }
    Ok(())
}

fn previsible_encoded_bytes(
    record: &ProviderActivationRecord,
    present_digest_or_nonce_fields: i64,
    terminal_present: bool,
    audit_present: bool,
) -> Result<i64, ObservationProviderError> {
    let operation_len = i64::try_from(record.operation_id.len()).map_err(|_| {
        ObservationProviderError::CapacityExceeded("previsible operation id".to_owned())
    })?;
    let identity_len = i64::try_from(record.claims.exact_id.len()).map_err(|_| {
        ObservationProviderError::CapacityExceeded("previsible identity id".to_owned())
    })?;
    previsible_encoded_len_from_lengths(
        operation_len,
        identity_len,
        present_digest_or_nonce_fields,
        terminal_present,
        audit_present,
    )
}

fn previsible_encoded_len_from_lengths(
    operation_len: i64,
    identity_len: i64,
    present_digest_or_nonce_fields: i64,
    terminal_present: bool,
    audit_present: bool,
) -> Result<i64, ObservationProviderError> {
    if operation_len <= 0
        || identity_len <= 0
        || present_digest_or_nonce_fields < 0
        || present_digest_or_nonce_fields > 10
    {
        return Err(ObservationProviderError::RecoveryRequired(
            "invalid previsible canonical field widths".to_owned(),
        ));
    }
    // version + nonce + boot + registry + role + two framed strings +
    // operation/class tags + incarnation/digest/sequences/phase + ten option
    // tags + terminal/audit option tags.  Present 32-byte fields and u64
    // option payloads add only their payload width because the tag is already
    // included in the base.
    let base = 1
        + 32
        + 16
        + 16
        + 1
        + (4 + operation_len)
        + 1
        + (4 + identity_len)
        + 1
        + 8
        + 32
        + 8
        + 1
        + 10
        + 8
        + 1
        + 1;
    let encoded = base
        + present_digest_or_nonce_fields
            .checked_mul(32)
            .ok_or_else(|| {
                ObservationProviderError::CapacityExceeded("previsible receipt fields".to_owned())
            })?
        + if terminal_present { 8 } else { 0 }
        + if audit_present { 8 } else { 0 };
    if !(147..=PREVISIBLE_TOTAL_BYTES).contains(&encoded) {
        return Err(ObservationProviderError::CapacityExceeded(
            "previsible canonical encoding".to_owned(),
        ));
    }
    Ok(encoded)
}

fn previsible_accounting(
    conn: &Connection,
    record: &ProviderActivationRecord,
) -> Result<(String, i64, i64), ObservationProviderError> {
    conn.query_row(
        "SELECT phase,encoded_bytes,future_reserved_bytes
         FROM observation_previsible_activations
         WHERE activation_nonce=?1 AND operation_id=?2 AND identity_id=?3",
        params![
            record.activation_nonce.as_slice(),
            record.operation_id,
            record.claims.exact_id,
        ],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )
    .optional()?
    .ok_or_else(|| {
        ObservationProviderError::InvalidState("previsible journal row is missing".to_owned())
    })
}

fn adjust_previsible_capacity(
    conn: &Connection,
    old_encoded: i64,
    old_future: i64,
    new_encoded: i64,
    new_future: i64,
) -> Result<(), ObservationProviderError> {
    let actual_delta = new_encoded.checked_sub(old_encoded).ok_or_else(|| {
        ObservationProviderError::RecoveryRequired(
            "previsible actual-byte accounting overflow".to_owned(),
        )
    })?;
    let future_delta = new_future.checked_sub(old_future).ok_or_else(|| {
        ObservationProviderError::RecoveryRequired(
            "previsible future-byte accounting overflow".to_owned(),
        )
    })?;
    let changed = conn.execute(
        "UPDATE observation_previsible_capacity
         SET actual_encoded_bytes=actual_encoded_bytes+?1,
             future_reserved_bytes=future_reserved_bytes+?2
         WHERE singleton=1
           AND actual_encoded_bytes+?1 BETWEEN 0 AND ?3
           AND future_reserved_bytes+?2 BETWEEN 0 AND ?3
           AND actual_encoded_bytes+future_reserved_bytes+?1+?2 <= ?3",
        params![actual_delta, future_delta, MAX_PREVISIBLE_COMBINED_BYTES],
    )?;
    if changed != 1 {
        return Err(ObservationProviderError::RecoveryRequired(
            "previsible capacity accounting transition failed".to_owned(),
        ));
    }
    Ok(())
}

fn termination_request_digest(operation_id: &str, ids: &[String]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"advance.contract218.termination-request.v1\0");
    hasher.update((operation_id.len() as u64).to_be_bytes());
    hasher.update(operation_id.as_bytes());
    hasher.update((ids.len() as u64).to_be_bytes());
    for id in ids {
        hasher.update((id.len() as u64).to_be_bytes());
        hasher.update(id.as_bytes());
    }
    hasher.finalize().into()
}

fn termination_member_set_digest(
    claims: &[ObservationIdentityClaims],
) -> Result<[u8; 32], ObservationProviderError> {
    contract123_termination_member_set_digest(claims).map_err(ObservationProviderError::from)
}

fn load_operation_member_claims(
    conn: &Connection,
    operation_id: &str,
) -> Result<Vec<ObservationIdentityClaims>, ObservationProviderError> {
    let mut stmt = conn.prepare(
        "SELECT identity_id FROM observation_identity_operation_members
         WHERE operation_id=?1 ORDER BY identity_id COLLATE BINARY",
    )?;
    let ids = stmt
        .query_map(params![operation_id], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    drop(stmt);
    let mut claims = Vec::with_capacity(ids.len());
    for id in ids {
        claims.push(read_identity_claims(conn, &id)?.ok_or_else(|| {
            ObservationProviderError::RecoveryRequired(
                "termination member identity is missing".to_owned(),
            )
        })?);
    }
    Ok(claims)
}

fn termination_finalize_encoded_len(
    operation_id_len: usize,
    present_digest_or_nonce_fields: i64,
    finalize_sequence_present: bool,
    terminal_present: bool,
    audit_present: bool,
) -> Result<i64, ObservationProviderError> {
    let operation_id_len = i64::try_from(operation_id_len).map_err(|_| {
        ObservationProviderError::CapacityExceeded("termination operation id".to_owned())
    })?;
    if !(1..=256).contains(&operation_id_len) || !(0..=6).contains(&present_digest_or_nonce_fields)
    {
        return Err(ObservationProviderError::RecoveryRequired(
            "termination finalization canonical field widths are invalid".to_owned(),
        ));
    }
    // Version, framed operation id, kind, registry, boot, prepare digest,
    // prepare nonce/sequence, member digest, phase, and nine option tags.
    let base = 1 + (4 + operation_id_len) + 1 + 16 + 16 + 32 + 32 + 8 + 32 + 1 + 9;
    let encoded = base
        + present_digest_or_nonce_fields * 32
        + if finalize_sequence_present { 8 } else { 0 }
        + if terminal_present { 8 } else { 0 }
        + if audit_present { 8 } else { 0 };
    if !(1..=TERMINATION_FINALIZE_TOTAL_BYTES).contains(&encoded) {
        return Err(ObservationProviderError::CapacityExceeded(
            "termination finalization canonical encoding".to_owned(),
        ));
    }
    Ok(encoded)
}

fn reserve_termination_finalize_capacity(
    conn: &Connection,
    encoded_bytes: i64,
    max_combined_bytes: i64,
) -> Result<i64, ObservationProviderError> {
    if !(TERMINATION_FINALIZE_TOTAL_BYTES..=MAX_TERMINATION_FINALIZE_COMBINED_BYTES)
        .contains(&max_combined_bytes)
    {
        return Err(ObservationProviderError::CapacityExceeded(
            "termination finalization effective byte cap".to_owned(),
        ));
    }
    let future_reserved_bytes = TERMINATION_FINALIZE_TOTAL_BYTES
        .checked_sub(encoded_bytes)
        .ok_or_else(|| {
            ObservationProviderError::CapacityExceeded(
                "termination finalization reservation".to_owned(),
            )
        })?;
    let changed = conn.execute(
        "UPDATE observation_termination_finalize_capacity
         SET row_count=row_count+1,
             actual_encoded_bytes=actual_encoded_bytes+?1,
             future_reserved_bytes=future_reserved_bytes+?2
         WHERE singleton=1 AND row_count < ?3
           AND actual_encoded_bytes+future_reserved_bytes+?4 <= ?5",
        params![
            encoded_bytes,
            future_reserved_bytes,
            MAX_TERMINATION_FINALIZE_ROWS,
            TERMINATION_FINALIZE_TOTAL_BYTES,
            max_combined_bytes,
        ],
    )?;
    if changed != 1 {
        return Err(ObservationProviderError::CapacityExceeded(
            "termination finalization row/byte reservation".to_owned(),
        ));
    }
    Ok(future_reserved_bytes)
}

fn adjust_termination_finalize_capacity(
    conn: &Connection,
    old_encoded: i64,
    old_future: i64,
    new_encoded: i64,
    new_future: i64,
) -> Result<(), ObservationProviderError> {
    let actual_delta = new_encoded.checked_sub(old_encoded).ok_or_else(|| {
        ObservationProviderError::RecoveryRequired(
            "termination actual-byte accounting overflow".to_owned(),
        )
    })?;
    let future_delta = new_future.checked_sub(old_future).ok_or_else(|| {
        ObservationProviderError::RecoveryRequired(
            "termination future-byte accounting overflow".to_owned(),
        )
    })?;
    let changed = conn.execute(
        "UPDATE observation_termination_finalize_capacity
         SET actual_encoded_bytes=actual_encoded_bytes+?1,
             future_reserved_bytes=future_reserved_bytes+?2
         WHERE singleton=1
           AND actual_encoded_bytes+?1 BETWEEN 0 AND ?3
           AND future_reserved_bytes+?2 BETWEEN 0 AND ?3
           AND actual_encoded_bytes+future_reserved_bytes+?1+?2 <= ?3",
        params![
            actual_delta,
            future_delta,
            MAX_TERMINATION_FINALIZE_COMBINED_BYTES,
        ],
    )?;
    if changed != 1 {
        return Err(ObservationProviderError::RecoveryRequired(
            "termination finalization capacity transition failed".to_owned(),
        ));
    }
    Ok(())
}

fn validate_carrier_migration_plan(
    config: &ObservationProviderConfig,
    plan: &CarrierMigrationPlanMetadata,
) -> Result<(), ObservationProviderError> {
    let future = plan
        .planned_row_count
        .checked_mul(CARRIER_MIGRATION_ROW_RESERVATION_BYTES)
        .ok_or_else(|| {
            ObservationProviderError::CapacityExceeded(
                "carrier-migration worst-case row bytes".to_owned(),
            )
        })?;
    if plan.registry_instance != config.registry_instance
        || plan.migration_id == [0; 16]
        || plan.m019_ledger_instance == [0; 16]
        || plan.cross_owner_key_epoch == 0
        || plan.target_m019_sequence < plan.source_m019_sequence
        || plan.source_m019_sequence > i64::MAX as u64
        || plan.target_m019_sequence > i64::MAX as u64
        || plan.sqlite_retained_high_water > i64::MAX as u64
        || plan.jsonl_retained_high_water > i64::MAX as u64
        || plan.planned_row_count > MAX_CARRIER_MIGRATION_ROWS
        || future > MAX_CARRIER_MIGRATION_COMBINED_BYTES
        || [
            plan.source_m019_head,
            plan.source_m019_state_root,
            plan.target_m019_head,
            plan.target_m019_state_root,
            plan.sqlite_store_instance_digest,
            plan.sqlite_source_root,
            plan.sqlite_target_root,
            plan.jsonl_store_instance_digest,
            plan.jsonl_source_inventory_root,
            plan.jsonl_target_inventory_root,
            plan.frozen_row_set_digest,
            plan.owner_plan_digest,
            plan.freeze_receipt_digest,
        ]
        .contains(&[0; 32])
    {
        return Err(ObservationProviderError::CapacityExceeded(
            "carrier-migration row/count/byte reservation or typed plan binding".to_owned(),
        ));
    }
    Ok(())
}

fn validate_carrier_migration_row(
    row: &CarrierMigrationRowMetadata,
) -> Result<(), ObservationProviderError> {
    if !matches!(row.store_kind, 1 | 2)
        || !(300..=555).contains(&row.legacy_receipt.len())
        || [
            row.event_key_digest,
            row.event_cursor_digest,
            row.receipt_nonce,
            row.owner_intent_digest,
            row.owner_preimage_digest,
            row.owner_postimage_digest,
        ]
        .contains(&[0; 32])
    {
        return Err(ObservationProviderError::InvalidInput(
            "carrier-migration typed row is malformed".to_owned(),
        ));
    }
    Ok(())
}

fn carrier_migration_row_encoded_len(
    legacy_receipt_len: usize,
    finalized: bool,
) -> Result<i64, ObservationProviderError> {
    let receipt_len = i64::try_from(legacy_receipt_len).map_err(|_| {
        ObservationProviderError::CapacityExceeded(
            "carrier-migration legacy receipt encoding".to_owned(),
        )
    })?;
    if !(300..=555).contains(&receipt_len) {
        return Err(ObservationProviderError::RecoveryRequired(
            "carrier-migration legacy receipt length is noncanonical".to_owned(),
        ));
    }
    // Version, migration/store, six fixed row bindings, framed legacy
    // receipt, phase, and two option tags. Finalized adds digest+sequence.
    let encoded = 217_i64
        .checked_add(receipt_len)
        .and_then(|value| value.checked_add(if finalized { 40 } else { 0 }))
        .ok_or_else(|| {
            ObservationProviderError::CapacityExceeded("carrier-migration row encoding".to_owned())
        })?;
    if !(1..=CARRIER_MIGRATION_ROW_RESERVATION_BYTES as i64).contains(&encoded) {
        return Err(ObservationProviderError::CapacityExceeded(
            "carrier-migration row terminal reservation".to_owned(),
        ));
    }
    Ok(encoded)
}

fn carrier_migration_owner_commit_digest(
    plan: &CarrierMigrationPlanMetadata,
    row: &CarrierMigrationRowMetadata,
    committed: &RegistryAnchorTuple,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"advance.contract218.carrier-migration-owner-commit-foundation.v1\0");
    hasher.update(plan.migration_id);
    hasher.update(plan.registry_instance);
    hasher.update([row.store_kind]);
    hasher.update(row.event_key_digest);
    hasher.update(row.event_cursor_digest);
    hasher.update(row.receipt_nonce);
    hasher.update(row.owner_intent_digest);
    hasher.update(row.owner_preimage_digest);
    hasher.update(row.owner_postimage_digest);
    hasher.update(committed.sequence.to_be_bytes());
    hasher.update(committed.head);
    hasher.update(committed.state_root);
    hasher.update(plan.m019_ledger_instance);
    hasher.update(plan.target_m019_sequence.to_be_bytes());
    hasher.update(plan.target_m019_head);
    hasher.update(plan.target_m019_state_root);
    hasher.finalize().into()
}

fn carrier_migration_owner_finalized_digest(plan: &CarrierMigrationPlanMetadata) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"advance.contract218.carrier-migration-owner-finalized-foundation.v1\0");
    hasher.update(plan.migration_id);
    hasher.update(plan.registry_instance);
    hasher.update(plan.m019_ledger_instance);
    hasher.update(plan.planned_row_count.to_be_bytes());
    hasher.update(plan.owner_plan_digest);
    hasher.update(plan.target_m019_sequence.to_be_bytes());
    hasher.update(plan.target_m019_head);
    hasher.update(plan.target_m019_state_root);
    hasher.update(plan.sqlite_target_root);
    hasher.update(plan.jsonl_target_inventory_root);
    hasher.finalize().into()
}

#[cfg(any(test, feature = "test-support"))]
fn carrier_migration_fixture_digest(seed: u64, label: &[u8], ordinal: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"advance.contract218.carrier-migration-test-fixture.v1\0");
    hasher.update(seed.to_be_bytes());
    hasher.update((label.len() as u64).to_be_bytes());
    hasher.update(label);
    hasher.update(ordinal.to_be_bytes());
    hasher.finalize().into()
}

#[cfg(any(test, feature = "test-support"))]
fn carrier_migration_fixture_plan(
    registry_instance: [u8; 16],
    seed: u64,
    planned_row_count: u64,
) -> CarrierMigrationPlanMetadata {
    let migration = carrier_migration_fixture_digest(seed, b"migration", 0);
    let ledger = carrier_migration_fixture_digest(seed, b"ledger", 0);
    let source_sequence = seed;
    let target_sequence = source_sequence
        .saturating_add(planned_row_count)
        .saturating_add(1);
    CarrierMigrationPlanMetadata {
        migration_id: migration[..16].try_into().expect("fixed fixture width"),
        registry_instance,
        m019_ledger_instance: ledger[..16].try_into().expect("fixed fixture width"),
        cross_owner_key_epoch: 1,
        source_m019_sequence: source_sequence,
        source_m019_head: carrier_migration_fixture_digest(seed, b"source-head", 0),
        source_m019_state_root: carrier_migration_fixture_digest(seed, b"source-root", 0),
        target_m019_sequence: target_sequence,
        target_m019_head: carrier_migration_fixture_digest(seed, b"target-head", 0),
        target_m019_state_root: carrier_migration_fixture_digest(seed, b"target-root", 0),
        sqlite_store_instance_digest: carrier_migration_fixture_digest(seed, b"sqlite-store", 0),
        sqlite_retained_high_water: source_sequence,
        sqlite_source_root: carrier_migration_fixture_digest(seed, b"sqlite-source", 0),
        sqlite_target_root: carrier_migration_fixture_digest(seed, b"sqlite-target", 0),
        jsonl_store_instance_digest: carrier_migration_fixture_digest(seed, b"jsonl-store", 0),
        jsonl_retained_high_water: source_sequence,
        jsonl_source_inventory_root: carrier_migration_fixture_digest(seed, b"jsonl-source", 0),
        jsonl_target_inventory_root: carrier_migration_fixture_digest(seed, b"jsonl-target", 0),
        frozen_row_set_digest: carrier_migration_fixture_digest(seed, b"frozen-set", 0),
        owner_plan_digest: carrier_migration_fixture_digest(seed, b"owner-plan", 0),
        freeze_receipt_digest: carrier_migration_fixture_digest(seed, b"freeze", 0),
        planned_row_count,
    }
}

#[cfg(any(test, feature = "test-support"))]
fn carrier_migration_fixture_row(
    plan: &CarrierMigrationPlanMetadata,
    ordinal: u64,
    store: CarrierMigrationStore,
) -> CarrierMigrationRowMetadata {
    let seed = u64::from_be_bytes(
        plan.migration_id[..8]
            .try_into()
            .expect("fixed fixture width"),
    );
    let receipt_block = carrier_migration_fixture_digest(seed, b"legacy-receipt", ordinal);
    let mut legacy_receipt = Vec::with_capacity(300);
    while legacy_receipt.len() < 300 {
        legacy_receipt.extend_from_slice(&receipt_block);
    }
    legacy_receipt.truncate(300);
    let mut event_key_digest = carrier_migration_fixture_digest(seed, b"event-key", ordinal);
    event_key_digest[..8].copy_from_slice(&ordinal.to_be_bytes());
    CarrierMigrationRowMetadata {
        ordinal,
        store_kind: store.tag(),
        event_key_digest,
        event_cursor_digest: carrier_migration_fixture_digest(seed, b"event-cursor", ordinal),
        receipt_nonce: carrier_migration_fixture_digest(seed, b"receipt-nonce", ordinal),
        legacy_receipt,
        owner_intent_digest: carrier_migration_fixture_digest(seed, b"owner-intent", ordinal),
        owner_preimage_digest: carrier_migration_fixture_digest(seed, b"owner-preimage", ordinal),
        owner_postimage_digest: carrier_migration_fixture_digest(seed, b"owner-postimage", ordinal),
    }
}

fn carrier_migration_header_identity_matches(
    conn: &Connection,
    plan: &CarrierMigrationPlanMetadata,
) -> Result<bool, ObservationProviderError> {
    let exact: i64 = conn.query_row(
        "SELECT COUNT(*) FROM observation_carrier_migrations
         WHERE migration_id=?1 AND registry_instance_id=?2
           AND m019_ledger_instance_id=?3 AND cross_owner_key_epoch=?4
           AND source_m019_sequence=?5 AND source_m019_head=?6
           AND source_m019_state_root=?7 AND target_m019_sequence=?8
           AND target_m019_head=?9 AND target_m019_state_root=?10
           AND sqlite_store_instance_digest=?11 AND sqlite_retained_high_water=?12
           AND sqlite_source_root=?13 AND sqlite_target_root=?14
           AND jsonl_store_instance_digest=?15 AND jsonl_retained_high_water=?16
           AND jsonl_source_inventory_root=?17 AND jsonl_target_inventory_root=?18
           AND frozen_row_set_digest=?19 AND owner_plan_digest=?20
           AND freeze_receipt_digest=?21 AND planned_row_count=?22",
        params![
            plan.migration_id.as_slice(),
            plan.registry_instance.as_slice(),
            plan.m019_ledger_instance.as_slice(),
            i64::from(plan.cross_owner_key_epoch),
            plan.source_m019_sequence as i64,
            plan.source_m019_head.as_slice(),
            plan.source_m019_state_root.as_slice(),
            plan.target_m019_sequence as i64,
            plan.target_m019_head.as_slice(),
            plan.target_m019_state_root.as_slice(),
            plan.sqlite_store_instance_digest.as_slice(),
            plan.sqlite_retained_high_water as i64,
            plan.sqlite_source_root.as_slice(),
            plan.sqlite_target_root.as_slice(),
            plan.jsonl_store_instance_digest.as_slice(),
            plan.jsonl_retained_high_water as i64,
            plan.jsonl_source_inventory_root.as_slice(),
            plan.jsonl_target_inventory_root.as_slice(),
            plan.frozen_row_set_digest.as_slice(),
            plan.owner_plan_digest.as_slice(),
            plan.freeze_receipt_digest.as_slice(),
            plan.planned_row_count as i64,
        ],
        |row| row.get(0),
    )?;
    if exact == 1 {
        return Ok(true);
    }
    let same_id: i64 = conn.query_row(
        "SELECT COUNT(*) FROM observation_carrier_migrations WHERE migration_id=?1",
        params![plan.migration_id.as_slice()],
        |row| row.get(0),
    )?;
    if same_id != 0 {
        return Err(ObservationProviderError::RecoveryRequired(
            "durable carrier-migration header differs from its opaque plan".to_owned(),
        ));
    }
    Ok(false)
}

fn reserve_carrier_migration_operation(
    conn: &Connection,
    plan: &CarrierMigrationPlanMetadata,
) -> Result<(), ObservationProviderError> {
    let existing: i64 = conn.query_row(
        "SELECT COUNT(*) FROM observation_carrier_migrations",
        [],
        |row| row.get(0),
    )?;
    if existing != 0 {
        return Err(ObservationProviderError::IdentityConflict);
    }
    let future = plan
        .planned_row_count
        .checked_mul(CARRIER_MIGRATION_ROW_RESERVATION_BYTES)
        .filter(|value| *value <= MAX_CARRIER_MIGRATION_COMBINED_BYTES)
        .ok_or_else(|| {
            ObservationProviderError::CapacityExceeded(
                "carrier-migration full terminal reservation".to_owned(),
            )
        })?;
    let phase = if plan.planned_row_count == 0 {
        "verified"
    } else {
        "issuing"
    };
    let sequence = next_registry_sequence(conn)?;
    conn.execute(
        "INSERT INTO observation_carrier_migrations
            (migration_id,registry_instance_id,m019_ledger_instance_id,
             cross_owner_key_epoch,source_m019_sequence,source_m019_head,
             source_m019_state_root,target_m019_sequence,target_m019_head,
             target_m019_state_root,sqlite_store_instance_digest,
             sqlite_retained_high_water,sqlite_source_root,sqlite_target_root,
             jsonl_store_instance_digest,jsonl_retained_high_water,
             jsonl_source_inventory_root,jsonl_target_inventory_root,
             frozen_row_set_digest,owner_plan_digest,freeze_receipt_digest,
             planned_row_count,issued_row_count,finalized_row_count,
             actual_encoded_bytes,future_reserved_bytes,phase,updated_registry_sequence)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,
                 ?15,?16,?17,?18,?19,?20,?21,?22,0,0,0,?23,?24,?25)",
        params![
            plan.migration_id.as_slice(),
            plan.registry_instance.as_slice(),
            plan.m019_ledger_instance.as_slice(),
            i64::from(plan.cross_owner_key_epoch),
            plan.source_m019_sequence as i64,
            plan.source_m019_head.as_slice(),
            plan.source_m019_state_root.as_slice(),
            plan.target_m019_sequence as i64,
            plan.target_m019_head.as_slice(),
            plan.target_m019_state_root.as_slice(),
            plan.sqlite_store_instance_digest.as_slice(),
            plan.sqlite_retained_high_water as i64,
            plan.sqlite_source_root.as_slice(),
            plan.sqlite_target_root.as_slice(),
            plan.jsonl_store_instance_digest.as_slice(),
            plan.jsonl_retained_high_water as i64,
            plan.jsonl_source_inventory_root.as_slice(),
            plan.jsonl_target_inventory_root.as_slice(),
            plan.frozen_row_set_digest.as_slice(),
            plan.owner_plan_digest.as_slice(),
            plan.freeze_receipt_digest.as_slice(),
            plan.planned_row_count as i64,
            future as i64,
            phase,
            sequence as i64,
        ],
    )?;
    Ok(())
}

fn prepare_carrier_migration_row_operation(
    conn: &Connection,
    plan: &CarrierMigrationPlanMetadata,
    row: &CarrierMigrationRowMetadata,
) -> Result<(), ObservationProviderError> {
    if !carrier_migration_header_identity_matches(conn, plan)?
        || row.ordinal >= plan.planned_row_count
    {
        return Err(ObservationProviderError::InvalidState(
            "carrier-migration row is outside its rooted plan".to_owned(),
        ));
    }
    validate_carrier_migration_row(row)?;
    let (phase, planned, issued, actual, future): (String, i64, i64, i64, i64) = conn.query_row(
        "SELECT phase,planned_row_count,issued_row_count,
                    actual_encoded_bytes,future_reserved_bytes
             FROM observation_carrier_migrations WHERE migration_id=?1",
        params![plan.migration_id.as_slice()],
        |record| {
            Ok((
                record.get(0)?,
                record.get(1)?,
                record.get(2)?,
                record.get(3)?,
                record.get(4)?,
            ))
        },
    )?;
    if phase != "issuing"
        || u64::try_from(planned).ok() != Some(plan.planned_row_count)
        || u64::try_from(issued).ok() != Some(row.ordinal)
        || future < CARRIER_MIGRATION_ROW_RESERVATION_BYTES as i64
    {
        return Err(ObservationProviderError::InvalidState(
            "carrier-migration prepared rows are not the canonical planned prefix".to_owned(),
        ));
    }
    let prior: Option<(i64, Vec<u8>)> = conn
        .query_row(
            "SELECT store_kind,event_key_digest
             FROM observation_carrier_migration_rows
             WHERE migration_id=?1
             ORDER BY store_kind DESC,event_key_digest DESC LIMIT 1",
            params![plan.migration_id.as_slice()],
            |record| Ok((record.get(0)?, record.get(1)?)),
        )
        .optional()?;
    if let Some((prior_store, prior_key)) = prior {
        if (prior_store, prior_key.as_slice())
            >= (i64::from(row.store_kind), row.event_key_digest.as_slice())
        {
            return Err(ObservationProviderError::InvalidState(
                "carrier-migration row does not extend canonical owner order".to_owned(),
            ));
        }
    }
    let encoded = carrier_migration_row_encoded_len(row.legacy_receipt.len(), false)?;
    conn.execute(
        "INSERT INTO observation_carrier_migration_rows
            (migration_id,store_kind,event_key_digest,event_cursor_digest,
             receipt_nonce,legacy_receipt,owner_intent_digest,
             owner_preimage_digest,owner_postimage_digest,phase,
             owner_commit_receipt_digest,finalized_registry_sequence,encoded_bytes)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,'prepared',NULL,NULL,?10)",
        params![
            plan.migration_id.as_slice(),
            i64::from(row.store_kind),
            row.event_key_digest.as_slice(),
            row.event_cursor_digest.as_slice(),
            row.receipt_nonce.as_slice(),
            row.legacy_receipt.as_slice(),
            row.owner_intent_digest.as_slice(),
            row.owner_preimage_digest.as_slice(),
            row.owner_postimage_digest.as_slice(),
            encoded,
        ],
    )?;
    let next_issued = issued + 1;
    let next_phase = if next_issued == planned {
        "owner-ready"
    } else {
        "issuing"
    };
    let changed = conn.execute(
        "UPDATE observation_carrier_migrations
         SET issued_row_count=?1,actual_encoded_bytes=?2,
             future_reserved_bytes=?3,phase=?4,updated_registry_sequence=?5
         WHERE migration_id=?6 AND phase='issuing'
           AND issued_row_count=?7 AND actual_encoded_bytes=?8
           AND future_reserved_bytes=?9",
        params![
            next_issued,
            actual + encoded,
            future - CARRIER_MIGRATION_ROW_RESERVATION_BYTES as i64,
            next_phase,
            next_registry_sequence(conn)? as i64,
            plan.migration_id.as_slice(),
            issued,
            actual,
            future,
        ],
    )?;
    if changed != 1 {
        return Err(ObservationProviderError::InvalidState(
            "carrier-migration header reservation changed during row prepare".to_owned(),
        ));
    }
    Ok(())
}

fn finalize_carrier_migration_row_operation(
    conn: &Connection,
    plan: &CarrierMigrationPlanMetadata,
    row: &CarrierMigrationRowMetadata,
    receipt_digest: [u8; 32],
) -> Result<(), ObservationProviderError> {
    if !carrier_migration_header_identity_matches(conn, plan)? || receipt_digest == [0; 32] {
        return Err(ObservationProviderError::InvalidState(
            "carrier-migration finalize binding is malformed".to_owned(),
        ));
    }
    let (phase, planned, finalized, actual): (String, i64, i64, i64) = conn.query_row(
        "SELECT phase,planned_row_count,finalized_row_count,actual_encoded_bytes
         FROM observation_carrier_migrations WHERE migration_id=?1",
        params![plan.migration_id.as_slice()],
        |record| {
            Ok((
                record.get(0)?,
                record.get(1)?,
                record.get(2)?,
                record.get(3)?,
            ))
        },
    )?;
    if phase != "owner-ready" || planned <= 0 || finalized >= planned {
        return Err(ObservationProviderError::InvalidState(
            "carrier-migration header is not owner-ready".to_owned(),
        ));
    }
    let prepared_encoded = carrier_migration_row_encoded_len(row.legacy_receipt.len(), false)?;
    let finalized_encoded = carrier_migration_row_encoded_len(row.legacy_receipt.len(), true)?;
    let row_changed = conn.execute(
        "UPDATE observation_carrier_migration_rows
         SET phase='finalized',owner_commit_receipt_digest=?1,
             finalized_registry_sequence=?2,encoded_bytes=?3
         WHERE migration_id=?4 AND store_kind=?5 AND event_key_digest=?6
           AND event_cursor_digest=?7 AND receipt_nonce=?8 AND legacy_receipt=?9
           AND owner_intent_digest=?10 AND owner_preimage_digest=?11
           AND owner_postimage_digest=?12 AND phase='prepared'
           AND owner_commit_receipt_digest IS NULL
           AND finalized_registry_sequence IS NULL AND encoded_bytes=?13",
        params![
            receipt_digest.as_slice(),
            next_registry_sequence(conn)? as i64,
            finalized_encoded,
            plan.migration_id.as_slice(),
            i64::from(row.store_kind),
            row.event_key_digest.as_slice(),
            row.event_cursor_digest.as_slice(),
            row.receipt_nonce.as_slice(),
            row.legacy_receipt.as_slice(),
            row.owner_intent_digest.as_slice(),
            row.owner_preimage_digest.as_slice(),
            row.owner_postimage_digest.as_slice(),
            prepared_encoded,
        ],
    )?;
    if row_changed != 1 {
        return Err(ObservationProviderError::InvalidState(
            "carrier-migration owner receipt does not name one prepared row".to_owned(),
        ));
    }
    let next_finalized = finalized + 1;
    let next_phase = if next_finalized == planned {
        "verifying"
    } else {
        "owner-ready"
    };
    let header_changed = conn.execute(
        "UPDATE observation_carrier_migrations
         SET finalized_row_count=?1,actual_encoded_bytes=?2,
             phase=?3,updated_registry_sequence=?4
         WHERE migration_id=?5 AND phase='owner-ready'
           AND finalized_row_count=?6 AND actual_encoded_bytes=?7",
        params![
            next_finalized,
            actual + (finalized_encoded - prepared_encoded),
            next_phase,
            next_registry_sequence(conn)? as i64,
            plan.migration_id.as_slice(),
            finalized,
            actual,
        ],
    )?;
    if header_changed != 1 {
        return Err(ObservationProviderError::InvalidState(
            "carrier-migration finalized counter transition is stale".to_owned(),
        ));
    }
    Ok(())
}

fn verify_carrier_migration_owner_finalized_operation(
    conn: &Connection,
    plan: &CarrierMigrationPlanMetadata,
) -> Result<(), ObservationProviderError> {
    if !carrier_migration_header_identity_matches(conn, plan)? {
        return Err(ObservationProviderError::InvalidState(
            "carrier-migration verified header is missing".to_owned(),
        ));
    }
    let changed = conn.execute(
        "UPDATE observation_carrier_migrations
         SET phase='verified',updated_registry_sequence=?1
         WHERE migration_id=?2 AND phase='verifying'
           AND planned_row_count>0
           AND issued_row_count=planned_row_count
           AND finalized_row_count=planned_row_count
           AND future_reserved_bytes=0",
        params![
            next_registry_sequence(conn)? as i64,
            plan.migration_id.as_slice(),
        ],
    )?;
    if changed != 1 {
        return Err(ObservationProviderError::InvalidState(
            "carrier-migration exact owner target is not ready for verification".to_owned(),
        ));
    }
    Ok(())
}

fn verify_carrier_migration_read_world(
    anchor: &dyn RegistryAnchorTransaction,
    conn: &Connection,
) -> Result<RegistryAnchorTuple, ObservationProviderError> {
    let ledger = read_ledger(conn)?.ok_or_else(|| {
        ObservationProviderError::RecoveryRequired("missing identity ledger".to_owned())
    })?;
    reconcile_external_anchor(anchor, &ledger)?;
    verify_complete_roots(conn, &ledger)?;
    validate_durable_invariants(conn)?;
    Ok(ledger)
}

fn read_carrier_migration_phase_exact(
    conn: &Connection,
    plan: &CarrierMigrationPlanMetadata,
) -> Result<Option<CarrierMigrationRecoveryPhase>, ObservationProviderError> {
    if !carrier_migration_header_identity_matches(conn, plan)? {
        return Ok(None);
    }
    let phase: String = conn.query_row(
        "SELECT phase FROM observation_carrier_migrations WHERE migration_id=?1",
        params![plan.migration_id.as_slice()],
        |row| row.get(0),
    )?;
    let phase = match phase.as_str() {
        "issuing" => CarrierMigrationRecoveryPhase::Issuing,
        "owner-ready" => CarrierMigrationRecoveryPhase::OwnerReady,
        "verifying" => CarrierMigrationRecoveryPhase::Verifying,
        "verified" => CarrierMigrationRecoveryPhase::Verified,
        _ => {
            return Err(ObservationProviderError::RecoveryRequired(
                "durable carrier-migration phase is unknown".to_owned(),
            ))
        }
    };
    Ok(Some(phase))
}

fn carrier_migration_prepared_row_matches(
    conn: &Connection,
    plan: &CarrierMigrationPlanMetadata,
    row: &CarrierMigrationRowMetadata,
) -> Result<bool, ObservationProviderError> {
    if !carrier_migration_header_identity_matches(conn, plan)? {
        return Ok(false);
    }
    let exact: i64 = conn.query_row(
        "SELECT COUNT(*) FROM observation_carrier_migration_rows
         WHERE migration_id=?1 AND store_kind=?2 AND event_key_digest=?3
           AND event_cursor_digest=?4 AND receipt_nonce=?5 AND legacy_receipt=?6
           AND owner_intent_digest=?7 AND owner_preimage_digest=?8
           AND owner_postimage_digest=?9 AND phase='prepared'
           AND owner_commit_receipt_digest IS NULL
           AND finalized_registry_sequence IS NULL AND encoded_bytes=?10",
        params![
            plan.migration_id.as_slice(),
            i64::from(row.store_kind),
            row.event_key_digest.as_slice(),
            row.event_cursor_digest.as_slice(),
            row.receipt_nonce.as_slice(),
            row.legacy_receipt.as_slice(),
            row.owner_intent_digest.as_slice(),
            row.owner_preimage_digest.as_slice(),
            row.owner_postimage_digest.as_slice(),
            carrier_migration_row_encoded_len(row.legacy_receipt.len(), false)?,
        ],
        |record| record.get(0),
    )?;
    if exact == 1 {
        return Ok(true);
    }
    let same_key: i64 = conn.query_row(
        "SELECT COUNT(*) FROM observation_carrier_migration_rows
         WHERE migration_id=?1 AND store_kind=?2 AND event_key_digest=?3",
        params![
            plan.migration_id.as_slice(),
            i64::from(row.store_kind),
            row.event_key_digest.as_slice(),
        ],
        |record| record.get(0),
    )?;
    if same_key != 0 {
        return Err(ObservationProviderError::InvalidState(
            "durable carrier-migration row differs from the typed owner intent".to_owned(),
        ));
    }
    Ok(false)
}

fn carrier_migration_finalized_row_matches(
    conn: &Connection,
    plan: &CarrierMigrationPlanMetadata,
    row: &CarrierMigrationRowMetadata,
    receipt_digest: [u8; 32],
) -> Result<bool, ObservationProviderError> {
    if !carrier_migration_header_identity_matches(conn, plan)? {
        return Ok(false);
    }
    let exact: i64 = conn.query_row(
        "SELECT COUNT(*) FROM observation_carrier_migration_rows
         WHERE migration_id=?1 AND store_kind=?2 AND event_key_digest=?3
           AND event_cursor_digest=?4 AND receipt_nonce=?5 AND legacy_receipt=?6
           AND owner_intent_digest=?7 AND owner_preimage_digest=?8
           AND owner_postimage_digest=?9 AND phase='finalized'
           AND owner_commit_receipt_digest=?10
           AND finalized_registry_sequence IS NOT NULL AND encoded_bytes=?11",
        params![
            plan.migration_id.as_slice(),
            i64::from(row.store_kind),
            row.event_key_digest.as_slice(),
            row.event_cursor_digest.as_slice(),
            row.receipt_nonce.as_slice(),
            row.legacy_receipt.as_slice(),
            row.owner_intent_digest.as_slice(),
            row.owner_preimage_digest.as_slice(),
            row.owner_postimage_digest.as_slice(),
            receipt_digest.as_slice(),
            carrier_migration_row_encoded_len(row.legacy_receipt.len(), true)?,
        ],
        |record| record.get(0),
    )?;
    if exact == 1 {
        return Ok(true);
    }
    // A byte-exact Prepared row is the normal preimage for the first owner
    // finalization.  It is not a conflicting same-key row: return `false` so
    // the caller can perform the anchored Prepared -> Finalized transition.
    // The prepared matcher itself rejects any same-key row whose immutable
    // owner intent differs, preserving the tamper/fork check here.
    if carrier_migration_prepared_row_matches(conn, plan, row)? {
        return Ok(false);
    }
    let same_key: i64 = conn.query_row(
        "SELECT COUNT(*) FROM observation_carrier_migration_rows
         WHERE migration_id=?1 AND store_kind=?2 AND event_key_digest=?3",
        params![
            plan.migration_id.as_slice(),
            i64::from(row.store_kind),
            row.event_key_digest.as_slice(),
        ],
        |record| record.get(0),
    )?;
    if same_key != 0 {
        return Err(ObservationProviderError::InvalidState(
            "durable carrier-migration finalized row differs from its owner receipt".to_owned(),
        ));
    }
    Ok(false)
}

#[allow(clippy::too_many_arguments)]
fn prepare_termination_operation(
    conn: &Connection,
    record: &TerminationOperationRecord,
    expected_members: &[ObservationIdentityClaims],
    retain_until_ms: u64,
    receipt_set: &VerifiedTerminationPrepareReceiptSet,
    prepare_ack_digest: [u8; 32],
    prepare_ack_nonce: [u8; 32],
    registry_instance: [u8; 16],
    operation_boot: [u8; 16],
    operation_kind: &str,
    expected_class: ObservationIdentityClass,
    max_combined_bytes: i64,
    admission_limits: AdmissionCapacityLimits,
) -> Result<(), ObservationProviderError> {
    if next_registry_sequence(conn)? != record.registry_sequence
        || prepare_ack_digest == [0; 32]
        || prepare_ack_nonce == [0; 32]
    {
        return Err(ObservationProviderError::InvalidState(
            "termination prepare sequence or acknowledgement projection is stale".to_owned(),
        ));
    }
    let metadata = receipt_set.metadata();
    if metadata.registry_instance != registry_instance
        || metadata.boot != operation_boot
        || metadata.operation_id != record.operation_id
        || metadata.member_set_digest != record.member_set_digest
        || metadata.registry_sequence != record.registry_sequence
        || usize::try_from(metadata.member_count).ok() != Some(expected_members.len())
        || metadata.members.len() != expected_members.len()
        || metadata.grant_subject_drain_receipt_set_digest == [0; 32]
        || metadata.source_emission_quiesce_receipt_set_digest == [0; 32]
        || metadata.aggregate_receipt_set_digest == [0; 32]
        || !matches!(operation_kind, "terminate-agents" | "terminate-component")
        || expected_members
            .iter()
            .any(|member| member.expected_class != expected_class)
    {
        return Err(ObservationProviderError::InvalidState(
            "termination prepare receipt-set metadata mismatch".to_owned(),
        ));
    }
    let mut expected = expected_members.to_vec();
    expected.sort_by(|left, right| {
        left.exact_id
            .as_bytes()
            .cmp(right.exact_id.as_bytes())
            .then_with(|| (left.expected_class as u8).cmp(&(right.expected_class as u8)))
            .then_with(|| left.incarnation.cmp(&right.incarnation))
    });
    let mut projected = metadata.members.clone();
    projected.sort_by(|left, right| {
        left.member
            .exact_id
            .as_bytes()
            .cmp(right.member.exact_id.as_bytes())
            .then_with(|| {
                (left.member.expected_class as u8).cmp(&(right.member.expected_class as u8))
            })
            .then_with(|| left.member.incarnation.cmp(&right.member.incarnation))
    });
    if projected
        .iter()
        .map(|member| &member.member)
        .ne(expected.iter())
        || projected.iter().any(|member| {
            member.grant_subject_drain_receipt_digest == [0; 32]
                || member.source_emission_quiesce_receipt_digest == [0; 32]
        })
    {
        return Err(ObservationProviderError::InvalidState(
            "termination prepare per-member receipt projection mismatch".to_owned(),
        ));
    }
    if operation_exists(conn, &record.operation_id)? {
        return Err(ObservationProviderError::IdentityConflict);
    }
    // Termination creates only one active operation.  It must remain available
    // when the identity or permanent-authority tables are full so that callers
    // can drain and collect retained state rather than deadlocking admission.
    let member_delta = u64::try_from(expected_members.len()).map_err(|_| {
        ObservationProviderError::CapacityExceeded(
            "termination member count exceeds canonical range".to_owned(),
        )
    })?;
    enforce_admission_capacity(conn, 0, 0, 1, 1, member_delta, admission_limits)?;
    let encoded_bytes =
        termination_finalize_encoded_len(record.operation_id.len(), 0, false, false, false)?;
    let future_reserved_bytes =
        reserve_termination_finalize_capacity(conn, encoded_bytes, max_combined_bytes)?;
    conn.execute(
        "INSERT INTO observation_identity_operations
            (operation_id,kind,phase,is_active,retain_until_ms,
             termination_emission_receipt_set_digest)
         VALUES (?1,?2,'prepared',1,?3,?4)",
        params![
            record.operation_id,
            operation_kind,
            retain_until_ms as i64,
            metadata
                .source_emission_quiesce_receipt_set_digest
                .as_slice(),
        ],
    )?;
    for member in &projected {
        let claims = &member.member;
        let identity_changed = conn.execute(
            "UPDATE observation_identities
             SET lifecycle_state='terminating',operation_id=?1,retain_until_ms=?2
             WHERE id=?3 AND class=?4 AND incarnation=?5
               AND declaration_digest=?6 AND lifecycle_state='live'
               AND catalog_visible=1 AND operation_id IS NULL",
            params![
                record.operation_id,
                retain_until_ms as i64,
                claims.exact_id,
                class_to_sql(expected_class),
                claims.incarnation as i64,
                claims.declaration_digest.as_bytes().as_slice(),
            ],
        )?;
        if identity_changed != 1 {
            return Err(ObservationProviderError::InvalidState(
                "termination member is no longer exact live".to_owned(),
            ));
        }
        conn.execute(
            "INSERT INTO observation_identity_operation_members
                (operation_id,identity_id,identity_class,identity_incarnation,
                 declaration_digest,termination_subject_receipt_digest,
                 termination_emission_receipt_digest,gc_phase,gc_generation,
                 gc_challenge_consumed,is_active)
             VALUES (?1,?2,?3,?4,?5,?6,?7,'idle',0,0,1)",
            params![
                record.operation_id,
                claims.exact_id,
                class_to_sql(expected_class),
                claims.incarnation as i64,
                claims.declaration_digest.as_bytes().as_slice(),
                member.grant_subject_drain_receipt_digest.as_slice(),
                member.source_emission_quiesce_receipt_digest.as_slice(),
            ],
        )?;
        if expected_class == ObservationIdentityClass::Component {
            let component_changed = conn.execute(
                "UPDATE components
                 SET lifecycle_state='terminating',catalog_visible=0,
                     operation_id=?1,retain_until_ms=?2
                 WHERE id=?3 AND identity_incarnation=?4
                   AND declaration_digest=?5 AND lifecycle_state='live'
                   AND catalog_visible=1 AND operation_id IS NULL",
                params![
                    record.operation_id,
                    retain_until_ms as i64,
                    claims.exact_id,
                    claims.incarnation as i64,
                    claims.declaration_digest.as_bytes().as_slice(),
                ],
            )?;
            if component_changed != 1 {
                return Err(ObservationProviderError::InvalidState(
                    "termination component projection is no longer exact live".to_owned(),
                ));
            }
        }
    }
    conn.execute(
        "INSERT INTO observation_termination_finalizations
            (operation_id,operation_kind,registry_instance_id,operation_boot_id,
             prepare_ack_digest,prepare_ack_nonce,prepare_sequence,
             member_set_digest,phase,encoded_bytes,future_reserved_bytes)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,'prepared',?9,?10)",
        params![
            record.operation_id,
            operation_kind,
            registry_instance.as_slice(),
            operation_boot.as_slice(),
            prepare_ack_digest.as_slice(),
            prepare_ack_nonce.as_slice(),
            record.registry_sequence as i64,
            record.member_set_digest.as_slice(),
            encoded_bytes,
            future_reserved_bytes,
        ],
    )?;
    Ok(())
}

fn finalize_termination_operation(
    conn: &Connection,
    record: &TerminationOperationRecord,
    metadata: &VerifiedTerminationFinalizeJournalMetadata,
    registry_instance: [u8; 16],
    operation_boot: [u8; 16],
    operation_kind: &str,
    expected_class: ObservationIdentityClass,
) -> Result<(), ObservationProviderError> {
    let claims = load_operation_member_claims(conn, &record.operation_id)?;
    if claims.is_empty()
        || claims
            .iter()
            .any(|claims| claims.expected_class != expected_class)
        || termination_member_set_digest(&claims)? != record.member_set_digest
        || !matches!(operation_kind, "terminate-agents" | "terminate-component")
    {
        return Err(ObservationProviderError::InvalidState(
            "termination finalization member set mismatch".to_owned(),
        ));
    }
    let next_sequence = next_registry_sequence(conn)?;
    if next_sequence <= record.registry_sequence {
        return Err(ObservationProviderError::InvalidState(
            "termination finalization sequence is stale".to_owned(),
        ));
    }
    let (old_encoded, old_future): (i64, i64) = conn
        .query_row(
            "SELECT encoded_bytes,future_reserved_bytes
             FROM observation_termination_finalizations
             WHERE operation_id=?1 AND operation_kind=?2
               AND registry_instance_id=?3 AND operation_boot_id=?4
               AND prepare_ack_digest=?5 AND prepare_ack_nonce=?6
               AND prepare_sequence=?7 AND member_set_digest=?8
               AND phase='prepared'",
            params![
                record.operation_id,
                operation_kind,
                registry_instance.as_slice(),
                operation_boot.as_slice(),
                metadata.prepare_ack_digest.as_slice(),
                metadata.prepare_ack_nonce.as_slice(),
                record.registry_sequence as i64,
                record.member_set_digest.as_slice(),
            ],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?
        .ok_or_else(|| {
            ObservationProviderError::InvalidState(
                "termination prepared finalization row metadata mismatch".to_owned(),
            )
        })?;
    let expected_prepared =
        termination_finalize_encoded_len(record.operation_id.len(), 0, false, false, false)?;
    if old_encoded != expected_prepared
        || old_future != TERMINATION_FINALIZE_TOTAL_BYTES - expected_prepared
    {
        return Err(ObservationProviderError::RecoveryRequired(
            "termination prepared finalization accounting mismatch".to_owned(),
        ));
    }
    let now_ms = crate::types::now_unix_ms().max(0);
    for claims in &claims {
        let changed = conn.execute(
            "UPDATE observation_identities
             SET lifecycle_state='tombstoned',tombstoned_at_ms=?1,catalog_visible=1
             WHERE id=?2 AND class=?3 AND incarnation=?4
               AND declaration_digest=?5 AND lifecycle_state='terminating'
               AND operation_id=?6 AND retain_until_ms IS NOT NULL",
            params![
                now_ms,
                claims.exact_id,
                class_to_sql(expected_class),
                claims.incarnation as i64,
                claims.declaration_digest.as_bytes().as_slice(),
                record.operation_id,
            ],
        )?;
        if changed != 1 {
            return Err(ObservationProviderError::InvalidState(
                "termination finalization member is not exactly terminating".to_owned(),
            ));
        }
        let member_changed = conn.execute(
            "UPDATE observation_identity_operation_members SET is_active=0
             WHERE operation_id=?1 AND identity_id=?2 AND identity_class=?3
               AND identity_incarnation=?4 AND declaration_digest=?5 AND is_active=1",
            params![
                record.operation_id,
                claims.exact_id,
                class_to_sql(expected_class),
                claims.incarnation as i64,
                claims.declaration_digest.as_bytes().as_slice(),
            ],
        )?;
        if member_changed != 1 {
            return Err(ObservationProviderError::InvalidState(
                "termination member journal is incomplete".to_owned(),
            ));
        }
        if expected_class == ObservationIdentityClass::Component {
            let component_changed = conn.execute(
                "UPDATE components
                 SET lifecycle_state='tombstoned',catalog_visible=0,
                     tombstoned_at_ms=?1
                 WHERE id=?2 AND identity_incarnation=?3
                   AND declaration_digest=?4 AND lifecycle_state='terminating'
                   AND operation_id=?5 AND retain_until_ms IS NOT NULL",
                params![
                    now_ms,
                    claims.exact_id,
                    claims.incarnation as i64,
                    claims.declaration_digest.as_bytes().as_slice(),
                    record.operation_id,
                ],
            )?;
            if component_changed != 1 {
                return Err(ObservationProviderError::InvalidState(
                    "termination component finalization projection is incomplete".to_owned(),
                ));
            }
        }
    }
    let operation_changed = conn.execute(
        "UPDATE observation_identity_operations SET phase='committed',is_active=0
         WHERE operation_id=?1 AND kind=?2
           AND phase='prepared' AND is_active=1",
        params![record.operation_id, operation_kind],
    )?;
    if operation_changed != 1 {
        return Err(ObservationProviderError::InvalidState(
            "termination operation is not active prepared".to_owned(),
        ));
    }
    let encoded_bytes =
        termination_finalize_encoded_len(record.operation_id.len(), 6, true, true, false)?;
    let finalization_changed = conn.execute(
        "UPDATE observation_termination_finalizations
         SET phase='finalized',cleanup_receipt_digest=?1,
             cleanup_high_water_digest=?2,cleanup_receipt_set_digest=?3,
             cleanup_nonce=?4,finalize_recovery_nonce=?5,
             finalize_sequence=?6,finalize_ack_digest=?7,terminal_at_ms=?8,
             encoded_bytes=?9,future_reserved_bytes=?10
         WHERE operation_id=?11 AND operation_kind=?12
           AND prepare_ack_digest=?13 AND prepare_ack_nonce=?14
           AND prepare_sequence=?15 AND member_set_digest=?16 AND phase='prepared'",
        params![
            metadata.cleanup_receipt_digest.as_slice(),
            metadata.cleanup_high_water_digest.as_slice(),
            metadata.cleanup_receipt_set_digest.as_slice(),
            metadata.cleanup_nonce.as_slice(),
            metadata.finalize_recovery_nonce.as_slice(),
            next_sequence as i64,
            metadata.finalize_ack_digest.as_slice(),
            now_ms,
            encoded_bytes,
            AUDIT_CHECKPOINT_BYTES,
            record.operation_id,
            operation_kind,
            metadata.prepare_ack_digest.as_slice(),
            metadata.prepare_ack_nonce.as_slice(),
            record.registry_sequence as i64,
            record.member_set_digest.as_slice(),
        ],
    )?;
    if finalization_changed != 1 {
        return Err(ObservationProviderError::InvalidState(
            "termination finalization journal transition is stale".to_owned(),
        ));
    }
    adjust_termination_finalize_capacity(
        conn,
        old_encoded,
        old_future,
        encoded_bytes,
        AUDIT_CHECKPOINT_BYTES,
    )?;
    Ok(())
}

fn prepare_tombstone_gc_operation(
    conn: &Connection,
    metadata: &RetainedTombstoneGcChallengeMetadata,
    previous_phase: &str,
    previous_generation: u64,
    expected_member_count: usize,
    operation_boot: [u8; 16],
) -> Result<(), ObservationProviderError> {
    if metadata.operation_boot != operation_boot
        || metadata.registry_instance == [0; 16]
        || metadata.member_set_digest == [0; 32]
        || metadata.tombstone_state_root == [0; 32]
        || metadata.challenge_nonce == [0; 32]
        || metadata.gc_generation == 0
        || metadata.gc_generation > i64::MAX as u64
        || next_registry_sequence(conn)? != metadata.gc_registry_sequence
        || !matches!(previous_phase, "idle" | "prepared")
        || previous_generation.checked_add(1) != Some(metadata.gc_generation)
    {
        return Err(ObservationProviderError::InvalidState(
            "retained-tombstone GC prepare metadata is stale or malformed".to_owned(),
        ));
    }
    let exact_operation: i64 = conn.query_row(
        "SELECT COUNT(*)
         FROM observation_identity_operations o
         JOIN observation_termination_finalizations f
           ON f.operation_id=o.operation_id
         WHERE o.operation_id=?1
           AND o.kind IN ('terminate-agents','terminate-component')
           AND o.phase='committed' AND o.is_active=0
           AND f.phase='finalized' AND f.member_set_digest=?2",
        params![metadata.operation_id, metadata.member_set_digest.as_slice()],
        |row| row.get(0),
    )?;
    if exact_operation != 1 {
        return Err(ObservationProviderError::InvalidState(
            "retained-tombstone GC operation is not exactly finalized".to_owned(),
        ));
    }
    let changed = conn.execute(
        "UPDATE observation_identity_operation_members
         SET gc_phase='prepared',gc_generation=?1,gc_registry_sequence=?2,
             gc_challenge_nonce=?3,gc_tombstone_state_root=?4,
             gc_operation_boot=?5,gc_challenge_consumed=0,
             gc_subject_receipt_digest=NULL,gc_reference_scan_digest=NULL
         WHERE operation_id=?6 AND gc_phase=?7 AND gc_generation=?8
           AND is_active=0",
        params![
            metadata.gc_generation as i64,
            metadata.gc_registry_sequence as i64,
            metadata.challenge_nonce.as_slice(),
            metadata.tombstone_state_root.as_slice(),
            operation_boot.as_slice(),
            metadata.operation_id,
            previous_phase,
            previous_generation as i64,
        ],
    )?;
    if changed != expected_member_count {
        return Err(ObservationProviderError::InvalidState(
            "retained-tombstone GC prepare did not transition the exact member set".to_owned(),
        ));
    }
    Ok(())
}

fn collect_tombstone_gc_operation(
    conn: &Connection,
    verified: &VerifiedRetainedTombstoneGcSet,
    registry_instance: [u8; 16],
    operation_boot: [u8; 16],
) -> Result<(), ObservationProviderError> {
    let metadata = verified.metadata();
    let current = read_ledger(conn)?.ok_or_else(|| {
        ObservationProviderError::RecoveryRequired("missing identity ledger".to_owned())
    })?;
    if metadata.registry_instance != registry_instance
        || metadata.operation_boot != operation_boot
        || metadata.member_set_digest == [0; 32]
        || metadata.tombstone_state_root == [0; 32]
        || metadata.challenge_nonce == [0; 32]
        || metadata.purpose2_digest == [0; 32]
        || metadata.aggregate_digest == [0; 32]
        || metadata.gc_generation == 0
        || metadata.gc_generation > i64::MAX as u64
        || metadata.registry.store_instance_id != registry_instance
        || metadata.registry.high_water != current.sequence
        || metadata.registry.state_root != current.state_root
    {
        return Err(ObservationProviderError::InvalidState(
            "verified retained-tombstone GC projection is malformed".to_owned(),
        ));
    }
    for owner in [
        &metadata.purpose2,
        &metadata.m009,
        &metadata.m019,
        &metadata.c123,
        &metadata.role_allocation,
        &metadata.registry,
    ] {
        if owner.store_instance_id == [0; 16]
            || owner.high_water == 0
            || owner.high_water > i64::MAX as u64
            || owner.state_root == [0; 32]
        {
            return Err(ObservationProviderError::InvalidState(
                "verified retained-tombstone owner high-water is invalid".to_owned(),
            ));
        }
    }
    let claims = load_operation_member_claims(conn, &metadata.operation_id)?;
    if claims.is_empty() || termination_member_set_digest(&claims)? != metadata.member_set_digest {
        return Err(ObservationProviderError::InvalidState(
            "retained-tombstone GC member set mismatch".to_owned(),
        ));
    }
    let now_ms = crate::types::now_unix_ms().max(0);
    for claims in &claims {
        let eligible: i64 = conn.query_row(
            "SELECT COUNT(*) FROM observation_identities
             WHERE id=?1 AND class=?2 AND incarnation=?3 AND declaration_digest=?4
               AND lifecycle_state='tombstoned' AND catalog_visible=1
               AND operation_id=?5 AND tombstoned_at_ms IS NOT NULL
               AND retain_until_ms IS NOT NULL AND retain_until_ms<=?6",
            params![
                claims.exact_id,
                class_to_sql(claims.expected_class),
                claims.incarnation as i64,
                claims.declaration_digest.as_bytes().as_slice(),
                metadata.operation_id,
                now_ms,
            ],
            |row| row.get(0),
        )?;
        if eligible != 1 {
            return Err(ObservationProviderError::InvalidState(
                "retained identity is no longer GC eligible".to_owned(),
            ));
        }
    }
    let changed = conn.execute(
        "UPDATE observation_identity_operation_members
         SET gc_phase='collected',gc_challenge_consumed=1,
             gc_subject_receipt_digest=?1,gc_reference_scan_digest=?2
         WHERE operation_id=?3 AND gc_phase='prepared'
           AND gc_generation=?4 AND gc_registry_sequence=?5
           AND gc_challenge_nonce=?6 AND gc_tombstone_state_root=?7
           AND gc_operation_boot=?8 AND gc_challenge_consumed=0
           AND gc_subject_receipt_digest IS NULL
           AND gc_reference_scan_digest IS NULL AND is_active=0",
        params![
            metadata.purpose2_digest.as_slice(),
            metadata.aggregate_digest.as_slice(),
            metadata.operation_id,
            metadata.gc_generation as i64,
            metadata.gc_registry_sequence as i64,
            metadata.challenge_nonce.as_slice(),
            metadata.tombstone_state_root.as_slice(),
            operation_boot.as_slice(),
        ],
    )?;
    if changed != claims.len() {
        return Err(ObservationProviderError::InvalidState(
            "retained-tombstone GC challenge is stale or already consumed".to_owned(),
        ));
    }
    for claims in &claims {
        if claims.expected_class == ObservationIdentityClass::Component {
            let deleted = conn.execute(
                "DELETE FROM components
                 WHERE id=?1 AND identity_incarnation=?2 AND declaration_digest=?3
                   AND lifecycle_state='tombstoned' AND operation_id=?4",
                params![
                    claims.exact_id,
                    claims.incarnation as i64,
                    claims.declaration_digest.as_bytes().as_slice(),
                    metadata.operation_id,
                ],
            )?;
            if deleted != 1 {
                return Err(ObservationProviderError::InvalidState(
                    "retained component projection is missing during GC".to_owned(),
                ));
            }
        }
        let deleted = conn.execute(
            "DELETE FROM observation_identities
             WHERE id=?1 AND class=?2 AND incarnation=?3 AND declaration_digest=?4
               AND lifecycle_state='tombstoned' AND operation_id=?5",
            params![
                claims.exact_id,
                class_to_sql(claims.expected_class),
                claims.incarnation as i64,
                claims.declaration_digest.as_bytes().as_slice(),
                metadata.operation_id,
            ],
        )?;
        if deleted != 1 {
            return Err(ObservationProviderError::InvalidState(
                "retained identity disappeared during GC".to_owned(),
            ));
        }
    }
    Ok(())
}

fn audit_checkpoint_commitment(
    registry_instance: [u8; 16],
    checkpoint_sequence: u64,
    covered_registry_sequence: u64,
    verified_at_ms: u64,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(AUDIT_CHECKPOINT_WITNESS_DOMAIN);
    hasher.update(registry_instance);
    hasher.update(checkpoint_sequence.to_be_bytes());
    hasher.update(covered_registry_sequence.to_be_bytes());
    hasher.update(verified_at_ms.to_be_bytes());
    hasher.finalize().into()
}

#[cfg(any(test, feature = "test-support"))]
fn authenticated_audit_checkpoint_witness(
    registry_instance: [u8; 16],
    checkpoint_sequence: u64,
    covered_registry_sequence: u64,
    verified_at_ms: u64,
) -> AuthenticatedAuditCheckpointWitness {
    AuthenticatedAuditCheckpointWitness {
        registry_instance,
        checkpoint_sequence,
        covered_registry_sequence,
        verified_at_ms,
        commitment: audit_checkpoint_commitment(
            registry_instance,
            checkpoint_sequence,
            covered_registry_sequence,
            verified_at_ms,
        ),
    }
}

fn verify_audit_checkpoint_witness(
    witness: &AuthenticatedAuditCheckpointWitness,
    expected_registry_instance: [u8; 16],
) -> Result<(), ObservationProviderError> {
    if witness.registry_instance != expected_registry_instance
        || witness.registry_instance == [0; 16]
        || witness.checkpoint_sequence == 0
        || witness.checkpoint_sequence > i64::MAX as u64
        || witness.covered_registry_sequence == 0
        || witness.covered_registry_sequence > i64::MAX as u64
        || witness.verified_at_ms == 0
        || witness.verified_at_ms > i64::MAX as u64
        || witness.commitment
            != audit_checkpoint_commitment(
                witness.registry_instance,
                witness.checkpoint_sequence,
                witness.covered_registry_sequence,
                witness.verified_at_ms,
            )
    {
        return Err(ObservationProviderError::InvalidInput(
            "opaque audit checkpoint witness is malformed or crossed".to_owned(),
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TerminalJournalKind {
    Previsible,
    Finalization,
}

#[derive(Debug)]
struct TerminalCompactionCandidate {
    operation_id: String,
    operation_kind: String,
    terminal_sequence: u64,
    terminal_at_ms: u64,
    audit_checkpoint_sequence: Option<u64>,
    encoded_bytes: u64,
    future_reserved_bytes: u64,
    member_count: u64,
    journal_kind: TerminalJournalKind,
    eligible_shape: bool,
}

fn apply_audit_checkpoint_or_compaction(
    conn: &Connection,
    witness: &AuthenticatedAuditCheckpointWitness,
    capacity_limits: AuditCheckpointCapacityLimits,
) -> Result<AuditCompactionOutcome, ObservationProviderError> {
    verify_audit_checkpoint_witness(witness, witness.registry_instance)?;
    let ledger = read_ledger(conn)?.ok_or_else(|| {
        ObservationProviderError::RecoveryRequired("missing identity ledger".to_owned())
    })?;
    if ledger.registry_instance != witness.registry_instance
        || witness.covered_registry_sequence > ledger.sequence
    {
        return Err(ObservationProviderError::InvalidState(
            "audit checkpoint is stale, crossed, or ahead of the registry".to_owned(),
        ));
    }
    let checkpoint = sqlite_i64(witness.checkpoint_sequence, "audit checkpoint sequence")?;
    let covered = sqlite_i64(
        witness.covered_registry_sequence,
        "audit checkpoint registry high-water",
    )?;
    let previsible_checkpointed = conn.execute(
        "UPDATE observation_previsible_activations
         SET audit_checkpoint_sequence=?1,
             encoded_bytes=encoded_bytes+?3,future_reserved_bytes=0
         WHERE audit_checkpoint_sequence IS NULL
           AND phase IN ('published','aborted')
           AND terminal_at_ms IS NOT NULL AND updated_sequence<=?2
           AND future_reserved_bytes=?3",
        params![checkpoint, covered, AUDIT_CHECKPOINT_BYTES],
    )?;
    let finalized_checkpointed = conn.execute(
        "UPDATE observation_termination_finalizations
         SET audit_checkpoint_sequence=?1,
             encoded_bytes=encoded_bytes+?3,future_reserved_bytes=0
         WHERE audit_checkpoint_sequence IS NULL AND phase='finalized'
           AND terminal_at_ms IS NOT NULL AND finalize_sequence<=?2
           AND future_reserved_bytes=?3",
        params![checkpoint, covered, AUDIT_CHECKPOINT_BYTES],
    )?;
    let checkpointed = previsible_checkpointed
        .checked_add(finalized_checkpointed)
        .ok_or_else(|| {
            ObservationProviderError::CapacityExceeded(
                "audit checkpoint journal count overflow".to_owned(),
            )
        })?;
    move_checkpoint_capacity(
        conn,
        "observation_previsible_capacity",
        u64::try_from(previsible_checkpointed).map_err(|_| {
            ObservationProviderError::CapacityExceeded("previsible checkpoint count".to_owned())
        })?,
        capacity_limits.previsible_combined_bytes,
    )?;
    move_checkpoint_capacity(
        conn,
        "observation_termination_finalize_capacity",
        u64::try_from(finalized_checkpointed).map_err(|_| {
            ObservationProviderError::CapacityExceeded("finalization checkpoint count".to_owned())
        })?,
        capacity_limits.finalization_combined_bytes,
    )?;
    // A row checkpointed in this write set is deliberately retained. A later
    // tag-7 transaction must observe that authenticated checkpoint in its
    // preimage before deletion, so NULL -> absent can never hide the proof.
    if checkpointed != 0 {
        return Ok(AuditCompactionOutcome {
            checkpointed_journals: u64::try_from(checkpointed).map_err(|_| {
                ObservationProviderError::CapacityExceeded(
                    "audit checkpoint journal count".to_owned(),
                )
            })?,
            ..AuditCompactionOutcome::default()
        });
    }

    let current_day_start = witness
        .verified_at_ms
        .checked_div(COMPLETE_UTC_DAY_MS)
        .and_then(|days| days.checked_mul(COMPLETE_UTC_DAY_MS))
        .ok_or_else(|| {
            ObservationProviderError::InvalidInput(
                "audit checkpoint UTC-day boundary overflow".to_owned(),
            )
        })?;
    let retention_cutoff = current_day_start
        .checked_sub(OBSERVATION_RETENTION_HORIZON_MS)
        .ok_or_else(|| {
            ObservationProviderError::InvalidState(
                "audit checkpoint predates the complete-day retention horizon".to_owned(),
            )
        })?;
    let candidates = load_terminal_compaction_candidates(conn)?;
    let mut prefix = Vec::new();
    for candidate in candidates {
        let eligible = candidate.eligible_shape
            && candidate.terminal_at_ms <= retention_cutoff
            && candidate.terminal_sequence <= witness.covered_registry_sequence
            && candidate
                .audit_checkpoint_sequence
                .is_some_and(|sequence| sequence > 0)
            && candidate.future_reserved_bytes == 0;
        if !eligible {
            break;
        }
        prefix.push(candidate);
    }
    if prefix.is_empty() {
        return Err(ObservationProviderError::InvalidState(
            "audit checkpoint covers no eligible terminal operation prefix".to_owned(),
        ));
    }

    let mut outcome = AuditCompactionOutcome::default();
    let mut previsible_rows = 0_u64;
    let mut previsible_actual = 0_u64;
    let mut previsible_future = 0_u64;
    let mut finalization_rows = 0_u64;
    let mut finalization_actual = 0_u64;
    let mut finalization_future = 0_u64;
    for candidate in &prefix {
        let journal_deleted = match candidate.journal_kind {
            TerminalJournalKind::Previsible => conn.execute(
                "DELETE FROM observation_previsible_activations
                 WHERE operation_id=?1 AND phase IN ('published','aborted')
                   AND audit_checkpoint_sequence IS NOT NULL",
                params![candidate.operation_id],
            )?,
            TerminalJournalKind::Finalization => conn.execute(
                "DELETE FROM observation_termination_finalizations
                 WHERE operation_id=?1 AND phase='finalized'
                   AND audit_checkpoint_sequence IS NOT NULL",
                params![candidate.operation_id],
            )?,
        };
        if journal_deleted != 1 {
            return Err(ObservationProviderError::InvalidState(
                "tag-7 did not delete one exact terminal journal".to_owned(),
            ));
        }
        match candidate.journal_kind {
            TerminalJournalKind::Previsible => {
                previsible_rows = previsible_rows.checked_add(1).ok_or_else(|| {
                    ObservationProviderError::CapacityExceeded(
                        "previsible compaction row count".to_owned(),
                    )
                })?;
                previsible_actual = previsible_actual
                    .checked_add(candidate.encoded_bytes)
                    .ok_or_else(|| {
                        ObservationProviderError::CapacityExceeded(
                            "previsible compaction actual bytes".to_owned(),
                        )
                    })?;
                previsible_future = previsible_future
                    .checked_add(candidate.future_reserved_bytes)
                    .ok_or_else(|| {
                        ObservationProviderError::CapacityExceeded(
                            "previsible compaction future bytes".to_owned(),
                        )
                    })?;
            }
            TerminalJournalKind::Finalization => {
                finalization_rows = finalization_rows.checked_add(1).ok_or_else(|| {
                    ObservationProviderError::CapacityExceeded(
                        "finalization compaction row count".to_owned(),
                    )
                })?;
                finalization_actual = finalization_actual
                    .checked_add(candidate.encoded_bytes)
                    .ok_or_else(|| {
                        ObservationProviderError::CapacityExceeded(
                            "finalization compaction actual bytes".to_owned(),
                        )
                    })?;
                finalization_future = finalization_future
                    .checked_add(candidate.future_reserved_bytes)
                    .ok_or_else(|| {
                        ObservationProviderError::CapacityExceeded(
                            "finalization compaction future bytes".to_owned(),
                        )
                    })?;
            }
        }
        let members_deleted = conn.execute(
            "DELETE FROM observation_identity_operation_members
             WHERE operation_id=?1 AND is_active=0",
            params![candidate.operation_id],
        )?;
        if u64::try_from(members_deleted).ok() != Some(candidate.member_count) {
            return Err(ObservationProviderError::InvalidState(
                "tag-7 did not delete the complete inactive member set".to_owned(),
            ));
        }
        let operation_deleted = conn.execute(
            "DELETE FROM observation_identity_operations
             WHERE operation_id=?1 AND kind=?2
               AND phase='committed' AND is_active=0",
            params![candidate.operation_id, candidate.operation_kind],
        )?;
        if operation_deleted != 1 {
            return Err(ObservationProviderError::InvalidState(
                "tag-7 did not delete one exact committed operation".to_owned(),
            ));
        }
        outcome.compacted_operations =
            outcome.compacted_operations.checked_add(1).ok_or_else(|| {
                ObservationProviderError::CapacityExceeded("compacted operation count".to_owned())
            })?;
        outcome.compacted_members = outcome
            .compacted_members
            .checked_add(candidate.member_count)
            .ok_or_else(|| {
                ObservationProviderError::CapacityExceeded("compacted member count".to_owned())
            })?;
        outcome.compacted_journals =
            outcome.compacted_journals.checked_add(1).ok_or_else(|| {
                ObservationProviderError::CapacityExceeded("compacted journal count".to_owned())
            })?;
    }
    decrement_compaction_capacity(
        conn,
        "observation_previsible_capacity",
        previsible_rows,
        previsible_actual,
        previsible_future,
    )?;
    decrement_compaction_capacity(
        conn,
        "observation_termination_finalize_capacity",
        finalization_rows,
        finalization_actual,
        finalization_future,
    )?;
    Ok(outcome)
}

fn load_terminal_compaction_candidates(
    conn: &Connection,
) -> Result<Vec<TerminalCompactionCandidate>, ObservationProviderError> {
    let mut operation_stmt = conn.prepare(
        "SELECT operation_id,kind FROM observation_identity_operations
         WHERE phase='committed' AND is_active=0",
    )?;
    let operations = operation_stmt
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    drop(operation_stmt);
    let mut candidates = Vec::with_capacity(operations.len());
    for (operation_id, operation_kind) in operations {
        let (journal_kind, terminal_sequence, terminal_at_ms, audit, encoded, future) = if matches!(
            operation_kind.as_str(),
            "register-agent" | "register-component"
        ) {
            let mut stmt = conn.prepare(
                "SELECT updated_sequence,terminal_at_ms,audit_checkpoint_sequence,
                            encoded_bytes,future_reserved_bytes
                     FROM observation_previsible_activations
                     WHERE operation_id=?1 AND phase IN ('published','aborted')",
            )?;
            let rows = stmt
                .query_map(params![operation_id], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, Option<i64>>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                    ))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            if rows.len() != 1 {
                return Err(ObservationProviderError::RecoveryRequired(
                    "committed registration lacks one terminal activation journal".to_owned(),
                ));
            }
            let row = rows[0];
            (
                TerminalJournalKind::Previsible,
                row.0,
                row.1,
                row.2,
                row.3,
                row.4,
            )
        } else if matches!(
            operation_kind.as_str(),
            "terminate-agents" | "terminate-component"
        ) {
            let mut stmt = conn.prepare(
                "SELECT finalize_sequence,terminal_at_ms,audit_checkpoint_sequence,
                            encoded_bytes,future_reserved_bytes
                     FROM observation_termination_finalizations
                     WHERE operation_id=?1 AND phase='finalized'",
            )?;
            let rows = stmt
                .query_map(params![operation_id], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, Option<i64>>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                    ))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            if rows.len() != 1 {
                return Err(ObservationProviderError::RecoveryRequired(
                    "committed termination lacks one finalized journal".to_owned(),
                ));
            }
            let row = rows[0];
            (
                TerminalJournalKind::Finalization,
                row.0,
                row.1,
                row.2,
                row.3,
                row.4,
            )
        } else {
            return Err(ObservationProviderError::RecoveryRequired(
                "committed operation has an unknown kind".to_owned(),
            ));
        };
        let terminal_sequence = sqlite_u64(terminal_sequence, "terminal operation sequence")?;
        let terminal_at_ms = sqlite_u64(terminal_at_ms, "terminal operation time")?;
        let audit_checkpoint_sequence = audit
            .map(|value| sqlite_u64(value, "terminal audit checkpoint"))
            .transpose()?;
        let encoded_bytes = sqlite_u64(encoded, "terminal journal encoded bytes")?;
        let future_reserved_bytes = sqlite_u64(future, "terminal journal future bytes")?;
        let (member_count, exact_shape): (i64, i64) = match operation_kind.as_str() {
            "register-agent" | "register-component" => conn.query_row(
                "SELECT COUNT(*),COALESCE(SUM(
                    CASE WHEN is_active=0 AND gc_phase='idle' THEN 1 ELSE 0 END
                 ),0)
                 FROM observation_identity_operation_members WHERE operation_id=?1",
                params![operation_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?,
            "terminate-agents" | "terminate-component" => conn.query_row(
                "SELECT COUNT(*),COALESCE(SUM(
                    CASE WHEN is_active=0 AND gc_phase='collected' THEN 1 ELSE 0 END
                 ),0)
                 FROM observation_identity_operation_members WHERE operation_id=?1",
                params![operation_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?,
            _ => unreachable!(),
        };
        let member_count = sqlite_u64(member_count, "terminal operation member count")?;
        let exact_shape = sqlite_u64(exact_shape, "terminal exact member count")?;
        let reference_count: i64 = conn.query_row(
            "SELECT
                (SELECT COUNT(*) FROM observation_identities WHERE operation_id=?1)
              + (SELECT COUNT(*) FROM components WHERE operation_id=?1)",
            params![operation_id],
            |row| row.get(0),
        )?;
        let exact_identity_count: i64 = if matches!(
            operation_kind.as_str(),
            "terminate-agents" | "terminate-component"
        ) {
            conn.query_row(
                "SELECT COUNT(*)
                 FROM observation_identity_operation_members m
                 JOIN observation_identities i
                   ON i.id=m.identity_id AND i.class=m.identity_class
                  AND i.incarnation=m.identity_incarnation
                  AND i.declaration_digest=m.declaration_digest
                 WHERE m.operation_id=?1",
                params![operation_id],
                |row| row.get(0),
            )?
        } else {
            0
        };
        let cardinality_ok = match operation_kind.as_str() {
            "register-agent" | "register-component" | "terminate-component" => member_count == 1,
            "terminate-agents" => member_count > 0,
            _ => false,
        };
        candidates.push(TerminalCompactionCandidate {
            operation_id,
            operation_kind,
            terminal_sequence,
            terminal_at_ms,
            audit_checkpoint_sequence,
            encoded_bytes,
            future_reserved_bytes,
            member_count,
            journal_kind,
            eligible_shape: cardinality_ok
                && exact_shape == member_count
                && reference_count == 0
                && exact_identity_count == 0,
        });
    }
    candidates.sort_by_key(|candidate| candidate.terminal_sequence);
    if candidates
        .windows(2)
        .any(|pair| pair[0].terminal_sequence == pair[1].terminal_sequence)
    {
        return Err(ObservationProviderError::RecoveryRequired(
            "terminal operation commit sequences are not unique".to_owned(),
        ));
    }
    Ok(candidates)
}

fn decrement_compaction_capacity(
    conn: &Connection,
    table: &str,
    rows: u64,
    actual: u64,
    future: u64,
) -> Result<(), ObservationProviderError> {
    if rows == 0 {
        if actual != 0 || future != 0 {
            return Err(ObservationProviderError::RecoveryRequired(
                "zero-row compaction reports nonzero bytes".to_owned(),
            ));
        }
        return Ok(());
    }
    let rows = sqlite_i64(rows, "compaction row decrement")?;
    let actual = sqlite_i64(actual, "compaction actual-byte decrement")?;
    let future = sqlite_i64(future, "compaction future-byte decrement")?;
    let statement = match table {
        "observation_previsible_capacity" => {
            "UPDATE observation_previsible_capacity
             SET row_count=row_count-?1,actual_encoded_bytes=actual_encoded_bytes-?2,
                 future_reserved_bytes=future_reserved_bytes-?3
             WHERE singleton=1 AND row_count>=?1
               AND actual_encoded_bytes>=?2 AND future_reserved_bytes>=?3"
        }
        "observation_termination_finalize_capacity" => {
            "UPDATE observation_termination_finalize_capacity
             SET row_count=row_count-?1,actual_encoded_bytes=actual_encoded_bytes-?2,
                 future_reserved_bytes=future_reserved_bytes-?3
             WHERE singleton=1 AND row_count>=?1
               AND actual_encoded_bytes>=?2 AND future_reserved_bytes>=?3"
        }
        _ => {
            return Err(ObservationProviderError::InvalidInput(
                "unknown compaction capacity singleton".to_owned(),
            ));
        }
    };
    if conn.execute(statement, params![rows, actual, future])? != 1 {
        return Err(ObservationProviderError::RecoveryRequired(
            "compaction capacity decrement is inconsistent".to_owned(),
        ));
    }
    Ok(())
}

fn move_checkpoint_capacity(
    conn: &Connection,
    table: &str,
    rows: u64,
    combined_limit: i64,
) -> Result<(), ObservationProviderError> {
    if rows == 0 {
        return Ok(());
    }
    let bytes = rows
        .checked_mul(AUDIT_CHECKPOINT_BYTES as u64)
        .ok_or_else(|| {
            ObservationProviderError::CapacityExceeded(
                "audit checkpoint accounting bytes".to_owned(),
            )
        })?;
    let bytes = sqlite_i64(bytes, "audit checkpoint accounting bytes")?;
    let production_limit = match table {
        "observation_previsible_capacity" => MAX_PREVISIBLE_COMBINED_BYTES,
        "observation_termination_finalize_capacity" => MAX_TERMINATION_FINALIZE_COMBINED_BYTES,
        _ => {
            return Err(ObservationProviderError::InvalidInput(
                "unknown checkpoint capacity singleton".to_owned(),
            ));
        }
    };
    if combined_limit < 0 || combined_limit > production_limit {
        return Err(ObservationProviderError::InvalidState(
            "audit checkpoint effective capacity is outside production bounds".to_owned(),
        ));
    }
    let statement = match table {
        "observation_previsible_capacity" => {
            "UPDATE observation_previsible_capacity
             SET actual_encoded_bytes=actual_encoded_bytes+?1,
                 future_reserved_bytes=future_reserved_bytes-?1
             WHERE singleton=1 AND future_reserved_bytes>=?1
               AND actual_encoded_bytes+?1<=?2
               AND actual_encoded_bytes+future_reserved_bytes<=?3"
        }
        "observation_termination_finalize_capacity" => {
            "UPDATE observation_termination_finalize_capacity
             SET actual_encoded_bytes=actual_encoded_bytes+?1,
                 future_reserved_bytes=future_reserved_bytes-?1
             WHERE singleton=1 AND future_reserved_bytes>=?1
               AND actual_encoded_bytes+?1<=?2
               AND actual_encoded_bytes+future_reserved_bytes<=?3"
        }
        _ => unreachable!(),
    };
    if conn.execute(statement, params![bytes, production_limit, combined_limit])? != 1 {
        return Err(ObservationProviderError::RecoveryRequired(
            "audit checkpoint future-to-actual capacity move is inconsistent".to_owned(),
        ));
    }
    Ok(())
}

impl SensitiveParamCatalog for RegistrySensitiveParamProvider {
    fn lookup(
        &self,
        canonical_component_id: &str,
    ) -> Result<SensitiveParamSnapshot, SensitiveParamCatalogError> {
        if !self.is_ready() {
            return Err(SensitiveParamCatalogError::RecoveryRequired);
        }
        let view = self
            .view
            .read()
            .map_err(|_| SensitiveParamCatalogError::RecoveryRequired)?;
        view.get(canonical_component_id)
            .filter(|row| row.lifecycle.permits_replay())
            .map(|row| row.snapshot.clone())
            .ok_or(SensitiveParamCatalogError::UnknownIdentity)
    }

    fn verify(
        &self,
        identity: &TrustedObservationIdentity,
    ) -> Result<SensitiveParamSnapshot, SensitiveParamCatalogError> {
        let claims = identity.claims_for_persistence();
        self.verifier.verify_live_identity(identity, &claims)?;
        let snapshot = self.lookup(&claims.exact_id)?;
        if snapshot.claims() != claims {
            return Err(SensitiveParamCatalogError::StaleIdentity);
        }
        let view = self
            .view
            .read()
            .map_err(|_| SensitiveParamCatalogError::RecoveryRequired)?;
        if !view
            .get(&claims.exact_id)
            .map(|row| row.lifecycle.permits_live_authority())
            .unwrap_or(false)
        {
            return Err(SensitiveParamCatalogError::StaleIdentity);
        }
        Ok(snapshot)
    }

    fn subscribe(&self) -> watch::Receiver<u64> {
        self.revision_tx.subscribe()
    }
}

impl ObservationIdentityAuthority for RegistrySensitiveParamProvider {
    fn mint_live_identity(
        &self,
        source: &AuthenticatedObservationSourceHandle,
    ) -> Result<TrustedObservationIdentity, SensitiveParamCatalogError> {
        if !self.is_ready() {
            return Err(SensitiveParamCatalogError::RecoveryRequired);
        }
        let identity = self.verifier.mint_live_identity(source)?;
        // `verify` authenticates the new token and checks the exact durable
        // tuple/lifecycle before authority crosses the provider boundary.
        self.verify(&identity)?;
        Ok(identity)
    }

    fn rehydrate_persisted_identity(
        &self,
        persisted: &PersistedObservationIdentity,
    ) -> Result<TrustedObservationIdentity, SensitiveParamCatalogError> {
        if !self.is_ready() {
            return Err(SensitiveParamCatalogError::RecoveryRequired);
        }
        self.require_persisted_key_status(persisted.key_id(), false)?;
        let keyring = self
            .persisted_keyring
            .lock()
            .map_err(|_| SensitiveParamCatalogError::RecoveryRequired)?;
        let keyring = keyring
            .as_ref()
            .ok_or(SensitiveParamCatalogError::RecoveryRequired)?;
        let verification = keyring.verification_key_capability(persisted.key_id())?;
        let identity = keyring.rehydrate_persisted_identity(&verification, persisted)?;
        let claims = identity.claims_for_persistence();
        let snapshot = self.lookup(&claims.exact_id)?;
        if snapshot.claims() != claims {
            return Err(SensitiveParamCatalogError::StaleIdentity);
        }
        Ok(identity)
    }

    fn verify_persisted_binding(
        &self,
        identity: &TrustedObservationIdentity,
        persisted: &PersistedObservationIdentity,
        observed: &PersistedObservationBinding,
    ) -> Result<SensitiveParamSnapshot, SensitiveParamCatalogError> {
        if !self.is_ready() {
            return Err(SensitiveParamCatalogError::RecoveryRequired);
        }
        self.require_persisted_key_status(persisted.key_id(), false)?;
        let claims = identity.claims_for_persistence();
        let snapshot = self.lookup(&claims.exact_id)?;
        if snapshot.claims() != claims {
            return Err(SensitiveParamCatalogError::StaleIdentity);
        }
        let keyring = self
            .persisted_keyring
            .lock()
            .map_err(|_| SensitiveParamCatalogError::RecoveryRequired)?;
        let keyring = keyring
            .as_ref()
            .ok_or(SensitiveParamCatalogError::RecoveryRequired)?;
        let verification = keyring.verification_key_capability(persisted.key_id())?;
        keyring.verify_persisted_identity(&verification, identity, persisted, observed, &claims)?;
        Ok(snapshot)
    }

    fn resolve_retained_source_binding(
        &self,
        digest: &SourceBindingDigest,
    ) -> Result<ObservationIdentityClaims, SensitiveParamCatalogError> {
        if !self.is_ready() {
            return Err(SensitiveParamCatalogError::RecoveryRequired);
        }
        let view = self
            .view
            .read()
            .map_err(|_| SensitiveParamCatalogError::RecoveryRequired)?;
        let mut resolved = None;
        for row in view.values().filter(|row| row.lifecycle.permits_replay()) {
            let claims = row.snapshot.claims();
            if self.verifier.source_binding_digest(&claims)? == *digest
                && resolved.replace(claims).is_some()
            {
                return Err(SensitiveParamCatalogError::RecoveryRequired);
            }
        }
        resolved.ok_or(SensitiveParamCatalogError::UnknownIdentity)
    }
}

impl ObservationIdentityPersistenceSealer for RegistrySensitiveParamProvider {
    fn seal_persisted_identity(
        &self,
        live_identity: &TrustedObservationIdentity,
        binding: &PersistedObservationBinding,
    ) -> Result<PersistedObservationIdentity, SensitiveParamCatalogError> {
        self.seal_or_reseal_with_custody(Some(live_identity), None, binding)
            .map_err(|error| error.as_catalog_error())
    }

    fn reseal_persisted_identity(
        &self,
        existing: &PersistedObservationIdentity,
        binding: &PersistedObservationBinding,
    ) -> Result<PersistedObservationIdentity, SensitiveParamCatalogError> {
        self.seal_or_reseal_with_custody(None, Some(existing), binding)
            .map_err(|error| error.as_catalog_error())
    }
}

impl ComponentObservationSourceIssuer for RegistrySensitiveParamProvider {
    fn issue_component_source(
        &self,
        receipt: &CommittedComponentSourceReceipt,
    ) -> Result<PrevisibleObservationActivation, SensitiveParamCatalogError> {
        if !self.is_ready() {
            return Err(SensitiveParamCatalogError::RecoveryRequired);
        }
        let activation = self.verifier.begin_component_activation(receipt)?;
        let record = self.verifier.inspect_component_activation(&activation)?;
        if let Some(prepared) = self
            .find_prepared_previsible_activation(&record)
            .map_err(|error| error.as_catalog_error())?
        {
            return self.verifier.rehydrate_component_activation(&prepared);
        }
        let discriminator = record.activation_nonce;
        let config = self.config.clone();
        self.anchored_mutation_sync(3, &discriminator, move |transaction| {
            persist_previsible_activation(
                transaction,
                &record,
                config.registry_instance,
                config.boot,
            )
        })
        .map_err(|error| error.as_catalog_error())?;
        Ok(activation)
    }

    fn publish_component_source(
        &self,
        activation: PrevisibleObservationActivation,
        ready: PrevisibleActivationReadyProof,
    ) -> ComponentPublicationResult {
        match self.verifier.verify_component_ready(activation, ready) {
            ComponentReadyVerification::Rejected(rejected) => {
                self.verifier.component_rejected_result(rejected)
            }
            ComponentReadyVerification::Verified(verified) => {
                let record = verified.provider_record();
                let metadata = match ready_journal_metadata(verified.proof_metadata()) {
                    Ok(metadata) => metadata,
                    Err(_) => return self.verifier.reject_component_publication(verified),
                };
                let discriminator = record.activation_nonce;
                let ready_record = record.clone();
                let ready_metadata = metadata.clone();
                if let Err(error) =
                    self.anchored_mutation_sync(3, &discriminator, move |transaction| {
                        mark_previsible_ready(transaction, &ready_record, &ready_metadata)
                    })
                {
                    return if error.gates_provider() {
                        self.verifier
                            .component_publication_outcome_unknown(verified)
                    } else {
                        self.verifier.reject_component_publication(verified)
                    };
                }
                let publishing_record = record.clone();
                let publishing_metadata = metadata.clone();
                if self
                    .anchored_mutation_sync(3, &discriminator, move |transaction| {
                        mark_previsible_publishing(
                            transaction,
                            &publishing_record,
                            &publishing_metadata,
                        )
                    })
                    .is_err()
                {
                    return self
                        .verifier
                        .component_publication_outcome_unknown(verified);
                }
                if self
                    .anchored_mutation_sync(3, &discriminator, move |transaction| {
                        complete_previsible_publication(transaction, &record, &metadata)
                    })
                    .is_err()
                {
                    return self
                        .verifier
                        .component_publication_outcome_unknown(verified);
                }
                let (result, _source_handle) =
                    self.verifier.complete_component_publication(verified);
                result
            }
        }
    }

    fn recover_component_publication(
        &self,
        recovery: ComponentPublicationRecoveryHandle,
    ) -> ComponentPublicationResult {
        let record = match self.verifier.inspect_component_recovery(&recovery) {
            Ok(record) => record,
            Err(_) => return ComponentPublicationResult::OutcomeUnknown(recovery),
        };
        let verified = self.verifier.resume_component_publication(recovery);
        let metadata = match ready_journal_metadata(verified.proof_metadata()) {
            Ok(metadata) => metadata,
            Err(_) => {
                return self
                    .verifier
                    .component_publication_outcome_unknown(verified)
            }
        };
        let mut phase = match self.recover_previsible_phase(&record, &metadata) {
            Ok(phase) => phase,
            Err(_) => {
                return self
                    .verifier
                    .component_publication_outcome_unknown(verified)
            }
        };
        if phase == "rejected" {
            return self.verifier.reject_component_publication(verified);
        }
        if phase == "prepared" {
            let transition_record = record.clone();
            let transition_metadata = metadata.clone();
            if self
                .anchored_mutation_sync(3, &record.activation_nonce, move |transaction| {
                    mark_previsible_ready(transaction, &transition_record, &transition_metadata)
                })
                .is_err()
            {
                return self
                    .verifier
                    .component_publication_outcome_unknown(verified);
            }
            phase = "ready".to_owned();
        }
        if phase == "ready" {
            let transition_record = record.clone();
            let transition_metadata = metadata.clone();
            if self
                .anchored_mutation_sync(3, &record.activation_nonce, move |transaction| {
                    mark_previsible_publishing(
                        transaction,
                        &transition_record,
                        &transition_metadata,
                    )
                })
                .is_err()
            {
                return self
                    .verifier
                    .component_publication_outcome_unknown(verified);
            }
            phase = "publishing".to_owned();
        }
        if phase == "publishing" {
            let discriminator = record.activation_nonce;
            if self
                .anchored_mutation_sync(3, &discriminator, move |transaction| {
                    complete_previsible_publication(transaction, &record, &metadata)
                })
                .is_err()
            {
                return self
                    .verifier
                    .component_publication_outcome_unknown(verified);
            }
            phase = "published".to_owned();
        }
        if phase != "published" {
            return self
                .verifier
                .component_publication_outcome_unknown(verified);
        }
        let (result, _source_handle) = self.verifier.complete_component_publication(verified);
        result
    }

    fn abort_component_source(
        &self,
        clean: ComponentAbortBundle,
    ) -> Result<(), SensitiveParamCatalogError> {
        let (record, verified_metadata) = self.verifier.inspect_component_abort(&clean)?;
        let metadata =
            abort_journal_metadata(&verified_metadata).map_err(|error| error.as_catalog_error())?;
        let discriminator = record.activation_nonce;
        let begin_record = record.clone();
        let begin_metadata = metadata.clone();
        self.anchored_mutation_sync(3, &discriminator, move |transaction| {
            begin_previsible_abort(transaction, &begin_record, &begin_metadata)
        })
        .map_err(|error| error.as_catalog_error())?;
        self.anchored_mutation_sync(3, &discriminator, move |transaction| {
            complete_previsible_abort(transaction, &record, &metadata)
        })
        .map_err(|error| error.as_catalog_error())?;
        self.verifier.consume_component_abort(clean)?;
        Ok(())
    }
}

impl AgentObservationIdentityRegistrar for RegistrySensitiveParamProvider {
    fn begin_agent_registration(
        &self,
        operation_id: &str,
        exact_agent_id: &str,
    ) -> Result<(), SensitiveParamCatalogError> {
        self.begin_agent_registration_journaled(operation_id, exact_agent_id)
            .map_err(|error| error.as_catalog_error())
    }

    fn activate_agent_unpublished(
        &self,
        operation_id: &str,
    ) -> Result<PrevisibleObservationActivation, SensitiveParamCatalogError> {
        self.activate_agent_registration(operation_id)
            .map_err(|error| error.as_catalog_error())
    }

    fn publish_agent_activation(
        &self,
        activation: PrevisibleObservationActivation,
        ready: PrevisibleActivationReadyProof,
    ) -> AgentPublicationResult {
        match self.verifier.verify_agent_ready(activation, ready) {
            AgentReadyVerification::Rejected(rejected) => {
                self.verifier.agent_rejected_result(rejected)
            }
            AgentReadyVerification::Verified(verified) => {
                let record = verified.provider_record();
                let metadata = match ready_journal_metadata(verified.proof_metadata()) {
                    Ok(metadata) => metadata,
                    Err(_) => return self.verifier.reject_agent_publication(verified),
                };
                let discriminator = record.activation_nonce;
                let ready_record = record.clone();
                let ready_metadata = metadata.clone();
                if let Err(error) =
                    self.anchored_mutation_sync(3, &discriminator, move |transaction| {
                        mark_previsible_ready(transaction, &ready_record, &ready_metadata)
                    })
                {
                    return if error.gates_provider() {
                        self.verifier.agent_publication_outcome_unknown(verified)
                    } else {
                        self.verifier.reject_agent_publication(verified)
                    };
                }
                let publishing_record = record.clone();
                let publishing_metadata = metadata.clone();
                if self
                    .anchored_mutation_sync(3, &discriminator, move |transaction| {
                        mark_previsible_publishing(
                            transaction,
                            &publishing_record,
                            &publishing_metadata,
                        )
                    })
                    .is_err()
                {
                    return self.verifier.agent_publication_outcome_unknown(verified);
                }
                if self
                    .anchored_mutation_sync(3, &discriminator, move |transaction| {
                        complete_previsible_publication(transaction, &record, &metadata)
                    })
                    .is_err()
                {
                    return self.verifier.agent_publication_outcome_unknown(verified);
                }
                let (result, _source_handle) = self.verifier.complete_agent_publication(verified);
                result
            }
        }
    }

    fn recover_agent_publication(
        &self,
        recovery: AgentPublicationRecoveryHandle,
    ) -> AgentPublicationResult {
        let record = match self.verifier.inspect_agent_recovery(&recovery) {
            Ok(record) => record,
            Err(_) => return AgentPublicationResult::OutcomeUnknown(recovery),
        };
        let verified = self.verifier.resume_agent_publication(recovery);
        let metadata = match ready_journal_metadata(verified.proof_metadata()) {
            Ok(metadata) => metadata,
            Err(_) => return self.verifier.agent_publication_outcome_unknown(verified),
        };
        let mut phase = match self.recover_previsible_phase(&record, &metadata) {
            Ok(phase) => phase,
            Err(_) => return self.verifier.agent_publication_outcome_unknown(verified),
        };
        if phase == "rejected" {
            return self.verifier.reject_agent_publication(verified);
        }
        if phase == "prepared" {
            let transition_record = record.clone();
            let transition_metadata = metadata.clone();
            if self
                .anchored_mutation_sync(3, &record.activation_nonce, move |transaction| {
                    mark_previsible_ready(transaction, &transition_record, &transition_metadata)
                })
                .is_err()
            {
                return self.verifier.agent_publication_outcome_unknown(verified);
            }
            phase = "ready".to_owned();
        }
        if phase == "ready" {
            let transition_record = record.clone();
            let transition_metadata = metadata.clone();
            if self
                .anchored_mutation_sync(3, &record.activation_nonce, move |transaction| {
                    mark_previsible_publishing(
                        transaction,
                        &transition_record,
                        &transition_metadata,
                    )
                })
                .is_err()
            {
                return self.verifier.agent_publication_outcome_unknown(verified);
            }
            phase = "publishing".to_owned();
        }
        if phase == "publishing" {
            let discriminator = record.activation_nonce;
            if self
                .anchored_mutation_sync(3, &discriminator, move |transaction| {
                    complete_previsible_publication(transaction, &record, &metadata)
                })
                .is_err()
            {
                return self.verifier.agent_publication_outcome_unknown(verified);
            }
            phase = "published".to_owned();
        }
        if phase != "published" {
            return self.verifier.agent_publication_outcome_unknown(verified);
        }
        let (result, _source_handle) = self.verifier.complete_agent_publication(verified);
        result
    }

    fn abort_agent_registration(
        &self,
        clean: AgentAbortBundle,
        retain_until_ms: u64,
    ) -> Result<(), SensitiveParamCatalogError> {
        if retain_until_ms > i64::MAX as u64 {
            return Err(SensitiveParamCatalogError::InvalidIdentity);
        }
        let (record, verified_metadata) = self.verifier.inspect_agent_abort(&clean)?;
        let metadata =
            abort_journal_metadata(&verified_metadata).map_err(|error| error.as_catalog_error())?;
        let discriminator = record.activation_nonce;
        let begin_record = record.clone();
        let begin_metadata = metadata.clone();
        self.anchored_mutation_sync(3, &discriminator, move |transaction| {
            begin_previsible_abort(transaction, &begin_record, &begin_metadata)
        })
        .map_err(|error| error.as_catalog_error())?;
        self.anchored_mutation_sync(3, &discriminator, move |transaction| {
            complete_previsible_abort(transaction, &record, &metadata)
        })
        .map_err(|error| error.as_catalog_error())?;
        self.verifier.consume_agent_abort(clean)?;
        Ok(())
    }

    fn prepare_agent_termination(
        &self,
        operation_id: &str,
        exact_agent_ids: &[String],
        retain_until_ms: u64,
        subject_drains: Vec<VerifiedGrantSubjectDrainToken>,
        emission_drains: Vec<VerifiedSourceEmissionQuiesceReceipt>,
    ) -> Result<TerminationPrepareCommitAck, TerminationPrepareFailure> {
        let request_digest = termination_request_digest(operation_id, exact_agent_ids);
        let request_sequence = self.current_registry_sequence_sync().unwrap_or(0);
        let now_ms = u64::try_from(crate::types::now_unix_ms().max(0)).unwrap_or(0);
        if retain_until_ms > i64::MAX as u64 || retain_until_ms < now_ms {
            return Err(self.termination_state.reject_invalid_prepare_request(
                operation_id,
                request_digest,
                request_sequence,
            ));
        }
        let (record, members) =
            match self.load_agent_termination_candidate(operation_id, exact_agent_ids) {
                Ok(candidate) => candidate,
                Err(_) => {
                    return Err(self.termination_state.reject_invalid_prepare_request(
                        operation_id,
                        request_digest,
                        request_sequence,
                    ))
                }
            };
        let receipt_set = match self
            .termination_state
            .verify_termination_prepare_receipt_sets(
                &record,
                &members,
                TerminationGrantSubjectDrainReceiptSet::new(subject_drains),
                TerminationSourceEmissionQuiesceReceiptSet::new(emission_drains),
            ) {
            Ok(receipt_set) => receipt_set,
            Err(_) => return Err(self.termination_rejected(record)),
        };
        let prepared = match self.termination_state.prepare_committed(record.clone()) {
            Ok(prepared) => prepared,
            Err(_) => return Err(self.termination_rejected(record)),
        };
        let prepare_ack_digest = match self.termination_state.prepare_ack_digest(&prepared) {
            Ok(digest) => digest,
            Err(_) => return Err(self.termination_rejected(record)),
        };
        let prepare_ack_nonce = match self.termination_state.prepare_ack_nonce(&prepared) {
            Ok(nonce) => nonce,
            Err(_) => return Err(self.termination_rejected(record)),
        };
        let discriminator = record.operation_id.as_bytes().to_vec();
        let record_for_tx = record.clone();
        let config = self.config.clone();
        let finalize_capacity_limit = self.take_termination_finalize_capacity_limit();
        let admission_limits = match self.admission_capacity_limits() {
            Ok(limits) => limits,
            Err(error) if error.gates_provider() => {
                return Err(self.termination_unknown(record));
            }
            Err(_) => return Err(self.termination_rejected(record)),
        };
        match self.anchored_mutation_sync(4, &discriminator, move |transaction| {
            prepare_termination_operation(
                transaction,
                &record_for_tx,
                &members,
                retain_until_ms,
                &receipt_set,
                prepare_ack_digest,
                prepare_ack_nonce,
                config.registry_instance,
                config.boot,
                "terminate-agents",
                ObservationIdentityClass::Agent,
                finalize_capacity_limit,
                admission_limits,
            )
        }) {
            Ok(()) => Ok(prepared),
            Err(error) if error.gates_provider() => Err(self.termination_unknown(record)),
            Err(_) => Err(self.termination_rejected(record)),
        }
    }

    fn recover_agent_termination_prepare(
        &self,
        recovery: TerminationPrepareRecoveryHandle,
    ) -> Result<TerminationPrepareCommitAck, TerminationPrepareFailure> {
        let record = match self.termination_state.inspect_prepare_recovery(&recovery) {
            Ok(record) => record,
            Err(_) => return Err(TerminationPrepareFailure::OutcomeUnknown(recovery)),
        };
        match self.recover_termination_prepare_ack(
            &record,
            "terminate-agents",
            ObservationIdentityClass::Agent,
        ) {
            Ok(Some(prepared)) => Ok(prepared),
            Ok(None) => {
                let resumed = self.termination_state.resume_prepare(recovery);
                Err(self.termination_rejected(resumed))
            }
            Err(_) => Err(TerminationPrepareFailure::OutcomeUnknown(recovery)),
        }
    }

    fn finalize_agent_termination(
        &self,
        prepared: TerminationPrepareCommitAck,
        cleanup: TerminationCleanupCompleteReceipt,
    ) -> TerminationFinalizeResult {
        let record = match self.termination_state.verify_prepare_ack(&prepared) {
            Ok(record) => record,
            Err(_) => return TerminationFinalizeResult::Rejected { prepared, cleanup },
        };
        if self
            .cleanup_verifier
            .verify_cleanup_complete(&cleanup, &record)
            .is_err()
        {
            return TerminationFinalizeResult::Rejected { prepared, cleanup };
        }
        let verified = match self.termination_state.verify_finalize_inputs(
            prepared,
            cleanup,
            &self.cleanup_verifier,
        ) {
            TerminationFinalizeInputVerification::Verified(verified) => verified,
            TerminationFinalizeInputVerification::Rejected { prepared, cleanup } => {
                return TerminationFinalizeResult::Rejected { prepared, cleanup };
            }
        };
        let metadata = match self
            .termination_state
            .finalize_journal_metadata(&verified, &self.cleanup_verifier)
        {
            Ok(metadata) => metadata,
            Err(_) => return self.termination_state.finalize_rejected(verified),
        };
        let discriminator = record.operation_id.as_bytes().to_vec();
        let record_for_tx = record.clone();
        let config = self.config.clone();
        match self.anchored_mutation_sync(5, &discriminator, move |transaction| {
            finalize_termination_operation(
                transaction,
                &record_for_tx,
                &metadata,
                config.registry_instance,
                config.boot,
                "terminate-agents",
                ObservationIdentityClass::Agent,
            )
        }) {
            Ok(()) => self.termination_state.finalize_committed(verified),
            Err(error) if error.gates_provider() => {
                self.termination_state.finalize_outcome_unknown(verified)
            }
            Err(_) => self.termination_state.finalize_rejected(verified),
        }
    }

    fn recover_agent_termination(
        &self,
        recovery: TerminationFinalizeRecoveryHandle,
    ) -> TerminationFinalizeResult {
        let record = match self.termination_state.inspect_finalize_recovery(&recovery) {
            Ok(record) => record,
            Err(_) => return TerminationFinalizeResult::OutcomeUnknown(recovery),
        };
        let metadata = match self
            .termination_state
            .inspect_finalize_recovery_journal_metadata(&recovery, &self.cleanup_verifier)
        {
            Ok(metadata) => metadata,
            Err(_) => return TerminationFinalizeResult::OutcomeUnknown(recovery),
        };
        if self
            .recover_termination_operation(
                &record,
                "terminate-agents",
                ObservationIdentityClass::Agent,
            )
            .is_err()
        {
            return TerminationFinalizeResult::OutcomeUnknown(recovery);
        }
        let committed = self
            .termination_finalization_is_committed(
                &record,
                &metadata,
                "terminate-agents",
                ObservationIdentityClass::Agent,
            )
            .unwrap_or(false);
        let verified = self.termination_state.resume_finalize(recovery);
        if committed {
            self.termination_state.finalize_committed(verified)
        } else {
            self.termination_state.finalize_rejected(verified)
        }
    }
}

impl HostObservationIdentityRegistrar for RegistrySensitiveParamProvider {
    fn register_host(
        &self,
        emitter: HostEmitterId,
    ) -> Result<IssuedObservationSourceHandle, SensitiveParamCatalogError> {
        if !self.is_ready() {
            return Err(SensitiveParamCatalogError::RecoveryRequired);
        }
        let id = emitter.canonical_id().to_owned();
        let existing = self
            .view
            .read()
            .map_err(|_| SensitiveParamCatalogError::RecoveryRequired)?
            .get(&id)
            .filter(|row| row.lifecycle == IdentityLifecycle::Permanent)
            .map(|row| row.snapshot.claims());
        let claims = match existing {
            Some(claims) => claims,
            None => {
                let discriminator = id.as_bytes().to_vec();
                let admission_limits = self
                    .admission_capacity_limits()
                    .map_err(|error| error.as_catalog_error())?;
                self.anchored_mutation_sync(6, &discriminator, |transaction| {
                    if let Some(existing) = read_identity_claims(transaction, &id)? {
                        if existing.expected_class != ObservationIdentityClass::Host {
                            return Err(ObservationProviderError::IdentityConflict);
                        }
                        return Ok(existing);
                    }
                    let authority_delta = u64::from(!authority_row_exists(transaction, &id)?);
                    // Host registration is not journaled as an active operation.
                    enforce_admission_capacity(
                        transaction,
                        1,
                        authority_delta,
                        0,
                        0,
                        0,
                        admission_limits,
                    )?;
                    let incarnation = allocate_incarnation(
                        transaction,
                        &id,
                        ObservationIdentityClass::Host,
                        None,
                    )?;
                    let digest = SensitiveParamDeclaration::host(emitter).digest_for(
                        &id,
                        ObservationIdentityClass::Host,
                        incarnation,
                    )?;
                    insert_authority_and_identity(
                        transaction,
                        &id,
                        ObservationIdentityClass::Host,
                        incarnation,
                        digest,
                        "permanent",
                        true,
                        None,
                        None,
                        None,
                    )?;
                    Ok(ObservationIdentityClaims {
                        exact_id: id,
                        expected_class: ObservationIdentityClass::Host,
                        incarnation,
                        declaration_digest: digest,
                    })
                })
                .map_err(|error| error.as_catalog_error())?
            }
        };
        self.verifier.issue_named_live_source(claims)
    }

    fn reissue_boot_sources(
        &self,
        receipt: &CompletedIdentityHydrationReceipt,
    ) -> Result<Vec<IssuedObservationSourceHandle>, SensitiveParamCatalogError> {
        if !self.is_ready() {
            return Err(SensitiveParamCatalogError::RecoveryRequired);
        }
        let _mutation_guard = self
            .registry
            .observation_mutation_lock
            .try_lock()
            .map_err(|_| SensitiveParamCatalogError::StorageUnavailable)?;
        let conn = self
            .registry
            .conn
            .try_lock()
            .map_err(|_| SensitiveParamCatalogError::StorageUnavailable)?;
        let result =
            (|| -> Result<Vec<IssuedObservationSourceHandle>, ObservationProviderError> {
                let ledger = read_ledger(&conn)?.ok_or_else(|| {
                    ObservationProviderError::RecoveryRequired("missing identity ledger".to_owned())
                })?;
                reconcile_external_anchor(self.anchor.as_ref(), &ledger)?;
                verify_complete_roots(&conn, &ledger)?;
                validate_durable_invariants(&conn)?;
                self.verifier.verify_completed_hydration_receipt(
                    receipt,
                    ledger.sequence,
                    ledger.state_root,
                )?;
                let view = self.view.read().map_err(|_| {
                    ObservationProviderError::RecoveryRequired(
                        "catalog view lock is poisoned".to_owned(),
                    )
                })?;
                view.values()
                    .filter(|row| row.lifecycle.permits_live_authority())
                    .map(|row| {
                        self.verifier
                            .issue_named_live_source(row.snapshot.claims())
                            .map_err(ObservationProviderError::from)
                    })
                    .collect()
            })();
        if let Err(error) = &result {
            if error.gates_provider() {
                self.ready.store(false, Ordering::Release);
            }
        }
        result.map_err(|error| error.as_catalog_error())
    }
}

fn validated_component_declaration(
    names: Vec<String>,
) -> Result<SensitiveParamDeclaration, ObservationProviderError> {
    if names.iter().any(|name| name.chars().any(char::is_control)) {
        return Err(ObservationProviderError::InvalidInput(
            "sensitive parameter names cannot contain control characters".to_owned(),
        ));
    }
    SensitiveParamDeclaration::component(names).map_err(|error| match error {
        SensitiveParamCatalogError::CapacityExceeded => {
            ObservationProviderError::CapacityExceeded("sensitive declaration".to_owned())
        }
        _ => ObservationProviderError::InvalidInput("invalid sensitive declaration".to_owned()),
    })
}

fn canonical_sensitive_param_tail(names: &[String]) -> Result<Vec<u8>, ObservationProviderError> {
    let count = u32::try_from(names.len()).map_err(|_| {
        ObservationProviderError::CapacityExceeded("sensitive declaration count".to_owned())
    })?;
    let mut bytes = Vec::with_capacity(4 + names.iter().map(|name| 4 + name.len()).sum::<usize>());
    bytes.extend_from_slice(&count.to_be_bytes());
    for name in names {
        encode_text(&mut bytes, name)?;
    }
    Ok(bytes)
}

fn validate_operation_id(operation_id: &str) -> Result<(), ObservationProviderError> {
    if operation_id.is_empty() || operation_id.len() > 256 {
        return Err(ObservationProviderError::InvalidInput(
            "operation id must be 1..=256 UTF-8 bytes".to_owned(),
        ));
    }
    Ok(())
}

fn validate_ordinary_identity_id(id: &str) -> Result<(), ObservationProviderError> {
    if id.is_empty()
        || id.len() > 256
        || id.starts_with("__sys:")
        || matches!(id, "runtime" | "retention_sweeper" | "pack-manager")
    {
        return Err(ObservationProviderError::InvalidInput(
            "ordinary identity id is empty, oversized, or reserved".to_owned(),
        ));
    }
    Ok(())
}

fn class_to_sql(class: ObservationIdentityClass) -> &'static str {
    match class {
        ObservationIdentityClass::Component => "component",
        ObservationIdentityClass::Agent => "agent",
        ObservationIdentityClass::Host => "host",
    }
}

fn class_from_sql(value: &str) -> Result<ObservationIdentityClass, ObservationProviderError> {
    match value {
        "component" => Ok(ObservationIdentityClass::Component),
        "agent" => Ok(ObservationIdentityClass::Agent),
        "host" => Ok(ObservationIdentityClass::Host),
        _ => Err(ObservationProviderError::RecoveryRequired(
            "unknown persisted identity class".to_owned(),
        )),
    }
}

fn read_identity_claims(
    conn: &Connection,
    id: &str,
) -> Result<Option<ObservationIdentityClaims>, ObservationProviderError> {
    let row: Option<(String, i64, Vec<u8>)> = conn
        .query_row(
            "SELECT class,incarnation,declaration_digest FROM observation_identities WHERE id=?1",
            params![id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let Some((class, incarnation, stored_digest)) = row else {
        return Ok(None);
    };
    let class = class_from_sql(&class)?;
    let incarnation = u64::try_from(incarnation).map_err(|_| {
        ObservationProviderError::RecoveryRequired("invalid incarnation".to_owned())
    })?;
    let expected_digest = reconstruct_declaration_digest(conn, id, class, incarnation)?;
    if stored_digest.as_slice() != expected_digest.as_bytes() {
        return Err(ObservationProviderError::RecoveryRequired(
            "stored declaration digest does not match canonical declaration".to_owned(),
        ));
    }
    Ok(Some(ObservationIdentityClaims {
        exact_id: id.to_owned(),
        expected_class: class,
        incarnation,
        declaration_digest: expected_digest,
    }))
}

fn require_exact_catalog_claims(
    conn: &Connection,
    expected: &ObservationIdentityClaims,
    live_required: bool,
) -> Result<(), ObservationProviderError> {
    let observed = read_identity_claims(conn, &expected.exact_id)?
        .ok_or(ObservationProviderError::UnknownIdentity)?;
    if &observed != expected {
        return Err(ObservationProviderError::Catalog(
            SensitiveParamCatalogError::StaleIdentity,
        ));
    }
    let (lifecycle, catalog_visible): (String, i64) = conn.query_row(
        "SELECT lifecycle_state,catalog_visible FROM observation_identities WHERE id=?1",
        params![expected.exact_id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let lifecycle = IdentityLifecycle::parse(&lifecycle)?;
    let eligible = if live_required {
        lifecycle.permits_live_authority()
    } else {
        lifecycle.permits_replay()
    };
    if !eligible || catalog_visible != 1 {
        return Err(ObservationProviderError::Catalog(
            SensitiveParamCatalogError::StaleIdentity,
        ));
    }
    Ok(())
}

fn require_sql_key_status(
    conn: &Connection,
    key_id: u32,
    signing_required: bool,
) -> Result<(), ObservationProviderError> {
    let status: Option<String> = conn
        .query_row(
            "SELECT status FROM observation_persisted_keyring_entries WHERE key_id=?1",
            params![i64::from(key_id)],
            |row| row.get(0),
        )
        .optional()?;
    match (signing_required, status.as_deref()) {
        (true, Some("signing")) | (false, Some("signing" | "verify-only")) => Ok(()),
        _ => Err(ObservationProviderError::Catalog(
            SensitiveParamCatalogError::InvalidCarrier,
        )),
    }
}

fn operation_exists(
    conn: &Connection,
    operation_id: &str,
) -> Result<bool, ObservationProviderError> {
    let exists: i64 = conn.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM observation_identity_operations WHERE operation_id=?1
         )",
        params![operation_id],
        |row| row.get(0),
    )?;
    Ok(exists != 0)
}

fn reconstruct_declaration_digest(
    conn: &Connection,
    id: &str,
    class: ObservationIdentityClass,
    incarnation: u64,
) -> Result<DeclarationDigest, ObservationProviderError> {
    let declaration = match class {
        ObservationIdentityClass::Component => {
            let json: String = conn.query_row(
                "SELECT submit_config_json FROM components WHERE id=?1",
                params![id],
                |row| row.get(0),
            )?;
            let config: ComponentSubmitConfig = serde_json::from_str(&json)
                .map_err(|error| RegistryError::Serde(error.to_string()))?;
            validated_component_declaration(config.sensitive_params)?
        }
        ObservationIdentityClass::Agent => SensitiveParamDeclaration::agent_known_empty(),
        ObservationIdentityClass::Host => {
            use advance_shared_types::observation_identity::HostEmitterId;
            let emitter = match id {
                "__sys:runtime" => HostEmitterId::Runtime,
                "__sys:retention_sweeper" => HostEmitterId::RetentionSweeper,
                "__sys:pack-manager" => HostEmitterId::PackManager,
                _ => {
                    return Err(ObservationProviderError::RecoveryRequired(
                        "unlisted host identity".to_owned(),
                    ));
                }
            };
            SensitiveParamDeclaration::host(emitter)
        }
    };
    declaration
        .digest_for(id, class, incarnation)
        .map_err(|_| ObservationProviderError::RecoveryRequired("invalid declaration".to_owned()))
}

fn allocate_incarnation(
    conn: &Connection,
    id: &str,
    class: ObservationIdentityClass,
    expected_previous: Option<u64>,
) -> Result<u64, ObservationProviderError> {
    let existing: Option<(String, i64)> = conn
        .query_row(
            "SELECT class,last_incarnation FROM observation_identity_authority WHERE id=?1",
            params![id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    match existing {
        None => {
            if expected_previous.is_some() {
                return Err(ObservationProviderError::IdentityConflict);
            }
            Ok(1)
        }
        Some((stored_class, last)) => {
            if class_from_sql(&stored_class)? != class {
                return Err(ObservationProviderError::IdentityConflict);
            }
            let last = u64::try_from(last).map_err(|_| {
                ObservationProviderError::RecoveryRequired(
                    "invalid authority high-water".to_owned(),
                )
            })?;
            if expected_previous.is_some_and(|expected| expected != last) {
                return Err(ObservationProviderError::IdentityConflict);
            }
            last.checked_add(1)
                .filter(|next| *next <= i64::MAX as u64)
                .ok_or_else(|| {
                    ObservationProviderError::CapacityExceeded(
                        "identity incarnation exhausted".to_owned(),
                    )
                })
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn insert_authority_and_identity(
    conn: &Connection,
    id: &str,
    class: ObservationIdentityClass,
    incarnation: u64,
    digest: DeclarationDigest,
    lifecycle_state: &str,
    catalog_visible: bool,
    operation_id: Option<&str>,
    tombstoned_at_ms: Option<u64>,
    retain_until_ms: Option<u64>,
) -> Result<(), ObservationProviderError> {
    let authority_exists: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM observation_identity_authority WHERE id=?1)",
        params![id],
        |row| row.get(0),
    )?;
    if authority_exists {
        let changed = conn.execute(
            "UPDATE observation_identity_authority
             SET last_incarnation=?1,last_declaration_digest=?2
             WHERE id=?3 AND class=?4 AND last_incarnation < ?1",
            params![
                incarnation as i64,
                digest.as_bytes().as_slice(),
                id,
                class_to_sql(class)
            ],
        )?;
        if changed != 1 {
            return Err(ObservationProviderError::IdentityConflict);
        }
    } else {
        conn.execute(
            "INSERT INTO observation_identity_authority
                (id,class,last_incarnation,last_declaration_digest)
             VALUES (?1,?2,?3,?4)",
            params![
                id,
                class_to_sql(class),
                incarnation as i64,
                digest.as_bytes().as_slice()
            ],
        )?;
    }
    conn.execute(
        "INSERT INTO observation_identities
            (id,class,incarnation,declaration_digest,lifecycle_state,catalog_visible,
             operation_id,tombstoned_at_ms,retain_until_ms)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
        params![
            id,
            class_to_sql(class),
            incarnation as i64,
            digest.as_bytes().as_slice(),
            lifecycle_state,
            i64::from(catalog_visible),
            operation_id,
            tombstoned_at_ms.map(|v| v as i64),
            retain_until_ms.map(|v| v as i64),
        ],
    )?;
    Ok(())
}

fn authority_row_exists(conn: &Connection, id: &str) -> Result<bool, ObservationProviderError> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM observation_identity_authority WHERE id=?1)",
        params![id],
        |row| row.get(0),
    )
    .map_err(ObservationProviderError::from)
}

fn enforce_admission_capacity(
    conn: &Connection,
    identity_delta: u64,
    authority_delta: u64,
    active_operation_delta: u64,
    operation_row_delta: u64,
    member_row_delta: u64,
    limits: AdmissionCapacityLimits,
) -> Result<(), ObservationProviderError> {
    let identities: i64 =
        conn.query_row("SELECT COUNT(*) FROM observation_identities", [], |row| {
            row.get(0)
        })?;
    let authorities: i64 = conn.query_row(
        "SELECT COUNT(*) FROM observation_identity_authority",
        [],
        |row| row.get(0),
    )?;
    let active_operations: i64 = conn.query_row(
        "SELECT COUNT(*) FROM observation_identity_operations WHERE is_active=1",
        [],
        |row| row.get(0),
    )?;
    // Active rows reserve their eventual committed-history slots, so ordinary
    // completion can never fail merely because another operation filled the
    // replay ledger in the meantime.
    let operation_rows: i64 = conn.query_row(
        "SELECT COUNT(*) FROM observation_identity_operations",
        [],
        |row| row.get(0),
    )?;
    let member_rows: i64 = conn.query_row(
        "SELECT COUNT(*) FROM observation_identity_operation_members",
        [],
        |row| row.get(0),
    )?;
    let identities = u64::try_from(identities).map_err(|_| {
        ObservationProviderError::RecoveryRequired("negative identity row count".to_owned())
    })?;
    let authorities = u64::try_from(authorities).map_err(|_| {
        ObservationProviderError::RecoveryRequired("negative authority row count".to_owned())
    })?;
    let active_operations = u64::try_from(active_operations).map_err(|_| {
        ObservationProviderError::RecoveryRequired("negative active-operation count".to_owned())
    })?;
    let operation_rows = u64::try_from(operation_rows).map_err(|_| {
        ObservationProviderError::RecoveryRequired("negative operation row count".to_owned())
    })?;
    let member_rows = u64::try_from(member_rows).map_err(|_| {
        ObservationProviderError::RecoveryRequired("negative operation-member count".to_owned())
    })?;
    if identities
        .checked_add(identity_delta)
        .is_none_or(|next| next > limits.identities)
        || authorities
            .checked_add(authority_delta)
            .is_none_or(|next| next > limits.authorities)
        || active_operations
            .checked_add(active_operation_delta)
            .is_none_or(|next| next > limits.active_operations)
        || operation_rows
            .checked_add(operation_row_delta)
            .is_none_or(|next| next > limits.operations)
        || member_rows
            .checked_add(member_row_delta)
            .is_none_or(|next| next > limits.members)
    {
        return Err(ObservationProviderError::CapacityExceeded(
            "identity/authority/active-operation/committed-history bound".to_owned(),
        ));
    }
    Ok(())
}

fn load_view_rows(
    conn: &Arc<tokio::sync::Mutex<Connection>>,
    revision: u64,
) -> Result<BTreeMap<String, IdentityViewRow>, ObservationProviderError> {
    let conn = conn.blocking_lock();
    load_view_rows_from_connection(&conn, revision)
}

fn load_view_rows_from_connection(
    conn: &Connection,
    revision: u64,
) -> Result<BTreeMap<String, IdentityViewRow>, ObservationProviderError> {
    validate_durable_invariants(conn)?;
    let mut stmt = conn.prepare(
        "SELECT id,class,incarnation,declaration_digest,lifecycle_state,catalog_visible
         FROM observation_identities ORDER BY id COLLATE BINARY",
    )?;
    let mut rows = stmt.query([])?;
    let mut result = BTreeMap::new();
    while let Some(row) = rows.next()? {
        let id: String = row.get(0)?;
        let class_text: String = row.get(1)?;
        let class = class_from_sql(&class_text)?;
        let incarnation = u64::try_from(row.get::<_, i64>(2)?).map_err(|_| {
            ObservationProviderError::RecoveryRequired("invalid incarnation".to_owned())
        })?;
        let stored_digest: Vec<u8> = row.get(3)?;
        let lifecycle = IdentityLifecycle::parse(&row.get::<_, String>(4)?)?;
        let visible = row.get::<_, i64>(5)? == 1;
        if !visible {
            continue;
        }
        let digest = reconstruct_declaration_digest(conn, &id, class, incarnation)?;
        if stored_digest.as_slice() != digest.as_bytes() {
            return Err(ObservationProviderError::RecoveryRequired(
                "view hydration declaration mismatch".to_owned(),
            ));
        }
        let names = if class == ObservationIdentityClass::Component {
            let json: String = conn.query_row(
                "SELECT submit_config_json FROM components WHERE id=?1",
                params![id],
                |row| row.get(0),
            )?;
            let config: ComponentSubmitConfig = serde_json::from_str(&json)
                .map_err(|error| RegistryError::Serde(error.to_string()))?;
            validated_component_declaration(config.sensitive_params)?.names()
        } else {
            Arc::from([])
        };
        let snapshot = SensitiveParamSnapshot {
            canonical_component_id: id.clone(),
            identity_class: class,
            incarnation,
            declaration_digest: digest,
            names,
            revision,
        };
        snapshot.validate().map_err(|_| {
            ObservationProviderError::RecoveryRequired("invalid hydrated snapshot".to_owned())
        })?;
        if result
            .insert(
                snapshot.canonical_component_id.clone(),
                IdentityViewRow {
                    snapshot,
                    lifecycle,
                },
            )
            .is_some()
        {
            return Err(ObservationProviderError::RecoveryRequired(
                "duplicate global identity in hydrated view".to_owned(),
            ));
        }
    }
    Ok(result)
}

fn validate_durable_invariants(conn: &Connection) -> Result<(), ObservationProviderError> {
    verify_observation_schema_fingerprint(conn)?;
    let foreign_key_error: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM pragma_foreign_key_check LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    if foreign_key_error.is_some() {
        return Err(ObservationProviderError::RecoveryRequired(
            "foreign-key check failed".to_owned(),
        ));
    }

    let orphan_component: i64 = conn.query_row(
        "SELECT COUNT(*) FROM observation_identities i
         LEFT JOIN components c ON c.id=i.id
         WHERE i.class='component' AND c.id IS NULL",
        [],
        |row| row.get(0),
    )?;
    let split_component: i64 = conn.query_row(
        "SELECT COUNT(*) FROM components c
         LEFT JOIN observation_identities i ON i.id=c.id AND i.class='component'
         WHERE c.identity_incarnation IS NULL OR c.declaration_digest IS NULL
            OR i.id IS NULL OR i.incarnation != c.identity_incarnation
            OR i.declaration_digest != c.declaration_digest",
        [],
        |row| row.get(0),
    )?;
    let authority_mismatch: i64 = conn.query_row(
        "SELECT COUNT(*) FROM observation_identities i
         LEFT JOIN observation_identity_authority a ON a.id=i.id
         WHERE a.id IS NULL OR a.class != i.class OR a.last_incarnation < i.incarnation",
        [],
        |row| row.get(0),
    )?;
    let active_mismatch: i64 = conn.query_row(
        "SELECT COUNT(*) FROM observation_identity_operation_members m
         JOIN observation_identity_operations o ON o.operation_id=m.operation_id
         WHERE m.is_active != o.is_active",
        [],
        |row| row.get(0),
    )?;
    let reserved_namespace_mismatch: i64 = conn.query_row(
        "SELECT COUNT(*) FROM observation_identities
         WHERE (class IN ('component','agent') AND id GLOB '__sys:*')
            OR (class='host' AND id NOT IN (
                '__sys:runtime','__sys:retention_sweeper','__sys:pack-manager'))",
        [],
        |row| row.get(0),
    )?;
    let projection_mismatch: i64 = conn.query_row(
        "SELECT COUNT(*) FROM observation_identities i
         JOIN components c ON c.id=i.id
         WHERE i.class='component' AND (
             i.incarnation != c.identity_incarnation
             OR i.declaration_digest != c.declaration_digest
             OR (i.lifecycle_state='pending' AND c.lifecycle_state!='live')
             OR (i.lifecycle_state!='pending' AND i.lifecycle_state != c.lifecycle_state)
             OR i.catalog_visible != CASE WHEN i.lifecycle_state='pending' THEN 0 ELSE 1 END
             OR c.catalog_visible != CASE WHEN c.lifecycle_state='live'
                                           AND i.lifecycle_state='live' THEN 1 ELSE 0 END
             OR i.operation_id IS NOT c.operation_id
             OR i.tombstoned_at_ms IS NOT c.tombstoned_at_ms
             OR i.retain_until_ms IS NOT c.retain_until_ms)",
        [],
        |row| row.get(0),
    )?;
    let (capacity_rows, capacity_actual, capacity_future): (i64, i64, i64) = conn.query_row(
        "SELECT row_count,actual_encoded_bytes,future_reserved_bytes
         FROM observation_previsible_capacity WHERE singleton=1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    let (actual_rows, actual_bytes, future_bytes): (i64, i64, i64) = conn.query_row(
        "SELECT COUNT(*),COALESCE(SUM(encoded_bytes),0),
                COALESCE(SUM(future_reserved_bytes),0)
         FROM observation_previsible_activations",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    // A prepared registration with no tag-3 row owns one complete future
    // journal reservation. The singleton is intentionally aggregate, while
    // this deterministic join makes every reserved row/byte attributable to
    // one exact operation across restart.
    let pending_previsible_reservations: i64 = conn.query_row(
        "SELECT COUNT(*)
         FROM observation_identity_operations o
         WHERE o.kind IN ('register-agent','register-component')
           AND o.phase='prepared' AND o.is_active=1
           AND NOT EXISTS (
             SELECT 1 FROM observation_previsible_activations p
             WHERE p.operation_id=o.operation_id
           )",
        [],
        |row| row.get(0),
    )?;
    let expected_capacity_rows = actual_rows
        .checked_add(pending_previsible_reservations)
        .ok_or_else(|| {
            ObservationProviderError::RecoveryRequired(
                "previsible operation-linked row accounting overflow".to_owned(),
            )
        })?;
    let expected_capacity_future = pending_previsible_reservations
        .checked_mul(PREVISIBLE_TOTAL_BYTES)
        .and_then(|reserved| future_bytes.checked_add(reserved))
        .ok_or_else(|| {
            ObservationProviderError::RecoveryRequired(
                "previsible operation-linked byte accounting overflow".to_owned(),
            )
        })?;
    if orphan_component != 0
        || split_component != 0
        || authority_mismatch != 0
        || active_mismatch != 0
        || reserved_namespace_mismatch != 0
        || projection_mismatch != 0
        || (capacity_rows, capacity_actual, capacity_future)
            != (
                expected_capacity_rows,
                actual_bytes,
                expected_capacity_future,
            )
    {
        return Err(ObservationProviderError::RecoveryRequired(
            "joined component/identity/authority/operation invariant failed".to_owned(),
        ));
    }

    validate_component_declaration_projection(conn)?;
    validate_previsible_row_encodings(conn)?;
    validate_termination_finalize_rows(conn)?;
    validate_carrier_migration_rows(conn)?;

    enforce_persisted_capacity(conn)?;
    Ok(())
}

fn validate_component_declaration_projection(
    conn: &Connection,
) -> Result<(), ObservationProviderError> {
    let mut stmt = conn.prepare(
        "SELECT id,submit_config_json,sensitive_params,identity_incarnation,declaration_digest
         FROM components",
    )?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let id: String = row.get(0)?;
        let json: String = row.get(1)?;
        let stored_tail: Vec<u8> = row.get(2)?;
        let incarnation = u64::try_from(row.get::<_, i64>(3)?).map_err(|_| {
            ObservationProviderError::RecoveryRequired(
                "component incarnation is outside canonical range".to_owned(),
            )
        })?;
        let stored_digest: Vec<u8> = row.get(4)?;
        let config: ComponentSubmitConfig =
            serde_json::from_str(&json).map_err(|error| RegistryError::Serde(error.to_string()))?;
        let declaration = validated_component_declaration(config.sensitive_params)?;
        let canonical_tail = canonical_sensitive_param_tail(declaration.names().as_ref())?;
        let expected_digest =
            declaration.digest_for(&id, ObservationIdentityClass::Component, incarnation)?;
        if stored_tail != canonical_tail || stored_digest.as_slice() != expected_digest.as_bytes() {
            return Err(ObservationProviderError::RecoveryRequired(
                "component sensitive-parameter projection/digest mismatch".to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_previsible_row_encodings(conn: &Connection) -> Result<(), ObservationProviderError> {
    let mut stmt = conn.prepare(
        "SELECT length(CAST(operation_id AS BLOB)),
                length(CAST(identity_id AS BLOB)),phase,
                (subject_receipt_digest IS NOT NULL)+
                (table_receipt_digest IS NOT NULL)+
                (lifecycle_receipt_digest IS NOT NULL)+
                (subject_absence_digest IS NOT NULL)+
                (table_absence_digest IS NOT NULL)+
                (lifecycle_absence_digest IS NOT NULL)+
                (ready_proof_nonce IS NOT NULL)+
                (abort_proof_nonce IS NOT NULL)+
                (rejection_nonce IS NOT NULL)+
                (recovery_nonce IS NOT NULL),
                terminal_at_ms IS NOT NULL,audit_checkpoint_sequence IS NOT NULL,
                encoded_bytes,future_reserved_bytes
         FROM observation_previsible_activations",
    )?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let operation_len: i64 = row.get(0)?;
        let identity_len: i64 = row.get(1)?;
        let phase: String = row.get(2)?;
        let present: i64 = row.get(3)?;
        let terminal: bool = row.get(4)?;
        let audit: bool = row.get(5)?;
        let stored_encoded: i64 = row.get(6)?;
        let stored_future: i64 = row.get(7)?;
        let expected_encoded = previsible_encoded_len_from_lengths(
            operation_len,
            identity_len,
            present,
            terminal,
            audit,
        )?;
        let expected_future = if matches!(phase.as_str(), "published" | "aborted") {
            if audit {
                0
            } else {
                AUDIT_CHECKPOINT_BYTES
            }
        } else {
            PREVISIBLE_TOTAL_BYTES - expected_encoded
        };
        if stored_encoded != expected_encoded || stored_future != expected_future {
            return Err(ObservationProviderError::RecoveryRequired(
                "previsible row canonical byte accounting mismatch".to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_termination_finalize_rows(conn: &Connection) -> Result<(), ObservationProviderError> {
    let (capacity_rows, capacity_actual, capacity_future): (i64, i64, i64) = conn.query_row(
        "SELECT row_count,actual_encoded_bytes,future_reserved_bytes
         FROM observation_termination_finalize_capacity WHERE singleton=1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    let (actual_rows, actual_bytes, future_bytes): (i64, i64, i64) = conn.query_row(
        "SELECT COUNT(*),COALESCE(SUM(encoded_bytes),0),
                COALESCE(SUM(future_reserved_bytes),0)
         FROM observation_termination_finalizations",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    if (capacity_rows, capacity_actual, capacity_future)
        != (actual_rows, actual_bytes, future_bytes)
    {
        return Err(ObservationProviderError::RecoveryRequired(
            "termination finalization capacity counters mismatch".to_owned(),
        ));
    }
    let association_mismatch: i64 = conn.query_row(
        "SELECT COUNT(*)
         FROM observation_termination_finalizations f
         JOIN observation_identity_operations o ON o.operation_id=f.operation_id
         WHERE f.operation_kind!=o.kind
            OR (f.phase='prepared' AND (o.phase!='prepared' OR o.is_active!=1))
            OR (f.phase='finalized' AND (o.phase!='committed' OR o.is_active!=0))
            OR f.prepare_ack_digest=zeroblob(32)
            OR f.prepare_ack_nonce=zeroblob(32)
            OR f.member_set_digest=zeroblob(32)
            OR (f.phase='finalized' AND (
                 f.cleanup_receipt_digest=zeroblob(32)
                 OR f.cleanup_high_water_digest=zeroblob(32)
                 OR f.cleanup_receipt_set_digest=zeroblob(32)
                 OR f.cleanup_nonce=zeroblob(32)
                 OR f.finalize_recovery_nonce=zeroblob(32)
                 OR f.finalize_ack_digest=zeroblob(32)))",
        [],
        |row| row.get(0),
    )?;
    let missing_receipt_projection: i64 = conn.query_row(
        "SELECT COUNT(*)
         FROM observation_identity_operation_members m
         JOIN observation_identity_operations o ON o.operation_id=m.operation_id
         WHERE o.kind IN ('terminate-agents','terminate-component')
           AND (m.termination_subject_receipt_digest IS NULL
                OR m.termination_emission_receipt_digest IS NULL
                OR m.termination_subject_receipt_digest=zeroblob(32)
                OR m.termination_emission_receipt_digest=zeroblob(32))",
        [],
        |row| row.get(0),
    )?;
    if association_mismatch != 0 || missing_receipt_projection != 0 {
        return Err(ObservationProviderError::RecoveryRequired(
            "termination operation/finalization/receipt association mismatch".to_owned(),
        ));
    }
    let mut stmt = conn.prepare(
        "SELECT length(CAST(operation_id AS BLOB)),phase,
                (cleanup_receipt_digest IS NOT NULL)+
                (cleanup_high_water_digest IS NOT NULL)+
                (cleanup_receipt_set_digest IS NOT NULL)+
                (cleanup_nonce IS NOT NULL)+
                (finalize_recovery_nonce IS NOT NULL)+
                (finalize_ack_digest IS NOT NULL),
                finalize_sequence IS NOT NULL,terminal_at_ms IS NOT NULL,
                audit_checkpoint_sequence IS NOT NULL,
                encoded_bytes,future_reserved_bytes
         FROM observation_termination_finalizations",
    )?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let operation_len = usize::try_from(row.get::<_, i64>(0)?).map_err(|_| {
            ObservationProviderError::RecoveryRequired(
                "termination operation id length is invalid".to_owned(),
            )
        })?;
        let phase: String = row.get(1)?;
        let present: i64 = row.get(2)?;
        let finalize_sequence_present: bool = row.get(3)?;
        let terminal_present: bool = row.get(4)?;
        let audit_present: bool = row.get(5)?;
        let encoded_bytes: i64 = row.get(6)?;
        let future_reserved_bytes: i64 = row.get(7)?;
        let expected_encoded = termination_finalize_encoded_len(
            operation_len,
            present,
            finalize_sequence_present,
            terminal_present,
            audit_present,
        )?;
        let expected_future = if phase == "finalized" {
            if audit_present {
                0
            } else {
                AUDIT_CHECKPOINT_BYTES
            }
        } else {
            TERMINATION_FINALIZE_TOTAL_BYTES - expected_encoded
        };
        if encoded_bytes != expected_encoded || future_reserved_bytes != expected_future {
            return Err(ObservationProviderError::RecoveryRequired(
                "termination finalization canonical byte accounting mismatch".to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_carrier_migration_rows(conn: &Connection) -> Result<(), ObservationProviderError> {
    let invalid_header: i64 = conn.query_row(
        "SELECT COUNT(*) FROM observation_carrier_migrations
         WHERE migration_id=zeroblob(16) OR registry_instance_id=zeroblob(16)
            OR m019_ledger_instance_id=zeroblob(16)
            OR source_m019_head=zeroblob(32)
            OR source_m019_state_root=zeroblob(32)
            OR target_m019_head=zeroblob(32)
            OR target_m019_state_root=zeroblob(32)
            OR sqlite_store_instance_digest=zeroblob(32)
            OR sqlite_source_root=zeroblob(32) OR sqlite_target_root=zeroblob(32)
            OR jsonl_store_instance_digest=zeroblob(32)
            OR jsonl_source_inventory_root=zeroblob(32)
            OR jsonl_target_inventory_root=zeroblob(32)
            OR frozen_row_set_digest=zeroblob(32)
            OR owner_plan_digest=zeroblob(32)
            OR freeze_receipt_digest=zeroblob(32)
            OR planned_row_count>?1
            OR actual_encoded_bytes+future_reserved_bytes>?2",
        params![
            MAX_CARRIER_MIGRATION_ROWS as i64,
            MAX_CARRIER_MIGRATION_COMBINED_BYTES as i64,
        ],
        |row| row.get(0),
    )?;
    let invalid_row: i64 = conn.query_row(
        "SELECT COUNT(*) FROM observation_carrier_migration_rows
         WHERE event_key_digest=zeroblob(32)
            OR event_cursor_digest=zeroblob(32)
            OR receipt_nonce=zeroblob(32)
            OR owner_intent_digest=zeroblob(32)
            OR owner_preimage_digest=zeroblob(32)
            OR owner_postimage_digest=zeroblob(32)
            OR (phase='finalized' AND owner_commit_receipt_digest=zeroblob(32))",
        [],
        |row| row.get(0),
    )?;
    if invalid_header != 0 || invalid_row != 0 {
        return Err(ObservationProviderError::RecoveryRequired(
            "carrier-migration header/row contains a zero or over-cap binding".to_owned(),
        ));
    }

    let mut headers = conn.prepare(
        "SELECT migration_id,planned_row_count,issued_row_count,finalized_row_count,
                actual_encoded_bytes,future_reserved_bytes,phase
         FROM observation_carrier_migrations",
    )?;
    let mut rows = headers.query([])?;
    while let Some(header) = rows.next()? {
        let migration_id: Vec<u8> = header.get(0)?;
        let planned: i64 = header.get(1)?;
        let issued: i64 = header.get(2)?;
        let finalized: i64 = header.get(3)?;
        let actual: i64 = header.get(4)?;
        let future: i64 = header.get(5)?;
        let phase: String = header.get(6)?;
        let (row_count, finalized_count, encoded_sum): (i64, i64, i64) = conn.query_row(
            "SELECT COUNT(*),
                    COALESCE(SUM(CASE WHEN phase='finalized' THEN 1 ELSE 0 END),0),
                    COALESCE(SUM(encoded_bytes),0)
             FROM observation_carrier_migration_rows WHERE migration_id=?1",
            params![migration_id.as_slice()],
            |record| Ok((record.get(0)?, record.get(1)?, record.get(2)?)),
        )?;
        let expected_future = planned
            .checked_sub(issued)
            .and_then(|remaining| {
                remaining.checked_mul(CARRIER_MIGRATION_ROW_RESERVATION_BYTES as i64)
            })
            .ok_or_else(|| {
                ObservationProviderError::RecoveryRequired(
                    "carrier-migration reservation counter overflow".to_owned(),
                )
            })?;
        let phase_counts_valid = match phase.as_str() {
            "issuing" => planned > 0 && issued < planned && finalized < planned,
            "owner-ready" => planned > 0 && issued == planned && finalized < planned && future == 0,
            "verifying" => planned > 0 && issued == planned && finalized == planned && future == 0,
            "verified" => issued == planned && finalized == planned && future == 0,
            _ => false,
        };
        if row_count != issued
            || finalized_count != finalized
            || encoded_sum != actual
            || expected_future != future
            || !phase_counts_valid
        {
            return Err(ObservationProviderError::RecoveryRequired(
                "carrier-migration row/count/byte/phase invariant failed".to_owned(),
            ));
        }
    }
    drop(rows);
    drop(headers);

    let mut encoded_rows = conn.prepare(
        "SELECT length(legacy_receipt),phase,encoded_bytes
         FROM observation_carrier_migration_rows",
    )?;
    let mut rows = encoded_rows.query([])?;
    while let Some(row) = rows.next()? {
        let receipt_len = usize::try_from(row.get::<_, i64>(0)?).map_err(|_| {
            ObservationProviderError::RecoveryRequired(
                "carrier-migration receipt length is invalid".to_owned(),
            )
        })?;
        let phase: String = row.get(1)?;
        let encoded: i64 = row.get(2)?;
        let expected = carrier_migration_row_encoded_len(receipt_len, phase == "finalized")?;
        if !matches!(phase.as_str(), "prepared" | "finalized") || encoded != expected {
            return Err(ObservationProviderError::RecoveryRequired(
                "carrier-migration row canonical encoding mismatch".to_owned(),
            ));
        }
    }
    Ok(())
}

struct DurablePrevisibleRow {
    activation_nonce: Vec<u8>,
    operation_id: String,
    operation_kind: String,
    identity_id: String,
    identity_class: String,
    identity_incarnation: i64,
    declaration_digest: Vec<u8>,
    registry_sequence: i64,
    phase: String,
    role: i64,
    registry_instance: Vec<u8>,
    boot: Vec<u8>,
    subject_receipt: Option<Vec<u8>>,
    table_receipt: Option<Vec<u8>>,
    lifecycle_receipt: Option<Vec<u8>>,
    subject_absence: Option<Vec<u8>>,
    table_absence: Option<Vec<u8>>,
    lifecycle_absence: Option<Vec<u8>>,
    ready_nonce: Option<Vec<u8>>,
    abort_nonce: Option<Vec<u8>>,
    recovery_nonce: Option<Vec<u8>>,
}

enum DurablePrevisibleRecovery {
    Ready(ProviderActivationRecord, ReadyProofJournalMetadata),
    Publishing(ProviderActivationRecord, ReadyProofJournalMetadata),
    Aborting(ProviderActivationRecord, AbortProofJournalMetadata),
}

fn exact_previsible_array(
    bytes: Vec<u8>,
    field: &str,
) -> Result<[u8; 32], ObservationProviderError> {
    let value: [u8; 32] = bytes.try_into().map_err(|_| {
        ObservationProviderError::RecoveryRequired(format!(
            "durable previsible {field} has invalid width"
        ))
    })?;
    if value == [0; 32] {
        return Err(ObservationProviderError::RecoveryRequired(format!(
            "durable previsible {field} is zero"
        )));
    }
    Ok(value)
}

fn required_previsible_array(
    value: Option<Vec<u8>>,
    field: &str,
) -> Result<[u8; 32], ObservationProviderError> {
    exact_previsible_array(
        value.ok_or_else(|| {
            ObservationProviderError::RecoveryRequired(format!(
                "durable previsible {field} is missing"
            ))
        })?,
        field,
    )
}

fn load_durable_previsible_recovery(
    conn: &Connection,
    expected_registry_instance: [u8; 16],
    expected_boot: [u8; 16],
) -> Result<Option<DurablePrevisibleRecovery>, ObservationProviderError> {
    let row = conn
        .query_row(
            "SELECT activation_nonce,operation_id,operation_kind,identity_id,
                    identity_class,identity_incarnation,declaration_digest,
                    registry_sequence,phase,role,registry_instance_id,boot_id,
                    subject_receipt_digest,table_receipt_digest,
                    lifecycle_receipt_digest,subject_absence_digest,
                    table_absence_digest,lifecycle_absence_digest,
                    ready_proof_nonce,abort_proof_nonce,recovery_nonce
             FROM observation_previsible_activations
             WHERE phase IN ('ready','publishing','aborting')
             ORDER BY updated_sequence,activation_nonce LIMIT 1",
            [],
            |row| {
                Ok(DurablePrevisibleRow {
                    activation_nonce: row.get(0)?,
                    operation_id: row.get(1)?,
                    operation_kind: row.get(2)?,
                    identity_id: row.get(3)?,
                    identity_class: row.get(4)?,
                    identity_incarnation: row.get(5)?,
                    declaration_digest: row.get(6)?,
                    registry_sequence: row.get(7)?,
                    phase: row.get(8)?,
                    role: row.get(9)?,
                    registry_instance: row.get(10)?,
                    boot: row.get(11)?,
                    subject_receipt: row.get(12)?,
                    table_receipt: row.get(13)?,
                    lifecycle_receipt: row.get(14)?,
                    subject_absence: row.get(15)?,
                    table_absence: row.get(16)?,
                    lifecycle_absence: row.get(17)?,
                    ready_nonce: row.get(18)?,
                    abort_nonce: row.get(19)?,
                    recovery_nonce: row.get(20)?,
                })
            },
        )
        .optional()?;
    let Some(row) = row else {
        return Ok(None);
    };
    if row.registry_instance.as_slice() != expected_registry_instance.as_slice()
        || row.boot.as_slice() != expected_boot.as_slice()
    {
        return Err(ObservationProviderError::RecoveryRequired(
            "durable previsible row belongs to a different registry or boot".to_owned(),
        ));
    }
    let expected_class = class_from_sql(&row.identity_class)?;
    let (kind, expected_kind, expected_role) = match expected_class {
        ObservationIdentityClass::Component => (
            PrevisibleActivationKind::Component,
            "register-component",
            PrevisibleActivationKind::Component as i64,
        ),
        ObservationIdentityClass::Agent => (
            PrevisibleActivationKind::Agent,
            "register-agent",
            PrevisibleActivationKind::Agent as i64,
        ),
        ObservationIdentityClass::Host => {
            return Err(ObservationProviderError::RecoveryRequired(
                "host identity cannot own a previsible activation".to_owned(),
            ))
        }
    };
    if row.operation_kind != expected_kind || row.role != expected_role {
        return Err(ObservationProviderError::RecoveryRequired(
            "durable previsible role/class/kind projection mismatch".to_owned(),
        ));
    }
    let claims = read_identity_claims(conn, &row.identity_id)?.ok_or_else(|| {
        ObservationProviderError::RecoveryRequired(
            "durable previsible hidden identity is missing".to_owned(),
        )
    })?;
    if claims.expected_class != expected_class
        || i64::try_from(claims.incarnation).ok() != Some(row.identity_incarnation)
        || claims.declaration_digest.as_bytes().as_slice() != row.declaration_digest.as_slice()
    {
        return Err(ObservationProviderError::RecoveryRequired(
            "durable previsible identity claims mismatch".to_owned(),
        ));
    }
    let activation_nonce = exact_previsible_array(row.activation_nonce, "activation nonce")?;
    let registry_sequence = u64::try_from(row.registry_sequence)
        .ok()
        .filter(|sequence| *sequence != 0)
        .ok_or_else(|| {
            ObservationProviderError::RecoveryRequired(
                "durable previsible registry sequence is invalid".to_owned(),
            )
        })?;
    let record = ProviderActivationRecord {
        kind,
        activation_nonce,
        operation_id: row.operation_id,
        claims,
        registry_sequence,
    };
    match row.phase.as_str() {
        "ready" | "publishing" => {
            let metadata = ReadyProofJournalMetadata {
                subject_receipt_digest: required_previsible_array(
                    row.subject_receipt,
                    "subject receipt digest",
                )?,
                table_receipt_digest: required_previsible_array(
                    row.table_receipt,
                    "table receipt digest",
                )?,
                lifecycle_receipt_digest: required_previsible_array(
                    row.lifecycle_receipt,
                    "lifecycle receipt digest",
                )?,
                proof_nonce: required_previsible_array(row.ready_nonce, "Ready proof nonce")?,
                recovery_nonce: required_previsible_array(
                    row.recovery_nonce,
                    "publication recovery nonce",
                )?,
            };
            Ok(Some(if row.phase == "ready" {
                DurablePrevisibleRecovery::Ready(record, metadata)
            } else {
                DurablePrevisibleRecovery::Publishing(record, metadata)
            }))
        }
        "aborting" => Ok(Some(DurablePrevisibleRecovery::Aborting(
            record,
            AbortProofJournalMetadata {
                subject_absence_digest: required_previsible_array(
                    row.subject_absence,
                    "subject absence digest",
                )?,
                table_absence_digest: required_previsible_array(
                    row.table_absence,
                    "table absence digest",
                )?,
                lifecycle_absence_digest: required_previsible_array(
                    row.lifecycle_absence,
                    "lifecycle absence digest",
                )?,
                proof_nonce: required_previsible_array(row.abort_nonce, "Abort proof nonce")?,
                recovery_nonce: required_previsible_array(
                    row.recovery_nonce,
                    "abort recovery nonce",
                )?,
            },
        ))),
        _ => Err(ObservationProviderError::RecoveryRequired(
            "unknown durable previsible recovery phase".to_owned(),
        )),
    }
}

fn recover_durable_inflight_rows(
    conn: &mut Connection,
    db_path: &std::path::Path,
    anchor: &dyn RegistryAnchorTransaction,
    expected_registry_instance: [u8; 16],
    expected_boot: [u8; 16],
) -> Result<(), ObservationProviderError> {
    loop {
        let Some(recovery) =
            load_durable_previsible_recovery(conn, expected_registry_instance, expected_boot)?
        else {
            return Ok(());
        };
        match recovery {
            DurablePrevisibleRecovery::Ready(record, metadata) => {
                let discriminator = record.activation_nonce;
                run_anchored_mutation_on_connection(
                    conn,
                    db_path,
                    anchor,
                    3,
                    &discriminator,
                    #[cfg(any(test, feature = "test-support"))]
                    None,
                    move |transaction| mark_previsible_publishing(transaction, &record, &metadata),
                )?;
            }
            DurablePrevisibleRecovery::Publishing(record, metadata) => {
                let discriminator = record.activation_nonce;
                run_anchored_mutation_on_connection(
                    conn,
                    db_path,
                    anchor,
                    3,
                    &discriminator,
                    #[cfg(any(test, feature = "test-support"))]
                    None,
                    move |transaction| {
                        complete_previsible_publication(transaction, &record, &metadata)
                    },
                )?;
            }
            DurablePrevisibleRecovery::Aborting(record, metadata) => {
                let discriminator = record.activation_nonce;
                run_anchored_mutation_on_connection(
                    conn,
                    db_path,
                    anchor,
                    3,
                    &discriminator,
                    #[cfg(any(test, feature = "test-support"))]
                    None,
                    move |transaction| complete_previsible_abort(transaction, &record, &metadata),
                )?;
            }
        }
    }
}

fn verify_keyring_configuration(
    conn: &Connection,
    config: &ObservationProviderConfig,
    projection: &PersistedKeyringProjection,
) -> Result<(), ObservationProviderError> {
    verify_keyring_projection(conn, projection)?;
    let configured = projection.entries.iter().find(|entry| {
        entry.key_id == config.signing_key_id
            && entry.status == PersistedKeyringStatus::Signing
            && entry.master_key_epoch == config.master_key_epoch
    });
    if configured.is_none() || projection.manifest_key_epoch != config.registry_manifest_key_epoch {
        return Err(ObservationProviderError::RecoveryRequired(
            "persisted keyring does not name the configured signing key/epoch".to_owned(),
        ));
    }
    Ok(())
}

fn apply_keyring_projection(
    conn: &Connection,
    projection: &PersistedKeyringProjection,
) -> Result<(), ObservationProviderError> {
    let signing_key_id = projection
        .entries
        .iter()
        .find(|entry| entry.status == PersistedKeyringStatus::Signing)
        .map(|entry| entry.key_id)
        .ok_or_else(|| {
            ObservationProviderError::RecoveryRequired(
                "authenticated keyring projection has no signing entry".to_owned(),
            )
        })?;

    // Avoid transiently violating the one-signing-key unique index while a
    // rotation inserts its newly allocated signing entry.
    conn.execute(
        "UPDATE observation_persisted_keyring_entries
         SET status='verify-only'
         WHERE status='signing' AND key_id<>?1",
        params![i64::from(signing_key_id)],
    )?;
    for entry in &projection.entries {
        let status = match entry.status {
            PersistedKeyringStatus::Signing => "signing",
            PersistedKeyringStatus::VerifyOnly => "verify-only",
            PersistedKeyringStatus::Retired => "retired",
        };
        let sqlite_scan_sequence = entry
            .scan
            .as_ref()
            .map(|scan| sqlite_i64(scan.sqlite_scan_sequence, "keyring scan sequence"))
            .transpose()?;
        let jsonl_inventory_digest = entry
            .scan
            .as_ref()
            .map(|scan| scan.jsonl_inventory_digest.as_slice());
        let jsonl_segment_count = entry
            .scan
            .as_ref()
            .map(|scan| sqlite_i64(scan.jsonl_segment_count, "JSONL segment count"))
            .transpose()?;
        let jsonl_byte_count = entry
            .scan
            .as_ref()
            .map(|scan| sqlite_i64(scan.jsonl_byte_count, "JSONL byte count"))
            .transpose()?;
        let retention_high_water_ms = entry
            .scan
            .as_ref()
            .map(|scan| sqlite_i64(scan.retention_high_water_ms, "retention high-water"))
            .transpose()?;
        conn.execute(
            "INSERT INTO observation_persisted_keyring_entries
                (key_id,status,master_key_epoch,last_issued_at_ms,
                 sqlite_scan_sequence,jsonl_inventory_digest,jsonl_segment_count,
                 jsonl_byte_count,retention_high_water_ms)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)
             ON CONFLICT(key_id) DO UPDATE SET
                status=excluded.status,
                master_key_epoch=excluded.master_key_epoch,
                last_issued_at_ms=excluded.last_issued_at_ms,
                sqlite_scan_sequence=excluded.sqlite_scan_sequence,
                jsonl_inventory_digest=excluded.jsonl_inventory_digest,
                jsonl_segment_count=excluded.jsonl_segment_count,
                jsonl_byte_count=excluded.jsonl_byte_count,
                retention_high_water_ms=excluded.retention_high_water_ms",
            params![
                i64::from(entry.key_id),
                status,
                i64::from(entry.master_key_epoch),
                sqlite_i64(entry.last_issued_at_ms, "last-issued time")?,
                sqlite_scan_sequence,
                jsonl_inventory_digest,
                jsonl_segment_count,
                jsonl_byte_count,
                retention_high_water_ms,
            ],
        )?;
    }
    Ok(())
}

fn verify_keyring_projection(
    conn: &Connection,
    expected: &PersistedKeyringProjection,
) -> Result<(), ObservationProviderError> {
    let mut statement = conn.prepare(
        "SELECT key_id,status,master_key_epoch,last_issued_at_ms,
                sqlite_scan_sequence,jsonl_inventory_digest,jsonl_segment_count,
                jsonl_byte_count,retention_high_water_ms
         FROM observation_persisted_keyring_entries ORDER BY key_id",
    )?;
    let mut rows = statement.query([])?;
    let mut observed = Vec::new();
    while let Some(row) = rows.next()? {
        let key_id = sqlite_u32(row.get::<_, i64>(0)?, "key id")?;
        let status = match row.get::<_, String>(1)?.as_str() {
            "signing" => PersistedKeyringStatus::Signing,
            "verify-only" => PersistedKeyringStatus::VerifyOnly,
            "retired" => PersistedKeyringStatus::Retired,
            _ => {
                return Err(ObservationProviderError::RecoveryRequired(
                    "unknown persisted keyring status".to_owned(),
                ))
            }
        };
        let master_key_epoch = sqlite_u32(row.get::<_, i64>(2)?, "master-key epoch")?;
        let last_issued_at_ms = sqlite_u64(row.get::<_, i64>(3)?, "last-issued time")?;
        let sqlite_scan_sequence = row.get::<_, Option<i64>>(4)?;
        let jsonl_inventory_digest = row.get::<_, Option<Vec<u8>>>(5)?;
        let jsonl_segment_count = row.get::<_, Option<i64>>(6)?;
        let jsonl_byte_count = row.get::<_, Option<i64>>(7)?;
        let retention_high_water_ms = row.get::<_, Option<i64>>(8)?;
        let scan = match (
            sqlite_scan_sequence,
            jsonl_inventory_digest,
            jsonl_segment_count,
            jsonl_byte_count,
            retention_high_water_ms,
        ) {
            (None, None, None, None, None) => None,
            (Some(sequence), Some(digest), Some(segments), Some(bytes), Some(retention)) => {
                Some(crate::observation_anchor::PersistedKeyringScanProjection {
                    sqlite_scan_sequence: sqlite_u64(sequence, "keyring scan sequence")?,
                    jsonl_inventory_digest: fixed::<32>(digest, "JSONL inventory digest")?,
                    jsonl_segment_count: sqlite_u64(segments, "JSONL segment count")?,
                    jsonl_byte_count: sqlite_u64(bytes, "JSONL byte count")?,
                    retention_high_water_ms: sqlite_u64(retention, "retention high-water")?,
                })
            }
            _ => {
                return Err(ObservationProviderError::RecoveryRequired(
                    "persisted keyring scan projection is partial".to_owned(),
                ))
            }
        };
        observed.push(PersistedKeyringEntryProjection {
            key_id,
            status,
            master_key_epoch,
            last_issued_at_ms,
            scan,
        });
    }
    if observed != expected.entries {
        return Err(ObservationProviderError::RecoveryRequired(
            "SQLite keyring projection differs from authenticated complete file".to_owned(),
        ));
    }
    Ok(())
}

fn sqlite_i64(value: u64, label: &str) -> Result<i64, ObservationProviderError> {
    i64::try_from(value).map_err(|_| {
        ObservationProviderError::CapacityExceeded(format!("{label} exceeds SQLite range"))
    })
}

fn sqlite_u64(value: i64, label: &str) -> Result<u64, ObservationProviderError> {
    u64::try_from(value).map_err(|_| {
        ObservationProviderError::RecoveryRequired(format!("negative {label} in SQLite"))
    })
}

fn sqlite_u32(value: i64, label: &str) -> Result<u32, ObservationProviderError> {
    u32::try_from(value).map_err(|_| {
        ObservationProviderError::RecoveryRequired(format!(
            "{label} is outside canonical u32 range"
        ))
    })
}

fn enforce_persisted_capacity(conn: &Connection) -> Result<(), ObservationProviderError> {
    let identities: i64 =
        conn.query_row("SELECT COUNT(*) FROM observation_identities", [], |row| {
            row.get(0)
        })?;
    let authority: i64 = conn.query_row(
        "SELECT COUNT(*) FROM observation_identity_authority",
        [],
        |row| row.get(0),
    )?;
    let active: i64 = conn.query_row(
        "SELECT COUNT(*) FROM observation_identity_operations WHERE is_active=1",
        [],
        |row| row.get(0),
    )?;
    let operations: i64 = conn.query_row(
        "SELECT COUNT(*) FROM observation_identity_operations",
        [],
        |row| row.get(0),
    )?;
    let members: i64 = conn.query_row(
        "SELECT COUNT(*) FROM observation_identity_operation_members",
        [],
        |row| row.get(0),
    )?;
    if identities > MAX_LIVE_RETAINED_IDENTITIES as i64
        || authority > MAX_AUTHORITY_ROWS as i64
        || active > MAX_ACTIVE_IDENTITY_OPERATIONS as i64
        || operations > MAX_COMMITTED_IDENTITY_OPERATIONS as i64
        || members > MAX_COMMITTED_IDENTITY_MEMBERS as i64
    {
        return Err(ObservationProviderError::RecoveryRequired(
            "persisted observation capacity exceeds configured hard bounds".to_owned(),
        ));
    }
    Ok(())
}

fn reconcile_external_anchor(
    anchor: &dyn RegistryAnchorTransaction,
    ledger: &RegistryAnchorTuple,
) -> Result<(), ObservationProviderError> {
    let observed = anchor.observe()?;
    let capability =
        RegistryRecoveryCapability::from_durable_reread(anchor, observed, ledger.clone())?;
    anchor.recover(capability)?;
    let settled = anchor.observe()?;
    match settled {
        RegistryAnchorWorld::CompactCurrent { current, .. } if current == *ledger => Ok(()),
        _ => Err(ObservationProviderError::RecoveryRequired(
            "anchor recovery did not settle on the SQLite ledger tuple".to_owned(),
        )),
    }
}

fn read_ledger(conn: &Connection) -> Result<Option<RegistryAnchorTuple>, ObservationProviderError> {
    let row = conn
        .query_row(
            "SELECT registry_instance_id,committed_sequence,committed_head_digest,
                    committed_state_root,committed_keyring_root,
                    committed_role_allocation_root,migration_digest
             FROM observation_identity_ledger WHERE singleton=1",
            [],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                ))
            },
        )
        .optional()?;
    let Some((instance, sequence, head, state, keyring, role, migration)) = row else {
        return Ok(None);
    };
    Ok(Some(RegistryAnchorTuple {
        registry_instance: fixed::<16>(instance, "registry instance")?,
        sequence: u64::try_from(sequence).map_err(|_| {
            ObservationProviderError::RecoveryRequired("negative registry sequence".to_owned())
        })?,
        head: fixed::<32>(head, "registry head")?,
        state_root: fixed::<32>(state, "registry state root")?,
        keyring_root: fixed::<32>(keyring, "keyring root")?,
        role_allocation_root: fixed::<32>(role, "role allocation root")?,
        migration_digest: fixed::<32>(migration, "migration digest")?,
    }))
}

fn write_ledger(
    conn: &Connection,
    tuple: &RegistryAnchorTuple,
) -> Result<(), ObservationProviderError> {
    conn.execute(
        "INSERT INTO observation_identity_ledger
            (singleton,registry_instance_id,committed_sequence,committed_head_digest,
             committed_state_root,committed_keyring_root,
             committed_role_allocation_root,migration_digest)
         VALUES (1,?1,?2,?3,?4,?5,?6,?7)
         ON CONFLICT(singleton) DO UPDATE SET
            registry_instance_id=excluded.registry_instance_id,
            committed_sequence=excluded.committed_sequence,
            committed_head_digest=excluded.committed_head_digest,
            committed_state_root=excluded.committed_state_root,
            committed_keyring_root=excluded.committed_keyring_root,
            committed_role_allocation_root=excluded.committed_role_allocation_root,
            migration_digest=excluded.migration_digest",
        params![
            tuple.registry_instance.as_slice(),
            i64::try_from(tuple.sequence).map_err(|_| {
                ObservationProviderError::CapacityExceeded(
                    "registry sequence exceeds SQLite range".to_owned(),
                )
            })?,
            tuple.head.as_slice(),
            tuple.state_root.as_slice(),
            tuple.keyring_root.as_slice(),
            tuple.role_allocation_root.as_slice(),
            tuple.migration_digest.as_slice(),
        ],
    )?;
    Ok(())
}

fn read_head_context(conn: &Connection) -> Result<RegistryHeadContext, ObservationProviderError> {
    let row: Option<(Vec<u8>, i64)> = conn
        .query_row(
            "SELECT current_marker_root,current_manifest_key_epoch
             FROM observation_registry_head_context WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let (marker, epoch) = row.ok_or_else(|| {
        ObservationProviderError::RecoveryRequired(
            "durable registry head context is missing".to_owned(),
        )
    })?;
    let epoch = u32::try_from(epoch).map_err(|_| {
        ObservationProviderError::RecoveryRequired(
            "durable manifest key epoch is outside u32".to_owned(),
        )
    })?;
    RegistryHeadContext::unchanged(fixed::<32>(marker, "marker root")?, epoch)
        .map_err(ObservationProviderError::from)
}

fn write_head_context(
    conn: &Connection,
    marker_root: [u8; 32],
    manifest_key_epoch: u32,
) -> Result<(), ObservationProviderError> {
    RegistryHeadContext::unchanged(marker_root, manifest_key_epoch)?;
    conn.execute(
        "INSERT INTO observation_registry_head_context
            (singleton,current_marker_root,current_manifest_key_epoch)
         VALUES (1,?1,?2)
         ON CONFLICT(singleton) DO UPDATE SET
            current_marker_root=excluded.current_marker_root,
            current_manifest_key_epoch=excluded.current_manifest_key_epoch",
        params![marker_root.as_slice(), i64::from(manifest_key_epoch)],
    )?;
    Ok(())
}

fn verify_complete_roots(
    conn: &Connection,
    ledger: &RegistryAnchorTuple,
) -> Result<(), ObservationProviderError> {
    let state_root = compute_state_root(conn)?;
    if state_root != ledger.state_root {
        return Err(ObservationProviderError::RecoveryRequired(
            "full SQLite state-root scan disagrees with the anchored ledger".to_owned(),
        ));
    }
    Ok(())
}

fn compute_state_root(conn: &Connection) -> Result<[u8; 32], ObservationProviderError> {
    let snapshot = capture_registry_snapshot(conn).map_err(codec_error)?;
    canonical_state_root(&snapshot).map_err(codec_error)
}

fn encode_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), ObservationProviderError> {
    let len = u32::try_from(bytes.len()).map_err(|_| {
        ObservationProviderError::CapacityExceeded("canonical row field".to_owned())
    })?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

fn encode_text(out: &mut Vec<u8>, text: &str) -> Result<(), ObservationProviderError> {
    encode_bytes(out, text.as_bytes())
}

fn genesis_head(
    instance: [u8; 16],
    state_root: [u8; 32],
    keyring_root: [u8; 32],
    role_root: [u8; 32],
    migration_digest: [u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(GENESIS_DOMAIN);
    hasher.update(instance);
    hasher.update(state_root);
    hasher.update(keyring_root);
    hasher.update(role_root);
    hasher.update(migration_digest);
    hasher.finalize().into()
}

fn codec_error(error: String) -> ObservationProviderError {
    ObservationProviderError::RecoveryRequired(format!(
        "canonical registry codec rejected durable state: {error}"
    ))
}

fn fixed<const N: usize>(value: Vec<u8>, label: &str) -> Result<[u8; N], ObservationProviderError> {
    value
        .try_into()
        .map_err(|_| ObservationProviderError::RecoveryRequired(format!("invalid {label} width")))
}

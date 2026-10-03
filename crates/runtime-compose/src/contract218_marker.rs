//! Authenticated external custody for the one-time CONTRACT-218 legacy marker.
//!
//! The retained artifact is always the exact 298-byte canonical marker.  The
//! host-master key stays inside persisted-keyring custody, while scheduler code
//! receives only [`PreparedLegacyRegistryMigration`], whose constructor parses
//! the exact block and target artifact roots. A private authenticated sidecar
//! binds the complete Prepared/Installed/Complete byte plan before any opaque
//! scheduler artifact can leave custody, so crash recovery never re-mints a
//! future phase nonce.

use crate::contract218_anchor::{
    secure_create_new_regular, secure_open_regular, secure_regular_exists, secure_remove_regular,
    secure_replace_regular, FilePlatformMonotonicAnchorStore, SharedMarkerCustodyClaim,
};
use crate::contract218_keyring::FilePersistedIdentityKeyringCustody;
use crate::contract218_roles::FileContract218RoleRootCustody;
use advance_scheduler::observation_anchor::{
    prepare_legacy_registry_migration, PreparedLegacyMarkerMutation,
    PreparedLegacyRegistryMigration, RegistryAnchorError, RegistryAnchorTuple,
};
use advance_scheduler::sensitive_params::{
    VerifiedLegacyAnchorInstalled, VerifiedLegacyMarkerTransitionCommitted,
    VerifiedLegacyMigrationComplete,
};
use rand::rngs::OsRng;
use rand::RngCore;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use subtle::ConstantTimeEq;
use thiserror::Error;

const CURRENT_FILE: &str = "contract218.migration-marker.current";
const PENDING_FILE: &str = "contract218.migration-marker.pending";
const PLAN_FILE: &str = "contract218.migration-marker.plan";
const MARKER_VERSION: u8 = 1;
const BLOCK_LEN: usize = 228;
const MARKER_PRECEDING_LEN: usize = 266;
const MARKER_LEN: usize = 298;
const PLAN_VERSION: u8 = 1;
const PLAN_PAYLOAD_LEN: usize = 1 + (3 * MARKER_LEN);
const PLAN_LEN: usize = PLAN_PAYLOAD_LEN + 32;
const PLAN_MAC_DOMAIN: &[u8] = b"advance.contract218.registry-migration-marker-plan.v1\0";

/// Trusted composition-root proof of both the live exclusive RuntimeLock and
/// the local platform principal named by the immutable migration block.
///
/// The custody owner passes only the digest already present in the block.  It
/// never accepts a caller-reported boolean or alternate operator digest.
pub trait LegacyMigrationOperatorAuthority: Send + Sync {
    fn verify_exclusive_runtime_and_operator(
        &self,
        workspace_root: &Path,
        registry_instance: [u8; 16],
        operator_principal_digest: [u8; 32],
    ) -> Result<(), String>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum LegacyMigrationMarkerPhase {
    Prepared = 1,
    Installed = 2,
    Complete = 3,
}

impl LegacyMigrationMarkerPhase {
    fn parse(value: u8) -> Result<Self, LegacyMigrationMarkerError> {
        match value {
            1 => Ok(Self::Prepared),
            2 => Ok(Self::Installed),
            3 => Ok(Self::Complete),
            _ => Err(LegacyMigrationMarkerError::AuthenticationFailed),
        }
    }

    fn successor(self) -> Option<Self> {
        match self {
            Self::Prepared => Some(Self::Installed),
            Self::Installed => Some(Self::Complete),
            Self::Complete => None,
        }
    }
}

#[cfg(feature = "test-support")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LegacyMigrationMarkerRecovery {
    Clean,
    RolledBackPending,
    PromotedPending,
}

#[cfg(feature = "test-support")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LegacyMigrationMarkerFailpoint {
    AfterPlanTemporaryFsync,
    AfterPlanFsync,
    AfterCurrentTemporaryFsync,
    AfterPendingTemporaryFsync,
    AfterPendingFsync,
    BeforePendingPromotion,
}

#[derive(Debug, Error)]
pub enum LegacyMigrationMarkerError {
    #[error("legacy-migration marker I/O failed: {0}")]
    Io(String),
    #[error("legacy-migration marker authentication failed")]
    AuthenticationFailed,
    #[error("legacy-migration marker requires operator recovery: {0}")]
    RecoveryRequired(String),
    #[error("legacy-migration operator authorization failed: {0}")]
    Unauthorized(String),
    #[error("invalid legacy-migration marker input: {0}")]
    Invalid(String),
    #[cfg(feature = "test-support")]
    #[error("legacy-migration marker failpoint: {0:?}")]
    Failpoint(LegacyMigrationMarkerFailpoint),
}

#[derive(Clone)]
pub struct FileLegacyMigrationMarkerCustody {
    inner: Arc<MarkerInner>,
}

struct MarkerInner {
    directory: PathBuf,
    workspace: PathBuf,
    anchor: FilePlatformMonotonicAnchorStore,
    keyring: FilePersistedIdentityKeyringCustody,
    roles: FileContract218RoleRootCustody,
    authority: Arc<dyn LegacyMigrationOperatorAuthority>,
    _exclusive_custody: SharedMarkerCustodyClaim,
    writer: Mutex<()>,
    #[cfg(feature = "test-support")]
    failpoint: Mutex<Option<LegacyMigrationMarkerFailpoint>>,
}

/// Exact authenticated marker plan retained across every migration typestate.
/// The scheduler artifact clone is deliberately private: phase witnesses are
/// always verified against these same bytes, even after the one public
/// scheduler artifact has been consumed.
struct LegacyMigrationPlanCore {
    inner: Arc<MarkerInner>,
    block: [u8; BLOCK_LEN],
    manifest_key_epoch: u32,
    prepared: [u8; MARKER_LEN],
    installed: [u8; MARKER_LEN],
    complete: [u8; MARKER_LEN],
    retained_scheduler_artifacts: PreparedLegacyRegistryMigration,
}

/// Move-only Prepared typestate.  It is the only state that can release the
/// initial scheduler migration artifact or stage Prepared→Installed.
pub struct AuthenticatedLegacyMigrationPlan {
    core: LegacyMigrationPlanCore,
    scheduler_artifacts: Option<PreparedLegacyRegistryMigration>,
}

/// Move-only Installed typestate.  Complete cannot be staged from Prepared.
pub struct InstalledLegacyMigrationPlan {
    core: LegacyMigrationPlanCore,
}

/// Terminal move-only Complete typestate.
pub struct CompleteLegacyMigrationPlan {
    core: LegacyMigrationPlanCore,
}

/// Prepared→Installed has written the exact authenticated pending marker and
/// released one opaque scheduler mutation.  Only a matching scheduler commit
/// witness can finalize the owner rename.
pub struct StagedLegacyInstalledTransition {
    core: LegacyMigrationPlanCore,
    scheduler_transition: Option<PreparedLegacyMarkerMutation>,
    expected_next: RegistryAnchorTuple,
}

/// Installed→Complete has written the exact authenticated pending marker and
/// released one opaque scheduler mutation.  Carrier completion alone cannot
/// rename it; the subsequent scheduler commit witness is also mandatory.
pub struct StagedLegacyCompleteTransition {
    core: LegacyMigrationPlanCore,
    scheduler_transition: Option<PreparedLegacyMarkerMutation>,
    expected_next: RegistryAnchorTuple,
}

/// Restart reconstruction of a durable Prepared/current + Installed/pending
/// pair. It exposes only the exact opaque migration plan needed by M014's
/// committed-transition recovery API.
pub struct RecoverableLegacyInstalledTransition {
    core: LegacyMigrationPlanCore,
}

/// Restart reconstruction of a durable Installed/current + Complete/pending
/// pair. It exposes only the exact opaque migration plan needed by M014's
/// committed-transition recovery API.
pub struct RecoverableLegacyCompleteTransition {
    core: LegacyMigrationPlanCore,
}

impl std::fmt::Debug for AuthenticatedLegacyMigrationPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuthenticatedLegacyMigrationPlan(<opaque>)")
    }
}

impl std::fmt::Debug for InstalledLegacyMigrationPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("InstalledLegacyMigrationPlan(<opaque>)")
    }
}

impl std::fmt::Debug for CompleteLegacyMigrationPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CompleteLegacyMigrationPlan(<opaque>)")
    }
}

impl std::fmt::Debug for StagedLegacyInstalledTransition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StagedLegacyInstalledTransition(<opaque>)")
    }
}

impl std::fmt::Debug for StagedLegacyCompleteTransition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StagedLegacyCompleteTransition(<opaque>)")
    }
}

impl std::fmt::Debug for RecoverableLegacyInstalledTransition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecoverableLegacyInstalledTransition(<opaque>)")
    }
}

impl std::fmt::Debug for RecoverableLegacyCompleteTransition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecoverableLegacyCompleteTransition(<opaque>)")
    }
}

impl AuthenticatedLegacyMigrationPlan {
    pub fn take_scheduler_artifacts(
        &mut self,
    ) -> Result<PreparedLegacyRegistryMigration, LegacyMigrationMarkerError> {
        self.scheduler_artifacts.take().ok_or_else(|| {
            LegacyMigrationMarkerError::Invalid(
                "scheduler migration artifacts were already consumed".to_owned(),
            )
        })
    }

    /// Stage the exact Prepared→Installed owner artifact only after M014 has
    /// proved the target database and external anchor are durably installed.
    /// The current marker remains Prepared until [`Self::stage_installed`]'s
    /// result receives a matching scheduler commit witness.
    pub fn stage_installed(
        self,
        installed: VerifiedLegacyAnchorInstalled,
    ) -> Result<StagedLegacyInstalledTransition, LegacyMigrationMarkerError> {
        let core = self.core;
        installed
            .verify_for(&core.retained_scheduler_artifacts)
            .map_err(marker_anchor_error)?;
        core.inner.stage_exact(
            &core.block,
            core.manifest_key_epoch,
            &core.prepared,
            &core.installed,
            LegacyMigrationMarkerPhase::Prepared,
            LegacyMigrationMarkerPhase::Installed,
        )?;
        let scheduler_transition = match installed.prepare_installed_marker_transition(
            &core.inner.anchor,
            &core.retained_scheduler_artifacts,
        ) {
            Ok(transition) => transition,
            Err(error) => {
                core.inner.rollback_exact_pending(&core.installed)?;
                return Err(marker_anchor_error(error));
            }
        };
        let expected_next = scheduler_transition.next().clone();
        Ok(StagedLegacyInstalledTransition {
            core,
            scheduler_transition: Some(scheduler_transition),
            expected_next,
        })
    }

    #[cfg(feature = "test-support")]
    pub fn promote_installed_for_test(&self) -> Result<(), LegacyMigrationMarkerError> {
        self.core.inner.transition_exact_for_test(
            &self.core.block,
            self.core.manifest_key_epoch,
            &self.core.prepared,
            &self.core.installed,
            LegacyMigrationMarkerPhase::Prepared,
            LegacyMigrationMarkerPhase::Installed,
        )
    }

    #[cfg(feature = "test-support")]
    pub fn promote_complete_for_test(&self) -> Result<(), LegacyMigrationMarkerError> {
        self.core.inner.transition_exact_for_test(
            &self.core.block,
            self.core.manifest_key_epoch,
            &self.core.installed,
            &self.core.complete,
            LegacyMigrationMarkerPhase::Installed,
            LegacyMigrationMarkerPhase::Complete,
        )
    }
}

impl InstalledLegacyMigrationPlan {
    pub fn marker_root(&self) -> [u8; 32] {
        self.core
            .retained_scheduler_artifacts
            .installed_marker_root()
    }

    /// Stage Installed→Complete only after the scheduler has verified the
    /// complete carrier migration.  A second, later tag-13 commit witness is
    /// still required before the marker owner publishes Complete.
    pub fn stage_complete(
        self,
        complete: VerifiedLegacyMigrationComplete,
    ) -> Result<StagedLegacyCompleteTransition, LegacyMigrationMarkerError> {
        let core = self.core;
        complete
            .verify_for(&core.retained_scheduler_artifacts)
            .map_err(marker_anchor_error)?;
        core.inner.stage_exact(
            &core.block,
            core.manifest_key_epoch,
            &core.installed,
            &core.complete,
            LegacyMigrationMarkerPhase::Installed,
            LegacyMigrationMarkerPhase::Complete,
        )?;
        let scheduler_transition = match complete.prepare_complete_marker_transition(
            &core.inner.anchor,
            &core.retained_scheduler_artifacts,
        ) {
            Ok(transition) => transition,
            Err(error) => {
                core.inner.rollback_exact_pending(&core.complete)?;
                return Err(marker_anchor_error(error));
            }
        };
        let expected_next = scheduler_transition.next().clone();
        Ok(StagedLegacyCompleteTransition {
            core,
            scheduler_transition: Some(scheduler_transition),
            expected_next,
        })
    }
}

impl CompleteLegacyMigrationPlan {
    pub fn marker_root(&self) -> [u8; 32] {
        self.core
            .retained_scheduler_artifacts
            .complete_marker_root()
    }
}

impl StagedLegacyInstalledTransition {
    /// Move the one scheduler-owned mutation out exactly once.
    pub fn take_scheduler_transition(
        &mut self,
    ) -> Result<PreparedLegacyMarkerMutation, LegacyMigrationMarkerError> {
        self.scheduler_transition.take().ok_or_else(|| {
            LegacyMigrationMarkerError::Invalid(
                "Installed scheduler transition was already consumed".to_owned(),
            )
        })
    }

    /// Publish Installed only after the exact staged mutation committed.
    pub fn finish_installed(
        self,
        committed: VerifiedLegacyMarkerTransitionCommitted,
    ) -> Result<InstalledLegacyMigrationPlan, LegacyMigrationMarkerError> {
        if self.scheduler_transition.is_some() {
            return Err(LegacyMigrationMarkerError::Invalid(
                "Installed scheduler transition must be consumed before commit acknowledgement"
                    .to_owned(),
            ));
        }
        let observed = committed
            .verify_installed_for(&self.core.retained_scheduler_artifacts)
            .map_err(marker_anchor_error)?;
        if observed != &self.expected_next {
            return Err(LegacyMigrationMarkerError::AuthenticationFailed);
        }
        committed
            .verify_anchor_lease(&self.core.inner.anchor)
            .map_err(marker_anchor_error)?;
        self.core.inner.promote_staged_exact(
            &self.core.block,
            self.core.manifest_key_epoch,
            &self.core.prepared,
            &self.core.installed,
            LegacyMigrationMarkerPhase::Prepared,
            LegacyMigrationMarkerPhase::Installed,
            Some(observed),
        )?;
        Ok(InstalledLegacyMigrationPlan { core: self.core })
    }
}

impl StagedLegacyCompleteTransition {
    /// Move the one scheduler-owned mutation out exactly once.
    pub fn take_scheduler_transition(
        &mut self,
    ) -> Result<PreparedLegacyMarkerMutation, LegacyMigrationMarkerError> {
        self.scheduler_transition.take().ok_or_else(|| {
            LegacyMigrationMarkerError::Invalid(
                "Complete scheduler transition was already consumed".to_owned(),
            )
        })
    }

    /// Publish Complete only after the exact staged mutation committed.
    pub fn finish_complete(
        self,
        committed: VerifiedLegacyMarkerTransitionCommitted,
    ) -> Result<CompleteLegacyMigrationPlan, LegacyMigrationMarkerError> {
        if self.scheduler_transition.is_some() {
            return Err(LegacyMigrationMarkerError::Invalid(
                "Complete scheduler transition must be consumed before commit acknowledgement"
                    .to_owned(),
            ));
        }
        let observed = committed
            .verify_complete_for(&self.core.retained_scheduler_artifacts)
            .map_err(marker_anchor_error)?;
        if observed != &self.expected_next {
            return Err(LegacyMigrationMarkerError::AuthenticationFailed);
        }
        committed
            .verify_anchor_lease(&self.core.inner.anchor)
            .map_err(marker_anchor_error)?;
        self.core.inner.promote_staged_exact(
            &self.core.block,
            self.core.manifest_key_epoch,
            &self.core.installed,
            &self.core.complete,
            LegacyMigrationMarkerPhase::Installed,
            LegacyMigrationMarkerPhase::Complete,
            Some(observed),
        )?;
        Ok(CompleteLegacyMigrationPlan { core: self.core })
    }
}

impl RecoverableLegacyInstalledTransition {
    /// Borrow the exact plan for
    /// `RegistrySensitiveParamProvider::recover_legacy_installed_marker_transition`.
    pub fn scheduler_recovery_artifacts(&self) -> &PreparedLegacyRegistryMigration {
        &self.core.retained_scheduler_artifacts
    }

    /// Re-derive the exact opaque mutation when the scheduler proves the
    /// migration is still at its precommit Installed boundary. If the anchor
    /// already contains the postimage this fails closed; use M014's committed
    /// recovery API and [`Self::finish_installed`] instead.
    pub fn restage_installed(
        self,
        installed: VerifiedLegacyAnchorInstalled,
    ) -> Result<StagedLegacyInstalledTransition, LegacyMigrationMarkerError> {
        let scheduler_transition = installed
            .prepare_installed_marker_transition(
                &self.core.inner.anchor,
                &self.core.retained_scheduler_artifacts,
            )
            .map_err(marker_anchor_error)?;
        let expected_next = scheduler_transition.next().clone();
        Ok(StagedLegacyInstalledTransition {
            core: self.core,
            scheduler_transition: Some(scheduler_transition),
            expected_next,
        })
    }

    pub fn finish_installed(
        self,
        committed: VerifiedLegacyMarkerTransitionCommitted,
    ) -> Result<InstalledLegacyMigrationPlan, LegacyMigrationMarkerError> {
        let observed = committed
            .verify_installed_for(&self.core.retained_scheduler_artifacts)
            .map_err(marker_anchor_error)?;
        committed
            .verify_anchor_lease(&self.core.inner.anchor)
            .map_err(marker_anchor_error)?;
        self.core.inner.promote_staged_exact(
            &self.core.block,
            self.core.manifest_key_epoch,
            &self.core.prepared,
            &self.core.installed,
            LegacyMigrationMarkerPhase::Prepared,
            LegacyMigrationMarkerPhase::Installed,
            Some(observed),
        )?;
        Ok(InstalledLegacyMigrationPlan { core: self.core })
    }
}

impl RecoverableLegacyCompleteTransition {
    /// Borrow the exact plan for
    /// `RegistrySensitiveParamProvider::recover_legacy_complete_marker_transition`.
    pub fn scheduler_recovery_artifacts(&self) -> &PreparedLegacyRegistryMigration {
        &self.core.retained_scheduler_artifacts
    }

    /// Re-derive the exact opaque mutation when the scheduler proves the
    /// carrier migration is complete but its tag-13 transition is still at
    /// the precommit boundary.
    pub fn restage_complete(
        self,
        complete: VerifiedLegacyMigrationComplete,
    ) -> Result<StagedLegacyCompleteTransition, LegacyMigrationMarkerError> {
        let scheduler_transition = complete
            .prepare_complete_marker_transition(
                &self.core.inner.anchor,
                &self.core.retained_scheduler_artifacts,
            )
            .map_err(marker_anchor_error)?;
        let expected_next = scheduler_transition.next().clone();
        Ok(StagedLegacyCompleteTransition {
            core: self.core,
            scheduler_transition: Some(scheduler_transition),
            expected_next,
        })
    }

    pub fn finish_complete(
        self,
        committed: VerifiedLegacyMarkerTransitionCommitted,
    ) -> Result<CompleteLegacyMigrationPlan, LegacyMigrationMarkerError> {
        let observed = committed
            .verify_complete_for(&self.core.retained_scheduler_artifacts)
            .map_err(marker_anchor_error)?;
        committed
            .verify_anchor_lease(&self.core.inner.anchor)
            .map_err(marker_anchor_error)?;
        self.core.inner.promote_staged_exact(
            &self.core.block,
            self.core.manifest_key_epoch,
            &self.core.installed,
            &self.core.complete,
            LegacyMigrationMarkerPhase::Installed,
            LegacyMigrationMarkerPhase::Complete,
            Some(observed),
        )?;
        Ok(CompleteLegacyMigrationPlan { core: self.core })
    }
}

impl FileLegacyMigrationMarkerCustody {
    pub fn from_anchor_store(
        anchor: &FilePlatformMonotonicAnchorStore,
        keyring: &FilePersistedIdentityKeyringCustody,
        roles: &FileContract218RoleRootCustody,
        authority: Arc<dyn LegacyMigrationOperatorAuthority>,
    ) -> Result<Self, LegacyMigrationMarkerError> {
        if !keyring.shares_anchor(anchor) || !roles.shares_anchor(anchor) {
            return Err(LegacyMigrationMarkerError::Invalid(
                "marker, keyring, and role custody must share one anchor lease".to_owned(),
            ));
        }
        let (directory, workspace, exclusive) =
            anchor.claim_marker_custody().map_err(marker_anchor_error)?;
        let inner = Arc::new(MarkerInner {
            directory,
            workspace,
            anchor: anchor.clone(),
            keyring: keyring.clone(),
            roles: roles.clone(),
            authority,
            _exclusive_custody: exclusive,
            writer: Mutex::new(()),
            #[cfg(feature = "test-support")]
            failpoint: Mutex::new(None),
        });
        inner.validate_open_state()?;
        Ok(Self { inner })
    }

    /// Authenticate the exact target keyring and empty role manifest, create
    /// three unique phase markers, durably bind the complete three-phase plan,
    /// retain Prepared, and return an opaque plan.
    pub fn initialize_prepared(
        &self,
        migration_block: [u8; BLOCK_LEN],
        manifest_key_epoch: u32,
    ) -> Result<AuthenticatedLegacyMigrationPlan, LegacyMigrationMarkerError> {
        if manifest_key_epoch == 0 {
            return Err(LegacyMigrationMarkerError::Invalid(
                "manifest key epoch must be positive".to_owned(),
            ));
        }
        let _writer = self.inner.writer.lock().map_err(|_| lock_error())?;
        self.inner
            .anchor
            .require_uninitialized_for_migration()
            .map_err(marker_anchor_error)?;
        if self.inner.is_plan_only_state()? {
            let persisted = self.inner.read_authenticated_plan()?;
            if persisted.block != migration_block
                || persisted.manifest_key_epoch != manifest_key_epoch
            {
                return Err(LegacyMigrationMarkerError::AuthenticationFailed);
            }
            let mut plan =
                self.inner
                    .build_plan(migration_block, manifest_key_epoch, Some(persisted))?;
            self.inner.write_current_prepared(&plan.core.prepared)?;
            let durable = self.inner.read_authenticated(&self.inner.current_path())?;
            if durable.phase != LegacyMigrationMarkerPhase::Prepared
                || durable.bytes != plan.core.prepared
            {
                return Err(LegacyMigrationMarkerError::AuthenticationFailed);
            }
            plan.core.prepared = durable.bytes;
            return Ok(plan);
        }
        self.inner.require_no_marker_artifacts()?;
        let projection = parse_block(&migration_block)?;
        self.inner.verify_authority(&projection)?;
        let mut plan = self
            .inner
            .build_plan(migration_block, manifest_key_epoch, None)?;
        self.inner.write_plan(&plan)?;
        #[cfg(feature = "test-support")]
        self.inner
            .maybe_fail(LegacyMigrationMarkerFailpoint::AfterPlanFsync)?;
        let durable_plan = self.inner.read_authenticated_plan()?;
        if durable_plan.block != plan.core.block
            || durable_plan.manifest_key_epoch != plan.core.manifest_key_epoch
            || durable_plan.prepared != plan.core.prepared
            || durable_plan.installed != plan.core.installed
            || durable_plan.complete != plan.core.complete
        {
            return Err(LegacyMigrationMarkerError::AuthenticationFailed);
        }
        self.inner.write_current_prepared(&plan.core.prepared)?;
        // Re-read and authenticate the durable bytes before releasing them to
        // scheduler code.
        let durable = self.inner.read_authenticated(&self.inner.current_path())?;
        if durable.bytes != durable_plan.prepared
            || durable.bytes != plan.core.prepared
            || durable.phase != LegacyMigrationMarkerPhase::Prepared
        {
            return Err(LegacyMigrationMarkerError::AuthenticationFailed);
        }
        plan.core.prepared = durable.bytes;
        Ok(plan)
    }

    #[cfg(feature = "test-support")]
    /// Test-only low-level reconciliation used to exercise every file-system
    /// crash boundary. Production resumes only a physically retained compact
    /// typestate and never accepts a caller-selected durable phase. A pending
    /// marker can only be rolled back to current or promoted to its exact
    /// consecutive successor.
    pub fn recover_expected_phase(
        &self,
        expected_phase: LegacyMigrationMarkerPhase,
    ) -> Result<LegacyMigrationMarkerRecovery, LegacyMigrationMarkerError> {
        let _writer = self.inner.writer.lock().map_err(|_| lock_error())?;
        self.inner.recover_unlocked(expected_phase)
    }

    #[cfg(feature = "test-support")]
    /// Rebuild an in-memory opaque plan from the authenticated retained phase
    /// after recovery. All three phase witnesses come from the durable,
    /// authenticated plan; restart never mints replacement future nonces.
    pub fn resume_plan(
        &self,
        expected_phase: LegacyMigrationMarkerPhase,
    ) -> Result<AuthenticatedLegacyMigrationPlan, LegacyMigrationMarkerError> {
        let _writer = self.inner.writer.lock().map_err(|_| lock_error())?;
        self.inner.recover_unlocked(expected_phase)?;
        let current = self.inner.read_authenticated(&self.inner.current_path())?;
        if current.phase != expected_phase {
            return Err(LegacyMigrationMarkerError::RecoveryRequired(
                "retained marker phase differs from the durable migration phase".to_owned(),
            ));
        }
        let persisted = self.inner.read_authenticated_plan()?;
        if persisted.marker_for_phase(expected_phase) != &current.bytes {
            return Err(LegacyMigrationMarkerError::AuthenticationFailed);
        }
        self.inner
            .build_plan(current.block, current.manifest_key_epoch, Some(persisted))
    }

    /// Resume only a clean, physically retained Prepared typestate. Pending
    /// state requires scheduler-authoritative transition recovery instead of
    /// a caller-supplied phase guess.
    pub fn resume_prepared(
        &self,
    ) -> Result<AuthenticatedLegacyMigrationPlan, LegacyMigrationMarkerError> {
        self.resume_clean_exact(LegacyMigrationMarkerPhase::Prepared)
    }

    /// Resume only a clean, physically retained Installed typestate.
    pub fn resume_installed(
        &self,
    ) -> Result<InstalledLegacyMigrationPlan, LegacyMigrationMarkerError> {
        let plan = self.resume_clean_exact(LegacyMigrationMarkerPhase::Installed)?;
        Ok(InstalledLegacyMigrationPlan { core: plan.core })
    }

    /// Resume only a clean, physically retained terminal Complete typestate.
    pub fn resume_complete(
        &self,
    ) -> Result<CompleteLegacyMigrationPlan, LegacyMigrationMarkerError> {
        let plan = self.resume_clean_exact(LegacyMigrationMarkerPhase::Complete)?;
        Ok(CompleteLegacyMigrationPlan { core: plan.core })
    }

    /// Reconstruct the exact durable Prepared/current + Installed/pending
    /// pair after restart. The caller must ask M014 to recover the committed
    /// transition with [`RecoverableLegacyInstalledTransition::scheduler_recovery_artifacts`]
    /// before owner promotion is possible.
    pub fn resume_staged_installed(
        &self,
    ) -> Result<RecoverableLegacyInstalledTransition, LegacyMigrationMarkerError> {
        Ok(RecoverableLegacyInstalledTransition {
            core: self.resume_staged_exact(
                LegacyMigrationMarkerPhase::Prepared,
                LegacyMigrationMarkerPhase::Installed,
            )?,
        })
    }

    /// Reconstruct the exact durable Installed/current + Complete/pending
    /// pair after restart. The caller must ask M014 to recover the committed
    /// transition with [`RecoverableLegacyCompleteTransition::scheduler_recovery_artifacts`]
    /// before owner promotion is possible.
    pub fn resume_staged_complete(
        &self,
    ) -> Result<RecoverableLegacyCompleteTransition, LegacyMigrationMarkerError> {
        Ok(RecoverableLegacyCompleteTransition {
            core: self.resume_staged_exact(
                LegacyMigrationMarkerPhase::Installed,
                LegacyMigrationMarkerPhase::Complete,
            )?,
        })
    }

    fn resume_staged_exact(
        &self,
        expected_current_phase: LegacyMigrationMarkerPhase,
        expected_pending_phase: LegacyMigrationMarkerPhase,
    ) -> Result<LegacyMigrationPlanCore, LegacyMigrationMarkerError> {
        let _writer = self.inner.writer.lock().map_err(|_| lock_error())?;
        if marker_file_exists(&atomic_temporary_path(&self.inner.pending_path())?)?
            || marker_file_exists(&atomic_temporary_path(&self.inner.current_path())?)?
            || marker_file_exists(&atomic_temporary_path(&self.inner.plan_path())?)?
            || !marker_file_exists(&self.inner.pending_path())?
        {
            return Err(LegacyMigrationMarkerError::RecoveryRequired(
                "no compact durable staged marker transition is available".to_owned(),
            ));
        }
        let persisted = self.inner.read_authenticated_plan()?;
        let current = self.inner.read_authenticated(&self.inner.current_path())?;
        let pending = self.inner.read_authenticated(&self.inner.pending_path())?;
        validate_marker_successor(&current, &pending)?;
        if current.phase != expected_current_phase
            || pending.phase != expected_pending_phase
            || persisted.marker_for_phase(expected_current_phase) != &current.bytes
            || persisted.marker_for_phase(expected_pending_phase) != &pending.bytes
        {
            return Err(LegacyMigrationMarkerError::AuthenticationFailed);
        }
        let plan =
            self.inner
                .build_plan(current.block, current.manifest_key_epoch, Some(persisted))?;
        Ok(plan.core)
    }

    fn resume_clean_exact(
        &self,
        expected_phase: LegacyMigrationMarkerPhase,
    ) -> Result<AuthenticatedLegacyMigrationPlan, LegacyMigrationMarkerError> {
        let _writer = self.inner.writer.lock().map_err(|_| lock_error())?;
        if marker_file_exists(&self.inner.pending_path())?
            || marker_file_exists(&atomic_temporary_path(&self.inner.pending_path())?)?
            || marker_file_exists(&atomic_temporary_path(&self.inner.current_path())?)?
            || marker_file_exists(&atomic_temporary_path(&self.inner.plan_path())?)?
        {
            return Err(LegacyMigrationMarkerError::RecoveryRequired(
                "staged marker transition requires scheduler-authoritative recovery".to_owned(),
            ));
        }
        let current = self.inner.read_authenticated(&self.inner.current_path())?;
        if current.phase != expected_phase {
            return Err(LegacyMigrationMarkerError::RecoveryRequired(
                "retained marker does not match the requested typestate".to_owned(),
            ));
        }
        let persisted = self.inner.read_authenticated_plan()?;
        if persisted.marker_for_phase(expected_phase) != &current.bytes {
            return Err(LegacyMigrationMarkerError::AuthenticationFailed);
        }
        self.inner
            .build_plan(current.block, current.manifest_key_epoch, Some(persisted))
    }

    pub fn current_phase(&self) -> Result<LegacyMigrationMarkerPhase, LegacyMigrationMarkerError> {
        let _writer = self.inner.writer.lock().map_err(|_| lock_error())?;
        if marker_file_exists(&self.inner.pending_path())?
            || marker_file_exists(&atomic_temporary_path(&self.inner.pending_path())?)?
            || marker_file_exists(&atomic_temporary_path(&self.inner.current_path())?)?
            || marker_file_exists(&atomic_temporary_path(&self.inner.plan_path())?)?
        {
            return Err(LegacyMigrationMarkerError::RecoveryRequired(
                "marker pending state must be reconciled first".to_owned(),
            ));
        }
        let current = self.inner.read_authenticated(&self.inner.current_path())?;
        let plan = self.inner.read_authenticated_plan()?;
        if plan.marker_for_phase(current.phase) != &current.bytes {
            return Err(LegacyMigrationMarkerError::AuthenticationFailed);
        }
        Ok(current.phase)
    }

    #[cfg(feature = "test-support")]
    pub fn set_failpoint_for_test(&self, failpoint: LegacyMigrationMarkerFailpoint) {
        *self.inner.failpoint.lock().expect("marker failpoint lock") = Some(failpoint);
    }
}

struct BlockProjection {
    registry_instance: [u8; 16],
    operator_principal_digest: [u8; 32],
}

struct ParsedMarker {
    manifest_key_epoch: u32,
    block: [u8; BLOCK_LEN],
    phase: LegacyMigrationMarkerPhase,
    nonce: [u8; 32],
    bytes: [u8; MARKER_LEN],
}

struct PersistedMarkerPlan {
    manifest_key_epoch: u32,
    block: [u8; BLOCK_LEN],
    prepared: [u8; MARKER_LEN],
    installed: [u8; MARKER_LEN],
    complete: [u8; MARKER_LEN],
}

impl PersistedMarkerPlan {
    fn marker_for_phase(&self, phase: LegacyMigrationMarkerPhase) -> &[u8; MARKER_LEN] {
        match phase {
            LegacyMigrationMarkerPhase::Prepared => &self.prepared,
            LegacyMigrationMarkerPhase::Installed => &self.installed,
            LegacyMigrationMarkerPhase::Complete => &self.complete,
        }
    }
}

#[derive(Clone, Copy)]
enum AtomicMarkerArtifact {
    Plan,
    Current,
    Pending,
}

impl MarkerInner {
    fn validate_open_state(&self) -> Result<(), LegacyMigrationMarkerError> {
        if marker_file_exists(&atomic_temporary_path(&self.current_path())?)?
            || marker_file_exists(&atomic_temporary_path(&self.plan_path())?)?
        {
            return Err(LegacyMigrationMarkerError::RecoveryRequired(
                "interrupted migration-marker plan/current write requires operator recovery"
                    .to_owned(),
            ));
        }
        if !marker_file_exists(&self.current_path())? {
            if marker_file_exists(&self.pending_path())?
                || marker_file_exists(&atomic_temporary_path(&self.pending_path())?)?
            {
                return Err(LegacyMigrationMarkerError::RecoveryRequired(
                    "orphan migration-marker pending state".to_owned(),
                ));
            }
            if marker_file_exists(&self.plan_path())? {
                self.read_authenticated_plan()?;
            }
            return Ok(());
        }
        if !marker_file_exists(&self.plan_path())? {
            return Err(LegacyMigrationMarkerError::RecoveryRequired(
                "durable migration marker has no authenticated phase plan".to_owned(),
            ));
        }
        let plan = self.read_authenticated_plan()?;
        let current = self.read_authenticated(&self.current_path())?;
        if plan.marker_for_phase(current.phase) != &current.bytes {
            return Err(LegacyMigrationMarkerError::AuthenticationFailed);
        }
        if marker_file_exists(&self.pending_path())? {
            let pending = self.read_authenticated(&self.pending_path())?;
            validate_marker_successor(&current, &pending)?;
            if plan.marker_for_phase(pending.phase) != &pending.bytes {
                return Err(LegacyMigrationMarkerError::AuthenticationFailed);
            }
        }
        Ok(())
    }

    fn is_plan_only_state(&self) -> Result<bool, LegacyMigrationMarkerError> {
        Ok(marker_file_exists(&self.plan_path())?
            && !marker_file_exists(&self.current_path())?
            && !marker_file_exists(&self.pending_path())?
            && !marker_file_exists(&atomic_temporary_path(&self.plan_path())?)?
            && !marker_file_exists(&atomic_temporary_path(&self.current_path())?)?
            && !marker_file_exists(&atomic_temporary_path(&self.pending_path())?)?)
    }

    fn build_plan(
        self: &Arc<Self>,
        block: [u8; BLOCK_LEN],
        manifest_key_epoch: u32,
        persisted: Option<PersistedMarkerPlan>,
    ) -> Result<AuthenticatedLegacyMigrationPlan, LegacyMigrationMarkerError> {
        let projection = parse_block(&block)?;
        self.verify_authority(&projection)?;
        let keyring_file = self
            .keyring
            .authenticated_initial_file_for_migration(
                projection.registry_instance,
                manifest_key_epoch,
            )
            .map_err(|error| LegacyMigrationMarkerError::RecoveryRequired(error.to_string()))?;
        let role_file = self
            .roles
            .authenticated_initial_file_for_migration(projection.registry_instance)
            .map_err(|error| LegacyMigrationMarkerError::RecoveryRequired(error.to_string()))?;

        let (prepared, installed, complete) = if let Some(persisted) = persisted {
            if persisted.block != block || persisted.manifest_key_epoch != manifest_key_epoch {
                return Err(LegacyMigrationMarkerError::AuthenticationFailed);
            }
            (persisted.prepared, persisted.installed, persisted.complete)
        } else {
            let mut nonces = Vec::with_capacity(3);
            while nonces.len() < 3 {
                let nonce = random_nonzero_nonce()?;
                if !nonces.contains(&nonce) {
                    nonces.push(nonce);
                }
            }
            (
                self.encode_marker(
                    manifest_key_epoch,
                    block,
                    LegacyMigrationMarkerPhase::Prepared,
                    nonces[0],
                )?,
                self.encode_marker(
                    manifest_key_epoch,
                    block,
                    LegacyMigrationMarkerPhase::Installed,
                    nonces[1],
                )?,
                self.encode_marker(
                    manifest_key_epoch,
                    block,
                    LegacyMigrationMarkerPhase::Complete,
                    nonces[2],
                )?,
            )
        };
        let artifacts = prepare_legacy_registry_migration(
            &self.anchor,
            &block,
            &prepared,
            &installed,
            &complete,
            &keyring_file,
            &role_file,
        )
        .map_err(marker_anchor_error)?;
        Ok(AuthenticatedLegacyMigrationPlan {
            core: LegacyMigrationPlanCore {
                inner: Arc::clone(self),
                block,
                manifest_key_epoch,
                prepared,
                installed,
                complete,
                retained_scheduler_artifacts: artifacts.clone(),
            },
            scheduler_artifacts: Some(artifacts),
        })
    }

    fn encode_plan(
        &self,
        plan: &AuthenticatedLegacyMigrationPlan,
    ) -> Result<[u8; PLAN_LEN], LegacyMigrationMarkerError> {
        let projection = parse_block(&plan.core.block)?;
        let mut bytes = [0_u8; PLAN_LEN];
        bytes[0] = PLAN_VERSION;
        bytes[1..1 + MARKER_LEN].copy_from_slice(&plan.core.prepared);
        bytes[1 + MARKER_LEN..1 + (2 * MARKER_LEN)].copy_from_slice(&plan.core.installed);
        bytes[1 + (2 * MARKER_LEN)..PLAN_PAYLOAD_LEN].copy_from_slice(&plan.core.complete);
        let mut mac_input = Vec::with_capacity(PLAN_MAC_DOMAIN.len() + PLAN_PAYLOAD_LEN);
        mac_input.extend_from_slice(PLAN_MAC_DOMAIN);
        mac_input.extend_from_slice(&bytes[..PLAN_PAYLOAD_LEN]);
        let mac = self
            .keyring
            .marker_mac(
                plan.core.manifest_key_epoch,
                projection.registry_instance,
                &mac_input,
            )
            .map_err(|error| LegacyMigrationMarkerError::RecoveryRequired(error.to_string()))?;
        bytes[PLAN_PAYLOAD_LEN..].copy_from_slice(&mac);
        Ok(bytes)
    }

    fn read_authenticated_plan(&self) -> Result<PersistedMarkerPlan, LegacyMigrationMarkerError> {
        let path = self.plan_path();
        let mut file = secure_open_regular(&path)
            .map_err(|error| marker_io("open marker plan", &path, error))?;
        if file
            .metadata()
            .map_err(|error| marker_io("stat marker plan", &path, error))?
            .len()
            != PLAN_LEN as u64
        {
            return Err(LegacyMigrationMarkerError::AuthenticationFailed);
        }
        let mut bytes = [0_u8; PLAN_LEN];
        file.read_exact(&mut bytes)
            .map_err(|error| marker_io("read marker plan", &path, error))?;
        if bytes[0] != PLAN_VERSION {
            return Err(LegacyMigrationMarkerError::AuthenticationFailed);
        }
        let prepared_bytes = marker_array_at(&bytes, 1)?;
        let installed_bytes = marker_array_at(&bytes, 1 + MARKER_LEN)?;
        let complete_bytes = marker_array_at(&bytes, 1 + (2 * MARKER_LEN))?;
        let prepared = self.authenticate_bytes(&prepared_bytes)?;
        let installed = self.authenticate_bytes(&installed_bytes)?;
        let complete = self.authenticate_bytes(&complete_bytes)?;
        if prepared.phase != LegacyMigrationMarkerPhase::Prepared
            || installed.phase != LegacyMigrationMarkerPhase::Installed
            || complete.phase != LegacyMigrationMarkerPhase::Complete
            || prepared.block != installed.block
            || installed.block != complete.block
            || prepared.manifest_key_epoch != installed.manifest_key_epoch
            || installed.manifest_key_epoch != complete.manifest_key_epoch
            || prepared.nonce == complete.nonce
        {
            return Err(LegacyMigrationMarkerError::AuthenticationFailed);
        }
        validate_marker_successor(&prepared, &installed)?;
        validate_marker_successor(&installed, &complete)?;
        let projection = parse_block(&prepared.block)?;
        let mut mac_input = Vec::with_capacity(PLAN_MAC_DOMAIN.len() + PLAN_PAYLOAD_LEN);
        mac_input.extend_from_slice(PLAN_MAC_DOMAIN);
        mac_input.extend_from_slice(&bytes[..PLAN_PAYLOAD_LEN]);
        let expected = self
            .keyring
            .marker_mac(
                prepared.manifest_key_epoch,
                projection.registry_instance,
                &mac_input,
            )
            .map_err(|error| LegacyMigrationMarkerError::RecoveryRequired(error.to_string()))?;
        if expected.ct_eq(&bytes[PLAN_PAYLOAD_LEN..]).unwrap_u8() != 1 {
            return Err(LegacyMigrationMarkerError::AuthenticationFailed);
        }
        Ok(PersistedMarkerPlan {
            manifest_key_epoch: prepared.manifest_key_epoch,
            block: prepared.block,
            prepared: prepared.bytes,
            installed: installed.bytes,
            complete: complete.bytes,
        })
    }

    fn verify_authority(
        &self,
        projection: &BlockProjection,
    ) -> Result<(), LegacyMigrationMarkerError> {
        self.authority
            .verify_exclusive_runtime_and_operator(
                &self.workspace,
                projection.registry_instance,
                projection.operator_principal_digest,
            )
            .map_err(LegacyMigrationMarkerError::Unauthorized)
    }

    fn encode_marker(
        &self,
        manifest_key_epoch: u32,
        block: [u8; BLOCK_LEN],
        phase: LegacyMigrationMarkerPhase,
        nonce: [u8; 32],
    ) -> Result<[u8; MARKER_LEN], LegacyMigrationMarkerError> {
        if manifest_key_epoch == 0 || nonce == [0; 32] {
            return Err(LegacyMigrationMarkerError::Invalid(
                "marker epoch and nonce must be nonzero".to_owned(),
            ));
        }
        let projection = parse_block(&block)?;
        let mut preceding = Vec::with_capacity(MARKER_PRECEDING_LEN);
        preceding.push(MARKER_VERSION);
        preceding.extend_from_slice(&manifest_key_epoch.to_be_bytes());
        preceding.extend_from_slice(&block);
        preceding.push(phase as u8);
        preceding.extend_from_slice(&nonce);
        debug_assert_eq!(preceding.len(), MARKER_PRECEDING_LEN);
        let mac = self
            .keyring
            .marker_mac(manifest_key_epoch, projection.registry_instance, &preceding)
            .map_err(|error| LegacyMigrationMarkerError::RecoveryRequired(error.to_string()))?;
        let mut bytes = [0_u8; MARKER_LEN];
        bytes[..MARKER_PRECEDING_LEN].copy_from_slice(&preceding);
        bytes[MARKER_PRECEDING_LEN..].copy_from_slice(&mac);
        Ok(bytes)
    }

    fn read_authenticated(&self, path: &Path) -> Result<ParsedMarker, LegacyMigrationMarkerError> {
        let mut bytes = Vec::new();
        secure_open_regular(path)
            .and_then(|mut file| file.read_to_end(&mut bytes))
            .map_err(|error| marker_io("read marker", path, error))?;
        let bytes: [u8; MARKER_LEN] = bytes
            .try_into()
            .map_err(|_| LegacyMigrationMarkerError::AuthenticationFailed)?;
        if bytes[0] != MARKER_VERSION {
            return Err(LegacyMigrationMarkerError::AuthenticationFailed);
        }
        let manifest_key_epoch = u32::from_be_bytes(
            bytes[1..5]
                .try_into()
                .map_err(|_| LegacyMigrationMarkerError::AuthenticationFailed)?,
        );
        let block: [u8; BLOCK_LEN] = bytes[5..233]
            .try_into()
            .map_err(|_| LegacyMigrationMarkerError::AuthenticationFailed)?;
        let phase = LegacyMigrationMarkerPhase::parse(bytes[233])?;
        let nonce: [u8; 32] = bytes[234..266]
            .try_into()
            .map_err(|_| LegacyMigrationMarkerError::AuthenticationFailed)?;
        if manifest_key_epoch == 0 || nonce == [0; 32] {
            return Err(LegacyMigrationMarkerError::AuthenticationFailed);
        }
        let projection = parse_block(&block)?;
        self.verify_authority(&projection)?;
        let expected = self
            .keyring
            .marker_mac(
                manifest_key_epoch,
                projection.registry_instance,
                &bytes[..MARKER_PRECEDING_LEN],
            )
            .map_err(|error| LegacyMigrationMarkerError::RecoveryRequired(error.to_string()))?;
        if expected.ct_eq(&bytes[MARKER_PRECEDING_LEN..]).unwrap_u8() != 1 {
            return Err(LegacyMigrationMarkerError::AuthenticationFailed);
        }
        Ok(ParsedMarker {
            manifest_key_epoch,
            block,
            phase,
            nonce,
            bytes,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn stage_exact(
        &self,
        block: &[u8; BLOCK_LEN],
        manifest_key_epoch: u32,
        expected_current: &[u8; MARKER_LEN],
        next: &[u8; MARKER_LEN],
        expected_phase: LegacyMigrationMarkerPhase,
        next_phase: LegacyMigrationMarkerPhase,
    ) -> Result<(), LegacyMigrationMarkerError> {
        let _writer = self.writer.lock().map_err(|_| lock_error())?;
        if marker_file_exists(&atomic_temporary_path(&self.current_path())?)?
            || marker_file_exists(&atomic_temporary_path(&self.pending_path())?)?
            || marker_file_exists(&self.pending_path())?
        {
            return Err(LegacyMigrationMarkerError::RecoveryRequired(
                "marker pending state must be reconciled before transition".to_owned(),
            ));
        }
        if marker_file_exists(&atomic_temporary_path(&self.plan_path())?)? {
            return Err(LegacyMigrationMarkerError::RecoveryRequired(
                "marker plan state must be compact before transition".to_owned(),
            ));
        }
        let plan = self.read_authenticated_plan()?;
        let current = self.read_authenticated(&self.current_path())?;
        if plan.block != *block
            || plan.manifest_key_epoch != manifest_key_epoch
            || plan.marker_for_phase(expected_phase) != expected_current
            || plan.marker_for_phase(next_phase) != next
        {
            return Err(LegacyMigrationMarkerError::AuthenticationFailed);
        }
        let parsed_next = self.authenticate_bytes(next)?;
        if current.block != *block
            || current.manifest_key_epoch != manifest_key_epoch
            || current.phase != expected_phase
            || current.bytes != *expected_current
            || parsed_next.block != *block
            || parsed_next.manifest_key_epoch != manifest_key_epoch
            || parsed_next.phase != next_phase
        {
            return Err(LegacyMigrationMarkerError::AuthenticationFailed);
        }
        validate_marker_successor(&current, &parsed_next)?;
        self.write_pending(next)?;
        #[cfg(feature = "test-support")]
        self.maybe_fail(LegacyMigrationMarkerFailpoint::AfterPendingFsync)?;
        Ok(())
    }

    fn rollback_exact_pending(
        &self,
        expected_pending: &[u8; MARKER_LEN],
    ) -> Result<(), LegacyMigrationMarkerError> {
        let _writer = self.writer.lock().map_err(|_| lock_error())?;
        if marker_file_exists(&atomic_temporary_path(&self.pending_path())?)? {
            return Err(LegacyMigrationMarkerError::RecoveryRequired(
                "cannot roll back a torn marker pending write".to_owned(),
            ));
        }
        if !marker_file_exists(&self.pending_path())? {
            return Ok(());
        }
        let pending = self.read_authenticated(&self.pending_path())?;
        if pending.bytes != *expected_pending {
            return Err(LegacyMigrationMarkerError::AuthenticationFailed);
        }
        secure_remove_regular(&self.pending_path()).map_err(|error| {
            marker_io(
                "roll back rejected pending marker",
                &self.pending_path(),
                error,
            )
        })?;
        fsync_directory(&self.directory)
    }

    #[allow(clippy::too_many_arguments)]
    fn promote_staged_exact(
        &self,
        block: &[u8; BLOCK_LEN],
        manifest_key_epoch: u32,
        expected_current: &[u8; MARKER_LEN],
        next: &[u8; MARKER_LEN],
        expected_phase: LegacyMigrationMarkerPhase,
        next_phase: LegacyMigrationMarkerPhase,
        anchored: Option<&RegistryAnchorTuple>,
    ) -> Result<(), LegacyMigrationMarkerError> {
        let _writer = self.writer.lock().map_err(|_| lock_error())?;
        if marker_file_exists(&atomic_temporary_path(&self.current_path())?)?
            || marker_file_exists(&atomic_temporary_path(&self.pending_path())?)?
            || marker_file_exists(&atomic_temporary_path(&self.plan_path())?)?
        {
            return Err(LegacyMigrationMarkerError::RecoveryRequired(
                "marker staged state is torn".to_owned(),
            ));
        }
        let plan = self.read_authenticated_plan()?;
        let current = self.read_authenticated(&self.current_path())?;
        if plan.block != *block
            || plan.manifest_key_epoch != manifest_key_epoch
            || plan.marker_for_phase(expected_phase) != expected_current
            || plan.marker_for_phase(next_phase) != next
        {
            return Err(LegacyMigrationMarkerError::AuthenticationFailed);
        }
        if current.phase == next_phase
            && current.bytes == *next
            && !marker_file_exists(&self.pending_path())?
        {
            return Ok(());
        }
        if !marker_file_exists(&self.pending_path())? {
            return Err(LegacyMigrationMarkerError::RecoveryRequired(
                "scheduler committed a marker transition without its exact staged owner artifact"
                    .to_owned(),
            ));
        }
        let pending = self.read_authenticated(&self.pending_path())?;
        if current.block != *block
            || current.manifest_key_epoch != manifest_key_epoch
            || current.phase != expected_phase
            || current.bytes != *expected_current
            || pending.block != *block
            || pending.manifest_key_epoch != manifest_key_epoch
            || pending.phase != next_phase
            || pending.bytes != *next
        {
            return Err(LegacyMigrationMarkerError::AuthenticationFailed);
        }
        validate_marker_successor(&current, &pending)?;
        if let Some(anchored) = anchored {
            match self
                .anchor
                .authenticated_world()
                .map_err(marker_anchor_error)?
            {
                advance_scheduler::observation_anchor::RegistryAnchorWorld::CompactCurrent {
                    current,
                    ..
                } if current == *anchored => {}
                _ => return Err(LegacyMigrationMarkerError::AuthenticationFailed),
            }
        } else {
            #[cfg(not(feature = "test-support"))]
            return Err(LegacyMigrationMarkerError::RecoveryRequired(
                "owner promotion requires the concrete compact anchor witness".to_owned(),
            ));
        }
        #[cfg(feature = "test-support")]
        self.maybe_fail(LegacyMigrationMarkerFailpoint::BeforePendingPromotion)?;
        secure_replace_regular(&self.pending_path(), &self.current_path())
            .map_err(|error| marker_io("promote pending marker", &self.pending_path(), error))?;
        fsync_directory(&self.directory)
    }

    #[cfg(feature = "test-support")]
    #[allow(clippy::too_many_arguments)]
    fn transition_exact_for_test(
        &self,
        block: &[u8; BLOCK_LEN],
        manifest_key_epoch: u32,
        expected_current: &[u8; MARKER_LEN],
        next: &[u8; MARKER_LEN],
        expected_phase: LegacyMigrationMarkerPhase,
        next_phase: LegacyMigrationMarkerPhase,
    ) -> Result<(), LegacyMigrationMarkerError> {
        self.stage_exact(
            block,
            manifest_key_epoch,
            expected_current,
            next,
            expected_phase,
            next_phase,
        )?;
        self.promote_staged_exact(
            block,
            manifest_key_epoch,
            expected_current,
            next,
            expected_phase,
            next_phase,
            None,
        )
    }

    fn authenticate_bytes(
        &self,
        bytes: &[u8; MARKER_LEN],
    ) -> Result<ParsedMarker, LegacyMigrationMarkerError> {
        // Decode without publishing a marker artifact.  The same exact parser
        // is kept in one place by using the canonical byte offsets directly.
        if bytes[0] != MARKER_VERSION {
            return Err(LegacyMigrationMarkerError::AuthenticationFailed);
        }
        let manifest_key_epoch = u32::from_be_bytes(marker_array_at(bytes, 1)?);
        let block = marker_array_at(bytes, 5)?;
        let phase = LegacyMigrationMarkerPhase::parse(bytes[233])?;
        let nonce = marker_array_at(bytes, 234)?;
        if manifest_key_epoch == 0 || nonce == [0; 32] {
            return Err(LegacyMigrationMarkerError::AuthenticationFailed);
        }
        let projection = parse_block(&block)?;
        self.verify_authority(&projection)?;
        let expected = self
            .keyring
            .marker_mac(
                manifest_key_epoch,
                projection.registry_instance,
                &bytes[..MARKER_PRECEDING_LEN],
            )
            .map_err(|error| LegacyMigrationMarkerError::RecoveryRequired(error.to_string()))?;
        if expected.ct_eq(&bytes[MARKER_PRECEDING_LEN..]).unwrap_u8() != 1 {
            return Err(LegacyMigrationMarkerError::AuthenticationFailed);
        }
        Ok(ParsedMarker {
            manifest_key_epoch,
            block,
            phase,
            nonce,
            bytes: *bytes,
        })
    }

    #[cfg(feature = "test-support")]
    fn recover_unlocked(
        &self,
        expected_phase: LegacyMigrationMarkerPhase,
    ) -> Result<LegacyMigrationMarkerRecovery, LegacyMigrationMarkerError> {
        if marker_file_exists(&atomic_temporary_path(&self.current_path())?)?
            || marker_file_exists(&atomic_temporary_path(&self.plan_path())?)?
        {
            return Err(LegacyMigrationMarkerError::RecoveryRequired(
                "interrupted marker plan/current replacement cannot be inferred".to_owned(),
            ));
        }
        let plan = self.read_authenticated_plan()?;
        let current = self.read_authenticated(&self.current_path())?;
        if plan.marker_for_phase(current.phase) != &current.bytes {
            return Err(LegacyMigrationMarkerError::AuthenticationFailed);
        }
        let pending_temporary = atomic_temporary_path(&self.pending_path())?;
        if marker_file_exists(&pending_temporary)? {
            if marker_file_exists(&self.pending_path())? || current.phase != expected_phase {
                return Err(LegacyMigrationMarkerError::RecoveryRequired(
                    "torn marker pending write conflicts with the durable phase".to_owned(),
                ));
            }
            secure_remove_regular(&pending_temporary).map_err(|error| {
                marker_io("remove torn pending marker", &pending_temporary, error)
            })?;
            fsync_directory(&self.directory)?;
            return Ok(LegacyMigrationMarkerRecovery::RolledBackPending);
        }
        if !marker_file_exists(&self.pending_path())? {
            return if current.phase == expected_phase {
                Ok(LegacyMigrationMarkerRecovery::Clean)
            } else {
                Err(LegacyMigrationMarkerError::RecoveryRequired(
                    "retained marker does not match the durable migration phase".to_owned(),
                ))
            };
        }
        let pending = self.read_authenticated(&self.pending_path())?;
        validate_marker_successor(&current, &pending)?;
        if plan.marker_for_phase(pending.phase) != &pending.bytes {
            return Err(LegacyMigrationMarkerError::AuthenticationFailed);
        }
        if current.phase == expected_phase {
            secure_remove_regular(&self.pending_path()).map_err(|error| {
                marker_io("roll back pending marker", &self.pending_path(), error)
            })?;
            fsync_directory(&self.directory)?;
            Ok(LegacyMigrationMarkerRecovery::RolledBackPending)
        } else if pending.phase == expected_phase {
            secure_replace_regular(&self.pending_path(), &self.current_path()).map_err(
                |error| marker_io("recover pending marker", &self.pending_path(), error),
            )?;
            fsync_directory(&self.directory)?;
            Ok(LegacyMigrationMarkerRecovery::PromotedPending)
        } else {
            Err(LegacyMigrationMarkerError::RecoveryRequired(
                "pending marker names neither allowed durable phase".to_owned(),
            ))
        }
    }

    fn require_no_marker_artifacts(&self) -> Result<(), LegacyMigrationMarkerError> {
        if marker_file_exists(&self.current_path())?
            || marker_file_exists(&self.pending_path())?
            || marker_file_exists(&self.plan_path())?
            || marker_file_exists(&atomic_temporary_path(&self.current_path())?)?
            || marker_file_exists(&atomic_temporary_path(&self.pending_path())?)?
            || marker_file_exists(&atomic_temporary_path(&self.plan_path())?)?
        {
            return Err(LegacyMigrationMarkerError::RecoveryRequired(
                "migration-marker initialization encountered pre-existing state".to_owned(),
            ));
        }
        Ok(())
    }

    fn write_plan(
        &self,
        plan: &AuthenticatedLegacyMigrationPlan,
    ) -> Result<(), LegacyMigrationMarkerError> {
        let bytes = self.encode_plan(plan)?;
        self.atomic_write(&self.plan_path(), &bytes, AtomicMarkerArtifact::Plan)
    }

    fn write_current_prepared(
        &self,
        bytes: &[u8; MARKER_LEN],
    ) -> Result<(), LegacyMigrationMarkerError> {
        self.atomic_write(&self.current_path(), bytes, AtomicMarkerArtifact::Current)
    }

    fn write_pending(&self, bytes: &[u8; MARKER_LEN]) -> Result<(), LegacyMigrationMarkerError> {
        self.atomic_write(&self.pending_path(), bytes, AtomicMarkerArtifact::Pending)
    }

    fn atomic_write(
        &self,
        path: &Path,
        bytes: &[u8],
        artifact: AtomicMarkerArtifact,
    ) -> Result<(), LegacyMigrationMarkerError> {
        let temporary = atomic_temporary_path(path)?;
        marker_file_exists(path)?;
        let mut file = secure_create_new_regular(&temporary)
            .map_err(|error| marker_io("open marker temporary", &temporary, error))?;
        file.write_all(bytes)
            .and_then(|_| file.sync_all())
            .map_err(|error| marker_io("write/fsync marker temporary", &temporary, error))?;
        #[cfg(feature = "test-support")]
        self.maybe_fail(match artifact {
            AtomicMarkerArtifact::Plan => LegacyMigrationMarkerFailpoint::AfterPlanTemporaryFsync,
            AtomicMarkerArtifact::Current => {
                LegacyMigrationMarkerFailpoint::AfterCurrentTemporaryFsync
            }
            AtomicMarkerArtifact::Pending => {
                LegacyMigrationMarkerFailpoint::AfterPendingTemporaryFsync
            }
        })?;
        #[cfg(not(feature = "test-support"))]
        let _ = artifact;
        secure_replace_regular(&temporary, path)
            .map_err(|error| marker_io("rename marker temporary", path, error))?;
        fsync_directory(&self.directory)
    }

    fn current_path(&self) -> PathBuf {
        self.directory.join(CURRENT_FILE)
    }

    fn pending_path(&self) -> PathBuf {
        self.directory.join(PENDING_FILE)
    }

    fn plan_path(&self) -> PathBuf {
        self.directory.join(PLAN_FILE)
    }

    #[cfg(feature = "test-support")]
    fn maybe_fail(
        &self,
        expected: LegacyMigrationMarkerFailpoint,
    ) -> Result<(), LegacyMigrationMarkerError> {
        let mut armed = self.failpoint.lock().map_err(|_| lock_error())?;
        if *armed == Some(expected) {
            *armed = None;
            return Err(LegacyMigrationMarkerError::Failpoint(expected));
        }
        Ok(())
    }
}

fn parse_block(block: &[u8; BLOCK_LEN]) -> Result<BlockProjection, LegacyMigrationMarkerError> {
    let migration_id = marker_array_at(block, 0)?;
    let registry_instance = marker_array_at(block, 16)?;
    let legacy_file_identity_digest = marker_array_at(block, 32)?;
    let legacy_projection_root = marker_array_at(block, 64)?;
    let target_schema_version = u32::from_be_bytes(marker_array_at(block, 96)?);
    let target_state_root = marker_array_at(block, 100)?;
    let target_keyring_root = marker_array_at(block, 132)?;
    let target_role_allocation_root = marker_array_at(block, 164)?;
    let operator_principal_digest = marker_array_at(block, 196)?;
    if migration_id == [0; 16]
        || registry_instance == [0; 16]
        || legacy_file_identity_digest == [0; 32]
        || legacy_projection_root == [0; 32]
        || target_schema_version != 1
        || target_state_root == [0; 32]
        || target_keyring_root == [0; 32]
        || target_role_allocation_root == [0; 32]
        || operator_principal_digest == [0; 32]
    {
        return Err(LegacyMigrationMarkerError::AuthenticationFailed);
    }
    Ok(BlockProjection {
        registry_instance,
        operator_principal_digest,
    })
}

fn marker_array_at<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; N], LegacyMigrationMarkerError> {
    let end = offset
        .checked_add(N)
        .ok_or(LegacyMigrationMarkerError::AuthenticationFailed)?;
    bytes
        .get(offset..end)
        .ok_or(LegacyMigrationMarkerError::AuthenticationFailed)?
        .try_into()
        .map_err(|_| LegacyMigrationMarkerError::AuthenticationFailed)
}

fn validate_marker_successor(
    current: &ParsedMarker,
    pending: &ParsedMarker,
) -> Result<(), LegacyMigrationMarkerError> {
    if current.block != pending.block
        || current.manifest_key_epoch != pending.manifest_key_epoch
        || current.phase.successor() != Some(pending.phase)
        || current.nonce == pending.nonce
    {
        return Err(LegacyMigrationMarkerError::AuthenticationFailed);
    }
    Ok(())
}

fn random_nonzero_nonce() -> Result<[u8; 32], LegacyMigrationMarkerError> {
    for _ in 0..16 {
        let mut nonce = [0_u8; 32];
        OsRng.fill_bytes(&mut nonce);
        if nonce != [0; 32] {
            return Ok(nonce);
        }
    }
    Err(LegacyMigrationMarkerError::RecoveryRequired(
        "CSPRNG repeatedly returned an all-zero marker nonce".to_owned(),
    ))
}

fn atomic_temporary_path(path: &Path) -> Result<PathBuf, LegacyMigrationMarkerError> {
    let parent = path.parent().ok_or_else(|| {
        LegacyMigrationMarkerError::Invalid("marker path has no parent".to_owned())
    })?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            LegacyMigrationMarkerError::Invalid("marker filename is not UTF-8".to_owned())
        })?;
    Ok(parent.join(format!(".{name}.tmp")))
}

fn marker_file_exists(path: &Path) -> Result<bool, LegacyMigrationMarkerError> {
    secure_regular_exists(path).map_err(|error| {
        LegacyMigrationMarkerError::RecoveryRequired(format!(
            "inspect confined marker artifact {}: {error}",
            path.display()
        ))
    })
}

/// Exercises the production marker leaf gate with an integration-test supplied path.
#[cfg(feature = "test-support")]
#[doc(hidden)]
pub fn test_only_marker_file_exists(path: &Path) -> Result<bool, LegacyMigrationMarkerError> {
    marker_file_exists(path)
}

fn fsync_directory(directory: &Path) -> Result<(), LegacyMigrationMarkerError> {
    File::open(directory)
        .and_then(|file| file.sync_all())
        .map_err(|error| marker_io("fsync marker directory", directory, error))
}

fn marker_io(context: &str, path: &Path, error: std::io::Error) -> LegacyMigrationMarkerError {
    LegacyMigrationMarkerError::Io(format!("{context} {}: {error}", path.display()))
}

fn lock_error() -> LegacyMigrationMarkerError {
    LegacyMigrationMarkerError::RecoveryRequired("marker process lock poisoned".to_owned())
}

fn marker_anchor_error(error: RegistryAnchorError) -> LegacyMigrationMarkerError {
    match error {
        RegistryAnchorError::AuthenticationFailed => {
            LegacyMigrationMarkerError::AuthenticationFailed
        }
        RegistryAnchorError::InvalidTransition => LegacyMigrationMarkerError::Invalid(
            "scheduler rejected the canonical migration artifact set".to_owned(),
        ),
        other => LegacyMigrationMarkerError::RecoveryRequired(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn every_marker_leaf_uses_the_character_device_rejecting_gate() {
        for leaf in [
            CURRENT_FILE,
            PENDING_FILE,
            PLAN_FILE,
            ".contract218.migration-marker.current.tmp",
            ".contract218.migration-marker.pending.tmp",
            ".contract218.migration-marker.plan.tmp",
        ] {
            assert!(
                marker_file_exists(Path::new("/dev/null")).is_err(),
                "marker leaf {leaf} accepted a character device"
            );
        }
    }
}

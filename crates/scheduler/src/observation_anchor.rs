//! Scheduler-owned CONTRACT-218 registry-anchor seam.
//!
//! This is deliberately not a shared-types contract and is not re-exported
//! from the scheduler crate root.  The composition root supplies the platform
//! implementation, while the scheduler owns the ordering and recovery policy.

use std::path::Path;

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;

const HEAD_DOMAIN: &[u8] = b"advance.contract218.registry-head.v1\0";
const MIGRATION_DIGEST_DOMAIN: &[u8] = b"advance.contract218.registry-migration-digest.v1\0";
const MIGRATION_MARKER_ROOT_DOMAIN: &[u8] = b"advance.contract218.registry-marker-root.v1\0";
const PERSISTED_KEYRING_FILE_ROOT_DOMAIN: &[u8] =
    b"advance.contract218.persisted-keyring-file.v1\0";
const ROLE_ALLOCATION_FILE_ROOT_DOMAIN: &[u8] = b"advance.contract218.role-allocation-file.v1\0";
const WRITE_SET_DOMAIN: &[u8] = b"advance.contract218.registry-write-set.v1\0";

/// Complete authenticated tuple shared by the SQLite ledger and external
/// monotonic anchor.  Equality is intentionally all-or-nothing: accepting a
/// subset would make same-sequence forks or restored authority snapshots look
/// current.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistryAnchorTuple {
    pub registry_instance: [u8; 16],
    pub sequence: u64,
    pub head: [u8; 32],
    pub state_root: [u8; 32],
    pub keyring_root: [u8; 32],
    pub role_allocation_root: [u8; 32],
    pub migration_digest: [u8; 32],
}

/// The authenticated external state visible at boot.
///
/// These variants deliberately encode only the three artifact shapes that can
/// participate in the four legal recovery worlds.  There is no "best effort"
/// or caller-selected tuple variant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RegistryAnchorWorld {
    /// The selected bundle still points at its current set and contains one
    /// authenticated pending next set.
    PendingCurrent {
        generation: u64,
        previous: RegistryAnchorTuple,
        next: RegistryAnchorTuple,
    },
    /// The selected set is the authenticated next set; compaction has not yet
    /// selected a no-next bundle.
    SelectedNext {
        generation: u64,
        next: RegistryAnchorTuple,
    },
    /// Clean steady state: selected current set and no pending next set.
    CompactCurrent {
        generation: u64,
        current: RegistryAnchorTuple,
    },
}

/// The four and only four accepted boot relations between the external anchor
/// and the durable SQLite ledger.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistryRecoveryDecision {
    RollBackPending,
    FinishPendingPromotion,
    CompactSelectedNext,
    Clean,
}

#[derive(Debug, Error, Clone, Eq, PartialEq)]
pub enum RegistryAnchorError {
    /// The external store has no selector, bundle, pending, or temporary
    /// artifact at all.  This is distinct from an unavailable or partially
    /// present store and authorizes only exact first-install recovery paths.
    #[error("external registry anchor is exactly uninitialized")]
    Uninitialized,
    #[error("external registry anchor is unavailable: {0}")]
    Unavailable(String),
    #[error("external registry anchor authentication failed")]
    AuthenticationFailed,
    #[error("registry anchor generation is exhausted")]
    GenerationExhausted,
    #[error("registry anchor compare-and-swap failed")]
    CompareAndSwapFailed,
    #[error("registry anchor and SQLite ledger require operator recovery: {0}")]
    RecoveryRequired(String),
    #[error("registry anchor transition was attempted out of order")]
    InvalidTransition,
}

/// Move-only proof that the exact registry database was genuinely empty when
/// its sequence-zero tuple was derived.  Only `ComponentRegistry` can issue
/// this value after a full scan under its mutation lock; neither callers nor
/// the external anchor can construct, clone, or serialize it.
pub struct VerifiedEmptyRegistryGenesis {
    tuple: RegistryAnchorTuple,
    workspace_identity_digest: [u8; 32],
    registry_identity_digest: [u8; 32],
}

/// Move-only proof that an authenticated stopped legacy migration produced
/// the exact nonempty sequence-zero target named by its retained Complete
/// marker.  Only scheduler migration code can construct this value after the
/// source projection, target state root, and connected database identity have
/// all been checked.
pub struct VerifiedLegacyRegistryMigrationGenesis {
    tuple: RegistryAnchorTuple,
    marker_root: [u8; 32],
    manifest_key_epoch: u32,
    migration_id: [u8; 16],
    workspace_identity_digest: [u8; 32],
    registry_identity_digest: [u8; 32],
}

impl VerifiedLegacyRegistryMigrationGenesis {
    pub fn tuple(&self) -> &RegistryAnchorTuple {
        &self.tuple
    }

    pub fn marker_root(&self) -> [u8; 32] {
        self.marker_root
    }

    pub fn manifest_key_epoch(&self) -> u32 {
        self.manifest_key_epoch
    }

    pub fn migration_id(&self) -> [u8; 16] {
        self.migration_id
    }

    pub fn verify_workspace_identity(
        &self,
        workspace_root: &Path,
    ) -> Result<(), RegistryAnchorError> {
        let canonical = workspace_root.canonicalize().map_err(|error| {
            RegistryAnchorError::Unavailable(format!(
                "canonicalize migration workspace identity: {error}"
            ))
        })?;
        let observed = canonical_path_digest(b"workspace", &canonical);
        if bool::from(observed.ct_eq(&self.workspace_identity_digest)) {
            Ok(())
        } else {
            Err(RegistryAnchorError::AuthenticationFailed)
        }
    }

    pub fn verify_registry_identity(
        &self,
        workspace_root: &Path,
        database_path: &Path,
    ) -> Result<(), RegistryAnchorError> {
        let workspace = workspace_root.canonicalize().map_err(|error| {
            RegistryAnchorError::Unavailable(format!(
                "canonicalize migration workspace identity: {error}"
            ))
        })?;
        let database = database_path.canonicalize().map_err(|error| {
            RegistryAnchorError::Unavailable(format!(
                "canonicalize migration database identity: {error}"
            ))
        })?;
        let observed = registry_identity_digest(&workspace, &database);
        if bool::from(observed.ct_eq(&self.registry_identity_digest)) {
            Ok(())
        } else {
            Err(RegistryAnchorError::AuthenticationFailed)
        }
    }

    pub(crate) fn from_verified_legacy_migration(
        tuple: RegistryAnchorTuple,
        marker_root: [u8; 32],
        manifest_key_epoch: u32,
        migration_id: [u8; 16],
        workspace_root: &Path,
        database_path: &Path,
    ) -> Result<Self, RegistryAnchorError> {
        if tuple.sequence != 0
            || tuple.registry_instance == [0; 16]
            || marker_root == [0; 32]
            || manifest_key_epoch == 0
            || migration_id == [0; 16]
        {
            return Err(RegistryAnchorError::InvalidTransition);
        }
        let workspace = workspace_root.canonicalize().map_err(|error| {
            RegistryAnchorError::Unavailable(format!(
                "canonicalize migration workspace identity: {error}"
            ))
        })?;
        let database = database_path.canonicalize().map_err(|error| {
            RegistryAnchorError::Unavailable(format!(
                "canonicalize migration database identity: {error}"
            ))
        })?;
        if database.parent() != Some(workspace.as_path()) {
            return Err(RegistryAnchorError::AuthenticationFailed);
        }
        Ok(Self {
            tuple,
            marker_root,
            manifest_key_epoch,
            migration_id,
            workspace_identity_digest: canonical_path_digest(b"workspace", &workspace),
            registry_identity_digest: registry_identity_digest(&workspace, &database),
        })
    }
}

impl VerifiedEmptyRegistryGenesis {
    pub fn tuple(&self) -> &RegistryAnchorTuple {
        &self.tuple
    }

    /// Bind genesis to the canonical workspace identity retained by the
    /// platform store without exposing the digest itself.
    pub fn verify_workspace_identity(
        &self,
        workspace_root: &Path,
    ) -> Result<(), RegistryAnchorError> {
        let canonical = workspace_root.canonicalize().map_err(|error| {
            RegistryAnchorError::Unavailable(format!(
                "canonicalize genesis workspace identity: {error}"
            ))
        })?;
        let observed = canonical_path_digest(b"workspace", &canonical);
        if bool::from(observed.ct_eq(&self.workspace_identity_digest)) {
            Ok(())
        } else {
            Err(RegistryAnchorError::AuthenticationFailed)
        }
    }

    /// Optional stricter check for platform stores that retain the exact
    /// registry database path in addition to the workspace root.
    pub fn verify_registry_identity(
        &self,
        workspace_root: &Path,
        database_path: &Path,
    ) -> Result<(), RegistryAnchorError> {
        let workspace = workspace_root.canonicalize().map_err(|error| {
            RegistryAnchorError::Unavailable(format!(
                "canonicalize genesis workspace identity: {error}"
            ))
        })?;
        let database = database_path.canonicalize().map_err(|error| {
            RegistryAnchorError::Unavailable(format!(
                "canonicalize genesis database identity: {error}"
            ))
        })?;
        let observed = registry_identity_digest(&workspace, &database);
        if bool::from(observed.ct_eq(&self.registry_identity_digest)) {
            Ok(())
        } else {
            Err(RegistryAnchorError::AuthenticationFailed)
        }
    }

    pub(crate) fn from_verified_empty_registry(
        tuple: RegistryAnchorTuple,
        workspace_root: &Path,
        database_path: &Path,
    ) -> Result<Self, RegistryAnchorError> {
        if tuple.sequence != 0 || tuple.registry_instance == [0; 16] {
            return Err(RegistryAnchorError::InvalidTransition);
        }
        let workspace = workspace_root.canonicalize().map_err(|error| {
            RegistryAnchorError::Unavailable(format!(
                "canonicalize genesis workspace identity: {error}"
            ))
        })?;
        let database = database_path.canonicalize().map_err(|error| {
            RegistryAnchorError::Unavailable(format!(
                "canonicalize genesis database identity: {error}"
            ))
        })?;
        if database.parent() != Some(workspace.as_path()) {
            return Err(RegistryAnchorError::AuthenticationFailed);
        }
        Ok(Self {
            tuple,
            workspace_identity_digest: canonical_path_digest(b"workspace", &workspace),
            registry_identity_digest: registry_identity_digest(&workspace, &database),
        })
    }

    #[cfg(feature = "test-support")]
    pub fn fixture_for_test(
        tuple: RegistryAnchorTuple,
        workspace_root: &Path,
        database_path: &Path,
    ) -> Result<Self, RegistryAnchorError> {
        Self::from_verified_empty_registry(tuple, workspace_root, database_path)
    }
}

impl std::fmt::Debug for VerifiedEmptyRegistryGenesis {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VerifiedEmptyRegistryGenesis(<opaque>)")
    }
}

struct RoleDependencyBinding {
    registry_instance: [u8; 16],
    boot: [u8; 16],
    family_version: u16,
    ledger_sequence: u64,
    state_root: [u8; 32],
    role_allocation_root: [u8; 32],
    purpose: u8,
    scan_high_water: u64,
}

/// Move-only full-scan proof that an old boot still owns at least one rooted
/// replay dependency.  Its fields and constructor remain scheduler-private.
pub struct RetainedRoleDependencyReceipt {
    binding: RoleDependencyBinding,
}

/// Move-only full-scan proof that an old boot owns no rooted replay
/// dependency at the exact anchored high-water.
pub struct ZeroRoleDependencyReceipt {
    binding: RoleDependencyBinding,
}

impl RetainedRoleDependencyReceipt {
    pub fn verify_for_recovery_open(
        self,
        expected_boot: [u8; 16],
        expected_family_version: u16,
        anchored: &RegistryAnchorTuple,
        minimum_scan_high_water: u64,
    ) -> Result<u64, RegistryAnchorError> {
        verify_role_dependency_binding(
            &self.binding,
            1,
            expected_boot,
            expected_family_version,
            anchored,
            minimum_scan_high_water,
        )
    }

    pub(crate) fn from_full_scan(
        anchored: &RegistryAnchorTuple,
        boot: [u8; 16],
        family_version: u16,
        scan_high_water: u64,
    ) -> Result<Self, RegistryAnchorError> {
        Ok(Self {
            binding: role_dependency_binding(anchored, boot, family_version, 1, scan_high_water)?,
        })
    }

    #[cfg(feature = "test-support")]
    pub fn fixture_for_test(
        anchored: &RegistryAnchorTuple,
        boot: [u8; 16],
        family_version: u16,
        scan_high_water: u64,
    ) -> Result<Self, RegistryAnchorError> {
        Self::from_full_scan(anchored, boot, family_version, scan_high_water)
    }
}

impl ZeroRoleDependencyReceipt {
    pub fn verify_for_erase(
        self,
        expected_boot: [u8; 16],
        expected_family_version: u16,
        anchored: &RegistryAnchorTuple,
        minimum_scan_high_water: u64,
    ) -> Result<u64, RegistryAnchorError> {
        verify_role_dependency_binding(
            &self.binding,
            2,
            expected_boot,
            expected_family_version,
            anchored,
            minimum_scan_high_water,
        )
    }

    pub(crate) fn from_full_scan(
        anchored: &RegistryAnchorTuple,
        boot: [u8; 16],
        family_version: u16,
        scan_high_water: u64,
    ) -> Result<Self, RegistryAnchorError> {
        Ok(Self {
            binding: role_dependency_binding(anchored, boot, family_version, 2, scan_high_water)?,
        })
    }

    #[cfg(feature = "test-support")]
    pub fn fixture_for_test(
        anchored: &RegistryAnchorTuple,
        boot: [u8; 16],
        family_version: u16,
        scan_high_water: u64,
    ) -> Result<Self, RegistryAnchorError> {
        Self::from_full_scan(anchored, boot, family_version, scan_high_water)
    }
}

impl std::fmt::Debug for RetainedRoleDependencyReceipt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RetainedRoleDependencyReceipt(<opaque>)")
    }
}

impl std::fmt::Debug for ZeroRoleDependencyReceipt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ZeroRoleDependencyReceipt(<opaque>)")
    }
}

fn role_dependency_binding(
    anchored: &RegistryAnchorTuple,
    boot: [u8; 16],
    family_version: u16,
    purpose: u8,
    scan_high_water: u64,
) -> Result<RoleDependencyBinding, RegistryAnchorError> {
    if anchored.registry_instance == [0; 16]
        || boot == [0; 16]
        || family_version != 1
        || !matches!(purpose, 1 | 2)
        || scan_high_water == 0
        || scan_high_water != anchored.sequence
    {
        return Err(RegistryAnchorError::InvalidTransition);
    }
    Ok(RoleDependencyBinding {
        registry_instance: anchored.registry_instance,
        boot,
        family_version,
        ledger_sequence: anchored.sequence,
        state_root: anchored.state_root,
        role_allocation_root: anchored.role_allocation_root,
        purpose,
        scan_high_water,
    })
}

fn verify_role_dependency_binding(
    binding: &RoleDependencyBinding,
    expected_purpose: u8,
    expected_boot: [u8; 16],
    expected_family_version: u16,
    anchored: &RegistryAnchorTuple,
    minimum_scan_high_water: u64,
) -> Result<u64, RegistryAnchorError> {
    if binding.purpose != expected_purpose
        || binding.family_version != expected_family_version
        || binding.ledger_sequence != anchored.sequence
        || binding.scan_high_water != anchored.sequence
        || binding.scan_high_water < minimum_scan_high_water
        || !bool::from(binding.registry_instance.ct_eq(&anchored.registry_instance))
        || !bool::from(binding.boot.ct_eq(&expected_boot))
        || !bool::from(binding.state_root.ct_eq(&anchored.state_root))
        || !bool::from(
            binding
                .role_allocation_root
                .ct_eq(&anchored.role_allocation_root),
        )
    {
        return Err(RegistryAnchorError::AuthenticationFailed);
    }
    Ok(binding.scan_high_water)
}

/// Classify the external/SQLite relation without mutating either owner.
///
/// Exact tuple equality includes instance, sequence, head, state root,
/// keyring/role roots, and migration digest.  Consequently an old snapshot, a
/// same-sequence fork, or a mixed artifact set cannot enter a legal branch.
pub fn classify_recovery(
    external: &RegistryAnchorWorld,
    sqlite: &RegistryAnchorTuple,
) -> Result<RegistryRecoveryDecision, RegistryAnchorError> {
    match external {
        RegistryAnchorWorld::PendingCurrent { previous, next, .. }
            if sqlite == previous && is_structural_successor(previous, next) =>
        {
            Ok(RegistryRecoveryDecision::RollBackPending)
        }
        RegistryAnchorWorld::PendingCurrent { previous, next, .. }
            if sqlite == next && is_structural_successor(previous, next) =>
        {
            Ok(RegistryRecoveryDecision::FinishPendingPromotion)
        }
        RegistryAnchorWorld::SelectedNext { next, .. } if sqlite == next => {
            Ok(RegistryRecoveryDecision::CompactSelectedNext)
        }
        RegistryAnchorWorld::CompactCurrent { current, .. } if sqlite == current => {
            Ok(RegistryRecoveryDecision::Clean)
        }
        _ => Err(RegistryAnchorError::RecoveryRequired(
            "illegal selector/bundle/ledger cross-product or fork".to_owned(),
        )),
    }
}

fn is_structural_successor(previous: &RegistryAnchorTuple, next: &RegistryAnchorTuple) -> bool {
    previous.registry_instance == next.registry_instance
        && previous.sequence.checked_add(1) == Some(next.sequence)
        && previous.migration_digest == next.migration_digest
        && previous.head != next.head
}

fn canonical_path_digest(kind: &[u8], path: &Path) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"advance.contract218.registry-path-identity.v1\0");
    hasher.update((kind.len() as u32).to_be_bytes());
    hasher.update(kind);
    update_path_bytes(&mut hasher, path);
    hasher.finalize().into()
}

fn registry_identity_digest(workspace: &Path, database: &Path) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"advance.contract218.registry-database-identity.v1\0");
    hasher.update(canonical_path_digest(b"workspace", workspace));
    hasher.update(canonical_path_digest(b"database", database));
    hasher.finalize().into()
}

#[cfg(unix)]
fn update_path_bytes(hasher: &mut Sha256, path: &Path) {
    use std::os::unix::ffi::OsStrExt;

    let bytes = path.as_os_str().as_bytes();
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

#[cfg(windows)]
fn update_path_bytes(hasher: &mut Sha256, path: &Path) {
    use std::os::windows::ffi::OsStrExt;

    let units: Vec<u16> = path.as_os_str().encode_wide().collect();
    hasher.update(((units.len() * 2) as u64).to_be_bytes());
    for unit in units {
        hasher.update(unit.to_le_bytes());
    }
}

#[cfg(not(any(unix, windows)))]
fn update_path_bytes(hasher: &mut Sha256, path: &Path) {
    let text = path.as_os_str().to_string_lossy();
    hasher.update((text.len() as u64).to_be_bytes());
    hasher.update(text.as_bytes());
}

/// External-artifact fields which participate in the canonical successor
/// head but intentionally do not live in [`RegistryAnchorTuple`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistryHeadContext {
    pub previous_marker_root: [u8; 32],
    pub next_marker_root: [u8; 32],
    /// Epoch authenticating the current external *registry manifest*.  This
    /// is deliberately distinct from the independently authenticated role-
    /// allocation manifest's header epoch.
    pub manifest_key_epoch: u32,
    /// Epoch authenticating the no-pending next external registry manifest.
    pub next_manifest_key_epoch: u32,
}

impl RegistryHeadContext {
    pub fn unchanged(
        marker_root: [u8; 32],
        manifest_key_epoch: u32,
    ) -> Result<Self, RegistryAnchorError> {
        let context = Self {
            previous_marker_root: marker_root,
            next_marker_root: marker_root,
            manifest_key_epoch,
            next_manifest_key_epoch: manifest_key_epoch,
        };
        context.validate()?;
        Ok(context)
    }

    fn validate(&self) -> Result<(), RegistryAnchorError> {
        if self.previous_marker_root == [0; 32]
            || self.next_marker_root == [0; 32]
            || self.manifest_key_epoch == 0
            || self.next_manifest_key_epoch == 0
        {
            return Err(RegistryAnchorError::InvalidTransition);
        }
        Ok(())
    }
}

/// Exact postimage proposed for one provider mutation.
///
/// External crates can inspect this value but cannot mint a raw transition:
///
/// ```compile_fail
/// use advance_scheduler::observation_anchor::{
///     RegistryAnchorMutation, RegistryAnchorTuple, RegistryHeadContext,
/// };
/// fn forge(previous: RegistryAnchorTuple, next: RegistryAnchorTuple, context: RegistryHeadContext) {
///     let _ = RegistryAnchorMutation {
///         previous,
///         next,
///         head_context: context,
///         operation_tag: 6,
///         write_set_digest: [0; 32],
///     };
/// }
/// ```
///
/// The anchor-bound custody lease is move-only and cannot be duplicated:
///
/// ```compile_fail
/// use advance_scheduler::observation_anchor::RegistryAnchorMutation;
/// fn require_clone<T: Clone>() {}
/// require_clone::<RegistryAnchorMutation>();
/// ```
pub struct RegistryAnchorMutation {
    previous: RegistryAnchorTuple,
    next: RegistryAnchorTuple,
    head_context: RegistryHeadContext,
    operation_tag: u8,
    write_set_digest: [u8; 32],
    anchor_lease_challenge: [u8; 32],
    anchor_lease_tag: [u8; 32],
}

impl RegistryAnchorMutation {
    /// Exact preimage tuple.  Construction stays scheduler-private; external
    /// custody implementations receive only this read-only projection.
    pub fn previous(&self) -> &RegistryAnchorTuple {
        &self.previous
    }

    /// Exact database/anchor successor named by this scheduler-issued
    /// mutation.
    pub fn next(&self) -> &RegistryAnchorTuple {
        &self.next
    }

    pub fn head_context(&self) -> &RegistryHeadContext {
        &self.head_context
    }

    pub fn operation_tag(&self) -> u8 {
        self.operation_tag
    }

    pub fn write_set_digest(&self) -> [u8; 32] {
        self.write_set_digest
    }

    /// Validate the complete G→G+1 mutation before any external artifact is
    /// written.  This binds both the closed operation tag and exact write-set
    /// digest into the successor head while permitting authenticated tag-6
    /// keyring, role-root, marker-root, or manifest-epoch rotation.  The
    /// migration digest is invariant for the lifetime of one registry.
    pub fn validate(&self) -> Result<(), RegistryAnchorError> {
        self.head_context.validate()?;
        if !(1..=8).contains(&self.operation_tag)
            || !is_structural_successor(&self.previous, &self.next)
            || derive_next_head(
                &self.previous,
                &self.next,
                &self.head_context,
                self.operation_tag,
                self.write_set_digest,
            )? != self.next.head
        {
            return Err(RegistryAnchorError::InvalidTransition);
        }
        Ok(())
    }

    /// Reauthenticate the concrete custody lease before any pending external
    /// state is written.  The challenge covers the exact registry pre/post
    /// tuple (the database lease), while the implementation's tag binds its
    /// installation and workspace custody identity.
    pub fn verify_anchor_lease(
        &self,
        anchor: &dyn RegistryAnchorTransaction,
    ) -> Result<(), RegistryAnchorError> {
        self.validate()?;
        let observed = anchor.anchor_lease_tag(self.anchor_lease_challenge)?;
        if observed == [0; 32] || !bool::from(observed.ct_eq(&self.anchor_lease_tag)) {
            return Err(RegistryAnchorError::AuthenticationFailed);
        }
        Ok(())
    }

    /// Scheduler-only constructor for an ordinary SQLite write.  `next` must
    /// contain the exact postimage with a zero head; this function derives the
    /// only accepted successor head and closes construction before the value
    /// crosses into the external-anchor implementation.
    pub(crate) fn from_scheduler_postimage(
        anchor: &dyn RegistryAnchorTransaction,
        previous: RegistryAnchorTuple,
        mut next: RegistryAnchorTuple,
        head_context: RegistryHeadContext,
        operation_tag: u8,
        write_set_digest: [u8; 32],
    ) -> Result<Self, RegistryAnchorError> {
        if next.head != [0; 32] {
            return Err(RegistryAnchorError::InvalidTransition);
        }
        next.head = derive_next_head(
            &previous,
            &next,
            &head_context,
            operation_tag,
            write_set_digest,
        )?;
        let mutation = Self {
            previous,
            next,
            head_context,
            operation_tag,
            write_set_digest,
            anchor_lease_challenge: [0; 32],
            anchor_lease_tag: [0; 32],
        };
        mutation.validate()?;
        mutation.bind_to_anchor(anchor)
    }

    /// Test-only raw fixture constructor.  Production dependants cannot mint
    /// an anchor mutation or choose a successor head.
    #[cfg(feature = "test-support")]
    pub fn fixture_for_test(
        anchor: &dyn RegistryAnchorTransaction,
        previous: RegistryAnchorTuple,
        next: RegistryAnchorTuple,
        head_context: RegistryHeadContext,
        operation_tag: u8,
        write_set_digest: [u8; 32],
    ) -> Result<Self, RegistryAnchorError> {
        if next.head == [0; 32] {
            Self::from_scheduler_postimage(
                anchor,
                previous,
                next,
                head_context,
                operation_tag,
                write_set_digest,
            )
        } else {
            let mutation = Self {
                previous,
                next,
                head_context,
                operation_tag,
                write_set_digest,
                anchor_lease_challenge: [0; 32],
                anchor_lease_tag: [0; 32],
            };
            mutation.validate()?;
            mutation.bind_to_anchor(anchor)
        }
    }

    fn bind_to_anchor(
        mut self,
        anchor: &dyn RegistryAnchorTransaction,
    ) -> Result<Self, RegistryAnchorError> {
        let mut challenge = Sha256::new();
        challenge.update(b"advance.contract218.registry-mutation-anchor-lease.v1\0");
        challenge.update(self.binding_digest());
        self.anchor_lease_challenge = challenge.finalize().into();
        self.anchor_lease_tag = anchor.anchor_lease_tag(self.anchor_lease_challenge)?;
        if self.anchor_lease_tag == [0; 32] {
            return Err(RegistryAnchorError::AuthenticationFailed);
        }
        self.verify_anchor_lease(anchor)?;
        Ok(self)
    }

    fn binding_digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"advance.contract218.registry-mutation-capability.v1\0");
        update_tuple_digest(&mut hasher, &self.previous);
        update_tuple_digest(&mut hasher, &self.next);
        hasher.update(self.head_context.previous_marker_root);
        hasher.update(self.head_context.next_marker_root);
        hasher.update(self.head_context.manifest_key_epoch.to_be_bytes());
        hasher.update(self.head_context.next_manifest_key_epoch.to_be_bytes());
        hasher.update([self.operation_tag]);
        hasher.update(self.write_set_digest);
        hasher.finalize().into()
    }
}

impl std::fmt::Debug for RegistryAnchorMutation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RegistryAnchorMutation(<opaque move-only custody lease>)")
    }
}

/// Derive the authenticated successor head from the complete before/after
/// tuple plus the closed operation tag and write-set digest.  External anchor
/// implementations call [`RegistryAnchorMutation::validate`] before writing;
/// the provider uses this function to construct that validated mutation.
pub(crate) fn derive_next_head(
    previous: &RegistryAnchorTuple,
    next: &RegistryAnchorTuple,
    context: &RegistryHeadContext,
    operation_tag: u8,
    write_set_digest: [u8; 32],
) -> Result<[u8; 32], RegistryAnchorError> {
    if previous.registry_instance != next.registry_instance
        || previous.sequence.checked_add(1) != Some(next.sequence)
        || previous.migration_digest != next.migration_digest
        || !(1..=8).contains(&operation_tag)
    {
        return Err(RegistryAnchorError::InvalidTransition);
    }
    context.validate()?;
    let mut hasher = Sha256::new();
    hasher.update(HEAD_DOMAIN);
    hasher.update(previous.registry_instance);
    hasher.update(next.sequence.to_be_bytes());
    hasher.update(previous.head);
    hasher.update(previous.state_root);
    hasher.update(next.state_root);
    hasher.update(previous.keyring_root);
    hasher.update(next.keyring_root);
    hasher.update(previous.role_allocation_root);
    hasher.update(next.role_allocation_root);
    hasher.update(context.previous_marker_root);
    hasher.update(context.next_marker_root);
    hasher.update(context.manifest_key_epoch.to_be_bytes());
    hasher.update(context.next_manifest_key_epoch.to_be_bytes());
    hasher.update(previous.migration_digest);
    hasher.update([operation_tag]);
    hasher.update(write_set_digest);
    Ok(hasher.finalize().into())
}

/// Verify a persisted pending manifest without exposing a head-minting
/// primitive to external crates.  This is the only restart-time operation an
/// external anchor needs: it can reject a forged successor, but cannot derive
/// and package a new scheduler mutation.
pub fn verify_successor_head(
    previous: &RegistryAnchorTuple,
    next: &RegistryAnchorTuple,
    context: &RegistryHeadContext,
    operation_tag: u8,
    write_set_digest: [u8; 32],
) -> Result<(), RegistryAnchorError> {
    let expected = derive_next_head(previous, next, context, operation_tag, write_set_digest)?;
    if bool::from(expected.ct_eq(&next.head)) {
        Ok(())
    } else {
        Err(RegistryAnchorError::AuthenticationFailed)
    }
}

#[cfg(feature = "test-support")]
pub fn derive_next_head_for_test(
    previous: &RegistryAnchorTuple,
    next: &RegistryAnchorTuple,
    context: &RegistryHeadContext,
    operation_tag: u8,
    write_set_digest: [u8; 32],
) -> Result<[u8; 32], RegistryAnchorError> {
    derive_next_head(previous, next, context, operation_tag, write_set_digest)
}

fn update_tuple_digest(hasher: &mut Sha256, tuple: &RegistryAnchorTuple) {
    hasher.update(tuple.registry_instance);
    hasher.update(tuple.sequence.to_be_bytes());
    hasher.update(tuple.head);
    hasher.update(tuple.state_root);
    hasher.update(tuple.keyring_root);
    hasher.update(tuple.role_allocation_root);
    hasher.update(tuple.migration_digest);
}

fn update_anchor_world_digest(hasher: &mut Sha256, world: &RegistryAnchorWorld) {
    match world {
        RegistryAnchorWorld::PendingCurrent {
            generation,
            previous,
            next,
        } => {
            hasher.update([1]);
            hasher.update(generation.to_be_bytes());
            update_tuple_digest(hasher, previous);
            update_tuple_digest(hasher, next);
        }
        RegistryAnchorWorld::SelectedNext { generation, next } => {
            hasher.update([2]);
            hasher.update(generation.to_be_bytes());
            update_tuple_digest(hasher, next);
        }
        RegistryAnchorWorld::CompactCurrent {
            generation,
            current,
        } => {
            hasher.update([3]);
            hasher.update(generation.to_be_bytes());
            update_tuple_digest(hasher, current);
        }
    }
}

fn recovery_decision_tag(decision: RegistryRecoveryDecision) -> u8 {
    match decision {
        RegistryRecoveryDecision::RollBackPending => 1,
        RegistryRecoveryDecision::FinishPendingPromotion => 2,
        RegistryRecoveryDecision::CompactSelectedNext => 3,
        RegistryRecoveryDecision::Clean => 4,
    }
}

/// Scheduler-owned, opaque tag-6 role-manifest mutation.  The caller supplies
/// complete authenticated manifest files, never roots or a raw write-set
/// digest.  The scheduler recomputes both file roots and the canonical
/// synthetic tag-14 write-set record.
pub struct PreparedRoleAllocationMutation {
    mutation: RegistryAnchorMutation,
    previous_manifest_bytes: Vec<u8>,
    next_manifest_bytes: Vec<u8>,
}

impl PreparedRoleAllocationMutation {
    fn from_authenticated_manifests(
        anchor: &dyn RegistryAnchorTransaction,
        current: RegistryAnchorTuple,
        head_context: RegistryHeadContext,
        previous_manifest_bytes: &[u8],
        next_manifest_bytes: &[u8],
    ) -> Result<Self, RegistryAnchorError> {
        let previous_manifest =
            parse_role_manifest(previous_manifest_bytes, current.registry_instance)?;
        let next_manifest = parse_role_manifest(next_manifest_bytes, current.registry_instance)?;
        validate_role_manifest_successor(
            &previous_manifest,
            &next_manifest,
            current
                .sequence
                .checked_add(1)
                .ok_or(RegistryAnchorError::InvalidTransition)?,
        )?;
        if previous_manifest_bytes == next_manifest_bytes {
            return Err(RegistryAnchorError::InvalidTransition);
        }

        let previous_root = role_allocation_file_root(previous_manifest_bytes);
        let next_root = role_allocation_file_root(next_manifest_bytes);
        if previous_root != current.role_allocation_root || previous_root == next_root {
            return Err(RegistryAnchorError::InvalidTransition);
        }

        let write_set_digest =
            synthetic_artifact_write_set_digest(14, previous_manifest_bytes, next_manifest_bytes)?;
        let mut next = current.clone();
        next.sequence = current
            .sequence
            .checked_add(1)
            .ok_or(RegistryAnchorError::InvalidTransition)?;
        next.role_allocation_root = next_root;
        next.head = [0; 32];
        let mutation = RegistryAnchorMutation::from_scheduler_postimage(
            anchor,
            current,
            next,
            head_context,
            6,
            write_set_digest,
        )?;
        Ok(Self {
            mutation,
            previous_manifest_bytes: previous_manifest_bytes.to_vec(),
            next_manifest_bytes: next_manifest_bytes.to_vec(),
        })
    }

    #[cfg(feature = "test-support")]
    pub fn fixture_for_test(
        anchor: &dyn RegistryAnchorTransaction,
        current: RegistryAnchorTuple,
        head_context: RegistryHeadContext,
        previous_manifest_bytes: &[u8],
        next_manifest_bytes: &[u8],
    ) -> Result<Self, RegistryAnchorError> {
        Self::from_authenticated_manifests(
            anchor,
            current,
            head_context,
            previous_manifest_bytes,
            next_manifest_bytes,
        )
    }

    #[cfg(feature = "test-support")]
    pub fn database_commit_proof_for_test(
        &self,
        anchor: &dyn RegistryAnchorTransaction,
    ) -> Result<RegistryDatabaseCommitProof, RegistryAnchorError> {
        RegistryDatabaseCommitProof::fixture_for_test(anchor, &self.mutation)
    }

    pub fn previous_role_allocation_root(&self) -> [u8; 32] {
        self.mutation.previous.role_allocation_root
    }

    pub fn next_role_allocation_root(&self) -> [u8; 32] {
        self.mutation.next.role_allocation_root
    }

    /// Read-only tuple access for the custody owner's exact pre/post checks.
    pub fn previous(&self) -> &RegistryAnchorTuple {
        &self.mutation.previous
    }

    /// Read-only tuple access for the custody owner's exact pre/post checks.
    pub fn next(&self) -> &RegistryAnchorTuple {
        &self.mutation.next
    }

    /// Start the external typestate transition without exposing the raw
    /// mutation.  This is used by custody failpoint/recovery witnesses; normal
    /// provider composition passes the opaque value to the provider instead.
    #[cfg(feature = "test-support")]
    pub fn prepare_external_anchor(
        self,
        anchor: &dyn RegistryAnchorTransaction,
    ) -> Result<Box<dyn PreparedCurrent>, RegistryAnchorError> {
        anchor.authenticate_role_allocation_artifacts(
            &self.mutation.previous,
            &self.mutation.head_context,
            &self.previous_manifest_bytes,
            &self.next_manifest_bytes,
        )?;
        anchor.prepare_current(self.mutation)
    }

    pub(crate) fn into_mutation_authenticated(
        self,
        anchor: &dyn RegistryAnchorTransaction,
    ) -> Result<RegistryAnchorMutation, RegistryAnchorError> {
        anchor.authenticate_role_allocation_artifacts(
            &self.mutation.previous,
            &self.mutation.head_context,
            &self.previous_manifest_bytes,
            &self.next_manifest_bytes,
        )?;
        self.mutation.verify_anchor_lease(anchor)?;
        Ok(self.mutation)
    }
}

/// Authenticate both complete role-allocation files through the actual
/// custody/anchor implementation before constructing the scheduler-owned
/// opaque mutation.  Structural parsing alone is deliberately insufficient.
pub fn prepare_role_allocation_mutation(
    anchor: &dyn RegistryAnchorTransaction,
    current: RegistryAnchorTuple,
    head_context: RegistryHeadContext,
    previous_manifest_bytes: &[u8],
    next_manifest_bytes: &[u8],
) -> Result<PreparedRoleAllocationMutation, RegistryAnchorError> {
    anchor.authenticate_role_allocation_artifacts(
        &current,
        &head_context,
        previous_manifest_bytes,
        next_manifest_bytes,
    )?;
    PreparedRoleAllocationMutation::from_authenticated_manifests(
        anchor,
        current,
        head_context,
        previous_manifest_bytes,
        next_manifest_bytes,
    )
}

impl std::fmt::Debug for PreparedRoleAllocationMutation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PreparedRoleAllocationMutation(<opaque>)")
    }
}

/// Scheduler-owned, opaque tag-6 persisted-keyring replacement.  The custody
/// owner authenticates both complete files before calling this constructor;
/// the scheduler independently enforces their canonical framing, legal
/// generation/status successor, exact file roots, and synthetic tag-12 write
/// set.  No caller can supply a root, head, or write-set digest directly.
pub struct PreparedPersistedKeyringMutation {
    mutation: RegistryAnchorMutation,
    previous_projection: PersistedKeyringProjection,
    next_projection: PersistedKeyringProjection,
    previous_file_bytes: Vec<u8>,
    next_file_bytes: Vec<u8>,
}

impl PreparedPersistedKeyringMutation {
    fn from_authenticated_files(
        anchor: &dyn RegistryAnchorTransaction,
        current: RegistryAnchorTuple,
        head_context: RegistryHeadContext,
        previous_file_bytes: &[u8],
        next_file_bytes: &[u8],
    ) -> Result<Self, RegistryAnchorError> {
        let previous =
            parse_persisted_keyring_file(previous_file_bytes, current.registry_instance)?;
        let next = parse_persisted_keyring_file(next_file_bytes, current.registry_instance)?;
        if previous.manifest_key_epoch != head_context.manifest_key_epoch
            || next.manifest_key_epoch != head_context.next_manifest_key_epoch
            || previous_file_bytes == next_file_bytes
        {
            return Err(RegistryAnchorError::InvalidTransition);
        }

        let previous_root = persisted_keyring_file_root(previous_file_bytes);
        let next_root = persisted_keyring_file_root(next_file_bytes);
        if previous_root != current.keyring_root || previous_root == next_root {
            return Err(RegistryAnchorError::InvalidTransition);
        }
        validate_persisted_keyring_successor(&previous, &next, previous_root)?;

        let write_set_digest =
            synthetic_artifact_write_set_digest(12, previous_file_bytes, next_file_bytes)?;
        let mut next_tuple = current.clone();
        next_tuple.sequence = current
            .sequence
            .checked_add(1)
            .ok_or(RegistryAnchorError::InvalidTransition)?;
        next_tuple.keyring_root = next_root;
        next_tuple.head = [0; 32];
        let mutation = RegistryAnchorMutation::from_scheduler_postimage(
            anchor,
            current,
            next_tuple,
            head_context,
            6,
            write_set_digest,
        )?;
        Ok(Self {
            mutation,
            previous_projection: previous.into_projection(),
            next_projection: next.into_projection(),
            previous_file_bytes: previous_file_bytes.to_vec(),
            next_file_bytes: next_file_bytes.to_vec(),
        })
    }

    #[cfg(feature = "test-support")]
    pub fn fixture_for_test(
        anchor: &dyn RegistryAnchorTransaction,
        current: RegistryAnchorTuple,
        head_context: RegistryHeadContext,
        previous_file_bytes: &[u8],
        next_file_bytes: &[u8],
    ) -> Result<Self, RegistryAnchorError> {
        Self::from_authenticated_files(
            anchor,
            current,
            head_context,
            previous_file_bytes,
            next_file_bytes,
        )
    }

    #[cfg(feature = "test-support")]
    pub fn database_commit_proof_for_test(
        &self,
        anchor: &dyn RegistryAnchorTransaction,
    ) -> Result<RegistryDatabaseCommitProof, RegistryAnchorError> {
        RegistryDatabaseCommitProof::fixture_for_test(anchor, &self.mutation)
    }

    pub fn previous(&self) -> &RegistryAnchorTuple {
        &self.mutation.previous
    }

    pub fn next(&self) -> &RegistryAnchorTuple {
        &self.mutation.next
    }

    pub fn previous_keyring_root(&self) -> [u8; 32] {
        self.mutation.previous.keyring_root
    }

    pub fn next_keyring_root(&self) -> [u8; 32] {
        self.mutation.next.keyring_root
    }

    #[cfg(feature = "test-support")]
    pub fn prepare_external_anchor(
        self,
        anchor: &dyn RegistryAnchorTransaction,
    ) -> Result<Box<dyn PreparedCurrent>, RegistryAnchorError> {
        anchor.authenticate_persisted_keyring_artifacts(
            &self.mutation.previous,
            &self.mutation.head_context,
            &self.previous_file_bytes,
            &self.next_file_bytes,
        )?;
        anchor.prepare_current(self.mutation)
    }

    pub(crate) fn verify_exact_last_issued_replacement(
        &self,
        signing_key_id: u32,
        issued_at_ms: u64,
    ) -> Result<(), RegistryAnchorError> {
        if self.mutation.head_context.previous_marker_root
            != self.mutation.head_context.next_marker_root
            || self.mutation.head_context.manifest_key_epoch
                != self.mutation.head_context.next_manifest_key_epoch
            || self.previous_projection.manifest_key_epoch
                != self.next_projection.manifest_key_epoch
        {
            return Err(RegistryAnchorError::InvalidTransition);
        }
        let mut expected = self.previous_projection.clone();
        let entry = expected
            .entries
            .iter_mut()
            .find(|entry| entry.key_id == signing_key_id)
            .ok_or(RegistryAnchorError::InvalidTransition)?;
        if entry.status != PersistedKeyringStatus::Signing || entry.scan.is_some() {
            return Err(RegistryAnchorError::InvalidTransition);
        }
        entry.last_issued_at_ms = entry.last_issued_at_ms.max(issued_at_ms);
        if expected != self.next_projection {
            return Err(RegistryAnchorError::InvalidTransition);
        }
        Ok(())
    }

    pub(crate) fn verify_exact_signing_rotation(&self) -> Result<(), RegistryAnchorError> {
        if self.mutation.head_context.previous_marker_root
            != self.mutation.head_context.next_marker_root
            || self.mutation.head_context.manifest_key_epoch
                != self.mutation.head_context.next_manifest_key_epoch
            || self.previous_projection.manifest_key_epoch
                != self.next_projection.manifest_key_epoch
            || self.next_projection.entries.len() != self.previous_projection.entries.len() + 1
        {
            return Err(RegistryAnchorError::InvalidTransition);
        }
        let previous_signing = self
            .previous_projection
            .entries
            .iter()
            .find(|entry| entry.status == PersistedKeyringStatus::Signing)
            .ok_or(RegistryAnchorError::InvalidTransition)?;
        let next_signing = self
            .next_projection
            .entries
            .iter()
            .find(|entry| entry.status == PersistedKeyringStatus::Signing)
            .ok_or(RegistryAnchorError::InvalidTransition)?;
        if next_signing.key_id <= previous_signing.key_id
            || next_signing.last_issued_at_ms != 0
            || next_signing.scan.is_some()
        {
            return Err(RegistryAnchorError::InvalidTransition);
        }
        let mut expected_old = self.previous_projection.entries.clone();
        expected_old
            .iter_mut()
            .find(|entry| entry.key_id == previous_signing.key_id)
            .ok_or(RegistryAnchorError::InvalidTransition)?
            .status = PersistedKeyringStatus::VerifyOnly;
        let next_old: Vec<_> = self
            .next_projection
            .entries
            .iter()
            .filter(|entry| entry.key_id != next_signing.key_id)
            .cloned()
            .collect();
        if next_old != expected_old {
            return Err(RegistryAnchorError::InvalidTransition);
        }
        Ok(())
    }

    pub(crate) fn verify_exact_retirement(
        &self,
        key_id: u32,
        scan: PersistedKeyringScanProjection,
    ) -> Result<(), RegistryAnchorError> {
        if self.mutation.head_context.previous_marker_root
            != self.mutation.head_context.next_marker_root
            || self.mutation.head_context.manifest_key_epoch
                != self.mutation.head_context.next_manifest_key_epoch
            || self.previous_projection.manifest_key_epoch
                != self.next_projection.manifest_key_epoch
        {
            return Err(RegistryAnchorError::InvalidTransition);
        }
        let mut expected = self.previous_projection.clone();
        let entry = expected
            .entries
            .iter_mut()
            .find(|entry| entry.key_id == key_id)
            .ok_or(RegistryAnchorError::InvalidTransition)?;
        if entry.status != PersistedKeyringStatus::VerifyOnly {
            return Err(RegistryAnchorError::InvalidTransition);
        }
        entry.status = PersistedKeyringStatus::Retired;
        entry.scan = Some(scan);
        if expected != self.next_projection {
            return Err(RegistryAnchorError::InvalidTransition);
        }
        Ok(())
    }

    pub(crate) fn into_parts_authenticated(
        self,
        anchor: &dyn RegistryAnchorTransaction,
    ) -> Result<
        (
            RegistryAnchorMutation,
            PersistedKeyringProjection,
            PersistedKeyringProjection,
        ),
        RegistryAnchorError,
    > {
        anchor.authenticate_persisted_keyring_artifacts(
            &self.mutation.previous,
            &self.mutation.head_context,
            &self.previous_file_bytes,
            &self.next_file_bytes,
        )?;
        self.mutation.verify_anchor_lease(anchor)?;
        Ok((
            self.mutation,
            self.previous_projection,
            self.next_projection,
        ))
    }
}

/// Authenticate both complete persisted-keyring files through the actual
/// custody/anchor implementation before constructing the scheduler-owned
/// opaque mutation.
pub fn prepare_persisted_keyring_mutation(
    anchor: &dyn RegistryAnchorTransaction,
    current: RegistryAnchorTuple,
    head_context: RegistryHeadContext,
    previous_file_bytes: &[u8],
    next_file_bytes: &[u8],
) -> Result<PreparedPersistedKeyringMutation, RegistryAnchorError> {
    anchor.authenticate_persisted_keyring_artifacts(
        &current,
        &head_context,
        previous_file_bytes,
        next_file_bytes,
    )?;
    PreparedPersistedKeyringMutation::from_authenticated_files(
        anchor,
        current,
        head_context,
        previous_file_bytes,
        next_file_bytes,
    )
}

impl std::fmt::Debug for PreparedPersistedKeyringMutation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PreparedPersistedKeyringMutation(<opaque>)")
    }
}

pub fn persisted_keyring_file_root(complete_file_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PERSISTED_KEYRING_FILE_ROOT_DOMAIN);
    hasher.update(complete_file_bytes);
    hasher.finalize().into()
}

/// Opaque, scheduler-parsed positive legacy-migration artifact set.  The
/// external custody owner authenticates the three marker MACs and complete
/// keyring/role files first; this constructor then enforces the ratified
/// 228/298-byte framing, immutable block, forward phase order, exact target
/// roots, and migration/marker digests.
#[derive(Clone)]
pub struct PreparedLegacyRegistryMigration {
    block: [u8; 228],
    projection: LegacyRegistryMigrationProjection,
    prepared_marker: Vec<u8>,
    installed_marker: Vec<u8>,
    complete_marker: Vec<u8>,
    initial_keyring_file: Vec<u8>,
    initial_role_allocation_file: Vec<u8>,
}

impl PreparedLegacyRegistryMigration {
    fn from_authenticated_artifacts(
        migration_block: &[u8],
        prepared_marker: &[u8],
        installed_marker: &[u8],
        complete_marker: &[u8],
        initial_keyring_file: &[u8],
        initial_role_allocation_file: &[u8],
    ) -> Result<Self, RegistryAnchorError> {
        let block: [u8; 228] = migration_block
            .try_into()
            .map_err(|_| RegistryAnchorError::InvalidTransition)?;
        let projection = parse_legacy_migration_block(&block)?;
        let prepared = parse_legacy_migration_marker(prepared_marker, 1)?;
        let installed = parse_legacy_migration_marker(installed_marker, 2)?;
        let complete = parse_legacy_migration_marker(complete_marker, 3)?;
        if prepared.block != block
            || installed.block != block
            || complete.block != block
            || prepared.manifest_key_epoch != installed.manifest_key_epoch
            || installed.manifest_key_epoch != complete.manifest_key_epoch
            || prepared.nonce == installed.nonce
            || prepared.nonce == complete.nonce
            || installed.nonce == complete.nonce
        {
            return Err(RegistryAnchorError::InvalidTransition);
        }
        let (keyring_root, keyring_projection) = authenticated_persisted_keyring_projection(
            initial_keyring_file,
            projection.registry_instance,
        )?;
        parse_role_manifest(initial_role_allocation_file, projection.registry_instance)?;
        if keyring_root != projection.target_keyring_root
            || role_allocation_file_root(initial_role_allocation_file)
                != projection.target_role_allocation_root
            || keyring_projection.manifest_key_epoch != complete.manifest_key_epoch
        {
            return Err(RegistryAnchorError::InvalidTransition);
        }
        Ok(Self {
            block,
            projection,
            prepared_marker: prepared_marker.to_vec(),
            installed_marker: installed_marker.to_vec(),
            complete_marker: complete_marker.to_vec(),
            initial_keyring_file: initial_keyring_file.to_vec(),
            initial_role_allocation_file: initial_role_allocation_file.to_vec(),
        })
    }

    #[cfg(feature = "test-support")]
    pub fn fixture_for_test(
        migration_block: &[u8],
        prepared_marker: &[u8],
        installed_marker: &[u8],
        complete_marker: &[u8],
        initial_keyring_file: &[u8],
        initial_role_allocation_file: &[u8],
    ) -> Result<Self, RegistryAnchorError> {
        Self::from_authenticated_artifacts(
            migration_block,
            prepared_marker,
            installed_marker,
            complete_marker,
            initial_keyring_file,
            initial_role_allocation_file,
        )
    }

    pub fn registry_instance(&self) -> [u8; 16] {
        self.projection.registry_instance
    }

    pub fn migration_id(&self) -> [u8; 16] {
        self.projection.migration_id
    }

    pub fn target_state_root(&self) -> [u8; 32] {
        self.projection.target_state_root
    }

    pub fn target_keyring_root(&self) -> [u8; 32] {
        self.projection.target_keyring_root
    }

    pub fn target_role_allocation_root(&self) -> [u8; 32] {
        self.projection.target_role_allocation_root
    }

    pub fn migration_digest(&self) -> [u8; 32] {
        legacy_registry_migration_digest(&self.block)
    }

    pub fn complete_marker_root(&self) -> [u8; 32] {
        registry_marker_root(&self.complete_marker)
            .expect("constructor validated complete marker width")
    }

    pub fn prepared_marker_root(&self) -> [u8; 32] {
        registry_marker_root(&self.prepared_marker)
            .expect("constructor validated prepared marker width")
    }

    pub fn installed_marker_root(&self) -> [u8; 32] {
        registry_marker_root(&self.installed_marker)
            .expect("constructor validated installed marker width")
    }

    pub fn manifest_key_epoch(&self) -> u32 {
        parse_legacy_migration_marker(&self.complete_marker, 3)
            .expect("constructor validated complete marker")
            .manifest_key_epoch
    }

    pub fn legacy_file_identity_digest(&self) -> [u8; 32] {
        self.projection.legacy_file_identity_digest
    }

    pub fn legacy_projection_root(&self) -> [u8; 32] {
        self.projection.legacy_projection_root
    }

    pub fn operator_principal_digest(&self) -> [u8; 32] {
        self.projection.operator_principal_digest
    }

    pub fn prepared_marker_bytes(&self) -> &[u8] {
        &self.prepared_marker
    }

    pub fn installed_marker_bytes(&self) -> &[u8] {
        &self.installed_marker
    }

    pub fn complete_marker_bytes(&self) -> &[u8] {
        &self.complete_marker
    }

    /// Reauthenticate the exact retained bytes with the concrete anchor that
    /// will own the migration.  This prevents an object minted by a permissive
    /// or fake authenticator from crossing into a real provider.
    pub fn authenticate_with(
        &self,
        anchor: &dyn RegistryAnchorTransaction,
    ) -> Result<(), RegistryAnchorError> {
        anchor.authenticate_legacy_migration_artifacts(
            &self.block,
            &self.prepared_marker,
            &self.installed_marker,
            &self.complete_marker,
            &self.initial_keyring_file,
            &self.initial_role_allocation_file,
        )
    }

    /// Exact opaque binding shared by scheduler-issued phase witnesses.  The
    /// digest is never accepted from a caller as authority; it is recomputed
    /// only from this authenticated artifact object.
    pub(crate) fn plan_binding_digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"advance.contract218.legacy-migration-plan-binding.v1\0");
        for bytes in [
            self.block.as_slice(),
            self.prepared_marker.as_slice(),
            self.installed_marker.as_slice(),
            self.complete_marker.as_slice(),
            self.initial_keyring_file.as_slice(),
            self.initial_role_allocation_file.as_slice(),
        ] {
            hasher.update((bytes.len() as u32).to_be_bytes());
            hasher.update(bytes);
        }
        hasher.finalize().into()
    }
}

/// Authenticate the complete stopped-migration artifact set through its real
/// custody implementation before releasing an opaque scheduler plan.
pub fn prepare_legacy_registry_migration(
    anchor: &dyn RegistryAnchorTransaction,
    migration_block: &[u8],
    prepared_marker: &[u8],
    installed_marker: &[u8],
    complete_marker: &[u8],
    initial_keyring_file: &[u8],
    initial_role_allocation_file: &[u8],
) -> Result<PreparedLegacyRegistryMigration, RegistryAnchorError> {
    anchor.authenticate_legacy_migration_artifacts(
        migration_block,
        prepared_marker,
        installed_marker,
        complete_marker,
        initial_keyring_file,
        initial_role_allocation_file,
    )?;
    PreparedLegacyRegistryMigration::from_authenticated_artifacts(
        migration_block,
        prepared_marker,
        installed_marker,
        complete_marker,
        initial_keyring_file,
        initial_role_allocation_file,
    )
}

/// Opaque tag-6/synthetic-tag-13 marker replacement.  It retains the exact
/// authenticated plan so the real provider/anchor can reauthenticate custody
/// immediately before committing the transition.
pub struct PreparedLegacyMarkerMutation {
    mutation: RegistryAnchorMutation,
    migration: PreparedLegacyRegistryMigration,
    previous_marker: Vec<u8>,
    next_marker: Vec<u8>,
    next_phase: u8,
    anchor_lease_challenge: [u8; 32],
    anchor_lease_tag: [u8; 32],
}

pub(crate) struct AuthenticatedLegacyMarkerMutation {
    mutation: RegistryAnchorMutation,
    anchor_lease_challenge: [u8; 32],
    anchor_lease_tag: [u8; 32],
}

impl AuthenticatedLegacyMarkerMutation {
    pub(crate) fn mutation(&self) -> &RegistryAnchorMutation {
        &self.mutation
    }

    #[cfg(test)]
    pub(crate) fn write_set_digest(&self) -> [u8; 32] {
        self.mutation.write_set_digest()
    }

    pub(crate) fn exactly_matches(&self, other: &Self) -> bool {
        self.mutation.previous == other.mutation.previous
            && self.mutation.next == other.mutation.next
            && self.mutation.head_context == other.mutation.head_context
            && self.mutation.operation_tag == other.mutation.operation_tag
            && self.mutation.write_set_digest == other.mutation.write_set_digest
            && self.mutation.anchor_lease_challenge == other.mutation.anchor_lease_challenge
            && bool::from(
                self.mutation
                    .anchor_lease_tag
                    .ct_eq(&other.mutation.anchor_lease_tag),
            )
            && self.anchor_lease_challenge == other.anchor_lease_challenge
            && bool::from(self.anchor_lease_tag.ct_eq(&other.anchor_lease_tag))
    }

    pub(crate) fn into_parts(self) -> (RegistryAnchorMutation, [u8; 32], [u8; 32]) {
        (
            self.mutation,
            self.anchor_lease_challenge,
            self.anchor_lease_tag,
        )
    }
}

impl PreparedLegacyMarkerMutation {
    pub fn previous(&self) -> &RegistryAnchorTuple {
        &self.mutation.previous
    }

    pub fn next(&self) -> &RegistryAnchorTuple {
        &self.mutation.next
    }

    pub fn previous_marker_root(&self) -> [u8; 32] {
        self.mutation.head_context.previous_marker_root
    }

    pub fn next_marker_root(&self) -> [u8; 32] {
        self.mutation.head_context.next_marker_root
    }

    pub(crate) fn next_phase(&self) -> u8 {
        self.next_phase
    }

    pub(crate) fn plan_binding_digest(&self) -> [u8; 32] {
        self.migration.plan_binding_digest()
    }

    pub(crate) fn authenticated_mutation(
        &self,
        anchor: &dyn RegistryAnchorTransaction,
    ) -> Result<AuthenticatedLegacyMarkerMutation, RegistryAnchorError> {
        anchor.authenticate_legacy_marker_transition_artifacts(
            &self.mutation.previous,
            &self.mutation.next,
            &self.mutation.head_context,
            &self.previous_marker,
            &self.next_marker,
        )?;
        self.mutation.verify_anchor_lease(anchor)?;
        let mut postimage = self.mutation.next.clone();
        postimage.head = [0; 32];
        let rebuilt = RegistryAnchorMutation::from_scheduler_postimage(
            anchor,
            self.mutation.previous.clone(),
            postimage,
            self.mutation.head_context.clone(),
            self.mutation.operation_tag,
            self.mutation.write_set_digest,
        )?;
        if rebuilt.next != self.mutation.next {
            return Err(RegistryAnchorError::AuthenticationFailed);
        }
        let (anchor_lease_challenge, anchor_lease_tag) = legacy_marker_anchor_lease_binding(
            anchor,
            &self.migration,
            rebuilt.next(),
            self.next_phase,
        )?;
        if anchor_lease_challenge != self.anchor_lease_challenge
            || !bool::from(anchor_lease_tag.ct_eq(&self.anchor_lease_tag))
        {
            return Err(RegistryAnchorError::AuthenticationFailed);
        }
        Ok(AuthenticatedLegacyMarkerMutation {
            mutation: rebuilt,
            anchor_lease_challenge,
            anchor_lease_tag,
        })
    }
}

impl std::fmt::Debug for PreparedLegacyMarkerMutation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PreparedLegacyMarkerMutation(<opaque>)")
    }
}

fn prepare_legacy_marker_mutation(
    anchor: &dyn RegistryAnchorTransaction,
    migration: &PreparedLegacyRegistryMigration,
    current: RegistryAnchorTuple,
    head_context: RegistryHeadContext,
    previous_marker: &[u8],
    next_marker: &[u8],
    next_phase: u8,
) -> Result<PreparedLegacyMarkerMutation, RegistryAnchorError> {
    if current.registry_instance != migration.registry_instance()
        || current.migration_digest != migration.migration_digest()
        || head_context.manifest_key_epoch != migration.manifest_key_epoch()
        || head_context.next_manifest_key_epoch != migration.manifest_key_epoch()
        || registry_marker_root(previous_marker)? != head_context.previous_marker_root
        || registry_marker_root(next_marker)? != head_context.next_marker_root
        || previous_marker == next_marker
        || !matches!(next_phase, 2 | 3)
    {
        return Err(RegistryAnchorError::InvalidTransition);
    }
    if next_phase == 2
        && (current.sequence != 0
            || current.state_root != migration.target_state_root()
            || current.keyring_root != migration.target_keyring_root()
            || current.role_allocation_root != migration.target_role_allocation_root())
    {
        return Err(RegistryAnchorError::InvalidTransition);
    }
    let write_set_digest = synthetic_artifact_write_set_digest(13, previous_marker, next_marker)?;
    let mut next = current.clone();
    next.sequence = current
        .sequence
        .checked_add(1)
        .ok_or(RegistryAnchorError::InvalidTransition)?;
    next.head = [0; 32];
    let mutation = RegistryAnchorMutation::from_scheduler_postimage(
        anchor,
        current,
        next,
        head_context,
        6,
        write_set_digest,
    )?;
    anchor.authenticate_legacy_marker_transition_artifacts(
        &mutation.previous,
        &mutation.next,
        &mutation.head_context,
        previous_marker,
        next_marker,
    )?;
    let (anchor_lease_challenge, anchor_lease_tag) =
        legacy_marker_anchor_lease_binding(anchor, migration, mutation.next(), next_phase)?;
    Ok(PreparedLegacyMarkerMutation {
        mutation,
        migration: migration.clone(),
        previous_marker: previous_marker.to_vec(),
        next_marker: next_marker.to_vec(),
        next_phase,
        anchor_lease_challenge,
        anchor_lease_tag,
    })
}

pub(crate) fn legacy_marker_anchor_lease_binding(
    anchor: &dyn RegistryAnchorTransaction,
    migration: &PreparedLegacyRegistryMigration,
    next: &RegistryAnchorTuple,
    next_phase: u8,
) -> Result<([u8; 32], [u8; 32]), RegistryAnchorError> {
    if !matches!(next_phase, 2 | 3)
        || next.registry_instance != migration.registry_instance()
        || next.migration_digest != migration.migration_digest()
    {
        return Err(RegistryAnchorError::InvalidTransition);
    }
    let mut lease = Sha256::new();
    lease.update(b"advance.contract218.marker-anchor-lease-challenge.v1\0");
    lease.update(migration.plan_binding_digest());
    update_tuple_digest(&mut lease, next);
    lease.update([next_phase]);
    let challenge: [u8; 32] = lease.finalize().into();
    let tag = anchor.anchor_lease_tag(challenge)?;
    if tag == [0; 32] {
        return Err(RegistryAnchorError::AuthenticationFailed);
    }
    Ok((challenge, tag))
}

pub(crate) fn prepare_legacy_installed_marker_mutation(
    anchor: &dyn RegistryAnchorTransaction,
    migration: &PreparedLegacyRegistryMigration,
    current: RegistryAnchorTuple,
    head_context: RegistryHeadContext,
) -> Result<PreparedLegacyMarkerMutation, RegistryAnchorError> {
    prepare_legacy_marker_mutation(
        anchor,
        migration,
        current,
        head_context,
        migration.prepared_marker_bytes(),
        migration.installed_marker_bytes(),
        2,
    )
}

pub(crate) fn prepare_legacy_complete_marker_mutation(
    anchor: &dyn RegistryAnchorTransaction,
    migration: &PreparedLegacyRegistryMigration,
    current: RegistryAnchorTuple,
    head_context: RegistryHeadContext,
) -> Result<PreparedLegacyMarkerMutation, RegistryAnchorError> {
    prepare_legacy_marker_mutation(
        anchor,
        migration,
        current,
        head_context,
        migration.installed_marker_bytes(),
        migration.complete_marker_bytes(),
        3,
    )
}

impl std::fmt::Debug for PreparedLegacyRegistryMigration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PreparedLegacyRegistryMigration(<opaque>)")
    }
}

pub fn legacy_registry_migration_digest(block: &[u8; 228]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(MIGRATION_DIGEST_DOMAIN);
    hasher.update([2]);
    hasher.update(228_u16.to_be_bytes());
    hasher.update(block);
    hasher.finalize().into()
}

pub fn registry_marker_root(marker: &[u8]) -> Result<[u8; 32], RegistryAnchorError> {
    if !matches!(marker.len(), 0 | 298) {
        return Err(RegistryAnchorError::InvalidTransition);
    }
    let mut hasher = Sha256::new();
    hasher.update(MIGRATION_MARKER_ROOT_DOMAIN);
    hasher.update((marker.len() as u32).to_be_bytes());
    hasher.update(marker);
    Ok(hasher.finalize().into())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LegacyRegistryMigrationProjection {
    migration_id: [u8; 16],
    registry_instance: [u8; 16],
    legacy_file_identity_digest: [u8; 32],
    legacy_projection_root: [u8; 32],
    target_state_root: [u8; 32],
    target_keyring_root: [u8; 32],
    target_role_allocation_root: [u8; 32],
    operator_principal_digest: [u8; 32],
}

fn parse_legacy_migration_block(
    block: &[u8; 228],
) -> Result<LegacyRegistryMigrationProjection, RegistryAnchorError> {
    let mut cursor = RoleManifestCursor {
        bytes: block,
        offset: 0,
    };
    let migration_id = cursor.array::<16>()?;
    let registry_instance = cursor.array::<16>()?;
    let legacy_file_identity_digest = cursor.array::<32>()?;
    let legacy_projection_root = cursor.array::<32>()?;
    if cursor.u32()? != 1 {
        return Err(RegistryAnchorError::InvalidTransition);
    }
    let target_state_root = cursor.array::<32>()?;
    let target_keyring_root = cursor.array::<32>()?;
    let target_role_allocation_root = cursor.array::<32>()?;
    let operator_principal_digest = cursor.array::<32>()?;
    if migration_id == [0; 16]
        || registry_instance == [0; 16]
        || legacy_file_identity_digest == [0; 32]
        || legacy_projection_root == [0; 32]
        || target_state_root == [0; 32]
        || target_keyring_root == [0; 32]
        || target_role_allocation_root == [0; 32]
        || operator_principal_digest == [0; 32]
        || cursor.offset != block.len()
    {
        return Err(RegistryAnchorError::InvalidTransition);
    }
    Ok(LegacyRegistryMigrationProjection {
        migration_id,
        registry_instance,
        legacy_file_identity_digest,
        legacy_projection_root,
        target_state_root,
        target_keyring_root,
        target_role_allocation_root,
        operator_principal_digest,
    })
}

struct ParsedLegacyMigrationMarker {
    manifest_key_epoch: u32,
    block: [u8; 228],
    nonce: [u8; 32],
}

fn parse_legacy_migration_marker(
    bytes: &[u8],
    expected_phase: u8,
) -> Result<ParsedLegacyMigrationMarker, RegistryAnchorError> {
    if bytes.len() != 298 {
        return Err(RegistryAnchorError::InvalidTransition);
    }
    let mut cursor = RoleManifestCursor { bytes, offset: 0 };
    if cursor.u8()? != 1 {
        return Err(RegistryAnchorError::InvalidTransition);
    }
    let manifest_key_epoch = cursor.u32()?;
    let block = cursor.array::<228>()?;
    let phase = cursor.u8()?;
    let nonce = cursor.array::<32>()?;
    let _mac = cursor.array::<32>()?;
    if manifest_key_epoch == 0
        || phase != expected_phase
        || nonce == [0; 32]
        || cursor.offset != bytes.len()
    {
        return Err(RegistryAnchorError::InvalidTransition);
    }
    Ok(ParsedLegacyMigrationMarker {
        manifest_key_epoch,
        block,
        nonce,
    })
}

pub(crate) fn authenticated_persisted_keyring_projection(
    complete_file_bytes: &[u8],
    registry_instance: [u8; 16],
) -> Result<([u8; 32], PersistedKeyringProjection), RegistryAnchorError> {
    let parsed = parse_persisted_keyring_file(complete_file_bytes, registry_instance)?;
    Ok((
        persisted_keyring_file_root(complete_file_bytes),
        parsed.into_projection(),
    ))
}

pub fn role_allocation_file_root(complete_manifest_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ROLE_ALLOCATION_FILE_ROOT_DOMAIN);
    hasher.update(complete_manifest_bytes);
    hasher.finalize().into()
}

#[cfg(test)]
fn validate_role_manifest_header(
    bytes: &[u8],
    expected_registry_instance: [u8; 16],
) -> Result<(), RegistryAnchorError> {
    parse_role_manifest(bytes, expected_registry_instance).map(|_| ())
}

fn validate_role_manifest_successor(
    previous: &ParsedRoleManifest,
    next: &ParsedRoleManifest,
    target_registry_sequence: u64,
) -> Result<(), RegistryAnchorError> {
    if previous.generation.checked_add(1) != Some(next.generation)
        || next.next_allocation_sequence < previous.next_allocation_sequence
    {
        return Err(RegistryAnchorError::InvalidTransition);
    }

    for (key, old) in &previous.entries {
        let new = next
            .entries
            .get(key)
            .ok_or(RegistryAnchorError::InvalidTransition)?;
        if old.allocation_sequence != new.allocation_sequence
            || old.created_registry_sequence != new.created_registry_sequence
        {
            return Err(RegistryAnchorError::InvalidTransition);
        }
        match (&old.state, &new.state) {
            (ParsedRoleEntryState::Active, ParsedRoleEntryState::Active) => {}
            (
                ParsedRoleEntryState::Active,
                ParsedRoleEntryState::Erased {
                    erased_registry_sequence,
                    dependency_high_water,
                },
            ) if *erased_registry_sequence == target_registry_sequence
                && dependency_high_water.checked_add(1) == Some(target_registry_sequence) => {}
            (ParsedRoleEntryState::Erased { .. }, ParsedRoleEntryState::Erased { .. })
                if old.canonical_bytes == new.canonical_bytes => {}
            _ => return Err(RegistryAnchorError::InvalidTransition),
        }
    }

    for (key, entry) in &next.entries {
        if !previous.entries.contains_key(key)
            && (!matches!(entry.state, ParsedRoleEntryState::Active)
                || entry.allocation_sequence < previous.next_allocation_sequence
                || entry.created_registry_sequence != target_registry_sequence)
        {
            return Err(RegistryAnchorError::InvalidTransition);
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ParsedPersistedKeyring {
    manifest_key_epoch: u32,
    generation: u64,
    previous_keyring_root: [u8; 32],
    kdf_salt: [u8; 32],
    next_key_id: u64,
    signing_key_id: u32,
    entries: std::collections::BTreeMap<u32, ParsedPersistedKeyringEntry>,
}

impl ParsedPersistedKeyring {
    fn into_projection(self) -> PersistedKeyringProjection {
        PersistedKeyringProjection {
            manifest_key_epoch: self.manifest_key_epoch,
            entries: self
                .entries
                .into_values()
                .map(|entry| PersistedKeyringEntryProjection {
                    key_id: entry.key_id,
                    status: entry.status,
                    master_key_epoch: entry.master_key_epoch,
                    last_issued_at_ms: entry.last_issued_at_ms,
                    scan: entry.scan,
                })
                .collect(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ParsedPersistedKeyringEntry {
    key_id: u32,
    status: PersistedKeyringStatus,
    master_key_epoch: u32,
    last_issued_at_ms: u64,
    scan: Option<PersistedKeyringScanProjection>,
    canonical_bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PersistedKeyringStatus {
    Signing,
    VerifyOnly,
    Retired,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PersistedKeyringScanProjection {
    pub sqlite_scan_sequence: u64,
    pub jsonl_inventory_digest: [u8; 32],
    pub jsonl_segment_count: u64,
    pub jsonl_byte_count: u64,
    pub retention_high_water_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PersistedKeyringEntryProjection {
    pub key_id: u32,
    pub status: PersistedKeyringStatus,
    pub master_key_epoch: u32,
    pub last_issued_at_ms: u64,
    pub scan: Option<PersistedKeyringScanProjection>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PersistedKeyringProjection {
    pub manifest_key_epoch: u32,
    pub entries: Vec<PersistedKeyringEntryProjection>,
}

fn parse_persisted_keyring_file(
    bytes: &[u8],
    expected_registry_instance: [u8; 16],
) -> Result<ParsedPersistedKeyring, RegistryAnchorError> {
    // Header + nonce + MAC.  Authentication belongs to the external custody
    // owner; this parser rejects every alternate width/order/trailing form.
    const MIN_LEN: usize = 1 + 4 + 16 + 8 + 32 + 32 + 8 + 4 + 4 + 32 + 32;
    if bytes.len() < MIN_LEN {
        return Err(RegistryAnchorError::InvalidTransition);
    }
    let mut cursor = RoleManifestCursor { bytes, offset: 0 };
    if cursor.u8()? != 1 {
        return Err(RegistryAnchorError::InvalidTransition);
    }
    let manifest_key_epoch = cursor.u32()?;
    let registry_instance = cursor.array::<16>()?;
    let generation = cursor.u64()?;
    let previous_keyring_root = cursor.array::<32>()?;
    let kdf_salt = cursor.array::<32>()?;
    let next_key_id = cursor.u64()?;
    let signing_key_id = cursor.u32()?;
    let entry_count = cursor.u32()?;
    if manifest_key_epoch == 0
        || registry_instance != expected_registry_instance
        || expected_registry_instance == [0; 16]
        || kdf_salt == [0; 32]
        || entry_count == 0
        || signing_key_id == 0
    {
        return Err(RegistryAnchorError::InvalidTransition);
    }
    if (generation == 0 && previous_keyring_root != [0; 32])
        || (generation != 0 && previous_keyring_root == [0; 32])
    {
        return Err(RegistryAnchorError::InvalidTransition);
    }

    let entry_capacity =
        usize::try_from(entry_count).map_err(|_| RegistryAnchorError::InvalidTransition)?;
    let mut entries = std::collections::BTreeMap::new();
    let mut previous_id = 0_u32;
    let mut signing_count = 0_u32;
    for _ in 0..entry_capacity {
        let start = cursor.offset;
        let key_id = cursor.u32()?;
        let status = match cursor.u8()? {
            1 => PersistedKeyringStatus::Signing,
            2 => PersistedKeyringStatus::VerifyOnly,
            3 => PersistedKeyringStatus::Retired,
            _ => return Err(RegistryAnchorError::InvalidTransition),
        };
        let master_key_epoch = cursor.u32()?;
        let last_issued_at_ms = cursor.u64()?;
        let scan = match cursor.u8()? {
            0 => None,
            1 => Some(PersistedKeyringScanProjection {
                sqlite_scan_sequence: cursor.u64()?,
                jsonl_inventory_digest: cursor.array::<32>()?,
                jsonl_segment_count: cursor.u64()?,
                jsonl_byte_count: cursor.u64()?,
                retention_high_water_ms: cursor.u64()?,
            }),
            _ => return Err(RegistryAnchorError::InvalidTransition),
        };
        if key_id == 0
            || key_id <= previous_id
            || master_key_epoch == 0
            || (status == PersistedKeyringStatus::Signing && scan.is_some())
            || (status == PersistedKeyringStatus::Retired && scan.is_none())
        {
            return Err(RegistryAnchorError::InvalidTransition);
        }
        if status == PersistedKeyringStatus::Signing {
            signing_count = signing_count
                .checked_add(1)
                .ok_or(RegistryAnchorError::InvalidTransition)?;
            if key_id != signing_key_id {
                return Err(RegistryAnchorError::InvalidTransition);
            }
        }
        previous_id = key_id;
        let canonical_bytes = bytes[start..cursor.offset].to_vec();
        entries.insert(
            key_id,
            ParsedPersistedKeyringEntry {
                key_id,
                status,
                master_key_epoch,
                last_issued_at_ms,
                scan,
                canonical_bytes,
            },
        );
    }
    if signing_count != 1
        || u64::from(previous_id).checked_add(1) != Some(next_key_id)
        || entries.len() != entry_capacity
    {
        return Err(RegistryAnchorError::InvalidTransition);
    }
    let manifest_nonce = cursor.array::<32>()?;
    let _manifest_mac = cursor.array::<32>()?;
    if manifest_nonce == [0; 32] || cursor.offset != bytes.len() {
        return Err(RegistryAnchorError::InvalidTransition);
    }
    Ok(ParsedPersistedKeyring {
        manifest_key_epoch,
        generation,
        previous_keyring_root,
        kdf_salt,
        next_key_id,
        signing_key_id,
        entries,
    })
}

fn validate_persisted_keyring_successor(
    previous: &ParsedPersistedKeyring,
    next: &ParsedPersistedKeyring,
    previous_file_root: [u8; 32],
) -> Result<(), RegistryAnchorError> {
    if previous.generation.checked_add(1) != Some(next.generation)
        || next.previous_keyring_root != previous_file_root
        || previous.kdf_salt != next.kdf_salt
        || next.entries.len() < previous.entries.len()
        || next.entries.len() > previous.entries.len() + 1
    {
        return Err(RegistryAnchorError::InvalidTransition);
    }

    for (key_id, old) in &previous.entries {
        let new = next
            .entries
            .get(key_id)
            .ok_or(RegistryAnchorError::InvalidTransition)?;
        if old.master_key_epoch != new.master_key_epoch
            || new.last_issued_at_ms < old.last_issued_at_ms
            || (old.status != PersistedKeyringStatus::Signing
                && new.last_issued_at_ms != old.last_issued_at_ms)
        {
            return Err(RegistryAnchorError::InvalidTransition);
        }
        let legal_status = matches!(
            (old.status, new.status),
            (
                PersistedKeyringStatus::Signing,
                PersistedKeyringStatus::Signing
            ) | (
                PersistedKeyringStatus::Signing,
                PersistedKeyringStatus::VerifyOnly
            ) | (
                PersistedKeyringStatus::VerifyOnly,
                PersistedKeyringStatus::VerifyOnly
            ) | (
                PersistedKeyringStatus::VerifyOnly,
                PersistedKeyringStatus::Retired
            ) | (
                PersistedKeyringStatus::Retired,
                PersistedKeyringStatus::Retired
            )
        );
        if !legal_status
            || (old.status == PersistedKeyringStatus::Retired
                && old.canonical_bytes != new.canonical_bytes)
            || !scan_projection_is_successor(old.scan.as_ref(), new.scan.as_ref())
        {
            return Err(RegistryAnchorError::InvalidTransition);
        }
    }

    if next.entries.len() == previous.entries.len() {
        if next.next_key_id != previous.next_key_id
            || next.signing_key_id != previous.signing_key_id
        {
            return Err(RegistryAnchorError::InvalidTransition);
        }
    } else {
        let allocated_id = u32::try_from(previous.next_key_id)
            .map_err(|_| RegistryAnchorError::InvalidTransition)?;
        let allocated = next
            .entries
            .get(&allocated_id)
            .ok_or(RegistryAnchorError::InvalidTransition)?;
        let old_signing = previous
            .entries
            .get(&previous.signing_key_id)
            .ok_or(RegistryAnchorError::InvalidTransition)?;
        let old_signing_next = next
            .entries
            .get(&previous.signing_key_id)
            .ok_or(RegistryAnchorError::InvalidTransition)?;
        if allocated.status != PersistedKeyringStatus::Signing
            || allocated.scan.is_some()
            || allocated.last_issued_at_ms != 0
            || next.signing_key_id != allocated_id
            || old_signing.status != PersistedKeyringStatus::Signing
            || old_signing_next.status != PersistedKeyringStatus::VerifyOnly
            || next.next_key_id
                != previous
                    .next_key_id
                    .checked_add(1)
                    .ok_or(RegistryAnchorError::InvalidTransition)?
        {
            return Err(RegistryAnchorError::InvalidTransition);
        }
    }
    Ok(())
}

fn scan_projection_is_successor(
    previous: Option<&PersistedKeyringScanProjection>,
    next: Option<&PersistedKeyringScanProjection>,
) -> bool {
    match (previous, next) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(previous), Some(next)) => {
            next.sqlite_scan_sequence >= previous.sqlite_scan_sequence
                && next.jsonl_segment_count >= previous.jsonl_segment_count
                && next.jsonl_byte_count >= previous.jsonl_byte_count
                && next.retention_high_water_ms >= previous.retention_high_water_ms
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ParsedRoleManifest {
    manifest_key_epoch: u32,
    generation: u64,
    next_allocation_sequence: u64,
    entries: std::collections::BTreeMap<([u8; 16], u32), ParsedRoleEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ParsedRoleEntry {
    allocation_sequence: u64,
    created_registry_sequence: u64,
    state: ParsedRoleEntryState,
    canonical_bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ParsedRoleEntryState {
    Active,
    Erased {
        erased_registry_sequence: u64,
        dependency_high_water: u64,
    },
}

fn parse_role_manifest(
    bytes: &[u8],
    expected_registry_instance: [u8; 16],
) -> Result<ParsedRoleManifest, RegistryAnchorError> {
    // The custody owner remains responsible for authenticating the MAC.  The
    // scheduler independently validates the complete canonical framing so an
    // alternate family width, nonce width, option grammar, generation, or
    // trailing-byte representation cannot acquire a canonical file root.
    const MIN_LEN: usize = 1 + 4 + 16 + 8 + 8 + 4 + 32 + 32;
    if bytes.len() < MIN_LEN {
        return Err(RegistryAnchorError::InvalidTransition);
    }
    let mut cursor = RoleManifestCursor { bytes, offset: 0 };
    if cursor.u8()? != 1 {
        return Err(RegistryAnchorError::InvalidTransition);
    }
    let manifest_key_epoch = cursor.u32()?;
    if manifest_key_epoch == 0 {
        return Err(RegistryAnchorError::InvalidTransition);
    }
    if cursor.array::<16>()? != expected_registry_instance {
        return Err(RegistryAnchorError::InvalidTransition);
    }
    let generation = cursor.u64()?;
    let next_allocation_sequence = cursor.u64()?;
    let entry_count = cursor.u32()?;
    if entry_count > 65_536 || next_allocation_sequence == 0 {
        return Err(RegistryAnchorError::InvalidTransition);
    }

    let mut previous_key: Option<([u8; 16], u32)> = None;
    let mut maximum_allocation_sequence = 0_u64;
    let mut allocation_sequences = std::collections::BTreeSet::new();
    let mut entries = std::collections::BTreeMap::new();
    for _ in 0..entry_count {
        let entry_start = cursor.offset;
        let boot = cursor.array::<16>()?;
        let family = cursor.u32()?;
        let allocation_sequence = cursor.u64()?;
        let state = cursor.u8()?;
        let wrap_key_epoch = cursor.u32()?;
        let previsible_nonce = cursor.option_array::<24>()?;
        let previsible_ciphertext = cursor.option_array::<48>()?;
        let cleanup_nonce = cursor.option_array::<24>()?;
        let cleanup_ciphertext = cursor.option_array::<48>()?;
        let created_registry_sequence = cursor.u64()?;
        let erased_registry_sequence = cursor.option_u64()?;
        let dependency_high_water = cursor.u64()?;

        let key = (boot, family);
        if boot == [0; 16]
            || family != 1
            || allocation_sequence == 0
            || wrap_key_epoch == 0
            || created_registry_sequence == 0
            || previous_key
                .as_ref()
                .is_some_and(|previous| previous >= &key)
            || !allocation_sequences.insert(allocation_sequence)
        {
            return Err(RegistryAnchorError::InvalidTransition);
        }
        previous_key = Some(key);
        maximum_allocation_sequence = maximum_allocation_sequence.max(allocation_sequence);

        let parsed_state = match state {
            1 if erased_registry_sequence.is_none()
                && dependency_high_water == 0
                && previsible_nonce.is_some_and(|nonce| nonce != [0; 24])
                && cleanup_nonce.is_some_and(|nonce| nonce != [0; 24])
                && previsible_nonce != cleanup_nonce
                && previsible_ciphertext.is_some()
                && cleanup_ciphertext.is_some() =>
            {
                ParsedRoleEntryState::Active
            }
            2 if previsible_nonce.is_none()
                && previsible_ciphertext.is_none()
                && cleanup_nonce.is_none()
                && cleanup_ciphertext.is_none()
                && erased_registry_sequence.is_some_and(|erased| {
                    erased > created_registry_sequence
                        && dependency_high_water.checked_add(1) == Some(erased)
                }) =>
            {
                ParsedRoleEntryState::Erased {
                    erased_registry_sequence: erased_registry_sequence
                        .ok_or(RegistryAnchorError::InvalidTransition)?,
                    dependency_high_water,
                }
            }
            _ => return Err(RegistryAnchorError::InvalidTransition),
        };
        entries.insert(
            key,
            ParsedRoleEntry {
                allocation_sequence,
                created_registry_sequence,
                state: parsed_state,
                canonical_bytes: bytes[entry_start..cursor.offset].to_vec(),
            },
        );
    }

    if (entry_count == 0 && (generation != 0 || next_allocation_sequence != 1))
        || (entry_count != 0
            && (generation == 0
                || maximum_allocation_sequence.checked_add(1) != Some(next_allocation_sequence)))
    {
        return Err(RegistryAnchorError::InvalidTransition);
    }
    let manifest_nonce = cursor.array::<32>()?;
    let _manifest_mac = cursor.array::<32>()?;
    if manifest_nonce == [0; 32] || cursor.offset != bytes.len() {
        return Err(RegistryAnchorError::InvalidTransition);
    }
    Ok(ParsedRoleManifest {
        manifest_key_epoch,
        generation,
        next_allocation_sequence,
        entries,
    })
}

struct RoleManifestCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl RoleManifestCursor<'_> {
    fn u8(&mut self) -> Result<u8, RegistryAnchorError> {
        Ok(self.array::<1>()?[0])
    }

    fn u32(&mut self) -> Result<u32, RegistryAnchorError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, RegistryAnchorError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn option_u64(&mut self) -> Result<Option<u64>, RegistryAnchorError> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.u64()?)),
            _ => Err(RegistryAnchorError::InvalidTransition),
        }
    }

    fn option_array<const N: usize>(&mut self) -> Result<Option<[u8; N]>, RegistryAnchorError> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.array()?)),
            _ => Err(RegistryAnchorError::InvalidTransition),
        }
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], RegistryAnchorError> {
        let end = self
            .offset
            .checked_add(N)
            .ok_or(RegistryAnchorError::InvalidTransition)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(RegistryAnchorError::InvalidTransition)?;
        self.offset = end;
        value
            .try_into()
            .map_err(|_| RegistryAnchorError::InvalidTransition)
    }
}

fn synthetic_artifact_write_set_digest(
    table_tag: u8,
    before: &[u8],
    after: &[u8],
) -> Result<[u8; 32], RegistryAnchorError> {
    let before_len =
        u32::try_from(before.len()).map_err(|_| RegistryAnchorError::InvalidTransition)?;
    let after_len =
        u32::try_from(after.len()).map_err(|_| RegistryAnchorError::InvalidTransition)?;
    let key = 1_u64.to_be_bytes();
    let mut hasher = Sha256::new();
    hasher.update(WRITE_SET_DOMAIN);
    hasher.update(1_u32.to_be_bytes());
    hasher.update([table_tag]);
    hasher.update((key.len() as u32).to_be_bytes());
    hasher.update(key);
    hasher.update(before_len.to_be_bytes());
    hasher.update(before);
    hasher.update(after_len.to_be_bytes());
    hasher.update(after);
    Ok(hasher.finalize().into())
}

/// Move-only proof that the exact successor named by one scheduler-issued
/// mutation was committed, checkpointed, and re-read from the SQLite ledger.
/// Its constructor is scheduler-private, so an external caller cannot advance
/// the platform selector by echoing a tuple it merely learned from the
/// mutation.
pub struct RegistryDatabaseCommitProof {
    mutation_binding: [u8; 32],
    committed: RegistryAnchorTuple,
    anchor_lease_challenge: [u8; 32],
    anchor_lease_tag: [u8; 32],
}

/// Scheduler-private move-only issuer retained across consumption of the
/// mutation by `prepare_current`.  It can release a database-commit proof only
/// for the exact postimage re-read after SQLite durability.
pub(crate) struct RegistryDatabaseCommitProofIssuer {
    mutation_binding: [u8; 32],
    committed: RegistryAnchorTuple,
    anchor_lease_challenge: [u8; 32],
    anchor_lease_tag: [u8; 32],
}

impl RegistryDatabaseCommitProofIssuer {
    pub(crate) fn for_mutation(
        anchor: &dyn RegistryAnchorTransaction,
        mutation: &RegistryAnchorMutation,
    ) -> Result<Self, RegistryAnchorError> {
        mutation.verify_anchor_lease(anchor)?;
        let mut challenge = Sha256::new();
        challenge.update(b"advance.contract218.database-commit-anchor-lease.v1\0");
        challenge.update(mutation.binding_digest());
        update_tuple_digest(&mut challenge, mutation.next());
        let anchor_lease_challenge: [u8; 32] = challenge.finalize().into();
        let anchor_lease_tag = anchor.anchor_lease_tag(anchor_lease_challenge)?;
        if anchor_lease_tag == [0; 32] {
            return Err(RegistryAnchorError::AuthenticationFailed);
        }
        Ok(Self {
            mutation_binding: mutation.binding_digest(),
            committed: mutation.next().clone(),
            anchor_lease_challenge,
            anchor_lease_tag,
        })
    }

    pub(crate) fn from_durable_reread(
        self,
        anchor: &dyn RegistryAnchorTransaction,
        committed: RegistryAnchorTuple,
    ) -> Result<RegistryDatabaseCommitProof, RegistryAnchorError> {
        if committed != self.committed {
            return Err(RegistryAnchorError::InvalidTransition);
        }
        let observed = anchor.anchor_lease_tag(self.anchor_lease_challenge)?;
        if observed == [0; 32] || !bool::from(observed.ct_eq(&self.anchor_lease_tag)) {
            return Err(RegistryAnchorError::AuthenticationFailed);
        }
        Ok(RegistryDatabaseCommitProof {
            mutation_binding: self.mutation_binding,
            committed,
            anchor_lease_challenge: self.anchor_lease_challenge,
            anchor_lease_tag: self.anchor_lease_tag,
        })
    }
}

impl RegistryDatabaseCommitProof {
    pub fn committed(&self) -> &RegistryAnchorTuple {
        &self.committed
    }

    pub fn verify_for(&self, mutation: &RegistryAnchorMutation) -> Result<(), RegistryAnchorError> {
        if self.committed != mutation.next
            || !bool::from(self.mutation_binding.ct_eq(&mutation.binding_digest()))
        {
            return Err(RegistryAnchorError::AuthenticationFailed);
        }
        Ok(())
    }

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

    #[cfg(feature = "test-support")]
    pub(crate) fn from_durable_reread(
        anchor: &dyn RegistryAnchorTransaction,
        mutation: &RegistryAnchorMutation,
        committed: RegistryAnchorTuple,
    ) -> Result<Self, RegistryAnchorError> {
        RegistryDatabaseCommitProofIssuer::for_mutation(anchor, mutation)?
            .from_durable_reread(anchor, committed)
    }

    #[cfg(feature = "test-support")]
    pub fn fixture_for_test(
        anchor: &dyn RegistryAnchorTransaction,
        mutation: &RegistryAnchorMutation,
    ) -> Result<Self, RegistryAnchorError> {
        Self::from_durable_reread(anchor, mutation, mutation.next.clone())
    }
}

impl std::fmt::Debug for RegistryDatabaseCommitProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RegistryDatabaseCommitProof(<opaque>)")
    }
}

/// Scheduler-issued, move-only authorization for exactly one recovery world.
/// It binds the authenticated external world observed under the provider's
/// mutation lock to the tuple re-read from SQLite.  The external store must
/// re-observe the same world before applying the closed recovery decision.
pub struct RegistryRecoveryCapability {
    external: RegistryAnchorWorld,
    ledger: RegistryAnchorTuple,
    decision: RegistryRecoveryDecision,
    anchor_lease_challenge: [u8; 32],
    anchor_lease_tag: [u8; 32],
}

impl RegistryRecoveryCapability {
    pub fn external(&self) -> &RegistryAnchorWorld {
        &self.external
    }

    pub fn ledger(&self) -> &RegistryAnchorTuple {
        &self.ledger
    }

    pub fn decision(&self) -> RegistryRecoveryDecision {
        self.decision
    }

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

    pub(crate) fn from_durable_reread(
        anchor: &dyn RegistryAnchorTransaction,
        external: RegistryAnchorWorld,
        ledger: RegistryAnchorTuple,
    ) -> Result<Self, RegistryAnchorError> {
        let decision = classify_recovery(&external, &ledger)?;
        let mut challenge = Sha256::new();
        challenge.update(b"advance.contract218.recovery-anchor-lease.v1\0");
        update_anchor_world_digest(&mut challenge, &external);
        update_tuple_digest(&mut challenge, &ledger);
        challenge.update([recovery_decision_tag(decision)]);
        let anchor_lease_challenge: [u8; 32] = challenge.finalize().into();
        let anchor_lease_tag = anchor.anchor_lease_tag(anchor_lease_challenge)?;
        if anchor_lease_tag == [0; 32] {
            return Err(RegistryAnchorError::AuthenticationFailed);
        }
        Ok(Self {
            external,
            ledger,
            decision,
            anchor_lease_challenge,
            anchor_lease_tag,
        })
    }

    #[cfg(feature = "test-support")]
    pub fn fixture_for_test(
        anchor: &dyn RegistryAnchorTransaction,
        external: RegistryAnchorWorld,
        ledger: RegistryAnchorTuple,
    ) -> Result<Self, RegistryAnchorError> {
        Self::from_durable_reread(anchor, external, ledger)
    }
}

impl std::fmt::Debug for RegistryRecoveryCapability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RegistryRecoveryCapability(<opaque>)")
    }
}

/// First opaque mutation state.  Its implementation has durably written a
/// pending bundle and selected that bundle's current set.
///
/// Learning the proposed tuple does not authorize selector advancement; only
/// the scheduler-issued durable-reread capability has the accepted type:
///
/// ```compile_fail
/// use advance_scheduler::observation_anchor::{PreparedCurrent, RegistryAnchorTuple};
/// fn echo_tuple(prepared: Box<dyn PreparedCurrent>, learned: RegistryAnchorTuple) {
///     let _ = prepared.database_committed(&learned);
/// }
/// ```
pub trait PreparedCurrent: Send {
    fn database_committed(
        self: Box<Self>,
        committed: RegistryDatabaseCommitProof,
    ) -> Result<Box<dyn DatabaseCommitted>, RegistryAnchorError>;
}

/// SQLite/WAL durability has been acknowledged; selecting next is now legal.
pub trait DatabaseCommitted: Send {
    fn select_next(self: Box<Self>) -> Result<Box<dyn SelectedNext>, RegistryAnchorError>;
}

/// The external selector names next; only no-next compaction remains.
pub trait SelectedNext: Send {
    fn compact(self: Box<Self>) -> Result<Box<dyn Compacted>, RegistryAnchorError>;
}

/// Terminal mutation state.  The selected external tuple must equal the
/// committed SQLite tuple before the provider publishes its in-memory view.
pub trait Compacted: Send {
    fn current(&self) -> &RegistryAnchorTuple;
}

/// Scheduler-private dependency injected by MODULE-001 composition.
///
/// This trait is public only so the CLI crate can implement it through the
/// `observation_anchor` module path.  It is not a CONTRACT-218 host port and is
/// intentionally absent from shared-types and crate-root re-exports.
pub trait RegistryAnchorTransaction: Send + Sync {
    /// Read and authenticate the platform selector plus selected bundle.
    fn observe(&self) -> Result<RegistryAnchorWorld, RegistryAnchorError>;

    /// Bind a scheduler challenge to this concrete, live custody lease.  The
    /// implementation must retain an unexported process secret shared by its
    /// clones.  Marker commit witnesses carry only challenge/tag and are
    /// rejected by any different or permissive anchor implementation.
    fn anchor_lease_tag(&self, _challenge: [u8; 32]) -> Result<[u8; 32], RegistryAnchorError> {
        Err(RegistryAnchorError::Unavailable(
            "external anchor exposes no concrete custody-lease binding".to_owned(),
        ))
    }

    /// Authenticate the exact physical current/pending role-allocation files
    /// and bind them to the observed tuple/context.  Implementations that do
    /// not own this custody capability fail closed.
    fn authenticate_role_allocation_artifacts(
        &self,
        _current: &RegistryAnchorTuple,
        _head_context: &RegistryHeadContext,
        _previous_manifest_bytes: &[u8],
        _next_manifest_bytes: &[u8],
    ) -> Result<(), RegistryAnchorError> {
        Err(RegistryAnchorError::Unavailable(
            "external anchor has no authenticated role-allocation custody".to_owned(),
        ))
    }

    /// Authenticate the exact physical current/pending persisted-keyring
    /// files and bind them to the observed tuple/context.
    fn authenticate_persisted_keyring_artifacts(
        &self,
        _current: &RegistryAnchorTuple,
        _head_context: &RegistryHeadContext,
        _previous_file_bytes: &[u8],
        _next_file_bytes: &[u8],
    ) -> Result<(), RegistryAnchorError> {
        Err(RegistryAnchorError::Unavailable(
            "external anchor has no authenticated persisted-keyring custody".to_owned(),
        ))
    }

    /// Authenticate every exact file in a stopped legacy migration.  This is
    /// invoked both when the plan is created and again by the real provider.
    fn authenticate_legacy_migration_artifacts(
        &self,
        _migration_block: &[u8],
        _prepared_marker: &[u8],
        _installed_marker: &[u8],
        _complete_marker: &[u8],
        _initial_keyring_file: &[u8],
        _initial_role_allocation_file: &[u8],
    ) -> Result<(), RegistryAnchorError> {
        Err(RegistryAnchorError::Unavailable(
            "external anchor has no authenticated legacy-migration custody".to_owned(),
        ))
    }

    /// Authenticate the exact physical current/pending migration-marker files
    /// for one scheduler-derived synthetic tag-13 transition.
    fn authenticate_legacy_marker_transition_artifacts(
        &self,
        _previous: &RegistryAnchorTuple,
        _next: &RegistryAnchorTuple,
        _head_context: &RegistryHeadContext,
        _previous_marker: &[u8],
        _next_marker: &[u8],
    ) -> Result<(), RegistryAnchorError> {
        Err(RegistryAnchorError::Unavailable(
            "external anchor has no authenticated migration-marker transition custody".to_owned(),
        ))
    }

    /// Bootstrap a genuinely empty registry.  Implementations must create the
    /// compact generation-1 anchor exactly once and reject any pre-existing
    /// platform or workspace state.
    fn initialize_compact(
        &self,
        genesis: VerifiedEmptyRegistryGenesis,
    ) -> Result<(), RegistryAnchorError>;

    /// Install the exact nonempty sequence-zero tuple produced by an
    /// authenticated stopped legacy migration.  Implementations without
    /// migration custody fail closed while retaining greenfield support.
    fn initialize_migrated_compact(
        &self,
        _genesis: VerifiedLegacyRegistryMigrationGenesis,
        _artifacts: PreparedLegacyRegistryMigration,
    ) -> Result<(), RegistryAnchorError> {
        Err(RegistryAnchorError::Unavailable(
            "external anchor has no authenticated legacy-migration custody".to_owned(),
        ))
    }

    /// Start a normal G+1/G+2/G+3 mutation and return the first opaque state.
    fn prepare_current(
        &self,
        mutation: RegistryAnchorMutation,
    ) -> Result<Box<dyn PreparedCurrent>, RegistryAnchorError>;

    /// Apply the one closed recovery action authorized by the scheduler after
    /// it re-read SQLite.  Raw expected tuples are intentionally not accepted.
    fn recover(&self, capability: RegistryRecoveryCapability) -> Result<(), RegistryAnchorError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tuple(sequence: u64, discriminator: u8) -> RegistryAnchorTuple {
        RegistryAnchorTuple {
            registry_instance: [1; 16],
            sequence,
            head: [discriminator; 32],
            state_root: [discriminator.wrapping_add(1); 32],
            keyring_root: [2; 32],
            role_allocation_root: [3; 32],
            migration_digest: [4; 32],
        }
    }

    struct DefaultLeaseAnchor;

    struct TestLeaseAnchor;

    impl RegistryAnchorTransaction for TestLeaseAnchor {
        fn observe(&self) -> Result<RegistryAnchorWorld, RegistryAnchorError> {
            Err(RegistryAnchorError::Uninitialized)
        }

        fn anchor_lease_tag(&self, challenge: [u8; 32]) -> Result<[u8; 32], RegistryAnchorError> {
            let mut digest = Sha256::new();
            digest.update(b"advance.contract218.unit-anchor-lease.v1\0");
            digest.update(challenge);
            Ok(digest.finalize().into())
        }

        fn initialize_compact(
            &self,
            _genesis: VerifiedEmptyRegistryGenesis,
        ) -> Result<(), RegistryAnchorError> {
            Err(RegistryAnchorError::InvalidTransition)
        }

        fn prepare_current(
            &self,
            _mutation: RegistryAnchorMutation,
        ) -> Result<Box<dyn PreparedCurrent>, RegistryAnchorError> {
            Err(RegistryAnchorError::InvalidTransition)
        }

        fn recover(
            &self,
            _capability: RegistryRecoveryCapability,
        ) -> Result<(), RegistryAnchorError> {
            Err(RegistryAnchorError::InvalidTransition)
        }
    }

    impl RegistryAnchorTransaction for DefaultLeaseAnchor {
        fn observe(&self) -> Result<RegistryAnchorWorld, RegistryAnchorError> {
            Err(RegistryAnchorError::Uninitialized)
        }

        fn initialize_compact(
            &self,
            _genesis: VerifiedEmptyRegistryGenesis,
        ) -> Result<(), RegistryAnchorError> {
            Err(RegistryAnchorError::InvalidTransition)
        }

        fn prepare_current(
            &self,
            _mutation: RegistryAnchorMutation,
        ) -> Result<Box<dyn PreparedCurrent>, RegistryAnchorError> {
            Err(RegistryAnchorError::InvalidTransition)
        }

        fn recover(
            &self,
            _capability: RegistryRecoveryCapability,
        ) -> Result<(), RegistryAnchorError> {
            Err(RegistryAnchorError::InvalidTransition)
        }
    }

    #[test]
    fn fake_default_anchor_cannot_issue_commit_or_recovery_capabilities() {
        let anchor = DefaultLeaseAnchor;
        let previous = tuple(7, 7);
        let mut next = tuple(8, 0);
        next.head = [0; 32];
        assert!(matches!(
            RegistryAnchorMutation::from_scheduler_postimage(
                &anchor,
                previous.clone(),
                next,
                RegistryHeadContext::unchanged([9; 32], 1).unwrap(),
                6,
                [8; 32],
            ),
            Err(RegistryAnchorError::Unavailable(_))
        ));
        assert!(matches!(
            RegistryRecoveryCapability::from_durable_reread(
                &anchor,
                RegistryAnchorWorld::CompactCurrent {
                    generation: 3,
                    current: previous.clone(),
                },
                previous,
            ),
            Err(RegistryAnchorError::Unavailable(_))
        ));
    }

    fn keyring_file(
        instance: [u8; 16],
        generation: u64,
        previous_root: [u8; 32],
        last_issued_at_ms: u64,
        nonce: u8,
    ) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(191);
        bytes.push(1);
        bytes.extend_from_slice(&1_u32.to_be_bytes());
        bytes.extend_from_slice(&instance);
        bytes.extend_from_slice(&generation.to_be_bytes());
        bytes.extend_from_slice(&previous_root);
        bytes.extend_from_slice(&[0x66; 32]);
        bytes.extend_from_slice(&2_u64.to_be_bytes());
        bytes.extend_from_slice(&1_u32.to_be_bytes());
        bytes.extend_from_slice(&1_u32.to_be_bytes());
        bytes.extend_from_slice(&1_u32.to_be_bytes());
        bytes.push(1);
        bytes.extend_from_slice(&1_u32.to_be_bytes());
        bytes.extend_from_slice(&last_issued_at_ms.to_be_bytes());
        bytes.push(0);
        bytes.extend_from_slice(&[nonce; 32]);
        bytes.extend_from_slice(&[0x88; 32]);
        assert_eq!(bytes.len(), 191);
        bytes
    }

    #[test]
    fn exactly_four_recovery_worlds_are_accepted() {
        let previous = tuple(7, 7);
        let next = tuple(8, 8);

        assert_eq!(
            classify_recovery(
                &RegistryAnchorWorld::PendingCurrent {
                    generation: 10,
                    previous: previous.clone(),
                    next: next.clone(),
                },
                &previous,
            ),
            Ok(RegistryRecoveryDecision::RollBackPending)
        );
        assert_eq!(
            classify_recovery(
                &RegistryAnchorWorld::PendingCurrent {
                    generation: 10,
                    previous: previous.clone(),
                    next: next.clone(),
                },
                &next,
            ),
            Ok(RegistryRecoveryDecision::FinishPendingPromotion)
        );
        assert_eq!(
            classify_recovery(
                &RegistryAnchorWorld::SelectedNext {
                    generation: 11,
                    next: next.clone(),
                },
                &next,
            ),
            Ok(RegistryRecoveryDecision::CompactSelectedNext)
        );
        assert_eq!(
            classify_recovery(
                &RegistryAnchorWorld::CompactCurrent {
                    generation: 12,
                    current: next.clone(),
                },
                &next,
            ),
            Ok(RegistryRecoveryDecision::Clean)
        );
    }

    #[test]
    fn cross_products_and_same_sequence_forks_fail_closed() {
        let previous = tuple(7, 7);
        let next = tuple(8, 8);
        let fork = tuple(8, 99);

        let worlds = [
            RegistryAnchorWorld::PendingCurrent {
                generation: 10,
                previous: previous.clone(),
                next: next.clone(),
            },
            RegistryAnchorWorld::SelectedNext {
                generation: 11,
                next: next.clone(),
            },
            RegistryAnchorWorld::CompactCurrent {
                generation: 12,
                current: next,
            },
        ];

        for world in worlds {
            assert!(matches!(
                classify_recovery(&world, &fork),
                Err(RegistryAnchorError::RecoveryRequired(_))
            ));
        }
    }

    #[test]
    fn pending_current_rejects_a_malformed_successor_even_for_rollback() {
        let previous = tuple(7, 7);
        let mut malformed = tuple(9, 8);
        malformed.role_allocation_root = [99; 32];
        let world = RegistryAnchorWorld::PendingCurrent {
            generation: 10,
            previous: previous.clone(),
            next: malformed,
        };

        assert!(matches!(
            classify_recovery(&world, &previous),
            Err(RegistryAnchorError::RecoveryRequired(_))
        ));
    }

    #[test]
    fn tag_six_root_change_is_a_legal_successor_in_all_four_recovery_worlds() {
        let previous = tuple(7, 7);
        let mut next = tuple(8, 0);
        next.keyring_root = [41; 32];
        next.role_allocation_root = [42; 32];
        let write_set_digest = [44; 32];
        let head_context = RegistryHeadContext {
            previous_marker_root: [45; 32],
            next_marker_root: [46; 32],
            manifest_key_epoch: 7,
            next_manifest_key_epoch: 8,
        };
        next.head = [0; 32];
        let mutation = RegistryAnchorMutation::from_scheduler_postimage(
            &TestLeaseAnchor,
            previous.clone(),
            next.clone(),
            head_context,
            6,
            write_set_digest,
        )
        .unwrap();
        let next = mutation.next().clone();
        mutation.validate().unwrap();

        assert_eq!(
            classify_recovery(
                &RegistryAnchorWorld::PendingCurrent {
                    generation: 10,
                    previous: previous.clone(),
                    next: next.clone(),
                },
                &previous,
            ),
            Ok(RegistryRecoveryDecision::RollBackPending)
        );
        assert_eq!(
            classify_recovery(
                &RegistryAnchorWorld::PendingCurrent {
                    generation: 10,
                    previous,
                    next: next.clone(),
                },
                &next,
            ),
            Ok(RegistryRecoveryDecision::FinishPendingPromotion)
        );
        assert_eq!(
            classify_recovery(
                &RegistryAnchorWorld::SelectedNext {
                    generation: 11,
                    next: next.clone(),
                },
                &next,
            ),
            Ok(RegistryRecoveryDecision::CompactSelectedNext)
        );
        assert_eq!(
            classify_recovery(
                &RegistryAnchorWorld::CompactCurrent {
                    generation: 12,
                    current: next.clone(),
                },
                &next,
            ),
            Ok(RegistryRecoveryDecision::Clean)
        );

        let mut wrong_tag = mutation;
        wrong_tag.operation_tag = 5;
        assert_eq!(
            wrong_tag.validate(),
            Err(RegistryAnchorError::InvalidTransition)
        );
        let mut wrong_sequence = next.clone();
        wrong_sequence.sequence += 1;
        assert!(matches!(
            classify_recovery(
                &RegistryAnchorWorld::PendingCurrent {
                    generation: 13,
                    previous: tuple(7, 7),
                    next: wrong_sequence,
                },
                &next,
            ),
            Err(RegistryAnchorError::RecoveryRequired(_))
        ));
    }

    #[test]
    fn successor_rejects_changed_migration_digest() {
        let previous = tuple(7, 7);
        let mut next = tuple(8, 8);
        next.migration_digest = [99; 32];
        let context = RegistryHeadContext::unchanged([9; 32], 1).unwrap();
        assert_eq!(
            derive_next_head(&previous, &next, &context, 6, [3; 32]),
            Err(RegistryAnchorError::InvalidTransition)
        );
        assert!(matches!(
            classify_recovery(
                &RegistryAnchorWorld::PendingCurrent {
                    generation: 10,
                    previous: previous.clone(),
                    next,
                },
                &previous,
            ),
            Err(RegistryAnchorError::RecoveryRequired(_))
        ));
    }

    #[test]
    fn role_manifest_empty_file_boundary_is_105_bytes() {
        let instance = [7; 16];
        let mut valid = vec![0_u8; 105];
        valid[0] = 1;
        valid[1..5].copy_from_slice(&1_u32.to_be_bytes());
        valid[5..21].copy_from_slice(&instance);
        valid[29..37].copy_from_slice(&1_u64.to_be_bytes());
        valid[41..73].fill(1);
        assert_eq!(validate_role_manifest_header(&valid, instance), Ok(()));
        valid.pop();
        assert_eq!(
            validate_role_manifest_header(&valid, instance),
            Err(RegistryAnchorError::InvalidTransition)
        );
    }

    #[test]
    fn opaque_role_mutation_recomputes_file_roots_and_tag_fourteen_write_set() {
        let instance = [7; 16];
        let mut previous_file = vec![0_u8; 105];
        previous_file[0] = 1;
        previous_file[1..5].copy_from_slice(&1_u32.to_be_bytes());
        previous_file[5..21].copy_from_slice(&instance);
        previous_file[29..37].copy_from_slice(&1_u64.to_be_bytes());
        previous_file[41..73].fill(1);

        let mut next_file = Vec::new();
        next_file.push(1);
        next_file.extend_from_slice(&1_u32.to_be_bytes());
        next_file.extend_from_slice(&instance);
        next_file.extend_from_slice(&1_u64.to_be_bytes());
        next_file.extend_from_slice(&2_u64.to_be_bytes());
        next_file.extend_from_slice(&1_u32.to_be_bytes());
        next_file.extend_from_slice(&[2; 16]);
        next_file.extend_from_slice(&1_u32.to_be_bytes());
        next_file.extend_from_slice(&1_u64.to_be_bytes());
        next_file.push(1);
        next_file.extend_from_slice(&1_u32.to_be_bytes());
        next_file.push(1);
        next_file.extend_from_slice(&[3; 24]);
        next_file.push(1);
        next_file.extend_from_slice(&[4; 48]);
        next_file.push(1);
        next_file.extend_from_slice(&[5; 24]);
        next_file.push(1);
        next_file.extend_from_slice(&[6; 48]);
        next_file.extend_from_slice(&5_u64.to_be_bytes());
        next_file.push(0);
        next_file.extend_from_slice(&0_u64.to_be_bytes());
        next_file.extend_from_slice(&[7; 32]);
        next_file.extend_from_slice(&[8; 32]);

        let mut current = tuple(4, 9);
        current.registry_instance = instance;
        current.role_allocation_root = role_allocation_file_root(&previous_file);
        let context = RegistryHeadContext::unchanged([6; 32], 1).unwrap();
        let prepared = PreparedRoleAllocationMutation::from_authenticated_manifests(
            &TestLeaseAnchor,
            current.clone(),
            context,
            &previous_file,
            &next_file,
        )
        .unwrap();
        assert_eq!(prepared.previous(), &current);
        assert_eq!(
            prepared.next_role_allocation_root(),
            role_allocation_file_root(&next_file)
        );
        assert_eq!(prepared.next().sequence, current.sequence + 1);
        assert_eq!(prepared.next().migration_digest, current.migration_digest);
    }

    #[test]
    fn opaque_keyring_mutation_recomputes_file_roots_and_tag_twelve_write_set() {
        let instance = [7; 16];
        let previous_file = keyring_file(instance, 0, [0; 32], 0, 7);
        let previous_root = persisted_keyring_file_root(&previous_file);
        let next_file = keyring_file(instance, 1, previous_root, 9, 8);
        let mut current = tuple(4, 9);
        current.registry_instance = instance;
        current.keyring_root = previous_root;
        let context = RegistryHeadContext::unchanged([6; 32], 1).unwrap();
        let prepared = PreparedPersistedKeyringMutation::from_authenticated_files(
            &TestLeaseAnchor,
            current.clone(),
            context,
            &previous_file,
            &next_file,
        )
        .unwrap();
        assert_eq!(prepared.previous(), &current);
        assert_eq!(
            prepared.next_keyring_root(),
            persisted_keyring_file_root(&next_file)
        );
        assert_eq!(prepared.next().sequence, current.sequence + 1);
        assert_eq!(prepared.next().state_root, current.state_root);
        assert_eq!(
            prepared.next().role_allocation_root,
            current.role_allocation_root
        );

        let mut stale_previous_link = next_file.clone();
        stale_previous_link[29..61].fill(0);
        assert!(matches!(
            PreparedPersistedKeyringMutation::from_authenticated_files(
                &TestLeaseAnchor,
                current,
                RegistryHeadContext::unchanged([6; 32], 1).unwrap(),
                &previous_file,
                &stale_previous_link,
            ),
            Err(RegistryAnchorError::InvalidTransition)
        ));
    }
}

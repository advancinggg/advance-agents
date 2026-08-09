//! Authenticated at-rest custody for CONTRACT-218 lifecycle role roots.
//!
//! Every `(boot_id, family_version=1)` allocation is permanent.  Active rows
//! contain two independently wrapped roots; erased rows retain only their
//! allocation/erase high-water tombstone.  Updates are written as a pending
//! manifest and become current only after the registry anchor names the new
//! manifest root (operation tag 6 at the scheduler layer).

use crate::contract218_anchor::{
    secure_create_new_regular, secure_open_regular, secure_regular_exists, secure_remove_regular,
    secure_replace_regular, FilePlatformMonotonicAnchorStore, SharedRoleCustodyClaim,
};
use advance_scheduler::observation_anchor::{
    prepare_role_allocation_mutation, role_allocation_file_root, PreparedRoleAllocationMutation,
    RegistryAnchorTransaction, RegistryAnchorTuple, RegistryAnchorWorld, RegistryHeadContext,
    RetainedRoleDependencyReceipt, ZeroRoleDependencyReceipt,
};
use advance_shared_types::contract218_previsible::{
    Contract218LifecycleRoleSet, Contract218RoleRootMaterial,
};
use advance_shared_types::observation_identity::SensitiveParamCatalogError;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

type HmacSha256 = Hmac<Sha256>;

const CURRENT_FILE: &str = "contract218.roles.current";
const PENDING_FILE: &str = "contract218.roles.pending";
const MANIFEST_VERSION: u8 = 1;
const FAMILY_VERSION: u16 = 1;
const ACTIVE_TAG: u8 = 1;
const ERASED_TAG: u8 = 2;
const ROOT_CIPHERTEXT_LEN: usize = 48;
const MAX_ROLE_ALLOCATIONS: usize = 65_536;
const ROLE_ROOT_WRAP_INFO_DOMAIN: &[u8] = b"advance.contract218.role-root-wrap.v1\0";
const ROLE_MANIFEST_KEY_INFO_DOMAIN: &[u8] =
    b"advance.contract218.role-allocation-manifest-key.v1\0";
const ROLE_MANIFEST_MAC_DOMAIN: &[u8] = b"advance.contract218.role-allocation-manifest.v1\0";

#[derive(Debug, Error)]
pub enum RoleRootCustodyError {
    #[error("role-root custody I/O failed: {0}")]
    Io(String),
    #[error("role-root manifest authentication failed")]
    AuthenticationFailed,
    #[error("role-root manifest requires operator recovery: {0}")]
    RecoveryRequired(String),
    #[error("role-root allocation already exists")]
    AlreadyAllocated,
    #[error("role-root allocation was not found")]
    NotFound,
    #[error("role-root allocation has been permanently erased")]
    Erased,
    #[error("retained replay dependency is required to open an old boot")]
    RetainedDependencyRequired,
    #[error("role-root erase requires a complete zero-dependency scan")]
    DependenciesRemain,
    #[error("role-root anchor does not name the prepared manifest")]
    AnchorMismatch,
    #[error("invalid role-root lifecycle input: {0}")]
    Invalid(String),
    #[error("role-root cryptographic operation failed")]
    Crypto,
}

/// Authenticated digest stored in `RegistryAnchorTuple.role_allocation_root`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RoleAllocationRoot([u8; 32]);

impl RoleAllocationRoot {
    pub fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Explicit outcome of attempting to protect unwrapped roots in memory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryProtection {
    Locked,
    Unsupported,
}

/// Safe platform seam for optional `mlock`-equivalent custody.
pub trait SensitiveMemoryCustody: Send + Sync {
    fn protect(
        &self,
        first: &mut [u8; 32],
        second: &mut [u8; 32],
    ) -> Result<MemoryProtection, RoleRootCustodyError>;
}

/// Explicit fallback used where no safe `mlock` backend is installed.  Root
/// buffers remain zeroizing and exclusive disk/process custody remains intact.
pub struct UnsupportedMemoryCustody;

impl SensitiveMemoryCustody for UnsupportedMemoryCustody {
    fn protect(
        &self,
        _first: &mut [u8; 32],
        _second: &mut [u8; 32],
    ) -> Result<MemoryProtection, RoleRootCustodyError> {
        Ok(MemoryProtection::Unsupported)
    }
}

/// Move-only build-and-hold result.  No production API exports either root or
/// constructs provider-owned lifecycle roles from this Order-2 foundation.
pub struct OpenedContract218RoleRoots {
    registry_instance: [u8; 16],
    boot_id: [u8; 16],
    _wrap_key_epoch: u32,
    _first_root: Zeroizing<[u8; 32]>,
    _second_root: Zeroizing<[u8; 32]>,
    memory_protection: MemoryProtection,
}

impl OpenedContract218RoleRoots {
    pub fn memory_protection(&self) -> MemoryProtection {
        self.memory_protection
    }

    /// Move the authenticated roots directly into the shared one-shot role
    /// factory.  Root bytes never cross this custody boundary as a returned
    /// value and remain zeroizing on every failure path.
    pub fn into_lifecycle_roles(
        self,
    ) -> Result<Contract218LifecycleRoleSet, SensitiveParamCatalogError> {
        Contract218RoleRootMaterial::from_authenticated_custody(
            self.registry_instance,
            self.boot_id,
            self._first_root,
            self._second_root,
        )
        .map(Contract218RoleRootMaterial::into_lifecycle_factory)?
        .split_once()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RoleManifestRecovery {
    Clean,
    RolledBackPending,
    PromotedPending,
}

#[derive(Clone)]
pub struct FileContract218RoleRootCustody {
    inner: Arc<RoleCustodyInner>,
}

struct RoleCustodyInner {
    directory: PathBuf,
    anchor: FilePlatformMonotonicAnchorStore,
    _exclusive_custody: SharedRoleCustodyClaim,
    keys: Mutex<BTreeMap<u32, Zeroizing<[u8; 32]>>>,
    memory: Arc<dyn SensitiveMemoryCustody>,
    writer: Mutex<()>,
    session_open_root: Mutex<Option<RoleAllocationRoot>>,
}

impl FileContract218RoleRootCustody {
    pub(crate) fn shares_anchor(&self, anchor: &FilePlatformMonotonicAnchorStore) -> bool {
        self.inner.anchor.shares_store_with(anchor)
    }

    /// Share the exact anchor custody lease; opening a second independent
    /// anchor/role object for the same platform directory remains impossible.
    pub fn from_anchor_store(
        anchor: &FilePlatformMonotonicAnchorStore,
        manifest_key_epoch: u32,
        master_key: Zeroizing<[u8; 32]>,
    ) -> Result<Self, RoleRootCustodyError> {
        Self::from_anchor_store_with_keys(
            anchor,
            vec![(manifest_key_epoch, master_key)],
            Arc::new(UnsupportedMemoryCustody),
        )
    }

    pub fn from_anchor_store_with_keys(
        anchor: &FilePlatformMonotonicAnchorStore,
        keys: Vec<(u32, Zeroizing<[u8; 32]>)>,
        memory: Arc<dyn SensitiveMemoryCustody>,
    ) -> Result<Self, RoleRootCustodyError> {
        let (directory, custody) = anchor
            .claim_role_custody()
            .map_err(|error| RoleRootCustodyError::RecoveryRequired(error.to_string()))?;
        let mut keyring = BTreeMap::new();
        for (epoch, key) in keys {
            if epoch == 0 || key.as_ref() == &[0; 32] || keyring.insert(epoch, key).is_some() {
                return Err(RoleRootCustodyError::Invalid(
                    "key epochs must be unique, nonzero, and nonzero-keyed".to_owned(),
                ));
            }
        }
        if keyring.is_empty() {
            return Err(RoleRootCustodyError::Invalid(
                "at least one manifest key is required".to_owned(),
            ));
        }
        let inner = Arc::new(RoleCustodyInner {
            directory,
            anchor: anchor.clone(),
            _exclusive_custody: custody,
            keys: Mutex::new(keyring),
            memory,
            writer: Mutex::new(()),
            session_open_root: Mutex::new(None),
        });
        if role_file_exists(&inner.current_path())? {
            let (_, bytes) = inner.read_manifest(&inner.current_path())?;
            *inner.session_open_root.lock().map_err(|_| lock_error())? = Some(root_of(&bytes));
        }
        Ok(Self { inner })
    }

    /// Create an authenticated empty manifest before the genesis anchor is
    /// installed.  Repeated or partially initialized calls fail closed.
    pub fn initialize_empty(
        &self,
        registry_instance: [u8; 16],
        manifest_key_epoch: u32,
    ) -> Result<RoleAllocationRoot, RoleRootCustodyError> {
        if registry_instance == [0; 16] || manifest_key_epoch == 0 {
            return Err(RoleRootCustodyError::Invalid(
                "registry instance and key epoch must be nonzero".to_owned(),
            ));
        }
        let _writer = self.inner.writer.lock().map_err(|_| lock_error())?;
        let current_path = self.inner.current_path();
        let pending_path = self.inner.pending_path();
        if role_file_exists(&current_path)?
            || role_file_exists(&pending_path)?
            || role_file_exists(&atomic_temporary_path(&current_path)?)?
            || role_file_exists(&atomic_temporary_path(&pending_path)?)?
        {
            return Err(RoleRootCustodyError::RecoveryRequired(
                "role manifest initialization encountered pre-existing state".to_owned(),
            ));
        }
        self.inner.require_key(manifest_key_epoch)?;
        let manifest = RoleManifest {
            manifest_key_epoch,
            registry_instance,
            allocation_generation: 0,
            next_allocation_sequence: 1,
            entries: BTreeMap::new(),
            nonce: random_nonzero_manifest_nonce()?,
        };
        let bytes = self.inner.encode_manifest(&manifest)?;
        atomic_write(&current_path, &bytes)?;
        Ok(root_of(&bytes))
    }

    pub fn current_root(&self) -> Result<RoleAllocationRoot, RoleRootCustodyError> {
        let _writer = self.inner.writer.lock().map_err(|_| lock_error())?;
        let (_, bytes) = self.inner.read_manifest(&self.inner.current_path())?;
        Ok(root_of(&bytes))
    }

    /// Migration-only authenticated generation-zero manifest read.  The
    /// scheduler's opaque migration constructor consumes these complete bytes;
    /// normal role mutations must continue through the anchored API.
    pub(crate) fn authenticated_initial_file_for_migration(
        &self,
        expected_registry_instance: [u8; 16],
    ) -> Result<Zeroizing<Vec<u8>>, RoleRootCustodyError> {
        let _writer = self.inner.writer.lock().map_err(|_| lock_error())?;
        self.inner.require_no_pending()?;
        let (manifest, bytes) = self.inner.read_manifest(&self.inner.current_path())?;
        if manifest.registry_instance != expected_registry_instance
            || manifest.allocation_generation != 0
            || manifest.next_allocation_sequence != 1
            || !manifest.entries.is_empty()
        {
            return Err(RoleRootCustodyError::AuthenticationFailed);
        }
        Ok(bytes)
    }

    /// Write a pending Active allocation.  The returned roots remain
    /// zeroizing and cannot be opened by consumers until `commit_anchored`.
    pub fn prepare_create_once(
        &self,
        boot_id: [u8; 16],
        family_version: u16,
        head_context: RegistryHeadContext,
    ) -> Result<PreparedRoleRootCreation, RoleRootCustodyError> {
        validate_key(boot_id, family_version)?;
        let _writer = self.inner.writer.lock().map_err(|_| lock_error())?;
        self.inner.require_no_pending()?;
        let (mut manifest, current_bytes) = self.inner.read_manifest(&self.inner.current_path())?;
        let previous_root = root_of(&current_bytes);
        let current_anchor = self
            .inner
            .verified_current_anchor(&manifest, previous_root)?;
        let key = (boot_id, family_version);
        if manifest.entries.contains_key(&key) {
            return Err(RoleRootCustodyError::AlreadyAllocated);
        }
        if manifest.entries.len() >= MAX_ROLE_ALLOCATIONS {
            return Err(RoleRootCustodyError::Invalid(
                "role allocation capacity exceeded".to_owned(),
            ));
        }
        let allocation_sequence = manifest.next_allocation_sequence;
        manifest.next_allocation_sequence =
            allocation_sequence.checked_add(1).ok_or_else(|| {
                RoleRootCustodyError::Invalid("allocation sequence exhausted".to_owned())
            })?;
        manifest.allocation_generation =
            manifest
                .allocation_generation
                .checked_add(1)
                .ok_or_else(|| {
                    RoleRootCustodyError::Invalid("allocation generation exhausted".to_owned())
                })?;

        let (first_root, second_root) = independent_roots()?;
        let created_registry_sequence =
            current_anchor.sequence.checked_add(1).ok_or_else(|| {
                RoleRootCustodyError::Invalid("registry sequence exhausted".to_owned())
            })?;
        let active = self.inner.wrap_active(
            &manifest,
            boot_id,
            family_version,
            allocation_sequence,
            created_registry_sequence,
            0,
            &first_root,
            &second_root,
        )?;
        manifest.entries.insert(key, RoleEntry::Active(active));
        manifest.nonce = random_nonzero_manifest_nonce()?;
        let pending_bytes = self.inner.encode_manifest(&manifest)?;
        let pending_path = self.inner.pending_path();
        atomic_write(&pending_path, &pending_bytes)?;
        let anchor_preparation = match prepare_role_allocation_mutation(
            &self.inner.anchor,
            current_anchor,
            head_context,
            &current_bytes,
            &pending_bytes,
        ) {
            Ok(preparation) => preparation,
            Err(error) => {
                cleanup_failed_pending_write(&pending_path)?;
                return Err(anchor_error(error));
            }
        };
        let expected_previous_anchor = anchor_preparation.previous().clone();
        let expected_next_anchor = anchor_preparation.next().clone();
        let new_root = root_of(&pending_bytes);
        Ok(PreparedRoleRootCreation {
            inner: Arc::clone(&self.inner),
            previous_root,
            new_root,
            anchor_preparation: Some(anchor_preparation),
            expected_previous_anchor,
            expected_next_anchor,
            registry_instance: manifest.registry_instance,
            boot_id,
            manifest_key_epoch: manifest.manifest_key_epoch,
            first_root: Some(first_root),
            second_root: Some(second_root),
        })
    }

    /// Reconcile only the three legal role-manifest relations: clean current,
    /// pending rollback, or pending promotion.  Any third/forked root fails.
    pub fn recover_against(
        &self,
        anchored: &RegistryAnchorTuple,
    ) -> Result<RoleManifestRecovery, RoleRootCustodyError> {
        let _writer = self.inner.writer.lock().map_err(|_| lock_error())?;
        self.inner.recover_unlocked(anchored)
    }

    pub fn open_for_recovery(
        &self,
        boot_id: [u8; 16],
        family_version: u16,
        dependency: Option<RetainedRoleDependencyReceipt>,
        anchored: &RegistryAnchorTuple,
    ) -> Result<OpenedContract218RoleRoots, RoleRootCustodyError> {
        validate_key(boot_id, family_version)?;
        let dependency = dependency.ok_or(RoleRootCustodyError::RetainedDependencyRequired)?;
        let _writer = self.inner.writer.lock().map_err(|_| lock_error())?;
        self.inner.recover_unlocked(anchored)?;
        let (manifest, _) = self.inner.read_manifest(&self.inner.current_path())?;
        let active = match manifest.entries.get(&(boot_id, family_version)) {
            Some(RoleEntry::Active(active)) => active,
            Some(RoleEntry::Erased(_)) => return Err(RoleRootCustodyError::Erased),
            None => return Err(RoleRootCustodyError::NotFound),
        };
        dependency
            .verify_for_recovery_open(
                boot_id,
                family_version,
                anchored,
                active.dependency_high_water,
            )
            .map_err(|_| RoleRootCustodyError::RetainedDependencyRequired)?;
        self.inner
            .open_active(&manifest, boot_id, family_version, active)
    }

    /// Rewrap every Active entry under a new manifest epoch.  The new key is
    /// retained alongside the old key; the caller may retire old epochs only
    /// after reopening and verifying the anchored new manifest.
    pub fn prepare_rewrap(
        &self,
        new_epoch: u32,
        new_master_key: Zeroizing<[u8; 32]>,
        head_context: RegistryHeadContext,
    ) -> Result<PreparedRoleManifestUpdate, RoleRootCustodyError> {
        if new_epoch == 0 || new_master_key.as_ref() == &[0; 32] {
            return Err(RoleRootCustodyError::Invalid(
                "rewrap key epoch/key must be nonzero".to_owned(),
            ));
        }
        let _writer = self.inner.writer.lock().map_err(|_| lock_error())?;
        self.inner.require_no_pending()?;
        let (old_manifest, current_bytes) = self.inner.read_manifest(&self.inner.current_path())?;
        let previous_root = root_of(&current_bytes);
        let current_anchor = self
            .inner
            .verified_current_anchor(&old_manifest, previous_root)?;
        if new_epoch <= old_manifest.manifest_key_epoch {
            return Err(RoleRootCustodyError::Invalid(
                "rewrap epoch must strictly advance".to_owned(),
            ));
        }
        {
            let keys = self.inner.keys.lock().map_err(|_| lock_error())?;
            if keys.contains_key(&new_epoch) {
                return Err(RoleRootCustodyError::Invalid(
                    "rewrap epoch already exists".to_owned(),
                ));
            }
        }

        let mut manifest = RoleManifest {
            manifest_key_epoch: new_epoch,
            registry_instance: old_manifest.registry_instance,
            allocation_generation: old_manifest
                .allocation_generation
                .checked_add(1)
                .ok_or_else(|| {
                    RoleRootCustodyError::Invalid("allocation generation exhausted".to_owned())
                })?,
            next_allocation_sequence: old_manifest.next_allocation_sequence,
            entries: BTreeMap::new(),
            nonce: random_nonzero_manifest_nonce()?,
        };
        for (&key, entry) in &old_manifest.entries {
            let replacement = match entry {
                RoleEntry::Active(active) => {
                    let (first, second) =
                        self.inner
                            .unwrap_active(&old_manifest, key.0, key.1, active)?;
                    let wrapped = self.inner.wrap_active_with_master_key(
                        &manifest,
                        key.0,
                        key.1,
                        active.allocation_sequence,
                        active.created_registry_sequence,
                        active.dependency_high_water,
                        &first,
                        &second,
                        &*new_master_key,
                    )?;
                    RoleEntry::Active(wrapped)
                }
                RoleEntry::Erased(erased) => RoleEntry::Erased(erased.clone()),
            };
            manifest.entries.insert(key, replacement);
        }
        let pending_bytes = self
            .inner
            .encode_manifest_with_master_key(&manifest, &*new_master_key)?;
        let new_root = root_of(&pending_bytes);
        let pending_path = self.inner.pending_path();
        let mut keys = self.inner.keys.lock().map_err(|_| lock_error())?;
        if keys.contains_key(&new_epoch) {
            return Err(RoleRootCustodyError::Invalid(
                "rewrap epoch already exists".to_owned(),
            ));
        }
        if let Err(write_error) = atomic_write(&pending_path, &pending_bytes) {
            drop(keys);
            if let Err(cleanup_error) = cleanup_failed_pending_write(&pending_path) {
                return Err(RoleRootCustodyError::RecoveryRequired(format!(
                    "rewrap write failed ({write_error}); pending cleanup failed ({cleanup_error})"
                )));
            }
            return Err(write_error);
        }
        let anchor_preparation = match prepare_role_allocation_mutation(
            &self.inner.anchor,
            current_anchor,
            head_context,
            &current_bytes,
            &pending_bytes,
        ) {
            Ok(preparation) => preparation,
            Err(error) => {
                drop(keys);
                cleanup_failed_pending_write(&pending_path)?;
                return Err(anchor_error(error));
            }
        };
        let expected_previous_anchor = anchor_preparation.previous().clone();
        let expected_next_anchor = anchor_preparation.next().clone();
        let replaced = keys.insert(new_epoch, new_master_key);
        debug_assert!(replaced.is_none());
        drop(keys);
        Ok(PreparedRoleManifestUpdate {
            inner: Arc::clone(&self.inner),
            previous_root,
            new_root,
            anchor_preparation: Some(anchor_preparation),
            expected_previous_anchor,
            expected_next_anchor,
            registry_instance: manifest.registry_instance,
            retire_old_epochs_on_commit: false,
            committed_epoch: new_epoch,
        })
    }

    /// Cryptographically erase one allocation.  A scheduler-issued, anchored
    /// full-scan receipt is consumed; every surviving Active entry is rewrapped
    /// under a fresh epoch, and the erased entry becomes ciphertext-free.  The
    /// old epoch is destroyed only after the exact tag-6 anchor commits.
    pub fn prepare_erase(
        &self,
        boot_id: [u8; 16],
        family_version: u16,
        dependency: ZeroRoleDependencyReceipt,
        new_epoch: u32,
        new_master_key: Zeroizing<[u8; 32]>,
        head_context: RegistryHeadContext,
    ) -> Result<PreparedRoleManifestUpdate, RoleRootCustodyError> {
        validate_key(boot_id, family_version)?;
        if new_epoch == 0 || new_master_key.as_ref() == &[0; 32] {
            return Err(RoleRootCustodyError::Invalid(
                "erase key epoch/key must be nonzero".to_owned(),
            ));
        }
        let _writer = self.inner.writer.lock().map_err(|_| lock_error())?;
        self.inner.require_no_pending()?;
        let (old_manifest, current_bytes) = self.inner.read_manifest(&self.inner.current_path())?;
        let previous_root = root_of(&current_bytes);
        let current_anchor = self
            .inner
            .verified_current_anchor(&old_manifest, previous_root)?;
        if new_epoch <= old_manifest.manifest_key_epoch {
            return Err(RoleRootCustodyError::Invalid(
                "erase epoch must strictly advance".to_owned(),
            ));
        }
        {
            let keys = self.inner.keys.lock().map_err(|_| lock_error())?;
            if keys.contains_key(&new_epoch) {
                return Err(RoleRootCustodyError::Invalid(
                    "erase epoch already exists".to_owned(),
                ));
            }
        }

        let target = (boot_id, family_version);
        let target_active = match old_manifest.entries.get(&target) {
            Some(RoleEntry::Active(active)) => active.clone(),
            Some(RoleEntry::Erased(_)) => return Err(RoleRootCustodyError::Erased),
            None => return Err(RoleRootCustodyError::NotFound),
        };
        let scan_high_water = dependency
            .verify_for_erase(
                boot_id,
                family_version,
                &current_anchor,
                target_active.dependency_high_water,
            )
            .map_err(|_| RoleRootCustodyError::DependenciesRemain)?;
        if scan_high_water != current_anchor.sequence {
            return Err(RoleRootCustodyError::DependenciesRemain);
        }
        let erased_registry_sequence = current_anchor.sequence.checked_add(1).ok_or_else(|| {
            RoleRootCustodyError::Invalid("registry sequence exhausted".to_owned())
        })?;
        let allocation_generation = old_manifest
            .allocation_generation
            .checked_add(1)
            .ok_or_else(|| {
                RoleRootCustodyError::Invalid("allocation generation exhausted".to_owned())
            })?;
        let mut manifest = RoleManifest {
            manifest_key_epoch: new_epoch,
            registry_instance: old_manifest.registry_instance,
            allocation_generation,
            next_allocation_sequence: old_manifest.next_allocation_sequence,
            entries: BTreeMap::new(),
            nonce: random_nonzero_manifest_nonce()?,
        };
        for (&key, entry) in &old_manifest.entries {
            let replacement = if key == target {
                RoleEntry::Erased(ErasedEntry {
                    allocation_sequence: target_active.allocation_sequence,
                    wrap_key_epoch: target_active.wrap_key_epoch,
                    created_registry_sequence: target_active.created_registry_sequence,
                    erased_registry_sequence,
                    dependency_high_water: scan_high_water,
                })
            } else {
                match entry {
                    RoleEntry::Active(active) => {
                        let (first, second) =
                            self.inner
                                .unwrap_active(&old_manifest, key.0, key.1, active)?;
                        let wrapped = self.inner.wrap_active_with_master_key(
                            &manifest,
                            key.0,
                            key.1,
                            active.allocation_sequence,
                            active.created_registry_sequence,
                            active.dependency_high_water,
                            &first,
                            &second,
                            &*new_master_key,
                        )?;
                        RoleEntry::Active(wrapped)
                    }
                    RoleEntry::Erased(erased) => RoleEntry::Erased(erased.clone()),
                }
            };
            manifest.entries.insert(key, replacement);
        }

        let pending_bytes = self
            .inner
            .encode_manifest_with_master_key(&manifest, &*new_master_key)?;
        let new_root = root_of(&pending_bytes);
        let pending_path = self.inner.pending_path();
        if let Err(write_error) = atomic_write(&pending_path, &pending_bytes) {
            if let Err(cleanup_error) = cleanup_failed_pending_write(&pending_path) {
                return Err(RoleRootCustodyError::RecoveryRequired(format!(
                    "erase write failed ({write_error}); pending cleanup failed ({cleanup_error})"
                )));
            }
            return Err(write_error);
        }
        let anchor_preparation = match prepare_role_allocation_mutation(
            &self.inner.anchor,
            current_anchor,
            head_context,
            &current_bytes,
            &pending_bytes,
        ) {
            Ok(preparation) => preparation,
            Err(error) => {
                cleanup_failed_pending_write(&pending_path)?;
                return Err(anchor_error(error));
            }
        };
        let expected_previous_anchor = anchor_preparation.previous().clone();
        let expected_next_anchor = anchor_preparation.next().clone();

        let mut keys = self.inner.keys.lock().map_err(|_| lock_error())?;
        if keys.contains_key(&new_epoch) {
            drop(keys);
            cleanup_failed_pending_write(&pending_path)?;
            return Err(RoleRootCustodyError::Invalid(
                "erase epoch already exists".to_owned(),
            ));
        }
        let replaced = keys.insert(new_epoch, new_master_key);
        debug_assert!(replaced.is_none());
        drop(keys);
        Ok(PreparedRoleManifestUpdate {
            inner: Arc::clone(&self.inner),
            previous_root,
            new_root,
            anchor_preparation: Some(anchor_preparation),
            expected_previous_anchor,
            expected_next_anchor,
            registry_instance: manifest.registry_instance,
            retire_old_epochs_on_commit: true,
            committed_epoch: new_epoch,
        })
    }

    /// After a restart has authenticated the new epoch and anchor root, forget
    /// every older wrapping key.  Erased entries contain no ciphertext to keep.
    pub fn retire_previous_epochs_after_restart(
        &self,
        anchored: &RegistryAnchorTuple,
    ) -> Result<(), RoleRootCustodyError> {
        let _writer = self.inner.writer.lock().map_err(|_| lock_error())?;
        self.inner.recover_unlocked(anchored)?;
        let (manifest, bytes) = self.inner.read_manifest(&self.inner.current_path())?;
        validate_anchor(&manifest, root_of(&bytes), anchored)?;
        if *self
            .inner
            .session_open_root
            .lock()
            .map_err(|_| lock_error())?
            != Some(root_of(&bytes))
        {
            return Err(RoleRootCustodyError::RecoveryRequired(
                "old wrapping epochs may be retired only by a custody object reopened on the anchored manifest"
                    .to_owned(),
            ));
        }
        let mut keys = self.inner.keys.lock().map_err(|_| lock_error())?;
        keys.retain(|epoch, _| *epoch == manifest.manifest_key_epoch);
        Ok(())
    }

    #[cfg(feature = "test-support")]
    pub fn retained_key_epochs_for_test(&self) -> Vec<u32> {
        self.inner
            .keys
            .lock()
            .expect("role keyring lock poisoned")
            .keys()
            .copied()
            .collect()
    }

    #[cfg(feature = "test-support")]
    pub fn wrapping_key_matches_for_test(&self, epoch: u32, expected: &[u8; 32]) -> bool {
        self.inner
            .keys
            .lock()
            .expect("role keyring lock poisoned")
            .get(&epoch)
            .is_some_and(|key| key.as_ref().ct_eq(expected.as_slice()).unwrap_u8() == 1)
    }

    #[cfg(feature = "test-support")]
    pub fn allocation_is_erased_for_test(
        &self,
        boot_id: [u8; 16],
        family_version: u16,
    ) -> Result<bool, RoleRootCustodyError> {
        let _writer = self.inner.writer.lock().map_err(|_| lock_error())?;
        let (manifest, _) = self.inner.read_manifest(&self.inner.current_path())?;
        Ok(matches!(
            manifest.entries.get(&(boot_id, family_version)),
            Some(RoleEntry::Erased(_))
        ))
    }
}

pub struct PreparedRoleRootCreation {
    inner: Arc<RoleCustodyInner>,
    previous_root: RoleAllocationRoot,
    new_root: RoleAllocationRoot,
    anchor_preparation: Option<PreparedRoleAllocationMutation>,
    expected_previous_anchor: RegistryAnchorTuple,
    expected_next_anchor: RegistryAnchorTuple,
    registry_instance: [u8; 16],
    boot_id: [u8; 16],
    manifest_key_epoch: u32,
    first_root: Option<Zeroizing<[u8; 32]>>,
    second_root: Option<Zeroizing<[u8; 32]>>,
}

impl PreparedRoleRootCreation {
    pub fn previous_root(&self) -> RoleAllocationRoot {
        self.previous_root
    }

    pub fn new_root(&self) -> RoleAllocationRoot {
        self.new_root
    }

    pub fn anchor_previous(&self) -> &RegistryAnchorTuple {
        &self.expected_previous_anchor
    }

    pub fn anchor_next(&self) -> &RegistryAnchorTuple {
        &self.expected_next_anchor
    }

    /// Move the scheduler-owned mutation into the provider (or a foundation
    /// failpoint harness).  It cannot be taken twice or reconstructed from raw
    /// roots/digests by the caller.
    pub fn take_anchor_preparation(
        &mut self,
    ) -> Result<PreparedRoleAllocationMutation, RoleRootCustodyError> {
        self.anchor_preparation.take().ok_or_else(|| {
            RoleRootCustodyError::Invalid("role anchor preparation was already consumed".to_owned())
        })
    }

    pub fn commit_anchored(
        mut self,
        anchored: &RegistryAnchorTuple,
    ) -> Result<OpenedContract218RoleRoots, RoleRootCustodyError> {
        if anchored != &self.expected_next_anchor {
            return Err(RoleRootCustodyError::AnchorMismatch);
        }
        let _writer = self.inner.writer.lock().map_err(|_| lock_error())?;
        self.inner.promote_pending(
            self.previous_root,
            self.new_root,
            self.registry_instance,
            anchored,
        )?;
        let mut first = self.first_root.take().ok_or(RoleRootCustodyError::Crypto)?;
        let mut second = self
            .second_root
            .take()
            .ok_or(RoleRootCustodyError::Crypto)?;
        let protection = self.inner.memory.protect(&mut first, &mut second)?;
        Ok(OpenedContract218RoleRoots {
            registry_instance: self.registry_instance,
            boot_id: self.boot_id,
            _wrap_key_epoch: self.manifest_key_epoch,
            _first_root: first,
            _second_root: second,
            memory_protection: protection,
        })
    }
}

pub struct PreparedRoleManifestUpdate {
    inner: Arc<RoleCustodyInner>,
    previous_root: RoleAllocationRoot,
    new_root: RoleAllocationRoot,
    anchor_preparation: Option<PreparedRoleAllocationMutation>,
    expected_previous_anchor: RegistryAnchorTuple,
    expected_next_anchor: RegistryAnchorTuple,
    registry_instance: [u8; 16],
    retire_old_epochs_on_commit: bool,
    committed_epoch: u32,
}

impl PreparedRoleManifestUpdate {
    pub fn previous_root(&self) -> RoleAllocationRoot {
        self.previous_root
    }

    pub fn new_root(&self) -> RoleAllocationRoot {
        self.new_root
    }

    pub fn anchor_previous(&self) -> &RegistryAnchorTuple {
        &self.expected_previous_anchor
    }

    pub fn anchor_next(&self) -> &RegistryAnchorTuple {
        &self.expected_next_anchor
    }

    pub fn take_anchor_preparation(
        &mut self,
    ) -> Result<PreparedRoleAllocationMutation, RoleRootCustodyError> {
        self.anchor_preparation.take().ok_or_else(|| {
            RoleRootCustodyError::Invalid("role anchor preparation was already consumed".to_owned())
        })
    }

    pub fn commit_anchored(
        self,
        anchored: &RegistryAnchorTuple,
    ) -> Result<(), RoleRootCustodyError> {
        if anchored != &self.expected_next_anchor {
            return Err(RoleRootCustodyError::AnchorMismatch);
        }
        let _writer = self.inner.writer.lock().map_err(|_| lock_error())?;
        self.inner.promote_pending(
            self.previous_root,
            self.new_root,
            self.registry_instance,
            anchored,
        )?;
        if self.retire_old_epochs_on_commit {
            self.inner
                .keys
                .lock()
                .map_err(|_| lock_error())?
                .retain(|epoch, _| *epoch == self.committed_epoch);
        }
        Ok(())
    }
}

#[derive(Clone)]
struct RoleManifest {
    manifest_key_epoch: u32,
    registry_instance: [u8; 16],
    allocation_generation: u64,
    next_allocation_sequence: u64,
    entries: BTreeMap<([u8; 16], u16), RoleEntry>,
    nonce: [u8; 32],
}

#[derive(Clone, Eq, PartialEq)]
enum RoleEntry {
    Active(ActiveEntry),
    Erased(ErasedEntry),
}

#[derive(Clone, Eq, PartialEq)]
struct ActiveEntry {
    allocation_sequence: u64,
    wrap_key_epoch: u32,
    first_nonce: [u8; 24],
    first_ciphertext: [u8; ROOT_CIPHERTEXT_LEN],
    second_nonce: [u8; 24],
    second_ciphertext: [u8; ROOT_CIPHERTEXT_LEN],
    created_registry_sequence: u64,
    dependency_high_water: u64,
}

impl Drop for ActiveEntry {
    fn drop(&mut self) {
        self.first_nonce.zeroize();
        self.first_ciphertext.zeroize();
        self.second_nonce.zeroize();
        self.second_ciphertext.zeroize();
    }
}

#[derive(Clone, Eq, PartialEq)]
struct ErasedEntry {
    allocation_sequence: u64,
    wrap_key_epoch: u32,
    created_registry_sequence: u64,
    erased_registry_sequence: u64,
    dependency_high_water: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RoleManifestTransition {
    Create,
    Rewrap,
    Erase,
}

impl RoleCustodyInner {
    fn current_path(&self) -> PathBuf {
        self.directory.join(CURRENT_FILE)
    }

    fn pending_path(&self) -> PathBuf {
        self.directory.join(PENDING_FILE)
    }

    fn verified_current_anchor(
        &self,
        manifest: &RoleManifest,
        root: RoleAllocationRoot,
    ) -> Result<RegistryAnchorTuple, RoleRootCustodyError> {
        match self.anchor.observe().map_err(anchor_error)? {
            RegistryAnchorWorld::CompactCurrent { current, .. }
                if current.registry_instance == manifest.registry_instance
                    && current.role_allocation_root == root.0 =>
            {
                Ok(current)
            }
            _ => Err(RoleRootCustodyError::RecoveryRequired(
                "role mutation requires the exact compact current anchor".to_owned(),
            )),
        }
    }

    fn require_no_pending(&self) -> Result<(), RoleRootCustodyError> {
        if role_file_exists(&self.pending_path())?
            || role_file_exists(&atomic_temporary_path(&self.pending_path())?)?
        {
            return Err(RoleRootCustodyError::RecoveryRequired(
                "pending role manifest must be reconciled first".to_owned(),
            ));
        }
        Ok(())
    }

    fn require_key(&self, epoch: u32) -> Result<(), RoleRootCustodyError> {
        if self
            .keys
            .lock()
            .map_err(|_| lock_error())?
            .contains_key(&epoch)
        {
            Ok(())
        } else {
            Err(RoleRootCustodyError::RecoveryRequired(format!(
                "manifest key epoch {epoch} is unavailable"
            )))
        }
    }

    fn encode_manifest(
        &self,
        manifest: &RoleManifest,
    ) -> Result<Zeroizing<Vec<u8>>, RoleRootCustodyError> {
        self.encode_manifest_with_optional_master_key(manifest, None)
    }

    fn encode_manifest_with_master_key(
        &self,
        manifest: &RoleManifest,
        master_key: &[u8; 32],
    ) -> Result<Zeroizing<Vec<u8>>, RoleRootCustodyError> {
        self.encode_manifest_with_optional_master_key(manifest, Some(master_key))
    }

    fn encode_manifest_with_optional_master_key(
        &self,
        manifest: &RoleManifest,
        master_key: Option<&[u8; 32]>,
    ) -> Result<Zeroizing<Vec<u8>>, RoleRootCustodyError> {
        let mut bytes = encode_manifest_preceding_bytes(manifest)?;
        let tag = match master_key {
            Some(master_key) => self.manifest_mac_with_master_key(
                manifest.manifest_key_epoch,
                manifest.registry_instance,
                master_key,
                &bytes,
            )?,
            None => self.manifest_mac(
                manifest.manifest_key_epoch,
                manifest.registry_instance,
                &bytes,
            )?,
        };
        bytes.extend_from_slice(&tag);
        Ok(Zeroizing::new(bytes))
    }

    fn read_manifest(
        &self,
        path: &Path,
    ) -> Result<(RoleManifest, Zeroizing<Vec<u8>>), RoleRootCustodyError> {
        let mut bytes = Vec::new();
        secure_open_regular(path)
            .and_then(|mut file| file.read_to_end(&mut bytes))
            .map_err(|error| {
                RoleRootCustodyError::Io(format!("read {}: {error}", path.display()))
            })?;
        let bytes = Zeroizing::new(bytes);
        let manifest = self.decode_manifest(&bytes)?;
        Ok((manifest, bytes))
    }

    fn decode_manifest(&self, bytes: &[u8]) -> Result<RoleManifest, RoleRootCustodyError> {
        const MINIMUM: usize = 1 + 4 + 16 + 8 + 8 + 4 + 32 + 32;
        if bytes.len() < MINIMUM {
            return Err(RoleRootCustodyError::AuthenticationFailed);
        }
        let (body, observed_tag) = bytes.split_at(bytes.len() - 32);
        let mut header = RoleCursor::new(body);
        if header.u8()? != MANIFEST_VERSION {
            return Err(RoleRootCustodyError::AuthenticationFailed);
        }
        let epoch = header.u32()?;
        let registry_instance = header.array::<16>()?;
        let expected_tag = self.manifest_mac(epoch, registry_instance, body)?;
        if expected_tag.ct_eq(observed_tag).unwrap_u8() != 1 {
            return Err(RoleRootCustodyError::AuthenticationFailed);
        }
        let allocation_generation = header.u64()?;
        let next_allocation_sequence = header.u64()?;
        let entry_count = header.u32()? as usize;
        if registry_instance == [0; 16]
            || epoch == 0
            || next_allocation_sequence == 0
            || entry_count > MAX_ROLE_ALLOCATIONS
        {
            return Err(RoleRootCustodyError::AuthenticationFailed);
        }
        let mut entries = BTreeMap::new();
        let mut previous_key = None;
        let mut highest_allocation_sequence = 0u64;
        let mut allocation_sequences = std::collections::BTreeSet::new();
        let mut wrapping_nonces = std::collections::BTreeSet::new();
        for _ in 0..entry_count {
            let boot_id = header.array::<16>()?;
            let family_wire = header.u32()?;
            let family_version = u16::try_from(family_wire)
                .map_err(|_| RoleRootCustodyError::AuthenticationFailed)?;
            validate_key(boot_id, family_version)
                .map_err(|_| RoleRootCustodyError::AuthenticationFailed)?;
            let key = (boot_id, family_version);
            if previous_key.is_some_and(|previous| previous >= key) {
                return Err(RoleRootCustodyError::AuthenticationFailed);
            }
            previous_key = Some(key);
            let allocation_sequence = header.u64()?;
            let state = header.u8()?;
            let wrap_key_epoch = header.u32()?;
            let first_nonce = header.option_array::<24>()?;
            let first_ciphertext = header.option_array::<ROOT_CIPHERTEXT_LEN>()?;
            let second_nonce = header.option_array::<24>()?;
            let second_ciphertext = header.option_array::<ROOT_CIPHERTEXT_LEN>()?;
            let created_registry_sequence = header.u64()?;
            let erased_registry_sequence = header.option_u64()?;
            let dependency_high_water = header.u64()?;
            if allocation_sequence == 0
                || wrap_key_epoch == 0
                || created_registry_sequence == 0
                || !allocation_sequences.insert(allocation_sequence)
            {
                return Err(RoleRootCustodyError::AuthenticationFailed);
            }
            highest_allocation_sequence = highest_allocation_sequence.max(allocation_sequence);
            let entry = match state {
                ACTIVE_TAG
                    if erased_registry_sequence.is_none()
                        && dependency_high_water == 0
                        && first_nonce.is_some_and(|nonce| nonce != [0; 24])
                        && second_nonce.is_some_and(|nonce| nonce != [0; 24])
                        && first_nonce != second_nonce
                        && first_nonce.is_some_and(|nonce| wrapping_nonces.insert(nonce))
                        && second_nonce.is_some_and(|nonce| wrapping_nonces.insert(nonce))
                        && first_ciphertext.is_some()
                        && second_ciphertext.is_some() =>
                {
                    RoleEntry::Active(ActiveEntry {
                        allocation_sequence,
                        wrap_key_epoch,
                        first_nonce: first_nonce.expect("guarded option"),
                        first_ciphertext: first_ciphertext.expect("guarded option"),
                        second_nonce: second_nonce.expect("guarded option"),
                        second_ciphertext: second_ciphertext.expect("guarded option"),
                        created_registry_sequence,
                        dependency_high_water,
                    })
                }
                ERASED_TAG
                    if first_nonce.is_none()
                        && first_ciphertext.is_none()
                        && second_nonce.is_none()
                        && second_ciphertext.is_none()
                        && erased_registry_sequence.is_some_and(|erased| {
                            erased > created_registry_sequence
                                && dependency_high_water.checked_add(1) == Some(erased)
                        }) =>
                {
                    RoleEntry::Erased(ErasedEntry {
                        allocation_sequence,
                        wrap_key_epoch,
                        created_registry_sequence,
                        erased_registry_sequence: erased_registry_sequence.expect("guarded option"),
                        dependency_high_water,
                    })
                }
                _ => return Err(RoleRootCustodyError::AuthenticationFailed),
            };
            if entries.insert(key, entry).is_some() {
                return Err(RoleRootCustodyError::AuthenticationFailed);
            }
        }
        if (entry_count == 0 && (allocation_generation != 0 || next_allocation_sequence != 1))
            || (entry_count != 0
                && (allocation_generation == 0
                    || highest_allocation_sequence.checked_add(1)
                        != Some(next_allocation_sequence)))
        {
            return Err(RoleRootCustodyError::AuthenticationFailed);
        }
        let nonce = header.array::<32>()?;
        if nonce == [0; 32] || !header.is_empty() {
            return Err(RoleRootCustodyError::AuthenticationFailed);
        }
        Ok(RoleManifest {
            manifest_key_epoch: epoch,
            registry_instance,
            allocation_generation,
            next_allocation_sequence,
            entries,
            nonce,
        })
    }

    fn manifest_mac(
        &self,
        epoch: u32,
        registry_instance: [u8; 16],
        bytes: &[u8],
    ) -> Result<[u8; 32], RoleRootCustodyError> {
        let keys = self.keys.lock().map_err(|_| lock_error())?;
        let master_key = keys.get(&epoch).ok_or_else(|| {
            RoleRootCustodyError::RecoveryRequired(format!(
                "manifest key epoch {epoch} is unavailable"
            ))
        })?;
        manifest_mac_with_master_key(master_key, epoch, registry_instance, bytes)
    }

    fn manifest_mac_with_master_key(
        &self,
        epoch: u32,
        registry_instance: [u8; 16],
        master_key: &[u8; 32],
        bytes: &[u8],
    ) -> Result<[u8; 32], RoleRootCustodyError> {
        manifest_mac_with_master_key(master_key, epoch, registry_instance, bytes)
    }

    fn wrap_active(
        &self,
        manifest: &RoleManifest,
        boot_id: [u8; 16],
        family_version: u16,
        allocation_sequence: u64,
        created_registry_sequence: u64,
        dependency_high_water: u64,
        first_root: &[u8; 32],
        second_root: &[u8; 32],
    ) -> Result<ActiveEntry, RoleRootCustodyError> {
        let keys = self.keys.lock().map_err(|_| lock_error())?;
        let master_key = keys.get(&manifest.manifest_key_epoch).ok_or_else(|| {
            RoleRootCustodyError::RecoveryRequired(format!(
                "wrapping key epoch {} is unavailable",
                manifest.manifest_key_epoch
            ))
        })?;
        let key = derive_role_wrap_key(
            master_key,
            manifest.registry_instance,
            boot_id,
            family_version,
        )?;
        self.wrap_active_with_derived_key(
            boot_id,
            family_version,
            allocation_sequence,
            manifest.manifest_key_epoch,
            created_registry_sequence,
            dependency_high_water,
            first_root,
            second_root,
            &*key,
        )
    }

    fn wrap_active_with_master_key(
        &self,
        manifest: &RoleManifest,
        boot_id: [u8; 16],
        family_version: u16,
        allocation_sequence: u64,
        created_registry_sequence: u64,
        dependency_high_water: u64,
        first_root: &[u8; 32],
        second_root: &[u8; 32],
        master_key: &[u8; 32],
    ) -> Result<ActiveEntry, RoleRootCustodyError> {
        let key = derive_role_wrap_key(
            master_key,
            manifest.registry_instance,
            boot_id,
            family_version,
        )?;
        self.wrap_active_with_derived_key(
            boot_id,
            family_version,
            allocation_sequence,
            manifest.manifest_key_epoch,
            created_registry_sequence,
            dependency_high_water,
            first_root,
            second_root,
            &*key,
        )
    }

    fn wrap_active_with_derived_key(
        &self,
        boot_id: [u8; 16],
        family_version: u16,
        allocation_sequence: u64,
        wrap_key_epoch: u32,
        created_registry_sequence: u64,
        dependency_high_water: u64,
        first_root: &[u8; 32],
        second_root: &[u8; 32],
        derived_key: &[u8; 32],
    ) -> Result<ActiveEntry, RoleRootCustodyError> {
        let cipher = XChaCha20Poly1305::new_from_slice(derived_key)
            .map_err(|_| RoleRootCustodyError::Crypto)?;
        let first_nonce = random_nonzero_nonce()?;
        let mut second_nonce = random_nonzero_nonce()?;
        while second_nonce == first_nonce {
            second_nonce = random_nonzero_nonce()?;
        }
        let aad = entry_aad(
            boot_id,
            family_version,
            allocation_sequence,
            wrap_key_epoch,
            created_registry_sequence,
            dependency_high_water,
        );
        let first = cipher
            .encrypt(
                XNonce::from_slice(&first_nonce),
                Payload {
                    msg: first_root,
                    aad: &aad,
                },
            )
            .map_err(|_| RoleRootCustodyError::Crypto)?;
        let second = cipher
            .encrypt(
                XNonce::from_slice(&second_nonce),
                Payload {
                    msg: second_root,
                    aad: &aad,
                },
            )
            .map_err(|_| RoleRootCustodyError::Crypto)?;
        Ok(ActiveEntry {
            allocation_sequence,
            wrap_key_epoch,
            first_nonce,
            first_ciphertext: first.try_into().map_err(|_| RoleRootCustodyError::Crypto)?,
            second_nonce,
            second_ciphertext: second
                .try_into()
                .map_err(|_| RoleRootCustodyError::Crypto)?,
            created_registry_sequence,
            dependency_high_water,
        })
    }

    fn unwrap_active(
        &self,
        manifest: &RoleManifest,
        boot_id: [u8; 16],
        family_version: u16,
        active: &ActiveEntry,
    ) -> Result<(Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>), RoleRootCustodyError> {
        let keys = self.keys.lock().map_err(|_| lock_error())?;
        let master_key = keys.get(&active.wrap_key_epoch).ok_or_else(|| {
            RoleRootCustodyError::RecoveryRequired(format!(
                "wrapping key epoch {} is unavailable",
                active.wrap_key_epoch
            ))
        })?;
        let key = derive_role_wrap_key(
            master_key,
            manifest.registry_instance,
            boot_id,
            family_version,
        )?;
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
            .map_err(|_| RoleRootCustodyError::Crypto)?;
        let aad = entry_aad(
            boot_id,
            family_version,
            active.allocation_sequence,
            active.wrap_key_epoch,
            active.created_registry_sequence,
            active.dependency_high_water,
        );
        let mut first = cipher
            .decrypt(
                XNonce::from_slice(&active.first_nonce),
                Payload {
                    msg: &active.first_ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| RoleRootCustodyError::AuthenticationFailed)?;
        let mut second = cipher
            .decrypt(
                XNonce::from_slice(&active.second_nonce),
                Payload {
                    msg: &active.second_ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| RoleRootCustodyError::AuthenticationFailed)?;
        if first.len() != 32 || second.len() != 32 {
            first.zeroize();
            second.zeroize();
            return Err(RoleRootCustodyError::AuthenticationFailed);
        }
        let mut first_root = Zeroizing::new([0u8; 32]);
        let mut second_root = Zeroizing::new([0u8; 32]);
        first_root.copy_from_slice(&first);
        second_root.copy_from_slice(&second);
        first.zeroize();
        second.zeroize();
        if first_root.as_ref() == &[0; 32]
            || second_root.as_ref() == &[0; 32]
            || first_root.as_ref().ct_eq(second_root.as_ref()).unwrap_u8() == 1
        {
            return Err(RoleRootCustodyError::AuthenticationFailed);
        }
        Ok((first_root, second_root))
    }

    fn open_active(
        &self,
        manifest: &RoleManifest,
        boot_id: [u8; 16],
        family_version: u16,
        active: &ActiveEntry,
    ) -> Result<OpenedContract218RoleRoots, RoleRootCustodyError> {
        let (mut first, mut second) =
            self.unwrap_active(manifest, boot_id, family_version, active)?;
        let protection = self.memory.protect(&mut first, &mut second)?;
        Ok(OpenedContract218RoleRoots {
            registry_instance: manifest.registry_instance,
            boot_id,
            _wrap_key_epoch: active.wrap_key_epoch,
            _first_root: first,
            _second_root: second,
            memory_protection: protection,
        })
    }

    fn classify_manifest_successor(
        &self,
        current: &RoleManifest,
        pending: &RoleManifest,
    ) -> Result<RoleManifestTransition, RoleRootCustodyError> {
        let expected_generation =
            current
                .allocation_generation
                .checked_add(1)
                .ok_or_else(|| {
                    RoleRootCustodyError::RecoveryRequired(
                        "current role manifest generation is exhausted".to_owned(),
                    )
                })?;
        if pending.registry_instance != current.registry_instance
            || pending.allocation_generation != expected_generation
            || pending.nonce == current.nonce
        {
            return Err(invalid_pending_successor());
        }

        if pending.manifest_key_epoch == current.manifest_key_epoch {
            let expected_sequence =
                current
                    .next_allocation_sequence
                    .checked_add(1)
                    .ok_or_else(|| {
                        RoleRootCustodyError::RecoveryRequired(
                            "current role allocation sequence is exhausted".to_owned(),
                        )
                    })?;
            let expected_entry_count = current.entries.len().checked_add(1).ok_or_else(|| {
                RoleRootCustodyError::RecoveryRequired(
                    "role allocation entry count overflowed".to_owned(),
                )
            })?;
            if pending.next_allocation_sequence != expected_sequence
                || pending.entries.len() != expected_entry_count
                || current
                    .entries
                    .iter()
                    .any(|(key, entry)| pending.entries.get(key) != Some(entry))
            {
                return Err(invalid_pending_successor());
            }
            let mut additions = pending
                .entries
                .iter()
                .filter(|(key, _)| !current.entries.contains_key(key));
            let Some((_, RoleEntry::Active(active))) = additions.next() else {
                return Err(invalid_pending_successor());
            };
            if additions.next().is_some()
                || active.allocation_sequence != current.next_allocation_sequence
                || active.wrap_key_epoch != current.manifest_key_epoch
                || active.dependency_high_water != 0
            {
                return Err(invalid_pending_successor());
            }
            return Ok(RoleManifestTransition::Create);
        }

        if pending.manifest_key_epoch <= current.manifest_key_epoch
            || pending.entries.len() != current.entries.len()
            || current
                .entries
                .keys()
                .any(|key| !pending.entries.contains_key(key))
        {
            return Err(invalid_pending_successor());
        }
        if pending.next_allocation_sequence != current.next_allocation_sequence {
            return Err(invalid_pending_successor());
        }

        let mut erased_count = 0usize;
        for (&key, current_entry) in &current.entries {
            let pending_entry = pending
                .entries
                .get(&key)
                .ok_or_else(invalid_pending_successor)?;
            match (current_entry, pending_entry) {
                (RoleEntry::Erased(before), RoleEntry::Erased(after)) if before == after => {}
                (RoleEntry::Active(before), RoleEntry::Active(after))
                    if before.allocation_sequence == after.allocation_sequence
                        && before.created_registry_sequence == after.created_registry_sequence
                        && before.dependency_high_water == after.dependency_high_water
                        && after.wrap_key_epoch == pending.manifest_key_epoch =>
                {
                    let (before_first, before_second) =
                        self.unwrap_active(current, key.0, key.1, before)?;
                    let (after_first, after_second) =
                        self.unwrap_active(pending, key.0, key.1, after)?;
                    if before_first
                        .as_ref()
                        .ct_eq(after_first.as_ref())
                        .unwrap_u8()
                        != 1
                        || before_second
                            .as_ref()
                            .ct_eq(after_second.as_ref())
                            .unwrap_u8()
                            != 1
                    {
                        return Err(invalid_pending_successor());
                    }
                }
                (RoleEntry::Active(before), RoleEntry::Erased(after)) => {
                    if after.allocation_sequence != before.allocation_sequence
                        || after.wrap_key_epoch != before.wrap_key_epoch
                        || after.created_registry_sequence != before.created_registry_sequence
                        || after.dependency_high_water < before.dependency_high_water
                        || after.dependency_high_water.checked_add(1)
                            != Some(after.erased_registry_sequence)
                    {
                        return Err(invalid_pending_successor());
                    }
                    erased_count = erased_count.checked_add(1).ok_or_else(|| {
                        RoleRootCustodyError::RecoveryRequired(
                            "role erase transition count overflowed".to_owned(),
                        )
                    })?;
                }
                _ => return Err(invalid_pending_successor()),
            }
        }

        if erased_count == 0 {
            Ok(RoleManifestTransition::Rewrap)
        } else if erased_count == 1 {
            Ok(RoleManifestTransition::Erase)
        } else {
            Err(invalid_pending_successor())
        }
    }

    fn validate_transition_registry_sequence(
        &self,
        current: &RoleManifest,
        pending: &RoleManifest,
        transition: RoleManifestTransition,
        next_registry_sequence: u64,
    ) -> Result<(), RoleRootCustodyError> {
        if next_registry_sequence == 0 {
            return Err(invalid_pending_successor());
        }
        match transition {
            RoleManifestTransition::Create => {
                let created = pending
                    .entries
                    .iter()
                    .find_map(|(key, entry)| (!current.entries.contains_key(key)).then_some(entry))
                    .and_then(|entry| match entry {
                        RoleEntry::Active(active) => Some(active.created_registry_sequence),
                        RoleEntry::Erased(_) => None,
                    });
                if created != Some(next_registry_sequence) {
                    return Err(invalid_pending_successor());
                }
            }
            RoleManifestTransition::Erase => {
                let erased = current.entries.iter().find_map(|(key, before)| {
                    match (before, pending.entries.get(key)) {
                        (RoleEntry::Active(_), Some(RoleEntry::Erased(after))) => Some(after),
                        _ => None,
                    }
                });
                if !erased.is_some_and(|entry| {
                    entry.erased_registry_sequence == next_registry_sequence
                        && entry.dependency_high_water.checked_add(1)
                            == Some(next_registry_sequence)
                }) {
                    return Err(invalid_pending_successor());
                }
            }
            RoleManifestTransition::Rewrap => {}
        }
        Ok(())
    }

    fn recover_unlocked(
        &self,
        anchored: &RegistryAnchorTuple,
    ) -> Result<RoleManifestRecovery, RoleRootCustodyError> {
        match self.anchor.observe().map_err(anchor_error)? {
            RegistryAnchorWorld::CompactCurrent { current, .. } if current == *anchored => {}
            _ => return Err(RoleRootCustodyError::AnchorMismatch),
        }
        let (current, current_bytes) = self.read_manifest(&self.current_path())?;
        let current_root = root_of(&current_bytes);
        if current.registry_instance != anchored.registry_instance {
            return Err(RoleRootCustodyError::AnchorMismatch);
        }
        if !role_file_exists(&self.pending_path())? {
            validate_anchor(&current, current_root, anchored)?;
            return Ok(RoleManifestRecovery::Clean);
        }
        let (pending, pending_bytes) = self.read_manifest(&self.pending_path())?;
        let pending_root = root_of(&pending_bytes);
        let transition = self.classify_manifest_successor(&current, &pending)?;
        if pending_root == current_root {
            return Err(invalid_pending_successor());
        }
        if anchored.role_allocation_root == current_root.0 {
            let next_registry_sequence = anchored.sequence.checked_add(1).ok_or_else(|| {
                RoleRootCustodyError::RecoveryRequired(
                    "current registry sequence is exhausted".to_owned(),
                )
            })?;
            self.validate_transition_registry_sequence(
                &current,
                &pending,
                transition,
                next_registry_sequence,
            )?;
            secure_remove_regular(&self.pending_path()).map_err(|error| {
                RoleRootCustodyError::Io(format!("remove rolled-back pending manifest: {error}"))
            })?;
            fsync_directory(&self.directory)?;
            if pending.manifest_key_epoch != current.manifest_key_epoch {
                self.keys
                    .lock()
                    .map_err(|_| lock_error())?
                    .remove(&pending.manifest_key_epoch);
            }
            Ok(RoleManifestRecovery::RolledBackPending)
        } else if anchored.role_allocation_root == pending_root.0 {
            self.validate_transition_registry_sequence(
                &current,
                &pending,
                transition,
                anchored.sequence,
            )?;
            self.promote_pending_files()?;
            if transition == RoleManifestTransition::Erase {
                self.keys
                    .lock()
                    .map_err(|_| lock_error())?
                    .retain(|epoch, _| *epoch == pending.manifest_key_epoch);
            }
            Ok(RoleManifestRecovery::PromotedPending)
        } else {
            Err(RoleRootCustodyError::RecoveryRequired(
                "anchor names neither current nor pending role manifest".to_owned(),
            ))
        }
    }

    fn promote_pending(
        &self,
        expected_previous: RoleAllocationRoot,
        expected_next: RoleAllocationRoot,
        registry_instance: [u8; 16],
        anchored: &RegistryAnchorTuple,
    ) -> Result<(), RoleRootCustodyError> {
        match self.anchor.observe().map_err(anchor_error)? {
            RegistryAnchorWorld::CompactCurrent { current, .. } if current == *anchored => {}
            _ => return Err(RoleRootCustodyError::AnchorMismatch),
        }
        let (current, current_bytes) = self.read_manifest(&self.current_path())?;
        let (pending, pending_bytes) = self.read_manifest(&self.pending_path())?;
        if current.registry_instance != registry_instance
            || pending.registry_instance != registry_instance
            || root_of(&current_bytes) != expected_previous
            || root_of(&pending_bytes) != expected_next
        {
            return Err(RoleRootCustodyError::RecoveryRequired(
                "prepared role manifest changed before commit".to_owned(),
            ));
        }
        let transition = self.classify_manifest_successor(&current, &pending)?;
        self.validate_transition_registry_sequence(
            &current,
            &pending,
            transition,
            anchored.sequence,
        )?;
        validate_anchor(&pending, expected_next, anchored)?;
        self.promote_pending_files()
    }

    fn promote_pending_files(&self) -> Result<(), RoleRootCustodyError> {
        secure_replace_regular(&self.pending_path(), &self.current_path()).map_err(|error| {
            RoleRootCustodyError::Io(format!("promote pending role manifest: {error}"))
        })?;
        fsync_directory(&self.directory)
    }
}

fn derive_role_wrap_key(
    master_key: &[u8; 32],
    registry_instance: [u8; 16],
    boot_id: [u8; 16],
    family_version: u16,
) -> Result<Zeroizing<[u8; 32]>, RoleRootCustodyError> {
    let mut salt = [0u8; 32];
    salt[..16].copy_from_slice(&registry_instance);
    salt[16..].copy_from_slice(&boot_id);
    let mut info = Vec::with_capacity(ROLE_ROOT_WRAP_INFO_DOMAIN.len() + 4);
    info.extend_from_slice(ROLE_ROOT_WRAP_INFO_DOMAIN);
    info.extend_from_slice(&u32::from(family_version).to_be_bytes());
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), master_key);
    let mut output = Zeroizing::new([0u8; 32]);
    hkdf.expand(&info, output.as_mut())
        .map_err(|_| RoleRootCustodyError::Crypto)?;
    Ok(output)
}

fn derive_manifest_mac_key(
    master_key: &[u8; 32],
    epoch: u32,
    registry_instance: [u8; 16],
) -> Result<Zeroizing<[u8; 32]>, RoleRootCustodyError> {
    let mut info = Vec::with_capacity(ROLE_MANIFEST_KEY_INFO_DOMAIN.len() + 4);
    info.extend_from_slice(ROLE_MANIFEST_KEY_INFO_DOMAIN);
    info.extend_from_slice(&epoch.to_be_bytes());
    let hkdf = Hkdf::<Sha256>::new(Some(&registry_instance), master_key);
    let mut output = Zeroizing::new([0u8; 32]);
    hkdf.expand(&info, output.as_mut())
        .map_err(|_| RoleRootCustodyError::Crypto)?;
    Ok(output)
}

fn manifest_mac_with_master_key(
    master_key: &[u8; 32],
    epoch: u32,
    registry_instance: [u8; 16],
    preceding_bytes: &[u8],
) -> Result<[u8; 32], RoleRootCustodyError> {
    let key = derive_manifest_mac_key(master_key, epoch, registry_instance)?;
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key.as_ref())
        .map_err(|_| RoleRootCustodyError::Crypto)?;
    mac.update(ROLE_MANIFEST_MAC_DOMAIN);
    mac.update(preceding_bytes);
    Ok(mac.finalize().into_bytes().into())
}

fn entry_aad(
    boot_id: [u8; 16],
    family_version: u16,
    allocation_sequence: u64,
    wrap_key_epoch: u32,
    created_registry_sequence: u64,
    dependency_high_water: u64,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(16 + 4 + 8 + 1 + 4 + 8 + 8);
    aad.extend_from_slice(&boot_id);
    aad.extend_from_slice(&u32::from(family_version).to_be_bytes());
    aad.extend_from_slice(&allocation_sequence.to_be_bytes());
    aad.push(ACTIVE_TAG);
    aad.extend_from_slice(&wrap_key_epoch.to_be_bytes());
    aad.extend_from_slice(&created_registry_sequence.to_be_bytes());
    aad.extend_from_slice(&dependency_high_water.to_be_bytes());
    aad
}

fn encode_manifest_preceding_bytes(
    manifest: &RoleManifest,
) -> Result<Vec<u8>, RoleRootCustodyError> {
    validate_manifest_canonical(manifest)?;
    let mut bytes = Vec::new();
    bytes.push(MANIFEST_VERSION);
    bytes.extend_from_slice(&manifest.manifest_key_epoch.to_be_bytes());
    bytes.extend_from_slice(&manifest.registry_instance);
    bytes.extend_from_slice(&manifest.allocation_generation.to_be_bytes());
    bytes.extend_from_slice(&manifest.next_allocation_sequence.to_be_bytes());
    bytes.extend_from_slice(&(manifest.entries.len() as u32).to_be_bytes());
    for (&(boot_id, family_version), entry) in &manifest.entries {
        bytes.extend_from_slice(&boot_id);
        bytes.extend_from_slice(&u32::from(family_version).to_be_bytes());
        match entry {
            RoleEntry::Active(active) => {
                bytes.extend_from_slice(&active.allocation_sequence.to_be_bytes());
                bytes.push(ACTIVE_TAG);
                bytes.extend_from_slice(&active.wrap_key_epoch.to_be_bytes());
                push_option_array(&mut bytes, Some(&active.first_nonce));
                push_option_array(&mut bytes, Some(&active.first_ciphertext));
                push_option_array(&mut bytes, Some(&active.second_nonce));
                push_option_array(&mut bytes, Some(&active.second_ciphertext));
                bytes.extend_from_slice(&active.created_registry_sequence.to_be_bytes());
                bytes.push(0);
                bytes.extend_from_slice(&active.dependency_high_water.to_be_bytes());
            }
            RoleEntry::Erased(erased) => {
                bytes.extend_from_slice(&erased.allocation_sequence.to_be_bytes());
                bytes.push(ERASED_TAG);
                bytes.extend_from_slice(&erased.wrap_key_epoch.to_be_bytes());
                bytes.extend_from_slice(&[0, 0, 0, 0]);
                bytes.extend_from_slice(&erased.created_registry_sequence.to_be_bytes());
                bytes.push(1);
                bytes.extend_from_slice(&erased.erased_registry_sequence.to_be_bytes());
                bytes.extend_from_slice(&erased.dependency_high_water.to_be_bytes());
            }
        }
    }
    bytes.extend_from_slice(&manifest.nonce);
    Ok(bytes)
}

fn push_option_array<const N: usize>(bytes: &mut Vec<u8>, value: Option<&[u8; N]>) {
    match value {
        Some(value) => {
            bytes.push(1);
            bytes.extend_from_slice(value);
        }
        None => bytes.push(0),
    }
}

fn validate_manifest_canonical(manifest: &RoleManifest) -> Result<(), RoleRootCustodyError> {
    if manifest.entries.len() > MAX_ROLE_ALLOCATIONS
        || manifest.registry_instance == [0; 16]
        || manifest.manifest_key_epoch == 0
        || manifest.next_allocation_sequence == 0
        || manifest.nonce == [0; 32]
    {
        return Err(RoleRootCustodyError::Invalid(
            "manifest header is outside canonical bounds".to_owned(),
        ));
    }
    if manifest.entries.is_empty() {
        if manifest.allocation_generation != 0 || manifest.next_allocation_sequence != 1 {
            return Err(RoleRootCustodyError::Invalid(
                "empty manifest must be the exact generation-zero form".to_owned(),
            ));
        }
        return Ok(());
    }
    if manifest.allocation_generation == 0 {
        return Err(RoleRootCustodyError::Invalid(
            "nonempty manifest generation must be positive".to_owned(),
        ));
    }

    let mut allocation_sequences = std::collections::BTreeSet::new();
    let mut wrapping_nonces = std::collections::BTreeSet::new();
    let mut maximum_allocation_sequence = 0_u64;
    for (&(boot_id, family_version), entry) in &manifest.entries {
        validate_key(boot_id, family_version)?;
        let (allocation_sequence, wrap_key_epoch, created_registry_sequence) = match entry {
            RoleEntry::Active(active) => {
                if active.dependency_high_water != 0
                    || active.first_nonce == [0; 24]
                    || active.second_nonce == [0; 24]
                    || active.first_nonce == active.second_nonce
                    || !wrapping_nonces.insert(active.first_nonce)
                    || !wrapping_nonces.insert(active.second_nonce)
                {
                    return Err(RoleRootCustodyError::Invalid(
                        "active role entry violates canonical constraints".to_owned(),
                    ));
                }
                (
                    active.allocation_sequence,
                    active.wrap_key_epoch,
                    active.created_registry_sequence,
                )
            }
            RoleEntry::Erased(erased) => {
                if erased.erased_registry_sequence <= erased.created_registry_sequence
                    || erased.dependency_high_water.checked_add(1)
                        != Some(erased.erased_registry_sequence)
                {
                    return Err(RoleRootCustodyError::Invalid(
                        "erased role entry violates canonical constraints".to_owned(),
                    ));
                }
                (
                    erased.allocation_sequence,
                    erased.wrap_key_epoch,
                    erased.created_registry_sequence,
                )
            }
        };
        if allocation_sequence == 0
            || wrap_key_epoch == 0
            || created_registry_sequence == 0
            || !allocation_sequences.insert(allocation_sequence)
        {
            return Err(RoleRootCustodyError::Invalid(
                "role entry identity is outside canonical bounds".to_owned(),
            ));
        }
        maximum_allocation_sequence = maximum_allocation_sequence.max(allocation_sequence);
    }
    if maximum_allocation_sequence.checked_add(1) != Some(manifest.next_allocation_sequence) {
        return Err(RoleRootCustodyError::Invalid(
            "next allocation sequence is not one above the maximum".to_owned(),
        ));
    }
    Ok(())
}

fn validate_anchor(
    manifest: &RoleManifest,
    root: RoleAllocationRoot,
    anchored: &RegistryAnchorTuple,
) -> Result<(), RoleRootCustodyError> {
    if manifest.registry_instance != anchored.registry_instance
        || root.0.ct_eq(&anchored.role_allocation_root).unwrap_u8() != 1
    {
        return Err(RoleRootCustodyError::AnchorMismatch);
    }
    Ok(())
}

fn anchor_error(
    error: advance_scheduler::observation_anchor::RegistryAnchorError,
) -> RoleRootCustodyError {
    RoleRootCustodyError::RecoveryRequired(error.to_string())
}

fn validate_key(boot_id: [u8; 16], family_version: u16) -> Result<(), RoleRootCustodyError> {
    if boot_id == [0; 16] || family_version != FAMILY_VERSION {
        return Err(RoleRootCustodyError::Invalid(
            "boot id must be nonzero and family version must equal 1".to_owned(),
        ));
    }
    Ok(())
}

fn independent_roots() -> Result<(Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>), RoleRootCustodyError> {
    let mut first = Zeroizing::new([0u8; 32]);
    let mut second = Zeroizing::new([0u8; 32]);
    OsRng
        .try_fill_bytes(first.as_mut())
        .map_err(|_| RoleRootCustodyError::Crypto)?;
    while first.as_ref() == &[0; 32] {
        OsRng
            .try_fill_bytes(first.as_mut())
            .map_err(|_| RoleRootCustodyError::Crypto)?;
    }
    OsRng
        .try_fill_bytes(second.as_mut())
        .map_err(|_| RoleRootCustodyError::Crypto)?;
    while second.as_ref() == &[0; 32] || first.as_ref().ct_eq(second.as_ref()).unwrap_u8() == 1 {
        OsRng
            .try_fill_bytes(second.as_mut())
            .map_err(|_| RoleRootCustodyError::Crypto)?;
    }
    Ok((first, second))
}

fn random_nonzero_nonce() -> Result<[u8; 24], RoleRootCustodyError> {
    let mut nonce = [0u8; 24];
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| RoleRootCustodyError::Crypto)?;
    while nonce == [0; 24] {
        OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| RoleRootCustodyError::Crypto)?;
    }
    Ok(nonce)
}

fn random_nonzero_manifest_nonce() -> Result<[u8; 32], RoleRootCustodyError> {
    let mut nonce = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| RoleRootCustodyError::Crypto)?;
    while nonce == [0; 32] {
        OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| RoleRootCustodyError::Crypto)?;
    }
    Ok(nonce)
}

fn root_of(bytes: &[u8]) -> RoleAllocationRoot {
    RoleAllocationRoot(role_allocation_file_root(bytes))
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), RoleRootCustodyError> {
    let parent = path
        .parent()
        .ok_or_else(|| RoleRootCustodyError::Io("role manifest path has no parent".to_owned()))?;
    let temporary = atomic_temporary_path(path)?;
    role_file_exists(path)?;
    let mut file = secure_create_new_regular(&temporary)
        .map_err(|error| RoleRootCustodyError::Io(format!("open role manifest temp: {error}")))?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|error| {
            RoleRootCustodyError::Io(format!("write/fsync role manifest temp: {error}"))
        })?;
    secure_replace_regular(&temporary, path)
        .map_err(|error| RoleRootCustodyError::Io(format!("rename role manifest: {error}")))?;
    fsync_directory(parent)
}

fn cleanup_failed_pending_write(path: &Path) -> Result<(), RoleRootCustodyError> {
    let parent = path
        .parent()
        .ok_or_else(|| RoleRootCustodyError::Io("role manifest path has no parent".to_owned()))?;
    let temporary = atomic_temporary_path(path)?;
    for artifact in [path, temporary.as_path()] {
        match secure_remove_regular(artifact) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(RoleRootCustodyError::Io(format!(
                    "remove failed rewrap artifact {}: {error}",
                    artifact.display()
                )))
            }
        }
    }
    fsync_directory(parent)
}

fn atomic_temporary_path(path: &Path) -> Result<PathBuf, RoleRootCustodyError> {
    let parent = path
        .parent()
        .ok_or_else(|| RoleRootCustodyError::Io("role manifest path has no parent".to_owned()))?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            RoleRootCustodyError::Io("role manifest path is not valid UTF-8".to_owned())
        })?;
    Ok(parent.join(format!(".{name}.tmp")))
}

fn role_file_exists(path: &Path) -> Result<bool, RoleRootCustodyError> {
    secure_regular_exists(path).map_err(|error| {
        RoleRootCustodyError::RecoveryRequired(format!(
            "inspect confined role artifact {}: {error}",
            path.display()
        ))
    })
}

/// Exercises the production role-root leaf gate with an integration-test supplied path.
#[cfg(feature = "test-support")]
#[doc(hidden)]
pub fn test_only_role_file_exists(path: &Path) -> Result<bool, RoleRootCustodyError> {
    role_file_exists(path)
}

fn fsync_directory(directory: &Path) -> Result<(), RoleRootCustodyError> {
    File::open(directory)
        .and_then(|file| file.sync_all())
        .map_err(|error| {
            RoleRootCustodyError::Io(format!("fsync role manifest directory: {error}"))
        })
}

fn lock_error() -> RoleRootCustodyError {
    RoleRootCustodyError::Io("role-root process lock poisoned".to_owned())
}

fn invalid_pending_successor() -> RoleRootCustodyError {
    RoleRootCustodyError::RecoveryRequired(
        "pending role manifest is not the unique legal next generation".to_owned(),
    )
}

struct RoleCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> RoleCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], RoleRootCustodyError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(RoleRootCustodyError::AuthenticationFailed)?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or(RoleRootCustodyError::AuthenticationFailed)?;
        self.offset = end;
        Ok(bytes)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], RoleRootCustodyError> {
        self.take(N)?
            .try_into()
            .map_err(|_| RoleRootCustodyError::AuthenticationFailed)
    }

    fn u8(&mut self) -> Result<u8, RoleRootCustodyError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, RoleRootCustodyError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, RoleRootCustodyError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn option_u64(&mut self) -> Result<Option<u64>, RoleRootCustodyError> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.u64()?)),
            _ => Err(RoleRootCustodyError::AuthenticationFailed),
        }
    }

    fn option_array<const N: usize>(&mut self) -> Result<Option<[u8; N]>, RoleRootCustodyError> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.array()?)),
            _ => Err(RoleRootCustodyError::AuthenticationFailed),
        }
    }

    fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn every_role_leaf_uses_the_character_device_rejecting_gate() {
        for leaf in [
            CURRENT_FILE,
            PENDING_FILE,
            ".contract218.roles.current.tmp",
            ".contract218.roles.pending.tmp",
        ] {
            assert!(
                role_file_exists(Path::new("/dev/null")).is_err(),
                "role leaf {leaf} accepted a character device"
            );
        }
    }

    #[test]
    fn xchacha_root_wrap_literal_kat() {
        let master_key = [0x42; 32];
        let registry_instance = [0x33; 16];
        let boot_id = [0x44; 16];
        let key = derive_role_wrap_key(&master_key, registry_instance, boot_id, 1).unwrap();
        assert_eq!(
            hex::encode(key.as_ref()),
            "853c122827a58101b9f54d47b516743a1fb0cfd6d744b3161ae58c2c95f5c4ad"
        );
        let aad = entry_aad(boot_id, 1, 7, 9, 11, 0);
        assert_eq!(
            hex::encode(&aad),
            "444444444444444444444444444444440000000100000000000000070100000009000000000000000b0000000000000000"
        );
        let nonce = [0x24; 24];
        let root = [0x11; 32];
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref()).unwrap();
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &root,
                    aad: &aad,
                },
            )
            .unwrap();
        assert_eq!(ciphertext.len(), ROOT_CIPHERTEXT_LEN);
        assert_eq!(
            hex::encode(&ciphertext),
            "19b8a84256e56f1257105b07d79b52cec329452943e38ad11b17041c7589a43e1a78f066091638510d14aa53abf21727"
        );
        assert_eq!(
            cipher
                .decrypt(
                    XNonce::from_slice(&nonce),
                    Payload {
                        msg: &ciphertext,
                        aad: &aad,
                    }
                )
                .unwrap(),
            root
        );
    }

    #[test]
    fn exact_empty_manifest_is_105_bytes_and_has_literal_mac() {
        let master_key = [0x42; 32];
        let manifest = RoleManifest {
            manifest_key_epoch: 7,
            registry_instance: [0x33; 16],
            allocation_generation: 0,
            next_allocation_sequence: 1,
            entries: BTreeMap::new(),
            nonce: [0x55; 32],
        };
        let mut bytes = encode_manifest_preceding_bytes(&manifest).unwrap();
        assert_eq!(bytes.len(), 73);
        let mac = manifest_mac_with_master_key(
            &master_key,
            manifest.manifest_key_epoch,
            manifest.registry_instance,
            &bytes,
        )
        .unwrap();
        assert_eq!(
            hex::encode(mac),
            "4946bdf2d9478315b69481ea9e8123f46553d8050f1c1d581bce145baaa2aeb6"
        );
        bytes.extend_from_slice(&mac);
        assert_eq!(bytes.len(), 105);
        assert_eq!(
            hex::encode(role_allocation_file_root(&bytes)),
            "5ed4ada04d84fc200b9749283beb6d72a7733670b1b5af981a201bd2d0e01067"
        );
    }
}

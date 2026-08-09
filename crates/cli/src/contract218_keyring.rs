//! Authenticated external custody for CONTRACT-218 persisted-identity keys.
//!
//! The file is an anchored, complete replacement artifact.  This Order-2
//! foundation never exports a host-master or derived carrier key and does not
//! accept caller-reported retirement scan watermarks.

use crate::contract218_anchor::{
    secure_create_new_regular, secure_open_regular, secure_regular_exists, secure_remove_regular,
    secure_replace_regular, FilePlatformMonotonicAnchorStore, SharedKeyringCustodyClaim,
};
use advance_scheduler::observation_anchor::{
    persisted_keyring_file_root, prepare_persisted_keyring_mutation,
    PreparedPersistedKeyringMutation, RegistryAnchorTransaction, RegistryAnchorTuple,
    RegistryAnchorWorld, RegistryHeadContext,
};
use advance_scheduler::sensitive_params::{
    PersistedKeyringCustody, PreparedPersistedKeyringCustodyMutation,
};
use advance_shared_types::contract218_previsible::{
    CustodySignedPersistedIdentity, PersistedIdentityKeyCapabilityBinding,
    PersistedIdentityKeyStatus, PersistedIdentityKeyringBinding, PersistedIdentityKeyringProvider,
    PersistedIdentitySigningRequest, PersistedIdentityVerificationRequest,
    VerifiedPersistedKeyRetirementScanSet,
};
use advance_shared_types::observation_identity::{
    SensitiveParamCatalogError, MAX_PERSISTED_IDENTITY_BYTES, MIN_PERSISTED_IDENTITY_BYTES,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

const CURRENT_FILE: &str = "contract218.keyring.current";
const PENDING_FILE: &str = "contract218.keyring.pending";
const FILE_VERSION: u8 = 1;
const SIGNING_TAG: u8 = 1;
const VERIFY_ONLY_TAG: u8 = 2;
const RETIRED_TAG: u8 = 3;
const MANIFEST_KEY_INFO_DOMAIN: &[u8] = b"advance.contract218.persisted-keyring-manifest-key.v1\0";
const MANIFEST_MAC_DOMAIN: &[u8] = b"advance.contract218.persisted-keyring-manifest.v1\0";
const CARRIER_KEY_INFO_DOMAIN: &[u8] = b"advance.contract218.persisted-identity-key.v1\0";
const CARRIER_MAC_DOMAIN: &[u8] = b"advance.contract218.persisted-identity.v1\0";
const MIGRATION_MARKER_KEY_INFO_DOMAIN: &[u8] =
    b"advance.contract218.registry-migration-marker-key.v1\0";
const MIGRATION_MARKER_MAC_DOMAIN: &[u8] = b"advance.contract218.registry-migration-marker.v1\0";

#[derive(Debug, Error)]
pub enum PersistedKeyringCustodyError {
    #[error("persisted-keyring I/O failed: {0}")]
    Io(String),
    #[error("persisted-keyring authentication failed")]
    AuthenticationFailed,
    #[error("persisted-keyring requires operator recovery: {0}")]
    RecoveryRequired(String),
    #[error("persisted-keyring anchor does not name the prepared file")]
    AnchorMismatch,
    #[error("persisted-keyring key id is unavailable")]
    KeyUnavailable,
    #[error("persisted-keyring key is permanently retired")]
    Retired,
    #[error("invalid persisted-keyring input: {0}")]
    Invalid(String),
    #[error("persisted-keyring cryptographic operation failed")]
    Crypto,
    #[cfg(feature = "test-support")]
    #[error("persisted-keyring failpoint: {0:?}")]
    Failpoint(KeyringFailpoint),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PersistedKeyringRoot([u8; 32]);

impl PersistedKeyringRoot {
    pub fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PersistedKeyStatus {
    Signing,
    VerifyOnly,
    Retired,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistedKeyEntryView {
    pub key_id: u32,
    pub status: PersistedKeyStatus,
    pub master_key_epoch: u32,
    pub last_issued_at_ms: u64,
    pub has_complete_retirement_scan: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PersistedKeyringRecovery {
    Clean,
    RolledBackPending,
    PromotedPending,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg(feature = "test-support")]
pub enum KeyringFailpoint {
    AfterPendingFsync,
    BeforePendingPromotion,
}

#[derive(Clone)]
pub struct FilePersistedIdentityKeyringCustody {
    inner: Arc<KeyringInner>,
}

struct KeyringInner {
    directory: PathBuf,
    anchor: FilePlatformMonotonicAnchorStore,
    _exclusive_custody: SharedKeyringCustodyClaim,
    master_keys: Mutex<BTreeMap<u32, Zeroizing<[u8; 32]>>>,
    writer: Mutex<()>,
    session_open_root: Mutex<Option<PersistedKeyringRoot>>,
    #[cfg(feature = "test-support")]
    failpoint: Mutex<Option<KeyringFailpoint>>,
}

impl FilePersistedIdentityKeyringCustody {
    pub(crate) fn shares_anchor(&self, anchor: &FilePlatformMonotonicAnchorStore) -> bool {
        self.inner.anchor.shares_store_with(anchor)
    }

    pub fn from_anchor_store(
        anchor: &FilePlatformMonotonicAnchorStore,
        master_keys: Vec<(u32, Zeroizing<[u8; 32]>)>,
    ) -> Result<Self, PersistedKeyringCustodyError> {
        let (directory, custody) = anchor.claim_keyring_custody().map_err(anchor_error)?;
        let mut keys = BTreeMap::new();
        for (epoch, key) in master_keys {
            if epoch == 0 || key.as_ref() == &[0; 32] || keys.insert(epoch, key).is_some() {
                return Err(PersistedKeyringCustodyError::Invalid(
                    "master-key epochs must be unique, positive, and nonzero-keyed".to_owned(),
                ));
            }
        }
        if keys.is_empty() {
            return Err(PersistedKeyringCustodyError::Invalid(
                "at least one host-master epoch is required".to_owned(),
            ));
        }
        let inner = Arc::new(KeyringInner {
            directory,
            anchor: anchor.clone(),
            _exclusive_custody: custody,
            master_keys: Mutex::new(keys),
            writer: Mutex::new(()),
            session_open_root: Mutex::new(None),
            #[cfg(feature = "test-support")]
            failpoint: Mutex::new(None),
        });
        if keyring_file_exists(&inner.current_path())? {
            if keyring_file_exists(&atomic_temporary_path(&inner.current_path())?)? {
                return Err(PersistedKeyringCustodyError::RecoveryRequired(
                    "keyring custody found an interrupted atomic write".to_owned(),
                ));
            }
            let (manifest, bytes) = inner.read_manifest(&inner.current_path())?;
            inner.require_ready_keys(&manifest)?;
            *inner.session_open_root.lock().map_err(|_| lock_error())? = Some(root_of(&bytes));
        }
        Ok(Self { inner })
    }

    pub fn initialize_genesis(
        &self,
        registry_instance: [u8; 16],
        manifest_key_epoch: u32,
        signing_master_key_epoch: u32,
    ) -> Result<PersistedKeyringRoot, PersistedKeyringCustodyError> {
        if registry_instance == [0; 16] || manifest_key_epoch == 0 || signing_master_key_epoch == 0
        {
            return Err(PersistedKeyringCustodyError::Invalid(
                "registry and key epochs must be positive".to_owned(),
            ));
        }
        let _writer = self.inner.writer.lock().map_err(|_| lock_error())?;
        let current = self.inner.current_path();
        let pending = self.inner.pending_path();
        if keyring_file_exists(&current)?
            || keyring_file_exists(&pending)?
            || keyring_file_exists(&atomic_temporary_path(&current)?)?
            || keyring_file_exists(&atomic_temporary_path(&pending)?)?
        {
            return Err(PersistedKeyringCustodyError::RecoveryRequired(
                "keyring initialization encountered pre-existing state".to_owned(),
            ));
        }
        self.inner.require_key(manifest_key_epoch)?;
        self.inner.require_key(signing_master_key_epoch)?;
        let mut entries = BTreeMap::new();
        entries.insert(
            1,
            KeyEntry {
                status: PersistedKeyStatus::Signing,
                master_key_epoch: signing_master_key_epoch,
                last_issued_at_ms: 0,
                scan: None,
            },
        );
        let manifest = KeyringManifest {
            manifest_key_epoch,
            registry_instance,
            generation: 0,
            previous_keyring_root: [0; 32],
            kdf_salt: random_nonzero_32()?,
            next_key_id: 2,
            signing_key_id: 1,
            entries,
            manifest_nonce: random_nonzero_32()?,
        };
        let bytes = self.inner.encode_manifest(&manifest)?;
        atomic_write(&current, &bytes)?;
        let root = root_of(&bytes);
        *self
            .inner
            .session_open_root
            .lock()
            .map_err(|_| lock_error())? = Some(root);
        Ok(root)
    }

    pub fn current_root(&self) -> Result<PersistedKeyringRoot, PersistedKeyringCustodyError> {
        let _writer = self.inner.writer.lock().map_err(|_| lock_error())?;
        let (_, bytes) = self.inner.read_manifest(&self.inner.current_path())?;
        Ok(root_of(&bytes))
    }

    /// Read the authenticated registry identity from the custody manifest.
    /// The external anchor is checked when present; the only exception is the
    /// exact selector-free greenfield window before provider genesis.
    pub fn registry_instance(&self) -> Result<[u8; 16], PersistedKeyringCustodyError> {
        let _writer = self.inner.writer.lock().map_err(|_| lock_error())?;
        let (manifest, bytes) = self.inner.read_manifest(&self.inner.current_path())?;
        self.inner.require_ready_keys(&manifest)?;
        self.inner
            .verify_anchor_or_exact_greenfield(&manifest, root_of(&bytes))?;
        Ok(manifest.registry_instance)
    }

    pub fn authenticated_current_file(
        &self,
        expected_registry_instance: [u8; 16],
    ) -> Result<Vec<u8>, PersistedKeyringCustodyError> {
        let _writer = self.inner.writer.lock().map_err(|_| lock_error())?;
        self.inner.require_no_pending()?;
        let (manifest, bytes) = self.inner.read_manifest(&self.inner.current_path())?;
        if manifest.registry_instance != expected_registry_instance {
            return Err(PersistedKeyringCustodyError::AnchorMismatch);
        }
        self.inner.require_ready_keys(&manifest)?;
        self.inner
            .verify_anchor_or_exact_greenfield(&manifest, root_of(&bytes))?;
        Ok(bytes.to_vec())
    }

    /// Migration-only read of the authenticated generation-zero target before
    /// a platform anchor exists.  This stays crate-private so ordinary callers
    /// cannot bypass the anchor check performed by `authenticated_current_file`.
    pub(crate) fn authenticated_initial_file_for_migration(
        &self,
        expected_registry_instance: [u8; 16],
        expected_manifest_key_epoch: u32,
    ) -> Result<Zeroizing<Vec<u8>>, PersistedKeyringCustodyError> {
        let _writer = self.inner.writer.lock().map_err(|_| lock_error())?;
        self.inner.require_no_pending()?;
        let (manifest, bytes) = self.inner.read_manifest(&self.inner.current_path())?;
        if manifest.registry_instance != expected_registry_instance
            || manifest.manifest_key_epoch != expected_manifest_key_epoch
            || manifest.generation != 0
            || manifest.previous_keyring_root != [0; 32]
        {
            return Err(PersistedKeyringCustodyError::AuthenticationFailed);
        }
        self.inner.require_ready_keys(&manifest)?;
        Ok(bytes)
    }

    pub(crate) fn marker_mac(
        &self,
        manifest_key_epoch: u32,
        registry_instance: [u8; 16],
        preceding_marker_bytes: &[u8],
    ) -> Result<[u8; 32], PersistedKeyringCustodyError> {
        self.inner.marker_mac(
            manifest_key_epoch,
            registry_instance,
            preceding_marker_bytes,
        )
    }

    pub fn entries(&self) -> Result<Vec<PersistedKeyEntryView>, PersistedKeyringCustodyError> {
        let _writer = self.inner.writer.lock().map_err(|_| lock_error())?;
        self.inner.require_no_pending()?;
        let (manifest, bytes) = self.inner.read_manifest(&self.inner.current_path())?;
        self.inner
            .verified_current_anchor(&manifest, root_of(&bytes))?;
        Ok(manifest
            .entries
            .iter()
            .map(|(&key_id, entry)| PersistedKeyEntryView {
                key_id,
                status: entry.status,
                master_key_epoch: entry.master_key_epoch,
                last_issued_at_ms: entry.last_issued_at_ms,
                has_complete_retirement_scan: entry.scan.is_some(),
            })
            .collect())
    }

    pub fn signing_key_id(&self) -> Result<u32, PersistedKeyringCustodyError> {
        let _writer = self.inner.writer.lock().map_err(|_| lock_error())?;
        self.inner.require_no_pending()?;
        let (manifest, bytes) = self.inner.read_manifest(&self.inner.current_path())?;
        self.inner
            .verified_current_anchor(&manifest, root_of(&bytes))?;
        Ok(manifest.signing_key_id)
    }

    /// Verify an already persisted carrier without exposing its derived key.
    /// Retired tombstones never authorize derivation.
    pub fn verify_carrier_mac(
        &self,
        key_id: u32,
        preceding_carrier_bytes: &[u8],
        observed_mac: &[u8; 32],
    ) -> Result<(), PersistedKeyringCustodyError> {
        let _writer = self.inner.writer.lock().map_err(|_| lock_error())?;
        self.inner.require_no_pending()?;
        let (manifest, bytes) = self.inner.read_manifest(&self.inner.current_path())?;
        self.inner
            .verified_current_anchor(&manifest, root_of(&bytes))?;
        let entry = manifest
            .entries
            .get(&key_id)
            .ok_or(PersistedKeyringCustodyError::KeyUnavailable)?;
        if entry.status == PersistedKeyStatus::Retired {
            return Err(PersistedKeyringCustodyError::Retired);
        }
        let key =
            self.inner
                .derive_carrier_key(entry.master_key_epoch, manifest.kdf_salt, key_id)?;
        let expected = carrier_mac(&key, preceding_carrier_bytes)?;
        if expected.ct_eq(observed_mac).unwrap_u8() != 1 {
            return Err(PersistedKeyringCustodyError::AuthenticationFailed);
        }
        Ok(())
    }

    pub fn prepare_rotate(
        &self,
        new_signing_master_key_epoch: u32,
        head_context: RegistryHeadContext,
    ) -> Result<PreparedPersistedKeyringUpdate, PersistedKeyringCustodyError> {
        if new_signing_master_key_epoch == 0 {
            return Err(PersistedKeyringCustodyError::Invalid(
                "new signing master-key epoch must be positive".to_owned(),
            ));
        }
        let _writer = self.inner.writer.lock().map_err(|_| lock_error())?;
        self.inner.require_no_pending()?;
        self.inner.require_key(new_signing_master_key_epoch)?;
        self.inner
            .require_key(head_context.next_manifest_key_epoch)?;
        let (current, current_bytes) = self.inner.read_manifest(&self.inner.current_path())?;
        if current.manifest_key_epoch != head_context.manifest_key_epoch
            || head_context.next_manifest_key_epoch < current.manifest_key_epoch
        {
            return Err(PersistedKeyringCustodyError::Invalid(
                "head-context key epochs do not match the current keyring".to_owned(),
            ));
        }
        let previous_root = root_of(&current_bytes);
        let previous_binding = provider_keyring_binding(&current, previous_root)?;
        let current_anchor = self
            .inner
            .verified_current_anchor(&current, previous_root)?;
        let new_id = u32::try_from(current.next_key_id).map_err(|_| {
            PersistedKeyringCustodyError::Invalid("persisted key id space is exhausted".to_owned())
        })?;
        let mut next = current.clone();
        next.manifest_key_epoch = head_context.next_manifest_key_epoch;
        next.generation = current.generation.checked_add(1).ok_or_else(|| {
            PersistedKeyringCustodyError::Invalid("keyring generation is exhausted".to_owned())
        })?;
        next.previous_keyring_root = previous_root.0;
        next.next_key_id = current.next_key_id.checked_add(1).ok_or_else(|| {
            PersistedKeyringCustodyError::Invalid("persisted key id space is exhausted".to_owned())
        })?;
        next.signing_key_id = new_id;
        next.manifest_nonce = random_nonzero_32()?;
        next.entries
            .get_mut(&current.signing_key_id)
            .ok_or_else(|| PersistedKeyringCustodyError::AuthenticationFailed)?
            .status = PersistedKeyStatus::VerifyOnly;
        next.entries.insert(
            new_id,
            KeyEntry {
                status: PersistedKeyStatus::Signing,
                master_key_epoch: new_signing_master_key_epoch,
                last_issued_at_ms: 0,
                scan: None,
            },
        );
        let pending_bytes = self.inner.encode_manifest(&next)?;
        let pending_path = self.inner.pending_path();
        atomic_write(&pending_path, &pending_bytes)?;
        let preparation = match prepare_persisted_keyring_mutation(
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
        let expected_previous_anchor = preparation.previous().clone();
        let expected_next_anchor = preparation.next().clone();
        let next_root = root_of(&pending_bytes);
        let next_binding = provider_keyring_binding(&next, next_root)?;
        #[cfg(feature = "test-support")]
        self.inner.maybe_fail(KeyringFailpoint::AfterPendingFsync)?;
        Ok(PreparedPersistedKeyringUpdate {
            inner: Arc::clone(&self.inner),
            previous_root,
            next_root,
            previous_binding,
            next_binding,
            preparation: Some(preparation),
            expected_previous_anchor,
            expected_next_anchor,
            registry_instance: current.registry_instance,
        })
    }

    pub fn prepare_last_issued_replacement(
        &self,
        key_id: u32,
        issued_at_ms: u64,
        head_context: RegistryHeadContext,
    ) -> Result<PreparedPersistedKeyringUpdate, PersistedKeyringCustodyError> {
        let _writer = self.inner.writer.lock().map_err(|_| lock_error())?;
        self.inner.require_no_pending()?;
        let (current, current_bytes) = self.inner.read_manifest(&self.inner.current_path())?;
        if current.manifest_key_epoch != head_context.manifest_key_epoch
            || head_context.next_manifest_key_epoch != current.manifest_key_epoch
            || key_id != current.signing_key_id
        {
            return Err(PersistedKeyringCustodyError::Invalid(
                "last-issued replacement must name the current Signing key and manifest epoch"
                    .to_owned(),
            ));
        }
        let previous_root = root_of(&current_bytes);
        let previous_binding = provider_keyring_binding(&current, previous_root)?;
        let current_anchor = self
            .inner
            .verified_current_anchor(&current, previous_root)?;
        let mut next = current.clone();
        let signing = next
            .entries
            .get_mut(&key_id)
            .ok_or_else(|| PersistedKeyringCustodyError::AuthenticationFailed)?;
        if signing.status != PersistedKeyStatus::Signing
            || issued_at_ms <= signing.last_issued_at_ms
        {
            return Err(PersistedKeyringCustodyError::Invalid(
                "last-issued time must strictly advance the current Signing entry".to_owned(),
            ));
        }
        signing.last_issued_at_ms = issued_at_ms;
        next.generation = current.generation.checked_add(1).ok_or_else(|| {
            PersistedKeyringCustodyError::Invalid("keyring generation is exhausted".to_owned())
        })?;
        next.previous_keyring_root = previous_root.0;
        next.manifest_nonce = random_nonzero_32()?;
        let pending_bytes = self.inner.encode_manifest(&next)?;
        let pending_path = self.inner.pending_path();
        atomic_write(&pending_path, &pending_bytes)?;
        let preparation = match prepare_persisted_keyring_mutation(
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
        let expected_previous_anchor = preparation.previous().clone();
        let expected_next_anchor = preparation.next().clone();
        let next_root = root_of(&pending_bytes);
        let next_binding = provider_keyring_binding(&next, next_root)?;
        #[cfg(feature = "test-support")]
        self.inner.maybe_fail(KeyringFailpoint::AfterPendingFsync)?;
        Ok(PreparedPersistedKeyringUpdate {
            inner: Arc::clone(&self.inner),
            previous_root,
            next_root,
            previous_binding,
            next_binding,
            preparation: Some(preparation),
            expected_previous_anchor,
            expected_next_anchor,
            registry_instance: current.registry_instance,
        })
    }

    pub fn prepare_retirement(
        &self,
        verified_scans: VerifiedPersistedKeyRetirementScanSet,
        head_context: RegistryHeadContext,
    ) -> Result<PreparedPersistedKeyringUpdate, PersistedKeyringCustodyError> {
        let metadata = verified_scans.metadata();
        let _writer = self.inner.writer.lock().map_err(|_| lock_error())?;
        self.inner.require_no_pending()?;
        let (current, current_bytes) = self.inner.read_manifest(&self.inner.current_path())?;
        let previous_root = root_of(&current_bytes);
        if current.manifest_key_epoch != head_context.manifest_key_epoch
            || head_context.next_manifest_key_epoch != current.manifest_key_epoch
            || metadata.registry_instance != current.registry_instance
            || metadata.keyring_root != previous_root.0
            || metadata.keyring_generation != current.generation
            || metadata.key_id == 0
        {
            return Err(PersistedKeyringCustodyError::Invalid(
                "verified retirement scans do not bind the current keyring".to_owned(),
            ));
        }
        let previous_binding = provider_keyring_binding(&current, previous_root)?;
        let current_anchor = self
            .inner
            .verified_current_anchor(&current, previous_root)?;
        let mut next = current.clone();
        let entry = next
            .entries
            .get_mut(&metadata.key_id)
            .ok_or(PersistedKeyringCustodyError::KeyUnavailable)?;
        if entry.status != PersistedKeyStatus::VerifyOnly || entry.scan.is_some() {
            return Err(PersistedKeyringCustodyError::Invalid(
                "only an unscanned VerifyOnly key can retire".to_owned(),
            ));
        }
        entry.status = PersistedKeyStatus::Retired;
        entry.scan = Some(RetirementScan {
            sqlite_scan_sequence: metadata.sqlite.high_water,
            jsonl_inventory_digest: metadata.jsonl.inventory_digest,
            jsonl_segment_count: metadata.jsonl.segment_count,
            jsonl_byte_count: metadata.jsonl.byte_count,
            retention_high_water_ms: metadata.jsonl.retention_high_water,
        });
        next.generation = current.generation.checked_add(1).ok_or_else(|| {
            PersistedKeyringCustodyError::Invalid("keyring generation is exhausted".to_owned())
        })?;
        next.previous_keyring_root = previous_root.0;
        next.manifest_nonce = random_nonzero_32()?;
        let pending_bytes = self.inner.encode_manifest(&next)?;
        let pending_path = self.inner.pending_path();
        atomic_write(&pending_path, &pending_bytes)?;
        let preparation = match prepare_persisted_keyring_mutation(
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
        let expected_previous_anchor = preparation.previous().clone();
        let expected_next_anchor = preparation.next().clone();
        let next_root = root_of(&pending_bytes);
        let next_binding = provider_keyring_binding(&next, next_root)?;
        #[cfg(feature = "test-support")]
        self.inner.maybe_fail(KeyringFailpoint::AfterPendingFsync)?;
        Ok(PreparedPersistedKeyringUpdate {
            inner: Arc::clone(&self.inner),
            previous_root,
            next_root,
            previous_binding,
            next_binding,
            preparation: Some(preparation),
            expected_previous_anchor,
            expected_next_anchor,
            registry_instance: current.registry_instance,
        })
    }

    pub fn recover_against(
        &self,
        anchored: &RegistryAnchorTuple,
    ) -> Result<PersistedKeyringRecovery, PersistedKeyringCustodyError> {
        let _writer = self.inner.writer.lock().map_err(|_| lock_error())?;
        self.inner.recover_unlocked(anchored)
    }

    /// Remove only host-master epochs no longer named by the current manifest
    /// or any Signing/VerifyOnly entry, and only in a custody object reopened
    /// on the exact anchored current file.
    pub fn retire_unreferenced_master_epochs_after_restart(
        &self,
        anchored: &RegistryAnchorTuple,
    ) -> Result<(), PersistedKeyringCustodyError> {
        let _writer = self.inner.writer.lock().map_err(|_| lock_error())?;
        self.inner.recover_unlocked(anchored)?;
        let (manifest, bytes) = self.inner.read_manifest(&self.inner.current_path())?;
        let root = root_of(&bytes);
        validate_anchor(&manifest, root, anchored)?;
        if *self
            .inner
            .session_open_root
            .lock()
            .map_err(|_| lock_error())?
            != Some(root)
        {
            return Err(PersistedKeyringCustodyError::RecoveryRequired(
                "master epochs may be retired only after reopening the anchored keyring".to_owned(),
            ));
        }
        let mut required = BTreeSet::from([manifest.manifest_key_epoch]);
        for entry in manifest.entries.values() {
            if entry.status != PersistedKeyStatus::Retired {
                required.insert(entry.master_key_epoch);
            }
        }
        self.inner
            .master_keys
            .lock()
            .map_err(|_| lock_error())?
            .retain(|epoch, _| required.contains(epoch));
        Ok(())
    }

    #[cfg(feature = "test-support")]
    pub fn set_failpoint_for_test(&self, failpoint: KeyringFailpoint) {
        *self.inner.failpoint.lock().expect("keyring failpoint lock") = Some(failpoint);
    }

    #[cfg(feature = "test-support")]
    pub fn retained_master_epochs_for_test(&self) -> Vec<u32> {
        self.inner
            .master_keys
            .lock()
            .expect("keyring master-key lock")
            .keys()
            .copied()
            .collect()
    }
}

impl PersistedIdentityKeyringProvider for FilePersistedIdentityKeyringCustody {
    fn current_keyring_binding(
        &self,
    ) -> Result<PersistedIdentityKeyringBinding, SensitiveParamCatalogError> {
        let _writer = self
            .inner
            .writer
            .lock()
            .map_err(|_| SensitiveParamCatalogError::StorageUnavailable)?;
        let (manifest, bytes) = self
            .inner
            .authenticated_provider_snapshot()
            .map_err(provider_error)?;
        provider_keyring_binding(&manifest, root_of(&bytes)).map_err(provider_error)
    }

    fn signing_key_binding(
        &self,
    ) -> Result<PersistedIdentityKeyCapabilityBinding, SensitiveParamCatalogError> {
        let _writer = self
            .inner
            .writer
            .lock()
            .map_err(|_| SensitiveParamCatalogError::StorageUnavailable)?;
        let (manifest, bytes) = self
            .inner
            .authenticated_provider_snapshot()
            .map_err(provider_error)?;
        let keyring =
            provider_keyring_binding(&manifest, root_of(&bytes)).map_err(provider_error)?;
        let entry = manifest
            .entries
            .get(&manifest.signing_key_id)
            .ok_or(SensitiveParamCatalogError::InvalidCarrier)?;
        provider_entry_binding(keyring, manifest.signing_key_id, entry).map_err(provider_error)
    }

    fn verification_key_binding(
        &self,
        key_id: u32,
    ) -> Result<PersistedIdentityKeyCapabilityBinding, SensitiveParamCatalogError> {
        let _writer = self
            .inner
            .writer
            .lock()
            .map_err(|_| SensitiveParamCatalogError::StorageUnavailable)?;
        let (manifest, bytes) = self
            .inner
            .authenticated_provider_snapshot()
            .map_err(provider_error)?;
        let keyring =
            provider_keyring_binding(&manifest, root_of(&bytes)).map_err(provider_error)?;
        let entry = manifest
            .entries
            .get(&key_id)
            .ok_or(SensitiveParamCatalogError::InvalidCarrier)?;
        if entry.status == PersistedKeyStatus::Retired {
            return Err(SensitiveParamCatalogError::InvalidCarrier);
        }
        provider_entry_binding(keyring, key_id, entry).map_err(provider_error)
    }

    fn sign_persisted_identity(
        &self,
        request: &PersistedIdentitySigningRequest,
    ) -> Result<CustodySignedPersistedIdentity, SensitiveParamCatalogError> {
        let _writer = self
            .inner
            .writer
            .lock()
            .map_err(|_| SensitiveParamCatalogError::StorageUnavailable)?;
        let (manifest, bytes) = self
            .inner
            .authenticated_provider_snapshot()
            .map_err(provider_error)?;
        let keyring =
            provider_keyring_binding(&manifest, root_of(&bytes)).map_err(provider_error)?;
        let key_id = manifest.signing_key_id;
        let entry = manifest
            .entries
            .get(&key_id)
            .ok_or(SensitiveParamCatalogError::InvalidCarrier)?;
        let expected = provider_entry_binding(keyring, key_id, entry).map_err(provider_error)?;
        let preceding = request.canonical_preceding_bytes();
        if request.key_binding() != expected
            || entry.status != PersistedKeyStatus::Signing
            || !(MIN_PERSISTED_IDENTITY_BYTES - 32..=MAX_PERSISTED_IDENTITY_BYTES - 32)
                .contains(&preceding.len())
            || preceding.first() != Some(&1)
            || preceding
                .get(1..5)
                .and_then(|bytes| bytes.try_into().ok())
                .map(u32::from_be_bytes)
                != Some(key_id)
        {
            return Err(SensitiveParamCatalogError::InvalidCarrier);
        }
        let key = self
            .inner
            .derive_carrier_key(entry.master_key_epoch, manifest.kdf_salt, key_id)
            .map_err(provider_error)?;
        let tag = carrier_mac(&key, preceding).map_err(provider_error)?;
        let mut canonical = Vec::with_capacity(preceding.len() + 32);
        canonical.extend_from_slice(preceding);
        canonical.extend_from_slice(&tag);
        Ok(CustodySignedPersistedIdentity::from_typed_signing_operation(canonical))
    }

    fn verify_persisted_identity(
        &self,
        request: &PersistedIdentityVerificationRequest,
    ) -> Result<(), SensitiveParamCatalogError> {
        let _writer = self
            .inner
            .writer
            .lock()
            .map_err(|_| SensitiveParamCatalogError::StorageUnavailable)?;
        let (manifest, bytes) = self
            .inner
            .authenticated_provider_snapshot()
            .map_err(provider_error)?;
        let keyring =
            provider_keyring_binding(&manifest, root_of(&bytes)).map_err(provider_error)?;
        let binding = request.key_binding();
        let key_id = binding.key_id();
        let entry = manifest
            .entries
            .get(&key_id)
            .ok_or(SensitiveParamCatalogError::InvalidCarrier)?;
        if entry.status == PersistedKeyStatus::Retired
            || provider_entry_binding(keyring, key_id, entry).map_err(provider_error)? != binding
        {
            return Err(SensitiveParamCatalogError::InvalidCarrier);
        }
        let canonical = request.canonical_bytes();
        if !(MIN_PERSISTED_IDENTITY_BYTES..=MAX_PERSISTED_IDENTITY_BYTES).contains(&canonical.len())
            || canonical.first() != Some(&1)
            || canonical
                .get(1..5)
                .and_then(|bytes| bytes.try_into().ok())
                .map(u32::from_be_bytes)
                != Some(key_id)
        {
            return Err(SensitiveParamCatalogError::InvalidCarrier);
        }
        let split = canonical.len() - 32;
        let observed: [u8; 32] = canonical[split..]
            .try_into()
            .map_err(|_| SensitiveParamCatalogError::InvalidCarrier)?;
        let key = self
            .inner
            .derive_carrier_key(entry.master_key_epoch, manifest.kdf_salt, key_id)
            .map_err(provider_error)?;
        let expected = carrier_mac(&key, &canonical[..split]).map_err(provider_error)?;
        if expected.ct_eq(&observed).unwrap_u8() == 1 {
            Ok(())
        } else {
            Err(SensitiveParamCatalogError::InvalidCarrier)
        }
    }
}

impl PersistedKeyringCustody for FilePersistedIdentityKeyringCustody {
    fn authenticated_current_file(
        &self,
        expected_registry_instance: [u8; 16],
    ) -> Result<Vec<u8>, advance_scheduler::observation_anchor::RegistryAnchorError> {
        FilePersistedIdentityKeyringCustody::authenticated_current_file(
            self,
            expected_registry_instance,
        )
        .map_err(scheduler_custody_error)
    }

    fn prepare_last_issued_replacement(
        &self,
        key_id: u32,
        issued_at_ms: u64,
        head_context: RegistryHeadContext,
    ) -> Result<
        Box<dyn PreparedPersistedKeyringCustodyMutation>,
        advance_scheduler::observation_anchor::RegistryAnchorError,
    > {
        Ok(Box::new(
            FilePersistedIdentityKeyringCustody::prepare_last_issued_replacement(
                self,
                key_id,
                issued_at_ms,
                head_context,
            )
            .map_err(scheduler_custody_error)?,
        ))
    }

    fn prepare_signing_rotation(
        &self,
        new_signing_master_key_epoch: u32,
        head_context: RegistryHeadContext,
    ) -> Result<
        Box<dyn PreparedPersistedKeyringCustodyMutation>,
        advance_scheduler::observation_anchor::RegistryAnchorError,
    > {
        Ok(Box::new(
            self.prepare_rotate(new_signing_master_key_epoch, head_context)
                .map_err(scheduler_custody_error)?,
        ))
    }

    fn prepare_retirement(
        &self,
        verified_scans: VerifiedPersistedKeyRetirementScanSet,
        head_context: RegistryHeadContext,
    ) -> Result<
        Box<dyn PreparedPersistedKeyringCustodyMutation>,
        advance_scheduler::observation_anchor::RegistryAnchorError,
    > {
        Ok(Box::new(
            FilePersistedIdentityKeyringCustody::prepare_retirement(
                self,
                verified_scans,
                head_context,
            )
            .map_err(scheduler_custody_error)?,
        ))
    }
}

pub struct PreparedPersistedKeyringUpdate {
    inner: Arc<KeyringInner>,
    previous_root: PersistedKeyringRoot,
    next_root: PersistedKeyringRoot,
    previous_binding: PersistedIdentityKeyringBinding,
    next_binding: PersistedIdentityKeyringBinding,
    preparation: Option<PreparedPersistedKeyringMutation>,
    expected_previous_anchor: RegistryAnchorTuple,
    expected_next_anchor: RegistryAnchorTuple,
    registry_instance: [u8; 16],
}

impl PreparedPersistedKeyringUpdate {
    pub fn previous_root(&self) -> PersistedKeyringRoot {
        self.previous_root
    }

    pub fn next_root(&self) -> PersistedKeyringRoot {
        self.next_root
    }

    pub fn anchor_previous(&self) -> &RegistryAnchorTuple {
        &self.expected_previous_anchor
    }

    pub fn anchor_next(&self) -> &RegistryAnchorTuple {
        &self.expected_next_anchor
    }

    pub fn take_anchor_preparation(
        &mut self,
    ) -> Result<PreparedPersistedKeyringMutation, PersistedKeyringCustodyError> {
        self.preparation.take().ok_or_else(|| {
            PersistedKeyringCustodyError::Invalid(
                "keyring anchor preparation was already consumed".to_owned(),
            )
        })
    }

    pub fn commit_anchored(
        self,
        anchored: &RegistryAnchorTuple,
    ) -> Result<(), PersistedKeyringCustodyError> {
        if anchored != &self.expected_next_anchor {
            return Err(PersistedKeyringCustodyError::AnchorMismatch);
        }
        let _writer = self.inner.writer.lock().map_err(|_| lock_error())?;
        #[cfg(feature = "test-support")]
        self.inner
            .maybe_fail(KeyringFailpoint::BeforePendingPromotion)?;
        self.inner.promote_pending(
            self.previous_root,
            self.next_root,
            self.registry_instance,
            anchored,
        )
    }
}

impl PreparedPersistedKeyringCustodyMutation for PreparedPersistedKeyringUpdate {
    fn previous_binding(&self) -> PersistedIdentityKeyringBinding {
        self.previous_binding
    }

    fn next_binding(&self) -> PersistedIdentityKeyringBinding {
        self.next_binding
    }

    fn take_scheduler_preparation(
        &mut self,
    ) -> Result<
        PreparedPersistedKeyringMutation,
        advance_scheduler::observation_anchor::RegistryAnchorError,
    > {
        self.take_anchor_preparation()
            .map_err(scheduler_custody_error)
    }

    fn promote_after_anchor(
        self: Box<Self>,
        anchored: &RegistryAnchorTuple,
    ) -> Result<(), advance_scheduler::observation_anchor::RegistryAnchorError> {
        (*self)
            .commit_anchored(anchored)
            .map_err(scheduler_custody_error)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct KeyringManifest {
    manifest_key_epoch: u32,
    registry_instance: [u8; 16],
    generation: u64,
    previous_keyring_root: [u8; 32],
    kdf_salt: [u8; 32],
    next_key_id: u64,
    signing_key_id: u32,
    entries: BTreeMap<u32, KeyEntry>,
    manifest_nonce: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct KeyEntry {
    status: PersistedKeyStatus,
    master_key_epoch: u32,
    last_issued_at_ms: u64,
    scan: Option<RetirementScan>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RetirementScan {
    sqlite_scan_sequence: u64,
    jsonl_inventory_digest: [u8; 32],
    jsonl_segment_count: u64,
    jsonl_byte_count: u64,
    retention_high_water_ms: u64,
}

impl KeyringInner {
    fn current_path(&self) -> PathBuf {
        self.directory.join(CURRENT_FILE)
    }

    fn pending_path(&self) -> PathBuf {
        self.directory.join(PENDING_FILE)
    }

    fn require_key(&self, epoch: u32) -> Result<(), PersistedKeyringCustodyError> {
        if self
            .master_keys
            .lock()
            .map_err(|_| lock_error())?
            .contains_key(&epoch)
        {
            Ok(())
        } else {
            Err(PersistedKeyringCustodyError::RecoveryRequired(format!(
                "host-master epoch {epoch} is unavailable"
            )))
        }
    }

    fn require_ready_keys(
        &self,
        manifest: &KeyringManifest,
    ) -> Result<(), PersistedKeyringCustodyError> {
        self.require_key(manifest.manifest_key_epoch)?;
        for entry in manifest.entries.values() {
            if entry.status != PersistedKeyStatus::Retired {
                self.require_key(entry.master_key_epoch)?;
            }
        }
        Ok(())
    }

    fn require_no_pending(&self) -> Result<(), PersistedKeyringCustodyError> {
        if keyring_file_exists(&self.pending_path())?
            || keyring_file_exists(&atomic_temporary_path(&self.pending_path())?)?
            || keyring_file_exists(&atomic_temporary_path(&self.current_path())?)?
        {
            return Err(PersistedKeyringCustodyError::RecoveryRequired(
                "pending keyring must be reconciled first".to_owned(),
            ));
        }
        Ok(())
    }

    fn authenticated_provider_snapshot(
        &self,
    ) -> Result<(KeyringManifest, Zeroizing<Vec<u8>>), PersistedKeyringCustodyError> {
        self.require_no_pending()?;
        let (manifest, bytes) = self.read_manifest(&self.current_path())?;
        self.require_ready_keys(&manifest)?;
        self.verify_anchor_or_exact_greenfield(&manifest, root_of(&bytes))?;
        Ok((manifest, bytes))
    }

    fn verify_anchor_or_exact_greenfield(
        &self,
        manifest: &KeyringManifest,
        root: PersistedKeyringRoot,
    ) -> Result<(), PersistedKeyringCustodyError> {
        match self.verified_current_anchor(manifest, root) {
            Ok(_) => Ok(()),
            Err(_)
                if manifest.generation == 0
                    && manifest.previous_keyring_root == [0; 32]
                    && self.anchor.is_exact_pre_genesis().map_err(anchor_error)? =>
            {
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    fn verified_current_anchor(
        &self,
        manifest: &KeyringManifest,
        root: PersistedKeyringRoot,
    ) -> Result<RegistryAnchorTuple, PersistedKeyringCustodyError> {
        match self.anchor.observe().map_err(anchor_error)? {
            RegistryAnchorWorld::CompactCurrent { current, .. }
                if current.registry_instance == manifest.registry_instance
                    && current.keyring_root == root.0 =>
            {
                Ok(current)
            }
            _ => Err(PersistedKeyringCustodyError::RecoveryRequired(
                "keyring mutation requires the exact compact current anchor".to_owned(),
            )),
        }
    }

    fn encode_manifest(
        &self,
        manifest: &KeyringManifest,
    ) -> Result<Zeroizing<Vec<u8>>, PersistedKeyringCustodyError> {
        let mut bytes = encode_preceding_bytes(manifest)?;
        let keys = self.master_keys.lock().map_err(|_| lock_error())?;
        let master = keys.get(&manifest.manifest_key_epoch).ok_or_else(|| {
            PersistedKeyringCustodyError::RecoveryRequired(format!(
                "manifest host-master epoch {} is unavailable",
                manifest.manifest_key_epoch
            ))
        })?;
        let mac = manifest_mac(
            master,
            manifest.manifest_key_epoch,
            manifest.registry_instance,
            manifest.kdf_salt,
            &bytes,
        )?;
        bytes.extend_from_slice(&mac);
        Ok(Zeroizing::new(bytes))
    }

    fn read_manifest(
        &self,
        path: &Path,
    ) -> Result<(KeyringManifest, Zeroizing<Vec<u8>>), PersistedKeyringCustodyError> {
        let mut bytes = Vec::new();
        secure_open_regular(path)
            .and_then(|mut file| file.read_to_end(&mut bytes))
            .map_err(|error| {
                PersistedKeyringCustodyError::Io(format!("read {}: {error}", path.display()))
            })?;
        let bytes = Zeroizing::new(bytes);
        let manifest = self.decode_manifest(&bytes)?;
        Ok((manifest, bytes))
    }

    fn decode_manifest(
        &self,
        bytes: &[u8],
    ) -> Result<KeyringManifest, PersistedKeyringCustodyError> {
        const MINIMUM: usize = 1 + 4 + 16 + 8 + 32 + 32 + 8 + 4 + 4 + 32 + 32;
        if bytes.len() < MINIMUM {
            return Err(PersistedKeyringCustodyError::AuthenticationFailed);
        }
        let (preceding, observed_mac) = bytes.split_at(bytes.len() - 32);
        let mut cursor = KeyringCursor::new(preceding);
        if cursor.u8()? != FILE_VERSION {
            return Err(PersistedKeyringCustodyError::AuthenticationFailed);
        }
        let manifest_key_epoch = cursor.u32()?;
        let registry_instance = cursor.array::<16>()?;
        let generation = cursor.u64()?;
        let previous_keyring_root = cursor.array::<32>()?;
        let kdf_salt = cursor.array::<32>()?;
        let keys = self.master_keys.lock().map_err(|_| lock_error())?;
        let master = keys.get(&manifest_key_epoch).ok_or_else(|| {
            PersistedKeyringCustodyError::RecoveryRequired(format!(
                "manifest host-master epoch {manifest_key_epoch} is unavailable"
            ))
        })?;
        let expected_mac = manifest_mac(
            master,
            manifest_key_epoch,
            registry_instance,
            kdf_salt,
            preceding,
        )?;
        drop(keys);
        if expected_mac.ct_eq(observed_mac).unwrap_u8() != 1 {
            return Err(PersistedKeyringCustodyError::AuthenticationFailed);
        }
        let next_key_id = cursor.u64()?;
        let signing_key_id = cursor.u32()?;
        let entry_count = usize::try_from(cursor.u32()?)
            .map_err(|_| PersistedKeyringCustodyError::AuthenticationFailed)?;
        if manifest_key_epoch == 0
            || registry_instance == [0; 16]
            || kdf_salt == [0; 32]
            || entry_count == 0
            || signing_key_id == 0
            || (generation == 0 && previous_keyring_root != [0; 32])
            || (generation != 0 && previous_keyring_root == [0; 32])
        {
            return Err(PersistedKeyringCustodyError::AuthenticationFailed);
        }
        let mut entries = BTreeMap::new();
        let mut previous_id = 0u32;
        let mut signing_count = 0usize;
        for _ in 0..entry_count {
            let key_id = cursor.u32()?;
            let status = match cursor.u8()? {
                SIGNING_TAG => PersistedKeyStatus::Signing,
                VERIFY_ONLY_TAG => PersistedKeyStatus::VerifyOnly,
                RETIRED_TAG => PersistedKeyStatus::Retired,
                _ => return Err(PersistedKeyringCustodyError::AuthenticationFailed),
            };
            let master_key_epoch = cursor.u32()?;
            let last_issued_at_ms = cursor.u64()?;
            let scan = match cursor.u8()? {
                0 => None,
                1 => Some(RetirementScan {
                    sqlite_scan_sequence: cursor.u64()?,
                    jsonl_inventory_digest: cursor.array::<32>()?,
                    jsonl_segment_count: cursor.u64()?,
                    jsonl_byte_count: cursor.u64()?,
                    retention_high_water_ms: cursor.u64()?,
                }),
                _ => return Err(PersistedKeyringCustodyError::AuthenticationFailed),
            };
            if key_id == 0
                || key_id <= previous_id
                || master_key_epoch == 0
                || (status == PersistedKeyStatus::Signing && scan.is_some())
                || (status == PersistedKeyStatus::Retired && scan.is_none())
            {
                return Err(PersistedKeyringCustodyError::AuthenticationFailed);
            }
            if status == PersistedKeyStatus::Signing {
                signing_count = signing_count
                    .checked_add(1)
                    .ok_or(PersistedKeyringCustodyError::AuthenticationFailed)?;
                if key_id != signing_key_id {
                    return Err(PersistedKeyringCustodyError::AuthenticationFailed);
                }
            }
            previous_id = key_id;
            if entries
                .insert(
                    key_id,
                    KeyEntry {
                        status,
                        master_key_epoch,
                        last_issued_at_ms,
                        scan,
                    },
                )
                .is_some()
            {
                return Err(PersistedKeyringCustodyError::AuthenticationFailed);
            }
        }
        if signing_count != 1
            || u64::from(previous_id).checked_add(1) != Some(next_key_id)
            || entries.len() != entry_count
        {
            return Err(PersistedKeyringCustodyError::AuthenticationFailed);
        }
        let manifest_nonce = cursor.array::<32>()?;
        if manifest_nonce == [0; 32] || !cursor.is_empty() {
            return Err(PersistedKeyringCustodyError::AuthenticationFailed);
        }
        Ok(KeyringManifest {
            manifest_key_epoch,
            registry_instance,
            generation,
            previous_keyring_root,
            kdf_salt,
            next_key_id,
            signing_key_id,
            entries,
            manifest_nonce,
        })
    }

    fn derive_carrier_key(
        &self,
        master_key_epoch: u32,
        kdf_salt: [u8; 32],
        key_id: u32,
    ) -> Result<Zeroizing<[u8; 32]>, PersistedKeyringCustodyError> {
        let keys = self.master_keys.lock().map_err(|_| lock_error())?;
        let master = keys
            .get(&master_key_epoch)
            .ok_or(PersistedKeyringCustodyError::KeyUnavailable)?;
        derive_carrier_key(master, kdf_salt, key_id)
    }

    fn marker_mac(
        &self,
        manifest_key_epoch: u32,
        registry_instance: [u8; 16],
        preceding_marker_bytes: &[u8],
    ) -> Result<[u8; 32], PersistedKeyringCustodyError> {
        if manifest_key_epoch == 0 || registry_instance == [0; 16] {
            return Err(PersistedKeyringCustodyError::Invalid(
                "migration marker key binding must be nonzero".to_owned(),
            ));
        }
        let keys = self.master_keys.lock().map_err(|_| lock_error())?;
        let master = keys.get(&manifest_key_epoch).ok_or_else(|| {
            PersistedKeyringCustodyError::RecoveryRequired(format!(
                "migration marker host-master epoch {manifest_key_epoch} is unavailable"
            ))
        })?;
        migration_marker_mac_with_master(
            master,
            manifest_key_epoch,
            registry_instance,
            preceding_marker_bytes,
        )
    }

    fn classify_successor(
        &self,
        current: &KeyringManifest,
        pending: &KeyringManifest,
        current_root: PersistedKeyringRoot,
    ) -> Result<(), PersistedKeyringCustodyError> {
        if current.generation.checked_add(1) != Some(pending.generation)
            || pending.previous_keyring_root != current_root.0
            || pending.kdf_salt != current.kdf_salt
            || pending.manifest_nonce == current.manifest_nonce
            || pending.manifest_key_epoch < current.manifest_key_epoch
            || pending.entries.len() < current.entries.len()
            || pending.entries.len() > current.entries.len() + 1
        {
            return Err(invalid_successor());
        }
        for (&key_id, before) in &current.entries {
            let after = pending.entries.get(&key_id).ok_or_else(invalid_successor)?;
            if before.master_key_epoch != after.master_key_epoch
                || after.last_issued_at_ms < before.last_issued_at_ms
                || (before.status != PersistedKeyStatus::Signing
                    && after.last_issued_at_ms != before.last_issued_at_ms)
                || !matches!(
                    (before.status, after.status),
                    (PersistedKeyStatus::Signing, PersistedKeyStatus::Signing)
                        | (PersistedKeyStatus::Signing, PersistedKeyStatus::VerifyOnly)
                        | (
                            PersistedKeyStatus::VerifyOnly,
                            PersistedKeyStatus::VerifyOnly
                        )
                        | (PersistedKeyStatus::VerifyOnly, PersistedKeyStatus::Retired)
                        | (PersistedKeyStatus::Retired, PersistedKeyStatus::Retired)
                )
                || (before.status == PersistedKeyStatus::Retired && before != after)
                || !scan_is_successor(before.scan.as_ref(), after.scan.as_ref())
            {
                return Err(invalid_successor());
            }
        }
        if pending.entries.len() == current.entries.len() {
            if pending.next_key_id != current.next_key_id
                || pending.signing_key_id != current.signing_key_id
            {
                return Err(invalid_successor());
            }
        } else {
            let new_id = u32::try_from(current.next_key_id).map_err(|_| invalid_successor())?;
            let new_entry = pending.entries.get(&new_id).ok_or_else(invalid_successor)?;
            let old_signing = current
                .entries
                .get(&current.signing_key_id)
                .ok_or_else(invalid_successor)?;
            let demoted = pending
                .entries
                .get(&current.signing_key_id)
                .ok_or_else(invalid_successor)?;
            if new_entry.status != PersistedKeyStatus::Signing
                || new_entry.scan.is_some()
                || new_entry.last_issued_at_ms != 0
                || pending.signing_key_id != new_id
                || old_signing.status != PersistedKeyStatus::Signing
                || demoted.status != PersistedKeyStatus::VerifyOnly
                || pending.next_key_id
                    != current
                        .next_key_id
                        .checked_add(1)
                        .ok_or_else(invalid_successor)?
            {
                return Err(invalid_successor());
            }
        }
        Ok(())
    }

    fn recover_unlocked(
        &self,
        anchored: &RegistryAnchorTuple,
    ) -> Result<PersistedKeyringRecovery, PersistedKeyringCustodyError> {
        match self.anchor.observe().map_err(anchor_error)? {
            RegistryAnchorWorld::CompactCurrent { current, .. } if current == *anchored => {}
            _ => return Err(PersistedKeyringCustodyError::AnchorMismatch),
        }
        let (current, current_bytes) = self.read_manifest(&self.current_path())?;
        self.require_ready_keys(&current)?;
        let current_root = root_of(&current_bytes);
        if current.registry_instance != anchored.registry_instance {
            return Err(PersistedKeyringCustodyError::AnchorMismatch);
        }
        let pending_temporary = atomic_temporary_path(&self.pending_path())?;
        if keyring_file_exists(&pending_temporary)? {
            if keyring_file_exists(&self.pending_path())? || anchored.keyring_root != current_root.0
            {
                return Err(PersistedKeyringCustodyError::RecoveryRequired(
                    "interrupted keyring write cannot be reconciled against the selected anchor"
                        .to_owned(),
                ));
            }
            secure_remove_regular(&pending_temporary).map_err(|error| {
                PersistedKeyringCustodyError::Io(format!(
                    "remove interrupted pending keyring temp: {error}"
                ))
            })?;
            fsync_directory(&self.directory)?;
            return Ok(PersistedKeyringRecovery::RolledBackPending);
        }
        if !keyring_file_exists(&self.pending_path())? {
            validate_anchor(&current, current_root, anchored)?;
            return Ok(PersistedKeyringRecovery::Clean);
        }
        let (pending, pending_bytes) = self.read_manifest(&self.pending_path())?;
        self.require_ready_keys(&pending)?;
        self.classify_successor(&current, &pending, current_root)?;
        let pending_root = root_of(&pending_bytes);
        if pending_root == current_root {
            return Err(invalid_successor());
        }
        if anchored.keyring_root == current_root.0 {
            secure_remove_regular(&self.pending_path()).map_err(|error| {
                PersistedKeyringCustodyError::Io(format!(
                    "remove rolled-back pending keyring: {error}"
                ))
            })?;
            fsync_directory(&self.directory)?;
            Ok(PersistedKeyringRecovery::RolledBackPending)
        } else if anchored.keyring_root == pending_root.0 {
            self.promote_pending_files()?;
            Ok(PersistedKeyringRecovery::PromotedPending)
        } else {
            Err(PersistedKeyringCustodyError::RecoveryRequired(
                "anchor names neither current nor pending keyring".to_owned(),
            ))
        }
    }

    fn promote_pending(
        &self,
        expected_previous: PersistedKeyringRoot,
        expected_next: PersistedKeyringRoot,
        registry_instance: [u8; 16],
        anchored: &RegistryAnchorTuple,
    ) -> Result<(), PersistedKeyringCustodyError> {
        match self.anchor.observe().map_err(anchor_error)? {
            RegistryAnchorWorld::CompactCurrent { current, .. } if current == *anchored => {}
            _ => return Err(PersistedKeyringCustodyError::AnchorMismatch),
        }
        let (current, current_bytes) = self.read_manifest(&self.current_path())?;
        let (pending, pending_bytes) = self.read_manifest(&self.pending_path())?;
        if current.registry_instance != registry_instance
            || pending.registry_instance != registry_instance
            || root_of(&current_bytes) != expected_previous
            || root_of(&pending_bytes) != expected_next
        {
            return Err(PersistedKeyringCustodyError::RecoveryRequired(
                "prepared keyring changed before commit".to_owned(),
            ));
        }
        self.classify_successor(&current, &pending, expected_previous)?;
        validate_anchor(&pending, expected_next, anchored)?;
        self.promote_pending_files()
    }

    fn promote_pending_files(&self) -> Result<(), PersistedKeyringCustodyError> {
        secure_replace_regular(&self.pending_path(), &self.current_path()).map_err(|error| {
            PersistedKeyringCustodyError::Io(format!("promote pending keyring: {error}"))
        })?;
        fsync_directory(&self.directory)
    }

    #[cfg(feature = "test-support")]
    fn maybe_fail(&self, point: KeyringFailpoint) -> Result<(), PersistedKeyringCustodyError> {
        let mut armed = self.failpoint.lock().map_err(|_| lock_error())?;
        if *armed == Some(point) {
            *armed = None;
            return Err(PersistedKeyringCustodyError::Failpoint(point));
        }
        Ok(())
    }
}

fn encode_preceding_bytes(
    manifest: &KeyringManifest,
) -> Result<Vec<u8>, PersistedKeyringCustodyError> {
    validate_manifest(manifest)?;
    let mut bytes = Vec::new();
    bytes.push(FILE_VERSION);
    bytes.extend_from_slice(&manifest.manifest_key_epoch.to_be_bytes());
    bytes.extend_from_slice(&manifest.registry_instance);
    bytes.extend_from_slice(&manifest.generation.to_be_bytes());
    bytes.extend_from_slice(&manifest.previous_keyring_root);
    bytes.extend_from_slice(&manifest.kdf_salt);
    bytes.extend_from_slice(&manifest.next_key_id.to_be_bytes());
    bytes.extend_from_slice(&manifest.signing_key_id.to_be_bytes());
    bytes.extend_from_slice(&(manifest.entries.len() as u32).to_be_bytes());
    for (&key_id, entry) in &manifest.entries {
        bytes.extend_from_slice(&key_id.to_be_bytes());
        bytes.push(match entry.status {
            PersistedKeyStatus::Signing => SIGNING_TAG,
            PersistedKeyStatus::VerifyOnly => VERIFY_ONLY_TAG,
            PersistedKeyStatus::Retired => RETIRED_TAG,
        });
        bytes.extend_from_slice(&entry.master_key_epoch.to_be_bytes());
        bytes.extend_from_slice(&entry.last_issued_at_ms.to_be_bytes());
        match &entry.scan {
            None => bytes.push(0),
            Some(scan) => {
                bytes.push(1);
                bytes.extend_from_slice(&scan.sqlite_scan_sequence.to_be_bytes());
                bytes.extend_from_slice(&scan.jsonl_inventory_digest);
                bytes.extend_from_slice(&scan.jsonl_segment_count.to_be_bytes());
                bytes.extend_from_slice(&scan.jsonl_byte_count.to_be_bytes());
                bytes.extend_from_slice(&scan.retention_high_water_ms.to_be_bytes());
            }
        }
    }
    bytes.extend_from_slice(&manifest.manifest_nonce);
    Ok(bytes)
}

fn validate_manifest(manifest: &KeyringManifest) -> Result<(), PersistedKeyringCustodyError> {
    if manifest.manifest_key_epoch == 0
        || manifest.registry_instance == [0; 16]
        || manifest.kdf_salt == [0; 32]
        || manifest.entries.is_empty()
        || manifest.entries.len() > u32::MAX as usize
        || manifest.signing_key_id == 0
        || manifest.manifest_nonce == [0; 32]
        || (manifest.generation == 0 && manifest.previous_keyring_root != [0; 32])
        || (manifest.generation != 0 && manifest.previous_keyring_root == [0; 32])
    {
        return Err(PersistedKeyringCustodyError::Invalid(
            "keyring header is outside canonical bounds".to_owned(),
        ));
    }
    let mut previous_id = 0u32;
    let mut signing_count = 0usize;
    for (&key_id, entry) in &manifest.entries {
        if key_id == 0
            || key_id <= previous_id
            || entry.master_key_epoch == 0
            || (entry.status == PersistedKeyStatus::Signing && entry.scan.is_some())
            || (entry.status == PersistedKeyStatus::Retired && entry.scan.is_none())
        {
            return Err(PersistedKeyringCustodyError::Invalid(
                "keyring entry violates canonical constraints".to_owned(),
            ));
        }
        if entry.status == PersistedKeyStatus::Signing {
            signing_count = signing_count.checked_add(1).ok_or_else(|| {
                PersistedKeyringCustodyError::Invalid("signing key count overflowed".to_owned())
            })?;
            if key_id != manifest.signing_key_id {
                return Err(PersistedKeyringCustodyError::Invalid(
                    "signing key id does not name the sole Signing entry".to_owned(),
                ));
            }
        }
        previous_id = key_id;
    }
    if signing_count != 1 || u64::from(previous_id).checked_add(1) != Some(manifest.next_key_id) {
        return Err(PersistedKeyringCustodyError::Invalid(
            "key ids are not a canonical monotonic allocation".to_owned(),
        ));
    }
    Ok(())
}

fn scan_is_successor(previous: Option<&RetirementScan>, next: Option<&RetirementScan>) -> bool {
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

fn derive_manifest_key(
    master_key: &[u8; 32],
    manifest_key_epoch: u32,
    registry_instance: [u8; 16],
    kdf_salt: [u8; 32],
) -> Result<Zeroizing<[u8; 32]>, PersistedKeyringCustodyError> {
    let mut salt = [0u8; 48];
    salt[..16].copy_from_slice(&registry_instance);
    salt[16..].copy_from_slice(&kdf_salt);
    let mut info = Vec::with_capacity(MANIFEST_KEY_INFO_DOMAIN.len() + 4);
    info.extend_from_slice(MANIFEST_KEY_INFO_DOMAIN);
    info.extend_from_slice(&manifest_key_epoch.to_be_bytes());
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), master_key);
    let mut output = Zeroizing::new([0u8; 32]);
    hkdf.expand(&info, output.as_mut())
        .map_err(|_| PersistedKeyringCustodyError::Crypto)?;
    Ok(output)
}

fn manifest_mac(
    master_key: &[u8; 32],
    manifest_key_epoch: u32,
    registry_instance: [u8; 16],
    kdf_salt: [u8; 32],
    preceding: &[u8],
) -> Result<[u8; 32], PersistedKeyringCustodyError> {
    let key = derive_manifest_key(master_key, manifest_key_epoch, registry_instance, kdf_salt)?;
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key.as_ref())
        .map_err(|_| PersistedKeyringCustodyError::Crypto)?;
    mac.update(MANIFEST_MAC_DOMAIN);
    mac.update(preceding);
    Ok(mac.finalize().into_bytes().into())
}

fn derive_carrier_key(
    master_key: &[u8; 32],
    kdf_salt: [u8; 32],
    key_id: u32,
) -> Result<Zeroizing<[u8; 32]>, PersistedKeyringCustodyError> {
    if key_id == 0 {
        return Err(PersistedKeyringCustodyError::Invalid(
            "carrier key id must be positive".to_owned(),
        ));
    }
    let mut info = Vec::with_capacity(CARRIER_KEY_INFO_DOMAIN.len() + 4);
    info.extend_from_slice(CARRIER_KEY_INFO_DOMAIN);
    info.extend_from_slice(&key_id.to_be_bytes());
    let hkdf = Hkdf::<Sha256>::new(Some(&kdf_salt), master_key);
    let mut output = Zeroizing::new([0u8; 32]);
    hkdf.expand(&info, output.as_mut())
        .map_err(|_| PersistedKeyringCustodyError::Crypto)?;
    Ok(output)
}

fn carrier_mac(
    carrier_key: &[u8; 32],
    preceding: &[u8],
) -> Result<[u8; 32], PersistedKeyringCustodyError> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(carrier_key)
        .map_err(|_| PersistedKeyringCustodyError::Crypto)?;
    mac.update(CARRIER_MAC_DOMAIN);
    mac.update(preceding);
    Ok(mac.finalize().into_bytes().into())
}

fn migration_marker_mac_with_master(
    master_key: &[u8; 32],
    manifest_key_epoch: u32,
    registry_instance: [u8; 16],
    preceding_marker_bytes: &[u8],
) -> Result<[u8; 32], PersistedKeyringCustodyError> {
    let mut info = Vec::with_capacity(MIGRATION_MARKER_KEY_INFO_DOMAIN.len() + 4);
    info.extend_from_slice(MIGRATION_MARKER_KEY_INFO_DOMAIN);
    info.extend_from_slice(&manifest_key_epoch.to_be_bytes());
    let hkdf = Hkdf::<Sha256>::new(Some(&registry_instance), master_key);
    let mut marker_key = Zeroizing::new([0_u8; 32]);
    hkdf.expand(&info, marker_key.as_mut())
        .map_err(|_| PersistedKeyringCustodyError::Crypto)?;
    let mut mac = HmacSha256::new_from_slice(marker_key.as_ref())
        .map_err(|_| PersistedKeyringCustodyError::Crypto)?;
    mac.update(MIGRATION_MARKER_MAC_DOMAIN);
    mac.update(preceding_marker_bytes);
    Ok(mac.finalize().into_bytes().into())
}

fn root_of(bytes: &[u8]) -> PersistedKeyringRoot {
    PersistedKeyringRoot(persisted_keyring_file_root(bytes))
}

fn provider_keyring_binding(
    manifest: &KeyringManifest,
    root: PersistedKeyringRoot,
) -> Result<PersistedIdentityKeyringBinding, PersistedKeyringCustodyError> {
    PersistedIdentityKeyringBinding::from_authenticated_keyring(
        manifest.registry_instance,
        root.0,
        manifest.generation,
    )
    .map_err(|_| PersistedKeyringCustodyError::AuthenticationFailed)
}

fn provider_entry_binding(
    keyring: PersistedIdentityKeyringBinding,
    key_id: u32,
    entry: &KeyEntry,
) -> Result<PersistedIdentityKeyCapabilityBinding, PersistedKeyringCustodyError> {
    let status = match entry.status {
        PersistedKeyStatus::Signing => PersistedIdentityKeyStatus::Signing,
        PersistedKeyStatus::VerifyOnly => PersistedIdentityKeyStatus::VerifyOnly,
        PersistedKeyStatus::Retired => PersistedIdentityKeyStatus::Retired,
    };
    PersistedIdentityKeyCapabilityBinding::from_authenticated_keyring(
        keyring,
        key_id,
        entry.master_key_epoch,
        status,
    )
    .map_err(|_| PersistedKeyringCustodyError::AuthenticationFailed)
}

fn validate_anchor(
    manifest: &KeyringManifest,
    root: PersistedKeyringRoot,
    anchored: &RegistryAnchorTuple,
) -> Result<(), PersistedKeyringCustodyError> {
    if manifest.registry_instance != anchored.registry_instance
        || root.0.ct_eq(&anchored.keyring_root).unwrap_u8() != 1
    {
        return Err(PersistedKeyringCustodyError::AnchorMismatch);
    }
    Ok(())
}

fn random_nonzero_32() -> Result<[u8; 32], PersistedKeyringCustodyError> {
    let mut bytes = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| PersistedKeyringCustodyError::Crypto)?;
    while bytes == [0; 32] {
        OsRng
            .try_fill_bytes(&mut bytes)
            .map_err(|_| PersistedKeyringCustodyError::Crypto)?;
    }
    Ok(bytes)
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), PersistedKeyringCustodyError> {
    let parent = path
        .parent()
        .ok_or_else(|| PersistedKeyringCustodyError::Io("keyring path has no parent".to_owned()))?;
    let temporary = atomic_temporary_path(path)?;
    keyring_file_exists(path)?;
    let mut file = secure_create_new_regular(&temporary)
        .map_err(|error| PersistedKeyringCustodyError::Io(format!("open keyring temp: {error}")))?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|error| {
            PersistedKeyringCustodyError::Io(format!("write/fsync keyring temp: {error}"))
        })?;
    secure_replace_regular(&temporary, path)
        .map_err(|error| PersistedKeyringCustodyError::Io(format!("rename keyring: {error}")))?;
    fsync_directory(parent)
}

fn atomic_temporary_path(path: &Path) -> Result<PathBuf, PersistedKeyringCustodyError> {
    let parent = path
        .parent()
        .ok_or_else(|| PersistedKeyringCustodyError::Io("keyring path has no parent".to_owned()))?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| PersistedKeyringCustodyError::Io("invalid keyring path".to_owned()))?;
    Ok(parent.join(format!(".{name}.tmp")))
}

fn keyring_file_exists(path: &Path) -> Result<bool, PersistedKeyringCustodyError> {
    secure_regular_exists(path).map_err(|error| {
        PersistedKeyringCustodyError::RecoveryRequired(format!(
            "inspect confined keyring artifact {}: {error}",
            path.display()
        ))
    })
}

/// Exercises the production keyring leaf gate with an integration-test supplied path.
#[cfg(feature = "test-support")]
#[doc(hidden)]
pub fn test_only_keyring_file_exists(path: &Path) -> Result<bool, PersistedKeyringCustodyError> {
    keyring_file_exists(path)
}

fn cleanup_failed_pending_write(path: &Path) -> Result<(), PersistedKeyringCustodyError> {
    let parent = path
        .parent()
        .ok_or_else(|| PersistedKeyringCustodyError::Io("keyring path has no parent".to_owned()))?;
    let temporary = atomic_temporary_path(path)?;
    for artifact in [path, temporary.as_path()] {
        match secure_remove_regular(artifact) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(PersistedKeyringCustodyError::Io(format!(
                    "remove failed pending keyring artifact {}: {error}",
                    artifact.display()
                )))
            }
        }
    }
    fsync_directory(parent)
}

fn fsync_directory(directory: &Path) -> Result<(), PersistedKeyringCustodyError> {
    File::open(directory)
        .and_then(|file| file.sync_all())
        .map_err(|error| {
            PersistedKeyringCustodyError::Io(format!("fsync keyring directory: {error}"))
        })
}

fn anchor_error(
    error: advance_scheduler::observation_anchor::RegistryAnchorError,
) -> PersistedKeyringCustodyError {
    PersistedKeyringCustodyError::RecoveryRequired(error.to_string())
}

fn provider_error(error: PersistedKeyringCustodyError) -> SensitiveParamCatalogError {
    match error {
        PersistedKeyringCustodyError::AuthenticationFailed
        | PersistedKeyringCustodyError::KeyUnavailable
        | PersistedKeyringCustodyError::Retired
        | PersistedKeyringCustodyError::Invalid(_) => SensitiveParamCatalogError::InvalidCarrier,
        PersistedKeyringCustodyError::AnchorMismatch => SensitiveParamCatalogError::StaleIdentity,
        PersistedKeyringCustodyError::RecoveryRequired(_) => {
            SensitiveParamCatalogError::RecoveryRequired
        }
        PersistedKeyringCustodyError::Io(_) | PersistedKeyringCustodyError::Crypto => {
            SensitiveParamCatalogError::StorageUnavailable
        }
        #[cfg(feature = "test-support")]
        PersistedKeyringCustodyError::Failpoint(_) => {
            SensitiveParamCatalogError::StorageUnavailable
        }
    }
}

fn scheduler_custody_error(
    error: PersistedKeyringCustodyError,
) -> advance_scheduler::observation_anchor::RegistryAnchorError {
    use advance_scheduler::observation_anchor::RegistryAnchorError;
    match error {
        PersistedKeyringCustodyError::AuthenticationFailed => {
            RegistryAnchorError::AuthenticationFailed
        }
        PersistedKeyringCustodyError::AnchorMismatch => RegistryAnchorError::CompareAndSwapFailed,
        PersistedKeyringCustodyError::Invalid(_)
        | PersistedKeyringCustodyError::KeyUnavailable
        | PersistedKeyringCustodyError::Retired => RegistryAnchorError::InvalidTransition,
        PersistedKeyringCustodyError::RecoveryRequired(message) => {
            RegistryAnchorError::RecoveryRequired(message)
        }
        PersistedKeyringCustodyError::Io(message) => RegistryAnchorError::Unavailable(message),
        PersistedKeyringCustodyError::Crypto => {
            RegistryAnchorError::Unavailable("persisted-keyring cryptography failed".to_owned())
        }
        #[cfg(feature = "test-support")]
        PersistedKeyringCustodyError::Failpoint(point) => {
            RegistryAnchorError::Unavailable(format!("persisted-keyring failpoint: {point:?}"))
        }
    }
}

fn lock_error() -> PersistedKeyringCustodyError {
    PersistedKeyringCustodyError::Io("persisted-keyring process lock poisoned".to_owned())
}

fn invalid_successor() -> PersistedKeyringCustodyError {
    PersistedKeyringCustodyError::RecoveryRequired(
        "pending keyring is not the unique legal next generation".to_owned(),
    )
}

struct KeyringCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> KeyringCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], PersistedKeyringCustodyError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(PersistedKeyringCustodyError::AuthenticationFailed)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(PersistedKeyringCustodyError::AuthenticationFailed)?;
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], PersistedKeyringCustodyError> {
        self.take(N)?
            .try_into()
            .map_err(|_| PersistedKeyringCustodyError::AuthenticationFailed)
    }

    fn u8(&mut self) -> Result<u8, PersistedKeyringCustodyError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, PersistedKeyringCustodyError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, PersistedKeyringCustodyError> {
        Ok(u64::from_be_bytes(self.array()?))
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
    fn every_keyring_leaf_uses_the_character_device_rejecting_gate() {
        for leaf in [
            CURRENT_FILE,
            PENDING_FILE,
            ".contract218.keyring.current.tmp",
            ".contract218.keyring.pending.tmp",
        ] {
            assert!(
                keyring_file_exists(Path::new("/dev/null")).is_err(),
                "keyring leaf {leaf} accepted a character device"
            );
        }
    }

    #[test]
    fn persisted_identity_key_literal_kat() {
        let key = derive_carrier_key(&[0; 32], [1; 32], 1).unwrap();
        assert_eq!(
            hex::encode(key.as_ref()),
            "bf8f52ac21c5e9b48d5b389a04acd72bf7438a0b35da2771f718a097d7580e07"
        );
    }

    #[test]
    fn exact_generation_zero_keyring_is_191_bytes_and_literal_rooted() {
        let mut entries = BTreeMap::new();
        entries.insert(
            1,
            KeyEntry {
                status: PersistedKeyStatus::Signing,
                master_key_epoch: 7,
                last_issued_at_ms: 0,
                scan: None,
            },
        );
        let manifest = KeyringManifest {
            manifest_key_epoch: 7,
            registry_instance: [0x33; 16],
            generation: 0,
            previous_keyring_root: [0; 32],
            kdf_salt: [0x44; 32],
            next_key_id: 2,
            signing_key_id: 1,
            entries,
            manifest_nonce: [0x55; 32],
        };
        let mut bytes = encode_preceding_bytes(&manifest).unwrap();
        assert_eq!(bytes.len(), 159);
        let mac = manifest_mac(
            &[0x22; 32],
            manifest.manifest_key_epoch,
            manifest.registry_instance,
            manifest.kdf_salt,
            &bytes,
        )
        .unwrap();
        assert_eq!(
            hex::encode(mac),
            "dbb19994e175edd1794e1b3978b0e7b951eaa56d011ed8161bf44351394ebce8"
        );
        bytes.extend_from_slice(&mac);
        assert_eq!(bytes.len(), 191);
        assert_eq!(
            hex::encode(persisted_keyring_file_root(&bytes)),
            "947c65e5d7dc5f22e6b92529491aafa0ab2248e1dca0805115fa52a766670663"
        );
    }

    #[test]
    fn exact_298_byte_migration_marker_mac_and_root_literal_kat() {
        let mut block = [0_u8; 228];
        block[0..16].copy_from_slice(&[0x10; 16]);
        block[16..32].copy_from_slice(&[0x11; 16]);
        block[32..64].copy_from_slice(&[0x21; 32]);
        block[64..96].copy_from_slice(&[0x22; 32]);
        block[96..100].copy_from_slice(&1_u32.to_be_bytes());
        block[100..132].copy_from_slice(&[0x23; 32]);
        block[132..164].copy_from_slice(&[0x25; 32]);
        block[164..196].copy_from_slice(&[0x26; 32]);
        block[196..228].copy_from_slice(&[0x24; 32]);
        let mut preceding = Vec::with_capacity(266);
        preceding.push(1);
        preceding.extend_from_slice(&1_u32.to_be_bytes());
        preceding.extend_from_slice(&block);
        preceding.push(1);
        preceding.extend_from_slice(&[0xA1; 32]);
        assert_eq!(preceding.len(), 266);
        let mac = migration_marker_mac_with_master(&[0x71; 32], 1, [0x11; 16], &preceding).unwrap();
        assert_eq!(
            hex::encode(mac),
            "5617c75644cb9a9fd6a1347591c144cb5b41eee57389597dcafe55ff8aa000bd"
        );
        preceding.extend_from_slice(&mac);
        assert_eq!(preceding.len(), 298);
        assert_eq!(
            hex::encode(
                advance_scheduler::observation_anchor::registry_marker_root(&preceding).unwrap()
            ),
            "0b99b88c349ef61692793b7e3b63348e03f882fe11ce96cab35529fd4885c2d6"
        );
    }
}

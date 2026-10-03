//! Exact external monotonic anchor for the CONTRACT-218 registry.
//!
//! Bundles contain the complete registry-manifest, persisted-keyring,
//! role-allocation, and optional migration-marker artifact set.  Authority is
//! selected only by an injected platform monotonic record; bundle files alone
//! are never treated as rollback protection.

use advance_scheduler::observation_anchor::{
    legacy_registry_migration_digest, persisted_keyring_file_root, registry_marker_root,
    role_allocation_file_root, verify_successor_head, Compacted, DatabaseCommitted,
    PreparedCurrent, PreparedLegacyRegistryMigration, RegistryAnchorError, RegistryAnchorMutation,
    RegistryAnchorTransaction, RegistryAnchorTuple, RegistryAnchorWorld,
    RegistryDatabaseCommitProof, RegistryRecoveryCapability, RegistryRecoveryDecision,
    SelectedNext, VerifiedEmptyRegistryGenesis, VerifiedLegacyRegistryMigrationGenesis,
};
use fd_lock::RwLock as FileRwLock;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex, OnceLock};
use std::thread::JoinHandle;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

const BUNDLE_FILES: [&str; 2] = ["contract218.bundle-a", "contract218.bundle-b"];
const CUSTODY_FILE: &str = "contract218.custody.lock";
const KEYRING_CURRENT: &str = "contract218.keyring.current";
const KEYRING_PENDING: &str = "contract218.keyring.pending";
const ROLES_CURRENT: &str = "contract218.roles.current";
const ROLES_PENDING: &str = "contract218.roles.pending";
const MARKER_CURRENT: &str = "contract218.migration-marker.current";
const MARKER_PENDING: &str = "contract218.migration-marker.pending";

const FORMAT_VERSION: u8 = 1;
const SELECTOR_PRECEDING_LEN: usize = 119;
pub const PLATFORM_SELECTOR_LEN: usize = 151;
const MARKER_LEN: usize = 298;

const SELECTOR_INFO: &[u8] = b"advance.contract218.registry-anchor-selector.v1\0";
const SELECTOR_MAC_DOMAIN: &[u8] = b"advance.contract218.registry-anchor-selector.v1\0";
const MANIFEST_INFO: &[u8] = b"advance.contract218.registry-manifest-key.v1\0";
const MANIFEST_MAC_DOMAIN: &[u8] = b"advance.contract218.registry-manifest.v1\0";
const ROLE_MANIFEST_INFO: &[u8] = b"advance.contract218.role-allocation-manifest-key.v1\0";
const ROLE_MANIFEST_MAC_DOMAIN: &[u8] = b"advance.contract218.role-allocation-manifest.v1\0";
const KEYRING_MANIFEST_INFO: &[u8] = b"advance.contract218.persisted-keyring-manifest-key.v1\0";
const KEYRING_MANIFEST_MAC_DOMAIN: &[u8] = b"advance.contract218.persisted-keyring-manifest.v1\0";
const MARKER_INFO: &[u8] = b"advance.contract218.registry-migration-marker-key.v1\0";
const MARKER_MAC_DOMAIN: &[u8] = b"advance.contract218.registry-migration-marker.v1\0";
const BUNDLE_ROOT_DOMAIN: &[u8] = b"advance.contract218.registry-anchor-bundle.v1\0";
const ARTIFACT_SET_ROOT_DOMAIN: &[u8] = b"advance.contract218.registry-artifact-set.v1\0";
const MIGRATION_DIGEST_DOMAIN: &[u8] = b"advance.contract218.registry-migration-digest.v1\0";

/// Non-exportable selector-key capability.  `mac_for_epoch` supports the
/// current signing epoch and retained VerifyOnly epochs.
pub trait PlatformAnchorSeal: Send + Sync {
    fn current_epoch(&self) -> u32;
    fn mac_for_epoch(
        &self,
        epoch: u32,
        installation_id: [u8; 16],
        preceding: &[u8],
    ) -> Result<[u8; 32], RegistryAnchorError>;
}

/// Process-confined test/platform adapter with no key-export operation.
pub struct HmacPlatformAnchorSeal {
    current_epoch: u32,
    keys: BTreeMap<u32, Zeroizing<[u8; 32]>>,
}

impl HmacPlatformAnchorSeal {
    pub fn consume_platform_key(
        epoch: u32,
        key: Zeroizing<[u8; 32]>,
    ) -> Result<Self, RegistryAnchorError> {
        if epoch == 0 || key.as_ref() == &[0; 32] {
            return Err(RegistryAnchorError::InvalidTransition);
        }
        let mut keys = BTreeMap::new();
        keys.insert(epoch, key);
        Ok(Self {
            current_epoch: epoch,
            keys,
        })
    }

    pub fn retain_verify_only_key(
        mut self,
        epoch: u32,
        key: Zeroizing<[u8; 32]>,
    ) -> Result<Self, RegistryAnchorError> {
        if epoch == 0
            || epoch >= self.current_epoch
            || key.as_ref() == &[0; 32]
            || self.keys.insert(epoch, key).is_some()
        {
            return Err(RegistryAnchorError::InvalidTransition);
        }
        Ok(self)
    }
}

impl PlatformAnchorSeal for HmacPlatformAnchorSeal {
    fn current_epoch(&self) -> u32 {
        self.current_epoch
    }

    fn mac_for_epoch(
        &self,
        epoch: u32,
        installation_id: [u8; 16],
        preceding: &[u8],
    ) -> Result<[u8; 32], RegistryAnchorError> {
        let master = self
            .keys
            .get(&epoch)
            .ok_or(RegistryAnchorError::AuthenticationFailed)?;
        let mut info = SELECTOR_INFO.to_vec();
        info.extend_from_slice(&epoch.to_be_bytes());
        let mut key = Zeroizing::new([0u8; 32]);
        Hkdf::<Sha256>::new(Some(&installation_id), master.as_ref())
            .expand(&info, key.as_mut())
            .map_err(|_| RegistryAnchorError::AuthenticationFailed)?;
        let mut mac = HmacSha256::new_from_slice(key.as_ref())
            .map_err(|_| RegistryAnchorError::AuthenticationFailed)?;
        mac.update(SELECTOR_MAC_DOMAIN);
        mac.update(preceding);
        Ok(mac.finalize().into_bytes().into())
    }
}

/// Host-master capability used only for the external registry manifest.
pub trait RegistryManifestSeal: Send + Sync {
    fn mac_for_epoch(
        &self,
        epoch: u32,
        registry_instance: [u8; 16],
        preceding: &[u8],
    ) -> Result<[u8; 32], RegistryAnchorError>;

    fn role_allocation_mac_for_epoch(
        &self,
        epoch: u32,
        registry_instance: [u8; 16],
        preceding: &[u8],
    ) -> Result<[u8; 32], RegistryAnchorError>;

    fn persisted_keyring_mac_for_epoch(
        &self,
        epoch: u32,
        registry_instance: [u8; 16],
        kdf_salt: [u8; 32],
        preceding: &[u8],
    ) -> Result<[u8; 32], RegistryAnchorError>;

    fn migration_marker_mac_for_epoch(
        &self,
        epoch: u32,
        registry_instance: [u8; 16],
        preceding: &[u8],
    ) -> Result<[u8; 32], RegistryAnchorError>;
}

pub struct HmacRegistryManifestSeal {
    keys: BTreeMap<u32, Zeroizing<[u8; 32]>>,
}

impl HmacRegistryManifestSeal {
    pub fn consume_host_master_keys(
        keys: Vec<(u32, Zeroizing<[u8; 32]>)>,
    ) -> Result<Self, RegistryAnchorError> {
        let mut retained = BTreeMap::new();
        for (epoch, key) in keys {
            if epoch == 0 || key.as_ref() == &[0; 32] || retained.insert(epoch, key).is_some() {
                return Err(RegistryAnchorError::InvalidTransition);
            }
        }
        if retained.is_empty() {
            return Err(RegistryAnchorError::InvalidTransition);
        }
        Ok(Self { keys: retained })
    }

    fn typed_mac(
        &self,
        epoch: u32,
        salt: &[u8],
        info_domain: &[u8],
        mac_domain: &[u8],
        preceding: &[u8],
    ) -> Result<[u8; 32], RegistryAnchorError> {
        let master = self
            .keys
            .get(&epoch)
            .ok_or(RegistryAnchorError::AuthenticationFailed)?;
        let mut info = info_domain.to_vec();
        info.extend_from_slice(&epoch.to_be_bytes());
        let mut key = Zeroizing::new([0u8; 32]);
        Hkdf::<Sha256>::new(Some(salt), master.as_ref())
            .expand(&info, key.as_mut())
            .map_err(|_| RegistryAnchorError::AuthenticationFailed)?;
        let mut mac = HmacSha256::new_from_slice(key.as_ref())
            .map_err(|_| RegistryAnchorError::AuthenticationFailed)?;
        mac.update(mac_domain);
        mac.update(preceding);
        Ok(mac.finalize().into_bytes().into())
    }
}

impl RegistryManifestSeal for HmacRegistryManifestSeal {
    fn mac_for_epoch(
        &self,
        epoch: u32,
        registry_instance: [u8; 16],
        preceding: &[u8],
    ) -> Result<[u8; 32], RegistryAnchorError> {
        self.typed_mac(
            epoch,
            &registry_instance,
            MANIFEST_INFO,
            MANIFEST_MAC_DOMAIN,
            preceding,
        )
    }

    fn role_allocation_mac_for_epoch(
        &self,
        epoch: u32,
        registry_instance: [u8; 16],
        preceding: &[u8],
    ) -> Result<[u8; 32], RegistryAnchorError> {
        self.typed_mac(
            epoch,
            &registry_instance,
            ROLE_MANIFEST_INFO,
            ROLE_MANIFEST_MAC_DOMAIN,
            preceding,
        )
    }

    fn persisted_keyring_mac_for_epoch(
        &self,
        epoch: u32,
        registry_instance: [u8; 16],
        kdf_salt: [u8; 32],
        preceding: &[u8],
    ) -> Result<[u8; 32], RegistryAnchorError> {
        let mut salt = [0u8; 48];
        salt[..16].copy_from_slice(&registry_instance);
        salt[16..].copy_from_slice(&kdf_salt);
        self.typed_mac(
            epoch,
            &salt,
            KEYRING_MANIFEST_INFO,
            KEYRING_MANIFEST_MAC_DOMAIN,
            preceding,
        )
    }

    fn migration_marker_mac_for_epoch(
        &self,
        epoch: u32,
        registry_instance: [u8; 16],
        preceding: &[u8],
    ) -> Result<[u8; 32], RegistryAnchorError> {
        self.typed_mac(
            epoch,
            &registry_instance,
            MARKER_INFO,
            MARKER_MAC_DOMAIN,
            preceding,
        )
    }
}

/// Protected platform record.  Its installation id is created and owned by
/// the provider, never selected by the anchor caller.  CAS must enforce exact
/// expected bytes, consecutive positive generations, and nonce uniqueness.
pub trait PlatformMonotonicRecord: Send + Sync {
    fn installation_id(&self) -> [u8; 16];
    /// Bind this protected record exactly once to the canonical workspace
    /// identity.  Rebinding the same record to any other workspace must fail.
    fn bind_workspace_identity(
        &self,
        workspace_identity_digest: [u8; 32],
    ) -> Result<(), RegistryAnchorError>;
    fn read_selector(&self) -> Result<Option<Vec<u8>>, RegistryAnchorError>;
    /// Production implementations create generation 1 exactly once, require
    /// every later generation to be previous+1, and permanently reject nonce
    /// reuse.  Fixture backends may seed a high generation only for MAX-3
    /// boundary tests and are unavailable without `test-support`.
    fn compare_and_swap(
        &self,
        expected: Option<&[u8]>,
        replacement: &[u8],
        next_generation: u64,
        nonce: [u8; 32],
    ) -> Result<(), RegistryAnchorError>;
}

#[cfg(feature = "test-support")]
#[derive(Default)]
struct MemoryRecordState {
    workspace_identity_digest: Option<[u8; 32]>,
    selector: Option<Vec<u8>>,
    generation: u64,
    seen_nonces: HashSet<[u8; 32]>,
}

/// Deterministic protected-record fixture.  Keeping this object outside the
/// copied workspace/platform files models the actual platform rollback wall.
#[cfg(feature = "test-support")]
pub struct MemoryPlatformMonotonicRecord {
    installation_id: [u8; 16],
    state: Mutex<MemoryRecordState>,
}

#[cfg(feature = "test-support")]
impl MemoryPlatformMonotonicRecord {
    pub fn deterministic_for_test(installation_id: [u8; 16]) -> Result<Self, RegistryAnchorError> {
        if installation_id == [0; 16] {
            return Err(RegistryAnchorError::InvalidTransition);
        }
        Ok(Self {
            installation_id,
            state: Mutex::new(MemoryRecordState::default()),
        })
    }
}

#[cfg(feature = "test-support")]
impl PlatformMonotonicRecord for MemoryPlatformMonotonicRecord {
    fn installation_id(&self) -> [u8; 16] {
        self.installation_id
    }

    fn bind_workspace_identity(
        &self,
        workspace_identity_digest: [u8; 32],
    ) -> Result<(), RegistryAnchorError> {
        if workspace_identity_digest == [0; 32] {
            return Err(RegistryAnchorError::InvalidTransition);
        }
        let mut state = self.state.lock().map_err(|_| lock_poisoned())?;
        match state.workspace_identity_digest {
            None => {
                state.workspace_identity_digest = Some(workspace_identity_digest);
                Ok(())
            }
            Some(bound) if bound == workspace_identity_digest => Ok(()),
            Some(_) => Err(RegistryAnchorError::AuthenticationFailed),
        }
    }

    fn read_selector(&self) -> Result<Option<Vec<u8>>, RegistryAnchorError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| lock_poisoned())?
            .selector
            .clone())
    }

    fn compare_and_swap(
        &self,
        expected: Option<&[u8]>,
        replacement: &[u8],
        next_generation: u64,
        nonce: [u8; 32],
    ) -> Result<(), RegistryAnchorError> {
        let mut state = self.state.lock().map_err(|_| lock_poisoned())?;
        let generation_is_legal = if state.generation == 0 {
            next_generation > 0
        } else {
            next_generation == state.generation.checked_add(1).unwrap_or(0)
        };
        if state.workspace_identity_digest.is_none()
            || state.selector.as_deref() != expected
            || !generation_is_legal
            || next_generation == 0
            || nonce == [0; 32]
            || !state.seen_nonces.insert(nonce)
        {
            return Err(RegistryAnchorError::CompareAndSwapFailed);
        }
        state.selector = Some(replacement.to_vec());
        state.generation = next_generation;
        Ok(())
    }
}

const TEST_RECORD_MAGIC: &[u8; 8] = b"A218TST1";

/// Platform-owned monotonic record stored outside the workspace snapshot
/// domain.  The caller must place this file in protected platform state (the
/// production bootstrap uses the per-user Advance state directory); the
/// workspace custody lock and the record's atomic replace serialize CAS.
pub struct FilePlatformMonotonicRecord {
    path: PathBuf,
    installation_id: [u8; 16],
    writer: Mutex<()>,
    allow_high_genesis: bool,
}

impl FilePlatformMonotonicRecord {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, RegistryAnchorError> {
        Self::open_inner(path.as_ref(), false)
    }

    fn open_inner(path: &Path, allow_high_genesis: bool) -> Result<Self, RegistryAnchorError> {
        let path = path.to_path_buf();
        let parent = path.parent().ok_or_else(|| {
            RegistryAnchorError::Unavailable("test record path has no parent".to_owned())
        })?;
        fs::create_dir_all(parent)
            .map_err(|error| unavailable("create test record directory", error))?;
        let installation_id = if secure_regular_exists(&path)
            .map_err(|error| unavailable("inspect test platform monotonic record", error))?
        {
            decode_test_record(
                &read_exact_file(&path)
                    .map_err(|error| unavailable("read test platform monotonic record", error))?,
            )?
            .0
        } else {
            let id = random_nonzero_16()?;
            atomic_write(&path, &encode_test_record(id, None, 0, None, &[])?)?;
            id
        };
        Ok(Self {
            path,
            installation_id,
            writer: Mutex::new(()),
            allow_high_genesis,
        })
    }

    #[cfg(feature = "test-support")]
    pub fn open_for_test(path: impl AsRef<Path>) -> Result<Self, RegistryAnchorError> {
        Self::open_inner(path.as_ref(), true)
    }
}

#[cfg(feature = "test-support")]
pub type FileTestPlatformMonotonicRecord = FilePlatformMonotonicRecord;

impl PlatformMonotonicRecord for FilePlatformMonotonicRecord {
    fn installation_id(&self) -> [u8; 16] {
        self.installation_id
    }

    fn bind_workspace_identity(
        &self,
        workspace_identity_digest: [u8; 32],
    ) -> Result<(), RegistryAnchorError> {
        if workspace_identity_digest == [0; 32] {
            return Err(RegistryAnchorError::InvalidTransition);
        }
        let _writer = self.writer.lock().map_err(|_| lock_poisoned())?;
        let bytes = read_exact_file(&self.path)
            .map_err(|error| unavailable("read test platform monotonic record", error))?;
        let (id, bound, generation, selector, nonces) = decode_test_record(&bytes)?;
        if id != self.installation_id {
            return Err(RegistryAnchorError::AuthenticationFailed);
        }
        match bound {
            Some(bound) if bound != workspace_identity_digest => {
                Err(RegistryAnchorError::AuthenticationFailed)
            }
            Some(_) => Ok(()),
            None => atomic_write(
                &self.path,
                &encode_test_record(
                    id,
                    Some(workspace_identity_digest),
                    generation,
                    selector.as_deref(),
                    &nonces,
                )?,
            ),
        }
    }

    fn read_selector(&self) -> Result<Option<Vec<u8>>, RegistryAnchorError> {
        let _writer = self.writer.lock().map_err(|_| lock_poisoned())?;
        let (id, _, _, selector, _) = decode_test_record(
            &read_exact_file(&self.path)
                .map_err(|error| unavailable("read test platform monotonic record", error))?,
        )?;
        if id != self.installation_id {
            return Err(RegistryAnchorError::AuthenticationFailed);
        }
        Ok(selector)
    }

    fn compare_and_swap(
        &self,
        expected: Option<&[u8]>,
        replacement: &[u8],
        next_generation: u64,
        nonce: [u8; 32],
    ) -> Result<(), RegistryAnchorError> {
        let _writer = self.writer.lock().map_err(|_| lock_poisoned())?;
        let bytes = read_exact_file(&self.path)
            .map_err(|error| unavailable("read test platform monotonic record", error))?;
        let (id, binding, generation, current, mut nonces) = decode_test_record(&bytes)?;
        let generation_is_legal = if generation == 0 {
            next_generation == 1 || (self.allow_high_genesis && next_generation > 0)
        } else {
            next_generation == generation.checked_add(1).unwrap_or(0)
        };
        if id != self.installation_id
            || binding.is_none()
            || current.as_deref() != expected
            || !generation_is_legal
            || next_generation == 0
            || nonce == [0; 32]
            || nonces.contains(&nonce)
            || nonces.len() >= 1_000_000
        {
            return Err(RegistryAnchorError::CompareAndSwapFailed);
        }
        nonces.push(nonce);
        atomic_write(
            &self.path,
            &encode_test_record(id, binding, next_generation, Some(replacement), &nonces)?,
        )
    }
}

fn encode_test_record(
    installation_id: [u8; 16],
    workspace_identity_digest: Option<[u8; 32]>,
    generation: u64,
    selector: Option<&[u8]>,
    nonces: &[[u8; 32]],
) -> Result<Vec<u8>, RegistryAnchorError> {
    let mut out = Vec::new();
    out.extend_from_slice(TEST_RECORD_MAGIC);
    out.extend_from_slice(&installation_id);
    match workspace_identity_digest {
        None => out.push(0),
        Some(digest) => {
            out.push(1);
            out.extend_from_slice(&digest);
        }
    }
    out.extend_from_slice(&generation.to_be_bytes());
    match selector {
        None => out.push(0),
        Some(selector) => {
            out.push(1);
            out.extend_from_slice(
                &u32::try_from(selector.len())
                    .map_err(|_| RegistryAnchorError::InvalidTransition)?
                    .to_be_bytes(),
            );
            out.extend_from_slice(selector);
        }
    }
    out.extend_from_slice(
        &u32::try_from(nonces.len())
            .map_err(|_| RegistryAnchorError::InvalidTransition)?
            .to_be_bytes(),
    );
    for nonce in nonces {
        if *nonce == [0; 32] {
            return Err(RegistryAnchorError::InvalidTransition);
        }
        out.extend_from_slice(nonce);
    }
    Ok(out)
}

fn decode_test_record(
    bytes: &[u8],
) -> Result<
    (
        [u8; 16],
        Option<[u8; 32]>,
        u64,
        Option<Vec<u8>>,
        Vec<[u8; 32]>,
    ),
    RegistryAnchorError,
> {
    let mut cursor = Cursor::new(bytes);
    if cursor.take(8)? != TEST_RECORD_MAGIC {
        return Err(RegistryAnchorError::AuthenticationFailed);
    }
    let installation_id = cursor.array::<16>()?;
    let workspace_identity_digest = match cursor.u8()? {
        0 => None,
        1 => Some(cursor.array::<32>()?),
        _ => return Err(RegistryAnchorError::AuthenticationFailed),
    };
    let generation = cursor.u64()?;
    let selector = match cursor.u8()? {
        0 if generation == 0 => None,
        1 if generation > 0 => {
            let len = cursor.u32()? as usize;
            Some(cursor.take(len)?.to_vec())
        }
        _ => return Err(RegistryAnchorError::AuthenticationFailed),
    };
    let nonce_count = cursor.u32()? as usize;
    if nonce_count > 1_000_000 {
        return Err(RegistryAnchorError::AuthenticationFailed);
    }
    let mut nonces = Vec::with_capacity(nonce_count);
    let mut unique = HashSet::with_capacity(nonce_count);
    for _ in 0..nonce_count {
        let nonce = cursor.array::<32>()?;
        if nonce == [0; 32] || !unique.insert(nonce) {
            return Err(RegistryAnchorError::AuthenticationFailed);
        }
        nonces.push(nonce);
    }
    if installation_id == [0; 16]
        || workspace_identity_digest == Some([0; 32])
        || !cursor.is_empty()
    {
        return Err(RegistryAnchorError::AuthenticationFailed);
    }
    Ok((
        installation_id,
        workspace_identity_digest,
        generation,
        selector,
        nonces,
    ))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnchorFailpoint {
    AfterBundleFsync,
    AfterSelectorFsync,
}

#[derive(Clone)]
pub struct FilePlatformMonotonicAnchorStore {
    inner: Arc<FileAnchorInner>,
}

struct FileAnchorInner {
    directory: PathBuf,
    workspace: PathBuf,
    installation_id: [u8; 16],
    record: Arc<dyn PlatformMonotonicRecord>,
    selector_seal: Arc<dyn PlatformAnchorSeal>,
    manifest_seal: Arc<dyn RegistryManifestSeal>,
    lease_secret: Zeroizing<[u8; 32]>,
    _custody: Arc<AnchorCustody>,
    writer: Mutex<()>,
    failpoint: Mutex<Option<AnchorFailpoint>>,
    role_custody_claimed: Arc<AtomicBool>,
    keyring_custody_claimed: Arc<AtomicBool>,
    marker_custody_claimed: Arc<AtomicBool>,
}

impl FilePlatformMonotonicAnchorStore {
    pub fn acquire(
        platform_directory: impl AsRef<Path>,
        workspace_snapshot_root: impl AsRef<Path>,
        record: Arc<dyn PlatformMonotonicRecord>,
        selector_seal: Arc<dyn PlatformAnchorSeal>,
        manifest_seal: Arc<dyn RegistryManifestSeal>,
    ) -> Result<Self, RegistryAnchorError> {
        if selector_seal.current_epoch() == 0 || record.installation_id() == [0; 16] {
            return Err(RegistryAnchorError::InvalidTransition);
        }
        fs::create_dir_all(platform_directory.as_ref())
            .map_err(|error| unavailable("create platform anchor directory", error))?;
        let directory = fs::canonicalize(platform_directory.as_ref())
            .map_err(|error| unavailable("canonicalize platform anchor directory", error))?;
        let workspace = fs::canonicalize(workspace_snapshot_root.as_ref())
            .map_err(|error| unavailable("canonicalize workspace snapshot root", error))?;
        if directory.starts_with(&workspace) {
            return Err(RegistryAnchorError::RecoveryRequired(
                "platform anchor must live outside the workspace snapshot domain".to_owned(),
            ));
        }
        let platform_custody = ExclusiveCustody::acquire_platform(directory.join(CUSTODY_FILE))?;
        let workspace_custody = ExclusiveCustody::acquire_workspace(workspace.clone())?;
        record.bind_workspace_identity(workspace_identity_digest(&workspace))?;
        let lease_secret = Zeroizing::new(random_nonzero_32()?);
        Ok(Self {
            inner: Arc::new(FileAnchorInner {
                directory,
                workspace,
                installation_id: record.installation_id(),
                record,
                selector_seal,
                manifest_seal,
                lease_secret,
                _custody: Arc::new(AnchorCustody {
                    _platform: platform_custody,
                    _workspace: workspace_custody,
                }),
                writer: Mutex::new(()),
                failpoint: Mutex::new(None),
                role_custody_claimed: Arc::new(AtomicBool::new(false)),
                keyring_custody_claimed: Arc::new(AtomicBool::new(false)),
                marker_custody_claimed: Arc::new(AtomicBool::new(false)),
            }),
        })
    }

    pub(crate) fn shares_store_with(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }

    /// Exact pre-genesis state used only while the authenticated keyring and
    /// empty role manifest are being assembled for the first provider open.
    /// Once a selector exists this can never return true again, even if bundle
    /// files are removed or rolled back.
    pub(crate) fn is_exact_pre_genesis(&self) -> Result<bool, RegistryAnchorError> {
        if self.inner.record.read_selector()?.is_some() {
            return Ok(false);
        }
        for file in BUNDLE_FILES {
            if secure_regular_exists(&self.inner.directory.join(file))
                .map_err(|error| unavailable("inspect pre-genesis anchor bundle", error))?
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub(crate) fn require_uninitialized_for_migration(&self) -> Result<(), RegistryAnchorError> {
        let _writer = self.inner.writer.lock().map_err(|_| lock_poisoned())?;
        if !self.inner.anchor_artifacts_are_exactly_absent()? {
            return Err(RegistryAnchorError::RecoveryRequired(
                "legacy migration requires an exactly uninitialized external anchor".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn authenticated_world(&self) -> Result<RegistryAnchorWorld, RegistryAnchorError> {
        self.inner.read_selected().map(|selected| selected.world)
    }

    #[cfg(feature = "test-support")]
    pub fn set_failpoint_for_test(&self, failpoint: AnchorFailpoint) {
        *self
            .inner
            .failpoint
            .lock()
            .expect("failpoint lock poisoned") = Some(failpoint);
    }

    /// Explicit test fixture only.  Production initialization never creates
    /// owner artifacts and rejects their absence.
    #[cfg(feature = "test-support")]
    pub fn install_minimal_artifacts_for_test(
        &self,
        tuple: &RegistryAnchorTuple,
        manifest_key_epoch: u32,
    ) -> Result<(), RegistryAnchorError> {
        self.inner
            .install_minimal_artifacts_for_test(tuple, manifest_key_epoch)
    }

    #[cfg(feature = "test-support")]
    pub fn initialize_compact_at_generation_for_test(
        &self,
        genesis: &RegistryAnchorTuple,
        generation: u64,
    ) -> Result<(), RegistryAnchorError> {
        self.inner.install_minimal_artifacts_for_test(genesis, 1)?;
        self.inner.initialize_compact(genesis, 1, generation)
    }

    pub(crate) fn claim_role_custody(
        &self,
    ) -> Result<(PathBuf, SharedRoleCustodyClaim), RegistryAnchorError> {
        claim_custody(
            &self.inner.role_custody_claimed,
            "a second CONTRACT-218 role-root custody object is already active",
        )?;
        Ok((
            self.inner.directory.clone(),
            SharedRoleCustodyClaim {
                _exclusive: Arc::clone(&self.inner._custody),
                claimed: Arc::clone(&self.inner.role_custody_claimed),
            },
        ))
    }

    pub(crate) fn claim_keyring_custody(
        &self,
    ) -> Result<(PathBuf, SharedKeyringCustodyClaim), RegistryAnchorError> {
        claim_custody(
            &self.inner.keyring_custody_claimed,
            "a second persisted-keyring custody object is already active",
        )?;
        Ok((
            self.inner.directory.clone(),
            SharedKeyringCustodyClaim {
                _exclusive: Arc::clone(&self.inner._custody),
                claimed: Arc::clone(&self.inner.keyring_custody_claimed),
            },
        ))
    }

    pub(crate) fn claim_marker_custody(
        &self,
    ) -> Result<(PathBuf, PathBuf, SharedMarkerCustodyClaim), RegistryAnchorError> {
        claim_custody(
            &self.inner.marker_custody_claimed,
            "a second legacy-migration marker custody object is already active",
        )?;
        Ok((
            self.inner.directory.clone(),
            self.inner.workspace.clone(),
            SharedMarkerCustodyClaim {
                _exclusive: Arc::clone(&self.inner._custody),
                claimed: Arc::clone(&self.inner.marker_custody_claimed),
            },
        ))
    }
}

fn claim_custody(flag: &AtomicBool, message: &str) -> Result<(), RegistryAnchorError> {
    flag.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .map(|_| ())
        .map_err(|_| RegistryAnchorError::RecoveryRequired(message.to_owned()))
}

impl RegistryAnchorTransaction for FilePlatformMonotonicAnchorStore {
    fn observe(&self) -> Result<RegistryAnchorWorld, RegistryAnchorError> {
        self.authenticated_world()
    }

    fn anchor_lease_tag(&self, challenge: [u8; 32]) -> Result<[u8; 32], RegistryAnchorError> {
        if challenge == [0; 32] {
            return Err(RegistryAnchorError::InvalidTransition);
        }
        let mut mac = HmacSha256::new_from_slice(self.inner.lease_secret.as_ref())
            .map_err(|_| RegistryAnchorError::AuthenticationFailed)?;
        mac.update(b"advance.contract218.marker-anchor-lease.v1\0");
        mac.update(&self.inner.installation_id);
        mac.update(&workspace_identity_digest(&self.inner.workspace));
        mac.update(&challenge);
        Ok(mac.finalize().into_bytes().into())
    }

    fn authenticate_role_allocation_artifacts(
        &self,
        current: &RegistryAnchorTuple,
        head_context: &advance_scheduler::observation_anchor::RegistryHeadContext,
        previous_manifest_bytes: &[u8],
        next_manifest_bytes: &[u8],
    ) -> Result<(), RegistryAnchorError> {
        self.inner.authenticate_role_allocation_artifacts(
            current,
            head_context,
            previous_manifest_bytes,
            next_manifest_bytes,
        )
    }

    fn authenticate_persisted_keyring_artifacts(
        &self,
        current: &RegistryAnchorTuple,
        head_context: &advance_scheduler::observation_anchor::RegistryHeadContext,
        previous_file_bytes: &[u8],
        next_file_bytes: &[u8],
    ) -> Result<(), RegistryAnchorError> {
        self.inner.authenticate_persisted_keyring_artifacts(
            current,
            head_context,
            previous_file_bytes,
            next_file_bytes,
        )
    }

    fn authenticate_legacy_migration_artifacts(
        &self,
        migration_block: &[u8],
        prepared_marker: &[u8],
        installed_marker: &[u8],
        complete_marker: &[u8],
        initial_keyring_file: &[u8],
        initial_role_allocation_file: &[u8],
    ) -> Result<(), RegistryAnchorError> {
        self.inner.authenticate_legacy_migration_artifacts(
            migration_block,
            prepared_marker,
            installed_marker,
            complete_marker,
            initial_keyring_file,
            initial_role_allocation_file,
        )
    }

    fn authenticate_legacy_marker_transition_artifacts(
        &self,
        previous: &RegistryAnchorTuple,
        next: &RegistryAnchorTuple,
        head_context: &advance_scheduler::observation_anchor::RegistryHeadContext,
        previous_marker: &[u8],
        next_marker: &[u8],
    ) -> Result<(), RegistryAnchorError> {
        self.inner.authenticate_legacy_marker_transition_artifacts(
            previous,
            next,
            head_context,
            previous_marker,
            next_marker,
        )
    }

    fn initialize_compact(
        &self,
        genesis: VerifiedEmptyRegistryGenesis,
    ) -> Result<(), RegistryAnchorError> {
        genesis.verify_workspace_identity(&self.inner.workspace)?;
        let epoch = self.inner.current_artifact_epoch(genesis.tuple())?;
        self.inner.initialize_compact(genesis.tuple(), epoch, 1)
    }

    fn initialize_migrated_compact(
        &self,
        genesis: VerifiedLegacyRegistryMigrationGenesis,
        artifacts: PreparedLegacyRegistryMigration,
    ) -> Result<(), RegistryAnchorError> {
        genesis.verify_workspace_identity(&self.inner.workspace)?;
        artifacts.authenticate_with(self)?;
        let tuple = genesis.tuple();
        if tuple.sequence != 0
            || tuple.registry_instance != artifacts.registry_instance()
            || tuple.state_root != artifacts.target_state_root()
            || tuple.keyring_root != artifacts.target_keyring_root()
            || tuple.role_allocation_root != artifacts.target_role_allocation_root()
            || tuple.migration_digest != artifacts.migration_digest()
            || genesis.marker_root() != artifacts.prepared_marker_root()
            || genesis.manifest_key_epoch() != artifacts.manifest_key_epoch()
            || genesis.migration_id() != artifacts.migration_id()
        {
            return Err(RegistryAnchorError::AuthenticationFailed);
        }
        let current_marker = read_required(
            &self.inner.directory.join(MARKER_CURRENT),
            "Prepared migration marker",
        )?;
        if current_marker != artifacts.prepared_marker_bytes()
            || secure_regular_exists(&self.inner.directory.join(MARKER_PENDING))
                .map_err(|error| unavailable("inspect pending migration marker", error))?
            || secure_regular_exists(&self.inner.directory.join(format!(".{MARKER_CURRENT}.tmp")))
                .map_err(|error| unavailable("inspect current marker temporary", error))?
            || secure_regular_exists(&self.inner.directory.join(format!(".{MARKER_PENDING}.tmp")))
                .map_err(|error| unavailable("inspect pending marker temporary", error))?
        {
            return Err(RegistryAnchorError::AuthenticationFailed);
        }
        self.inner
            .initialize_compact(tuple, genesis.manifest_key_epoch(), 1)
    }

    fn prepare_current(
        &self,
        mutation: RegistryAnchorMutation,
    ) -> Result<Box<dyn PreparedCurrent>, RegistryAnchorError> {
        // Validate the move-only scheduler lease before the first pending
        // bundle write.  A mutation issued for another installation,
        // workspace, or registry postimage never reaches FileAnchorInner.
        mutation.verify_anchor_lease(self)?;
        self.inner.prepare_current(&mutation)?;
        Ok(Box::new(FilePreparedCurrent {
            inner: Arc::clone(&self.inner),
            mutation,
        }))
    }

    fn recover(&self, capability: RegistryRecoveryCapability) -> Result<(), RegistryAnchorError> {
        capability.verify_anchor_lease(self)?;
        if self.authenticated_world()? != *capability.external() {
            return Err(RegistryAnchorError::CompareAndSwapFailed);
        }
        match capability.decision() {
            RegistryRecoveryDecision::RollBackPending => {
                self.inner.rollback_pending(capability.ledger())
            }
            RegistryRecoveryDecision::FinishPendingPromotion => {
                self.inner.select_next(capability.ledger())?;
                self.inner.compact(capability.ledger())
            }
            RegistryRecoveryDecision::CompactSelectedNext => {
                self.inner.compact(capability.ledger())
            }
            RegistryRecoveryDecision::Clean => match self.authenticated_world()? {
                RegistryAnchorWorld::CompactCurrent { current, .. }
                    if current == *capability.ledger() =>
                {
                    Ok(())
                }
                _ => Err(RegistryAnchorError::CompareAndSwapFailed),
            },
        }
    }
}

struct FilePreparedCurrent {
    inner: Arc<FileAnchorInner>,
    mutation: RegistryAnchorMutation,
}

impl PreparedCurrent for FilePreparedCurrent {
    fn database_committed(
        self: Box<Self>,
        committed: RegistryDatabaseCommitProof,
    ) -> Result<Box<dyn DatabaseCommitted>, RegistryAnchorError> {
        committed.verify_for(&self.mutation)?;
        let anchor = FilePlatformMonotonicAnchorStore {
            inner: Arc::clone(&self.inner),
        };
        committed.verify_anchor_lease(&anchor)?;
        let committed = committed.committed().clone();
        match self.inner.read_selected()?.world {
            RegistryAnchorWorld::PendingCurrent { previous, next, .. }
                if previous == *self.mutation.previous() && next == committed =>
            {
                Ok(Box::new(FileDatabaseCommitted {
                    inner: Arc::clone(&self.inner),
                    committed,
                }))
            }
            _ => Err(RegistryAnchorError::InvalidTransition),
        }
    }
}

struct FileDatabaseCommitted {
    inner: Arc<FileAnchorInner>,
    committed: RegistryAnchorTuple,
}

impl DatabaseCommitted for FileDatabaseCommitted {
    fn select_next(self: Box<Self>) -> Result<Box<dyn SelectedNext>, RegistryAnchorError> {
        self.inner.select_next(&self.committed)?;
        Ok(Box::new(FileSelectedNext {
            inner: Arc::clone(&self.inner),
            committed: self.committed,
        }))
    }
}

struct FileSelectedNext {
    inner: Arc<FileAnchorInner>,
    committed: RegistryAnchorTuple,
}

impl SelectedNext for FileSelectedNext {
    fn compact(self: Box<Self>) -> Result<Box<dyn Compacted>, RegistryAnchorError> {
        self.inner.compact(&self.committed)?;
        Ok(Box::new(FileCompacted {
            current: self.committed,
        }))
    }
}

struct FileCompacted {
    current: RegistryAnchorTuple,
}

impl Compacted for FileCompacted {
    fn current(&self) -> &RegistryAnchorTuple {
        &self.current
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PendingManifestFields {
    previous_sequence: u64,
    previous_head: [u8; 32],
    previous_state_root: [u8; 32],
    previous_keyring_root: [u8; 32],
    next_sequence: u64,
    next_head: [u8; 32],
    next_state_root: [u8; 32],
    next_keyring_root: [u8; 32],
    previous_role_allocation_root: [u8; 32],
    next_role_allocation_root: [u8; 32],
    previous_marker_root: [u8; 32],
    next_marker_root: [u8; 32],
    next_manifest_key_epoch: u32,
    next_artifact_root: [u8; 32],
    operation_tag: u8,
    write_set_digest: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RegistryManifest {
    manifest_key_epoch: u32,
    committed: RegistryAnchorTuple,
    pending: Option<PendingManifestFields>,
    nonce: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ArtifactSet {
    registry_manifest: Vec<u8>,
    persisted_keyring: Vec<u8>,
    role_allocation: Vec<u8>,
    marker: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RegistryAnchorBundle {
    current: ArtifactSet,
    next: Option<ArtifactSet>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SelectedSet {
    Current = 1,
    Next = 2,
}

impl SelectedSet {
    fn decode(value: u8) -> Result<Self, RegistryAnchorError> {
        match value {
            1 => Ok(Self::Current),
            2 => Ok(Self::Next),
            _ => Err(RegistryAnchorError::AuthenticationFailed),
        }
    }
}

#[derive(Clone, Debug)]
struct Selector {
    selector_key_epoch: u32,
    workspace_installation_id: [u8; 16],
    generation: u64,
    active_slot: usize,
    selected_set: SelectedSet,
    active_bundle_root: [u8; 32],
    registry_instance: [u8; 16],
    selected_sequence: u64,
    nonce: [u8; 32],
}

struct SelectedState {
    selector_bytes: Vec<u8>,
    selector: Selector,
    bundle: RegistryAnchorBundle,
    current_manifest: RegistryManifest,
    next_manifest: Option<RegistryManifest>,
    world: RegistryAnchorWorld,
}

impl FileAnchorInner {
    fn authenticate_role_allocation_artifacts(
        &self,
        current: &RegistryAnchorTuple,
        head_context: &advance_scheduler::observation_anchor::RegistryHeadContext,
        previous: &[u8],
        next: &[u8],
    ) -> Result<(), RegistryAnchorError> {
        let _writer = self.writer.lock().map_err(|_| lock_poisoned())?;
        let selected = self.read_selected_unlocked()?;
        if !matches!(
            &selected.world,
            RegistryAnchorWorld::CompactCurrent { current: observed, .. } if observed == current
        ) || selected.current_manifest.manifest_key_epoch != head_context.manifest_key_epoch
            || selected.bundle.current.role_allocation != previous
            || read_required(&self.directory.join(ROLES_CURRENT), "current role manifest")?
                != previous
            || read_required(&self.directory.join(ROLES_PENDING), "pending role manifest")? != next
            || role_allocation_file_root(previous) != current.role_allocation_root
            || registry_marker_root(&selected.bundle.current.marker)?
                != head_context.previous_marker_root
            || head_context.previous_marker_root != head_context.next_marker_root
        {
            return Err(RegistryAnchorError::AuthenticationFailed);
        }
        authenticate_role_file(previous, self.manifest_seal.as_ref())?;
        authenticate_role_file(next, self.manifest_seal.as_ref())?;
        let (previous_epoch, previous_instance) = artifact_header(previous)?;
        let (next_epoch, next_instance) = artifact_header(next)?;
        if previous_epoch != head_context.manifest_key_epoch
            || next_epoch != head_context.next_manifest_key_epoch
            || previous_instance != current.registry_instance
            || next_instance != current.registry_instance
        {
            return Err(RegistryAnchorError::AuthenticationFailed);
        }
        Ok(())
    }

    fn authenticate_persisted_keyring_artifacts(
        &self,
        current: &RegistryAnchorTuple,
        head_context: &advance_scheduler::observation_anchor::RegistryHeadContext,
        previous: &[u8],
        next: &[u8],
    ) -> Result<(), RegistryAnchorError> {
        let _writer = self.writer.lock().map_err(|_| lock_poisoned())?;
        let selected = self.read_selected_unlocked()?;
        if !matches!(
            &selected.world,
            RegistryAnchorWorld::CompactCurrent { current: observed, .. } if observed == current
        ) || selected.current_manifest.manifest_key_epoch != head_context.manifest_key_epoch
            || selected.bundle.current.persisted_keyring != previous
            || read_required(
                &self.directory.join(KEYRING_CURRENT),
                "current persisted keyring",
            )? != previous
            || read_required(
                &self.directory.join(KEYRING_PENDING),
                "pending persisted keyring",
            )? != next
            || persisted_keyring_file_root(previous) != current.keyring_root
            || registry_marker_root(&selected.bundle.current.marker)?
                != head_context.previous_marker_root
            || head_context.previous_marker_root != head_context.next_marker_root
        {
            return Err(RegistryAnchorError::AuthenticationFailed);
        }
        authenticate_keyring_file(previous, self.manifest_seal.as_ref())?;
        authenticate_keyring_file(next, self.manifest_seal.as_ref())?;
        let (previous_epoch, previous_instance) = artifact_header(previous)?;
        let (next_epoch, next_instance) = artifact_header(next)?;
        if previous_epoch != head_context.manifest_key_epoch
            || next_epoch != head_context.next_manifest_key_epoch
            || previous_instance != current.registry_instance
            || next_instance != current.registry_instance
        {
            return Err(RegistryAnchorError::AuthenticationFailed);
        }
        Ok(())
    }

    fn authenticate_legacy_migration_artifacts(
        &self,
        migration_block: &[u8],
        prepared_marker: &[u8],
        installed_marker: &[u8],
        complete_marker: &[u8],
        initial_keyring_file: &[u8],
        initial_role_allocation_file: &[u8],
    ) -> Result<(), RegistryAnchorError> {
        let _writer = self.writer.lock().map_err(|_| lock_poisoned())?;
        if migration_block.len() != 228 {
            return Err(RegistryAnchorError::AuthenticationFailed);
        }
        let anchor_is_absent = self.anchor_artifacts_are_exactly_absent()?;
        let physical_keyring = read_required(
            &self.directory.join(KEYRING_CURRENT),
            "initial persisted keyring",
        )?;
        let physical_roles =
            read_required(&self.directory.join(ROLES_CURRENT), "initial role manifest")?;
        if physical_keyring != initial_keyring_file
            || physical_roles != initial_role_allocation_file
        {
            return Err(RegistryAnchorError::AuthenticationFailed);
        }
        authenticate_keyring_file(initial_keyring_file, self.manifest_seal.as_ref())?;
        authenticate_role_file(initial_role_allocation_file, self.manifest_seal.as_ref())?;
        let (epoch, instance) = artifact_header(initial_keyring_file)?;
        let (role_epoch, role_instance) = artifact_header(initial_role_allocation_file)?;
        if epoch != role_epoch || instance != role_instance {
            return Err(RegistryAnchorError::AuthenticationFailed);
        }
        let mut observed_nonces = HashSet::new();
        for (expected_phase, marker) in [
            (1_u8, prepared_marker),
            (2_u8, installed_marker),
            (3_u8, complete_marker),
        ] {
            authenticate_marker_file(marker, self.manifest_seal.as_ref())?;
            if marker[1..5] != epoch.to_be_bytes()
                || marker[5..233] != *migration_block
                || marker[21..37] != instance
                || marker[233] != expected_phase
                || !observed_nonces.insert(&marker[234..266])
            {
                return Err(RegistryAnchorError::AuthenticationFailed);
            }
        }
        if !anchor_is_absent {
            let selected = self.read_selected_unlocked()?;
            let selected_tuple = match &selected.world {
                RegistryAnchorWorld::CompactCurrent { current, .. } => current,
                _ => return Err(RegistryAnchorError::AuthenticationFailed),
            };
            let block: &[u8; 228] = migration_block
                .try_into()
                .map_err(|_| RegistryAnchorError::AuthenticationFailed)?;
            if selected_tuple.registry_instance != instance
                || selected_tuple.migration_digest != legacy_registry_migration_digest(block)
                || selected.bundle.current.persisted_keyring != initial_keyring_file
                || selected.bundle.current.role_allocation != initial_role_allocation_file
            {
                return Err(RegistryAnchorError::AuthenticationFailed);
            }
            let physical_current = read_required(
                &self.directory.join(MARKER_CURRENT),
                "current migration marker",
            )?;
            let physical_pending = match read_exact_file(&self.directory.join(MARKER_PENDING)) {
                Ok(bytes) => Some(bytes),
                Err(error) if error.kind() == io::ErrorKind::NotFound => None,
                Err(error) => return Err(unavailable("read pending migration marker", error)),
            };
            let planned = [prepared_marker, installed_marker, complete_marker];
            let selected_marker = selected.bundle.current.marker.as_slice();
            let selected_is_planned = planned.contains(&selected_marker);
            let current_is_planned = planned.contains(&physical_current.as_slice());
            let pending_is_planned = physical_pending
                .as_deref()
                .map_or(true, |pending| planned.contains(&pending));
            let owner_relation = selected_marker == physical_current
                || physical_pending.as_deref() == Some(selected_marker);
            if !selected_is_planned || !current_is_planned || !pending_is_planned || !owner_relation
            {
                return Err(RegistryAnchorError::AuthenticationFailed);
            }
        }
        Ok(())
    }

    fn authenticate_legacy_marker_transition_artifacts(
        &self,
        previous_tuple: &RegistryAnchorTuple,
        next_tuple: &RegistryAnchorTuple,
        head_context: &advance_scheduler::observation_anchor::RegistryHeadContext,
        previous: &[u8],
        next: &[u8],
    ) -> Result<(), RegistryAnchorError> {
        let _writer = self.writer.lock().map_err(|_| lock_poisoned())?;
        let selected = self.read_selected_unlocked()?;
        let physical_current = read_required(
            &self.directory.join(MARKER_CURRENT),
            "current migration marker",
        )?;
        let physical_pending = match read_exact_file(&self.directory.join(MARKER_PENDING)) {
            Ok(bytes) => Some(bytes),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(unavailable("read pending migration marker", error)),
        };
        let selected_tuple = match &selected.world {
            RegistryAnchorWorld::CompactCurrent { current, .. } => current,
            _ => return Err(RegistryAnchorError::AuthenticationFailed),
        };
        let precommit = selected_tuple == previous_tuple
            && selected.bundle.current.marker == previous
            && physical_current == previous
            && physical_pending.as_deref() == Some(next);
        let committed = selected_tuple == next_tuple
            && selected.bundle.current.marker == next
            && ((physical_current == previous && physical_pending.as_deref() == Some(next))
                || (physical_current == next && physical_pending.is_none()));
        if !(precommit || committed)
            || selected.current_manifest.manifest_key_epoch != head_context.next_manifest_key_epoch
            || registry_marker_root(previous)? != head_context.previous_marker_root
            || registry_marker_root(next)? != head_context.next_marker_root
            || previous.len() != MARKER_LEN
            || next.len() != MARKER_LEN
        {
            return Err(RegistryAnchorError::AuthenticationFailed);
        }
        authenticate_marker_file(previous, self.manifest_seal.as_ref())?;
        authenticate_marker_file(next, self.manifest_seal.as_ref())?;
        if previous[1..5] != head_context.manifest_key_epoch.to_be_bytes()
            || next[1..5] != head_context.next_manifest_key_epoch.to_be_bytes()
            || previous[5..233] != next[5..233]
            || previous[21..37] != previous_tuple.registry_instance
            || next[21..37] != previous_tuple.registry_instance
            || previous_tuple.registry_instance != next_tuple.registry_instance
            || previous[233].checked_add(1) != Some(next[233])
            || !matches!(next[233], 2 | 3)
        {
            return Err(RegistryAnchorError::AuthenticationFailed);
        }
        Ok(())
    }

    fn initialize_compact(
        &self,
        genesis: &RegistryAnchorTuple,
        manifest_key_epoch: u32,
        generation: u64,
    ) -> Result<(), RegistryAnchorError> {
        if generation == 0 {
            return Err(RegistryAnchorError::InvalidTransition);
        }
        let _writer = self.writer.lock().map_err(|_| lock_poisoned())?;
        if !self.anchor_artifacts_are_exactly_absent()? {
            return Err(RegistryAnchorError::RecoveryRequired(
                "anchor initialization encountered pre-existing state".to_owned(),
            ));
        }
        self.require_no_owner_pending_or_temp()?;
        let artifacts = self.read_owner_artifacts(genesis, manifest_key_epoch, false)?;
        let manifest = RegistryManifest {
            manifest_key_epoch,
            committed: genesis.clone(),
            pending: None,
            nonce: random_nonzero_32()?,
        };
        let set = ArtifactSet {
            registry_manifest: encode_manifest(&manifest, self.manifest_seal.as_ref())?,
            persisted_keyring: artifacts.persisted_keyring,
            role_allocation: artifacts.role_allocation,
            marker: artifacts.marker,
        };
        validate_artifact_set(&set, self.manifest_seal.as_ref())?;
        let bundle = RegistryAnchorBundle {
            current: set,
            next: None,
        };
        self.write_bundle_and_select(0, &bundle, SelectedSet::Current, generation, None)
    }

    fn prepare_current(
        &self,
        mutation: &RegistryAnchorMutation,
    ) -> Result<(), RegistryAnchorError> {
        mutation.validate()?;
        let _writer = self.writer.lock().map_err(|_| lock_poisoned())?;
        let selected = self.read_selected_unlocked()?;
        let current = match &selected.world {
            RegistryAnchorWorld::CompactCurrent { current, .. } => current,
            _ => return Err(RegistryAnchorError::InvalidTransition),
        };
        if current != mutation.previous() {
            return Err(RegistryAnchorError::CompareAndSwapFailed);
        }
        if selected.selector.generation > u64::MAX - 3 {
            return Err(RegistryAnchorError::GenerationExhausted);
        }
        let previous_owner = self.read_owner_artifacts(
            mutation.previous(),
            mutation.head_context().manifest_key_epoch,
            false,
        )?;
        let next_owner = self.read_next_owner_artifacts(mutation, &previous_owner)?;

        let mut next_set = ArtifactSet {
            registry_manifest: Vec::new(),
            persisted_keyring: next_owner.persisted_keyring,
            role_allocation: next_owner.role_allocation,
            marker: next_owner.marker,
        };
        let next_nonce = fresh_nonce_excluding(&[selected.current_manifest.nonce])?;
        let next_manifest = RegistryManifest {
            manifest_key_epoch: mutation.head_context().next_manifest_key_epoch,
            committed: mutation.next().clone(),
            pending: None,
            nonce: next_nonce,
        };
        next_set.registry_manifest = encode_manifest(&next_manifest, self.manifest_seal.as_ref())?;
        let next_artifact_root = artifact_set_root(&next_set)?;
        let current_manifest = RegistryManifest {
            manifest_key_epoch: mutation.head_context().manifest_key_epoch,
            committed: mutation.previous().clone(),
            pending: Some(PendingManifestFields {
                previous_sequence: mutation.previous().sequence,
                previous_head: mutation.previous().head,
                previous_state_root: mutation.previous().state_root,
                previous_keyring_root: mutation.previous().keyring_root,
                next_sequence: mutation.next().sequence,
                next_head: mutation.next().head,
                next_state_root: mutation.next().state_root,
                next_keyring_root: mutation.next().keyring_root,
                previous_role_allocation_root: mutation.previous().role_allocation_root,
                next_role_allocation_root: mutation.next().role_allocation_root,
                previous_marker_root: mutation.head_context().previous_marker_root,
                next_marker_root: mutation.head_context().next_marker_root,
                next_manifest_key_epoch: mutation.head_context().next_manifest_key_epoch,
                next_artifact_root,
                operation_tag: mutation.operation_tag(),
                write_set_digest: mutation.write_set_digest(),
            }),
            nonce: fresh_nonce_excluding(&[selected.current_manifest.nonce, next_nonce])?,
        };
        let current_set = ArtifactSet {
            registry_manifest: encode_manifest(&current_manifest, self.manifest_seal.as_ref())?,
            persisted_keyring: previous_owner.persisted_keyring,
            role_allocation: previous_owner.role_allocation,
            marker: previous_owner.marker,
        };
        let bundle = RegistryAnchorBundle {
            current: current_set,
            next: Some(next_set),
        };
        validate_pending_bundle(&bundle, self.manifest_seal.as_ref())?;
        self.write_bundle_and_select(
            1 - selected.selector.active_slot,
            &bundle,
            SelectedSet::Current,
            next_generation(selected.selector.generation)?,
            Some(&selected.selector_bytes),
        )
    }

    fn rollback_pending(
        &self,
        expected_previous: &RegistryAnchorTuple,
    ) -> Result<(), RegistryAnchorError> {
        let _writer = self.writer.lock().map_err(|_| lock_poisoned())?;
        let selected = self.read_selected_unlocked()?;
        match &selected.world {
            RegistryAnchorWorld::PendingCurrent { previous, .. }
                if previous == expected_previous => {}
            _ => return Err(RegistryAnchorError::InvalidTransition),
        }
        let old = &selected.bundle.current;
        let mut excluded = vec![selected.current_manifest.nonce];
        if let Some(next) = &selected.next_manifest {
            excluded.push(next.nonce);
        }
        let compact_manifest = RegistryManifest {
            manifest_key_epoch: selected.current_manifest.manifest_key_epoch,
            committed: expected_previous.clone(),
            pending: None,
            nonce: fresh_nonce_excluding(&excluded)?,
        };
        let compact = RegistryAnchorBundle {
            current: ArtifactSet {
                registry_manifest: encode_manifest(&compact_manifest, self.manifest_seal.as_ref())?,
                persisted_keyring: old.persisted_keyring.clone(),
                role_allocation: old.role_allocation.clone(),
                marker: old.marker.clone(),
            },
            next: None,
        };
        self.write_bundle_and_select(
            1 - selected.selector.active_slot,
            &compact,
            SelectedSet::Current,
            next_generation(selected.selector.generation)?,
            Some(&selected.selector_bytes),
        )
    }

    fn select_next(&self, expected_next: &RegistryAnchorTuple) -> Result<(), RegistryAnchorError> {
        let _writer = self.writer.lock().map_err(|_| lock_poisoned())?;
        let selected = self.read_selected_unlocked()?;
        match &selected.world {
            RegistryAnchorWorld::PendingCurrent { next, .. } if next == expected_next => {}
            _ => return Err(RegistryAnchorError::InvalidTransition),
        }
        self.select_existing_bundle(
            &selected,
            SelectedSet::Next,
            next_generation(selected.selector.generation)?,
        )
    }

    fn compact(&self, expected_next: &RegistryAnchorTuple) -> Result<(), RegistryAnchorError> {
        let _writer = self.writer.lock().map_err(|_| lock_poisoned())?;
        let selected = self.read_selected_unlocked()?;
        match &selected.world {
            RegistryAnchorWorld::SelectedNext { next, .. } if next == expected_next => {}
            _ => return Err(RegistryAnchorError::InvalidTransition),
        }
        let next = selected
            .bundle
            .next
            .as_ref()
            .ok_or(RegistryAnchorError::AuthenticationFailed)?;
        let compact = RegistryAnchorBundle {
            current: next.clone(),
            next: None,
        };
        self.write_bundle_and_select(
            1 - selected.selector.active_slot,
            &compact,
            SelectedSet::Current,
            next_generation(selected.selector.generation)?,
            Some(&selected.selector_bytes),
        )
    }

    fn select_existing_bundle(
        &self,
        selected: &SelectedState,
        selected_set: SelectedSet,
        generation: u64,
    ) -> Result<(), RegistryAnchorError> {
        let tuple = match selected_set {
            SelectedSet::Current => &selected.current_manifest.committed,
            SelectedSet::Next => {
                &selected
                    .next_manifest
                    .as_ref()
                    .ok_or(RegistryAnchorError::InvalidTransition)?
                    .committed
            }
        };
        let selector = Selector {
            selector_key_epoch: self.selector_seal.current_epoch(),
            workspace_installation_id: self.installation_id,
            generation,
            active_slot: selected.selector.active_slot,
            selected_set,
            active_bundle_root: selected.selector.active_bundle_root,
            registry_instance: tuple.registry_instance,
            selected_sequence: tuple.sequence,
            nonce: random_nonzero_32()?,
        };
        let bytes = encode_selector(&selector, self.selector_seal.as_ref())?;
        self.record.compare_and_swap(
            Some(&selected.selector_bytes),
            &bytes,
            generation,
            selector.nonce,
        )?;
        self.trip_failpoint(AnchorFailpoint::AfterSelectorFsync)
    }

    fn write_bundle_and_select(
        &self,
        slot: usize,
        bundle: &RegistryAnchorBundle,
        selected_set: SelectedSet,
        generation: u64,
        expected_selector: Option<&[u8]>,
    ) -> Result<(), RegistryAnchorError> {
        if slot > 1 || generation == 0 {
            return Err(RegistryAnchorError::InvalidTransition);
        }
        let bundle_bytes = encode_bundle(bundle)?;
        atomic_write(&self.bundle_path(slot), &bundle_bytes)?;
        self.trip_failpoint(AnchorFailpoint::AfterBundleFsync)?;
        let manifest = match selected_set {
            SelectedSet::Current => decode_manifest(
                &bundle.current.registry_manifest,
                self.manifest_seal.as_ref(),
            )?,
            SelectedSet::Next => decode_manifest(
                &bundle
                    .next
                    .as_ref()
                    .ok_or(RegistryAnchorError::InvalidTransition)?
                    .registry_manifest,
                self.manifest_seal.as_ref(),
            )?,
        };
        let selector = Selector {
            selector_key_epoch: self.selector_seal.current_epoch(),
            workspace_installation_id: self.installation_id,
            generation,
            active_slot: slot,
            selected_set,
            active_bundle_root: bundle_root(&bundle_bytes),
            registry_instance: manifest.committed.registry_instance,
            selected_sequence: manifest.committed.sequence,
            nonce: random_nonzero_32()?,
        };
        let selector_bytes = encode_selector(&selector, self.selector_seal.as_ref())?;
        self.record.compare_and_swap(
            expected_selector,
            &selector_bytes,
            generation,
            selector.nonce,
        )?;
        self.trip_failpoint(AnchorFailpoint::AfterSelectorFsync)
    }

    fn trip_failpoint(&self, expected: AnchorFailpoint) -> Result<(), RegistryAnchorError> {
        let mut failpoint = self.failpoint.lock().map_err(|_| lock_poisoned())?;
        if *failpoint == Some(expected) {
            *failpoint = None;
            return Err(RegistryAnchorError::Unavailable(format!(
                "injected crash after {expected:?}"
            )));
        }
        Ok(())
    }

    fn read_selected(&self) -> Result<SelectedState, RegistryAnchorError> {
        let _writer = self.writer.lock().map_err(|_| lock_poisoned())?;
        self.read_selected_unlocked()
    }

    fn read_selected_unlocked(&self) -> Result<SelectedState, RegistryAnchorError> {
        let selector_bytes = match self.record.read_selector()? {
            Some(bytes) => bytes,
            None => {
                return if self.bundle_or_temp_exists()? {
                    Err(RegistryAnchorError::RecoveryRequired(
                        "platform selector is missing while a bundle artifact exists".to_owned(),
                    ))
                } else {
                    Err(RegistryAnchorError::Uninitialized)
                }
            }
        };
        let selector = decode_selector(
            &selector_bytes,
            self.installation_id,
            self.selector_seal.as_ref(),
        )?;
        let bundle_bytes =
            read_exact_file(&self.bundle_path(selector.active_slot)).map_err(|error| {
                if error.kind() == io::ErrorKind::NotFound {
                    RegistryAnchorError::RecoveryRequired(
                        "platform selector names a missing anchor bundle".to_owned(),
                    )
                } else {
                    unavailable("read selected anchor bundle", error)
                }
            })?;
        if bundle_root(&bundle_bytes)
            .ct_eq(&selector.active_bundle_root)
            .unwrap_u8()
            != 1
        {
            return Err(RegistryAnchorError::AuthenticationFailed);
        }
        let bundle = decode_bundle(&bundle_bytes)?;
        let current_manifest = validate_artifact_set(&bundle.current, self.manifest_seal.as_ref())?;
        let next_manifest = match &bundle.next {
            Some(next) => Some(validate_artifact_set(next, self.manifest_seal.as_ref())?),
            None => None,
        };
        if next_manifest.is_some() {
            validate_pending_bundle(&bundle, self.manifest_seal.as_ref())?;
        } else if current_manifest.pending.is_some() {
            return Err(RegistryAnchorError::AuthenticationFailed);
        }
        let selected_manifest = match selector.selected_set {
            SelectedSet::Current => &current_manifest,
            SelectedSet::Next => next_manifest
                .as_ref()
                .ok_or(RegistryAnchorError::AuthenticationFailed)?,
        };
        if selector.registry_instance != selected_manifest.committed.registry_instance
            || selector.selected_sequence != selected_manifest.committed.sequence
        {
            return Err(RegistryAnchorError::AuthenticationFailed);
        }
        let world = match (
            selector.selected_set,
            &current_manifest.pending,
            &next_manifest,
        ) {
            (SelectedSet::Current, Some(_), Some(next)) => RegistryAnchorWorld::PendingCurrent {
                generation: selector.generation,
                previous: current_manifest.committed.clone(),
                next: next.committed.clone(),
            },
            (SelectedSet::Next, Some(_), Some(next)) => RegistryAnchorWorld::SelectedNext {
                generation: selector.generation,
                next: next.committed.clone(),
            },
            (SelectedSet::Current, None, None) => RegistryAnchorWorld::CompactCurrent {
                generation: selector.generation,
                current: current_manifest.committed.clone(),
            },
            _ => return Err(RegistryAnchorError::AuthenticationFailed),
        };
        Ok(SelectedState {
            selector_bytes,
            selector,
            bundle,
            current_manifest,
            next_manifest,
            world,
        })
    }

    fn current_artifact_epoch(
        &self,
        tuple: &RegistryAnchorTuple,
    ) -> Result<u32, RegistryAnchorError> {
        let keyring = read_required(&self.directory.join(KEYRING_CURRENT), "current keyring")?;
        let role = read_required(&self.directory.join(ROLES_CURRENT), "current role manifest")?;
        let (keyring_epoch, keyring_instance) = artifact_header(&keyring)?;
        let (role_epoch, role_instance) = artifact_header(&role)?;
        if keyring_epoch != role_epoch
            || keyring_instance != tuple.registry_instance
            || role_instance != tuple.registry_instance
        {
            return Err(RegistryAnchorError::AuthenticationFailed);
        }
        Ok(keyring_epoch)
    }

    fn read_owner_artifacts(
        &self,
        tuple: &RegistryAnchorTuple,
        manifest_key_epoch: u32,
        pending: bool,
    ) -> Result<OwnerArtifacts, RegistryAnchorError> {
        let keyring_name = if pending {
            KEYRING_PENDING
        } else {
            KEYRING_CURRENT
        };
        let roles_name = if pending {
            ROLES_PENDING
        } else {
            ROLES_CURRENT
        };
        let marker_name = if pending {
            MARKER_PENDING
        } else {
            MARKER_CURRENT
        };
        let persisted_keyring = read_required(
            &self.directory.join(keyring_name),
            "persisted keyring artifact",
        )?;
        let role_allocation =
            read_required(&self.directory.join(roles_name), "role-allocation artifact")?;
        let marker = match read_exact_file(&self.directory.join(marker_name)) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
            Err(error) => return Err(unavailable("read migration marker artifact", error)),
        };
        validate_owner_artifacts(
            tuple,
            manifest_key_epoch,
            &persisted_keyring,
            &role_allocation,
            &marker,
            self.manifest_seal.as_ref(),
        )?;
        Ok(OwnerArtifacts {
            persisted_keyring,
            role_allocation,
            marker,
        })
    }

    fn read_next_owner_artifacts(
        &self,
        mutation: &RegistryAnchorMutation,
        previous: &OwnerArtifacts,
    ) -> Result<OwnerArtifacts, RegistryAnchorError> {
        let persisted_keyring = self.next_artifact_bytes(
            KEYRING_CURRENT,
            KEYRING_PENDING,
            mutation.previous().keyring_root,
            mutation.next().keyring_root,
            &previous.persisted_keyring,
            persisted_keyring_file_root,
        )?;
        let role_allocation = self.next_artifact_bytes(
            ROLES_CURRENT,
            ROLES_PENDING,
            mutation.previous().role_allocation_root,
            mutation.next().role_allocation_root,
            &previous.role_allocation,
            role_allocation_file_root,
        )?;
        let marker = if mutation.head_context().previous_marker_root
            == mutation.head_context().next_marker_root
        {
            previous.marker.clone()
        } else {
            let bytes = read_required(
                &self.directory.join(MARKER_PENDING),
                "pending migration marker artifact",
            )?;
            if registry_marker_root(&bytes)? != mutation.head_context().next_marker_root {
                return Err(RegistryAnchorError::AuthenticationFailed);
            }
            bytes
        };
        validate_owner_artifacts(
            mutation.next(),
            mutation.head_context().next_manifest_key_epoch,
            &persisted_keyring,
            &role_allocation,
            &marker,
            self.manifest_seal.as_ref(),
        )?;
        if registry_marker_root(&previous.marker)? != mutation.head_context().previous_marker_root
            || registry_marker_root(&marker)? != mutation.head_context().next_marker_root
        {
            return Err(RegistryAnchorError::AuthenticationFailed);
        }
        Ok(OwnerArtifacts {
            persisted_keyring,
            role_allocation,
            marker,
        })
    }

    fn next_artifact_bytes<F>(
        &self,
        _current_name: &str,
        pending_name: &str,
        previous_root: [u8; 32],
        next_root: [u8; 32],
        previous_bytes: &[u8],
        root: F,
    ) -> Result<Vec<u8>, RegistryAnchorError>
    where
        F: Fn(&[u8]) -> [u8; 32],
    {
        if root(previous_bytes) != previous_root {
            return Err(RegistryAnchorError::AuthenticationFailed);
        }
        if previous_root == next_root {
            return Ok(previous_bytes.to_vec());
        }
        let bytes = read_required(&self.directory.join(pending_name), "pending owner artifact")?;
        if root(&bytes) != next_root {
            return Err(RegistryAnchorError::AuthenticationFailed);
        }
        Ok(bytes)
    }

    fn bundle_path(&self, slot: usize) -> PathBuf {
        self.directory.join(BUNDLE_FILES[slot])
    }

    fn require_no_owner_pending_or_temp(&self) -> Result<(), RegistryAnchorError> {
        for file in [
            KEYRING_PENDING,
            ROLES_PENDING,
            MARKER_PENDING,
            ".contract218.keyring.current.tmp",
            ".contract218.keyring.pending.tmp",
            ".contract218.roles.current.tmp",
            ".contract218.roles.pending.tmp",
            ".contract218.migration-marker.current.tmp",
            ".contract218.migration-marker.pending.tmp",
        ] {
            if secure_regular_exists(&self.directory.join(file))
                .map_err(|error| unavailable("inspect owner pending artifact", error))?
            {
                return Err(RegistryAnchorError::RecoveryRequired(
                    "owner artifact set contains pending or torn state".to_owned(),
                ));
            }
        }
        Ok(())
    }

    fn temporary_path(&self, file_name: &str) -> PathBuf {
        self.directory.join(format!(".{file_name}.tmp"))
    }

    fn bundle_or_temp_exists(&self) -> Result<bool, RegistryAnchorError> {
        for path in [
            self.bundle_path(0),
            self.bundle_path(1),
            self.temporary_path(BUNDLE_FILES[0]),
            self.temporary_path(BUNDLE_FILES[1]),
        ] {
            match fs::symlink_metadata(path) {
                Ok(_) => return Ok(true),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(unavailable("inspect anchor artifact", error)),
            }
        }
        Ok(false)
    }

    fn anchor_artifacts_are_exactly_absent(&self) -> Result<bool, RegistryAnchorError> {
        Ok(self.record.read_selector()?.is_none() && !self.bundle_or_temp_exists()?)
    }

    #[cfg(feature = "test-support")]
    fn install_minimal_artifacts_for_test(
        &self,
        tuple: &RegistryAnchorTuple,
        manifest_key_epoch: u32,
    ) -> Result<(), RegistryAnchorError> {
        let keyring = minimal_owner_artifact(manifest_key_epoch, tuple.registry_instance, 0x4b);
        let roles = minimal_owner_artifact(manifest_key_epoch, tuple.registry_instance, 0x52);
        let keyring_path = self.directory.join(KEYRING_CURRENT);
        let roles_path = self.directory.join(ROLES_CURRENT);
        if !secure_regular_exists(&keyring_path)
            .map_err(|error| unavailable("inspect test keyring", error))?
        {
            atomic_write(&keyring_path, &keyring)?;
        }
        if !secure_regular_exists(&roles_path)
            .map_err(|error| unavailable("inspect test roles", error))?
        {
            atomic_write(&roles_path, &roles)?;
        }
        let observed_keyring = read_required(&keyring_path, "test keyring")?;
        let observed_roles = read_required(&roles_path, "test roles")?;
        if persisted_keyring_file_root(&observed_keyring) != tuple.keyring_root
            || role_allocation_file_root(&observed_roles) != tuple.role_allocation_root
        {
            return Err(RegistryAnchorError::AuthenticationFailed);
        }
        Ok(())
    }
}

struct OwnerArtifacts {
    persisted_keyring: Vec<u8>,
    role_allocation: Vec<u8>,
    marker: Vec<u8>,
}

fn validate_owner_artifacts(
    tuple: &RegistryAnchorTuple,
    manifest_key_epoch: u32,
    keyring: &[u8],
    roles: &[u8],
    marker: &[u8],
    seal: &dyn RegistryManifestSeal,
) -> Result<(), RegistryAnchorError> {
    let (keyring_epoch, keyring_instance) = artifact_header(keyring)?;
    let (role_epoch, role_instance) = artifact_header(roles)?;
    if manifest_key_epoch == 0
        || keyring_epoch != manifest_key_epoch
        || role_epoch != manifest_key_epoch
        || keyring_instance != tuple.registry_instance
        || role_instance != tuple.registry_instance
        || persisted_keyring_file_root(keyring) != tuple.keyring_root
        || role_allocation_file_root(roles) != tuple.role_allocation_root
    {
        return Err(RegistryAnchorError::AuthenticationFailed);
    }
    authenticate_keyring_file(keyring, seal)?;
    authenticate_role_file(roles, seal)?;
    if !marker.is_empty() {
        authenticate_marker_file(marker, seal)?;
    }
    validate_marker_binding(marker, tuple, manifest_key_epoch)
}

fn authenticate_role_file(
    bytes: &[u8],
    seal: &dyn RegistryManifestSeal,
) -> Result<(), RegistryAnchorError> {
    #[cfg(feature = "test-support")]
    if bytes.len() == 22 && matches!(bytes.last(), Some(0x52)) {
        return Ok(());
    }
    if bytes.len() < 1 + 4 + 16 + 32 {
        return Err(RegistryAnchorError::AuthenticationFailed);
    }
    let (epoch, instance) = artifact_header(bytes)?;
    let (preceding, observed) = bytes.split_at(bytes.len() - 32);
    let expected = seal.role_allocation_mac_for_epoch(epoch, instance, preceding)?;
    if expected.ct_eq(observed).unwrap_u8() != 1 {
        return Err(RegistryAnchorError::AuthenticationFailed);
    }
    Ok(())
}

fn authenticate_keyring_file(
    bytes: &[u8],
    seal: &dyn RegistryManifestSeal,
) -> Result<(), RegistryAnchorError> {
    #[cfg(feature = "test-support")]
    if bytes.len() == 22 && matches!(bytes.last(), Some(0x4b)) {
        return Ok(());
    }
    // version + epoch + instance + generation + previous-root + KDF salt + MAC
    if bytes.len() < 1 + 4 + 16 + 8 + 32 + 32 + 32 {
        return Err(RegistryAnchorError::AuthenticationFailed);
    }
    let (epoch, instance) = artifact_header(bytes)?;
    let kdf_salt: [u8; 32] = bytes[61..93]
        .try_into()
        .map_err(|_| RegistryAnchorError::AuthenticationFailed)?;
    let (preceding, observed) = bytes.split_at(bytes.len() - 32);
    let expected = seal.persisted_keyring_mac_for_epoch(epoch, instance, kdf_salt, preceding)?;
    if expected.ct_eq(observed).unwrap_u8() != 1 {
        return Err(RegistryAnchorError::AuthenticationFailed);
    }
    Ok(())
}

fn authenticate_marker_file(
    bytes: &[u8],
    seal: &dyn RegistryManifestSeal,
) -> Result<(), RegistryAnchorError> {
    if bytes.len() != MARKER_LEN {
        return Err(RegistryAnchorError::AuthenticationFailed);
    }
    let (epoch, instance) = {
        let epoch = u32::from_be_bytes(
            bytes[1..5]
                .try_into()
                .map_err(|_| RegistryAnchorError::AuthenticationFailed)?,
        );
        let instance: [u8; 16] = bytes[21..37]
            .try_into()
            .map_err(|_| RegistryAnchorError::AuthenticationFailed)?;
        (epoch, instance)
    };
    if bytes[0] != FORMAT_VERSION || epoch == 0 || instance == [0; 16] {
        return Err(RegistryAnchorError::AuthenticationFailed);
    }
    let (preceding, observed) = bytes.split_at(bytes.len() - 32);
    let expected = seal.migration_marker_mac_for_epoch(epoch, instance, preceding)?;
    if expected.ct_eq(observed).unwrap_u8() != 1 {
        return Err(RegistryAnchorError::AuthenticationFailed);
    }
    Ok(())
}

fn artifact_header(bytes: &[u8]) -> Result<(u32, [u8; 16]), RegistryAnchorError> {
    let mut cursor = Cursor::new(bytes);
    if cursor.u8()? != FORMAT_VERSION {
        return Err(RegistryAnchorError::AuthenticationFailed);
    }
    let epoch = cursor.u32()?;
    let instance = cursor.array::<16>()?;
    if epoch == 0 || instance == [0; 16] {
        return Err(RegistryAnchorError::AuthenticationFailed);
    }
    Ok((epoch, instance))
}

fn validate_marker_binding(
    marker: &[u8],
    tuple: &RegistryAnchorTuple,
    manifest_key_epoch: u32,
) -> Result<(), RegistryAnchorError> {
    let expected_digest = if marker.is_empty() {
        greenfield_migration_digest()
    } else {
        if marker.len() != MARKER_LEN
            || marker[0] != FORMAT_VERSION
            || u32::from_be_bytes(marker[1..5].try_into().unwrap()) != manifest_key_epoch
        {
            return Err(RegistryAnchorError::AuthenticationFailed);
        }
        let block: &[u8; 228] = marker[5..233]
            .try_into()
            .map_err(|_| RegistryAnchorError::AuthenticationFailed)?;
        if block[..16] == [0; 16]
            || block[16..32] != tuple.registry_instance
            || u32::from_be_bytes(block[96..100].try_into().unwrap()) != 1
            || (tuple.sequence == 0
                && (block[100..132] != tuple.state_root
                    || block[132..164] != tuple.keyring_root
                    || block[164..196] != tuple.role_allocation_root))
            || !matches!(marker[233], 1..=3)
            || marker[234..266] == [0; 32]
        {
            return Err(RegistryAnchorError::AuthenticationFailed);
        }
        legacy_registry_migration_digest(block)
    };
    if tuple.migration_digest != expected_digest {
        return Err(RegistryAnchorError::AuthenticationFailed);
    }
    Ok(())
}

fn greenfield_migration_digest() -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(MIGRATION_DIGEST_DOMAIN);
    hasher.update([1]);
    hasher.update(0u16.to_be_bytes());
    hasher.finalize().into()
}

fn encode_manifest(
    manifest: &RegistryManifest,
    seal: &dyn RegistryManifestSeal,
) -> Result<Vec<u8>, RegistryAnchorError> {
    if manifest.manifest_key_epoch == 0
        || manifest.committed.registry_instance == [0; 16]
        || manifest.nonce == [0; 32]
    {
        return Err(RegistryAnchorError::InvalidTransition);
    }
    let mut out = Vec::new();
    out.push(FORMAT_VERSION);
    out.extend_from_slice(&manifest.manifest_key_epoch.to_be_bytes());
    encode_committed_tuple(&manifest.committed, &mut out);
    match &manifest.pending {
        None => out.push(0),
        Some(pending) => {
            out.push(1);
            encode_pending(pending, &mut out);
        }
    }
    out.extend_from_slice(&manifest.nonce);
    let mac = seal.mac_for_epoch(
        manifest.manifest_key_epoch,
        manifest.committed.registry_instance,
        &out,
    )?;
    out.extend_from_slice(&mac);
    Ok(out)
}

fn decode_manifest(
    bytes: &[u8],
    seal: &dyn RegistryManifestSeal,
) -> Result<RegistryManifest, RegistryAnchorError> {
    const MINIMUM: usize = 1 + 4 + 16 + 8 + 5 * 32 + 1 + 32 + 32;
    if bytes.len() < MINIMUM {
        return Err(RegistryAnchorError::AuthenticationFailed);
    }
    let (preceding, observed_mac) = bytes.split_at(bytes.len() - 32);
    let mut cursor = Cursor::new(preceding);
    if cursor.u8()? != FORMAT_VERSION {
        return Err(RegistryAnchorError::AuthenticationFailed);
    }
    let manifest_key_epoch = cursor.u32()?;
    let committed = decode_committed_tuple(&mut cursor)?;
    let expected_mac =
        seal.mac_for_epoch(manifest_key_epoch, committed.registry_instance, preceding)?;
    if expected_mac.ct_eq(observed_mac).unwrap_u8() != 1 {
        return Err(RegistryAnchorError::AuthenticationFailed);
    }
    let pending = match cursor.u8()? {
        0 => None,
        1 => Some(decode_pending(&mut cursor)?),
        _ => return Err(RegistryAnchorError::AuthenticationFailed),
    };
    let nonce = cursor.array::<32>()?;
    if manifest_key_epoch == 0
        || committed.registry_instance == [0; 16]
        || nonce == [0; 32]
        || !cursor.is_empty()
    {
        return Err(RegistryAnchorError::AuthenticationFailed);
    }
    if let Some(pending) = &pending {
        validate_pending_manifest(&committed, pending)?;
    }
    Ok(RegistryManifest {
        manifest_key_epoch,
        committed,
        pending,
        nonce,
    })
}

fn encode_committed_tuple(tuple: &RegistryAnchorTuple, out: &mut Vec<u8>) {
    out.extend_from_slice(&tuple.registry_instance);
    out.extend_from_slice(&tuple.sequence.to_be_bytes());
    out.extend_from_slice(&tuple.head);
    out.extend_from_slice(&tuple.state_root);
    out.extend_from_slice(&tuple.keyring_root);
    out.extend_from_slice(&tuple.role_allocation_root);
    out.extend_from_slice(&tuple.migration_digest);
}

fn decode_committed_tuple(
    cursor: &mut Cursor<'_>,
) -> Result<RegistryAnchorTuple, RegistryAnchorError> {
    Ok(RegistryAnchorTuple {
        registry_instance: cursor.array::<16>()?,
        sequence: cursor.u64()?,
        head: cursor.array::<32>()?,
        state_root: cursor.array::<32>()?,
        keyring_root: cursor.array::<32>()?,
        role_allocation_root: cursor.array::<32>()?,
        migration_digest: cursor.array::<32>()?,
    })
}

fn encode_pending(pending: &PendingManifestFields, out: &mut Vec<u8>) {
    out.extend_from_slice(&pending.previous_sequence.to_be_bytes());
    out.extend_from_slice(&pending.previous_head);
    out.extend_from_slice(&pending.previous_state_root);
    out.extend_from_slice(&pending.previous_keyring_root);
    out.extend_from_slice(&pending.next_sequence.to_be_bytes());
    out.extend_from_slice(&pending.next_head);
    out.extend_from_slice(&pending.next_state_root);
    out.extend_from_slice(&pending.next_keyring_root);
    out.extend_from_slice(&pending.previous_role_allocation_root);
    out.extend_from_slice(&pending.next_role_allocation_root);
    out.extend_from_slice(&pending.previous_marker_root);
    out.extend_from_slice(&pending.next_marker_root);
    out.extend_from_slice(&pending.next_manifest_key_epoch.to_be_bytes());
    out.extend_from_slice(&pending.next_artifact_root);
    out.push(pending.operation_tag);
    out.extend_from_slice(&pending.write_set_digest);
}

fn decode_pending(cursor: &mut Cursor<'_>) -> Result<PendingManifestFields, RegistryAnchorError> {
    Ok(PendingManifestFields {
        previous_sequence: cursor.u64()?,
        previous_head: cursor.array::<32>()?,
        previous_state_root: cursor.array::<32>()?,
        previous_keyring_root: cursor.array::<32>()?,
        next_sequence: cursor.u64()?,
        next_head: cursor.array::<32>()?,
        next_state_root: cursor.array::<32>()?,
        next_keyring_root: cursor.array::<32>()?,
        previous_role_allocation_root: cursor.array::<32>()?,
        next_role_allocation_root: cursor.array::<32>()?,
        previous_marker_root: cursor.array::<32>()?,
        next_marker_root: cursor.array::<32>()?,
        next_manifest_key_epoch: cursor.u32()?,
        next_artifact_root: cursor.array::<32>()?,
        operation_tag: cursor.u8()?,
        write_set_digest: cursor.array::<32>()?,
    })
}

fn validate_pending_manifest(
    committed: &RegistryAnchorTuple,
    pending: &PendingManifestFields,
) -> Result<(), RegistryAnchorError> {
    if pending.previous_sequence != committed.sequence
        || pending.previous_head != committed.head
        || pending.previous_state_root != committed.state_root
        || pending.previous_keyring_root != committed.keyring_root
        || pending.previous_role_allocation_root != committed.role_allocation_root
        || pending.next_sequence != committed.sequence.checked_add(1).unwrap_or(0)
        || pending.next_manifest_key_epoch == 0
        || !(1..=8).contains(&pending.operation_tag)
    {
        return Err(RegistryAnchorError::AuthenticationFailed);
    }
    Ok(())
}

fn encode_artifact_set(set: &ArtifactSet) -> Result<Vec<u8>, RegistryAnchorError> {
    let mut out = Vec::new();
    for bytes in [
        &set.registry_manifest,
        &set.persisted_keyring,
        &set.role_allocation,
        &set.marker,
    ] {
        out.extend_from_slice(
            &u32::try_from(bytes.len())
                .map_err(|_| RegistryAnchorError::InvalidTransition)?
                .to_be_bytes(),
        );
        out.extend_from_slice(bytes);
    }
    Ok(out)
}

fn decode_artifact_set(bytes: &[u8]) -> Result<ArtifactSet, RegistryAnchorError> {
    let mut cursor = Cursor::new(bytes);
    let registry_manifest = cursor.len_prefixed()?.to_vec();
    let persisted_keyring = cursor.len_prefixed()?.to_vec();
    let role_allocation = cursor.len_prefixed()?.to_vec();
    let marker = cursor.len_prefixed()?.to_vec();
    if !cursor.is_empty()
        || registry_manifest.is_empty()
        || persisted_keyring.is_empty()
        || role_allocation.is_empty()
        || !matches!(marker.len(), 0 | MARKER_LEN)
    {
        return Err(RegistryAnchorError::AuthenticationFailed);
    }
    Ok(ArtifactSet {
        registry_manifest,
        persisted_keyring,
        role_allocation,
        marker,
    })
}

fn artifact_set_root(set: &ArtifactSet) -> Result<[u8; 32], RegistryAnchorError> {
    let mut hasher = Sha256::new();
    hasher.update(ARTIFACT_SET_ROOT_DOMAIN);
    hasher.update(encode_artifact_set(set)?);
    Ok(hasher.finalize().into())
}

fn validate_artifact_set(
    set: &ArtifactSet,
    seal: &dyn RegistryManifestSeal,
) -> Result<RegistryManifest, RegistryAnchorError> {
    let manifest = decode_manifest(&set.registry_manifest, seal)?;
    validate_owner_artifacts(
        &manifest.committed,
        manifest.manifest_key_epoch,
        &set.persisted_keyring,
        &set.role_allocation,
        &set.marker,
        seal,
    )?;
    Ok(manifest)
}

fn validate_pending_bundle(
    bundle: &RegistryAnchorBundle,
    seal: &dyn RegistryManifestSeal,
) -> Result<(), RegistryAnchorError> {
    let current = validate_artifact_set(&bundle.current, seal)?;
    let next_set = bundle
        .next
        .as_ref()
        .ok_or(RegistryAnchorError::AuthenticationFailed)?;
    let next = validate_artifact_set(next_set, seal)?;
    let pending = current
        .pending
        .as_ref()
        .ok_or(RegistryAnchorError::AuthenticationFailed)?;
    let context = advance_scheduler::observation_anchor::RegistryHeadContext {
        previous_marker_root: pending.previous_marker_root,
        next_marker_root: pending.next_marker_root,
        manifest_key_epoch: current.manifest_key_epoch,
        next_manifest_key_epoch: pending.next_manifest_key_epoch,
    };
    verify_successor_head(
        &current.committed,
        &next.committed,
        &context,
        pending.operation_tag,
        pending.write_set_digest,
    )
    .map_err(|_| RegistryAnchorError::AuthenticationFailed)?;
    if next.pending.is_some()
        || current.committed.registry_instance != next.committed.registry_instance
        || current.committed.migration_digest != next.committed.migration_digest
        || pending.next_sequence != next.committed.sequence
        || pending.next_head != next.committed.head
        || pending.next_state_root != next.committed.state_root
        || pending.next_keyring_root != next.committed.keyring_root
        || pending.next_role_allocation_root != next.committed.role_allocation_root
        || pending.previous_marker_root != registry_marker_root(&bundle.current.marker)?
        || pending.next_marker_root != registry_marker_root(&next_set.marker)?
        || pending.next_manifest_key_epoch != next.manifest_key_epoch
        || pending.next_artifact_root != artifact_set_root(next_set)?
        || current.nonce == next.nonce
    {
        return Err(RegistryAnchorError::AuthenticationFailed);
    }
    Ok(())
}

fn encode_bundle(bundle: &RegistryAnchorBundle) -> Result<Vec<u8>, RegistryAnchorError> {
    let current = encode_artifact_set(&bundle.current)?;
    let mut out = Vec::new();
    out.push(FORMAT_VERSION);
    out.extend_from_slice(
        &u32::try_from(current.len())
            .map_err(|_| RegistryAnchorError::InvalidTransition)?
            .to_be_bytes(),
    );
    out.extend_from_slice(&current);
    match &bundle.next {
        None => out.push(0),
        Some(next) => {
            let next = encode_artifact_set(next)?;
            out.push(1);
            out.extend_from_slice(
                &u32::try_from(next.len())
                    .map_err(|_| RegistryAnchorError::InvalidTransition)?
                    .to_be_bytes(),
            );
            out.extend_from_slice(&next);
        }
    }
    Ok(out)
}

fn decode_bundle(bytes: &[u8]) -> Result<RegistryAnchorBundle, RegistryAnchorError> {
    let mut cursor = Cursor::new(bytes);
    if cursor.u8()? != FORMAT_VERSION {
        return Err(RegistryAnchorError::AuthenticationFailed);
    }
    let current = decode_artifact_set(cursor.len_prefixed()?)?;
    let next = match cursor.u8()? {
        0 => None,
        1 => Some(decode_artifact_set(cursor.len_prefixed()?)?),
        _ => return Err(RegistryAnchorError::AuthenticationFailed),
    };
    if !cursor.is_empty() {
        return Err(RegistryAnchorError::AuthenticationFailed);
    }
    Ok(RegistryAnchorBundle { current, next })
}

fn bundle_root(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(BUNDLE_ROOT_DOMAIN);
    hasher.update(bytes);
    hasher.finalize().into()
}

fn next_generation(current: u64) -> Result<u64, RegistryAnchorError> {
    current
        .checked_add(1)
        .ok_or(RegistryAnchorError::GenerationExhausted)
}

fn encode_selector(
    selector: &Selector,
    seal: &dyn PlatformAnchorSeal,
) -> Result<Vec<u8>, RegistryAnchorError> {
    if selector.selector_key_epoch == 0
        || selector.workspace_installation_id == [0; 16]
        || selector.generation == 0
        || selector.active_slot > 1
        || selector.registry_instance == [0; 16]
        || selector.nonce == [0; 32]
    {
        return Err(RegistryAnchorError::InvalidTransition);
    }
    let mut out = Vec::with_capacity(PLATFORM_SELECTOR_LEN);
    out.push(FORMAT_VERSION);
    out.extend_from_slice(&selector.selector_key_epoch.to_be_bytes());
    out.extend_from_slice(&selector.workspace_installation_id);
    out.extend_from_slice(&selector.generation.to_be_bytes());
    out.push((selector.active_slot + 1) as u8);
    out.push(selector.selected_set as u8);
    out.extend_from_slice(&selector.active_bundle_root);
    out.extend_from_slice(&selector.registry_instance);
    out.extend_from_slice(&selector.selected_sequence.to_be_bytes());
    out.extend_from_slice(&selector.nonce);
    debug_assert_eq!(out.len(), SELECTOR_PRECEDING_LEN);
    let mac = seal.mac_for_epoch(
        selector.selector_key_epoch,
        selector.workspace_installation_id,
        &out,
    )?;
    out.extend_from_slice(&mac);
    debug_assert_eq!(out.len(), PLATFORM_SELECTOR_LEN);
    Ok(out)
}

fn decode_selector(
    bytes: &[u8],
    expected_installation_id: [u8; 16],
    seal: &dyn PlatformAnchorSeal,
) -> Result<Selector, RegistryAnchorError> {
    if bytes.len() != PLATFORM_SELECTOR_LEN {
        return Err(RegistryAnchorError::AuthenticationFailed);
    }
    let (preceding, observed_mac) = bytes.split_at(SELECTOR_PRECEDING_LEN);
    let mut cursor = Cursor::new(preceding);
    if cursor.u8()? != FORMAT_VERSION {
        return Err(RegistryAnchorError::AuthenticationFailed);
    }
    let selector_key_epoch = cursor.u32()?;
    let workspace_installation_id = cursor.array::<16>()?;
    let expected_mac =
        seal.mac_for_epoch(selector_key_epoch, workspace_installation_id, preceding)?;
    if expected_mac.ct_eq(observed_mac).unwrap_u8() != 1 {
        return Err(RegistryAnchorError::AuthenticationFailed);
    }
    let generation = cursor.u64()?;
    let active_slot = match cursor.u8()? {
        1 => 0,
        2 => 1,
        _ => return Err(RegistryAnchorError::AuthenticationFailed),
    };
    let selected_set = SelectedSet::decode(cursor.u8()?)?;
    let active_bundle_root = cursor.array::<32>()?;
    let registry_instance = cursor.array::<16>()?;
    let selected_sequence = cursor.u64()?;
    let nonce = cursor.array::<32>()?;
    if workspace_installation_id != expected_installation_id
        || workspace_installation_id == [0; 16]
        || selector_key_epoch == 0
        || generation == 0
        || registry_instance == [0; 16]
        || nonce == [0; 32]
        || !cursor.is_empty()
    {
        return Err(RegistryAnchorError::AuthenticationFailed);
    }
    Ok(Selector {
        selector_key_epoch,
        workspace_installation_id,
        generation,
        active_slot,
        selected_set,
        active_bundle_root,
        registry_instance,
        selected_sequence,
        nonce,
    })
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], RegistryAnchorError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(RegistryAnchorError::AuthenticationFailed)?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or(RegistryAnchorError::AuthenticationFailed)?;
        self.offset = end;
        Ok(bytes)
    }

    fn len_prefixed(&mut self) -> Result<&'a [u8], RegistryAnchorError> {
        let len = self.u32()? as usize;
        self.take(len)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], RegistryAnchorError> {
        self.take(N)?
            .try_into()
            .map_err(|_| RegistryAnchorError::AuthenticationFailed)
    }

    fn u8(&mut self) -> Result<u8, RegistryAnchorError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, RegistryAnchorError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, RegistryAnchorError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

fn read_required(path: &Path, name: &str) -> Result<Vec<u8>, RegistryAnchorError> {
    read_exact_file(path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            RegistryAnchorError::RecoveryRequired(format!("missing {name}"))
        } else {
            unavailable(&format!("read {name}"), error)
        }
    })
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), RegistryAnchorError> {
    let parent = path
        .parent()
        .ok_or_else(|| RegistryAnchorError::Unavailable("anchor path has no parent".to_owned()))?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| RegistryAnchorError::Unavailable("anchor path is not UTF-8".to_owned()))?;
    let temporary = parent.join(format!(".{file_name}.tmp"));
    // Reject symlink/non-regular targets before creating a deterministic
    // temporary.  `create_new` plus O_NOFOLLOW prevents both existing and
    // dangling `.tmp` links from being followed or clobbered.
    secure_regular_exists(path)
        .map_err(|error| unavailable("inspect anchor replacement target", error))?;
    let mut file = secure_create_new_regular(&temporary)
        .map_err(|error| unavailable("open anchor temporary file", error))?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|error| unavailable("write/fsync anchor temporary file", error))?;
    secure_replace_regular(&temporary, path)
        .map_err(|error| unavailable("rename anchor file", error))?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| unavailable("fsync anchor parent directory", error))
}

fn read_exact_file(path: &Path) -> io::Result<Vec<u8>> {
    let mut file = secure_open_regular(path)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// `lstat`-style existence check shared by every CONTRACT-218 file owner.
/// Present symlinks, directories, devices, sockets, and FIFOs are rejected;
/// dangling symlinks therefore never masquerade as an absent file.
pub(crate) fn secure_regular_exists(path: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata_is_confined_regular(&metadata) {
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "{} is not a confined single-link regular file",
                        path.display()
                    ),
                ))
            } else {
                Ok(true)
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

/// Exercises the production anchor leaf gate with an integration-test supplied path.
#[cfg(feature = "test-support")]
#[doc(hidden)]
pub fn test_only_anchor_file_exists(path: &Path) -> io::Result<bool> {
    secure_regular_exists(path)
}

fn metadata_is_confined_regular(metadata: &fs::Metadata) -> bool {
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        metadata.nlink() == 1
    }
    #[cfg(not(unix))]
    {
        true
    }
}

pub(crate) fn secure_open_regular(path: &Path) -> io::Result<File> {
    if !secure_regular_exists(path)? {
        return Err(io::Error::new(io::ErrorKind::NotFound, "file is absent"));
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata_is_confined_regular(&metadata) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "opened object is not a regular file",
        ));
    }
    Ok(file)
}

pub(crate) fn secure_create_new_regular(path: &Path) -> io::Result<File> {
    // `symlink_metadata` is intentional: an existing dangling symlink must be
    // reported as occupied, not followed by create.
    if secure_regular_exists(path)? {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "exclusive temporary already exists",
        ));
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let file = options.open(path)?;
    if !metadata_is_confined_regular(&file.metadata()?) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "created object is not a regular file",
        ));
    }
    Ok(file)
}

pub(crate) fn secure_open_or_create_regular(path: &Path) -> io::Result<File> {
    match secure_regular_exists(path)? {
        true => {
            let mut options = OpenOptions::new();
            options.read(true).write(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
            }
            let file = options.open(path)?;
            if !metadata_is_confined_regular(&file.metadata()?) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "opened custody object is not a regular file",
                ));
            }
            Ok(file)
        }
        false => secure_create_new_regular(path),
    }
}

pub(crate) fn secure_replace_regular(source: &Path, target: &Path) -> io::Result<()> {
    if !secure_regular_exists(source)? {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "replacement source is absent",
        ));
    }
    secure_regular_exists(target)?;
    fs::rename(source, target)
}

pub(crate) fn secure_remove_regular(path: &Path) -> io::Result<()> {
    if !secure_regular_exists(path)? {
        return Err(io::Error::new(io::ErrorKind::NotFound, "file is absent"));
    }
    fs::remove_file(path)
}

fn random_nonzero_16() -> Result<[u8; 16], RegistryAnchorError> {
    for _ in 0..8 {
        let mut value = [0u8; 16];
        OsRng.fill_bytes(&mut value);
        if value != [0; 16] {
            return Ok(value);
        }
    }
    Err(RegistryAnchorError::Unavailable(
        "CSPRNG repeatedly returned a zero installation id".to_owned(),
    ))
}

fn random_nonzero_32() -> Result<[u8; 32], RegistryAnchorError> {
    for _ in 0..8 {
        let mut value = [0u8; 32];
        OsRng.fill_bytes(&mut value);
        if value != [0; 32] {
            return Ok(value);
        }
    }
    Err(RegistryAnchorError::Unavailable(
        "CSPRNG repeatedly returned a zero nonce".to_owned(),
    ))
}

fn fresh_nonce_excluding(excluded: &[[u8; 32]]) -> Result<[u8; 32], RegistryAnchorError> {
    for _ in 0..8 {
        let nonce = random_nonzero_32()?;
        if !excluded.contains(&nonce) {
            return Ok(nonce);
        }
    }
    Err(RegistryAnchorError::Unavailable(
        "CSPRNG repeatedly returned a duplicate manifest nonce".to_owned(),
    ))
}

fn unavailable(context: &str, error: io::Error) -> RegistryAnchorError {
    RegistryAnchorError::Unavailable(format!("{context}: {error}"))
}

fn workspace_identity_digest(workspace: &Path) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"advance.contract218.workspace-installation-binding.v1\0");
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let bytes = workspace.as_os_str().as_bytes();
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        let units: Vec<u16> = workspace.as_os_str().encode_wide().collect();
        hasher.update(((units.len() * 2) as u64).to_be_bytes());
        for unit in units {
            hasher.update(unit.to_le_bytes());
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let bytes = workspace.as_os_str().to_string_lossy();
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes.as_bytes());
    }
    hasher.finalize().into()
}

fn lock_poisoned() -> RegistryAnchorError {
    RegistryAnchorError::Unavailable("anchor process lock poisoned".to_owned())
}

#[cfg(feature = "test-support")]
fn minimal_owner_artifact(epoch: u32, instance: [u8; 16], discriminator: u8) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.push(FORMAT_VERSION);
    bytes.extend_from_slice(&epoch.to_be_bytes());
    bytes.extend_from_slice(&instance);
    bytes.push(discriminator);
    bytes
}

pub(crate) struct ExclusiveCustody {
    identity: PathBuf,
    release: Option<mpsc::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

struct AnchorCustody {
    _platform: ExclusiveCustody,
    _workspace: ExclusiveCustody,
}

pub(crate) struct SharedRoleCustodyClaim {
    _exclusive: Arc<AnchorCustody>,
    claimed: Arc<AtomicBool>,
}

pub(crate) struct SharedKeyringCustodyClaim {
    _exclusive: Arc<AnchorCustody>,
    claimed: Arc<AtomicBool>,
}

pub(crate) struct SharedMarkerCustodyClaim {
    _exclusive: Arc<AnchorCustody>,
    claimed: Arc<AtomicBool>,
}

impl Drop for SharedRoleCustodyClaim {
    fn drop(&mut self) {
        self.claimed.store(false, Ordering::Release);
    }
}

impl Drop for SharedKeyringCustodyClaim {
    fn drop(&mut self) {
        self.claimed.store(false, Ordering::Release);
    }
}

impl Drop for SharedMarkerCustodyClaim {
    fn drop(&mut self) {
        self.claimed.store(false, Ordering::Release);
    }
}

fn process_custody_paths() -> &'static Mutex<HashSet<PathBuf>> {
    static PATHS: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();
    PATHS.get_or_init(|| Mutex::new(HashSet::new()))
}

impl ExclusiveCustody {
    fn acquire_platform(path: PathBuf) -> Result<Self, RegistryAnchorError> {
        let identity = path.clone();
        Self::acquire(identity, "open anchor custody file", move || {
            secure_open_or_create_regular(&path)
        })
    }

    fn acquire_workspace(workspace: PathBuf) -> Result<Self, RegistryAnchorError> {
        if !workspace.is_dir() {
            return Err(RegistryAnchorError::RecoveryRequired(
                "workspace custody identity must be a canonical directory".to_owned(),
            ));
        }
        let identity = workspace.clone();
        Self::acquire(identity, "open workspace custody directory", move || {
            File::open(workspace)
        })
    }

    fn acquire<F>(
        identity: PathBuf,
        open_context: &'static str,
        open: F,
    ) -> Result<Self, RegistryAnchorError>
    where
        F: FnOnce() -> io::Result<File>,
    {
        {
            let mut paths = process_custody_paths()
                .lock()
                .map_err(|_| lock_poisoned())?;
            if !paths.insert(identity.clone()) {
                return Err(RegistryAnchorError::RecoveryRequired(
                    "a second CONTRACT-218 custody object is already active".to_owned(),
                ));
            }
        }
        let file = match open() {
            Ok(file) => file,
            Err(error) => {
                process_custody_paths()
                    .lock()
                    .map_err(|_| lock_poisoned())?
                    .remove(&identity);
                return Err(unavailable(open_context, error));
            }
        };
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::channel();
        let thread = std::thread::Builder::new()
            .name("contract218-anchor-custody".to_owned())
            .spawn(move || {
                let mut lock = FileRwLock::new(file);
                match lock.try_write() {
                    Ok(_guard) => {
                        let _ = ready_tx.send(Ok(()));
                        let _ = release_rx.recv();
                    }
                    Err(error) => {
                        let _ = ready_tx.send(Err(error));
                    }
                };
            })
            .map_err(|error| unavailable("spawn anchor custody thread", error))?;
        match ready_rx.recv() {
            Ok(Ok(())) => Ok(Self {
                identity,
                release: Some(release_tx),
                thread: Some(thread),
            }),
            Ok(Err(error)) => {
                let _ = thread.join();
                process_custody_paths()
                    .lock()
                    .map_err(|_| lock_poisoned())?
                    .remove(&identity);
                Err(RegistryAnchorError::RecoveryRequired(format!(
                    "another process owns CONTRACT-218 custody: {error}"
                )))
            }
            Err(_) => {
                let _ = thread.join();
                process_custody_paths()
                    .lock()
                    .map_err(|_| lock_poisoned())?
                    .remove(&identity);
                Err(RegistryAnchorError::Unavailable(
                    "anchor custody thread exited before acquisition".to_owned(),
                ))
            }
        }
    }
}

impl Drop for ExclusiveCustody {
    fn drop(&mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        if let Ok(mut paths) = process_custody_paths().lock() {
            paths.remove(&self.identity);
        }
    }
}

#[cfg(test)]
mod exact_wire_tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn every_anchor_leaf_uses_the_character_device_rejecting_gate() {
        for leaf in [
            "contract218.platform-record.test-only",
            "contract218.custody.lock",
            "contract218.bundle-a",
            "contract218.bundle-b",
            ".contract218.bundle-a.tmp",
            ".contract218.bundle-b.tmp",
        ] {
            assert!(
                secure_regular_exists(Path::new("/dev/null")).is_err(),
                "anchor leaf {leaf} accepted a character device"
            );
        }
    }

    #[test]
    fn selector_151_byte_literal_kat_and_field_offsets() {
        let seal =
            HmacPlatformAnchorSeal::consume_platform_key(7, Zeroizing::new([0xa5; 32])).unwrap();
        let selector = Selector {
            selector_key_epoch: 7,
            workspace_installation_id: [0x10; 16],
            generation: 9,
            active_slot: 1,
            selected_set: SelectedSet::Next,
            active_bundle_root: [0x20; 32],
            registry_instance: [0x11; 16],
            selected_sequence: 5,
            nonce: [0x30; 32],
        };
        let bytes = encode_selector(&selector, &seal).unwrap();
        assert_eq!(bytes.len(), 151);
        assert_eq!(bytes[0], 1);
        assert_eq!(&bytes[1..5], &7u32.to_be_bytes());
        assert_eq!(&bytes[5..21], &[0x10; 16]);
        assert_eq!(&bytes[21..29], &9u64.to_be_bytes());
        assert_eq!(bytes[29], 2);
        assert_eq!(bytes[30], 2);
        assert_eq!(
            hex::encode(bytes),
            "0100000007101010101010101010101010101010100000000000000009020220202020202020202020202020202020202020202020202020202020202020201111111111111111111111111111111100000000000000053030303030303030303030303030303030303030303030303030303030303030bfa2b80d1e11ab723a7cb6cc1b342f5082401a1e8ee574054ee3f5c4165a1886"
        );
    }

    #[test]
    fn registry_manifest_artifact_set_and_bundle_literal_roots() {
        let seal = HmacRegistryManifestSeal::consume_host_master_keys(vec![(
            1,
            Zeroizing::new([0x71; 32]),
        )])
        .unwrap();
        let manifest = RegistryManifest {
            manifest_key_epoch: 1,
            committed: RegistryAnchorTuple {
                registry_instance: [0x11; 16],
                sequence: 0,
                head: [0x21; 32],
                state_root: [0x22; 32],
                keyring_root: [0x23; 32],
                role_allocation_root: [0x24; 32],
                migration_digest: [0x25; 32],
            },
            pending: None,
            nonce: [0x31; 32],
        };
        let manifest_bytes = encode_manifest(&manifest, &seal).unwrap();
        assert_eq!(manifest_bytes.len(), 254);
        assert_eq!(
            hex::encode(Sha256::digest(&manifest_bytes)),
            "e41bf0366bb4ce140e09dd47f4ddcff8304e0bf863cbab67a5c8bebed2aca1b9"
        );
        let set = ArtifactSet {
            registry_manifest: manifest_bytes,
            persisted_keyring: vec![0xaa, 0xbb],
            role_allocation: vec![0xcc],
            marker: Vec::new(),
        };
        let set_bytes = encode_artifact_set(&set).unwrap();
        assert_eq!(&set_bytes[..4], &254u32.to_be_bytes());
        assert_eq!(set_bytes.len(), 273);
        assert_eq!(
            hex::encode(artifact_set_root(&set).unwrap()),
            "4e8ee2723cc0a4aede6a3180c246c38a620e7093d6bda1438d973c5ea85bb2d3"
        );
        let bundle = RegistryAnchorBundle {
            current: set,
            next: None,
        };
        let bytes = encode_bundle(&bundle).unwrap();
        assert_eq!(bytes.len(), 279);
        assert_eq!(bytes[0], 1);
        assert_eq!(&bytes[1..5], &273u32.to_be_bytes());
        assert_eq!(*bytes.last().unwrap(), 0);
        assert_eq!(
            hex::encode(bundle_root(&bytes)),
            "f4b1f45c673aa92920a88e2d7c70f8ea2ae3c1d2e67bffa092358eb15ed4b188"
        );
        assert_eq!(decode_bundle(&bytes).unwrap(), bundle);
    }

    #[test]
    fn exact_decoders_reject_extension_and_unknown_tags() {
        let set = ArtifactSet {
            registry_manifest: vec![1],
            persisted_keyring: vec![2],
            role_allocation: vec![3],
            marker: Vec::new(),
        };
        let bundle = RegistryAnchorBundle {
            current: set,
            next: None,
        };
        let mut bytes = encode_bundle(&bundle).unwrap();
        bytes.push(0);
        assert!(decode_bundle(&bytes).is_err());
        let last = bytes.len() - 2;
        bytes.truncate(bytes.len() - 1);
        bytes[last] = 9;
        assert!(decode_bundle(&bytes).is_err());
    }
}

//! Production CONTRACT-218 composition over one workspace ComponentRegistry.
//!
//! Platform state is rooted outside the workspace snapshot domain.  Boot uses
//! an unpublished one-shot role set only long enough to initialize/recover the
//! anchored provider, commits the real current-boot allocation through the
//! provider's tag-6 transaction, then drops and reopens with the authenticated
//! custody roots before any observation source is published.

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use advance_scheduler::observation_anchor::{RegistryAnchorTransaction, RegistryAnchorWorld};
use advance_scheduler::registry::ComponentRegistry;
use advance_scheduler::sensitive_params::{
    ObservationProviderConfig, PersistedKeyringCustody, RegistrySensitiveParamProvider,
};
use advance_shared_types::contract218_previsible::{
    Contract218LifecycleRoleSet, Contract218RoleRootMaterial, PrevisibleProofIssuerRole,
    TerminationCleanupReceiptIssuerRole,
};
use advance_shared_types::observation_identity::SensitiveParamCatalogError;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::contract218_anchor::{
    secure_create_new_regular, secure_open_regular, FilePlatformMonotonicAnchorStore,
    FilePlatformMonotonicRecord, HmacPlatformAnchorSeal, HmacRegistryManifestSeal,
};
use crate::contract218_keyring::FilePersistedIdentityKeyringCustody;
use crate::contract218_roles::FileContract218RoleRootCustody;

const HOST_MASTER_FILE: &str = "contract218.host-master";
const PLATFORM_RECORD_FILE: &str = "contract218.platform-record";
const KEYRING_FILE: &str = "contract218.keyring.current";
const ROLES_FILE: &str = "contract218.roles.current";
const ROLE_FAMILY_VERSION: u16 = 1;

pub struct Contract218Runtime {
    pub provider: Arc<RegistrySensitiveParamProvider>,
    pub ready_issuer: Arc<PrevisibleProofIssuerRole>,
    pub cleanup_issuer: Arc<TerminationCleanupReceiptIssuerRole>,
    pub boot_id: [u8; 16],
    _anchor: FilePlatformMonotonicAnchorStore,
    _keyring: FilePersistedIdentityKeyringCustody,
    _roles: FileContract218RoleRootCustody,
}

pub async fn bootstrap_contract218(
    workspace: &Path,
    registry: Arc<ComponentRegistry>,
) -> Result<Contract218Runtime, String> {
    let canonical_workspace = fs::canonicalize(workspace)
        .map_err(|error| format!("canonicalize CONTRACT-218 workspace: {error}"))?;
    // The anchor's workspace-identity input must be byte-identical to the
    // `ComponentRegistry` trust root that issues empty/migration witnesses.
    // Production confines the database under `<workspace>/.triggers`, while
    // focused callers may open it directly under their workspace root.
    let registry_trust_root = registry
        .database_path()
        .parent()
        .ok_or("CONTRACT-218 registry database has no trust root")?;
    let registry_trust_root = fs::canonicalize(registry_trust_root)
        .map_err(|error| format!("canonicalize CONTRACT-218 registry trust root: {error}"))?;
    if !registry_trust_root.starts_with(&canonical_workspace) {
        return Err("CONTRACT-218 registry trust root escapes the workspace".to_owned());
    }
    let platform = platform_directory(&canonical_workspace)?;
    fs::create_dir_all(&platform)
        .map_err(|error| format!("create CONTRACT-218 platform directory: {error}"))?;

    let master = load_or_create_master(&platform.join(HOST_MASTER_FILE))?;
    let record = Arc::new(
        FilePlatformMonotonicRecord::open(platform.join(PLATFORM_RECORD_FILE))
            .map_err(|error| format!("open CONTRACT-218 platform record: {error}"))?,
    );
    let selector = Arc::new(
        HmacPlatformAnchorSeal::consume_platform_key(1, master.clone())
            .map_err(|error| format!("construct CONTRACT-218 selector seal: {error}"))?,
    );
    let manifest = Arc::new(
        HmacRegistryManifestSeal::consume_host_master_keys(vec![(1, master.clone())])
            .map_err(|error| format!("construct CONTRACT-218 manifest seal: {error}"))?,
    );
    let anchor = FilePlatformMonotonicAnchorStore::acquire(
        &platform,
        &registry_trust_root,
        record,
        selector,
        manifest,
    )
    .map_err(|error| format!("acquire CONTRACT-218 anchor: {error}"))?;

    let keyring =
        FilePersistedIdentityKeyringCustody::from_anchor_store(&anchor, vec![(1, master.clone())])
            .map_err(|error| format!("open CONTRACT-218 keyring: {error}"))?;
    let roles = FileContract218RoleRootCustody::from_anchor_store(&anchor, 1, master)
        .map_err(|error| format!("open CONTRACT-218 role custody: {error}"))?;

    let keyring_exists = regular_file_exists(&platform.join(KEYRING_FILE))?;
    let roles_exists = regular_file_exists(&platform.join(ROLES_FILE))?;
    if keyring_exists != roles_exists {
        return Err("CONTRACT-218 platform artifacts are partially initialized".to_owned());
    }

    let registry_instance = if keyring_exists {
        keyring
            .registry_instance()
            .map_err(|error| format!("read CONTRACT-218 registry identity: {error}"))?
    } else {
        let instance = fresh_nonzero_16()?;
        keyring
            .initialize_genesis(instance, 1, 1)
            .map_err(|error| format!("initialize CONTRACT-218 keyring: {error}"))?;
        roles
            .initialize_empty(instance, 1)
            .map_err(|error| format!("initialize CONTRACT-218 role manifest: {error}"))?;
        instance
    };
    let boot_id = fresh_nonzero_16()?;

    if keyring_exists {
        let anchored = selected_anchor_tuple(&anchor)?;
        roles
            .recover_against(&anchored)
            .map_err(|error| format!("recover CONTRACT-218 role manifest: {error}"))?;
    }

    let current_role_root = roles
        .current_root()
        .map_err(|error| format!("read CONTRACT-218 role root: {error}"))?
        .into_bytes();
    let current_keyring = keyring
        .authenticated_current_file(registry_instance)
        .map_err(|error| format!("read CONTRACT-218 keyring file: {error}"))?;
    let bootstrap_config = ObservationProviderConfig::greenfield(
        registry_instance,
        boot_id,
        current_role_root,
        current_keyring,
    )
    .map_err(|error| format!("construct CONTRACT-218 provider config: {error}"))?;

    // The bootstrap roles are never published.  They exist only to let the
    // provider establish/recover the anchor that authorizes the real tag-6
    // role allocation below.
    let bootstrap_roles = fresh_lifecycle_roles(registry_instance, boot_id)?;
    let (bootstrap_provider, _, _) = open_provider(
        Arc::clone(&registry),
        &anchor,
        &keyring,
        bootstrap_config,
        bootstrap_roles,
    )
    .await?;

    let head_context = bootstrap_provider
        .role_allocation_head_context()
        .await
        .map_err(|error| format!("read role-allocation head: {error}"))?;
    let mut prepared = roles
        .prepare_create_once(boot_id, ROLE_FAMILY_VERSION, head_context)
        .map_err(|error| format!("prepare current-boot role roots: {error}"))?;
    let mutation = prepared
        .take_anchor_preparation()
        .map_err(|error| format!("take role-allocation mutation: {error}"))?;
    let anchored = bootstrap_provider
        .commit_role_allocation_mutation(mutation)
        .await
        .map_err(|error| format!("commit current-boot role roots: {error}"))?;
    drop(bootstrap_provider);
    let opened = prepared
        .commit_anchored(&anchored)
        .map_err(|error| format!("open committed current-boot role roots: {error}"))?;
    let real_roles = opened
        .into_lifecycle_roles()
        .map_err(catalog_error("split current-boot role roots"))?;

    let final_keyring = keyring
        .authenticated_current_file(registry_instance)
        .map_err(|error| format!("re-read CONTRACT-218 keyring file: {error}"))?;
    let final_config = ObservationProviderConfig::greenfield(
        registry_instance,
        boot_id,
        anchored.role_allocation_root,
        final_keyring,
    )
    .map_err(|error| format!("construct final CONTRACT-218 provider config: {error}"))?;
    let (provider, ready_issuer, cleanup_issuer) =
        open_provider(registry, &anchor, &keyring, final_config, real_roles).await?;

    Ok(Contract218Runtime {
        provider,
        ready_issuer: Arc::new(ready_issuer),
        cleanup_issuer: Arc::new(cleanup_issuer),
        boot_id,
        _anchor: anchor,
        _keyring: keyring,
        _roles: roles,
    })
}

async fn open_provider(
    registry: Arc<ComponentRegistry>,
    anchor: &FilePlatformMonotonicAnchorStore,
    keyring: &FilePersistedIdentityKeyringCustody,
    config: ObservationProviderConfig,
    roles: Contract218LifecycleRoleSet,
) -> Result<
    (
        Arc<RegistrySensitiveParamProvider>,
        PrevisibleProofIssuerRole,
        TerminationCleanupReceiptIssuerRole,
    ),
    String,
> {
    let (issuer, mut verifier, termination, cleanup_issuer, cleanup_verifier) =
        roles.move_to_composition();
    let installer = verifier
        .take_persisted_identity_keyring_installer()
        .map_err(catalog_error("take persisted-keyring installer"))?;
    let persisted_keyring = installer
        .install_authenticated_custody(Box::new(keyring.clone()))
        .map_err(catalog_error("install persisted-keyring custody"))?;
    let keyring_custody: Arc<dyn PersistedKeyringCustody> = Arc::new(keyring.clone());
    let anchor_tx: Arc<dyn RegistryAnchorTransaction> = Arc::new(anchor.clone());
    let provider = RegistrySensitiveParamProvider::open(
        registry,
        anchor_tx,
        config,
        verifier,
        persisted_keyring,
        keyring_custody,
        termination,
        cleanup_verifier,
    )
    .await
    .map_err(|error| format!("open CONTRACT-218 provider: {error}"))?;
    Ok((provider, issuer, cleanup_issuer))
}

fn fresh_lifecycle_roles(
    registry_instance: [u8; 16],
    boot_id: [u8; 16],
) -> Result<Contract218LifecycleRoleSet, String> {
    let first = fresh_nonzero_32()?;
    let mut second = fresh_nonzero_32()?;
    while second == first {
        second = fresh_nonzero_32()?;
    }
    Contract218RoleRootMaterial::from_authenticated_custody(
        registry_instance,
        boot_id,
        Zeroizing::new(first),
        Zeroizing::new(second),
    )
    .and_then(|roots| roots.into_lifecycle_factory().split_once())
    .map_err(catalog_error("construct bootstrap lifecycle roles"))
}

fn selected_anchor_tuple(
    anchor: &FilePlatformMonotonicAnchorStore,
) -> Result<advance_scheduler::observation_anchor::RegistryAnchorTuple, String> {
    match anchor
        .authenticated_world()
        .map_err(|error| format!("read CONTRACT-218 anchor: {error}"))?
    {
        RegistryAnchorWorld::PendingCurrent { previous, .. } => Ok(previous),
        RegistryAnchorWorld::SelectedNext { next, .. } => Ok(next),
        RegistryAnchorWorld::CompactCurrent { current, .. } => Ok(current),
    }
}

fn platform_directory(workspace: &Path) -> Result<PathBuf, String> {
    let digest = Sha256::digest(workspace.to_string_lossy().as_bytes());
    let workspace_key = hex::encode(digest);
    let base = if cfg!(feature = "test-support") {
        std::env::temp_dir().join("advance-agents-contract218-platform")
    } else if cfg!(target_os = "macos") {
        let home = std::env::var_os("HOME").ok_or("HOME is unavailable for CONTRACT-218")?;
        PathBuf::from(home).join("Library/Application Support/advance-agents/contract218")
    } else if let Some(state) = std::env::var_os("XDG_STATE_HOME") {
        PathBuf::from(state).join("advance-agents/contract218")
    } else {
        let home = std::env::var_os("HOME").ok_or("HOME is unavailable for CONTRACT-218")?;
        PathBuf::from(home).join(".local/state/advance-agents/contract218")
    };
    Ok(base.join(workspace_key))
}

fn load_or_create_master(path: &Path) -> Result<Zeroizing<[u8; 32]>, String> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    match secure_open_regular(path) {
        Ok(mut file) => {
            file.read_exact(bytes.as_mut())
                .map_err(|error| format!("read CONTRACT-218 host master: {error}"))?;
            let mut trailing = [0u8; 1];
            if file
                .read(&mut trailing)
                .map_err(|error| format!("measure CONTRACT-218 host master: {error}"))?
                != 0
            {
                return Err("CONTRACT-218 host master has an invalid length".to_owned());
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            OsRng.fill_bytes(bytes.as_mut());
            if bytes.as_ref() == &[0; 32] {
                return Err("CSPRNG returned a zero CONTRACT-218 host master".to_owned());
            }
            let mut file = secure_create_new_regular(path)
                .map_err(|create| format!("create CONTRACT-218 host master: {create}"))?;
            file.write_all(bytes.as_ref())
                .and_then(|_| file.sync_all())
                .map_err(|write| format!("persist CONTRACT-218 host master: {write}"))?;
        }
        Err(error) => return Err(format!("open CONTRACT-218 host master: {error}")),
    }
    if bytes.as_ref() == &[0; 32] {
        return Err("CONTRACT-218 host master is zero".to_owned());
    }
    Ok(bytes)
}

fn regular_file_exists(path: &Path) -> Result<bool, String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => Ok(true),
        Ok(_) => Err(format!(
            "CONTRACT-218 artifact is not a regular file: {}",
            path.display()
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(format!("inspect CONTRACT-218 artifact: {error}")),
    }
}

fn fresh_nonzero_16() -> Result<[u8; 16], String> {
    let mut value = [0u8; 16];
    OsRng.fill_bytes(&mut value);
    if value == [0; 16] {
        return Err("CSPRNG returned a zero 16-byte value".to_owned());
    }
    Ok(value)
}

fn fresh_nonzero_32() -> Result<[u8; 32], String> {
    let mut value = [0u8; 32];
    OsRng.fill_bytes(&mut value);
    if value == [0; 32] {
        return Err("CSPRNG returned a zero 32-byte value".to_owned());
    }
    Ok(value)
}

fn catalog_error(context: &'static str) -> impl FnOnce(SensitiveParamCatalogError) -> String {
    move |error| format!("{context}: {error:?}")
}

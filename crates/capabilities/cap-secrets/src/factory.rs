//! The ONE place that maps `runtime-config.yaml`'s `secrets:` block to a master key + a
//! [`SecretStorage`] backend (this lane).
//!
//! Before this module every composition site (advance-home first-open, `advance start`
//! wiring, `advance secrets set|list|remove`, `advance init`) hard-coded
//! `FileSecretStorage::open(<home>/.advance/secrets.json)` plus its own copy of the
//! `SecretsConfig → MasterKeyConfig` mapping. They now call [`load_master_key`] /
//! [`open_storage`] / [`open_secret_store`] / [`open_secret_storage_unkeyed`], so the
//! `keychain-sync` source is honoured everywhere at once, and the two legacy sources
//! (`keychain` = the `keyring` file keychain with env fallback, `env-var`) keep their exact
//! pre-existing behaviour.
//!
//! Master-key precedence in `keychain-sync` mode: the configured env var first (the
//! pre-existing operator contract — also the fallback when the daemon process itself cannot
//! reach the keychain and the App hands it the key) → the namespace's keychain master item →
//! mint-and-store ONLY when the namespace holds no ciphertext at all. `<home>/.advance/master.key`
//! is never read or written in this mode. A keychain error fails closed. A non-Apple platform
//! configured for `keychain-sync` fails closed with [`PLATFORM_UNSUPPORTED_MSG`].

use std::path::Path;
use std::sync::Arc;

use advance_runtime::config::{KeychainSyncConfig, MasterKeySource, SecretsConfig};
use zeroize::Zeroizing;

use crate::error::SecretError;
use crate::file_storage::FileSecretStorage;
use crate::keychain_sync::{
    AppleKeychainSecretStorage, KeychainMasterKeyStore, SecItemOps, DEFAULT_NAMESPACE,
};
use crate::master_key::{
    ensure_master_key, load_master_key as load_from_config, resolve_master_key, EntryProvider,
    MasterKeyConfig, DEFAULT_KEYCHAIN_ACCOUNT, DEFAULT_KEYCHAIN_SERVICE,
};
use crate::storage::SecretStorage;
use crate::store::SecretStore;

/// The `KeyLoad` message a non-Apple host answers for `master-key-source: keychain-sync`.
pub const PLATFORM_UNSUPPORTED_MSG: &str =
    "secrets.master-key-source keychain-sync is unsupported on this platform";

/// Where the master key and the ciphertext rows live.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecretsBackend {
    /// `<home>/.advance/master.key` (or the env var / `keyring` file keychain) +
    /// `<home>/.advance/secrets.json`.
    File,
    /// iCloud-Keychain-synchronized generic-password items (see [`crate::keychain_sync`]).
    KeychainSync,
}

/// The backend the `secrets:` block selects.
pub fn backend_of(cfg: &SecretsConfig) -> SecretsBackend {
    match cfg.master_key_source {
        MasterKeySource::KeychainSync => SecretsBackend::KeychainSync,
        MasterKeySource::Keychain | MasterKeySource::EnvVar => SecretsBackend::File,
    }
}

/// Whether this build can serve `keychain-sync` (Apple targets only).
pub fn platform_supports_keychain_sync() -> bool {
    cfg!(target_vendor = "apple")
}

/// The [`MasterKeyConfig`] of the File backend: `keychain` → the `keyring` file keychain
/// with the env var as fallback; `env-var` → the env var only. For `keychain-sync` this is
/// the env-var-only view (the keychain leg is [`KeychainMasterKeyStore`], not `keyring`).
pub fn file_master_key_config(cfg: &SecretsConfig) -> MasterKeyConfig {
    match cfg.master_key_source {
        MasterKeySource::EnvVar | MasterKeySource::KeychainSync => {
            MasterKeyConfig::EnvVar(cfg.env_var_name.clone())
        }
        MasterKeySource::Keychain => MasterKeyConfig::Keychain {
            service: DEFAULT_KEYCHAIN_SERVICE.to_string(),
            account: DEFAULT_KEYCHAIN_ACCOUNT.to_string(),
            fallback_env_var: Some(cfg.env_var_name.clone()),
        },
    }
}

/// The effective `secrets.keychain` settings (defaults when the block is absent).
pub fn keychain_settings(cfg: &SecretsConfig) -> KeychainSyncConfig {
    cfg.keychain.clone().unwrap_or_default()
}

/// The production [`SecItemOps`] of this platform, or the platform-unsupported error.
pub fn default_sec_item_ops() -> Result<Arc<dyn SecItemOps>, SecretError> {
    #[cfg(target_vendor = "apple")]
    {
        Ok(Arc::new(crate::keychain_sync::RealSecItemOps))
    }
    #[cfg(not(target_vendor = "apple"))]
    {
        Err(SecretError::KeyLoad(PLATFORM_UNSUPPORTED_MSG.into()))
    }
}

fn ops_or_default(ops: Option<Arc<dyn SecItemOps>>) -> Result<Arc<dyn SecItemOps>, SecretError> {
    match ops {
        Some(ops) => Ok(ops),
        None => default_sec_item_ops(),
    }
}

/// Whether a missing master key may be minted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MasterKeyPolicy {
    /// First-open / provisioning: mint when nothing exists yet (File: the pre-existing
    /// [`ensure_master_key`]; keychain-sync: only when the namespace holds no ciphertext).
    Ensure,
    /// Daemon / resolve paths: never mint; a missing key is a `KeyLoad` error.
    Resolve,
}

/// The keychain master item of `cfg` (namespace / access group / sync flag from
/// `secrets.keychain`).
pub fn keychain_master_store(
    cfg: &SecretsConfig,
    ops: Arc<dyn SecItemOps>,
) -> KeychainMasterKeyStore {
    let kc = keychain_settings(cfg);
    KeychainMasterKeyStore::new(
        ops,
        &kc.namespace,
        kc.access_group.as_deref(),
        kc.synchronizable,
    )
}

/// The env-var leg shared by both backends: the configured env var, decoded, or `None` when
/// unset.
fn env_master_key(cfg: &SecretsConfig) -> Result<Option<Zeroizing<[u8; 32]>>, SecretError> {
    match std::env::var(&cfg.env_var_name) {
        Ok(s) => crate::master_key::decode_to_key(&Zeroizing::new(s)).map(Some),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(_) => Err(SecretError::KeyLoad(format!(
            "env var {} contains non-UTF-8 bytes",
            cfg.env_var_name
        ))),
    }
}

/// Load (or, under [`MasterKeyPolicy::Ensure`], mint) the master key `cfg` selects.
///
/// File backend: byte-identical to the pre-existing paths — `Ensure` is
/// [`ensure_master_key`] (env → workspace file → keychain → mint); `Resolve` is
/// [`resolve_master_key`] then [`load_master_key`](crate::load_master_key) (never mints).
/// keychain-sync backend: env var → keychain master item → (`Ensure` only) mint when the
/// namespace has no ciphertext; `<home>/.advance/master.key` is never touched.
pub fn load_master_key(
    home: &Path,
    cfg: &SecretsConfig,
    entries: &dyn EntryProvider,
    ops: Option<Arc<dyn SecItemOps>>,
    policy: MasterKeyPolicy,
) -> Result<Zeroizing<[u8; 32]>, SecretError> {
    match backend_of(cfg) {
        SecretsBackend::File => {
            let mk = file_master_key_config(cfg);
            match policy {
                MasterKeyPolicy::Ensure => ensure_master_key(home, &mk, entries),
                MasterKeyPolicy::Resolve => {
                    if let Some(key) = resolve_master_key(home, &mk, entries)? {
                        return Ok(key);
                    }
                    load_from_config(&mk, entries)
                }
            }
        }
        SecretsBackend::KeychainSync => {
            let ops = ops_or_default(ops)?;
            let store = keychain_master_store(cfg, ops);
            if let Some(key) = env_master_key(cfg)? {
                // The operator-provided key wins for this process. Persist it into the
                // keychain when the namespace has none yet, so the next boot without the env
                // var finds it; a keychain that cannot be written (the App-provided-key
                // fallback deployment) must not turn a valid key into a boot failure.
                if matches!(store.read(), Ok(None)) {
                    let _ = store.store(&key);
                }
                return Ok(key);
            }
            if let Some(key) = store.read()? {
                return Ok(key);
            }
            match policy {
                MasterKeyPolicy::Resolve => Err(SecretError::KeyLoad(
                    "keychain-sync master key not found in the keychain and the env var is unset"
                        .into(),
                )),
                MasterKeyPolicy::Ensure => {
                    if store.namespace_has_ciphertext()? {
                        return Err(SecretError::KeyLoad(
                            "keychain-sync master key missing while the namespace already holds ciphertext; refusing to mint a new key over it"
                                .into(),
                        ));
                    }
                    store.mint()
                }
            }
        }
    }
}

/// Open the ciphertext backend `cfg` selects. `kid` is the id of the master key the handle
/// decrypts with (`None` = an unkeyed handle for `names` / `remove`; keychain-sync `get`
/// refuses it, the File backend ignores it).
pub fn open_storage(
    home: &Path,
    cfg: &SecretsConfig,
    ops: Option<Arc<dyn SecItemOps>>,
    master: Option<&[u8; 32]>,
) -> Result<Arc<dyn SecretStorage>, SecretError> {
    match backend_of(cfg) {
        SecretsBackend::File => Ok(Arc::new(FileSecretStorage::open(
            home.join(".advance").join("secrets.json"),
        )?)),
        SecretsBackend::KeychainSync => {
            let ops = ops_or_default(ops)?;
            let kc = keychain_settings(cfg);
            let storage = match master {
                Some(master) => AppleKeychainSecretStorage::new(
                    ops,
                    &kc.namespace,
                    kc.access_group.as_deref(),
                    kc.synchronizable,
                    master,
                ),
                None => AppleKeychainSecretStorage::unkeyed(
                    ops,
                    &kc.namespace,
                    kc.access_group.as_deref(),
                    kc.synchronizable,
                ),
            };
            Ok(Arc::new(storage))
        }
    }
}

/// A master key plus the matching ciphertext backend.
pub struct OpenedSecretStore {
    pub master: Zeroizing<[u8; 32]>,
    pub storage: Arc<dyn SecretStorage>,
}

impl OpenedSecretStore {
    pub fn into_store(self) -> SecretStore {
        SecretStore::new(self.master, self.storage)
    }
}

/// [`load_master_key`] + [`open_storage`] in one call.
pub fn open_secret_store(
    home: &Path,
    cfg: &SecretsConfig,
    entries: &dyn EntryProvider,
    ops: Option<Arc<dyn SecItemOps>>,
    policy: MasterKeyPolicy,
) -> Result<OpenedSecretStore, SecretError> {
    let master = load_master_key(home, cfg, entries, ops.clone(), policy)?;
    let storage = open_storage(home, cfg, ops, Some(&master))?;
    Ok(OpenedSecretStore { master, storage })
}

/// The ciphertext backend without any master key (`advance secrets list|remove`).
pub fn open_secret_storage_unkeyed(
    home: &Path,
    cfg: &SecretsConfig,
    ops: Option<Arc<dyn SecItemOps>>,
) -> Result<Arc<dyn SecretStorage>, SecretError> {
    open_storage(home, cfg, ops, None)
}

/// The namespace `cfg` addresses (for diagnostics / projections).
pub fn namespace_of(cfg: &SecretsConfig) -> String {
    cfg.keychain
        .as_ref()
        .map(|k| k.namespace.clone())
        .unwrap_or_else(|| DEFAULT_NAMESPACE.to_string())
}

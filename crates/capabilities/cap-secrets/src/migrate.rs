//! Moving a home between the File backend and keychain-sync
//! (this lane).
//!
//! - [`migrate_file_to_keychain`]: re-encrypts every `secrets.json` row under the keychain
//!   master key (env var → keychain item → minted when the namespace is empty), verifies each
//!   name round-trips, then renames `secrets.json` / `master.key` to `*.migrated`. Idempotent:
//!   without both source files there is nothing to do. The daemon runs it at boot when the
//!   config says `keychain-sync` but the home still carries the File artifacts
//!   ([`auto_migrate_if_needed`]).
//! - [`migrate_keychain_to_file`]: the explicit reverse (`advance secrets migrate --to file`).
//!   Keychain items are NOT deleted — deleting a synchronizable item would remove it from the
//!   user's other devices.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use advance_runtime::config::SecretsConfig;
use secrecy::ExposeSecret;

use crate::error::SecretError;
use crate::factory::{
    backend_of, keychain_settings, load_master_key, open_storage, MasterKeyPolicy, SecretsBackend,
};
use crate::file_storage::FileSecretStorage;
use crate::keychain_sync::SecItemOps;
use crate::master_key::{
    ensure_master_key, read_workspace_master_key, workspace_master_key_path, EntryProvider,
    MasterKeyConfig, DEFAULT_KEYCHAIN_ACCOUNT, DEFAULT_KEYCHAIN_SERVICE,
};
use crate::storage::SecretStorage;
use crate::store::SecretStore;

/// Suffix appended to the File artifacts once their content lives in the keychain.
pub const MIGRATED_SUFFIX: &str = ".migrated";

/// The direction of an explicit migration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MigrationTarget {
    File,
    KeychainSync,
}

impl MigrationTarget {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "file" => Some(Self::File),
            "keychain-sync" => Some(Self::KeychainSync),
            _ => None,
        }
    }
}

/// What a migration did (names only — never values).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MigrationReport {
    /// Secret names re-encrypted into the target backend, sorted.
    pub migrated: Vec<String>,
    /// Files renamed to `*.migrated`.
    pub renamed: Vec<PathBuf>,
    /// The source backend had nothing to migrate.
    pub nothing_to_do: bool,
}

fn secrets_json_path(home: &Path) -> PathBuf {
    home.join(".advance").join("secrets.json")
}

fn is_regular_file(path: &Path) -> bool {
    std::fs::symlink_metadata(path)
        .map(|m| m.file_type().is_file())
        .unwrap_or(false)
}

/// Whether the home still carries BOTH File artifacts (`master.key` + `secrets.json`).
pub fn file_artifacts_present(home: &Path) -> bool {
    is_regular_file(&workspace_master_key_path(home)) && is_regular_file(&secrets_json_path(home))
}

fn migrated_name(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(MIGRATED_SUFFIX);
    path.with_file_name(name)
}

fn rename_migrated(path: &Path, report: &mut MigrationReport) -> Result<(), SecretError> {
    let target = migrated_name(path);
    std::fs::rename(path, &target).map_err(|e| {
        SecretError::KeyLoad(format!(
            "rename {} after migration failed: {e}",
            path.display()
        ))
    })?;
    report.renamed.push(target);
    Ok(())
}

/// Copy every secret of `src` into `dst`, verifying each round-trips. Names only in the
/// report.
fn copy_all(src: &SecretStore, dst: &SecretStore) -> Result<Vec<String>, SecretError> {
    let names = src.names();
    for name in &names {
        let plaintext = src.resolve(name)?;
        dst.store(name, plaintext.expose_secret())?;
        let back = dst.resolve(name)?;
        if back.expose_secret() != plaintext.expose_secret() {
            return Err(SecretError::Crypto("migration roundtrip mismatch"));
        }
    }
    Ok(names)
}

/// The File-side master key of a home that is being migrated AWAY from the File backend:
/// the workspace file itself (the env var, if set, names the keychain-sync key now).
fn file_master_for_source(home: &Path) -> Result<zeroize::Zeroizing<[u8; 32]>, SecretError> {
    read_workspace_master_key(home)?.ok_or_else(|| {
        SecretError::KeyLoad(
            "master.key is missing; secrets.json cannot be migrated without it".into(),
        )
    })
}

/// The `secrets:` block as the File backend would read it after the migration
/// (`keychain` source = the scaffold default: `keyring` file keychain with the env var as
/// fallback).
fn file_target_master_config(cfg: &SecretsConfig) -> MasterKeyConfig {
    MasterKeyConfig::Keychain {
        service: DEFAULT_KEYCHAIN_SERVICE.to_string(),
        account: DEFAULT_KEYCHAIN_ACCOUNT.to_string(),
        fallback_env_var: Some(cfg.env_var_name.clone()),
    }
}

/// `secrets.json` (+ `master.key`) → keychain items of `cfg`'s namespace.
pub fn migrate_file_to_keychain(
    home: &Path,
    cfg: &SecretsConfig,
    entries: &dyn EntryProvider,
    ops: Option<Arc<dyn SecItemOps>>,
) -> Result<MigrationReport, SecretError> {
    let mut report = MigrationReport::default();
    let secrets_path = secrets_json_path(home);
    if !is_regular_file(&secrets_path) {
        report.nothing_to_do = true;
        return Ok(report);
    }
    let src_master = file_master_for_source(home)?;
    let src_storage: Arc<dyn SecretStorage> = Arc::new(FileSecretStorage::open(&secrets_path)?);
    let src = SecretStore::new(src_master, src_storage);

    // Target: the keychain-sync store of `cfg` (env var → keychain item → mint when the
    // namespace is empty). Force the keychain-sync view even if the caller passed a File
    // config (the explicit `--to keychain-sync` command runs before the YAML is flipped).
    let mut target_cfg = cfg.clone();
    target_cfg.master_key_source = advance_runtime::config::MasterKeySource::KeychainSync;
    if target_cfg.keychain.is_none() {
        target_cfg.keychain = Some(keychain_settings(cfg));
    }
    let dst_master = load_master_key(
        home,
        &target_cfg,
        entries,
        ops.clone(),
        MasterKeyPolicy::Ensure,
    )?;
    let dst_storage = open_storage(home, &target_cfg, ops, Some(&dst_master))?;
    let dst = SecretStore::new(dst_master, dst_storage);

    report.migrated = copy_all(&src, &dst)?;
    drop(src);
    rename_migrated(&secrets_path, &mut report)?;
    let master_path = workspace_master_key_path(home);
    if is_regular_file(&master_path) {
        rename_migrated(&master_path, &mut report)?;
    }
    Ok(report)
}

/// Keychain items of `cfg`'s namespace → `secrets.json` under a File master key
/// (`ensure_master_key` with the scaffold-default source: env var → `master.key` → `keyring`
/// → mint). Keychain items stay in place.
pub fn migrate_keychain_to_file(
    home: &Path,
    cfg: &SecretsConfig,
    entries: &dyn EntryProvider,
    ops: Option<Arc<dyn SecItemOps>>,
) -> Result<MigrationReport, SecretError> {
    let mut report = MigrationReport::default();
    let mut source_cfg = cfg.clone();
    source_cfg.master_key_source = advance_runtime::config::MasterKeySource::KeychainSync;
    if source_cfg.keychain.is_none() {
        source_cfg.keychain = Some(keychain_settings(cfg));
    }
    let src_master = load_master_key(
        home,
        &source_cfg,
        entries,
        ops.clone(),
        MasterKeyPolicy::Resolve,
    )?;
    let src_storage = open_storage(home, &source_cfg, ops, Some(&src_master))?;
    let src = SecretStore::new(src_master, src_storage);
    if src.names().is_empty() {
        report.nothing_to_do = true;
        return Ok(report);
    }

    let dst_master = ensure_master_key(home, &file_target_master_config(cfg), entries)?;
    let dst_storage: Arc<dyn SecretStorage> =
        Arc::new(FileSecretStorage::open(secrets_json_path(home))?);
    let dst = SecretStore::new(dst_master, dst_storage);
    report.migrated = copy_all(&src, &dst)?;
    Ok(report)
}

/// The daemon-boot leg: when `cfg` says `keychain-sync` and the home still carries both File
/// artifacts, migrate them; otherwise do nothing. `Ok(None)` = no migration ran.
pub fn auto_migrate_if_needed(
    home: &Path,
    cfg: &SecretsConfig,
    entries: &dyn EntryProvider,
    ops: Option<Arc<dyn SecItemOps>>,
) -> Result<Option<MigrationReport>, SecretError> {
    if backend_of(cfg) != SecretsBackend::KeychainSync || !file_artifacts_present(home) {
        return Ok(None);
    }
    migrate_file_to_keychain(home, cfg, entries, ops).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrated_name_appends_suffix() {
        assert_eq!(
            migrated_name(Path::new("/x/.advance/secrets.json")),
            PathBuf::from("/x/.advance/secrets.json.migrated")
        );
    }

    #[test]
    fn target_parses() {
        assert_eq!(MigrationTarget::parse("file"), Some(MigrationTarget::File));
        assert_eq!(
            MigrationTarget::parse("keychain-sync"),
            Some(MigrationTarget::KeychainSync)
        );
        assert_eq!(MigrationTarget::parse("keychain"), None);
    }
}

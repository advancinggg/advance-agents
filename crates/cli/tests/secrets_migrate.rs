//! `advance secrets migrate --to keychain-sync | file` over a mock keychain:
//! the File artifacts move into keychain items
//! (every name verified), get renamed `*.migrated`, the YAML repoints at `keychain-sync`; the
//! reverse rebuilds `secrets.json` and repoints at the File source, keychain items untouched.
//! Hermetic: a mock `SecItemOps` and a NotFound `keyring` seam — the dev machine's real
//! keychain is never consulted.

use std::sync::Arc;

use advance_cli::commands::secrets::run_migrate_with;
use advance_home::{read_secrets_mode, write_recognizable_home, SecretsMode};
use advance_runtime::config::MasterKeySource;
use cap_secrets::{
    open_secret_store, read_workspace_master_key, EntryError, EntryProvider, FileSecretStorage,
    KeychainItem, MasterKeyPolicy, MigrationTarget, MockSecItemOps, SecItemOps, SecretStorage,
    SecretStore,
};
use secrecy::ExposeSecret;

struct NoKeyring;

impl EntryProvider for NoKeyring {
    fn get_password(&self, _: &str, _: &str) -> Result<String, EntryError> {
        Err(EntryError::NotFound("test".into()))
    }
}

fn seeded_file_home() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let ws = std::fs::canonicalize(dir.path()).unwrap().join("home");
    write_recognizable_home(&ws).unwrap();
    let master = read_workspace_master_key(&ws)
        .unwrap()
        .expect("File-mode scaffold mints master.key");
    let storage: Arc<dyn SecretStorage> =
        Arc::new(FileSecretStorage::open(ws.join(".advance/secrets.json")).unwrap());
    let store = SecretStore::new(master, storage);
    store.store("anthropic-api-key", "sk-ant-migrate").unwrap();
    store.store("openai-api-key", "sk-oai-migrate").unwrap();
    (dir, ws)
}

fn item(namespace: &str, kind: &str, account: &str) -> KeychainItem {
    KeychainItem {
        service: format!("agents.advance.{namespace}.{kind}"),
        account: account.into(),
        synchronizable: true,
        access_group: None,
    }
}

#[test]
fn migrate_to_keychain_sync_then_back_to_file() {
    // `--to keychain-sync` is refused on a non-Apple host before anything is touched; the
    // mock-backed round trip below is an Apple-only witness (CI on Linux exercises the refusal).
    if !cap_secrets::platform_supports_keychain_sync() {
        let (_dir, ws) = seeded_file_home();
        let err = run_migrate_with(
            MigrationTarget::KeychainSync,
            Some(ws),
            Some(MockSecItemOps::new() as Arc<dyn SecItemOps>),
            &NoKeyring,
        )
        .unwrap_err();
        assert!(err.contains("unsupported on this platform"), "{err}");
        return;
    }
    // The keychain-sync target reads the configured env var first; keep the test independent
    // of the developer's shell.
    std::env::remove_var("SECRETS_MASTER_KEY");
    let (_dir, ws) = seeded_file_home();
    let ops = MockSecItemOps::new();
    let ops_dyn: Arc<dyn SecItemOps> = ops.clone();

    // → keychain-sync
    let report = run_migrate_with(
        MigrationTarget::KeychainSync,
        Some(ws.clone()),
        Some(ops_dyn.clone()),
        &NoKeyring,
    )
    .expect("file → keychain-sync");
    assert_eq!(
        report.migrated,
        vec![
            "anthropic-api-key".to_string(),
            "openai-api-key".to_string()
        ]
    );
    assert_eq!(report.renamed.len(), 2);
    assert!(ws.join(".advance/secrets.json.migrated").is_file());
    assert!(ws.join(".advance/master.key.migrated").is_file());
    assert!(!ws.join(".advance/secrets.json").exists());
    assert!(!ws.join(".advance/master.key").exists());
    assert!(ops.contains(&item("default", "master", "master-key")));
    assert!(ops.contains(&item("default", "secrets", "anthropic-api-key")));
    assert!(ops.contains(&item("default", "secrets", "openai-api-key")));
    let view = read_secrets_mode(&ws).unwrap();
    assert_eq!(view.mode, SecretsMode::KeychainSync);
    assert_eq!(view.master_key_source, MasterKeySource::KeychainSync);
    let raw = std::fs::read_to_string(ws.join(".advance/runtime-config.yaml")).unwrap();
    assert!(raw.contains("master-key-source: keychain-sync"));
    assert!(raw.contains("llm-providers"), "rest of the config kept");

    // The keychain store (what `advance start` opens now) resolves both names.
    let cfg =
        advance_runtime::config::load_config(&ws.join(".advance/runtime-config.yaml")).unwrap();
    let store = open_secret_store(
        &ws,
        &cfg.secrets,
        &NoKeyring,
        Some(ops_dyn.clone()),
        MasterKeyPolicy::Resolve,
    )
    .unwrap()
    .into_store();
    assert_eq!(
        store.resolve("anthropic-api-key").unwrap().expose_secret(),
        "sk-ant-migrate"
    );

    // Idempotent: nothing left to move, config stays.
    let again = run_migrate_with(
        MigrationTarget::KeychainSync,
        Some(ws.clone()),
        Some(ops_dyn.clone()),
        &NoKeyring,
    )
    .unwrap();
    assert!(again.nothing_to_do);
    assert_eq!(
        read_secrets_mode(&ws).unwrap().mode,
        SecretsMode::KeychainSync
    );

    // → file
    let back = run_migrate_with(
        MigrationTarget::File,
        Some(ws.clone()),
        Some(ops_dyn.clone()),
        &NoKeyring,
    )
    .expect("keychain-sync → file");
    assert_eq!(back.migrated.len(), 2);
    assert!(ws.join(".advance/secrets.json").is_file());
    assert!(ws.join(".advance/master.key").is_file());
    let view = read_secrets_mode(&ws).unwrap();
    assert_eq!(view.mode, SecretsMode::File);
    assert_eq!(view.master_key_source, MasterKeySource::Keychain);
    // Keychain items are never deleted by the reverse migration.
    assert!(ops.contains(&item("default", "secrets", "anthropic-api-key")));
    let cfg =
        advance_runtime::config::load_config(&ws.join(".advance/runtime-config.yaml")).unwrap();
    let file_store = open_secret_store(
        &ws,
        &cfg.secrets,
        &NoKeyring,
        None,
        MasterKeyPolicy::Resolve,
    )
    .unwrap()
    .into_store();
    assert_eq!(
        file_store
            .resolve("openai-api-key")
            .unwrap()
            .expose_secret(),
        "sk-oai-migrate"
    );
}

#[test]
fn migrate_rejects_unknown_target_and_uninitialized_home() {
    assert!(MigrationTarget::parse("keychain").is_none());
    let dir = tempfile::tempdir().unwrap();
    let err = run_migrate_with(
        MigrationTarget::File,
        Some(dir.path().to_path_buf()),
        Some(MockSecItemOps::new() as Arc<dyn SecItemOps>),
        &NoKeyring,
    )
    .unwrap_err();
    assert!(err.contains("advance init"), "{err}");
}

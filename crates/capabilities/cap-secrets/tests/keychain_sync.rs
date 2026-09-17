//! keychain-sync backend witnesses over `MockSecItemOps`: the factory, the store, the
//! master-key precedence, the kid guard, the migration in both directions and the
//! synchronizable toggle — all without a real keychain.
//!
//! Env-var cases are serialized through one mutex (the factory reads the configured env var),
//! and every case uses its OWN env var name so no case can observe another's value.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use advance_runtime::config::{KeychainSyncConfig, MasterKeySource, SecretsConfig};
use cap_secrets::{
    auto_migrate_if_needed, backend_of, file_artifacts_present, load_master_key_for,
    migrate_file_to_keychain, migrate_keychain_to_file, open_secret_storage_unkeyed,
    open_secret_store, platform_supports_keychain_sync, EntryError, EntryProvider,
    FileSecretStorage, KeychainItem, MasterKeyPolicy, MigrationTarget, MockSecItemOps,
    SecItemError, SecItemOps, SecretError, SecretStorage, SecretStore, SecretsBackend,
};
use secrecy::ExposeSecret;
use zeroize::Zeroizing;

static ENV_MUTEX: Mutex<()> = Mutex::new(());

/// `keyring` is never consulted by keychain-sync; this provider proves it by failing loudly.
struct NeverKeyring;

impl EntryProvider for NeverKeyring {
    fn get_password(&self, service: &str, account: &str) -> Result<String, EntryError> {
        panic!("keyring consulted for {service}/{account} — keychain-sync must never use it")
    }
}

/// The legacy File-mode provider (NotFound → env fallback / mint).
struct NoEntry;

impl EntryProvider for NoEntry {
    fn get_password(&self, _: &str, _: &str) -> Result<String, EntryError> {
        Err(EntryError::NotFound("none".into()))
    }
}

fn sync_cfg(env: &str, namespace: &str, synchronizable: bool) -> SecretsConfig {
    SecretsConfig {
        master_key_source: MasterKeySource::KeychainSync,
        env_var_name: env.into(),
        keychain: Some(KeychainSyncConfig {
            access_group: None,
            namespace: namespace.into(),
            synchronizable,
        }),
        dependencies: HashMap::new(),
    }
}

fn file_cfg(env: &str) -> SecretsConfig {
    SecretsConfig {
        master_key_source: MasterKeySource::EnvVar,
        env_var_name: env.into(),
        keychain: None,
        dependencies: HashMap::new(),
    }
}

fn home() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join(".advance")).unwrap();
    dir
}

fn no_file_artifacts(home: &Path) {
    assert!(
        !home.join(".advance/secrets.json").exists(),
        "keychain-sync must not write secrets.json"
    );
    assert!(
        !home.join(".advance/master.key").exists(),
        "keychain-sync must not write master.key"
    );
}

fn secrets_item(namespace: &str, account: &str, synchronizable: bool) -> KeychainItem {
    KeychainItem {
        service: format!("agents.advance.{namespace}.secrets"),
        account: account.into(),
        synchronizable,
        access_group: None,
    }
}

fn master_item(namespace: &str, synchronizable: bool) -> KeychainItem {
    KeychainItem {
        service: format!("agents.advance.{namespace}.master"),
        account: "master-key".into(),
        synchronizable,
        access_group: None,
    }
}

fn with_env_unset<F: FnOnce()>(env: &str, f: F) {
    let _g = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    std::env::remove_var(env);
    f();
    std::env::remove_var(env);
}

fn with_env<F: FnOnce()>(env: &str, value: &str, f: F) {
    let _g = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var(env, value);
    f();
    std::env::remove_var(env);
}

fn ops_arc(ops: &Arc<MockSecItemOps>) -> Option<Arc<dyn SecItemOps>> {
    Some(ops.clone() as Arc<dyn SecItemOps>)
}

// ── KS-01: store/resolve round-trip lives in the keychain only ───────────────────────────────
#[test]
fn ks01_roundtrip_writes_keychain_items_and_no_files() {
    let env = "ADV_KS01_MK";
    with_env_unset(env, || {
        let dir = home();
        let ops = MockSecItemOps::new();
        let cfg = sync_cfg(env, "ks01", true);
        assert_eq!(backend_of(&cfg), SecretsBackend::KeychainSync);
        let opened = open_secret_store(
            dir.path(),
            &cfg,
            &NeverKeyring,
            ops_arc(&ops),
            MasterKeyPolicy::Ensure,
        )
        .expect("empty namespace mints a master key");
        let store = opened.into_store();
        store.store("anthropic-api-key", "sk-ant-ks01").unwrap();
        assert_eq!(
            store.resolve("anthropic-api-key").unwrap().expose_secret(),
            "sk-ant-ks01"
        );
        assert!(store.exists("anthropic-api-key").unwrap());
        assert_eq!(store.names(), vec!["anthropic-api-key".to_string()]);
        no_file_artifacts(dir.path());
        assert!(ops.contains(&master_item("ks01", true)));
        assert!(ops.contains(&secrets_item("ks01", "anthropic-api-key", true)));
        // The raw item never holds the plaintext.
        let raw = ops
            .data(&secrets_item("ks01", "anthropic-api-key", true))
            .unwrap();
        assert!(!raw.windows(11).any(|w| w == b"sk-ant-ks01"));
        assert_eq!(raw[0], 1, "value format version");

        // A second open (daemon restart) resolves through the same items.
        let again = open_secret_store(
            dir.path(),
            &cfg,
            &NeverKeyring,
            ops_arc(&ops),
            MasterKeyPolicy::Resolve,
        )
        .unwrap()
        .into_store();
        assert_eq!(
            again.resolve("anthropic-api-key").unwrap().expose_secret(),
            "sk-ant-ks01"
        );
        assert!(again.remove("anthropic-api-key").unwrap());
        assert!(!ops.contains(&secrets_item("ks01", "anthropic-api-key", true)));
        no_file_artifacts(dir.path());
    });
}

// ── KS-02: keychain unavailable fails closed (no mint, no files) ─────────────────────────────
#[test]
fn ks02_keychain_unavailable_fails_closed() {
    let env = "ADV_KS02_MK";
    with_env_unset(env, || {
        let dir = home();
        let ops = MockSecItemOps::new();
        ops.fail_with(SecItemError::missing_entitlement());
        let cfg = sync_cfg(env, "ks02", true);
        for policy in [MasterKeyPolicy::Ensure, MasterKeyPolicy::Resolve] {
            let err = open_secret_store(dir.path(), &cfg, &NeverKeyring, ops_arc(&ops), policy)
                .err()
                .expect("must fail closed");
            let text = format!("{err}");
            assert!(matches!(err, SecretError::KeyLoad(_)), "{text}");
            assert!(text.contains("keychain unavailable"), "{text}");
            assert!(text.contains("-34018"), "{text}");
        }
        assert!(ops.is_empty(), "nothing minted while unavailable");
        no_file_artifacts(dir.path());
    });
}

// ── KS-03: env var wins and is persisted into an empty keychain namespace ────────────────────
#[test]
fn ks03_env_var_first_then_keychain() {
    let env = "ADV_KS03_MK";
    let hex = "0f".repeat(32);
    let dir = home();
    let ops = MockSecItemOps::new();
    let cfg = sync_cfg(env, "ks03", true);
    with_env(env, &hex, || {
        let key = load_master_key_for(
            dir.path(),
            &cfg,
            &NeverKeyring,
            ops_arc(&ops),
            MasterKeyPolicy::Resolve,
        )
        .unwrap();
        assert_eq!(hex::encode(&key[..]), hex);
        // Persisted so the next boot without the env var finds it.
        assert_eq!(
            ops.data(&master_item("ks03", true)).unwrap(),
            hex.as_bytes()
        );
    });
    with_env_unset(env, || {
        let key = load_master_key_for(
            dir.path(),
            &cfg,
            &NeverKeyring,
            ops_arc(&ops),
            MasterKeyPolicy::Resolve,
        )
        .unwrap();
        assert_eq!(hex::encode(&key[..]), hex);
    });
    // A DIFFERENT env key does not overwrite an existing keychain item; it wins for the
    // process only.
    let other = "1e".repeat(32);
    with_env(env, &other, || {
        let key = load_master_key_for(
            dir.path(),
            &cfg,
            &NeverKeyring,
            ops_arc(&ops),
            MasterKeyPolicy::Resolve,
        )
        .unwrap();
        assert_eq!(hex::encode(&key[..]), other);
        assert_eq!(
            ops.data(&master_item("ks03", true)).unwrap(),
            hex.as_bytes(),
            "keychain item untouched"
        );
    });
    no_file_artifacts(dir.path());
}

// ── KS-04: ciphertext without a master key → KeyLoad (never a fresh mint) ────────────────────
#[test]
fn ks04_no_mint_over_existing_ciphertext() {
    let env = "ADV_KS04_MK";
    with_env_unset(env, || {
        let dir = home();
        let ops = MockSecItemOps::new();
        let cfg = sync_cfg(env, "ks04", true);
        // A synced provider row exists (from another device), but the master item did not sync.
        ops.add(
            &secrets_item("ks04", "openai-api-key", true),
            b"\x01abcd\x00rest",
        )
        .unwrap();
        for policy in [MasterKeyPolicy::Ensure, MasterKeyPolicy::Resolve] {
            let err = open_secret_store(dir.path(), &cfg, &NeverKeyring, ops_arc(&ops), policy)
                .err()
                .expect("must not mint over ciphertext");
            assert!(matches!(err, SecretError::KeyLoad(_)), "{err}");
        }
        assert!(
            !ops.contains(&master_item("ks04", true)),
            "no master minted"
        );
        no_file_artifacts(dir.path());
    });
}

// ── KS-05: a row written under another master key → KeyMismatch with the clear reason ────────
#[test]
fn ks05_kid_mismatch_is_named() {
    let env = "ADV_KS05_MK";
    with_env_unset(env, || {
        let dir = home();
        let ops = MockSecItemOps::new();
        let cfg = sync_cfg(env, "ks05", true);
        let first = open_secret_store(
            dir.path(),
            &cfg,
            &NeverKeyring,
            ops_arc(&ops),
            MasterKeyPolicy::Ensure,
        )
        .unwrap()
        .into_store();
        first.store("k", "v").unwrap();
        // Simulate a re-minted master key on another device: replace the master item.
        ops.update(&master_item("ks05", true), "ab".repeat(32).as_bytes())
            .unwrap();
        let second = open_secret_store(
            dir.path(),
            &cfg,
            &NeverKeyring,
            ops_arc(&ops),
            MasterKeyPolicy::Resolve,
        )
        .unwrap()
        .into_store();
        let err = second.resolve("k").unwrap_err();
        assert!(matches!(err, SecretError::KeyMismatch), "{err}");
        let text = format!("{err}");
        assert!(text.contains("different master key"), "{text}");
        assert!(!text.contains("decrypt failed"), "{text}");
        // Storing under the current key repairs the row.
        second.store("k", "v2").unwrap();
        assert_eq!(second.resolve("k").unwrap().expose_secret(), "v2");
    });
}

// ── KS-06: file → keychain migration, verified, renamed, idempotent; then back ───────────────
#[test]
fn ks06_migration_roundtrip_idempotent() {
    let env = "ADV_KS06_MK";
    with_env_unset(env, || {
        let dir = home();
        let ops = MockSecItemOps::new();
        // Seed a File-mode home: master.key + secrets.json with two secrets.
        let file_cfg = file_cfg(env);
        let master = Zeroizing::new([0x5au8; 32]);
        std::fs::write(
            dir.path().join(".advance/master.key"),
            hex::encode(&master[..]),
        )
        .unwrap();
        {
            let storage: Arc<dyn SecretStorage> = Arc::new(
                FileSecretStorage::open(dir.path().join(".advance/secrets.json")).unwrap(),
            );
            let store = SecretStore::new(master.clone(), storage);
            store.store("anthropic-api-key", "sk-ant").unwrap();
            store.store("openai-api-key", "sk-oai").unwrap();
        }
        assert!(file_artifacts_present(dir.path()));
        assert_eq!(backend_of(&file_cfg), SecretsBackend::File);

        let sync_cfg = sync_cfg(env, "ks06", true);
        // Daemon-boot auto migration.
        let report = auto_migrate_if_needed(dir.path(), &sync_cfg, &NoEntry, ops_arc(&ops))
            .unwrap()
            .expect("artifacts present ⇒ migration runs");
        assert_eq!(
            report.migrated,
            vec![
                "anthropic-api-key".to_string(),
                "openai-api-key".to_string()
            ]
        );
        assert_eq!(report.renamed.len(), 2);
        assert!(!report.nothing_to_do);
        assert!(dir.path().join(".advance/secrets.json.migrated").is_file());
        assert!(dir.path().join(".advance/master.key.migrated").is_file());
        assert!(!file_artifacts_present(dir.path()));
        assert!(ops.contains(&master_item("ks06", true)));
        assert!(ops.contains(&secrets_item("ks06", "anthropic-api-key", true)));
        assert!(ops.contains(&secrets_item("ks06", "openai-api-key", true)));

        // The keychain store resolves both.
        let store = open_secret_store(
            dir.path(),
            &sync_cfg,
            &NeverKeyring,
            ops_arc(&ops),
            MasterKeyPolicy::Resolve,
        )
        .unwrap()
        .into_store();
        assert_eq!(
            store.resolve("anthropic-api-key").unwrap().expose_secret(),
            "sk-ant"
        );
        assert_eq!(
            store.resolve("openai-api-key").unwrap().expose_secret(),
            "sk-oai"
        );

        // Idempotent: a second boot does nothing.
        assert!(
            auto_migrate_if_needed(dir.path(), &sync_cfg, &NoEntry, ops_arc(&ops))
                .unwrap()
                .is_none()
        );
        // Explicit file→keychain with nothing left is a no-op report.
        let again =
            migrate_file_to_keychain(dir.path(), &sync_cfg, &NoEntry, ops_arc(&ops)).unwrap();
        assert!(again.nothing_to_do);

        // Back to File: secrets.json reappears under a File master key; keychain items stay.
        let back =
            migrate_keychain_to_file(dir.path(), &sync_cfg, &NoEntry, ops_arc(&ops)).unwrap();
        assert_eq!(back.migrated.len(), 2);
        assert!(dir.path().join(".advance/secrets.json").is_file());
        assert!(dir.path().join(".advance/master.key").is_file());
        assert!(ops.contains(&secrets_item("ks06", "anthropic-api-key", true)));
        let file_store = open_secret_store(
            dir.path(),
            &file_cfg,
            &NoEntry,
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
            "sk-oai"
        );
        assert_eq!(MigrationTarget::parse("file"), Some(MigrationTarget::File));
    });
}

// ── KS-07: synchronizable → ThisDeviceOnly keeps the synced items ────────────────────────────
#[test]
fn ks07_synchronizable_toggle_keeps_synced_items() {
    let env = "ADV_KS07_MK";
    with_env_unset(env, || {
        let dir = home();
        let ops = MockSecItemOps::new();
        let synced = open_secret_store(
            dir.path(),
            &sync_cfg(env, "ks07", true),
            &NeverKeyring,
            ops_arc(&ops),
            MasterKeyPolicy::Ensure,
        )
        .unwrap()
        .into_store();
        synced.store("k", "v").unwrap();
        let before = ops.len();

        let local = open_secret_store(
            dir.path(),
            &sync_cfg(env, "ks07", false),
            &NeverKeyring,
            ops_arc(&ops),
            MasterKeyPolicy::Resolve,
        )
        .unwrap()
        .into_store();
        assert_eq!(local.resolve("k").unwrap().expose_secret(), "v");
        assert!(
            ops.contains(&master_item("ks07", false)),
            "local master copy"
        );
        assert!(
            ops.contains(&secrets_item("ks07", "k", false)),
            "local row copy"
        );
        assert!(ops.contains(&master_item("ks07", true)));
        assert!(ops.contains(&secrets_item("ks07", "k", true)));
        assert_eq!(ops.len(), before + 2, "copies added, nothing removed");
        // Local writes stay local.
        local.store("k", "v-local").unwrap();
        assert_eq!(synced.resolve("k").unwrap().expose_secret(), "v");
        assert_eq!(local.resolve("k").unwrap().expose_secret(), "v-local");
        assert!(local.remove("k").unwrap());
        assert!(
            ops.contains(&secrets_item("ks07", "k", true)),
            "never deletes the synced row"
        );
    });
}

// ── KS-08: unkeyed handle lists names and removes without a master key ───────────────────────
#[test]
fn ks08_unkeyed_list_and_remove() {
    let env = "ADV_KS08_MK";
    with_env_unset(env, || {
        let dir = home();
        let ops = MockSecItemOps::new();
        let cfg = sync_cfg(env, "ks08", true);
        open_secret_store(
            dir.path(),
            &cfg,
            &NeverKeyring,
            ops_arc(&ops),
            MasterKeyPolicy::Ensure,
        )
        .unwrap()
        .into_store()
        .store("a", "1")
        .unwrap();
        let unkeyed = open_secret_storage_unkeyed(dir.path(), &cfg, ops_arc(&ops)).unwrap();
        assert_eq!(unkeyed.names(), vec!["a".to_string()]);
        assert!(unkeyed.remove("a").unwrap());
        assert!(unkeyed.names().is_empty());
    });
}

// ── KS-09: platform gate ─────────────────────────────────────────────────────────────────────
#[test]
fn ks09_platform_gate_matches_target() {
    assert_eq!(
        platform_supports_keychain_sync(),
        cfg!(target_vendor = "apple")
    );
    #[cfg(not(target_vendor = "apple"))]
    {
        let dir = home();
        let err = open_secret_store(
            dir.path(),
            &sync_cfg("ADV_KS09_MK", "ks09", true),
            &NeverKeyring,
            None,
            MasterKeyPolicy::Ensure,
        )
        .err()
        .expect("non-Apple keychain-sync fails closed");
        assert!(format!("{err}").contains("unsupported on this platform"));
    }
}

// ── KS-10: File modes are untouched by the factory ───────────────────────────────────────────
#[test]
fn ks10_file_mode_through_factory_is_the_legacy_layout() {
    let env = "ADV_KS10_MK";
    let hex = "3c".repeat(32);
    with_env(env, &hex, || {
        let dir = home();
        let cfg = file_cfg(env);
        let store = open_secret_store(dir.path(), &cfg, &NoEntry, None, MasterKeyPolicy::Ensure)
            .unwrap()
            .into_store();
        store.store("n", "v").unwrap();
        assert!(dir.path().join(".advance/secrets.json").is_file());
        assert!(
            dir.path().join(".advance/master.key").is_file(),
            "ensure_master_key persists the env key into the workspace file"
        );
        let unkeyed = open_secret_storage_unkeyed(dir.path(), &cfg, None).unwrap();
        assert_eq!(unkeyed.names(), vec!["n".to_string()]);
    });
}

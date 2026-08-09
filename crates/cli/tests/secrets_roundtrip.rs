//! /dev WS-A — `advance secrets set` → `FileSecretStorage` → daemon-equivalent
//! resolve round-trip (test case 7).
//!
//! Proves the operator path the e2e spine relies on: `advance secrets set`
//! reads a value from stdin, encrypts it under the master key, and persists the
//! ciphertext to `<ws>/.advance/secrets.json`; a `SecretStore` built over
//! `FileSecretStorage` with the SAME master key (exactly what `advance start`
//! constructs in `wiring.rs`) resolves it back at request time. Also exercises
//! `secrets list` + `secrets remove`.

use std::sync::Arc;

use cap_secrets::{FileSecretStorage, SecretStorage, SecretStore};
use secrecy::ExposeSecret;
use zeroize::Zeroizing;

/// 64 hex chars = the 32-byte master key `[0x5a; 32]`. The CLI child reads this
/// via `$SECRETS_MASTER_KEY`; `init_workspace` pins the scaffolded config to
/// `master-key-source: env-var` so the child loads THIS key deterministically,
/// independent of the dev machine's OS keychain. (The scaffold default is
/// `keychain` — correct for production, where `advance secrets set` and
/// `advance start` both consult the keychain consistently. But this test's
/// resolve side hardcodes these same 32 bytes in-process; if the child instead
/// picked up a real `advance-agents/master-key` keychain entry, set would
/// encrypt under that key while resolve decrypts under `[0x5a; 32]`, surfacing
/// as `aes-gcm decrypt failed`.) The in-process resolve side uses the identical
/// 32 bytes directly, so set and resolve share the same key.
const MASTER_KEY_HEX: &str = "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";

fn advance_bin() -> std::path::PathBuf {
    assert_cmd::cargo::cargo_bin("advance")
}

fn init_workspace(dir: &tempfile::TempDir) -> std::path::PathBuf {
    let ws = dir.path().to_path_buf();
    let status = std::process::Command::new(advance_bin())
        .arg("init")
        .arg(&ws)
        .status()
        .expect("spawn advance init");
    assert!(status.success(), "advance init failed: {status:?}");
    // Hermeticity: pin `master-key-source: env-var` so the spawned `advance`
    // children load the master key from `$SECRETS_MASTER_KEY` deterministically,
    // regardless of whether the dev machine's OS keychain has an
    // `advance-agents/master-key` entry. (See MASTER_KEY_HEX.) Production keeps
    // the scaffold's `keychain` default; this override is test-local.
    let cfg_path = ws.join(".advance").join("runtime-config.yaml");
    let cfg = std::fs::read_to_string(&cfg_path).expect("read runtime-config.yaml");
    assert!(
        cfg.contains("master-key-source: keychain"),
        "scaffolded config should default to keychain source"
    );
    let cfg = cfg.replace("master-key-source: keychain", "master-key-source: env-var");
    std::fs::write(&cfg_path, cfg).expect("write runtime-config.yaml");
    ws
}

#[test]
fn secrets_set_then_daemon_resolves_then_remove() {
    let dir = tempfile::tempdir().unwrap();
    let ws = init_workspace(&dir);

    // `advance secrets set anthropic-api-key` — value piped on stdin (NOT argv).
    assert_cmd::Command::cargo_bin("advance")
        .unwrap()
        .env("SECRETS_MASTER_KEY", MASTER_KEY_HEX)
        .args(["secrets", "set", "anthropic-api-key", "--workspace"])
        .arg(&ws)
        .write_stdin("sk-ant-test-value")
        .assert()
        .success();

    let secrets_path = ws.join(".advance").join("secrets.json");
    assert!(
        secrets_path.is_file(),
        "secrets.json should exist after `secrets set`"
    );

    // `advance secrets list` shows the NAME (never the value).
    assert_cmd::Command::cargo_bin("advance")
        .unwrap()
        .args(["secrets", "list", "--workspace"])
        .arg(&ws)
        .assert()
        .success()
        .stdout(predicates::str::contains("anthropic-api-key"));

    // Daemon-equivalent resolve: a SecretStore over FileSecretStorage with the
    // SAME master key decrypts the value back — proving `advance secrets set`
    // wrote a blob `advance start` can resolve at LLM-request time.
    let key = Zeroizing::new([0x5au8; 32]);
    let storage: Arc<dyn SecretStorage> =
        Arc::new(FileSecretStorage::open(&secrets_path).expect("open secrets.json"));
    let store = SecretStore::new(key, storage);
    let resolved = store
        .resolve("anthropic-api-key")
        .expect("resolve stored secret");
    assert_eq!(resolved.expose_secret(), "sk-ant-test-value");

    // `advance secrets remove` deletes it.
    assert_cmd::Command::cargo_bin("advance")
        .unwrap()
        .args(["secrets", "remove", "anthropic-api-key", "--workspace"])
        .arg(&ws)
        .assert()
        .success();
    let after = FileSecretStorage::open(&secrets_path).expect("reopen secrets.json");
    assert!(
        after.names().is_empty(),
        "secret should be gone after `secrets remove`"
    );
}

#[test]
fn secrets_set_rejects_empty_stdin() {
    let dir = tempfile::tempdir().unwrap();
    let ws = init_workspace(&dir);
    // Empty stdin → friendly failure, not a stored empty secret.
    assert_cmd::Command::cargo_bin("advance")
        .unwrap()
        .env("SECRETS_MASTER_KEY", MASTER_KEY_HEX)
        .args(["secrets", "set", "anthropic-api-key", "--workspace"])
        .arg(&ws)
        .write_stdin("")
        .assert()
        .failure();
    assert!(
        !ws.join(".advance").join("secrets.json").exists(),
        "no secrets.json should be written for an empty value"
    );
}

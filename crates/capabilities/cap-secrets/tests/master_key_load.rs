//! T19 (MODULE-012-AC-03): master-key loader integration tests.
//!
//! All sub-cases are serialized via a static Mutex because they
//! manipulate the `SECRETS_MASTER_KEY` env var. `SECRETS_MASTER_KEY`
//! is read by no other code in this test binary (the `load_master_key`
//! under test is the only reader), so per-binary serialization is
//! sufficient.

use std::sync::Mutex;

use cap_secrets::{load_master_key, EntryError, EntryProvider, MasterKeyConfig, SecretError};

static TEST_MUTEX: Mutex<()> = Mutex::new(());

const ENV_VAR: &str = "SECRETS_MASTER_KEY";

// A valid 32-byte key encoded as 64 hex chars.
const VALID_HEX_32: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

struct TestEntryProvider {
    result: Result<String, EntryError>,
}

impl TestEntryProvider {
    fn ok(s: &str) -> Self {
        Self {
            result: Ok(s.to_string()),
        }
    }

    fn not_found() -> Self {
        Self {
            result: Err(EntryError::NotFound("test/fixture".into())),
        }
    }
}

impl EntryProvider for TestEntryProvider {
    fn get_password(&self, _service: &str, _account: &str) -> Result<String, EntryError> {
        self.result.clone()
    }
}

/// RAII guard that restores the prior env-var state on drop (runs even
/// on panic, so a failing test does not leak `SECRETS_MASTER_KEY` to
/// subsequent tests in this binary).
///
/// SAFETY: `std::env::set_var` / `remove_var` are documented by the
/// Rust std as unsound in multithreaded non-Windows programs when other
/// threads read the environment concurrently. Mitigation:
/// (a) every call here holds the `TEST_MUTEX` guard → single-threaded
/// access to the env-var table for the duration of mutation.
/// (b) `SECRETS_MASTER_KEY` is read by no other thread in this test
/// binary (the `load_master_key` under test is the only reader).
/// (c) no C library with its own `getenv`-style reader is invoked during
/// the test.
/// Therefore the std hazard does not apply in practice.
struct EnvGuard {
    prior: Option<String>,
    // Drop order: the std::sync::MutexGuard is held as long as this
    // struct lives, keeping the serialization invariant during restore.
    _mutex_guard: std::sync::MutexGuard<'static, ()>,
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        match &self.prior {
            Some(v) => std::env::set_var(ENV_VAR, v),
            None => std::env::remove_var(ENV_VAR),
        }
    }
}

fn with_env<F: FnOnce()>(value: Option<&str>, f: F) {
    let mutex_guard = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let prior = std::env::var(ENV_VAR).ok();
    // Move the mutex guard into the EnvGuard so Drop restores the env-var
    // state *and* releases the mutex in that order — even on panic.
    let _guard = EnvGuard {
        prior,
        _mutex_guard: mutex_guard,
    };
    match value {
        Some(v) => std::env::set_var(ENV_VAR, v),
        None => std::env::remove_var(ENV_VAR),
    }
    f();
    // _guard drops here (normal path): env-var restored, then mutex released.
}

// ---------- EnvVar arm ----------

#[test]
fn t19_1_envvar_valid_hex_succeeds() {
    with_env(Some(VALID_HEX_32), || {
        let cfg = MasterKeyConfig::EnvVar(ENV_VAR.into());
        let provider = TestEntryProvider::not_found();
        let key = load_master_key(&cfg, &provider).expect("should succeed");
        assert_eq!(key.as_ref().len(), 32);
        // First byte of "0123..." hex = 0x01
        assert_eq!(key.as_ref()[0], 0x01);
    });
}

#[test]
fn t19_2_envvar_unset_fails_key_load() {
    with_env(None, || {
        let cfg = MasterKeyConfig::EnvVar(ENV_VAR.into());
        let provider = TestEntryProvider::not_found();
        match load_master_key(&cfg, &provider) {
            Err(SecretError::KeyLoad(_)) => {}
            other => panic!("expected KeyLoad, got {other:?}"),
        }
    });
}

#[test]
fn t19_3_envvar_invalid_hex_fails_key_load() {
    with_env(Some("not-hex-at-all-xx"), || {
        let cfg = MasterKeyConfig::EnvVar(ENV_VAR.into());
        let provider = TestEntryProvider::not_found();
        match load_master_key(&cfg, &provider) {
            Err(SecretError::KeyLoad(_)) => {}
            other => panic!("expected KeyLoad, got {other:?}"),
        }
    });
}

#[test]
fn t19_4_envvar_wrong_length_fails_key_load() {
    // 24 bytes = 48 hex chars, not 64.
    let short_hex = "0123456789abcdef0123456789abcdef0123456789abcdef";
    with_env(Some(short_hex), || {
        let cfg = MasterKeyConfig::EnvVar(ENV_VAR.into());
        let provider = TestEntryProvider::not_found();
        match load_master_key(&cfg, &provider) {
            Err(SecretError::KeyLoad(msg)) => {
                assert!(
                    msg.contains("32 bytes") || msg.contains("got "),
                    "expected length error, got {msg:?}"
                );
            }
            other => panic!("expected KeyLoad, got {other:?}"),
        }
    });
}

// ---------- Keychain arm ----------

#[test]
fn t19_5_keychain_not_found_then_envvar_fallback_succeeds() {
    // AC-03 happy path: Keychain miss → env-var fallback resolves.
    with_env(Some(VALID_HEX_32), || {
        let cfg = MasterKeyConfig::Keychain {
            service: "advance-agents".into(),
            account: "master-key".into(),
            fallback_env_var: Some(ENV_VAR.into()),
        };
        let provider = TestEntryProvider::not_found();
        let key = load_master_key(&cfg, &provider).expect("should succeed via fallback");
        assert_eq!(key.as_ref().len(), 32);
    });
}

#[test]
fn t19_6_keychain_not_found_no_fallback_fails() {
    // Hold the mutex because we don't want a concurrent test setting
    // SECRETS_MASTER_KEY to accidentally "rescue" this case.
    let _g = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let cfg = MasterKeyConfig::Keychain {
        service: "advance-agents".into(),
        account: "master-key".into(),
        fallback_env_var: None,
    };
    let provider = TestEntryProvider::not_found();
    match load_master_key(&cfg, &provider) {
        Err(SecretError::KeyLoad(msg)) => {
            assert!(
                msg.contains("no fallback"),
                "expected 'no fallback' message, got {msg:?}"
            );
        }
        other => panic!("expected KeyLoad, got {other:?}"),
    }
}

#[test]
fn t19_7_keychain_ok_decodes_and_returns_key() {
    let _g = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let cfg = MasterKeyConfig::Keychain {
        service: "advance-agents".into(),
        account: "master-key".into(),
        fallback_env_var: None,
    };
    let provider = TestEntryProvider::ok(VALID_HEX_32);
    let key = load_master_key(&cfg, &provider).expect("should decode from keychain");
    assert_eq!(key.as_ref().len(), 32);
    assert_eq!(key.as_ref()[0], 0x01);
}

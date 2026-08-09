//! Integration tests covering previously-uncovered loader error paths +
//! master-key rotation defense (Slice m012-slice-a-2026-05-18 regression-lock).
//!
//! - T21 (t_int_01_entry_open_routes_through_keyload, all platforms):
//!   `EntryError::Open` routes through `SecretError::KeyLoad` with the
//!   correct Display chain. Locks master_key.rs:121-125 (uncovered by T19).
//!
//! - T22 (t_int_02_envvar_not_unicode_unix, Unix only):
//!   `VarError::NotUnicode` on the `EnvVar` arm produces the exact
//!   no-byte-echo error message. Locks master_key.rs:132-138.
//!
//! - T23 (t_int_03_keychain_fallback_not_unicode_unix, Unix only):
//!   `VarError::NotUnicode` on the Keychain → env-var fallback arm
//!   produces the exact no-byte-echo error message.
//!   Locks master_key.rs:109-113.
//!
//! - T24 (t_int_04_master_key_rotation_defense, all platforms):
//!   property test for HKDF-binding — encrypt under K1, attempt
//!   decrypt under K2 fails with `SecretError::Crypto`. Reinforces
//!   the already-covered Crypto-error branch with a previously-
//!   implicit master-binding trigger.
//!
//! No source-tree change to `crates/capabilities/cap-secrets/src/`.
//! No new dependencies. T22/T23 are `#[cfg(unix)]` because non-UTF-8
//! `OsString` construction uses `std::os::unix::ffi::OsStringExt`.

use std::sync::Arc;
use std::sync::Mutex;

use cap_secrets::{
    load_master_key, EntryError, EntryProvider, InMemorySecretStorage, MasterKeyConfig,
    SecretError, SecretStorage, SecretStore,
};
use zeroize::Zeroizing;

/// Test-binary-local EntryProvider mock with three outcomes. Distinct
/// from `master_key_load.rs::TestEntryProvider` (separate test binary —
/// each `tests/*.rs` compiles to its own integration crate).
struct TestEntryProvider {
    result: Result<String, EntryError>,
}

impl TestEntryProvider {
    fn not_found() -> Self {
        Self {
            result: Err(EntryError::NotFound("test/fixture".into())),
        }
    }

    fn open_err(msg: &str) -> Self {
        Self {
            result: Err(EntryError::Open(msg.to_string())),
        }
    }
}

impl EntryProvider for TestEntryProvider {
    fn get_password(&self, _service: &str, _account: &str) -> Result<String, EntryError> {
        self.result.clone()
    }
}

// ─── T21 — EntryError::Open routed through SecretError::KeyLoad ───────────

#[test]
fn t_int_01_entry_open_routes_through_keyload() {
    let provider = TestEntryProvider::open_err("simulated keychain open failure");
    let cfg = MasterKeyConfig::Keychain {
        service: "advance-agents-test".into(),
        account: "master-key-test".into(),
        fallback_env_var: None,
    };

    // Render Display BEFORE the match — `SecretError` is non-Copy and
    // the match below consumes `err`. The "master key load failed:"
    // prefix is added by `SecretError::Display` (error.rs:36); the
    // inner `KeyLoad(msg)` carries only the inner text, so the prefix
    // check MUST be on the full Display output.
    let err = load_master_key(&cfg, &provider).unwrap_err();
    let display = format!("{err}");

    match err {
        SecretError::KeyLoad(_) => {}
        other => panic!("expected KeyLoad, got {other:?}"),
    }

    assert!(
        display.starts_with("master key load failed:"),
        "missing outer SecretError::Display prefix: {display:?}"
    );
    assert!(
        display.contains("keychain entry open failed:"),
        "missing inner EntryError::Open Display: {display:?}"
    );
    assert!(
        display.contains("simulated keychain open failure"),
        "missing round-tripped provider message: {display:?}"
    );
}

// ─── T22/T23 — VarError::NotUnicode no-byte-echo defense (Unix only) ──────

#[cfg(unix)]
mod not_unicode_env_tests {
    use super::*;
    use std::env;
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    static ENV_TEST_MUTEX: Mutex<()> = Mutex::new(());

    /// RAII guard that snapshots and restores an OsString-typed env var
    /// using `var_os` (so non-UTF-8 prior values are preserved, unlike
    /// the UTF-8-only `master_key_load.rs::EnvGuard`). Drop order:
    /// env-var restored, THEN mutex released (the mutex is held in the
    /// `_mutex_guard` field for the lifetime of this struct).
    ///
    /// SAFETY: `std::env::set_var` / `remove_var` are documented by the
    /// Rust std as unsound in multithreaded non-Windows programs when
    /// other threads read the environment concurrently (Rust 2024
    /// makes both `unsafe fn`). Mitigation in this binary is partial:
    /// (a) every call here holds the `ENV_TEST_MUTEX` guard →
    ///     single-threaded access to the env-var TABLE (the WRITE
    ///     side) for the duration of mutation. T22 and T23 cannot
    ///     race each other's `set_var`/`remove_var`.
    /// (b) the env-var names used here (`SECRETS_ENC_TEST_KEY_T02`,
    ///     `SECRETS_ENC_TEST_KEY_T03`) are read by no other code in
    ///     this test binary that we wrote (the `load_master_key`
    ///     under test is our only reader).
    /// (c) no C library that uses its own getenv-style reader is
    ///     invoked from our test path (T22/T23 use `TestEntryProvider`
    ///     not `DefaultEntryProvider`/`keyring::Entry`).
    /// Residual hazard NOT fully mitigated: cargo's own libtest
    /// worker threads call `getenv` on common runtime vars
    /// (`RUST_BACKTRACE`, `RUST_TEST_TIME_*`, locale vars, etc.)
    /// during test scheduling and panic-format paths. Our mutex
    /// covers our writers but cannot block libtest's transitive
    /// reader paths at the C library level. In practice this surface
    /// has not been observed to manifest in this project's CI
    /// (matches the pre-existing `master_key_load.rs::EnvGuard`
    /// posture), but the "does not apply in practice" framing of
    /// the prior comment was too strong — flagged by ADVERSARIAL
    /// round 11 W2 (2026-05-18). Accept residual exposure for this
    /// test-only code surface.
    struct EnvOsGuard {
        name: String,
        prior: Option<OsString>,
        _mutex_guard: std::sync::MutexGuard<'static, ()>,
    }

    impl Drop for EnvOsGuard {
        fn drop(&mut self) {
            match &self.prior {
                Some(v) => env::set_var(&self.name, v),
                None => env::remove_var(&self.name),
            }
        }
    }

    fn with_env_os<F: FnOnce()>(name: &str, value: Option<OsString>, f: F) {
        let mutex_guard = ENV_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let prior = env::var_os(name);
        let _guard = EnvOsGuard {
            name: name.to_string(),
            prior,
            _mutex_guard: mutex_guard,
        };
        match value {
            Some(v) => env::set_var(name, &v),
            None => env::remove_var(name),
        }
        f();
        // _guard drops here: env-var restored, then mutex released.
    }

    fn invalid_utf8_os() -> OsString {
        OsString::from_vec(vec![0xff, 0xfe, 0xfd])
    }

    fn assert_no_byte_leak(msg: &str) {
        let bytes = msg.as_bytes();
        assert!(!bytes.contains(&0xff), "msg leaked byte 0xff: {msg:?}");
        assert!(!bytes.contains(&0xfe), "msg leaked byte 0xfe: {msg:?}");
        assert!(!bytes.contains(&0xfd), "msg leaked byte 0xfd: {msg:?}");
        assert!(
            !msg.contains('\u{fffd}'),
            "msg leaked U+FFFD (lossy conversion): {msg:?}"
        );
    }

    #[test]
    fn t_int_02_envvar_not_unicode_unix() {
        let env_name = "SECRETS_ENC_TEST_KEY_T02";
        with_env_os(env_name, Some(invalid_utf8_os()), || {
            let provider = TestEntryProvider::not_found();
            let cfg = MasterKeyConfig::EnvVar(env_name.into());

            let err = load_master_key(&cfg, &provider).unwrap_err();
            let msg = format!("{err}");

            match err {
                SecretError::KeyLoad(_) => {}
                other => panic!("expected KeyLoad, got {other:?}"),
            }

            assert_eq!(
                msg,
                "master key load failed: env var SECRETS_ENC_TEST_KEY_T02 contains non-UTF-8 bytes",
                "Display chain regressed (expected exact text)"
            );
            assert_no_byte_leak(&msg);
        });
    }

    #[test]
    fn t_int_03_keychain_fallback_not_unicode_unix() {
        let env_name = "SECRETS_ENC_TEST_KEY_T03";
        with_env_os(env_name, Some(invalid_utf8_os()), || {
            let provider = TestEntryProvider::not_found();
            let cfg = MasterKeyConfig::Keychain {
                service: "advance-agents-test".into(),
                account: "master-key-test".into(),
                fallback_env_var: Some(env_name.into()),
            };

            let err = load_master_key(&cfg, &provider).unwrap_err();
            let msg = format!("{err}");

            match err {
                SecretError::KeyLoad(_) => {}
                other => panic!("expected KeyLoad, got {other:?}"),
            }

            assert_eq!(
                msg,
                "master key load failed: keychain NotFound; env var SECRETS_ENC_TEST_KEY_T03 contains non-UTF-8 bytes",
                "Display chain regressed (expected exact text)"
            );
            assert_no_byte_leak(&msg);
        });
    }
}

// ─── T24 — Master-key rotation defense (property test) ────────────────────

#[test]
fn t_int_04_master_key_rotation_defense() {
    use secrecy::ExposeSecret;

    let storage: Arc<dyn SecretStorage> = Arc::new(InMemorySecretStorage::new());

    // Encrypt "v" under master K1.
    let store_a = SecretStore::new(Zeroizing::new([0x11u8; 32]), Arc::clone(&storage));
    store_a.store("k", "v").unwrap();

    // Attempt to decrypt under master K2 — same backing storage, SAME
    // secret name "k" so AAD is constant. Failure must be attributable
    // to HKDF-derived per-secret key mismatch under different masters,
    // NOT AAD-mismatch (the row-swap-attack failure mode covered by
    // `test_resolve_row_swap_returns_crypto_error` at store.rs:260).
    let store_b = SecretStore::new(Zeroizing::new([0x22u8; 32]), Arc::clone(&storage));
    match store_b.resolve("k").unwrap_err() {
        SecretError::Crypto(_) => {}
        other => panic!("expected Crypto, got {other:?}"),
    }

    // Soft sanity check: store_a still decrypts the row. Locks
    // `SecretStore::resolve` does-not-call-`put` semantic via
    // `InMemorySecretStorage::get`'s clone behavior (storage.rs:87).
    // If the storage backend later swaps to SQLite, this assertion's
    // meaning would shift — kept as soft sanity check only.
    assert_eq!(store_a.resolve("k").unwrap().expose_secret(), "v");
}

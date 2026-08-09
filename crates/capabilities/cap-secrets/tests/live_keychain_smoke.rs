//! REQ-095 live-platform smoke — MANUAL, dev-machine only.
//!
//! Run explicitly with:
//!   cargo test -p cap-secrets --test live_keychain_smoke -- --ignored
//!
//! Exercises the REAL OS credential store (macOS Keychain Services / Linux
//! secret-service) through the production `DefaultEntryProvider` — the one
//! leg the mocked `EntryProvider` suites (`master_key_load.rs`,
//! `encryption.rs`) deliberately do not touch. `#[ignore]`d because CI has
//! no interactive credential store (macOS TCC consent / D-Bus session — the
//! MODULE-012 §3.6 REQ-095 pin); witnessed manually per the user-directed
//! 2026-07-04 decision, result recorded in MODULE-012 §3.6 + REQ-095.
//!
//! Hygiene: uses a unique per-run service name and deletes the credential in
//! all paths (best-effort) so repeated runs never leak entries into the
//! developer's keychain.

use cap_secrets::master_key::{
    load_master_key, DefaultEntryProvider, EntryError, EntryProvider, MasterKeyConfig,
};

const ACCOUNT: &str = "req095-smoke";

fn unique_service() -> String {
    // No wall-clock dependence beyond uniqueness; pid keeps concurrent runs apart.
    format!("advance-agents-req095-smoke-{}", std::process::id())
}

/// Roundtrip against the REAL credential store: write via `keyring::Entry`
/// (the same crate the production provider wraps), read back through the
/// PRODUCTION `DefaultEntryProvider`, then drive the full production
/// `load_master_key` Keychain arm, then delete and verify the production
/// NotFound mapping.
#[test]
#[ignore = "live OS credential store — manual dev-machine smoke (REQ-095); CI has no TCC/D-Bus"]
fn req095_live_keychain_roundtrip_through_production_provider() {
    let service = unique_service();
    let key_hex = "a3f1c2d4e5b6978800112233445566778899aabbccddeeff0123456789abcdef";

    let entry = keyring::Entry::new(&service, ACCOUNT).expect("open live keychain entry");
    entry
        .set_password(key_hex)
        .expect("write to the LIVE OS credential store");

    // Guarantee cleanup even on assertion failure below.
    struct Cleanup(String);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            if let Ok(e) = keyring::Entry::new(&self.0, ACCOUNT) {
                let _ = e.delete_password();
            }
        }
    }
    let _cleanup = Cleanup(service.clone());

    // Production read path.
    let provider = DefaultEntryProvider;
    let read = provider
        .get_password(&service, ACCOUNT)
        .expect("production DefaultEntryProvider reads the live store");
    assert_eq!(read, key_hex, "live store returns the exact stored value");

    // Full production chain: config -> live provider -> hex decode -> 32-byte key.
    let cfg = MasterKeyConfig::Keychain {
        service: service.clone(),
        account: ACCOUNT.to_string(),
        fallback_env_var: None,
    };
    let key = load_master_key(&cfg, &provider)
        .expect("load_master_key over the LIVE keychain yields a 32-byte master key");
    assert_eq!(key.len(), 32);
    assert_eq!(hex::encode(&key[..]), key_hex);

    // Delete, then the PRODUCTION provider must map the live store's
    // no-entry answer to EntryError::NotFound (the env-fallback trigger).
    keyring::Entry::new(&service, ACCOUNT)
        .expect("reopen entry")
        .delete_password()
        .expect("delete live credential");
    match provider.get_password(&service, ACCOUNT) {
        Err(EntryError::NotFound(_)) => {}
        other => panic!("expected live NotFound after delete, got {other:?}"),
    }
}

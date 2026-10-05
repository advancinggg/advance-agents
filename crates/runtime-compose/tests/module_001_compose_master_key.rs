//! MODULE-001-AC-30 — `MasterKeyInput::Provided` is used as given: on a home whose config
//! names a master-key environment variable that is not set, the composition that reads the
//! key from the config fails, and the one given the key composes without minting, loading
//! or writing any key material (no `.advance/master.key`); a home that needs no key stays
//! keyless even when one is provided; and the options never print the key.
//!
//! The compositions of this binary run one at a time (`serial`).

#[path = "support/t111.rs"]
mod t111;

use std::sync::Arc;

use advance_runtime_compose::test_support::MemoryComposeLog;
use advance_runtime_compose::{compose, MasterKeyInput, Zeroizing};
use t111::{serial, T111Home, MASTER_KEY_ENV};

/// A master-key variable no test sets.
const UNSET_KEY_ENV: &str = "ADVANCE_T111_UNSET_MASTER_KEY";
const KEY: [u8; 32] = [0x5a; 32];

fn provided() -> MasterKeyInput {
    MasterKeyInput::Provided(Zeroizing::new(KEY))
}

#[tokio::test(flavor = "current_thread")]
async fn module_001_ac30_master_key_provided_used_as_given() {
    let _serial = serial();
    assert!(
        std::env::var_os(UNSET_KEY_ENV).is_none(),
        "{UNSET_KEY_ENV} is unset"
    );

    // A home that needs a key (llm), whose config names the unset variable.
    let home = T111Home::new(&["fs", "llm"], true);
    home.edit_runtime_config(|yaml| yaml.replace(MASTER_KEY_ENV, UNSET_KEY_ENV));
    let key_file = home.home.join(".advance/master.key");

    // Non-vacuity: the key the config names is unavailable.
    let from_config = compose(home.options(Arc::new(MemoryComposeLog::new())), Vec::new()).await;
    assert!(
        from_config.is_err(),
        "without the variable the config's key cannot be read"
    );
    assert!(!home.lock_path().exists());

    let options = home
        .options(Arc::new(MemoryComposeLog::new()))
        .with_master_key(provided());
    let debug = format!("{options:?}");
    assert!(
        !debug.contains("5a5a") && !debug.contains("90, 90"),
        "the options never print the key: {debug}"
    );
    let runtime = compose(options, Vec::new())
        .await
        .expect("composes with the provided key");
    assert!(!key_file.exists(), "no key material is written");
    runtime.shutdown().await.expect("shutdown");
    assert!(!key_file.exists(), "no key material is written");

    // A home that needs no key stays keyless.
    let keyless = T111Home::new(&["fs"], true);
    keyless.edit_runtime_config(|yaml| yaml.replace(MASTER_KEY_ENV, UNSET_KEY_ENV));
    let runtime = compose(
        keyless
            .options(Arc::new(MemoryComposeLog::new()))
            .with_master_key(provided()),
        Vec::new(),
    )
    .await
    .expect("a keyless home composes with a provided key");
    runtime.shutdown().await.expect("shutdown");
    assert!(
        !keyless.home.join(".advance/master.key").exists(),
        "no key material is written"
    );
}

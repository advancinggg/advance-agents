//! V12 — DEFAULT_DRIVER_LINEAGE upgrades previous CREATE_DRIVERs and leaves
//! custom hashes (and child agents) alone.

use std::fs;

use advance_home::{
    current_create_driver_sha256, maybe_upgrade_default_driver, upgrade_default_drivers_under,
    DriverUpgrade, DEFAULT_DRIVER_LINEAGE,
};

const CURRENT: &[u8] = include_bytes!("../src/fixtures/behavior.core.wasm");
const V0147: &[u8] = include_bytes!("../../runtime/tests/fixtures/guest-rust-llm-tools.core.wasm");
const CUSTOM: &[u8] = b"\0asm\x01\0\0\0custom-not-in-lineage-driver-bytes";

fn write_driver(workspace: &std::path::Path, bytes: &[u8]) {
    let agent = workspace.join(".agent");
    fs::create_dir_all(&agent).unwrap();
    fs::write(agent.join("behavior.wasm"), bytes).unwrap();
}

#[test]
fn v12_lineage_contains_historical_and_current() {
    assert!(DEFAULT_DRIVER_LINEAGE
        .iter()
        .any(|e| *e == "d431c8bf" || e.starts_with("d431c8bf")));
    assert!(DEFAULT_DRIVER_LINEAGE
        .iter()
        .any(|e| e.starts_with("0b0a3cce")));
    let current = current_create_driver_sha256();
    assert!(
        DEFAULT_DRIVER_LINEAGE.iter().any(|e| *e == current),
        "current CREATE_DRIVER hash belongs in the lineage"
    );
}

#[test]
fn v12_v0147_hash_is_upgraded_custom_is_untouched() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    write_driver(&home, V0147);

    match maybe_upgrade_default_driver(&home) {
        DriverUpgrade::Upgraded { from } => {
            assert!(
                from.starts_with("0b0a3cce"),
                "upgrade records the v0.1.47 hash, got {from}"
            );
        }
        other => panic!("v0.1.47 driver must be upgraded, got {other:?}"),
    }
    assert_eq!(
        fs::read(home.join(".agent").join("behavior.wasm")).unwrap(),
        CURRENT
    );

    match maybe_upgrade_default_driver(&home) {
        DriverUpgrade::Current => {}
        other => panic!("second pass on the current driver is Current, got {other:?}"),
    }

    let custom = tmp.path().join("custom");
    write_driver(&custom, CUSTOM);
    let before = fs::read(custom.join(".agent").join("behavior.wasm")).unwrap();
    match maybe_upgrade_default_driver(&custom) {
        DriverUpgrade::Custom { sha256 } => {
            assert!(!sha256.starts_with("0b0a3cce"));
            assert_ne!(sha256, current_create_driver_sha256());
        }
        other => panic!("custom hash must be left alone, got {other:?}"),
    }
    assert_eq!(
        fs::read(custom.join(".agent").join("behavior.wasm")).unwrap(),
        before
    );

    let missing = tmp.path().join("empty");
    fs::create_dir_all(missing.join(".agent")).unwrap();
    assert_eq!(
        maybe_upgrade_default_driver(&missing),
        DriverUpgrade::Missing
    );
}

#[test]
fn v12_child_agents_follow_the_same_rule() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    write_driver(&home, V0147);
    let child = home.join("researcher");
    write_driver(&child, V0147);
    let custom_child = home.join("custom-child");
    write_driver(&custom_child, CUSTOM);

    let outcomes = upgrade_default_drivers_under(&home);
    let upgraded = outcomes
        .iter()
        .filter(|(_, o)| matches!(o, DriverUpgrade::Upgraded { .. }))
        .count();
    assert_eq!(upgraded, 2, "root and researcher upgrade, got {outcomes:?}");

    assert_eq!(
        fs::read(home.join(".agent").join("behavior.wasm")).unwrap(),
        CURRENT
    );
    assert_eq!(
        fs::read(child.join(".agent").join("behavior.wasm")).unwrap(),
        CURRENT
    );
    assert_eq!(
        fs::read(custom_child.join(".agent").join("behavior.wasm")).unwrap(),
        CUSTOM
    );
}

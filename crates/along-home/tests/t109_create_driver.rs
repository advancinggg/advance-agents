//! MODULE-001-T109 — C243 create deploys a loader-resolvable behavior.wasm.

use std::fs;

use advance_along_home::{AlongHomeFirstOpen, HostAlongHome, RecognizeClass};

#[test]
fn t109_create_writes_wasm_and_second_create_does_not_overwrite() {
    let tmp = tempfile::tempdir().unwrap();
    let parent = tmp.path();
    let h = HostAlongHome::production();

    let first = h.create(parent, "home-a").unwrap();
    let driver = first.path().join(".agent").join("behavior.wasm");
    assert!(
        driver.is_file(),
        "new-home create writes .agent/behavior.wasm"
    );
    let bytes = fs::read(&driver).unwrap();
    assert!(bytes.len() >= 8, "driver is a wasm binary");
    assert_eq!(&bytes[0..4], b"\0asm");
    assert!(
        bytes[4] == 0x01 || bytes[4] == 0x0d,
        "core module 0x01 or encoded Component 0x0d, got {}",
        bytes[4]
    );

    let second = h.create(parent, "home-a").unwrap();
    assert_eq!(second.path(), first.path());
    assert_eq!(fs::read(&driver).unwrap(), bytes);
}

#[test]
fn t109_rollback_delete_wasm_second_create_is_ac24_open() {
    let tmp = tempfile::tempdir().unwrap();
    let parent = tmp.path();
    let h = HostAlongHome::production();
    let first = h.create(parent, "home-b").unwrap();
    let driver = first.path().join(".agent").join("behavior.wasm");
    fs::remove_file(&driver).unwrap();
    assert!(!driver.exists());

    let second = h.create(parent, "home-b").unwrap();
    assert_eq!(second.path(), first.path());
    assert!(matches!(
        h.recognize(second.path()),
        RecognizeClass::Recognized { .. }
    ));
    assert!(
        !driver.exists(),
        "create onto recognizable name must not rewrite the driver"
    );
}

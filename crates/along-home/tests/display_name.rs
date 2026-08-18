//! T50 / T51 / T106 — MODULE-005-AC-30 + MODULE-001-AC-27 name path

use advance_along_home::{
    write_recognizable_home, AlongHomeFirstOpen, DisplayNameError, HostAlongHome,
    TopLevelDisplayName,
};

#[test]
fn t50_t106_set_and_read() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("h");
    write_recognizable_home(&home).unwrap();
    let h = HostAlongHome::production();
    let handle = h.open(&home).unwrap();
    h.set_display_name(&handle, "Atlas").unwrap();
    assert_eq!(TopLevelDisplayName::TREE_ID, "default-agent");
    assert_eq!(TopLevelDisplayName::MAILBOX_ID, "agent:default");
    assert_eq!(h.current_display_name(&handle).as_deref(), Some("Atlas"));
    assert_eq!(TopLevelDisplayName::get(&home).as_deref(), Some("Atlas"));
}

#[test]
fn t51_reject_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("h");
    write_recognizable_home(&home).unwrap();
    let h = HostAlongHome::production();
    let handle = h.open(&home).unwrap();
    h.set_display_name(&handle, "Atlas").unwrap();
    assert_eq!(
        h.set_display_name(&handle, "").unwrap_err(),
        DisplayNameError::Empty
    );
    assert_eq!(
        h.set_display_name(&handle, "   ").unwrap_err(),
        DisplayNameError::Empty
    );
    assert_eq!(h.current_display_name(&handle).as_deref(), Some("Atlas"));
}

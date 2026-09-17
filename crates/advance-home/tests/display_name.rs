//! T50 / T51 / T106 — MODULE-005-AC-30 + MODULE-001-AC-27 name path

use advance_home::{
    write_recognizable_home, DisplayNameError, HostWorkspaceHome, TopLevelDisplayName,
    WorkspaceHomeFirstOpen,
};

#[test]
fn t50_t106_set_and_read() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("h");
    write_recognizable_home(&home).unwrap();
    let h = HostWorkspaceHome::production();
    let handle = h.open(&home).unwrap();
    h.set_display_name(&handle, "Atlas").unwrap();
    assert_eq!(h.current_display_name(&handle).as_deref(), Some("Atlas"));
    assert_eq!(TopLevelDisplayName::get(&home).as_deref(), Some("Atlas"));
}

#[test]
fn t51_reject_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("h");
    write_recognizable_home(&home).unwrap();
    let h = HostWorkspaceHome::production();
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

#[test]
fn name_lives_in_config_document_and_keeps_other_keys() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("h");
    write_recognizable_home(&home).unwrap();
    let before = std::fs::read_to_string(home.join(".agent/config.yaml")).unwrap();
    TopLevelDisplayName::set(&home, "  Atlas  ").unwrap();
    let after = std::fs::read_to_string(home.join(".agent/config.yaml")).unwrap();
    assert!(
        after.starts_with(&before),
        "existing keys kept verbatim:\n{after}"
    );
    assert!(after.ends_with("display-name: Atlas\n"), "{after}");
    assert!(
        !home.join(".agent/display-name").exists(),
        "no sidecar written"
    );
    assert_eq!(TopLevelDisplayName::get(&home).as_deref(), Some("Atlas"));
    // A second set replaces the key in place (no duplicate).
    TopLevelDisplayName::set(&home, "Nova").unwrap();
    let again = std::fs::read_to_string(home.join(".agent/config.yaml")).unwrap();
    assert_eq!(again.matches("display-name:").count(), 1, "{again}");
    assert_eq!(TopLevelDisplayName::get(&home).as_deref(), Some("Nova"));
}

#[test]
fn a_sidecar_file_is_never_consulted() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("h");
    write_recognizable_home(&home).unwrap();
    std::fs::write(home.join(".agent/display-name"), "Ghost").unwrap();
    assert_eq!(TopLevelDisplayName::get(&home), None);
    TopLevelDisplayName::set(&home, "Real").unwrap();
    assert_eq!(TopLevelDisplayName::get(&home).as_deref(), Some("Real"));
}

#[test]
fn set_refuses_a_non_mapping_document() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("h");
    write_recognizable_home(&home).unwrap();
    std::fs::write(home.join(".agent/config.yaml"), "- not\n- a mapping\n").unwrap();
    assert!(TopLevelDisplayName::set(&home, "Atlas").is_err());
    assert_eq!(
        std::fs::read_to_string(home.join(".agent/config.yaml")).unwrap(),
        "- not\n- a mapping\n",
        "document left untouched"
    );
}

//! Presets added and removed while the runtime runs (an installed pack's `presets/`), through
//! the ONE shared `Arc<PresetRegistry>` the intake, resolver chain and agent-grant bundle hold.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use cap_grant::preset::PresetRegistry;

fn agenda_editor() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../packs/agenda/presets/agenda-editor.yaml")
}

#[test]
fn a_pack_preset_is_added_and_removed_through_a_shared_registry() {
    let shared = Arc::new(PresetRegistry::with_builtins());
    let preset = PresetRegistry::parse_custom_yaml(&agenda_editor())
        .expect("the shipped agenda-editor preset parses");
    assert_eq!(preset.name, "agenda-editor");
    assert_eq!(preset.grants.len(), 2);
    assert!(!shared.contains("agenda-editor"));

    shared.insert(preset).expect("insert");
    assert!(shared.contains("agenda-editor"));
    assert_eq!(
        shared.get("agenda-editor").unwrap().grants[1].capability,
        "data"
    );
    assert_eq!(
        shared.names(),
        vec!["agenda-editor", "autonomous", "restrict", "supervised"]
    );

    assert!(shared.remove("agenda-editor"));
    assert!(!shared.remove("agenda-editor"), "already gone");
    assert!(shared.get("agenda-editor").is_none());
}

#[test]
fn builtins_can_be_neither_replaced_nor_removed() {
    let shared = PresetRegistry::with_builtins();
    let mut shadow = shared.get("restrict").unwrap().as_ref().clone();
    shadow.resolver_chain_names = vec!["SubsetAutoApprove".into()];
    assert!(shared.insert(shadow).is_err());
    assert!(!shared.remove("restrict"));
    assert!(!shared.remove("RESTRICT"), "case-folded built-in names too");
    assert_eq!(
        shared.get("restrict").unwrap().resolver_chain_names,
        vec!["AutoDeny".to_string()]
    );
}

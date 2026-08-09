//! AC-01 end-to-end storage path tests (T38).
//!
//! Verifies that after a successful install, the pack lives at the canonical
//! `<packs_dir>/{name}@{version}/` path, `<packs_dir>/.meta.yaml` has an
//! entry under `{name}@{version}`, and `registry.has(name, version)` +
//! `registry.list_installed()` reflect the install.

use std::path::Path;
use std::sync::Arc;

use advance_pack_manager::{
    AutoApprove, InMemoryPackRegistry, Installer, PackRegistry, RecordingTraceSink,
};

fn make_pack_fixture(root: &Path, name: &str, version: &str) -> std::path::PathBuf {
    let pack_dir = root.join("source");
    std::fs::create_dir_all(&pack_dir).unwrap();
    std::fs::create_dir_all(pack_dir.join("behavior-binaries")).unwrap();
    std::fs::write(
        pack_dir.join("behavior-binaries").join("researcher.wasm"),
        b"",
    )
    .unwrap();
    std::fs::write(
        pack_dir.join("pack.yaml"),
        format!(
            r#"name: {name}
version: {version}
runtime-version: ">=0.0.1"
dependencies: []
provides:
  behavior-binaries: [researcher]
required-capabilities:
  - fs
trust-level: untrusted
checksums:
  algo: sha256
  files: {{}}
"#
        ),
    )
    .unwrap();
    pack_dir
}

#[tokio::test]
async fn t38_pack_installed_at_canonical_path() {
    let dir = tempfile::TempDir::new().unwrap();
    let pack_src = make_pack_fixture(dir.path(), "researchpack", "1.0.0");
    let packs_dir = dir.path().join("packs");
    let registry = Arc::new(InMemoryPackRegistry::new(packs_dir.clone()));
    let sink = Arc::new(RecordingTraceSink::new());
    let installer = Installer {
        packs_dir: packs_dir.clone(),
        registry: registry.clone(),
        current_runtime_version: "0.5.0".into(),
        approval: Arc::new(AutoApprove),
        trace_sink: sink.clone(),
        dep_resolver: None,
        event_bus: None,
        registry_client: None,
        fetch_timeout: None,
    };

    installer
        .install(pack_src.to_string_lossy().as_ref())
        .await
        .expect("install should succeed");

    // (1) Canonical pack root exists with pack.yaml.
    let install_root = packs_dir.join("researchpack@1.0.0");
    assert!(install_root.exists(), "{install_root:?} missing");
    assert!(install_root.join("pack.yaml").is_file());
    assert!(install_root
        .join("behavior-binaries")
        .join("researcher.wasm")
        .is_file());

    // (2) The install-dir-level .meta.yaml has the entry.
    let meta_path = packs_dir.join(".meta.yaml");
    assert!(meta_path.exists(), "{meta_path:?} missing");
    let meta_text = std::fs::read_to_string(&meta_path).unwrap();
    assert!(
        meta_text.contains("researchpack@1.0.0"),
        ".meta.yaml is missing the install entry: {meta_text}"
    );

    // (3) Registry queries reflect the install.
    assert!(registry.has("researchpack", "1.0.0"));
    let listed = registry.list_installed();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].name, "researchpack");
    assert_eq!(listed[0].version, "1.0.0");
    assert_eq!(listed[0].install_path, install_root);
}

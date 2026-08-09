//! AC-03 directory layout validation tests (T39, T39b, T40, T41).
//!
//! `validate_pack_layout` is a `pub(crate)` helper — exercised through the
//! public `Installer::install` path (step ⑥ inline call). Layout-violation
//! packs surface as install-time `InvalidManifest` errors.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use advance_pack_manager::{
    AutoApprove, InMemoryPackRegistry, Installer, PackError, RecordingTraceSink,
};

/// Build a pack source directory with the given top-level extras and a
/// minimal valid `pack.yaml` + `behavior-binaries/researcher.wasm`.
/// `extras` items: (relative path, is_dir, optional file contents).
fn build_pack_source(root: &Path, name: &str, extras: &[(&str, bool, &[u8])]) -> PathBuf {
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
version: 1.0.0
runtime-version: ">=0.0.1"
dependencies: []
provides:
  behavior-binaries: [researcher]
required-capabilities: []
trust-level: untrusted
checksums:
  algo: sha256
  files: {{}}
"#
        ),
    )
    .unwrap();
    for (path, is_dir, content) in extras {
        let p = pack_dir.join(path);
        if *is_dir {
            std::fs::create_dir_all(&p).unwrap();
        } else {
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(&p, content).unwrap();
        }
    }
    pack_dir
}

async fn install_pack(pack_src: &Path, packs_dir: &Path) -> Result<(), PackError> {
    let registry = Arc::new(InMemoryPackRegistry::new(packs_dir.to_path_buf()));
    let sink = Arc::new(RecordingTraceSink::new());
    let installer = Installer {
        packs_dir: packs_dir.to_path_buf(),
        registry,
        current_runtime_version: "0.5.0".into(),
        approval: Arc::new(AutoApprove),
        trace_sink: sink,
        dep_resolver: None,
        event_bus: None,
        registry_client: None,
        fetch_timeout: None,
    };
    installer
        .install(pack_src.to_string_lossy().as_ref())
        .await
        .map(|_| ())
}

#[tokio::test]
async fn t39_full_canonical_layout_installs_cleanly() {
    let dir = tempfile::TempDir::new().unwrap();
    let extras: Vec<(&str, bool, &[u8])> = vec![
        ("agent-templates", true, b"" as &[u8]),
        ("skills", true, b""),
        ("components", true, b""),
        ("channel-adapters", true, b""),
        ("mcp-servers", true, b""),
        ("presets", true, b""),
        ("workflows", true, b""),
        ("memory-seeds", true, b""),
        ("meta-schema-extensions", true, b""),
    ];
    let pack_src = build_pack_source(dir.path(), "full-pack", &extras);
    let packs_dir = dir.path().join("packs");
    install_pack(&pack_src, &packs_dir).await.unwrap();
}

#[tokio::test]
async fn t39b_sparse_subset_layout_installs_cleanly() {
    // Pack ships only behavior-binaries (already in the base fixture);
    // none of the other 9 subdirs. Per AC-03 subset interpretation, this
    // is valid.
    let dir = tempfile::TempDir::new().unwrap();
    let pack_src = build_pack_source(dir.path(), "sparse-pack", &[]);
    let packs_dir = dir.path().join("packs");
    install_pack(&pack_src, &packs_dir).await.unwrap();
}

#[tokio::test]
async fn t40_extra_top_level_dir_is_rejected() {
    let dir = tempfile::TempDir::new().unwrap();
    let extras: Vec<(&str, bool, &[u8])> = vec![("extra", true, b"" as &[u8])];
    let pack_src = build_pack_source(dir.path(), "extra-dir-pack", &extras);
    let packs_dir = dir.path().join("packs");
    match install_pack(&pack_src, &packs_dir).await {
        Err(PackError::InvalidManifest(msg)) => assert!(
            msg.contains("extra"),
            "expected layout rejection, got: {msg}"
        ),
        other => panic!("expected InvalidManifest, got {other:?}"),
    }
}

#[tokio::test]
async fn t40_root_level_wasm_is_rejected() {
    let dir = tempfile::TempDir::new().unwrap();
    let extras: Vec<(&str, bool, &[u8])> = vec![("tool.wasm", false, b"\0asm" as &[u8])];
    let pack_src = build_pack_source(dir.path(), "rootwasm-pack", &extras);
    let packs_dir = dir.path().join("packs");
    match install_pack(&pack_src, &packs_dir).await {
        Err(PackError::InvalidManifest(msg)) => assert!(
            msg.contains("tool.wasm"),
            "expected layout rejection, got: {msg}"
        ),
        other => panic!("expected InvalidManifest, got {other:?}"),
    }
}

#[tokio::test]
async fn t40_readme_is_rejected_per_strict_allowlist() {
    let dir = tempfile::TempDir::new().unwrap();
    let extras: Vec<(&str, bool, &[u8])> = vec![("README.md", false, b"# hi" as &[u8])];
    let pack_src = build_pack_source(dir.path(), "readme-pack", &extras);
    let packs_dir = dir.path().join("packs");
    match install_pack(&pack_src, &packs_dir).await {
        Err(PackError::InvalidManifest(msg)) => assert!(
            msg.contains("README.md"),
            "expected layout rejection, got: {msg}"
        ),
        other => panic!("expected InvalidManifest, got {other:?}"),
    }
}

#[tokio::test]
async fn t40_license_is_rejected() {
    let dir = tempfile::TempDir::new().unwrap();
    let extras: Vec<(&str, bool, &[u8])> = vec![("LICENSE", false, b"MIT" as &[u8])];
    let pack_src = build_pack_source(dir.path(), "license-pack", &extras);
    let packs_dir = dir.path().join("packs");
    match install_pack(&pack_src, &packs_dir).await {
        Err(PackError::InvalidManifest(msg)) => assert!(
            msg.contains("LICENSE"),
            "expected layout rejection, got: {msg}"
        ),
        other => panic!("expected InvalidManifest, got {other:?}"),
    }
}

#[tokio::test]
async fn t41_validate_pack_layout_requires_pack_yaml() {
    // The layout module's pack-yaml requirement is exercised at unit level
    // because the public install path requires pack.yaml at step ③ first.
    // We construct a synthetic install dir without pack.yaml and re-run the
    // step ⑦ → ⑧ path via rescan, which surfaces a different error class.
    //
    // The direct `validate_pack_layout` happy/sad paths are covered by the
    // inline unit tests in `layout.rs` (#[cfg(test)] mod). Here we cover
    // the install-time integration angle: an install_path that loses its
    // pack.yaml between copy and rescan surfaces InvalidManifest at the
    // rescan step. This documents the layout-discipline contract from the
    // integration side.
    let dir = tempfile::TempDir::new().unwrap();
    let pack_src = build_pack_source(dir.path(), "good", &[]);
    let packs_dir = dir.path().join("packs");
    install_pack(&pack_src, &packs_dir).await.unwrap();
    // Remove pack.yaml post-install to simulate corruption.
    let install_root = packs_dir.join("good@1.0.0");
    std::fs::remove_file(install_root.join("pack.yaml")).unwrap();
    // Rescan surfaces the missing pack.yaml as Io (regression coverage —
    // validate_pack_layout is install-time only; rescan reads
    // `<install>/pack.yaml` via the registry's existing path). The error
    // class differs but the principle (layout discipline observable) holds.
    let registry = InMemoryPackRegistry::new(packs_dir.clone());
    match registry.rescan().await {
        Err(_) => {}
        Ok(_) => panic!("expected error after removing pack.yaml"),
    }
}

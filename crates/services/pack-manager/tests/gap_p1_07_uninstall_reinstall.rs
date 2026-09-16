#![cfg(feature = "gap-p1")]
//! GAP-07 (P1) — uninstall / reinstall semantics.
//!
//! Contract under test:
//! - `Installer::uninstall(name, version)` removes `packs_dir/{name}@{version}`, drops the
//!   `.meta.yaml` key, rescans the registry, and refuses when another installed pack depends
//!   on it (`PackError::DependentsExist`).
//! - A second install of an already-installed `{name}@{version}` fails with
//!   `PackError::AlreadyInstalled` BEFORE checksum/approval (no Step4 trace), judged from
//!   disk state (dir or `.meta.yaml` key), not the in-memory registry.
//!
//! Activation: delete the `#![cfg]` line once the API exists (plan §0.2).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use advance_pack_manager::{
    AutoApprove, DependencyResolver, InMemoryPackRegistry, InstallStep, Installer, PackError,
    PackRegistry, RecordingTraceSink, SourceRef,
};
use async_trait::async_trait;

fn write_pack(root: &Path, name: &str, version: &str, deps: &[(&str, &str)]) -> PathBuf {
    let dir = root.join(format!("{name}-{version}-src"));
    std::fs::create_dir_all(dir.join("behavior-binaries")).unwrap();
    std::fs::write(dir.join("behavior-binaries/dummy.wasm"), b"\0asm\x01\0\0\0").unwrap();
    let mut yaml = format!(
        "name: {name}\nversion: {version}\nruntime-version: \">=0.1.0\"\nprovides:\n  behavior-binaries:\n    - dummy\nchecksums:\n  algo: sha256\n  files: {{}}\n"
    );
    if !deps.is_empty() {
        yaml.push_str("dependencies:\n");
        for (n, req) in deps {
            yaml.push_str(&format!("  - name: {n}\n    version: \"{req}\"\n"));
        }
    }
    std::fs::write(dir.join("pack.yaml"), yaml).unwrap();
    dir
}

fn installer(packs_dir: &Path, trace: Arc<RecordingTraceSink>) -> Installer {
    Installer::new(
        packs_dir,
        Arc::new(InMemoryPackRegistry::new(packs_dir.to_path_buf())),
        "0.1.0",
        Arc::new(AutoApprove),
    )
    .with_trace_sink(trace)
}

/// Maps a dependency name to a local source directory.
struct LocalResolver(Vec<(String, PathBuf)>);

#[async_trait]
impl DependencyResolver for LocalResolver {
    async fn resolve(&self, name: &str, _req: &semver::VersionReq) -> Result<SourceRef, PackError> {
        self.0
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, p)| SourceRef::Local(p.clone()))
            .ok_or_else(|| PackError::DependencyNotFound {
                name: name.to_string(),
                version_req: "*".to_string(),
            })
    }
}

#[tokio::test]
async fn g07_reinstall_same_version_fails_before_approval() {
    let work = tempfile::TempDir::new().unwrap();
    let packs = tempfile::TempDir::new().unwrap();
    let src = write_pack(work.path(), "a", "1.0.0", &[]);

    let first = installer(packs.path(), Arc::new(RecordingTraceSink::new()));
    first
        .install(src.to_str().unwrap())
        .await
        .expect("first install");
    let installed_wasm = packs.path().join("a@1.0.0/behavior-binaries/dummy.wasm");
    assert!(installed_wasm.is_file());

    // Fresh installer + fresh (empty) registry: the judgement must come from disk.
    let trace = Arc::new(RecordingTraceSink::new());
    let second = installer(packs.path(), trace.clone());
    let err = second
        .install(src.to_str().unwrap())
        .await
        .expect_err("second install of a@1.0.0 must fail");
    match err {
        PackError::AlreadyInstalled { name, version } => {
            assert_eq!(name, "a");
            assert_eq!(version, "1.0.0");
        }
        other => panic!("expected AlreadyInstalled, got {other:?}"),
    }
    let steps = trace.steps();
    assert!(
        !steps.contains(&InstallStep::Step4AdminApproval),
        "reinstall must be refused before the admin approval step; trace = {steps:?}"
    );
    assert!(
        installed_wasm.is_file(),
        "original install must be untouched"
    );
}

#[tokio::test]
async fn g07_uninstall_removes_dir_meta_and_rescans() {
    let work = tempfile::TempDir::new().unwrap();
    let packs = tempfile::TempDir::new().unwrap();
    let src = write_pack(work.path(), "a", "1.0.0", &[]);
    let inst = installer(packs.path(), Arc::new(RecordingTraceSink::new()));
    inst.install(src.to_str().unwrap()).await.unwrap();
    assert!(inst.registry.has("a", "1.0.0"));

    let report = inst.uninstall("a", "1.0.0").await.expect("uninstall");
    assert_eq!(report.name, "a");
    assert_eq!(report.version, "1.0.0");
    assert_eq!(report.removed_path, packs.path().join("a@1.0.0"));
    assert!(
        !packs.path().join("a@1.0.0").exists(),
        "install dir must be removed"
    );

    let meta = std::fs::read_to_string(packs.path().join(".meta.yaml")).unwrap();
    assert!(
        !meta.contains("a@1.0.0"),
        ".meta.yaml key must be dropped: {meta}"
    );
    assert!(
        !inst.registry.has("a", "1.0.0"),
        "registry must be rescanned"
    );
    assert!(inst.registry.list_installed().is_empty());
}

#[tokio::test]
async fn g07_uninstall_missing_is_pack_not_found() {
    let packs = tempfile::TempDir::new().unwrap();
    let inst = installer(packs.path(), Arc::new(RecordingTraceSink::new()));
    let err = inst
        .uninstall("ghost", "9.9.9")
        .await
        .expect_err("nothing installed");
    assert!(
        matches!(err, PackError::PackNotFound(..)),
        "expected PackNotFound, got {err:?}"
    );
}

#[tokio::test]
async fn g07_reinstall_after_uninstall_succeeds() {
    let work = tempfile::TempDir::new().unwrap();
    let packs = tempfile::TempDir::new().unwrap();
    let src = write_pack(work.path(), "a", "1.0.0", &[]);
    let inst = installer(packs.path(), Arc::new(RecordingTraceSink::new()));
    inst.install(src.to_str().unwrap()).await.unwrap();
    inst.uninstall("a", "1.0.0").await.unwrap();
    let report = inst
        .install(src.to_str().unwrap())
        .await
        .expect("reinstall after uninstall");
    assert_eq!(report.version, "1.0.0");
    assert!(inst.registry.has("a", "1.0.0"));
}

#[tokio::test]
async fn g07_uninstall_with_dependents_is_refused_until_dependents_go() {
    let work = tempfile::TempDir::new().unwrap();
    let packs = tempfile::TempDir::new().unwrap();
    let a_src = write_pack(work.path(), "a", "1.0.0", &[]);
    let b_src = write_pack(work.path(), "b", "1.0.0", &[("a", "^1.0")]);

    let inst = installer(packs.path(), Arc::new(RecordingTraceSink::new()))
        .with_dep_resolver(Arc::new(LocalResolver(vec![("a".into(), a_src)])));
    inst.install(b_src.to_str().unwrap())
        .await
        .expect("b (and its dep a) install");
    assert!(inst.registry.has("a", "1.0.0"));
    assert!(inst.registry.has("b", "1.0.0"));

    let err = inst
        .uninstall("a", "1.0.0")
        .await
        .expect_err("a has a dependent (b) — must refuse");
    match err {
        PackError::DependentsExist {
            name, dependents, ..
        } => {
            assert_eq!(name, "a");
            assert_eq!(dependents, vec!["b@1.0.0".to_string()]);
        }
        other => panic!("expected DependentsExist, got {other:?}"),
    }
    assert!(
        packs.path().join("a@1.0.0").exists(),
        "refusal must not delete anything"
    );

    inst.uninstall("b", "1.0.0")
        .await
        .expect("b has no dependents");
    inst.uninstall("a", "1.0.0").await.expect("a is free now");
    assert!(inst.registry.list_installed().is_empty());
}

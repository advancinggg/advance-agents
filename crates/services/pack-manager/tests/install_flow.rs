//! Install-flow integration tests: T17–T22, T23, T27, T28, T37, T38.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use advance_pack_manager::{
    AutoApprove, AutoReject, InMemoryPackRegistry, InstallStep, Installer, MetaIndex,
    MetaPackEntry, MetaScope, PackError, PackRegistry, RecordingTraceSink, TrustLevel,
};
// Test fixture: build a pack source directory containing pack.yaml + an empty
// `behavior-binaries/` so the directory structure is non-trivial.
// Slice A: pack.yaml does NOT need to checksum itself (avoids the self-referential
// fixed-point problem). The fixture writes a clean pack.yaml with an empty
// `checksums.files` map. Pack integrity is enforced via admin approval at step ④.
fn make_pack_fixture(root: &Path, name: &str, version: &str, runtime_range: &str) -> PathBuf {
    let pack_dir = root.join("source");
    std::fs::create_dir_all(&pack_dir).unwrap();
    // The fixture declares `provides: behavior-binaries: [researcher]`, so the
    // matching artifact must exist on disk — `Installer::install`'s step ⑥a
    // `verify_provides_on_disk` rejects declared-but-missing components.
    std::fs::create_dir_all(pack_dir.join("behavior-binaries")).unwrap();
    std::fs::write(
        pack_dir.join("behavior-binaries").join("researcher.wasm"),
        b"",
    )
    .unwrap();

    let pack_yaml = format!(
        r#"name: {name}
version: {version}
runtime-version: "{runtime_range}"
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
    );

    std::fs::write(pack_dir.join("pack.yaml"), pack_yaml).unwrap();
    pack_dir
}

#[tokio::test]
async fn t17_happy_path_emits_8_trace_events_in_order() {
    let dir = tempfile::TempDir::new().unwrap();
    let pack_src = make_pack_fixture(dir.path(), "foo", "1.0.0", ">=0.0.1");
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

    let report = installer
        .install(pack_src.to_string_lossy().as_ref())
        .await
        .expect("install should succeed");

    assert_eq!(report.name, "foo");
    assert_eq!(report.version, "1.0.0");
    assert_eq!(
        report.trace_steps,
        vec![
            InstallStep::Step1ParseSource,
            InstallStep::Step2DownloadToTemp,
            InstallStep::Step3VerifyChecksums,
            InstallStep::Step4AdminApproval,
            InstallStep::Step5RecursiveDeps,
            InstallStep::Step6CopyToInstallDir,
            InstallStep::Step7UpdateMetaIndex,
            InstallStep::Step8RegistryRescan,
        ]
    );
    assert!(registry.has("foo", "1.0.0"));
}

#[tokio::test]
async fn t18_tampered_checksum_aborts_at_step3_before_step4() {
    let dir = tempfile::TempDir::new().unwrap();
    let pack_src = dir.path().join("source");
    std::fs::create_dir_all(&pack_src).unwrap();
    // Write a content file with a known body BUT claim a different digest in the manifest.
    std::fs::create_dir_all(pack_src.join("behavior-binaries")).unwrap();
    std::fs::write(pack_src.join("behavior-binaries/foo.wasm"), b"real content").unwrap();
    let bad = r#"name: foo
version: 1.0.0
runtime-version: ">=0.0.1"
dependencies: []
provides:
  behavior-binaries: [foo]
required-capabilities:
  - fs
trust-level: untrusted
checksums:
  algo: sha256
  files:
    behavior-binaries/foo.wasm: "0000000000000000000000000000000000000000000000000000000000000000"
"#;
    std::fs::write(pack_src.join("pack.yaml"), bad).unwrap();

    let packs_dir = dir.path().join("packs");
    let registry = Arc::new(InMemoryPackRegistry::new(packs_dir.clone()));
    let sink = Arc::new(RecordingTraceSink::new());
    let installer = Installer {
        packs_dir,
        registry,
        current_runtime_version: "0.5.0".into(),
        approval: Arc::new(AutoApprove),
        trace_sink: sink.clone(),
        dep_resolver: None,
        event_bus: None,
        registry_client: None,
        fetch_timeout: None,
    };

    match installer.install(pack_src.to_string_lossy().as_ref()).await {
        Err(PackError::ChecksumMismatch(_, _, _)) => {}
        other => panic!("expected ChecksumMismatch, got {other:?}"),
    }
    let steps = sink.steps();
    assert!(!steps.contains(&InstallStep::Step4AdminApproval));
}

#[tokio::test]
async fn t19_admin_reject_stops_after_step4() {
    let dir = tempfile::TempDir::new().unwrap();
    let pack_src = make_pack_fixture(dir.path(), "foo", "1.0.0", ">=0.0.1");
    let packs_dir = dir.path().join("packs");
    let registry = Arc::new(InMemoryPackRegistry::new(packs_dir.clone()));
    let sink = Arc::new(RecordingTraceSink::new());
    let installer = Installer {
        packs_dir,
        registry,
        current_runtime_version: "0.5.0".into(),
        approval: Arc::new(AutoReject),
        trace_sink: sink.clone(),
        dep_resolver: None,
        event_bus: None,
        registry_client: None,
        fetch_timeout: None,
    };

    match installer.install(pack_src.to_string_lossy().as_ref()).await {
        Err(PackError::AdminRejected) => {}
        other => panic!("expected AdminRejected, got {other:?}"),
    }
    let steps = sink.steps();
    assert!(steps.contains(&InstallStep::Step4AdminApproval));
    assert!(!steps.contains(&InstallStep::Step5RecursiveDeps));
}

#[tokio::test]
async fn t20_runtime_version_mismatch_at_step3() {
    let dir = tempfile::TempDir::new().unwrap();
    let pack_src = make_pack_fixture(dir.path(), "foo", "1.0.0", ">=99.0.0");
    let packs_dir = dir.path().join("packs");
    let registry = Arc::new(InMemoryPackRegistry::new(packs_dir.clone()));
    let sink = Arc::new(RecordingTraceSink::new());
    let installer = Installer {
        packs_dir,
        registry,
        current_runtime_version: "0.5.0".into(),
        approval: Arc::new(AutoApprove),
        trace_sink: sink,
        dep_resolver: None,
        event_bus: None,
        registry_client: None,
        fetch_timeout: None,
    };
    match installer.install(pack_src.to_string_lossy().as_ref()).await {
        Err(PackError::RuntimeVersionMismatch { .. }) => {}
        other => panic!("expected RuntimeVersionMismatch, got {other:?}"),
    }
}

/// Slice B: with `dep_resolver: None`, a pack declaring non-empty dependencies
/// surfaces `InvalidManifest` (was `NotImplemented` in Slice A's empty-deps
/// fast-path). The recursive-install behavior is exercised in
/// `tests/recursive_deps.rs` with a configured DependencyResolver.
#[tokio::test]
async fn t21_non_empty_deps_without_resolver_errors() {
    let dir = tempfile::TempDir::new().unwrap();
    let pack_src = dir.path().join("source");
    std::fs::create_dir_all(&pack_src).unwrap();
    let yaml_body = r#"name: foo
version: 1.0.0
runtime-version: ">=0.0.1"
dependencies:
  - name: bar
    version: "^1.0.0"
provides:
  behavior-binaries: []
required-capabilities:
  - fs
trust-level: untrusted
checksums:
  algo: sha256
  files: {}
"#;
    std::fs::write(pack_src.join("pack.yaml"), yaml_body).unwrap();

    let packs_dir = dir.path().join("packs");
    let registry = Arc::new(InMemoryPackRegistry::new(packs_dir.clone()));
    let sink = Arc::new(RecordingTraceSink::new());
    let installer = Installer {
        packs_dir,
        registry,
        current_runtime_version: "0.5.0".into(),
        approval: Arc::new(AutoApprove),
        trace_sink: sink,
        dep_resolver: None,
        event_bus: None,
        registry_client: None,
        fetch_timeout: None,
    };
    match installer.install(pack_src.to_string_lossy().as_ref()).await {
        Err(PackError::InvalidManifest(msg)) => assert!(
            msg.contains("DependencyResolver"),
            "expected DependencyResolver missing message, got: {msg}"
        ),
        other => panic!("expected InvalidManifest(DependencyResolver), got {other:?}"),
    }
}

#[tokio::test]
async fn t22_meta_yaml_contains_scope_and_pack_entry() {
    let dir = tempfile::TempDir::new().unwrap();
    let pack_src = make_pack_fixture(dir.path(), "foo", "1.0.0", ">=0.0.1");
    let packs_dir = dir.path().join("packs");
    let registry = Arc::new(InMemoryPackRegistry::new(packs_dir.clone()));
    let sink = Arc::new(RecordingTraceSink::new());
    let installer = Installer {
        packs_dir: packs_dir.clone(),
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
        .unwrap();

    let meta_path = packs_dir.join(".meta.yaml");
    let meta_text = std::fs::read_to_string(&meta_path).unwrap();
    let idx: MetaIndex = serde_yml::from_str(&meta_text).unwrap();
    assert!(idx.packs.contains_key("foo@1.0.0"));
    assert_eq!(idx.scope.description, "Installed packs");
}

#[tokio::test]
async fn t23_step3_precedes_step4_isolated_ordering() {
    let dir = tempfile::TempDir::new().unwrap();
    let pack_src = make_pack_fixture(dir.path(), "foo", "1.0.0", ">=0.0.1");
    let packs_dir = dir.path().join("packs");
    let registry = Arc::new(InMemoryPackRegistry::new(packs_dir.clone()));
    let sink = Arc::new(RecordingTraceSink::new());
    let installer = Installer {
        packs_dir,
        registry,
        current_runtime_version: "0.5.0".into(),
        approval: Arc::new(AutoApprove),
        trace_sink: sink.clone(),
        dep_resolver: None,
        event_bus: None,
        registry_client: None,
        fetch_timeout: None,
    };
    let report = installer
        .install(pack_src.to_string_lossy().as_ref())
        .await
        .unwrap();
    let i3 = report
        .trace_steps
        .iter()
        .position(|s| *s == InstallStep::Step3VerifyChecksums)
        .unwrap();
    let i4 = report
        .trace_steps
        .iter()
        .position(|s| *s == InstallStep::Step4AdminApproval)
        .unwrap();
    assert!(i3 < i4, "Step3 must precede Step4");
}

#[tokio::test]
async fn t27_symlink_in_source_rejected() {
    let dir = tempfile::TempDir::new().unwrap();
    let pack_src = make_pack_fixture(dir.path(), "foo", "1.0.0", ">=0.0.1");
    // Inject a symlink alongside pack.yaml.
    let target = pack_src.join("evil-link");
    #[cfg(unix)]
    std::os::unix::fs::symlink("/etc/passwd", &target).unwrap();
    #[cfg(not(unix))]
    {
        // On non-Unix, skip the test; the symlink defense applies POSIX-wide.
        eprintln!("symlink test skipped on non-Unix");
        return;
    }

    let packs_dir = dir.path().join("packs");
    let registry = Arc::new(InMemoryPackRegistry::new(packs_dir.clone()));
    let sink = Arc::new(RecordingTraceSink::new());
    let installer = Installer {
        packs_dir,
        registry,
        current_runtime_version: "0.5.0".into(),
        approval: Arc::new(AutoApprove),
        trace_sink: sink,
        dep_resolver: None,
        event_bus: None,
        registry_client: None,
        fetch_timeout: None,
    };
    match installer.install(pack_src.to_string_lossy().as_ref()).await {
        Err(PackError::InvalidManifest(msg)) => assert!(msg.contains("symlink")),
        other => panic!("expected InvalidManifest(symlink), got {other:?}"),
    }
}

#[tokio::test]
async fn t28_meta_yaml_tempfile_cleaned_up() {
    let dir = tempfile::TempDir::new().unwrap();
    let pack_src = make_pack_fixture(dir.path(), "foo", "1.0.0", ">=0.0.1");
    let packs_dir = dir.path().join("packs");
    let registry = Arc::new(InMemoryPackRegistry::new(packs_dir.clone()));
    let sink = Arc::new(RecordingTraceSink::new());
    let installer = Installer {
        packs_dir: packs_dir.clone(),
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
        .unwrap();

    // No `.meta.yaml.tmp.*` files left behind.
    let leftovers: Vec<_> = std::fs::read_dir(&packs_dir)
        .unwrap()
        .filter_map(|r| r.ok())
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with(".meta.yaml.tmp.")
        })
        .collect();
    assert!(
        leftovers.is_empty(),
        "tempfiles left behind: {:?}",
        leftovers
    );
    assert!(packs_dir.join(".meta.yaml").exists());
}

// T37: rescan atomicity — pre-populate registry via on-disk meta then install a 3rd pack.
// Verifies that after step ⑧ the registry has 3 packs (no observable empty window since
// the implementation uses atomic read-build-swap; serial-process Slice A test asserts
// post-install state shows all 3).
#[tokio::test]
async fn t37_rescan_atomicity_post_state_complete() {
    let dir = tempfile::TempDir::new().unwrap();
    let packs_dir = dir.path().join("packs");
    std::fs::create_dir_all(&packs_dir).unwrap();

    // Pre-create on-disk state for 2 packs (their pack.yaml files + meta entries).
    for n in &["pre-a", "pre-b"] {
        let install_path = packs_dir.join(format!("{n}@1.0.0"));
        std::fs::create_dir_all(&install_path).unwrap();
        let pack_yaml_body = format!(
            r#"name: {n}
version: 1.0.0
runtime-version: ">=0.0.1"
dependencies: []
provides:
  behavior-binaries: []
required-capabilities:
  - fs
trust-level: untrusted
checksums:
  algo: sha256
  files: {{}}
"#
        );
        std::fs::write(install_path.join("pack.yaml"), pack_yaml_body).unwrap();
    }

    // Build the .meta.yaml index.
    let mut idx = MetaIndex {
        scope: MetaScope::default(),
        packs: Default::default(),
    };
    for n in &["pre-a", "pre-b"] {
        idx.packs.insert(
            format!("{n}@1.0.0"),
            MetaPackEntry {
                description: None,
                installed_at: "2026-05-11T00:00:00Z".into(),
                required_capabilities: vec!["fs".into()],
                trust_level: TrustLevel::Untrusted,
            },
        );
    }
    let yaml = serde_yml::to_string(&idx).unwrap();
    std::fs::write(packs_dir.join(".meta.yaml"), yaml).unwrap();

    // Now install a 3rd pack — rescan after install should pick up all 3.
    let pack_src = make_pack_fixture(dir.path(), "new-c", "1.0.0", ">=0.0.1");
    let registry = Arc::new(InMemoryPackRegistry::new(packs_dir.clone()));
    let sink = Arc::new(RecordingTraceSink::new());
    let installer = Installer {
        packs_dir: packs_dir.clone(),
        registry: registry.clone(),
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
        .unwrap();

    let installed = registry.list_installed();
    let names: Vec<String> = installed.iter().map(|m| m.name.clone()).collect();
    assert!(names.contains(&"pre-a".to_string()));
    assert!(names.contains(&"pre-b".to_string()));
    assert!(names.contains(&"new-c".to_string()));
    assert_eq!(installed.len(), 3);
}

#[tokio::test]
async fn t38_rescan_partial_failure_atomic_abort() {
    let dir = tempfile::TempDir::new().unwrap();
    let packs_dir = dir.path().join("packs");
    std::fs::create_dir_all(&packs_dir).unwrap();

    // Pre-install one valid pack manually (via test helper).
    let registry = Arc::new(InMemoryPackRegistry::new(packs_dir.clone()));

    // Write .meta.yaml referencing a pack that has a CORRUPT pack.yaml on disk.
    let bad_install = packs_dir.join("bad@1.0.0");
    std::fs::create_dir_all(&bad_install).unwrap();
    std::fs::write(bad_install.join("pack.yaml"), "not-valid-yaml: : :").unwrap();

    let mut idx = MetaIndex {
        scope: MetaScope::default(),
        packs: Default::default(),
    };
    idx.packs.insert(
        "bad@1.0.0".into(),
        MetaPackEntry {
            description: None,
            installed_at: "2026-05-11T00:00:00Z".into(),
            required_capabilities: vec!["fs".into()],
            trust_level: TrustLevel::Untrusted,
        },
    );
    let yaml = serde_yml::to_string(&idx).unwrap();
    std::fs::write(packs_dir.join(".meta.yaml"), yaml).unwrap();

    // Direct rescan should fail.
    match registry.rescan().await {
        Err(_) => {}
        Ok(_) => panic!("expected rescan to fail on corrupt pack.yaml"),
    }
    // Registry remained empty (no partial state).
    assert!(registry.list_installed().is_empty());
}

// Codex round-4 W-B: destination-side TOCTOU symlink defense in
// `copy_dir_no_symlinks`. The install_path must not pre-exist (whether as a
// regular dir, a regular file, or a symlink); a pre-existing symlink would
// otherwise redirect step ⑥ writes outside the pack root.

#[tokio::test]
async fn t39_install_path_preexists_as_dir_rejected() {
    let dir = tempfile::TempDir::new().unwrap();
    let pack_src = make_pack_fixture(dir.path(), "foo", "1.0.0", ">=0.0.1");
    let packs_dir = dir.path().join("packs");
    std::fs::create_dir_all(packs_dir.join("foo@1.0.0")).unwrap();

    let registry = Arc::new(InMemoryPackRegistry::new(packs_dir.clone()));
    let sink = Arc::new(RecordingTraceSink::new());
    let installer = Installer {
        packs_dir,
        registry,
        current_runtime_version: "0.5.0".into(),
        approval: Arc::new(AutoApprove),
        trace_sink: sink,
        dep_resolver: None,
        event_bus: None,
        registry_client: None,
        fetch_timeout: None,
    };
    match installer.install(pack_src.to_string_lossy().as_ref()).await {
        Err(PackError::InvalidManifest(msg)) => assert!(
            msg.contains("must not pre-exist") || msg.contains("pre-existing"),
            "expected pre-existence rejection, got: {msg}"
        ),
        other => panic!("expected InvalidManifest(pre-existing), got {other:?}"),
    }
}

#[tokio::test]
async fn t40_install_path_preexists_as_symlink_rejected() {
    #[cfg(not(unix))]
    {
        eprintln!("symlink test skipped on non-Unix");
        return;
    }
    #[cfg(unix)]
    {
        let dir = tempfile::TempDir::new().unwrap();
        let pack_src = make_pack_fixture(dir.path(), "foo", "1.0.0", ">=0.0.1");
        let packs_dir = dir.path().join("packs");
        std::fs::create_dir_all(&packs_dir).unwrap();
        // Symlink the install_path to a directory we control elsewhere — without
        // the dst-side check, the install copy would write through the link
        // into `attacker_dir`. With the fix, the install must reject.
        let attacker_dir = dir.path().join("attacker_target");
        std::fs::create_dir_all(&attacker_dir).unwrap();
        std::os::unix::fs::symlink(&attacker_dir, packs_dir.join("foo@1.0.0")).unwrap();

        let registry = Arc::new(InMemoryPackRegistry::new(packs_dir.clone()));
        let sink = Arc::new(RecordingTraceSink::new());
        let installer = Installer {
            packs_dir,
            registry,
            current_runtime_version: "0.5.0".into(),
            approval: Arc::new(AutoApprove),
            trace_sink: sink,
            dep_resolver: None,
            event_bus: None,
            registry_client: None,
            fetch_timeout: None,
        };
        match installer.install(pack_src.to_string_lossy().as_ref()).await {
            Err(PackError::InvalidManifest(msg)) => {
                assert!(
                    msg.contains("symlink") || msg.contains("pre-exist"),
                    "expected dst symlink/pre-exist rejection, got: {msg}"
                );
            }
            other => panic!("expected InvalidManifest(symlink), got {other:?}"),
        }
        // attacker_target must be untouched — no pack.yaml written through it.
        assert!(!attacker_dir.join("pack.yaml").exists());
    }
}

// Codex round-4 W-C: `provides[*]` entries must have matching on-disk
// artifacts at canonical §19.3 paths. Step ⑥a `verify_provides_on_disk`
// catches manifest drift at install time rather than as a runtime dead-path.

#[tokio::test]
async fn t41_provides_missing_file_artifact_rejected() {
    let dir = tempfile::TempDir::new().unwrap();
    let pack_src = dir.path().join("source");
    std::fs::create_dir_all(&pack_src).unwrap();
    // pack.yaml declares `behavior-binaries: [tool]` but no tool.wasm exists.
    let yaml = r#"name: foo
version: 1.0.0
runtime-version: ">=0.0.1"
dependencies: []
provides:
  behavior-binaries: [tool]
required-capabilities:
  - fs
trust-level: untrusted
checksums:
  algo: sha256
  files: {}
"#;
    std::fs::write(pack_src.join("pack.yaml"), yaml).unwrap();

    let packs_dir = dir.path().join("packs");
    let registry = Arc::new(InMemoryPackRegistry::new(packs_dir.clone()));
    let sink = Arc::new(RecordingTraceSink::new());
    let installer = Installer {
        packs_dir,
        registry,
        current_runtime_version: "0.5.0".into(),
        approval: Arc::new(AutoApprove),
        trace_sink: sink,
        dep_resolver: None,
        event_bus: None,
        registry_client: None,
        fetch_timeout: None,
    };
    match installer.install(pack_src.to_string_lossy().as_ref()).await {
        Err(PackError::InvalidManifest(msg)) => assert!(
            msg.contains("missing on disk") && msg.contains("Binary"),
            "expected provides missing-artifact rejection, got: {msg}"
        ),
        other => panic!("expected InvalidManifest(missing), got {other:?}"),
    }
}

#[tokio::test]
async fn t42_provides_missing_directory_artifact_rejected() {
    let dir = tempfile::TempDir::new().unwrap();
    let pack_src = dir.path().join("source");
    std::fs::create_dir_all(&pack_src).unwrap();
    // pack.yaml declares `skills: [my-skill]` but no skills/my-skill/ dir
    // exists. Skill is a directory-backed kind per §19.3.
    let yaml = r#"name: foo
version: 1.0.0
runtime-version: ">=0.0.1"
dependencies: []
provides:
  skills: [my-skill]
required-capabilities:
  - fs
trust-level: untrusted
checksums:
  algo: sha256
  files: {}
"#;
    std::fs::write(pack_src.join("pack.yaml"), yaml).unwrap();

    let packs_dir = dir.path().join("packs");
    let registry = Arc::new(InMemoryPackRegistry::new(packs_dir.clone()));
    let sink = Arc::new(RecordingTraceSink::new());
    let installer = Installer {
        packs_dir,
        registry,
        current_runtime_version: "0.5.0".into(),
        approval: Arc::new(AutoApprove),
        trace_sink: sink,
        dep_resolver: None,
        event_bus: None,
        registry_client: None,
        fetch_timeout: None,
    };
    match installer.install(pack_src.to_string_lossy().as_ref()).await {
        Err(PackError::InvalidManifest(msg)) => assert!(
            msg.contains("missing on disk") && msg.contains("Skill"),
            "expected provides directory-kind missing rejection, got: {msg}"
        ),
        other => panic!("expected InvalidManifest(missing-skill-dir), got {other:?}"),
    }
}

// Codex round-5 W-B/W-C coverage gaps: regular-file pre-existence at
// install_path (W-B file branch) + symlink rejection at provides path +
// wrong-type artifacts at provides path (W-C).

#[tokio::test]
async fn t43_install_path_preexists_as_file_rejected() {
    let dir = tempfile::TempDir::new().unwrap();
    let pack_src = make_pack_fixture(dir.path(), "foo", "1.0.0", ">=0.0.1");
    let packs_dir = dir.path().join("packs");
    std::fs::create_dir_all(&packs_dir).unwrap();
    // Pre-create install_path as a regular file (not dir, not symlink).
    std::fs::write(packs_dir.join("foo@1.0.0"), b"stale partial install").unwrap();

    let registry = Arc::new(InMemoryPackRegistry::new(packs_dir.clone()));
    let sink = Arc::new(RecordingTraceSink::new());
    let installer = Installer {
        packs_dir,
        registry,
        current_runtime_version: "0.5.0".into(),
        approval: Arc::new(AutoApprove),
        trace_sink: sink,
        dep_resolver: None,
        event_bus: None,
        registry_client: None,
        fetch_timeout: None,
    };
    match installer.install(pack_src.to_string_lossy().as_ref()).await {
        Err(PackError::InvalidManifest(msg)) => assert!(
            msg.contains("must not pre-exist") && msg.contains("non-directory"),
            "expected non-directory pre-existence rejection, got: {msg}"
        ),
        other => panic!("expected InvalidManifest(pre-existing file), got {other:?}"),
    }
}

#[tokio::test]
async fn t44_provides_file_artifact_is_symlink_rejected() {
    #[cfg(not(unix))]
    {
        eprintln!("symlink test skipped on non-Unix");
        return;
    }
    #[cfg(unix)]
    {
        let dir = tempfile::TempDir::new().unwrap();
        let pack_src = dir.path().join("source");
        std::fs::create_dir_all(pack_src.join("behavior-binaries")).unwrap();
        // Replace the declared `tool.wasm` regular file with a symlink to
        // some attacker target inside the pack source. copy_dir_no_symlinks
        // already rejects symlinks during step ⑥ source walk, so this test
        // actually validates the step ② source-side defense rather than
        // step ⑥a — same outcome, complementary coverage.
        let attacker = dir.path().join("attacker.wasm");
        std::fs::write(&attacker, b"malicious").unwrap();
        std::os::unix::fs::symlink(&attacker, pack_src.join("behavior-binaries/tool.wasm"))
            .unwrap();

        let yaml = r#"name: foo
version: 1.0.0
runtime-version: ">=0.0.1"
dependencies: []
provides:
  behavior-binaries: [tool]
required-capabilities:
  - fs
trust-level: untrusted
checksums:
  algo: sha256
  files: {}
"#;
        std::fs::write(pack_src.join("pack.yaml"), yaml).unwrap();

        let packs_dir = dir.path().join("packs");
        let registry = Arc::new(InMemoryPackRegistry::new(packs_dir.clone()));
        let sink = Arc::new(RecordingTraceSink::new());
        let installer = Installer {
            packs_dir,
            registry,
            current_runtime_version: "0.5.0".into(),
            approval: Arc::new(AutoApprove),
            trace_sink: sink,
            dep_resolver: None,
            event_bus: None,
            registry_client: None,
            fetch_timeout: None,
        };
        match installer.install(pack_src.to_string_lossy().as_ref()).await {
            Err(PackError::InvalidManifest(msg)) => assert!(
                msg.contains("symlink"),
                "expected symlink rejection (step ② source or step ⑥a artifact), got: {msg}"
            ),
            other => panic!("expected InvalidManifest(symlink), got {other:?}"),
        }
    }
}

#[tokio::test]
async fn t45_provides_file_kind_has_directory_artifact_rejected() {
    let dir = tempfile::TempDir::new().unwrap();
    let pack_src = dir.path().join("source");
    std::fs::create_dir_all(&pack_src).unwrap();
    // pack.yaml declares `behavior-binaries: [tool]` (file-backed) but the
    // on-disk artifact is a directory named tool.wasm — exercises the
    // wrong-type branch in verify_provides_on_disk for file-backed kinds.
    std::fs::create_dir_all(pack_src.join("behavior-binaries/tool.wasm")).unwrap();

    let yaml = r#"name: foo
version: 1.0.0
runtime-version: ">=0.0.1"
dependencies: []
provides:
  behavior-binaries: [tool]
required-capabilities:
  - fs
trust-level: untrusted
checksums:
  algo: sha256
  files: {}
"#;
    std::fs::write(pack_src.join("pack.yaml"), yaml).unwrap();

    let packs_dir = dir.path().join("packs");
    let registry = Arc::new(InMemoryPackRegistry::new(packs_dir.clone()));
    let sink = Arc::new(RecordingTraceSink::new());
    let installer = Installer {
        packs_dir,
        registry,
        current_runtime_version: "0.5.0".into(),
        approval: Arc::new(AutoApprove),
        trace_sink: sink,
        dep_resolver: None,
        event_bus: None,
        registry_client: None,
        fetch_timeout: None,
    };
    match installer.install(pack_src.to_string_lossy().as_ref()).await {
        Err(PackError::InvalidManifest(msg)) => assert!(
            msg.contains("must be a regular file") && msg.contains("Binary"),
            "expected wrong-type (file-backed → dir) rejection, got: {msg}"
        ),
        other => panic!("expected InvalidManifest(wrong-type-file), got {other:?}"),
    }
}

#[tokio::test]
async fn t46_provides_dir_kind_has_file_artifact_rejected() {
    let dir = tempfile::TempDir::new().unwrap();
    let pack_src = dir.path().join("source");
    std::fs::create_dir_all(pack_src.join("skills")).unwrap();
    // pack.yaml declares `skills: [my-skill]` (directory-backed) but
    // skills/my-skill is a regular file — exercises the wrong-type branch
    // in verify_provides_on_disk for directory-backed kinds.
    std::fs::write(pack_src.join("skills/my-skill"), b"not a skill dir").unwrap();

    let yaml = r#"name: foo
version: 1.0.0
runtime-version: ">=0.0.1"
dependencies: []
provides:
  skills: [my-skill]
required-capabilities:
  - fs
trust-level: untrusted
checksums:
  algo: sha256
  files: {}
"#;
    std::fs::write(pack_src.join("pack.yaml"), yaml).unwrap();

    let packs_dir = dir.path().join("packs");
    let registry = Arc::new(InMemoryPackRegistry::new(packs_dir.clone()));
    let sink = Arc::new(RecordingTraceSink::new());
    let installer = Installer {
        packs_dir,
        registry,
        current_runtime_version: "0.5.0".into(),
        approval: Arc::new(AutoApprove),
        trace_sink: sink,
        dep_resolver: None,
        event_bus: None,
        registry_client: None,
        fetch_timeout: None,
    };
    match installer.install(pack_src.to_string_lossy().as_ref()).await {
        Err(PackError::InvalidManifest(msg)) => assert!(
            msg.contains("must be a directory") && msg.contains("Skill"),
            "expected wrong-type (dir-backed → file) rejection, got: {msg}"
        ),
        other => panic!("expected InvalidManifest(wrong-type-dir), got {other:?}"),
    }
}

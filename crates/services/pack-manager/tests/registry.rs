//! Registry integration tests: T13, T14, T29, T30, T31, T32.

use std::collections::BTreeMap;
use std::sync::Arc;

use advance_pack_manager::{
    ComponentKind, InMemoryPackRegistry, PackChecksums, PackError, PackManifest, PackMetadata,
    PackProvides, PackRegistry, TrustLevel,
};

fn make_manifest(name: &str, version: &str, provides: PackProvides) -> PackManifest {
    let mut files = BTreeMap::new();
    files.insert("pack.yaml".into(), "abc".repeat(22)); // 66 chars; arbitrary hex placeholder
    PackManifest {
        name: name.into(),
        version: version.into(),
        author: None,
        description: None,
        license: None,
        runtime_version: ">=0.0.1".into(),
        dependencies: vec![],
        provides,
        required_capabilities: vec![],
        trust_level: TrustLevel::Untrusted,
        checksums: PackChecksums {
            algo: advance_pack_manager::ChecksumAlgo::Sha256,
            files,
        },
    }
}

fn make_meta(name: &str, version: &str, install_path: std::path::PathBuf) -> PackMetadata {
    PackMetadata {
        name: name.into(),
        version: version.into(),
        install_path,
        trust_level: TrustLevel::Untrusted,
        required_capabilities: vec![],
    }
}

#[tokio::test]
async fn t13_cross_pack_distinct_resolutions() {
    let dir = tempfile::TempDir::new().unwrap();
    let reg = Arc::new(InMemoryPackRegistry::new(dir.path().to_path_buf()));

    // Register pack-a@1.0.0 with behavior-binaries: [tool]
    let pa_path = dir.path().join("pack-a@1.0.0");
    let mut pa_provides = PackProvides::default();
    pa_provides.behavior_binaries.push("tool".into());
    reg.upsert_for_test(
        make_meta("pack-a", "1.0.0", pa_path.clone()),
        make_manifest("pack-a", "1.0.0", pa_provides),
    );

    // Register pack-b@2.0.0 with behavior-binaries: [tool]
    let pb_path = dir.path().join("pack-b@2.0.0");
    let mut pb_provides = PackProvides::default();
    pb_provides.behavior_binaries.push("tool".into());
    reg.upsert_for_test(
        make_meta("pack-b", "2.0.0", pb_path.clone()),
        make_manifest("pack-b", "2.0.0", pb_provides),
    );

    let ra = reg.resolve("pack-a@1.0.0/tool").unwrap();
    let rb = reg.resolve("pack-b@2.0.0/tool").unwrap();

    assert_eq!(ra.pack_name, "pack-a");
    assert_eq!(rb.pack_name, "pack-b");
    assert_ne!(ra.local_path, rb.local_path);
    assert_eq!(ra.component_kind, ComponentKind::Binary);
}

#[tokio::test]
async fn t14_same_name_different_version() {
    let dir = tempfile::TempDir::new().unwrap();
    let reg = Arc::new(InMemoryPackRegistry::new(dir.path().to_path_buf()));

    for v in &["1.0.0", "2.0.0"] {
        let mut p = PackProvides::default();
        p.behavior_binaries.push("tool".into());
        let path = dir.path().join(format!("pack-a@{v}"));
        reg.upsert_for_test(make_meta("pack-a", v, path), make_manifest("pack-a", v, p));
    }

    let r1 = reg.resolve("pack-a@1.0.0/tool").unwrap();
    let r2 = reg.resolve("pack-a@2.0.0/tool").unwrap();
    assert_eq!(r1.version, "1.0.0");
    assert_eq!(r2.version, "2.0.0");
    assert_ne!(r1.local_path, r2.local_path);
}

#[tokio::test]
async fn t29_bare_name_resolves_with_extension() {
    let dir = tempfile::TempDir::new().unwrap();
    let reg = Arc::new(InMemoryPackRegistry::new(dir.path().to_path_buf()));
    let pa_path = dir.path().join("pack-a@1.0.0");
    let mut p = PackProvides::default();
    p.behavior_binaries.push("tool".into());
    reg.upsert_for_test(
        make_meta("pack-a", "1.0.0", pa_path.clone()),
        make_manifest("pack-a", "1.0.0", p),
    );

    let r = reg.resolve("pack-a@1.0.0/tool").unwrap();
    assert_eq!(r.component_kind, ComponentKind::Binary);
    assert_eq!(
        r.local_path,
        pa_path.join("behavior-binaries").join("tool.wasm")
    );
}

#[tokio::test]
async fn t30_prefixed_resolves() {
    let dir = tempfile::TempDir::new().unwrap();
    let reg = Arc::new(InMemoryPackRegistry::new(dir.path().to_path_buf()));
    let pa_path = dir.path().join("pack-a@1.0.0");
    let mut p = PackProvides::default();
    p.behavior_binaries.push("tool".into());
    reg.upsert_for_test(
        make_meta("pack-a", "1.0.0", pa_path.clone()),
        make_manifest("pack-a", "1.0.0", p),
    );

    let r = reg.resolve("pack-a@1.0.0/behavior-binaries/tool").unwrap();
    assert_eq!(r.component_kind, ComponentKind::Binary);
    assert_eq!(
        r.local_path,
        pa_path.join("behavior-binaries").join("tool.wasm")
    );
}

#[tokio::test]
async fn t31_ambiguous_bare_name() {
    let dir = tempfile::TempDir::new().unwrap();
    let reg = Arc::new(InMemoryPackRegistry::new(dir.path().to_path_buf()));
    let pa_path = dir.path().join("pack-a@1.0.0");
    let mut p = PackProvides::default();
    p.behavior_binaries.push("x".into());
    p.workflows.push("x".into());
    reg.upsert_for_test(
        make_meta("pack-a", "1.0.0", pa_path),
        make_manifest("pack-a", "1.0.0", p),
    );

    match reg.resolve("pack-a@1.0.0/x") {
        Err(PackError::AmbiguousComponent { kinds, .. }) => {
            assert_eq!(kinds.len(), 2);
            assert!(kinds.contains(&ComponentKind::Binary));
            assert!(kinds.contains(&ComponentKind::Workflow));
        }
        other => panic!("expected AmbiguousComponent, got {other:?}"),
    }
}

#[tokio::test]
async fn t32_prefixed_name_not_in_provides() {
    let dir = tempfile::TempDir::new().unwrap();
    let reg = Arc::new(InMemoryPackRegistry::new(dir.path().to_path_buf()));
    let pa_path = dir.path().join("pack-a@1.0.0");
    let p = PackProvides::default(); // empty components: []
    reg.upsert_for_test(
        make_meta("pack-a", "1.0.0", pa_path),
        make_manifest("pack-a", "1.0.0", p),
    );

    match reg.resolve("pack-a@1.0.0/components/missing") {
        Err(PackError::ComponentNotFound { .. }) => {}
        other => panic!("expected ComponentNotFound, got {other:?}"),
    }
}

/// Slice C — function name retained for git-diff readability; body
/// rewritten to assert the AC-14 PackNotFound semantic (no fixture pack
/// installed, so the lookup precedes the constraint-surface check).
/// Positive AC-14 happy-path coverage lives in tests/resolve_pack_component.rs.
#[tokio::test]
async fn resolve_pack_component_is_not_implemented() {
    let dir = tempfile::TempDir::new().unwrap();
    let reg = InMemoryPackRegistry::new(dir.path().to_path_buf());
    match reg.resolve_pack_component("pack-a@1.0.0/foo") {
        Err(PackError::PackNotFound(name, ver)) => {
            assert_eq!(name, "pack-a");
            assert_eq!(ver, "1.0.0");
        }
        other => panic!("expected PackNotFound (no fixture), got {other:?}"),
    }
}

// Codex round-3 Info: regression coverage for malicious .meta.yaml keys and
// the fresh-install empty-dir path through rescan().

#[tokio::test]
async fn rescan_fresh_dir_returns_empty_registry() {
    let dir = tempfile::TempDir::new().unwrap();
    let missing = dir.path().join("nonexistent-packs-dir");
    let reg = InMemoryPackRegistry::new(missing);
    reg.rescan()
        .await
        .expect("missing packs_dir → empty registry, not Io");
    assert!(reg.list_installed().is_empty());
}

#[tokio::test]
async fn rescan_rejects_malicious_meta_key_traversal() {
    use advance_pack_manager::{MetaIndex, MetaPackEntry, MetaScope, TrustLevel};

    let dir = tempfile::TempDir::new().unwrap();
    let packs_dir = dir.path().join("packs");
    std::fs::create_dir_all(&packs_dir).unwrap();

    let mut idx = MetaIndex {
        scope: MetaScope::default(),
        packs: Default::default(),
    };
    // Inject a key with `..` traversal — rescan must reject before any join.
    idx.packs.insert(
        "evil..@1.0.0".into(),
        MetaPackEntry {
            description: None,
            installed_at: "2026-05-11T00:00:00Z".into(),
            required_capabilities: vec!["fs".into()],
            trust_level: TrustLevel::Untrusted,
        },
    );
    let yaml = serde_yml::to_string(&idx).unwrap();
    std::fs::write(packs_dir.join(".meta.yaml"), yaml).unwrap();

    let reg = InMemoryPackRegistry::new(packs_dir);
    match reg.rescan().await {
        Err(PackError::InvalidManifest(msg)) => {
            assert!(
                msg.contains("rejected") || msg.contains("traversal"),
                "expected key rejection, got: {msg}"
            );
        }
        other => panic!("expected InvalidManifest for malicious key, got {other:?}"),
    }
    assert!(reg.list_installed().is_empty());
}

#[tokio::test]
async fn rescan_rejects_malicious_meta_key_separator() {
    use advance_pack_manager::{MetaIndex, MetaPackEntry, MetaScope, TrustLevel};

    let dir = tempfile::TempDir::new().unwrap();
    let packs_dir = dir.path().join("packs");
    std::fs::create_dir_all(&packs_dir).unwrap();

    let mut idx = MetaIndex {
        scope: MetaScope::default(),
        packs: Default::default(),
    };
    // Key with `/` — would join into a nested filesystem path.
    idx.packs.insert(
        "sub/pack@1.0.0".into(),
        MetaPackEntry {
            description: None,
            installed_at: "2026-05-11T00:00:00Z".into(),
            required_capabilities: vec!["fs".into()],
            trust_level: TrustLevel::Untrusted,
        },
    );
    let yaml = serde_yml::to_string(&idx).unwrap();
    std::fs::write(packs_dir.join(".meta.yaml"), yaml).unwrap();

    let reg = InMemoryPackRegistry::new(packs_dir);
    match reg.rescan().await {
        Err(PackError::InvalidManifest(_)) => {}
        other => panic!("expected InvalidManifest, got {other:?}"),
    }
}

// Round-9 adversarial defenses: rescan tamper detection + .meta.yaml
// hardening. Each test exercises one of the round-9 fixes against a
// crafted attacker scenario.

#[tokio::test]
async fn rescan_rejects_at_symbol_in_key() {
    use advance_pack_manager::{MetaIndex, MetaPackEntry, MetaScope, TrustLevel};

    let dir = tempfile::TempDir::new().unwrap();
    let packs_dir = dir.path().join("packs");
    std::fs::create_dir_all(&packs_dir).unwrap();

    let mut idx = MetaIndex {
        scope: MetaScope::default(),
        packs: Default::default(),
    };
    // Key with two `@` would split as name="foo", version="bar@1.0.0" —
    // post-split version contains @ which the round-9 hardening rejects.
    idx.packs.insert(
        "foo@bar@1.0.0".into(),
        MetaPackEntry {
            description: None,
            installed_at: "2026-05-11T00:00:00Z".into(),
            required_capabilities: vec!["fs".into()],
            trust_level: TrustLevel::Untrusted,
        },
    );
    let yaml = serde_yml::to_string(&idx).unwrap();
    std::fs::write(packs_dir.join(".meta.yaml"), yaml).unwrap();

    let reg = InMemoryPackRegistry::new(packs_dir);
    match reg.rescan().await {
        Err(PackError::InvalidManifest(msg)) => assert!(
            msg.contains("extra `@`") || msg.contains("@"),
            "expected @-rejection, got: {msg}"
        ),
        other => panic!("expected InvalidManifest, got {other:?}"),
    }
}

#[tokio::test]
async fn rescan_rejects_unicode_invisible_in_key() {
    use advance_pack_manager::{MetaIndex, MetaPackEntry, MetaScope, TrustLevel};

    let dir = tempfile::TempDir::new().unwrap();
    let packs_dir = dir.path().join("packs");
    std::fs::create_dir_all(&packs_dir).unwrap();

    let mut idx = MetaIndex {
        scope: MetaScope::default(),
        packs: Default::default(),
    };
    // Zero-width space U+200B in the key — visually impersonates ASCII
    // but resolves to a different filesystem path. Round-9 hardening
    // rejects all Unicode control / whitespace codepoints in keys.
    idx.packs.insert(
        "foo\u{200B}bar@1.0.0".into(),
        MetaPackEntry {
            description: None,
            installed_at: "2026-05-11T00:00:00Z".into(),
            required_capabilities: vec!["fs".into()],
            trust_level: TrustLevel::Untrusted,
        },
    );
    let yaml = serde_yml::to_string(&idx).unwrap();
    std::fs::write(packs_dir.join(".meta.yaml"), yaml).unwrap();

    let reg = InMemoryPackRegistry::new(packs_dir);
    match reg.rescan().await {
        Err(PackError::InvalidManifest(msg)) => assert!(
            msg.contains("non-ASCII") || msg.contains("control") || msg.contains("whitespace"),
            "expected non-ASCII/control/whitespace rejection, got: {msg}"
        ),
        other => panic!("expected InvalidManifest, got {other:?}"),
    }
}

#[tokio::test]
async fn rescan_rejects_meta_trust_level_drift() {
    use advance_pack_manager::{MetaIndex, MetaPackEntry, MetaScope, TrustLevel};

    let dir = tempfile::TempDir::new().unwrap();
    let packs_dir = dir.path().join("packs");
    std::fs::create_dir_all(&packs_dir).unwrap();
    // Install a pack with trust_level=Untrusted in pack.yaml.
    let install_path = packs_dir.join("foo@1.0.0");
    std::fs::create_dir_all(&install_path).unwrap();
    let pack_yaml = r#"name: foo
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
  files: {}
"#;
    std::fs::write(install_path.join("pack.yaml"), pack_yaml).unwrap();

    // Now write a tampered .meta.yaml that claims Trusted for the same pack.
    let mut idx = MetaIndex {
        scope: MetaScope::default(),
        packs: Default::default(),
    };
    idx.packs.insert(
        "foo@1.0.0".into(),
        MetaPackEntry {
            description: None,
            installed_at: "2026-05-11T00:00:00Z".into(),
            required_capabilities: vec!["fs".into()],
            trust_level: TrustLevel::Trusted, // ← TAMPER
        },
    );
    let yaml = serde_yml::to_string(&idx).unwrap();
    std::fs::write(packs_dir.join(".meta.yaml"), yaml).unwrap();

    let reg = InMemoryPackRegistry::new(packs_dir);
    match reg.rescan().await {
        Err(PackError::InvalidManifest(msg)) => assert!(
            msg.contains("trust_level") && msg.contains("tamper"),
            "expected trust_level tamper rejection, got: {msg}"
        ),
        other => panic!("expected InvalidManifest, got {other:?}"),
    }
}

#[tokio::test]
async fn rescan_rejects_meta_required_capabilities_drift() {
    use advance_pack_manager::{MetaIndex, MetaPackEntry, MetaScope, TrustLevel};

    let dir = tempfile::TempDir::new().unwrap();
    let packs_dir = dir.path().join("packs");
    std::fs::create_dir_all(&packs_dir).unwrap();
    let install_path = packs_dir.join("foo@1.0.0");
    std::fs::create_dir_all(&install_path).unwrap();
    let pack_yaml = r#"name: foo
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
  files: {}
"#;
    std::fs::write(install_path.join("pack.yaml"), pack_yaml).unwrap();

    let mut idx = MetaIndex {
        scope: MetaScope::default(),
        packs: Default::default(),
    };
    idx.packs.insert(
        "foo@1.0.0".into(),
        MetaPackEntry {
            description: None,
            installed_at: "2026-05-11T00:00:00Z".into(),
            // Tampered: claim only fewer/different caps than pack.yaml.
            required_capabilities: vec![],
            trust_level: TrustLevel::Untrusted,
        },
    );
    let yaml = serde_yml::to_string(&idx).unwrap();
    std::fs::write(packs_dir.join(".meta.yaml"), yaml).unwrap();

    let reg = InMemoryPackRegistry::new(packs_dir);
    match reg.rescan().await {
        Err(PackError::InvalidManifest(msg)) => assert!(
            msg.contains("required_capabilities") && msg.contains("tamper"),
            "expected required_capabilities tamper rejection, got: {msg}"
        ),
        other => panic!("expected InvalidManifest, got {other:?}"),
    }
}

#[tokio::test]
async fn rescan_rejects_post_install_artifact_tamper() {
    use advance_pack_manager::{MetaIndex, MetaPackEntry, MetaScope, TrustLevel};

    let dir = tempfile::TempDir::new().unwrap();
    let packs_dir = dir.path().join("packs");
    std::fs::create_dir_all(&packs_dir).unwrap();
    let install_path = packs_dir.join("foo@1.0.0");
    std::fs::create_dir_all(install_path.join("behavior-binaries")).unwrap();
    // pack.yaml declares behavior-binaries: [tool] but the artifact has
    // been deleted post-install (or never existed in this attacker
    // scenario). Codex r3 W1 attack: install once, then delete the
    // artifact, then trigger rescan.
    let pack_yaml = r#"name: foo
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
    std::fs::write(install_path.join("pack.yaml"), pack_yaml).unwrap();
    // tool.wasm is intentionally NOT created — simulates post-install
    // tamper / deletion. Without the round-3 fix, rescan accepts.

    let mut idx = MetaIndex {
        scope: MetaScope::default(),
        packs: Default::default(),
    };
    idx.packs.insert(
        "foo@1.0.0".into(),
        MetaPackEntry {
            description: None,
            installed_at: "2026-05-12T00:00:00Z".into(),
            required_capabilities: vec!["fs".into()],
            trust_level: TrustLevel::Untrusted,
        },
    );
    let yaml = serde_yml::to_string(&idx).unwrap();
    std::fs::write(packs_dir.join(".meta.yaml"), yaml).unwrap();

    let reg = InMemoryPackRegistry::new(packs_dir);
    match reg.rescan().await {
        Err(PackError::InvalidManifest(msg)) => assert!(
            msg.contains("missing on disk") && msg.contains("Binary"),
            "expected post-install artifact-missing rejection, got: {msg}"
        ),
        other => panic!("expected InvalidManifest(missing artifact), got {other:?}"),
    }
}

#[tokio::test]
async fn rescan_rejects_meta_yaml_alias_bomb() {
    let dir = tempfile::TempDir::new().unwrap();
    let packs_dir = dir.path().join("packs");
    std::fs::create_dir_all(&packs_dir).unwrap();
    // YAML billion-laughs: small file balloons during alias deref.
    let bomb = r#"_scope:
  description: bomb
  tags: [admin]
a: &a [1,1,1,1,1,1,1,1,1]
b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]
"#;
    std::fs::write(packs_dir.join(".meta.yaml"), bomb).unwrap();

    let reg = InMemoryPackRegistry::new(packs_dir);
    match reg.rescan().await {
        Err(PackError::InvalidManifest(msg)) => assert!(
            msg.contains("alias references") || msg.contains("billion-laughs"),
            "expected alias-ref rejection, got: {msg}"
        ),
        other => panic!("expected InvalidManifest(alias), got {other:?}"),
    }
}

#[tokio::test]
async fn rescan_rejects_meta_yaml_symlink() {
    #[cfg(not(unix))]
    {
        eprintln!("symlink test skipped on non-Unix");
        return;
    }
    #[cfg(unix)]
    {
        let dir = tempfile::TempDir::new().unwrap();
        let packs_dir = dir.path().join("packs");
        std::fs::create_dir_all(&packs_dir).unwrap();
        // Plant a victim target outside packs_dir that the attacker would
        // want to leak content of via the parse-error excerpt.
        let victim = dir.path().join("victim_secrets.txt");
        std::fs::write(&victim, b"super-secret-content").unwrap();
        // Replace .meta.yaml with a symlink to the victim.
        std::os::unix::fs::symlink(&victim, packs_dir.join(".meta.yaml")).unwrap();

        let reg = InMemoryPackRegistry::new(packs_dir);
        match reg.rescan().await {
            Err(PackError::InvalidManifest(msg)) => assert!(
                msg.contains("symlink"),
                "expected symlink rejection, got: {msg}"
            ),
            other => panic!("expected InvalidManifest(symlink), got {other:?}"),
        }
    }
}

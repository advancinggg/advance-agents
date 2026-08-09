//! Slice D AC-05+AC-08 cross-source recursive deps + T82d parse_source
//! dispatch arm coverage + T82e validate() negative coverage.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use advance_pack_manager::{
    parse_source, AutoApprove, DependencyResolver, InMemoryPackRegistry, Installer,
    MockRegistryClient, PackError, PackRegistry, RecordingTraceSink, SourceRef,
};

mod common;
use common::{build_tarball_fixture, FixtureContent};

#[test]
fn t82d_parse_source_dispatch_arm_coverage() {
    assert_eq!(
        parse_source("./pack").unwrap(),
        SourceRef::Local(PathBuf::from("./pack"))
    );
    assert_eq!(
        parse_source("git+https://x/r").unwrap(),
        SourceRef::GitUrl {
            url: "https://x/r".into(),
            git_ref: None
        }
    );
    assert_eq!(
        parse_source("git+file:///tmp/r@v1").unwrap(),
        SourceRef::GitUrl {
            url: "file:///tmp/r".into(),
            git_ref: Some("v1".into())
        }
    );
    assert_eq!(
        parse_source("/tmp/p.tar.gz").unwrap(),
        SourceRef::Tarball(PathBuf::from("/tmp/p.tar.gz"))
    );
    assert_eq!(
        parse_source("registry:foo@1.0.0").unwrap(),
        SourceRef::Registry {
            name: "foo".into(),
            version: "1.0.0".into()
        }
    );
}

#[tokio::test]
async fn t82e_validate_rejects_resolver_injected_invalid_source_ref() {
    // (a) Registry traversal name
    let src = SourceRef::Registry {
        name: "../etc".into(),
        version: "passwd".into(),
    };
    assert!(matches!(src.validate(), Err(PackError::InvalidManifest(_))));

    // (b) Registry empty name
    let src = SourceRef::Registry {
        name: "".into(),
        version: "1.0".into(),
    };
    assert!(matches!(src.validate(), Err(PackError::InvalidManifest(_))));

    // (c) GitUrl invalid scheme
    let src = SourceRef::GitUrl {
        url: "ftp://x/r".into(),
        git_ref: None,
    };
    assert!(matches!(src.validate(), Err(PackError::InvalidManifest(_))));

    // (d) GitUrl empty URL
    let src = SourceRef::GitUrl {
        url: "".into(),
        git_ref: None,
    };
    assert!(matches!(src.validate(), Err(PackError::InvalidManifest(_))));

    // (e) GitUrl leading-dash ref
    let src = SourceRef::GitUrl {
        url: "https://x/r".into(),
        git_ref: Some("-rf".into()),
    };
    assert!(matches!(src.validate(), Err(PackError::InvalidManifest(_))));

    // (f) GitUrl slash in ref (round-7 W2 add)
    let src = SourceRef::GitUrl {
        url: "https://x/r".into(),
        git_ref: Some("feature/foo".into()),
    };
    assert!(matches!(src.validate(), Err(PackError::InvalidManifest(_))));

    // (g) GitUrl `.lock` suffix
    let src = SourceRef::GitUrl {
        url: "https://x/r".into(),
        git_ref: Some("v1.lock".into()),
    };
    assert!(matches!(src.validate(), Err(PackError::InvalidManifest(_))));

    // (h) GitUrl trailing dot
    let src = SourceRef::GitUrl {
        url: "https://x/r".into(),
        git_ref: Some("v1.".into()),
    };
    assert!(matches!(src.validate(), Err(PackError::InvalidManifest(_))));

    // (i) GitUrl overlength
    let src = SourceRef::GitUrl {
        url: "https://x/r".into(),
        git_ref: Some("a".repeat(256)),
    };
    assert!(matches!(src.validate(), Err(PackError::InvalidManifest(_))));

    // (j) GitUrl forbidden metacharacter
    let src = SourceRef::GitUrl {
        url: "https://x/r".into(),
        git_ref: Some("v1?x".into()),
    };
    assert!(matches!(src.validate(), Err(PackError::InvalidManifest(_))));

    // (k) GitUrl SHA-shaped ref
    let src = SourceRef::GitUrl {
        url: "https://x/r".into(),
        git_ref: Some("abcdef0123456789abcdef0123456789abcdef01".into()),
    };
    assert!(matches!(src.validate(), Err(PackError::InvalidManifest(_))));

    // (l) Tarball wrong extension
    let src = SourceRef::Tarball(PathBuf::from("/tmp/p.bin"));
    assert!(matches!(src.validate(), Err(PackError::InvalidManifest(_))));

    // (m) AUDIT round-3 fix Codex Diff W1: resolver-injected userinfo URL with
    // `@` in url field. parse_source's strict 0/1/2+ @ rule would reject this
    // at parse time; validate() must enforce the same invariant on the
    // recursive-injection path so a buggy/hostile resolver cannot bypass.
    let src = SourceRef::GitUrl {
        url: "https://user:token@host/repo".into(),
        git_ref: None,
    };
    match src.validate() {
        Err(PackError::InvalidManifest(msg)) => {
            assert!(
                msg.contains("'@'") || msg.contains("@<ref>"),
                "expected @-rejection diagnostic, got: {msg}"
            );
        }
        other => panic!("expected InvalidManifest(@ rejection), got {other:?}"),
    }
}

/// Mock resolver for T82b — returns a tarball SourceRef for the named dep.
struct TarballResolver {
    tarball: PathBuf,
}

#[async_trait]
impl DependencyResolver for TarballResolver {
    async fn resolve(
        &self,
        _name: &str,
        _req: &semver::VersionReq,
    ) -> Result<SourceRef, PackError> {
        Ok(SourceRef::Tarball(self.tarball.clone()))
    }
}

/// Mock resolver for T82c — returns a Registry SourceRef for the named dep.
struct RegistryResolver {
    name: String,
    version: String,
}

#[async_trait]
impl DependencyResolver for RegistryResolver {
    async fn resolve(
        &self,
        _name: &str,
        _req: &semver::VersionReq,
    ) -> Result<SourceRef, PackError> {
        Ok(SourceRef::Registry {
            name: self.name.clone(),
            version: self.version.clone(),
        })
    }
}

/// T82b — recursive deps with tarball child. Root pack is Local with a dep on
/// `child@^1.0.0`; resolver returns a tarball SourceRef. Both installs
/// complete; both packs in registry.
#[tokio::test]
async fn t82b_recursive_deps_tarball_child() {
    let fixture_dir = tempfile::TempDir::new().unwrap();
    let child_tarball = build_tarball_fixture(fixture_dir.path(), FixtureContent::ValidPack);

    // Root pack — Local, declares dep on `foo@^1.0.0`.
    let root_dir = tempfile::TempDir::new().unwrap();
    let root_pack = root_dir.path().join("root_pack");
    std::fs::create_dir_all(&root_pack).unwrap();
    std::fs::write(
        root_pack.join("pack.yaml"),
        r#"name: root
version: 1.0.0
description: root pack with dep
runtime-version: ">=0.1.0"
dependencies:
  - name: foo
    version: "^1.0.0"
provides:
  behavior-binaries:
    - dummy
checksums:
  algo: sha256
  files: {}
trust-level: untrusted
"#,
    )
    .unwrap();
    std::fs::create_dir_all(root_pack.join("behavior-binaries")).unwrap();
    std::fs::write(
        root_pack.join("behavior-binaries/dummy.wasm"),
        b"\0asm\x01\x00\x00\x00",
    )
    .unwrap();

    let packs_dir = tempfile::TempDir::new().unwrap();
    let registry = Arc::new(InMemoryPackRegistry::new(packs_dir.path().to_path_buf()));
    let installer = Installer {
        packs_dir: packs_dir.path().to_path_buf(),
        registry: registry.clone(),
        current_runtime_version: "0.1.0".to_string(),
        approval: Arc::new(AutoApprove),
        trace_sink: Arc::new(RecordingTraceSink::new()),
        dep_resolver: Some(Arc::new(TarballResolver {
            tarball: child_tarball,
        })),
        event_bus: None,
        registry_client: None,
        fetch_timeout: None,
    };

    installer
        .install(root_pack.to_str().unwrap())
        .await
        .expect("root install w/ tarball child should succeed");
    assert!(registry.has("root", "1.0.0"));
    assert!(registry.has("foo", "1.0.0"));
}

/// T82f — ADVERSARIAL round-1 Codex W7: cross-source dependency
/// name-identity-binding regression. A hostile resolver returns a Local pack
/// whose own manifest declares `name: wrapper` (NOT `name: foo`) when asked
/// for `foo`. The recursive install completes, but the post-install
/// name-binding check in deps.rs catches that report.name != dep.name and
/// rejects with `DependencyVersionMismatch` mentioning "substitution-attack
/// rejected".
#[tokio::test]
async fn t82f_resolver_wrapper_substitution_rejected() {
    // Build a "wrapper" pack on disk: pack.yaml says name=wrapper, version=1.0.0,
    // but the resolver returns this when asked for `foo`.
    let wrapper_dir = tempfile::TempDir::new().unwrap();
    let wrapper_pack = wrapper_dir.path().join("wrapper_pack");
    std::fs::create_dir_all(&wrapper_pack).unwrap();
    std::fs::write(
        wrapper_pack.join("pack.yaml"),
        r#"name: wrapper
version: 1.0.0
description: substitution attack — wrapper pretending to be foo
runtime-version: ">=0.1.0"
provides:
  behavior-binaries:
    - dummy
checksums:
  algo: sha256
  files: {}
trust-level: untrusted
"#,
    )
    .unwrap();
    std::fs::create_dir_all(wrapper_pack.join("behavior-binaries")).unwrap();
    std::fs::write(
        wrapper_pack.join("behavior-binaries/dummy.wasm"),
        b"\0asm\x01\x00\x00\x00",
    )
    .unwrap();

    struct WrapperSubstitutionResolver {
        wrapper_path: PathBuf,
    }
    #[async_trait]
    impl DependencyResolver for WrapperSubstitutionResolver {
        async fn resolve(
            &self,
            _name: &str,
            _req: &semver::VersionReq,
        ) -> Result<SourceRef, PackError> {
            Ok(SourceRef::Local(self.wrapper_path.clone()))
        }
    }

    let root_dir = tempfile::TempDir::new().unwrap();
    let root_pack = root_dir.path().join("root_pack");
    std::fs::create_dir_all(&root_pack).unwrap();
    std::fs::write(
        root_pack.join("pack.yaml"),
        r#"name: root
version: 1.0.0
description: root pack
runtime-version: ">=0.1.0"
dependencies:
  - name: foo
    version: "^1.0.0"
provides:
  behavior-binaries:
    - dummy
checksums:
  algo: sha256
  files: {}
trust-level: untrusted
"#,
    )
    .unwrap();
    std::fs::create_dir_all(root_pack.join("behavior-binaries")).unwrap();
    std::fs::write(
        root_pack.join("behavior-binaries/dummy.wasm"),
        b"\0asm\x01\x00\x00\x00",
    )
    .unwrap();

    let packs_dir = tempfile::TempDir::new().unwrap();
    let registry = Arc::new(InMemoryPackRegistry::new(packs_dir.path().to_path_buf()));
    let installer = Installer {
        packs_dir: packs_dir.path().to_path_buf(),
        registry: registry.clone(),
        current_runtime_version: "0.1.0".to_string(),
        approval: Arc::new(AutoApprove),
        trace_sink: Arc::new(RecordingTraceSink::new()),
        dep_resolver: Some(Arc::new(WrapperSubstitutionResolver {
            wrapper_path: wrapper_pack,
        })),
        event_bus: None,
        registry_client: None,
        fetch_timeout: None,
    };

    let res = installer.install(root_pack.to_str().unwrap()).await;
    match res {
        Err(PackError::DependencyVersionMismatch { name, found, .. }) => {
            assert_eq!(name, "foo");
            assert!(
                found.contains("wrapper") && found.contains("substitution-attack"),
                "expected substitution-attack diagnostic, got: found={found}"
            );
        }
        other => panic!("expected DependencyVersionMismatch(substitution-attack), got {other:?}"),
    }
}

/// T82c — recursive deps with registry child. Root pack is Local with a dep on
/// `child@^1.0.0`; resolver returns Registry SourceRef; MockRegistryClient
/// supplies the tarball fixture.
#[tokio::test]
async fn t82c_recursive_deps_registry_child() {
    let fixture_dir = tempfile::TempDir::new().unwrap();
    let child_tarball = build_tarball_fixture(fixture_dir.path(), FixtureContent::ValidPack);

    let root_dir = tempfile::TempDir::new().unwrap();
    let root_pack = root_dir.path().join("root_pack");
    std::fs::create_dir_all(&root_pack).unwrap();
    std::fs::write(
        root_pack.join("pack.yaml"),
        r#"name: root
version: 1.0.0
description: root pack with registry dep
runtime-version: ">=0.1.0"
dependencies:
  - name: foo
    version: "^1.0.0"
provides:
  behavior-binaries:
    - dummy
checksums:
  algo: sha256
  files: {}
trust-level: untrusted
"#,
    )
    .unwrap();
    std::fs::create_dir_all(root_pack.join("behavior-binaries")).unwrap();
    std::fs::write(
        root_pack.join("behavior-binaries/dummy.wasm"),
        b"\0asm\x01\x00\x00\x00",
    )
    .unwrap();

    let mock_reg = Arc::new(MockRegistryClient::new());
    mock_reg.insert_fixture("foo", "1.0.0", child_tarball);

    let packs_dir = tempfile::TempDir::new().unwrap();
    let registry = Arc::new(InMemoryPackRegistry::new(packs_dir.path().to_path_buf()));
    let installer = Installer {
        packs_dir: packs_dir.path().to_path_buf(),
        registry: registry.clone(),
        current_runtime_version: "0.1.0".to_string(),
        approval: Arc::new(AutoApprove),
        trace_sink: Arc::new(RecordingTraceSink::new()),
        dep_resolver: Some(Arc::new(RegistryResolver {
            name: "foo".into(),
            version: "1.0.0".into(),
        })),
        event_bus: None,
        registry_client: Some(mock_reg),
        fetch_timeout: Some(Duration::from_secs(10)),
    };

    installer
        .install(root_pack.to_str().unwrap())
        .await
        .expect("root install w/ registry child should succeed");
    assert!(registry.has("root", "1.0.0"));
    assert!(registry.has("foo", "1.0.0"));
}

//! Slice D AC-05 git+file:// / git+https:// install path tests.
//! T70a (no-ref → HEAD), T70b (`@v1.0` → tag), T71 (scheme rejection),
//! T71b (ref grammar), T72/T73 (env hardening), T74 (timeout/unreachable),
//! T74b (git binary preflight), T82a (cross-source: git child).
//!
//! All tests acquire `ENV_LOCK` because git subprocess invocations observe
//! process-wide env vars (HOME, PATH, XDG_CONFIG_HOME); env-mutating tests
//! (T72/T73/T74b) and env-observing tests (T70a/T70b/T74/T82a/T83) must
//! serialize within this binary.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use advance_pack_manager::{
    parse_source, AutoApprove, DependencyResolver, InMemoryPackRegistry, Installer, PackError,
    PackRegistry, RecordingTraceSink, SourceRef,
};

mod common;
use common::{build_git_fixture, ENV_LOCK};

fn make_installer(packs_dir: &std::path::Path) -> Installer {
    Installer {
        packs_dir: packs_dir.to_path_buf(),
        registry: Arc::new(InMemoryPackRegistry::new(packs_dir.to_path_buf())),
        current_runtime_version: "0.1.0".to_string(),
        approval: Arc::new(AutoApprove),
        trace_sink: Arc::new(RecordingTraceSink::new()),
        dep_resolver: None,
        event_bus: None,
        registry_client: None,
        fetch_timeout: Some(Duration::from_secs(30)),
    }
}

#[tokio::test]
async fn t70a_git_file_no_ref_clones_head() {
    let _g = ENV_LOCK.lock().await;
    let work = tempfile::TempDir::new().unwrap();
    let bare = build_git_fixture(work.path(), true); // 2 commits, HEAD = v2.0.0
    let source = format!("git+file://{}", bare.display());
    let packs_dir = tempfile::TempDir::new().unwrap();
    let installer = make_installer(packs_dir.path());

    let report = installer
        .install(&source)
        .await
        .expect("git no-ref install");
    // HEAD is the v2.0.0 commit per build_git_fixture(true).
    assert_eq!(report.name, "foo");
    assert_eq!(report.version, "2.0.0");
    assert!(installer.registry.has("foo", "2.0.0"));
    // Confirm post-clone `.git` strip — install_path must NOT contain .git/.
    let install_dir = packs_dir.path().join("foo@2.0.0");
    assert!(
        !install_dir.join(".git").exists(),
        ".git directory should be stripped post-clone"
    );
}

#[tokio::test]
async fn t70b_git_file_with_v10_tag_clones_tagged_commit() {
    let _g = ENV_LOCK.lock().await;
    let work = tempfile::TempDir::new().unwrap();
    let bare = build_git_fixture(work.path(), true);
    let source = format!("git+file://{}@v1.0", bare.display());
    let packs_dir = tempfile::TempDir::new().unwrap();
    let installer = make_installer(packs_dir.path());

    let report = installer.install(&source).await.expect("git @v1.0 install");
    // v1.0 tag points to the FIRST commit which had pack.yaml { version: 1.0.0 }.
    assert_eq!(report.name, "foo");
    assert_eq!(report.version, "1.0.0");
    assert!(installer.registry.has("foo", "1.0.0"));
    // Confirm tagged content via pack.yaml read.
    let install_pack_yaml = packs_dir.path().join("foo@1.0.0/pack.yaml");
    let content = std::fs::read_to_string(&install_pack_yaml).unwrap();
    assert!(content.contains("version: 1.0.0"));
    assert!(content.contains("v1.0.0 tagged"));
}

#[test]
fn t71_git_url_scheme_whitelist_rejects_invalid_schemes() {
    // For URLs with no `@`, scheme-rejection fires directly.
    for bad in &["git+http://example.com/r", "git+git://example.com/r"] {
        match parse_source(bad) {
            Err(PackError::InvalidManifest(msg)) => {
                assert!(
                    msg.contains("unsupported git URL scheme"),
                    "expected scheme-rejection for {bad}, got: {msg}"
                );
            }
            other => panic!("expected InvalidManifest for {bad}, got {other:?}"),
        }
    }
    // For URLs with `@` like `git+ssh://user@host/r`, the strict 0/1/2+ @ rule
    // fires first: 1 @ → split → right side `host/r` contains `/` → ref-grammar
    // rejection (the scheme rejection would have fired second, but ref check
    // shadows it). Either error path is correct rejection of the malformed URL.
    let ssh_case = "git+ssh://user@host/r";
    match parse_source(ssh_case) {
        Err(PackError::InvalidManifest(msg)) => {
            assert!(
                msg.contains("unsupported git URL scheme")
                    || msg.contains("forbidden character")
                    || msg.contains("multiple @"),
                "expected scheme-or-ref-rejection for {ssh_case}, got: {msg}"
            );
        }
        other => panic!("expected InvalidManifest for {ssh_case}, got {other:?}"),
    }
}

#[test]
fn t71b_git_ref_grammar_comprehensive_positive_and_negative() {
    // Positive cases
    assert!(matches!(
        parse_source("git+https://x/r@v1.0").unwrap(),
        SourceRef::GitUrl { git_ref: Some(ref r), .. } if r == "v1.0"
    ));
    assert!(matches!(
        parse_source("git+https://x/r@v1.0.0+build.123").unwrap(),
        SourceRef::GitUrl { git_ref: Some(ref r), .. } if r == "v1.0.0+build.123"
    ));
    assert!(matches!(
        parse_source("git+https://x/r").unwrap(),
        SourceRef::GitUrl { git_ref: None, .. }
    ));
    // 255-char length boundary — accepted
    let long_ref = "a".repeat(255);
    let long_url = format!("git+https://x/r@{long_ref}");
    assert!(matches!(
        parse_source(&long_url).unwrap(),
        SourceRef::GitUrl {
            git_ref: Some(_),
            ..
        }
    ));

    // Negative cases — each MUST return InvalidManifest
    let neg = vec![
        ("git+https://x/r@-rf", "leading dash"),
        ("git+https://x/r@a..b", "dot-dot"),
        ("git+https://x/r@v1\nfoo", "newline / control"),
        ("git+https://x/r@v1 spaces", "whitespace"),
        ("git+https://x/r@", "empty ref"),
        ("git+https://x/r@feature/foo", "slash in ref"),
        ("git+https://x/r@.hidden", "leading dot"),
        ("git+https://x/r@trailing.", "trailing dot"),
        ("git+https://x/r@v1.lock", ".lock suffix"),
        ("git+https://x/r@v1?query", "? metacharacter"),
        ("git+https://x/r@v1^upstream", "^ metacharacter"),
        ("git+https://x/r@v1~1", "~ metacharacter"),
        ("git+https://x/r@v1:foo", ": metacharacter"),
        ("git+https://x/r@v1*glob", "* metacharacter"),
        ("git+https://x/r@v1[bracket", "[ metacharacter"),
        (
            "git+https://x/r@abcdef0123456789abcdef0123456789abcdef01",
            "40-char SHA",
        ),
        ("git+https://user@host/r@v1", "2+ @"),
        (
            "git+https://user@host/r",
            "userinfo URL without explicit ref → 1@ but slash on right",
        ),
    ];
    for (input, label) in neg {
        match parse_source(input) {
            Err(PackError::InvalidManifest(_)) => {}
            other => panic!("expected InvalidManifest for {label} ({input:?}), got {other:?}"),
        }
    }

    // 256-char overlength — InvalidManifest
    let too_long = format!("git+https://x/r@{}", "a".repeat(256));
    assert!(matches!(
        parse_source(&too_long),
        Err(PackError::InvalidManifest(_))
    ));
    // Backslash in ref — InvalidManifest
    let backslash = r"git+https://x/r@v1\backslash";
    assert!(matches!(
        parse_source(backslash),
        Err(PackError::InvalidManifest(_))
    ));
}

#[tokio::test]
async fn t72_git_clone_env_clear_drops_home_insteadof_redirect() {
    let _g = ENV_LOCK.lock().await;
    let work = tempfile::TempDir::new().unwrap();
    let bare = build_git_fixture(work.path(), false);
    let source = format!("git+file://{}", bare.display());

    // Set HOME to a tempdir with a poisoned `.gitconfig` that would redirect.
    let poisoned_home = tempfile::TempDir::new().unwrap();
    let gitconfig = poisoned_home.path().join(".gitconfig");
    std::fs::write(
        &gitconfig,
        format!(
            r#"[url "file:///etc/passwd"]
    insteadOf = file://{}
"#,
            bare.display()
        ),
    )
    .unwrap();
    let original_home = std::env::var_os("HOME");
    std::env::set_var("HOME", poisoned_home.path());

    let packs_dir = tempfile::TempDir::new().unwrap();
    let installer = make_installer(packs_dir.path());

    let result = installer.install(&source).await;
    if let Some(h) = original_home {
        std::env::set_var("HOME", h);
    } else {
        std::env::remove_var("HOME");
    }

    // Install should succeed because subprocess env_clear() drops HOME, so the
    // poisoned .gitconfig insteadOf rule is invisible to the git subprocess.
    let report = result.expect("install should succeed; env_clear neutralizes HOME poisoning");
    assert_eq!(report.name, "foo");
}

#[tokio::test]
async fn t73_git_clone_git_config_global_dev_null_short_circuits_external_config() {
    let _g = ENV_LOCK.lock().await;
    let work = tempfile::TempDir::new().unwrap();
    let bare = build_git_fixture(work.path(), false);
    let source = format!("git+file://{}", bare.display());

    // Set XDG_CONFIG_HOME to a poisoned location.
    let poisoned_xdg = tempfile::TempDir::new().unwrap();
    let xdg_git_dir = poisoned_xdg.path().join("git");
    std::fs::create_dir_all(&xdg_git_dir).unwrap();
    std::fs::write(
        xdg_git_dir.join("config"),
        format!(
            r#"[url "file:///etc/passwd"]
    insteadOf = file://{}
"#,
            bare.display()
        ),
    )
    .unwrap();
    let original_xdg = std::env::var_os("XDG_CONFIG_HOME");
    std::env::set_var("XDG_CONFIG_HOME", poisoned_xdg.path());

    let packs_dir = tempfile::TempDir::new().unwrap();
    let installer = make_installer(packs_dir.path());
    let result = installer.install(&source).await;
    if let Some(x) = original_xdg {
        std::env::set_var("XDG_CONFIG_HOME", x);
    } else {
        std::env::remove_var("XDG_CONFIG_HOME");
    }
    let report =
        result.expect("install should succeed; GIT_CONFIG_GLOBAL=/dev/null neutralizes XDG");
    assert_eq!(report.name, "foo");
}

#[tokio::test]
async fn t74_git_clone_timeout_or_unreachable_host() {
    let _g = ENV_LOCK.lock().await;
    let source = "git+https://192.0.2.1/repo"; // TEST-NET-1 per RFC 5737
    let packs_dir = tempfile::TempDir::new().unwrap();
    let mut installer = make_installer(packs_dir.path());
    installer.fetch_timeout = Some(Duration::from_secs(3));

    let res = installer.install(source).await;
    match res {
        Err(PackError::GitCloneFailed { reason, .. }) => {
            // CI-environment-tolerant: accept timeout OR connection-refused OR
            // host-unreachable OR DNS-failure messages.
            let r = reason.to_lowercase();
            assert!(
                r.contains("timeout")
                    || r.contains("could not resolve")
                    || r.contains("connection refused")
                    || r.contains("host")
                    || r.contains("unreachable")
                    || r.contains("connect"),
                "expected timeout-or-unreachable diagnostic, got: {reason}"
            );
        }
        other => panic!("expected GitCloneFailed(timeout/unreachable), got {other:?}"),
    }
}

#[tokio::test]
async fn t74b_git_binary_preflight_error_on_empty_path() {
    let _g = ENV_LOCK.lock().await;
    let work = tempfile::TempDir::new().unwrap();
    let bare = build_git_fixture(work.path(), false);
    let source = format!("git+file://{}", bare.display());
    let packs_dir = tempfile::TempDir::new().unwrap();
    let installer = make_installer(packs_dir.path());

    let original_path = std::env::var_os("PATH");
    std::env::set_var("PATH", "");
    let result = installer.install(&source).await;
    if let Some(p) = original_path {
        std::env::set_var("PATH", p);
    } else {
        std::env::remove_var("PATH");
    }

    match result {
        Err(PackError::GitCloneFailed { reason, .. }) => {
            assert!(
                reason.contains("not found")
                    || reason.contains("No such")
                    || reason.contains("os error"),
                "expected git-binary-not-found diagnostic, got: {reason}"
            );
        }
        other => panic!("expected GitCloneFailed(git not found), got {other:?}"),
    }
}

/// T82a — cross-source recursive dep with git child.
struct GitResolver {
    url: String,
}

#[async_trait]
impl DependencyResolver for GitResolver {
    async fn resolve(
        &self,
        _name: &str,
        _req: &semver::VersionReq,
    ) -> Result<SourceRef, PackError> {
        Ok(SourceRef::GitUrl {
            url: self.url.clone(),
            git_ref: None,
        })
    }
}

#[tokio::test]
async fn t82a_recursive_deps_git_child() {
    let _g = ENV_LOCK.lock().await;
    let work = tempfile::TempDir::new().unwrap();
    let child_bare = build_git_fixture(work.path(), false);
    let child_url = format!("file://{}", child_bare.display());

    let root_dir = tempfile::TempDir::new().unwrap();
    let root_pack = root_dir.path().join("root_pack");
    std::fs::create_dir_all(&root_pack).unwrap();
    std::fs::write(
        root_pack.join("pack.yaml"),
        r#"name: root
version: 1.0.0
description: root with git child
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
        dep_resolver: Some(Arc::new(GitResolver { url: child_url })),
        event_bus: None,
        registry_client: None,
        fetch_timeout: Some(Duration::from_secs(30)),
    };

    installer
        .install(root_pack.to_str().unwrap())
        .await
        .expect("root install w/ git child should succeed");
    assert!(registry.has("root", "1.0.0"));
    assert!(registry.has("foo", "1.0.0"));
}

// Suppress unused-import warning on unused parse_source/PathBuf in this binary
// (some imports are conditional or for future expansion).
#[allow(dead_code)]
fn _unused_imports_marker() {
    let _ = parse_source("x");
    let _ = PathBuf::from(".");
}

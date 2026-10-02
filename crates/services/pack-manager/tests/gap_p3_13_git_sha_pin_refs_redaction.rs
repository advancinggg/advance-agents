//! GAP-13 (P3) — git source: commit-SHA pin, slash refs, credential redaction.
//!

use std::path::Path;
use std::sync::Arc;

use advance_pack_manager::{
    parse_source, AutoApprove, InMemoryPackRegistry, Installer, PackRegistry, SourceRef,
};

mod common;
use common::{build_git_fixture, ENV_LOCK};

fn git(args: &[&str], cwd: &Path) -> String {
    let out = std::process::Command::new("git")
        .args(args)
        .current_dir(cwd)
        .output()
        .expect("git available");
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

#[test]
fn g13_slash_refs_are_accepted_by_the_ref_grammar() {
    match parse_source("git+https://example.com/org/repo.git@release/1.x").expect("slash ref") {
        SourceRef::GitUrl { git_ref, .. } => {
            assert_eq!(git_ref.as_deref(), Some("release/1.x"))
        }
        other => panic!("expected GitUrl, got {other:?}"),
    }
    for bad in [
        "git+https://example.com/r@feature/..evil",
        "git+https://example.com/r@-leading-dash",
        "git+https://example.com/r@refs/heads/x.lock",
        "git+https://example.com/r@a//b",
        "git+https://example.com/r@trailing/",
        "git+https://example.com/r@a@{1}",
    ] {
        assert!(parse_source(bad).is_err(), "must reject {bad}");
    }
}

#[tokio::test]
async fn g13_commit_sha_pin_installs_exactly_that_commit() {
    let _g = ENV_LOCK.lock().await;
    let work = tempfile::TempDir::new().unwrap();
    let bare = build_git_fixture(work.path(), true); // v1.0 tag = first commit (1.0.0), HEAD = 2.0.0
    let sha = git(&["rev-parse", "v1.0^{commit}"], &bare);
    assert_eq!(sha.len(), 40);
    // Local bare repos need this for fetch-by-SHA (GitHub/GitLab allow it by default).
    git(&["config", "uploadpack.allowAnySHA1InWant", "true"], &bare);

    let packs = tempfile::TempDir::new().unwrap();
    let inst = Installer::new(
        packs.path(),
        Arc::new(InMemoryPackRegistry::new(packs.path().to_path_buf())),
        "0.1.0",
        Arc::new(AutoApprove),
    );
    let report = inst
        .install(&format!("git+file://{}@{sha}", bare.display()))
        .await
        .expect("SHA-pinned install");
    assert_eq!(report.version, "1.0.0", "the pinned commit, not HEAD");
    assert!(inst.registry.has("foo", "1.0.0"));
    assert!(!packs.path().join("foo@1.0.0/.git").exists());
}

#[test]
fn g13_userinfo_is_rejected_and_never_echoed() {
    let err = parse_source("git+https://user:s3cr3t-token@example.com/org/repo.git")
        .expect_err("userinfo URLs are rejected");
    let text = err.to_string();
    assert!(
        !text.contains("s3cr3t-token"),
        "credential leaked into error text: {text}"
    );
    assert!(text.contains("***"), "redaction marker expected: {text}");

    // A resolver-injected value must also present redacted.
    let injected = SourceRef::GitUrl {
        url: "https://user:s3cr3t-token@example.com/org/repo.git".to_string(),
        git_ref: None,
    };
    let form = injected.source_form();
    assert!(!form.contains("s3cr3t-token"), "source_form leaked: {form}");
    assert!(injected.validate().is_err());
}

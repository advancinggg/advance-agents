//! Slice D AC-05 integration tests for tarball source-type install path.
//! T75 (end-to-end), T76 (`..` traversal), T77 (symlink), T77b (hardlink),
//! T78 (absolute path), T79 (size cap), T79b (entry count cap).

use std::sync::Arc;

use advance_pack_manager::{
    AutoApprove, InMemoryPackRegistry, Installer, PackError, PackRegistry, RecordingTraceSink,
};

mod common;
use common::{build_tarball_fixture, FixtureContent};

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
        fetch_timeout: None,
    }
}

#[tokio::test]
async fn t75_tarball_end_to_end_install() {
    let fixture_dir = tempfile::TempDir::new().unwrap();
    let tarball = build_tarball_fixture(fixture_dir.path(), FixtureContent::ValidPack);
    let packs_dir = tempfile::TempDir::new().unwrap();
    let installer = make_installer(packs_dir.path());

    let report = installer
        .install(tarball.to_str().unwrap())
        .await
        .expect("tarball install should succeed");
    assert_eq!(report.name, "foo");
    assert_eq!(report.version, "1.0.0");
    assert!(installer.registry.has("foo", "1.0.0"));
}

#[tokio::test]
async fn t76_tarball_traversal_entry_rejected() {
    let fixture_dir = tempfile::TempDir::new().unwrap();
    let tarball = build_tarball_fixture(fixture_dir.path(), FixtureContent::TraversalEntry);
    let packs_dir = tempfile::TempDir::new().unwrap();
    let installer = make_installer(packs_dir.path());

    let res = installer.install(tarball.to_str().unwrap()).await;
    match res {
        Err(PackError::TarballExtractFailed { reason, .. }) => {
            assert!(
                reason.contains("parent-directory") || reason.contains("traversal"),
                "expected traversal-rejection diagnostic, got: {reason}"
            );
        }
        other => panic!("expected TarballExtractFailed(traversal), got {other:?}"),
    }
}

#[cfg(unix)]
#[tokio::test]
async fn t77_tarball_symlink_entry_rejected() {
    let fixture_dir = tempfile::TempDir::new().unwrap();
    let tarball = build_tarball_fixture(fixture_dir.path(), FixtureContent::SymlinkEntry);
    let packs_dir = tempfile::TempDir::new().unwrap();
    let installer = make_installer(packs_dir.path());

    let res = installer.install(tarball.to_str().unwrap()).await;
    match res {
        Err(PackError::TarballExtractFailed { reason, .. }) => {
            assert!(
                reason.contains("symlink"),
                "expected symlink-rejection diagnostic, got: {reason}"
            );
        }
        other => panic!("expected TarballExtractFailed(symlink), got {other:?}"),
    }
}

#[cfg(unix)]
#[tokio::test]
async fn t77b_tarball_hardlink_entry_rejected() {
    let fixture_dir = tempfile::TempDir::new().unwrap();
    let tarball = build_tarball_fixture(fixture_dir.path(), FixtureContent::HardlinkEntry);
    let packs_dir = tempfile::TempDir::new().unwrap();
    let installer = make_installer(packs_dir.path());

    let res = installer.install(tarball.to_str().unwrap()).await;
    match res {
        Err(PackError::TarballExtractFailed { reason, .. }) => {
            assert!(
                reason.contains("hardlink") || reason.contains("Link"),
                "expected hardlink-rejection diagnostic, got: {reason}"
            );
        }
        other => panic!("expected TarballExtractFailed(hardlink), got {other:?}"),
    }
}

#[tokio::test]
async fn t78_tarball_absolute_path_entry_rejected() {
    let fixture_dir = tempfile::TempDir::new().unwrap();
    let tarball = build_tarball_fixture(fixture_dir.path(), FixtureContent::AbsolutePathEntry);
    let packs_dir = tempfile::TempDir::new().unwrap();
    let installer = make_installer(packs_dir.path());

    let res = installer.install(tarball.to_str().unwrap()).await;
    match res {
        Err(PackError::TarballExtractFailed { reason, .. }) => {
            assert!(
                reason.contains("absolute") || reason.contains("traversal"),
                "expected absolute-path-rejection diagnostic, got: {reason}"
            );
        }
        other => panic!("expected TarballExtractFailed(absolute), got {other:?}"),
    }
}

#[tokio::test]
async fn t79_tarball_size_cap_exceeded() {
    let fixture_dir = tempfile::TempDir::new().unwrap();
    let tarball = build_tarball_fixture(fixture_dir.path(), FixtureContent::OversizedPayload);
    let packs_dir = tempfile::TempDir::new().unwrap();
    let installer = make_installer(packs_dir.path());

    let res = installer.install(tarball.to_str().unwrap()).await;
    match res {
        Err(PackError::TarballExtractFailed { reason, .. }) => {
            assert!(
                reason.contains("size cap") || reason.contains("size"),
                "expected size-cap-rejection diagnostic, got: {reason}"
            );
        }
        other => panic!("expected TarballExtractFailed(size cap), got {other:?}"),
    }
}

#[tokio::test]
async fn t79b_tarball_entry_count_cap_exceeded() {
    let fixture_dir = tempfile::TempDir::new().unwrap();
    let tarball = build_tarball_fixture(fixture_dir.path(), FixtureContent::TooManyEntries);
    let packs_dir = tempfile::TempDir::new().unwrap();
    let installer = make_installer(packs_dir.path());

    let res = installer.install(tarball.to_str().unwrap()).await;
    match res {
        Err(PackError::TarballExtractFailed { reason, .. }) => {
            assert!(
                reason.contains("entry count"),
                "expected entry-count-cap diagnostic, got: {reason}"
            );
        }
        other => panic!("expected TarballExtractFailed(entry count), got {other:?}"),
    }
}

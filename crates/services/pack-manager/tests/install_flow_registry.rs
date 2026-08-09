//! Slice D AC-05 integration tests for the registry source-type install path.
//! T80 (end-to-end via MockRegistryClient), T80b (RegistryFetchFailed surfaces),
//! T81 (no-client InvalidManifest).

use std::sync::Arc;
use std::time::Duration;

use advance_pack_manager::{
    AutoApprove, InMemoryPackRegistry, InstallStep, Installer, MockRegistryClient, PackError,
    PackRegistry, RecordingTraceSink,
};

mod common;
use common::{build_tarball_fixture, FixtureContent};

#[tokio::test]
async fn t80_registry_source_end_to_end_via_mock_registry_client() {
    let blob_dir = tempfile::TempDir::new().unwrap();
    let fixture = build_tarball_fixture(blob_dir.path(), FixtureContent::ValidPack);
    let mock = Arc::new(MockRegistryClient::new());
    mock.insert_fixture("foo", "1.0.0", fixture);
    let packs_dir = tempfile::TempDir::new().unwrap();
    let registry = Arc::new(InMemoryPackRegistry::new(packs_dir.path().to_path_buf()));
    let trace = Arc::new(RecordingTraceSink::new());

    let installer = Installer {
        packs_dir: packs_dir.path().to_path_buf(),
        registry: registry.clone(),
        current_runtime_version: "0.1.0".to_string(),
        approval: Arc::new(AutoApprove),
        trace_sink: trace.clone(),
        dep_resolver: None,
        event_bus: None,
        registry_client: Some(mock.clone()),
        fetch_timeout: Some(Duration::from_secs(10)),
    };

    let report = installer.install("registry:foo@1.0.0").await.unwrap();
    assert_eq!(report.name, "foo");
    assert_eq!(report.version, "1.0.0");
    assert!(registry.has("foo", "1.0.0"));
    // 8-step trace order verification
    let steps = trace.steps();
    assert_eq!(
        steps,
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
}

#[tokio::test]
async fn t80b_registry_fetch_failed_timeout() {
    let blob_dir = tempfile::TempDir::new().unwrap();
    let fixture = build_tarball_fixture(blob_dir.path(), FixtureContent::ValidPack);
    let mock = Arc::new(MockRegistryClient::new());
    mock.insert_fixture("foo", "1.0.0", fixture);
    mock.set_sleep(Duration::from_secs(5));

    let packs_dir = tempfile::TempDir::new().unwrap();
    let registry = Arc::new(InMemoryPackRegistry::new(packs_dir.path().to_path_buf()));
    let installer = Installer {
        packs_dir: packs_dir.path().to_path_buf(),
        registry: registry.clone(),
        current_runtime_version: "0.1.0".to_string(),
        approval: Arc::new(AutoApprove),
        trace_sink: Arc::new(RecordingTraceSink::new()),
        dep_resolver: None,
        event_bus: None,
        registry_client: Some(mock.clone()),
        fetch_timeout: Some(Duration::from_secs(1)),
    };

    let res = installer.install("registry:foo@1.0.0").await;
    match res {
        Err(PackError::RegistryFetchFailed { reason, .. }) => {
            assert!(
                reason.contains("timeout"),
                "expected timeout reason, got: {reason}"
            );
        }
        other => panic!("expected RegistryFetchFailed(timeout), got {other:?}"),
    }
}

#[tokio::test]
async fn t80b_registry_fetch_failed_client_error_propagates() {
    let mock = Arc::new(MockRegistryClient::new());
    mock.set_err_fn(|name, version| PackError::RegistryFetchFailed {
        name: name.to_string(),
        version: version.to_string(),
        reason: "client error: simulated network unreachable".into(),
    });

    let packs_dir = tempfile::TempDir::new().unwrap();
    let registry = Arc::new(InMemoryPackRegistry::new(packs_dir.path().to_path_buf()));
    let installer = Installer {
        packs_dir: packs_dir.path().to_path_buf(),
        registry: registry.clone(),
        current_runtime_version: "0.1.0".to_string(),
        approval: Arc::new(AutoApprove),
        trace_sink: Arc::new(RecordingTraceSink::new()),
        dep_resolver: None,
        event_bus: None,
        registry_client: Some(mock.clone()),
        fetch_timeout: Some(Duration::from_secs(10)),
    };

    let res = installer.install("registry:bar@1.0.0").await;
    match res {
        Err(PackError::RegistryFetchFailed { reason, .. }) => {
            assert!(
                reason.contains("client error"),
                "expected client-error reason, got: {reason}"
            );
        }
        other => panic!("expected RegistryFetchFailed(client error), got {other:?}"),
    }
}

#[tokio::test]
async fn t80c_registry_identity_mismatch_rejected() {
    // AUDIT round-1 fix Codex Diff W1 regression: ensure manifest.name +
    // manifest.version are bound to the requested registry:<name>@<version>
    // selector. Mock client returns a fixture whose pack.yaml says
    // `name: foo` but we request `name: bar` → InvalidManifest.
    let blob_dir = tempfile::TempDir::new().unwrap();
    // Fixture has name=foo per common::build_tarball_fixture's pack.yaml.
    let fixture = build_tarball_fixture(blob_dir.path(), FixtureContent::ValidPack);
    let mock = Arc::new(MockRegistryClient::new());
    // Register fixture under (bar, 9.9.9) — request matches selector but the
    // fixture's pack.yaml manifest says foo@1.0.0.
    mock.insert_fixture("bar", "9.9.9", fixture);

    let packs_dir = tempfile::TempDir::new().unwrap();
    let registry = Arc::new(InMemoryPackRegistry::new(packs_dir.path().to_path_buf()));
    let installer = Installer {
        packs_dir: packs_dir.path().to_path_buf(),
        registry: registry.clone(),
        current_runtime_version: "0.1.0".to_string(),
        approval: Arc::new(AutoApprove),
        trace_sink: Arc::new(RecordingTraceSink::new()),
        dep_resolver: None,
        event_bus: None,
        registry_client: Some(mock.clone()),
        fetch_timeout: Some(Duration::from_secs(10)),
    };

    let res = installer.install("registry:bar@9.9.9").await;
    match res {
        Err(PackError::InvalidManifest(msg)) => {
            assert!(
                msg.contains("registry identity mismatch"),
                "expected registry-identity-mismatch diagnostic, got: {msg}"
            );
        }
        other => panic!("expected InvalidManifest(registry identity mismatch), got {other:?}"),
    }
}

#[tokio::test]
async fn t80d_registry_path_confinement_rejected() {
    // AUDIT round-1 fix Codex Diff W2 regression: ensure the path returned by
    // RegistryClient::fetch_tarball is confined under blob_dir. A buggy/hostile
    // client that returns an arbitrary path (e.g. one outside blob_dir, even
    // if valid pointing at a real tarball) must be rejected before untar.

    // Strategy: build a fixture tarball at an OUTSIDE-blob_dir location, then
    // use a custom mock client that returns that outside path.
    struct OutOfTreeClient {
        out_of_tree_path: std::path::PathBuf,
    }
    #[async_trait::async_trait]
    impl advance_pack_manager::RegistryClient for OutOfTreeClient {
        async fn fetch_tarball(
            &self,
            _name: &str,
            _version: &str,
            _dest_dir: &std::path::Path,
        ) -> Result<std::path::PathBuf, PackError> {
            // Intentionally return a path OUTSIDE the dest_dir.
            Ok(self.out_of_tree_path.clone())
        }
    }

    let outside_dir = tempfile::TempDir::new().unwrap();
    let outside_tarball = build_tarball_fixture(outside_dir.path(), FixtureContent::ValidPack);
    let client = Arc::new(OutOfTreeClient {
        out_of_tree_path: outside_tarball,
    });

    let packs_dir = tempfile::TempDir::new().unwrap();
    let registry = Arc::new(InMemoryPackRegistry::new(packs_dir.path().to_path_buf()));
    let installer = Installer {
        packs_dir: packs_dir.path().to_path_buf(),
        registry: registry.clone(),
        current_runtime_version: "0.1.0".to_string(),
        approval: Arc::new(AutoApprove),
        trace_sink: Arc::new(RecordingTraceSink::new()),
        dep_resolver: None,
        event_bus: None,
        registry_client: Some(client),
        fetch_timeout: Some(Duration::from_secs(10)),
    };

    let res = installer.install("registry:foo@1.0.0").await;
    match res {
        Err(PackError::RegistryFetchFailed { reason, .. }) => {
            assert!(
                reason.contains("outside blob_dir"),
                "expected outside-blob_dir diagnostic, got: {reason}"
            );
        }
        other => panic!("expected RegistryFetchFailed(outside blob_dir), got {other:?}"),
    }
}

#[cfg(unix)]
#[tokio::test]
async fn t80e_registry_returned_symlink_rejected() {
    // AUDIT round-1 fix shared with direct-tarball path: ensure
    // fetch_tarball_into_existing_tmp's symlink_metadata + is_file probe
    // catches a RegistryClient that returns a symlink path (even one INSIDE
    // blob_dir).
    struct SymlinkReturnClient;
    #[async_trait::async_trait]
    impl advance_pack_manager::RegistryClient for SymlinkReturnClient {
        async fn fetch_tarball(
            &self,
            _name: &str,
            _version: &str,
            dest_dir: &std::path::Path,
        ) -> Result<std::path::PathBuf, PackError> {
            // Create a real tarball OUTSIDE dest_dir, then symlink INSIDE dest_dir
            // pointing to it.
            std::fs::create_dir_all(dest_dir).unwrap();
            let real_tarball_holder = tempfile::TempDir::new().unwrap();
            let real_tarball =
                build_tarball_fixture(real_tarball_holder.path(), FixtureContent::ValidPack);
            // Copy the real tarball INTO dest_dir first to satisfy path confinement.
            let real_inside = dest_dir.join("real.tar.gz");
            std::fs::copy(&real_tarball, &real_inside).unwrap();
            // Create symlink INSIDE dest_dir pointing to real_inside.
            let symlink_path = dest_dir.join("symlinked.tar.gz");
            std::os::unix::fs::symlink(&real_inside, &symlink_path).unwrap();
            // Leak the holder so the symlink target survives.
            std::mem::forget(real_tarball_holder);
            Ok(symlink_path)
        }
    }

    let client = Arc::new(SymlinkReturnClient);
    let packs_dir = tempfile::TempDir::new().unwrap();
    let registry = Arc::new(InMemoryPackRegistry::new(packs_dir.path().to_path_buf()));
    let installer = Installer {
        packs_dir: packs_dir.path().to_path_buf(),
        registry: registry.clone(),
        current_runtime_version: "0.1.0".to_string(),
        approval: Arc::new(AutoApprove),
        trace_sink: Arc::new(RecordingTraceSink::new()),
        dep_resolver: None,
        event_bus: None,
        registry_client: Some(client),
        fetch_timeout: Some(Duration::from_secs(10)),
    };

    let res = installer.install("registry:foo@1.0.0").await;
    // The symlink path's canonicalize resolves to the real target, which is
    // INSIDE blob_dir (path confinement passes), then the shared
    // symlink_metadata gate rejects it as TarballExtractFailed.
    match res {
        Err(PackError::TarballExtractFailed { reason, .. }) => {
            assert!(
                reason.contains("symlink"),
                "expected tarball-symlink diagnostic, got: {reason}"
            );
        }
        // Acceptable alternative: canonicalize() in path-confinement check
        // resolves the symlink, and if that path is somewhere unexpected it
        // returns RegistryFetchFailed.
        Err(PackError::RegistryFetchFailed { reason, .. }) => {
            assert!(
                reason.contains("outside blob_dir"),
                "expected outside-blob_dir or symlink rejection, got: {reason}"
            );
        }
        other => panic!("expected symlink-rejection or path-confinement, got {other:?}"),
    }
}

#[tokio::test]
async fn t81_registry_source_without_client_configured_rejected() {
    let packs_dir = tempfile::TempDir::new().unwrap();
    let registry = Arc::new(InMemoryPackRegistry::new(packs_dir.path().to_path_buf()));
    let installer = Installer {
        packs_dir: packs_dir.path().to_path_buf(),
        registry: registry.clone(),
        current_runtime_version: "0.1.0".to_string(),
        approval: Arc::new(AutoApprove),
        trace_sink: Arc::new(RecordingTraceSink::new()),
        dep_resolver: None,
        event_bus: None,
        registry_client: None,
        fetch_timeout: None,
    };

    let res = installer.install("registry:foo@1.0.0").await;
    match res {
        Err(PackError::InvalidManifest(msg)) => {
            assert!(
                msg.contains("no RegistryClient configured"),
                "expected no-client diagnostic, got: {msg}"
            );
        }
        other => panic!("expected InvalidManifest(no RegistryClient), got {other:?}"),
    }
}

//! Slice D AC-05 trace-event order verification per source type.
//! T83 (git+file://), T84 (tarball), T85 (registry). Each test asserts the
//! exact 8-step trace sequence.

use std::sync::Arc;
use std::time::Duration;

use advance_pack_manager::{
    AutoApprove, InMemoryPackRegistry, InstallStep, Installer, MockRegistryClient,
    RecordingTraceSink,
};

mod common;
use common::{build_git_fixture, build_tarball_fixture, FixtureContent, ENV_LOCK};

const EXPECTED_8_STEPS: &[InstallStep] = &[
    InstallStep::Step1ParseSource,
    InstallStep::Step2DownloadToTemp,
    InstallStep::Step3VerifyChecksums,
    InstallStep::Step4AdminApproval,
    InstallStep::Step5RecursiveDeps,
    InstallStep::Step6CopyToInstallDir,
    InstallStep::Step7UpdateMetaIndex,
    InstallStep::Step8RegistryRescan,
];

#[tokio::test]
async fn t83_8step_trace_for_git_file_source() {
    let _g = ENV_LOCK.lock().await;
    let work = tempfile::TempDir::new().unwrap();
    let bare = build_git_fixture(work.path(), false);
    let source = format!("git+file://{}", bare.display());

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
        registry_client: None,
        fetch_timeout: Some(Duration::from_secs(30)),
    };

    installer.install(&source).await.expect("git install");
    assert_eq!(trace.steps(), EXPECTED_8_STEPS);
}

#[tokio::test]
async fn t84_8step_trace_for_tarball_source() {
    let fixture_dir = tempfile::TempDir::new().unwrap();
    let tarball = build_tarball_fixture(fixture_dir.path(), FixtureContent::ValidPack);
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
        registry_client: None,
        fetch_timeout: None,
    };

    installer.install(tarball.to_str().unwrap()).await.unwrap();
    assert_eq!(trace.steps(), EXPECTED_8_STEPS);
}

#[tokio::test]
async fn t85_8step_trace_for_registry_source() {
    let fixture_dir = tempfile::TempDir::new().unwrap();
    let tarball = build_tarball_fixture(fixture_dir.path(), FixtureContent::ValidPack);
    let mock = Arc::new(MockRegistryClient::new());
    mock.insert_fixture("foo", "1.0.0", tarball);
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
        registry_client: Some(mock),
        fetch_timeout: Some(Duration::from_secs(10)),
    };

    installer.install("registry:foo@1.0.0").await.unwrap();
    assert_eq!(trace.steps(), EXPECTED_8_STEPS);
}

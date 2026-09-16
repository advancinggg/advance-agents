#![cfg(feature = "gap-p1")]
//! GAP-16 (P1) — `required-capabilities` validated against a capability catalog.
//! Implemented as an `ApprovalStrategy`
//! decorator so `Installer` gains no field.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use advance_pack_manager::{
    AutoApprove, CatalogCheckedApproval, InMemoryPackRegistry, InstallStep, Installer, PackError,
    RecordingTraceSink, StaticCapabilityCatalog,
};

fn write_pack(root: &Path, required: &[&str]) -> PathBuf {
    let dir = root.join("foo-src");
    std::fs::create_dir_all(dir.join("behavior-binaries")).unwrap();
    std::fs::write(dir.join("behavior-binaries/dummy.wasm"), b"\0asm\x01\0\0\0").unwrap();
    let mut yaml = String::from(
        "name: foo\nversion: 1.0.0\nruntime-version: \">=0.1.0\"\nprovides:\n  behavior-binaries:\n    - dummy\nchecksums:\n  algo: sha256\n  files: {}\n",
    );
    if !required.is_empty() {
        yaml.push_str("required-capabilities:\n");
        for r in required {
            yaml.push_str(&format!("  - {r}\n"));
        }
    }
    std::fs::write(dir.join("pack.yaml"), yaml).unwrap();
    dir
}

fn installer(packs: &Path, catalog: &[&str], trace: Arc<RecordingTraceSink>) -> Installer {
    let approval = CatalogCheckedApproval::new(
        Arc::new(AutoApprove),
        Arc::new(StaticCapabilityCatalog::new(
            catalog.iter().map(|s| s.to_string()),
        )),
    );
    Installer::new(
        packs,
        Arc::new(InMemoryPackRegistry::new(packs.to_path_buf())),
        "0.1.0",
        Arc::new(approval),
    )
    .with_trace_sink(trace)
}

#[tokio::test]
async fn g16_known_required_capabilities_pass_through_to_inner_strategy() {
    let work = tempfile::TempDir::new().unwrap();
    let packs = tempfile::TempDir::new().unwrap();
    let src = write_pack(work.path(), &["fs", "llm"]);
    let inst = installer(
        packs.path(),
        &["fs", "llm", "tools"],
        Arc::new(RecordingTraceSink::new()),
    );
    inst.install(src.to_str().unwrap())
        .await
        .expect("all required capabilities are known → inner AutoApprove decides");
}

#[tokio::test]
async fn g16_unknown_required_capability_is_rejected_at_approval_step() {
    let work = tempfile::TempDir::new().unwrap();
    let packs = tempfile::TempDir::new().unwrap();
    let src = write_pack(work.path(), &["fs", "teleport"]);
    let trace = Arc::new(RecordingTraceSink::new());
    let inst = installer(packs.path(), &["fs", "llm"], trace.clone());
    let err = inst
        .install(src.to_str().unwrap())
        .await
        .expect_err("unknown capability must fail install");
    match err {
        PackError::UnknownRequiredCapability { pack, unknown } => {
            assert_eq!(pack, "foo");
            assert_eq!(unknown, vec!["teleport".to_string()]);
        }
        other => panic!("expected UnknownRequiredCapability, got {other:?}"),
    }
    let steps = trace.steps();
    assert!(
        steps.contains(&InstallStep::Step4AdminApproval),
        "rejection happens AT step 4"
    );
    assert!(
        !steps.contains(&InstallStep::Step5RecursiveDeps),
        "and nothing after it runs"
    );
    assert!(!packs.path().join("foo@1.0.0").exists());
}

#[tokio::test]
async fn g16_empty_required_capabilities_never_consults_catalog() {
    let work = tempfile::TempDir::new().unwrap();
    let packs = tempfile::TempDir::new().unwrap();
    let src = write_pack(work.path(), &[]);
    // Empty catalog: would reject ANY declared capability — but nothing is declared.
    let inst = installer(packs.path(), &[], Arc::new(RecordingTraceSink::new()));
    inst.install(src.to_str().unwrap())
        .await
        .expect("no requirements → install");
}

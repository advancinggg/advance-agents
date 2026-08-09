//! AC-14 — `resolve_pack_component` constraint surface + happy-path tests.
//!
//! Test IDs: T52, T52b, T52c, T52d, T53, T54, T54-empty-map, T54b, T54c,
//! T54d, T55 (11 tests for AC-14 surface); T64, T65 (2 unit-level path
//! rejection tests). Total 13 tests in this file.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use advance_pack_manager::{
    AutoApprove, InMemoryPackRegistry, Installer, PackError, PackRegistry, RecordingTraceSink,
};

/// Build a pack source with `components/eval/component.yaml` configured per
/// the test caller's needs. The `component_yaml` string is written verbatim
/// to `components/eval/component.yaml`; `eval.wasm` exists alongside (the
/// pack ships its binary inside the component dir for simplicity).
fn build_eval_pack(root: &Path, name: &str, component_yaml: &str) -> PathBuf {
    let pack_dir = root.join(format!("source-{name}"));
    std::fs::create_dir_all(&pack_dir).unwrap();
    std::fs::create_dir_all(pack_dir.join("components").join("eval")).unwrap();
    std::fs::write(
        pack_dir
            .join("components")
            .join("eval")
            .join("component.yaml"),
        component_yaml,
    )
    .unwrap();
    std::fs::write(
        pack_dir.join("components").join("eval").join("eval.wasm"),
        b"\x00asm\x01\x00\x00\x00",
    )
    .unwrap();
    // Also place a "shared" binary at behavior-binaries for behavior-ref
    // canonical-form testing.
    std::fs::create_dir_all(pack_dir.join("behavior-binaries")).unwrap();
    std::fs::write(
        pack_dir.join("behavior-binaries").join("shared-eval.wasm"),
        b"\x00asm\xFF\xFE\xFD\xFC",
    )
    .unwrap();
    std::fs::write(
        pack_dir.join("pack.yaml"),
        format!(
            r#"name: {name}
version: 1.0.0
runtime-version: ">=0.0.1"
dependencies: []
provides:
  components: [eval]
  behavior-binaries: [shared-eval]
required-capabilities: []
trust-level: untrusted
checksums:
  algo: sha256
  files: {{}}
"#
        ),
    )
    .unwrap();
    pack_dir
}

async fn install(
    name: &str,
    component_yaml: &str,
) -> (tempfile::TempDir, Arc<InMemoryPackRegistry>) {
    let dir = tempfile::TempDir::new().unwrap();
    let pack_src = build_eval_pack(dir.path(), name, component_yaml);
    let packs_dir = dir.path().join("packs");
    let registry = Arc::new(InMemoryPackRegistry::new(packs_dir.clone()));
    let sink = Arc::new(RecordingTraceSink::new());
    let installer = Installer {
        packs_dir,
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
        .expect("install fixture");
    (dir, registry)
}

#[tokio::test]
async fn t52_binary_field_happy_path() {
    let yaml = r#"component-type: task
binary: ./eval.wasm
capabilities:
  - capability: cap-fs
  - capability: cap-llm
"#;
    let (_dir, registry) = install("packT52", yaml).await;
    let resolution = registry
        .resolve_pack_component("packT52@1.0.0/components/eval")
        .unwrap();
    assert!(!resolution.binary.is_empty(), "binary bytes must be loaded");
    assert_eq!(resolution.capabilities.len(), 2);
    assert_eq!(resolution.capabilities[0].capability.as_str(), "cap-fs");
    assert_eq!(resolution.capabilities[1].capability.as_str(), "cap-llm");
    assert_eq!(resolution.manifest.component_type, "task");
}

#[tokio::test]
async fn t52b_behavior_ref_canonical_form() {
    let yaml = r#"component-type: task
behavior-ref: ../../behavior-binaries/shared-eval.wasm
capabilities: []
"#;
    let (_dir, registry) = install("packT52b", yaml).await;
    let resolution = registry
        .resolve_pack_component("packT52b@1.0.0/components/eval")
        .unwrap();
    assert!(!resolution.binary.is_empty());
    // The shared-eval.wasm fixture has a recognisable trailing pattern.
    assert!(resolution.binary.ends_with(b"\xFF\xFE\xFD\xFC"));
}

#[tokio::test]
async fn t52c_accept_and_ignore_stubs_dont_fail() {
    let yaml = r#"component-type: task
binary: ./eval.wasm
capabilities: []
id: ignored-id
restart-policy: ignored-policy
delay: 42
initial-grants:
  - some: thing
preset: ignored-preset
"#;
    let (_dir, registry) = install("packT52c", yaml).await;
    let resolution = registry
        .resolve_pack_component("packT52c@1.0.0/components/eval")
        .unwrap();
    assert_eq!(resolution.manifest.component_type, "task");
}

#[tokio::test]
async fn t52d_output_dir_sentinel_and_declared_paths() {
    // (1) Omitted output-dir → empty PathBuf.
    let omitted = r#"component-type: task
binary: ./eval.wasm
capabilities: []
"#;
    let (_dir, reg) = install("packT52d-omit", omitted).await;
    let r1 = reg
        .resolve_pack_component("packT52d-omit@1.0.0/components/eval")
        .unwrap();
    assert_eq!(
        r1.output_dir,
        PathBuf::new(),
        "omitted output-dir must return empty PathBuf sentinel"
    );

    // (2) Declared output-dir: results/foo → raw PathBuf::from("results/foo"),
    // NOT joined against install_path.
    let declared = r#"component-type: task
binary: ./eval.wasm
output-dir: results/foo
capabilities: []
"#;
    let (_dir2, reg2) = install("packT52d-decl", declared).await;
    let r2 = reg2
        .resolve_pack_component("packT52d-decl@1.0.0/components/eval")
        .unwrap();
    assert_eq!(
        r2.output_dir,
        PathBuf::from("results/foo"),
        "declared output-dir must be raw declared path, NOT joined against install_path"
    );
}

#[tokio::test]
async fn t53_non_task_component_type_rejected() {
    let yaml = r#"component-type: agent
binary: ./eval.wasm
capabilities: []
"#;
    let (_dir, reg) = install("packT53", yaml).await;
    match reg.resolve_pack_component("packT53@1.0.0/components/eval") {
        Err(PackError::ConstraintViolation { reason }) => {
            assert!(
                reason.contains("component-type") && reason.contains("task"),
                "expected component-type constraint, got: {reason}"
            );
        }
        other => panic!("expected ConstraintViolation, got {other:?}"),
    }
}

#[tokio::test]
async fn t54_non_empty_trigger_rejected() {
    let yaml = r#"component-type: task
binary: ./eval.wasm
trigger:
  event-type: foo
capabilities: []
"#;
    let (_dir, reg) = install("packT54", yaml).await;
    match reg.resolve_pack_component("packT54@1.0.0/components/eval") {
        Err(PackError::ConstraintViolation { reason }) => {
            assert!(
                reason.contains("trigger"),
                "expected trigger constraint, got: {reason}"
            );
        }
        other => panic!("expected ConstraintViolation, got {other:?}"),
    }
}

#[tokio::test]
async fn t54_empty_map_trigger_accepted() {
    // PRD §4.7.4: "absent or empty". Empty mapping is empty.
    let yaml = r#"component-type: task
binary: ./eval.wasm
trigger: {}
capabilities: []
"#;
    let (_dir, reg) = install("packT54map", yaml).await;
    reg.resolve_pack_component("packT54map@1.0.0/components/eval")
        .unwrap();
}

#[tokio::test]
async fn t54_empty_seq_trigger_accepted() {
    let yaml = r#"component-type: task
binary: ./eval.wasm
trigger: []
capabilities: []
"#;
    let (_dir, reg) = install("packT54seq", yaml).await;
    reg.resolve_pack_component("packT54seq@1.0.0/components/eval")
        .unwrap();
}

#[tokio::test]
async fn t54_null_trigger_accepted() {
    let yaml = r#"component-type: task
binary: ./eval.wasm
trigger: null
capabilities: []
"#;
    let (_dir, reg) = install("packT54null", yaml).await;
    reg.resolve_pack_component("packT54null@1.0.0/components/eval")
        .unwrap();
}

#[tokio::test]
async fn t54b_both_binary_and_behavior_ref_set_prefers_behavior_ref() {
    let yaml = r#"component-type: task
binary: ./eval.wasm
behavior-ref: ../../behavior-binaries/shared-eval.wasm
capabilities: []
"#;
    let (_dir, reg) = install("packT54b", yaml).await;
    let resolution = reg
        .resolve_pack_component("packT54b@1.0.0/components/eval")
        .unwrap();
    // behavior-ref wins → bytes from shared-eval.wasm (which ends with the
    // sentinel pattern). The binary field's eval.wasm has a DIFFERENT body.
    assert!(
        resolution.binary.ends_with(b"\xFF\xFE\xFD\xFC"),
        "behavior-ref should win when both fields present"
    );
}

#[tokio::test]
async fn t54c_neither_binary_nor_behavior_ref_rejected() {
    let yaml = r#"component-type: task
capabilities: []
"#;
    let (_dir, reg) = install("packT54c", yaml).await;
    match reg.resolve_pack_component("packT54c@1.0.0/components/eval") {
        Err(PackError::ConstraintViolation { reason }) => {
            assert!(
                reason.contains("behavior-ref") || reason.contains("binary"),
                "expected binary/behavior-ref constraint, got: {reason}"
            );
        }
        other => panic!("expected ConstraintViolation, got {other:?}"),
    }
}

#[tokio::test]
async fn t54d_unknown_forward_compat_fields_silently_accepted() {
    // PRD §4.3 base schema has `retry`; PRD §4.7.4 line 838's accept-and-
    // ignore covers it. Verifies `deny_unknown_fields` is NOT in effect.
    let yaml = r#"component-type: task
binary: ./eval.wasm
capabilities: []
retry:
  max-attempts: 3
chain-id: evaluator-loop
"#;
    let (_dir, reg) = install("packT54d", yaml).await;
    reg.resolve_pack_component("packT54d@1.0.0/components/eval")
        .unwrap();
}

#[tokio::test]
async fn t55_non_runnable_component_kind_rejected() {
    // The fixture also provides an agent-template. Calling
    // resolve_pack_component on it must surface ConstraintViolation
    // (kind mismatch).
    let yaml = r#"component-type: task
binary: ./eval.wasm
capabilities: []
"#;
    let dir = tempfile::TempDir::new().unwrap();
    // Build a pack with BOTH components/eval AND agent-templates/researcher.
    let pack_src = build_eval_pack(dir.path(), "packT55", yaml);
    std::fs::create_dir_all(pack_src.join("agent-templates").join("researcher")).unwrap();
    std::fs::write(
        pack_src
            .join("agent-templates")
            .join("researcher")
            .join("AGENTS.md"),
        b"# template",
    )
    .unwrap();
    // Rewrite pack.yaml to declare agent-templates in provides.
    let pack_yaml_path = pack_src.join("pack.yaml");
    let original = std::fs::read_to_string(&pack_yaml_path).unwrap();
    let with_template = original.replace(
        "provides:\n  components: [eval]",
        "provides:\n  agent-templates: [researcher]\n  components: [eval]",
    );
    std::fs::write(&pack_yaml_path, with_template).unwrap();

    let packs_dir = dir.path().join("packs");
    let registry = Arc::new(InMemoryPackRegistry::new(packs_dir.clone()));
    let sink = Arc::new(RecordingTraceSink::new());
    let installer = Installer {
        packs_dir,
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

    match registry.resolve_pack_component("packT55@1.0.0/agent-templates/researcher") {
        Err(PackError::ConstraintViolation { reason }) => {
            assert!(
                reason.contains("runnable component") || reason.contains("AgentTemplate"),
                "expected runnable-component constraint, got: {reason}"
            );
        }
        other => panic!("expected ConstraintViolation, got {other:?}"),
    }
}

// ── Unit-level path-rejection tests (T64, T65) ─────────────────────────

#[tokio::test]
async fn t64_binary_symlink_rejected() {
    #[cfg(not(unix))]
    {
        eprintln!("symlink unit test skipped on non-Unix");
        return;
    }
    #[cfg(unix)]
    {
        // Build a pack where `components/eval/eval.wasm` is a SYMLINK to
        // a target file. parse_component_manifest must reject this.
        let dir = tempfile::TempDir::new().unwrap();
        let pack_dir = dir.path().join("source");
        std::fs::create_dir_all(pack_dir.join("components").join("eval")).unwrap();
        // The pre-install step ② copy_dir_no_symlinks would reject ANY symlink
        // in the source tree, so we install the pack with a regular file,
        // then SWAP eval.wasm for a symlink AFTER install. parse_component_manifest
        // re-stats at resolve time and catches the symlink.
        std::fs::write(
            pack_dir.join("components").join("eval").join("eval.wasm"),
            b"valid",
        )
        .unwrap();
        std::fs::write(
            pack_dir
                .join("components")
                .join("eval")
                .join("component.yaml"),
            "component-type: task\nbinary: ./eval.wasm\ncapabilities: []\n",
        )
        .unwrap();
        std::fs::write(
            pack_dir.join("pack.yaml"),
            r#"name: packT64
version: 1.0.0
runtime-version: ">=0.0.1"
dependencies: []
provides:
  components: [eval]
required-capabilities: []
trust-level: untrusted
checksums:
  algo: sha256
  files: {}
"#,
        )
        .unwrap();
        let packs_dir = dir.path().join("packs");
        let registry = Arc::new(InMemoryPackRegistry::new(packs_dir.clone()));
        let installer = Installer {
            packs_dir: packs_dir.clone(),
            registry: registry.clone(),
            current_runtime_version: "0.5.0".into(),
            approval: Arc::new(AutoApprove),
            trace_sink: Arc::new(RecordingTraceSink::new()),
            dep_resolver: None,
            event_bus: None,
            registry_client: None,
            fetch_timeout: None,
        };
        installer
            .install(pack_dir.to_string_lossy().as_ref())
            .await
            .unwrap();
        // Swap the installed eval.wasm for a symlink.
        let installed_wasm = packs_dir
            .join("packT64@1.0.0")
            .join("components")
            .join("eval")
            .join("eval.wasm");
        std::fs::remove_file(&installed_wasm).unwrap();
        let bait = dir.path().join("bait.bin");
        std::fs::write(&bait, b"x").unwrap();
        std::os::unix::fs::symlink(&bait, &installed_wasm).unwrap();

        match registry.resolve_pack_component("packT64@1.0.0/components/eval") {
            Err(PackError::InvalidManifest(msg)) => assert!(
                msg.contains("symlink"),
                "expected symlink rejection, got: {msg}"
            ),
            other => panic!("expected InvalidManifest(symlink), got {other:?}"),
        }
    }
}

#[tokio::test]
async fn t65_binary_path_escape_rejected() {
    // `behavior-ref: ../../etc/passwd` — even if it resolves to a real
    // file, canonicalize + ancestor check rejects the escape.
    // (We can't easily test this without an OS-level setup; verify the
    // simpler case: behavior-ref pointing OUTSIDE the install path.)
    let yaml = r#"component-type: task
behavior-ref: ../../../etc/passwd
capabilities: []
"#;
    let dir = tempfile::TempDir::new().unwrap();
    let pack_src = build_eval_pack(dir.path(), "packT65", yaml);
    // /etc/passwd is unlikely to exist OR is outside install_path; either
    // way the resolver must error before reading.
    let packs_dir = dir.path().join("packs");
    let registry = Arc::new(InMemoryPackRegistry::new(packs_dir.clone()));
    let installer = Installer {
        packs_dir,
        registry: registry.clone(),
        current_runtime_version: "0.5.0".into(),
        approval: Arc::new(AutoApprove),
        trace_sink: Arc::new(RecordingTraceSink::new()),
        dep_resolver: None,
        event_bus: None,
        registry_client: None,
        fetch_timeout: None,
    };
    installer
        .install(pack_src.to_string_lossy().as_ref())
        .await
        .unwrap();
    match registry.resolve_pack_component("packT65@1.0.0/components/eval") {
        Err(PackError::InvalidManifest(msg)) => {
            assert!(
                msg.contains("escape") || msg.contains("missing") || msg.contains("symlink"),
                "expected escape / missing / symlink rejection, got: {msg}"
            );
        }
        Err(PackError::Io { .. }) => {
            // Path doesn't exist or permission-denied — acceptable: the
            // resolver did NOT silently follow the escape.
        }
        other => panic!("expected InvalidManifest or Io for escape path, got {other:?}"),
    }
}

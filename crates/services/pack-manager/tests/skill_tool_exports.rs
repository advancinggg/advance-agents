//! AC-29 point 1 (m017-slice-l) — `advance pack install` validates each skill
//! bundle's optional `skills/<name>/tool.wasm` exports the `tool-exports`
//! contract (via the cap-tools validator, CONTRACT-163). Exercises the gate
//! end-to-end through the real `Installer` flow.
//!
//! Component fixtures are synthesized in-test via `wit_component::dummy_module`
//! (no committed `.wasm` classifies as the shapes we need): a `tool-exports`
//! component (describe + execute) must be ACCEPTED; a `runnable`-only component
//! must be REJECTED; a knowledge-only skill (no tool.wasm) must be ACCEPTED.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use advance_pack_manager::{
    AutoApprove, InMemoryPackRegistry, Installer, PackError, PackRegistry, RecordingTraceSink,
};
use wit_component::{embed_component_metadata, ComponentEncoder, StringEncoding};
use wit_parser::{ManglingAndAbi, Resolve};

// Canonical `advance:runtime` package so dummy_module emits exports mangled as
// the validator expects (`advance:runtime/tool-exports@0.1.0#describe`, etc.).
const WIT_TOOL_EXPORTS: &str = r#"
package advance:runtime@0.1.0;

interface tool-exports {
    record method-info { name: string }
    record tool-description { description: string, methods: list<method-info> }
    describe: func() -> tool-description;
    execute: func(method: string, params: list<u8>) -> result<list<u8>, string>;
}

world tool-world { export tool-exports; }
"#;

const WIT_RUNNABLE: &str = r#"
package advance:runtime@0.1.0;

interface runnable { run: func(); }

world runnable-world { export runnable; }
"#;

fn build_dummy_component(wit: &str, world: &str) -> Vec<u8> {
    let mut resolve = Resolve::default();
    let pkg = resolve.push_str("inline.wit", wit).expect("WIT parses");
    let world = resolve
        .select_world(&[pkg], Some(world))
        .expect("world found");
    let mut core = wit_component::dummy_module(&resolve, world, ManglingAndAbi::Standard32);
    embed_component_metadata(&mut core, &resolve, world, StringEncoding::UTF8)
        .expect("embed metadata");
    ComponentEncoder::default()
        .validate(true)
        .module(&core)
        .expect("module accepted")
        .encode()
        .expect("component encoded")
}

/// Build a pack SOURCE tree declaring `skills: [echoer]`. The skill ships a
/// `SKILL.md` and, when `tool_wasm` is `Some`, a `tool.wasm`. `checksums.files`
/// is empty (pack.yaml self-checksum is not required; the tool.wasm is the
/// in-skill executable, not a declared checksummed artifact).
fn make_skill_pack_fixture(root: &Path, tool_wasm: Option<&[u8]>) -> PathBuf {
    let pack_dir = root.join("source");
    let skill_dir = pack_dir.join("skills").join("echoer");
    std::fs::create_dir_all(&skill_dir).unwrap();
    std::fs::write(skill_dir.join("SKILL.md"), b"# echoer\n\nEcho skill.\n").unwrap();
    if let Some(bytes) = tool_wasm {
        std::fs::write(skill_dir.join("tool.wasm"), bytes).unwrap();
    }
    let pack_yaml = r#"name: skillpack
version: 1.0.0
runtime-version: ">=0.0.1"
dependencies: []
provides:
  skills: [echoer]
required-capabilities: []
trust-level: untrusted
checksums:
  algo: sha256
  files: {}
"#;
    std::fs::write(pack_dir.join("pack.yaml"), pack_yaml).unwrap();
    pack_dir
}

fn make_installer(packs_dir: PathBuf) -> (Installer, Arc<InMemoryPackRegistry>) {
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
    (installer, registry)
}

#[tokio::test]
async fn ac29_install_rejects_skill_with_non_tool_wasm() {
    let dir = tempfile::TempDir::new().unwrap();
    // A `runnable`-only component is NOT a tool — install must fail closed.
    let runnable = build_dummy_component(WIT_RUNNABLE, "runnable-world");
    let pack_src = make_skill_pack_fixture(dir.path(), Some(&runnable));
    let (installer, registry) = make_installer(dir.path().join("packs"));

    let err = installer
        .install(pack_src.to_string_lossy().as_ref())
        .await
        .expect_err("install must reject a skill whose tool.wasm lacks tool-exports");
    match err {
        PackError::InvalidManifest(msg) => assert!(
            msg.contains("tool-exports") && msg.contains("echoer"),
            "expected tool-exports rejection naming the skill, got: {msg}"
        ),
        other => panic!("expected InvalidManifest, got {other:?}"),
    }
    // Fail-closed: the pack was NOT registered.
    assert!(!registry.has("skillpack", "1.0.0"));
}

#[tokio::test]
async fn ac29_install_accepts_skill_with_tool_exports_wasm() {
    let dir = tempfile::TempDir::new().unwrap();
    let tool = build_dummy_component(WIT_TOOL_EXPORTS, "tool-world");
    let pack_src = make_skill_pack_fixture(dir.path(), Some(&tool));
    let (installer, registry) = make_installer(dir.path().join("packs"));

    installer
        .install(pack_src.to_string_lossy().as_ref())
        .await
        .expect("install should succeed for a valid tool-exports skill tool.wasm");
    assert!(registry.has("skillpack", "1.0.0"));
}

#[tokio::test]
async fn ac29_install_accepts_knowledge_only_skill() {
    let dir = tempfile::TempDir::new().unwrap();
    // No tool.wasm → knowledge-only skill; the gate is opt-in on presence.
    let pack_src = make_skill_pack_fixture(dir.path(), None);
    let (installer, registry) = make_installer(dir.path().join("packs"));

    installer
        .install(pack_src.to_string_lossy().as_ref())
        .await
        .expect("install should succeed for a knowledge-only skill");
    assert!(registry.has("skillpack", "1.0.0"));
}

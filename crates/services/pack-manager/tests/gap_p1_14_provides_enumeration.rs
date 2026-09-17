//! GAP-14 (P1) — `PackRegistry::provides(name, version)` enumeration.
//! See the internal pack gap-closure plan §2.3. The cap-lifecycle half
//! (`PackTemplateResolver::list()`) lives in crates/capabilities/cap-lifecycle/tests/.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use advance_pack_manager::{
    AutoApprove, ComponentKind, InMemoryPackRegistry, Installer, PackProvideEntry, PackRegistry,
};

const TEMPLATE_YAML: &str = "name: researcher\nversion: 1.0.0\ndescription: Research template\nbehavior:\n  type: embedded\n  binary: behavior.wasm\ndefault-model: sonnet\n";

fn write_pack(root: &Path) -> PathBuf {
    let dir = root.join("foo-src");
    std::fs::create_dir_all(dir.join("behavior-binaries")).unwrap();
    std::fs::create_dir_all(dir.join("agent-templates/researcher")).unwrap();
    std::fs::create_dir_all(dir.join("skills/web-search")).unwrap();
    std::fs::write(dir.join("behavior-binaries/dummy.wasm"), b"\0asm\x01\0\0\0").unwrap();
    std::fs::write(
        dir.join("agent-templates/researcher/template.yaml"),
        TEMPLATE_YAML,
    )
    .unwrap();
    std::fs::write(
        dir.join("agent-templates/researcher/AGENTS.md"),
        "# researcher\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("agent-templates/researcher/behavior.wasm"),
        b"\0asm\x01\0\0\0",
    )
    .unwrap();
    std::fs::write(dir.join("skills/web-search/SKILL.md"), "# web search\n").unwrap();
    std::fs::write(
        dir.join("pack.yaml"),
        "name: foo\nversion: 1.0.0\nruntime-version: \">=0.1.0\"\nprovides:\n  behavior-binaries:\n    - dummy\n  agent-templates:\n    - researcher\n  skills:\n    - web-search\nchecksums:\n  algo: sha256\n  files: {}\n",
    )
    .unwrap();
    dir
}

#[tokio::test]
async fn g14_provides_lists_every_declared_kind_after_install() {
    let work = tempfile::TempDir::new().unwrap();
    let packs = tempfile::TempDir::new().unwrap();
    let registry = Arc::new(InMemoryPackRegistry::new(packs.path().to_path_buf()));
    let inst = Installer::new(
        packs.path(),
        registry.clone(),
        "0.1.0",
        Arc::new(AutoApprove),
    );
    let src = write_pack(work.path());
    inst.install(src.to_str().unwrap()).await.expect("install");

    let provides = registry
        .provides("foo", "1.0.0")
        .expect("installed pack must enumerate its provides");
    let expect = |kind: ComponentKind, name: &str| PackProvideEntry {
        kind,
        name: name.to_string(),
    };
    assert!(
        provides.contains(&expect(ComponentKind::Binary, "dummy")),
        "{provides:?}"
    );
    assert!(
        provides.contains(&expect(ComponentKind::AgentTemplate, "researcher")),
        "{provides:?}"
    );
    assert!(
        provides.contains(&expect(ComponentKind::Skill, "web-search")),
        "{provides:?}"
    );
    assert_eq!(
        provides.len(),
        3,
        "exactly the declared entries: {provides:?}"
    );
}

#[tokio::test]
async fn g14_provides_is_none_for_unknown_pack_or_version() {
    let packs = tempfile::TempDir::new().unwrap();
    let registry = InMemoryPackRegistry::new(packs.path().to_path_buf());
    registry.rescan().await.expect("rescan of empty packs dir");
    assert!(registry.provides("nope", "1.0.0").is_none());
}

#[tokio::test]
async fn g14_provides_survives_rescan_from_disk() {
    let work = tempfile::TempDir::new().unwrap();
    let packs = tempfile::TempDir::new().unwrap();
    let inst = Installer::new(
        packs.path(),
        Arc::new(InMemoryPackRegistry::new(packs.path().to_path_buf())),
        "0.1.0",
        Arc::new(AutoApprove),
    );
    let src = write_pack(work.path());
    inst.install(src.to_str().unwrap()).await.unwrap();

    // A brand-new registry over the same packs_dir must rebuild provides from .meta.yaml +
    // pack.yaml (cold start), not from in-process state.
    let cold = InMemoryPackRegistry::new(packs.path().to_path_buf());
    cold.rescan().await.unwrap();
    let provides = cold
        .provides("foo", "1.0.0")
        .expect("cold registry enumerates provides");
    assert!(provides
        .iter()
        .any(|p| p.kind == ComponentKind::AgentTemplate && p.name == "researcher"));
}

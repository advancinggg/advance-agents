#![cfg(feature = "gap-p1")]
//! GAP-14 (P1, cap-lifecycle half) — `PackTemplateResolver::list()` enumerates installed
//! pack templates as FQ refs (was a sanctioned empty Vec because `PackRegistry` had no
//! provides enumeration).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use advance_pack_manager::{AutoApprove, InMemoryPackRegistry, Installer, PackRegistry};
use cap_lifecycle::pack_template_resolver::PackTemplateResolver;
use cap_lifecycle::templates::TemplateResolver;

const TEMPLATE_YAML: &str = "name: researcher\nversion: 1.0.0\ndescription: Research template\nbehavior:\n  type: embedded\n  binary: behavior.wasm\ndefault-model: sonnet\n";

fn write_pack(root: &Path, name: &str, templates: &[&str]) -> PathBuf {
    let dir = root.join(format!("{name}-src"));
    let mut provides = String::from("  agent-templates:\n");
    for t in templates {
        let td = dir.join("agent-templates").join(t);
        std::fs::create_dir_all(&td).unwrap();
        std::fs::write(
            td.join("template.yaml"),
            TEMPLATE_YAML.replace("researcher", t),
        )
        .unwrap();
        std::fs::write(td.join("AGENTS.md"), format!("# {t}\n")).unwrap();
        std::fs::write(td.join("behavior.wasm"), b"\0asm\x01\0\0\0").unwrap();
        provides.push_str(&format!("    - {t}\n"));
    }
    std::fs::write(
        dir.join("pack.yaml"),
        format!("name: {name}\nversion: 1.0.0\nruntime-version: \">=0.1.0\"\nprovides:\n{provides}checksums:\n  algo: sha256\n  files: {{}}\n"),
    )
    .unwrap();
    dir
}

#[tokio::test]
async fn ptl_01_list_returns_fq_refs_for_every_installed_template() {
    let tmp = tempfile::TempDir::new().unwrap();
    let packs = tmp.path().join("packs");
    let registry = Arc::new(InMemoryPackRegistry::new(packs.clone()));
    let inst = Installer::new(&packs, registry.clone(), "0.1.0", Arc::new(AutoApprove));
    inst.install(
        write_pack(tmp.path(), "foo", &["researcher", "writer"])
            .to_str()
            .unwrap(),
    )
    .await
    .unwrap();
    inst.install(
        write_pack(tmp.path(), "bar", &["reviewer"])
            .to_str()
            .unwrap(),
    )
    .await
    .unwrap();

    let resolver = PackTemplateResolver::new(registry as Arc<dyn PackRegistry>);
    let mut listed = resolver.list();
    listed.sort();
    assert_eq!(
        listed,
        vec![
            "bar@1.0.0/agent-templates/reviewer".to_string(),
            "foo@1.0.0/agent-templates/researcher".to_string(),
            "foo@1.0.0/agent-templates/writer".to_string(),
        ]
    );
    for fq in &listed {
        let content = resolver
            .resolve(fq)
            .unwrap_or_else(|e| panic!("listed ref {fq} must resolve: {e:?}"));
        assert!(!content.agents_md.is_empty());
    }
}

#[tokio::test]
async fn ptl_02_list_is_empty_without_packs_and_ignores_non_template_provides() {
    let tmp = tempfile::TempDir::new().unwrap();
    let packs = tmp.path().join("packs");
    let registry = Arc::new(InMemoryPackRegistry::new(packs.clone()));
    registry.rescan().await.unwrap();
    let resolver = PackTemplateResolver::new(registry.clone() as Arc<dyn PackRegistry>);
    assert!(resolver.list().is_empty());

    // A pack with only behavior-binaries contributes no template refs.
    let dir = tmp.path().join("bin-src");
    std::fs::create_dir_all(dir.join("behavior-binaries")).unwrap();
    std::fs::write(dir.join("behavior-binaries/dummy.wasm"), b"\0asm\x01\0\0\0").unwrap();
    std::fs::write(
        dir.join("pack.yaml"),
        "name: bin\nversion: 1.0.0\nruntime-version: \">=0.1.0\"\nprovides:\n  behavior-binaries:\n    - dummy\nchecksums:\n  algo: sha256\n  files: {}\n",
    )
    .unwrap();
    Installer::new(&packs, registry, "0.1.0", Arc::new(AutoApprove))
        .install(dir.to_str().unwrap())
        .await
        .unwrap();
    assert!(resolver.list().is_empty());
}

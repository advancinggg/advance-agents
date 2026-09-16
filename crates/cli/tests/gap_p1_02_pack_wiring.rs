#![cfg(feature = "gap-p1")]
//! GAP-02 (P1) — composition-root pack wiring. See docs/plans/PACK-GAP-CLOSURE.md §2.8.
//! `build_pack_wiring` must yield a registry rescanned from disk, a chained template
//! resolver (builtins + pack FQ refs), and a pack evaluator resolver.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use advance_cli::pack_wiring::{build_pack_wiring, ChainedTemplateResolver};
use advance_pack_manager::{AutoApprove, InMemoryPackRegistry, Installer, PackRegistry};
use cap_lifecycle::templates::{
    BuiltinTemplateRegistry, TemplateContent, TemplateError, TemplateResolver,
};

const TEMPLATE_YAML: &str = "name: researcher\nversion: 1.0.0\ndescription: Research template\nbehavior:\n  type: embedded\n  binary: behavior.wasm\ndefault-model: sonnet\n";
const MARKER: &str = "PACK-WIRING-MARKER";

fn write_pack(root: &Path) -> PathBuf {
    let dir = root.join("foo-src");
    let t = dir.join("agent-templates/researcher");
    std::fs::create_dir_all(&t).unwrap();
    std::fs::write(t.join("template.yaml"), TEMPLATE_YAML).unwrap();
    std::fs::write(t.join("AGENTS.md"), format!("# researcher\n{MARKER}\n")).unwrap();
    std::fs::write(t.join("behavior.wasm"), b"\0asm\x01\0\0\0").unwrap();
    std::fs::write(
        dir.join("pack.yaml"),
        "name: foo\nversion: 1.0.0\nruntime-version: \">=0.1.0\"\nprovides:\n  agent-templates:\n    - researcher\nchecksums:\n  algo: sha256\n  files: {}\n",
    )
    .unwrap();
    dir
}

async fn install(packs: &Path, src: &Path) {
    Installer::new(
        packs,
        Arc::new(InMemoryPackRegistry::new(packs.to_path_buf())),
        "0.1.0",
        Arc::new(AutoApprove),
    )
    .install(src.to_str().unwrap())
    .await
    .expect("install");
}

#[tokio::test]
async fn pw_01_wiring_rescans_installed_packs_and_resolves_fq_templates() {
    let tmp = tempfile::TempDir::new().unwrap();
    let packs = tmp.path().join("packs");
    install(&packs, &write_pack(tmp.path())).await;

    let wiring = build_pack_wiring(&packs, None).await.expect("wiring");
    assert!(
        wiring.registry.has("foo", "1.0.0"),
        "registry rescanned from disk"
    );

    let content = wiring
        .template_resolver
        .resolve("foo@1.0.0/agent-templates/researcher")
        .expect("pack template resolves through the chain");
    assert!(content.agents_md.contains(MARKER));
    assert_eq!(content.name, "researcher");
}

#[tokio::test]
async fn pw_02_builtins_still_resolve_and_list_is_the_union() {
    let tmp = tempfile::TempDir::new().unwrap();
    let packs = tmp.path().join("packs");
    install(&packs, &write_pack(tmp.path())).await;
    let wiring = build_pack_wiring(&packs, None).await.unwrap();

    let builtin = BuiltinTemplateRegistry::new();
    let builtin_names = builtin.list();
    assert!(!builtin_names.is_empty(), "runtime ships builtin templates");
    for name in &builtin_names {
        wiring
            .template_resolver
            .resolve(name)
            .unwrap_or_else(|e| panic!("builtin {name} must still resolve: {e:?}"));
    }
    let listed = wiring.template_resolver.list();
    for name in &builtin_names {
        assert!(listed.contains(name), "{listed:?}");
    }
    assert!(
        listed.contains(&"foo@1.0.0/agent-templates/researcher".to_string()),
        "pack templates are discoverable: {listed:?}"
    );
}

#[tokio::test]
async fn pw_03_missing_packs_dir_yields_empty_registry_not_error() {
    let tmp = tempfile::TempDir::new().unwrap();
    let packs = tmp.path().join("never-created");
    let wiring = build_pack_wiring(&packs, None)
        .await
        .expect("fresh workspace boots");
    assert!(wiring.registry.list_installed().is_empty());
    assert!(packs.is_dir(), "packs dir is created for later installs");
    assert!(wiring
        .template_resolver
        .resolve("nope@1.0.0/agent-templates/x")
        .is_err());
}

#[test]
fn pw_04_chain_routes_by_reference_shape() {
    struct Pack;
    impl TemplateResolver for Pack {
        fn resolve(&self, r: &str) -> Result<TemplateContent, TemplateError> {
            Err(TemplateError::NotFound(format!("pack:{r}")))
        }
        fn list(&self) -> Vec<String> {
            vec!["p@1.0.0/agent-templates/t".into()]
        }
    }
    let chain =
        ChainedTemplateResolver::new(Arc::new(BuiltinTemplateRegistry::new()), Arc::new(Pack));
    // FQ shape (has '@' and '/') goes to the pack half — surfaces the pack half's error.
    let err = chain.resolve("p@1.0.0/agent-templates/t").unwrap_err();
    assert!(format!("{err:?}").contains("pack:"), "{err:?}");
    // Bare name goes to builtins.
    let first = BuiltinTemplateRegistry::new().list()[0].clone();
    assert!(chain.resolve(&first).is_ok());
    assert!(chain
        .list()
        .contains(&"p@1.0.0/agent-templates/t".to_string()));
}

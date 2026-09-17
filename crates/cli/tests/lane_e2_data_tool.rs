#![cfg(feature = "lane-e2")]
//! Lane E2 — the `data` host tool is wired into the production registry, the `agenda` pack
//! builds to a real `tool.wasm` and installs, and `describe` sees the bound operations
//! (the internal entity-data lane plan §3). The build test needs `wasm32-unknown-unknown`
//! installed (`rustup target add wasm32-unknown-unknown`), as CI does from E2 on.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use advance_cli::commands::pack::{build_pack, PackBuildManifest};
use advance_cli::data_wiring::register_data_tool;
use advance_event_bus::taxonomy::{self, ALL_EVENT_TYPES, TRIGGER_BUS_WHITELIST};
use advance_pack_manager::{
    verify_checksums, AutoApprove, InMemoryPackRegistry, Installer, PackManifest, PackRegistry,
};
use advance_shared_types::traits::CallableInventoryReader;
use cap_data::test_support::{
    agenda_schema, AllowAll, DirWorkspaceFs, FixedClock, MemoryEntityIndex, SequentialIds,
};
use cap_data::DataStore;
use cap_tools::{wasm_tool_entries, CallableInventory, LazyRegistryConfig, LazyToolRegistry, ToolRegistry};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

fn store(ws: &Path) -> Arc<DataStore> {
    Arc::new(DataStore::new(
        Arc::new(DirWorkspaceFs::new(ws.to_path_buf())),
        Arc::new(MemoryEntityIndex::default()),
        agenda_schema(),
        Arc::new(SequentialIds::default()),
        Arc::new(FixedClock::at("2026-09-17T08:00:00Z")),
    ))
}

#[tokio::test]
async fn e2_data_tool_is_listed_and_enters_the_callable_inventory() {
    let ws = tempfile::TempDir::new().unwrap();
    let registry = LazyToolRegistry::new(LazyRegistryConfig::default());
    register_data_tool(&registry, store(ws.path()), Arc::new(AllowAll))
        .await
        .expect("register data tool");

    let listed = registry.list().await;
    let data = listed.iter().find(|t| t.id == "data").expect("`data` is a listed tool");
    assert_eq!(data.methods.len(), 9);
    assert!(data.methods.iter().any(|m| m.name == "apply"));

    // The same snapshot `start.rs` takes for the context assembler's `# Available Tools`.
    let inventory = CallableInventory::new(wasm_tool_entries(&registry).await, vec![]);
    assert!(
        inventory.list_wasm_tools("alice").iter().any(|t| t.name == "data"),
        "the model can see `data`"
    );
}

#[test]
fn e2_entity_changed_is_registered_but_never_a_trigger() {
    assert_eq!(taxonomy::data::ENTITY_CHANGED, "data.entity_changed");
    assert!(ALL_EVENT_TYPES.contains(&taxonomy::data::ENTITY_CHANGED));
    assert!(!TRIGGER_BUS_WHITELIST.contains(&taxonomy::data::ENTITY_CHANGED));
    assert_eq!(TRIGGER_BUS_WHITELIST.len(), 12, "PRD §15.4 stays at 12");
}

#[test]
fn e2_build_manifest_parses() {
    let m = PackBuildManifest::load(&repo_root().join("packs/agenda.build.yaml")).expect("manifest");
    assert_eq!(m.tools.len(), 1);
    assert_eq!(m.tools[0].skill, "agenda");
    assert_eq!(m.tools[0].crate_dir, PathBuf::from("crates/packs/agenda-tools"));
    assert!(
        PackBuildManifest::load(&repo_root().join("packs/nope.build.yaml")).is_err(),
        "a missing manifest is an error for the loader; `build_pack` treats it as text-only"
    );
}

#[tokio::test]
async fn e2_pack_build_emits_tool_wasm_with_checksums_installs_and_binds_operations() {
    let out = tempfile::TempDir::new().unwrap();
    let src = repo_root().join("packs/agenda");
    let built = build_pack(&src, out.path()).expect("build agenda (needs wasm32 target)");
    assert_eq!(built.dir, out.path().join("agenda"));
    let wasm = built.dir.join("skills/agenda/tool.wasm");
    assert!(wasm.is_file(), "{}", wasm.display());
    assert_eq!(built.tools, vec![wasm.clone()]);

    // The source pack.yaml is untouched; the output one lists every artifact and verifies.
    let source_manifest = std::fs::read_to_string(src.join("pack.yaml")).unwrap();
    assert!(source_manifest.contains("files: {}"));
    let out_manifest = std::fs::read_to_string(built.dir.join("pack.yaml")).unwrap();
    assert!(out_manifest.contains("skills/agenda/tool.wasm"), "{out_manifest}");
    assert!(out_manifest.contains("skills/agenda/SKILL.md"), "{out_manifest}");
    let parsed = PackManifest::from_yaml(&out_manifest).unwrap();
    verify_checksums(&built.dir, &parsed.checksums).expect("self-consistent checksums");

    // Installs with the real installer; the skill (with its tool.wasm) resolves.
    let packs = tempfile::TempDir::new().unwrap();
    let packs_dir = packs.path().join("packs");
    let registry = Arc::new(InMemoryPackRegistry::new(packs_dir.clone()));
    let installer = Installer::new(
        &packs_dir,
        registry.clone(),
        env!("CARGO_PKG_VERSION"),
        Arc::new(AutoApprove),
    );
    let report = installer.install(built.dir.to_str().unwrap()).await.expect("install built pack");
    assert_eq!(report.name, "agenda");
    let skill = registry.resolve("agenda@0.1.0/skills/agenda").expect("skill resolves");
    assert!(skill.local_path.join("tool.wasm").is_file());

    // Once the skill tool is registered under its canonical id, `describe` marks the bound
    // operations available; before that they are reported (honestly) as unavailable.
    let ws = tempfile::TempDir::new().unwrap();
    let tools = LazyToolRegistry::new(LazyRegistryConfig::default());
    let reducer = advance_cli::data_wiring::deterministic_reducer(Arc::new(tools));
    let s = DataStore::new(
        Arc::new(DirWorkspaceFs::new(ws.path().to_path_buf())),
        Arc::new(MemoryEntityIndex::default()),
        agenda_schema(),
        Arc::new(SequentialIds::default()),
        Arc::new(FixedClock::at("2026-09-17T08:00:00Z")),
    )
    .with_reducer(reducer.clone());
    assert!(s.describe("alice").aspects[0].operations.iter().all(|o| !o.available));
    reducer
        .registry()
        .register_binary("skill::agenda", std::fs::read(&wasm).unwrap())
        .await;
    assert!(s.describe("alice").aspects[0].operations.iter().all(|o| o.available));
}

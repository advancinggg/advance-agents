//! `packs/` directory CI guard.
//!
//! Every subdirectory of the repository's `packs/` is a first-party or community pack. This
//! test drives the REAL `advance_pack_manager::Installer` over each one into a fresh temporary
//! packs dir: layout allow-list, manifest grammar, provides-on-disk, skill tool-exports,
//! resource-capability manifests, `.meta.yaml` index and registry rescan all run for real.
//! `AutoApprove` is deliberate — CI validates structure, not the operator's capability decision
//! (a pack's `required-capabilities` are checked against the runtime catalog at real install).
//!
//! A pack that fails to install fails the build. Adding a pack = adding a directory.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use advance_pack_manager::{
    AutoApprove, ComponentKind, InMemoryPackRegistry, Installer, PackRegistry,
};

/// The MODULE-018 install-layout directory of each provide kind (the `{kind-dir}` segment of a
/// prefixed FQ ref). Exhaustive on purpose: a 12th kind must be added here too.
fn kind_dir(kind: ComponentKind) -> &'static str {
    match kind {
        ComponentKind::Binary => "behavior-binaries",
        ComponentKind::AgentTemplate => "agent-templates",
        ComponentKind::Skill => "skills",
        ComponentKind::RunnableComponent => "components",
        ComponentKind::ChannelAdapter => "channel-adapters",
        ComponentKind::McpServer => "mcp-servers",
        ComponentKind::Preset => "presets",
        ComponentKind::Workflow => "workflows",
        ComponentKind::MemorySeed => "memory-seeds",
        ComponentKind::MetaSchemaExtension => "meta-schema-extensions",
        ComponentKind::ResourceCapability => "resource-capabilities",
    }
}

fn packs_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../packs")
        .canonicalize()
        .expect("packs/ directory exists at the repository root")
}

fn pack_dirs() -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(packs_root())
        .expect("read packs/")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    dirs.sort();
    dirs
}

#[tokio::test]
async fn every_pack_in_packs_dir_installs_with_the_real_installer() {
    let dirs = pack_dirs();
    assert!(
        !dirs.is_empty(),
        "packs/ must contain at least the first-party packs"
    );
    let tmp = tempfile::TempDir::new().unwrap();
    let packs_dir = tmp.path().join("packs");
    let registry = Arc::new(InMemoryPackRegistry::new(packs_dir.clone()));
    let installer = Installer::new(
        &packs_dir,
        registry.clone(),
        env!("CARGO_PKG_VERSION"),
        Arc::new(AutoApprove),
    );

    for dir in &dirs {
        let manifest = std::fs::read_to_string(dir.join("pack.yaml"))
            .unwrap_or_else(|e| panic!("{}: pack.yaml unreadable: {e}", dir.display()));
        assert!(
            manifest.contains("trust-level: untrusted"),
            "{}: contribution rule 1 — trust-level must be untrusted",
            dir.display()
        );
        let report = installer
            .install(dir.to_str().unwrap())
            .await
            .unwrap_or_else(|e| panic!("{}: install failed: {e}", dir.display()));
        assert!(
            registry.has(&report.name, &report.version),
            "{}: not in registry after install",
            dir.display()
        );
        // Every declared provide resolves through the registry in the prefixed FQ-ref form
        // (`{pack}@{version}/{kind-dir}/{name}`, the one the runtime uses when a pack reuses a
        // name across kinds — `agenda` is both a skill and a meta-schema extension), so a typo
        // between pack.yaml and the directory tree cannot ship.
        let provides = registry
            .provides(&report.name, &report.version)
            .expect("installed pack enumerates provides");
        assert!(
            !provides.is_empty(),
            "{}: a pack must provide something",
            dir.display()
        );
        for p in provides {
            let fq = format!(
                "{}@{}/{}/{}",
                report.name,
                report.version,
                kind_dir(p.kind),
                p.name
            );
            registry.resolve(&fq).unwrap_or_else(|e| {
                panic!("{}: provide {fq} does not resolve: {e}", dir.display())
            });
        }
    }
    assert_eq!(registry.list_installed().len(), dirs.len());
}

/// `<repo>/target/packs/*` — the output of `advance pack build` (CI runs it before the tests;
/// locally the test is a no-op until a build ran). Each built pack installs into ITS OWN fresh
/// packs dir (it shares `name@version` with its source directory) and its skill `tool.wasm`
/// passes the installer's tool-exports validation.
#[tokio::test]
async fn every_built_pack_installs_with_the_real_installer() {
    let built_root = packs_root().join("../target/packs");
    let Ok(built_root) = built_root.canonicalize() else {
        eprintln!("target/packs absent — run `advance pack build` first; skipping");
        return;
    };
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(&built_root)
        .expect("read target/packs")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_dir() && p.join("pack.yaml").is_file())
        .collect();
    dirs.sort();
    for dir in &dirs {
        let tmp = tempfile::TempDir::new().unwrap();
        let packs_dir = tmp.path().join("packs");
        let registry = Arc::new(InMemoryPackRegistry::new(packs_dir.clone()));
        let installer = Installer::new(
            &packs_dir,
            registry.clone(),
            env!("CARGO_PKG_VERSION"),
            Arc::new(AutoApprove),
        );
        let report = installer
            .install(dir.to_str().unwrap())
            .await
            .unwrap_or_else(|e| panic!("{}: built pack install failed: {e}", dir.display()));
        assert!(registry.has(&report.name, &report.version));
        for p in registry
            .provides(&report.name, &report.version)
            .expect("provides")
        {
            if p.kind == ComponentKind::Skill {
                let fq = format!("{}@{}/skills/{}", report.name, report.version, p.name);
                let resolved = registry.resolve(&fq).expect("skill resolves");
                if dir.join("skills").join(&p.name).join("tool.wasm").is_file() {
                    assert!(
                        resolved.local_path.join("tool.wasm").is_file(),
                        "{fq}: tool.wasm installed"
                    );
                }
            }
        }
    }
}

#[test]
fn packs_dir_has_no_stray_top_level_files() {
    for dir in pack_dirs() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let name = entry.unwrap().file_name();
            let name = name.to_string_lossy();
            let ok = name == "pack.yaml"
                || name == "pack.sig"
                || matches!(
                    name.as_ref(),
                    "behavior-binaries"
                        | "agent-templates"
                        | "skills"
                        | "components"
                        | "channel-adapters"
                        | "mcp-servers"
                        | "presets"
                        | "workflows"
                        | "memory-seeds"
                        | "meta-schema-extensions"
                        | "resource-capabilities"
                );
            assert!(ok, "{}: stray top-level entry {name:?}", dir.display());
        }
    }
}

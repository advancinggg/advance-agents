//! AC-11 — NamespaceResolver three-tier lookup tests (T47-T51).
//!
//! Tier priority: agent-local → admin → built-in. Fall-through ONLY on
//! `PackNotFound` (tier doesn't own the pack@version). `ComponentNotFound`
//! / `AmbiguousComponent` propagate verbatim (tier owns the pack but the
//! component is missing within it). `UnversionedRef` bubbles up.

use std::path::Path;
use std::sync::Arc;

use advance_pack_manager::{
    AutoApprove, InMemoryPackRegistry, Installer, NamespaceResolver, PackError, PackRegistry,
    RecordingTraceSink,
};

fn build_pack_with_template(root: &Path, name: &str) -> std::path::PathBuf {
    let pack_dir = root.join(format!("source-{name}"));
    std::fs::create_dir_all(&pack_dir).unwrap();
    std::fs::create_dir_all(pack_dir.join("agent-templates").join("researcher")).unwrap();
    std::fs::write(
        pack_dir
            .join("agent-templates")
            .join("researcher")
            .join("AGENTS.md"),
        format!("# {name} researcher"),
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
  agent-templates: [researcher]
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

async fn install_to_tier(
    fixture_root: &Path,
    tier_dir_name: &str,
    pack_name: &str,
) -> Arc<InMemoryPackRegistry> {
    let pack_src = build_pack_with_template(fixture_root, &format!("{tier_dir_name}-src"));
    // Rewrite pack name in the source's pack.yaml so different tiers can
    // host packs with the SAME name but different identities (verifies the
    // priority semantic).
    let pack_yaml_path = pack_src.join("pack.yaml");
    let original = std::fs::read_to_string(&pack_yaml_path).unwrap();
    let rewritten = original.replace(
        &format!("name: {tier_dir_name}-src"),
        &format!("name: {pack_name}"),
    );
    std::fs::write(&pack_yaml_path, rewritten).unwrap();

    let packs_dir = fixture_root.join(format!("packs-{tier_dir_name}"));
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
        .expect("install");
    registry
}

#[tokio::test]
async fn t47_agent_local_wins_over_admin() {
    let dir = tempfile::TempDir::new().unwrap();
    let agent_local = install_to_tier(dir.path(), "local", "researchpack").await;
    let admin = install_to_tier(dir.path(), "admin", "researchpack").await;
    let resolver = NamespaceResolver::new(admin.clone())
        .with_agent_local(agent_local.clone() as Arc<dyn PackRegistry>);

    let resolution = resolver
        .resolve("researchpack@1.0.0/agent-templates/researcher")
        .unwrap();
    // Should be rooted in the agent-local tier's packs_dir.
    let local_packs_dir = agent_local.packs_dir();
    assert!(
        resolution.local_path.starts_with(local_packs_dir),
        "agent-local should win — resolution.local_path={:?}, expected under {:?}",
        resolution.local_path,
        local_packs_dir,
    );
}

#[tokio::test]
async fn t48_admin_fallback_when_agent_local_missing_pack() {
    let dir = tempfile::TempDir::new().unwrap();
    let admin = install_to_tier(dir.path(), "admin", "adminonly").await;
    // Empty agent-local: no packs installed.
    let agent_local_empty = Arc::new(InMemoryPackRegistry::new(dir.path().join("empty-local")));
    let resolver = NamespaceResolver::new(admin.clone())
        .with_agent_local(agent_local_empty as Arc<dyn PackRegistry>);

    let resolution = resolver
        .resolve("adminonly@1.0.0/agent-templates/researcher")
        .unwrap();
    let admin_packs_dir = admin.packs_dir();
    assert!(resolution.local_path.starts_with(admin_packs_dir));
}

#[tokio::test]
async fn t49_builtin_fallback_when_agent_local_and_admin_missing() {
    let dir = tempfile::TempDir::new().unwrap();
    let agent_local_empty = Arc::new(InMemoryPackRegistry::new(dir.path().join("local-empty")));
    let admin_empty = Arc::new(InMemoryPackRegistry::new(dir.path().join("admin-empty")));
    let builtin = install_to_tier(dir.path(), "builtin", "builtinpack").await;
    let resolver = NamespaceResolver::new(admin_empty as Arc<dyn PackRegistry>)
        .with_agent_local(agent_local_empty as Arc<dyn PackRegistry>)
        .with_builtin(builtin.clone() as Arc<dyn PackRegistry>);

    let resolution = resolver
        .resolve("builtinpack@1.0.0/agent-templates/researcher")
        .unwrap();
    let builtin_packs_dir = builtin.packs_dir();
    assert!(resolution.local_path.starts_with(builtin_packs_dir));
}

#[tokio::test]
async fn t50_all_tiers_absent_returns_pack_not_found() {
    let dir = tempfile::TempDir::new().unwrap();
    let admin_empty = Arc::new(InMemoryPackRegistry::new(dir.path().join("admin-empty")));
    let resolver = NamespaceResolver::new(admin_empty as Arc<dyn PackRegistry>);
    match resolver.resolve("never-existed@1.0.0/agent-templates/x") {
        Err(PackError::PackNotFound(name, ver)) => {
            assert_eq!(name, "never-existed");
            assert_eq!(ver, "1.0.0");
        }
        other => panic!("expected PackNotFound, got {other:?}"),
    }
}

#[tokio::test]
async fn t51_unversioned_fq_ref_propagates_without_tier_lookup() {
    // The first tier's `resolve()` invokes `parse_fq_ref`, which surfaces
    // `UnversionedRef`. `NamespaceResolver`'s fall-through rule rejects
    // anything other than `PackNotFound`, so `UnversionedRef` propagates
    // straight to the caller.
    let dir = tempfile::TempDir::new().unwrap();
    let admin = install_to_tier(dir.path(), "admin", "anypack").await;
    let resolver = NamespaceResolver::new(admin as Arc<dyn PackRegistry>);
    match resolver.resolve("anypack/no-version") {
        Err(PackError::UnversionedRef(_)) => {}
        other => panic!("expected UnversionedRef, got {other:?}"),
    }
}

#[tokio::test]
async fn t51b_component_not_found_in_owning_tier_does_not_fall_through() {
    // Agent-local has the pack but NOT the component; admin has the same
    // pack name@ver WITH the component. Fall-through must NOT happen —
    // the agent-local tier owns the pack-namespace's components.
    let dir = tempfile::TempDir::new().unwrap();
    let agent_local = install_to_tier(dir.path(), "local", "samepack").await;
    let admin = install_to_tier(dir.path(), "admin", "samepack").await;
    let resolver = NamespaceResolver::new(admin as Arc<dyn PackRegistry>)
        .with_agent_local(agent_local as Arc<dyn PackRegistry>);
    // `nosuch` does not exist in either tier's `provides[*]`.
    match resolver.resolve("samepack@1.0.0/agent-templates/nosuch") {
        Err(PackError::ComponentNotFound { component, .. }) => {
            assert_eq!(component, "agent-templates/nosuch");
        }
        other => panic!("expected ComponentNotFound from agent-local tier, got {other:?}"),
    }
}

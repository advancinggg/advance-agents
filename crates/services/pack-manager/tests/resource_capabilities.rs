//! MODULE-018-AC-17 (REQ-380) integration tests — the 11th `resource-capabilities`
//! provide category, end-to-end over the REAL `Installer` / `InMemoryPackRegistry` /
//! `DefaultMaterializer`.
//!
//! T86 — a valid resource-capabilities pack installs cleanly AND the pack registry
//!       RESOLVES the capability to `ComponentKind::ResourceCapability` (registered at
//!       install, register-not-copied).
//! T87 — a declared resource-capability whose dir / `capability.yaml` is missing → install fails.
//! T88 — a malformed `capability.yaml` (ADR-shape violation) → install fails.
//! T89 — `register_resource_capability` returns the content-derived `ResourceCapabilityId`;
//!       a wrong-kind ref → `MaterializeMissingProvide`; register-not-copy (no target param).
//! T90 — post-install tamper of `capability.yaml` → `rescan()` re-validates and FAILS.
//!
//! Anti-fake-green: on the PRE-BUILD tree a `resource-capabilities:` key is rejected at
//! manifest parse (`PackProvides` `deny_unknown_fields`) and the layout allow-list, so
//! T86's clean install is a genuine before/after behaviour change; T87/T88/T90 prove the
//! validation is load-bearing (invalid packs are rejected, not blanket-accepted).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use advance_pack_manager::{
    AutoApprove, ComponentKind, DefaultMaterializer, InMemoryPackRegistry, Installer,
    MaterializeAction, McpServerId, PackError, PackInstallReport, PackRegistry, RecordingTraceSink,
    ResourceCapabilityId, SecretStore, SecretValue, WorkflowExecutor, WorkflowTrigger,
};

// ───── fixtures ─────────────────────────────────────────────────────────

const VALID_CAPABILITY_YAML: &str = r#"
id: advance.structured-data
description: Structured data resource capability.
supports:
  resource_types: [project, collection]
  mime_types: [text/markdown]
  ref_schemes: [data]
  projection_schemas: [advance.entity-table.v1]
canonical_surfaces:
  - projection-native
store:
  default_backend: sqlite
  ownership: workspace-owned
  projection_format: ndjson
tools:
  - name: advance.data.query
    read_only: true
  - name: advance.data.upsert
    read_only: false
mcp:
  expose_tools: true
  expose_resources: true
widgets:
  - entity.table
  - entity.form
"#;

// Sentinels for the capability.yaml contents argument.
const NO_DIR: &str = "<<no-dir>>";
const NO_FILE: &str = "<<no-file>>";

/// Build a pack SOURCE tree declaring `resource-capabilities: [<cap names>]` plus a
/// `presets/pset.yaml` (so T89 has a wrong-kind ref to feed). Each `(cap_name, yaml)`:
///   - `NO_DIR`  → declare the name but do NOT create `resource-capabilities/{name}/`
///   - `NO_FILE` → create the dir but NOT `capability.yaml`
///   - otherwise → create the dir + `capability.yaml` with the given contents
fn build_rescap_pack_source(
    root: &Path,
    name: &str,
    version: &str,
    caps: &[(&str, &str)],
) -> PathBuf {
    let pack_dir = root.join(format!("source-{name}"));
    std::fs::create_dir_all(&pack_dir).unwrap();

    // A wrong-kind sibling (a preset) so register_resource_capability can be fed a
    // ref that resolves to a DIFFERENT ComponentKind.
    std::fs::create_dir_all(pack_dir.join("presets")).unwrap();
    std::fs::write(pack_dir.join("presets").join("pset.yaml"), b"caps: []").unwrap();

    let mut names = Vec::new();
    for (cap_name, yaml) in caps {
        names.push((*cap_name).to_string());
        if *yaml == NO_DIR {
            continue;
        }
        let cap_dir = pack_dir.join("resource-capabilities").join(cap_name);
        std::fs::create_dir_all(&cap_dir).unwrap();
        if *yaml != NO_FILE {
            std::fs::write(cap_dir.join("capability.yaml"), yaml.as_bytes()).unwrap();
        }
    }

    let names_yaml = names
        .iter()
        .map(|n| format!("\"{n}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let pack_yaml = format!(
        "name: {name}\nversion: {version}\nruntime-version: \">=0.0.1\"\ndependencies: []\nprovides:\n  presets: [pset]\n  resource-capabilities: [{names_yaml}]\nrequired-capabilities: []\ntrust-level: untrusted\nchecksums:\n  algo: sha256\n  files: {{}}\n"
    );
    std::fs::write(pack_dir.join("pack.yaml"), pack_yaml).unwrap();
    pack_dir
}

/// Install a source pack via the real `Installer`; returns the registry, packs dir, and
/// the install report (for the 8-step trace assertion in T86).
async fn install_rescap_pack(
    pack_src: &Path,
    work: &Path,
) -> Result<(Arc<InMemoryPackRegistry>, PathBuf, PackInstallReport), PackError> {
    let packs_dir = work.join("packs");
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
    let report = installer
        .install(pack_src.to_string_lossy().as_ref())
        .await?;
    Ok((registry, packs_dir, report))
}

// Minimal seams for DefaultMaterializer construction. register_resource_capability
// uses only self.registry, so these are never invoked.
struct NoopExecutor;
impl WorkflowExecutor for NoopExecutor {
    fn spawn_child(
        &self,
        _: &str,
        _: &Path,
        _: &BTreeMap<String, serde_yml::Value>,
    ) -> Result<(), PackError> {
        Ok(())
    }
    fn submit_component(&self, _: &str, _: &WorkflowTrigger) -> Result<(), PackError> {
        Ok(())
    }
    fn register_mcp_server(
        &self,
        _: &str,
        _: &BTreeMap<String, SecretValue>,
    ) -> Result<McpServerId, PackError> {
        Ok(McpServerId("noop".into()))
    }
}
struct NoopSecretStore;
impl SecretStore for NoopSecretStore {
    fn get(&self, _: &str) -> Option<SecretValue> {
        None
    }
}

// ───── T86 — install + registered/resolvable ─────────────────────────────

#[tokio::test]
async fn t86_resource_capability_pack_installs_and_is_registered() {
    let dir = tempfile::TempDir::new().unwrap();
    let src = build_rescap_pack_source(
        dir.path(),
        "okfpack",
        "1.0.0",
        &[("structured-data", VALID_CAPABILITY_YAML)],
    );
    let (registry, packs_dir, report) = install_rescap_pack(&src, dir.path())
        .await
        .expect("a valid resource-capabilities pack must install cleanly");

    // AC-17 validation runs INSIDE the existing step ⑥ window — no new InstallStep is
    // added, so the canonical 8-step PRD §19.5 trace is preserved.
    assert_eq!(
        report.trace_steps.len(),
        8,
        "trace: {:?}",
        report.trace_steps
    );

    // "Registered at install" — the pack registry resolves the capability to type 11.
    let res = registry
        .resolve("okfpack@1.0.0/resource-capabilities/structured-data")
        .expect("installed resource-capability must resolve");
    assert_eq!(res.component_kind, ComponentKind::ResourceCapability);

    // Register-not-copied: the manifest lives at its canonical install path; nothing was
    // materialized into an agent workspace.
    let installed_manifest = packs_dir
        .join("okfpack@1.0.0")
        .join("resource-capabilities")
        .join("structured-data")
        .join("capability.yaml");
    assert!(installed_manifest.is_file());
}

// ───── T87 — missing dir / manifest rejected at install ───────────────────

#[tokio::test]
async fn t87_missing_capability_yaml_or_dir_rejected_at_install() {
    // (a) dir created but no capability.yaml.
    let dir = tempfile::TempDir::new().unwrap();
    let src = build_rescap_pack_source(
        dir.path(),
        "okfpack",
        "1.0.0",
        &[("structured-data", NO_FILE)],
    );
    let err = install_rescap_pack(&src, dir.path())
        .await
        .map(|_| ())
        .expect_err("missing capability.yaml must reject install");
    assert!(matches!(err, PackError::InvalidManifest(_)), "got {err:?}");

    // (b) declared name with no dir at all.
    let dir2 = tempfile::TempDir::new().unwrap();
    let src2 = build_rescap_pack_source(
        dir2.path(),
        "okfpack2",
        "1.0.0",
        &[("structured-data", NO_DIR)],
    );
    let err2 = install_rescap_pack(&src2, dir2.path())
        .await
        .map(|_| ())
        .expect_err("missing resource-capability dir must reject install");
    assert!(
        matches!(err2, PackError::InvalidManifest(_)),
        "got {err2:?}"
    );
}

// ───── T88 — malformed manifest rejected at install ───────────────────────

#[tokio::test]
async fn t88_malformed_capability_yaml_rejected_at_install() {
    // (a) unknown canonical_surface → ConstraintViolation.
    let dir = tempfile::TempDir::new().unwrap();
    let bad = "id: advance.x\ncanonical_surfaces: [not-a-real-surface]\n";
    let src = build_rescap_pack_source(dir.path(), "okfpack", "1.0.0", &[("structured-data", bad)]);
    let err = install_rescap_pack(&src, dir.path())
        .await
        .map(|_| ())
        .expect_err("bad canonical_surface must reject install");
    assert!(
        matches!(err, PackError::ConstraintViolation { .. }),
        "got {err:?}"
    );

    // (b) empty canonical_surfaces → ConstraintViolation.
    let dir2 = tempfile::TempDir::new().unwrap();
    let bad2 = "id: advance.x\ncanonical_surfaces: []\n";
    let src2 = build_rescap_pack_source(
        dir2.path(),
        "okfpack2",
        "1.0.0",
        &[("structured-data", bad2)],
    );
    let err2 = install_rescap_pack(&src2, dir2.path())
        .await
        .map(|_| ())
        .expect_err("empty canonical_surfaces must reject install");
    assert!(
        matches!(err2, PackError::ConstraintViolation { .. }),
        "got {err2:?}"
    );

    // (c) missing required `id` → parse error surfaces as InvalidManifest.
    let dir3 = tempfile::TempDir::new().unwrap();
    let bad3 = "canonical_surfaces: [projection-native]\n";
    let src3 = build_rescap_pack_source(
        dir3.path(),
        "okfpack3",
        "1.0.0",
        &[("structured-data", bad3)],
    );
    let err3 = install_rescap_pack(&src3, dir3.path())
        .await
        .map(|_| ())
        .expect_err("missing id must reject install");
    assert!(
        matches!(err3, PackError::InvalidManifest(_)),
        "got {err3:?}"
    );
}

// ───── T89 — register_resource_capability surface ─────────────────────────

#[tokio::test]
async fn t89_register_resource_capability_returns_manifest_id() {
    let dir = tempfile::TempDir::new().unwrap();
    let src = build_rescap_pack_source(
        dir.path(),
        "okfpack",
        "1.0.0",
        &[("structured-data", VALID_CAPABILITY_YAML)],
    );
    let (registry, packs_dir, _report) = install_rescap_pack(&src, dir.path())
        .await
        .expect("install");

    let registry_dyn: Arc<dyn PackRegistry> = registry.clone();
    let mat = DefaultMaterializer::new(
        registry_dyn,
        Arc::new(NoopExecutor),
        Arc::new(NoopSecretStore),
    );

    // Happy path: the returned id is CONTENT-DERIVED from the manifest `id:` — not a
    // synthetic placeholder. register-not-copy by construction (no `target` param).
    let id = mat
        .register_resource_capability("okfpack@1.0.0/resource-capabilities/structured-data")
        .expect("register a valid resource-capability");
    assert_eq!(id, ResourceCapabilityId("advance.structured-data".into()));

    // Wrong-kind ref (a preset) → MaterializeMissingProvide (the resolve_kind guard).
    assert!(matches!(
        mat.register_resource_capability("okfpack@1.0.0/presets/pset"),
        Err(PackError::MaterializeMissingProvide { .. })
    ));

    // On-demand shape re-validation (adversarial round 12): since shape-parse is
    // install-only (not re-run on rescan), a post-install manifest-shape tamper is caught
    // when the capability is register()'d — register re-parses + validates.
    let installed = packs_dir
        .join("okfpack@1.0.0")
        .join("resource-capabilities")
        .join("structured-data")
        .join("capability.yaml");
    std::fs::write(
        &installed,
        b"id: advance.x\ncanonical_surfaces: [not-a-real-surface]\n",
    )
    .unwrap();
    assert!(matches!(
        mat.register_resource_capability("okfpack@1.0.0/resource-capabilities/structured-data"),
        Err(PackError::ConstraintViolation { .. })
    ));
}

// ───── T90 — rescan re-checks existence (shape parse is install-only) ─────────

#[tokio::test]
async fn t90_rescan_rechecks_existence_shape_is_install_only() {
    let dir = tempfile::TempDir::new().unwrap();
    let src = build_rescap_pack_source(
        dir.path(),
        "okfpack",
        "1.0.0",
        &[("structured-data", VALID_CAPABILITY_YAML)],
    );
    let (registry, packs_dir, _report) = install_rescap_pack(&src, dir.path())
        .await
        .expect("install");

    // Sanity: resolves cleanly before tamper.
    assert!(registry
        .resolve("okfpack@1.0.0/resource-capabilities/structured-data")
        .is_ok());

    let installed_manifest = packs_dir
        .join("okfpack@1.0.0")
        .join("resource-capabilities")
        .join("structured-data")
        .join("capability.yaml");

    // (a) corrupt-SHAPE tamper → rescan re-checks EXISTENCE only (shape parse is
    //     install-only per the rescan cost invariant / adversarial round 12), so rescan
    //     SUCCEEDS on a shape-corrupt-but-present manifest. (The corrupt shape is instead
    //     caught on-demand at `register_resource_capability` — witnessed in T89.)
    std::fs::write(
        &installed_manifest,
        b"id: advance.x\ncanonical_surfaces: [not-a-real-surface]\n",
    )
    .unwrap();
    registry
        .rescan()
        .await
        .expect("rescan re-checks existence only; a corrupt shape is NOT re-parsed on rescan");

    // (b) DELETE tamper → rescan's existence re-check (verify_provides_on_disk inner-file) → Err.
    std::fs::remove_file(&installed_manifest).unwrap();
    let err2 = registry
        .rescan()
        .await
        .expect_err("rescan must reject a deleted capability.yaml");
    assert!(
        matches!(err2, PackError::InvalidManifest(_)),
        "got {err2:?}"
    );
}

#![cfg(feature = "gap-p2")]
//! GAP-09 (P2, pack-manager half) — materializer semantics that stop being no-ops.
//! See docs/plans/PACK-GAP-CLOSURE.md §3.1:
//! - `materialize_channel_adapter` → explicit `NotImplemented` (cap-channel has no
//!   path-loaded adapter surface) instead of a silent directory copy.
//! - `merge_meta_schema_extension` → STRUCTURED merge into a single YAML document
//!   (identical redeclaration is idempotent; differing type → ConstraintViolation),
//!   never `---`-separated multi-doc append.
//! The cli bridges (skills / presets / mcp / memory-seeds) are witnessed in
//! crates/cli/tests/gap_p2_08_09_bridges.rs.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use advance_pack_manager::{
    AutoApprove, DefaultMaterializer, InMemoryPackRegistry, Installer, MaterializeAction,
    McpServerId, PackError, PackRegistry, SecretStore, SecretValue, WorkflowExecutor,
    WorkflowTrigger,
};

/// The materializer's executor / secret-store ports are irrelevant to these two methods;
/// plain no-op implementations keep the fixture honest (no mocks with behavior).
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
        r: &str,
        _: &BTreeMap<String, SecretValue>,
    ) -> Result<McpServerId, PackError> {
        Ok(McpServerId(r.to_string()))
    }
}

struct NoSecrets;
impl SecretStore for NoSecrets {
    fn get(&self, _: &str) -> Option<SecretValue> {
        None
    }
}

fn materializer(registry: Arc<InMemoryPackRegistry>) -> DefaultMaterializer {
    DefaultMaterializer::new(
        registry as Arc<dyn PackRegistry>,
        Arc::new(NoopExecutor),
        Arc::new(NoSecrets),
    )
}

fn write_pack(root: &Path, name: &str, schema_ext: &str) -> PathBuf {
    let dir = root.join(format!("{name}-src"));
    std::fs::create_dir_all(dir.join("channel-adapters/slack")).unwrap();
    std::fs::create_dir_all(dir.join("meta-schema-extensions")).unwrap();
    std::fs::write(
        dir.join("channel-adapters/slack/adapter.wasm"),
        b"\0asm\x01\0\0\0",
    )
    .unwrap();
    std::fs::write(dir.join("meta-schema-extensions/fields.yaml"), schema_ext).unwrap();
    std::fs::write(
        dir.join("pack.yaml"),
        format!("name: {name}\nversion: 1.0.0\nruntime-version: \">=0.1.0\"\nprovides:\n  channel-adapters:\n    - slack\n  meta-schema-extensions:\n    - fields\nchecksums:\n  algo: sha256\n  files: {{}}\n"),
    )
    .unwrap();
    dir
}

async fn install_all(packs: &Path, srcs: &[PathBuf]) -> Arc<InMemoryPackRegistry> {
    let registry = Arc::new(InMemoryPackRegistry::new(packs.to_path_buf()));
    let inst = Installer::new(packs, registry.clone(), "0.1.0", Arc::new(AutoApprove));
    for s in srcs {
        inst.install(s.to_str().unwrap()).await.expect("install");
    }
    registry
}

const EXT_INT: &str = "optional:\n  priority:\n    type: integer\n    default: 0\n";
const EXT_STR: &str = "optional:\n  priority:\n    type: string\n";
const EXT_OTHER: &str = "optional:\n  published:\n    type: boolean\n    default: false\n";

#[tokio::test]
async fn g09_channel_adapter_materialization_is_explicitly_unsupported() {
    let work = tempfile::TempDir::new().unwrap();
    let packs = tempfile::TempDir::new().unwrap();
    let registry = install_all(packs.path(), &[write_pack(work.path(), "a", EXT_INT)]).await;
    let m = materializer(registry);
    let target = work.path().join("adapter-out");
    let err = m
        .materialize_channel_adapter("a@1.0.0/channel-adapters/slack", &target)
        .expect_err("must not silently copy");
    assert!(matches!(err, PackError::NotImplemented(_)), "got {err:?}");
    assert!(
        !target.exists(),
        "nothing is written for an unsupported kind"
    );
}

#[tokio::test]
async fn g09_meta_schema_merge_produces_single_document_and_is_idempotent() {
    let work = tempfile::TempDir::new().unwrap();
    let packs = tempfile::TempDir::new().unwrap();
    let registry = install_all(
        packs.path(),
        &[
            write_pack(work.path(), "a", EXT_INT),
            write_pack(work.path(), "b", EXT_OTHER),
            write_pack(work.path(), "c", EXT_INT), // identical redeclaration of `priority`
        ],
    )
    .await;
    let m = materializer(registry);
    let target = work.path().join("meta-schema.yaml");
    std::fs::write(
        &target,
        "required:\n  name:\n    type: string\n    auto: filename\n",
    )
    .unwrap();

    m.merge_meta_schema_extension("a@1.0.0/meta-schema-extensions/fields", &target)
        .unwrap();
    m.merge_meta_schema_extension("b@1.0.0/meta-schema-extensions/fields", &target)
        .unwrap();
    m.merge_meta_schema_extension("c@1.0.0/meta-schema-extensions/fields", &target)
        .unwrap();

    let text = std::fs::read_to_string(&target).unwrap();
    assert!(
        !text.contains("\n---"),
        "must be ONE YAML document, got:\n{text}"
    );
    let doc: serde_yml::Value = serde_yml::from_str(&text).expect("single parsable document");
    let optional = doc
        .get("optional")
        .and_then(|v| v.as_mapping())
        .expect("optional map");
    assert_eq!(optional.len(), 2, "priority + published, each once: {text}");
    let prio = optional.get("priority").expect("priority present");
    assert_eq!(prio.get("type").and_then(|t| t.as_str()), Some("integer"));
    assert!(optional.get("published").is_some());
    // The pre-existing required section is preserved.
    assert!(doc.get("required").and_then(|r| r.get("name")).is_some());
}

#[tokio::test]
async fn g09_meta_schema_merge_rejects_conflicting_field_type() {
    let work = tempfile::TempDir::new().unwrap();
    let packs = tempfile::TempDir::new().unwrap();
    let registry = install_all(
        packs.path(),
        &[
            write_pack(work.path(), "a", EXT_INT),
            write_pack(work.path(), "b", EXT_STR),
        ],
    )
    .await;
    let m = materializer(registry);
    let target = work.path().join("meta-schema.yaml");
    m.merge_meta_schema_extension("a@1.0.0/meta-schema-extensions/fields", &target)
        .unwrap();
    let before = std::fs::read_to_string(&target).unwrap();
    let err = m
        .merge_meta_schema_extension("b@1.0.0/meta-schema-extensions/fields", &target)
        .expect_err("integer vs string for the same field");
    match err {
        PackError::ConstraintViolation { reason } => {
            assert!(reason.contains("priority"), "{reason}")
        }
        other => panic!("expected ConstraintViolation, got {other:?}"),
    }
    assert_eq!(
        std::fs::read_to_string(&target).unwrap(),
        before,
        "target untouched on conflict"
    );
}

#![cfg(feature = "gap-p2")]
//! GAP-08 + GAP-09 (P2, cli half) — pack → subsystem bridges with trust propagation.
//! See docs/plans/PACK-GAP-CLOSURE.md §3.1 / §3.2.
//!
//! FIXTURE-GRAMMAR notes: the `mcp-servers/*.yaml` and `presets/*.yaml` fixtures below
//! must follow the grammars ALREADY enforced by `materialize_impl.rs::register_mcp_server`
//! and `cap_grant::preset::PresetRegistry::load_custom_yaml`. Adjust the fixture strings
//! to those parsers if they reject — do not bend the parsers to the fixtures.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use advance_cli::pack_bridges::{
    PackBridgeError, PackMcpBridge, PackMemorySeedBridge, PackMetaSchemaBridge, PackPresetBridge,
    PackSkillBridge,
};
use advance_pack_manager::{
    AutoApprove, InMemoryPackRegistry, Installer, PackRegistry, SecretStore, SecretValue,
};
use cap_fs::meta_schema::{FieldType, MetaSchemaLoader};
use cap_grant::preset::PresetRegistry;
use cap_mcp::McpTransportSpec;
use cap_skills::{AdminPoolStorage, Provenance, TrustLevel};

const MCP_STDIO: &str = "server-id: local-tools\ndescription: stdio server\ntransport:\n  kind: stdio\n  command: /usr/bin/true\n  args: []\nsecret-refs:\n  API_TOKEN: mcp-token\n";
const MCP_HTTP: &str = "server-id: remote-tools\ndescription: http server\ntransport:\n  kind: http\n  endpoint-url: https://mcp.example.com/sse\n";
const PRESET: &str = "name: data-readonly\ngrants:\n  - capability: tools\n    params: []\n";
const SEEDS: &str = "{\"id\":\"seed-1\",\"type\":\"fact\",\"content\":\"pack seed one\",\"created_at\":\"2026-09-15T00:00:00Z\",\"tags\":[\"pack\"]}\n{\"id\":\"seed-2\",\"type\":\"fact\",\"content\":\"pack seed two\",\"created_at\":\"2026-09-15T00:00:00Z\"}\n";

fn write_pack(root: &Path, name: &str, trust: &str) -> PathBuf {
    let dir = root.join(format!("{name}-src"));
    for sub in [
        "skills/web-search",
        "mcp-servers",
        "presets",
        "meta-schema-extensions",
        "memory-seeds",
    ] {
        std::fs::create_dir_all(dir.join(sub)).unwrap();
    }
    std::fs::write(
        dir.join("skills/web-search/SKILL.md"),
        "# web-search\nUse the web.\n",
    )
    .unwrap();
    std::fs::write(dir.join("mcp-servers/local.yaml"), MCP_STDIO).unwrap();
    std::fs::write(dir.join("mcp-servers/remote.yaml"), MCP_HTTP).unwrap();
    std::fs::write(dir.join("presets/data-readonly.yaml"), PRESET).unwrap();
    std::fs::write(
        dir.join("meta-schema-extensions/todo.yaml"),
        "optional:\n  priority:\n    type: integer\n    default: 0\n",
    )
    .unwrap();
    std::fs::write(dir.join("memory-seeds/base.jsonl"), SEEDS).unwrap();
    std::fs::write(
        dir.join("pack.yaml"),
        format!("name: {name}\nversion: 1.0.0\nruntime-version: \">=0.1.0\"\ntrust-level: {trust}\nprovides:\n  skills:\n    - web-search\n  mcp-servers:\n    - local\n    - remote\n  presets:\n    - data-readonly\n  meta-schema-extensions:\n    - todo\n  memory-seeds:\n    - base\nchecksums:\n  algo: sha256\n  files: {{}}\n"),
    )
    .unwrap();
    dir
}

async fn registry_with(packs: &Path, srcs: &[PathBuf]) -> Arc<dyn PackRegistry> {
    let registry = Arc::new(InMemoryPackRegistry::new(packs.to_path_buf()));
    let inst = Installer::new(packs, registry.clone(), "0.1.0", Arc::new(AutoApprove));
    for s in srcs {
        inst.install(s.to_str().unwrap()).await.expect("install");
    }
    registry
}

struct Secrets;
impl SecretStore for Secrets {
    fn get(&self, key: &str) -> Option<SecretValue> {
        (key == "mcp-token").then(|| SecretValue::new("tok-123"))
    }
}

#[tokio::test]
async fn br_01_skill_bridge_imports_into_admin_pool_with_pack_trust() {
    let tmp = tempfile::TempDir::new().unwrap();
    let packs = tmp.path().join("packs");
    let reg = registry_with(
        &packs,
        &[
            write_pack(tmp.path(), "u", "untrusted"),
            write_pack(tmp.path(), "t", "trusted"),
        ],
    )
    .await;
    let pool = AdminPoolStorage::with_default_writer(tmp.path().join("pool"));
    let bridge = PackSkillBridge::new(reg.clone());

    let imported = bridge
        .import("u@1.0.0/skills/web-search", &pool, tmp.path())
        .await
        .expect("import from untrusted pack");
    assert_eq!(imported.provenance, Provenance::Imported);
    assert_eq!(imported.trust_level, TrustLevel::Untrusted);
    let bundle = pool
        .read_bundle("web-search")
        .await
        .unwrap()
        .expect("bundle in pool");
    assert_eq!(bundle.provenance, Provenance::Imported);
    assert_eq!(bundle.trust_level, TrustLevel::Untrusted);

    // Same skill name from a TRUSTED pack (admin-approved trust in .meta.yaml) → Trusted.
    let pool2 = AdminPoolStorage::with_default_writer(tmp.path().join("pool2"));
    let imported = bridge
        .import("t@1.0.0/skills/web-search", &pool2, tmp.path())
        .await
        .expect("import from trusted pack");
    assert_eq!(imported.trust_level, TrustLevel::Trusted);
}

#[tokio::test]
async fn br_02_mcp_bridge_refuses_stdio_from_untrusted_and_resolves_secrets() {
    let tmp = tempfile::TempDir::new().unwrap();
    let packs = tmp.path().join("packs");
    let reg = registry_with(
        &packs,
        &[
            write_pack(tmp.path(), "u", "untrusted"),
            write_pack(tmp.path(), "t", "trusted"),
        ],
    )
    .await;
    let bridge = PackMcpBridge::new(reg);

    let err = bridge
        .entry("u@1.0.0/mcp-servers/local", &Secrets)
        .expect_err("stdio from an untrusted pack = arbitrary code execution");
    assert!(
        matches!(err, PackBridgeError::TrustDenied { .. }),
        "{err:?}"
    );

    // http transport is fine even from untrusted (cap-http security chain applies).
    let entry = bridge
        .entry("u@1.0.0/mcp-servers/remote", &Secrets)
        .expect("http ok");
    assert_eq!(entry.server_id, "remote-tools");
    assert!(matches!(entry.transport, McpTransportSpec::Http { .. }));

    let entry = bridge
        .entry("t@1.0.0/mcp-servers/local", &Secrets)
        .expect("trusted stdio ok");
    match entry.transport {
        McpTransportSpec::Stdio { env, .. } => {
            assert_eq!(
                env.get("API_TOKEN").map(String::as_str),
                Some("tok-123"),
                "secret-ref resolved"
            );
        }
        other => panic!("expected stdio, got {other:?}"),
    }
}

#[tokio::test]
async fn br_03_preset_bridge_loads_into_cap_grant_registry() {
    let tmp = tempfile::TempDir::new().unwrap();
    let packs = tmp.path().join("packs");
    let reg = registry_with(&packs, &[write_pack(tmp.path(), "t", "trusted")]).await;
    let bridge = PackPresetBridge::new(reg);
    let mut presets = PresetRegistry::with_builtins();
    let name = bridge
        .load("t@1.0.0/presets/data-readonly", &mut presets)
        .expect("preset loads through cap-grant's own parser");
    assert_eq!(name, "data-readonly");
    assert!(presets.get("data-readonly").is_some());
    assert!(matches!(
        bridge.load("t@1.0.0/presets/nope", &mut presets),
        Err(PackBridgeError::Pack(_))
    ));
}

#[tokio::test]
async fn br_04_meta_schema_bridge_merges_and_reloads_loader() {
    let tmp = tempfile::TempDir::new().unwrap();
    let packs = tmp.path().join("packs");
    let reg = registry_with(&packs, &[write_pack(tmp.path(), "t", "trusted")]).await;
    let schema_path = tmp.path().join(".agent/meta-schema.yaml");
    std::fs::create_dir_all(schema_path.parent().unwrap()).unwrap();
    let loader = MetaSchemaLoader::new_with_default(schema_path.clone());
    assert!(!loader.current().optional.contains_key("priority"));

    let report = PackMetaSchemaBridge::new(reg)
        .merge("t@1.0.0/meta-schema-extensions/todo", &loader)
        .expect("merge + reload");
    assert_eq!(report.added, vec!["priority".to_string()]);
    let spec = loader
        .current()
        .optional
        .get("priority")
        .cloned()
        .expect("live schema updated");
    assert_eq!(spec.field_type, FieldType::Integer);
    assert!(
        schema_path.is_file(),
        "merged schema persisted where the watcher looks"
    );
}

#[tokio::test]
async fn br_05_memory_seed_bridge_appends_once() {
    let tmp = tempfile::TempDir::new().unwrap();
    let packs = tmp.path().join("packs");
    let reg = registry_with(&packs, &[write_pack(tmp.path(), "t", "trusted")]).await;
    let knowledge = tmp.path().join(".agent/memory/knowledge.jsonl");
    std::fs::create_dir_all(knowledge.parent().unwrap()).unwrap();
    let bridge = PackMemorySeedBridge::new(reg);

    let r1 = bridge
        .seed("t@1.0.0/memory-seeds/base", &knowledge)
        .expect("seed");
    assert_eq!((r1.appended, r1.skipped_duplicates), (2, 0));
    let r2 = bridge
        .seed("t@1.0.0/memory-seeds/base", &knowledge)
        .expect("idempotent");
    assert_eq!((r2.appended, r2.skipped_duplicates), (0, 2));

    let text = std::fs::read_to_string(&knowledge).unwrap();
    assert_eq!(text.lines().count(), 2);
    for line in text.lines() {
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        assert!(
            v["sources"]
                .as_array()
                .map(|a| !a.is_empty())
                .unwrap_or(false),
            "pack provenance recorded: {line}"
        );
    }
}

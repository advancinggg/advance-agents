//! GAP-08 + GAP-09 (P2, cli half) — pack → subsystem bridges with trust propagation.
//!
//!
//! FIXTURE-GRAMMAR notes: the `mcp-servers/*.yaml` and `presets/*.yaml` fixtures below
//! must follow the grammars ALREADY enforced by `materialize_impl.rs::register_mcp_server`
//! and `cap_grant::preset::PresetRegistry::load_custom_yaml`. Adjust the fixture strings
//! to those parsers if they reject — do not bend the parsers to the fixtures.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use advance_cli::mcp_wiring::stdio_child_env;
use advance_cli::pack_bridges::{
    PackBridgeError, PackMcpBridge, PackMemorySeedBridge, PackMetaSchemaBridge, PackPresetBridge,
    PackSkillBridge,
};
use advance_pack_manager::{
    AutoApprove, InMemoryPackRegistry, Installer, McpTransportDecl, PackError, PackRegistry,
    SecretStore, SecretValue,
};
use cap_fs::meta_schema::{FieldType, MetaSchemaLoader};
use cap_grant::preset::PresetRegistry;
use cap_mcp::McpTransportSpec;
use cap_skills::{AdminPoolStorage, Provenance, TrustLevel};
use ed25519_dalek::{Signer, SigningKey};

/// FIXTURE (P3 §4.1): since lane P3 an unsigned `trust-level: trusted` claim is
/// DOWNGRADED to `untrusted` at install, so a fixture pack is only effectively
/// trusted when its `pack.yaml` is signed by a configured trust root. The
/// "trusted" packs below carry a `pack.sig` from this fixed key and the
/// installer is given its public key as the sole root.
fn trust_root_key() -> SigningKey {
    SigningKey::from_bytes(&[42u8; 32])
}

const MCP_STDIO: &str = "server-id: local-tools\ndescription: stdio server\ntransport:\n  kind: stdio\n  command: /usr/bin/true\n  args: []\nsecret-refs:\n  API_TOKEN: mcp-token\n";
const MCP_HTTP: &str = "server-id: remote-tools\ndescription: http server\ntransport:\n  kind: http\n  endpoint-url: https://mcp.example.com/sse\n";
const MCP_LOOPBACK: &str = "server-id: host-tools\ndescription: http server on the host\ntransport:\n  kind: http\n  endpoint-url: http://127.0.0.1:8931/mcp\n";
const MCP_CREDENTIALED: &str = "server-id: keyed-tools\ndescription: http server with a key\ntransport:\n  kind: http\n  endpoint-url: https://mcp.example.com/mcp\ncredentials:\n  - position: bearer\n    secret: mcp-token\n";
const MCP_ENV: &str = "server-id: env-tools\ndescription: stdio server with literals\ntransport:\n  kind: stdio\n  command: /usr/bin/true\n  env:\n    GREETING: hello\n    PATH: /pack/bin\n  cwd: /srv/env-tools\nsecret-refs:\n  API_TOKEN: mcp-token\n";
// FIXTURE-GRAMMAR: `cap_grant::preset::parse_preset` requires `default-ttl` and a
// per-grant `ttl` (once | lifecycle | persistent | {duration|until}); the plan's
// draft omitted both.
const PRESET: &str = "name: data-readonly\ndefault-ttl: once\ngrants:\n  - capability: tools\n    params: []\n    ttl: once\n";
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
    std::fs::write(dir.join("mcp-servers/loopback.yaml"), MCP_LOOPBACK).unwrap();
    std::fs::write(dir.join("mcp-servers/keyed.yaml"), MCP_CREDENTIALED).unwrap();
    std::fs::write(dir.join("mcp-servers/envy.yaml"), MCP_ENV).unwrap();
    std::fs::write(dir.join("presets/data-readonly.yaml"), PRESET).unwrap();
    std::fs::write(
        dir.join("meta-schema-extensions/todo.yaml"),
        "optional:\n  priority:\n    type: integer\n    default: 0\n",
    )
    .unwrap();
    std::fs::write(dir.join("memory-seeds/base.jsonl"), SEEDS).unwrap();
    let pack_yaml = format!("name: {name}\nversion: 1.0.0\nruntime-version: \">=0.1.0\"\ntrust-level: {trust}\nprovides:\n  skills:\n    - web-search\n  mcp-servers:\n    - local\n    - remote\n    - loopback\n    - keyed\n    - envy\n  presets:\n    - data-readonly\n  meta-schema-extensions:\n    - todo\n  memory-seeds:\n    - base\nchecksums:\n  algo: sha256\n  files: {{}}\n");
    std::fs::write(dir.join("pack.yaml"), &pack_yaml).unwrap();
    if trust == "trusted" {
        let key = trust_root_key();
        let sig = key.sign(pack_yaml.as_bytes());
        std::fs::write(
            dir.join("pack.sig"),
            format!(
                "alg: ed25519\npublic-key: {}\nsignature: {}\n",
                hex::encode(key.verifying_key().to_bytes()),
                hex::encode(sig.to_bytes())
            ),
        )
        .unwrap();
    }
    dir
}

async fn registry_with(packs: &Path, srcs: &[PathBuf]) -> Arc<dyn PackRegistry> {
    let registry = Arc::new(InMemoryPackRegistry::new(packs.to_path_buf()));
    let inst = Installer::new(packs, registry.clone(), "0.1.0", Arc::new(AutoApprove))
        .with_trust_roots(vec![hex::encode(
            trust_root_key().verifying_key().to_bytes(),
        )]);
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

// A pack's http server on loopback is refused, whatever the pack's trust: the host's own
// loopback is reachable only through a server file the operator wrote.
#[tokio::test]
async fn br_02b_mcp_bridge_refuses_a_loopback_endpoint_from_any_pack() {
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

    for pack in ["u", "t"] {
        let err = bridge
            .entry(&format!("{pack}@1.0.0/mcp-servers/loopback"), &Secrets)
            .expect_err("a pack may not reach the host's loopback");
        match err {
            PackBridgeError::Pack(PackError::ConstraintViolation { reason }) => {
                assert!(reason.contains("loopback"), "{reason}");
                assert!(reason.contains("host-tools"), "{reason}");
            }
            other => panic!("{pack}: expected a constraint violation, got {other:?}"),
        }
        // Its other http server is still admitted.
        bridge
            .entry(&format!("{pack}@1.0.0/mcp-servers/remote"), &Secrets)
            .expect("http off loopback");
    }
}

// A pack may not bind cap-secrets credentials to an http server, whatever its trust: the
// bridge refuses such a manifest as an entry and as a registration to persist, while the
// pack's http server without credentials is admitted.
#[tokio::test]
async fn br_02c_mcp_bridge_refuses_credentials_from_any_pack() {
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

    for pack in ["u", "t"] {
        let keyed = format!("{pack}@1.0.0/mcp-servers/keyed");
        let refusals = [
            bridge
                .entry(&keyed, &Secrets)
                .map(|_| ())
                .expect_err("no entry binds a pack's credentials"),
            bridge
                .plan(&keyed, &BTreeMap::new())
                .map(|_| ())
                .expect_err("no registration binds a pack's credentials"),
        ];
        for err in refusals {
            match err {
                PackBridgeError::Pack(PackError::ConstraintViolation { reason }) => {
                    assert!(
                        reason.contains(
                            "pack-origin http servers may not bind cap-secrets credentials"
                        ),
                        "{reason}"
                    );
                    assert!(reason.contains("keyed-tools"), "{reason}");
                    assert!(reason.contains(&format!("{pack}@1.0.0")), "{reason}");
                }
                other => panic!("{pack}: expected a constraint violation, got {other:?}"),
            }
        }
        let registration = bridge
            .plan(
                &format!("{pack}@1.0.0/mcp-servers/remote"),
                &BTreeMap::new(),
            )
            .expect("an http server without credentials");
        assert_eq!(registration.server_id, "remote-tools");
    }
}

// A trusted pack's stdio server carries its `env` literals and working directory: the
// registration a sink persists holds them unchanged, and the entry's environment is built as
// the loader builds an operator server's (the daemon's baseline variables, the literals over
// them, the secrets over both), to run in that directory.
#[tokio::test]
async fn br_02d_mcp_bridge_carries_env_literals_and_the_working_directory() {
    let tmp = tempfile::TempDir::new().unwrap();
    let packs = tmp.path().join("packs");
    let reg = registry_with(&packs, &[write_pack(tmp.path(), "t", "trusted")]).await;
    let bridge = PackMcpBridge::new(reg);
    let literals = BTreeMap::from([
        ("GREETING".to_string(), "hello".to_string()),
        ("PATH".to_string(), "/pack/bin".to_string()),
    ]);

    let registration = bridge
        .plan("t@1.0.0/mcp-servers/envy", &BTreeMap::new())
        .expect("a trusted pack's stdio server");
    assert_eq!(
        registration.transport,
        McpTransportDecl::Stdio {
            command: "/usr/bin/true".into(),
            args: vec![],
            env: literals.clone(),
            cwd: Some("/srv/env-tools".into()),
        }
    );
    assert_eq!(
        registration.secret_refs,
        BTreeMap::from([("API_TOKEN".to_string(), "mcp-token".to_string())])
    );

    let entry = bridge
        .entry("t@1.0.0/mcp-servers/envy", &Secrets)
        .expect("a trusted pack's stdio server");
    match entry.transport {
        McpTransportSpec::Stdio { env, cwd, .. } => {
            assert_eq!(cwd, Some(PathBuf::from("/srv/env-tools")));
            assert_eq!(
                env,
                stdio_child_env(
                    std::env::vars_os(),
                    &literals,
                    [("API_TOKEN".to_string(), "tok-123".to_string())]
                )
            );
            assert_eq!(env.get("PATH").map(String::as_str), Some("/pack/bin"));
            assert_eq!(env.get("GREETING").map(String::as_str), Some("hello"));
            assert_eq!(env.get("API_TOKEN").map(String::as_str), Some("tok-123"));
        }
        other => panic!("expected stdio, got {other:?}"),
    }
}

// A workflow step's secret named as one of the manifest's `env` literals is refused, as a
// registration to persist and as an entry: a variable of the server's environment is either a
// literal or a secret.
#[tokio::test]
async fn br_02e_mcp_bridge_refuses_a_step_secret_named_as_an_env_literal() {
    let tmp = tempfile::TempDir::new().unwrap();
    let packs = tmp.path().join("packs");
    let reg = registry_with(&packs, &[write_pack(tmp.path(), "t", "trusted")]).await;
    let bridge = PackMcpBridge::new(reg);

    let refusals = [
        bridge
            .plan(
                "t@1.0.0/mcp-servers/envy",
                &BTreeMap::from([("GREETING".to_string(), "mcp-token".to_string())]),
            )
            .map(|_| ())
            .expect_err("a step's secret named as a literal"),
        bridge
            .entry_with_env(
                "t@1.0.0/mcp-servers/envy",
                &Secrets,
                &BTreeMap::from([("GREETING".to_string(), SecretValue::new("tok-456"))]),
            )
            .map(|_| ())
            .expect_err("a step's secret named as a literal"),
    ];
    for err in refusals {
        match err {
            PackBridgeError::Pack(PackError::ConstraintViolation { reason }) => {
                assert!(
                    reason.contains("GREETING") && reason.contains("env literal"),
                    "{reason}"
                );
            }
            other => panic!("expected a constraint violation, got {other:?}"),
        }
    }

    // Under a name of its own, the step's secret is merged in.
    let registration = bridge
        .plan(
            "t@1.0.0/mcp-servers/envy",
            &BTreeMap::from([("EXTRA_TOKEN".to_string(), "mcp-token".to_string())]),
        )
        .expect("a step's secret under a name of its own");
    assert_eq!(
        registration
            .secret_refs
            .get("EXTRA_TOKEN")
            .map(String::as_str),
        Some("mcp-token")
    );
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

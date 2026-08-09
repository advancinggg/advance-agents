//! Slice BS-1 (2026-06-01) — wiring smoke for the remaining cap-* providers +
//! real master key, registered by `advance_cli::wiring::wire_capabilities`.
//!
//! Verifies **MODULE-012-AC-16** (capabilities registered into the host fn
//! table via M001 HostRegistry / CapabilityInjector at startup; injection only
//! for declared capabilities) plus the master-key placeholder closure (the
//! `[0u8; 32]` → real env-var-sourced key; smoke-tested, NOT AC-credited —
//! AC-17 stays deferred per MODULE-012 §3.6).
//!
//! - BS1-T01 (AC-16): all 7 declared caps registered, each under its namespace.
//! - BS1-T02 (AC-16): capability-gated — only the declared cap is present.
//! - BS1-T03/T04/T05/T07: master-key positive / unset-fails / invalid-hex /
//!   non-default-env-var-name (proves the placeholder is gone + the config
//!   field is consulted).
//! - BS1-T06 (AC-16): post-build cap-tools registration is visible.
//! - BS1-T08 (AC-16): `CapabilityInjector::inject` links a pre-build (`secrets`)
//!   AND a post-build (`tools`) capability at L0 (the slice's top-risk path).

use std::path::PathBuf;

use advance_cli::wiring::{wire_capabilities, CliWiringError};
use advance_runtime::bootstrap::RuntimeHostBuilder;
use advance_runtime::ComponentCtx;
use advance_shared_types::capability::{CapRequest, CapabilityId};

/// 64 hex chars = 32 bytes — a valid master key for `load_master_key`.
const VALID_KEY_HEX: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

// Per-test env-var names (distinct so no test contends on a shared var).
const MK_MAIN: &str = "ADV_BS1_MK_MAIN"; // set → valid
const MK_BADHEX: &str = "ADV_BS1_MK_BADHEX"; // set → invalid hex
const MK_CUSTOM: &str = "ADV_BS1_MK_CUSTOM"; // set → valid (non-default name)
const MK_UNSET: &str = "ADV_BS1_MK_UNSET"; // never set

/// All 7 cap-* capabilities declared active.
const ALL_CAPS: &str = "\
capabilities:
  secrets: true
  fs: true
  tools: true
  skills: true
  memory: true
  grant: true
  llm: true
";

const ONLY_SECRETS: &str = "capabilities:\n  secrets: true\n";

/// Set the test env vars exactly once for this binary. `std::sync::Once` runs
/// the writes on a single thread (others block), so there is no concurrent env
/// mutation; subsequent `wire_capabilities` access is read-only. SAFETY:
/// `std::env::set_var` / `remove_var` are safe in edition 2021.
fn ensure_test_env() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        std::env::set_var(MK_MAIN, VALID_KEY_HEX);
        std::env::set_var(MK_CUSTOM, VALID_KEY_HEX);
        std::env::set_var(MK_BADHEX, "not-valid-hex");
        std::env::remove_var(MK_UNSET); // guarantee absent
    });
}

/// `runtime-config.yaml` with the given `secrets.master-key-source` +
/// `env-var-name`. One valid `llm-providers` entry so cap-llm has a usable
/// provider config and `RuntimeConfigWatcher::new` validation passes.
fn runtime_yaml(master_key_source: &str, env_var_name: &str) -> String {
    format!(
        r#"wasm:
  max_memory_pages: 1024
  epoch_interruption_ms: 100
  fuel_enabled: false

llm-providers:
  - id: anthropic
    endpoint: https://api.anthropic.com
    api-key-secret: anthropic-api-key
    model-aliases:
      sonnet: claude-sonnet-4-5
    cost-per-mtoken-in: 3.00
    cost-per-mtoken-out: 15.00
    rate-limit:
      requests-per-minute: 1000
      tokens-per-minute: 400000

cron:
  max_jitter_ratio: 0.1

git:
  gc_interval_hours: 24
  max_tracked_file_mb: 10

secrets:
  master-key-source: {master_key_source}
  env-var-name: {env_var_name}

post-processor:
  llm-model: sonnet-light
  llm-failure-cooldown-seconds: 600

database:
  db-path: ".runtime/index.db"
  pool-size: 4
"#
    )
}

/// Tempdir workspace with `.advance/runtime-config.yaml` + `.runtime/events/jsonl`
/// + `.agent/` and (optionally) `.agent/config.yaml`.
fn fresh_workspace(yaml: &str, agent_caps: Option<&str>) -> (tempfile::TempDir, PathBuf, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let workspace = std::fs::canonicalize(dir.path()).expect("canonicalize");
    std::fs::create_dir_all(workspace.join(".advance")).unwrap();
    std::fs::create_dir_all(workspace.join(".runtime/events/jsonl")).unwrap();
    std::fs::create_dir_all(workspace.join(".agent")).unwrap();
    let config_path = workspace.join(".advance/runtime-config.yaml");
    std::fs::write(&config_path, yaml).unwrap();
    if let Some(caps) = agent_caps {
        std::fs::write(workspace.join(".agent/config.yaml"), caps).unwrap();
    }
    (dir, workspace, config_path)
}

/// BS1-T01 (AC-16): every declared capability is registered under its namespace.
#[tokio::test(flavor = "multi_thread")]
async fn bs1_t01_all_capabilities_registered() {
    ensure_test_env();
    let yaml = runtime_yaml("env-var", MK_MAIN);
    let (_g, ws, cfg) = fresh_workspace(&yaml, Some(ALL_CAPS));
    let builder = RuntimeHostBuilder::new(&cfg, &ws).await.expect("builder");
    let (host, _h) = wire_capabilities(builder, &ws).await.expect("wire");

    let reg = host.host_registry();
    for (cap, ns) in [
        ("secrets", "advance:runtime/agent-secrets@0.1.0"),
        ("fs", "advance:runtime/agent-fs@0.1.0"),
        ("tools", "advance:runtime/agent-tools@0.1.0"),
        ("skills", "advance:runtime/agent-skills@0.1.0"),
        ("memory", "advance:runtime/agent-memory@0.1.0"),
        ("grant", "advance:runtime/agent-grant@0.1.0"),
        ("llm", "advance:runtime/agent-llm@0.1.0"),
    ] {
        let specs = reg.lookup(cap);
        assert!(
            !specs.is_empty(),
            "BS1-T01: capability `{cap}` must be registered when declared active; got empty"
        );
        assert!(
            specs.iter().all(|s| s.namespace == ns),
            "BS1-T01: `{cap}` specs must use namespace `{ns}`; got: {specs:?}"
        );
    }
}

/// BS1-T02 (AC-16): only the declared capability is registered; the rest are
/// absent (capability-gated injection — the "not present when undeclared" half
/// of AC-16).
#[tokio::test(flavor = "multi_thread")]
async fn bs1_t02_capability_gated_registration() {
    ensure_test_env();
    let yaml = runtime_yaml("env-var", MK_MAIN);
    let (_g, ws, cfg) = fresh_workspace(&yaml, Some(ONLY_SECRETS));
    let builder = RuntimeHostBuilder::new(&cfg, &ws).await.expect("builder");
    let (host, _h) = wire_capabilities(builder, &ws).await.expect("wire");

    let reg = host.host_registry();
    assert!(
        !reg.lookup("secrets").is_empty(),
        "BS1-T02: declared `secrets` must be present"
    );
    for cap in ["fs", "tools", "skills", "memory", "grant", "llm"] {
        assert!(
            reg.lookup(cap).is_empty(),
            "BS1-T02: undeclared `{cap}` must be ABSENT (capability-gated); got: {:?}",
            reg.lookup(cap)
        );
    }
}

/// BS1-T03: a valid 64-hex env-var master key → wire succeeds (positive path).
#[tokio::test(flavor = "multi_thread")]
async fn bs1_t03_master_key_env_var_positive() {
    ensure_test_env();
    let yaml = runtime_yaml("env-var", MK_MAIN);
    let (_g, ws, cfg) = fresh_workspace(&yaml, Some(ONLY_SECRETS));
    let builder = RuntimeHostBuilder::new(&cfg, &ws).await.expect("builder");
    let res = wire_capabilities(builder, &ws).await;
    assert!(
        res.is_ok(),
        "BS1-T03: valid 64-hex env-var key → wire Ok; got: {:?}",
        res.err().map(|e| e.to_string())
    );
}

/// BS1-T04: master-key env var UNSET → wire fails closed with
/// `CliWiringError::MasterKey`. Proves the Slice-AG `[0u8; 32]` placeholder is
/// GONE (the old code succeeded regardless of the env).
#[tokio::test(flavor = "multi_thread")]
async fn bs1_t04_master_key_unset_fails_closed() {
    ensure_test_env();
    let yaml = runtime_yaml("env-var", MK_UNSET);
    let (_g, ws, cfg) = fresh_workspace(&yaml, Some(ONLY_SECRETS));
    let builder = RuntimeHostBuilder::new(&cfg, &ws).await.expect("builder");
    let err = wire_capabilities(builder, &ws)
        .await
        .err()
        .expect("BS1-T04: missing master-key env var must fail wiring (placeholder is gone)");
    assert!(
        matches!(err, CliWiringError::MasterKey(_)),
        "BS1-T04: expected CliWiringError::MasterKey; got: {err}"
    );
}

/// BS1-T05: env var set to invalid (non-hex) → wire fails with
/// `CliWiringError::MasterKey` (delegates to `load_master_key`'s 64-hex check).
#[tokio::test(flavor = "multi_thread")]
async fn bs1_t05_master_key_invalid_hex_fails() {
    ensure_test_env();
    let yaml = runtime_yaml("env-var", MK_BADHEX);
    let (_g, ws, cfg) = fresh_workspace(&yaml, Some(ONLY_SECRETS));
    let builder = RuntimeHostBuilder::new(&cfg, &ws).await.expect("builder");
    let err = wire_capabilities(builder, &ws)
        .await
        .err()
        .expect("BS1-T05: invalid-hex master key must fail wiring");
    assert!(
        matches!(err, CliWiringError::MasterKey(_)),
        "BS1-T05: expected CliWiringError::MasterKey; got: {err}"
    );
}

/// BS1-T06 (AC-16): cap-tools is registered POST-build (its engine handle only
/// exists after `build()`); both `tool-invoke` + `list-tools` are present,
/// proving the post-build registration into the shared registry is visible.
#[tokio::test(flavor = "multi_thread")]
async fn bs1_t06_post_build_tools_registered() {
    ensure_test_env();
    let yaml = runtime_yaml("env-var", MK_MAIN);
    let (_g, ws, cfg) = fresh_workspace(&yaml, Some(ALL_CAPS));
    let builder = RuntimeHostBuilder::new(&cfg, &ws).await.expect("builder");
    let (host, _h) = wire_capabilities(builder, &ws).await.expect("wire");

    let specs = host.host_registry().lookup("tools");
    let names: std::collections::HashSet<&str> = specs.iter().map(|s| s.name.as_str()).collect();
    assert!(
        names.contains("tool-invoke"),
        "BS1-T06: post-build cap-tools `tool-invoke` must be registered; got: {names:?}"
    );
    assert!(
        names.contains("list-tools"),
        "BS1-T06: post-build cap-tools `list-tools` must be registered; got: {names:?}"
    );
}

/// BS1-T07: a NON-default `secrets.env-var-name` is honoured (the default
/// `SECRETS_MASTER_KEY` is unset in this binary; success proves
/// `wire_capabilities` reads the config field, not a hard-coded name).
#[tokio::test(flavor = "multi_thread")]
async fn bs1_t07_non_default_env_var_name_honored() {
    ensure_test_env();
    let yaml = runtime_yaml("env-var", MK_CUSTOM);
    let (_g, ws, cfg) = fresh_workspace(&yaml, Some(ONLY_SECRETS));
    let builder = RuntimeHostBuilder::new(&cfg, &ws).await.expect("builder");
    let res = wire_capabilities(builder, &ws).await;
    assert!(
        res.is_ok(),
        "BS1-T07: custom env-var-name must be consulted → wire Ok; got: {:?}",
        res.err().map(|e| e.to_string())
    );
}

/// BS1-T08 (AC-16): `CapabilityInjector::inject` links host fns at L0 for BOTH
/// a pre-build capability (`secrets`) and the POST-build `tools` capability —
/// witnessing AC-16's "registered via CapabilityInjector" at the linker layer
/// (not just the registry-data layer), including the slice's top-risk
/// post-build-registration-visible-to-the-built-injector path.
#[tokio::test(flavor = "multi_thread")]
async fn bs1_t08_l0_inject_pre_and_post_build_caps() {
    ensure_test_env();
    let yaml = runtime_yaml("env-var", MK_MAIN);
    let (_g, ws, cfg) = fresh_workspace(&yaml, Some(ALL_CAPS));
    let builder = RuntimeHostBuilder::new(&cfg, &ws).await.expect("builder");
    let (host, _h) = wire_capabilities(builder, &ws).await.expect("wire");

    let runtime = host.component_runtime();
    // Single-expression engine borrow (binding the handle to a `let` would drop
    // the temporary while borrowed — same as T-AG-05).
    let mut linker =
        wasmtime::component::Linker::<ComponentCtx>::new(runtime.host_engine_handle().engine());
    let caps = vec![
        CapRequest {
            capability: CapabilityId::new("secrets"),
        },
        CapRequest {
            capability: CapabilityId::new("tools"),
        },
    ];
    let result = host.capability_injector().inject(&mut linker, &caps);
    assert!(
        result.is_ok(),
        "BS1-T08: inject for declared `secrets` (pre-build) + `tools` (post-build) must succeed at L0; got: {result:?}"
    );
}

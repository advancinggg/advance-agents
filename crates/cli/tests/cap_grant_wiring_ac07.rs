//! Slice AG (2026-05-11) — MODULE-001-AC-07 verification: `auto-grant: false`
//! → host fn linked at L0, no persistent Grant at L1.
//!
//! AC-07 is verified by the conjunction T-AG-01 ∧ T-AG-02 ∧ T-AG-03 ∧ T-AG-05.
//! T-AG-04 is graceful-degradation (missing `.agent/config.yaml`).

use std::path::PathBuf;
use std::sync::Arc;

use advance_cli::wiring::wire_capabilities;
use advance_runtime::bootstrap::RuntimeHostBuilder;
use advance_shared_types::capability::{CapParams, CapRequest, CapabilityId, GrantDecision};

const MINIMAL_RUNTIME_YAML: &str = "\
wasm:
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
  master-key-source: env-var
  env-var-name: SECRETS_MASTER_KEY

post-processor:
  llm-model: sonnet-light
  llm-failure-cooldown-seconds: 600

database:
  db-path: \".runtime/index.db\"
  pool-size: 4
";

/// Slice BS-1 (2026-06-01): `wire_capabilities` now loads a REAL master key
/// (replacing the `[0u8; 32]` placeholder) whenever `secrets`/`llm` is declared
/// active. The fixture's `master-key-source` is now `env-var`, so the
/// secrets-active tests below (T-AG-01/02/03/05) must provide a valid 64-hex
/// `SECRETS_MASTER_KEY` or `wire_capabilities` returns `CliWiringError::MasterKey`.
/// 64 hex chars = 32 bytes.
const TEST_MASTER_KEY_HEX: &str =
    "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

/// Set `SECRETS_MASTER_KEY` exactly once for this test binary (the value is
/// constant + valid, so a single process-wide set is safe). `std::sync::Once`
/// runs the set on one thread with all other threads blocked, so there is no
/// concurrent env mutation; subsequent access during `wire_capabilities` is
/// read-only. Called by every secrets-active test before wiring. T-AG-04 (no
/// `.agent/config.yaml` → `needs_key == false`) does NOT call it and never reads
/// the env var. SAFETY: `std::env::set_var` is safe in edition 2021.
fn ensure_test_master_key() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| std::env::set_var("SECRETS_MASTER_KEY", TEST_MASTER_KEY_HEX));
}

/// Build a tempdir workspace with `.advance/runtime-config.yaml` + `.runtime/`
/// scaffolding + `.runtime/events/jsonl/` + a per-test `.agent/config.yaml`
/// payload.
fn fresh_workspace_with_agent_config(
    agent_caps_yaml: &str,
) -> (tempfile::TempDir, PathBuf, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let workspace = std::fs::canonicalize(dir.path()).expect("canonicalize");
    std::fs::create_dir_all(workspace.join(".advance")).unwrap();
    std::fs::create_dir_all(workspace.join(".runtime")).unwrap();
    std::fs::create_dir_all(workspace.join(".runtime/events/jsonl")).unwrap();
    std::fs::create_dir_all(workspace.join(".agent")).unwrap();
    let config_path = workspace.join(".advance/runtime-config.yaml");
    std::fs::write(&config_path, MINIMAL_RUNTIME_YAML).unwrap();
    let agent_path = workspace.join(".agent/config.yaml");
    std::fs::write(&agent_path, agent_caps_yaml).unwrap();
    (dir, workspace, config_path)
}

/// Workspace with NO `.agent/config.yaml` (T-AG-04 fixture).
fn fresh_workspace_without_agent_config() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let workspace = std::fs::canonicalize(dir.path()).expect("canonicalize");
    std::fs::create_dir_all(workspace.join(".advance")).unwrap();
    std::fs::create_dir_all(workspace.join(".runtime")).unwrap();
    std::fs::create_dir_all(workspace.join(".runtime/events/jsonl")).unwrap();
    let config_path = workspace.join(".advance/runtime-config.yaml");
    std::fs::write(&config_path, MINIMAL_RUNTIME_YAML).unwrap();
    (dir, workspace, config_path)
}

#[tokio::test(flavor = "multi_thread")]
async fn t_ag_01_auto_grant_false_ac_07_verifier() {
    ensure_test_master_key();
    let (_guard, ws, cfg) =
        fresh_workspace_with_agent_config("capabilities:\n  secrets:\n    auto-grant: false\n");
    let builder = RuntimeHostBuilder::new(&cfg, &ws).await.expect("builder");
    let (host, handles) = wire_capabilities(builder, &ws).await.expect("wire");

    // L0 assertion: cap-secrets host fn IS registered in HostRegistry —
    // not just SOME spec, but the EXACT cap-secrets spec shape
    // (capability `secrets` + namespace `advance:runtime/agent-secrets@0.1.0` +
    // name `secret-exists` + idempotent `true`).
    //
    // Adversarial R1 Codex W1 fix: lookup("secrets").is_empty() alone is
    // too weak — a wrong namespace or wrong function name would still pass.
    // Adversarial R2 Codex W1 fix: pin `idempotent: true` as an extra
    // identity signal so a spec registered with the right strings but the
    // wrong idempotency contract would also fail this assertion.
    //
    // Scope note: this is identity-by-metadata; the conjunction does NOT
    // invoke the registered handler (no guest WASM exists in this slice;
    // handler-execution coverage is delegated to future MODULE-005 /
    // MODULE-006 scheduler slices that ship guest invocation). The
    // conjunction T-AG-01 ∧ T-AG-02 ∧ T-AG-03 ∧ T-AG-05 covers identity +
    // Linker-binding + GrantCheck both deny & allow paths, which is the
    // strongest evidence a wiring-only slice can produce.
    let secrets_specs = host.host_registry().lookup("secrets");
    let cap_secrets_spec = secrets_specs.iter().find(|s| {
        s.capability == "secrets"
            && s.namespace == "advance:runtime/agent-secrets@0.1.0"
            && s.name == "secret-exists"
            && s.idempotent
    });
    assert!(
        cap_secrets_spec.is_some(),
        "AC-07 L0: cap-secrets host fn (capability=`secrets`, namespace=`advance:runtime/agent-secrets@0.1.0`, name=`secret-exists`, idempotent=true) must be linked when YAML declares `secrets: {{ auto-grant: false }}`; got specs: {secrets_specs:?}"
    );

    // L1 assertion: cap-grant GrantStore has 0 active grants for "secrets".
    let grants = handles.cap_grant.store.list_by_grantee("default-agent");
    let secrets_grants: Vec<_> = grants
        .iter()
        .filter(|g| g.capability == "secrets")
        .collect();
    assert_eq!(
        secrets_grants.len(),
        0,
        "AC-07 L1: no persistent Grant for `auto-grant: false` cap; got: {secrets_grants:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn t_ag_02_positive_control_auto_grant_true_creates_grant() {
    ensure_test_master_key();
    let (_guard, ws, cfg) = fresh_workspace_with_agent_config("capabilities:\n  secrets: true\n");
    let builder = RuntimeHostBuilder::new(&cfg, &ws).await.expect("builder");
    let (host, handles) = wire_capabilities(builder, &ws).await.expect("wire");

    // L0 assertion: host fn registered (same strict shape as T-AG-01 —
    // capability + namespace + name + idempotent invariants per
    // Adversarial R1 W1 + R2 W1).
    let secrets_specs = host.host_registry().lookup("secrets");
    let cap_secrets_spec = secrets_specs.iter().find(|s| {
        s.capability == "secrets"
            && s.namespace == "advance:runtime/agent-secrets@0.1.0"
            && s.name == "secret-exists"
            && s.idempotent
    });
    assert!(
        cap_secrets_spec.is_some(),
        "Positive control L0: cap-secrets host fn (capability=`secrets`, namespace=`advance:runtime/agent-secrets@0.1.0`, name=`secret-exists`, idempotent=true) must be linked when YAML declares `secrets: true`; got specs: {secrets_specs:?}"
    );

    // L1 assertion: exactly 1 active Grant for "secrets" (this is the
    // load-bearing positive-control check that catches the silent-cap-drop
    // failure mode — without this, T-AG-01 could pass for the wrong reason).
    let grants = handles.cap_grant.store.list_by_grantee("default-agent");
    let secrets_grants: Vec<_> = grants
        .iter()
        .filter(|g| g.capability == "secrets")
        .collect();
    assert_eq!(
        secrets_grants.len(),
        1,
        "Positive control L1: `secrets: true` must produce exactly 1 active Grant; got: {secrets_grants:?}"
    );

    // Positive-control Allow assertion (Adversarial R1 Codex W2 fix): when
    // `secrets: true` produces a persistent Grant, the production
    // `GrantCheckImpl.check(...)` MUST return `Allow` for the same
    // (agent, capability, function) tuple — the symmetric counterpart to
    // T-AG-03's Deny check. Without this, T-AG-02 could pass even if the
    // GrantCheck were wired wrong for the `true` case.
    let decision = host.grant_check().check(
        "default-agent",
        "secrets",
        "secret-exists",
        &CapParams::empty(),
    );
    match decision {
        GrantDecision::Allow => {
            // expected
        }
        other => panic!(
            "Positive control: expected Allow from production GrantCheckImpl on `secrets: true`; got: {other:?}"
        ),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn t_ag_03_production_grant_check_wired_not_stub() {
    ensure_test_master_key();
    let (_guard, ws, cfg) =
        fresh_workspace_with_agent_config("capabilities:\n  secrets:\n    auto-grant: false\n");
    let builder = RuntimeHostBuilder::new(&cfg, &ws).await.expect("builder");
    let (host, handles) = wire_capabilities(builder, &ws).await.expect("wire");

    // Identity check: host.grant_check() must be pointer-identical to the
    // Arc threaded into RuntimeHostBuilder::build via wire_capabilities.
    // This catches the case where wire_capabilities accidentally kept the
    // AllowAllGrantCheck stub.
    assert!(
        Arc::ptr_eq(&host.grant_check(), &handles.cap_grant.grant_check),
        "T-AG-03 wiring identity: host.grant_check() must be the cap-grant Arc"
    );

    // Behaviour check: with no Grant for "secrets" (auto-grant: false),
    // the wired GrantCheckImpl must return Deny — proving the production
    // GrantCheckImpl is wired in (AllowAllGrantCheck would return Allow).
    let decision = host.grant_check().check(
        "default-agent",
        "secrets",
        "secret-exists",
        &CapParams::empty(),
    );
    match decision {
        GrantDecision::Deny(reason) => {
            assert!(
                reason.contains("secrets") || reason.contains("no active grant"),
                "T-AG-03 deny reason should mention `secrets` or `no active grant`: {reason}"
            );
        }
        other => panic!("T-AG-03: expected Deny from production GrantCheckImpl, got: {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn t_ag_04_missing_agent_config_graceful_degradation() {
    let (_guard, ws, cfg) = fresh_workspace_without_agent_config();
    let builder = RuntimeHostBuilder::new(&cfg, &ws).await.expect("builder");
    let result = wire_capabilities(builder, &ws).await;
    let (host, handles) = match result {
        Ok(pair) => pair,
        Err(e) => panic!(
            "T-AG-04: wire_capabilities must succeed when `.agent/config.yaml` is absent (graceful degradation); got error: {e}"
        ),
    };

    // cap-grant store must be empty for the default agent (no static config
    // to compile from).
    let grants = handles.cap_grant.store.list_by_grantee("default-agent");
    assert!(
        grants.is_empty(),
        "T-AG-04: cap-grant store should be empty when `.agent/config.yaml` is absent; got: {grants:?}"
    );

    // cap-secrets registration SKIPPED via the conditional gate
    // (yaml_declares_active_capability returns false on missing file).
    assert!(
        host.host_registry().lookup("secrets").is_empty(),
        "T-AG-04: cap-secrets registration must be SKIPPED when YAML is absent"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn t_ag_05_l0_inject_links_secrets_host_fn_into_linker() {
    ensure_test_master_key();
    let (_guard, ws, cfg) =
        fresh_workspace_with_agent_config("capabilities:\n  secrets:\n    auto-grant: false\n");
    let builder = RuntimeHostBuilder::new(&cfg, &ws).await.expect("builder");
    let (host, _handles) = wire_capabilities(builder, &ws).await.expect("wire");

    // T-AG-05: exercise the strict-Linker reading of "linked at L0".
    // Per wit_dispatch::T42, the `advance-host` world has zero function
    // imports today, so calling `inject` on a Linker constructed from
    // `host_engine` doesn't wire anything into an actual guest's
    // instantiation path. What `inject` DOES exercise is:
    //   (a) HostRegistry::lookup("secrets") returns >= 1 spec,
    //   (b) Linker::instance("advance:runtime/agent-secrets@0.1.0") succeeds,
    //   (c) LinkerInstance::func_new_async("secret-exists", closure) succeeds.
    // This is the strict reading of "linked at L0" that Codex Round-1
    // Critical asked for.
    //
    // Plan-Eval R2 Claude-Warning 1: use single-expression form for
    // `host.component_runtime().host_engine_handle().engine()` — binding
    // the handle to a `let` would fail with "temporary value dropped while
    // borrowed" because `host_engine_handle()` returns by value.
    use advance_runtime::ComponentCtx;
    let runtime = host.component_runtime();
    let mut linker =
        wasmtime::component::Linker::<ComponentCtx>::new(runtime.host_engine_handle().engine());
    let caps = vec![CapRequest {
        capability: CapabilityId::new("secrets"),
    }];
    let result = host.capability_injector().inject(&mut linker, &caps);
    assert!(
        result.is_ok(),
        "T-AG-05 strict L0 link: inject must succeed for declared `secrets` cap; got: {result:?}"
    );
}

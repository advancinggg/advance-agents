//! MODULE-012-AC-15 — secret-exists caller-dependency gate, PRODUCTION wiring
//! (Wave-18 Lane-3). Witnesses that the cli composition root
//! (`register_secrets_capability`) builds a real `DeclaredDependencyPolicy` from
//! the `secrets.dependencies` config map and registers the GATED `secret-exists`
//! handler over the REAL production caller identity (`HostCallContext.agent_id`,
//! the bare `default-agent` stamped at `start.rs:776`).
//!
//! - T15h: `build_secrets_dependency_policy` config→policy mapping (unit; pins
//!   the Vec→HashSet conversion + `Some` iff non-empty + fail-closed semantics).
//! - T15i: PRODUCTION reject path through the real `wire_capabilities` — a
//!   declared caller passes, an undeclared agent / undeclared name are denied.
//! - T15j: default-permissive (no `secrets.dependencies`) = byte-identical
//!   regression — the gate is operator-opt-in.

use advance_cli::wiring::{build_secrets_dependency_policy, wire_capabilities};
use advance_runtime::bootstrap::RuntimeHostBuilder;
use advance_runtime::config::{MasterKeySource, SecretsConfig};
use advance_runtime::host_registry::HostCallContext;
use std::collections::HashMap;
use std::path::PathBuf;
use wasmtime::component::Val;

const SECRETS_NS: &str = "advance:runtime/agent-secrets@0.1.0";
/// 64 hex chars = 32 bytes, the EnvVar master-key shape.
const MASTER_KEY_HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// Runtime-config YAML with a configurable `secrets:` block. `env_var_name` is
/// per-test so concurrent tests never collide on the process-global env, and
/// `dependencies_yaml` is spliced verbatim (empty string ⇒ no `dependencies`
/// key ⇒ the default-permissive path).
fn runtime_yaml(env_var_name: &str, dependencies_yaml: &str) -> String {
    format!(
        "\
wasm:
  max_memory_pages: 1024
  epoch_interruption_ms: 100
  fuel_enabled: false

llm-providers: []

cron:
  max_jitter_ratio: 0.1

git:
  gc_interval_hours: 24
  max_tracked_file_mb: 10

secrets:
  master-key-source: env-var
  env-var-name: {env_var_name}
{dependencies_yaml}
post-processor:
  llm-model: sonnet-light
  llm-failure-cooldown-seconds: 600

database:
  db-path: \".runtime/index.db\"
  pool-size: 4
"
    )
}

/// Materialize a tempdir workspace with `.advance/runtime-config.yaml` +
/// `.runtime/` scaffolding + a `secrets`-declaring `.agent/config.yaml`.
fn fresh_secrets_workspace(runtime_yaml: &str) -> (tempfile::TempDir, PathBuf, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let workspace = std::fs::canonicalize(dir.path()).expect("canonicalize");
    std::fs::create_dir_all(workspace.join(".advance")).unwrap();
    std::fs::create_dir_all(workspace.join(".runtime")).unwrap();
    std::fs::create_dir_all(workspace.join(".runtime/events/jsonl")).unwrap();
    std::fs::create_dir_all(workspace.join(".agent")).unwrap();
    let config_path = workspace.join(".advance/runtime-config.yaml");
    std::fs::write(&config_path, runtime_yaml).unwrap();
    std::fs::write(
        workspace.join(".agent/config.yaml"),
        "capabilities:\n  secrets: true\n",
    )
    .unwrap();
    (dir, workspace, config_path)
}

fn secret_exists_ctx(agent_id: &str) -> HostCallContext {
    HostCallContext {
        agent_id: agent_id.to_string(),
        trace_id: "tr-t15".to_string(),
        turn_id: None,
        capability: "secrets".to_string(),
        function: "advance:runtime/agent-secrets::secret-exists".to_string(),
        run_id: None,
        iteration: None,
    }
}

/// T15h — `build_secrets_dependency_policy` config→policy mapping. A non-empty
/// `dependencies` map yields `Some(policy)` that permits the declared
/// `(agent, secret)` pair and fail-closes on every other name / unknown agent;
/// an empty map yields `None` (selects the permissive handler).
#[test]
fn t15h_build_policy_maps_config_to_declared_policy() {
    // Empty → None (the operator-opt-in default; permissive handler).
    let empty = SecretsConfig {
        master_key_source: MasterKeySource::EnvVar,
        env_var_name: "X".into(),
        dependencies: HashMap::new(),
    };
    assert!(
        build_secrets_dependency_policy(&empty).is_none(),
        "empty dependencies map must yield None (permissive handler selected)"
    );

    // Non-empty → Some(policy) with the declared allowlist semantics.
    let mut deps = HashMap::new();
    deps.insert("default-agent".to_string(), vec!["api_key".to_string()]);
    let configured = SecretsConfig {
        master_key_source: MasterKeySource::EnvVar,
        env_var_name: "X".into(),
        dependencies: deps,
    };
    let policy = build_secrets_dependency_policy(&configured)
        .expect("non-empty dependencies map must yield Some(policy)");

    assert!(
        policy.permits(&secret_exists_ctx("default-agent"), "api_key"),
        "declared (default-agent, api_key) pair must be permitted"
    );
    assert!(
        !policy.permits(&secret_exists_ctx("default-agent"), "other"),
        "an undeclared NAME must be denied (Vec→HashSet membership)"
    );
    assert!(
        !policy.permits(&secret_exists_ctx("other-agent"), "api_key"),
        "an unknown AGENT must fail closed (HashMap miss)"
    );
}

/// T15i — PRODUCTION reject path. With `secrets.dependencies: {default-agent:
/// [api_key]}`, the real `wire_capabilities` registers the GATED handler; the
/// declared caller passes; an undeclared agent and an undeclared name are both
/// denied with `permission-denied`.
///
/// WITNESS-FLOOR DISCLOSURE: this drives the REAL production registration
/// (`wire_capabilities` → `register_secrets_capability` → the gated handler over a
/// `DeclaredDependencyPolicy`), but invokes the registered handler with a
/// HAND-CONSTRUCTED `HostCallContext` rather than through the Wasmtime
/// `CapabilityInjector` closure. The production injector stamps
/// `ctx.agent_id = "default-agent"` (the bare cap id at `start.rs:776` →
/// `agent_loop.rs` `ComponentCtx::new` → `capability_injector.rs`
/// `to_host_call_context`) — a host-owned value a guest cannot influence; that
/// stamping is exercised by every SUT/daemon-boot path (e.g. `messaging_wiring_b2`
/// admits the bare `default-agent` caller). So the binding between this test's
/// `"default-agent"` key and the real production identity is sound; the per-call
/// `CapabilityInjector` lift is the only leg this unit witness does not itself
/// re-drive (same sanctioned stand-in posture as `sys_j55_notify_agent`'s
/// `ctx.agent_id="system"` stamp). REQ-183 is a `unit`-verification REQ.
#[tokio::test(flavor = "multi_thread")]
async fn t15i_production_gate_rejects_undeclared_caller_and_name() {
    let env_var = "SECRETS_MASTER_KEY_T15I";
    std::env::set_var(env_var, MASTER_KEY_HEX);
    let deps_yaml = "  dependencies:\n    default-agent:\n      - api_key\n";
    let (_g, ws, cfg) = fresh_secrets_workspace(&runtime_yaml(env_var, deps_yaml));

    let builder = RuntimeHostBuilder::new(&cfg, &ws).await.expect("builder");
    let (host, _handles) = wire_capabilities(builder, &ws).await.expect("wire");

    let spec = host
        .host_registry()
        .lookup("secrets")
        .into_iter()
        .find(|s| s.namespace == SECRETS_NS && s.name == "secret-exists")
        .expect("secrets declared ⇒ secret-exists must be registered");
    let handler = spec.handler.clone();

    // (a) the DECLARED caller (default-agent, api_key) is PERMITTED → it reaches
    //     the storage probe and returns a bool (the store is empty ⇒ false). The
    //     point is the Ok(Bool) shape — the gate did NOT reject.
    let out = handler
        .call(
            secret_exists_ctx("default-agent"),
            vec![Val::String("api_key".into())],
            1,
        )
        .await
        .expect("permitted call should succeed");
    match &out[0] {
        Val::Result(Ok(Some(inner))) => match inner.as_ref() {
            Val::Bool(_) => {}
            other => panic!("expected Ok(Bool), got {other:?}"),
        },
        other => panic!("declared caller must be permitted (Ok(Bool)), got {other:?}"),
    }

    // (b) an UNDECLARED agent → permission-denied (fail-closed HashMap miss).
    assert_permission_denied(
        &handler
            .call(
                secret_exists_ctx("other-agent"),
                vec![Val::String("api_key".into())],
                1,
            )
            .await
            .expect("rejected call returns the error in-band"),
        "unknown agent_id must be denied",
    );

    // (c) the declared agent + an UNDECLARED name → permission-denied.
    assert_permission_denied(
        &handler
            .call(
                secret_exists_ctx("default-agent"),
                vec![Val::String("not_declared".into())],
                1,
            )
            .await
            .expect("rejected call returns the error in-band"),
        "undeclared secret name must be denied",
    );
}

/// T15j — default-permissive regression. With NO `secrets.dependencies` key,
/// `register_secrets_capability` selects the permissive handler, so ANY caller's
/// `secret-exists` is allowed (Ok(Bool)) — byte-identical to pre-Wave-18. The
/// gate is operator-opt-in: absence of config must never start denying probes.
#[tokio::test(flavor = "multi_thread")]
async fn t15j_no_config_is_permissive_regression() {
    let env_var = "SECRETS_MASTER_KEY_T15J";
    std::env::set_var(env_var, MASTER_KEY_HEX);
    // No `dependencies:` key at all.
    let (_g, ws, cfg) = fresh_secrets_workspace(&runtime_yaml(env_var, ""));

    let builder = RuntimeHostBuilder::new(&cfg, &ws).await.expect("builder");
    let (host, _handles) = wire_capabilities(builder, &ws).await.expect("wire");

    let handler = host
        .host_registry()
        .lookup("secrets")
        .into_iter()
        .find(|s| s.namespace == SECRETS_NS && s.name == "secret-exists")
        .expect("secret-exists registered")
        .handler
        .clone();

    // An ARBITRARY caller (not in any allowlist — there is none) is permitted.
    let out = handler
        .call(
            secret_exists_ctx("any-uncontrolled-agent"),
            vec![Val::String("whatever".into())],
            1,
        )
        .await
        .expect("permissive handler call should succeed");
    match &out[0] {
        Val::Result(Ok(Some(inner))) => match inner.as_ref() {
            Val::Bool(_) => {}
            other => panic!("expected Ok(Bool), got {other:?}"),
        },
        other => {
            panic!("no-config default must be permissive (Ok(Bool) for any caller), got {other:?}")
        }
    }
}

fn assert_permission_denied(out: &[Val], ctx: &str) {
    match &out[0] {
        Val::Result(Err(Some(boxed))) => match boxed.as_ref() {
            Val::Variant(case, _) => assert_eq!(
                case, "permission-denied",
                "{ctx}: expected secret-error::permission-denied, got variant `{case}`"
            ),
            other => panic!("{ctx}: expected a secret-error variant, got {other:?}"),
        },
        other => panic!("{ctx}: expected Result(Err(permission-denied)), got {other:?}"),
    }
}

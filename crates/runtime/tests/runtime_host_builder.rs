//! Slice AG (2026-05-11) — `RuntimeHostBuilder` surface tests.
//!
//! T71 happy-path `RuntimeHostBuilder::new` on tempdir + valid YAML.
//! T72 `build()` injects custom `Arc<dyn GrantCheck>` (Arc::ptr_eq identity).
//! T73 `host_registry()` + `circuit_breaker_bus()` Arc identity preserved
//!     across the `build()` boundary.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use advance_runtime::RuntimeHostBuilder;
use advance_shared_types::capability::{CapParams, GrantDecision};
use advance_shared_types::traits::GrantCheck;
use wasmtime::component::Val;

const MINIMAL_VALID_YAML: &str = "\
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
  master-key-source: keychain
  env-var-name: SECRETS_MASTER_KEY

post-processor:
  llm-model: sonnet-light
  llm-failure-cooldown-seconds: 600

database:
  db-path: \".runtime/index.db\"
  pool-size: 4
";

fn fresh_workspace() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let workspace = std::fs::canonicalize(dir.path()).expect("canonicalize");
    std::fs::create_dir_all(workspace.join(".advance")).unwrap();
    std::fs::create_dir_all(workspace.join(".runtime")).unwrap();
    let config_path = workspace.join(".advance").join("runtime-config.yaml");
    std::fs::write(&config_path, MINIMAL_VALID_YAML).unwrap();
    (dir, workspace, config_path)
}

/// AlwaysDeny `GrantCheck` mock for T72. Identity-stable via `Arc::ptr_eq`.
#[derive(Debug)]
struct AlwaysDenyGrantCheck;

impl GrantCheck for AlwaysDenyGrantCheck {
    fn check(
        &self,
        _agent_id: &str,
        capability: &str,
        _function: &str,
        _params: &CapParams,
    ) -> GrantDecision {
        GrantDecision::Deny(format!("AlwaysDenyGrantCheck: no grant for {capability}"))
    }
}

#[tokio::test]
async fn t71_runtime_host_builder_new_happy_path() {
    let (_guard, workspace, config_path) = fresh_workspace();
    let builder = RuntimeHostBuilder::new(&config_path, &workspace)
        .await
        .expect("RuntimeHostBuilder::new");

    // Pre-build accessors return populated state.
    assert!(builder.config().wasm.max_memory_pages > 0);
    assert_eq!(builder.workspace_root(), workspace.as_path());
    assert!(builder.sqlite_index_handle().schema_version() > 0);

    // host_registry empty at construction (no host fns registered yet).
    assert!(builder.host_registry().lookup("nonexistent").is_empty());
}

#[tokio::test]
async fn t72_build_injects_custom_grant_check() {
    let (_guard, workspace, config_path) = fresh_workspace();
    let builder = RuntimeHostBuilder::new(&config_path, &workspace)
        .await
        .expect("RuntimeHostBuilder::new");

    // Inject a custom GrantCheck. Arc::ptr_eq verifies pointer identity:
    // the SAME Arc allocation flows from build() → host.grant_check().
    let custom: Arc<dyn GrantCheck> = Arc::new(AlwaysDenyGrantCheck);
    let custom_clone = custom.clone();
    let host = builder.build(custom).expect("build");
    assert!(
        Arc::ptr_eq(&host.grant_check(), &custom_clone),
        "host.grant_check() must pointer-equal the injected Arc",
    );

    // Behaviour check: the injected GrantCheck is the one being called.
    let decision = host
        .grant_check()
        .check("agent-x", "fs", "fs::read", &CapParams::empty());
    match decision {
        GrantDecision::Deny(reason) => {
            assert!(
                reason.contains("AlwaysDenyGrantCheck"),
                "deny reason must come from the injected mock: {reason}",
            );
        }
        other => panic!("expected Deny from injected mock, got: {other:?}"),
    }
}

#[tokio::test]
async fn t73_builder_arc_identity_preserved_across_build() {
    let (_guard, workspace, config_path) = fresh_workspace();
    let builder = RuntimeHostBuilder::new(&config_path, &workspace)
        .await
        .expect("RuntimeHostBuilder::new");

    // Save Arc clones from pre-build accessors.
    let pre_registry = builder.host_registry();
    let pre_breaker = builder.circuit_breaker_bus();
    let pre_config_watcher = builder.config_watcher();
    let pre_sqlite = builder.sqlite_index_handle();
    let pre_recall = builder.recall();
    let pre_unified_search = builder.unified_search();

    // Consume the builder by `build()`.
    let stub: Arc<dyn GrantCheck> = Arc::new(AlwaysDenyGrantCheck);
    let host = builder.build(stub).expect("build");

    // Pointer identity is preserved for the 6 fields the builder
    // owned and moved into the final RuntimeHost.
    assert!(
        Arc::ptr_eq(&pre_registry, &host.host_registry()),
        "host_registry Arc identity must be stable across build"
    );
    assert!(
        Arc::ptr_eq(&pre_breaker, &host.circuit_breaker_bus()),
        "circuit_breaker_bus Arc identity must be stable across build"
    );
    assert!(
        Arc::ptr_eq(&pre_config_watcher, &host.config_watcher()),
        "config_watcher Arc identity must be stable across build"
    );
    assert!(
        Arc::ptr_eq(&pre_sqlite, &host.sqlite_index_handle()),
        "sqlite_index_handle Arc identity must be stable across build"
    );
    assert!(
        Arc::ptr_eq(&pre_recall, &host.recall()),
        "recall Arc identity must be stable across build"
    );
    assert!(
        Arc::ptr_eq(&pre_unified_search, &host.unified_search()),
        "unified_search Arc identity must be stable across build"
    );
}

// Force `Future` + `Pin` + `Val` imports to be referenced (silences
// dead-code warnings on cfg-gated test files in some toolchains).
#[allow(dead_code)]
fn _unused_imports() {
    let _: Option<Pin<Box<dyn Future<Output = Val> + Send>>> = None;
}

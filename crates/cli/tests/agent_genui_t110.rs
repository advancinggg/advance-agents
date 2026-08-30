//! MODULE-001-T110 — composition-root flag off / flag on (T110-6 / T110-7).

use std::path::PathBuf;

use advance_cli::wiring::wire_capabilities;
use advance_runtime::bootstrap::RuntimeHostBuilder;
use advance_runtime::ComponentCtx;
use advance_shared_types::capability::{CapRequest, CapabilityId};

const VALID_KEY_HEX: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
const MK_GENUI: &str = "ADV_T110_MK_GENUI";

fn ensure_test_env() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        std::env::set_var(MK_GENUI, VALID_KEY_HEX);
    });
}

fn runtime_yaml(extra_genui: &str) -> String {
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
  master-key-source: env-var
  env-var-name: {MK_GENUI}

post-processor:
  llm-model: sonnet-light
  llm-failure-cooldown-seconds: 600

database:
  db-path: ".runtime/index.db"
  pool-size: 4
{extra_genui}"#
    )
}

fn fresh_workspace(yaml: &str) -> (tempfile::TempDir, PathBuf, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let workspace = std::fs::canonicalize(dir.path()).expect("canonicalize");
    std::fs::create_dir_all(workspace.join(".advance")).unwrap();
    std::fs::create_dir_all(workspace.join(".runtime/events/jsonl")).unwrap();
    std::fs::create_dir_all(workspace.join(".agent")).unwrap();
    let config_path = workspace.join(".advance/runtime-config.yaml");
    std::fs::write(&config_path, yaml).unwrap();
    std::fs::write(
        workspace.join(".agent/config.yaml"),
        "capabilities:\n  secrets: true\n",
    )
    .unwrap();
    (dir, workspace, config_path)
}

#[tokio::test(flavor = "multi_thread")]
async fn t110_6_wire_capabilities_default_runtime_yaml_no_genui() {
    ensure_test_env();
    let yaml = runtime_yaml("");
    let (_g, ws, cfg) = fresh_workspace(&yaml);
    let builder = RuntimeHostBuilder::new(&cfg, &ws).await.expect("builder");
    let (host, _h) = wire_capabilities(builder, &ws).await.expect("wire");
    assert!(
        host.host_registry().lookup("genui").is_empty(),
        "default-off: lookup(genui) must be empty"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn t110_7_wire_capabilities_flag_on_register_and_inject() {
    ensure_test_env();
    let yaml = runtime_yaml("genui:\n  enabled: true\n");
    let (_g, ws, cfg) = fresh_workspace(&yaml);
    let builder = RuntimeHostBuilder::new(&cfg, &ws).await.expect("builder");
    let (host, _h) = wire_capabilities(builder, &ws).await.expect("wire");

    let specs = host.host_registry().lookup("genui");
    assert_eq!(specs.len(), 1);
    assert_eq!(specs[0].name, "emit-document");
    assert_eq!(specs[0].namespace, "advance:runtime/agent-genui@0.1.0");

    let runtime = host.component_runtime();
    let mut linker =
        wasmtime::component::Linker::<ComponentCtx>::new(runtime.host_engine_handle().engine());
    let caps = vec![CapRequest {
        capability: CapabilityId::new("genui"),
    }];
    host.capability_injector()
        .inject(&mut linker, &caps)
        .expect("inject CapRequest{{genui}} when flag on");
}

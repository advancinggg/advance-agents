//! MODULE-005-AC-29 (T46) — production-wiring witness for the `knowledge.jsonl`
//! producer-boundary guard.
//!
//! Drives the REAL production composition root `advance_cli::wiring::wire_capabilities`
//! (the same fn the daemon boots through) and proves the guard is LIVE: over a workspace
//! containing a real `report.txt`, a guest `remember(report.txt bytes)` is REJECTED at
//! the production memory handler, while a genuine insight is accepted and persisted.
//! REQ-211 is enforced end-to-end (best-effort ceiling per MODULE-005 §3.8).
//!
//! The system-acceptance `sys_j20`/`sys_j21` harness registers memory directly via
//! `register_agent_memory_with_git` (policy = None), so it does NOT exercise the
//! CLI-injected policy — this is the sole CLI-injection witness. Mirrors the
//! `wiring_memory_persist.rs` production-composition-root precedent.

use std::path::PathBuf;

use advance_cli::wiring::wire_capabilities;
use advance_runtime::bootstrap::RuntimeHostBuilder;
use advance_runtime::host_registry::HostCallContext;
use cap_memory::{CAPABILITY, NAMESPACE};
use wasmtime::component::Val;

fn runtime_yaml() -> String {
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
  env-var-name: ADV_PBTEST_MK_UNUSED

post-processor:
  llm-model: sonnet-light
  llm-failure-cooldown-seconds: 600

database:
  db-path: ".runtime/index.db"
  pool-size: 4
"#
    .to_string()
}

const MEMORY_ONLY_CAPS: &str = "capabilities:\n  memory: true\n";

/// A workspace whose root holds a real `report.txt` (≥512 B) — the file-dump target.
fn workspace_with_report() -> (tempfile::TempDir, PathBuf, PathBuf, String) {
    let dir = tempfile::tempdir().expect("tempdir");
    let workspace = std::fs::canonicalize(dir.path()).expect("canonicalize");
    std::fs::create_dir_all(workspace.join(".advance")).unwrap();
    std::fs::create_dir_all(workspace.join(".runtime/events/jsonl")).unwrap();
    std::fs::create_dir_all(workspace.join(".agent")).unwrap();
    let config_path = workspace.join(".advance/runtime-config.yaml");
    std::fs::write(&config_path, runtime_yaml()).unwrap();
    std::fs::write(workspace.join(".agent/config.yaml"), MEMORY_ONLY_CAPS).unwrap();
    // The real working file an agent must NOT dump verbatim into knowledge.jsonl.
    let file_content = "The quarterly report shows revenue up 12% across all regions. ".repeat(16);
    assert!(file_content.len() >= 512);
    std::fs::write(workspace.join("report.txt"), file_content.as_bytes()).unwrap();
    (dir, workspace, config_path, file_content)
}

fn ctx_for(agent: &str) -> HostCallContext {
    HostCallContext {
        agent_id: agent.to_string(),
        trace_id: "trace-pbwire".to_string(),
        turn_id: None,
        capability: CAPABILITY.to_string(),
        function: format!("{NAMESPACE}::remember"),
        run_id: None,
        iteration: None,
    }
}

/// Drive the production-registered `remember` handler; return the raw result Val.
async fn remember_raw(host: &advance_runtime::RuntimeHost, agent: &str, content: &str) -> Vec<Val> {
    let spec = host
        .host_registry()
        .lookup(CAPABILITY)
        .into_iter()
        .find(|s| s.namespace == NAMESPACE && s.name == "remember")
        .expect("production wire_capabilities registered the memory `remember` host fn");
    spec.handler
        .call(
            ctx_for(agent),
            vec![Val::String(content.into()), Val::List(vec![])],
            1,
        )
        .await
        .expect("remember handler call ok")
}

#[tokio::test(flavor = "multi_thread")]
async fn ac_29_production_wiring_rejects_file_bytes_accepts_insight() {
    let (_g, ws, cfg, file_content) = workspace_with_report();

    let builder = RuntimeHostBuilder::new(&cfg, &ws).await.expect("builder");
    let (host, handles) = wire_capabilities(builder, &ws).await.expect("wire");

    // A guest that copies the whole workspace file's bytes into remember() is REJECTED
    // by the production-wired producer-boundary guard.
    let rejected = remember_raw(&host, "default-agent", &file_content).await;
    match &rejected[0] {
        Val::Result(Err(Some(payload))) => match payload.as_ref() {
            Val::Variant(name, inner) => {
                assert_eq!(
                    name, "storage-error",
                    "producer-boundary reject lowers to storage-error"
                );
                assert!(
                    matches!(inner.as_deref(), Some(Val::String(s)) if s.contains("report.txt")),
                    "the reject reason names the duplicated workspace file"
                );
            }
            other => panic!("expected Variant, got {other:?}"),
        },
        other => panic!("file-byte remember must be rejected in production, got {other:?}"),
    }

    // A genuine insight is accepted and persisted.
    let accepted = remember_raw(
        &host,
        "default-agent",
        "Cross-file insight: the retry loop double-counts tokens under contention.",
    )
    .await;
    assert!(
        matches!(&accepted[0], Val::Result(Ok(_))),
        "a genuine insight is accepted in production, got {:?}",
        accepted[0]
    );

    drop(host);
    drop(handles);
}

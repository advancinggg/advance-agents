//! /dev slice backbone-step3 — MODULE-011-AC-39 production-binding witness.
//!
//! Drives the REAL production composition root `advance_cli::wiring::wire_capabilities`
//! (the same fn the daemon calls at `commands/start.rs:213`) and proves that with
//! `memory` declared, the cap-memory store is rooted at the literal `<ws>/.agent/memory`
//! and persists a `remember` to per-agent `knowledge.jsonl` that survives the
//! host/store dropping (a restart analogue) — bound to the literal `.agent/memory/`
//! path, NOT a bare tempdir. AC-39's three clauses:
//!   (a) `.agent/memory/` binding across restart — remember via the production-
//!       registered handler, then re-open `<ws>/.agent/memory` and recall it;
//!   (b) per-agent scoping / no cross-agent leakage — two agents write distinct
//!       entries; each recall returns ONLY the queried agent's entry;
//!   (c) fresh agent starts empty — a brand-new dir re-opens empty.
//!
//! Witness class = integration test (AC-39 §1.5). This exercises the `wire_capabilities`
//! library composition root, not a full daemon boot; the daemon reuses the identical
//! `wire_capabilities`, whose boot-safety is covered by `wiring_bs1.rs`.
//!
//! The memory `remember` is driven via the registered handler's
//! `HostFunctionHandler::call(ctx, params, 1)` (results_len=1 — the cap-memory handlers
//! require it). This is below-the-handler-boundary store durability, not a grant/identity
//! property, so the direct handler call is a faithful persistence witness.

use std::path::PathBuf;

use advance_cli::wiring::wire_capabilities;
use advance_runtime::bootstrap::RuntimeHostBuilder;
use advance_runtime::host_registry::HostCallContext;
use cap_memory::{MemoryStore, CAPABILITY, DEFAULT_MAX_ACTIVE_PER_AGENT, NAMESPACE};
use wasmtime::component::Val;

/// Minimal valid `runtime-config.yaml` (mirrors `wiring_bs1.rs::runtime_yaml`). The
/// `secrets.master-key-source` is never consulted: declaring only `memory` leaves
/// `needs_key = false`, so `load_real_master_key` is never called.
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
  env-var-name: ADV_MEMTEST_MK_UNUSED

post-processor:
  llm-model: sonnet-light
  llm-failure-cooldown-seconds: 600

database:
  db-path: ".runtime/index.db"
  pool-size: 4
"#
    .to_string()
}

/// `.agent/config.yaml` declaring ONLY the memory capability active.
const MEMORY_ONLY_CAPS: &str = "capabilities:\n  memory: true\n";

fn fresh_workspace() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let workspace = std::fs::canonicalize(dir.path()).expect("canonicalize");
    std::fs::create_dir_all(workspace.join(".advance")).unwrap();
    std::fs::create_dir_all(workspace.join(".runtime/events/jsonl")).unwrap();
    std::fs::create_dir_all(workspace.join(".agent")).unwrap();
    let config_path = workspace.join(".advance/runtime-config.yaml");
    std::fs::write(&config_path, runtime_yaml()).unwrap();
    std::fs::write(workspace.join(".agent/config.yaml"), MEMORY_ONLY_CAPS).unwrap();
    (dir, workspace, config_path)
}

fn ctx_for(agent: &str) -> HostCallContext {
    HostCallContext {
        agent_id: agent.to_string(),
        trace_id: "trace-memtest".to_string(),
        turn_id: None,
        capability: CAPABILITY.to_string(),
        function: format!("{NAMESPACE}::remember"),
        run_id: None,
        iteration: None,
    }
}

/// Drive the production-registered `remember` handler for `agent` with `content`.
async fn remember(host: &advance_runtime::RuntimeHost, agent: &str, content: &str) {
    let spec = host
        .host_registry()
        .lookup(CAPABILITY)
        .into_iter()
        .find(|s| s.namespace == NAMESPACE && s.name == "remember")
        .expect("production wire_capabilities registered the memory `remember` host fn");
    let params = vec![Val::String(content.into()), Val::List(vec![])];
    let out = spec
        .handler
        .call(ctx_for(agent), params, 1)
        .await
        .expect("remember handler call ok");
    match &out[0] {
        Val::Result(Ok(_)) => {}
        other => panic!("remember for {agent} should succeed, got {other:?}"),
    }
}

/// `true` iff any per-agent subdir under `root` contains a `knowledge.jsonl` file.
fn knowledge_jsonl_present(root: &std::path::Path) -> bool {
    let Ok(rd) = std::fs::read_dir(root) else {
        return false;
    };
    for entry in rd.flatten() {
        let p = entry.path();
        if p.is_dir() && p.join("knowledge.jsonl").is_file() {
            return true;
        }
    }
    false
}

#[tokio::test(flavor = "multi_thread")]
async fn ac_39_production_memory_persists_under_agent_memory_across_restart() {
    let (_g, ws, cfg) = fresh_workspace();

    // Production composition root: wire the real cap-memory store rooted at
    // <ws>/.agent/memory via the same path the daemon boots through.
    {
        let builder = RuntimeHostBuilder::new(&cfg, &ws).await.expect("builder");
        let (host, handles) = wire_capabilities(builder, &ws).await.expect("wire");

        // Two agents write DISTINCT entries through the production-registered handler.
        remember(&host, "default-agent", "durable-prod-binding").await;
        remember(&host, "other-agent", "other-secret-xyz").await;

        // The literal on-disk file landed under <ws>/.agent/memory.
        let mem_root = ws.join(".agent").join("memory");
        assert!(
            knowledge_jsonl_present(&mem_root),
            "AC-39(a): production wiring rooted knowledge.jsonl under {}",
            mem_root.display()
        );

        // Drop the host AND the WiringHandles (which hold the EventBus + git queue)
        // BEFORE re-opening the store, so nothing contends on the workspace.
        drop(host);
        drop(handles);
    }

    // Restart analogue: a FRESH MemoryStore over the SAME .agent/memory dir hydrates
    // the persisted entries from knowledge.jsonl.
    let mem_root = ws.join(".agent").join("memory");
    let reopened = MemoryStore::open(&mem_root, DEFAULT_MAX_ACTIVE_PER_AGENT)
        .expect("re-open production memory dir");

    // (a) across-restart binding: default-agent's entry survived.
    assert!(
        !reopened.recall("default-agent", "durable", 10).is_empty(),
        "AC-39(a): default-agent's memory persisted under .agent/memory across restart"
    );

    // (b) per-agent scoping / no cross-agent leakage (non-degenerate — BOTH agents wrote):
    //   - default-agent's query hits ONLY its own bucket;
    //   - other-agent never wrote "durable" → empty for that query;
    //   - other-agent's own entry is recall-able under other-agent;
    //   - default-agent never wrote "other-secret" → empty for that query.
    assert!(
        reopened.recall("other-agent", "durable", 10).is_empty(),
        "AC-39(b): other-agent has no 'durable' entry (no cross-agent leakage)"
    );
    assert!(
        !reopened
            .recall("other-agent", "other-secret", 10)
            .is_empty(),
        "AC-39(b): other-agent recalls its OWN entry"
    );
    assert!(
        reopened
            .recall("default-agent", "other-secret", 10)
            .is_empty(),
        "AC-39(b): default-agent has no 'other-secret' entry (no cross-agent leakage)"
    );

    // (c) fresh agent starts empty: a brand-new .agent/memory dir hydrates to empty.
    let fresh = tempfile::tempdir().expect("fresh tempdir");
    let fresh_store = MemoryStore::open(
        fresh.path().join(".agent").join("memory"),
        DEFAULT_MAX_ACTIVE_PER_AGENT,
    )
    .expect("open fresh memory dir");
    assert!(
        fresh_store
            .recall("default-agent", "durable", 10)
            .is_empty(),
        "AC-39(c): a freshly-opened .agent/memory dir starts empty"
    );
}

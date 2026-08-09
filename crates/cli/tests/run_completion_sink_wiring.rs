//! Wave-24 `req270-sink` — production COMPOSITION witness (anti-fake-green) for
//! CONTRACT-184 `RunCompletionSink`.
//!
//! Guards the claim that `wire_capabilities` (the `advance start` composition root,
//! `crates/cli/src/wiring.rs`) actually COMPOSES the `ComponentResolutionSink` into
//! the production `RunManager` — NOT merely that the sink type exists (the
//! built-but-unwired fake-green class). The discriminator: the parked
//! `ComponentFinished` await is resolved by driving a REAL `complete_run` over the
//! SAME `handles.run_manager` that `wiring.rs` attached the sink to (via
//! `handles.await_manager`, the same composition-root `AwaitSessionManagerImpl` the
//! sink wraps) — a test-constructed `RunManager` would NOT resolve it.
//!
//! HONEST scope (this is a COMPOSITION witness, not a production-reachability one):
//! it proves the sink is attached at the composition root. It does NOT prove a
//! shipped-daemon path drives it — the component-completion driver is unbuilt,
//! a submitted component creates no `RunManager` run, and the auto-settle
//! `complete_run` callsite is behind a dormant session registry (its colon
//! `auto:{agent}` task_ids would also short-circuit). Thus REQ-270 stays Partial
//! (MODULE-007 §3.6:1099/:1100).

use std::sync::Arc;
use std::time::Duration;

use advance_cli::wiring::wire_capabilities;
use advance_reply_tracker::{AwaitSessionManager, AwaitSessionManagerImpl};
use advance_run_manager::RunConfig;
use advance_runtime::bootstrap::RuntimeHostBuilder;
use advance_shared_types::await_session::{
    AwaitMode, AwaitOptions, AwaitRequest, ComponentAwaitRequest, ReplyStatus, TimeoutPolicy,
};

const MINIMAL_RUNTIME_YAML: &str = "\
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
  env-var-name: SECRETS_MASTER_KEY

post-processor:
  llm-model: sonnet-light
  llm-failure-cooldown-seconds: 600

database:
  db-path: \".runtime/index.db\"
  pool-size: 4
";

const TEST_MASTER_KEY_HEX: &str =
    "102132435465768798a9bacbdcedfe0f102132435465768798a9bacbdcedfe0f";

fn ensure_test_master_key() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| std::env::set_var("SECRETS_MASTER_KEY", TEST_MASTER_KEY_HEX));
}

fn fresh_workspace(
    agent_caps_yaml: &str,
) -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
    ensure_test_master_key();
    let dir = tempfile::tempdir().expect("tempdir");
    let workspace = std::fs::canonicalize(dir.path()).expect("canonicalize");
    std::fs::create_dir_all(workspace.join(".advance")).unwrap();
    std::fs::create_dir_all(workspace.join(".runtime")).unwrap();
    std::fs::create_dir_all(workspace.join(".runtime/events/jsonl")).unwrap();
    std::fs::create_dir_all(workspace.join(".agent")).unwrap();
    let config_path = workspace.join(".advance/runtime-config.yaml");
    std::fs::write(&config_path, MINIMAL_RUNTIME_YAML).unwrap();
    std::fs::write(workspace.join(".agent/config.yaml"), agent_caps_yaml).unwrap();
    (dir, workspace, config_path)
}

fn component_req(component_id: &str) -> AwaitRequest {
    AwaitRequest::ComponentFinished(ComponentAwaitRequest {
        component_id: component_id.to_string(),
        correlation_id: format!("corr-{component_id}"),
    })
}

fn allof() -> AwaitOptions {
    AwaitOptions {
        mode: AwaitMode::AllOf,
        idle_timeout_secs: None,
        on_idle_timeout: TimeoutPolicy::ReturnPartial,
        keep_losers: false,
    }
}

/// Deterministically wait until `start()` has registered its session (parked) — a
/// real signal with a bounded deadline, not a fixed scheduler-yield budget.
async fn wait_until_parked<T>(
    manager: &AwaitSessionManagerImpl,
    start_handle: &tokio::task::JoinHandle<T>,
    expected: usize,
) {
    if tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if manager.session_count_for_test().await == expected {
                return;
            }
            assert!(
                !start_handle.is_finished(),
                "start() terminated before registering the parked session"
            );
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .is_err()
    {
        panic!(
            "wait_until_parked: expected {expected} registered session(s), got {}",
            manager.session_count_for_test().await
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn composition_root_sink_resolves_a_parked_component_finished() {
    let (_g, ws, cfg) = fresh_workspace("capabilities:\n  messaging: true\n");
    let builder = RuntimeHostBuilder::new(&cfg, &ws).await.expect("builder");
    let (_host, handles) = wire_capabilities(builder, &ws)
        .await
        .expect("wire_capabilities");

    // The composition root exposes the messaging await manager (declares_messaging),
    // which is the SAME instance the composed RunCompletionSink wraps.
    let manager = handles
        .await_manager
        .clone()
        .expect("messaging ⇒ await_manager is Some at the composition root");

    // Park a real ComponentFinished await on the composition-root manager.
    let mgr = Arc::clone(&manager);
    let start_handle = tokio::spawn(async move {
        mgr.start("controller", vec![component_req("comp-root")], allof())
            .await
    });
    wait_until_parked(&manager, &start_handle, 1).await;
    assert!(
        !start_handle.is_finished(),
        "the await must be parked before the run completes"
    );

    // Drive a REAL production complete_run over the SAME composition-root RunManager
    // that wiring.rs attached the sink to — the anti-fake-green discriminator (a
    // test-constructed RunManager would not resolve the composition-root await).
    let run_id = handles
        .run_manager
        .ensure_run("comp-root", "comp-root", RunConfig::default())
        .expect("ensure_run over the composition-root RunManager");
    handles
        .run_manager
        .complete_run(&run_id, "done".to_string())
        .expect("complete_run fires the composed RunCompletionSink");

    // The composed sink resolves the parked await status-only / empty-payload (§2.3).
    let result = tokio::time::timeout(Duration::from_secs(5), start_handle)
        .await
        .expect("await resolved within 5s via the composition-root sink")
        .expect("start task did not panic")
        .expect("start returned Ok(AwaitResult)");
    assert_eq!(result.replies.len(), 1, "one slot");
    assert_eq!(
        result.replies[0].source, "component:comp-root",
        "source = component:{{id}}"
    );
    assert_eq!(
        result.replies[0].status,
        ReplyStatus::Completed,
        "marked completed"
    );
    assert!(
        result.replies[0].payload.is_empty(),
        "STATUS-ONLY per §2.3 — payload MUST be empty, got {} bytes",
        result.replies[0].payload.len()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn non_messaging_daemon_exposes_no_await_manager() {
    // A no-messaging agent exposes no await manager. This guards the prerequisite
    // used by the current composition gate; it does not introspect RunManager's
    // private optional sink field.
    let (_g, ws, cfg) = fresh_workspace("capabilities:\n  fs: true\n");
    let builder = RuntimeHostBuilder::new(&cfg, &ws).await.expect("builder");
    let (_host, handles) = wire_capabilities(builder, &ws)
        .await
        .expect("wire_capabilities");
    assert!(
        handles.await_manager.is_none(),
        "no messaging ⇒ no composition-root await manager exposed"
    );
}

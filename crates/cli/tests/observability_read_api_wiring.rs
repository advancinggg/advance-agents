//! MODULE-019-AC-23 / CONTRACT-185 — PRODUCTION composition witnesses (T89, T90).
//!
//! These pin that the `ObservabilityReadApi` returned by the real
//! `wire_capabilities` composition root reads the SAME production `EventBus` the
//! root registered — NOT a SUT self-assembly:
//!
//! - **T89** (positive): `WiringHandles.observability_read_api` is `Some`; an
//!   event emitted through the wired `event_bus_dyn` is delivered to a
//!   subscription taken from that handle, and is also queryable from the
//!   persisted store.
//! - **T90** (negative identity discriminator): a SEPARATE standalone bus's read
//!   api receives NOTHING when events are emitted to the wired bus, while the
//!   wired handle receives them — proving identity binding, refuting a fake that
//!   would receive from any bus.
//!
//! ZERO ledger flips here beyond the AC-23 SUMMARY flip these witness.

use std::sync::Arc;
use std::time::Duration;

use advance_cli::wiring::wire_capabilities;
use advance_event_bus::{EventBus, EventBusConfig, EventFilter, ReadCursor, ReadNext};
use advance_runtime::bootstrap::RuntimeHostBuilder;
use advance_shared_types::chrono::Utc;
use advance_shared_types::event::Event;
use serde_json::json;

fn runtime_yaml() -> String {
    r#"wasm:
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
  env-var-name: ADV_READAPI_MK_UNUSED

post-processor:
  llm-model: sonnet-light
  llm-failure-cooldown-seconds: 600

database:
  db-path: ".runtime/index.db"
  pool-size: 4
"#
    .to_string()
}

fn fresh_workspace() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let workspace = std::fs::canonicalize(dir.path()).expect("canonicalize");
    std::fs::create_dir_all(workspace.join(".advance")).unwrap();
    std::fs::create_dir_all(workspace.join(".runtime/events/jsonl")).unwrap();
    std::fs::create_dir_all(workspace.join(".agent")).unwrap();
    let config_path = workspace.join(".advance/runtime-config.yaml");
    std::fs::write(&config_path, runtime_yaml()).unwrap();
    std::fs::write(
        workspace.join(".agent/config.yaml"),
        "capabilities:\n  fs: true\n",
    )
    .unwrap();
    (dir, workspace, config_path)
}

fn ev(id: &str, event_type: &str) -> Event {
    Event {
        id: id.into(),
        timestamp: Utc::now(),
        agent_id: "agent-a".into(),
        task_id: None,
        run_id: None,
        execution_id: None,
        trace_id: "tr-wiring".into(),
        span_id: "s-1".into(),
        parent_span_id: None,
        event_type: event_type.into(),
        payload: json!({}),
        duration_ms: None,
    }
}

/// T89 — the production composition root registers a live read api over the
/// wired bus; events emitted via the wired `event_bus_dyn` are readable through it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t89_production_wiring_read_api_reads_wired_bus() {
    let (_g, ws, cfg) = fresh_workspace();
    let builder = RuntimeHostBuilder::new(&cfg, &ws).await.expect("builder");
    let (_host, handles) = wire_capabilities(builder, &ws).await.expect("wire");

    let read = handles
        .observability_read_api
        .clone()
        .expect("production async bus ⇒ observability_read_api is Some");

    // (a) live: subscribe on the wired read api, emit through the wired emit
    // surface, receive it.
    let mut sub = read.subscribe(EventFilter {
        event_type_prefix: Some("run.".into()),
        ..Default::default()
    });
    handles.event_bus_dyn.emit(ev("w1", "run.created"));
    handles.event_bus_dyn.emit(ev("noise", "fs.read")); // filtered out
    handles.event_bus_dyn.emit(ev("w2", "run.round_completed"));

    let mut got = Vec::new();
    for _ in 0..2 {
        match tokio::time::timeout(Duration::from_secs(3), sub.recv()).await {
            Ok(ReadNext::Event(e)) => got.push(e.id.clone()),
            other => panic!("expected Event from the wired bus, got {other:?}"),
        }
    }
    assert_eq!(
        got,
        vec!["w1", "w2"],
        "the read api registered by wire_capabilities receives events emitted through the wired event_bus_dyn"
    );

    // (b) historical: the same events are queryable from the persisted store.
    tokio::time::sleep(Duration::from_millis(400)).await;
    let rows = read
        .query(
            &EventFilter {
                trace_id: Some("tr-wiring".into()),
                ..Default::default()
            },
            100,
        )
        .await
        .expect("query");
    let ids: std::collections::HashSet<String> = rows.iter().map(|r| r.event.id.clone()).collect();
    assert!(
        ids.contains("w1") && ids.contains("w2"),
        "wired read api's historical query sees the persisted events"
    );

    // (c) durable resume through the wired handle: emit an anchor + a later event,
    // then resume(anchor) replays the later one via the production composition.
    handles.event_bus_dyn.emit(ev("anchor", "run.created"));
    tokio::time::sleep(Duration::from_millis(300)).await;
    handles
        .event_bus_dyn
        .emit(ev("after", "run.round_completed"));
    tokio::time::sleep(Duration::from_millis(300)).await;
    let mut stream = read
        .resume(Some(ReadCursor("anchor".into())), EventFilter::default())
        .await
        .expect("resume through wired handle");
    let mut replayed = Vec::new();
    loop {
        match tokio::time::timeout(Duration::from_millis(500), stream.recv()).await {
            Ok(Ok(Some(re))) => replayed.push(re.event.id.clone()),
            _ => break,
        }
    }
    assert!(
        replayed.contains(&"after".to_string()),
        "resume from a cursor replays through the wired composition; got {replayed:?}"
    );
}

/// T90 — negative identity discriminator: a standalone bus's read api receives
/// NOTHING from the wired bus. Proves the wired handle is bound to the wired bus,
/// not to any bus (refutes a SUT self-assembly / any-bus fake).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t90_standalone_read_api_receives_nothing_from_wired_bus() {
    let (_g, ws, cfg) = fresh_workspace();
    let builder = RuntimeHostBuilder::new(&cfg, &ws).await.expect("builder");
    let (_host, handles) = wire_capabilities(builder, &ws).await.expect("wire");

    let wired_read = handles
        .observability_read_api
        .clone()
        .expect("observability_read_api Some");

    // A SEPARATE standalone bus (different pool + broadcaster).
    let temp = tempfile::TempDir::new().unwrap();
    let mut c = EventBusConfig::new(temp.path().join("j"), temp.path().join("events.db"));
    c.websocket_addr = "127.0.0.1:0".parse().unwrap();
    let standalone = EventBus::new(c).await.expect("standalone bus");
    let standalone_read = standalone.read_api().expect("Some");

    // Subscribe on BOTH before emitting.
    let mut wired_sub = wired_read.subscribe(EventFilter::default());
    let mut standalone_sub = standalone_read.subscribe(EventFilter::default());

    // Emit only to the WIRED bus.
    handles.event_bus_dyn.emit(ev("only-wired", "task.created"));

    // Wired subscription receives it.
    match tokio::time::timeout(Duration::from_secs(3), wired_sub.recv()).await {
        Ok(ReadNext::Event(e)) => assert_eq!(e.id, "only-wired"),
        other => panic!("wired read api must receive the wired emit, got {other:?}"),
    }

    // Standalone subscription (different bus) receives NOTHING.
    assert!(
        tokio::time::timeout(Duration::from_millis(500), standalone_sub.recv())
            .await
            .is_err(),
        "a read api over a DIFFERENT bus must NOT receive the wired bus's events — identity binding holds"
    );

    let _ = Arc::new(standalone); // hold to end of scope
}

//! await-leg B-2 (2026-06-22) — production messaging-wiring witness (anti-fake-green).
//!
//! Guards the claim that `wire_capabilities` actually wires the await-replies +
//! heartbeat host-fns + the `RunManagerSuspendSink` into production (closing
//! MODULE-007 §3.6 R9), NOT merely that `register_*` was called (the 228/257
//! built-but-unwired fake-green class).
//!
//! - **T-B2-01**: with `messaging` (+ `fs`) declared, the registry has BOTH
//!   `await-replies` (idempotent=false) + `heartbeat` (idempotent=true) under the
//!   canonical namespace — registration is LIVE, not absent.
//! - **T-B2-02** (the strongest): drives the PROD-REGISTERED handler (extracted
//!   from `lookup("messaging")`, carrying the wired sink) — a lone
//!   `component-finished` await parks → the suspend sink fires (run `Suspended`,
//!   with a BARE caller admitted) → `cancel_run` while Suspended exercises
//!   `RunManager::with_await_session_ref`'s close cascade → the await resolves WIT
//!   `session-closed` → resume is skipped (run stays `Cancelled`). No idle/timing
//!   dependency (the unwind is driven by cancel, not the 5s idle monitor).
//! - **T-B2-03**: no `messaging` cap declared ⇒ NO messaging host-fns registered
//!   (the `declares_messaging` gate holds; no inert always-on registration).
//! - **T-B2-05**: a messaging-ONLY (no-fs) agent wires cleanly (the hoisted
//!   `AgentTreeStore` builds for the dispatcher even without cap-fs).
//!
//! **ZERO ledger flips**: these are regression guards, not AC/SYS-AC witnesses. As of
//! await-leg B-4a (2026-06-22) `agent_config::KNOWN_CAPABILITIES` INCLUDES `messaging`
//! (so a messaging-declaring guest links it), but shipped agents stay dormant; these
//! tests drive `wire_capabilities` directly over a `messaging:true` config and read the
//! registry — they do not depend on `KNOWN_CAPABILITIES`.

use advance_cli::wiring::wire_capabilities;
use advance_run_manager::RunConfig;
use advance_runtime::bootstrap::RuntimeHostBuilder;
use advance_runtime::host_registry::HostCallContext;
use advance_shared_types::run::{RoundDecision, RoundResult, TaskRunStatus};
use std::path::PathBuf;
use std::time::Duration;
use wasmtime::component::Val;

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

const NS: &str = "advance:runtime/agent-messaging@0.1.0";
const TEST_MASTER_KEY_HEX: &str =
    "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

fn ensure_test_master_key() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| std::env::set_var("SECRETS_MASTER_KEY", TEST_MASTER_KEY_HEX));
}

/// Build a tempdir workspace with `.advance/runtime-config.yaml` + `.runtime/`
/// scaffolding + a per-test `.agent/config.yaml`.
fn fresh_workspace(agent_caps_yaml: &str) -> (tempfile::TempDir, PathBuf, PathBuf) {
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

/// Bespoke `await-replies` WIT params: a single `component-finished` slot (which
/// dispatch-skips → genuine park, no mailbox routing) + await-options that park
/// indefinitely (`idle-timeout-secs: none`; the unwind is driven by `cancel_run`,
/// NOT the idle monitor). `component-id`/`correlation-id` are non-empty safe opaque
/// ids (the manager admission runs `is_safe_opaque_id` BEFORE parking).
fn single_component_finished_params() -> Vec<Val> {
    vec![
        Val::List(vec![Val::Variant(
            "component-finished".into(),
            Some(Box::new(Val::Record(vec![
                ("component-id".into(), Val::String("comp-1".into())),
                ("correlation-id".into(), Val::String("corr-1".into())),
            ]))),
        )]),
        Val::Record(vec![
            ("mode".into(), Val::Variant("all-of".into(), None)),
            ("idle-timeout-secs".into(), Val::Option(None)),
            (
                "on-idle-timeout".into(),
                Val::Variant("return-partial".into(), None),
            ),
            ("keep-losers".into(), Val::Bool(false)),
        ]),
    ]
}

/// Assert a returned `Val` is the WIT `result<await-result, orchestration-error>`
/// Err arm carrying `orchestration-error::session-closed`. The handler returns a
/// Rust `Ok(vec![Val::Result(Err(..))])` (the WIT-level error is INSIDE the Ok vec),
/// mirroring the proven `assert_session_closed` shape in the system-acceptance
/// `sys_j06_pause_cancel_session_closed` witness.
fn assert_session_closed(v: &Val) {
    match v {
        Val::Result(Err(Some(inner))) => match inner.as_ref() {
            Val::Variant(case, _) => assert_eq!(
                case, "session-closed",
                "expected orchestration-error::session-closed, got variant `{case}`"
            ),
            other => panic!("expected an orchestration-error variant in Err, got {other:?}"),
        },
        other => panic!("expected result::Err(session-closed), got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn t_b2_01_messaging_registration_is_live() {
    let (_g, ws, cfg) = fresh_workspace("capabilities:\n  messaging: true\n  fs: true\n");
    let builder = RuntimeHostBuilder::new(&cfg, &ws).await.expect("builder");
    let (host, _handles) = wire_capabilities(builder, &ws).await.expect("wire");

    let specs = host.host_registry().lookup("messaging");
    let await_spec = specs.iter().find(|s| {
        s.capability == "messaging"
            && s.namespace == NS
            && s.name == "await-replies"
            && !s.idempotent
    });
    let hb_spec = specs.iter().find(|s| {
        s.capability == "messaging" && s.namespace == NS && s.name == "heartbeat" && s.idempotent
    });
    assert!(
        await_spec.is_some(),
        "messaging declared ⇒ `await-replies` host-fn (ns `{NS}`, idempotent=false) must be registered; got {specs:?}"
    );
    assert!(
        hb_spec.is_some(),
        "messaging declared ⇒ `heartbeat` host-fn (ns `{NS}`, idempotent=true) must be registered; got {specs:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn t_b2_02_handler_drives_suspend_on_park_then_cancel_closes() {
    let (_g, ws, cfg) = fresh_workspace("capabilities:\n  messaging: true\n");
    let builder = RuntimeHostBuilder::new(&cfg, &ws).await.expect("builder");
    let (host, handles) = wire_capabilities(builder, &ws).await.expect("wire");

    // Extract the SAME await-replies handler instance wiring registered (carrying
    // the production suspend sink) — driving this proves the registration is not inert.
    let await_spec = host
        .host_registry()
        .lookup("messaging")
        .into_iter()
        .find(|s| s.name == "await-replies")
        .expect("await-replies registered");
    let handler = await_spec.handler.clone();

    // An Active run on the SAME RunManager the wired sink points to.
    let run_id = handles
        .run_manager
        .ensure_run("default-agent", "default-agent", RunConfig::default())
        .expect("ensure_run");

    let ctx = HostCallContext {
        agent_id: "default-agent".to_string(), // BARE — the handler prepends `agent:`
        trace_id: "tr-b2".to_string(),
        turn_id: None,
        capability: "messaging".to_string(),
        function: "agent-messaging::await-replies".to_string(),
        run_id: Some(run_id.to_string()),
        iteration: None,
    };

    // Spawn the handler call; the lone component-finished slot parks indefinitely.
    let join = tokio::spawn(handler.call(ctx, single_component_finished_params(), 1));

    // The park drives `on_park` → `suspend_run` synchronously, so Suspended appears
    // sub-second. Observing it proves BOTH the sink is wired AND the bare caller was
    // admitted (a rejected caller would Err at admission BEFORE parking).
    let mut suspended = false;
    for _ in 0..400 {
        if let Ok(state) = handles.run_manager.run_status(&run_id) {
            if matches!(state.status, TaskRunStatus::Suspended) {
                suspended = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(
        suspended,
        "the parked await-replies must drive RunManager::suspend_run (run → Suspended) — proves the prod RunManagerSuspendSink is wired AND the bare `default-agent` caller was admitted"
    );

    // While Suspended, cancel. The Suspended branch consults `await_session_ref`
    // (must NOT be `PermissionDenied(await-session-ref-not-configured)`), closing the
    // await session. Await it to completion BEFORE joining the handler so the final
    // status assertion is order-deterministic.
    handles
        .run_manager
        .cancel_run(&run_id, "b2-witness-cancel".to_string())
        .await
        .expect("cancel_run while Suspended must succeed — proves RunManager::with_await_session_ref is wired in prod (else PermissionDenied: await-session-ref-not-configured)");

    // The close cascade resolves the parked await as Err(SessionClosed) → WIT
    // session-closed; the handler SKIPS resume on SessionClosed.
    let out = join
        .await
        .expect("join handler task")
        .expect("await-replies returns Ok(vec)");
    assert_eq!(out.len(), 1, "await-replies returns exactly one Val");
    assert_session_closed(&out[0]);

    // Resume was skipped ⇒ the run stays Cancelled (NOT flipped back to Active).
    // `Cancelled(String)` is a tuple variant — match with `Cancelled(_)`.
    let final_status = handles
        .run_manager
        .run_status(&run_id)
        .expect("run_status")
        .status;
    assert!(
        matches!(final_status, TaskRunStatus::Cancelled(_)),
        "run must stay Cancelled (resume skipped on SessionClosed); got {final_status:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn t_b2_03_no_messaging_cap_not_registered() {
    let (_g, ws, cfg) = fresh_workspace("capabilities:\n  fs: true\n");
    let builder = RuntimeHostBuilder::new(&cfg, &ws).await.expect("builder");
    let (host, _handles) = wire_capabilities(builder, &ws).await.expect("wire");
    let specs = host.host_registry().lookup("messaging");
    assert!(
        specs.is_empty(),
        "no `messaging` cap declared ⇒ NO messaging host-fns registered (the declares_messaging gate); got {specs:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "GHA: wire_capabilities rejects progress-lifecycle path policy on runner temp paths; quarantine for post-genesis hardening"]
async fn t_b2_04_run_manager_shares_agent_tree_for_descendant_cascade() {
    let (_g, ws, cfg) = fresh_workspace(
        "\
capabilities:
  messaging: true
  fs: true
agents:
  - alias: child-a
    template: explorer
    target-path: children/a
",
    );
    let builder = RuntimeHostBuilder::new(&cfg, &ws).await.expect("builder");
    let (_host, handles) = wire_capabilities(builder, &ws).await.expect("wire");

    let root_run = handles
        .run_manager
        .ensure_run("task-root", "default-agent", RunConfig::default())
        .expect("ensure root run");
    let child_run = handles
        .run_manager
        .ensure_run("task-child", "child-a", RunConfig::default())
        .expect("ensure child run");
    handles
        .run_manager
        .suspend_run(&child_run, "sid-child")
        .expect("suspend child");

    handles
        .run_manager
        .cancel_run(&root_run, "root-cancel".to_string())
        .await
        .expect("root cancel arms pending");
    let decision = handles
        .run_manager
        .complete_round(
            &root_run,
            RoundResult {
                summary: None,
                metrics: Vec::new(),
            },
        )
        .await
        .expect("normal complete_round settles root and cascades child");

    assert!(
        matches!(&decision, RoundDecision::Blocked(reason) if reason == "cancel-pending"),
        "root cancel must settle on the normal complete_round path; got {decision:?}"
    );
    let child_status = handles
        .run_manager
        .run_status(&child_run)
        .expect("child status")
        .status;
    assert!(
        matches!(&child_status, TaskRunStatus::Cancelled(reason) if reason == "root-cancel"),
        "config-declared child run must be cancelled via the shared AgentTreeSnapshot; got {child_status:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn t_b2_05_messaging_only_agent_wires_cleanly() {
    // No `fs` declared: exercises the new messaging-only construction path (the
    // hoisted AgentTreeStore is built for the dispatcher even without cap-fs).
    let (_g, ws, cfg) = fresh_workspace("capabilities:\n  messaging: true\n");
    let builder = RuntimeHostBuilder::new(&cfg, &ws).await.expect("builder");
    let (host, _handles) = wire_capabilities(builder, &ws)
        .await
        .expect("messaging-only wire must succeed (hoisted AgentTreeStore built without fs)");
    assert!(
        !host.host_registry().lookup("messaging").is_empty(),
        "a messaging-only agent registers the messaging host-fns"
    );
}

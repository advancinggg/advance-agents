//! Stage-B pass-2 — SYS-AC-109 run-leg + terminate-independence (SYS-J-34).
//!
//! Criterion (VERBATIM): "The admitted component runs on its own trigger
//! independent of the submitting agent (terminating the agent does not remove it)."
//!
//! This is the HONEST closer for the F1 fake-green (2026-06-13 reverted): the prior
//! 1B witness fabricated the driver harness-side, bound only by an id string
//! (deleting the submit still passed). Here the driver is materialized by the REAL
//! cli composition fn `run_readiness_gated_walk` over the SUT's live
//! `ComponentRegistry`, and `WasmRunnableHookFactory` loads THE ADMITTED ROW'S
//! EXACT BYTES (`load_component(row.binary)`) — so what runs is a function of the
//! submitted bytes, not the id.
//!
//! Component-type note: an admitted **Cron** row carries `interval_ms: None`
//! (recurring-interval derivation is waived product scaffolding) and the
//! materializer's Cron arm fail-closes on `None`, so Cron cannot run via the walk.
//! A **Watcher** materializes from its persisted `cfg.trigger` (no interval), and
//! SYS-J-34 explicitly covers "cron/daemon/**watcher**/task" — so the witness
//! admits a `Watcher(TriggerEvent "git.commit")` and fires it on the real trigger
//! bus. The walk path drives `WatcherDriver::run_with_trigger_source(emitter=None)`,
//! so the observable is the on-disk `result.bin` the driver writes (no events).
//!
//! Boot-seam disclosure: `run_readiness_gated_walk` is real cli product code, but no
//! production composition site calls it at boot yet (runnable_walk.rs module doc).
//! The harness supplies ONLY that startup-INVOCATION seam over REAL components (real
//! runtime/registry/factory/materializer/WatcherDriver + real trigger-bus dispatch —
//! no module in the SYS-J-34 chain mocked).

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use advance_cli::runnable_hook_factory::WasmRunnableHookFactory;
use advance_cli::runnable_walk::run_readiness_gated_walk;
use advance_scheduler::hook::{
    FileWatchSource, HookError, RunnableHookFactory, RuntimeReadiness, WebhookSource,
};
use advance_scheduler::trigger_source::TriggerFireEvent;
use advance_scheduler::types::{
    ComponentSubmitConfig, TriggerConfig, TriggerSubscription, WebhookConfig,
};
use advance_scheduler::{ComponentSubmitApi, TriggerBusDispatch};
use advance_shared_types::agent_tree::{AgentId, AgentKind, AgentTreeSnapshot};
use advance_shared_types::component::ComponentType;
use advance_shared_types::event::Event;
use async_trait::async_trait;
use serde_json::json;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use wit_component::ComponentEncoder;

use system_acceptance::{AgentSpec, Cap, GrantMode, SystemUnderTest};

// guest-rust-minimal's runnable.run() returns Completed{output: Some(RUN_SENTINEL)}
// UNCONDITIONALLY (no host fn, ignores trigger_context) → result.bin written.
const MINIMAL_CORE_BYTES: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-minimal.core.wasm");
// guest-rust-counter's runnable.run() returns Completed{output: None} → NO result.bin.
// The T-RF-05 distinct-valid-guest bytes-binding discriminator.
const COUNTER_CORE_BYTES: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-counter.core.wasm");
// The SUT's own guest (drives the build()'s runnable_parts runtime/injector).
const SKELETON: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-j01-skeleton.core.wasm");
/// What guest-rust-minimal's run() returns — proves the REAL guest body executed.
const RUN_SENTINEL: [u8; 4] = [0xAD, 0x11, 0xCE, 0x02];

const WHITELISTED_EVENT: &str = "git.commit";

// ── trivial in-test trigger-source doubles (never invoked for a TriggerEvent
//    watcher — only the Schedule/FileWatch/Webhook arms use them) ──────────────
struct ReadyProbe(bool);
#[async_trait]
impl RuntimeReadiness for ReadyProbe {
    async fn is_ready(&self) -> bool {
        self.0
    }
}
struct NoopFileWatchSource;
#[async_trait]
impl FileWatchSource for NoopFileWatchSource {
    async fn run(
        &self,
        _glob: String,
        _tx: mpsc::Sender<TriggerFireEvent>,
        cancel: CancellationToken,
    ) -> Result<(), HookError> {
        cancel.cancelled().await;
        Ok(())
    }
}
struct NoopWebhookSource;
#[async_trait]
impl WebhookSource for NoopWebhookSource {
    async fn run(
        &self,
        _cfg: WebhookConfig,
        _tx: mpsc::Sender<TriggerFireEvent>,
        cancel: CancellationToken,
    ) -> Result<(), HookError> {
        cancel.cancelled().await;
        Ok(())
    }
}

fn component_bytes(core: &[u8]) -> Vec<u8> {
    ComponentEncoder::default()
        .validate(true)
        .module(core)
        .expect("core module wraps")
        .encode()
        .expect("component encoded")
}

fn sub(event_type: &str) -> TriggerSubscription {
    TriggerSubscription {
        event_type: event_type.into(),
        filter: None,
        debounce_ms: None,
    }
}

fn evt(event_type: &str, payload: serde_json::Value) -> Event {
    Event::observability(event_type, "sys-j34-runleg", payload, None)
}

fn watcher_cfg(id: &str, binary: Vec<u8>, output_dir: Option<String>) -> ComponentSubmitConfig {
    ComponentSubmitConfig {
        sensitive_params: Vec::new(),
        id: id.into(),
        component_type: ComponentType::Watcher,
        binary,
        capabilities: vec![],
        output_dir,
        trigger: Some(TriggerConfig::TriggerEvent(sub(WHITELISTED_EVENT))),
        restart_policy: None,
        delay: None,
        initial_grants: None,
        preset: None,
        retry: None,
    }
}

/// Build the PRODUCTION `WasmRunnableHookFactory` over the SUT's real runtime +
/// injector (the same the message-driven path uses) — loads the admitted row's
/// EXACT bytes per row.
fn factory_from(sut: &SystemUnderTest) -> Arc<dyn RunnableHookFactory> {
    let (runtime, injector) = sut.runnable_factory_parts();
    Arc::new(WasmRunnableHookFactory::new(runtime, injector))
}

/// CWD-relative output dir (the materializer REJECTS absolute output_dir,
/// materializer.rs:168). The whole `system-acceptance` test binary shares one CWD,
/// so each test uses a DISTINCT literal dir. Cleaned at start + end.
fn fresh_reldir(name: &str) -> String {
    let _ = std::fs::remove_dir_all(name);
    // C2 (adversarial r9): a STALE `result.bin` (cleanup-failed or a literal-dir
    // collision) could satisfy the positive witness BEFORE any real run, because
    // `dispatch_until` checks `result.bin.exists()` before dispatching. Fail LOUDLY
    // if the dir is not genuinely clean, so a residual file cannot false-PASS.
    assert!(
        !Path::new(name).join("result.bin").exists(),
        "output dir {name:?} not clean (a stale result.bin would false-PASS the witness)"
    );
    name.to_string()
}
fn result_bin(reldir: &str) -> std::path::PathBuf {
    Path::new(reldir).join("result.bin")
}

/// Dispatch the whitelisted trigger on the REAL bus (fresh chain-id per attempt to
/// dodge the visited-set) until `cond` holds or the bounded budget runs out.
async fn dispatch_until<F: Fn() -> bool>(sut: &SystemUnderTest, tag: &str, cond: F) -> bool {
    for i in 0..2000u32 {
        if cond() {
            return true;
        }
        sut.trigger_bus().dispatch(evt(
            WHITELISTED_EVENT,
            json!({ "trigger_chain_id": format!("{tag}-{i}"), "chain_depth": 0 }),
        ));
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    cond()
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 1 — the admitted Watcher runs ON ITS OWN TRIGGER via the real registry→walk
// materialization, bound to the ROW'S BYTES (minimal SENTINEL vs counter None vs
// truncated build-fail — all under one walk, one dispatch stream).
// ─────────────────────────────────────────────────────────────────────────────
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_109_admitted_watcher_runs_on_own_trigger_bytes_bound() {
    let min_dir = fresh_reldir("sysac109-runleg-min");
    let cnt_dir = fresh_reldir("sysac109-runleg-cnt");
    let trunc_dir = fresh_reldir("sysac109-runleg-trunc");

    let sut = SystemUnderTest::builder()
        .with_triggers()
        .build(SKELETON)
        .await;
    let api = sut.submit_api();

    // Admit THREE watchers on the SAME whitelisted git.commit trigger:
    //  - w-min   : real guest-rust-minimal component bytes (→ result.bin == SENTINEL)
    //  - w-cnt   : real guest-rust-counter component bytes (run()→None → NO result.bin)
    //  - w-trunc : truncated minimal bytes (factory.build fails → NO result.bin)
    // Admission does NOT load/validate the binary, so all three are admitted.
    let min_bytes = component_bytes(MINIMAL_CORE_BYTES);
    let trunc_bytes = min_bytes[..min_bytes.len() / 2].to_vec();
    api.submit_component(
        "agent:root",
        watcher_cfg("w-min", min_bytes.clone(), Some(min_dir.clone())),
    )
    .await
    .expect("admit the minimal watcher");
    api.submit_component(
        "agent:root",
        watcher_cfg(
            "w-cnt",
            component_bytes(COUNTER_CORE_BYTES),
            Some(cnt_dir.clone()),
        ),
    )
    .await
    .expect("admit the counter watcher");
    api.submit_component(
        "agent:root",
        watcher_cfg("w-trunc", trunc_bytes, Some(trunc_dir.clone())),
    )
    .await
    .expect("admit the truncated watcher (admission does not validate the binary)");

    // Durable persistence (the admitted rows the walk will materialize FROM).
    let persisted = api
        .list_components_persisted()
        .await
        .expect("durable registry read");
    for id in ["w-min", "w-cnt", "w-trunc"] {
        assert!(
            persisted.iter().any(|r| r.id.as_str() == id),
            "{id} persisted to the ComponentRegistry"
        );
    }

    // Drive the REAL cli walk over the SUT's LIVE registry → materializes a driver
    // per row FROM ITS BYTES, subscribing each watcher to the SUT trigger bus.
    let cancel = CancellationToken::new();
    let handles = run_readiness_gated_walk(
        &**sut.submit_registry(),
        Arc::new(ReadyProbe(true)),
        factory_from(&sut),
        sut.trigger_bus().clone(),
        Arc::new(NoopFileWatchSource),
        Arc::new(NoopWebhookSource),
        cancel.clone(),
    )
    .await
    .expect("readiness-gated walk spawns the materialized drivers");

    // W3 (adversarial r9): positive evidence that ALL THREE rows were
    // materialization-PROCESSED by the walk — so the counter/truncate "no result.bin"
    // discriminators are load-bearing (the rows genuinely ran-or-failed through the
    // real row-bytes chain, not silently skipped). The walk returns one
    // (ComponentId, JoinHandle) per non-Agent row.
    let walked: Vec<String> = handles
        .iter()
        .map(|(id, _)| id.as_str().to_string())
        .collect();
    for id in ["w-min", "w-cnt", "w-trunc"] {
        assert!(
            walked.iter().any(|i| i == id),
            "walk materialized a driver task for {id} (proves it was not silently skipped); got {walked:?}"
        );
    }
    // Pull the truncated row's handle and await it: `materialize` fails at
    // `factory.build(&row.binary)` BEFORE the watcher loop, so the handle resolves to
    // an `Err(HookError)` — positive proof it was processed-and-rejected-on-bytes
    // (never ran), the bytes-binding the F1 fake-green forbids. The minimal/counter
    // watcher handles run until cancel — keep them alive.
    let mut kept = Vec::new();
    let mut trunc_handle = None;
    for (id, h) in handles {
        if id.as_str() == "w-trunc" {
            trunc_handle = Some(h);
        } else {
            kept.push((id, h));
        }
    }
    let _kept = kept;
    let trunc_res = trunc_handle
        .expect("w-trunc handle present")
        .await
        .expect("w-trunc materialize task joins");
    assert!(
        trunc_res.is_err(),
        "SYS-AC-109 bytes-binding: the truncated-bytes row failed at factory.build (Err), \
         proving the materializer loads + validates the ROW'S BYTES (it was processed, not \
         skipped, and never ran); got {trunc_res:?}"
    );

    // Fire the watchers' OWN trigger on the real bus until the minimal one runs.
    let min_bin = result_bin(&min_dir);
    let fired = dispatch_until(&sut, "chain-109", || min_bin.exists()).await;
    assert!(
        fired,
        "SYS-AC-109: the admitted minimal watcher ran on its own git.commit trigger \
         (result.bin at {})",
        min_bin.display()
    );

    // Give the sibling watchers ample chance to (not) write under more dispatches.
    for i in 0..20u32 {
        sut.trigger_bus().dispatch(evt(
            WHITELISTED_EVENT,
            json!({ "trigger_chain_id": format!("settle-{i}"), "chain_depth": 0 }),
        ));
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    // ── PRODUCT-bound assertions ──
    // (1) The minimal watcher ran the ROW'S BYTES → result.bin == RUN_SENTINEL.
    let got = std::fs::read(&min_bin).expect("minimal watcher wrote result.bin");
    assert_eq!(
        got, RUN_SENTINEL,
        "SYS-AC-109: result.bin is guest-rust-minimal's RUN_SENTINEL — the materialized \
         driver ran the admitted row's exact bytes (not an id/hardcoded default)"
    );
    // (2) T-RF-05 — same trigger, DIFFERENT bytes (counter) → DIFFERENT outcome
    //     (no result.bin). An id/hardcoded-bound driver would produce the same.
    assert!(
        !result_bin(&cnt_dir).exists(),
        "SYS-AC-109 bytes-binding: the counter watcher (run()→None) wrote NO result.bin — \
         the outcome is a function of the row BYTES, not the id"
    );
    // (3) T-RF-03 — truncated bytes → factory.build fails → driver never ran.
    assert!(
        !result_bin(&trunc_dir).exists(),
        "SYS-AC-109 bytes-binding: the truncated-bytes watcher failed to materialize \
         (factory.build Err) → NO result.bin"
    );

    cancel.cancel();
    let _ = std::fs::remove_dir_all(&min_dir);
    let _ = std::fs::remove_dir_all(&cnt_dir);
    let _ = std::fs::remove_dir_all(&trunc_dir);
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 2 — terminate-independence: a REAL terminate of the SUBMITTING agent
// (a terminable non-root bare-id child) does NOT remove the admitted component,
// and the running watcher keeps firing afterwards.
// ─────────────────────────────────────────────────────────────────────────────
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_109_terminate_submitter_does_not_remove_component() {
    use advance_run_manager::RunManager;
    use advance_shared_types::traits::EventBusEmit;
    use cap_lifecycle::{
        DefaultTerminateController, FsWorkspaceCleanup, GrantRevokeCascade, MailboxFlushCascade,
        RunManagerCascade, TerminateController,
    };

    struct DiscardBus;
    impl EventBusEmit for DiscardBus {
        fn emit(&self, _e: Event) {}
    }

    let out_dir = fresh_reldir("sysac109-terminate-out");

    // A real agent tree (root + a terminable non-root bare-id child) AND the trigger
    // substrate, in ONE system.
    let specs = vec![
        AgentSpec {
            id: "agent:root".into(),
            kind: AgentKind::Root,
            parent: None,
            caps: vec![Cap::Fs],
            capabilities: vec![],
        },
        AgentSpec {
            id: "agent:child-a".into(),
            kind: AgentKind::Child,
            parent: Some("agent:root".into()),
            caps: vec![Cap::Fs],
            capabilities: vec![],
        },
    ];
    let sut = SystemUnderTest::builder()
        .agents(&specs)
        .with_triggers()
        .grant(GrantMode::Real)
        .build(SKELETON)
        .await;

    let spawner = sut.spawner().expect(".agents() configures the spawner");
    let tree = spawner.tree().clone();
    let grant_store = sut.grant_store().expect("GrantMode::Real");
    let mailbox_store = sut.mailbox_store();

    // The SUBMITTER is the bare-id child-a (a real terminable tree node).
    sut.submit_api()
        .submit_component(
            "child-a",
            watcher_cfg(
                "w-term",
                component_bytes(MINIMAL_CORE_BYTES),
                Some(out_dir.clone()),
            ),
        )
        .await
        .expect("child-a admits a watcher");

    // Materialize + run it on its own trigger (result.bin proves it is live).
    let cancel = CancellationToken::new();
    let _handles = run_readiness_gated_walk(
        &**sut.submit_registry(),
        Arc::new(ReadyProbe(true)),
        factory_from(&sut),
        sut.trigger_bus().clone(),
        Arc::new(NoopFileWatchSource),
        Arc::new(NoopWebhookSource),
        cancel.clone(),
    )
    .await
    .expect("walk");
    let out_bin = result_bin(&out_dir);
    assert!(
        dispatch_until(&sut, "pre-term", || out_bin.exists()).await,
        "the child-a-submitted watcher is running pre-terminate (result.bin present)"
    );

    // ── REAL terminate of the submitting agent child-a (4 real cascade adapters) ──
    assert!(
        tree.snapshot()
            .nodes
            .iter()
            .any(|n| n.id == AgentId("child-a".into())),
        "child-a is in the tree pre-terminate"
    );
    let run_mgr = RunManager::new_arc(Arc::new(DiscardBus));
    let controller = DefaultTerminateController::new(
        tree.clone(),
        Arc::new(GrantRevokeCascade::new(Arc::clone(grant_store))),
        Arc::new(MailboxFlushCascade::new(Arc::clone(&mailbox_store))),
        Arc::new(RunManagerCascade::new(run_mgr)),
        Arc::new(FsWorkspaceCleanup::new(tree.workspace_root().to_path_buf())),
    );
    controller
        .terminate_child("root", "child-a")
        .expect("terminate child-a (root is its parent)");

    // Non-vacuity: the terminate ACTUALLY ran — child-a's node is gone.
    assert!(
        !tree
            .snapshot()
            .nodes
            .iter()
            .any(|n| n.id == AgentId("child-a".into())),
        "SYS-AC-109 (terminate non-vacuity): child-a removed from the tree post-terminate"
    );

    // ── "terminating the agent does not remove it" ──
    let persisted = sut
        .submit_api()
        .list_components_persisted()
        .await
        .expect("durable read");
    assert!(
        persisted.iter().any(|r| r.id.as_str() == "w-term"),
        "SYS-AC-109: the component submitted by child-a SURVIVES child-a's termination \
         (still in the durable registry)"
    );

    // ── and it STILL RUNS post-terminate ──
    // W2 (adversarial r9): DRAIN any in-flight pre-terminate watcher runs first, so
    // the reappearance below is attributable to a FRESH post-terminate trigger and
    // NOT pre-terminate backlog. Delete result.bin, confirm it stays absent through
    // the drain window (no backlog rewrites it), THEN dispatch fresh + assert.
    tokio::time::sleep(Duration::from_millis(250)).await; // let any backlog settle
    let _ = std::fs::remove_file(&out_bin);
    tokio::time::sleep(Duration::from_millis(150)).await; // drain-confirm window
    assert!(
        !out_bin.exists(),
        "SYS-AC-109: post-terminate drain — no pre-terminate backlog rewrote result.bin, \
         so the reappearance below is from a FRESH post-terminate trigger"
    );
    assert!(
        dispatch_until(&sut, "post-term", || out_bin.exists()).await,
        "SYS-AC-109: the component still runs on its own trigger AFTER its submitter was \
         terminated (a fresh git.commit re-drove it → result.bin re-written)"
    );
    assert_eq!(
        std::fs::read(&out_bin).expect("post-terminate result.bin"),
        RUN_SENTINEL,
        "SYS-AC-109: the post-terminate run is the real guest (RUN_SENTINEL)"
    );

    cancel.cancel();
    let _ = std::fs::remove_dir_all(&out_dir);
}

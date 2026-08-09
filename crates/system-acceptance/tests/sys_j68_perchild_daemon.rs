//! Wave-23 `perchild-daemon-1` — SYS-AC-279 witness: a production-daemon
//! `spawn-child` yields a LIVE served child, with a loop-registry entry, colon/bare
//! routing + id-bridge registration, and a served child loop — with NO
//! harness-supplied pieces (the crux of the 2026-07-04 per-child adjudication;
//! MODULE-001-AC-22 seams a–e).
//!
//! This is the "composed-production-builders equivalent" the AC-22 §1.5 criterion
//! sanctions (the AC-19 precedent `m001_ac19_multiagent_e2e.rs` composes the same
//! production builders). Unlike AC-19 — which HAND-SUPPLIED the child's colon
//! routing entry + hand-launched the child serve loop — here the routing, the
//! id-bridge pair, AND the serve loop all come from PRODUCTION code: the
//! `PerChildLoopManager` (cli composition root, seam d) attached as the
//! `DefaultSpawner`'s [`SpawnObserver`], driving the dual-grammar `DynamicRouting`
//! (seam e) the production `MailboxDispatcherImpl` reads.
//!
//! SYS-AC-279 is STRUCTURAL (loop-registry + colon/bare routing + id-bridge exist
//! + a SERVED loop, non-harness, + two discriminators). Liveness = the child's OWN
//! `handle-message` turn runs on the parent-routed message (the child loop's
//! recording `TurnObserver` fires). The parent→child delegation ROUNDTRIP + the
//! armed deadlock gate are SYS-AC-280 (Wave-24) — deliberately NOT exercised here.
//!
//! Discriminators (toggling the PRODUCTION seam, not harness fakes):
//! - **child-loop-absent** → the parent message routes + queues but NO turn runs;
//! - **routing-entry-absent** → the parent send dead-ends `unknown_target`.

#![allow(clippy::type_complexity)]

use std::future::Future;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use advance_cli::agent_loop::{RunSession, SessionRunCell, WasmMessageHandler};
use advance_cli::await_wiring::{build_await_messaging_chain, RunManagerSuspendSink};
use advance_cli::perchild_daemon::{KeyResolver, PerChildLoopCascade, PerChildLoopManager};
use advance_cli::wiring::{wire_capabilities, WiringHandles};
use advance_messaging::{
    AgentIdBridge, BreakerSubscriber, DynamicRouting, MailboxDispatcher, MailboxDispatcherImpl,
    MailboxStore, MsgError,
};
use advance_reply_tracker::{
    register_reply_tracker_host_fns_with_suspend_sink, AwaitSessionManagerImpl, ManagerOptions,
    RunSuspendSink, SendHandler,
};
use advance_run_manager::{RunConfig, RunId, RunManager};
use advance_runtime::bootstrap::{RuntimeHost, RuntimeHostBuilder};
use advance_runtime::capability_injector::CapabilityInjector;
use advance_runtime::circuit_breaker::{
    BreakerScope, BreakerState, CircuitBreaker, CircuitBreakerBus, DefaultCircuitBreakerBus,
};
use advance_runtime::config::WasmConfig;
use advance_runtime::host_registry::{
    HostCallContext, HostCallError, HostFunctionHandler, HostFunctionSpec, HostRegistry,
    InMemoryHostRegistry,
};
use advance_runtime::ComponentRuntime;
use advance_scheduler::hook::MessageHandler;
use advance_scheduler::types::ComponentConfig;
use advance_shared_types::agent_tree::{
    AgentId, AgentKind, AgentNode, AgentStatus, AgentTreeReader, AgentTreeSnapshot,
};
use advance_shared_types::await_session::{
    AgentAwaitRequest, AwaitMode, AwaitOptions, AwaitRequest, OrchestrationError, TimeoutPolicy,
};
use advance_shared_types::capability::{CapParams, CapRequest, CapabilityId, GrantDecision};
use advance_shared_types::event::Event;
use advance_shared_types::mailbox::{Message, MessageKind};
use advance_shared_types::run::TaskRunStatus;
use advance_shared_types::traits::{EventBusEmit, GrantCheck};
use cap_fs::{
    register_agent_fs, DefaultAtomicWriter, DefaultVirtualPathResolver, MetaSchemaLoader,
    StubFileHistoryProvider, VirtualPathResolver,
};
use cap_lifecycle::{
    AgentTreeStore, DefaultSpawner, DefaultTerminateController, GrantCascadeRevoke, LifecycleError,
    MailboxCascade, RunCascade, SpawnChildConfig, SpawnError, SpawnObserver, Spawner,
    SpawnerSubsetGate, TerminateController, WorkspaceCleanup,
};
use tempfile::TempDir;
use wasmtime::component::Val;

// The child driver: the minimal import-free guest — instantiates through the
// capabilities path with EMPTY caps and runs `handle-message` (a served turn) with
// no host-fn / grant dependency. Passed as the production `spawn-child` `binary`.
const CHILD_CORE: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-minimal.core.wasm");

const ROOT_BARE: &str = "default-agent";
const ROOT_COLON: &str = "agent:default";
const CHILD_BARE: &str = "childfoo";
const CHILD_COLON: &str = "agent:childfoo";

// ── stubs (mirrors the AC-19 witness) ────────────────────────────────────
struct AllowAll;
impl GrantCheck for AllowAll {
    fn check(&self, _: &str, _: &str, _: &str, _: &CapParams) -> GrantDecision {
        GrantDecision::Allow
    }
}
struct AllowAllSubset;
impl SpawnerSubsetGate for AllowAllSubset {
    fn check(
        &self,
        _p: &[advance_shared_types::agent_tree::Capability],
        _c: &[advance_shared_types::agent_tree::Capability],
    ) -> Result<(), SpawnError> {
        Ok(())
    }
}
struct CapturingBus {
    events: Mutex<Vec<Event>>,
}
impl EventBusEmit for CapturingBus {
    fn emit(&self, event: Event) {
        self.events.lock().unwrap().push(event);
    }
}

fn wasm_cfg() -> WasmConfig {
    WasmConfig {
        max_memory_pages: 256,
        epoch_interruption_ms: 100,
        fuel_enabled: false,
    }
}

struct Rig {
    mailbox_store: Arc<MailboxStore>,
    /// The REAL production send entrypoint (`handle_send`) over the SAME
    /// dispatcher + bridge — so the root→child send exercises the genuine
    /// `from` canonicalization (`agent:default`, not the mechanical
    /// `agent:default-agent`), not a hand-built envelope. (C1 audit fix.)
    manager: Arc<AwaitSessionManagerImpl>,
    routing: Arc<DynamicRouting>,
    bridge: Arc<AgentIdBridge>,
    mgr: Arc<PerChildLoopManager>,
    child_absent_pre: bool,
    child_present_post: bool,
}

impl Drop for Rig {
    fn drop(&mut self) {
        self.mgr.drain();
    }
}

/// Compose the production builders + the PerChildLoopManager, then drive a REAL
/// production `spawn_child` (the observer fires the seams). `skip_loop` /
/// `skip_routing` toggle the production seam for the two discriminators.
/// `child_bare` is the spawned child's bare id (normally [`CHILD_BARE`]; the
/// collision test passes `"default"`, whose mechanical colon hits the root's key).
async fn build_rig(skip_loop: bool, skip_routing: bool, child_bare: &str) -> Rig {
    let ws = TempDir::new().expect("tempdir");
    let ws_path = ws.path().to_path_buf();
    let territory = ws_path.join(ROOT_BARE);
    std::fs::create_dir_all(&territory).expect("territory");

    let bus: Arc<dyn EventBusEmit> = Arc::new(CapturingBus {
        events: Mutex::new(Vec::new()),
    });

    // Bare AgentTreeStore + the production root node.
    let bare_store = AgentTreeStore::new(ws_path.clone()).expect("bare store");
    bare_store
        .insert_root(AgentNode {
            id: AgentId(ROOT_BARE.to_string()),
            kind: AgentKind::Root,
            parent: None,
            workspace_path: territory.clone(),
            capabilities: vec![],
            template_ref: None,
            status: AgentStatus::Active,
        })
        .expect("insert root");

    // seam (e): dual-grammar DynamicRouting (colon map + bare delegation), seeded root.
    let routing = Arc::new(DynamicRouting::new(
        Arc::new(bare_store.clone()) as Arc<dyn AgentTreeReader>
    ));
    routing.seed_root(ROOT_COLON);
    // Registerable id-bridge seeded with the production root's colon/bare pair.
    let bridge = Arc::new(AgentIdBridge::from_pairs([(ROOT_COLON, ROOT_BARE)]));

    // Real MailboxStore + production dispatcher over the DynamicRouting tree.
    let mailbox_store = Arc::new(MailboxStore::new(NonZeroUsize::new(64).unwrap()));
    let dispatcher: Arc<dyn MailboxDispatcher> = Arc::new(
        MailboxDispatcherImpl::new(
            mailbox_store.clone(),
            routing.clone() as Arc<dyn AgentTreeReader>,
        )
        .with_id_bridge(bridge.clone()),
    );
    // C1 audit fix: the REAL production send entrypoint over that dispatcher, with
    // the SAME bridge in `ManagerOptions.id_bridge` — so `handle_send(ROOT_BARE, …)`
    // stamps the canonical `from = agent:default` (the production wiring in
    // `await_wiring::build_await_messaging_chain`), driving the genuine root→child
    // routing rather than a hand-built envelope.
    let manager = Arc::new(AwaitSessionManagerImpl::new(
        dispatcher.clone(),
        ManagerOptions {
            id_bridge: Some(bridge.clone()),
            ..ManagerOptions::default()
        },
    ));

    // Injector + runtime (production components).
    let registry: Arc<dyn HostRegistry> = Arc::new(InMemoryHostRegistry::new());
    let grant: Arc<dyn GrantCheck> = Arc::new(AllowAll);
    let breaker: Arc<dyn CircuitBreakerBus> = Arc::new(DefaultCircuitBreakerBus::new());
    let injector = Arc::new(CapabilityInjector::new(registry, grant, breaker));
    let runtime = Arc::new(ComponentRuntime::new(&wasm_cfg()).expect("runtime"));

    // seam (d): the PerChildLoopManager (the production observer). Bare→colon
    // resolver: root special, children mechanical. No grant store (no-cap child).
    let key_resolver: KeyResolver = Arc::new(|bare: &str| {
        if bare == ROOT_BARE {
            ROOT_COLON.to_string()
        } else {
            format!("agent:{bare}")
        }
    });
    let mgr = Arc::new(
        PerChildLoopManager::new(
            mailbox_store.clone(),
            bus.clone(),
            routing.clone(),
            bridge.clone(),
            None,
            bare_store.clone(),
            tokio::runtime::Handle::current(),
            key_resolver,
        )
        .with_toggles(skip_loop, skip_routing),
    );
    mgr.bind_runtime(runtime.clone(), injector.clone());

    // The production spawner with the observer attached.
    let spawner = DefaultSpawner::new(bare_store.clone(), Arc::new(AllowAllSubset))
        .with_spawn_observer(mgr.clone() as Arc<dyn SpawnObserver>);

    let child_absent_pre = !bare_store
        .snapshot()
        .nodes
        .iter()
        .any(|n| n.id.0 == child_bare);

    // Drive the REAL production spawn: the child driver bytes flow via the WIT
    // `binary` field (the spawn model — the child's CODE being test-supplied is
    // distinct from harness-supplied routing/loop). The observer fires the seams.
    spawner
        .spawn_child(SpawnChildConfig {
            parent_id: AgentId(ROOT_BARE.to_string()),
            child_id: AgentId(child_bare.to_string()),
            child_workspace_path: PathBuf::from("children").join(child_bare),
            capabilities: vec![],
            template_ref: None,
            binary: Some(CHILD_CORE.to_vec()),
        })
        .expect("spawn_child");

    let child_present_post = bare_store
        .snapshot()
        .nodes
        .iter()
        .any(|n| n.id.0 == child_bare);

    // Let the spawned serve loop bootstrap + park on its mailbox.
    tokio::time::sleep(Duration::from_millis(300)).await;

    Rig {
        mailbox_store,
        manager,
        routing,
        bridge,
        mgr,
        child_absent_pre,
        child_present_post,
    }
}

/// The genuine root→child send, driven through the PRODUCTION `handle_send` with
/// the BARE root id — so the manager's `canonical_sender` stamps the real
/// `from = agent:default` (NOT a hand-built `agent:default-agent`). Returns the
/// same `Result<(), MsgError>` the production send yields.
async fn root_sends_to_child(rig: &Rig) -> Result<(), MsgError> {
    rig.manager
        .handle_send(ROOT_BARE, CHILD_COLON, vec![0x27, 0x90], None)
        .await
}

fn child_mailbox_depth(store: &MailboxStore) -> usize {
    store.get(CHILD_COLON).map(|mb| mb.depth()).unwrap_or(0)
}

/// SYS-AC-279 core: a production spawn yields a live child — the loop-registry
/// entry + colon/bare routing + id-bridge registration EXIST (production,
/// non-harness), and the child's OWN `handle-message` turn runs on the routed
/// parent message.
#[tokio::test]
async fn sys_ac_279_spawn_yields_live_served_child() {
    let rig = build_rig(false, false, CHILD_BARE).await;

    // Runtime-spawn discriminator: child authored by the real spawn.
    assert!(rig.child_absent_pre, "child absent before spawn_child");
    assert!(rig.child_present_post, "child present after spawn_child");

    // Structural (asserted BEFORE any send) — all from PRODUCTION code:
    // colon/bare routing registered in DynamicRouting.
    assert!(
        rig.routing.agent_exists(CHILD_COLON),
        "seam (e): DynamicRouting has the child colon entry (non-harness)"
    );
    assert_eq!(
        rig.routing.parent_of(CHILD_COLON),
        Some(ROOT_COLON.to_string()),
        "seam (e): child's colon parent is the root"
    );
    // id-bridge registration (the ADR/criterion's literal 'id-bridge registration').
    assert_eq!(
        rig.bridge.resolve_owned(CHILD_COLON),
        Some((CHILD_BARE.to_string(), CHILD_COLON.to_string())),
        "seam (e): id-bridge resolves the spawned child's colon/bare pair"
    );

    // The root routes to the child via the PRODUCTION send path: `handle_send`
    // stamps the canonical `from = agent:default` (its `canonical_sender` resolving
    // the bare `default-agent` through the bridge), which `validate_routing` over
    // DynamicRouting admits as parent→child — NOT a harness-built `from`, and NOT
    // the mechanical `agent:default-agent` that would dead-end `no_adjacency`.
    let delivered = root_sends_to_child(&rig).await;
    assert!(
        delivered.is_ok(),
        "root→child send routes through the production send path (canonical from): {delivered:?}"
    );

    // Liveness (served-loop-exists): the child's OWN serve loop consumes + runs a
    // real `handle-message` turn (its recording TurnObserver fires). Bounded poll.
    let mut ran = false;
    for _ in 0..40 {
        if rig.mgr.child_turns(CHILD_COLON) >= 1 {
            ran = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        ran,
        "seam (c+d): the served child loop ran its OWN handle-message turn on the routed message"
    );
    // Consumed → the loop actually pulled the message off its mailbox.
    assert_eq!(
        child_mailbox_depth(&rig.mailbox_store),
        0,
        "the child serve loop consumed the routed message"
    );
    // seam (d) LOOP-REGISTRY (audit W1): the served child's loop handle is RETAINED
    // in the drain registry — proves the registry ENTRY exists (the daemon can abort
    // it at shutdown), not merely that a loop happened to run.
    assert_eq!(
        rig.mgr.active_loop_count(),
        1,
        "seam (d): the served child loop is retained in the shutdown-drain registry"
    );
}

/// Discriminator — child-loop-absent: routing IS registered so the parent send
/// routes + queues, but with NO served loop the child never runs a turn.
#[tokio::test]
async fn sys_ac_279_discriminator_child_loop_absent() {
    let rig = build_rig(true, false, CHILD_BARE).await;

    // Routing was registered (seam e ran); the loop was suppressed (seam d off).
    assert!(
        rig.routing.agent_exists(CHILD_COLON),
        "routing registered even with the loop suppressed"
    );
    let delivered = root_sends_to_child(&rig).await;
    assert!(delivered.is_ok(), "send routes + queues: {delivered:?}");

    // STRUCTURAL discriminator (audit W1/W2): `skip_loop` suppressed the serve
    // spawn, so NO loop handle is retained — a timing-INDEPENDENT proof that no loop
    // exists (the depth/turns checks below are secondary confirmation).
    assert_eq!(
        rig.mgr.active_loop_count(),
        0,
        "child-loop-absent: NO serve loop was retained in the registry"
    );
    // Give any (absent) loop time; the message stays QUEUED and no turn runs.
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(
        rig.mgr.child_turns(CHILD_COLON),
        0,
        "child-loop-absent → NO handle-message turn"
    );
    assert!(
        child_mailbox_depth(&rig.mailbox_store) >= 1,
        "the routed message sits queued (delivered, unconsumed)"
    );
}

/// Discriminator — routing-entry-absent: without the production routing
/// registration, the parent send dead-ends `unknown_target`.
#[tokio::test]
async fn sys_ac_279_discriminator_routing_entry_absent() {
    let rig = build_rig(false, true, CHILD_BARE).await;

    // The routing entry was suppressed (seam e off).
    assert!(
        !rig.routing.agent_exists(CHILD_COLON),
        "routing-entry-absent: DynamicRouting has NO child colon entry"
    );
    let delivered = root_sends_to_child(&rig).await;
    match delivered {
        Err(MsgError::InvalidTarget(reason)) => assert_eq!(
            reason, "unknown_target",
            "routing-entry-absent → unknown_target"
        ),
        other => panic!("expected unknown_target InvalidTarget, got {other:?}"),
    }
    // Nothing delivered, no turn.
    assert_eq!(child_mailbox_depth(&rig.mailbox_store), 0);
    assert_eq!(rig.mgr.child_turns(CHILD_COLON), 0);
    // The loop WAS served (only routing was suppressed), so its handle IS retained —
    // isolating this discriminator to the routing entry, not the loop (audit W1).
    assert_eq!(
        rig.mgr.active_loop_count(),
        1,
        "routing-entry-absent: the serve loop still runs (only routing suppressed)"
    );
}

/// audit r10 (confused-deputy guard): a runtime-spawned child whose BARE id
/// mechanically maps onto the ROOT's SPECIAL colon (`agent:default`) must NOT be
/// served — serving a loop on the root's key would hijack the root's mailbox. The
/// colliding child stays an unserved tree node; `agent:default` keeps the root's
/// identity, and no loop runs on it.
#[tokio::test]
async fn sys_ac_279_child_id_colliding_with_root_is_not_served() {
    // Spawn a child bare-named "default" → key_resolver's mechanical branch yields
    // colon "agent:default" == the ROOT's serve key (the reachable collision).
    let rig = build_rig(false, false, "default").await;

    // The spawn RECORDED the tree node (bare "default" != root bare "default-agent").
    assert!(
        rig.child_present_post,
        "the 'default' child tree node was recorded by the real spawn"
    );

    // But `agent:default` is STILL the ROOT (parent None): the colliding
    // register_child was REJECTED (first-wins), so no child reparented the root's
    // colon, and the id-bridge still resolves it to the root pair.
    assert_eq!(
        rig.routing.parent_of("agent:default"),
        None,
        "agent:default is still the ROOT — the colliding child was not reparented"
    );
    assert_eq!(
        rig.bridge.resolve_owned("agent:default"),
        Some((ROOT_BARE.to_string(), ROOT_COLON.to_string())),
        "agent:default still resolves to the root pair (child registration rejected)"
    );
    // The root's colon route SURVIVES the collision handling — still a LIVE, routable
    // ROOT, not merely `parent_of==None` (which is AMBIGUOUS: root OR absent). This
    // closes a fake-green where a `register_child` overwrite regression would let the
    // colliding child overwrite the root entry, and the guard's rollback
    // `unregister_child` would then DELETE the root's route (leaving `parent_of==None`
    // for the WRONG reason). `agent_exists` + `agent_kind==Root` prove the route is
    // intact. (audit adversarial r2)
    assert!(
        rig.routing.agent_exists(ROOT_COLON),
        "collision: the root's colon route SURVIVES (not deleted by the rejection)"
    );
    assert_eq!(
        rig.routing.agent_kind(ROOT_COLON),
        Some(AgentKind::Root),
        "collision: agent:default is still a live ROOT (not overwritten/absent)"
    );

    // STRUCTURAL discriminator (audit W1/W2): the colliding child was REJECTED before
    // the serve spawn, so NO loop handle is retained — a timing-INDEPENDENT proof that
    // no hijack loop exists on the root's key (the probe-consumption check below is a
    // secondary, timing-based confirmation). WITHOUT the guard this would be 1.
    assert_eq!(
        rig.mgr.active_loop_count(),
        0,
        "collision: the rejected child leaves NO retained serve loop on the root's key"
    );

    // DISCRIMINATOR (audit r11): deliver a message to the ROOT's mailbox key, then
    // prove it is NOT consumed. This is what makes the fix observable — the
    // structural assertions above are first-wins-INVARIANT (they hold with or
    // without the `on_child_spawned` guard, since `register_child`/`register` are
    // internally first-wins), and a bare `child_turns==0` would be VACUOUS (an empty
    // mailbox parks at `recv().await`). WITH the guard, no loop serves `agent:default`
    // so this probe sits UNCONSUMED (depth ≥ 1, 0 turns). WITHOUT the guard (the
    // confused-deputy bug), the colliding child's loop would be parked on
    // `recv("agent:default")` and would STEAL this probe — draining the mailbox and
    // running a turn. Both assertions below FLIP if the fix is reverted.
    rig.mailbox_store
        .get_or_create("agent:default")
        .expect("root mailbox")
        .deliver(Message {
            id: "sys-ac-279-collision-probe".to_string(),
            kind: MessageKind::Agent,
            from: "user:probe".to_string(),
            to: "agent:default".to_string(),
            payload: vec![0x01],
            context: None,
            timestamp: std::time::SystemTime::now(),
            origin: None,
        })
        .expect("deliver probe to the root's mailbox key");
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        rig.mgr.child_turns("agent:default"),
        0,
        "no hijack loop consumed the root's key (would be ≥1 if the collision child were served)"
    );
    assert!(
        rig.mailbox_store
            .get("agent:default")
            .map(|mb| mb.depth())
            .unwrap_or(0)
            >= 1,
        "the probe sits UNCONSUMED — no child loop hijacked the root's mailbox (would drain to 0 if served)"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Wave-24 `perchild-daemon-2` — SYS-AC-280/281/282
//
// These three journeys extend SYS-AC-279 (structural served child) into the
// LIVE production behaviours the resident per-child daemon must exhibit:
//   • SYS-AC-280 — the parent→child delegation ROUNDTRIP over the production
//     `build_await_messaging_chain` (event_bus + armed deadlock gate), served
//     by the `PerChildLoopManager` (NOT a hand-launched loop, NOT a
//     hand-supplied colon routing entry — both come from PRODUCTION code).
//   • SYS-AC-281 — the lifecycle legs on a SERVED production child: terminate
//     (seam-f loop_cascade), crash-cascade, and pause/breaker mailbox freeze.
//   • SYS-AC-282 — boot-declared config-tree children served at start with a
//     p99 delivery-latency SLO, via the REAL `materialize_config_tree` +
//     `serve_existing_children` primitives.
//
// Every discriminator toggles the PRODUCTION seam (loop-off, gate-arming,
// loop_cascade-absent, crash-skip, serve-skip) — not a harness fake.
// ═══════════════════════════════════════════════════════════════════════════

// The parent guest: awaits `agent:test-target`, writes on Ok, returns
// STATE_AWAIT_WRITE_OK. The child guest: sends `SEND_PAYLOAD` to `agent:parent`.
// The trap guest: traps in `handle-message` ("intentional guest trap"); imports
// agent-fs (so its fs cap must link at instantiation).
const AWAIT_WRITE_CORE: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-await-write.core.wasm");
const SEND_CORE: &[u8] = include_bytes!("../../runtime/tests/fixtures/guest-rust-send.core.wasm");
const TRAP_CORE: &[u8] = include_bytes!("fixtures/guest-rust-trap.core.wasm");

const STATE_AWAIT_WRITE_OK: [u8; 4] = [0xAC, 0x08, 0x14, 0x77];
const SEND_PAYLOAD: [u8; 4] = [0x5E, 0x4D, 0xB3, 0x01];

// The SYS-AC-280/281/282 root (distinct from the SYS-AC-279 `default-agent`
// root above): a mechanical `parent`↔`agent:parent` pair.
const PARENT_BARE: &str = "parent";
const PARENT_COLON: &str = "agent:parent";
// T-280's child bare id (guest-rust-await-write awaits `agent:test-target`).
const T280_CHILD_BARE: &str = "test-target";
const T280_CHILD_COLON: &str = "agent:test-target";
const T280_MASTER_KEY: &str = "4f0be08e7d1746246fe409f30f67df1826848f071d4608f41de29c5c082f9b31";
const T280_RUNTIME_YAML: &str = r#"wasm:
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
  env-var-name: SYS_J68_MASTER_KEY

post-processor:
  llm-model: sonnet-light
  llm-failure-cooldown-seconds: 600

database:
  db-path: ".runtime/index.db"
  pool-size: 4
"#;
const T280_AGENT_YAML: &str = "capabilities:\n  messaging: true\n";

// ── additive CapturingBus accessors (event oracle for T-280 + T-282) ─────────
impl CapturingBus {
    fn count(&self, ty: &str) -> usize {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.event_type == ty)
            .count()
    }
    fn events_of(&self, ty: &str) -> Vec<Event> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.event_type == ty)
            .cloned()
            .collect()
    }
    fn position_of(&self, ty: &str) -> Option<usize> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .position(|e| e.event_type == ty)
    }
}

fn cap(name: &str) -> advance_shared_types::agent_tree::Capability {
    advance_shared_types::agent_tree::Capability {
        id: CapabilityId::from(name),
        params: CapParams::empty(),
    }
}

// ── recording send-spy (copied from m001_ac19_multiagent_e2e) ────────────────
// Records the child's `(target, payload)` then delegates to the REAL SendHandler
// (records-then-delegates; the genuine reply routing still runs). Registered as
// the SINGLE `send` spec (the registry is append-only — a duplicate
// `(namespace,name)` fails at linker wiring, so reply-tracker must not also
// register `send`).
struct RecordingSendSpy {
    inner: SendHandler,
    recorded: Arc<Mutex<Vec<(String, Vec<u8>)>>>,
}
fn decode_payload_val(v: Option<&Val>) -> Option<Vec<u8>> {
    match v {
        Some(Val::List(items)) => {
            let mut out = Vec::with_capacity(items.len());
            for it in items {
                match it {
                    Val::U8(b) => out.push(*b),
                    _ => return None,
                }
            }
            Some(out)
        }
        _ => None,
    }
}
impl HostFunctionHandler for RecordingSendSpy {
    fn call(
        &self,
        ctx: HostCallContext,
        params: Vec<Val>,
        results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>> {
        if let Some(Val::String(t)) = params.first() {
            if let Some(payload) = decode_payload_val(params.get(1)) {
                self.recorded.lock().unwrap().push((t.clone(), payload));
            }
        }
        self.inner.call(ctx, params, results_len)
    }
}
fn register_recording_send_spy(
    registry: &dyn HostRegistry,
    manager: Arc<AwaitSessionManagerImpl>,
    recorded: Arc<Mutex<Vec<(String, Vec<u8>)>>>,
) {
    registry.register(HostFunctionSpec {
        capability: "messaging".to_string(),
        namespace: "advance:runtime/agent-messaging@0.1.0".to_string(),
        name: "send".to_string(),
        handler: Arc::new(RecordingSendSpy {
            inner: SendHandler::new(manager),
            recorded,
        }),
        idempotent: false,
    });
}

// ── no-op cascades for the terminate leg (loop_cascade is what's under test) ──
struct NoopGrant;
impl GrantCascadeRevoke for NoopGrant {
    fn revoke_for_agent(&self, _: &str) -> Result<(), LifecycleError> {
        Ok(())
    }
}
struct NoopMailbox;
impl MailboxCascade for NoopMailbox {
    fn flush_mailbox(&self, _: &str) -> Result<(), LifecycleError> {
        Ok(())
    }
    fn notify_parent_crash(&self, _: &str, _: &str, _: &str) -> Result<(), LifecycleError> {
        Ok(())
    }
}
struct NoopRun;
impl RunCascade for NoopRun {
    fn ensure_run(&self, _: &str) -> Result<(), LifecycleError> {
        Ok(())
    }
    fn cancel_run(&self, _: &str) -> Result<(), LifecycleError> {
        Ok(())
    }
}
struct NoopWorkspace;
impl WorkspaceCleanup for NoopWorkspace {
    fn remove_sub_workspace(&self, _: &std::path::Path) -> Result<(), LifecycleError> {
        Ok(())
    }
}

/// Find a `component.terminated` System crash report on `key`'s mailbox (copied
/// from sys_j10_child_trap). Returns the decoded payload, or `None`.
fn poll_crash_report(store: &MailboxStore, key: &str) -> Option<serde_json::Value> {
    let mb = store.get(key)?;
    let budget = mb.depth().saturating_add(4);
    for _ in 0..budget {
        let msg = match mb.poll() {
            Some(m) => m,
            None => break,
        };
        if msg.kind != MessageKind::System {
            continue;
        }
        if let Ok(p) = serde_json::from_slice::<serde_json::Value>(&msg.payload) {
            if p.get("event").and_then(|e| e.as_str()) == Some("component.terminated") {
                return Some(p);
            }
        }
    }
    None
}

async fn wait_run_parked(rm: &RunManager, rid: &RunId) -> bool {
    for _ in 0..400 {
        if let Ok(st) = rm.run_status(rid) {
            if matches!(st.status, TaskRunStatus::Suspended) && st.root_await.is_some() {
                return true;
            }
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    false
}

fn parent_msg_280(id: &str) -> Message {
    Message {
        id: id.to_string(),
        kind: MessageKind::User,
        from: "user:harness".to_string(),
        to: PARENT_COLON.to_string(),
        payload: vec![],
        context: None,
        timestamp: std::time::SystemTime::now(),
        origin: None,
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// T-280 (SYS-AC-280) — parent→child delegation roundtrip, armed gate.
// ═══════════════════════════════════════════════════════════════════════════

/// The T-280 rig: the AC-19 leg-a composition but over the PRODUCTION
/// `DynamicRouting` + a `PerChildLoopManager`-served child, with the messaging
/// chain built by the production `build_await_messaging_chain(..)` (the
/// event_bus arming + `agent_tree` deadlock-gate arming are LOAD-BEARING).
struct Rig280 {
    _ws: TempDir,
    _joint_ws: TempDir,
    _joint_host: RuntimeHost,
    _joint_handles: WiringHandles,
    bus: Arc<CapturingBus>,
    rm: Arc<RunManager>,
    rid: RunId,
    manager: Arc<AwaitSessionManagerImpl>,
    handler: Arc<WasmMessageHandler>,
    init_state: Vec<u8>,
    recorded_sends: Arc<Mutex<Vec<(String, Vec<u8>)>>>,
    mailbox_store: Arc<MailboxStore>,
    mgr: Arc<PerChildLoopManager>,
}
impl Drop for Rig280 {
    fn drop(&mut self) {
        self.mgr.drain();
    }
}

async fn build_rig_280(skip_loop: bool) -> Rig280 {
    let ws = TempDir::new().expect("tempdir");
    let ws_path = ws.path().to_path_buf();
    let territory = ws_path.join(PARENT_BARE);
    std::fs::create_dir_all(&territory).expect("territory");

    let bus = Arc::new(CapturingBus {
        events: Mutex::new(Vec::new()),
    });
    let bus_dyn: Arc<dyn EventBusEmit> = bus.clone();

    // Bare AgentTreeStore + production root (caps messaging+fs so the parent guest
    // can await + write).
    let bare_store = AgentTreeStore::new(ws_path.clone()).expect("bare store");
    bare_store
        .insert_root(AgentNode {
            id: AgentId(PARENT_BARE.to_string()),
            kind: AgentKind::Root,
            parent: None,
            workspace_path: territory.clone(),
            capabilities: vec![cap("messaging"), cap("fs")],
            template_ref: None,
            status: AgentStatus::Active,
        })
        .expect("insert root");

    // seam (e): DynamicRouting + registerable id-bridge, seeded with the root pair.
    let routing = Arc::new(DynamicRouting::new(
        Arc::new(bare_store.clone()) as Arc<dyn AgentTreeReader>
    ));
    routing.seed_root(PARENT_COLON);
    let bridge = Arc::new(AgentIdBridge::from_pairs([(PARENT_COLON, PARENT_BARE)]));

    // Reuse the exact jointly activated C216/C215 graph from the production
    // composition root.  A legacy MailboxStore here would make protected await
    // dispatch fail closed before the child can be served.
    static JOINT_HOME: OnceLock<TempDir> = OnceLock::new();
    static INIT_JOINT_ENV: std::sync::Once = std::sync::Once::new();
    INIT_JOINT_ENV.call_once(|| {
        std::env::set_var("SYS_J68_MASTER_KEY", T280_MASTER_KEY);
        let home = JOINT_HOME.get_or_init(|| tempfile::tempdir().expect("joint platform home"));
        let home_path = std::fs::canonicalize(home.path()).expect("canonical joint home");
        std::env::set_var("HOME", home_path);
    });
    let joint_ws = TempDir::new().expect("joint lifecycle workspace");
    let joint_path = std::fs::canonicalize(joint_ws.path()).expect("canonical joint workspace");
    std::fs::create_dir_all(joint_path.join(".advance")).expect("joint .advance");
    std::fs::create_dir_all(joint_path.join(".runtime/events/jsonl"))
        .expect("joint event directory");
    std::fs::create_dir_all(joint_path.join(".agent")).expect("joint .agent");
    let joint_config = joint_path.join(".advance/runtime-config.yaml");
    std::fs::write(&joint_config, T280_RUNTIME_YAML).expect("joint runtime config");
    std::fs::write(joint_path.join(".agent/config.yaml"), T280_AGENT_YAML)
        .expect("joint agent config");
    let joint_builder = RuntimeHostBuilder::new(&joint_config, &joint_path)
        .await
        .expect("joint runtime builder");
    let (joint_host, joint_handles) = wire_capabilities(joint_builder, &joint_path)
        .await
        .expect("joint C216/C215 production composition");
    let store = joint_handles
        .messaging_store
        .as_ref()
        .expect("joint protected mailbox store")
        .clone();
    let action_dispatcher = joint_handles
        .action_dispatcher_for_test()
        .expect("joint action dispatcher");
    let protected_boundary = joint_handles
        .protected_turn_boundary_for_test()
        .expect("joint execution boundary");

    // PRODUCTION messaging chain: event_bus (dispatcher `msg.received`) +
    // `agent_tree` (deadlock-gate arming) are both LOAD-BEARING here.
    let snapshot: Arc<dyn AgentTreeSnapshot> = Arc::new(bare_store.clone());
    let (manager, aref, _disp) = build_await_messaging_chain(
        store.clone(),
        routing.clone() as Arc<dyn AgentTreeReader>,
        bus_dyn.clone(),
        Some(bridge.clone()),
        Some(snapshot),
    );

    // RunManager + suspend sink (the park/resume lifecycle for the await).
    let rm = Arc::new(RunManager::new(bus_dyn.clone()).with_await_session_ref(aref));
    let rid = rm
        .ensure_run(PARENT_BARE, PARENT_BARE, RunConfig::default())
        .expect("ensure_run");
    let cell: SessionRunCell = Arc::new(OnceLock::new());
    cell.set(rid.clone()).expect("cell");
    let sink: Arc<dyn RunSuspendSink> = Arc::new(RunManagerSuspendSink::new(rm.clone()));

    // Shared host registry: recording send-spy + suspend-sink await + agent-fs.
    let registry: Arc<dyn HostRegistry> = Arc::new(InMemoryHostRegistry::new());
    let recorded_sends = Arc::new(Mutex::new(Vec::new()));
    register_recording_send_spy(&*registry, Arc::clone(&manager), recorded_sends.clone());
    register_reply_tracker_host_fns_with_suspend_sink(
        &*registry,
        Arc::clone(&manager),
        bus_dyn.clone(),
        Some(sink),
    );
    let resolver: Arc<dyn VirtualPathResolver> = Arc::new(DefaultVirtualPathResolver::new(
        ws_path.clone(),
        Arc::new(bare_store.clone()) as Arc<dyn AgentTreeSnapshot>,
    ));
    register_agent_fs(
        &*registry,
        resolver,
        bus_dyn.clone(),
        Arc::new(MetaSchemaLoader::new_with_default(PathBuf::new())),
        Arc::new(StubFileHistoryProvider),
        Arc::new(DefaultAtomicWriter),
        None,
        None,
        None,
        None,
        None,
    );

    let grant: Arc<dyn GrantCheck> = Arc::new(AllowAll);
    let breaker: Arc<dyn CircuitBreakerBus> = Arc::new(DefaultCircuitBreakerBus::new());
    let injector = Arc::new(CapabilityInjector::new(registry, grant, breaker));
    let runtime = Arc::new(ComponentRuntime::new(&wasm_cfg()).expect("runtime"));

    // seam (d): the PerChildLoopManager observer (mechanical resolver — root is
    // itself `agent:parent`, so no special mapping is needed).
    let key_resolver: KeyResolver = Arc::new(|bare: &str| format!("agent:{bare}"));
    let mgr = Arc::new(
        PerChildLoopManager::new(
            store.clone(),
            bus_dyn.clone(),
            routing.clone(),
            bridge.clone(),
            None,
            bare_store.clone(),
            tokio::runtime::Handle::current(),
            key_resolver,
        )
        .with_toggles(skip_loop, false)
        .with_progress_lifecycle(action_dispatcher, protected_boundary)
        // Select guest-rust-send's `send`-a-reply-to-parent branch (its multi-branch
        // fixture selector). The reply is a REAL `send` host-fn call routed through
        // the production dispatcher → `on_reply` → the parent's await resume — this
        // knob only picks which branch the fixture drives (a real child replies from
        // its own logic; production `PerChildLoopManager` passes `None`).
        .with_child_config_data(Some(b"send".to_vec())),
    );
    mgr.bind_runtime(runtime.clone(), injector.clone());

    // Production spawn of the child (guest-rust-send, caps messaging) — the
    // observer fires seams (d/e), so the child is SERVED with NO harness routing.
    let spawner = DefaultSpawner::new(bare_store.clone(), Arc::new(AllowAllSubset))
        .with_spawn_observer(mgr.clone() as Arc<dyn SpawnObserver>);
    spawner
        .spawn_child(SpawnChildConfig {
            parent_id: AgentId(PARENT_BARE.to_string()),
            child_id: AgentId(T280_CHILD_BARE.to_string()),
            child_workspace_path: PathBuf::from("children").join(T280_CHILD_BARE),
            capabilities: vec![cap("messaging")],
            template_ref: None,
            binary: Some(SEND_CORE.to_vec()),
        })
        .expect("spawn_child");

    // Parent handler (bare ctx `parent`), carrying a RunSession (park/resume).
    let parent_loaded = runtime
        .load_component(&build_agent::encode_core_to_component(AWAIT_WRITE_CORE).expect("encode"))
        .expect("parent component");
    let handler = Arc::new(
        WasmMessageHandler::new(
            runtime.clone(),
            parent_loaded,
            injector.clone(),
            vec![
                CapRequest {
                    capability: CapabilityId::from("messaging"),
                },
                CapRequest {
                    capability: CapabilityId::from("fs"),
                },
            ],
            PARENT_BARE.to_string(),
            "trace-280".to_string(),
        )
        .with_run_session(RunSession {
            run_manager: rm.clone(),
            cell: cell.clone(),
        }),
    );
    let init_state = handler
        .init(ComponentConfig {
            id: "test-parent".to_string(),
            config_data: Some(b"await-write".to_vec()),
            trigger_context: None,
        })
        .await
        .expect("parent init");

    // Let the served child loop bootstrap + park.
    tokio::time::sleep(Duration::from_millis(300)).await;

    Rig280 {
        _ws: ws,
        _joint_ws: joint_ws,
        _joint_host: joint_host,
        _joint_handles: joint_handles,
        bus,
        rm,
        rid,
        manager,
        handler,
        init_state,
        recorded_sends,
        mailbox_store: store,
        mgr,
    }
}

/// SYS-AC-280 core: the parent's `await-replies` request IS the cross-agent
/// message — dispatched via the PRODUCTION `DynamicRouting` into the
/// `PerChildLoopManager`-served child, whose OWN serve loop wakes, runs
/// `handle-message`, and issues a real `send` → the parent's await fiber resumes.
/// Event-grounded oracle (1 suspend + 1 resume(await_complete), ordered) + the
/// recording send-spy captures the child's payload + the served child ran a turn.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sys_ac_280_delegation_roundtrip_with_armed_gate() {
    let rig = build_rig_280(false).await;
    let rid = rig.rid.clone();
    let handler = rig.handler.clone();
    let init_state = rig.init_state.clone();

    let parent_task = tokio::spawn(async move {
        handler
            .handle_message(&parent_msg_280("msg-280-a"), init_state)
            .await
    });
    let result = tokio::time::timeout(Duration::from_secs(30), parent_task)
        .await
        .expect("parent resumes within 30s after the child's send")
        .expect("parent task panicked")
        .expect("parent handle_message Ok");
    assert_eq!(
        result.new_state, STATE_AWAIT_WRITE_OK,
        "the await returned Ok (a real reply resolved it via the served child)"
    );

    // Run resumed to Active, root_await cleared.
    let st = rig.rm.run_status(&rid).expect("status");
    assert!(
        matches!(st.status, TaskRunStatus::Active),
        "run resumed to Active (got {:?})",
        st.status
    );
    assert!(st.root_await.is_none(), "root_await cleared on resume");
    // Event oracle: exactly one suspend + one resume(await_complete); ordered.
    assert_eq!(
        rig.bus.count("run.suspended"),
        1,
        "one run.suspended (park)"
    );
    assert_eq!(
        rig.bus.count("run.resumed"),
        1,
        "one run.resumed (reply resume)"
    );
    let idx_s = rig
        .bus
        .position_of("run.suspended")
        .expect("suspend present");
    let idx_r = rig.bus.position_of("run.resumed").expect("resume present");
    assert!(idx_s < idx_r, "suspend precedes resume");
    let resumed = rig.bus.events_of("run.resumed");
    assert!(
        format!("{:?}", resumed[0]).contains("await_complete"),
        "run.resumed reason is await_complete: {:?}",
        resumed[0]
    );

    // Payload oracle: the child's real send round-tripped through the send host-fn.
    let sends = rig.recorded_sends.lock().unwrap().clone();
    assert!(
        sends
            .iter()
            .any(|(t, p)| t == PARENT_COLON && p.as_slice() == SEND_PAYLOAD),
        "the served child issued a real send(agent:parent, SEND_PAYLOAD); recorded={sends:?}"
    );
    // The child's OWN serve loop ran a `handle-message` turn.
    assert!(
        rig.mgr.child_turns(T280_CHILD_COLON) >= 1,
        "the PerChildLoopManager-served child ran its own turn on the delegated request"
    );
}

/// SYS-AC-280 discriminator (armed gate): with the deadlock gate ARMED via
/// `build_await_messaging_chain(.., Some(snapshot))`, an UPWARD await (child
/// awaits its ancestor parent) is whole-call `DeadlockDetected` before any
/// dispatch (parent mailbox stays empty). Control: the DOWNWARD parent→child
/// await is NOT deadlock-rejected (the `forms_cycle` gate is directional).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sys_ac_280_armed_gate_upward_await_deadlock() {
    let rig = build_rig_280(false).await;

    let res = rig
        .manager
        .start_with_run(
            T280_CHILD_BARE,
            None,
            vec![AwaitRequest::AgentRequest(AgentAwaitRequest {
                target: PARENT_COLON.to_string(),
                payload: vec![],
                correlation_id: "280-deadlock".to_string(),
                context: None,
            })],
            AwaitOptions {
                mode: AwaitMode::AllOf,
                idle_timeout_secs: Some(5),
                on_idle_timeout: TimeoutPolicy::Fail,
                keep_losers: false,
            },
        )
        .await;
    assert!(
        matches!(res, Err(OrchestrationError::DeadlockDetected(_))),
        "armed gate: upward child→ancestor await is whole-call DeadlockDetected; got {res:?}"
    );
    let depth = rig
        .mailbox_store
        .get(PARENT_COLON)
        .map(|mb| mb.depth())
        .unwrap_or(0);
    assert_eq!(
        depth, 0,
        "deadlock-rejected await dispatches nothing to parent"
    );

    // Control: the DOWNWARD parent→child await admits (directional gate).
    let down = tokio::time::timeout(
        Duration::from_millis(300),
        rig.manager.start_with_run(
            PARENT_BARE,
            None,
            vec![AwaitRequest::AgentRequest(AgentAwaitRequest {
                target: T280_CHILD_COLON.to_string(),
                payload: vec![],
                correlation_id: "280-control".to_string(),
                context: None,
            })],
            AwaitOptions {
                mode: AwaitMode::AllOf,
                idle_timeout_secs: Some(1),
                on_idle_timeout: TimeoutPolicy::ReturnPartial,
                keep_losers: false,
            },
        ),
    )
    .await;
    match down {
        Err(_elapsed) => { /* still parked / resolving → admitted */ }
        Ok(r) => assert!(
            !matches!(r, Err(OrchestrationError::DeadlockDetected(_))),
            "downward parent→child await must NOT be deadlock-rejected; got {r:?}"
        ),
    }
}

/// SYS-AC-280 discriminator (child-loop-off): with `skip_loop`, seam-(e) routing
/// IS registered so the await-request dispatches + the parent parks (1
/// run.suspended), but NO served loop handles it → 0 run.resumed within a bounded
/// grace, `child_turns == 0`, and the request sits queued in the child mailbox.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sys_ac_280_child_loop_off_parks_no_resume() {
    let rig = build_rig_280(true).await;
    let rid = rig.rid.clone();
    let handler = rig.handler.clone();
    let init_state = rig.init_state.clone();

    let parent = tokio::spawn(async move {
        handler
            .handle_message(&parent_msg_280("msg-280-noloop"), init_state)
            .await
    });
    assert!(
        wait_run_parked(&rig.rm, &rid).await,
        "parent parks (dispatch reached the child mailbox)"
    );
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(rig.bus.count("run.suspended"), 1, "the parent parked");
    assert_eq!(
        rig.bus.count("run.resumed"),
        0,
        "no resume (no served child loop handled the request)"
    );
    assert_eq!(
        rig.mgr.child_turns(T280_CHILD_COLON),
        0,
        "child-loop-off → no handle-message turn"
    );
    let depth = rig
        .mailbox_store
        .get(T280_CHILD_COLON)
        .map(|mb| mb.depth())
        .unwrap_or(0);
    assert!(
        depth >= 1,
        "the await-request sits queued in the child mailbox"
    );
    parent.abort();
}

// ═══════════════════════════════════════════════════════════════════════════
// T-281 (SYS-AC-281) — lifecycle legs on a SERVED production child.
// ═══════════════════════════════════════════════════════════════════════════

/// A rig that serves a production child (`childfoo` under root `parent`),
/// exposing the pieces the lifecycle legs drive: the bare tree, the mailbox
/// store, the DynamicRouting, the id-bridge, a `handle_send` entrypoint, and the
/// loop manager. `attach_crash`/`skip_crash` toggle the crash-cascade axis.
struct Rig281 {
    _ws: TempDir,
    bare_store: AgentTreeStore,
    store: Arc<MailboxStore>,
    routing: Arc<DynamicRouting>,
    manager: Arc<AwaitSessionManagerImpl>,
    mgr: Arc<PerChildLoopManager>,
}
impl Drop for Rig281 {
    fn drop(&mut self) {
        self.mgr.drain();
    }
}

async fn build_rig_281(
    child_core: &'static [u8],
    caps: Vec<advance_shared_types::agent_tree::Capability>,
    attach_crash: bool,
    skip_crash: bool,
) -> Rig281 {
    let ws = TempDir::new().expect("tempdir");
    let ws_path = ws.path().to_path_buf();
    let territory = ws_path.join(PARENT_BARE);
    std::fs::create_dir_all(&territory).expect("territory");

    let bus = Arc::new(CapturingBus {
        events: Mutex::new(Vec::new()),
    });
    let bus_dyn: Arc<dyn EventBusEmit> = bus.clone();

    let bare_store = AgentTreeStore::new(ws_path.clone()).expect("bare store");
    bare_store
        .insert_root(AgentNode {
            id: AgentId(PARENT_BARE.to_string()),
            kind: AgentKind::Root,
            parent: None,
            workspace_path: territory.clone(),
            capabilities: vec![],
            template_ref: None,
            status: AgentStatus::Active,
        })
        .expect("insert root");

    let routing = Arc::new(DynamicRouting::new(
        Arc::new(bare_store.clone()) as Arc<dyn AgentTreeReader>
    ));
    routing.seed_root(PARENT_COLON);
    let bridge = Arc::new(AgentIdBridge::from_pairs([(PARENT_COLON, PARENT_BARE)]));
    let store = Arc::new(MailboxStore::new(NonZeroUsize::new(64).unwrap()));

    let dispatcher: Arc<dyn MailboxDispatcher> = Arc::new(
        MailboxDispatcherImpl::new(store.clone(), routing.clone() as Arc<dyn AgentTreeReader>)
            .with_id_bridge(bridge.clone()),
    );
    let manager = Arc::new(AwaitSessionManagerImpl::new(
        dispatcher,
        ManagerOptions {
            id_bridge: Some(bridge.clone()),
            ..ManagerOptions::default()
        },
    ));

    // agent-fs so the trap child's agent-fs import links at instantiation (the
    // minimal child, caps [], never links it).
    let registry: Arc<dyn HostRegistry> = Arc::new(InMemoryHostRegistry::new());
    let resolver: Arc<dyn VirtualPathResolver> = Arc::new(DefaultVirtualPathResolver::new(
        ws_path.clone(),
        Arc::new(bare_store.clone()) as Arc<dyn AgentTreeSnapshot>,
    ));
    register_agent_fs(
        &*registry,
        resolver,
        bus_dyn.clone(),
        Arc::new(MetaSchemaLoader::new_with_default(PathBuf::new())),
        Arc::new(StubFileHistoryProvider),
        Arc::new(DefaultAtomicWriter),
        None,
        None,
        None,
        None,
        None,
    );

    let grant: Arc<dyn GrantCheck> = Arc::new(AllowAll);
    let breaker: Arc<dyn CircuitBreakerBus> = Arc::new(DefaultCircuitBreakerBus::new());
    let injector = Arc::new(CapabilityInjector::new(registry, grant, breaker));
    let runtime = Arc::new(ComponentRuntime::new(&wasm_cfg()).expect("runtime"));

    let key_resolver: KeyResolver = Arc::new(|bare: &str| format!("agent:{bare}"));
    let mut mgr_builder = PerChildLoopManager::new(
        store.clone(),
        bus_dyn.clone(),
        routing.clone(),
        bridge.clone(),
        None,
        bare_store.clone(),
        tokio::runtime::Handle::current(),
        key_resolver,
    );
    if attach_crash {
        // seam (f): the SOLE production CrashCascadeSink (bare parent → served
        // mailbox key `agent:{bare}`).
        let sink = advance_cli::crash_cascade::build_crash_cascade_sink(
            bare_store.clone(),
            store.clone(),
            |b: &str| format!("agent:{b}"),
        );
        mgr_builder = mgr_builder.with_crash_sink(sink);
    }
    if skip_crash {
        mgr_builder = mgr_builder.with_skip_crash(true);
    }
    let mgr = Arc::new(mgr_builder);
    mgr.bind_runtime(runtime.clone(), injector.clone());

    let spawner = DefaultSpawner::new(bare_store.clone(), Arc::new(AllowAllSubset))
        .with_spawn_observer(mgr.clone() as Arc<dyn SpawnObserver>);
    spawner
        .spawn_child(SpawnChildConfig {
            parent_id: AgentId(PARENT_BARE.to_string()),
            child_id: AgentId(CHILD_BARE.to_string()),
            child_workspace_path: PathBuf::from("children").join(CHILD_BARE),
            capabilities: caps,
            template_ref: None,
            binary: Some(child_core.to_vec()),
        })
        .expect("spawn_child");

    tokio::time::sleep(Duration::from_millis(300)).await;

    Rig281 {
        _ws: ws,
        bare_store,
        store,
        routing,
        manager,
        mgr,
    }
}

async fn drive_one_child_turn(rig: &Rig281, payload: Vec<u8>) {
    rig.manager
        .handle_send(PARENT_BARE, CHILD_COLON, payload, None)
        .await
        .expect("send to served child");
    for _ in 0..40 {
        if rig.mgr.child_turns(CHILD_COLON) >= 1 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("served child never ran a turn");
}

/// SYS-AC-281 terminate: the production `DefaultTerminateController` wired with
/// `.with_loop_cascade(PerChildLoopCascade)` aborts the terminating child's
/// serve loop (seam f) — after which `active_loop_count == 0`, routing no longer
/// resolves the child colon, a post-terminate send dead-ends `unknown_target`,
/// and no further turn runs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sys_ac_281_terminate_stops_served_child() {
    let rig = build_rig_281(CHILD_CORE, vec![], false, false).await;
    drive_one_child_turn(&rig, vec![0x01]).await;
    assert_eq!(rig.mgr.active_loop_count(), 1, "one served loop retained");

    // Non-vacuous DRAIN witness (Codex audit R7): freeze the child's mailbox and
    // queue a message it therefore CANNOT consume, so the post-terminate depth==0
    // proves `abort_child` DRAINED it (not the child having consumed it). A
    // regression deleting the drain loop would leave this message — the aborted
    // loop cannot consume it either.
    let child_mb = rig.store.get_or_create(CHILD_COLON).expect("child mailbox");
    child_mb.freeze();
    child_mb
        .deliver(Message {
            id: "281-drain-probe".to_string(),
            kind: MessageKind::Agent,
            from: PARENT_COLON.to_string(),
            to: CHILD_COLON.to_string(),
            payload: vec![0x03],
            context: None,
            timestamp: std::time::SystemTime::now(),
            origin: None,
        })
        .expect("deliver drain probe");
    assert!(
        child_mb.depth() >= 1,
        "drain probe queued (frozen, unconsumed) before terminate"
    );

    let controller = DefaultTerminateController::new(
        rig.bare_store.clone(),
        Arc::new(NoopGrant),
        Arc::new(NoopMailbox),
        Arc::new(NoopRun),
        Arc::new(NoopWorkspace),
    )
    .with_loop_cascade(Arc::new(PerChildLoopCascade::new(rig.mgr.clone())));

    let turns_before = rig.mgr.child_turns(CHILD_COLON);
    controller
        .terminate_child(PARENT_BARE, CHILD_BARE)
        .expect("terminate_child");

    assert_eq!(
        rig.mgr.active_loop_count(),
        0,
        "seam f: loop_cascade aborted + removed the served loop"
    );
    assert!(
        !rig.routing.agent_exists(CHILD_COLON),
        "seam f: colon routing unregistered on terminate"
    );
    match rig
        .manager
        .handle_send(PARENT_BARE, CHILD_COLON, vec![0x02], None)
        .await
    {
        Err(MsgError::InvalidTarget(r)) => {
            assert_eq!(r, "unknown_target", "post-terminate send dead-ends")
        }
        other => panic!("expected unknown_target after terminate, got {other:?}"),
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        rig.mgr.child_turns(CHILD_COLON),
        turns_before,
        "no further turn after terminate (loop is gone)"
    );
    assert_eq!(
        rig.store.get(CHILD_COLON).map(|mb| mb.depth()).unwrap_or(0),
        0,
        "seam f: abort_child DRAINED the terminated child's mailbox (drains per policy)"
    );
}

/// SYS-AC-281 terminate discriminator: WITHOUT `.with_loop_cascade`, the same
/// `terminate_child` removes the tree node but leaves the serve loop RUNNING —
/// `active_loop_count` stays 1, routing still resolves, and a post-terminate send
/// is consumed + runs a turn (the terminated child KEEPS serving). The loop
/// cascade is exactly what closes this gap.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sys_ac_281_terminate_without_loop_cascade_child_keeps_serving() {
    let rig = build_rig_281(CHILD_CORE, vec![], false, false).await;
    drive_one_child_turn(&rig, vec![0x01]).await;
    assert_eq!(rig.mgr.active_loop_count(), 1);

    let controller = DefaultTerminateController::new(
        rig.bare_store.clone(),
        Arc::new(NoopGrant),
        Arc::new(NoopMailbox),
        Arc::new(NoopRun),
        Arc::new(NoopWorkspace),
    ); // NO .with_loop_cascade — the discriminator
    controller
        .terminate_child(PARENT_BARE, CHILD_BARE)
        .expect("terminate_child");

    assert_eq!(
        rig.mgr.active_loop_count(),
        1,
        "WITHOUT loop_cascade the serve loop is NOT torn down"
    );
    assert!(
        rig.routing.agent_exists(CHILD_COLON),
        "WITHOUT loop_cascade the colon routing still resolves"
    );
    let before = rig.mgr.child_turns(CHILD_COLON);
    rig.manager
        .handle_send(PARENT_BARE, CHILD_COLON, vec![0x02], None)
        .await
        .expect("send still routes to the still-serving child");
    let mut advanced = false;
    for _ in 0..40 {
        if rig.mgr.child_turns(CHILD_COLON) > before {
            advanced = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        advanced,
        "WITHOUT the loop cascade the terminated child KEEPS serving (turn advanced)"
    );
}

/// SYS-AC-281 crash cascade: a SERVED trap child that traps mid-turn drives the
/// wired crash sink → the PARENT mailbox carries a `component.terminated` System
/// report naming the bare crashed child + the real guest-trap reason. The trigger
/// is a genuine guest trap in a real serve turn (NOT a direct `handle_crash`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sys_ac_281_crash_cascade_on_served_child() {
    let rig = build_rig_281(TRAP_CORE, vec![cap("fs")], true, false).await;
    rig.manager
        .handle_send(PARENT_BARE, CHILD_COLON, b"trigger-trap".to_vec(), None)
        .await
        .expect("send to trap child");

    let mut report = None;
    for _ in 0..80 {
        if let Some(p) = poll_crash_report(&rig.store, PARENT_COLON) {
            report = Some(p);
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let report = report.expect("the parent mailbox carries a component.terminated crash report");
    assert_eq!(report["event"], "component.terminated");
    assert_eq!(
        report["child"], CHILD_BARE,
        "the crash report names the BARE crashed child"
    );
    let reason = report["reason"].as_str().unwrap_or_default();
    assert!(
        reason.contains("intentional guest trap"),
        "the crash report carries the REAL guest trap reason; got {reason:?}"
    );
}

/// SYS-AC-281 crash discriminator: `with_skip_crash(true)` suppresses the seam-(f)
/// crash-sink attach — the identical trap produces NO crash report on the parent
/// mailbox (the cascade, not some always-on path, is what delivers it).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sys_ac_281_crash_cascade_skip_crash_no_report() {
    let rig = build_rig_281(TRAP_CORE, vec![cap("fs")], true, true).await;
    rig.manager
        .handle_send(PARENT_BARE, CHILD_COLON, b"trigger-trap".to_vec(), None)
        .await
        .expect("send to trap child");
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert!(
        poll_crash_report(&rig.store, PARENT_COLON).is_none(),
        "skip_crash → no crash sink attached → the parent receives NO crash report"
    );
}

/// SYS-AC-281 pause + breaker freeze: a SERVED child's mailbox holds delivered
/// messages while frozen — both via a DIRECT `freeze()`/`unfreeze()` and via the
/// production `BreakerSubscriber` routing an Agent-scoped Open/Closed
/// `BreakerEvent` to the mailbox. Frozen → no turn; unfrozen → the held message
/// is consumed.
///
/// SCOPE (honest disclosure): seam-f's breaker attach is the MODULE-006 **Layer-4**
/// mailbox freeze (HOLD queued messages + stop the child consuming = the "pauses the
/// child mailbox" criterion — resume on Closed), driven by `BreakerSubscriber` over
/// the shared store. It does NOT wire the separate **Layer-1** dispatcher gate
/// (`MailboxDispatcherImpl::with_circuit_breaker_bus`, which would REJECT new
/// deliveries while open) — that is an existing M006 mechanism outside this seam.
/// So a `handle_send` to a breaker-frozen child still ENQUEUES (asserted below); the
/// child just does not consume it until Closed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sys_ac_281_pause_and_breaker_freeze_child_mailbox() {
    let rig = build_rig_281(CHILD_CORE, vec![], false, false).await;
    assert_eq!(rig.mgr.active_loop_count(), 1, "served child loop");

    let mb = rig.store.get_or_create(CHILD_COLON).expect("child mailbox");

    // ── DIRECT freeze/unfreeze leg ──
    mb.freeze();
    rig.manager
        .handle_send(PARENT_BARE, CHILD_COLON, vec![0xA1], None)
        .await
        .expect("send while frozen");
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(
        rig.mgr.child_turns(CHILD_COLON),
        0,
        "frozen mailbox HOLDS the message — no turn runs"
    );
    assert!(mb.depth() >= 1, "the message sits queued while frozen");
    mb.unfreeze();
    let mut ran = false;
    for _ in 0..40 {
        if rig.mgr.child_turns(CHILD_COLON) >= 1 {
            ran = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        ran,
        "unfreeze → the child consumes the held message (turn runs)"
    );

    // ── BREAKER-driven freeze leg (BreakerSubscriber → mailbox freeze/unfreeze) ──
    let cb_bus: Arc<dyn CircuitBreakerBus> = Arc::new(DefaultCircuitBreakerBus::new());
    // Spawn the subscriber BEFORE opening (subscribe is append-only; open emits
    // only to already-subscribed senders).
    let _sub = BreakerSubscriber::spawn(cb_bus.clone(), rig.store.clone());
    cb_bus
        .open(CircuitBreaker {
            scope: BreakerScope::Agent,
            target: CHILD_COLON.to_string(),
            state: BreakerState::Open,
            kill_existing: false,
            reason: "sys-ac-281-breaker".to_string(),
        })
        .expect("open agent breaker");
    let mut frozen = false;
    for _ in 0..80 {
        if mb.is_frozen() {
            frozen = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(frozen, "breaker Open froze the child mailbox (Layer-4)");

    let before = rig.mgr.child_turns(CHILD_COLON);
    rig.manager
        .handle_send(PARENT_BARE, CHILD_COLON, vec![0xB2], None)
        .await
        .expect("send while breaker-frozen");
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(
        rig.mgr.child_turns(CHILD_COLON),
        before,
        "breaker-frozen mailbox HOLDS the delivery — no turn runs"
    );

    cb_bus
        .close(BreakerScope::Agent, CHILD_COLON)
        .expect("close agent breaker");
    let mut advanced = false;
    for _ in 0..80 {
        if rig.mgr.child_turns(CHILD_COLON) > before {
            advanced = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        advanced,
        "breaker Closed unfroze the mailbox → the held delivery is consumed"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// T-282 (SYS-AC-282) — boot-declared config-tree children served at start (SLO).
// ═══════════════════════════════════════════════════════════════════════════

/// The T-282 rig: root `parent`, ≥3 config-tree children materialized by the REAL
/// `materialize_config_tree` primitive (explorer template), each hand-provisioned
/// with a minimal driver, and — when `serve` — served at start by
/// `serve_existing_children` over the production messaging chain (event_bus
/// LOAD-BEARING → `msg.received` + `delivery_latency_ms`).
struct Rig282 {
    _ws: TempDir,
    bare_store: AgentTreeStore,
    routing: Arc<DynamicRouting>,
    bridge: Arc<AgentIdBridge>,
    manager: Arc<AwaitSessionManagerImpl>,
    mgr: Arc<PerChildLoopManager>,
    bus: Arc<CapturingBus>,
    child_aliases: Vec<String>,
}
impl Drop for Rig282 {
    fn drop(&mut self) {
        self.mgr.drain();
    }
}

async fn build_rig_282(serve: bool) -> Rig282 {
    let ws = TempDir::new().expect("tempdir");
    // Canonicalize (macOS /var→/private/var) so materialize's `resolve_under_parent`
    // containment check + the node workspace_path agree (mirrors the AC-25 witness).
    let ws_path = std::fs::canonicalize(ws.path()).expect("canonicalize ws");
    let territory = ws_path.join(PARENT_BARE);
    std::fs::create_dir_all(&territory).expect("territory");

    let bus = Arc::new(CapturingBus {
        events: Mutex::new(Vec::new()),
    });
    let bus_dyn: Arc<dyn EventBusEmit> = bus.clone();

    let bare_store = AgentTreeStore::new(ws_path.clone()).expect("bare store");
    bare_store
        .insert_root(AgentNode {
            id: AgentId(PARENT_BARE.to_string()),
            kind: AgentKind::Root,
            parent: None,
            workspace_path: territory.clone(),
            capabilities: vec![],
            template_ref: None,
            status: AgentStatus::Active,
        })
        .expect("insert root");

    let routing = Arc::new(DynamicRouting::new(
        Arc::new(bare_store.clone()) as Arc<dyn AgentTreeReader>
    ));
    routing.seed_root(PARENT_COLON);
    let bridge = Arc::new(AgentIdBridge::from_pairs([(PARENT_COLON, PARENT_BARE)]));
    let store = Arc::new(MailboxStore::new(NonZeroUsize::new(64).unwrap()));

    // PRODUCTION messaging chain — event_bus is LOAD-BEARING (the dispatcher emits
    // `msg.received` carrying `delivery_latency_ms`, the SLO signal).
    let snapshot: Arc<dyn AgentTreeSnapshot> = Arc::new(bare_store.clone());
    let (manager, _aref, _disp) = build_await_messaging_chain(
        store.clone(),
        routing.clone() as Arc<dyn AgentTreeReader>,
        bus_dyn.clone(),
        Some(bridge.clone()),
        Some(snapshot),
    );

    // Materialize ≥3 config-tree children via the REAL `materialize_config_tree`
    // (the `apply_auto_bootstrap` primitive) with the `explorer` template.
    let child_aliases = vec![
        "childa".to_string(),
        "childb".to_string(),
        "childc".to_string(),
    ];
    let decls: Vec<advance_cli::agent_config::AgentDecl> = child_aliases
        .iter()
        .map(|a| advance_cli::agent_config::AgentDecl {
            alias: a.clone(),
            template: "explorer".to_string(),
            target_path: PathBuf::from("children").join(a),
            children: vec![],
        })
        .collect();
    let tree_arc = Arc::new(bare_store.clone());
    advance_cli::wiring::materialize_config_tree(
        &tree_arc,
        &AgentId(PARENT_BARE.to_string()),
        &decls,
    )
    .expect("materialize_config_tree");

    // Operator-deploy analog: builtin templates ship NO driver, so hand-write a
    // minimal core to each child's `<ws>/.agent/behavior.wasm` (see the SLO test's
    // doc-comment for the disclosed boundary).
    for node in bare_store
        .snapshot()
        .nodes
        .iter()
        .filter(|n| n.parent.is_some())
    {
        let agent_dir = node.workspace_path.join(".agent");
        std::fs::create_dir_all(&agent_dir).expect("child .agent dir");
        std::fs::write(agent_dir.join("behavior.wasm"), CHILD_CORE).expect("write child driver");
    }

    let registry: Arc<dyn HostRegistry> = Arc::new(InMemoryHostRegistry::new());
    let grant: Arc<dyn GrantCheck> = Arc::new(AllowAll);
    let breaker: Arc<dyn CircuitBreakerBus> = Arc::new(DefaultCircuitBreakerBus::new());
    let injector = Arc::new(CapabilityInjector::new(registry, grant, breaker));
    let runtime = Arc::new(ComponentRuntime::new(&wasm_cfg()).expect("runtime"));

    let key_resolver: KeyResolver = Arc::new(|bare: &str| format!("agent:{bare}"));
    let mgr = Arc::new(PerChildLoopManager::new(
        store.clone(),
        bus_dyn.clone(),
        routing.clone(),
        bridge.clone(),
        None,
        bare_store.clone(),
        tokio::runtime::Handle::current(),
        key_resolver,
    ));
    mgr.bind_runtime(runtime.clone(), injector.clone());

    if serve {
        mgr.serve_existing_children();
        tokio::time::sleep(Duration::from_millis(400)).await;
    }

    Rig282 {
        _ws: ws,
        bare_store,
        routing,
        bridge,
        manager,
        mgr,
        bus,
        child_aliases,
    }
}

/// SYS-AC-282: boot-declared config-tree children (materialized by the REAL
/// `materialize_config_tree`) are ALL served at start (`active_loop_count >= 3`,
/// each routable + bridged), and a batch of deliveries meets the p99 < 1s
/// delivery-latency SLO (PRD §15.3.3).
///
/// DISCLOSED BOUNDARIES (two, both out of this witness's per-child-serve scope):
///   (i)  auto.bootstrap boot-CREATION trigger — the M015 `consult_auto_bootstrap`
///        primitive that DECIDES to materialize children at boot is out of scope
///        (waived_scope); this witness materializes them directly via the shared
///        `materialize_config_tree` primitive that primitive would call.
///   (ii) boot-child DRIVER provisioning — builtin templates ship NO `behavior_wasm`
///        (operator-deploy responsibility), so the witness supplies the driver
///        bytes (`<child_ws>/.agent/behavior.wasm`), the operator-deploy analog.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sys_ac_282_boot_declared_children_served_slo() {
    let rig = build_rig_282(true).await;

    // At start: every boot-declared child is a LIVE served loop, routable + bridged.
    assert!(
        rig.mgr.active_loop_count() >= 3,
        "boot-declared children are served at start (>=3 loops); got {}",
        rig.mgr.active_loop_count()
    );
    for a in &rig.child_aliases {
        let colon = format!("agent:{a}");
        assert!(
            rig.routing.agent_exists(&colon),
            "child {a} is routable at {colon}"
        );
        assert!(
            rig.bridge.resolve_owned(&colon).is_some(),
            "child {a}'s colon/bare pair is bridged"
        );
    }

    // Drive 5 deliveries per child = 15 (production `handle_send` → dispatcher
    // emits one `msg.received` carrying `delivery_latency_ms` per delivery).
    for a in &rig.child_aliases {
        let colon = format!("agent:{a}");
        for i in 0..5u8 {
            rig.manager
                .handle_send(PARENT_BARE, &colon, vec![i], None)
                .await
                .expect("send to boot-declared child");
        }
    }

    let mut lat: Vec<u64> = rig
        .bus
        .events_of("msg.received")
        .iter()
        .filter_map(|e| {
            e.payload
                .get("delivery_latency_ms")
                .and_then(|v| v.as_u64())
        })
        .collect();
    assert!(
        lat.len() >= 15,
        "one msg.received per delivery (>=15); got {}",
        lat.len()
    );
    lat.sort_unstable();
    let n = lat.len();
    let p99 = lat[((n - 1) * 99) / 100];
    assert!(
        p99 < 1000,
        "p99 delivery latency < 1s SLO; got {p99}ms (n={n})"
    );
}

/// SYS-AC-282 discriminator: a rig that SKIPS `serve_existing_children` — the ≥3
/// children exist as tree nodes (materialized) but NO serve loop starts
/// (`active_loop_count == 0`), no colon routing is registered, and a delivery
/// dead-ends `unknown_target` (queued-no-turn). `serve_existing_children` is what
/// makes the boot-declared children LIVE.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sys_ac_282_no_serve_children_dead_end() {
    let rig = build_rig_282(false).await;

    let nodes = rig.bare_store.snapshot().nodes;
    assert!(
        nodes.iter().filter(|n| n.parent.is_some()).count() >= 3,
        "the config-tree children ARE materialized as tree nodes"
    );
    assert_eq!(
        rig.mgr.active_loop_count(),
        0,
        "no serve loops without serve_existing_children"
    );
    for a in &rig.child_aliases {
        let colon = format!("agent:{a}");
        assert!(
            !rig.routing.agent_exists(&colon),
            "no colon routing entry registered without serve"
        );
        match rig
            .manager
            .handle_send(PARENT_BARE, &colon, vec![0x01], None)
            .await
        {
            Err(MsgError::InvalidTarget(r)) => {
                assert_eq!(r, "unknown_target", "unserved child delivery dead-ends")
            }
            other => panic!("expected unknown_target dead-end for {colon}, got {other:?}"),
        }
    }
}

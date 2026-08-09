//! Wave-23 `perchild-daemon-1` seam (d): [`PerChildLoopManager`] — the cli
//! composition root's [`SpawnObserver`] impl that makes a runtime-spawned child a
//! LIVE served agent inside the resident daemon (MODULE-001-AC-22, SYS-AC-279).
//!
//! On each successful `spawn_child`, once (post-`insert_child`) the manager:
//! - **(L1 grant)** delegates a subset-gated grant to the child for each of its
//!   declared capabilities via `GrantStore::delegate_grant` (which enforces
//!   active-parent / `caller==parent.grantee` / SUBSET / TTL+expiry clamp), so the
//!   child's own `send` passes the L1 grant gate — a served child that cannot act
//!   is not live;
//! - **(seam e)** registers the child's colon adjacency in the shared
//!   [`DynamicRouting`] + its colon/bare pair in the shared [`AgentIdBridge`], so a
//!   parent→child `send`/`await` routes with NO harness-supplied entry;
//! - **(seam c+d)** resolves the child workspace's materialized driver, loads it,
//!   and `tokio::spawn`s a per-agent [`AgentLoopDriverImpl`] serve loop keyed on the
//!   child COLON id (cap-id stays BARE), recorded in a loop-registry the daemon
//!   drains at shutdown.
//!
//! The post-`builder.build()` `ComponentRuntime` + `CapabilityInjector` are
//! LATE-BOUND (OnceLock) because `register_agent_spawn` — where the observer is
//! attached — runs before `builder.build()`.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};

use advance_messaging::{AgentIdBridge, DynamicRouting, MailboxStore};
use advance_runtime::{CapabilityInjector, ComponentRuntime};
use advance_scheduler::hook::{
    CrashCascadeSink, MessageHandler, ProtectedTurnExecutionBoundary, TurnObserver,
};
use advance_scheduler::types::{ComponentConfig, ComponentId, WasmInstance};
use advance_shared_types::agent_tree::{AgentId, AgentKind, AgentTreeReader, AgentTreeSnapshot};
use advance_shared_types::capability::CapRequest;
use advance_shared_types::mailbox::AgentActionDispatcher;
use advance_shared_types::traits::EventBusEmit;
use cap_grant::{GrantDraft, GrantStore, GrantTtl, SubsetValidatorImpl};
use cap_lifecycle::{AgentTreeStore, SpawnObserver};

use crate::agent_loop::{
    build_agent_loop, build_agent_loop_with_prebuilt_dispatcher, WasmMessageHandler,
};

/// Bare→colon key resolver (the crash-cascade pattern): the root is the special
/// pair (`default-agent`→`agent:default`), children are mechanical
/// (`child`→`agent:child`). The composition root — which alone knows the root's
/// special mapping — supplies it.
pub type KeyResolver = Arc<dyn Fn(&str) -> String + Send + Sync>;

/// Records each served child loop's turn completions so a witness can assert the
/// child ran its OWN `handle-message` (SYS-AC-279 liveness / child-loop-absent
/// discriminator).
#[derive(Default)]
pub struct RecordingTurnObserver {
    // Per-agent completed-turn COUNTS — NOT an unbounded per-turn log. A resident
    // daemon serves unboundedly many child turns over its lifetime, so a
    // `Vec<String>`-push-per-turn would grow without bound (audit r8 W4). A count
    // map is bounded by the number of DISTINCT served children, and `count()` is
    // O(1) instead of an O(n) scan.
    counts: Mutex<HashMap<String, usize>>,
}

impl RecordingTurnObserver {
    /// Number of completed turns recorded for `agent_id` (the colon serve key).
    pub fn count(&self, agent_id: &str) -> usize {
        self.counts
            .lock()
            .map(|c| c.get(agent_id).copied().unwrap_or(0))
            .unwrap_or(0)
    }
}

impl TurnObserver for RecordingTurnObserver {
    fn on_turn_complete(&self, agent_id: &str) {
        if let Ok(mut c) = self.counts.lock() {
            *c.entry(agent_id.to_string()).or_insert(0) += 1;
        }
    }
}

/// The cli composition root's per-child serve-loop manager (seam d). Shared as
/// `Arc<PerChildLoopManager>` — attached as the `DefaultSpawner`'s observer AND
/// retained by `WiringHandles` so `start.rs` can bind the post-build runtime and
/// drain the loops at shutdown.
pub struct PerChildLoopManager {
    // Late-bound post-`builder.build()`.
    runtime: OnceLock<Arc<ComponentRuntime>>,
    injector: OnceLock<Arc<CapabilityInjector>>,
    // Shared production deps (all exist before `register_agent_spawn`).
    store: Arc<MailboxStore>,
    event_bus: Arc<dyn EventBusEmit>,
    routing: Arc<DynamicRouting>,
    bridge: Arc<AgentIdBridge>,
    /// `None` disables grant delegation (a composed witness driving a no-cap child
    /// needs none, and avoids constructing a `GrantStore`); production passes
    /// `Some(cap_grant.store)`.
    grant_store: Option<Arc<GrantStore>>,
    tree: AgentTreeStore,
    handle: tokio::runtime::Handle,
    key_resolver: KeyResolver,
    turn_observer: Arc<RecordingTurnObserver>,
    /// Tee slice T3 (ADR 2026-07-22 D5): turn-end reap handle. When present the
    /// serve loop's observer becomes a fan-out (`RecordingTurnObserver` + reap), so
    /// a child turn that abandons a live LLM stream settles it at turn end. This is
    /// observer path (ii); the cli root is path (i) in `commands/start.rs`. The
    /// concrete `turn_observer` field TYPE is deliberately unchanged — existing
    /// MODULE-001-AC-22 witnesses read it through `turn_observer()`/`turn_count()`.
    llm_stream_reaper: std::sync::OnceLock<Arc<cap_llm::AgentStreamReaper>>,
    /// Loop-registry keyed by child COLON id (seam d + seam-f per-child abort).
    /// Keyed (not a flat `Vec`) so `abort_child` can abort + REMOVE exactly one
    /// child's loop, making `active_loop_count` deterministic.
    loops: Mutex<HashMap<String, tokio::task::JoinHandle<()>>>,
    /// seam (f): the shared crash-cascade sink attached to each child serve loop.
    /// Built once in wiring from the tree + mailbox store + resolver; it resolves
    /// the crashing agent's parent DYNAMICALLY, so one instance serves all agents.
    /// `None` in a witness that does not exercise the crash leg.
    crash_sink: Option<Arc<dyn CrashCascadeSink>>,
    /// Joint C215 dispatcher + C216 Store boundary. Production installs both
    /// from the one activation; legacy witnesses leave them absent.
    action_dispatcher: Option<Arc<dyn AgentActionDispatcher>>,
    protected_turn_boundary: Option<Arc<dyn ProtectedTurnExecutionBoundary>>,
    // Witness discriminator toggles (production default: all off).
    skip_loop: bool,
    skip_routing: bool,
    skip_crash: bool,
    /// Witness-only: the `config_data` handed to each spawned child's init
    /// `ComponentConfig` (production default `None` — a real child bootstraps its
    /// behaviour from its driver + workspace, not this fixture hook). A witness sets
    /// it to select a MULTI-BRANCH fixture's reply behaviour (e.g. `b"send"` →
    /// guest-rust-send issues its `send`-a-reply-to-parent turn). The reply itself,
    /// its routing, and the await resolution are ALL production — this only selects
    /// which branch the fixture exercises (a real child replies from its own logic).
    child_config_data: Option<Vec<u8>>,
}

impl PerChildLoopManager {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        store: Arc<MailboxStore>,
        event_bus: Arc<dyn EventBusEmit>,
        routing: Arc<DynamicRouting>,
        bridge: Arc<AgentIdBridge>,
        grant_store: Option<Arc<GrantStore>>,
        tree: AgentTreeStore,
        handle: tokio::runtime::Handle,
        key_resolver: KeyResolver,
    ) -> Self {
        Self {
            runtime: OnceLock::new(),
            injector: OnceLock::new(),
            store,
            event_bus,
            routing,
            bridge,
            grant_store,
            tree,
            handle,
            key_resolver,
            turn_observer: Arc::new(RecordingTurnObserver::default()),
            llm_stream_reaper: std::sync::OnceLock::new(),
            loops: Mutex::new(HashMap::new()),
            crash_sink: None,
            action_dispatcher: None,
            protected_turn_boundary: None,
            skip_loop: false,
            skip_routing: false,
            skip_crash: false,
            child_config_data: None,
        }
    }

    /// Witness-only: suppress the loop spawn (child-loop-absent discriminator) or
    /// the routing registration (routing-entry-absent discriminator). Production
    /// never sets these.
    pub fn with_toggles(mut self, skip_loop: bool, skip_routing: bool) -> Self {
        self.skip_loop = skip_loop;
        self.skip_routing = skip_routing;
        self
    }

    /// seam (f): attach the shared crash-cascade sink to each spawned child serve
    /// loop, so a trapping child turn drives `handle_crash` (child tree status →
    /// Failed + a parent `component.terminated` notice). Production builds the sink
    /// once in wiring and passes it here.
    pub fn with_crash_sink(mut self, sink: Arc<dyn CrashCascadeSink>) -> Self {
        self.crash_sink = Some(sink);
        self
    }

    /// Install the same jointly activated dispatcher/execution boundary used by
    /// the root loop. This is additive so older per-child witnesses remain on
    /// their explicitly legacy mailbox graph.
    pub fn with_progress_lifecycle(
        mut self,
        action_dispatcher: Arc<dyn AgentActionDispatcher>,
        protected_turn_boundary: Arc<dyn ProtectedTurnExecutionBoundary>,
    ) -> Self {
        self.action_dispatcher = Some(action_dispatcher);
        self.protected_turn_boundary = Some(protected_turn_boundary);
        self
    }

    /// Witness-only: suppress the seam-(f) crash-sink attach (the crash-cascade
    /// discriminator — WITHOUT the attach a trapping child drives no cascade).
    /// Production never sets this.
    pub fn with_skip_crash(mut self, skip_crash: bool) -> Self {
        self.skip_crash = skip_crash;
        self
    }

    /// Witness-only: set the `config_data` handed to each spawned child's init (a
    /// multi-branch fixture's behaviour selector). Production never sets this
    /// (default `None`); the reply/routing/await-resolution it enables are all
    /// production code paths.
    pub fn with_child_config_data(mut self, data: Option<Vec<u8>>) -> Self {
        self.child_config_data = data;
        self
    }

    /// Late-bind the post-`builder.build()` runtime + injector. Call once, after
    /// `wire_capabilities`'s `builder.build()`, before the root serve loop starts.
    pub fn bind_runtime(&self, runtime: Arc<ComponentRuntime>, injector: Arc<CapabilityInjector>) {
        let _ = self.runtime.set(runtime);
        let _ = self.injector.set(injector);
    }

    /// Install the tee-slice-T3 reap handle (observer path (ii)).
    ///
    /// Late-bound through a `OnceLock` — the manager is held behind an `Arc` by the
    /// time the composition root has the handle, matching this type's existing
    /// late-binding seams. Idempotent: a second install is ignored.
    pub fn set_llm_stream_reaper(&self, reaper: Arc<cap_llm::AgentStreamReaper>) {
        let _ = self.llm_stream_reaper.set(reaper);
    }

    /// The shared turn-recorder (for the witness liveness oracle).
    pub fn turn_observer(&self) -> Arc<RecordingTurnObserver> {
        self.turn_observer.clone()
    }

    /// Completed turns for the child colon id (witness liveness oracle).
    pub fn child_turns(&self, colon_id: &str) -> usize {
        self.turn_observer.count(colon_id)
    }

    /// Number of spawned child serve loops retained in the drain registry — the
    /// seam-(d) LOOP-REGISTRY the daemon aborts at shutdown. A served spawn pushes
    /// exactly one `JoinHandle`; a child that never serves (driverless / load-fail /
    /// colon-id collision / the `skip_loop` discriminator) registers none. A witness
    /// asserts this to prove the loop-registry entry EXISTS (not merely that a loop
    /// happened to run) and, for the collision guard, that a rejected child leaves
    /// NO retained loop.
    pub fn active_loop_count(&self) -> usize {
        // Count LIVE loops only: a naturally-returned serve leaves a FINISHED
        // handle in the map (no self-removal — that would race the post-spawn
        // insert), and `abort_child` REMOVES an aborted one synchronously.
        // Filtering `!is_finished()` keeps the count accurate for both paths
        // without a race, and preserves the SYS-AC-279 served-parked==1 /
        // absent==0 semantics (a served child parks on `recv`, never finishing).
        self.loops
            .lock()
            .map(|l| l.values().filter(|h| !h.is_finished()).count())
            .unwrap_or(0)
    }

    /// Abort all spawned child serve loops (daemon shutdown drain).
    pub fn drain(&self) {
        if let Ok(mut loops) = self.loops.lock() {
            for h in loops.values() {
                h.abort();
            }
            loops.clear();
        }
    }

    /// seam (f) terminate: abort ONE child's serve loop and tear down its
    /// per-child state, colon-correctly. `terminate_child` hands cascades the
    /// BARE id, but the loop-registry + routing + mailbox are COLON-keyed, so
    /// resolve bare→colon FIRST. Steps: (1) abort + REMOVE the retained loop
    /// handle (so `active_loop_count` decrements deterministically, not on the
    /// async `abort()` landing); (2) UNFREEZE then best-effort drain the colon
    /// mailbox (a prior breaker-open leaves it frozen, and `poll()` returns
    /// `None` while frozen — terminate must drain regardless); (3) unregister the
    /// colon routing + id-bridge pair so a post-terminate parent send dead-ends
    /// `unknown_target` rather than black-holing into a now-unserved mailbox.
    /// Idempotent; a bare id with no served loop still tears down routing + mailbox.
    pub fn abort_child(&self, bare_id: &str) {
        let colon = (self.key_resolver)(bare_id);
        // Root-collision guard (mirrors `on_child_spawned`'s serve-path guard @below):
        // a child whose bare id mechanically maps onto the ROOT's colon (a guest
        // `spawn-child(id="default")` → `agent:default`, the root's serve/mailbox key)
        // must NOT have the ROOT's mailbox unfrozen/drained — that would be a
        // confused-deputy message-loss on the most-privileged agent. `unregister_child`
        // / `bridge.unregister` already refuse the seed root, so the mailbox drain is
        // the sole exposure; bail out entirely when the colon IS the root (the root's
        // loop is served by `start.rs`, never retained in this registry — nothing to
        // abort). `agent_kind` reads the seeded root's colon kind from `DynamicRouting`.
        if self.routing.agent_kind(&colon) == Some(AgentKind::Root) {
            return;
        }
        if let Ok(mut loops) = self.loops.lock() {
            if let Some(h) = loops.remove(&colon) {
                h.abort();
            }
        }
        // Unregister routing + id-bridge FIRST, so a concurrent send dead-ends at
        // `validate_routing` (`unknown_target`) rather than passing the still-present
        // colon route and enqueueing into a now-unserved mailbox AFTER the drain
        // (the send-vs-terminate race — narrow the window by removing the route before
        // draining).
        self.routing.unregister_child(&colon);
        self.bridge.unregister(&colon, bare_id);
        // THEN unfreeze + best-effort drain any message that enqueued before the
        // unregister (a prior breaker-open leaves the mailbox frozen, and `poll`
        // returns `None` while frozen — terminate must drain regardless).
        if let Some(mb) = self.store.get(&colon) {
            mb.unfreeze();
            let mut budget = mb.depth().saturating_add(8);
            while budget > 0 && mb.poll().is_some() {
                budget -= 1;
            }
        }
    }

    /// Boot leg: serve every NON-ROOT child already present in the tree at daemon
    /// start — the config-tree `agents:` children `materialize_config_tree` created
    /// (M005-AC-25) and any auto-bootstrap child materialized via the shared
    /// `apply_auto_bootstrap` primitive (M015-AC-22) — by driving the SAME per-child
    /// serve path (`on_child_spawned`) a runtime spawn uses. Class-agnostic: it
    /// serves whatever non-root nodes exist. BFS from the root (via `children_of`)
    /// so a parent's colon adjacency is registered before its children's. Invoked
    /// ONCE at daemon start, after the root serve loop, via
    /// `wiring_handles.perchild_manager`; the loops it registers are drained by the
    /// existing shutdown `drain()`.
    pub fn serve_existing_children(&self) {
        let snapshot = self.tree.snapshot();
        let Some(root) = snapshot.nodes.iter().find(|n| n.parent.is_none()) else {
            return;
        };
        let mut queue: std::collections::VecDeque<AgentId> = snapshot
            .children_of
            .get(&root.id)
            .cloned()
            .unwrap_or_default()
            .into();
        while let Some(child_id) = queue.pop_front() {
            let Some(node) = snapshot.nodes.iter().find(|n| n.id == child_id) else {
                continue;
            };
            if let Some(parent) = node.parent.as_ref() {
                self.on_child_spawned(parent, &node.id, &node.workspace_path);
            }
            if let Some(grandchildren) = snapshot.children_of.get(&child_id) {
                queue.extend(grandchildren.iter().cloned());
            }
        }
    }

    /// Test-support seam for composition witnesses that stop after
    /// `wire_capabilities` and therefore do not execute `advance start`'s
    /// subsequent `serve_existing_children` boot step.  It registers the exact
    /// same colon routing/id-bridge pairs for already-materialized children,
    /// without spawning loops that would race the witness for mailbox turns.
    /// Production has no caller: the daemon uses `serve_existing_children`.
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn register_existing_routes_for_test(&self) -> usize {
        let snapshot = self.tree.snapshot();
        let Some(root) = snapshot.nodes.iter().find(|node| node.parent.is_none()) else {
            return 0;
        };
        let mut queue: std::collections::VecDeque<AgentId> = snapshot
            .children_of
            .get(&root.id)
            .cloned()
            .unwrap_or_default()
            .into();
        let mut registered = 0;
        while let Some(child_id) = queue.pop_front() {
            let Some(node) = snapshot.nodes.iter().find(|node| node.id == child_id) else {
                continue;
            };
            if let Some(parent) = node.parent.as_ref() {
                let child_colon = (self.key_resolver)(node.id.0.as_str());
                let parent_colon = (self.key_resolver)(parent.0.as_str());
                let routed = self.routing.register_child(&child_colon, &parent_colon);
                let bridged = self.bridge.register(&child_colon, node.id.0.as_str());
                assert_eq!(
                    routed, bridged,
                    "test route registration must be atomic across routing and bridge"
                );
                if routed {
                    registered += 1;
                }
            }
            if let Some(grandchildren) = snapshot.children_of.get(&child_id) {
                queue.extend(grandchildren.iter().cloned());
            }
        }
        registered
    }

    /// Delegate the child's declared caps (subset-gated) from the parent's held
    /// grants via the first-class `delegate_grant` primitive (which enforces
    /// active-parent / caller==parent.grantee / SUBSET / TTL+expiry clamp — the
    /// child grant provably cannot widen or outlive the parent). Best-effort per
    /// cap: a cap the parent does not hold is simply not delegated.
    fn delegate_child_grants(&self, parent_bare: &str, child_bare: &str, caps: &[CapRequest]) {
        let Some(grant_store) = self.grant_store.as_ref() else {
            return;
        };
        let parent_grants = grant_store.list_by_grantee(parent_bare);
        let validator = SubsetValidatorImpl::new();
        for cap in caps {
            let cap_name = cap.capability.as_str();
            let Some(pg) = parent_grants
                .iter()
                .find(|g| g.capability.as_str() == cap_name)
            else {
                continue;
            };
            let draft = GrantDraft {
                capability: cap_name.to_string(),
                params: Vec::new(),
                ttl: GrantTtl::Persistent,
            };
            let _ = grant_store.delegate_grant(
                pg.id.as_str(),
                child_bare,
                draft,
                parent_bare,
                &validator,
            );
        }
    }
}

impl SpawnObserver for PerChildLoopManager {
    fn on_child_spawned(&self, parent: &AgentId, child: &AgentId, workspace: &Path) {
        let parent_bare = parent.0.as_str();
        let child_bare = child.0.as_str();
        let child_colon = (self.key_resolver)(child_bare);
        let parent_colon = (self.key_resolver)(parent_bare);

        // The child's declared capabilities (from the freshly-inserted tree node).
        let caps: Vec<CapRequest> = self
            .tree
            .get_node(child)
            .map(|n| {
                n.capabilities
                    .iter()
                    .map(|c| CapRequest {
                        capability: c.id.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default();

        // seam (d).i — L1 grant delegation so the child can act.
        self.delegate_child_grants(parent_bare, child_bare, &caps);

        // Discriminator: child-loop-absent — register seam-(e) routing but serve NO
        // loop (the intentional routable-but-unserved state the witness asserts).
        if self.skip_loop {
            if !self.skip_routing {
                self.routing.register_child(&child_colon, &parent_colon);
                self.bridge.register(&child_colon, child_bare);
            }
            return;
        }

        // seam (c)+(d) — resolve the child driver, then serve the per-agent loop.
        // A driverless / resolve-failing / load-failing spawn returns BELOW WITHOUT
        // registering seam-(e) routing (audit r7 W1) — never a routable-but-unserved
        // child. seam-(e) registration happens AFTER a successful `load_component`
        // but BEFORE the spawn, and the spawned task TEARS IT DOWN when `serve`
        // returns (a component that loaded but trapped in `bootstrap_and_init`, or a
        // guest stop — audit r8 W2), so a child is routable EXACTLY while its loop can
        // run. (`skip_loop` above is the sole intentional register-without-loop path.)
        let (Some(runtime), Some(injector)) = (self.runtime.get(), self.injector.get()) else {
            eprintln!("perchild: runtime/injector not bound; child {child_bare} not served");
            return;
        };
        let bytes = match crate::commands::start::resolve_driver_component_bytes(workspace) {
            Ok(Some((_, bytes))) => bytes,
            Ok(None) => {
                eprintln!("perchild: child {child_bare} has no driver; not served");
                return;
            }
            Err(e) => {
                eprintln!("perchild: child {child_bare} driver resolve failed: {e}");
                return;
            }
        };
        let loaded = match runtime.load_component(&bytes) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("perchild: child {child_bare} load failed: {e:?}");
                return;
            }
        };
        // BARE cap-id (the L1 grant grantee + `send` `from` body), COLON serve key.
        let handler: Arc<dyn MessageHandler> = Arc::new(WasmMessageHandler::new(
            runtime.clone(),
            loaded,
            injector.clone(),
            caps,
            child_bare.to_string(),
            format!("trace-child-{child_bare}"),
        ));
        // Tee slice T3, observer path (ii): fan out to the recording observer AND
        // the turn-end reap. Recording runs first so existing MODULE-001-AC-22
        // witnesses observe the same counts they always did.
        let obs: Arc<dyn TurnObserver> = match self.llm_stream_reaper.get().cloned() {
            Some(reaper) => Arc::new(crate::reap::CompositeTurnObserver::new(vec![
                self.turn_observer.clone(),
                // §5.2 item 5: the authoritative (serve-key, cap-id) pair is injected
                // verbatim from the SAME locals this spawn serves under — never
                // re-derived from the serve id by string surgery.
                Arc::new(crate::reap::ReapTurnObserver::for_agent(
                    reaper,
                    child_colon.clone(),
                    child_bare.to_string(),
                )),
            ])),
            None => self.turn_observer.clone(),
        };
        let mut driver = match (
            self.action_dispatcher.as_ref(),
            self.protected_turn_boundary.as_ref(),
        ) {
            (Some(dispatcher), Some(boundary)) => build_agent_loop_with_prebuilt_dispatcher(
                self.store.clone(),
                handler,
                dispatcher.clone(),
            )
            .with_protected_turn_boundary(boundary.clone()),
            _ => build_agent_loop(self.store.clone(), handler, self.event_bus.clone(), None),
        }
        .with_turn_observer(obs);
        // seam (f): attach the crash-cascade sink so a trapping child turn drives
        // `handle_crash` (child tree status → Failed + parent `component.terminated`).
        // `skip_crash` (witness-only) suppresses it for the crash-cascade discriminator.
        if !self.skip_crash {
            if let Some(sink) = self.crash_sink.as_ref() {
                driver = driver.with_crash_cascade(sink.clone());
            }
        }
        let cfg = ComponentConfig {
            id: child_bare.to_string(),
            config_data: self.child_config_data.clone(),
            trigger_context: None,
        };
        let component_id = match ComponentId::new(format!("agent-{child_bare}-inst")) {
            Ok(c) => c,
            Err(_) => {
                eprintln!("perchild: child {child_bare} invalid component id");
                return;
            }
        };
        let instance = WasmInstance::new(component_id);
        let serve_key = child_colon.clone();
        // seam (e) — the driver LOADED, so register colon routing + the id-bridge
        // pair BEFORE the serve loop starts (a load-failing spawn returned above
        // without registering). Registered BEFORE the spawn so the teardown below can
        // never race ahead of the registration.
        //
        // audit r10 — COLON-ID COLLISION GUARD: `register_child` / `register` are
        // FIRST-WINS and return `false` when `child_colon` (or its bare form) already
        // belongs to another agent. The reachable case is a child whose bare id
        // MECHANICALLY maps onto the ROOT's SPECIAL colon — a guest
        // `spawn-child(id="default")` resolves to `agent:default`, the root's OWN
        // serve key (`validate_agent_id` is charset-only, no reserved-name guard).
        // Serving a loop on a colliding key would poll the INCUMBENT's mailbox — a
        // confused-deputy / message-theft hijack of the root. So on ANY rejected
        // registration, roll back a partial registration and DO NOT serve: the child
        // stays an unserved tree node (safe; the incumbent keeps its mailbox intact).
        // (`skip_routing` — a witness discriminator — intentionally serves without
        // registering and is production-unreachable.)
        if !self.skip_routing {
            let routed = self.routing.register_child(&child_colon, &parent_colon);
            let bridged = self.bridge.register(&child_colon, child_bare);
            if !routed || !bridged {
                if routed {
                    self.routing.unregister_child(&child_colon);
                }
                if bridged {
                    self.bridge.unregister(&child_colon, child_bare);
                }
                eprintln!(
                    "perchild: child {child_bare} colon id {child_colon} collides with an \
                     existing agent; not served (tree node recorded, unrouted)"
                );
                return;
            }
        }
        // audit r8 W2 — when `serve` RETURNS (a component that loaded but trapped in
        // `bootstrap_and_init`, or a guest stop), the loop is no longer live: TEAR
        // DOWN the seam-(e) registration so a parent send then dead-ends cleanly
        // (`unknown_target`) rather than black-holing into a now-unserved mailbox.
        let cleanup = (!self.skip_routing).then(|| {
            (
                self.routing.clone(),
                self.bridge.clone(),
                child_colon.clone(),
                child_bare.to_string(),
            )
        });
        let handle = self.handle.spawn(async move {
            driver.serve(&serve_key, cfg, instance).await;
            if let Some((routing, bridge, colon, bare)) = cleanup {
                routing.unregister_child(&colon);
                bridge.unregister(&colon, &bare);
            }
        });
        if let Ok(mut loops) = self.loops.lock() {
            loops.insert(child_colon, handle);
        }
    }
}

/// seam (f) glue: a cap-lifecycle [`cap_lifecycle::LoopCascade`] backed by the
/// [`PerChildLoopManager`]. A `DefaultTerminateController` wired with
/// `.with_loop_cascade(..)` uses it to abort a terminating child's serve loop + tear
/// down its colon routing / mailbox. `abort_loop` forwards the BARE tree id
/// `terminate_child` provides; `PerChildLoopManager::abort_child` resolves it to the
/// colon serve key.
///
/// **NOT wired into `advance start` this wave** (UNLIKE seam-f's crash sink, which IS
/// wired to the root + child loops this wave): `wire_capabilities` registers only
/// `register_agent_spawn` + `register_agent_decomposition`, NOT the full
/// `register_agent_lifecycle` bundle, so no production `terminate-child` controller
/// exists to attach this cascade to yet. The seam-f terminate leg is
/// witnessed at the composed-production-builders level (SYS-J-68 `sys_ac_281_*` construct
/// the production `DefaultTerminateController` + this adapter directly) — the mechanism is
/// proven; its guest-WIT production wiring is a later wave. (MODULE-001-AC-22 FLIPS at the
/// sanctioned composed-production-builders bar — its witness floor + seam-(f)'s NAMED
/// production mechanisms, `build_crash_cascade_sink` + `BreakerSubscriber` + the AC-21
/// cascade, ARE production callers; this terminate `abort_child` production caller is the
/// one disclosed deferral, recorded in the lane's `waived_scope`. Adversarial R13 H4:
/// user-accepted flip-with-caveat, 2026-07-09.)
pub struct PerChildLoopCascade {
    manager: Arc<PerChildLoopManager>,
}

impl PerChildLoopCascade {
    pub fn new(manager: Arc<PerChildLoopManager>) -> Self {
        Self { manager }
    }
}

impl cap_lifecycle::LoopCascade for PerChildLoopCascade {
    fn abort_loop(&self, agent_id: &str) {
        self.manager.abort_child(agent_id);
    }
}

//! Wave-23 `perchild-daemon-1` seam (d): [`PerChildLoopManager`] — the cli
//! composition root's [`SpawnObserver`] impl that makes a runtime-spawned child a
//! LIVE served agent inside the resident daemon (MODULE-001-AC-22, SYS-AC-279).
//!
//! On each successful `spawn_child`, once (post-`insert_child`) the manager:
//! - **(L1 grant)** delegates a subset-gated grant to the child for each of its
//!   declared capabilities via `GrantStore::delegate_grant` (which enforces
//!   active-parent / `caller==parent.grantee` / SUBSET / TTL+expiry clamp), so the
//!   child's own `send` passes the L1 grant gate — a served child that cannot act
//!   is not live. A capability declared with params is delegated with exactly
//!   those params; a bare one takes the parent grant's params. The parent's
//!   grants for the capability are tried in id order, and the first that accepts
//!   the delegation is used;
//! - **(seam e)** registers the child's colon adjacency in the shared
//!   [`DynamicRouting`] + its colon/bare pair in the shared [`AgentIdBridge`], so a
//!   parent→child `send`/`await` routes with NO harness-supplied entry;
//! - **(seam c+d)** resolves the child workspace's materialized driver, loads it,
//!   and `tokio::spawn`s a per-agent [`AgentLoopDriverImpl`] serve loop keyed on the
//!   child COLON id (cap-id stays BARE), recorded in a loop-registry the daemon
//!   drains at shutdown.
//!
//! The post-`builder.build()` `ComponentRuntime` + `CapabilityInjector` are
//! LATE-BOUND because `register_agent_spawn` — where the observer is attached —
//! runs before `builder.build()`. They are released again at shutdown
//! ([`PerChildLoopManager::unbind`]): the injector reaches the host registry,
//! whose spawn handler holds this manager as its observer, so while both stay
//! bound the manager and the registry keep each other alive.

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use advance_messaging::{AgentIdBridge, DynamicRouting, MailboxStore};
use advance_runtime::{CapabilityInjector, ComponentRuntime};
use advance_scheduler::hook::{
    CrashCascadeSink, MessageHandler, ProtectedTurnExecutionBoundary, TurnObserver,
};
use advance_scheduler::types::{ComponentConfig, ComponentId, WasmInstance};
use advance_shared_types::agent_tree::{
    AgentId, AgentKind, AgentTreeReader, AgentTreeSnapshot, Capability,
};
use advance_shared_types::capability::CapRequest;
use advance_shared_types::mailbox::AgentActionDispatcher;
use advance_shared_types::traits::EventBusEmit;
use cap_grant::{
    project_capability_params, GrantDraft, GrantStatus, GrantStore, GrantTtl, SubsetValidatorImpl,
};
use cap_lifecycle::{AgentTreeStore, SpawnObserver};

use crate::agent_loop::{
    build_agent_loop, build_agent_loop_with_prebuilt_dispatcher, WasmMessageHandler,
};
use crate::api::log_keys;
use crate::compose_log::LogHandle;

/// Bare→colon key resolver (the crash-cascade pattern): the root is the special
/// pair (`root`→`agent:root`), children are mechanical
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
    // Late-bound post-`builder.build()` ([`Self::bind_runtime`]); released by
    // [`Self::unbind`].
    runtime: Mutex<Option<Arc<ComponentRuntime>>>,
    injector: Mutex<Option<Arc<CapabilityInjector>>>,
    /// Set by [`Self::shutdown`]: no child is served from then on.
    closed: AtomicBool,
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
    /// Where an unserved child and an undelegated grant are reported
    /// ([`Self::with_log`]; none by default).
    log: LogHandle,
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
            runtime: Mutex::new(None),
            injector: Mutex::new(None),
            closed: AtomicBool::new(false),
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
            log: LogHandle::null(),
        }
    }

    /// Report unserved children and undelegated grants to `log`; each child's
    /// handler and turn-end reap report through it too.
    pub fn with_log(mut self, log: LogHandle) -> Self {
        self.log = log;
        self
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
    /// The first binding wins: a later call leaves a bound runtime and injector in place.
    pub fn bind_runtime(&self, runtime: Arc<ComponentRuntime>, injector: Arc<CapabilityInjector>) {
        lock(&self.runtime).get_or_insert(runtime);
        lock(&self.injector).get_or_insert(injector);
    }

    /// Release the late-bound runtime and injector.
    ///
    /// The injector holds the host registry, and the registry's spawn handler holds
    /// this manager (it is the spawner's observer): while both are bound, the manager
    /// and the registry keep each other — and every handler the registry holds, with
    /// the event bus and the git commit queue they reach — alive after their owners
    /// let go. Unbinding breaks that cycle. A child spawned afterwards is not served
    /// (it is reported as unbound). Idempotent.
    pub fn unbind(&self) {
        let runtime = lock(&self.runtime).take();
        let injector = lock(&self.injector).take();
        drop((runtime, injector));
    }

    /// Stop serving children, for an ordered shutdown: no child is served from now
    /// on, every child serve loop is aborted and awaited, then the runtime and
    /// injector are released ([`Self::unbind`]). Idempotent.
    pub async fn shutdown(&self) {
        self.closed.store(true, Ordering::SeqCst);
        let loops = std::mem::take(&mut *lock(&self.loops));
        for handle in loops.values() {
            handle.abort();
        }
        for (_, handle) in loops {
            let _ = handle.await;
        }
        self.unbind();
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
        // `spawn-child(id="default")` → `agent:root`, the root's serve/mailbox key)
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
    /// cap: a cap the parent does not hold is simply not delegated. When the
    /// parent holds several grants for a cap, they are tried in id order and the
    /// first one that accepts the delegation is used, so the outcome never
    /// depends on the store's hash order.
    fn delegate_child_grants(&self, parent_bare: &str, child_bare: &str, caps: &[Capability]) {
        let Some(grant_store) = self.grant_store.as_ref() else {
            return;
        };
        let now = chrono::Utc::now();
        // Only a grant that still authorizes the parent can be delegated from.
        let mut parent_grants = grant_store.list_by_grantee(parent_bare);
        parent_grants
            .retain(|g| g.status == GrantStatus::Active && g.expires_at.map_or(true, |t| t > now));
        parent_grants.sort_by(|a, b| a.id.as_str().cmp(b.id.as_str()));
        let validator = SubsetValidatorImpl::new();
        for cap in caps {
            let cap_name = cap.id.as_str();
            let mut candidates = parent_grants
                .iter()
                .filter(|g| g.capability.as_str() == cap_name)
                .peekable();
            if candidates.peek().is_none() {
                continue;
            }
            // A capability the child declared with params is delegated with exactly those
            // params, so the child never holds more than it asked for; `delegate_grant`
            // refuses them against a parent grant they are wider than. A bare declaration
            // takes what the parent grant holds (a whole-capability draft would be refused
            // against a restricted parent grant as a widening).
            let declared = match project_capability_params(cap) {
                Ok(declared) => declared,
                Err(e) => {
                    self.log.err(
                        log_keys::PERCHILD_NO_GRANT,
                        format!("advance: WARN child {child_bare} gets no `{cap_name}` grant: {e}"),
                    );
                    continue;
                }
            };
            let mut refusals: Vec<String> = Vec::new();
            let mut refused_restricted_fs = false;
            let delegated = candidates.any(|pg| {
                // `fs` path params are relative to the grantee's own territory, so a
                // restricted parent grant does not carry over to a child.
                if cap_name == "fs" && !pg.params.is_empty() {
                    refused_restricted_fs = true;
                    refusals.push(
                        "the parent's `fs` grant is path-restricted and paths do not carry \
                         across territories"
                            .to_string(),
                    );
                    return false;
                }
                let params = if declared.is_empty() {
                    pg.params.clone()
                } else {
                    declared.clone()
                };
                let draft = GrantDraft {
                    capability: cap_name.to_string(),
                    params,
                    ttl: GrantTtl::Persistent,
                };
                match grant_store.delegate_grant(
                    pg.id.as_str(),
                    child_bare,
                    draft,
                    parent_bare,
                    &validator,
                ) {
                    Ok(_) => true,
                    Err(e) => {
                        refusals.push(e.to_string());
                        false
                    }
                }
            });
            if !delegated {
                let key = if refused_restricted_fs && refusals.len() == 1 {
                    log_keys::PERCHILD_NO_FS_GRANT
                } else {
                    log_keys::PERCHILD_NO_GRANT
                };
                self.log.err(
                    key,
                    format!(
                        "advance: WARN child {child_bare} gets no `{cap_name}` grant: {}",
                        refusals.join("; ")
                    ),
                );
            }
        }
    }
}

impl SpawnObserver for PerChildLoopManager {
    fn on_child_spawned(&self, parent: &AgentId, child: &AgentId, workspace: &Path) {
        // Shut down: a child spawned now is never served.
        if self.closed.load(Ordering::SeqCst) {
            return;
        }
        let parent_bare = parent.0.as_str();
        let child_bare = child.0.as_str();
        let child_colon = (self.key_resolver)(child_bare);
        let parent_colon = (self.key_resolver)(parent_bare);

        // The child's declared capabilities (from the freshly-inserted tree node).
        let declared: Vec<Capability> = self
            .tree
            .get_node(child)
            .map(|n| n.capabilities)
            .unwrap_or_default();
        let caps: Vec<CapRequest> = declared
            .iter()
            .map(|c| CapRequest {
                capability: c.id.clone(),
            })
            .collect();

        // seam (d).i — L1 grant delegation so the child can act.
        self.delegate_child_grants(parent_bare, child_bare, &declared);

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
        let runtime = lock(&self.runtime).clone();
        let injector = lock(&self.injector).clone();
        let (Some(runtime), Some(injector)) = (runtime, injector) else {
            self.log.err(
                log_keys::PERCHILD_UNBOUND,
                format!("perchild: runtime/injector not bound; child {child_bare} not served"),
            );
            return;
        };
        let bytes = match crate::daemon::resolve_driver_component_bytes(workspace) {
            Ok(Some((_, bytes))) => bytes,
            Ok(None) => {
                self.log.err(
                    log_keys::PERCHILD_NO_DRIVER,
                    format!("perchild: child {child_bare} has no driver; not served"),
                );
                return;
            }
            Err(e) => {
                self.log.err(
                    log_keys::PERCHILD_DRIVER_RESOLVE_FAILED,
                    format!("perchild: child {child_bare} driver resolve failed: {e}"),
                );
                return;
            }
        };
        let loaded = match runtime.load_component(&bytes) {
            Ok(l) => l,
            Err(e) => {
                self.log.err(
                    log_keys::PERCHILD_LOAD_FAILED,
                    format!("perchild: child {child_bare} load failed: {e:?}"),
                );
                return;
            }
        };
        // BARE cap-id (the L1 grant grantee + `send` `from` body), COLON serve key.
        let handler: Arc<dyn MessageHandler> = Arc::new(
            WasmMessageHandler::new(
                runtime,
                loaded,
                injector,
                caps,
                child_bare.to_string(),
                format!("trace-child-{child_bare}"),
            )
            .with_log(self.log.clone()),
        );
        // Tee slice T3, observer path (ii): fan out to the recording observer AND
        // the turn-end reap. Recording runs first so existing MODULE-001-AC-22
        // witnesses observe the same counts they always did.
        let obs: Arc<dyn TurnObserver> = match self.llm_stream_reaper.get().cloned() {
            Some(reaper) => Arc::new(crate::reap::CompositeTurnObserver::new(vec![
                self.turn_observer.clone(),
                // §5.2 item 5: the authoritative (serve-key, cap-id) pair is injected
                // verbatim from the SAME locals this spawn serves under — never
                // re-derived from the serve id by string surgery.
                Arc::new(
                    crate::reap::ReapTurnObserver::for_agent(
                        reaper,
                        child_colon.clone(),
                        child_bare.to_string(),
                    )
                    .with_log(self.log.clone()),
                ),
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
                self.log.err(
                    log_keys::PERCHILD_INVALID_COMPONENT_ID,
                    format!("perchild: child {child_bare} invalid component id"),
                );
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
        // `spawn-child(id="default")` resolves to `agent:root`, the root's OWN
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
                self.log.err(
                    log_keys::PERCHILD_COLON_COLLISION,
                    format!(
                        "perchild: child {child_bare} colon id {child_colon} collides with an \
                         existing agent; not served (tree node recorded, unrouted)"
                    ),
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
        let mut loops = lock(&self.loops);
        // A shutdown that began meanwhile has already drained the registry: this loop
        // must not outlive it.
        if self.closed.load(Ordering::SeqCst) {
            drop(loops);
            handle.abort();
            return;
        }
        loops.insert(child_colon, handle);
    }
}

/// Lock `mutex`, recovering the guard from a poisoned lock (every value it guards
/// stays consistent across a panic: a slot or a map of task handles).
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
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

#[cfg(test)]
mod tests {
    use std::num::NonZeroUsize;

    use advance_database::{R2d2SqliteIndexHandle, SqliteIndexHandle};
    use advance_shared_types::agent_tree::{AgentNode, AgentStatus};
    use advance_shared_types::capability::{CapParams, CapabilityId};
    use advance_shared_types::event::Event;
    use cap_grant::{CapParam, Grant, GrantId, GrantIssuer, GrantProvenance, GrantSqliteIndex};
    use serde_json::json;

    use super::*;

    struct NullBus;

    impl EventBusEmit for NullBus {
        fn emit(&self, _: Event) {}
    }

    fn declared(id: &str, params: serde_json::Value) -> Capability {
        Capability {
            id: CapabilityId::from(id),
            params: CapParams::new(params),
        }
    }

    fn param(key: &str, value: &str) -> CapParam {
        CapParam {
            key: key.to_string(),
            value: value.to_string(),
        }
    }

    /// `root` holds `parent_grants` (`(grant id, capability, params)`); its child `kid` declares
    /// `child_caps`. No runtime is bound, so spawning the child runs the grant delegation and
    /// stops there.
    fn spawn_kid(
        parent_grants: Vec<(&str, &str, Vec<CapParam>)>,
        child_caps: Vec<Capability>,
    ) -> Vec<Grant> {
        let ws = tempfile::TempDir::new().expect("tempdir");
        let root_dir = ws.path().join("root");
        let kid_dir = root_dir.join("kid");
        std::fs::create_dir_all(&kid_dir).expect("territories");
        let root = AgentId("root".to_string());
        let kid = AgentId("kid".to_string());
        let tree = AgentTreeStore::new(ws.path().to_path_buf()).expect("tree");
        tree.insert_root(AgentNode {
            id: root.clone(),
            kind: AgentKind::Root,
            parent: None,
            workspace_path: root_dir,
            capabilities: Vec::new(),
            template_ref: None,
            status: AgentStatus::Active,
        })
        .expect("root node");
        tree.insert_child(
            &root,
            AgentNode {
                id: kid.clone(),
                kind: AgentKind::Child,
                parent: Some(root.clone()),
                workspace_path: kid_dir.clone(),
                capabilities: child_caps,
                template_ref: None,
                status: AgentStatus::Active,
            },
        )
        .expect("child node");

        let sqlite: Arc<dyn SqliteIndexHandle> =
            Arc::new(R2d2SqliteIndexHandle::new_in_memory().expect("sqlite"));
        let index = GrantSqliteIndex::new(sqlite);
        index.ensure_schema().expect("grant schema");
        let bus: Arc<dyn EventBusEmit> = Arc::new(NullBus);
        let grants = Arc::new(GrantStore::new(index, bus.clone()));
        for (id, capability, params) in parent_grants {
            grants
                .insert(Grant {
                    id: GrantId::new(id),
                    grantee: "root".to_string(),
                    capability: capability.to_string(),
                    params,
                    ttl: GrantTtl::Persistent,
                    issuer: GrantIssuer::Config,
                    provenance: GrantProvenance::StaticConfig,
                    status: GrantStatus::Active,
                    created_at: chrono::Utc::now(),
                    expires_at: None,
                })
                .expect("parent grant");
        }

        let routing = Arc::new(DynamicRouting::new(
            Arc::new(tree.clone()) as Arc<dyn AgentTreeReader>
        ));
        let manager = PerChildLoopManager::new(
            Arc::new(MailboxStore::new(NonZeroUsize::new(8).expect("capacity"))),
            bus,
            routing,
            Arc::new(AgentIdBridge::from_pairs([("agent:root", "root")])),
            Some(grants.clone()),
            tree,
            tokio::runtime::Handle::current(),
            Arc::new(|bare: &str| format!("agent:{bare}")),
        );
        manager.on_child_spawned(&root, &kid, &kid_dir);
        grants.list_by_grantee("kid")
    }

    fn grant_of<'a>(grants: &'a [Grant], capability: &str) -> Option<&'a Grant> {
        grants
            .iter()
            .find(|g| g.capability == capability && g.status == GrantStatus::Active)
    }

    fn params_of<'a>(grants: &'a [Grant], capability: &str) -> Option<&'a [CapParam]> {
        grant_of(grants, capability).map(|g| g.params.as_slice())
    }

    fn value_of<'a>(params: &'a [CapParam], key: &str) -> Option<&'a str> {
        params
            .iter()
            .find(|p| p.key == key)
            .map(|p| p.value.as_str())
    }

    #[tokio::test]
    async fn a_child_declaring_params_gets_exactly_those_params() {
        let kid = spawn_kid(
            vec![
                ("static:root:mcp", "mcp", Vec::new()),
                ("static:root:fs", "fs", Vec::new()),
            ],
            vec![
                declared(
                    "mcp",
                    json!({"servers": ["github"], "tool-patterns": ["get_*"]}),
                ),
                declared("fs", json!({"read-paths": ["/notes"]})),
            ],
        );
        let mcp = params_of(&kid, "mcp").expect("mcp delegated");
        assert_eq!(mcp.len(), 2, "{mcp:?}");
        assert_eq!(value_of(mcp, "servers"), Some("github"));
        assert_eq!(value_of(mcp, "tool-patterns"), Some("get_*"));
        let fs = params_of(&kid, "fs").expect("fs delegated");
        assert_eq!(fs.len(), 1, "{fs:?}");
        assert_eq!(value_of(fs, "read-paths"), Some("/notes"));
    }

    #[tokio::test]
    async fn a_bare_declaration_takes_the_parent_grant_params() {
        let kid = spawn_kid(
            vec![("static:root:mcp", "mcp", vec![param("servers", "github")])],
            vec![declared("mcp", serde_json::Value::Null)],
        );
        let mcp = params_of(&kid, "mcp").expect("mcp delegated");
        assert_eq!(mcp.len(), 1, "{mcp:?}");
        assert_eq!(value_of(mcp, "servers"), Some("github"));
    }

    #[tokio::test]
    async fn declared_params_narrower_than_a_restricted_parent_grant_are_delegated() {
        let kid = spawn_kid(
            vec![(
                "static:root:mcp",
                "mcp",
                vec![
                    param("servers", "github,slack"),
                    param("tool-patterns", "get_*,search_code"),
                ],
            )],
            vec![declared(
                "mcp",
                json!({"servers": ["github"], "tool-patterns": ["get_issue"]}),
            )],
        );
        let mcp = params_of(&kid, "mcp").expect("mcp delegated");
        assert_eq!(mcp.len(), 2, "{mcp:?}");
        assert_eq!(value_of(mcp, "servers"), Some("github"));
        assert_eq!(value_of(mcp, "tool-patterns"), Some("get_issue"));
    }

    // The grant that sorts first by id does not cover the declaration (a different server; a
    // path-restricted `fs` grant), so the delegation comes from the one after it that does,
    // whatever order the store lists them in.
    #[tokio::test]
    async fn a_declaration_is_delegated_from_the_parent_grant_that_accepts_it() {
        // Dynamic grant ids are UUIDs, which sort before `static:` ids.
        let kid = spawn_kid(
            vec![
                (
                    "00000000-0000-4000-8000-000000000001",
                    "mcp",
                    vec![param("servers", "github")],
                ),
                ("static:root:mcp", "mcp", vec![param("servers", "slack")]),
                (
                    "00000000-0000-4000-8000-000000000002",
                    "fs",
                    vec![param("read-paths", "/notes")],
                ),
                ("static:root:fs", "fs", Vec::new()),
            ],
            vec![
                declared("mcp", json!({"servers": ["slack"]})),
                declared("fs", serde_json::Value::Null),
            ],
        );
        let mcp = grant_of(&kid, "mcp").expect("mcp delegated");
        assert_eq!(mcp.params, vec![param("servers", "slack")]);
        assert_eq!(
            mcp.provenance,
            GrantProvenance::Delegated(GrantId::new("static:root:mcp"))
        );
        let fs = grant_of(&kid, "fs").expect("fs delegated");
        assert!(fs.params.is_empty(), "{fs:?}");
        assert_eq!(
            fs.provenance,
            GrantProvenance::Delegated(GrantId::new("static:root:fs"))
        );
        assert_eq!(kid.len(), 2, "{kid:?}");
    }

    #[tokio::test]
    async fn declared_params_wider_than_the_parent_grant_get_nothing() {
        let kid = spawn_kid(
            vec![
                ("static:root:mcp", "mcp", vec![param("servers", "github")]),
                ("static:root:fs", "fs", vec![param("read-paths", "/notes")]),
            ],
            vec![
                declared("mcp", json!({"servers": ["github", "slack"]})),
                declared("fs", json!({"read-paths": ["/notes"]})),
            ],
        );
        // Neither the declared params (wider than the parent grant) nor the parent's own.
        assert_eq!(params_of(&kid, "mcp"), None, "{kid:?}");
        // A path-restricted parent `fs` grant never carries across territories.
        assert_eq!(params_of(&kid, "fs"), None, "{kid:?}");
    }
}

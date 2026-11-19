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

use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use advance_messaging::{AgentIdBridge, DynamicRouting, MailboxStore};
use advance_runtime::{CapabilityInjector, ComponentRuntime};
use advance_scheduler::hook::{
    CrashCascadeSink, MessageHandler, ProtectedTurnExecutionBoundary, TurnEnd, TurnObserver,
    TurnOutcome,
};
use advance_scheduler::types::{ComponentConfig, ComponentId, WasmInstance};
use advance_shared_types::agent_tree::{
    AgentId, AgentKind, AgentStatus, AgentTreeReader, AgentTreeSnapshot, Capability,
};
use advance_shared_types::capability::CapRequest;
use advance_shared_types::mailbox::AgentActionDispatcher;
use advance_shared_types::traits::EventBusEmit;
use cap_grant::{
    project_capability_params, GrantDraft, GrantStatus, GrantStore, GrantTtl, SubsetValidatorImpl,
};
use cap_lifecycle::{AgentTreeStore, SpawnObserver};
use tokio::sync::watch;

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

/// The turn ends [`RecordingTurnObserver::turn_end_of`] remembers per child: its most
/// recent ones, so the record stays bounded however long a child is served.
const TURN_ENDS_KEPT: usize = 16;

/// Records each served child loop's turn completions so a witness can assert the
/// child ran its OWN `handle-message` (SYS-AC-279 liveness / child-loop-absent
/// discriminator), and how its most recent turns ended.
#[derive(Default)]
pub struct RecordingTurnObserver {
    // Per-agent completed-turn COUNTS — NOT an unbounded per-turn log. A resident
    // daemon serves unboundedly many child turns over its lifetime, so a
    // `Vec<String>`-push-per-turn would grow without bound (audit r8 W4). A count
    // map is bounded by the number of DISTINCT served children, and `count()` is
    // O(1) instead of an O(n) scan.
    counts: Mutex<HashMap<String, usize>>,
    /// Per agent, its last [`TURN_ENDS_KEPT`] turn ends: the message each turn
    /// executed and how it ended. Bounded like `counts`.
    ends: Mutex<HashMap<String, VecDeque<(String, TurnOutcome)>>>,
}

impl RecordingTurnObserver {
    /// Number of completed turns recorded for `agent_id` (the colon serve key).
    pub fn count(&self, agent_id: &str) -> usize {
        self.counts
            .lock()
            .map(|c| c.get(agent_id).copied().unwrap_or(0))
            .unwrap_or(0)
    }

    /// How the turn of `agent_id` (the colon serve key) that executed message
    /// `message_id` ended, while it is among the agent's last [`TURN_ENDS_KEPT`]
    /// turns. A turn end is reported once the turn ran to its END — its turn-end
    /// pipeline included — and before the turn is counted ([`Self::count`]).
    /// `None`: no such turn has ended.
    pub fn turn_end_of(&self, agent_id: &str, message_id: &str) -> Option<TurnOutcome> {
        self.ends.lock().ok().and_then(|ends| {
            ends.get(agent_id)?
                .iter()
                .find(|(ended, _)| ended == message_id)
                .map(|(_, outcome)| *outcome)
        })
    }
}

impl TurnObserver for RecordingTurnObserver {
    fn on_turn_complete(&self, agent_id: &str) {
        if let Ok(mut c) = self.counts.lock() {
            *c.entry(agent_id.to_string()).or_insert(0) += 1;
        }
    }

    fn on_turn_end(&self, agent_id: &str, end: &TurnEnd) {
        if let Ok(mut ends) = self.ends.lock() {
            let kept = ends.entry(agent_id.to_string()).or_default();
            if kept.len() == TURN_ENDS_KEPT {
                kept.pop_front();
            }
            kept.push_back((end.message_id.clone(), end.outcome));
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
    /// The loop-registry and the serves under way ([`LoopRegistry`]), shared with each
    /// loop's own teardown when it ends ([`RouteCleanup`]).
    loops: Arc<Mutex<LoopRegistry>>,
    /// Numbers the serves ([`Serving`]).
    next_serve: AtomicU64,
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
    /// Late-bound production context assembler + post-processor deps. Set
    /// after the LLM gateway exists and before any child is served; released by
    /// [`Self::unbind`] (they hold the host registry).
    context_deps: Mutex<Option<Arc<crate::child_context::ChildContextDeps>>>,
    /// Where a terminated child is forgotten from ([`Self::forget_child`]). Bound and
    /// released with the context deps.
    record_stores: Mutex<Option<RecordStores>>,
    /// Terminated children whose aborted loop has not ended yet ([`Self::forget_child`]),
    /// each under both of its ids. A child served later under either id waits for the
    /// pass before its own loop starts, and so does [`Self::shutdown`].
    sweeps: Mutex<Vec<PendingPass>>,
    /// Children terminated after a shutdown took the loop registry
    /// ([`Self::forget_child`]): the shutdown aborts and awaits their loops itself, and
    /// then forgets what those loops left ([`Self::shutdown`]). Queued under the
    /// `record_stores` lock, which [`Self::unbind`] empties it under.
    forget_at_shutdown: Mutex<Vec<AgentRecords>>,
    /// Terminates under way ([`TerminateScope`]): each teardown ([`Self::abort_child`]), and
    /// each terminate cascade for the whole of it, from its start, before it marks its
    /// subtree, to its end ([`Self::terminate_scope`]). One that took its child's
    /// loop out of the registry before a shutdown took the registry leaves the pass that
    /// shutdown must wait for only as it ends, and one between its stops and its teardowns
    /// still needs the stores to forget its nodes in and hand their knowledge over through:
    /// so a shutdown waits for every terminate under way before it lets go of them.
    terminates: Arc<Terminates>,
}

/// The serve loops retained ([`PerChildLoopManager::spawn_serve_loop`]) and the serves
/// under way ([`Serving`]), under one lock. A terminate cancels the serves of its child
/// and takes its loops out in one step ([`PerChildLoopManager::stop_child`], or
/// [`PerChildLoopManager::abort_child`] for a child not stopped first), and a serve
/// retains its loop only if it is not cancelled, in one step too: so either the terminate
/// finds the loop, or the serve finds itself cancelled.
///
/// What a child holds under a colon id — its route and its id pair — is registered and
/// torn down under this lock too, each change in one step: by a serve
/// ([`PerChildLoopManager::register_route`]), by a terminate
/// ([`PerChildLoopManager::tear_down_under`]), and by a loop as it ends ([`RouteCleanup`]).
/// So none of them meets one half done.
#[derive(Default)]
struct LoopRegistry {
    /// The loop retained under each colon id, with the child it serves (seam d + seam-f
    /// per-child abort). Keyed (not a flat `Vec`) so a terminate aborts + REMOVES exactly
    /// its child's loops, making `active_loop_count` deterministic. A loop that ended on
    /// its own stays until another is retained under its colon id or its child is
    /// terminated.
    retained: HashMap<String, Retained>,
    /// Loops stopped because another was retained in their place under their colon id:
    /// aborted, and awaited by [`PerChildLoopManager::shutdown`].
    stopping: Vec<tokio::task::JoinHandle<()>>,
    /// Loops a terminate stopped before its first step that can fail
    /// ([`PerChildLoopManager::stop_child`]), each with the colon id it was retained
    /// under: aborted, and kept until their child is torn down
    /// ([`PerChildLoopManager::abort_child`]) — which needs those colon ids, and waits
    /// for the loops in its pass — or a shutdown awaits them.
    stopped: Vec<(String, Retained)>,
    /// The serves under way, by number: the bare id of the child served, and whether a
    /// terminate of that child has cancelled the serve.
    serving: HashMap<u64, (String, bool)>,
}

/// A serve loop retained in the [`LoopRegistry`].
struct Retained {
    /// The child it serves, by bare id: the registry, not the colon id, tells whose a loop
    /// is — a child renamed keeps the colon id it was served under, and another child can
    /// take its old handle, and with it that colon id.
    bare_id: String,
    /// The serve that retained it ([`Serving`]).
    serve: u64,
    handle: tokio::task::JoinHandle<()>,
}

/// One serve of a child under way ([`LoopRegistry::serving`]): from the start of
/// [`SpawnObserver::on_child_spawned`] until it ends, its loop retained or not.
struct Serving<'a> {
    manager: &'a PerChildLoopManager,
    serve: u64,
}

impl<'a> Serving<'a> {
    fn begin(manager: &'a PerChildLoopManager, bare_id: &str) -> Self {
        let serve = manager.next_serve.fetch_add(1, Ordering::Relaxed);
        lock(&manager.loops)
            .serving
            .insert(serve, (bare_id.to_string(), false));
        Self { manager, serve }
    }
}

impl Drop for Serving<'_> {
    fn drop(&mut self) {
        lock(&self.manager.loops).serving.remove(&self.serve);
    }
}

/// Unregister the route and the id pair of the child `bare_id` under `colon` while they
/// are its own — the id bridge still pairs the two ids — and leave them alone otherwise:
/// another child holds the colon id now. Called with the registry's lock held, as every
/// registration is made ([`LoopRegistry`]), so no one meets one of the two without the
/// other. Returns whether they were its own.
fn unroute(routing: &DynamicRouting, bridge: &AgentIdBridge, bare_id: &str, colon: &str) -> bool {
    let own = bridge.unregister_pair(colon, bare_id);
    if own {
        routing.unregister_child(colon);
    }
    own
}

/// What a serve loop tears down when it ends on its own — `serve` returned: a component
/// that loaded but trapped in `bootstrap_and_init`, or a guest stop (audit r8 W2): the
/// route and the id pair its serve registered, so a parent send then dead-ends
/// (`unknown_target`) rather than black-holing into a mailbox no loop serves.
///
/// Only while the registry still retains this loop under its colon id, looked at under
/// the registry's lock. Once a terminate has taken the loop out, what is under the colon
/// id is the terminate's to tear down, and may be a successor's: the same bare id under
/// the same handle registers the very same pair. An abort cannot stop a loop past its
/// last await, so a loop that ends as its child is terminated would otherwise unroute the
/// child served in its place. Once a shutdown has taken it out, the route and the id pair
/// are left as they are, in memory, and go with the composition: no serve registers
/// anything after a shutdown has begun.
struct RouteCleanup {
    loops: Arc<Mutex<LoopRegistry>>,
    routing: Arc<DynamicRouting>,
    bridge: Arc<AgentIdBridge>,
    bare_id: String,
    colon_id: String,
    serve: u64,
}

impl RouteCleanup {
    fn run(self) {
        let registry = lock(&self.loops);
        let retained = registry
            .retained
            .get(&self.colon_id)
            .is_some_and(|retained| retained.serve == self.serve);
        if retained {
            unroute(&self.routing, &self.bridge, &self.bare_id, &self.colon_id);
        }
    }
}

/// The crash cascade of one serve's loop: tells `inner` of a crash of the loop only while
/// the registry still retains this loop, looked at under the registry's lock as the loop's
/// teardown is ([`RouteCleanup`]), and under the BARE id the registry records the loop
/// for — the colon id the loop serves under follows the child's handle as it was, so after
/// a rename it would name whoever holds that handle now. An abort cannot stop a loop past
/// its last await, so a loop that traps as its child is terminated would otherwise report
/// a crash of the child spawned since under the same ids. The lock is held while `inner`
/// runs, so a terminate cannot take the loop out — nor the child be respawned — between
/// the look and the report.
struct ServedCrashSink {
    inner: Arc<dyn CrashCascadeSink>,
    loops: Arc<Mutex<LoopRegistry>>,
    colon_id: String,
    serve: u64,
}

impl CrashCascadeSink for ServedCrashSink {
    fn handle_crash(&self, _served_as: &str, reason: &str) {
        let registry = lock(&self.loops);
        let retained = registry
            .retained
            .get(&self.colon_id)
            .filter(|retained| retained.serve == self.serve);
        if let Some(retained) = retained {
            self.inner.handle_crash(&retained.bare_id, reason);
        }
    }
}

/// The terminates under way ([`PerChildLoopManager::terminate_scope`]).
#[derive(Default)]
struct Terminates {
    under_way: Mutex<usize>,
    /// Told when the last terminate under way has ended.
    ended: tokio::sync::Notify,
    /// Told when a shutdown finds a terminate under way and waits for it: what a test
    /// watches for, rather than for a shutdown that has not ended yet.
    #[cfg(test)]
    waited_for: tokio::sync::Notify,
}

/// One terminate under way, counted until dropped ([`PerChildLoopManager::terminate_scope`]).
pub struct TerminateScope(Arc<Terminates>);

impl TerminateScope {
    fn begin(terminates: &Arc<Terminates>) -> Self {
        *lock(&terminates.under_way) += 1;
        Self(terminates.clone())
    }
}

impl Drop for TerminateScope {
    fn drop(&mut self) {
        let mut under_way = lock(&self.0.under_way);
        *under_way -= 1;
        if *under_way == 0 {
            self.0.ended.notify_waiters();
        }
    }
}

/// The second pass of a terminated child ([`PerChildLoopManager::forget_child`]),
/// still to run: it forgets the rows and the served record under the child's BARE id,
/// and the reports under it and the colon ids it held.
struct PendingPass {
    bare_id: String,
    colon_ids: Vec<String>,
    /// Closes when the pass has run.
    swept: watch::Receiver<()>,
}

/// A second pass reserved by a terminate before it tears anything down
/// ([`PerChildLoopManager::reserve_pass`]), pending in `sweeps` from then on and run by
/// [`PerChildLoopManager::forget_child`] once the child's loops have ended.
struct ReservedPass {
    /// The passes before it that share an id with it, to run first.
    earlier: Vec<watch::Receiver<()>>,
    /// Closes the pass when dropped.
    done: watch::Sender<()>,
}

/// The passes still pending in `passes` that forget something an agent known by
/// `bare_id` / `colon_ids` keeps — a pass that shares ANY of those ids with it. A bare id
/// and a colon id never equal each other (`agent:` is not a bare id), and the two need
/// not name each other: the colon id follows the agent's handle, so an agent created
/// later under a bare id a terminated child held can have another colon id, and one
/// created under its handle another bare id.
fn passes_pending_for(
    passes: &[PendingPass],
    bare_id: &str,
    colon_ids: &[&str],
) -> Vec<watch::Receiver<()>> {
    passes
        .iter()
        .filter(|pass| {
            pass.bare_id == bare_id
                || pass
                    .colon_ids
                    .iter()
                    .any(|held| colon_ids.contains(&held.as_str()))
        })
        .map(|pass| pass.swept.clone())
        .collect()
}

/// Remembers the provider entry each agent chats on — the LLM gateway
/// ([`cap_llm::LlmGateway::forget_agent`]).
trait ChatRecord: Send + Sync {
    /// Forget where `agent_id` (the BARE cap agent id) chats.
    fn forget_agent(&self, agent_id: &str);
}

impl ChatRecord for cap_llm::LlmGateway {
    fn forget_agent(&self, agent_id: &str) {
        cap_llm::LlmGateway::forget_agent(self, agent_id);
    }
}

/// Where the context engine keeps what it knows of an agent outside the agent's own
/// workspace, keyed by the agent's id: the shared cap-memory index (turn digests and their
/// vectors, task briefs, and the memory rows that mirror the status of the agent's knowledge
/// entries), the gateway's record of the provider entry the agent chats on and the store of
/// last assembly reports — all forgotten when the agent is terminated —, and the home's
/// knowledge entries, which are kept: they are history, and the agent's heir takes them over
/// ([`AgentRecords::hand_over_knowledge`]). The heir recalls them from the knowledge store,
/// as it recalls its own ([`cap_memory::MemoryStore::recall`]); its memory rows mirror them
/// once its next turn ends (`PostProcessor::sync_memory_index`).
#[derive(Clone)]
struct RecordStores {
    chats: Arc<dyn ChatRecord>,
    memory_index: Option<Arc<dyn cap_memory::SqliteIndex + Send + Sync>>,
    context_store: Arc<crate::context_inspect::ContextSnapshotStore>,
    /// The home's knowledge entries; `None` when the home keeps none.
    knowledge: Option<Arc<cap_memory::MemoryStore>>,
}

/// What [`RecordStores`] hold under one agent's ids, held so it can be forgotten when
/// the agent is terminated ([`PerChildLoopManager::forget_child`]): its bare id, the
/// colon ids it held then, and the ancestors its knowledge entries may go to.
#[derive(Clone)]
struct AgentRecords {
    bare_id: String,
    colon_ids: Vec<String>,
    /// The agent's ancestors, nearest first, read while the tree still held it
    /// ([`PerChildLoopManager::ancestors_of`]): the first of them alive at a hand-over takes
    /// its knowledge entries over. Empty when the tree no longer knew the agent.
    ancestors: Vec<String>,
    /// The tree, which tells at each hand-over which ancestors are alive.
    tree: AgentTreeStore,
    stores: RecordStores,
    log: LogHandle,
}

impl AgentRecords {
    fn colon_ids(&self) -> Vec<&str> {
        self.colon_ids.iter().map(String::as_str).collect()
    }

    /// Forget all of it: the agent is gone, and its ids name no agent any more.
    fn forget(&self) {
        self.stores
            .context_store
            .forget(&self.bare_id, &self.colon_ids());
        self.forget_written();
    }

    /// Forget what a loop still running may have written since [`Self::forget`]: a
    /// row, the entry a request of its guest was served by, an assembly report. The
    /// ids stay known — an agent spawned under them since has registered them.
    fn forget_late(&self) {
        let mut ids = vec![self.bare_id.as_str()];
        ids.extend(self.colon_ids());
        self.stores.context_store.forget_reports(&ids);
        self.forget_written();
    }

    /// Forget what the agent's loop wrote under its bare id — its index rows and the entry
    /// its guest was served by — and hand the knowledge entries it wrote over to its heir.
    fn forget_written(&self) {
        self.hand_over_knowledge();
        self.stores.chats.forget_agent(&self.bare_id);
        let Some(index) = self.stores.memory_index.as_ref() else {
            return;
        };
        if let Err(e) = index.forget_agent(&self.bare_id) {
            self.log.err(
                log_keys::PERCHILD_FORGET_FAILED,
                format!(
                    "perchild: the index rows of terminated child {} are not removed: {e}",
                    self.bare_id
                ),
            );
        }
    }
}

impl AgentRecords {
    /// Hand the agent's knowledge entries over to its heir ([`hand_over_along`]): the
    /// knowledge of a terminated agent is kept, as history, and taken over by the nearest of
    /// its ancestors alive — not marked terminated — when the hand-over runs (owner decision
    /// 2026-11-17), which recalls them as its own; each hand-over is logged, with what the
    /// heir holds since ([`log_keys::PERCHILD_HANDOVER`]). Best effort, as the archive of a
    /// Sub's memory is: a hand-over that fails is logged, the entries it could not move stay
    /// under the agent's id — or, when it failed half-way, under the heir's too —, and the
    /// terminate goes on. The second pass, once the agent's aborted loops have ended, hands
    /// over again what is under its id; an agent that had no loop has no second pass. The
    /// teardown of an agent the tree no longer knew hands nothing over, and logs nothing: the
    /// terminate that removed it read its ancestors while the tree still held it, and its
    /// teardown and second pass hand over what is the agent's; what is under the id besides
    /// is an agent's served under it since, or what an agent terminated before v0.1.57 left
    /// there (known item 1.2).
    fn hand_over_knowledge(&self) {
        let Some(knowledge) = self.stores.knowledge.as_ref() else {
            return;
        };
        let alive = |id: &str| {
            self.tree
                .get_node(&AgentId(id.to_string()))
                .is_some_and(|node| node.status != AgentStatus::Terminated)
        };
        let outcome = hand_over_along(knowledge, &self.bare_id, &self.ancestors, alive);
        self.report_hand_over(knowledge, outcome);
    }

    /// Log what a hand-over of the agent's knowledge entries did ([`Self::hand_over_knowledge`]):
    /// one that reached an heir on stdout, with what the heir holds since; entries left
    /// waiting, and a store that failed, on stderr; nothing when the agent held none, or the
    /// tree no longer knew it.
    fn report_hand_over(
        &self,
        knowledge: &cap_memory::MemoryStore,
        outcome: Result<HandOverOutcome, HandOverFailure>,
    ) {
        match outcome {
            Ok(HandOverOutcome::Nothing) | Err(HandOverFailure::Unknown) => {}
            Ok(HandOverOutcome::WithHeir { heir, moved }) => {
                let held = knowledge.active_count(&heir);
                self.log.out(
                    log_keys::PERCHILD_HANDOVER,
                    format!(
                        "perchild: the knowledge entries of terminated child {} are handed over \
                         to {heir} (moved {}, active {}); {heir} holds active entries: {} of \
                         its own, {} handed over to it",
                        self.bare_id,
                        moved.ids.len(),
                        moved.active,
                        held.own,
                        held.handed_over
                    ),
                );
            }
            Ok(HandOverOutcome::WithMarkedHeir { heir, moved }) => self.log.err(
                log_keys::PERCHILD_HANDOVER_FAILED,
                format!(
                    "perchild: the knowledge entries of terminated child {} (moved {}) wait \
                     under {heir}, terminated meanwhile: no ancestor above it is alive",
                    self.bare_id,
                    moved.ids.len()
                ),
            ),
            Err(HandOverFailure::NoAncestorAlive) => {
                if !knowledge.list(&self.bare_id).is_empty() {
                    self.log.err(
                        log_keys::PERCHILD_HANDOVER_FAILED,
                        format!(
                            "perchild: the knowledge entries of terminated child {} stay under \
                             its id: no ancestor of it is alive",
                            self.bare_id
                        ),
                    );
                }
            }
            Err(HandOverFailure::Store { from, to, error }) => self.log.err(
                log_keys::PERCHILD_HANDOVER_FAILED,
                format!(
                    "perchild: the knowledge entries of terminated child {} are not handed \
                     over from {from} to {to}: {error:?}",
                    self.bare_id
                ),
            ),
        }
    }
}

/// Where [`hand_over_along`] left the knowledge entries of the agent.
#[derive(Debug)]
enum HandOverOutcome {
    /// The agent held none.
    Nothing,
    /// The entries `moved` from the agent's id are with `heir`, alive when checked once they
    /// were there.
    WithHeir {
        heir: String,
        moved: cap_memory::HandedOver,
    },
    /// The entries `moved` from the agent's id wait under `heir`, marked terminated once they
    /// were there, with no ancestor above it alive — not while the root heads the chain.
    WithMarkedHeir {
        heir: String,
        moved: cap_memory::HandedOver,
    },
}

/// Why [`hand_over_along`] left the entries under the agent's id.
#[derive(Debug)]
enum HandOverFailure {
    /// No ancestor is on record: the tree no longer knew the agent at its teardown.
    Unknown,
    /// No ancestor on record is alive — not while the root heads the chain.
    NoAncestorAlive,
    /// The store could not move the entries `from` holds to `to`.
    Store {
        from: String,
        to: String,
        error: advance_shared_types::memory::PostProcessorError,
    },
}

/// Hand the knowledge entries of `bare_id` over to the first of its `ancestors` (nearest
/// first) that is `alive` ([`cap_memory::MemoryStore::hand_over`]), and check that heir
/// again once they are there. A terminate marks an agent terminated before it tears it
/// down, and hands its entries on when it does: an heir still alive after the hand-over is
/// marked, if ever, after it, so its own terminate hands the entries on; one marked
/// meanwhile may have handed its entries on already, so the entries just handed to it go on
/// from here to the next ancestor alive ([`cap_memory::MemoryStore::hand_over_some`]) — only
/// those: its own wait for its own teardown, as what a terminate has not torn down keeps its
/// records. The root is never terminated, so a walk that reaches it ends there.
fn hand_over_along(
    knowledge: &cap_memory::MemoryStore,
    bare_id: &str,
    ancestors: &[String],
    alive: impl Fn(&str) -> bool,
) -> Result<HandOverOutcome, HandOverFailure> {
    if ancestors.is_empty() {
        return Err(HandOverFailure::Unknown);
    }
    let mut from = bare_id;
    // What left the agent's id, and the heir marked meanwhile that holds it.
    let mut first: Option<cap_memory::HandedOver> = None;
    let mut marked: Option<&str> = None;
    for heir in ancestors {
        if !alive(heir) {
            continue;
        }
        let moved = match &first {
            None => knowledge.hand_over(from, heir),
            Some(first) => knowledge.hand_over_some(from, heir, &first.ids),
        }
        .map_err(|error| HandOverFailure::Store {
            from: from.to_string(),
            to: heir.clone(),
            error,
        })?;
        let handed = first.get_or_insert(moved);
        if handed.ids.is_empty() {
            return Ok(HandOverOutcome::Nothing);
        }
        if alive(heir) {
            return Ok(HandOverOutcome::WithHeir {
                heir: heir.clone(),
                moved: handed.clone(),
            });
        }
        marked = Some(heir.as_str());
        from = heir.as_str();
    }
    match (marked, first) {
        (Some(heir), Some(moved)) => Ok(HandOverOutcome::WithMarkedHeir {
            heir: heir.to_string(),
            moved,
        }),
        _ => Err(HandOverFailure::NoAncestorAlive),
    }
}

/// Wait until `swept` closes: the pass it stands for has run (or will never run —
/// its task is gone with the runtime).
async fn closed(mut swept: watch::Receiver<()>) {
    while swept.changed().await.is_ok() {}
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
            loops: Arc::new(Mutex::new(LoopRegistry::default())),
            next_serve: AtomicU64::new(0),
            crash_sink: None,
            action_dispatcher: None,
            protected_turn_boundary: None,
            skip_loop: false,
            skip_routing: false,
            skip_crash: false,
            child_config_data: None,
            log: LogHandle::null(),
            context_deps: Mutex::new(None),
            record_stores: Mutex::new(None),
            sweeps: Mutex::new(Vec::new()),
            forget_at_shutdown: Mutex::new(Vec::new()),
            terminates: Arc::new(Terminates::default()),
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
    /// Failed + a parent `component.terminated` notice; nothing for a child a terminate
    /// has marked terminated) — told of the child by its bare id, and only while the
    /// registry retains the loop ([`ServedCrashSink`]). Production builds the sink once in
    /// wiring and passes it here.
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

    /// Late-bind the production context assembler / post-processor deps.
    /// Call once, after the LLM gateway exists and before any child is served
    /// (including `serve_existing_children`). The first binding wins.
    pub fn bind_context(&self, deps: Arc<crate::child_context::ChildContextDeps>) {
        let mut bound = lock(&self.context_deps);
        if bound.is_some() {
            return;
        }
        *lock(&self.record_stores) = Some(RecordStores {
            chats: deps.gateway.clone(),
            memory_index: deps.memory_index.clone(),
            context_store: deps.context_store.clone(),
            knowledge: deps.memory_store.clone(),
        });
        *bound = Some(deps);
    }

    /// Release the late-bound runtime, injector and context deps.
    ///
    /// The injector holds the host registry, and so do the context deps
    /// ([`Self::bind_context`]); the registry's spawn handler holds this manager (it
    /// is the spawner's observer): while either is bound, the manager and the
    /// registry keep each other — and every handler the registry holds, with the
    /// event bus and the git commit queue they reach — alive after their owners let
    /// go. Unbinding breaks that cycle. A child spawned afterwards is not served (it
    /// is reported as unbound, before the context deps would be read). Idempotent.
    pub fn unbind(&self) {
        let runtime = lock(&self.runtime).take();
        let injector = lock(&self.injector).take();
        let context_deps = lock(&self.context_deps).take();
        // The stores, and with them a terminate queued for a shutdown that had already run
        // its queue: its own first pass came after every loop had ended, so nothing is
        // left for this one to do. Both under the lock a terminate queues under
        // ([`Self::forget_child`]), so none is queued once the stores are gone.
        let (record_stores, queued) = {
            let mut bound = lock(&self.record_stores);
            let queued = std::mem::take(&mut *lock(&self.forget_at_shutdown));
            (bound.take(), queued)
        };
        drop((runtime, injector, context_deps, record_stores, queued));
    }

    /// Stop serving children, for an ordered shutdown: no child is served from now
    /// on, every child serve loop is aborted and awaited — with those stopped because
    /// another took their place, and those a terminate stopped and has not torn down
    /// yet — the terminates under way are let end, what terminated
    /// children left is forgotten ([`Self::forget_child`]), then the runtime, injector
    /// and context deps are released ([`Self::unbind`]). Idempotent.
    pub async fn shutdown(&self) {
        self.closed.store(true, Ordering::SeqCst);
        let (retained, stopping, stopped) = {
            let mut registry = lock(&self.loops);
            (
                std::mem::take(&mut registry.retained),
                std::mem::take(&mut registry.stopping),
                std::mem::take(&mut registry.stopped),
            )
        };
        for retained in retained.values() {
            retained.handle.abort();
        }
        let handles = retained.into_values().map(|retained| retained.handle);
        let stopped = stopped.into_iter().map(|(_, stopped)| stopped.handle);
        for handle in handles.chain(stopping).chain(stopped) {
            let _ = handle.await;
        }
        // A terminate that took its child's loop out of the registry before it was taken
        // above leaves that loop's pass only as it ends.
        self.no_terminate_under_way().await;
        // Each waits for a loop `abort_child` aborted, so none waits long; and none is
        // left holding the gateway or the index once this returns.
        let sweeps = std::mem::take(&mut *lock(&self.sweeps));
        for pass in sweeps {
            closed(pass.swept).await;
        }
        // Children terminated after the registry was taken above: their loops were among
        // those aborted and awaited, so all they wrote is there to forget now. (One
        // terminated later still is forgotten by its terminate alone: every loop has
        // ended by then.)
        let late = std::mem::take(&mut *lock(&self.forget_at_shutdown));
        for records in late {
            records.forget_late();
        }
        self.unbind();
    }

    /// Wait until no terminate is under way ([`TerminateScope`]). A terminate does not wait
    /// for anything a shutdown holds: it ends.
    async fn no_terminate_under_way(&self) {
        loop {
            let ended = self.terminates.ended.notified();
            let mut ended = std::pin::pin!(ended);
            ended.as_mut().enable();
            if *lock(&self.terminates.under_way) == 0 {
                return;
            }
            #[cfg(test)]
            self.terminates.waited_for.notify_one();
            ended.await;
        }
    }

    /// Count a terminate as under way until the scope is dropped: a shutdown waits for it
    /// before it lets go of the stores ([`Self::shutdown`]). The terminate cascade holds one
    /// for the whole terminate, from its start, before it marks its subtree, to its end
    /// ([`cap_lifecycle::LoopCascade::terminate_scope`]), so a node stopped before a
    /// shutdown is still forgotten, and its knowledge handed over, when it is torn down
    /// after; each teardown holds one too ([`Self::abort_child`]).
    pub fn terminate_scope(&self) -> TerminateScope {
        TerminateScope::begin(&self.terminates)
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

    /// How the child `colon_id`'s turn of message `message_id` ended, once it ran to
    /// its end ([`RecordingTurnObserver::turn_end_of`]).
    pub fn child_turn_end(&self, colon_id: &str, message_id: &str) -> Option<TurnOutcome> {
        self.turn_observer.turn_end_of(colon_id, message_id)
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
            .map(|registry| {
                registry
                    .retained
                    .values()
                    .filter(|retained| !retained.handle.is_finished())
                    .count()
            })
            .unwrap_or(0)
    }

    /// Abort all spawned child serve loops (daemon shutdown drain). Those stopped
    /// because another took their place are aborted already.
    pub fn drain(&self) {
        if let Ok(mut registry) = self.loops.lock() {
            for retained in registry.retained.values() {
                retained.handle.abort();
            }
            registry.retained.clear();
        }
    }

    /// seam (f) terminate, first step: stop the child's serve loops, and tear nothing down.
    /// In one step under the registry's lock, as [`Self::abort_child`] takes them out:
    /// cancel the serves of the child under way ([`Self::spawn_serve_loop`]) and abort
    /// every loop retained for it, taking it out of those retained (so
    /// `active_loop_count` decrements now) into those stopped, where the child's teardown
    /// finds it. Nothing else is touched: the child's route and id pair, its mailbox and
    /// what the context engine keeps under its ids stay as they are — the child holding
    /// its ids, so no one else is served under them — until [`Self::abort_child`] tears it
    /// down. A loop stopped here that ends on its own tears nothing down
    /// ([`RouteCleanup`]), and one that traps reports no crash ([`ServedCrashSink`]): the
    /// registry no longer retains it. Idempotent.
    ///
    /// For the terminate cascade, which stops every loop of the subtree before its first
    /// step that can fail, and tears each node down only once that node's steps have
    /// succeeded ([`cap_lifecycle::LoopCascade`]): a terminate that fails part-way leaves no
    /// loop serving, and tears nothing down of a node it leaves in the tree but what its
    /// own steps for that node removed (its runs, the messages its mailbox flush took). A
    /// turn under way when its loop is stopped is cut off.
    pub fn stop_child(&self, bare_id: &str) {
        // Root-collision guard, as in `abort_child`: nothing of the root's is touched.
        if self.routing.agent_kind(&(self.key_resolver)(bare_id)) == Some(AgentKind::Root) {
            return;
        }
        let mut registry = lock(&self.loops);
        for (served, cancelled) in registry.serving.values_mut() {
            if served == bare_id {
                *cancelled = true;
            }
        }
        let mine: Vec<String> = registry
            .retained
            .iter()
            .filter(|(_, retained)| retained.bare_id == bare_id)
            .map(|(colon, _)| colon.clone())
            .collect();
        for colon in mine {
            if let Some(retained) = registry.retained.remove(&colon) {
                retained.handle.abort();
                registry.stopped.push((colon, retained));
            }
        }
    }

    /// seam (f) terminate: stop the child's serve loops and tear down its per-child
    /// state, colon-correctly. `terminate_child` hands cascades the BARE id, but the
    /// routing + mailbox are COLON-keyed. In one step under the registry's lock: (1) cancel
    /// the serves of the child under way ([`Self::spawn_serve_loop`]) and abort + REMOVE
    /// every loop retained for it (so `active_loop_count` decrements deterministically, not
    /// on the async `abort()` landing), taking with them those [`Self::stop_child`] stopped
    /// for it; (2) when it had loops, reserve the pass that forgets
    /// what they write late, for the colon ids it was served under and the one it resolves
    /// to now ([`Self::reserve_pass`]); (3) for each of those ids — each only while it is
    /// the child's or no one's ([`Self::tear_down_under`]) — unregister its route + id-bridge
    /// pair, so a post-terminate parent send dead-ends `unknown_target` rather than
    /// black-holing into a now-unserved mailbox, then UNFREEZE and best-effort drain the
    /// mailbox. Then (4) forget what the context engine keeps under the child's ids
    /// ([`Self::forget_child`]). Idempotent.
    ///
    /// One step: no serve registers one of these ids between its teardown and its drain,
    /// or before the pass is pending, and no loop ending tears down half of one.
    ///
    /// A renamed child keeps the colon id it was served under (the live mailbox keeps it
    /// until the next start), so the registry, not the resolver, tells which one that is.
    /// And another child can hold a colon id this one held — its old handle, taken after
    /// a rename — so what is under a colon id is torn down only while the id bridge pairs
    /// it with this child or with no one.
    pub fn abort_child(&self, bare_id: &str) {
        let _under_way = self.terminate_scope();
        let resolved = (self.key_resolver)(bare_id);
        // Root-collision guard (mirrors `on_child_spawned`'s serve-path guard @below):
        // a child whose bare id mechanically maps onto the ROOT's colon (a guest
        // `spawn-child(id="default")` → `agent:root`, the root's serve/mailbox key)
        // must NOT have the ROOT's mailbox unfrozen/drained — that would be a
        // confused-deputy message-loss on the most-privileged agent — nor anything
        // forgotten under its id. Bail out entirely when the colon IS the root (the root's
        // loop is served by `start.rs`, never retained in this registry — nothing to
        // abort). `agent_kind` reads the seeded root's colon kind from `DynamicRouting`.
        if self.routing.agent_kind(&resolved) == Some(AgentKind::Root) {
            return;
        }
        // Read while the tree still holds the child: the cascade removes it after this.
        let ancestors = self.ancestors_of(bare_id);
        let (colons, aborted, pass) = {
            let mut registry = lock(&self.loops);
            for (served, cancelled) in registry.serving.values_mut() {
                if served == bare_id {
                    *cancelled = true;
                }
            }
            let mine: Vec<String> = registry
                .retained
                .iter()
                .filter(|(_, retained)| retained.bare_id == bare_id)
                .map(|(colon, _)| colon.clone())
                .collect();
            let mut colons: Vec<String> = Vec::new();
            let mut aborted = Vec::new();
            // Those a stop took out first ([`Self::stop_child`]): aborted already, and
            // under colon ids the child still holds.
            for (colon, stopped) in std::mem::take(&mut registry.stopped) {
                if stopped.bare_id != bare_id {
                    registry.stopped.push((colon, stopped));
                    continue;
                }
                aborted.push(stopped.handle);
                if !colons.contains(&colon) {
                    colons.push(colon);
                }
            }
            for colon in mine {
                if let Some(retained) = registry.retained.remove(&colon) {
                    retained.handle.abort();
                    aborted.push(retained.handle);
                    if !colons.contains(&colon) {
                        colons.push(colon);
                    }
                }
            }
            // The id it resolves to now, unless a loop of another child is retained there.
            if !registry.retained.contains_key(&resolved) && !colons.contains(&resolved) {
                colons.push(resolved);
            }
            // Pending from here on: a child that takes one of these ids once it is free waits
            // for it ([`Self::spawn_serve_loop`]).
            let pass = (!aborted.is_empty()).then(|| self.reserve_pass(bare_id, &colons));
            colons.retain(|colon| self.tear_down_under(bare_id, colon));
            (colons, aborted, pass)
        };
        self.forget_child(bare_id, &colons, aborted, pass, ancestors);
    }

    /// The ancestors of `bare_id`, nearest first, up to the root: those its knowledge
    /// entries may go to when it is terminated ([`AgentRecords::hand_over_knowledge`]).
    /// Read while the tree still holds `bare_id` — the cascade tears a node down before it
    /// removes it, and removes only leaves, so every ancestor is in the tree too —; empty
    /// when the tree does not know `bare_id`.
    fn ancestors_of(&self, bare_id: &str) -> Vec<String> {
        let mut ancestors = Vec::new();
        let mut at = self
            .tree
            .get_node(&AgentId(bare_id.to_string()))
            .and_then(|node| node.parent);
        while let Some(id) = at {
            if ancestors.len() > self.tree.len() {
                break;
            }
            at = self.tree.get_node(&id).and_then(|node| node.parent);
            ancestors.push(id.0);
        }
        ancestors
    }

    /// Whether a terminate of the child `bare_id` may empty the mailbox under `colon`: it
    /// is the child's own or no one's — not the root's, not paired by the id bridge with
    /// another agent, no loop of another child retained under it — as the ids
    /// [`Self::abort_child`] tears down are. For the terminate cascade's mailbox flush,
    /// which comes after [`Self::stop_child`] and before [`Self::abort_child`], and
    /// resolves the child's colon id anew from its handle ([`crate::client_api_agents::ColonMailboxCascade`]): a child renamed and
    /// still served under its old handle's colon id keeps its mailbox when another child
    /// that took that handle is terminated.
    pub fn may_flush(&self, bare_id: &str, colon: &str) -> bool {
        let registry = lock(&self.loops);
        self.routing.agent_kind(colon) != Some(AgentKind::Root)
            && registry
                .retained
                .get(colon)
                .is_none_or(|retained| retained.bare_id == bare_id)
            && self
                .bridge
                .resolve_owned(colon)
                .is_none_or(|(holder, _)| holder == bare_id)
    }

    /// Reserve the second pass of the terminated child `bare_id`, for the colon ids
    /// `colons` it may have held ([`Self::forget_child`]): pending from now on, so a child
    /// served later under any of these ids waits for it ([`Self::passes_before_serving`]),
    /// and to run after every pass before it that shares an id with it
    /// ([`passes_pending_for`]).
    fn reserve_pass(&self, bare_id: &str, colons: &[String]) -> ReservedPass {
        let mut sweeps = lock(&self.sweeps);
        // A pass that has run closed its channel: nothing waits for it any more.
        sweeps.retain(|pass| pass.swept.has_changed().is_ok());
        let ids: Vec<&str> = colons.iter().map(String::as_str).collect();
        let earlier = passes_pending_for(&sweeps, bare_id, &ids);
        let (done, swept) = watch::channel(());
        sweeps.push(PendingPass {
            bare_id: bare_id.to_string(),
            colon_ids: colons.to_vec(),
            swept,
        });
        ReservedPass { earlier, done }
    }

    /// Tear down what the terminated child `bare_id` leaves under `colon`: its route and
    /// its id pair ([`unroute`]), then — once nothing routes there — what waits in the
    /// mailbox, unfrozen first (a prior breaker-open leaves it frozen, and `poll` returns
    /// `None` while frozen — terminate must drain regardless). The pair goes before the
    /// drain, so a concurrent send dead-ends at `validate_routing` (`unknown_target`)
    /// rather than enqueueing into a now-unserved mailbox after it.
    ///
    /// Returns `false`, touching nothing, when another agent holds `colon` now: the id
    /// bridge pairs it with another bare id (the root's included).
    fn tear_down_under(&self, bare_id: &str, colon: &str) -> bool {
        if self.routing.agent_kind(colon) == Some(AgentKind::Root) {
            return false;
        }
        if self
            .bridge
            .resolve_owned(colon)
            .is_some_and(|(holder, _)| holder != bare_id)
        {
            return false;
        }
        let own = unroute(&self.routing, &self.bridge, bare_id, colon);
        // Drained once nothing routes the id: a route left with no pair of this child's is
        // someone else's. (This manager leaves none: each registration and each teardown
        // here is one step under the registry's lock, held by the caller.)
        if own || self.routing.agent_kind(colon).is_none() {
            self.drain_mailbox(colon);
        }
        true
    }

    /// Unfreeze the mailbox `colon`, then drain it, best-effort.
    fn drain_mailbox(&self, colon: &str) {
        if let Some(mb) = self.store.get(colon) {
            mb.unfreeze();
            let mut budget = mb.depth().saturating_add(8);
            while budget > 0 && mb.poll().is_some() {
                budget -= 1;
            }
        }
    }

    /// The terminated child `bare_id` is gone: forget what the context engine keeps
    /// under its bare id and the colon ids `colons` it held ([`AgentRecords`]), so an
    /// agent created later under the same ids starts with none of it — neither the turns
    /// the earlier one could recall, nor the provider entry it chatted on — and hand its
    /// knowledge entries over to the first of its `ancestors` still alive
    /// ([`Self::ancestors_of`], [`AgentRecords::hand_over_knowledge`]).
    ///
    /// Forgotten here and — when the child had serve loops, `aborted` — once more when
    /// those loops have ended, by the pass the terminate reserved for it before it tore
    /// anything down (`pass`, [`Self::reserve_pass`]): an aborted loop stops at its next
    /// await, and until then may finish the step it is in and write a row. A child served
    /// later under any of these ids does not start before that second pass
    /// ([`Self::spawn_serve_loop`]), so it neither reads what the earlier loop wrote late
    /// nor loses a row of its own to the pass; and a second pass starts only after every
    /// pass before it that shares an id with it ([`passes_pending_for`]).
    ///
    /// Nothing is forgotten at a spawn: the tree is served again at every start
    /// ([`Self::serve_existing_children`]), and a spawn is not a new agent. Nothing
    /// can be forgotten either when no stores are bound (no context deps) or once a
    /// shutdown has let go of them — that is logged — but the pass still stays pending
    /// until the child's aborted loops have ended: a shutdown and a child served later
    /// under its ids wait for those loops all the same.
    fn forget_child(
        &self,
        bare_id: &str,
        colons: &[String],
        aborted: Vec<tokio::task::JoinHandle<()>>,
        pass: Option<ReservedPass>,
        ancestors: Vec<String>,
    ) {
        let records = {
            let bound = lock(&self.record_stores);
            match bound.clone() {
                Some(stores) => {
                    let records = AgentRecords {
                        bare_id: bare_id.to_string(),
                        colon_ids: colons.to_vec(),
                        ancestors,
                        tree: self.tree.clone(),
                        stores,
                        log: self.log.clone(),
                    };
                    // No loop here to wait for, because a shutdown under way took the
                    // registry: it awaits the child's loop and then runs the second pass.
                    // Queued BEFORE the first pass, so a shutdown that has already taken the
                    // queue has also seen every loop end — and the first pass, after it,
                    // forgets all they wrote. And queued while the stores are held, so a
                    // shutdown's release ([`Self::unbind`]) takes the queue with them or
                    // after it.
                    if aborted.is_empty() && self.closed.load(Ordering::SeqCst) {
                        lock(&self.forget_at_shutdown).push(records.clone());
                    }
                    Some(records)
                }
                None => {
                    if self.closed.load(Ordering::SeqCst) {
                        self.log.err(
                            log_keys::PERCHILD_FORGET_FAILED,
                            format!(
                                "perchild: terminated child {bare_id} is not forgotten: the \
                                 composition has shut down and let go of the stores it is \
                                 kept in"
                            ),
                        );
                    }
                    None
                }
            }
        };
        if let Some(records) = records.as_ref() {
            records.forget();
        }
        let Some(ReservedPass { earlier, done }) = pass else {
            return;
        };
        self.handle.spawn(async move {
            for earlier in earlier {
                closed(earlier).await;
            }
            for aborted in aborted {
                let _ = aborted.await;
            }
            if let Some(records) = records {
                records.forget_late();
                // Let go of the stores before telling anyone the pass has run: a shutdown
                // that waited for it releases them next.
                drop(records);
            }
            drop(done);
        });
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
                let msg = format!(
                    "advance: WARN child {child_bare} gets no `{cap_name}` grant: {}",
                    refusals.join("; ")
                );
                if refused_restricted_fs && refusals.len() == 1 {
                    self.log.err(log_keys::PERCHILD_NO_FS_GRANT, msg);
                } else {
                    self.log.err(log_keys::PERCHILD_NO_GRANT, msg);
                }
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
        // Under way from here: a terminate of the child from now on cancels it.
        let serving = Serving::begin(self, child_bare);
        // The node this serve is for, read once the serve is under way: a terminate of the
        // child too early to cancel it marked the child terminated before this read (the
        // cap-lifecycle cascade marks it before it stops the child's loops, and a crash of
        // those loops on the way out leaves the mark: `handle_crash`). It must still
        // be the node the call was made for — in the tree, not terminated, below `parent` and
        // at `workspace` ([`same_workspace`]), as the spawner and the boot walk
        // ([`Self::serve_existing_children`]) call it, and as no node changes once inserted. A
        // call that comes late (a spawn held up, a boot walk's snapshot gone stale) for a
        // child terminated since, or for another child that has taken its bare id since,
        // serves nothing.
        let Some(node) = self.tree.get_node(child).filter(|node| {
            node.status != AgentStatus::Terminated
                && node.parent.as_ref() == Some(parent)
                && same_workspace(&node.workspace_path, workspace)
        }) else {
            self.log.err(
                log_keys::PERCHILD_STALE_SERVE,
                format!(
                    "perchild: child {child_bare} was terminated, or its id taken by another \
                     child, before it was served; not served"
                ),
            );
            return;
        };
        let child_colon = (self.key_resolver)(child_bare);
        let parent_colon = (self.key_resolver)(parent_bare);

        // The child's declared capabilities (from its tree node).
        let declared: Vec<Capability> = node.capabilities;
        let caps: Vec<CapRequest> = declared
            .iter()
            .map(|c| CapRequest {
                capability: c.id.clone(),
            })
            .collect();

        // seam (d).i — L1 grant delegation so the child can act.
        self.delegate_child_grants(parent_bare, child_bare, &declared);

        // Discriminator: child-loop-absent — register seam-(e) routing but serve NO
        // loop (the intentional routable-but-unserved state the witness asserts), as a
        // serve registers ([`Self::register_unserved`]).
        if self.skip_loop {
            if !self.skip_routing {
                self.register_unserved(&serving, child_bare, &child_colon, &parent_colon);
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
        let handler: Arc<dyn MessageHandler> = {
            let mut h = WasmMessageHandler::new(
                runtime,
                loaded,
                injector,
                caps,
                child_bare.to_string(),
                format!("trace-child-{child_bare}"),
            )
            .with_log(self.log.clone());
            if let Some(deps) = lock(&self.context_deps).clone() {
                h = h.with_llm_gateway(deps.gateway.clone());
            }
            Arc::new(h)
        };
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
        // `handle_crash` (child tree status → Failed + parent `component.terminated`;
        // nothing once a terminate has marked the child terminated).
        // `skip_crash` (witness-only) suppresses it for the crash-cascade discriminator.
        if !self.skip_crash {
            if let Some(sink) = self.crash_sink.as_ref() {
                driver = driver.with_crash_cascade(Arc::new(ServedCrashSink {
                    inner: sink.clone(),
                    loops: self.loops.clone(),
                    colon_id: child_colon.clone(),
                    serve: serving.serve,
                }));
            }
        }
        let mut reports = None;
        if let Some(deps) = lock(&self.context_deps).clone() {
            let cap_names: Vec<String> =
                declared.iter().map(|c| c.id.as_str().to_string()).collect();
            driver = crate::child_context::attach_child_context(
                driver,
                &deps,
                child_bare,
                &child_colon,
                workspace,
                &cap_names,
            );
            reports = Some(deps.context_store.clone());
        }
        // The child's alias group in the context store: registered once its loop is
        // retained, so a child that is never served leaves none.
        let aliases = [child_bare.to_string(), child_colon.clone()];
        let retained = move || {
            if let Some(reports) = reports {
                reports.register_aliases(&aliases);
            }
        };
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
        // seam (e) — the driver LOADED, so the serve registers colon routing + the
        // id-bridge pair (a load-failing spawn returned above without registering), in
        // the one step that decides and spawns the loop ([`Self::spawn_serve_loop`],
        // [`Self::register_route`]): before the spawn, so the teardown below can never
        // race ahead of the registration. (`skip_routing` — a witness discriminator —
        // intentionally serves without registering and is production-unreachable.)
        // audit r8 W2 — when `serve` RETURNS (a component that loaded but trapped in
        // `bootstrap_and_init`, or a guest stop), the loop is no longer live: the loop TEARS
        // DOWN the seam-(e) registration so a parent send then dead-ends cleanly
        // (`unknown_target`) rather than black-holing into a now-unserved mailbox — while
        // the registry still retains it ([`Self::spawn_serve_loop`], [`RouteCleanup`]).
        let parent_route = (!self.skip_routing).then_some(parent_colon.as_str());
        self.spawn_serve_loop(
            &serving,
            child_bare,
            child_colon,
            parent_route,
            retained,
            async move {
                driver.serve(&serve_key, cfg, instance).await;
            },
        );
    }
}

impl PerChildLoopManager {
    /// The passes a loop served now for the child `bare_id`, under `colon_id`, waits for
    /// before it starts: those of a child that held either id before and was terminated
    /// ([`Self::forget_child`], [`passes_pending_for`]) — so it starts once that one's
    /// loop has ended and what it left is forgotten.
    fn passes_before_serving(&self, bare_id: &str, colon_id: &str) -> Vec<watch::Receiver<()>> {
        passes_pending_for(&lock(&self.sweeps), bare_id, &[colon_id])
    }

    /// Serve the child `bare_id` under `colon_id`, for `serving`, in one step under the
    /// registry's lock: decide; register the child's route below `parent_colon` and its id
    /// pair ([`Self::register_route`]) — none when `parent_colon` is `None`, the
    /// `skip_routing` witness serving unrouted; take the passes its loop waits for
    /// ([`Self::passes_before_serving`]); spawn `serve`, its serve loop, to start once those
    /// have run and, when `serve` returns, to tear down what was registered here while the
    /// registry still retains it ([`RouteCleanup`]); retain it; and run `retained`. Returns
    /// whether the loop is retained.
    ///
    /// It is not when, as the registry is taken, a shutdown has begun (it drains the
    /// registry, and no loop may outlive it); when a terminate of the child has cancelled
    /// `serving`; when the tree shows the child terminated or gone; or when its colon id
    /// collides with another agent's. Then nothing of it is left registered, and `serve`
    /// is never spawned.
    ///
    /// A terminate ([`Self::stop_child`], [`Self::abort_child`]) cancels the serves of its
    /// child under way and takes the child's loops out under the same lock: so either it
    /// finds the loop — and its teardown ([`Self::abort_child`]) tears down the route and
    /// the id pair registered with it — or the serve finds itself cancelled and registers
    /// nothing, so no later serve meets a route a cancelled serve
    /// holds. A serve that began after a terminate of its child reads the tree after
    /// that terminate marked the child terminated (the cap-lifecycle cascade marks it
    /// before it stops the child's loop, and a crash of that loop leaves the mark), so the
    /// tree shows it terminated or gone. So it does a child a failed terminate left marked
    /// terminated.
    ///
    /// The passes are taken once the colon id is registered: a child can register a colon
    /// id another child held only once that one's route and id pair under it are gone —
    /// torn down by that one's terminate, which reserved its pass first
    /// ([`Self::reserve_pass`]), or by that one's loop as it ended, which writes nothing
    /// after.
    ///
    /// A loop retained under `colon_id` before is stopped, not let go of: a task let go of
    /// runs on out of the registry's reach, and holds what it holds after a shutdown.
    fn spawn_serve_loop(
        &self,
        serving: &Serving<'_>,
        bare_id: &str,
        colon_id: String,
        parent_colon: Option<&str>,
        retained: impl FnOnce(),
        serve: impl std::future::Future<Output = ()> + Send + 'static,
    ) -> bool {
        {
            let mut registry = lock(&self.loops);
            if !self.may_serve(&registry, serving, bare_id) {
                return false;
            }
            if parent_colon.is_none_or(|parent| self.register_route(bare_id, &colon_id, parent)) {
                let predecessors = self.passes_before_serving(bare_id, &colon_id);
                // What the loop tears down when `serve` returns: what was registered here,
                // while the registry still retains this loop ([`RouteCleanup`]).
                let cleanup = parent_colon.map(|_| RouteCleanup {
                    loops: self.loops.clone(),
                    routing: self.routing.clone(),
                    bridge: self.bridge.clone(),
                    bare_id: bare_id.to_string(),
                    colon_id: colon_id.clone(),
                    serve: serving.serve,
                });
                let handle = self.handle.spawn(async move {
                    for swept in predecessors {
                        closed(swept).await;
                    }
                    serve.await;
                    if let Some(cleanup) = cleanup {
                        cleanup.run();
                    }
                });
                let replaced = registry.retained.insert(
                    colon_id,
                    Retained {
                        bare_id: bare_id.to_string(),
                        serve: serving.serve,
                        handle,
                    },
                );
                if let Some(replaced) = replaced {
                    replaced.handle.abort();
                    // Those stopped before and ended since leave nothing to wait for.
                    registry.stopping.retain(|stopped| !stopped.is_finished());
                    registry.stopping.push(replaced.handle);
                }
                retained();
                return true;
            }
        }
        self.log.err(
            log_keys::PERCHILD_COLON_COLLISION,
            format!(
                "perchild: child {bare_id} colon id {colon_id} collides with an existing agent; \
                 not served (tree node recorded, unrouted)"
            ),
        );
        false
    }

    /// Whether the serve `serving` of the child `bare_id` may go on, `registry` — the
    /// registry's lock — held: no shutdown has begun (it drains the registry, and no loop
    /// may outlive it), no terminate of the child has cancelled the serve, and the tree
    /// shows the child neither terminated nor gone.
    fn may_serve(&self, registry: &LoopRegistry, serving: &Serving<'_>, bare_id: &str) -> bool {
        if self.closed.load(Ordering::SeqCst) {
            return false;
        }
        let cancelled = registry
            .serving
            .get(&serving.serve)
            .is_some_and(|(_, cancelled)| *cancelled);
        let gone = self
            .tree
            .get_node(&AgentId(bare_id.to_string()))
            .is_none_or(|node| node.status == AgentStatus::Terminated);
        !cancelled && !gone
    }

    /// The serve of the `skip_loop` witness: register the route of the child `bare_id`
    /// below `parent_colon` and its id pair, and serve no loop — in one step under the
    /// registry's lock, as [`Self::spawn_serve_loop`] registers, and only while the serve
    /// may go on ([`Self::may_serve`]). Returns whether it registered.
    fn register_unserved(
        &self,
        serving: &Serving<'_>,
        bare_id: &str,
        colon_id: &str,
        parent_colon: &str,
    ) -> bool {
        let registry = lock(&self.loops);
        self.may_serve(&registry, serving, bare_id)
            && self.register_route(bare_id, colon_id, parent_colon)
    }

    /// Register the route of the child `bare_id` under `colon_id`, below `parent_colon`,
    /// and its id pair (seam e), the registry's lock held. Returns whether both are its own
    /// now; when either is another agent's, the one it did register is undone, and nothing
    /// of it is left.
    ///
    /// audit r10 — COLON-ID COLLISION GUARD: `register_child` / `register` are FIRST-WINS
    /// and return `false` when `colon_id` (or the bare form) already belongs to another
    /// agent. The reachable case is a child whose bare id MECHANICALLY maps onto the ROOT's
    /// SPECIAL colon — a guest `spawn-child(id="default")` resolves to `agent:root`, the
    /// root's OWN serve key (`validate_agent_id` is charset-only, no reserved-name guard).
    /// Serving a loop on a colliding key would poll the INCUMBENT's mailbox — a
    /// confused-deputy / message-theft hijack of the root. So on ANY rejected registration
    /// the serve rolls back a partial one and DOES NOT serve: the child stays an unserved
    /// tree node (safe; the incumbent keeps its mailbox intact).
    fn register_route(&self, bare_id: &str, colon_id: &str, parent_colon: &str) -> bool {
        let routed = self.routing.register_child(colon_id, parent_colon);
        let bridged = self.bridge.register(colon_id, bare_id);
        if routed && bridged {
            return true;
        }
        if routed {
            self.routing.unregister_child(colon_id);
        }
        if bridged {
            self.bridge.unregister(colon_id, bare_id);
        }
        false
    }
}

/// Lock `mutex`, recovering the guard from a poisoned lock (every value it guards
/// stays consistent across a panic: a slot or a map of task handles).
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

/// Whether `workspace`, as a serve is called with it, is the workspace `canonical` of a tree
/// node. The tree keeps the canonical form (`AgentTreeStore::insert_child` canonicalizes
/// it), which the path a spawner hands on need not be: a temporary directory under `/var`
/// is under `/private/var` on macOS. A workspace that is not there any more is not it.
fn same_workspace(canonical: &Path, workspace: &Path) -> bool {
    canonical == workspace
        || workspace
            .canonicalize()
            .is_ok_and(|workspace| workspace == canonical)
}

/// seam (f) glue: a cap-lifecycle [`cap_lifecycle::LoopCascade`] backed by the
/// [`PerChildLoopManager`]. A `DefaultTerminateController` wired with
/// `.with_loop_cascade(..)` uses it to stop a terminating child's serve loop, and to tear
/// down its colon routing / mailbox / records once the child's own cascade steps have
/// succeeded. `stop_loop` and `abort_loop` forward the BARE tree id `terminate_child`
/// provides; `PerChildLoopManager::stop_child` and `PerChildLoopManager::abort_child` find
/// the loops and the colon ids the child was served under.
///
/// Wired into `advance start` for the terminate controller of the Client API agents
/// family (`DELETE /client/agents/{id}`), which the pack workflow executor's spawn
/// compensation shares (`wiring.rs`, `build_agent_terminate_controller`): a child
/// terminated through either stops its loops here, while other spawns and terminates may
/// run concurrently. A guest's own `terminate-child` is not registered: `wire_capabilities`
/// registers `register_agent_spawn` + `register_agent_decomposition`, not the full
/// `register_agent_lifecycle` bundle. SYS-J-68 `sys_ac_281_*` witness the leg on the
/// production `DefaultTerminateController` + this adapter.
pub struct PerChildLoopCascade {
    manager: Arc<PerChildLoopManager>,
}

impl PerChildLoopCascade {
    pub fn new(manager: Arc<PerChildLoopManager>) -> Self {
        Self { manager }
    }
}

impl cap_lifecycle::LoopCascade for PerChildLoopCascade {
    fn stop_loop(&self, agent_id: &str) {
        self.manager.stop_child(agent_id);
    }

    fn abort_loop(&self, agent_id: &str) {
        self.manager.abort_child(agent_id);
    }

    fn terminate_scope(&self) -> Option<Box<dyn Send>> {
        Some(Box::new(self.manager.terminate_scope()))
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroUsize;

    use advance_database::{R2d2SqliteIndexHandle, SqliteIndexHandle};
    use advance_shared_types::agent_tree::AgentNode;
    use advance_shared_types::capability::{CapParams, CapabilityId};
    use advance_shared_types::event::Event;
    use advance_shared_types::mailbox::{Message, MessageKind};
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
        let home = kid_home(parent_grants, child_caps);
        home.manager
            .on_child_spawned(&home.root, &home.kid, &home.kid_dir);
        home.grants.list_by_grantee("kid")
    }

    /// The home [`spawn_kid`] spawns `kid` in, before the spawn.
    struct KidHome {
        _ws: tempfile::TempDir,
        manager: PerChildLoopManager,
        grants: Arc<GrantStore>,
        root: AgentId,
        kid: AgentId,
        kid_dir: std::path::PathBuf,
    }

    fn kid_home(
        parent_grants: Vec<(&str, &str, Vec<CapParam>)>,
        child_caps: Vec<Capability>,
    ) -> KidHome {
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
        KidHome {
            _ws: ws,
            manager,
            grants,
            root,
            kid,
            kid_dir,
        }
    }

    /// A serve called late serves nothing — for a child terminated since or gone, or for a
    /// node that is not the one the call was made for (below another parent, at another
    /// workspace: another child took the bare id since). It delegates no grant, and says
    /// why. Called for the node that is there, it goes on (to the unbound runtime, here).
    #[tokio::test]
    async fn a_serve_called_for_a_node_that_is_not_there_any_more_serves_nothing() {
        let grants = || vec![("static:root:mcp", "mcp", Vec::new())];
        let caps = || vec![declared("mcp", serde_json::Value::Null)];
        for stale in ["terminated", "gone", "another parent", "another workspace"] {
            let lines = Arc::new(Lines::default());
            let mut home = kid_home(grants(), caps());
            home.manager = home.manager.with_log(LogHandle::new(lines.clone()));
            let mut parent = home.root.clone();
            let mut workspace = home.kid_dir.clone();
            match stale {
                "terminated" => home
                    .manager
                    .tree
                    .set_status(&home.kid, AgentStatus::Terminated)
                    .expect("kid is in the tree"),
                "gone" => {
                    home.manager.tree.remove(&home.kid).expect("kid is a leaf");
                }
                "another parent" => parent = AgentId("other".to_string()),
                _ => workspace = home.kid_dir.join("elsewhere"),
            }
            home.manager
                .on_child_spawned(&parent, &home.kid, &workspace);
            assert!(home.grants.list_by_grantee("kid").is_empty(), "{stale}");
            assert_eq!(lines.keys(), [log_keys::PERCHILD_STALE_SERVE], "{stale}");
        }

        let lines = Arc::new(Lines::default());
        let mut home = kid_home(grants(), caps());
        home.manager = home.manager.with_log(LogHandle::new(lines.clone()));
        home.manager
            .on_child_spawned(&home.root, &home.kid, &home.kid_dir);
        assert!(grant_of(&home.grants.list_by_grantee("kid"), "mcp").is_some());
        assert_eq!(lines.keys(), [log_keys::PERCHILD_UNBOUND]);
    }

    /// A workspace is the node's when it is the node's canonical path or leads to it (a
    /// path through a link, as a temporary directory on macOS is), and not when it is
    /// another directory or not there at all.
    #[cfg(unix)]
    #[test]
    fn a_workspace_is_the_nodes_when_it_leads_to_the_same_directory() {
        let ws = tempfile::TempDir::new().expect("tempdir");
        let real = ws.path().join("real");
        let other = ws.path().join("other");
        std::fs::create_dir_all(&real).expect("real");
        std::fs::create_dir_all(&other).expect("other");
        let link = ws.path().join("link");
        std::os::unix::fs::symlink(&real, &link).expect("link");
        let canonical = real.canonicalize().expect("canonical");

        assert!(same_workspace(&canonical, &canonical));
        assert!(same_workspace(&canonical, &link), "through a link");
        assert!(same_workspace(&canonical, &real));
        assert!(!same_workspace(&canonical, &other), "another directory");
        assert!(!same_workspace(&canonical, &ws.path().join("gone")), "gone");
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

    // -----------------------------------------------------------------------
    // A terminated child is forgotten
    // -----------------------------------------------------------------------

    use std::sync::atomic::AtomicBool;
    use std::sync::mpsc;

    use advance_context_engine::AssemblyReportSink;
    use cap_memory::{InMemorySqliteIndex, SqliteIndex, TurnIndexRow};

    use crate::context_inspect::ContextSnapshotStore;

    /// Records the ids it is told to forget.
    #[derive(Default)]
    struct Chats(Mutex<Vec<String>>);

    impl Chats {
        fn forgotten(&self) -> Vec<String> {
            self.0.lock().unwrap().clone()
        }
    }

    impl ChatRecord for Chats {
        fn forget_agent(&self, agent_id: &str) {
            self.0.lock().unwrap().push(agent_id.to_string());
        }
    }

    /// A manager over a tree of `root` and its child `kid`, bound to the stores a
    /// terminated child is forgotten from. No runtime is bound: no child is served.
    struct Managed {
        _ws: tempfile::TempDir,
        manager: PerChildLoopManager,
        chats: Arc<Chats>,
        index: Arc<InMemorySqliteIndex>,
        reports: Arc<ContextSnapshotStore>,
        knowledge: Arc<cap_memory::MemoryStore>,
    }

    fn managed() -> Managed {
        // The root's mailbox is the special pair; `default` maps onto it too.
        managed_with(Arc::new(|bare: &str| match bare {
            "root" | "default" => "agent:root".to_string(),
            other => format!("agent:{other}"),
        }))
    }

    /// [`managed`] whose colon ids follow the handles in `handles` (an agent without
    /// one keeps its bare id), as the production resolver follows the tree's handles.
    fn managed_with_handles(handles: Arc<Mutex<HashMap<String, String>>>) -> Managed {
        managed_with(Arc::new(move |bare: &str| match bare {
            "root" | "default" => "agent:root".to_string(),
            other => {
                let handle = handles.lock().unwrap().get(other).cloned();
                format!("agent:{}", handle.as_deref().unwrap_or(other))
            }
        }))
    }

    fn managed_with(key_resolver: KeyResolver) -> Managed {
        let ws = tempfile::TempDir::new().expect("tempdir");
        let root_dir = ws.path().join("root");
        let kid_dir = root_dir.join("kid");
        std::fs::create_dir_all(&kid_dir).expect("territories");
        let root = AgentId("root".to_string());
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
                id: AgentId("kid".to_string()),
                kind: AgentKind::Child,
                parent: Some(root.clone()),
                workspace_path: kid_dir,
                capabilities: Vec::new(),
                template_ref: None,
                status: AgentStatus::Active,
            },
        )
        .expect("child node");
        let routing = Arc::new(DynamicRouting::new(
            Arc::new(tree.clone()) as Arc<dyn AgentTreeReader>
        ));
        routing.seed_root("agent:root");
        let manager = PerChildLoopManager::new(
            Arc::new(MailboxStore::new(NonZeroUsize::new(8).expect("capacity"))),
            Arc::new(NullBus),
            routing,
            Arc::new(AgentIdBridge::from_pairs([("agent:root", "root")])),
            None,
            tree,
            tokio::runtime::Handle::current(),
            key_resolver,
        );
        let chats = Arc::new(Chats::default());
        let index = Arc::new(InMemorySqliteIndex::default());
        let reports = Arc::new(ContextSnapshotStore::new());
        let knowledge = Arc::new(cap_memory::MemoryStore::new());
        *lock(&manager.record_stores) = Some(RecordStores {
            chats: chats.clone(),
            memory_index: Some(index.clone()),
            context_store: reports.clone(),
            knowledge: Some(knowledge.clone()),
        });
        Managed {
            _ws: ws,
            manager,
            chats,
            index,
            reports,
            knowledge,
        }
    }

    fn turn_of(agent: &str, turn: u32) -> TurnIndexRow {
        TurnIndexRow {
            agent_id: agent.to_string(),
            task_id: "task".to_string(),
            turn,
            digest: format!("what {agent} was told in turn {turn}"),
            embedding: vec![1.0, 0.0],
            embedding_model: Some("embed".to_string()),
            reference_count: 0,
            updated_at: "2026-11-17T00:00:00Z".to_string(),
        }
    }

    fn turns_of(index: &InMemorySqliteIndex, agent: &str) -> usize {
        index.list_turns_for_agent(agent).len()
    }

    fn aliases(bare: &str) -> [String; 2] {
        [bare.to_string(), format!("agent:{bare}")]
    }

    /// A loop that is in the middle of a step when it is told to stop: it goes on to
    /// write one more row of `agent` (turn 2) before it reaches an await, where the
    /// abort ends it. Returns the loop, the sender that lets the step finish and the
    /// flag the write sets.
    fn loop_in_a_step(
        index: &Arc<InMemorySqliteIndex>,
        agent: &'static str,
    ) -> (
        tokio::task::JoinHandle<()>,
        mpsc::Sender<()>,
        Arc<AtomicBool>,
    ) {
        let (in_step, entered) = mpsc::channel::<()>();
        let (finish, may_finish) = mpsc::channel::<()>();
        let written = Arc::new(AtomicBool::new(false));
        let (index, wrote) = (index.clone(), written.clone());
        let looping = tokio::spawn(async move {
            in_step.send(()).expect("the test waits for the step");
            may_finish
                .recv_timeout(WAIT)
                .expect("the test lets the step finish");
            index.upsert_turn(turn_of(agent, 2));
            wrote.store(true, Ordering::SeqCst);
            std::future::pending::<()>().await;
        });
        entered.recv_timeout(WAIT).expect("the loop is in its step");
        (looping, finish, written)
    }

    /// The most recent pass pending under `colon`.
    fn pending_pass(manager: &PerChildLoopManager, colon: &str) -> watch::Receiver<()> {
        lock(&manager.sweeps)
            .iter()
            .rev()
            .find(|pass| pass.colon_ids.iter().any(|held| held == colon))
            .map(|pass| pass.swept.clone())
            .unwrap_or_else(|| panic!("no pass is pending for {colon}"))
    }

    /// The loop `looping`, already running, retained for the child `bare` under `colon`.
    fn retain_running(
        manager: &PerChildLoopManager,
        bare: &str,
        colon: &str,
        looping: tokio::task::JoinHandle<()>,
    ) {
        lock(&manager.loops).retained.insert(
            colon.to_string(),
            Retained {
                bare_id: bare.to_string(),
                serve: manager.next_serve.fetch_add(1, Ordering::Relaxed),
                handle: looping,
            },
        );
    }

    /// Serve the child `bare` under `colon` with `serve` as `on_child_spawned` does, a serve
    /// begun now, registering no route (as the `skip_routing` witness serves; [`route`]
    /// stands in for the registration where a test needs one). Returns whether its loop is
    /// retained.
    fn serve(
        manager: &PerChildLoopManager,
        bare: &str,
        colon: &str,
        serve: impl std::future::Future<Output = ()> + Send + 'static,
    ) -> bool {
        let serving = Serving::begin(manager, bare);
        manager.spawn_serve_loop(&serving, bare, colon.to_string(), None, || {}, serve)
    }

    /// [`serve`], registering the child's route below the root and its id pair, as the
    /// serve of a spawned child does.
    fn serve_routed(
        manager: &PerChildLoopManager,
        bare: &str,
        colon: &str,
        serve: impl std::future::Future<Output = ()> + Send + 'static,
    ) -> bool {
        let serving = Serving::begin(manager, bare);
        manager.spawn_serve_loop(
            &serving,
            bare,
            colon.to_string(),
            Some("agent:root"),
            || {},
            serve,
        )
    }

    /// Nothing of the child `bare` is registered under `colon`: no route, no id pair.
    fn assert_not_registered(manager: &PerChildLoopManager, bare: &str, colon: &str) {
        assert_eq!(manager.routing.agent_kind(colon), None, "{colon} is routed");
        assert_eq!(manager.bridge.resolve_owned(colon), None);
        assert_eq!(manager.bridge.resolve_owned(bare), None);
    }

    /// The child each loop retained under `colon` serves.
    fn served_under(manager: &PerChildLoopManager, colon: &str) -> Option<String> {
        lock(&manager.loops)
            .retained
            .get(colon)
            .map(|retained| retained.bare_id.clone())
    }

    /// How long a test waits for what must happen: a regression that never lets it happen
    /// fails the test instead of stalling the run.
    const WAIT: std::time::Duration = std::time::Duration::from_secs(20);

    /// `wait`, which must end within [`WAIT`].
    async fn within<T>(wait: impl std::future::Future<Output = T>) -> T {
        tokio::time::timeout(WAIT, wait)
            .await
            .expect("ends in time")
    }

    /// Drive `shutdown` until it waits for a terminate under way ([`Terminates::waited_for`]),
    /// within [`WAIT`]: a shutdown that ends first has let go of the stores while a
    /// terminate was under way.
    async fn waits_for_a_terminate(
        manager: &PerChildLoopManager,
        shutdown: std::pin::Pin<&mut impl std::future::Future<Output = ()>>,
    ) {
        within(async {
            tokio::select! {
                () = manager.terminates.waited_for.notified() => {}
                () = shutdown => panic!("the shutdown ended while a terminate was under way"),
            }
        })
        .await;
    }

    /// Join `thread`, which must end within [`WAIT`].
    fn joined<T>(thread: std::thread::JoinHandle<T>) -> T {
        let deadline = std::time::Instant::now() + WAIT;
        while !thread.is_finished() {
            assert!(
                std::time::Instant::now() < deadline,
                "the thread ends in time"
            );
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        thread.join().expect("the thread ends without a panic")
    }

    /// Route the child `bare` under `colon` — its route and its id pair, as its serve
    /// registers them — with a message waiting in its mailbox.
    fn route(manager: &PerChildLoopManager, bare: &str, colon: &str) {
        assert!(manager.routing.register_child(colon, "agent:root"));
        assert!(manager.bridge.register(colon, bare));
        deliver(manager, bare, colon);
    }

    /// Leave a message for the child `bare` waiting in the mailbox `colon`.
    fn deliver(manager: &PerChildLoopManager, bare: &str, colon: &str) {
        manager
            .store
            .get_or_create(colon)
            .expect("mailbox")
            .deliver(Message {
                id: format!("for-{bare}"),
                kind: MessageKind::User,
                from: "user:test".to_string(),
                to: colon.to_string(),
                payload: b"hello".to_vec(),
                context: None,
                timestamp: std::time::SystemTime::now(),
                origin: None,
            })
            .expect("delivered");
    }

    /// Wait until no loop retained by `manager` runs any more.
    async fn loops_ended(manager: &PerChildLoopManager) {
        within(async {
            while manager.active_loop_count() > 0 {
                tokio::task::yield_now().await;
            }
        })
        .await;
    }

    /// Nothing of the child `bare` is left routed under `colon`, nor waiting in its
    /// mailbox.
    fn assert_unrouted(manager: &PerChildLoopManager, bare: &str, colon: &str) {
        assert_eq!(manager.routing.agent_kind(colon), None, "{colon} is routed");
        assert_eq!(manager.bridge.resolve_owned(colon), None);
        assert_eq!(manager.bridge.resolve_owned(bare), None);
        assert_eq!(
            manager.store.get(colon).map(|mailbox| mailbox.depth()),
            Some(0),
            "the mailbox is drained"
        );
    }

    /// A knowledge entry of `agent`'s.
    fn knowledge_of(agent: &str, id: &str, content: &str) -> cap_memory::MemoryEntry {
        cap_memory::MemoryEntry {
            id: id.to_string(),
            agent_id: agent.to_string(),
            entry_type: cap_memory::MemoryType::Fact,
            content: content.to_string(),
            tags: Vec::new(),
            created_at: "2026-11-17T00:00:00Z".to_string(),
            task_origin: None,
            is_active: true,
            superseded_by: None,
            status: cap_memory::MemoryStatus::Active,
            supersession_reason: None,
            cluster_id: None,
            sources: Vec::new(),
        }
    }

    fn knowledge_ids(home: &Managed, agent: &str) -> Vec<String> {
        home.knowledge
            .list(agent)
            .into_iter()
            .map(|entry| entry.id)
            .collect()
    }

    fn mark_terminated(home: &Managed, bare: &str) {
        home.manager
            .tree
            .set_status(&AgentId(bare.to_string()), AgentStatus::Terminated)
            .expect("the node is in the tree");
    }

    /// A terminated child's knowledge entries are kept, as history, and taken over by its
    /// parent (owner decision 2026-11-17): under the parent's id, naming the child.
    #[tokio::test]
    async fn a_terminated_child_hands_its_knowledge_over_to_its_parent() {
        let lines = Arc::new(Lines::default());
        let mut home = managed();
        home.manager = home.manager.with_log(LogHandle::new(lines.clone()));
        home.knowledge
            .insert("root", knowledge_of("root", "r1", "the root's own"))
            .expect("insert");
        home.knowledge
            .insert("kid", knowledge_of("kid", "k1", "what the child learned"))
            .expect("insert");
        mark_terminated(&home, "kid");
        home.manager.abort_child("kid");
        assert!(
            knowledge_ids(&home, "kid").is_empty(),
            "the child holds none"
        );
        assert_eq!(knowledge_ids(&home, "root"), ["r1", "k1"]);
        let taken = home
            .knowledge
            .get("root", "k1")
            .expect("the parent holds it");
        assert_eq!(taken.agent_id, "root");
        assert_eq!(taken.tags, ["from-agent:kid"]);
        let recalled: Vec<String> = home
            .knowledge
            .recall("root", "learned", 10)
            .into_iter()
            .map(|entry| entry.id)
            .collect();
        assert_eq!(recalled, ["k1"], "the parent recalls it as its own");
        assert_eq!(lines.keys(), [log_keys::PERCHILD_HANDOVER]);
        let line = lines.0.lock().unwrap()[0].1.clone();
        assert_eq!(
            line,
            "perchild: the knowledge entries of terminated child kid are handed over to root \
             (moved 1, active 1); root holds active entries: 1 of its own, 1 handed over to it"
        );
    }

    /// A loop that is in the middle of a step when it is told to stop: it goes on to
    /// remember one more entry of `agent`'s (`id`) before it reaches an await, where the
    /// abort ends it. Returns the loop and the sender that lets the step finish.
    fn remembering_in_a_step(
        knowledge: &Arc<cap_memory::MemoryStore>,
        agent: &'static str,
        id: &'static str,
    ) -> (tokio::task::JoinHandle<()>, mpsc::Sender<()>) {
        let (in_step, entered) = mpsc::channel::<()>();
        let (finish, may_finish) = mpsc::channel::<()>();
        let knowledge = knowledge.clone();
        let looping = tokio::spawn(async move {
            in_step.send(()).expect("the test waits for the step");
            may_finish
                .recv_timeout(WAIT)
                .expect("the test lets the step finish");
            knowledge
                .insert(
                    agent,
                    knowledge_of(agent, id, "learned at the end of a step"),
                )
                .expect("insert");
            std::future::pending::<()>().await;
        });
        entered.recv_timeout(WAIT).expect("the loop is in its step");
        (looping, finish)
    }

    /// A subtree's knowledge goes to the agent that outlives it, whichever pass runs last:
    /// a grandchild's entries — and the one its loop writes late, once its parent, being
    /// terminated with it, has been torn down — to the root, not to that parent.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_terminated_subtree_hands_its_knowledge_over_to_the_agent_that_outlives_it() {
        let home = managed();
        let workspace = home._ws.path().join("root").join("kid").join("gc");
        std::fs::create_dir_all(&workspace).expect("territory");
        home.manager
            .tree
            .insert_child(
                &AgentId("kid".to_string()),
                AgentNode {
                    id: AgentId("gc".to_string()),
                    kind: AgentKind::Child,
                    parent: Some(AgentId("kid".to_string())),
                    workspace_path: workspace,
                    capabilities: Vec::new(),
                    template_ref: None,
                    status: AgentStatus::Active,
                },
            )
            .expect("grandchild node");
        home.knowledge
            .insert(
                "gc",
                knowledge_of("gc", "g1", "what the grandchild learned"),
            )
            .expect("insert");
        home.knowledge
            .insert("kid", knowledge_of("kid", "k1", "what the child learned"))
            .expect("insert");
        let (looping, finish) = remembering_in_a_step(&home.knowledge, "gc", "g-late");
        route(&home.manager, "gc", "agent:gc");
        retain_running(&home.manager, "gc", "agent:gc", looping);
        mark_terminated(&home, "kid");
        mark_terminated(&home, "gc");

        // Post-order, each node torn down and then removed, as the cascade does.
        home.manager.abort_child("gc");
        let pass = pending_pass(&home.manager, "agent:gc");
        home.manager
            .tree
            .remove(&AgentId("gc".to_string()))
            .expect("a leaf");
        home.manager.abort_child("kid");
        home.manager
            .tree
            .remove(&AgentId("kid".to_string()))
            .expect("a leaf");
        assert_eq!(knowledge_ids(&home, "root"), ["g1", "k1"]);

        finish.send(()).expect("the loop is still in its step");
        within(closed(pass)).await;
        assert!(knowledge_ids(&home, "gc").is_empty());
        assert!(
            knowledge_ids(&home, "kid").is_empty(),
            "nothing goes to the parent terminated with it"
        );
        assert_eq!(knowledge_ids(&home, "root"), ["g1", "k1", "g-late"]);
        let tags = |id: &str| home.knowledge.get("root", id).expect("held").tags;
        assert_eq!(tags("g1"), ["from-agent:gc"]);
        assert_eq!(tags("k1"), ["from-agent:kid"]);
        assert_eq!(tags("g-late"), ["from-agent:gc"]);
    }

    /// A loop in the middle of a step when its child is terminated may write a knowledge
    /// entry after the first pass: the second pass, once the loop has ended, hands it over
    /// too — nothing is left under the child's id for an agent served there later.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_knowledge_entry_written_late_is_handed_over_by_the_second_pass() {
        let home = managed();
        home.knowledge
            .insert("kid", knowledge_of("kid", "k1", "what the child learned"))
            .expect("insert");
        let (looping, finish) = remembering_in_a_step(&home.knowledge, "kid", "late");
        route(&home.manager, "kid", "agent:kid");
        retain_running(&home.manager, "kid", "agent:kid", looping);
        mark_terminated(&home, "kid");

        home.manager.abort_child("kid");
        assert_eq!(knowledge_ids(&home, "root"), ["k1"], "the first pass");
        let pass = pending_pass(&home.manager, "agent:kid");
        finish.send(()).expect("the loop is still in its step");
        within(closed(pass)).await;
        assert!(knowledge_ids(&home, "kid").is_empty(), "nothing is left");
        assert_eq!(knowledge_ids(&home, "root"), ["k1", "late"]);
    }

    /// Add the grandchild `gc` below `kid` to the tree of `home`.
    fn add_grandchild(home: &Managed) {
        let workspace = home._ws.path().join("root").join("kid").join("gc");
        std::fs::create_dir_all(&workspace).expect("territory");
        home.manager
            .tree
            .insert_child(
                &AgentId("kid".to_string()),
                AgentNode {
                    id: AgentId("gc".to_string()),
                    kind: AgentKind::Child,
                    parent: Some(AgentId("kid".to_string())),
                    workspace_path: workspace,
                    capabilities: Vec::new(),
                    template_ref: None,
                    status: AgentStatus::Active,
                },
            )
            .expect("grandchild node");
    }

    /// The heir is found again at each hand-over: a grandchild terminated alone hands its
    /// entries to its parent; once that parent has been terminated and torn down too — with
    /// no loop, so with no second pass of its own —, the entry the grandchild's loop wrote
    /// late goes to the root, not to the parent's id, which no agent holds any more.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_late_entry_goes_past_an_heir_torn_down_since_the_first_pass() {
        let home = managed();
        add_grandchild(&home);
        home.knowledge
            .insert(
                "gc",
                knowledge_of("gc", "g1", "what the grandchild learned"),
            )
            .expect("insert");
        home.knowledge
            .insert("kid", knowledge_of("kid", "k1", "what the child learned"))
            .expect("insert");
        let (looping, finish) = remembering_in_a_step(&home.knowledge, "gc", "g-late");
        route(&home.manager, "gc", "agent:gc");
        retain_running(&home.manager, "gc", "agent:gc", looping);

        mark_terminated(&home, "gc");
        home.manager.abort_child("gc");
        let pass = pending_pass(&home.manager, "agent:gc");
        home.manager
            .tree
            .remove(&AgentId("gc".to_string()))
            .expect("a leaf");
        assert_eq!(knowledge_ids(&home, "kid"), ["k1", "g1"], "its parent's");

        mark_terminated(&home, "kid");
        home.manager.abort_child("kid");
        home.manager
            .tree
            .remove(&AgentId("kid".to_string()))
            .expect("a leaf");
        assert_eq!(knowledge_ids(&home, "root"), ["k1", "g1"]);

        finish.send(()).expect("the loop is still in its step");
        within(closed(pass)).await;
        assert!(knowledge_ids(&home, "gc").is_empty());
        assert!(
            knowledge_ids(&home, "kid").is_empty(),
            "nothing goes to an agent torn down"
        );
        assert_eq!(knowledge_ids(&home, "root"), ["k1", "g1", "g-late"]);
    }

    /// An heir marked terminated since the first pass — its terminate stopped part-way and
    /// left it in the tree for a retry — is passed over: the entry written late goes to the
    /// next ancestor alive, and the heir keeps its own entries until its own teardown.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_late_entry_passes_over_an_heir_marked_terminated_since_the_first_pass() {
        let home = managed();
        add_grandchild(&home);
        home.knowledge
            .insert("kid", knowledge_of("kid", "k1", "what the child learned"))
            .expect("insert");
        let (looping, finish) = remembering_in_a_step(&home.knowledge, "gc", "g-late");
        route(&home.manager, "gc", "agent:gc");
        retain_running(&home.manager, "gc", "agent:gc", looping);
        mark_terminated(&home, "gc");
        home.manager.abort_child("gc");
        let pass = pending_pass(&home.manager, "agent:gc");
        home.manager
            .tree
            .remove(&AgentId("gc".to_string()))
            .expect("a leaf");

        mark_terminated(&home, "kid");
        finish.send(()).expect("the loop is still in its step");
        within(closed(pass)).await;
        assert_eq!(knowledge_ids(&home, "root"), ["g-late"]);
        assert_eq!(
            knowledge_ids(&home, "kid"),
            ["k1"],
            "the heir passed over keeps its own"
        );

        home.manager.abort_child("kid");
        assert_eq!(knowledge_ids(&home, "root"), ["g-late", "k1"]);
    }

    /// An heir marked terminated between a hand-over to it and the check after — its own
    /// terminate may have handed its entries on already — has the entries just handed to it
    /// handed on, to the next ancestor alive, and only those: its own wait for its own
    /// teardown.
    #[test]
    fn an_heir_terminated_during_a_hand_over_hands_on_only_the_entries_just_handed_to_it() {
        let knowledge = cap_memory::MemoryStore::new();
        knowledge
            .insert("kid", knowledge_of("kid", "k1", "the heir's own"))
            .expect("insert");
        knowledge
            .insert("gc", knowledge_of("gc", "g1", "the grandchild's"))
            .expect("insert");
        let checks = std::sync::Mutex::new(Vec::<String>::new());
        let alive = |id: &str| {
            let mut checks = checks.lock().unwrap();
            checks.push(id.to_string());
            // Alive when it is chosen; marked terminated by the time it is checked again.
            !(id == "kid" && checks.iter().filter(|seen| *seen == "kid").count() > 1)
        };
        let ancestors = ["kid".to_string(), "root".to_string()];
        let outcome = hand_over_along(&knowledge, "gc", &ancestors, alive);
        assert!(
            matches!(
                &outcome,
                Ok(HandOverOutcome::WithHeir { heir, moved }) if heir == "root" && moved.ids == ["g1"]
            ),
            "{outcome:?}"
        );
        assert!(knowledge.list("gc").is_empty());
        assert_eq!(
            ids_of(&knowledge, "kid"),
            ["k1"],
            "its own wait for its own teardown"
        );
        assert_eq!(ids_of(&knowledge, "root"), ["g1"]);
        assert_eq!(*checks.lock().unwrap(), ["kid", "kid", "root", "root"]);
    }

    fn ids_of(knowledge: &cap_memory::MemoryStore, agent: &str) -> Vec<String> {
        knowledge
            .list(agent)
            .into_iter()
            .map(|entry| entry.id)
            .collect()
    }

    /// With no ancestor on record, or none alive, nothing moves; the entries handed to an
    /// heir marked once it held them wait under it when no ancestor above it is alive; and
    /// an agent that holds none hands nothing over.
    #[test]
    fn a_hand_over_without_an_heir_alive_leaves_the_entries_where_they_are() {
        let knowledge = cap_memory::MemoryStore::new();
        knowledge
            .insert("gc", knowledge_of("gc", "g1", "the grandchild's"))
            .expect("insert");
        let ancestors = ["kid".to_string(), "root".to_string()];
        assert!(matches!(
            hand_over_along(&knowledge, "gc", &[], |_| true),
            Err(HandOverFailure::Unknown)
        ));
        assert!(matches!(
            hand_over_along(&knowledge, "gc", &ancestors, |_| false),
            Err(HandOverFailure::NoAncestorAlive)
        ));
        assert_eq!(ids_of(&knowledge, "gc"), ["g1"]);

        // kid is alive when chosen and marked by the time it is checked again; the root is
        // never alive here.
        let checked = std::sync::Mutex::new(0);
        let alive = |id: &str| {
            id == "kid" && {
                let mut checked = checked.lock().unwrap();
                *checked += 1;
                *checked == 1
            }
        };
        let outcome = hand_over_along(&knowledge, "gc", &ancestors, alive);
        assert!(
            matches!(
                &outcome,
                Ok(HandOverOutcome::WithMarkedHeir { heir, moved }) if heir == "kid" && moved.ids == ["g1"]
            ),
            "{outcome:?}"
        );
        assert_eq!(ids_of(&knowledge, "kid"), ["g1"]);
        assert!(matches!(
            hand_over_along(&knowledge, "gc", &ancestors, |_| true),
            Ok(HandOverOutcome::Nothing)
        ));
    }

    /// Records the stream and key of each line it is given.
    #[derive(Default)]
    struct Streams(Mutex<Vec<(crate::api::LogStream, &'static str)>>);

    impl crate::api::ComposeLog for Streams {
        fn line(&self, line: &crate::api::ComposeLogLine) {
            self.0.lock().unwrap().push((line.stream, line.key));
        }

        fn ready(&self, line: &crate::api::ComposeLogLine) -> std::io::Result<()> {
            self.line(line);
            Ok(())
        }
    }

    /// Each outcome of a hand-over is logged where it belongs: one that reached an heir on
    /// stdout; entries left waiting under an heir marked meanwhile, or under the agent's id
    /// with no ancestor alive, and a store that failed, on stderr; nothing when the agent held
    /// none — with no ancestor alive either — or the tree no longer knew it.
    #[tokio::test]
    async fn each_hand_over_outcome_is_logged_where_it_belongs() {
        use crate::api::LogStream::{Stderr, Stdout};
        let home = managed();
        let streams = Arc::new(Streams::default());
        let records = AgentRecords {
            bare_id: "kid".to_string(),
            colon_ids: vec![],
            ancestors: vec!["root".to_string()],
            tree: home.manager.tree.clone(),
            stores: RecordStores {
                chats: home.chats.clone(),
                memory_index: None,
                context_store: home.reports.clone(),
                knowledge: Some(home.knowledge.clone()),
            },
            log: LogHandle::new(streams.clone()),
        };
        let moved = cap_memory::HandedOver {
            ids: vec!["k1".to_string()],
            gained: 1,
            active: 1,
        };
        let logged = |outcome| {
            streams.0.lock().unwrap().clear();
            records.report_hand_over(&home.knowledge, outcome);
            streams.0.lock().unwrap().clone()
        };
        assert!(logged(Ok(HandOverOutcome::Nothing)).is_empty());
        assert!(logged(Err(HandOverFailure::Unknown)).is_empty());
        assert!(
            logged(Err(HandOverFailure::NoAncestorAlive)).is_empty(),
            "the agent holds none"
        );
        assert_eq!(
            logged(Ok(HandOverOutcome::WithHeir {
                heir: "root".to_string(),
                moved: moved.clone(),
            })),
            [(Stdout, log_keys::PERCHILD_HANDOVER)]
        );
        assert_eq!(
            logged(Ok(HandOverOutcome::WithMarkedHeir {
                heir: "mid".to_string(),
                moved,
            })),
            [(Stderr, log_keys::PERCHILD_HANDOVER_FAILED)]
        );
        assert_eq!(
            logged(Err(HandOverFailure::Store {
                from: "kid".to_string(),
                to: "root".to_string(),
                error: advance_shared_types::memory::PostProcessorError::LimitExceeded,
            })),
            [(Stderr, log_keys::PERCHILD_HANDOVER_FAILED)]
        );
        home.knowledge
            .insert("kid", knowledge_of("kid", "k1", "what the child learned"))
            .expect("insert");
        assert_eq!(
            logged(Err(HandOverFailure::NoAncestorAlive)),
            [(Stderr, log_keys::PERCHILD_HANDOVER_FAILED)]
        );
    }

    /// A shutdown that comes while a terminate's scope is held — between its stop of a node
    /// and the node's teardown — waits for the scope: the node is forgotten, and its
    /// knowledge handed over, while the stores are still bound; only then does the shutdown
    /// let go of them.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_shutdown_waits_for_a_terminate_between_its_stops_and_its_teardowns() {
        let home = managed();
        home.knowledge
            .insert("kid", knowledge_of("kid", "k1", "what the child learned"))
            .expect("insert");
        let looping = tokio::spawn(std::future::pending::<()>());
        route(&home.manager, "kid", "agent:kid");
        retain_running(&home.manager, "kid", "agent:kid", looping);
        mark_terminated(&home, "kid");
        let scope = home.manager.terminate_scope();
        home.manager.stop_child("kid");

        let shutdown = home.manager.shutdown();
        let mut shutdown = std::pin::pin!(shutdown);
        waits_for_a_terminate(&home.manager, shutdown.as_mut()).await;
        home.manager.abort_child("kid");
        drop(scope);
        within(shutdown).await;
        assert!(knowledge_ids(&home, "kid").is_empty());
        assert_eq!(
            knowledge_ids(&home, "root"),
            ["k1"],
            "handed over while the stores were bound"
        );
    }

    /// A child the tree no longer knows when it is torn down — the terminate that removed it
    /// hands its knowledge over — hands nothing over and raises no alarm: what is under its
    /// id stays.
    #[tokio::test]
    async fn a_child_the_tree_no_longer_knows_keeps_its_knowledge_and_logs_nothing() {
        let lines = Arc::new(Lines::default());
        let mut home = managed();
        home.manager = home.manager.with_log(LogHandle::new(lines.clone()));
        home.knowledge
            .insert("ghost", knowledge_of("ghost", "x1", "an orphan's"))
            .expect("insert");
        home.manager.abort_child("ghost");
        assert_eq!(knowledge_ids(&home, "ghost"), ["x1"]);
        assert!(knowledge_ids(&home, "root").is_empty());
        assert!(lines.keys().is_empty(), "{:?}", lines.keys());
    }

    /// A grant revoke that holds the terminate it is a step of until the test lets it go.
    struct HeldRevoke {
        entered: Mutex<Option<mpsc::Sender<()>>>,
        release: Mutex<mpsc::Receiver<()>>,
    }

    impl cap_lifecycle::GrantCascadeRevoke for HeldRevoke {
        fn revoke_for_agent(&self, _agent_id: &str) -> Result<(), cap_lifecycle::LifecycleError> {
            if let Some(entered) = self.entered.lock().unwrap().take() {
                let _ = entered.send(());
            }
            let _ = self.release.lock().unwrap().recv();
            Ok(())
        }
    }

    /// The other cascade steps, which do nothing.
    struct NoSteps;

    impl cap_lifecycle::MailboxCascade for NoSteps {
        fn flush_mailbox(&self, _agent_id: &str) -> Result<(), cap_lifecycle::LifecycleError> {
            Ok(())
        }

        fn notify_parent_crash(
            &self,
            _parent_id: &str,
            _child_id: &str,
            _reason: &str,
        ) -> Result<(), cap_lifecycle::LifecycleError> {
            Ok(())
        }
    }

    impl cap_lifecycle::RunCascade for NoSteps {
        fn ensure_run(&self, _agent_id: &str) -> Result<(), cap_lifecycle::LifecycleError> {
            Ok(())
        }

        fn cancel_run(&self, _agent_id: &str) -> Result<(), cap_lifecycle::LifecycleError> {
            Ok(())
        }
    }

    impl cap_lifecycle::WorkspaceCleanup for NoSteps {
        fn remove_sub_workspace(
            &self,
            _workspace_path: &std::path::Path,
        ) -> Result<(), cap_lifecycle::LifecycleError> {
            Ok(())
        }
    }

    /// The production terminate — `DefaultTerminateController` with this module's
    /// [`PerChildLoopCascade`] — holds its scope while a step of it blocks: a shutdown that
    /// comes then waits for it, and the child's knowledge is handed over while the stores
    /// are bound.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_shutdown_waits_for_a_production_terminate_held_up_in_a_step() {
        use cap_lifecycle::TerminateController;
        let Managed {
            _ws,
            manager,
            knowledge,
            ..
        } = managed();
        let manager = Arc::new(manager);
        knowledge
            .insert("kid", knowledge_of("kid", "k1", "what the child learned"))
            .expect("insert");
        route(&manager, "kid", "agent:kid");
        retain_running(
            &manager,
            "kid",
            "agent:kid",
            tokio::spawn(std::future::pending::<()>()),
        );
        let (entered, held) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let steps = Arc::new(NoSteps);
        let controller = cap_lifecycle::DefaultTerminateController::new(
            manager.tree.clone(),
            Arc::new(HeldRevoke {
                entered: Mutex::new(Some(entered)),
                release: Mutex::new(released),
            }),
            steps.clone(),
            steps.clone(),
            steps,
        )
        .with_loop_cascade(Arc::new(PerChildLoopCascade::new(manager.clone())));
        let terminate = std::thread::spawn(move || controller.terminate_child("root", "kid"));
        held.recv_timeout(std::time::Duration::from_secs(10))
            .expect("the terminate reaches its grant revoke");

        let shutdown = manager.shutdown();
        let mut shutdown = std::pin::pin!(shutdown);
        waits_for_a_terminate(&manager, shutdown.as_mut()).await;
        release.send(()).expect("the revoke waits");
        joined(terminate).expect("the terminate succeeds");
        within(shutdown).await;
        assert!(knowledge.list("kid").is_empty());
        assert_eq!(
            ids_of(&knowledge, "root"),
            ["k1"],
            "handed over while the stores were bound"
        );
    }

    /// Add the child `bare` of `root` to the tree of `home`.
    fn add_child(home: &Managed, bare: &str) {
        let root = AgentId("root".to_string());
        let workspace = home._ws.path().join("root").join(bare);
        std::fs::create_dir_all(&workspace).expect("territory");
        home.manager
            .tree
            .insert_child(
                &root,
                AgentNode {
                    id: AgentId(bare.to_string()),
                    kind: AgentKind::Child,
                    parent: Some(root.clone()),
                    workspace_path: workspace,
                    capabilities: Vec::new(),
                    template_ref: None,
                    status: AgentStatus::Active,
                },
            )
            .expect("child node");
    }

    /// Records the lines it is given, by key.
    #[derive(Default)]
    struct Lines(Mutex<Vec<(&'static str, String)>>);

    impl Lines {
        fn keys(&self) -> Vec<&'static str> {
            self.0.lock().unwrap().iter().map(|(key, _)| *key).collect()
        }
    }

    impl crate::api::ComposeLog for Lines {
        fn line(&self, line: &crate::api::ComposeLogLine) {
            self.0.lock().unwrap().push((line.key, line.text.clone()));
        }

        fn ready(&self, line: &crate::api::ComposeLogLine) -> std::io::Result<()> {
            self.line(line);
            Ok(())
        }
    }

    /// Holds the first line logged under its key — and with it the call that logs it —
    /// until the test lets it go.
    struct HeldLine {
        key: &'static str,
        entered: Mutex<Option<mpsc::Sender<()>>>,
        release: Mutex<mpsc::Receiver<()>>,
    }

    impl HeldLine {
        /// Returns the sink, the receiver told when the line is held, and the sender that
        /// lets it go on.
        fn on(key: &'static str) -> (Arc<Self>, mpsc::Receiver<()>, mpsc::Sender<()>) {
            let (entered, held) = mpsc::channel();
            let (release, released) = mpsc::channel();
            let sink = Arc::new(Self {
                key,
                entered: Mutex::new(Some(entered)),
                release: Mutex::new(released),
            });
            (sink, held, release)
        }
    }

    impl crate::api::ComposeLog for HeldLine {
        fn line(&self, line: &crate::api::ComposeLogLine) {
            if line.key != self.key {
                return;
            }
            let entered = self.entered.lock().unwrap().take();
            if let Some(entered) = entered {
                entered.send(()).expect("the test waits for the line");
                self.release
                    .lock()
                    .unwrap()
                    .recv_timeout(WAIT)
                    .expect("the test lets the line go on");
            }
        }

        fn ready(&self, line: &crate::api::ComposeLogLine) -> std::io::Result<()> {
            self.line(line);
            Ok(())
        }
    }

    /// Records the ids it is told to forget, like [`Chats`], and can hold the next call
    /// until the test lets it go.
    #[derive(Default)]
    struct HeldChats {
        forgotten: Mutex<Vec<String>>,
        hold: Mutex<Option<(mpsc::Sender<()>, mpsc::Receiver<()>)>>,
    }

    impl HeldChats {
        /// Hold the next call. Returns the receiver told when it is held, and the sender
        /// that lets it go on.
        fn hold_next(&self) -> (mpsc::Receiver<()>, mpsc::Sender<()>) {
            let (entered, held) = mpsc::channel();
            let (let_go, release) = mpsc::channel();
            *self.hold.lock().unwrap() = Some((entered, release));
            (held, let_go)
        }

        fn forgotten(&self) -> Vec<String> {
            self.forgotten.lock().unwrap().clone()
        }
    }

    impl ChatRecord for HeldChats {
        fn forget_agent(&self, agent_id: &str) {
            self.forgotten.lock().unwrap().push(agent_id.to_string());
            let hold = self.hold.lock().unwrap().take();
            if let Some((entered, release)) = hold {
                entered.send(()).expect("the test waits for the call");
                release
                    .recv_timeout(WAIT)
                    .expect("the test lets the call go on");
            }
        }
    }

    /// Terminating a child forgets its rows of the shared index, where it chats and
    /// its assembly report — the one under its colon id, as its loop records it — and
    /// nothing of any other agent.
    #[tokio::test]
    async fn a_terminated_child_is_forgotten_and_no_other_agent_is() {
        let home = managed();
        for agent in ["root", "kid", "other"] {
            home.index.upsert_turn(turn_of(agent, 1));
            home.reports.register_aliases(&aliases(agent));
            home.reports.record(crate::context_inspect::test_report(
                &format!("agent:{agent}"),
                100,
            ));
        }

        home.manager.abort_child("kid");

        assert_eq!(turns_of(&home.index, "kid"), 0);
        assert_eq!(turns_of(&home.index, "root"), 1);
        assert_eq!(turns_of(&home.index, "other"), 1);
        assert_eq!(home.chats.forgotten(), ["kid"]);
        assert!(!home.reports.knows("kid") && !home.reports.knows("agent:kid"));
        assert!(home.reports.snapshot("agent:kid").is_none(), "its report");
        assert!(home.reports.knows("root") && home.reports.knows("other"));
        assert!(home.reports.snapshot("agent:other").is_some());
        // It had no serve loop: nothing is left to wait for.
        assert!(lock(&home.manager.sweeps).is_empty());
    }

    /// The root is never forgotten: not by its own id, and not by a child id that
    /// maps onto the root's mailbox — nor is anything else forgotten for such an id.
    #[tokio::test]
    async fn an_id_that_maps_onto_the_root_forgets_nothing() {
        let home = managed();
        for agent in ["root", "default"] {
            home.index.upsert_turn(turn_of(agent, 1));
        }
        home.reports.register_aliases(&aliases("root"));

        home.manager.abort_child("default");
        home.manager.abort_child("root");

        assert_eq!(turns_of(&home.index, "root"), 1);
        assert_eq!(turns_of(&home.index, "default"), 1);
        assert!(home.chats.forgotten().is_empty());
        assert!(home.reports.knows("root"));
    }

    /// Once the stores are released (a shutdown), a terminate forgets nothing.
    #[tokio::test]
    async fn nothing_is_forgotten_once_the_stores_are_released() {
        let home = managed();
        home.index.upsert_turn(turn_of("kid", 1));
        home.manager.unbind();
        home.manager.abort_child("kid");
        assert_eq!(turns_of(&home.index, "kid"), 1);
        assert!(home.chats.forgotten().is_empty());
    }

    /// A terminate that comes after a shutdown let go of the stores says it forgot
    /// nothing.
    #[tokio::test]
    async fn a_terminate_after_a_shutdown_is_reported() {
        let lines = Arc::new(Lines::default());
        let mut home = managed();
        home.manager = home.manager.with_log(LogHandle::new(lines.clone()));
        home.index.upsert_turn(turn_of("kid", 1));
        within(home.manager.shutdown()).await;
        assert!(lines.keys().is_empty());

        home.manager.abort_child("kid");
        assert_eq!(turns_of(&home.index, "kid"), 1);
        assert!(home.chats.forgotten().is_empty());
        assert_eq!(lines.keys(), [log_keys::PERCHILD_FORGET_FAILED]);
        assert!(lines.0.lock().unwrap()[0]
            .1
            .contains("terminated child kid"));
    }

    /// An aborted loop that is in the middle of a step still writes what the step
    /// writes. That row is forgotten too, once the loop has ended — and until then a
    /// pass is pending under the child's id, which a loop served under the same id
    /// waits for.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn what_an_aborted_loop_writes_late_is_forgotten_when_it_has_ended() {
        let home = managed();
        home.index.upsert_turn(turn_of("kid", 1));
        let (looping, finish, written) = loop_in_a_step(&home.index, "kid");
        retain_running(&home.manager, "kid", "agent:kid", looping);

        home.manager.abort_child("kid");
        assert_eq!(turns_of(&home.index, "kid"), 0, "forgotten at once");
        let pass = pending_pass(&home.manager, "agent:kid");
        assert!(pass.has_changed().is_ok(), "the loop has not ended yet");
        // The step assembled once more, too: a report under the colon id it serves.
        home.reports
            .record(crate::context_inspect::test_report("agent:kid", 200));

        finish.send(()).expect("the loop is still in its step");
        within(closed(pass)).await;
        assert!(written.load(Ordering::SeqCst), "the step wrote its row");
        assert_eq!(turns_of(&home.index, "kid"), 0, "and the row is forgotten");
        assert!(
            home.reports.snapshot("agent:kid").is_none(),
            "and its report"
        );
        assert_eq!(home.chats.forgotten(), ["kid", "kid"]);
    }

    /// With no stores bound (no context deps) nothing is forgotten, but the pass of a
    /// terminated child still stays pending until its aborted loop has ended: a shutdown and
    /// a child served later under its ids wait for that loop all the same.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn without_stores_the_pass_still_waits_for_the_aborted_loop() {
        let home = managed();
        *lock(&home.manager.record_stores) = None;
        let (looping, finish, _written) = loop_in_a_step(&home.index, "kid");
        retain_running(&home.manager, "kid", "agent:kid", looping);

        home.manager.abort_child("kid");
        let pass = pending_pass(&home.manager, "agent:kid");
        assert!(pass.has_changed().is_ok(), "the loop has not ended yet");

        finish.send(()).expect("the loop is still in its step");
        within(closed(pass)).await;
        assert!(home.chats.forgotten().is_empty(), "nothing to forget it in");
    }

    /// Two children terminated one after the other under the same id: the second
    /// pass runs only after the first, however early the second loop ended.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn passes_under_one_id_run_in_the_order_of_the_terminations() {
        let home = managed();
        let (first, finish, written) = loop_in_a_step(&home.index, "kid");
        retain_running(&home.manager, "kid", "agent:kid", first);
        home.manager.abort_child("kid");

        // A loop served under the same id since, terminated while the first one is
        // still in its step. It ends at once.
        let second = tokio::spawn(std::future::pending::<()>());
        retain_running(&home.manager, "kid", "agent:kid", second);
        home.manager.abort_child("kid");
        let pass = pending_pass(&home.manager, "agent:kid");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(
            pass.has_changed().is_ok(),
            "the second pass waits for the first, which waits for the first loop"
        );

        finish
            .send(())
            .expect("the first loop is still in its step");
        within(closed(pass)).await;
        assert!(written.load(Ordering::SeqCst));
        assert_eq!(turns_of(&home.index, "kid"), 0);
        // At each terminate, and once more after each loop's end.
        assert_eq!(home.chats.forgotten(), ["kid"; 4]);
    }

    /// A shutdown waits for the passes still pending, and leaves none behind holding
    /// the stores.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_shutdown_waits_for_the_pending_passes() {
        let home = managed();
        let (looping, finish, written) = loop_in_a_step(&home.index, "kid");
        retain_running(&home.manager, "kid", "agent:kid", looping);
        home.manager.abort_child("kid");

        let letting_go = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(100));
            finish.send(()).expect("the loop is still in its step");
        });
        within(home.manager.shutdown()).await;
        joined(letting_go);

        assert!(written.load(Ordering::SeqCst));
        assert_eq!(turns_of(&home.index, "kid"), 0, "the late row is forgotten");
        assert!(lock(&home.manager.sweeps).is_empty());
        assert!(lock(&home.manager.record_stores).is_none());
        // Nothing but the test holds the stores any more.
        assert_eq!(Arc::strong_count(&home.index), 1);
        assert_eq!(Arc::strong_count(&home.chats), 1);
    }

    /// A child renamed while it is served is still served under the colon id it was
    /// served as — its loop, its route, its mailbox, its alias group and its reports are
    /// keyed by that one — and its terminate tears down what is under that id, not under
    /// the new handle's alone.
    #[tokio::test]
    async fn a_renamed_child_is_terminated_under_the_id_it_was_served_as() {
        let handles = Arc::new(Mutex::new(HashMap::new()));
        let home = managed_with_handles(handles.clone());
        home.index.upsert_turn(turn_of("kid", 1));
        home.reports.register_aliases(&aliases("kid"));
        home.reports
            .record(crate::context_inspect::test_report("agent:kid", 100));
        route(&home.manager, "kid", "agent:kid");
        assert!(serve(
            &home.manager,
            "kid",
            "agent:kid",
            std::future::pending::<()>()
        ));

        handles
            .lock()
            .unwrap()
            .insert("kid".to_string(), "helper".to_string());
        home.manager.abort_child("kid");

        assert_eq!(
            served_under(&home.manager, "agent:kid"),
            None,
            "the loop it was served by is aborted"
        );
        assert_unrouted(&home.manager, "kid", "agent:kid");
        assert!(!home.reports.knows("kid") && !home.reports.knows("agent:kid"));
        assert!(home.reports.snapshot("agent:kid").is_none(), "its report");
        assert_eq!(turns_of(&home.index, "kid"), 0);
        // Its loop's pass is pending under the id it was served as.
        within(closed(pending_pass(&home.manager, "agent:kid"))).await;
    }

    /// The child `kid` served under `agent:kid`, its loop ended on its own (its finished
    /// handle stays in the registry), then renamed: its colon id is `agent:helper` now,
    /// and its old one free for another child. Its rows and its alias group are recorded,
    /// and so are a row of `newcomer`, the child that takes the old colon id.
    async fn served_ended_and_renamed() -> (Managed, Arc<Mutex<HashMap<String, String>>>) {
        let handles = Arc::new(Mutex::new(HashMap::new()));
        let home = managed_with_handles(handles.clone());
        add_child(&home, "newcomer");
        for agent in ["kid", "newcomer"] {
            home.index.upsert_turn(turn_of(agent, 1));
        }
        home.reports.register_aliases(&aliases("kid"));
        assert!(serve(&home.manager, "kid", "agent:kid", async {}));
        loops_ended(&home.manager).await;
        assert_eq!(
            served_under(&home.manager, "agent:kid").as_deref(),
            Some("kid")
        );
        handles
            .lock()
            .unwrap()
            .insert("kid".to_string(), "helper".to_string());
        (home, handles)
    }

    /// The newcomer holds `agent:kid`: its route, its id pair, the message waiting in
    /// its mailbox, its row, its alias group and its report.
    fn assert_newcomer_holds_the_id(home: &Managed) {
        let manager = &home.manager;
        assert_eq!(
            manager.routing.agent_kind("agent:kid"),
            Some(AgentKind::Child)
        );
        let pair = Some(("newcomer".to_string(), "agent:kid".to_string()));
        assert_eq!(manager.bridge.resolve_owned("agent:kid"), pair);
        assert_eq!(manager.bridge.resolve_owned("newcomer"), pair);
        assert_eq!(
            manager
                .store
                .get("agent:kid")
                .map(|mailbox| mailbox.depth()),
            Some(1),
            "its message is still waiting"
        );
        assert_eq!(turns_of(&home.index, "newcomer"), 1);
        let report = home.reports.snapshot("newcomer").expect("its report");
        assert_eq!(report.report.used_tokens, 700);
    }

    /// Another child took the old handle of a child whose loop had ended on its own — and
    /// with it the colon id — and is served under it. The first child's terminate finds
    /// no loop of its own there, and leaves alone all the newcomer holds under the id.
    #[tokio::test]
    async fn a_terminate_leaves_alone_a_loop_another_child_serves_under_its_old_colon_id() {
        let (home, _handles) = served_ended_and_renamed().await;
        route(&home.manager, "newcomer", "agent:kid");
        assert!(serve(
            &home.manager,
            "newcomer",
            "agent:kid",
            std::future::pending::<()>()
        ));
        home.reports
            .register_aliases(&["newcomer".to_string(), "agent:kid".to_string()]);
        home.reports
            .record(crate::context_inspect::test_report("agent:kid", 700));

        home.manager.abort_child("kid");
        assert_newcomer_holds_the_id(&home);
        assert_eq!(
            served_under(&home.manager, "agent:kid").as_deref(),
            Some("newcomer")
        );
        assert_eq!(home.manager.active_loop_count(), 1);
        assert_eq!(turns_of(&home.index, "kid"), 0);
        assert!(!home.reports.knows("kid"), "its own alias group goes");
    }

    /// As [`a_terminate_leaves_alone_a_loop_another_child_serves_under_its_old_colon_id`],
    /// but the first child's terminate still finds its own ended loop under the colon id:
    /// the newcomer's serve registered the id after the terminate took that loop out of the
    /// registry, and before its teardown (outside the registry's lock) reached the id. The
    /// teardown finds the id paired with the newcomer and leaves alone all the newcomer
    /// holds under it; the newcomer's loop is retained after it.
    #[tokio::test]
    async fn a_terminate_leaves_alone_what_another_child_registered_under_its_old_colon_id() {
        let (home, _handles) = served_ended_and_renamed().await;
        route(&home.manager, "newcomer", "agent:kid");
        home.reports
            .register_aliases(&["newcomer".to_string(), "agent:kid".to_string()]);
        home.reports
            .record(crate::context_inspect::test_report("agent:kid", 700));

        home.manager.abort_child("kid");
        assert_newcomer_holds_the_id(&home);
        assert_eq!(served_under(&home.manager, "agent:kid"), None);
        assert_eq!(turns_of(&home.index, "kid"), 0);
        assert!(!home.reports.knows("kid"));
        // The pass of its ended loop forgets nothing under the newcomer's colon id.
        within(closed(pending_pass(&home.manager, "agent:helper"))).await;
        assert_newcomer_holds_the_id(&home);

        assert!(serve(
            &home.manager,
            "newcomer",
            "agent:kid",
            std::future::pending::<()>()
        ));
        assert_eq!(home.manager.active_loop_count(), 1);
    }

    /// A child renamed to the handle another child gave up after its loop ended on its
    /// own resolves to that child's colon id, where that child's ended loop is still
    /// retained: its terminate leaves alone what that child left under the id — its
    /// report, its alias group, its loop.
    #[tokio::test]
    async fn a_terminate_leaves_alone_what_another_child_left_under_the_id_it_resolves_to() {
        let handles = Arc::new(Mutex::new(HashMap::new()));
        let home = managed_with_handles(handles.clone());
        add_child(&home, "other");
        assert!(serve(&home.manager, "other", "agent:helper", async {}));
        loops_ended(&home.manager).await;
        home.reports
            .register_aliases(&["other".to_string(), "agent:helper".to_string()]);
        home.reports
            .record(crate::context_inspect::test_report("agent:helper", 700));
        {
            let mut handles = handles.lock().unwrap();
            handles.insert("other".to_string(), "other-renamed".to_string());
            handles.insert("kid".to_string(), "helper".to_string());
        }

        home.manager.abort_child("kid");
        let report = home.reports.snapshot("other").expect("its report");
        assert_eq!(report.report.used_tokens, 700);
        assert_eq!(
            served_under(&home.manager, "agent:helper").as_deref(),
            Some("other")
        );
    }

    /// What waits under a colon id a terminated child was served under is drained while
    /// no one routes the id — the child's loop ended on its own, and its serve undid its
    /// route — and left alone while someone else routes it with no id pair (a state built
    /// by hand: this manager never leaves one, its registrations and teardowns each one
    /// step under the registry's lock): that route stays, and so does the message under
    /// it.
    #[tokio::test]
    async fn a_terminate_drains_a_colon_id_only_while_no_one_routes_it() {
        for registering in [false, true] {
            let home = managed();
            assert!(serve(&home.manager, "kid", "agent:kid", async {}));
            loops_ended(&home.manager).await;
            if registering {
                assert!(home
                    .manager
                    .routing
                    .register_child("agent:kid", "agent:root"));
            }
            deliver(&home.manager, "newcomer", "agent:kid");

            home.manager.abort_child("kid");
            let depth = home
                .manager
                .store
                .get("agent:kid")
                .map(|mailbox| mailbox.depth());
            if registering {
                assert_eq!(
                    home.manager.routing.agent_kind("agent:kid"),
                    Some(AgentKind::Child),
                    "the other serve's route stays"
                );
                assert_eq!(depth, Some(1), "the message for its child stays");
            } else {
                assert_unrouted(&home.manager, "kid", "agent:kid");
            }
            assert_eq!(served_under(&home.manager, "agent:kid"), None);
        }
    }

    /// A child renamed while it was served, its loop in the middle of a step: its terminate
    /// reserves its pass before it tears anything down. So a child that takes the colon id
    /// the moment it is free — while the terminate is still in its first pass — is served
    /// only after that pass, as one under the same bare id would be, and the loop's late
    /// row is forgotten by then.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_child_that_takes_a_terminated_childs_colon_id_starts_after_its_pass() {
        let handles = Arc::new(Mutex::new(HashMap::new()));
        let home = managed_with_handles(handles.clone());
        let chats = Arc::new(HeldChats::default());
        *lock(&home.manager.record_stores) = Some(RecordStores {
            chats: chats.clone(),
            memory_index: Some(home.index.clone()),
            context_store: home.reports.clone(),
            knowledge: Some(home.knowledge.clone()),
        });
        add_child(&home, "newcomer");
        let (looping, finish, written) = loop_in_a_step(&home.index, "kid");
        route(&home.manager, "kid", "agent:kid");
        retain_running(&home.manager, "kid", "agent:kid", looping);
        handles
            .lock()
            .unwrap()
            .insert("kid".to_string(), "helper".to_string());
        let manager = Arc::new(home.manager);

        // The terminate is held in its first pass, its teardown done.
        let (held, let_go) = chats.hold_next();
        let terminating = std::thread::spawn({
            let manager = manager.clone();
            move || manager.abort_child("kid")
        });
        held.recv_timeout(WAIT)
            .expect("the terminate is in its first pass");
        let (looping, started) = marked_serve();
        assert!(serve_routed(&manager, "newcomer", "agent:kid", looping));
        deliver(&manager, "newcomer", "agent:kid");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(
            !started.load(Ordering::SeqCst),
            "the newcomer waits for the terminated child's pass"
        );

        let_go.send(()).expect("the terminate is held");
        joined(terminating);
        finish.send(()).expect("the loop is still in its step");
        within(async {
            while !started.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await;
        assert!(written.load(Ordering::SeqCst), "the loop wrote late");
        assert_eq!(turns_of(&home.index, "kid"), 0, "and it is forgotten");
        assert_eq!(
            served_under(&manager, "agent:kid").as_deref(),
            Some("newcomer")
        );
        let pair = Some(("newcomer".to_string(), "agent:kid".to_string()));
        assert_eq!(manager.bridge.resolve_owned("agent:kid"), pair);
        assert_eq!(
            manager
                .store
                .get("agent:kid")
                .map(|mailbox| mailbox.depth()),
            Some(1),
            "the newcomer's message is still waiting"
        );
    }

    /// A terminate stops every loop retained for its child, whatever colon id each was
    /// retained under — and waits for each in its pass.
    #[tokio::test]
    async fn a_terminate_stops_every_loop_of_its_child() {
        let home = managed();
        let (alive, stopped) = tokio::sync::oneshot::channel::<()>();
        retain_running(
            &home.manager,
            "kid",
            "agent:helper",
            tokio::spawn(async move {
                let _alive = alive;
                std::future::pending::<()>().await
            }),
        );
        retain_running(
            &home.manager,
            "kid",
            "agent:kid",
            tokio::spawn(std::future::pending::<()>()),
        );
        retain_running(
            &home.manager,
            "other",
            "agent:other",
            tokio::spawn(std::future::pending::<()>()),
        );

        home.manager.abort_child("kid");
        assert_eq!(served_under(&home.manager, "agent:helper"), None);
        assert_eq!(served_under(&home.manager, "agent:kid"), None);
        assert_eq!(
            served_under(&home.manager, "agent:other").as_deref(),
            Some("other")
        );
        within(stopped)
            .await
            .expect_err("stopped, and told nothing");
        within(closed(pending_pass(&home.manager, "agent:helper"))).await;
        assert_eq!(home.manager.active_loop_count(), 1);
    }

    /// The colon id follows the handle, so an agent created later under a bare id a
    /// terminated child held can have another colon id — and one created under its
    /// handle another bare id. Either way it waits for the pass of the child that held
    /// the id, and a later pass runs only after that one: the pass forgets by bare id.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_pending_pass_is_waited_for_under_either_id() {
        let handles = Arc::new(Mutex::new(HashMap::new()));
        handles
            .lock()
            .unwrap()
            .insert("kid".to_string(), "helper".to_string());
        let home = managed_with_handles(handles.clone());
        let (first, finish, written) = loop_in_a_step(&home.index, "kid");
        retain_running(&home.manager, "kid", "agent:helper", first);
        home.manager.abort_child("kid");

        let waited_by =
            |bare: &str, colon: &str| home.manager.passes_before_serving(bare, colon).len();
        // The same bare id with no handle any more, and the same handle on a new bare id.
        assert_eq!(waited_by("kid", "agent:kid"), 1);
        assert_eq!(waited_by("newcomer", "agent:helper"), 1);
        // An agent that shares neither id waits for nothing.
        assert_eq!(waited_by("other", "agent:other"), 0);

        // A child served since under the same bare id and no handle, terminated while
        // the first loop is still in its step. Its loop ends at once; its pass does not
        // run before the first.
        handles.lock().unwrap().remove("kid");
        retain_running(
            &home.manager,
            "kid",
            "agent:kid",
            tokio::spawn(std::future::pending::<()>()),
        );
        home.manager.abort_child("kid");
        let second = pending_pass(&home.manager, "agent:kid");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(
            second.has_changed().is_ok(),
            "the second pass waits for the first, which waits for the first loop"
        );

        finish
            .send(())
            .expect("the first loop is still in its step");
        within(closed(second)).await;
        assert!(written.load(Ordering::SeqCst));
        assert_eq!(turns_of(&home.index, "kid"), 0);
    }

    /// A child terminated after a shutdown took the loop registry has no loop here to
    /// wait for: the shutdown awaits that loop itself, then forgets what it wrote late.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_child_terminated_during_a_shutdown_is_forgotten_after_its_loop_ended() {
        let home = managed();
        home.index.upsert_turn(turn_of("kid", 1));
        let (looping, finish, written) = loop_in_a_step(&home.index, "kid");
        retain_running(&home.manager, "kid", "agent:kid", looping);

        // The first steps of a shutdown: closed, and the registry taken.
        home.manager.closed.store(true, Ordering::SeqCst);
        let taken = std::mem::take(&mut lock(&home.manager.loops).retained);
        home.manager.abort_child("kid");
        assert_eq!(turns_of(&home.index, "kid"), 0, "forgotten at once");
        assert!(lock(&home.manager.sweeps).is_empty(), "no loop to wait for");

        // The loop finishes its step, then the shutdown aborts and awaits it.
        finish.send(()).expect("the loop is still in its step");
        for (_, retained) in taken {
            within(async {
                while !written.load(Ordering::SeqCst) {
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                }
            })
            .await;
            retained.handle.abort();
            let _ = within(retained.handle).await;
        }
        assert_eq!(
            turns_of(&home.index, "kid"),
            1,
            "the loop wrote one more row"
        );

        within(home.manager.shutdown()).await;
        assert_eq!(turns_of(&home.index, "kid"), 0, "the late row is forgotten");
        assert_eq!(home.chats.forgotten(), ["kid", "kid"]);
        assert!(lock(&home.manager.forget_at_shutdown).is_empty());
        assert_eq!(Arc::strong_count(&home.index), 1);
    }

    /// A terminate under way when a shutdown begins — it has taken its child's loop out
    /// of the registry, and has not yet left the pass that forgets what that loop writes
    /// late: the shutdown waits for it, and then for that pass, before it lets go of the
    /// stores.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_shutdown_waits_for_a_terminate_under_way() {
        let home = managed();
        let chats = Arc::new(HeldChats::default());
        *lock(&home.manager.record_stores) = Some(RecordStores {
            chats: chats.clone(),
            memory_index: Some(home.index.clone()),
            context_store: home.reports.clone(),
            knowledge: Some(home.knowledge.clone()),
        });
        home.index.upsert_turn(turn_of("kid", 1));
        let (looping, finish, written) = loop_in_a_step(&home.index, "kid");
        let manager = Arc::new(home.manager);
        retain_running(&manager, "kid", "agent:kid", looping);

        // The terminate is held in its first pass, the loop out of the registry already.
        let (held, let_go) = chats.hold_next();
        let terminating = std::thread::spawn({
            let manager = manager.clone();
            move || manager.abort_child("kid")
        });
        held.recv_timeout(WAIT)
            .expect("the terminate is in its first pass");
        assert!(lock(&manager.loops).retained.is_empty());

        let shutting_down = tokio::spawn({
            let manager = manager.clone();
            async move { manager.shutdown().await }
        });
        within(manager.terminates.waited_for.notified()).await;
        assert!(
            !shutting_down.is_finished(),
            "the shutdown waits for the terminate under way"
        );

        let_go.send(()).expect("the terminate is held");
        joined(terminating);
        // The loop finishes its step, writing one more row, and ends at its abort.
        finish.send(()).expect("the loop is still in its step");
        within(shutting_down).await.expect("the shutdown ends");

        assert!(written.load(Ordering::SeqCst), "the step wrote its row");
        assert_eq!(turns_of(&home.index, "kid"), 0, "the late row is forgotten");
        assert_eq!(chats.forgotten(), ["kid", "kid"]);
        assert!(lock(&manager.sweeps).is_empty());
        assert!(lock(&manager.record_stores).is_none());
        // Nothing but the test holds the stores any more.
        assert_eq!(Arc::strong_count(&home.index), 1);
        assert_eq!(Arc::strong_count(&chats), 1);
    }

    /// A terminate is under way from its start: one held before it has taken its child's
    /// loop out of the registry — while it resolves the child's colon id — is waited for by
    /// a shutdown that has taken the registry meanwhile and aborted that loop, which ends
    /// once its step is done. The terminate, let go, finds no loop: it forgets the child —
    /// the row the loop wrote in its step with the rest — and leaves the child to the
    /// shutdown, which forgets it once more.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_shutdown_waits_for_a_terminate_from_its_start() {
        let (entered, held) = mpsc::channel::<()>();
        let (let_go, release) = mpsc::channel::<()>();
        let hold = Mutex::new(Some((entered, release)));
        let home = managed_with(Arc::new(move |bare: &str| {
            if bare == "kid" {
                if let Some((entered, release)) = hold.lock().unwrap().take() {
                    entered.send(()).expect("the test waits for the terminate");
                    release
                        .recv_timeout(WAIT)
                        .expect("the test lets the terminate go on");
                }
            }
            format!("agent:{bare}")
        }));
        home.index.upsert_turn(turn_of("kid", 1));
        let (looping, finish, written) = loop_in_a_step(&home.index, "kid");
        retain_running(&home.manager, "kid", "agent:kid", looping);
        let manager = Arc::new(home.manager);
        let terminating = std::thread::spawn({
            let manager = manager.clone();
            move || manager.abort_child("kid")
        });
        held.recv_timeout(WAIT)
            .expect("the terminate is resolving the colon id");

        let shutting_down = tokio::spawn({
            let manager = manager.clone();
            async move { manager.shutdown().await }
        });
        // The shutdown takes the registry and aborts the loop, which ends once its step is
        // done.
        within(async {
            while !lock(&manager.loops).retained.is_empty() {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await;
        finish.send(()).expect("the loop is still in its step");
        within(async {
            while !written.load(Ordering::SeqCst) {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await;
        within(manager.terminates.waited_for.notified()).await;
        assert!(
            !shutting_down.is_finished(),
            "the shutdown waits for the terminate under way"
        );

        let_go.send(()).expect("the terminate is held");
        joined(terminating);
        within(shutting_down).await.expect("the shutdown ends");

        assert_eq!(
            turns_of(&home.index, "kid"),
            0,
            "the step's row is forgotten"
        );
        // At the terminate, and once more by the shutdown after the loop had ended.
        assert_eq!(home.chats.forgotten(), ["kid", "kid"]);
        assert!(lock(&manager.forget_at_shutdown).is_empty());
        assert!(lock(&manager.record_stores).is_none());
        assert_eq!(Arc::strong_count(&home.index), 1);
        assert_eq!(Arc::strong_count(&home.chats), 1);
    }

    /// A terminate that began after a shutdown stopped waiting for terminates, and is
    /// still forgetting its child while the shutdown lets go of the stores, leaves nothing
    /// holding them: it queued the child for the shutdown while the stores were held, and
    /// the release took the queue with them.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_terminate_across_the_release_leaves_nothing_holding_the_stores() {
        let home = managed();
        let chats = Arc::new(HeldChats::default());
        *lock(&home.manager.record_stores) = Some(RecordStores {
            chats: chats.clone(),
            memory_index: Some(home.index.clone()),
            context_store: home.reports.clone(),
            knowledge: Some(home.knowledge.clone()),
        });
        home.index.upsert_turn(turn_of("kid", 1));
        let manager = Arc::new(home.manager);
        // A shutdown up to its release: closed, the registry taken (there is no loop of the
        // child here), no terminate under way then, the queue run.
        manager.closed.store(true, Ordering::SeqCst);

        let (held, let_go) = chats.hold_next();
        let terminating = std::thread::spawn({
            let manager = manager.clone();
            move || manager.abort_child("kid")
        });
        held.recv_timeout(WAIT)
            .expect("the terminate is in its first pass");
        manager.unbind();
        let_go.send(()).expect("the terminate is held");
        joined(terminating);

        assert_eq!(
            turns_of(&home.index, "kid"),
            0,
            "forgotten by the terminate"
        );
        assert!(lock(&manager.forget_at_shutdown).is_empty());
        assert_eq!(Arc::strong_count(&home.index), 1);
        assert_eq!(Arc::strong_count(&chats), 1);
    }

    /// A loop served for a child under an id a terminated child held starts only once that
    /// child's loop has ended and its pass has run — under the same bare id with another
    /// colon id, and under the same colon id with another bare id — so the pass neither
    /// forgets what the new loop writes nor leaves it what the old loop wrote late. A loop
    /// that shares neither id starts at once.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_child_served_under_an_id_a_terminated_child_held_starts_after_its_pass() {
        let handles = Arc::new(Mutex::new(HashMap::new()));
        handles
            .lock()
            .unwrap()
            .insert("kid".to_string(), "helper".to_string());
        let home = managed_with_handles(handles);
        for bare in ["newcomer", "other"] {
            add_child(&home, bare);
        }
        let (first, finish, written) = loop_in_a_step(&home.index, "kid");
        retain_running(&home.manager, "kid", "agent:helper", first);
        home.manager.abort_child("kid");
        let pass = pending_pass(&home.manager, "agent:helper");

        // Each loop writes a row of its own as it starts.
        let serving = |agent: &'static str| {
            let index = home.index.clone();
            let (tell, told) = tokio::sync::oneshot::channel::<()>();
            let serve = async move {
                index.upsert_turn(turn_of(agent, 3));
                let _ = tell.send(());
                std::future::pending::<()>().await;
            };
            (serve, told)
        };
        let (looping, kid_started) = serving("kid");
        assert!(serve(&home.manager, "kid", "agent:kid", looping));
        let (looping, newcomer_started) = serving("newcomer");
        assert!(serve(&home.manager, "newcomer", "agent:helper", looping));
        let (looping, other_started) = serving("other");
        assert!(serve(&home.manager, "other", "agent:other", looping));
        assert_eq!(
            home.manager.active_loop_count(),
            3,
            "all three are retained"
        );

        within(other_started)
            .await
            .expect("a loop that shares no id starts at once");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(pass.has_changed().is_ok(), "the first loop is in its step");
        assert_eq!(
            turns_of(&home.index, "kid"),
            0,
            "not started under the bare id"
        );
        assert_eq!(
            turns_of(&home.index, "newcomer"),
            0,
            "not started under the colon id"
        );

        finish
            .send(())
            .expect("the first loop is still in its step");
        within(kid_started).await.expect("started after the pass");
        within(newcomer_started)
            .await
            .expect("started after the pass");
        assert!(written.load(Ordering::SeqCst), "the first loop wrote late");
        // The pass forgot the late row (turn 2) before the new loop wrote its own (turn 3).
        let kept: Vec<u32> = home
            .index
            .list_turns_for_agent("kid")
            .iter()
            .map(|row| row.turn)
            .collect();
        assert_eq!(kept, [3]);
        assert_eq!(turns_of(&home.index, "newcomer"), 1);
    }

    /// A serve loop that marks when it starts, and the mark.
    fn marked_serve() -> (
        impl std::future::Future<Output = ()> + Send + 'static,
        Arc<AtomicBool>,
    ) {
        let started = Arc::new(AtomicBool::new(false));
        let marks = started.clone();
        let serve = async move {
            marks.store(true, Ordering::SeqCst);
            std::future::pending::<()>().await
        };
        (serve, started)
    }

    /// `retained` for [`PerChildLoopManager::spawn_serve_loop`] that marks when it runs,
    /// and the mark.
    fn marked_retain() -> (impl FnOnce(), Arc<AtomicBool>) {
        let told = Arc::new(AtomicBool::new(false));
        let marks = told.clone();
        (move || marks.store(true, Ordering::SeqCst), told)
    }

    /// Let the runtime run what it has to run for a while.
    async fn let_run() {
        for _ in 0..16 {
            tokio::task::yield_now().await;
        }
    }

    /// The tree shows the child terminated — a terminate marked it so before the serve
    /// began, or failed after marking it — or gone: the serve registers nothing, retains
    /// no loop and never starts it. No loop ran, so no pass is left to forget what one
    /// wrote, and nothing is forgotten.
    #[tokio::test]
    async fn a_child_the_tree_shows_terminated_or_gone_is_not_served() {
        let home = managed();
        let kid = AgentId("kid".to_string());
        home.manager
            .tree
            .set_status(&kid, AgentStatus::Terminated)
            .expect("kid is in the tree");
        for gone in [false, true] {
            if gone {
                home.manager.tree.remove(&kid).expect("kid is a leaf");
            }
            let (looping, started) = marked_serve();
            let (retained, told) = marked_retain();
            let serving = Serving::begin(&home.manager, "kid");
            assert!(!home.manager.spawn_serve_loop(
                &serving,
                "kid",
                "agent:kid".to_string(),
                Some("agent:root"),
                retained,
                looping
            ));
            assert_eq!(
                served_under(&home.manager, "agent:kid"),
                None,
                "not retained"
            );
            assert!(!told.load(Ordering::SeqCst), "nothing recorded of it");
            assert_not_registered(&home.manager, "kid", "agent:kid");
            let_run().await;
            assert!(!started.load(Ordering::SeqCst), "never started");
        }
        assert!(lock(&home.manager.sweeps).is_empty());
        assert!(home.chats.forgotten().is_empty());
    }

    /// A terminate of a child while a serve of it is under way cancels the serve: it
    /// registers nothing, and its loop is not retained and never started — though the
    /// tree still shows the child active (as it shows a child created since under the
    /// same bare id: the tree cannot tell the two apart). A terminate of another child
    /// cancels nothing of it, and a serve begun after the terminate is not cancelled by
    /// it: it registers the child's route and id pair, and its loop is retained and runs.
    #[tokio::test]
    async fn a_terminate_cancels_the_serves_of_its_child_under_way() {
        let home = managed();
        let serving = Serving::begin(&home.manager, "kid");
        home.manager.abort_child("other");
        home.manager.abort_child("kid");
        let (looping, started) = marked_serve();
        let (retained, told) = marked_retain();
        assert!(!home.manager.spawn_serve_loop(
            &serving,
            "kid",
            "agent:kid".to_string(),
            Some("agent:root"),
            retained,
            looping
        ));
        drop(serving);
        assert_eq!(
            served_under(&home.manager, "agent:kid"),
            None,
            "not retained"
        );
        assert!(!told.load(Ordering::SeqCst), "nothing recorded of it");
        assert_not_registered(&home.manager, "kid", "agent:kid");
        let_run().await;
        assert!(!started.load(Ordering::SeqCst), "never started");
        assert!(
            lock(&home.manager.loops).serving.is_empty(),
            "no serve is under way any more"
        );

        let serving = Serving::begin(&home.manager, "kid");
        home.manager.abort_child("other");
        let (looping, started) = marked_serve();
        let (retained, told) = marked_retain();
        assert!(home.manager.spawn_serve_loop(
            &serving,
            "kid",
            "agent:kid".to_string(),
            Some("agent:root"),
            retained,
            looping
        ));
        assert!(told.load(Ordering::SeqCst));
        assert_eq!(
            home.manager.routing.agent_kind("agent:kid"),
            Some(AgentKind::Child)
        );
        assert_eq!(
            home.manager.bridge.resolve_owned("kid"),
            Some(("kid".to_string(), "agent:kid".to_string()))
        );
        within(async {
            while !started.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await;
    }

    /// A serve of `kid` stalled under way for the whole of a terminate of `kid` and of the
    /// serve of a child that has taken the colon id since: the serve, cancelled, touches
    /// nothing under the colon id — that child's route, id pair, loop and message stay —
    /// and, never trying to register, is no collision either.
    #[tokio::test]
    async fn a_cancelled_serve_leaves_alone_what_another_child_registered_since() {
        let lines = Arc::new(Lines::default());
        let mut home = managed();
        home.manager = home.manager.with_log(LogHandle::new(lines.clone()));
        add_child(&home, "newcomer");
        let serving = Serving::begin(&home.manager, "kid");
        home.manager.abort_child("kid");
        assert!(serve_routed(
            &home.manager,
            "newcomer",
            "agent:kid",
            std::future::pending::<()>()
        ));
        deliver(&home.manager, "newcomer", "agent:kid");

        let (looping, started) = marked_serve();
        assert!(!home.manager.spawn_serve_loop(
            &serving,
            "kid",
            "agent:kid".to_string(),
            Some("agent:root"),
            || {},
            looping
        ));
        drop(serving);
        assert_eq!(
            home.manager.routing.agent_kind("agent:kid"),
            Some(AgentKind::Child)
        );
        let pair = Some(("newcomer".to_string(), "agent:kid".to_string()));
        assert_eq!(home.manager.bridge.resolve_owned("agent:kid"), pair);
        assert_eq!(home.manager.bridge.resolve_owned("newcomer"), pair);
        assert_eq!(
            home.manager
                .store
                .get("agent:kid")
                .map(|mailbox| mailbox.depth()),
            Some(1)
        );
        assert_eq!(
            served_under(&home.manager, "agent:kid").as_deref(),
            Some("newcomer")
        );
        assert!(lines.keys().is_empty(), "{:?}", lines.keys());
        let_run().await;
        assert!(!started.load(Ordering::SeqCst), "never started");
    }

    /// A routed loop that ends on its own — its component trapped as it started, or its
    /// guest stopped — tears down the route and the id pair its serve registered, so a send
    /// to the child dead-ends rather than waiting in a mailbox no loop serves. Its finished
    /// handle stays retained until another loop takes its place or its child is terminated.
    #[tokio::test]
    async fn a_routed_loop_that_ends_on_its_own_is_unrouted() {
        let home = managed();
        assert!(serve_routed(&home.manager, "kid", "agent:kid", async {}));
        loops_ended(&home.manager).await;
        assert_not_registered(&home.manager, "kid", "agent:kid");
        assert_eq!(
            served_under(&home.manager, "agent:kid").as_deref(),
            Some("kid")
        );
    }

    /// A loop that ends as its child is terminated — in a step, past its last await, where
    /// the abort cannot stop it — tears down what its serve registered only while the
    /// registry still retains it. By then the terminate has taken it out, and the child
    /// served since under the same ids (the same bare id under the same handle registers
    /// the very same pair) keeps its route and its id pair. That child's loop, retained when
    /// it ends, tears its own down.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_loop_that_ends_after_its_terminate_leaves_its_successor_routed() {
        let home = managed();
        let (entered, in_step) = mpsc::channel();
        let (finish, finished) = mpsc::channel::<()>();
        assert!(serve_routed(
            &home.manager,
            "kid",
            "agent:kid",
            async move {
                entered.send(()).expect("the test waits for the step");
                finished.recv_timeout(WAIT).expect("the test ends the step");
            }
        ));
        in_step.recv_timeout(WAIT).expect("the loop is in its step");
        home.manager.abort_child("kid");
        assert_not_registered(&home.manager, "kid", "agent:kid");
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        assert!(serve_routed(
            &home.manager,
            "kid",
            "agent:kid",
            async move {
                let _ = stopped.await;
            }
        ));
        let pass = pending_pass(&home.manager, "agent:kid");

        finish.send(()).expect("the first loop is in its step");
        // The pass waits for the first loop to end: it has torn down what it would by then.
        within(closed(pass)).await;
        assert_eq!(
            home.manager.routing.agent_kind("agent:kid"),
            Some(AgentKind::Child),
            "the successor's route"
        );
        assert_eq!(
            home.manager.bridge.resolve_owned("agent:kid"),
            Some(("kid".to_string(), "agent:kid".to_string())),
            "the successor's id pair"
        );

        stop.send(()).expect("the successor is served");
        loops_ended(&home.manager).await;
        assert_not_registered(&home.manager, "kid", "agent:kid");
    }

    /// The terminate cascade's mailbox flush, which resolves the child's colon id anew
    /// after [`PerChildLoopManager::abort_child`], may empty a mailbox only of the child's
    /// own or of no one: not the root's, not one the id bridge pairs with another child,
    /// not one another child's loop is retained under (a child renamed keeps serving the
    /// colon id of its old handle, which another child can take).
    #[tokio::test]
    async fn a_terminate_flushes_only_a_mailbox_of_its_child_or_of_no_one() {
        let home = managed();
        assert!(
            !home.manager.may_flush("default", "agent:root"),
            "the root's"
        );
        assert!(
            !home.manager.may_flush("root", "agent:root"),
            "the root's own"
        );
        route(&home.manager, "other", "agent:helper");
        assert!(
            !home.manager.may_flush("kid", "agent:helper"),
            "another child's pair"
        );
        let elsewhere = tokio::spawn(std::future::pending::<()>());
        retain_running(&home.manager, "other", "agent:old", elsewhere);
        assert!(
            !home.manager.may_flush("kid", "agent:old"),
            "another child's loop"
        );

        route(&home.manager, "kid", "agent:kid");
        assert!(home.manager.may_flush("kid", "agent:kid"), "its own pair");
        let mine = tokio::spawn(std::future::pending::<()>());
        retain_running(&home.manager, "kid", "agent:mine", mine);
        assert!(home.manager.may_flush("kid", "agent:mine"), "its own loop");
        assert!(home.manager.may_flush("kid", "agent:nobody"), "no one's");
        within(home.manager.shutdown()).await;
    }

    /// The `skip_loop` witness's serve registers its child's route and id pair as a serve
    /// does: in one step, and not once a terminate of the child has cancelled it.
    #[tokio::test]
    async fn a_serve_without_a_loop_registers_only_while_it_may_serve() {
        let home = managed();
        let serving = Serving::begin(&home.manager, "kid");
        home.manager.abort_child("kid");
        assert!(!home
            .manager
            .register_unserved(&serving, "kid", "agent:kid", "agent:root"));
        drop(serving);
        assert_not_registered(&home.manager, "kid", "agent:kid");

        let serving = Serving::begin(&home.manager, "kid");
        assert!(home
            .manager
            .register_unserved(&serving, "kid", "agent:kid", "agent:root"));
        assert_eq!(
            home.manager.routing.agent_kind("agent:kid"),
            Some(AgentKind::Child)
        );
        assert_eq!(
            home.manager.bridge.resolve_owned("kid"),
            Some(("kid".to_string(), "agent:kid".to_string()))
        );
        assert_eq!(served_under(&home.manager, "agent:kid"), None, "no loop");
    }

    /// The same through the spawn: a terminate of the child while its `skip_loop` serve is
    /// under way — held as it delegates the child's grants, past the check of its node —
    /// leaves nothing of it registered. Not held, the serve registers the child's route.
    #[tokio::test]
    async fn a_spawn_without_a_loop_cancelled_under_way_registers_nothing() {
        for terminated in [true, false] {
            let (held, entered, release) = HeldLine::on(log_keys::PERCHILD_NO_FS_GRANT);
            let home = kid_home(
                vec![("static:root:fs", "fs", vec![param("paths", "notes")])],
                vec![declared("fs", serde_json::Value::Null)],
            );
            let manager = Arc::new(
                home.manager
                    .with_log(LogHandle::new(held))
                    .with_toggles(true, false),
            );
            let spawning = {
                let manager = manager.clone();
                let (root, kid, dir) = (home.root.clone(), home.kid.clone(), home.kid_dir.clone());
                std::thread::spawn(move || manager.on_child_spawned(&root, &kid, &dir))
            };
            entered
                .recv_timeout(WAIT)
                .expect("the serve delegates the grants");
            if terminated {
                manager.abort_child("kid");
            }
            release.send(()).expect("the serve is held");
            joined(spawning);
            if terminated {
                assert_not_registered(&manager, "kid", "agent:kid");
            } else {
                assert_eq!(
                    manager.routing.agent_kind("agent:kid"),
                    Some(AgentKind::Child)
                );
                assert_eq!(
                    manager.bridge.resolve_owned("kid"),
                    Some(("kid".to_string(), "agent:kid".to_string()))
                );
            }
        }
    }

    /// Records the crashes it is told of.
    #[derive(Default)]
    struct Crashes(Mutex<Vec<(String, String)>>);

    impl CrashCascadeSink for Crashes {
        fn handle_crash(&self, agent_id: &str, reason: &str) {
            self.0
                .lock()
                .unwrap()
                .push((agent_id.to_string(), reason.to_string()));
        }
    }

    /// The crash sink `on_child_spawned` gives the loop retained under `colon`.
    fn crash_sink_of(
        manager: &PerChildLoopManager,
        inner: Arc<dyn CrashCascadeSink>,
        colon: &str,
    ) -> ServedCrashSink {
        let serve = lock(&manager.loops)
            .retained
            .get(colon)
            .map(|retained| retained.serve)
            .expect("a loop is retained");
        ServedCrashSink {
            inner,
            loops: manager.loops.clone(),
            colon_id: colon.to_string(),
            serve,
        }
    }

    /// The crash notices (`component.terminated`) taken from the mailbox `key`.
    fn crash_notices(store: &MailboxStore, key: &str) -> Vec<serde_json::Value> {
        let Some(mailbox) = store.get(key) else {
            return Vec::new();
        };
        std::iter::from_fn(|| mailbox.poll())
            .filter_map(|message| {
                serde_json::from_slice::<serde_json::Value>(&message.payload).ok()
            })
            .filter(|payload| payload["event"] == "component.terminated")
            .collect()
    }

    /// A crash of a child's loop as its terminate is under way — the cascade has marked the
    /// child terminated and not yet reached its loop — leaves the mark and tells no one,
    /// through the production crash cascade; so a serve called for the child once its loop
    /// is taken out (a boot walk's, from a snapshot taken before) serves nothing. A crash
    /// before the terminate is reported through the same sink: the child fails, its parent
    /// is told.
    #[tokio::test]
    async fn a_crash_as_its_child_is_terminated_leaves_it_terminated() {
        let lines = Arc::new(Lines::default());
        let mut home = kid_home(Vec::new(), Vec::new());
        home.manager = home.manager.with_log(LogHandle::new(lines.clone()));
        let store = home.manager.store.clone();
        let inner = crate::crash_cascade::build_crash_cascade_sink(
            home.manager.tree.clone(),
            store.clone(),
            |bare: &str| format!("agent:{bare}"),
        );
        assert!(serve_routed(
            &home.manager,
            "kid",
            "agent:kid",
            std::future::pending::<()>()
        ));
        let sink = crash_sink_of(&home.manager, inner, "agent:kid");
        let status = || {
            home.manager
                .tree
                .get_node(&home.kid)
                .map(|node| node.status)
        };

        sink.handle_crash("agent:kid", "a trap");
        assert_eq!(status(), Some(AgentStatus::Failed));
        let notices = crash_notices(&store, "agent:root");
        assert_eq!(notices.len(), 1, "{notices:?}");
        assert_eq!(notices[0]["child"], "kid");

        home.manager
            .tree
            .set_status(&home.kid, AgentStatus::Terminated)
            .expect("kid is in the tree");
        sink.handle_crash("agent:kid", "a trap as it is terminated");
        assert_eq!(status(), Some(AgentStatus::Terminated));
        assert_eq!(
            crash_notices(&store, "agent:root"),
            Vec::<serde_json::Value>::new()
        );

        home.manager.abort_child("kid");
        home.manager
            .on_child_spawned(&home.root, &home.kid, &home.kid_dir);
        assert_eq!(served_under(&home.manager, "agent:kid"), None);
        assert_eq!(lines.keys(), [log_keys::PERCHILD_STALE_SERVE]);
        within(home.manager.shutdown()).await;
    }

    /// A loop's crash is told of its child by the child's bare id — not by the colon id the
    /// loop serves under, which follows the child's old handle once it is renamed — and only
    /// while the loop is retained: not once its child is terminated, nor while the loop of
    /// the child served since under the same ids is.
    #[tokio::test]
    async fn a_loops_crash_is_told_of_its_child_only_while_it_is_retained() {
        let handles = Arc::new(Mutex::new(HashMap::new()));
        let home = managed_with_handles(handles.clone());
        let crashes = Arc::new(Crashes::default());
        let told = || crashes.0.lock().unwrap().clone();
        assert!(serve_routed(
            &home.manager,
            "kid",
            "agent:kid",
            std::future::pending::<()>()
        ));
        let first = crash_sink_of(&home.manager, crashes.clone(), "agent:kid");
        handles
            .lock()
            .unwrap()
            .insert("kid".to_string(), "helper".to_string());
        first.handle_crash("agent:kid", "a trap");
        assert_eq!(told(), [("kid".to_string(), "a trap".to_string())]);

        home.manager.abort_child("kid");
        first.handle_crash("agent:kid", "a trap as it is terminated");
        handles.lock().unwrap().remove("kid");
        assert!(serve_routed(
            &home.manager,
            "kid",
            "agent:kid",
            std::future::pending::<()>()
        ));
        first.handle_crash("agent:kid", "a trap once the child is served again");
        assert_eq!(told().len(), 1, "{:?}", told());
        within(home.manager.shutdown()).await;
    }

    /// Records, each time it is told of a crash, whether the registry's lock is held then.
    struct LockProbe {
        loops: Arc<Mutex<LoopRegistry>>,
        held: Mutex<Vec<bool>>,
    }

    impl CrashCascadeSink for LockProbe {
        fn handle_crash(&self, _agent_id: &str, _reason: &str) {
            let held = matches!(
                self.loops.try_lock(),
                Err(std::sync::TryLockError::WouldBlock)
            );
            self.held.lock().unwrap().push(held);
        }
    }

    /// A loop's crash is told with the registry's lock held, so no terminate can take the
    /// loop out — and no respawn put a successor under the same id — between the look at
    /// the registry and the report.
    #[tokio::test]
    async fn a_loops_crash_is_told_under_the_registrys_lock() {
        let home = managed();
        assert!(serve_routed(
            &home.manager,
            "kid",
            "agent:kid",
            std::future::pending::<()>()
        ));
        let probe = Arc::new(LockProbe {
            loops: home.manager.loops.clone(),
            held: Mutex::default(),
        });
        crash_sink_of(&home.manager, probe.clone(), "agent:kid")
            .handle_crash("agent:kid", "a trap");
        assert_eq!(*probe.held.lock().unwrap(), [true]);
        within(home.manager.shutdown()).await;
    }

    /// A loop stopped in the place of another is kept to be awaited only while it may still
    /// run: the next loop stopped under that colon id lets go of one that has ended.
    #[tokio::test]
    async fn a_stopped_loop_that_has_ended_is_let_go_of() {
        let home = managed();
        assert!(serve(&home.manager, "kid", "agent:kid", async {}));
        loops_ended(&home.manager).await;
        for _ in 0..2 {
            assert!(serve(
                &home.manager,
                "kid",
                "agent:kid",
                std::future::pending::<()>()
            ));
        }
        assert_eq!(
            lock(&home.manager.loops).stopping.len(),
            1,
            "only the loop stopped last"
        );
        within(home.manager.shutdown()).await;
    }

    /// A serve whose colon id is another agent's — its route and id pair, its route alone
    /// (an agent registering it), or the child's bare id paired with another colon id — is
    /// not served: it leaves what is another's alone and nothing of its own behind, retains
    /// no loop, and says why.
    #[tokio::test]
    async fn a_serve_whose_colon_id_collides_is_not_served() {
        for held in ["route and pair", "route", "bare id"] {
            let lines = Arc::new(Lines::default());
            let mut home = managed();
            home.manager = home.manager.with_log(LogHandle::new(lines.clone()));
            match held {
                "route and pair" => route(&home.manager, "other", "agent:kid"),
                "route" => assert!(home
                    .manager
                    .routing
                    .register_child("agent:kid", "agent:root")),
                _ => assert!(home.manager.bridge.register("agent:elsewhere", "kid")),
            }
            let (looping, started) = marked_serve();
            assert!(!serve_routed(&home.manager, "kid", "agent:kid", looping));
            assert_eq!(served_under(&home.manager, "agent:kid"), None, "{held}");
            assert_eq!(lines.keys(), [log_keys::PERCHILD_COLON_COLLISION], "{held}");
            let routed = home.manager.routing.agent_kind("agent:kid");
            let bridge = &home.manager.bridge;
            match held {
                "route and pair" => {
                    assert_eq!(routed, Some(AgentKind::Child));
                    assert_eq!(
                        bridge.resolve_owned("agent:kid"),
                        Some(("other".to_string(), "agent:kid".to_string()))
                    );
                    assert_eq!(bridge.resolve_owned("kid"), None);
                }
                "route" => {
                    assert_eq!(routed, Some(AgentKind::Child), "the other route stays");
                    assert_eq!(bridge.resolve_owned("kid"), None, "its pair is undone");
                    assert_eq!(bridge.resolve_owned("agent:kid"), None);
                }
                _ => {
                    assert_eq!(routed, None, "its route is undone");
                    assert_eq!(
                        bridge.resolve_owned("kid"),
                        Some(("kid".to_string(), "agent:elsewhere".to_string()))
                    );
                }
            }
            let_run().await;
            assert!(!started.load(Ordering::SeqCst), "never started");
        }
    }

    /// A child the tree shows failed or paused is still a child: its serve registers its
    /// route and id pair, retains its loop and records it, and nothing of the child is torn
    /// down or forgotten.
    #[tokio::test]
    async fn a_failed_or_paused_child_is_served() {
        for status in [AgentStatus::Failed, AgentStatus::Paused] {
            let home = managed();
            home.index.upsert_turn(turn_of("kid", 1));
            home.manager
                .tree
                .set_status(&AgentId("kid".to_string()), status)
                .expect("kid is in the tree");
            let (looping, started) = marked_serve();
            let (retained, told) = marked_retain();
            let serving = Serving::begin(&home.manager, "kid");
            assert!(home.manager.spawn_serve_loop(
                &serving,
                "kid",
                "agent:kid".to_string(),
                Some("agent:root"),
                retained,
                looping
            ));
            assert!(told.load(Ordering::SeqCst));
            within(async {
                while !started.load(Ordering::SeqCst) {
                    tokio::task::yield_now().await;
                }
            })
            .await;
            assert_eq!(
                served_under(&home.manager, "agent:kid").as_deref(),
                Some("kid")
            );
            assert_eq!(
                home.manager.routing.agent_kind("agent:kid"),
                Some(AgentKind::Child),
                "still routed"
            );
            assert_eq!(
                home.manager.bridge.resolve_owned("kid"),
                Some(("kid".to_string(), "agent:kid".to_string()))
            );
            assert_eq!(turns_of(&home.index, "kid"), 1);
            assert!(home.chats.forgotten().is_empty());
        }
    }

    /// A loop retained under a colon id a loop is still retained under (two serves under
    /// one colon id, which a witness that registers no routes allows) takes its place, and
    /// that loop is stopped rather than let go of — none runs on out of the registry's
    /// reach — and awaited by a shutdown.
    #[tokio::test]
    async fn a_loop_retained_in_the_place_of_another_stops_it() {
        let home = managed();
        add_child(&home, "newcomer");
        let (alive, stopped) = tokio::sync::oneshot::channel::<()>();
        assert!(serve(&home.manager, "kid", "agent:kid", async move {
            let _alive = alive;
            std::future::pending::<()>().await
        }));
        assert!(serve(
            &home.manager,
            "newcomer",
            "agent:kid",
            std::future::pending::<()>()
        ));
        within(stopped)
            .await
            .expect_err("the loop it took the place of is stopped, and told nothing");
        assert_eq!(home.manager.active_loop_count(), 1);
        assert_eq!(
            served_under(&home.manager, "agent:kid").as_deref(),
            Some("newcomer")
        );
        assert_eq!(lock(&home.manager.loops).stopping.len(), 1);

        within(home.manager.shutdown()).await;
        let registry = lock(&home.manager.loops);
        assert!(registry.retained.is_empty() && registry.stopping.is_empty());
    }

    /// A loop stopped because another was retained in its place can be in the middle of
    /// a step: a shutdown waits for it to end, as for the loops it stops itself.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_shutdown_waits_for_a_loop_stopped_in_the_place_of_another() {
        let home = managed();
        add_child(&home, "newcomer");
        let (looping, finish, written) = loop_in_a_step(&home.index, "kid");
        retain_running(&home.manager, "kid", "agent:kid", looping);
        assert!(serve(
            &home.manager,
            "newcomer",
            "agent:kid",
            std::future::pending::<()>()
        ));
        assert_eq!(lock(&home.manager.loops).stopping.len(), 1);

        let manager = Arc::new(home.manager);
        let shutting_down = tokio::spawn({
            let manager = manager.clone();
            async move { manager.shutdown().await }
        });
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(
            !shutting_down.is_finished(),
            "the shutdown waits for the stopped loop, in its step"
        );
        finish.send(()).expect("the loop is still in its step");
        within(shutting_down)
            .await
            .expect("the shutdown ends without a panic");
        assert!(
            written.load(Ordering::SeqCst),
            "the loop ended its step before the shutdown returned"
        );
    }

    /// A terminate stops every loop of the subtree before its first step that can fail,
    /// and tears a node down only once that node's steps have succeeded (MODULE-005
    /// terminate-child flow). The stop cuts off a turn under way and tears nothing down: the
    /// child's route and id pair, the message waiting in its mailbox, its rows, its report
    /// and where it chats all stay until its teardown — and it leaves the loops of other
    /// children alone. The teardown takes them, and its pass waits for the loop the stop
    /// aborted, which may still be in a step.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_stopped_child_keeps_its_route_mailbox_and_records_until_it_is_torn_down() {
        let home = managed();
        home.index.upsert_turn(turn_of("kid", 1));
        home.reports.register_aliases(&aliases("kid"));
        home.reports
            .record(crate::context_inspect::test_report("agent:kid", 100));
        route(&home.manager, "kid", "agent:kid");
        let (looping, finish, written) = loop_in_a_step(&home.index, "kid");
        retain_running(&home.manager, "kid", "agent:kid", looping);
        retain_running(
            &home.manager,
            "other",
            "agent:other",
            tokio::spawn(std::future::pending::<()>()),
        );

        home.manager.stop_child("kid");
        home.manager.stop_child("kid");
        assert_eq!(served_under(&home.manager, "agent:kid"), None, "stopped");
        assert_eq!(
            home.manager.active_loop_count(),
            1,
            "the other child's runs"
        );
        assert_eq!(
            served_under(&home.manager, "agent:other").as_deref(),
            Some("other")
        );
        assert_eq!(lock(&home.manager.loops).stopped.len(), 1, "stopped once");
        assert_eq!(
            home.manager.routing.agent_kind("agent:kid"),
            Some(AgentKind::Child),
            "its route stays"
        );
        assert_eq!(
            home.manager.bridge.resolve_owned("agent:kid"),
            Some(("kid".to_string(), "agent:kid".to_string())),
            "its id pair stays"
        );
        assert_eq!(
            home.manager
                .store
                .get("agent:kid")
                .map(|mailbox| mailbox.depth()),
            Some(1),
            "its message waits"
        );
        assert_eq!(turns_of(&home.index, "kid"), 1, "its rows stay");
        assert!(
            home.reports.snapshot("agent:kid").is_some(),
            "its report stays"
        );
        assert!(home.chats.forgotten().is_empty(), "where it chats stays");
        assert!(lock(&home.manager.sweeps).is_empty(), "no pass is pending");

        home.manager.abort_child("kid");
        assert_unrouted(&home.manager, "kid", "agent:kid");
        assert_eq!(turns_of(&home.index, "kid"), 0, "forgotten at its teardown");
        assert!(home.reports.snapshot("agent:kid").is_none());
        assert!(lock(&home.manager.loops).stopped.is_empty());
        let pass = pending_pass(&home.manager, "agent:kid");
        assert!(
            pass.has_changed().is_ok(),
            "the stopped loop has not ended yet"
        );
        finish.send(()).expect("the loop is still in its step");
        within(closed(pass)).await;
        assert!(written.load(Ordering::SeqCst), "the step wrote its row");
        assert_eq!(turns_of(&home.index, "kid"), 0, "and the row is forgotten");
        assert_eq!(home.chats.forgotten(), ["kid", "kid"]);
        assert_eq!(
            served_under(&home.manager, "agent:other").as_deref(),
            Some("other")
        );
    }

    /// A stop cancels the serves of its child under way, as a terminate does: a serve that
    /// comes to retain its loop after the stop finds itself cancelled, and registers
    /// nothing.
    #[tokio::test]
    async fn a_stop_cancels_the_serves_of_its_child_under_way() {
        let home = managed();
        let serving = Serving::begin(&home.manager, "kid");
        home.manager.stop_child("kid");
        assert!(!home.manager.spawn_serve_loop(
            &serving,
            "kid",
            "agent:kid".to_string(),
            Some("agent:root"),
            || {},
            std::future::pending::<()>(),
        ));
        assert_not_registered(&home.manager, "kid", "agent:kid");
        assert_eq!(home.manager.active_loop_count(), 0);
        assert!(lock(&home.manager.loops).stopped.is_empty());
    }

    /// A loop a terminate stopped can be in the middle of a step, its child not torn down
    /// yet — the terminate failed after the stop: a shutdown waits for it to end, as for
    /// the loops it stops itself.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_shutdown_waits_for_a_loop_a_terminate_stopped() {
        let home = managed();
        let (looping, finish, written) = loop_in_a_step(&home.index, "kid");
        retain_running(&home.manager, "kid", "agent:kid", looping);
        home.manager.stop_child("kid");

        let manager = Arc::new(home.manager);
        let shutting_down = tokio::spawn({
            let manager = manager.clone();
            async move { manager.shutdown().await }
        });
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(
            !shutting_down.is_finished(),
            "the shutdown waits for the stopped loop, in its step"
        );
        finish.send(()).expect("the loop is still in its step");
        within(shutting_down)
            .await
            .expect("the shutdown ends without a panic");
        assert!(
            written.load(Ordering::SeqCst),
            "the loop ended its step before the shutdown returned"
        );
        assert!(lock(&manager.loops).stopped.is_empty());
    }
}

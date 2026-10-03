//! /dev Slice BS-3 (2026-06-03) — CLI-composition-root agent-loop wiring.
//!
//! The scheduler's `AgentLoopDriverImpl` is dependency-inverted over six traits
//! and takes NO compile-time dependency on the runtime / messaging / memory
//! crates (MODULE-014 trait-inversion posture). This module — living in the CLI,
//! which sits at the top of the dep graph — is the **composition root** that
//! supplies the concrete impls (the path MODULE-001 §3.6 documents as "point 4:
//! cli/src/wiring.rs", and which AC-18's runtime-crate-composition text cannot
//! take because messaging/reply-tracker/cap-lifecycle already depend on
//! advance-runtime → a cycle).
//!
//! It provides:
//! - [`WasmMessageHandler`] — the production WASM bridge: loads + instantiates a
//!   guest component through the existing `advance-host-with-capabilities` bindgen
//!   and drives `call_init` / `call_handle_message`. The reusable
//!   `(bindings, Store)` sits behind a synchronous `Mutex<Option<_>>` only while
//!   idle. `handle_message` takes the pair out before awaiting guest code, so
//!   cancellation drops the real Store instead of leaving it parked behind an
//!   async mutex.
//! - [`StoreMailboxReader`] — reads the SAME `MailboxStore` the dispatcher writes.
//! - minimal [`MinimalContextAssembler`] / [`MinimalRunBootstrap`]
//!   (the LLM/context and run-manager legs are out of this walking-skeleton's
//!   scope; the loop discards the assembled context). The action dispatcher now
//!   uses the real `EventBusRejectionSink` (production `security.action_rejected`
//!   emit) plus an optional `OutboundActionSink` (Phase-2 reply delivery — the
//!   daemon wires [`crate::reply::ReplyRouterSink`]; the harness passes `None`).
//! - [`build_agent_loop`] — assembles all six deps into an `AgentLoopDriverImpl`.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex, OnceLock};

use async_trait::async_trait;
use wasmtime::Store;

// Phase-3 kickoff (2026-06-06): the live per-session run producer + per-turn
// `complete_round` budget wiring.
use advance_run_manager::{RunConfig, RunId, RunManager};
use advance_shared_types::run::RoundResult;

use advance_runtime::wit_bindings::with_caps::advance::runtime::types as wit_types;
use advance_runtime::{
    AdvanceHostWithCapabilities, CapabilityInjector, ComponentCtx, ComponentRuntime,
    LoadedComponent,
};
use advance_scheduler::agent_loop::AgentLoopDriverImpl;
use advance_scheduler::hook::{BootstrapError, HookError, MessageHandler, RunBootstrap};
use advance_scheduler::types::ComponentConfig;
use advance_shared_types::capability::CapRequest;
use advance_shared_types::context::{
    AssemblyContext, AssemblyError, AssemblyResult, ContextAssembler, LlmMessage, TierTokenCounts,
};
use advance_shared_types::mailbox::{
    ActionResult, AgentAction, AgentActionDispatcher, MailboxReader, MailboxTurnEnvelope, Message,
};
use advance_shared_types::memory::PostProcessorHook;
use advance_shared_types::traits::EventBusEmit;
use advance_shared_types::turn_attribution::TurnMailboxError;

use advance_messaging::{
    AgentActionDispatcherImpl, EventBusRejectionSink, MailboxStore, OutboundActionSink,
};
use cap_http::{DefaultActionValidator, DEFAULT_MAX_DUPLICATE_PAYLOADS};
use cap_llm::LlmGateway;
use cap_memory::PostProcessor;

/// Production WASM-bridge `MessageHandler`. One handler drives one guest
/// component; `init` instantiates a fresh per-turn instance (and runs the guest's
/// `init` export), `handle_message` drives `handle-message` on that instance.
/// Phase-3 kickoff (2026-06-06): a shared cell carrying the session `RunId`
/// minted ONCE by the driver-side [`RunManagerBootstrap`] and read by the
/// [`WasmMessageHandler`] in `init` (so there is exactly one `ensure_run`). The
/// driver's `bootstrap_and_init` runs `run_bootstrap.ensure_run` (which sets the
/// cell) strictly before `message_handler.init` (which reads it).
pub type SessionRunCell = Arc<OnceLock<RunId>>;

/// Phase-3 kickoff: the per-session run wiring handed to a production
/// [`WasmMessageHandler`] via [`WasmMessageHandler::with_run_session`]. `None`
/// (the harness/test path) preserves the prior `run_id == None` behaviour.
#[derive(Clone)]
pub struct RunSession {
    /// The live `RunManager` (shared with the driver-side bootstrap). Used for
    /// per-turn `complete_round`.
    pub run_manager: Arc<RunManager>,
    /// The shared cell the bootstrap publishes the session `RunId` into.
    pub cell: SessionRunCell,
}

type WasmInstancePair = (AdvanceHostWithCapabilities, Store<ComponentCtx>);

/// Owns the concrete guest pair across exactly one guest future. On task
/// cancellation this guard is dropped with the future: it drops the pair first
/// and only then clears `store_in_guest_call`, allowing the scheduler's
/// synchronous cancellation finalizer to truthfully attest Store destruction.
struct OwnedWasmInstance<'a> {
    pair: Option<WasmInstancePair>,
    store_in_guest_call: &'a AtomicBool,
}

impl<'a> OwnedWasmInstance<'a> {
    fn new(pair: WasmInstancePair, store_in_guest_call: &'a AtomicBool) -> Result<Self, HookError> {
        store_in_guest_call
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| HookError::Failure("guest Store already in flight".into()))?;
        Ok(Self {
            pair: Some(pair),
            store_in_guest_call,
        })
    }

    fn pair_mut(&mut self) -> &mut WasmInstancePair {
        self.pair
            .as_mut()
            .expect("owned guest pair remains present until return/drop")
    }

    fn return_to(
        mut self,
        slot: &StdMutex<Option<WasmInstancePair>>,
        poisoned: &AtomicBool,
    ) -> Result<(), HookError> {
        if poisoned.load(Ordering::Acquire) {
            return Err(HookError::Failure("guest Store is poisoned".into()));
        }
        let pair = self
            .pair
            .take()
            .expect("owned guest pair remains present until return/drop");
        let mut idle = slot
            .lock()
            .map_err(|_| HookError::Failure("guest Store slot poisoned".into()))?;
        if poisoned.load(Ordering::Acquire) || idle.is_some() {
            drop(idle);
            drop(pair);
            self.store_in_guest_call.store(false, Ordering::Release);
            return Err(HookError::Failure("guest Store return rejected".into()));
        }
        *idle = Some(pair);
        self.store_in_guest_call.store(false, Ordering::Release);
        Ok(())
    }
}

impl Drop for OwnedWasmInstance<'_> {
    fn drop(&mut self) {
        // Explicit ordering is load-bearing: Store is gone before observers can
        // see `store_in_guest_call == false` and issue StoreDestroyed.
        drop(self.pair.take());
        self.store_in_guest_call.store(false, Ordering::Release);
    }
}

pub struct WasmMessageHandler {
    runtime: Arc<ComponentRuntime>,
    loaded: LoadedComponent,
    injector: Arc<CapabilityInjector>,
    caps: Vec<CapRequest>,
    agent_id: String,
    trace_id: String,
    /// Idle reusable `(bindings, Store)`. No mutex guard crosses an await:
    /// `handle_message` synchronously takes the pair into [`OwnedWasmInstance`].
    instance: StdMutex<Option<WasmInstancePair>>,
    /// True only while [`OwnedWasmInstance`] owns the pair across guest await.
    /// Cleared strictly after the pair is returned or physically dropped.
    store_in_guest_call: AtomicBool,
    /// Phase-3 kickoff: `Some` on the production path — `init` sets
    /// `ComponentCtx.run_id` from `cell` before instantiation, and
    /// `handle_message` calls `complete_round` per guest-reaching turn. `None`
    /// (harness/tests) → `run_id` stays `None`, budget skipped (prior behaviour).
    run_session: Option<RunSession>,
    /// C216 Store identity is host-minted and never guest-controlled. A
    /// sequential `run_agent` restart may replace a fully idle Store; that
    /// replacement rotates this incarnation while holding the instance lock.
    store_incarnation: StdMutex<[u8; 16]>,
    store_epoch: AtomicU64,
    /// Synchronous cancellation gate. Once set, no subsequent guest call can
    /// reacquire/reuse the Store even if task abort prevented async destruction.
    store_poisoned: AtomicBool,
    active_turn: StdMutex<Option<String>>,
}

impl WasmMessageHandler {
    pub fn new(
        runtime: Arc<ComponentRuntime>,
        loaded: LoadedComponent,
        injector: Arc<CapabilityInjector>,
        caps: Vec<CapRequest>,
        agent_id: String,
        trace_id: String,
    ) -> Self {
        Self {
            runtime,
            loaded,
            injector,
            caps,
            agent_id,
            trace_id,
            instance: StdMutex::new(None),
            store_in_guest_call: AtomicBool::new(false),
            run_session: None,
            store_incarnation: StdMutex::new(*uuid::Uuid::new_v4().as_bytes()),
            store_epoch: AtomicU64::new(0),
            store_poisoned: AtomicBool::new(false),
            active_turn: StdMutex::new(None),
        }
    }

    /// Phase-3 kickoff opt-in builder — install the per-session run wiring (the
    /// production path). Additive; the 6 existing `new()` callers (cli +
    /// system-acceptance tests) keep `run_session = None` and the prior
    /// `run_id == None` behaviour. Only `start.rs` chains this.
    pub fn with_run_session(mut self, run_session: RunSession) -> Self {
        self.run_session = Some(run_session);
        self
    }
}

#[async_trait]
impl MessageHandler for WasmMessageHandler {
    async fn init(&self, config: ComponentConfig) -> Result<Vec<u8>, HookError> {
        let mut ctx = ComponentCtx::new(self.agent_id.clone(), self.trace_id.clone(), Vec::new());
        // Phase-3 kickoff: set the session run_id on the ComponentCtx BEFORE
        // instantiation (instantiate consumes `ctx` by value into the Store and
        // may run guest start code, so a post-instantiation `store.data_mut()`
        // write would miss it). The bootstrap published the RunId into the cell
        // earlier in `bootstrap_and_init`. `to_host_call_context` then propagates
        // run_id → HostCallContext → LlmRequestContext → the gateway preflight.
        if let Some(rs) = &self.run_session {
            match rs.cell.get() {
                Some(rid) => ctx.run_id = Some(rid.as_ref().to_string()),
                // Fail-closed: a `Some(run_session)` with an unset cell means the
                // bootstrap's ensure_run never published (a wiring regression).
                // A public LLM entry point must NOT serve unbudgeted, so refuse.
                None => {
                    return Err(HookError::Failure(
                        "session run not established (run_session set but cell empty)".into(),
                    ))
                }
            }
        }
        let (bindings, mut store) = self
            .runtime
            .instantiate_advance_host_with_capabilities_async(
                &self.loaded,
                ctx,
                &self.caps,
                &self.injector,
            )
            .await
            .map_err(|e| HookError::Failure(format!("instantiate: {e:?}")))?;
        // scheduler ComponentConfig -> wit ComponentConfig (trigger_context dropped —
        // distinct enums; the agent skeleton's is None).
        let wit_cfg = wit_types::ComponentConfig {
            id: config.id,
            config_data: config.config_data,
            trigger_context: None,
        };
        let state = bindings
            .advance_runtime_message_driven()
            .call_init(&mut store, &wit_cfg)
            .await
            .map_err(|e| HookError::Failure(format!("call_init trap: {e:?}")))?
            .map_err(|e| HookError::Failure(format!("init returned err: {e}")))?;
        let mut idle = self
            .instance
            .lock()
            .map_err(|_| HookError::Failure("guest Store slot poisoned".into()))?;
        if self.store_in_guest_call.load(Ordering::Acquire) {
            return Err(HookError::Failure(
                "guest Store initialized more than once".into(),
            ));
        }
        let active = self
            .active_turn
            .lock()
            .map_err(|_| HookError::Failure("trusted turn state poisoned".into()))?;
        if active.is_some() {
            return Err(HookError::Failure(
                "guest Store initialized during an active turn".into(),
            ));
        }
        let recovering_destroyed_store = self.store_poisoned.load(Ordering::Acquire);
        if recovering_destroyed_store && idle.is_some() {
            return Err(HookError::Failure(
                "poisoned guest Store was not destroyed".into(),
            ));
        }
        let replacing_idle_store = idle.is_some();
        if replacing_idle_store || recovering_destroyed_store {
            let mut incarnation = self
                .store_incarnation
                .lock()
                .map_err(|_| HookError::Failure("guest Store incarnation poisoned".into()))?;
            *incarnation = *uuid::Uuid::new_v4().as_bytes();
            self.store_epoch.store(0, Ordering::Release);
        }
        // Instantiate and guest-init succeeded before this replacement point,
        // so a failed restart leaves the prior idle Store available. Holding
        // the instance lock across incarnation rotation makes the new pair and
        // its identity visible as one host-side transition.
        let prior = idle.replace((bindings, store));
        if recovering_destroyed_store {
            // The poison bit remains set while the replacement is instantiated
            // and guest-initialized. Clear it only after the fresh pair and its
            // rotated host identity are published under the instance lock.
            self.store_poisoned.store(false, Ordering::Release);
        }
        drop(active);
        drop(prior);
        Ok(state)
    }

    async fn handle_message(
        &self,
        msg: &Message,
        state: Vec<u8>,
    ) -> Result<ActionResult, HookError> {
        if self.store_poisoned.load(Ordering::Acquire) {
            return Err(HookError::Failure("guest Store is poisoned".into()));
        }
        // Take the concrete pair out of shared state BEFORE constructing the
        // guest future. No lock guard crosses the await. If the outer scheduler
        // future is aborted, `OwnedWasmInstance::drop` physically drops Store.
        let pair = {
            let mut idle = self
                .instance
                .lock()
                .map_err(|_| HookError::Failure("guest Store slot poisoned".into()))?;
            if self.store_poisoned.load(Ordering::Acquire) {
                return Err(HookError::Failure("guest Store is poisoned".into()));
            }
            idle.take()
                .ok_or_else(|| HookError::Failure("handle_message called before init".into()))?
        };
        let mut owned = OwnedWasmInstance::new(pair, &self.store_in_guest_call)?;
        let trusted_turn_id = self
            .active_turn
            .lock()
            .map_err(|_| HookError::Failure("trusted turn state poisoned".into()))?
            .clone();
        {
            let pair = owned.pair_mut();
            if let Some(tid) = msg.context.as_ref().and_then(|c| c.trace_id.clone()) {
                pair.1.data_mut().trace_id = tid;
            }
            // The C216 identity stamp is the final host mutation immediately
            // before `call_handle_message`; it is never sourced from Message.
            if let Some(turn_id) = trusted_turn_id.as_ref() {
                if pair.1.data().turn_id.is_some() {
                    self.store_poisoned.store(true, Ordering::Release);
                    return Err(HookError::Failure("trusted turn Store not clear".into()));
                }
                pair.1.data_mut().stamp_trusted_turn(turn_id.clone());
            }
        }
        let wit_msg = wit_types::Message {
            payload: msg.payload.clone(),
        };
        let call_result = {
            let pair = owned.pair_mut();
            pair.0
                .advance_runtime_message_driven()
                .call_handle_message(&mut pair.1, &wit_msg, &state)
                .await
        };

        let wit_result = match call_result {
            Ok(Ok(result)) => result,
            Ok(Err(error)) => {
                self.store_poisoned.store(true, Ordering::Release);
                drop(owned);
                return Err(HookError::Failure(format!(
                    "handle_message returned err: {error}"
                )));
            }
            Err(error) => {
                self.store_poisoned.store(true, Ordering::Release);
                drop(owned);
                return Err(HookError::Failure(format!(
                    "call_handle_message trap: {error:?}"
                )));
            }
        };
        if let Some(turn_id) = trusted_turn_id.as_ref() {
            let pair = owned.pair_mut();
            if pair.1.data().turn_id.as_deref() != Some(turn_id.as_str()) {
                self.store_poisoned.store(true, Ordering::Release);
                return Err(HookError::Failure("trusted turn identity mismatch".into()));
            }
            // Normal guest return clears the Store before it becomes reusable.
            // The later scheduler finalizer only verifies this state and advances
            // the monotonic drain epoch after every turn effect has settled.
            pair.1.data_mut().clear_trusted_turn();
        }
        owned.return_to(&self.instance, &self.store_poisoned)?;

        // Phase-3 kickoff: advance the rounds counter once per guest-reaching turn
        // (the guest's `agent-llm/generate` ran under the session run_id and the
        // EventBus CostTracker accrued its cost). `complete_round` increments
        // `rounds_used` and returns a `RoundDecision`, but it does NOT itself stop
        // the serve loop (the run stays Active) — its decision is informational.
        // ENFORCEMENT of the rounds cap is the gateway preflight: the NEXT
        // `agent-llm/generate` is denied (`budget-exceeded-rounds`) once
        // `rounds_used >= limit`. So the rounds cap bounds LLM-REACHING turns; a
        // guest that never calls `generate` (or traps) accrues rounds without
        // being blocked here — but it also spends no LLM budget. Firing on Ok AND
        // Err keeps the count honest across the guest-error/trap path. Best-effort:
        // a `complete_round` error is logged, not swallowed (a silent failure would
        // stop advancing the rounds counter the gateway gate reads).
        if let Some(rs) = &self.run_session {
            if let Some(rid) = rs.cell.get() {
                if let Err(e) = rs
                    .run_manager
                    .complete_round_with_trace(
                        rid,
                        RoundResult {
                            summary: None,
                            metrics: Vec::new(),
                        },
                        // Stage-F obs SLICE 1: thread the chain trace + chain-root
                        // span so `run.round_completed` joins the chain (137) AND
                        // links to the context.assembled root (138 pair).
                        msg.context.as_ref().and_then(|c| c.trace_id.clone()),
                        Some(advance_shared_types::event::chain_root_span_id(&msg.id)),
                    )
                    .await
                {
                    eprintln!(
                        "advance: complete_round failed for run {}: {e:?}",
                        rid.as_ref()
                    );
                }
            }
        }

        Ok(ActionResult {
            new_state: wit_result.new_state,
            actions: wit_result
                .actions
                .into_iter()
                .map(|a| AgentAction { payload: a.payload })
                .collect(),
        })
    }

    fn trusted_store_incarnation(&self) -> Option<[u8; 16]> {
        if self.store_poisoned.load(Ordering::Acquire) {
            return None;
        }
        // Lock ordering matches `init`: instance, then incarnation. This keeps
        // a sequential Store replacement and its fresh C216 identity atomic to
        // the scheduler while preserving the pre-init identity witness.
        let _idle = self.instance.lock().ok()?;
        let incarnation = *self.store_incarnation.lock().ok()?;
        Some(incarnation)
    }

    async fn stamp_trusted_turn(&self, turn_id: &str) -> Result<(), HookError> {
        if turn_id.is_empty() || self.store_poisoned.load(Ordering::Acquire) {
            return Err(HookError::Failure("trusted turn stamp rejected".into()));
        }
        if self.store_in_guest_call.load(Ordering::Acquire)
            || self
                .instance
                .lock()
                .map_err(|_| HookError::Failure("guest Store slot poisoned".into()))?
                .is_none()
        {
            return Err(HookError::Failure("guest Store unavailable".into()));
        }
        {
            let mut active = self
                .active_turn
                .lock()
                .map_err(|_| HookError::Failure("trusted turn state poisoned".into()))?;
            if active.is_some() {
                return Err(HookError::Failure("trusted turn already active".into()));
            }
            *active = Some(turn_id.to_string());
        }
        Ok(())
    }

    async fn clear_trusted_turn(&self, turn_id: &str) -> Result<u64, HookError> {
        if self.store_poisoned.load(Ordering::Acquire)
            || self.store_in_guest_call.load(Ordering::Acquire)
        {
            return Err(HookError::Failure("guest Store unavailable".into()));
        }
        let idle = self
            .instance
            .lock()
            .map_err(|_| HookError::Failure("guest Store slot poisoned".into()))?;
        let pair = idle
            .as_ref()
            .ok_or_else(|| HookError::Failure("guest Store unavailable".into()))?;
        if pair.1.data().turn_id.is_some() {
            return Err(HookError::Failure("trusted turn Store not clear".into()));
        }
        drop(idle);
        {
            let mut active = self
                .active_turn
                .lock()
                .map_err(|_| HookError::Failure("trusted turn state poisoned".into()))?;
            if active.as_deref() != Some(turn_id) {
                return Err(HookError::Failure("trusted turn identity mismatch".into()));
            }
            *active = None;
        }
        self.store_epoch
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |epoch| {
                epoch.checked_add(1)
            })
            .map(|previous| previous + 1)
            .map_err(|_| {
                self.store_poisoned.store(true, Ordering::Release);
                HookError::Failure("trusted Store epoch exhausted".into())
            })
    }

    async fn destroy_trusted_turn(&self, turn_id: &str) -> Result<(), HookError> {
        self.destroy_trusted_turn_now(turn_id)
    }

    fn destroy_trusted_turn_now(&self, turn_id: &str) -> Result<(), HookError> {
        self.store_poisoned.store(true, Ordering::Release);
        let destroyed = self
            .instance
            .lock()
            .map_err(|_| HookError::Failure("guest Store slot poisoned".into()))?
            .take();
        drop(destroyed);
        // `OwnedWasmInstance::drop` clears this only after dropping its pair. A
        // true value therefore means a concrete Store still exists in a guest
        // future and StoreDestroyed must not be asserted yet.
        if self.store_in_guest_call.load(Ordering::Acquire) {
            return Err(HookError::Failure("guest Store still in flight".into()));
        }
        {
            let mut active = self
                .active_turn
                .lock()
                .map_err(|_| HookError::Failure("trusted turn state poisoned".into()))?;
            if active.as_deref().is_some_and(|active| active != turn_id) {
                return Err(HookError::Failure("trusted turn identity mismatch".into()));
            }
            *active = None;
        }
        Ok(())
    }
}

/// `MailboxReader` adapter over a shared `MailboxStore` — the loop's `recv` reads
/// the same per-agent `Mailbox` the dispatcher's `deliver` writes.
pub struct StoreMailboxReader {
    store: Arc<MailboxStore>,
}

impl StoreMailboxReader {
    pub fn new(store: Arc<MailboxStore>) -> Self {
        Self { store }
    }
}

#[async_trait]
impl MailboxReader for StoreMailboxReader {
    async fn recv(&self, agent_id: &str) -> Message {
        self.store
            .get_or_create(agent_id)
            .expect("mailbox for a valid agent id")
            .recv()
            .await
    }
    async fn recv_turn(&self, agent_id: &str) -> Result<MailboxTurnEnvelope, TurnMailboxError> {
        self.store
            .get_or_create(agent_id)
            .map_err(|_| TurnMailboxError::Busy)?
            .recv_turn()
            .await
    }
    fn poll(&self, agent_id: &str) -> Option<Message> {
        self.store
            .get_or_create(agent_id)
            .ok()
            .and_then(|mb| mb.poll())
    }
    fn poll_turn(&self, agent_id: &str) -> Result<Option<MailboxTurnEnvelope>, TurnMailboxError> {
        self.store
            .get_or_create(agent_id)
            .map_err(|_| TurnMailboxError::Busy)?
            .poll_turn()
    }
    fn depth(&self, _agent_id: &str) -> usize {
        0
    }
    fn freeze(&self, _agent_id: &str) {}
    fn unfreeze(&self, _agent_id: &str) {}
}

/// Minimal `ContextAssembler` — the agent loop builds an `AssemblyContext`, calls
/// `assemble`, and DISCARDS the result (no LLM-generate wiring in the loop; the
/// guest drives any LLM call itself). Returning an empty `AssemblyResult` is
/// sufficient for the walking skeleton.
pub struct MinimalContextAssembler;

#[async_trait]
impl ContextAssembler for MinimalContextAssembler {
    async fn assemble(&self, _ctx: AssemblyContext) -> Result<AssemblyResult, AssemblyError> {
        Ok(AssemblyResult {
            messages: Vec::new(),
            routing_method: "search".to_string(),
            routing_confidence: 0.0,
            is_new_task: true,
            tier_token_counts: TierTokenCounts {
                tier1a: 0,
                tier1b: 0,
                tier2: 0,
                tier3: 0,
            },
        })
    }
    fn inject_tier3_warning(&self, _agent_id: &str, _msg: &str) {}
}

/// Backbone Step 2 (2026-06-07) — the production `ContextAssembler` that makes
/// host-assembled layered context actually feed the LLM. It WRAPS the real
/// `ContextAssemblerImpl` (built by [`crate::context_wiring::build_context_assembler`])
/// and, on each `assemble`, PUBLISHES the assembled `AssemblyResult.messages` into
/// the [`LlmGateway`]'s per-agent assembled-context store (keyed by the bare cap
/// `agent_id` that also seeds `ComponentCtx.agent_id`). The guest's
/// `agent-llm/generate` later reads + prepends them (cap-llm `AgentLlmGenerateHandler`).
///
/// Why publish here (a side channel) rather than thread the result through the
/// scheduler: the scheduler's `run_turn_once` is dependency-inverted and must not
/// depend on cap-llm, so it returns-and-drops the `AssemblyResult`. The wrapper —
/// living at the cli composition root, which DOES depend on cap-llm — turns that
/// dropped result into the gateway-store publish. `assemble` runs strictly before
/// the guest's generate within a turn, so the publish happens-before the read.
/// Keying on the FIXED `agent_id` (not `AssemblyContext.agent_id`, the colon
/// messaging id) makes the publish key match the generate handler's
/// `HostCallContext.agent_id` in both production and the harness.
pub struct PublishingContextAssembler {
    inner: Arc<dyn ContextAssembler>,
    gateway: Arc<LlmGateway>,
    /// Bare cap id (= `WasmMessageHandler.agent_id` = `ComponentCtx.agent_id`).
    agent_id: String,
}

impl PublishingContextAssembler {
    pub fn new(
        inner: Arc<dyn ContextAssembler>,
        gateway: Arc<LlmGateway>,
        agent_id: String,
    ) -> Self {
        Self {
            inner,
            gateway,
            agent_id,
        }
    }
}

#[async_trait]
impl ContextAssembler for PublishingContextAssembler {
    async fn assemble(&self, ctx: AssemblyContext) -> Result<AssemblyResult, AssemblyError> {
        let result = self.inner.assemble(ctx).await?;
        // Overwrite each turn (per-turn freshness). Cheap Arc<[..]> from the Vec.
        let msgs: Arc<[LlmMessage]> = Arc::from(result.messages.clone());
        self.gateway.publish_assembled(&self.agent_id, msgs);
        Ok(result)
    }

    fn inject_tier3_warning(&self, agent_id: &str, msg: &str) {
        self.inner.inject_tier3_warning(agent_id, msg);
    }
}

/// Minimal `RunBootstrap` — returns a synthetic run id. Retained as the
/// `build_agent_loop` default for the harness/test path (where `run_session`
/// is `None`, so the synthetic id is never set on a `ComponentCtx`).
pub struct MinimalRunBootstrap;

#[async_trait]
impl RunBootstrap for MinimalRunBootstrap {
    async fn ensure_run(&self, controller_agent: &str) -> Result<String, BootstrapError> {
        Ok(format!("run-{controller_agent}"))
    }
}

/// Phase-3 kickoff (2026-06-06): the production `RunBootstrap`. Mints the ONE
/// session run via `RunManager::ensure_run` at serve start and publishes its
/// `RunId` into the shared [`SessionRunCell`] the [`WasmMessageHandler`] reads in
/// `init`. The driver's `bootstrap_and_init` discards the returned String (it
/// only checks `Err`), so the cell is the real hand-off. Keyed on the **bare cap
/// id** (`session_agent`, matching `WasmMessageHandler.agent_id` + cap-fs/cap-grant
/// controller resolution), NOT the colon messaging id the driver passes.
pub struct RunManagerBootstrap {
    pub run_manager: Arc<RunManager>,
    pub run_config: RunConfig,
    pub session_agent: String,
    pub cell: SessionRunCell,
}

#[async_trait]
impl RunBootstrap for RunManagerBootstrap {
    async fn ensure_run(&self, _controller_agent: &str) -> Result<String, BootstrapError> {
        // Ignore the driver's `controller_agent` (the colon messaging id); use the
        // bare cap id so the run's controller resolves consistently with the
        // producer (`WasmMessageHandler.agent_id`).
        let rid = self
            .run_manager
            .ensure_run(
                &self.session_agent,
                &self.session_agent,
                self.run_config.clone(),
            )
            .map_err(|e| BootstrapError::EnsureRun(format!("{e:?}")))?;
        // Publish into the shared cell for the handler's `init` to read. `set`
        // errors only if already set (idempotent across a re-bootstrap) — ignore.
        let _ = self.cell.set(rid.clone());
        Ok(rid.to_string())
    }
}

/// Assemble all six `AgentLoopDriverImpl` dependencies. `mailbox_reader` reads the
/// shared `store` the dispatcher writes; `message_handler` is the production WASM
/// bridge. The action-validator is the real `cap_http::DefaultActionValidator`,
/// gated through the real [`EventBusRejectionSink`] (emits `security.action_rejected`
/// via `event_bus` on rejection — completing the production path of MODULE-006-AC-11).
///
/// `outbound` is the optional post-dispatch delivery seam (MODULE-006 §2.7):
/// `Some(sink)` (the daemon wires [`crate::reply::ReplyRouterSink`]) routes each
/// validated action batch — including an empty one — to the sink so the guest's
/// reply becomes observable; `None` (the system-acceptance harness + the
/// fs-only full-turn test) keeps the dispatcher gate-only, preserving prior
/// behavior.
/// BYTE-IDENTICAL 4-arg form — the action-validator uses the compile-time
/// default thresholds (`DefaultActionValidator::new()`). Kept so the ~16 existing
/// test/system-acceptance callers compile unchanged. Production
/// (`commands/start.rs`) calls [`build_agent_loop_with_action_limit`] to apply the
/// `security.action_validator.max_message_size` config snapshot (MODULE-012 AC-17).
pub fn build_agent_loop(
    store: Arc<MailboxStore>,
    message_handler: Arc<dyn MessageHandler>,
    event_bus: Arc<dyn EventBusEmit>,
    outbound: Option<Arc<dyn OutboundActionSink>>,
) -> AgentLoopDriverImpl {
    build_agent_loop_inner(
        store,
        message_handler,
        event_bus,
        outbound,
        Arc::new(DefaultActionValidator::new()),
    )
}

/// Wave-16 Lane-4 (MODULE-012 AC-17): like [`build_agent_loop`] but builds the
/// `ActionValidator` from `security.action_validator.max_message_size` (read once
/// at construction — a **snapshot**, NOT a live source, to preserve the
/// CONTRACT-113 determinism invariant: same `(agent_id, actions)` → same result,
/// no clock/RNG/I/O). The duplicate-payload threshold keeps its default
/// (`DEFAULT_MAX_DUPLICATE_PAYLOADS`; not an AC-17 config key).
pub fn build_agent_loop_with_action_limit(
    store: Arc<MailboxStore>,
    message_handler: Arc<dyn MessageHandler>,
    event_bus: Arc<dyn EventBusEmit>,
    outbound: Option<Arc<dyn OutboundActionSink>>,
    max_message_size: usize,
) -> AgentLoopDriverImpl {
    build_agent_loop_inner(
        store,
        message_handler,
        event_bus,
        outbound,
        Arc::new(DefaultActionValidator::with_thresholds(
            max_message_size,
            DEFAULT_MAX_DUPLICATE_PAYLOADS,
        )),
    )
}

/// Assemble the loop around an already-published action dispatcher. Atomic
/// C215/C216 composition uses this entry point so no dormant legacy dispatcher
/// is constructed and then overwritten after joint activation.
pub fn build_agent_loop_with_prebuilt_dispatcher(
    store: Arc<MailboxStore>,
    message_handler: Arc<dyn MessageHandler>,
    action_dispatcher: Arc<dyn AgentActionDispatcher>,
) -> AgentLoopDriverImpl {
    build_agent_loop_from_dispatcher(store, message_handler, action_dispatcher)
}

fn build_agent_loop_inner(
    store: Arc<MailboxStore>,
    message_handler: Arc<dyn MessageHandler>,
    event_bus: Arc<dyn EventBusEmit>,
    outbound: Option<Arc<dyn OutboundActionSink>>,
    action_validator: Arc<DefaultActionValidator>,
) -> AgentLoopDriverImpl {
    // Validator-first gate (CONTRACT-113) + production rejection emit (CONTRACT-180)
    // + the optional outbound delivery seam.
    let mut dispatcher = AgentActionDispatcherImpl::new(
        action_validator,
        Arc::new(EventBusRejectionSink::new(event_bus)),
    );
    if let Some(outbound) = outbound {
        dispatcher = dispatcher.with_outbound(outbound);
    }
    let action_dispatcher: Arc<dyn AgentActionDispatcher> = Arc::new(dispatcher);
    build_agent_loop_from_dispatcher(store, message_handler, action_dispatcher)
}

fn build_agent_loop_from_dispatcher(
    store: Arc<MailboxStore>,
    message_handler: Arc<dyn MessageHandler>,
    action_dispatcher: Arc<dyn AgentActionDispatcher>,
) -> AgentLoopDriverImpl {
    let mailbox_reader: Arc<dyn MailboxReader> = Arc::new(StoreMailboxReader::new(store));
    let context_assembler: Arc<dyn ContextAssembler> = Arc::new(MinimalContextAssembler);
    let post_processor: Arc<dyn PostProcessorHook> = Arc::new(PostProcessor::new());
    let run_bootstrap: Arc<dyn RunBootstrap> = Arc::new(MinimalRunBootstrap);
    AgentLoopDriverImpl::new(
        mailbox_reader,
        context_assembler,
        post_processor,
        action_dispatcher,
        run_bootstrap,
        message_handler,
    )
}

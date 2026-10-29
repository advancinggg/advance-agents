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
use std::sync::{Arc, Mutex as StdMutex, OnceLock, PoisonError};

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

use crate::api::log_keys;
use crate::compose_log::LogHandle;

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

/// ADR 2026-10-24 D4 — the host-minted transcript scope of ONE guest
/// `handle-message` invocation that runs without a CONTRACT-216 trusted turn
/// (an agent whose mailbox turns are unprotected). The id is minted here,
/// never read from the Message or the guest, and is stamped only on
/// `ComponentCtx::transcript_scope` — never on `turn_id`, so cost attribution,
/// reply routing and the progress lifecycle never see it. Dropping the guard
/// drops the scope's transcript; `handle_message` drops it as soon as the
/// guest call returns (normal return, guest error, trap, contained panic), and
/// a cancelled call drops it with the future, so nothing carries into the
/// next turn.
struct InvocationTranscriptScope<'a> {
    id: String,
    agent_id: &'a str,
    gateway: Option<&'a Arc<LlmGateway>>,
}

impl<'a> InvocationTranscriptScope<'a> {
    fn mint(agent_id: &'a str, gateway: Option<&'a Arc<LlmGateway>>) -> Self {
        Self {
            id: format!("invocation-{}", uuid::Uuid::new_v4()),
            agent_id,
            gateway,
        }
    }
}

impl Drop for InvocationTranscriptScope<'_> {
    fn drop(&mut self) {
        if let Some(gw) = self.gateway {
            gw.end_turn(self.agent_id, &self.id);
        }
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
    /// The config of the latest `init`, kept to start a fresh instance.
    init_config: StdMutex<Option<ComponentConfig>>,
    /// Set when the last guest call trapped because a contained extension
    /// host-function panic left no in-band answer. `before_next_turn` also revives
    /// after any other failure that destroyed the Store; this flag only selects
    /// the log text when that revive cannot start.
    fresh_instance_due: AtomicBool,
    /// Where a failed `complete_round` or fresh instance is reported
    /// ([`Self::with_log`]; none by default).
    log: LogHandle,
    /// Host-owned turn transcript (ADR 2026-10-24 D4). `end_turn` drops the
    /// slot at `clear_trusted_turn` / `destroy_trusted_turn` for a trusted
    /// turn, and when the guest call returns for an invocation that ran under
    /// a minted scope ([`InvocationTranscriptScope`]). `None` on the harness
    /// path that never wires llm.
    llm_gateway: Option<Arc<LlmGateway>>,
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
            init_config: StdMutex::new(None),
            fresh_instance_due: AtomicBool::new(false),
            log: LogHandle::null(),
            llm_gateway: None,
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

    /// Report a failed per-turn `complete_round`, or a fresh instance that could not
    /// be started, to `log`.
    pub fn with_log(mut self, log: LogHandle) -> Self {
        self.log = log;
        self
    }

    /// Drop the host-owned turn transcript when the trusted turn ends, or when
    /// an invocation without one returns.
    pub fn with_llm_gateway(mut self, gateway: Arc<LlmGateway>) -> Self {
        self.llm_gateway = Some(gateway);
        self
    }

    fn drop_transcript(&self, turn_id: &str) {
        if let Some(gw) = &self.llm_gateway {
            gw.end_turn(&self.agent_id, turn_id);
        }
    }
}

#[async_trait]
impl MessageHandler for WasmMessageHandler {
    async fn init(&self, config: ComponentConfig) -> Result<Vec<u8>, HookError> {
        *self
            .init_config
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(config.clone());
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
        // ADR 2026-10-24 D4: every invocation gets a host-owned transcript
        // scope. A trusted turn is its own scope (`stamp_trusted_turn` below);
        // an invocation without one gets a scope minted for this call only.
        let mut invocation_scope = trusted_turn_id
            .is_none()
            .then(|| InvocationTranscriptScope::mint(&self.agent_id, self.llm_gateway.as_ref()));
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
            } else if let Some(scope) = invocation_scope.as_ref() {
                pair.1.data_mut().stamp_transcript_scope(scope.id.clone());
            }
        }
        let wit_msg = wit_types::Message {
            payload: msg.payload.clone(),
        };
        let (call_result, trapped_by_contained_panic) = {
            let pair = owned.pair_mut();
            crate::extension::guest_call::run(
                pair.0.advance_runtime_message_driven().call_handle_message(
                    &mut pair.1,
                    &wit_msg,
                    &state,
                ),
            )
            .await
        };
        // The minted scope ends with the call it was minted for, whatever the
        // call returned: clear it from the (possibly reused) Store and drop its
        // transcript here. A cancelled call never reaches this point; dropping
        // the future drops the guard (transcript) and `owned` (the Store).
        if let Some(scope) = invocation_scope.take() {
            owned.pair_mut().1.data_mut().clear_transcript_scope();
            drop(scope);
        }

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
                if trapped_by_contained_panic {
                    self.fresh_instance_due.store(true, Ordering::Release);
                }
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
                    self.log.err(
                        log_keys::COMPLETE_ROUND_FAILED,
                        format!(
                            "advance: complete_round failed for run {}: {e:?}",
                            rid.as_ref()
                        ),
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
        self.drop_transcript(turn_id);
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
        self.drop_transcript(turn_id);
        Ok(())
    }

    /// After a turn whose failure destroyed the guest Store, start a fresh instance
    /// before the next turn reads [`Self::trusted_store_incarnation`]. The guest's
    /// linear memory is not kept. The state the host carries between turns is: this
    /// method discards the bytes `init` returns, and the scheduler keeps the vector
    /// it already holds. A Store that is still inside a guest call is left alone.
    /// A poisoned Store that was not destroyed is left poisoned, so the next call
    /// still refuses. A fresh instance that cannot be started is logged, and the
    /// Store stays poisoned.
    async fn before_next_turn(&self) {
        if self.store_in_guest_call.load(Ordering::Acquire) {
            return;
        }
        let store_present = self
            .instance
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_some();
        if store_present {
            return;
        }
        let poisoned = self.store_poisoned.load(Ordering::Acquire);
        let from_panic = self.fresh_instance_due.load(Ordering::Acquire);
        if !poisoned && !from_panic {
            return;
        }
        self.fresh_instance_due.store(false, Ordering::Release);
        let config = self
            .init_config
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let Some(config) = config else {
            return;
        };
        if let Err(error) = self.init(config).await {
            let why = if from_panic {
                "after a contained extension panic"
            } else {
                "after the previous turn destroyed the guest Store"
            };
            self.log.err(
                log_keys::FRESH_INSTANCE_FAILED,
                format!(
                    "advance: WARN agent {}: no fresh guest instance {why}: {error}",
                    self.agent_id
                ),
            );
        }
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
/// `agent-llm/generate` later peeks them as the stable seed of every generate /
/// stream of the turn (cap-llm `AgentLlmGenerateHandler`; ADR 2026-10-24 D4).
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

#[cfg(test)]
mod invocation_transcript_scope_tests {
    //! ADR 2026-10-24 D4 — the host-owned transcript scope of every guest invocation, over the
    //! real hello-llm guest, the real `CapabilityInjector` and the real cap-llm `generate`
    //! handler and gateway (only the upstream is scripted). An invocation without a trusted
    //! turn runs under a scope the host mints for that call only: it reaches the transcript
    //! paths and never `turn_id`, and every exit of the guest call drops it.

    use std::collections::HashSet;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::atomic::AtomicUsize;
    use std::sync::Mutex;
    use std::time::{Duration, SystemTime};

    use advance_runtime::circuit_breaker::DefaultCircuitBreakerBus;
    use advance_runtime::config::{RuntimeConfig, WasmConfig};
    use advance_runtime::host_registry::{
        HostCallContext, HostCallError, HostFunctionHandler, HostFunctionSpec, HostRegistry,
        InMemoryHostRegistry,
    };
    use advance_shared_types::capability::{CapParams, CapabilityId, GrantDecision};
    use advance_shared_types::mailbox::MessageKind;
    use advance_shared_types::security_validator::{
        HttpCapability, HttpError, HttpRequest, HttpResponse, HttpSecurityChain,
    };
    use advance_shared_types::traits::GrantCheck;
    use advance_shared_types::turn_attribution::{
        CostAttributionLookup, TurnCostAttributionReadPort,
    };
    use cap_llm::TranscriptMode;
    use wasmtime::component::types::ComponentFunc;
    use wasmtime::component::Val;
    use wit_component::ComponentEncoder;

    use super::*;

    const AGENT: &str = "agent:scoped";
    const PROMPT: &str = "what is in the notes";
    const REPLY: &str = "the notes list three things";

    struct AllowAll;

    impl GrantCheck for AllowAll {
        fn check(&self, _: &str, _: &str, _: &str, _: &CapParams) -> GrantDecision {
            GrantDecision::Allow
        }
    }

    /// The scripted upstream: a chat completion answering [`REPLY`], or a 401 while `fail`.
    #[derive(Default)]
    struct Upstream {
        fail: AtomicBool,
        calls: AtomicUsize,
    }

    #[async_trait]
    impl HttpSecurityChain for Upstream {
        async fn execute(
            &self,
            _: &str,
            _: HttpRequest,
            _: &HttpCapability,
        ) -> Result<HttpResponse, HttpError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fail.load(Ordering::SeqCst) {
                return Ok(HttpResponse {
                    status: 401,
                    headers: Vec::new(),
                    body: b"{}".to_vec(),
                });
            }
            Ok(HttpResponse {
                status: 200,
                headers: Vec::new(),
                body: serde_json::to_vec(&serde_json::json!({
                    "choices": [{"message": {"content": REPLY}, "finish_reason": "stop"}],
                    "usage": {"prompt_tokens": 3, "completion_tokens": 2},
                    "model": "scoped-model",
                }))
                .expect("answer serializes"),
            })
        }
    }

    /// Every turn id cost attribution is asked about.
    #[derive(Default)]
    struct RecordingTurnCost(Mutex<Vec<String>>);

    impl TurnCostAttributionReadPort for RecordingTurnCost {
        fn cost_attribution(&self, turn_id: &str, _: &str) -> CostAttributionLookup {
            self.0.lock().unwrap().push(turn_id.to_string());
            CostAttributionLookup::Untracked
        }
    }

    /// How the scripted `generate` leaves the guest call.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Exit {
        /// The real handler answers; the guest returns its action.
        Return,
        /// The real handler answers a model error; the guest returns an error.
        GuestError,
        /// The host function fails: the guest call traps.
        Trap,
        /// The host function fails as a contained extension panic does.
        ContainedPanic,
        /// The host function never answers; the caller gives up on the call.
        Cancelled,
    }

    /// What one `generate` call saw.
    #[derive(Clone, Debug)]
    struct Seen {
        turn_id: Option<String>,
        scope: Option<String>,
        /// Transcript messages under the scope when the call left.
        recorded: usize,
    }

    /// Transcript messages recorded for `scope` (seed and prompt excluded).
    fn transcript_len(gateway: &LlmGateway, scope: &str) -> usize {
        let with = gateway.build_guest_messages(AGENT, Some(scope), "", TranscriptMode::Continue);
        let without = gateway.build_guest_messages(AGENT, None, "", TranscriptMode::Continue);
        with.len() - without.len()
    }

    /// Wraps the real `generate` handler. Each call records what it saw; every exit but
    /// [`Exit::Return`] first records one transcript entry under the scope, so the exit has
    /// something to drop.
    struct ScriptedGenerate {
        inner: Arc<dyn HostFunctionHandler>,
        gateway: Arc<LlmGateway>,
        exit: Mutex<Exit>,
        seen: Arc<Mutex<Vec<Seen>>>,
    }

    impl ScriptedGenerate {
        fn run(
            &self,
            ctx: HostCallContext,
            inner: Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>>,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>>
        {
            let exit = *self.exit.lock().unwrap();
            let gateway = Arc::clone(&self.gateway);
            let seen = Arc::clone(&self.seen);
            Box::pin(async move {
                let scope = ctx.transcript_scope.clone();
                let note = |recorded| Seen {
                    turn_id: ctx.turn_id.clone(),
                    scope: scope.clone(),
                    recorded,
                };
                if exit != Exit::Return {
                    if let Some(scope) = scope.as_deref() {
                        gateway.record_tool_result(AGENT, scope, "call-1", "notes", "three things");
                    }
                }
                let recorded = scope.as_deref().map_or(0, |s| transcript_len(&gateway, s));
                match exit {
                    Exit::Return | Exit::GuestError => {
                        let out = inner.await;
                        let recorded = scope.as_deref().map_or(0, |s| transcript_len(&gateway, s));
                        seen.lock().unwrap().push(note(recorded));
                        out
                    }
                    Exit::Trap => {
                        seen.lock().unwrap().push(note(recorded));
                        Err(HostCallError::HandlerError("scripted trap".into()))
                    }
                    Exit::ContainedPanic => {
                        seen.lock().unwrap().push(note(recorded));
                        crate::extension::guest_call::mark_trapped_by_contained_panic();
                        Err(HostCallError::HandlerError(
                            "scripted contained panic".into(),
                        ))
                    }
                    Exit::Cancelled => {
                        seen.lock().unwrap().push(note(recorded));
                        std::future::pending().await
                    }
                }
            })
        }
    }

    impl HostFunctionHandler for ScriptedGenerate {
        fn call(
            &self,
            ctx: HostCallContext,
            params: Vec<Val>,
            results_len: usize,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>>
        {
            let inner = self.inner.call(ctx.clone(), params, results_len);
            self.run(ctx, inner)
        }

        fn call_typed(
            &self,
            func: &ComponentFunc,
            ctx: HostCallContext,
            params: Vec<Val>,
            results_len: usize,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>>
        {
            let inner = self
                .inner
                .call_typed(func, ctx.clone(), params, results_len);
            self.run(ctx, inner)
        }
    }

    struct Rig {
        handler: WasmMessageHandler,
        gateway: Arc<LlmGateway>,
        upstream: Arc<Upstream>,
        generate: Arc<ScriptedGenerate>,
        seen: Arc<Mutex<Vec<Seen>>>,
        turn_cost: Arc<RecordingTurnCost>,
    }

    impl Rig {
        async fn new() -> Self {
            let config: RuntimeConfig = serde_yml::from_str(
                "wasm:\n  max_memory_pages: 1024\n  epoch_interruption_ms: 100\n  fuel_enabled: false\n\
                 llm-providers:\n  - id: scoped\n    endpoint: https://api.example.test\n    \
                 api-key-secret: scoped-api-key\n    model-aliases:\n      default: scoped-model\n    \
                 cost-per-mtoken-in: 1.0\n    cost-per-mtoken-out: 2.0\n    rate-limit:\n      \
                 requests-per-minute: 1000\n      tokens-per-minute: 400000\n\
                 cron:\n  max_jitter_ratio: 0.1\ngit:\n  gc_interval_hours: 24\n  max_tracked_file_mb: 10\n\
                 secrets:\n  master-key-source: env-var\n  env-var-name: SCOPED_TEST_MASTER_KEY\n\
                 post-processor:\n  llm-model: scoped-model\n  llm-failure-cooldown-seconds: 600\n",
            )
            .expect("runtime config parses");
            let upstream = Arc::new(Upstream::default());
            let gateway = Arc::new(LlmGateway::new(
                Arc::new(cap_llm::StaticConfig(Arc::new(config))),
                Arc::clone(&upstream) as Arc<dyn HttpSecurityChain>,
                Arc::new(cap_llm::PreflightAllowBudget),
                Arc::new(cap_llm::DiscardEventBus),
                Arc::new(cap_llm::NoopRepetition),
                AGENT.to_string(),
            ));
            let turn_cost = Arc::new(RecordingTurnCost::default());
            // The production registration of `agent-llm`, with `generate` wrapped.
            let real = InMemoryHostRegistry::new();
            let _reaper = cap_llm::register_agent_llm_with_turn_cost(
                &real,
                Arc::clone(&gateway),
                Some(Arc::clone(&turn_cost) as Arc<dyn TurnCostAttributionReadPort>),
            );
            let registry: Arc<dyn HostRegistry> = Arc::new(InMemoryHostRegistry::new());
            let seen = Arc::new(Mutex::new(Vec::new()));
            let mut generate = None;
            for spec in real.lookup("llm") {
                if spec.name == "generate" {
                    let wrapped = Arc::new(ScriptedGenerate {
                        inner: Arc::clone(&spec.handler),
                        gateway: Arc::clone(&gateway),
                        exit: Mutex::new(Exit::Return),
                        seen: Arc::clone(&seen),
                    });
                    generate = Some(Arc::clone(&wrapped));
                    registry.register(HostFunctionSpec {
                        handler: wrapped,
                        ..spec
                    });
                } else {
                    registry.register(spec);
                }
            }
            let generate = generate.expect("agent-llm registers generate");
            let injector = Arc::new(CapabilityInjector::new(
                registry,
                Arc::new(AllowAll),
                Arc::new(DefaultCircuitBreakerBus::new()),
            ));
            let component = ComponentEncoder::default()
                .validate(true)
                .module(crate::test_support::fixture::hello_llm_core())
                .expect("encoder accepts the hello-llm core")
                .encode()
                .expect("encode to a component");
            let runtime = Arc::new(
                ComponentRuntime::new(&WasmConfig {
                    max_memory_pages: 256,
                    epoch_interruption_ms: 100,
                    fuel_enabled: false,
                })
                .expect("runtime"),
            );
            let loaded = runtime.load_component(&component).expect("component loads");
            let handler = WasmMessageHandler::new(
                runtime,
                loaded,
                injector,
                vec![CapRequest {
                    capability: CapabilityId::from("llm"),
                }],
                AGENT.to_string(),
                "trace-scoped".to_string(),
            )
            .with_llm_gateway(Arc::clone(&gateway));
            handler.init(component_config()).await.expect("init");
            Self {
                handler,
                gateway,
                upstream,
                generate,
                seen,
                turn_cost,
            }
        }

        fn exit_by(&self, exit: Exit) {
            *self.generate.exit.lock().unwrap() = exit;
            self.upstream
                .fail
                .store(exit == Exit::GuestError, Ordering::SeqCst);
        }

        fn last_seen(&self) -> Seen {
            self.seen
                .lock()
                .unwrap()
                .last()
                .cloned()
                .expect("generate was called")
        }

        /// The scope stamped on the idle Store, if any.
        fn idle_store_scope(&self) -> (Option<String>, Option<String>) {
            let idle = self.handler.instance.lock().unwrap();
            let ctx = idle.as_ref().expect("idle Store").1.data();
            (
                ctx.turn_id.clone(),
                ctx.transcript_scope().map(str::to_string),
            )
        }

        /// A seed for the turn, as the context assembler publishes one.
        fn publish_seed(&self) {
            self.gateway.publish_assembled(
                AGENT,
                Arc::from(vec![LlmMessage {
                    role: "system".into(),
                    content: "persona".into(),
                }]),
            );
        }
    }

    fn component_config() -> ComponentConfig {
        ComponentConfig {
            id: AGENT.to_string(),
            config_data: None,
            trigger_context: None,
        }
    }

    fn message(id: &str) -> Message {
        Message {
            id: id.to_string(),
            kind: MessageKind::User,
            from: "user:test".to_string(),
            to: AGENT.to_string(),
            payload: PROMPT.as_bytes().to_vec(),
            context: None,
            timestamp: SystemTime::now(),
            origin: None,
        }
    }

    /// Every exit of an unprotected invocation — a normal return, a guest error, a trap, a
    /// contained panic and a cancelled call — ran under a scope minted for that call alone,
    /// never on `turn_id`, and left neither its transcript nor the seed behind; the Store that
    /// is reused carries no scope; cost attribution was never asked about a minted id.
    #[tokio::test(flavor = "multi_thread")]
    async fn every_exit_of_an_unprotected_invocation_drops_its_minted_scope() {
        let rig = Rig::new().await;
        let mut scopes = HashSet::new();
        let exits = [
            Exit::Return,
            Exit::Return,
            Exit::GuestError,
            Exit::Trap,
            Exit::ContainedPanic,
            Exit::Cancelled,
        ];
        for (n, exit) in exits.into_iter().enumerate() {
            rig.exit_by(exit);
            rig.publish_seed();
            let msg = message(&format!("m{n}"));
            let outcome = tokio::time::timeout(
                Duration::from_secs(2),
                rig.handler.handle_message(&msg, Vec::new()),
            )
            .await;
            match exit {
                Exit::Return => {
                    let result = outcome.expect("answers").expect("the turn returns");
                    assert_eq!(result.actions.len(), 1, "{exit:?}");
                    assert_eq!(result.actions[0].payload, REPLY.as_bytes(), "{exit:?}");
                    assert_eq!(rig.idle_store_scope(), (None, None), "{exit:?}");
                }
                Exit::GuestError | Exit::Trap | Exit::ContainedPanic => {
                    let error = outcome.expect("answers").expect_err("the turn fails");
                    assert!(
                        matches!(error, HookError::Failure(_)),
                        "{exit:?}: {error:?}"
                    );
                }
                Exit::Cancelled => assert!(outcome.is_err(), "the call never answers"),
            }
            let seen = rig.last_seen();
            assert_eq!(
                seen.turn_id, None,
                "{exit:?}: the minted id never reaches turn_id"
            );
            let scope = seen.scope.expect("every invocation has a scope");
            assert!(scope.starts_with("invocation-"), "{exit:?}: {scope}");
            assert!(
                scopes.insert(scope.clone()),
                "{exit:?}: a fresh scope per invocation"
            );
            let expected = if exit == Exit::Return {
                2 // the prompt and the reply
            } else {
                1 // the scripted entry
            };
            assert_eq!(
                seen.recorded, expected,
                "{exit:?}: recorded under the scope"
            );
            assert_eq!(
                transcript_len(&rig.gateway, &scope),
                0,
                "{exit:?}: the minted transcript is dropped when the call leaves"
            );
            assert!(
                rig.gateway.assembled_for(AGENT).is_none(),
                "{exit:?}: the seed goes with it"
            );
            match exit {
                // A failed call destroyed the Store: start the fresh instance the next turn
                // gets.
                Exit::GuestError | Exit::Trap | Exit::ContainedPanic => {
                    rig.handler.before_next_turn().await;
                }
                // A cancelled call dropped its Store with the future.
                Exit::Cancelled => assert!(rig.handler.instance.lock().unwrap().is_none()),
                Exit::Return => {}
            }
        }
        assert_eq!(scopes.len(), exits.len());
        assert!(
            rig.turn_cost.0.lock().unwrap().is_empty(),
            "cost attribution reads turn_id only, and no unprotected call has one"
        );
        assert_eq!(rig.upstream.calls.load(Ordering::SeqCst), 3);
    }

    /// A trusted turn is its own transcript scope, exactly as before: the call sees the turn
    /// id on both fields, no scope is minted, the transcript outlives the invocation until the
    /// trusted turn is cleared, and cost attribution is asked about the turn id.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_protected_turn_keeps_its_trusted_turn_as_the_transcript_scope() {
        let rig = Rig::new().await;
        rig.exit_by(Exit::Return);
        rig.handler
            .stamp_trusted_turn("turn-7")
            .await
            .expect("stamp");
        let result = rig
            .handler
            .handle_message(&message("m1"), Vec::new())
            .await
            .expect("the turn returns");
        assert_eq!(result.actions[0].payload, REPLY.as_bytes());
        let seen = rig.last_seen();
        assert_eq!(seen.turn_id.as_deref(), Some("turn-7"));
        assert_eq!(seen.scope.as_deref(), Some("turn-7"));
        assert_eq!(seen.recorded, 2);
        assert_eq!(
            transcript_len(&rig.gateway, "turn-7"),
            2,
            "the trusted turn's transcript lives until the turn is cleared"
        );
        assert_eq!(rig.idle_store_scope(), (None, None));
        rig.handler
            .clear_trusted_turn("turn-7")
            .await
            .expect("clear");
        assert_eq!(transcript_len(&rig.gateway, "turn-7"), 0);
        assert_eq!(rig.turn_cost.0.lock().unwrap().as_slice(), ["turn-7"]);
    }
}

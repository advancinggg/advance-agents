//! `AgentLoopDriver` (CONTRACT-132) + Slice C full single-turn pipeline.
//!
//! Slice A shipped the skeleton with 4 inverted-trait `Arc<dyn ...>`
//! fields and `unimplemented!()` `run_agent` / `handle_trap` bodies.
//!
//! Slice B added a 5th field `run_bootstrap: Arc<dyn RunBootstrap>` and
//! made `run_agent` call `run_bootstrap.ensure_run(agent_id)` before
//! returning early.
//!
//! Slice C adds a 6th field `message_handler: Arc<dyn MessageHandler>`
//! (abstracts WASM `instance.call_init` + `call_handle_message` per AC-15)
//! and rewrites `run_agent` to run the full single-turn happy-path
//! pipeline: bootstrap → init → recv → assemble (full 7-field canonical
//! `AssemblyContext`) → handle_message (2-arg WIT shape) → dispatch
//! (M006-owned ActionValidator gate per ARCH §4.2) → post_process.
//!
//! Phase-2 Step-2 (2026-06-05): the canonical MODULE-014 §1.4.1 multi-turn
//! loop is now INTERNALIZED in the sibling inherent method [`AgentLoopDriverImpl::serve`].
//! `run_agent` STAYS the single-turn-per-call primitive (the system-acceptance
//! harness `run_turn()` + the AC-15 pipeline test depend on it returning after
//! one turn); `serve` shares the per-turn body via the private `run_turn_once`
//! helper, runs `bootstrap` + `init` ONCE, then loops `run_turn_once` carrying
//! `state = action_result.new_state` across turns in-process. The production
//! daemon (MODULE-001 composition root) spawns `serve`; the loop exits via
//! task-abort (no mailbox-close primitive exists). An optional
//! [`TurnObserver`] fires at every turn boundary so the daemon can resolve a
//! no-reply turn's `POST /msg` correlation + clear its single-in-flight guard.
//!
//! MODULE-014 §1.4.1 deviations note + §3.8(a) reflect these changes; see
//! `docs/modules/MODULE-014-scheduler.md`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use async_trait::async_trait;

use advance_shared_types::agent_tree::{AgentState, AgentStatus};
use advance_shared_types::context::{AssemblyContext, ContextAssembler};
use advance_shared_types::mailbox::{AgentActionDispatcher, MailboxReader, MailboxTurnIdentity};
use advance_shared_types::memory::PostProcessorHook;
use advance_shared_types::traits::EventBusEmit;
use advance_shared_types::turn_attribution::TurnStartOutcome;

use crate::component_emit::emit_component_error;
use crate::contracts::AgentLoopDriver;
use crate::daemon::{restart_decision, RestartDecision};
use crate::hook::{
    CrashCascadeSink, HookError, MessageHandler, ProtectedTurnExecutionBoundary, RunBootstrap,
    TurnObserver, TurnPersistenceBoundary, WorkspaceRollbackSink,
};
use crate::types::{ComponentConfig, RestartPolicy, TrapError, WasmInstance};

/// Slice C impl. 6 inverted-trait `Arc<dyn ...>` fields:
/// 1-4 from Slice A (MailboxReader, ContextAssembler, PostProcessorHook,
/// AgentActionDispatcher); 5 from Slice B (RunBootstrap); 6 from Slice
/// C (MessageHandler — 2-arg WIT `handle-message` abstraction per AC-15).
pub struct AgentLoopDriverImpl {
    /// MODULE-006 inverted trait — agent-loop polls mailbox via this.
    pub mailbox_reader: Arc<dyn MailboxReader>,
    /// MODULE-010 inverted trait — pre-turn context assembly.
    pub context_assembler: Arc<dyn ContextAssembler>,
    /// MODULE-011 inverted trait — post-turn memory / summary pipeline.
    pub post_processor: Arc<dyn PostProcessorHook>,
    /// MODULE-006 inverted trait — action-result dispatch +
    /// ActionValidator-first invariant.
    pub action_dispatcher: Arc<dyn AgentActionDispatcher>,
    /// Slice B addition: scheduler-crate-local `RunBootstrap` trait that
    /// abstracts M008 `ensure_run`.
    pub run_bootstrap: Arc<dyn RunBootstrap>,
    /// Slice C addition: scheduler-crate-local `MessageHandler` trait
    /// (2-arg WIT-faithful `init` + `handle_message`). Real
    /// Wasmtime-backed impl in a follow-up slice; Slice C uses a mock
    /// for AC-15 verification.
    pub message_handler: Arc<dyn MessageHandler>,
    /// Phase-2 Step-2 OPTIONAL per-turn boundary observer used ONLY by the
    /// `serve` loop (the single-turn `run_agent` never invokes it). `None` for
    /// all `new()` callers (tests / harness); the daemon wires one via
    /// [`AgentLoopDriverImpl::with_turn_observer`].
    pub turn_observer: Option<Arc<dyn TurnObserver>>,
    /// Stage-C SAT-A: the model id fed into each turn's `AssemblyContext.model`
    /// (drives MODULE-010's budget / progressive-mode selection). Empty by
    /// default — `new()` callers (tests + the system-acceptance harness via
    /// `build_agent_loop`) keep `""` so `model_context_window` behaviour is
    /// unchanged (harness-neutral). The cli composition root installs a CONCRETE
    /// model id via [`AgentLoopDriverImpl::with_model`].
    pub model: String,
    /// MODULE-014-AC-25 (029) OPTIONAL `component.error` EventBus emitter. `None`
    /// for every `new()`/harness caller (no emit — prior behaviour); the cli
    /// composition root wires the production bus via
    /// [`AgentLoopDriverImpl::with_component_error_emitter`].
    pub component_error_emitter: Option<Arc<dyn EventBusEmit>>,
    /// MODULE-014-AC-25 (029) OPTIONAL trap RestartPolicy. `None` (default) →
    /// `handle_trap` never requests a stop → the infinite-serve contract is
    /// unchanged for every existing caller. `Some(p)` → `handle_trap` computes
    /// `restart_decision(p, false)` and sets [`Self::stop_requested`] on `Stop`
    /// (Never). Installed via [`AgentLoopDriverImpl::with_restart_policy`].
    pub restart_policy: Option<RestartPolicy>,
    /// Wave-18 OPTIONAL crash-cascade sink. `None` for every `new()`/harness caller
    /// (byte-identical to the prior `handle_trap`); the cli composition root wires
    /// the production sink (cli `build_crash_cascade_sink`) via
    /// [`AgentLoopDriverImpl::with_crash_cascade`]. Invoked by `handle_trap` ONLY on
    /// `TrapError::Crash` (never `Cancelled`) — drives the cap-lifecycle
    /// `handle_crash` → `notify_parent_crash` parent-mailbox cascade (SYS-AC-030).
    pub crash_sink: Option<Arc<dyn CrashCascadeSink>>,
    /// Wave-19 OPTIONAL workspace-rollback sink (SYS-AC-028). `None` for every
    /// `new()`/harness caller (byte-identical to the prior loop); the cli composition root
    /// wires the production sink (cli `build_workspace_rollback_sink`) via
    /// [`AgentLoopDriverImpl::with_workspace_rollback`]. `run_turn_once` calls
    /// `mark_pre_turn` before `handle_message`; `handle_trap` calls `rollback_on_crash` ONLY
    /// on `TrapError::Crash` (never `Cancelled`) — reverts the child territory's committed
    /// subtree to the pre-turn state (forward-rollback-commit; MODULE-014 §3.8 (z)).
    pub workspace_rollback_sink: Option<Arc<dyn WorkspaceRollbackSink>>,
    /// AC-22 support: optional live-turn persistence boundary. `None` for all
    /// legacy constructors, so the existing agent loop remains unchanged unless
    /// the cli composition root wires this hook.
    pub turn_persistence_boundary: Option<Arc<dyn TurnPersistenceBoundary>>,
    /// CONTRACT-216 protected mailbox→Store lifecycle. `None` preserves every
    /// legacy reader/handler path; a protected envelope fails closed unless the
    /// CLI composition root installs this boundary.
    pub protected_turn_boundary: Option<Arc<dyn ProtectedTurnExecutionBoundary>>,
    /// MODULE-014-AC-25 (029) interior trap stop cell. `handle_trap` (which takes
    /// `&self` per CONTRACT-132) sets it on a `RestartDecision::Stop`; `serve` /
    /// `serve_n_turns` read it after each turn and break when set. Defaults `false`.
    stop_requested: Arc<AtomicBool>,
}

/// Cancellation-safe owner for one C216 turn after the dequeue guard crosses
/// `start_turn`. Until a terminal proof succeeds, dropping the scheduler future
/// synchronously poisons the Store and records `StoreDestroyed`; this covers
/// task abort while awaiting assembly, guest execution, dispatch, or postprocess.
struct ActiveProtectedTurn {
    identity: MailboxTurnIdentity,
    store_incarnation: [u8; 16],
    boundary: Arc<dyn ProtectedTurnExecutionBoundary>,
    handler: Arc<dyn MessageHandler>,
    armed: bool,
}

impl ActiveProtectedTurn {
    fn new(
        identity: MailboxTurnIdentity,
        store_incarnation: [u8; 16],
        boundary: Arc<dyn ProtectedTurnExecutionBoundary>,
        handler: Arc<dyn MessageHandler>,
    ) -> Self {
        Self {
            identity,
            store_incarnation,
            boundary,
            handler,
            armed: true,
        }
    }

    async fn finish_drained(&mut self) -> Result<(), HookError> {
        let epoch = self
            .handler
            .clear_trusted_turn(&self.identity.turn_id)
            .await?;
        self.boundary
            .finish_drained(&self.identity, self.store_incarnation, epoch)?;
        self.armed = false;
        Ok(())
    }

    async fn finish_destroyed(&mut self) -> Result<(), HookError> {
        self.handler
            .destroy_trusted_turn(&self.identity.turn_id)
            .await?;
        self.boundary
            .finish_store_destroyed(&self.identity, self.store_incarnation)?;
        self.armed = false;
        Ok(())
    }
}

impl Drop for ActiveProtectedTurn {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        // Never assert StoreDestroyed from a poison bit alone. The handler must
        // synchronously take/drop the reusable pair, or prove that cancellation
        // already dropped the guest future's owned pair, before C216 may retire
        // the running turn with a Store-destruction proof.
        if self
            .handler
            .destroy_trusted_turn_now(&self.identity.turn_id)
            .is_ok()
        {
            let _ = self
                .boundary
                .finish_store_destroyed(&self.identity, self.store_incarnation);
        }
        self.armed = false;
    }
}

impl AgentLoopDriverImpl {
    /// Slice C constructor: 6 arguments (Slice B had 5). Breaking change
    /// — in-tree callers (`tests/agent_loop_bootstrap.rs` + any
    /// constructions in new Slice C tests) are updated.
    pub fn new(
        mailbox_reader: Arc<dyn MailboxReader>,
        context_assembler: Arc<dyn ContextAssembler>,
        post_processor: Arc<dyn PostProcessorHook>,
        action_dispatcher: Arc<dyn AgentActionDispatcher>,
        run_bootstrap: Arc<dyn RunBootstrap>,
        message_handler: Arc<dyn MessageHandler>,
    ) -> Self {
        Self {
            mailbox_reader,
            context_assembler,
            post_processor,
            action_dispatcher,
            run_bootstrap,
            message_handler,
            turn_observer: None,
            model: String::new(),
            component_error_emitter: None,
            restart_policy: None,
            crash_sink: None,
            workspace_rollback_sink: None,
            turn_persistence_boundary: None,
            protected_turn_boundary: None,
            stop_requested: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Stage-C SAT-A opt-in builder — set the model id fed into each turn's
    /// `AssemblyContext.model`. The cli composition root resolves a CONCRETE
    /// provider model id (via `cap_llm::resolve_provider_and_model`) and installs
    /// it here so MODULE-010's `model_context_window` returns a real budget
    /// rather than the fail-safe-small default. Additive; existing `new()`
    /// callers (tests + `build_agent_loop` harness) keep the empty default.
    pub fn with_model(mut self, model: String) -> Self {
        self.model = model;
        self
    }

    /// Phase-2 Step-2 opt-in builder — wire a [`TurnObserver`] that is invoked at
    /// the end of every `serve` loop iteration. Without it, `serve` runs the loop
    /// with no per-turn callback (the single-turn `run_agent` path is unaffected
    /// either way). Mirrors the `AgentActionDispatcherImpl::with_outbound` opt-in
    /// pattern so existing 6-arg `new()` callers compile unchanged.
    pub fn with_turn_observer(mut self, observer: Arc<dyn TurnObserver>) -> Self {
        self.turn_observer = Some(observer);
        self
    }

    /// Phase-3 kickoff opt-in builder — replace the `run_bootstrap` supplied to
    /// `new()`. The driver calls `run_bootstrap.ensure_run` once at serve start
    /// (in `bootstrap_and_init`); the cli composition root uses this to install a
    /// real `RunManagerBootstrap` (which mints the session run + publishes its
    /// `RunId` into a shared cell) in place of the default `MinimalRunBootstrap`.
    /// Additive; existing callers (including the harness via `build_agent_loop`)
    /// keep their `new()`-supplied bootstrap.
    pub fn with_run_bootstrap(mut self, run_bootstrap: Arc<dyn RunBootstrap>) -> Self {
        self.run_bootstrap = run_bootstrap;
        self
    }

    /// Backbone Step 2 (2026-06-07) opt-in builder — replace the
    /// `context_assembler` supplied to `new()`. The cli composition root uses
    /// this to install a real `ContextAssemblerImpl` (wrapped in a
    /// `PublishingContextAssembler` that publishes the assembled layered context
    /// to the LLM gateway) in place of the default `MinimalContextAssembler`.
    /// Additive; existing callers (incl. the harness via `build_agent_loop`)
    /// keep their `new()`-supplied assembler. `run_turn_once` / the
    /// `MessageHandler` trait / CONTRACT-132 are UNCHANGED.
    pub fn with_context_assembler(mut self, context_assembler: Arc<dyn ContextAssembler>) -> Self {
        self.context_assembler = context_assembler;
        self
    }

    /// SAT-B (slice satB-postproc) opt-in builder — replace the `post_processor`
    /// supplied to `new()`. The cli composition root uses this to install the
    /// real components-backed `cap_memory::PostProcessor` (gated on
    /// `memory_store` + `llm_gateway` being present) in place of the default
    /// trace-only `PostProcessor::new()`. Additive; existing callers (incl. the
    /// harness via `build_agent_loop`) keep their `new()`-supplied post-processor,
    /// so the 9-step / synthetic-entry contract is unchanged for every test path.
    pub fn with_post_processor(mut self, post_processor: Arc<dyn PostProcessorHook>) -> Self {
        self.post_processor = post_processor;
        self
    }

    /// MODULE-014-AC-25 (029) opt-in builder — install the `component.error`
    /// EventBus emitter used by [`Self::handle_trap`]. Additive (mirrors
    /// `with_turn_observer`); existing `new()` callers keep `None` (no emit).
    pub fn with_component_error_emitter(mut self, emitter: Arc<dyn EventBusEmit>) -> Self {
        self.component_error_emitter = Some(emitter);
        self
    }

    /// MODULE-014-AC-25 (029) opt-in builder — install the trap `RestartPolicy`.
    /// Additive; `None` default preserves the infinite-serve-on-trap behaviour
    /// (a concrete `RestartPolicy::Never` default would instead Stop the loop —
    /// hence the `Option` gate). `Some(Never)` → serve loop breaks on a trap;
    /// `Some(OnFailure|Always)` → serve loop continues.
    pub fn with_restart_policy(mut self, policy: RestartPolicy) -> Self {
        self.restart_policy = Some(policy);
        self
    }

    /// Wave-18 opt-in builder — install the crash-cascade sink. Additive; `None`
    /// default leaves `handle_trap` byte-identical for every existing caller. When
    /// present, `handle_trap` invokes `sink.handle_crash(agent_id, reason)` ONLY on
    /// `TrapError::Crash` (never `Cancelled`). Mirrors the AC-25
    /// `with_component_error_emitter` / `with_restart_policy` Option-gated pattern.
    pub fn with_crash_cascade(mut self, sink: Arc<dyn CrashCascadeSink>) -> Self {
        self.crash_sink = Some(sink);
        self
    }

    /// Wave-19 opt-in builder — install the workspace-rollback sink (SYS-AC-028). Additive;
    /// `None` default leaves `run_turn_once` + `handle_trap` byte-identical for every existing
    /// caller. When present, `run_turn_once` calls `sink.mark_pre_turn(agent_id)` before
    /// `handle_message`, and `handle_trap` calls `sink.rollback_on_crash(agent_id)` ONLY on
    /// `TrapError::Crash` (never `Cancelled`). Mirrors the `with_crash_cascade` Option-gated
    /// pattern.
    pub fn with_workspace_rollback(mut self, sink: Arc<dyn WorkspaceRollbackSink>) -> Self {
        self.workspace_rollback_sink = Some(sink);
        self
    }

    /// AC-22 opt-in builder — install a turn persistence boundary. On success
    /// `finish_turn` runs after `handle_message` returns `Ok` and before
    /// dispatch/post-process. A `finish_turn` error is a persistence turn error:
    /// dispatch/post-process are skipped, prior guest state is kept, and the
    /// guest trap path is not invoked.
    pub fn with_turn_persistence_boundary(
        mut self,
        boundary: Arc<dyn TurnPersistenceBoundary>,
    ) -> Self {
        self.turn_persistence_boundary = Some(boundary);
        self
    }

    /// Install the jointly activated CONTRACT-216 execution boundary. The
    /// boundary is consulted only for envelopes carrying the move-only
    /// mailbox dequeue guard; legacy messages remain byte-identical.
    pub fn with_protected_turn_boundary(
        mut self,
        boundary: Arc<dyn ProtectedTurnExecutionBoundary>,
    ) -> Self {
        self.protected_turn_boundary = Some(boundary);
        self
    }

    /// Test-only accessor for the `AgentLoopDriver::handle_trap` trait method
    /// (Wave-18 crash-cascade Crash-vs-Cancelled discriminator). `run_turn_once` only
    /// ever surfaces `HookError::Failure` as `TrapError::Crash`, so the `Cancelled`
    /// arm is unreachable through the public serve API — a `test-support` test drives
    /// it here to prove the Crash-only `crash_sink` filter is load-bearing.
    #[cfg(feature = "test-support")]
    pub async fn handle_trap_for_test(&self, agent_id: &str, trap: TrapError) {
        self.handle_trap(agent_id, trap).await;
    }

    /// `ensure_run` (Slice B) + WIT `init(component-config) -> result<list<u8>,
    /// error>` (Slice C). Returns the initial agent `state` on success, or `None`
    /// after logging an `ensure_run` / `init` error. Shared by `run_agent`
    /// (single-turn) and `serve` (multi-turn) — both bootstrap + init exactly
    /// once; `serve` then loops, `run_agent` runs one turn.
    async fn bootstrap_and_init(
        &self,
        agent_id: &str,
        component_config: ComponentConfig,
    ) -> Option<Vec<u8>> {
        // Step 1: ensure a Run exists for this agent.
        if let Err(e) = self.run_bootstrap.ensure_run(agent_id).await {
            eprintln!(
                "AgentLoopDriverImpl: ensure_run failed for agent_id={:?}: {}",
                agent_id, e
            );
            return None;
        }
        // Step 2: WIT `init`. Consumes `component_config` by value (WIT semantics).
        match self.message_handler.init(component_config).await {
            Ok(s) => Some(s),
            Err(e) => {
                eprintln!(
                    "AgentLoopDriverImpl: init failed for agent_id={:?}: {}",
                    agent_id, e
                );
                None
            }
        }
    }

    /// Run ONE turn: recv → assemble → handle_message → dispatch → post_process.
    ///
    /// Returns the NEXT agent state, which `serve` threads into the following
    /// turn (cross-turn continuity). On any per-turn error it logs and returns
    /// the PRIOR `state` (WIT semantics: no new-state on error → keep prior),
    /// so a single bad turn never loses the last-good state nor kills the loop.
    ///
    /// Behaviour is byte-for-byte identical to the pre-Phase-2 single-turn
    /// `run_agent` pipeline on every path — INCLUDING the dispatch-error path,
    /// which returns WITHOUT running `post_process` (the old `run_agent`
    /// `return`ed there). `run_agent` calls this once (discarding the returned
    /// state); `serve` calls it in a loop.
    async fn run_turn_once(&self, agent_id: &str, state: Vec<u8>) -> Vec<u8> {
        // Step 3: receive the exact mailbox execution envelope. A protected
        // message keeps its move-only dequeue guard beside its identity until
        // immediately before guest execution; every pre-start early return lets
        // the guard's Drop perform exact abandon.
        let envelope = match self.mailbox_reader.recv_turn(agent_id).await {
            Ok(envelope) => envelope,
            Err(error) => {
                eprintln!(
                    "AgentLoopDriverImpl::run_turn_once: protected recv failed for agent_id={agent_id:?}: {error:?}"
                );
                return state;
            }
        };
        let (mut msg, turn_identity, mut dequeued_turn) = envelope.into_parts();
        if turn_identity.is_some() != dequeued_turn.is_some() {
            eprintln!(
                "AgentLoopDriverImpl::run_turn_once: incomplete protected envelope for agent_id={agent_id:?}"
            );
            return state;
        }
        // CONTRACT-216 admission is the first execution-side operation after
        // envelope shape validation. In particular, protected start precedes
        // trace mutation, context assembly, persistence hooks, rollback marks,
        // or any reusable Store access. Once start returns Execute, install the
        // active RAII owner before the first await; every later early return or
        // cancellation must therefore destroy the exact Store incarnation.
        let mut protected_turn = if let Some(identity) = turn_identity.as_ref() {
            let Some(boundary) = self.protected_turn_boundary.as_ref().cloned() else {
                eprintln!(
                    "AgentLoopDriverImpl::run_turn_once: protected turn boundary unavailable for agent_id={agent_id:?}"
                );
                return state;
            };
            let Some(store_incarnation) = self
                .message_handler
                .trusted_store_incarnation()
                .filter(|value| *value != [0; 16])
            else {
                eprintln!(
                    "AgentLoopDriverImpl::run_turn_once: protected Store incarnation unavailable for agent_id={agent_id:?}"
                );
                return state;
            };
            let guard = dequeued_turn
                .take()
                .expect("protected envelope shape checked before execution");
            match boundary.begin(identity, guard) {
                Ok(TurnStartOutcome::DoNotExecute) => return state,
                Err(error) => {
                    eprintln!(
                        "AgentLoopDriverImpl::run_turn_once: protected turn start failed for agent_id={agent_id:?}: {error}"
                    );
                    return state;
                }
                Ok(TurnStartOutcome::Execute) => {
                    let mut active = ActiveProtectedTurn::new(
                        identity.clone(),
                        store_incarnation,
                        boundary,
                        Arc::clone(&self.message_handler),
                    );
                    // This arms only host-owned trusted identity state. The
                    // concrete Store is taken synchronously by handle_message
                    // and stamped immediately before call_handle_message.
                    if let Err(error) = self
                        .message_handler
                        .stamp_trusted_turn(&identity.turn_id)
                        .await
                    {
                        let _ = active.finish_destroyed().await;
                        eprintln!(
                            "AgentLoopDriverImpl::run_turn_once: trusted turn stamp failed for agent_id={agent_id:?}: {error}"
                        );
                        return state;
                    }
                    Some(active)
                }
            }
        } else {
            None
        };
        // Stage-F obs SLICE 1 — establish the per-chain `trace_id` at the universal
        // inbound admission point (right after recv, BEFORE the `msg.clone()` into
        // `AssemblyContext` and the `&msg` into `handle_message`). `ensure_chain_trace`
        // inherits an existing trace (reply/threaded chain) or mints a fresh per-fire
        // one, writing it onto `msg.context` so every downstream emitter of this turn
        // (context.assembled, the re-stamped cap events, run.round_completed) shares it.
        // Production inbound (POST /msg / channel pump) delivers `context: None` and
        // bypasses the dispatcher, so this is the ONLY universal mint point.
        let _chain_trace_id = advance_shared_types::mailbox::ensure_chain_trace(&mut msg);
        // `msg.context: Option<MessageContext>` — Option-aware access.
        let task_id_opt = msg.context.as_ref().and_then(|c| c.task_id.clone());
        let run_id_opt = msg.context.as_ref().and_then(|c| c.run_id.clone());
        // Step 4: build the full 7-field canonical `AssemblyContext`. Stage-C
        // SAT-A fills the live-turn fields the assembler needs: `prompt` = the
        // real user turn text decoded from `msg.payload` (64 KiB-capped — see
        // `prompt_from_payload`; §3.8 (b)), `model` = the driver's configured
        // model id (`with_model`; empty default → harness-neutral). `turn_buffer`
        // STAYS empty — there is no in-process per-turn history store; the
        // multi-source history reaches the prompt via MODULE-010's `assemble()`
        // L0-L6 digest fold, not `turn_buffer`. `prior_state: AgentState` is the
        // host-side rehydration record, DISTINCT from the `state: Vec<u8>`
        // WASM-managed payload. `iteration` / `turn_counter` stay 0.
        let ctx = AssemblyContext {
            agent_id: agent_id.to_string(),
            task_id: task_id_opt.clone(),
            message: msg.clone(),
            prompt: prompt_from_payload(&msg.payload),
            model: self.model.clone(),
            turn_buffer: Vec::new(),
            prior_state: AgentState {
                agent_id: agent_id.to_string(),
                status: AgentStatus::Active,
                current_task_id: task_id_opt,
                current_run_id: run_id_opt,
                iteration: 0,
                turn_counter: 0,
                last_handle_message_at: None,
            },
        };
        // `AssemblyResult.messages` intentionally discarded (no llm.generate
        // wiring yet — §3.8 (b)). On error, keep prior state and continue.
        if let Err(e) = self.context_assembler.assemble(ctx).await {
            eprintln!(
                "AgentLoopDriverImpl::run_turn_once: assemble failed for agent_id={:?}: {:?}",
                agent_id, e
            );
            return state;
        }
        // Wave-19 (SYS-AC-028): record the agent territory's pre-turn HEAD BEFORE the guest
        // can write any file, so a mid-turn trap can roll the committed subtree back to it.
        // `None` (every existing caller) = no-op, byte-identical.
        if let Some(sink) = self.workspace_rollback_sink.as_ref() {
            sink.mark_pre_turn(agent_id);
        }
        let turn_lease = match self.turn_persistence_boundary.as_ref() {
            Some(boundary) => match boundary.begin_turn(agent_id, &msg).await {
                Ok(lease_id) => Some(lease_id),
                Err(e) => {
                    let reason = format!("turn persistence begin failed: {e}");
                    emit_component_error(
                        self.component_error_emitter.as_ref(),
                        agent_id,
                        "turn-persistence",
                        &reason,
                    );
                    eprintln!(
                        "AgentLoopDriverImpl::run_turn_once: {reason} for agent_id={agent_id:?}"
                    );
                    return state;
                }
            },
            None => None,
        };
        // Step 5: WIT `handle-message(msg, state)` — EXACTLY 2 WIT-mapped args
        // (structurally enforced by the trait signature). `state.clone()` so the
        // prior value survives a `handle_message` error (the error arms return it).
        match self
            .message_handler
            .handle_message(&msg, state.clone())
            .await
        {
            Ok(action_result) => {
                if let (Some(boundary), Some(lease_id)) =
                    (self.turn_persistence_boundary.as_ref(), turn_lease.as_ref())
                {
                    if let Err(e) = boundary.finish_turn(agent_id, lease_id).await {
                        if let Some(active) = protected_turn.as_mut() {
                            let _ = active.finish_destroyed().await;
                        }
                        let reason = format!("turn persistence finalizer failed: {e}");
                        emit_component_error(
                            self.component_error_emitter.as_ref(),
                            agent_id,
                            "turn-persistence",
                            &reason,
                        );
                        eprintln!(
                            "AgentLoopDriverImpl::run_turn_once: {reason} for agent_id={agent_id:?}"
                        );
                        return state;
                    }
                }
                // Step 6: dispatch. M006's dispatcher internally invokes the
                // ActionValidator (CONTRACT-113) gate per ARCH §4.2. On error,
                // log + return `new_state` WITHOUT post_process — preserving the
                // pre-Phase-2 `run_agent` dispatch-error early-return EXACTLY.
                // Step-3 (CONTRACT-051 seam extension): pass the source inbound
                // `msg` so the in-host channel reply path can build a per-message
                // `OutboundTarget` from `msg.origin.channel_metadata`. The
                // returned `DeliveryReport` is not consumed on the daemon path
                // (Step-3 ships only `Delivered`); the dispatch-error early-return
                // stays byte-identical.
                if let Err(e) = self
                    .action_dispatcher
                    .dispatch(agent_id, &msg, &action_result.actions)
                    .await
                {
                    if let Some(active) = protected_turn.as_mut() {
                        if let Err(finish_error) = active.finish_drained().await {
                            eprintln!(
                                "AgentLoopDriverImpl::run_turn_once: protected turn finalizer failed for agent_id={agent_id:?}: {finish_error}"
                            );
                            return state;
                        }
                    }
                    eprintln!(
                        "AgentLoopDriverImpl::run_turn_once: dispatch failed for agent_id={:?}: {:?}",
                        agent_id, e
                    );
                    return action_result.new_state;
                }
                // Step 7: post-process (happy path). Error swallowed via `let _`.
                let _ = self
                    .post_processor
                    .run(agent_id, &msg, &action_result)
                    .await;
                if let Some(active) = protected_turn.as_mut() {
                    if let Err(error) = active.finish_drained().await {
                        eprintln!(
                            "AgentLoopDriverImpl::run_turn_once: protected turn finalizer failed for agent_id={agent_id:?}: {error}"
                        );
                        return state;
                    }
                }
                action_result.new_state
            }
            Err(HookError::Failure(reason)) => {
                if let (Some(boundary), Some(lease_id)) =
                    (self.turn_persistence_boundary.as_ref(), turn_lease.as_ref())
                {
                    boundary.abort_turn(agent_id, lease_id, &reason).await;
                }
                if let Some(active) = protected_turn.as_mut() {
                    if let Err(error) = active.finish_destroyed().await {
                        eprintln!(
                            "AgentLoopDriverImpl::run_turn_once: protected trap finalizer failed for agent_id={agent_id:?}: {error}"
                        );
                    }
                }
                // Trap-equivalent failure → handle_trap; keep prior state.
                self.handle_trap(agent_id, TrapError::Crash(reason)).await;
                state
            }
            Err(e) => {
                if let (Some(boundary), Some(lease_id)) =
                    (self.turn_persistence_boundary.as_ref(), turn_lease.as_ref())
                {
                    boundary
                        .abort_turn(agent_id, lease_id, &e.to_string())
                        .await;
                }
                if let Some(active) = protected_turn.as_mut() {
                    if let Err(error) = active.finish_destroyed().await {
                        eprintln!(
                            "AgentLoopDriverImpl::run_turn_once: protected cancellation finalizer failed for agent_id={agent_id:?}: {error}"
                        );
                    }
                }
                eprintln!(
                    "AgentLoopDriverImpl::run_turn_once: handle_message error for agent_id={:?}: {}",
                    agent_id, e
                );
                state
            }
        }
    }

    /// Phase-2 Step-2 serving loop — the internalized canonical MODULE-014
    /// §1.4.1 multi-turn loop. `bootstrap` + `init` ONCE, then loop
    /// `run_turn_once`, threading `new_state` across turns in-process.
    ///
    /// Infinite: there is no mailbox-close primitive (`MailboxStore` exposes
    /// none), so the loop exits ONLY when the spawned task is aborted (the
    /// production daemon's shutdown `handle.abort()`). The optional
    /// [`TurnObserver`] fires at EVERY turn boundary (a successful turn OR a
    /// handled error/trap) so the daemon can resolve a no-reply turn's
    /// `POST /msg` correlation slot + clear its single-in-flight guard without
    /// waiting for the reply timeout.
    ///
    /// Known limitation: the daemon's `WasmMessageHandler` reuses ONE Wasmtime
    /// `Store` across turns; a guest trap poisons it, so after the first trap
    /// every turn fails instantly (perpetual-error) with no auto-recovery.
    /// Restart-on-trap is the daemon restart-policy's job (§1.4.2b / AC-21).
    pub async fn serve(
        &self,
        agent_id: &str,
        component_config: ComponentConfig,
        _instance: WasmInstance,
    ) {
        let mut state = match self.bootstrap_and_init(agent_id, component_config).await {
            Some(s) => s,
            None => return,
        };
        loop {
            state = self.run_turn_once(agent_id, state).await;
            if let Some(observer) = &self.turn_observer {
                observer.on_turn_complete(agent_id);
            }
            // MODULE-014-AC-25 (029): a guest trap under `RestartPolicy::Never`
            // (→ `RestartDecision::Stop`) sets the stop cell in `handle_trap`;
            // break the serve loop. `Restart` (OnFailure/Always) and the `None`
            // default leave the cell clear → the loop continues (unchanged).
            if self.stop_requested.load(Ordering::SeqCst) {
                break;
            }
        }
    }

    /// Backbone Step 4 — the BOUNDED sibling of [`Self::serve`]: `bootstrap` +
    /// `init` ONCE, then run EXACTLY `n` turns via the shared `run_turn_once`
    /// helper (threading `new_state` across turns identically to `serve`), then
    /// RETURN. The optional [`TurnObserver`] fires at every turn boundary, as in
    /// `serve`. This is NOT a separate loop: it shares the identical private
    /// `bootstrap_and_init` + `run_turn_once` machinery, so `run_agent`(1 turn) /
    /// `serve_n_turns`(bounded `n`) / `serve`(∞) are the three members of the same
    /// per-turn pipeline.
    ///
    /// Synchronous + abort-free: it returns after `n` turns rather than parking
    /// the infinite `serve` loop, so a caller holding the driver by value (e.g.
    /// the system-acceptance `SystemUnderTest`, whose `run_turns(&self)` can only
    /// BORROW its owned driver and cannot spawn-move `serve`) can drive a real
    /// multi-turn run on one persistent loop and assert after it returns.
    ///
    /// Recv contract: each turn's first action is `mailbox_reader.recv(agent_id)`,
    /// which AWAITS a message. The caller MUST enqueue at least `n` messages
    /// before (or concurrently with) the call, or the `n`-th turn parks forever.
    /// Same Wasmtime-Store-reuse trap caveat as `serve` applies.
    ///
    /// **`test-support`-gated**: this bounded driver exists ONLY for the
    /// system-acceptance harness + the scheduler unit test. The production daemon
    /// spawns the infinite `serve` (with an abortable task + cancellation), never
    /// `serve_n_turns`, so the bounded, unbounded-`n`, cancellation-less loop is
    /// excluded from a targeted `cargo build -p advance-cli` daemon binary.
    #[cfg(feature = "test-support")]
    pub async fn serve_n_turns(
        &self,
        agent_id: &str,
        component_config: ComponentConfig,
        _instance: WasmInstance,
        n: usize,
    ) {
        let mut state = match self.bootstrap_and_init(agent_id, component_config).await {
            Some(s) => s,
            None => return,
        };
        for _ in 0..n {
            state = self.run_turn_once(agent_id, state).await;
            if let Some(observer) = &self.turn_observer {
                observer.on_turn_complete(agent_id);
            }
            // MODULE-014-AC-25 (029): honor the same trap stop cell as `serve` so
            // a `RestartPolicy::Never` trap ends the bounded run early (and the
            // test-support driver witnesses the policy-driven break — T-029b).
            if self.stop_requested.load(Ordering::SeqCst) {
                break;
            }
        }
    }
}

#[async_trait]
impl AgentLoopDriver for AgentLoopDriverImpl {
    async fn run_agent(
        &self,
        agent_id: &str,
        component_config: ComponentConfig,
        _instance: WasmInstance,
    ) {
        // Single-turn-per-call primitive (CONTRACT-132) — UNCHANGED behaviour.
        // bootstrap + init once, then ONE turn via the shared `run_turn_once`
        // helper, then return. The system-acceptance harness `run_turn()` + the
        // AC-15 pipeline test depend on this returning after one turn; the
        // multi-turn serving loop lives in `serve` (Phase-2 Step-2). The
        // single-turn path does NOT invoke `turn_observer`.
        let state = match self.bootstrap_and_init(agent_id, component_config).await {
            Some(s) => s,
            None => return,
        };
        // Single turn: the returned next-state is discarded.
        let _ = self.run_turn_once(agent_id, state).await;
    }

    async fn handle_trap(&self, agent_id: &str, trap: TrapError) {
        // MODULE-014-AC-25 (029): on a guest trap, (1) emit a `component.error`
        // EventBus event via the optional injected emitter (no-op when `None` —
        // every `new()`/harness caller), and (2) apply the configured RestartPolicy
        // by computing `restart_decision(policy, succeeded=false)` and requesting a
        // serve-loop stop on `RestartDecision::Stop` (Never). `handle_trap` returns
        // `()` (CONTRACT-132 unchanged), so the decision is surfaced to `serve` /
        // `serve_n_turns` via the interior `stop_requested` cell. The daemon's
        // exponential-backoff restart ladder (AC-21) is a separate concern and is
        // NOT duplicated here. The Slice-B eprintln diagnostic is retained for
        // local-dev visibility (production redaction per §3.8 (b)).
        let reason = match &trap {
            TrapError::Crash(r) => r.as_str(),
            TrapError::Cancelled => "cancelled",
        };
        emit_component_error(
            self.component_error_emitter.as_ref(),
            agent_id,
            "agent",
            reason,
        );
        if let Some(policy) = self.restart_policy {
            if matches!(restart_decision(policy, false), RestartDecision::Stop) {
                self.stop_requested.store(true, Ordering::SeqCst);
            }
        }
        // Wave-18: drive the crash-cascade sink ONLY on a real crash (NOT a
        // cooperative `Cancelled`), and only when one is wired (`None` = byte-identical
        // to the prior behaviour). The cli `build_crash_cascade_sink` impl bridges this
        // colon-keyed `agent_id` to the bare-keyed cap-lifecycle tree + drives
        // `handle_crash` → `notify_parent_crash` (parent mailbox `component.terminated`).
        if let (TrapError::Crash(r), Some(sink)) = (&trap, self.crash_sink.as_ref()) {
            sink.handle_crash(agent_id, r.as_str());
        }
        // Wave-19 (SYS-AC-028): roll the child workspace back to the marked pre-turn commit
        // ONLY on a real crash (NOT a cooperative `Cancelled`), and only when a sink is wired
        // (`None` = byte-identical). The cli `build_workspace_rollback_sink` impl reverts the
        // child territory's committed subtree to the pre-turn state (forward-rollback-commit).
        // AFTER the crash cascade so the parent crash-report (030) is delivered regardless.
        if let (TrapError::Crash(_), Some(sink)) = (&trap, self.workspace_rollback_sink.as_ref()) {
            sink.rollback_on_crash(agent_id).await;
        }
        eprintln!(
            "AgentLoopDriverImpl::handle_trap: trap surfaced — agent_id={:?}, trap={:?}",
            agent_id, trap
        );
    }
}

/// Stage-C SAT-A: `AssemblyContext.prompt` cap (advisory ≤ 64 KiB per
/// `shared-types/src/context.rs`). Mailbox `Message.payload` can be up to ~1 MiB
/// (MODULE-006 prose), so cap BEFORE materializing the prompt.
const MAX_PROMPT_BYTES: usize = 64 * 1024;

/// Decode `msg.payload` into the turn's user prompt, bounded to ≤ 64 KiB. Byte-cap
/// FIRST (slice ≤ 64 KiB raw bytes — `from_utf8_lossy` maps any split multibyte
/// char at the cut to U+FFFD), then char-cap the decoded `String` to ≤ 64 KiB
/// bytes (lossy U+FFFD expansion — 3 bytes per invalid byte — can otherwise push
/// the decoded length back over the cap). A non-UTF-8 payload degrades to a
/// lossy-decoded prompt rather than failing the turn.
fn prompt_from_payload(payload: &[u8]) -> String {
    let head = if payload.len() > MAX_PROMPT_BYTES {
        &payload[..MAX_PROMPT_BYTES]
    } else {
        payload
    };
    let mut s = String::from_utf8_lossy(head).into_owned();
    if s.len() > MAX_PROMPT_BYTES {
        let mut end = MAX_PROMPT_BYTES;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        s.truncate(end);
    }
    s
}

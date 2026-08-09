//! Scheduler-crate-local hook traits.
//!
//! Slice B established the pattern with `RunnableHook` (abstracts WASM
//! `instance.call_run`) and `RunBootstrap` (abstracts M008
//! `RunManager::ensure_run`).
//!
//! Slice C extends with 4 more scheduler-local traits that follow the
//! same in-crate plug-in pattern (NO new compile-time dependencies on
//! other workspace crates — keeps the M014-trait-inversion posture from
//! MODULE-014 §2.2 intact):
//! - `MessageHandler` — abstracts WASM `instance.call_init` +
//!   `call_handle_message(msg, state)` (2-arg WIT-faithful) for the
//!   agent-loop driver's full message pipeline (AC-15).
//! - `RuntimeReadiness` — abstracts the M001 runtime-ready probe.
//!   `Scheduler::start_with_readiness` consults this trait to fail-fast
//!   when HostRegistry reports not-ready (AC-20). Real HostRegistry-backed
//!   adapter lives in a follow-up wiring slice.
//! - `FileWatchSource` + `WebhookSource` — pluggable trigger event
//!   producers wired through `trigger_source.rs::FileWatchTriggerSource`
//!   / `WebhookTriggerSource` per AC-14. Real notify-crate + HTTP-listener
//!   impls are follow-up slices.

use std::sync::Arc;

use async_trait::async_trait;
use thiserror::Error;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use advance_shared_types::capability::CapRequest;
use advance_shared_types::component::ComponentType;
use advance_shared_types::mailbox::{
    ActionResult, DequeuedTurnGuard, MailboxTurnIdentity, Message,
};
use advance_shared_types::turn_attribution::TurnStartOutcome;

use crate::trigger_source::TriggerFireEvent;
use crate::types::{ComponentConfig, RunResult, WebhookConfig};

/// Failures returned by `RunnableHook::run_once`.
#[derive(Debug, Error)]
pub enum HookError {
    #[error("hook failure: {0}")]
    Failure(String),
    #[error("cancelled")]
    Cancelled,
}

/// Slice B abstraction over `WasmInstance::call_run(component_config)`.
///
/// Implementations are responsible for:
/// - WASM instance load + capability injection (the MODULE-001 wiring
///   is declared in `waived_scope` as part of the AC-13/14/15/19
///   driver-loop scaffolding)
/// - Per-call timeout / cancellation
/// - Mapping host errors to `HookError::Failure(reason)` or
///   `HookError::Cancelled`
///
/// Production: backed by the runtime crate's `wasmtime::component::Instance`
/// holder. Tests: mock impl that records invocations and returns a canned
/// `RunResult`.
#[async_trait]
pub trait RunnableHook: Send + Sync {
    async fn run_once(&self, config: ComponentConfig) -> Result<RunResult, HookError>;
}

/// Failures returned by `RunBootstrap::ensure_run`.
#[derive(Debug, Error)]
pub enum BootstrapError {
    #[error("ensure_run failed: {0}")]
    EnsureRun(String),
}

/// Slice B abstraction over MODULE-008 `RunManager::ensure_run`.
///
/// **Signature rationale** (Round-1 Warning-2 fix): takes ONLY
/// `controller_agent`, NOT a separate `task_id`. The Slice A `ComponentConfig.id`
/// is the COMPONENT identifier (agent_id for agents), NOT the M008 `task_id`.
/// Conflating the two would cause M008's `AgentRunResolver` ambiguity fallback
/// to fire spuriously. The implementation is responsible for deriving
/// `task_id` from its own context (e.g. looking up the agent's task
/// assignment in agent-tree).
///
/// Returns the stable RunId as a `String` to keep the type boundary
/// opaque at the trait surface — the scheduler does not depend on the
/// M008 internal `RunId` newtype, only on its stringified form. A
/// typed-newtype tightening is only justified once a caller actually
/// needs to round-trip the RunId across a typed boundary; today the
/// only caller logs/forwards it as a string.
///
/// Idempotency invariant (M008 §1.3.2): repeated calls with the same
/// controller_agent + live task return the same RunId.
#[async_trait]
pub trait RunBootstrap: Send + Sync {
    async fn ensure_run(&self, controller_agent: &str) -> Result<String, BootstrapError>;
}

// ---- Slice C additions ----

/// Slice C abstraction over WASM `instance.call_init` +
/// `instance.call_handle_message`. The trait signatures mirror PRD §3.3
/// WIT exactly:
/// - `init(config: component-config) -> result<list<u8>, error>` →
///   `init(&self, config: ComponentConfig) -> Result<Vec<u8>, HookError>`
/// - `handle-message(msg: message, state: list<u8>) -> result<action-result, error>`
///   → `handle_message(&self, msg: &Message, state: Vec<u8>) ->
///   Result<ActionResult, HookError>`
///
/// **2-arg WIT compliance**: `handle_message` takes EXACTLY 2 WIT-mapped
/// params (msg + state). The `&self` is host-side dispatch context; the
/// `agent_id` lives on the caller (`AgentLoopDriverImpl::run_agent`) and
/// is not a WIT arg.
///
/// Production: backed by the runtime crate's
/// `wasmtime::component::Instance` holder (the same plug-in point as
/// `RunnableHook`). Tests: mock impl recording invocations + returning
/// canned `Vec<u8>` / `ActionResult`.
#[async_trait]
pub trait MessageHandler: Send + Sync {
    async fn init(&self, config: ComponentConfig) -> Result<Vec<u8>, HookError>;
    async fn handle_message(
        &self,
        msg: &Message,
        state: Vec<u8>,
    ) -> Result<ActionResult, HookError>;

    /// Return the non-zero incarnation of the reusable guest Store. Protected
    /// turns query this before crossing the allocation-free C216 start commit,
    /// so any later stamp failure can still retire the exact running turn as a
    /// destroyed Store. Legacy handlers intentionally return `None`.
    fn trusted_store_incarnation(&self) -> Option<[u8; 16]> {
        None
    }

    /// Stamp the host-authenticated turn id into the Store immediately before
    /// guest execution. The default fails closed if a protected envelope is
    /// ever routed to a legacy handler.
    async fn stamp_trusted_turn(&self, _turn_id: &str) -> Result<(), HookError> {
        Err(HookError::Failure(
            "protected turn store stamping unavailable".to_string(),
        ))
    }

    /// Clear a normally completed turn after dispatch and post-processing have
    /// settled, returning the monotonic Store-drain epoch used by C216.
    async fn clear_trusted_turn(&self, _turn_id: &str) -> Result<u64, HookError> {
        Err(HookError::Failure(
            "protected turn store clearing unavailable".to_string(),
        ))
    }

    /// Destroy the Store on trap/error/cancel before C216 publishes its exact
    /// `StoreDestroyed` proof.
    async fn destroy_trusted_turn(&self, _turn_id: &str) -> Result<(), HookError> {
        Err(HookError::Failure(
            "protected turn store destruction unavailable".to_string(),
        ))
    }

    /// Cancellation-safe synchronous destruction boundary. Dropping an
    /// in-flight scheduler future cannot await Store destruction, so a real
    /// protected handler must synchronously take and drop any reusable Store
    /// (or verify that the cancelled guest future already dropped its owned
    /// Store) before returning `Ok`. The scheduler may publish
    /// `StoreDestroyed` only after this method succeeds.
    fn destroy_trusted_turn_now(&self, _turn_id: &str) -> Result<(), HookError> {
        Err(HookError::Failure(
            "synchronous protected Store destruction unavailable".to_string(),
        ))
    }
}

/// Scheduler-local inversion seam for CONTRACT-216 execution. The concrete
/// adapter lives at the CLI composition root, keeping MODULE-014 independent
/// of the messaging implementation crate. Completion methods also forward any
/// opaque source-quiesced receipt to C215 before returning.
pub trait ProtectedTurnExecutionBoundary: Send + Sync {
    fn begin(
        &self,
        identity: &MailboxTurnIdentity,
        guard: DequeuedTurnGuard,
    ) -> Result<TurnStartOutcome, HookError>;

    fn finish_drained(
        &self,
        identity: &MailboxTurnIdentity,
        store_incarnation: [u8; 16],
        store_epoch: u64,
    ) -> Result<(), HookError>;

    fn finish_store_destroyed(
        &self,
        identity: &MailboxTurnIdentity,
        store_incarnation: [u8; 16],
    ) -> Result<(), HookError>;
}

/// Phase-2 Step-2 optional per-turn boundary observer for the serving loop.
///
/// `AgentLoopDriverImpl::serve` calls `on_turn_complete` at the END of EVERY
/// serving-loop iteration — after `dispatch` + `post_process` on a successful
/// turn, OR after a handled `assemble` / `handle_message` / `dispatch` error or
/// trap — regardless of outcome. The daemon (MODULE-001 composition root) wires
/// an impl that uses this boundary to (a) resolve a no-reply turn's `POST /msg`
/// correlation slot WITHOUT waiting for the reply timeout, and (b) clear its
/// single-in-flight guard so the next serial POST proceeds.
///
/// Same scheduler-crate-LOCAL in-crate plug-in pattern as `RunBootstrap` /
/// `MessageHandler` (NOT a shared `CONTRACT-*`, NO new compile-time dependency on
/// other workspace crates — keeps the MODULE-014 §2.2 trait-inversion posture).
/// The single-turn `run_agent` primitive does NOT invoke it; it is a serving-loop
/// concern only.
pub trait TurnObserver: Send + Sync {
    fn on_turn_complete(&self, agent_id: &str);
}

/// Optional persistence boundary for live agent turns.
///
/// This scheduler-local seam brackets `MessageHandler::handle_message` without
/// changing CONTRACT-132. A capability can use it to begin a durable turn lease,
/// finalize staged host-function side effects before dispatch/post-process, and
/// abort staged state when the guest fails before finalization.
#[async_trait]
pub trait TurnPersistenceBoundary: Send + Sync {
    async fn begin_turn(&self, agent_id: &str, msg: &Message) -> Result<String, HookError>;
    async fn finish_turn(&self, agent_id: &str, lease_id: &str) -> Result<(), HookError>;
    async fn abort_turn(&self, agent_id: &str, lease_id: &str, reason: &str);
}

/// Wave-18 optional crash-cascade out-seam for `AgentLoopDriverImpl::handle_trap`.
///
/// When a served agent's guest traps mid-turn (`TrapError::Crash`), `handle_trap`
/// — AFTER its existing `component.error` emit + restart-policy decision — invokes
/// `handle_crash(agent_id, reason)` on this sink IF one is wired (the field is
/// `Option`; `None` = byte-identical to the prior `handle_trap`). It is NOT invoked
/// on a cooperative `TrapError::Cancelled` (a cancel is not a crash; a parent
/// crash-report on cancel would be a false alarm).
///
/// Same scheduler-crate-LOCAL in-crate plug-in pattern as `TurnObserver` /
/// `RunBootstrap` / `MessageHandler` (NOT a shared `CONTRACT-*`, NO new compile-time
/// dependency on other workspace crates — keeps the MODULE-014 §2.2 trait-inversion
/// posture). The sole production impl is the cli `build_crash_cascade_sink`, which
/// bridges the scheduler's colon-keyed `agent_id` to the cap-lifecycle bare-keyed
/// `AgentTreeStore` and drives the real `DefaultTerminateController::handle_crash`
/// → `notify_parent_crash` cascade (MODULE-001 §3.7/§3.8, MODULE-005 §3.7).
pub trait CrashCascadeSink: Send + Sync {
    fn handle_crash(&self, agent_id: &str, reason: &str);
}

/// Wave-19 optional workspace-rollback out-seam for `AgentLoopDriverImpl` (SYS-AC-028).
///
/// On each served turn, `run_turn_once` calls `mark_pre_turn(agent_id)` BEFORE
/// `handle_message` (the sink records the agent territory's pre-turn HEAD); and when a
/// guest traps mid-turn (`TrapError::Crash`), `handle_trap` — AFTER the crash cascade —
/// invokes `rollback_on_crash(agent_id)` to revert the agent's committed workspace subtree
/// to that recorded pre-turn state. The field is `Option`; `None` = byte-identical to the
/// prior loop. NOT invoked on a cooperative `TrapError::Cancelled`.
///
/// Same scheduler-crate-LOCAL in-crate plug-in pattern as `CrashCascadeSink` (NOT a shared
/// `CONTRACT-*`, NO new compile-time dependency on other workspace crates — keeps the
/// MODULE-014 §2.2 trait-inversion posture). The sole production impl is the cli
/// `build_workspace_rollback_sink` (forward-rollback-commit: reverts the child subtree via
/// CONTRACT-021 `WorkspaceRollback` + a per-written-dir `.meta.yaml` removal (content-empty dirs;
/// fail-safe-keep otherwise) + a compensating non-`[turn]`
/// commit over the shared queue, so the child territory's full committed subtree == pre-turn;
/// MODULE-014 §3.8 (z), MODULE-001 §3.7).
#[async_trait]
pub trait WorkspaceRollbackSink: Send + Sync {
    /// Record the agent territory's pre-turn HEAD (called before `handle_message`). Sync +
    /// best-effort: a failed read is the sink's own concern — a subsequent `rollback_on_crash`
    /// with no recorded marker no-ops.
    fn mark_pre_turn(&self, agent_id: &str);
    /// Roll the agent's workspace back to the recorded pre-turn state (called on `Crash`).
    /// Best-effort; must NOT panic the serve loop.
    async fn rollback_on_crash(&self, agent_id: &str);
}

/// Slice C abstraction over the M001 runtime-ready probe.
/// `Scheduler::start_with_readiness(probe)` consults this trait to
/// fail-fast when HostRegistry reports not-ready (AC-20). The real
/// HostRegistry-backed adapter lives in a follow-up wiring slice; the
/// scheduler crate does NOT take a compile-time `advance-runtime` dep
/// (preserves the M014-trait-inversion posture).
#[async_trait]
pub trait RuntimeReadiness: Send + Sync {
    async fn is_ready(&self) -> bool;
}

/// Slice C pluggable filesystem-notification source. Producer side of
/// `FileWatchTriggerSource` per AC-14. A real notify-crate-backed impl
/// is a follow-up supply-chain-review concern; Slice C ships only the
/// trait surface + test-mock impl pattern.
///
/// Invocation contract: producer task sends `TriggerFireEvent` records to
/// `tx` whenever a filesystem event matching `glob` arrives. Cancellation
/// via the shared `CancellationToken`. Returns `Err(HookError)` on
/// non-cancel terminal failure (e.g. inotify setup error).
#[async_trait]
pub trait FileWatchSource: Send + Sync {
    async fn run(
        &self,
        glob: String,
        tx: mpsc::Sender<TriggerFireEvent>,
        cancel: CancellationToken,
    ) -> Result<(), HookError>;
}

/// Stage-F obs SLICE 3 — scheduler-local seam for the component-type circuit
/// breaker (SYS-AC-228). Trait inversion: the scheduler consults this gate at the
/// `ComponentMaterializer::materialize` dispatch path WITHOUT a compile-time
/// `advance-runtime` dependency (the concrete `DefaultCircuitBreakerBus`-backed
/// adapter lives at the cli composition root). Mirrors the
/// `RuntimeReadiness`/`FileWatchSource`/`WebhookSource` seam pattern.
///
/// `is_open_component_type(kind)` returns `Some(reason)` when a breaker of
/// scope=component-type is OPEN for `kind` (that type's dispatch is blocked /
/// fails-closed while other component types proceed), or `None` to allow.
/// Sync (a non-blocking in-memory query — no `async_trait`).
pub trait ComponentTypeBreakerGate: Send + Sync {
    fn is_open_component_type(&self, kind: ComponentType) -> Option<String>;
}

/// Slice C pluggable HTTP-listener source. Producer side of
/// `WebhookTriggerSource` per AC-14. A real axum/hyper-backed impl is a
/// follow-up slice; Slice C ships only the trait surface + test-mock
/// impl pattern.
///
/// Invocation contract: producer task listens on the webhook endpoint
/// specified in `cfg.path`, validates HMAC against `cfg.secret`, and
/// sends a `TriggerFireEvent` per accepted POST. Cancellation via the
/// shared `CancellationToken`.
#[async_trait]
pub trait WebhookSource: Send + Sync {
    async fn run(
        &self,
        cfg: WebhookConfig,
        tx: mpsc::Sender<TriggerFireEvent>,
        cancel: CancellationToken,
    ) -> Result<(), HookError>;
}

// ---- S3 (registry→driver materializer satellite) addition ----

/// Dependency-inverted factory that builds a [`RunnableHook`] from a
/// component's raw binary bytes. The 8th scheduler-crate-local seam trait
/// (same in-crate plug-in pattern as `RunnableHook` / `MessageHandler` /
/// `RuntimeReadiness` / `FileWatchSource` / `WebhookSource`): the scheduler
/// holds `Arc<dyn RunnableHookFactory>`; the WASM-loading impl plugs in at the
/// cli composition root.
///
/// **Signature rationale (trait-inversion):** takes `binary: &[u8]`, NOT a
/// runtime `LoadedComponent`. The runtime/`wasmtime` types never leak into the
/// scheduler trait surface — the cli impl owns the `&[u8] → LoadedComponent →
/// WasmRunnableHook` load step (the production `WasmRunnableHook` lives at the
/// cli root `crates/cli/src/runnable_hook.rs`, NOT in the scheduler). This
/// preserves the MODULE-014 §2.2 trait-inversion posture (no compile-time
/// `advance-runtime`/`wasmtime` edge in the scheduler crate) exactly like the 7
/// prior seam traits.
///
/// Consumer: [`crate::materializer::ComponentMaterializer`] calls `build` with
/// the binary/id/capabilities EXTRACTED FROM a `ComponentRegistryRow` before
/// dispatching the resulting hook to the matching driver entry — the
/// data-driven link that the SYS-AC-109 fake-green (id-string-only binding)
/// forbids.
///
/// Returns `Arc<dyn RunnableHook>` (not `Box`) to match every driver entry's
/// `hook: Arc<dyn RunnableHook>` parameter.
#[async_trait]
pub trait RunnableHookFactory: Send + Sync {
    async fn build(
        &self,
        binary: &[u8],
        component_id: &str,
        caps: &[CapRequest],
    ) -> Result<Arc<dyn RunnableHook>, HookError>;
}

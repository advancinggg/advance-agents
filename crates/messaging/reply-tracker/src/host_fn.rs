//! Slice E (2026-05-24) — `agent-messaging::await-replies` + `heartbeat`
//! WIT host-function handlers.
//!
//! Per MODULE-007 §3.6 slice-E ADR-via-prose entry: both handlers are
//! colocated with [`crate::manager::AwaitSessionManagerImpl`] in
//! `crates/messaging/reply-tracker/` (NOT `crates/messaging/src/`) because:
//! 1. **Parallel-safety constraint** forbids m006/src edits this slice;
//! 2. **trace_id freshness** (slice-D §3.6 invariant "where the handle-
//!    message context exists") is preserved by [`HostCallContext::trace_id`]
//!    being stamped fresh per WIT call by the Wasmtime `CapabilityInjector`
//!    regardless of which crate the `impl HostFunctionHandler` lives in;
//! 3. **cap-* precedent** — cap-tools/src/host_fn.rs etc. colocate the
//!    host-fn surface with the manager surface in the specialist crate.
//!
//! ## Handler semantics
//!
//! [`AwaitRepliesHandler`] is a **pure Val encode/decode wrapper** delegating
//! to [`AwaitSessionManagerImpl::start_with_run`]. NO event is emitted from
//! THIS handler — it has an `observability-allowlist.toml` row recording that
//! (the AC-14 emit-eligibility lint passes via the allowlist). **Wave-15 Lane A
//! (2026-06-24)**: `deadlock_rejected` (SYS-AC-169) and `await_idle_timeout`
//! (SYS-AC-252) ARE now emitted in-boundary — NOT from this handler, but from
//! the manager admission path + the idle monitor (`ManagerOptions.event_emitter`;
//! session-stable envelope, empty trace_id — MODULE-007 §3.8). **Wave-20: the
//! other 4 orchestration.* events (await_started / await_satisfied /
//! await_session_closed / reply_late) are now ALSO emitted from the MANAGER
//! (NOT this handler) — all 7 events emit; AC-17 flips at SUMMARY.**
//!
//! [`HeartbeatHandler`] decodes `progress: option<string>`, calls
//! [`AwaitSessionManagerImpl::heartbeat_for_target`] (which resets the
//! `liveness` index per slice-B AC-10 + enumerates Open sessions where the
//! caller is an `AgentRequest` target — from-target authorization-by-design
//! per AC-11 §3.6 slice-E refinement), and emits one
//! `orchestration.await_progress` event per affected session via
//! [`HostCallContext::trace_id`] (fresh per WIT call — preserves the
//! slice-D trace_id-must-be-fresh invariant). This satisfies AC-12 EMIT-half
//! (RESET-half landed in slice-B) AND AC-21 sub-1 (heartbeat→event).
//!
//! ## WIT-vs-Rust projection (private helpers)
//!
//! The handlers' private encode/decode helpers bridge the WIT-vs-Rust shape
//! asymmetries documented in MODULE-007 §2.3 (the 6-bullet asymmetry block):
//! - WIT `await-result` (2-field `{replies, completed-all}`) ↔ Rust
//!   `AwaitResult` (5-field): `completed-all` is derived from `status` per
//!   asymmetry bullet 3.
//! - WIT `reply-result` (4-field `{correlation-id, target, task-id, status}`) ↔ Rust
//!   `ReplyResult` (6-field): Wave-23 wit-widening now lowers the host-internal
//!   `task_id` to the guest-visible WIT `task-id`; `correlation-id` recovered from
//!   the originating `AwaitRequest[slot]`; `payload` joined into WIT
//!   `reply-status::success` payload per asymmetry bullets 4 + 5.
//! - WIT `orchestration-error` (6-variant) ↔ Rust `OrchestrationError`
//!   (9-variant): the 3 Rust-only variants (`NotFound`, `InvalidRequest`,
//!   `Downstream`) project to WIT `invalid-target("internal:{kind}:{msg}")`
//!   per MODULE-007 §2.8 projection rule.
//! - WIT `message-context` (3-field `{task-id, run-id, execution-id}`) ↔
//!   Rust `MessageContext` (6-field): WIT subset; trace_id / in_reply_to /
//!   correlation_id default to None on decode.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use advance_runtime::host_registry::{HostCallContext, HostCallError, HostFunctionHandler};
use advance_shared_types::await_session::{
    AgentAwaitRequest, AwaitMode, AwaitOptions, AwaitRequest, AwaitResult, AwaitSessionStatus,
    ComponentAwaitRequest, OrchestrationError, ReplyResult, ReplyStatus, SessionId, TimeoutPolicy,
};
use advance_shared_types::mailbox::{MessageContext, MsgError};
use advance_shared_types::traits::EventBusEmit;
use advance_shared_types::turn_attribution::{
    ReplyRouteClaim, SendTurnClassification, TurnReplyError, TurnReplyRoutingPort,
};
// await-leg B-3 (2026-06-22): `send` bounds its payload at the M006 mailbox cap
// (1 MiB) — aliased to avoid the name collision with the reply-tracker-local
// `crate::manager::MAX_PAYLOAD_BYTES` (64 KiB await-slot cap) imported below.
use advance_messaging::MAX_PAYLOAD_BYTES as MSG_MAX_PAYLOAD_BYTES;
use wasmtime::component::Val;

use crate::run_sink::RunSuspendSink;

use crate::events::build_await_progress_event;
use crate::manager::{
    AwaitSessionManagerImpl, ClaimedReplySettlement, MAX_FANOUT, MAX_OPAQUE_ID_BYTES,
    MAX_PAYLOAD_BYTES,
};

/// Slice E adversarial-round 8 W1: bound the WIT `heartbeat(progress)` string
/// to defend against unbounded memory amplification at the host-fn decode
/// layer. 4 KiB matches reasonable user-facing progress strings (PRD §9.2
/// implies short status updates) while preventing multi-GiB string DoS.
const MAX_HEARTBEAT_PROGRESS_BYTES: usize = 4 * 1024;

/// Slice E adversarial-round 8 Info-7: sanitize attacker-supplied error text
/// before projecting it into guest-visible WIT errors. Strips ASCII control
/// chars (defangs log-injection) and truncates to a bounded length (defangs
/// echo-channel amplification). Mirrors the `sanitize_for_error` discipline
/// at manager.rs (slice-A precedent).
fn sanitize_decode_error(raw: &str) -> String {
    let cleaned: String = raw.chars().filter(|c| !c.is_control()).take(256).collect();
    cleaned
}

/// MODULE-007 AC-21 `await-replies` host-fn handler.
///
/// Pure Val encode/decode wrapper delegating to
/// [`AwaitSessionManagerImpl::start_with_run`]. NO event emission from THIS
/// handler. **Wave-15 Lane A**: `deadlock_rejected` + `await_idle_timeout` are
/// now emitted in-boundary — but from the manager admission path + the idle
/// monitor (`ManagerOptions.event_emitter`), NOT from this WIT wrapper. **Wave-20:
/// the other 4 orchestration.* events (`await_started`, `await_satisfied`,
/// `await_session_closed`, `reply_late`) are now ALSO emitted from the MANAGER
/// (admission / terminal / close / on_reply orphan paths), NOT from this WIT
/// wrapper — so all 7 events emit in-boundary; AC-17 flips at SUMMARY.** See
/// `observability-allowlist.toml` row
/// `[[handler]] crate="advance-reply-tracker" struct="AwaitRepliesHandler"`.
pub struct AwaitRepliesHandler {
    manager: Arc<AwaitSessionManagerImpl>,
    /// Backbone Step 4b (2026-06-08) — OPTIONAL run-suspend/resume driver. When
    /// `Some` AND `ctx.run_id` is present, a parked await drives the M008 Run
    /// `suspend_run`/`resume_run_if_suspended` lifecycle via this port. `None` (the prior
    /// slice-E default) → no suspend/resume (exact prior behaviour). Additive:
    /// `new()` is unchanged, so the existing call sites stay green.
    run_suspend_sink: Option<Arc<dyn RunSuspendSink>>,
}

impl AwaitRepliesHandler {
    pub fn new(manager: Arc<AwaitSessionManagerImpl>) -> Self {
        Self {
            manager,
            run_suspend_sink: None,
        }
    }

    /// Backbone Step 4b opt-in builder — install the [`RunSuspendSink`] port so
    /// a parked `await-replies` call drives M008 suspend (on park) / resume (on
    /// any await resolution except a pause/cancel `SessionClosed`). Additive;
    /// `new()` + `register_reply_tracker_host_fns` signatures are unchanged.
    pub fn with_run_suspend_sink(mut self, sink: Arc<dyn RunSuspendSink>) -> Self {
        self.run_suspend_sink = Some(sink);
        self
    }
}

impl HostFunctionHandler for AwaitRepliesHandler {
    fn call(
        &self,
        ctx: HostCallContext,
        params: Vec<Val>,
        _results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>> {
        // Plan W1: clone Arc into the async move block; `&self` cannot outlive `call()`.
        let manager = Arc::clone(&self.manager);
        let run_suspend_sink = self.run_suspend_sink.clone();
        Box::pin(async move {
            // Step 1: decode params (or return orchestration-error Err arm).
            let (requests, options) = match decode_await_replies_params(&params) {
                Ok(d) => d,
                Err(e) => {
                    // Adversarial round 8 Info-7: sanitize decoder echo channel
                    // (strip control chars, length-cap) before guest-visible projection.
                    return Ok(vec![encode_orchestration_error(
                        &OrchestrationError::InvalidRequest(format!(
                            "decode-failed:{}",
                            sanitize_decode_error(&e)
                        )),
                    )]);
                }
            };
            // Save the original requests for correlation_id back-routing (the
            // Rust ReplyResult has `slot` not `correlation_id`; we need the
            // originating request to recover correlation-id at WIT encode time).
            let requests_for_encode = requests.clone();
            // Step 2: delegate (NO emit from this handler — see allowlist row).
            //
            // Backbone Step 4b: when a `RunSuspendSink` + `ctx.run_id` are present,
            // drive the M008 Run suspend/resume lifecycle around the park. The
            // handler mints its OWN session id (uuid v4 — the manager's
            // `session_id_factory` is private) so it can suspend with that id; the
            // `on_park` hook fires `suspend_run` ONLY at the genuine park point
            // (never on a synchronous fast-path resolution). Resume fires on ANY
            // await resolution (`Ok` replies/partial-timeout OR `Err(IdleTimeoutExceeded)`
            // Fail-policy timeout — the await is OVER, so the run must leave Suspended)
            // EXCEPT `Err(SessionClosed)`, which is the pause/cancel path that owns the
            // `Suspended → Paused/Cancelled` transition (avoids the resume-vs-pause race).
            let result = match (run_suspend_sink.as_ref(), ctx.run_id.as_deref()) {
                (Some(sink), Some(run_id)) => {
                    let sid = SessionId(uuid::Uuid::new_v4().to_string());
                    let suspended = Arc::new(AtomicBool::new(false));
                    let on_park: Box<dyn FnOnce() + Send> = {
                        let sink = Arc::clone(sink);
                        let suspended = Arc::clone(&suspended);
                        let run_id = run_id.to_string();
                        let sid = sid.clone();
                        Box::new(move || {
                            // `on_await_start` returns true iff suspend_run succeeded.
                            suspended.store(sink.on_await_start(&run_id, &sid), Ordering::SeqCst);
                        })
                    };
                    let r = manager
                        .start_with_run_and_session(
                            sid.clone(),
                            &ctx.agent_id,
                            ctx.run_id.as_deref(),
                            requests,
                            options,
                            Some(on_park),
                        )
                        .await;
                    // Resume on ANY await RESOLUTION except `Err(SessionClosed)`,
                    // and only if we actually suspended. The parked await resolves
                    // as `Ok` (replies completed / `ReturnPartial` timeout) OR
                    // `Err(IdleTimeoutExceeded)` (the `Fail`-policy idle timeout) OR
                    // `Err(SessionClosed)` (pause/cancel close). For Ok AND the
                    // timeout-Err the await is OVER → resume the run (Suspended →
                    // Active) so it is NOT left stuck Suspended (the idle-timeout-Fail
                    // resource-leak surfaced by the §5.2 adversarial review). ONLY
                    // `Err(SessionClosed)` is skipped — pause/cancel owns that
                    // `Suspended → Paused/Cancelled` transition (the resume-vs-pause
                    // race fix). `resume_run_if_suspended` is atomic Suspended-only,
                    // so it is a no-op if some other path already left Suspended.
                    let resolved_not_closed =
                        !matches!(&r, Err(OrchestrationError::SessionClosed(_)));
                    if suspended.load(Ordering::SeqCst) && resolved_not_closed {
                        sink.on_await_resolve(run_id, &sid);
                    }
                    r
                }
                _ => {
                    // No sink / no run_id → prior slice-E behaviour (no suspend/resume).
                    manager
                        .start_with_run(&ctx.agent_id, ctx.run_id.as_deref(), requests, options)
                        .await
                }
            };
            // Step 3: encode result-or-error per WIT result<await-result, orchestration-error>.
            Ok(vec![encode_await_result_or_error(
                result,
                &requests_for_encode,
            )])
        })
    }
}

/// MODULE-007 AC-11 + AC-12 + AC-21 sub-1 `heartbeat` host-fn handler.
///
/// Decodes `Option<String>` progress, calls
/// [`AwaitSessionManagerImpl::heartbeat_for_target`] (resets `liveness` per
/// slice-B AC-10 + enumerates from-target sessions), and emits one
/// `orchestration.await_progress` event per affected session via
/// [`HostCallContext::trace_id`] (fresh per WIT call). The `emit(...)` call
/// is bare-in-handler-body per the MODULE-019 AC-14 observability lint
/// recognition (no allowlist row needed).
pub struct HeartbeatHandler {
    manager: Arc<AwaitSessionManagerImpl>,
    emitter: Arc<dyn EventBusEmit>,
}

impl HeartbeatHandler {
    pub fn new(manager: Arc<AwaitSessionManagerImpl>, emitter: Arc<dyn EventBusEmit>) -> Self {
        Self { manager, emitter }
    }
}

impl HostFunctionHandler for HeartbeatHandler {
    fn call(
        &self,
        ctx: HostCallContext,
        params: Vec<Val>,
        _results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>> {
        // Plan W1: clone Arc into the async move block.
        let manager = Arc::clone(&self.manager);
        let emitter = Arc::clone(&self.emitter);
        Box::pin(async move {
            // Step 1: decode params (or return msg-error Err arm).
            let progress = match decode_heartbeat_params(&params) {
                Ok(p) => p,
                Err(e) => {
                    // Adversarial round 8 Info-7: sanitize decoder echo channel.
                    return Ok(vec![encode_msg_error(&MsgError::InvalidPayload(format!(
                        "decode-failed:{}",
                        sanitize_decode_error(&e)
                    )))]);
                }
            };
            // Step 2: invoke manager (async — heartbeat_for_target acquires
            // sessions.read().await per the tokio::sync::RwLock invariant).
            let affected = manager
                .heartbeat_for_target(&ctx.agent_id, progress.clone())
                .await;
            // Step 3: emit one event per affected session.
            for session_id in &affected {
                let event = build_await_progress_event(
                    &ctx,
                    session_id,
                    &ctx.agent_id,
                    progress.as_deref(),
                );
                emitter.emit(event);
            }
            // Step 4: return Ok-unit (heartbeat WIT signature: result<_, msg-error>).
            Ok(vec![encode_msg_result_unit_ok()])
        })
    }
}

/// MODULE-006 `send` host-fn handler (await-leg B-3, 2026-06-22).
///
/// Pure Val decode wrapper delegating to
/// [`AwaitSessionManagerImpl::handle_send`] — routes a child→parent reply into
/// MODULE-007 `on_reply` when the target owns an open await slot for the source,
/// else falls back to genuine M006 mailbox delivery (the manager owns the
/// dispatcher privately). Registered under capability `"messaging"` / namespace
/// `"advance:runtime/agent-messaging@0.1.0"` / name `"send"` by
/// [`register_send_host_fn`]. NO event emission from this handler — the
/// `msg.received` emit on the delivery-fallback path is the M006 dispatcher's
/// (`MailboxDispatcherImpl`) responsibility, and a reply route does not emit
/// (the M019 await/orchestration emit boundary owns those).
pub struct SendHandler {
    manager: Arc<AwaitSessionManagerImpl>,
    turn_reply: Option<Arc<dyn TurnReplyRoutingPort>>,
    claim_recovery: Arc<ReplyClaimRecoveryLatch>,
}

impl SendHandler {
    pub fn new(manager: Arc<AwaitSessionManagerImpl>) -> Self {
        Self {
            manager,
            turn_reply: None,
            claim_recovery: Arc::new(ReplyClaimRecoveryLatch::new()),
        }
    }

    pub fn with_turn_reply_routing(mut self, turn_reply: Arc<dyn TurnReplyRoutingPort>) -> Self {
        self.turn_reply = Some(turn_reply);
        self
    }
}

struct ActiveReplyDeliveryGuard {
    settlement: Arc<ClaimedReplySettlement>,
    recovery: Arc<ReplyClaimRecoveryLatch>,
}

impl ActiveReplyDeliveryGuard {
    fn new(
        settlement: Arc<ClaimedReplySettlement>,
        recovery: Arc<ReplyClaimRecoveryLatch>,
    ) -> Self {
        Self {
            settlement,
            recovery,
        }
    }
}

impl Drop for ActiveReplyDeliveryGuard {
    fn drop(&mut self) {
        if !self.settlement.abandon() {
            self.recovery.retain(Arc::clone(&self.settlement));
        }
    }
}

const MAX_REPLY_CLAIM_RECOVERY: usize = 4096;

/// Bounded process-lifetime owner for claim tokens whose provider cleanup was
/// temporarily unavailable. Retried at each subsequent send call; a token is
/// never dropped merely because begin/abort raced cancellation or contention.
struct ReplyClaimRecoveryLatch {
    pending: std::sync::Mutex<Vec<Arc<ClaimedReplySettlement>>>,
}

impl ReplyClaimRecoveryLatch {
    fn new() -> Self {
        Self {
            pending: std::sync::Mutex::new(Vec::with_capacity(MAX_REPLY_CLAIM_RECOVERY)),
        }
    }

    fn retain(&self, settlement: Arc<ClaimedReplySettlement>) {
        let mut pending = self
            .pending
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert!(pending.len() < MAX_REPLY_CLAIM_RECOVERY);
        pending.push(settlement);
    }

    fn recover(&self) {
        let pending = {
            let mut pending = self
                .pending
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            std::mem::take(&mut *pending)
        };
        let mut still_pending = Vec::new();
        for settlement in pending {
            if !settlement.abandon() {
                still_pending.push(settlement);
            }
        }
        self.pending
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .extend(still_pending);
    }
}

fn turn_reply_msg_error(error: TurnReplyError) -> MsgError {
    MsgError::CapabilityDenied(error.code().to_string())
}

impl HostFunctionHandler for SendHandler {
    fn call(
        &self,
        ctx: HostCallContext,
        params: Vec<Val>,
        _results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>> {
        let manager = Arc::clone(&self.manager);
        let turn_reply = self.turn_reply.clone();
        let claim_recovery = Arc::clone(&self.claim_recovery);
        Box::pin(async move {
            claim_recovery.recover();
            // Step 1: decode params (or return msg-error Err arm).
            let (target, payload, context) = match decode_send_params(&params) {
                Ok(d) => d,
                Err(e) => {
                    // Adversarial round 8 Info-7 precedent: sanitize the decoder
                    // echo channel before guest-visible projection.
                    return Ok(vec![encode_msg_error(&MsgError::InvalidPayload(format!(
                        "decode-failed:{}",
                        sanitize_decode_error(&e)
                    )))]);
                }
            };
            // Step 2: a trusted turn stamp selects the exact C216 route. The
            // legacy heuristic remains only for untracked/non-parent sends.
            let result = if let (Some(port), Some(turn_id)) = (turn_reply, ctx.turn_id.as_deref()) {
                match port.classify_send(turn_id, &ctx.agent_id, &target) {
                    SendTurnClassification::ActiveParent
                    | SendTurnClassification::DetachedParent => {
                        match port.claim_active_reply(turn_id, &ctx.agent_id, &target) {
                            Ok(ReplyRouteClaim::Active(claimed)) => {
                                let (route, token) = claimed.into_parts();
                                let settlement =
                                    ClaimedReplySettlement::new(Arc::clone(&port), token);
                                let _guard = ActiveReplyDeliveryGuard::new(
                                    Arc::clone(&settlement),
                                    Arc::clone(&claim_recovery),
                                );
                                if let Err(error) = settlement.begin_delivery() {
                                    Err(turn_reply_msg_error(error))
                                } else {
                                    match manager
                                        .route_claimed_reply(
                                            &route,
                                            payload,
                                            Arc::clone(&settlement),
                                        )
                                        .await
                                    {
                                        Ok(()) => Ok(()),
                                        Err(_) if settlement.slot_was_recorded() => {
                                            Err(MsgError::CapabilityDenied(
                                                "reply-recovery-pending".to_string(),
                                            ))
                                        }
                                        Err(_) => match settlement.settle_definite_rejection() {
                                            Ok(()) => Err(MsgError::CapabilityDenied(
                                                "turn-reply-not-accepted".to_string(),
                                            )),
                                            Err(error) => Err(turn_reply_msg_error(error)),
                                        },
                                    }
                                }
                            }
                            Ok(ReplyRouteClaim::DetachedLate(token)) => {
                                // CONTRACT-216 late disposition is claimed under
                                // the registry lock before this branch.  Emit the
                                // single audit outcome, drop the payload without
                                // any mailbox/session lookup, then complete the
                                // opaque claim.  A repeat observes AlreadyHandled
                                // and therefore emits nothing.
                                manager.emit_detached_reply_late(&ctx.agent_id, &target, turn_id);
                                port.complete_reply_late(token)
                                    .map_err(turn_reply_msg_error)
                            }
                            Ok(ReplyRouteClaim::AlreadyHandled) => Ok(()),
                            Err(error) => Err(turn_reply_msg_error(error)),
                        }
                    }
                    SendTurnClassification::NonCallable(_)
                    | SendTurnClassification::IdentityMismatch => {
                        Err(MsgError::CapabilityDenied("turn-not-callable".to_string()))
                    }
                    SendTurnClassification::DetachedUnrelated => {
                        let sanitized = context.map(|mut value| {
                            value.run_id = None;
                            value.execution_id = None;
                            value.trace_id = None;
                            value.in_reply_to = None;
                            value.correlation_id = None;
                            value
                        });
                        manager
                            .handle_send(&ctx.agent_id, &target, payload, sanitized)
                            .await
                    }
                    SendTurnClassification::Untracked => {
                        manager
                            .handle_send(&ctx.agent_id, &target, payload, context)
                            .await
                    }
                }
            } else {
                manager
                    .handle_send(&ctx.agent_id, &target, payload, context)
                    .await
            };
            // Step 3: lower onto WIT `result<_, msg-error>`.
            Ok(vec![match result {
                Ok(()) => encode_msg_result_unit_ok(),
                Err(e) => encode_msg_error(&e),
            }])
        })
    }
}

// ════════════════════════════════════════════════════════════════════════
// Decoders
// ════════════════════════════════════════════════════════════════════════

/// Decode `await-replies` WIT params: `(list<await-request>, await-options)`.
pub(crate) fn decode_await_replies_params(
    params: &[Val],
) -> Result<(Vec<AwaitRequest>, AwaitOptions), String> {
    if params.len() != 2 {
        return Err(format!(
            "await-replies expects 2 params (requests, options), got {}",
            params.len()
        ));
    }
    let requests = decode_await_request_list(&params[0])?;
    let options = decode_await_options(&params[1])?;
    Ok((requests, options))
}

fn decode_await_request_list(val: &Val) -> Result<Vec<AwaitRequest>, String> {
    match val {
        Val::List(items) => {
            // Adversarial round 8 W3: bound list length at the decode layer
            // BEFORE the per-element walk to defend against pre-admission
            // heap exhaustion (mirrors cap-tools host_fn.rs:249 precedent).
            // The admission-time MAX_FANOUT cap at manager.rs:469 is the
            // late-stage enforcement; this is the upstream lifter-allocation
            // bound.
            if items.len() > MAX_FANOUT {
                return Err(format!(
                    "requests: list length {} exceeds MAX_FANOUT {}",
                    items.len(),
                    MAX_FANOUT
                ));
            }
            items
                .iter()
                .enumerate()
                .map(|(i, v)| decode_await_request(v).map_err(|e| format!("requests[{i}]: {e}")))
                .collect()
        }
        other => Err(format!("requests: expected list, got {other:?}")),
    }
}

fn decode_await_request(val: &Val) -> Result<AwaitRequest, String> {
    match val {
        Val::Variant(case, payload) => match case.as_str() {
            "agent-request" => {
                let inner = payload
                    .as_ref()
                    .ok_or_else(|| "agent-request: missing payload".to_string())?;
                let agent_req = decode_agent_await_request(inner)?;
                Ok(AwaitRequest::AgentRequest(agent_req))
            }
            "component-finished" => {
                let inner = payload
                    .as_ref()
                    .ok_or_else(|| "component-finished: missing payload".to_string())?;
                let comp_req = decode_component_await_request(inner)?;
                Ok(AwaitRequest::ComponentFinished(comp_req))
            }
            other => Err(format!("await-request: unknown variant case {other:?}")),
        },
        other => Err(format!("await-request: expected variant, got {other:?}")),
    }
}

fn decode_agent_await_request(val: &Val) -> Result<AgentAwaitRequest, String> {
    let fields = decode_record(val, "agent-await-request")?;
    let target = decode_bounded_string_field(fields, "target", MAX_OPAQUE_ID_BYTES)?;
    let payload = decode_byte_list_field(fields, "payload")?;
    let correlation_id =
        decode_bounded_string_field(fields, "correlation-id", MAX_OPAQUE_ID_BYTES)?;
    let context = decode_option_message_context_field(fields, "context")?;
    Ok(AgentAwaitRequest {
        target,
        payload,
        correlation_id,
        context,
    })
}

fn decode_component_await_request(val: &Val) -> Result<ComponentAwaitRequest, String> {
    let fields = decode_record(val, "component-await-request")?;
    let component_id = decode_bounded_string_field(fields, "component-id", MAX_OPAQUE_ID_BYTES)?;
    let correlation_id =
        decode_bounded_string_field(fields, "correlation-id", MAX_OPAQUE_ID_BYTES)?;
    Ok(ComponentAwaitRequest {
        component_id,
        correlation_id,
    })
}

fn decode_await_options(val: &Val) -> Result<AwaitOptions, String> {
    let fields = decode_record(val, "await-options")?;
    let mode = decode_await_mode_field(fields, "mode")?;
    let idle_timeout_secs = decode_option_u32_field(fields, "idle-timeout-secs")?;
    let on_idle_timeout = decode_timeout_policy_field(fields, "on-idle-timeout")?;
    let keep_losers = decode_bool_field(fields, "keep-losers")?;
    Ok(AwaitOptions {
        mode,
        idle_timeout_secs,
        on_idle_timeout,
        keep_losers,
    })
}

fn decode_await_mode_field(fields: &[(String, Val)], field: &str) -> Result<AwaitMode, String> {
    let v = lookup_field(fields, field)?;
    match v {
        Val::Variant(case, _) => match case.as_str() {
            "all-of" => Ok(AwaitMode::AllOf),
            "any-of" => Ok(AwaitMode::AnyOf),
            other => Err(format!("{field}: unknown await-mode case {other:?}")),
        },
        other => Err(format!("{field}: expected variant, got {other:?}")),
    }
}

fn decode_timeout_policy_field(
    fields: &[(String, Val)],
    field: &str,
) -> Result<TimeoutPolicy, String> {
    let v = lookup_field(fields, field)?;
    match v {
        Val::Variant(case, _) => match case.as_str() {
            "return-partial" => Ok(TimeoutPolicy::ReturnPartial),
            "fail" => Ok(TimeoutPolicy::Fail),
            other => Err(format!("{field}: unknown timeout-policy case {other:?}")),
        },
        other => Err(format!("{field}: expected variant, got {other:?}")),
    }
}

fn decode_option_message_context_field(
    fields: &[(String, Val)],
    field: &str,
) -> Result<Option<MessageContext>, String> {
    let v = lookup_field(fields, field)?;
    match v {
        Val::Option(None) => Ok(None),
        Val::Option(Some(inner)) => {
            let ctx_fields = decode_record(inner, "message-context")?;
            // Wave-23 adversarial fix: bound the guest-controlled context ids at
            // MAX_OPAQUE_ID_BYTES (matching sibling target/correlation-id) so the
            // reply-result.task-id echo cannot amplify unbounded guest input.
            let task_id =
                decode_bounded_option_string_field(ctx_fields, "task-id", MAX_OPAQUE_ID_BYTES)?;
            let run_id =
                decode_bounded_option_string_field(ctx_fields, "run-id", MAX_OPAQUE_ID_BYTES)?;
            let execution_id = decode_bounded_option_string_field(
                ctx_fields,
                "execution-id",
                MAX_OPAQUE_ID_BYTES,
            )?;
            // WIT message-context is 3-field; Rust is 6-field. Other 3 default
            // to None per WIT-vs-Rust asymmetry (the WIT subset is intentional —
            // trace_id / in_reply_to / correlation_id are runtime-internal).
            Ok(Some(MessageContext {
                task_id,
                run_id,
                execution_id,
                trace_id: None,
                in_reply_to: None,
                correlation_id: None,
            }))
        }
        other => Err(format!("{field}: expected option, got {other:?}")),
    }
}

/// Decode `heartbeat` WIT params: `(progress: option<string>)`.
///
/// Adversarial round 8 W1: bound the progress string at `MAX_HEARTBEAT_PROGRESS_BYTES`
/// to defend against unbounded memory amplification (the string is cloned
/// once per affected session into the emitted event payload).
pub(crate) fn decode_heartbeat_params(params: &[Val]) -> Result<Option<String>, String> {
    if params.len() != 1 {
        return Err(format!(
            "heartbeat expects 1 param (progress), got {}",
            params.len()
        ));
    }
    match &params[0] {
        Val::Option(None) => Ok(None),
        Val::Option(Some(inner)) => match inner.as_ref() {
            Val::String(s) => {
                if s.len() > MAX_HEARTBEAT_PROGRESS_BYTES {
                    return Err(format!(
                        "progress: string length {} exceeds MAX_HEARTBEAT_PROGRESS_BYTES {}",
                        s.len(),
                        MAX_HEARTBEAT_PROGRESS_BYTES
                    ));
                }
                Ok(Some(s.clone()))
            }
            other => Err(format!("progress: expected option<string>, got {other:?}")),
        },
        other => Err(format!("progress: expected option<string>, got {other:?}")),
    }
}

/// Decode `send` WIT params: `(target: string, payload: list<u8>,
/// context: option<message-context>)` (await-leg B-3, 2026-06-22).
///
/// `target` is bounded at `MAX_OPAQUE_ID_BYTES`; `payload` is bounded at the
/// **M006 mailbox cap** [`MSG_MAX_PAYLOAD_BYTES`] (1 MiB) — so `send` is exactly
/// as permissive as M006 mailbox delivery / `notify-agent`, NOT the reply-tracker
/// 64 KiB await-slot cap. Mirrors `messaging/src/host_fn.rs::decode_notify_agent_params`.
pub(crate) fn decode_send_params(
    params: &[Val],
) -> Result<(String, Vec<u8>, Option<MessageContext>), String> {
    if params.len() != 3 {
        return Err(format!(
            "send expects 3 params (target, payload, context), got {}",
            params.len()
        ));
    }
    let target = match &params[0] {
        Val::String(s) => {
            if s.len() > MAX_OPAQUE_ID_BYTES {
                return Err(format!(
                    "target: string length {} exceeds bound {}",
                    s.len(),
                    MAX_OPAQUE_ID_BYTES
                ));
            }
            s.clone()
        }
        other => return Err(format!("target: expected string, got {other:?}")),
    };
    let payload = decode_byte_list_bounded(&params[1], MSG_MAX_PAYLOAD_BYTES, "payload")?;
    let context = decode_option_message_context(&params[2])?;
    Ok((target, payload, context))
}

/// await-leg B-3 — decode a `list<u8>` Val, bounding the length BEFORE the
/// per-element walk (mirrors the private `decode_byte_list_field` but takes the
/// Val + an explicit cap directly, so `send` can use the M006 1 MiB cap rather
/// than the reply-tracker 64 KiB await-slot cap).
fn decode_byte_list_bounded(val: &Val, max_bytes: usize, what: &str) -> Result<Vec<u8>, String> {
    match val {
        Val::List(items) => {
            if items.len() > max_bytes {
                return Err(format!(
                    "{what}: list length {} exceeds bound {}",
                    items.len(),
                    max_bytes
                ));
            }
            items
                .iter()
                .map(|v| match v {
                    Val::U8(b) => Ok(*b),
                    other => Err(format!("{what}: expected list<u8>, got element {other:?}")),
                })
                .collect()
        }
        other => Err(format!("{what}: expected list<u8>, got {other:?}")),
    }
}

/// await-leg B-3 — decode a top-level `option<message-context>` Val (the WIT
/// 3-field subset `{task-id, run-id, execution-id}`; the other 3 Rust
/// `MessageContext` fields default to `None` per the §2.3 WIT-vs-Rust asymmetry).
/// Standalone (the `send` param is a top-level option, not a record field — the
/// existing `decode_option_message_context_field` is kept byte-identical).
fn decode_option_message_context(val: &Val) -> Result<Option<MessageContext>, String> {
    match val {
        Val::Option(None) => Ok(None),
        Val::Option(Some(inner)) => {
            let ctx_fields = decode_record(inner, "message-context")?;
            // Wave-23 adversarial fix: bound the guest-controlled context ids at
            // MAX_OPAQUE_ID_BYTES (matching sibling target/correlation-id) so the
            // reply-result.task-id echo cannot amplify unbounded guest input.
            let task_id =
                decode_bounded_option_string_field(ctx_fields, "task-id", MAX_OPAQUE_ID_BYTES)?;
            let run_id =
                decode_bounded_option_string_field(ctx_fields, "run-id", MAX_OPAQUE_ID_BYTES)?;
            let execution_id = decode_bounded_option_string_field(
                ctx_fields,
                "execution-id",
                MAX_OPAQUE_ID_BYTES,
            )?;
            Ok(Some(MessageContext {
                task_id,
                run_id,
                execution_id,
                trace_id: None,
                in_reply_to: None,
                correlation_id: None,
            }))
        }
        other => Err(format!(
            "context: expected option<message-context>, got {other:?}"
        )),
    }
}

// ─── Decoder primitives ─────────────────────────────────────────────────

fn decode_record<'a>(val: &'a Val, what: &str) -> Result<&'a [(String, Val)], String> {
    match val {
        Val::Record(fields) => Ok(fields),
        other => Err(format!("{what}: expected record, got {other:?}")),
    }
}

fn lookup_field<'a>(fields: &'a [(String, Val)], name: &str) -> Result<&'a Val, String> {
    fields
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v)
        .ok_or_else(|| format!("missing field {name:?}"))
}

/// Adversarial round 8 W2/W3-companion: bounded string decode for opaque IDs
/// (target, correlation-id, component-id). Enforces a per-field max-byte cap
/// at the decode layer, BEFORE allocating the owned String. Slice E switched
/// from an unbounded `decode_string_field` to this bounded variant per the
/// adversarial-round-8 W1/W2/W3 family — all in-WIT-decoder string fields
/// now carry an explicit length cap.
fn decode_bounded_string_field(
    fields: &[(String, Val)],
    field: &str,
    max_bytes: usize,
) -> Result<String, String> {
    match lookup_field(fields, field)? {
        Val::String(s) => {
            if s.len() > max_bytes {
                return Err(format!(
                    "{field}: string length {} exceeds bound {}",
                    s.len(),
                    max_bytes
                ));
            }
            Ok(s.clone())
        }
        other => Err(format!("{field}: expected string, got {other:?}")),
    }
}

/// Decode a WIT `option<string>` field, REJECTING an inner string longer than
/// `max_bytes` (the option-case mirror of [`decode_bounded_string_field`]).
///
/// Wave-23 wit-widening adversarial round 10 (dual-model): the `message-context`
/// id fields (`task-id` / `run-id` / `execution-id`) on the await-replies + send
/// paths were previously decoded UNBOUNDED, unlike the sibling `target` /
/// `correlation-id` (`decode_bounded_string_field(MAX_OPAQUE_ID_BYTES)`). A guest
/// could alias all `MAX_FANOUT × 3` context (ptr,len) pairs at one large
/// linear-memory buffer for ~96× host-memory amplification held for the session
/// lifetime — and the Wave-23 `reply-result.task-id` echo surfaced/round-tripped
/// it. Bounding at decode (before `AwaitSession::new` clones the requests) closes
/// the amplification and enforces the 256 B/field bound MODULE-001 §3.6(g) assumed.
fn decode_bounded_option_string_field(
    fields: &[(String, Val)],
    field: &str,
    max_bytes: usize,
) -> Result<Option<String>, String> {
    match lookup_field(fields, field)? {
        Val::Option(None) => Ok(None),
        Val::Option(Some(inner)) => match inner.as_ref() {
            Val::String(s) => {
                if s.len() > max_bytes {
                    return Err(format!(
                        "{field}: string length {} exceeds bound {}",
                        s.len(),
                        max_bytes
                    ));
                }
                Ok(Some(s.clone()))
            }
            other => Err(format!("{field}: expected option<string>, got {other:?}")),
        },
        other => Err(format!("{field}: expected option<string>, got {other:?}")),
    }
}

fn decode_option_u32_field(fields: &[(String, Val)], field: &str) -> Result<Option<u32>, String> {
    match lookup_field(fields, field)? {
        Val::Option(None) => Ok(None),
        Val::Option(Some(inner)) => match inner.as_ref() {
            Val::U32(n) => Ok(Some(*n)),
            other => Err(format!("{field}: expected option<u32>, got {other:?}")),
        },
        other => Err(format!("{field}: expected option<u32>, got {other:?}")),
    }
}

fn decode_bool_field(fields: &[(String, Val)], field: &str) -> Result<bool, String> {
    match lookup_field(fields, field)? {
        Val::Bool(b) => Ok(*b),
        other => Err(format!("{field}: expected bool, got {other:?}")),
    }
}

fn decode_byte_list_field(fields: &[(String, Val)], field: &str) -> Result<Vec<u8>, String> {
    match lookup_field(fields, field)? {
        Val::List(items) => {
            // Adversarial round 8 W2: bound length BEFORE the per-element walk.
            // Each Val::U8 wrapper carries ~24 bytes on 64-bit, so a 1M-element
            // Vec<Val> occupies ~24 MiB of upstream lifter memory BEFORE this
            // decoder allocates the Vec<u8>. Failing here at the length check
            // bounds the per-WIT-call allocation deterministically. Mirrors
            // cap-tools host_fn.rs:249 precedent — MAX_PAYLOAD_BYTES is the
            // per-slot admission-time cap reused here for symmetry.
            if items.len() > MAX_PAYLOAD_BYTES {
                return Err(format!(
                    "{field}: list length {} exceeds MAX_PAYLOAD_BYTES {}",
                    items.len(),
                    MAX_PAYLOAD_BYTES
                ));
            }
            items
                .iter()
                .map(|v| match v {
                    Val::U8(b) => Ok(*b),
                    other => Err(format!("{field}: expected list<u8>, got element {other:?}")),
                })
                .collect()
        }
        other => Err(format!("{field}: expected list<u8>, got {other:?}")),
    }
}

// ════════════════════════════════════════════════════════════════════════
// Encoders
// ════════════════════════════════════════════════════════════════════════

/// Encode the result of `start_with_run` as the WIT
/// `result<await-result, orchestration-error>` Val.
pub(crate) fn encode_await_result_or_error(
    result: Result<AwaitResult, OrchestrationError>,
    originating_requests: &[AwaitRequest],
) -> Val {
    match result {
        Ok(await_result) => Val::Result(Ok(Some(Box::new(encode_await_result(
            &await_result,
            originating_requests,
        ))))),
        Err(err) => encode_orchestration_error(&err),
    }
}

fn encode_await_result(rust: &AwaitResult, originating_requests: &[AwaitRequest]) -> Val {
    // WIT-vs-Rust asymmetry bullet 3: completed_all = derivable from status.
    // Per PRD §9.2 "若所有目标都在派发阶段失败 → 仍返回 Ok(await-result)" —
    // FailedDispatch maps to completed_all=true (all slots terminally resolved
    // in dispatch). Completed maps to completed_all=true. PartialTimeout /
    // FailedTimeout / Cancelled = false (some slots not all-of-completed).
    let completed_all = matches!(
        rust.status,
        AwaitSessionStatus::Completed | AwaitSessionStatus::FailedDispatch
    );
    let replies: Vec<Val> = rust
        .replies
        .iter()
        .map(|r| rust_reply_to_wit_reply(r, originating_requests))
        .collect();
    Val::Record(vec![
        ("replies".into(), Val::List(replies)),
        ("completed-all".into(), Val::Bool(completed_all)),
    ])
}

fn rust_reply_to_wit_reply(rust: &ReplyResult, originating_requests: &[AwaitRequest]) -> Val {
    // WIT-vs-Rust asymmetry bullet 4: WIT reply-result is 4-field
    // `{correlation-id, target, task-id, status}` (Wave-23 wit-widening exposed the
    // host-internal `task_id` guest-side); Rust is 6-field
    // `{slot, source, payload, status, received_at, task_id}`. Recover correlation-id
    // from the originating request at rust.slot. If slot index is out-of-range
    // (defensive — should not happen in practice; manager preserves the
    // 1:1 request[i] ↔ reply[i] mapping), fall back to empty string.
    let correlation_id = originating_requests
        .get(rust.slot as usize)
        .map(|req| match req {
            AwaitRequest::AgentRequest(a) => a.correlation_id.clone(),
            AwaitRequest::ComponentFinished(c) => c.correlation_id.clone(),
        })
        .unwrap_or_default();
    // Wave-23: lower the host-internal winner `task_id` (Wave-20 AC-13 rule 1) to the
    // guest-visible WIT `reply-result.task-id: option<string>`. `None` → `Val::Option(None)`.
    let task_id = match &rust.task_id {
        Some(t) => Val::Option(Some(Box::new(Val::String(t.clone())))),
        None => Val::Option(None),
    };
    Val::Record(vec![
        ("correlation-id".into(), Val::String(correlation_id)),
        ("target".into(), Val::String(rust.source.clone())),
        ("task-id".into(), task_id),
        (
            "status".into(),
            rust_reply_status_to_wit(&rust.status, &rust.payload),
        ),
    ])
}

fn rust_reply_status_to_wit(rust: &ReplyStatus, payload: &[u8]) -> Val {
    // WIT-vs-Rust asymmetry bullet 5: WIT reply-status has 5 variants,
    // Rust has 4. Mapping:
    //   - Rust Completed + non-empty payload → WIT success(list<u8>)
    //   - Rust Completed + empty payload → WIT completed (no payload)
    //     (ComponentFinished case per §2.3 — result in output-dir, not WIT)
    //   - Rust TimedOut → WIT timed-out
    //   - Rust Cancelled → WIT detached (slice-A loser-omission projection
    //     per §2.3 bullet 5)
    //   - Rust Failed(reason) → WIT error(reason)
    match rust {
        ReplyStatus::Completed => {
            if payload.is_empty() {
                Val::Variant("completed".into(), None)
            } else {
                let bytes: Vec<Val> = payload.iter().map(|b| Val::U8(*b)).collect();
                Val::Variant("success".into(), Some(Box::new(Val::List(bytes))))
            }
        }
        ReplyStatus::TimedOut => Val::Variant("timed-out".into(), None),
        ReplyStatus::Cancelled => Val::Variant("detached".into(), None),
        ReplyStatus::Failed(reason) => {
            Val::Variant("error".into(), Some(Box::new(Val::String(reason.clone()))))
        }
    }
}

/// Encode a Rust `OrchestrationError` 9-variant into the WIT
/// `result<await-result, orchestration-error>::Err(orchestration-error-6-variant)`.
///
/// WIT-vs-Rust asymmetry bullet 6 (MODULE-007 §2.8): the 3 Rust-only variants
/// (`NotFound`, `InvalidRequest`, `Downstream`) project to WIT
/// `invalid-target("internal:{kind}:{msg}")` with a PII-safe "internal:"
/// prefix per §2.8 "no user data in the projected string" invariant.
pub(crate) fn encode_orchestration_error(err: &OrchestrationError) -> Val {
    let (case, msg): (&str, String) = match err {
        OrchestrationError::CapabilityDenied(s) => ("capability-denied", s.clone()),
        OrchestrationError::InvalidTarget(s) => ("invalid-target", s.clone()),
        OrchestrationError::DeadlockDetected(s) => ("deadlock-detected", s.clone()),
        OrchestrationError::SessionLimitExceeded(s) => ("session-limit-exceeded", s.clone()),
        OrchestrationError::SessionClosed(s) => ("session-closed", s.clone()),
        OrchestrationError::IdleTimeoutExceeded(s) => ("idle-timeout-exceeded", s.clone()),
        // §2.8 Rust-only-variant projection rule.
        OrchestrationError::NotFound(s) => ("invalid-target", format!("internal:not-found:{s}")),
        OrchestrationError::InvalidRequest(s) => {
            ("invalid-target", format!("internal:invalid-request:{s}"))
        }
        OrchestrationError::Downstream(s) => ("invalid-target", format!("internal:downstream:{s}")),
    };
    Val::Result(Err(Some(Box::new(Val::Variant(
        case.to_string(),
        Some(Box::new(Val::String(msg))),
    )))))
}

/// Encode `result<_, msg-error>::Ok` (the success-unit return arm for
/// `heartbeat`).
pub(crate) fn encode_msg_result_unit_ok() -> Val {
    Val::Result(Ok(None))
}

/// Encode a Rust `MsgError` as WIT `result<_, msg-error>::Err`.
pub(crate) fn encode_msg_error(err: &MsgError) -> Val {
    let case_payload: (&str, Option<Box<Val>>) = match err {
        MsgError::InvalidTarget(s) => ("invalid-target", Some(Box::new(Val::String(s.clone())))),
        MsgError::MailboxFull => ("mailbox-full", None),
        MsgError::CircuitBreakerOpen(s) => (
            "circuit-breaker-open",
            Some(Box::new(Val::String(s.clone()))),
        ),
        MsgError::CapabilityDenied(s) => {
            ("capability-denied", Some(Box::new(Val::String(s.clone()))))
        }
        MsgError::InvalidPayload(s) => ("invalid-payload", Some(Box::new(Val::String(s.clone())))),
    };
    Val::Result(Err(Some(Box::new(Val::Variant(
        case_payload.0.to_string(),
        case_payload.1,
    )))))
}

// ---------------------------------------------------------------------------
// register_reply_tracker_host_fns — Slice m001-slice-bootstrap (2026-05-28)
// ---------------------------------------------------------------------------

use advance_runtime::host_registry::{HostFunctionSpec, HostRegistry};

/// Slice m001-slice-bootstrap (2026-05-28) — register both reply-tracker
/// host-fn handlers ([`AwaitRepliesHandler`] + [`HeartbeatHandler`]) into a
/// [`HostRegistry`] under capability `"messaging"` and namespace
/// `"advance:runtime/agent-messaging@0.1.0"` (matches the canonical
/// component-model linker identifier emitted by Wasmtime 43 — the WIT
/// package version `@0.1.0` is part of the namespace lookup key).
///
/// **NOTE — partial coverage of the agent-messaging interface**: the WIT
/// interface (`crates/runtime/wit/advance.wit:529-612`) declares THREE
/// host functions: `send`, `heartbeat`, `await-replies`. This helper
/// registers only `heartbeat` + `await-replies`. As of await-leg B-3
/// (2026-06-22) [`SendHandler`] EXISTS and `send` is registered by the
/// sibling [`register_send_host_fn`] (NOT by this helper), so a guest that
/// imports `send` must have BOTH registered to instantiate without
/// `InstantiateError::LinkerTypecheck` (the production `wire_capabilities`
/// `declares_messaging` block + the `send_host_fn` test both do; this 3-arg
/// helper is kept for the await-replies/heartbeat-only callers). await-leg
/// B-4a (2026-06-22) added `"messaging"` to `agent_config::KNOWN_CAPABILITIES`,
/// so a `messaging`-declaring guest now LINKS these imports (DORMANT only for
/// shipped agents).
///
/// Returns `()` (HostRegistry::register is void per
/// `crates/runtime/src/host_registry.rs:147` — registrations are infallible
/// at the registry layer; downstream `CapabilityInjector::inject` can still
/// fail with `LinkerError` on duplicate name/namespace, surfaced through
/// the slice-m001-slice-bootstrap `From<HostError> for InstantiateError`
/// shim into the consumer's `InstantiateError::LinkerTypecheck` variant).
///
/// `manager` is shared between both handlers (cheap `Arc::clone`). The
/// `event_bus` `Arc` is wired into `HeartbeatHandler` for the in-boundary
/// `orchestration.await_progress` emission (slice-E). `AwaitRepliesHandler`
/// does not consume `event_bus` (no emit from this WIT wrapper). `deadlock_rejected`
/// + `await_idle_timeout` (Wave-15) and **the other 4 events (`await_started`/
/// `await_satisfied`/`await_session_closed`/`reply_late`, Wave-20)** all emit from
/// the manager admission / terminal / close / on_reply paths (via
/// `ManagerOptions.event_emitter`, wired at the composition root) — NONE from this
/// WIT wrapper, so all 7 emit in-boundary while THIS handler stays no-emit (see the
/// observability-allowlist row).
///
/// **Idempotency**: `await-replies` is registered with `idempotent: false`
/// (state-modifying; admits a new session). `heartbeat` is registered with
/// `idempotent: true` (resets idle clock + emits an event; safe to re-issue
/// — re-emission of the event under the same trace_id is the M019/M015
/// dedupe boundary's responsibility, NOT this handler's).
pub fn register_reply_tracker_host_fns(
    registry: &dyn HostRegistry,
    manager: Arc<AwaitSessionManagerImpl>,
    event_bus: Arc<dyn EventBusEmit>,
) {
    // await-leg B-2 (2026-06-22): delegate to the sink-aware variant with no
    // suspend sink → byte-identical prior behaviour. The signature stays
    // unchanged so the existing (test) callers compile untouched.
    register_reply_tracker_host_fns_with_suspend_sink(registry, manager, event_bus, None)
}

/// await-leg B-2 (2026-06-22) — sink-aware variant of
/// [`register_reply_tracker_host_fns`] that installs a [`RunSuspendSink`] on the
/// `await-replies` handler so a parked await drives the M008 Run
/// suspend/resume lifecycle (`AwaitRepliesHandler::with_run_suspend_sink`).
///
/// This is the production composition-root entry (cli `wire_capabilities`), wiring
/// the `RunManagerSuspendSink` adapter (closes MODULE-007 §3.6 R9). When
/// `run_suspend_sink` is `None` it is byte-identical to the prior sink-less
/// registration. Both `await-replies` + `heartbeat` are registered (same
/// namespace / idempotency as before). `heartbeat` does not consume the sink.
pub fn register_reply_tracker_host_fns_with_suspend_sink(
    registry: &dyn HostRegistry,
    manager: Arc<AwaitSessionManagerImpl>,
    event_bus: Arc<dyn EventBusEmit>,
    run_suspend_sink: Option<Arc<dyn RunSuspendSink>>,
) {
    let mut await_handler = AwaitRepliesHandler::new(Arc::clone(&manager));
    if let Some(sink) = run_suspend_sink {
        await_handler = await_handler.with_run_suspend_sink(sink);
    }
    registry.register(HostFunctionSpec {
        capability: "messaging".to_string(),
        namespace: "advance:runtime/agent-messaging@0.1.0".to_string(),
        name: "await-replies".to_string(),
        handler: Arc::new(await_handler),
        idempotent: false,
    });
    registry.register(HostFunctionSpec {
        capability: "messaging".to_string(),
        namespace: "advance:runtime/agent-messaging@0.1.0".to_string(),
        name: "heartbeat".to_string(),
        handler: Arc::new(HeartbeatHandler::new(manager, event_bus)),
        idempotent: true,
    });
}

/// await-leg B-3 (2026-06-22) — register the WASM `send` host-fn handler
/// ([`SendHandler`]) into a [`HostRegistry`] under capability `"messaging"` and
/// namespace `"advance:runtime/agent-messaging@0.1.0"` (the SAME namespace as
/// `await-replies`/`heartbeat`; the runtime `CapabilityInjector` routes this
/// name through its typed `register_typed_send` path). This closes the
/// `crates/runtime/wit/advance.wit:544` `send` LinkerTypecheck gap documented in
/// the [`register_reply_tracker_host_fns`] NOTE above.
///
/// SEPARATE from [`register_reply_tracker_host_fns`] / its `_with_suspend_sink`
/// variant so those functions' existing callers stay byte-identical (and so the
/// `send` handler — which needs only the `manager`, reaching the dispatcher via
/// its private field through `handle_send` — composes independently). Production
/// (cli `wiring.rs`) calls this in the `declares_messaging` block alongside the
/// reply-tracker suspend-sink registration.
///
/// `idempotent: false` — `send` is state-modifying (records a reply / delivers a
/// message). ⚠ DISTINCT from cap-channel's `send-raw` (capability `"channel"`,
/// namespace `"advance:runtime/channel-host@0.1.0"`).
pub fn register_send_host_fn(registry: &dyn HostRegistry, manager: Arc<AwaitSessionManagerImpl>) {
    register_send_host_fn_inner(registry, manager, None);
}

pub fn register_send_host_fn_with_turn_reply_routing(
    registry: &dyn HostRegistry,
    manager: Arc<AwaitSessionManagerImpl>,
    turn_reply: Arc<dyn TurnReplyRoutingPort>,
) {
    register_send_host_fn_inner(registry, manager, Some(turn_reply));
}

fn register_send_host_fn_inner(
    registry: &dyn HostRegistry,
    manager: Arc<AwaitSessionManagerImpl>,
    turn_reply: Option<Arc<dyn TurnReplyRoutingPort>>,
) {
    let handler = match turn_reply {
        Some(turn_reply) => SendHandler::new(manager).with_turn_reply_routing(turn_reply),
        None => SendHandler::new(manager),
    };
    registry.register(HostFunctionSpec {
        capability: "messaging".to_string(),
        namespace: "advance:runtime/agent-messaging@0.1.0".to_string(),
        name: "send".to_string(),
        handler: Arc::new(handler),
        idempotent: false,
    });
}

#[cfg(test)]
mod wave23_reply_result_task_id_tests {
    //! T-N1 (Wave-23 wit-widening): `rust_reply_to_wit_reply` lowers the host-internal
    //! `ReplyResult.task_id` to the guest-visible WIT `reply-result.task-id:
    //! option<string>` (Some + None arms). Pairs with the lift-side T-N2 round-trip in
    //! `capability_injector.rs::lift_await_result_ok_all_reply_status_arms`.
    use super::{decode_bounded_option_string_field, rust_reply_to_wit_reply, MAX_OPAQUE_ID_BYTES};
    use advance_shared_types::await_session::{
        AgentAwaitRequest, AwaitRequest, ReplyResult, ReplyStatus,
    };
    use wasmtime::component::Val;

    fn agent_req(correlation_id: &str) -> AwaitRequest {
        AwaitRequest::AgentRequest(AgentAwaitRequest {
            target: "agent:t".into(),
            payload: vec![],
            correlation_id: correlation_id.into(),
            context: None,
        })
    }

    fn reply(slot: u32, task_id: Option<&str>) -> ReplyResult {
        ReplyResult {
            slot,
            source: "agent:t".into(),
            payload: b"ok".to_vec(),
            status: ReplyStatus::Completed,
            received_at: chrono::Utc::now(),
            task_id: task_id.map(|s| s.to_string()),
        }
    }

    fn task_id_field(v: &Val) -> &Val {
        match v {
            Val::Record(fields) => fields
                .iter()
                .find(|(n, _)| n == "task-id")
                .map(|(_, val)| val)
                .expect("reply-result must carry a `task-id` field"),
            other => panic!("expected reply-result Record, got {other:?}"),
        }
    }

    #[test]
    fn tn1_lowers_some_task_id() {
        let reqs = vec![agent_req("corr-0")];
        let wit = rust_reply_to_wit_reply(&reply(0, Some("task-abc")), &reqs);
        match task_id_field(&wit) {
            Val::Option(Some(inner)) => {
                assert!(matches!(&**inner, Val::String(s) if s == "task-abc"))
            }
            other => panic!("expected option<string> Some, got {other:?}"),
        }
    }

    #[test]
    fn tn1_lowers_none_task_id() {
        let reqs = vec![agent_req("corr-0")];
        let wit = rust_reply_to_wit_reply(&reply(0, None), &reqs);
        assert!(matches!(task_id_field(&wit), Val::Option(None)));
    }

    // T-N3 (adversarial round 10, dual-model Warning fix): the message-context id
    // decode is length-bounded at MAX_OPAQUE_ID_BYTES — an oversized guest task-id
    // is rejected AT DECODE (before AwaitSession clones it), so it cannot amplify
    // host memory or round-trip via the reply-result.task-id echo.
    #[test]
    fn tn3_context_id_decode_is_length_bounded() {
        let opt_field = |s: Option<String>| {
            vec![(
                "task-id".to_string(),
                Val::Option(s.map(|v| Box::new(Val::String(v)))),
            )]
        };
        // At the bound (256 B) -> accepted.
        let at_bound = "a".repeat(MAX_OPAQUE_ID_BYTES);
        assert_eq!(
            decode_bounded_option_string_field(
                &opt_field(Some(at_bound.clone())),
                "task-id",
                MAX_OPAQUE_ID_BYTES
            )
            .unwrap(),
            Some(at_bound)
        );
        // One byte over the bound -> rejected (Err), never cloned into the session.
        let over = "a".repeat(MAX_OPAQUE_ID_BYTES + 1);
        assert!(decode_bounded_option_string_field(
            &opt_field(Some(over)),
            "task-id",
            MAX_OPAQUE_ID_BYTES
        )
        .is_err());
        // None -> Ok(None).
        assert_eq!(
            decode_bounded_option_string_field(&opt_field(None), "task-id", MAX_OPAQUE_ID_BYTES)
                .unwrap(),
            None
        );
    }
}

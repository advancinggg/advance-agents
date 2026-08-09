//! AC-10 per-session idle monitor.
//!
//! `idle_monitor_task` is a `tokio::spawn`ed loop, one per open session,
//! that resolves a session when it has been idle (no reply / no heartbeat /
//! no open-keeping reply) for `idle_timeout`. `resolve_idle` is the
//! promoted real idle-resolution body (previously inlined in the
//! `on_idle_timeout_for_test` test hook) — a free async fn over cloned `Arc`
//! handles (no `Arc<Self>`).
//!
//! The §1.4 AC-10 criterion (per-session idle monitor; idle ≥ timeout →
//! resolve per `TimeoutPolicy`) carries no event requirement of its own.
//! **Wave-15 Lane A (2026-06-24)**: when an `EventBusEmit` is threaded in (from
//! `ManagerOptions.event_emitter`), `resolve_idle`'s `ReturnPartial` arm emits
//! one `orchestration.await_idle_timeout` event (SYS-AC-252) — session-stable
//! envelope (caller `agent_id` + `caller_run_id` + `SessionId`), empty
//! `trace_id` (the `Event::observability` precedent; PRD §15.2-consistent — see
//! MODULE-007 §3.8). The `Fail` arm emits nothing. `None` emitter ⇒ no emit
//! (exact prior behavior). The prior "no orchestration.* event on the idle path
//! / emission belongs at the M006 host-fn layer" note is superseded for this
//! event.
//!
//! The authoritative idle clock is the manager's `liveness` index, keyed by
//! `SessionId`, holding a `tokio::time::Instant` `last_activity`.
//! `tokio::time::Instant` is clock-aware (real time in prod; driven by
//! `tokio::time::advance()` under `start_paused`), so the monitor's virtual
//! `tokio::time::sleep` tick and `last_activity.elapsed()` stay
//! virtual-time-consistent (a `std::time::Instant` would read the real
//! monotonic clock and never fire under `start_paused`).

use std::collections::HashMap;
use std::sync::Arc;

use chrono::Utc;
use tokio::sync::{Mutex, RwLock};

use advance_messaging::{PreparedTurnBatch, TurnMailboxDispatchPort};
use advance_shared_types::await_session::{
    AwaitResult, AwaitSessionStatus, OrchestrationError, ReplyStatus, SessionId, TimeoutPolicy,
};
use advance_shared_types::traits::EventBusEmit;

use crate::manager::{decrement_caller_count, LivenessRec, SessionEntry};

/// Idle-monitor tick interval (seconds). Design-fixed literal per MODULE-007
/// §1.5 / the plan's NFR row — 5 s gives 720 ticks before fire even at the
/// `MAX_IDLE_TIMEOUT_SECS_CAP` (3600 s) ceiling.
const IDLE_TICK_SECS: u64 = 5;

/// Per-session idle monitor loop. Spawned by `start()` after the
/// session-insert critical section. Resolves the session via
/// `resolve_idle` when it has been idle ≥ its `idle_timeout`.
///
/// **Race 1 (heartbeat/reply-vs-timeout)** is closed by
/// claim-under-the-deciding-lock: every tick re-locks `liveness`; if the
/// session id is absent the monitor exits (a terminal path evicted it); if
/// `last_activity.elapsed() < idle_timeout` a heartbeat or open-keeping reply
/// reset it, so the monitor drops the guard and continues; only when
/// `elapsed() >= idle_timeout` does it `remove(&sid)` **under the same
/// guard** (atomically claiming the resolution) before dropping the guard and
/// calling `resolve_idle`. A heartbeat/reply reset that lands after the claim
/// sees `None` and is a no-op.
pub(crate) async fn idle_monitor_task(
    sessions: Arc<RwLock<HashMap<SessionId, SessionEntry>>>,
    per_caller_count: Arc<Mutex<HashMap<String, usize>>>,
    liveness: Arc<std::sync::Mutex<HashMap<SessionId, LivenessRec>>>,
    turn_mailbox_dispatch: Option<Arc<dyn TurnMailboxDispatchPort>>,
    turn_batches: Arc<std::sync::Mutex<HashMap<SessionId, PreparedTurnBatch>>>,
    sid: SessionId,
    // Wave-15 Lane A: optional sink for `orchestration.await_idle_timeout`
    // (SYS-AC-252), + the effective idle-timeout threshold for the event's
    // `idle_seconds` payload. Cloned from `ManagerOptions.event_emitter` at the
    // `tokio::spawn` site; `None` ⇒ no emit (exact prior behavior).
    event_emitter: Option<Arc<dyn EventBusEmit>>,
    idle_timeout_secs: u32,
) {
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(IDLE_TICK_SECS)).await;

        // Claim-under-the-deciding-lock. `liveness` is a std-Mutex held only
        // for O(1) map ops — no `.await` inside this block.
        let claimed = {
            let mut map = liveness.lock().unwrap_or_else(|e| e.into_inner());
            match map.get(&sid) {
                // Evicted by a terminal path (reply-complete / close /
                // early-resolve / all-failed / a prior resolve_idle) → exit.
                None => return,
                Some(rec) => {
                    let timeout = std::time::Duration::from_secs(rec.idle_timeout_secs as u64);
                    if rec.last_activity.elapsed() < timeout {
                        // A heartbeat or open-keeping reply reset the clock.
                        false
                    } else {
                        // Claim: remove under the SAME guard so a concurrent
                        // reset after this point sees None and no-ops.
                        map.remove(&sid);
                        true
                    }
                }
            }
        };

        if claimed {
            resolve_idle(
                sessions,
                per_caller_count,
                liveness,
                turn_mailbox_dispatch,
                turn_batches,
                sid,
                event_emitter,
                idle_timeout_secs,
            )
            .await;
            return;
        }
        // else: not yet idle — loop and sleep again.
    }
}

/// Resolve a session that has hit its idle timeout. Promoted verbatim (in
/// behavior) from the slice-A `on_idle_timeout_for_test` body so the test
/// hook and the real monitor share one implementation.
///
/// **Race 2 (reply-completion-vs-timeout)** is closed at the `sessions`
/// layer: `on_reply` (is_complete), `close`, `early_resolve`, `all_failed`
/// and this fn all terminal-`sessions.write().remove(&sid)`; the first
/// remover is the sole oneshot sender. If a reply completed the session
/// first, `sessions.remove()` returns `None` here and we early-return — the
/// oneshot is consumed exactly once.
///
/// Behavior by [`TimeoutPolicy`] (unchanged from slice-A):
/// - `Fail`: resolve `Err(IdleTimeoutExceeded(...))`.
/// - `ReturnPartial`: unfilled slots → `TimedOut`; resolve
///   `Ok(AwaitResult { status: PartialTimeout, ... })`.
///
/// `liveness` is evicted on this path too (defensively — the monitor already
/// removed it under the claim guard, but `on_idle_timeout_for_test` reaches
/// here without the monitor's claim, so absence ⟺ resolved is preserved).
/// **Wave-15 Lane A**: the `ReturnPartial` arm emits one
/// `orchestration.await_idle_timeout` (SYS-AC-252) when `event_emitter` is
/// `Some`; the `Fail` arm emits nothing.
pub(crate) async fn resolve_idle(
    sessions: Arc<RwLock<HashMap<SessionId, SessionEntry>>>,
    per_caller_count: Arc<Mutex<HashMap<String, usize>>>,
    liveness: Arc<std::sync::Mutex<HashMap<SessionId, LivenessRec>>>,
    turn_mailbox_dispatch: Option<Arc<dyn TurnMailboxDispatchPort>>,
    turn_batches: Arc<std::sync::Mutex<HashMap<SessionId, PreparedTurnBatch>>>,
    sid: SessionId,
    // Wave-15 Lane A (SYS-AC-252): see `idle_monitor_task`.
    event_emitter: Option<Arc<dyn EventBusEmit>>,
    idle_timeout_secs: u32,
) {
    let mut sessions_guard = sessions.write().await;
    let Some((mut session, tx)) = sessions_guard.remove(&sid) else {
        // Race 2: a reply completed (or close cancelled) the session first.
        // Evict any liveness remnant and early-return — oneshot already sent.
        liveness
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&sid);
        return;
    };
    let session_id_str = session.id.0.clone();
    let mode = session.options.mode;
    let policy = session.options.on_idle_timeout;
    let now = Utc::now();
    drop(sessions_guard);

    if let Some(port) = turn_mailbox_dispatch.as_ref() {
        let batch = turn_batches
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&sid);
        if let Some(mut batch) = batch {
            // On provider failure, PreparedTurnBatch::Drop transfers every
            // retained authority into the mailbox store's bounded latch.
            let _result = port.detach_turn_batch(&sid, &mut batch);
        }
    }

    // Terminal path → evict liveness so `absence ⟺ resolved/closed`.
    liveness
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&sid);

    // Decrement per-caller count.
    let caller = session.agent_id.clone();
    decrement_caller_count(&per_caller_count, &caller).await;

    match policy {
        TimeoutPolicy::Fail => {
            let _ = tx.send(Err(OrchestrationError::IdleTimeoutExceeded(
                "idle-timeout".to_string(),
            )));
        }
        TimeoutPolicy::ReturnPartial => {
            session.fill_unresolved_as_timed_out(now);
            let replies = session.snapshot_replies_all();
            // Wave-15 Lane A (SYS-AC-252): emit orchestration.await_idle_timeout
            // BEFORE sending the oneshot. Session-stable envelope (caller
            // agent_id + caller_run_id + SessionId), empty trace_id. `target` =
            // the first timed-out slot's source (deterministic by slot order;
            // `agent:<name>` or `component:<id>`), falling back to the caller
            // when no slot source is available. `None` emitter ⇒ no emit.
            if let Some(emitter) = event_emitter.as_ref() {
                let target = replies
                    .iter()
                    .find(|r| r.status == ReplyStatus::TimedOut)
                    .map(|r| r.source.clone())
                    .unwrap_or_else(|| session.agent_id.clone());
                emitter.emit(crate::events::build_idle_timeout_event(
                    &session.agent_id,
                    session.caller_run_id.as_deref(),
                    &session.id,
                    &target,
                    idle_timeout_secs,
                ));
            }
            let result = AwaitResult {
                session_id: session_id_str,
                mode,
                replies,
                status: AwaitSessionStatus::PartialTimeout,
                ended_at: now,
            };
            let _ = tx.send(Ok(result));
        }
    }
}

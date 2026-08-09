//! `WatcherDriver` (PRD §4.3) + real `trigger-event` subscription loop.
//!
//! Slice A shipped the skeleton struct.
//! Slice B adds `run_trigger_event_subscription(id, sub, dispatcher, hook,
//! cancel_token)`:
//! - Subscribes via `dispatcher.subscribe(sub)`; rejects if REJECTED sentinel.
//! - Polls `dispatcher.drain_for_subscription(sub_id)` every 25 ms.
//! - Invokes `hook.run_once(...)` for each drained entry.
//! - RAII `UnsubscribeOnDrop` ensures cleanup on every unwind path
//!   (panic, early Err, cancel) — closes Round-1 Warning-4 leak risk.
//! - Cancellation via `CancellationToken`.
//!
//! File-watch (`notify` crate) + webhook HTTP variants are part of
//! the AC-19 watcher-variant scaffolding declared in `waived_scope`
//! (`.dev-state/state.json`).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;

use advance_shared_types::traits::EventBusEmit;

use crate::component_emit::{
    emit_component_error, emit_component_finished, emit_component_started,
};
use crate::contracts::TriggerBusDispatch;
use crate::hook::{HookError, RunnableHook};
use crate::output;
use crate::trigger_bus::TriggerBusDispatchImpl;
use crate::trigger_source::{TriggerFireEvent, TriggerSource};
use crate::types::{ComponentConfig, SubscriptionId, TriggerSubscription};

/// Slice A `WatcherDriver` skeleton + Slice B real subscribe-and-drain loop.
#[derive(Default)]
pub struct WatcherDriver;

impl WatcherDriver {
    pub fn new() -> Self {
        Self
    }

    /// Subscribe to `sub` via `dispatcher`; poll
    /// `dispatcher.drain_for_subscription(sub_id)` every 25 ms and invoke
    /// `hook` for each entry.
    ///
    /// Polling (rather than channel-based) keeps the dispatcher API
    /// surface narrow and bounded — `drain_for_subscription` is the
    /// single read API on the bus. The 25 ms cadence is the latency
    /// budget the watcher accepts in exchange for that simplicity; a
    /// per-subscription `mpsc::Receiver` upgrade is part of the full
    /// AC-19 runnable-ABI integration scaffolding declared in
    /// `waived_scope`.
    ///
    /// `UnsubscribeOnDrop` (defined in this file) RAII-guards the
    /// subscription so unwind paths (panic / cancel / early Err) all
    /// unsubscribe cleanly.
    pub async fn run_trigger_event_subscription(
        id: &str,
        sub: TriggerSubscription,
        dispatcher: Arc<TriggerBusDispatchImpl>,
        hook: Arc<dyn RunnableHook>,
        cancel_token: CancellationToken,
    ) -> Result<SubscriptionId, HookError> {
        // Preserved byte-compatibly: delegate to the emitter-aware variant
        // with no event sink (sched-residue slice, the run_periodic /
        // run_periodic_with_emitter precedent).
        Self::run_trigger_event_subscription_with_emitter(
            id,
            sub,
            dispatcher,
            hook,
            None,
            cancel_token,
        )
        .await
    }

    /// sched-residue: emitter-aware sibling of
    /// [`WatcherDriver::run_trigger_event_subscription`]. Identical
    /// poll-and-drain loop, but emits `component.started` before each
    /// drained-entry hook invocation and `component.finished` /
    /// `component.error` from the (previously fully-swallowed) result —
    /// the swallow-and-continue semantics are preserved: the loop never
    /// terminates on a hook error, the binding is the only change.
    /// `emitter == None` ⇒ behaves exactly like the pre-existing entry.
    pub async fn run_trigger_event_subscription_with_emitter(
        id: &str,
        sub: TriggerSubscription,
        dispatcher: Arc<TriggerBusDispatchImpl>,
        hook: Arc<dyn RunnableHook>,
        emitter: Option<Arc<dyn EventBusEmit>>,
        cancel_token: CancellationToken,
    ) -> Result<SubscriptionId, HookError> {
        // Audit Round-1 Warning-1 fix: use caller-supplied `id` for the
        // hook's `ComponentConfig.id` so observability/telemetry can
        // correlate hook invocations with the originating watcher
        // component. Slice A would have discarded `id` (`let _ = id`).
        let owned_id = id.to_string();
        let sub_id = dispatcher.subscribe(sub);
        if sub_id == SubscriptionId::REJECTED {
            return Err(HookError::Failure(
                "trigger-event subscription rejected (non-whitelisted or over-cap)".into(),
            ));
        }
        // From this point on, ANY return path (Ok, Err, panic unwind)
        // unsubscribes via Drop. The `unsubscribe(REJECTED)` Slice A
        // passthrough makes the early-error path above safe to skip
        // (REJECTED isn't in the index, nothing to clean up).
        let _guard = UnsubscribeOnDrop {
            dispatcher: Arc::clone(&dispatcher),
            sub_id,
        };
        // 25 ms poll (latency trade-off — adds up to ~25ms between
        // dispatch and hook invocation). The per-subscription
        // `mpsc::Receiver` upgrade that wakes the watcher task
        // immediately is part of the AC-19 runnable-ABI scaffolding
        // declared in `waived_scope`.
        //
        // Audit Round-2 Warning-2 fix: drain BEFORE sleeping so events
        // already queued at subscription time fire immediately rather
        // than waiting one poll cycle.
        //
        // Audit Round-2 Warning-1 fix: cancel-check between drained
        // entries so cancellation is bounded by ONE hook duration, not
        // batch_size × hook_duration.
        let poll_interval = Duration::from_millis(25);
        loop {
            if cancel_token.is_cancelled() {
                return Ok(sub_id);
            }
            let drained = dispatcher.drain_for_subscription(sub_id);
            for entry in drained {
                if cancel_token.is_cancelled() {
                    return Ok(sub_id);
                }
                let config = ComponentConfig {
                    id: owned_id.clone(),
                    config_data: None,
                    // sched-harvest 1B (SYS-AC-101): the drained entry's
                    // chain context (event_type / timestamp / payload /
                    // chain_id / ADVANCED depth) now reaches the runnable —
                    // the deferred Slice-C "populated from entry.event"
                    // integration. See `DispatchedEntry::to_trigger_context`
                    // for the bounded-echo payload discipline.
                    trigger_context: Some(entry.to_trigger_context()),
                };
                // Per-hook errors are swallowed and the watcher loop
                // keeps polling — the watcher's job is event delivery,
                // not application-level error handling. Per-hook
                // restart / circuit-breaker policy is part of the
                // AC-19 scaffolding declared in `waived_scope`.
                // sched-residue: bind the result for component.* emission;
                // the swallow semantics are unchanged (no break, no `?`).
                emit_component_started(emitter.as_ref(), &owned_id, "watcher");
                let run_started_at = Instant::now();
                match hook.run_once(config).await {
                    Ok(run_result) => emit_component_finished(
                        emitter.as_ref(),
                        &owned_id,
                        "watcher",
                        run_started_at.elapsed().as_millis() as u64,
                        &run_result.status,
                    ),
                    Err(HookError::Failure(msg)) => {
                        emit_component_error(emitter.as_ref(), &owned_id, "watcher", &msg);
                    }
                    Err(HookError::Cancelled) => {
                        // Swallowed like every other hook error here
                        // (pre-existing semantics); no emission.
                    }
                }
            }
            tokio::select! {
                _ = cancel_token.cancelled() => return Ok(sub_id),
                _ = sleep(poll_interval) => {}
            }
        }
    }

    /// Slice C unified entry method (AC-14 + AC-19). Drives any
    /// `Box<dyn TriggerSource>` (one of 5 resolved by `resolve_trigger`):
    /// Schedule / FileWatch / Webhook / AnyOf / TriggerEvent.
    ///
    /// Pipeline:
    /// 1. Spawn the source as a task; it sends `TriggerFireEvent` records
    ///    via a 64-bounded mpsc channel.
    /// 2. Drain the channel; per fire event, invoke `hook.run_once(...)`
    ///    and (when `output_dir` is Some) atomically write the returned
    ///    `RunResult.output` to `{output_dir}/result.bin`.
    /// 3. On cancel or source-task completion: stop draining.
    /// 4. **Source-error surface** (closes a Warning-class adversarial
    ///    gap): the source task's terminal `Result<(), HookError>` is
    ///    collected via the JoinHandle AFTER the drain loop exits. If
    ///    the source returned `Err(HookError)` (e.g.
    ///    `SubscriptionId::REJECTED` from `TriggerEventSource` on
    ///    non-whitelisted event), the watcher returns that error
    ///    instead of `Ok(())`. Race-condition-free: source completion
    ///    drops its `tx`, which causes `rx.recv()` → None and breaks
    ///    the drain loop.
    ///
    /// Event-loss bound on cancel: the drain loop exits immediately
    /// without draining `rx`, then aborts the source task. Lost-event
    /// upper bound on the cancel path = up to `channel_buffer` (= 64)
    /// already-queued events in `rx` PLUS up to 1 in-flight event in
    /// the source's `tx.send(...).await` between
    /// `drain_for_subscription` and the `await` (Slice C adversarial
    /// round 1 fix to the earlier "up to 1" claim). Slice C accepts
    /// this as the cancel-shutdown semantic; production-grade graceful
    /// drain (drain `rx` before `abort`) is a follow-up concern.
    pub async fn run_with_trigger_source(
        id: &str,
        source: Box<dyn TriggerSource>,
        hook: Arc<dyn RunnableHook>,
        output_dir: Option<PathBuf>,
        cancel: CancellationToken,
    ) -> Result<(), HookError> {
        // Preserved byte-compatibly: delegate to the emitter-aware variant
        // with no event sink (sched-residue slice, the run_periodic /
        // run_periodic_with_emitter precedent).
        Self::run_with_trigger_source_with_emitter(id, source, hook, output_dir, None, cancel).await
    }

    /// sched-residue: emitter-aware sibling of
    /// [`WatcherDriver::run_with_trigger_source`] — the unified AC-14/AC-19
    /// entry, so this is the path that future webhook/filewatch/anyof
    /// witnesses (SYS-AC-105 family) observe component.* on. Emits
    /// `component.started` before each fire's hook invocation,
    /// `component.finished` on Ok, `component.error` on
    /// `Err(HookError::Failure)` (the loop continues, pre-existing
    /// semantics); cancel paths emit nothing (orphan-started accepted
    /// posture). `emitter == None` ⇒ behaves exactly like the pre-existing
    /// entry.
    pub async fn run_with_trigger_source_with_emitter(
        id: &str,
        source: Box<dyn TriggerSource>,
        hook: Arc<dyn RunnableHook>,
        output_dir: Option<PathBuf>,
        emitter: Option<Arc<dyn EventBusEmit>>,
        cancel: CancellationToken,
    ) -> Result<(), HookError> {
        let owned_id = id.to_string();
        let (tx, mut rx) = mpsc::channel::<TriggerFireEvent>(64);
        let cancel_for_source = cancel.clone();
        let source_handle: tokio::task::JoinHandle<Result<(), HookError>> =
            tokio::spawn(async move { source.run(tx, cancel_for_source).await });
        let drain_result: Result<(), HookError> = loop {
            tokio::select! {
                _ = cancel.cancelled() => break Ok(()),
                evt = rx.recv() => {
                    let Some(evt) = evt else { break Ok(()); };
                    let config = ComponentConfig {
                        id: owned_id.clone(),
                        config_data: None,
                        trigger_context: evt.trigger_context,
                    };
                    emit_component_started(emitter.as_ref(), &owned_id, "watcher");
                    let run_started_at = Instant::now();
                    match hook.run_once(config).await {
                        Ok(run_result) => {
                            emit_component_finished(
                                emitter.as_ref(),
                                &owned_id,
                                "watcher",
                                run_started_at.elapsed().as_millis() as u64,
                                &run_result.status,
                            );
                            if let Some(dir) = output_dir.as_deref() {
                                if let Err(e) = output::write_result_to_dir(dir, &run_result).await
                                {
                                    eprintln!(
                                        "WatcherDriver::run_with_trigger_source id={:?}: write_result_to_dir failed: {}",
                                        owned_id, e
                                    );
                                }
                            }
                        }
                        Err(HookError::Cancelled) => break Ok(()),
                        Err(HookError::Failure(msg)) => {
                            // Slice B/C precedent: per-hook errors don't
                            // terminate the watcher loop — the watcher's
                            // job is event delivery, not application-level
                            // error handling. sched-residue: the structured
                            // surface is component.error.
                            emit_component_error(emitter.as_ref(), &owned_id, "watcher", &msg);
                        }
                    }
                }
            }
        };
        // Drain loop terminated. Abort the source task (idempotent
        // against an already-completed task) then collect its terminal
        // Result via the JoinHandle — surface source errors back to the
        // caller. If source's task panicked or was aborted mid-flight,
        // prefer the drain_result.
        source_handle.abort();
        match source_handle.await {
            Ok(Ok(())) => drain_result,
            Ok(Err(source_err)) => Err(source_err),
            Err(join_err) if join_err.is_panic() => {
                // Slice C adversarial round 2 fix (W2): mirror
                // AnyOfTriggerSource's panic-detection pattern so a
                // panicking source impl (e.g. user-pluggable
                // FileWatchSource / WebhookSource with `.unwrap()`)
                // surfaces as Err(HookError::Failure) rather than
                // silently returning the drain_result.
                Err(HookError::Failure(format!(
                    "WatcherDriver source task panicked: {join_err}"
                )))
            }
            Err(_join_err) => drain_result, // aborted or cancelled
        }
    }
}

/// RAII unsubscribe guard. On any unwind path inside
/// `run_trigger_event_subscription` (panic, early `Err`, normal `Ok` after
/// the loop exits), `Drop` calls `unsubscribe(sub_id)` so the subscription
/// doesn't leak. The Slice A `unsubscribe(REJECTED)` sentinel-passthrough
/// keeps the no-op case safe.
struct UnsubscribeOnDrop {
    dispatcher: Arc<TriggerBusDispatchImpl>,
    sub_id: SubscriptionId,
}

impl Drop for UnsubscribeOnDrop {
    fn drop(&mut self) {
        self.dispatcher.unsubscribe(self.sub_id);
    }
}

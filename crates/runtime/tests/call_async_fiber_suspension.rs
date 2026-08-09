//! Slice AD — MODULE-001-AC-14 closure: `call_async` fiber suspension at host-fn await.
//!
//! Materializes §3.3 T12: "host fn calls await-replies equivalent → WASM fiber suspends,
//! other Tokio tasks run".
//!
//! AC-14 §1.5 criterion:
//! > Wasmtime `call_async` is used for entry-point invocation so host functions can
//! > suspend the WASM fiber at `await-replies`. (REQ-043 ownership: MODULE-001 owns
//! > the host-side `call_async` integration; MODULE-007 await-orchestration owns the
//! > orchestration semantics.)
//!
//! Test vehicle: bare-Linker pattern (Slice V `wasi_linker.rs` precedent for the
//! linker construction; Slice AB T55 `execution_budget.rs` precedent for the
//! wedge-resistant harness shape). Inline Component WAT imports
//! `test:fiber/wait` (no-arg, no-result) and exports `run` calling it. The host
//! fn registered via `LinkerInstance::func_new_async` awaits a `tokio::sync::Notify`,
//! exercising wasmtime's fiber-async suspension primitive.
//!
//! Harness: plain `#[test]` on the cargo-test main thread; `std::thread::spawn`
//! a guest thread hosting `Builder::new_current_thread().enable_all()` tokio
//! runtime; main-thread `std::sync::mpsc::Receiver::recv_timeout` watchdog
//! independent of any tokio executor (T55 precedent for wedge resistance).
//!
//! Scope boundary: T42 architectural guard preserved by NOT modifying
//! `crates/runtime/wit/advance.wit` (advance-host world stays zero-import).
//! Production `instantiate_advance_host_async` end-to-end and CapabilityInjector ×
//! fiber-suspension cross-product remain waived per §3.6 deferrals.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use advance_runtime::{
    capability_injector::ComponentCtx, component_loader::ComponentRuntime, config::WasmConfig,
};

/// Component WAT importing `test:fiber/wait` and exporting `run` that calls it
/// once. Empty-signature `(func)` shorthand at component level mirrors the
/// existing precedent at `crates/runtime/tests/capability_injector.rs:247` /
/// `:303`. No-result canonical-ABI lift/lower is trivial (no realloc / no
/// post-return required).
const FIBER_WAT: &str = r#"
(component
  (import "test:fiber/wait" (instance $h
    (export "wait" (func))
  ))
  (core func $wait_lowered (canon lower (func $h "wait")))
  (core module $m
    (import "test:fiber" "wait" (func $wait_imp))
    (func (export "run") call $wait_imp)
  )
  (core instance $i (instantiate $m
    (with "test:fiber" (instance (export "wait" (func $wait_lowered))))
  ))
  (func (export "run") (canon lift (core func $i "run")))
)
"#;

fn wasm_cfg() -> WasmConfig {
    // Mirror the helper in tests/capability_injector.rs and tests/wasi_linker.rs.
    // Engine has `epoch_interruption(true)` per Decision 16; raw stores' default
    // deadline=0 is "already elapsed" per §3.6 mixed-use caveat — the test arms
    // it with `set_epoch_deadline(u64::MAX/2)` below.
    WasmConfig {
        max_memory_pages: 256,
        epoch_interruption_ms: 100,
        fuel_enabled: false,
    }
}

/// Diagnostic taxonomy for the main-thread mpsc watchdog. Mirrors T55's
/// `SetupComplete` / `YieldObserved` / `GuestReturnedEarly` 3-variant pattern,
/// extended with four T12-specific variants
/// (`SiblingObservedSuspension` / `SiblingMaxItersExhausted` /
/// `GuestCallTimedOut` / `GuestThreadFailure`) to disambiguate
/// fiber-suspension wiring failures from post-resume wedges from genuine pass
/// from guest-thread panics.
#[derive(Debug)]
enum T12Msg {
    /// Setup phase completed (parse WAT → load Component → register host fn →
    /// build raw Store → instantiate). Anything before this is OUTSIDE
    /// fiber-suspension scope.
    SetupComplete,
    /// Sibling observed `host_fn_entered=true` and called `notify.notify_one()`.
    /// Proves (a) `entered.store(true)` ran inside the host fn body and (b)
    /// `guest_call.poll()` returned Pending at the host fn's
    /// `notify.notified().await`, freeing the executor to schedule sibling.
    SiblingObservedSuspension,
    /// Sibling exhausted MAX_ITERS yields without ever observing
    /// `host_fn_entered=true`. Indicates fiber-suspension wiring is broken
    /// (call_async did not yield to the executor at the host fn await).
    SiblingMaxItersExhausted,
    /// Guest call returned `Ok(())` within the inner 8s timeout AND the
    /// in-thread `assert!(host_fn_resumed)` passed (closure body ran past
    /// `notify.notified().await`).
    GuestCallCompletedOk,
    /// Guest call returned `Err(_)` within the inner 8s timeout. Carries the
    /// wasmtime error text for the main-thread diagnostic panic.
    GuestCallFailed(String),
    /// Inner 8s `tokio::time::timeout` fired. Indicates a wedge inside the
    /// wasmtime poll loop OR sibling failed to schedule
    /// `notify.notify_one()` in time.
    GuestCallTimedOut,
    /// Adversarial-fix R1 (overall round 9): captures any panic from inside
    /// the guest thread (e.g., a `.expect(...)` that fires before
    /// `SetupComplete` is sent). Without this variant, a guest-thread panic
    /// appears to the main thread as an opaque "phase-1 timeout" — masking
    /// the real failure mode and leaving a detached `JoinHandle` orphan.
    /// `catch_unwind` around the `rt.block_on` call surfaces the panic
    /// payload as a String.
    GuestThreadFailure(String),
}

#[test]
fn module_001_t12_call_async_fiber_suspension_at_await() {
    let (tx, rx) = std::sync::mpsc::channel::<T12Msg>();

    // Adversarial-fix R1 (overall round 9): wrap rt.block_on in
    // std::panic::catch_unwind so a panic inside the guest thread (e.g., an
    // .expect(...) firing before SetupComplete is sent) is captured and
    // surfaced as a T12Msg::GuestThreadFailure rather than dying silently and
    // letting the main-thread phase-1 watchdog report a misleading "OUTSIDE
    // fiber-suspension scope" timeout. Bind the JoinHandle (NOT `_guest_thread`)
    // so the main thread can `.join()` it at the end of the test for clean
    // OS-thread cleanup — addresses the "orphan thread" concern raised by both
    // adversarial evaluators.
    //
    // AssertUnwindSafe is acceptable here because the closure ends with the
    // tokio runtime being dropped; any captured state is local to this thread
    // and is not observed by other threads after the panic. The guest thread
    // does not modify any shared state visible to the main thread — all
    // signaling goes through the mpsc channel.
    let guest_thread = std::thread::Builder::new()
        .name("t12-guest".into())
        .spawn({
            let tx = tx.clone();
            move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .expect("build current_thread tokio runtime");
                    rt.block_on(t12_guest_thread_body(tx.clone()));
                }));
                if let Err(panic_payload) = result {
                    let msg = panic_payload
                        .downcast_ref::<&str>()
                        .map(|s| (*s).to_string())
                        .or_else(|| panic_payload.downcast_ref::<String>().cloned())
                        .unwrap_or_else(|| "<non-string panic payload>".to_string());
                    let _ = tx.send(T12Msg::GuestThreadFailure(msg));
                }
            }
        })
        .expect("spawn t12-guest thread");

    // Phase 1 watchdog: wait for SetupComplete (10s).
    // A failure here points to fixture / runtime / instantiate problems,
    // NOT to fiber suspension. Distinct diagnostic per T55 precedent.
    // Adversarial-fix R1 + R2: handle T12Msg::GuestThreadFailure so a
    // pre-SetupComplete panic surfaces with the actual panic message. DO NOT
    // call `guest_thread.join()` on a phase-1 failure path — if the guest
    // thread is wedged in setup (instantiate_async spinloop, fixture load
    // hang), join blocks the main thread forever and converts a clean
    // loud-panic into a silent CI hang. R2 adversarial Codex Warning drove
    // this correction: join is ONLY safe on paths where we have
    // positive evidence the guest thread body has returned (i.e., we
    // received a terminal GuestCall* or GuestThreadFailure message).
    let phase1_panic: Option<(String, bool /* guest body returned */)> =
        match rx.recv_timeout(Duration::from_secs(10)) {
            Ok(T12Msg::SetupComplete) => None,
            // GuestThreadFailure proves catch_unwind completed AND tx.send
            // succeeded AND the spawn closure is returning — guest body is
            // known to have exited. Safe to join.
            Ok(T12Msg::GuestThreadFailure(msg)) => Some((
                format!("T12: guest thread panicked before SetupComplete — actual cause: {msg}"),
                true,
            )),
            // Unexpected message is a logic error, not a wedge; body might
            // still be running (it sent an unexpected message but hasn't
            // returned yet). Skip join to avoid a possible hang.
            Ok(other) => Some((
                format!("T12: unexpected first message from guest thread: {other:?}"),
                false,
            )),
            // Timeout: guest thread is possibly wedged in setup. DO NOT join
            // (would hang indefinitely). Accept the orphan OS thread; the
            // cargo-test process exit will reap it.
            Err(_) => Some((
                String::from(
                    "T12: guest thread did not send SetupComplete within 10s — \
                     investigate ComponentRuntime::new / wat::parse_str / \
                     load_component / linker.instance(...) / func_new_async / \
                     Store::new / instantiate_pre / instantiate_async / get_func / \
                     typed::<(), ()> — failure is OUTSIDE fiber-suspension scope. \
                     (No GuestThreadFailure was received either, so the guest \
                     thread is wedged or panicked silently before catch_unwind \
                     could fire. Guest OS thread is NOT joined — orphan \
                     accepted; process exit will reap.)",
                ),
                false,
            )),
        };
    if let Some((msg, safe_to_join)) = phase1_panic {
        if safe_to_join {
            let _ = guest_thread.join();
        }
        panic!("{}", msg);
    }

    // Phase 2 watchdog: drain remaining messages within 15s. Expect
    // SiblingObservedSuspension and GuestCallCompletedOk in some order.
    let mut sibling_observed = false;
    let mut sibling_max_iters = false;
    let mut guest_completed_ok = false;
    let mut guest_failed: Option<String> = None;
    let mut guest_timed_out = false;
    let mut guest_thread_failure: Option<String> = None;

    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline && (!sibling_observed || !guest_completed_ok) {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match rx.recv_timeout(remaining) {
            Ok(T12Msg::SiblingObservedSuspension) => sibling_observed = true,
            Ok(T12Msg::SiblingMaxItersExhausted) => {
                // R3 adversarial fix Codex W1: previously broke early
                // (audit-fix R1 Info #5), but a guest body that sends
                // GuestCallFailed quickly before the host fn is ever invoked
                // ALSO triggers SiblingMaxItersExhausted (sibling polled
                // MAX_ITERS without observing entered=true because the call
                // errored before reaching the host fn). Breaking early here
                // would mask the more informative GuestCallFailed diagnostic.
                // R3 fix: just record the flag and continue draining the
                // channel for the full 15s window. The cascade below
                // prioritizes GuestCallFailed / GuestCallTimedOut /
                // GuestThreadFailure over sibling_max_iters so the more
                // informative root-cause wins when both arrive.
                sibling_max_iters = true;
            }
            Ok(T12Msg::GuestCallCompletedOk) => guest_completed_ok = true,
            Ok(T12Msg::GuestCallFailed(e)) => {
                guest_failed = Some(e);
                break;
            }
            Ok(T12Msg::GuestCallTimedOut) => {
                guest_timed_out = true;
                break;
            }
            Ok(T12Msg::GuestThreadFailure(msg)) => {
                // Adversarial-fix R1: guest thread panicked AFTER SetupComplete
                // (e.g., the in-thread `assert!(host_fn_resumed)` fired).
                // Surface the actual panic message instead of letting the
                // watchdog conflate it with a wedge.
                guest_thread_failure = Some(msg);
                break;
            }
            Ok(T12Msg::SetupComplete) => {
                // R3 adversarial fix Claude W1: this defensive panic was
                // silently orphaning the guest thread without the
                // orphan-accepted disclaimer that other safe_to_join=false
                // paths carry. The duplicate-SetupComplete case is structurally
                // impossible (the guest body sends SetupComplete exactly once),
                // but if a future refactor breaks that invariant, surface the
                // orphan-acceptance like the other wedge-suspect paths.
                panic!(
                    "T12: duplicate SetupComplete from guest thread — guest body \
                     may still be running. (Guest OS thread is NOT joined — orphan \
                     accepted; process exit will reap.)"
                );
            }
            Err(_) => break, // timeout — fall through to diagnostic assertions
        }
    }

    // Adversarial-fix R1 + R2: compute diagnostic panic message first, decide
    // whether the guest thread is in a known-completed state (safe to join)
    // or possibly-wedged state (skip join — accept orphan), then optionally
    // join, then panic. Single move site for `guest_thread` keeps the
    // borrow-checker happy.
    //
    // R2 correction: NEVER join unconditionally on diagnostic paths where the
    // guest thread might still be wedged — that converts a loud panic into a
    // silent CI hang, defeating the wedge-resistant design. Join is safe ONLY
    // when we received a terminal message (GuestCall* / GuestThreadFailure)
    // proving the guest body has returned. On wedge-suspect paths
    // (SiblingMaxItersExhausted; phase-2 silence), accept the OS-thread
    // orphan; cargo-test process exit will reap it.
    //
    // GuestThreadFailure is checked FIRST so a captured panic from inside
    // the guest thread surfaces with the actual message rather than being
    // masked by downstream sibling/timeout diagnostics.
    let (panic_msg, safe_to_join): (Option<String>, bool) = if let Some(msg) = guest_thread_failure
    {
        // Guest body returned (catch_unwind unwound, tx.send completed,
        // spawn closure returned). Safe to join.
        (
            Some(format!(
                "T12: guest thread panicked after SetupComplete — actual cause: {msg}"
            )),
            true,
        )
    } else if let Some(err) = guest_failed {
        // R3 adversarial fix Codex W1: GuestCallFailed must be checked BEFORE
        // sibling_max_iters. A regression where wasmtime's call_async
        // produces an Err before invoking the host fn would emit BOTH
        // SiblingMaxItersExhausted (sibling never observed entered=true) AND
        // GuestCallFailed(err). The wasmtime error is the actual root cause;
        // the sibling-exhaustion is a downstream symptom. Prioritize the
        // root cause. Guest body returned — safe to join.
        (Some(format!("T12: guest call returned Err: {err}")), true)
    } else if guest_timed_out {
        // Inner 8s tokio::time::timeout fired; that means the executor WAS
        // being polled (the timer future got Pending-Ready'd), so the guest
        // body's `match guest_result` arm ran and sent GuestCallTimedOut
        // before returning. Safe to join.
        (
            Some(format!(
                "T12: guest call did not complete within the inner 8s timeout — \
                 call_async wedged inside the wasmtime poll loop OR sibling failed \
                 to schedule notify.notify_one() in time. If SiblingObservedSuspension \
                 arrived (sibling_observed={sibling_observed}), the wedge is \
                 post-resume (notify fired but fiber didn't resume); otherwise the \
                 wedge is pre-suspension."
            )),
            true,
        )
    } else if sibling_max_iters {
        // R3 adversarial fix Codex W1: this branch fires ONLY when sibling
        // exhausted MAX_ITERS AND no GuestCallFailed/TimedOut/ThreadFailure
        // arrived in the 15s phase-2 window. That means the guest body is
        // truly wedged (call_async never returned Pending OR is still
        // waiting for the notify_one sibling never sent). DO NOT join —
        // possible hang.
        (
            Some(String::from(
                "T12: sibling task polled MAX_ITERS yields without observing \
                 host_fn_entered=true — fiber-suspension wiring is broken. \
                 call_async did not return Pending to the executor at the host fn \
                 notify.notified().await suspension point. Sibling never got to \
                 schedule notify.notify_one(), so guest call would also wedge \
                 waiting for resume signal. (Guest OS thread is NOT joined — \
                 orphan accepted; process exit will reap.)",
            )),
            false,
        )
    } else if !guest_completed_ok && !sibling_observed {
        // Phase-2 silence: no terminal message arrived within 15s. Guest
        // thread may be wedged. DO NOT join.
        (
            Some(String::from(
                "T12: neither GuestCallCompletedOk nor SiblingObservedSuspension \
                 received within 15s — guest thread wedged completely (wasmtime \
                 poll spinloop or executor stuck) or panicked silently. \
                 Main-thread mpsc watchdog fired. (Guest OS thread is NOT \
                 joined — orphan accepted; process exit will reap.)",
            )),
            false,
        )
    } else if !sibling_observed {
        // guest_completed_ok is true → guest body returned. Safe to join.
        (
            Some(String::from(
                "T12: guest call completed but sibling never observed fiber suspension \
                 — guest call may have run synchronously without yielding (regression: \
                 host fn body did not actually await, so cooperative-scheduling proof \
                 vacuously held)",
            )),
            true,
        )
    } else if !guest_completed_ok {
        // sibling_observed is true but no GuestCall* terminal message
        // arrived. Guest body may be wedged after sibling's notify_one
        // fired (post-resume wedge). DO NOT join.
        (
            Some(String::from(
                "T12: guest call did not complete OK within 15s watchdog \
                 (Guest OS thread is NOT joined — orphan accepted; process \
                 exit will reap.)",
            )),
            false,
        )
    } else {
        // Pass path: both flags set, all messages received cleanly. Guest
        // body returned. Safe to join.
        (None, true)
    };

    if safe_to_join {
        let _ = guest_thread.join();
    }

    if let Some(msg) = panic_msg {
        panic!("{}", msg);
    }
}

async fn t12_guest_thread_body(tx: std::sync::mpsc::Sender<T12Msg>) {
    let runtime = ComponentRuntime::new(&wasm_cfg()).expect("runtime");
    let component_bytes = wat::parse_str(FIBER_WAT).expect("parse FIBER_WAT");
    let loaded = runtime
        .load_component(&component_bytes)
        .expect("load Component");

    // Coordination primitives shared with the host fn closure and sibling task.
    let notify = Arc::new(tokio::sync::Notify::new());
    let host_fn_entered = Arc::new(AtomicBool::new(false));
    let host_fn_resumed = Arc::new(AtomicBool::new(false));

    // Build a custom Linker; register `wait` host fn via `func_new_async`.
    // Closure arity is FOUR per `LinkerInstance::func_new_async` in wasmtime
    // 43.0.1 — `Fn(StoreContextMut<'a, T>, types::ComponentFunc, &'a [Val],
    // &'a mut [Val]) -> Box<dyn Future<Output = Result<()>> + Send + 'a>`. The
    // existing `crates/runtime/src/capability_injector.rs:212` confirms the
    // 4-arg shape: `move |store_ctx, _component_func, params, results|`.
    let mut linker: wasmtime::component::Linker<ComponentCtx> =
        wasmtime::component::Linker::new(runtime.host_engine_handle().engine());
    {
        let notify_for_handler = notify.clone();
        let entered_for_handler = host_fn_entered.clone();
        let resumed_for_handler = host_fn_resumed.clone();
        let mut instance = linker.instance("test:fiber/wait").expect("instance");
        instance
            .func_new_async("wait", move |_store, _component_func, _params, _results| {
                let notify = notify_for_handler.clone();
                let entered = entered_for_handler.clone();
                let resumed = resumed_for_handler.clone();
                Box::new(async move {
                    entered.store(true, Ordering::SeqCst);
                    notify.notified().await; // <-- fiber suspends here
                    resumed.store(true, Ordering::SeqCst);
                    Ok(())
                })
            })
            .expect("register wait fn");
    }

    // Build raw Store. Engine has `epoch_interruption(true)`; arm deadline far
    // out so default trap behavior never fires. No ticker is spawned on the
    // bare-Store path (lazy spawn only via `instantiate_advance_host_async`,
    // which we deliberately do NOT call), so the engine's epoch never advances
    // past 0 — the deadline of `u64::MAX / 2` is unreachable in practice.
    let ctx = ComponentCtx::new("agent-t12".into(), "trace-t12".into(), Vec::new());
    let mut store = wasmtime::Store::new(runtime.host_engine_handle().engine(), ctx);
    store.set_epoch_deadline(u64::MAX / 2);

    let pre = linker
        .instantiate_pre(loaded.component())
        .expect("instantiate_pre");
    let instance = pre
        .instantiate_async(&mut store)
        .await
        .expect("instantiate_async");
    let run_func = instance
        .get_func(&mut store, "run")
        .expect("export `run` present");
    let typed: wasmtime::component::TypedFunc<(), ()> =
        run_func.typed::<(), ()>(&store).expect("typed::<(), ()>");

    // Setup is complete — main thread can advance to phase 2 watchdog.
    let _ = tx.send(T12Msg::SetupComplete);

    // Spawn sibling on the SAME current_thread runtime. If fiber suspension
    // works, guest_call.poll() returns Pending at the host fn await, allowing
    // this sibling to be polled.
    let tx_sibling = tx.clone();
    let sibling = {
        let entered = host_fn_entered.clone();
        let notify = notify.clone();
        tokio::spawn(async move {
            const MAX_ITERS: usize = 10_000;
            for _ in 0..MAX_ITERS {
                if entered.load(Ordering::SeqCst) {
                    let _ = tx_sibling.send(T12Msg::SiblingObservedSuspension);
                    notify.notify_one();
                    return;
                }
                tokio::task::yield_now().await;
            }
            // MAX_ITERS exhausted — sibling never observed entered=true. The
            // host fn body never ran, OR call_async never returned Pending so
            // the executor never scheduled this sibling. Either way, fiber
            // suspension is not behaving as required.
            let _ = tx_sibling.send(T12Msg::SiblingMaxItersExhausted);
        })
    };

    // Drive guest call. Inner timeout is a safety net; main-thread mpsc
    // watchdog is the load-bearing one. wasmtime 43.0.1 marks
    // `TypedFunc::post_return_async` as
    // `#[deprecated(note = "no longer needs to be called; this function has
    // no effect")]` (verified in
    // wasmtime-43.0.1/src/runtime/component/func/typed.rs:568-576) — its body
    // returns Ok(()) with no side effects because `call_async` invokes
    // `post_return_impl` internally. So we do NOT call it.
    let guest_result = tokio::time::timeout(Duration::from_secs(8), async {
        typed.call_async(&mut store, ()).await?;
        Result::<(), wasmtime::Error>::Ok(())
    })
    .await;

    // Best-effort reap the sibling task (it should be done by now since the
    // host fn could only resume via sibling.notify_one()).
    let _ = sibling.await;

    match guest_result {
        Ok(Ok(())) => {
            // Belt-and-suspenders check: closure body must have run past the await.
            assert!(
                host_fn_resumed.load(Ordering::SeqCst),
                "host fn closure did not resume past notify.notified().await even \
                 though guest call returned Ok — invariant broken"
            );
            let _ = tx.send(T12Msg::GuestCallCompletedOk);
        }
        Ok(Err(e)) => {
            let _ = tx.send(T12Msg::GuestCallFailed(format!("{e}")));
        }
        Err(_elapsed) => {
            let _ = tx.send(T12Msg::GuestCallTimedOut);
        }
    }
}

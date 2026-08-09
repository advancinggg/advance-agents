//! Slice AB — WASM execution-budget hardening integration tests.
//!
//! - T53: `memory.grow` beyond `max_memory_pages` returns -1 (StoreLimits rejects).
//! - T54: `memory.grow` within `max_memory_pages` succeeds (returns previous pages).
//! - T55: Tight-loop guest cooperatively yields via
//!   `Store::epoch_deadline_async_yield_and_update` + OS-thread ticker.
//!
//! Tests route through `ComponentRuntime::instantiate_advance_host_async` to exercise
//! the Slice AB wiring end-to-end (lazy ticker spawn, `apply_host_execution_budget`
//! helper installing `StoreLimits` + yield config).
//!
//! The extended `guest-rust-minimal` fixture branches on `config.config_data`:
//! - `Some(b"grow:N")` — `core::arch::wasm32::memory_grow(0, N)` returning prev pages
//!   (or `usize::MAX` on failure, which cast to i32 is `-1`).
//! - `Some(b"loop")` — infinite `loop { core::hint::spin_loop() }`.
//! - Other — existing sentinel bytes (`[0xAD, 0x11, 0xCE, 0x02]`).

use advance_runtime::{
    config::WasmConfig, wit_bindings::advance::runtime::types as wit_types, ComponentCtx,
    ComponentRuntime,
};
use wit_component::ComponentEncoder;

const CORE_MODULE_BYTES: &[u8] = include_bytes!("fixtures/guest-rust-minimal.core.wasm");

fn wasm_cfg_with_pages(max_pages: u32) -> WasmConfig {
    WasmConfig {
        max_memory_pages: max_pages,
        epoch_interruption_ms: 100,
        fuel_enabled: false,
    }
}

fn ctx() -> ComponentCtx {
    ComponentCtx::new(
        "agent-exec-budget".into(),
        "trace-exec-budget".into(),
        Vec::new(),
    )
}

fn rust_guest_component_bytes() -> Vec<u8> {
    ComponentEncoder::default()
        .validate(true)
        .module(CORE_MODULE_BYTES)
        .expect("core module accepted by ComponentEncoder")
        .encode()
        .expect("component encoded")
}

async fn call_run_with_config_data(
    runtime: &ComponentRuntime,
    max_pages: u32,
    config_data: Option<Vec<u8>>,
) -> Result<wit_types::RunResult, String> {
    let _ = max_pages; // currently carried via the outer runtime; kept for traceability
    let component_bytes = rust_guest_component_bytes();
    let loaded = runtime
        .load_component(&component_bytes)
        .expect("guest component loads");
    let (bindings, mut store) = runtime
        .instantiate_advance_host_async(&loaded, ctx())
        .await
        .expect("instantiate");

    let cfg = wit_types::ComponentConfig {
        id: "t-exec".into(),
        config_data,
        trigger_context: None,
    };
    bindings
        .advance_runtime_runnable()
        .call_run(&mut store, &cfg)
        .await
        .expect("call_run returns")
}

fn decode_le_i32(bytes: &[u8]) -> i32 {
    assert_eq!(bytes.len(), 4, "output must be 4 bytes (le-encoded i32)");
    let mut arr = [0u8; 4];
    arr.copy_from_slice(bytes);
    i32::from_le_bytes(arr)
}

#[tokio::test]
async fn module_001_t53_memory_grow_beyond_cap_rejected() {
    let runtime = ComponentRuntime::new(&wasm_cfg_with_pages(256)).expect("runtime");

    let run_result = call_run_with_config_data(&runtime, 256, Some(b"grow:300".to_vec()))
        .await
        .expect("run returns Ok");

    assert!(
        matches!(run_result.status, wit_types::RunStatus::Completed),
        "status should be Completed (guest returns Ok even on grow failure)"
    );
    let output = run_result.output.expect("output bytes present");
    let grow_result = decode_le_i32(&output);
    assert_eq!(
        grow_result, -1,
        "memory.grow(300) with max_memory_pages=256 must be rejected by StoreLimits, returning -1"
    );
}

#[tokio::test]
async fn module_001_t54_memory_grow_within_cap_permitted() {
    let runtime = ComponentRuntime::new(&wasm_cfg_with_pages(256)).expect("runtime");

    let run_result = call_run_with_config_data(&runtime, 256, Some(b"grow:100".to_vec()))
        .await
        .expect("run returns Ok");

    assert!(matches!(run_result.status, wit_types::RunStatus::Completed));
    let output = run_result.output.expect("output bytes present");
    let grow_result = decode_le_i32(&output);
    assert!(
        grow_result >= 0,
        "memory.grow(100) with max_memory_pages=256 must succeed and return previous page count (>=0), got {}",
        grow_result
    );
}

/// T55 — cooperative yield via OS-thread epoch ticker + async_yield_and_update.
///
/// Wedge-resistant design: plain `#[test]` (NOT `#[tokio::test]`). Guest runs on a
/// dedicated `std::thread` with its own current_thread tokio runtime. Main thread
/// uses `std::sync::mpsc::Receiver::recv_timeout` — a stdlib primitive independent
/// of any tokio executor, so a wedged guest thread CANNOT block the main watchdog.
///
/// Three-outcome protocol (R5 disambiguation):
/// - `Err(Elapsed)` from `tokio::time::timeout(3s, call_run)` → guest thread sends
///   `T55Msg::YieldObserved`; main thread reports pass.
/// - `Ok(_)` (guest completed within 3s — trap or early return) → guest thread
///   sends `T55Msg::GuestReturnedEarly { is_ok }`; main thread reports
///   "guest completed unexpectedly" (NOT a yield-wedge diagnostic).
/// - No message within 5s → guest thread wedged on tight-loop; main thread reports
///   "cooperative yield broken".
/// T55 message taxonomy sent from the guest thread to the main watchdog.
///
/// Three phases are distinguished so the main-thread watchdog can report the
/// SPECIFIC failure mode rather than conflating distinct failures into "yield
/// broken":
///
/// - `SetupComplete`: fires after `instantiate_advance_host_async` succeeds and
///   BEFORE the tight-loop guest call. Without this sentinel, a setup failure
///   (fixture load / runtime build / instantiate) would present identically to a
///   true yield wedge.
/// - `YieldObserved`: fires when `tokio::time::timeout(3s, call_run)` returned
///   `Err(Elapsed)` — i.e., the guest ran for 3 full seconds WITHOUT ever
///   returning. This is the "cooperative yield works" signal (timer future got
///   polled at yield points and fired at 3s).
/// - `GuestReturnedEarly(bool)`: fires when `call_run` ITSELF completed within
///   the 3s timeout (unexpected for a tight-loop guest). The bool carries
///   `result.is_ok()` for diagnostic context. This happens when the guest
///   traps (e.g., wasmtime epoch-interruption, stack overflow) or unexpectedly
///   returns. Main thread can then report "guest completed unexpectedly"
///   rather than "yield broken".
#[derive(Debug)]
enum T55Msg {
    SetupComplete,
    YieldObserved,
    GuestReturnedEarly { is_ok: bool },
}

#[test]
fn module_001_t55_tight_loop_cooperative_yield() {
    let (tx, rx) = std::sync::mpsc::channel::<T55Msg>();

    let _guest_thread = std::thread::Builder::new()
        .name("t55-guest".into())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("build guest tokio runtime");
            rt.block_on(async move {
                let runtime = ComponentRuntime::new(&wasm_cfg_with_pages(256)).expect("runtime");
                let component_bytes = rust_guest_component_bytes();
                let loaded = runtime
                    .load_component(&component_bytes)
                    .expect("guest component loads");
                let (bindings, mut store) = runtime
                    .instantiate_advance_host_async(&loaded, ctx())
                    .await
                    .expect("instantiate");

                let cfg = wit_types::ComponentConfig {
                    id: "t55".into(),
                    config_data: Some(b"loop".to_vec()),
                    trigger_context: None,
                };

                // Send SetupComplete BEFORE entering the tight-loop guest call.
                // The main thread requires this sentinel before starting the
                // yield watchdog — otherwise a setup failure would masquerade
                // as a yield-wedge failure.
                let _ = tx.send(T55Msg::SetupComplete);

                // This call enters the guest's tight-loop branch. It should NEVER
                // return naturally. `tokio::time::timeout` wraps it — if cooperative
                // yield works, the timer future gets polled at yield points and
                // fires after 3s with Err(Elapsed). If yield is broken, the guest
                // monopolizes this thread's executor and the timeout never fires.
                let result = tokio::time::timeout(
                    std::time::Duration::from_secs(3),
                    bindings
                        .advance_runtime_runnable()
                        .call_run(&mut store, &cfg),
                )
                .await;

                // Disambiguate three outcomes for the main-thread watchdog:
                // - Err(Elapsed): timeout fired (yield works).
                // - Ok(inner): call_run completed within 3s (unexpected — trap or
                //   early return). Forward the inner Ok/Err state so the main
                //   thread can report "guest completed unexpectedly" rather than
                //   masking the event as a yield wedge.
                match result {
                    Err(_elapsed) => {
                        let _ = tx.send(T55Msg::YieldObserved);
                    }
                    Ok(inner) => {
                        let _ = tx.send(T55Msg::GuestReturnedEarly {
                            is_ok: inner.is_ok(),
                        });
                    }
                }
            });
        })
        .expect("spawn guest thread");

    // Main thread watchdog: two-phase protocol, disambiguates setup vs yield failures.
    //
    // Phase 1: wait for SetupComplete. A setup failure (panic) or timeout here
    // indicates a problem OUTSIDE the yield-wedge scope (fixture load, runtime
    // build, instantiate).
    match rx.recv_timeout(std::time::Duration::from_secs(10)) {
        Ok(T55Msg::SetupComplete) => {
            // Setup succeeded. Now watch for YieldObserved within 5s.
        }
        Ok(other) => {
            panic!(
                "T55: unexpected first message from guest thread: {:?}",
                other
            );
        }
        Err(_) => {
            panic!(
                "T55: guest thread did not complete SETUP within 10s — the failure \
                 is in ComponentRuntime construction / load_component / instantiate, \
                 NOT in cooperative yield. Investigate the guest thread's panic/error."
            );
        }
    }

    // Phase 2: now that setup is confirmed complete, disambiguate three outcomes:
    //   Ok(YieldObserved)            → cooperative yield works (pass).
    //   Ok(GuestReturnedEarly{...})  → guest completed unexpectedly (trap / early
    //                                  return) — NOT a yield-wedge diagnostic.
    //   Err(_)                       → true yield wedge (no message sent within
    //                                  5s; guest thread stuck in tight-loop).
    match rx.recv_timeout(std::time::Duration::from_secs(5)) {
        Ok(T55Msg::YieldObserved) => {
            // Guest thread's timeout fired → cooperative yield works. ✓
        }
        Ok(T55Msg::GuestReturnedEarly { is_ok }) => {
            panic!(
                "T55: tight-loop guest call returned within 3s (is_ok={is_ok}) — \
                 cooperative yield was NOT exercised because call_run completed \
                 unexpectedly (wasmtime trap, early return, or fixture regression). \
                 Investigate call_run's actual return value; do NOT assume yield \
                 is broken."
            );
        }
        Ok(T55Msg::SetupComplete) => {
            panic!("T55: unexpected duplicate SetupComplete message from guest thread");
        }
        Err(_) => {
            panic!(
                "T55: guest setup completed, but tight-loop call did not timeout \
                 within 5s AND did not send GuestReturnedEarly — cooperative yield \
                 is broken (ticker + epoch_deadline_async_yield_and_update wiring)"
            );
        }
    }
    // Guest thread lifecycle:
    //
    // PASS case (cooperative yield works): the guest thread's
    // `tokio::time::timeout(3s)` fires → mpsc send → async block exits →
    // `block_on` returns → thread closure exits → thread terminates cleanly.
    // No orphan; no CPU-burn leak to sibling tests.
    //
    // FAIL case (cooperative yield broken): the guest thread's tight-loop call
    // never yields, `tokio::time::timeout` never fires, the thread is stuck.
    // Main thread's panic on Phase 2 timeout kills T55 but NOT the orphan thread;
    // under cargo-test's parallel harness, sibling tests in the same binary
    // run concurrent with the orphan until the test binary exits. This is
    // acceptable as a failure-mode trade-off: T55 has already panicked loudly
    // with "cooperative yield broken" diagnostic, so the failure is clearly
    // attributed and not silent. Killing the orphan without `std::process::exit`
    // (which would nuke parallel sibling tests) is not feasible — Rust lacks a
    // portable thread-kill primitive. A future hardening slice could bound the
    // guest loop (e.g., via a Store limiter on instructions) to cap the
    // failure-case CPU burn.
}

//! Slice C — T57: NFR p99 emit < 10 µs hot-loop benchmark (MODULE-019 §1.5).
//!
//! 10K iterations of `EventBusEmit::emit()` from a hot loop. Reports
//! min/p50/p99/max/mean to stderr. In release builds (`!cfg!(debug_assertions)`)
//! asserts strictly; in debug builds reports only — debug runtime overhead
//! makes 10 µs unachievable. CI must run `cargo test --release` to enforce.

use std::sync::Arc;
use std::time::{Duration, Instant};

use advance_event_bus::{EventBus, EventBusConfig};
use advance_shared_types::event::Event;
use advance_shared_types::traits::EventBusEmit;
use chrono::Utc;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t57_emit_p99_under_10us() {
    const WARMUP: usize = 1000;
    const ITERATIONS: usize = 10_000;

    let temp = tempfile::TempDir::new().unwrap();
    let mut cfg = EventBusConfig::new(temp.path().join("events"), temp.path().join("events.db"));
    cfg.websocket_addr = "127.0.0.1:0".parse().unwrap();
    let bus = EventBus::new(cfg).await.expect("bus");
    let bus: Arc<dyn EventBusEmit> = Arc::new(bus_into_arc(bus));

    let make_event = |i: usize| Event {
        id: format!("evt-perf-{i:05}"),
        timestamp: Utc::now(),
        agent_id: "perf-agent".to_string(),
        task_id: None,
        run_id: None,
        execution_id: None,
        trace_id: format!("tr-perf-{i:05}"),
        span_id: format!("sp-perf-{i:05}"),
        parent_span_id: None,
        event_type: "runtime.started".to_string(),
        payload: serde_json::json!({"i": i, "static": "payload"}),
        duration_ms: None,
    };

    // Warmup.
    for i in 0..WARMUP {
        bus.emit(make_event(i));
    }

    // Measured iterations.
    let mut samples: Vec<u64> = Vec::with_capacity(ITERATIONS);
    for i in 0..ITERATIONS {
        let t0 = Instant::now();
        bus.emit(make_event(i + WARMUP));
        let elapsed = t0.elapsed();
        samples.push(elapsed.as_nanos() as u64);
    }

    samples.sort_unstable();
    let min_ns = samples[0];
    let p50_ns = samples[ITERATIONS / 2];
    let p99_ns = samples[(ITERATIONS as f64 * 0.99) as usize];
    let max_ns = samples[ITERATIONS - 1];
    let mean_ns: u64 = samples.iter().sum::<u64>() / ITERATIONS as u64;

    let p99 = Duration::from_nanos(p99_ns);
    eprintln!(
        "T57 emit perf — debug={debug} | min={min_ns}ns p50={p50_ns}ns p99={p99_ns}ns max={max_ns}ns mean={mean_ns}ns",
        debug = cfg!(debug_assertions),
    );

    // Release-mode strict assertion. Debug-mode report-only.
    if !cfg!(debug_assertions) {
        assert!(
            p99 < Duration::from_micros(10),
            "NFR violation: p99 = {p99:?} >= 10 µs"
        );
    }
}

// We need to wrap EventBus in Arc<dyn EventBusEmit>, but EventBus::shutdown takes
// self. Just consume bus directly in the test — the Arc holds it for the duration
// of measurements, then drops at end-of-scope.
fn bus_into_arc(bus: EventBus) -> EventBus {
    bus
}

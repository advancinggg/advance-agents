//! Witness #1 for the production [`WasmRunnableHookFactory`] (B3 satellite).
//!
//! These cli tests prove the factory is **bytes-bound**: the hook it produces
//! loads + runs the EXACT bytes handed to `build`, a changed/corrupt submit
//! changes the outcome, and the requested caps are threaded into instantiation
//! (not dropped). That is the cli-layer precondition for the mainline SYS-AC-109
//! kill (the id-string fake-green class) — NOT the kill itself, which lives in
//! the waived live-`ComponentRegistry` composition the harness drives.
//!
//! Fixture: `guest-rust-minimal` — its `runnable.run(config_data: None)` returns
//! `Completed { output: Some([0xAD,0x11,0xCE,0x02]) }` and calls NO host fn, so
//! an empty `InMemoryHostRegistry` + `inject(&[])` instantiates it cleanly
//! through the production `WasmRunnableHook`'s with-capabilities path.

use std::sync::{Arc, Mutex};

use advance_cli::runnable_hook_factory::WasmRunnableHookFactory;
use advance_runtime::circuit_breaker::{CircuitBreakerBus, DefaultCircuitBreakerBus};
use advance_runtime::config::WasmConfig;
use advance_runtime::host_registry::{HostRegistry, InMemoryHostRegistry};
use advance_runtime::{CapabilityInjector, ComponentRuntime};
use advance_scheduler::hook::RunnableHookFactory;
use advance_scheduler::types::{ComponentConfig, RunStatus};
use advance_shared_types::capability::{CapParams, CapRequest, CapabilityId, GrantDecision};
use advance_shared_types::event::Event;
use advance_shared_types::traits::{EventBusEmit, GrantCheck};
use wit_component::ComponentEncoder;

const CORE_BYTES: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-minimal.core.wasm");
/// A SECOND, distinct valid runnable fixture: `guest-rust-counter` (world
/// `advance-host`, zero imports — instantiates through the with-caps path like
/// minimal). Its `run()` returns `Completed { output: None }` — DIFFERENT from
/// minimal's `Some(RUN_SENTINEL)`. Used by the strong bytes-binding
/// discriminator (T-RF-05).
const COUNTER_CORE_BYTES: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-counter.core.wasm");
const LEGACY3_SENSITIVE_CORE_BYTES: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-legacy3-sensitive.core.wasm");
/// The sentinel the minimal guest's `run(config_data: None)` returns — proves
/// the REAL guest run() body executed, not merely that build succeeded.
const RUN_SENTINEL: [u8; 4] = [0xAD, 0x11, 0xCE, 0x02];

struct AllowAll;
impl GrantCheck for AllowAll {
    fn check(&self, _: &str, _: &str, _: &str, _: &CapParams) -> GrantDecision {
        GrantDecision::Allow
    }
}

fn wasm_cfg() -> WasmConfig {
    WasmConfig {
        max_memory_pages: 256,
        epoch_interruption_ms: 100,
        fuel_enabled: false,
    }
}

fn component_bytes() -> Vec<u8> {
    ComponentEncoder::default()
        .validate(true)
        .module(CORE_BYTES)
        .expect("core module wraps")
        .encode()
        .expect("component encoded")
}

fn counter_component_bytes() -> Vec<u8> {
    ComponentEncoder::default()
        .validate(true)
        .module(COUNTER_CORE_BYTES)
        .expect("counter core module wraps")
        .encode()
        .expect("counter component encoded")
}

fn sensitive_component_bytes() -> Vec<u8> {
    ComponentEncoder::default()
        .validate(true)
        .module(LEGACY3_SENSITIVE_CORE_BYTES)
        .expect("sensitive core module wraps")
        .encode()
        .expect("sensitive component encoded")
}

#[derive(Default)]
struct RecordingEventBus(Mutex<Vec<Event>>);

impl EventBusEmit for RecordingEventBus {
    fn emit(&self, event: Event) {
        self.0.lock().expect("recording event lock").push(event);
    }
}

/// The spike's `build_injector_and_registry` shape: empty registry (no host fns
/// registered) + AllowAll grant + default breaker. The minimal guest needs none
/// of these registered because it calls no host fn.
fn build_factory() -> WasmRunnableHookFactory {
    let runtime = Arc::new(ComponentRuntime::new(&wasm_cfg()).expect("runtime"));
    let registry: Arc<dyn HostRegistry> = Arc::new(InMemoryHostRegistry::new());
    let grant: Arc<dyn GrantCheck> = Arc::new(AllowAll);
    let breaker: Arc<dyn CircuitBreakerBus> = Arc::new(DefaultCircuitBreakerBus::new());
    let injector = Arc::new(CapabilityInjector::new(registry, grant, breaker));
    WasmRunnableHookFactory::new(runtime, injector)
}

fn cfg(id: &str) -> ComponentConfig {
    ComponentConfig {
        id: id.to_owned(),
        config_data: None,
        trigger_context: None,
    }
}

/// T-RF-01 — the production factory loads the real bytes and the produced hook
/// runs the REAL guest in a fresh guest (Completed + exact sentinel). Also the
/// R1 de-risk: confirms `guest-rust-minimal` (zero imports) instantiates through
/// `WasmRunnableHook`'s with-capabilities path with empty caps.
#[tokio::test]
async fn factory_builds_hook_that_runs_real_bytes() {
    let factory = build_factory();
    let hook = factory
        .build(&component_bytes(), "comp-1", &[])
        .await
        .expect("factory builds a hook from the real component bytes");
    let result = hook
        .run_once(cfg("comp-1"))
        .await
        .expect("hook runs the real guest end-to-end");
    assert!(matches!(result.status, RunStatus::Completed));
    assert_eq!(
        result.output,
        Some(RUN_SENTINEL.to_vec()),
        "the REAL guest run() body executed and returned its sentinel output"
    );
}

/// T-RF-02 — fresh-guest / stateless: each `run_once` gets a fresh Store, so two
/// runs on the same hook both succeed with the same sentinel.
#[tokio::test]
async fn hook_runs_are_fresh_and_repeatable() {
    let factory = build_factory();
    let hook = factory
        .build(&component_bytes(), "comp-1", &[])
        .await
        .unwrap();

    let r1 = hook.run_once(cfg("comp-1")).await.expect("first run");
    let r2 = hook.run_once(cfg("comp-1")).await.expect("second run");
    assert!(matches!(r1.status, RunStatus::Completed));
    assert!(matches!(r2.status, RunStatus::Completed));
    assert_eq!(r1.output, Some(RUN_SENTINEL.to_vec()));
    assert_eq!(
        r2.output,
        Some(RUN_SENTINEL.to_vec()),
        "stateless across runs"
    );
}

/// T-RF-03 — mutation discriminator (bytes-binding). A DETERMINISTIC invalid
/// mutation (truncate to len/2 — a truncated wasm component always fails
/// validation, unlike "flip one byte" which could land in a custom section)
/// makes `build` fail. Proves the produced hook is bound to the actual BYTES,
/// not an id string: a changed/deleted submit changes the outcome.
#[tokio::test]
async fn corrupt_bytes_fail_to_build() {
    let factory = build_factory();
    let bytes = component_bytes();
    let truncated = &bytes[..bytes.len() / 2];

    let result = factory.build(truncated, "comp-1", &[]).await;
    assert!(
        result.is_err(),
        "truncated component bytes must fail to load (build Err), got Ok"
    );
}

/// T-RF-04 — caps ARE threaded into instantiation (not dropped). `build`
/// succeeds (it does not consume caps — only loads bytes), but `run_once` with
/// an UNregistered `fs.read` cap fails: the with-capabilities instantiate calls
/// `inject(&[fs.read])` → empty-registry lookup → `UnknownCapability` →
/// `HookError::Failure`. A factory that DROPPED caps (passed `&[]` to the hook)
/// would instead run `Completed`; the run-time `Err` proves the row's caps
/// reached `inject`.
#[tokio::test]
async fn caps_are_threaded_into_instantiation() {
    let factory = build_factory();
    let caps = vec![CapRequest {
        capability: CapabilityId::new("fs.read"),
    }];

    let hook = factory
        .build(&component_bytes(), "comp-2", &caps)
        .await
        .expect("build succeeds — caps are consumed at run, not at build");
    let result = hook.run_once(cfg("comp-2")).await;
    assert!(
        result.is_err(),
        "an unregistered cap must fail instantiation (caps threaded into inject), got {result:?}"
    );
}

/// T-RF-05 — STRONG bytes-binding discriminator (adversarial round 7 Info-1).
/// The SAME factory builds TWO DISTINCT, both-valid components and they produce
/// DISTINCT run outputs: `guest-rust-minimal` → `Some(RUN_SENTINEL)`,
/// `guest-rust-counter` → `None`. This closes the "loads-but-runs-a-different-
/// embedded-component" fake-green gap that the load-fail discriminators
/// (T-RF-03) alone cannot catch: an impl that ignored `binary` and ran a single
/// hardcoded/embedded/id-keyed component would return the SAME output for both
/// and fail the `assert_ne!`. Proves the run output is genuinely a function of
/// the BYTES handed to `build` — the bytes-binding the SYS-AC-109 fake-green
/// class forbids.
#[tokio::test]
async fn distinct_components_produce_distinct_run_outputs() {
    let factory = build_factory();
    let minimal = factory
        .build(&component_bytes(), "min", &[])
        .await
        .expect("minimal builds");
    let counter = factory
        .build(&counter_component_bytes(), "cnt", &[])
        .await
        .expect("counter builds");

    let r_min = minimal.run_once(cfg("min")).await.expect("minimal runs");
    let r_cnt = counter.run_once(cfg("cnt")).await.expect("counter runs");

    assert!(matches!(r_min.status, RunStatus::Completed));
    assert!(matches!(r_cnt.status, RunStatus::Completed));
    assert_eq!(
        r_min.output,
        Some(RUN_SENTINEL.to_vec()),
        "minimal returns its sentinel output"
    );
    assert_eq!(r_cnt.output, None, "counter returns no output");
    assert_ne!(
        r_min.output, r_cnt.output,
        "two distinct valid components MUST produce distinct run outputs — the run \
         is a function of the BYTES, not an embedded/id-bound default"
    );
}

/// MODULE-012-T10 positive execution discriminator: the exact raw sentinel originates in a real
/// Rust/WASM guest, crosses the production Wasmtime runnable hook, remains available to execution,
/// and is emitted as typed nested/canonical JSON for the observation guard.
#[tokio::test]
async fn legacy3_sensitive_guest_reaches_execution_and_observation_boundary() {
    const SENTINEL: &str = "legacy3-raw-secret-7f3a";
    let bus = Arc::new(RecordingEventBus::default());
    let factory = build_factory().with_event_bus(bus.clone());
    let hook = factory
        .build(&sensitive_component_bytes(), "legacy3-sensitive", &[])
        .await
        .expect("sensitive component builds");

    let result = hook
        .run_once(cfg("legacy3-sensitive"))
        .await
        .expect("real sensitive guest runs");
    let raw = String::from_utf8(result.output.expect("guest output")).expect("UTF-8 guest JSON");
    assert!(
        raw.contains(SENTINEL),
        "execution receives the exact raw sentinel"
    );

    let events = bus.0.lock().expect("recording event lock");
    assert_eq!(events.len(), 1, "one run.completed observation");
    let payload = serde_json::to_string(&events[0].payload).expect("event payload JSON");
    assert!(
        payload.contains(SENTINEL),
        "pre-redaction observation carries the guest result"
    );
    assert_eq!(events[0].event_type, "run.completed");
    assert_eq!(events[0].agent_id, "legacy3-sensitive");
    let run_id = events[0].run_id.as_deref().expect("execution run id");
    assert_eq!(run_id.len(), 36);
    assert_eq!(uuid::Uuid::parse_str(run_id).unwrap().to_string(), run_id);
    assert_eq!(
        events[0].payload["result"]["named_params"]["api_key"],
        SENTINEL
    );
    assert_eq!(
        events[0].payload["result"]["nested"][0]["named_params"]["api_key"],
        SENTINEL
    );
    assert_eq!(
        events[0].payload["result"]["cap_params"][0]["value"],
        SENTINEL
    );
}

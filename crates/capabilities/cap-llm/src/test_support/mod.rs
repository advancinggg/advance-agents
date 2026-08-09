//! Test support fixtures for cap-llm. `#[cfg(test)]` only — sibling-crate
//! consumption is out of scope for Slice B-2 (round-2 C4 decision).
//!
//! Provides:
//! - [`MockHttpSecurityChain`] — scripted-response chain with optional step_tracer
//! - [`MockRunBudget`]         — scripted check() + commit() recording
//! - [`MockEventBusEmit`]      — collects emitted events into a Mutex<Vec<Event>>
//! - [`MockRuntimeConfigProvider`] — swappable Arc<RuntimeConfig> with set_config()
//! - [`test_gateway`]          — Arc<LlmGateway> wired with sane mock defaults

#![cfg(test)]

mod mock_chain;
mod mock_config_provider;
mod mock_event_bus;
mod mock_repetition_guard;
mod mock_run_budget;

pub(crate) use mock_chain::MockHttpSecurityChain;
pub(crate) use mock_config_provider::MockRuntimeConfigProvider;
pub(crate) use mock_event_bus::MockEventBusEmit;
pub(crate) use mock_repetition_guard::{
    no_op_repetition_guard, MockRepetitionGuard, RepGuardPolicy,
};
pub(crate) use mock_run_budget::MockRunBudget;

use std::sync::Arc;

use advance_shared_types::traits::HttpStreamingChain;
use cap_http::DefaultLeakDetector;

use crate::gateway::LlmGateway;

const FIXTURE_RUNTIME_CONFIG_YAML: &str = r#"
wasm:
  max_memory_pages: 1024
  epoch_interruption_ms: 100
  fuel_enabled: false

llm-providers:
  - id: openai
    endpoint: https://api.openai.com
    api-key-secret: openai-api-key
    model-aliases:
      gpt4o: gpt-4o-2024-08-06
    cost-per-mtoken-in: 2.50
    cost-per-mtoken-out: 10.00
  - id: anthropic
    endpoint: https://api.anthropic.com
    api-key-secret: anthropic-api-key
    model-aliases:
      sonnet: claude-sonnet-4-5
    cost-per-mtoken-in: 3.00
    cost-per-mtoken-out: 15.00

cron:
  max_jitter_ratio: 0.1

git:
  gc_interval_hours: 24
  max_tracked_file_mb: 10

circuit-breakers: []

secrets:
  master-key-source: keychain
  env-var-name: SECRETS_MASTER_KEY

users: []

post-processor:
  llm-model: sonnet-light
  llm-failure-cooldown-seconds: 600
"#;

/// Parse the canonical fixture RuntimeConfig YAML used by every cap-llm
/// `#[cfg(test)]` module. Panics on parse failure (test-only path).
pub(crate) fn fixture_runtime_config() -> advance_runtime::config::RuntimeConfig {
    serde_yml::from_str(FIXTURE_RUNTIME_CONFIG_YAML).expect("fixture RuntimeConfig YAML must parse")
}

/// Build an `Arc<LlmGateway>` wired to a sane default mock configuration:
/// - `MockRuntimeConfigProvider` returning `fixture_runtime_config()`
/// - empty `MockHttpSecurityChain` (no scripted responses; tests that
///   exercise the chain must register fixtures via the returned
///   chain Arc — use [`test_gateway_with`] for that).
/// - `MockRunBudget::default()` (always Allow; commits are recorded).
/// - `MockEventBusEmit::default()` (collect into Vec).
pub(crate) fn test_gateway() -> Arc<LlmGateway> {
    let cfg_provider = Arc::new(MockRuntimeConfigProvider::new(fixture_runtime_config()));
    let chain = Arc::new(MockHttpSecurityChain::default());
    let budget = Arc::new(MockRunBudget::default());
    let bus = Arc::new(MockEventBusEmit::default());
    let rep_guard = no_op_repetition_guard();
    let mut gw = LlmGateway::new(
        cfg_provider,
        chain.clone(),
        budget,
        bus,
        rep_guard,
        "test-agent".into(),
    );
    // S4: wire live by default so stream tests use the live path (no "not wired" error).
    gw = gw.with_live_streaming(
        chain as Arc<dyn HttpStreamingChain>,
        Arc::new(DefaultLeakDetector::default()),
    );
    Arc::new(gw)
}

/// Slice C (2026-05-09): build an `Arc<LlmGateway>` with caller-supplied bus
/// and chain so propagation tests hold `Arc`s to the same instances the
/// gateway emits to / dispatches through. AC-01 anchor test (T01a) uses this
/// to (1) capture emitted `llm.request` events for run_id / iteration
/// assertions and (2) script a happy-path successful upstream HTTP response
/// via `chain.push_response(path_suffix, response)`.
pub(crate) fn test_gateway_with(
    bus: Arc<MockEventBusEmit>,
    chain: Arc<MockHttpSecurityChain>,
) -> Arc<LlmGateway> {
    let cfg_provider = Arc::new(MockRuntimeConfigProvider::new(fixture_runtime_config()));
    let rep_guard = no_op_repetition_guard();
    let budget = Arc::new(MockRunBudget::default());
    let mut gw = LlmGateway::new(
        cfg_provider,
        chain.clone(),
        budget,
        bus,
        rep_guard,
        "test-agent".into(),
    );
    gw = gw.with_live_streaming(
        chain as Arc<dyn HttpStreamingChain>,
        Arc::new(DefaultLeakDetector::default()),
    );
    Arc::new(gw)
}

/// Slice D: build an `Arc<LlmGateway>` with caller-supplied repetition guard +
/// run budget so Slice-D AC-16 tests (T13/T13a-e/T17) can assert record_output
/// + commit interactions.
pub(crate) fn test_gateway_with_repguard(
    bus: Arc<MockEventBusEmit>,
    chain: Arc<MockHttpSecurityChain>,
    budget: Arc<MockRunBudget>,
    rep_guard: Arc<MockRepetitionGuard>,
) -> Arc<LlmGateway> {
    let cfg_provider = Arc::new(MockRuntimeConfigProvider::new(fixture_runtime_config()));
    let mut gw = LlmGateway::new(
        cfg_provider,
        chain.clone(),
        budget,
        bus,
        rep_guard,
        "test-agent".into(),
    );
    gw = gw.with_live_streaming(
        chain as Arc<dyn HttpStreamingChain>,
        Arc::new(DefaultLeakDetector::default()),
    );
    Arc::new(gw)
}

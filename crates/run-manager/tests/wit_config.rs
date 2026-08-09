//! Slice C AC-13 tests (T92–T95c): WIT-shape config serde + defaults +
//! run-level override storage + accessors.

use std::sync::{Arc, Mutex};

use advance_run_manager::{
    repetition_guard::AgentRunResolver, RepetitionGuardConfig, RetryConfig, RunConfig, RunManager,
};
use advance_shared_types::event::Event;
use advance_shared_types::repetition::{OutputHash, RepetitionDecision, ToolCallSignature};
use advance_shared_types::traits::{EventBusEmit, RepetitionGuardCheck};

#[derive(Default)]
struct MockBus {
    events: Mutex<Vec<Event>>,
}

impl EventBusEmit for MockBus {
    fn emit(&self, event: Event) {
        self.events.lock().unwrap().push(event);
    }
}

fn fresh_mgr() -> Arc<RunManager> {
    let bus: Arc<dyn EventBusEmit> = Arc::new(MockBus::default());
    Arc::new(RunManager::new(bus))
}

/// T92 — WitRunConfig / RunConfig serde roundtrip with all fields
/// populated.
#[test]
fn t92_wit_run_config_serde_roundtrip() {
    let cfg = RunConfig {
        token_limit: Some(1000),
        cost_usd_limit: Some(10.0),
        rounds_limit: Some(20),
        retry_overrides: Some(RetryConfig {
            llm_max_retries: Some(5),
            llm_base_delay_ms: Some(500),
            llm_max_delay_ms: Some(20000),
            tool_max_retries: Some(1),
            tool_base_delay_ms: Some(250),
            tool_max_delay_ms: Some(5000),
        }),
        repetition_guard: Some(RepetitionGuardConfig {
            enabled: Some(true),
            window_size: Some(8),
            repeat_threshold: Some(2),
            action: Some("terminate".into()),
        }),
    };
    let yaml = serde_yml::to_string(&cfg).unwrap();
    let decoded: RunConfig = serde_yml::from_str(&yaml).unwrap();
    assert_eq!(decoded, cfg);
}

/// T93 — RepetitionGuardConfig::apply_defaults produces WIT defaults.
#[test]
fn t93_repetition_guard_config_apply_defaults() {
    let cfg = RepetitionGuardConfig::default();
    let d = cfg.apply_defaults();
    assert!(d.enabled);
    assert_eq!(d.window_size, 10);
    assert_eq!(d.repeat_threshold, 3);
    assert_eq!(d.action, "warn-then-terminate");
}

/// T94 — RetryConfig::apply_defaults produces WIT defaults.
#[test]
fn t94_retry_config_apply_defaults() {
    let cfg = RetryConfig::default();
    let d = cfg.apply_defaults();
    assert_eq!(d.llm_max_retries, 3);
    assert_eq!(d.llm_base_delay_ms, 1000);
    assert_eq!(d.llm_max_delay_ms, 30000);
    assert_eq!(d.tool_max_retries, 2);
    assert_eq!(d.tool_base_delay_ms, 500);
    assert_eq!(d.tool_max_delay_ms, 10000);
}

/// Stub AgentRunResolver for the from_config tests (avoids the unique-live
/// match constraint of the real RunManager-as-resolver path).
#[allow(dead_code)] // retained test scaffold: not every test in this binary constructs it
struct StubResolver;
impl AgentRunResolver for StubResolver {
    fn resolve(&self, _agent_id: &str) -> (Option<String>, Option<String>) {
        (None, None)
    }
}

/// T95 — RepetitionGuardConfig.enabled=Some(false) → guard short-circuits
/// to Pass at entry (record_tool_call / record_output always Pass).
#[test]
fn t95_enabled_false_short_circuits_to_pass() {
    let mgr = fresh_mgr();
    let cfg = RepetitionGuardConfig {
        enabled: Some(false),
        window_size: Some(5),
        repeat_threshold: Some(2),
        action: Some("terminate".into()),
    };
    let guard = mgr.build_repetition_guard_from_config(&cfg);
    // Hammer the guard 5x with the same signature — expect Pass every time
    // because enabled=false.
    let sig = ToolCallSignature {
        tool_id: "t".into(),
        method: "m".into(),
        params_hash: 0,
    };
    for _ in 0..5 {
        let d = guard.record_tool_call("agent-A", sig.clone());
        assert!(matches!(d, RepetitionDecision::Pass));
    }
}

/// T95b — enabled=Some(true) (or None default): guard behaves normally.
#[test]
fn t95b_enabled_true_normal_behavior() {
    let mgr = fresh_mgr();
    let cfg = RepetitionGuardConfig {
        enabled: Some(true),
        window_size: Some(5),
        repeat_threshold: Some(2),
        action: Some("terminate".into()),
    };
    let guard = mgr.build_repetition_guard_from_config(&cfg);
    let sig = ToolCallSignature {
        tool_id: "t".into(),
        method: "m".into(),
        params_hash: 0,
    };
    // First repeat at threshold=2 should hit Terminate (per the terminate
    // action). After 2 sequential identical sigs → Terminate.
    let _ = guard.record_tool_call("agent-A", sig.clone());
    let d2 = guard.record_tool_call("agent-A", sig.clone());
    assert!(matches!(d2, RepetitionDecision::Terminate(_)));

    // Also verify output-hash path: 2x identical output hash → Terminate.
    let h = OutputHash([0u8; 32]);
    let _ = guard.record_output("agent-B", h.clone());
    let d2 = guard.record_output("agent-B", h.clone());
    assert!(matches!(d2, RepetitionDecision::Terminate(_)));
}

/// T95c — AC-13 RUN-LEVEL OVERRIDE STORAGE: ensure_run with full
/// retry_overrides + repetition_guard config; accessors return the same
/// values; survives clone/snapshot.
#[test]
fn t95c_run_level_override_storage_roundtrip() {
    let mgr = fresh_mgr();
    let rg_cfg = RepetitionGuardConfig {
        enabled: Some(true),
        window_size: Some(5),
        repeat_threshold: Some(2),
        action: Some("terminate".into()),
    };
    let retry_cfg = RetryConfig {
        llm_max_retries: Some(7),
        llm_base_delay_ms: Some(123),
        llm_max_delay_ms: Some(1234),
        tool_max_retries: Some(2),
        tool_base_delay_ms: Some(45),
        tool_max_delay_ms: Some(456),
    };
    let id = mgr
        .ensure_run(
            "task-1",
            "root",
            RunConfig {
                token_limit: None,
                cost_usd_limit: None,
                rounds_limit: None,
                retry_overrides: Some(retry_cfg.clone()),
                repetition_guard: Some(rg_cfg.clone()),
            },
        )
        .unwrap();
    assert_eq!(mgr.repetition_guard_overrides(&id), Some(rg_cfg));
    assert_eq!(mgr.retry_overrides(&id), Some(retry_cfg));
}

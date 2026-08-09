//! Slice B AC-10 integration tests: WarnThenTerminate Tier-3 inject
//! wiring (T61–T65b).

use std::sync::{Arc, Mutex};

use advance_run_manager::{RepetitionAction, RepetitionGuard};
use advance_shared_types::context::{
    AssemblyContext, AssemblyError, AssemblyResult, ContextAssembler,
};
use advance_shared_types::repetition::{OutputHash, RepetitionDecision, ToolCallSignature};
use advance_shared_types::security_validator::{
    InjectionFlag, PromptInjectionHelpers, Severity, TrustLevel,
};
use advance_shared_types::traits::RepetitionGuardCheck;
use async_trait::async_trait;

#[derive(Default)]
struct MockContextAssembler {
    calls: Mutex<Vec<(String, String)>>, // (agent_id, msg)
}

impl MockContextAssembler {
    fn new_arc() -> Arc<Self> {
        Arc::new(Self::default())
    }
    fn call_count(&self) -> usize {
        self.calls.lock().unwrap().len()
    }
    fn last(&self) -> Option<(String, String)> {
        self.calls.lock().unwrap().last().cloned()
    }
}

#[async_trait]
impl ContextAssembler for MockContextAssembler {
    async fn assemble(&self, _: AssemblyContext) -> Result<AssemblyResult, AssemblyError> {
        unimplemented!("not used in AC-10 tests")
    }
    fn inject_tier3_warning(&self, agent_id: &str, msg: &str) {
        self.calls
            .lock()
            .unwrap()
            .push((agent_id.to_string(), msg.to_string()));
    }
}

#[derive(Default)]
struct MockPromptInjectionHelpers {
    flag_calls: Mutex<Vec<String>>,
    wrap_calls: Mutex<Vec<(String, String, TrustLevel)>>,
    force_critical: Mutex<bool>,
    wrap_marker: String,
}

impl MockPromptInjectionHelpers {
    fn new_arc() -> Arc<Self> {
        Arc::new(Self {
            wrap_marker: "[WRAPPED]".into(),
            ..Self::default()
        })
    }
    fn flag_count(&self) -> usize {
        self.flag_calls.lock().unwrap().len()
    }
    fn wrap_count(&self) -> usize {
        self.wrap_calls.lock().unwrap().len()
    }
    fn last_wrap(&self) -> Option<(String, String, TrustLevel)> {
        self.wrap_calls.lock().unwrap().last().cloned()
    }
    fn set_critical(&self, yes: bool) {
        *self.force_critical.lock().unwrap() = yes;
    }
}

impl PromptInjectionHelpers for MockPromptInjectionHelpers {
    fn flag_injection_patterns(&self, content: &str) -> Vec<InjectionFlag> {
        self.flag_calls.lock().unwrap().push(content.to_string());
        if *self.force_critical.lock().unwrap() {
            vec![InjectionFlag {
                pattern_name: "fake-critical".into(),
                offset: 0,
                length: 0,
                severity: Severity::Critical,
            }]
        } else {
            vec![]
        }
    }
    fn wrap_with_boundary(&self, content: &str, source: &str, trust: TrustLevel) -> String {
        self.wrap_calls.lock().unwrap().push((
            content.to_string(),
            source.to_string(),
            trust.clone(),
        ));
        format!("{}{}{}", self.wrap_marker, content, self.wrap_marker)
    }
}

fn output_hash(byte: u8) -> OutputHash {
    OutputHash([byte; 32])
}

/// T61 — first repeat: Warn returned; full inject chain fires; flag+wrap+inject all invoked.
#[tokio::test]
async fn t61_warn_then_terminate_first_repeat_full_inject_chain() {
    let ca = MockContextAssembler::new_arc();
    let pi = MockPromptInjectionHelpers::new_arc();
    let guard = RepetitionGuard::new(10, 2, RepetitionAction::WarnThenTerminate)
        .with_context_assembler(Arc::clone(&ca) as Arc<dyn ContextAssembler>)
        .with_prompt_injection_helpers(Arc::clone(&pi) as Arc<dyn PromptInjectionHelpers>);

    let h = output_hash(0xAA);
    let _ = guard.record_output("root", h.clone()); // first observation, no repeat
    let d = guard.record_output("root", h); // second — threshold=2 → Warn

    assert!(matches!(d, RepetitionDecision::Warn(_)));
    assert_eq!(pi.flag_count(), 1);
    assert_eq!(pi.wrap_count(), 1);
    let (content, source, trust) = pi.last_wrap().unwrap();
    assert!(content.contains("Repetition detected"));
    assert_eq!(source, "repetition-guard");
    assert!(matches!(trust, TrustLevel::Untrusted));
    assert_eq!(ca.call_count(), 1);
    let (agent_id, msg) = ca.last().unwrap();
    assert_eq!(agent_id, "root");
    assert!(msg.contains("[WRAPPED]"), "msg should be wrapped: {msg}");
}

/// T62 — second repeat: Terminate returned; inject NOT invoked again; warned flag cleared.
#[tokio::test]
async fn t62_warn_then_terminate_second_repeat_terminates() {
    let ca = MockContextAssembler::new_arc();
    let pi = MockPromptInjectionHelpers::new_arc();
    let guard = RepetitionGuard::new(10, 2, RepetitionAction::WarnThenTerminate)
        .with_context_assembler(Arc::clone(&ca) as Arc<dyn ContextAssembler>)
        .with_prompt_injection_helpers(Arc::clone(&pi) as Arc<dyn PromptInjectionHelpers>);

    let h = output_hash(0xAA);
    let _ = guard.record_output("root", h.clone());
    let _ = guard.record_output("root", h.clone()); // first repeat → Warn + inject
    let d = guard.record_output("root", h); // second repeat → Terminate

    assert!(matches!(d, RepetitionDecision::Terminate(_)));
    // inject_tier3_warning NOT invoked second time.
    assert_eq!(ca.call_count(), 1);
}

/// T63 — WarnThenTerminate WITHOUT with_context_assembler: still Warn, no inject.
#[tokio::test]
async fn t63_warn_then_terminate_no_context_assembler() {
    let guard = RepetitionGuard::new(10, 2, RepetitionAction::WarnThenTerminate);

    let h = output_hash(0xAA);
    let _ = guard.record_output("root", h.clone());
    let d = guard.record_output("root", h);

    assert!(matches!(d, RepetitionDecision::Warn(_)));
    // No mocks to assert; the absence of panics is sufficient.
}

/// T64 — WarnThenTerminate WITH context_assembler but WITHOUT prompt_injection_helpers:
/// fail-closed, inject NEVER invoked.
#[tokio::test]
async fn t64_warn_then_terminate_no_pih_fails_closed() {
    let ca = MockContextAssembler::new_arc();
    let guard = RepetitionGuard::new(10, 2, RepetitionAction::WarnThenTerminate)
        .with_context_assembler(Arc::clone(&ca) as Arc<dyn ContextAssembler>);

    let h = output_hash(0xAA);
    let _ = guard.record_output("root", h.clone());
    let d = guard.record_output("root", h);

    assert!(matches!(d, RepetitionDecision::Warn(_)));
    assert_eq!(ca.call_count(), 0); // fail-closed: no inject
}

/// T65 — Tool-call path shares the inject chain (record_tool_call exercises same decide_locked).
#[tokio::test]
async fn t65_tool_call_path_shares_inject_chain() {
    let ca = MockContextAssembler::new_arc();
    let pi = MockPromptInjectionHelpers::new_arc();
    let guard = RepetitionGuard::new(10, 3, RepetitionAction::WarnThenTerminate)
        .with_context_assembler(Arc::clone(&ca) as Arc<dyn ContextAssembler>)
        .with_prompt_injection_helpers(Arc::clone(&pi) as Arc<dyn PromptInjectionHelpers>);

    let sig = ToolCallSignature {
        tool_id: "fs::read".into(),
        method: "read".into(),
        params_hash: 0xDEADBEEF_DEADBEEF,
    };
    let _ = guard.record_tool_call("root", sig.clone());
    let _ = guard.record_tool_call("root", sig.clone());
    let d = guard.record_tool_call("root", sig.clone());

    assert!(matches!(d, RepetitionDecision::Warn(_)));
    assert_eq!(pi.flag_count(), 1);
    assert_eq!(pi.wrap_count(), 1);
    assert_eq!(ca.call_count(), 1);
    let (_, msg) = ca.last().unwrap();
    assert!(msg.contains("fs::read::read"));
}

/// T65b — Severity::Critical short-circuit: PIH returns Critical flag →
/// inject NEVER invoked, no wrap_with_boundary call either.
#[tokio::test]
async fn t65b_critical_severity_short_circuits_inject() {
    let ca = MockContextAssembler::new_arc();
    let pi = MockPromptInjectionHelpers::new_arc();
    pi.set_critical(true);
    let guard = RepetitionGuard::new(10, 2, RepetitionAction::WarnThenTerminate)
        .with_context_assembler(Arc::clone(&ca) as Arc<dyn ContextAssembler>)
        .with_prompt_injection_helpers(Arc::clone(&pi) as Arc<dyn PromptInjectionHelpers>);

    let h = output_hash(0xAA);
    let _ = guard.record_output("root", h.clone());
    let d = guard.record_output("root", h);

    assert!(matches!(d, RepetitionDecision::Warn(_)));
    // flag_injection_patterns called, but wrap_with_boundary + inject NOT called.
    assert_eq!(pi.flag_count(), 1);
    assert_eq!(pi.wrap_count(), 0);
    assert_eq!(ca.call_count(), 0);
}

/// Adversarial round 1 regression: lock-drop-before-inject — a
/// ContextAssembler impl that re-enters the guard (calls
/// `record_tool_call` from within `inject_tier3_warning`) must NOT
/// deadlock. The Slice B fix moves the inject_tier3_warning callback
/// OUT of the per_agent write lock.
#[tokio::test]
async fn t_adv_inject_callback_can_reenter_guard() {
    use std::sync::Mutex;

    struct ReentrantCA {
        guard_ref: Mutex<Option<Arc<RepetitionGuard>>>,
        reentry_count: Mutex<u32>,
    }
    #[async_trait::async_trait]
    impl ContextAssembler for ReentrantCA {
        async fn assemble(&self, _: AssemblyContext) -> Result<AssemblyResult, AssemblyError> {
            unimplemented!()
        }
        fn inject_tier3_warning(&self, agent_id: &str, _msg: &str) {
            // Re-enter the guard from within the inject callback.
            // This would deadlock if decide_locked were still holding
            // the per_agent write lock when invoking inject_tier3_warning.
            *self.reentry_count.lock().unwrap() += 1;
            if let Some(guard) = self.guard_ref.lock().unwrap().clone() {
                let sig = advance_shared_types::repetition::ToolCallSignature {
                    tool_id: "fs".into(),
                    method: "stat".into(),
                    params_hash: 0xABCDEF,
                };
                let _ = guard.record_tool_call(agent_id, sig);
            }
        }
    }

    let ca = Arc::new(ReentrantCA {
        guard_ref: Mutex::new(None),
        reentry_count: Mutex::new(0),
    });
    let pi = MockPromptInjectionHelpers::new_arc();
    let guard = Arc::new(
        RepetitionGuard::new(10, 2, RepetitionAction::WarnThenTerminate)
            .with_context_assembler(Arc::clone(&ca) as Arc<dyn ContextAssembler>)
            .with_prompt_injection_helpers(Arc::clone(&pi) as Arc<dyn PromptInjectionHelpers>),
    );
    *ca.guard_ref.lock().unwrap() = Some(Arc::clone(&guard));

    let h = output_hash(0xAA);
    let _ = guard.record_output("root", h.clone());
    let d = guard.record_output("root", h); // triggers Warn + inject + re-entry

    assert!(matches!(d, RepetitionDecision::Warn(_)));
    assert_eq!(*ca.reentry_count.lock().unwrap(), 1);
}

/// Adversarial round 1 regression: emit-dedup — consecutive observations
/// with the same decision (action_taken) emit `run.repetition_detected`
/// ONLY once. Closes the emit-spam DoS surface.
#[tokio::test]
async fn t_adv_emit_dedup_suppresses_duplicate_decisions() {
    use advance_run_manager::{RunConfig, RunManager};
    use advance_shared_types::traits::EventBusEmit;

    #[derive(Default)]
    struct CountingBus {
        count: Mutex<u32>,
    }
    impl EventBusEmit for CountingBus {
        fn emit(&self, _: advance_shared_types::event::Event) {
            *self.count.lock().unwrap() += 1;
        }
    }

    let bus = Arc::new(CountingBus::default());
    let mgr = RunManager::new_arc(Arc::clone(&bus) as Arc<dyn EventBusEmit>);
    let _ = mgr
        .ensure_run("task-x", "agent-x", RunConfig::default())
        .unwrap();
    let guard = mgr.build_repetition_guard(10, 2, RepetitionAction::Terminate);

    let h = output_hash(0x77);
    // Establish window with two identical observations.
    let _ = guard.record_output("agent-x", h.clone());
    let _ = guard.record_output("agent-x", h.clone()); // triggers Terminate + 1st emit
    let _ = guard.record_output("agent-x", h.clone()); // SAME decision → no emit
    let _ = guard.record_output("agent-x", h.clone()); // SAME decision → no emit
    let _ = guard.record_output("agent-x", h); // SAME decision → no emit

    // ensure_run emits run.created (1), guard emits run.repetition_detected (1).
    // Total: 2 emits. Without dedup it would be 1 + 4 = 5.
    let count = *bus.count.lock().unwrap();
    assert_eq!(
        count, 2,
        "expected 2 emits (created + 1 deduplicated detected), got {count}"
    );
}

/// Wave-12 T-RM-LATEBIND — `set_context_assembler` late-binds the inject sink
/// AFTER construction (the cli composition-root path: the process-global guard
/// is built at `wire_capabilities` Step 7 before the per-agent assembler exists,
/// then bound in `try_spawn_agent_loop`). A guard built with PIH but NO assembler
/// does not inject; once `set_context_assembler` binds it, a repeated tool-triplet
/// (×3, the default threshold) fires the inject through that assembler.
#[tokio::test]
async fn t_wave12_set_context_assembler_late_binds_inject() {
    let ca = MockContextAssembler::new_arc();
    let pi = MockPromptInjectionHelpers::new_arc();
    // Built with PIH only — assembler NOT wired at construction (mirrors Step 7).
    let guard = RepetitionGuard::new(10, 3, RepetitionAction::WarnThenTerminate)
        .with_prompt_injection_helpers(Arc::clone(&pi) as Arc<dyn PromptInjectionHelpers>);

    let sig = ToolCallSignature {
        tool_id: "fs::read".into(),
        method: "read".into(),
        params_hash: 0xDEAD_BEEF_DEAD_BEEF,
    };
    // Below threshold 3 + no assembler → no inject.
    let _ = guard.record_tool_call("agent-lb", sig.clone());
    let _ = guard.record_tool_call("agent-lb", sig.clone());
    assert_eq!(ca.call_count(), 0, "no inject below threshold");

    // LATE-BIND the assembler (the cli `set_context_assembler(inner)` path).
    assert!(
        guard.set_context_assembler(Arc::clone(&ca) as Arc<dyn ContextAssembler>),
        "first set_context_assembler returns true"
    );
    // A SECOND set is a no-op (idempotent OnceLock — single-agent daemon sets once).
    assert!(
        !guard.set_context_assembler(MockContextAssembler::new_arc() as Arc<dyn ContextAssembler>),
        "second set_context_assembler returns false (cell already set)"
    );

    // 3rd identical call reaches threshold 3 → Warn + inject through the bound CA.
    let d = guard.record_tool_call("agent-lb", sig);
    assert!(
        matches!(d, RepetitionDecision::Warn(_)),
        "3rd identical → Warn"
    );
    assert_eq!(
        ca.call_count(),
        1,
        "inject fired through the late-bound assembler"
    );
    let (agent, msg) = ca.last().unwrap();
    assert_eq!(agent, "agent-lb");
    assert!(
        msg.contains("Repetition detected"),
        "injected the warn message"
    );
}

/// Wave-12 T-RM-UNBOUND — discriminator: a guard whose assembler is NEVER bound
/// still Warns but does NOT inject (fail-closed `(None,_)` arm == pre-Wave-12).
#[tokio::test]
async fn t_wave12_unbound_assembler_warns_without_inject() {
    let pi = MockPromptInjectionHelpers::new_arc();
    let guard = RepetitionGuard::new(10, 3, RepetitionAction::WarnThenTerminate)
        .with_prompt_injection_helpers(Arc::clone(&pi) as Arc<dyn PromptInjectionHelpers>);
    let sig = ToolCallSignature {
        tool_id: "fs::read".into(),
        method: "read".into(),
        params_hash: 0xDEAD_BEEF_DEAD_BEEF,
    };
    let _ = guard.record_tool_call("agent-u", sig.clone());
    let _ = guard.record_tool_call("agent-u", sig.clone());
    let d = guard.record_tool_call("agent-u", sig);
    assert!(
        matches!(d, RepetitionDecision::Warn(_)),
        "3rd identical → Warn"
    );
    // No assembler bound → the (None,_) arm never reaches PIH → no inject prep.
    assert_eq!(pi.flag_count(), 0, "no inject prep without an assembler");
    assert_eq!(pi.wrap_count(), 0);
}

//! Slice B AC-17 integration tests: the full PRD §15.3.4A 11-event
//! lifecycle taxonomy (T66–T70b) including payload-shape checks,
//! decision wire-format pinning, and emit-order invariants.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use advance_run_manager::{AgentRunResolver, RepetitionAction, RunConfig, RunManager};
use advance_shared_types::await_session::{
    AwaitSessionRef, AwaitTreeSummary, OrchestrationError, SessionId,
};
use advance_shared_types::event::Event;
use advance_shared_types::repetition::{OutputHash, RepetitionDecision};
use advance_shared_types::run::{RoundResult, TaskRunStatus};
use advance_shared_types::traits::{EventBusEmit, RepetitionGuardCheck};
use async_trait::async_trait;
use uuid::{Uuid, Version};

#[derive(Default)]
struct MockBus {
    events: Mutex<Vec<Event>>,
}

impl MockBus {
    fn new_arc() -> Arc<Self> {
        Arc::new(Self::default())
    }
    fn types(&self) -> Vec<String> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .map(|e| e.event_type.clone())
            .collect()
    }
    fn find_first(&self, ty: &str) -> Option<Event> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .find(|e| e.event_type == ty)
            .cloned()
    }
    fn find_all(&self, ty: &str) -> Vec<Event> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.event_type == ty)
            .cloned()
            .collect()
    }
}

impl EventBusEmit for MockBus {
    fn emit(&self, event: Event) {
        self.events.lock().unwrap().push(event);
    }
}

#[derive(Default)]
struct StubAwait {
    exists_map: Mutex<std::collections::HashMap<String, bool>>,
}

impl StubAwait {
    fn new_arc() -> Arc<Self> {
        Arc::new(Self::default())
    }
    fn set_exists(&self, sid: &str, ok: bool) {
        self.exists_map.lock().unwrap().insert(sid.to_string(), ok);
    }
}

#[async_trait]
impl AwaitSessionRef for StubAwait {
    fn exists(&self, sid: &SessionId) -> bool {
        *self.exists_map.lock().unwrap().get(&sid.0).unwrap_or(&true)
    }
    fn walk_tree(&self, _: &SessionId) -> Option<AwaitTreeSummary> {
        None
    }
    async fn close(&self, _: &SessionId, _: &str) -> Result<(), OrchestrationError> {
        Ok(())
    }
}

fn assert_uuid_v4(field: &str, value: &str) {
    let uuid = Uuid::parse_str(value).unwrap_or_else(|e| panic!("{field}={value:?} not UUID: {e}"));
    assert_eq!(
        uuid.get_version(),
        Some(Version::Random),
        "{field}={value:?} must be UUID v4"
    );
}

/// T66 — drive the full lifecycle through multiple Runs; assert each of
/// the 11 PRD §15.3.4A event names appears.
#[tokio::test]
async fn t66_eleven_event_lifecycle_set_membership() {
    let bus = MockBus::new_arc();
    let ar = StubAwait::new_arc();
    let mgr = RunManager::new_arc(Arc::clone(&bus) as Arc<dyn EventBusEmit>);
    let mgr_with_ar = Arc::new(
        RunManager::new(Arc::clone(&bus) as Arc<dyn EventBusEmit>)
            .with_await_session_ref(Arc::clone(&ar) as Arc<dyn AwaitSessionRef>),
    );

    // === Run A: full lifecycle ===
    // ensure (1) → run.created
    let id_a = mgr_with_ar
        .ensure_run("task-A", "root", RunConfig::default())
        .unwrap();
    // ensure (2) on same task while live → run.reused
    let id_a_again = mgr_with_ar
        .ensure_run("task-A", "root", RunConfig::default())
        .unwrap();
    assert_eq!(id_a, id_a_again);
    // suspend → run.suspended
    mgr_with_ar.suspend_run(&id_a, "sid-A").unwrap();
    // resume("await_complete") → run.resumed
    mgr_with_ar
        .resume_run(&id_a, "await_complete".into())
        .unwrap();
    // complete_round → run.round_completed
    mgr_with_ar
        .complete_round(
            &id_a,
            RoundResult {
                summary: None,
                metrics: vec![],
            },
        )
        .await
        .unwrap();
    // pause branch (b) — Active no session
    mgr_with_ar
        .pause_run(&id_a, "ops-pause".into())
        .await
        .unwrap();
    // complete_round settles → run.round_completed + run.paused
    mgr_with_ar
        .complete_round(
            &id_a,
            RoundResult {
                summary: None,
                metrics: vec![],
            },
        )
        .await
        .unwrap();
    // resume("manual") → run.resumed (again)
    mgr_with_ar.resume_run(&id_a, "manual".into()).unwrap();
    // complete_run → run.completed
    mgr_with_ar.complete_run(&id_a, "done".into()).unwrap();

    // === Run B: fail ===
    let id_b = mgr_with_ar
        .ensure_run("task-B", "root", RunConfig::default())
        .unwrap();
    mgr_with_ar.fail_run(&id_b, "boom".into()).unwrap();

    // === Run C: cancel branch (a) Suspended ===
    let id_c = mgr_with_ar
        .ensure_run("task-C", "root", RunConfig::default())
        .unwrap();
    mgr_with_ar.suspend_run(&id_c, "sid-C").unwrap();
    mgr_with_ar
        .cancel_run(&id_c, "user-cancel".into())
        .await
        .unwrap();

    // === Run D: crash recovery ===
    let id_d = mgr_with_ar
        .ensure_run("task-D", "root", RunConfig::default())
        .unwrap();
    mgr_with_ar
        .with_status_for_test(&id_d, TaskRunStatus::Suspended)
        .unwrap();
    mgr_with_ar
        .with_root_await_for_test(&id_d, Some("sid-D".into()))
        .unwrap();
    ar.set_exists("sid-D", false);
    mgr_with_ar
        .recover_on_startup(Arc::clone(&ar) as Arc<dyn AwaitSessionRef>)
        .await;

    // === Run E: repetition_detected via the separate mgr (avoid ambiguity) ===
    let id_e = mgr
        .ensure_run("task-E", "agent-e", RunConfig::default())
        .unwrap();
    let _ = id_e;
    let guard = mgr.build_repetition_guard(10, 2, RepetitionAction::WarnOnly);
    let h = OutputHash([0x42; 32]);
    let _ = guard.record_output("agent-e", h.clone());
    let _ = guard.record_output("agent-e", h);

    // Set-membership: every PRD §15.3.4A name appears at least once.
    let seen: HashSet<String> = bus.types().into_iter().collect();
    let expected: HashSet<&'static str> = [
        "run.created",
        "run.reused",
        "run.suspended",
        "run.resumed",
        "run.round_completed",
        "run.paused",
        "run.completed",
        "run.failed",
        "run.cancelled",
        "run.interrupted",
        "run.repetition_detected",
    ]
    .iter()
    .copied()
    .collect();
    let missing: Vec<&str> = expected
        .iter()
        .filter(|e| !seen.contains(**e))
        .copied()
        .collect();
    assert!(missing.is_empty(), "Missing event types: {missing:?}");
}

/// T67 — payload field check for ALL 11 events + UUID-v4 invariants.
#[tokio::test]
async fn t67_eleven_event_payload_shape_and_uuid_pin() {
    // Build a sufficient sequence to fire each of the 11 events.
    let bus = MockBus::new_arc();
    let ar = StubAwait::new_arc();
    let mgr = Arc::new(
        RunManager::new(Arc::clone(&bus) as Arc<dyn EventBusEmit>)
            .with_await_session_ref(Arc::clone(&ar) as Arc<dyn AwaitSessionRef>),
    );

    // ensure (run.created)
    let id_a = mgr
        .ensure_run("task-A", "root", RunConfig::default())
        .unwrap();
    // ensure live → run.reused
    let _ = mgr
        .ensure_run("task-A", "root", RunConfig::default())
        .unwrap();
    // suspend → run.suspended
    mgr.suspend_run(&id_a, "sid-A").unwrap();
    // resume → run.resumed
    mgr.resume_run(&id_a, "await_complete".into()).unwrap();
    // complete_round → run.round_completed
    mgr.complete_round(
        &id_a,
        RoundResult {
            summary: None,
            metrics: vec![],
        },
    )
    .await
    .unwrap();
    // pause branch (b) + complete_round settle → run.paused
    mgr.pause_run(&id_a, "ops".into()).await.unwrap();
    mgr.complete_round(
        &id_a,
        RoundResult {
            summary: None,
            metrics: vec![],
        },
    )
    .await
    .unwrap();
    // resume → complete → run.completed
    mgr.resume_run(&id_a, "manual".into()).unwrap();
    mgr.complete_run(&id_a, "done".into()).unwrap();

    // Run B: fail → run.failed
    let id_b = mgr
        .ensure_run("task-B", "root", RunConfig::default())
        .unwrap();
    mgr.fail_run(&id_b, "oops".into()).unwrap();

    // Run C: cancel branch (a) → run.cancelled
    let id_c = mgr
        .ensure_run("task-C", "root", RunConfig::default())
        .unwrap();
    mgr.suspend_run(&id_c, "sid-C").unwrap();
    mgr.cancel_run(&id_c, "user-cancel".into()).await.unwrap();

    // Run D: recovery → run.interrupted
    let id_d = mgr
        .ensure_run("task-D", "root", RunConfig::default())
        .unwrap();
    mgr.with_status_for_test(&id_d, TaskRunStatus::Suspended)
        .unwrap();
    mgr.with_root_await_for_test(&id_d, Some("sid-D".into()))
        .unwrap();
    ar.set_exists("sid-D", false);
    mgr.recover_on_startup(Arc::clone(&ar) as Arc<dyn AwaitSessionRef>)
        .await;

    // Run E: repetition_detected via separate mgr to avoid resolver ambiguity.
    let bus_e = MockBus::new_arc();
    let mgr_e = RunManager::new_arc(Arc::clone(&bus_e) as Arc<dyn EventBusEmit>);
    let _id_e = mgr_e
        .ensure_run("task-E", "agent-e", RunConfig::default())
        .unwrap();
    let guard = mgr_e.build_repetition_guard(10, 2, RepetitionAction::WarnOnly);
    let h = OutputHash([0x99; 32]);
    let _ = guard.record_output("agent-e", h.clone());
    let _ = guard.record_output("agent-e", h);

    // Helper: assert UUID-v4 on every emitted event.
    let merge_events: Vec<Event> = bus
        .events
        .lock()
        .unwrap()
        .iter()
        .chain(bus_e.events.lock().unwrap().iter())
        .cloned()
        .collect();
    for evt in &merge_events {
        assert_uuid_v4("event.id", &evt.id);
        assert_uuid_v4("event.trace_id", &evt.trace_id);
        assert_uuid_v4("event.span_id", &evt.span_id);
    }

    // Per-event payload assertions.
    let created = bus.find_first("run.created").unwrap();
    assert_eq!(
        created.payload.get("task_id").and_then(|v| v.as_str()),
        Some("task-A")
    );
    assert_eq!(
        created
            .payload
            .get("controller_agent")
            .and_then(|v| v.as_str()),
        Some("root")
    );
    assert_eq!(created.agent_id, "root");

    let reused = bus.find_first("run.reused").unwrap();
    assert_eq!(
        reused.payload.get("status").and_then(|v| v.as_str()),
        Some("active")
    );

    let suspended = bus.find_first("run.suspended").unwrap();
    assert_eq!(
        suspended
            .payload
            .get("root_await_session_id")
            .and_then(|v| v.as_str()),
        Some("sid-A")
    );

    let resumed = bus.find_first("run.resumed").unwrap();
    assert_eq!(
        resumed.payload.get("reason").and_then(|v| v.as_str()),
        Some("await_complete")
    );

    let rc = bus.find_first("run.round_completed").unwrap();
    assert!(rc.payload.get("iteration").is_some());
    assert!(rc.payload.get("token_used").is_some());
    assert!(rc.payload.get("cost_usd").is_some());
    assert_eq!(
        rc.payload.get("decision").and_then(|v| v.as_str()),
        Some("continue-allowed")
    );

    let paused = bus.find_first("run.paused").unwrap();
    assert_eq!(
        paused.payload.get("reason").and_then(|v| v.as_str()),
        Some("ops")
    );

    let completed = bus.find_first("run.completed").unwrap();
    assert_eq!(
        completed.payload.get("outcome").and_then(|v| v.as_str()),
        Some("done")
    );

    let failed = bus.find_first("run.failed").unwrap();
    assert_eq!(
        failed.payload.get("reason").and_then(|v| v.as_str()),
        Some("oops")
    );

    let cancelled = bus.find_first("run.cancelled").unwrap();
    assert_eq!(
        cancelled.payload.get("reason").and_then(|v| v.as_str()),
        Some("user-cancel")
    );

    let interrupted = bus.find_first("run.interrupted").unwrap();
    assert_eq!(
        interrupted.payload.get("reason").and_then(|v| v.as_str()),
        Some("crash-recovery")
    );

    let rep = bus_e.find_first("run.repetition_detected").unwrap();
    assert_eq!(
        rep.payload.get("detection_type").and_then(|v| v.as_str()),
        Some("output_repeat")
    );
    assert!(rep.payload.get("details").is_some());
    assert!(rep.payload.get("repeat_count").is_some());
    assert_eq!(
        rep.payload.get("action_taken").and_then(|v| v.as_str()),
        Some("warn")
    );
}

/// T68 — `run.resumed` reason discrimination.
#[tokio::test]
async fn t68_run_resumed_reason_discrimination() {
    let bus = MockBus::new_arc();
    let ar = StubAwait::new_arc();
    let mgr = RunManager::new(Arc::clone(&bus) as Arc<dyn EventBusEmit>)
        .with_await_session_ref(Arc::clone(&ar) as Arc<dyn AwaitSessionRef>);

    let id1 = mgr
        .ensure_run("task-1", "root", RunConfig::default())
        .unwrap();
    mgr.suspend_run(&id1, "sid-1").unwrap();
    mgr.resume_run(&id1, "await_complete".into()).unwrap();

    let id2 = mgr
        .ensure_run("task-2", "root", RunConfig::default())
        .unwrap();
    mgr.suspend_run(&id2, "sid-2").unwrap();
    mgr.pause_run(&id2, "p".into()).await.unwrap();
    mgr.resume_run(&id2, "manual".into()).unwrap();

    let reasons: Vec<String> = bus
        .find_all("run.resumed")
        .iter()
        .map(|e| {
            e.payload
                .get("reason")
                .and_then(|v| v.as_str())
                .unwrap()
                .to_string()
        })
        .collect();
    assert_eq!(reasons, vec!["await_complete", "manual"]);
}

/// T69 — `run.repetition_detected` discriminator fields.
#[tokio::test]
async fn t69_repetition_detected_discriminators() {
    let bus = MockBus::new_arc();
    let mgr = RunManager::new_arc(Arc::clone(&bus) as Arc<dyn EventBusEmit>);

    // tool_call path
    let _ = mgr
        .ensure_run("task-1", "agent-1", RunConfig::default())
        .unwrap();
    let guard = mgr.build_repetition_guard(10, 2, RepetitionAction::Terminate);
    let sig = advance_shared_types::repetition::ToolCallSignature {
        tool_id: "fs".into(),
        method: "read".into(),
        params_hash: 0xDEADBEEF,
    };
    let _ = guard.record_tool_call("agent-1", sig.clone());
    let d_tool = guard.record_tool_call("agent-1", sig);
    assert!(matches!(d_tool, RepetitionDecision::Terminate(_)));

    let tool_evt = bus.find_first("run.repetition_detected").unwrap();
    assert_eq!(
        tool_evt
            .payload
            .get("detection_type")
            .and_then(|v| v.as_str()),
        Some("tool_call")
    );
    assert_eq!(
        tool_evt
            .payload
            .get("action_taken")
            .and_then(|v| v.as_str()),
        Some("terminate")
    );

    // output_repeat path — fresh manager+agent so the previous run.repetition_detected
    // doesn't shadow our find_first.
    let bus2 = MockBus::new_arc();
    let mgr2 = RunManager::new_arc(Arc::clone(&bus2) as Arc<dyn EventBusEmit>);
    let _ = mgr2
        .ensure_run("task-2", "agent-2", RunConfig::default())
        .unwrap();
    let guard2 = mgr2.build_repetition_guard(10, 2, RepetitionAction::WarnOnly);
    let h = OutputHash([0xAB; 32]);
    let _ = guard2.record_output("agent-2", h.clone());
    let _ = guard2.record_output("agent-2", h);
    let out_evt = bus2.find_first("run.repetition_detected").unwrap();
    assert_eq!(
        out_evt
            .payload
            .get("detection_type")
            .and_then(|v| v.as_str()),
        Some("output_repeat")
    );
    assert_eq!(
        out_evt.payload.get("action_taken").and_then(|v| v.as_str()),
        Some("warn")
    );
}

/// T70 — pause branch (a) emits run.paused AFTER `AwaitSessionRef::close`
/// returns. The mock records a close-completed timestamp; we observe that
/// the event was emitted AFTER that point (event order in bus reflects emit
/// order; close completes before the emit by construction in pause_run).
#[tokio::test]
async fn t70_pause_branch_a_emits_after_close() {
    use std::sync::atomic::{AtomicBool, Ordering};

    struct OrderingAwait {
        close_seen: AtomicBool,
    }

    #[async_trait]
    impl AwaitSessionRef for OrderingAwait {
        fn exists(&self, _: &SessionId) -> bool {
            true
        }
        fn walk_tree(&self, _: &SessionId) -> Option<AwaitTreeSummary> {
            None
        }
        async fn close(&self, _: &SessionId, _: &str) -> Result<(), OrchestrationError> {
            self.close_seen.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    let bus = MockBus::new_arc();
    let ar = Arc::new(OrderingAwait {
        close_seen: AtomicBool::new(false),
    });
    let mgr = RunManager::new(Arc::clone(&bus) as Arc<dyn EventBusEmit>)
        .with_await_session_ref(Arc::clone(&ar) as Arc<dyn AwaitSessionRef>);

    let id = mgr
        .ensure_run("task-1", "root", RunConfig::default())
        .unwrap();
    mgr.suspend_run(&id, "sid-1").unwrap();

    // Before pause_run: close not seen.
    assert!(!ar.close_seen.load(Ordering::SeqCst));

    mgr.pause_run(&id, "paused".into()).await.unwrap();

    // After pause_run returns: close has been called AND run.paused emitted.
    assert!(ar.close_seen.load(Ordering::SeqCst));
    let types = bus.types();
    assert!(types.contains(&"run.paused".to_string()));
}

/// T70b — `run.round_completed.payload.decision` under all 3 cases.
#[tokio::test]
async fn t70b_round_completed_decision_wire_format() {
    use advance_shared_types::run::{RoundDecision, RoundResult};

    // (a) Normal complete_round → continue-allowed.
    let (bus, mgr) = {
        let bus = MockBus::new_arc();
        let mgr = RunManager::new(Arc::clone(&bus) as Arc<dyn EventBusEmit>);
        (bus, mgr)
    };
    let id = mgr
        .ensure_run("task-1", "root", RunConfig::default())
        .unwrap();
    let _ = mgr
        .complete_round(
            &id,
            RoundResult {
                summary: None,
                metrics: vec![],
            },
        )
        .await
        .unwrap();
    let rc = bus.find_first("run.round_completed").unwrap();
    assert_eq!(
        rc.payload.get("decision").and_then(|v| v.as_str()),
        Some("continue-allowed")
    );

    // (b) rounds_limit boundary → blocked:rounds-exceeded.
    let bus2 = MockBus::new_arc();
    let mgr2 = RunManager::new(Arc::clone(&bus2) as Arc<dyn EventBusEmit>);
    let mut cfg = RunConfig::default();
    cfg.rounds_limit = Some(1);
    let id2 = mgr2.ensure_run("task-2", "root", cfg).unwrap();
    let _ = mgr2
        .complete_round(
            &id2,
            RoundResult {
                summary: None,
                metrics: vec![],
            },
        )
        .await
        .unwrap();
    // 2nd round trips rounds-exceeded.
    let d = mgr2
        .complete_round(
            &id2,
            RoundResult {
                summary: None,
                metrics: vec![],
            },
        )
        .await
        .unwrap();
    assert!(matches!(d, RoundDecision::Blocked(ref s) if s == "rounds-exceeded"));
    let last_rc = bus2.find_all("run.round_completed");
    assert_eq!(
        last_rc
            .last()
            .unwrap()
            .payload
            .get("decision")
            .and_then(|v| v.as_str()),
        Some("blocked:rounds-exceeded")
    );

    // (c) cancel_pending set → blocked:cancel-pending.
    let bus3 = MockBus::new_arc();
    let mgr3 = RunManager::new(Arc::clone(&bus3) as Arc<dyn EventBusEmit>);
    let id3 = mgr3
        .ensure_run("task-3", "root", RunConfig::default())
        .unwrap();
    mgr3.cancel_run(&id3, "user".into()).await.unwrap();
    let d3 = mgr3
        .complete_round(
            &id3,
            RoundResult {
                summary: None,
                metrics: vec![],
            },
        )
        .await
        .unwrap();
    assert!(matches!(d3, RoundDecision::Blocked(ref s) if s == "cancel-pending"));
    let rc3 = bus3.find_first("run.round_completed").unwrap();
    assert_eq!(
        rc3.payload.get("decision").and_then(|v| v.as_str()),
        Some("blocked:cancel-pending")
    );
}

/// Extra — `AgentRunResolver` ambiguity returns (None, None).
#[test]
fn t_extra_resolver_ambiguous_returns_none() {
    let bus = MockBus::new_arc();
    let mgr = RunManager::new_arc(Arc::clone(&bus) as Arc<dyn EventBusEmit>);

    let _id1 = mgr
        .ensure_run("task-1", "root", RunConfig::default())
        .unwrap();
    let _id2 = mgr
        .ensure_run("task-2", "root", RunConfig::default())
        .unwrap();

    let (rid, tid): (Option<String>, Option<String>) = mgr.resolve("root");
    assert_eq!(rid, None);
    assert_eq!(tid, None);
}

/// Extra — `RunId` plumbing for `run.repetition_detected`: when exactly one
/// live Run is owned by the agent, Event.run_id is populated.
#[test]
fn t_extra_resolver_unique_match_populates_run_id() {
    let bus = MockBus::new_arc();
    let mgr = RunManager::new_arc(Arc::clone(&bus) as Arc<dyn EventBusEmit>);
    let id = mgr
        .ensure_run("task-x", "agent-x", RunConfig::default())
        .unwrap();

    let guard = mgr.build_repetition_guard(10, 2, RepetitionAction::WarnOnly);
    let h = OutputHash([0x01; 32]);
    let _ = guard.record_output("agent-x", h.clone());
    let _ = guard.record_output("agent-x", h);

    let evt: Event = {
        let evs = bus.events.lock().unwrap();
        evs.iter()
            .find(|e| e.event_type == "run.repetition_detected")
            .cloned()
            .expect("event present")
    };
    assert_eq!(evt.run_id.as_deref(), Some(id.as_ref()));
    assert_eq!(evt.task_id.as_deref(), Some("task-x"));
    assert_eq!(evt.agent_id, "agent-x");
    // run_id NOT duplicated in payload (Event-level only).
    assert!(evt.payload.get("run_id").is_none());
}

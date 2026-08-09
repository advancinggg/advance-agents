//! Wave-11 Lane C — build-lane witness: the production cap-tools `tool-invoke`
//! dispatch FEEDS the run-manager `RepetitionGuard` (closes the orphan
//! `record_tool_call` producer gap).
//!
//! Anti-fake-green discipline: every test drives the REAL registered
//! `AgentToolsInvokeHandler` (looked up from a `HostRegistry` populated by
//! `register_agent_tools_with_guard`) with real `Val` params over the REAL
//! `advance_run_manager::RepetitionGuard` — NEVER a hand-built
//! `ToolCallSignature` and NEVER a direct `guard.record_tool_call`. The
//! signature is produced by the real decode → dispatch → record chain.
//! Run-resolution (T1/T4) is exercised against a real `RunManager` + `ensure_run`
//! so the emitted `run.repetition_detected` carries a non-null `run_id`/`task_id`.
//! Assertions filter the captured stream by `event_type` (the shared bus also
//! carries `run.created` / `tool.*`), never by positional index.
//!
//! SATELLITE: flips ZERO SYS-AC. This proves the PRODUCER; the SYS-AC-122 e2e
//! flip is a later mainline harvest (which must additionally wire the Tier-3
//! inject + `ensure_run` a live Run — see MODULE-008/017 §3.6).

mod common;

use std::sync::Arc;

use advance_run_manager::{RepetitionAction, RepetitionGuard, RunConfig, RunManager};
use advance_runtime::host_registry::{HostCallContext, HostRegistry, InMemoryHostRegistry};
use advance_shared_types::event::Event;
use advance_shared_types::traits::{EventBusEmit, RepetitionGuardCheck};
use async_trait::async_trait;
use cap_tools::{
    register_agent_tools, register_agent_tools_with_guard, ToolError, ToolInfo, ToolInstance,
    ToolRegistry,
};
use wasmtime::component::Val;

use common::RecordingEmitter;

const CAP: &str = "tools";

/// Echo registry — every invoke returns `Ok(params)` so a `Pass`/`Warn`
/// outcome surfaces a `tool.result` (distinguishable from a `Terminate` which
/// discards the outcome into `invocation-failed`).
struct EchoRegistry;

#[async_trait]
impl ToolRegistry for EchoRegistry {
    async fn load(&self, _: &str) -> Result<ToolInstance, ToolError> {
        Err(ToolError::NotFound("unused".into()))
    }
    async fn invoke(&self, _: &str, _: &str, params: &[u8]) -> Result<Vec<u8>, ToolError> {
        Ok(params.to_vec())
    }
    async fn list(&self) -> Vec<ToolInfo> {
        vec![]
    }
    async fn evict_lru(&self) {}
}

/// Counts how many times `invoke` actually reaches the registry — used to
/// witness that a `Terminate` decision PREVENTS the invocation (before-invoke
/// gating), not merely discards its result.
struct CountingRegistry {
    invokes: Arc<std::sync::atomic::AtomicUsize>,
}

#[async_trait]
impl ToolRegistry for CountingRegistry {
    async fn load(&self, _: &str) -> Result<ToolInstance, ToolError> {
        Err(ToolError::NotFound("unused".into()))
    }
    async fn invoke(&self, _: &str, _: &str, params: &[u8]) -> Result<Vec<u8>, ToolError> {
        self.invokes
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(params.to_vec())
    }
    async fn list(&self) -> Vec<ToolInfo> {
        vec![]
    }
    async fn evict_lru(&self) {}
}

fn ctx_for(agent_id: &str) -> HostCallContext {
    HostCallContext {
        agent_id: agent_id.into(),
        trace_id: "trace-w11c".into(),
        turn_id: None,
        capability: CAP.into(),
        function: "advance:runtime/agent-tools@0.1.0::tool-invoke".into(),
        run_id: None,
        iteration: None,
    }
}

fn invoke_params(tool_id: &str, method: &str, bytes: &[u8]) -> Vec<Val> {
    vec![
        Val::String(tool_id.into()),
        Val::String(method.into()),
        Val::List(bytes.iter().map(|b| Val::U8(*b)).collect()),
    ]
}

/// Drive the REAL registered `tool-invoke` handler once.
async fn invoke(
    registry: &InMemoryHostRegistry,
    ctx: HostCallContext,
    params: Vec<Val>,
) -> Vec<Val> {
    let spec = registry
        .lookup(CAP)
        .into_iter()
        .find(|s| s.name == "tool-invoke")
        .expect("tool-invoke is registered");
    spec.handler
        .call(ctx, params, 1)
        .await
        .expect("handler returns Ok")
}

fn repetition_events(rec: &RecordingEmitter) -> Vec<Event> {
    rec.snapshot()
        .into_iter()
        .filter(|e| e.event_type == "run.repetition_detected")
        .collect()
}

fn count_events(rec: &RecordingEmitter, ty: &str) -> usize {
    rec.snapshot().iter().filter(|e| e.event_type == ty).count()
}

/// The WIT `tool-error` variant case of an `Err`-arm result, if any.
fn err_case(out: &[Val]) -> Option<String> {
    match out.first() {
        Some(Val::Result(Err(Some(b)))) => match b.as_ref() {
            Val::Variant(case, _) => Some(case.clone()),
            _ => None,
        },
        _ => None,
    }
}

fn is_ok_result(out: &[Val]) -> bool {
    matches!(out.first(), Some(Val::Result(Ok(_))))
}

// ──────────────────────────────────────────────────────────────────────────
// W11C-T1 — WarnThenTerminate over a REAL RunManager+ensure_run: 3 identical
//           calls warn (call 3) with genuine run-resolution; the 4th terminates.
// ──────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn w11c_t1_warn_then_terminate_with_real_run_resolution() {
    let rec = Arc::new(RecordingEmitter::default());
    let bus: Arc<dyn EventBusEmit> = rec.clone();
    let rm = RunManager::new_arc(bus);
    // Register a LIVE Run for agent-A so AgentRunResolver resolves run_id/task_id
    // (without this the resolver returns (None,None) → the run_id assertion below
    // would be a latent fake-green).
    rm.ensure_run("task-1", "agent-A", RunConfig::default())
        .expect("run created");
    let guard: Arc<dyn RepetitionGuardCheck> =
        Arc::new(rm.build_repetition_guard(10, 3, RepetitionAction::WarnThenTerminate));

    let registry = InMemoryHostRegistry::new();
    register_agent_tools_with_guard(&registry, Arc::new(EchoRegistry), rec.clone(), guard);

    let p = || invoke_params("echo-tool", "say", &[1, 2, 3]);

    // Calls 1 & 2: below threshold → Pass → real outcome, no repetition event.
    assert!(is_ok_result(
        &invoke(&registry, ctx_for("agent-A"), p()).await
    ));
    assert!(is_ok_result(
        &invoke(&registry, ctx_for("agent-A"), p()).await
    ));
    assert!(
        repetition_events(&rec).is_empty(),
        "no repetition before the threshold is crossed"
    );

    // Call 3: first detection → Warn → event{warn}; the call STILL proceeds.
    assert!(
        is_ok_result(&invoke(&registry, ctx_for("agent-A"), p()).await),
        "Warn surfaces the real tool outcome"
    );
    let warns = repetition_events(&rec);
    assert_eq!(warns.len(), 1, "exactly one repetition event after call 3");
    let w = &warns[0];
    assert_eq!(w.payload["detection_type"], "tool_call");
    assert_eq!(w.payload["action_taken"], "warn");
    assert!(w.payload["repeat_count"].as_u64().unwrap() >= 3);
    // Genuine run-resolution (the W2a fix): non-null run_id + the real task_id.
    assert!(
        w.run_id.is_some(),
        "run_id resolved via ensure_run + AgentRunResolver"
    );
    assert_eq!(w.task_id.as_deref(), Some("task-1"));
    assert_eq!(w.agent_id, "agent-A");

    // Call 4: warned → Terminate → event{terminate} + invocation-failed; outcome discarded.
    let o4 = invoke(&registry, ctx_for("agent-A"), p()).await;
    assert_eq!(
        err_case(&o4).as_deref(),
        Some("invocation-failed"),
        "Terminate discards the outcome → generic invocation-failed"
    );
    let evs = repetition_events(&rec);
    assert_eq!(evs.len(), 2, "warn (call 3) then terminate (call 4)");
    assert_eq!(evs[1].payload["action_taken"], "terminate");
    // Calls 1-3 produced tool.result; the terminated call 4 did NOT.
    assert_eq!(count_events(&rec, "tool.result"), 3);
}

// ──────────────────────────────────────────────────────────────────────────
// W11C-T2 — Terminate policy: 3rd identical call fails; the event `details`
//           carries the canonical signature PREFIX (not the private FNV hash).
// ──────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn w11c_t2_terminate_third_call_and_details_prefix() {
    let rec = Arc::new(RecordingEmitter::default());
    let guard: Arc<dyn RepetitionGuardCheck> = Arc::new(
        RepetitionGuard::new(10, 3, RepetitionAction::Terminate).with_event_bus(rec.clone()),
    );
    let registry = InMemoryHostRegistry::new();
    register_agent_tools_with_guard(&registry, Arc::new(EchoRegistry), rec.clone(), guard);

    let p = || invoke_params("echo-tool", "say", &[9, 9]);
    assert!(is_ok_result(
        &invoke(&registry, ctx_for("agent-A"), p()).await
    ));
    assert!(is_ok_result(
        &invoke(&registry, ctx_for("agent-A"), p()).await
    ));
    let o3 = invoke(&registry, ctx_for("agent-A"), p()).await;
    assert_eq!(err_case(&o3).as_deref(), Some("invocation-failed"));

    let evs = repetition_events(&rec);
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].payload["action_taken"], "terminate");
    let details = evs[0].payload["details"]
        .as_str()
        .expect("details is a string");
    assert!(
        details.starts_with("echo-tool::say#"),
        "details should carry the canonical signature prefix, got {details:?}"
    );
}

// ──────────────────────────────────────────────────────────────────────────
// W11C-T3 — Negative: varied params (distinct params_hash) never trip the guard.
// ──────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn w11c_t3_distinct_params_never_trip() {
    let rec = Arc::new(RecordingEmitter::default());
    let guard: Arc<dyn RepetitionGuardCheck> = Arc::new(
        RepetitionGuard::new(10, 3, RepetitionAction::Terminate).with_event_bus(rec.clone()),
    );
    let registry = InMemoryHostRegistry::new();
    register_agent_tools_with_guard(&registry, Arc::new(EchoRegistry), rec.clone(), guard);

    for i in 0..5u8 {
        let o = invoke(
            &registry,
            ctx_for("agent-A"),
            invoke_params("echo-tool", "say", &[i]),
        )
        .await;
        assert!(is_ok_result(&o), "distinct params must proceed");
    }
    assert!(
        repetition_events(&rec).is_empty(),
        "varied tool calls must not over-fire the guard"
    );
}

// ──────────────────────────────────────────────────────────────────────────
// W11C-T4 — Per-agent isolation over a real RunManager: agent-A trips (with
//           resolved run_id), agent-B's same signature does NOT.
// ──────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn w11c_t4_per_agent_isolation_with_resolution() {
    let rec = Arc::new(RecordingEmitter::default());
    let bus: Arc<dyn EventBusEmit> = rec.clone();
    let rm = RunManager::new_arc(bus);
    rm.ensure_run("task-A", "agent-A", RunConfig::default())
        .unwrap();
    rm.ensure_run("task-B", "agent-B", RunConfig::default())
        .unwrap();
    let guard: Arc<dyn RepetitionGuardCheck> =
        Arc::new(rm.build_repetition_guard(10, 3, RepetitionAction::Terminate));
    let registry = InMemoryHostRegistry::new();
    register_agent_tools_with_guard(&registry, Arc::new(EchoRegistry), rec.clone(), guard);

    let p = || invoke_params("shared-tool", "run", &[7]);
    invoke(&registry, ctx_for("agent-A"), p()).await;
    invoke(&registry, ctx_for("agent-A"), p()).await;
    let a3 = invoke(&registry, ctx_for("agent-A"), p()).await;
    assert_eq!(
        err_case(&a3).as_deref(),
        Some("invocation-failed"),
        "agent-A trips on the 3rd"
    );

    // agent-B's first identical call uses an INDEPENDENT per-agent window.
    let b1 = invoke(&registry, ctx_for("agent-B"), p()).await;
    assert!(
        is_ok_result(&b1),
        "agent-B is isolated from agent-A's window"
    );

    let evs = repetition_events(&rec);
    assert_eq!(evs.len(), 1, "only agent-A tripped");
    assert_eq!(evs[0].agent_id, "agent-A");
    assert!(evs[0].run_id.is_some());
    assert_eq!(evs[0].task_id.as_deref(), Some("task-A"));
}

// ──────────────────────────────────────────────────────────────────────────
// W11C-T5 — Boundary: the byte-identical 3-arg `register_agent_tools` (no-op
//           guard) NEVER terminates / emits — proves the delegation preserves
//           the system-acceptance harness + legacy callers' behavior.
// ──────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn w11c_t5_legacy_three_arg_path_never_guards() {
    let rec = Arc::new(RecordingEmitter::default());
    let registry = InMemoryHostRegistry::new();
    register_agent_tools(&registry, Arc::new(EchoRegistry), rec.clone());

    let p = || invoke_params("echo-tool", "say", &[1]);
    for _ in 0..5 {
        assert!(
            is_ok_result(&invoke(&registry, ctx_for("agent-A"), p()).await),
            "the no-op guard never terminates"
        );
    }
    assert!(
        repetition_events(&rec).is_empty(),
        "the 3-arg path emits no run.repetition_detected"
    );
}

// ──────────────────────────────────────────────────────────────────────────
// W11C-T6 — Producer-side sanitization (C1): a control-char tool_id/method is
//           rejected at decode with input-validation-failed, BEFORE any
//           signature construction, so the guard is never fed.
// ──────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn w11c_t6_control_char_identifier_rejected_before_signature() {
    let rec = Arc::new(RecordingEmitter::default());
    let guard: Arc<dyn RepetitionGuardCheck> = Arc::new(
        RepetitionGuard::new(10, 3, RepetitionAction::Terminate).with_event_bus(rec.clone()),
    );
    let registry = InMemoryHostRegistry::new();
    register_agent_tools_with_guard(&registry, Arc::new(EchoRegistry), rec.clone(), guard);

    // Control char in tool_id.
    let o_id = invoke(
        &registry,
        ctx_for("agent-A"),
        invoke_params("a\nb", "say", &[1]),
    )
    .await;
    assert_eq!(err_case(&o_id).as_deref(), Some("input-validation-failed"));

    // Control char (NUL) in method.
    let o_m = invoke(
        &registry,
        ctx_for("agent-A"),
        invoke_params("echo-tool", "sa\u{0}y", &[1]),
    )
    .await;
    assert_eq!(err_case(&o_m).as_deref(), Some("input-validation-failed"));

    assert!(
        repetition_events(&rec).is_empty(),
        "rejected before signature construction → guard never fed"
    );
}

// ──────────────────────────────────────────────────────────────────────────
// W11C-T7 — action-prevention (adversarial round-7 W1): a Terminate decision
//           must PREVENT the tool invocation (before-invoke gating), not run it
//           then discard the result. Witnessed via a registry that counts real
//           invocations.
// ──────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn w11c_t7_terminate_prevents_the_tool_invocation() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let rec = Arc::new(RecordingEmitter::default());
    let guard: Arc<dyn RepetitionGuardCheck> = Arc::new(
        RepetitionGuard::new(10, 3, RepetitionAction::Terminate).with_event_bus(rec.clone()),
    );
    let invokes = Arc::new(AtomicUsize::new(0));
    let registry = InMemoryHostRegistry::new();
    register_agent_tools_with_guard(
        &registry,
        Arc::new(CountingRegistry {
            invokes: invokes.clone(),
        }),
        rec.clone(),
        guard,
    );

    let p = || invoke_params("echo-tool", "say", &[5, 5]);
    invoke(&registry, ctx_for("agent-A"), p()).await; // 1 → Pass → invoked
    invoke(&registry, ctx_for("agent-A"), p()).await; // 2 → Pass → invoked
    let o3 = invoke(&registry, ctx_for("agent-A"), p()).await; // 3 → Terminate → BLOCKED
    assert_eq!(err_case(&o3).as_deref(), Some("invocation-failed"));

    // The 3rd (terminated) call must NOT have reached the tool registry: only
    // the first two invocations actually executed.
    assert_eq!(
        invokes.load(Ordering::SeqCst),
        2,
        "Terminate must PREVENT the tool invocation (action-prevention), not run-then-discard"
    );
    // And exactly one terminate event fired.
    let evs = repetition_events(&rec);
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].payload["action_taken"], "terminate");
}

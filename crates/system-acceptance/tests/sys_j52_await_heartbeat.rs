//! Track C — SYS-J-52 witness: await heartbeat + idle-timeout against the
//! **REAL `advance-reply-tracker` provider** (no mock/stub of any module in the
//! chain).
//!
//! ## What this file witnesses
//!
//! - **SYS-AC-165** (heartbeat → `orchestration.await_progress` + idle reset):
//!   split into two real-provider legs because the harness `RealBus`
//!   (synchronous `EventBus`) requires a `multi_thread` runtime while the
//!   idle-clock-RESET semantics are only observable under a virtual clock
//!   (`tokio::test(start_paused)`, single-thread) — the two cannot be combined:
//!     - `sys_ac_165_heartbeat_emits_await_progress_on_harness_bus`
//!       (`multi_thread`, `.events(EventSink::RealBus)`): the PARENT caller
//!       parks an `AgentRequest(target="agent:child")` session via the real
//!       `sut.await_manager().start(..)`; the heartbeat is driven AS THE CHILD
//!       through the real registered `HeartbeatHandler` via
//!       `sut.call_host_fn_as_agent("child", "messaging",
//!       "advance:runtime/agent-messaging@0.1.0", "heartbeat", ..)` so
//!       `heartbeat_for_target`'s `agent:child` needle matches the session's
//!       `AgentRequest` target. Asserts an `orchestration.await_progress` row in
//!       the real EventBus SQLite `events` table AND that the parked `start`
//!       future is NOT resolved (the heartbeat neither completed nor idle-closed
//!       the session — idle is reset / still open).
//!     - `sys_ac_165_heartbeat_resets_idle_clock` (`start_paused`,
//!       directly-constructed REAL `AwaitSessionManagerImpl` + a test-owned
//!       `EventBusEmit` sink): the faithful idle-clock-RESET witness. Parks an
//!       `AgentRequest(target="agent:child")` session with a short
//!       `idle_timeout_secs`; advances virtual time to just below the timeout;
//!       calls the EXACT method `HeartbeatHandler` calls
//!       (`manager.heartbeat_for_target("child", ..)`) and asserts it returns
//!       the parked session id (from-target match); then advances PAST the
//!       original timeout but within a fresh timeout window measured from the
//!       heartbeat — the session is STILL OPEN (the clock was reset). A final
//!       advance well past the timeout lets the REAL idle monitor fire,
//!       confirming the session was genuinely live (not leaked).
//!
//! - **SYS-AC-166** (`start_paused`, directly-constructed REAL manager): a
//!   2-slot `AllOf` session with `on_idle_timeout=ReturnPartial` + a short
//!   `idle_timeout_secs`; resolve ONE slot via the real `on_reply`; advance
//!   virtual time past the idle timeout; the parked `start` resolves
//!   `Ok(AwaitResult)` with `status == PartialTimeout`, the resolved slot
//!   `Completed`, and the silent slot `TimedOut`.
//!
//! - **SYS-AC-167** (`start_paused`, directly-constructed REAL manager): same
//!   2-slot `AllOf` shape with `on_idle_timeout=Fail`; advance past the idle
//!   timeout; the parked `start` resolves `Err(OrchestrationError::IdleTimeoutExceeded)`.
//!
//! ## REAL-PROVIDER witness (not a guest turn)
//!
//! Per the HF-sanctioned `mode_agents_smoke.rs` pattern, the guest→host reply /
//! heartbeat loop is upstream-blocked (no `send`/reply host-fn; see the crate
//! README "HF fast-follow blockers"), so each leg drives the REAL production
//! `advance_reply_tracker::AwaitSessionManagerImpl` / `HeartbeatHandler`
//! DIRECTLY — either the one wired by the harness (`sut.await_manager()` /
//! `sut.call_host_fn_as_agent`) or one constructed in-test with the SAME
//! production types (deterministic `session_id_factory` + a test-owned
//! `EventBusEmit` collector). No module in the chain is mocked: the manager, the
//! idle monitor (`crate::idle::idle_monitor_task` driven by the real
//! `tokio::time` virtual clock), `heartbeat_for_target`, and `on_reply` are all
//! the real bodies.
//!
//! ## Deliberately NOT asserted (deferred legs)
//!
//! - **SYS-AC-251** (parent turn RESUMED after idle timeout): the run-loop
//!   suspend/resume wiring is upstream-blocked (no Wasmtime `call_async` fiber
//!   resume entry) — a recorded `system_acceptance_deferred` entry, not claimed
//!   here.
//! - **SYS-AC-252** (`orchestration.await_idle_timeout` event): **witnessed**
//!   (Wave-15 Lane A, 2026-06-24) by `sys_ac_252_return_partial_idle_timeout_*`
//!   below — a `multi_thread` + `RealBus` ReturnPartial idle timeout where the
//!   REAL idle monitor fires (~5s) and the in-boundary `idle.rs` emit lands an
//!   `orchestration.await_idle_timeout` row in `events.db` (read back via
//!   `assert_db_event`). The `start_paused` legs above (165b/166/167) use
//!   `real_manager_with_fixed_id` whose `ManagerOptions.event_emitter` is `None`
//!   (RealBus is incompatible with virtual time), so THEY emit no idle event;
//!   the dedicated 252 test wires the emitter.
//! - The WIT-projection encode/decode surface of `await-replies` (the
//!   `AwaitRepliesHandler`) is exercised by reply-tracker's own crate tests; the
//!   166/167 legs drive `start` via the typed Rust API (the manager body the WIT
//!   handler delegates to) so the idle behavior — not the Val projection — is the
//!   subject under test.

use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use advance_messaging::{MailboxDispatcher, MailboxDispatcherImpl, MailboxStore};
use advance_reply_tracker::{AwaitSessionManager, AwaitSessionManagerImpl, ManagerOptions};
use advance_shared_types::agent_tree::{AgentKind, Capability};
use advance_shared_types::await_session::{
    AgentAwaitRequest, AwaitMode, AwaitOptions, AwaitRequest, AwaitSessionStatus,
    ComponentAwaitRequest, OrchestrationError, ReplyResult, ReplyStatus, SessionId, TimeoutPolicy,
};
use advance_shared_types::event::Event;
use advance_shared_types::traits::EventBusEmit;
use wasmtime::component::Val;

use system_acceptance::{AgentSpec, EventSink, SystemUnderTest};

const CORE_BYTES: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-j01-skeleton.core.wasm");

/// The `messaging` capability + canonical agent-messaging namespace/name the
/// harness registers the reply-tracker host fns under (`host_fn.rs:724-737`).
const MESSAGING_CAP: &str = "messaging";
const MESSAGING_NS: &str = "advance:runtime/agent-messaging@0.1.0";

// ───────────────────────────────────────────────────────────────────────────
// Self-contained test seams (defined INSIDE this integration binary).
// ───────────────────────────────────────────────────────────────────────────

/// A test-owned `EventBusEmit` collector — the real provider stays the
/// production type; only the sink is observed (mirrors the `sys_j47` discipline
/// where the seam IS `EventBusEmit`). Used by the directly-constructed-manager
/// legs that do NOT share the harness bus.
struct CollectingSink {
    events: Mutex<Vec<Event>>,
}
impl CollectingSink {
    fn new() -> Self {
        Self {
            events: Mutex::new(Vec::new()),
        }
    }
    fn events(&self) -> Vec<Event> {
        self.events.lock().unwrap().clone()
    }
}
impl EventBusEmit for CollectingSink {
    fn emit(&self, event: Event) {
        self.events.lock().unwrap().push(event);
    }
}

/// An empty `AgentTreeReader` for a directly-constructed `MailboxDispatcherImpl`.
/// The 165b/166/167 legs use ONLY `ComponentFinished` slots, which `dispatch.rs`
/// resolves WITHOUT ever invoking the dispatcher's `deliver` (and therefore
/// never consults this tree) — so a no-adjacency reader is sufficient. The real
/// `AgentRequest` parking/needle path is covered by the harness leg (165a),
/// whose dispatcher carries the real `HarnessAgentTree`.
struct NoTree;
impl advance_shared_types::agent_tree::AgentTreeReader for NoTree {
    fn parent_of(&self, _id: &str) -> Option<String> {
        None
    }
    fn children_of(&self, _id: &str) -> Vec<String> {
        Vec::new()
    }
    fn siblings_of(&self, _id: &str) -> Vec<String> {
        Vec::new()
    }
    fn agent_exists(&self, _id: &str) -> bool {
        false
    }
    fn agent_kind(&self, _id: &str) -> Option<AgentKind> {
        None
    }
    fn capabilities(&self, _id: &str) -> Vec<Capability> {
        Vec::new()
    }
}

/// Build a directly-constructed REAL `AwaitSessionManagerImpl` with a
/// DETERMINISTIC, single-shot `session_id_factory` returning `fixed_id` so the
/// test knows the parked session id up front (no test-only helper needed). The
/// dispatcher is the real `MailboxDispatcherImpl` over a real `MailboxStore` +
/// `NoTree` (never invoked for ComponentFinished slots).
fn real_manager_with_fixed_id(
    fixed_id: &str,
    idle_timeout_default_sec: u32,
) -> Arc<AwaitSessionManagerImpl> {
    let store = Arc::new(MailboxStore::new(NonZeroUsize::new(64).unwrap()));
    let tree: Arc<dyn advance_shared_types::agent_tree::AgentTreeReader> = Arc::new(NoTree);
    let dispatcher: Arc<dyn MailboxDispatcher> = Arc::new(MailboxDispatcherImpl::new(store, tree));
    let id = fixed_id.to_string();
    Arc::new(AwaitSessionManagerImpl::new(
        dispatcher,
        ManagerOptions {
            idle_timeout_default_sec,
            session_id_factory: Arc::new(move || SessionId(id.clone())),
            ..ManagerOptions::default()
        },
    ))
}

/// Yield repeatedly so a freshly-`tokio::spawn`ed `start` task has a chance to
/// run far enough to admit (insert) its session before the caller resolves /
/// advances the clock. Under `start_paused` real-time sleeps do not elapse, so
/// cooperative `yield_now` is the way to let the sibling task progress.
async fn wait_until_session_admitted(mgr: &Arc<AwaitSessionManagerImpl>, sid: &SessionId) {
    // A bogus `on_reply` probe returns `NotFound` until the session is admitted;
    // an admitted session returns an `InvalidRequest` (slot/source mismatch) —
    // either non-NotFound outcome proves admission. We never actually resolve
    // the session with this probe (the slot index is out of range / source is
    // bogus), so it stays parked for the real test body.
    //
    // These are `#[tokio::test(start_paused = true)]` (current-thread, virtual
    // clock): scheduling is COOPERATIVE, not wall-clock — `yield_now` deterministically
    // hands control to the spawned `start` task, which admits within a handful of
    // iterations. There is no OS-scheduler starvation race here (a real sleep would
    // not even elapse under the paused clock). The large iteration budget is logical-
    // progress headroom that fails LOUD on a genuine never-admit bug, not a timing race.
    for _ in 0..1_000_000 {
        let probe = ReplyResult {
            slot: u32::MAX,
            source: "probe:not-a-real-source".to_string(),
            payload: Vec::new(),
            status: ReplyStatus::Completed,
            received_at: chrono::Utc::now(),
            task_id: None,
        };
        match mgr.on_reply(sid, u32::MAX, probe).await {
            Err(OrchestrationError::NotFound(_)) => tokio::task::yield_now().await,
            _ => return, // admitted (got past the NotFound gate)
        }
    }
    panic!("session {} was never admitted", sid.0);
}

fn agent_request(target: &str, correlation_id: &str) -> AwaitRequest {
    AwaitRequest::AgentRequest(AgentAwaitRequest {
        target: target.to_string(),
        payload: Vec::new(),
        correlation_id: correlation_id.to_string(),
        context: None,
    })
}

fn component_request(component_id: &str, correlation_id: &str) -> AwaitRequest {
    AwaitRequest::ComponentFinished(ComponentAwaitRequest {
        component_id: component_id.to_string(),
        correlation_id: correlation_id.to_string(),
    })
}

fn root_and_child_specs() -> Vec<AgentSpec> {
    vec![
        AgentSpec {
            id: "agent:root".into(),
            kind: AgentKind::Root,
            parent: None,
            caps: vec![],
            capabilities: vec![],
        },
        AgentSpec {
            id: "agent:child".into(),
            kind: AgentKind::Child,
            parent: Some("agent:root".into()),
            caps: vec![],
            capabilities: vec![],
        },
    ]
}

// ═══════════════════════════════════════════════════════════════════════════
// SYS-AC-165a — heartbeat → orchestration.await_progress on the REAL bus.
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_165_heartbeat_emits_await_progress_on_harness_bus() {
    let sut = SystemUnderTest::builder()
        .agents(&root_and_child_specs())
        .events(EventSink::RealBus)
        .build(CORE_BYTES)
        .await;
    let mgr = sut.await_manager().expect(".agents() configured");

    // PARENT ("root", bare) parks an AgentRequest awaiting the CHILD. The
    // dispatcher's real HarnessAgentTree admits the parent→child route
    // (validate_routing: to_parent == Some(from)), so the slot dispatches Ok
    // and the AllOf-1 session PARKS (never the all-failed fast path). A long
    // idle timeout keeps it open for the duration of this real-time test.
    let opts = AwaitOptions {
        mode: AwaitMode::AllOf,
        idle_timeout_secs: Some(3600),
        on_idle_timeout: TimeoutPolicy::ReturnPartial,
        keep_losers: false,
    };
    let req = agent_request("agent:child", "corr-165a");
    let start = tokio::spawn(async move { mgr.start("root", vec![req], opts).await });

    // The harness's deterministic factory yields `hf-await-0` for the first
    // session; wait until that session is admitted before the heartbeat.
    let session_id = SessionId("hf-await-0".to_string());
    let probe_mgr = sut.await_manager().unwrap();
    wait_until_session_admitted(&probe_mgr, &session_id).await;

    // Heartbeat AS THE CHILD through the REAL registered HeartbeatHandler. The
    // needle becomes `agent:child`, matching the parked session's AgentRequest
    // target → `heartbeat_for_target` resets liveness + the handler emits one
    // `orchestration.await_progress` event into the harness bus.
    let hb_params = vec![Val::Option(Some(Box::new(Val::String(
        "indexing 40%".to_string(),
    ))))];
    let hb = sut
        .call_host_fn_as_agent("child", MESSAGING_CAP, MESSAGING_NS, "heartbeat", hb_params)
        .await
        .expect("heartbeat host-fn returns Ok(result<_, msg-error>)");
    // The WIT return arm is `result<_, msg-error>::Ok` → `Val::Result(Ok(None))`.
    assert!(
        matches!(hb.first(), Some(Val::Result(Ok(_)))),
        "heartbeat returned the success-unit arm, got {hb:?}"
    );

    // The in-boundary `orchestration.await_progress` event landed in the REAL
    // EventBus SQLite `events` table (same store /query/events reads), carrying
    // this session id + the from-target child agent id.
    let row = sut.assert_db_event("orchestration.await_progress", |r| {
        r.agent_id.as_deref() == Some("child")
    });
    let payload = row
        .payload
        .expect("await_progress row carries a JSON payload");
    assert!(
        payload.contains("hf-await-0"),
        "await_progress payload names the heartbeated session: {payload}"
    );
    // The real emitted payload identifies the heartbeating target by its (bare)
    // agent id and carries the progress string — the SYS-AC-165 observable
    // ("emits orchestration.await_progress carrying the progress payload").
    assert!(
        payload.contains("child"),
        "await_progress payload identifies the heartbeating child target: {payload}"
    );
    assert!(
        payload.contains("indexing 40%"),
        "await_progress carries the heartbeat progress payload: {payload}"
    );
    assert!(
        sut.db_event_count(Some("orchestration.await_progress")) >= 1,
        "at least one await_progress row persisted"
    );
    sut.assert_no_dropped_events();

    // Idle was reset, NOT resolved: the heartbeat neither completed the AllOf
    // session nor idle-closed it, so the parked `start` future is still pending.
    assert!(
        !start.is_finished(),
        "the session is still OPEN after the heartbeat (idle reset, not resolved)"
    );

    // This leg's idle timeout is 3600s and the task is aborted, so the idle
    // monitor never fires — only the heartbeat's await_progress exists in the
    // orchestration.* family here. (SYS-AC-252's await_idle_timeout is witnessed
    // by the dedicated multi_thread+RealBus test below.)
    start.abort();
}

// ═══════════════════════════════════════════════════════════════════════════
// SYS-AC-165b — heartbeat RESETS the idle clock (faithful virtual-clock witness).
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test(start_paused = true)]
async fn sys_ac_165_heartbeat_resets_idle_clock() {
    let sink = Arc::new(CollectingSink::new());
    // A short idle timeout so the monitor's 5 s ticks cross it quickly under the
    // virtual clock. idle_timeout = 30 s, monitor ticks every 5 s.
    let idle_secs: u32 = 30;
    let mgr = real_manager_with_fixed_id("sess-165b", idle_secs);

    // A 2-slot AllOf session that PARKS with `agent:child` in its `expected`
    // (so the from-target heartbeat needle matches):
    //   - slot 0 = AgentRequest(target="agent:child"): on the directly-built
    //     NoTree dispatcher its `deliver` fails (`validate_routing` →
    //     unknown_target) and the slot is recorded `Failed` — but it stays in
    //     `session.expected`, which is what `heartbeat_for_target` scans.
    //   - slot 1 = ComponentFinished (dispatch-free, returns Ok, stays
    //     unresolved) keeps the AllOf session OPEN (`is_complete()` is false),
    //     so the session is NOT all-failed and `start` parks on the oneshot.
    // We never resolve via the real dispatcher here; the witness is the idle
    // monitor's behavior + the `heartbeat_for_target` needle match.
    let opts = AwaitOptions {
        mode: AwaitMode::AllOf,
        idle_timeout_secs: Some(idle_secs),
        on_idle_timeout: TimeoutPolicy::ReturnPartial,
        keep_losers: false,
    };
    let requests = vec![
        agent_request("agent:child", "corr-165b-a"),
        component_request("comp-165b", "corr-165b-c"),
    ];
    let mgr_task = mgr.clone();
    let start = tokio::spawn(async move { mgr_task.start("root", requests, opts).await });

    let sid = SessionId("sess-165b".to_string());
    wait_until_session_admitted(&mgr, &sid).await;
    // The child-AgentRequest slot's deliver on NoTree fails → that slot is
    // recorded Failed, but the ComponentFinished slot keeps the AllOf session
    // open (is_complete() is false), so `start` is still parked.
    assert!(
        !start.is_finished(),
        "session parked open (component slot unresolved)"
    );

    // Advance to JUST BELOW the idle timeout (t = 25 s < 30 s): the monitor has
    // ticked at 5/10/15/20/25 s but elapsed < timeout each time → no fire.
    tokio::time::advance(Duration::from_secs(25)).await;
    tokio::task::yield_now().await;
    assert!(
        !start.is_finished(),
        "session still open just below the idle timeout"
    );

    // Drive the EXACT method HeartbeatHandler calls. needle = `agent:child`
    // matches the session's AgentRequest target → returns the parked session id
    // AND resets its liveness clock to "now" (t = 25 s).
    let affected = mgr
        .heartbeat_for_target("child", Some("still working".to_string()))
        .await;
    assert_eq!(
        affected,
        vec![sid.clone()],
        "heartbeat_for_target matched the from-target session and returned its id"
    );

    // Now advance PAST the ORIGINAL deadline (t = 25 + 20 = 45 s > 30 s) but the
    // reset moved the deadline to 25 + 30 = 55 s, so the session is STILL OPEN —
    // proving the heartbeat RESET the idle clock (without the reset it would have
    // fired around t = 30 s).
    tokio::time::advance(Duration::from_secs(20)).await;
    tokio::task::yield_now().await;
    assert!(
        !start.is_finished(),
        "session STILL open past the original deadline — the heartbeat reset the clock"
    );

    // Finally advance well past the post-reset deadline (t = 45 + 20 = 65 s >
    // 55 s): the REAL idle monitor now fires (ReturnPartial) and resolves the
    // parked `start` — confirming the session was genuinely live, not leaked.
    tokio::time::advance(Duration::from_secs(20)).await;
    let result = start
        .await
        .expect("start task joined")
        .expect("ReturnPartial idle resolves Ok");
    assert_eq!(
        result.status,
        AwaitSessionStatus::PartialTimeout,
        "post-reset idle timeout resolves PartialTimeout"
    );

    // This leg's `real_manager_with_fixed_id` has `ManagerOptions.event_emitter
    // = None`, so even though the REAL idle monitor fires (ReturnPartial) here,
    // it emits nothing — and `heartbeat_for_target` (called directly) emits
    // nothing either (the await_progress emit lives in the HostFn handler,
    // witnessed in 165a). The dedicated multi_thread+RealBus test below wires the
    // emitter and witnesses the SYS-AC-252 `await_idle_timeout` row.
    let progress: Vec<Event> = sink
        .events()
        .into_iter()
        .filter(|e| e.event_type == "orchestration.await_progress")
        .collect();
    assert!(
        progress.is_empty(),
        "heartbeat_for_target itself emits no event"
    );
    assert!(
        sink.events().is_empty(),
        "the emitter-less idle path emits NO event: {:?}",
        sink.events()
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// SYS-AC-166 — ReturnPartial idle timeout → PartialTimeout + per-slot TimedOut.
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test(start_paused = true)]
async fn sys_ac_166_return_partial_idle_timeout_yields_partial_with_timed_out_slot() {
    let idle_secs: u32 = 20;
    let mgr = real_manager_with_fixed_id("sess-166", idle_secs);

    // A 2-slot AllOf session of dispatch-free ComponentFinished slots: both park
    // (no deliver), neither fast-fails. on_idle_timeout = ReturnPartial.
    let opts = AwaitOptions {
        mode: AwaitMode::AllOf,
        idle_timeout_secs: Some(idle_secs),
        on_idle_timeout: TimeoutPolicy::ReturnPartial,
        keep_losers: false,
    };
    let requests = vec![
        component_request("comp-A", "corr-166-a"),
        component_request("comp-B", "corr-166-b"),
    ];
    let mgr_task = mgr.clone();
    let start = tokio::spawn(async move { mgr_task.start("root", requests, opts).await });

    let sid = SessionId("sess-166".to_string());
    wait_until_session_admitted(&mgr, &sid).await;

    // Resolve EXACTLY ONE slot (slot 0) via the REAL on_reply. For an AllOf
    // 2-slot session this is open-keeping (is_complete() false) — the session
    // stays parked, and on_reply RESETS the idle clock.
    let reply0 = ReplyResult {
        slot: 0,
        source: "component:comp-A".to_string(),
        payload: Vec::new(),
        status: ReplyStatus::Completed,
        received_at: chrono::Utc::now(),
        task_id: None,
    };
    mgr.on_reply(&sid, 0, reply0)
        .await
        .expect("on_reply slot 0 (open-keeping) succeeds");
    assert!(
        !start.is_finished(),
        "AllOf with one slot still pending stays open"
    );

    // Advance virtual time PAST the idle timeout (measured from the slot-0 reply
    // reset): 5 s monitor ticks; with idle_timeout = 20 s and a generous 40 s
    // advance we cross several ticks beyond the deadline so the monitor fires.
    tokio::time::advance(Duration::from_secs(40)).await;

    let result = start
        .await
        .expect("start task joined")
        .expect("ReturnPartial → Ok(AwaitResult)");

    assert_eq!(
        result.status,
        AwaitSessionStatus::PartialTimeout,
        "idle timeout under ReturnPartial yields PartialTimeout"
    );
    // Both slots are present (full per-slot snapshot): slot 0 Completed (the
    // resolved reply), slot 1 TimedOut (the silent slot filled by resolve_idle).
    let by_slot: HashMap<u32, &ReplyResult> = result.replies.iter().map(|r| (r.slot, r)).collect();
    let slot0 = by_slot.get(&0).expect("resolved slot 0 present");
    assert_eq!(
        slot0.status,
        ReplyStatus::Completed,
        "resolved slot stays Completed"
    );
    assert_eq!(slot0.source, "component:comp-A");
    assert!(
        slot0.payload.is_empty(),
        "ComponentFinished reply stays status-only"
    );
    let slot1 = by_slot.get(&1).expect("silent slot 1 present");
    assert_eq!(
        slot1.status,
        ReplyStatus::TimedOut,
        "the silent slot is filled as TimedOut by resolve_idle"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// SYS-AC-167 — Fail idle timeout → Err(IdleTimeoutExceeded).
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test(start_paused = true)]
async fn sys_ac_167_fail_idle_timeout_yields_idle_timeout_exceeded() {
    let idle_secs: u32 = 20;
    let mgr = real_manager_with_fixed_id("sess-167", idle_secs);

    // Same 2-slot AllOf ComponentFinished shape, but on_idle_timeout = Fail.
    let opts = AwaitOptions {
        mode: AwaitMode::AllOf,
        idle_timeout_secs: Some(idle_secs),
        on_idle_timeout: TimeoutPolicy::Fail,
        keep_losers: false,
    };
    let requests = vec![
        component_request("comp-A", "corr-167-a"),
        component_request("comp-B", "corr-167-b"),
    ];
    let mgr_task = mgr.clone();
    let start = tokio::spawn(async move { mgr_task.start("root", requests, opts).await });

    let sid = SessionId("sess-167".to_string());
    wait_until_session_admitted(&mgr, &sid).await;
    assert!(!start.is_finished(), "session parked open (no replies)");

    // Advance PAST the idle timeout → the REAL idle monitor fires under the Fail
    // policy.
    tokio::time::advance(Duration::from_secs(40)).await;

    let outcome = start.await.expect("start task joined");
    match outcome {
        Err(OrchestrationError::IdleTimeoutExceeded(_)) => {}
        other => {
            panic!("Fail idle-timeout policy must resolve Err(IdleTimeoutExceeded), got {other:?}")
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// SYS-AC-252 — ReturnPartial idle timeout emits orchestration.await_idle_timeout
// on the REAL EventBus (multi_thread + RealBus; the REAL idle monitor fires).
// ═══════════════════════════════════════════════════════════════════════════
//
// RealBus (synchronous SQLite EventBus) requires a multi_thread runtime and is
// incompatible with `start_paused` virtual time (see the file header / 165a), so
// — unlike the 166/167 virtual-clock legs — this witness lets the REAL idle
// monitor fire under real wall-clock: `idle_timeout_secs=1` + IDLE_TICK_SECS=5
// ⇒ the first 5 s tick sees elapsed ≥ 1 s and resolves. The orchestration event
// row is read back from the same SQLite store the sys_j47/mode_events witnesses
// query — an independent oracle, not an internal manager value.

#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_252_return_partial_idle_timeout_emits_await_idle_timeout() {
    let sut = SystemUnderTest::builder()
        .agents(&root_and_child_specs())
        .events(EventSink::RealBus)
        .build(CORE_BYTES)
        .await;
    let mgr = sut.await_manager().expect(".agents() configured");

    // A 2-slot AllOf ReturnPartial session of dispatch-free ComponentFinished
    // slots (both park, no `deliver`) with a SHORT idle timeout. `start("root")`
    // ⇒ the session's caller agent_id is "root".
    let opts = AwaitOptions {
        mode: AwaitMode::AllOf,
        idle_timeout_secs: Some(1),
        on_idle_timeout: TimeoutPolicy::ReturnPartial,
        keep_losers: false,
    };
    let requests = vec![
        component_request("comp-252-a", "corr-252-a"),
        component_request("comp-252-b", "corr-252-b"),
    ];
    let m = mgr.clone();
    let start = tokio::spawn(async move { m.start("root", requests, opts).await });

    // The REAL idle monitor (spawned by `start`) fires after ~5 s real time and
    // resolves the parked session ReturnPartial → PartialTimeout.
    let result = start
        .await
        .expect("start task joined")
        .expect("ReturnPartial idle timeout resolves Ok(AwaitResult)");
    assert_eq!(
        result.status,
        AwaitSessionStatus::PartialTimeout,
        "ReturnPartial idle timeout resolves PartialTimeout"
    );

    // The in-boundary orchestration.await_idle_timeout event landed in the REAL
    // EventBus SQLite `events` table (same store /query/events reads), carrying
    // this session's caller agent id + the idle_seconds payload.
    let row = sut.assert_db_event("orchestration.await_idle_timeout", |r| {
        r.agent_id.as_deref() == Some("root")
    });
    let payload = row
        .payload
        .expect("await_idle_timeout row carries a payload");
    assert!(
        payload.contains("hf-await-0"),
        "await_idle_timeout payload names the timed-out session: {payload}"
    );
    assert!(
        payload.contains("idle_seconds"),
        "await_idle_timeout payload carries idle_seconds (PRD §15.3.4B): {payload}"
    );
    assert!(
        sut.db_event_count(Some("orchestration.await_idle_timeout")) >= 1,
        "at least one await_idle_timeout row persisted"
    );
    sut.assert_no_dropped_events();
}

/// Discriminator: a session that COMPLETES via replies before the idle timeout
/// (long 3600 s idle) emits NO await_idle_timeout — the event is causally tied
/// to the ReturnPartial idle resolution, not unconditional.
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_252_completed_session_emits_no_await_idle_timeout() {
    let sut = SystemUnderTest::builder()
        .agents(&root_and_child_specs())
        .events(EventSink::RealBus)
        .build(CORE_BYTES)
        .await;
    let mgr = sut.await_manager().expect(".agents() configured");

    let opts = AwaitOptions {
        mode: AwaitMode::AllOf,
        idle_timeout_secs: Some(3600), // never fires within the test
        on_idle_timeout: TimeoutPolicy::ReturnPartial,
        keep_losers: false,
    };
    let requests = vec![
        component_request("comp-d-a", "corr-d-a"),
        component_request("comp-d-b", "corr-d-b"),
    ];
    let m = mgr.clone();
    let start = tokio::spawn(async move { m.start("root", requests, opts).await });

    let session_id = SessionId("hf-await-0".to_string());
    wait_until_session_admitted(&mgr, &session_id).await;

    // Complete BOTH slots → AllOf resolves Completed (no idle timeout).
    for (slot, src) in [(0u32, "component:comp-d-a"), (1u32, "component:comp-d-b")] {
        mgr.on_reply(
            &session_id,
            slot,
            ReplyResult {
                slot,
                source: src.to_string(),
                payload: Vec::new(),
                status: ReplyStatus::Completed,
                received_at: chrono::Utc::now(),
                task_id: None,
            },
        )
        .await
        .expect("on_reply ok");
    }
    let result = start.await.expect("joined").expect("completes Ok");
    assert_eq!(result.status, AwaitSessionStatus::Completed);
    assert!(
        result.replies.iter().all(|reply| reply.payload.is_empty()),
        "completed ComponentFinished replies stay status-only"
    );

    assert_eq!(
        sut.db_event_count(Some("orchestration.await_idle_timeout")),
        0,
        "a reply-completed session emits no await_idle_timeout"
    );
}

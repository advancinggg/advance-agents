//! await-leg B-4a (Wave-10 Lane B, 2026-06-22) — the agent-loop await-PARK witness.
//!
//! Proves the keystone the capability flip (`KNOWN_CAPABILITIES += "messaging"`)
//! unlocks: a REAL `messaging`-declaring guest whose `handle-message` calls
//! `await-replies` PARKS its M008 Run, and is RESUMED by a CHILD agent's **product
//! `send`** — NOT a harness `on_reply`/`close`/`resume_run` (the differentiator from
//! the 183/185-class harness-stitch witnesses).
//!
//! Driving altitude: the parent runs through the PRODUCTION
//! [`WasmMessageHandler`]`::handle_message` with a `RunSession` (the same path
//! `start.rs` wires), so the per-turn `complete_round_with_trace` fires exactly once
//! → one `run.round_completed` across the whole fan-out (the fiber suspends INSIDE the
//! single `call_handle_message`, so the park stays within one turn). The agent-loop's
//! `run_turn_once` wrapper merely awaits `handle_message`, so driving `handle_message`
//! directly faithfully witnesses the park.
//!
//! Codex plan-r1: the manager uses a `MockDispatcher` (deliver → Ok) — the same
//! witness floor as `fiber_suspend_resume.rs` (T58) + `send_host_fn.rs` (B-3); the
//! real `MailboxDispatcherImpl`'s `validate_routing` would fail-dispatch the await to
//! a non-tree target BEFORE it parks. The PARK, the `RunManagerSuspendSink`
//! suspend/resume, and the product-`send` → `on_reply` resolution are all real.
//!
//! Correlation (no new wasm fixtures): the parent `guest-rust-with-caps` await branch
//! awaits `agent:test-target`; the child `guest-rust-send` is instantiated as
//! `ctx.agent_id="test-target"` and sends to `agent:parent`, so
//! `try_route_reply(owner="parent", source="test-target")` matches the parent slot.
//!
//! **ZERO ledger flips** (satellite, DORMANT for shipped agents): proves the MECHANISM
//! only; the AC-08/AC-14 + SYS-AC 014/018/251 flips are the Wave-11 B-4b harvest.

use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use advance_cli::agent_loop::{RunSession, SessionRunCell, WasmMessageHandler};
use advance_cli::await_wiring::RunManagerSuspendSink;
use advance_messaging::MailboxDispatcher;
use advance_reply_tracker::manager::ManagerOptions;
use advance_reply_tracker::{
    register_reply_tracker_host_fns_with_suspend_sink, register_send_host_fn,
    AwaitSessionManagerImpl, RunSuspendSink,
};
use advance_run_manager::{RunConfig, RunManager};
use advance_runtime::capability_injector::{CapabilityInjector, ComponentCtx};
use advance_runtime::circuit_breaker::{CircuitBreakerBus, DefaultCircuitBreakerBus};
use advance_runtime::config::WasmConfig;
use advance_runtime::host_registry::{HostRegistry, InMemoryHostRegistry};
use advance_runtime::wit_bindings::with_caps::advance::runtime::types as wit_types;
use advance_runtime::ComponentRuntime;
use advance_scheduler::hook::MessageHandler;
use advance_scheduler::types::ComponentConfig;
use advance_shared_types::capability::{CapParams, CapRequest, CapabilityId, GrantDecision};
use advance_shared_types::event::Event;
use advance_shared_types::mailbox::{Message, MessageContext, MessageKind, MsgError, NotifyError};
use advance_shared_types::run::TaskRunStatus;
use advance_shared_types::traits::{EventBusEmit, GrantCheck};
use wit_component::ComponentEncoder;

const PARENT_CORE: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-with-caps.core.wasm");
const CHILD_CORE: &[u8] = include_bytes!("../../runtime/tests/fixtures/guest-rust-send.core.wasm");

// Must match the fixtures.
const STATE_AWAIT_OK: [u8; 4] = [0xAC, 0x08, 0x14, 0x01]; // guest-rust-with-caps await branch
const STATE_SEND_OK: [u8; 4] = [0x5E, 0x4D, 0x0C, 0x01]; // guest-rust-send send branch

// ── stubs (mirror fiber_suspend_resume.rs / send_host_fn.rs) ──

struct AllowAll;
impl GrantCheck for AllowAll {
    fn check(&self, _: &str, _: &str, _: &str, _: &CapParams) -> GrantDecision {
        GrantDecision::Allow
    }
}

/// Captures every emitted event by type (so the witness asserts the run-lifecycle
/// triple per-type — `ensure_run` ALSO emits `run.created`, so a total-count==3
/// assertion would be wrong).
struct CapturingBus {
    events: Mutex<Vec<Event>>,
}
impl CapturingBus {
    fn new() -> Self {
        Self {
            events: Mutex::new(Vec::new()),
        }
    }
    fn snapshot(&self) -> Vec<Event> {
        self.events.lock().unwrap().clone()
    }
}
impl EventBusEmit for CapturingBus {
    fn emit(&self, event: Event) {
        self.events.lock().unwrap().push(event);
    }
}

/// Mock dispatcher — `deliver` → Ok so the parent's await-request dispatch keeps the
/// session Open (parks) rather than transitioning to FailedDispatch. NOT part of the
/// park/resume mechanism the witness proves (Codex plan-r1).
struct MockDispatcher;
#[async_trait::async_trait]
impl MailboxDispatcher for MockDispatcher {
    async fn deliver(&self, _target: &str, _msg: Message) -> Result<(), MsgError> {
        Ok(())
    }
    async fn reply(&self, _f: &str, _i: &str, _p: Vec<u8>) -> Result<(), MsgError> {
        Ok(())
    }
    async fn notify_agent(
        &self,
        _f: &str,
        _t: &str,
        _p: Vec<u8>,
        _c: Option<MessageContext>,
    ) -> Result<(), NotifyError> {
        Ok(())
    }
}

fn wasm_cfg() -> WasmConfig {
    WasmConfig {
        max_memory_pages: 256,
        epoch_interruption_ms: 100,
        fuel_enabled: false,
    }
}

fn component_bytes(core: &[u8]) -> Vec<u8> {
    ComponentEncoder::default()
        .validate(true)
        .module(core)
        .expect("core wraps")
        .encode()
        .expect("component encoded")
}

fn count(events: &[Event], ty: &str) -> usize {
    events.iter().filter(|e| e.event_type == ty).count()
}

/// B-4a — the build-lane await-park witness.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b4a_guest_await_park_resumed_by_product_send() {
    // 1. Shared capturing bus + a real RunManager on the SAME bus (so run.suspended /
    //    run.resumed / run.round_completed are all captured).
    let bus = Arc::new(CapturingBus::new());
    let run_manager = Arc::new(RunManager::new(bus.clone() as Arc<dyn EventBusEmit>));

    // 2. Mint the session run + publish it into the cell (mirrors RunManagerBootstrap;
    //    WasmMessageHandler::init reads the cell into ctx.run_id and fail-closes if
    //    unset). The parent's await-replies handler suspends THIS run.
    let cell: SessionRunCell = Arc::new(OnceLock::new());
    let rid = run_manager
        .ensure_run("parent", "parent", RunConfig::default())
        .expect("ensure_run mints the session run");
    cell.set(rid.clone()).expect("cell empty");

    // 3. Messaging chain over a MockDispatcher; register send + the sink-aware
    //    await-replies/heartbeat with a production RunManagerSuspendSink over the run.
    let registry: Arc<dyn HostRegistry> = Arc::new(InMemoryHostRegistry::new());
    let dispatcher: Arc<dyn MailboxDispatcher> = Arc::new(MockDispatcher);
    let manager = Arc::new(AwaitSessionManagerImpl::new(
        dispatcher,
        ManagerOptions::default(),
    ));
    let sink: Arc<dyn RunSuspendSink> = Arc::new(RunManagerSuspendSink::new(run_manager.clone()));
    register_send_host_fn(&*registry, Arc::clone(&manager));
    register_reply_tracker_host_fns_with_suspend_sink(
        &*registry,
        Arc::clone(&manager),
        bus.clone() as Arc<dyn EventBusEmit>,
        Some(sink),
    );

    // 4. Shared injector + runtime + both fixtures.
    let grant: Arc<dyn GrantCheck> = Arc::new(AllowAll);
    let breaker: Arc<dyn CircuitBreakerBus> = Arc::new(DefaultCircuitBreakerBus::new());
    let injector = Arc::new(CapabilityInjector::new(registry, grant, breaker));
    let runtime = Arc::new(ComponentRuntime::new(&wasm_cfg()).expect("runtime"));
    let parent_loaded = runtime
        .load_component(&component_bytes(PARENT_CORE))
        .expect("parent component loads");
    let child_loaded = runtime
        .load_component(&component_bytes(CHILD_CORE))
        .expect("child component loads");
    let caps = vec![CapRequest {
        capability: CapabilityId::from("messaging"),
    }];

    // 5. Parent: production WasmMessageHandler WITH the run session (ctx.agent_id =
    //    bare "parent" → start_with_run's is_safe_id("agent:parent") passes), config
    //    "await-replies" so handle-message routes to the await branch.
    let handler: Arc<dyn MessageHandler> = Arc::new(
        WasmMessageHandler::new(
            runtime.clone(),
            parent_loaded,
            injector.clone(),
            caps.clone(),
            "parent".to_string(),
            "trace-b4a".to_string(),
        )
        .with_run_session(RunSession {
            run_manager: run_manager.clone(),
            cell: cell.clone(),
        }),
    );
    let init_state = handler
        .init(ComponentConfig {
            id: "test-parent".to_string(),
            config_data: Some(b"await-replies".to_vec()),
            trigger_context: None,
        })
        .await
        .expect("parent init (cell set → ctx.run_id populated)");
    assert_eq!(init_state, b"await-replies");

    // 6. Spawn the parent turn — it PARKS inside call_handle_message at await-replies.
    let parent_task = {
        let handler = handler.clone();
        let msg = Message {
            id: "msg-b4a-parent".to_string(),
            kind: MessageKind::User,
            from: "user:harness".to_string(),
            to: "parent".to_string(),
            payload: vec![], // the guest dispatches on `state`, not payload
            context: None,
            timestamp: std::time::SystemTime::now(),
            origin: None,
        };
        tokio::spawn(async move { handler.handle_message(&msg, init_state).await })
    };

    // 7. (a) Witness the PARK: poll until the run is Suspended with a live root_await.
    let mut parked = false;
    for _ in 0..400 {
        if let Ok(st) = run_manager.run_status(&rid) {
            if matches!(st.status, TaskRunStatus::Suspended) && st.root_await.is_some() {
                parked = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        parked,
        "parent run must enter Suspended (parked at await-replies)"
    );

    // 8. Drive the CHILD product `send` (NOT a harness on_reply/close/resume_run):
    //    instantiate guest-rust-send as "test-target", config "send" → it calls
    //    send("agent:parent") → SendHandler → handle_send → try_route_reply → on_reply
    //    → fires the parent's oneshot.
    let child_ctx = ComponentCtx::new("test-target".into(), "trace-child".into(), Vec::new());
    let (child_bindings, mut child_store) = runtime
        .instantiate_advance_host_with_capabilities_async(
            &child_loaded,
            child_ctx,
            &caps,
            &*injector,
        )
        .await
        .expect("child instantiate (send-importing guest links under messaging cap)");
    let child_state = child_bindings
        .advance_runtime_message_driven()
        .call_init(
            &mut child_store,
            &wit_types::ComponentConfig {
                id: "test-child".into(),
                config_data: Some(b"send".to_vec()),
                trigger_context: None,
            },
        )
        .await
        .expect("child init call")
        .expect("child init Ok");
    let child_action = child_bindings
        .advance_runtime_message_driven()
        .call_handle_message(
            &mut child_store,
            &wit_types::Message { payload: vec![] },
            &child_state,
        )
        .await
        .expect("child handle-message call")
        .expect("child handle-message Ok (send returned Ok → routed)");
    assert_eq!(
        child_action.new_state, STATE_SEND_OK,
        "child returned the send witness state → the product send ran + routed"
    );

    // 9. (b) The parent fiber RESUMES and the turn completes.
    let parent_result = tokio::time::timeout(Duration::from_secs(30), parent_task)
        .await
        .expect("parent handle-message must complete within 30s after the child send")
        .expect("parent task panicked")
        .expect("parent handle-message Ok");
    assert_eq!(
        parent_result.new_state, STATE_AWAIT_OK,
        "parent fiber resumed: await-replies returned and the guest produced the witness state"
    );

    // run back Active, root_await cleared.
    let st = run_manager
        .run_status(&rid)
        .expect("run_status after resume");
    assert!(
        matches!(st.status, TaskRunStatus::Active),
        "run resumed to Active (got {:?})",
        st.status
    );
    assert!(st.root_await.is_none(), "root_await cleared on resume");

    // 10. (c) Exactly one each of the run-lifecycle triple, suspended-before-resumed.
    let events = bus.snapshot();
    assert_eq!(
        count(&events, "run.suspended"),
        1,
        "one run.suspended (the park)"
    );
    assert_eq!(
        count(&events, "run.resumed"),
        1,
        "one run.resumed (the product-send resume)"
    );
    assert_eq!(
        count(&events, "run.round_completed"),
        1,
        "exactly one run.round_completed across the fan-out (one turn-commit boundary)"
    );
    let idx_susp = events
        .iter()
        .position(|e| e.event_type == "run.suspended")
        .unwrap();
    let idx_res = events
        .iter()
        .position(|e| e.event_type == "run.resumed")
        .unwrap();
    assert!(idx_susp < idx_res, "run.suspended precedes run.resumed");
    // the resume is an await-completion resume (reason await_complete), not a manual one.
    let resumed = &events[idx_res];
    assert!(
        format!("{resumed:?}").contains("await_complete"),
        "run.resumed reason is await_complete (the await-completion resume): {resumed:?}"
    );

    // (d) The harness NEVER called on_reply/close/resume_run/resolve_await — resolution
    //     was driven solely by the child guest's product `send`. (Guaranteed by
    //     construction: this test only drives the child's send host-fn.)
}

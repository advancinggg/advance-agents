//! Slice m001-slice-bootstrap (2026-05-28) — MODULE-007-AC-08 + AC-14 closure.
//!
//! AC-08 §1.4: "Wasmtime `call_async` fiber suspension at `await-replies`
//! entry (host fn handler invokes `manager.start(...)` from within
//! `call_async`)."
//! AC-14 §1.4: "Wasmtime `call_async` fiber resume on session resolution:
//! host fn handler awaits the manager's oneshot and unblocks the WASM
//! fiber."
//!
//! The guest calls `await-replies` with one slot. The host-side
//! `AwaitRepliesHandler` invokes `manager.start_with_run(...)`, reached via the
//! typed `func_wrap_async` registration (await-leg slice 1, 2026-06-21 — the
//! dynamic `func_new_async` `&[Val]` lift mis-shaped the `list<await-request>`
//! variant; see the `module_001_t58` docstring) — fiber suspends at
//! await-replies entry. The test driver then calls `manager.close(session_id, ...)` to fire the
//! session oneshot — fiber resumes. The deterministic
//! `ManagerOptions.session_id_factory` lets the test driver know the
//! session_id BEFORE the guest calls await-replies (avoids feature-gated
//! `first_open_session_id_for_test`).
//!
//! The test driver substitutes for the deferred production Reply-delivery
//! feature (gate-only AgentActionDispatcher + missing action ABI — tracked
//! under MODULE-001 §3.6 AC-18/AC-19 deferral). The fiber suspend+resume
//! MECHANISM through the real AwaitRepliesHandler + CapabilityInjector +
//! call_async is genuinely exercised.

use std::sync::Arc;
use std::time::Duration;

use advance_messaging::MailboxDispatcher;
use advance_reply_tracker::manager::ManagerOptions;
use advance_reply_tracker::{
    register_reply_tracker_host_fns, AwaitSessionManager, AwaitSessionManagerImpl,
};
use advance_runtime::capability_injector::{CapabilityInjector, ComponentCtx};
use advance_runtime::circuit_breaker::{CircuitBreakerBus, DefaultCircuitBreakerBus};
use advance_runtime::config::WasmConfig;
use advance_runtime::host_registry::{HostRegistry, InMemoryHostRegistry};
use advance_runtime::wit_bindings::with_caps::advance::runtime::types as wit_types;
use advance_runtime::ComponentRuntime;
use advance_shared_types::await_session::SessionId;
use advance_shared_types::capability::{CapParams, CapRequest, CapabilityId, GrantDecision};
use advance_shared_types::event::Event;
use advance_shared_types::mailbox::{Message, MessageContext, MsgError, NotifyError};
use advance_shared_types::traits::{EventBusEmit, GrantCheck};
use wit_component::ComponentEncoder;

const CORE_BYTES: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-with-caps.core.wasm");
const STATE_AWAIT_OK: [u8; 4] = [0xAC, 0x08, 0x14, 0x01];
const TEST_SESSION_ID: &str = "test-fiber-session-001";

// ---------- Test stubs ----------

struct AllowAll;
impl GrantCheck for AllowAll {
    fn check(&self, _: &str, _: &str, _: &str, _: &CapParams) -> GrantDecision {
        GrantDecision::Allow
    }
}

struct NoopEventBus;
impl EventBusEmit for NoopEventBus {
    fn emit(&self, _event: Event) {}
}

/// Mock MailboxDispatcher (per existing T02c session-lifecycle test pattern)
/// — returns Ok for every dispatch so the session stays Open awaiting the
/// reply rather than transitioning to FailedDispatch on a routing error.
struct MockDispatcher;
#[async_trait::async_trait]
impl MailboxDispatcher for MockDispatcher {
    async fn deliver(&self, _target: &str, _msg: Message) -> Result<(), MsgError> {
        Ok(())
    }
    async fn reply(
        &self,
        _from: &str,
        _to_message_id: &str,
        _payload: Vec<u8>,
    ) -> Result<(), MsgError> {
        Ok(())
    }
    async fn notify_agent(
        &self,
        _from: &str,
        _target: &str,
        _payload: Vec<u8>,
        _context: Option<MessageContext>,
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

fn ctx() -> ComponentCtx {
    // The agent_id becomes the `await-replies` caller passed to
    // `AwaitSessionManagerImpl::start_with_run`, which validates it as a BARE
    // agent body — it does `is_safe_id(format!("agent:{caller}"))` (manager.rs),
    // so a `"agent:"`-PREFIXED value double-prefixes to `agent:agent:caller` and
    // is rejected as a non-safe id. Use the bare form. (`heartbeat` tolerates
    // either via prefix-stripping, but `start_with_run` does not — the documented
    // asymmetry. The original `#[ignore]`'d body used `"agent:caller"`, which was
    // never exercised end-to-end; the slice-1 typed-lift fix surfaced it.)
    ComponentCtx::new("caller".into(), "trace-fiber".into(), Vec::new())
}

fn component_bytes() -> Vec<u8> {
    ComponentEncoder::default()
        .validate(true)
        .module(CORE_BYTES)
        .expect("core wraps")
        .encode()
        .expect("component encoded")
}

/// T58 — M007-AC-08 + AC-14 fiber suspend/resume witness.
///
/// **History (m001-slice-bootstrap, 2026-05-28):** the `await-replies` WIT call
/// from the WASM guest did NOT reach `AwaitSessionManagerImpl::start_with_run`.
/// The host's `AwaitRepliesHandler` was wired correctly (T57 heartbeat works
/// through the same path), but the `AwaitRequest` variant decoder in
/// `crates/messaging/reply-tracker/src/host_fn.rs:decode_await_request` expects
/// `Val::Variant("agent-request", ...)` while Wasmtime's canonical-ABI lift for
/// *dynamically*-registered host fns (`LinkerInstance::func_new_async`) does not
/// produce that variant shape for the complex `list<await-request>` parameter —
/// so the session poll loop never observed a session being created. The test was
/// `#[ignore]`'d to preserve the body as documentation.
///
/// **Resolution (await-leg slice 1, 2026-06-21):** `CapabilityInjector::inject`
/// now registers `await-replies`/`heartbeat` through Wasmtime 43's TYPED
/// `LinkerInstance::func_wrap_async` (over the bindgen-generated typed structs);
/// the typed canonical-ABI lift produces the correct `list<await-request>` shape,
/// then the injector host-builds the canonical `Val` the existing decoder
/// consumes and delegates to the SAME registered handler under the SAME L1/CB
/// gates. The fiber suspend+resume MECHANISM through the real `AwaitRepliesHandler`
/// + real `CapabilityInjector` + real `call_async` is exercised end-to-end; the
/// `#[ignore]` is removed. (Per the satellite discipline the §3.4 AC-08/AC-14
/// ledger flip is held for a harvest pass — see MODULE-007 §3.5/§3.7.)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_t58_fiber_suspend_resume() {
    // 1. Build wiring with deterministic session_id factory so the test
    //    driver knows the session_id BEFORE the guest calls await-replies
    //    (R3 W2 fix — avoids feature-gated first_open_session_id_for_test).
    let registry: Arc<dyn HostRegistry> = Arc::new(InMemoryHostRegistry::new());
    let dispatcher: Arc<dyn MailboxDispatcher> = Arc::new(MockDispatcher);

    let opts = ManagerOptions {
        session_id_factory: Arc::new(|| SessionId(TEST_SESSION_ID.into())),
        ..ManagerOptions::default()
    };
    let manager = Arc::new(AwaitSessionManagerImpl::new(dispatcher, opts));
    let event_bus: Arc<dyn EventBusEmit> = Arc::new(NoopEventBus);
    register_reply_tracker_host_fns(&*registry, manager.clone(), event_bus);

    let grant: Arc<dyn GrantCheck> = Arc::new(AllowAll);
    let breaker: Arc<dyn CircuitBreakerBus> = Arc::new(DefaultCircuitBreakerBus::new());
    let injector = CapabilityInjector::new(registry, grant, breaker);
    let caps = vec![CapRequest {
        capability: CapabilityId::from("messaging"),
    }];

    // 2. Build the runtime + load the with-caps fixture.
    let runtime = ComponentRuntime::new(&wasm_cfg()).expect("runtime");
    let loaded = runtime
        .load_component(&component_bytes())
        .expect("component loads");
    let (bindings, mut store) = runtime
        .instantiate_advance_host_with_capabilities_async(&loaded, ctx(), &caps, &injector)
        .await
        .expect("instantiate");

    // 3. init with config_data=b"await-replies" so handle-message routes
    //    to the await-replies branch.
    let cfg = wit_types::ComponentConfig {
        id: "test-fiber".into(),
        config_data: Some(b"await-replies".to_vec()),
        trigger_context: None,
    };
    let init_state = bindings
        .advance_runtime_message_driven()
        .call_init(&mut store, &cfg)
        .await
        .expect("init call")
        .expect("init Ok");
    assert_eq!(init_state, b"await-replies");

    // 4. Spawn a sibling tokio task: it waits a short cooperative delay,
    //    then calls `manager.close(TEST_SESSION_ID)` to fire the session
    //    oneshot. This triggers AC-14 fiber resume.
    let manager_for_resolve = manager.clone();
    let resolver = tokio::spawn(async move {
        // Wait long enough for handle-message to enter await-replies
        // and the fiber to suspend. The await-replies dispatch path is
        // synchronous from the guest's view; the host fn awaits the
        // session oneshot. Poll for the session to appear in the
        // manager's `sessions` map (debug-only test-helper feature),
        // then call close to resolve.
        for attempt in 0..50 {
            // 50 * 50ms = 2.5s upper bound for the guest to enter await-replies
            tokio::time::sleep(Duration::from_millis(50)).await;
            // Best-effort check: the session_id_factory always returns the
            // SAME id, so any open session in the manager is the one we
            // want. Use first_open_session_id_for_test (feature-gated; cli
            // dev-dep enables it).
            // We only proceed when there is exactly one session — earlier
            // attempts may find zero sessions if the guest hasn't reached
            // await-replies yet.
            let sessions_now = manager_for_resolve.session_count_for_test().await;
            if sessions_now >= 1 {
                eprintln!(
                    "resolver: observed {sessions_now} session(s) after {} ms; closing",
                    (attempt + 1) * 50
                );
                break;
            }
        }
        let sid = SessionId(TEST_SESSION_ID.into());
        manager_for_resolve
            .close(&sid, "test-driver-resolved")
            .await
            .expect("manager.close should resolve the suspended fiber");
    });

    // 5. Drive handle-message under a 30s watchdog. Without the resolver
    //    closing the session, this would block until the session's
    //    idle timeout (or forever). With the resolver, the fiber should
    //    resume within ~200ms.
    let msg = wit_types::Message { payload: vec![] };
    let result = tokio::time::timeout(
        Duration::from_secs(30),
        bindings
            .advance_runtime_message_driven()
            .call_handle_message(&mut store, &msg, &init_state),
    )
    .await
    .expect("watchdog: handle-message should complete within 30s after resolver fires")
    .expect("handle-message host call");

    // 6. Wait for the resolver task to finish so it doesn't leak.
    resolver.await.expect("resolver task");

    // 7. Witness AC-08 (fiber suspended at entry) + AC-14 (fiber resumed on
    //    session resolution): the guest's await-replies handler observed a
    //    resolution (Ok or Err) and returned STATE_AWAIT_OK. If the fiber
    //    hadn't suspended on entry, handle-message would have returned
    //    BEFORE the resolver fired. If the fiber hadn't resumed, the
    //    watchdog above would have fired.
    let action_result = result.expect("handle-message Ok");
    assert_eq!(
        action_result.new_state, STATE_AWAIT_OK,
        "fiber resumed: guest observed session resolution and returned witness state"
    );
}

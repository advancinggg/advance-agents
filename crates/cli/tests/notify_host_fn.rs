//! Wave-20 Lane `messagingabi` — the WASM `notify` host-fn instantiate+invoke+
//! deliver witness (M006-AC-02 + AC-15).
//!
//! Proves (against the dedicated `guest-rust-notify` fixture, which IMPORTS +
//! CALLS the `notify` host fns):
//!   1. **Instantiate**: a guest importing `notify-agent` / `notify-channel`
//!      instantiates through the production `CapabilityInjector` WITHOUT a
//!      `LinkerTypecheck` failure — the Wave-20 `register_typed_notify_agent` /
//!      `register_typed_notify_channel` injector path satisfies the import.
//!   2. **Invoke + deliver (AC-02)**: driving the guest's real
//!      `notify::notify_agent("agent:target", …)` through the typed injector path
//!      reaches `NotifyAgentHandler` → `MailboxDispatcherImpl::notify_agent` and
//!      the payload lands in the target's REAL mailbox (a real bare-keyed
//!      `cap_lifecycle::AgentTreeStore`). The guest runs under a PRODUCTION-
//!      FAITHFUL BARE `ctx.agent_id` (`default-agent`) — the Wave-20 seam-(a)
//!      sender normalization maps it to its canonical colon (`agent:default`) for
//!      the `is_safe_id(from)` gate.
//!   3. **Anti-fake-green discriminator**: the SAME guest call against the SAME
//!      real chain WITHOUT the id-bridge fails — the bare sender no longer
//!      normalizes, so `is_safe_id(from)` rejects → the guest's notify-agent
//!      returns Err → handle-message returns Err. The bridge is LOAD-BEARING.
//!   4. **AC-15**: a `system`-identity caller (cron/daemon) delivers via
//!      notify-agent to a NON-ADJACENT target with NO hierarchy check, through
//!      the real WIT host-fn ingress + a real component caller boundary (NOT an
//!      in-process dispatcher call — the new caller-boundary evidence AC-15
//!      required).

use std::sync::Arc;
use std::time::Duration;

use advance_messaging::{
    register_notify_channel_host_fn, register_notify_host_fns, AgentIdBridge,
    ChannelAdapterRegistry, ChannelNotifier, EmptyChannelAdapterRegistry, MailboxDispatcher,
    MailboxDispatcherImpl, MailboxStore, MessageTrace, NotifyError, DEFAULT_CAPACITY,
};
use advance_runtime::capability_injector::{CapabilityInjector, ComponentCtx};
use advance_runtime::circuit_breaker::{CircuitBreakerBus, DefaultCircuitBreakerBus};
use advance_runtime::config::WasmConfig;
use advance_runtime::host_registry::{HostRegistry, InMemoryHostRegistry};
use advance_runtime::wit_bindings::with_caps::advance::runtime::types as wit_types;
use advance_runtime::ComponentRuntime;
use advance_shared_types::agent_tree::{AgentId, AgentKind, AgentNode, AgentStatus};
use advance_shared_types::capability::{CapParams, CapRequest, CapabilityId, GrantDecision};
use advance_shared_types::traits::GrantCheck;
use cap_lifecycle::AgentTreeStore;
use tempfile::TempDir;
use wit_component::ComponentEncoder;

const CORE_BYTES: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-notify.core.wasm");

// Must match the guest fixture (`guest-rust-notify/src/lib.rs`).
const NOTIFY_PAYLOAD: [u8; 4] = [0x07, 0x1F, 0xAB, 0x01];
const STATE_NOTIFY_AGENT_OK: [u8; 4] = [0x07, 0x1F, 0x0A, 0x01];

const ROOT_BARE: &str = "default-agent";
const ROOT_COLON: &str = "agent:default";
const TARGET_BARE: &str = "target";
const TARGET_COLON: &str = "agent:target"; // == the fixture's NOTIFY_AGENT_TARGET

struct AllowAll;
impl GrantCheck for AllowAll {
    fn check(&self, _: &str, _: &str, _: &str, _: &CapParams) -> GrantDecision {
        GrantDecision::Allow
    }
}

fn node(id: &str, kind: AgentKind, parent: Option<&str>, ws: std::path::PathBuf) -> AgentNode {
    AgentNode {
        id: AgentId(id.into()),
        kind,
        parent: parent.map(|p| AgentId(p.into())),
        workspace_path: ws,
        capabilities: Vec::new(),
        template_ref: None,
        status: AgentStatus::Active,
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
        .expect("core wraps")
        .encode()
        .expect("component encoded")
}

/// Build a REAL bare-keyed `AgentTreeStore` (root `default-agent` + a child
/// `target`) + a `MailboxDispatcherImpl`. When `wire_bridge`, the dispatcher
/// carries the colon/bare `AgentIdBridge` for BOTH the sender (`default-agent`)
/// and the target (`target`). Returns the `TempDir` (held for the tree's
/// lifetime), the shared store, and the shared dispatcher as an `Arc`.
fn build(wire_bridge: bool) -> (TempDir, Arc<MailboxStore>, Arc<MailboxDispatcherImpl>) {
    let tmp = TempDir::new().unwrap();
    let tree = AgentTreeStore::new(tmp.path().to_path_buf()).unwrap();

    let root_ws = tree.workspace_root().join(ROOT_BARE);
    std::fs::create_dir_all(&root_ws).unwrap();
    tree.insert_root(node(ROOT_BARE, AgentKind::Root, None, root_ws))
        .unwrap();

    let target_ws = tree
        .workspace_root()
        .join(format!("{ROOT_BARE}/{TARGET_BARE}"));
    std::fs::create_dir_all(&target_ws).unwrap();
    tree.insert_child(
        &AgentId(ROOT_BARE.into()),
        node(TARGET_BARE, AgentKind::Child, Some(ROOT_BARE), target_ws),
    )
    .unwrap();
    // Sanity: the REAL tree rejects the colon forms (the production residual).
    assert!(tree.contains(&AgentId(TARGET_BARE.into())));
    assert!(!tree.contains(&AgentId(TARGET_COLON.into())));

    let store = Arc::new(MailboxStore::new(DEFAULT_CAPACITY));
    let registry: Arc<dyn ChannelAdapterRegistry> = Arc::new(EmptyChannelAdapterRegistry);
    let mut d = MailboxDispatcherImpl::new_full(
        store.clone(),
        Arc::new(tree),
        Arc::new(MessageTrace::new()),
        registry,
    );
    if wire_bridge {
        let bridge = AgentIdBridge::from_pairs([
            (ROOT_COLON.to_string(), ROOT_BARE.to_string()),
            (TARGET_COLON.to_string(), TARGET_BARE.to_string()),
        ]);
        d = d.with_id_bridge(Arc::new(bridge));
    }
    (tmp, store, Arc::new(d))
}

/// Compose registry+injector+runtime and instantiate the notify-importing guest.
/// Returns (bindings, store) — driving the guest's handle-message with
/// `config_data == branch` selects the notify branch.
async fn instantiate(
    dispatcher: Arc<MailboxDispatcherImpl>,
    caller_id: &str,
) -> (
    advance_runtime::wit_bindings::with_caps::AdvanceHostWithCapabilities,
    wasmtime::Store<ComponentCtx>,
) {
    let registry: Arc<dyn HostRegistry> = Arc::new(InMemoryHostRegistry::new());
    register_notify_host_fns(&*registry, dispatcher.clone() as Arc<dyn MailboxDispatcher>);
    register_notify_channel_host_fn(&*registry, dispatcher as Arc<dyn ChannelNotifier>);

    let grant: Arc<dyn GrantCheck> = Arc::new(AllowAll);
    let breaker: Arc<dyn CircuitBreakerBus> = Arc::new(DefaultCircuitBreakerBus::new());
    let injector = CapabilityInjector::new(registry, grant, breaker);
    let caps = vec![CapRequest {
        capability: CapabilityId::from("messaging"),
    }];

    let runtime = ComponentRuntime::new(&wasm_cfg()).expect("runtime");
    let loaded = runtime
        .load_component(&component_bytes())
        .expect("component loads");
    // PRODUCTION-FAITHFUL: caller_id is BARE for the agent case (default-agent);
    // for the AC-15 case it is the system identity.
    let ctx = ComponentCtx::new(caller_id.into(), "trace-w20".into(), Vec::new());
    runtime
        .instantiate_advance_host_with_capabilities_async(&loaded, ctx, &caps, &injector)
        .await
        .expect("instantiate — a notify-importing guest must link without LinkerTypecheck")
}

/// Drive the guest's `notify-agent` branch; returns the handle-message result.
async fn drive_notify_agent(
    bindings: &advance_runtime::wit_bindings::with_caps::AdvanceHostWithCapabilities,
    store: &mut wasmtime::Store<ComponentCtx>,
) -> Result<wit_types::ActionResult, String> {
    let cfg = wit_types::ComponentConfig {
        id: "test-w20-notify".into(),
        config_data: Some(b"notify-agent".to_vec()),
        trigger_context: None,
    };
    let init_state = bindings
        .advance_runtime_message_driven()
        .call_init(&mut *store, &cfg)
        .await
        .expect("init call")
        .expect("init Ok");
    let msg = wit_types::Message { payload: vec![] };
    tokio::time::timeout(
        Duration::from_secs(30),
        bindings
            .advance_runtime_message_driven()
            .call_handle_message(&mut *store, &msg, &init_state),
    )
    .await
    .expect("watchdog: handle-message within 30s")
    .expect("handle-message host call")
}

/// TB-W20-02a (AC-02): a notify-importing guest under a PRODUCTION-FAITHFUL BARE
/// `ctx.agent_id` calls notify-agent through the real injector → handler →
/// dispatcher; the payload lands in the target's REAL mailbox. Seam-(a) sender
/// normalization + the id-bridge are LOAD-BEARING (proven by 02a-off below).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tb_w20_02a_notify_agent_real_chain_bare_sender_delivers() {
    let (_tmp, store, dispatcher) = build(true);
    let (bindings, mut wstore) = instantiate(dispatcher, ROOT_BARE).await;

    let action = drive_notify_agent(&bindings, &mut wstore)
        .await
        .expect("handle-message Ok (notify-agent returned Ok)");
    assert_eq!(
        action.new_state, STATE_NOTIFY_AGENT_OK,
        "guest returned the notify witness state → notify-agent ran + returned Ok"
    );

    // The payload landed in the target's REAL (canonical colon) mailbox.
    let mb = store
        .get(TARGET_COLON)
        .expect("canonical target mailbox exists");
    let msg = mb.recv().await;
    assert_eq!(msg.to, TARGET_COLON);
    assert_eq!(
        msg.from, ROOT_COLON,
        "sender stamped canonical colon (seam-a normalization of the bare ctx.agent_id)"
    );
    assert_eq!(msg.payload, NOTIFY_PAYLOAD.to_vec());
    assert!(
        store.get(ROOT_BARE).is_none() && store.get(TARGET_BARE).is_none(),
        "no orphan bare-keyed mailbox"
    );
}

/// TB-W20-02a-off (anti-fake-green): the SAME guest call WITHOUT the id-bridge
/// fails — the bare sender no longer normalizes, `is_safe_id(from)` rejects, so
/// the guest's notify-agent returns Err and handle-message returns Err. Nothing
/// is delivered. Proves the bridge + seam-(a) are LOAD-BEARING.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tb_w20_02a_off_no_bridge_bare_sender_rejected() {
    let (_tmp, store, dispatcher) = build(false);
    let (bindings, mut wstore) = instantiate(dispatcher, ROOT_BARE).await;

    let result = drive_notify_agent(&bindings, &mut wstore).await;
    assert!(
        result.is_err(),
        "without the bridge the bare sender fails is_safe_id → guest Err, got {result:?}"
    );
    assert!(
        store.get(TARGET_COLON).is_none() && store.get(TARGET_BARE).is_none(),
        "bridge-off delivers nothing"
    );
}

/// TB-W20-15a (AC-15): a `system`-identity caller (cron/daemon) delivers via
/// notify-agent to a NON-ADJACENT target with NO hierarchy check, through the
/// real WIT host-fn ingress + a real component caller boundary. `system` passes
/// `is_safe_id(from)` directly (no normalization needed); the target colon id
/// resolves through the bridge against the real bare tree.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tb_w20_15a_system_caller_no_hierarchy_check_delivers() {
    let (_tmp, store, dispatcher) = build(true);
    // The caller is the `system` identity (a cron/daemon), NOT a tree member and
    // NOT a parent/ancestor of `target` — notify must deliver WITHOUT a
    // hierarchy/adjacency check (the AC-15 bypass).
    let (bindings, mut wstore) = instantiate(dispatcher, "system").await;

    let action = drive_notify_agent(&bindings, &mut wstore)
        .await
        .expect("handle-message Ok (system caller's notify-agent returned Ok)");
    assert_eq!(action.new_state, STATE_NOTIFY_AGENT_OK);

    let mb = store.get(TARGET_COLON).expect("target mailbox exists");
    let msg = mb.recv().await;
    assert_eq!(msg.to, TARGET_COLON);
    assert_eq!(
        msg.from, "system",
        "cron/daemon system caller, no hierarchy check"
    );
    assert_eq!(msg.payload, NOTIFY_PAYLOAD.to_vec());
}

/// Belt-and-suspenders: the dispatcher's `notify_agent` rejects an unsafe target
/// id directly (the gate is real, not bypassed by the bridge). Guards the
/// `is_safe_id` invariant the witness relies on.
#[tokio::test(flavor = "multi_thread")]
async fn tb_w20_dispatcher_rejects_unsafe_target() {
    let (_tmp, _store, dispatcher) = build(true);
    let err = dispatcher
        .notify_agent("system", "agent:a:b", b"x".to_vec(), None)
        .await
        .unwrap_err();
    assert_eq!(err, NotifyError::InvalidTarget("invalid_id".into()));
}

//! Track C — SYS-J-10 (a child agent traps mid-turn → its state is not written; the parent
//! receives a crash report).
//!
//! MAINLINE Wave-5 harvest (2026-06-21): **SYS-AC-029 is FLIPPED**; SYS-AC-028 / 030 stay
//! deferred. The 029 deferral reason ("restart policy is run-manager/supervision, not wired
//! in the harness") is STALE — the Stage-E run-loop slice wired the trap → `component.error`
//! emitter (`AgentLoopDriverImpl::with_component_error_emitter`, production at start.rs:612)
//! AND the `RestartPolicy` decision (`with_restart_policy` → `handle_trap` →
//! `restart_decision`). `sys_ac_029_*` below drive a REAL trapping GUEST (the
//! `guest-rust-trap` fixture whose `handle_message` returns Err — NOT the harness mock
//! `TrappingHandler`) through the production `serve_n_turns`, witnessing `component.error`
//! from the real guest trap plus the restart-policy break/continue decision.
//!
//! Wave-18 Lane 4 (2026-06-26): **SYS-AC-030 is now WITNESSED + flipped**. The orphan is
//! closed — the cli `build_crash_cascade_sink` (the SOLE production `CrashCascadeSink` impl)
//! wires the scheduler's new `handle_trap`-on-`Crash` seam to the REAL cap-lifecycle
//! `DefaultTerminateController::handle_crash` → `notify_parent_crash` cascade across the
//! colon/bare id seam. `sys_ac_030_*` below drives a REAL trapping CHILD guest through the
//! production `AgentLoopDriverImpl` (the SUT `.agents()` node driver + the default-off
//! `.with_crash_cascade()` axis) — NOT a direct `handle_crash` call — so the trigger is a
//! genuine mid-turn guest trap (drive-prod-fn precedent 098/101/109/202). The parent then
//! polls a `component.terminated` System crash report off its own mailbox.
//!
//! Wave-19 Lane 4 (2026-06-26): **SYS-AC-028 is now WITNESSED** via the forward-rollback-commit
//! (MODULE-014 §3.8 (z)). The `with_workspace_rollback()` axis wires the production
//! `WorkspaceRollbackSink` (cli `build_workspace_rollback_sink`): on a child `Crash` trap it
//! reverts the child subtree to the pre-turn `[seed]` baseline (`WorkspaceRollback::rollback`
//! FullDirectory) + removes the added `.meta.yaml` + a compensating `[micro]` commit, so the
//! child territory's FULL committed subtree returns to pre-turn (siblings preserved, no reset).
//! `sys_ac_028_*` below drive the REAL `guest-rust-write-then-trap` child (writes then traps)
//! through the production `AgentLoopDriverImpl::handle_trap(Crash)`. DISCLOSED spec-reading
//! (T028-C makes it explicit): the per-write `[turn]` write commit SURVIVES in history — the
//! witness proves committed-subtree equality + a non-`[turn]` HEAD, NOT the strict "no new turn
//! commit" (that needs the out-of-lane per-write→per-turn redesign). The §3 deferral row is
//! removed at the SUMMARY bookkeeping commit.

use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use advance_cli::agent_loop::{build_agent_loop, WasmMessageHandler};
use advance_messaging::{MailboxDispatcher, MailboxDispatcherImpl, MailboxStore};
use advance_runtime::capability_injector::CapabilityInjector;
use advance_runtime::circuit_breaker::{CircuitBreakerBus, DefaultCircuitBreakerBus};
use advance_runtime::config::WasmConfig;
use advance_runtime::host_registry::{HostRegistry, InMemoryHostRegistry};
use advance_runtime::ComponentRuntime;
use advance_scheduler::agent_loop::AgentLoopDriverImpl;
use advance_scheduler::hook::MessageHandler;
use advance_scheduler::types::{ComponentConfig, ComponentId, RestartPolicy, WasmInstance};
use advance_shared_types::agent_tree::{
    AgentId, AgentKind, AgentNode, AgentStatus, AgentTreeReader, AgentTreeSnapshot,
    AgentTreeSnapshotData, Capability,
};
use advance_shared_types::capability::{CapParams, CapRequest, CapabilityId, GrantDecision};
use advance_shared_types::event::Event;
use advance_shared_types::mailbox::{Message, MessageKind};
use advance_shared_types::traits::{EventBusEmit, GrantCheck};
use cap_fs::{
    register_agent_fs, DefaultAtomicWriter, DefaultVirtualPathResolver, MetaSchemaLoader,
    StubFileHistoryProvider, VirtualPathResolver,
};
use system_acceptance::{AgentSpec, Cap, SystemUnderTest};

const TRAP_CORE: &[u8] = include_bytes!("fixtures/guest-rust-trap.core.wasm");
const AGENT_ID: &str = "agent:trap";
const AGENT_DIR: &str = "trap";

// ── doubles ──────────────────────────────────────────────────────────────────

struct AllowAll;
impl GrantCheck for AllowAll {
    fn check(&self, _: &str, _: &str, _: &str, _: &CapParams) -> GrantDecision {
        GrantDecision::Allow
    }
}

#[derive(Default)]
struct CapturingBus {
    events: Mutex<Vec<Event>>,
}
impl CapturingBus {
    fn events_of(&self, ty: &str) -> Vec<Event> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.event_type == ty)
            .cloned()
            .collect()
    }
    fn count(&self, ty: &str) -> usize {
        self.events_of(ty).len()
    }
}
impl EventBusEmit for CapturingBus {
    fn emit(&self, event: Event) {
        self.events.lock().unwrap().push(event);
    }
}

struct OneAgentTree {
    nodes: Vec<AgentNode>,
}
impl OneAgentTree {
    fn new(workspace: PathBuf) -> Self {
        Self {
            nodes: vec![AgentNode {
                id: AgentId(AGENT_ID.to_string()),
                kind: AgentKind::Root,
                parent: None,
                workspace_path: workspace,
                capabilities: Vec::new(),
                template_ref: None,
                status: AgentStatus::Active,
            }],
        }
    }
}
impl AgentTreeReader for OneAgentTree {
    fn parent_of(&self, _: &str) -> Option<String> {
        None
    }
    fn children_of(&self, _: &str) -> Vec<String> {
        Vec::new()
    }
    fn siblings_of(&self, _: &str) -> Vec<String> {
        Vec::new()
    }
    fn agent_exists(&self, id: &str) -> bool {
        self.nodes.iter().any(|n| n.id.0 == id)
    }
    fn agent_kind(&self, id: &str) -> Option<AgentKind> {
        self.nodes
            .iter()
            .find(|n| n.id.0 == id)
            .map(|n| n.kind.clone())
    }
    fn capabilities(&self, _: &str) -> Vec<Capability> {
        Vec::new()
    }
}
impl AgentTreeSnapshot for OneAgentTree {
    fn snapshot(&self) -> AgentTreeSnapshotData {
        AgentTreeSnapshotData {
            nodes: self.nodes.clone(),
            parent_of: HashMap::new(),
            children_of: HashMap::new(),
            peer_slug_map: HashMap::new(),
            revision: 0,
        }
    }
}

fn wasm_cfg() -> WasmConfig {
    WasmConfig {
        max_memory_pages: 256,
        epoch_interruption_ms: 100,
        fuel_enabled: false,
    }
}

/// The real production agent loop over the trapping guest, with the trap
/// `component.error` emitter + the configured RestartPolicy wired (mirroring
/// production start.rs). Returns the driver (owned, to drive serve_n_turns), the
/// dispatcher (to deliver inbound messages), the shared bus, and the tempdir guard.
struct TrapStack {
    driver: AgentLoopDriverImpl,
    dispatcher: Arc<MailboxDispatcherImpl>,
    bus: Arc<CapturingBus>,
    _tmp: tempfile::TempDir,
}

fn build_trap_stack(policy: RestartPolicy) -> TrapStack {
    let tmp = tempfile::TempDir::new().unwrap();
    let workspace_root = tmp.path().to_path_buf();
    let agent_workspace = workspace_root.join(AGENT_DIR);
    std::fs::create_dir_all(&agent_workspace).unwrap();

    let bus = Arc::new(CapturingBus::default());
    let bus_dyn: Arc<dyn EventBusEmit> = bus.clone();
    let tree = Arc::new(OneAgentTree::new(agent_workspace));

    // cap-fs registered ONLY so the trapping guest's `agent-fs` import resolves at
    // instantiation (the guest never calls it — it traps in handle_message). No git
    // sync (the guest writes nothing).
    let resolver: Arc<dyn VirtualPathResolver> = Arc::new(DefaultVirtualPathResolver::new(
        workspace_root.clone(),
        tree.clone() as Arc<dyn AgentTreeSnapshot>,
    ));
    let schema = Arc::new(MetaSchemaLoader::new_with_default(PathBuf::new()));
    let registry: Arc<dyn HostRegistry> = Arc::new(InMemoryHostRegistry::new());
    register_agent_fs(
        &*registry,
        resolver,
        bus_dyn.clone(),
        schema,
        Arc::new(StubFileHistoryProvider),
        Arc::new(DefaultAtomicWriter),
        None,
        None,
        None,
        None,
        None,
    );
    let grant: Arc<dyn GrantCheck> = Arc::new(AllowAll);
    let breaker: Arc<dyn CircuitBreakerBus> = Arc::new(DefaultCircuitBreakerBus::new());
    let injector = Arc::new(CapabilityInjector::new(registry.clone(), grant, breaker));

    let runtime = Arc::new(ComponentRuntime::new(&wasm_cfg()).expect("runtime"));
    let component = build_agent::encode_core_to_component(TRAP_CORE).expect("encode trap guest");
    let loaded = runtime
        .load_component(&component)
        .expect("trap component loads");

    let message_handler: Arc<dyn MessageHandler> = Arc::new(WasmMessageHandler::new(
        runtime,
        loaded,
        injector,
        vec![CapRequest {
            capability: CapabilityId::from("fs"),
        }],
        AGENT_ID.to_string(),
        "trace-harness".to_string(),
    ));

    let store = Arc::new(MailboxStore::new(NonZeroUsize::new(64).unwrap()));
    let dispatcher = Arc::new(
        MailboxDispatcherImpl::new(store.clone(), tree.clone() as Arc<dyn AgentTreeReader>)
            .with_event_bus(bus_dyn.clone()),
    );

    // Wire the production trap seams: the component.error emitter (start.rs:612) +
    // the RestartPolicy decision.
    let driver = build_agent_loop(store.clone(), message_handler, bus_dyn.clone(), None)
        .with_component_error_emitter(bus_dyn.clone())
        .with_restart_policy(policy);

    TrapStack {
        driver,
        dispatcher,
        bus,
        _tmp: tmp,
    }
}

async fn deliver(dispatcher: &MailboxDispatcherImpl, n: usize) {
    for i in 0..n {
        let msg = Message {
            id: format!("trap-msg-{i}"),
            kind: MessageKind::User,
            from: "user:harness".to_string(),
            to: AGENT_ID.to_string(),
            payload: b"trigger-trap".to_vec(),
            context: None,
            timestamp: SystemTime::now(),
            origin: None,
        };
        dispatcher.deliver(AGENT_ID, msg).await.expect("deliver");
    }
}

fn cfg() -> ComponentConfig {
    ComponentConfig {
        id: AGENT_ID.to_string(),
        config_data: None,
        trigger_context: None,
    }
}

fn instance() -> WasmInstance {
    WasmInstance::new(ComponentId::new("trap-inst".to_string()).expect("component id"))
}

// ── SYS-AC-029 (Never) — a real guest trap emits component.error and STOPS ─────
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_029_real_guest_trap_emits_component_error_never_stops() {
    let stack = build_trap_stack(RestartPolicy::Never);
    // Two messages queued; serve_n_turns(2) would process both, but a Never trap on
    // turn 1 sets the stop cell → the bounded loop breaks BEFORE the second turn.
    deliver(&stack.dispatcher, 2).await;
    stack
        .driver
        .serve_n_turns(AGENT_ID, cfg(), instance(), 2)
        .await;

    let errors = stack.bus.events_of("component.error");
    // Restart policy Never → the run STOPPED after the first trap (exactly one).
    assert_eq!(
        errors.len(),
        1,
        "RestartPolicy::Never stops the loop after the first trap (one component.error)"
    );
    // The component.error is from the REAL guest trap (the guest's Err reason),
    // not a harness-emitted event.
    let reason = errors[0]
        .payload
        .get("message")
        .and_then(|r| r.as_str())
        .unwrap_or_default();
    assert!(
        reason.contains("intentional guest trap"),
        "component.error carries the REAL guest trap reason; got payload {:?}",
        errors[0].payload
    );
    // and it's attributed to the trapping agent's component type.
    assert_eq!(
        errors[0]
            .payload
            .get("component_type")
            .and_then(|c| c.as_str()),
        Some("agent"),
        "component.error names the agent component type"
    );
}

// ── SYS-AC-029 (OnFailure) — the trap continues the loop (restart) ─────────────
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_029_real_guest_trap_on_failure_continues() {
    let stack = build_trap_stack(RestartPolicy::OnFailure);
    // Two messages; OnFailure does NOT set the stop cell, so the bounded loop
    // processes BOTH turns → two component.error (the restart/continue decision).
    deliver(&stack.dispatcher, 2).await;
    stack
        .driver
        .serve_n_turns(AGENT_ID, cfg(), instance(), 2)
        .await;

    assert_eq!(
        stack.bus.count("component.error"),
        2,
        "RestartPolicy::OnFailure continues past the trap (one component.error per turn)"
    );
}

// ── SYS-AC-030 — a real child guest trap → the parent receives a crash report ──

/// Parent (root) + child specs for the crash-cascade tree. Canonical colon ids; the
/// SUT bares them for the cap-lifecycle `AgentTreeStore` (`agent:child` → `child`,
/// parent `child` → bare `parent`). Both declare `Cap::Fs` so the trap guest's
/// `agent-fs` import resolves at instantiation (the guest traps in `handle_message`
/// before ever calling it).
fn parent_and_child() -> Vec<AgentSpec> {
    vec![
        AgentSpec {
            id: "agent:parent".into(),
            kind: AgentKind::Root,
            parent: None,
            caps: vec![Cap::Fs],
            capabilities: vec![],
        },
        AgentSpec {
            id: "agent:child".into(),
            kind: AgentKind::Child,
            parent: Some("agent:parent".into()),
            caps: vec![Cap::Fs],
            capabilities: vec![],
        },
    ]
}

/// Find a `component.terminated` System crash report addressed to `key`'s mailbox.
/// Returns the decoded payload, or `None` if no such message is present.
fn poll_crash_report(store: &MailboxStore, key: &str) -> Option<serde_json::Value> {
    let mb = store.get(key)?;
    let budget = mb.depth().saturating_add(4);
    for _ in 0..budget {
        let msg = match mb.poll() {
            Some(m) => m,
            None => break,
        };
        if msg.kind != MessageKind::System {
            continue;
        }
        if let Ok(p) = serde_json::from_slice::<serde_json::Value>(&msg.payload) {
            if p.get("event").and_then(|e| e.as_str()) == Some("component.terminated") {
                return Some(p);
            }
        }
    }
    None
}

/// SYS-AC-030: a CHILD running a real trapping guest INSIDE the production agent loop
/// → `handle_trap(Crash)` → the wired crash-cascade sink → the PARENT mailbox carries a
/// `component.terminated` System message bound to the real trap. Oracle: parent mailbox
/// poll (commit-model-independent). Anti-fake-green: the trigger is a genuine guest trap
/// in a real serve turn (NOT a direct `handle_crash`); the reason is the real guest trap
/// string; the axis-off control gets NO message; the wrong (bare) key is empty.
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_030_parent_receives_crash_report() {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Fs])
        .agents(&parent_and_child())
        .with_crash_cascade()
        .build(TRAP_CORE)
        .await;

    // Inject FIRST (the child's serve `recv` parks until a message arrives), then run
    // exactly one turn for the child → the guest traps in `handle_message`.
    sut.inject_message_to("agent:child", "harness", b"trigger-trap")
        .await;
    sut.run_turns_for("agent:child", 1).await;

    let store = sut.mailbox_store();
    let report = poll_crash_report(&store, "agent:parent")
        .expect("the parent's colon mailbox carries a component.terminated crash report");
    assert_eq!(report["event"], "component.terminated");
    assert_eq!(
        report["child"], "child",
        "the crash report names the BARE crashed child tree id"
    );
    let reason = report["reason"].as_str().unwrap_or_default();
    assert!(
        reason.contains("intentional guest trap"),
        "the crash report carries the REAL guest trap reason; got {reason:?}"
    );

    // Wrong-key discriminator: the BARE `parent` key was never a delivery target — the
    // colon resolver bridge is load-bearing (a hardcoded bare delivery would orphan it).
    assert!(
        store.get("parent").is_none(),
        "bare `parent` mailbox is never created → delivery used the colon bridge"
    );
}

/// SYS-AC-030 anti-fake-green control: WITHOUT `.with_crash_cascade()`, the identical
/// real child trap produces NO crash report on the parent mailbox (the cascade, not some
/// always-on path, is what delivers it). The trap itself still happens (the 029 tests
/// witness the `component.error`); only the parent NOTIFICATION is gated by the axis.
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_030_axis_off_no_crash_report() {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Fs])
        .agents(&parent_and_child())
        // no .with_crash_cascade()
        .build(TRAP_CORE)
        .await;

    sut.inject_message_to("agent:child", "harness", b"trigger-trap")
        .await;
    sut.run_turns_for("agent:child", 1).await;

    let store = sut.mailbox_store();
    assert!(
        poll_crash_report(&store, "agent:parent").is_none(),
        "axis-off: no crash sink wired → the parent receives NO component.terminated report"
    );
}

// ── SYS-AC-028 — a child trap rolls its workspace back to the pre-turn commit ──
//
// Wave-19 Lane 4: the forward-rollback-commit. The `guest-rust-write-then-trap` child
// WRITES `child-out.txt` (a per-write `[turn]` commit) THEN traps; the wired
// `WorkspaceRollbackSink` reverts the child subtree to the pre-turn `[seed]` baseline + a
// compensating `[micro]` commit (incl. removing the added `.meta.yaml`), so the child
// territory's FULL HEAD-committed subtree returns to pre-turn. Oracle: committed-subtree
// blob/oid set (NOT working-tree). DISCLOSED spec-reading (T028-C makes it explicit): the
// per-write `[turn]` write commit SURVIVES in history (the strict "no new turn commit" is
// not met); the witness proves committed-subtree equality + a non-`[turn]` HEAD.

/// The write-then-trap child (writes a witness file at the territory root, then traps).
const WRITE_THEN_TRAP_CORE: &[u8] = include_bytes!("fixtures/guest-rust-write-then-trap.core.wasm");

/// Repo-relative prefix of `agent:child`'s territory under `agent:parent` (the
/// `build_agents_handle` layout: `<parent_bare>/children/<bare>`). Trailing slash so a
/// sibling like `child2` cannot prefix-collide.
const CHILD_TERRITORY: &str = "parent/children/child/";

/// The set of HEAD-committed `(path, blob-oid)` pairs under `prefix` (repo-workdir-relative),
/// the committed-subtree oracle. The OID (not just the path) is compared so that a same-path
/// blob whose CONTENT changed (e.g. a stale `.meta.yaml` left over a non-empty baseline) is
/// caught — set equality with pre-turn means BOTH the path set AND every blob's content match.
/// Empty on an unborn/absent HEAD.
fn committed_blobs_under(
    ws: &std::path::Path,
    prefix: &str,
) -> std::collections::BTreeSet<(String, String)> {
    let mut out = std::collections::BTreeSet::new();
    let repo = match git2::Repository::open(ws) {
        Ok(r) => r,
        Err(_) => return out,
    };
    let tree = match repo
        .head()
        .and_then(|h| h.peel_to_commit())
        .and_then(|c| c.tree())
    {
        Ok(t) => t,
        Err(_) => return out,
    };
    let _ = tree.walk(git2::TreeWalkMode::PreOrder, |dir, entry| {
        if entry.kind() == Some(git2::ObjectType::Blob) {
            let full = format!("{dir}{}", entry.name().unwrap_or(""));
            if full.starts_with(prefix) {
                out.insert((full, entry.id().to_string()));
            }
        }
        git2::TreeWalkResult::Ok
    });
    out
}

/// HEAD-ancestry commit messages, most-recent first.
fn commit_messages(ws: &std::path::Path) -> Vec<String> {
    let repo = match git2::Repository::open(ws) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    let mut cur = repo.head().ok().and_then(|h| h.peel_to_commit().ok());
    while let Some(c) = cur {
        out.push(c.message().unwrap_or("").to_string());
        cur = c.parent(0).ok();
    }
    out
}

/// True when the working tree matches HEAD for every path under `prefix` (git status clean
/// for the child territory) — INCLUDING untracked files (libgit2 omits them by default), so a
/// leftover untracked write would be caught too.
fn child_status_clean(ws: &std::path::Path, prefix: &str) -> bool {
    let repo = match git2::Repository::open(ws) {
        Ok(r) => r,
        Err(_) => return false,
    };
    let mut opts = git2::StatusOptions::new();
    opts.include_untracked(true).recurse_untracked_dirs(true);
    let statuses = match repo.statuses(Some(&mut opts)) {
        Ok(s) => s,
        Err(_) => return false,
    };
    !statuses
        .iter()
        .any(|s| s.path().map(|p| p.starts_with(prefix)).unwrap_or(false))
}

/// T028-A — happy path: a real child trap rolls the committed subtree back to pre-turn.
/// Oracle: the FULL child-subtree committed blob set returns to the `[seed]` baseline
/// (the write AND its `.meta.yaml` sidecar gone), git status clean, HEAD is the `[micro]`
/// rollback commit (not `[turn]`).
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_028_child_trap_committed_subtree_returns_to_pre_turn() {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Fs])
        .agents(&parent_and_child())
        .with_workspace_rollback()
        .build(WRITE_THEN_TRAP_CORE)
        .await;
    let ws = sut.workspace_root().to_path_buf();

    // Pre-turn: the `[seed]` baseline committed the child's `.agent/config.yaml` (and nothing
    // else under the territory).
    let pre = committed_blobs_under(&ws, CHILD_TERRITORY);
    assert!(
        pre.iter().any(|p| p.0.ends_with("/.agent/config.yaml")),
        "baseline committed the child's .agent/config.yaml; got {pre:?}"
    );
    assert!(
        !pre.iter().any(|p| p.0.ends_with("child-out.txt")),
        "pre-turn: no witness file committed yet; got {pre:?}"
    );

    // Run exactly one child turn: the guest writes child-out.txt (per-write [turn] commit)
    // then traps → handle_trap → the wired WorkspaceRollbackSink reverts + compensates.
    sut.inject_message_to("agent:child", "harness", b"trigger-trap")
        .await;
    sut.run_turns_for("agent:child", 1).await;

    // The committed subtree returned to pre-turn (full blob/oid set equality).
    let post = committed_blobs_under(&ws, CHILD_TERRITORY);
    assert_eq!(
        post, pre,
        "child territory committed subtree == pre-turn (full blob set); got {post:?}"
    );
    assert!(
        !post.iter().any(|p| p.0.ends_with("child-out.txt")),
        "the trapping turn's write is GONE from the committed subtree"
    );
    assert!(
        !post.iter().any(|p| p.0.ends_with("/.meta.yaml")),
        "the turn's .meta.yaml sidecar is GONE from the committed subtree (F3 meta cleanup)"
    );

    // git status clean for the child territory (working tree == HEAD).
    assert!(
        child_status_clean(&ws, CHILD_TERRITORY),
        "git status clean for the child territory after rollback"
    );

    // HEAD is the [micro] compensating rollback commit, NOT a [turn].
    let msgs = commit_messages(&ws);
    let head = msgs.first().cloned().unwrap_or_default();
    assert!(
        head.starts_with("[micro]"),
        "HEAD is the [micro] compensating rollback commit; got {head:?}"
    );
    assert!(!head.starts_with("[turn]"), "HEAD is NOT a turn commit");
}

/// T028-B — anti-fake-green control: WITHOUT `.with_workspace_rollback()`, the identical
/// real child trap leaves the write COMMITTED (no rollback fires). Proves the write
/// genuinely happens + persists, and that the rollback axis (not some always-on path) is
/// what removes it in T028-A.
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_028_axis_off_write_persists() {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Fs])
        .agents(&parent_and_child())
        // no .with_workspace_rollback()
        .build(WRITE_THEN_TRAP_CORE)
        .await;
    let ws = sut.workspace_root().to_path_buf();

    sut.inject_message_to("agent:child", "harness", b"trigger-trap")
        .await;
    sut.run_turns_for("agent:child", 1).await;

    let post = committed_blobs_under(&ws, CHILD_TERRITORY);
    assert!(
        post.iter().any(|p| p.0.ends_with("child-out.txt")),
        "axis-off: the write PERSISTS in the committed subtree (no rollback wired); got {post:?}"
    );
    let msgs = commit_messages(&ws);
    assert!(
        msgs.iter().any(|m| m.starts_with("[turn]")),
        "axis-off: the per-write [turn] commit carries the write (non-vacuous); got {msgs:?}"
    );
}

/// T028-C — disclosed spec-reading made explicit: the rollback COMPENSATES a real committed
/// write rather than erasing it. The per-write `[turn]` commit SURVIVES in HEAD's ancestry
/// (transparently witnessed, not hidden) with the `[micro]` rollback commit on top. Proves
/// the rollback is non-vacuous (a real write committed) and honestly surfaces that the strict
/// "no new turn commit" is met only at the net/HEAD level, not in history.
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_028_turn_write_commit_compensated_not_erased() {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Fs])
        .agents(&parent_and_child())
        .with_workspace_rollback()
        .build(WRITE_THEN_TRAP_CORE)
        .await;
    let ws = sut.workspace_root().to_path_buf();

    sut.inject_message_to("agent:child", "harness", b"trigger-trap")
        .await;
    sut.run_turns_for("agent:child", 1).await;

    let msgs = commit_messages(&ws);
    let micro_idx = msgs.iter().position(|m| m.starts_with("[micro]"));
    let turn_idx = msgs.iter().position(|m| m.starts_with("[turn]"));
    assert!(
        micro_idx.is_some(),
        "a [micro] rollback commit exists (the compensation); got {msgs:?}"
    );
    assert!(
        turn_idx.is_some(),
        "the per-write [turn] commit SURVIVES in history (disclosed: compensated, not erased); got {msgs:?}"
    );
    assert!(
        micro_idx.unwrap() < turn_idx.unwrap(),
        "the [micro] rollback commit sits ON TOP of the [turn] write commit (HEAD-first order); got {msgs:?}"
    );
}

/// Commit a single file (a SIBLING agent's work, OUTSIDE the child territory) directly via git2,
/// returning its committed blob-oid hex. Used by T028-D to prove the child rollback is
/// territory-scoped.
fn commit_sibling_file(ws: &std::path::Path, vpath: &str, content: &[u8]) -> String {
    let physical = ws.join(vpath);
    if let Some(parent) = physical.parent() {
        std::fs::create_dir_all(parent).expect("sibling dir");
    }
    std::fs::write(&physical, content).expect("write sibling file");
    let repo = git2::Repository::open(ws).expect("open repo");
    let mut index = repo.index().expect("index");
    index
        .add_path(std::path::Path::new(vpath))
        .expect("add sibling");
    index.write().expect("write index");
    let tree_oid = index.write_tree().expect("write tree");
    let tree = repo.find_tree(tree_oid).expect("find tree");
    // The committed blob is content-addressed, so the tree we just built carries the same oid the
    // commit will. Read it from `tree` (avoids re-walking HEAD after the commit).
    let blob_oid = tree
        .get_path(std::path::Path::new(vpath))
        .expect("sibling blob in tree")
        .id()
        .to_string();
    let sig = git2::Signature::now("harness-sibling", "sibling@harness.test").expect("sibling sig");
    let parent = repo
        .head()
        .ok()
        .and_then(|h| h.peel_to_commit().ok())
        .expect("born HEAD (baseline) before sibling commit");
    repo.commit(
        Some("HEAD"),
        &sig,
        &sig,
        "[turn] [agent:sibling] sibling work",
        &tree,
        &[&parent],
    )
    .expect("sibling commit");
    blob_oid
}

/// T028-D — territory-scoped soundness: a SIBLING's committed blob (OUTSIDE the child territory)
/// SURVIVES the child trap+rollback. This is the empirical proof that the forward-rollback-commit
/// is territory-scoped — NOT a repo-global `git reset` (which would discard the sibling's commit
/// on the ONE shared workspace repo) and NOT a history rewrite — the core reason the design is
/// sound where an unsound reset would not be.
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_028_sibling_commits_preserved() {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Fs])
        .agents(&parent_and_child())
        .with_workspace_rollback()
        .build(WRITE_THEN_TRAP_CORE)
        .await;
    let ws = sut.workspace_root().to_path_buf();

    // A sibling commits a blob OUTSIDE the child territory (a [turn] commit), AFTER the [seed]
    // baseline and BEFORE the child's trapping turn → it is part of the pre-turn repo state.
    let sibling_oid = commit_sibling_file(&ws, "sibling-work.txt", b"sibling-agent-output");

    // Run the child's trap turn → write child-out.txt → trap → territory-scoped rollback.
    sut.inject_message_to("agent:child", "harness", b"trigger-trap")
        .await;
    sut.run_turns_for("agent:child", 1).await;

    // The sibling's blob is STILL committed at HEAD with the SAME oid (the child's compensating
    // [micro] commit preserves every path outside its writable domain; no repo-global reset).
    let sib = committed_blobs_under(&ws, "sibling-work.txt");
    assert!(
        sib.contains(&("sibling-work.txt".to_string(), sibling_oid)),
        "the sibling's committed blob survives the child rollback (territory-scoped, no repo-global reset); got {sib:?}"
    );

    // And the child rollback still happened (its trapping-turn write is gone from the committed
    // subtree) — proving the rollback fired, not that it merely no-op'd to preserve the sibling.
    let child = committed_blobs_under(&ws, CHILD_TERRITORY);
    assert!(
        !child.iter().any(|(p, _)| p.ends_with("child-out.txt")),
        "the child's trapping-turn write is rolled back even with a sibling commit present; got {child:?}"
    );
}

/// T028-E — non-empty-baseline (2nd+-turn): the KEEP branch preserves a PRE-EXISTING committed
/// file with NO DATA LOSS, even though the committed `.meta.yaml` is left stale (the disclosed
/// deferred limitation). Witnesses the substantive AC intent for the non-empty case: the agent's
/// CONTENT returns to pre-turn (the trap-write is rolled back; the pre-existing durable file
/// survives UNCHANGED), and the non-empty territory dir makes the sink take the fail-safe KEEP
/// path (it leaves the turn's freshly-added `.meta.yaml` rather than risk clobbering a sidecar in
/// a dir that still holds content). NOTE: this `keep.txt` is committed via git2 with NO `.meta.yaml`,
/// so the kept sidecar here is the turn's freshly-added orphan; the genuine worst case the KEEP
/// rationale guards — a PRE-EXISTING user-authored `.meta.yaml` (description/tags) the turn updates
/// and the rollback would otherwise clobber — is the disclosed-deferred limitation and is NOT
/// witnessed here. Full-tree blob/oid equality is deliberately NOT asserted — for a non-empty
/// baseline the `.meta.yaml` stays stale; a byte-exact restore needs the pre-turn blob (out-of-lane,
/// deferred to the Wave-19 daemon wiring — see `cli/src/workspace_rollback.rs`).
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_028_non_empty_baseline_no_data_loss() {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Fs])
        .agents(&parent_and_child())
        .with_workspace_rollback()
        .build(WRITE_THEN_TRAP_CORE)
        .await;
    let ws = sut.workspace_root().to_path_buf();

    // A PRE-EXISTING committed regular file in the CHILD territory (a prior turn's durable output)
    // → the territory dir is non-empty, so the trap rollback takes the fail-safe KEEP path.
    let keep_oid = commit_sibling_file(&ws, "parent/children/child/keep.txt", b"prior-turn-output");

    sut.inject_message_to("agent:child", "harness", b"trigger-trap")
        .await;
    sut.run_turns_for("agent:child", 1).await;

    let child = committed_blobs_under(&ws, CHILD_TERRITORY);
    // NO DATA LOSS: the pre-existing committed file survives with its EXACT oid (the KEEP-branch
    // fail-safe did not clobber it; the rollback did not corrupt it).
    assert!(
        child.contains(&("parent/children/child/keep.txt".to_string(), keep_oid)),
        "the pre-existing committed file survives the trap rollback UNCHANGED (no data loss); got {child:?}"
    );
    // CONTENT RETURNS: the trapping turn's write is rolled back (gone from the committed subtree).
    assert!(
        !child.iter().any(|(p, _)| p.ends_with("child-out.txt")),
        "the trapping turn's write is rolled back even on a NON-empty baseline; got {child:?}"
    );
}

//! Wave-18 — `cli::crash_cascade::build_crash_cascade_sink` unit witness.
//!
//! Drives the production sink in ISOLATION (no full agent-loop) to pin the two-id
//! bridge: a COLON-keyed scheduler `agent_id` → BARE cap-lifecycle tree lookup →
//! `handle_crash` → `notify_parent_crash` → the parent's resolver-mapped (colon)
//! mailbox. The end-to-end SYS-AC-030 flip lives in
//! `system-acceptance/tests/sys_j10_child_trap.rs` (a real guest trap through the
//! production `AgentLoopDriverImpl`); this test isolates the cli composition fn + its
//! discriminators (wrong-key empty, root-no-notify, absent-node-swallowed).

use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::Arc;

use advance_cli::crash_cascade::build_crash_cascade_sink;
use advance_messaging::MailboxStore;
use advance_scheduler::CrashCascadeSink;
use advance_shared_types::agent_tree::{AgentId, AgentKind, AgentNode, AgentStatus};
use advance_shared_types::mailbox::MessageKind;
use cap_lifecycle::AgentTreeStore;
use tempfile::TempDir;

fn node(id: &str, kind: AgentKind, parent: Option<&str>, ws: PathBuf) -> AgentNode {
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

/// Build a real bare-keyed tree (root → child) + a shared mailbox store.
fn setup() -> (TempDir, AgentTreeStore, Arc<MailboxStore>) {
    let tmp = TempDir::new().unwrap();
    let tree = AgentTreeStore::new(tmp.path().to_path_buf()).unwrap();
    let rws = tree.workspace_root().join("root");
    std::fs::create_dir_all(&rws).unwrap();
    tree.insert_root(node("root", AgentKind::Root, None, rws))
        .unwrap();
    let cws = tree.workspace_root().join("root/child");
    std::fs::create_dir_all(&cws).unwrap();
    tree.insert_child(
        &AgentId("root".into()),
        node("child", AgentKind::Child, Some("root"), cws),
    )
    .unwrap();
    let store = Arc::new(MailboxStore::new(NonZeroUsize::new(64).unwrap()));
    (tmp, tree, store)
}

/// The symmetric resolver the harness + spawned-children use: bare `b` → `agent:{b}`.
fn colon_resolver(b: &str) -> String {
    format!("agent:{b}")
}

/// T-CCS-01: a colon-keyed child crash delivers a `component.terminated` System
/// message to the parent's COLON mailbox; the bare keys are never touched (the
/// resolver bridge is load-bearing).
#[test]
fn t_ccs_01_colon_child_crash_reaches_colon_parent_mailbox() {
    let (_tmp, tree, store) = setup();
    let sink: Arc<dyn CrashCascadeSink> =
        build_crash_cascade_sink(tree, store.clone(), colon_resolver);

    // Scheduler hands the COLON-keyed served id.
    sink.handle_crash("agent:child", "boom-trap");

    // Delivered to the parent's served (colon) mailbox.
    let parent_mb = store
        .get("agent:root")
        .expect("parent colon mailbox created on delivery");
    assert_eq!(
        parent_mb.depth(),
        1,
        "exactly one crash report on the parent mailbox"
    );
    let msg = parent_mb.poll().expect("the crash report");
    assert_eq!(
        msg.kind,
        MessageKind::System,
        "crash report is a System message"
    );
    assert_eq!(msg.from, "system");
    assert_eq!(msg.to, "agent:root");
    let payload: serde_json::Value = serde_json::from_slice(&msg.payload).unwrap();
    assert_eq!(payload["event"], "component.terminated");
    assert_eq!(
        payload["child"], "child",
        "the BARE child id is reported in the payload"
    );
    assert_eq!(
        payload["reason"], "boom-trap",
        "the real trap reason is reported verbatim"
    );

    // Wrong-key discriminator: the BARE keys were never created → the colon bridge is
    // doing the work (a hardcoded bare delivery would have orphaned the report here).
    assert!(
        store.get("root").is_none(),
        "bare `root` key is never a delivery target"
    );
    assert!(
        store.get("child").is_none(),
        "bare `child` key is never a delivery target"
    );
}

/// T-CCS-02: a ROOT crash (no parent) flips status but notifies nobody — no mailbox
/// is created, and the sink does not panic (handle_crash returns Ok on a None parent).
#[test]
fn t_ccs_02_root_crash_notifies_nobody() {
    let (_tmp, tree, store) = setup();
    let sink: Arc<dyn CrashCascadeSink> =
        build_crash_cascade_sink(tree, store.clone(), colon_resolver);

    sink.handle_crash("agent:root", "root-boom");

    assert!(
        store.get("agent:root").is_none(),
        "a root crash creates no mailbox (no parent)"
    );
    assert!(
        store.get("agent:child").is_none(),
        "no child mailbox either"
    );
}

/// T-CCS-03: an absent node → `handle_crash` returns `Err(NotFound)`, which the sink
/// SWALLOWS (best-effort; must never panic the serve loop) and delivers nothing.
#[test]
fn t_ccs_03_absent_node_is_swallowed() {
    let (_tmp, tree, store) = setup();
    let sink: Arc<dyn CrashCascadeSink> =
        build_crash_cascade_sink(tree, store.clone(), colon_resolver);

    // No `ghost` node in the tree → set_status fails → NotFound → swallowed.
    sink.handle_crash("agent:ghost", "ghost-boom");

    assert!(store.get("agent:ghost").is_none());
    assert!(
        store.get("agent:root").is_none(),
        "no spurious delivery to anyone"
    );
}

//! HF fast-follow smoke (2026-06-03): `.agents([...])` multi-agent substrate.
//!
//! Witnesses the REAL providers (not a guest turn — the guest spawn/await/reply
//! loop is upstream-blocked; see the crate README "HF fast-follow blockers"):
//!   - a seeded multi-node tree (HF-T02),
//!   - a real `DefaultSpawner.spawn_child` mutating the bare-id store (HF-T03, SYS-J-07 shape),
//!   - a real `AwaitSessionManagerImpl` oneshot resolution (HF-T04, SYS-J-05 shape).

use std::path::PathBuf;

use advance_reply_tracker::AwaitSessionManager;
use advance_shared_types::agent_tree::{AgentId, AgentKind};
use advance_shared_types::await_session::{
    AwaitMode, AwaitOptions, AwaitRequest, AwaitSessionStatus, ComponentAwaitRequest, ReplyResult,
    ReplyStatus, SessionId, TimeoutPolicy,
};
use cap_lifecycle::{SpawnChildConfig, Spawner};
use system_acceptance::{AgentSpec, Cap, SystemUnderTest};

const CORE_BYTES: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-j01-skeleton.core.wasm");

fn root_and_child() -> Vec<AgentSpec> {
    vec![
        AgentSpec {
            id: "agent:root".into(),
            kind: AgentKind::Root,
            parent: None,
            caps: vec![Cap::Fs],
            capabilities: vec![],
        },
        AgentSpec {
            id: "agent:c1".into(),
            kind: AgentKind::Child,
            parent: Some("agent:root".into()),
            caps: vec![],
            capabilities: vec![],
        },
    ]
}

#[tokio::test]
async fn agents_seeds_a_multi_node_tree() {
    let sut = SystemUnderTest::builder()
        .agents(&root_and_child())
        .build(CORE_BYTES)
        .await;
    let snap = sut.tree_snapshot();
    assert_eq!(snap.nodes.len(), 2, "seeded root + child");
    assert!(snap
        .nodes
        .iter()
        .any(|n| n.id.0 == "root" && n.parent.is_none()));
    assert!(snap
        .nodes
        .iter()
        .any(|n| n.id.0 == "c1" && n.parent.as_ref().map(|p| p.0.as_str()) == Some("root")));
}

#[tokio::test]
async fn spawn_child_mutates_the_real_tree() {
    let sut = SystemUnderTest::builder()
        .agents(&root_and_child())
        .build(CORE_BYTES)
        .await;
    let spawner = sut.spawner().expect(".agents() configured");

    spawner
        .spawn_child(SpawnChildConfig {
            parent_id: AgentId("root".into()),
            child_id: AgentId("gc1".into()),
            child_workspace_path: PathBuf::from("children/gc1"),
            capabilities: vec![],
            template_ref: None,
            binary: None,
        })
        .expect("spawn grandchild under root");

    let snap = sut.tree_snapshot();
    assert_eq!(snap.nodes.len(), 3, "root + c1 + spawned gc1");
    assert!(
        snap.nodes
            .iter()
            .any(|n| n.id.0 == "gc1" && n.parent.as_ref().map(|p| p.0.as_str()) == Some("root")),
        "spawned grandchild appears with parent=root"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn await_session_resolves_with_an_injected_reply() {
    let sut = SystemUnderTest::builder()
        .agents(&root_and_child())
        .build(CORE_BYTES)
        .await;
    let mgr = sut.await_manager().expect(".agents() configured");

    // ComponentFinished is dispatcher-free → start() parks on the oneshot rather
    // than hitting the all-failed fast path. Caller is BARE ("root", not "agent:root").
    let req = AwaitRequest::ComponentFinished(ComponentAwaitRequest {
        component_id: "comp1".into(),
        correlation_id: "corr1".into(),
    });
    let opts = AwaitOptions {
        mode: AwaitMode::AllOf,
        idle_timeout_secs: Some(3600),
        on_idle_timeout: TimeoutPolicy::ReturnPartial,
        keep_losers: false,
    };
    let start = tokio::spawn(async move { mgr.start("root", vec![req], opts).await });

    // First session id from the harness's deterministic factory is `hf-await-0`.
    // on_reply requires slot==0 + source=="component:<component_id>" exactly,
    // and ComponentFinished replies are status-only (empty payload).
    let reply = ReplyResult {
        slot: 0,
        source: "component:comp1".into(),
        payload: Vec::new(),
        status: ReplyStatus::Completed,
        received_at: chrono::Utc::now(),
        task_id: None,
    };
    sut.resolve_await(&SessionId("hf-await-0".into()), 0, reply)
        .await
        .expect("inject reply resolves the session");

    let result = start
        .await
        .expect("start task joined")
        .expect("await resolved Ok");
    assert_eq!(result.status, AwaitSessionStatus::Completed);
    assert_eq!(result.replies.len(), 1, "aggregated one reply");
    assert_eq!(result.replies[0].source, "component:comp1");
    assert_eq!(result.replies[0].status, ReplyStatus::Completed);
    assert!(
        result.replies[0].payload.is_empty(),
        "ComponentFinished reply stays status-only"
    );
}

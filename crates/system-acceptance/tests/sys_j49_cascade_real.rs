//! Stage-B — SYS-J-49 terminate-cascade observables (SYS-AC-156/248/249/250).
//!
//! Witnesses the REAL production terminate cascade driving the REAL cascade adapters
//! on a live Sub descendant — the previously-deferred multi-agent-wired-harness leg:
//!   - SYS-AC-156 — post-cascade the descendant's RUN is cancelled (run-status !=
//!     Active): a live run is seeded for the Sub, and after the cascade the run is the
//!     verbatim `TaskRunStatus::Cancelled(_)` variant (NOT a cooperative cancel_pending
//!     that leaves it Active), plus a real `run.cancelled` event.
//!   - SYS-AC-248 — post-cascade the descendant's mailbox is flushed (no deliverable
//!     messages remain).
//!   - SYS-AC-249 — post-cascade the descendant's own grants are revoked (a
//!     `grant.revoked` event with grantee == that agent).
//!   - SYS-AC-250 — terminating a Sub removes its `/.sub/{uuid}/` workspace directory
//!     from disk.
//!
//! Real, no-mock wiring: the harness `.agents()` substrate's REAL `DefaultSpawner` +
//! `AgentTreeStore`; `spawn_sub` materializes the Sub's real `.sub/<uuid>` dir on disk;
//! a REAL `GrantStore` (`.grant(GrantMode::Real)`, wired to the SAME event bus
//! `sut.events()` reads) + REAL `MailboxStore` (`sut.mailbox_store()`); and a REAL
//! `DefaultTerminateController` over ALL FOUR REAL cascade adapters
//! (`GrantRevokeCascade` / `MailboxFlushCascade` / `RunManagerCascade` /
//! `FsWorkspaceCleanup`) — NO `Noop*` stub. For SYS-AC-156 the `RunManagerCascade` is
//! constructed with a REAL `RunManager` on a CAPTURING bus, and a real run is seeded
//! for the descendant Sub BEFORE the cascade — so the rewired (2026-06-15) synchronous
//! agent-keyed `cancel_run_for_agent` forces that run to `Cancelled`, observable
//! immediately after `terminate_child` returns.
//!
//! Driven directly on the real controller (the `terminate-*` guest host-fn is
//! upstream-blocked for SYS-J-49) — the accepted Track-C witness bar already used by
//! SYS-AC-155/157/158 in `sys_j49_terminate_subtree.rs`. Every assertion binds to real
//! PRODUCT output: a real run forced to `Cancelled` + a real `run.cancelled` event, a
//! real `revoke_by_grantee`-emitted event, a real drained mailbox, a real removed dir.
//!
//! `#[tokio::test(flavor = "multi_thread")]` — the harness boots a real async EventBus /
//! dispatcher inside `.build()`.

use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use advance_run_manager::{RunConfig, RunManager};
use advance_shared_types::agent_tree::{AgentId, AgentKind, AgentTreeSnapshot};
use advance_shared_types::event::Event;
use advance_shared_types::mailbox::{Message, MessageKind};
use advance_shared_types::run::TaskRunStatus;
use advance_shared_types::traits::EventBusEmit;
use cap_grant::data::{
    CapParam, Grant, GrantId, GrantIssuer, GrantProvenance, GrantStatus, GrantTtl,
};
use cap_lifecycle::{
    DefaultTerminateController, FsWorkspaceCleanup, GrantRevokeCascade, MailboxFlushCascade,
    RunManagerCascade, SpawnSubConfig, Spawner, TerminateController,
};
use system_acceptance::{AgentSpec, Cap, GrantMode, SystemUnderTest};

const CORE_BYTES: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-j01-skeleton.core.wasm");

/// A capturing event sink for the cascade's REAL `RunManager`, so the
/// `run.cancelled` event the rewired forced cancel emits is observable (the SUT's
/// own bus does not carry this separately-constructed RunManager's events). The
/// adapter under test (`RunManagerCascade`) is the real production type, not a stub.
#[derive(Clone)]
struct CapturingBus {
    events: Arc<Mutex<Vec<Event>>>,
}
impl EventBusEmit for CapturingBus {
    fn emit(&self, event: Event) {
        self.events
            .lock()
            .expect("captured bus poisoned")
            .push(event);
    }
}

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
            caps: vec![Cap::Fs],
            capabilities: vec![],
        },
    ]
}

#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_156_248_249_250_terminate_cascade_real_adapters() {
    let sut = SystemUnderTest::builder()
        .agents(&root_and_child())
        .grant(GrantMode::Real)
        .build(CORE_BYTES)
        .await;

    let spawner = sut
        .spawner()
        .expect(".agents() configures the real spawner");
    let grant_store = sut
        .grant_store()
        .expect("GrantMode::Real configures the real grant store");
    let mailbox_store = sut.mailbox_store();
    // AgentTreeStore is Clone (shares its Arc<RwLock> inner) — the controller mutates
    // the SAME live store the spawner seeded.
    let store = spawner.tree().clone();

    // Spawn a REAL Sub under the Child → materializes <c1_ws>/.sub/<uuid> on disk +
    // a Sub node whose workspace_path is that path.
    let sub_id = spawner
        .spawn_sub(SpawnSubConfig {
            parent_id: AgentId("c1".to_string()),
            capabilities: vec![],
            template_ref: None,
        })
        .expect("spawn_sub under the child");
    let sub = sub_id.0.clone();

    // SYS-AC-250 precondition: capture the real /.sub/{uuid}/ workspace dir.
    let snap = store.snapshot();
    let sub_ws = snap
        .nodes
        .iter()
        .find(|n| n.id == sub_id)
        .expect("sub node present in the tree")
        .workspace_path
        .clone();
    assert!(
        sub_ws.exists(),
        "sub workspace materialized on disk pre-cascade: {}",
        sub_ws.display()
    );
    assert!(
        sub_ws.to_string_lossy().contains("/.sub/"),
        "sub workspace is the /.sub/{{uuid}}/ layout (not children/): {}",
        sub_ws.display()
    );

    // SYS-AC-248 precondition: seed the sub's mailbox with deliverable messages.
    let mb = mailbox_store
        .get_or_create(&sub)
        .expect("create sub mailbox");
    for i in 0..3 {
        mb.deliver(Message {
            id: format!("m-{i}"),
            kind: MessageKind::User,
            from: "tester".into(),
            to: sub.clone(),
            payload: format!("payload-{i}").into_bytes(),
            context: None,
            timestamp: SystemTime::now(),
            origin: None,
        })
        .expect("deliver to sub mailbox");
    }
    assert_eq!(
        mb.depth(),
        3,
        "sub mailbox holds 3 deliverable messages pre-cascade"
    );

    // SYS-AC-249 precondition: seed an ACTIVE grant whose grantee == the sub.
    grant_store
        .insert(Grant {
            id: GrantId::new(format!("grant-for-{sub}")),
            grantee: sub.clone(),
            capability: "fs".into(),
            params: vec![CapParam {
                key: "write-paths".into(),
                value: "[]".into(),
            }],
            ttl: GrantTtl::Lifecycle,
            issuer: GrantIssuer::Parent("c1".into()),
            provenance: GrantProvenance::Delegated(GrantId::new("seed-grant")),
            status: GrantStatus::Active,
            created_at: chrono::Utc::now(),
            expires_at: None,
        })
        .expect("insert active grant for the sub");

    // ── SYS-AC-156 precondition: a REAL live run for the descendant Sub ────────
    // The RunManager runs on a CAPTURING bus so its `run.cancelled` is observable.
    // ensure_run keys task_id == controller_agent == sub, so the rewired adapter's
    // `cancel_run_for_agent(sub)` resolves it via the controller_agent store scan.
    let captured = Arc::new(Mutex::new(Vec::<Event>::new()));
    let run_mgr = RunManager::new_arc(Arc::new(CapturingBus {
        events: captured.clone(),
    }));
    // Clone the Arc BEFORE moving the manager into the cascade, so we can read the
    // run's post-cascade status (the Sub's tree node is removed by the cascade, so
    // status must be read from the surviving RunManager handle, not the tree).
    let run_mgr_read = Arc::clone(&run_mgr);
    let run_id = run_mgr
        .ensure_run(&sub, &sub, RunConfig::default())
        .expect("ensure_run for the descendant sub");
    let run_id_str = run_id.to_string();
    assert!(
        matches!(
            run_mgr_read.snapshot_status_for_test(&run_id),
            Some(TaskRunStatus::Active)
        ),
        "SYS-AC-156 precondition: the seeded descendant run is Active pre-cascade; got {:?}",
        run_mgr_read.snapshot_status_for_test(&run_id)
    );

    // Build the REAL terminate cascade — ALL FOUR adapters real (no Noop). The
    // RunManagerCascade wraps the real RunManager carrying the seeded sub run.
    let controller = DefaultTerminateController::new(
        store.clone(),
        Arc::new(GrantRevokeCascade::new(Arc::clone(grant_store))),
        Arc::new(MailboxFlushCascade::new(Arc::clone(&mailbox_store))),
        Arc::new(RunManagerCascade::new(run_mgr)),
        Arc::new(FsWorkspaceCleanup::new(
            store.workspace_root().to_path_buf(),
        )),
    );

    // Drive the REAL cascade: the Child terminates its Sub child → post-order cascade
    // runs all four adapters on the sub (terminate.rs:215-232).
    controller
        .terminate_child("c1", &sub)
        .expect("terminate_child(c1, sub) ok");

    // ── SYS-AC-156 — descendant run forced to Cancelled (run-status != Active) ──
    let status_after = run_mgr_read.snapshot_status_for_test(&run_id);
    assert!(
        matches!(status_after, Some(TaskRunStatus::Cancelled(_))),
        "SYS-AC-156: descendant run force-settled to the Cancelled VARIANT post-cascade \
         (run-status != Active — a cooperative cancel_pending that left it Active would \
         be a fake-green); got {status_after:?}"
    );
    let cap = captured.lock().expect("captured bus poisoned");
    let cancelled: Vec<_> = cap
        .iter()
        .filter(|e| e.event_type == "run.cancelled")
        .collect();
    assert!(
        cancelled.iter().any(|e| {
            e.run_id.as_deref() == Some(run_id_str.as_str())
                && e.payload["reason"].as_str() == Some("terminate-cascade")
        }),
        "SYS-AC-156: a real run.cancelled event with run_id {run_id_str} + reason \
         'terminate-cascade'; got {:?}",
        cancelled
            .iter()
            .map(|e| (e.run_id.clone(), e.payload["reason"].clone()))
            .collect::<Vec<_>>()
    );
    drop(cap);

    // ── SYS-AC-248 — descendant mailbox flushed ────────────────────────────────
    let mb_after = mailbox_store
        .get(&sub)
        .expect("sub mailbox still registered (flush drains, does not remove)");
    assert_eq!(
        mb_after.depth(),
        0,
        "SYS-AC-248: sub mailbox flushed post-cascade (no deliverable messages remain)"
    );
    assert!(
        mb_after.poll().is_none(),
        "SYS-AC-248: no deliverable message remains after flush"
    );

    // ── SYS-AC-249 — descendant grant.revoked with grantee == that agent ───────
    let evs = sut.events();
    let revoked: Vec<_> = evs
        .iter()
        .filter(|e| e.event_type == "grant.revoked")
        .collect();
    assert!(
        revoked
            .iter()
            .any(|e| e.payload["grantee"].as_str() == Some(sub.as_str())),
        "SYS-AC-249: a real grant.revoked event carries grantee == sub ({sub}); got grantees {:?}",
        revoked
            .iter()
            .map(|e| e.payload["grantee"].clone())
            .collect::<Vec<_>>()
    );

    // ── SYS-AC-250 — Sub /.sub/{uuid}/ workspace dir removed from disk ─────────
    assert!(
        !sub_ws.exists(),
        "SYS-AC-250: sub /.sub/{{uuid}}/ workspace dir removed from disk: {}",
        sub_ws.display()
    );

    // Cascade integrity: the sub node is gone from the tree.
    assert!(
        !store.snapshot().nodes.iter().any(|n| n.id == sub_id),
        "sub node removed from the tree post-cascade"
    );
}

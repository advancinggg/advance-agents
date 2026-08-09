//! Track C — SYS-J-49 terminate witness: tree-state invariants only.
//!
//! Witnesses two SYS-AC against the REAL production cap-lifecycle providers
//! (no mock/stub of the module under test):
//!   - **SYS-AC-157** — a `spawn-child` under a FROZEN parent is rejected. The
//!     parent is frozen via the real `AgentTreeStore::set_status(parent,
//!     AgentStatus::Terminated)` (the same in-place status flip the production
//!     terminate-cascade's top-down freeze uses — `tree.rs:273-282`), reached
//!     through the harness `.agents()` substrate's real `DefaultSpawner` +
//!     `DefaultSpawner::tree()`. The subsequent real `DefaultSpawner::spawn_child`
//!     hits `insert_child`'s atomic frozen-parent guard (`tree.rs:179-184`) and
//!     surfaces `SpawnError::TreeStateInvalid` (the spawner re-wraps the
//!     `insert_child` failure as `TreeStateInvalid`, `spawn.rs:288-296`).
//!   - **SYS-AC-158** — `terminate_agent(caller, root_id)` on a Root node →
//!     `LifecycleError::PermissionDenied("Root agent cannot be terminated")`,
//!     driven through a real `DefaultTerminateController` over a real
//!     `AgentTreeStore` containing a Root node (`terminate.rs:236-273`, Root-deny
//!     pre-check at 253-256).
//!
//! REAL-PROVIDER witness (NOT a guest turn). The guest-driven
//! spawn/terminate→host loop is upstream-blocked (no `terminate-*` host fn drives
//! a guest turn yet; see the crate README "HF fast-follow blockers" + the
//! `mode_agents_smoke.rs` precedent), so — exactly as that HF-sanctioned smoke
//! does — these tests drive the real `DefaultSpawner` / `DefaultTerminateController`
//! / `AgentTreeStore` DIRECTLY from the test. That is the accepted Track-C
//! witness bar for these tree-state invariants.
//!
//! **SYS-AC-155 (lifecycle-harvest 2026-06-12) is NOW asserted below** via the
//! shared `lifecycle_support` Cap::Lifecycle fixture: `terminate-child` driven
//! through the production WIT dispatch on a live 2-level subtree → every
//! descendant absent from the post tree-snapshot + a `child-stats` lookup, AND
//! `lifecycle.terminate_child` (root) + `lifecycle.terminate_agent` (per
//! descendant) captured (the `wit_impl.rs` dispatch-arm emission landed this
//! slice; MODULE-005-AC-28).
//!
//! Deliberately NOT asserted (deferred legs — recorded in
//! `state.json.system_acceptance_deferred`, mirrored to SYSTEM-ACCEPTANCE.md §3):
//!   - **Remaining cascade observables** (SYS-AC-156/248/249/250):
//!     descendant-run cancellation, mailbox flush, `grant.revoked`, and
//!     Sub-workspace removal — the four cascade seams (`GrantCascadeRevoke` /
//!     `MailboxCascade` / `RunCascade` / `WorkspaceCleanup`) are satisfied by
//!     Ok-stub test impls here (their production adapters are wired/witnessed
//!     elsewhere — cascade_adapters.rs — or pending). SYS-AC-158's
//!     Root-deny path returns at `terminate.rs:253-256` BEFORE any cascade runs,
//!     so the no-op cascade impls defined below are NEVER invoked — supplying them
//!     is purely to satisfy `DefaultTerminateController::new`'s constructor
//!     signature and is NOT a witness-floor violation (no fake stands in for any
//!     code path the asserted criterion actually exercises).
//!   - This file uses `set_status(Terminated)` to freeze (the criterion's
//!     "FROZEN parent") rather than `terminate_child`, because `terminate_child`'s
//!     post-order cascade `tree.remove`s the parent itself — yielding
//!     `ParentNotFound` on a later spawn, a DIFFERENT state than the frozen-parent
//!     guard the criterion names.
//!
//! `#[tokio::test(flavor = "multi_thread")]` for the harness-backed 157 test
//! (the real async EventBus / dispatcher wiring boots inside `.build()`); 158
//! is sync-only and uses a plain `#[test]`.

use std::path::PathBuf;
use std::sync::Arc;

use advance_shared_types::agent_tree::{AgentId, AgentKind, AgentNode, AgentStatus, Capability};
use cap_lifecycle::{
    AgentTreeStore, DefaultTerminateController, GrantCascadeRevoke, LifecycleError, MailboxCascade,
    RunCascade, SpawnChildConfig, SpawnError, Spawner, TerminateController, WorkspaceCleanup,
};
use system_acceptance::{AgentSpec, Cap, SystemUnderTest};

const CORE_BYTES: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-j01-skeleton.core.wasm");

/// The `.agents()` seed used for 157: a Root + one Child. The harness derives
/// the BARE store ids (`root`, `c1`) from these canonical `agent:` ids and seeds
/// the real `AgentTreeStore` behind `sut.spawner()`.
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

// ---------------------------------------------------------------------------
// SYS-AC-157 — spawn-child under a FROZEN parent is rejected.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_157_spawn_under_frozen_parent_rejected() {
    let sut = SystemUnderTest::builder()
        .agents(&root_and_child())
        .build(CORE_BYTES)
        .await;

    // The harness `.agents()` substrate exposes the REAL `DefaultSpawner` over
    // the REAL bare-id `AgentTreeStore` (root + c1 already seeded). `DefaultSpawner::tree()`
    // hands back the same live store so we can freeze a node before spawning.
    let spawner = sut
        .spawner()
        .expect(".agents() configures the real spawner");
    let store = spawner.tree();

    let parent = AgentId("c1".to_string());

    // Sanity: parent starts Active (so the reject below is caused by the freeze,
    // not a pre-existing bad state). Spawning into an Active Child succeeds in
    // mode_agents_smoke; here we instead freeze first and assert the reject.
    assert!(store.contains(&parent), "c1 seeded into the real store");

    // Freeze the parent via the REAL in-place status flip — the same mutator the
    // production terminate-cascade top-down freeze drives (tree.rs:273-282).
    store
        .set_status(&parent, AgentStatus::Terminated)
        .expect("set_status(c1, Terminated) flips the live node");

    // Now drive the REAL spawner: spawn_child materializes the workspace then
    // calls insert_child, which hits the atomic frozen-parent guard
    // (tree.rs:179-184) and fails; spawn_child re-wraps that as TreeStateInvalid
    // (spawn.rs:288-296).
    let err = spawner
        .spawn_child(SpawnChildConfig {
            parent_id: parent.clone(),
            child_id: AgentId("gc_under_frozen".to_string()),
            child_workspace_path: PathBuf::from("children/gc_under_frozen"),
            capabilities: vec![],
            template_ref: None,
            binary: None,
        })
        .expect_err("spawn under a frozen (Terminated) parent must be rejected");

    match err {
        SpawnError::TreeStateInvalid(_) => {}
        other => {
            panic!("expected SpawnError::TreeStateInvalid (frozen-parent guard), got {other:?}")
        }
    }

    // The frozen subtree did not gain a node — the spawn was rejected atomically,
    // not partially applied. (Witness-floor: tree-state invariant only.)
    assert!(
        !store.contains(&AgentId("gc_under_frozen".to_string())),
        "rejected spawn left no node in the real store"
    );
}

// ---------------------------------------------------------------------------
// SYS-AC-158 — terminate_agent on a Root is permission-denied.
// ---------------------------------------------------------------------------

/// No-op `GrantCascadeRevoke`. NEVER invoked by 158 (Root-deny returns at
/// terminate.rs:253-256 BEFORE the cascade) — present only to satisfy
/// `DefaultTerminateController::new`'s signature. See the module docstring.
struct NoopGrantCascade;
impl GrantCascadeRevoke for NoopGrantCascade {
    fn revoke_for_agent(&self, _agent_id: &str) -> Result<(), LifecycleError> {
        Ok(())
    }
}

/// No-op `MailboxCascade` — see `NoopGrantCascade`.
struct NoopMailboxCascade;
impl MailboxCascade for NoopMailboxCascade {
    fn flush_mailbox(&self, _agent_id: &str) -> Result<(), LifecycleError> {
        Ok(())
    }
    fn notify_parent_crash(
        &self,
        _parent_id: &str,
        _child_id: &str,
        _reason: &str,
    ) -> Result<(), LifecycleError> {
        Ok(())
    }
}

/// No-op `RunCascade` — see `NoopGrantCascade`.
struct NoopRunCascade;
impl RunCascade for NoopRunCascade {
    fn ensure_run(&self, _agent_id: &str) -> Result<(), LifecycleError> {
        Ok(())
    }
    fn cancel_run(&self, _agent_id: &str) -> Result<(), LifecycleError> {
        Ok(())
    }
}

/// No-op `WorkspaceCleanup` — see `NoopGrantCascade`.
struct NoopWorkspaceCleanup;
impl WorkspaceCleanup for NoopWorkspaceCleanup {
    fn remove_sub_workspace(
        &self,
        _workspace_path: &std::path::Path,
    ) -> Result<(), LifecycleError> {
        Ok(())
    }
}

#[test]
fn sys_ac_158_terminate_agent_on_root_is_permission_denied() {
    // Build a REAL AgentTreeStore with a single Root node. The Root's
    // workspace_path must exist + canonicalize + lie under the (canonical)
    // store workspace_root, so create the dir on disk first.
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let store = AgentTreeStore::new(tmp.path().to_path_buf()).expect("agent tree store");
    let canonical_root = store.workspace_root().to_path_buf();

    let root_dir = canonical_root.join("root");
    std::fs::create_dir_all(&root_dir).expect("create root workspace dir");

    let root_id = AgentId("root".to_string());
    store
        .insert_root(AgentNode {
            id: root_id.clone(),
            kind: AgentKind::Root,
            parent: None,
            workspace_path: root_dir,
            capabilities: Vec::<Capability>::new(),
            template_ref: None,
            status: AgentStatus::Active,
        })
        .expect("insert Root node");

    // The REAL terminate controller over the real store. The four cascade seams
    // are no-op impls that 158 NEVER reaches (Root-deny pre-check fires first).
    let controller = DefaultTerminateController::new(
        store.clone(),
        Arc::new(NoopGrantCascade),
        Arc::new(NoopMailboxCascade),
        Arc::new(NoopRunCascade),
        Arc::new(NoopWorkspaceCleanup),
    );

    // Caller id is irrelevant to the Root-deny path (it returns before the
    // parent/caller check). Use the same id as the target for clarity.
    let err = controller
        .terminate_agent("root", "root")
        .expect_err("terminating a Root must be permission-denied");

    match err {
        LifecycleError::PermissionDenied(msg) => {
            assert!(
                msg.contains("Root agent cannot be terminated"),
                "expected the Root-deny message, got: {msg:?}"
            );
        }
        other => panic!(
            "expected LifecycleError::PermissionDenied (Root cannot be terminated), got {other:?}"
        ),
    }

    // Tree-state invariant: the Root is untouched (still present, still Active) —
    // the deny is fail-closed with no partial mutation.
    let node = store
        .get_node(&root_id)
        .expect("Root still present after deny");
    assert_eq!(
        node.status,
        AgentStatus::Active,
        "Root status unchanged by the denied terminate"
    );
    assert_eq!(node.kind, AgentKind::Root);
}

// ── SYS-AC-155 — lifecycle-harvest 2026-06-12 ───────────────────────────────
// terminate-child on a live 2-level subtree through the production WIT
// dispatch (shared lifecycle_support fixture): every descendant removed from
// the tree (post-snapshot + child-stats lookup) + lifecycle.terminate_child
// for the root + lifecycle.terminate_agent per descendant.

#[path = "lifecycle_support/mod.rs"]
mod lifecycle_support;

#[tokio::test]
async fn sys_ac_155_terminate_child_removes_subtree_and_emits_events() {
    use advance_shared_types::agent_tree::AgentTreeSnapshot;
    use wasmtime::component::Val;

    let fx = lifecycle_support::LifecycleFixture::new_with_root("root-a");
    fx.add_node("root-a", "child-a", AgentKind::Child);
    fx.add_node("child-a", "grand-1", AgentKind::Sub);
    fx.add_node("child-a", "grand-2", AgentKind::Child);

    let res = fx
        .call(
            "root-a",
            "terminate-child",
            vec![Val::String("child-a".into())],
        )
        .await
        .expect("terminate-child dispatch ok");
    assert!(
        matches!(&res[0], Val::Result(Ok(None))),
        "terminate-child ok: {:?}",
        res[0]
    );

    // Removal leg: child + every descendant absent from a subsequent snapshot.
    let snap = fx.tree.snapshot();
    for id in ["child-a", "grand-1", "grand-2"] {
        assert!(
            !snap.nodes.iter().any(|n| n.id.0 == id),
            "{id} absent from the post-terminate tree snapshot"
        );
    }
    // ...and from a child-stats lookup (the criterion's "self-stats lookup"
    // surface — driven through the same WIT dispatch; absent → not-found).
    let stats = fx
        .call("root-a", "child-stats", vec![Val::String("child-a".into())])
        .await
        .expect("child-stats dispatch ok");
    assert_eq!(
        lifecycle_support::err_variant_name(&stats[0]),
        "not-found",
        "terminated child absent from stats lookup"
    );

    // Event leg: terminate_child(root) + terminate_agent per descendant.
    let events = fx.events();
    let tc: Vec<_> = events
        .iter()
        .filter(|e| e.event_type == "lifecycle.terminate_child")
        .collect();
    assert_eq!(
        tc.len(),
        1,
        "exactly one lifecycle.terminate_child: {events:?}"
    );
    assert_eq!(tc[0].payload["initiator"], "root-a");
    assert_eq!(tc[0].payload["child_id"], "child-a");
    assert_eq!(tc[0].payload["reason"], "terminate-child");

    let ta: Vec<_> = events
        .iter()
        .filter(|e| e.event_type == "lifecycle.terminate_agent")
        .collect();
    assert_eq!(ta.len(), 2, "one lifecycle.terminate_agent per descendant");
    let by_id = |id: &str| {
        ta.iter()
            .find(|e| e.payload["agent_id"] == id)
            .unwrap_or_else(|| panic!("terminate_agent for {id}"))
    };
    assert_eq!(by_id("grand-1").payload["agent_kind"], "sub");
    assert_eq!(by_id("grand-1").payload["reason"], "cascade");
    assert_eq!(by_id("grand-2").payload["agent_kind"], "child");
    assert_eq!(by_id("grand-2").payload["reason"], "cascade");
    for e in &ta {
        assert_eq!(e.payload["initiator"], "root-a");
    }
}

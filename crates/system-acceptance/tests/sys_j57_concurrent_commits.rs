//! SYS-J-57 — two concurrent agents → serialized single-in-flight commits.
//!
//! Wired system (no module mocked): the `.agents([root, a, b])` multi-agent
//! substrate drives TWO production agent-loop drivers (one per child node, each
//! built with `build_agent_loop` + a `WasmMessageHandler` baked with the node's
//! canonical id) over the ONE shared `DefaultGitCommitQueue` + ONE cap-fs resolver
//! (`HarnessAgentTree`) the harness wires. Each `guest-rust-j01-skeleton` turn
//! performs one real `agent-fs::write` of `j01.txt` into its OWN distinct nested
//! territory; the queue worker emits `git.commit` (MODULE-003-AC-25) after each
//! successful commit, observable via `events()`.
//!
//! This file was previously a co-located blocker-spec (no live test) because the
//! harness was single-agent (`OneAgentTree`) and the `.agents()` HF primitive was
//! unbuilt. The primitive slice (GAP-1 populated `HarnessAgentTree::snapshot()`
//! ancestry maps, GAP-2 distinct on-disk territories, GAP-3 per-node run methods)
//! unblocks it.
//!
//! Witness discipline (binds to PRODUCT behavior, not harness-injected state):
//!   - SYS-AC-178: exactly TWO `git.commit` events, one per agent's handle-message,
//!     with DISTINCT initiators — plus a deletion control (run only A → exactly ONE
//!     commit), so a fabricated second commit cannot pass.
//!   - SYS-AC-179: the two commits' EVENT `affected_paths` are DISJOINT and each is
//!     rooted in its writer's DISTINCT territory (non-vacuous only because GAP-2
//!     gave distinct territories — with the old shared workspace both would collide
//!     on one path); the log is linear (no merge/octopus commit).
//!   - GAP-1 non-vacuity: a real `DefaultVirtualPathResolver` over the harness's own
//!     canonical `HarnessAgentTree` snapshot drives `resolve_child_read` (Ok) + the
//!     Rule-2 child-territory write-block (PermissionDenied) — an EMPTY `children_of`
//!     (the pre-GAP-1 state) would FAIL both.

use std::collections::BTreeSet;
use std::sync::Arc;

use advance_shared_types::agent_tree::{AgentKind, AgentTreeSnapshot};
use cap_fs::{DefaultVirtualPathResolver, FsError, VirtualPathResolver};
use system_acceptance::{AgentSpec, Cap, SystemUnderTest};

const J01_SKELETON: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-j01-skeleton.core.wasm");

/// root + two child writers A and B (canonical `agent:` ids). A and B are the
/// concurrent committers; root is the ancestor used for the GAP-1 non-vacuity legs.
fn root_a_b() -> Vec<AgentSpec> {
    vec![
        AgentSpec {
            id: "agent:root".into(),
            kind: AgentKind::Root,
            parent: None,
            caps: vec![Cap::Fs],
            capabilities: vec![],
        },
        AgentSpec {
            id: "agent:a".into(),
            kind: AgentKind::Child,
            parent: Some("agent:root".into()),
            caps: vec![Cap::Fs],
            capabilities: vec![],
        },
        AgentSpec {
            id: "agent:b".into(),
            kind: AgentKind::Child,
            parent: Some("agent:root".into()),
            caps: vec![Cap::Fs],
            capabilities: vec![],
        },
    ]
}

fn commit_event_paths(payload: &serde_json::Value) -> Vec<String> {
    payload["affected_paths"]
        .as_array()
        .expect("affected_paths array")
        .iter()
        .map(|v| v.as_str().expect("path is a string").to_string())
        .collect()
}

/// SYS-AC-178 + SYS-AC-179: two concurrent agents each commit exactly one turn
/// through the single-in-flight queue; the two commits are disjoint and linear.
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_178_179_two_agents_serialized_concurrent_commits() {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Fs])
        .agents(&root_a_b())
        .build(J01_SKELETON)
        .await;

    // Queue a turn for each child, then drive BOTH turns CONCURRENTLY so their
    // commit submissions genuinely race the one queue (serialization-under-
    // contention, not mere ordering). Each future borrows &self immutably and
    // runs on its own per-node driver/handler/guest-store.
    sut.inject_message_to("agent:a", "ext-a", b"sys-j57-a")
        .await;
    sut.inject_message_to("agent:b", "ext-b", b"sys-j57-b")
        .await;
    tokio::join!(sut.run_turn_for("agent:a"), sut.run_turn_for("agent:b"));

    // --- SYS-AC-178: exactly TWO git.commit events (no third, no merged) ---
    let commit_events: Vec<_> = sut
        .events()
        .into_iter()
        .filter(|e| e.event_type == "git.commit")
        .collect();
    assert_eq!(
        commit_events.len(),
        2,
        "exactly two git.commit events — one per agent's handle-message, no third/merged: {commit_events:?}"
    );
    for e in &commit_events {
        assert_eq!(
            e.payload["commit_type"], "turn",
            "each is a turn commit: {e:?}"
        );
    }

    // One commit per agent, with DISTINCT initiators. NOTE: `Adv003GitSync` builds
    // initiator = format!("agent:{ctx.agent_id}") and ctx.agent_id is the canonical
    // node id ("agent:a"), so the emitted initiator is DOUBLE-prefixed
    // "agent:agent:a" / "agent:agent:b". Assert the exact set (not == "agent:a",
    // and not .contains("a") — both ids contain 'a').
    let initiators: BTreeSet<String> = commit_events
        .iter()
        .map(|e| {
            e.payload["initiator"]
                .as_str()
                .expect("initiator string")
                .to_string()
        })
        .collect();
    let expected: BTreeSet<String> = ["agent:agent:a".to_string(), "agent:agent:b".to_string()]
        .into_iter()
        .collect();
    assert_eq!(
        initiators, expected,
        "one commit per agent, distinct (double-prefixed) initiators"
    );

    // --- SYS-AC-179: disjoint EVENT affected_paths, each rooted in its writer's
    // distinct territory; repo-relative; linear log ---
    let event_for = |init: &str| -> &serde_json::Value {
        &commit_events
            .iter()
            .find(|e| e.payload["initiator"] == init)
            .unwrap_or_else(|| panic!("a commit event for initiator {init}"))
            .payload
    };
    let a_paths = commit_event_paths(event_for("agent:agent:a"));
    let b_paths = commit_event_paths(event_for("agent:agent:b"));

    // Repo-relative (no absolute leak).
    for p in a_paths.iter().chain(b_paths.iter()) {
        assert!(!p.starts_with('/'), "repo-relative paths only: {p}");
    }
    // Each rooted in the writer's own DISTINCT nested territory.
    assert!(
        a_paths.iter().all(|p| p.starts_with("root/children/a/")),
        "A's affected_paths are all under its territory root/children/a/: {a_paths:?}"
    );
    assert!(
        b_paths.iter().all(|p| p.starts_with("root/children/b/")),
        "B's affected_paths are all under its territory root/children/b/: {b_paths:?}"
    );
    // The two commits' path SETS are DISJOINT (non-overlapping trees). This is the
    // assertion GAP-2 makes non-vacuous: with the old shared default_workspace both
    // agents would write the same `agent/j01.txt` → overlap → this would fail.
    let a_set: BTreeSet<&String> = a_paths.iter().collect();
    let b_set: BTreeSet<&String> = b_paths.iter().collect();
    assert!(
        a_set.is_disjoint(&b_set),
        "the two concurrent commits have disjoint affected_paths: A={a_paths:?} B={b_paths:?}"
    );
    // Each writer's own data file landed (same filename, distinct territory).
    assert!(
        a_paths.iter().any(|p| p.ends_with("j01.txt")),
        "A's turn wrote j01.txt: {a_paths:?}"
    );
    assert!(
        b_paths.iter().any(|p| p.ends_with("j01.txt")),
        "B's turn wrote j01.txt: {b_paths:?}"
    );

    // Linear log: exactly two turn commits, none a merge (the single-in-flight
    // queue serializes — `bootstrap_repo_at` leaves an unborn HEAD, so the first
    // (root) turn commit has parent_count 0 and the second has 1; a merge would be
    // >= 2). turn_commits() walks the first-parent chain from HEAD, so len == 2
    // confirms the two commits form a single line, not two siblings.
    let commits = sut.turn_commits();
    assert_eq!(
        commits.len(),
        2,
        "two commits on a single first-parent chain: {commits:?}"
    );
    for c in &commits {
        assert!(c.is_turn, "each is a [turn] commit: {c:?}");
        assert!(
            c.parent_count <= 1,
            "linear log — no merge/octopus commit (parent_count <= 1): {c:?}"
        );
    }

    // SYS-AC-179 "non-overlapping trees / no corruption" at the committed-TREE
    // level (not just the per-commit affected_paths delta): the HEAD commit's tree
    // (cumulative recursive blob walk) contains BOTH writers' real files at their
    // DISTINCT territory paths — both writes landed un-corrupted on disjoint
    // subtrees, neither clobbering the other. commits[0] is HEAD (the 2nd commit,
    // whose tree includes the 1st commit's file); order-independent under the race.
    let head_tree = &commits[0].tree_paths;
    assert!(
        head_tree.iter().any(|p| p == "root/children/a/j01.txt"),
        "final committed tree contains A's file at its own territory path: {head_tree:?}"
    );
    assert!(
        head_tree.iter().any(|p| p == "root/children/b/j01.txt"),
        "final committed tree contains B's file at its own territory path: {head_tree:?}"
    );
}

/// SYS-AC-178 deletion control: with only ONE agent's turn driven, exactly ONE
/// `git.commit` is emitted. This proves the second commit in the main test is
/// caused by B's handle-message (not fabricated) — removing B's turn drops it.
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_178_single_agent_turn_yields_exactly_one_commit() {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Fs])
        .agents(&root_a_b())
        .build(J01_SKELETON)
        .await;

    sut.inject_message_to("agent:a", "ext-a", b"sys-j57-a-only")
        .await;
    sut.run_turn_for("agent:a").await;

    let commit_events: Vec<_> = sut
        .events()
        .into_iter()
        .filter(|e| e.event_type == "git.commit")
        .collect();
    assert_eq!(
        commit_events.len(),
        1,
        "exactly one git.commit when only A's turn runs (the 2nd commit is caused by B, not fabricated): {commit_events:?}"
    );
    assert_eq!(
        commit_events[0].payload["initiator"], "agent:agent:a",
        "the single commit is attributed to A: {:?}",
        commit_events[0].payload
    );
}

/// SYS-AC-178 "serialized in a DETERMINISTIC order" clause. The concurrent test
/// (above) proves serialization-under-contention but tolerates either commit order
/// (a true race has no stable winner). This test pins the *deterministic* half: the
/// single-in-flight queue commits in SUBMISSION order, so driving A's turn fully
/// then B's turn yields git.commit events emitted deterministically [A, B] (and the
/// reverse drive would yield [B, A]) — the order is a deterministic function of the
/// submission sequence, never interleaved.
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_178_serialized_commit_order_is_deterministic_when_sequenced() {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Fs])
        .agents(&root_a_b())
        .build(J01_SKELETON)
        .await;

    // Sequential, awaited in order: A's full turn (commit) THEN B's full turn.
    sut.inject_message_to("agent:a", "ext-a", b"seq-a").await;
    sut.run_turn_for("agent:a").await;
    sut.inject_message_to("agent:b", "ext-b", b"seq-b").await;
    sut.run_turn_for("agent:b").await;

    let commit_events: Vec<_> = sut
        .events()
        .into_iter()
        .filter(|e| e.event_type == "git.commit")
        .collect();
    assert_eq!(commit_events.len(), 2, "two commits: {commit_events:?}");
    // git.commit events are captured in emission order; the serialized queue
    // commits A (submitted first) before B → deterministic [A, B].
    assert_eq!(
        commit_events[0].payload["initiator"], "agent:agent:a",
        "A (submitted first) commits first — deterministic serialized order"
    );
    assert_eq!(
        commit_events[1].payload["initiator"], "agent:agent:b",
        "B (submitted second) commits second"
    );
    // The git log reflects the same total order: HEAD is the newest (B's) commit,
    // its first-parent chain leads back through A's (root) commit — a single line.
    let commits = sut.turn_commits();
    assert_eq!(commits.len(), 2, "linear two-commit chain: {commits:?}");
    assert!(
        commits.iter().all(|c| c.parent_count <= 1),
        "no merge in the deterministic chain: {commits:?}"
    );
}

/// GAP-1 non-vacuity (underpins SYS-AC-179): the harness's own canonical
/// `HarnessAgentTree` snapshot now populates `children_of`, so a real
/// `DefaultVirtualPathResolver` over it grants the parent a cross-territory READ
/// of the child (`resolve_child_read` → Ok) and DENIES a parent WRITE into the
/// child's territory (Rule-2 → PermissionDenied). With the pre-GAP-1 empty maps
/// the first would NotFound and the second would be allowed — so this test fails
/// if GAP-1 regresses.
#[tokio::test(flavor = "multi_thread")]
async fn gap1_harness_snapshot_drives_child_read_and_rule2_write_block() {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Fs])
        .agents(&root_a_b())
        .build(J01_SKELETON)
        .await;

    // Run A's real turn so j01.txt exists inside A's territory (proves the
    // territory is a real, agent-writable dir — not just a registered path).
    sut.inject_message_to("agent:a", "ext-a", b"seed-a").await;
    sut.run_turn_for("agent:a").await;

    // Build a REAL DefaultVirtualPathResolver over the harness's canonical
    // HarnessAgentTree snapshot (the SAME provider wired into the fs host fns).
    let tree_snap: Arc<dyn AgentTreeSnapshot> = sut
        .harness_agent_tree()
        .expect(".agents() set → canonical tree retained");
    let resolver = DefaultVirtualPathResolver::new(sut.workspace_root().to_path_buf(), tree_snap);

    // --- resolve_child_read: ROOT may read inside A's territory (Rule 2 read) ---
    // Canonical ids: a bare id would silently NotFound (the map is canonical-keyed).
    let child_path = resolver
        .resolve_child_read("agent:root", "agent:a", "j01.txt")
        .expect("populated children_of → parent reads inside child territory (Rule 2)");
    assert!(
        child_path.ends_with("root/children/a/j01.txt"),
        "resolved into A's distinct territory: {}",
        child_path.display()
    );
    assert!(
        std::fs::read(&child_path).is_ok(),
        "the resolved child-territory path is the real file A's turn wrote"
    );

    // --- Rule-2 child-territory write-block: ROOT write into A's territory denied ---
    // From root's own territory, `children/a/evil.txt` resolves under A's
    // registered (nested) workspace_path → PermissionDenied. Empty children_of
    // would make this block dead → the write would be ALLOWED.
    let err = resolver
        .resolve_write("agent:root", "children/a/evil.txt")
        .expect_err("populated children_of → Rule-2 denies parent write into child territory");
    assert!(
        matches!(err, FsError::PermissionDenied(_)),
        "expected FsError::PermissionDenied (Rule-2 child-territory overlap), got {err:?}"
    );
}

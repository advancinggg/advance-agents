//! Track C — SYS-J-07 witness: spawn-child workspace materialization + tree node,
//! plus the parent⇄child territory access rules (read-allowed, write-denied).
//!
//! Witnesses three SYS-AC end-to-end against the REAL production providers — NOT a
//! guest turn (the guest spawn→child-reply→parent-resume loop is upstream-blocked;
//! see the crate README "HF fast-follow blockers" + `mode_agents_smoke.rs`). Per the
//! HF-sanctioned `.agents()` pattern, the test drives the real providers DIRECTLY:
//!
//!   - **SYS-AC-019** (spawn-child → `.agent/` workspace + tree node): the harness's
//!     real `cap_lifecycle::DefaultSpawner` (`sut.spawner()`) runs `spawn_child`, which
//!     calls the real `init_child_workspace` (`cap-lifecycle/src/workspace.rs:170-250`)
//!     to materialize the child's `.agent/` skeleton on disk and `insert_child` into the
//!     real bare-id `AgentTreeStore`. We witness BOTH legs: the on-disk
//!     `<child_ws>/.agent/config.yaml` (read via `std::fs` over the canonical child
//!     `workspace_path` from the snapshot) AND the new tree node `gc1` with parent
//!     `root` (`sut.tree_snapshot()`).
//!
//!   - **SYS-AC-020** (parent reads child territory, read-only — Rule 2): a real
//!     `cap_fs::DefaultVirtualPathResolver` built over the SAME real `AgentTreeStore`
//!     the spawner mutated (it implements `AgentTreeSnapshot` with populated
//!     `children_of`, `tree.rs:430-458`) resolves `resolve_child_read(root, gc1, file)`
//!     → `Ok(physical)` pointing inside gc1's territory (`resolver.rs:395-441`).
//!
//!   - **SYS-AC-021** (parent write into child territory → PermissionDenied — Rule 2):
//!     the same real resolver's `resolve_write(root, "children/gc1/<file>")` →
//!     `Err(FsError::PermissionDenied)` because the path resolves under a registered
//!     child's `workspace_path` (`resolver.rs:362-373`, the Rule-2 overlap denial).
//!
//! Provider-reuse note (witness-floor): the resolver is constructed in-test, but it is
//! the REAL `DefaultVirtualPathResolver` wired over the REAL `AgentTreeStore` that the
//! REAL `DefaultSpawner` just mutated — no module in the chain is mocked/stubbed. The
//! spawn → store → snapshot → resolver path is end-to-end real. (Reusing the
//! spawner's `AgentTreeStore::snapshot` is the faithful real source here because it
//! is the store the spawner just MUTATED — it reflects the runtime `spawn_child` of
//! `gc1`, which the harness's static `HarnessAgentTree` (seeded from the initial
//! `.agents([...])` specs) does not. As of the SYS-J-57 primitive slice
//! `HarnessAgentTree::snapshot()` DOES populate `children_of` for its declared
//! tree — see `sys_j57_concurrent_commits.rs` — but that static tree still wouldn't
//! show a runtime-spawned node, so the spawner's store remains the correct source
//! for THIS test per the plan's J-07 design + the `cap-fs resolver.rs` contract.)
//!
//! Scope discipline — deliberately NOT asserted here (recorded deferrals, see plan
//! `## Test-case design` + SYSTEM-ACCEPTANCE.md §3):
//!   - SYS-AC-196 (spawn-child <500ms perf-SLO) — unreliable under the shared
//!     disk-pressured parallel-worktree CI; deferred (env), not a correctness leg.
//!   - The guest-driven spawn-child host fn + child-reply→parent-resume loop is the
//!     upstream-blocked surface (no `send` host fn); this file witnesses the provider
//!     primitives only, exactly as `mode_agents_smoke.rs` does.

use std::path::PathBuf;
use std::sync::Arc;

use advance_shared_types::agent_tree::{AgentId, AgentKind, AgentTreeSnapshot};
use cap_fs::{DefaultVirtualPathResolver, FsError, VirtualPathResolver};
use cap_lifecycle::{SpawnChildConfig, Spawner};
use system_acceptance::{AgentSpec, Cap, SystemUnderTest};

const CORE_BYTES: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-j01-skeleton.core.wasm");

/// A single-root `.agents([...])` tree. The harness seeds `root` at
/// `<canonical_root>/root`; the test spawns `gc1` under it.
fn root_only() -> Vec<AgentSpec> {
    vec![AgentSpec {
        id: "agent:root".into(),
        kind: AgentKind::Root,
        parent: None,
        caps: vec![Cap::Fs],
        capabilities: vec![],
    }]
}

/// SYS-AC-019: a real `spawn_child` materializes the child's `.agent/config.yaml`
/// on disk AND inserts a `gc1` node (parent=`root`) into the real `AgentTreeStore`.
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_019_spawn_child_materializes_workspace_and_tree_node() {
    let sut = SystemUnderTest::builder()
        .agents(&root_only())
        .build(CORE_BYTES)
        .await;
    let spawner = sut.spawner().expect(".agents() configured");

    let child = spawner
        .spawn_child(SpawnChildConfig {
            parent_id: AgentId("root".into()),
            child_id: AgentId("gc1".into()),
            child_workspace_path: PathBuf::from("children/gc1"),
            capabilities: vec![],
            template_ref: None,
            binary: None,
        })
        .expect("spawn child gc1 under root");
    assert_eq!(child.0, "gc1", "spawn_child returns the new child id");

    // --- tree-node leg: gc1 appears with parent=root in the REAL store snapshot ---
    let snap = sut.tree_snapshot();
    let gc1 = snap
        .nodes
        .iter()
        .find(|n| n.id.0 == "gc1")
        .expect("gc1 node present in the spawn-witness store");
    assert_eq!(
        gc1.parent.as_ref().map(|p| p.0.as_str()),
        Some("root"),
        "gc1's parent is root"
    );
    assert_eq!(gc1.kind, AgentKind::Child, "spawn_child registers a Child");
    assert!(
        snap.children_of
            .get(&AgentId("root".into()))
            .map(|kids| kids.iter().any(|c| c.0 == "gc1"))
            .unwrap_or(false),
        "children_of[root] contains gc1 (real insert_child)"
    );

    // --- on-disk leg: init_child_workspace wrote `.agent/config.yaml` under the
    // child's canonical territory. Use the snapshot's canonical workspace_path (NOT
    // sut.workspace_root(), which on macOS is the un-canonicalized /var alias). ---
    let child_ws = &gc1.workspace_path;
    let config = child_ws.join(".agent").join("config.yaml");
    assert!(
        config.is_file(),
        "spawn_child materialized {} on disk",
        config.display()
    );
    let body = std::fs::read_to_string(&config).expect("read child .agent/config.yaml");
    assert!(
        body.contains("kind: \"child\""),
        "config.yaml records the Child kind (init_child_workspace): {body:?}"
    );
    // The full Slice-A skeleton is present.
    assert!(
        child_ws.join(".agent").join("AGENTS.md").is_file(),
        "child .agent/AGENTS.md materialized"
    );
    assert!(
        child_ws.join(".agent").join("skills").is_dir(),
        "child .agent/skills/ materialized"
    );
}

/// SYS-AC-020 + SYS-AC-021: the parent (`root`) can READ inside the child's
/// territory (Rule 2, read-only) but a WRITE into the child's territory is denied.
/// Driven through the REAL `DefaultVirtualPathResolver` over the REAL `AgentTreeStore`
/// the spawner mutated.
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_020_021_parent_reads_child_but_write_is_denied() {
    let sut = SystemUnderTest::builder()
        .agents(&root_only())
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
        .expect("spawn child gc1 under root");

    // Real resolver wired over the REAL store the spawner just mutated. `AgentTreeStore`
    // is `Clone` (Arc-backed inner) and implements `AgentTreeSnapshot` with populated
    // `children_of` (tree.rs:430-458) — the faithful real territory source.
    let store = spawner.tree().clone();
    let canonical_root = store.workspace_root().to_path_buf();
    let tree_snap: Arc<dyn AgentTreeSnapshot> = Arc::new(store);
    let resolver = DefaultVirtualPathResolver::new(canonical_root, tree_snap);

    // Seed a real file inside gc1's territory so the parent-read resolves to an
    // existing, readable physical path (the snapshot's workspace_path is canonical).
    let snap = sut.tree_snapshot();
    let gc1_ws = snap
        .nodes
        .iter()
        .find(|n| n.id.0 == "gc1")
        .expect("gc1 in store")
        .workspace_path
        .clone();
    let child_note = gc1_ws.join("note.txt");
    std::fs::write(&child_note, b"child-owned content").expect("seed child note.txt");

    // --- SYS-AC-020: parent (root) reads inside the child (gc1) territory → Ok ---
    let read_path = resolver
        .resolve_child_read("root", "gc1", "note.txt")
        .expect("Rule 2: parent may read inside child territory");
    assert_eq!(
        read_path, child_note,
        "resolve_child_read returns the child-territory physical path"
    );
    assert_eq!(
        std::fs::read_to_string(&read_path).expect("read resolved child path"),
        "child-owned content",
        "the resolved path is the real child-owned file (read-only access witnessed)"
    );
    // Read-only premise corroborated: child_read resolves INTO the child's own
    // territory (gc1's workspace_path), the cross-territory read Rule 2 grants.
    assert!(
        read_path.starts_with(&gc1_ws),
        "the read target {} is inside the child's territory {}",
        read_path.display(),
        gc1_ws.display()
    );

    // --- SYS-AC-021: parent (root) WRITE into the child territory → PermissionDenied ---
    // From root's own workspace, "children/gc1/<file>" resolves under gc1's
    // registered workspace_path → the Rule-2 child-territory overlap denial.
    let err = resolver
        .resolve_write("root", "children/gc1/evil.txt")
        .expect_err("Rule 2: parent write into child territory must be denied");
    assert!(
        matches!(err, FsError::PermissionDenied(_)),
        "expected FsError::PermissionDenied (Rule 2 child-territory overlap), got {err:?}"
    );
}

//! MODULE-011 Wave-9 Lane B — cli L6 `StalenessProbe` production-wiring witnesses.
//!
//! The lane builds the real MODULE-002-blob-backed staleness probe; a later harvest
//! flips SYS-AC-069. These tests gate via `cargo test` (the lane flips no AC):
//!
//! - W3: the causal probe — `GitBlobFileResolver` over a REAL `DefaultVirtualPathResolver`
//!   + a real on-disk file + the real `advance_git::blob_oid_of_file` → `run_stale_detection`
//!   judges the file-ref Valid (present), Stale (gone), Stale (superseded), Stale (escaping
//!   vpath fail-safe).
//! - W5: `build_l6_stale_resolver` — Some(tree) resolves a real OID; None → `EmptyAgentTree`
//!   → None.
//! - W6: the `attach_l6_with_stale_resolver` `Some`-arm END-TO-END — drive a real L6 run via
//!   the returned `Components.l6_handler.dispatch(..)` and assert the file-ref entry is NOT
//!   orphaned under the real probe vs ORPHANED under the empty stub (the production
//!   substitution the start.rs git-queue branch performs).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use advance_cli::l6_wiring::{
    attach_l6_with_stale_resolver, build_l6_stale_resolver, GitBlobFileResolver,
};
use advance_git::{blob_oid_of_file, bootstrap_repo_at, DefaultGitCommitQueue, GitCommitQueue};
use advance_shared_types::agent_tree::{
    AgentId, AgentKind, AgentNode, AgentStatus, AgentTreeReader, AgentTreeSnapshot,
    AgentTreeSnapshotData, Capability,
};

use cap_fs::{DefaultVirtualPathResolver, VirtualPathResolver};
use cap_memory::clock::MutableClock;
use cap_memory::knowledge::{MemoryEntry, MemorySource, MemoryStatus, MemoryType};
use cap_memory::l6::{
    run_stale_detection, FileBlobResolver, ResolverStalenessProbe, StubL6Classifier,
};
use cap_memory::store::MemoryStore;
use cap_memory::{
    Components, FailureCooldown, InMemorySimilarityIndex, LeaseDecision, Reconciler,
    StubBatchExtractor, DEFAULT_THRESHOLD,
};

fn t0() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000)
}

/// Minimal `AgentTreeSnapshot` fixture: maps a single agent id → a territory dir.
/// `resolve_read` only consults `snapshot()` (`n.id.0 == agent_id` → `workspace_path`),
/// so the other 6 `AgentTreeReader` methods return defaults.
struct TestTree {
    agent_id: String,
    territory: PathBuf,
}

impl TestTree {
    fn new(agent_id: &str, territory: PathBuf) -> Self {
        Self {
            agent_id: agent_id.to_string(),
            territory,
        }
    }
}

impl AgentTreeReader for TestTree {
    fn parent_of(&self, _agent_id: &str) -> Option<String> {
        None
    }
    fn children_of(&self, _agent_id: &str) -> Vec<String> {
        vec![]
    }
    fn siblings_of(&self, _agent_id: &str) -> Vec<String> {
        vec![]
    }
    fn agent_exists(&self, agent_id: &str) -> bool {
        agent_id == self.agent_id
    }
    fn agent_kind(&self, agent_id: &str) -> Option<AgentKind> {
        (agent_id == self.agent_id).then_some(AgentKind::Root)
    }
    fn capabilities(&self, _agent_id: &str) -> Vec<Capability> {
        vec![]
    }
}

impl AgentTreeSnapshot for TestTree {
    fn snapshot(&self) -> AgentTreeSnapshotData {
        // `resolve_read` only consults `nodes` (matches `n.id.0 == agent_id` →
        // `workspace_path`); the HashMap projections are unused by the staleness path.
        AgentTreeSnapshotData {
            nodes: vec![AgentNode {
                id: AgentId(self.agent_id.clone()),
                kind: AgentKind::Root,
                parent: None,
                workspace_path: self.territory.clone(),
                capabilities: vec![],
                template_ref: None,
                status: AgentStatus::Active,
            }],
            parent_of: std::collections::HashMap::new(),
            children_of: std::collections::HashMap::new(),
            peer_slug_map: std::collections::HashMap::new(),
            revision: 0,
        }
    }
}

/// A file-ref-sourced fact for "agent:r" carrying an explicit `blob_id`.
fn file_ref_fact(id: &str, vpath: &str, blob_id: &str) -> MemoryEntry {
    MemoryEntry {
        id: id.into(),
        agent_id: "agent:r".into(),
        entry_type: MemoryType::Fact,
        content: "rust is memory safe and fast".into(),
        tags: vec!["pricing".into()],
        created_at: "2026-01-01T00:00:00Z".into(),
        task_origin: None,
        is_active: true,
        superseded_by: None,
        status: MemoryStatus::Active,
        supersession_reason: None,
        cluster_id: None,
        sources: vec![MemorySource::FileRef {
            agent_id: "agent:r".into(),
            vpath: vpath.into(),
            commit_ish: "working-tree".into(),
            blob_id: blob_id.into(),
            line_range: None,
        }],
    }
}

/// A task-turn-sourced fact (no file-ref) so a cluster reaches ≥3 members.
fn task_turn_fact(id: &str) -> MemoryEntry {
    MemoryEntry {
        id: id.into(),
        agent_id: "agent:r".into(),
        entry_type: MemoryType::Fact,
        content: "rust is memory safe and fast".into(),
        tags: vec!["pricing".into()],
        created_at: "2026-01-01T00:00:00Z".into(),
        task_origin: None,
        is_active: true,
        superseded_by: None,
        status: MemoryStatus::Active,
        supersession_reason: None,
        cluster_id: None,
        sources: vec![MemorySource::TaskTurn {
            task_id: "task-1".into(),
            turn: 1,
        }],
    }
}

// ──────────────────────────────── W3 ────────────────────────────────

#[test]
fn w3_git_blob_resolver_causal_valid_stale_superseded_escaping() {
    let td = tempfile::tempdir().unwrap();
    let territory = td.path().to_path_buf();
    std::fs::create_dir_all(territory.join("data")).unwrap();
    let file = territory.join("data/e1.csv");
    std::fs::write(&file, b"col_a,col_b\n1,2\n").unwrap();
    let oid = blob_oid_of_file(&file).expect("the real file hashes");

    let tree = Arc::new(TestTree::new("agent:r", territory.clone()));
    let resolver: Arc<dyn VirtualPathResolver> =
        Arc::new(DefaultVirtualPathResolver::new(territory.clone(), tree));
    let probe = ResolverStalenessProbe::new(Arc::new(GitBlobFileResolver::new(resolver)));

    // Valid (positive leg, explicitly asserted): the stored blob equals the current blob.
    let store = MemoryStore::new();
    store
        .insert("agent:r", file_ref_fact("e1", "data/e1.csv", &oid))
        .unwrap();
    let r = run_stale_detection(&store, "agent:r", &probe);
    assert_eq!(
        r.valid_ids,
        vec!["e1".to_string()],
        "a file-ref whose blob still resolves is Valid (synthesis-eligible)"
    );
    assert!(r.stale_ids.is_empty());

    // Stale (gone): delete the file.
    std::fs::remove_file(&file).unwrap();
    let r = run_stale_detection(&store, "agent:r", &probe);
    assert_eq!(r.stale_ids, vec!["e1".to_string()], "a gone file is Stale");
    assert!(r.valid_ids.is_empty());

    // Stale (superseded): recreate with DIFFERENT content → a different blob.
    std::fs::write(&file, b"totally different content\n").unwrap();
    let r = run_stale_detection(&store, "agent:r", &probe);
    assert_eq!(
        r.stale_ids,
        vec!["e1".to_string()],
        "a superseded (different-blob) file is Stale"
    );

    // Stale (escaping vpath fail-safe): a `..`-traversal vpath → resolve_read reject →
    // current_blob None → not-resolved → Stale (never falsely Valid).
    let store2 = MemoryStore::new();
    store2
        .insert("agent:r", file_ref_fact("esc", "../escape.csv", &oid))
        .unwrap();
    let r = run_stale_detection(&store2, "agent:r", &probe);
    assert_eq!(
        r.stale_ids,
        vec!["esc".to_string()],
        "an escaping vpath is rejected by resolve_read → Stale (conservative fail-safe)"
    );
}

// ──────────────────────────────── W5 ────────────────────────────────

#[test]
fn w5_build_l6_stale_resolver_some_resolves_none_empty_tree() {
    let td = tempfile::tempdir().unwrap();
    let territory = td.path().to_path_buf();
    std::fs::create_dir_all(territory.join("data")).unwrap();
    let file = territory.join("data/e1.csv");
    std::fs::write(&file, b"hello\n").unwrap();
    let oid = blob_oid_of_file(&file).unwrap();

    // Some(tree): the production helper resolves the real on-disk blob.
    let tree = Arc::new(TestTree::new("agent:r", territory.clone()));
    let r_some = build_l6_stale_resolver(territory.clone(), Some(tree));
    assert_eq!(
        r_some.current_blob("agent:r", "data/e1.csv"),
        Some(oid),
        "Some(tree) → resolves the real current blob"
    );

    // None → EmptyAgentTree → every resolve_read NotFound → None (conservative Stale path).
    let r_none = build_l6_stale_resolver(territory.clone(), None);
    assert_eq!(
        r_none.current_blob("agent:r", "data/e1.csv"),
        None,
        "None → EmptyAgentTree → no node maps agent:r → None"
    );
}

// ──────────────────────────────── W6 ────────────────────────────────

/// Drive a real L6 run through `attach_l6_with_stale_resolver` and return the persisted
/// status of the file-ref entry `e1` after Step-5b. `with_real_resolver` selects the
/// `Some`-arm (real `ResolverStalenessProbe`) vs the `None`-arm (empty `InMemoryStalenessProbe`).
/// Step-5b's `mark_orphaned` over `stale_ids` runs (and persists) before the git commit and
/// is not rolled back, so the status discriminator holds regardless of the commit outcome.
async fn e1_status_after_l6(with_real_resolver: bool) -> MemoryStatus {
    let td = tempfile::tempdir().unwrap();
    let workdir = td.path().to_path_buf();
    bootstrap_repo_at(&workdir).unwrap();
    // Territory == the git workdir; the file-ref resolves under it.
    std::fs::create_dir_all(workdir.join("data")).unwrap();
    let file = workdir.join("data/e1.csv");
    std::fs::write(&file, b"col_a,col_b\n1,2\n").unwrap();
    let oid = blob_oid_of_file(&file).expect("real file hashes");

    // Store: a ≥3-member consistent cluster; e1 carries the real-blob file-ref.
    let store = Arc::new(MemoryStore::new());
    store
        .insert("agent:r", file_ref_fact("e1", "data/e1.csv", &oid))
        .unwrap();
    store.insert("agent:r", task_turn_fact("e2")).unwrap();
    store.insert("agent:r", task_turn_fact("e3")).unwrap();

    // Components::with_l6_defaults (the dispatch path ignores extractor/reconciler/cooldown).
    let extractor = Arc::new(StubBatchExtractor::with_extraction(Default::default()));
    let reconciler =
        Reconciler::from_concrete(Arc::new(InMemorySimilarityIndex::new()), DEFAULT_THRESHOLD);
    let cooldown = Arc::new(FailureCooldown::new(600));
    let clock = Arc::new(MutableClock::new(t0()));
    let components =
        Components::with_l6_defaults(extractor, reconciler, Arc::clone(&store), cooldown, clock);

    // Seed the shared lease (the runnable shares components.lease via attach).
    let tok = match components
        .lease
        .begin_acquire("agent:r", t0(), Duration::from_secs(600))
    {
        LeaseDecision::Acquired { token } => token,
        other => panic!("expected Acquired, got {other:?}"),
    };
    assert!(components.lease.confirm_acquire("agent:r", &tok));

    let git_queue: Arc<dyn GitCommitQueue> =
        Arc::new(DefaultGitCommitQueue::spawn(workdir.clone()).unwrap());
    let mem_root = workdir.join(".agent").join("memory");

    let stale_resolver: Option<Arc<dyn FileBlobResolver>> = if with_real_resolver {
        let tree = Arc::new(TestTree::new("agent:r", workdir.clone()));
        let vpr: Arc<dyn VirtualPathResolver> =
            Arc::new(DefaultVirtualPathResolver::new(workdir.clone(), tree));
        Some(Arc::new(GitBlobFileResolver::new(vpr)))
    } else {
        None
    };

    let classifier: Arc<dyn cap_memory::l6::L6Classifier + Send + Sync> =
        Arc::new(StubL6Classifier::new());
    let components = attach_l6_with_stale_resolver(
        components,
        classifier,
        git_queue,
        workdir.clone(),
        mem_root,
        stale_resolver,
    );

    // Drive the in-process L6 dispatch (the production Step-9 path).
    let handler = components
        .l6_handler
        .as_ref()
        .expect("attach set l6_handler");
    let _ran = handler.dispatch("agent:r", &tok).await;

    store.get("agent:r", "e1").expect("e1 still present").status
}

// W6 Some-arm: the real `ResolverStalenessProbe` judges e1 Valid → NOT orphaned.
#[tokio::test]
async fn w6_some_arm_real_probe_keeps_fileref_active() {
    let status = e1_status_after_l6(true).await;
    assert_ne!(
        status,
        MemoryStatus::Orphaned,
        "Some(resolver) → ResolverStalenessProbe judges the matching-blob file-ref Valid → not orphaned (synthesis-eligible)"
    );
}

// W6 None-arm (discriminator): the empty `InMemoryStalenessProbe` judges e1 Stale → ORPHANED.
// A refactor reverting the Some-arm to the empty stub flips Some's status to Orphaned and
// fails `w6_some_arm_real_probe_keeps_fileref_active`.
#[tokio::test]
async fn w6_none_arm_empty_stub_orphans_fileref() {
    let status = e1_status_after_l6(false).await;
    assert_eq!(
        status,
        MemoryStatus::Orphaned,
        "None → empty InMemoryStalenessProbe judges the file-ref Stale → orphaned (today's wiring)"
    );
}

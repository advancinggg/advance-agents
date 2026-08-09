//! Slice H (REQ-275 foundation) — real-advance-git integration tests for
//! `SkillPersistenceCoordinator`.
//!
//! SH-08: rollback via real `DefaultGitCommitQueue` + real `DiskSkillStorage`.
//! SH-09: delete-with-sidecars; `git log` shows the `[micro] [runtime:auto-loop]`
//!        commit + `git status` is CLEAN post-commit.
//!
//! Setup pattern (R5 Codex Critical #1 fix): independent `DiskSkillStorage`
//! construction + seeding via `SkillStore::propose_draft + activate` BEFORE
//! the coordinator is built. The coordinator's `new(...)` constructs its own
//! `DiskSkillStorage` on the SAME canonical `agent_root`, so it reads the
//! seeded state from disk.

use advance_git::{
    bootstrap_repo_at, CommitRequest, CommitType, DefaultGitCommitQueue, GitCommitQueue,
};
use advance_shared_types::event::Event;
use advance_shared_types::traits::EventBusEmit;
use cap_skills::persistence::{DiskSkillStorage, SkillStorage};
use cap_skills::persistence_phase::{Initiator, SkillPersistenceCoordinator};
use cap_skills::SkillStore;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::TempDir;

/// Test-private `EventBusEmit` impl that captures every event.
#[derive(Default)]
struct CollectingEventBus {
    events: Mutex<Vec<Event>>,
}

impl CollectingEventBus {
    fn new() -> Self {
        Self::default()
    }
    fn len(&self) -> usize {
        self.events.lock().unwrap().len()
    }
    fn snapshot(&self) -> Vec<Event> {
        self.events.lock().unwrap().clone()
    }
}

impl EventBusEmit for CollectingEventBus {
    fn emit(&self, event: Event) {
        self.events.lock().unwrap().push(event);
    }
}

fn valid_skill_content() -> String {
    "---\nname: web-search\ndescription: a test skill\n---\n# Body\n".to_string()
}

/// Helper: read all commit subjects from HEAD (newest first).
fn list_commit_subjects(workdir: &std::path::Path) -> Vec<String> {
    let repo = git2::Repository::open(workdir).expect("open repo");
    let mut walk = repo.revwalk().expect("revwalk");
    walk.push_head().expect("push_head");
    let mut out = Vec::new();
    for oid in walk {
        let oid = oid.expect("walk oid");
        let c = repo.find_commit(oid).expect("find commit");
        out.push(c.summary().unwrap_or("").to_string());
    }
    out
}

/// Helper: is the working tree clean (no uncommitted changes / untracked)?
fn workdir_clean(workdir: &std::path::Path) -> bool {
    let repo = git2::Repository::open(workdir).expect("open repo");
    let mut opts = git2::StatusOptions::new();
    opts.include_untracked(true).recurse_untracked_dirs(true);
    let statuses = repo.statuses(Some(&mut opts)).expect("statuses");
    statuses.is_empty()
}

#[tokio::test]
async fn sh_08_real_git_rollback_micro_commit() {
    let dir = TempDir::new().unwrap();
    bootstrap_repo_at(dir.path()).unwrap();

    // Seed a v1 active skill via independent storage + SkillStore BEFORE
    // the coordinator is constructed. Use canonical agent_root so the
    // coordinator's internal DiskSkillStorage sees the same paths.
    let canonical_root = std::fs::canonicalize(dir.path()).unwrap();
    let setup_storage: Arc<dyn SkillStorage> = Arc::new(DiskSkillStorage::with_default_writer(
        canonical_root.clone(),
    ));
    let setup_store = SkillStore::with_storage(setup_storage);
    let draft_id = setup_store
        .propose_draft("web-search".into(), valid_skill_content(), vec![])
        .await
        .unwrap();
    let skill_id = setup_store.activate(&draft_id).await.unwrap();
    assert_eq!(skill_id, "web-search");
    drop(setup_store);

    // Make a baseline turn commit so the rollback has prior content to walk
    // against. (Without this, the queue would create the first commit; for a
    // rollback test we want a clean two-commit history.)
    let queue = DefaultGitCommitQueue::spawn(canonical_root.clone()).unwrap();
    let bus = Arc::new(CollectingEventBus::new());

    let skill_md = canonical_root
        .join(".agent")
        .join("skills")
        .join("web-search")
        .join("SKILL.md");
    let meta_yaml = canonical_root
        .join(".agent")
        .join("skills")
        .join("web-search")
        .join(".meta.yaml");
    let baseline_req = CommitRequest::new(
        "root",
        "baseline activate",
        vec![skill_md.clone(), meta_yaml.clone()],
        CommitType::Turn,
        "agent:test",
    );
    let baseline_rx = queue.submit(baseline_req);
    let _baseline_oid = baseline_rx.await.expect("worker").expect("commit");

    let coordinator = SkillPersistenceCoordinator::new(
        "root".into(),
        canonical_root.clone(),
        Arc::new(queue) as Arc<dyn GitCommitQueue>,
        bus.clone() as Arc<dyn EventBusEmit>,
    );

    let result = coordinator
        .rollback_skill_with_persistence(Initiator::AutoLoop, "web-search", 1, "iter discard")
        .await
        .unwrap();
    assert_eq!(result.new_version, 2);

    let subjects = list_commit_subjects(&canonical_root);
    let head = &subjects[0];
    assert_eq!(head, "[micro] [runtime:auto-loop] rollback web-search v1");

    assert_eq!(bus.len(), 1);
    let evs = bus.snapshot();
    assert_eq!(evs[0].event_type, "skill.rolled_back");

    drop(coordinator);
    tokio::time::sleep(Duration::from_millis(20)).await;
}

#[tokio::test]
async fn sh_09_real_git_delete_with_sidecars_clean_status() {
    let dir = TempDir::new().unwrap();
    bootstrap_repo_at(dir.path()).unwrap();

    let canonical_root = std::fs::canonicalize(dir.path()).unwrap();
    let setup_storage: Arc<dyn SkillStorage> = Arc::new(DiskSkillStorage::with_default_writer(
        canonical_root.clone(),
    ));
    let setup_store = SkillStore::with_storage(setup_storage);
    let draft_id = setup_store
        .propose_draft("web-search".into(), valid_skill_content(), vec![])
        .await
        .unwrap();
    setup_store.activate(&draft_id).await.unwrap();
    drop(setup_store);

    // Add a tool.wasm sidecar BEFORE the baseline commit so it lands in
    // HEAD's tree. Use raw fs::write since AdminPool/materialize is out of
    // slice scope.
    let skill_dir = canonical_root
        .join(".agent")
        .join("skills")
        .join("web-search");
    let tool_wasm = skill_dir.join("tool.wasm");
    tokio::fs::write(&tool_wasm, [0xAA, 0xBB, 0xCC])
        .await
        .unwrap();

    let queue = DefaultGitCommitQueue::spawn(canonical_root.clone()).unwrap();
    let bus = Arc::new(CollectingEventBus::new());

    // Baseline commit with all 3 disk paths so HEAD's tree tracks SKILL.md +
    // .meta.yaml + tool.wasm.
    let skill_md = skill_dir.join("SKILL.md");
    let meta_yaml = skill_dir.join(".meta.yaml");
    let baseline_req = CommitRequest::new(
        "root",
        "baseline activate + sidecar",
        vec![skill_md.clone(), meta_yaml.clone(), tool_wasm.clone()],
        CommitType::Turn,
        "agent:test",
    );
    let baseline_rx = queue.submit(baseline_req);
    let _ = baseline_rx.await.expect("worker").expect("commit");

    let coordinator = SkillPersistenceCoordinator::new(
        "root".into(),
        canonical_root.clone(),
        Arc::new(queue) as Arc<dyn GitCommitQueue>,
        bus.clone() as Arc<dyn EventBusEmit>,
    );

    coordinator
        .delete_skill_with_persistence(Initiator::AutoLoop, "web-search", "iter discard")
        .await
        .unwrap();

    let subjects = list_commit_subjects(&canonical_root);
    let head = &subjects[0];
    assert_eq!(head, "[micro] [runtime:auto-loop] delete web-search");

    // git status should be clean: SKILL.md + .meta.yaml + tool.wasm removed
    // from disk AND staged-as-deleted in the commit; v1 archive added to
    // commit AND present on disk; no orphans.
    assert!(
        workdir_clean(&canonical_root),
        "expected clean git status post-delete, but workdir is dirty"
    );

    assert_eq!(bus.len(), 1);
    let evs = bus.snapshot();
    assert_eq!(evs[0].event_type, "skill.deleted");

    drop(coordinator);
    tokio::time::sleep(Duration::from_millis(20)).await;
}

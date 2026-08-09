//! Wave-18 Lane 2 — the production `SkillRollback` bridge + the AC-21 micro-
//! commit-before-event ordering.
//!
//! Drives the REAL `advance_cli::skill_rollback_bridge::build_auto_skill_rollback_bridge`
//! over a REAL `cap_skills::SkillPersistenceCoordinator` (`Initiator::AutoLoop`
//! micro lane) bound to a disk-backed `SkillStore` (`SingleAgentSkillStoreProvider`)
//! + a real `DefaultGitCommitQueue` over a born-HEAD git workspace + a real
//! `EventBusEmit`. No test double on the path under assertion — these witnesses
//! exercise the exact production seam that the Wave-17 strict-hold flagged as
//! unbuilt (`build_auto_loop_driver` wired NO `SkillRollback`).
//!
//! - **Invariant reconciliation** (MODULE-017-AC-07 / §3.6 (xx)): idempotent
//!   rollback when already at target is a no-op (no version bump / commit /
//!   event); delete-when-absent is a no-op `Ok`; rollback-when-absent fails
//!   closed (deleted-then-restore unsupported — never a fake `Ok`).
//! - **AC-21 ordering** (MODULE-003-AC-21 / REQ-275): an AutoLoop rollback emits
//!   `skill.rolled_back` only AFTER the `[micro] [runtime:auto-loop]` commit is
//!   durable (the event-time git HEAD is the new micro commit, not the pre-call
//!   HEAD).

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex};

use advance_cli::skill_rollback_bridge::build_auto_skill_rollback_bridge;
use advance_git::{DefaultGitCommitQueue, GitCommitQueue};
use advance_scheduler_auto_loop::SkillRollback;
use advance_shared_types::event::Event;
use advance_shared_types::traits::EventBusEmit;
use cap_skills::provider::{SingleAgentSkillStoreProvider, SkillStoreProvider};
use cap_skills::{Initiator, SkillPersistenceCoordinator, SkillStore};
use git2::{Repository, Signature};
use tokio::sync::Mutex;

/// The cli skills coordinator binds to `DEFAULT_AGENT_ID`; the bridge ignores
/// `agent_id`, so the witnesses drive the production-identical single agent.
const AGENT: &str = "default-agent";

// ── git + event-bus harness ──────────────────────────────────────────────

/// Bootstrap a `main` repo with an empty-tree initial commit (born HEAD) so the
/// commit queue can append on top.
fn bootstrap_repo(dir: &Path) {
    advance_git::bootstrap_repo_at(dir).expect("bootstrap_repo_at");
    let repo = Repository::open(dir).expect("open repo");
    let sig = Signature::now("runtime", "runtime@advance-agents").expect("sig");
    let tree_oid = {
        let mut idx = repo.index().expect("index");
        idx.write_tree().expect("write empty tree")
    };
    let tree = repo.find_tree(tree_oid).expect("find empty tree");
    repo.commit(
        Some("refs/heads/main"),
        &sig,
        &sig,
        "initial commit",
        &tree,
        &[],
    )
    .expect("initial commit");
    repo.set_head("refs/heads/main").expect("set_head");
    repo.checkout_head(None).expect("checkout_head");
}

fn head_oid(dir: &Path) -> Option<String> {
    Repository::open(dir)
        .ok()?
        .head()
        .ok()?
        .target()
        .map(|o| o.to_string())
}

fn head_message(dir: &Path) -> String {
    let repo = Repository::open(dir).expect("open repo");
    let commit = repo.head().unwrap().peel_to_commit().unwrap();
    commit.message().unwrap_or("").to_string()
}

fn commit_count(dir: &Path) -> usize {
    let repo = Repository::open(dir).expect("open repo");
    let mut walk = repo.revwalk().expect("revwalk");
    walk.push_head().expect("push head");
    walk.count()
}

/// A real `EventBusEmit` that records every event AND, for each `skill.*` event,
/// snapshots the git HEAD oid AT EMIT TIME — the AC-21 commit-before-event
/// discriminator (if the event fired before the commit, the snapshot would still
/// be the pre-call HEAD).
struct RecordingBus {
    repo_dir: PathBuf,
    events: StdMutex<Vec<Event>>,
    head_at_emit: StdMutex<Vec<(String, Option<String>)>>,
}

impl RecordingBus {
    fn new(repo_dir: PathBuf) -> Self {
        Self {
            repo_dir,
            events: StdMutex::new(Vec::new()),
            head_at_emit: StdMutex::new(Vec::new()),
        }
    }
    fn count(&self, event_type: &str) -> usize {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.event_type == event_type)
            .count()
    }
    /// The HEAD oid captured when the first event of `event_type` was emitted.
    fn head_when_emitted(&self, event_type: &str) -> Option<String> {
        self.head_at_emit
            .lock()
            .unwrap()
            .iter()
            .find(|(t, _)| t == event_type)
            .and_then(|(_, h)| h.clone())
    }
}

impl EventBusEmit for RecordingBus {
    fn emit(&self, event: Event) {
        if event.event_type.starts_with("skill.") {
            let head = head_oid(&self.repo_dir);
            self.head_at_emit
                .lock()
                .unwrap()
                .push((event.event_type.clone(), head));
        }
        self.events.lock().unwrap().push(event);
    }
}

struct Harness {
    _tmp: tempfile::TempDir,
    ws: PathBuf,
    shared: Arc<Mutex<SkillStore>>,
    coordinator: Arc<SkillPersistenceCoordinator>,
    bridge: Arc<dyn SkillRollback>,
    bus: Arc<RecordingBus>,
    _queue: Arc<DefaultGitCommitQueue>,
}

impl Harness {
    async fn new() -> Self {
        let tmp = tempfile::tempdir().expect("tempdir");
        let ws = std::fs::canonicalize(tmp.path()).expect("canonicalize");
        bootstrap_repo(&ws);

        // Disk-backed store rooted at <ws>/.agent — identical to the production
        // wire_capabilities skills arm (DiskSkillStorage appends `.agent/skills`).
        let agent_root = ws.join(".agent");
        std::fs::create_dir_all(&agent_root).expect("mk .agent");
        let provider = SingleAgentSkillStoreProvider::new(AGENT, agent_root.clone());
        let shared = provider.get(AGENT).await.expect("resolve store");

        let bus = Arc::new(RecordingBus::new(ws.clone()));
        let bus_dyn: Arc<dyn EventBusEmit> = bus.clone();

        let queue = Arc::new(
            DefaultGitCommitQueue::spawn_with_event_bus(ws.clone(), bus_dyn.clone())
                .expect("spawn git commit queue"),
        );
        let queue_trait: Arc<dyn GitCommitQueue> = queue.clone();

        let coordinator = Arc::new(SkillPersistenceCoordinator::with_shared_store(
            AGENT.to_string(),
            agent_root,
            Arc::clone(&shared),
            queue_trait,
            bus_dyn,
        ));
        let bridge =
            build_auto_skill_rollback_bridge(Arc::clone(&coordinator), Arc::clone(&shared));

        Self {
            _tmp: tmp,
            ws,
            shared,
            coordinator,
            bridge,
            bus,
            _queue: queue,
        }
    }

    /// Activate skill `name` (proposing a fresh draft carrying `marker`) through
    /// the coordinator's turn lane — the production agent-activate path. Returns
    /// the new active version.
    async fn activate(&self, name: &str, marker: &str) -> u32 {
        let draft_id = {
            let g = self.shared.lock().await;
            g.propose_draft(name.to_string(), content(marker), vec![])
                .await
                .expect("propose_draft")
        };
        self.coordinator
            .activate_skill_with_persistence(
                Initiator::Agent {
                    id: AGENT.to_string(),
                },
                &draft_id,
                "setup",
            )
            .await
            .expect("activate")
            .version
    }

    async fn active_version(&self, name: &str) -> Option<u32> {
        let g = self.shared.lock().await;
        g.get(name).await.ok().map(|s| s.version)
    }

    async fn active_content(&self, name: &str) -> Option<String> {
        let g = self.shared.lock().await;
        g.get(name).await.ok().map(|s| s.content)
    }
}

fn content(marker: &str) -> String {
    format!("---\nname: skill\ndescription: {marker}\n---\n# {marker}\n")
}

// ── T-S2-2b — invariant reconciliation ───────────────────────────────────

/// Idempotent rollback: rollback-to-the-current-version is a no-op — no version
/// bump, NO new commit, NO `skill.rolled_back` event.
#[tokio::test(flavor = "multi_thread")]
async fn bridge_idempotent_rollback_is_noop() {
    let h = Harness::new().await;
    assert_eq!(h.activate("t", "t-v1").await, 1, "baseline t @ v1");

    let head_before = head_oid(&h.ws);
    let commits_before = commit_count(&h.ws);
    let rolled_before = h.bus.count("skill.rolled_back");

    // current(1) == target(1) ⇒ no-op Ok (the guard short-circuits before the
    // coordinator is consulted).
    h.bridge
        .rollback_skill(AGENT, "t", 1)
        .await
        .expect("idempotent rollback Ok");

    assert_eq!(
        h.active_version("t").await,
        Some(1),
        "version NOT bumped (still v1)"
    );
    assert_eq!(
        head_oid(&h.ws),
        head_before,
        "no new commit (HEAD unchanged)"
    );
    assert_eq!(
        commit_count(&h.ws),
        commits_before,
        "commit count unchanged"
    );
    assert_eq!(
        h.bus.count("skill.rolled_back"),
        rolled_before,
        "no skill.rolled_back event for a no-op rollback"
    );
}

/// No-op delete when absent: deleting a skill that does not exist returns `Ok`
/// (SkillNotFound → Ok) without a commit or a `skill.deleted` event.
#[tokio::test(flavor = "multi_thread")]
async fn bridge_delete_absent_is_noop_ok() {
    let h = Harness::new().await;
    let head_before = head_oid(&h.ws);

    h.bridge
        .delete_skill(AGENT, "ghost")
        .await
        .expect("delete-absent is Ok");

    assert_eq!(head_oid(&h.ws), head_before, "no commit for a no-op delete");
    assert_eq!(
        h.bus.count("skill.deleted"),
        0,
        "no skill.deleted event when absent"
    );
}

/// Rollback-when-absent fails closed: a `Version(n)` pre-state whose skill is
/// gone at discard cannot be restored by `SkillStore::rollback` (no re-create),
/// so the bridge surfaces an error — never a fake `Ok`.
#[tokio::test(flavor = "multi_thread")]
async fn bridge_rollback_absent_fails_closed() {
    let h = Harness::new().await;

    let err = h
        .bridge
        .rollback_skill(AGENT, "ghost", 1)
        .await
        .expect_err("rollback of an absent skill must fail closed");
    let msg = format!("{err}");
    assert!(
        msg.contains("deleted-then-restore") || msg.contains("absent"),
        "fail-closed reason names the deleted-then-restore limitation: {msg}"
    );
    assert_eq!(
        h.bus.count("skill.rolled_back"),
        0,
        "no event on a fail-closed rollback"
    );
}

/// Real delete through the bridge mutates the store (SkillNotFound after) and
/// emits `skill.deleted`.
#[tokio::test(flavor = "multi_thread")]
async fn bridge_real_delete_removes_and_emits() {
    let h = Harness::new().await;
    h.activate("d", "d-v1").await;
    assert_eq!(h.active_version("d").await, Some(1), "d present pre-delete");

    h.bridge.delete_skill(AGENT, "d").await.expect("delete Ok");

    assert_eq!(
        h.active_version("d").await,
        None,
        "d removed from the store"
    );
    assert_eq!(
        h.bus.count("skill.deleted"),
        1,
        "exactly one skill.deleted event"
    );
}

// ── T-S3-1 — AC-21 micro-commit-before-event ordering ────────────────────

/// A real AutoLoop rollback through the production bridge restores the prior
/// CONTENT, produces a `[micro] [runtime:auto-loop]` commit, and emits
/// `skill.rolled_back` only AFTER that commit is durable (the event-time HEAD is
/// the new micro commit, not the pre-call HEAD).
#[tokio::test(flavor = "multi_thread")]
async fn bridge_rollback_micro_commit_durable_before_event() {
    let h = Harness::new().await;
    assert_eq!(h.activate("t", "t-v1").await, 1, "t @ v1");
    assert_eq!(h.activate("t", "t-v2").await, 2, "t @ v2 (v1 archived)");

    let head_before = head_oid(&h.ws).expect("HEAD before");
    let commits_before = commit_count(&h.ws);

    // current(2) != target(1) ⇒ a real rollback on the AutoLoop micro lane.
    h.bridge
        .rollback_skill(AGENT, "t", 1)
        .await
        .expect("real rollback Ok");

    // Effect: the v1 CONTENT is restored (rollback bumps the active version but
    // restores the older content — v3 content == v1, NOT v2).
    let restored = h.active_content("t").await.expect("t still active");
    assert!(
        restored.contains("t-v1") && !restored.contains("t-v2"),
        "rollback restored the v1 content (got: {restored})"
    );

    // A new commit landed and it is the micro/auto-loop commit.
    assert_eq!(
        commit_count(&h.ws),
        commits_before + 1,
        "exactly one new commit"
    );
    let msg = head_message(&h.ws);
    assert!(
        msg.starts_with("[micro] [runtime:auto-loop]"),
        "the rollback commit is tagged micro + runtime:auto-loop: {msg:?}"
    );

    // Ordering: the HEAD captured when skill.rolled_back fired is the NEW commit
    // (HEAD advanced past the pre-call commit) — the commit was durable BEFORE
    // the event. If the event had fired first, this would still be head_before.
    assert_eq!(
        h.bus.count("skill.rolled_back"),
        1,
        "exactly one skill.rolled_back"
    );
    let head_at_event = h
        .bus
        .head_when_emitted("skill.rolled_back")
        .expect("HEAD captured at event emit");
    assert_ne!(
        head_at_event, head_before,
        "the micro commit is durable (HEAD advanced) BEFORE skill.rolled_back fires"
    );
    assert_eq!(
        head_at_event,
        head_oid(&h.ws).unwrap(),
        "the event-time HEAD is the final micro commit (commit-then-emit)"
    );
}

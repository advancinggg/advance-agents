//! Wave-10 Lane C — build-lane witnesses for the agent turn-lane skill
//! lifecycle emitters (076/077).
//!
//! These drive the REAL registered host-fns (`register_agent_skills_with_lifecycle`)
//! over a real `DefaultGitCommitQueue` + real `DiskSkillStorage`, and assert that
//! a successful agent `activate-skill` emits `skill.activated` + a `commit_type:
//! turn` commit (LC-01), and that the agent-callable `rollback-skill` drives the
//! coordinator → `skill.rolled_back` + version restore + turn commit (LC-02). The
//! event/commit are PRODUCT-emitted by the wired coordinator — NOT harness-injected.
//!
//! These are BUILD-LANE witnesses (prove the emitters fire); they do NOT claim a
//! SYS-AC flip. SYS-AC-076/077 stay `#[ignore]`d in
//! `crates/system-acceptance/tests/sys_j25_skill_lifecycle.rs` until the mainline
//! harvest.
//!
//! Provider/coordinator are rooted at `<repo>/.agent` (production-wiring parity),
//! so `DiskSkillStorage` + the coordinator's `affected_paths` both resolve to
//! `<repo>/.agent/.agent/skills/{id}/...` (the double-`.agent` layout). The
//! asserted committed-tree path is therefore `.agent/.agent/skills/{id}/SKILL.md`
//! — NOT SH-08/09's single-`.agent` shape (those root the coordinator at the repo
//! root). The witness derives the asserted path from the SAME `agent_root` it
//! constructs the provider/coordinator with, so the two cannot desync.

use std::sync::{Arc, Mutex};

use advance_git::{bootstrap_repo_at, DefaultGitCommitQueue, GitCommitQueue};
use advance_runtime::host_registry::{
    HostCallContext, HostFunctionSpec, HostRegistry, InMemoryHostRegistry,
};
use advance_shared_types::event::Event;
use advance_shared_types::traits::EventBusEmit;
use cap_skills::provider::{SingleAgentSkillStoreProvider, SkillStoreProvider};
use cap_skills::{register_agent_skills_with_lifecycle, SkillPersistenceCoordinator, SkillStore};
use tempfile::TempDir;
use wasmtime::component::Val;

const NS: &str = "advance:runtime/agent-skills@0.1.0";
const CAP: &str = "skills";
const AGENT: &str = "default-agent";

/// Captures every emitted event for assertions.
#[derive(Default)]
struct CollectingEventBus {
    events: Mutex<Vec<Event>>,
}

impl CollectingEventBus {
    fn snapshot(&self) -> Vec<Event> {
        self.events.lock().unwrap().clone()
    }
    fn of_type(&self, t: &str) -> Vec<Event> {
        self.snapshot()
            .into_iter()
            .filter(|e| e.event_type == t)
            .collect()
    }
}

impl EventBusEmit for CollectingEventBus {
    fn emit(&self, event: Event) {
        self.events.lock().unwrap().push(event);
    }
}

fn valid_content(name: &str) -> String {
    format!("---\nname: {name}\ndescription: a test skill\n---\n# {name}\nbody for {name}\n")
}

fn ctx_for(agent_id: &str, function: &str) -> HostCallContext {
    HostCallContext {
        agent_id: agent_id.to_string(),
        trace_id: "t-lc".to_string(),
        turn_id: None,
        capability: CAP.to_string(),
        function: format!("{NS}::{function}"),
        run_id: None,
        iteration: None,
    }
}

fn lookup(registry: &InMemoryHostRegistry, name: &str) -> HostFunctionSpec {
    registry
        .lookup(CAP)
        .into_iter()
        .find(|s| s.namespace == NS && s.name == name)
        .unwrap_or_else(|| panic!("host fn {name} not registered"))
}

/// Test fixture: real git repo + commit queue + recording bus + a provider whose
/// store is SHARED into the coordinator (so all skills ops serialize on one mutex).
struct Fixture {
    _dir: TempDir,
    workspace: std::path::PathBuf,
    registry: InMemoryHostRegistry,
    bus: Arc<CollectingEventBus>,
    shared: Arc<tokio::sync::Mutex<SkillStore>>,
    // Held for the queue worker's lifetime (Drop drains the worker).
    _queue: Arc<DefaultGitCommitQueue>,
}

impl Fixture {
    async fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let workspace = dir.path().to_path_buf();
        bootstrap_repo_at(&workspace).expect("bootstrap_repo_at");

        let queue =
            Arc::new(DefaultGitCommitQueue::spawn(workspace.clone()).expect("commit queue spawn"));
        let bus = Arc::new(CollectingEventBus::default());

        // Provider rooted at <repo>/.agent (production parity).
        let agent_root = workspace.join(".agent");
        let provider = Arc::new(SingleAgentSkillStoreProvider::new(
            AGENT,
            agent_root.clone(),
        ));
        // Resolve the provider's store and SHARE it into the coordinator.
        let shared = provider.get(AGENT).await.expect("resolve shared store");

        let coordinator = Arc::new(SkillPersistenceCoordinator::with_shared_store(
            AGENT.to_string(),
            agent_root,
            shared.clone(),
            queue.clone() as Arc<dyn GitCommitQueue>,
            bus.clone() as Arc<dyn EventBusEmit>,
        ));

        let registry = InMemoryHostRegistry::new();
        register_agent_skills_with_lifecycle(&registry, provider, coordinator);

        Self {
            _dir: dir,
            workspace,
            registry,
            bus,
            shared,
            _queue: queue,
        }
    }

    async fn call(&self, name: &str, agent_id: &str, params: Vec<Val>) -> Val {
        let spec = lookup(&self.registry, name);
        let out = spec
            .handler
            .call(ctx_for(agent_id, name), params, 1)
            .await
            .unwrap_or_else(|e| panic!("{name} dispatch: {e:?}"));
        out.into_iter().next().expect("one result Val")
    }

    async fn propose(&self, name: &str, content: &str) -> Val {
        self.call(
            "propose-skill-draft",
            AGENT,
            vec![
                Val::String(name.to_string()),
                Val::String(content.to_string()),
                Val::List(Vec::new()),
            ],
        )
        .await
    }

    async fn activate(&self, agent_id: &str, draft: &str) -> Val {
        self.call(
            "activate-skill",
            agent_id,
            vec![Val::String(draft.to_string())],
        )
        .await
    }

    async fn rollback(&self, skill: &str, version: u32) -> Val {
        self.call(
            "rollback-skill",
            AGENT,
            vec![Val::String(skill.to_string()), Val::U32(version)],
        )
        .await
    }

    /// The committed blob bytes at `<repo>/.agent/.agent/skills/{id}/SKILL.md` in HEAD's tree.
    fn head_skill_md(&self, skill_id: &str) -> Option<String> {
        let repo = git2::Repository::open(&self.workspace).ok()?;
        let head = repo.head().ok()?.peel_to_commit().ok()?;
        let tree = head.tree().ok()?;
        let rel = format!(".agent/.agent/skills/{skill_id}/SKILL.md");
        let entry = tree.get_path(std::path::Path::new(&rel)).ok()?;
        let obj = entry.to_object(&repo).ok()?;
        let blob = obj.as_blob()?.content().to_vec();
        String::from_utf8(blob).ok()
    }

    fn head_message(&self) -> String {
        let repo = git2::Repository::open(&self.workspace).unwrap();
        let head = repo.head().unwrap().peel_to_commit().unwrap();
        head.message().unwrap_or("").to_string()
    }
}

fn ok_string(v: &Val) -> Option<String> {
    match v {
        Val::Result(Ok(Some(inner))) => match inner.as_ref() {
            Val::String(s) => Some(s.clone()),
            _ => None,
        },
        _ => None,
    }
}

fn is_ok_unit(v: &Val) -> bool {
    matches!(v, Val::Result(Ok(None)))
}

fn err_case(v: &Val) -> Option<String> {
    match v {
        Val::Result(Err(Some(inner))) => match inner.as_ref() {
            Val::Variant(case, _) => Some(case.clone()),
            _ => None,
        },
        _ => None,
    }
}

// ── LC-01 — activate emits skill.activated + a turn commit containing the blob ──
#[tokio::test]
async fn lc_01_activate_emits_skill_activated_and_turn_commit() {
    let fx = Fixture::new().await;

    let content = valid_content("myskill");
    assert_eq!(
        ok_string(&fx.propose("myskill", &content).await).as_deref(),
        Some("myskill")
    );

    let activated = fx.activate(AGENT, "myskill").await;
    assert_eq!(
        ok_string(&activated).as_deref(),
        Some("myskill"),
        "activate returns Ok(skill-id)"
    );

    // PRODUCT-emitted event: exactly one skill.activated for version 1.
    let events = fx.bus.of_type("skill.activated");
    assert_eq!(events.len(), 1, "exactly one skill.activated emitted");
    let e = &events[0];
    assert_eq!(e.payload["skill_id"], "myskill");
    assert_eq!(e.payload["version"], 1);

    // Anti-fake-green: the turn commit's TREE actually contains the activated bytes.
    let md = fx
        .head_skill_md("myskill")
        .expect("HEAD tree contains the activated SKILL.md");
    assert!(
        md.contains("name: myskill"),
        "committed blob is the activated content: {md}"
    );
    let msg = fx.head_message();
    assert!(
        msg.starts_with("[turn] [agent:default-agent]"),
        "commit is a turn commit: {msg}"
    );
    assert!(
        msg.contains("activate myskill v1"),
        "commit names the activate: {msg}"
    );
}

// ── LC-02 — rollback emits skill.rolled_back, restores the version, turn commit ──
#[tokio::test]
async fn lc_02_rollback_emits_event_restores_version_and_turn_commit() {
    let fx = Fixture::new().await;

    // v1 (body "ONE"), then v2 (body "TWO").
    let v1 = valid_content("myskill").replace("body for myskill", "ONE");
    assert_eq!(
        ok_string(&fx.propose("myskill", &v1).await).as_deref(),
        Some("myskill")
    );
    assert_eq!(
        ok_string(&fx.activate(AGENT, "myskill").await).as_deref(),
        Some("myskill")
    );

    let v2 = valid_content("myskill").replace("body for myskill", "TWO");
    assert_eq!(
        ok_string(&fx.propose("myskill", &v2).await).as_deref(),
        Some("myskill")
    );
    assert_eq!(
        ok_string(&fx.activate(AGENT, "myskill").await).as_deref(),
        Some("myskill")
    );

    // Roll back to version 1.
    let rolled = fx.rollback("myskill", 1).await;
    assert!(is_ok_unit(&rolled), "rollback returns Ok(()): {rolled:?}");

    let events = fx.bus.of_type("skill.rolled_back");
    assert_eq!(events.len(), 1, "exactly one skill.rolled_back emitted");
    let e = &events[0];
    assert_eq!(e.payload["from_version"], 2);
    assert_eq!(e.payload["to_version"], 3);

    // Active is bumped to v3 and content is restored to v1's body.
    let active = fx.shared.lock().await.get("myskill").await.unwrap();
    assert_eq!(
        active.version, 3,
        "rollback appends a new active at prior+1"
    );
    assert!(
        active.content.contains("ONE"),
        "v1 content restored: {}",
        active.content
    );

    // The rollback turn commit's tree carries the restored bytes.
    let md = fx
        .head_skill_md("myskill")
        .expect("HEAD tree contains the restored SKILL.md");
    assert!(
        md.contains("ONE"),
        "committed blob is the restored v1 content: {md}"
    );
    let msg = fx.head_message();
    assert!(
        msg.starts_with("[turn] [agent:default-agent]"),
        "rollback is a turn commit: {msg}"
    );
    assert!(
        msg.contains("rollback myskill v1"),
        "commit names the rollback: {msg}"
    );
}

// ── SH-18 — agent-id isolation guard: a mismatched ctx.agent_id is rejected ──
#[tokio::test]
async fn sh_18_coordinator_routed_handler_rejects_foreign_agent() {
    let fx = Fixture::new().await;

    let content = valid_content("myskill");
    assert_eq!(
        ok_string(&fx.propose("myskill", &content).await).as_deref(),
        Some("myskill")
    );

    // activate as a DIFFERENT agent than the coordinator is bound to.
    let blocked = fx.activate("intruder", "myskill").await;
    assert_eq!(
        err_case(&blocked).as_deref(),
        Some("not-found"),
        "a foreign agent's activate is rejected with not-found (isolation guard)"
    );

    // The guard fired BEFORE the coordinator: no event, no commit on HEAD for the skill.
    assert!(
        fx.bus.of_type("skill.activated").is_empty(),
        "no event on a rejected foreign activate"
    );
    assert!(
        fx.head_skill_md("myskill").is_none(),
        "no skill commit landed for the rejected activate"
    );

    // Discriminator: the legitimate agent DOES activate.
    assert_eq!(
        ok_string(&fx.activate(AGENT, "myskill").await).as_deref(),
        Some("myskill")
    );
    assert_eq!(fx.bus.of_type("skill.activated").len(), 1);
}

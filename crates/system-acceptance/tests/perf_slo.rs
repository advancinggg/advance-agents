//! Perf-CI lane — perf-SLO SYS-AC witnesses (median-of-N / warm-run / outlier-drop).
//!
//! Witnesses the perf-SLO class SYS-AC by timing the NAMED PRODUCT SEAM directly at a
//! clean seam (never a whole turn, never a `sleep`):
//!   - SYS-AC-214 SYS-J-22  `PostProcessor::run`              (<3 s, text post-proc)
//!   - SYS-AC-196 SYS-J-07  `DefaultSpawner::spawn_child`     (<500 ms)
//!   - SYS-AC-199 SYS-J-08  spawn-from-template (`apply_template` path) (<500 ms)
//!   - SYS-AC-238 SYS-J-50  `WorkspaceRollback::rollback` ~100 files     (<500 ms)
//!   - SYS-AC-241 SYS-J-51  `rollback_to_checkpoint` ~100 files          (<500 ms)
//!   - SYS-AC-191 SYS-J-03  `ContextAssembler::assemble` p95              (<500 ms)
//!   - SYS-AC-195 SYS-J-06  pause-run → suspended-guest resolves session-closed (<100 ms)
//!   - SYS-AC-234 SYS-J-46  startup reconcile / index rebuild  (<5 s/10K + >10K rows/min)
//!   - SYS-AC-246 SYS-J-57  serialized commit throughput        (>100 commits/s)
//!
//! ## How to run (the system-acceptance harness for these rows)
//!
//! Every perf test is `#[ignore]`d so the DEFAULT `cargo test -p system-acceptance` suite
//! stays fast and non-flaky. Witness them on the real wired system with:
//!
//!     cargo test -p system-acceptance --release --test perf_slo -- --ignored --test-threads=1
//!
//! `--release` (dev profile is 2–10× slower → 191/195/234/246 would breach from debug
//! overhead alone), `--test-threads=1` (serial — parallel-test/parallel-worktree contention
//! is the original perf-SLO defer reason). The `perf_support_math` self-test below is NOT
//! ignored — it runs in the default suite and guards the statistic helper against a
//! silently-broken median/p95 (an anti-fake-green control).
//!
//! ## Disk pinning (documented)
//!
//! Every timed fixture uses `tempfile::TempDir::new()` → `std::env::temp_dir()`, which on a
//! Darwin host is `/var/folders/.../T` — the INTERNAL APFS volume, not whatever (possibly
//! slow, external) volume holds the checkout. Pinning the git repos / 10K-file tree / sqlite
//! to the internal SSD is what makes 234/238/241/246 attemptable.
//!
//! ## Witness-fidelity disclosures (honest, recorded on each §2 flip + change-history)
//!
//!   - 214: the loopback LLM runs the REAL gateway + 10-step HTTP chain to 127.0.0.1 with a
//!     SCRIPTED reply, so BOTH the network RTT AND the model inference time are excluded — this
//!     times the real extraction-call machinery + ALL real downstream writes, not an
//!     LLM-inclusive end-to-end SLO. (Same hermetic-CI constraint class as 191's embedding.)
//!   - 191: production `assemble()` today wires REAL L0 (knowledge map) + L2/L3/L4 (history),
//!     while L1/L5/L6 are stub-wired (their backends are deferred SYS-AC). This times
//!     `assemble()` AS THE PRODUCT RUNS TODAY (disclosed), `task_id=Some(..)` excluding the
//!     embedding round-trip per the criterion.
//!   - 234: the >10K/min rebuild rate is computed from the PRODUCT-reported
//!     `rebuild_report.content_rows` (asserted ≥10_000), not the fixture file count.

#![allow(clippy::needless_range_loop)]

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use advance_git::{
    bootstrap_repo_at, CommitRequest, CommitType, DefaultGitCommitQueue, DefaultNamedCheckpoint,
    DefaultWorkspaceRollback, GitCommitQueue, NamedCheckpoint, RollbackMode, RollbackTarget,
    WorkspaceRollback,
};
use advance_runtime::host_registry::HostFunctionHandler;
use advance_shared_types::agent_tree::{
    AgentId, AgentKind, AgentNode, AgentState, AgentStatus, Capability,
};
use advance_shared_types::context::AssemblyContext;
use advance_shared_types::event::Event;
use advance_shared_types::mailbox::{
    ActionResult, AgentAction, Message, MessageContext, MessageKind,
};
use advance_shared_types::traits::EventBusEmit;
use cap_lifecycle::{
    AgentTreeStore, DefaultSpawner, SpawnChildConfig, SpawnError, Spawner, SpawnerSubsetGate,
    TemplateContent, TemplateError, TemplateResolver, TemplateSkillEntry,
};
use cap_memory::{
    MemoryEntry, MemoryStatus, MemoryStore, MemoryType, DEFAULT_MAX_ACTIVE_PER_AGENT,
};
use git2::{Repository, Signature};
use system_acceptance::llm_loopback::ScriptedResponse;
use system_acceptance::{Cap, LlmMode, SystemUnderTest, AGENT_ID};
use tempfile::TempDir;

#[path = "perf_support/mod.rs"]
mod perf_support;
#[path = "step4b_support/mod.rs"]
mod step4b;

use perf_support::{collect, stats_from, Budget};

const J01_SKELETON: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-j01-skeleton.core.wasm");
const MEM_SKELETON: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-mem-skeleton.core.wasm");

const IGNORE_REASON: &str =
    "perf-SLO lane: run via `cargo test -p system-acceptance --release --test perf_slo -- --ignored --test-threads=1`";

// ───────────────────────────────────────────────────────────────────────────
// Shared in-file event sinks (each tests/*.rs is its own integration binary).
// ───────────────────────────────────────────────────────────────────────────

struct NoopBus;
impl EventBusEmit for NoopBus {
    fn emit(&self, _e: Event) {}
}

#[derive(Default)]
struct CapturingEventBus {
    events: Mutex<Vec<Event>>,
}
impl CapturingEventBus {
    fn new() -> Self {
        Self::default()
    }
    fn count(&self, ty: &str) -> usize {
        self.events
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|e| e.event_type == ty)
            .count()
    }
}
impl EventBusEmit for CapturingEventBus {
    fn emit(&self, e: Event) {
        self.events
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(e);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// perf_support self-test (NOT ignored — runs in the default suite as a
// fake-green guard on the median/p95/trim math).
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn perf_support_math() {
    // sorted: 1..=11 ms plus one 1000 ms outlier ⇒ n = 12.
    let mut v: Vec<Duration> = (1u64..=11).map(Duration::from_millis).collect();
    v.push(Duration::from_millis(1000));
    let s = stats_from(v, 1); // drop 1 from each end
                              // trimmed = 2..=11 (10 values) ⇒ median = (6 + 7) / 2 = 6.5; the 1000 ms outlier
                              // is dropped from the median but stays visible in p95/max.
    assert!((s.median_ms - 6.5).abs() < 1e-6, "median = {}", s.median_ms);
    assert_eq!(s.n, 12);
    assert_eq!(s.trimmed_n, 10);
    assert!((s.min_ms - 1.0).abs() < 1e-6, "min = {}", s.min_ms);
    assert!(s.max_ms >= 999.0, "max captures the outlier = {}", s.max_ms);
    // p95 idx = ceil(12 * 0.95) - 1 = 11 ⇒ the 1000 ms tail.
    assert!(s.p95_ms >= 999.0, "p95 = {}", s.p95_ms);
    // The outlier-drop keeps the median robust (the whole point of the methodology).
    assert!(
        s.median_ms < 10.0,
        "median must be robust to the 1000 ms outlier"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// SYS-AC-214 — text post-processing pass < 3 s (PostProcessor::run)
// ═══════════════════════════════════════════════════════════════════════════

fn extraction_json() -> String {
    // A well-formed batched-extraction completion the Step-2 parser accepts. The
    // knowledge content drives Step 5-8 downstream writes (summary.yaml etc.).
    r#"{"digest":"perf214-digest","knowledge":[{"content":"perf214-knowledge-marker","tags":["t"],"kind":"fact"}]}"#
        .to_string()
}

fn make_turn_msg(task: &str) -> Message {
    Message {
        id: format!("m-{task}"),
        kind: MessageKind::User,
        from: "user:tester".into(),
        to: AGENT_ID.into(),
        payload: b"please remember the rotation policy for the deploy key".to_vec(),
        context: Some(MessageContext {
            task_id: Some(task.to_string()),
            run_id: None,
            execution_id: None,
            trace_id: None,
            in_reply_to: None,
            correlation_id: None,
        }),
        timestamp: SystemTime::now(),
        origin: None,
    }
}

fn make_action_result() -> ActionResult {
    ActionResult {
        new_state: b"{}".to_vec(),
        actions: vec![AgentAction {
            payload: b"reply: the deploy key rotates every ninety days".to_vec(),
        }],
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "perf-SLO lane: see file header / IGNORE_REASON"]
async fn perf_214_postproc_run_under_3s() {
    let _ = IGNORE_REASON;
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Memory, Cap::Llm])
        // Loopback (in-process) scripted extraction → no network; the FIFO replays for
        // every run() call, so each sample fires exactly one batched-extraction POST.
        .llm(LlmMode::LoopbackScripted(vec![ScriptedResponse::ok_chat(
            &extraction_json(),
            7,
            9,
        )]))
        .with_live_memory()
        .build(MEM_SKELETON)
        .await;

    let pp = sut
        .live_post_processor()
        .expect("214: live PostProcessor present under .with_live_memory()");
    let agent_id = sut.agent_id().to_string();
    let mem_dir = sut.memory_dir().to_path_buf();

    let stats = collect(Budget::bound(), |i| {
        // Fresh task partition per sample → distinct downstream writes (no dedup/collision),
        // and a successful extraction never trips the failure-cooldown, so each run() fires.
        let pp = pp.clone();
        let agent_id = agent_id.clone();
        let mem_dir = mem_dir.clone();
        async move {
            let task = format!("perf214-{i}");
            let msg = make_turn_msg(&task);
            let result = make_action_result();
            let t0 = Instant::now();
            pp.run(&agent_id, &msg, &result)
                .await
                .expect("214: PostProcessor::run");
            let dt = t0.elapsed();
            // Product-output binding (untimed): the extraction's downstream Step-7 writeback
            // materialized summary.yaml under tasks/{task}/ — a bare Ok(()) cannot pass.
            let summary = mem_dir.join("tasks").join(&task).join("summary.yaml");
            assert!(
                summary.exists(),
                "214: Step-7 wrote summary.yaml at {summary:?} (downstream writes fired)"
            );
            dt
        }
    })
    .await;

    stats.report("SYS-AC-214 PostProcessor::run");
    // Product-output binding (aggregate): EVERY run() fired exactly one batched-extraction
    // POST. Budget::bound() = warmup(1) + samples(11) = 12 run() calls; the mem-skeleton path
    // makes no generate call, so each run() POSTs exactly once (the extraction). Asserting the
    // EXACT count (>= 12, the run total) means a single skipped extraction (→ 11) FAILS — a
    // tighter binding than a loose `>= samples` (which a hidden skip could satisfy).
    let posts = sut.llm_chat_request_count();
    assert!(
        posts >= 12,
        "214: all 12 run() calls (1 warm + 11 samples) must each fire one extraction POST (count={posts})"
    );
    assert!(
        stats.median_ms < 3000.0,
        "SYS-AC-214: text post-proc median {:.3} ms must be < 3000 ms (loopback RTT+inference excluded — see header)",
        stats.median_ms
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// SYS-AC-196 — spawn-child < 500 ms (DefaultSpawner::spawn_child, sync)
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test(flavor = "multi_thread")]
#[ignore = "perf-SLO lane: see file header / IGNORE_REASON"]
async fn perf_196_spawn_child_under_500ms() {
    // Local real tree + real DefaultSpawner so we can bind to the PRODUCT output (the
    // materialized child workspace + the real tree insert), not just the returned id.
    let (_tmp, tree, spawner) = local_tree_and_spawner();

    let stats = collect(Budget::bound(), move |i| {
        let spawner = spawner.clone();
        let tree = tree.clone();
        async move {
            // Unique child id per sample (spawn_child registers the child in the tree).
            let child_id = format!("gc{i}");
            let cfg = SpawnChildConfig {
                parent_id: AgentId("root".into()),
                child_id: AgentId(child_id.clone()),
                child_workspace_path: PathBuf::from(format!("agents/{child_id}")),
                capabilities: vec![],
                template_ref: None,
                binary: None,
            };
            let t0 = Instant::now();
            let child = spawner.spawn_child(cfg).expect("196: spawn_child");
            let dt = t0.elapsed();
            // Product-output binding: the child node was inserted into the REAL tree AND
            // init_child_workspace materialized its `.agent/config.yaml` on disk (a wrong
            // spawn would leave neither — the returned id alone is just my echoed input).
            let node = tree
                .get_node(&child)
                .expect("196: child node registered in the real AgentTreeStore");
            assert!(
                agent_dir(&node.workspace_path)
                    .join("config.yaml")
                    .is_file(),
                "196: init_child_workspace materialized the child .agent/config.yaml on disk"
            );
            dt
        }
    })
    .await;

    stats.report("SYS-AC-196 spawn_child");
    assert!(
        stats.median_ms < 500.0,
        "SYS-AC-196: spawn-child median {:.3} ms must be < 500 ms",
        stats.median_ms
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// SYS-AC-199 — spawn-from-template materializes < 500 ms (apply_template path)
// ═══════════════════════════════════════════════════════════════════════════
//
// Times the REAL production template-materialization path: `spawn_child(template_ref=Some)`
// → `init_child_workspace` → `apply_template` (cap-lifecycle). `apply_template` is the
// dominant leg; driving it through the real spawn path (the sys_j08 precedent) is the
// faithful witness of "a typical template materializes in under 500 ms", and avoids a
// hand-assembled `.agent/` skeleton.

const WASM_HEADER: &[u8] = b"\0asm\x01\0\0\0";
const SKILL_BYTES: &[u8] = b"# greet skill\n";
const SEED: &str = "{\"insight\":\"seed-knowledge\"}\n";
const AGENTS_MD: &str = "# Self-Improvement Guidelines\n(materialized by template)\n";

struct MaterializingResolver;
impl TemplateResolver for MaterializingResolver {
    fn resolve(&self, _template_ref: &str) -> Result<TemplateContent, TemplateError> {
        Ok(TemplateContent {
            name: "tmpl".to_string(),
            manifest_yaml: "name: tmpl\n".to_string(),
            agents_md: AGENTS_MD.to_string(),
            skills: vec![TemplateSkillEntry {
                relative_path: PathBuf::from("greet.md"),
                content: SKILL_BYTES.to_vec(),
            }],
            memory_seed_jsonl: Some(SEED.to_string()),
            behavior_wasm: Some(WASM_HEADER.to_vec()),
        })
    }
    fn list(&self) -> Vec<String> {
        vec!["tmpl".to_string()]
    }
}

struct AlwaysOkGate;
impl SpawnerSubsetGate for AlwaysOkGate {
    fn check(&self, _p: &[Capability], _c: &[Capability]) -> Result<(), SpawnError> {
        Ok(())
    }
}

fn agent_dir(ws: &Path) -> PathBuf {
    ws.join(".agent")
}

/// A fresh real `AgentTreeStore` + real `DefaultSpawner` (with the MaterializingResolver
/// wired, so template spawns materialize a non-vacuous behavior+skill+seed payload). The
/// returned tree is a clone sharing the spawner's store, so `tree.get_node(child)` after a
/// spawn reflects the real insert + the canonical child workspace_path. Used by both the
/// 196 (bare spawn) and 199 (template spawn) witnesses.
fn local_tree_and_spawner() -> (TempDir, AgentTreeStore, Arc<DefaultSpawner>) {
    let tmp = TempDir::new().unwrap();
    let workspace_root = tmp.path().canonicalize().expect("canonicalize");
    let tree = AgentTreeStore::new(workspace_root.clone()).unwrap();
    let root_ws = workspace_root.join("root_ws");
    std::fs::create_dir_all(&root_ws).unwrap();
    tree.insert_root(AgentNode {
        id: AgentId("root".to_string()),
        kind: AgentKind::Root,
        parent: None,
        workspace_path: root_ws,
        capabilities: Vec::new(),
        template_ref: None,
        status: AgentStatus::Active,
    })
    .unwrap();
    let spawner = Arc::new(DefaultSpawner::with_template_resolver(
        tree.clone(),
        Arc::new(AlwaysOkGate),
        Arc::new(MaterializingResolver),
    ));
    (tmp, tree, spawner)
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "perf-SLO lane: see file header / IGNORE_REASON"]
async fn perf_199_apply_template_under_500ms() {
    let (_tmp, tree, spawner) = local_tree_and_spawner();

    let stats = collect(Budget::bound(), move |i| {
        let spawner = spawner.clone();
        let tree = tree.clone();
        async move {
            let child_id = format!("tmplchild{i}");
            let cfg = SpawnChildConfig {
                parent_id: AgentId("root".into()),
                child_id: AgentId(child_id.clone()),
                child_workspace_path: PathBuf::from(format!("agents/{child_id}")),
                capabilities: vec![],
                template_ref: Some("tmpl".into()),
                binary: None,
            };
            let t0 = Instant::now();
            let child = spawner
                .spawn_child(cfg)
                .expect("199: spawn_child from template (apply_template)");
            let dt = t0.elapsed();
            // Product-output binding (untimed): apply_template actually MATERIALIZED the
            // template payload on disk under the child's canonical workspace — behavior.wasm,
            // AGENTS.md, the skill, and the memory seed. The returned id alone would not prove
            // the materialization happened.
            let ad = agent_dir(
                &tree
                    .get_node(&child)
                    .expect("199: child node")
                    .workspace_path,
            );
            assert_eq!(
                std::fs::read(ad.join("behavior.wasm")).expect("199: behavior.wasm"),
                WASM_HEADER,
                "199: behavior.wasm materialized with the template bytes"
            );
            assert!(
                std::fs::read_to_string(ad.join("AGENTS.md"))
                    .expect("199: AGENTS.md")
                    .contains("Self-Improvement Guidelines"),
                "199: AGENTS.md materialized from the template"
            );
            assert_eq!(
                std::fs::read(ad.join("skills").join("greet.md")).expect("199: skill"),
                SKILL_BYTES,
                "199: the template skill materialized"
            );
            assert_eq!(
                std::fs::read_to_string(ad.join("memory").join("knowledge.jsonl"))
                    .expect("199: memory seed"),
                SEED,
                "199: the template memory seed materialized (Child kind)"
            );
            dt
        }
    })
    .await;

    stats.report("SYS-AC-199 template materialize");
    assert!(
        stats.median_ms < 500.0,
        "SYS-AC-199: template-materialize median {:.3} ms must be < 500 ms",
        stats.median_ms
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Shared git fixtures for 238 / 241 (real libgit2, internal-APFS temp).
// ───────────────────────────────────────────────────────────────────────────

const ROLLBACK_FILES: usize = 100;

/// Bootstrap an UNBORN-HEAD single-branch repo and seed a `worker` territory whose base
/// commit holds `ROLLBACK_FILES` writable files (`worker/f{n}.md` = `base-{n}`). Returns
/// the tempdir guard, repo path, and base-commit Oid (the rollback target).
fn seed_worker_repo() -> (TempDir, PathBuf, git2::Oid) {
    let td = TempDir::new().expect("tempdir");
    let p = td.path().to_path_buf();
    bootstrap_repo_at(&p).expect("bootstrap single-branch repo");

    let repo = Repository::open(&p).unwrap();
    std::fs::create_dir_all(p.join("worker/.agent")).unwrap();
    std::fs::write(p.join("worker/.agent/config.yaml"), "agent_id: worker\n").unwrap();
    for n in 0..ROLLBACK_FILES {
        std::fs::write(p.join(format!("worker/f{n}.md")), format!("base-{n}")).unwrap();
    }
    let mut idx = repo.index().unwrap();
    idx.add_path(Path::new("worker/.agent/config.yaml"))
        .unwrap();
    for n in 0..ROLLBACK_FILES {
        idx.add_path(Path::new(&format!("worker/f{n}.md"))).unwrap();
    }
    idx.write().unwrap();
    let tree_id = idx.write_tree().unwrap();
    let tree = repo.find_tree(tree_id).unwrap();
    let sig = Signature::now("t", "t@x").unwrap();
    let oid = repo
        .commit(
            Some("HEAD"),
            &sig,
            &sig,
            "base: worker territory",
            &tree,
            &[],
        )
        .unwrap();
    (td, p, oid)
}

/// Overwrite all `ROLLBACK_FILES` writable files with drift content (untimed setup before
/// each timed rollback, so the rollback has a non-empty affected set every sample).
fn drift_worker(p: &Path) {
    for n in 0..ROLLBACK_FILES {
        std::fs::write(p.join(format!("worker/f{n}.md")), format!("DRIFT-{n}")).unwrap();
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// SYS-AC-238 — rollback ~100 files < 500 ms (WorkspaceRollback::rollback)
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test(flavor = "multi_thread")]
#[ignore = "perf-SLO lane: see file header / IGNORE_REASON"]
async fn perf_238_rollback_100_files_under_500ms() {
    let (_td, repo, target) = seed_worker_repo();
    let target_str = target.to_string();

    let stats = collect(Budget::bound(), move |_i| {
        let repo = repo.clone();
        let target_str = target_str.clone();
        async move {
            drift_worker(&repo); // untimed
            let rb = DefaultWorkspaceRollback::with_event_bus(
                repo.clone(),
                Arc::new(NoopBus) as Arc<dyn EventBusEmit>,
            )
            .unwrap();
            let t0 = Instant::now();
            let affected = rb
                .rollback(
                    "worker",
                    RollbackTarget::Commit(target_str.clone()),
                    RollbackMode::FullDirectory,
                )
                .await
                .expect("238: rollback");
            let dt = t0.elapsed();
            // Non-vacuity: ~100 files reverted, and a spot-checked file matches base content
            // (a wrong agent/target/fixture would time an empty no-op rollback).
            assert!(
                affected.len() >= ROLLBACK_FILES - 5,
                "238: rollback reverted ~{ROLLBACK_FILES} files (got {})",
                affected.len()
            );
            assert_eq!(
                std::fs::read_to_string(repo.join("worker/f0.md")).unwrap(),
                "base-0",
                "238: a reverted file matches its base-commit content"
            );
            dt
        }
    })
    .await;

    stats.report("SYS-AC-238 rollback ~100 files");
    assert!(
        stats.median_ms < 500.0,
        "SYS-AC-238: rollback median {:.3} ms must be < 500 ms",
        stats.median_ms
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// SYS-AC-241 — rollback-to-checkpoint ~100 files < 500 ms
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test(flavor = "multi_thread")]
#[ignore = "perf-SLO lane: see file header / IGNORE_REASON"]
async fn perf_241_rollback_to_checkpoint_under_500ms() {
    let (_td, repo, _target) = seed_worker_repo();
    // Path-scoped checkpoint over the ~100 base files (captures base content; needs ≥1 commit,
    // which seed_worker_repo provided).
    let ncp = DefaultNamedCheckpoint::new(repo.clone()).expect("241: DefaultNamedCheckpoint::new");
    // Checkpoint paths are resolved RELATIVE to the agent's territory (`worker/`), so they
    // are territory-relative (`f{n}.md`), NOT repo-relative (`worker/f{n}.md`) — the latter
    // would double the prefix to `worker/worker/f{n}.md`.
    let ckpt_paths: Vec<PathBuf> = (0..ROLLBACK_FILES)
        .map(|n| PathBuf::from(format!("f{n}.md")))
        .collect();
    ncp.create("worker", "ckpt", Some(ckpt_paths))
        .expect("241: create checkpoint");

    let stats = collect(Budget::bound(), move |_i| {
        let repo = repo.clone();
        async move {
            drift_worker(&repo); // untimed
            let rb = DefaultWorkspaceRollback::with_event_bus(
                repo.clone(),
                Arc::new(NoopBus) as Arc<dyn EventBusEmit>,
            )
            .unwrap();
            let t0 = Instant::now();
            let restored = rb
                .rollback_to_checkpoint("worker", "ckpt")
                .await
                .expect("241: rollback_to_checkpoint");
            let dt = t0.elapsed();
            assert!(
                restored.len() >= ROLLBACK_FILES - 5,
                "241: rollback-to-checkpoint restored ~{ROLLBACK_FILES} files (got {})",
                restored.len()
            );
            assert_eq!(
                std::fs::read_to_string(repo.join("worker/f0.md")).unwrap(),
                "base-0",
                "241: a restored file matches its checkpoint content"
            );
            dt
        }
    })
    .await;

    stats.report("SYS-AC-241 rollback-to-checkpoint ~100 files");
    assert!(
        stats.median_ms < 500.0,
        "SYS-AC-241: rollback-to-checkpoint median {:.3} ms must be < 500 ms",
        stats.median_ms
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// SYS-AC-191 — assemble() p95 < 500 ms (excluding embedding) [CAVEAT]
// ═══════════════════════════════════════════════════════════════════════════

const K_BODY_A: &str = "deploy-key-rotates-every-ninety-days";

fn mem_fact(id: &str, content: &str) -> MemoryEntry {
    MemoryEntry {
        id: id.into(),
        agent_id: AGENT_ID.into(),
        entry_type: MemoryType::Fact,
        content: content.into(),
        tags: vec![],
        created_at: "2026-01-01T00:00:00Z".into(),
        task_origin: None,
        is_active: true,
        superseded_by: None,
        status: MemoryStatus::Active,
        supersession_reason: None,
        cluster_id: None,
        sources: vec![],
    }
}

fn make_assembly_ctx(task: &str) -> AssemblyContext {
    AssemblyContext {
        agent_id: AGENT_ID.to_string(),
        // task_id=Some(..) → the assembler SKIPS TaskRouter→embedding (assembler.rs gates
        // routing on task_id.is_none()), so the criterion's "excluding embedding round-trips"
        // holds while the L0 + L2/L3/L4 read-path is still exercised.
        task_id: Some(task.to_string()),
        message: Message {
            id: "assemble-probe".into(),
            kind: MessageKind::User,
            from: "user:tester".into(),
            to: AGENT_ID.into(),
            payload: b"assemble probe prompt".to_vec(),
            context: Some(MessageContext {
                task_id: Some(task.to_string()),
                run_id: None,
                execution_id: None,
                trace_id: None,
                in_reply_to: None,
                correlation_id: None,
            }),
            timestamp: SystemTime::now(),
            origin: None,
        },
        prompt: "assemble probe prompt".into(),
        model: "gpt-4o-mini".into(),
        turn_buffer: vec![],
        prior_state: AgentState {
            agent_id: AGENT_ID.into(),
            status: AgentStatus::Active,
            current_task_id: Some(task.to_string()),
            current_run_id: None,
            iteration: 0,
            turn_counter: 0,
            last_handle_message_at: None,
        },
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "perf-SLO lane: see file header / IGNORE_REASON"]
async fn perf_191_assemble_p95_under_500ms() {
    let task = "perf191";
    // Seed L0 knowledge BEFORE build (the assembler-site MemoryStore is a boot snapshot).
    let dir = TempDir::new().expect("tempdir");
    {
        let store =
            MemoryStore::open(dir.path(), DEFAULT_MAX_ACTIVE_PER_AGENT).expect("seed store");
        store.insert(AGENT_ID, mem_fact("k1", K_BODY_A)).unwrap();
    }
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Memory, Cap::Llm])
        .llm(LlmMode::LoopbackScripted(vec![ScriptedResponse::ok_chat(
            &extraction_json(),
            7,
            9,
        )]))
        .with_memory_dir(dir.path().to_path_buf())
        .with_live_memory()
        .build(MEM_SKELETON)
        .await;

    // Warm the L2/L3/L4 history on disk: one UNTIMED real turn under `task` (Step-7 writes
    // tasks/{task}/summary.yaml + turn-index.yaml), so assemble() exercises the real history
    // readers too — not just L0.
    sut.inject_message_with_task("tester", task, b"seed-history-turn")
        .await;
    sut.run_turn().await;

    let assembler = sut
        .context_assembler_inner()
        .expect("191: inner ContextAssembler present under .with_live_memory()");

    // Non-vacuity (untimed): the assembled prompt carries the seeded L0 knowledge body and is
    // a real existing-task assemble — never a degenerate/empty result.
    let probe = assembler
        .assemble(make_assembly_ctx(task))
        .await
        .expect("191: assemble probe");
    let joined: String = probe
        .messages
        .iter()
        .map(|m| m.content.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        joined.contains(K_BODY_A),
        "191: assembled messages must carry the seeded L0 knowledge body (real assemble, not empty)"
    );
    assert!(!probe.is_new_task, "191: task_id=Some ⇒ existing task");
    assert!(
        probe.messages.len() >= 1,
        "191: at least one assembled message"
    );

    let stats = collect(Budget::tight(), move |_i| {
        let assembler = assembler.clone();
        async move {
            let ctx = make_assembly_ctx(task);
            let t0 = Instant::now();
            let _ = assembler.assemble(ctx).await.expect("191: assemble");
            t0.elapsed()
        }
    })
    .await;

    stats.report("SYS-AC-191 assemble() [L1/L5/L6 stub-wired — see header]");
    assert!(
        stats.p95_ms < 500.0,
        "SYS-AC-191: assemble() p95 {:.3} ms must be < 500 ms (embedding excluded via task_id=Some)",
        stats.p95_ms
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// SYS-AC-195 — pause-run → suspended guest resolves session-closed < 100 ms [CAVEAT]
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test(flavor = "multi_thread")]
#[ignore = "perf-SLO lane: see file header / IGNORE_REASON"]
async fn perf_195_pause_session_closed_under_100ms() {
    let stats = collect(Budget::tight(), |i| async move {
        // UNTIMED: fresh wired chain + a parked await-replies guest call.
        let w = step4b::Wired::build(&format!("perf195-{i}"));
        let run_id = w.run_id.clone();
        let handler = Arc::clone(&w.handler);
        let ctx = w.ctx();
        let params = step4b::single_slot_params("agent:child", "corr-1");
        let (tx, rx) = tokio::sync::oneshot::channel::<Instant>();
        let join = tokio::spawn(async move {
            let r = handler.call(ctx, params, 1).await;
            // t1 — captured INSIDE the waiter at the instant the suspended guest call
            // returns session-closed (excludes pause_run's post-close bookkeeping, which
            // runs after ar.close().await in the driver task, off this t0→t1 path).
            let t1 = Instant::now();
            let _ = tx.send(t1);
            r
        });
        step4b::wait_until(|| w.event_count("run.suspended") == 1, "run.suspended").await;

        // TIMED: pause-issued → suspended guest call resolves.
        let t0 = Instant::now();
        w.rm.pause_run(&run_id, "perf-pause".to_string())
            .await
            .expect("195: pause_run");
        let t1 = tokio::time::timeout(Duration::from_secs(5), rx)
            .await
            .expect("195: guest call did not resolve within 5 s")
            .expect("195: waiter t1");
        let _ = join.await; // untimed cleanup
        t1.saturating_duration_since(t0)
    })
    .await;

    stats.report("SYS-AC-195 pause→session-closed");
    assert!(
        stats.median_ms < 100.0,
        "SYS-AC-195: pause→session-closed median {:.3} ms must be < 100 ms (cross-task wakeup tail — re-defer if it breaches)",
        stats.median_ms
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// SYS-AC-234 — startup reconcile / index rebuild (<5 s/10K + >10K rows/min) [CAVEAT]
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test(flavor = "multi_thread")]
#[ignore = "perf-SLO lane: see file header / IGNORE_REASON"]
async fn perf_234_reconcile_10k_under_5s() {
    const N_FILES: usize = 10_000;
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Fs])
        .with_sqlite_index()
        .build(J01_SKELETON)
        .await;

    // Build a 10K-file territory OUTSIDE the timed region (internal-APFS temp).
    let territory = sut.workspace_root().join("bigterritory");
    std::fs::create_dir_all(territory.join(".agent")).expect("territory marker");
    for i in 0..N_FILES {
        std::fs::write(
            territory.join(format!("f{i}.md")),
            format!("content-{i} body text"),
        )
        .unwrap();
    }

    // Warm the page cache + the index path (discarded run).
    let _ = sut.boot_reconcile().await;

    // Median-of-3 timed reconciles (each truncates + rebuilds independently).
    let mut durs = Vec::new();
    let mut content_rows = 0u64;
    for _ in 0..3 {
        let t0 = Instant::now();
        let report = sut.boot_reconcile().await;
        durs.push(t0.elapsed());
        content_rows = report
            .rebuild_report
            .as_ref()
            .map(|r| r.content_rows)
            .unwrap_or(0);
    }
    let stats = stats_from(durs, 0);
    stats.report("SYS-AC-234 reconcile 10K");
    println!("[perf] SYS-AC-234 product content_rows = {content_rows}");

    // Product-output binding: the rebuild actually indexed the 10K-file fixture.
    assert!(
        content_rows >= N_FILES as u64,
        "234: product rebuild_report.content_rows {content_rows} must be ≥ {N_FILES} (fixture indexed)"
    );
    // Startup SLO: wall < 5 s.
    assert!(
        stats.median_ms < 5000.0,
        "SYS-AC-234: reconcile median {:.1} ms must be < 5000 ms for 10K files",
        stats.median_ms
    );
    // Rebuild rate from PRODUCT output (content_rows), not fixture size.
    let rows_per_min = (content_rows as f64) / (stats.median_ms / 1000.0 / 60.0);
    assert!(
        rows_per_min > 10_000.0,
        "SYS-AC-234: rebuild rate {rows_per_min:.0} rows/min must be > 10000/min"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// SYS-AC-246 — serialized commit throughput > 100/s (DefaultGitCommitQueue) [CAVEAT]
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test(flavor = "multi_thread")]
#[ignore = "perf-SLO lane: see file header / IGNORE_REASON"]
async fn perf_246_commit_throughput_over_100ps() {
    const M: usize = 500;
    let mut durs = Vec::new();

    // 1 warm-up batch + 3 measured batches (median-of-3); each batch is a FRESH repo.
    for batch in 0..4 {
        let td = TempDir::new().unwrap();
        let repo = td.path().to_path_buf();
        bootstrap_repo_at(&repo).unwrap();
        let sink = Arc::new(CapturingEventBus::new());
        let queue = DefaultGitCommitQueue::spawn_with_event_bus(
            repo.clone(),
            sink.clone() as Arc<dyn EventBusEmit>,
        )
        .unwrap();

        // Pre-create all M distinct files OUTSIDE the timed region, so the measured interval
        // is the commit-queue seam ONLY (submit + worker do_commit + ack), not the fixture
        // file writes. Distinct file per commit ⇒ a real fresh tree delta every iteration
        // (no same-tree no-op). `do_commit` normalizes the path relative to the workdir.
        for i in 0..M {
            std::fs::write(repo.join(format!("f{i}.txt")), format!("commit-{i}")).unwrap();
        }
        let t0 = Instant::now();
        let mut rxs = Vec::with_capacity(M);
        for i in 0..M {
            let req = CommitRequest::new(
                "agent:perf",
                format!("[turn] commit {i}"),
                vec![repo.join(format!("f{i}.txt"))],
                CommitType::Turn,
                "agent:perf",
            );
            rxs.push(queue.submit(req));
        }
        // Await every receiver: count only successful, distinct Oids (completed product
        // commits — not attempted submissions).
        let mut oids = std::collections::HashSet::new();
        for rx in rxs {
            let oid = rx
                .await
                .expect("246: commit receiver")
                .expect("246: commit Ok(Oid)");
            oids.insert(oid.to_string());
        }
        let dt = t0.elapsed();

        assert_eq!(oids.len(), M, "246: all {M} commits produced distinct Oids");
        // Product evidence: the queue emitted exactly M git.commit events.
        assert_eq!(
            sink.count("git.commit"),
            M,
            "246: queue emitted {M} git.commit events"
        );
        if batch > 0 {
            durs.push(dt);
        }
    }

    let stats = stats_from(durs, 0);
    let median_s = stats.median_ms / 1000.0;
    let throughput = (M as f64) / median_s;
    println!(
        "[perf] SYS-AC-246 commit throughput: {throughput:.0}/s (median batch of {M} in {:.1} ms)",
        stats.median_ms
    );
    assert!(
        throughput > 100.0,
        "SYS-AC-246: commit throughput {throughput:.0}/s must be > 100/s"
    );
}

//! MAINLINE harvest — shared test-side wiring for the auto-mode coordination-primitive
//! witnesses (SYS-J-11/12/59/62; SYS-AC 031-036 / 184 / 202 / 256 / 258 flipped earlier;
//! 183/185/257 flipped Wave-8 Lane A; 201 flipped Wave-14 Lane B via the real
//! evaluator-executing `ExecutingComponentMetricReader` — see `criteria_with_component_guardrail`
//! + `build_executing_evaluator_reader` below).
//!
//! Mirrors `tests/step4b_support/mod.rs`: builds the REAL chain test-side. The driver is the
//! PRODUCTION cli composition (`advance_cli::auto_wiring::build_auto_loop_driver` — real M003
//! checkpoint/rollback + the production `EventBusAutoIterationSink`/`EventBusNotifySink`
//! adapters; or `build_auto_loop_driver_with_channel_notify` via [`WireOpts::notify_channel`],
//! which installs the production `CapChannelNotifySink` for 257) reclaimed via `Arc::try_unwrap`
//! (refcount 1) and augmented with the documented harvest install-point seams
//! (`results_writer`/`skill_rollback`/`cost_tracker`) the cli leaves unwired. `auto.*` + `run.*`
//! events land in [`RecordingBus`] (a real `EventBusEmit`, the SUT `CapturingBus` role).
//!
//! The harness simulates the AGENT-side inputs (`iteration_start`/`close_iteration`/
//! `record_complete_cycle_request` — there is no guest-WASM-in-auto-loop wiring, so the agent
//! side is harness-driven for ALL auto witnesses) and plays the dormant `register_session`/
//! `request_cancel` caller via [`AutoWired::auto_tick_extension`]. The PRODUCTION auto tick
//! caller now EXISTS — `start.rs:333-344` registers the `AutoTickExtension` (wrapping the
//! `AutoTickCoordinator`) on a `Scheduler` driven by `run_scheduler_tick_loop` — so the
//! load-bearing terminal settle (`complete_run` 183 / `cancel_run_for_agent` 185) and the
//! degrade notify (`channel.raw_sent` 257) are PRODUCT-driven via `on_tick`, not the witness.
//! All ASSERTED output is real product output.

#![allow(dead_code)]

/// Wave-18 Lane 2 — the production cli skills coordinator binds to
/// `DEFAULT_AGENT_ID` (`default-agent`); the `build_bridged` chain mirrors that
/// so the record-side observer's session gate + the M003 root resolve align.
const BRIDGE_AGENT: &str = "default-agent";

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::{Arc, Mutex as StdMutex};

use async_trait::async_trait;
use git2::{Repository, Signature};
use tempfile::TempDir;

use advance_cli::auto_tick_extension::AutoTickExtension;
use advance_cli::auto_wiring::{
    build_auto_loop_driver, build_auto_loop_driver_with_channel_notify, build_auto_round_advancer,
};
use advance_cli::crash_coordinator::AutoTickCoordinator;
// Wave-18 Lane 2 — the PRODUCTION M015→M017 SkillRollback bridge + pre-activation
// observer (the cli composition-root adapters), used by `AutoWired::build_bridged`
// so the re-pointed sys_j12 witnesses drive the REAL production bridge instead of
// the test-side `RecordingRealSkillRollback`.
use advance_cli::skill_rollback_bridge::{
    build_auto_skill_rollback_bridge, build_pre_activation_observer,
};
use advance_git::{DefaultGitCommitQueue, GitCommitQueue};
use advance_run_manager::{RunConfig, RunId, RunManager};
use advance_runtime::config::{NotifyChannelConfig, WasmConfig};
use advance_runtime::ComponentRuntime;
use advance_scheduler_auto_loop::{
    config::{MetricSource, Objective, Op, Predicate, Role, SafetyValve, SuccessCriteria},
    DefaultAutoLoopDriver, EvaluatorManifest, EvaluatorSpec, IterationCloseCtx, PerIterationBudget,
    ResultsWriter, SkillRollback, SkillTrackerError,
};
use advance_shared_types::cost::RunCost;
use advance_shared_types::event::Event;
use advance_shared_types::traits::{CostTrackerQuery, EventBusEmit};
use cap_channel::OutboundTransport;
use cap_skills::provider::{SingleAgentSkillStoreProvider, SkillStoreProvider};
use cap_skills::SkillStore;
use cap_skills::{Initiator, SkillPersistenceCoordinator};
use tokio::sync::Mutex as TokioMutex;

// ---------------------------------------------------------------------------
// RecordingBus — the real EventBusEmit capture surface (auto.* + run.* events).
// ---------------------------------------------------------------------------

/// A real `EventBusEmit` that records every emission for assertion — the SUT
/// `CapturingBus` role for this harness (the production cli sinks + the real
/// `RunManager` emit through it).
#[derive(Default)]
pub struct RecordingBus {
    pub events: StdMutex<Vec<Event>>,
}

impl EventBusEmit for RecordingBus {
    fn emit(&self, event: Event) {
        self.events.lock().unwrap().push(event);
    }
}

impl RecordingBus {
    pub fn events_of(&self, event_type: &str) -> Vec<Event> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.event_type == event_type)
            .cloned()
            .collect()
    }

    pub fn event_count(&self, event_type: &str) -> usize {
        self.events_of(event_type).len()
    }

    /// Index of the first event of `event_type` in emission order (or None).
    pub fn first_index_of(&self, event_type: &str) -> Option<usize> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .position(|e| e.event_type == event_type)
    }

    /// All event types in emission order (debug aid).
    pub fn types(&self) -> Vec<String> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .map(|e| e.event_type.clone())
            .collect()
    }
}

// ---------------------------------------------------------------------------
// git helpers (copied from scheduler/auto-loop/tests/common/mod.rs — cross-crate
// test modules cannot be shared).
// ---------------------------------------------------------------------------

/// Bootstrap a single-branch (`main`) repo via advance-git, then create an
/// empty-tree initial commit on `refs/heads/main` so MODULE-003's
/// `NamedCheckpoint::create` does not hit the unborn-HEAD rejection.
pub fn bootstrap_repo_with_initial_commit(dir: &Path) {
    advance_git::bootstrap_repo_at(dir).expect("bootstrap_repo_at");
    let repo = Repository::open(dir).expect("open bootstrapped repo");
    let sig = Signature::now("runtime", "runtime@advance-agents").expect("signature");
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
    repo.set_head("refs/heads/main").expect("set_head main");
    repo.checkout_head(None).expect("checkout_head");
}

/// Write `content` to `<repo>/<rel_path>` (creating parent dirs), stage it, and
/// commit on top of HEAD. Raw libgit2 bypasses MODULE-003's path validators.
pub fn commit_file(repo_dir: &Path, rel_path: &str, content: &[u8]) {
    let abs = repo_dir.join(rel_path);
    if let Some(parent) = abs.parent() {
        std::fs::create_dir_all(parent).expect("create parent dirs");
    }
    std::fs::write(&abs, content).expect("write file");

    let repo = Repository::open(repo_dir).expect("open repo for commit_file");
    let mut idx = repo.index().expect("index");
    idx.add_path(Path::new(rel_path)).expect("index add_path");
    idx.write().expect("index write");
    let tree_oid = idx.write_tree().expect("write_tree");
    let tree = repo.find_tree(tree_oid).expect("find_tree");
    let sig = Signature::now("runtime", "runtime@advance-agents").expect("signature");
    let parent_commit = repo
        .head()
        .expect("head")
        .peel_to_commit()
        .expect("peel head to commit");
    repo.commit(
        Some("HEAD"),
        &sig,
        &sig,
        &format!("commit {rel_path}"),
        &tree,
        &[&parent_commit],
    )
    .expect("commit_file commit");
}

/// Does `full_ref` (e.g. `refs/tags/checkpoint/root/auto-iter-1`) exist?
pub fn tag_exists(repo_dir: &Path, full_ref: &str) -> bool {
    let repo = Repository::open(repo_dir).expect("open repo for tag check");
    let found = repo.find_reference(full_ref).is_ok();
    found
}

/// Count `refs/tags/checkpoint/{agent}/auto-iter-*` tags.
pub fn auto_iter_tag_count(repo_dir: &Path, agent: &str) -> usize {
    let repo = Repository::open(repo_dir).expect("open repo for tag count");
    let glob = format!("refs/tags/checkpoint/{agent}/auto-iter-*");
    let count = match repo.references_glob(&glob) {
        Ok(refs) => refs.count(),
        Err(_) => 0,
    };
    count
}

// ---------------------------------------------------------------------------
// MockCostTracker (copied verbatim from scheduler/auto-loop/tests/common/mod.rs).
// ---------------------------------------------------------------------------

/// Configurable cost per (run_id, iteration). Drives a real cost reading through
/// `check_per_iteration_budget`.
#[derive(Default)]
pub struct MockCostTracker {
    costs: HashMap<(String, u32), RunCost>,
}

impl MockCostTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_cost(mut self, run_id: &str, iteration: u32, cost: RunCost) -> Self {
        self.costs.insert((run_id.to_string(), iteration), cost);
        self
    }
}

impl CostTrackerQuery for MockCostTracker {
    fn query_run(&self, run_id: &str) -> Option<RunCost> {
        let mut acc: Option<RunCost> = None;
        for ((rid, _iter), cost) in &self.costs {
            if rid == run_id {
                let entry = acc.get_or_insert_with(RunCost::default);
                entry.tokens_in = entry.tokens_in.saturating_add(cost.tokens_in);
                entry.tokens_out = entry.tokens_out.saturating_add(cost.tokens_out);
                if cost.cost_usd.is_finite() {
                    entry.cost_usd += cost.cost_usd;
                }
                entry.request_count = entry.request_count.saturating_add(cost.request_count);
            }
        }
        acc
    }
    fn query_iteration(&self, run_id: &str, iteration: u32) -> Option<RunCost> {
        self.costs.get(&(run_id.to_string(), iteration)).cloned()
    }
}

pub fn run_cost(tokens_in: u64, tokens_out: u64, cost_usd: f64) -> RunCost {
    RunCost {
        tokens_in,
        tokens_out,
        cost_usd,
        request_count: 0,
    }
}

// ---------------------------------------------------------------------------
// RecordingRealSkillRollback — the M015->M017 bridge: RECORDS the dispatch (034)
// AND delegates to the REAL cap_skills::SkillStore mutation (034/036).
// ---------------------------------------------------------------------------

/// A single recorded auto-loop skill-rollback dispatch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecordedCall {
    Rollback {
        skill_id: String,
        target_version: u32,
    },
    Delete {
        skill_id: String,
    },
}

/// Faithful M015->M017 bridge. The auto-loop `SkillRollback` trait carries
/// `agent_id`; the single test SkillStore is per-agent (`"root"`), so the
/// adapter DROPS `agent_id` and delegates to the REAL `SkillStore::rollback` /
/// `delete` (the actual M017 mutation — NOT a no-op). Records each call for the
/// 034 dispatch assertion.
pub struct RecordingRealSkillRollback {
    store: Arc<SkillStore>,
    calls: StdMutex<Vec<RecordedCall>>,
}

impl RecordingRealSkillRollback {
    pub fn new(store: Arc<SkillStore>) -> Self {
        Self {
            store,
            calls: StdMutex::new(Vec::new()),
        }
    }

    pub fn calls(&self) -> Vec<RecordedCall> {
        self.calls.lock().unwrap().clone()
    }
}

#[async_trait]
impl SkillRollback for RecordingRealSkillRollback {
    async fn rollback_skill(
        &self,
        _agent_id: &str,
        skill_id: &str,
        target_version: u32,
    ) -> Result<(), SkillTrackerError> {
        self.calls.lock().unwrap().push(RecordedCall::Rollback {
            skill_id: skill_id.to_string(),
            target_version,
        });
        self.store
            .rollback(skill_id, target_version)
            .await
            .map_err(|e| SkillTrackerError::Rollback(format!("rollback {skill_id}: {e}")))
    }

    async fn delete_skill(&self, _agent_id: &str, skill_id: &str) -> Result<(), SkillTrackerError> {
        self.calls.lock().unwrap().push(RecordedCall::Delete {
            skill_id: skill_id.to_string(),
        });
        self.store
            .delete(skill_id)
            .await
            .map_err(|e| SkillTrackerError::Rollback(format!("delete {skill_id}: {e}")))
    }
}

// ---------------------------------------------------------------------------
// Criteria + IterationCloseCtx builders (mirror the auto-loop test cribs).
// ---------------------------------------------------------------------------

/// Primary-only criteria with comparison `op` (Op::Lt = lower-is-better).
pub fn primary_criteria(op: Op) -> SuccessCriteria {
    SuccessCriteria {
        evaluator: None,
        objectives: vec![Objective {
            name: "val-bpb".to_string(),
            role: Role::Primary,
            metric_source: MetricSource::File {
                path: "metrics/bpb.json".to_string(),
                key: "val_bpb".to_string(),
            },
            predicate: Predicate {
                op,
                threshold: None,
            },
        }],
        per_iteration_budget: None,
        fail_fast: None,
        safety_valve: None,
    }
}

/// Op::Lt primary criteria with a `SafetyValve` (256/258).
pub fn criteria_with_safety_valve(sv: SafetyValve) -> SuccessCriteria {
    let mut c = primary_criteria(Op::Lt);
    c.safety_valve = Some(sv);
    c
}

/// Op::Lt primary criteria with a per-iteration budget (202).
pub fn criteria_with_budget(budget: PerIterationBudget) -> SuccessCriteria {
    let mut c = primary_criteria(Op::Lt);
    c.per_iteration_budget = Some(budget);
    c
}

/// Build an `IterationCloseCtx`. `primary` None → no metric (discard); Some →
/// keep/discard decided by improvement vs `previous_best`. `crashed` → crash arm.
pub fn close_ctx(agent: &str, iter: u32, primary: Option<f64>, crashed: bool) -> IterationCloseCtx {
    let mut metrics = BTreeMap::new();
    if let Some(m) = primary {
        metrics.insert("val_bpb".to_string(), m);
    }
    IterationCloseCtx {
        agent_id: agent.to_string(),
        run_id: Some(format!("run-{agent}")),
        iteration: iter,
        checkpoint_label: format!("auto-iter-{iter}"),
        primary_metric: primary,
        metrics,
        crashed,
        crash_reason: if crashed {
            Some("boom".to_string())
        } else {
            None
        },
        summary: Some(format!("iter-{iter}")),
        cost_usd: 0.01,
        wall_time_sec: 1,
    }
}

// ---------------------------------------------------------------------------
// AutoWired — the fully-wired real chain for a witness.
// ---------------------------------------------------------------------------

/// Opt-in harvest-install-point seams to augment the cli-built driver with.
#[derive(Default)]
pub struct WireOpts {
    /// `.with_results_writer(ResultsWriter::new(ws))` (033/036/202; 183/184-partial).
    pub results: bool,
    /// Build a real `SkillStore` + `RecordingRealSkillRollback` and
    /// `.with_skill_rollback(...)` (034/035/036).
    pub skill_rollback: bool,
    /// `.with_cost_tracker(...)` (202).
    pub cost: Option<Arc<MockCostTracker>>,
    /// 257 — build the driver through the PRODUCTION
    /// `build_auto_loop_driver_with_channel_notify` config-sourcing path, which installs
    /// `CapChannelNotifySink` (→ `channel.raw_sent`) REPLACING the `EventBusNotifySink`
    /// (→ `auto.notify`) default. Tuple = (event-bus-wired egress transport, owner agent
    /// id, `channels.notify` config). This is the WITNESS-FLOOR-strict 257 install: the
    /// PRODUCTION fn installs the sink, not an inline `.with_notify_sink` harness swap
    /// (which the adversarial-r6 round refuted as a harness-only install).
    pub notify_channel: Option<(Arc<dyn OutboundTransport>, String, NotifyChannelConfig)>,
}

pub struct AutoWired {
    pub tmp: TempDir,
    pub bus: Arc<RecordingBus>,
    pub driver: Arc<DefaultAutoLoopDriver>,
    pub rm: Arc<RunManager>,
    /// Present only when `WireOpts.skill_rollback` was set (the legacy `build`
    /// path with the test-side `RecordingRealSkillRollback`).
    pub skill_store: Option<Arc<SkillStore>>,
    pub skill_rollback: Option<Arc<RecordingRealSkillRollback>>,
    /// Wave-18 Lane 2 (`build_bridged` only): the disk-backed shared `SkillStore`
    /// (`provider.get()`) the PRODUCTION bridge + coordinator operate on.
    pub skill_shared: Option<Arc<TokioMutex<SkillStore>>>,
    /// Wave-18 Lane 2 (`build_bridged` only): the production
    /// `SkillPersistenceCoordinator` (AutoLoop micro lane via the bridge;
    /// record-side observer attached, forwarding to `driver`).
    pub skill_coordinator: Option<Arc<SkillPersistenceCoordinator>>,
    /// Wave-18 Lane 2 (`build_bridged` only): the real git commit queue backing
    /// the coordinator (held so its `Drop` drains the worker after assertions).
    pub skill_queue: Option<Arc<DefaultGitCommitQueue>>,
}

impl AutoWired {
    /// Build the real chain: a temp git repo (born HEAD + a `work.txt` baseline),
    /// the production cli driver augmented with the opted-in seams, and a real
    /// `RunManager` with the production auto round-advancer. Agent id is `"root"`
    /// so `DefaultWorkspaceRollback` resolves to the workdir root sentinel.
    pub fn build(opts: WireOpts) -> Self {
        let tmp = tempfile::tempdir().expect("tempdir");
        bootstrap_repo_with_initial_commit(tmp.path());
        commit_file(tmp.path(), "work.txt", b"baseline");

        let bus = Arc::new(RecordingBus::default());
        let bus_dyn: Arc<dyn EventBusEmit> = bus.clone();

        // Production composition root — real M003 checkpoint/rollback + the
        // production EventBusAutoIterationSink/EventBusNotifySink (events -> bus).
        // 257: when `notify_channel` is set, build through the PRODUCTION
        // `build_auto_loop_driver_with_channel_notify` so the config-sourcing path
        // installs `CapChannelNotifySink` (replacing EventBusNotifySink) — the
        // witness-floor-strict sink install, not a harness `.with_notify_sink` swap.
        // Both `build_*` fns return a still-UNIQUE Arc, so the augment `try_unwrap`
        // below succeeds in either branch.
        let arc = if let Some((transport, owner, cfg)) = &opts.notify_channel {
            build_auto_loop_driver_with_channel_notify(
                tmp.path(),
                bus_dyn,
                Arc::clone(transport),
                owner,
                cfg,
            )
            .expect("notify config valid")
            .expect("workspace is a git repo")
        } else {
            build_auto_loop_driver(tmp.path(), bus_dyn).expect("workspace is a git repo")
        };
        let mut driver = match Arc::try_unwrap(arc) {
            Ok(d) => d,
            Err(_) => panic!("driver Arc not unique — cannot augment"),
        };

        if opts.results {
            driver =
                driver.with_results_writer(Arc::new(ResultsWriter::new(tmp.path().to_path_buf())));
        }

        let (skill_store, skill_rollback) = if opts.skill_rollback {
            let store = Arc::new(SkillStore::new());
            let rec = Arc::new(RecordingRealSkillRollback::new(Arc::clone(&store)));
            driver = driver.with_skill_rollback(Arc::clone(&rec) as Arc<dyn SkillRollback>);
            (Some(store), Some(rec))
        } else {
            (None, None)
        };

        if let Some(c) = &opts.cost {
            driver = driver.with_cost_tracker(Arc::clone(c) as Arc<dyn CostTrackerQuery>);
        }

        // (257's CapChannelNotifySink is installed by build_auto_loop_driver_with_channel_notify
        // above — the production config-sourcing path — not by an inline post-build swap.)

        let driver = Arc::new(driver);
        let rm = Arc::new(
            RunManager::new(bus.clone() as Arc<dyn EventBusEmit>)
                .with_round_advancer(build_auto_round_advancer(Arc::clone(&driver))),
        );

        Self {
            tmp,
            bus,
            driver,
            rm,
            skill_store,
            skill_rollback,
            skill_shared: None,
            skill_coordinator: None,
            skill_queue: None,
        }
    }

    /// Wave-18 Lane 2 — build the chain with the REAL production SkillRollback
    /// bridge wired over the Arc'd driver (the cli `wire_capabilities`
    /// composition: OnceLock late-bind `set_skill_rollback` + a
    /// `SkillPersistenceCoordinator` carrying the record-side
    /// `DriverPreActivationObserver`). Mirrors production exactly: ONE disk-backed
    /// `SkillStore` rooted at `<ws>/.agent` (`provider.get()`), a real
    /// `DefaultGitCommitQueue`, the `default-agent` binding, and a
    /// `.agent/config.yaml` so the M003 FullDirectory rollback resolves the
    /// `default-agent` root to the workspace root. The re-pointed sys_j12
    /// witnesses drive THIS — NOT the test-side `RecordingRealSkillRollback`.
    ///
    /// `WireOpts.skill_rollback` is ignored here (always bridged); `results` and
    /// the other seams are honored via the base `build`.
    pub async fn build_bridged(opts: WireOpts) -> Self {
        // Base chain WITHOUT the legacy skill seam — the production bridge is
        // wired below over the Arc'd driver via the OnceLock late-bind, exactly
        // like the cli `wire_capabilities` skills arm.
        let mut w = Self::build(WireOpts {
            skill_rollback: false,
            ..opts
        });

        let ws = w.tmp.path().to_path_buf();
        let agent_root = ws.join(".agent");
        std::fs::create_dir_all(&agent_root).expect("mk .agent");
        // The M003 `DefaultWorkspaceRollback` resolves `default-agent` → the
        // workspace root only when `<ws>/.agent/config.yaml` declares it (else
        // only the `"root"` sentinel maps to the workdir). `.agent/**` is excluded
        // from the rollback, so this untracked file survives a discard.
        std::fs::write(
            agent_root.join("config.yaml"),
            format!("agent_id: {BRIDGE_AGENT}\n"),
        )
        .expect("write .agent/config.yaml");

        // Disk-backed shared store (production parity): provider rooted at
        // `<ws>/.agent`; DiskSkillStorage appends `.agent/skills`.
        let provider = SingleAgentSkillStoreProvider::new(BRIDGE_AGENT, agent_root.clone());
        let shared = provider
            .get(BRIDGE_AGENT)
            .await
            .expect("single-agent provider resolves its own id");

        // Real git commit queue over the workspace (born-HEAD bootstrap ran in
        // `build`). Bus-wired so each commit emits `git.commit`.
        let queue = Arc::new(
            DefaultGitCommitQueue::spawn_with_event_bus(
                ws.clone(),
                w.bus.clone() as Arc<dyn EventBusEmit>,
            )
            .expect("spawn git commit queue"),
        );
        let queue_trait: Arc<dyn GitCommitQueue> = queue.clone();

        // Coordinator on the AutoLoop micro lane (via the bridge) + the
        // record-side observer forwarding to THIS driver — the production
        // composition (cli `wiring.rs` `Some(queue)` skills arm).
        let observer = build_pre_activation_observer(&w.driver);
        let coordinator = Arc::new(
            SkillPersistenceCoordinator::with_shared_store(
                BRIDGE_AGENT.to_string(),
                agent_root,
                Arc::clone(&shared),
                queue_trait,
                w.bus.clone() as Arc<dyn EventBusEmit>,
            )
            .with_pre_activation_observer(observer),
        );
        // OnceLock late-bind: the driver Arc was already cloned into the
        // round-advancer in `build`; the set is visible through every clone.
        w.driver
            .set_skill_rollback(build_auto_skill_rollback_bridge(
                Arc::clone(&coordinator),
                Arc::clone(&shared),
            ));

        w.skill_shared = Some(shared);
        w.skill_coordinator = Some(coordinator);
        w.skill_queue = Some(queue);
        w
    }

    /// Activate skill `name` (proposing a fresh draft carrying `marker`) through
    /// the production coordinator turn lane — the agent-activate path that fires
    /// the record-side observer. Returns the new active version. Only valid on a
    /// `build_bridged` chain.
    pub async fn coord_activate(&self, name: &str, marker: &str) -> u32 {
        let shared = self.skill_shared.as_ref().expect("build_bridged chain");
        let coordinator = self
            .skill_coordinator
            .as_ref()
            .expect("build_bridged chain");
        // Valid SKILL.md: the `marker` lands in the description + body so distinct
        // versions are content-distinguishable.
        let content = format!("---\nname: {name}\ndescription: {marker}\n---\n# {marker}\n");
        let draft_id = {
            let g = shared.lock().await;
            g.propose_draft(name.to_string(), content, vec![])
                .await
                .expect("propose_draft")
        };
        coordinator
            .activate_skill_with_persistence(
                Initiator::Agent {
                    id: BRIDGE_AGENT.to_string(),
                },
                &draft_id,
                "agent activate",
            )
            .await
            .expect("activate")
            .version
    }

    /// Current active version of `name` on the bridged shared store (`None` ⇒
    /// absent).
    pub async fn coord_version(&self, name: &str) -> Option<u32> {
        let shared = self.skill_shared.as_ref().expect("build_bridged chain");
        let g = shared.lock().await;
        g.get(name).await.ok().map(|s| s.version)
    }

    /// Current active content of `name` on the bridged shared store (`None` ⇒
    /// absent).
    pub async fn coord_content(&self, name: &str) -> Option<String> {
        let shared = self.skill_shared.as_ref().expect("build_bridged chain");
        let g = shared.lock().await;
        g.get(name).await.ok().map(|s| s.content)
    }

    pub fn ws(&self) -> &Path {
        self.tmp.path()
    }

    pub fn tag(&self, agent: &str, n: u32) -> String {
        format!("refs/tags/checkpoint/{agent}/auto-iter-{n}")
    }

    /// Build the PRODUCTION auto tick caller over THIS wired chain — the
    /// `AutoTickCoordinator` (Wave-6 Lane C; owns the same driver + this `rm`) wrapped
    /// in the `AutoTickExtension` (Wave-7 Lane B; the `SchedulerExtension` the daemon
    /// registers at `start.rs:333-344`). Mirrors the production composition exactly: the
    /// coordinator + extension share the SAME `driver` Arc this `AutoWired` built (and
    /// whose auto round-advancer was cloned into `self.rm`).
    ///
    /// The witness plays ONLY the dormant `register_session` / `request_cancel` caller
    /// (the un-wired `advance auto start`/`cancel` boot install points — the
    /// 098/101/109 no-production-caller precedent). The returned extension's `on_tick`
    /// drives `coordinator.settle_completed` (183) / `cancel` (185); THOSE make the
    /// load-bearing `RunManager::complete_run` / `cancel_run_for_agent` calls — never
    /// the witness (the witness-floor invariant for the re-pointed 183/185 flips).
    pub fn auto_tick_extension(&self) -> Arc<AutoTickExtension> {
        let coordinator = Arc::new(AutoTickCoordinator::new(
            Arc::clone(&self.driver),
            Arc::clone(&self.rm),
        ));
        Arc::new(AutoTickExtension::new(
            Arc::clone(&self.driver),
            coordinator,
        ))
    }

    /// Mint the `auto:{agent}` Run and register the run_id -> agent_id mapping so
    /// the production round-advancer routes it (the 183/185 settle keys on this
    /// RunManager-minted `run-{uuid}`).
    pub fn mint_auto_run(&self, agent: &str) -> RunId {
        let rid = self
            .rm
            .ensure_run(&format!("auto:{agent}"), "root", RunConfig::default())
            .expect("ensure_run");
        self.driver
            .register_run(rid.as_ref(), agent)
            .expect("register_run");
        rid
    }
}

// ---------------------------------------------------------------------------
// Wave-14 Lane B (SYS-AC-201) — component-guardrail criteria + the production
// evaluator-executing ComponentMetricReader builder.
// ---------------------------------------------------------------------------

/// Criteria with a `Role::Primary` File objective + ONE `Role::Guardrail`
/// `MetricSource::Component{output_key}` objective. `per_iteration_budget: None`
/// so `run_guarded_iteration`'s budget branch is a no-op (`check_budget(None) ->
/// Ok`) and control reaches the guardrail branch. `evaluator: Some(...)` is
/// REQUIRED — `SuccessCriteria::validate()` (called by `driver.start`) rejects a
/// `MetricSource::Component` objective when `evaluator` is `None`
/// (`AutoLoopError::MissingEvaluator`); the ref string is just a config label
/// (the reader is handed the resolved spec directly, bypassing resolution).
pub fn criteria_with_component_guardrail(
    output_key: &str,
    op: Op,
    threshold: f64,
) -> SuccessCriteria {
    SuccessCriteria {
        evaluator: Some("test-evaluator@0.0.0/eval".to_string()),
        objectives: vec![
            Objective {
                name: "val-bpb".to_string(),
                role: Role::Primary,
                metric_source: MetricSource::File {
                    path: "metrics/bpb.json".to_string(),
                    key: "val_bpb".to_string(),
                },
                predicate: Predicate {
                    op: Op::Lt,
                    threshold: None,
                },
            },
            Objective {
                name: "guardrail-score".to_string(),
                role: Role::Guardrail,
                metric_source: MetricSource::Component {
                    output_key: output_key.to_string(),
                },
                predicate: Predicate {
                    op,
                    threshold: Some(threshold),
                },
            },
        ],
        per_iteration_budget: None,
        fail_fast: None,
        safety_valve: None,
    }
}

/// Build the PRODUCTION `ExecutingComponentMetricReader` over a REAL
/// `ComponentRuntime` + a committed evaluator fixture core module
/// (`fixture_core_bytes`). The reader normalizes core→Component itself, so the
/// RAW core bytes are passed as `EvaluatorSpec.binary`. The returned reader has
/// already executed the fixture's `run()` and cached its output JSON — pass it
/// straight to `run_guarded_iteration` (whose `read_component_metric` is sync).
pub async fn build_executing_evaluator_reader(
    fixture_core_bytes: &[u8],
) -> advance_cli::evaluator_reader::ExecutingComponentMetricReader {
    let runtime = ComponentRuntime::new(&WasmConfig {
        max_memory_pages: 256,
        epoch_interruption_ms: 100,
        fuel_enabled: false,
    })
    .expect("construct ComponentRuntime");
    let spec = EvaluatorSpec {
        binary: fixture_core_bytes.to_vec(),
        capabilities: Vec::new(),
        output_dir: std::path::PathBuf::new(),
        manifest: EvaluatorManifest {
            component_type: "task".to_string(),
            has_binary: true,
            trigger_present: false,
            raw_yaml: String::new(),
        },
    };
    advance_cli::evaluator_reader::ExecutingComponentMetricReader::run(
        &runtime,
        &spec,
        "auto-eval:root:iter-1",
        "trace-201",
    )
    .await
    .expect("evaluator reader: execute fixture + parse output JSON")
}

/// Like [`build_executing_evaluator_reader`] but returns the `Result` and takes
/// explicit `capabilities`, so a witness can assert the no-caps fail-CLOSED reject
/// (adversarial round-8 W3: the capability trust boundary is explicit, not relying
/// on an opaque LinkerTypecheck trap).
pub async fn try_build_evaluator_reader_with_caps(
    fixture_core_bytes: &[u8],
    capabilities: Vec<advance_shared_types::capability::CapRequest>,
) -> Result<
    advance_cli::evaluator_reader::ExecutingComponentMetricReader,
    advance_scheduler_auto_loop::MetricReadError,
> {
    let runtime = ComponentRuntime::new(&WasmConfig {
        max_memory_pages: 256,
        epoch_interruption_ms: 100,
        fuel_enabled: false,
    })
    .expect("construct ComponentRuntime");
    let spec = EvaluatorSpec {
        binary: fixture_core_bytes.to_vec(),
        capabilities,
        output_dir: std::path::PathBuf::new(),
        manifest: EvaluatorManifest {
            component_type: "task".to_string(),
            has_binary: true,
            trigger_present: false,
            raw_yaml: String::new(),
        },
    };
    advance_cli::evaluator_reader::ExecutingComponentMetricReader::run(
        &runtime,
        &spec,
        "auto-eval:root:iter-1",
        "trace-201",
    )
    .await
}

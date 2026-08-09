//! Shared test fixtures for the auto-loop integration tests.
//!
//! `git2` is a TEST-ONLY dev-dependency here (production code in this crate
//! never imports it — Git access goes through advance-git's
//! CONTRACT-020/021/022 surface per MODULE-003 §1.1). Building initial
//! commits / committing files / reading raw tag messages in tests via
//! libgit2 is the same pattern MODULE-003's own tests use.

#![allow(dead_code)] // helpers are used à la carte across test files

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use advance_scheduler::{ComponentEvent, SchedulerExtension, SchedulerTick};
use std::collections::HashMap;
use std::sync::Mutex;

use advance_scheduler_auto_loop::{
    AutoBootstrapApplier, AutoBootstrapApplierError, AutoBootstrapEventSink,
    AutoBootstrapSinkError, AutoEventSinkError, AutoIterationEventPayload, AutoIterationEventSink,
    AutoLoopError, AutoStateReader, BootstrapEventPayload, CompletionSummary, EvaluatorManifest,
    EvaluatorResolveError, EvaluatorResolver, EvaluatorSpec, IterationCheckpoint,
    IterationRollback, IterationStatus, M015BootstrapReport, NotifySink, NotifySinkError,
    RunBudgetSource, SkillRollback, SkillTrackerError,
};
use advance_shared_types::capability::BudgetDecision;
use advance_shared_types::cost::RunCost;
use advance_shared_types::traits::CostTrackerQuery;
use async_trait::async_trait;
use git2::{Repository, Signature};

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
    // Point HEAD at main + reset the working tree so the repo is in a
    // clean, born state.
    repo.set_head("refs/heads/main").expect("set_head main");
    repo.checkout_head(None).expect("checkout_head");
}

/// Write `content` to `<repo>/<rel_path>` (creating parent dirs), stage it,
/// and commit on top of HEAD. Works for nested paths like
/// `.agent/keep.txt` — raw libgit2 bypasses MODULE-003's
/// `validate_create_path` (which only guards path-scoped
/// `NamedCheckpoint::create`, NOT arbitrary commits).
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

/// Read a raw annotated-tag message via git2 (the `NamedCheckpoint::list`
/// `CheckpointEntry` exposes only parsed `paths`/`valid`, not the raw
/// message — round-5 W3).
pub fn read_tag_message(repo_dir: &Path, full_ref: &str) -> String {
    let repo = Repository::open(repo_dir).expect("open repo for tag read");
    let r = repo.find_reference(full_ref).expect("find tag ref");
    let tag = r
        .peel_to_tag()
        .expect("peel_to_tag (expected annotated tag)");
    tag.message().expect("tag message").trim().to_string()
}

pub fn tag_exists(repo_dir: &Path, full_ref: &str) -> bool {
    let repo = Repository::open(repo_dir).expect("open repo for tag check");
    let found = repo.find_reference(full_ref).is_ok();
    found
}

// ---- Test doubles ----

/// `IterationCheckpoint` double that always succeeds (used by the
/// CONTRACT-140 start/stop/status test where no real git is needed).
pub struct NoopIterationCheckpoint;

#[async_trait]
impl IterationCheckpoint for NoopIterationCheckpoint {
    async fn checkpoint_baseline(&self, _agent_id: &str) -> Result<(), AutoLoopError> {
        Ok(())
    }
    async fn checkpoint_iteration(&self, _agent_id: &str, _n: u32) -> Result<(), AutoLoopError> {
        Ok(())
    }
}

/// `IterationRollback` double that always succeeds.
pub struct NoopIterationRollback;

#[async_trait]
impl IterationRollback for NoopIterationRollback {
    async fn rollback_iteration(&self, _agent_id: &str, _n: u32) -> Result<(), AutoLoopError> {
        Ok(())
    }
}

/// Minimal `SchedulerExtension` double that bumps a shared counter on every
/// tick — the defense-in-depth proof that `Scheduler::dispatch_tick` fans
/// out to EVERY registered extension, not just the first.
pub struct CountingExtension {
    name: String,
    pub ticks: Arc<AtomicUsize>,
    pub events: Arc<AtomicUsize>,
}

impl CountingExtension {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            ticks: Arc::new(AtomicUsize::new(0)),
            events: Arc::new(AtomicUsize::new(0)),
        }
    }
}

#[async_trait]
impl SchedulerExtension for CountingExtension {
    fn name(&self) -> &str {
        &self.name
    }
    async fn on_tick(&self, _tick: SchedulerTick) {
        self.ticks.fetch_add(1, Ordering::Relaxed);
    }
    async fn on_component_event(&self, _event: ComponentEvent) {
        self.events.fetch_add(1, Ordering::Relaxed);
    }
}

// ---- Slice-B test doubles ----

/// Slice-B test double for AC-19 evidence path. Records every
/// `resolve_evaluator` call into a shared `AtomicUsize` counter so tests can
/// assert that the manual-cancel path NEVER invokes the evaluator.
///
/// Used by `tests/state_machine.rs` (manual cancel test): the test wires
/// this into `DefaultAutoLoopDriver::with_evaluator_resolver`, calls
/// `start` + `handle_manual_cancel`, and asserts `counter == 0`.
pub struct RecordingEvaluatorResolver {
    pub counter: Arc<AtomicUsize>,
}

impl RecordingEvaluatorResolver {
    pub fn new() -> Self {
        Self {
            counter: Arc::new(AtomicUsize::new(0)),
        }
    }
}

#[async_trait]
impl EvaluatorResolver for RecordingEvaluatorResolver {
    async fn resolve_evaluator(
        &self,
        fq_ref: &str,
    ) -> Result<EvaluatorSpec, EvaluatorResolveError> {
        self.counter.fetch_add(1, Ordering::Relaxed);
        Err(EvaluatorResolveError::NotFound(fq_ref.to_string()))
    }
}

// ---- Slice-C test doubles ----

/// Slice-C test double for AC-18 / AC-21 SkillTracker integration. Records
/// every `rollback_skill` / `delete_skill` call into a shared Vec so tests
/// can assert the exact call sequence (agent_id, skill_id, target_version).
#[derive(Clone, Default)]
pub struct RecordingSkillRollback {
    calls: Arc<Mutex<Vec<RecordedCall>>>,
}

/// Single recorded call from `RecordingSkillRollback`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecordedCall {
    Rollback {
        agent_id: String,
        skill_id: String,
        target_version: u32,
    },
    Delete {
        agent_id: String,
        skill_id: String,
    },
}

impl RecordingSkillRollback {
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot of all calls observed so far.
    pub fn calls(&self) -> Vec<RecordedCall> {
        self.calls
            .lock()
            .expect("RecordingSkillRollback mutex")
            .clone()
    }
}

#[async_trait]
impl SkillRollback for RecordingSkillRollback {
    async fn rollback_skill(
        &self,
        agent_id: &str,
        skill_id: &str,
        target_version: u32,
    ) -> Result<(), SkillTrackerError> {
        self.calls
            .lock()
            .expect("RecordingSkillRollback mutex")
            .push(RecordedCall::Rollback {
                agent_id: agent_id.to_string(),
                skill_id: skill_id.to_string(),
                target_version,
            });
        Ok(())
    }

    async fn delete_skill(&self, agent_id: &str, skill_id: &str) -> Result<(), SkillTrackerError> {
        self.calls
            .lock()
            .expect("RecordingSkillRollback mutex")
            .push(RecordedCall::Delete {
                agent_id: agent_id.to_string(),
                skill_id: skill_id.to_string(),
            });
        Ok(())
    }
}

/// Slice-C test double that returns `Err` for a configurable skill_id and
/// `Ok` otherwise — used to verify SkillTracker partial-drain semantics
/// (audit Round-1 W1 fix). Calls are recorded just like
/// `RecordingSkillRollback` so tests can assert exactly which entries
/// were attempted before the short-circuit.
#[derive(Clone)]
pub struct FailingSkillRollback {
    fail_on: String,
    calls: Arc<Mutex<Vec<RecordedCall>>>,
}

impl FailingSkillRollback {
    pub fn fail_on(skill_id: &str) -> Self {
        Self {
            fail_on: skill_id.to_string(),
            calls: Arc::new(Mutex::new(Vec::new())),
        }
    }
    pub fn calls(&self) -> Vec<RecordedCall> {
        self.calls
            .lock()
            .expect("FailingSkillRollback mutex")
            .clone()
    }
}

#[async_trait]
impl SkillRollback for FailingSkillRollback {
    async fn rollback_skill(
        &self,
        agent_id: &str,
        skill_id: &str,
        target_version: u32,
    ) -> Result<(), SkillTrackerError> {
        self.calls
            .lock()
            .expect("FailingSkillRollback mutex")
            .push(RecordedCall::Rollback {
                agent_id: agent_id.to_string(),
                skill_id: skill_id.to_string(),
                target_version,
            });
        if skill_id == self.fail_on {
            Err(SkillTrackerError::Rollback(format!(
                "configured failure on skill_id={skill_id}"
            )))
        } else {
            Ok(())
        }
    }

    async fn delete_skill(&self, agent_id: &str, skill_id: &str) -> Result<(), SkillTrackerError> {
        self.calls
            .lock()
            .expect("FailingSkillRollback mutex")
            .push(RecordedCall::Delete {
                agent_id: agent_id.to_string(),
                skill_id: skill_id.to_string(),
            });
        if skill_id == self.fail_on {
            Err(SkillTrackerError::Rollback(format!(
                "configured failure on skill_id={skill_id}"
            )))
        } else {
            Ok(())
        }
    }
}

/// Slice-C test double for [`AutoStateReader`] — composes the four reads
/// (agent_id_for_run, complete_cycle_request, last_iteration_status,
/// budget_decision) from configurable HashMaps. Test files construct one
/// via [`MockAutoStateReader::new`] then call `.with_*()` methods to seed
/// the maps before passing the reader to `AutoLoopRoundAdvancer::new`.
#[derive(Default)]
pub struct MockAutoStateReader {
    pub agent_for_run: HashMap<String, String>,
    pub complete_cycle_for_agent: HashMap<String, CompletionSummary>,
    pub status_for_agent: HashMap<String, IterationStatus>,
    pub budget_decision_for: HashMap<String, BudgetDecision>,
}

impl MockAutoStateReader {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_agent_for_run(mut self, run_id: &str, agent_id: &str) -> Self {
        self.agent_for_run
            .insert(run_id.to_string(), agent_id.to_string());
        self
    }

    pub fn with_complete_cycle(mut self, agent_id: &str, summary: CompletionSummary) -> Self {
        self.complete_cycle_for_agent
            .insert(agent_id.to_string(), summary);
        self
    }

    pub fn with_status(mut self, agent_id: &str, status: IterationStatus) -> Self {
        self.status_for_agent.insert(agent_id.to_string(), status);
        self
    }

    pub fn with_budget(mut self, run_id: &str, decision: BudgetDecision) -> Self {
        self.budget_decision_for
            .insert(run_id.to_string(), decision);
        self
    }
}

impl AutoStateReader for MockAutoStateReader {
    fn agent_id_for_run(&self, run_id: &str) -> Option<String> {
        self.agent_for_run.get(run_id).cloned()
    }
    fn complete_cycle_request(&self, agent_id: &str) -> Option<CompletionSummary> {
        self.complete_cycle_for_agent.get(agent_id).cloned()
    }
    fn last_iteration_status(&self, agent_id: &str) -> Option<IterationStatus> {
        self.status_for_agent.get(agent_id).copied()
    }
    fn budget_decision(&self, run_id: &str, _agent_id: &str) -> BudgetDecision {
        self.budget_decision_for
            .get(run_id)
            .cloned()
            .unwrap_or(BudgetDecision::Allow)
    }
}

/// Slice-C test double for AC-08: returns Ok(EvaluatorSpec) carrying a
/// VIOLATING `EvaluatorManifest`. Parameterized by the violation variant
/// the spec should carry (the test then calls
/// `validate_constraint_surface(&spec.manifest)` and asserts the
/// expected `ConstraintViolation`).
///
/// Distinct from `RecordingEvaluatorResolver`, which always returns
/// `Err(NotFound)`.
pub struct ViolatingEvaluatorResolver {
    manifest: EvaluatorManifest,
}

impl ViolatingEvaluatorResolver {
    /// Manifest with `component_type="agent"` → triggers `WrongComponentType("agent")`.
    pub fn wrong_component_type() -> Self {
        Self {
            manifest: EvaluatorManifest {
                component_type: "agent".to_string(),
                has_binary: true,
                trigger_present: false,
                raw_yaml: String::new(),
            },
        }
    }

    /// Manifest with `trigger_present=true` → triggers `TriggerPresent`.
    pub fn trigger_present() -> Self {
        Self {
            manifest: EvaluatorManifest {
                component_type: "task".to_string(),
                has_binary: true,
                trigger_present: true,
                raw_yaml: String::new(),
            },
        }
    }

    /// Manifest with `has_binary=false` → triggers `NoBinary`.
    pub fn no_binary() -> Self {
        Self {
            manifest: EvaluatorManifest {
                component_type: "task".to_string(),
                has_binary: false,
                trigger_present: false,
                raw_yaml: String::new(),
            },
        }
    }
}

#[async_trait]
impl EvaluatorResolver for ViolatingEvaluatorResolver {
    async fn resolve_evaluator(
        &self,
        _fq_ref: &str,
    ) -> Result<EvaluatorSpec, EvaluatorResolveError> {
        Ok(EvaluatorSpec {
            binary: vec![0u8; 4], // satisfy has_binary contract for the spec wrapper
            capabilities: Vec::new(),
            output_dir: std::path::PathBuf::from("/tmp/violating-eval"),
            manifest: self.manifest.clone(),
        })
    }
}

/// Slice-C test double for AC-08 / AC-09 positive path: returns
/// Ok(EvaluatorSpec) carrying a CONFORMANT `EvaluatorManifest`
/// (`component_type="task"`, `has_binary=true`, `trigger_present=false`).
pub struct ValidSpecEvaluatorResolver;

#[async_trait]
impl EvaluatorResolver for ValidSpecEvaluatorResolver {
    async fn resolve_evaluator(
        &self,
        _fq_ref: &str,
    ) -> Result<EvaluatorSpec, EvaluatorResolveError> {
        Ok(EvaluatorSpec {
            binary: vec![0u8; 16],
            capabilities: Vec::new(),
            output_dir: std::path::PathBuf::from("/tmp/valid-eval"),
            manifest: EvaluatorManifest {
                component_type: "task".to_string(),
                has_binary: true,
                trigger_present: false,
                raw_yaml: String::new(),
            },
        })
    }
}

/// Slice-C test double for AC-02: configurable cost per (run_id, iteration)
/// tuple. Lets the budget-independence test drive a real cost reading
/// through `check_per_iteration_budget`.
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
        // Sum across all iterations for this run. The slice-C tests don't
        // exercise this path (only `check_per_iteration_budget` uses
        // `query_iteration`), but the trait requires the method.
        // Audit Round-1 W4 fix: `cost_usd` direct `+=` propagates
        // NaN/Infinity. The slice-B production `RunCost.cost_usd` field
        // is normally finite, but a test mock must defend itself —
        // skip non-finite cost increments so the accumulator stays
        // analyzable.
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

// ---- Slice-D test doubles (AC-22 coordination surface) ----

/// Slice-D test double for [`AutoBootstrapApplier`]. Returns a preconfigured
/// `Result<M015BootstrapReport, AutoBootstrapApplierError>` and records the
/// `(parent_agent_id, raw_yaml)` of each `apply` call so tests can assert the
/// coordination layer delegated with the right inputs.
#[derive(Clone)]
pub struct RecordingAutoBootstrapApplier {
    result: Arc<Result<M015BootstrapReport, AutoBootstrapApplierError>>,
    calls: Arc<Mutex<Vec<(String, String)>>>,
}

impl RecordingAutoBootstrapApplier {
    /// Construct with the `Result` the applier should return on every `apply`.
    pub fn new(result: Result<M015BootstrapReport, AutoBootstrapApplierError>) -> Self {
        Self {
            result: Arc::new(result),
            calls: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Snapshot of `(parent_agent_id, raw_yaml)` for each `apply` call.
    pub fn calls(&self) -> Vec<(String, String)> {
        self.calls
            .lock()
            .expect("RecordingAutoBootstrapApplier mutex")
            .clone()
    }
}

#[async_trait]
impl AutoBootstrapApplier for RecordingAutoBootstrapApplier {
    async fn apply(
        &self,
        parent_agent_id: &str,
        raw_yaml: &str,
    ) -> Result<M015BootstrapReport, AutoBootstrapApplierError> {
        self.calls
            .lock()
            .expect("RecordingAutoBootstrapApplier mutex")
            .push((parent_agent_id.to_string(), raw_yaml.to_string()));
        (*self.result).clone()
    }
}

/// Slice-D test double for [`AutoBootstrapEventSink`]. Records every emitted
/// [`BootstrapEventPayload`] in order. Optionally configured to fail `emit`
/// for a set of payload indices (0-based, in emission order) so tests can
/// exercise the no-short-circuit sink-failure aggregation.
#[derive(Clone, Default)]
pub struct RecordingAutoBootstrapEventSink {
    calls: Arc<Mutex<Vec<BootstrapEventPayload>>>,
    fail_indices: Arc<Vec<usize>>,
    counter: Arc<AtomicUsize>,
}

impl RecordingAutoBootstrapEventSink {
    /// Sink that records all emits and never fails.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sink that fails `emit` for the given 0-based emission indices (still
    /// records the payload before returning the error — no short-circuit).
    pub fn failing_at(fail_indices: Vec<usize>) -> Self {
        Self {
            calls: Arc::new(Mutex::new(Vec::new())),
            fail_indices: Arc::new(fail_indices),
            counter: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Snapshot of all emitted payloads in emission order.
    pub fn calls(&self) -> Vec<BootstrapEventPayload> {
        self.calls
            .lock()
            .expect("RecordingAutoBootstrapEventSink mutex")
            .clone()
    }
}

#[async_trait]
impl AutoBootstrapEventSink for RecordingAutoBootstrapEventSink {
    async fn emit(&self, payload: BootstrapEventPayload) -> Result<(), AutoBootstrapSinkError> {
        let idx = self.counter.fetch_add(1, Ordering::SeqCst);
        self.calls
            .lock()
            .expect("RecordingAutoBootstrapEventSink mutex")
            .push(payload);
        if self.fail_indices.contains(&idx) {
            Err(AutoBootstrapSinkError::EmitFailed(format!(
                "configured failure at emit index {idx}"
            )))
        } else {
            Ok(())
        }
    }
}

/// Stage-D: records every `auto.*` lifecycle event the integrated loop emits.
#[derive(Default)]
pub struct RecordingIterationEventSink {
    events: Mutex<Vec<AutoIterationEventPayload>>,
}

impl RecordingIterationEventSink {
    pub fn new() -> Self {
        Self {
            events: Mutex::new(Vec::new()),
        }
    }
    /// All recorded payloads, in emission order.
    pub fn events(&self) -> Vec<AutoIterationEventPayload> {
        self.events
            .lock()
            .expect("RecordingIterationEventSink mutex")
            .clone()
    }
    /// The recorded event-type strings, in emission order.
    pub fn event_types(&self) -> Vec<&'static str> {
        self.events
            .lock()
            .expect("RecordingIterationEventSink mutex")
            .iter()
            .map(|e| e.event_type())
            .collect()
    }
}

#[async_trait]
impl AutoIterationEventSink for RecordingIterationEventSink {
    async fn emit(&self, payload: AutoIterationEventPayload) -> Result<(), AutoEventSinkError> {
        self.events
            .lock()
            .expect("RecordingIterationEventSink mutex")
            .push(payload);
        Ok(())
    }
}

/// Stage-D: records every degrade/halt notification `(agent_id, message)`.
#[derive(Default)]
pub struct RecordingNotifySink {
    calls: Mutex<Vec<(String, String)>>,
}

impl RecordingNotifySink {
    pub fn new() -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
        }
    }
    pub fn calls(&self) -> Vec<(String, String)> {
        self.calls
            .lock()
            .expect("RecordingNotifySink mutex")
            .clone()
    }
}

#[async_trait]
impl NotifySink for RecordingNotifySink {
    async fn notify(&self, agent_id: &str, message: &str) -> Result<(), NotifySinkError> {
        self.calls
            .lock()
            .expect("RecordingNotifySink mutex")
            .push((agent_id.to_string(), message.to_string()));
        Ok(())
    }
}

/// Stage-D: a configurable [`RunBudgetSource`] returning a fixed decision.
pub struct MockRunBudgetSource {
    decision: BudgetDecision,
}

impl MockRunBudgetSource {
    pub fn allow() -> Self {
        Self {
            decision: BudgetDecision::Allow,
        }
    }
    pub fn deny(reason: &str) -> Self {
        Self {
            decision: BudgetDecision::Deny(reason.to_string()),
        }
    }
}

impl RunBudgetSource for MockRunBudgetSource {
    fn budget_decision(&self, _run_id: &str, _agent_id: &str) -> BudgetDecision {
        self.decision.clone()
    }
}

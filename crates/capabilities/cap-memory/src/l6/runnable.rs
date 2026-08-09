//! `L6Runnable` — the concrete CONTRACT-102 `L6Handler` (Slice C). MODULE-011
//! §1.3.6. The runnable owns BOTH entry points: `handle()` performs Steps 1–5
//! (pure-compute Steps 1–4 → lease-loss gate → persistence Step 5
//! flush/commit/emit) and returns `L6Outcome`; `on_component_finished()`
//! performs Step 6 (event-driven late-`component.finished` match-then-clear
//! with `lease_id`-mismatch mis-clearing defense). "The background runnable
//! runs 6 steps in order" (AC-14) is this full lifecycle across the two
//! methods, traced verbatim against `L6_CANONICAL_STEPS` (anchored in
//! MODULE-011 §2.7, mirroring the §1.3.5 → `post_processor::CANONICAL_STEPS`
//! precedent).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use advance_shared_types::memory::{
    KnowledgeHealthSnapshot, L6Context, L6Cursor, L6Error, L6Handler, L6Outcome,
};
use async_trait::async_trait;

use crate::clock::Clock;
use crate::knowledge::{MemoryEntry, MemoryStatus, MemoryType};
use crate::skill_candidate::{SkillCandidate, SkillCandidateStore};
use crate::store::MemoryStore;

use super::batch_id::BatchIdSource;
use super::classifier::{
    ClusterClassification, L6ClassificationInput, L6Classifier, TaskRef, MAX_CLUSTERS,
    MAX_STALE_ENTRIES, MAX_TASK_EXTRACTS,
};
use super::cluster::L6ClusterBuilder;
use super::commit::{CommitFile, ContentKind, L6Committer};
use super::cursor::L6CursorStore;
use super::emit::{L6CompletedPayload, L6Delta, L6Emitter};
use super::knowledge_map::{KnowledgeMap, KnowledgeMapTopic};
use super::lease::LeaseStore;
use super::stale::{run_stale_detection, StaleStateSnapshot, StalenessProbe};
use super::synthesis::{
    should_synthesize, SynthesisGateResult, SynthesisGenerator, SynthesisInput, MAX_SYNTHESES,
};

/// Canonical 6-step label list (AC-14 doc anchor — MODULE-011 §2.7
/// `L6_CANONICAL_STEPS`; mirrors `post_processor::CANONICAL_STEPS` ↔ §1.3.5).
/// `runnable.rs` traces these verbatim. Labels 1–5 are pushed by `handle()`;
/// label 6 by `on_component_finished()` on the matched path.
pub const L6_CANONICAL_STEPS: [&str; 6] = [
    "Step 1: Stale detection",
    "Step 2: Semantic clustering",
    "Step 3: Batch LLM call",
    "Step 4: Synthesis generation",
    "Step 5: Persistence phase (flush → commit → emit)",
    "Step 6: Clear lease",
];

/// Step 6 input (scheduler-delivered; slice C tests synthesize it directly).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComponentFinished {
    pub component_id: String,
    pub lease_id: String,
}

/// §2.10 `memory.l6.lease_timeout_min` (10 min) — the TTL the runnable uses
/// when it needs to reason about lease validity.
pub const L6_LEASE_TTL: Duration = Duration::from_secs(600);

pub struct L6Runnable {
    pub component_id: String,
    pub clock: Arc<dyn Clock + Send + Sync>,
    pub batch_id_source: Arc<dyn BatchIdSource + Send + Sync>,
    pub store: Arc<MemoryStore>,
    pub lease: Arc<dyn LeaseStore + Send + Sync>,
    pub staleness: Arc<dyn StalenessProbe + Send + Sync>,
    pub cluster_builder: Arc<L6ClusterBuilder>,
    pub classifier: Arc<dyn L6Classifier + Send + Sync>,
    pub synthesis_gen: Arc<dyn SynthesisGenerator + Send + Sync>,
    pub knowledge_map: Arc<Mutex<KnowledgeMap>>,
    pub syntheses: Arc<Mutex<HashMap<String, String>>>,
    pub committer: Arc<dyn L6Committer + Send + Sync>,
    pub emitter: Arc<dyn L6Emitter + Send + Sync>,
    pub cursor_store: Arc<L6CursorStore>,
    trace: Arc<Mutex<Vec<String>>>,
    sub_trace_5: Arc<Mutex<Vec<String>>>,
    stale_state: Arc<Mutex<StaleStateSnapshot>>,
    /// SAT-C (slice satC-l6): the cap-memory memory root
    /// (`<workspace>/.agent/memory`). `None` (the `new` default) keeps Step-5b
    /// in-memory-only with the historical flat `.agent/memory/...` CommitFile
    /// vpaths — preserving every rootless integration test + AC-15. `Some(root)`
    /// (set via [`L6Runnable::with_fs_root`] at the cli composition root) makes
    /// Step-5b serialize `_knowledge_map.yaml` + the accepted `syntheses/*.md`
    /// to disk under `<root>/<slug(agent)>/` and emit ABSOLUTE on-disk vpaths so
    /// the production `GitQueueL6Committer` commits real files. See §3.8 note 19(f).
    fs_root: Option<PathBuf>,
    /// slice wave6-laneB: optional skill-candidate producer store (rooted at
    /// `<mem_root>/_skill_candidates.jsonl` by the cli `attach_l6`). `None` (the
    /// `new` default) keeps Step-5a flushing ONLY the cursor (historical behaviour
    /// — all existing rootless/integration tests + AC-15 unchanged). `Some` (set via
    /// [`L6Runnable::with_skill_candidate_store`]) makes Step-5a append a candidate
    /// per `skill_health` stale/unhealthy entry (deterministic id ⇒ idempotent) and
    /// Step-5c emit `skill.candidate_generated`. See §3.8 note 21.
    skill_candidate_store: Option<Arc<SkillCandidateStore>>,
}

impl L6Runnable {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        component_id: impl Into<String>,
        clock: Arc<dyn Clock + Send + Sync>,
        batch_id_source: Arc<dyn BatchIdSource + Send + Sync>,
        store: Arc<MemoryStore>,
        lease: Arc<dyn LeaseStore + Send + Sync>,
        staleness: Arc<dyn StalenessProbe + Send + Sync>,
        cluster_builder: Arc<L6ClusterBuilder>,
        classifier: Arc<dyn L6Classifier + Send + Sync>,
        synthesis_gen: Arc<dyn SynthesisGenerator + Send + Sync>,
        knowledge_map: Arc<Mutex<KnowledgeMap>>,
        syntheses: Arc<Mutex<HashMap<String, String>>>,
        committer: Arc<dyn L6Committer + Send + Sync>,
        emitter: Arc<dyn L6Emitter + Send + Sync>,
        cursor_store: Arc<L6CursorStore>,
    ) -> Self {
        Self {
            component_id: component_id.into(),
            clock,
            batch_id_source,
            store,
            lease,
            staleness,
            cluster_builder,
            classifier,
            synthesis_gen,
            knowledge_map,
            syntheses,
            committer,
            emitter,
            cursor_store,
            trace: Arc::new(Mutex::new(Vec::new())),
            sub_trace_5: Arc::new(Mutex::new(Vec::new())),
            stale_state: Arc::new(Mutex::new(StaleStateSnapshot::default())),
            // SAT-C: rootless by default (in-memory Step-5b + flat vpaths) —
            // the cli composition root opts into on-disk serialization via
            // `with_fs_root`. Keeps the 14-arg ctor + all callers UNCHANGED.
            fs_root: None,
            // slice wave6-laneB: no candidate production unless opted in via
            // `with_skill_candidate_store` (keeps the 14-arg ctor + callers UNCHANGED).
            skill_candidate_store: None,
        }
    }

    /// SAT-C (slice satC-l6): set the cap-memory memory root so Step-5b
    /// serializes `_knowledge_map.yaml` + the accepted `syntheses/*.md` to disk
    /// under `<root>/<slug(agent)>/` and emits absolute on-disk CommitFile
    /// vpaths. Consuming builder (mirrors `Components::with_fs_root`). Absent ⇒
    /// the historical in-memory + flat-vpath behaviour (rootless tests + AC-15
    /// unchanged).
    pub fn with_fs_root(mut self, root: impl Into<PathBuf>) -> Self {
        self.fs_root = Some(root.into());
        self
    }

    /// slice wave6-laneB: attach a skill-candidate producer store so Step-5a appends
    /// candidates promoted from the classifier's `skill_health` (stale/unhealthy →
    /// candidate) + Step-5c emits `skill.candidate_generated`. Absent ⇒ no candidate
    /// production (the historical cursor-only Step-5a flush). Consuming builder
    /// (mirrors `with_fs_root`).
    pub fn with_skill_candidate_store(mut self, store: Arc<SkillCandidateStore>) -> Self {
        self.skill_candidate_store = Some(store);
        self
    }

    pub fn trace_snapshot(&self) -> Vec<String> {
        self.trace
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    pub fn sub_trace_5(&self) -> Vec<String> {
        self.sub_trace_5
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn push(&self, label: &str) {
        self.trace
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(label.to_string());
    }

    fn push5(&self, label: &str) {
        self.sub_trace_5
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(label.to_string());
    }

    /// Step 6 — the runnable's event-driven late-`component.finished`
    /// match-then-clear (§1.3.6 step 6). The scheduler delivers a (possibly
    /// late / possibly stale) `component.finished` for a known agent — the
    /// agent the runnable's `handle()` ran for — so this method is
    /// agent-scoped. Matches `ev.component_id == self.component_id` AND
    /// `ev.lease_id` against the agent's CURRENT live lease token; on full
    /// match, token-checked `release` + push the "Step 6: Clear lease"
    /// canonical label. On mismatch (a previously-aborted L6 run delivering a
    /// stale `lease_id`) OR no live lease → NO-OP, the live lease is NOT
    /// cleared (mis-clearing defense). Returns true iff the lease was cleared.
    /// This is the only Step 6 entry point (slice-C tests + the scheduler
    /// drive it directly).
    pub fn on_component_finished(&self, agent_id: &str, ev: &ComponentFinished) -> bool {
        if ev.component_id != self.component_id {
            return false;
        }
        let now = self.clock.now();
        match self.lease.current_token(agent_id, now) {
            Some(tok) if tok == ev.lease_id => {
                let cleared = self.lease.release(agent_id, &ev.lease_id);
                if cleared {
                    self.push(L6_CANONICAL_STEPS[5]); // "Step 6: Clear lease"
                }
                cleared
            }
            // Stale lease_id (previously-aborted run) OR no live lease →
            // no-op (mis-clearing defense).
            _ => false,
        }
    }

    fn build_pref_entry(&self, agent_id: &str, content: &str, batch_id: &str) -> MemoryEntry {
        MemoryEntry {
            id: format!("l6-pref-{}-{}", batch_id, sanitize_id(content)),
            agent_id: agent_id.to_string(),
            entry_type: MemoryType::UserPreference,
            content: content.to_string(),
            tags: vec![format!("l6_batch:{batch_id}"), "consolidated".into()],
            created_at: "1970-01-01T00:00:00Z".into(),
            task_origin: None,
            is_active: true,
            superseded_by: None,
            status: MemoryStatus::Active,
            supersession_reason: None,
            cluster_id: None,
            sources: vec![],
        }
    }
}

fn sanitize_id(s: &str) -> String {
    let cleaned: String = s
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    cleaned.chars().take(24).collect()
}

/// SAT-C adversarial r1 (#5): refuse to write L6 artifacts through a pre-planted
/// SYMLINKED directory. A non-existent dir is fine (`atomic_write`'s
/// `create_dir_all` creates it); an existing symlink dir is rejected so a rooted
/// write cannot escape `<mem_root>/<slug(agent)>/`. Uses `symlink_metadata` (does
/// NOT follow the link), mirroring the SAT-B audit-r15 `persistence::ensure_agent_dir`
/// hardening. (A residual create-then-write TOCTOU remains — full closure needs
/// `openat`/`O_NOFOLLOW` — accepted, consistent with the rest of the memory write
/// path; the tree is owner-only 0700 / not guest-reachable.)
fn reject_symlinked_dir(dir: &std::path::Path) -> Result<(), L6Error> {
    if let Ok(md) = std::fs::symlink_metadata(dir) {
        if md.file_type().is_symlink() {
            return Err(L6Error::StorageError(format!(
                "refusing L6 write through a symlinked dir: {}",
                dir.display()
            )));
        }
    }
    Ok(())
}

#[async_trait]
impl L6Handler for L6Runnable {
    async fn handle(&self, ctx: L6Context) -> Result<L6Outcome, L6Error> {
        let agent = ctx.agent_id.clone();
        let batch_id = self.batch_id_source.next();
        let l6_commit_ts = self.clock.now();
        let now = l6_commit_ts;

        // Per-run reset: stale_state is NEVER a cross-run freshness cache
        // (AC-23 non-regression).
        *self
            .stale_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = StaleStateSnapshot::default();

        // ───── Steps 1–4: no persisted MEMORY-STORE side effects ─────
        // (no flush/commit/emit, no store-content mutation). NB (slice
        // wave6-laneB): the Step-3 classify-failure path MAY token-checked-release
        // the lease (the 216 retry shape) — a control-state action, not a
        // store-content mutation, so this invariant is unaffected.
        // Step 1 — stale detection (pure: compute the report; the
        // status→Orphaned mutation is applied in 5b commit).
        self.push(L6_CANONICAL_STEPS[0]);
        let report = run_stale_detection(&self.store, &agent, self.staleness.as_ref());
        let partial_set: std::collections::HashSet<String> =
            report.partial_stale_ids.iter().cloned().collect();

        // Active snapshot for clustering/synthesis (taken once, pure).
        let active: Vec<MemoryEntry> = self
            .store
            .list(&agent)
            .into_iter()
            .filter(|e| e.is_active)
            .collect();
        let stale_ids: std::collections::HashSet<String> =
            report.stale_ids.iter().cloned().collect();

        // Step 2 — semantic clustering (pure compute, no SimilarityIndex).
        self.push(L6_CANONICAL_STEPS[1]);
        let assignments = self.cluster_builder.build_clusters(&active, &batch_id);

        // Step 3 — batch LLM classification (clamped to §2.10 caps; pure).
        self.push(L6_CANONICAL_STEPS[2]);
        let by_id: HashMap<&str, &MemoryEntry> =
            active.iter().map(|e| (e.id.as_str(), e)).collect();
        let clusters_with_entries: Vec<_> = assignments
            .iter()
            .take(MAX_CLUSTERS)
            .map(|a| {
                let entries: Vec<MemoryEntry> = a
                    .entry_ids
                    .iter()
                    .filter_map(|id| by_id.get(id.as_str()).map(|e| (*e).clone()))
                    .collect();
                (a.clone(), entries)
            })
            .collect();
        let stale_candidates: Vec<MemoryEntry> = active
            .iter()
            .filter(|e| stale_ids.contains(&e.id))
            .take(MAX_STALE_ENTRIES)
            .cloned()
            .collect();
        let completed_tasks: Vec<TaskRef> = ctx
            .cursor
            .as_ref()
            .and_then(|c| c.last_knowledge_id.clone())
            .map(|_| Vec::new())
            .unwrap_or_default();
        let _ = MAX_TASK_EXTRACTS;
        let cls_input = L6ClassificationInput {
            agent_id: agent.clone(),
            batch_id: batch_id.clone(),
            stale_candidates,
            clusters: clusters_with_entries.clone(),
            completed_tasks,
        };
        // Step-3 LLM-failure abort (slice wave6-laneB / the 216 "lease cleared"
        // shape): on classify failure, token-checked-release the live lease so the
        // next trigger retries, then propagate the error (the L6DispatchAdapter then
        // emits component.error). The release is a NO-OP when the lease is already
        // lost — it never clears a lease we do not own, identical to the lease-loss
        // gate below and the 5b commit-failure release at the bottom of Step 5. A
        // lease release is control state, NOT a persisted MEMORY-STORE mutation, so
        // the Steps-1–4 "no store side effects" invariant above still holds.
        let cls_out = match self.classifier.classify(&cls_input).await {
            Ok(out) => out,
            Err(e) => {
                self.lease.release(&agent, &ctx.lease_token);
                return Err(e);
            }
        };

        // Step 4 — synthesis generation (5-gate per cluster, max 3; pure —
        // collect planned (assignment, synthesis), mutate in 5b).
        self.push(L6_CANONICAL_STEPS[3]);
        let mut planned: Vec<(String /*cluster_id*/, super::synthesis::Synthesis)> = Vec::new();
        for (assignment, entries) in &clusters_with_entries {
            if planned.len() >= MAX_SYNTHESES {
                break;
            }
            // Override status→Orphaned for this-run stale members so gate (e)
            // fires for entries detected stale in THIS run.
            let view: Vec<MemoryEntry> = entries
                .iter()
                .map(|e| {
                    if stale_ids.contains(&e.id) {
                        let mut c = e.clone();
                        c.status = MemoryStatus::Orphaned;
                        c
                    } else {
                        e.clone()
                    }
                })
                .collect();
            let classification = cls_out
                .cluster_decisions
                .get(&assignment.cluster_id)
                .copied()
                .unwrap_or(ClusterClassification::Consistent);
            if let SynthesisGateResult::Pass = should_synthesize(&view, classification) {
                let slug = assignment
                    .cluster_id
                    .strip_prefix("cl-")
                    .and_then(|r| r.rfind('-').map(|i| r[..i].to_string()))
                    .unwrap_or_else(|| "topic".to_string());
                let synth = self.synthesis_gen.generate(&SynthesisInput {
                    cluster_id: assignment.cluster_id.clone(),
                    topic_slug: slug,
                    entries: view,
                });
                planned.push((assignment.cluster_id.clone(), synth));
            }
        }

        // ───── LEASE-LOSS GATE — ONCE, BEFORE the persistence phase ─────
        // (Round-2 Warning-2): a lost lease aborts with ZERO MEMORY-STORE side
        // effects (no flush/commit/emit, no store-content mutation). Steps 1–4
        // above mutate no store content, so that holds. (The Step-3 classify path
        // may have token-checked-released the lease on an LLM failure and returned
        // already — that release is control state, not store content.)
        match self.lease.current_token(&agent, now) {
            Some(tok) if tok == ctx.lease_token => {}
            _ => return Err(L6Error::LeaseLost),
        }

        // ───── Step 5 — persistence phase (flush → commit → emit) ─────
        self.push(L6_CANONICAL_STEPS[4]);

        // 5a flush — `_knowledge_cursor.yaml` + (slice wave6-laneB) the
        // `_skill_candidates.jsonl` producer flush when a candidate store is wired.
        // (`_skill_health.yaml` flush stays deferred.)
        self.push5("5a flush");
        let last_knowledge_id = active.last().map(|e| e.id.clone());
        self.cursor_store.flush(
            &agent,
            L6Cursor {
                last_knowledge_id,
                last_completed_at: l6_commit_ts,
            },
        );

        // slice wave6-laneB (186): promote skill candidates from the classifier's
        // real `skill_health` (status `stale`/`unhealthy` → candidate) into the
        // append-only `_skill_candidates.jsonl`. The description is STRICTLY
        // run-invariant (derived only from the (skill, status) pair — no batch_id /
        // timestamp / ordering), so `candidate_id` (sha256 of name+description) is
        // stable across runs ⇒ `append_generated` dedups (no double-write on an
        // `l6_batch_id` retry) and the JSONL cannot grow unbounded. Append is
        // BEST-EFFORT — a per-candidate writer error (oversize / io) is skipped and
        // never fails the consolidation (an auxiliary producer output). This is a
        // runtime-private 5a flush (NOT rolled back on a 5b commit failure); the
        // `skill.candidate_generated` emit happens at 5c only on full success.
        // `generated` carries the NEWLY-appended (candidate_id, skill_name) for 5c.
        //
        // Emit delivery is AT-MOST-ONCE, intentionally (adversarial r6 W-16-2, Info):
        // a 5b commit failure returns before 5c, and the run-invariant candidate_id
        // means a later retry's `append_generated` dedups (Ok(false)) → the candidate
        // is NOT re-collected here → its `skill.candidate_generated` event never re-emits.
        // The candidate itself is NEVER LOST — the 5a JSONL line persists on disk in the
        // runtime-private `_skill_candidates.jsonl` (which is NOT part of the L6 git
        // commit file set — it is a runtime store, not a committed memory artifact) and
        // stays discoverable via `list-skill-candidates`; only the push NOTIFICATION is
        // at-most-once, matching the sibling `memory.l6_completed` emit-on-success
        // posture. Re-emitting from the still-pending set instead would SPAM the event
        // every L6 cycle for any never-resolved candidate, so the "newly appended this
        // run" gate is deliberate.
        let mut generated_candidates: Vec<(String, String)> = Vec::new();
        if let Some(store) = &self.skill_candidate_store {
            for h in &cls_out.skill_health {
                if !matches!(h.status.as_str(), "stale" | "unhealthy") {
                    continue;
                }
                let cand = SkillCandidate::new(
                    h.skill.clone(),
                    format!(
                        "L6 consolidation flagged skill '{}' as {}; candidate for review.",
                        h.skill, h.status
                    ),
                );
                match store.append_generated(&cand) {
                    // newly appended → emit at 5c
                    Ok(true) => generated_candidates.push((cand.candidate_id, h.skill.clone())),
                    // idempotent (already known, e.g. an l6_batch retry) → no re-emit
                    Ok(false) => {}
                    // best-effort: skip a writer error; never fail the consolidation
                    Err(_) => {}
                }
            }
        }

        // 5b commit. Wrapped so a mid-run Step-5 failure (StorageError /
        // GitCommitFailed) releases the live lease (token-checked) BEFORE
        // propagating — the crate-side of SYS-AC-216 (slice m011-mem-product).
        // Without the release the lease would sit Active until TTL, blocking
        // the next consolidation. The partial 5a cursor flush + any 5b store
        // mutations already applied are NOT rolled back (pre-existing posture);
        // retry idempotency rests on l6_batch_id (AC-32). See §3.8 note 16(d).
        self.push5("5b commit");
        let commit_result: Result<(u32, u32, u32), L6Error> = (|| {
            // (i) stale → Orphaned (the §1.3.6 "stale detection failed" persisted
            //     status mutation).
            for id in &report.stale_ids {
                self.store
                    .mark_orphaned(&agent, id)
                    .map_err(|e| L6Error::StorageError(format!("{e:?}")))?;
            }
            // (ii) cluster_id writeback (journaled). Iterate the SAME
            // MAX_CLUSTERS-capped set Step 3 classified (clusters_with_entries),
            // NOT the raw `assignments` — so cluster_deltas counts exactly the
            // clusters that received a classification decision (no asymmetric
            // take-cap; clusters 11+ are neither classified nor written).
            let mut cluster_deltas = 0u32;
            for (a, _) in &clusters_with_entries {
                cluster_deltas = cluster_deltas.saturating_add(1);
                for eid in &a.entry_ids {
                    self.store
                        .write_cluster_id(&agent, eid, &a.cluster_id, l6_commit_ts)
                        .map_err(|e| L6Error::StorageError(format!("{e:?}")))?;
                }
            }
            // (iii) consolidated_preferences append (tagged l6_batch:{id}).
            let mut entries_written = 0u32;
            for pref in &cls_out.consolidated_preferences {
                let entry = self.build_pref_entry(&agent, pref, &batch_id);
                self.store
                    .append_consolidated_preference(&agent, entry, l6_commit_ts)
                    .map_err(|e| L6Error::StorageError(format!("{e:?}")))?;
                entries_written = entries_written.saturating_add(1);
            }
            // (iv) KnowledgeMap + syntheses map (in memory). SAT-C: track the
            // per-run ACCEPTED set (paths that passed the budget gate) — the
            // rooted disk-serialization + commit list reference ONLY these real
            // files, NOT the raw `planned` (which includes budget-rejected
            // entries) nor `self.syntheses` (which accumulates ACROSS L6 runs).
            let mut syntheses_written = 0u32;
            let mut accepted: Vec<(String, String)> = Vec::new();
            let mut km_yaml_to_write: Option<String> = None;
            {
                let mut km = self
                    .knowledge_map
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let mut sy = self
                    .syntheses
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                for (cluster_id, synth) in &planned {
                    let topic_slug = synth
                        .path
                        .strip_prefix("syntheses/")
                        .and_then(|p| p.strip_suffix(".md"))
                        .unwrap_or("topic")
                        .to_string();
                    let topic = KnowledgeMapTopic {
                        topic_slug,
                        synthesis_path: synth.path.clone(),
                        cluster_id: cluster_id.clone(),
                        tokens: 50,
                    };
                    // Budget-aware; over-budget topics are skipped (AC-16).
                    if km.add_topic(topic).is_ok() {
                        sy.insert(synth.path.clone(), synth.content.clone());
                        accepted.push((synth.path.clone(), synth.content.clone()));
                        syntheses_written = syntheses_written.saturating_add(1);
                    }
                }
                // SAT-C: serialize the knowledge map UNDER the lock (CPU only),
                // but defer the disk writes to AFTER the lock is dropped so an
                // fsync never blocks a concurrent km/syntheses reader.
                if self.fs_root.is_some() {
                    km_yaml_to_write = Some(serde_yml::to_string(&*km).map_err(|e| {
                        L6Error::StorageError(format!("_knowledge_map.yaml serialize: {e}"))
                    })?);
                }
            }
            // (iv.b) SAT-C: when rooted, write `_knowledge_map.yaml` + the
            // ACCEPTED syntheses to disk under `<root>/<slug(agent)>/` so the
            // production committer commits real files (the in-memory committer
            // masked their absence). `atomic_write` create_dir_all's the parent
            // (incl. `syntheses/`). Rootless ⇒ skipped → in-memory-only behaviour
            // (rootless tests + AC-15 unchanged). See §3.8 note 19(f).
            if let Some(root) = &self.fs_root {
                let dir = root.join(crate::persistence::slug(&agent));
                // adversarial r1 (#5): symlink-reject the agent dir + `syntheses`
                // subdir before writing. `atomic_write`'s `create_dir_all` would
                // otherwise FOLLOW a pre-planted parent symlink and write the L6
                // artifacts OUTSIDE the per-agent memory root. Mirrors the SAT-B
                // audit-r15 `ensure_agent_dir` hardening (the knowledge.jsonl
                // path). Non-guest-reachable (`.agent/memory` is owner-only 0700)
                // but hardened for parity.
                reject_symlinked_dir(&dir)?;
                if !accepted.is_empty() {
                    reject_symlinked_dir(&dir.join("syntheses"))?;
                }
                if let Some(yaml) = &km_yaml_to_write {
                    crate::persistence::atomic_write(
                        &dir.join("_knowledge_map.yaml"),
                        yaml.as_bytes(),
                    )
                    .map_err(|e| {
                        L6Error::StorageError(format!("_knowledge_map.yaml write: {e:?}"))
                    })?;
                }
                for (path, content) in &accepted {
                    crate::persistence::atomic_write(&dir.join(path), content.as_bytes()).map_err(
                        |e| L6Error::StorageError(format!("synthesis write {path}: {e:?}")),
                    )?;
                }
            }
            // (v) commit. ROOTED → absolute on-disk paths (matching the per-slug
            // store layout + the just-written files; ACCEPTED-only). ROOTLESS →
            // the historical flat `.agent/memory/...` vpaths over ALL `planned`
            // (preserves the in-memory-committer test contract). §3.8 note 19(a/f).
            let files: Vec<CommitFile> = if let Some(root) = &self.fs_root {
                let dir = root.join(crate::persistence::slug(&agent));
                // Only commit files that ACTUALLY EXIST on disk (audit r1 W1):
                // the store writes knowledge.jsonl lazily (absent until the
                // agent's first knowledge write), and the git queue would treat
                // a missing affected path as a DELETION-staging request. The
                // _knowledge_map.yaml + the accepted syntheses were just written
                // in (iv.b) above, so they exist; knowledge.jsonl is gated on
                // its on-disk presence.
                let mut v: Vec<CommitFile> = Vec::new();
                let kj = dir.join("knowledge.jsonl");
                if kj.exists() {
                    v.push(CommitFile {
                        vpath: kj.to_string_lossy().into_owned(),
                        content_kind: ContentKind::KnowledgeJsonl,
                    });
                }
                let km_path = dir.join("_knowledge_map.yaml");
                if km_path.exists() {
                    v.push(CommitFile {
                        vpath: km_path.to_string_lossy().into_owned(),
                        content_kind: ContentKind::KnowledgeMapYaml,
                    });
                }
                for (path, _) in &accepted {
                    let p = dir.join(path);
                    if p.exists() {
                        v.push(CommitFile {
                            vpath: p.to_string_lossy().into_owned(),
                            content_kind: ContentKind::Synthesis { path: path.clone() },
                        });
                    }
                }
                v
            } else {
                let mut v = vec![
                    CommitFile {
                        vpath: ".agent/memory/knowledge.jsonl".into(),
                        content_kind: ContentKind::KnowledgeJsonl,
                    },
                    CommitFile {
                        vpath: ".agent/memory/_knowledge_map.yaml".into(),
                        content_kind: ContentKind::KnowledgeMapYaml,
                    },
                ];
                for (_, synth) in &planned {
                    v.push(CommitFile {
                        vpath: format!(".agent/memory/{}", synth.path),
                        content_kind: ContentKind::Synthesis {
                            path: synth.path.clone(),
                        },
                    });
                }
                v
            };
            self.committer
                .commit(&agent, &batch_id, &files)
                .map_err(|e| L6Error::GitCommitFailed(e.to_string()))?;
            Ok((cluster_deltas, entries_written, syntheses_written))
        })();
        let (cluster_deltas, entries_written, syntheses_written) = match commit_result {
            Ok(v) => v,
            Err(e) => {
                // Mid-run-failure cleanup: token-checked release of the live
                // lease (no-op on token mismatch — preserves the Step-6
                // mis-clearing defense).
                self.lease.release(&agent, &ctx.lease_token);
                return Err(e);
            }
        };

        // 5c emit — single snapshot computation (shared by the event payload
        // and the L6Outcome return; §3.8 note 3).
        self.push5("5c emit");
        *self
            .stale_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = StaleStateSnapshot {
            partial_stale_ids: partial_set.clone(),
        };
        let snapshot: KnowledgeHealthSnapshot =
            super::health_snapshot::compute_health_snapshot(&self.store, &agent, &partial_set, now);
        let contested_clusters = cls_out
            .cluster_decisions
            .values()
            .filter(|&&c| c == ClusterClassification::Contested)
            .count() as u32;
        let delta = L6Delta {
            clusters_merged: cluster_deltas,
            entries_pruned: 0, // §3.8 note 4: no prune op in the 6-step flow
            syntheses_generated: syntheses_written,
            contested_clusters,
            orphaned_entries: report.stale_ids.len() as u32,
        };
        // slice wave6-laneB (186): emit `skill.candidate_generated` for each NEWLY
        // appended candidate (5a-appended, 5b-commit-succeeded), BEFORE
        // `memory.l6_completed` per the §1.4.6 step-5c ordering. Default no-op on
        // emitters that don't override it (InMemoryEmitter captures, EventBusL6Emitter fires).
        for (candidate_id, skill_name) in &generated_candidates {
            self.emitter
                .emit_skill_candidate_generated(&agent, candidate_id, skill_name);
        }
        self.emitter.emit_l6_completed(L6CompletedPayload {
            agent_id: agent.clone(),
            batch_id: batch_id.clone(),
            // Slice D: PRD §15.3.22-mandated `lease_id` on the wire. The live
            // lease token is already in scope at this emit site (also used by
            // the §1.3.6-step-6 lease-loss gate above).
            lease_id: ctx.lease_token.clone(),
            delta,
            snapshot: snapshot.clone(),
        });

        // RETURN — CONTRACT-102 L6Outcome (≠ L6CompletedPayload; shares the
        // one `snapshot`). §3.8 note 3 / Round-4 Warning-2.
        Ok(L6Outcome {
            entries_written,
            syntheses_written,
            knowledge_map_updated: entries_written > 0 || syntheses_written > 0,
            cluster_deltas,
            health_snapshot: snapshot,
        })
    }
}

#[cfg(test)]
mod adv_r1_tests {
    use super::reject_symlinked_dir;

    /// SAT-C adversarial r1 (#5): the rooted-write guard refuses a symlinked dir
    /// (would let a write escape the memory root) but allows a real or
    /// not-yet-created dir (the normal first-run path).
    #[test]
    fn reject_symlinked_dir_refuses_symlink_allows_real_and_missing() {
        let tmp = tempfile::tempdir().unwrap();
        // Missing dir → Ok (atomic_write's create_dir_all makes it on first run).
        assert!(reject_symlinked_dir(&tmp.path().join("missing")).is_ok());
        // Real dir → Ok.
        let real = tmp.path().join("real");
        std::fs::create_dir(&real).unwrap();
        assert!(reject_symlinked_dir(&real).is_ok());
        // Symlinked dir → Err (refused before any write).
        #[cfg(unix)]
        {
            let target = tmp.path().join("target");
            std::fs::create_dir(&target).unwrap();
            let link = tmp.path().join("link");
            std::os::unix::fs::symlink(&target, &link).unwrap();
            assert!(
                reject_symlinked_dir(&link).is_err(),
                "a pre-planted symlinked dir must be refused"
            );
        }
    }
}

//! In-memory `RunStore` (Slice A — no YAML persistence; AC-15 deferred).
//!
//! Single source of truth for Run rows + `task_id → run_id` reverse index
//! for live (Active / Suspended / Paused) runs. All synchronization happens
//! at the outer `Arc<RwLock<RunStore>>` held by `RunManager` and
//! `InMemoryRunBudget` (single lock; no per-run Mutex — see §3.8 doc note).

use std::collections::HashMap;

use crate::run::{is_live_status, Run, RunId};

pub(crate) struct RunStore {
    runs: HashMap<RunId, Run>,
    live_by_task: HashMap<String, RunId>,
}

impl RunStore {
    pub(crate) fn new() -> Self {
        Self {
            runs: HashMap::new(),
            live_by_task: HashMap::new(),
        }
    }

    pub(crate) fn find_live_by_task(&self, task_id: &str) -> Option<&Run> {
        let run_id = self.live_by_task.get(task_id)?;
        let run = self.runs.get(run_id)?;
        if is_live_status(&run.status) {
            Some(run)
        } else {
            // Defensive: a stale entry pointing to a now-terminal run should
            // never happen because `drop_live` is called on every terminal
            // transition. Returning None here keeps the live-set semantics
            // honest even under invariant drift.
            None
        }
    }

    pub(crate) fn insert(&mut self, run: Run) {
        let id = run.id.clone();
        let task_id = run.task_id.clone();
        self.runs.insert(id.clone(), run);
        // Only insert into live_by_task if the new run is live (it is —
        // Run::new sets status=Active — but defensive checks).
        if let Some(r) = self.runs.get(&id) {
            if is_live_status(&r.status) {
                self.live_by_task.insert(task_id, id);
            }
        }
    }

    pub(crate) fn get(&self, run_id: &str) -> Option<&Run> {
        self.runs.get(run_id)
    }

    pub(crate) fn get_mut(&mut self, run_id: &str) -> Option<&mut Run> {
        self.runs.get_mut(run_id)
    }

    /// O(1) removal — callers pass the task_id directly (which they already
    /// know from `run.task_id`). Fixes the O(n) lock-convoy DoS surfaced
    /// by the adversarial review.
    pub(crate) fn drop_live_by_task(&mut self, task_id: &str) {
        self.live_by_task.remove(task_id);
    }

    /// Legacy O(n) path retained for callers that only know `run_id` (e.g.,
    /// `with_status_for_test`'s terminal branch). Bounded by live-task
    /// count, not run count. `__test-util`-feature-gated so non-test builds
    /// don't fire dead-code warnings.
    #[cfg(feature = "__test-util")]
    pub(crate) fn drop_live_by_run(&mut self, run_id: &str) {
        let task_id_to_drop: Option<String> = self.live_by_task.iter().find_map(|(tid, rid)| {
            if rid.as_ref() == run_id {
                Some(tid.clone())
            } else {
                None
            }
        });
        if let Some(tid) = task_id_to_drop {
            self.live_by_task.remove(&tid);
        }
    }

    /// Idempotent insert into `live_by_task` — used by
    /// `RunManager::with_status_for_test` when installing a live target
    /// status. `__test-util`-feature-gated to silence dead-code warnings
    /// in non-test builds.
    #[cfg(feature = "__test-util")]
    pub(crate) fn ensure_live(&mut self, task_id: &str, run_id: &RunId) {
        self.live_by_task
            .insert(task_id.to_string(), run_id.clone());
    }

    pub(crate) fn runs_len(&self) -> usize {
        self.runs.len()
    }

    /// Slice C — remove a run by id. Used by `RunManager::ensure_run` to roll
    /// back the in-memory insert if `RunPersister::persist` fails (closes
    /// the audit R2 fail-open Warning by ensuring memory + disk stay
    /// consistent at create time).
    pub(crate) fn remove(&mut self, run_id: &str) {
        self.runs.remove(run_id);
    }

    /// Slice B addition — read-only iterator over all Run rows. Used by
    /// `recover_on_startup` for the Suspended-candidate scan and by
    /// `AgentRunResolver::resolve` for agent → run lookup. Callers MUST
    /// hold a read lock on the surrounding `RwLock<RunStore>` while
    /// consuming the iterator (HashMap iteration order is non-deterministic;
    /// see resolver's secondary-tie-break logic for stability).
    pub(crate) fn iter(&self) -> impl Iterator<Item = &Run> {
        self.runs.values()
    }
}

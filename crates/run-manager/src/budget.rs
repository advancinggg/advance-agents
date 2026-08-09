//! `InMemoryRunBudget` impl of `RunBudget` trait (CONTRACT-073).
//!
//! Reservation-on-check + clamp-on-commit atomicity. See MODULE-008 §3.8
//! Implementation Notes for the design rationale.

use std::sync::{Arc, RwLock};

use advance_shared_types::capability::BudgetDecision;
use advance_shared_types::run::TaskRunStatus;
use advance_shared_types::traits::{CostTrackerQuery, RunBudget};

use crate::identifier::validate_run_id;
use crate::persist::RunPersister;
use crate::store::RunStore;

pub struct InMemoryRunBudget {
    store: Arc<RwLock<RunStore>>,
    cost_tracker: Option<Arc<dyn CostTrackerQuery>>,
    /// Slice C — optional persister; when wired, `commit` re-persists the
    /// affected Run after the budget mutation so token_used / cost_usd
    /// survive restart (closes audit R3 Critical: budget mutations were
    /// not persisted, allowing reload-reopen of spent budget).
    persister: Option<Arc<RunPersister>>,
}

impl InMemoryRunBudget {
    pub(crate) fn new_with_cost_tracker(
        store: Arc<RwLock<RunStore>>,
        cost_tracker: Option<Arc<dyn CostTrackerQuery>>,
        persister: Option<Arc<RunPersister>>,
    ) -> Self {
        Self {
            store,
            cost_tracker,
            persister,
        }
    }

    /// Slice C builder — wire a [`CostTrackerQuery`] provider (MODULE-019
    /// CONTRACT-181). When wired, `check` uses `max(local, tracker.query_run)`
    /// at the cost gate to defend against the lagging-tracker fail-open vector.
    pub fn with_cost_tracker(mut self, ct: Arc<dyn CostTrackerQuery>) -> Self {
        self.cost_tracker = Some(ct);
        self
    }
}

impl RunBudget for InMemoryRunBudget {
    fn check(&self, run_id: &str, additional_tokens: u64, additional_cost: f64) -> BudgetDecision {
        if validate_run_id(run_id).is_err() {
            return BudgetDecision::Deny("budget-invalid-run-id".into());
        }
        if !additional_cost.is_finite() || additional_cost < 0.0 {
            return BudgetDecision::Deny("budget-invalid-cost".into());
        }

        let mut store = self.store.write().unwrap();
        let run = match store.get_mut(run_id) {
            Some(r) => r,
            None => return BudgetDecision::Deny("budget-unknown-run".into()),
        };
        // Status gate: refuse budget activity on terminal runs. Closes the
        // adversarial round-3 Critical surface where `check`+`commit` on a
        // Completed/Failed/Cancelled run would re-fill drained reservations
        // and inflate `token_used` / `cost_usd` post-termination.
        if !matches!(
            run.status,
            TaskRunStatus::Active | TaskRunStatus::Suspended | TaskRunStatus::Paused
        ) {
            return BudgetDecision::Deny("budget-run-terminal".into());
        }
        let b = &mut run.budget;

        // Rounds gate first (no `additional_rounds` parameter in trait
        // signature — uses stored counter; inclusive `>=` per §3.8
        // asymmetry note).
        if let Some(limit) = b.rounds_limit {
            if b.rounds_used >= limit {
                return BudgetDecision::Deny("budget-exceeded-rounds".into());
            }
        }

        // Token gate (committed + reserved + additional vs limit).
        let token_after = b
            .token_used
            .saturating_add(b.token_reserved)
            .saturating_add(additional_tokens);
        if let Some(limit) = b.token_limit {
            if token_after > limit {
                return BudgetDecision::Deny("budget-exceeded-tokens".into());
            }
        }

        // Cost gate. Slice C: when a CostTrackerQuery is wired (CONTRACT-181),
        // use `max(local cost_usd, tracker.query_run)` as the effective
        // committed cost. Lagging tracker (returns Some(lower)) → use local;
        // tracker-ahead (returns Some(higher)) → use tracker (fail-closed);
        // tracker None or missing → fall back to local (Slice A semantics).
        let effective_cost_usd = match &self.cost_tracker {
            Some(ct) => match ct.query_run(run_id) {
                Some(rc) if rc.cost_usd > b.cost_usd => rc.cost_usd,
                _ => b.cost_usd,
            },
            None => b.cost_usd,
        };
        let cost_after = effective_cost_usd + b.cost_reserved + additional_cost;
        if !cost_after.is_finite() {
            return BudgetDecision::Deny("budget-cost-overflow".into());
        }
        if let Some(limit) = b.cost_limit {
            if cost_after > limit {
                return BudgetDecision::Deny("budget-exceeded-cost".into());
            }
        }

        // Reservation: hold the headroom for the caller's pending commit.
        b.token_reserved = b.token_reserved.saturating_add(additional_tokens);
        b.cost_reserved += additional_cost;
        BudgetDecision::Allow
    }

    fn commit(&self, run_id: &str, tokens: u64, cost: f64) {
        if validate_run_id(run_id).is_err() {
            eprintln!("RunBudget::commit invalid run_id={:?}", run_id);
            return;
        }
        if !cost.is_finite() || cost < 0.0 {
            eprintln!("RunBudget::commit invalid cost={cost}");
            return;
        }
        let mut store = self.store.write().unwrap();
        let run = match store.get_mut(run_id) {
            Some(r) => r,
            None => {
                eprintln!("RunBudget::commit unknown run_id={run_id}");
                return;
            }
        };
        // Status gate: silently drop commits against terminal runs. The
        // reservation was drained at terminal transition; allowing commit
        // to bump `token_used` post-termination would defeat the drain.
        if !matches!(
            run.status,
            TaskRunStatus::Active | TaskRunStatus::Suspended | TaskRunStatus::Paused
        ) {
            eprintln!("RunBudget::commit dropped — run is terminal: run_id={run_id}");
            return;
        }
        let b = &mut run.budget;

        // CLAMP commit to reservation — over-commit dropped + logged.
        // Under-commit leaves excess reservation (accepted §3.8 trade-off).
        let allowed_tokens = b.token_reserved.min(tokens);
        let allowed_cost = b.cost_reserved.min(cost);
        if tokens > allowed_tokens {
            eprintln!(
                "RunBudget::commit excess tokens dropped: requested={tokens} reserved={allowed_tokens} run_id={run_id}"
            );
        }
        if cost > allowed_cost {
            eprintln!(
                "RunBudget::commit excess cost dropped: requested={cost} reserved={allowed_cost} run_id={run_id}"
            );
        }
        b.token_reserved -= allowed_tokens;
        b.cost_reserved -= allowed_cost;
        b.token_used = b.token_used.saturating_add(allowed_tokens);
        b.cost_usd += allowed_cost;
        // Slice C — capture a snapshot inside the lock so we can persist
        // post-mutation outside the lock (matches Slice A/B
        // lock-drop-before-emit / lock-drop-before-IO pattern). Best-effort:
        // on disk failure, the in-memory state is the source of truth for
        // the rest of the process; on restart, the disk YAML reloads the
        // last successfully-persisted budget. Operators monitor eprintln.
        let snapshot = run.clone();
        drop(store);
        if let Some(persister) = self.persister.as_ref() {
            if let Err(e) = persister.persist(&snapshot) {
                eprintln!(
                    "InMemoryRunBudget::commit persist failed for run_id={:?}: {:?} — restart may reload pre-commit budget",
                    run_id, e
                );
            }
        }
    }
}

//! Scripted `MockRunBudget` for cap-llm's `#[cfg(test)]` modules.

#![cfg(test)]

use std::collections::HashMap;
use std::sync::Mutex;

use advance_shared_types::capability::BudgetDecision;
use advance_shared_types::traits::RunBudget;

#[derive(Default)]
pub(crate) struct MockRunBudget {
    /// run_id → deny reason. Absent → Allow.
    pub deny_reasons: Mutex<HashMap<String, String>>,
    /// (run_id, tokens, cost) recorded per commit().
    pub commits: Mutex<Vec<(String, u64, f64)>>,
    /// (run_id, additional_tokens, additional_cost) recorded per check().
    pub checks: Mutex<Vec<(String, u64, f64)>>,
}

impl MockRunBudget {
    pub fn deny(&self, run_id: &str, reason: &str) {
        self.deny_reasons
            .lock()
            .unwrap()
            .insert(run_id.to_string(), reason.to_string());
    }
}

impl RunBudget for MockRunBudget {
    fn check(&self, run_id: &str, additional_tokens: u64, additional_cost: f64) -> BudgetDecision {
        self.checks
            .lock()
            .unwrap()
            .push((run_id.to_string(), additional_tokens, additional_cost));
        match self.deny_reasons.lock().unwrap().get(run_id) {
            Some(reason) => BudgetDecision::Deny(reason.clone()),
            None => BudgetDecision::Allow,
        }
    }

    fn commit(&self, run_id: &str, tokens: u64, cost: f64) {
        self.commits
            .lock()
            .unwrap()
            .push((run_id.to_string(), tokens, cost));
    }
}

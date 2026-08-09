//! L6 hot-path trigger evaluation (AC-12) + post-processor Step 9 trigger
//! state. MODULE-011 §1.3.6 "Hot-path evaluation".
//!
//! Any-of over 3 conditions, short-circuit cheapest-first
//! (`CompletedTasks` counter-cmp → `NewEntries` counter-cmp →
//! `HoursSinceLast` SystemTime subtract+cmp). `TriggerOutcome.evaluated`
//! records the conditions actually checked, in order, stopping at the first
//! that fires — the AC-12 short-circuit witness (no separate counter type).

use std::time::{Duration, SystemTime};

/// The 3 any-of conditions, ordered cheapest-first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TriggerCond {
    CompletedTasks,
    NewEntries,
    HoursSinceLast,
}

/// Instrumented evaluation result. `evaluated` is the ordered list of
/// conditions inspected; it stops at the first firing condition (short-circuit
/// witness for AC-12) or contains all 3 when none fire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TriggerOutcome {
    pub fired: bool,
    pub evaluated: Vec<TriggerCond>,
}

/// §2.10 thresholds: 24h / 20 / 3.
#[derive(Clone, Copy, Debug)]
pub struct L6TriggerThresholds {
    pub hours_since_last: u64,
    pub new_entries_threshold: u32,
    pub completed_tasks_delta: u32,
}

impl Default for L6TriggerThresholds {
    fn default() -> Self {
        Self {
            hours_since_last: 24,
            new_entries_threshold: 20,
            completed_tasks_delta: 3,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct L6TriggerInput {
    pub now: SystemTime,
    /// `None` (never run) ⇒ HoursSinceLast fires (treat as ∞ elapsed).
    pub last_l6_at: Option<SystemTime>,
    pub new_entries_since_last: u32,
    pub completed_tasks_delta: u32,
}

#[derive(Clone, Debug, Default)]
pub struct L6TriggerEvaluator {
    thresholds: L6TriggerThresholds,
}

impl L6TriggerEvaluator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_thresholds(thresholds: L6TriggerThresholds) -> Self {
        Self { thresholds }
    }

    /// Any-of, short-circuit cheapest-first. `evaluated` witnesses the
    /// short-circuit (AC-12).
    pub fn should_trigger(&self, input: &L6TriggerInput) -> TriggerOutcome {
        let mut evaluated = Vec::with_capacity(3);

        // Cond 3 (cheapest — counter compare).
        evaluated.push(TriggerCond::CompletedTasks);
        if input.completed_tasks_delta >= self.thresholds.completed_tasks_delta {
            return TriggerOutcome {
                fired: true,
                evaluated,
            };
        }

        // Cond 2 (counter compare).
        evaluated.push(TriggerCond::NewEntries);
        if input.new_entries_since_last >= self.thresholds.new_entries_threshold {
            return TriggerOutcome {
                fired: true,
                evaluated,
            };
        }

        // Cond 1 (SystemTime subtract + compare; `None` ⇒ fire).
        evaluated.push(TriggerCond::HoursSinceLast);
        let hours_fire = match input.last_l6_at {
            None => true,
            Some(last) => match input.now.duration_since(last) {
                Ok(elapsed) => {
                    elapsed >= Duration::from_secs(self.thresholds.hours_since_last * 3600)
                }
                // Clock regression — be conservative, do NOT fire on a
                // negative elapsed (mirrors FailureCooldown's fail-closed
                // posture: a backstepped clock should not spuriously trigger).
                Err(_) => false,
            },
        };
        TriggerOutcome {
            fired: hours_fire,
            evaluated,
        }
    }
}

/// Post-processor Step 9 trigger state — accumulates the deltas + last-L6
/// watermark. `record_task_completed` is the slice-C test API (real
/// event-sourced task-completion detection is `waived_scope`).
#[derive(Clone, Debug, Default)]
pub struct L6TriggerState {
    pub new_entries_since_last: u32,
    pub completed_tasks_delta: u32,
    pub last_l6_at: Option<SystemTime>,
}

impl L6TriggerState {
    pub fn record_new_entry(&mut self) {
        self.new_entries_since_last = self.new_entries_since_last.saturating_add(1);
    }

    pub fn record_task_completed(&mut self) {
        self.completed_tasks_delta = self.completed_tasks_delta.saturating_add(1);
    }

    pub fn mark_l6_ran(&mut self, at: SystemTime) {
        self.last_l6_at = Some(at);
        self.new_entries_since_last = 0;
        self.completed_tasks_delta = 0;
    }

    pub fn to_input(&self, now: SystemTime) -> L6TriggerInput {
        L6TriggerInput {
            now,
            last_l6_at: self.last_l6_at,
            new_entries_since_last: self.new_entries_since_last,
            completed_tasks_delta: self.completed_tasks_delta,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
    }

    #[test]
    fn only_completed_tasks_fires_short_circuit_at_cheapest() {
        let ev = L6TriggerEvaluator::new();
        let out = ev.should_trigger(&L6TriggerInput {
            now: at(1_000_000),
            last_l6_at: Some(at(1_000_000)), // 0 elapsed
            new_entries_since_last: 0,
            completed_tasks_delta: 3,
        });
        assert!(out.fired);
        assert_eq!(out.evaluated, vec![TriggerCond::CompletedTasks]);
    }

    #[test]
    fn only_new_entries_fires() {
        let ev = L6TriggerEvaluator::new();
        let out = ev.should_trigger(&L6TriggerInput {
            now: at(1_000_000),
            last_l6_at: Some(at(1_000_000)),
            new_entries_since_last: 20,
            completed_tasks_delta: 0,
        });
        assert!(out.fired);
        assert_eq!(
            out.evaluated,
            vec![TriggerCond::CompletedTasks, TriggerCond::NewEntries]
        );
    }

    #[test]
    fn only_hours_since_last_fires() {
        let ev = L6TriggerEvaluator::new();
        let out = ev.should_trigger(&L6TriggerInput {
            now: at(1_000_000 + 24 * 3600),
            last_l6_at: Some(at(1_000_000)),
            new_entries_since_last: 0,
            completed_tasks_delta: 0,
        });
        assert!(out.fired);
        assert_eq!(
            out.evaluated,
            vec![
                TriggerCond::CompletedTasks,
                TriggerCond::NewEntries,
                TriggerCond::HoursSinceLast
            ]
        );
    }

    #[test]
    fn none_met_does_not_fire_evaluates_all_three() {
        let ev = L6TriggerEvaluator::new();
        let out = ev.should_trigger(&L6TriggerInput {
            now: at(1_000_000 + 3600), // only 1h elapsed
            last_l6_at: Some(at(1_000_000)),
            new_entries_since_last: 1,
            completed_tasks_delta: 1,
        });
        assert!(!out.fired);
        assert_eq!(
            out.evaluated,
            vec![
                TriggerCond::CompletedTasks,
                TriggerCond::NewEntries,
                TriggerCond::HoursSinceLast
            ]
        );
    }

    #[test]
    fn cond3_and_cond1_both_met_short_circuits_at_cond3() {
        let ev = L6TriggerEvaluator::new();
        let out = ev.should_trigger(&L6TriggerInput {
            now: at(1_000_000 + 48 * 3600),
            last_l6_at: Some(at(1_000_000)),
            new_entries_since_last: 0,
            completed_tasks_delta: 5,
        });
        assert!(out.fired);
        assert_eq!(out.evaluated, vec![TriggerCond::CompletedTasks]);
    }

    #[test]
    fn last_l6_none_makes_hours_fire() {
        let ev = L6TriggerEvaluator::new();
        let out = ev.should_trigger(&L6TriggerInput {
            now: at(1_000_000),
            last_l6_at: None,
            new_entries_since_last: 0,
            completed_tasks_delta: 0,
        });
        assert!(out.fired);
        assert_eq!(out.evaluated.last(), Some(&TriggerCond::HoursSinceLast));
    }

    #[test]
    fn trigger_state_accumulates_and_resets() {
        let mut st = L6TriggerState::default();
        st.record_new_entry();
        st.record_new_entry();
        st.record_task_completed();
        assert_eq!(st.new_entries_since_last, 2);
        assert_eq!(st.completed_tasks_delta, 1);
        st.mark_l6_ran(at(5_000));
        assert_eq!(st.new_entries_since_last, 0);
        assert_eq!(st.completed_tasks_delta, 0);
        assert_eq!(st.last_l6_at, Some(at(5_000)));
    }
}

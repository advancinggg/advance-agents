//! Fail-fast monitor (PRD §4.7.9 / MODULE-015 §1.3 / AC-14 foundation —
//! verification deferred to the integrated §4.7.7 loop slice).
//!
//! Slice-B scope: ships the trait + threshold-based and presence-based check
//! semantics as INDEPENDENT PRIMITIVES. The integrated loop (periodic check
//! + crash-path trigger) is deferred.

use serde::{Deserialize, Serialize};

use crate::config::{MetricSource, Predicate};

/// One row in `auto-loop.fail_fast` (PRD §4.7.9). Distinct from `Objective`
/// because fail_fast metrics have no `name` / `role` — the role is implicit
/// `Role::FailFast`. `predicate: None` indicates presence-based detection
/// (event source only; the event's appearance is the trigger).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FailFastMetric {
    pub metric_source: MetricSource,
    #[serde(default)]
    pub predicate: Option<Predicate>,
}

/// Outcome of a single fail-fast check pass over the configured metrics.
#[derive(Clone, Debug, PartialEq)]
pub enum FailFastOutcome {
    /// All metrics within bounds.
    Pass,
    /// First-encountered breach; short-circuits the check.
    Trigger { reason: String },
}

/// Fail-fast monitor trait — implementations check each configured metric
/// once per call. The integrated-loop slice wires this to the scheduler's
/// periodic tick (frequency = `schedule` config or `after-each-turn`).
pub trait FailFastMonitor: Send + Sync {
    /// Evaluate every metric in `metrics`. Returns `FailFastOutcome::Trigger`
    /// on the first detected breach (subsequent metrics are NOT evaluated —
    /// observable via call-count side-effects in test doubles).
    fn check_iteration(&self, metrics: &[FailFastMetric]) -> FailFastOutcome;
}

/// Default monitor that takes pre-evaluated metric values as input. Concrete
/// readers (file / event / component) wire in the integrated-loop slice;
/// the primitive itself is decoupled from I/O for unit testing.
///
/// `EvaluatedMetric` represents one metric's resolved state — either a
/// numeric reading (`Value(f64)`) for threshold comparison OR a presence
/// signal (`Present(bool)`) for event-presence detection.
#[derive(Clone, Debug, PartialEq)]
pub enum EvaluatedMetric {
    /// Numeric reading; pairs with a `Predicate::op` + `Predicate::threshold`.
    Value(f64),
    /// Event-presence signal; pairs with `predicate: None`.
    Present(bool),
}

/// Default impl: applies a `Predicate` against an `EvaluatedMetric` and
/// short-circuits on first trigger. Stateless.
pub struct DefaultFailFastMonitor;

impl DefaultFailFastMonitor {
    /// Convenience for callers with pre-evaluated readings: pairs each
    /// `FailFastMetric` with an `EvaluatedMetric` and returns the outcome.
    ///
    /// **Length-mismatch semantics** (adversarial Round-1 Warning fix):
    /// when `readings.len() < metrics.len()`, the function returns
    /// `FailFastOutcome::Trigger` (fail-CLOSED) with reason
    /// `"fail-fast: insufficient readings (have=N, need=M)"`. Previously
    /// this silently skipped the unmatched metrics (fail-OPEN), allowing
    /// hostile callers to suppress fail-fast triggers by under-supplying
    /// readings. The integrated-loop slice is responsible for ensuring
    /// readings.len() == metrics.len() before calling.
    pub fn check_with_readings(
        metrics: &[FailFastMetric],
        readings: &[EvaluatedMetric],
    ) -> FailFastOutcome {
        if readings.len() < metrics.len() {
            return FailFastOutcome::Trigger {
                reason: format!(
                    "fail-fast: insufficient readings (have={}, need={})",
                    readings.len(),
                    metrics.len()
                ),
            };
        }
        for (i, metric) in metrics.iter().enumerate() {
            // After the length-mismatch guard above, indexing is safe.
            let reading = &readings[i];
            match (&metric.predicate, reading) {
                (None, EvaluatedMetric::Present(true)) => {
                    return FailFastOutcome::Trigger {
                        reason: format!("fail-fast: presence-based metric triggered (index {i})"),
                    };
                }
                (None, _) => {
                    // Presence-based but not present (or numeric mismatch) → continue.
                }
                (Some(pred), EvaluatedMetric::Value(v)) => {
                    if predicate_breached(pred, *v) {
                        return FailFastOutcome::Trigger {
                            reason: format!(
                                "fail-fast: metric index {i} breached predicate (observed={v}, op={:?}, threshold={:?})",
                                pred.op, pred.threshold
                            ),
                        };
                    }
                }
                (Some(_), EvaluatedMetric::Present(_)) => {
                    // Threshold predicate with presence-only reading → continue.
                }
            }
        }
        FailFastOutcome::Pass
    }
}

impl FailFastMonitor for DefaultFailFastMonitor {
    fn check_iteration(&self, _metrics: &[FailFastMetric]) -> FailFastOutcome {
        // Default impl without I/O-backed readers returns Pass. Production
        // wiring uses `check_with_readings` after the integrated loop has
        // fetched concrete metric values via FileMetricReader /
        // EventMetricReader / ComponentMetricReader (metric.rs trait stubs).
        FailFastOutcome::Pass
    }
}

/// Predicate breach check (used by both fail_fast and the integrated loop's
/// guardrail check). Pure-function semantics: `op` of `lt` / `le` / `gt` /
/// `ge` / `eq` compared against the optional `threshold`. Predicates without
/// a threshold (primary's keep/discard comparison) are NOT handled here —
/// the integrated loop compares against `previous_best` separately.
///
/// **`Op::Eq` semantics** (adversarial Round-1 Warning fix): floating-point
/// equality uses a **relative tolerance** of [`EQ_RELATIVE_TOLERANCE`]
/// (1e-9), scaled by `max(|observed|, |threshold|, 1.0)`. This avoids the
/// absolute-`f64::EPSILON` pitfall where huge thresholds were "always equal"
/// in a 1-unit window and tiny thresholds were "never equal." For exact
/// integer-valued metrics the tolerance is 1e-9 — well within representable
/// integer precision for u32-scale token counts; for floating-point bpb-style
/// metrics the relative tolerance is 1e-9 of the magnitude.
///
/// **NaN / non-finite semantics** (adversarial Round-2 Warning fix):
/// `observed.is_nan()` or `threshold.is_nan()` returns `true` (fail-CLOSED
/// → reports a breach). A buggy or hostile metric source emitting NaN
/// (e.g., divide-by-zero in extractor, NaN-string parsed leniently,
/// NaN-propagation through model output) previously slipped through ALL
/// comparison ops because IEEE 754 makes every comparison with NaN
/// false. The fix surfaces NaN as a fail-fast trigger so iterations
/// don't continue burning budget on broken metrics. `infinity` values
/// remain compared per IEEE 754 semantics (`+inf > N` is true for finite
/// N) — this matches operator expectations for runaway-metric detection.
pub fn predicate_breached(pred: &Predicate, observed: f64) -> bool {
    use crate::config::Op;
    let Some(threshold) = pred.threshold else {
        return false;
    };
    // Adversarial Round-2 fix: NaN observed or NaN threshold → fail-CLOSED.
    // Otherwise hostile/buggy metric sources bypass the fail-fast monitor
    // because IEEE 754 returns false for every NaN comparison.
    if observed.is_nan() || threshold.is_nan() {
        return true;
    }
    match pred.op {
        Op::Lt => observed < threshold,
        Op::Le => observed <= threshold,
        Op::Gt => observed > threshold,
        Op::Ge => observed >= threshold,
        Op::Eq => {
            let scale = observed.abs().max(threshold.abs()).max(1.0);
            (observed - threshold).abs() <= EQ_RELATIVE_TOLERANCE * scale
        }
    }
}

/// Relative tolerance for `Op::Eq` floating-point comparisons (adversarial
/// Round-1 Warning fix). 1e-9 is well below typical metric precision while
/// staying robust against `f64` round-trip noise.
pub const EQ_RELATIVE_TOLERANCE: f64 = 1e-9;

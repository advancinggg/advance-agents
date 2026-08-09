//! `success_criteria` config parser + startup validation (AC-04 / AC-05).
//!
//! Wire shape: PRD §4.7.4 / MODULE-015 §1.3.2. The spec-canonical YAML is
//! nested under a top-level **`auto-loop:`** key (the OUTER key is
//! hyphenated; INNER keys are snake_case):
//!
//! ```yaml
//! auto-loop:
//!   evaluator: research-pack@1.2.0/evaluator-bpb
//!   objectives:
//!     - name: val-bpb
//!       role: primary
//!       metric_source: { type: file, path: metrics/bpb.json, key: val_bpb }
//!       predicate: { op: lt }
//! ```
//!
//! [`SuccessCriteria::parse_yaml`] deserializes [`AutoLoopDoc`] (the wrapper)
//! and returns the inner [`SuccessCriteria`]. The ONLY hyphenated key in the
//! whole schema is the outer `auto-loop` (explicit `#[serde(rename =
//! "auto-loop")]`); everything inside is `snake_case` because MODULE-015's
//! `success_criteria` is a YAML config, NOT a WIT record (contrast
//! MODULE-014's PRD §9.5 kebab WIT shapes).
//!
//! Slice A enforces only the AC-04 (exactly-one-primary) + AC-05
//! (evaluator-if-component) rules; the role × metric_source role-allowed
//! matrix (AC-06/07) is deferred to slice B — the parser accepts those
//! combinations.

use serde::{Deserialize, Deserializer, Serialize};

use crate::error::AutoLoopError;

/// Max UTF-8 byte length of any bounded string wire field. Post-parse
/// rejection: serde materializes the `String` first, then the bounded
/// helper rejects fail-closed if it exceeds this cap (so an oversized
/// string in `success_criteria` is rejected, not silently retained).
/// Peak parse memory is bounded by serde_yml's own input-size limit, not
/// this cap — same post-parse posture + operator-authored-admin-config
/// trust model as [`MAX_OBJECTIVES`] / [`MAX_FILTER_VALUE_BYTES`] (audit
/// round-3 wording made consistent with the others).
pub const MAX_CONFIG_STRING_LEN: usize = 1024;

/// Max objectives in a single `success_criteria`. Rejected by
/// `deserialize_bounded_objectives` as part of `parse_yaml` (so the parse
/// path fails closed with `AutoLoopError::Parse` instead of silently
/// accepting an oversized list) AND re-checked at
/// [`SuccessCriteria::validate`] → [`AutoLoopError::TooManyObjectives`]
/// for the direct-Rust-construction path.
///
/// Threat-model note (audit round-2 wording fix): this is a **post-parse
/// rejection** that bounds the *accepted/stored* config — serde first
/// materializes the `Vec<Objective>`, then the helper rejects if
/// `len > MAX_OBJECTIVES`. Peak *parse* memory is bounded by serde_yml's
/// own input-size limit, not by this cap (a streaming pre-allocation
/// bound would need a custom `Visitor`). This matches the established
/// MODULE-014 `MAX_OPAQUE_VALUE_BYTES` precedent and is the appropriate
/// fit for `success_criteria`, which is operator-authored admin config
/// (MODULE-015 §1.6 — evaluator/config is admin-approved, not arbitrary
/// untrusted wire input), so bounding the accepted value + fail-closed
/// rejection is the right posture; full streaming-bound hardening is
/// unnecessary at this trust layer.
pub const MAX_OBJECTIVES: usize = 64;

/// Max serialized byte size of the optional `MetricSource::Event.filter`
/// opaque `serde_json::Value`. Bounds the *accepted/stored* filter so an
/// oversized nested value in `success_criteria` is rejected fail-closed
/// (not silently retained). Peak *parse* memory is bounded by serde_yml's
/// own input-size limit, not by this cap — same post-parse posture as
/// [`MAX_OBJECTIVES`] and the established MODULE-014
/// `MAX_OPAQUE_VALUE_BYTES` precedent; appropriate for operator-authored
/// admin config (MODULE-015 §1.6). 16 KiB. (audit round-1 fix; round-2
/// wording made accurate.)
pub const MAX_FILTER_VALUE_BYTES: usize = 16 * 1024;

fn deserialize_bounded_string<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    if s.len() > MAX_CONFIG_STRING_LEN {
        return Err(serde::de::Error::custom(format!(
            "config string field length {} exceeds MAX_CONFIG_STRING_LEN {}",
            s.len(),
            MAX_CONFIG_STRING_LEN
        )));
    }
    Ok(s)
}

fn deserialize_bounded_string_opt<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let s: Option<String> = Option::deserialize(deserializer)?;
    if let Some(ref inner) = s {
        if inner.len() > MAX_CONFIG_STRING_LEN {
            return Err(serde::de::Error::custom(format!(
                "optional config string field length {} exceeds MAX_CONFIG_STRING_LEN {}",
                inner.len(),
                MAX_CONFIG_STRING_LEN
            )));
        }
    }
    Ok(s)
}

/// Parse-path cap on the objectives list: serde first materializes the
/// `Vec<Objective>`, then this helper rejects (fail-closed) if
/// `len > MAX_OBJECTIVES` so `parse_yaml` returns `AutoLoopError::Parse`
/// rather than silently accepting an oversized list. Post-parse rejection
/// (peak parse memory bounded by serde_yml's input-size limit, not this
/// cap — see [`MAX_OBJECTIVES`] threat-model note + the
/// `deserialize_bounded_filter` caveat below; matches MODULE-014's
/// precedent). `validate()` re-checks for the direct-Rust-construction
/// path. (audit round-1 fix; round-2 wording made accurate.)
fn deserialize_bounded_objectives<'de, D>(deserializer: D) -> Result<Vec<Objective>, D::Error>
where
    D: Deserializer<'de>,
{
    let v: Vec<Objective> = Vec::deserialize(deserializer)?;
    if v.len() > MAX_OBJECTIVES {
        return Err(serde::de::Error::custom(format!(
            "objectives length {} exceeds MAX_OBJECTIVES {}",
            v.len(),
            MAX_OBJECTIVES
        )));
    }
    Ok(v)
}

/// Parse-path cap on the optional `fail_fast` list: same fail-closed
/// posture as [`deserialize_bounded_objectives`]. serde first materializes
/// the `Option<Vec<FailFastMetric>>`, then this helper rejects oversized
/// lists at the serde boundary so `parse_yaml` returns
/// `AutoLoopError::Parse` rather than silently accepting an OOM-amplifying
/// list. (Adversarial round-1 Critical fix — `fail_fast` previously lacked
/// the boundary cap that `objectives` had, allowing a multi-GB list to be
/// materialized before `validate()` rejected it.)
fn deserialize_bounded_fail_fast<'de, D>(
    deserializer: D,
) -> Result<Option<Vec<crate::fail_fast::FailFastMetric>>, D::Error>
where
    D: Deserializer<'de>,
{
    let v: Option<Vec<crate::fail_fast::FailFastMetric>> = Option::deserialize(deserializer)?;
    if let Some(ref inner) = v {
        if inner.len() > MAX_OBJECTIVES {
            return Err(serde::de::Error::custom(format!(
                "fail_fast length {} exceeds MAX_OBJECTIVES {}",
                inner.len(),
                MAX_OBJECTIVES
            )));
        }
    }
    Ok(v)
}

/// Parse-path cap on the opaque `MetricSource::Event.filter` value:
/// reject (fail-closed) payloads whose serialized form exceeds
/// [`MAX_FILTER_VALUE_BYTES`]. The check runs AFTER `Value` parsing, so
/// peak parse memory is bounded only by serde_yml's own input-size limit;
/// the *accepted/stored* value is hard-bounded. (audit round-1 fix;
/// round-2 wording made accurate — this is post-parse bounding of the
/// stored value, not a pre-allocation streaming bound; matches the
/// MODULE-014 precedent and the operator-authored-config trust model.)
fn deserialize_bounded_filter<'de, D>(
    deserializer: D,
) -> Result<Option<serde_json::Value>, D::Error>
where
    D: Deserializer<'de>,
{
    let v: Option<serde_json::Value> = Option::deserialize(deserializer)?;
    if let Some(ref inner) = v {
        let size = inner.to_string().len();
        if size > MAX_FILTER_VALUE_BYTES {
            return Err(serde::de::Error::custom(format!(
                "metric_source.filter serialized size {size} exceeds MAX_FILTER_VALUE_BYTES {MAX_FILTER_VALUE_BYTES}"
            )));
        }
    }
    Ok(v)
}

/// Outer wrapper for the spec-canonical `auto-loop:`-keyed config document
/// (PRD §4.7.4 / MODULE-015 §1.3.2). [`SuccessCriteria::parse_yaml`]
/// deserializes THIS, then returns the inner [`SuccessCriteria`]. The outer
/// key is hyphenated, so an explicit `rename` (not `rename_all`) is used.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AutoLoopDoc {
    #[serde(rename = "auto-loop")]
    pub auto_loop: SuccessCriteria,
}

/// The `auto-loop:` config object: an optional evaluator Pack ref + the
/// objectives list + slice-B additive widenings (`per_iteration_budget`,
/// `fail_fast`). This IS the type CONTRACT-140's `AutoLoopConfig` parameter
/// aliases (see [`AutoLoopConfig`]).
///
/// Slice-B widening is non-breaking: both new fields are `Option<...>` +
/// `#[serde(default)]`, so configs predating slice B parse unchanged.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct SuccessCriteria {
    #[serde(default, deserialize_with = "deserialize_bounded_string_opt")]
    pub evaluator: Option<String>,
    #[serde(deserialize_with = "deserialize_bounded_objectives")]
    pub objectives: Vec<Objective>,
    /// PRD §4.7.8 — slice-B addition. Optional per-iteration budget config.
    #[serde(default)]
    pub per_iteration_budget: Option<crate::budget::PerIterationBudget>,
    /// PRD §4.7.9 — slice-B addition. Optional list of fail-fast metrics
    /// monitored periodically during an iteration. Adversarial Round-1
    /// Critical fix: parse-path cap via `deserialize_bounded_fail_fast`
    /// so oversized lists are rejected at the serde boundary (not after
    /// allocation); `validate()` re-checks for the direct-Rust-construction
    /// path. Matches `objectives` posture.
    #[serde(default, deserialize_with = "deserialize_bounded_fail_fast")]
    pub fail_fast: Option<Vec<crate::fail_fast::FailFastMetric>>,
    /// Stage-D — global safety valve + degrade thresholds (PRD §4.7.5 / §4.7.8,
    /// MODULE-015 §2.10). ONE additive field nesting all safety/degrade knobs.
    /// `Option` + `#[serde(default)]` so pre-Stage-D configs parse unchanged; an
    /// absent value still enforces the §2.10 DEFAULT limits (the detectors
    /// materialize defaults via [`SafetyValve`]'s accessor methods), NOT
    /// "no limit".
    #[serde(default)]
    pub safety_valve: Option<SafetyValve>,
}

/// §2.10 safety-valve hard-limit + degrade-threshold defaults (MODULE-015
/// §2.10 lines 473-479). Applied by the [`SafetyValve`] accessors when a
/// field is `None`, so an absent/partial `safety_valve` still enforces the
/// mandated limits.
pub const DEFAULT_MAX_ITERATIONS: u32 = 100;
/// §2.10 default `auto_loop.max_cost_usd`.
pub const DEFAULT_MAX_COST_USD: f64 = 100.0;
/// §2.10 default `auto_loop.max_wall_time_hours` (HOURS — distinct scale from
/// the per-iteration [`crate::budget::PerIterationBudget::max_wall_time_sec`]
/// which is SECONDS; the global valve is whole-run hours).
pub const DEFAULT_MAX_WALL_TIME_HOURS: u64 = 24;
/// §2.10 default `auto_loop.consecutive_no_progress_limit`.
pub const DEFAULT_NO_PROGRESS_LIMIT: u32 = 5;
/// §2.10 default `auto_loop.consecutive_llm_errors_limit`.
pub const DEFAULT_LLM_ERRORS_LIMIT: u32 = 3;
/// §2.10 default `auto_loop.llm_error_backoff_base_sec`.
pub const DEFAULT_LLM_BACKOFF_BASE_SEC: u64 = 60;
/// §2.10 default `auto_loop.llm_error_backoff_max_sec` (1h cap).
pub const DEFAULT_LLM_BACKOFF_MAX_SEC: u64 = 3600;

/// Exponent cap for the LLM-error exponential backoff (`2^n`). Clamped so
/// `base*2^n` cannot overflow `u64` before the `min(max)` clamp — at n=20 the
/// factor (≈1.05M) already vastly exceeds any realistic `max_sec`, so the
/// result saturates to `max` long before this cap. Defense-in-depth against a
/// hostile/huge `consecutive_llm_errors`.
pub const BACKOFF_EXP_CAP: u32 = 20;

/// Stage-D global safety valve (hard stop) + degrade-threshold config
/// (MODULE-015 §2.10). All fields `Option`; accessors materialize the §2.10
/// defaults when `None`. Wall-time is HOURS (the whole-run valve), distinct
/// from the per-iteration budget's seconds.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct SafetyValve {
    #[serde(default)]
    pub max_iterations: Option<u32>,
    #[serde(default)]
    pub max_cost_usd: Option<f64>,
    #[serde(default)]
    pub max_wall_time_hours: Option<u64>,
    #[serde(default)]
    pub consecutive_no_progress_limit: Option<u32>,
    #[serde(default)]
    pub consecutive_llm_errors_limit: Option<u32>,
    #[serde(default)]
    pub llm_error_backoff_base_sec: Option<u64>,
    #[serde(default)]
    pub llm_error_backoff_max_sec: Option<u64>,
}

impl SafetyValve {
    /// `max_iterations`, defaulting to §2.10's 100.
    pub fn max_iterations(&self) -> u32 {
        self.max_iterations.unwrap_or(DEFAULT_MAX_ITERATIONS)
    }
    /// `max_cost_usd`, defaulting to §2.10's 100.0. (Finite-ness is enforced at
    /// [`SuccessCriteria::validate`] admission time.)
    pub fn max_cost_usd(&self) -> f64 {
        self.max_cost_usd.unwrap_or(DEFAULT_MAX_COST_USD)
    }
    /// `max_wall_time_hours`, defaulting to §2.10's 24.
    pub fn max_wall_time_hours(&self) -> u64 {
        self.max_wall_time_hours
            .unwrap_or(DEFAULT_MAX_WALL_TIME_HOURS)
    }
    /// The whole-run wall-time limit in SECONDS (`hours * 3600`, saturating).
    pub fn max_wall_time_sec(&self) -> u64 {
        self.max_wall_time_hours().saturating_mul(3600)
    }
    /// Consecutive-no-progress Degrade threshold, defaulting to §2.10's 5.
    pub fn no_progress_limit(&self) -> u32 {
        self.consecutive_no_progress_limit
            .unwrap_or(DEFAULT_NO_PROGRESS_LIMIT)
    }
    /// Consecutive-LLM-error Degrade threshold, defaulting to §2.10's 3.
    pub fn llm_errors_limit(&self) -> u32 {
        self.consecutive_llm_errors_limit
            .unwrap_or(DEFAULT_LLM_ERRORS_LIMIT)
    }
    /// Exponential-backoff base seconds, defaulting to §2.10's 60.
    pub fn llm_backoff_base_sec(&self) -> u64 {
        self.llm_error_backoff_base_sec
            .unwrap_or(DEFAULT_LLM_BACKOFF_BASE_SEC)
    }
    /// Exponential-backoff max seconds (1h), defaulting to §2.10's 3600.
    pub fn llm_backoff_max_sec(&self) -> u64 {
        self.llm_error_backoff_max_sec
            .unwrap_or(DEFAULT_LLM_BACKOFF_MAX_SEC)
    }

    /// Compute the LLM-error backoff deadline (ms) from `now_ms` + the current
    /// error streak. All arithmetic is checked/saturating with a clamped
    /// exponent ([`BACKOFF_EXP_CAP`]) so no value can panic (debug) or wrap
    /// (release); the delay saturates to `llm_backoff_max_sec`.
    pub fn backoff_until_ms(&self, now_ms: u64, consecutive_llm_errors: u32) -> u64 {
        let n = consecutive_llm_errors.min(BACKOFF_EXP_CAP);
        let base_ms = self.llm_backoff_base_sec().saturating_mul(1000);
        let max_ms = self.llm_backoff_max_sec().saturating_mul(1000);
        let factor = 2u64.saturating_pow(n);
        let delay = base_ms.saturating_mul(factor).min(max_ms);
        now_ms.saturating_add(delay)
    }
}

/// One objective row. `metric_source` (snake_case wire key) is the field the
/// round-6 fix turned on — PRD §4.7.4 line 787 spells it `metric_source`.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct Objective {
    #[serde(deserialize_with = "deserialize_bounded_string")]
    pub name: String,
    pub role: Role,
    pub metric_source: MetricSource,
    pub predicate: Predicate,
}

/// Objective role. `primary` decides keep/discard; `guardrail` does a
/// threshold check; `fail_fast` (PRD §4.7.9) is mid-iteration. Slice A only
/// validates the exactly-one-primary rule.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Primary,
    Guardrail,
    FailFast,
}

/// Metric source. `#[serde(tag = "type")]` matches the spec
/// `metric_source: { type: file, ... }` discriminator (PRD §4.7.4).
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum MetricSource {
    File {
        #[serde(deserialize_with = "deserialize_bounded_string")]
        path: String,
        #[serde(deserialize_with = "deserialize_bounded_string")]
        key: String,
    },
    Event {
        #[serde(deserialize_with = "deserialize_bounded_string")]
        event_type: String,
        #[serde(default, deserialize_with = "deserialize_bounded_string_opt")]
        payload_key: Option<String>,
        // NOT `serde_yml::Value` — that would leak serde_yml into this
        // crate's PUBLIC API (MetricSource is re-exported), coupling every
        // consumer to the serde_yml pin and violating the workspace
        // boundary discipline MODULE-003 follows (git2 kept pub(crate)).
        // `serde_json::Value` is the workspace-standard opaque public value
        // type (precedent: scheduler types.rs GrantDraft/RetryConfig).
        // serde_yml deserializes a YAML mapping into serde_json::Value
        // transparently. Bounded at the serde boundary
        // (deserialize_bounded_filter) so an attacker cannot embed a
        // multi-GB nested value in success_criteria (audit round-1 fix).
        #[serde(default, deserialize_with = "deserialize_bounded_filter")]
        filter: Option<serde_json::Value>,
    },
    Component {
        #[serde(deserialize_with = "deserialize_bounded_string")]
        output_key: String,
    },
}

/// keep/discard comparison predicate. `op: lt` etc. per PRD §4.7.4.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct Predicate {
    pub op: Op,
    #[serde(default)]
    pub threshold: Option<f64>,
}

/// Comparison operator. `lt`/`gt`/`le`/`ge`/`eq` per PRD §4.7.4.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Op {
    Lt,
    Gt,
    Le,
    Ge,
    Eq,
}

/// CONTRACT-140 §2.3 names the `start` parameter `AutoLoopConfig`. The
/// documented `auto-loop:` config object IS `{evaluator, objectives}` =
/// [`SuccessCriteria`], so this is a spec-faithful type alias, not an
/// invented wrapper (mirrors `AutoError = AutoLoopError`). Slice B may
/// widen it to a struct super-setting `SuccessCriteria` with safety-valve
/// fields (max_iterations / max_cost_usd / max_wall_time_sec — AC-13);
/// that is a non-breaking widening because no slice-A caller depends on
/// `AutoLoopConfig` being a bare alias.
pub type AutoLoopConfig = SuccessCriteria;

impl SuccessCriteria {
    /// Parse the spec-canonical `auto-loop:`-wrapped config document and
    /// return the unwrapped inner criteria. Expects the wrapper (the real
    /// config-file shape); a bare `{evaluator, objectives}` doc is rejected
    /// by `AutoLoopDoc`'s `deny_unknown_fields`.
    pub fn parse_yaml(s: &str) -> Result<SuccessCriteria, AutoLoopError> {
        serde_yml::from_str::<AutoLoopDoc>(s)
            .map(|d| d.auto_loop)
            .map_err(|e| AutoLoopError::Parse(e.to_string()))
    }

    /// Startup validation (admission-time, called by
    /// `DefaultAutoLoopDriver::start` and exercised directly by tests):
    /// - AC-04: exactly one `role: primary` objective.
    /// - AC-05: any `metric_source` with `type: component` requires a
    ///   top-level `evaluator`.
    /// - defense-in-depth: at most [`MAX_OBJECTIVES`] objectives. NOTE:
    ///   the parse path already fails closed at the serde boundary
    ///   (`deserialize_bounded_objectives`), so this re-check only fires
    ///   for the direct-Rust-construction path (someone building
    ///   `SuccessCriteria` in code, bypassing `parse_yaml`).
    ///
    /// Slice B (AC-06 / AC-07): the role × metric_source role-allowed
    /// matrix is enforced via `crate::metric::validate_role_source_matrix`
    /// at the end. Slice B also defense-in-depth-checks the optional
    /// `fail_fast` list size against [`MAX_OBJECTIVES`] (the serde
    /// boundary cap on `objectives` doesn't apply to `fail_fast`).
    pub fn validate(&self) -> Result<(), AutoLoopError> {
        if self.objectives.len() > MAX_OBJECTIVES {
            return Err(AutoLoopError::TooManyObjectives(self.objectives.len()));
        }

        // Stage-D: reject non-finite cost limits at admission. `check_budget`
        // (and the safety-valve detector) compare `observed > limit`; a `NaN`
        // limit makes the comparison `false` (cap never trips) and `+Inf`
        // disables the cap — both fail-OPEN. Validate BOTH the global
        // safety-valve cost and the pre-existing per-iteration budget cost so
        // a bad config is rejected fail-CLOSED at `start()` (matches the
        // results.rs non-finite posture + the RunBudget finite invariant).
        if let Some(sv) = self.safety_valve.as_ref() {
            if let Some(c) = sv.max_cost_usd {
                if !c.is_finite() {
                    return Err(AutoLoopError::NonFiniteCostLimit(
                        "safety_valve.max_cost_usd",
                    ));
                }
            }
        }
        if let Some(b) = self.per_iteration_budget.as_ref() {
            if let Some(c) = b.max_cost_usd {
                if !c.is_finite() {
                    return Err(AutoLoopError::NonFiniteCostLimit(
                        "per_iteration_budget.max_cost_usd",
                    ));
                }
            }
        }

        if let Some(fail_fast) = self.fail_fast.as_ref() {
            if fail_fast.len() > MAX_OBJECTIVES {
                return Err(AutoLoopError::TooManyObjectives(fail_fast.len()));
            }
        }

        let primary_count = self
            .objectives
            .iter()
            .filter(|o| o.role == Role::Primary)
            .count();
        match primary_count {
            0 => return Err(AutoLoopError::MissingPrimary),
            1 => {}
            n => return Err(AutoLoopError::MultiplePrimary(n)),
        }

        // AC-05 evaluator-required: a `type: component` metric_source needs a
        // top-level evaluator. Wave-22 (autoloop-integ): this now scans BOTH
        // `objectives` AND `fail_fast` — a Component-source fail_fast metric is
        // executable (the integrated crash-coordinator reads it via the real
        // ComponentMetricReader), so a Component fail_fast without an evaluator
        // must be rejected at admission, not silently accepted.
        let has_component = self
            .objectives
            .iter()
            .map(|o| &o.metric_source)
            .chain(self.fail_fast.iter().flatten().map(|m| &m.metric_source))
            .any(|src| matches!(src, MetricSource::Component { .. }));
        if has_component && self.evaluator.is_none() {
            return Err(AutoLoopError::MissingEvaluator);
        }

        // Slice B AC-06/AC-07 admission-time check.
        crate::metric::validate_role_source_matrix(self)?;

        Ok(())
    }

    /// The configured [`SafetyValve`], or a default-valued one (which still
    /// materializes the §2.10 hard limits via its accessors) when none is set.
    /// The Stage-D `on_tick` detectors read limits through this so an absent
    /// `safety_valve` enforces the §2.10 defaults, NOT "no limit".
    pub fn safety_valve_or_default(&self) -> SafetyValve {
        self.safety_valve.clone().unwrap_or_default()
    }
}

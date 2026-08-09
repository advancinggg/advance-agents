//! Metric source readers + role × source matrix validator (PRD §4.7.4 /
//! MODULE-015 §1.3.2). Slice-B in-scope: AC-06 (3 source types with correct
//! role constraints) + AC-07 (high-fanout event types require filter).
//!
//! Role × source matrix per PRD §4.7.4 Table + §4.7.9 example, resolved
//! permissively per MODULE-015 §3.8 note 5 (slice-B design choice):
//!
//! | Role        | File | Event | Component |
//! |-------------|------|-------|-----------|
//! | Primary     | Ok   | Err   | Ok        |
//! | Guardrail   | Ok   | Ok†   | Ok        |
//! | FailFast    | Ok‡  | Ok†   | Ok‡       |
//!
//! † Event requires non-empty `filter` for high-fanout event_types
//!   (`component.finished` / `component.error`).
//! ‡ Permissive per PRD §4.7.9 example using `type: file` with `fail_fast` —
//!   strict §4.7.4 reading would prohibit but §4.7.9 endorses (see §3.8 note 5).

use crate::config::{MetricSource, Objective, Role, SuccessCriteria};

/// High-fanout event_types per PRD §4.7.4 — filter mandatory when used with
/// `type: event` to avoid matching evaluator's own events or unrelated
/// components (PRD §4.7.4 line 818).
pub const HIGH_FANOUT_EVENT_TYPES: &[&str] = &["component.finished", "component.error"];

/// Role × source matrix violations (AC-06/AC-07).
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum MetricRoleSourceError {
    /// AC-06: `role: primary` with `metric_source: { type: event }` is prohibited.
    #[error("role=primary with metric_source.type=event is prohibited (PRD §4.7.4 Table)")]
    EventNotAllowedAsPrimary,

    /// AC-07: high-fanout event_type without a filter is prohibited.
    #[error("metric_source.type=event with event_type=`{0}` requires non-empty `filter` (high-fanout event)")]
    FilterRequiredForHighFanout(String),
}

/// Pure-function role × source check (testable in isolation).
pub fn validate_role_source(
    role: Role,
    source: &MetricSource,
) -> Result<(), MetricRoleSourceError> {
    match (role, source) {
        (Role::Primary, MetricSource::Event { .. }) => {
            Err(MetricRoleSourceError::EventNotAllowedAsPrimary)
        }
        (
            _,
            MetricSource::Event {
                event_type, filter, ..
            },
        ) => {
            if HIGH_FANOUT_EVENT_TYPES.contains(&event_type.as_str())
                && !is_filter_substantive(filter.as_ref())
            {
                return Err(MetricRoleSourceError::FilterRequiredForHighFanout(
                    event_type.clone(),
                ));
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// Returns true when the filter is BOTH present AND substantive (non-empty
/// non-null content matching event payload fields). Adversarial Round-2
/// Warning fix: previously the validator only checked `filter.is_none()`,
/// accepting `filter: null`, `filter: {}`, `filter: []` — all of which
/// defeat the filter's purpose (matching all events including the
/// evaluator's own emissions on high-fanout types).
///
/// "Substantive" means: an object with at least one key (the
/// MODULE-014 §9.5 `trigger-filter` precise-match field model), OR a
/// non-empty array. Bare scalars (booleans, numbers, strings) and `null`
/// are rejected — they don't form a precise-match constraint per the
/// existing trigger-filter semantics.
fn is_filter_substantive(filter: Option<&serde_json::Value>) -> bool {
    let Some(v) = filter else {
        return false;
    };
    match v {
        serde_json::Value::Null => false,
        serde_json::Value::Object(map) => !map.is_empty(),
        serde_json::Value::Array(arr) => !arr.is_empty(),
        // Bare scalars (bool / number / string) don't form a
        // precise-match field constraint — reject as not substantive.
        _ => false,
    }
}

/// Aggregate validator: walks `criteria.objectives` (each with its declared
/// role) AND `criteria.fail_fast` (each with implicit Role::FailFast).
/// Slice B extends `SuccessCriteria::validate()` to call this at the end.
pub fn validate_role_source_matrix(
    criteria: &SuccessCriteria,
) -> Result<(), MetricRoleSourceError> {
    for obj in &criteria.objectives {
        validate_role_source(obj.role, &obj.metric_source)?;
    }
    if let Some(fail_fast) = criteria.fail_fast.as_ref() {
        for metric in fail_fast {
            validate_role_source(Role::FailFast, &metric.metric_source)?;
        }
    }
    Ok(())
}

/// Reader stub traits — concrete implementations land with the integrated
/// loop. Slice B ships only the trait surface so test doubles can be wired.

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum MetricReadError {
    #[error("metric path not found: {0}")]
    NotFound(String),
    #[error("metric parse error: {0}")]
    Parse(String),
}

/// Reads a `MetricSource::File` (workspace-relative JSON/YAML lookup).
pub trait FileMetricReader: Send + Sync {
    fn read_file_metric(&self, path: &str, key: &str) -> Result<f64, MetricReadError>;
}

/// Reads a `MetricSource::Event` (EventBus subscription within the current
/// iteration window). Returns presence or extracted-value-as-f64.
pub trait EventMetricReader: Send + Sync {
    fn is_event_present(&self, event_type: &str, filter: Option<&serde_json::Value>) -> bool;
    fn read_event_metric(
        &self,
        event_type: &str,
        payload_key: &str,
        filter: Option<&serde_json::Value>,
    ) -> Result<f64, MetricReadError>;
}

/// Reads a `MetricSource::Component` (evaluator component output JSON).
pub trait ComponentMetricReader: Send + Sync {
    fn read_component_metric(&self, output_key: &str) -> Result<f64, MetricReadError>;
}

/// Wave-22 (autoloop-integ) — the real, workspace-rooted [`FileMetricReader`]
/// production impl. Reads a JSON (or YAML) metric file under the workspace and
/// extracts a numeric top-level `key` as `f64`.
///
/// **Path confinement (security — never read outside the workspace).** The
/// resolution order is deliberate (plan-eval r5/r6): (i) LEXICAL reject FIRST —
/// an absolute `path` or any `..` / root / prefix component is rejected WITHOUT
/// touching the filesystem; (ii) join the (now guaranteed-relative) path under
/// `workspace_root`; (iii) if the joined path does NOT exist, return `NotFound`
/// (an in-bounds-absent metric file is a clean `NotFound`, never a reject —
/// `canonicalize` is not called on a non-existent path); (iv) if it DOES exist,
/// `canonicalize` it and verify it stays under `canonicalize(workspace_root)`,
/// rejecting a symlink escape BEFORE any read; (v) read the verified CANONICAL
/// path (not the original joined path) — closing a symlink-swap micro-TOCTOU.
///
/// A rejected (out-of-bounds) path and a wired-but-absent file both surface as
/// [`MetricReadError::NotFound`] (with distinguishing messages); the fail-fast
/// branch treats any read error as a fail-CLOSED crash (matching the guardrail
/// branch), so the security property — never read outside the workspace — is
/// what the ordering guarantees.
///
/// **Residual check-vs-read TOCTOU (unreachable in production).** Between the
/// `canonicalize`+verify and the read, an intermediate path component of the
/// verified canonical path could in principle be swapped for a symlink escaping
/// the workspace (reading the verified canonical *path string*, not a pinned
/// file descriptor). This is UNREACHABLE for the sandboxed guest: cap-fs
/// mediates every guest filesystem op and does NOT permit symlink creation
/// (the same invariant Wave-16 relied on — "cap-fs no-symlink-create ⇒ TOCTOU
/// unreachable"), so the guest cannot create the symlink to swap. And even if a
/// swap did occur, the fail_fast branch reads the value into a single `f64` and
/// fail-CLOSES on any error, bounding the impact to a numeric read of one
/// attacker-chosen file — never a write or arbitrary disclosure. A future
/// hardening (open-then-verify via `openat2(RESOLVE_BENEATH)`) is Linux-only and
/// unnecessary under the cap-fs invariant.
pub struct DefaultFileMetricReader {
    workspace_root: std::path::PathBuf,
}

impl DefaultFileMetricReader {
    pub fn new(workspace_root: impl Into<std::path::PathBuf>) -> Self {
        Self {
            workspace_root: workspace_root.into(),
        }
    }
}

impl FileMetricReader for DefaultFileMetricReader {
    fn read_file_metric(&self, path: &str, key: &str) -> Result<f64, MetricReadError> {
        use std::path::{Component, Path};

        // (i) LEXICAL reject — absolute or traversal, WITHOUT touching the FS.
        let rel = Path::new(path);
        if rel.is_absolute() {
            return Err(MetricReadError::NotFound(format!(
                "metric path escapes workspace (absolute): {path}"
            )));
        }
        for comp in rel.components() {
            match comp {
                Component::Normal(_) | Component::CurDir => {}
                Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                    return Err(MetricReadError::NotFound(format!(
                        "metric path escapes workspace (traversal): {path}"
                    )));
                }
            }
        }

        // (ii) join under the workspace root.
        let joined = self.workspace_root.join(rel);

        // (iii) in-bounds-absent → NotFound (do NOT canonicalize a missing path,
        // and never read outside the workspace).
        if !joined.exists() {
            return Err(MetricReadError::NotFound(format!(
                "metric file not found: {path}"
            )));
        }

        // (iv) canonicalize + verify under the canonical workspace root BEFORE
        // reading — rejects a symlink whose target escapes the workspace.
        let canon = joined.canonicalize().map_err(|e| {
            MetricReadError::NotFound(format!("metric path canonicalize failed: {path}: {e}"))
        })?;
        let canon_root = self.workspace_root.canonicalize().map_err(|e| {
            MetricReadError::NotFound(format!("workspace root canonicalize failed: {e}"))
        })?;
        if !canon.starts_with(&canon_root) {
            return Err(MetricReadError::NotFound(format!(
                "metric path escapes workspace (symlink): {path}"
            )));
        }

        // (v) read the VERIFIED canonical path (not the pre-canonicalize join).
        let content = std::fs::read_to_string(&canon).map_err(|e| {
            MetricReadError::NotFound(format!("metric file read failed: {path}: {e}"))
        })?;

        // Parse JSON first (strict/common), then YAML (a superset) as a fallback.
        let value: serde_json::Value = serde_json::from_str(&content)
            .or_else(|_| serde_yml::from_str::<serde_json::Value>(&content))
            .map_err(|e| {
                MetricReadError::Parse(format!("metric file parse failed: {path}: {e}"))
            })?;

        let field = value.get(key).ok_or_else(|| {
            MetricReadError::NotFound(format!("metric key not found: `{key}` in {path}"))
        })?;
        let num = field.as_f64().ok_or_else(|| {
            MetricReadError::Parse(format!("metric key `{key}` is not a number in {path}"))
        })?;
        if !num.is_finite() {
            return Err(MetricReadError::Parse(format!(
                "metric key `{key}` is non-finite in {path}"
            )));
        }
        Ok(num)
    }
}

/// Convenience: extract objective via index for callers that want
/// observability into which specific objective failed validation.
pub fn matrix_view(criteria: &SuccessCriteria) -> Vec<(Role, &MetricSource)> {
    let mut out: Vec<(Role, &MetricSource)> = criteria
        .objectives
        .iter()
        .map(|o: &Objective| (o.role, &o.metric_source))
        .collect();
    if let Some(fail_fast) = criteria.fail_fast.as_ref() {
        for metric in fail_fast {
            out.push((Role::FailFast, &metric.metric_source));
        }
    }
    out
}

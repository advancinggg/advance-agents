//! Auto-bootstrap coordination surface (PRD §12.5.6 / §15.3.21 / MODULE-015
//! §1.4 AC-22 — M015-side closure; cross-module wiring deferred to the
//! integrated-loop slice).
//!
//! # Boundary note (m015-slice-d)
//!
//! MODULE-005 (cap-lifecycle) owns the AUTHORITATIVE auto-bootstrap executor
//! (`parse_auto_bootstrap` + `apply_auto_bootstrap` — the §12.5.6 5-row matrix,
//! hardened YAML parser, kind=child validation). This module does **NOT**
//! duplicate that logic. It ships a COORDINATION surface analogous to how
//! MODULE-015 consumes `CostTrackerQuery` (MODULE-019) and `SkillStateReader`
//! (MODULE-017) via dependency-inverted traits:
//!
//! - [`AutoBootstrapApplier`] abstracts M005's executor (the integrated-loop
//!   slice provides an adapter that calls cap-lifecycle and translates its
//!   `BootstrapReport`/`BootstrapError` into [`M015BootstrapReport`] — see
//!   MODULE-015 §3.8 note 9 for the translation contract).
//! - [`AutoBootstrapEventSink`] abstracts MODULE-019's `EventBusEmit`
//!   (CONTRACT-180) — the integrated-loop slice provides an adapter wrapping
//!   the sync `emit` in an `async fn`.
//!
//! [`crate::driver::DefaultAutoLoopDriver::consult_auto_bootstrap`] is the
//! M015-side coordination method that composes the two surfaces. Its
//! invocation at Auto-mode startup (the `start → checkpoint_baseline →
//! consult_auto_bootstrap → iteration loop` sequence) is integrated-loop
//! deferred.
//!
//! # Event payload semantics (PRD §15.3.21)
//!
//! All `auto.bootstrap.{spawned,skipped,conflict}` payloads carry `agent_id` =
//! the PARENT root agent (the Auto-mode initializer per PRD §12.5.6), with the
//! per-entry child identifier in the separate `alias` field. `spawned` also
//! carries `template`; `skipped` + `conflict` omit `template`; `conflict` adds
//! `conflict_type ∈ {alias_path_mismatch, path_occupied, template_mismatch}`.

use async_trait::async_trait;

use crate::config::MAX_CONFIG_STRING_LEN;
use crate::round_advancer::sanitize_for_audit;

/// Defensive cap on the number of bootstrap entries M015 will translate +
/// emit per `consult_auto_bootstrap` call. Checked on `report.entries.len()`
/// BEFORE emission, on BOTH the Ok-path (→ `ReportTooLarge`) and the
/// Dispatch-with-partial path (→ skip the over-cap partial emission). Mirrors
/// MODULE-005's `MAX_BOOTSTRAP_ENTRIES = 64` (a separate constant — M015 does
/// not import cap-lifecycle). M005's `parse_auto_bootstrap` already enforces
/// this cap upstream, so a report exceeding it can only arrive from a
/// buggy/hostile applier adapter → fail-CLOSED.
pub const MAX_BOOTSTRAP_ENTRIES: usize = 64;

/// Skip reason for an [`M015BootstrapOutcome::Skipped`] entry. Per PRD §12.5.6
/// the only idempotent-skip case is "alias exists, target-path matches,
/// template matches".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SkippedKind {
    /// Alias already exists at the matching target-path with a matching
    /// template version → idempotent skip (PRD §12.5.6 row 2).
    AliasExistsTemplateMatches,
}

/// Conflict reason for an [`M015BootstrapOutcome::Conflict`] entry. Maps 1:1
/// to PRD §15.3.21's `conflict_type` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConflictKind {
    /// Alias exists but its target-path differs from the requested one (PRD
    /// §12.5.6 row 3). `conflict_type: "alias_path_mismatch"`.
    AliasPathMismatch,
    /// Target-path is occupied by a different alias (PRD §12.5.6 row 4).
    /// `conflict_type: "path_occupied"`.
    PathOccupied,
    /// Alias + target-path match but the template version/content differs
    /// (PRD §12.5.6 row 5). `conflict_type: "template_mismatch"`.
    TemplateMismatch,
}

impl ConflictKind {
    /// Stable PRD §15.3.21 `conflict_type` discriminator string.
    pub fn as_conflict_type(&self) -> &'static str {
        match self {
            ConflictKind::AliasPathMismatch => "alias_path_mismatch",
            ConflictKind::PathOccupied => "path_occupied",
            ConflictKind::TemplateMismatch => "template_mismatch",
        }
    }
}

/// Per-entry outcome of an auto-bootstrap decision (M015-local categorization
/// of M005's executor result — see the §3.8 note 9 translation contract).
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum M015BootstrapOutcome {
    /// A new child was spawned (PRD §12.5.6 row 1).
    Spawned,
    /// The child already existed; the bootstrap was an idempotent no-op.
    Skipped { skip_reason: SkippedKind },
    /// A conflict was detected; no spawn occurred.
    Conflict { conflict_type: ConflictKind },
}

/// One bootstrap entry's outcome. Carries only the fields that map to PRD
/// §15.3.21 payload fields (`template`/`alias`/`target_path`) plus the outcome
/// discriminator.
///
/// **No `agent_id` field**: the emitted event's `agent_id` is ALWAYS the
/// PARENT root (set by [`report_to_event_payloads`]'s `parent_agent_id` arg),
/// so a per-entry agent_id would be vestigial.
#[derive(Debug, Clone, PartialEq)]
pub struct M015BootstrapEntry {
    pub template: String,
    pub alias: String,
    pub target_path: String,
    pub outcome: M015BootstrapOutcome,
}

/// M015-local report shape returned by an [`AutoBootstrapApplier`]. NOT a
/// duplicate of M005's `BootstrapReport` — the integrated-loop adapter
/// translates M005's output into this shape per the §3.8 note 9 contract.
#[derive(Debug, Clone, PartialEq)]
pub struct M015BootstrapReport {
    pub entries: Vec<M015BootstrapEntry>,
}

/// One `auto.bootstrap.*` event payload (PRD §15.3.21 verbatim per event
/// kind). Tagged enum so field-presence is enforced at the type level: a
/// `Skipped` event cannot carry a `template`; a `Conflict` event cannot omit
/// `conflict_type`.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum BootstrapEventPayload {
    /// `auto.bootstrap.spawned` — fields `{agent_id, template, alias, target_path}`.
    Spawned {
        /// PARENT root agent_id (the Auto-mode initializer).
        agent_id: String,
        template: String,
        alias: String,
        target_path: String,
    },
    /// `auto.bootstrap.skipped` — fields `{agent_id, alias, target_path}` (no template).
    Skipped {
        agent_id: String,
        alias: String,
        target_path: String,
    },
    /// `auto.bootstrap.conflict` — fields `{agent_id, alias, target_path, conflict_type}`.
    Conflict {
        agent_id: String,
        alias: String,
        target_path: String,
        conflict_type: &'static str,
    },
}

/// Audit record returned (NOT emitted) alongside the payloads when a payload
/// field exceeded [`MAX_CONFIG_STRING_LEN`] and was truncated.
///
/// **Emission is integrated-loop-deferred (slice-D):** `report_to_event_payloads`
/// RETURNS these records, but the slice-D coordination path
/// ([`crate::driver::DefaultAutoLoopDriver::consult_auto_bootstrap`]) does NOT
/// emit `auto.bootstrap.field_truncated` events — M015 has no event channel
/// for them yet. The integrated-loop slice (which wires the M019
/// `EventBusEmit` sink) owns surfacing them. `original_byte_len` is measured
/// AFTER [`sanitize_for_audit`] (the value actually being truncated), so it
/// reflects the post-sanitization byte length.
#[derive(Debug, Clone, PartialEq)]
pub struct TruncationRecord {
    pub payload_index: usize,
    pub field_name: &'static str,
    pub original_byte_len: usize,
    pub truncated_byte_len: usize,
}

/// Char-boundary-safe truncation to at most `max_bytes` UTF-8 bytes. If
/// truncation occurs, a 3-byte `…` ellipsis replaces the trailing slot (same
/// posture as `driver::truncate_at_char_boundary` for
/// `MAX_DECISION_REASON_BYTES`). Returns `(possibly-truncated string,
/// truncated?)`.
fn truncate_field(s: &str, max_bytes: usize) -> (String, bool) {
    if s.len() <= max_bytes {
        return (s.to_string(), false);
    }
    let ellipsis = "…";
    let target = max_bytes.saturating_sub(ellipsis.len());
    let mut end = target;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = String::with_capacity(end + ellipsis.len());
    out.push_str(&s[..end]);
    out.push_str(ellipsis);
    (out, true)
}

/// Sanitize then length-cap one field value, recording a [`TruncationRecord`]
/// into `records` if truncation occurred. Order: [`sanitize_for_audit`]
/// (strip control / C1 / DEL / ANSI-ESC / Trojan-Source bidi-override marks →
/// `_`) FIRST, then char-boundary-safe truncation. Sanitization can only
/// shrink-or-preserve byte length (multi-byte bidi marks → 1-byte `_`), so the
/// recorded `original_byte_len` is the post-sanitization length actually being
/// truncated.
fn sanitize_and_cap(
    raw: &str,
    field_name: &'static str,
    payload_index: usize,
    records: &mut Vec<TruncationRecord>,
) -> String {
    let sanitized = sanitize_for_audit(raw);
    let (capped, truncated) = truncate_field(&sanitized, MAX_CONFIG_STRING_LEN);
    if truncated {
        records.push(TruncationRecord {
            payload_index,
            field_name,
            original_byte_len: sanitized.len(),
            truncated_byte_len: capped.len(),
        });
    }
    capped
}

/// Pure translation: [`M015BootstrapReport`] + the parent root `agent_id` →
/// `(payloads, truncation_records)`.
///
/// Every payload variant carries `agent_id = parent_agent_id` (PRD §12.5.6
/// framing — events describe the parent's Auto-mode-init actions). `Spawned`
/// carries `template`; `Skipped` + `Conflict` omit it per PRD §15.3.21.
///
/// **Security (adversarial slice-D fix):** every field (`agent_id`, `template`,
/// `alias`, `target_path`) is run through [`sanitize_for_audit`] BEFORE the
/// length cap, because these strings flow into `auto.bootstrap.*` events →
/// operator audit logs / EventBus jsonl — the same sink class that
/// `round_advancer::sanitize_for_audit` already protects for `RoundDecision`
/// text. This neutralizes log-line injection, ANSI terminal corruption, and
/// Trojan-Source (CVE-2021-42574) bidi-override spoofing from
/// untrusted/imported template fields. Then each field is capped at
/// [`MAX_CONFIG_STRING_LEN`] bytes with char-boundary-safe truncation.
///
/// `parent_agent_id` is sanitized + capped ONCE (it is identical across all
/// payloads), so a single oversized parent id yields at most one
/// `TruncationRecord`, not one per entry.
pub fn report_to_event_payloads(
    report: &M015BootstrapReport,
    parent_agent_id: &str,
) -> (Vec<BootstrapEventPayload>, Vec<TruncationRecord>) {
    let mut payloads = Vec::with_capacity(report.entries.len());
    let mut records = Vec::new();
    // agent_id is shared across all payloads — sanitize + cap ONCE
    // (adversarial Info #5: avoids N duplicate records + allocations). Its
    // truncation, if any, is recorded against payload_index 0.
    let agent_id = sanitize_and_cap(parent_agent_id, "agent_id", 0, &mut records);
    for (i, entry) in report.entries.iter().enumerate() {
        let alias = sanitize_and_cap(&entry.alias, "alias", i, &mut records);
        let target_path = sanitize_and_cap(&entry.target_path, "target_path", i, &mut records);
        let payload = match &entry.outcome {
            M015BootstrapOutcome::Spawned => {
                let template = sanitize_and_cap(&entry.template, "template", i, &mut records);
                BootstrapEventPayload::Spawned {
                    agent_id: agent_id.clone(),
                    template,
                    alias,
                    target_path,
                }
            }
            M015BootstrapOutcome::Skipped { .. } => BootstrapEventPayload::Skipped {
                agent_id: agent_id.clone(),
                alias,
                target_path,
            },
            M015BootstrapOutcome::Conflict { conflict_type } => BootstrapEventPayload::Conflict {
                agent_id: agent_id.clone(),
                alias,
                target_path,
                conflict_type: conflict_type.as_conflict_type(),
            },
        };
        payloads.push(payload);
    }
    (payloads, records)
}

/// Error returned by an [`AutoBootstrapApplier`]. The integrated-loop adapter
/// maps M005's `BootstrapError` variants into these per the §3.8 note 9
/// contract.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum AutoBootstrapApplierError {
    /// Could not parse the supplied YAML (M005 `ParseError` / `InputTooLarge` /
    /// `YamlAnchorAmplification` / `LimitExceeded` / `InvalidAlias`). Zero
    /// progress — no partial.
    #[error("auto-bootstrap parse error: {0}")]
    Parse(String),
    /// Rejected before any spawn (M005 `ParentNotFound`, or `SubKindRejected`
    /// with no partial progress). Zero progress — no partial.
    #[error("auto-bootstrap validation error: {0}")]
    Validation(String),
    /// Spawn dispatch failed mid-batch (M005 `SpawnFailed` / `ParentVanished` /
    /// `InvalidTargetPath`, or `SubKindRejected` with partial progress).
    /// Carries the entries that LANDED before the failure so
    /// [`crate::driver::DefaultAutoLoopDriver::consult_auto_bootstrap`] can emit
    /// their events (observability) BEFORE surfacing the error.
    #[error("auto-bootstrap dispatch failure: {msg}")]
    Dispatch {
        msg: String,
        partial: M015BootstrapReport,
    },
}

/// Error returned by an [`AutoBootstrapEventSink`].
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum AutoBootstrapSinkError {
    /// Event-bus emit failed (transient — production wiring may retry; M015's
    /// coordination layer does NOT retry).
    #[error("event sink emit failed: {0}")]
    EmitFailed(String),
}

/// Coordination-layer error surfaced by
/// [`crate::driver::DefaultAutoLoopDriver::consult_auto_bootstrap`], wrapped by
/// `AutoLoopError::AutoBootstrap`.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum AutoBootstrapCoordinationError {
    /// A non-empty `auto.bootstrap` config was supplied but the applier and/or
    /// sink was not wired (fail-CLOSED: a wiring bug must not silently swallow
    /// the bootstrap intent).
    #[error("auto-bootstrap not configured (applier_present={applier_present}, sink_present={sink_present})")]
    NotConfigured {
        applier_present: bool,
        sink_present: bool,
    },
    /// The applier returned an error.
    #[error("auto-bootstrap applier failed: {0}")]
    ApplierFailed(AutoBootstrapApplierError),
    /// One or more sink emits failed. Carries `(payload_index, error)` pairs
    /// (in `report.entries` order) so operators see WHICH entries failed.
    #[error("auto-bootstrap sink failures: {0:?}")]
    SinkFailures(Vec<(usize, AutoBootstrapSinkError)>),
    /// The applier returned more entries than [`MAX_BOOTSTRAP_ENTRIES`]
    /// (fail-CLOSED — a report this large can only come from a buggy/hostile
    /// adapter, since M005's parser caps upstream).
    #[error("auto-bootstrap report too large (received={received}, limit={limit})")]
    ReportTooLarge { received: usize, limit: usize },
}

/// Executor surface for auto-bootstrap (M005-side, dependency-inverted). The
/// integrated-loop slice provides an adapter binding to cap-lifecycle's
/// `parse_auto_bootstrap` + `apply_auto_bootstrap` (which is synchronous — the
/// adapter may use `spawn_blocking`).
#[async_trait]
pub trait AutoBootstrapApplier: Send + Sync {
    /// Parse + apply the `auto.bootstrap` config for `parent_agent_id`,
    /// returning a categorized [`M015BootstrapReport`].
    async fn apply(
        &self,
        parent_agent_id: &str,
        raw_yaml: &str,
    ) -> Result<M015BootstrapReport, AutoBootstrapApplierError>;
}

/// Event-emit surface for auto-bootstrap (M019-side, dependency-inverted).
///
/// Declared `async` for call-chain composition (`consult_auto_bootstrap` is
/// already `async`) + forward-compat, NOT because M019's `EventBusEmit::emit`
/// is awaitable — that surface is synchronous fire-and-forget. The production
/// adapter wrapping it is a trivial `async fn emit(...) { self.bus.emit(ev); Ok(()) }`.
#[async_trait]
pub trait AutoBootstrapEventSink: Send + Sync {
    /// Emit one `auto.bootstrap.*` event.
    async fn emit(&self, payload: BootstrapEventPayload) -> Result<(), AutoBootstrapSinkError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conflict_kind_discriminator_strings() {
        assert_eq!(
            ConflictKind::AliasPathMismatch.as_conflict_type(),
            "alias_path_mismatch"
        );
        assert_eq!(
            ConflictKind::PathOccupied.as_conflict_type(),
            "path_occupied"
        );
        assert_eq!(
            ConflictKind::TemplateMismatch.as_conflict_type(),
            "template_mismatch"
        );
    }

    #[test]
    fn truncate_field_passes_through_short() {
        let (out, truncated) = truncate_field("short", MAX_CONFIG_STRING_LEN);
        assert_eq!(out, "short");
        assert!(!truncated);
    }

    #[test]
    fn truncate_field_char_boundary_safe() {
        // 1020 ASCII + 4-byte emoji (bytes 1020-1023) + trailing 'b' (byte 1024)
        // = 1025 bytes. Cap 1024 - 3 (ellipsis) = target 1021, which is mid-emoji
        // → walk back to byte 1020 → 1020 + 3 = 1023 bytes.
        let s = format!("{}{}{}", "a".repeat(1020), "🚀", "b");
        assert_eq!(s.len(), 1025);
        let (out, truncated) = truncate_field(&s, MAX_CONFIG_STRING_LEN);
        assert!(truncated);
        assert_eq!(out.len(), 1023);
        assert!(out.ends_with('…'));
        assert!(out.starts_with(&"a".repeat(1020)));
    }
}

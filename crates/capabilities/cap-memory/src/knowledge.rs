//! `knowledge.jsonl` data models — MODULE-011 §1.3.2 schema.
//!
//! 13-field [`MemoryEntry`] record, tagged [`MemorySource`] variant
//! (`task-turn` / `file-ref` per MODULE-011 §1.4 AC-26 canonical 5-field
//! form), [`MemoryType`] / [`MemoryStatus`] / [`SupersessionReason`] enums,
//! and a [`MemoryEntry::validate_invariants`] check enforcing the §1.3.2
//! status-table biconditionals.

use serde::de::{Error as SerdeError, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;
use std::time::{Duration, SystemTime};
use thiserror::Error;

use advance_shared_types::chrono::DateTime;

/// Memory entry kind. MODULE-011 §1.3.2 `type` field. Wire form is
/// kebab-case (`fact` / `user-preference`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MemoryType {
    Fact,
    UserPreference,
}

/// Status state-machine state. MODULE-011 §1.3.2 `status` field.
/// Five variants; status is bound to `is_active` and `superseded_by` per
/// [`MemoryEntry::validate_invariants`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MemoryStatus {
    Active,
    Contested,
    Orphaned,
    Superseded,
    Forgotten,
}

impl MemoryStatus {
    /// Lowercase string form of the variant, matching the `#[serde(rename_all
    /// = "lowercase")]` representation. Returned as `&'static str` to avoid
    /// per-call `String` allocation (slice F, AC-24): `Components::sync_memory_index`
    /// mirrors `entry.status.as_str()` into `MemoryIndexRow.epistemic_status`.
    ///
    /// The private `wit_impl::memory_status_to_string -> String` is retained
    /// for its `String`-returning callers (Val encoding); a future micro-cleanup
    /// can refactor it to `as_str().to_string()`.
    pub fn as_str(&self) -> &'static str {
        match self {
            MemoryStatus::Active => "active",
            MemoryStatus::Contested => "contested",
            MemoryStatus::Orphaned => "orphaned",
            MemoryStatus::Superseded => "superseded",
            MemoryStatus::Forgotten => "forgotten",
        }
    }
}

/// Reason a memory entry was superseded. PRD §11.1.2 line 3849 lists
/// `contradiction | refinement | merge | null`; the `null` is captured
/// by the `Option<SupersessionReason>` wrapper on [`MemoryEntry::supersession_reason`],
/// leaving three concrete variants here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SupersessionReason {
    Contradiction,
    Refinement,
    Merge,
}

/// Inclusive line range. Indexing convention (0-based vs 1-based) is a
/// consumer-level concern; Slice A treats the values as opaque `u32`
/// witnesses to a specific git blob's content. Mirrors the shape of
/// [`crate::turn_index::LogOffset`] `{start_line, end_line}` from
/// MODULE-011 §1.3.4 — same struct-with-named-fields pattern so the
/// on-disk encoding is consistent across the module.
///
/// **Inverted-range guard**: [`LineRange::validate`] enforces `start <=
/// end` so a tampered fixture with `{"start": 100, "end": 50}` is
/// rejected by [`MemoryEntry::validate_invariants`] (Adversarial Round 2
/// fix).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LineRange {
    pub start: u32,
    pub end: u32,
}

impl LineRange {
    /// Validate that `start <= end`. Called from
    /// [`MemoryEntry::validate_invariants`] (via
    /// [`MemorySource::validate_invariants`]) and exposed as `pub` so
    /// callers that hold a bare `LineRange` (e.g. from a future
    /// query-API slice) can validate without round-tripping through
    /// the full `MemoryEntry`.
    pub fn validate(&self) -> Result<(), MemoryError> {
        if self.start > self.end {
            return Err(MemoryError::InvariantViolation(
                "LineRange.start must be <= end (inverted range rejected)",
            ));
        }
        Ok(())
    }
}

/// Tagged variant for `MemoryEntry.sources`. MODULE-011 §1.4 AC-26
/// canonical form:
///
/// - `task-turn(task_id, turn)` — provenance pointer at conversation turn.
/// - `file-ref(agent_id, vpath, commit_ish, blob_id, line_range?)` —
///   provenance pointer at file content; only this variant participates
///   in L6 staleness detection (handled by a future slice).
///
/// **Schema-lock guarantee**: serde does NOT honor
/// `#[serde(deny_unknown_fields)]` on internally-tagged enums (a known
/// serde limitation; see e.g. serde issue tracker). To make the
/// unknown-field rejection a hard guarantee — important when an
/// attacker may control workspace files or future host-fn-delivered
/// JSON — this type ships a hand-rolled [`Deserialize`] impl that
/// validates the JSON's key set against the exact expected fields for
/// each variant. Any unknown key (e.g. a `vpath` field smuggled inside
/// a `task-turn` record) raises a deserialize error rather than
/// silently passing through.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum MemorySource {
    TaskTurn {
        task_id: String,
        turn: u32,
    },
    FileRef {
        agent_id: String,
        vpath: String,
        commit_ish: String,
        blob_id: String,
        line_range: Option<LineRange>,
    },
}

impl MemorySource {
    /// Validate the nested invariants of this source (currently: only
    /// `FileRef.line_range`'s ordering). Useful when a caller
    /// deserializes a `MemorySource` directly (not through a
    /// `MemoryEntry`) and wants the same range checks
    /// [`MemoryEntry::validate_invariants`] applies. Idempotent.
    pub fn validate_invariants(&self) -> Result<(), MemoryError> {
        if let MemorySource::FileRef {
            line_range: Some(range),
            ..
        } = self
        {
            range.validate()?;
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for MemorySource {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct MemorySourceVisitor;

        impl<'de> Visitor<'de> for MemorySourceVisitor {
            type Value = MemorySource;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a MemorySource map (kind=task-turn or kind=file-ref)")
            }

            fn visit_map<M>(self, mut map: M) -> Result<MemorySource, M::Error>
            where
                M: MapAccess<'de>,
            {
                use serde_json::Value;

                // Cap on key COUNT — caps structural breadth only (not
                // per-value size). The largest legal variant
                // (`file-ref`) is 1 discriminant + 5 fields = 6 keys;
                // 16 leaves headroom while rejecting attacker-crafted
                // JSON with long unknown-key tails. This does NOT cap
                // the size of individual values (a 1GB string value is
                // still allowed past this check); the bounded-input
                // guarantee is the caller's responsibility per the
                // `MemoryEntry` rustdoc — apply an
                // `io::Read::take(MAX_BYTES)` wrapper or pre-check
                // file size before invoking `serde_json::from_*`.
                // (Adversarial Round 2 fix; clarification Round 3.)
                const MAX_KEYS: usize = 16;

                let mut buffered: Vec<(String, Value)> = Vec::new();
                let mut kind_count: u32 = 0;
                while let Some(key) = map.next_key::<String>()? {
                    if key == "kind" {
                        kind_count = kind_count.saturating_add(1);
                        if kind_count > 1 {
                            return Err(M::Error::custom("duplicate field `kind`"));
                        }
                    }
                    if buffered.len() >= MAX_KEYS {
                        return Err(M::Error::custom(format!(
                            "MemorySource exceeds max key count {MAX_KEYS} \
                             (DoS-amplification guard; legal variants have ≤ 6 keys)"
                        )));
                    }
                    let value: Value = map.next_value()?;
                    buffered.push((key, value));
                }

                // After the duplicate-`kind` check above, exactly one
                // `kind` entry is present (or zero — handled below).
                let kind_value = buffered
                    .iter()
                    .find(|(k, _)| k == "kind")
                    .map(|(_, v)| v.clone())
                    .ok_or_else(|| M::Error::missing_field("kind"))?;
                let kind = kind_value
                    .as_str()
                    .ok_or_else(|| M::Error::custom("`kind` must be a string"))?
                    .to_string();

                let mut payload = serde_json::Map::new();
                for (k, v) in buffered {
                    if k == "kind" {
                        continue;
                    }
                    if payload.insert(k.clone(), v).is_some() {
                        return Err(M::Error::custom(format!("duplicate field `{k}`")));
                    }
                }

                match kind.as_str() {
                    "task-turn" => {
                        let allowed: &[&str] = &["task_id", "turn"];
                        for key in payload.keys() {
                            if !allowed.contains(&key.as_str()) {
                                return Err(M::Error::custom(format!(
                                    "unknown field `{key}` for kind=`task-turn`"
                                )));
                            }
                        }
                        let task_id_v = payload
                            .remove("task_id")
                            .ok_or_else(|| M::Error::missing_field("task_id"))?;
                        let task_id: String = serde_json::from_value(task_id_v)
                            .map_err(|e| M::Error::custom(format!("task_id: {e}")))?;
                        let turn_v = payload
                            .remove("turn")
                            .ok_or_else(|| M::Error::missing_field("turn"))?;
                        let turn: u32 = serde_json::from_value(turn_v)
                            .map_err(|e| M::Error::custom(format!("turn: {e}")))?;
                        Ok(MemorySource::TaskTurn { task_id, turn })
                    }
                    "file-ref" => {
                        let allowed: &[&str] =
                            &["agent_id", "vpath", "commit_ish", "blob_id", "line_range"];
                        for key in payload.keys() {
                            if !allowed.contains(&key.as_str()) {
                                return Err(M::Error::custom(format!(
                                    "unknown field `{key}` for kind=`file-ref`"
                                )));
                            }
                        }
                        let agent_id_v = payload
                            .remove("agent_id")
                            .ok_or_else(|| M::Error::missing_field("agent_id"))?;
                        let agent_id: String = serde_json::from_value(agent_id_v)
                            .map_err(|e| M::Error::custom(format!("agent_id: {e}")))?;
                        let vpath_v = payload
                            .remove("vpath")
                            .ok_or_else(|| M::Error::missing_field("vpath"))?;
                        let vpath: String = serde_json::from_value(vpath_v)
                            .map_err(|e| M::Error::custom(format!("vpath: {e}")))?;
                        let commit_ish_v = payload
                            .remove("commit_ish")
                            .ok_or_else(|| M::Error::missing_field("commit_ish"))?;
                        let commit_ish: String = serde_json::from_value(commit_ish_v)
                            .map_err(|e| M::Error::custom(format!("commit_ish: {e}")))?;
                        let blob_id_v = payload
                            .remove("blob_id")
                            .ok_or_else(|| M::Error::missing_field("blob_id"))?;
                        let blob_id: String = serde_json::from_value(blob_id_v)
                            .map_err(|e| M::Error::custom(format!("blob_id: {e}")))?;
                        let line_range_v = payload.remove("line_range").unwrap_or(Value::Null);
                        let line_range: Option<LineRange> = serde_json::from_value(line_range_v)
                            .map_err(|e| M::Error::custom(format!("line_range: {e}")))?;
                        Ok(MemorySource::FileRef {
                            agent_id,
                            vpath,
                            commit_ish,
                            blob_id,
                            line_range,
                        })
                    }
                    other => Err(M::Error::custom(format!(
                        "unknown variant `{other}`, expected `task-turn` or `file-ref`"
                    ))),
                }
            }
        }

        deserializer.deserialize_map(MemorySourceVisitor)
    }
}

/// Single record of `knowledge.jsonl`. 13 fields per MODULE-011 §1.3.2.
///
/// **Schema shape**: `#[serde(deny_unknown_fields)]` locks the top-level
/// key set, and the hand-rolled [`MemorySource`] [`Deserialize`] further
/// locks each variant's inner key set. Unknown JSON keys raise a
/// `serde::de::Error` rather than silently passing through.
///
/// **Invariants are NOT enforced at deserialize time** — Slice A
/// scaffolds the schema only. Consumers reading `MemoryEntry` from
/// untrusted JSON (e.g., a tampered workspace file or a future
/// host-fn-delivered payload) MUST call [`MemoryEntry::validate_invariants`]
/// before relying on the §1.3.2 status-table biconditionals. The type
/// system carries no automatic witness; the value semantics are
/// "raw record + opt-in check". A future slice may introduce a
/// `ValidatedMemoryEntry` newtype that performs the check in its
/// constructor.
///
/// **Bounded-input responsibility**: `Vec<MemorySource>` and `Vec<String>`
/// have no built-in size cap; a tampered JSON document can carry
/// arbitrarily large arrays / strings and cause a DoS-class OOM at
/// deserialize time. Consumers reading from untrusted sources MUST
/// apply an input-size cap **before** deserialization (e.g., wrap the
/// reader with `io::Read::take(MAX_BYTES)`, configure
/// `serde_json::Deserializer::from_reader(..)`'s buffer policy, or
/// validate the on-disk file size first). Slice A does not impose
/// hard bounds because the normative PRD §11.1.2 schema does not
/// specify them; future slices that wire I/O paths SHOULD pin
/// per-field caps consistent with each consumer's threat model.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryEntry {
    pub id: String,
    pub agent_id: String,
    #[serde(rename = "type")]
    pub entry_type: MemoryType,
    pub content: String,
    pub tags: Vec<String>,
    /// ISO-8601 UTC timestamp string (matches MODULE-011 §1.3.2 example
    /// convention; Slice A does not introduce a typed time wrapper).
    pub created_at: String,
    /// Origin task id; `null` per PRD §11.1.2 when the entry has no task
    /// context (e.g., consolidated_preferences seeded outside a task).
    pub task_origin: Option<String>,
    pub is_active: bool,
    pub superseded_by: Option<String>,
    pub status: MemoryStatus,
    pub supersession_reason: Option<SupersessionReason>,
    /// L6 semantic-cluster id; `null` until L6 has clustered the entry.
    pub cluster_id: Option<String>,
    pub sources: Vec<MemorySource>,
}

/// Error type for [`MemoryEntry::validate_invariants`]. Slice A only
/// produces the `InvariantViolation` variant; later slices that wire
/// persistence may extend this enum.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Error)]
pub enum MemoryError {
    #[error("memory invariant violation: {0}")]
    InvariantViolation(&'static str),
}

/// MODULE-011 §1.4 AC-23 (REQ-217): freshness enum **computed at query time, NOT
/// persisted**. PRD §11.1.2 lines 3893-3895 defines three buckets over the
/// computed delta `now - max(created_at, last_accessed)`:
///
/// - `Fresh`: `delta < 7 days` — recently created or accessed
/// - `Aging`: `7 days ≤ delta < 30 days` — medium-term inactive
/// - `Stale`: `delta ≥ 30 days` — long-term inactive
///
/// # Compile-time witness for "not persisted"
///
/// `Freshness` deliberately has NO `Serialize` / `Deserialize` derives. PRD
/// §11.1.2 line 3897 states "freshness 不写入任何 synthesis frontmatter——它是
/// 相对 now 的时间窗口，持久化会过期失真". The compile-time witness is this
/// `compile_fail,E0277` doctest — `serde_json::to_string` requires a
/// `T: Serialize` bound, and the absence of a `Serialize` impl on `Freshness`
/// fails type-checking with E0277 (`the trait bound \`Freshness: Serialize\`
/// is not satisfied`):
///
/// ```compile_fail,E0277
/// use cap_memory::Freshness;
/// let _ = serde_json::to_string(&Freshness::Fresh).unwrap();
/// ```
///
/// The pinned `E0277` rules out passing for unrelated compile errors (e.g.,
/// E0432 unresolved import). The `use cap_memory::Freshness;` line resolves
/// the type before the `to_string` call hits the trait-bound check.
///
/// Defense-in-depth: a value-level negative test in [`MemoryEntry`] serde
/// round-trip also asserts the JSON never contains a `freshness` key (the
/// runtime witness; cf. [`MemoryEntry::compute_freshness`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Freshness {
    Fresh,
    Aging,
    Stale,
}

const SEVEN_DAYS: Duration = Duration::from_secs(7 * 24 * 3600);
const THIRTY_DAYS: Duration = Duration::from_secs(30 * 24 * 3600);

impl MemoryEntry {
    /// MODULE-011 §1.4 AC-23 (REQ-217): compute freshness from `created_at` and an
    /// optional `last_accessed` timestamp against `now`. PRD §11.1.2 lines 3893-3895
    /// formula: `delta = now - max(parsed_created_at, last_accessed)` → bucket.
    ///
    /// Semantics:
    /// - `last_accessed == None` → reference = parsed `created_at`.
    /// - `last_accessed == Some(t) > parsed_created_at` → reference = `t`.
    /// - `last_accessed == Some(t) <= parsed_created_at` → reference = parsed
    ///   `created_at` (a stale access ts cannot make the entry "younger").
    ///
    /// Parse-failure / degraded-input policy:
    /// - Malformed `created_at` (not RFC 3339) → returns `Stale` conservatively.
    ///   No panic. The cap-memory layer prefers under-counting freshness over
    ///   crashing on a tampered or untyped string.
    /// - The slice-B/D `"1970-01-01T00:00:00Z"` epoch stub parses correctly but
    ///   any reasonable `now` produces `delta >> 30d` → naturally `Stale`.
    ///
    /// Clock-skew edge:
    /// - If `now < reference`, the delta is clamped to zero (`Fresh`). This
    ///   matches the natural reading "if access is in the future, treat as just
    ///   accessed" and avoids panic-on-negative-Duration.
    pub fn compute_freshness(
        &self,
        last_accessed: Option<SystemTime>,
        now: SystemTime,
    ) -> Freshness {
        let parsed_created = match DateTime::parse_from_rfc3339(&self.created_at) {
            Ok(dt) => {
                let secs = dt.timestamp();
                if secs >= 0 {
                    // Preserve subsecond precision: a created_at like
                    // "2026-03-23T10:00:00.5Z" must NOT be silently
                    // rounded to the nearest second, otherwise a true
                    // delta of `6d 23h 59m 59.5s` could be misbucketed
                    // at the 7d / 30d boundaries. `Duration::new(secs,
                    // nanos)` uses the full nanosecond resolution
                    // chrono returns via `timestamp_subsec_nanos()`.
                    let nanos = dt.timestamp_subsec_nanos();
                    SystemTime::UNIX_EPOCH + Duration::new(secs as u64, nanos)
                } else {
                    // Pre-epoch timestamps are not modeled by PRD §11.1.2;
                    // fall back to `Stale` conservatively (same posture as
                    // malformed input).
                    return Freshness::Stale;
                }
            }
            Err(_) => return Freshness::Stale,
        };
        let reference = match last_accessed {
            Some(t) if t > parsed_created => t,
            _ => parsed_created,
        };
        let delta = now.duration_since(reference).unwrap_or(Duration::ZERO);
        if delta < SEVEN_DAYS {
            Freshness::Fresh
        } else if delta < THIRTY_DAYS {
            Freshness::Aging
        } else {
            Freshness::Stale
        }
    }

    /// Enforce the MODULE-011 §1.3.2 status-table biconditionals + PRD
    /// §11.1.2 row 4 `superseded_by` linkage.
    ///
    /// 1. `is_active == true  ↔ status ∈ {Active, Contested, Orphaned}`
    /// 2. `is_active == false ↔ status ∈ {Superseded, Forgotten}`
    /// 3. `status == Superseded ↔ superseded_by.is_some()`
    ///
    /// The `supersession_reason` field is **not** invariant-linked to
    /// `status` in Slice A — PRD's status table does not normatively
    /// bind it (only an example-level `null` convention for non-superseded
    /// entries). Future reconciliation slices may add tighter validation.
    pub fn validate_invariants(&self) -> Result<(), MemoryError> {
        use MemoryStatus::*;

        let active_status = matches!(self.status, Active | Contested | Orphaned);
        let inactive_status = matches!(self.status, Superseded | Forgotten);

        if self.is_active && !active_status {
            return Err(MemoryError::InvariantViolation(
                "is_active=true requires status in {Active, Contested, Orphaned}",
            ));
        }
        if !self.is_active && !inactive_status {
            return Err(MemoryError::InvariantViolation(
                "is_active=false requires status in {Superseded, Forgotten}",
            ));
        }

        let is_superseded = matches!(self.status, Superseded);
        if is_superseded && self.superseded_by.is_none() {
            return Err(MemoryError::InvariantViolation(
                "status=Superseded requires superseded_by.is_some()",
            ));
        }
        if !is_superseded && self.superseded_by.is_some() {
            return Err(MemoryError::InvariantViolation(
                "non-superseded entries must have superseded_by=None",
            ));
        }

        // Delegate to each `MemorySource::validate_invariants`
        // (currently: file-ref line_range ordering).
        for source in &self.sources {
            source.validate_invariants()?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_status_as_str_maps_all_5_variants_to_lowercase() {
        // Slice F (AC-24): cross-validates against the
        // `#[serde(rename_all = "lowercase")]` representation. Any future
        // variant addition will fail BOTH this match-style table and the
        // wit_impl::memory_status_to_string sibling (lockstep maintenance —
        // see MODULE-011 §3.8 note 12 (g)).
        assert_eq!(MemoryStatus::Active.as_str(), "active");
        assert_eq!(MemoryStatus::Contested.as_str(), "contested");
        assert_eq!(MemoryStatus::Orphaned.as_str(), "orphaned");
        assert_eq!(MemoryStatus::Superseded.as_str(), "superseded");
        assert_eq!(MemoryStatus::Forgotten.as_str(), "forgotten");
    }

    fn base_active_entry() -> MemoryEntry {
        MemoryEntry {
            id: "mem-042".into(),
            agent_id: "research".into(),
            entry_type: MemoryType::Fact,
            content: "竞品A涨价15%因AI功能".into(),
            tags: vec!["pricing".into(), "competitor-a".into()],
            created_at: "2026-03-23T10:00:00Z".into(),
            task_origin: Some("task-001".into()),
            is_active: true,
            superseded_by: None,
            status: MemoryStatus::Active,
            supersession_reason: None,
            cluster_id: Some("cl-pricing-2026q1".into()),
            sources: vec![
                MemorySource::TaskTurn {
                    task_id: "task-001".into(),
                    turn: 28,
                },
                MemorySource::FileRef {
                    agent_id: "research".into(),
                    vpath: "data/pricing.csv".into(),
                    commit_ish: "abc1234".into(),
                    blob_id: "a1b2c3d4".into(),
                    line_range: None,
                },
            ],
        }
    }

    #[test]
    fn entry_roundtrip_all_fields() {
        let entry = base_active_entry();
        let json = serde_json::to_string(&entry).expect("serialize");
        let parsed: MemoryEntry = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(entry, parsed);
        // Spot-check that all 13 field keys are present in the JSON.
        for key in [
            "id",
            "agent_id",
            "type",
            "content",
            "tags",
            "created_at",
            "task_origin",
            "is_active",
            "superseded_by",
            "status",
            "supersession_reason",
            "cluster_id",
            "sources",
        ] {
            assert!(
                json.contains(&format!("\"{key}\"")),
                "expected JSON to contain field '{key}', got: {json}"
            );
        }
    }

    /// Fixture-based test: uses the AC-26 canonical 5-field form for
    /// `file-ref` that matches MODULE-011 §1.3.2's amended example
    /// (post-DOCS-phase edit in /dev Slice A).
    #[test]
    fn entry_deserialize_from_module_doc_example() {
        let fixture = r#"{
          "id": "mem-042",
          "agent_id": "research",
          "type": "fact",
          "content": "竞品A涨价15%因AI功能",
          "tags": ["pricing", "competitor-a"],
          "created_at": "2026-03-23T10:00:00Z",
          "task_origin": "task-001",
          "is_active": true,
          "superseded_by": null,
          "status": "active",
          "supersession_reason": null,
          "cluster_id": "cl-pricing-2026q1",
          "sources": [
            {"kind": "task-turn", "task_id": "task-001", "turn": 28},
            {"kind": "file-ref", "agent_id": "research", "vpath": "data/pricing.csv", "commit_ish": "abc1234", "blob_id": "a1b2c3d4", "line_range": null}
          ]
        }"#;
        let parsed: MemoryEntry = serde_json::from_str(fixture).expect("parse fixture");
        assert_eq!(parsed.id, "mem-042");
        assert_eq!(parsed.entry_type, MemoryType::Fact);
        assert_eq!(parsed.cluster_id.as_deref(), Some("cl-pricing-2026q1"));
        assert_eq!(parsed.sources.len(), 2);
        match &parsed.sources[1] {
            MemorySource::FileRef {
                agent_id,
                vpath,
                commit_ish,
                blob_id,
                line_range,
            } => {
                assert_eq!(agent_id, "research");
                assert_eq!(vpath, "data/pricing.csv");
                assert_eq!(commit_ish, "abc1234");
                assert_eq!(blob_id, "a1b2c3d4");
                assert_eq!(*line_range, None);
            }
            other => panic!("expected FileRef, got {other:?}"),
        }
    }

    /// Defensive negative assertion: an unknown JSON key (e.g. the
    /// non-persisted `freshness` enum from PRD §11.1.2) fails to
    /// deserialize because `MemoryEntry` is `#[serde(deny_unknown_fields)]`.
    /// AC-23's full verification (which also requires a query-time
    /// `Freshness::compute` function) is out of scope for Slice A.
    #[test]
    fn entry_rejects_unknown_field() {
        let fixture = r#"{
          "id": "mem-042",
          "agent_id": "research",
          "type": "fact",
          "content": "x",
          "tags": [],
          "created_at": "2026-03-23T10:00:00Z",
          "task_origin": null,
          "is_active": true,
          "superseded_by": null,
          "status": "active",
          "supersession_reason": null,
          "cluster_id": null,
          "sources": [],
          "freshness": "stale"
        }"#;
        let result: Result<MemoryEntry, _> = serde_json::from_str(fixture);
        assert!(
            result.is_err(),
            "expected deserialize to fail on unknown field, got {result:?}"
        );
    }

    #[test]
    fn entry_optional_supersession_reason_when_active() {
        let entry = base_active_entry();
        assert!(entry.supersession_reason.is_none());
        assert!(entry.superseded_by.is_none());
        let json = serde_json::to_string(&entry).expect("serialize");
        assert!(json.contains("\"supersession_reason\":null"));
        assert!(json.contains("\"superseded_by\":null"));
    }

    #[test]
    fn status_invariant_active_set() {
        for status in [
            MemoryStatus::Active,
            MemoryStatus::Contested,
            MemoryStatus::Orphaned,
        ] {
            let mut entry = base_active_entry();
            entry.status = status;
            entry.is_active = true;
            entry.superseded_by = None;
            entry
                .validate_invariants()
                .unwrap_or_else(|e| panic!("expected accept for {status:?}: {e}"));
        }
    }

    #[test]
    fn status_invariant_inactive_set() {
        // Superseded — requires superseded_by.
        let mut superseded = base_active_entry();
        superseded.is_active = false;
        superseded.status = MemoryStatus::Superseded;
        superseded.superseded_by = Some("mem-099".into());
        superseded
            .validate_invariants()
            .expect("superseded accepted");

        // Forgotten — no superseded_by.
        let mut forgotten = base_active_entry();
        forgotten.is_active = false;
        forgotten.status = MemoryStatus::Forgotten;
        forgotten.superseded_by = None;
        forgotten.validate_invariants().expect("forgotten accepted");
    }

    #[test]
    fn status_invariant_rejects_active_superseded() {
        let mut entry = base_active_entry();
        entry.is_active = true;
        entry.status = MemoryStatus::Superseded;
        entry.superseded_by = Some("mem-099".into());
        assert!(entry.validate_invariants().is_err());
    }

    #[test]
    fn status_invariant_rejects_inactive_active() {
        let mut entry = base_active_entry();
        entry.is_active = false;
        entry.status = MemoryStatus::Active;
        assert!(entry.validate_invariants().is_err());
    }

    #[test]
    fn status_invariant_rejects_superseded_without_link() {
        let mut entry = base_active_entry();
        entry.is_active = false;
        entry.status = MemoryStatus::Superseded;
        entry.superseded_by = None;
        let err = entry.validate_invariants().expect_err("rejected");
        assert!(matches!(err, MemoryError::InvariantViolation(msg) if msg.contains("Superseded")));
    }

    #[test]
    fn status_invariant_rejects_non_superseded_with_link() {
        let mut entry = base_active_entry();
        entry.is_active = true;
        entry.status = MemoryStatus::Active;
        entry.superseded_by = Some("mem-099".into());
        assert!(entry.validate_invariants().is_err());
    }

    #[test]
    fn sources_variant_task_turn_roundtrip() {
        let src = MemorySource::TaskTurn {
            task_id: "task-001".into(),
            turn: 28,
        };
        let json = serde_json::to_string(&src).expect("serialize");
        assert!(json.contains("\"kind\":\"task-turn\""));
        assert!(json.contains("\"task_id\":\"task-001\""));
        let parsed: MemorySource = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(src, parsed);
    }

    #[test]
    fn sources_variant_file_ref_roundtrip() {
        let src = MemorySource::FileRef {
            agent_id: "research".into(),
            vpath: "data/pricing.csv".into(),
            commit_ish: "abc1234".into(),
            blob_id: "a1b2c3d4".into(),
            line_range: Some(LineRange { start: 10, end: 20 }),
        };
        let json = serde_json::to_string(&src).expect("serialize");
        assert!(json.contains("\"kind\":\"file-ref\""));
        assert!(json.contains("\"line_range\":{\"start\":10,\"end\":20}"));
        let parsed: MemorySource = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(src, parsed);
    }

    #[test]
    fn sources_variant_file_ref_optional_line_range_null() {
        let src = MemorySource::FileRef {
            agent_id: "research".into(),
            vpath: "data/pricing.csv".into(),
            commit_ish: "abc1234".into(),
            blob_id: "a1b2c3d4".into(),
            line_range: None,
        };
        let json = serde_json::to_string(&src).expect("serialize");
        assert!(json.contains("\"line_range\":null"));
        let parsed: MemorySource = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(src, parsed);
    }

    /// Regression test for the adversarial Round-1 finding: `serde(tag =
    /// "kind")` internally-tagged enums do NOT honor
    /// `deny_unknown_fields`. The hand-rolled `Deserialize` impl on
    /// [`MemorySource`] enforces strict key sets per variant.
    #[test]
    fn sources_variant_rejects_unknown_field_on_task_turn() {
        let fixture = r#"{"kind":"task-turn","task_id":"task-001","turn":28,"smuggled":"x"}"#;
        let result: Result<MemorySource, _> = serde_json::from_str(fixture);
        assert!(result.is_err(), "unknown field on task-turn must reject");
    }

    #[test]
    fn sources_variant_rejects_smuggled_file_ref_field_on_task_turn() {
        // An attacker smuggles a file-ref field into a task-turn record.
        let fixture =
            r#"{"kind":"task-turn","task_id":"task-001","turn":28,"vpath":"smuggled.csv"}"#;
        let result: Result<MemorySource, _> = serde_json::from_str(fixture);
        assert!(
            result.is_err(),
            "cross-variant field smuggling must reject; got {result:?}"
        );
    }

    #[test]
    fn sources_variant_rejects_unknown_field_on_file_ref() {
        let fixture = r#"{
            "kind": "file-ref",
            "agent_id": "research",
            "vpath": "data/pricing.csv",
            "commit_ish": "abc1234",
            "blob_id": "a1b2c3d4",
            "line_range": null,
            "extra_attacker_field": "x"
        }"#;
        let result: Result<MemorySource, _> = serde_json::from_str(fixture);
        assert!(result.is_err(), "unknown field on file-ref must reject");
    }

    #[test]
    fn sources_variant_rejects_unknown_kind() {
        let fixture = r#"{"kind":"completely-fake-kind","task_id":"x","turn":1}"#;
        let result: Result<MemorySource, _> = serde_json::from_str(fixture);
        assert!(result.is_err(), "unknown kind must reject");
    }

    /// Adversarial Round 2 fix: duplicate `kind` keys are rejected
    /// rather than silently picking the first.
    #[test]
    fn sources_variant_rejects_duplicate_kind() {
        let fixture = r#"{"kind":"task-turn","task_id":"x","turn":1,"kind":"file-ref"}"#;
        let result: Result<MemorySource, _> = serde_json::from_str(fixture);
        assert!(
            result.is_err(),
            "duplicate `kind` must reject (round-2 smuggling fix); got {result:?}"
        );
    }

    /// Adversarial Round 2 fix: the visitor caps the buffered key count
    /// at 16 BEFORE materializing nested Values. A craft with 100+
    /// unknown keys is rejected without amplifying memory.
    #[test]
    fn sources_variant_rejects_excessive_key_count() {
        let mut json = String::from(r#"{"kind":"task-turn","task_id":"x","turn":1"#);
        for i in 0..50 {
            json.push_str(&format!(",\"unknown_{i}\":\"x\""));
        }
        json.push('}');
        let result: Result<MemorySource, _> = serde_json::from_str(&json);
        assert!(
            result.is_err(),
            "excessive key count must reject (DoS amplification guard)"
        );
    }

    /// Adversarial Round 2 fix: `LineRange.validate` rejects inverted
    /// ranges, and `MemoryEntry::validate_invariants` runs that check
    /// for every nested `file-ref` source.
    #[test]
    fn line_range_validate_rejects_inverted() {
        let bad = LineRange {
            start: 100,
            end: 50,
        };
        assert!(bad.validate().is_err());
        let ok = LineRange {
            start: 50,
            end: 100,
        };
        assert!(ok.validate().is_ok());
        let eq = LineRange { start: 7, end: 7 };
        assert!(eq.validate().is_ok());
    }

    #[test]
    fn validate_invariants_rejects_inverted_line_range() {
        let mut entry = base_active_entry();
        entry.sources = vec![MemorySource::FileRef {
            agent_id: "research".into(),
            vpath: "data/pricing.csv".into(),
            commit_ish: "abc1234".into(),
            blob_id: "a1b2c3d4".into(),
            line_range: Some(LineRange {
                start: 200,
                end: 50,
            }),
        }];
        assert!(entry.validate_invariants().is_err());
    }

    /// Adversarial Round 3 fix: a caller deserializing a bare
    /// `MemorySource` (not via `MemoryEntry`) can validate ranges
    /// directly via [`MemorySource::validate_invariants`].
    #[test]
    fn memory_source_validate_invariants_rejects_inverted_line_range() {
        let src = MemorySource::FileRef {
            agent_id: "research".into(),
            vpath: "data/pricing.csv".into(),
            commit_ish: "abc1234".into(),
            blob_id: "a1b2c3d4".into(),
            line_range: Some(LineRange { start: 99, end: 7 }),
        };
        assert!(src.validate_invariants().is_err());
    }

    #[test]
    fn memory_source_validate_invariants_accepts_task_turn_and_no_range() {
        let task_src = MemorySource::TaskTurn {
            task_id: "task-001".into(),
            turn: 28,
        };
        assert!(task_src.validate_invariants().is_ok());
        let file_no_range = MemorySource::FileRef {
            agent_id: "research".into(),
            vpath: "data/pricing.csv".into(),
            commit_ish: "abc1234".into(),
            blob_id: "a1b2c3d4".into(),
            line_range: None,
        };
        assert!(file_no_range.validate_invariants().is_ok());
    }

    /// Adversarial Round 3 fix: boundary tests for the `MAX_KEYS = 16`
    /// cap — exactly 16 keys (incl. `kind`) on a `task-turn` rejects
    /// at the unknown-key check (because legal `task-turn` has 3 keys
    /// total), while exactly 17 keys hits the MAX_KEYS guard first.
    /// Combined: both rejection paths fire.
    #[test]
    fn sources_variant_max_keys_boundary() {
        // 17 keys (including kind) — exceeds MAX_KEYS = 16.
        let mut json = String::from(r#"{"kind":"task-turn","task_id":"x","turn":1"#);
        for i in 0..14 {
            json.push_str(&format!(",\"k{i}\":\"v\""));
        }
        json.push('}');
        let result: Result<MemorySource, _> = serde_json::from_str(&json);
        assert!(result.is_err(), "17-key fixture must reject");

        // Exactly 16 keys — still rejects (unknown-field check fires
        // because legal `task-turn` has only 3 keys).
        let mut json16 = String::from(r#"{"kind":"task-turn","task_id":"x","turn":1"#);
        for i in 0..13 {
            json16.push_str(&format!(",\"k{i}\":\"v\""));
        }
        json16.push('}');
        let result16: Result<MemorySource, _> = serde_json::from_str(&json16);
        assert!(result16.is_err(), "16-key task-turn fixture must reject");
    }

    #[test]
    fn sources_user_preference_empty_vec_ok() {
        let mut entry = base_active_entry();
        entry.entry_type = MemoryType::UserPreference;
        entry.sources = vec![];
        let json = serde_json::to_string(&entry).expect("serialize");
        assert!(json.contains("\"sources\":[]"));
        let parsed: MemoryEntry = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(entry, parsed);
    }

    #[test]
    fn type_enum_roundtrip() {
        let fact = serde_json::to_string(&MemoryType::Fact).unwrap();
        assert_eq!(fact, "\"fact\"");
        let user_pref = serde_json::to_string(&MemoryType::UserPreference).unwrap();
        assert_eq!(user_pref, "\"user-preference\"");
        let parsed_fact: MemoryType = serde_json::from_str("\"fact\"").unwrap();
        assert_eq!(parsed_fact, MemoryType::Fact);
        let parsed_pref: MemoryType = serde_json::from_str("\"user-preference\"").unwrap();
        assert_eq!(parsed_pref, MemoryType::UserPreference);
    }

    #[test]
    fn status_enum_roundtrip() {
        for (variant, wire) in [
            (MemoryStatus::Active, "\"active\""),
            (MemoryStatus::Contested, "\"contested\""),
            (MemoryStatus::Orphaned, "\"orphaned\""),
            (MemoryStatus::Superseded, "\"superseded\""),
            (MemoryStatus::Forgotten, "\"forgotten\""),
        ] {
            let json = serde_json::to_string(&variant).unwrap();
            assert_eq!(json, wire);
            let parsed: MemoryStatus = serde_json::from_str(wire).unwrap();
            assert_eq!(variant, parsed);
        }
    }

    #[test]
    fn supersession_reason_enum_roundtrip() {
        for (variant, wire) in [
            (SupersessionReason::Contradiction, "\"contradiction\""),
            (SupersessionReason::Refinement, "\"refinement\""),
            (SupersessionReason::Merge, "\"merge\""),
        ] {
            let json = serde_json::to_string(&variant).unwrap();
            assert_eq!(json, wire);
            let parsed: SupersessionReason = serde_json::from_str(wire).unwrap();
            assert_eq!(variant, parsed);
        }
    }

    // ─────────────────────────── AC-23 (REQ-217) ───────────────────────────
    //
    // `Freshness` enum + `MemoryEntry::compute_freshness` per PRD §11.1.2
    // lines 3893-3895 (`< 7d → Fresh`; `7d ≤ delta < 30d → Aging`;
    // `delta ≥ 30d → Stale`). All tests below use synthetic SystemTime
    // arithmetic; no clock dependency.

    fn entry_with_created_at(created_at: &str) -> MemoryEntry {
        MemoryEntry {
            id: "mem-freshness-test".into(),
            agent_id: "research".into(),
            entry_type: MemoryType::Fact,
            content: "test".into(),
            tags: vec![],
            created_at: created_at.into(),
            task_origin: None,
            is_active: true,
            superseded_by: None,
            status: MemoryStatus::Active,
            supersession_reason: None,
            cluster_id: None,
            sources: vec![],
        }
    }

    /// Synthetic SystemTime at a positive offset from UNIX_EPOCH. Avoids
    /// `SystemTime::now()` so tests are deterministic.
    fn epoch_plus(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
    }

    #[test]
    fn freshness_variant_count_is_three() {
        // Exhaustive match — if a variant is added or removed without
        // updating §1.4 AC-23 / PRD §11.1.2, this `match` ceases to compile
        // (compile-time guard against silent enum drift).
        let variants = [Freshness::Fresh, Freshness::Aging, Freshness::Stale];
        for v in variants {
            match v {
                Freshness::Fresh | Freshness::Aging | Freshness::Stale => {}
            }
        }
        assert_eq!(variants.len(), 3);
    }

    #[test]
    fn freshness_boundary_fresh_just_below_7d() {
        // created_at = epoch; now = epoch + (7d - 1s) → Fresh.
        let entry = entry_with_created_at("1970-01-01T00:00:00Z");
        let now = epoch_plus(7 * 24 * 3600 - 1);
        assert_eq!(entry.compute_freshness(None, now), Freshness::Fresh);
    }

    #[test]
    fn freshness_boundary_aging_at_exactly_7d() {
        // PRD: `7d <= delta < 30d → Aging`. The 7d lower-bound is INCLUSIVE.
        let entry = entry_with_created_at("1970-01-01T00:00:00Z");
        let now = epoch_plus(7 * 24 * 3600);
        assert_eq!(entry.compute_freshness(None, now), Freshness::Aging);
    }

    #[test]
    fn freshness_boundary_aging_just_below_30d() {
        let entry = entry_with_created_at("1970-01-01T00:00:00Z");
        let now = epoch_plus(30 * 24 * 3600 - 1);
        assert_eq!(entry.compute_freshness(None, now), Freshness::Aging);
    }

    #[test]
    fn freshness_boundary_stale_at_exactly_30d() {
        // PRD: `delta >= 30d → Stale`. The 30d threshold is INCLUSIVE.
        let entry = entry_with_created_at("1970-01-01T00:00:00Z");
        let now = epoch_plus(30 * 24 * 3600);
        assert_eq!(entry.compute_freshness(None, now), Freshness::Stale);
    }

    #[test]
    fn freshness_last_accessed_some_supersedes_created_at() {
        // created_at = epoch (very old); last_accessed = now-1s → Fresh.
        let entry = entry_with_created_at("1970-01-01T00:00:00Z");
        let now = epoch_plus(100 * 24 * 3600); // 100 days after epoch
        let last_accessed = now - Duration::from_secs(1); // 1s before now
        assert_eq!(
            entry.compute_freshness(Some(last_accessed), now),
            Freshness::Fresh
        );
    }

    #[test]
    fn freshness_last_accessed_none_falls_back_to_created_at_only() {
        // Same fixture as above, but last_accessed=None → falls back to
        // created_at (epoch) → delta = 100d → Stale.
        let entry = entry_with_created_at("1970-01-01T00:00:00Z");
        let now = epoch_plus(100 * 24 * 3600);
        assert_eq!(entry.compute_freshness(None, now), Freshness::Stale);
    }

    #[test]
    fn freshness_last_accessed_older_than_created_keeps_created_reference() {
        // Stale `last_accessed` cannot make an entry "younger" — reference
        // takes `max(parsed_created, last_accessed)`. created_at = 30d after
        // epoch (≈ 2,592,000s); last_accessed = epoch (very stale). now =
        // 30d + 5d → delta = 5d (against created_at) → Fresh.
        let entry = entry_with_created_at("1970-01-31T00:00:00Z"); // 30d after epoch
        let now = epoch_plus(35 * 24 * 3600);
        let stale_access = epoch_plus(0); // very stale
        assert_eq!(
            entry.compute_freshness(Some(stale_access), now),
            Freshness::Fresh
        );
    }

    #[test]
    fn freshness_epoch_stub_falls_through_to_stale() {
        // Slice-B/D `"1970-01-01T00:00:00Z"` epoch stub (per §3.6 "real
        // wall-clock timestamps" row) parses correctly but any reasonable
        // `now` produces `delta >> 30d` → Stale. Explicit no-panic test.
        let entry = entry_with_created_at("1970-01-01T00:00:00Z");
        let now = epoch_plus(30 * 24 * 3600 + 1);
        assert_eq!(entry.compute_freshness(None, now), Freshness::Stale);
    }

    #[test]
    fn freshness_malformed_created_at_falls_back_to_stale_without_panic() {
        // Conservative parse-failure policy: any string not RFC 3339 →
        // returns Stale. Must NOT panic.
        for bad in &["not-a-date", "", "2026/03/23 10:00:00", "X"] {
            let entry = entry_with_created_at(bad);
            let now = epoch_plus(10);
            assert_eq!(entry.compute_freshness(None, now), Freshness::Stale);
        }
    }

    #[test]
    fn freshness_clock_skew_now_before_reference_clamps_to_fresh() {
        // If `now < reference` (clock skew), Duration::ZERO falls through
        // to Fresh. No panic on negative Duration.
        let entry = entry_with_created_at("2026-03-23T10:00:00Z");
        // now = 1 day BEFORE created_at parsed timestamp
        let parsed_created_secs = DateTime::parse_from_rfc3339("2026-03-23T10:00:00Z")
            .unwrap()
            .timestamp() as u64;
        let now = epoch_plus(parsed_created_secs - 86_400);
        assert_eq!(entry.compute_freshness(None, now), Freshness::Fresh);
    }

    #[test]
    fn freshness_subsecond_precision_preserved_at_7d_boundary() {
        // Audit-round-2 W (Doc evaluators): the regression test fixture
        // must DISCRIMINATE the precision-fixed code path from the
        // pre-fix path that dropped subseconds. Fixture chosen so the
        // two paths produce DIFFERENT verdicts:
        //
        //   created_at = "1970-01-01T00:00:00.500Z"  →  parsed = epoch + 0.5s
        //   now        = epoch + 7d EXACTLY
        //
        //   Correct (subsec-preserving):
        //     delta = 7d - 0.5s = 604_799.5s  <  SEVEN_DAYS (604_800s)
        //     → Fresh
        //   Buggy (subsec-dropped, parsed = epoch + 0s):
        //     delta = 7d EXACTLY = 604_800s  >=  SEVEN_DAYS
        //     → Aging (PRD §11.1.2 7d boundary is INCLUSIVE on the Aging
        //       side, asserted by `freshness_boundary_aging_at_exactly_7d`).
        //
        // The assertion `Fresh` passes under the fixed code and would
        // FAIL under the pre-fix code (which would produce Aging). This
        // is the discriminative regression witness for round-1 W1.
        let entry = entry_with_created_at("1970-01-01T00:00:00.500Z");
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(7 * 24 * 3600);
        assert_eq!(entry.compute_freshness(None, now), Freshness::Fresh);
    }

    #[test]
    fn freshness_subsecond_precision_preserved_at_30d_boundary() {
        // Audit-round-2 Info (Codex Diff): defense-in-depth twin for the
        // 30d boundary. Same discriminative shape as the 7d test:
        //
        //   created_at = "1970-01-01T00:00:00.500Z"  →  parsed = epoch + 0.5s
        //   now        = epoch + 30d EXACTLY
        //
        //   Correct (subsec-preserving):
        //     delta = 30d - 0.5s  <  THIRTY_DAYS
        //     → Aging
        //   Buggy (subsec-dropped):
        //     delta = 30d EXACTLY  >=  THIRTY_DAYS
        //     → Stale (PRD §11.1.2 30d boundary is INCLUSIVE on the Stale
        //       side, asserted by `freshness_boundary_stale_at_exactly_30d`).
        let entry = entry_with_created_at("1970-01-01T00:00:00.500Z");
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(30 * 24 * 3600);
        assert_eq!(entry.compute_freshness(None, now), Freshness::Aging);
    }

    #[test]
    fn freshness_never_persisted_in_memoryentry_json() {
        // Value-level defense in depth (complements the compile_fail,E0277
        // doctest on `Freshness` itself). A `MemoryEntry` serialized to
        // JSON must NOT contain a `freshness` key — `Freshness` is computed
        // at query time only, never carried by the entry.
        let entry = base_active_entry();
        let json = serde_json::to_string(&entry).expect("serialize");
        assert!(
            !json.contains("\"freshness\""),
            "MemoryEntry JSON must not contain `freshness` key, got: {json}"
        );
    }
}

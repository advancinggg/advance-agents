//! Integration tests for slice H (m011-slice-h): AC-05 cap-memory-half closure.
//!
//! MODULE-011-AC-05 §1.4 verification class is "integration test". T05-B and
//! T05-C are the PRIMARY integration tests exercising the schemas of the 2
//! cap-memory-owned files via the public `cap_memory::Summary` + `cap_memory::TurnIndex`
//! API. T05-A and T05-D are supporting unit-class mirrors of the inline
//! `src/task_storage.rs::tests` (slice-G T18-A inline+integration mirror precedent).
//!
//! AC-05 partition (cap-memory-half / cross-module-half):
//!
//! - **cap-memory-half** (THIS SLICE): `pub const TASK_STORAGE_FILES: &[&str; 4]`
//!   SPEC contract declaring the AC-05 §1.4 line 360 4-file layout verbatim,
//!   plus per-file consts + subset arrays + dir template; schema-level coverage
//!   of the 2 cap-memory-owned files (`summary.yaml` via `Summary` / `turn-index.yaml`
//!   via `TurnIndex`) — both fully YAML-roundtrippable per slice A + this slice's
//!   T05-B / T05-C public-API mirrors.
//! - **cross-module-half** (DEFERRED, see §3.6 row "AC-05 cross-module half:
//!   on-disk persistence of the 4-file task storage layout"):
//!   - `llm-turns.jsonl` is owned by MODULE-001 runtime (PRD §11.2 append-only
//!     audit log); cap-memory only references it via `TurnEntry.log_offset`.
//!   - `decomposition.yaml` is OPTIONAL per AC-05 wording; owner TBD (likely
//!     MODULE-008 run-manager or a future task-decomposition module).
//!   - On-disk writes of `summary.yaml` + `turn-index.yaml` are deferred to the
//!     future MODULE-002 fs wiring slice — same posture as the existing §3.6
//!     "L6 on-disk persistence" row.

use cap_memory::{
    Confidence, Correction, CorrectionDrift, Epoch, Finding, Importance, KeyDecision, LogOffset,
    PreferenceSignal, ReadFileVersion, RecurringPattern, Summary, SummaryMeta, TurnEntry,
    TurnIndex, TurnIndexMeta, TASK_DECOMPOSITION_FILENAME, TASK_LLM_TURNS_FILENAME,
    TASK_STORAGE_DIR_TEMPLATE, TASK_STORAGE_FILES, TASK_STORAGE_OPTIONAL_FILES,
    TASK_STORAGE_REQUIRED_FILES, TASK_SUMMARY_FILENAME, TASK_TURN_INDEX_FILENAME,
};

// ─────────────────────────────────────────────────────────────────────────
// T05-A — TASK_STORAGE_FILES const re-export mirror (Unit-class)
// ─────────────────────────────────────────────────────────────────────────

/// AC-05 SPEC contract guard at the publicly re-exported path. Coexists with
/// the inline `src/task_storage.rs::tests::task_storage_files_const_matches_ac05_wording`
/// which exercises the const in its declaring module — this test additionally
/// verifies the `pub use` re-export shape from `lib.rs`.
#[test]
fn t05_a_task_storage_files_const_re_exported() {
    assert_eq!(
        TASK_STORAGE_FILES,
        &[
            "summary.yaml",
            "llm-turns.jsonl",
            "turn-index.yaml",
            "decomposition.yaml"
        ],
        "TASK_STORAGE_FILES must match AC-05 §1.4 line 360 wording verbatim with ordering"
    );
    // Per-file consts also reachable through the re-export.
    assert_eq!(TASK_SUMMARY_FILENAME, "summary.yaml");
    assert_eq!(TASK_LLM_TURNS_FILENAME, "llm-turns.jsonl");
    assert_eq!(TASK_TURN_INDEX_FILENAME, "turn-index.yaml");
    assert_eq!(TASK_DECOMPOSITION_FILENAME, "decomposition.yaml");
    // Dir template too.
    assert_eq!(TASK_STORAGE_DIR_TEMPLATE, ".agent/memory/tasks/{task_id}/");
}

// ─────────────────────────────────────────────────────────────────────────
// T05-B — Summary serde-YAML roundtrip via public API (Integration-class)
// ─────────────────────────────────────────────────────────────────────────

/// AC-05's "summary.yaml" file is materialized by `cap_memory::Summary`'s YAML
/// serialization. This test cross-references the inline
/// `src/summary.rs::tests::summary_roundtrip_full_schema` but exercises the
/// PUBLIC API surface from a cross-crate test (slice-G T18-A pattern):
/// construct via the public `Summary` + `SummaryMeta` + sub-types, serialize
/// via `serde_yml::to_string`, assert YAML body contains canonical field names,
/// deserialize, assert round-trip equality.
#[test]
fn t05_b_summary_serde_yaml_roundtrip_via_public_api() {
    let summary = Summary {
        meta: SummaryMeta {
            task_id: "task-slice-h".into(),
            agent_id: "research".into(),
            title: "Slice H AC-05 closure".into(),
            status: "active".into(),
            profile: "research".into(),
            turns_total: 7,
            last_updated: "2026-05-25T00:00:00Z".into(),
            last_turn_at: "2026-05-25T00:00:00Z".into(),
            last_brief_update: 5,
            last_decisions_update: 3,
            last_state_update: 1,
        },
        brief: "AC-05 SPEC contract via TASK_STORAGE_FILES".into(),
        key_decisions: vec![KeyDecision {
            turn: 2,
            content: "Adopt slice-G partition pattern (SPEC-contract const + cap-memory-half)"
                .into(),
        }],
        findings: vec![Finding {
            content: "All 4 R2 structural checks passed inline".into(),
            confidence: Confidence::High,
            turn: 4,
        }],
        open_questions: vec!["decomposition.yaml owner (MODULE-008 or new task-decomp?)".into()],
        current_state: "DOCS+IMPLEMENT in progress, AUDIT next".into(),
        errors_and_corrections: vec![Correction {
            turn: 1,
            content: "R1 FileRef guard rejected due to L6 synthesis 5-gate incompatibility".into(),
        }],
        workflow: "PLAN → DOCS → IMPLEMENT → AUDIT → TEST → SUMMARY".into(),
    };

    let yaml = serde_yml::to_string(&summary).expect("serialize summary");

    // Canonical §1.3.3 field-name presence — AC-05's "summary.yaml" must
    // carry these as wire field names.
    assert!(
        yaml.contains("_meta:"),
        "summary.yaml must have _meta block"
    );
    assert!(
        yaml.contains("brief:"),
        "summary.yaml must have brief field"
    );
    assert!(
        yaml.contains("key_decisions:"),
        "summary.yaml must have key_decisions field"
    );
    assert!(
        yaml.contains("findings:"),
        "summary.yaml must have findings field"
    );
    assert!(
        yaml.contains("open_questions:"),
        "summary.yaml must have open_questions field"
    );
    assert!(
        yaml.contains("current_state:"),
        "summary.yaml must have current_state field"
    );
    assert!(
        yaml.contains("errors_and_corrections:"),
        "summary.yaml must have errors_and_corrections field"
    );
    assert!(
        yaml.contains("workflow:"),
        "summary.yaml must have workflow field"
    );
    // _meta cursors for AC-28 cadence gating (slice E) must also round-trip.
    assert!(yaml.contains("last_brief_update:"));
    assert!(yaml.contains("last_decisions_update:"));
    assert!(yaml.contains("last_state_update:"));

    // Round-trip equality.
    let parsed: Summary = serde_yml::from_str(&yaml).expect("deserialize summary");
    assert_eq!(
        summary, parsed,
        "Summary YAML round-trip must preserve equality"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// T05-C — TurnIndex serde-YAML roundtrip via public API (Integration-class)
// ─────────────────────────────────────────────────────────────────────────

/// AC-05's "turn-index.yaml" file is materialized by `cap_memory::TurnIndex`'s
/// YAML serialization. This test mirrors the inline
/// `src/turn_index.rs::tests::turn_index_roundtrip_l0_l2_l3` via the PUBLIC
/// API.
#[test]
fn t05_c_turn_index_serde_yaml_roundtrip_via_public_api() {
    let index = TurnIndex {
        meta: TurnIndexMeta {
            last_epoch_turn: 20,
            last_epoch_at: "2026-05-24T22:00:00Z".into(),
        },
        turns: vec![TurnEntry {
            turn: 27,
            timestamp: "2026-05-25T01:00:00Z".into(),
            agent_id: "research".into(),
            task_id: "task-slice-h".into(),
            log_offset: LogOffset {
                start_line: 540,
                end_line: 620,
            },
            has_user_instruction: true,
            has_user_correction: false,
            has_tool_use: true,
            has_decision: true,
            importance: Importance::Notable,
            digest: "AC-05 SPEC contract declared".into(),
            collapsed_view: "[user] approve plan → [agent] write task_storage.rs".into(),
            git_commit: "abc1234".into(),
            git_diff_summary: "+1 src/task_storage.rs".into(),
            git_checkpoints: vec!["checkpoint-pre-implement".into()],
            reference_count: 1,
            content_identifiers: vec!["src/task_storage.rs".into()],
            read_file_versions: vec![ReadFileVersion {
                path: "docs/modules/MODULE-011-memory-system.md".into(),
                blob_id: "a1b2c3d4".into(),
            }],
            tokens_digest: 18,
            tokens_collapse_excerpt: 64,
            tokens_l0_processed: 1500,
        }],
        epochs: vec![Epoch {
            id: "epoch-slice-h-01".into(),
            turns: (1, 20),
            generated_at: "2026-05-24T22:00:00Z".into(),
            summary: "Established slice-G partition precedent for SPEC contracts".into(),
            key_turns: vec![3, 7, 14, 20],
            tokens: 95,
            recurring_patterns: vec![RecurringPattern {
                pattern: "plan → eval → revise → eval-pass".into(),
                occurrences: vec![1, 8, 15],
            }],
            preference_signals: vec![PreferenceSignal {
                signal: "prefer Iron-Rule-compliant waived_scope over free-form Out-of-Scope prose"
                    .into(),
                related_turns: vec![5, 12],
                confidence: 0.9,
            }],
            correction_drift: vec![CorrectionDrift {
                from: "FileRef guard at MemoryStore::insert".into(),
                to: "AC-02 in waived_scope; AC-05 only".into(),
                drift_turns: vec![10],
            }],
        }],
    };

    let yaml = serde_yml::to_string(&index).expect("serialize turn_index");

    // Canonical §1.3.4 field-name presence — AC-05's "turn-index.yaml" must
    // carry L0 collapsed_view + L2 digest + L3 epochs as wire field names.
    assert!(
        yaml.contains("_meta:"),
        "turn-index.yaml must have _meta block"
    );
    assert!(
        yaml.contains("turns:"),
        "turn-index.yaml must have turns field"
    );
    assert!(
        yaml.contains("epochs:"),
        "turn-index.yaml must have epochs field"
    );
    assert!(
        yaml.contains("collapsed_view:"),
        "L0 collapsed_view must round-trip"
    );
    assert!(yaml.contains("digest:"), "L2 digest must round-trip");
    assert!(
        yaml.contains("recurring_patterns:"),
        "L3 recurring_patterns must round-trip"
    );
    assert!(
        yaml.contains("preference_signals:"),
        "L3 preference_signals must round-trip"
    );
    assert!(
        yaml.contains("correction_drift:"),
        "L3 correction_drift must round-trip"
    );

    let parsed: TurnIndex = serde_yml::from_str(&yaml).expect("deserialize turn_index");
    assert_eq!(
        index, parsed,
        "TurnIndex YAML round-trip must preserve equality"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// T05-D — Subset relations on the re-exported consts (Unit-class)
// ─────────────────────────────────────────────────────────────────────────

/// Mirrors the inline `src/task_storage.rs::tests::subset_arithmetic_holds`
/// via the publicly re-exported consts, plus the per-file-const ↔
/// TASK_STORAGE_FILES ordering verification (which slice-G's T18-A precedent
/// also pinned at the cross-crate test surface).
#[test]
fn t05_d_subset_relations_via_public_api() {
    // Sizes: 3 required + 1 optional = 4 total.
    assert_eq!(TASK_STORAGE_REQUIRED_FILES.len(), 3);
    assert_eq!(TASK_STORAGE_OPTIONAL_FILES.len(), 1);
    assert_eq!(TASK_STORAGE_FILES.len(), 4);
    assert_eq!(
        TASK_STORAGE_REQUIRED_FILES.len() + TASK_STORAGE_OPTIONAL_FILES.len(),
        TASK_STORAGE_FILES.len(),
        "required + optional must equal full"
    );

    // required ⊆ full
    for &f in TASK_STORAGE_REQUIRED_FILES {
        assert!(
            TASK_STORAGE_FILES.contains(&f),
            "required {f} must appear in TASK_STORAGE_FILES"
        );
        assert!(
            !TASK_STORAGE_OPTIONAL_FILES.contains(&f),
            "required {f} must NOT appear in TASK_STORAGE_OPTIONAL_FILES"
        );
    }
    // optional ⊆ full
    for &f in TASK_STORAGE_OPTIONAL_FILES {
        assert!(
            TASK_STORAGE_FILES.contains(&f),
            "optional {f} must appear in TASK_STORAGE_FILES"
        );
        assert!(
            !TASK_STORAGE_REQUIRED_FILES.contains(&f),
            "optional {f} must NOT appear in TASK_STORAGE_REQUIRED_FILES"
        );
    }

    // Ordering pin: each per-file const matches the corresponding TASK_STORAGE_FILES entry.
    assert_eq!(TASK_STORAGE_FILES[0], TASK_SUMMARY_FILENAME);
    assert_eq!(TASK_STORAGE_FILES[1], TASK_LLM_TURNS_FILENAME);
    assert_eq!(TASK_STORAGE_FILES[2], TASK_TURN_INDEX_FILENAME);
    assert_eq!(TASK_STORAGE_FILES[3], TASK_DECOMPOSITION_FILENAME);
}

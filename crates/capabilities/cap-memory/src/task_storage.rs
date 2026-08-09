//! AC-05 task storage layout SPEC contract — MODULE-011 §1.4 line 360.
//!
//! Slice H (m011-slice-h) closes the **cap-memory half** of AC-05 by declaring
//! the canonical 4-file layout consumed by the deferred MODULE-002 fs wiring
//! slice + MODULE-001 runtime (llm-turns.jsonl append-only audit log). Same
//! partition pattern as slice G's [`crate::ROLLBACK_GIT_PATHS`] (AC-18) and
//! slice E's `tests/integration_internal_ac_closure.rs` (AC-25 6-category
//! storage classification per PRD §11.1.1).
//!
//! cap-memory owns 2 of the 4 files (summary.yaml + turn-index.yaml — see
//! [`crate::summary::Summary`] / [`crate::turn_index::TurnIndex`] schemas
//! shipped in slice A). The other 2 (`llm-turns.jsonl` + `decomposition.yaml`)
//! live outside cap-memory:
//!
//! - `llm-turns.jsonl` — runtime audit-log append (MODULE-001 + PRD §11.2);
//!   cap-memory only references it via [`crate::turn_index::TurnEntry::log_offset`].
//! - `decomposition.yaml` — OPTIONAL per AC-05 wording; owner TBD (likely
//!   MODULE-008 run-manager or a future task-decomposition module).
//!
//! See §3.6 row "AC-05 cross-module half: on-disk persistence of the 4-file
//! task storage layout" for the deferred consumer details.

/// Summary file basename — [`crate::summary::Summary`] serializes to YAML here.
pub const TASK_SUMMARY_FILENAME: &str = "summary.yaml";

/// LLM turns append-only audit log — owned by MODULE-001 runtime per PRD §11.2.
pub const TASK_LLM_TURNS_FILENAME: &str = "llm-turns.jsonl";

/// Turn index — [`crate::turn_index::TurnIndex`] serializes to YAML here.
pub const TASK_TURN_INDEX_FILENAME: &str = "turn-index.yaml";

/// Decomposition file — OPTIONAL per AC-05 §1.4 line 360.
pub const TASK_DECOMPOSITION_FILENAME: &str = "decomposition.yaml";

/// Canonical 4-file layout per AC-05 §1.4 line 360 verbatim ordering.
///
/// First 3 entries are required; entry 4 (`decomposition.yaml`) is optional.
/// Subset relations: `TASK_STORAGE_REQUIRED_FILES ∪ TASK_STORAGE_OPTIONAL_FILES
/// = TASK_STORAGE_FILES`, `TASK_STORAGE_REQUIRED_FILES ∩
/// TASK_STORAGE_OPTIONAL_FILES = ∅`.
pub const TASK_STORAGE_FILES: &[&str; 4] = &[
    TASK_SUMMARY_FILENAME,
    TASK_LLM_TURNS_FILENAME,
    TASK_TURN_INDEX_FILENAME,
    TASK_DECOMPOSITION_FILENAME,
];

/// The 3 required files (subset of [`TASK_STORAGE_FILES`]).
pub const TASK_STORAGE_REQUIRED_FILES: &[&str; 3] = &[
    TASK_SUMMARY_FILENAME,
    TASK_LLM_TURNS_FILENAME,
    TASK_TURN_INDEX_FILENAME,
];

/// The 1 optional file (subset of [`TASK_STORAGE_FILES`]).
pub const TASK_STORAGE_OPTIONAL_FILES: &[&str; 1] = &[TASK_DECOMPOSITION_FILENAME];

/// Per-task subdirectory template under the agent's `.agent/memory/` root.
///
/// The `{task_id}` placeholder is interpolated by the deferred MODULE-002 fs
/// wiring slice — cap-memory does not perform on-disk writes (see [`crate::summary::Summary`]
/// rustdoc and the §3.6 "L6 on-disk persistence" / "AC-05 cross-module half:
/// on-disk persistence" rows).
///
/// **Path-traversal sanitization contract (consumer obligation)**: the deferred
/// MODULE-002 fs consumer MUST treat `task_id` as untrusted (guest-controllable
/// via WIT host fns and runtime task creation paths) and validate against path
/// escape BEFORE substituting into this template. Naive `String::replace(...)`
/// with an attacker-supplied `task_id` (e.g., `"../../etc/passwd"`,
/// `"../../../target"`, embedded NUL byte, embedded `/`, absolute-path prefix)
/// would escape the `.agent/memory/tasks/` sandbox. Recommended mitigation:
/// (a) a typed `TaskId` newtype whose constructor enforces `[a-z0-9-]+` (or
/// the project's chosen identifier grammar) and rejects all path metacharacters,
/// OR (b) `Path::join`-based composition with a final realpath-confinement check
/// rooted at the agent's `.agent/memory/` directory. Adversarial-round-1
/// finding (slice H — m011-slice-h): not exploitable here (cap-memory does not
/// interpolate), but documented defensively to prevent the consumer from
/// missing the trust boundary.
pub const TASK_STORAGE_DIR_TEMPLATE: &str = ".agent/memory/tasks/{task_id}/";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_storage_files_const_matches_ac05_wording() {
        // AC-05 §1.4 line 360 wording (verbatim including ordering):
        // "Task storage: summary.yaml + llm-turns.jsonl + turn-index.yaml + optional decomposition.yaml"
        assert_eq!(
            TASK_STORAGE_FILES,
            &[
                "summary.yaml",
                "llm-turns.jsonl",
                "turn-index.yaml",
                "decomposition.yaml"
            ]
        );
    }

    #[test]
    fn subset_arithmetic_holds() {
        // required + optional = full; required ∩ optional = ∅
        assert_eq!(
            TASK_STORAGE_REQUIRED_FILES.len() + TASK_STORAGE_OPTIONAL_FILES.len(),
            TASK_STORAGE_FILES.len()
        );
        for &f in TASK_STORAGE_REQUIRED_FILES {
            assert!(
                TASK_STORAGE_FILES.contains(&f),
                "required file {f} must appear in TASK_STORAGE_FILES"
            );
            assert!(
                !TASK_STORAGE_OPTIONAL_FILES.contains(&f),
                "required file {f} must NOT appear in TASK_STORAGE_OPTIONAL_FILES"
            );
        }
        for &f in TASK_STORAGE_OPTIONAL_FILES {
            assert!(
                TASK_STORAGE_FILES.contains(&f),
                "optional file {f} must appear in TASK_STORAGE_FILES"
            );
            assert!(
                !TASK_STORAGE_REQUIRED_FILES.contains(&f),
                "optional file {f} must NOT appear in TASK_STORAGE_REQUIRED_FILES"
            );
        }
    }

    #[test]
    fn dir_template_has_task_id_placeholder() {
        assert!(
            TASK_STORAGE_DIR_TEMPLATE.contains("{task_id}"),
            "dir template must contain `{{task_id}}` placeholder"
        );
        assert!(
            TASK_STORAGE_DIR_TEMPLATE.starts_with(".agent/memory/"),
            "dir template must root under `.agent/memory/`"
        );
        assert!(
            TASK_STORAGE_DIR_TEMPLATE.ends_with('/'),
            "dir template must end with `/`"
        );
    }

    #[test]
    fn per_file_consts_match_full_list_entries() {
        // Each per-file const matches the corresponding entry in TASK_STORAGE_FILES,
        // pinning the ordering against future drift.
        assert_eq!(TASK_STORAGE_FILES[0], TASK_SUMMARY_FILENAME);
        assert_eq!(TASK_STORAGE_FILES[1], TASK_LLM_TURNS_FILENAME);
        assert_eq!(TASK_STORAGE_FILES[2], TASK_TURN_INDEX_FILENAME);
        assert_eq!(TASK_STORAGE_FILES[3], TASK_DECOMPOSITION_FILENAME);
    }
}

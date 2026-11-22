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
/// MODULE-010 B1 — where a task's turn index moves its oldest entries to stay under its read
/// cap: one JSON [`crate::turn_index::TurnEntry`] per line, appended. The index and its archive
/// hold every entry between them, so the `turn_index` table is still rebuilt from files whole
/// (PRD §11.2.1).
pub const TASK_TURN_INDEX_ARCHIVE_FILENAME: &str = "turn-index-archive.jsonl";
/// The most bytes of a turn-index archive a read reads.
pub const MAX_TURN_INDEX_ARCHIVE_BYTES: u64 = 64 * 1024 * 1024;

/// Append `entries` to the turn-index archive at `path`, one line each, in one write followed
/// by an fsync. A last line with no newline — an append that was cut short — is ended first, so
/// the entries written now start on lines of their own. A path that is a link or not a regular
/// file is refused.
pub fn append_turn_index_archive(
    path: &std::path::Path,
    entries: &[crate::turn_index::TurnEntry],
) -> std::io::Result<()> {
    use std::io::{Read, Seek, SeekFrom, Write};
    let refuse = || {
        std::io::Error::other(format!(
            "refusing a turn-index archive that is not a regular file: {path:?}"
        ))
    };
    if std::fs::symlink_metadata(path).is_ok_and(|m| !m.file_type().is_file()) {
        return Err(refuse());
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true).append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(refuse());
    }
    let mut buf = Vec::new();
    if meta.len() > 0 {
        let mut last = [0u8; 1];
        file.seek(SeekFrom::Start(meta.len() - 1))?;
        file.read_exact(&mut last)?;
        if last[0] != b'\n' {
            buf.push(b'\n');
        }
    }
    for entry in entries {
        serde_json::to_writer(&mut buf, entry).map_err(std::io::Error::other)?;
        buf.push(b'\n');
    }
    file.write_all(&buf)?;
    file.sync_data()
}

/// The entries of the turn-index archive at `path`, oldest first, from its first
/// [`MAX_TURN_INDEX_ARCHIVE_BYTES`]. A missing archive, a link or a non-regular file reads as
/// none; a line that does not parse is skipped.
pub fn load_turn_index_archive(path: &std::path::Path) -> Vec<crate::turn_index::TurnEntry> {
    use std::io::{BufRead, Read};
    if !std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_file()) {
        return Vec::new();
    }
    let Ok(file) = std::fs::File::open(path) else {
        return Vec::new();
    };
    std::io::BufReader::new(file.take(MAX_TURN_INDEX_ARCHIVE_BYTES))
        .split(b'\n')
        .map_while(Result::ok)
        .filter_map(|line| serde_json::from_slice(&line).ok())
        .collect()
}

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
/// The directory is PRD §11.2's (MODULE-010 B1, D1): the post-processor's Step 0 logs
/// each turn there and Step 7 writes the summary and the turn index there, under the agent's
/// tasks root (`Components::with_tasks_root`, `<workspace>/.agent/tasks/active`), with the
/// `task_id` sanitized first and the directory confined (`post_processor::confined_task_dir`).
///
/// **Path-traversal sanitization contract (consumer obligation)**: the deferred
/// MODULE-002 fs consumer MUST treat `task_id` as untrusted (guest-controllable
/// via WIT host fns and runtime task creation paths) and validate against path
/// escape BEFORE substituting into this template. Naive `String::replace(...)`
/// with an attacker-supplied `task_id` (e.g., `"../../etc/passwd"`,
/// `"../../../target"`, embedded NUL byte, embedded `/`, absolute-path prefix)
/// would escape the `.agent/tasks/active/` sandbox. Recommended mitigation:
/// (a) a typed `TaskId` newtype whose constructor enforces `[a-z0-9-]+` (or
/// the project's chosen identifier grammar) and rejects all path metacharacters,
/// OR (b) `Path::join`-based composition with a final realpath-confinement check
/// rooted at the agent's `.agent/tasks/active/` directory. Adversarial-round-1
/// finding (slice H — m011-slice-h): not exploitable here (cap-memory does not
/// interpolate), but documented defensively to prevent the consumer from
/// missing the trust boundary.
pub const TASK_STORAGE_DIR_TEMPLATE: &str = ".agent/tasks/active/{task_id}/";

#[cfg(test)]
mod tests {
    use super::*;

    /// An archive whose last append was cut short takes the next entries on lines of their own.
    #[test]
    fn an_archive_append_ends_a_torn_last_line_first() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(TASK_TURN_INDEX_ARCHIVE_FILENAME);
        let entry = |turn: u32| crate::turn_index::TurnEntry {
            turn,
            timestamp: "2026-11-21T10:00:00Z".into(),
            agent_id: "a".into(),
            task_id: "t1".into(),
            log_offset: crate::turn_index::LogOffset {
                start_line: 0,
                end_line: 0,
            },
            has_user_instruction: false,
            has_user_correction: false,
            has_tool_use: false,
            has_decision: false,
            importance: crate::turn_index::Importance::Normal,
            digest: format!("turn {turn}"),
            collapsed_view: String::new(),
            git_commit: String::new(),
            git_diff_summary: String::new(),
            git_checkpoints: vec![],
            reference_count: 0,
            content_identifiers: vec![],
            read_file_versions: vec![],
            tokens_digest: 0,
            tokens_collapse_excerpt: 0,
            tokens_l0_processed: 0,
        };
        append_turn_index_archive(&path, &[entry(1)]).unwrap();
        // An append cut short: part of an entry, no newline.
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        std::io::Write::write_all(&mut file, b"{\"turn\":2,\"times").unwrap();
        drop(file);
        append_turn_index_archive(&path, &[entry(2), entry(3)]).unwrap();
        let turns: Vec<u32> = load_turn_index_archive(&path)
            .iter()
            .map(|e| e.turn)
            .collect();
        assert_eq!(turns, [1, 2, 3]);
        // A link or a directory is refused.
        assert!(append_turn_index_archive(dir.path(), &[entry(4)]).is_err());
    }

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
            TASK_STORAGE_DIR_TEMPLATE.starts_with(".agent/tasks/active/"),
            "dir template must root under `.agent/tasks/active/` (PRD §11.2)"
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

//! YAML persistence for `Run` rows under `state_dir` (Slice C, AC-15).
//!
//! Atomic write via `tempfile::NamedTempFile::new_in(state_dir)`:
//! 1. write the YAML body to the tempfile;
//! 2. `sync_all()` on the tempfile (durability of contents);
//! 3. `persist(target)` — atomic rename to `<task_id>.yaml`;
//! 4. `sync_all()` on the parent directory (durability of the entry — Unix
//!    only; Windows skips per platform parity).
//!
//! **Path-traversal defense** at the persister boundary: REJECTS task_id
//! equal to `.` / `..`, leading-dot, or interior `..` substring. ACCEPTS `:`
//! because REQ-069 canonical `auto:{agent-id}` task_ids contain it and `:`
//! is filesystem-legal on Unix/APFS/Linux ext4. Windows NTFS support is
//! waived for Slice C (see MODULE-008 §3.6).
//!
//! **Single-writer invariant**: `RunPersister` assumes single-process
//! ownership of `state_dir`. Concurrent multi-process file-locking
//! (`flock` / `O_EXCL` pidfile) is waived for Slice C.

use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;

use advance_shared_types::run::RunError;
use tempfile::NamedTempFile;

use crate::identifier::{validate_agent_id, validate_run_id, validate_task_id};
use crate::run::Run;

/// Manages YAML persistence of `Run` rows under a directory.
pub struct RunPersister {
    state_dir: PathBuf,
}

impl RunPersister {
    /// Construct a persister rooted at `state_dir`. The directory MUST
    /// already exist (the persister does not create it); on Unix the
    /// caller is responsible for setting 0o700 mode on the directory if
    /// secrecy is required.
    pub fn new(state_dir: PathBuf) -> Self {
        Self { state_dir }
    }

    /// Validate that `task_id` is safe to use as a filesystem name. This
    /// is the persister-side filter that ensure_run pre-validates against
    /// BEFORE inserting into the in-memory store (so memory/disk stay
    /// consistent). REJECTS: `task_id == "."`, `task_id == ".."`, leading
    /// dot, interior `..` substring. ACCEPTS `:` per REQ-069.
    pub fn validate_path_safe(task_id: &str) -> Result<(), &'static str> {
        if task_id.is_empty() {
            return Err("empty");
        }
        if task_id == "." || task_id == ".." {
            return Err("reserved");
        }
        if task_id.starts_with('.') {
            return Err("leading-dot");
        }
        if task_id.contains("..") {
            return Err("interior-dotdot");
        }
        Ok(())
    }

    fn target_path(&self, task_id: &str) -> PathBuf {
        self.state_dir.join(format!("{task_id}.yaml"))
    }

    /// Persist a `Run` to `<state_dir>/<task_id>.yaml` atomically.
    pub fn persist(&self, run: &Run) -> Result<(), RunError> {
        Self::validate_path_safe(&run.task_id)
            .map_err(|e| RunError::PermissionDenied(format!("persist-unsafe-task-id: {e}")))?;
        let target = self.target_path(&run.task_id);

        let body = serde_yml::to_string(run)
            .map_err(|e| RunError::PermissionDenied(format!("persist-serialize: {e}")))?;

        // Step 1 — create tempfile in state_dir (so rename is atomic on
        // the same filesystem).
        let mut tmp = NamedTempFile::new_in(&self.state_dir)
            .map_err(|e| RunError::PermissionDenied(format!("persist-tmpfile: {e}")))?;

        // Step 2 — write body + fsync the tempfile BEFORE rename. Step 3 —
        // rename. Step 4 — parent dir fsync (Unix only).
        tmp.write_all(body.as_bytes())
            .map_err(|e| RunError::PermissionDenied(format!("persist-write: {e}")))?;

        #[cfg(unix)]
        {
            tmp.as_file()
                .sync_all()
                .map_err(|e| RunError::PermissionDenied(format!("persist-sync-tmpfile: {e}")))?;
        }

        tmp.persist(&target)
            .map_err(|e| RunError::PermissionDenied(format!("persist-rename: {e}")))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // Belt-and-braces: ensure 0o600 on the final file (NamedTempFile
            // already uses 0o600 on Unix, but a fresh chmod prevents any
            // permission surprise from non-default umask environments). Log
            // failures so operators can detect mode-divergence (closes
            // audit R3 silent-failure Warning).
            match fs::metadata(&target) {
                Ok(meta) => {
                    let mut perms = meta.permissions();
                    perms.set_mode(0o600);
                    if let Err(e) = fs::set_permissions(&target, perms) {
                        eprintln!(
                            "RunPersister::persist set_permissions(0o600) failed for {:?}: {:?}",
                            target, e
                        );
                    }
                }
                Err(e) => {
                    eprintln!(
                        "RunPersister::persist metadata({:?}) failed: {:?} — file mode may not be 0o600",
                        target, e
                    );
                }
            }
            // Parent-dir fsync for the durability of the directory entry.
            // Log failure so operators can detect durability degradation.
            match File::open(&self.state_dir) {
                Ok(dir) => {
                    if let Err(e) = dir.sync_all() {
                        eprintln!(
                            "RunPersister::persist parent-dir sync_all({:?}) failed: {:?} — directory entry durability degraded",
                            self.state_dir, e
                        );
                    }
                }
                Err(e) => {
                    eprintln!(
                        "RunPersister::persist parent-dir open({:?}) failed: {:?} — directory entry sync skipped",
                        self.state_dir, e
                    );
                }
            }
        }

        Ok(())
    }

    /// Load every `*.yaml` file under `state_dir` as a `Run`. Corrupted
    /// entries are skipped with `eprintln!` and counted in the returned
    /// `invalid_count`. Returns a `Result` so callers can distinguish a
    /// genuine `read_dir` failure (state_dir missing, unreadable) from
    /// "directory is empty / has no parseable yaml" — closes the
    /// fail-open vector where `recover_from_disk` would otherwise look
    /// like a clean recovery on a missing state_dir (Codex audit R1
    /// Warning).
    pub fn load_all(&self) -> Result<(Vec<Run>, u32), RunError> {
        // Slice C — cap in-progress Vec growth at MAX_RUNS_PER_STORE
        // (closes adversarial R2 Warning: load_all would otherwise build
        // a full Vec of millions of Run rows before recover_from_disk
        // could apply its own cap, enabling startup memory exhaustion).
        // Excess valid rows are counted as invalid_count and skipped at
        // load time.
        const MAX_LOAD_ROWS: usize = crate::run::MAX_RUNS_PER_STORE;
        // Slice C — aggregate scan cap across BOTH valid and invalid
        // entries (closes adversarial R5 Warning: cap_during_load only
        // bounded valid rows; a directory flooded with malformed yaml
        // could still stall cold-start while we hold store.write()).
        // 2x MAX_LOAD_ROWS allowance keeps recovery responsive while
        // tolerating some directory-walk noise.
        const MAX_SCAN_ENTRIES: usize = MAX_LOAD_ROWS * 2;
        let mut scanned_entries: usize = 0;
        let mut runs: Vec<Run> = Vec::new();
        let mut invalid_count: u32 = 0;
        let entries = fs::read_dir(&self.state_dir).map_err(|e| {
            RunError::PermissionDenied(format!("load_all-read_dir({:?}): {:?}", self.state_dir, e))
        })?;
        for entry in entries.flatten() {
            scanned_entries = scanned_entries.saturating_add(1);
            // Slice C — aggregate scan cap: bail out of the read_dir loop
            // once we've inspected too many entries (regardless of how
            // many were valid). Prevents directory-flood DoS during
            // cold-start while we hold store.write().
            if scanned_entries > MAX_SCAN_ENTRIES {
                eprintln!(
                    "RunPersister::load_all: aggregate scan cap {} reached at entry {:?}; stopping enumeration",
                    MAX_SCAN_ENTRIES, entry.path()
                );
                invalid_count = invalid_count.saturating_add(1);
                break;
            }
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("yaml") {
                continue;
            }
            // Slice C — symlink defense: refuse to follow symlinks out of
            // state_dir (closes audit R1 adversarial Warning: place
            // state_dir/evil.yaml → /etc/passwd, load_all would read it via
            // fs::read_to_string which follows). Use symlink_metadata which
            // does NOT follow. Also reject non-regular files (FIFO, device
            // nodes, sockets) — closes R4 Warning: a `state_dir/hang.yaml`
            // named pipe would otherwise block `read_to_string` forever
            // while we hold `store.write()`.
            match fs::symlink_metadata(&path) {
                Ok(meta) => {
                    if meta.file_type().is_symlink() {
                        eprintln!(
                            "RunPersister::load_all: refusing to follow symlink {:?}",
                            path
                        );
                        invalid_count = invalid_count.saturating_add(1);
                        continue;
                    }
                    if !meta.file_type().is_file() {
                        eprintln!(
                            "RunPersister::load_all: refusing non-regular file {:?} (FIFO/socket/device)",
                            path
                        );
                        invalid_count = invalid_count.saturating_add(1);
                        continue;
                    }
                    // Slice C — body-size cap: refuse to load YAML bodies
                    // larger than 64 KiB. A single Run record is well under
                    // 4 KiB even with full Slice B+C field set; a >64 KiB
                    // YAML is either corruption or an attacker amplifying
                    // memory cost (closes the recover_from_disk DoS-via-
                    // huge-yaml vector).
                    const MAX_YAML_BODY_BYTES: u64 = 65_536;
                    if meta.len() > MAX_YAML_BODY_BYTES {
                        eprintln!(
                            "RunPersister::load_all: file {:?} exceeds {} bytes (got {}); skipping",
                            path,
                            MAX_YAML_BODY_BYTES,
                            meta.len()
                        );
                        invalid_count = invalid_count.saturating_add(1);
                        continue;
                    }
                }
                Err(e) => {
                    eprintln!(
                        "RunPersister::load_all: symlink_metadata({:?}) failed: {:?}",
                        path, e
                    );
                    invalid_count = invalid_count.saturating_add(1);
                    continue;
                }
            }
            let body = match fs::read_to_string(&path) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("RunPersister::load_all: read {:?} failed: {:?}", path, e);
                    invalid_count = invalid_count.saturating_add(1);
                    continue;
                }
            };
            let run: Run = match serde_yml::from_str(&body) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("RunPersister::load_all: parse {:?} failed: {:?}", path, e);
                    invalid_count = invalid_count.saturating_add(1);
                    continue;
                }
            };
            // Defense-in-depth: validate that the deserialized Run.task_id
            // matches the file basename (closes Claude audit R1 Warning —
            // a YAML at task-1.yaml with task_id="task-2" would otherwise
            // poison the live_by_task index on the next persist).
            let basename_task_id = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
            if basename_task_id != run.task_id {
                eprintln!(
                    "RunPersister::load_all: task_id mismatch — file {:?} declares task_id={:?} (skip)",
                    path, run.task_id
                );
                invalid_count = invalid_count.saturating_add(1);
                continue;
            }
            // Slice C — re-validate identifier charsets on disk-loaded
            // Runs (closes audit R3 Warning: load_all accepted deserialized
            // Run rows without re-validating run_id / task_id /
            // controller_agent. Corrupted or hand-edited YAML can
            // otherwise inject invalid live entries that would later
            // surface as runtime panics or trust-boundary leaks).
            if validate_run_id(run.id.as_ref()).is_err()
                || validate_task_id(&run.task_id).is_err()
                || validate_agent_id(&run.controller_agent).is_err()
            {
                eprintln!(
                    "RunPersister::load_all: identifier charset failed re-validation for file {:?} (skip)",
                    path
                );
                invalid_count = invalid_count.saturating_add(1);
                continue;
            }
            // Slice C — persister-path-safe check: refuse rows whose
            // task_id would have been rejected at ensure_run-time
            // (`.`/`..`/leading-dot/interior-..). Hand-edited YAML named
            // `state_dir/.hidden.yaml` could otherwise be reloaded but
            // would fail subsequent persist (closes audit R1 adversarial
            // "unpersistable zombie runs" Warning).
            if Self::validate_path_safe(&run.task_id).is_err() {
                eprintln!(
                    "RunPersister::load_all: task_id {:?} fails persist-safe (zombie); skipping",
                    run.task_id
                );
                invalid_count = invalid_count.saturating_add(1);
                continue;
            }
            // Slice C — numeric budget invariant re-validation: refuse
            // rows with negative / non-finite cost_usd / cost_reserved.
            // Hand-edited YAML with negative cost_usd would reopen spent
            // budget headroom by lowering the `cost_after` sum at the
            // gate (closes audit R1 adversarial "numeric invariant
            // bypass" Warning).
            if !run.budget.cost_usd.is_finite()
                || run.budget.cost_usd < 0.0
                || !run.budget.cost_reserved.is_finite()
                || run.budget.cost_reserved < 0.0
            {
                eprintln!(
                    "RunPersister::load_all: invalid budget invariants in {:?} (cost_usd={}, cost_reserved={}); skipping",
                    path, run.budget.cost_usd, run.budget.cost_reserved
                );
                invalid_count = invalid_count.saturating_add(1);
                continue;
            }
            if let Some(limit) = run.budget.cost_limit {
                if !limit.is_finite() || limit < 0.0 {
                    eprintln!(
                        "RunPersister::load_all: invalid cost_limit in {:?} ({}); skipping",
                        path, limit
                    );
                    invalid_count = invalid_count.saturating_add(1);
                    continue;
                }
            }
            // Slice C — state-machine invariant re-validation (closes
            // adversarial R4 Warning: hand-edited YAML with status=Active
            // + root_await=Some bypassed in-memory invariant guards).
            // §1.3.3 canonical invariant: Active runs MUST NOT have
            // root_await set; Suspended runs SHOULD have root_await set;
            // terminal runs MUST have drained reservations.
            use advance_shared_types::run::TaskRunStatus as TS;
            let invariant_ok = match (&run.status, run.root_await.is_some()) {
                (TS::Active, true) => false, // Active+root_await=Some is invariant violation
                (TS::Completed | TS::Failed(_) | TS::Cancelled(_), _) => {
                    // Terminal: must have drained reservations.
                    run.budget.token_reserved == 0 && run.budget.cost_reserved == 0.0
                }
                _ => true,
            };
            if !invariant_ok {
                eprintln!(
                    "RunPersister::load_all: state-machine invariant violation in {:?} (status={:?}, root_await={:?}, token_reserved={}, cost_reserved={}); skipping",
                    path, run.status, run.root_await, run.budget.token_reserved, run.budget.cost_reserved
                );
                invalid_count = invalid_count.saturating_add(1);
                continue;
            }
            // Cap the in-progress Vec — bound startup memory growth. Break
            // out of the loop (don't `continue`) to avoid attacker-
            // controlled cold-start CPU/IO DoS from a flooded state_dir
            // (closes adversarial R4 Warning: continuing to iterate +
            // parse remaining files past the cap is itself a DoS vector).
            if runs.len() >= MAX_LOAD_ROWS {
                eprintln!(
                    "RunPersister::load_all: in-progress cap {} reached; stopping enumeration (state_dir has more entries)",
                    MAX_LOAD_ROWS
                );
                invalid_count = invalid_count.saturating_add(1);
                break;
            }
            runs.push(run);
        }
        Ok((runs, invalid_count))
    }
}

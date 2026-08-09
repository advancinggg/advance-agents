//! Daily-rotated JSONL file writer (Slice A — synchronous).

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use chrono::NaiveDate;

use crate::error::EventBusError;
use crate::event_io::{event_to_jsonl_line, Event};

/// Open the daily JSONL file with `O_NOFOLLOW` on Unix.
///
/// **Bounded threat model** (round-2 adversarial Critical 1 + W5 honest
/// deferral): `O_NOFOLLOW` only inspects the *final* path component. If an
/// attacker can replace a *parent directory* of `jsonl_dir` with a symlink,
/// the open call traverses the redirected directory tree before reaching the
/// final-component check. Full directory-traversal symlink defense requires
/// `openat2(RESOLVE_NO_SYMLINKS)` (Linux 5.6+) or an `O_DIRECTORY|O_NOFOLLOW`
/// fd captured at construction with subsequent `openat()` calls — both
/// deferred to Slice B. Slice A inherits the M004 trust boundary
/// (`crates/database/src/handle.rs:18-26`): callers must be process-internal
/// trusted code with path-isolation responsibility.
///
/// **Windows reparse points** (round-2 adversarial W5): bare `OpenOptions::open`
/// on Windows DOES follow `IO_REPARSE_TAG_SYMLINK` and `IO_REPARSE_TAG_MOUNT_POINT`
/// reparse points by default. Slice A's Windows path therefore relies only on
/// the `symlink_metadata` pre-check at the call site (which is racy but blocks
/// the common attack of pre-staging the daily file as a symlink). Full
/// `FILE_FLAG_OPEN_REPARSE_POINT` opt-out is deferred to Slice B alongside
/// the cross-platform openat2/openat refactor.
#[cfg(unix)]
fn open_append_no_follow(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .create(true)
        .append(true)
        .custom_flags(libc::O_NOFOLLOW)
        .mode(0o600) // Round-1 adversarial W8 fix — explicit 0o600 mode (no world-readable).
        .open(path)
}

#[cfg(not(unix))]
fn open_append_no_follow(path: &Path) -> std::io::Result<File> {
    OpenOptions::new().create(true).append(true).open(path)
}

/// Daily-rotated JSONL writer. Rotation is keyed off `event.timestamp.date_naive()`,
/// NOT wall clock — eliminates the midnight wall-clock-vs-event-timestamp race.
pub(crate) struct EventFileWriter {
    jsonl_dir: PathBuf,
    cached: Mutex<Option<(NaiveDate, BufWriter<File>)>>,
}

impl EventFileWriter {
    pub(crate) fn new(jsonl_dir: PathBuf) -> Result<Self, EventBusError> {
        // Round-2 adversarial W6 fix: create the JSONL directory with mode 0o700
        // on Unix. Default umask leaves dirs at 0o755 — world-listable, exposing
        // a timing/cardinality side channel via `ls jsonl_dir` and enabling the
        // squat-then-symlink-tomorrow's-file DoS (Critical 1's pre-condition).
        // Best-effort: if the dir already exists with looser permissions, we
        // tighten them; if chmod fails (e.g., on FAT/exFAT), fall through —
        // file-level 0o600 protections still apply.
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new()
                .mode(0o700)
                .recursive(true)
                .create(&jsonl_dir)?;
            // For an already-existing dir, set mode to 0o700 explicitly.
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = std::fs::metadata(&jsonl_dir) {
                let mut perms = meta.permissions();
                perms.set_mode(0o700);
                let _ = std::fs::set_permissions(&jsonl_dir, perms);
            }
        }
        #[cfg(not(unix))]
        std::fs::create_dir_all(&jsonl_dir)?;

        Ok(Self {
            jsonl_dir,
            cached: Mutex::new(None),
        })
    }

    pub(crate) fn append(&self, event: &Event) -> Result<(), EventBusError> {
        let line = event_to_jsonl_line(event)?;
        self.append_line(&line, event.timestamp.date_naive())
    }

    /// Slice B: write a pre-formatted line (already terminated with `\n`) into the
    /// daily-rotated JSONL file matching `target_date`. Used by the file_writer
    /// actor to support LeakDetector scrubbing on the line BEFORE rotation logic
    /// (the scrubbed string differs from the verbatim event JSON, but both must
    /// land in the same daily file keyed by event timestamp's date).
    pub(crate) fn append_line(
        &self,
        line: &str,
        target_date: NaiveDate,
    ) -> Result<(), EventBusError> {
        // Round-1 adversarial W1 fix: recover from poison instead of panicking.
        // A poisoned mutex MUST NOT propagate a panic to the caller — the trait
        // `EventBusEmit::emit` returns `()`, and the documented contract is
        // "swallow errors silently into dropped_count". `into_inner()` proceeds
        // with the inner data despite poison.
        // Round-2 adversarial W4 fix: when the mutex was poisoned, the cached
        // BufWriter may hold a partially-written line or a closed-by-OS fd.
        // Discard the cache entirely on poison recovery so the next write
        // forces a fresh `open` and clean BufWriter — preventing corrupted
        // JSONL output from a prior panic.
        let mut cached = match self.cached.lock() {
            Ok(guard) => guard,
            Err(poison) => {
                let mut guard = poison.into_inner();
                *guard = None;
                guard
            }
        };

        let needs_rotation = match &*cached {
            Some((cached_date, _)) => *cached_date != target_date,
            None => true,
        };

        if needs_rotation {
            let path = file_path_for(&self.jsonl_dir, target_date);
            // Round-1 adversarial Critical 1 fix: pre-check for symlink before
            // open (defense-in-depth alongside `O_NOFOLLOW` on Unix). On
            // platforms without O_NOFOLLOW support, this still rejects the
            // common attack of pre-staging a symlinked target file.
            if let Ok(meta) = std::fs::symlink_metadata(&path) {
                if meta.file_type().is_symlink() {
                    return Err(EventBusError::SymlinkAtOutputPath {
                        path: path.display().to_string(),
                    });
                }
            }
            // Cold-start path: open `<jsonl_dir>/<target_date>.jsonl` in append
            // mode regardless of whether prior files exist for other dates.
            // Same-day append regression is locked by T_S A12. `O_NOFOLLOW` on
            // Unix returns `ELOOP` if the path is a symlink (round-1
            // adversarial Critical 1 final gate).
            let file = open_append_no_follow(&path)?;
            let writer = BufWriter::new(file);
            *cached = Some((target_date, writer));
        }

        let (_, writer) = cached.as_mut().expect("rotation produced a writer");
        writer.write_all(line.as_bytes())?;
        writer.flush()?;
        Ok(())
    }
}

fn file_path_for(jsonl_dir: &Path, date: NaiveDate) -> PathBuf {
    jsonl_dir.join(format!("{}.jsonl", date.format("%Y-%m-%d")))
}

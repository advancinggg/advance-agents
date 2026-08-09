//! Slice C — JSONL retention sweeper (MODULE-019 §1.3.5 + AC-19).
//!
//! Periodic background task that removes daily-rotated JSONL files older than
//! `EventBusConfig::jsonl_retention_days`. Today's file is NEVER removed
//! regardless of retention. Symlinks are skipped on the DELETE path
//! (defense-in-depth alongside Slice A/B's WRITE-path symlink defense).
//!
//! # Architecture
//!
//! - [`RetentionSweeperShared`]: owns sweep state (jsonl_dir, retention_days,
//!   clock, pool, pipeline) + the per-iteration `sweep_once` async method.
//! - [`run_sweeper_loop`]: production driver — calls `shared.sweep_once()` on a
//!   timer, exits on `cancel_token.cancelled()`.
//! - [`EventBus::sweep_once_for_tests`](crate::EventBus::sweep_once_for_tests):
//!   integration-test entry point that calls `sweep_once` directly without
//!   going through the run-loop. Bypasses timer-wheel races.
//!
//! # Silent-success / loud-failure
//!
//! On a successful sweep iteration the sweeper emits NO events; state is
//! exposed via `GET /query/sweeper_state`. On real I/O failure
//! (PermissionDenied on parent dir, symlink rejection, retention_overflow),
//! it emits a `runtime.warning` event through `EmitPipeline` so the warning
//! flows through the same fan-out path as user-domain code (preserves
//! AC-13's "no separate tracing subsystem" invariant).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::TransactionBehavior;
use tokio_util::sync::CancellationToken;

use advance_shared_types::event::Event;

use crate::clock::Clock;
use crate::taxonomy;
use crate::EmitPipeline;

/// Hard cap to prevent `chrono::Duration::days` overflow on values close to
/// `u32::MAX`. 36 500 days ≈ 100 years — any value above this is meaningless
/// for a JSONL observability cleanup task.
pub(crate) const MAX_RETENTION_DAYS: u32 = 36_500;

/// Slice C — sweep state + per-iteration logic. Owned by both the
/// background run-loop and `EventBus::sweep_once_for_tests`.
pub(crate) struct RetentionSweeperShared {
    pub(crate) jsonl_dir: PathBuf,
    pub(crate) retention_days: u32,
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) pool: Arc<Pool<SqliteConnectionManager>>,
    pub(crate) pipeline: EmitPipeline,
}

/// Slice C — production run-loop driver. Spawned as the 5th tokio background
/// task by `EventBus::new`. Calls `shared.sweep_once()` periodically.
pub(crate) async fn run_sweeper_loop(
    shared: Arc<RetentionSweeperShared>,
    sweep_interval: Duration,
    cancel_token: CancellationToken,
) {
    loop {
        tokio::select! {
            _ = cancel_token.cancelled() => return,
            _ = tokio::time::sleep(sweep_interval) => {
                if let Err(e) = shared.sweep_once().await {
                    // Top-level sweep error (e.g., read_dir failure) — emit warning
                    // but keep the loop alive so the next tick retries.
                    shared.emit_warning(
                        "sweep_top_level_error",
                        None,
                        &e.to_string(),
                    );
                }
            }
        }
    }
}

impl RetentionSweeperShared {
    /// Slice C — fire one sweep iteration. Returns Err only on irrecoverable
    /// top-level failures (e.g., the read_dir call itself fails); per-file
    /// errors emit `runtime.warning` and continue iterating.
    pub(crate) async fn sweep_once(&self) -> Result<(), std::io::Error> {
        if self.retention_days == 0 {
            // Early-return: no sweeper_state write either.
            return Ok(());
        }

        // Defense-in-depth even if EventBus::new clamping was bypassed.
        let retention_days = self.retention_days.min(MAX_RETENTION_DAYS);
        let now = self.clock.now();
        let today = now.date_naive();

        // Round 4 Codex W1 + Round 5 chrono-overflow defense: try_days returns
        // None on i64 overflow; checked_sub_signed returns None on
        // unrepresentable date. Either branch emits a runtime.warning + skips
        // the tick.
        let duration = match chrono::Duration::try_days(retention_days as i64) {
            Some(d) => d,
            None => {
                self.emit_warning(
                    "retention_overflow",
                    None,
                    "Duration::try_days returned None",
                );
                return Ok(());
            }
        };
        let cutoff = match today.checked_sub_signed(duration) {
            Some(d) => d,
            None => {
                self.emit_warning(
                    "retention_overflow",
                    None,
                    &format!(
                        "retention_days={} produces unrepresentable cutoff",
                        retention_days
                    ),
                );
                return Ok(());
            }
        };

        let mut removed_files: u64 = 0;
        let mut removed_bytes: u64 = 0;

        let read_dir = match std::fs::read_dir(&self.jsonl_dir) {
            Ok(rd) => rd,
            Err(e) => return Err(e),
        };

        for entry in read_dir {
            // Round 1 AUDIT W1 (Codex): surface read_dir iteration errors via
            // runtime.warning instead of silently continuing — otherwise the
            // sweep finishes "successfully" while glossing over genuine FS
            // failures, contradicting the loud-on-failure spec semantics.
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    self.emit_warning(&format!("{:?}", e.kind()), None, &e.to_string());
                    continue;
                }
            };
            let entry_path = entry.path();

            let ftype = match entry.file_type() {
                Ok(t) => t,
                Err(e) => {
                    self.emit_warning(
                        &format!("{:?}", e.kind()),
                        Some(&entry_path),
                        &e.to_string(),
                    );
                    continue;
                }
            };
            // Only regular files OR symlinks (symlinks fall through to the
            // dedicated rejection branch below).
            if !ftype.is_file() && !ftype.is_symlink() {
                continue;
            }

            let name = match entry.file_name().to_str() {
                Some(n) => n.to_string(),
                None => continue, // non-UTF-8 filename, skip
            };
            if name.starts_with('.') {
                continue; // skip dotfiles like .DS_Store
            }
            if !name.ends_with(".jsonl") {
                continue;
            }
            let stem = &name[..name.len() - ".jsonl".len()];

            // Slice C plan Round 5 W3 fix (Codex): chrono's parse_from_str
            // accepts non-zero-padded month/day. Strict 10-char + ASCII-digit
            // gate rejects `2026-4-1.jsonl`, `02026-04-01.jsonl`, etc.
            if stem.len() != 10 {
                continue;
            }
            if !stem.bytes().all(|b| b.is_ascii_digit() || b == b'-') {
                continue;
            }

            let date = match chrono::NaiveDate::parse_from_str(stem, "%Y-%m-%d") {
                Ok(d) => d,
                Err(_) => continue,
            };

            // Today's file is pinned regardless of retention.
            if date == today {
                continue;
            }
            // Within retention window: keep.
            if date >= cutoff {
                continue;
            }

            // Symlink defense on the DELETE path. symlink_metadata does not
            // follow the link; if the entry is a symlink, emit warning + skip.
            match std::fs::symlink_metadata(&entry_path) {
                Ok(m) if m.file_type().is_symlink() => {
                    self.emit_warning(
                        "symlink",
                        Some(&entry_path),
                        "symlink rejected on retention sweep",
                    );
                }
                Ok(m) => {
                    let size = m.len();
                    match std::fs::remove_file(&entry_path) {
                        Ok(()) => {
                            removed_files += 1;
                            removed_bytes += size;
                        }
                        Err(e) => {
                            self.emit_warning(
                                &format!("{:?}", e.kind()),
                                Some(&entry_path),
                                &e.to_string(),
                            );
                        }
                    }
                }
                Err(e) => {
                    self.emit_warning(
                        &format!("{:?}", e.kind()),
                        Some(&entry_path),
                        &e.to_string(),
                    );
                }
            }
        }

        // Single transactional UPSERT of the sweeper_state row. Slice C plan
        // Round 5 Codex W3 fix: ON CONFLICT(id) DO UPDATE pattern is resilient
        // to a missing seed row (defense against partial migration / external
        // delete).
        if let Err(e) = self.persist_sweep_result(now, removed_files, removed_bytes) {
            return Err(e);
        }

        Ok(())
    }

    fn persist_sweep_result(
        &self,
        now: DateTime<Utc>,
        files: u64,
        bytes: u64,
    ) -> Result<(), std::io::Error> {
        let mut conn = self.pool.get().map_err(std::io::Error::other)?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(std::io::Error::other)?;
        tx.execute(
            "INSERT INTO sweeper_state (id, last_sweep_at, files_removed_total, bytes_freed_total, sweep_count) \
             VALUES (1, ?1, ?2, ?3, 1) \
             ON CONFLICT(id) DO UPDATE SET \
               last_sweep_at = excluded.last_sweep_at, \
               files_removed_total = files_removed_total + excluded.files_removed_total, \
               bytes_freed_total = bytes_freed_total + excluded.bytes_freed_total, \
               sweep_count = sweep_count + 1",
            rusqlite::params![now.to_rfc3339(), files as i64, bytes as i64],
        )
        .map_err(std::io::Error::other)?;
        tx.commit().map_err(std::io::Error::other)?;
        Ok(())
    }

    pub(crate) fn emit_warning(&self, reason: &str, path: Option<&Path>, _details: &str) {
        let event = build_warning_event(self.clock.as_ref(), reason, path);
        self.pipeline.emit(event);
    }
}

/// Slice C — construct a `runtime.warning` event with ULID-based ids and the
/// `__sys:retention_sweeper` system-emitter agent_id. All field lengths are
/// well within `validate_event_size` limits (ULIDs are 26 chars; ids are
/// "evt-sweeper-" + ULID = 38 chars, under MAX_ID_LEN=256).
fn build_warning_event(clock: &dyn Clock, reason: &str, path: Option<&Path>) -> Event {
    let id = format!("evt-sweeper-{}", ulid::Ulid::new());
    let trace_id = format!("tr-sweeper-{}", ulid::Ulid::new());
    let span_id = format!("sp-sweeper-{}", ulid::Ulid::new());
    Event {
        id,
        timestamp: clock.now(),
        agent_id: "__sys:retention_sweeper".to_string(),
        task_id: None,
        run_id: None,
        execution_id: None,
        trace_id,
        span_id,
        parent_span_id: None,
        event_type: taxonomy::extensions::RUNTIME_WARNING.to_string(),
        payload: serde_json::json!({
            "reason": reason,
            "path": path.map(|p| p.display().to_string()),
            "source": "retention_sweeper",
        }),
        duration_ms: None,
    }
}

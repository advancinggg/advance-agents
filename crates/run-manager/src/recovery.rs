//! Slice B crash recovery — in-memory walk of `RunStore` for Suspended
//! runs whose `root_await` session is no longer alive in M007's
//! `AwaitSessionRef`. Resets to Active + emits `run.interrupted`.
//!
//! **Disk-scan prefix DEFERRED to AC-15**: this walk operates on the
//! in-memory store. The production cold-start crash recovery flow per
//! MODULE-008 §1.3.4 requires AC-15 to reload `/.runtime/runs/*.yaml`
//! into the store BEFORE invoking `recover_on_startup`. The Slice B
//! verification of AC-07 covers the walk + transition + emit + report
//! logic; AC-15 adds the disk-reload prefix. See MODULE-008 §3.6 known
//! gaps.

use std::sync::Arc;

use advance_shared_types::await_session::{AwaitSessionRef, SessionId};
use advance_shared_types::run::TaskRunStatus;
use chrono::Utc;

use crate::events;
use crate::identifier::validate_session_id;
use crate::run::{RunId, RunManager};

/// Slice B recovery report. Each `Suspended` candidate increments
/// `suspended_scanned`; the per-candidate outcome increments at most
/// ONE of `interrupted_emitted` / `invalid_session_id` / `raced_skipped`
/// (the remaining case — `exists()` returned true, session alive — is
/// counted implicitly by `suspended_scanned - (other counters)`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RecoveryReport {
    pub suspended_scanned: u32,
    pub interrupted_emitted: u32,
    pub invalid_session_id: u32,
    pub raced_skipped: u32,
    /// Slice C — count of Runs loaded from disk via
    /// [`RunManager::recover_from_disk`].
    pub disk_loaded: u32,
    /// Slice C — count of `*.yaml` files that failed to parse during
    /// [`RunManager::recover_from_disk`]. Logged via eprintln; skipped.
    pub disk_invalid: u32,
}

impl RunManager {
    /// Scan in-memory `RunStore` for Suspended runs whose `root_await`
    /// session is no longer alive; reset to Active + emit `run.interrupted`.
    /// **Requires** `with_await_session_ref(...)` builder. Returns a
    /// `RecoveryReport` with per-outcome counters.
    pub async fn recover_on_startup(
        &self,
        await_session_ref: Arc<dyn AwaitSessionRef>,
    ) -> RecoveryReport {
        let mut report = RecoveryReport::default();

        // Phase 1: read-only collection of Suspended candidates.
        let candidates: Vec<(RunId, String, String, Option<String>)> = {
            let store = self.store.read().unwrap();
            store
                .iter()
                .filter_map(|r| {
                    if matches!(r.status, TaskRunStatus::Suspended) {
                        Some((
                            r.id.clone(),
                            r.task_id.clone(),
                            r.controller_agent.clone(),
                            r.root_await.clone(),
                        ))
                    } else {
                        None
                    }
                })
                .collect()
        };

        // Phase 2: per-candidate query + mutate under double recheck.
        for (run_id, task_id, controller_agent, root_await_snap) in candidates {
            report.suspended_scanned = report.suspended_scanned.saturating_add(1);
            let Some(sid_str) = root_await_snap.clone() else {
                eprintln!(
                    "recovery: Suspended Run {} has root_await=None — skipping",
                    run_id
                );
                continue;
            };
            // Fail-closed on invalid charset: corrupted YAML or attacker-
            // supplied bytes are skipped with a byte-length log (NOT the
            // content, to avoid log injection).
            if validate_session_id(&sid_str).is_err() {
                eprintln!(
                    "recovery: Suspended Run {} has invalid root_await (len={}) — skipping",
                    run_id,
                    sid_str.len()
                );
                report.invalid_session_id = report.invalid_session_id.saturating_add(1);
                continue;
            }
            let sid = SessionId(sid_str.clone());
            if await_session_ref.exists(&sid) {
                // Session alive — no crash; leave Run alone.
                continue;
            }
            // Session lost — reset to Active + emit run.interrupted.
            // Double recheck (status + root_await match) under write lock
            // to defend against TOCTOU race with concurrent pause/resume.
            let mutated = {
                let mut store = self.store.write().unwrap();
                if let Some(run) = store.get_mut(run_id.as_ref()) {
                    if !matches!(run.status, TaskRunStatus::Suspended) {
                        false
                    } else if run.root_await.as_deref() != Some(sid_str.as_str()) {
                        false
                    } else {
                        run.status = TaskRunStatus::Active;
                        run.root_await = None;
                        run.updated_at = Utc::now();
                        true
                    }
                } else {
                    false
                }
            };
            if !mutated {
                report.raced_skipped = report.raced_skipped.saturating_add(1);
                continue;
            }
            // Slice C — write-back the Suspended → Active flip to disk
            // BEFORE emitting `run.interrupted`. Without this, the next
            // restart would re-load the stale Suspended YAML and re-emit
            // run.interrupted. Best-effort: log persist failures but don't
            // block the emit (next state mutation will retry the persist).
            if let Some(persister) = self.persister.as_ref() {
                let snapshot = {
                    let store = self.store.read().unwrap();
                    store.get(run_id.as_ref()).cloned()
                };
                if let Some(run) = snapshot {
                    if let Err(e) = persister.persist(&run) {
                        eprintln!(
                            "recovery: write-back persist failed for run_id={}: {:?} — re-interrupt risk on next restart",
                            run.id, e
                        );
                    }
                }
            }
            // Emit AFTER lock drop + persist.
            let evt = events::run_interrupted_event(
                run_id.as_ref(),
                &task_id,
                &controller_agent,
                "crash-recovery",
            );
            self.event_bus.emit(evt);
            // Wave-12 Lane B (CONTRACT-182): AFTER the event, push a synthesized
            // `Message::RunInterrupted` into the controller's mailbox via the
            // injected RunInterruptSink (MODULE-006). Best-effort — a delivery
            // failure is logged but never blocks the recovery walk or the
            // report. `None` ⇒ event-only (byte-identical to pre-Wave-12).
            if let Some(sink) = self.run_interrupt_sink.as_ref() {
                if let Err(e) = sink.deliver_run_interrupted(
                    &controller_agent,
                    run_id.as_ref(),
                    &task_id,
                    "crash-recovery",
                ) {
                    // Log-injection hardening (defense-in-depth, consistent with
                    // the len-not-content / `{:?}` convention used above for
                    // attacker-influenceable values): render `controller_agent`
                    // via `{:?}` so a control char can never forge a log line if
                    // a future regression were to drop the store-ingress
                    // `validate_agent_id` charset gate. `controller_agent` is
                    // charset-validated today, so no control char is reachable.
                    eprintln!(
                        "recovery: run_interrupt_sink delivery failed for run_id={} controller={:?}: {:?}",
                        run_id, controller_agent, e
                    );
                }
            }
            report.interrupted_emitted = report.interrupted_emitted.saturating_add(1);
        }
        report
    }

    /// Slice C (AC-15) — load every `*.yaml` file under the configured
    /// `state_dir` into the in-memory store. Holds `store.write()` for
    /// the entire load (single-writer invariant per
    /// [`crate::persist::RunPersister`] rustdoc). Returns a fresh
    /// [`RecoveryReport`] with `disk_loaded` + `disk_invalid` populated.
    ///
    /// REQUIRES `with_state_dir(...)` to be wired; else returns
    /// `Err(PermissionDenied("recover-from-disk-requires-state-dir"))`.
    pub fn recover_from_disk(
        self: &std::sync::Arc<Self>,
    ) -> Result<RecoveryReport, advance_shared_types::run::RunError> {
        let persister = match self.persister.as_ref() {
            Some(p) => p,
            None => {
                return Err(advance_shared_types::run::RunError::PermissionDenied(
                    "recover-from-disk-requires-state-dir".into(),
                ))
            }
        };
        let mut report = RecoveryReport::default();
        // Single-writer invariant — hold store.write() for the whole load AND
        // the disk read to prevent concurrent ensure_run from inserting a
        // colliding live_by_task entry between load_all and store.insert
        // (closes audit R2 doc-vs-code drift on the locking story).
        let mut store = self.store.write().unwrap();
        let (runs, invalid_count) = persister.load_all()?;
        report.disk_invalid = invalid_count;
        for run in runs {
            // Slice C — enforce MAX_RUNS_PER_STORE on the disk-reload path
            // too (closes audit R1 adversarial "poisoned state_dir bypasses
            // memory cap" Info). Drop excess rows with eprintln so an
            // operator can tell the difference between "store full from
            // legitimate growth" and "state_dir flooded with stale yaml".
            if store.runs_len() >= crate::run::MAX_RUNS_PER_STORE {
                eprintln!(
                    "recover_from_disk: store cap {} reached; dropping disk row run_id={} task_id={:?}",
                    crate::run::MAX_RUNS_PER_STORE,
                    run.id,
                    run.task_id
                );
                report.disk_invalid = report.disk_invalid.saturating_add(1);
                continue;
            }
            // Skip if we already have this run_id OR if the task already has a
            // live row in the in-memory store (single-live-run-per-task
            // invariant per §1.3.1; closes audit R2 Warning).
            if store.get(run.id.as_ref()).is_some() {
                continue;
            }
            // Slice C — defense against colliding task_id in the in-memory
            // store. cold_start_recovery's contract requires it to run
            // BEFORE any guest dispatch (per §3.10 + waived_scope), but a
            // mis-use would otherwise let two live runs share a task_id.
            if crate::run::is_live_status(&run.status)
                && store.find_live_by_task(&run.task_id).is_some()
            {
                eprintln!(
                    "recover_from_disk: live run for task_id={:?} already in store; skipping disk row run_id={}",
                    run.task_id, run.id
                );
                continue;
            }
            store.insert(run);
            report.disk_loaded = report.disk_loaded.saturating_add(1);
        }
        Ok(report)
    }

    /// Slice C — production cold-start entry point. Sequences
    /// [`Self::recover_from_disk`] (sync) then [`Self::recover_on_startup`]
    /// (async). Returns a merged [`RecoveryReport`] aggregating both halves.
    pub async fn cold_start_recovery(
        self: &std::sync::Arc<Self>,
        await_session_ref: Arc<dyn AwaitSessionRef>,
    ) -> Result<RecoveryReport, advance_shared_types::run::RunError> {
        let from_disk = self.recover_from_disk()?;
        let walked = self.recover_on_startup(await_session_ref).await;
        Ok(RecoveryReport {
            suspended_scanned: walked.suspended_scanned,
            interrupted_emitted: walked.interrupted_emitted,
            invalid_session_id: walked.invalid_session_id,
            raced_skipped: walked.raced_skipped,
            disk_loaded: from_disk.disk_loaded,
            disk_invalid: from_disk.disk_invalid,
        })
    }
}

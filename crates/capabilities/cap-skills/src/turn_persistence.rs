//! Wave-20 (build-only) — `SkillTurnPersistenceDriver`: the MODULE-014 turn-end
//! seam the §3.6 (uu)/(aaa) deferral named.
//!
//! Wraps the UNCHANGED per-op [`SkillPersistenceCoordinator`] and adds the two
//! MODULE-017-AC-22 durability legs the user adjudicated per-leg (2026-06-27):
//! - **leg (b)** `flush_runtime_private` — flush the runtime-private overlay to
//!   disk with **retry-once-then-error**; on the 2nd failure the turn errors and
//!   steps 2/3 (commit + emit) are skipped (PRD §12.6.4 step 1).
//! - **leg (c)** `commit_op_with_compensation` — on a git-commit failure, **roll
//!   back the live in-memory state** ([`SkillStore::snapshot_live`] /
//!   [`SkillStore::restore_live`]) and **re-enqueue** the op for the next turn,
//!   discriminating against the OLD storage-left-mutated behavior (SH-03/SH-16).
//!
//! STATUS (2026-07-03): AC-22 is `passed` / REQ-275 Verified — the
//! skill-persist lane (2026-07-01) wired this driver into the live scheduler
//! turn loop + cli composition root and closed flip-blockers (A) lease
//! reconciliation and (C) op preconditions; the §3.6 (ccc) closure pass
//! (2026-07-03) closed (B) via crash-atomic lease journal writes,
//! quarantine-not-wedge reconcile parsing, bounded replay attempts,
//! retry-once restore halves, and the single-track durable pending rule (see
//! `turn_runtime.rs` + MODULE-017 §3.6 (ccc)). The former delete-op exclusion
//! is also closed: `TurnSkillOp::Delete` runs with a sidecar-aware
//! `snapshot_skill_dir` restore alongside the `LiveSnapshot{active,draft}`
//! compensation.

use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::Mutex;

use crate::error::SkillError;
use crate::lifecycle::SkillStore;
use crate::persistence::DraftBlob;
use crate::persistence_phase::{Initiator, SkillPersistenceCoordinator};

/// Cap on how many turns a commit-failed op is re-enqueued before it is dropped
/// (with a host-side log) rather than retried forever.
const MAX_REQUEUE: u32 = 3;

/// Cap on the per-turn runtime-private overlay (number of staged drafts). Bounds
/// the driver's in-memory growth (adversarial-r1 W4); a staged draft beyond the
/// cap is dropped with a host-side log. Aligned with the per-skill enumeration
/// cap precedent (`MAX_ENUMERATE_ENTRIES = 256`).
const MAX_OVERLAY: usize = 256;

/// Cap on the cross-turn re-enqueue (`pending`) buffer — bounds the number of
/// distinct commit-failed ops carried across turns (adversarial-r2: a `pending`
/// analogue of `MAX_OVERLAY`). A push past the cap is dropped with a host log.
const MAX_PENDING: usize = 256;

/// Per-op control-flow outcome (internal — distinguishes the turn-loop's
/// continue-vs-abort decision, adversarial-r2).
enum OpOutcome {
    /// Durably committed, OR commit-failed + compensated cleanly (rolled back +
    /// re-enqueued). Nothing else to do this turn.
    Done,
    /// Commit failed AND the rollback (`restore_live`) ALSO failed — the live
    /// state may be PARTIAL. The op is re-enqueued (UNLESS it was abandoned at
    /// `MAX_REQUEUE` or could not fit `MAX_PENDING`); the turn MUST stop (not run
    /// later ops against torn state) and re-enqueue the remaining ops.
    Torn(SkillError),
    /// THIS op is not processed further by the turn loop; other ops may safely
    /// continue (the store is consistent). Covers a non-retryable coordinator
    /// error (rolled back to the snapshot), a commit-failure abandoned at
    /// `MAX_REQUEUE` or dropped at `MAX_PENDING` (cleanly rolled back, retry
    /// genuinely gone), AND a transient `snapshot_live` fault (which re-enqueues
    /// the op for next turn UNLESS abandoned/cap-full — so "dropped" here means
    /// "dropped from THIS turn's loop", which is NOT always "discarded"; inspect
    /// `pending`).
    Dropped(SkillError),
}

/// A git-tracked skill op orchestrated by the turn-end driver. `Delete` joined
/// as a variant in the 2026-07-01 skill-persist lane — it runs with a
/// sidecar-aware `snapshot_skill_dir`/`restore_skill_dir` compensation on top
/// of the `LiveSnapshot{active,draft}` restore (the former build-only
/// exclusion is retired — §3.6 (ccc) CLOSURE).
#[derive(Clone, Debug, PartialEq)]
pub enum TurnSkillOp {
    Activate {
        draft_id: String,
        reason: String,
    },
    Rollback {
        skill_id: String,
        version: u32,
        reason: String,
    },
    Delete {
        skill_id: String,
        reason: String,
    },
}

impl TurnSkillOp {
    /// The skill id whose live `{active, draft}` state leg-(c) snapshots. For
    /// `Activate` the draft is name-keyed (`draft_id == skill_id`).
    pub fn skill_id(&self) -> &str {
        match self {
            TurnSkillOp::Activate { draft_id, .. } => draft_id,
            TurnSkillOp::Rollback { skill_id, .. } => skill_id,
            TurnSkillOp::Delete { skill_id, .. } => skill_id,
        }
    }
}

/// A re-enqueued op carried across turns (leg-(c) "re-enqueue for next turn").
#[derive(Clone, Debug)]
pub struct PendingSkillOp {
    pub op: TurnSkillOp,
    /// How many times this op has been re-enqueued (after a commit failure OR a
    /// transient `snapshot_live` fault). Bounds COMBINED retries: at
    /// `>= MAX_REQUEUE` the op is abandoned, so neither cause can loop forever.
    pub requeue_count: u32,
}

impl PendingSkillOp {
    pub fn new(op: TurnSkillOp) -> Self {
        Self {
            op,
            requeue_count: 0,
        }
    }
}

/// Leg-(b) Step-1 flush of the turn's runtime-private overlay to disk.
/// Injectable so the witness can fault it; the driver wraps it with
/// retry-once-then-error.
///
/// SCOPE this lane: the overlay is `Vec<DraftBlob>` — the `_drafts/` runtime-
/// private files only. The broader PRD §12.6.4 Step-1 surface (the
/// `_skill_candidates.jsonl` candidate lines, `_skill_health.yaml`) is NOT part
/// of this build's overlay; that widening is deferred with the rest of the held
/// AC-22 (MODULE-017 §3.6 (ccc)). (cap-memory already persists candidate lines
/// through its own L6 producer store.)
#[async_trait]
pub trait RuntimePrivateFlush: Send + Sync {
    async fn flush(&self, overlay: &[DraftBlob]) -> Result<(), SkillError>;
}

/// Default production flusher: persists each overlay draft blob verbatim via
/// [`SkillStore::flush_draft`] (no re-validation/sweep — the entries were
/// validated when they entered the overlay).
pub struct StoreDraftFlush {
    skill_store: Arc<Mutex<SkillStore>>,
}

impl StoreDraftFlush {
    pub fn new(skill_store: Arc<Mutex<SkillStore>>) -> Self {
        Self { skill_store }
    }
}

#[async_trait]
impl RuntimePrivateFlush for StoreDraftFlush {
    async fn flush(&self, overlay: &[DraftBlob]) -> Result<(), SkillError> {
        let guard = self.skill_store.lock().await;
        for blob in overlay {
            guard.flush_draft(blob).await?;
        }
        Ok(())
    }
}

/// The turn-end persistence driver. Holds the SAME shared
/// `Arc<tokio::sync::Mutex<SkillStore>>` the coordinator was built with
/// (`with_shared_store`) so leg-(c)'s snapshot/restore see the coordinator's
/// writes.
pub struct SkillTurnPersistenceDriver {
    skill_store: Arc<Mutex<SkillStore>>,
    coordinator: Arc<SkillPersistenceCoordinator>,
    flusher: Arc<dyn RuntimePrivateFlush>,
    /// The turn's accumulated runtime-private writes (leg-b overlay).
    overlay: Vec<DraftBlob>,
    /// Ops rolled back + re-enqueued after a commit failure (leg-c).
    pending: Vec<PendingSkillOp>,
}

impl SkillTurnPersistenceDriver {
    /// Construct over a shared store + its coordinator + a runtime-private
    /// flusher. `skill_store` MUST be the SAME `Arc<Mutex<SkillStore>>` the
    /// coordinator was built with (`with_shared_store`).
    pub fn new(
        skill_store: Arc<Mutex<SkillStore>>,
        coordinator: Arc<SkillPersistenceCoordinator>,
        flusher: Arc<dyn RuntimePrivateFlush>,
    ) -> Self {
        Self {
            skill_store,
            coordinator,
            flusher,
            overlay: Vec::new(),
            pending: Vec::new(),
        }
    }

    /// Stage a runtime-private draft into the turn's overlay (flushed by
    /// [`Self::flush_runtime_private`] at the start of `run_turn_persistence`).
    /// Bounded by [`MAX_OVERLAY`] (adversarial-r1 W4) — a draft past the cap is
    /// dropped with a host-side log rather than growing the overlay unbounded.
    pub fn stage_draft(&mut self, blob: DraftBlob) {
        if self.overlay.len() >= MAX_OVERLAY {
            eprintln!(
                "cap-skills turn-persistence: overlay at MAX_OVERLAY ({MAX_OVERLAY}); dropping staged draft {:?}",
                blob.name
            );
            return;
        }
        self.overlay.push(blob);
    }

    /// The ops awaiting a next-turn retry after a commit failure (leg-c).
    pub fn pending(&self) -> &[PendingSkillOp] {
        &self.pending
    }

    /// Drain ops awaiting a next-turn retry. Used by the live turn runtime after
    /// it has durably mirrored the retry queue into the lease journal.
    pub fn take_pending(&mut self) -> Vec<PendingSkillOp> {
        std::mem::take(&mut self.pending)
    }

    // ─── leg (b) — Step-1 overlay→disk flush with retry-once-then-error ───

    /// Flush the runtime-private overlay to disk. On success the overlay is
    /// cleared. On the FIRST flush failure, retries exactly once; on the second
    /// failure returns an error (the turn must NOT proceed to commit/emit —
    /// PRD §12.6.4 step-1-failure semantics + AC-22 retry-once).
    pub async fn flush_runtime_private(&mut self) -> Result<(), SkillError> {
        if self.overlay.is_empty() {
            return Ok(());
        }
        match self.flusher.flush(&self.overlay).await {
            Ok(()) => {
                self.overlay.clear();
                Ok(())
            }
            Err(first) => {
                eprintln!("cap-skills turn-flush: attempt 1 failed, retrying once: {first}");
                // Retry ONCE.
                match self.flusher.flush(&self.overlay).await {
                    Ok(()) => {
                        self.overlay.clear();
                        Ok(())
                    }
                    Err(second) => {
                        // Fixed safe-class string (SB-22 redaction); rich error
                        // host-side only. Overlay is RETAINED (PRD §12.6.4:
                        // "step 1 失败 → overlay 保留").
                        eprintln!(
                            "cap-skills turn-flush: attempt 2 (retry) failed, error-raising the turn: {second}"
                        );
                        Err(SkillError::InvalidTransition(
                            "runtime-private flush failed after retry".to_string(),
                        ))
                    }
                }
            }
        }
    }

    // ─── leg (c) — commit-failure compensation (activate/rollback) ────────

    /// Run one git-tracked op with failure compensation. Three NON-overlapping
    /// lock spans avoid the coordinator's non-reentrant-mutex deadlock: (1)
    /// snapshot under a scoped lock (DROPPED), (2) invoke the coordinator (it
    /// re-locks the SAME mutex internally), (3) on ANY coordinator error, restore
    /// the live state to the snapshot under a fresh scoped lock — and, for a
    /// retryable commit failure, re-enqueue.
    ///
    /// `Ok` ⇒ the op durably committed, OR a commit-failure was compensated
    /// (rolled back + re-enqueued).
    ///
    /// `Err` ⇒ the op did NOT durably commit. **The caller MUST NOT manually
    /// re-issue the op** (adversarial-r4 F1): an `Err` does NOT imply "not
    /// re-enqueued" — the driver OWNS retry via [`Self::pending`], and several
    /// `Err` paths self-re-enqueue (a commit-failure whose rollback also faulted;
    /// a transient `snapshot_live` read fault). A blind manual retry on top of the
    /// pending drain would DOUBLE-EXECUTE the op (for `Rollback`: two version
    /// bumps + two events). Inspect [`Self::pending`] to see the retry, and drive
    /// ops through [`Self::run_turn_persistence`] (which manages the queue) rather
    /// than re-calling this single-op entry point. The `Err` cases that are NOT
    /// re-enqueued: a genuinely non-retryable coordinator error (e.g.
    /// `DraftNotFound`, rolled back then surfaced as the original error); a
    /// commit-failure that exhausted `MAX_REQUEUE` or could not fit the
    /// `MAX_PENDING` buffer (rolled back, surfaced as an abandon/overflow error);
    /// and a non-retryable error whose rollback ALSO faulted (surfaced as the
    /// RESTORE error with the live state possibly torn). In every `Err` case the
    /// "inspect `pending()`, never blindly re-issue" rule still applies.
    pub async fn commit_op_with_compensation(&mut self, op: TurnSkillOp) -> Result<(), SkillError> {
        match self.process_pending_op(PendingSkillOp::new(op)).await {
            OpOutcome::Done => Ok(()),
            // Torn (commit-failure whose rollback faulted — re-enqueued unless
            // abandoned) and Dropped (a non-retryable error, OR a snapshot fault
            // that re-enqueued, OR a clean abandon) both surface as `Err`; per the
            // contract above, the caller inspects `pending()` rather than retrying.
            OpOutcome::Torn(e) | OpOutcome::Dropped(e) => Err(e),
        }
    }

    /// Re-enqueue an op for a later turn, bounded by [`MAX_PENDING`]
    /// (adversarial-r2). Returns `true` if the op was enqueued, `false` if it was
    /// dropped at the cap (with a host-side log) — so callers can report the
    /// ACTUAL re-enqueued count (adversarial-r3 Info 5b).
    fn push_pending(&mut self, op: PendingSkillOp) -> bool {
        if self.pending.len() >= MAX_PENDING {
            eprintln!(
                "cap-skills turn-persistence: pending at MAX_PENDING ({MAX_PENDING}); dropping re-enqueued op for {:?}",
                op.op.skill_id()
            );
            return false;
        }
        self.pending.push(op);
        true
    }

    async fn process_pending_op(&mut self, pending: PendingSkillOp) -> OpOutcome {
        let skill_id = pending.op.skill_id().to_string();
        let abandoned = pending.requeue_count >= MAX_REQUEUE;

        // Span 1 — snapshot the pre-op LIVE state; guard DROPPED at block end so
        // the snapshot-fault re-enqueue below can take `&mut self`.
        let snapshot_result = {
            let guard = self.skill_store.lock().await;
            guard.snapshot_live(&skill_id).await
        };
        let snapshot = match snapshot_result {
            Ok(s) => s,
            // A snapshot read fault means the op NEVER ran (nothing mutated).
            // Re-enqueue (bounded) so a transient read fault retries rather than
            // silently dropping a durable op (adversarial-r3 Info 4). CAPTURE the
            // push result so the log is accurate at the MAX_PENDING cap, matching
            // the commit-failure + Torn paths (adversarial-r8 Info).
            Err(e) => {
                let reenqueued = !abandoned
                    && self.push_pending(PendingSkillOp {
                        op: pending.op,
                        requeue_count: pending.requeue_count + 1,
                    });
                eprintln!(
                    "cap-skills turn-persistence: snapshot_live failed for {:?} (op {}): {e}",
                    skill_id,
                    if reenqueued {
                        "re-enqueued"
                    } else if abandoned {
                        "abandoned"
                    } else {
                        "dropped at MAX_PENDING"
                    }
                );
                return OpOutcome::Dropped(e);
            }
        };
        let dir_snapshot = if matches!(pending.op, TurnSkillOp::Delete { .. }) {
            match snapshot_skill_dir(self.coordinator.agent_root(), &skill_id).await {
                Ok(s) => Some(s),
                Err(e) => return OpOutcome::Dropped(e),
            }
        } else {
            None
        };

        // Span 2 — invoke the per-op coordinator (re-locks the SAME mutex).
        let Err(e) = self.invoke_coordinator(&pending.op).await else {
            return OpOutcome::Done;
        };

        // Span 3 — ANY coordinator error may have left a PARTIAL mutation: the
        // coordinator op is multi-step non-atomic (e.g. `SkillStore::activate`
        // does `write_active` THEN `delete_draft`; a fault between them leaves the
        // active installed without a commit — adversarial-r3 W2). So roll back to
        // the pre-op snapshot regardless of the error class. CAPTURE the result
        // (do NOT `?`) so the re-enqueue below runs even if the rollback faults
        // (adversarial-r1 W3). `restore_live` writes the draft first (bounding a
        // fault's damage to a torn active half) and retries each half once; a
        // still-torn restore is caught by the durable-lease replay's
        // precondition gate and PARKED (2026-07-03 §3.6 (ccc) closure).
        let restore_result = {
            let guard = self.skill_store.lock().await;
            guard.restore_live(&snapshot).await
        };
        let restore_result = match (restore_result, dir_snapshot.as_ref()) {
            (Ok(()), Some(snapshot)) => {
                restore_skill_dir(self.coordinator.agent_root(), snapshot).await
            }
            (other, _) => other,
        };

        // Only COMMIT failures are retryable (transient git) → re-enqueue
        // (bounded). Other errors (`DraftNotFound`, a storage fault) are NOT
        // retryable → drop after the rollback. CAPTURE whether the re-enqueue
        // actually LANDED — `push_pending` returns `false` at `MAX_PENDING`
        // (adversarial-r5: a cap-full commit-failure that neither committed nor
        // re-enqueued must NOT be reported as `Done` — that would silently lose
        // the retry). The `&&` short-circuits so `push_pending` (which moves
        // `pending.op`) only runs for a retryable, non-abandoned op.
        let retryable = is_commit_failure(&e);
        let reenqueued = retryable
            && !abandoned
            && self.push_pending(PendingSkillOp {
                op: pending.op,
                requeue_count: pending.requeue_count + 1,
            });
        match restore_result {
            // The rollback ITSELF failed → live state may be PARTIAL → the TURN
            // must stop (not run later ops against torn state). Surface `Torn`.
            Err(re) => {
                eprintln!(
                    "cap-skills turn-persistence: restore_live failed mid-compensation for {:?} (live state may be partial; op {}): {re}",
                    skill_id,
                    if reenqueued { "re-enqueued" } else { "not re-enqueued" }
                );
                OpOutcome::Torn(re)
            }
            // Rolled back cleanly AND the commit-failure op actually re-enqueued.
            Ok(()) if reenqueued => OpOutcome::Done,
            // Rolled back cleanly but NOT re-enqueued. For a retryable
            // commit-failure that means it was ABANDONED (past MAX_REQUEUE) OR
            // DROPPED at MAX_PENDING — either way the retry is gone, so surface an
            // error (NOT a silent `Done`). A non-retryable coordinator error
            // surfaces its own `e`. Other ops may still continue (state is clean).
            Ok(()) => {
                let dropped = if retryable {
                    let why = if abandoned {
                        format!("abandoned after {MAX_REQUEUE} commit-failure retries")
                    } else {
                        format!("dropped at MAX_PENDING ({MAX_PENDING}) — pending buffer full")
                    };
                    eprintln!(
                        "cap-skills turn-persistence: commit-failed op for {:?} {why} (live state rolled back)",
                        skill_id
                    );
                    SkillError::InvalidTransition(format!("skill op {why} (state rolled back)"))
                } else {
                    e
                };
                OpOutcome::Dropped(dropped)
            }
        }
    }

    async fn invoke_coordinator(&self, op: &TurnSkillOp) -> Result<(), SkillError> {
        let initiator = Initiator::Agent {
            id: self.coordinator.agent_id().to_string(),
        };
        match op {
            TurnSkillOp::Activate { draft_id, reason } => self
                .coordinator
                .activate_skill_with_persistence(initiator, draft_id, reason)
                .await
                .map(|_| ()),
            TurnSkillOp::Rollback {
                skill_id,
                version,
                reason,
            } => self
                .coordinator
                .rollback_skill_with_persistence(initiator, skill_id, *version, reason)
                .await
                .map(|_| ()),
            TurnSkillOp::Delete { skill_id, reason } => self
                .coordinator
                .delete_skill_with_persistence(initiator, skill_id, reason)
                .await
                .map(|_| ()),
        }
    }

    // ─── turn orchestration ───────────────────────────────────────────────

    /// Run a turn's persistence phase: (1) leg-(b) flush the runtime-private
    /// overlay; then (2) drain any prior-turn re-enqueued ops FOLLOWED BY this
    /// turn's ops, each through leg-(c) commit-with-compensation. A draft-only
    /// turn (no `ops`, no prior pending) flushes the overlay and issues NO commit.
    ///
    /// Err-return contract: an `Err` means at least one step did not fully
    /// succeed — but the driver OWNS retry, so a caller MUST NOT manually
    /// re-issue any op (inspect [`Self::pending`] for what is retained):
    /// - A leg-(b) **flush failure** aborts the turn BEFORE any commit (overlay
    ///   retained for the flush retry); this turn's `ops` are RE-ENQUEUED
    ///   (bounded by `MAX_PENDING` — an overflow drops with a host log, the same
    ///   bound every re-enqueue obeys) rather than silently discarded
    ///   (adversarial-r6), and retry next turn.
    /// - An **op-processing** error (after a successful flush) does NOT mean the
    ///   whole turn failed: ops that durably committed earlier in the same turn
    ///   ARE committed (their events emitted); commit-failed + the aborted-turn's
    ///   remaining ops are re-enqueued and self-retry next turn.
    pub async fn run_turn_persistence(&mut self, ops: Vec<TurnSkillOp>) -> Result<(), SkillError> {
        self.run_pending_turn_persistence(ops.into_iter().map(PendingSkillOp::new).collect())
            .await
    }

    pub async fn run_pending_turn_persistence(
        &mut self,
        ops: Vec<PendingSkillOp>,
    ) -> Result<(), SkillError> {
        // Step 1 (leg b). On failure the overlay is retained for the flush retry
        // and the turn errors BEFORE any commit/emit — but RE-ENQUEUE this turn's
        // ops (bounded) so they are NOT silently lost (the caller moved them in);
        // they retry next turn once the flush recovers (adversarial-r6).
        if let Err(e) = self.flush_runtime_private().await {
            for op in ops {
                self.push_pending(op);
            }
            return Err(e);
        }

        // Drain prior-turn re-enqueued ops first (FIFO across turns), then this
        // turn's new ops. `process_pending_op` may push fresh entries onto
        // `self.pending` for commit-failed ops — those wait for the NEXT turn.
        let mut queue: Vec<PendingSkillOp> = std::mem::take(&mut self.pending);
        queue.extend(ops);

        // Process the queue (plan-eval-r1-audit W2 + adversarial-r2):
        // - `Done`    → continue.
        // - `Dropped` → a non-compensable error on ONE op (or a clean
        //   MAX_REQUEUE abandon); the store is consistent, so log + CONTINUE the
        //   rest of the turn (one bad op must not drop the others). The first
        //   such error is surfaced AFTER the whole queue runs.
        // - `Torn`    → a restore failure left the live state PARTIAL; STOP the
        //   turn (do NOT run later ops against torn state) and re-enqueue the
        //   REMAINING ops so they retry next turn (not lost). Surface the error.
        let mut first_err: Option<SkillError> = None;
        let mut iter = queue.into_iter();
        while let Some(pending) = iter.next() {
            match self.process_pending_op(pending).await {
                OpOutcome::Done => {}
                OpOutcome::Dropped(e) => {
                    eprintln!(
                        "cap-skills turn-persistence: op dropped (non-compensable / abandoned), continuing the turn: {e}"
                    );
                    if first_err.is_none() {
                        first_err = Some(e);
                    }
                }
                OpOutcome::Torn(e) => {
                    let remaining: Vec<PendingSkillOp> = iter.collect();
                    let total = remaining.len();
                    // Count the ACTUAL re-enqueues — push_pending may drop at
                    // MAX_PENDING (adversarial-r3 Info 5b: do not overstate).
                    let mut requeued = 0usize;
                    for op in remaining {
                        if self.push_pending(op) {
                            requeued += 1;
                        }
                    }
                    eprintln!(
                        "cap-skills turn-persistence: restore failure left live state partial; aborting turn, {requeued}/{total} remaining op(s) re-enqueued: {e}"
                    );
                    return Err(e);
                }
            }
        }
        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

/// True iff `e` is one of the coordinator's COMMIT-path failures — the errors
/// leg-(c) compensates because the store was mutated but the commit did NOT
/// land (other store errors, e.g. `DraftNotFound`, propagate uncompensated).
///
/// Both commit-path errors must match (plan-eval-r1-audit W3 fix):
/// - `"git commit failed"` — the git worker reported a `GitError`
///   (`persistence_phase.rs` activate/rollback/delete commit arms).
/// - `"commit worker closed"` — the commit oneshot channel dropped (the worker
///   died) BEFORE replying; the store is mutated but no commit landed — exactly
///   the SH-03/SH-16 store-left-mutated state leg-(c) exists to roll back.
///
/// NOTE: this is an untyped string match coupled to the coordinator's
/// `SkillError::InvalidTransition` payloads (the coordinator is consumed
/// unchanged this lane). A future hardening should promote these to a shared
/// `const` / typed variant so a coordinator reword cannot silently regress
/// leg-(c).
fn is_commit_failure(e: &SkillError) -> bool {
    matches!(
        e,
        SkillError::InvalidTransition(msg)
            if msg.contains("git commit failed") || msg.contains("commit worker closed")
    )
}

#[derive(Clone, Debug)]
struct SkillDirSnapshot {
    skill_id: String,
    files: Vec<(std::path::PathBuf, Vec<u8>)>,
}

async fn snapshot_skill_dir(
    agent_root: &std::path::Path,
    skill_id: &str,
) -> Result<SkillDirSnapshot, SkillError> {
    let root = agent_root.join(".agent").join("skills").join(skill_id);
    let mut files = Vec::new();
    let mut stack = vec![root.clone()];
    while let Some(dir) = stack.pop() {
        let mut entries = match tokio::fs::read_dir(&dir).await {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => break,
            Err(e) => {
                return Err(SkillError::InvalidTransition(format!(
                    "snapshot skill dir read_dir: {e}"
                )))
            }
        };
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|e| SkillError::InvalidTransition(format!("snapshot skill dir next: {e}")))?
        {
            let path = entry.path();
            let file_type = entry
                .file_type()
                .await
                .map_err(|e| SkillError::InvalidTransition(format!("snapshot file_type: {e}")))?;
            if file_type.is_dir() {
                stack.push(path);
            } else if file_type.is_file() {
                let rel = path
                    .strip_prefix(&root)
                    .map_err(|e| SkillError::InvalidTransition(format!("snapshot strip: {e}")))?
                    .to_path_buf();
                let bytes = tokio::fs::read(&path)
                    .await
                    .map_err(|e| SkillError::InvalidTransition(format!("snapshot read: {e}")))?;
                files.push((rel, bytes));
            }
        }
    }
    Ok(SkillDirSnapshot {
        skill_id: skill_id.to_string(),
        files,
    })
}

async fn restore_skill_dir(
    agent_root: &std::path::Path,
    snapshot: &SkillDirSnapshot,
) -> Result<(), SkillError> {
    let root = agent_root
        .join(".agent")
        .join("skills")
        .join(&snapshot.skill_id);
    for (rel, bytes) in &snapshot.files {
        let path = root.join(rel);
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| SkillError::InvalidTransition(format!("restore sidecar dir: {e}")))?;
        }
        tokio::fs::write(&path, bytes)
            .await
            .map_err(|e| SkillError::InvalidTransition(format!("restore sidecar file: {e}")))?;
    }
    Ok(())
}

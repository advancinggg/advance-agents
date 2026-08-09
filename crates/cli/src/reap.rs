//! Turn-end reap observer composite (ADR 2026-07-22 D5, tee slice T3).
//!
//! On turn completion the host synchronously SNAPSHOTS the agent's live LLM
//! streams (fixing the victim set at the boundary) and defers their settlement —
//! upstream abort, billing, terminal mark, and the CONTRACT-234 `Terminal(Reaped)`
//! publish — to tokio's blocking pool (round 24; an earlier sentence here said
//! "synchronously reaps", which the snapshot/defer split made false).
//!
//! There are TWO distinct observer wiring paths and the composite must cover BOTH,
//! or every served child turn silently misses reaping:
//!   (i)  the cli root's `WatchTurnObserver` (`commands/start.rs`), and
//!   (ii) the per-child serve loop's observer (`perchild_daemon.rs`).
//!
//! **Recorded naming imprecision (MODULE-009 §3.6.6).** MODULE-009-AC-22 calls path
//! (ii) "the per-child serve loop's `ProtectedTurnExecutionBoundary` observer". In
//! code the serve loop attaches its observer with `.with_turn_observer(obs)`;
//! `protected_turn_boundary` is an INDEPENDENT optional seam applied only when a
//! dispatcher and a boundary are both present. `turn_observer` is the correct seam,
//! and the criterion's naming is recorded as an imprecision rather than silently
//! repaired here.

use std::sync::Arc;

use advance_scheduler::TurnObserver;

/// Fan-out over several [`TurnObserver`]s, preserving declaration order.
///
/// Order matters: the reap observer runs AFTER the wrapped observers, so a
/// `WatchTurnObserver` still clears its in-flight guard promptly even if a reap has
/// streams to settle.
pub struct CompositeTurnObserver {
    observers: Vec<Arc<dyn TurnObserver>>,
}

impl CompositeTurnObserver {
    pub fn new(observers: Vec<Arc<dyn TurnObserver>>) -> Self {
        Self { observers }
    }
}

impl TurnObserver for CompositeTurnObserver {
    fn on_turn_complete(&self, agent_id: &str) {
        for observer in &self.observers {
            observer.on_turn_complete(agent_id);
        }
    }
}

/// Reaps ONE agent's live streams at its turn boundary, identified by an exact
/// authoritative pair injected at construction.
///
/// Observers receive the COLON-keyed serve id (e.g. `agent:child-7`), while cap-llm's
/// stream registry is keyed by the BARE cap-id — including the root special pair
/// `agent:default` → `default-agent`. Both production composition sites already HOLD
/// that pair when they build the observer (`start.rs`: `DEFAULT_MSG_AGENT_ID` +
/// `cap_agent_id`; `perchild_daemon.rs::on_child_spawned`: `child_colon` +
/// `child_bare`), so the pair is injected verbatim and never re-derived: there is no
/// resolver, no prefix-stripping, and no re-hard-coded constant (ADVERSARIAL §5.2
/// item 5 — the earlier `default_serve_id_resolver` guessed the mapping by string
/// surgery and silently depended on a cross-crate collision guard). An id that does
/// not match the injected serve key EXACTLY reaps NOTHING, so one agent's turn can
/// never settle another agent's streams.
pub struct ReapTurnObserver {
    reaper: Arc<cap_llm::AgentStreamReaper>,
    /// The COLON serve key this observer's serve loop runs under.
    serve_id: String,
    /// The BARE cap-id the stream registry keys this agent's streams by.
    cap_id: String,
    /// At most ONE deferred settle task in flight per OBSERVER INSTANCE (round 24;
    /// wording precised round 25 — the two production sites build one observer per
    /// serve loop, so per agent in production): without this, every boundary
    /// completing while a batch was still settling re-snapshotted the same resident
    /// victims and queued another blocking task — an unbounded, guest-pumpable
    /// fan-out onto the shared blocking pool. ROUND 25: the slot holds the
    /// `JoinHandle` and gates on `is_finished()` instead of a bool flag — a flag
    /// set before a spawn that then panics (worker-thread exhaustion) or whose task
    /// is dropped at pool shutdown stayed `true` FOREVER, silently disabling
    /// turn-end reap for the agent; a cancelled or panicked task's handle reads
    /// finished, so this slot self-heals. The one residual mode: a settle HUNG in
    /// I/O keeps the slot busy indefinitely (indistinguishable from running) and
    /// victims fall to the TTL sweep.
    settle_task: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl ReapTurnObserver {
    /// Build the observer for one agent from its authoritative id pair.
    pub fn for_agent(
        reaper: Arc<cap_llm::AgentStreamReaper>,
        serve_id: impl Into<String>,
        cap_id: impl Into<String>,
    ) -> Self {
        Self {
            reaper,
            serve_id: serve_id.into(),
            cap_id: cap_id.into(),
            settle_task: std::sync::Mutex::new(None),
        }
    }

    /// Reap if `serve_id` matches the injected serve key exactly, returning how many
    /// settlements this call WON (an overlap victim an earlier deferred batch already
    /// settled counts zero — round 24). Fully SYNCHRONOUS (witness API). Shares its guard with
    /// `on_turn_complete` via `snapshot_if_match`, so there is exactly ONE copy of the
    /// mismatch check (round-23 diff finding: the two paths had diverged, leaving the
    /// production guard a duplicated, untested statement).
    pub fn reap_now(&self, serve_id: &str) -> usize {
        match self.snapshot_if_match(serve_id) {
            Some(batch) => batch.settle(),
            None => 0,
        }
    }

    /// The ONE guard + snapshot both entry points share: exact serve-key match, then
    /// a synchronous victim snapshot (single registry-lock acquisition, no I/O).
    /// `None` = nothing to do (mismatch, or no victims).
    fn snapshot_if_match(&self, serve_id: &str) -> Option<cap_llm::ReapBatch> {
        if serve_id != self.serve_id {
            return None;
        }
        let batch = self.reaper.snapshot_reap(&self.cap_id);
        (!batch.is_empty()).then_some(batch)
    }
}

impl TurnObserver for ReapTurnObserver {
    /// ADVERSARIAL §5.2: CONTAIN the reap. `serve` calls `on_turn_complete` with no
    /// `catch_unwind` of its own; without this boundary a panicking reap turns every
    /// later turn boundary into a panic and permanently kills that agent's serve loop.
    /// Reaping is best-effort cleanup: losing it costs a delayed settle (the TTL sweep
    /// still collects the stream), while losing the loop costs the agent entirely.
    ///
    /// ADVERSARIAL §5.2 item 4 (fsync storm), round-23/24 design. `advance start`
    /// runs a CURRENT-THREAD runtime (`commands/start.rs::run`), so anything that
    /// blocks the runtime thread blocks the HTTP listener, every serve loop, and the
    /// TTL sweeper alike — an earlier `block_in_place` arm was dead code there
    /// (round-23 adversarial Critical). The split that works on BOTH flavors:
    /// - SYNCHRONOUS at the boundary: the victim SNAPSHOT (`snapshot_if_match` — one
    ///   registry-lock acquisition, no I/O). Fixing the set here means a stream
    ///   planted by a later turn is never in this turn's batch, so the deferred
    ///   settlement can never kill a legitimately in-flight stream. (That "a later
    ///   turn cannot start first" holds is a property of the CALLERS — `serve` fires
    ///   observers synchronously between turns, and the guest only learns a handle
    ///   after `insert_live` — inspection-verified, recorded in MODULE-009 §3.6.6.)
    /// - DEFERRED off the runtime thread: `ReapBatch::settle` (abort + settle + evict,
    ///   including the per-victim `RunBudget::commit` fsyncs) runs on tokio's blocking
    ///   pool via `spawn_blocking`, which exists on current-thread runtimes too, so
    ///   the runtime thread never executes settlement I/O at a turn boundary. Round 24
    ///   additionally moved the commit CALL outside `Settlement::inner`, so a reader
    ///   racing the deferred settle (the owner task's per-delta accounting, a guest
    ///   poll) blocks only on in-memory work, never on an fsync. Outside any runtime
    ///   the batch settles inline (synchronous witness paths, non-async embedders).
    /// HONEST BOUNDS AND MODES (round 24 removed an unsupported "milliseconds"):
    /// - Promptness: the batch queues on the SHARED blocking pool (skills-import git
    ///   ops, tools validation, DB work also use it), so settlement lag has no hard
    ///   bound short of the 300-second TTL; until the batch runs, its victims are not
    ///   yet aborted (the guest may keep receiving deltas — billed at decode time, so
    ///   accounting is unaffected) and still occupy global-cap slots. A reservation
    ///   released late only makes the next budget check conservative, never generous.
    /// - Fan-out: at most ONE settle task per observer instance is in flight
    ///   (`settle_task` gated on `JoinHandle::is_finished` — round 25; see the field
    ///   doc for the self-healing rationale and the hung-I/O residual); a boundary
    ///   arriving mid-settle skips dispatch and its victims wait for the next
    ///   boundary or the TTL sweep. The skip is silent — it is normal operation.
    /// - Victim count per batch is bounded by the global `MAX_CONCURRENT_STREAMS`
    ///   (256) — the run budget bounds tokens/cost, not stream count.
    /// - Shutdown: a task queued when the blocking pool is shutting down has its
    ///   closure dropped by tokio (`task.shutdown()`), and its handle RESOLVES with
    ///   a cancelled `JoinError` (round 26 corrected an earlier "never-resolving
    ///   handle" — tokio's stale inline comment says that; the shutdown call settles
    ///   it); the batch's entries stay resident and settle as `Abandoned` at
    ///   registry teardown — acceptable only because the process is exiting. The
    ///   resolved handle reads finished, so the slot does not stay latched.
    fn on_turn_complete(&self, agent_id: &str) {
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let Some(batch) = self.snapshot_if_match(agent_id) else {
                return;
            };
            match tokio::runtime::Handle::try_current() {
                Ok(_) => {
                    let mut slot = self.settle_task.lock().unwrap_or_else(|p| p.into_inner());
                    if slot.as_ref().is_some_and(|h| !h.is_finished()) {
                        // A previous batch is still settling: drop this snapshot (its
                        // entries stay resident) and let the next boundary or the TTL
                        // sweep collect them, rather than queueing unbounded work.
                        return;
                    }
                    let agent = agent_id.to_string();
                    // The spawn CALL itself can panic (worker-thread exhaustion);
                    // it is inside the outer catch_unwind and nothing is stored on
                    // that unwind, so the next boundary simply retries (round 25 —
                    // the previous bool flag latched permanently here).
                    let handle = tokio::task::spawn_blocking(move || {
                        let settled =
                            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                batch.settle()
                            }));
                        if settled.is_err() {
                            eprintln!(
                                "reap: deferred stream settlement panicked for {agent}; \
                                 remaining streams settle at TTL"
                            );
                        }
                    });
                    *slot = Some(handle);
                }
                Err(_) => {
                    batch.settle();
                }
            }
        }));
        if outcome.is_err() {
            // The panic is already reported by the default hook; keep the loop alive.
            eprintln!(
                "reap: turn-end stream reap panicked for {agent_id}; \
                 serve loop continues, streams settle at TTL"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    struct Counting(Arc<AtomicUsize>);
    impl TurnObserver for Counting {
        fn on_turn_complete(&self, _agent_id: &str) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct Tagging(&'static str, Arc<Mutex<Vec<&'static str>>>);
    impl TurnObserver for Tagging {
        fn on_turn_complete(&self, _agent_id: &str) {
            self.1.lock().unwrap().push(self.0);
        }
    }

    /// The type rustdoc's ordering claim is load-bearing (the watch observer must
    /// clear its in-flight guard BEFORE a reap settles streams): the composite
    /// must run observers in declaration order. Pins the TYPE guarantee; the two
    /// production vec literals' element order remains inspection-verified.
    #[test]
    fn composite_preserves_declaration_order() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let composite = CompositeTurnObserver::new(vec![
            Arc::new(Tagging("first", log.clone())) as Arc<dyn TurnObserver>,
            Arc::new(Tagging("second", log.clone())),
        ]);
        composite.on_turn_complete("agent:default");
        assert_eq!(*log.lock().unwrap(), vec!["first", "second"]);
    }

    #[test]
    fn composite_fans_out_to_every_observer() {
        let a = Arc::new(AtomicUsize::new(0));
        let b = Arc::new(AtomicUsize::new(0));
        let composite = CompositeTurnObserver::new(vec![
            Arc::new(Counting(a.clone())),
            Arc::new(Counting(b.clone())),
        ]);
        composite.on_turn_complete("agent:default");
        assert_eq!(a.load(Ordering::SeqCst), 1);
        assert_eq!(b.load(Ordering::SeqCst), 1);
    }
}

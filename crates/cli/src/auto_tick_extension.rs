//! Production tick caller for the auto-mode terminal-settle coordinator
//! (Wave-7 Lane B, 2026-06-22) — the SYS-AC-183/185 product seam.
//!
//! [`AutoTickExtension`] is the cli `SchedulerExtension` that gives the
//! Wave-6 Lane C [`AutoTickCoordinator`] a PRODUCTION caller. The coordinator was
//! built correct-at-the-seam (its `settle_completed`/`cancel` read the advancer's
//! terminal decision and THEMSELVES call `complete_run`/`cancel_run_for_agent`)
//! but had zero production driver. `advance start` registers this extension on a
//! [`advance_scheduler::Scheduler`] driven by `run_scheduler_tick_loop`, so on each
//! production tick:
//!
//! 1. the driver's `run_cadence_pass` runs (degrade/halt detection + notify —
//!    MODULE-015, previously never ticked in production); then
//! 2. any pending operator cancels are drained → `coordinator.cancel` (185); then
//! 3. each registered auto session is settled → `coordinator.settle_completed`
//!    (183) — a no-op until the agent records a complete-cycle.
//!
//! **The settle stays product-driven**: the tick calls `settle_completed`/`cancel`;
//! THOSE make the `RunManager` call — never the reverse. The coordinator's
//! TOCTOU / decoupled-state-machine fail-CLOSED `Err`s are LOGGED loudly here and
//! the session is left registered (never silently swallowed, never half-settled).
//!
//! **Dormant until the harvest wires session registration.** This extension's
//! settle pass iterates [`register_session`]-populated sessions, and the cancel
//! pass drains [`request_cancel`]-enqueued requests. Neither has a production
//! caller yet — the `advance auto start` subcommand + the operator-cancel path are
//! harvest install points (MODULE-015 §3.6). So in the live daemon today the
//! registry is empty and the settle/cancel passes are no-ops; the tick loop runs
//! (real wiring), the behavior activates with the harvest.
//!
//! [`register_session`]: AutoTickExtension::register_session
//! [`request_cancel`]: AutoTickExtension::request_cancel

use std::sync::{Arc, Mutex};

use advance_scheduler::{ComponentEvent, SchedulerExtension, SchedulerTick};
use advance_scheduler_auto_loop::DefaultAutoLoopDriver;
use async_trait::async_trait;

use crate::crash_coordinator::{AutoTickCoordinator, TerminalSettle};

/// A registered auto session: the agent id + its RunManager-minted `RunId`
/// string (`run-{uuid}` — the colon-free settle key `settle_completed` needs).
type Session = (String, String);

/// Upper bound on the pending-cancel queue (drained in full every tick; this caps
/// only within-tick growth from a hot caller — adversarial r10 I4).
const MAX_PENDING_CANCELS: usize = 4096;

/// The auto-mode production tick caller. Owns the driver (for the cadence pass)
/// + the terminal-settle coordinator (which owns its OWN clone of the SAME
/// driver + the `RunManager`), plus the session registry and the pending-cancel
/// queue the future harvest auto-start / operator-cancel paths feed.
pub struct AutoTickExtension {
    /// The SAME `Arc<DefaultAutoLoopDriver>` the coordinator was built with —
    /// held here only to run the degrade/halt cadence pass on each tick.
    driver: Arc<DefaultAutoLoopDriver>,
    coordinator: Arc<AutoTickCoordinator>,
    /// Active auto sessions to settle (agent_id → run_id). Empty in production
    /// today: [`Self::register_session`] has test/system-witness callers only; the
    /// future auto-start boot is the named installation point.
    sessions: Mutex<Vec<Session>>,
    /// Pending operator cancels (agent_id, reason) drained per tick. Enqueued by
    /// the harvest's operator-cancel path via [`Self::request_cancel`].
    pending_cancels: Mutex<Vec<(String, String)>>,
}

impl AutoTickExtension {
    /// `driver` MUST be the SAME `Arc<DefaultAutoLoopDriver>` that `coordinator`
    /// was constructed with (so the cadence pass and the settle operate on one
    /// driver state machine).
    pub fn new(driver: Arc<DefaultAutoLoopDriver>, coordinator: Arc<AutoTickCoordinator>) -> Self {
        Self {
            driver,
            coordinator,
            sessions: Mutex::new(Vec::new()),
            pending_cancels: Mutex::new(Vec::new()),
        }
    }

    /// Register an active auto session so the next tick settles it on a recorded
    /// complete-cycle (183). Re-registering the same `agent_id` REPLACES the prior
    /// entry (a reused agent id for a new run). There is no production caller yet;
    /// the future `advance auto start` boot, after `start_auto_session` + run mint,
    /// is the named installation point.
    ///
    /// NB (re-registration hazard): the driver's `complete_cycle_request` is a
    /// never-cleared PEEK — re-registering a reused `agent_id` after a prior
    /// completion requires a fresh driver session / cleared flag, else the first
    /// tick settles the new run against the stale request (MODULE-015 §3.6).
    pub fn register_session(&self, agent_id: impl Into<String>, run_id: impl Into<String>) {
        let agent_id = agent_id.into();
        let run_id = run_id.into();
        let mut s = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        s.retain(|(a, _)| a != &agent_id);
        s.push((agent_id, run_id));
    }

    /// Remove a session from the registry by `run_id` (idempotent). Matches BOTH
    /// `agent_id` AND `run_id` — used on the SETTLE path (completion is run-scoped),
    /// so a CONCURRENT same-agent re-registration for a NEW run (which
    /// `register_session` would have REPLACED this entry with, between the tick's
    /// snapshot and this call) is NOT clobbered by stale terminal cleanup (audit r4
    /// Codex W2: generation-blind deregister). `pub` so an operator path can drop a
    /// specific session.
    pub fn deregister_session(&self, agent_id: &str, run_id: &str) {
        let mut s = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        s.retain(|(a, r)| !(a == agent_id && r == run_id));
    }

    /// Remove ALL sessions for `agent_id` (idempotent). Used on the CANCEL path:
    /// `coordinator.cancel` → `cancel_run_for_agent` is AGENT-scoped (it cancels the
    /// agent's current live run regardless of which `run_id` was registered), so after
    /// a cancel the agent has no live run and every entry for it must go — including a
    /// concurrent same-agent re-registration whose new run the agent-scoped cancel just
    /// cancelled. Deregistering only the snapshotted `run_id` would leave that
    /// wrongly-cancelled new run registered and surface a spurious settle error next
    /// tick (adversarial r10 W3).
    pub fn deregister_agent(&self, agent_id: &str) {
        let mut s = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        s.retain(|(a, _)| a != agent_id);
    }

    /// Enqueue an operator manual-cancel; the next tick drains it →
    /// `coordinator.cancel` → `cancel_run_for_agent` (185). The driver has no
    /// pending-cancel accessor (manual cancel is direct-call only), so this
    /// extension-local queue makes 185 tick-driven + symmetric with 183 WITHOUT
    /// touching the auto-loop crate. Harvest install point caller: the
    /// operator-cancel path (e.g. an `advance auto cancel` subcommand). Bounded
    /// (`MAX_PENDING_CANCELS`): the queue is drained in full every tick, but a hot
    /// caller could grow it within one tick window — over the cap the oldest entries
    /// are dropped (loudly) so a buggy caller can't grow it without bound (adversarial
    /// r10 I4 backpressure).
    pub fn request_cancel(&self, agent_id: impl Into<String>, reason: impl Into<String>) {
        let mut q = self
            .pending_cancels
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if q.len() >= MAX_PENDING_CANCELS {
            let dropped = q.len() - MAX_PENDING_CANCELS + 1;
            q.drain(0..dropped);
            eprintln!(
                "advance: auto-tick pending-cancel queue at cap ({MAX_PENDING_CANCELS}); \
                 dropped {dropped} oldest request(s)"
            );
        }
        q.push((agent_id.into(), reason.into()));
    }

    /// Number of registered sessions (test/introspection).
    pub fn session_count(&self) -> usize {
        self.sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }

    /// The per-tick settle pass — extracted from `on_tick` so the unit tests can
    /// drive it deterministically (and so `on_tick` is a thin wrapper). Runs the
    /// cadence pass, drains cancels (185), then settles each session (183).
    pub async fn run_settle_pass(&self, now_ms: u64) {
        // (a) degrade/halt cadence over the driver's live auto sessions. This runs
        //     FIRST (preserving the driver's own on_tick order) so a safety-valve
        //     breach Halts before a same-tick complete-cycle could Complete it — the
        //     safety-first ordering. The degrade/halt NOTIFY egress it awaits is
        //     best-effort + bounded (cap-http DEFAULT_TIMEOUT 30s / 10s connect), and
        //     daemon shutdown is unaffected regardless (the tick loop races
        //     dispatch_tick against cancel) — so a slow notify only transiently
        //     delays this tick's settle, never blocks shutdown (audit r4 Codex W3,
        //     arbitrated: bounded best-effort; reorder rejected to keep Halt > Complete).
        self.driver.run_cadence_pass(now_ms).await;

        // (b) drain pending operator cancels and settle each. `coordinator.cancel`
        //     → `cancel_run_for_agent` is AGENT-scoped (cancels the agent's CURRENT
        //     live run, whatever run_id), so on a successful / idempotent-terminal
        //     cancel we deregister the AGENT (all its sessions) — the agent has no live
        //     run left, and this correctly drops a concurrent same-agent re-registration
        //     whose new run the agent-scoped cancel just cancelled (deregistering only
        //     the snapshotted run_id would leave that wrongly-cancelled run registered →
        //     a spurious settle error next tick; adversarial r10 W3). This also keeps a
        //     same-tick complete_cycle_request from re-polling a now-Cancelled run.
        let cancels: Vec<(String, String)> = {
            let mut q = self
                .pending_cancels
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            std::mem::take(&mut *q)
        };
        for (agent_id, reason) in cancels {
            match self.coordinator.cancel(&agent_id, &reason) {
                Ok(()) => self.deregister_agent(&agent_id),
                Err(e) => eprintln!(
                    "advance: auto-tick cancel failed for {agent_id:?}: {e} (session left registered)"
                ),
            }
        }

        // (c) snapshot the session list UNDER the lock, drop the guard, THEN
        //     `.await` the settle (holding a std Mutex guard across `.await` is a
        //     !Send compile error under SchedulerExtension: Send + Sync).
        let sessions: Vec<Session> = {
            self.sessions
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
        };
        for (agent_id, run_id) in sessions {
            match self.coordinator.settle_completed(&agent_id, &run_id).await {
                // Terminal — the run settled (or a prior settle already did);
                // stop re-polling the never-cleared complete_cycle_request PEEK.
                Ok(TerminalSettle::Completed) | Ok(TerminalSettle::AlreadySettled) => {
                    self.deregister_session(&agent_id, &run_id)
                }
                // No complete-cycle recorded yet → keep registered for a later tick.
                Ok(TerminalSettle::Continued) => {}
                // Fail-CLOSED loud: never silently swallow, never half-settle.
                // Leave registered for a later retry / operator action.
                Err(e) => eprintln!(
                    "advance: auto-tick settle failed for {agent_id:?} (run {run_id:?}): {e} \
                     (session left registered)"
                ),
            }
        }
    }
}

#[async_trait]
impl SchedulerExtension for AutoTickExtension {
    fn name(&self) -> &str {
        "auto-tick"
    }

    async fn on_tick(&self, tick: SchedulerTick) {
        self.run_settle_pass(tick.now_ms).await;
    }

    async fn on_component_event(&self, _event: ComponentEvent) {
        // The auto terminal-settle path is tick-driven, not component-event-driven.
    }
}

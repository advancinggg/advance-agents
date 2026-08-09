//! `AwaitSession` struct + `SessionStatus` enum + lifecycle primitives.
//!
//! Slice m007-A scope: foundation primitives only. `Paused` status is a
//! later slice (per MODULE-007 §1.3.1). `created_at` / `last_activity` use
//! [`std::time::Instant`] — monotonic clock, correct for idle-timer
//! arithmetic. AwaitSession is in-memory only per MODULE-007 §2.11 (no
//! serialization needed).

use std::time::Instant;

use advance_shared_types::await_session::{
    AwaitMode, AwaitOptions, AwaitRequest, AwaitSessionStatus, ReplyResult, ReplyStatus, SessionId,
};

/// Session lifecycle status. Slice-A subset of MODULE-007 §1.3.1's
/// 5-variant enum — `Paused` is a later slice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionStatus {
    Open,
    Completed,
    TimedOut,
    Cancelled,
}

/// Reasons for `record_reply` to refuse a write. Surfaced as
/// `OrchestrationError::InvalidRequest` strings at the manager boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordReplyError {
    /// Slot index is out of bounds.
    OutOfBounds,
    /// Slot already has a recorded reply — silent overwrite is forbidden.
    AlreadyRecorded,
}

/// In-memory await-session. Lost on crash per MODULE-007 §2.11.
///
/// **Construction invariant** (AC-02 / T02a): `created_at == last_activity`
/// after [`AwaitSession::new`]. Both fields are assigned from a single
/// `let now = Instant::now()` capture inside the constructor; two separate
/// `Instant::now()` calls would produce different timestamps and break the
/// invariant.
#[derive(Clone, Debug)]
pub struct AwaitSession {
    pub id: SessionId,
    /// Slice-A always `None`; slice-C AC-16 wires nested session linkage via
    /// `RunStateSync::current_session(caller_run_id)`.
    pub parent_session: Option<SessionId>,
    /// Caller agent id (bare name, e.g. `"researcher"`; dispatch prefixes to
    /// `agent:researcher` when building the `Message.from`).
    pub agent_id: String,
    /// Caller's run id, captured at admission for the session-stable
    /// `orchestration.*` event envelope (Wave-15 Lane A — `await_idle_timeout`).
    /// `None` when the run id is unavailable (e.g. the trait `start()` path
    /// delegates `caller_run_id=None`). Set by the manager post-construction
    /// (mirrors `parent_session`); `new()` defaults it `None`.
    pub caller_run_id: Option<String>,
    pub options: AwaitOptions,
    pub expected: Vec<AwaitRequest>,
    /// Per-slot reply result; `None` until `record_reply` is called.
    pub received: Vec<Option<ReplyResult>>,
    pub status: SessionStatus,
    pub created_at: Instant,
    pub last_activity: Instant,
}

impl AwaitSession {
    /// Construct a new Open session. Captures `Instant::now()` once and
    /// assigns both `created_at` and `last_activity` from it so T02a's
    /// equality assertion is exact.
    pub fn new(
        id: SessionId,
        agent_id: String,
        options: AwaitOptions,
        expected: Vec<AwaitRequest>,
    ) -> Self {
        let now = Instant::now();
        let received = vec![None; expected.len()];
        Self {
            id,
            parent_session: None,
            agent_id,
            caller_run_id: None,
            options,
            expected,
            received,
            status: SessionStatus::Open,
            created_at: now,
            last_activity: now,
        }
    }

    /// Transition `status: Open → Cancelled`. Idempotent — second call leaves
    /// status at `Cancelled` (T02b).
    pub fn cancel(&mut self, _reason: &str) {
        self.status = SessionStatus::Cancelled;
    }

    /// Record a per-slot [`ReplyResult`]. Returns `Ok(())` on success or an
    /// enum describing why the write was refused.
    ///
    /// **Adversarial round 1 W4 fix**: OOB slot indices now surface
    /// `RecordReplyError::OutOfBounds` instead of being silently dropped.
    ///
    /// **Adversarial round 2 W4 fix**: duplicate writes to the same slot now
    /// surface `RecordReplyError::AlreadyRecorded`. Previously the second
    /// `on_reply(slot=N, ...)` for the same slot silently overwrote the
    /// first — allowing an attacker who could call `on_reply` to tamper
    /// with already-recorded replies before completion.
    pub fn record_reply(&mut self, slot: u32, reply: ReplyResult) -> Result<(), RecordReplyError> {
        let idx = slot as usize;
        if idx >= self.received.len() {
            return Err(RecordReplyError::OutOfBounds);
        }
        if self.received[idx].is_some() {
            return Err(RecordReplyError::AlreadyRecorded);
        }
        self.received[idx] = Some(reply);
        Ok(())
    }

    /// Mode-aware completion check.
    /// - `AllOf`: every slot has a `Some` ReplyResult.
    /// - `AnyOf`: at least one slot has a `Some` ReplyResult with
    ///   `status == ReplyStatus::Completed` (first-wins per §2.3:442).
    pub fn is_complete(&self) -> bool {
        match self.options.mode {
            AwaitMode::AllOf => self.received.iter().all(Option::is_some),
            AwaitMode::AnyOf => self.received.iter().any(|r| {
                matches!(
                    r.as_ref().map(|rr| &rr.status),
                    Some(ReplyStatus::Completed)
                )
            }),
        }
    }

    /// Build the `Vec<ReplyResult>` for an [`AwaitSessionStatus::Completed`]
    /// resolution.
    ///
    /// - `(AnyOf, keep_losers=false)` — loser-omission per §2.3:441: only the
    ///   winner (a `ReplyStatus::Completed` slot) is returned; other slots omitted.
    /// - `(AnyOf, keep_losers=true)` — **keep losers WITH detach materialization**
    ///   (Wave-24 / AC-13 rule 2 / PRD §9.2 rule 1 observable half): recorded slots (winner +
    ///   already-terminal `Failed`/`TimedOut` losers) are returned verbatim, and
    ///   each still-pending (`None`) non-winner slot is MATERIALIZED as a
    ///   `detached` loser (`ReplyStatus::Cancelled` + `task_id` substitute-or-clear;
    ///   see `materialize_detached_loser`) instead of being
    ///   silently dropped. `now` timestamps the materialized losers' `received_at`.
    /// - `AllOf` (either `keep_losers`) — every recorded slot verbatim. Detach
    ///   materialization is a **keep-losers-only** concept, so `AllOf` keeps the
    ///   safe drop-`None` `filter_map` (never fabricates a `detached` loser).
    ///   `is_complete` for `AllOf` requires all-`Some` anyway, so no `None`
    ///   reaches here on any live path.
    pub fn snapshot_replies(&self, now: chrono::DateTime<chrono::Utc>) -> Vec<ReplyResult> {
        match (self.options.mode, self.options.keep_losers) {
            (AwaitMode::AnyOf, false) => self
                .received
                .iter()
                .filter_map(|r| r.as_ref())
                .filter(|rr| matches!(rr.status, ReplyStatus::Completed))
                .cloned()
                .collect(),
            // Keep-losers detach materialization (Wave-24) — ONLY this arm.
            (AwaitMode::AnyOf, true) => self
                .received
                .iter()
                .enumerate()
                .map(|(idx, slot)| match slot {
                    Some(rr) => rr.clone(),
                    None => crate::detach::materialize_detached_loser(
                        self.expected.get(idx),
                        idx as u32,
                        now,
                    ),
                })
                .collect(),
            // AllOf (either keep_losers): recorded slots verbatim; `None` dropped
            // (never materialized — detach is a keep-losers-only concept). `now`
            // is unused here (materialization only fires in the AnyOf+true arm).
            _ => self
                .received
                .iter()
                .filter_map(|r| r.as_ref().cloned())
                .collect(),
        }
    }

    /// Build the `Vec<ReplyResult>` for partial-timeout / failed-dispatch /
    /// cancelled resolutions. Includes every slot (Some) regardless of
    /// status (no loser-omission filter — the caller wants to see what
    /// happened to each slot).
    pub fn snapshot_replies_all(&self) -> Vec<ReplyResult> {
        self.received
            .iter()
            .filter_map(|r| r.as_ref().cloned())
            .collect()
    }

    /// Resolve the per-slot status for unfilled slots according to
    /// `TimeoutPolicy::ReturnPartial`: completed slots stay as-is, unfilled
    /// slots become `TimedOut`. For `TimeoutPolicy::Fail` the manager
    /// short-circuits to `Err(IdleTimeoutExceeded)` and does not call this.
    pub fn fill_unresolved_as_timed_out(&mut self, now: chrono::DateTime<chrono::Utc>) {
        for (idx, slot) in self.received.iter_mut().enumerate() {
            if slot.is_none() {
                let target_source = match self.expected.get(idx) {
                    Some(AwaitRequest::AgentRequest(req)) => req.target.clone(),
                    Some(AwaitRequest::ComponentFinished(req)) => {
                        format!("component:{}", req.component_id)
                    }
                    None => String::new(),
                };
                *slot = Some(ReplyResult {
                    slot: idx as u32,
                    source: target_source,
                    payload: Vec::new(),
                    status: ReplyStatus::TimedOut,
                    received_at: now,
                    task_id: None, // timeout loser (AC-13 rule 2 / PRD rule 1 task-id half deferred here)
                });
            }
        }
        self.status = SessionStatus::TimedOut;
    }

    /// Map `SessionStatus → AwaitSessionStatus` for AwaitResult construction.
    /// Slice-A does not use `SessionStatus::Paused`.
    pub fn projected_status(&self) -> AwaitSessionStatus {
        match self.status {
            SessionStatus::Open | SessionStatus::Completed => AwaitSessionStatus::Completed,
            SessionStatus::TimedOut => AwaitSessionStatus::PartialTimeout,
            SessionStatus::Cancelled => AwaitSessionStatus::Cancelled,
        }
    }
}

//! Backbone Step 4b (2026-06-08) — `RunSuspendSink`: the reply-tracker-LOCAL
//! dependency-inversion PORT that lets the `await-replies` host-fn drive the
//! MODULE-008 Run lifecycle (suspend on await / resume on reply-completion)
//! WITHOUT this crate taking a compile-time dependency on `advance-run-manager`.
//!
//! This mirrors the existing AC-16 [`crate::session_context::SessionContextProvider`]
//! inversion (a reply-tracker-local trait whose production impl is backed by M008
//! at the composition root). Verified dependency topology: neither
//! `advance-reply-tracker` nor `advance-run-manager` depends on the other, so a
//! shared-types trait would be the only alternative home — and that would make
//! this a CONTRACT with cross-module impact ceremony. A crate-local port keeps
//! `modified_contracts = []` and adds zero new compile deps.
//!
//! The ADAPTER (`RunManagerSuspendSink`, impl over `Arc<RunManager>`) lives at a
//! composition root that depends on both crates. This slice provides it TEST-SIDE
//! in the `system-acceptance` harness (Track-H real-wiring); the production
//! `advance start` daemon wiring is the named R9 follow-up (see MODULE-007 §3.6).

use advance_shared_types::await_session::SessionId;

/// Port the `AwaitRepliesHandler` calls to drive the M008 Run's suspend/resume
/// lifecycle around an `await-replies` park. The production adapter delegates to
/// `RunManager::suspend_run` / `RunManager::resume_run_if_suspended` (the atomic
/// Suspended-only await-completion resume).
///
/// # Invocation contract
///
/// - [`Self::on_await_start`] is called at the GENUINE park point (the handler
///   wires it as the `on_park` hook of
///   [`crate::manager::AwaitSessionManagerImpl::start_with_run_and_session`], so
///   it fires ONLY when the await truly parks — never on a synchronous
///   fast-path resolution). It transitions the Run `Active → Suspended`
///   (`root_await = Some(session_id)`) and emits `run.suspended`. It returns
///   `true` iff the suspend succeeded; the handler stores this and uses it to
///   decide whether a later resume is warranted.
/// - [`Self::on_await_resolve`] is called by the handler AFTER the await returns
///   — when (a) `on_await_start` reported `true` AND (b) the await did NOT return
///   `Err(SessionClosed)`. The await resolves as `Ok` (replies completed / a
///   `ReturnPartial` timeout) OR `Err(IdleTimeoutExceeded)` (a `Fail`-policy idle
///   timeout) OR `Err(SessionClosed)` (pause/cancel close): for the first two the
///   await is OVER, so the Run must leave `Suspended` (else a `Fail`-policy
///   timeout would strand it suspended forever); only `Err(SessionClosed)` is
///   skipped (pause/cancel owns the `Suspended → Paused/Cancelled` transition).
///   It transitions the Run `Suspended → Active` (clears `root_await`) and emits
///   `run.resumed` (reason `await_complete`). The impl MUST resume **atomically
///   and only from `Suspended`** (e.g. `RunManager::resume_run_if_suspended`, NOT
///   the operator `resume_run` which also accepts `Paused → Active`): a child
///   reply resolving `Ok` can race a concurrent operator `pause_run`/`cancel_run`,
///   and a non-atomic Suspended-only resume would clobber the operator's
///   Paused/Cancelled transition back to Active. If the Run already left
///   `Suspended`, this is a no-op.
pub trait RunSuspendSink: Send + Sync {
    /// Suspend the run identified by `run_id` at the await on `session_id`.
    /// Returns `true` iff the run is now `Suspended` (suspend succeeded).
    fn on_await_start(&self, run_id: &str, session_id: &SessionId) -> bool;

    /// Resume the run identified by `run_id` after a genuine reply-completion.
    /// Best-effort (no-op if the run already left `Suspended`).
    fn on_await_resolve(&self, run_id: &str, session_id: &SessionId);
}

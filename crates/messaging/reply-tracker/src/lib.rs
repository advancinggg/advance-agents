//! MODULE-007 await-orchestration (slices m007-A 2026-05-18 + m007-B
//! 2026-05-19 + m007-C 2026-05-21).
//!
//! Ships the [`AwaitSessionManager`] trait (CONTRACT-060) with
//! [`AwaitSessionManagerImpl`], the [`AwaitSession`] lifecycle
//! (Open/Cancelled), per-slot dispatch via
//! [`advance_messaging::MailboxDispatcher`] (CONTRACT-051), and
//! admission/dispatch error triage (slice A); plus **AC-09 deadlock
//! detection** (a
//! reply-tracker-local `parent_of` ancestry walk over a
//! [`advance_shared_types::agent_tree::AgentTreeSnapshot`] snapshot —
//! `is_ancestor_of` is absent from CONTRACT-040) and the **AC-10
//! per-session idle monitor** with a sync-`on_heartbeat` idle-clock reset
//! (slice B). [`CapabilityConfig`] adds 5 in-boundary `await-replies`
//! capability admission knobs (REQ-092: 4 in slice B + `max_depth` in
//! slice C completing AC-18). **Slice C** adds [`SessionContextProvider`]
//! (run-scoped `caller_run_id: &str` seam over M008 RunStateSync) +
//! `compute_depth_in_map` parent-chain walk + non-trait `start_with_run`
//! entry point for nested-tree linkage (AC-16).
//!
//! **Wave-20 Lane `messagingabi` (2026-06-27) — SUPERSEDES the "3 of 7" /
//! "remaining 4 out-of-boundary" statements throughout this module doc:** the 4
//! remaining `orchestration.*` events (`await_started`, `await_satisfied`,
//! `await_session_closed`, `reply_late`) are NOW built in-boundary (emit sites in
//! [`manager`], builders in [`events`]), so ALL 7 events emit; AC-17 flips
//! `untested→passed` at SUMMARY. The historical 3-of-7 prose below is retained
//! for lineage but is no longer the current state.
//!
//! **Orchestration.* event emission (historical lineage).** Slice E / Wave-15
//! landed the first 3 of 7 in-boundary emits. **[SUPERSEDED Wave-20 messagingabi]**
//! the remaining 4 (`await_started`, `await_satisfied`, `await_session_closed`,
//! `reply_late`) now also emit in-boundary; AC-17 flipped `passed`. Direct-orphan
//! `reply_late` remains AC-17 event-mechanism only (not production AC-13 rule 4
//! for child `send`). See MODULE-007 §3.4 AC-17 / §3.6 / §3.7.
//!
//! **Slice E** adds host-fn handler colocation ([`host_fn`]) for the WIT
//! `agent-messaging::await-replies` + `heartbeat` methods, satisfying
//! MODULE-006-AC-12 delegation in-boundary (handler placed in reply-tracker
//! per MODULE-007 §3.6 ADR-via-prose entry — parallel-safety + cap-*
//! precedent). The slice-E `await_progress` emit is INTENTIONAL SCAFFOLDING
//! for AC-12 (whose criterion specifically requires it). **[SUPERSEDED Wave-20]**
//! AC-17's full 7-event taxonomy later closed in-boundary; AC-17 is `passed`.
//! Orphan `reply_late` is AC-17-only, not production AC-13 rule 4.
//!
//! **Landed in slice C** (MODULE-007 §1.4 + §3.7):
//! - AC-16: nested AwaitSession tree (`parent_session` linkage) via the
//!   local [`SessionContextProvider`] trait abstraction (slice-D wiring
//!   backs with M008 RunStateSync). Non-trait `start_with_run(caller,
//!   caller_run_id, ...)` carries the run_id from future host-fn handler;
//!   CONTRACT-060::start surface stays byte-identical.
//! - AC-18: full 5-knob capability config — `max_depth` admission gate
//!   added via parent-chain walk under `sessions.read()`.
//!
//! **Status (current)**:
//! - AC-08 / AC-14 (fiber suspend/resume): **passed** Wave-16 harvest (typed
//!   `call_async` path). Not re-opened by keeplosers-2.
//! - AC-17: full `orchestration.*` taxonomy — **Wave-20 closed**; all 7 emit
//!   in-boundary; AC-17 `passed`. Direct-orphan `reply_late` is AC-17
//!   event-mechanism evidence only (not production AC-13 rule 4 for child
//!   `send`).
//! - AC-13: keep-losers=true detach — rule (1) winner task-id in-boundary
//!   (Wave-20/23); Wave-24 built AC-13 rule 2 / PRD rule 1 **observable** half
//!   via [`detach`]. Full 4-rule conjunction still `untested`: clearing
//!   writer/locus, cost DATA, and production rule 4 remain future work.
//! - AC-11 / AC-20 / AC-21: M006-adjacent host-fn surfaces (see MODULE-007 §3.4).
//!
//! **Still open / future work**:
//! - Faithful sync shadow-index for `exists`/`walk_tree` (production
//!   `AwaitSessionManagerRef` **lands** `close` faithfully + best-effort
//!   `exists`/`walk_tree` via `try_read`; wired via `with_await_session_ref`).
//!   AC-16 landed via [`SessionContextProvider`].
//!
//! **Landed in slice G** (Wave-19 Lane 3, 2026-06-26; MODULE-007 §3.7):
//! - AC-19 (REQ-270): the §2.3 component-finished resolution path —
//!   [`component_resolution::ComponentResolutionSink`] (impl of the shared-types
//!   [`advance_shared_types::RunCompletionSink`] / CONTRACT-184, fired by
//!   MODULE-008 `complete_run` on `run.completed`) + the inherent
//!   [`manager::AwaitSessionManagerImpl::resolve_component_finished`] mark the
//!   matching `ComponentFinished` slot `Completed` STATUS-ONLY (EMPTY payload —
//!   the caller reads `output-dir/result.bin` per §2.3). REQ-270 held `Partial`
//!   (production daemon sink wiring is the Wave-20 follow-up).
//!
//! See MODULE-007 §3.6 Known Gaps for the AC-02 component-type:task
//! admission restriction deferral (once the M005 ComponentRegistry surface
//! is available) and the slice-C transient-dangling-parent residual.

#![forbid(unsafe_code)]

pub mod await_session_ref;
pub mod component_resolution;
pub mod deadlock;
pub mod detach;
pub mod dispatch;
pub mod error;
pub mod events;
pub mod host_fn;
pub mod idle;
pub mod manager;
pub mod run_sink;
pub mod session;
pub mod session_context;
pub mod turn_attribution;

pub use await_session_ref::AwaitSessionManagerRef;
pub use component_resolution::ComponentResolutionSink;
pub use error::{AdmissionError, DispatchSlotError, MAX_REASON_LEN};
pub use events::{
    build_await_progress_event, build_await_satisfied_event, build_await_session_closed_event,
    build_await_started_event, build_deadlock_rejected_event, build_idle_timeout_event,
    build_reply_late_event, AWAIT_IDLE_TIMEOUT, AWAIT_PROGRESS, AWAIT_SATISFIED,
    AWAIT_SESSION_CLOSED, AWAIT_STARTED, DEADLOCK_REJECTED, REPLY_LATE,
};
pub use host_fn::{
    register_reply_tracker_host_fns, register_reply_tracker_host_fns_with_suspend_sink,
    register_send_host_fn, register_send_host_fn_with_turn_reply_routing, AwaitRepliesHandler,
    HeartbeatHandler, SendHandler,
};
pub use manager::{
    AwaitSessionManager, AwaitSessionManagerImpl, CapabilityConfig, ManagerOptions, MAX_FANOUT,
    MAX_IDLE_TIMEOUT_DEFAULT_SEC, MAX_IDLE_TIMEOUT_SECS_CAP, MAX_INFLIGHT, MAX_OPAQUE_ID_BYTES,
    MAX_PAYLOAD_BYTES, MAX_SESSIONS_GLOBAL,
};
pub use run_sink::RunSuspendSink;
pub use session::{AwaitSession, RecordReplyError, SessionStatus};
pub use session_context::SessionContextProvider;
pub use turn_attribution::{
    canonical_turn_identity_facades, compose_turn_attribution_facades, TurnAttributionFacades,
};

//! `agent-run` WIT host-side dispatcher per MODULE-008 §2.3 + PRD §9.5.1.
//!
//! Slice C — closes AC-12's Rust-side WIT surface half. `AgentRunWitImpl`
//! wraps an `Arc<RunManager>` and exposes the 7 WIT methods (ensure-run /
//! complete-round / complete-run / pause-run / resume-run / cancel-run /
//! run-status) with WIT-shape argument and return types.
//!
//! HostRegistry / Val-encoding wiring (the
//! `LinkerInstance::func_new_async` registration that wires this struct's
//! methods into the wasmtime `ComponentLinker`) is deferred to a future
//! MODULE-001 / runtime integration slice — matches the MODULE-009
//! cap-llm `host_fn.rs` pattern (the WIT declaration and host_fn wiring
//! slices were split there too). See MODULE-008 §3.6 known-gap.

use std::sync::Arc;

use advance_shared_types::run::{RoundDecision, RoundResult};

use crate::run::{RunConfig, RunId, RunManager};
use crate::wit_types::{WitRunConfig, WitRunError, WitRunState};

/// 7-method WIT surface for `agent-run`. Wraps an `Arc<RunManager>`.
///
/// **Caller-agent context**: the WIT `agent-run` interface (PRD §9.5.1) does
/// NOT carry `controller-agent` as a method argument — the WASM caller's
/// agent identity is resolved by the host-fn dispatcher from
/// `HostCallContext::caller_agent_id` at the LinkerInstance bind time. For
/// this slice (Rust-level surface only; host-fn wiring deferred per §3.6),
/// `AgentRunWitImpl::new_with_caller_agent` accepts the caller agent at
/// construction time so the Rust-level integration tests can exercise the
/// surface without a real wasmtime context.
pub struct AgentRunWitImpl {
    mgr: Arc<RunManager>,
    /// Host-side context — represents the calling agent's identity. The
    /// future host_fn wiring extracts this from `HostCallContext::caller_agent_id`
    /// at each call site; for tests / direct use we set it once at
    /// construction.
    caller_agent: String,
}

impl AgentRunWitImpl {
    /// Construct with caller_agent context. The caller_agent identity is
    /// used for two security-critical purposes: (1) it becomes the
    /// `controller_agent` of new Runs created via `ensure_run`; (2) every
    /// method that operates on an existing `run_id` enforces ownership —
    /// the call is rejected with `WitRunError::PermissionDenied` if
    /// `run.controller_agent != caller_agent`. This defends against the
    /// "guest with stolen run_id controls another agent's run" attack
    /// surface (closes audit R1 adversarial Critical).
    pub fn new_with_caller_agent(mgr: Arc<RunManager>, caller_agent: impl Into<String>) -> Self {
        Self {
            mgr,
            caller_agent: caller_agent.into(),
        }
    }

    /// Test-only constructor — defaults caller_agent to `"root"`. Compiled
    /// only when the `__test-util` feature is enabled so production code
    /// must always provide an explicit caller_agent identity via
    /// `new_with_caller_agent`. Closes the audit R1 adversarial Info
    /// finding about implicit root elevation.
    #[cfg(feature = "__test-util")]
    pub fn new(mgr: Arc<RunManager>) -> Self {
        Self::new_with_caller_agent(mgr, "root")
    }

    /// Slice C — enforce caller ownership of `run_id` for all mutating
    /// methods. Returns Err(NotFound) if the run doesn't exist (don't leak
    /// presence of foreign runs); returns Err(PermissionDenied) if the run
    /// exists but is owned by a different controller_agent.
    fn assert_caller_owns(&self, run_id: &str) -> Result<(), WitRunError> {
        let owner = self.mgr.controller_agent_of(run_id);
        match owner {
            None => Err(WitRunError::NotFound(run_id.to_string())),
            Some(controller) if controller == self.caller_agent => Ok(()),
            Some(_) => {
                // Return NotFound (NOT PermissionDenied) — don't leak that
                // the run exists under another caller. The presence-leak
                // through PermissionDenied is itself an info-disclosure
                // vector.
                Err(WitRunError::NotFound(run_id.to_string()))
            }
        }
    }

    /// `ensure-run: func(task-id: string, config: run-config) -> result<run-id, run-error>`.
    /// The 2-arg WIT signature: `controller_agent` is NOT a parameter; it
    /// comes from the host-side caller-agent context (see struct rustdoc).
    ///
    /// **Security gates** (close adversarial R2 Critical findings):
    /// 1. **Auto-mode task-id ownership**: if `task_id` starts with `auto:`,
    ///    the suffix MUST match `caller_agent`. Per REQ-069, an Auto Run
    ///    `auto:foo` is the autonomous run of agent `foo`; allowing any
    ///    caller to instantiate `auto:victim` would let a guest hijack
    ///    another agent's auto-mode dispatch path (skipping round advance
    ///    + event emit + pending-settle in M008's complete_round).
    /// 2. **Task-id cross-agent collision**: if a live run for `task_id`
    ///    already exists with a DIFFERENT `controller_agent`, return
    ///    `Err(PermissionDenied("task-owned-by-different-agent"))`. The
    ///    underlying `RunManager::ensure_run` is the idempotent
    ///    deduplication site but is agent-blind by design; the WIT layer
    ///    is where authz lives.
    pub fn ensure_run(&self, task_id: String, config: WitRunConfig) -> Result<String, WitRunError> {
        // Gate 1: auto-mode task-id must match caller_agent.
        if let Some(agent_in_task) = task_id.strip_prefix("auto:") {
            if agent_in_task != self.caller_agent {
                return Err(WitRunError::PermissionDenied(format!(
                    "auto-mode-task-id-must-match-caller: task_id={:?}, caller={:?}",
                    task_id, self.caller_agent
                )));
            }
        }
        // Gate 2: cross-agent task-id collision via the strict variant
        // that performs the cross-agent authz check inside the same
        // store.write() critical section as the create/reuse decision
        // (closes adversarial R4 TOCTOU: prior code did a pre-check via
        // `task_owner_if_live` outside the lock that could be raced by
        // concurrent callers).
        let cfg: RunConfig = config.into();
        self.mgr
            .ensure_run_strict(&task_id, &self.caller_agent, cfg)
            .map(|rid| rid.to_string())
            .map_err(WitRunError::from)
    }

    /// `complete-round: func(run-id, result: round-result) -> result<round-decision, run-error>`.
    pub async fn complete_round(
        &self,
        run_id: String,
        result: RoundResult,
    ) -> Result<RoundDecision, WitRunError> {
        let rid = RunId::from_string(run_id)
            .map_err(|e| WitRunError::PermissionDenied(format!("invalid-run-id: {e}")))?;
        self.assert_caller_owns(rid.as_ref())?;
        self.mgr
            .complete_round(&rid, result)
            .await
            .map_err(WitRunError::from)
    }

    /// `complete-run: func(run-id, outcome: string) -> result<_, run-error>`.
    pub fn complete_run(&self, run_id: String, outcome: String) -> Result<(), WitRunError> {
        let rid = RunId::from_string(run_id)
            .map_err(|e| WitRunError::PermissionDenied(format!("invalid-run-id: {e}")))?;
        self.assert_caller_owns(rid.as_ref())?;
        self.mgr
            .complete_run(&rid, outcome)
            .map_err(WitRunError::from)
    }

    /// `pause-run: func(run-id, reason: option<string>) -> result<_, run-error>`.
    /// When `reason == None`, defaults to empty string `""` per the WIT
    /// `option<string>` shape — the empty reason flows through to
    /// `Run.pause_pending` via the existing branch-(b) path.
    pub async fn pause_run(
        &self,
        run_id: String,
        reason: Option<String>,
    ) -> Result<(), WitRunError> {
        let rid = RunId::from_string(run_id)
            .map_err(|e| WitRunError::PermissionDenied(format!("invalid-run-id: {e}")))?;
        self.assert_caller_owns(rid.as_ref())?;
        let r = reason.unwrap_or_default();
        self.mgr.pause_run(&rid, r).await.map_err(WitRunError::from)
    }

    /// `resume-run: func(run-id) -> result<_, run-error>`.
    /// WIT signature has no reason param; defaults to `"manual"` per
    /// PRD §9.5.1 line 3208 + the `RunManager::resume_run` whitelist.
    pub fn resume_run(&self, run_id: String) -> Result<(), WitRunError> {
        let rid = RunId::from_string(run_id)
            .map_err(|e| WitRunError::PermissionDenied(format!("invalid-run-id: {e}")))?;
        self.assert_caller_owns(rid.as_ref())?;
        self.mgr
            .resume_run(&rid, "manual".to_string())
            .map_err(WitRunError::from)
    }

    /// `cancel-run: func(run-id, reason: option<string>) -> result<_, run-error>`.
    /// Same None → empty-string default as `pause_run`.
    pub async fn cancel_run(
        &self,
        run_id: String,
        reason: Option<String>,
    ) -> Result<(), WitRunError> {
        let rid = RunId::from_string(run_id)
            .map_err(|e| WitRunError::PermissionDenied(format!("invalid-run-id: {e}")))?;
        self.assert_caller_owns(rid.as_ref())?;
        let r = reason.unwrap_or_default();
        self.mgr
            .cancel_run(&rid, r)
            .await
            .map_err(WitRunError::from)
    }

    /// `run-status: func(run-id) -> result<run-state, run-error>`.
    pub fn run_status(&self, run_id: String) -> Result<WitRunState, WitRunError> {
        let rid = RunId::from_string(run_id)
            .map_err(|e| WitRunError::PermissionDenied(format!("invalid-run-id: {e}")))?;
        self.assert_caller_owns(rid.as_ref())?;
        self.mgr.run_status(&rid).map_err(WitRunError::from)
    }
}

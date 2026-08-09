//! `Resolver` + `ResolverChain` (MODULE-013 §1.4.2 / PRD §5.7.3).
//!
//! Slice B ships:
//! - `Resolver` trait (sync — `fn resolve(&self, req, ctx) -> ResolverOutcome`).
//! - `ResolverChain` (sync `evaluate` — see Architecture Decision §D in the
//!   slice plan; spec line 154 declares `pub async fn evaluate` but Slice B's
//!   resolvers are synchronous stubs and adopting `async fn` would require
//!   pinning Tokio runtime context everywhere with no Slice-B benefit. Slice
//!   D will adopt `async fn` when the WIT-level `request-capability` host
//!   function or ParentApproval's actual approval pathway requires `await`).
//! - 5 built-in resolvers:
//!   * `SubsetAutoApproveResolver` — full Slice-B logic (delegates to
//!     SubsetValidator; approves if request is subset of any parent grant).
//!   * `BudgetCheckResolver` — real budget-exhausted Deny (Wave-20): holds an
//!     optional `Arc<dyn RunBudget>` (CONTRACT-073); given a budget + a
//!     per-request `run_id`, `resolve` probes `RunBudget::check(run_id, 0, 0.0)`
//!     and returns `Deny` when the run is exhausted, else `Abstain`. Production
//!     wiring injects the live run budget; `new()` remains a compatibility
//!     constructor for tests and callers with no run scope.
//!   * `ParentApprovalResolver` — configurable Pending/Approve test backend, or
//!     Abstain when no parent-approval backend is installed.
//!   * `ChannelResolver` — correlated channel-approval seam with bounded
//!     duplicate suppression, pending/approved/denied retry mapping, and
//!     fail-closed delivery-error handling.
//!   * `AutoDenyResolver` — full Slice-B logic (always denies).
//!
//! `ResolverChain::evaluate` emits `resolver.invoked` per resolver iteration
//! (PRD §15.3.18 4-field payload `agent_id, capability, resolver_type,
//! decision`). Spec §2.3 explicitly excludes `pending` from the `decision`
//! enum (the Pending state is internal to MODULE-013 and surfaces as
//! `grant-decision::pending` at the WIT boundary, NOT as an event).

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use advance_shared_types::capability::BudgetDecision;
use advance_shared_types::traits::{EventBusEmit, RunBudget};
use chrono::Utc;
use serde::Serialize;
use uuid::Uuid;

use crate::data::{
    CapParam, ChainDecision, Grant, GrantDraft, GrantId, GrantIssuer, GrantProvenance,
    GrantRequest, GrantStatus, GrantTtl, ResolverOutcome,
};
use crate::events::resolver_invoked_event;
use crate::store::GrantStore;
use crate::subset::SubsetValidator;

/// Bounded duplicate-suppression cache for unresolved Channel approval sends.
pub const CHANNEL_APPROVAL_SENT_CACHE_MAX: usize = 1024;
const CHANNEL_APPROVAL_DELIVERY_TIMEOUT: Duration = Duration::from_secs(2);
const CHANNEL_APPROVAL_DELIVERY_QUEUE_MAX: usize = 1;
const CHANNEL_APPROVAL_DENIED_REASON: &str = "channel-denied";

/// MODULE-013 §1.4.2 Resolver trait.
pub trait Resolver: Send + Sync {
    /// Stable name used as the `resolver_type` field in the
    /// `resolver.invoked` event payload (PRD §15.3.18). Must be one of:
    /// `SubsetAutoApprove`, `BudgetCheck`, `ParentApproval`, `Channel`,
    /// `AutoDeny`, or a custom-resolver name supplied by Slice D / future
    /// runtime config.
    fn name(&self) -> &'static str;

    fn resolve(&self, req: &GrantRequest, ctx: &ResolverContext<'_>) -> ResolverOutcome;
}

/// Context passed to each [`Resolver::resolve`] call. Constructed by
/// [`ResolverChain::evaluate`]'s caller (Slice B test fixtures or Slice D's
/// WIT translation layer).
pub struct ResolverContext<'a> {
    /// Caller's currently active grants (the "parent grants" set).
    /// `SubsetAutoApproveResolver` walks this list to find a parent grant
    /// that covers the requested params; other resolvers may consult it for
    /// budget / approval routing decisions.
    pub parent_grants: &'a [Grant],
    /// Wave-20 — the per-request business-execution run id (M008 `run_id`,
    /// CONTRACT-073), threaded from `HostCallContext.run_id` at the WIT layer.
    /// `BudgetCheckResolver` consults it (with its injected `RunBudget`) to
    /// gate on per-run budget exhaustion. `None` ⇒ no run scope → BudgetCheck
    /// abstains. (In production this IS populated — `init` sets
    /// `ctx.run_id = Some(rid)`; production wiring injects the live budget so
    /// exhausted runs deny here before later approval resolvers.)
    pub run_id: Option<&'a str>,
}

/// MODULE-013 §1.4.2 ResolverChain.
pub struct ResolverChain {
    resolvers: Vec<Box<dyn Resolver>>,
}

impl ResolverChain {
    pub fn new(resolvers: Vec<Box<dyn Resolver>>) -> Self {
        Self { resolvers }
    }

    pub fn resolvers(&self) -> &[Box<dyn Resolver>] {
        &self.resolvers
    }

    /// Iterate resolvers in order; first non-Abstain decides. After the
    /// loop, all-Abstain falls through to `Denied("no resolver matched")`
    /// — the AutoDeny resolver as the last entry guarantees this branch is
    /// unreachable in practice.
    ///
    /// Emits a `resolver.invoked` event after each resolver runs (Round 3
    /// Warning 4 fix — symmetric with spec §1.4.2's inline example showing
    /// `event_bus.emit(Event::GrantIssued ...)`). Pending outcomes are
    /// labelled `pending` internally for telemetry purposes only; the spec
    /// §2.3 `decision` enum does NOT include `pending`, so per-event
    /// `decision` values for ParentApproval/Channel-style Pending paths
    /// emit `abstain` to comply with the enum constraint (the WIT layer
    /// re-surfaces Pending via `grant-decision::pending`, separately from
    /// the event payload).
    pub fn evaluate(
        &self,
        req: GrantRequest,
        ctx: ResolverContext<'_>,
        store: &GrantStore,
        event_bus: &Arc<dyn EventBusEmit>,
    ) -> ChainDecision {
        self.evaluate_with_insert(req, ctx, event_bus, |grant| store.insert_dynamic(grant))
    }

    /// Same resolver walk as [`Self::evaluate`], but the caller already holds
    /// [`GrantStore`]'s dynamic-insert read barrier from before it snapshotted
    /// `ResolverContext::parent_grants`. This keeps the production
    /// request-capability path atomic against preset apply without recursively
    /// acquiring the same `RwLock` on approve.
    pub(crate) fn evaluate_with_dynamic_insert_barrier(
        &self,
        req: GrantRequest,
        ctx: ResolverContext<'_>,
        store: &GrantStore,
        event_bus: &Arc<dyn EventBusEmit>,
    ) -> ChainDecision {
        self.evaluate_with_insert(req, ctx, event_bus, |grant| {
            store.insert_dynamic_inner(grant)
        })
    }

    fn evaluate_with_insert<F>(
        &self,
        req: GrantRequest,
        ctx: ResolverContext<'_>,
        event_bus: &Arc<dyn EventBusEmit>,
        mut insert_grant: F,
    ) -> ChainDecision
    where
        F: FnMut(Grant) -> crate::error::Result<GrantId>,
    {
        for r in &self.resolvers {
            let outcome = r.resolve(&req, &ctx);
            let decision_label = match &outcome {
                ResolverOutcome::Approve(_) => "approve",
                ResolverOutcome::Deny(_) => "deny",
                ResolverOutcome::Abstain | ResolverOutcome::Pending => "abstain",
            };
            event_bus.emit(resolver_invoked_event(
                &req.caller,
                &req.capability,
                r.name(),
                decision_label,
            ));
            match outcome {
                ResolverOutcome::Approve(draft) => {
                    let new_id = GrantId::new(Uuid::new_v4().to_string());
                    let grant = Grant {
                        id: new_id.clone(),
                        grantee: req.caller.clone(),
                        capability: draft.capability.clone(),
                        params: draft.params.clone(),
                        ttl: draft.ttl.clone(),
                        issuer: GrantIssuer::Resolver(r.name().to_string()),
                        provenance: GrantProvenance::Requested,
                        status: GrantStatus::Active,
                        created_at: Utc::now(),
                        expires_at: compute_expires_at(&draft.ttl),
                    };
                    return match insert_grant(grant) {
                        Ok(id) => ChainDecision::Approved(id),
                        // Slice D Audit-fix R2 — opaque internal-error message: the
                        // raw `{e}` (typically `Db` / `Yaml` / `InvalidConfig`) flows
                        // unmodified through `ChainDecision::Denied` into the WIT
                        // layer's `chain_decision_to_val` which lowers it to
                        // `grant-decision::denied(reason)`. That bypasses the §2.8
                        // mandate that `Db` / `Yaml` collapse onto opaque
                        // `invalid-params("internal-error")`. We emit a generic
                        // string here so the WIT-visible reason cannot leak raw
                        // database failure detail. The raw `{e}` is dropped on the
                        // floor at this site; future hardening slice can route it
                        // to a degraded-runtime event_bus emit.
                        Err(_) => ChainDecision::Denied(format!(
                            "resolver {} approved but insert failed (internal error)",
                            r.name()
                        )),
                    };
                }
                ResolverOutcome::Deny(reason) => return ChainDecision::Denied(reason),
                ResolverOutcome::Pending => return ChainDecision::Pending,
                ResolverOutcome::Abstain => continue,
            }
        }
        ChainDecision::Denied("no resolver matched".into())
    }
}

fn compute_expires_at(ttl: &GrantTtl) -> Option<chrono::DateTime<chrono::Utc>> {
    match ttl {
        GrantTtl::Once | GrantTtl::Lifecycle | GrantTtl::Persistent => None,
        GrantTtl::Duration(ms) => {
            let dt =
                Utc::now() + chrono::Duration::milliseconds(i64::try_from(*ms).unwrap_or(i64::MAX));
            Some(dt)
        }
        GrantTtl::Until(t) => Some(*t),
    }
}

// ============================================================================
// 5 built-in resolvers
// ============================================================================

/// Approves a request if it is a parameter-level subset of some parent
/// grant. The actual subset semantics are delegated to the injected
/// `SubsetValidator` so Slice B tests can stub it.
pub struct SubsetAutoApproveResolver {
    validator: Arc<dyn SubsetValidator>,
}

impl SubsetAutoApproveResolver {
    pub fn new(validator: Arc<dyn SubsetValidator>) -> Self {
        Self { validator }
    }
}

impl Resolver for SubsetAutoApproveResolver {
    fn name(&self) -> &'static str {
        "SubsetAutoApprove"
    }

    fn resolve(&self, req: &GrantRequest, ctx: &ResolverContext<'_>) -> ResolverOutcome {
        let draft = GrantDraft {
            capability: req.capability.clone(),
            params: req.params.clone().unwrap_or_default(),
            ttl: req.ttl.clone(),
        };
        for parent in ctx.parent_grants {
            // Audit-fix R4 (Adversarial Critical 3): only consider parent
            // grants whose grantee matches the request's caller. Without
            // this filter, a request from agent X could auto-approve
            // against agent Y's grants if `ctx.parent_grants` was
            // mis-derived (or supplied by an adversarial caller). PRD
            // §5.7.4 mandates the parent set be derived from the
            // requester's identity; this gate enforces that invariant
            // even when `ctx.parent_grants` contains grants from other
            // grantees.
            if parent.grantee != req.caller {
                continue;
            }
            if parent.status != GrantStatus::Active {
                continue;
            }
            if parent.capability != req.capability {
                continue;
            }
            if self.validator.validate(parent, &draft).is_ok() {
                return ResolverOutcome::Approve(draft);
            }
        }
        // No parent covers the request — abstain (let next resolver decide).
        ResolverOutcome::Abstain
    }
}

/// Budget-exhaustion gate (PRD §5.7.3: "预算阈值内 abstain，超出时 deny").
///
/// Wave-20 builds the real Deny: holds an OPTIONAL `Arc<dyn RunBudget>`
/// (CONTRACT-073). When a budget AND a per-request `run_id` are present,
/// `resolve` probes `RunBudget::check(run_id, 0, 0.0)` — a side-effect-free
/// probe (the `Allow` path reserves `additional_tokens = 0` /
/// `additional_cost = 0.0`, a no-op) — and maps `Deny → ResolverOutcome::Deny`
/// / `Allow → Abstain` (headroom; let the next resolver decide). The primary
/// Deny is genuine exhaustion (rounds_used ≥ limit — inclusive; or
/// committed+reserved over a token/cost limit). NOTE: `RunBudget::check` is
/// fail-closed, so it ALSO returns `Deny` for an unknown / terminal /
/// invalid-id run; the resolver forwards those verbatim (a grant request bearing
/// such a run_id is denied — the conservative posture). With NO budget or NO
/// run_id the resolver abstains.
///
/// Production wiring injects the live `RunBudget` via
/// [`BudgetCheckResolver::with_budget`]. The no-arg [`BudgetCheckResolver::new`]
/// constructor stays available for compatibility seams that intentionally have no
/// run-budget source; with no budget or no `run_id`, the resolver abstains.
pub struct BudgetCheckResolver {
    budget: Option<Arc<dyn RunBudget>>,
}

impl BudgetCheckResolver {
    /// Compatibility constructor — no budget source ⇒ always `Abstain`.
    pub fn new() -> Self {
        Self { budget: None }
    }

    /// Inject a `RunBudget` (CONTRACT-073) so the resolver gates on per-run
    /// budget exhaustion. The per-request `run_id` is supplied separately via
    /// [`ResolverContext::run_id`].
    pub fn with_budget(budget: Arc<dyn RunBudget>) -> Self {
        Self {
            budget: Some(budget),
        }
    }
}

impl Default for BudgetCheckResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl Resolver for BudgetCheckResolver {
    fn name(&self) -> &'static str {
        "BudgetCheck"
    }

    fn resolve(&self, _req: &GrantRequest, ctx: &ResolverContext<'_>) -> ResolverOutcome {
        match (&self.budget, ctx.run_id) {
            (Some(budget), Some(run_id)) => match budget.check(run_id, 0, 0.0) {
                // Run already exhausted → deny (PRD §5.7.3 "超出时 deny"). The
                // reason string carries the budget's invariant exhaustion code
                // (e.g. `budget-exceeded-rounds`); it is opaque per CONTRACT-073.
                BudgetDecision::Deny(reason) => ResolverOutcome::Deny(reason),
                // Headroom → abstain, let the next resolver decide.
                BudgetDecision::Allow => ResolverOutcome::Abstain,
            },
            // No budget source or no run scope → abstain.
            _ => ResolverOutcome::Abstain,
        }
    }
}

/// Parent-approval resolver. Test fixtures can install a pending/approve
/// backend; production paths that have no parent-approval backend use
/// [`ParentApprovalResolver::new_abstain`] so the Channel resolver can decide.
pub struct ParentApprovalResolver {
    approve: AtomicBool,
    has_backend: bool,
}

impl ParentApprovalResolver {
    pub fn new_pending() -> Self {
        Self {
            approve: AtomicBool::new(false),
            has_backend: true,
        }
    }

    pub fn new_approve() -> Self {
        Self {
            approve: AtomicBool::new(true),
            has_backend: true,
        }
    }

    pub fn new_abstain() -> Self {
        Self {
            approve: AtomicBool::new(false),
            has_backend: false,
        }
    }

    pub fn set_approve(&self, v: bool) {
        self.approve.store(v, Ordering::SeqCst);
    }
}

impl Resolver for ParentApprovalResolver {
    fn name(&self) -> &'static str {
        "ParentApproval"
    }

    fn resolve(&self, req: &GrantRequest, _ctx: &ResolverContext<'_>) -> ResolverOutcome {
        if !self.has_backend {
            return ResolverOutcome::Abstain;
        }
        if self.approve.load(Ordering::SeqCst) {
            ResolverOutcome::Approve(GrantDraft {
                capability: req.capability.clone(),
                params: req.params.clone().unwrap_or_default(),
                ttl: req.ttl.clone(),
            })
        } else {
            ResolverOutcome::Pending
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChannelApprovalDecision {
    Pending,
    Approved,
    Denied(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelApprovalRequest {
    pub request_id: String,
    pub caller: String,
    pub capability: String,
    pub params: Option<Vec<crate::data::CapParam>>,
    pub ttl: GrantTtl,
    pub justification: Option<String>,
}

impl ChannelApprovalRequest {
    fn from_grant_request(req: &GrantRequest, request_id: String) -> Self {
        Self {
            request_id,
            caller: req.caller.clone(),
            capability: req.capability.clone(),
            params: req.params.clone(),
            ttl: req.ttl.clone(),
            justification: req.justification.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelApprovalError {
    reason: String,
}

impl ChannelApprovalError {
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }

    pub fn reason(&self) -> &str {
        &self.reason
    }
}

impl fmt::Display for ChannelApprovalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.reason.fmt(f)
    }
}

impl std::error::Error for ChannelApprovalError {}

pub trait ChannelApprovalPort: Send + Sync {
    fn decision(&self, request_id: &str) -> ChannelApprovalDecision;
    fn request_approval(&self, request: ChannelApprovalRequest)
        -> Result<(), ChannelApprovalError>;

    /// ATOMICALLY consume an approved request and return its (possibly narrowed)
    /// parameters — the single, race-free replacement for a separate
    /// read-then-remove. Called by the `ChannelResolver` once it has observed
    /// `decision() == Approved`:
    /// - `Some(None)` — approve the request as delivered (no narrowing).
    /// - `Some(Some(params))` — the operator narrowed to a CONTRACT-122-validated
    ///   subset; the resolver builds the approved draft with THESE params.
    /// - `None` — the entry is no longer Approved (a concurrent retry already
    ///   consumed it, or it was superseded to Denied/Pending/removed). The caller
    ///   MUST NOT approve; it re-evaluates delivery (→ Pending / re-deliver).
    ///
    /// The default `Some(None)` (approve-as-delivered) keeps stateless
    /// `ChannelApprovalPort` impls (e.g. fixed test ports) source-compatible: they
    /// gate approval solely via `decision()`, so there is nothing to consume. A
    /// stateful backend (the operator intake) MUST remove the entry under one lock
    /// so two racing retries cannot both approve — the first gets the narrowed
    /// params, the second gets `None` (and must not fall back to the wider draft).
    fn take_approved(&self, _request_id: &str) -> Option<Option<Vec<CapParam>>> {
        Some(None)
    }

    /// Consume/cleanup hook invoked by the `ChannelResolver` immediately after a
    /// TERMINAL Denied decision has been observed on a retry, so the backend can
    /// drop the parked entry (single-use + bounded-registry). Default no-op keeps
    /// existing impls source-compatible. (Approved entries are consumed atomically
    /// by `take_approved`; this covers the Denied path.)
    fn resolved(&self, _request_id: &str) {}
}

/// Channel-backed approval resolver. With no port installed it abstains. With a
/// port installed it sends one correlated approval request per canonical
/// logical `GrantRequest` while that request remains in the bounded sent cache,
/// returns Pending only after successful delivery, maps terminal channel
/// decisions to Approve/Deny on retry, and fails closed without caching the
/// request when delivery fails. Terminal channel decisions are single-use:
/// after a decision is consumed, a later identical logical request receives a
/// fresh request id. Concurrent duplicates wait for the in-flight delivery
/// attempt to settle so they cannot observe Pending before an approval request
/// exists.
pub struct ChannelResolver {
    approval: Option<Arc<dyn ChannelApprovalPort>>,
    sent: Mutex<SentApprovalCache>,
    sent_changed: Condvar,
    delivery_worker: Mutex<Option<ChannelApprovalDeliveryWorker>>,
}

impl ChannelResolver {
    pub fn new() -> Self {
        Self {
            approval: None,
            sent: Mutex::new(SentApprovalCache::default()),
            sent_changed: Condvar::new(),
            delivery_worker: Mutex::new(None),
        }
    }

    pub fn with_approval_port(approval: Arc<dyn ChannelApprovalPort>) -> Self {
        Self::with_approval_port_and_sent_cache_limit(approval, CHANNEL_APPROVAL_SENT_CACHE_MAX)
    }

    pub fn with_approval_port_and_sent_cache_limit(
        approval: Arc<dyn ChannelApprovalPort>,
        sent_cache_limit: usize,
    ) -> Self {
        Self {
            approval: Some(approval),
            sent: Mutex::new(SentApprovalCache::new(sent_cache_limit)),
            sent_changed: Condvar::new(),
            delivery_worker: Mutex::new(None),
        }
    }
}

impl Default for ChannelResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl Resolver for ChannelResolver {
    fn name(&self) -> &'static str {
        "Channel"
    }

    fn resolve(&self, req: &GrantRequest, _ctx: &ResolverContext<'_>) -> ResolverOutcome {
        let Some(approval) = &self.approval else {
            return ResolverOutcome::Abstain;
        };
        let fingerprint = channel_request_fingerprint(req);
        if let Some(delivered) = self.delivered_approval(&fingerprint) {
            match approval.decision(&delivered.request_id) {
                ChannelApprovalDecision::Approved => {
                    // ATOMICALLY consume the approval + read its narrowed params in
                    // one backend op, so two racing retries cannot both approve: the
                    // winner gets `Some(narrowed)`, a loser gets `None` and must NOT
                    // fall back to the wider `delivered.draft` (which would grant more
                    // than the operator approved — a fail-open leak).
                    match approval.take_approved(&delivered.request_id) {
                        Some(narrowed) => {
                            self.forget_sent(&fingerprint);
                            let draft = match narrowed {
                                Some(params) => GrantDraft {
                                    capability: delivered.draft.capability,
                                    params,
                                    ttl: delivered.draft.ttl,
                                },
                                None => delivered.draft,
                            };
                            return ResolverOutcome::Approve(draft);
                        }
                        None => {
                            // Concurrently consumed / no longer Approved — do not
                            // approve or `forget_sent` (the winning retry owns
                            // cleanup); fall through to re-evaluate delivery below
                            // (→ Pending / re-deliver a fresh approval request).
                        }
                    }
                }
                ChannelApprovalDecision::Denied(_) => {
                    approval.resolved(&delivered.request_id);
                    self.forget_sent(&fingerprint);
                    return ResolverOutcome::Deny(CHANNEL_APPROVAL_DENIED_REASON.to_string());
                }
                ChannelApprovalDecision::Pending => {}
            }
        }
        match self.pending_delivery_action(fingerprint.clone(), req) {
            ApprovalDeliveryAction::Deliver(request_id) => {
                let approval_request = ChannelApprovalRequest::from_grant_request(req, request_id);
                let delivery =
                    self.deliver_approval_request(Arc::clone(approval), approval_request);
                match delivery {
                    Ok(()) => self.finish_pending_delivery(&fingerprint, true),
                    Err(()) => {
                        self.finish_pending_delivery(&fingerprint, false);
                        return ResolverOutcome::Deny("channel-approval-unavailable".to_string());
                    }
                }
            }
            ApprovalDeliveryAction::AlreadyDelivered => {}
            ApprovalDeliveryAction::Unavailable => {
                return ResolverOutcome::Deny("channel-approval-unavailable".to_string());
            }
        }
        ResolverOutcome::Pending
    }
}

#[derive(Clone)]
struct ChannelApprovalDeliveryWorker {
    sender: mpsc::SyncSender<ChannelApprovalDeliveryJob>,
}

struct ChannelApprovalDeliveryJob {
    approval: Arc<dyn ChannelApprovalPort>,
    request: ChannelApprovalRequest,
    reply: mpsc::Sender<Result<(), ()>>,
}

impl ChannelResolver {
    fn delivered_approval(&self, fingerprint: &str) -> Option<DeliveredApproval> {
        let sent = self
            .sent
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match sent.state(fingerprint) {
            Some(SentApprovalState::Delivered { request_id, draft }) => Some(DeliveredApproval {
                request_id: request_id.clone(),
                draft: draft.clone(),
            }),
            _ => None,
        }
    }
    fn pending_delivery_action(
        &self,
        fingerprint: String,
        req: &GrantRequest,
    ) -> ApprovalDeliveryAction {
        let mut sent = self
            .sent
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        loop {
            match sent.begin_delivery(fingerprint.clone(), grant_draft_from_request(req)) {
                SentApprovalCacheAction::Deliver(request_id) => {
                    return ApprovalDeliveryAction::Deliver(request_id);
                }
                SentApprovalCacheAction::AlreadyDelivered => {
                    return ApprovalDeliveryAction::AlreadyDelivered;
                }
                SentApprovalCacheAction::WaitForDelivery => {
                    sent = self
                        .sent_changed
                        .wait(sent)
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                }
                SentApprovalCacheAction::CacheFull => return ApprovalDeliveryAction::Unavailable,
            }
        }
    }

    fn deliver_approval_request(
        &self,
        approval: Arc<dyn ChannelApprovalPort>,
        request: ChannelApprovalRequest,
    ) -> Result<(), ()> {
        let sender = self.delivery_sender()?;
        let (reply, result) = mpsc::channel();
        let job = ChannelApprovalDeliveryJob {
            approval,
            request,
            reply,
        };
        if sender.try_send(job).is_err() {
            return Err(());
        }
        result
            .recv_timeout(CHANNEL_APPROVAL_DELIVERY_TIMEOUT)
            .unwrap_or(Err(()))
    }

    fn delivery_sender(&self) -> Result<mpsc::SyncSender<ChannelApprovalDeliveryJob>, ()> {
        let mut worker = self
            .delivery_worker
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(worker) = worker.as_ref() {
            return Ok(worker.sender.clone());
        }

        let (sender, receiver) = mpsc::sync_channel(CHANNEL_APPROVAL_DELIVERY_QUEUE_MAX);
        let thread_sender = sender.clone();
        let Ok(_) = std::thread::Builder::new()
            .name("cap-grant-channel-approval".to_string())
            .spawn(move || run_channel_approval_delivery_worker(receiver))
        else {
            return Err(());
        };
        *worker = Some(ChannelApprovalDeliveryWorker {
            sender: thread_sender,
        });
        Ok(sender)
    }

    fn finish_pending_delivery(&self, fingerprint: &str, delivered: bool) {
        self.sent
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .finish_delivery(fingerprint, delivered);
        self.sent_changed.notify_all();
    }

    fn forget_sent(&self, fingerprint: &str) {
        self.sent
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .forget(fingerprint);
        self.sent_changed.notify_all();
    }
}

fn run_channel_approval_delivery_worker(receiver: mpsc::Receiver<ChannelApprovalDeliveryJob>) {
    while let Ok(job) = receiver.recv() {
        let delivery = catch_unwind(AssertUnwindSafe(|| {
            job.approval.request_approval(job.request)
        }));
        let result = match delivery {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) | Err(_) => Err(()),
        };
        let _ = job.reply.send(result);
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ApprovalDeliveryAction {
    Deliver(String),
    AlreadyDelivered,
    Unavailable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum SentApprovalCacheAction {
    Deliver(String),
    AlreadyDelivered,
    WaitForDelivery,
    CacheFull,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum SentApprovalState {
    Delivering {
        request_id: String,
        draft: GrantDraft,
    },
    Delivered {
        request_id: String,
        draft: GrantDraft,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DeliveredApproval {
    request_id: String,
    draft: GrantDraft,
}

struct SentApprovalCache {
    seen: HashMap<String, SentApprovalState>,
    order: VecDeque<String>,
    max_entries: usize,
}

impl SentApprovalCache {
    fn new(max_entries: usize) -> Self {
        Self {
            seen: HashMap::new(),
            order: VecDeque::new(),
            max_entries: max_entries.max(1),
        }
    }

    fn begin_delivery(
        &mut self,
        fingerprint: String,
        draft: GrantDraft,
    ) -> SentApprovalCacheAction {
        match self.seen.get(&fingerprint) {
            Some(SentApprovalState::Delivered { .. }) => {
                return SentApprovalCacheAction::AlreadyDelivered;
            }
            Some(SentApprovalState::Delivering { .. }) => {
                return SentApprovalCacheAction::WaitForDelivery;
            }
            None => {}
        }
        if self.order.len() >= self.max_entries {
            self.evict_one_delivered_entry();
        }
        if self.order.len() >= self.max_entries {
            return SentApprovalCacheAction::CacheFull;
        }
        let request_id = new_channel_request_id();
        self.seen.insert(
            fingerprint.clone(),
            SentApprovalState::Delivering {
                request_id: request_id.clone(),
                draft,
            },
        );
        self.order.push_back(fingerprint);
        SentApprovalCacheAction::Deliver(request_id)
    }

    fn state(&self, fingerprint: &str) -> Option<&SentApprovalState> {
        self.seen.get(fingerprint)
    }

    fn finish_delivery(&mut self, fingerprint: &str, delivered: bool) {
        if delivered {
            if let Some(state) = self.seen.get_mut(fingerprint) {
                if let SentApprovalState::Delivering { request_id, draft } = state {
                    *state = SentApprovalState::Delivered {
                        request_id: request_id.clone(),
                        draft: draft.clone(),
                    };
                }
            }
            self.evict_delivered_overflow();
        } else {
            self.forget(fingerprint);
        }
    }

    fn evict_delivered_overflow(&mut self) {
        let mut scanned = 0usize;
        while self.order.len() > self.max_entries && scanned < self.order.len() {
            let Some(candidate) = self.order.pop_front() else {
                break;
            };
            match self.seen.get(&candidate) {
                Some(SentApprovalState::Delivering { .. }) => {
                    self.order.push_back(candidate);
                    scanned += 1;
                }
                Some(SentApprovalState::Delivered { .. }) | None => {
                    self.seen.remove(&candidate);
                    scanned = 0;
                }
            }
        }
    }

    fn evict_one_delivered_entry(&mut self) {
        let mut scanned = 0usize;
        while scanned < self.order.len() {
            let Some(candidate) = self.order.pop_front() else {
                break;
            };
            match self.seen.get(&candidate) {
                Some(SentApprovalState::Delivered { .. }) | None => {
                    self.seen.remove(&candidate);
                    break;
                }
                Some(SentApprovalState::Delivering { .. }) => {
                    self.order.push_back(candidate);
                    scanned += 1;
                }
            }
        }
    }

    fn forget(&mut self, request_id: &str) {
        if self.seen.remove(request_id).is_some() {
            self.order.retain(|seen_id| seen_id != request_id);
        }
    }
}

impl Default for SentApprovalCache {
    fn default() -> Self {
        Self::new(CHANNEL_APPROVAL_SENT_CACHE_MAX)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
struct ChannelRequestParamFingerprint<'a> {
    key: &'a str,
    value: &'a str,
}

#[derive(Serialize)]
struct ChannelRequestFingerprint<'a> {
    caller: &'a str,
    capability: &'a str,
    params: Vec<ChannelRequestParamFingerprint<'a>>,
    ttl: &'a GrantTtl,
    justification: &'a Option<String>,
}

fn channel_request_fingerprint(req: &GrantRequest) -> String {
    let mut params: Vec<_> = req
        .params
        .as_deref()
        .unwrap_or_default()
        .iter()
        .map(|param| ChannelRequestParamFingerprint {
            key: param.key.as_str(),
            value: param.value.as_str(),
        })
        .collect();
    params.sort_unstable();
    params.dedup();
    let fingerprint = ChannelRequestFingerprint {
        caller: &req.caller,
        capability: &req.capability,
        params,
        ttl: &req.ttl,
        justification: &req.justification,
    };
    let serialized = serde_json::to_string(&fingerprint)
        .unwrap_or_else(|_| format!("{}:{}:{:?}", req.caller, req.capability, req.params));
    format!("grant-approval:{serialized}")
}

fn grant_draft_from_request(req: &GrantRequest) -> GrantDraft {
    GrantDraft {
        capability: req.capability.clone(),
        params: req.params.clone().unwrap_or_default(),
        ttl: req.ttl.clone(),
    }
}

fn new_channel_request_id() -> String {
    format!("grant-approval:{}", Uuid::new_v4())
}

/// Always-deny chain terminator.
pub struct AutoDenyResolver;

impl AutoDenyResolver {
    pub fn new() -> Self {
        Self
    }
}

impl Default for AutoDenyResolver {
    fn default() -> Self {
        Self
    }
}

impl Resolver for AutoDenyResolver {
    fn name(&self) -> &'static str {
        "AutoDeny"
    }

    fn resolve(&self, _req: &GrantRequest, _ctx: &ResolverContext<'_>) -> ResolverOutcome {
        ResolverOutcome::Deny("AutoDenyResolver: request denied by chain terminator".into())
    }
}

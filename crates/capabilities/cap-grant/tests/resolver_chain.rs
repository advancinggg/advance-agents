//! ResolverChain tests — AC-06 + AC-17 verification.

mod common;

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use advance_shared_types::traits::EventBusEmit;
use cap_grant::data::{
    CapParam, ChainDecision, Grant, GrantId, GrantIssuer, GrantProvenance, GrantRequest,
    GrantStatus, GrantTtl, ResolverOutcome,
};
use cap_grant::resolver::{
    AutoDenyResolver, BudgetCheckResolver, ChannelApprovalDecision, ChannelApprovalError,
    ChannelApprovalPort, ChannelApprovalRequest, ChannelResolver, ParentApprovalResolver, Resolver,
    ResolverChain, ResolverContext, SubsetAutoApproveResolver,
};
use cap_grant::subset::SubsetValidatorImpl;
use chrono::Utc;

use crate::common::{make_store, RecordingBus};

/// Test-only resolver that always abstains.
struct AlwaysAbstain;
impl Resolver for AlwaysAbstain {
    fn name(&self) -> &'static str {
        "AlwaysAbstain"
    }
    fn resolve(&self, _req: &GrantRequest, _ctx: &ResolverContext<'_>) -> ResolverOutcome {
        ResolverOutcome::Abstain
    }
}

/// Test-only resolver that always approves with the requested params.
struct AlwaysApprove;
impl Resolver for AlwaysApprove {
    fn name(&self) -> &'static str {
        "AlwaysApprove"
    }
    fn resolve(&self, req: &GrantRequest, _ctx: &ResolverContext<'_>) -> ResolverOutcome {
        ResolverOutcome::Approve(cap_grant::data::GrantDraft {
            capability: req.capability.clone(),
            params: req.params.clone().unwrap_or_default(),
            ttl: req.ttl.clone(),
        })
    }
}

/// Test-only resolver that always denies.
struct AlwaysDeny;
impl Resolver for AlwaysDeny {
    fn name(&self) -> &'static str {
        "AlwaysDeny"
    }
    fn resolve(&self, _req: &GrantRequest, _ctx: &ResolverContext<'_>) -> ResolverOutcome {
        ResolverOutcome::Deny("test deny".to_string())
    }
}

fn req(caller: &str, capability: &str) -> GrantRequest {
    GrantRequest {
        caller: caller.to_string(),
        capability: capability.to_string(),
        params: None,
        ttl: GrantTtl::Once,
        justification: None,
    }
}

fn req_with_justification(caller: &str, capability: &str, justification: &str) -> GrantRequest {
    GrantRequest {
        caller: caller.to_string(),
        capability: capability.to_string(),
        params: None,
        ttl: GrantTtl::Once,
        justification: Some(justification.to_string()),
    }
}

fn req_with_params(caller: &str, capability: &str, params: &[(&str, &str)]) -> GrantRequest {
    GrantRequest {
        caller: caller.to_string(),
        capability: capability.to_string(),
        params: Some(
            params
                .iter()
                .map(|(key, value)| CapParam {
                    key: (*key).to_string(),
                    value: (*value).to_string(),
                })
                .collect(),
        ),
        ttl: GrantTtl::Once,
        justification: None,
    }
}

#[derive(Default)]
struct RecordingApprovalPort {
    decisions: Mutex<HashMap<String, ChannelApprovalDecision>>,
    requests: Mutex<Vec<ChannelApprovalRequest>>,
}

impl RecordingApprovalPort {
    fn approve(&self, request_id: &str) {
        self.decisions
            .lock()
            .unwrap()
            .insert(request_id.to_string(), ChannelApprovalDecision::Approved);
    }

    fn deny(&self, request_id: &str, reason: &str) {
        self.decisions.lock().unwrap().insert(
            request_id.to_string(),
            ChannelApprovalDecision::Denied(reason.to_string()),
        );
    }

    fn requests(&self) -> Vec<ChannelApprovalRequest> {
        self.requests.lock().unwrap().clone()
    }
}

impl ChannelApprovalPort for RecordingApprovalPort {
    fn decision(&self, request_id: &str) -> ChannelApprovalDecision {
        self.decisions
            .lock()
            .unwrap()
            .get(request_id)
            .cloned()
            .unwrap_or(ChannelApprovalDecision::Pending)
    }

    fn request_approval(
        &self,
        request: ChannelApprovalRequest,
    ) -> Result<(), ChannelApprovalError> {
        self.requests.lock().unwrap().push(request);
        Ok(())
    }
}

struct SpoofingApprovalPort {
    decision: ChannelApprovalDecision,
    requests: Mutex<Vec<ChannelApprovalRequest>>,
}

impl SpoofingApprovalPort {
    fn approved() -> Self {
        Self {
            decision: ChannelApprovalDecision::Approved,
            requests: Mutex::new(Vec::new()),
        }
    }

    fn denied(reason: &str) -> Self {
        Self {
            decision: ChannelApprovalDecision::Denied(reason.to_string()),
            requests: Mutex::new(Vec::new()),
        }
    }

    fn requests(&self) -> Vec<ChannelApprovalRequest> {
        self.requests.lock().unwrap().clone()
    }
}

impl ChannelApprovalPort for SpoofingApprovalPort {
    fn decision(&self, _request_id: &str) -> ChannelApprovalDecision {
        self.decision.clone()
    }

    fn request_approval(
        &self,
        request: ChannelApprovalRequest,
    ) -> Result<(), ChannelApprovalError> {
        self.requests.lock().unwrap().push(request);
        Ok(())
    }
}

struct FailingOnceApprovalPort {
    failed: AtomicBool,
    attempts: Mutex<Vec<String>>,
}

impl FailingOnceApprovalPort {
    fn new() -> Self {
        Self {
            failed: AtomicBool::new(false),
            attempts: Mutex::new(Vec::new()),
        }
    }

    fn attempts(&self) -> Vec<String> {
        self.attempts.lock().unwrap().clone()
    }
}

impl ChannelApprovalPort for FailingOnceApprovalPort {
    fn decision(&self, _request_id: &str) -> ChannelApprovalDecision {
        ChannelApprovalDecision::Pending
    }

    fn request_approval(
        &self,
        request: ChannelApprovalRequest,
    ) -> Result<(), ChannelApprovalError> {
        self.attempts
            .lock()
            .unwrap()
            .push(request.request_id.clone());
        if !self.failed.swap(true, Ordering::SeqCst) {
            return Err(ChannelApprovalError::new("queue unavailable"));
        }
        Ok(())
    }
}

struct PanickingOnceApprovalPort {
    panicked: AtomicBool,
    attempts: Mutex<Vec<String>>,
}

impl PanickingOnceApprovalPort {
    fn new() -> Self {
        Self {
            panicked: AtomicBool::new(false),
            attempts: Mutex::new(Vec::new()),
        }
    }

    fn attempts(&self) -> Vec<String> {
        self.attempts.lock().unwrap().clone()
    }
}

impl ChannelApprovalPort for PanickingOnceApprovalPort {
    fn decision(&self, _request_id: &str) -> ChannelApprovalDecision {
        ChannelApprovalDecision::Pending
    }

    fn request_approval(
        &self,
        request: ChannelApprovalRequest,
    ) -> Result<(), ChannelApprovalError> {
        self.attempts
            .lock()
            .unwrap()
            .push(request.request_id.clone());
        if !self.panicked.swap(true, Ordering::SeqCst) {
            panic!("approval backend panic must not leak or strand cache state");
        }
        Ok(())
    }
}

struct BlockingApprovalPort {
    release: Mutex<Receiver<()>>,
    attempts: Mutex<Vec<String>>,
}

impl BlockingApprovalPort {
    fn new(release: Receiver<()>) -> Self {
        Self {
            release: Mutex::new(release),
            attempts: Mutex::new(Vec::new()),
        }
    }

    fn attempts(&self) -> Vec<String> {
        self.attempts.lock().unwrap().clone()
    }
}

impl ChannelApprovalPort for BlockingApprovalPort {
    fn decision(&self, _request_id: &str) -> ChannelApprovalDecision {
        ChannelApprovalDecision::Pending
    }

    fn request_approval(
        &self,
        request: ChannelApprovalRequest,
    ) -> Result<(), ChannelApprovalError> {
        let attempt_count = {
            let mut attempts = self.attempts.lock().unwrap();
            attempts.push(request.request_id.clone());
            attempts.len()
        };
        if attempt_count == 1 {
            let _ = self.release.lock().unwrap().recv();
            Ok(())
        } else {
            Err(ChannelApprovalError::new(
                "approval backend still unavailable",
            ))
        }
    }
}

struct BlockingFirstFailureApprovalPort {
    first_entered: Mutex<Option<Sender<()>>>,
    first_release: Mutex<Receiver<()>>,
    attempts: Mutex<Vec<String>>,
}

impl BlockingFirstFailureApprovalPort {
    fn new(first_entered: Sender<()>, first_release: Receiver<()>) -> Self {
        Self {
            first_entered: Mutex::new(Some(first_entered)),
            first_release: Mutex::new(first_release),
            attempts: Mutex::new(Vec::new()),
        }
    }

    fn attempts(&self) -> Vec<String> {
        self.attempts.lock().unwrap().clone()
    }
}

impl ChannelApprovalPort for BlockingFirstFailureApprovalPort {
    fn decision(&self, _request_id: &str) -> ChannelApprovalDecision {
        ChannelApprovalDecision::Pending
    }

    fn request_approval(
        &self,
        request: ChannelApprovalRequest,
    ) -> Result<(), ChannelApprovalError> {
        let attempt_no = {
            let mut attempts = self.attempts.lock().unwrap();
            attempts.push(request.request_id.clone());
            attempts.len()
        };
        if attempt_no == 1 {
            if let Some(tx) = self.first_entered.lock().unwrap().take() {
                let _ = tx.send(());
            }
            self.first_release.lock().unwrap().recv().unwrap();
            return Err(ChannelApprovalError::new("queue unavailable"));
        }
        Ok(())
    }
}

#[test]
fn t06_chain_first_approve_short_circuits() {
    // Chain [Abstain → Approve → AutoDeny]: first Approve wins.
    let (store, bus, _h) = make_store();
    let bus_dyn: Arc<dyn EventBusEmit> = bus.clone();
    let chain = ResolverChain::new(vec![
        Box::new(AlwaysAbstain),
        Box::new(AlwaysApprove),
        Box::new(AutoDenyResolver::new()),
    ]);
    let result = chain.evaluate(
        req("alice", "fs"),
        ResolverContext {
            parent_grants: &[],
            run_id: None,
        },
        &store,
        &bus_dyn,
    );
    assert!(
        matches!(result, ChainDecision::Approved(_)),
        "got: {result:?}"
    );
}

#[test]
fn t06_chain_first_deny_short_circuits() {
    // Chain [Abstain → Deny → AutoDeny]: first Deny short-circuits.
    let (store, bus, _h) = make_store();
    let bus_dyn: Arc<dyn EventBusEmit> = bus.clone();
    let chain = ResolverChain::new(vec![
        Box::new(AlwaysAbstain),
        Box::new(AlwaysDeny),
        Box::new(AutoDenyResolver::new()),
    ]);
    let result = chain.evaluate(
        req("alice", "fs"),
        ResolverContext {
            parent_grants: &[],
            run_id: None,
        },
        &store,
        &bus_dyn,
    );
    let ChainDecision::Denied(reason) = result else {
        panic!("expected Denied, got: {result:?}");
    };
    assert_eq!(reason, "test deny");
}

#[test]
fn t06_chain_all_abstain_falls_through_no_resolver_matched() {
    let (store, bus, _h) = make_store();
    let bus_dyn: Arc<dyn EventBusEmit> = bus.clone();
    let chain = ResolverChain::new(vec![Box::new(AlwaysAbstain)]);
    let result = chain.evaluate(
        req("alice", "fs"),
        ResolverContext {
            parent_grants: &[],
            run_id: None,
        },
        &store,
        &bus_dyn,
    );
    let ChainDecision::Denied(reason) = result else {
        panic!("expected Denied, got: {result:?}");
    };
    assert!(reason.contains("no resolver matched"), "got: {reason}");
}

#[test]
fn t06_chain_subset_auto_approve_then_auto_deny() {
    // Chain [SubsetAutoApprove (with no parent grants → abstain) → AutoDeny].
    // No parent grants means the subset resolver abstains; AutoDeny denies.
    let (store, bus, _h) = make_store();
    let bus_dyn: Arc<dyn EventBusEmit> = bus.clone();
    let validator = Arc::new(SubsetValidatorImpl::new());
    let chain = ResolverChain::new(vec![
        Box::new(SubsetAutoApproveResolver::new(validator)),
        Box::new(AutoDenyResolver::new()),
    ]);
    let result = chain.evaluate(
        req("alice", "fs"),
        ResolverContext {
            parent_grants: &[],
            run_id: None,
        },
        &store,
        &bus_dyn,
    );
    assert!(
        matches!(result, ChainDecision::Denied(_)),
        "got: {result:?}"
    );
}

#[test]
fn t17_pending_then_approve_after_flag_flip() {
    // Chain [ParentApproval(stub-pending) → AutoDeny]. First call → Pending.
    // Flip flag → Approve. Second call → Approved.
    let (store, bus, _h) = make_store();
    let bus_dyn: Arc<dyn EventBusEmit> = bus.clone();
    let parent_approval = Arc::new(ParentApprovalResolver::new_pending());

    // Wrapper that delegates to the shared ParentApproval instance so we can
    // flip the flag from the test.
    struct DelegateApproval(Arc<ParentApprovalResolver>);
    impl Resolver for DelegateApproval {
        fn name(&self) -> &'static str {
            "ParentApproval"
        }
        fn resolve(&self, req: &GrantRequest, ctx: &ResolverContext<'_>) -> ResolverOutcome {
            self.0.resolve(req, ctx)
        }
    }

    let chain = ResolverChain::new(vec![
        Box::new(DelegateApproval(parent_approval.clone())),
        Box::new(AutoDenyResolver::new()),
    ]);
    let r1 = chain.evaluate(
        req("alice", "fs"),
        ResolverContext {
            parent_grants: &[],
            run_id: None,
        },
        &store,
        &bus_dyn,
    );
    assert!(matches!(r1, ChainDecision::Pending), "round 1: {r1:?}");

    parent_approval.set_approve(true);
    let r2 = chain.evaluate(
        req("alice", "fs"),
        ResolverContext {
            parent_grants: &[],
            run_id: None,
        },
        &store,
        &bus_dyn,
    );
    assert!(matches!(r2, ChainDecision::Approved(_)), "round 2: {r2:?}");
}

#[test]
fn t06_pending_returns_pending_not_denied() {
    // Verify that the chain does NOT fall through to AutoDeny when an earlier
    // resolver returns Pending — Pending must be propagated.
    let (store, bus, _h) = make_store();
    let bus_dyn: Arc<dyn EventBusEmit> = bus.clone();
    let chain = ResolverChain::new(vec![
        Box::new(ParentApprovalResolver::new_pending()),
        Box::new(AutoDenyResolver::new()),
    ]);
    let result = chain.evaluate(
        req("alice", "fs"),
        ResolverContext {
            parent_grants: &[],
            run_id: None,
        },
        &store,
        &bus_dyn,
    );
    assert!(matches!(result, ChainDecision::Pending));
}

#[test]
fn t17_parent_approval_no_backend_abstains() {
    let resolver = ParentApprovalResolver::new_abstain();
    let outcome = resolver.resolve(
        &req("alice", "fs"),
        &ResolverContext {
            parent_grants: &[],
            run_id: None,
        },
    );
    assert!(
        matches!(outcome, ResolverOutcome::Abstain),
        "no parent-approval backend should let later resolvers decide, got {outcome:?}"
    );
}

#[test]
fn t06_resolver_invoked_event_emitted_per_iteration() {
    // Round 3 Warning 4 fix verification: ResolverChain::evaluate emits
    // resolver.invoked per resolver iteration. Chain [Abstain → Approve]:
    // expect 2 events with decisions abstain then approve.
    let (store, bus, _h) = make_store();
    let bus_dyn: Arc<dyn EventBusEmit> = bus.clone();
    let chain = ResolverChain::new(vec![Box::new(AlwaysAbstain), Box::new(AlwaysApprove)]);
    let _ = chain.evaluate(
        req("alice", "fs"),
        ResolverContext {
            parent_grants: &[],
            run_id: None,
        },
        &store,
        &bus_dyn,
    );
    let invoked: Vec<_> = bus
        .all_of("resolver.invoked")
        .into_iter()
        .map(|e| e.payload)
        .collect();
    assert_eq!(invoked.len(), 2, "expected 2 resolver.invoked events");
    assert_eq!(invoked[0]["decision"], "abstain", "first should be abstain");
    assert_eq!(
        invoked[1]["decision"], "approve",
        "second should be approve"
    );
    // Verify field set per PRD §15.3.18.
    for e in &invoked {
        assert!(e.get("agent_id").is_some());
        assert!(e.get("capability").is_some());
        assert!(e.get("resolver_type").is_some());
        assert!(e.get("decision").is_some());
    }
    // Silence unused warnings on RecordingBus alias.
    let _ = std::any::type_name::<RecordingBus>();
}

// ============================================================================
// AC-22 — per-resolver decision characterization.
// These exercise `Resolver::resolve` directly so each built-in resolver's
// individual decision is pinned. The real budget-exhausted Deny path lives
// behind `BudgetCheckResolver::with_budget(..)` and is covered in
// `tests/budget_check_resolver.rs`; this file pins the compatibility no-budget
// abstain path, the no-channel-port abstain path, and the channel approval seam's
// correlated Pending/Approve/Deny behavior.
// ============================================================================

/// An Active parent grant for `grantee`, capability `capability`, with the
/// given params (empty params = whole-capability grant per SubsetValidator).
fn active_parent(grantee: &str, capability: &str) -> Grant {
    Grant {
        id: GrantId::new("ac22-parent"),
        grantee: grantee.to_string(),
        capability: capability.to_string(),
        params: Vec::new(), // whole-capability → covers any same-capability request
        ttl: GrantTtl::Persistent,
        issuer: GrantIssuer::Config,
        provenance: GrantProvenance::StaticConfig,
        status: GrantStatus::Active,
        created_at: Utc::now(),
        expires_at: None,
    }
}

#[test]
fn t39_subset_auto_approve_approve_on_subset_else_abstain() {
    let resolver = SubsetAutoApproveResolver::new(Arc::new(SubsetValidatorImpl::new()));

    // APPROVE: a covering (whole-capability) parent grant for the SAME caller
    // and capability → the request (whole-capability) is a subset → Approve.
    let parent = active_parent("alice", "fs");
    let r = resolver.resolve(
        &req("alice", "fs"),
        &ResolverContext {
            parent_grants: std::slice::from_ref(&parent),
            run_id: None,
        },
    );
    assert!(
        matches!(r, ResolverOutcome::Approve(_)),
        "covering parent grant → Approve, got {r:?}"
    );

    // ABSTAIN: no parent grants at all.
    let r = resolver.resolve(
        &req("alice", "fs"),
        &ResolverContext {
            parent_grants: &[],
            run_id: None,
        },
    );
    assert!(
        matches!(r, ResolverOutcome::Abstain),
        "no parent grant → Abstain, got {r:?}"
    );

    // ABSTAIN: a parent grant for a DIFFERENT capability does not cover the
    // request (cross-capability subset is never legal).
    let other_cap = active_parent("alice", "http");
    let r = resolver.resolve(
        &req("alice", "fs"),
        &ResolverContext {
            parent_grants: std::slice::from_ref(&other_cap),
            run_id: None,
        },
    );
    assert!(
        matches!(r, ResolverOutcome::Abstain),
        "non-matching capability → Abstain, got {r:?}"
    );

    // ABSTAIN: a parent grant belonging to a DIFFERENT grantee must NOT
    // auto-approve the caller's request (PRD §5.7.4 identity gate).
    let foreign = active_parent("mallory", "fs");
    let r = resolver.resolve(
        &req("alice", "fs"),
        &ResolverContext {
            parent_grants: std::slice::from_ref(&foreign),
            run_id: None,
        },
    );
    assert!(
        matches!(r, ResolverOutcome::Abstain),
        "foreign-grantee parent → Abstain, got {r:?}"
    );
}

#[test]
fn t40_auto_deny_terminal_deny() {
    let resolver = AutoDenyResolver::new();
    let r = resolver.resolve(
        &req("alice", "fs"),
        &ResolverContext {
            parent_grants: &[],
            run_id: None,
        },
    );
    let ResolverOutcome::Deny(reason) = r else {
        panic!("AutoDeny must Deny, got {r:?}");
    };
    assert!(reason.contains("denied"), "deny reason: {reason}");

    // Terminal + unconditional: denies even when a covering parent grant exists.
    let parent = active_parent("alice", "fs");
    let r2 = resolver.resolve(
        &req("alice", "fs"),
        &ResolverContext {
            parent_grants: std::slice::from_ref(&parent),
            run_id: None,
        },
    );
    assert!(
        matches!(r2, ResolverOutcome::Deny(_)),
        "AutoDeny is unconditional, got {r2:?}"
    );
}

#[test]
fn t41_budget_check_no_budget_compatibility_abstains() {
    // Compatibility no-budget constructor: no injected budget → Abstain. The
    // production resolver chain uses `with_budget` and is covered by CLI/SYS-J
    // witnesses.
    let resolver = BudgetCheckResolver::new();
    let r = resolver.resolve(
        &req("alice", "fs"),
        &ResolverContext {
            parent_grants: &[],
            run_id: None,
        },
    );
    assert!(
        matches!(r, ResolverOutcome::Abstain),
        "BudgetCheck no-budget default → Abstain, got {r:?}"
    );

    // Independent of caller / capability / parent grants: without a budget the
    // gate is never consulted; run_id is irrelevant.
    let parent = active_parent("alice", "fs");
    let r2 = resolver.resolve(
        &req("bob", "http"),
        &ResolverContext {
            parent_grants: std::slice::from_ref(&parent),
            run_id: None,
        },
    );
    assert!(
        matches!(r2, ResolverOutcome::Abstain),
        "BudgetCheck with no injected budget always Abstains, got {r2:?}"
    );
}

#[test]
fn t42_channel_without_approval_port_abstains() {
    // No channel approval port installed: Channel lets the chain fail closed via
    // later resolvers.
    let resolver = ChannelResolver::new();
    let r = resolver.resolve(
        &req("alice", "fs"),
        &ResolverContext {
            parent_grants: &[],
            run_id: None,
        },
    );
    assert!(
        matches!(r, ResolverOutcome::Abstain),
        "Channel with no approval port → Abstain, got {r:?}"
    );

    let parent = active_parent("alice", "fs");
    let r2 = resolver.resolve(
        &req("bob", "messaging"),
        &ResolverContext {
            parent_grants: std::slice::from_ref(&parent),
            run_id: None,
        },
    );
    assert!(
        matches!(r2, ResolverOutcome::Abstain),
        "Channel with no approval port always Abstains, got {r2:?}"
    );
}

#[test]
fn t42_channel_preplayed_approval_is_ignored_until_request_is_delivered() {
    let port = Arc::new(SpoofingApprovalPort::approved());
    let port_dyn: Arc<dyn ChannelApprovalPort> = port.clone();
    let resolver = ChannelResolver::with_approval_port(port_dyn);
    let request = req("alice", "fs");
    let ctx = ResolverContext {
        parent_grants: &[],
        run_id: None,
    };

    let first = resolver.resolve(&request, &ctx);
    assert!(
        matches!(first, ResolverOutcome::Pending),
        "preplayed approval must not approve before delivery, got {first:?}"
    );
    assert_eq!(port.requests().len(), 1, "first call delivers the request");

    let second = resolver.resolve(&request, &ctx);
    assert!(
        matches!(second, ResolverOutcome::Approve(_)),
        "delivered request may consume the approval decision, got {second:?}"
    );
}

#[test]
fn t42_channel_preplayed_denial_is_ignored_until_request_is_delivered() {
    let port = Arc::new(SpoofingApprovalPort::denied("channel-denied"));
    let port_dyn: Arc<dyn ChannelApprovalPort> = port.clone();
    let resolver = ChannelResolver::with_approval_port(port_dyn);
    let request = req("alice", "fs");
    let ctx = ResolverContext {
        parent_grants: &[],
        run_id: None,
    };

    let first = resolver.resolve(&request, &ctx);
    assert!(
        matches!(first, ResolverOutcome::Pending),
        "preplayed denial must not deny before delivery, got {first:?}"
    );
    assert_eq!(port.requests().len(), 1, "first call delivers the request");

    let second = resolver.resolve(&request, &ctx);
    let ResolverOutcome::Deny(reason) = second else {
        panic!("delivered request may consume the denial decision, got {second:?}");
    };
    assert_eq!(reason, "channel-denied");
}

#[test]
fn t42_channel_pending_is_correlated_and_idempotent_then_approved() {
    let port = Arc::new(RecordingApprovalPort::default());
    let port_dyn: Arc<dyn ChannelApprovalPort> = port.clone();
    let resolver = ChannelResolver::with_approval_port(port_dyn);
    let request = req("alice", "fs");
    let ctx = ResolverContext {
        parent_grants: &[],
        run_id: None,
    };

    let first = resolver.resolve(&request, &ctx);
    assert!(
        matches!(first, ResolverOutcome::Pending),
        "first unresolved call → Pending"
    );
    let sent = port.requests();
    assert_eq!(
        sent.len(),
        1,
        "first pending call sends one approval request"
    );
    assert_eq!(sent[0].caller, "alice");
    assert_eq!(sent[0].capability, "fs");
    let request_id = sent[0].request_id.clone();

    let second = resolver.resolve(&request, &ctx);
    assert!(
        matches!(second, ResolverOutcome::Pending),
        "retry while unresolved stays Pending"
    );
    assert_eq!(
        port.requests().len(),
        1,
        "same unresolved request is not sent twice"
    );

    port.approve(&request_id);
    let approved = resolver.resolve(&request, &ctx);
    assert!(
        matches!(approved, ResolverOutcome::Approve(_)),
        "terminal channel approve maps to resolver Approve, got {approved:?}"
    );
}

#[test]
fn t42_channel_approval_is_single_use_for_identical_future_request() {
    let port = Arc::new(RecordingApprovalPort::default());
    let port_dyn: Arc<dyn ChannelApprovalPort> = port.clone();
    let resolver = ChannelResolver::with_approval_port(port_dyn);
    let request = req("alice", "fs");
    let ctx = ResolverContext {
        parent_grants: &[],
        run_id: None,
    };

    assert!(matches!(
        resolver.resolve(&request, &ctx),
        ResolverOutcome::Pending
    ));
    let first_request_id = port.requests()[0].request_id.clone();
    port.approve(&first_request_id);
    assert!(
        matches!(
            resolver.resolve(&request, &ctx),
            ResolverOutcome::Approve(_)
        ),
        "first delivered approval should be consumed"
    );

    let replayed = resolver.resolve(&request, &ctx);
    assert!(
        matches!(replayed, ResolverOutcome::Pending),
        "a later identical request must create a fresh approval request, got {replayed:?}"
    );
    let sent = port.requests();
    assert_eq!(sent.len(), 2, "later identical request is delivered again");
    assert_ne!(
        sent[0].request_id, sent[1].request_id,
        "terminal approvals are tied to one unique channel request id"
    );
}

#[test]
fn t42_channel_fingerprint_canonicalizes_param_order_and_exact_duplicates() {
    let port = Arc::new(RecordingApprovalPort::default());
    let port_dyn: Arc<dyn ChannelApprovalPort> = port.clone();
    let resolver = ChannelResolver::with_approval_port(port_dyn);
    let ctx = ResolverContext {
        parent_grants: &[],
        run_id: None,
    };

    let first = req_with_params(
        "alice",
        "fs",
        &[
            ("write-paths", "/tmp/out"),
            ("read-paths", "/tmp/in"),
            ("read-paths", "/tmp/in"),
        ],
    );
    let same_logical_request = req_with_params(
        "alice",
        "fs",
        &[("read-paths", "/tmp/in"), ("write-paths", "/tmp/out")],
    );

    assert!(matches!(
        resolver.resolve(&first, &ctx),
        ResolverOutcome::Pending
    ));
    assert!(matches!(
        resolver.resolve(&same_logical_request, &ctx),
        ResolverOutcome::Pending
    ));
    assert_eq!(
        port.requests().len(),
        1,
        "caller-controlled parameter order and exact duplicates must not bypass duplicate suppression"
    );
}

#[test]
fn t42_channel_approval_uses_delivered_payload_not_retry_payload() {
    let port = Arc::new(RecordingApprovalPort::default());
    let port_dyn: Arc<dyn ChannelApprovalPort> = port.clone();
    let resolver = ChannelResolver::with_approval_port(port_dyn);
    let ctx = ResolverContext {
        parent_grants: &[],
        run_id: None,
    };

    let delivered = req_with_params(
        "alice",
        "fs",
        &[("read-paths", "/safe"), ("read-paths", "/evil")],
    );
    let retry_same_fingerprint = req_with_params(
        "alice",
        "fs",
        &[("read-paths", "/evil"), ("read-paths", "/safe")],
    );

    assert!(matches!(
        resolver.resolve(&delivered, &ctx),
        ResolverOutcome::Pending
    ));
    let request_id = port.requests()[0].request_id.clone();
    port.approve(&request_id);

    let approved = resolver.resolve(&retry_same_fingerprint, &ctx);
    let ResolverOutcome::Approve(draft) = approved else {
        panic!("approved channel decision should approve, got {approved:?}");
    };
    assert_eq!(
        draft.params,
        delivered.params.unwrap(),
        "terminal approval must grant the exact raw params delivered to the approval backend"
    );
}

#[test]
fn t42_channel_inflight_send_cache_is_bounded_and_fails_closed() {
    let (first_entered_tx, first_entered_rx) = mpsc::channel();
    let (first_release_tx, first_release_rx) = mpsc::channel();
    let port = Arc::new(BlockingFirstFailureApprovalPort::new(
        first_entered_tx,
        first_release_rx,
    ));
    let port_dyn: Arc<dyn ChannelApprovalPort> = port.clone();
    let resolver = Arc::new(ChannelResolver::with_approval_port_and_sent_cache_limit(
        port_dyn, 1,
    ));

    let first_resolver = resolver.clone();
    let first = thread::spawn(move || {
        let request = req_with_justification("alice", "fs", "first");
        first_resolver.resolve(
            &request,
            &ResolverContext {
                parent_grants: &[],
                run_id: None,
            },
        )
    });
    first_entered_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("first delivery attempt should enter the approval port");

    let second = resolver.resolve(
        &req_with_justification("alice", "fs", "second"),
        &ResolverContext {
            parent_grants: &[],
            run_id: None,
        },
    );
    let ResolverOutcome::Deny(reason) = second else {
        let _ = first_release_tx.send(());
        let _ = first.join();
        panic!("full in-flight approval cache must fail closed, got {second:?}");
    };
    assert_eq!(reason, "channel-approval-unavailable");
    assert_eq!(
        port.attempts().len(),
        1,
        "cache-full request must not enqueue another approval delivery"
    );

    first_release_tx
        .send(())
        .expect("first delivery release receiver should still be open");
    let first = first.join().expect("first resolver thread panicked");
    assert!(
        matches!(first, ResolverOutcome::Deny(_)),
        "first blocked delivery fixture fails once after release, got {first:?}"
    );
}

#[test]
fn t42_channel_pending_send_cache_is_bounded() {
    let port = Arc::new(RecordingApprovalPort::default());
    let port_dyn: Arc<dyn ChannelApprovalPort> = port.clone();
    let resolver = ChannelResolver::with_approval_port_and_sent_cache_limit(port_dyn, 2);
    let ctx = ResolverContext {
        parent_grants: &[],
        run_id: None,
    };

    let first = req_with_justification("alice", "fs", "one");
    let second = req_with_justification("alice", "fs", "two");
    let third = req_with_justification("alice", "fs", "three");

    assert!(matches!(
        resolver.resolve(&first, &ctx),
        ResolverOutcome::Pending
    ));
    assert!(matches!(
        resolver.resolve(&second, &ctx),
        ResolverOutcome::Pending
    ));
    assert!(matches!(
        resolver.resolve(&third, &ctx),
        ResolverOutcome::Pending
    ));
    assert_eq!(
        port.requests().len(),
        3,
        "three unique pending requests are sent"
    );

    assert!(matches!(
        resolver.resolve(&third, &ctx),
        ResolverOutcome::Pending
    ));
    assert_eq!(
        port.requests().len(),
        3,
        "recent pending request remains idempotent inside the bounded cache"
    );

    assert!(matches!(
        resolver.resolve(&first, &ctx),
        ResolverOutcome::Pending
    ));
    assert_eq!(
        port.requests().len(),
        4,
        "oldest pending request is evicted when the bounded cache fills"
    );
}

#[test]
fn t42_channel_send_failure_is_not_cached_as_pending() {
    let port = Arc::new(FailingOnceApprovalPort::new());
    let port_dyn: Arc<dyn ChannelApprovalPort> = port.clone();
    let resolver = ChannelResolver::with_approval_port(port_dyn);
    let request = req("alice", "fs");
    let ctx = ResolverContext {
        parent_grants: &[],
        run_id: None,
    };

    let first = resolver.resolve(&request, &ctx);
    let ResolverOutcome::Deny(reason) = first else {
        panic!("failed approval delivery must fail closed, got {first:?}");
    };
    assert!(
        reason == "channel-approval-unavailable" && !reason.contains("queue unavailable"),
        "failure reason should be public and opaque, got {reason:?}"
    );
    assert_eq!(port.attempts().len(), 1, "first call attempted delivery");

    let second = resolver.resolve(&request, &ctx);
    assert!(
        matches!(second, ResolverOutcome::Pending),
        "retry after delivery failure should attempt again and become Pending, got {second:?}"
    );
    assert_eq!(
        port.attempts().len(),
        2,
        "failed delivery must not occupy the duplicate-suppression cache"
    );
}

#[test]
fn t42_channel_concurrent_send_failure_does_not_return_false_pending() {
    let (first_entered_tx, first_entered_rx) = mpsc::channel();
    let (first_release_tx, first_release_rx) = mpsc::channel();
    let port = Arc::new(BlockingFirstFailureApprovalPort::new(
        first_entered_tx,
        first_release_rx,
    ));
    let port_dyn: Arc<dyn ChannelApprovalPort> = port.clone();
    let resolver = Arc::new(ChannelResolver::with_approval_port(port_dyn));

    let first_resolver = resolver.clone();
    let first = thread::spawn(move || {
        let request = req("alice", "fs");
        first_resolver.resolve(
            &request,
            &ResolverContext {
                parent_grants: &[],
                run_id: None,
            },
        )
    });
    first_entered_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("first delivery attempt should enter the approval port");

    let (second_done_tx, second_done_rx) = mpsc::channel();
    let second_resolver = resolver.clone();
    let second = thread::spawn(move || {
        let request = req("alice", "fs");
        let outcome = second_resolver.resolve(
            &request,
            &ResolverContext {
                parent_grants: &[],
                run_id: None,
            },
        );
        let _ = second_done_tx.send(());
        outcome
    });
    if second_done_rx
        .recv_timeout(Duration::from_millis(100))
        .is_ok()
    {
        let _ = first_release_tx.send(());
        let early = second.join().expect("second resolver thread panicked");
        let _ = first.join();
        panic!("duplicate returned before delivery settled: {early:?}");
    }

    first_release_tx
        .send(())
        .expect("first delivery release receiver should still be open");
    let first = first.join().expect("first resolver thread panicked");
    let second = second.join().expect("second resolver thread panicked");

    let ResolverOutcome::Deny(reason) = first else {
        panic!("first delivery failure must fail closed, got {first:?}");
    };
    assert!(
        reason == "channel-approval-unavailable" && !reason.contains("queue unavailable"),
        "failure reason should be public and opaque, got {reason:?}"
    );
    assert!(
        matches!(second, ResolverOutcome::Pending),
        "duplicate should retry delivery after the failed first send and become Pending, got {second:?}"
    );
    assert_eq!(
        port.attempts().len(),
        2,
        "concurrent failed delivery must not let a duplicate observe false Pending"
    );
}

#[test]
fn t42_channel_request_approval_panic_is_not_cached_as_delivering() {
    let port = Arc::new(PanickingOnceApprovalPort::new());
    let port_dyn: Arc<dyn ChannelApprovalPort> = port.clone();
    let resolver = ChannelResolver::with_approval_port(port_dyn);
    let request = req("alice", "fs");
    let ctx = ResolverContext {
        parent_grants: &[],
        run_id: None,
    };

    let first = resolver.resolve(&request, &ctx);
    let ResolverOutcome::Deny(reason) = first else {
        panic!("panicking approval delivery must fail closed, got {first:?}");
    };
    assert_eq!(
        reason, "channel-approval-unavailable",
        "panic detail must not leak to the guest"
    );
    assert_eq!(port.attempts().len(), 1, "first call attempted delivery");

    let second = resolver.resolve(&request, &ctx);
    assert!(
        matches!(second, ResolverOutcome::Pending),
        "retry after caught panic should not block on stale Delivering state, got {second:?}"
    );
    assert_eq!(
        port.attempts().len(),
        2,
        "caught panic must clear the duplicate-suppression cache"
    );
}

#[test]
fn t42_channel_request_approval_timeout_is_not_cached_as_delivering() {
    let (release_tx, release_rx) = mpsc::channel();
    let port = Arc::new(BlockingApprovalPort::new(release_rx));
    let port_dyn: Arc<dyn ChannelApprovalPort> = port.clone();
    let resolver = ChannelResolver::with_approval_port(port_dyn);
    let request = req("alice", "fs");
    let ctx = ResolverContext {
        parent_grants: &[],
        run_id: None,
    };

    let first = resolver.resolve(&request, &ctx);
    let ResolverOutcome::Deny(reason) = first else {
        panic!("timed-out approval delivery must fail closed, got {first:?}");
    };
    assert_eq!(reason, "channel-approval-unavailable");
    assert_eq!(port.attempts().len(), 1, "first call attempted delivery");
    let _ = release_tx.send(());

    let second = resolver.resolve(&request, &ctx);
    let ResolverOutcome::Deny(reason) = second else {
        panic!(
            "retry should attempt delivery again rather than hang on stale state, got {second:?}"
        );
    };
    assert_eq!(reason, "channel-approval-unavailable");
    assert_eq!(
        port.attempts().len(),
        2,
        "timed-out delivery must clear the duplicate-suppression cache"
    );
}

#[test]
fn t42_channel_denial_maps_to_resolver_deny() {
    let port = Arc::new(RecordingApprovalPort::default());
    let port_dyn: Arc<dyn ChannelApprovalPort> = port.clone();
    let resolver = ChannelResolver::with_approval_port(port_dyn);
    let request = req("alice", "fs");
    let ctx = ResolverContext {
        parent_grants: &[],
        run_id: None,
    };

    let first = resolver.resolve(&request, &ctx);
    assert!(matches!(first, ResolverOutcome::Pending));
    let request_id = port.requests()[0].request_id.clone();
    port.deny(&request_id, "channel-denied");

    let denied = resolver.resolve(&request, &ctx);
    let ResolverOutcome::Deny(reason) = denied else {
        panic!("terminal channel denial maps to resolver Deny, got {denied:?}");
    };
    assert_eq!(reason, "channel-denied");
}

#[test]
fn t42_channel_denial_reason_is_opaque_to_guest() {
    let port = Arc::new(RecordingApprovalPort::default());
    let port_dyn: Arc<dyn ChannelApprovalPort> = port.clone();
    let resolver = ChannelResolver::with_approval_port(port_dyn);
    let request = req("alice", "fs");
    let ctx = ResolverContext {
        parent_grants: &[],
        run_id: None,
    };

    assert!(matches!(
        resolver.resolve(&request, &ctx),
        ResolverOutcome::Pending
    ));
    let request_id = port.requests()[0].request_id.clone();
    port.deny(
        &request_id,
        &format!("secret-token\x1b[31m\n{}", "x".repeat(1024)),
    );

    let denied = resolver.resolve(&request, &ctx);
    let ResolverOutcome::Deny(reason) = denied else {
        panic!("terminal channel denial maps to resolver Deny, got {denied:?}");
    };
    assert_eq!(reason, "channel-denied");
    assert!(!reason.contains("secret-token"));
    assert!(!reason.contains('\x1b'));
}

#[test]
fn t42_chain_reaches_channel_when_parent_backend_absent() {
    let (store, bus, _h) = make_store();
    let bus_dyn: Arc<dyn EventBusEmit> = bus.clone();
    let port = Arc::new(RecordingApprovalPort::default());
    let port_dyn: Arc<dyn ChannelApprovalPort> = port.clone();
    let chain = ResolverChain::new(vec![
        Box::new(SubsetAutoApproveResolver::new(Arc::new(
            SubsetValidatorImpl::new(),
        ))) as Box<dyn Resolver>,
        Box::new(BudgetCheckResolver::new()),
        Box::new(ParentApprovalResolver::new_abstain()),
        Box::new(ChannelResolver::with_approval_port(port_dyn)),
        Box::new(AutoDenyResolver::new()),
    ]);

    let result = chain.evaluate(
        req("alice", "fs"),
        ResolverContext {
            parent_grants: &[],
            run_id: None,
        },
        &store,
        &bus_dyn,
    );
    assert!(
        matches!(result, ChainDecision::Pending),
        "Channel Pending short-circuits"
    );
    let invoked: Vec<_> = bus
        .all_of("resolver.invoked")
        .into_iter()
        .map(|e| e.payload)
        .collect();
    let resolver_types: Vec<_> = invoked
        .iter()
        .filter_map(|payload| payload["resolver_type"].as_str())
        .collect();
    assert_eq!(
        resolver_types,
        vec![
            "SubsetAutoApprove",
            "BudgetCheck",
            "ParentApproval",
            "Channel"
        ]
    );
    assert_eq!(
        port.requests().len(),
        1,
        "Channel sent one approval request"
    );
}

//! CONTRACT-123 `GrantApprovalIntake` integration witnesses (MODULE-013 AC-24).
//!
//! Drives the operator approval loop end to end against a REAL `GrantStore` +
//! `ResolverChain` (with the intake injected as the `ChannelApprovalPort`) +
//! `SubsetValidatorImpl` + `PresetRegistry` + a capturing EventBus. Nothing is
//! mocked (witness-floor). AI-09/AI-09-barrier lives in-src (`src/approval_intake.rs`)
//! because it reaches `pub(crate)` barrier helpers.

mod common;

use std::sync::Arc;

use advance_shared_types::traits::EventBusEmit;
use cap_grant::data::{
    CapParam, ChainDecision, Grant, GrantDraft, GrantId, GrantIssuer, GrantProvenance,
    GrantRequest, GrantStatus, GrantTtl,
};
use cap_grant::error::CapGrantError;
use cap_grant::preset::PresetRegistry;
use cap_grant::resolver::{
    AutoDenyResolver, ChannelApprovalDecision, ChannelApprovalError, ChannelApprovalPort,
    ChannelApprovalRequest, ChannelResolver, ResolverChain, ResolverContext,
    SubsetAutoApproveResolver,
};
use cap_grant::store::GrantStore;
use cap_grant::subset::{SubsetValidator, SubsetValidatorImpl};
use cap_grant::{GrantApprovalIntake, MAX_PENDING_PER_CALLER, MAX_PENDING_REQUESTS};
use chrono::Utc;

use common::{make_store, RecordingBus};

/// Build a store + recording bus + intake + a production-shaped chain
/// (`[SubsetAutoApprove, Channel(intake), AutoDeny]`) sharing one EventBus.
fn setup() -> (
    Arc<GrantStore>,
    Arc<RecordingBus>,
    Arc<GrantApprovalIntake>,
    ResolverChain,
) {
    let (store, bus, _handle) = make_store();
    let validator: Arc<dyn SubsetValidator> = Arc::new(SubsetValidatorImpl::new());
    let bus_dyn: Arc<dyn EventBusEmit> = bus.clone();
    let intake = Arc::new(GrantApprovalIntake::new(
        store.clone(),
        validator.clone(),
        Arc::new(PresetRegistry::with_builtins()),
        bus_dyn,
    ));
    let chain = ResolverChain::new(vec![
        Box::new(SubsetAutoApproveResolver::new(validator)),
        Box::new(ChannelResolver::with_approval_port(
            intake.clone() as Arc<dyn ChannelApprovalPort>
        )),
        Box::new(AutoDenyResolver::new()),
    ]);
    (store, bus, intake, chain)
}

/// A request for `fs` read-paths with no covering parent grant — reaches the
/// Channel resolver (SubsetAutoApprove abstains). Stable fingerprint across
/// calls (identical fields).
fn fs_request(paths: &str) -> GrantRequest {
    GrantRequest {
        caller: "agent:a".to_string(),
        capability: "fs".to_string(),
        params: Some(vec![CapParam {
            key: "read-paths".to_string(),
            value: paths.to_string(),
        }]),
        ttl: GrantTtl::Once,
        justification: Some("intake test".to_string()),
    }
}

fn read_paths(value: &str) -> Vec<CapParam> {
    vec![CapParam {
        key: "read-paths".to_string(),
        value: value.to_string(),
    }]
}

fn fs_grant(id: &str, grantee: &str, paths: &str) -> Grant {
    Grant {
        id: GrantId::new(id),
        grantee: grantee.to_string(),
        capability: "fs".to_string(),
        params: read_paths(paths),
        ttl: GrantTtl::Lifecycle,
        issuer: GrantIssuer::Admin,
        provenance: GrantProvenance::Requested,
        status: GrantStatus::Active,
        created_at: Utc::now(),
        expires_at: None,
    }
}

/// Run the chain over `req`, snapshotting parent grants like production.
fn drive(
    chain: &ResolverChain,
    store: &GrantStore,
    bus: &Arc<RecordingBus>,
    req: GrantRequest,
) -> ChainDecision {
    let parents = store.list_by_grantee(&req.caller);
    let ctx = ResolverContext {
        parent_grants: &parents,
        run_id: None,
    };
    let bus_dyn: Arc<dyn EventBusEmit> = bus.clone();
    chain.evaluate(req, ctx, store, &bus_dyn)
}

/// True iff the bus captured a `resolver.invoked` emitted by the intake
/// (`resolver_type == "GrantApprovalIntake"`) with the given decision.
fn intake_invoked(bus: &RecordingBus, decision: &str) -> bool {
    bus.all_of("resolver.invoked").iter().any(|e| {
        e.payload.get("resolver_type").and_then(|v| v.as_str()) == Some("GrantApprovalIntake")
            && e.payload.get("decision").and_then(|v| v.as_str()) == Some(decision)
    })
}

/// A fail-closed port mirroring the production `UnavailableChannelApprovalPort`
/// (no operator backend installed).
struct UnavailablePort;
impl ChannelApprovalPort for UnavailablePort {
    fn decision(&self, _request_id: &str) -> ChannelApprovalDecision {
        ChannelApprovalDecision::Pending
    }
    fn request_approval(
        &self,
        _request: ChannelApprovalRequest,
    ) -> std::result::Result<(), ChannelApprovalError> {
        Err(ChannelApprovalError::new("unavailable"))
    }
}

// ---- AI-01/02: park + list + retry-without-decision --------------------------

#[test]
fn ai_01_request_parks_pending_and_is_listed() {
    let (store, bus, intake, chain) = setup();
    let d = drive(&chain, &store, &bus, fs_request("/a,/b"));
    assert_eq!(
        d,
        ChainDecision::Pending,
        "no covering parent → parks pending"
    );
    let pending = intake.list_pending();
    assert_eq!(pending.len(), 1, "exactly one parked request");
    assert_eq!(pending[0].caller, "agent:a");
    assert_eq!(pending[0].capability, "fs");
    assert_eq!(pending[0].params, Some(read_paths("/a,/b")));
}

#[test]
fn ai_02_retry_without_decision_stays_pending() {
    let (store, bus, intake, chain) = setup();
    assert_eq!(
        drive(&chain, &store, &bus, fs_request("/a,/b")),
        ChainDecision::Pending
    );
    assert_eq!(
        drive(&chain, &store, &bus, fs_request("/a,/b")),
        ChainDecision::Pending,
        "no operator decision → still pending"
    );
    assert_eq!(intake.list_pending().len(), 1);
}

// ---- AI-03/04/05/06: approve / deny / narrow ---------------------------------

#[test]
fn ai_03_approve_then_retry_grants() {
    let (store, bus, intake, chain) = setup();
    drive(&chain, &store, &bus, fs_request("/a,/b"));
    let rid = intake.list_pending()[0].request_id.clone();

    intake.approve(&rid).expect("approve");
    assert!(
        intake_invoked(&bus, "approve"),
        "action-time resolver.invoked(GrantApprovalIntake, approve)"
    );

    let d = drive(&chain, &store, &bus, fs_request("/a,/b"));
    assert!(
        matches!(d, ChainDecision::Approved(_)),
        "retry approves, got {d:?}"
    );
    assert!(bus.count_of("grant.issued") >= 1, "grant.issued on approve");
    assert!(
        intake.list_pending().is_empty(),
        "single-use: consumed via resolved()"
    );
}

#[test]
fn ai_04_deny_then_retry_denied() {
    let (store, bus, intake, chain) = setup();
    drive(&chain, &store, &bus, fs_request("/a,/b"));
    let rid = intake.list_pending()[0].request_id.clone();

    intake.deny(&rid, "operator rejected").expect("deny");
    assert!(
        intake_invoked(&bus, "deny"),
        "resolver.invoked(GrantApprovalIntake, deny)"
    );

    let grants_before = bus.count_of("grant.issued");
    let d = drive(&chain, &store, &bus, fs_request("/a,/b"));
    assert!(
        matches!(d, ChainDecision::Denied(_)),
        "retry denied, got {d:?}"
    );
    assert_eq!(
        bus.count_of("grant.issued"),
        grants_before,
        "deny issues no grant"
    );
}

#[test]
fn ai_05_narrow_then_retry_grants_narrowed_params() {
    let (store, bus, intake, chain) = setup();
    drive(&chain, &store, &bus, fs_request("/a,/b"));
    let rid = intake.list_pending()[0].request_id.clone();

    // Narrow the 2-path request to just "/a" (a valid subset).
    intake
        .narrow(&rid, read_paths("/a"))
        .expect("narrow to a valid subset");
    assert!(
        intake_invoked(&bus, "approve"),
        "narrow emits approve audit"
    );

    let d = drive(&chain, &store, &bus, fs_request("/a,/b"));
    let ChainDecision::Approved(id) = d else {
        panic!("narrow retry should approve, got {d:?}");
    };
    let g = store.get(id.as_str()).expect("issued grant exists");
    assert_eq!(
        g.params,
        read_paths("/a"),
        "issued grant carries the NARROWED params, not the 2-path request"
    );
}

#[test]
fn ai_06_narrow_non_subset_rejected_stays_pending() {
    let (store, bus, intake, chain) = setup();
    drive(&chain, &store, &bus, fs_request("/a,/b"));
    let rid = intake.list_pending()[0].request_id.clone();

    // "/c" is not a prefix-subpath of "/a" or "/b" → SubsetViolation.
    let err = intake
        .narrow(&rid, read_paths("/c"))
        .expect_err("non-subset narrow must be rejected");
    assert!(
        matches!(err, CapGrantError::SubsetViolation(_)),
        "non-subset narrow → SubsetViolation, got {err:?}"
    );
    assert_eq!(intake.list_pending().len(), 1, "fail-closed: stays pending");
    assert_eq!(
        drive(&chain, &store, &bus, fs_request("/a,/b")),
        ChainDecision::Pending,
        "retry after a rejected narrow is still pending"
    );
}

// ---- AI-07: revoke -----------------------------------------------------------

#[test]
fn ai_07_revoke_cascades_root_and_descendant() {
    let (store, bus, intake, _chain) = setup();
    let validator = SubsetValidatorImpl::new();
    store
        .insert_dynamic(fs_grant("root", "agent:a", "/a,/b"))
        .expect("seed root");
    let _child = store
        .delegate_grant(
            "root",
            "agent:b",
            GrantDraft {
                capability: "fs".to_string(),
                params: read_paths("/a"),
                ttl: GrantTtl::Once,
            },
            "agent:a",
            &validator,
        )
        .expect("delegate a child under root");

    let n = intake.revoke("root").expect("revoke root");
    assert!(n >= 2, "revoke returns root + descendant count, got {n}");
    assert!(
        bus.count_of("grant.revoked") >= 2,
        "grant.revoked per grant"
    );
    assert_eq!(store.get("root").unwrap().status, GrantStatus::Revoked);
}

// ---- AI-08/08b: apply preset -------------------------------------------------

#[test]
fn ai_08_apply_restrict_revokes_all_creates_none() {
    let (store, bus, intake, _chain) = setup();
    store
        .insert_dynamic(fs_grant("g1", "agent:a", "/a"))
        .expect("seed g1");
    store
        .insert_dynamic(fs_grant("g2", "agent:a", "/b"))
        .expect("seed g2");

    let created = intake
        .apply_preset("agent:a", "restrict")
        .expect("apply restrict");
    assert!(created.is_empty(), "restrict creates no grants");

    let evt = bus
        .first_of("preset.applied")
        .expect("preset.applied emitted");
    assert_eq!(
        evt.payload["grants_revoked"], 2,
        "both dynamic grants revoked"
    );
    assert_eq!(evt.payload["grants_created"], 0);

    let active_dyn: Vec<GrantId> = store
        .list_by_grantee("agent:a")
        .into_iter()
        .filter(|g| {
            g.status == GrantStatus::Active
                && !matches!(g.provenance, GrantProvenance::StaticConfig)
        })
        .map(|g| g.id)
        .collect();
    assert!(active_dyn.is_empty(), "no active dynamic grants remain");
}

#[test]
fn ai_08b_apply_custom_preset_creates_within_existing_authority() {
    let (store, bus, _handle) = make_store();
    let validator: Arc<dyn SubsetValidator> = Arc::new(SubsetValidatorImpl::new());
    let mut presets = PresetRegistry::with_builtins();
    let yaml = r#"
name: intake-custom
resolver-chain:
  - AutoDeny
default-ttl: lifecycle
grants:
  - capability: fs
    params:
      - key: read-paths
        value: /tmp/preset/*
    ttl: lifecycle
"#;
    let value: serde_yml::Value = serde_yml::from_str(yaml).expect("parse custom preset");
    presets
        .load_custom_value(&value)
        .expect("custom preset loads");
    let bus_dyn: Arc<dyn EventBusEmit> = bus.clone();
    let intake = GrantApprovalIntake::new(store.clone(), validator, Arc::new(presets), bus_dyn);

    // Pre-seed a COVERING grant so the preset's grant passes the Step-2 subset
    // check (apply_preset re-scopes within the target's EXISTING authority).
    store
        .insert_dynamic(fs_grant("cover", "agent:a", "/tmp/preset/*"))
        .expect("seed covering grant");

    let created = intake
        .apply_preset("agent:a", "intake-custom")
        .expect("apply custom preset");
    assert_eq!(created.len(), 1, "custom preset's 1 grant created");
    let evt = bus
        .first_of("preset.applied")
        .expect("preset.applied emitted");
    assert_eq!(evt.payload["grants_created"], 1);
}

// ---- AI-09b: stale approval superseded by preset (sequential) ----------------

#[test]
fn ai_09b_approve_then_preset_supersedes_stale_approval() {
    let (store, bus, intake, chain) = setup();
    drive(&chain, &store, &bus, fs_request("/a,/b"));
    let rid = intake.list_pending()[0].request_id.clone();
    intake.approve(&rid).expect("approve");

    // Operator applies restrict to the target BEFORE the guest retries.
    intake
        .apply_preset("agent:a", "restrict")
        .expect("apply restrict");

    // Retry observes the superseded (terminal-Denied) decision — NOT auto-grant,
    // NOT invisible-pending.
    let d = drive(&chain, &store, &bus, fs_request("/a,/b"));
    assert!(
        matches!(d, ChainDecision::Denied(_)),
        "stale approval superseded by preset → Denied, got {d:?}"
    );
    assert!(intake.list_pending().is_empty(), "consumed on retry");

    // A fresh request re-pends (both caches re-synced).
    assert_eq!(
        drive(&chain, &store, &bus, fs_request("/a,/b")),
        ChainDecision::Pending,
        "fresh request re-pends after supersede"
    );
}

// ---- AI-10: anti-fake-green discriminator ------------------------------------

#[test]
fn ai_10_discriminator_intake_is_load_bearing() {
    // (a) No operator backend (fail-closed port) → the request is Denied.
    let (store_a, bus_a, _ha) = make_store();
    let validator: Arc<dyn SubsetValidator> = Arc::new(SubsetValidatorImpl::new());
    let chain_a = ResolverChain::new(vec![
        Box::new(SubsetAutoApproveResolver::new(validator)),
        Box::new(ChannelResolver::with_approval_port(Arc::new(
            UnavailablePort,
        ))),
        Box::new(AutoDenyResolver::new()),
    ]);
    let d_a = drive(&chain_a, &store_a, &bus_a, fs_request("/a,/b"));
    assert!(
        matches!(d_a, ChainDecision::Denied(_)),
        "no backend → Denied (channel-approval-unavailable), got {d_a:?}"
    );

    // (b) With the intake + an operator approve → Approved. The intake is
    // load-bearing: swapping it out flips approved→denied.
    let (store_b, bus_b, intake, chain_b) = setup();
    drive(&chain_b, &store_b, &bus_b, fs_request("/a,/b"));
    let rid = intake.list_pending()[0].request_id.clone();
    intake.approve(&rid).unwrap();
    let d_b = drive(&chain_b, &store_b, &bus_b, fs_request("/a,/b"));
    assert!(
        matches!(d_b, ChainDecision::Approved(_)),
        "intake + approve → Approved, got {d_b:?}"
    );
}

// ---- AI-13: cleanup (resolved consume) + fail-closed overflow -----------------

#[test]
fn ai_13a_resolved_consumes_registry_entry() {
    let (store, bus, intake, chain) = setup();
    drive(&chain, &store, &bus, fs_request("/a,/b"));
    assert_eq!(intake.total_entries(), 1, "one parked entry");
    let rid = intake.list_pending()[0].request_id.clone();
    intake.approve(&rid).unwrap();
    assert_eq!(
        intake.total_entries(),
        1,
        "approved entry still tracked until the retry consumes it"
    );
    drive(&chain, &store, &bus, fs_request("/a,/b"));
    assert_eq!(
        intake.total_entries(),
        0,
        "resolved() removed the consumed entry (list_pending, Pending-only, can't observe this)"
    );
    assert!(intake.list_pending().is_empty());
}

#[test]
fn ai_13b_overflow_fails_closed_never_evicts_live_pending() {
    let (store, bus, _handle) = make_store();
    let validator: Arc<dyn SubsetValidator> = Arc::new(SubsetValidatorImpl::new());
    let bus_dyn: Arc<dyn EventBusEmit> = bus.clone();
    let intake = GrantApprovalIntake::new(
        store,
        validator,
        Arc::new(PresetRegistry::with_builtins()),
        bus_dyn,
    );

    // Fill the GLOBAL 1024 cap with LIVE pending entries, distributed across
    // enough distinct callers to stay within each agent's per-caller quota
    // (MAX_PENDING_REQUESTS / MAX_PENDING_PER_CALLER = 16 callers × 64).
    let callers = MAX_PENDING_REQUESTS / MAX_PENDING_PER_CALLER;
    for c in 0..callers {
        for i in 0..MAX_PENDING_PER_CALLER {
            let req = channel_req(&format!("agent:{c}"), &format!("r{c}-{i}"));
            intake.request_approval(req).expect("park within both caps");
        }
    }
    assert_eq!(intake.total_entries(), MAX_PENDING_REQUESTS);

    // A fresh caller (within its own per-agent quota) → the GLOBAL cap is full,
    // all 1024 are live Pending, no TERMINAL entry to evict → fail closed (no live
    // Pending is evicted).
    let overflow = channel_req("agent:overflow", "overflow");
    assert!(
        intake.request_approval(overflow).is_err(),
        "overflow fails closed when all 1024 are live pending"
    );
    assert_eq!(
        intake.total_entries(),
        MAX_PENDING_REQUESTS,
        "no live pending entry was evicted"
    );
}

// ---- AI-14: take_approved is a single-use atomic consume (anti-fail-open) -----

#[test]
fn ai_14_take_approved_consumes_atomically_no_double_grant() {
    let (store, bus, intake, chain) = setup();
    drive(&chain, &store, &bus, fs_request("/a,/b"));
    let rid = intake.list_pending()[0].request_id.clone();
    intake
        .narrow(&rid, read_paths("/a"))
        .expect("narrow to a subset");

    // The winning retry atomically consumes + reads the narrowed params.
    let first = intake.take_approved(&rid);
    assert_eq!(
        first,
        Some(Some(read_paths("/a"))),
        "winning retry gets the narrowed params"
    );
    // A racing second retry gets None — NOT Some(None). Some(None) would let the
    // ChannelResolver fall back to the WIDER original draft (a fail-open leak that
    // grants /a,/b after the operator narrowed to /a).
    let second = intake.take_approved(&rid);
    assert_eq!(
        second, None,
        "a second retry cannot re-consume — no wider-grant fallback"
    );
    assert_eq!(intake.total_entries(), 0, "entry consumed exactly once");
}

// ---- AI-15: apply_preset name pre-check preserves the pending queue -----------

#[test]
fn ai_15_apply_preset_bad_name_preserves_pending_queue() {
    let (store, bus, intake, chain) = setup();
    drive(&chain, &store, &bus, fs_request("/a,/b"));
    assert_eq!(intake.list_pending().len(), 1);

    // A typo'd (unknown but well-formed) preset name → PresetNotFound, WITHOUT
    // nuking the in-flight approval queue (the pre-check precedes invalidation).
    let err = intake
        .apply_preset("agent:a", "no-such-preset")
        .expect_err("unknown preset");
    assert!(
        matches!(err, CapGrantError::PresetNotFound(_)),
        "unknown preset → PresetNotFound, got {err:?}"
    );
    assert_eq!(
        intake.list_pending().len(),
        1,
        "typo did not invalidate the pending queue"
    );

    // A malformed (control-byte) name → InvalidConfig (bounded, no raw echo), and
    // still does not invalidate.
    let err2 = intake
        .apply_preset("agent:a", "bad\u{7}name")
        .expect_err("control-byte preset name");
    assert!(
        matches!(err2, CapGrantError::InvalidConfig(_)),
        "control-byte name → InvalidConfig, got {err2:?}"
    );
    assert_eq!(
        intake.list_pending().len(),
        1,
        "malformed name did not invalidate the pending queue"
    );
}

// ---- AI-16: per-agent pending quota (cross-agent DoS defense) -----------------

fn channel_req(caller: &str, request_id: &str) -> ChannelApprovalRequest {
    ChannelApprovalRequest {
        request_id: request_id.to_string(),
        caller: caller.to_string(),
        capability: "fs".to_string(),
        params: None,
        ttl: GrantTtl::Once,
        justification: None,
    }
}

#[test]
fn ai_16_per_agent_pending_quota_prevents_cross_agent_starvation() {
    let (store, bus, _handle) = make_store();
    let validator: Arc<dyn SubsetValidator> = Arc::new(SubsetValidatorImpl::new());
    let bus_dyn: Arc<dyn EventBusEmit> = bus.clone();
    let intake = GrantApprovalIntake::new(
        store,
        validator,
        Arc::new(PresetRegistry::with_builtins()),
        bus_dyn,
    );

    // agent:a parks exactly its per-agent quota of live pending requests.
    for i in 0..MAX_PENDING_PER_CALLER {
        intake
            .request_approval(channel_req("agent:a", &format!("a{i}")))
            .expect("within the per-agent quota");
    }
    // The next request from the SAME agent is denied (fail-closed) — it cannot
    // monopolize the shared registry.
    assert!(
        intake
            .request_approval(channel_req("agent:a", "a-over"))
            .is_err(),
        "per-agent pending quota is enforced"
    );
    // A DIFFERENT agent is NOT starved — it retains capacity.
    assert!(
        intake
            .request_approval(channel_req("agent:b", "b0"))
            .is_ok(),
        "other agents retain capacity (no cross-agent starvation)"
    );
}

// ---- AI-17: narrow param bounds (defense-in-depth) ---------------------------

#[test]
fn ai_17_narrow_rejects_oversized_params() {
    let (store, bus, intake, chain) = setup();
    drive(&chain, &store, &bus, fs_request("/a,/b"));
    let rid = intake.list_pending()[0].request_id.clone();

    // A narrow whose value exceeds the 4096-byte cap → InvalidConfig (bounded),
    // BEFORE subset validation, and does NOT decide the request.
    let oversized = vec![CapParam {
        key: "read-paths".to_string(),
        value: "x".repeat(5000),
    }];
    let err = intake
        .narrow(&rid, oversized)
        .expect_err("oversized narrow must be rejected");
    assert!(
        matches!(err, CapGrantError::InvalidConfig(_)),
        "oversized narrow → InvalidConfig, got {err:?}"
    );
    assert_eq!(
        intake.list_pending().len(),
        1,
        "a rejected narrow leaves the request pending"
    );
}

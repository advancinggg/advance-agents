//! SYS-J-13 — an agent calls `request-capability`; the runtime walks the resolver chain,
//! emitting `resolver.invoked` per resolver, and on approve issues a grant. Plus the TtlSweeper
//! auto-expiry leg. Chain: MODULE-013 (cap-grant) → MODULE-004 (runtime) → MODULE-019
//! (events).
//!
//! Witnessed over the REAL wired `SystemUnderTest` (production composition root, real cap-grant
//! `ResolverChain` + `GrantStore` + `GrantCheckImpl` + real EventBus JSONL/SQLite writes) via a
//! real guest turn (host-authoritative `agent:harness` identity through the real
//! `CapabilityInjector` L1 gate).
//! The bootstrap `"grant"` self-management grant is pre-seeded (every agent-grant host fn is L1-gated
//! under capability `"grant"`); scenario grants are pre-seeded via the colon-tolerant
//! `insert_dynamic`. Guest-turn assertions bind to real EventBus SQLite rows, WIT projection
//! reads (`active-grants`), and the fixture guest's outbound replies.
//!
//! Active: SYS-AC-037 (approve/deny/pending after the walk), SYS-AC-038 (one resolver.invoked per
//! resolver that runs), SYS-AC-039 (approve → grant.issued + appears in active-grants; restrict →
//! denied), SYS-AC-204 (Duration/until TTL auto-expired by the real spawned TtlSweeper), SYS-AC-203 +
//! SYS-AC-262 (apply-preset over the canonical `agent:harness` caller — un-deferred 2026-06-06 by
//! the colon-id reconciliation in cap-grant `store.rs`/`preset.rs`; a real guest turn now drives
//! apply-preset).

#[path = "d_grant/mod.rs"]
mod d_grant;
use d_grant::*;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use advance_run_manager::{RunConfig, RunManager};
use advance_shared_types::event::Event;
use advance_shared_types::run::RoundResult;
use advance_shared_types::traits::{EventBusEmit, RunBudget};
use cap_grant::data::{GrantStatus, GrantTtl};
use cap_grant::{
    ChannelApprovalDecision, ChannelApprovalError, ChannelApprovalPort, ChannelApprovalRequest,
    PresetRegistry,
};
use serde_json::Value;
use serde_yml::Value as YamlValue;
use system_acceptance::{
    Cap, DbEventRow, EventSink, GrantChain, GrantMode, SystemUnderTest, AGENT_ID,
};
use wasmtime::component::Val;

struct NoopBus;

impl EventBusEmit for NoopBus {
    fn emit(&self, _event: Event) {}
}

#[derive(Default)]
struct RecordingChannelApproval {
    requests: Mutex<Vec<ChannelApprovalRequest>>,
}

impl RecordingChannelApproval {
    fn requests(&self) -> Vec<ChannelApprovalRequest> {
        self.requests.lock().unwrap().clone()
    }
}

impl ChannelApprovalPort for RecordingChannelApproval {
    fn decision(&self, _request_id: &str) -> ChannelApprovalDecision {
        ChannelApprovalDecision::Pending
    }

    fn request_approval(
        &self,
        request: ChannelApprovalRequest,
    ) -> Result<(), ChannelApprovalError> {
        self.requests.lock().unwrap().push(request);
        Ok(())
    }
}

async fn active_grants_projection(sut: &SystemUnderTest) -> Vec<(String, String, String, String)> {
    let out = sut
        .call_host_fn_n(
            "grant",
            cap_grant::AGENT_GRANT_NAMESPACE,
            "active-grants",
            vec![],
            1,
        )
        .await
        .expect("active-grants host fn");
    let [Val::Result(Ok(Some(inner)))] = out.as_slice() else {
        panic!("expected active-grants ok result, got {out:?}");
    };
    let Val::List(grants) = inner.as_ref() else {
        panic!("expected active-grants list payload, got {inner:?}");
    };
    grants
        .iter()
        .map(|grant| {
            let Val::Record(fields) = grant else {
                panic!("expected grant-info record, got {grant:?}");
            };
            (
                record_string(fields, "id"),
                record_string(fields, "capability"),
                record_string(fields, "issuer"),
                record_variant(fields, "status"),
            )
        })
        .collect()
}

fn grant_request_val(capability: &str, key: &str, value: &str) -> Val {
    Val::Record(vec![
        ("capability".into(), Val::String(capability.into())),
        (
            "params".into(),
            Val::Option(Some(Box::new(Val::List(vec![Val::Record(vec![
                ("key".into(), Val::String(key.into())),
                ("value".into(), Val::String(value.into())),
            ])])))),
        ),
        (
            "justification".into(),
            Val::Option(Some(Box::new(Val::String("system witness".into())))),
        ),
    ])
}

fn ok_some_payload(out: Vec<Val>, label: &str) -> Val {
    let [Val::Result(Ok(Some(inner)))] = out.as_slice() else {
        panic!("expected {label} ok result, got {out:?}");
    };
    inner.as_ref().clone()
}

fn delivered_reply_strings(sut: &SystemUnderTest) -> Vec<String> {
    sut.delivered_replies()
        .into_iter()
        .map(|payload| String::from_utf8(payload).expect("guest reply is utf-8"))
        .collect()
}

fn only_delivered_reply(sut: &SystemUnderTest) -> String {
    let replies = delivered_reply_strings(sut);
    assert_eq!(replies.len(), 1, "expected exactly one guest reply");
    replies.into_iter().next().expect("one reply")
}

fn record_string(fields: &[(String, Val)], key: &str) -> String {
    fields
        .iter()
        .find_map(|(k, v)| {
            if k == key {
                if let Val::String(s) = v {
                    return Some(s.clone());
                }
            }
            None
        })
        .unwrap_or_else(|| panic!("missing string field {key} in {fields:?}"))
}

fn record_variant(fields: &[(String, Val)], key: &str) -> String {
    fields
        .iter()
        .find_map(|(k, v)| {
            if k == key {
                if let Val::Variant(case, _) = v {
                    return Some(case.clone());
                }
            }
            None
        })
        .unwrap_or_else(|| panic!("missing variant field {key} in {fields:?}"))
}

fn db_events_of_types(sut: &SystemUnderTest, types: &[&str]) -> Vec<DbEventRow> {
    sut.events_from_db()
        .into_iter()
        .filter(|e| types.contains(&e.event_type.as_str()))
        .collect()
}

fn db_payload(e: &DbEventRow) -> Value {
    e.payload
        .as_deref()
        .map(|p| serde_json::from_str(p).expect("event payload is JSON"))
        .unwrap_or(Value::Null)
}

fn db_str_field(e: &DbEventRow, key: &str) -> Option<String> {
    db_payload(e)
        .get(key)
        .and_then(|v| v.as_str())
        .map(str::to_string)
}

fn db_u64_field(e: &DbEventRow, key: &str) -> Option<u64> {
    db_payload(e).get(key).and_then(|v| v.as_u64())
}

fn db_decision_of(e: &DbEventRow) -> Option<String> {
    db_str_field(e, "decision")
}

fn db_resolver_type_of(e: &DbEventRow) -> Option<String> {
    db_str_field(e, "resolver_type")
}

/// SYS-AC-037 (approved) + SYS-AC-038 (exactly one resolver runs) + SYS-AC-039 (grant.issued + active).
#[tokio::test]
async fn sys_ac_037_038_039_supervised_approves_and_issues() {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Grant])
        .grant(GrantMode::Real)
        .grant_chain(GrantChain::Supervised)
        .with_reply_capture()
        .events(EventSink::RealBus)
        .build(GRANT_GUEST)
        .await;
    let store = sut.grant_store().expect("Real grant store");
    seed_grant_capability(store, AGENT_ID);
    // Parent fs grant covering /ws → SubsetAutoApprove approves the /ws/sub ⊆ /ws subset request.
    seed_grant(
        store,
        "parent-fs",
        AGENT_ID,
        "fs",
        vec![cap("write-paths", "/ws")],
        GrantTtl::Persistent,
        None,
    );

    sut.inject_message("h", b"req fs write-paths=/ws/sub").await;
    sut.run_turn().await;

    // SYS-AC-038: exactly one resolver.invoked (SubsetAutoApprove approves and short-circuits).
    let ri = db_events_of_types(&sut, &["resolver.invoked"]);
    assert_eq!(ri.len(), 1, "approved request: exactly one resolver runs");
    assert_eq!(db_decision_of(&ri[0]).as_deref(), Some("approve"));
    assert_eq!(
        db_resolver_type_of(&ri[0]).as_deref(),
        Some("SubsetAutoApprove")
    );
    assert_eq!(db_str_field(&ri[0], "agent_id").as_deref(), Some(AGENT_ID));
    assert_eq!(db_str_field(&ri[0], "capability").as_deref(), Some("fs"));

    // SYS-AC-039: a grant.issued from the resolver (issuer "resolver:SubsetAutoApprove";
    // pre-seeds carry issuer "config", so this uniquely selects the resolver-issued grant).
    let issued: Vec<_> = db_events_of_types(&sut, &["grant.issued"])
        .into_iter()
        .filter(|e| db_str_field(e, "issuer").as_deref() == Some("resolver:SubsetAutoApprove"))
        .collect();
    assert_eq!(
        issued.len(),
        1,
        "approve issues exactly one resolver-granted grant"
    );
    assert_eq!(
        db_str_field(&issued[0], "capability").as_deref(),
        Some("fs")
    );

    // SYS-AC-037/039: the new grant appears Active in active-grants, issued by the resolver
    // (the auto-approved child grant's TTL is Once, NOT the parent's Persistent — request-capability
    // hardcodes GrantTtl::Once; we assert capability/issuer/status, not TTL inheritance).
    let resolver_fs: Vec<_> = active_grants_projection(&sut)
        .await
        .into_iter()
        .filter(|(_id, capability, issuer, status)| {
            capability == "fs" && issuer == "resolver:SubsetAutoApprove" && status == "active"
        })
        .collect();
    assert_eq!(
        resolver_fs.len(),
        1,
        "the approved request issued exactly one resolver fs grant"
    );

    let reply = only_delivered_reply(&sut);
    let approved_id = reply
        .strip_prefix("req:approved:")
        .unwrap_or_else(|| panic!("expected request-capability approved reply, got {reply:?}"));
    assert!(
        !approved_id.is_empty(),
        "guest turn returns grant-decision::approved(grant-id)"
    );
    sut.assert_no_dropped_events();
}

/// SYS-AC-037 (pending) + SYS-AC-038 (resolver walk reaches Channel and awaits approval).
#[tokio::test]
async fn sys_ac_037_038_supervised_pending_when_no_parent_grant() {
    let channel_port = Arc::new(RecordingChannelApproval::default());
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Grant])
        .grant(GrantMode::Real)
        .grant_chain(GrantChain::Supervised)
        .grant_channel_approval(channel_port.clone())
        .with_reply_capture()
        .events(EventSink::RealBus)
        .build(GRANT_GUEST)
        .await;
    let store = sut.grant_store().expect("Real grant store");
    seed_grant_capability(store, AGENT_ID); // only the bootstrap grant — no parent fs grant

    sut.inject_message("h", b"req fs write-paths=/ws/x").await;
    sut.run_turn().await;

    // SubsetAutoApprove(abstain) + BudgetCheck(abstain) + ParentApproval(no backend → abstain)
    // + Channel(pending→abstain event), then short-circuits before AutoDeny.
    let ri = db_events_of_types(&sut, &["resolver.invoked"]);
    assert_eq!(
        ri.len(),
        4,
        "pending: resolver walk reaches Channel approval"
    );
    let types: Vec<String> = ri.iter().filter_map(db_resolver_type_of).collect();
    assert_eq!(
        types,
        vec![
            "SubsetAutoApprove",
            "BudgetCheck",
            "ParentApproval",
            "Channel"
        ]
    );
    assert!(
        ri.iter()
            .all(|e| db_decision_of(e).as_deref() == Some("abstain")),
        "all four abstain (Pending→abstain)"
    );

    let requests = channel_port.requests();
    assert_eq!(
        requests.len(),
        1,
        "Channel sends one correlated approval request"
    );
    assert_eq!(requests[0].caller, AGENT_ID);
    assert_eq!(requests[0].capability, "fs");

    // Pending issues no grant.
    let issued_fs: Vec<_> = db_events_of_types(&sut, &["grant.issued"])
        .into_iter()
        .filter(|e| db_str_field(e, "issuer").as_deref() == Some("resolver:SubsetAutoApprove"))
        .collect();
    assert!(issued_fs.is_empty(), "pending issues no grant");

    assert_eq!(only_delivered_reply(&sut), "req:pending");
    sut.assert_no_dropped_events();
}

/// SYS-AC-037/038/039 — exhausted run budget denies at BudgetCheck, before approval legs.
#[tokio::test]
async fn sys_ac_037_038_039_supervised_budget_denies_on_exhausted_session_run() {
    let run_bus: Arc<dyn EventBusEmit> = Arc::new(NoopBus);
    let run_manager = Arc::new(RunManager::new(run_bus));
    let run_config = RunConfig {
        rounds_limit: Some(1),
        ..Default::default()
    };
    let run_id = run_manager
        .ensure_run(AGENT_ID, AGENT_ID, run_config.clone())
        .expect("ensure_run");
    run_manager
        .complete_round(
            &run_id,
            RoundResult {
                summary: None,
                metrics: vec![],
            },
        )
        .await
        .expect("complete_round");
    let resolver_budget: Arc<dyn RunBudget> = Arc::new(run_manager.budget());

    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Grant])
        .grant(GrantMode::Real)
        .grant_chain(GrantChain::Supervised)
        .grant_resolver_budget(resolver_budget)
        .grant_run_session(run_manager, run_config)
        .with_reply_capture()
        .events(EventSink::RealBus)
        .build(GRANT_GUEST)
        .await;
    let store = sut.grant_store().expect("Real grant store");
    seed_grant_capability(&store, AGENT_ID);

    sut.inject_message("h", b"req fs write-paths=/ws/exhausted")
        .await;
    sut.run_turn().await;

    let ri = db_events_of_types(&sut, &["resolver.invoked"]);
    assert_eq!(
        ri.len(),
        2,
        "BudgetCheck deny short-circuits before approval legs"
    );
    let types: Vec<String> = ri.iter().filter_map(db_resolver_type_of).collect();
    assert_eq!(types, vec!["SubsetAutoApprove", "BudgetCheck"]);
    assert_eq!(db_decision_of(&ri[0]).as_deref(), Some("abstain"));
    assert_eq!(db_decision_of(&ri[1]).as_deref(), Some("deny"));

    assert_eq!(
        only_delivered_reply(&sut),
        "req:denied:budget-exceeded-rounds",
        "guest turn returns the real exhausted-rounds denial reason"
    );

    let issued_fs: Vec<_> = db_events_of_types(&sut, &["grant.issued"])
        .into_iter()
        .filter(|e| db_str_field(e, "capability").as_deref() == Some("fs"))
        .collect();
    assert!(issued_fs.is_empty(), "budget denial issues no fs grant");
    sut.assert_no_dropped_events();
}

/// SYS-AC-037 (denied) + SYS-AC-039 (restrict preset revokes grants, then the same request denies).
#[tokio::test]
async fn sys_ac_037_039_restrict_preset_denies() {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Grant])
        .grant(GrantMode::Real)
        .grant_chain(GrantChain::Supervised)
        .with_reply_capture()
        .events(EventSink::RealBus)
        .build(GRANT_GUEST)
        .await;
    let store = sut.grant_store().expect("Real grant store");
    seed_grant_capability(store, AGENT_ID);
    seed_grant(
        store,
        "parent-fs-for-restrict",
        AGENT_ID,
        "fs",
        vec![cap("write-paths", "/ws")],
        GrantTtl::Persistent,
        None,
    );

    sut.inject_message("h", b"apply-preset agent:harness restrict")
        .await;
    sut.run_turn().await;

    let applied = db_events_of_types(&sut, &["preset.applied"]);
    assert_eq!(applied.len(), 1, "restrict preset is applied by guest turn");
    assert_eq!(
        db_str_field(&applied[0], "preset_name").as_deref(),
        Some("restrict")
    );
    assert_eq!(db_u64_field(&applied[0], "grants_revoked"), Some(2));
    assert!(
        active_grants_projection(&sut).await.is_empty(),
        "restrict preset leaves the agent with its declared empty grant set"
    );

    // Re-seed only the self-management grant so the fixture can call request-capability
    // through the L1 gate; do not re-seed any fs grant.
    seed_grant_capability(store, AGENT_ID);
    sut.inject_message("h", b"req fs write-paths=/ws/y").await;
    sut.run_turn().await;

    let ri = db_events_of_types(&sut, &["resolver.invoked"]);
    let last = ri
        .last()
        .expect("request-capability invoked the resolver chain");
    assert_eq!(db_decision_of(last).as_deref(), Some("deny"));
    assert_eq!(db_resolver_type_of(last).as_deref(), Some("AutoDeny"));

    let issued_fs: Vec<_> = db_events_of_types(&sut, &["grant.issued"])
        .into_iter()
        .filter(|e| {
            db_str_field(e, "issuer")
                .as_deref()
                .is_some_and(|i| i.starts_with("resolver:"))
        })
        .filter(|e| db_str_field(e, "capability").as_deref() == Some("fs"))
        .collect();
    assert!(
        issued_fs.is_empty(),
        "restrict denial issues no resolver fs grant"
    );

    let replies = delivered_reply_strings(&sut);
    assert_eq!(
        replies.first().map(String::as_str),
        Some("apply-preset:ok:")
    );
    assert!(
        replies
            .get(1)
            .is_some_and(|reply| reply.starts_with("req:denied:")),
        "guest turn returns grant-decision::denied(reason), got {replies:?}"
    );
    sut.assert_no_dropped_events();
}

/// SYS-AC-204 — a Duration/until-TTL grant is auto-expired by the real `TtlSweeper`: a
/// `grant.expired` event fires (via the store's captured bus) and the grant flips Active→Expired.
#[tokio::test]
async fn sys_ac_204_ttl_sweeper_expires_grant() {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Grant])
        .grant(GrantMode::Real)
        .grant_chain(GrantChain::Supervised)
        .with_grant_ttl_sweeper(Duration::from_millis(10))
        .events(EventSink::RealBus)
        .build(GRANT_GUEST)
        .await;
    let store = sut.grant_store().expect("Real grant store");

    // Past-expiry until-TTL grant; deterministic past/future stamps.
    let past = chrono::DateTime::from_timestamp(1_000_000_000, 0).expect("valid past ts"); // 2001
    seed_grant(
        store,
        "ttl-grant",
        AGENT_ID,
        "fs",
        vec![cap("write-paths", "/ws/t")],
        GrantTtl::Until(past),
        Some(past),
    );

    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        let g = store
            .get("ttl-grant")
            .expect("grant still present after expiry");
        if g.status == GrantStatus::Expired {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "spawned TtlSweeper did not expire ttl-grant within the timeout"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    let expired: Vec<_> = db_events_of_types(&sut, &["grant.expired"])
        .into_iter()
        .filter(|e| db_str_field(e, "grant_id").as_deref() == Some("ttl-grant"))
        .collect();
    assert_eq!(
        expired.len(),
        1,
        "the past-expiry grant fired exactly one grant.expired"
    );
    assert_eq!(
        db_str_field(&expired[0], "capability").as_deref(),
        Some("fs")
    );

    let g = store
        .get("ttl-grant")
        .expect("grant still present after expiry");
    assert_eq!(g.status, GrantStatus::Expired, "Active→Expired (terminal)");
    assert!(
        active_grants_projection(&sut)
            .await
            .into_iter()
            .all(|(id, _, _, _)| id != "ttl-grant"),
        "expired grant is absent from the WIT active-grants projection"
    );
    sut.assert_no_dropped_events();
}

// ---------------------------------------------------------------------------------------------
// Un-deferred 2026-06-06 (colon-id reconciliation): apply-preset now accepts the canonical
// `agent:harness` caller id (cap-grant store.rs/preset.rs `is_agent_or_bare_id`), so a real guest
// turn drives it over the wired SystemUnderTest. Witnessed via EventBus events + the grant store
// (the guest swallows WIT returns — same model that passed SYS-AC-037/038/039).
// ---------------------------------------------------------------------------------------------

/// SYS-AC-203 — apply-preset(unknown) returns preset-not-found and issues/revokes nothing.
/// e2e witness = the no-mutation consequence; the `preset-not-found` WIT return is module-level
/// (cap-grant/tests/wit_impl.rs `sd_n07`).
#[tokio::test]
async fn sys_ac_203_apply_preset_unknown_is_noop() {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Grant])
        .grant(GrantMode::Real)
        .grant_chain(GrantChain::Supervised)
        .with_reply_capture()
        .events(EventSink::RealBus)
        .build(GRANT_GUEST)
        .await;
    let store = sut.grant_store().expect("Real grant store");
    seed_grant_capability(store, AGENT_ID);
    seed_grant(
        store,
        "keep-grant",
        AGENT_ID,
        "fs",
        vec![cap("write-paths", "/ws")],
        GrantTtl::Persistent,
        None,
    );
    let mut before_active = active_grants_projection(&sut).await;
    before_active.sort();
    let issued_before = db_events_of_types(&sut, &["grant.issued"]).len();
    let revoked_before = db_events_of_types(&sut, &["grant.revoked"]).len();

    sut.inject_message("h", b"apply-preset agent:harness no-such-preset")
        .await;
    sut.run_turn().await;

    assert_eq!(
        only_delivered_reply(&sut),
        "apply-preset:error:preset-not-found:no-such-preset"
    );

    // Issues/revokes no grant: no preset.applied, no new grant.issued/revoked rows, and
    // active-grants is byte-for-byte unchanged from the pre-call projection.
    assert!(
        db_events_of_types(&sut, &["preset.applied"]).is_empty(),
        "unknown preset applies nothing"
    );
    assert_eq!(
        db_events_of_types(&sut, &["grant.issued"]).len(),
        issued_before,
        "unknown preset issues no new grant"
    );
    assert_eq!(
        db_events_of_types(&sut, &["grant.revoked"]).len(),
        revoked_before,
        "unknown preset revokes no grant"
    );
    let mut active = active_grants_projection(&sut).await;
    active.sort();
    assert_eq!(
        active, before_active,
        "active-grants WIT projection is exactly unchanged"
    );

    sut.assert_no_dropped_events();
}

/// SYS-AC-262 — apply-preset(known) atomically revokes existing dynamic grants + creates the
/// preset's grants + emits preset.applied; active-grants reflects exactly the preset set.
#[tokio::test]
async fn sys_ac_262_apply_preset_atomic_revoke_and_emit() {
    let preset_yaml = r#"
name: sys262-nonempty
resolver-chain: [SubsetAutoApprove, BudgetCheck, AutoDeny]
default-ttl: lifecycle
grants:
  - capability: fs
    params:
      - key: write-paths
        value: /a
    ttl: persistent
"#;
    let mut presets = PresetRegistry::with_builtins();
    let preset_value: YamlValue = serde_yml::from_str(preset_yaml).expect("preset yaml parses");
    presets
        .load_custom_value(&preset_value)
        .expect("custom SYS-AC-262 preset loads");
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Grant])
        .grant(GrantMode::Real)
        .grant_chain(GrantChain::Supervised)
        .grant_presets(Arc::new(presets))
        .with_reply_capture()
        .events(EventSink::RealBus)
        .build(GRANT_GUEST)
        .await;
    let store = sut.grant_store().expect("Real grant store");
    // Three Active dynamic grants for agent:harness: the bootstrap "grant" self-management grant
    // (required to reach apply-preset through the L1 gate) + dyn-1 + dyn-2.
    seed_grant_capability(store, AGENT_ID);
    seed_grant(
        store,
        "dyn-1",
        AGENT_ID,
        "fs",
        vec![cap("write-paths", "/a")],
        GrantTtl::Persistent,
        None,
    );
    seed_grant(
        store,
        "dyn-2",
        AGENT_ID,
        "memory",
        vec![],
        GrantTtl::Persistent,
        None,
    );

    sut.inject_message("h", b"apply-preset agent:harness sys262-nonempty")
        .await;
    sut.run_turn().await;

    let reply = only_delivered_reply(&sut);
    assert!(
        reply.starts_with("apply-preset:ok:"),
        "custom non-empty preset returns created grant ids, got {reply:?}"
    );
    let created_ids: Vec<&str> = reply
        .strip_prefix("apply-preset:ok:")
        .unwrap()
        .split(',')
        .filter(|s| !s.is_empty())
        .collect();
    assert_eq!(created_ids.len(), 1, "one preset grant id returned");

    let applied = db_events_of_types(&sut, &["preset.applied"]);
    assert_eq!(applied.len(), 1, "exactly one preset.applied");
    assert_eq!(
        db_str_field(&applied[0], "target_agent").as_deref(),
        Some(AGENT_ID)
    );
    assert_eq!(
        db_str_field(&applied[0], "preset_name").as_deref(),
        Some("sys262-nonempty")
    );
    // All 3 pre-existing Active dynamic grants (Requested provenance) are revoked; the custom
    // preset declares one fs grant, so grants_created == 1.
    assert_eq!(db_u64_field(&applied[0], "grants_revoked"), Some(3));
    assert_eq!(db_u64_field(&applied[0], "grants_created"), Some(1));
    // active-grants subsequently reflects exactly the custom preset's non-empty grant set.
    let active = active_grants_projection(&sut).await;
    assert_eq!(
        active,
        vec![(
            created_ids[0].to_string(),
            "fs".to_string(),
            "resolver:preset:sys262-nonempty".to_string(),
            "active".to_string()
        )],
        "active-grants == sys262-nonempty's declared grant set"
    );
    sut.assert_no_dropped_events();
}

/// SYS-AC-262 — real host-boundary request-capability racing apply-preset still leaves
/// active-grants equal to the preset's declared set.
#[tokio::test]
async fn sys_ac_262_concurrent_request_and_apply_preset_converges_to_preset_set() {
    let preset_yaml = r#"
name: sys262-nonempty
resolver-chain: [SubsetAutoApprove, BudgetCheck, AutoDeny]
default-ttl: lifecycle
grants:
  - capability: fs
    params:
      - key: write-paths
        value: /a
    ttl: persistent
"#;
    let mut presets = PresetRegistry::with_builtins();
    let preset_value: YamlValue = serde_yml::from_str(preset_yaml).expect("preset yaml parses");
    presets
        .load_custom_value(&preset_value)
        .expect("custom SYS-AC-262 preset loads");
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Grant])
        .grant(GrantMode::Real)
        .grant_chain(GrantChain::Supervised)
        .grant_presets(Arc::new(presets))
        .events(EventSink::RealBus)
        .build(GRANT_GUEST)
        .await;
    let store = sut.grant_store().expect("Real grant store");
    seed_grant(
        store,
        "race-parent-fs",
        AGENT_ID,
        "fs",
        vec![cap("write-paths", "/old")],
        GrantTtl::Persistent,
        None,
    );
    seed_grant(
        store,
        "race-preset-cover-fs",
        AGENT_ID,
        "fs",
        vec![cap("write-paths", "/a")],
        GrantTtl::Persistent,
        None,
    );
    seed_grant(
        store,
        "race-dyn-memory",
        AGENT_ID,
        "memory",
        vec![],
        GrantTtl::Persistent,
        None,
    );

    let request = sut.call_host_fn_n(
        "grant",
        cap_grant::AGENT_GRANT_NAMESPACE,
        "request-capability",
        vec![grant_request_val("fs", "write-paths", "/old/sub")],
        1,
    );
    let apply = sut.call_host_fn_n(
        "grant",
        cap_grant::AGENT_GRANT_NAMESPACE,
        "apply-preset",
        vec![
            Val::String(AGENT_ID.to_string()),
            Val::String("sys262-nonempty".to_string()),
        ],
        1,
    );
    let (request_out, apply_out) = tokio::join!(request, apply);

    let request_payload = ok_some_payload(
        request_out.expect("request-capability host fn succeeds"),
        "request-capability",
    );
    let Val::Variant(request_case, _) = request_payload else {
        panic!("expected request grant-decision variant, got {request_payload:?}");
    };
    assert!(
        matches!(request_case.as_str(), "approved" | "denied"),
        "request either wins-before-apply and approves or loses-after-apply and denies, got {request_case:?}"
    );

    let apply_payload = ok_some_payload(
        apply_out.expect("apply-preset host fn succeeds"),
        "apply-preset",
    );
    let Val::List(created) = apply_payload else {
        panic!("expected apply-preset created-id list, got {apply_payload:?}");
    };
    assert_eq!(created.len(), 1, "custom preset creates one grant");
    let Val::String(created_id) = &created[0] else {
        panic!("expected created grant id string, got {:?}", created[0]);
    };

    let applied = db_events_of_types(&sut, &["preset.applied"]);
    assert_eq!(applied.len(), 1, "exactly one preset.applied");
    assert_eq!(
        db_str_field(&applied[0], "preset_name").as_deref(),
        Some("sys262-nonempty")
    );
    assert!(
        matches!(db_u64_field(&applied[0], "grants_revoked"), Some(3 | 4)),
        "apply revokes the three pre-existing grants, plus the racing request if it approved first"
    );
    assert_eq!(db_u64_field(&applied[0], "grants_created"), Some(1));

    let active = active_grants_projection(&sut).await;
    assert_eq!(
        active,
        vec![(
            created_id.clone(),
            "fs".to_string(),
            "resolver:preset:sys262-nonempty".to_string(),
            "active".to_string()
        )],
        "concurrent request/apply leaves exactly the preset grant active"
    );
    sut.assert_no_dropped_events();
}

//! SYS-J-34 submit journey witnesses (SYS-AC-108, 110, 111, 225; SYS-AC-109 partial).
//!
//! SYS-AC-225 (Wave-10 Lane A): the per-submitter scheduled-component quota (default 20) reject —
//! the 21st submit for one submitter → `spawn-error::resource-limit` with no component registered
//! (`sys_ac_225_over_quota_reject_no_registration`), product-computed in the real
//! `InMemoryComponentSubmitApi` + verified against the durable `ComponentRegistry`.
//!
//! Real product: the production `InMemoryComponentSubmitApi` + SQLite `ComponentRegistry`
//! (scheduler `submit.rs` / `registry.rs`) — admission rules + durable registry
//! persistence (MODULE-005→MODULE-014→MODULE-013). Driven through the harness
//! `.with_triggers()` seam (`sut.submit_api()`, `with_registry` + `with_quota(20)`).
//!
//! SYS-AC-109 PARTIAL (re-asserted by the 2026-06-13 adversarial round, F1): the
//! durability/independence clause (the admitted component's durable registry row
//! survives + is queryable independently of the submitter — no submitter→component
//! cascade; the submitter is metadata-only) is witnessed. The "runs on its own
//! trigger" clause is RE-DEFERRED to §3: the runnable-run MECHANISM exists (1B
//! `WasmRunnableHook` + `CronDriver`, witnessed by SYS-AC-098/101 whose criteria
//! target those mechanisms themselves), but the registry→driver MATERIALIZATION
//! layer (admitted row's trigger/binary → live driver) is unbuilt
//! (`scheduler.rs` ComponentType→driver dispatch + post-readiness registration are
//! waived_scope) — a harness-fabricated driver bound to the admission only by an id
//! string is fake-green (deleting the submit still passes the run assertions), the
//! exact class the witness-floor forbids. No run leg is asserted here.
//!
//! SYS-AC-110 is witnessed against the REAL chain: submit admission rule 5
//! (`SubmitSubsetGate`, sched-residue 2026-06-12) gated by the REAL validator adapter
//! the MODULE-014 §1.7 recipe prescribes — `cap_grant::validate_capability_subset`
//! over the SUT's own wired `GrantStore::list_by_grantee` (Active-only filter,
//! CSV→array re-projection, `agent:`-prefix duality, fail-closed catch-all), composed
//! by the harness `.with_submit_subset_gate()` axis over `GrantMode::Real`. An
//! over-grant request is rejected `SpawnError::SubsetViolation` BEFORE any side effect
//! (no quota slot, no registry row, no admission row) — the no-component-registered
//! clause is asserted against both the in-memory view and the durable registry.

use advance_scheduler::types::{SpawnError, TriggerConfig, TriggerSubscription};
use advance_scheduler::{ComponentSubmitApi, ComponentSubmitConfig};
use advance_shared_types::capability::{CapRequest, CapabilityId};
use advance_shared_types::component::ComponentType;
use cap_grant::data::GrantTtl;

use system_acceptance::{GrantMode, SystemUnderTest};

#[path = "d_grant/mod.rs"]
mod d_grant;
use d_grant::seed_grant;

const J01_SKELETON: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-j01-skeleton.core.wasm");

fn cfg(
    id: &str,
    component_type: ComponentType,
    capabilities: Vec<CapRequest>,
    trigger: Option<TriggerConfig>,
) -> ComponentSubmitConfig {
    ComponentSubmitConfig {
        sensitive_params: Vec::new(),
        id: id.into(),
        component_type,
        binary: Vec::new(),
        capabilities,
        output_dir: None,
        trigger,
        restart_policy: None,
        delay: None,
        initial_grants: None,
        preset: None,
        retry: None,
    }
}

async fn triggers_sut() -> SystemUnderTest {
    SystemUnderTest::builder()
        .with_triggers()
        .build(J01_SKELETON)
        .await
}

// SYS-AC-108 — a valid SubmitComponent (cron/task config) is admitted and registered
// (persisted to the ComponentRegistry, queryable).
#[tokio::test]
async fn sys_ac_108_valid_submit_admitted_and_persisted() {
    let sut = triggers_sut().await;
    let api = sut.submit_api();

    let id = api
        .submit_component(
            "agent:root",
            cfg("comp-108", ComponentType::Cron, vec![], None),
        )
        .await
        .expect("a valid cron submit is admitted");
    assert_eq!(id.as_str(), "comp-108");

    // Queryable via the in-memory admission view.
    let listed = api.list_components().await;
    assert!(
        listed.iter().any(|c| c.id.as_str() == "comp-108"),
        "admitted component is listed"
    );

    // Persisted to the durable ComponentRegistry (the "persisted to ComponentRegistry,
    // queryable" clause — witnessed via the durable registry view).
    let persisted = api
        .list_components_persisted()
        .await
        .expect("durable registry read");
    assert!(
        persisted.iter().any(|r| r.id.as_str() == "comp-108"),
        "admitted component is persisted to the ComponentRegistry"
    );
}

// SYS-AC-111 — a daemon declaring a trigger-event trigger (or a lifecycle.spawn-child
// cap) is rejected at admission (spawn-error invalid-config / capability-denied); nothing
// is registered.
#[tokio::test]
async fn sys_ac_111_daemon_trigger_event_and_lifecycle_cap_rejected() {
    let sut = triggers_sut().await;
    let api = sut.submit_api();

    // Daemon + trigger-event trigger → InvalidConfig.
    let te = cfg(
        "d-te",
        ComponentType::Daemon,
        vec![],
        Some(TriggerConfig::TriggerEvent(TriggerSubscription {
            event_type: "grant.issued".into(),
            filter: None,
            debounce_ms: None,
        })),
    );
    let err = api.submit_component("agent:root", te).await.unwrap_err();
    assert!(
        matches!(err, SpawnError::InvalidConfig(_)),
        "daemon + trigger-event → InvalidConfig; got {err:?}"
    );

    // Daemon + lifecycle.spawn-child cap → CapabilityDenied.
    let lc = cfg(
        "d-lc",
        ComponentType::Daemon,
        vec![CapRequest {
            capability: CapabilityId::from("lifecycle.spawn-child"),
        }],
        None,
    );
    let err2 = api.submit_component("agent:root", lc).await.unwrap_err();
    assert!(
        matches!(err2, SpawnError::CapabilityDenied(_)),
        "daemon + lifecycle.spawn-child → CapabilityDenied; got {err2:?}"
    );

    // Neither rejected submit was registered.
    let persisted = api.list_components_persisted().await.expect("durable read");
    assert!(
        !persisted
            .iter()
            .any(|r| r.id.as_str() == "d-te" || r.id.as_str() == "d-lc"),
        "rejected submits leave nothing registered"
    );
}

/// A `.with_submit_subset_gate()` SUT: the REAL subset-validator adapter (cap-grant
/// `validate_capability_subset` over the SUT's wired `GrantStore`) gating submit
/// admission rule 5.
async fn gated_sut() -> SystemUnderTest {
    SystemUnderTest::builder()
        .grant(GrantMode::Real)
        .with_triggers()
        .with_submit_subset_gate()
        .build(J01_SKELETON)
        .await
}

fn caps(ids: &[&str]) -> Vec<CapRequest> {
    ids.iter()
        .map(|id| CapRequest {
            capability: CapabilityId::from(*id),
        })
        .collect()
}

// SYS-AC-110 — a SubmitComponent whose requested capabilities exceed the submitter's
// grant is rejected by the real SubsetValidator (spawn-error::subset-violation) and no
// component is registered; a within-grant submit from the same submitter admits (the
// gate is live, not vacuous).
#[tokio::test]
async fn sys_ac_110_overgrant_submit_rejected_nothing_registered() {
    let sut = gated_sut().await;
    let api = sut.submit_api();
    let grants = sut
        .grant_store()
        .expect("GrantMode::Real wires the real store");

    // The submitter's REAL grant set: Active `fs` only (whole capability).
    seed_grant(
        grants,
        "g-110-fs",
        "agent:limited",
        "fs",
        vec![],
        GrantTtl::Persistent,
        None,
    );

    // Over-grant: the component requests `fs` + `http`, but the submitter holds no
    // `http` grant → the real validator rejects, fail-closed, at admission rule 5.
    let err = api
        .submit_component(
            "agent:limited",
            cfg(
                "comp-110-over",
                ComponentType::Task,
                caps(&["fs", "http"]),
                None,
            ),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(err, SpawnError::SubsetViolation(_)),
        "over-grant submit → SubsetViolation from the real validator; got {err:?}"
    );

    // No component registered: rule 5 runs BEFORE the critical section — the
    // rejected submit holds no admission row and no durable registry row.
    let listed = api.list_components().await;
    assert!(
        !listed.iter().any(|c| c.id.as_str() == "comp-110-over"),
        "the rejected component is absent from the admission view"
    );
    let persisted = api.list_components_persisted().await.expect("durable read");
    assert!(
        !persisted.iter().any(|r| r.id.as_str() == "comp-110-over"),
        "the rejected component is absent from the durable ComponentRegistry"
    );

    // Control: a within-grant request from the SAME submitter admits through the
    // SAME live gate (and proves the rejection above was the validator, not an
    // always-deny stub).
    api.submit_component(
        "agent:limited",
        cfg("comp-110-ok", ComponentType::Task, caps(&["fs"]), None),
    )
    .await
    .expect("a within-grant submit admits through the live subset gate");
    let persisted = api.list_components_persisted().await.expect("durable read");
    assert!(
        persisted.iter().any(|r| r.id.as_str() == "comp-110-ok"),
        "the admitted within-grant component is durably registered"
    );
}

// SYS-AC-110 (adapter contract legs) — the `agent:`-prefix grantee duality (a grant
// keyed by the BARE body authorizes the canonical `agent:`-prefixed submitter) and the
// Active-only filter (a REVOKED grant no longer authorizes its capability).
#[tokio::test]
async fn sys_ac_110_grantee_duality_and_active_filter() {
    let sut = gated_sut().await;
    let api = sut.submit_api();
    let grants = sut
        .grant_store()
        .expect("GrantMode::Real wires the real store");

    // Duality: the grant is keyed by the BARE body (`GrantStore::insert`'s charset
    // gate colon-rejects `agent:` grantees, so static grants are bare-keyed); the
    // submitter arrives canonical. The adapter unions both grantee views → admits.
    seed_grant(
        grants,
        "g-110-bare",
        "dual",
        "fs",
        vec![],
        GrantTtl::Persistent,
        None,
    );
    api.submit_component(
        "agent:dual",
        cfg("comp-110-dual", ComponentType::Task, caps(&["fs"]), None),
    )
    .await
    .expect("a bare-keyed grant authorizes the canonical agent:-prefixed submitter");

    // Active filter: grant `http`, then revoke it — the revoked grant must NOT
    // authorize (list_by_grantee returns every status; the adapter filters Active).
    seed_grant(
        grants,
        "g-110-http",
        "dual",
        "http",
        vec![],
        GrantTtl::Persistent,
        None,
    );
    grants
        .revoke_by_grantee("dual")
        .expect("revoke the submitter's grants");
    let err = api
        .submit_component(
            "agent:dual",
            cfg(
                "comp-110-revoked",
                ComponentType::Task,
                caps(&["http"]),
                None,
            ),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(err, SpawnError::SubsetViolation(_)),
        "a revoked grant no longer authorizes its capability (Active-only filter); got {err:?}"
    );
    let persisted = api.list_components_persisted().await.expect("durable read");
    assert!(
        !persisted
            .iter()
            .any(|r| r.id.as_str() == "comp-110-revoked"),
        "the revoked-grant rejection registered nothing"
    );
}

// SYS-AC-109 (partial) — the admitted component is durable and queryable
// independently of the submitter (no submitter→component cascade; the submitter is
// metadata-only, so terminating the submitting agent does not remove the registered
// component). The "runs on its own trigger" clause is RE-DEFERRED to §3 (see module
// docs — adversarial-round F1): no production registry→driver materializer exists,
// and a harness-fabricated run is not a witness of it.
#[tokio::test]
async fn sys_ac_109_admitted_component_durable_independent_of_submitter() {
    let sut = triggers_sut().await;
    let api = sut.submit_api();

    // Submitted by an "ephemeral" submitter agent.
    api.submit_component(
        "agent:ephemeral",
        cfg("comp-109", ComponentType::Cron, vec![], None),
    )
    .await
    .expect("admitted");

    // The durable registry row is queryable via the registry view — NOT keyed on the
    // submitter's liveness (the admission API records the submitter as metadata only and
    // has no submitter-cascade removal rule). This is the "independent of the submitting
    // agent / terminating the agent does not remove it" property at the durability layer.
    let persisted = api.list_components_persisted().await.expect("durable read");
    let row = persisted
        .iter()
        .find(|r| r.id.as_str() == "comp-109")
        .expect("component durable in the registry independent of the submitter");
    assert_eq!(
        row.submitter, "agent:ephemeral",
        "submitter is recorded as metadata only"
    );
}

// SYS-AC-225 (Wave-10 Lane A) — a SubmitComponent that would exceed the submitter's per-agent
// scheduled-component quota (default 20) is rejected with `spawn-error::resource-limit` and NO
// component is registered. The rejection is PRODUCT-computed inside the real
// `InMemoryComponentSubmitApi::submit_component` (`submitter_count >= effective_cap`,
// scheduler/submit.rs:390) and returns BEFORE the write-through registry insert AND the in-memory
// store insert — so the over-quota submit registers nowhere. Driven via `sut.submit_api()` (the SAME
// instance the wired trigger/WIT path uses); the read-back is the real durable `ComponentRegistry`.
// (Criterion trimmed 2026-06-16: the illustrative warning-event parenthetical was removed — the
// reject + non-registration guarantee is what this witnesses.)
#[tokio::test]
async fn sys_ac_225_over_quota_reject_no_registration() {
    let sut = triggers_sut().await; // default `.with_quota(20)` == DEFAULT_MAX_SCHEDULED_COMPONENTS
    let api = sut.submit_api();

    // 20 DISTINCT-id submits for ONE submitter — all admitted. Distinct ids are REQUIRED: the
    // dup-check (`store.contains_key` → AlreadyExists) + the Agent/Daemon type rules all run BEFORE
    // the AC-09 quota gate, so a reused id would short-circuit on AlreadyExists and never exercise
    // the quota path.
    for i in 0..20 {
        api.submit_component(
            "agent:quota-a",
            cfg(&format!("a-{i}"), ComponentType::Task, vec![], None),
        )
        .await
        .unwrap_or_else(|e| panic!("submit #{i} within the 20-quota must be admitted; got {e:?}"));
    }

    // The 21st for the SAME submitter → ResourceLimit (the product-computed quota reject).
    let err = api
        .submit_component(
            "agent:quota-a",
            cfg("a-20", ComponentType::Task, vec![], None),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(err, SpawnError::ResourceLimit(_)),
        "the 21st submit over the default-20 quota → spawn-error::resource-limit; got {err:?}"
    );

    // No component registered for the rejected submit: the submitter's durable count stays EXACTLY
    // 20 and the over-quota id never persisted (the reject returns before registry + store insert).
    let persisted = api
        .list_components_persisted()
        .await
        .expect("durable registry read");
    let a_count = persisted
        .iter()
        .filter(|r| r.submitter == "agent:quota-a")
        .count();
    assert_eq!(
        a_count, 20,
        "the rejected 21st did NOT register — the submitter's durable count stays 20"
    );
    assert!(
        !persisted.iter().any(|r| r.id.as_str() == "a-20"),
        "the over-quota component id `a-20` never persisted to the ComponentRegistry"
    );

    // Discriminator (anti-fake-green): the quota is PER-SUBMITTER — a DIFFERENT submitter's 1st
    // submit still succeeds + registers, proving the reject keys on real per-submitter store state
    // (`r.submitter == submitter`), not a global cap.
    let b_id = api
        .submit_component(
            "agent:quota-b",
            cfg("b-0", ComponentType::Task, vec![], None),
        )
        .await
        .expect("a fresh submitter has its own 20-budget — its 1st submit is admitted");
    assert_eq!(b_id.as_str(), "b-0");
    let persisted2 = api
        .list_components_persisted()
        .await
        .expect("durable registry read");
    assert!(
        persisted2
            .iter()
            .any(|r| r.id.as_str() == "b-0" && r.submitter == "agent:quota-b"),
        "the discriminator submit registered under agent:quota-b (per-submitter budget)"
    );
}

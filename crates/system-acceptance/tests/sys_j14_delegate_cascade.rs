//! SYS-J-14 — a parent delegates a capability to a child, narrows it, then revokes it, and the
//! revocation cascades to descendant grants. Chain: MODULE-013 → MODULE-003 → MODULE-004.
//!
//! Active: SYS-AC-205 — the colon-safe authorization leg: a `revoke-grant` whose target grant is
//! owned by a DIFFERENT agent (caller_id != grantee) returns permission-denied and performs no
//! mutation. Witnessed over the REAL wired harness via a real guest turn (`agent:harness` identity);
//! `revoke-grant`'s `cascade_revoke` keys on a grant-id (not an agent id) and the ownership
//! pre-check returns permission-denied BEFORE any mutation, so it is reachable as `agent:harness`.
//!
//! Un-deferred 2026-06-06 (colon-id reconciliation): delegate-grant / narrow-grant now accept the
//! canonical `agent:harness` caller id a real guest turn presents (cap-grant
//! `store.rs::is_agent_or_bare_id`), so SYS-AC-040 (delegate-grant), SYS-AC-041 (narrow-grant),
//! and SYS-AC-042 (revoke cascade to a delegated descendant) are witnessed over the wired
//! SystemUnderTest via a real `agent:harness` guest turn. Witnessed via EventBus events + the
//! grant store (the guest swallows WIT returns — same model as SYS-AC-037/038/039/205).

#[path = "d_grant/mod.rs"]
mod d_grant;
use d_grant::*;

use cap_grant::data::{GrantId, GrantProvenance, GrantStatus, GrantTtl};
use system_acceptance::{Cap, GrantChain, GrantMode, SystemUnderTest, AGENT_ID};

/// SYS-AC-205 — revoke a grant owned by a different agent → permission-denied, no mutation.
#[tokio::test]
async fn sys_ac_205_revoke_other_agents_grant_denied_no_mutation() {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Grant])
        .grant(GrantMode::Real)
        .grant_chain(GrantChain::Supervised)
        .build(GRANT_GUEST)
        .await;
    let store = sut.grant_store().expect("Real grant store");
    seed_grant_capability(store, AGENT_ID);
    // A grant owned by a DIFFERENT agent.
    seed_grant(
        store,
        "x-other",
        "agent:other",
        "fs",
        vec![cap("write-paths", "/other")],
        GrantTtl::Persistent,
        None,
    );

    // caller agent:harness passes the self-only gate (target==caller) but fails the ownership
    // pre-check (x-other ∉ list_by_grantee(agent:harness)) → permission-denied before cascade_revoke.
    sut.inject_message("h", b"revoke agent:harness x-other")
        .await;
    sut.run_turn().await;

    let g = store
        .get("x-other")
        .expect("the other agent's grant still exists");
    assert_eq!(
        g.status,
        GrantStatus::Active,
        "permission-denied: no mutation, X stays Active"
    );

    let revoked_x: Vec<_> = sut
        .events_of_types(&["grant.revoked"])
        .into_iter()
        .filter(|e| str_field(e, "grant_id").as_deref() == Some("x-other"))
        .collect();
    assert!(
        revoked_x.is_empty(),
        "no grant.revoked for the unowned grant"
    );
}

// ---------------------------------------------------------------------------------------------
// Deferred (two-ID-conventions product gap) — un-ignore once HF bridges the id conventions.
// ---------------------------------------------------------------------------------------------

/// SYS-AC-040 — after delegate-grant to a child, the child's active-grants lists the grant with
/// provenance delegated:<parent-grant-id>.
#[tokio::test]
async fn sys_ac_040_delegate_records_provenance() {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Grant])
        .grant(GrantMode::Real)
        .grant_chain(GrantChain::Supervised)
        .build(GRANT_GUEST)
        .await;
    let store = sut.grant_store().expect("Real grant store");
    seed_grant_capability(store, AGENT_ID);
    seed_grant(
        store,
        "parent-fs",
        AGENT_ID,
        "fs",
        vec![cap("write-paths", "/ws")],
        GrantTtl::Persistent,
        None,
    );

    sut.inject_message("h", b"delegate agent:child fs write-paths=/ws/child")
        .await;
    sut.run_turn().await;

    let child: Vec<_> = store
        .list_by_grantee("agent:child")
        .into_iter()
        .filter(|g| g.capability == "fs")
        .collect();
    assert_eq!(child.len(), 1, "the child received the delegated grant");
    assert_eq!(
        child[0].status,
        GrantStatus::Active,
        "the delegated grant is Active"
    );
    assert_eq!(
        child[0].provenance,
        GrantProvenance::Delegated(GrantId::new("parent-fs")),
        "provenance records the exact parent grant id (delegated:parent-fs)"
    );
}

/// SYS-AC-041 — narrow-grant emits grant.narrowed {grant_id, old_params, new_params, narrowed_by}
/// and grant-status returns the narrowed params. grant-status is a pure projection of the store;
/// since the guest swallows WIT returns, the narrowed params are witnessed via the grant.narrowed
/// payload + the post-turn store (the single Active fs grant carries the narrowed write-paths).
#[tokio::test]
async fn sys_ac_041_narrow_emits_and_updates() {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Grant])
        .grant(GrantMode::Real)
        .grant_chain(GrantChain::Supervised)
        .build(GRANT_GUEST)
        .await;
    let store = sut.grant_store().expect("Real grant store");
    seed_grant_capability(store, AGENT_ID);
    seed_grant(
        store,
        "narrow-me",
        AGENT_ID,
        "fs",
        vec![cap("write-paths", "/ws")],
        GrantTtl::Persistent,
        None,
    );

    sut.inject_message(
        "h",
        b"narrow agent:harness narrow-me write-paths=/ws/narrowed",
    )
    .await;
    sut.run_turn().await;

    let narrowed = sut.events_of_types(&["grant.narrowed"]);
    assert_eq!(narrowed.len(), 1, "narrow emits exactly one grant.narrowed");
    // Full 4-field payload, incl. narrowed_by == the canonical caller.
    assert_eq!(
        str_field(&narrowed[0], "narrowed_by").as_deref(),
        Some(AGENT_ID)
    );
    assert!(
        narrowed[0].payload.get("grant_id").is_some(),
        "payload carries grant_id"
    );
    assert!(
        narrowed[0].payload.get("old_params").is_some(),
        "payload carries old_params"
    );
    assert!(
        narrowed[0].payload.get("new_params").is_some(),
        "payload carries new_params"
    );
    // narrow mints a NEW Active grant (the seeded one is Revoked); its params are the narrowed
    // set — exactly what grant-status would return for agent:harness.
    let active_fs: Vec<_> = store
        .list_by_grantee(AGENT_ID)
        .into_iter()
        .filter(|g| g.capability == "fs" && g.status == GrantStatus::Active)
        .collect();
    assert_eq!(
        active_fs.len(),
        1,
        "exactly one Active fs grant after narrow"
    );
    assert_eq!(
        active_fs[0].params,
        vec![cap("write-paths", "/ws/narrowed")],
        "the Active fs grant carries the narrowed params"
    );
}

/// SYS-AC-042 — revoking the parent emits grant.revoked {..., revoked_by, cascade_count>=1} and
/// the descendant grant becomes revoked.
#[tokio::test]
async fn sys_ac_042_revoke_cascades_to_descendants() {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Grant])
        .grant(GrantMode::Real)
        .grant_chain(GrantChain::Supervised)
        .build(GRANT_GUEST)
        .await;
    let store = sut.grant_store().expect("Real grant store");
    seed_grant_capability(store, AGENT_ID);
    seed_grant(
        store,
        "root-fs",
        AGENT_ID,
        "fs",
        vec![cap("write-paths", "/ws")],
        GrantTtl::Persistent,
        None,
    );

    sut.inject_message("h", b"delegate agent:child fs write-paths=/ws/child")
        .await;
    sut.run_turn().await;
    // The delegated descendant exists and is Active before the revoke.
    let descendant = store
        .list_by_grantee("agent:child")
        .into_iter()
        .find(|g| g.capability == "fs")
        .expect("delegated descendant exists");
    assert_eq!(
        descendant.status,
        GrantStatus::Active,
        "descendant Active before revoke"
    );

    sut.inject_message("h", b"revoke agent:harness root-fs")
        .await;
    sut.run_turn().await;

    // The root revoke carries revoked_by + cascade_count>=1 ...
    let root_revoked = sut
        .events_of_types(&["grant.revoked"])
        .into_iter()
        .find(|e| str_field(e, "grant_id").as_deref() == Some("root-fs"))
        .expect("grant.revoked for the root grant");
    assert!(
        str_field(&root_revoked, "revoked_by").is_some(),
        "root revoke carries revoked_by"
    );
    assert!(
        root_revoked
            .payload
            .get("cascade_count")
            .and_then(|v| v.as_u64())
            .unwrap_or(0)
            >= 1,
        "cascade_count >= 1 on the root revoke"
    );
    // ... and the descendant grant is now Revoked.
    assert_eq!(
        store.get(descendant.id.as_str()).map(|g| g.status),
        Some(GrantStatus::Revoked),
        "the delegated descendant became Revoked via cascade"
    );
}

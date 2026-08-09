//! Tests for sweeper-adjacent semantics: T02, T03, T27, T-A1, T15 (integration).

mod common;

use std::sync::Arc;
use std::time::Duration;

use cap_grant::data::{Grant, GrantId, GrantIssuer, GrantProvenance, GrantStatus, GrantTtl};
use cap_grant::TtlSweeper;
use chrono::{TimeZone, Utc};

use crate::common::make_store;

fn mk_grant(
    id: &str,
    grantee: &str,
    capability: &str,
    ttl: GrantTtl,
    expires_at: Option<chrono::DateTime<Utc>>,
) -> Grant {
    Grant {
        id: GrantId::new(id),
        grantee: grantee.to_string(),
        capability: capability.to_string(),
        params: vec![],
        ttl,
        issuer: GrantIssuer::Config,
        provenance: GrantProvenance::StaticConfig,
        status: GrantStatus::Active,
        created_at: Utc::now(),
        expires_at,
    }
}

// MODULE-013-T02 — AC-02 — Once consumed on first use.
#[test]
fn ttl_once_consumed_on_first_use() {
    let (store, bus, _h) = make_store();
    let g = mk_grant("g1", "alice", "fs", GrantTtl::Once, None);
    store.insert(g).unwrap();

    store.consume("g1", "test::consume").unwrap();
    let after = store.get("g1").unwrap();
    assert_eq!(after.status, GrantStatus::Consumed);

    let err = store.consume("g1", "test::consume").unwrap_err();
    assert!(matches!(err, cap_grant::CapGrantError::NotFound(_)));

    assert_eq!(bus.count_of("grant.consumed"), 1);
    // Audit-fix R4 Diff W3: assert the new 4th PRD field appears in the
    // emitted payload (Slice C widening of grant.consumed).
    let evt = bus.first_of("grant.consumed").expect("event present");
    assert_eq!(evt.payload["consumed_by_function"], "test::consume");
    assert_eq!(evt.payload["grant_id"], "g1");
    assert_eq!(evt.payload["grantee"], "alice");
    assert_eq!(evt.payload["capability"], "fs");
}

// MODULE-013-T03 — AC-02 — Lifecycle revoked when grantee terminates.
#[test]
fn ttl_lifecycle_revoked_on_terminate() {
    let (store, bus, _h) = make_store();
    let g = mk_grant("g-life", "alice", "fs", GrantTtl::Lifecycle, None);
    store.insert(g).unwrap();

    let revoked = store.revoke_by_grantee("alice").unwrap();
    assert_eq!(revoked.len(), 1);
    let after = store.get("g-life").unwrap();
    assert_eq!(after.status, GrantStatus::Revoked);
    let evt = bus.first_of("grant.revoked").expect("revoked event");
    assert_eq!(
        evt.payload["revoked_by"].as_str().unwrap(),
        "grantee-terminate:alice"
    );
}

// MODULE-013-T27 — AC-02 — Persistent + Until.
#[test]
fn ttl_persistent_and_until() {
    let (store, bus, _h) = make_store();

    // Persistent never expires.
    let perm = mk_grant("g-perm", "alice", "fs", GrantTtl::Persistent, None);
    store.insert(perm).unwrap();

    // Until(t) where t is in the past.
    let past = Utc.timestamp_opt(1_000_000_000, 0).unwrap();
    let until = mk_grant(
        "g-until",
        "alice",
        "http",
        GrantTtl::Until(past),
        Some(past),
    );
    store.insert(until).unwrap();

    let sweeper = TtlSweeper::new(store.clone(), {
        let b: Arc<dyn advance_shared_types::traits::EventBusEmit> = bus.clone();
        b
    });
    sweeper.tick(Utc::now());

    assert_eq!(store.get("g-perm").unwrap().status, GrantStatus::Active);
    assert_eq!(store.get("g-until").unwrap().status, GrantStatus::Expired);

    // tick a far future moment — persistent still active.
    let far = Utc.timestamp_opt(3_000_000_000, 0).unwrap();
    sweeper.tick(far);
    assert_eq!(store.get("g-perm").unwrap().status, GrantStatus::Active);
}

// T-A1 — AC-02 — Duration expires after window via tick(now).
#[test]
fn ttl_duration_expires_after_window() {
    let (store, bus, _h) = make_store();
    let issued = Utc::now();
    let ms: u64 = 50;
    // Slice A's tick uses expires_at directly; for Duration grants the
    // expires_at is computed by the issuer (slice B+ for dynamic;
    // for tests we set it directly).
    let expires = issued + chrono::Duration::milliseconds(ms as i64);
    let g = mk_grant(
        "g-dur",
        "alice",
        "fs",
        GrantTtl::Duration(ms),
        Some(expires),
    );
    store.insert(g).unwrap();

    // Tick BEFORE expiry — still active.
    let before = expires - chrono::Duration::milliseconds(10);
    let sweeper = TtlSweeper::new(store.clone(), {
        let b: Arc<dyn advance_shared_types::traits::EventBusEmit> = bus.clone();
        b
    });
    sweeper.tick(before);
    assert_eq!(store.get("g-dur").unwrap().status, GrantStatus::Active);

    // Tick AFTER expiry — expired.
    let after = expires + chrono::Duration::milliseconds(50);
    sweeper.tick(after);
    assert_eq!(store.get("g-dur").unwrap().status, GrantStatus::Expired);
    assert_eq!(bus.count_of("grant.expired"), 1);
}

// MODULE-013-T15 — AC-13 — Sweeper expires on schedule (integration).
#[tokio::test]
async fn sweeper_expires_on_schedule() {
    let (store, bus, _h) = make_store();
    let now = Utc::now();
    let expires = now + chrono::Duration::milliseconds(120);
    let g = mk_grant(
        "g-sched",
        "alice",
        "fs",
        GrantTtl::Duration(120),
        Some(expires),
    );
    store.insert(g).unwrap();

    let bus_dyn: Arc<dyn advance_shared_types::traits::EventBusEmit> = bus.clone();
    let s = TtlSweeper::new(store.clone(), bus_dyn);
    let _h = s.clone().spawn(Duration::from_millis(50));

    // Wait long enough for the sweep to fire after expiry.
    tokio::time::sleep(Duration::from_millis(400)).await;

    assert_eq!(store.get("g-sched").unwrap().status, GrantStatus::Expired);
    assert!(bus.count_of("grant.expired") >= 1);

    drop(s);
}

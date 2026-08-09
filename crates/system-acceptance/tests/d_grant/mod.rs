//! Shared helpers for the Track-D grant system-acceptance witnesses (SYS-J-13/14/15).
//!
//! Included into each `sys_j1*_*.rs` test binary via `#[path = "d_grant/mod.rs"] mod d_grant;`
//! (the `h_loopback` pattern). Not itself a test binary (subdir module).

#![allow(dead_code)] // each test binary uses a subset of these helpers

use std::sync::Arc;

use advance_shared_types::event::Event;
use advance_shared_types::traits::EventBusEmit;
use cap_grant::data::{
    CapParam, Grant, GrantId, GrantIssuer, GrantProvenance, GrantStatus, GrantTtl,
};
use cap_grant::GrantStore;

/// The Track-D grant guest (imports agent-grant; dispatches req/revoke/delegate/narrow/apply-preset).
pub const GRANT_GUEST: &[u8] =
    include_bytes!("../../../runtime/tests/fixtures/guest-rust-d-grant.core.wasm");

/// The BS-3 fs guest (writes one file via fs.write) — reused for the SYS-J-15 L1-deny witness.
pub const J01_GUEST: &[u8] =
    include_bytes!("../../../runtime/tests/fixtures/guest-rust-j01-skeleton.core.wasm");

/// A no-op EventBus for constructing a `TtlSweeper`: the sweeper's own bus arg is dead-held
/// (`#[allow(dead_code)]` on the field), and `grant.expired` is emitted by `store.expire_ids`
/// via the STORE's own (harness-captured) bus — so this no-op bus is never used to emit.
pub struct NoopBus;
impl EventBusEmit for NoopBus {
    fn emit(&self, _event: Event) {}
}

pub fn cap(key: &str, value: &str) -> CapParam {
    CapParam {
        key: key.to_string(),
        value: value.to_string(),
    }
}

/// Seed an Active dynamic grant directly into the real wired store via the colon-tolerant
/// `insert_dynamic` path (provenance `Requested`, since `insert` colon-rejects `agent:`
/// grantees and `insert_dynamic` rejects `StaticConfig`). Returns the assigned id.
pub fn seed_grant(
    store: &GrantStore,
    id: &str,
    grantee: &str,
    capability: &str,
    params: Vec<CapParam>,
    ttl: GrantTtl,
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
) -> GrantId {
    let g = Grant {
        id: GrantId::new(id),
        grantee: grantee.to_string(),
        capability: capability.to_string(),
        params,
        ttl,
        issuer: GrantIssuer::Config,
        provenance: GrantProvenance::Requested,
        status: GrantStatus::Active,
        created_at: chrono::Utc::now(),
        expires_at,
    };
    store
        .insert_dynamic(g)
        .expect("seed grant via insert_dynamic")
}

/// Seed the bootstrap `"grant"` self-management grant for the harness agent — required
/// because every agent-grant host fn runs under capability `"grant"` at the L1 gate
/// (`capability_injector.rs`); without it the guest's grant call traps the turn.
pub fn seed_grant_capability(store: &GrantStore, agent: &str) -> GrantId {
    seed_grant(
        store,
        "seed-grant-cap",
        agent,
        "grant",
        vec![],
        GrantTtl::Persistent,
        None,
    )
}

/// Read a string field from an `Event`'s JSON payload.
pub fn str_field(e: &Event, key: &str) -> Option<String> {
    e.payload
        .get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}
pub fn decision_of(e: &Event) -> Option<String> {
    str_field(e, "decision")
}
pub fn resolver_type_of(e: &Event) -> Option<String> {
    str_field(e, "resolver_type")
}

/// Construct a `TtlSweeper` over the real wired store (the no-op bus arg is dead-held).
pub fn ttl_sweeper(store: Arc<GrantStore>) -> Arc<cap_grant::TtlSweeper> {
    let bus: Arc<dyn EventBusEmit> = Arc::new(NoopBus);
    cap_grant::TtlSweeper::new(store, bus)
}

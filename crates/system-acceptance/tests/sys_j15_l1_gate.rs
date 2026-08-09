//! SYS-J-15 — a host function present in the instance (L0) is still blocked at call time when no
//! L1 grant is present, producing an `authz.checked` event. Chain: MODULE-001 → MODULE-013 → MODULE-019.
//!
//! Witnessed over the REAL wired harness, reusing the BS-3 fs guest (`guest-rust-j01-skeleton`,
//! which on handle-message does ONE `fs.write`): under `grant(Real)` with NO fs grant issued, the
//! real `GrantCheckImpl` L1 gate denies the ungranted `fs.write` (the same authorization
//! differential as the green `mode_grant_smoke::real_grant_denies_ungranted_fs_write`), emitting an
//! `authz.checked` denied event (DeniedOnly default) via the store's captured bus before the trap.
//!
//! Active: SYS-AC-043 (L0-present fn denied at call time → no commit, no file), SYS-AC-044
//! (authz.checked {decision:denied, grant_id:"", function:".../agent-fs@0.1.0::write"}), SYS-AC-045
//! (this L1 authz.checked is distinct from the L0 `security.capability_denied`, which cap-grant
//! never emits).

#[path = "d_grant/mod.rs"]
mod d_grant;
use d_grant::*;

use system_acceptance::{Cap, GrantMode, SystemUnderTest};

#[tokio::test]
async fn sys_ac_043_044_045_l1_denies_ungranted_fs_write_with_authz_checked() {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Fs])
        .grant(GrantMode::Real) // real GrantCheckImpl L1 gate; no fs grant pre-seeded
        .build(J01_GUEST)
        .await;

    sut.inject_message("h", b"l1-deny-write").await;
    sut.run_turn().await;

    // SYS-AC-043: the host fn exists (L0) but is L1-denied → no turn commit, file never lands.
    assert_eq!(
        sut.turn_commits().iter().filter(|c| c.is_turn).count(),
        0,
        "ungranted fs.write denied at L1 → no turn commit"
    );
    assert!(
        sut.read_workspace_file("j01.txt").is_none(),
        "the denied write never landed"
    );

    // SYS-AC-044: an authz.checked denied event for the fs write host fn, with empty grant_id.
    let denied: Vec<_> = sut
        .events_of_types(&["authz.checked"])
        .into_iter()
        .filter(|e| str_field(e, "decision").as_deref() == Some("denied"))
        .collect();
    assert!(
        !denied.is_empty(),
        "the L1 deny emitted an authz.checked denied event"
    );
    let write_denial = denied
        .iter()
        .find(|e| {
            str_field(e, "function").as_deref() == Some("advance:runtime/agent-fs@0.1.0::write")
        })
        .expect("authz.checked for the fs write host fn");
    assert_eq!(
        str_field(write_denial, "grant_id").as_deref(),
        Some(""),
        "denied → empty grant_id"
    );

    // SYS-AC-045: the L1 authz.checked is distinct from the L0 security.capability_denied
    // (reserved for un-injected functions; cap-grant never emits it).
    assert!(
        sut.events_of_types(&["security.capability_denied"])
            .is_empty(),
        "L1 authz.checked is distinct from the L0 security.capability_denied"
    );
}

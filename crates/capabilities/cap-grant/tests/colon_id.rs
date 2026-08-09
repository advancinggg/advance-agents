//! Colon-id reconciliation regression tests (2026-06-06): the dynamic mutation paths
//! (`delegate_grant` / `narrow` / `apply_preset`) must accept the runtime's canonical
//! `agent:<slug>` caller / child / target id (so a real guest turn can drive them) while
//! STILL rejecting `user:` / multi-colon / malformed-prefix / control-byte / oversize ids.
//!
//! These are the module-level witnesses backing the SYS-AC-040/041/042/203/262 e2e flips:
//! T-COLON-01 (delegate accepts canonical), T-COLON-02 (narrow accepts canonical),
//! T-COLON-03 (apply_preset accepts canonical), T-COLON-04 (non-canonical colon ids rejected
//! on all three fns — incl. `user:alice`, which pins `agent:`-ONLY), T-COLON-05 (canonical
//! prefix but control-byte / oversize still rejected). The static-config `insert` path keeps
//! its stricter no-`:` grantee gate (deterministic-id separator) — see negative_paths.rs.

mod common;

use cap_grant::data::{
    CapParam, Grant, GrantDraft, GrantId, GrantIssuer, GrantProvenance, GrantStatus, GrantTtl,
};
use cap_grant::{CapGrantError, PresetRegistry, SubsetValidatorImpl, PRESET_RESTRICT};
use chrono::Utc;

use crate::common::make_store;

const HARNESS: &str = "agent:harness";
const CHILD: &str = "agent:child";

fn cap(key: &str, value: &str) -> CapParam {
    CapParam {
        key: key.to_string(),
        value: value.to_string(),
    }
}

/// Seed an Active dynamic grant via the colon-tolerant `insert_dynamic` path (provenance
/// `Requested`) — the same pattern the system-acceptance harness uses for `agent:`-grantees.
fn seed(
    store: &cap_grant::GrantStore,
    id: &str,
    grantee: &str,
    capability: &str,
    params: Vec<CapParam>,
) -> GrantId {
    let g = Grant {
        id: GrantId::new(id),
        grantee: grantee.to_string(),
        capability: capability.to_string(),
        params,
        ttl: GrantTtl::Persistent,
        issuer: GrantIssuer::Config,
        provenance: GrantProvenance::Requested,
        status: GrantStatus::Active,
        created_at: Utc::now(),
        expires_at: None,
    };
    store.insert_dynamic(g).expect("seed via insert_dynamic")
}

fn fs_draft(write_path: &str) -> GrantDraft {
    GrantDraft {
        capability: "fs".to_string(),
        params: vec![cap("write-paths", write_path)],
        ttl: GrantTtl::Persistent,
    }
}

// T-COLON-01 — delegate_grant accepts a canonical `agent:` caller_id AND child_agent.
#[test]
fn delegate_accepts_canonical_agent_ids() {
    let (store, bus, _h) = make_store();
    seed(
        &store,
        "parent-fs",
        HARNESS,
        "fs",
        vec![cap("write-paths", "/ws")],
    );
    let validator = SubsetValidatorImpl;

    let new_id = store
        .delegate_grant(
            "parent-fs",
            CHILD,
            fs_draft("/ws/child"),
            HARNESS,
            &validator,
        )
        .expect("delegate with canonical agent: ids succeeds");

    let child = store.get(new_id.as_str()).expect("child grant exists");
    assert_eq!(
        child.grantee, CHILD,
        "child grant grantee is the canonical agent:child"
    );
    assert_eq!(child.status, GrantStatus::Active);
    assert_eq!(
        child.provenance,
        GrantProvenance::Delegated(GrantId::new("parent-fs")),
        "provenance records the exact parent grant id"
    );
    // Witnessed via list_by_grantee on the canonical child id.
    let child_grants: Vec<_> = store
        .list_by_grantee(CHILD)
        .into_iter()
        .filter(|g| g.capability == "fs")
        .collect();
    assert_eq!(
        child_grants.len(),
        1,
        "child's active-grants lists exactly the delegated fs grant"
    );

    let evt = bus
        .first_of("grant.delegated")
        .expect("grant.delegated emitted");
    assert_eq!(evt.payload["parent_agent"], HARNESS);
    assert_eq!(evt.payload["child_agent"], CHILD);
}

// T-COLON-02 — narrow accepts a canonical `agent:` caller_id; narrowed params are observable.
#[test]
fn narrow_accepts_canonical_agent_id() {
    let (store, bus, _h) = make_store();
    seed(
        &store,
        "narrow-me",
        HARNESS,
        "fs",
        vec![cap("write-paths", "/ws")],
    );
    let validator = SubsetValidatorImpl;

    let new_id = store
        .narrow(
            "narrow-me",
            vec![cap("write-paths", "/ws/narrowed")],
            HARNESS,
            &validator,
        )
        .expect("narrow with canonical agent: caller succeeds");

    // grant.narrowed carries the full 4-field payload incl. narrowed_by == agent:harness.
    let evt = bus
        .first_of("grant.narrowed")
        .expect("grant.narrowed emitted");
    assert_eq!(evt.payload["narrowed_by"], HARNESS);
    assert_eq!(bus.count_of("grant.narrowed"), 1);

    // narrow mints a NEW grant (the seeded one is Revoked); the narrowed params live on the
    // new Active grant — exactly what grant-status would return.
    let narrowed = store.get(new_id.as_str()).expect("narrowed grant exists");
    assert_eq!(narrowed.status, GrantStatus::Active);
    assert_eq!(narrowed.params, vec![cap("write-paths", "/ws/narrowed")]);
    assert_eq!(narrowed.grantee, HARNESS);
}

// T-COLON-03 — apply_preset accepts a canonical `agent:` caller_id == target_grantee.
#[test]
fn apply_preset_accepts_canonical_agent_id() {
    let (store, bus, _h) = make_store();
    let validator = SubsetValidatorImpl;
    let registry = PresetRegistry::with_builtins();

    registry
        .apply_preset(PRESET_RESTRICT, HARNESS, &store, &validator, HARNESS)
        .expect("apply_preset with canonical agent: caller==target succeeds");

    let evt = bus
        .first_of("preset.applied")
        .expect("preset.applied emitted");
    assert_eq!(evt.payload["target_agent"], HARNESS);
}

// T-COLON-04 — non-canonical colon ids are STILL rejected on all three mutation paths.
// `user:alice` is included specifically to pin `agent:`-ONLY (it would be accepted under an
// `agent:|user:` predicate).
#[test]
fn malformed_colon_ids_rejected_everywhere() {
    let bad_ids = [
        "user:alice",        // single-colon user id — pins agent:-only
        "user:agent:victim", // multi-colon
        "agent:a:b",         // multi-colon under agent:
        "ali:ce",            // unknown prefix
        "bo:b",              // unknown prefix
        "agent:",            // empty body
        ":foo",              // leading colon
        "foo:bar",           // unknown prefix
    ];
    let validator = SubsetValidatorImpl;

    for bad in bad_ids {
        // delegate caller_id (valid parent-id string + valid child so the caller gate fires).
        let (store, bus, _h) = make_store();
        let err = store
            .delegate_grant("static:alice:http", "bob", fs_draft("/ws"), bad, &validator)
            .unwrap_err();
        assert!(
            matches!(err, CapGrantError::InvalidConfig(_)),
            "delegate caller {bad:?}: {err:?}"
        );
        assert_eq!(
            bus.count_of("grant.delegated"),
            0,
            "delegate caller {bad:?} emits nothing"
        );

        // delegate child_agent (valid bare caller).
        let (store, bus, _h) = make_store();
        let err = store
            .delegate_grant(
                "static:alice:http",
                bad,
                fs_draft("/ws"),
                "alice",
                &validator,
            )
            .unwrap_err();
        assert!(
            matches!(err, CapGrantError::InvalidConfig(_)),
            "delegate child {bad:?}: {err:?}"
        );
        assert_eq!(
            bus.count_of("grant.delegated"),
            0,
            "delegate child {bad:?} emits nothing"
        );

        // narrow caller_id (gate fires before grant lookup).
        let (store, bus, _h) = make_store();
        let err = store
            .narrow(
                "any-grant",
                vec![cap("write-paths", "/ws")],
                bad,
                &validator,
            )
            .unwrap_err();
        assert!(
            matches!(err, CapGrantError::InvalidConfig(_)),
            "narrow caller {bad:?}: {err:?}"
        );
        assert_eq!(
            bus.count_of("grant.narrowed"),
            0,
            "narrow caller {bad:?} emits nothing"
        );

        // apply_preset caller_id.
        let (store, bus, _h) = make_store();
        let registry = PresetRegistry::with_builtins();
        let err = registry
            .apply_preset(PRESET_RESTRICT, "alice", &store, &validator, bad)
            .unwrap_err();
        assert!(
            matches!(err, CapGrantError::InvalidConfig(_)),
            "preset caller {bad:?}: {err:?}"
        );
        assert_eq!(
            bus.count_of("preset.applied"),
            0,
            "preset caller {bad:?} emits nothing"
        );

        // apply_preset target_grantee.
        let (store, bus, _h) = make_store();
        let registry = PresetRegistry::with_builtins();
        let err = registry
            .apply_preset(PRESET_RESTRICT, bad, &store, &validator, "alice")
            .unwrap_err();
        assert!(
            matches!(err, CapGrantError::InvalidConfig(_)),
            "preset target {bad:?}: {err:?}"
        );
        assert_eq!(
            bus.count_of("preset.applied"),
            0,
            "preset target {bad:?} emits nothing"
        );
    }
}

// T-COLON-05 — a canonical `agent:` prefix with a control byte or oversize body is STILL
// rejected (the widening does not re-open control-byte / DoS-amplification surfaces).
#[test]
fn canonical_prefix_control_or_oversize_rejected() {
    let validator = SubsetValidatorImpl;
    let oversize = format!("agent:{}", "a".repeat(257)); // > 256-byte cap
    let bad_ids = ["agent:a\nb", "agent:a\0b", oversize.as_str()];

    for bad in bad_ids {
        let (store, _bus, _h) = make_store();
        let err = store
            .delegate_grant("static:alice:http", "bob", fs_draft("/ws"), bad, &validator)
            .unwrap_err();
        assert!(
            matches!(err, CapGrantError::InvalidConfig(_)),
            "delegate caller {bad:?}: {err:?}"
        );

        let (store, _bus, _h) = make_store();
        let err = store
            .narrow(
                "any-grant",
                vec![cap("write-paths", "/ws")],
                bad,
                &validator,
            )
            .unwrap_err();
        assert!(
            matches!(err, CapGrantError::InvalidConfig(_)),
            "narrow caller {bad:?}: {err:?}"
        );
    }
}

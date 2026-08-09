//! AC-05 (REQ-201) — `IdentityResolver`: channel-specific id → `user:alice`.
//! Canonical §3.3 T06 is a UNIT test ("telegram:user123 → user:alice");
//! these tests verify the mapping logic + construction validation.

use std::collections::HashMap;

use advance_messaging::{IdentityResolver, IdentityResolverError, UserChannelMapping};

fn chan(kind: &str, id: &str) -> HashMap<String, String> {
    let mut m = HashMap::new();
    m.insert(kind.to_string(), id.to_string());
    m
}

// T-B01 — resolve hit (canonical T06).
#[test]
fn t_b01_resolve_hit() {
    let r = IdentityResolver::from_user_mappings(&[UserChannelMapping {
        id: "user:alice".into(),
        channels: vec![chan("telegram", "user123")],
    }])
    .unwrap();
    assert_eq!(
        r.resolve("telegram", "user123").as_deref(),
        Some("user:alice")
    );
}

// T-B02 — unknown channel_id → None.
#[test]
fn t_b02_unknown_id_none() {
    let r = IdentityResolver::from_user_mappings(&[UserChannelMapping {
        id: "user:alice".into(),
        channels: vec![chan("telegram", "user123")],
    }])
    .unwrap();
    assert_eq!(r.resolve("telegram", "missing"), None);
}

// T-B03 — unknown channel_kind → None (even when the id exists under
// another kind).
#[test]
fn t_b03_unknown_kind_none() {
    let r = IdentityResolver::from_user_mappings(&[UserChannelMapping {
        id: "user:alice".into(),
        channels: vec![chan("telegram", "user123")],
    }])
    .unwrap();
    assert_eq!(r.resolve("discord", "user123"), None);
}

// T-B04 — duplicate (kind, id) across users → DuplicateChannelPair.
#[test]
fn t_b04_dup_pair_rejected() {
    let err = IdentityResolver::from_user_mappings(&[
        UserChannelMapping {
            id: "user:alice".into(),
            channels: vec![chan("telegram", "shared")],
        },
        UserChannelMapping {
            id: "user:bob".into(),
            channels: vec![chan("telegram", "shared")],
        },
    ])
    .unwrap_err();
    assert_eq!(err, IdentityResolverError::DuplicateChannelPair);
}

// T-B05 — empty id / channel_kind / channel_id → EmptyField.
#[test]
fn t_b05_empty_fields_rejected() {
    let empty_id = IdentityResolver::from_user_mappings(&[UserChannelMapping {
        id: String::new(),
        channels: vec![chan("telegram", "x")],
    }])
    .unwrap_err();
    assert_eq!(empty_id, IdentityResolverError::EmptyField("id"));

    let empty_kind = IdentityResolver::from_user_mappings(&[UserChannelMapping {
        id: "user:alice".into(),
        channels: vec![chan("", "x")],
    }])
    .unwrap_err();
    assert_eq!(
        empty_kind,
        IdentityResolverError::EmptyField("channel_kind")
    );

    let empty_cid = IdentityResolver::from_user_mappings(&[UserChannelMapping {
        id: "user:alice".into(),
        channels: vec![chan("telegram", "")],
    }])
    .unwrap_err();
    assert_eq!(empty_cid, IdentityResolverError::EmptyField("channel_id"));
}

// T-B06 — unsafe / non-`user:` id + multi-key channel map rejected.
#[test]
fn t_b06_unsafe_id_and_multikey_rejected() {
    // Not user:-prefixed.
    let bare = IdentityResolver::from_user_mappings(&[UserChannelMapping {
        id: "alice".into(),
        channels: vec![chan("telegram", "x")],
    }])
    .unwrap_err();
    assert_eq!(bare, IdentityResolverError::UnsafeUserId);

    // Newline splice in id.
    let splice = IdentityResolver::from_user_mappings(&[UserChannelMapping {
        id: "user:alice\nspoof".into(),
        channels: vec![chan("telegram", "x")],
    }])
    .unwrap_err();
    assert_eq!(splice, IdentityResolverError::UnsafeUserId);

    // Multi-key channel map.
    let mut multi = HashMap::new();
    multi.insert("telegram".to_string(), "a".to_string());
    multi.insert("slack".to_string(), "b".to_string());
    let mk = IdentityResolver::from_user_mappings(&[UserChannelMapping {
        id: "user:alice".into(),
        channels: vec![multi],
    }])
    .unwrap_err();
    assert_eq!(mk, IdentityResolverError::MultiKeyChannelMap);
}

// T-B44 — colon-bearing channel_kind/channel_id do NOT alias across
// logically-distinct pairs (Adversarial r1 fix: tuple key, not "{k}:{id}"
// concatenation). ("a:b","c") and ("a","b:c") must remain SEPARATE
// mappings resolving to their own distinct unified ids — no identity-spoof
// collision.
#[test]
fn t_b44_colon_keys_no_alias_collision() {
    let r = IdentityResolver::from_user_mappings(&[
        UserChannelMapping {
            id: "user:alice".into(),
            channels: vec![chan("a:b", "c")],
        },
        UserChannelMapping {
            id: "user:bob".into(),
            channels: vec![chan("a", "b:c")],
        },
    ])
    .expect("colon-bearing distinct pairs must NOT be rejected as duplicates");
    assert_eq!(r.resolve("a:b", "c").as_deref(), Some("user:alice"));
    assert_eq!(r.resolve("a", "b:c").as_deref(), Some("user:bob"));
    // The pre-fix concatenation would have aliased both to "a:b:c"; assert
    // the cross-lookups do NOT leak the other identity.
    assert_eq!(r.resolve("a:b:c", "").as_deref(), None);
    assert_eq!(r.resolve("", "a:b:c").as_deref(), None);
}

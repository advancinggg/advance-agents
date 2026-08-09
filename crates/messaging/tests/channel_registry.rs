//! `StaticChannelAdapterRegistry::insert` validation-branch tripwires
//! (T-B37..T-B40) + IdentityResolver cap branch (T-B41). These close the
//! audit-flagged untested security-relevant boundary code (the registry
//! gates which agent a channel notify is routed to; the resolver cap bounds
//! memory).

use std::collections::HashMap;

use advance_messaging::{
    ChannelAdapterRegistry, EmptyChannelAdapterRegistry, IdentityResolver, IdentityResolverError,
    MsgError, StaticChannelAdapterRegistry, UserChannelMapping, MAX_CHANNEL_ADAPTERS,
    MAX_IDENTITY_MAPPINGS,
};

// T-B37 — insert rejects an empty channel_id.
#[test]
fn t_b37_insert_empty_channel_id() {
    let mut r = StaticChannelAdapterRegistry::new();
    let err = r.insert("", "agent:adapter-tg").unwrap_err();
    assert_eq!(err, MsgError::InvalidTarget("channel_id_empty".into()));
}

// T-B38 — insert rejects a non-safe / non-`agent:`-prefixed adapter id.
#[test]
fn t_b38_insert_invalid_adapter_id() {
    let mut r = StaticChannelAdapterRegistry::new();
    // Not agent:-prefixed.
    assert_eq!(
        r.insert("telegram", "user:alice").unwrap_err(),
        MsgError::InvalidTarget("adapter_id_invalid".into())
    );
    // Newline splice.
    assert_eq!(
        r.insert("telegram", "agent:tg\nspoof").unwrap_err(),
        MsgError::InvalidTarget("adapter_id_invalid".into())
    );
}

// T-B39 — insert rejects past MAX_CHANNEL_ADAPTERS with CapabilityDenied.
#[test]
fn t_b39_insert_registry_full() {
    let mut r = StaticChannelAdapterRegistry::new();
    for i in 0..MAX_CHANNEL_ADAPTERS {
        r.insert(format!("chan{i}"), "agent:adapter").unwrap();
    }
    let err = r.insert("chan_overflow", "agent:adapter").unwrap_err();
    assert_eq!(err, MsgError::CapabilityDenied("registry_full".into()));
}

// T-B40 — at cap, overwriting an EXISTING channel_id is allowed (the cap
// guards growth, not updates); and Empty registry resolves nothing.
#[test]
fn t_b40_overwrite_at_cap_and_empty_registry() {
    let mut r = StaticChannelAdapterRegistry::new();
    for i in 0..MAX_CHANNEL_ADAPTERS {
        r.insert(format!("chan{i}"), "agent:a").unwrap();
    }
    // contains_key bypasses the cap → update succeeds.
    r.insert("chan0", "agent:updated")
        .expect("overwriting an existing key at cap must succeed");
    assert_eq!(r.resolve("chan0").as_deref(), Some("agent:updated"));

    let empty = EmptyChannelAdapterRegistry;
    assert_eq!(empty.resolve("anything"), None);
}

// T-B41 — IdentityResolver caps at MAX_IDENTITY_MAPPINGS → TooManyMappings.
#[test]
fn t_b41_identity_resolver_cap() {
    // One user carrying MAX_IDENTITY_MAPPINGS + 1 single-key channel maps.
    let channels: Vec<HashMap<String, String>> = (0..=MAX_IDENTITY_MAPPINGS)
        .map(|i| {
            let mut m = HashMap::new();
            m.insert("telegram".to_string(), format!("id{i}"));
            m
        })
        .collect();
    let err = IdentityResolver::from_user_mappings(&[UserChannelMapping {
        id: "user:alice".into(),
        channels,
    }])
    .unwrap_err();
    assert_eq!(err, IdentityResolverError::TooManyMappings);
}

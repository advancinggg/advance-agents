//! Slice I — type-level tests for CapabilityId / CapRequest / CapParams.
//!
//! Mirrors the Slice A' test pattern: serde round-trip, wire-format lock,
//! deny_unknown_fields negative, compile-time Send+Sync+Clone+Debug+PartialEq.

use advance_shared_types::capability::{CapParams, CapRequest, CapabilityId};
use serde_json::json;
use std::collections::HashMap;

#[test]
fn capability_id_from_str_roundtrip() {
    let id = CapabilityId::from("cap-fs");
    let json = serde_json::to_string(&id).unwrap();
    assert_eq!(json, r#""cap-fs""#);
    let back: CapabilityId = serde_json::from_str(&json).unwrap();
    assert_eq!(id, back);
}

#[test]
fn capability_id_display_and_as_ref() {
    let id = CapabilityId::from("cap-fs");
    assert_eq!(format!("{}", id), "cap-fs");
    assert_eq!(id.as_ref(), "cap-fs");
    assert_eq!(id.as_str(), "cap-fs");
}

#[test]
fn capability_id_hash_eq_in_hashmap() {
    let mut m: HashMap<CapabilityId, u32> = HashMap::new();
    m.insert(CapabilityId::from("cap-a"), 1);
    m.insert(CapabilityId::from("cap-b"), 2);
    m.insert(CapabilityId::from("cap-c"), 3);
    assert_eq!(m.get(&CapabilityId::from("cap-a")), Some(&1));
    assert_eq!(m.get(&CapabilityId::from("cap-b")), Some(&2));
    assert_eq!(m.get(&CapabilityId::from("cap-c")), Some(&3));
    // Borrow<str> probe — key insight that enables HostRegistry migration.
    assert_eq!(m.get("cap-a"), Some(&1));
    assert_eq!(m.get("cap-missing"), None);
}

#[test]
fn capability_id_wire_format_lock() {
    let id = CapabilityId::new("cap-fs-read");
    assert_eq!(serde_json::to_string(&id).unwrap(), r#""cap-fs-read""#);
}

#[test]
fn caprequest_serde_roundtrip() {
    let req = CapRequest {
        capability: CapabilityId::from("cap-llm"),
    };
    let json = serde_json::to_string(&req).unwrap();
    let back: CapRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(req, back);
}

#[test]
fn caprequest_deny_unknown_fields_rejects_smuggled_key() {
    let bad = r#"{"capability":"cap-fs","injected":"x"}"#;
    let err = serde_json::from_str::<CapRequest>(bad).unwrap_err();
    assert_eq!(err.classify(), serde_json::error::Category::Data);
}

#[test]
fn caprequest_wire_format_lock() {
    let req = CapRequest {
        capability: CapabilityId::from("cap-fs-read"),
    };
    assert_eq!(
        serde_json::to_string(&req).unwrap(),
        r#"{"capability":"cap-fs-read"}"#
    );
}

#[test]
fn capparams_transparent_serde() {
    let p = CapParams::from(json!({"a": 1}));
    assert_eq!(serde_json::to_string(&p).unwrap(), r#"{"a":1}"#);
}

#[test]
fn capparams_accepts_any_json() {
    for raw in ["null", "true", "42", r#""s""#, "[]", "{}"] {
        let p: CapParams = serde_json::from_str(raw).unwrap();
        assert_eq!(serde_json::to_string(&p).unwrap(), raw);
    }
}

#[test]
fn types_are_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<CapabilityId>();
    assert_send_sync::<CapRequest>();
    assert_send_sync::<CapParams>();
}

#[test]
fn types_are_clone_debug_partialeq() {
    fn assert_traits<T: Clone + std::fmt::Debug + PartialEq>() {}
    assert_traits::<CapabilityId>();
    assert_traits::<CapRequest>();
    assert_traits::<CapParams>();
}

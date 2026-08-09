//! MODULE-014 source witness (Wave-20): the additive
//! `ComponentSubmitConfig.sensitive_params` field — serde round-trip, back-compat
//! under `deny_unknown_fields`, and the bounded-deserialize caps (width +
//! per-name length). The M014 source for the MODULE-012-AC-10 redaction (HELD).

use advance_scheduler::types::{
    ComponentSubmitConfig, MAX_SENSITIVE_PARAMS, MAX_SENSITIVE_PARAM_NAME_LEN,
};
use advance_shared_types::component::ComponentType;

fn base() -> ComponentSubmitConfig {
    ComponentSubmitConfig {
        id: "comp-1".into(),
        component_type: ComponentType::Task,
        binary: Vec::new(),
        capabilities: Vec::new(),
        output_dir: None,
        trigger: None,
        restart_policy: None,
        delay: None,
        initial_grants: None,
        preset: None,
        retry: None,
        sensitive_params: vec!["api_key".into(), "password".into()],
    }
}

#[test]
fn roundtrips_with_kebab_wire_key() {
    let cfg = base();
    let s = serde_json::to_string(&cfg).unwrap();
    assert!(s.contains("\"sensitive-params\""), "kebab wire key: {s}");
    let back: ComponentSubmitConfig = serde_json::from_str(&s).unwrap();
    assert_eq!(back.sensitive_params, vec!["api_key", "password"]);
}

#[test]
fn back_compat_missing_field_defaults_empty() {
    // An OLD config JSON without `sensitive-params` still deserializes (default
    // empty) despite `deny_unknown_fields` (which rejects EXTRA, not MISSING).
    let mut v = serde_json::to_value(base()).unwrap();
    v.as_object_mut().unwrap().remove("sensitive-params");
    let cfg: ComponentSubmitConfig = serde_json::from_value(v).unwrap();
    assert!(cfg.sensitive_params.is_empty());
}

#[test]
fn rejects_oversize_list_width() {
    let mut v = serde_json::to_value(base()).unwrap();
    let too_many: Vec<String> = (0..(MAX_SENSITIVE_PARAMS + 1))
        .map(|i| format!("p{i}"))
        .collect();
    v["sensitive-params"] = serde_json::to_value(too_many).unwrap();
    let err = serde_json::from_value::<ComponentSubmitConfig>(v).unwrap_err();
    assert!(
        err.to_string().contains("MAX_SENSITIVE_PARAMS"),
        "width cap reject: {err}"
    );
}

#[test]
fn rejects_oversize_param_name() {
    let mut v = serde_json::to_value(base()).unwrap();
    let long = "x".repeat(MAX_SENSITIVE_PARAM_NAME_LEN + 1);
    v["sensitive-params"] = serde_json::json!([long]);
    let err = serde_json::from_value::<ComponentSubmitConfig>(v).unwrap_err();
    assert!(
        err.to_string().contains("MAX_SENSITIVE_PARAM_NAME_LEN"),
        "name-length cap reject: {err}"
    );
}

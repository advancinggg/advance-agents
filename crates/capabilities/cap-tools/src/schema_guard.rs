//! Intra-schema `$ref` / `$id` guard. MODULE-017 Slice F.
//!
//! Local duplicate of `cap-mcp/src/schema_validator.rs::require_intra_schema_refs`
//! (cap-mcp keeps it module-private, so cross-crate reuse would require either a
//! cap-mcp surface change or adding cap-mcp as a cap-tools dependency — both out
//! of Slice F scope; see MODULE-017 §3.6 (mm) for the consolidation-deferral
//! rationale).
//!
//! `jsonschema = 0.18.3`'s default resolver fetches absolute `$ref` URLs at
//! compile time — a DoS surface when schemas are attacker-influenced. This guard
//! runs BEFORE `JSONSchema::compile` and fails closed on:
//! 1. any `$ref` / `$dynamicRef` / `$recursiveRef` not exactly `#` or `#/`-prefixed,
//! 2. any `$id` with an absolute-URI scheme (`<word>:`) or scheme-relative `//` form,
//! 3. nesting deeper than [`MAX_SCHEMA_DEPTH`].

/// Recursion-depth bound for the schema walk. 64 levels is generous for any sane
/// JSON Schema; rejects deeply-nested DoS payloads before the recursion reaches
/// the host thread's stack-overflow point. Note: `serde_json::from_str` already
/// fails closed at its own built-in recursion limit (128) when the schema string
/// is parsed upstream, so this bound is a belt-and-suspenders guard over the
/// already-materialized `Value`.
pub(crate) const MAX_SCHEMA_DEPTH: usize = 64;

/// Walk a schema `Value`, rejecting non-intra-schema refs + scheme-bearing `$id`
/// + over-deep nesting. Returns `Err(reason)` with a fixed safe-class message on
/// rejection (the caller maps it to `ToolError::Input/OutputValidationFailed`).
pub(crate) fn require_intra_schema_refs(schema: &serde_json::Value) -> Result<(), String> {
    fn walk(v: &serde_json::Value, depth: usize) -> Result<(), String> {
        if depth > MAX_SCHEMA_DEPTH {
            return Err(format!("schema nesting exceeds depth {MAX_SCHEMA_DEPTH}"));
        }
        match v {
            serde_json::Value::Object(map) => {
                // `$id` base-URI rejection: jsonschema 0.18.3 uses `$id` as a base
                // URI for ref resolution. A scheme-bearing or scheme-relative `$id`
                // could trigger remote base-URI resolution even when all `$ref`
                // values pass the intra-schema check. A relative `$id` like
                // `"my-schema"` or `"#frag"` is permitted.
                if let Some(serde_json::Value::String(s)) = map.get("$id") {
                    let trimmed = s.trim();
                    let has_scheme = trimmed
                        .find(':')
                        .map(|i| {
                            let before = &trimmed[..i];
                            !before.is_empty()
                                && before.chars().all(|c| {
                                    c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.'
                                })
                        })
                        .unwrap_or(false);
                    if has_scheme || trimmed.starts_with("//") {
                        return Err(
                            "schema $id must not contain an absolute URI / scheme-relative form"
                                .to_string(),
                        );
                    }
                }
                for ref_key in &["$ref", "$dynamicRef", "$recursiveRef"] {
                    if let Some(serde_json::Value::String(s)) = map.get(*ref_key) {
                        if s != "#" && !s.starts_with("#/") {
                            return Err(format!(
                                "schema {ref_key} must be intra-schema (`#` or `#/...`)"
                            ));
                        }
                    }
                }
                for child in map.values() {
                    walk(child, depth + 1)?;
                }
                Ok(())
            }
            serde_json::Value::Array(arr) => {
                for child in arr {
                    walk(child, depth + 1)?;
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }
    walk(schema, 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // MODULE-017-T85 — non-intra $ref rejected.
    #[test]
    fn t85_rejects_network_ref() {
        let schema =
            json!({"type": "object", "properties": {"x": {"$ref": "https://malicious/foo"}}});
        assert!(require_intra_schema_refs(&schema).is_err());
    }

    #[test]
    fn t85_accepts_intra_refs() {
        assert!(require_intra_schema_refs(&json!({"$ref": "#"})).is_ok());
        assert!(require_intra_schema_refs(&json!({"$ref": "#/definitions/foo"})).is_ok());
    }

    // MODULE-017-T86 — non-intra $dynamicRef + $recursiveRef rejected.
    #[test]
    fn t86_rejects_dynamic_and_recursive_refs() {
        assert!(require_intra_schema_refs(&json!({"$dynamicRef": "https://x/y"})).is_err());
        assert!(
            require_intra_schema_refs(&json!({"$recursiveRef": "file:///etc/passwd"})).is_err()
        );
        // Intra forms of both are accepted.
        assert!(require_intra_schema_refs(&json!({"$dynamicRef": "#/$defs/node"})).is_ok());
        assert!(require_intra_schema_refs(&json!({"$recursiveRef": "#"})).is_ok());
    }

    // MODULE-017-T86b — $id scheme / scheme-relative rejected; relative accepted.
    #[test]
    fn t86b_id_scheme_rejection() {
        assert!(require_intra_schema_refs(&json!({"$id": "https://evil/x"})).is_err());
        assert!(require_intra_schema_refs(&json!({"$id": "//host/x"})).is_err());
        assert!(require_intra_schema_refs(&json!({"$id": "file:///x"})).is_err());
        // Relative + fragment forms are permitted.
        assert!(require_intra_schema_refs(&json!({"$id": "my-schema"})).is_ok());
        assert!(require_intra_schema_refs(&json!({"$id": "#frag"})).is_ok());
    }

    // MODULE-017-T86c — nesting deeper than MAX_SCHEMA_DEPTH rejected.
    #[test]
    fn t86c_depth_bound() {
        // Build a nested-object schema MAX_SCHEMA_DEPTH+5 deep.
        let mut v = json!({"type": "string"});
        for _ in 0..(MAX_SCHEMA_DEPTH + 5) {
            v = json!({"type": "object", "properties": {"n": v}});
        }
        assert!(require_intra_schema_refs(&v).is_err());
        // A shallow schema is fine.
        assert!(require_intra_schema_refs(
            &json!({"type": "object", "properties": {"x": {"type": "number"}}})
        )
        .is_ok());
    }
}

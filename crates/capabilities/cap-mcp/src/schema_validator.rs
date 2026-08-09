//! `SchemaValidator` — MODULE-017 Slice D AC-13.
//!
//! Wraps `jsonschema::JSONSchema` for input/output validation on
//! `invoke-mcp-tool`. The validator runs a recursive pre-scan that rejects any
//! schema whose `$ref` / `$dynamicRef` / `$recursiveRef` value isn't exactly
//! `#` (whole-document) or a `#/`-prefixed JSON Pointer fragment.
//!
//! jsonschema = 0.18.3's default resolver fetches absolute URLs at compile
//! time, which is a DoS surface when schemas can be attacker-controlled (an
//! MCP server can return arbitrary tool schemas). The fail-closed pre-scan is
//! broader than a scheme blocklist (which would miss `file://` / `data:` /
//! `javascript:` / scheme-relative `//host/x`) and aligns with the typical
//! "self-contained schema" use case for MCP tool input/output.

use std::sync::Arc;

use crate::error::McpError;

pub struct SchemaValidator {
    inner: Arc<jsonschema::JSONSchema>,
}

impl std::fmt::Debug for SchemaValidator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SchemaValidator")
            .field("inner", &"<JSONSchema>")
            .finish()
    }
}

impl SchemaValidator {
    /// Compile a schema. Rejects schemas containing non-intra-schema `$ref` /
    /// `$dynamicRef` / `$recursiveRef` values, then compiles via
    /// `jsonschema::JSONSchema::compile`. Returns `McpErrorKind::InvalidResponse`
    /// for both pre-scan and compile failures.
    pub fn new(schema: &serde_json::Value) -> Result<Self, McpError> {
        require_intra_schema_refs(schema)?;
        let compiled = jsonschema::JSONSchema::compile(schema)
            .map_err(|e| McpError::invalid_response(format!("invalid schema: {e}")))?;
        Ok(Self {
            inner: Arc::new(compiled),
        })
    }

    /// Validate a value against the compiled schema. Returns Ok(()) on success,
    /// `McpErrorKind::InvalidResponse` with the first validation error message
    /// on failure (redacted-safe-class style mirroring SB-22 discipline).
    pub fn validate(&self, value: &serde_json::Value) -> Result<(), McpError> {
        match self.inner.validate(value) {
            Ok(()) => Ok(()),
            Err(_errors) => {
                // Audit round 1 W8 fix: jsonschema's ValidationError::to_string()
                // embeds the offending JSON value verbatim — when validating an
                // MCP-server-controlled output, this would leak server-controlled
                // content into the agent-facing error message, bypassing the
                // leak detector (which scanned the raw bytes but not the
                // formatted error). Fixed safe-class message only.
                Err(McpError::invalid_response("schema validation failed"))
            }
        }
    }
}

/// Recursive walk over Objects + Arrays + scalars. For any Object containing
/// `$ref` / `$dynamicRef` / `$recursiveRef` with a String value, reject unless
/// the value is exactly `#` or starts with `#/` (JSON Pointer fragment form).
/// Adversarial round 1 W3 fix: bound recursion depth to prevent
/// stack-overflow on pathologically-nested schemas. 64 levels is generous
/// for any sane JSON-schema; rejects deeply-nested DoS payloads BEFORE the
/// recursion reaches the host thread's stack-overflow point. Note: the
/// schema itself was already materialized as a serde_json::Value upstream
/// (so the deserializer must already have accepted it), but jsonschema's
/// own internal walks can still exhaust stack on such inputs.
pub(crate) const MAX_SCHEMA_DEPTH: usize = 64;

fn require_intra_schema_refs(schema: &serde_json::Value) -> Result<(), McpError> {
    fn walk(v: &serde_json::Value, depth: usize) -> Result<(), McpError> {
        if depth > MAX_SCHEMA_DEPTH {
            return Err(McpError::invalid_response(format!(
                "schema nesting exceeds depth {MAX_SCHEMA_DEPTH}"
            )));
        }
        match v {
            serde_json::Value::Object(map) => {
                // Audit round 1 W5 fix: jsonschema 0.18.3 uses `$id` as a
                // base URI for ref resolution. A schema with `$id`
                // containing an absolute URI scheme could trigger remote
                // base-URI resolution / fetch attempts even when all
                // `$ref` values pass the intra-schema check. Reject any
                // `$id` that contains a scheme-like prefix (`<word>:`)
                // OR that starts with `//` (scheme-relative). A relative
                // `$id` like `"my-schema"` or `"#frag"` is permitted.
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
                        return Err(McpError::invalid_response(
                            "schema $id must not contain an absolute URI / scheme-relative form",
                        ));
                    }
                }
                for ref_key in &["$ref", "$dynamicRef", "$recursiveRef"] {
                    if let Some(serde_json::Value::String(s)) = map.get(*ref_key) {
                        if s != "#" && !s.starts_with("#/") {
                            return Err(McpError::invalid_response(format!(
                                "schema {ref_key} must be intra-schema (`#` or `#/...`)",
                            )));
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

// Slice D — compile-time Send + Sync proof. JSONSchema's internals are regex-
// backed; this asserts the trait bounds hold so SchemaValidator can be cloned
// behind Arc and shared across host_fn dispatch tasks.
fn _assert_send_sync()
where
    SchemaValidator: Send + Sync,
{
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn new_accepts_valid_draft_07_schema() {
        let schema = json!({
            "$schema": "http://json-schema.org/draft-07/schema#",
            "type": "object",
            "properties": {"name": {"type": "string"}},
            "required": ["name"],
        });
        SchemaValidator::new(&schema).expect("valid schema");
    }

    #[test]
    fn new_rejects_unparseable_schema() {
        let schema = json!({"type": 42}); // type should be a string, not a number
        let err = SchemaValidator::new(&schema).expect_err("must reject");
        assert_eq!(err.kind, crate::error::McpErrorKind::InvalidResponse);
        assert!(err.message.contains("invalid schema"));
    }

    #[test]
    fn validate_accepts_matching_value() {
        let schema = json!({
            "type": "object",
            "properties": {"name": {"type": "string"}},
            "required": ["name"],
        });
        let v = SchemaValidator::new(&schema).unwrap();
        v.validate(&json!({"name": "alice"})).expect("matches");
    }

    #[test]
    fn validate_rejects_violating_value() {
        let schema = json!({
            "type": "object",
            "properties": {"name": {"type": "string"}},
            "required": ["name"],
        });
        let v = SchemaValidator::new(&schema).unwrap();
        let err = v.validate(&json!({})).expect_err("missing required");
        assert_eq!(err.kind, crate::error::McpErrorKind::InvalidResponse);
        assert!(err.message.contains("schema validation failed"));
    }

    #[test]
    fn rejects_external_ref_http() {
        let s = json!({"$ref": "http://example.com/schema.json"});
        let err = SchemaValidator::new(&s).expect_err("http");
        assert!(err.message.contains("must be intra-schema"));
    }

    #[test]
    fn rejects_external_ref_https() {
        let s = json!({"$ref": "https://example.com/schema.json"});
        let err = SchemaValidator::new(&s).expect_err("https");
        assert!(err.message.contains("must be intra-schema"));
    }

    #[test]
    fn rejects_external_ref_https_uppercase() {
        let s = json!({"$ref": "HTTPS://example.com/schema.json"});
        let err = SchemaValidator::new(&s).expect_err("HTTPS uppercase");
        assert!(err.message.contains("must be intra-schema"));
    }

    #[test]
    fn rejects_external_ref_file() {
        let s = json!({"$ref": "file:///etc/passwd"});
        let err = SchemaValidator::new(&s).expect_err("file");
        assert!(err.message.contains("must be intra-schema"));
    }

    #[test]
    fn rejects_external_ref_data() {
        let s = json!({"$ref": "data:application/json,{}"});
        let err = SchemaValidator::new(&s).expect_err("data");
        assert!(err.message.contains("must be intra-schema"));
    }

    #[test]
    fn rejects_external_ref_javascript() {
        let s = json!({"$ref": "javascript:alert(1)"});
        let err = SchemaValidator::new(&s).expect_err("js");
        assert!(err.message.contains("must be intra-schema"));
    }

    #[test]
    fn rejects_protocol_relative() {
        let s = json!({"$ref": "//host/x"});
        let err = SchemaValidator::new(&s).expect_err("//");
        assert!(err.message.contains("must be intra-schema"));
    }

    #[test]
    fn rejects_relative_path() {
        let s = json!({"$ref": "other.json"});
        let err = SchemaValidator::new(&s).expect_err("relative");
        assert!(err.message.contains("must be intra-schema"));
    }

    #[test]
    fn rejects_absolute_path() {
        let s = json!({"$ref": "/abs/path"});
        let err = SchemaValidator::new(&s).expect_err("abs path");
        assert!(err.message.contains("must be intra-schema"));
    }

    #[test]
    fn rejects_anchor_lookalike_http() {
        // Round 3 Claude Info 4 regression: starts_with('#') would have passed
        // this. The stricter rule `s == "#" || s.starts_with("#/")` rejects it.
        let s = json!({"$ref": "#http://malicious"});
        let err = SchemaValidator::new(&s).expect_err("#http://");
        assert!(err.message.contains("must be intra-schema"));
    }

    #[test]
    fn accepts_intra_schema_root() {
        // `#` alone refers to the whole schema document.
        let s = json!({
            "type": "object",
            "properties": {"self": {"$ref": "#"}}
        });
        SchemaValidator::new(&s).expect("# accepted");
    }

    #[test]
    fn accepts_intra_schema_pointer() {
        let s = json!({
            "$defs": {"Foo": {"type": "string"}},
            "type": "object",
            "properties": {"x": {"$ref": "#/$defs/Foo"}}
        });
        SchemaValidator::new(&s).expect("#/$defs/Foo accepted");
    }

    #[test]
    fn rejects_external_dynamic_ref() {
        let s = json!({"$dynamicRef": "http://x"});
        let err = SchemaValidator::new(&s).expect_err("$dynamicRef external");
        assert!(err.message.contains("must be intra-schema"));
    }

    #[test]
    fn rejects_external_recursive_ref() {
        let s = json!({"$recursiveRef": "http://x"});
        let err = SchemaValidator::new(&s).expect_err("$recursiveRef external");
        assert!(err.message.contains("must be intra-schema"));
    }

    #[test]
    fn walk_descends_into_arrays() {
        let s = json!({
            "type": "object",
            "properties": {
                "items": {
                    "type": "array",
                    "items": [{"$ref": "http://buried"}]
                }
            }
        });
        let err = SchemaValidator::new(&s).expect_err("array-nested $ref");
        assert!(err.message.contains("must be intra-schema"));
    }
}

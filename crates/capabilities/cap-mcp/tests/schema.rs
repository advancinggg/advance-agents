//! Slice D AC-13 — JSON-Schema validation (SD-16..SD-22).

use std::collections::BTreeMap;
use std::sync::Arc;

use advance_shared_types::security_validator::{LeakDetector, ScanContext, ScanResult};
use cap_mcp::{
    McpClient, McpError, McpErrorKind, McpServerEntry, McpServersConfig, McpTransport,
    McpTransportSpec, SchemaValidator, ToolSchemas,
};

mod support;
use support::mock_transport::CountingMockTransport;

struct NoOpDetector;
impl LeakDetector for NoOpDetector {
    fn scan(&self, _t: &str, _c: ScanContext) -> ScanResult {
        ScanResult::Clean
    }
    fn scan_headers(&self, _h: &[(String, String)]) -> ScanResult {
        ScanResult::Clean
    }
}

// ─────────────────────────────────────────────────────────────────────────
// SD-16 — SchemaValidator::new accepts a valid draft-07 schema
// ─────────────────────────────────────────────────────────────────────────
#[test]
fn sd_16_valid_schema_compiles() {
    let s = serde_json::json!({
        "type": "object",
        "properties": {"x": {"type": "string"}},
        "required": ["x"],
    });
    SchemaValidator::new(&s).expect("valid schema");
}

// ─────────────────────────────────────────────────────────────────────────
// SD-17 — invalid schema rejected with InvalidResponse
// ─────────────────────────────────────────────────────────────────────────
#[test]
fn sd_17_invalid_schema_rejected() {
    let s = serde_json::json!({"type": 42});
    let err = SchemaValidator::new(&s).expect_err("invalid schema");
    assert_eq!(err.kind, McpErrorKind::InvalidResponse);
    assert!(err.message.contains("invalid schema"));
}

// ─────────────────────────────────────────────────────────────────────────
// SD-18 — validate accepts matching value
// ─────────────────────────────────────────────────────────────────────────
#[test]
fn sd_18_validate_matching_value() {
    let s = serde_json::json!({
        "type": "object",
        "properties": {"x": {"type": "string"}},
        "required": ["x"],
    });
    let v = SchemaValidator::new(&s).unwrap();
    v.validate(&serde_json::json!({"x": "hi"}))
        .expect("matches");
}

// ─────────────────────────────────────────────────────────────────────────
// SD-19 — validate rejects violating value (single error class)
// ─────────────────────────────────────────────────────────────────────────
#[test]
fn sd_19_validate_violating_value() {
    let s = serde_json::json!({
        "type": "object",
        "properties": {"x": {"type": "string"}},
        "required": ["x"],
    });
    let v = SchemaValidator::new(&s).unwrap();
    let err = v.validate(&serde_json::json!({})).expect_err("missing");
    assert_eq!(err.kind, McpErrorKind::InvalidResponse);
    assert!(err.message.contains("schema validation failed"));
}

// ─────────────────────────────────────────────────────────────────────────
// SD-20 — invoke_tool with bad input rejected BEFORE dispatch
//        (CountingMockTransport.call_count() must be 0)
// ─────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn sd_20_bad_input_rejected_before_dispatch() {
    let mut schemas = BTreeMap::new();
    schemas.insert(
        "echo".to_string(),
        ToolSchemas {
            input: Some(serde_json::json!({
                "type": "object",
                "properties": {"x": {"type": "string"}},
                "required": ["x"],
            })),
            output: None,
        },
    );
    let entry = McpServerEntry {
        server_id: "alpha".to_string(),
        description: "test".to_string(),
        // Transport-spec field is unused here — we inject the mock directly via
        // new_with_transports.
        transport: McpTransportSpec::Stdio {
            command: "true".to_string(),
            args: vec![],
            env: BTreeMap::new(),
        },
        tool_patterns: None,
        tool_schemas: schemas,
    };
    let cfg = Arc::new(
        McpServersConfig::builder()
            .add_server(entry)
            .unwrap()
            .build(),
    );

    let mock = Arc::new(CountingMockTransport::new("alpha"));
    let mock_dyn: Arc<dyn McpTransport> = mock.clone();
    let mut injected = std::collections::HashMap::new();
    injected.insert("alpha".to_string(), mock_dyn);
    let client = McpClient::new_with_transports(cfg, Arc::new(NoOpDetector), injected);

    // Invoke with input missing required "x" field.
    let bad_input = serde_json::to_vec(&serde_json::json!({})).unwrap();
    let err = client
        .invoke_tool("alpha", "echo", &bad_input)
        .await
        .expect_err("input validation must reject");
    assert_eq!(err.kind, McpErrorKind::InvalidResponse);
    assert!(err.message.contains("schema validation failed"));
    assert_eq!(
        mock.call_count(),
        0,
        "transport must NOT be called when input fails schema validation"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// SD-21 — invoke_tool with bad output rejected via output schema
// ─────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn sd_21_bad_output_rejected_via_output_schema() {
    let mut schemas = BTreeMap::new();
    schemas.insert(
        "echo".to_string(),
        ToolSchemas {
            input: None,
            output: Some(serde_json::json!({
                "type": "object",
                "properties": {"y": {"type": "string"}},
                "required": ["y"],
            })),
        },
    );
    let entry = McpServerEntry {
        server_id: "alpha".to_string(),
        description: "test".to_string(),
        transport: McpTransportSpec::Stdio {
            command: "true".to_string(),
            args: vec![],
            env: BTreeMap::new(),
        },
        tool_patterns: None,
        tool_schemas: schemas,
    };
    let cfg = Arc::new(
        McpServersConfig::builder()
            .add_server(entry)
            .unwrap()
            .build(),
    );

    let mock = Arc::new(CountingMockTransport::new("alpha"));
    mock.push_ok(serde_json::json!({"unexpected": "payload"})); // no "y" field
    let mock_dyn: Arc<dyn McpTransport> = mock.clone();
    let mut injected = std::collections::HashMap::new();
    injected.insert("alpha".to_string(), mock_dyn);
    let client = McpClient::new_with_transports(cfg, Arc::new(NoOpDetector), injected);

    let err = client
        .invoke_tool("alpha", "echo", b"{}")
        .await
        .expect_err("output validation must reject");
    assert_eq!(err.kind, McpErrorKind::InvalidResponse);
    assert!(err.message.contains("schema validation failed"));
}

// ─────────────────────────────────────────────────────────────────────────
// SD-22 — external $ref / $dynamicRef / $recursiveRef rejected
// ─────────────────────────────────────────────────────────────────────────
#[test]
fn sd_22_external_refs_rejected() {
    let bad_refs = [
        serde_json::json!({"$ref": "http://example.com/schema.json"}),
        serde_json::json!({"$ref": "https://example.com/schema.json"}),
        serde_json::json!({"$ref": "HTTPS://example.com/schema.json"}),
        serde_json::json!({"$ref": "file:///etc/passwd"}),
        serde_json::json!({"$ref": "data:application/json,{}"}),
        serde_json::json!({"$ref": "javascript:alert(1)"}),
        serde_json::json!({"$ref": "//host/x"}),
        serde_json::json!({"$ref": "other.json"}),
        serde_json::json!({"$ref": "/abs/path"}),
        serde_json::json!({"$ref": "#http://malicious"}), // Round 3 regression
        serde_json::json!({"$dynamicRef": "http://x"}),
        serde_json::json!({"$recursiveRef": "http://x"}),
    ];
    for s in bad_refs.iter() {
        let err = SchemaValidator::new(s).expect_err(&format!("must reject {s}"));
        assert_eq!(err.kind, McpErrorKind::InvalidResponse);
        assert!(
            err.message.contains("must be intra-schema"),
            "msg={}",
            err.message
        );
    }
    // Intra-schema forms accepted:
    let good_refs = [
        serde_json::json!({"$ref": "#"}),
        serde_json::json!({
            "$defs": {"Foo": {"type": "string"}},
            "$ref": "#/$defs/Foo",
        }),
    ];
    for s in good_refs.iter() {
        SchemaValidator::new(s).expect(&format!("intra-schema must compile: {s}"));
    }
}

// Audit round 1 W5 fix regression: $id with absolute URI must be rejected
// (jsonschema 0.18.3 uses $id as base URI for ref resolution, potentially
// triggering remote fetch even when all $ref values look intra-schema).
#[test]
fn sd_22_id_with_absolute_uri_rejected() {
    let bad_ids = [
        serde_json::json!({"$id": "http://attacker.example/", "type": "object"}),
        serde_json::json!({"$id": "https://attacker.example/", "type": "object"}),
        serde_json::json!({"$id": "file:///etc/passwd"}),
        serde_json::json!({"$id": "//host/x"}),
        serde_json::json!({"$id": "data:application/json,{}"}),
    ];
    for s in bad_ids.iter() {
        let err = SchemaValidator::new(s).expect_err(&format!("must reject $id: {s}"));
        assert_eq!(err.kind, McpErrorKind::InvalidResponse);
        assert!(
            err.message.contains("$id"),
            "expected $id rejection message, got: {}",
            err.message
        );
    }
    // Note: jsonschema 0.18.3's own URL parser is strict — it rejects
    // `"my-schema"` with "relative URL without a base" before our pre-scan
    // even runs. So we don't separately verify relative $id "good" cases;
    // the goal of this test is the SECURITY check on absolute/scheme-relative
    // forms (our walker fires first, so the rejection message contains "$id").
    // jsonschema's later rejection paths are out-of-scope for this regression.
}

// Adversarial round 1 W3 regression: pathologically-nested schema rejected
// at the recursion-depth bound (MAX_SCHEMA_DEPTH = 64).
#[test]
fn sd_22_deeply_nested_schema_rejected() {
    // Build a schema with ~100 nested {"properties":{"x":{...}}} levels.
    let mut inner = serde_json::json!({"type": "string"});
    for _ in 0..100 {
        inner = serde_json::json!({
            "type": "object",
            "properties": {"x": inner}
        });
    }
    let err = SchemaValidator::new(&inner).expect_err("deep schema must reject");
    assert_eq!(err.kind, McpErrorKind::InvalidResponse);
    assert!(
        err.message.contains("depth"),
        "expected depth-bound rejection, got: {}",
        err.message
    );
}

#[test]
fn sd_22_shallow_schema_accepted() {
    // Each `{"type": "object", "properties": {"x": inner}}` nesting adds
    // ~2 walker recursion levels (outer object + properties value). 20
    // user-nesting levels = ~40 walker depths, well within MAX_SCHEMA_DEPTH=64.
    let mut inner = serde_json::json!({"type": "string"});
    for _ in 0..20 {
        inner = serde_json::json!({
            "type": "object",
            "properties": {"x": inner}
        });
    }
    SchemaValidator::new(&inner).expect("20-level schema must compile");
}

fn _unused_mcp_error(_e: &McpError) {}

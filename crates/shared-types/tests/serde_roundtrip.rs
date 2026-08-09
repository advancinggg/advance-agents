//! serde round-trip + wire-format tests for shared-types data types
//! (Slice A' BudgetDecision/ToolEntry/McpToolEntry, Slice J GrantDecision,
//! Slice K ToolCallSignature/OutputHash/RepetitionDecision).
//!
//! Two layers of coverage:
//! 1. **Round-trip symmetry** (`rt<T>`): structural regression catch — any change that
//!    breaks `Serialize` / `Deserialize` reciprocity or the derive attributes will fail.
//! 2. **Wire-format assertions** (`wire_*`): lock the exact JSON string for a
//!    representative instance of each type. These catch field renames, tag style
//!    changes, or any serde attribute that would otherwise silently change the emitted
//!    JSON while still satisfying round-trip symmetry.

use advance_shared_types::capability::*;

fn rt<T>(v: T)
where
    T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
{
    let encoded = serde_json::to_string(&v).expect("serialize");
    let decoded: T = serde_json::from_str(&encoded).expect("deserialize");
    assert_eq!(v, decoded);
}

// ---------- Round-trip symmetry tests ----------

#[test]
fn rt_budget_decision_allow() {
    rt(BudgetDecision::Allow);
}

#[test]
fn rt_budget_decision_deny() {
    rt(BudgetDecision::Deny("over budget".into()));
}

#[test]
fn rt_tool_entry_empty_schema() {
    rt(ToolEntry {
        name: "weather".into(),
        description: "Get weather for a location".into(),
        params_schema: serde_json::json!({}),
    });
}

#[test]
fn rt_tool_entry_with_schema() {
    rt(ToolEntry {
        name: "search".into(),
        description: "Full text search".into(),
        params_schema: serde_json::json!({
            "type": "object",
            "properties": {
                "q": { "type": "string" }
            }
        }),
    });
}

#[test]
fn rt_mcp_tool_entry() {
    rt(McpToolEntry {
        name: "calc".into(),
        description: "Calculator".into(),
        params_schema: serde_json::json!({}),
        server_id: "srv1".into(),
    });
}

// ---------- Wire-format lock tests ----------
//
// These assert the exact JSON string for each type. If serde attributes, field names,
// field order, or enum tag style change, these tests will fail even when round-trip
// symmetry still passes.

#[test]
fn wire_budget_decision_allow() {
    let encoded = serde_json::to_string(&BudgetDecision::Allow).expect("serialize");
    assert_eq!(encoded, r#""Allow""#);
}

#[test]
fn wire_budget_decision_deny() {
    let encoded =
        serde_json::to_string(&BudgetDecision::Deny("limit reached".into())).expect("serialize");
    assert_eq!(encoded, r#"{"Deny":"limit reached"}"#);
}

#[test]
fn wire_tool_entry() {
    let v = ToolEntry {
        name: "weather".into(),
        description: "Get weather".into(),
        params_schema: serde_json::json!({}),
    };
    let encoded = serde_json::to_string(&v).expect("serialize");
    assert_eq!(
        encoded,
        r#"{"name":"weather","description":"Get weather","params_schema":{}}"#
    );
}

#[test]
fn wire_mcp_tool_entry() {
    let v = McpToolEntry {
        name: "calc".into(),
        description: "Calculator".into(),
        params_schema: serde_json::json!({}),
        server_id: "srv1".into(),
    };
    let encoded = serde_json::to_string(&v).expect("serialize");
    assert_eq!(
        encoded,
        r#"{"name":"calc","description":"Calculator","params_schema":{},"server_id":"srv1"}"#
    );
}

// ---------- Negative tests: lock deny_unknown_fields hardening ----------
//
// These tests fail-by-passing if a future refactor silently drops
// `#[serde(deny_unknown_fields)]` from the struct definitions. Without them the
// hardening attribute can regress and CI would stay green, reopening the
// field-smuggling attack surface flagged by the adversarial evaluator.

#[test]
fn deny_unknown_field_tool_entry() {
    let json = r#"{"name":"weather","description":"Get weather","params_schema":{},"extra_field":"smuggled"}"#;
    let result: Result<ToolEntry, serde_json::Error> = serde_json::from_str(json);
    // Rejection is the load-bearing property. Use serde_json's stable error Category
    // API instead of substring-matching the (unstable) error message text.
    let err =
        result.expect_err("ToolEntry must reject unknown fields (deny_unknown_fields regression)");
    assert_eq!(
        err.classify(),
        serde_json::error::Category::Data,
        "expected Data category error (semantic rejection), got: {err}"
    );
}

#[test]
fn deny_unknown_field_mcp_tool_entry() {
    let json = r#"{"name":"calc","description":"Calculator","params_schema":{},"server_id":"srv1","malicious":true}"#;
    let result: Result<McpToolEntry, serde_json::Error> = serde_json::from_str(json);
    let err = result
        .expect_err("McpToolEntry must reject unknown fields (deny_unknown_fields regression)");
    assert_eq!(
        err.classify(),
        serde_json::error::Category::Data,
        "expected Data category error (semantic rejection), got: {err}"
    );
}

// Note: no `deny_unknown_field_budget_decision` regression test yet. A prior revision
// of this file contained a negative test asserting that multi-key enum payloads are
// rejected, but that rejection comes from serde's externally-tagged enum parser's
// single-key constraint, not from `#[serde(deny_unknown_fields)]`. The attribute IS
// applied to BudgetDecision in capability.rs as forward-looking hardening (it becomes
// load-bearing when a future variant is added in struct form), but it cannot be
// regression-tested until such a struct variant exists. Adding a false-positive lock
// here would only create misleading coverage signal, so the attribute presence is
// documented in the struct rustdoc instead.

// ============================================================================
// Slice J — GrantDecision round-trip + wire-format locks
// ============================================================================

#[test]
fn rt_grant_decision_allow() {
    rt(GrantDecision::Allow);
}

#[test]
fn rt_grant_decision_deny() {
    rt(GrantDecision::Deny("capability-not-granted".to_string()));
}

#[test]
fn wire_grant_decision_allow() {
    let json = serde_json::to_string(&GrantDecision::Allow).unwrap();
    assert_eq!(json, r#""Allow""#);
}

#[test]
fn wire_grant_decision_deny() {
    let json =
        serde_json::to_string(&GrantDecision::Deny("capability-not-granted".to_string())).unwrap();
    assert_eq!(json, r#"{"Deny":"capability-not-granted"}"#);
}

// ---------- Slice K (CONTRACT-072 RepetitionGuardCheck supporting types) ----------

use advance_shared_types::repetition::{OutputHash, RepetitionDecision, ToolCallSignature};

fn sample_sig() -> ToolCallSignature {
    ToolCallSignature {
        tool_id: "fs".to_string(),
        method: "read".to_string(),
        params_hash: 0x0123_4567_89ab_cdefu64,
    }
}

#[test]
fn rt_tool_call_signature() {
    rt(sample_sig());
}

#[test]
fn wire_tool_call_signature() {
    let json = serde_json::to_string(&sample_sig()).unwrap();
    assert_eq!(
        json,
        r#"{"tool_id":"fs","method":"read","params_hash":81985529216486895}"#
    );
}

#[test]
fn deny_unknown_field_tool_call_signature() {
    // Mirrors Slice A' `ToolEntry`/`McpToolEntry` hardening: attacker-influenced
    // `tool_id`/`method` originate from WASM component manifests / MCP server
    // responses. deny_unknown_fields provides a structural defense against
    // smuggled fields.
    let bad = r#"{"tool_id":"fs","method":"read","params_hash":0,"smuggled":true}"#;
    let result = serde_json::from_str::<ToolCallSignature>(bad);
    assert!(
        result.is_err(),
        "deny_unknown_fields should reject smuggled field"
    );
}

#[test]
fn display_tool_call_signature() {
    // Locks the MODULE-008:229 / §1.3.5 canonical format
    // "{tool_id}::{method}#{params_hash:016x}" required by sig.to_string().
    let rendered = sample_sig().to_string();
    assert_eq!(rendered, "fs::read#0123456789abcdef");
}

#[test]
fn rt_output_hash() {
    let mut bytes = [0u8; 32];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = i as u8;
    }
    rt(OutputHash(bytes));
}

#[test]
fn wire_output_hash() {
    // #[serde(transparent)] over [u8; 32] → JSON array of 32 u8 numbers.
    // Regression-locks against accidental `serde_bytes`/base64 flip.
    let mut bytes = [0u8; 32];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = i as u8;
    }
    let json = serde_json::to_string(&OutputHash(bytes)).unwrap();
    let expected = format!(
        "[{}]",
        (0u8..32)
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join(",")
    );
    assert_eq!(json, expected);
}

#[test]
fn rt_repetition_decision_pass() {
    rt(RepetitionDecision::Pass);
}

#[test]
fn rt_repetition_decision_warn() {
    rt(RepetitionDecision::Warn("output-repeat".to_string()));
}

#[test]
fn rt_repetition_decision_terminate() {
    rt(RepetitionDecision::Terminate("tool-repeat".to_string()));
}

#[test]
fn wire_repetition_decision_pass() {
    let json = serde_json::to_string(&RepetitionDecision::Pass).unwrap();
    assert_eq!(json, r#""Pass""#);
}

#[test]
fn wire_repetition_decision_warn() {
    let json =
        serde_json::to_string(&RepetitionDecision::Warn("output-repeat".to_string())).unwrap();
    assert_eq!(json, r#"{"Warn":"output-repeat"}"#);
}

#[test]
fn wire_repetition_decision_terminate() {
    let json =
        serde_json::to_string(&RepetitionDecision::Terminate("tool-repeat".to_string())).unwrap();
    assert_eq!(json, r#"{"Terminate":"tool-repeat"}"#);
}

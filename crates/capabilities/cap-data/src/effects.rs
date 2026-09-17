//! The effect list a pure reducer returns from `data.apply` (plan §2.6).
//!
//! ```json
//! { "effects": [
//!   { "set":     { "target": "launch.md#e-…", "field": "exdates", "value": ["…"] } },
//!   { "unset":   { "target": "launch.md#e-…", "field": "assignee" } },
//!   { "create":  { "parent": "launch.md", "record": { "type": "meeting", "title": "…" } } },
//!   { "promote": { "target": "launch.md#e-…", "to": "file" } },
//!   { "demote":  { "target": "launch/sync.md" } }
//! ] }
//! ```
//!
//! or `{ "error": "<reason>" }` for a precondition failure (nothing is written). Bounds:
//! ≤ [`MAX_EFFECTS_PER_APPLY`] effects, reducer input ≤ [`MAX_REDUCER_INPUT_BYTES`], output ≤
//! [`MAX_REDUCER_OUTPUT_BYTES`]; an effect may only target the operation's own record, its
//! parent file, or a record this same apply created.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Cap on effects per `apply`.
pub const MAX_EFFECTS_PER_APPLY: usize = 64;
/// Cap on the JSON handed to a reducer.
pub const MAX_REDUCER_INPUT_BYTES: usize = 1024 * 1024;
/// Cap on the JSON a reducer returns.
pub const MAX_REDUCER_OUTPUT_BYTES: usize = 1024 * 1024;

/// One effect. Targets are `"path"` (file record) or `"path#e-…"` (inline item).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase", deny_unknown_fields)]
pub enum Effect {
    Set {
        target: String,
        field: String,
        value: Value,
    },
    Unset {
        target: String,
        field: String,
    },
    Create {
        parent: String,
        record: Value,
    },
    Promote {
        target: String,
        to: String,
    },
    Demote {
        target: String,
    },
}

/// The reducer's reply.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReducerOutput {
    #[serde(default)]
    pub effects: Vec<Effect>,
    #[serde(default)]
    pub error: Option<String>,
}

impl ReducerOutput {
    /// Parse + bound-check reducer bytes.
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > MAX_REDUCER_OUTPUT_BYTES {
            return Err(format!(
                "reducer output is {} bytes (max {MAX_REDUCER_OUTPUT_BYTES})",
                bytes.len()
            ));
        }
        let out: ReducerOutput = serde_json::from_slice(bytes)
            .map_err(|e| format!("reducer output is not valid JSON: {e}"))?;
        if out.effects.len() > MAX_EFFECTS_PER_APPLY {
            return Err(format!(
                "reducer returned {} effects (max {MAX_EFFECTS_PER_APPLY})",
                out.effects.len()
            ));
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_effects_and_errors() {
        let out = ReducerOutput::parse(
            br#"{"effects":[{"set":{"target":"a.md","field":"x","value":1}}]}"#,
        )
        .unwrap();
        assert_eq!(out.effects.len(), 1);
        let out = ReducerOutput::parse(br#"{"error":"nope"}"#).unwrap();
        assert_eq!(out.error.as_deref(), Some("nope"));
        assert!(ReducerOutput::parse(br#"{"effects":[{"explode":{}}]}"#).is_err());
        let many = format!(
            "{{\"effects\":[{}]}}",
            vec![r#"{"unset":{"target":"a.md","field":"x"}}"#; MAX_EFFECTS_PER_APPLY + 1].join(",")
        );
        assert!(ReducerOutput::parse(many.as_bytes()).is_err());
    }
}

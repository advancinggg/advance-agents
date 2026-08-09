//! Structured-output parse + validate per MODULE-009 §1.4.3.
//!
//! `try_parse_and_validate(text, schema_json)` extracts JSON from the LLM
//! response (preferring fenced ```json ... ``` blocks, falling back to a
//! brace-balanced raw extraction), parses the per-call JSON Schema, and
//! validates the extracted JSON against the schema. Returns canonical
//! JSON bytes on success.
//!
//! Bounded-input guards close the trivial DoS path of an attacker-controlled
//! schema or response causing the validator to allocate unbounded memory:
//! - text  > 256 KiB → StructuredOutputFailed("input too large")
//! - schema > 64 KiB → StructuredOutputFailed("schema too large")

use crate::error::LlmError;

const MAX_STRUCTURED_INPUT_BYTES: usize = 256 * 1024;
const MAX_STRUCTURED_SCHEMA_BYTES: usize = 64 * 1024;

/// Try to extract a JSON value from `text`, parse `schema_json`, and validate.
/// On success returns the canonical bytes of the extracted JSON.
pub fn try_parse_and_validate(text: &str, schema_json: &str) -> Result<Vec<u8>, LlmError> {
    if text.len() > MAX_STRUCTURED_INPUT_BYTES {
        return Err(LlmError::StructuredOutputFailed("input too large".into()));
    }
    if schema_json.len() > MAX_STRUCTURED_SCHEMA_BYTES {
        return Err(LlmError::StructuredOutputFailed("schema too large".into()));
    }

    let extracted = extract_json_fenced(text)
        .or_else(|| extract_json_raw(text))
        .ok_or_else(|| LlmError::StructuredOutputFailed("no JSON found".into()))?;

    let schema_value: serde_json::Value = serde_json::from_str(schema_json)
        .map_err(|e| LlmError::StructuredOutputFailed(format!("schema parse error: {e}")))?;

    let compiled = jsonschema::JSONSchema::compile(&schema_value)
        .map_err(|e| LlmError::StructuredOutputFailed(format!("schema compile error: {e}")))?;

    let extracted_value: serde_json::Value = serde_json::from_str(extracted).map_err(|e| {
        LlmError::StructuredOutputFailed(format!("extracted JSON parse error: {e}"))
    })?;

    if let Err(errors) = compiled.validate(&extracted_value) {
        let detail = errors.map(|e| e.to_string()).collect::<Vec<_>>().join("; ");
        return Err(LlmError::StructuredOutputFailed(format!(
            "schema validation failed: {detail}"
        )));
    }

    // Round-AUDIT-3 W3 fix: return canonical JSON bytes via re-serialization
    // (key order = serde_json's BTreeMap if `preserve_order` feature is off,
    // otherwise insertion order; in both cases whitespace and formatting are
    // normalized). The earlier `extracted.as_bytes().to_vec()` returned the
    // upstream raw slice verbatim, so semantically-identical responses with
    // different whitespace would produce different byte outputs — breaking
    // the §1.4.3 "canonical JSON bytes" contract.
    serde_json::to_vec(&extracted_value)
        .map_err(|e| LlmError::StructuredOutputFailed(format!("canonical re-serialize error: {e}")))
}

/// Extract JSON from a fenced code block. Prefers ```json ... ```
/// (case-insensitive on the language tag), falls back to plain ``` ... ```.
/// Returns the inner content, trimmed of leading/trailing whitespace.
fn extract_json_fenced(text: &str) -> Option<&str> {
    // Prefer a fenced block tagged "json".
    let mut search = text;
    while let Some(open_idx) = search.find("```") {
        let after_open = &search[open_idx + 3..];
        let (lang_end, after_lang) = match after_open.find('\n') {
            Some(i) => (i, &after_open[i + 1..]),
            None => return None,
        };
        let lang_tag = after_open[..lang_end].trim().to_ascii_lowercase();
        if lang_tag.is_empty() || lang_tag == "json" {
            // Find matching close fence.
            if let Some(close_idx) = after_lang.find("```") {
                return Some(after_lang[..close_idx].trim());
            }
        }
        // Not the right fence; keep searching after this one.
        search = after_lang;
    }
    None
}

/// Extract a balanced top-level JSON object or array from `text`. Tracks
/// brace depth, treating string contents (and `\\` escapes) so braces inside
/// strings do not unbalance the count. Returns the slice spanning the first
/// balanced object or array, or `None` if no balanced span exists.
fn extract_json_raw(text: &str) -> Option<&str> {
    let bytes = text.as_bytes();
    // Find the first '{' or '[' that begins a balanced top-level value.
    let start = bytes.iter().position(|&b| b == b'{' || b == b'[')?;
    let opener = bytes[start];
    let closer = if opener == b'{' { b'}' } else { b']' };

    let mut depth: i32 = 0;
    let mut in_string = false;
    let mut escape = false;
    let mut i = start;
    while i < bytes.len() {
        let b = bytes[i];
        if in_string {
            if escape {
                escape = false;
            } else if b == b'\\' {
                escape = true;
            } else if b == b'"' {
                in_string = false;
            }
        } else if b == b'"' {
            in_string = true;
        } else if b == opener {
            depth += 1;
        } else if b == closer {
            depth -= 1;
            if depth == 0 {
                // text is &str; the i+1 boundary lies on an ASCII byte (closer
                // is `}` or `]`, both single-byte UTF-8), so direct slicing is
                // safe.
                return Some(&text[start..=i]);
            }
        }
        i += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn schema_x_int() -> &'static str {
        r#"{"type":"object","properties":{"x":{"type":"integer"}},"required":["x"]}"#
    }

    /// MODULE-009-T58 — fenced extract + validate happy path.
    #[test]
    fn t_try_parse_fenced_happy() {
        let text = "```json\n{\"x\":1}\n```";
        let bytes = try_parse_and_validate(text, schema_x_int()).expect("ok");
        assert_eq!(std::str::from_utf8(&bytes).unwrap(), r#"{"x":1}"#);
    }

    /// Round-AUDIT-4 W2 — canonical-bytes regression: whitespace-decorated
    /// input must be normalized in the returned bytes (no leading spaces, no
    /// pretty-printed indentation, no trailing whitespace). Two semantically-
    /// identical inputs with different whitespace MUST produce IDENTICAL bytes.
    #[test]
    fn t_try_parse_canonical_bytes_normalizes_whitespace() {
        let pretty = "```json\n{\n  \"x\":   42  ,\n   \"y\":\"hello\"\n}\n```";
        let compact = r#"```json
{"x":42,"y":"hello"}
```"#;
        let schema = r#"{"type":"object","properties":{"x":{"type":"integer"},"y":{"type":"string"}},"required":["x","y"]}"#;
        let bytes_pretty = try_parse_and_validate(pretty, schema).expect("pretty ok");
        let bytes_compact = try_parse_and_validate(compact, schema).expect("compact ok");
        assert_eq!(
            bytes_pretty, bytes_compact,
            "canonical re-serialization must produce identical bytes for whitespace-divergent input"
        );
        // Canonical form has no surrounding whitespace.
        let canonical = std::str::from_utf8(&bytes_pretty).unwrap();
        assert!(
            !canonical.contains("  "),
            "canonical bytes contain double-space: {canonical:?}"
        );
        assert!(
            !canonical.contains('\n'),
            "canonical bytes contain newline: {canonical:?}"
        );
        assert!(
            canonical.starts_with('{'),
            "canonical bytes don't start with '{{': {canonical:?}"
        );
        assert!(
            canonical.ends_with('}'),
            "canonical bytes don't end with '}}': {canonical:?}"
        );
    }

    /// MODULE-009-T59 — raw extract fallback.
    #[test]
    fn t_try_parse_raw_fallback() {
        let text = r#"Result: {"x":1}"#;
        let bytes = try_parse_and_validate(text, schema_x_int()).expect("ok");
        assert_eq!(std::str::from_utf8(&bytes).unwrap(), r#"{"x":1}"#);
    }

    /// MODULE-009-T60 — no-JSON path.
    #[test]
    fn t_try_parse_no_json() {
        let err = try_parse_and_validate("garbage no json", schema_x_int()).unwrap_err();
        match err {
            LlmError::StructuredOutputFailed(msg) => assert!(msg.contains("no JSON found")),
            _ => panic!("expected StructuredOutputFailed"),
        }
    }

    /// MODULE-009-T61 — schema-compile failure path.
    #[test]
    fn t_try_parse_schema_compile_fails() {
        let text = r#"{"x":1}"#;
        let bad_schema = "{ malformed";
        let err = try_parse_and_validate(text, bad_schema).unwrap_err();
        match err {
            LlmError::StructuredOutputFailed(msg) => {
                // Either parse-error or compile-error wording is acceptable;
                // the body just has to surface "schema" so the caller can act.
                assert!(msg.contains("schema"), "msg={msg}");
            }
            _ => panic!("expected StructuredOutputFailed"),
        }
    }

    /// MODULE-009-T62 — validation failure path with details.
    #[test]
    fn t_try_parse_validation_failure() {
        let text = r#"{"x":"not an int"}"#;
        let err = try_parse_and_validate(text, schema_x_int()).unwrap_err();
        match err {
            LlmError::StructuredOutputFailed(msg) => {
                assert!(msg.contains("schema validation failed"), "msg={msg}");
            }
            _ => panic!("expected StructuredOutputFailed"),
        }
    }

    /// MODULE-009-T63 — bounded-input guard.
    #[test]
    fn t_try_parse_bounded_input() {
        let text = "a".repeat(MAX_STRUCTURED_INPUT_BYTES + 1);
        let err = try_parse_and_validate(&text, schema_x_int()).unwrap_err();
        match err {
            LlmError::StructuredOutputFailed(msg) => assert!(msg.contains("input too large")),
            _ => panic!("expected StructuredOutputFailed"),
        }
    }

    #[test]
    fn t_try_parse_bounded_schema() {
        let text = r#"{"x":1}"#;
        let big_schema = format!(
            "{{ \"x\": \"{}\" }}",
            "p".repeat(MAX_STRUCTURED_SCHEMA_BYTES)
        );
        let err = try_parse_and_validate(text, &big_schema).unwrap_err();
        match err {
            LlmError::StructuredOutputFailed(msg) => assert!(msg.contains("schema too large")),
            _ => panic!("expected StructuredOutputFailed"),
        }
    }

    #[test]
    fn t_extract_raw_string_aware() {
        // Brace inside a string must NOT unbalance.
        let text = r#"prefix {"x":"a}b","y":1} suffix"#;
        let extracted = extract_json_raw(text).unwrap();
        assert_eq!(extracted, r#"{"x":"a}b","y":1}"#);
    }
}

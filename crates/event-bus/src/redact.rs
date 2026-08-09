//! Final structured-observation guard for declared component parameters.
//!
//! The complete CONTRACT-219 authority/proof gate lives in `shared-types` + M012.  EventBus owns
//! the last sink-side invariant: it never treats ordinary Event structure as a parameter map and
//! it never falls back to the original payload after a malformed or over-budget canonical
//! parameter container.  Only the two wire containers emitted by typed runtime adapters are
//! eligible here:
//!
//! - `named_params: { <name>: <value>, ... }`
//! - `cap_params: [{ "key": <name>, "value": <value> }, ...]`

use std::collections::HashSet;
use std::sync::Arc;

use serde_json::Value;

pub const REDACTED: &str = "[REDACTED]";
pub const MAX_REDACT_DEPTH: usize = 32;
pub const MAX_REDACT_NODES: usize = 4096;

/// Source of the already-validated declaration selected for an emitting component.
pub trait SensitiveParamsSource: Send + Sync {
    fn names_for(&self, agent_id: &str) -> Option<Arc<HashSet<String>>>;
}

/// Complete outcome of the sink-side structured projection.
#[derive(Clone, Debug, PartialEq)]
pub enum SensitiveParamProjection {
    /// The complete tree passed validation and contained no selected value.
    Unchanged,
    /// The complete tree passed validation and every selected value was replaced.
    Redacted(Value),
    /// Shape/depth/node validation failed.  Observation sinks must suppress the whole event.
    Blocked,
}

/// Validate the complete payload first, then clone and redact canonical parameter containers.
/// No partial tree is returned on failure.
pub fn project_sensitive_params(
    payload: &Value,
    names: &HashSet<String>,
) -> SensitiveParamProjection {
    let mut nodes = 0usize;
    if validate_value(payload, 1, &mut nodes, ContainerContext::Ordinary).is_err() {
        return SensitiveParamProjection::Blocked;
    }
    let mut changed = false;
    let projected = redact_value(payload, names, ContainerContext::Ordinary, &mut changed);
    if changed {
        SensitiveParamProjection::Redacted(projected)
    } else {
        SensitiveParamProjection::Unchanged
    }
}

/// Backward-compatible helper retained for callers that only need the changed clone.  A blocked
/// payload and an unchanged payload both return `None`; EventBus itself uses
/// [`project_sensitive_params`] so it can distinguish and suppress blocked observations.
pub fn redact_sensitive_params(payload: &Value, names: &HashSet<String>) -> Option<Value> {
    match project_sensitive_params(payload, names) {
        SensitiveParamProjection::Redacted(value) => Some(value),
        SensitiveParamProjection::Unchanged | SensitiveParamProjection::Blocked => None,
    }
}

#[derive(Clone, Copy)]
enum ContainerContext {
    Ordinary,
    NamedParams,
    CapParams,
}

fn validate_value(
    value: &Value,
    depth: usize,
    nodes: &mut usize,
    context: ContainerContext,
) -> Result<(), ()> {
    if depth > MAX_REDACT_DEPTH {
        return Err(());
    }
    *nodes = nodes.checked_add(1).ok_or(())?;
    if *nodes > MAX_REDACT_NODES {
        return Err(());
    }
    match (context, value) {
        (ContainerContext::NamedParams, Value::Object(values)) => {
            for (name, child) in values {
                if name.is_empty() {
                    return Err(());
                }
                validate_value(child, depth + 1, nodes, ContainerContext::Ordinary)?;
            }
        }
        (ContainerContext::CapParams, Value::Array(values)) => {
            let mut keys = HashSet::with_capacity(values.len());
            for entry in values {
                *nodes = nodes.checked_add(1).ok_or(())?;
                if *nodes > MAX_REDACT_NODES || depth + 1 > MAX_REDACT_DEPTH {
                    return Err(());
                }
                let object = entry.as_object().ok_or(())?;
                if object.len() != 2 {
                    return Err(());
                }
                let key = object.get("key").and_then(Value::as_str).ok_or(())?;
                let parameter = object.get("value").ok_or(())?;
                if key.is_empty() || !keys.insert(key) {
                    return Err(());
                }
                validate_value(parameter, depth + 2, nodes, ContainerContext::Ordinary)?;
            }
        }
        (ContainerContext::Ordinary, Value::Object(values)) => {
            for (name, child) in values {
                let child_context = match name.as_str() {
                    "named_params" => ContainerContext::NamedParams,
                    "cap_params" => ContainerContext::CapParams,
                    _ => ContainerContext::Ordinary,
                };
                validate_value(child, depth + 1, nodes, child_context)?;
            }
        }
        (ContainerContext::Ordinary, Value::Array(values)) => {
            for child in values {
                validate_value(child, depth + 1, nodes, ContainerContext::Ordinary)?;
            }
        }
        (ContainerContext::NamedParams, _)
        | (ContainerContext::CapParams, _)
        | (ContainerContext::Ordinary, _) => {
            if !matches!(context, ContainerContext::Ordinary) {
                return Err(());
            }
        }
    }
    Ok(())
}

fn redact_value(
    value: &Value,
    names: &HashSet<String>,
    context: ContainerContext,
    changed: &mut bool,
) -> Value {
    match (context, value) {
        (ContainerContext::NamedParams, Value::Object(values)) => Value::Object(
            values
                .iter()
                .map(|(name, child)| {
                    let value = if names.contains(name) {
                        *changed = true;
                        Value::String(REDACTED.to_owned())
                    } else {
                        redact_value(child, names, ContainerContext::Ordinary, changed)
                    };
                    (name.clone(), value)
                })
                .collect(),
        ),
        (ContainerContext::CapParams, Value::Array(values)) => Value::Array(
            values
                .iter()
                .map(|entry| {
                    let object = entry.as_object().expect("validated cap-param entry");
                    let key = object
                        .get("key")
                        .and_then(Value::as_str)
                        .expect("validated cap-param key");
                    let parameter = object.get("value").expect("validated cap-param value");
                    let value = if names.contains(key) {
                        *changed = true;
                        Value::String(REDACTED.to_owned())
                    } else {
                        redact_value(parameter, names, ContainerContext::Ordinary, changed)
                    };
                    serde_json::json!({ "key": key, "value": value })
                })
                .collect(),
        ),
        (ContainerContext::Ordinary, Value::Object(values)) => Value::Object(
            values
                .iter()
                .map(|(name, child)| {
                    let child_context = match name.as_str() {
                        "named_params" => ContainerContext::NamedParams,
                        "cap_params" => ContainerContext::CapParams,
                        _ => ContainerContext::Ordinary,
                    };
                    (
                        name.clone(),
                        redact_value(child, names, child_context, changed),
                    )
                })
                .collect(),
        ),
        (ContainerContext::Ordinary, Value::Array(values)) => Value::Array(
            values
                .iter()
                .map(|child| redact_value(child, names, ContainerContext::Ordinary, changed))
                .collect(),
        ),
        (_, scalar) => scalar.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn names(values: &[&str]) -> HashSet<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn redacts_only_canonical_containers_and_keeps_structural_names() {
        let payload = json!({
            "id": "structural-id",
            "api_key": "ordinary-lookalike",
            "nested": {"named_params": {"api_key": "secret", "safe": "ok"}},
            "cap_params": [{"key": "api_key", "value": "secret"}]
        });
        let SensitiveParamProjection::Redacted(out) =
            project_sensitive_params(&payload, &names(&["api_key", "id"]))
        else {
            panic!("expected redaction")
        };
        assert_eq!(out["id"], "structural-id");
        assert_eq!(out["api_key"], "ordinary-lookalike");
        assert_eq!(out["nested"]["named_params"]["api_key"], REDACTED);
        assert_eq!(out["nested"]["named_params"]["safe"], "ok");
        assert_eq!(out["cap_params"][0]["value"], REDACTED);
    }

    #[test]
    fn malformed_cap_params_and_excess_depth_block() {
        assert_eq!(
            project_sensitive_params(
                &json!({"cap_params": [{"key": "api_key", "value": "x", "extra": 1}]}),
                &names(&["api_key"]),
            ),
            SensitiveParamProjection::Blocked
        );
        let mut value = json!({"named_params": {"api_key": "x"}});
        for _ in 0..MAX_REDACT_DEPTH {
            value = json!({"nested": value});
        }
        assert_eq!(
            project_sensitive_params(&value, &names(&["api_key"])),
            SensitiveParamProjection::Blocked
        );
    }

    #[test]
    fn known_empty_still_validates_complete_shape() {
        assert_eq!(
            project_sensitive_params(&json!({"named_params": {"safe": 1}}), &names(&[])),
            SensitiveParamProjection::Unchanged
        );
        assert_eq!(
            project_sensitive_params(&json!({"named_params": []}), &names(&[])),
            SensitiveParamProjection::Blocked
        );
    }
}

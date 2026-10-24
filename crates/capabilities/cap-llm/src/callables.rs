//! ADR 2026-10-24 D5 — expand `llm-params.callables` into the native `tools` array.

use crate::error::LlmError;
use crate::gateway::ToolDefinition;

/// Default native `tools` array cap (ADR 2026-10-24 D5). Configurable on the gateway.
pub const DEFAULT_MAX_NATIVE_TOOLS: usize = 128;

/// WIT `callable-selection` (`all` / `only(list<string>)`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CallableSelection {
    All,
    Only(Vec<String>),
}

/// Host-owned catalog projection the gateway expands into `ChatParams.tools`.
pub trait CallableCatalogPort: Send + Sync {
    fn list_for_agent(&self, agent_id: &str) -> Vec<ToolDefinition>;
}

/// Outcome of [`apply_callables`]. `dropped_unknown` is the `only(...)` names
/// that were not in the catalog (logged + test-visible).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ApplyCallablesResult {
    pub tools: Option<Vec<ToolDefinition>>,
    pub dropped_unknown: Vec<String>,
}

/// Expand the guest's catalog selection and merge with guest-defined `tools`.
///
/// - `selection == None` → catalog stays out (one-shot guests unchanged).
/// - `All` → every catalog entry for the agent.
/// - `Only` → catalog entries whose names match; unknown names are dropped.
/// - A guest `tools` name that collides with a selected catalog name fails
///   with `provider-error("callable-collision: <name>")`.
/// - The merged array is catalog ++ guest, then truncated to `max_tools`.
pub fn apply_callables(
    selection: Option<&CallableSelection>,
    guest_tools: Option<Vec<ToolDefinition>>,
    catalog: &[ToolDefinition],
    max_tools: usize,
) -> Result<ApplyCallablesResult, LlmError> {
    let guest = guest_tools.unwrap_or_default();
    let Some(sel) = selection else {
        let tools = if guest.is_empty() {
            None
        } else {
            Some(truncate(guest, max_tools))
        };
        return Ok(ApplyCallablesResult {
            tools,
            dropped_unknown: Vec::new(),
        });
    };

    let mut dropped_unknown = Vec::new();
    let selected: Vec<ToolDefinition> = match sel {
        CallableSelection::All => catalog.to_vec(),
        CallableSelection::Only(names) => {
            let mut out = Vec::new();
            for name in names {
                let needle = normalize_only_name(name);
                if let Some(entry) = catalog.iter().find(|c| c.name == *name || c.name == needle) {
                    if !out.iter().any(|e: &ToolDefinition| e.name == entry.name) {
                        out.push(entry.clone());
                    }
                } else {
                    dropped_unknown.push(name.clone());
                }
            }
            out
        }
    };

    for g in &guest {
        if selected.iter().any(|c| c.name == g.name) {
            return Err(LlmError::ProviderError(format!(
                "callable-collision: {}",
                g.name
            )));
        }
    }

    let mut merged = selected;
    merged.extend(guest);
    let tools = if merged.is_empty() {
        None
    } else {
        Some(truncate(merged, max_tools))
    };
    Ok(ApplyCallablesResult {
        tools,
        dropped_unknown,
    })
}

fn normalize_only_name(name: &str) -> String {
    cap_tools_normalize(name)
}

/// Last `.` → `__` when the name has no `__` yet (agenda `data.describe`).
fn cap_tools_normalize(name: &str) -> String {
    if name.contains("__") {
        return name.to_string();
    }
    if let Some(idx) = name.rfind('.') {
        let mut out = String::with_capacity(name.len() + 1);
        out.push_str(&name[..idx]);
        out.push_str("__");
        out.push_str(&name[idx + 1..]);
        return out;
    }
    name.to_string()
}

fn truncate(mut tools: Vec<ToolDefinition>, max_tools: usize) -> Vec<ToolDefinition> {
    if max_tools == 0 {
        return Vec::new();
    }
    if tools.len() > max_tools {
        tools.truncate(max_tools);
    }
    tools
}

#[cfg(test)]
mod tests {
    use super::*;

    fn td(name: &str) -> ToolDefinition {
        ToolDefinition {
            name: name.into(),
            description: format!("{name} desc"),
            parameters: serde_json::json!({"type": "object"}),
        }
    }

    #[test]
    fn absent_selection_keeps_guest_tools_only() {
        let r = apply_callables(None, Some(vec![td("plan")]), &[td("write")], 128).unwrap();
        let names: Vec<_> = r.tools.unwrap().into_iter().map(|t| t.name).collect();
        assert_eq!(names, vec!["plan"]);
        assert!(r.dropped_unknown.is_empty());
    }

    #[test]
    fn all_merges_catalog_then_guest() {
        let r = apply_callables(
            Some(&CallableSelection::All),
            Some(vec![td("plan")]),
            &[td("write"), td("remember")],
            128,
        )
        .unwrap();
        let names: Vec<_> = r.tools.unwrap().into_iter().map(|t| t.name).collect();
        assert_eq!(names, vec!["write", "remember", "plan"]);
    }

    #[test]
    fn only_drops_unknown_with_visible_log() {
        let r = apply_callables(
            Some(&CallableSelection::Only(vec![
                "write".into(),
                "nope".into(),
                "data.describe".into(),
            ])),
            None,
            &[td("write"), td("data__describe")],
            128,
        )
        .unwrap();
        let names: Vec<_> = r.tools.unwrap().into_iter().map(|t| t.name).collect();
        assert_eq!(names, vec!["write", "data__describe"]);
        assert_eq!(r.dropped_unknown, vec!["nope"]);
    }

    #[test]
    fn guest_catalog_collision_fails_with_prefix() {
        let err = apply_callables(
            Some(&CallableSelection::All),
            Some(vec![td("write")]),
            &[td("write")],
            128,
        )
        .unwrap_err();
        assert!(
            matches!(err, LlmError::ProviderError(ref m) if m == "callable-collision: write"),
            "{err:?}"
        );
    }

    #[test]
    fn array_cap_is_configurable() {
        let r = apply_callables(
            Some(&CallableSelection::All),
            Some(vec![td("plan")]),
            &[td("write"), td("read")],
            2,
        )
        .unwrap();
        assert_eq!(r.tools.unwrap().len(), 2);
    }
}

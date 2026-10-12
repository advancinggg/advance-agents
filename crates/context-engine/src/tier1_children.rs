//! Tier 1b ⑥ — child-agent roster.
//!
//! Renders **direct** `AgentKind::Child` nodes of the assembling agent as
//! `# Available Children`. Grandchildren are excluded (parent match is
//! one hop). `AgentKind::Sub` stays in the Tier 2 ⑬ delegates section so
//! the two inventories do not double-render.
//!
//! **Omit-when-empty**: unlike `# Available Delegates` (always-header), this
//! section is omitted entirely when there are no matching children, so
//! empty-tree assemble output stays byte-identical to the pre-roster
//! prompts.
//!
//! **Basic info only**: handle (falls back to id) + capability ids. No
//! child's `AGENTS.md`, workspace path, or `template_ref`. Terminated and
//! Failed children are omitted.

use advance_shared_types::agent_tree::{AgentId, AgentKind, AgentStatus};
use advance_shared_types::traits::AgentTreeSnapshot;

use crate::tier2::sanitize_description;
use crate::tier2_delegates::join_caps_capped;
use crate::warning_queue::is_valid_agent_id;

/// Build the Tier 1b ⑥ child roster. `None` when `agent_id` is invalid or
/// the tree has no matching direct Child.
pub fn format_available_children_section(
    snap: &dyn AgentTreeSnapshot,
    agent_id: &str,
) -> Option<String> {
    format_available_children_section_with_aliases(snap, agent_id, &[])
}

/// Alias-aware variant — matches `node.parent` against `{agent_id} ∪ aliases`
/// so a Child recorded under the BARE cap-id surfaces on a COLON-keyed
/// assemble turn (same colon/bare bridge as `# Available Delegates`).
pub fn format_available_children_section_with_aliases(
    snap: &dyn AgentTreeSnapshot,
    agent_id: &str,
    aliases: &[String],
) -> Option<String> {
    let mut keys: Vec<AgentId> = Vec::with_capacity(1 + aliases.len());
    if is_valid_agent_id(agent_id) {
        keys.push(AgentId(agent_id.to_string()));
    }
    for a in aliases {
        if a != agent_id && is_valid_agent_id(a) && !keys.iter().any(|k| k.0 == *a) {
            keys.push(AgentId(a.clone()));
        }
    }
    if keys.is_empty() {
        return None;
    }

    let data = snap.snapshot();
    let mut lines = String::new();
    for node in &data.nodes {
        if node.kind != AgentKind::Child {
            continue;
        }
        if matches!(node.status, AgentStatus::Terminated | AgentStatus::Failed) {
            continue;
        }
        match node.parent.as_ref() {
            Some(p) if keys.contains(p) => {}
            _ => continue,
        }
        let name = sanitize_description(&data.handle_of(&node.id));
        let caps = sanitize_description(&join_caps_capped(&node.capabilities));
        lines.push_str(&format!("- {name} — {caps}\n"));
    }
    if lines.is_empty() {
        return None;
    }
    let mut section = String::from("# Available Children\n\n");
    section.push_str(&lines);
    Some(section)
}

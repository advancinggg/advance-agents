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
//! Each Child carries status (including Terminated / Failed, so a parent
//! can see a child that hung), workspace path, optional `template_ref`,
//! capability ids, and the child's `AGENTS.md` when the identity port
//! can read it.

use advance_shared_types::agent_tree::{AgentId, AgentKind, AgentStatus};
use advance_shared_types::traits::AgentTreeSnapshot;

use crate::ports::AgentIdentityReader;
use crate::tier2::{sanitize_description, sanitize_identity_document};
use crate::tier2_delegates::join_caps_capped;
use crate::warning_queue::is_valid_agent_id;

fn status_label(status: &AgentStatus) -> &'static str {
    match status {
        AgentStatus::Active => "active",
        AgentStatus::Paused => "paused",
        AgentStatus::Terminated => "terminated",
        AgentStatus::Failed => "failed",
    }
}

/// Build the Tier 1b ⑥ child roster. `None` when `agent_id` is invalid or
/// the tree has no matching direct Child.
pub async fn format_available_children_section(
    snap: &dyn AgentTreeSnapshot,
    identity: &dyn AgentIdentityReader,
    agent_id: &str,
) -> Option<String> {
    format_available_children_section_with_aliases(snap, identity, agent_id, &[]).await
}

/// Alias-aware variant — matches `node.parent` against `{agent_id} ∪ aliases`
/// so a Child recorded under the BARE cap-id surfaces on a COLON-keyed
/// assemble turn (same colon/bare bridge as `# Available Delegates`).
pub async fn format_available_children_section_with_aliases(
    snap: &dyn AgentTreeSnapshot,
    identity: &dyn AgentIdentityReader,
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
    let mut blocks = String::new();
    for node in &data.nodes {
        if node.kind != AgentKind::Child {
            continue;
        }
        match node.parent.as_ref() {
            Some(p) if keys.contains(p) => {}
            _ => continue,
        }
        let name = sanitize_description(&data.handle_of(&node.id));
        let workspace = sanitize_description(&node.workspace_path.display().to_string());
        let caps = sanitize_description(&join_caps_capped(&node.capabilities));
        if !blocks.is_empty() {
            blocks.push('\n');
        }
        blocks.push_str(&format!("## {name}\n"));
        blocks.push_str(&format!("- status: {}\n", status_label(&node.status)));
        blocks.push_str(&format!("- workspace: {workspace}\n"));
        if let Some(template) = node.template_ref.as_deref() {
            let safe = sanitize_description(template);
            if !safe.trim().is_empty() {
                blocks.push_str(&format!("- template: {safe}\n"));
            }
        }
        blocks.push_str(&format!("- capabilities: {caps}\n"));
        if let Some(document) = identity.agents_md_for_workspace(&node.workspace_path).await {
            let safe = sanitize_identity_document(&document);
            if !safe.trim().is_empty() {
                blocks.push('\n');
                blocks.push_str(&safe);
                if !safe.ends_with('\n') {
                    blocks.push('\n');
                }
            }
        }
    }
    if blocks.is_empty() {
        return None;
    }
    let mut section = String::from("# Available Children\n\n");
    section.push_str(&blocks);
    Some(section)
}

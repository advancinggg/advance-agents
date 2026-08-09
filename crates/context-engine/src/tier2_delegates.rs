//! AC-19 — Tier 2 ⑬ "Available Delegates" (PRD §3.10 dual positioning).
//!
//! Renders Sub-Agents as first-class delegation targets, **parallel to**
//! (NOT merged into) the AC-18 `# Available Tools` section. The fourth Layer-2
//! Execution Object (Delegate / Sub-Agent) is presented here; the other three
//! (host fn / WASM tool / MCP tool) stay in `# Available Tools` per ARCH §8
//! Decision 15.
//!
//! **Presentation scope** (MODULE-010 §1.3.3 ⑬ clarification): this section
//! renders `AgentKind::Sub` agents ONLY. The child-agent roster is the
//! separate Tier 1b ⑥ presentation (a future slice). Both are presentations
//! of the same unchanged CONTRACT-040 reader surface (which §2.2 documents as
//! enumerating both child + sub). The `Sub`-only filter here prevents the
//! future Tier 1b ⑥ slice from double-rendering child agents.
//!
//! **Sanitization**: a Sub-Agent's `id` (`AgentId`) is *documented* as
//! whitelist-validatable (`^[A-Za-z0-9_-]{1,64}$` per `agent_tree.rs:60-70`),
//! but that document-level invariant is a **caller obligation**, NOT a
//! type-level enforcement — `AgentId(pub String)` accepts any bytes. The
//! capability summary is sourced from the *structured* `capabilities[].id`
//! (`CapabilityId`, a transparent newtype over `String`). Round-10 doc
//! correction: `CapabilityId` is likewise **NOT charset-bounded at the type
//! level** — `CapabilityId::new`/`From<&str>`/`From<String>` accept any
//! string. Both the `AgentId`-stringified name AND the `capabilities[].id`
//! join are routed through the shared `pub(crate)`
//! [`crate::tier2::sanitize_description`] as defense-in-depth (a near-no-op
//! in practice for whitelist-charset producers, but the *only* place this
//! module's output is structurally guaranteed safe — do NOT skip the
//! sanitizer based on assumed upstream validation). The capability summary
//! deliberately avoids the un-whitelisted free-text `AgentNode.template_ref`
//! field, which is a true attacker-controlled string.

use advance_shared_types::agent_tree::{AgentId, AgentKind};
use advance_shared_types::traits::AgentTreeSnapshot;

use crate::tier2::sanitize_description;
use crate::warning_queue::is_valid_agent_id;

/// Per-capability id length cap before joining (round-10 Warning 5
/// defense-in-depth). 64 bytes mirrors the `AgentId` recommended bound;
/// capabilities exceeding this are TRUNCATED (with `…` suffix) so a single
/// monster capability cannot bloat the join.
const MAX_CAP_ID_LEN: usize = 64;

/// Per-Sub-agent total joined-summary length cap (round-10 Warning 5). 512
/// bytes is well above any reasonable per-agent capability list size while
/// bounding adversarial-cardinality blowups (e.g., a malicious tree node
/// with 10k capability entries × 1 KiB each).
const MAX_SUMMARY_LEN: usize = 512;

/// Build the Tier 2 ⑬ "Available Delegates" section for `agent_id`. Always
/// emits the `# Available Delegates` header (parallel to the AC-18
/// `# Available Tools` always-header convention); zero Subs ⇒ header only.
///
/// **Round-10 ADVERSARIAL Warning 2** — defensive `agent_id` validation: the
/// in-tree caller (`assembler.rs::assemble`) already validates per CONTRACT-090
/// invariant 4, but this function is `pub` and re-exported from `lib.rs` for
/// symmetry with `format_available_tools_section`. Defense-in-depth: an invalid
/// `agent_id` (failing the M008 `validate_task_id`-equivalent charset/length
/// check) yields the empty header section. No external caller can bypass
/// invariant 4 by skipping the assembler entry.
pub fn format_available_delegates_section(snap: &dyn AgentTreeSnapshot, agent_id: &str) -> String {
    // 2-arg form (single-id match, no aliases) — kept byte-identical for the
    // existing call sites. Delegates to the Wave-12 alias-aware form with an
    // empty alias set.
    format_available_delegates_section_with_aliases(snap, agent_id, &[])
}

/// Wave-12 — alias-aware variant (SYS-AC-011). Matches a Sub-Agent's
/// `node.parent` against the agent's full id-**alias set** (`{agent_id} ∪
/// aliases`), not the single `agent_id`. This bridges the colon/bare keying
/// split: production cap-lifecycle spawns record `Sub` nodes under the BARE
/// cap-id (`default-agent`) while `assemble()` runs under the COLON msg-id
/// (`agent:default`). The cli composition root passes the production
/// `query_aliases = [cap_agent_id, msg_agent_id]` (the SAME set already wired
/// to the Tier-1b memory readers). An empty `aliases` slice ⇒ the original
/// single-id behaviour. Each candidate key (the `agent_id` AND each alias) is
/// independently whitelist-validated (`is_valid_agent_id`); an invalid id never
/// becomes a match key (defense-in-depth, CONTRACT-090 invariant 4). If NO
/// candidate is valid, the empty header is returned (fail-closed, preserving
/// the original 2-arg guard).
pub fn format_available_delegates_section_with_aliases(
    snap: &dyn AgentTreeSnapshot,
    agent_id: &str,
    aliases: &[String],
) -> String {
    // Build the set of valid parent keys: {agent_id} ∪ {valid distinct aliases}.
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
        return String::from("# Available Delegates\n\n");
    }
    let data = snap.snapshot();

    let mut s = String::from("# Available Delegates\n\n");
    for node in &data.nodes {
        // Sub-Agents whose parent is THIS agent (under ANY of its id aliases).
        // `Child` is intentionally excluded (Tier 1b ⑥, future).
        if node.kind != AgentKind::Sub {
            continue;
        }
        match node.parent.as_ref() {
            Some(p) if keys.contains(p) => {}
            _ => continue,
        }
        let name = sanitize_description(&node.id.0);
        // Round-10 Warning 5: cap per-id at MAX_CAP_ID_LEN AND the joined
        // summary at MAX_SUMMARY_LEN to bound adversarial-cardinality blow-up
        // (a malicious tree node with thousands of long capability strings
        // would otherwise allocate per-`assemble()` memory in proportion to
        // its content). UTF-8 char-boundary truncation; "…" suffix when
        // truncated.
        let caps_joined = join_caps_capped(&node.capabilities);
        let caps = sanitize_description(&caps_joined);
        s.push_str(&format!("- {name} — {caps}\n"));
    }
    s
}

fn join_caps_capped(caps: &[advance_shared_types::agent_tree::Capability]) -> String {
    let mut out = String::with_capacity(MAX_SUMMARY_LEN.min(256));
    let mut truncated_total = false;
    for (i, c) in caps.iter().enumerate() {
        let id = c.id.as_str();
        let mut id_truncated = false;
        let id_capped = if id.len() > MAX_CAP_ID_LEN {
            let mut keep = MAX_CAP_ID_LEN;
            while keep > 0 && !id.is_char_boundary(keep) {
                keep -= 1;
            }
            id_truncated = true;
            &id[..keep]
        } else {
            id
        };
        let sep_len = if i == 0 { 0 } else { 2 }; // ", "
        let suffix_len = if id_truncated { 1 } else { 0 }; // "…" UTF-8 ≤ 3, but we count chars conservatively below
                                                           // Decide whether adding (sep + id_capped + suffix) would exceed the total cap.
        let projected = out
            .len()
            .saturating_add(sep_len)
            .saturating_add(id_capped.len())
            .saturating_add(if id_truncated { 3 } else { 0 }); // "…" is 3 bytes in UTF-8
        if projected > MAX_SUMMARY_LEN {
            truncated_total = true;
            break;
        }
        if i > 0 {
            out.push_str(", ");
        }
        out.push_str(id_capped);
        if id_truncated {
            out.push('…');
        }
        let _ = suffix_len; // future-use marker, currently informational
    }
    if truncated_total {
        // Reserve a trailing marker so operators see the truncation, even if
        // it would push the byte count modestly past MAX_SUMMARY_LEN — the
        // marker is small (~6 bytes) and the cap is a soft guard, not a hard
        // contract like the knowledge-map 500-token rule.
        out.push_str(" …");
    }
    out
}

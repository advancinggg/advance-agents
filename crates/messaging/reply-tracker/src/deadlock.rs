//! AC-09 deadlock detection — reply-tracker-local ancestry walk.
//!
//! `is_ancestor_of` is absent from the shared-types `AgentTreeSnapshot`
//! trait (CONTRACT-040 ships `parent_of`/`children_of`/`siblings_of`), so
//! AC-09 is implemented this slice via an equivalent `parent_of` upward walk
//! over a [`AgentTreeSnapshotData`] snapshot (MODULE-007 §3.7 mechanism, not a
//! narrowing). The §1.4 AC-09 criterion (admission rejects a would-be cycle
//! with `OrchestrationError::DeadlockDetected`) carries **no event
//! requirement** itself. `forms_cycle` returns a plain `bool` (the detection
//! predicate). **Wave-15 Lane A (2026-06-24)**: the some-but-not-all-cycle
//! `orchestration.deadlock_rejected` event (SYS-AC-169) IS now emitted
//! in-boundary from the manager admission path (see MODULE-007 §1.5 AC-17 /
//! §3.6 / §3.8) — its PRD §15.3.4B `cycle` payload field is populated by
//! `cycle_path` below (the same bounded upward walk, returning the
//! `[caller, …, target]` chain). The earlier "deadlock_rejected is out of the
//! reply-tracker crate boundary / the cycle path was only needed for a
//! now-removed payload" note is superseded.

use advance_shared_types::agent_tree::{AgentId, AgentTreeSnapshotData};

/// Returns `true` iff awaiting `target_bare` from `caller_bare` would form a
/// cycle in the agent tree.
///
/// `caller_bare` arrives as a bare agent name (the runtime stamps the caller
/// bare, e.g. `"researcher"`). `target_bare` is the canonical request target
/// body — callers strip the leading `agent:` prefix before calling (the
/// `parent_of` map is keyed by bare [`AgentId`], grammar
/// `^[A-Za-z0-9_-]{1,64}$`).
///
/// Direction (adjudicated — ADR
/// `2026-06-10-await-deadlock-direction-adjudication`): a deadlock is an
/// await edge pointing **upward** — the target is the caller itself
/// (self-await) or an **ancestor** of the caller. Downward awaits (target is
/// a descendant) are the normal SYS-J-05 parent→child delegation pattern and
/// are **admitted**: downward edges follow the acyclic agent tree and can
/// never close an await cycle on their own.
///
/// Mechanism: walk `snapshot.parent_of` upward from `AgentId(caller_bare)`.
/// A cycle exists iff `target_bare` is reached during the walk OR
/// `target_bare == caller_bare` (self-await). The walk is bounded by
/// `snapshot.nodes.len()` (or the `parent_of` map length, whichever is
/// larger) hops so a malformed self-referential `parent_of` terminates
/// instead of looping forever. An unknown/absent key (the caller or one of
/// its recorded ancestors missing from `parent_of`) yields `false` — no
/// ancestry information, no cycle; a target absent from the tree likewise
/// falls through to the existing per-slot dispatch invalid-target path,
/// AC-07-preserving. Reaching a root (`None` parent) without meeting the
/// target yields `false`.
///
/// This is a **static conservative approximation** over tree ancestry, not a
/// dynamic wait-graph: it rejects a child awaiting an *idle* ancestor (one
/// not actually parked on the caller's subtree) even though that await would
/// resolve. The precise dynamic wait-graph check is a separately queued
/// end-state (see MODULE-007 §3.6); the ADR above is the authority for the
/// direction adjudicated here.
///
/// # Threat model (Adversarial round R20-W3)
///
/// This function bounds the WALK (against an infinite loop on a malformed
/// cyclic `parent_of`), but it does NOT bound the snapshot SIZE. The
/// `AgentTreeSnapshotData` is produced by the trusted MODULE-005
/// `AgentTreeSnapshot` provider (an injected dependency wired by the
/// runtime — like the `MailboxDispatcher`), reflecting the system's REAL
/// agent tree, which is bounded by the system's own agent-spawn limits.
/// It is NOT attacker-supplied via the `await-replies` request, so a
/// "hostile oversized snapshot" requires compromising the trusted provider
/// — outside this slice's threat model. Bounding/rejecting an oversized or
/// adversarial tree is the MODULE-005 provider's documented responsibility
/// (the same trust class as the `caller`/`agent_id` host-fn-stamped ids and
/// the dispatcher). The cost here is O(`max_hops`) per agent slot ×
/// ≤ `MAX_FANOUT` slots over that producer-bounded tree.
pub(crate) fn forms_cycle(
    snapshot: &AgentTreeSnapshotData,
    caller_bare: &str,
    target_bare: &str,
) -> bool {
    // Self-await is always a cycle.
    if target_bare == caller_bare {
        return true;
    }
    // Bound the walk so a malformed cyclic `parent_of` (e.g. b→c→b with the
    // target absent from the loop) terminates. `nodes.len()` is the
    // canonical agent count; fall back to the `parent_of` map length when
    // the snapshot's `nodes` vec is empty but `parent_of` is populated
    // (defensive — the §2.3 consistency invariant says they agree, but we
    // do not trust an attacker-crafted snapshot).
    let max_hops = snapshot.nodes.len().max(snapshot.parent_of.len());
    let mut current = AgentId(caller_bare.to_string());
    for _ in 0..max_hops {
        match snapshot.parent_of.get(&current) {
            // Unknown/absent key → no ancestry information → no cycle.
            None => return false,
            // Root reached (parent is None) without meeting the target —
            // the target is not an ancestor of the caller.
            Some(None) => return false,
            Some(Some(parent)) => {
                if parent.0 == target_bare {
                    // Target is an ancestor of the caller → upward await.
                    return true;
                }
                current = parent.clone();
            }
        }
    }
    // Exhausted the hop bound without reaching the target or a root — treat
    // as no detected cycle (a malformed cyclic ancestor chain that never
    // includes the target is not a caller↔target deadlock for this request).
    false
}

/// Reconstruct the detected upward-await cycle path `[caller_bare, …,
/// target_bare]` for the `orchestration.deadlock_rejected` event payload (PRD
/// §15.3.4B `cycle` field). Wave-15 Lane A.
///
/// Walks `snapshot.parent_of` up from `caller_bare` (the SAME bounded walk as
/// `forms_cycle` — `forms_cycle` is unchanged), collecting each hop, and
/// stops when `target_bare` is reached. Returns `[caller_bare, …,
/// target_bare]`. Self-await (`target_bare == caller_bare`) → `[caller_bare]`.
///
/// Callers only invoke this for a slot `forms_cycle` already confirmed cyclic
/// (so the target IS reachable upward); if the walk nonetheless exhausts the
/// hop bound or hits a root/absent key without meeting the target (a malformed
/// snapshot), the partial chain walked so far is returned as a best-effort
/// representation — the event payload is observability data, never a
/// correctness gate.
pub(crate) fn cycle_path(
    snapshot: &AgentTreeSnapshotData,
    caller_bare: &str,
    target_bare: &str,
) -> Vec<String> {
    let mut path = vec![caller_bare.to_string()];
    if target_bare == caller_bare {
        return path;
    }
    let max_hops = snapshot.nodes.len().max(snapshot.parent_of.len());
    let mut current = AgentId(caller_bare.to_string());
    for _ in 0..max_hops {
        match snapshot.parent_of.get(&current) {
            None => return path,
            Some(None) => return path,
            Some(Some(parent)) => {
                path.push(parent.0.clone());
                if parent.0 == target_bare {
                    return path;
                }
                current = parent.clone();
            }
        }
    }
    path
}

#[cfg(test)]
mod tests {
    use super::*;
    use advance_shared_types::agent_tree::{
        AgentKind, AgentNode, AgentStatus, AgentTreeSnapshotData,
    };
    use std::collections::HashMap;
    use std::path::PathBuf;

    fn node(id: &str) -> AgentNode {
        AgentNode {
            id: AgentId(id.to_string()),
            kind: AgentKind::Child,
            parent: None,
            workspace_path: PathBuf::from("/tmp"),
            capabilities: vec![],
            template_ref: None,
            status: AgentStatus::Active,
        }
    }

    fn snap(node_ids: &[&str], parent_pairs: &[(&str, Option<&str>)]) -> AgentTreeSnapshotData {
        let mut parent_of = HashMap::new();
        for (child, parent) in parent_pairs {
            parent_of.insert(
                AgentId(child.to_string()),
                parent.map(|p| AgentId(p.to_string())),
            );
        }
        AgentTreeSnapshotData {
            nodes: node_ids.iter().map(|i| node(i)).collect(),
            parent_of,
            children_of: HashMap::new(),
            peer_slug_map: HashMap::new(),
            revision: 1,
        }
    }

    #[test]
    fn t08c_i_target_equals_caller_is_cycle() {
        // (i) self-await: target == caller → true.
        let s = snap(&["a"], &[("a", None)]);
        assert!(forms_cycle(&s, "a", "a"));
    }

    #[test]
    fn t08c_ii_agent_prefixed_normalized_3hop_to_ancestor_is_cycle() {
        // (ii) normalized 3-hop chain d→c→b→a: caller "d" awaits its
        // great-grand-ancestor "a" — an upward await → cycle.
        // The manager strips the `agent:` prefix before calling; this test
        // passes the already-normalized bare body, mirroring that contract.
        let s = snap(
            &["a", "b", "c", "d"],
            &[
                ("d", Some("c")),
                ("c", Some("b")),
                ("b", Some("a")),
                ("a", None),
            ],
        );
        assert!(forms_cycle(&s, "d", "a"));
    }

    #[test]
    fn t08c_iii_sibling_is_not_cycle() {
        // (iii) sibling: caller "b" and target "c" both children of "a" —
        // walking up from caller b reaches a (root, ≠ target) → false.
        let s = snap(
            &["a", "b", "c"],
            &[("b", Some("a")), ("c", Some("a")), ("a", None)],
        );
        assert!(!forms_cycle(&s, "b", "c"));
    }

    #[test]
    fn t08c_iv_absent_key_is_not_cycle() {
        // (iv) caller absent from parent_of → no ancestry information →
        // false (the walk now starts at the caller; an unknown caller key
        // yields false immediately).
        let s = snap(&["a"], &[("a", None)]);
        assert!(!forms_cycle(&s, "zzz", "a"));
    }

    #[test]
    fn t08c_v_none_root_not_caller_is_not_cycle() {
        // (v) caller "a" is a root (parent None); target "root" is an
        // unrelated root, never reached during the walk → false.
        let s = snap(&["a", "root"], &[("root", None), ("a", None)]);
        assert!(!forms_cycle(&s, "a", "root"));
    }

    #[test]
    fn t08c_vi_malformed_cyclic_parent_of_bounded_terminates_false() {
        // (vi) malformed cyclic parent_of with the TARGET absent from the
        // loop: caller "b" sits inside the b→c→b loop. The walk must
        // exhaust the hop bound (nodes.len()) instead of looping forever,
        // and report false (no caller↔target deadlock for this request).
        let s = snap(&["b", "c"], &[("b", Some("c")), ("c", Some("b"))]);
        assert!(!forms_cycle(&s, "b", "target-not-in-tree"));
    }

    #[test]
    fn t08c_viii_empty_nodes_parent_of_fallback_bounds_walk() {
        // (viii) hop-bound fallback lock: `max_hops` is
        // `nodes.len().max(parent_of.len())`. With an EMPTY `nodes` vec and
        // a populated `parent_of` (the documented defensive case — we do
        // not trust an attacker-crafted snapshot), the `parent_of` length
        // must govern the bound: caller "b" awaiting its parent "a" over
        // parent_of {b→a, a→root} must still be detected as an upward-await
        // cycle. If the fallback regressed to `nodes.len()` alone the bound
        // would be 0, the walk would never run, and this genuine cycle
        // would be wrongly admitted (false negative).
        let s = snap(&[], &[("b", Some("a")), ("a", None)]);
        assert!(
            forms_cycle(&s, "b", "a"),
            "empty-nodes snapshot must still detect the upward await via \
             the parent_of-length hop-bound fallback"
        );
    }

    #[test]
    fn t08c_vii_descendant_target_is_not_cycle() {
        // (vii) admit-direction unit lock (ADR
        // 2026-06-10-await-deadlock-direction-adjudication): a downward
        // await — the target is a DESCENDANT of the caller — is the
        // SYS-J-05 delegation pattern and must NOT be a cycle. Direct
        // child (a awaits b) and great-grandchild (a awaits d) over the
        // chain d→c→b→a.
        let s = snap(
            &["a", "b", "c", "d"],
            &[
                ("d", Some("c")),
                ("c", Some("b")),
                ("b", Some("a")),
                ("a", None),
            ],
        );
        assert!(!forms_cycle(&s, "a", "b"), "direct child must be admitted");
        assert!(
            !forms_cycle(&s, "a", "d"),
            "great-grandchild must be admitted"
        );
    }
}

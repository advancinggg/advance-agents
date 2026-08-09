//! Wave-13 Lane C — `memory_search_docs`: the product ingestion path that
//! enumerates an agent's ACTIVE memory entries into plain search-corpus docs
//! (MODULE-011 §3.7 Wave-13 Lane C). Closes the SYS-AC-005 deferral note's "no
//! product path populates the search corpus from MemoryStore" gap.
//!
//! Returns a crate-LOCAL [`MemorySearchDoc`] (id + text), NOT context-engine's
//! `CorpusDoc` — so cap-memory gains NO context-engine edge (the inverted-port
//! discipline; cap-memory stays a near-leaf). The mainline harvest (cli
//! composition root, where both crates are reachable) maps `MemorySearchDoc ->
//! advance_context_engine::CorpusDoc::memory` and feeds `build_agent_search_corpus`.

use crate::store::MemoryStore;

/// A plain memory-content doc for downstream search-corpus indexing: the entry's
/// stable id + its content text. Memory-kind is implied (the harvest maps these
/// to `CorpusDoc::memory`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemorySearchDoc {
    pub id: String,
    pub text: String,
}

/// Enumerate `agent_id`'s ACTIVE memory entries as [`MemorySearchDoc`]s for
/// search-corpus indexing. Uses the existing `MemoryStore::recall(agent_id, "",
/// …)` — an empty query matches every active entry, and `is_active=false`
/// entries (Forgotten / Superseded) are already excluded by `recall`. Entries
/// whose content is empty/whitespace are dropped (an empty doc cannot be
/// embedded or ranked).
///
/// `limit` bounds the number of NON-EMPTY docs returned (`limit == 0` ⇒
/// unbounded). The recall is therefore run UNBOUNDED and the limit applied
/// AFTER the empty-content filter — passing `limit` straight to `recall` would
/// let empty-content active entries consume limit slots (recall's `.take(limit)`
/// runs before this filter) and silently exclude later non-empty memories.
/// cap-memory's active set is retention-bounded, so the unbounded recall is safe.
pub fn memory_search_docs(store: &MemoryStore, agent_id: &str, limit: u32) -> Vec<MemorySearchDoc> {
    let mut docs: Vec<MemorySearchDoc> = store
        .recall(agent_id, "", 0)
        .into_iter()
        .filter(|e| !e.content.trim().is_empty())
        .map(|e| MemorySearchDoc {
            id: e.id,
            text: e.content,
        })
        .collect();
    if limit != 0 {
        docs.truncate(limit as usize);
    }
    docs
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::knowledge::{MemoryEntry, MemoryStatus, MemoryType};

    fn active_fact(id: &str, agent: &str, content: &str) -> MemoryEntry {
        MemoryEntry {
            id: id.to_string(),
            agent_id: agent.to_string(),
            entry_type: MemoryType::Fact,
            content: content.to_string(),
            tags: Vec::new(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            task_origin: None,
            is_active: true,
            superseded_by: None,
            status: MemoryStatus::Active,
            supersession_reason: None,
            cluster_id: None,
            sources: Vec::new(),
        }
    }

    #[test]
    fn enumerates_active_entries_with_verbatim_content() {
        let store = MemoryStore::new();
        store
            .insert(
                "agent-1",
                active_fact("m1", "agent-1", "the deploy script runs cargo build"),
            )
            .unwrap();
        store
            .insert(
                "agent-1",
                active_fact("m2", "agent-1", "the user prefers dark mode"),
            )
            .unwrap();

        let docs = memory_search_docs(&store, "agent-1", 64);
        assert_eq!(docs.len(), 2);
        let by_id: std::collections::HashMap<_, _> = docs
            .iter()
            .map(|d| (d.id.as_str(), d.text.as_str()))
            .collect();
        assert_eq!(by_id.get("m1"), Some(&"the deploy script runs cargo build"));
        assert_eq!(by_id.get("m2"), Some(&"the user prefers dark mode"));
    }

    #[test]
    fn limit_counts_non_empty_docs_not_scanned_entries() {
        // Two empty-content active entries precede a real one. `limit = 1` must
        // return the 1 NON-EMPTY doc — the empties must NOT consume the slot
        // (the bug `recall(.., limit)` would have: it `.take(1)` before filtering).
        let store = MemoryStore::new();
        store
            .insert("agent-1", active_fact("e1", "agent-1", "   "))
            .unwrap();
        store
            .insert("agent-1", active_fact("e2", "agent-1", "\t "))
            .unwrap();
        store
            .insert(
                "agent-1",
                active_fact("real", "agent-1", "real indexable content"),
            )
            .unwrap();

        let docs = memory_search_docs(&store, "agent-1", 1);
        assert_eq!(docs.len(), 1, "limit bounds NON-EMPTY docs");
        assert_eq!(docs[0].id, "real");
    }

    #[test]
    fn excludes_empty_content_and_other_agents() {
        let store = MemoryStore::new();
        store
            .insert("agent-1", active_fact("m1", "agent-1", "real content"))
            .unwrap();
        store
            .insert("agent-1", active_fact("m-empty", "agent-1", "   "))
            .unwrap();
        store
            .insert(
                "agent-2",
                active_fact("other", "agent-2", "other agent content"),
            )
            .unwrap();

        let docs = memory_search_docs(&store, "agent-1", 64);
        assert_eq!(docs.len(), 1);
        assert_eq!(docs[0].id, "m1");
    }
}

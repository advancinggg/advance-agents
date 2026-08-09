//! L6 Step 5c — `KnowledgeHealthSnapshot` computation (AC-35) + admin list
//! helpers (AC-36). MODULE-011 §1.3.6 step 5c / §1.2.
//!
//! AC-35: a SINGLE O(N) pass over the agent's entries (shared-types
//! `KnowledgeHealthSnapshot` rustdoc invariant: "MUST be O(N) single-scan, no
//! re-reads"). The cluster fold (`clusters_total` / `clusters_contested`) and
//! the `zero_access_30d` O(1) access-map lookup are folded into the SAME
//! iteration — no second scan, no `knowledge_map` dependency (clusters come
//! from the store's `cluster_id` field per AC-35, not `_knowledge_map.yaml`).

use std::collections::{HashMap, HashSet};
use std::time::SystemTime;

use advance_shared_types::memory::KnowledgeHealthSnapshot;

use crate::knowledge::{MemoryEntry, MemoryStatus};
use crate::store::MemoryStore;

#[inline]
fn inc(c: &mut u32) {
    *c = c.saturating_add(1);
}

/// Single O(N) scan. `partial_stale_ids` = THIS L6 run's
/// `StaleStateSnapshot.partial_stale_ids` (passed in; not recomputed).
pub fn compute_health_snapshot(
    store: &MemoryStore,
    agent_id: &str,
    partial_stale_ids: &HashSet<String>,
    now: SystemTime,
) -> KnowledgeHealthSnapshot {
    let mut total_active = 0u32;
    let mut active = 0u32;
    let mut contested = 0u32;
    let mut orphaned = 0u32;
    let mut forgotten = 0u32;
    let mut superseded = 0u32;
    let mut partial_stale = 0u32;
    let mut zero_access_30d = 0u32;
    // cluster_id → any-entry-contested? (built during the SAME pass).
    let mut clusters: HashMap<String, bool> = HashMap::new();

    for e in store.list(agent_id).iter() {
        if e.is_active {
            inc(&mut total_active);
        }
        match e.status {
            MemoryStatus::Active => inc(&mut active),
            MemoryStatus::Contested => inc(&mut contested),
            MemoryStatus::Orphaned => inc(&mut orphaned),
            MemoryStatus::Forgotten => inc(&mut forgotten),
            MemoryStatus::Superseded => inc(&mut superseded),
        }
        if partial_stale_ids.contains(&e.id) {
            inc(&mut partial_stale);
        }
        if e.is_active && store.is_zero_access_30d(agent_id, &e.id, now) {
            inc(&mut zero_access_30d);
        }
        if let Some(cid) = &e.cluster_id {
            if !cid.is_empty() {
                let flag = clusters.entry(cid.clone()).or_insert(false);
                if e.status == MemoryStatus::Contested {
                    *flag = true;
                }
            }
        }
    }

    let clusters_total = clusters.len() as u32;
    let clusters_contested = clusters.values().filter(|&&v| v).count() as u32;

    KnowledgeHealthSnapshot {
        total_active,
        active,
        contested,
        orphaned,
        forgotten,
        superseded,
        partial_stale,
        zero_access_30d,
        clusters_total,
        clusters_contested,
    }
}

/// AC-36 — contested entries grouped by `cluster_id`. O(N).
pub fn list_contested(store: &MemoryStore, agent_id: &str) -> HashMap<String, Vec<MemoryEntry>> {
    let mut out: HashMap<String, Vec<MemoryEntry>> = HashMap::new();
    for e in store
        .list(agent_id)
        .into_iter()
        .filter(|e| e.status == MemoryStatus::Contested)
    {
        let key = e.cluster_id.clone().unwrap_or_default();
        out.entry(key).or_default().push(e);
    }
    out
}

/// AC-36 — orphaned entries (with their sources). O(N).
pub fn list_orphaned(store: &MemoryStore, agent_id: &str) -> Vec<MemoryEntry> {
    store
        .list(agent_id)
        .into_iter()
        .filter(|e| e.status == MemoryStatus::Orphaned)
        .collect()
}

/// AC-36 — partial-stale entries (those in THIS run's partial-stale set). O(N).
pub fn list_partial_stale(
    store: &MemoryStore,
    agent_id: &str,
    partial_stale_ids: &HashSet<String>,
) -> Vec<MemoryEntry> {
    store
        .list(agent_id)
        .into_iter()
        .filter(|e| partial_stale_ids.contains(&e.id))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::knowledge::{MemoryStatus, MemoryType};

    fn entry(
        id: &str,
        status: MemoryStatus,
        is_active: bool,
        cluster: Option<&str>,
    ) -> MemoryEntry {
        MemoryEntry {
            id: id.into(),
            agent_id: "a".into(),
            entry_type: MemoryType::Fact,
            content: "x".into(),
            tags: vec![],
            created_at: "1970-01-01T00:00:00Z".into(),
            task_origin: None,
            is_active,
            superseded_by: if status == MemoryStatus::Superseded {
                Some("z".into())
            } else {
                None
            },
            status,
            supersession_reason: None,
            cluster_id: cluster.map(|c| c.to_string()),
            sources: vec![],
        }
    }

    #[test]
    fn snapshot_all_ten_counters_incl_cluster_fold() {
        let store = MemoryStore::new();
        let now = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(100 * 24 * 3600);
        // 3 active in cl-a (2 contested), 2 active in cl-b, + orphaned/forgotten/superseded.
        store
            .insert(
                "a",
                entry("a1", MemoryStatus::Contested, true, Some("cl-a")),
            )
            .unwrap();
        store
            .insert(
                "a",
                entry("a2", MemoryStatus::Contested, true, Some("cl-a")),
            )
            .unwrap();
        store
            .insert("a", entry("a3", MemoryStatus::Active, true, Some("cl-a")))
            .unwrap();
        store
            .insert("a", entry("b1", MemoryStatus::Active, true, Some("cl-b")))
            .unwrap();
        store
            .insert("a", entry("b2", MemoryStatus::Active, true, Some("cl-b")))
            .unwrap();
        store
            .insert("a", entry("o1", MemoryStatus::Orphaned, true, None))
            .unwrap();
        store
            .insert("a", entry("f1", MemoryStatus::Forgotten, false, None))
            .unwrap();
        store
            .insert("a", entry("s1", MemoryStatus::Superseded, false, None))
            .unwrap();
        // Mark recent access for all but one active entry → 1 zero-access.
        for id in ["a1", "a2", "a3", "b1", "o1"] {
            store.record_access("a", id, now);
        }
        // b2 has NO recorded access → zero_access_30d counts it (active).
        let partial: HashSet<String> = ["a3".to_string(), "b1".to_string()].into_iter().collect();

        let snap = compute_health_snapshot(&store, "a", &partial, now);
        assert_eq!(snap.total_active, 6); // a1 a2 a3 b1 b2 o1
        assert_eq!(snap.active, 3); // a3 b1 b2
        assert_eq!(snap.contested, 2); // a1 a2
        assert_eq!(snap.orphaned, 1); // o1
        assert_eq!(snap.forgotten, 1); // f1
        assert_eq!(snap.superseded, 1); // s1
        assert_eq!(snap.partial_stale, 2); // a3 b1
        assert_eq!(snap.zero_access_30d, 1); // b2 (active, no access recorded)
        assert_eq!(snap.clusters_total, 2); // cl-a, cl-b
        assert_eq!(snap.clusters_contested, 1); // cl-a (has a1/a2 contested)
    }

    #[test]
    fn admin_helpers() {
        let store = MemoryStore::new();
        store
            .insert(
                "a",
                entry("c1", MemoryStatus::Contested, true, Some("cl-x")),
            )
            .unwrap();
        store
            .insert(
                "a",
                entry("c2", MemoryStatus::Contested, true, Some("cl-x")),
            )
            .unwrap();
        store
            .insert("a", entry("o1", MemoryStatus::Orphaned, true, None))
            .unwrap();
        store
            .insert("a", entry("p1", MemoryStatus::Active, true, None))
            .unwrap();
        let partial: HashSet<String> = ["p1".to_string()].into_iter().collect();

        let contested = list_contested(&store, "a");
        assert_eq!(contested.len(), 1);
        assert_eq!(contested["cl-x"].len(), 2);
        assert_eq!(list_orphaned(&store, "a").len(), 1);
        let ps = list_partial_stale(&store, "a", &partial);
        assert_eq!(ps.len(), 1);
        assert_eq!(ps[0].id, "p1");
    }

    #[test]
    fn admin_helpers_latency_under_50ms_for_1000_entries() {
        let store = MemoryStore::new();
        for i in 0..1000 {
            let st = if i % 7 == 0 {
                MemoryStatus::Contested
            } else if i % 11 == 0 {
                MemoryStatus::Orphaned
            } else {
                MemoryStatus::Active
            };
            store
                .insert(
                    "a",
                    entry(&format!("e{i}"), st, true, Some(&format!("cl-{}", i % 13))),
                )
                .unwrap();
        }
        let partial: HashSet<String> = (0..1000)
            .filter(|i| i % 5 == 0)
            .map(|i| format!("e{i}"))
            .collect();
        let now = SystemTime::UNIX_EPOCH;
        let t = std::time::Instant::now();
        let _ = list_contested(&store, "a");
        let _ = list_orphaned(&store, "a");
        let _ = list_partial_stale(&store, "a", &partial);
        let _ = compute_health_snapshot(&store, "a", &partial, now);
        let elapsed = t.elapsed();
        assert!(
            elapsed < std::time::Duration::from_millis(50),
            "AC-36: helpers over 1000 entries must complete < 50 ms (the §1.4 normative \
             threshold, NOT a relaxed bound); took {elapsed:?}"
        );
    }
}

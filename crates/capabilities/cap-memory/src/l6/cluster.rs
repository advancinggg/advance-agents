//! L6 Step 2 — semantic clustering (pure compute). MODULE-011 §1.3.6 step 2.
//!
//! Round-2 Critical-1 resolution: `L6ClusterBuilder` is a self-contained
//! pure-compute struct, NOT a trait, and does NOT reuse the Slice B
//! `reconcile::SimilarityIndex` seam (whose single-query `find_similar` API
//! against its own separate seed cannot express all-pairs connected-components
//! clustering over the store's entries, and offers no store-entry id
//! correlation for the §1.3.6 step-5b cluster_id writeback). It computes
//! token-Jaccard all-pairs over the entries the caller passes
//! (`store.list(agent)` filtered to active), builds connected components via
//! union-find, drops single-item components, and assigns a stable
//! `cl-{slug}-{batch_suffix}` id whose `entry_ids` target the SAME store
//! entries by id.

use std::collections::HashSet;

use crate::knowledge::MemoryEntry;

/// §2.10 `memory.l6.cluster_threshold`.
pub const DEFAULT_CLUSTER_THRESHOLD: f64 = 0.80;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClusterAssignment {
    /// `cl-{topic_slug}-{batch_id[..8]}`.
    pub cluster_id: String,
    /// Store entry ids (the writeback targets).
    pub entry_ids: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct L6ClusterBuilder {
    threshold: f64,
}

impl Default for L6ClusterBuilder {
    fn default() -> Self {
        Self {
            threshold: DEFAULT_CLUSTER_THRESHOLD,
        }
    }
}

impl L6ClusterBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_threshold(threshold: f64) -> Self {
        Self { threshold }
    }

    /// Pure compute. `entries` = the agent's active store entries. Edge (i,j)
    /// iff `jaccard(tokens_i, tokens_j) >= threshold`; connected components via
    /// union-find; single-item components dropped (§1.3.6 step 2). Each
    /// surviving component → one `ClusterAssignment`. Deterministic: component
    /// order follows the lowest member index; `entry_ids` preserve input
    /// order.
    pub fn build_clusters(
        &self,
        entries: &[MemoryEntry],
        batch_id: &str,
    ) -> Vec<ClusterAssignment> {
        let n = entries.len();
        if n < 2 {
            return Vec::new();
        }
        let tokens: Vec<HashSet<String>> = entries.iter().map(|e| tokenize(&e.content)).collect();

        let mut parent: Vec<usize> = (0..n).collect();
        for i in 0..n {
            for j in (i + 1)..n {
                if jaccard(&tokens[i], &tokens[j]) >= self.threshold {
                    union(&mut parent, i, j);
                }
            }
        }

        // Group members by root, preserving first-seen order of roots and
        // input order of members.
        let mut roots_in_order: Vec<usize> = Vec::new();
        let mut members: std::collections::HashMap<usize, Vec<usize>> =
            std::collections::HashMap::new();
        for i in 0..n {
            let r = find(&mut parent, i);
            if !members.contains_key(&r) {
                roots_in_order.push(r);
            }
            members.entry(r).or_default().push(i);
        }

        let suffix = batch_suffix(batch_id);
        let mut out = Vec::new();
        for r in roots_in_order {
            let idxs = &members[&r];
            if idxs.len() < 2 {
                continue; // drop single-item clusters
            }
            // Slug from the lexicographically-lowest-id member's tags.
            let low = idxs
                .iter()
                .min_by(|&&a, &&b| entries[a].id.cmp(&entries[b].id))
                .copied()
                .expect("non-empty component");
            let slug = topic_slug(&entries[low]);
            let cluster_id = format!("cl-{slug}-{suffix}");
            let entry_ids = idxs.iter().map(|&i| entries[i].id.clone()).collect();
            out.push(ClusterAssignment {
                cluster_id,
                entry_ids,
            });
        }
        out
    }
}

fn tokenize(s: &str) -> HashSet<String> {
    s.split_whitespace().map(|t| t.to_lowercase()).collect()
}

fn jaccard(a: &HashSet<String>, b: &HashSet<String>) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    let inter = a.intersection(b).count() as f64;
    let union = a.union(b).count() as f64;
    if union == 0.0 {
        0.0
    } else {
        inter / union
    }
}

fn find(parent: &mut [usize], mut x: usize) -> usize {
    while parent[x] != x {
        parent[x] = parent[parent[x]]; // path halving
        x = parent[x];
    }
    x
}

fn union(parent: &mut [usize], a: usize, b: usize) {
    let ra = find(parent, a);
    let rb = find(parent, b);
    if ra != rb {
        // Attach larger index under smaller for deterministic roots.
        let (lo, hi) = if ra < rb { (ra, rb) } else { (rb, ra) };
        parent[hi] = lo;
    }
}

/// First 8 chars of `batch_id` (hex from `UuidBatchIdSource`;
/// `FixedBatchIdSource` in tests). Padded defensively if shorter.
fn batch_suffix(batch_id: &str) -> String {
    let s: String = batch_id.chars().take(8).collect();
    if s.is_empty() {
        "00000000".to_string()
    } else {
        s
    }
}

/// Slug from the entry's first 1-3 tags joined with `-`, sanitized to
/// `[a-z0-9-]+`. Fallback to the fixed literal `topic` when no usable ASCII
/// slug can be derived (content is frequently non-ASCII per §1.3.2's CJK
/// examples — a deterministic ASCII fallback keeps the AC-34 regex
/// `^cl-[a-z0-9][a-z0-9-]*-[0-9a-f]{1,16}$` stable). Capped at 24 chars.
fn topic_slug(entry: &MemoryEntry) -> String {
    let joined = entry
        .tags
        .iter()
        .take(3)
        .cloned()
        .collect::<Vec<_>>()
        .join("-");
    let mut s = String::new();
    let mut prev_dash = false;
    for ch in joined.to_lowercase().chars() {
        if ch.is_ascii_alphanumeric() {
            s.push(ch);
            prev_dash = false;
        } else if !prev_dash && !s.is_empty() {
            s.push('-');
            prev_dash = true;
        }
    }
    while s.ends_with('-') {
        s.pop();
    }
    if s.len() > 24 {
        s.truncate(24);
        while s.ends_with('-') {
            s.pop();
        }
    }
    // Must start with [a-z0-9] for the AC-34 regex.
    if s.is_empty() || !s.chars().next().unwrap().is_ascii_alphanumeric() {
        "topic".to_string()
    } else {
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::knowledge::{MemoryStatus, MemoryType};

    fn e(id: &str, content: &str, tags: &[&str]) -> MemoryEntry {
        MemoryEntry {
            id: id.into(),
            agent_id: "a".into(),
            entry_type: MemoryType::Fact,
            content: content.into(),
            tags: tags.iter().map(|t| t.to_string()).collect(),
            created_at: "1970-01-01T00:00:00Z".into(),
            task_origin: None,
            is_active: true,
            superseded_by: None,
            status: MemoryStatus::Active,
            supersession_reason: None,
            cluster_id: None,
            sources: vec![],
        }
    }

    #[test]
    fn forms_one_cluster_from_high_overlap_facts() {
        let b = L6ClusterBuilder::new();
        let entries = vec![
            e("e1", "rust is memory safe and fast", &["pricing"]),
            e("e2", "rust is memory safe and fast", &["pricing"]),
            e("e3", "rust is memory safe and fast", &["pricing"]),
        ];
        let cl = b.build_clusters(&entries, "b0c1d2e3");
        assert_eq!(cl.len(), 1);
        assert_eq!(cl[0].entry_ids, vec!["e1", "e2", "e3"]);
        let re = regex_like(&cl[0].cluster_id);
        assert!(
            re,
            "cluster_id {} must match the AC-34 shape",
            cl[0].cluster_id
        );
        assert!(cl[0].cluster_id.ends_with("-b0c1d2e3"));
    }

    #[test]
    fn drops_single_item_clusters() {
        let b = L6ClusterBuilder::new();
        let entries = vec![
            e("e1", "completely unrelated alpha", &[]),
            e("e2", "totally different beta gamma", &[]),
        ];
        assert!(b.build_clusters(&entries, "deadbeef").is_empty());
    }

    #[test]
    fn empty_or_single_input_yields_no_clusters() {
        let b = L6ClusterBuilder::new();
        assert!(b.build_clusters(&[], "x").is_empty());
        assert!(b.build_clusters(&[e("e1", "solo", &[])], "x").is_empty());
    }

    #[test]
    fn non_ascii_tags_fall_back_to_topic_literal() {
        let b = L6ClusterBuilder::new();
        let entries = vec![
            e("e1", "shared content tokens here", &["竞品定价"]),
            e("e2", "shared content tokens here", &["竞品定价"]),
        ];
        let cl = b.build_clusters(&entries, "abcdef12");
        assert_eq!(cl.len(), 1);
        assert!(
            cl[0].cluster_id.starts_with("cl-topic-"),
            "got {}",
            cl[0].cluster_id
        );
        assert!(regex_like(&cl[0].cluster_id));
    }

    /// Mimics `^cl-[a-z0-9][a-z0-9-]*-[0-9a-f]{1,16}$` without a regex dep.
    fn regex_like(s: &str) -> bool {
        let rest = match s.strip_prefix("cl-") {
            Some(r) => r,
            None => return false,
        };
        let dash = match rest.rfind('-') {
            Some(d) => d,
            None => return false,
        };
        let slug = &rest[..dash];
        let suffix = &rest[dash + 1..];
        if slug.is_empty() || suffix.is_empty() || suffix.len() > 16 {
            return false;
        }
        let mut chars = slug.chars();
        let first = chars.next().unwrap();
        if !first.is_ascii_alphanumeric() {
            return false;
        }
        if !slug.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return false;
        }
        suffix
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    }
}

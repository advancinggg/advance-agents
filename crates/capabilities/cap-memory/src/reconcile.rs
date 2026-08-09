//! Memory reconciliation — MODULE-011 §1.3.7 + §11.5. Slice B implements the
//! deterministic 4-branch decision aligned with the §1.3.7 `MemoryAction`
//! algebra; the §1.3.7 LLM relation classifier (Supplement / Contradiction /
//! Duplicate trichotomy) is `waived_scope` and lands with a future slice that
//! wires `BatchExtractor` to MODULE-009.
//!
//! The `SimilarityIndex` trait is the dependency-injection seam — internal to
//! cap-memory, NOT promoted to shared-types. Production wiring will provide an
//! adapter against MODULE-004 CONTRACT-031 `Recall::memory_vec`; slice B ships
//! `InMemorySimilarityIndex` (Jaccard on token sets) for tests.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use crate::knowledge::{MemoryEntry, MemoryType, SupersessionReason};

/// Default similarity threshold — MODULE-011 §2.10
/// `memory.reconcile.similarity_threshold`.
pub const DEFAULT_THRESHOLD: f64 = 0.85;

/// Internal dependency-injection seam for the similarity-search step of fact
/// reconciliation. NOT in shared-types.
pub trait SimilarityIndex: Send + Sync {
    /// Return all entries whose similarity to `content` ≥ `threshold` (in
    /// production: dense-vector cosine via MODULE-004 `memory_vec`; in slice B
    /// tests: Jaccard on token sets). Caller filters; `find_similar` MUST NOT
    /// drop entries by `is_active` status — slice B's reconciler may want to
    /// see superseded predecessors. The slice B InMemorySimilarityIndex
    /// returns its seed entries verbatim when their token-Jaccard with
    /// `content` ≥ `threshold`.
    fn find_similar(&self, agent_id: &str, content: &str, threshold: f64) -> Vec<MemoryEntry>;
}

/// Reconciliation outcome aligned with MODULE-011 §1.3.7 `MemoryAction` shape.
/// The four AC-10 verbs (Insert / Skip / Supersede{Refinement} / Supersede{Merge})
/// are all reachable via the deterministic decision table below. There is NO
/// standalone `Merge` verb — "merge" maps to `Supersede { reason:
/// SupersessionReason::Merge }`.
///
/// `Supersede` carries the full `MemoryEntry` (not just `String` content) so
/// the reconciler preserves `tags` / `task_origin` / `sources` / `cluster_id`
/// / etc. through the action.
#[derive(Clone, Debug)]
pub enum MemoryAction {
    Insert(MemoryEntry),
    Supersede {
        old_id: String,
        new_entry: MemoryEntry,
        reason: SupersessionReason,
    },
    Skip,
}

pub struct Reconciler<S: SimilarityIndex + ?Sized> {
    index: Arc<S>,
    threshold: f64,
}

impl<S: SimilarityIndex + ?Sized + Send + Sync> Reconciler<S> {
    pub fn new(index: Arc<S>, threshold: f64) -> Self {
        Self { index, threshold }
    }

    /// Decide what mutation, if any, should apply for `entry`.
    /// Top-down first-match-wins decision table:
    /// 1. `entry_type == UserPreference` → `Insert` unconditionally (AC-11).
    /// 2. similar.is_empty() → `Insert(entry.clone())`.
    /// 3. similar[0].content == entry.content → `Skip` (duplicate).
    /// 4. similar.len() == 1 → `Supersede { reason: Refinement }`.
    /// 5. similar.len() >= 2 → `Supersede { reason: Merge }`.
    pub fn reconcile(&self, agent_id: &str, entry: &MemoryEntry) -> MemoryAction {
        if entry.entry_type == MemoryType::UserPreference {
            return MemoryAction::Insert(entry.clone());
        }
        let similar = self
            .index
            .find_similar(agent_id, &entry.content, self.threshold);
        if similar.is_empty() {
            return MemoryAction::Insert(entry.clone());
        }
        if similar[0].content == entry.content {
            return MemoryAction::Skip;
        }
        let reason = if similar.len() == 1 {
            SupersessionReason::Refinement
        } else {
            SupersessionReason::Merge
        };
        MemoryAction::Supersede {
            old_id: similar[0].id.clone(),
            new_entry: entry.clone(),
            reason,
        }
    }
}

/// Build the unsized-`S` form from a concrete impl. Helper exists because
/// `Arc<Reconciler<ConcreteIndex>>` does NOT auto-coerce to `Arc<Reconciler<dyn
/// SimilarityIndex + Send + Sync>>` (Rust's auto-Unsize rule for nominal
/// structs requires the type parameter in the LAST field only; Reconciler's
/// `index: Arc<S>` precedes `threshold: f64`). The helper erases at the inner
/// `Arc<S>` level (where Arc-to-dyn coercion IS permitted for `Sized` `S:
/// Trait`), then constructs a fresh outer `Reconciler`.
impl Reconciler<dyn SimilarityIndex + Send + Sync> {
    pub fn from_concrete<S: SimilarityIndex + Send + Sync + 'static>(
        index: Arc<S>,
        threshold: f64,
    ) -> Arc<Reconciler<dyn SimilarityIndex + Send + Sync>> {
        let erased: Arc<dyn SimilarityIndex + Send + Sync> = index;
        Arc::new(Reconciler {
            index: erased,
            threshold,
        })
    }
}

/// Test-side `SimilarityIndex` stub with Jaccard-on-tokens similarity.
/// Tokenization: lowercase + split on whitespace; sets compared by `|A ∩ B| /
/// |A ∪ B|`. Tracks a `call_count` for tests that want to assert the index was
/// or was not consulted (e.g. AC-11 user-preference branch skips the index).
pub struct InMemorySimilarityIndex {
    seed: Mutex<Vec<MemoryEntry>>,
    call_count: std::sync::atomic::AtomicU64,
}

impl InMemorySimilarityIndex {
    pub fn new() -> Self {
        Self {
            seed: Mutex::new(Vec::new()),
            call_count: std::sync::atomic::AtomicU64::new(0),
        }
    }

    pub fn add(&self, entry: MemoryEntry) {
        let mut guard = self
            .seed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.push(entry);
    }

    pub fn call_count(&self) -> u64 {
        self.call_count.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl Default for InMemorySimilarityIndex {
    fn default() -> Self {
        Self::new()
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

impl SimilarityIndex for InMemorySimilarityIndex {
    fn find_similar(&self, agent_id: &str, content: &str, threshold: f64) -> Vec<MemoryEntry> {
        self.call_count
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let guard = self
            .seed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let q = tokenize(content);
        guard
            .iter()
            .filter(|e| e.agent_id == agent_id)
            .filter(|e| jaccard(&q, &tokenize(&e.content)) >= threshold)
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::knowledge::{MemoryStatus, MemoryType};

    fn fact_entry(id: &str, content: &str) -> MemoryEntry {
        MemoryEntry {
            id: id.into(),
            agent_id: "agent".into(),
            entry_type: MemoryType::Fact,
            content: content.into(),
            tags: vec![],
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

    fn pref_entry(id: &str, content: &str) -> MemoryEntry {
        MemoryEntry {
            entry_type: MemoryType::UserPreference,
            ..fact_entry(id, content)
        }
    }

    #[test]
    fn user_preference_always_inserts() {
        let idx = Arc::new(InMemorySimilarityIndex::new());
        idx.add(pref_entry("p1", "I prefer concise"));
        let reconciler = Reconciler::new(idx.clone(), DEFAULT_THRESHOLD);
        let new = pref_entry("p2", "I prefer verbose");
        match reconciler.reconcile("agent", &new) {
            MemoryAction::Insert(e) => assert_eq!(e.id, "p2"),
            other => panic!("expected Insert, got {:?}", other),
        }
        assert_eq!(
            idx.call_count(),
            0,
            "find_similar must NOT be called for user-preference branch"
        );
    }

    #[test]
    fn empty_index_returns_insert() {
        let idx = Arc::new(InMemorySimilarityIndex::new());
        let reconciler = Reconciler::new(idx, DEFAULT_THRESHOLD);
        let new = fact_entry("f1", "Rust is memory-safe");
        assert!(matches!(
            reconciler.reconcile("agent", &new),
            MemoryAction::Insert(_)
        ));
    }

    #[test]
    fn identical_content_returns_skip() {
        let idx = Arc::new(InMemorySimilarityIndex::new());
        idx.add(fact_entry("f0", "Rust is memory-safe"));
        let reconciler = Reconciler::new(idx, DEFAULT_THRESHOLD);
        let new = fact_entry("f1", "Rust is memory-safe");
        assert!(matches!(
            reconciler.reconcile("agent", &new),
            MemoryAction::Skip
        ));
    }

    #[test]
    fn single_high_similarity_returns_supersede_refinement() {
        let idx = Arc::new(InMemorySimilarityIndex::new());
        idx.add(fact_entry("f0", "Rust is memory-safe"));
        let reconciler = Reconciler::new(idx, 0.5);
        let new = fact_entry("f1", "Rust is memory-safe and fast");
        match reconciler.reconcile("agent", &new) {
            MemoryAction::Supersede { old_id, reason, .. } => {
                assert_eq!(old_id, "f0");
                assert_eq!(reason, SupersessionReason::Refinement);
            }
            other => panic!("expected Supersede{{Refinement}}, got {:?}", other),
        }
    }

    #[test]
    fn multi_cluster_returns_supersede_merge() {
        let idx = Arc::new(InMemorySimilarityIndex::new());
        idx.add(fact_entry("f0", "Rust is fast"));
        idx.add(fact_entry("f1", "Rust runs fast"));
        let reconciler = Reconciler::new(idx, 0.3);
        let new = fact_entry("f2", "Rust is fast and safe");
        match reconciler.reconcile("agent", &new) {
            MemoryAction::Supersede { reason, .. } => {
                assert_eq!(reason, SupersessionReason::Merge);
            }
            other => panic!("expected Supersede{{Merge}}, got {:?}", other),
        }
    }

    #[test]
    fn agent_isolation() {
        let idx = Arc::new(InMemorySimilarityIndex::new());
        idx.add(fact_entry("f0", "Rust is memory-safe"));
        // Different agent — should be invisible to find_similar
        let reconciler = Reconciler::new(idx, DEFAULT_THRESHOLD);
        let mut other = fact_entry("f1", "Rust is memory-safe");
        other.agent_id = "agent:other".into();
        // For agent "other", index has no entries → Insert.
        assert!(matches!(
            reconciler.reconcile("agent:other", &other),
            MemoryAction::Insert(_)
        ));
    }

    #[test]
    fn from_concrete_builds_erased_reconciler() {
        let idx = Arc::new(InMemorySimilarityIndex::new());
        let erased: Arc<Reconciler<dyn SimilarityIndex + Send + Sync>> =
            Reconciler::from_concrete(idx, DEFAULT_THRESHOLD);
        let new = fact_entry("f1", "anything");
        // Just exercise the dispatch path:
        let _ = erased.reconcile("agent", &new);
    }
}

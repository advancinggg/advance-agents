//! L6 Step 1 — stale/freshness detection over `kind=file-ref` sources.
//! MODULE-011 §1.3.6 step 1 ("Stale detection (pure compute): check
//! `kind=file-ref` sources; mark valid/stale/partial"). Internal cap-memory
//! seam — production wires MODULE-002 file-presence; Slice C ships
//! `InMemoryStalenessProbe`.

use std::collections::HashSet;
use std::sync::Arc;

use crate::knowledge::{MemoryEntry, MemorySource};
use crate::store::MemoryStore;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StalenessJudgment {
    /// All file-ref sources resolve.
    Valid,
    /// No file-ref source resolves.
    Stale,
    /// Some file-ref sources resolve, others do not.
    PartialStale,
}

pub trait StalenessProbe: Send + Sync {
    /// Judge an entry's file-ref sources. Entries with NO file-ref source are
    /// never passed here (the caller skips them — task-turn-only entries can
    /// never go stale).
    fn judge(&self, sources: &[MemorySource]) -> StalenessJudgment;
}

/// Slice C stub: a file-ref `(agent_id, vpath, blob_id)` is "present" iff in
/// the seeded set. Production replaces this with a MODULE-002 blob lookup.
#[derive(Default)]
pub struct InMemoryStalenessProbe {
    present: HashSet<(String, String, String)>,
}

impl InMemoryStalenessProbe {
    pub fn new() -> Self {
        Self {
            present: HashSet::new(),
        }
    }

    pub fn mark_present(&mut self, agent_id: &str, vpath: &str, blob_id: &str) {
        self.present
            .insert((agent_id.to_string(), vpath.to_string(), blob_id.to_string()));
    }

    /// Builder form for tests.
    pub fn with_present(mut self, agent_id: &str, vpath: &str, blob_id: &str) -> Self {
        self.mark_present(agent_id, vpath, blob_id);
        self
    }
}

impl StalenessProbe for InMemoryStalenessProbe {
    fn judge(&self, sources: &[MemorySource]) -> StalenessJudgment {
        let mut total = 0usize;
        let mut resolved = 0usize;
        for s in sources {
            if let MemorySource::FileRef {
                agent_id,
                vpath,
                blob_id,
                ..
            } = s
            {
                total += 1;
                let key = (agent_id.clone(), vpath.clone(), blob_id.clone());
                if self.present.contains(&key) {
                    resolved += 1;
                }
            }
        }
        // `total == 0` cannot happen — the caller only invokes `judge` for
        // entries with ≥1 file-ref source. Defensive: treat as Valid.
        if total == 0 || resolved == total {
            StalenessJudgment::Valid
        } else if resolved == 0 {
            StalenessJudgment::Stale
        } else {
            StalenessJudgment::PartialStale
        }
    }
}

/// Production port (Wave-9 Lane B): resolve the CURRENT blob id that a file-ref's
/// `(agent_id, vpath)` resolves to in the live filesystem/git state. `None` ⇒ the
/// file no longer resolves (gone / outside territory / unreadable / resolver-policy
/// reject). The cli `GitBlobFileResolver` provides the git-blob-backed impl (resolve
/// `(agent_id, vpath)` → physical path via MODULE-002, then `advance_git::blob_oid_of_file`),
/// keeping cap-memory free of any git/fs dependency (acyclic crate graph — this port is
/// `&str`/`String` only).
pub trait FileBlobResolver: Send + Sync {
    fn current_blob(&self, agent_id: &str, vpath: &str) -> Option<String>;
}

/// Production [`StalenessProbe`]: judges a file-ref entry by comparing each file-ref
/// source's stored `blob_id` against the CURRENT blob the file resolves to (via the
/// injected MODULE-002/003 [`FileBlobResolver`]). A source "resolves" iff its stored
/// `blob_id` is NON-EMPTY and equals the resolver's current blob (same content);
/// `Valid` iff every file-ref source resolves, `Stale` iff none do, `PartialStale` on a
/// mix — the SAME control flow as [`InMemoryStalenessProbe::judge`], sourcing presence
/// from REAL on-disk/git state instead of a seeded set.
///
/// **Empty-blob short-circuit**: a source whose stored `blob_id` is empty is counted
/// not-resolved WITHOUT calling the resolver — an uncaptured/empty provenance can never
/// match a concrete blob, so this is byte-identical to the empty [`InMemoryStalenessProbe`]
/// (whose present-set never holds an empty-blob key) AND avoids a pointless resolve+hash.
/// The sole current production file-ref producer emits an empty `blob_id`, so the
/// production verdict (Stale → orphaned) and IO are unchanged until a future read-path
/// emits real blob_ids; the real resolve+hash path is exercised only by NON-EMPTY OIDs.
pub struct ResolverStalenessProbe {
    resolver: Arc<dyn FileBlobResolver>,
}

impl ResolverStalenessProbe {
    pub fn new(resolver: Arc<dyn FileBlobResolver>) -> Self {
        Self { resolver }
    }
}

impl StalenessProbe for ResolverStalenessProbe {
    fn judge(&self, sources: &[MemorySource]) -> StalenessJudgment {
        let mut total = 0usize;
        let mut resolved = 0usize;
        for s in sources {
            if let MemorySource::FileRef {
                agent_id,
                vpath,
                blob_id,
                ..
            } = s
            {
                total += 1;
                // An empty stored blob_id can never match a concrete current blob; count
                // it not-resolved WITHOUT a resolver call (byte-and-IO-identical to the
                // empty `InMemoryStalenessProbe` for the current empty-blob producer).
                if blob_id.is_empty() {
                    continue;
                }
                if self.resolver.current_blob(agent_id, vpath).as_deref() == Some(blob_id.as_str())
                {
                    resolved += 1;
                }
            }
        }
        // `total == 0` cannot happen — the caller only invokes `judge` for entries with
        // ≥1 file-ref source. Defensive: treat as Valid (mirrors InMemoryStalenessProbe).
        if total == 0 || resolved == total {
            StalenessJudgment::Valid
        } else if resolved == 0 {
            StalenessJudgment::Stale
        } else {
            StalenessJudgment::PartialStale
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StaleDetectionReport {
    pub stale_ids: Vec<String>,
    pub partial_stale_ids: Vec<String>,
    pub valid_ids: Vec<String>,
}

/// Per-run transient snapshot held by `L6Runnable.stale_state`
/// (`Arc<Mutex<StaleStateSnapshot>>`). Caches THIS run's `partial_stale_ids`
/// so Step 5c's `compute_health_snapshot(.., &partial_stale_ids, ..)` can
/// consume them. Reset to empty at the START of every `L6Runnable::handle`
/// so it is NEVER a cross-run freshness cache (AC-23 non-regression — L6
/// `Orphaned` status is the §1.3.2 persisted status machine, distinct from
/// AC-23's query-time freshness enum, which this slice does not introduce).
#[derive(Clone, Debug, Default)]
pub struct StaleStateSnapshot {
    pub partial_stale_ids: HashSet<String>,
}

/// Run Step 1 over an agent's active entries. Entries with no file-ref source
/// are skipped (never stale). Entries judged `Stale` are recorded in
/// `stale_ids` (the caller marks them `Orphaned` per §1.3.6 — "L6 stale
/// detection failed" → orphaned); `PartialStale` in `partial_stale_ids`.
pub fn run_stale_detection(
    store: &MemoryStore,
    agent_id: &str,
    probe: &dyn StalenessProbe,
) -> StaleDetectionReport {
    let mut report = StaleDetectionReport::default();
    for e in store.list(agent_id).iter().filter(|e| e.is_active) {
        let has_file_ref = e
            .sources
            .iter()
            .any(|s| matches!(s, MemorySource::FileRef { .. }));
        if !has_file_ref {
            continue;
        }
        match probe.judge(&e.sources) {
            StalenessJudgment::Valid => report.valid_ids.push(e.id.clone()),
            StalenessJudgment::Stale => report.stale_ids.push(e.id.clone()),
            StalenessJudgment::PartialStale => report.partial_stale_ids.push(e.id.clone()),
        }
    }
    report
}

#[allow(dead_code)]
fn _entry_is_active(e: &MemoryEntry) -> bool {
    e.is_active
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::knowledge::{MemoryEntry, MemoryStatus, MemoryType};

    fn file_ref(vpath: &str, blob: &str) -> MemorySource {
        MemorySource::FileRef {
            agent_id: "a".into(),
            vpath: vpath.into(),
            commit_ish: "c".into(),
            blob_id: blob.into(),
            line_range: None,
        }
    }

    fn entry(id: &str, sources: Vec<MemorySource>) -> MemoryEntry {
        MemoryEntry {
            id: id.into(),
            agent_id: "a".into(),
            entry_type: MemoryType::Fact,
            content: "x".into(),
            tags: vec![],
            created_at: "1970-01-01T00:00:00Z".into(),
            task_origin: None,
            is_active: true,
            superseded_by: None,
            status: MemoryStatus::Active,
            supersession_reason: None,
            cluster_id: None,
            sources,
        }
    }

    #[test]
    fn judge_valid_stale_partial() {
        let probe = InMemoryStalenessProbe::new().with_present("a", "p1", "b1");
        assert_eq!(
            probe.judge(&[file_ref("p1", "b1")]),
            StalenessJudgment::Valid
        );
        assert_eq!(
            probe.judge(&[file_ref("p2", "b2")]),
            StalenessJudgment::Stale
        );
        assert_eq!(
            probe.judge(&[file_ref("p1", "b1"), file_ref("p2", "b2")]),
            StalenessJudgment::PartialStale
        );
    }

    #[test]
    fn run_skips_task_turn_only_and_classifies_file_ref() {
        let store = MemoryStore::new();
        store
            .insert(
                "a",
                entry(
                    "t",
                    vec![MemorySource::TaskTurn {
                        task_id: "t1".into(),
                        turn: 1,
                    }],
                ),
            )
            .unwrap();
        store
            .insert("a", entry("v", vec![file_ref("p1", "b1")]))
            .unwrap();
        store
            .insert("a", entry("s", vec![file_ref("gone", "b9")]))
            .unwrap();
        let probe = InMemoryStalenessProbe::new().with_present("a", "p1", "b1");
        let r = run_stale_detection(&store, "a", &probe);
        assert_eq!(r.valid_ids, vec!["v".to_string()]);
        assert_eq!(r.stale_ids, vec!["s".to_string()]);
        assert!(r.partial_stale_ids.is_empty());
        // "t" (task-turn only) skipped entirely.
        assert!(!r.valid_ids.contains(&"t".to_string()));
    }

    // ─────────── Wave-9 Lane B: ResolverStalenessProbe (W1/W1b/W2) ───────────

    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Fake [`FileBlobResolver`]: returns a canned current-blob per (agent_id, vpath)
    /// and COUNTS calls so W1b can assert the empty-blob short-circuit skips it.
    #[derive(Default)]
    struct FakeResolver {
        present: HashMap<(String, String), String>,
        calls: AtomicUsize,
    }
    impl FakeResolver {
        fn with(mut self, agent: &str, vpath: &str, blob: &str) -> Self {
            self.present
                .insert((agent.to_string(), vpath.to_string()), blob.to_string());
            self
        }
        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }
    impl FileBlobResolver for FakeResolver {
        fn current_blob(&self, agent_id: &str, vpath: &str) -> Option<String> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.present
                .get(&(agent_id.to_string(), vpath.to_string()))
                .cloned()
        }
    }

    // W1: judge Valid (current blob matches) / Stale (gone = resolver None) /
    // Stale (superseded = resolver returns a DIFFERENT blob) / PartialStale (mix).
    #[test]
    fn resolver_probe_judges_valid_stale_superseded_partial() {
        // p1→b1 present (matches), p3→DIFFERENT (superseded), p2 absent (gone).
        let probe = ResolverStalenessProbe::new(Arc::new(
            FakeResolver::default()
                .with("a", "p1", "b1")
                .with("a", "p3", "DIFFERENT"),
        ));
        // Valid: the file resolves to the stored blob.
        assert_eq!(
            probe.judge(&[file_ref("p1", "b1")]),
            StalenessJudgment::Valid
        );
        // Stale: the file is gone (resolver None).
        assert_eq!(
            probe.judge(&[file_ref("p2", "b2")]),
            StalenessJudgment::Stale
        );
        // Stale: the file resolves to a DIFFERENT blob (superseded content).
        assert_eq!(
            probe.judge(&[file_ref("p3", "b3")]),
            StalenessJudgment::Stale
        );
        // PartialStale: one resolves, one is gone.
        assert_eq!(
            probe.judge(&[file_ref("p1", "b1"), file_ref("p2", "b2")]),
            StalenessJudgment::PartialStale
        );
    }

    // W1b: an EMPTY stored blob_id is judged not-resolved (Stale) WITHOUT a resolver
    // call, AND is byte-identical to the empty `InMemoryStalenessProbe` verdict.
    #[test]
    fn resolver_probe_empty_blob_short_circuits_and_matches_inmemory_stub() {
        let fake = Arc::new(FakeResolver::default());
        let probe = ResolverStalenessProbe::new(fake.clone());
        // file_ref with an EMPTY blob_id (the shape the current production producer emits).
        assert_eq!(probe.judge(&[file_ref("p", "")]), StalenessJudgment::Stale);
        assert_eq!(fake.calls(), 0, "empty blob_id must NOT call the resolver");
        // Verdict is byte-identical to the empty InMemoryStalenessProbe.
        let stub = InMemoryStalenessProbe::new();
        assert_eq!(stub.judge(&[file_ref("p", "")]), StalenessJudgment::Stale);
    }

    // W2: the discriminator — the SAME file-ref entry is Stale under the empty
    // `InMemoryStalenessProbe` (today's wiring) but Valid under a matching
    // `ResolverStalenessProbe` (the production wiring). This is exactly the
    // orphaned-vs-synthesis-eligible flip the lane builds.
    #[test]
    fn discriminator_empty_stub_stale_vs_real_probe_valid() {
        let src = [file_ref("p1", "b1")];
        // Today: empty stub → Stale → (caller marks) Orphaned → excluded from synthesis.
        let empty = InMemoryStalenessProbe::new();
        assert_eq!(empty.judge(&src), StalenessJudgment::Stale);
        // Wave-9 Lane B: real probe whose resolver reports the matching blob → Valid.
        let real =
            ResolverStalenessProbe::new(Arc::new(FakeResolver::default().with("a", "p1", "b1")));
        assert_eq!(real.judge(&src), StalenessJudgment::Valid);
    }
}

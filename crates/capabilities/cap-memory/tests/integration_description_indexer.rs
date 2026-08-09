//! Integration tests for slice satD-vlm (SAT-D): the Step-3 `DescriptionIndexer`
//! seam + store-routing (the cap-memory half of the VLM bridge). The cli
//! `VlmDescriptionIndexer` adapter (MIME routing + `.meta.yaml` writeback) is
//! tested in `crates/cli`. Here a FAKE `DescriptionIndexer` exercises Step-3's
//! contract: it iterates `extraction.descriptions[].path`, calls the seam with
//! the BARE write id, and routes `Some(IndexedDescription)` into the STORE as a
//! `FileRef`-sourced entry so `MemoryStore::recall` surfaces it (SYS-AC-073
//! mechanics, witnessed via real recall — NOT a `memory_index` `!is_empty`).
//!
//! satD-U1 — seam called + description recall-able (073).
//! satD-U2 — `description_indexer: None` ⇒ Step-3 no-op (back-compat / AC-44).
//! satD-U3 — binary (`None`) ⇒ no entry; two DISTINCT paths ⇒ two entries
//!           (no distinct-file suppression; the guard is (vpath,content)-keyed).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use advance_shared_types::mailbox::{ActionResult, Message, MessageKind};
use advance_shared_types::memory::PostProcessorHook;
use async_trait::async_trait;
use cap_memory::post_processor::CANONICAL_STEPS;
use cap_memory::{
    Components, DescriptionIndexer, DescriptionUpdate, Extraction, FailureCooldown,
    InMemorySimilarityIndex, IndexedDescription, MemorySource, MemoryStore, MutableClock,
    PostProcessor, Reconciler, StubBatchExtractor, DEFAULT_THRESHOLD,
};

/// Fake seam: records each `(agent_id, path)` call and returns the configured
/// response for that path (`None` ⇒ "binary / not indexable").
struct FakeIndexer {
    calls: Arc<Mutex<Vec<(String, String)>>>,
    responses: HashMap<String, IndexedDescription>,
}

#[async_trait]
impl DescriptionIndexer for FakeIndexer {
    async fn index_description(&self, agent_id: &str, path: &str) -> Option<IndexedDescription> {
        self.calls
            .lock()
            .unwrap()
            .push((agent_id.to_string(), path.to_string()));
        self.responses.get(path).cloned()
    }
}

fn message() -> Message {
    Message {
        id: "msg-1".into(),
        kind: MessageKind::User,
        from: "user".into(),
        to: "agent".into(),
        payload: vec![],
        context: None,
        timestamp: SystemTime::UNIX_EPOCH,
        origin: None,
    }
}

fn result() -> ActionResult {
    ActionResult {
        new_state: vec![],
        actions: vec![],
    }
}

/// Build `Components` whose Step-2 extractor yields exactly `descriptions`
/// (empty knowledge), optionally attaching a `DescriptionIndexer` seam.
fn components_with(
    store: Arc<MemoryStore>,
    descriptions: Vec<DescriptionUpdate>,
    indexer: Option<Arc<FakeIndexer>>,
) -> Components {
    let extraction = Extraction {
        descriptions,
        knowledge: vec![],
        digest: None,
    };
    let extractor = Arc::new(StubBatchExtractor::with_extraction(extraction));
    let similarity = Arc::new(InMemorySimilarityIndex::new());
    let reconciler = Reconciler::from_concrete(similarity, DEFAULT_THRESHOLD);
    let cooldown = Arc::new(FailureCooldown::new(600));
    let clock = Arc::new(MutableClock::new(SystemTime::UNIX_EPOCH));
    let c = Components::with_l6_defaults(extractor, reconciler, store, cooldown, clock);
    match indexer {
        Some(i) => c.with_description_indexer(i),
        None => c,
    }
}

fn desc(path: &str) -> DescriptionUpdate {
    DescriptionUpdate {
        path: path.into(),
        // The stub text the LLM extraction produced; Step-3 uses the SEAM's
        // (re-derived) description, not this field.
        description: "stub".into(),
    }
}

fn indexed(vpath: &str, description: &str) -> IndexedDescription {
    IndexedDescription {
        vpath: vpath.into(),
        description: description.into(),
    }
}

/// satD-U1 — the seam is called with the bare write id + each changed path, and
/// its returned description lands in the STORE recall-able by content, carrying
/// a `FileRef` source for the normalized vpath.
#[tokio::test]
async fn sat_d_u1_seam_routes_description_into_store_recall() {
    let store = Arc::new(MemoryStore::new());
    let calls = Arc::new(Mutex::new(Vec::new()));
    let mut responses = HashMap::new();
    responses.insert(
        "pic.png".to_string(),
        indexed("pic.png", "flowchart diagram of the auth subsystem"),
    );
    let fake = Arc::new(FakeIndexer {
        calls: Arc::clone(&calls),
        responses,
    });
    let components = components_with(Arc::clone(&store), vec![desc("pic.png")], Some(fake));
    let pp = PostProcessor::with_components(components);

    pp.run("agent-x", &message(), &result())
        .await
        .expect("run Ok");

    // The seam was called once with (write_id == "agent-x", "pic.png").
    assert_eq!(
        *calls.lock().unwrap(),
        vec![("agent-x".to_string(), "pic.png".to_string())]
    );

    // 073: recall by a description substring returns the file entry.
    let hits = store.recall("agent-x", "flowchart", 0);
    assert_eq!(hits.len(), 1, "description recall-able via content");
    assert_eq!(hits[0].content, "flowchart diagram of the auth subsystem");
    // The entry carries a FileRef source for the normalized vpath.
    assert!(
        hits[0].sources.iter().any(|s| matches!(
            s,
            MemorySource::FileRef { vpath, .. } if vpath == "pic.png"
        )),
        "entry has a FileRef source with vpath == pic.png"
    );
}

/// satD-U2 — with NO seam attached, Step-3 is a documented no-op: nothing is
/// written to the store and the canonical 9-step trace is preserved (AC-44 /
/// AC-08 back-compat).
#[tokio::test]
async fn sat_d_u2_no_indexer_is_noop() {
    let store = Arc::new(MemoryStore::new());
    let components = components_with(Arc::clone(&store), vec![desc("pic.png")], None);
    let pp = PostProcessor::with_components(components);

    pp.run("agent-x", &message(), &result())
        .await
        .expect("run Ok");

    // No Step-3 store write.
    assert!(
        store.recall("agent-x", "", 0).is_empty(),
        "no entry written when description_indexer is None"
    );
    // Canonical 9-step trace preserved.
    assert_eq!(
        pp.trace_snapshot(),
        CANONICAL_STEPS
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
    );
}

/// satD-U3 — a `None` seam result (binary / not indexable) writes no entry; two
/// DISTINCT paths each produce their own entry (the (vpath,content)-keyed guard
/// does not suppress a distinct file even when descriptions are similar).
#[tokio::test]
async fn sat_d_u3_binary_skipped_distinct_paths_each_indexed() {
    let store = Arc::new(MemoryStore::new());
    let calls = Arc::new(Mutex::new(Vec::new()));
    let mut responses = HashMap::new();
    // a.png → indexable; blob.bin → None (binary); c.png → indexable (distinct
    // vpath, same description text as a.png on purpose — must NOT be suppressed).
    responses.insert("a.png".to_string(), indexed("a.png", "a blue diagram"));
    responses.insert("c.png".to_string(), indexed("c.png", "a blue diagram"));
    let fake = Arc::new(FakeIndexer {
        calls: Arc::clone(&calls),
        responses,
    });
    let components = components_with(
        Arc::clone(&store),
        vec![desc("a.png"), desc("blob.bin"), desc("c.png")],
        Some(fake),
    );
    let pp = PostProcessor::with_components(components);

    pp.run("agent-x", &message(), &result())
        .await
        .expect("run Ok");

    // The seam was consulted for all three paths.
    assert_eq!(calls.lock().unwrap().len(), 3);

    // blob.bin → None → no entry; a.png + c.png → two entries (distinct vpaths,
    // not collapsed despite identical content).
    let hits = store.recall("agent-x", "blue diagram", 0);
    assert_eq!(hits.len(), 2, "two distinct files each indexed");
    let mut vpaths: Vec<String> = hits
        .iter()
        .flat_map(|e| {
            e.sources.iter().filter_map(|s| match s {
                MemorySource::FileRef { vpath, .. } => Some(vpath.clone()),
                _ => None,
            })
        })
        .collect();
    vpaths.sort();
    assert_eq!(vpaths, vec!["a.png".to_string(), "c.png".to_string()]);
}

/// satD-U4 — re-indexing the SAME file with the SAME description across turns is
/// idempotent: the `(vpath,content)` guard skips the second insert so the store
/// holds exactly ONE active entry (the POSITIVE dedup branch — U3 covers only
/// its negation, distinct files sharing a description).
#[tokio::test]
async fn sat_d_u4_reindex_same_file_is_idempotent() {
    let store = Arc::new(MemoryStore::new());
    // Two separate post-processor turns over the SAME shared store; the seam
    // returns the same IndexedDescription for "pic.png" each turn.
    for _ in 0..2 {
        let mut responses = HashMap::new();
        responses.insert(
            "pic.png".to_string(),
            indexed("pic.png", "a stable diagram"),
        );
        let fake = Arc::new(FakeIndexer {
            calls: Arc::new(Mutex::new(Vec::new())),
            responses,
        });
        let components = components_with(Arc::clone(&store), vec![desc("pic.png")], Some(fake));
        let pp = PostProcessor::with_components(components);
        pp.run("agent-x", &message(), &result())
            .await
            .expect("run Ok");
    }
    // Re-indexed twice → exactly ONE active entry (dedup guard hit on turn 2).
    let hits = store.recall("agent-x", "stable diagram", 0);
    assert_eq!(
        hits.len(),
        1,
        "re-indexing the same (vpath,content) does not duplicate"
    );
}

/// satD-U5 — Step-3 caps the per-turn description fan-out (DoS bound). An
/// LLM-produced extraction with MORE than `MAX_INDEXED_DESCRIPTIONS_PER_TURN`
/// entries indexes at most the cap; the seam is never called for the excess.
#[tokio::test]
async fn sat_d_u5_caps_descriptions_per_turn() {
    use cap_memory::post_processor::MAX_INDEXED_DESCRIPTIONS_PER_TURN;

    let store = Arc::new(MemoryStore::new());
    let n = MAX_INDEXED_DESCRIPTIONS_PER_TURN + 10;
    let mut responses = HashMap::new();
    let descs: Vec<DescriptionUpdate> = (0..n)
        .map(|i| {
            let path = format!("f{i}.png");
            responses.insert(
                path.clone(),
                indexed(&path, &format!("description number {i}")),
            );
            desc(&path)
        })
        .collect();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let fake = Arc::new(FakeIndexer {
        calls: Arc::clone(&calls),
        responses,
    });
    let components = components_with(Arc::clone(&store), descs, Some(fake));
    let pp = PostProcessor::with_components(components);

    pp.run("agent-x", &message(), &result())
        .await
        .expect("run Ok");

    // The seam is consulted at most the cap (excess skipped BEFORE the call).
    assert_eq!(
        calls.lock().unwrap().len(),
        MAX_INDEXED_DESCRIPTIONS_PER_TURN,
        "per-turn description fan-out is capped"
    );
}

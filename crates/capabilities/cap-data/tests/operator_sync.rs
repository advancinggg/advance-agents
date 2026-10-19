//! C5 `sync_path_with` (OSS-5.md `operator_sync.rs`).

use std::sync::Arc;

use advance_shared_types::entity::{EntityId, EntityIndex, EntityQuery, EntityRow};
use cap_data::test_support::{
    agenda_schema, DirWorkspaceFs, FixedClock, MemoryEntityIndex, RecordingEvents, SequentialIds,
};
use cap_data::DataStore;

const ENTITY_CHANGED_EVENT: &str = "data.entity_changed";

const NOW: &str = "2026-09-17T08:00:00Z";
const USER_DOC: &str =
    "---\nid: e-01J9K3ZQ7A00000000000001\ntype: project\ntitle: User\n---\nuser\n";
const AGENT_DOC: &str =
    "---\nid: e-01J9K3ZQ7A00000000000001\ntype: project\ntitle: Agent\n---\nagent\n";
const NFD_DOC: &str = "---\nid: e-01J9K3ZQ7A00000000000002\ntype: project\ntitle: Cafe\n---\nnfc\n";
const ORIG_DOC: &str =
    "---\nid: e-01J9K3ZQ7A00000000000003\ntype: project\ntitle: Original\n---\norig\n";
const COPY_DOC: &str =
    "---\nid: e-01J9K3ZQ7A00000000000003\ntype: project\ntitle: Copy\n---\ncopy\n";
const CHILD_DOC: &str =
    "---\nid: e-01J9K3ZQ7A00000000000004\ntype: project\ntitle: Child\n---\nchild\n";

fn open(ws: &tempfile::TempDir) -> (DataStore, Arc<MemoryEntityIndex>, Arc<RecordingEvents>) {
    let events = Arc::new(RecordingEvents::default());
    let index = Arc::new(MemoryEntityIndex::default());
    let store = DataStore::new(
        Arc::new(DirWorkspaceFs::new(ws.path().to_path_buf())),
        index.clone(),
        agenda_schema(),
        Arc::new(SequentialIds::default()),
        Arc::new(FixedClock::at(NOW)),
    )
    .with_events(events.clone());
    (store, index, events)
}

async fn rows_for(index: &MemoryEntityIndex, agent: &str) -> Vec<EntityRow> {
    index.query(&EntityQuery::for_agent(agent)).await.unwrap()
}

#[tokio::test]
async fn user_then_agent_write_index_matches_disk() {
    let ws = tempfile::TempDir::new().unwrap();
    std::fs::write(ws.path().join("note.md"), USER_DOC).unwrap();
    let (store, index, _) = open(&ws);
    store
        .sync_path_with("alice", "note.md", "user:advance", "user_write", || {
            Some(USER_DOC.as_bytes().to_vec())
        })
        .await;
    std::fs::write(ws.path().join("note.md"), AGENT_DOC).unwrap();
    store.sync_path("alice", "note.md").await;
    let rows = rows_for(&index, "alice").await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].title.as_deref(), Some("Agent"));
    assert_eq!(
        std::fs::read_to_string(ws.path().join("note.md")).unwrap(),
        AGENT_DOC
    );
}

#[tokio::test]
async fn nfd_markdown_seed_and_user_edit_single_row() {
    let ws = tempfile::TempDir::new().unwrap();
    let nfc = "caf\u{00e9}.md";
    let nfd = "cafe\u{0301}.md";
    std::fs::write(ws.path().join(nfc), NFD_DOC).unwrap();
    let (store, index, _) = open(&ws);
    store
        .sync_path_with("alice", nfd, "user:advance", "user_write", || {
            Some(NFD_DOC.as_bytes().to_vec())
        })
        .await;
    store
        .sync_path_with("alice", nfc, "user:advance", "user_write", || {
            Some(NFD_DOC.as_bytes().to_vec())
        })
        .await;
    let rows = rows_for(&index, "alice").await;
    assert_eq!(rows.len(), 1, "NFC+NFD collapse to one row: {rows:?}");
    assert_eq!(rows[0].path, nfc);
}

#[tokio::test]
async fn duplicate_id_copy_keeps_original_row() {
    let ws = tempfile::TempDir::new().unwrap();
    std::fs::write(ws.path().join("orig.md"), ORIG_DOC).unwrap();
    std::fs::write(ws.path().join("copy.md"), COPY_DOC).unwrap();
    let (store, index, events) = open(&ws);
    store
        .sync_path_with("alice", "orig.md", "user:advance", "user_write", || {
            Some(ORIG_DOC.as_bytes().to_vec())
        })
        .await;
    store
        .sync_path_with("alice", "copy.md", "user:advance", "user_write", || {
            Some(COPY_DOC.as_bytes().to_vec())
        })
        .await;
    let id = EntityId("e-01J9K3ZQ7A00000000000003".into());
    let kept = index
        .get("alice", &id)
        .await
        .unwrap()
        .expect("original row");
    assert_eq!(kept.path, "orig.md");
    assert_eq!(kept.title.as_deref(), Some("Original"));
    let ev = events.snapshot();
    assert!(
        ev.iter()
            .any(|e| e.event_type == "runtime.degraded.entity_duplicate_id"),
        "duplicate id must degrade, not steal: {ev:?}"
    );
}

#[tokio::test]
async fn child_territory_edit_syncs_owner_rows() {
    let ws = tempfile::TempDir::new().unwrap();
    let child = ws.path().join(".agent").join("child");
    std::fs::create_dir_all(&child).unwrap();
    std::fs::write(child.join("task.md"), CHILD_DOC).unwrap();
    let (store, index, events) = open(&ws);
    store
        .sync_path_with(
            "alice",
            ".agent/child/task.md",
            "user:advance",
            "user_write",
            || Some(CHILD_DOC.as_bytes().to_vec()),
        )
        .await;
    let rows = rows_for(&index, "alice").await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].path, ".agent/child/task.md");
    assert_eq!(rows[0].agent_id, "alice");
    let changed: Vec<_> = events
        .snapshot()
        .into_iter()
        .filter(|e| e.event_type == ENTITY_CHANGED_EVENT)
        .collect();
    assert_eq!(changed.len(), 1);
    assert_eq!(changed[0].agent_id, "user:advance");
    assert_eq!(changed[0].payload["op"], "user_write");
}

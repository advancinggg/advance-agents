#![cfg(feature = "lane-e1")]
//! Lane E1 — `DataStore` operations over a temp workspace.
//! Contract draft: signatures per the plan; the in-memory `EntityIndex` + a plain-directory
//! `WorkspaceFs` are the test doubles the crate ships under `test-support`.

use std::sync::Arc;

use advance_shared_types::entity::{EntityId, EntityQuery};
use cap_data::test_support::{DirWorkspaceFs, MemoryEntityIndex, SequentialIds};
use cap_data::{DataError, DataStore, PatchOp, Record, Target, Tier};
use serde_json::json;

const PROJECT: &str = "---\nid: e-01J9K3ZQ7A00000000000000\ntype: project\ntitle: Launch\nassignee: agent:alice\n---\n# Launch\n\nprose stays untouched\n";

fn store(ws: &tempfile::TempDir) -> DataStore {
    std::fs::write(ws.path().join("launch.md"), PROJECT).unwrap();
    DataStore::new(
        Arc::new(DirWorkspaceFs::new(ws.path().to_path_buf())),
        Arc::new(MemoryEntityIndex::default()),
        cap_data::test_support::schema_with_aspects(),
        Arc::new(SequentialIds::default()),
    )
}

#[tokio::test]
async fn e1_create_inline_item_assigns_id_and_keeps_body_bytes() {
    let ws = tempfile::TempDir::new().unwrap();
    let s = store(&ws);
    let id = s
        .create(
            "alice",
            Target::Path("launch.md".into()),
            Record::from_json(json!({ "type": "work-item", "title": "完成 SDK 再生成", "status": "todo", "due": "2026-09-20T18:00:00+08:00" })),
        )
        .await
        .expect("create");
    assert!(id.0.starts_with("e-"), "{id:?}");
    let text = std::fs::read_to_string(ws.path().join("launch.md")).unwrap();
    assert!(
        text.ends_with("# Launch\n\nprose stays untouched\n"),
        "body bytes preserved"
    );
    assert!(
        text.contains("items:\n"),
        "inline item written into frontmatter: {text}"
    );
    let row = s
        .get(
            "alice",
            Target::Anchored {
                path: "launch.md".into(),
                id: id.clone(),
            },
        )
        .await
        .unwrap();
    assert_eq!(row.status.as_deref(), Some("todo"));
    assert_eq!(
        row.fields["assignee"],
        json!("agent:alice"),
        "inherited from the parent file (effective value)"
    );
}

#[tokio::test]
async fn e1_patch_is_field_level_and_canonical() {
    let ws = tempfile::TempDir::new().unwrap();
    let s = store(&ws);
    let id = s
        .create(
            "alice",
            Target::Path("launch.md".into()),
            Record::from_json(json!({ "type": "work-item", "title": "t", "status": "todo" })),
        )
        .await
        .unwrap();
    let target = Target::Anchored {
        path: "launch.md".into(),
        id: id.clone(),
    };
    s.patch(
        "alice",
        target.clone(),
        vec![PatchOp::Set("status".into(), json!("done"))],
    )
    .await
    .unwrap();
    let once = std::fs::read_to_string(ws.path().join("launch.md")).unwrap();
    // Patching an unrelated field again must not reorder or reformat anything else.
    s.patch(
        "alice",
        target.clone(),
        vec![PatchOp::Set("priority".into(), json!(2))],
    )
    .await
    .unwrap();
    let twice = std::fs::read_to_string(ws.path().join("launch.md")).unwrap();
    assert_eq!(
        once.replace("status: done\n", "status: done\n    priority: 2\n")
            .len(),
        twice.len()
    );
    // Schema violation is fail-closed and leaves the file untouched.
    let err = s
        .patch(
            "alice",
            target,
            vec![PatchOp::Set("priority".into(), json!("high"))],
        )
        .await
        .unwrap_err();
    assert!(matches!(err, DataError::Invalid(_)), "{err:?}");
    assert_eq!(
        std::fs::read_to_string(ws.path().join("launch.md")).unwrap(),
        twice
    );
}

#[tokio::test]
async fn e1_items_cap_forces_promotion() {
    let ws = tempfile::TempDir::new().unwrap();
    let s = store(&ws);
    for i in 0..cap_data::MAX_ITEMS_PER_FILE {
        s.create(
            "alice",
            Target::Path("launch.md".into()),
            Record::from_json(
                json!({ "type": "work-item", "title": format!("t{i}"), "status": "todo" }),
            ),
        )
        .await
        .unwrap();
    }
    let err = s
        .create(
            "alice",
            Target::Path("launch.md".into()),
            Record::from_json(
                json!({ "type": "work-item", "title": "one too many", "status": "todo" }),
            ),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, DataError::PromoteRequired { .. }), "{err:?}");
}

#[tokio::test]
async fn e1_promote_and_demote_keep_id_and_move_index_path() {
    let ws = tempfile::TempDir::new().unwrap();
    let s = store(&ws);
    let id = s
        .create(
            "alice",
            Target::Path("launch.md".into()),
            Record::from_json(
                json!({ "type": "work-item", "title": "法务对齐", "status": "doing" }),
            ),
        )
        .await
        .unwrap();
    let file = s
        .promote(
            "alice",
            Target::Anchored {
                path: "launch.md".into(),
                id: id.clone(),
            },
            Tier::File,
        )
        .await
        .expect("promote to file");
    let Target::Path(path) = &file else {
        panic!("expected a file target, got {file:?}")
    };
    assert!(ws.path().join(path).is_file());
    let parent = std::fs::read_to_string(ws.path().join("launch.md")).unwrap();
    assert!(
        parent.contains(&format!("id: {}\n", id.0)) && parent.contains("ref: "),
        "parent keeps a ref: {parent}"
    );
    let row = s.get("alice", file.clone()).await.unwrap();
    assert_eq!(row.id, id, "identity survives promotion");
    assert_eq!(row.path, *path);

    let back = s.demote("alice", file).await.expect("demote");
    assert!(matches!(back, Target::Anchored { .. }));
    assert!(!ws.path().join(path).exists());
    assert_eq!(s.get("alice", back).await.unwrap().id, id);
}

#[tokio::test]
async fn e1_query_by_aspect_and_due_window() {
    let ws = tempfile::TempDir::new().unwrap();
    let s = store(&ws);
    s.create("alice", Target::Path("launch.md".into()), Record::from_json(json!({ "type": "work-item", "title": "soon", "status": "todo", "due": "2026-09-20T00:00:00Z" }))).await.unwrap();
    s.create("alice", Target::Path("launch.md".into()), Record::from_json(json!({ "type": "work-item", "title": "later", "status": "todo", "due": "2026-12-01T00:00:00Z" }))).await.unwrap();
    s.create("alice", Target::Path("launch.md".into()), Record::from_json(json!({ "type": "event", "title": "meeting", "starts": "2026-09-22T02:00:00Z", "ends": "2026-09-22T03:00:00Z" }))).await.unwrap();
    let mut q = EntityQuery::for_agent("alice");
    q.aspect = Some("completion".into());
    q.due_between = Some((
        "2026-09-01T00:00:00Z".parse().unwrap(),
        "2026-10-01T00:00:00Z".parse().unwrap(),
    ));
    let rows = s.query(q).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].title.as_deref(), Some("soon"));
    let mut q = EntityQuery::for_agent("alice");
    q.aspect = Some("schedule".into());
    assert_eq!(s.query(q).await.unwrap().len(), 1);
}

#[tokio::test]
async fn e1_history_walks_the_record_not_the_file() {
    let ws = tempfile::TempDir::new().unwrap();
    let s = store(&ws);
    let id = s
        .create(
            "alice",
            Target::Path("launch.md".into()),
            Record::from_json(json!({ "type": "work-item", "title": "t", "status": "todo" })),
        )
        .await
        .unwrap();
    let target = Target::Anchored {
        path: "launch.md".into(),
        id: id.clone(),
    };
    s.patch(
        "alice",
        target.clone(),
        vec![PatchOp::Set("status".into(), json!("doing"))],
    )
    .await
    .unwrap();
    s.patch(
        "alice",
        target.clone(),
        vec![PatchOp::Set("status".into(), json!("done"))],
    )
    .await
    .unwrap();
    let versions = s.history("alice", target, 10).await.unwrap();
    let statuses: Vec<_> = versions
        .iter()
        .map(|v| v.record["status"].as_str().unwrap_or("").to_string())
        .collect();
    assert_eq!(
        statuses,
        vec!["done", "doing", "todo"],
        "newest first, one entry per change of THIS record"
    );
    let _ = EntityId("e-x".into());
}

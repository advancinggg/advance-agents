#![cfg(feature = "lane-e1")]
//! Lane E1 — `SqliteEntityIndex` over the workspace index DB.

use std::sync::Arc;

use advance_database::{R2d2SqliteIndexHandle, SqliteEntityIndex, SqliteIndexHandle};
use advance_shared_types::entity::{EntityId, EntityIndex, EntityKind, EntityQuery, EntityRow};
use chrono::{DateTime, Utc};

fn ts(s: &str) -> DateTime<Utc> {
    s.parse().unwrap()
}

fn row(id: &str, path: &str, anchor: Option<&str>, kind: EntityKind) -> EntityRow {
    EntityRow {
        id: EntityId(id.into()),
        agent_id: "alice".into(),
        path: path.into(),
        anchor: anchor.map(|a| EntityId(a.into())),
        parent: None,
        kind,
        r#type: "work-item".into(),
        title: Some(id.into()),
        status: Some("todo".into()),
        due_at: None,
        starts_at: None,
        ends_at: None,
        priority: None,
        fields: serde_json::json!({}),
        updated_at: ts("2026-09-16T00:00:00Z"),
    }
}

async fn index() -> (tempfile::TempDir, SqliteEntityIndex) {
    let tmp = tempfile::TempDir::new().unwrap();
    let handle = R2d2SqliteIndexHandle::open(tmp.path().join("index.sqlite"), 2).expect("open");
    handle
        .run_migrations()
        .expect("migrations incl. entity tables");
    let idx = SqliteEntityIndex::new(Arc::new(handle) as Arc<dyn SqliteIndexHandle>);
    (tmp, idx)
}

#[tokio::test]
async fn e1_replace_path_is_whole_path_replacement() {
    let (_t, idx) = index().await;
    idx.replace_path(
        "alice",
        "launch.md",
        vec![
            row("e-file", "launch.md", None, EntityKind::File),
            row("e-a", "launch.md", Some("e-a"), EntityKind::Item),
            row("e-b", "launch.md", Some("e-b"), EntityKind::Item),
        ],
    )
    .await
    .unwrap();
    idx.replace_path(
        "alice",
        "launch.md",
        vec![
            row("e-file", "launch.md", None, EntityKind::File),
            row("e-a", "launch.md", Some("e-a"), EntityKind::Item),
        ],
    )
    .await
    .unwrap();
    assert!(
        idx.get("alice", &EntityId("e-b".into()))
            .await
            .unwrap()
            .is_none(),
        "dropped item is gone"
    );
    assert!(idx
        .get("alice", &EntityId("e-a".into()))
        .await
        .unwrap()
        .is_some());
    assert!(
        idx.get("bob", &EntityId("e-a".into()))
            .await
            .unwrap()
            .is_none(),
        "agent-scoped"
    );
    idx.delete_path("alice", "launch.md").await.unwrap();
    assert!(idx
        .get("alice", &EntityId("e-file".into()))
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn e1_query_filters_and_bounds() {
    let (_t, idx) = index().await;
    let mut soon = row("e-soon", "a.md", None, EntityKind::File);
    soon.due_at = Some(ts("2026-09-20T00:00:00Z"));
    let mut later = row("e-later", "b.md", None, EntityKind::File);
    later.due_at = Some(ts("2026-12-01T00:00:00Z"));
    later.status = Some("done".into());
    idx.replace_path("alice", "a.md", vec![soon]).await.unwrap();
    idx.replace_path("alice", "b.md", vec![later])
        .await
        .unwrap();

    let mut q = EntityQuery::for_agent("alice");
    q.due_between = Some((ts("2026-09-01T00:00:00Z"), ts("2026-10-01T00:00:00Z")));
    let rows = idx.query(&q).await.unwrap();
    assert_eq!(
        rows.iter().map(|r| r.id.0.as_str()).collect::<Vec<_>>(),
        vec!["e-soon"]
    );

    let mut q = EntityQuery::for_agent("alice");
    q.status = Some("done".into());
    assert_eq!(idx.query(&q).await.unwrap().len(), 1);

    let mut q = EntityQuery::for_agent("alice");
    q.limit = 5000;
    assert!(
        idx.query(&q).await.is_err(),
        "limit above 1000 is rejected, not clamped silently"
    );
}

#[tokio::test]
async fn e1_repeat_expands_into_occurrences_with_horizon_and_cap() {
    let (_t, idx) = index().await;
    let mut weekly = row("e-w", "cal.md", None, EntityKind::File);
    weekly.r#type = "event".into();
    weekly.starts_at = Some(ts("2026-09-21T02:00:00Z"));
    weekly.ends_at = Some(ts("2026-09-21T03:00:00Z"));
    weekly.fields = serde_json::json!({ "repeat": "FREQ=WEEKLY;BYDAY=MO" });
    idx.replace_path("alice", "cal.md", vec![weekly])
        .await
        .unwrap();

    let mut q = EntityQuery::for_agent("alice");
    q.occurs_between = Some((ts("2026-10-01T00:00:00Z"), ts("2026-11-01T00:00:00Z")));
    let rows = idx.query(&q).await.unwrap();
    assert_eq!(
        rows.len(),
        1,
        "one entity even though it occurs 4 times in the window"
    );

    let mut q = EntityQuery::for_agent("alice");
    q.occurs_between = Some((ts("2028-01-01T00:00:00Z"), ts("2028-02-01T00:00:00Z")));
    assert!(
        idx.query(&q).await.unwrap().is_empty(),
        "beyond the 366-day horizon nothing is expanded"
    );

    let mut minutely = row("e-m", "spam.md", None, EntityKind::File);
    minutely.starts_at = Some(ts("2026-09-21T00:00:00Z"));
    minutely.fields = serde_json::json!({ "repeat": "FREQ=MINUTELY" });
    idx.replace_path("alice", "spam.md", vec![minutely])
        .await
        .unwrap();
    let got = idx
        .get("alice", &EntityId("e-m".into()))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        got.fields["__truncated"],
        serde_json::json!(true),
        "expansion capped at 1024"
    );
}

#[tokio::test]
async fn e1_truncate_clears_agent_rows_only() {
    let (_t, idx) = index().await;
    idx.replace_path(
        "alice",
        "a.md",
        vec![row("e-1", "a.md", None, EntityKind::File)],
    )
    .await
    .unwrap();
    let mut bob = row("e-2", "b.md", None, EntityKind::File);
    bob.agent_id = "bob".into();
    idx.replace_path("bob", "b.md", vec![bob]).await.unwrap();
    idx.truncate("alice").await.unwrap();
    assert!(idx
        .get("alice", &EntityId("e-1".into()))
        .await
        .unwrap()
        .is_none());
    assert!(idx
        .get("bob", &EntityId("e-2".into()))
        .await
        .unwrap()
        .is_some());
}

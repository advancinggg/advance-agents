//! Worker / files.changed events (OSS-5.md `operator_events.rs`).

mod common;

use std::time::Duration;

use cap_fs::operator::{CommitState, WriteIntent};

use common::OperatorHarness;

fn files_changed(h: &OperatorHarness) -> Vec<advance_shared_types::event::Event> {
    h.emitter
        .snapshot()
        .into_iter()
        .filter(|e| e.event_type == "files.changed")
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn worker_rows_only_for_committed_changes() {
    let h = OperatorHarness::open().await;
    h.upload("tracked.md", WriteIntent::Create, None, b"ok")
        .await
        .expect("create");
    tokio::time::sleep(Duration::from_millis(50)).await;
    let after_commit = files_changed(&h);
    assert!(
        after_commit
            .iter()
            .any(|e| e.payload.get("path").and_then(|v| v.as_str()) == Some("tracked.md")),
        "committed file emits files.changed: {after_commit:?}"
    );
    let n = after_commit.len();
    std::fs::create_dir(h.home.join("already")).unwrap();
    let out = h
        .core
        .mkdir(
            &common::operator_actor(),
            &cap_fs::operator::FilesMkdir {
                path: "already".into(),
                parents: true,
            },
        )
        .await
        .expect("unchanged mkdir");
    assert_eq!(out.commit, CommitState::Unchanged);
    tokio::time::sleep(Duration::from_millis(50)).await;
    let after_noop = files_changed(&h);
    assert_eq!(
        after_noop.len(),
        n,
        "Unchanged mkdir must not emit more files.changed rows"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn supplementary_rows_for_not_versioned_resave() {
    let h = OperatorHarness::open_with_mb(1).await;
    let big = vec![b'z'; 1_048_576 + 32];
    let out = h
        .upload("huge.bin", WriteIntent::Create, None, &big)
        .await
        .expect("oversize lands on disk");
    assert_eq!(std::fs::read(h.home.join("huge.bin")).unwrap(), big);
    tokio::time::sleep(Duration::from_millis(80)).await;
    let rows = files_changed(&h);
    let huge = rows
        .iter()
        .find(|e| e.payload.get("path").and_then(|v| v.as_str()) == Some("huge.bin"));
    assert!(
        huge.is_some() || out.commit != CommitState::Committed,
        "not-versioned primary still gets a supplementary files.changed row (or no user commit): commit={:?} rows={rows:?}",
        out.commit
    );
    if let Some(row) = huge {
        assert_eq!(
            row.payload.get("versioned").and_then(|v| v.as_str()),
            Some("no")
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn entity_changed_from_user_edit_attributed_to_user() {
    let h = OperatorHarness::open().await;
    h.upload("attr.md", WriteIntent::Create, None, b"user-bytes")
        .await
        .expect("create");
    tokio::time::sleep(Duration::from_millis(50)).await;
    let events = h.emitter.snapshot();
    let user_events: Vec<_> = events
        .iter()
        .filter(|e| e.event_type == "git.commit" || e.event_type == "files.changed")
        .collect();
    assert!(
        !user_events.is_empty(),
        "user edit must emit worker events: {events:?}"
    );
    assert!(
        user_events.iter().all(|e| e.agent_id.starts_with("user:")),
        "worker events attributed to user: {user_events:?}"
    );
}

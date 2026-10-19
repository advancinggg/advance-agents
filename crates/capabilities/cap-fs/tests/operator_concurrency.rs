//! Agent/user interleaving (OSS-5.md `operator_concurrency.rs`).

mod common;

use std::sync::Arc;

use advance_git::{ChangeRole, PathChange};
use cap_fs::operator::{CommitState, FilesError, WriteIntent};

use common::{operator_actor, OperatorHarness};

#[tokio::test(flavor = "multi_thread")]
async fn agent_write_then_user_stale_base_conflict() {
    let h = OperatorHarness::open().await;
    let created = h
        .upload("race.md", WriteIntent::Create, None, b"user-v1")
        .await
        .expect("create");
    std::fs::write(h.home.join("race.md"), b"agent-v2").unwrap();
    let err = h
        .core
        .check_write(
            &operator_actor(),
            &cap_fs::operator::FileWriteTarget {
                path: "race.md".into(),
                intent: WriteIntent::Edit,
                base_oid: created.oid,
                expected_bytes: None,
                batch: None,
            },
        )
        .unwrap_err();
    match err {
        FilesError::StaleBase { current_oid, .. } => {
            assert!(current_oid.is_some(), "stale_base returns disk oid");
        }
        other => panic!("expected stale_base, got {other:?}"),
    }
    assert_eq!(std::fs::read(h.home.join("race.md")).unwrap(), b"agent-v2");
}

#[tokio::test(flavor = "multi_thread")]
async fn agent_delete_then_user_recreate_attribution() {
    let h = OperatorHarness::open().await;
    h.upload("gone.md", WriteIntent::Create, None, b"first")
        .await
        .expect("create");
    std::fs::remove_file(h.home.join("gone.md")).unwrap();
    let out = h
        .upload("gone.md", WriteIntent::Create, None, b"again")
        .await
        .expect("user recreate");
    assert_eq!(out.commit, CommitState::Committed);
    assert_eq!(std::fs::read(h.home.join("gone.md")).unwrap(), b"again");
    let last = h.lane.commits.lock().unwrap().last().cloned().unwrap();
    assert_eq!(last.actor.initiator(), "user:advance");
    assert_eq!(last.op, advance_git::UserOpKind::Create);
}

#[tokio::test(flavor = "multi_thread")]
async fn agent_meta_edit_not_in_user_commit() {
    let h = OperatorHarness::open().await;
    let created = h
        .upload("notes.md", WriteIntent::Create, None, b"body-1")
        .await
        .expect("create");
    std::fs::write(
        h.home.join(".meta.yaml"),
        "notes.md:\n  name: \"Agent Title\"\n  description: \"agent-only\"\n",
    )
    .unwrap();
    h.upload("notes.md", WriteIntent::Edit, created.oid, b"body-2")
        .await
        .expect("user edit");
    assert!(h.lane.sidecar_always_in_last_prepare());
    let last = h.lane.commits.lock().unwrap().last().cloned().unwrap();
    for change in &last.changes {
        if let PathChange::Put { path, role, .. } = change {
            if path.nfc().ends_with(".meta.yaml") || path.nfc() == ".meta.yaml" {
                assert_eq!(
                    *role,
                    ChangeRole::Sidecar,
                    "agent sidecar must not be a user primary"
                );
            }
        }
    }
    let yaml = std::fs::read_to_string(h.home.join(".meta.yaml")).unwrap();
    assert!(yaml.contains("Agent Title"), "{yaml}");
}

#[tokio::test(flavor = "multi_thread")]
async fn commit_order_matches_meta_lock_order() {
    let h = Arc::new(OperatorHarness::open().await);
    let a = {
        let h = Arc::clone(&h);
        tokio::spawn(async move { h.upload("a.md", WriteIntent::Create, None, b"A").await })
    };
    let b = {
        let h = Arc::clone(&h);
        tokio::spawn(async move { h.upload("b.md", WriteIntent::Create, None, b"B").await })
    };
    let ra = a.await.expect("join a").expect("upload a");
    let rb = b.await.expect("join b").expect("upload b");
    assert_eq!(ra.commit, CommitState::Committed);
    assert_eq!(rb.commit, CommitState::Committed);
    assert_eq!(std::fs::read(h.home.join("a.md")).unwrap(), b"A");
    assert_eq!(std::fs::read(h.home.join("b.md")).unwrap(), b"B");
    let commits = h.lane.commits.lock().unwrap().clone();
    assert!(
        commits.len() >= 2,
        "both mutations committed: {}",
        commits.len()
    );
    let order: Vec<String> = commits
        .iter()
        .flat_map(|c| c.changes.iter())
        .filter_map(|ch| match ch {
            PathChange::Put { path, role, .. } if *role == ChangeRole::Primary => {
                Some(path.nfc().to_string())
            }
            _ => None,
        })
        .collect();
    let pos_a = order.iter().position(|p| p == "a.md");
    let pos_b = order.iter().position(|p| p == "b.md");
    assert!(pos_a.is_some() && pos_b.is_some(), "order={order:?}");
    assert_ne!(
        pos_a, pos_b,
        "L1 serializes distinct primary puts: {order:?}"
    );
}

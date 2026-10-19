//! MODULE-002-T81 — batch upload commit (R2b).

mod common;

use cap_fs::operator::{
    CommitState, FileUploadHandle, FileWriteTarget, FilesCommitBatch, FilesError, WriteIntent,
    WriteResult,
};

use common::{operator_actor, OperatorHarness};

const BATCH: &str = "abcdefghijklmnop";

async fn stage(
    h: &OperatorHarness,
    path: &str,
    intent: WriteIntent,
    base_oid: Option<String>,
    bytes: &[u8],
) -> WriteResult {
    let actor = operator_actor();
    let target = FileWriteTarget {
        path: path.into(),
        intent,
        base_oid,
        expected_bytes: Some(bytes.len() as u64),
        batch: Some(BATCH.into()),
    };
    let sink = h.core.begin_upload(&actor, &target).expect("begin");
    std::fs::write(&sink.staging_path, bytes).expect("stage bytes");
    h.core
        .finish_upload(
            &actor,
            &target,
            FileUploadHandle {
                token: sink.handle.token,
            },
        )
        .await
        .expect("finish staged")
}

#[tokio::test(flavor = "multi_thread")]
async fn commit_batch_one_upload_commit_with_mkdirs() {
    let h = OperatorHarness::open().await;
    let a = stage(&h, "reports/a.md", WriteIntent::Create, None, b"one").await;
    let b = stage(&h, "reports/b.md", WriteIntent::Create, None, b"two").await;
    let c = stage(&h, "reports/c.md", WriteIntent::Create, None, b"three").await;
    assert_eq!(a.commit, CommitState::Staged);
    assert_eq!(b.commit, CommitState::Staged);
    assert_eq!(c.commit, CommitState::Staged);
    assert!(
        !h.home.join("reports/a.md").exists(),
        "staged PUT must not publish"
    );
    let before = h.lane.commits.lock().unwrap().len();
    let out = h
        .core
        .commit_batch(
            &operator_actor(),
            &FilesCommitBatch {
                batch: BATCH.into(),
                mkdirs: vec!["reports".into(), "reports/empty".into()],
                parents: true,
            },
        )
        .await
        .expect("commit-batch");
    assert_eq!(
        out.commit,
        CommitState::Committed,
        "commit-batch {out:?}; last changes={:?}",
        h.lane.commits.lock().unwrap().last().map(|c| c
            .changes
            .iter()
            .map(|ch| format!("{ch:?}"))
            .collect::<Vec<_>>())
    );
    assert_eq!(std::fs::read(h.home.join("reports/a.md")).unwrap(), b"one");
    assert_eq!(std::fs::read(h.home.join("reports/b.md")).unwrap(), b"two");
    assert_eq!(
        std::fs::read(h.home.join("reports/c.md")).unwrap(),
        b"three"
    );
    assert!(h.home.join("reports/empty").is_dir());
    let commits = h.lane.commits.lock().unwrap().clone();
    assert_eq!(commits.len(), before + 1, "one upload commit");
    assert_eq!(commits.last().unwrap().op, advance_git::UserOpKind::Upload);
}

#[tokio::test(flavor = "multi_thread")]
async fn commit_batch_stale_base_commits_nothing() {
    let h = OperatorHarness::open().await;
    let created = h
        .upload("hit.md", WriteIntent::Create, None, b"v1")
        .await
        .expect("create");
    let _staged = stage(
        &h,
        "hit.md",
        WriteIntent::Edit,
        created.oid.clone(),
        b"v2-staged",
    )
    .await;
    h.upload("hit.md", WriteIntent::Edit, created.oid.clone(), b"other")
        .await
        .expect("move base");
    let before = h.lane.commits.lock().unwrap().len();
    let err = h
        .core
        .commit_batch(
            &operator_actor(),
            &FilesCommitBatch {
                batch: BATCH.into(),
                mkdirs: vec![],
                parents: true,
            },
        )
        .await
        .expect_err("stale_base");
    match err {
        FilesError::StaleBase { item: Some(0), .. } => {}
        other => panic!("expected stale_base item:0, got {other:?}"),
    }
    assert_eq!(std::fs::read(h.home.join("hit.md")).unwrap(), b"other");
    assert_eq!(h.lane.commits.lock().unwrap().len(), before);
}

#[tokio::test(flavor = "multi_thread")]
async fn commit_batch_expired_commits_nothing() {
    let h = OperatorHarness::open().await;
    let _ = stage(&h, "gone.md", WriteIntent::Create, None, b"x").await;
    h.core.expire_staged_puts(BATCH);
    let before = h.lane.commits.lock().unwrap().len();
    let err = h
        .core
        .commit_batch(
            &operator_actor(),
            &FilesCommitBatch {
                batch: BATCH.into(),
                mkdirs: vec![],
                parents: true,
            },
        )
        .await
        .expect_err("batch_expired");
    match err {
        FilesError::BatchExpired { item: Some(0) } => {}
        other => panic!("expected batch_expired item:0, got {other:?}"),
    }
    assert!(!h.home.join("gone.md").exists());
    assert_eq!(h.lane.commits.lock().unwrap().len(), before);
}

#[tokio::test]
async fn commit_batch_empty_is_batch_expired() {
    let h = OperatorHarness::open_mock().await;
    let err = h
        .core
        .commit_batch(
            &operator_actor(),
            &FilesCommitBatch {
                batch: BATCH.into(),
                mkdirs: vec![],
                parents: true,
            },
        )
        .await
        .expect_err("empty");
    match err {
        FilesError::BatchExpired { item: None } => {}
        other => panic!("expected batch_expired, got {other:?}"),
    }
}

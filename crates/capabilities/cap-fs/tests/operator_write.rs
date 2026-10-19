//! Operator upload / save integration (OSS-5.md `operator_write.rs`).

mod common;

use std::time::Duration;

use cap_fs::operator::{CommitState, FilesError, WriteIntent};

use common::{operator_actor, OperatorHarness};

#[tokio::test(flavor = "multi_thread")]
async fn upload_create_commits_file_and_meta_once() {
    let h = OperatorHarness::open().await;
    let out = h
        .upload("notes.md", WriteIntent::Create, None, b"# hello\n")
        .await
        .expect("create");
    assert_eq!(out.commit, CommitState::Committed);
    assert_eq!(
        std::fs::read(h.home.join("notes.md")).unwrap(),
        b"# hello\n"
    );
    assert!(
        h.home.join(".meta.yaml").exists(),
        "create writes the parent sidecar"
    );
    assert_eq!(h.lane.commits.lock().unwrap().len(), 1);
    assert!(h.lane.sidecar_always_in_last_prepare());
}

#[tokio::test(flavor = "multi_thread")]
async fn upload_edit_commits_exact_bytes_only() {
    let h = OperatorHarness::open().await;
    let created = h
        .upload("doc.md", WriteIntent::Create, None, b"v1")
        .await
        .expect("create");
    let edited = h
        .upload(
            "doc.md",
            WriteIntent::Edit,
            created.oid.clone(),
            b"v2-exact",
        )
        .await
        .expect("edit");
    assert_eq!(edited.commit, CommitState::Committed);
    assert_eq!(std::fs::read(h.home.join("doc.md")).unwrap(), b"v2-exact");
}

#[tokio::test]
async fn stale_base_returns_current_oid_disk_untouched() {
    let h = OperatorHarness::open_mock().await;
    std::fs::write(h.home.join("x.md"), b"disk").unwrap();
    let current = h
        .core
        .check_write(
            &operator_actor(),
            &cap_fs::operator::FileWriteTarget {
                path: "x.md".into(),
                intent: WriteIntent::Edit,
                base_oid: Some("0".repeat(40)),
                expected_bytes: None,
                batch: None,
            },
        )
        .unwrap_err();
    match current {
        FilesError::StaleBase { current_oid, .. } => {
            assert!(current_oid.is_some());
        }
        other => panic!("expected stale_base, got {other:?}"),
    }
    assert_eq!(std::fs::read(h.home.join("x.md")).unwrap(), b"disk");
}

#[tokio::test(flavor = "multi_thread")]
async fn equal_disk_not_in_head_commits() {
    let h = OperatorHarness::open().await;
    std::fs::write(h.home.join("seed.md"), b"same-bytes").unwrap();
    let out = h
        .upload("seed.md", WriteIntent::Upload, None, b"same-bytes")
        .await
        .expect("commit untracked equal bytes");
    assert_eq!(out.commit, CommitState::Committed);
    assert_eq!(
        std::fs::read(h.home.join("seed.md")).unwrap(),
        b"same-bytes"
    );
}

#[tokio::test]
async fn create_existing_target_exists_with_current_oid() {
    let h = OperatorHarness::open_mock().await;
    std::fs::write(h.home.join("hit.md"), b"present").unwrap();
    let err = h
        .core
        .check_write(
            &operator_actor(),
            &cap_fs::operator::FileWriteTarget {
                path: "hit.md".into(),
                intent: WriteIntent::Create,
                base_oid: None,
                expected_bytes: None,
                batch: None,
            },
        )
        .unwrap_err();
    match err {
        FilesError::TargetExists { current_oid, .. } => {
            assert!(current_oid.is_some(), "create collision returns disk oid");
        }
        other => panic!("expected target_exists, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn markdown_byte_exact() {
    let h = OperatorHarness::open().await;
    let body = b"---\ntitle: Q4\n---\r\nline\n";
    h.upload("q4.md", WriteIntent::Create, None, body)
        .await
        .expect("md");
    assert_eq!(std::fs::read(h.home.join("q4.md")).unwrap(), body);
}

#[tokio::test(flavor = "multi_thread")]
async fn over_threshold_not_versioned_too_large() {
    let h = OperatorHarness::open_with_mb(1).await;
    let big = vec![b'x'; 1_048_576 + 64];
    let out = h
        .upload("big.bin", WriteIntent::Create, None, &big)
        .await
        .expect("oversize upload still lands on disk");
    assert_eq!(std::fs::read(h.home.join("big.bin")).unwrap(), big);
    let repo = git2::Repository::open(&h.home).expect("repo");
    let tree = repo.head().expect("head").peel_to_tree().expect("tree");
    assert!(
        tree.get_name("big.bin").is_none(),
        "oversize primary must stay unversioned (commit={:?})",
        out.commit
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn edit_does_not_rewrite_meta() {
    let h = OperatorHarness::open().await;
    h.upload("keep.md", WriteIntent::Create, None, b"one")
        .await
        .unwrap();
    let sidecar = h.home.join(".meta.yaml");
    let before = std::fs::read(&sidecar).unwrap();
    let oid = {
        let st = h
            .core
            .check_write(
                &operator_actor(),
                &cap_fs::operator::FileWriteTarget {
                    path: "keep.md".into(),
                    intent: WriteIntent::Edit,
                    base_oid: None,
                    expected_bytes: None,
                    batch: None,
                },
            )
            .unwrap();
        match st {
            cap_fs::operator::WriteCheck::Allowed { current_oid } => current_oid,
            other => panic!("{other:?}"),
        }
    };
    h.upload("keep.md", WriteIntent::Edit, oid, b"two")
        .await
        .unwrap();
    assert_eq!(std::fs::read(&sidecar).unwrap(), before);
}

#[tokio::test(flavor = "multi_thread")]
async fn r9_prepare_includes_sidecar_always() {
    let h = OperatorHarness::open().await;
    h.upload("r9.md", WriteIntent::Create, None, b"r9")
        .await
        .unwrap();
    assert!(
        h.lane.sidecar_always_in_last_prepare(),
        "R9: prepare must include dir/.meta.yaml Always"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn files_save_releases_meta_lock_before_commit_executes() {
    let h = OperatorHarness::open().await;
    h.upload("lock.md", WriteIntent::Create, None, b"lock")
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(80)).await;
    let seen = h.lane.lock_free_after_enqueue.lock().unwrap().clone();
    assert!(
        seen.iter().any(|free| *free),
        "commit worker must observe L1 released: {seen:?}"
    );
    assert!(h.maintainer.try_acquire().is_some());
}

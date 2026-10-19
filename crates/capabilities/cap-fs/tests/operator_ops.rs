//! Operator mkdir/move/delete/restore/copy/version (OSS-5.md `operator_ops.rs`).

mod common;

use cap_fs::operator::{
    CommitState, CopyItem, FilesDelete, FilesDeleteItem, FilesError, FilesExternalItem, FilesMkdir,
    FilesMoveItem, FilesRestore, FilesRestoreItem, FilesSaveVersion, WriteIntent,
};

use common::{empty_prepare, operator_actor, OperatorHarness};

#[tokio::test(flavor = "multi_thread")]
async fn mkdir_parents_meta_per_level_one_commit() {
    let h = OperatorHarness::open().await;
    let out = h
        .core
        .mkdir(
            &operator_actor(),
            &FilesMkdir {
                path: "a/b/c".into(),
                parents: true,
            },
        )
        .await
        .unwrap();
    assert_eq!(out.commit, CommitState::Committed);
    assert!(h.home.join("a/b/c").is_dir());
    assert!(h.home.join("a/.meta.yaml").exists());
    assert!(h.home.join("a/b/.meta.yaml").exists());
    assert!(h.home.join("a/b/c/.meta.yaml").exists());
    assert_eq!(h.lane.commits.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn mkdir_parents_existing_is_unchanged() {
    let h = OperatorHarness::open_mock().await;
    std::fs::create_dir(h.home.join("notes")).unwrap();
    let out = h
        .core
        .mkdir(
            &operator_actor(),
            &FilesMkdir {
                path: "notes".into(),
                parents: true,
            },
        )
        .await
        .unwrap();
    assert_eq!(out.commit, CommitState::Unchanged);
    assert!(!out.disk_changed);
}

#[tokio::test(flavor = "multi_thread")]
async fn rename_rekeys_meta_preserving_user_values() {
    let h = OperatorHarness::open().await;
    h.upload("old.md", WriteIntent::Create, None, b"body")
        .await
        .unwrap();
    std::fs::write(
        h.home.join(".meta.yaml"),
        "old.md:\n  name: \"Kept Title\"\n  description: \"user\"\n  tags:\n    - keep\n",
    )
    .unwrap();
    h.core
        .move_items(
            &operator_actor(),
            &[FilesMoveItem {
                from: "old.md".into(),
                to: "new.md".into(),
                base_oid: None,
            }],
        )
        .await
        .unwrap();
    assert!(h.home.join("new.md").exists());
    assert!(!h.home.join("old.md").exists());
    let yaml = std::fs::read_to_string(h.home.join(".meta.yaml")).unwrap();
    assert!(yaml.contains("new.md:"), "{yaml}");
    assert!(yaml.contains("Kept Title"), "{yaml}");
    assert!(!yaml.contains("old.md:"), "{yaml}");
}

#[tokio::test]
async fn move_overlapping_items_refused() {
    let h = OperatorHarness::open_mock().await;
    let err = h
        .core
        .move_items(
            &operator_actor(),
            &[
                FilesMoveItem {
                    from: "dir".into(),
                    to: "out".into(),
                    base_oid: None,
                },
                FilesMoveItem {
                    from: "dir/inner".into(),
                    to: "out2".into(),
                    base_oid: None,
                },
            ],
        )
        .await
        .unwrap_err();
    assert!(
        matches!(err, FilesError::Overlap { item: Some(0 | 1) }),
        "{err:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn delete_file_trash_then_purge_after_commit() {
    let h = OperatorHarness::open().await;
    h.upload("gone.md", WriteIntent::Create, None, b"bye")
        .await
        .unwrap();
    let out = h
        .core
        .delete(
            &operator_actor(),
            &FilesDelete {
                items: vec![FilesDeleteItem {
                    path: "gone.md".into(),
                    base_oid: None,
                }],
                recursive: false,
                include_uncommitted: true,
                confirm_unversioned: true,
            },
        )
        .await
        .unwrap();
    assert_eq!(out.commit, CommitState::Committed);
    assert!(!h.home.join("gone.md").exists());
    let trash = h.home.join(".runtime").join("files").join("trash");
    if trash.exists() {
        let leftover: Vec<_> = std::fs::read_dir(&trash)
            .unwrap()
            .flatten()
            .map(|e| e.file_name())
            .collect();
        assert!(
            leftover.is_empty(),
            "committed delete must purge trash: {leftover:?}"
        );
    }
}

#[tokio::test]
async fn delete_uncommitted_requires_include_flag() {
    let h = OperatorHarness::open_mock().await;
    std::fs::write(h.home.join("dirty.md"), b"uncommitted").unwrap();
    let mut prep = empty_prepare();
    prep.unversioned_count = 1;
    prep.unversioned_bytes = 11;
    prep.unversioned = vec!["dirty.md".into()];
    h.lane.force_prepare(prep);
    let err = h
        .core
        .delete(
            &operator_actor(),
            &FilesDelete {
                items: vec![FilesDeleteItem {
                    path: "dirty.md".into(),
                    base_oid: None,
                }],
                recursive: false,
                include_uncommitted: false,
                confirm_unversioned: false,
            },
        )
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            FilesError::UnversionedContent { .. } | FilesError::InvalidRequest { .. }
        ),
        "{err:?}"
    );
    assert!(h.home.join("dirty.md").exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn restore_forward_commit() {
    let h = OperatorHarness::open().await;
    let first = h
        .upload("story.md", WriteIntent::Create, None, b"v1")
        .await
        .unwrap();
    h.upload("story.md", WriteIntent::Edit, first.oid.clone(), b"v2")
        .await
        .unwrap();
    let sha = first.sha.clone().expect("create commit sha");
    let out = h
        .core
        .restore(
            &operator_actor(),
            &FilesRestore {
                items: vec![FilesRestoreItem {
                    path: "story.md".into(),
                    from_sha: sha,
                    base_oid: None,
                    bytes: b"v1".to_vec(),
                    executable: false,
                }],
            },
        )
        .await
        .expect("restore");
    assert_eq!(out.commit, CommitState::Committed);
    assert_eq!(std::fs::read(h.home.join("story.md")).unwrap(), b"v1");
}

#[tokio::test(flavor = "multi_thread")]
async fn commit_external_modified_added_deleted() {
    let h = OperatorHarness::open().await;
    std::fs::write(h.home.join("ext.md"), b"added").unwrap();
    let oid = advance_git::blob_oid_of_bytes(b"added");
    let added = h
        .core
        .commit_external(
            &operator_actor(),
            &[FilesExternalItem {
                path: "ext.md".into(),
                oid: Some(oid.clone()),
            }],
        )
        .await
        .unwrap();
    assert_eq!(added.commit, CommitState::Committed);
    std::fs::write(h.home.join("ext.md"), b"changed").unwrap();
    let oid2 = advance_git::blob_oid_of_bytes(b"changed");
    let modified = h
        .core
        .commit_external(
            &operator_actor(),
            &[FilesExternalItem {
                path: "ext.md".into(),
                oid: Some(oid2),
            }],
        )
        .await
        .unwrap();
    assert_eq!(modified.commit, CommitState::Committed);
    std::fs::remove_file(h.home.join("ext.md")).unwrap();
    let deleted = h
        .core
        .commit_external(
            &operator_actor(),
            &[FilesExternalItem {
                path: "ext.md".into(),
                oid: None,
            }],
        )
        .await
        .unwrap();
    assert_eq!(deleted.commit, CommitState::Committed);
}

#[tokio::test(flavor = "multi_thread")]
async fn save_version_commit_and_tag() {
    let h = OperatorHarness::open().await;
    h.upload("snap.md", WriteIntent::Create, None, b"snap")
        .await
        .unwrap();
    let ver = h
        .core
        .save_version(
            &operator_actor(),
            &FilesSaveVersion {
                title: "Q4 notes".into(),
                paths: None,
            },
        )
        .await
        .unwrap();
    assert!(ver.tag.starts_with("checkpoint/user/"), "{}", ver.tag);
    assert_eq!(ver.title, "Q4 notes");
    assert_eq!(ver.sha.len(), 40);
}

#[tokio::test(flavor = "multi_thread")]
async fn r6_copy_file_one_commit() {
    let h = OperatorHarness::open().await;
    h.upload("src.md", WriteIntent::Create, None, b"copy-me")
        .await
        .unwrap();
    let before = h.lane.commits.lock().unwrap().len();
    let out = h
        .core
        .copy_items(
            &operator_actor(),
            &[CopyItem {
                from: "src.md".into(),
                to: "dup.md".into(),
            }],
        )
        .await
        .unwrap();
    assert_eq!(out.commit, CommitState::Committed);
    assert_eq!(std::fs::read(h.home.join("dup.md")).unwrap(), b"copy-me");
    assert_eq!(h.lane.commits.lock().unwrap().len(), before + 1);
}

#[tokio::test]
async fn r1_delete_confirm_unversioned_when_adopt_incomplete() {
    let h = OperatorHarness::open_mock().await;
    std::fs::write(h.home.join("huge.md"), b"x").unwrap();
    let mut prep = empty_prepare();
    prep.adopt_incomplete = true;
    prep.unversioned_count = 1;
    prep.unversioned_bytes = 1;
    h.lane.force_prepare(prep.clone());
    let refused = h
        .core
        .delete(
            &operator_actor(),
            &FilesDelete {
                items: vec![FilesDeleteItem {
                    path: "huge.md".into(),
                    base_oid: None,
                }],
                recursive: false,
                include_uncommitted: true,
                confirm_unversioned: false,
            },
        )
        .await
        .unwrap_err();
    assert_eq!(
        refused,
        FilesError::UnversionedContent {
            files: 1,
            bytes: 1,
            unknown: true,
        }
    );
    h.lane.force_prepare(prep);
    let ok = h
        .core
        .delete(
            &operator_actor(),
            &FilesDelete {
                items: vec![FilesDeleteItem {
                    path: "huge.md".into(),
                    base_oid: None,
                }],
                recursive: false,
                include_uncommitted: true,
                confirm_unversioned: true,
            },
        )
        .await
        .unwrap();
    assert!(ok.disk_changed);
    assert!(!h.home.join("huge.md").exists());
}

//! `prepare_read` / `open_read` (OSS-6 first stretch; OSS-5 gap).

mod common;

use std::os::unix::fs::symlink;

use advance_git::blob_oid_of_bytes;
use advance_shared_types::workspace_path::ReadOnlyReason;
use cap_fs::operator::{
    FilesError, ReadQuery, ReadSource, StatQuery, WriteIntent, UNSTABLE_READ_OID_THRESHOLD,
};

use common::OperatorHarness;

#[tokio::test]
async fn prepare_and_open_regular_file_streams_path() {
    let h = OperatorHarness::open_list().await;
    std::fs::write(h.home.join("note.md"), b"hello\n").unwrap();
    let v = h
        .core
        .prepare_read(&ReadQuery {
            path: "note.md".into(),
            rev: None,
            want_oid: true,
        })
        .expect("prepare");
    assert_eq!(v.path, "note.md");
    assert_eq!(v.size, 6);
    assert_eq!(v.content_type, "text/markdown");
    assert_eq!(
        v.oid.as_deref(),
        Some(blob_oid_of_bytes(b"hello\n").as_str())
    );
    assert!(v.identity.is_some());
    assert!(!v.already_current);
    match h.core.open_read("note.md", &v).expect("open") {
        ReadSource::Path(p) => {
            assert_eq!(p, h.home.join("note.md"));
            assert_eq!(std::fs::read(p).unwrap(), b"hello\n");
        }
        other => panic!("expected Path, got {other:?}"),
    }
}

#[tokio::test]
async fn nfd_prepare_read_resolves_nfc_entry() {
    let h = OperatorHarness::open_list().await;
    let nfc = "caf\u{00e9}.md";
    let nfd = "cafe\u{0301}.md";
    std::fs::write(h.home.join(nfc), b"nfc").unwrap();
    let v = h
        .core
        .prepare_read(&ReadQuery {
            path: nfd.into(),
            rev: None,
            want_oid: false,
        })
        .expect("NFD prepare");
    assert_eq!(v.path, nfc);
    assert_eq!(v.size, 3);
}

#[tokio::test]
async fn leaf_symlink_is_readonly_not_followed() {
    let h = OperatorHarness::open_list().await;
    std::fs::write(h.home.join("target.md"), b"secret").unwrap();
    symlink("target.md", h.home.join("alias.md")).unwrap();
    let err = h
        .core
        .prepare_read(&ReadQuery {
            path: "alias.md".into(),
            rev: None,
            want_oid: true,
        })
        .unwrap_err();
    assert_eq!(err, FilesError::ReadOnly(ReadOnlyReason::Symlink));
    assert_eq!(std::fs::read(h.home.join("target.md")).unwrap(), b"secret");
}

#[tokio::test]
async fn directory_is_not_a_file() {
    let h = OperatorHarness::open_list().await;
    std::fs::create_dir(h.home.join("folder")).unwrap();
    let err = h
        .core
        .prepare_read(&ReadQuery {
            path: "folder".into(),
            rev: None,
            want_oid: false,
        })
        .unwrap_err();
    assert_eq!(err, FilesError::NotAFile { item: None });
}

#[tokio::test]
async fn hidden_runtime_is_not_found() {
    let h = OperatorHarness::open_list().await;
    std::fs::create_dir_all(h.home.join(".runtime").join("files")).unwrap();
    std::fs::write(h.home.join(".runtime").join("files").join("x"), b"no").unwrap();
    let err = h
        .core
        .prepare_read(&ReadQuery {
            path: ".runtime/files/x".into(),
            rev: None,
            want_oid: false,
        })
        .unwrap_err();
    assert_eq!(err, FilesError::NotFound);
}

#[tokio::test]
async fn h2_large_unstable_file_is_readable_never_file_busy() {
    let h = OperatorHarness::open_list().await;
    let path = h.home.join("large.bin");
    let size = UNSTABLE_READ_OID_THRESHOLD + 1;
    std::fs::write(&path, vec![0xab; size as usize]).unwrap();
    let v = h
        .core
        .prepare_read(&ReadQuery {
            path: "large.bin".into(),
            rev: None,
            want_oid: true,
        })
        .expect("H2 still readable");
    assert_eq!(v.size, size);
    assert!(v.identity.is_some());
    match h.core.open_read("large.bin", &v).expect("open large") {
        ReadSource::Path(p) => assert_eq!(std::fs::metadata(p).unwrap().len(), size),
        other => panic!("expected Path, got {other:?}"),
    }
}

#[tokio::test]
async fn historical_rev_returns_old_bytes_after_wt_edit() {
    let h = OperatorHarness::open().await;
    let out = h
        .upload("story.md", WriteIntent::Create, None, b"first\n")
        .await
        .expect("create");
    assert_eq!(out.commit, cap_fs::operator::CommitState::Committed);
    let sha = out.sha.expect("commit sha");
    h.core
        .stat(&StatQuery {
            path: "story.md".into(),
        })
        .expect("exists");
    let _ = h
        .upload("story.md", WriteIntent::Edit, out.oid, b"second\n")
        .await
        .expect("edit");
    assert_eq!(std::fs::read(h.home.join("story.md")).unwrap(), b"second\n");
    let v = h
        .core
        .prepare_read(&ReadQuery {
            path: "story.md".into(),
            rev: Some(sha.clone()),
            want_oid: true,
        })
        .expect("historical prepare");
    assert_eq!(v.rev.as_deref(), Some(sha.as_str()));
    assert_eq!(v.size, 6);
    assert_eq!(
        v.oid.as_deref(),
        Some(blob_oid_of_bytes(b"first\n").as_str())
    );
    assert!(!v.already_current);
    match h.core.open_read("story.md", &v).expect("historical open") {
        ReadSource::Bytes(bytes) => assert_eq!(bytes, b"first\n"),
        other => panic!("expected Bytes, got {other:?}"),
    }
}

#[tokio::test]
async fn unknown_rev_is_unknown_version() {
    let h = OperatorHarness::open().await;
    std::fs::write(h.home.join("a.md"), b"x").unwrap();
    let err = h
        .core
        .prepare_read(&ReadQuery {
            path: "a.md".into(),
            rev: Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into()),
            want_oid: false,
        })
        .unwrap_err();
    assert_eq!(err, FilesError::UnknownVersion);
}

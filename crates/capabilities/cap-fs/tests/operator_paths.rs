//! Path / Unicode integration (OSS-5.md `operator_paths.rs`).

mod common;

use cap_fs::operator::{FilesError, ListQuery, StatQuery, WriteIntent};

use common::{operator_actor, OperatorHarness};

#[tokio::test(flavor = "multi_thread")]
async fn cjk_paths_roundtrip_list_write_commit() {
    let h = OperatorHarness::open().await;
    let path = "笔记/你好.md";
    h.core
        .mkdir(
            &operator_actor(),
            &cap_fs::operator::FilesMkdir {
                path: "笔记".into(),
                parents: false,
            },
        )
        .await
        .unwrap();
    let out = h
        .upload(path, WriteIntent::Create, None, "中文内容\n".as_bytes())
        .await
        .expect("cjk create");
    assert_eq!(out.commit, cap_fs::operator::CommitState::Committed);
    assert_eq!(
        std::fs::read(h.home.join(path)).unwrap(),
        "中文内容\n".as_bytes()
    );
    let listing = h
        .core
        .list(&ListQuery {
            dir: "笔记".into(),
            ..ListQuery::default()
        })
        .unwrap();
    assert!(
        listing.entries.iter().any(|e| e.name == "你好.md"),
        "{:?}",
        listing.entries
    );
}

#[tokio::test]
async fn nfd_request_resolves_nfc_entry() {
    let h = OperatorHarness::open_list().await;
    let nfc = "caf\u{00e9}.md";
    let nfd = "cafe\u{0301}.md";
    std::fs::write(h.home.join(nfc), b"nfc").unwrap();
    let st = h
        .core
        .stat(&StatQuery { path: nfd.into() })
        .expect("NFD request must resolve the NFC entry");
    assert_eq!(st.entry.name, nfc);
    assert_eq!(std::fs::read(h.home.join(nfc)).unwrap(), b"nfc");
}

#[tokio::test]
async fn create_case_variant_collision_refused() {
    let h = OperatorHarness::open_mock().await;
    std::fs::write(h.home.join("Notes.md"), b"kept").unwrap();
    let err = h
        .core
        .check_write(
            &operator_actor(),
            &cap_fs::operator::FileWriteTarget {
                path: "notes.md".into(),
                intent: WriteIntent::Create,
                base_oid: None,
                expected_bytes: None,
                batch: None,
            },
        )
        .unwrap_err();
    match err {
        FilesError::TargetExists { name_collision, .. } => {
            assert!(
                name_collision || cfg!(target_os = "macos"),
                "case variant must be target_exists (collision={name_collision})"
            );
        }
        other => panic!("expected target_exists, got {other:?}"),
    }
    assert_eq!(std::fs::read(h.home.join("Notes.md")).unwrap(), b"kept");
}

#[tokio::test]
async fn portable_key_collision_on_case_sensitive_fs() {
    let h = OperatorHarness::open_mock().await;
    std::fs::write(h.home.join("Straße.md"), b"ss").unwrap();
    let err = h
        .core
        .check_write(
            &operator_actor(),
            &cap_fs::operator::FileWriteTarget {
                path: "STRASSE.md".into(),
                intent: WriteIntent::Create,
                base_oid: None,
                expected_bytes: None,
                batch: None,
            },
        )
        .unwrap_err();
    match err {
        FilesError::TargetExists { name_collision, .. } => {
            assert!(
                name_collision,
                "portable key Straße/STRASSE must be name_collision"
            );
        }
        other => panic!("expected target_exists name_collision, got {other:?}"),
    }
}

#[tokio::test]
async fn zwj_name_on_disk_counted_unsupported() {
    let h = OperatorHarness::open_list().await;
    std::fs::write(h.home.join("keep\u{200d}.md"), b"zwj-legal").unwrap();
    std::fs::write(h.home.join(".g\u{200d}it"), b"alias").unwrap();
    let listing = h.core.list(&ListQuery::default()).unwrap();
    let names: Vec<&str> = listing.entries.iter().map(|e| e.name.as_str()).collect();
    assert!(
        names
            .iter()
            .any(|n| n.contains('\u{200d}') && n.ends_with(".md")),
        "legal ZWJ names list: {names:?}"
    );
    assert!(
        !names.iter().any(|n| n.contains("git")),
        "ZWJ alias of .git stays hidden: {names:?}"
    );
}

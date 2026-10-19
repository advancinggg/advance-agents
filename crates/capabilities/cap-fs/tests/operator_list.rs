//! Operator list / stat integration (OSS-5.md `operator_list.rs`).

mod common;

use cap_fs::operator::{FilesError, ListQuery, ListSort};

use common::OperatorHarness;

#[tokio::test]
async fn list_hides_hidden_junk_staging_tempfiles() {
    let h = OperatorHarness::open_list().await;
    std::fs::write(h.home.join("visible.md"), b"v").unwrap();
    std::fs::create_dir_all(h.home.join(".runtime").join("files").join("staging")).unwrap();
    std::fs::create_dir(h.home.join(".git")).unwrap();
    std::fs::write(h.home.join(".DS_Store"), b"junk").unwrap();
    std::fs::write(h.home.join(".tmpAbc123"), b"tmp").unwrap();
    std::fs::write(h.home.join(".~advance-x"), b"tmp").unwrap();
    std::fs::write(h.home.join(".obsidian"), b"ok").unwrap();
    let names = h.names("");
    assert!(names.contains(&"visible.md".into()));
    assert!(names.contains(&".obsidian".into()));
    assert!(!names.iter().any(|n| n == ".runtime"));
    assert!(!names.iter().any(|n| n == ".git"));
    assert!(!names.iter().any(|n| n == ".DS_Store"));
    assert!(!names.iter().any(|n| n == ".tmpAbc123"));
    assert!(!names.iter().any(|n| n == ".~advance-x"));
    assert!(!names.iter().any(|n| n == ".meta.yaml"));
}

#[tokio::test]
async fn list_hides_runtime() {
    let h = OperatorHarness::open_list().await;
    std::fs::create_dir_all(h.home.join(".runtime").join("files")).unwrap();
    std::fs::write(h.home.join("note.md"), b"n").unwrap();
    let names = h.names("");
    assert!(names.contains(&"note.md".into()));
    assert!(!names.iter().any(|n| n.eq_ignore_ascii_case(".runtime")));
}

#[tokio::test]
async fn list_offset_fingerprint_paging() {
    let h = OperatorHarness::open_list().await;
    for name in ["a.md", "b.md", "c.md", "d.md"] {
        std::fs::write(h.home.join(name), name.as_bytes()).unwrap();
    }
    let first = h
        .core
        .list(&ListQuery {
            limit: 2,
            sort: ListSort::Name,
            folders_first: true,
            ..ListQuery::default()
        })
        .unwrap();
    assert_eq!(first.entries.len(), 2);
    assert_eq!(first.next_offset, Some(2));
    assert!(!first.fingerprint.is_empty());
    let second = h
        .core
        .list(&ListQuery {
            offset: 2,
            fingerprint: Some(first.fingerprint.clone()),
            limit: 2,
            sort: ListSort::Name,
            folders_first: true,
            ..ListQuery::default()
        })
        .unwrap();
    assert_eq!(second.entries.len(), 2);
    assert_ne!(first.entries[0].name, second.entries[0].name);
    std::fs::write(h.home.join("e.md"), b"e").unwrap();
    let stale = h.core.list(&ListQuery {
        offset: 2,
        fingerprint: Some(first.fingerprint),
        limit: 2,
        ..ListQuery::default()
    });
    assert_eq!(stale.unwrap_err(), FilesError::ListingChanged);
}

#[tokio::test]
async fn list_meta_decoration_nfc_keys() {
    let h = OperatorHarness::open_list().await;
    let nfc = "caf\u{00e9}.md";
    std::fs::write(h.home.join(nfc), b"hello").unwrap();
    std::fs::write(
        h.home.join(".meta.yaml"),
        format!("{nfc}:\n  name: \"Cafe\"\n  description: \"nfc\"\n"),
    )
    .unwrap();
    let listing = h
        .core
        .list(&ListQuery {
            folders_first: true,
            ..ListQuery::default()
        })
        .unwrap();
    let names: Vec<&str> = listing.entries.iter().map(|e| e.name.as_str()).collect();
    assert!(names.contains(&nfc), "NFC stored name is listed: {names:?}");
    assert!(
        !names.contains(&".meta.yaml"),
        "sidecar stays hidden: {names:?}"
    );
    let st = h
        .core
        .stat(&cap_fs::operator::StatQuery { path: nfc.into() })
        .unwrap();
    assert_eq!(st.entry.name, nfc);
}

#[tokio::test]
async fn list_territory_and_foreign_repo_flags() {
    let h = OperatorHarness::open_list().await;
    std::fs::create_dir_all(h.home.join("child").join(".agent")).unwrap();
    std::fs::create_dir_all(h.home.join("ext").join(".git")).unwrap();
    std::fs::write(h.home.join("plain.md"), b"p").unwrap();
    let listing = h.core.list(&ListQuery::default()).unwrap();
    let child = listing
        .entries
        .iter()
        .find(|e| e.name == "child")
        .expect("child");
    let ext = listing
        .entries
        .iter()
        .find(|e| e.name == "ext")
        .expect("ext");
    let plain = listing
        .entries
        .iter()
        .find(|e| e.name == "plain.md")
        .expect("plain");
    assert!(child.territory_root, "`.agent` marks a territory root");
    assert!(ext.foreign_repo, "nested `.git` marks a foreign repo");
    assert!(!plain.territory_root);
    assert!(!plain.foreign_repo);
}

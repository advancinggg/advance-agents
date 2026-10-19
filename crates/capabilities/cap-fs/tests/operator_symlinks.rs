//! Symlink / special-file / H2 pins (OSS-5.md `operator_symlinks.rs`).

mod common;

use std::os::unix::fs::symlink;
use std::time::{Duration, Instant};

use advance_shared_types::workspace_path::ReadOnlyReason;
use cap_fs::operator::{FilesError, ListQuery, StatQuery, WriteIntent};

use common::{operator_actor, OperatorHarness};

#[tokio::test]
async fn dir_symlink_component_classified_symlink_not_enotdir() {
    let h = OperatorHarness::open_list().await;
    std::fs::create_dir(h.home.join("real")).unwrap();
    std::fs::write(h.home.join("real/a.md"), b"x").unwrap();
    symlink("real", h.home.join("link")).unwrap();
    let err = h
        .core
        .list(&ListQuery {
            dir: "link".into(),
            ..ListQuery::default()
        })
        .unwrap_err();
    assert!(
        matches!(
            err,
            FilesError::NotFound | FilesError::ReadOnly(ReadOnlyReason::Symlink)
        ),
        "dir symlink traversal is not ENOTDIR: {err:?}"
    );
}

#[tokio::test]
async fn leaf_symlink_listed_readonly_never_opened() {
    let h = OperatorHarness::open_list().await;
    std::fs::write(h.home.join("target.md"), b"secret").unwrap();
    symlink("target.md", h.home.join("alias.md")).unwrap();
    let listing = h.core.list(&ListQuery::default()).unwrap();
    let alias = listing
        .entries
        .iter()
        .find(|e| e.name == "alias.md")
        .expect("symlink is listed");
    assert_eq!(alias.kind, cap_fs::operator::EntryKind::Symlink);
    assert!(alias.read_only);
    assert_eq!(alias.read_only_reason, Some(ReadOnlyReason::Symlink));
    assert_eq!(std::fs::read(h.home.join("target.md")).unwrap(), b"secret");
}

#[tokio::test]
async fn write_never_follows_leaf_symlink() {
    let h = OperatorHarness::open_mock().await;
    std::fs::write(h.home.join("target.md"), b"secret").unwrap();
    symlink("target.md", h.home.join("alias.md")).unwrap();
    let err = h
        .core
        .check_write(
            &operator_actor(),
            &cap_fs::operator::FileWriteTarget {
                path: "alias.md".into(),
                intent: WriteIntent::Edit,
                base_oid: None,
                expected_bytes: None,
                batch: None,
            },
        )
        .unwrap_err();
    assert_eq!(err, FilesError::ReadOnly(ReadOnlyReason::Symlink));
    assert_eq!(std::fs::read(h.home.join("target.md")).unwrap(), b"secret");
}

#[tokio::test]
async fn fifo_entry_never_blocks() {
    let h = OperatorHarness::open_list().await;
    let fifo = h.home.join("pipe.fifo");
    #[cfg(unix)]
    {
        let path = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        let rc = unsafe { libc::mkfifo(path.as_ptr(), 0o600) };
        assert_eq!(rc, 0, "mkfifo");
    }
    let start = Instant::now();
    let listing = h.core.list(&ListQuery::default()).expect("list fifo");
    assert!(
        start.elapsed() < Duration::from_secs(1),
        "list blocked on fifo"
    );
    let _ = listing
        .entries
        .iter()
        .find(|e| e.name == "pipe.fifo")
        .expect("fifo listed");
    let start = Instant::now();
    let _ = h.core.stat(&StatQuery {
        path: "pipe.fifo".into(),
    });
    assert!(
        start.elapsed() < Duration::from_secs(1),
        "stat blocked on fifo"
    );
}

#[tokio::test]
async fn h2_unstable_large_file_is_readable() {
    let h = OperatorHarness::open_list().await;
    let path = h.home.join("big.bin");
    let blob = vec![0u8; 16 * 1024 * 1024 + 8];
    std::fs::write(&path, &blob).unwrap();
    let st = h
        .core
        .stat(&StatQuery {
            path: "big.bin".into(),
        })
        .expect("H2: large file stays readable");
    assert_eq!(st.entry.kind, cap_fs::operator::EntryKind::File);
    assert!(st.entry.size.unwrap_or(0) >= 16 * 1024 * 1024);
    std::fs::write(&path, b"mutated").unwrap();
    let again = h
        .core
        .stat(&StatQuery {
            path: "big.bin".into(),
        })
        .expect("H2: restat after mutation");
    assert_eq!(again.entry.size, Some(7));
}

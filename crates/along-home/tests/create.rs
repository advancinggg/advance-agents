//! T103 — MODULE-001-AC-24

use std::fs;

use advance_along_home::{AlongHomeFirstOpen, CreateError, HostAlongHome, RecognizeClass};

#[test]
fn t103_create_open_refuse_invalid() {
    let tmp = tempfile::tempdir().unwrap();
    let parent = tmp.path();
    let h = HostAlongHome::production();

    let first = h.create(parent, "home-a").unwrap();
    assert!(matches!(
        h.recognize(first.path()),
        RecognizeClass::Recognized { .. }
    ));
    let cfg = first.path().join(".advance").join("runtime-config.yaml");
    let before = fs::read(&cfg).unwrap();

    let second = h.create(parent, "home-a").unwrap();
    assert_eq!(second.path(), first.path());
    assert_eq!(fs::read(&cfg).unwrap(), before);

    let sibling = parent.join("not-home");
    fs::create_dir(&sibling).unwrap();
    fs::write(sibling.join("note.txt"), b"keep").unwrap();
    let err = h.create(parent, "not-home").unwrap_err();
    assert_eq!(err, CreateError::ExistsNotAlongHome);
    assert_eq!(fs::read(sibling.join("note.txt")).unwrap(), b"keep");

    assert_eq!(
        h.create(parent, "..").unwrap_err(),
        CreateError::InvalidName
    );
    assert_eq!(
        h.create(parent, "a/b").unwrap_err(),
        CreateError::InvalidName
    );
    assert_eq!(
        h.create(parent, r"a\b").unwrap_err(),
        CreateError::InvalidName
    );
    assert!(!parent.join("a").exists());
}

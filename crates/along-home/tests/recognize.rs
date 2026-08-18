//! T102 — MODULE-001-AC-23

use std::fs;
use std::os::unix::fs::PermissionsExt;

use advance_along_home::{
    write_recognizable_home, AlongHomeFirstOpen, HostAlongHome, RecognizeClass,
};

fn host() -> HostAlongHome {
    HostAlongHome::production()
}

#[test]
fn t102_recognize_classes_and_open() {
    let tmp = tempfile::tempdir().unwrap();
    let h = host();

    let created = tmp.path().join("created");
    write_recognizable_home(&created).unwrap();
    assert!(matches!(
        h.recognize(&created),
        RecognizeClass::Recognized { .. }
    ));
    assert!(h.open(&created).is_ok());

    let via_create = h.create(tmp.path(), "via-create").unwrap();
    assert!(matches!(
        h.recognize(via_create.path()),
        RecognizeClass::Recognized { .. }
    ));

    let empty = tmp.path().join("empty");
    fs::create_dir(&empty).unwrap();
    assert_eq!(h.recognize(&empty), RecognizeClass::NotAnAlongHome);
    assert!(matches!(
        h.open(&empty),
        Err(RecognizeClass::NotAnAlongHome)
    ));

    let file = tmp.path().join("file");
    fs::write(&file, b"x").unwrap();
    assert_eq!(h.recognize(&file), RecognizeClass::NotAnAlongHome);

    let damaged = tmp.path().join("damaged");
    fs::create_dir_all(damaged.join(".advance")).unwrap();
    fs::create_dir_all(damaged.join(".runtime")).unwrap();
    fs::create_dir_all(damaged.join(".agent")).unwrap();
    let starter = advance_along_home::MINIMAL_STARTER.as_bytes();
    fs::write(
        damaged.join(".advance").join("runtime-config.yaml"),
        &starter[..40.min(starter.len())],
    )
    .unwrap();
    assert_eq!(h.recognize(&damaged), RecognizeClass::Damaged);

    let unreadable = tmp.path().join("unreadable");
    fs::create_dir(&unreadable).unwrap();
    let mut perms = fs::metadata(&unreadable).unwrap().permissions();
    perms.set_mode(0o000);
    fs::set_permissions(&unreadable, perms).unwrap();
    let class = h.recognize(&unreadable);
    let mut restore = fs::metadata(&unreadable).unwrap().permissions();
    restore.set_mode(0o700);
    fs::set_permissions(&unreadable, restore).unwrap();
    assert_eq!(class, RecognizeClass::Unreadable);

    let unwritable = tmp.path().join("unwritable");
    write_recognizable_home(&unwritable).unwrap();
    let mut perms = fs::metadata(&unwritable).unwrap().permissions();
    perms.set_mode(0o500);
    fs::set_permissions(&unwritable, perms).unwrap();
    let class = h.recognize(&unwritable);
    let mut restore = fs::metadata(&unwritable).unwrap().permissions();
    restore.set_mode(0o700);
    fs::set_permissions(&unwritable, restore).unwrap();
    assert_eq!(class, RecognizeClass::Unwritable);

    let before: std::collections::BTreeSet<_> = fs::read_dir(tmp.path())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    let _ = h.recognize(&created);
    let _ = h.recognize(&empty);
    let after: std::collections::BTreeSet<_> = fs::read_dir(tmp.path())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(before, after);

    let src = include_str!("../src/recognize.rs");
    assert!(
        !src.contains("read_dir"),
        "recognize must not walk parent/sibling directories"
    );

    let planted = tmp.path().join("planted");
    fs::create_dir(&planted).unwrap();
    let elsewhere = tmp.path().join("elsewhere");
    fs::create_dir(&elsewhere).unwrap();
    std::os::unix::fs::symlink(&elsewhere, planted.join(".advance")).unwrap();
    fs::create_dir(planted.join(".runtime")).unwrap();
    fs::create_dir(planted.join(".agent")).unwrap();
    assert_eq!(h.recognize(&planted), RecognizeClass::Damaged);
}

//! Crash / journal recovery (OSS-5.md `operator_crash.rs`).

mod common;

use cap_fs::operator::journal::{
    journal_dir, load_journal, persist, ItemKind, JournalItem, JournalRecord, TypedOp,
    JOURNAL_RECORD_CAP,
};
use cap_fs::operator::{CapacityKind, CommitState, FilesError, FilesMkdir, WriteIntent};

use common::{operator_actor, OperatorHarness};

fn write_item(path: &str, post_oid: Option<&str>) -> JournalItem {
    JournalItem {
        kind: ItemKind::Write,
        from_rel: None,
        to_rel: path.into(),
        dev_ino: None,
        pre_identity: None,
        pre_oid: None,
        post_identity: None,
        post_oid: post_oid.map(str::to_string),
        entry_pre: None,
        temp_location: None,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn crash_at_after_journal_upload_create() {
    let h = OperatorHarness::open().await;
    let mut rec = JournalRecord::new(
        "01crashjournalcreate0000000001".into(),
        "user:advance".into(),
        TypedOp::Create,
    );
    rec.disk_changed = true;
    rec.items.push(write_item("crash-create.md", None));
    h.core.journal_intent(&rec).expect("persist crash journal");
    assert!(!h.home.join("crash-create.md").exists());
    let out = h
        .upload("crash-create.md", WriteIntent::Create, None, b"recovered")
        .await
        .expect("retry create after journal-only crash");
    assert_eq!(out.commit, CommitState::Committed);
    assert_eq!(
        std::fs::read(h.home.join("crash-create.md")).unwrap(),
        b"recovered"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn crash_at_after_data_mkdir() {
    let h = OperatorHarness::open().await;
    std::fs::create_dir(h.home.join("crash-dir")).unwrap();
    let mut rec = JournalRecord::new(
        "01crashafterdatamkdir000000001".into(),
        "user:advance".into(),
        TypedOp::CreateFolder,
    );
    rec.disk_changed = true;
    rec.items.push(JournalItem {
        kind: ItemKind::Mkdir,
        from_rel: None,
        to_rel: "crash-dir".into(),
        dev_ino: None,
        pre_identity: None,
        pre_oid: None,
        post_identity: None,
        post_oid: None,
        entry_pre: None,
        temp_location: None,
    });
    h.core.journal_intent(&rec).expect("persist mkdir journal");
    let out = h
        .core
        .mkdir(
            &operator_actor(),
            &FilesMkdir {
                path: "crash-dir".into(),
                parents: true,
            },
        )
        .await
        .expect("mkdir after crash");
    assert_eq!(out.commit, CommitState::Unchanged);
    assert!(h.home.join("crash-dir").is_dir());
}

#[tokio::test(flavor = "multi_thread")]
async fn crash_at_before_submit_delete() {
    let h = OperatorHarness::open().await;
    h.upload("doomed.md", WriteIntent::Create, None, b"bye")
        .await
        .expect("seed");
    std::fs::remove_file(h.home.join("doomed.md")).unwrap();
    let mut rec = JournalRecord::new(
        "01crashbeforesubmitdel00000001".into(),
        "user:advance".into(),
        TypedOp::Delete,
    );
    rec.disk_changed = true;
    rec.items.push(JournalItem {
        kind: ItemKind::Trash,
        from_rel: None,
        to_rel: "doomed.md".into(),
        dev_ino: None,
        pre_identity: None,
        pre_oid: None,
        post_identity: None,
        post_oid: None,
        entry_pre: None,
        temp_location: None,
    });
    h.core.journal_intent(&rec).expect("persist delete journal");
    h.upload("other.md", WriteIntent::Create, None, b"keep")
        .await
        .expect("touch replay");
    assert!(!h.home.join("doomed.md").exists());
    let names = h.names("");
    assert!(!names.iter().any(|n| n == "doomed.md"), "{names:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn replay_after_committed_is_unchanged() {
    let h = OperatorHarness::open().await;
    let created = h
        .upload("stable.md", WriteIntent::Create, None, b"same")
        .await
        .expect("create");
    let oid = created.oid.clone().expect("oid");
    let mut rec = JournalRecord::new(
        "01replayaftercommitted00000001".into(),
        "user:advance".into(),
        TypedOp::Create,
    );
    rec.disk_changed = true;
    rec.items.push(write_item("stable.md", Some(&oid)));
    persist(h.core.files_state(), &rec).expect("replay journal");
    let before = std::fs::read(h.home.join("stable.md")).unwrap();
    h.upload("next.md", WriteIntent::Create, None, b"next")
        .await
        .expect("unrelated create triggers replay");
    assert_eq!(std::fs::read(h.home.join("stable.md")).unwrap(), before);
}

#[tokio::test]
async fn journal_record_forgery_rejected() {
    let h = OperatorHarness::open_mock().await;
    let dir = journal_dir(h.core.files_state());
    std::fs::create_dir_all(&dir).unwrap();
    let forged_schema = dir.join("01forgedschema00000000000001.json");
    std::fs::write(
        &forged_schema,
        br#"{"v":2,"op_id":"01forgedschema00000000000001","created_ms":1,"actor_handle":"user:h","op":{"type":"edit"},"items":[],"metas":[],"disk_changed":false,"subject":"forged"}"#,
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&forged_schema, std::fs::Permissions::from_mode(0o600)).unwrap();
        let forged_mode = dir.join("01forgedmode0000000000000001.json");
        let mut good = JournalRecord::new(
            "01forgedmode0000000000000001".into(),
            "user:h".into(),
            TypedOp::Edit,
        );
        good.items.push(write_item("notes.md", Some("aa")));
        std::fs::write(&forged_mode, serde_json::to_vec(&good).unwrap()).unwrap();
        std::fs::set_permissions(&forged_mode, std::fs::Permissions::from_mode(0o644)).unwrap();
        let _ = load_journal(h.core.files_state()).unwrap();
        assert!(!forged_schema.exists());
        assert!(!forged_mode.exists());
    }
    h.core
        .check_write(
            &operator_actor(),
            &cap_fs::operator::FileWriteTarget {
                path: "ok.md".into(),
                intent: WriteIntent::Create,
                base_oid: None,
                expected_bytes: None,
                batch: None,
            },
        )
        .expect("operator still accepts writes after forgery purge");
}

#[tokio::test]
async fn journal_backlog_cap_refuses_new_mutations() {
    let h = OperatorHarness::open_mock().await;
    for i in 0..JOURNAL_RECORD_CAP {
        persist(
            h.core.files_state(),
            &JournalRecord::new(format!("cap{i:04}"), "user:advance".into(), TypedOp::Edit),
        )
        .expect("fill journal cap");
    }
    let err = h
        .core
        .mkdir(
            &operator_actor(),
            &FilesMkdir {
                path: "blocked".into(),
                parents: false,
            },
        )
        .await
        .unwrap_err();
    assert_eq!(
        err,
        FilesError::Capacity {
            kind: CapacityKind::Journal
        }
    );
    assert!(!h.home.join("blocked").exists());
}

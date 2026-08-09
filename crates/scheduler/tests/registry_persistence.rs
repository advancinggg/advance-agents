//! AC-07 verification: `ComponentRegistry::open_in` SQLite-backed
//! persistence + path-confinement.
//!
//! Tests:
//! - insert + close + reopen + list returns rows in `seq ASC` (stable
//!   insertion order across same-millisecond inserts via AUTOINCREMENT)
//! - duplicate id rejected with `AlreadyExists`
//! - delete + reopen returns surviving rows
//! - delete on missing id is idempotent Ok
//! - path-confinement rejects all 6 grammar-violating filenames
//! - path-confinement accepts a simple filename

use advance_scheduler::{
    ComponentRegistry, ComponentSubmitConfig, RegistryError, TriggerConfig, WebhookConfig,
};
use advance_shared_types::component::ComponentType;

fn dummy_cfg(id: &str, t: ComponentType) -> ComponentSubmitConfig {
    ComponentSubmitConfig {
        sensitive_params: Vec::new(),
        id: id.into(),
        component_type: t,
        binary: Vec::new(),
        capabilities: Vec::new(),
        output_dir: None,
        trigger: None,
        restart_policy: None,
        delay: None,
        initial_grants: None,
        preset: None,
        retry: None,
    }
}

#[tokio::test]
async fn insert_close_reopen_list() {
    let tempdir = tempfile::tempdir().unwrap();

    {
        let reg = ComponentRegistry::open_in(tempdir.path(), "components.db")
            .await
            .expect("open_in must succeed for a fresh tempdir");
        reg.insert(
            "agent:root",
            &dummy_cfg("cron-a", ComponentType::Cron),
            Some(5_000),
        )
        .await
        .unwrap();
        reg.insert(
            "agent:root",
            &dummy_cfg("daemon-b", ComponentType::Daemon),
            None,
        )
        .await
        .unwrap();
        reg.insert(
            "agent:other",
            &dummy_cfg("task-c", ComponentType::Task),
            None,
        )
        .await
        .unwrap();
        // Drop reg → close the SQLite connection.
    }

    // Reopen and read back.
    let reg2 = ComponentRegistry::open_in(tempdir.path(), "components.db")
        .await
        .expect("reopen must succeed");
    let rows = reg2.list().await.unwrap();
    assert_eq!(rows.len(), 3);
    // ORDER BY seq ASC guarantees insertion order.
    assert_eq!(rows[0].id.as_str(), "cron-a");
    assert_eq!(rows[1].id.as_str(), "daemon-b");
    assert_eq!(rows[2].id.as_str(), "task-c");
    // Verify metadata round-trips correctly.
    assert_eq!(rows[0].component_type, ComponentType::Cron);
    assert_eq!(rows[1].component_type, ComponentType::Daemon);
    assert_eq!(rows[2].component_type, ComponentType::Task);
    assert_eq!(rows[0].submitter, "agent:root");
    assert_eq!(rows[2].submitter, "agent:other");
    assert_eq!(rows[0].interval_ms, Some(5_000));
    assert_eq!(rows[1].interval_ms, None);
}

#[tokio::test]
async fn duplicate_id_rejected() {
    let tempdir = tempfile::tempdir().unwrap();
    let reg = ComponentRegistry::open_in(tempdir.path(), "components.db")
        .await
        .unwrap();
    reg.insert(
        "agent:root",
        &dummy_cfg("dup", ComponentType::Cron),
        Some(1_000),
    )
    .await
    .unwrap();
    let err = reg
        .insert(
            "agent:other",
            &dummy_cfg("dup", ComponentType::Daemon),
            None,
        )
        .await
        .unwrap_err();
    assert!(
        matches!(err, RegistryError::AlreadyExists(_)),
        "got {err:?}"
    );
}

#[tokio::test]
async fn delete_then_reopen() {
    let tempdir = tempfile::tempdir().unwrap();
    {
        let reg = ComponentRegistry::open_in(tempdir.path(), "components.db")
            .await
            .unwrap();
        reg.insert(
            "agent:root",
            &dummy_cfg("a", ComponentType::Cron),
            Some(5_000),
        )
        .await
        .unwrap();
        reg.insert("agent:root", &dummy_cfg("b", ComponentType::Task), None)
            .await
            .unwrap();
        reg.delete("a").await.unwrap();
    }
    let reg2 = ComponentRegistry::open_in(tempdir.path(), "components.db")
        .await
        .unwrap();
    let rows = reg2.list().await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].id.as_str(), "b");
}

#[tokio::test]
async fn delete_idempotent() {
    let tempdir = tempfile::tempdir().unwrap();
    let reg = ComponentRegistry::open_in(tempdir.path(), "components.db")
        .await
        .unwrap();
    // No row exists; delete must succeed silently.
    reg.delete("ghost")
        .await
        .expect("delete-missing must be Ok");
}

#[tokio::test]
async fn path_confinement_rejects_traversal() {
    let tempdir = tempfile::tempdir().unwrap();
    let bad_names = ["../escape.db", "subdir/foo.db", ".hidden.db", ".", "..", ""];
    for name in bad_names {
        let result = ComponentRegistry::open_in(tempdir.path(), name).await;
        // ComponentRegistry does not impl Debug (holds rusqlite::Connection
        // which lacks Debug); use is_err()+match instead of unwrap_err().
        assert!(result.is_err(), "expected error for {name:?}");
        match result {
            Err(RegistryError::InvalidFilename(_)) => {}
            Err(other) => panic!("expected InvalidFilename for {name:?}, got {other:?}"),
            Ok(_) => unreachable!(),
        }
    }
}

#[tokio::test]
async fn path_confinement_accepts_simple_name() {
    let tempdir = tempfile::tempdir().unwrap();
    let reg = ComponentRegistry::open_in(tempdir.path(), "components.db").await;
    assert!(reg.is_ok(), "simple filename must be accepted");
}

#[tokio::test]
async fn webhook_secret_redacted_on_insert() {
    let tempdir = tempfile::tempdir().unwrap();
    let mut cfg = dummy_cfg("hook-component", ComponentType::Watcher);
    cfg.trigger = Some(TriggerConfig::Webhook(WebhookConfig {
        path: "/hook".into(),
        secret: Some("super-secret-hmac-key".into()),
    }));
    {
        let reg = ComponentRegistry::open_in(tempdir.path(), "components.db")
            .await
            .unwrap();
        reg.insert("agent:root", &cfg, None).await.unwrap();
    }
    // Caller's cfg is NOT mutated.
    if let Some(TriggerConfig::Webhook(ref w)) = cfg.trigger {
        assert_eq!(w.secret.as_deref(), Some("super-secret-hmac-key"));
    } else {
        panic!("test fixture mutated unexpectedly");
    }
    let reg2 = ComponentRegistry::open_in(tempdir.path(), "components.db")
        .await
        .unwrap();
    let row = reg2.get("hook-component").await.unwrap().unwrap();
    match row.submit_config.trigger {
        Some(TriggerConfig::Webhook(w)) => {
            assert_eq!(w.path, "/hook");
            assert_eq!(w.secret, None, "secret must be redacted on persistence");
        }
        other => panic!("expected Webhook trigger, got {other:?}"),
    }
}

#[tokio::test]
async fn insert_rejects_sub_floor_interval() {
    // Adversarial-round-1 Critical-1 regression-lock: interval_ms < 100 ms
    // is rejected to prevent hot-loop in catch_up_components.
    let tempdir = tempfile::tempdir().unwrap();
    let reg = ComponentRegistry::open_in(tempdir.path(), "components.db")
        .await
        .unwrap();
    let cfg = dummy_cfg("bad-interval", ComponentType::Cron);

    // interval = 0
    let result0 = reg.insert("agent:root", &cfg, Some(0)).await;
    assert!(result0.is_err(), "interval_ms=0 must be rejected");

    // interval = negative
    let result_neg = reg.insert("agent:root", &cfg, Some(-1)).await;
    assert!(result_neg.is_err(), "interval_ms=-1 must be rejected");

    // interval = 99 (below floor)
    let result_low = reg.insert("agent:root", &cfg, Some(99)).await;
    assert!(result_low.is_err(), "interval_ms=99 must be rejected");

    // interval = 100 (at floor)
    let cfg2 = dummy_cfg("ok-interval", ComponentType::Cron);
    reg.insert("agent:root", &cfg2, Some(100))
        .await
        .expect("interval_ms=100 must be accepted (at floor)");

    // interval = None (one-shot)
    let cfg3 = dummy_cfg("oneshot", ComponentType::Task);
    reg.insert("agent:root", &cfg3, None)
        .await
        .expect("interval_ms=None (one-shot) must be accepted");
}

#[tokio::test]
async fn insert_rejects_deeply_nested_anyof() {
    // Adversarial-round-1 Critical-2 regression-lock: webhook-redaction walker
    // depth-capped at MAX_TRIGGER_NESTING_DEPTH=8 prevents stack-overflow via
    // direct registry-insert with deeply-nested AnyOf tree.
    let tempdir = tempfile::tempdir().unwrap();
    let reg = ComponentRegistry::open_in(tempdir.path(), "components.db")
        .await
        .unwrap();

    // Build a nested AnyOf of depth 10 (above MAX_TRIGGER_NESTING_DEPTH=8).
    let mut trigger = TriggerConfig::Schedule("every-1m".into());
    for _ in 0..10 {
        trigger = TriggerConfig::AnyOf(vec![trigger]);
    }
    let mut cfg = dummy_cfg("deep-nest", ComponentType::Watcher);
    cfg.trigger = Some(trigger);
    let result = reg.insert("agent:root", &cfg, None).await;
    assert!(
        result.is_err(),
        "deep AnyOf nesting must be rejected by redaction depth cap"
    );
}

#[tokio::test]
async fn webhook_secret_redacted_recursively_in_anyof() {
    let tempdir = tempfile::tempdir().unwrap();
    let mut cfg = dummy_cfg("any-hook", ComponentType::Watcher);
    cfg.trigger = Some(TriggerConfig::AnyOf(vec![
        TriggerConfig::Schedule("every-1m".into()),
        TriggerConfig::AnyOf(vec![TriggerConfig::Webhook(WebhookConfig {
            path: "/inner".into(),
            secret: Some("inner-secret".into()),
        })]),
    ]));
    {
        let reg = ComponentRegistry::open_in(tempdir.path(), "components.db")
            .await
            .unwrap();
        reg.insert("agent:root", &cfg, None).await.unwrap();
    }
    let reg2 = ComponentRegistry::open_in(tempdir.path(), "components.db")
        .await
        .unwrap();
    let row = reg2.get("any-hook").await.unwrap().unwrap();
    fn assert_no_webhook_secret(t: &TriggerConfig) {
        match t {
            TriggerConfig::Webhook(w) => assert_eq!(
                w.secret, None,
                "nested Webhook secret must be redacted on persistence"
            ),
            TriggerConfig::AnyOf(children) => {
                for c in children {
                    assert_no_webhook_secret(c);
                }
            }
            _ => {}
        }
    }
    if let Some(ref t) = row.submit_config.trigger {
        assert_no_webhook_secret(t);
    } else {
        panic!("trigger was unexpectedly None");
    }
}

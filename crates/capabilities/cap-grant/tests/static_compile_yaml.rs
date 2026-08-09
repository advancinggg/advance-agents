//! Static-config + register_cap_grant integration: T-A4, T-A7.

mod common;

use std::io::Write;
use std::sync::Arc;

use advance_database::{R2d2SqliteIndexHandle, SqliteIndexHandle};
use advance_shared_types::traits::EventBusEmit;
use cap_grant::{register_cap_grant, GrantSqliteIndex};
use tempfile::{NamedTempFile, TempDir};

use crate::common::RecordingBus;

const FIXTURE_YAML: &str = r#"capabilities:
  fs:
    read: [/research/]
  http:
    allowlist: ["https://api.example.com/*"]
"#;

// T-A4 — AC-04 — compile_then_dual_write end-to-end.
#[test]
fn compile_then_dual_write() {
    let dir = TempDir::new().unwrap();
    let yaml_path = dir.path().join("config.yaml");
    std::fs::write(&yaml_path, FIXTURE_YAML).unwrap();

    let handle: Arc<dyn SqliteIndexHandle> =
        Arc::new(R2d2SqliteIndexHandle::new_in_memory().unwrap());
    let bus = RecordingBus::new();
    let bus_dyn: Arc<dyn EventBusEmit> = bus.clone();

    let handles = register_cap_grant(
        handle.clone(),
        bus_dyn,
        Some(&yaml_path),
        "root-agent".to_string(),
        None,
    )
    .unwrap();

    // Both views agree.
    assert_eq!(handles.store.list_by_grantee("root-agent").len(), 2);
    let index = GrantSqliteIndex::new(handle);
    assert_eq!(index.count_rows().unwrap(), 2);

    // Deterministic ids verified.
    let ids: Vec<String> = handles
        .store
        .list_by_grantee("root-agent")
        .into_iter()
        .map(|g| g.id.0)
        .collect();
    assert!(ids.contains(&"static:root-agent:fs".to_string()));
    assert!(ids.contains(&"static:root-agent:http".to_string()));
}

// T-A7 — AC-04 + AC-18 — compile twice across a simulated restart, no accumulation.
#[test]
fn compile_twice_no_accumulation() {
    let yaml_file = NamedTempFile::new().unwrap();
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(yaml_file.path())
            .unwrap();
        f.write_all(FIXTURE_YAML.as_bytes()).unwrap();
        f.flush().unwrap();
    }

    let db_file = NamedTempFile::new().unwrap();
    let db_path = db_file.path().to_path_buf();
    drop(db_file);

    // First open + register — 2 rows in grant_index.
    {
        let handle: Arc<dyn SqliteIndexHandle> =
            Arc::new(R2d2SqliteIndexHandle::new(&db_path, 1).unwrap());
        let bus = RecordingBus::new();
        let bus_dyn: Arc<dyn EventBusEmit> = bus.clone();
        let handles = register_cap_grant(
            handle.clone(),
            bus_dyn,
            Some(yaml_file.path()),
            "root-agent".to_string(),
            None,
        )
        .unwrap();
        assert_eq!(handles.store.list_by_grantee("root-agent").len(), 2);
        let index = GrantSqliteIndex::new(handle);
        assert_eq!(index.count_rows().unwrap(), 2);
        // Drop handles + index when this scope ends.
        drop(handles);
    }

    // Second open + register — STILL 2 rows (deterministic id rule).
    {
        let handle: Arc<dyn SqliteIndexHandle> =
            Arc::new(R2d2SqliteIndexHandle::new(&db_path, 1).unwrap());
        let bus = RecordingBus::new();
        let bus_dyn: Arc<dyn EventBusEmit> = bus.clone();
        let handles = register_cap_grant(
            handle.clone(),
            bus_dyn,
            Some(yaml_file.path()),
            "root-agent".to_string(),
            None,
        )
        .unwrap();
        assert_eq!(handles.store.list_by_grantee("root-agent").len(), 2);
        let index = GrantSqliteIndex::new(handle);
        assert_eq!(index.count_rows().unwrap(), 2);

        let ids: Vec<String> = handles
            .store
            .list_by_grantee("root-agent")
            .into_iter()
            .map(|g| g.id.0)
            .collect();
        assert!(ids.contains(&"static:root-agent:fs".to_string()));
        assert!(ids.contains(&"static:root-agent:http".to_string()));
    }

    // Cleanup: explicit removal is unnecessary (db_path is in tempdir).
}

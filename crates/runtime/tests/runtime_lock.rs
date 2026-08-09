//! Tests for `RuntimeLock` — covers AC-06 (T02-T04 + extras) and AC-11 (T15 partial).

use advance_runtime::runtime_lock::{LockError, RuntimeLock};
use std::time::Duration;

/// Short heartbeat interval for fast tests.
const TEST_HB: Duration = Duration::from_secs(1);

// ---------------------------------------------------------------------------
// T02: acquire when absent (AC-06)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn acquire_when_absent() {
    let dir = tempfile::tempdir().unwrap();
    let lock = RuntimeLock::acquire(dir.path(), TEST_HB).await.unwrap();
    let lock_path = dir.path().join(".runtime/runtime.lock");
    assert!(lock_path.exists(), "lock file must be created");

    let content = std::fs::read_to_string(&lock_path).unwrap();
    let our_pid = std::process::id().to_string();
    assert!(
        content.contains(&format!("pid: {our_pid}")),
        "lock file must contain our PID"
    );
    drop(lock);
}

// ---------------------------------------------------------------------------
// T03: reject when active (AC-06)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn reject_when_active() {
    let dir = tempfile::tempdir().unwrap();
    let lock = RuntimeLock::acquire(dir.path(), TEST_HB).await.unwrap();

    // Second acquire on same workspace should fail
    let result = RuntimeLock::acquire(dir.path(), TEST_HB).await;
    match &result {
        Err(LockError::ActiveRuntime(pid)) => {
            assert_eq!(*pid, std::process::id());
        }
        other => panic!("expected ActiveRuntime, got: {other:?}"),
    }
    drop(lock);
}

// ---------------------------------------------------------------------------
// T04: recover from stale / dead PID (AC-06)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn recover_from_stale() {
    let dir = tempfile::tempdir().unwrap();
    let lock_dir = dir.path().join(".runtime");
    std::fs::create_dir_all(&lock_dir).unwrap();
    let lock_path = lock_dir.join("runtime.lock");

    // Write a lock with a dead PID (4 billion — almost certainly not a real process)
    let fake_lock = format!(
        "pid: 4000000000\nplatform_uid: \"fake:4000000000:never\"\nstarted_at: \"2020-01-01T00:00:00Z\"\nheartbeat_at: \"2020-01-01T00:00:00Z\"\nworkspace_root: \"{}\"\nversion: \"0.1.0\"",
        dir.path().display()
    );
    std::fs::write(&lock_path, &fake_lock).unwrap();

    // Should succeed — dead PID means stale
    let lock = RuntimeLock::acquire(dir.path(), TEST_HB).await.unwrap();
    let content = std::fs::read_to_string(&lock_path).unwrap();
    let our_pid = std::process::id().to_string();
    assert!(
        content.contains(&format!("pid: {our_pid}")),
        "lock overwritten with our PID"
    );
    drop(lock);
}

// ---------------------------------------------------------------------------
// T15 partial: single-tenant workspace (AC-11)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn single_tenant_workspace() {
    let dir = tempfile::tempdir().unwrap();
    let _lock = RuntimeLock::acquire(dir.path(), TEST_HB).await.unwrap();

    // Second acquire must fail — single-tenant invariant
    let result = RuntimeLock::acquire(dir.path(), TEST_HB).await;
    assert!(
        matches!(&result, Err(LockError::ActiveRuntime(_))),
        "second acquire must fail with ActiveRuntime, got: {result:?}"
    );
}

// ---------------------------------------------------------------------------
// Heartbeat updates timestamp (AC-06)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn heartbeat_updates_timestamp() {
    let dir = tempfile::tempdir().unwrap();
    let lock = RuntimeLock::acquire(dir.path(), TEST_HB).await.unwrap();
    let lock_path = dir.path().join(".runtime/runtime.lock");

    let before = std::fs::read_to_string(&lock_path).unwrap();
    let hb_before = extract_heartbeat(&before);

    // Wait for at least one heartbeat tick
    tokio::time::sleep(Duration::from_secs(2)).await;

    let after = std::fs::read_to_string(&lock_path).unwrap();
    let hb_after = extract_heartbeat(&after);

    assert_ne!(hb_before, hb_after, "heartbeat_at must have advanced");
    drop(lock);
}

fn extract_heartbeat(content: &str) -> String {
    content
        .lines()
        .find(|l| l.starts_with("heartbeat_at:"))
        .unwrap_or("")
        .to_string()
}

// ---------------------------------------------------------------------------
// Drop removes lock file (AC-06)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn drop_removes_lock_file() {
    let dir = tempfile::tempdir().unwrap();
    let lock = RuntimeLock::acquire(dir.path(), TEST_HB).await.unwrap();
    let lock_path = lock.path().to_path_buf();
    assert!(lock_path.exists());
    drop(lock);
    // Give a moment for Drop + abort to complete
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!lock_path.exists(), "lock file must be removed on drop");
}

// ---------------------------------------------------------------------------
// Lock file permissions (AC-06, §1.7 Security)
// ---------------------------------------------------------------------------

#[tokio::test]
#[cfg(unix)]
async fn lock_file_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let lock = RuntimeLock::acquire(dir.path(), TEST_HB).await.unwrap();
    let lock_path = dir.path().join(".runtime/runtime.lock");

    let meta = std::fs::metadata(&lock_path).unwrap();
    let mode = meta.permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "lock file must be 0600, got {mode:o}");
    drop(lock);
}

// ---------------------------------------------------------------------------
// PID-reuse gate (AC-06) — PID alive but platform_uid mismatch
// ---------------------------------------------------------------------------

#[tokio::test]
async fn recover_from_pid_reuse() {
    let dir = tempfile::tempdir().unwrap();
    let lock_dir = dir.path().join(".runtime");
    std::fs::create_dir_all(&lock_dir).unwrap();
    let lock_path = lock_dir.join("runtime.lock");

    // Write lock with OUR PID but a WRONG platform_uid (simulates PID reuse)
    let our_pid = std::process::id();
    let fake_lock = format!(
        "pid: {our_pid}\nplatform_uid: \"fake:0:reused\"\nstarted_at: \"2020-01-01T00:00:00Z\"\nheartbeat_at: \"{}\"\nworkspace_root: \"{}\"\nversion: \"0.1.0\"",
        chrono::Utc::now().to_rfc3339(),
        dir.path().display(),
    );
    std::fs::write(&lock_path, &fake_lock).unwrap();

    // Should succeed — PID alive but platform_uid mismatch → stale (gate B fails)
    let lock = RuntimeLock::acquire(dir.path(), TEST_HB).await.unwrap();
    let content = std::fs::read_to_string(lock.path()).unwrap();
    assert!(
        !content.contains("fake:0:reused"),
        "old platform_uid must be overwritten"
    );
    drop(lock);
}

// ---------------------------------------------------------------------------
// Malformed lock file (AC-06) — garbage content treated as stale
// ---------------------------------------------------------------------------

#[tokio::test]
async fn malformed_lock_file_parse_error() {
    let dir = tempfile::tempdir().unwrap();
    let lock_dir = dir.path().join(".runtime");
    std::fs::create_dir_all(&lock_dir).unwrap();
    let lock_path = lock_dir.join("runtime.lock");

    std::fs::write(&lock_path, "this is not yaml at all\n!@#$%^&*()\n").unwrap();

    // Should succeed — malformed file treated as stale
    let lock = RuntimeLock::acquire(dir.path(), TEST_HB).await.unwrap();
    let content = std::fs::read_to_string(lock.path()).unwrap();
    let our_pid = std::process::id().to_string();
    assert!(content.contains(&format!("pid: {our_pid}")));
    drop(lock);
}

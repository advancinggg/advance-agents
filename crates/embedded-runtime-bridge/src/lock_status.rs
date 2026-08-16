//! Bridge-local re-parse of `.runtime/runtime.lock` heartbeat (private helpers in advance-runtime).

use std::fs;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chrono::{DateTime, Utc};

/// Default staleness threshold matching runtime_lock (120s).
pub const STALENESS: Duration = Duration::from_secs(120);

#[derive(Debug, Clone)]
pub struct LockSnapshot {
    pub pid: u32,
    pub heartbeat_at: String,
}

/// Parse lock YAML written by RuntimeLock (key: value lines).
pub fn parse_lock_file(path: &Path) -> Option<LockSnapshot> {
    let content = fs::read_to_string(path).ok()?;
    let mut pid = None;
    let mut heartbeat_at = None;
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("pid:") {
            pid = rest.trim().parse().ok();
        } else if let Some(rest) = line.strip_prefix("heartbeat_at:") {
            heartbeat_at = Some(rest.trim().trim_matches('"').to_string());
        }
    }
    Some(LockSnapshot {
        pid: pid?,
        heartbeat_at: heartbeat_at?,
    })
}

/// True if heartbeat_at RFC3339 is within STALENESS of now.
pub fn heartbeat_fresh(heartbeat_at: &str) -> bool {
    let Ok(dt) = DateTime::parse_from_rfc3339(heartbeat_at) else {
        return false;
    };
    let hb = dt.with_timezone(&Utc);
    let now = Utc::now();
    let age = now.signed_duration_since(hb);
    age.num_seconds() >= 0 && (age.num_seconds() as u64) <= STALENESS.as_secs()
}

/// last_heartbeat_ok for embed with RuntimeLock held.
pub fn embed_lock_heartbeat_ok(workspace: &Path) -> bool {
    let path = workspace.join(".runtime").join("runtime.lock");
    let Some(snap) = parse_lock_file(&path) else {
        return false;
    };
    heartbeat_fresh(&snap.heartbeat_at)
}

/// For tests: wall clock now as secs (unused helpers keep API ready).
#[allow(dead_code)]
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

//! Structured-log channel for MODULE-003 §2.14 keys (ADR 2026-10-15).
//!
//! advance-git has no logger of its own. The commit worker records
//! `git.user_lane.head_moved_swept`, `git.repo.lane_policy_failed`,
//! `git.repo.precompose_disabled` and `git.user_lane.version_tag_failed` through
//! [`GitLog`] after the coord guard drops. Production wiring is OSS-6
//! (`spawn_with_config_and_event_bus_and_log`). A queue spawned without a log
//! emits none of these keys.
//!
//! Code that runs while the coord mutex is held must not call into a log
//! implementation; the worker logs only after `drop(guard)`.

#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::arithmetic_side_effects
)]

/// Severity of one structured log record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitLogLevel {
    Info,
    Warn,
}

/// Sink for the MODULE-003 §2.14 keys this crate emits.
pub trait GitLog: Send + Sync {
    fn log(&self, level: GitLogLevel, key: &'static str, fields: &[(&str, &str)]);
}

/// A `HeadMoved` attempt whose new tip already held the user's content
/// (`Unchanged` after a foreign commit, MODULE-003 §1.4.1 item 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Swept {
    pub sha: String,
    pub attempts: u32,
}

pub(crate) const HEAD_MOVED_SWEPT: &str = "git.user_lane.head_moved_swept";
pub(crate) const LANE_POLICY_FAILED: &str = "git.repo.lane_policy_failed";
pub(crate) const PRECOMPOSE_DISABLED: &str = "git.repo.precompose_disabled";
pub(crate) const VERSION_TAG_FAILED: &str = "git.user_lane.version_tag_failed";

pub(crate) fn emit(
    log: Option<&dyn GitLog>,
    level: GitLogLevel,
    key: &'static str,
    fields: &[(&str, &str)],
) {
    if let Some(log) = log {
        log.log(level, key, fields);
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct Tap {
        keys: Mutex<Vec<(&'static str, GitLogLevel)>>,
    }

    impl GitLog for Tap {
        fn log(&self, level: GitLogLevel, key: &'static str, _fields: &[(&str, &str)]) {
            self.keys.lock().unwrap().push((key, level));
        }
    }

    #[test]
    fn emit_is_a_no_op_without_a_sink() {
        emit(None, GitLogLevel::Warn, HEAD_MOVED_SWEPT, &[("sha", "abc")]);
    }

    #[test]
    fn emit_forwards_the_known_keys() {
        let tap = Tap {
            keys: Mutex::new(Vec::new()),
        };
        emit(
            Some(&tap),
            GitLogLevel::Warn,
            HEAD_MOVED_SWEPT,
            &[("sha", "abc"), ("attempts", "2")],
        );
        emit(
            Some(&tap),
            GitLogLevel::Warn,
            LANE_POLICY_FAILED,
            &[("repo", "/tmp/x"), ("step", "attributes")],
        );
        emit(
            Some(&tap),
            GitLogLevel::Info,
            PRECOMPOSE_DISABLED,
            &[("repo", "/tmp/x")],
        );
        emit(
            Some(&tap),
            GitLogLevel::Warn,
            VERSION_TAG_FAILED,
            &[("sha", "abc")],
        );
        let keys = tap.keys.lock().unwrap();
        assert_eq!(
            keys.as_slice(),
            &[
                (HEAD_MOVED_SWEPT, GitLogLevel::Warn),
                (LANE_POLICY_FAILED, GitLogLevel::Warn),
                (PRECOMPOSE_DISABLED, GitLogLevel::Info),
                (VERSION_TAG_FAILED, GitLogLevel::Warn),
            ]
        );
    }
}

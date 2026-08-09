//! Identifier validators (Slice A) — differentiated whitelist per ID type.
//!
//! - `validate_run_id`: M008-generated; strict ASCII alphanumeric + `_-`, max 64.
//! - `validate_task_id`: caller-provided; allows `:` and `.` for REQ-069
//!   `auto:{agent-id}` namespace + future tenant prefixes; max 128.
//! - `validate_agent_id`: same rule as task_id (e.g. `user:alice` / `team:foo`).

pub(crate) fn validate_run_id(s: &str) -> Result<(), &'static str> {
    if s.is_empty() {
        return Err("empty");
    }
    if s.len() > 64 {
        return Err("overlong");
    }
    if !s
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err("invalid-char");
    }
    Ok(())
}

pub(crate) fn validate_task_id(s: &str) -> Result<(), &'static str> {
    if s.is_empty() {
        return Err("empty");
    }
    if s.len() > 128 {
        return Err("overlong");
    }
    if !s
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b':' | b'.'))
    {
        return Err("invalid-char");
    }
    Ok(())
}

pub(crate) fn validate_agent_id(s: &str) -> Result<(), &'static str> {
    validate_task_id(s)
}

/// Slice B — `SessionId` charset rule per MODULE-007 `await_session.rs`
/// implementer invariant ("validate against `^[A-Za-z0-9_-]{1,64}$` before
/// use"). Same shape as `validate_run_id` (strict ASCII alphanumeric +
/// `_-`, max 64). Used by `suspend_run` AND `recover_on_startup`.
pub(crate) fn validate_session_id(s: &str) -> Result<(), &'static str> {
    validate_run_id(s)
}

/// Slice C — Auto-mode discrimination by `task_id` prefix per REQ-069.
/// PRD §4.7.2 line 865: an Auto Run is one whose `task-id == "auto:{agent-id}"`.
/// Used at the `RunManager::complete_round` dispatch site.
pub(crate) fn is_auto_mode(task_id: &str) -> bool {
    task_id.starts_with("auto:")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_id_strict() {
        assert!(validate_run_id("run-abc123").is_ok());
        assert!(validate_run_id("RUN_X9").is_ok());
        assert!(validate_run_id("").is_err());
        assert!(validate_run_id(&"a".repeat(65)).is_err());
        assert!(validate_run_id("../etc/passwd").is_err());
        assert!(validate_run_id("user:alice").is_err()); // `:` not allowed for run_id
        assert!(validate_run_id("foo.bar").is_err()); // `.` not allowed
        assert!(validate_run_id("with\x00null").is_err());
        assert!(validate_run_id("with\nnewline").is_err());
    }

    #[test]
    fn task_id_accepts_auto_namespace() {
        assert!(validate_task_id("auto:agent-foo").is_ok()); // REQ-069
        assert!(validate_task_id("user:alice").is_ok());
        assert!(validate_task_id("team:foo.bar").is_ok());
        assert!(validate_task_id("task-001").is_ok());
        assert!(validate_task_id("").is_err());
        assert!(validate_task_id(&"a".repeat(129)).is_err());
        assert!(validate_task_id("../etc").is_err());
        assert!(validate_task_id("space here").is_err());
    }

    #[test]
    fn agent_id_same_as_task_id() {
        assert!(validate_agent_id("auto:agent-foo").is_ok());
        assert!(validate_agent_id("root").is_ok());
        assert!(validate_agent_id("../etc/passwd").is_err());
    }
}

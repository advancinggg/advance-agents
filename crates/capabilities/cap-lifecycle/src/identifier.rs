//! Slice-A identifier + hidden-name helpers.

use crate::error::SpawnError;

/// Maximum AgentId byte length (matches shared-types Implementer Invariants).
pub const MAX_AGENT_ID_LEN: usize = 64;

/// Agent ids refused on **creation** paths only (MODULE-003-AC-30). Boot of a
/// legacy declared alias is not refused — see `validate_agent_id`.
pub const RESERVED_AGENT_IDS: &[&str] = &["user"];

/// Validate an `AgentId.0` string against `^[A-Za-z0-9_-]{1,64}$`.
///
/// Returns `Ok(())` on success; `Err(SpawnError::InvalidConfig)` on empty,
/// over-length, or off-charset input. Note that standard UUID v4 hyphens are
/// allowed (a 36-char UUID v4 passes the charset + length checks). Does **not**
/// refuse the reserved `user` namespace — that is [`validate_new_agent_id`].
pub fn validate_agent_id(id: &str) -> Result<(), SpawnError> {
    if id.is_empty() {
        return Err(SpawnError::InvalidConfig("agent id is empty".to_string()));
    }
    if id.len() > MAX_AGENT_ID_LEN {
        return Err(SpawnError::InvalidConfig(format!(
            "agent id length {} exceeds max {}",
            id.len(),
            MAX_AGENT_ID_LEN
        )));
    }
    for ch in id.chars() {
        let ok = ch.is_ascii_alphanumeric() || ch == '_' || ch == '-';
        if !ok {
            return Err(SpawnError::InvalidConfig(format!(
                "agent id contains invalid character {ch:?} (charset is [A-Za-z0-9_-])"
            )));
        }
    }
    Ok(())
}

/// [`validate_agent_id`] plus a case-insensitive reserved-id check. Used on
/// spawn handle pre-flight and non-UUID child ids (MODULE-003-T81).
pub fn validate_new_agent_id(id: &str) -> Result<(), SpawnError> {
    validate_agent_id(id)?;
    if RESERVED_AGENT_IDS
        .iter()
        .any(|reserved| id.eq_ignore_ascii_case(reserved))
    {
        return Err(SpawnError::InvalidConfig(format!(
            "agent id {id:?} is reserved"
        )));
    }
    Ok(())
}

/// Generate a fresh UUID v4 string suitable for the `/.sub/{uuid}/` directory name.
pub fn sub_uuid_v4() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Case-insensitive workspace-hidden-name allowlist. Slice-A narrow set
/// mirroring cap-fs `is_workspace_hidden_name`. Matches:
/// - `.git`, `.meta.yaml`, `.advance`, `.runtime` (exact, ascii-case-insensitive)
/// - Any name ending in `.sqlite`, `.sqlite-wal`, `.sqlite-shm`, `.sqlite-journal`
///
/// Does NOT match `.sub` or `.agent` (those are M005's own territory markers).
pub fn is_workspace_hidden_name(component: &str) -> bool {
    let lc = component.to_ascii_lowercase();
    matches!(lc.as_str(), ".git" | ".meta.yaml" | ".advance" | ".runtime")
        || lc.ends_with(".sqlite")
        || lc.ends_with(".sqlite-wal")
        || lc.ends_with(".sqlite-shm")
        || lc.ends_with(".sqlite-journal")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty() {
        assert!(matches!(
            validate_agent_id(""),
            Err(SpawnError::InvalidConfig(_))
        ));
    }

    #[test]
    fn rejects_overlong() {
        let s = "a".repeat(65);
        assert!(matches!(
            validate_agent_id(&s),
            Err(SpawnError::InvalidConfig(_))
        ));
    }

    #[test]
    fn rejects_whitespace() {
        assert!(matches!(
            validate_agent_id("hello world"),
            Err(SpawnError::InvalidConfig(_))
        ));
    }

    #[test]
    fn accepts_alphanumeric_dash_underscore() {
        assert!(validate_agent_id("a-bc_DEF-123").is_ok());
    }

    #[test]
    fn accepts_uuid_v4() {
        assert!(validate_agent_id("550e8400-e29b-41d4-a716-446655440000").is_ok());
    }

    #[test]
    fn sub_uuid_v4_validates() {
        let id = sub_uuid_v4();
        assert!(validate_agent_id(&id).is_ok());
        assert_eq!(id.len(), 36);
    }

    #[test]
    fn hidden_names_matched() {
        assert!(is_workspace_hidden_name(".git"));
        assert!(is_workspace_hidden_name(".meta.yaml"));
        assert!(is_workspace_hidden_name(".advance"));
        assert!(is_workspace_hidden_name(".runtime"));
        assert!(is_workspace_hidden_name(".RUNTIME"));
        assert!(is_workspace_hidden_name("foo.sqlite"));
        assert!(is_workspace_hidden_name("foo.sqlite-wal"));
        assert!(is_workspace_hidden_name("foo.sqlite-shm"));
        assert!(is_workspace_hidden_name("foo.sqlite-journal"));
    }

    #[test]
    fn hidden_names_case_insensitive() {
        assert!(is_workspace_hidden_name(".GIT"));
        assert!(is_workspace_hidden_name(".Meta.YAML"));
        assert!(is_workspace_hidden_name("foo.SQLITE-WAL"));
    }

    #[test]
    fn non_hidden_names_pass() {
        assert!(!is_workspace_hidden_name(".sub"));
        assert!(!is_workspace_hidden_name(".agent"));
        assert!(!is_workspace_hidden_name("agents"));
        assert!(!is_workspace_hidden_name("foo"));
    }

    // MODULE-003-T81: reserved on creation paths only.
    #[test]
    fn new_agent_id_refuses_reserved() {
        assert!(matches!(
            validate_new_agent_id("user"),
            Err(SpawnError::InvalidConfig(_))
        ));
        assert!(matches!(
            validate_new_agent_id("User"),
            Err(SpawnError::InvalidConfig(_))
        ));
        assert!(validate_agent_id("user").is_ok());
        assert!(validate_new_agent_id("writer").is_ok());
    }
}

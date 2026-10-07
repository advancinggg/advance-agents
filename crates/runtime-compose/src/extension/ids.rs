//! Extension id grammar and reserved names.

use crate::agent_config::KNOWN_CAPABILITIES;

/// Maximum byte length of an extension id (`[a-z][a-z0-9-]{0,31}`).
pub const EXTENSION_ID_MAX_LEN: usize = 32;

/// Names that are not valid extension ids, in addition to every
/// [`KNOWN_CAPABILITIES`] entry.
pub const RESERVED_EXTENSION_IDS: &[&str] = &["web", "data", "mcp"];

/// Reasons: `"empty"`, `"longer than 32 bytes"`, `"must start with a-z"`,
/// `"only a-z, 0-9 and '-' allowed"`, `"reserved"`. A trailing `-` is allowed.
pub fn check_extension_id(id: &str) -> Result<(), &'static str> {
    if id.is_empty() {
        return Err("empty");
    }
    if id.len() > EXTENSION_ID_MAX_LEN {
        return Err("longer than 32 bytes");
    }
    let mut chars = id.chars();
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() => {}
        _ => return Err("must start with a-z"),
    }
    if !id
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err("only a-z, 0-9 and '-' allowed");
    }
    if RESERVED_EXTENSION_IDS.contains(&id) || KNOWN_CAPABILITIES.contains(&id) {
        return Err("reserved");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_001_ac31_extension_ids_grammar_and_reserved() {
        for id in ["fixture", "fixture-two", "a", "x-"] {
            assert_eq!(check_extension_id(id), Ok(()), "{id}");
        }
        let thirty_two = "a".repeat(32);
        assert_eq!(thirty_two.len(), 32);
        assert_eq!(check_extension_id(&thirty_two), Ok(()));

        assert_eq!(check_extension_id(""), Err("empty"));
        assert_eq!(check_extension_id("Fixture"), Err("must start with a-z"));
        assert_eq!(check_extension_id("1x"), Err("must start with a-z"));
        assert_eq!(check_extension_id("-x"), Err("must start with a-z"));
        assert_eq!(
            check_extension_id("a.b"),
            Err("only a-z, 0-9 and '-' allowed")
        );
        assert_eq!(
            check_extension_id("a:b"),
            Err("only a-z, 0-9 and '-' allowed")
        );
        assert_eq!(
            check_extension_id("a/b"),
            Err("only a-z, 0-9 and '-' allowed")
        );
        assert_eq!(
            check_extension_id("a_b"),
            Err("only a-z, 0-9 and '-' allowed")
        );
        assert_eq!(
            check_extension_id(&"a".repeat(33)),
            Err("longer than 32 bytes")
        );

        for name in KNOWN_CAPABILITIES.iter().copied() {
            assert_eq!(check_extension_id(name), Err("reserved"), "{name}");
        }
        for name in RESERVED_EXTENSION_IDS {
            assert_eq!(check_extension_id(name), Err("reserved"), "{name}");
        }
    }
}

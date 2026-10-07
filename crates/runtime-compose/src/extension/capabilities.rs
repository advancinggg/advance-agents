//! Extension capability names: grammar, collisions, and the per-compose bound.

use crate::agent_config::KNOWN_CAPABILITIES;
use crate::api::{CapabilityRefusal, ComposeError};
use crate::effective_capabilities::{
    EXTENSION_CAPABILITY_MAX_LEN, MAX_EXTENSION_CAPABILITIES, RESERVED_CAPABILITY_NAMES,
};

/// One declared extension: `(id, its capabilities() slice)`, in registration order.
pub type Declaration = (&'static str, &'static [&'static str]);

const MALFORMED_COLON: &str = "contains ':', which cap-grant forbids";
const MALFORMED_GRAMMAR: &str = "not of the form <extension-id>.<name> (one '.', lowercase ASCII letters, digits, '_' or '-', at most 64 bytes)";

/// The name checks of one extension against the extensions before it.
/// First failure wins.
pub fn check_names(
    earlier: &[Declaration],
    id: &'static str,
    caps: &'static [&'static str],
) -> Result<(), ComposeError> {
    if caps.len() > MAX_EXTENSION_CAPABILITIES {
        return Err(refused(
            id,
            caps[MAX_EXTENSION_CAPABILITIES],
            CapabilityRefusal::TooMany {
                limit: MAX_EXTENSION_CAPABILITIES,
            },
        ));
    }
    for (index, name) in caps.iter().copied().enumerate() {
        if KNOWN_CAPABILITIES.contains(&name) || RESERVED_CAPABILITY_NAMES.contains(&name) {
            return Err(refused(id, name, CapabilityRefusal::Known));
        }
        if let Some(owner) = owner_in_earlier(earlier, name) {
            return Err(refused(
                id,
                name,
                CapabilityRefusal::OtherExtension { owner },
            ));
        }
        if caps[..index].contains(&name) {
            return Err(refused(id, name, CapabilityRefusal::Duplicate));
        }
        if name.contains(':') {
            return Err(refused(
                id,
                name,
                CapabilityRefusal::Malformed(MALFORMED_COLON),
            ));
        }
        if !well_formed(name) {
            return Err(refused(
                id,
                name,
                CapabilityRefusal::Malformed(MALFORMED_GRAMMAR),
            ));
        }
        let prefix = name
            .split_once('.')
            .expect("well_formed names have exactly one '.'")
            .0;
        if prefix != id {
            return Err(refused(id, name, CapabilityRefusal::ForeignPrefix));
        }
    }
    Ok(())
}

/// Once all extensions are checked: the per-compose bound over every declaration.
pub fn check_total(all: &[Declaration]) -> Result<(), ComposeError> {
    let mut count = 0;
    for (id, caps) in all {
        for name in *caps {
            count += 1;
            if count > MAX_EXTENSION_CAPABILITIES {
                return Err(refused(
                    id,
                    name,
                    CapabilityRefusal::TooMany {
                        limit: MAX_EXTENSION_CAPABILITIES,
                    },
                ));
            }
        }
    }
    Ok(())
}

fn owner_in_earlier(earlier: &[Declaration], name: &str) -> Option<&'static str> {
    earlier
        .iter()
        .find(|(_, caps)| caps.contains(&name))
        .map(|(owner, _)| *owner)
}

fn well_formed(name: &str) -> bool {
    if name.len() > EXTENSION_CAPABILITY_MAX_LEN {
        return false;
    }
    let mut parts = name.split('.');
    let Some(prefix) = parts.next() else {
        return false;
    };
    let Some(suffix) = parts.next() else {
        return false;
    };
    if parts.next().is_some() {
        return false;
    }
    charset_ok(prefix) && suffix_ok(suffix)
}

fn charset_ok(part: &str) -> bool {
    !part.is_empty()
        && part
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

fn suffix_ok(suffix: &str) -> bool {
    let mut chars = suffix.chars();
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() || c.is_ascii_digit() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

fn refused(extension: &'static str, capability: &str, reason: CapabilityRefusal) -> ComposeError {
    ComposeError::CapabilityCollision {
        extension,
        capability: capability.to_owned(),
        reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_collision(
        result: Result<(), ComposeError>,
        extension: &str,
        capability: &str,
        reason: CapabilityRefusal,
    ) {
        let err = match result {
            Err(err) => err,
            Ok(()) => panic!("expected CapabilityCollision, got Ok"),
        };
        match &err {
            ComposeError::CapabilityCollision {
                extension: got_ext,
                capability: got_cap,
                reason: got_reason,
            } => {
                assert_eq!(*got_ext, extension, "{err}");
                assert_eq!(got_cap, capability, "{err}");
                assert_eq!(got_reason, &reason, "{err}");
            }
            other => panic!("expected CapabilityCollision, got {other:?}"),
        }
        assert_eq!(
            err.to_string(),
            format!("extension {extension}: capability {capability} refused: {reason}")
        );
    }

    fn leaked_names(id: &'static str, n: usize) -> &'static [&'static str] {
        let names: Vec<&'static str> = (0..n)
            .map(|i| {
                let owned = format!("{id}.n{i:02}");
                Box::leak(owned.into_boxed_str()) as &'static str
            })
            .collect();
        Box::leak(names.into_boxed_slice())
    }

    #[test]
    fn module_001_ac31_check_names_order() {
        const OK: &[&str] = &["fixture.probe", "fixture.probe-2", "fixture.a_b"];
        check_names(&[], "fixture", OK).expect("valid names");
        check_names(&[], "fixture", &[]).expect("empty is identity");

        const FS: &[&str] = &["fs"];
        assert_collision(
            check_names(&[], "fixture", FS),
            "fixture",
            "fs",
            CapabilityRefusal::Known,
        );
        const WEB: &[&str] = &["web"];
        assert_collision(
            check_names(&[], "fixture", WEB),
            "fixture",
            "web",
            CapabilityRefusal::Known,
        );
        const DATA: &[&str] = &["data"];
        assert_collision(
            check_names(&[], "fixture", DATA),
            "fixture",
            "data",
            CapabilityRefusal::Known,
        );
        const MCP_SERVERS: &[&str] = &["mcp.servers"];
        assert_collision(
            check_names(&[], "fixture", MCP_SERVERS),
            "fixture",
            "mcp.servers",
            CapabilityRefusal::Known,
        );
        const MCP_PATTERNS: &[&str] = &["mcp.tool-patterns"];
        assert_collision(
            check_names(&[], "fixture", MCP_PATTERNS),
            "fixture",
            "mcp.tool-patterns",
            CapabilityRefusal::Known,
        );

        // Known before grammar: a reserved dotted name would otherwise be ForeignPrefix.
        const FS_THEN_COLON: &[&str] = &["fs", "fixture:probe"];
        assert_collision(
            check_names(&[], "fixture", FS_THEN_COLON),
            "fixture",
            "fs",
            CapabilityRefusal::Known,
        );

        const EARLIER_PROBE: Declaration = ("fixture", &["fixture.probe"]);
        const TWO_CLAIMS_PROBE: &[&str] = &["fixture.probe"];
        assert_collision(
            check_names(&[EARLIER_PROBE], "fixture-two", TWO_CLAIMS_PROBE),
            "fixture-two",
            "fixture.probe",
            CapabilityRefusal::OtherExtension { owner: "fixture" },
        );
        // OtherExtension before prefix, including when the current id matches the owner.
        assert_collision(
            check_names(&[EARLIER_PROBE], "fixture", TWO_CLAIMS_PROBE),
            "fixture",
            "fixture.probe",
            CapabilityRefusal::OtherExtension { owner: "fixture" },
        );

        const DUP: &[&str] = &["fixture.probe", "fixture.probe"];
        assert_collision(
            check_names(&[], "fixture", DUP),
            "fixture",
            "fixture.probe",
            CapabilityRefusal::Duplicate,
        );

        const COLON: &[&str] = &["fixture:probe"];
        assert_collision(
            check_names(&[], "fixture", COLON),
            "fixture",
            "fixture:probe",
            CapabilityRefusal::Malformed(MALFORMED_COLON),
        );

        const TWO_DOTS: &[&str] = &["fixture.a.b"];
        assert_collision(
            check_names(&[], "fixture", TWO_DOTS),
            "fixture",
            "fixture.a.b",
            CapabilityRefusal::Malformed(MALFORMED_GRAMMAR),
        );
        const UPPER_PREFIX: &[&str] = &["Fixture.probe"];
        assert_collision(
            check_names(&[], "fixture", UPPER_PREFIX),
            "fixture",
            "Fixture.probe",
            CapabilityRefusal::Malformed(MALFORMED_GRAMMAR),
        );
        const UPPER_SUFFIX: &[&str] = &["fixture.Probe"];
        assert_collision(
            check_names(&[], "fixture", UPPER_SUFFIX),
            "fixture",
            "fixture.Probe",
            CapabilityRefusal::Malformed(MALFORMED_GRAMMAR),
        );
        const BARE: &[&str] = &["probe"];
        assert_collision(
            check_names(&[], "fixture", BARE),
            "fixture",
            "probe",
            CapabilityRefusal::Malformed(MALFORMED_GRAMMAR),
        );
        const EMPTY_SUFFIX: &[&str] = &["fixture."];
        assert_collision(
            check_names(&[], "fixture", EMPTY_SUFFIX),
            "fixture",
            "fixture.",
            CapabilityRefusal::Malformed(MALFORMED_GRAMMAR),
        );
        const UNDERSCORE_SUFFIX: &[&str] = &["fixture._x"];
        assert_collision(
            check_names(&[], "fixture", UNDERSCORE_SUFFIX),
            "fixture",
            "fixture._x",
            CapabilityRefusal::Malformed(MALFORMED_GRAMMAR),
        );

        let long = format!("fixture.{}", "a".repeat(65 - "fixture.".len()));
        assert_eq!(long.len(), 65);
        let long_caps: &'static [&'static str] =
            Box::leak(vec![Box::leak(long.into_boxed_str()) as &'static str].into_boxed_slice());
        assert_collision(
            check_names(&[], "fixture", long_caps),
            "fixture",
            long_caps[0],
            CapabilityRefusal::Malformed(MALFORMED_GRAMMAR),
        );

        let ok64 = format!("fixture.{}", "a".repeat(64 - "fixture.".len()));
        assert_eq!(ok64.len(), 64);
        let ok64_caps: &'static [&'static str] =
            Box::leak(vec![Box::leak(ok64.into_boxed_str()) as &'static str].into_boxed_slice());
        check_names(&[], "fixture", ok64_caps).expect("64-byte name");

        const FOREIGN: &[&str] = &["fixture-two.x"];
        assert_collision(
            check_names(&[], "fixture", FOREIGN),
            "fixture",
            "fixture-two.x",
            CapabilityRefusal::ForeignPrefix,
        );

        let fifty_five = leaked_names("fixture", MAX_EXTENSION_CAPABILITIES + 1);
        assert_collision(
            check_names(&[], "fixture", fifty_five),
            "fixture",
            fifty_five[MAX_EXTENSION_CAPABILITIES],
            CapabilityRefusal::TooMany {
                limit: MAX_EXTENSION_CAPABILITIES,
            },
        );
        // The per-list bound is a cheap guard: it wins before Known on the first name.
        let too_many_known = {
            let mut names: Vec<&'static str> =
                leaked_names("fixture", MAX_EXTENSION_CAPABILITIES).to_vec();
            names.insert(0, "fs");
            Box::leak(names.into_boxed_slice()) as &'static [&'static str]
        };
        assert_eq!(too_many_known.len(), MAX_EXTENSION_CAPABILITIES + 1);
        assert_collision(
            check_names(&[], "fixture", too_many_known),
            "fixture",
            too_many_known[MAX_EXTENSION_CAPABILITIES],
            CapabilityRefusal::TooMany {
                limit: MAX_EXTENSION_CAPABILITIES,
            },
        );

        assert_eq!(
            CapabilityRefusal::Known.to_string(),
            "it is an OSS capability name"
        );
        assert_eq!(
            CapabilityRefusal::OtherExtension { owner: "fixture" }.to_string(),
            "extension fixture already declares it"
        );
        assert_eq!(CapabilityRefusal::Duplicate.to_string(), "declared twice");
        assert_eq!(
            CapabilityRefusal::Malformed(MALFORMED_COLON).to_string(),
            MALFORMED_COLON
        );
        assert_eq!(
            CapabilityRefusal::ForeignPrefix.to_string(),
            "its prefix is not this extension's id"
        );
        assert_eq!(
            CapabilityRefusal::TooMany {
                limit: MAX_EXTENSION_CAPABILITIES
            }
            .to_string(),
            format!("more than {MAX_EXTENSION_CAPABILITIES} extension capabilities")
        );
    }

    #[test]
    fn module_001_ac31_check_total_bound() {
        let first = leaked_names("fixture", 30);
        let second_ok = leaked_names("fixture-two", 24);
        check_total(&[("fixture", first), ("fixture-two", second_ok)])
            .expect("54 across two extensions");

        let second_over = leaked_names("fixture-two", 25);
        assert_collision(
            check_total(&[("fixture", first), ("fixture-two", second_over)]),
            "fixture-two",
            second_over[24],
            CapabilityRefusal::TooMany {
                limit: MAX_EXTENSION_CAPABILITIES,
            },
        );
    }
}

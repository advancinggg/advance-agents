//! T52 / T53 — MODULE-005-AC-31

use std::fs;
use std::process::Command;

#[test]
fn t52_single_display_name_writer() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let crates = root.join("crates");
    // The `display-name` key is defined ONCE (advance-home) and every production writer of
    // it goes through `TopLevelDisplayName::set`; no other crate spells the key.
    let output = Command::new("rg")
        .args(["--glob", "*.rs", r#""display-name""#])
        .arg(&crates)
        .output()
        .expect("rg");
    let text = String::from_utf8_lossy(&output.stdout);
    let spellings: Vec<_> = text
        .lines()
        .filter(|l| !l.contains("/tests/") && !l.contains("template_data.rs"))
        .collect();
    assert!(
        !spellings.is_empty(),
        "expected the DISPLAY_NAME_KEY definition"
    );
    assert!(
        spellings
            .iter()
            .all(|l| l.contains("advance-home") && l.contains("display_name.rs")),
        "{spellings:?}"
    );

    let callers = Command::new("rg")
        .args(["--glob", "*.rs", r"fn set_display_name|set_display_name\("])
        .arg(&crates)
        .output()
        .expect("rg callers");
    let caller_text = String::from_utf8_lossy(&callers.stdout);
    let first_open: Vec<_> = caller_text
        .lines()
        .filter(|l| {
            !l.contains("/tests/")
                && (l.contains("set_display_name(") || l.contains("fn set_display_name"))
        })
        .collect();
    assert!(
        first_open
            .iter()
            .any(|l| l.contains("advance-home") && l.contains("impls.rs")),
        "{first_open:?}"
    );
    assert!(
        first_open.iter().all(|l| {
            l.contains("advance-home")
                && (l.contains("impls.rs")
                    || l.contains("contract.rs")
                    || l.contains("display_name.rs"))
        }),
        "unexpected first-open writer: {first_open:?}"
    );
}

#[test]
fn t53_identity_is_runtime_resolved_not_hardcoded() {
    // The root's immutable id is minted/persisted by cap-lifecycle's identity module and its
    // handle is resolved at boot; no composition root pins a literal cap-layer id any more.
    let crates = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();
    let identity =
        fs::read_to_string(crates.join("capabilities/cap-lifecycle/src/identity.rs")).unwrap();
    assert!(identity.contains("pub const ID_KEY: &str = \"id\""));
    assert!(identity.contains("pub const ROOT_HANDLE: &str = \"root\""));
    let start = fs::read_to_string(crates.join("cli/src/commands/start.rs")).unwrap();
    assert!(!start.contains("let cap_agent_id = \"root\""));
    assert!(start.contains("let cap_agent_id = root_agent_id;"));
    let wiring = fs::read_to_string(crates.join("cli/src/wiring.rs")).unwrap();
    assert!(!wiring.contains("const DEFAULT_AGENT_ID"));
    assert!(wiring.contains("resolve_root_identity(workspace)"));
}

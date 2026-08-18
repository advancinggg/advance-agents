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
    let output = Command::new("rg")
        .args([
            "--glob",
            "*.rs",
            r#"join\("\.agent"\).*display-name|display-name"#,
        ])
        .arg(&crates)
        .output()
        .expect("rg");
    let text = String::from_utf8_lossy(&output.stdout);
    let path_builders: Vec<_> = text
        .lines()
        .filter(|l| l.contains("join") && l.contains("display-name") && !l.contains("/tests/"))
        .collect();
    assert!(
        !path_builders.is_empty(),
        "expected TopLevelDisplayName path builder"
    );
    assert!(
        path_builders
            .iter()
            .all(|l| l.contains("along-home") && l.contains("display_name.rs")),
        "{path_builders:?}"
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
            .any(|l| l.contains("along-home") && l.contains("impls.rs")),
        "{first_open:?}"
    );
    assert!(
        first_open.iter().all(|l| {
            l.contains("along-home")
                && (l.contains("impls.rs")
                    || l.contains("contract.rs")
                    || l.contains("display_name.rs"))
        }),
        "unexpected first-open writer: {first_open:?}"
    );
}

#[test]
fn t53_identity_constants() {
    assert_eq!(
        advance_along_home::TopLevelDisplayName::TREE_ID,
        "default-agent"
    );
    assert_eq!(
        advance_along_home::TopLevelDisplayName::MAILBOX_ID,
        "agent:default"
    );
    let start = fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("cli/src/commands/start.rs"),
    )
    .unwrap();
    assert!(start.contains("pub const DEFAULT_MSG_AGENT_ID: &str = \"agent:default\""));
    let wiring = fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("cli/src/wiring.rs"),
    )
    .unwrap();
    assert!(wiring.contains("const DEFAULT_AGENT_ID: &str = \"default-agent\""));
}

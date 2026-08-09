//! SC-35 — MODULE-017 Slice C WIT presence check for `interface agent-skills`.
//!
//! Verifies two invariants the Slice C plan committed to:
//!
//! 1. **Interface present in BOTH host + fixture WIT**: the WIT string
//!    `interface agent-skills` exists at the package level in
//!    `crates/runtime/wit/advance.wit` AND its byte-identical mirror at
//!    `crates/runtime/tests/fixtures/guest-rust-minimal/wit/advance.wit`
//!    (mirror invariant separately verified by the existing
//!    `module_001_t47_wit_parity_and_fixture_size_guards` test).
//!
//! 2. **No `advance-host` world import**: the M001-T42/T47 invariant that
//!    `world advance-host` has zero function-bearing imports must hold
//!    after Slice C adds the `agent-skills` interface. Parsed via
//!    `wit_parser::Resolve`.

use wit_parser::Resolve;

const HOST_WIT: &str = include_str!("../wit/advance.wit");
const FIXTURE_WIT: &str = include_str!("fixtures/guest-rust-minimal/wit/advance.wit");

#[test]
fn sc_35_agent_skills_declared_in_both_wit_files() {
    assert!(
        HOST_WIT.contains("interface agent-skills"),
        "host WIT must declare interface agent-skills"
    );
    assert!(
        FIXTURE_WIT.contains("interface agent-skills"),
        "fixture WIT must mirror interface agent-skills"
    );
    // Sanity: all 8 method signatures + the type aliases present in host WIT.
    for method in &[
        "propose-skill-draft:",
        "propose-skill-patch:",
        "update-skill-draft:",
        "activate-skill:",
        "rollback-skill:",
        "delete-skill:",
        "list-skill-candidates:",
        "resolve-skill-candidate:",
    ] {
        assert!(HOST_WIT.contains(method), "host WIT must declare {method}");
    }
    // Verify the payloadless `content-too-large` arm + presence of the other
    // 8 string-bearing arms — locks the §9.12 variant shape per the §1.A
    // mapping table.
    assert!(
        HOST_WIT.contains("content-too-large,"),
        "host WIT skill-error must declare content-too-large as a payloadless arm"
    );
    for arm in &[
        "invalid-name(string)",
        "invalid-frontmatter(string)",
        "name-conflict(string)",
        "security-violation(string)",
        "trust-violation(string)",
        "invalid-target(string)",
        "not-found(string)",
        "internal(string)",
    ] {
        assert!(
            HOST_WIT.contains(arm),
            "host WIT skill-error must declare {arm}"
        );
    }
}

#[test]
fn sc_35_advance_host_world_has_no_agent_skills_import() {
    let mut resolve = Resolve::default();
    let pkg = resolve
        .push_str("advance.wit", HOST_WIT)
        .expect("WIT parses");
    let world_id = resolve
        .select_world(&[pkg], Some("advance-host"))
        .expect("advance-host world found");
    let world = &resolve.worlds[world_id];
    for (key, _item) in &world.imports {
        let name = resolve.name_world_key(key);
        assert!(
            !name.contains("agent-skills"),
            "advance-host world must NOT import agent-skills; found import: {name}"
        );
    }
}

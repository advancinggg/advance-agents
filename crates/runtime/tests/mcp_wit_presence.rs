//! SB-20 — MODULE-017 Slice B WIT presence check.
//!
//! Verifies two invariants the plan committed to:
//!
//! 1. **Interface present in BOTH host + fixture WIT**: the WIT string
//!    `interface mcp-client` exists at the package level in
//!    `crates/runtime/wit/advance.wit` AND its byte-identical mirror at
//!    `crates/runtime/tests/fixtures/guest-rust-minimal/wit/advance.wit`
//!    (mirror invariant separately verified by the existing
//!    `module_001_t47_wit_parity_and_fixture_size_guards` test).
//!
//! 2. **No `advance-host` world import**: the M001-T47 invariant that
//!    `world advance-host` has zero function-bearing imports must
//!    still hold after Slice B adds the `mcp-client` interface. The
//!    test parses the host WIT via `wit_parser::Resolve` and inspects
//!    the world's `imports` map.

use wit_parser::Resolve;

const HOST_WIT: &str = include_str!("../wit/advance.wit");
const FIXTURE_WIT: &str = include_str!("fixtures/guest-rust-minimal/wit/advance.wit");

#[test]
fn sb_20_mcp_client_declared_in_both_wit_files() {
    assert!(
        HOST_WIT.contains("interface mcp-client"),
        "host WIT must declare interface mcp-client"
    );
    assert!(
        FIXTURE_WIT.contains("interface mcp-client"),
        "fixture WIT must mirror interface mcp-client"
    );
    // Sanity: all 7 method signatures present in host WIT.
    for method in &[
        "list-mcp-servers:",
        "list-mcp-tools:",
        "list-mcp-prompts:",
        "get-mcp-prompt:",
        "list-mcp-resources:",
        "read-mcp-resource:",
        "invoke-mcp-tool:",
    ] {
        assert!(HOST_WIT.contains(method), "host WIT must declare {method}");
    }
}

#[test]
fn sb_20_advance_host_world_has_no_mcp_client_import() {
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
            !name.contains("mcp-client"),
            "advance-host world must NOT import mcp-client; found import: {name}"
        );
    }
    // Also: ensure tool-related interfaces are NOT imported by the world
    // (consistent with M001-T47 zero-function-bearing-imports invariant).
    for (key, _item) in &world.imports {
        let name = resolve.name_world_key(key);
        assert!(
            !name.contains("tool-exports"),
            "advance-host world must NOT import tool-exports; found import: {name}"
        );
    }
}

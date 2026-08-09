//! AC-19 — Tier 2 ⑬ "Available Delegates" (T23: Sub-only filter +
//! sanitized capability summary + parallel coexistence with `# Available
//! Tools`).

use std::path::PathBuf;

use advance_context_engine::{
    format_available_delegates_section, format_available_delegates_section_with_aliases,
};
use advance_shared_types::agent_tree::{AgentId, AgentKind, AgentNode, AgentStatus, Capability};
use advance_shared_types::capability::{CapParams, CapabilityId};

#[path = "common/mod.rs"]
mod common;
use common::*;

fn cap(id: &str) -> Capability {
    Capability {
        id: CapabilityId::new(id),
        params: CapParams(serde_json::Value::Null),
    }
}

fn node(id: &str, kind: AgentKind, parent: &str, caps: Vec<Capability>) -> AgentNode {
    AgentNode {
        id: AgentId(id.into()),
        kind,
        parent: Some(AgentId(parent.into())),
        workspace_path: PathBuf::from("/ws"),
        capabilities: caps,
        template_ref: None,
        status: AgentStatus::Active,
    }
}

/// T23 — fixture tree with 2 Child + 2 Sub under "root"; one Sub's
/// capability id carries a BiDi/zero-width mark. Assert: only the 2 Subs
/// render (Child excluded); capability summaries are sanitized; the
/// `# Available Delegates` section coexists with `# Available Tools`
/// (parallel, not interleaved).
#[test]
fn t23_delegates_sub_only_sanitized_and_parallel() {
    let tree = FixtureTree {
        nodes: vec![
            node("child-1", AgentKind::Child, "root", vec![cap("fs.read")]),
            node("child-2", AgentKind::Child, "root", vec![cap("db.query")]),
            node(
                "sub-a",
                AgentKind::Sub,
                "root",
                vec![cap("fs.read"), cap("web.search")],
            ),
            // sub-b's capability id carries a zero-width space + BiDi RLO —
            // must be neutralized by the shared sanitize_description.
            node(
                "sub-b",
                AgentKind::Sub,
                "root",
                vec![cap("ev\u{200B}il\u{202E}cap")],
            ),
        ],
    };

    let section = format_available_delegates_section(&tree, "root");

    assert!(
        section.starts_with("# Available Delegates"),
        "header missing"
    );
    // Only the 2 Subs render; Children excluded.
    assert!(section.contains("- sub-a — "), "sub-a missing");
    assert!(section.contains("- sub-b — "), "sub-b missing");
    assert!(!section.contains("child-1"), "child-1 must be excluded");
    assert!(!section.contains("child-2"), "child-2 must be excluded");
    let delegate_lines = section.lines().filter(|l| l.starts_with("- ")).count();
    assert_eq!(delegate_lines, 2, "exactly 2 Sub delegates");

    // sub-a capability summary preserved (whitelist-charset → sanitizer
    // no-op in practice).
    assert!(section.contains("fs.read, web.search"));

    // sub-b crafted marks neutralized — raw ZWSP / RLO never emitted.
    assert!(
        !section.contains('\u{200B}'),
        "ZWSP must be sanitized out of the delegate section"
    );
    assert!(
        !section.contains('\u{202E}'),
        "BiDi RLO must be sanitized out of the delegate section"
    );
}

/// Round-10 Warning 2 regression lock: an invalid `agent_id` passed
/// directly to the pub fn returns the empty header (defensive guard;
/// no snapshot lookup with un-whitelisted bytes).
#[test]
fn invalid_agent_id_yields_empty_header_section() {
    let tree = FixtureTree {
        nodes: vec![node("sub-a", AgentKind::Sub, "root", vec![cap("fs.read")])],
    };
    for bad in &[
        "../etc/passwd",
        ";DROP TABLE",
        "id with spaces",
        "id\u{0000}NUL",
        "",
    ] {
        let section = format_available_delegates_section(&tree, bad);
        assert!(
            section.starts_with("# Available Delegates"),
            "header always emitted: bad={bad:?}"
        );
        assert_eq!(
            section.lines().filter(|l| l.starts_with("- ")).count(),
            0,
            "invalid agent_id must produce zero delegate lines: bad={bad:?}"
        );
    }
}

/// Round-10 Warning 5 regression lock: a Sub-agent with many long capability
/// ids has its joined summary CAPPED (per-id at 64 chars, total ≤ ~512
/// chars), not allowed to balloon unboundedly.
#[test]
fn capability_summary_is_length_capped() {
    let long = "x".repeat(200);
    let many_long_caps: Vec<_> = (0..100).map(|_| cap(&long)).collect();
    let tree = FixtureTree {
        nodes: vec![node("sub-big", AgentKind::Sub, "root", many_long_caps)],
    };
    let section = format_available_delegates_section(&tree, "root");
    let line = section
        .lines()
        .find(|l| l.starts_with("- sub-big — "))
        .expect("sub-big rendered");
    // Strip the "- sub-big — " prefix to inspect just the caps body.
    let caps_body = line.trim_start_matches("- sub-big — ");
    assert!(
        caps_body.len() < 600,
        "capability summary must be bounded: got {} bytes",
        caps_body.len()
    );
    // 200-char ids exceed MAX_CAP_ID_LEN=64 → each gets ellipsized.
    assert!(
        caps_body.contains('…'),
        "expected per-id truncation marker on >64-char ids"
    );
}

/// `# Available Delegates` coexists with `# Available Tools` in the
/// assembled output — parallel sections, both present, not merged.
#[tokio::test]
async fn delegates_and_tools_sections_coexist() {
    use advance_shared_types::context::ContextAssembler;

    let asm = build_assembler_with_empty_inventories();
    let result = asm.assemble(stub_ctx()).await.expect("assemble ok");

    let tools = result
        .messages
        .iter()
        .filter(|m| m.content.starts_with("# Available Tools"))
        .count();
    let delegates = result
        .messages
        .iter()
        .filter(|m| m.content.starts_with("# Available Delegates"))
        .count();
    assert_eq!(tools, 1, "exactly one # Available Tools section");
    assert_eq!(delegates, 1, "exactly one # Available Delegates section");
}

/// Wave-12 T-CE-ALIAS (SYS-AC-011) — the alias-aware variant matches a Sub
/// recorded under a BARE parent id even when the assemble turn runs under the
/// COLON id (the colon/bare bridge). The 2-arg single-id form does NOT; the
/// empty-alias form is byte-identical to the single-id form (back-compat).
#[test]
fn alias_aware_matches_sub_under_bare_parent_id() {
    // A Sub recorded under the BARE cap-id "default-agent" (as production
    // cap-lifecycle spawns do).
    let tree = FixtureTree {
        nodes: vec![node(
            "researcher",
            AgentKind::Sub,
            "default-agent",
            vec![cap("web.search")],
        )],
    };

    // Single-id under the COLON msg-id → MISS (the pre-Wave-12 production bug).
    let single = format_available_delegates_section(&tree, "agent:default");
    assert_eq!(
        single.lines().filter(|l| l.starts_with("- ")).count(),
        0,
        "colon-keyed single-id assemble misses the bare-keyed Sub"
    );

    // Alias-aware under the COLON msg-id WITH the {bare, colon} alias set → HIT.
    let aliases = vec!["default-agent".to_string(), "agent:default".to_string()];
    let aliased = format_available_delegates_section_with_aliases(&tree, "agent:default", &aliases);
    assert!(
        aliased.contains("- researcher — "),
        "alias bridge lists the Sub"
    );
    assert!(aliased.contains("web.search"));
    assert_eq!(
        aliased.lines().filter(|l| l.starts_with("- ")).count(),
        1,
        "exactly one delegate via the alias bridge"
    );

    // Empty alias set ⇒ byte-identical to the 2-arg single-id form.
    let empty_aliases =
        format_available_delegates_section_with_aliases(&tree, "agent:default", &[]);
    assert_eq!(
        empty_aliases, single,
        "empty aliases == single-id behaviour"
    );
}

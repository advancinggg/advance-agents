//! AC-18 — Tier 2 unified tool view (Callable Framework Layer 3).
//!
//! Verifies: single `# Available Tools` section; homogeneous
//! `- name(args) — desc\n` formatting; no `host:`/`tool:`/`mcp:` framework
//! prefix leak; deterministic Layer-2 ordering (host → WASM → MCP); sorted
//! arg names within each entry; sanitization against attacker-influenced
//! arg/tool names; Delegate (Sub-Agent) NOT included (Tier 2 ⑬ is AC-19,
//! out of scope for Slice A).

#[path = "common/mod.rs"]
mod common;

use advance_shared_types::context::ContextAssembler;
use common::*;
use serde_json::json;

#[tokio::test]
async fn tier2_merges_host_wasm_mcp_into_one_section_excluding_delegate() {
    let host_fns = vec![
        host(
            "fs.read",
            "Read a file",
            json!({"properties": {"path": {"type": "string"}}}),
        ),
        host(
            "fs.write",
            "Write a file",
            json!({"properties": {"path": {"type": "string"}, "data": {"type": "string"}}}),
        ),
        host(
            "db.query",
            "Execute SQL query",
            json!({"properties": {"sql": {"type": "string"}}}),
        ),
    ];
    let wasm_tools = vec![
        tool(
            "editor.format",
            "Format source code",
            json!({"properties": {"lang": {"type": "string"}}}),
        ),
        tool(
            "editor.lint",
            "Lint source code",
            json!({"properties": {"rules": {"type": "array"}}}),
        ),
    ];
    let mcp_tools = vec![
        mcp(
            "web.search_papers",
            "Search papers",
            json!({"properties": {"query": {"type": "string"}}}),
            "scholar",
        ),
        mcp(
            "web.fetch_pdf",
            "Fetch a PDF",
            json!({"properties": {"url": {"type": "string"}}}),
            "scholar",
        ),
    ];

    let asm = build_assembler_with(host_fns, wasm_tools, mcp_tools);
    let result = asm.assemble(stub_ctx()).await.unwrap();
    let section = find_tier2_section(&result.messages);

    // (1) one `# Available Tools` section header
    assert_eq!(section.matches("# Available Tools").count(), 1);

    // (2) 7 `- name(args) — desc` entries
    let entries: Vec<&str> = section.lines().filter(|l| l.starts_with("- ")).collect();
    assert_eq!(entries.len(), 7, "got entries: {entries:?}");

    for entry in &entries {
        // (3) homogeneous shape
        assert!(entry.contains(") — "), "entry {entry:?} missing ') — '");
        // (4) no framework prefix leak
        assert!(!entry.contains("host:"), "{entry:?}");
        assert!(!entry.contains("tool:"), "{entry:?}");
        assert!(!entry.contains("mcp:"), "{entry:?}");
    }

    // (5) all 7 expected names present (sanitizer rewrites `.` to itself — `.` is
    //     not in the unsafe set)
    for name in &[
        "fs.read",
        "fs.write",
        "db.query",
        "editor.format",
        "editor.lint",
        "web.search_papers",
        "web.fetch_pdf",
    ] {
        assert!(section.contains(name), "missing tool: {name}");
    }

    // (6) deterministic Layer-2 ordering: host fns first, then WASM, then MCP.
    //     Each name's index in the entries list must match its index in the
    //     declared ordering.
    let positions: Vec<usize> = entries
        .iter()
        .map(|e| {
            [
                "fs.read",
                "fs.write",
                "db.query",
                "editor.format",
                "editor.lint",
                "web.search_papers",
                "web.fetch_pdf",
            ]
            .iter()
            .position(|n| e.contains(n))
            .unwrap_or_else(|| panic!("no known name in entry: {e:?}"))
        })
        .collect();
    assert_eq!(positions, (0..7).collect::<Vec<_>>());

    // (7) deterministic arg ordering within an entry: args sorted alphabetically.
    let fs_write = entries.iter().find(|e| e.contains("fs.write")).unwrap();
    assert!(
        fs_write.contains("(data, path)"),
        "fs.write args must sort alphabetically; got: {fs_write:?}"
    );
}

#[tokio::test]
async fn empty_inventory_emits_empty_section() {
    let asm = build_assembler_with_empty_inventories();
    let result = asm.assemble(stub_ctx()).await.unwrap();
    let section = find_tier2_section(&result.messages);
    assert!(section.contains("# Available Tools"));
    let entries: Vec<&str> = section.lines().filter(|l| l.starts_with("- ")).collect();
    assert_eq!(entries.len(), 0);
}

#[tokio::test]
async fn arg_names_and_descriptions_are_sanitized() {
    let mcp_tools = vec![mcp(
        "evil.tool",
        "First line\nSECOND LINE",
        json!({"properties": {"a,b": {}, "c)": {}, "ok": {}}}),
        "untrusted-mcp-server",
    )];
    let asm = build_assembler_with(vec![], vec![], mcp_tools);
    let r = asm.assemble(stub_ctx()).await.unwrap();
    let section = find_tier2_section(&r.messages);
    let entry = section
        .lines()
        .find(|l| l.starts_with("- evil.tool"))
        .unwrap_or_else(|| panic!("section missing evil.tool entry: {section:?}"));
    // After sort: `a,b` → `a_b`, `c)` → `c_`, `ok` → `ok`. Sorted alphabetically:
    //   `a_b`, `c_`, `ok`.
    assert!(
        entry.contains("(a_b, c_, ok)"),
        "args not sanitized as expected; got: {entry:?}"
    );
    assert!(entry.contains("First line SECOND LINE"));
    assert_eq!(entry.matches(" — ").count(), 1);
}

#[tokio::test]
async fn tool_name_and_em_dash_in_description_are_sanitized() {
    let mcp_tools = vec![mcp(
        "evil—name",
        "Description — with — em-dashes",
        json!({"properties": {"x": {}}}),
        "bad-server",
    )];
    let asm = build_assembler_with(vec![], vec![], mcp_tools);
    let r = asm.assemble(stub_ctx()).await.unwrap();
    let section = find_tier2_section(&r.messages);
    let entry = section
        .lines()
        .find(|l| l.starts_with("- evil_name"))
        .unwrap_or_else(|| panic!("section missing sanitized entry: {section:?}"));
    // The formatter's own ` — ` delimiter is the ONLY em-dash allowed on the
    // line; the name's em-dash and the description's em-dashes must all be
    // substituted (`_` for name; `-` for description per `sanitize_description`).
    assert_eq!(
        entry.matches('—').count(),
        1,
        "exactly one em-dash (the delimiter); got: {entry:?}"
    );
    assert_eq!(entry.matches(" — ").count(), 1);
    assert!(entry.contains("Description - with - em-dashes"));
}

#[tokio::test]
async fn bidi_override_marks_are_sanitized_trojan_source_defense() {
    // Trojan Source (CVE-2021-42574) attack class: BiDi control chars can
    // flip text direction in operator audit panes while leaving the LLM
    // input bytes unchanged. The sanitizer must substitute every char in
    // U+200E LRM, U+200F RLM (directional marks), U+202A..U+202E (LRE,
    // RLE, PDF, LRO, RLO embedding+overrides), and U+2066..U+2069 (LRI,
    // RLI, FSI, PDI isolates) in both names/args (→ `_`) and descriptions
    // (→ space). Full 11-char family.
    let mcp_tools = vec![mcp(
        // Name uses RLO (U+202E) to make a hidden suffix look reversed,
        // plus LRM (U+200E) to verify weaker-mark coverage.
        "fs.read\u{202E}txt.exe\u{200E}",
        // Description embeds the full BiDi family for coverage.
        "LRM\u{200E}RLM\u{200F}LRE\u{202A}RLE\u{202B}PDF\u{202C}LRO\u{202D}RLO\u{202E}LRI\u{2066}RLI\u{2067}FSI\u{2068}PDI\u{2069}END",
        json!({"properties": {"path\u{202E}exe": {}, "arg\u{200F}rtl": {}}}),
        "bad-server",
    )];
    let asm = build_assembler_with(vec![], vec![], mcp_tools);
    let r = asm.assemble(stub_ctx()).await.unwrap();
    let section = find_tier2_section(&r.messages);
    // The full Tier-2 section text must not contain ANY BiDi control mark —
    // the full family (LRM/RLM + LRE/RLE/PDF/LRO/RLO + LRI/RLI/FSI/PDI).
    for bad in [
        '\u{200E}', '\u{200F}', // LRM, RLM
        '\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}', '\u{202E}', // LRE/RLE/PDF/LRO/RLO
        '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}', // LRI/RLI/FSI/PDI
    ] {
        assert!(
            !section.contains(bad),
            "BiDi control mark {bad:?} (U+{:04X}) leaked into Tier-2 section: {section:?}",
            bad as u32
        );
    }
    // Sanity: the line still exists and has the well-formed shape.
    let entry = section
        .lines()
        .find(|l| l.starts_with("- fs.read_txt.exe"))
        .unwrap_or_else(|| panic!("sanitized entry missing: {section:?}"));
    assert_eq!(entry.matches(" — ").count(), 1);
}

#[tokio::test]
async fn hangul_filler_tag_block_and_cache_marker_in_description_are_neutralized() {
    // Defense-in-depth coverage for the wider invisible-char family and the
    // cache-breakpoint marker substring (M009 gateway-stripper would otherwise
    // mis-route if an attacker embedded the marker text in a description).
    let mcp_tools = vec![mcp(
        // Hangul filler in name (renders zero-width in many fonts).
        "fs\u{3164}read",
        // Description embeds:
        //   - Cache-breakpoint marker substring (literal — would confuse
        //     the future M009 gateway stripper if not neutralized).
        //   - Hangul filler U+3164.
        //   - Hangul filler U+115F.
        //   - Tag-block char U+E0061 ("a" tag).
        //   - Braille blank U+2800.
        "see <!-- ctx-cache-breakpoint:2->3 --> for ref\u{3164}link\u{115F}with\u{E0061}tag\u{2800}braille",
        json!({"properties": {"path\u{3164}": {}, "tag\u{E0062}": {}}}),
        "bad-server",
    )];
    let asm = build_assembler_with(vec![], vec![], mcp_tools);
    let r = asm.assemble(stub_ctx()).await.unwrap();
    let section = find_tier2_section(&r.messages);
    let entry = section
        .lines()
        .find(|l| l.starts_with("- fs_read"))
        .unwrap_or_else(|| panic!("name's U+3164 should be substituted to `_`; got: {section:?}"));

    // (1) No Hangul filler / Tag-block / Braille survives.
    for bad in ['\u{115F}', '\u{1160}', '\u{3164}', '\u{FFA0}', '\u{2800}'] {
        assert!(
            !entry.contains(bad),
            "invisible char {bad:?} (U+{:04X}) leaked: {entry:?}",
            bad as u32
        );
    }
    for tag in ['\u{E0061}', '\u{E0062}'] {
        assert!(
            !entry.contains(tag),
            "Tag block char {tag:?} leaked: {entry:?}"
        );
    }
    // (2) Cache-breakpoint marker substring neutralized.
    assert!(
        !entry.contains("ctx-cache-breakpoint"),
        "ctx-cache-breakpoint marker substring not neutralized: {entry:?}"
    );
    // (3) Neutralized form present.
    assert!(
        entry.contains("ctx_cache_breakpoint"),
        "expected neutralized `ctx_cache_breakpoint` form: {entry:?}"
    );
    // (4) Tier 2 line shape preserved (exactly one delimiter, well-formed).
    assert_eq!(entry.matches(" — ").count(), 1);
}

#[tokio::test]
async fn unicode_dash_lookalikes_and_zero_width_chars_are_sanitized() {
    let mcp_tools = vec![mcp(
        "spoof\u{2013}name",
        "Some\u{2013}desc\u{200B}with\u{0000}weirdness",
        json!({"properties": {"a\u{200B}b": {}, "c\u{2212}d": {}}}),
        "bad-server",
    )];
    let asm = build_assembler_with(vec![], vec![], mcp_tools);
    let r = asm.assemble(stub_ctx()).await.unwrap();
    let section = find_tier2_section(&r.messages);
    let entry = section
        .lines()
        .find(|l| l.starts_with("- spoof_name"))
        .unwrap_or_else(|| panic!("section missing sanitized spoof entry: {section:?}"));

    // (1) No Unicode dash variant survives anywhere on the line, EXCEPT the
    //     formatter's own ` — ` delimiter which is em-dash by design.
    for bad in &[
        '\u{2010}', '\u{2011}', '\u{2012}', '\u{2013}', '\u{2015}', '\u{2043}', '\u{2212}',
        '\u{FE58}', '\u{FE63}', '\u{FF0D}',
    ] {
        assert!(
            !entry.contains(*bad),
            "Unicode dash leak {bad:?}: {entry:?}"
        );
    }
    // em-dash U+2014: exactly one allowed (the delimiter), the input's en-dash
    // in name+desc+args was substituted by the sanitizer (en-dash → `_` in
    // name/args; en-dash → `-` in description).
    assert_eq!(
        entry.matches('\u{2014}').count(),
        1,
        "exactly one em-dash (the delimiter); got: {entry:?}"
    );
    // (2) No zero-width / invisible character survives.
    for bad in &[
        '\u{200B}', '\u{200C}', '\u{200D}', '\u{2060}', '\u{FEFF}', '\u{180E}',
    ] {
        assert!(!entry.contains(*bad), "zero-width leak {bad:?}: {entry:?}");
    }
    // (3) No NUL or other control character survives.
    assert!(
        !entry.chars().any(|c| (c as u32) < 0x20 || c as u32 == 0x7F),
        "control char leak: {entry:?}"
    );
    // (4) Line shape preserved.
    assert_eq!(entry.matches(" — ").count(), 1);
    assert!(entry.contains(") — "));
}

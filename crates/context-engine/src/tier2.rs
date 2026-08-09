//! AC-18 Callable Framework Layer 3 — Tier 2 unified tool view.
//!
//! Merges the three Layer-2 Execution-Object kinds (host functions + WASM tools
//! + MCP tools) into a single `# Available Tools` Tier-2 markdown section with
//! homogeneous `- name(args) — desc\n` line shape. The Sub-Agent / Delegate
//! Layer-2 kind is explicitly NOT included here — it is presented separately
//! in Tier 2 ⑬ "Available Delegates" per PRD §3.10 dual positioning (covered
//! by AC-19, out of scope for Slice A).
//!
//! **CONTRACT-165 alignment**: the [`UnifiedToolRecord`] enum is a tagged
//! union of the three native struct types ([`HostFnEntry`],
//! [`advance_shared_types::capability::ToolEntry`],
//! [`advance_shared_types::capability::McpToolEntry`]) — discrimination is by
//! Rust enum variant, which IS "discrimination by struct type" at the
//! type-system level. The variant tag is the AC-18 `tool-source` metadata
//! field (so the runtime can route a call back to the correct ABI in a future
//! M014 dispatch slice).
//!
//! **Sanitization**: tool names, arg names, and descriptions are run through
//! defense-in-depth substitution sanitizers before formatting. The Tier-2
//! section is presented to the LLM, and attacker-influenced MCP server tools
//! could otherwise inject Unicode-dash spoofs (`evil–name` looks like
//! `evil-name`), zero-width name spoofs (`fs.read\u{200B}` looks like
//! `fs.read` to operator audit but is a distinct token to the LLM), or
//! line-shape-breaking delimiters (`,` `)` `\n`). Substitution preserves the
//! prompt's syntactic correctness for the LLM; MODULE-017's MCP server
//! registration path is the canonical place for outright rejection (out of
//! scope for Slice A — see MODULE-010 §3.6 Known Gaps row 2 for the dispatch
//! round-trip story).

use advance_shared_types::capability::{McpToolEntry, ToolEntry};

use crate::inventory::HostFnEntry;

/// MODULE-010 Layer-3 view — per-call merged inventory of every callable
/// surfaced into the agent's Tier-2 `# Available Tools` section. Each
/// variant carries its native source-type verbatim so the runtime dispatch
/// path (future M014 wiring slice) can match on the variant tag to route
/// back to the correct ABI.
#[derive(Clone, Debug, PartialEq)]
pub enum UnifiedToolRecord {
    HostFn(HostFnEntry),
    WasmTool(ToolEntry),
    McpTool(McpToolEntry),
}

impl UnifiedToolRecord {
    fn name(&self) -> &str {
        match self {
            Self::HostFn(e) => &e.name,
            Self::WasmTool(e) => &e.name,
            Self::McpTool(e) => &e.name,
        }
    }
    fn description(&self) -> &str {
        match self {
            Self::HostFn(e) => &e.description,
            Self::WasmTool(e) => &e.description,
            Self::McpTool(e) => &e.description,
        }
    }
    fn params_schema(&self) -> &serde_json::Value {
        match self {
            Self::HostFn(e) => &e.params_schema,
            Self::WasmTool(e) => &e.params_schema,
            Self::McpTool(e) => &e.params_schema,
        }
    }
}

/// Build the per-call unified tool inventory in deterministic Layer-2 order:
/// host fns first → WASM tools → MCP tools. Within each group the caller's
/// `Vec` insertion order is preserved (M017's `CallableInventoryReader`
/// implementations are responsible for ordering inside each group).
pub fn assemble_unified(
    host_fns: Vec<HostFnEntry>,
    wasm_tools: Vec<ToolEntry>,
    mcp_tools: Vec<McpToolEntry>,
) -> Vec<UnifiedToolRecord> {
    let mut out = Vec::with_capacity(host_fns.len() + wasm_tools.len() + mcp_tools.len());
    out.extend(host_fns.into_iter().map(UnifiedToolRecord::HostFn));
    out.extend(wasm_tools.into_iter().map(UnifiedToolRecord::WasmTool));
    out.extend(mcp_tools.into_iter().map(UnifiedToolRecord::McpTool));
    out
}

/// Render the unified inventory as a `# Available Tools` markdown section.
/// Per AC-18 invariants: single section header; homogeneous
/// `- name(args) — desc\n` line shape; no `host:` / `tool:` / `mcp:`
/// framework prefix leak (the variant tag is preserved out-of-band, NOT in
/// the entry text); deterministic ordering (host → WASM → MCP; args sorted
/// alphabetically for stability across `serde_json::Map` feature toggles).
pub fn format_available_tools_section(records: &[UnifiedToolRecord]) -> String {
    let mut s = String::from("# Available Tools\n\n");
    for r in records {
        let mut args = extract_top_level_arg_names(r.params_schema());
        args.sort();
        let sanitized_args: Vec<String> = args.into_iter().map(|a| sanitize_arg_name(&a)).collect();
        s.push_str(&format!(
            "- {}({}) — {}\n",
            sanitize_tool_name(r.name()),
            sanitized_args.join(", "),
            sanitize_description(r.description()),
        ));
    }
    s
}

fn extract_top_level_arg_names(schema: &serde_json::Value) -> Vec<String> {
    schema
        .get("properties")
        .and_then(|p| p.as_object())
        .map(|obj| obj.keys().cloned().collect())
        .unwrap_or_default()
}

/// Classifies a `char` as "would break the `- name(args) — desc\n` line shape
/// OR enable a spoofing / hiding attack against operator-side audit text".
/// Substituted with `_`. Single source of truth for arg + tool-name
/// sanitization. See module-level rustdoc + MODULE-010 §3.8 for rationale.
pub(crate) fn is_unsafe_for_tier2_line(c: char) -> bool {
    match c as u32 {
        0x00..=0x1F | 0x7F => return true,
        // BiDi control marks (Unicode Trojan Source — CVE-2021-42574 full class):
        // - U+200E LRM, U+200F RLM (directional marks — weaker than overrides
        //   but in the same family).
        // - U+202A LRE, U+202B RLE, U+202C PDF, U+202D LRO, U+202E RLO
        //   (embedding + override family).
        // - U+2066 LRI, U+2067 RLI, U+2068 FSI, U+2069 PDI (isolate family).
        // All 11 chars can flip text direction in operator audit panes while
        // leaving the LLM-visible byte sequence unchanged — same operator-vs-LLM
        // spoofing class as the zero-width chars in the explicit-match list below.
        0x200E..=0x200F | 0x202A..=0x202E | 0x2066..=0x2069 => return true,
        // Unicode Tag block (U+E0000..U+E007F) — Cf-class invisible characters
        // including U+E0001 LANGUAGE TAG + U+E0020..U+E007F TAG ASCII chars.
        // Used in the 2024 "ASCII smuggling" prompt-injection PoCs against
        // ChatGPT / Claude / Gemini (invisible to operator audit; LLMs may
        // tokenize them as distinct codepoints). Wider band than just U+E0001
        // because all Cf chars in this plane render zero-width.
        0xE0000..=0xE007F => return true,
        _ => {}
    }
    matches!(
        c,
        ','
            | '('
            | ')'
            // ASCII hyphen + every Unicode dash that looks like the ASCII
            // bullet prefix / ` — ` delimiter to operator audit text.
            | '-'
            | '\u{2010}'
            | '\u{2011}'
            | '\u{2012}'
            | '\u{2013}'
            | '\u{2014}'
            | '\u{2015}'
            | '\u{2043}'
            | '\u{2212}'
            | '\u{FE58}'
            | '\u{FE63}'
            | '\u{FF0D}'
            // Zero-width / invisible — visible to the LLM, invisible to
            // operator audit panes; enables silent tool-name spoofing.
            | '\u{200B}'
            | '\u{200C}'
            | '\u{200D}'
            | '\u{2060}'
            | '\u{FEFF}'
            | '\u{180E}'
            // Hangul fillers — render zero-width in operator audit text
            // (e.g. YouTube's "ㅤ" empty-username spoof). Distinct codepoints
            // to the LLM tokenizer; same hiding class as ZWSP/ZWNJ above.
            | '\u{115F}'
            | '\u{1160}'
            | '\u{3164}'
            | '\u{FFA0}'
            // Braille pattern blank — visible-but-empty; treated as space
            // by many fonts. Defense in depth against name-spoofing.
            | '\u{2800}'
            // Unicode line separators (treated like `\n`).
            | '\u{2028}'
            | '\u{2029}'
    )
}

fn sanitize_arg_name(s: &str) -> String {
    s.chars()
        .map(|c| if is_unsafe_for_tier2_line(c) { '_' } else { c })
        .collect()
}

fn sanitize_tool_name(s: &str) -> String {
    // Defense in depth at the formatter even though M017's
    // CallableInventoryReader registration boundary is the canonical place
    // for rejection. Substitute (not reject) so a well-formed line is always
    // produced; dispatch round-trip story deferred to future M014 wiring
    // slice — see MODULE-010 §3.6 Known Gaps row 2.
    s.chars()
        .map(|c| if is_unsafe_for_tier2_line(c) { '_' } else { c })
        .collect()
}

/// Cache-breakpoint marker prefix that the future M009 gateway stripper will
/// scan for (see `assembler.rs::TIER1B_TIER2_BREAKPOINT`/`TIER2_TIER3_BREAKPOINT`).
/// Defense-in-depth: even though the markers are emitted as standalone
/// `LlmMessage`s with their own `content`, an attacker-influenced description
/// or arg name could embed the literal substring and confuse the M009 stripper
/// into fragmenting cache regions or mis-translating to provider-native cache
/// hints. Sanitizers break this substring by replacing it with a `_`-only form.
pub(crate) const CACHE_BREAKPOINT_SENTINEL: &str = "ctx-cache-breakpoint";
pub(crate) const CACHE_BREAKPOINT_NEUTRALIZED: &str = "ctx_cache_breakpoint";

/// Neutralize the M009 gateway cache-breakpoint marker sentinel
/// (`ctx-cache-breakpoint` → `ctx_cache_breakpoint`) anywhere in `s`, so an
/// attacker who smuggled the literal marker substring into rendered content
/// cannot confuse the future M009 stripper into fragmenting cache regions.
///
/// **Byte-neutrality contract**: this is EXACTLY one substring `.replace` over
/// the two consts above, in that order — nothing else. `sanitize_description`'s
/// final step calls this so the char-only rendered-metadata path stays
/// byte-identical; the Stage-C SAT-E L4/L5 injection ingress
/// (`assembler::render_multilevel_digest`) applies it AFTER `layer2_wrap` to
/// preserve this defense (which `wrap_with_boundary` does not replicate). The
/// post-wrap application is envelope-safe — a plain substring replace touches
/// neither the `<data>` markup nor the U+200B closing-boundary defense.
pub(crate) fn neutralize_cache_breakpoint_markers(s: &str) -> String {
    s.replace(CACHE_BREAKPOINT_SENTINEL, CACHE_BREAKPOINT_NEUTRALIZED)
}

pub(crate) fn sanitize_description(s: &str) -> String {
    // Descriptions are body text — preserve most characters but collapse
    // line breaks to spaces (preserve word boundaries) and normalize Unicode
    // dashes to ASCII `-` so the ` — ` delimiter is unambiguous. Control
    // chars + zero-width + the full BiDi control family + Hangul fillers +
    // Tag block substitute to space (NOT `_`) since they're surrounded by
    // prose context. BiDi marks (U+200E LRM, U+200F RLM, U+202A..U+202E
    // overrides, U+2066..U+2069 isolates) are the Trojan Source
    // (CVE-2021-42574) attack class. Hangul fillers (U+115F/U+1160/U+3164/
    // U+FFA0), Braille blank (U+2800), and the Tag block (U+E0000..U+E007F)
    // are the wider zero-width / ASCII-smuggling family covered by the same
    // operator-vs-LLM threat model.
    let char_sanitized: String = s
        .chars()
        .map(|c| match c {
            '\n' | '\r' | '\u{2028}' | '\u{2029}' => ' ',
            '\u{2010}' | '\u{2011}' | '\u{2012}' | '\u{2013}' | '\u{2014}' | '\u{2015}'
            | '\u{2043}' | '\u{2212}' | '\u{FE58}' | '\u{FE63}' | '\u{FF0D}' => '-',
            '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{2060}' | '\u{FEFF}' | '\u{180E}' => ' ',
            // BiDi control marks (Trojan Source defense — full family
            // including LRM/RLM directional marks plus overrides + isolates).
            '\u{200E}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' => ' ',
            // Hangul fillers + Braille blank — render zero-width in many
            // fonts; substitute to space.
            '\u{115F}' | '\u{1160}' | '\u{3164}' | '\u{FFA0}' | '\u{2800}' => ' ',
            // Tag block (U+E0000..U+E007F) — ASCII smuggling defense.
            c if (c as u32) >= 0xE0000 && (c as u32) <= 0xE007F => ' ',
            c if (c as u32) < 0x20 || (c as u32) == 0x7F => ' ',
            c => c,
        })
        .collect();
    // Final defense: neutralize the M009 gateway cache-breakpoint marker
    // sentinel if an attacker embedded it in a description (descriptions
    // permit ASCII `-` so the substring survives char-level sanitization).
    neutralize_cache_breakpoint_markers(&char_sanitized)
}

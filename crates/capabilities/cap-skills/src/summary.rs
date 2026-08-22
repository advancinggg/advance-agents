//! Slice V1-c (2026-05-30) — `SKILL.md` first-paragraph summary extractor for
//! the L0 progressive-skill injection (MODULE-017 AC-27 / REQ-264, PRD §12.4.4).
//!
//! L0 = "inject ALL visible skills' SKILL.md summaries (first-paragraph,
//! ≤ 100 tokens each) into context by default". This module owns the
//! cap-skills side: turning a `SKILL.md` body into a short summary string.
//! The MODULE-010 context-engine side owns the Tier-2 ⑩ `# Available Skills`
//! injection + the aggregate budget cap (AC-15).
//!
//! Pure, additive, zero new dependencies.
//!
//! **Token estimate**: the cap is enforced with the shared
//! `advance_shared_types::token_estimate` ceil — `(len + 3) / 4`,
//! byte-identical to `advance_context_engine::assembler::chars_to_tokens`.

/// Maximum tokens for an L0 skill summary (AC-27: "first-paragraph, ≤ 100
/// tokens each").
pub const MAX_SKILL_SUMMARY_TOKENS: usize = 100;

/// Upper bound on how many bytes of the input the extractor scans before
/// paragraph extraction + allocation. The summary is truncated to ≤ 100 tokens
/// (~400 bytes) regardless, so a bounded prefix is far more than any legitimate
/// skill needs (frontmatter + headings + first paragraph). Defense-in-depth
/// (adversarial round 1 W3): `extract_skill_summary` is `pub`, so a future
/// caller could feed content outside the `SkillBundle::new` 50 KiB cap — this
/// bounds the transient allocation (and the `strip_frontmatter` scan) to a
/// constant regardless of input size.
const MAX_SCAN_BYTES: usize = 16 * 1024;

/// Extract the L0 summary from a `SKILL.md` body: the first non-empty
/// paragraph, truncated to ≤ [`MAX_SKILL_SUMMARY_TOKENS`] tokens.
///
/// Algorithm:
/// 1. Strip a leading YAML frontmatter block (`---` … `---`).
/// 2. Skip leading blank lines and Markdown ATX headings (`#`…`######`).
/// 3. Take the first paragraph (consecutive non-blank lines until a blank).
/// 4. Collapse interior whitespace (incl. the joined newlines) to single spaces.
/// 5. Truncate to ≤ `max_tokens` tokens at a char/word boundary (no ellipsis,
///    so the result is deterministically ≤ the byte budget).
///
/// Returns an empty string when the body has no prose paragraph (e.g. a
/// frontmatter-only or headings-only `SKILL.md`).
pub fn extract_skill_summary(skill_md: &str) -> String {
    extract_skill_summary_capped(skill_md, MAX_SKILL_SUMMARY_TOKENS)
}

/// [`extract_skill_summary`] with an explicit token cap (testing / future
/// callers that want a different budget).
pub fn extract_skill_summary_capped(skill_md: &str, max_tokens: usize) -> String {
    // Bound the scanned prefix BEFORE strip_frontmatter / the first-paragraph
    // join, so the transient allocation is a constant regardless of input size
    // (W3). Walk back to a UTF-8 char boundary.
    let mut scan_end = skill_md.len().min(MAX_SCAN_BYTES);
    while scan_end > 0 && !skill_md.is_char_boundary(scan_end) {
        scan_end -= 1;
    }
    let body = strip_frontmatter(&skill_md[..scan_end]);

    let mut para: Vec<&str> = Vec::new();
    for line in body.lines() {
        let t = line.trim();
        if para.is_empty() {
            // Still skipping leading blanks + ATX headings.
            if t.is_empty() || is_atx_heading(t) {
                continue;
            }
            para.push(t);
        } else if t.is_empty() {
            break; // first paragraph ends at the next blank line
        } else {
            para.push(t);
        }
    }

    let joined = collapse_ws(&para.join(" "));
    truncate_to_tokens(&joined, max_tokens)
}

/// Strip a leading YAML frontmatter block. A frontmatter block is a first
/// non-empty line of exactly `---` followed by a later closing `---` line.
/// Returns the slice AFTER the closing fence; if there is no well-formed
/// frontmatter, returns the input unchanged.
fn strip_frontmatter(s: &str) -> &str {
    let trimmed_start = s.trim_start_matches(['\u{feff}', '\n', '\r']);
    // Cheap path: only attempt if the body starts with `---`.
    let first_line_end = trimmed_start.find('\n').unwrap_or(trimmed_start.len());
    if trimmed_start[..first_line_end].trim() != "---" {
        return s;
    }
    // Find the closing `---` line.
    let mut idx = first_line_end;
    let bytes = trimmed_start.as_bytes();
    if idx < bytes.len() && bytes[idx] == b'\n' {
        idx += 1;
    }
    let mut search = &trimmed_start[idx..];
    let mut consumed = idx;
    loop {
        let line_end = search.find('\n').unwrap_or(search.len());
        if search[..line_end].trim() == "---" {
            // Return everything after this closing fence line.
            let after = consumed + line_end;
            let after = if after < trimmed_start.len() && trimmed_start.as_bytes()[after] == b'\n' {
                after + 1
            } else {
                after
            };
            return &trimmed_start[after..];
        }
        if line_end >= search.len() {
            // No closing fence — not valid frontmatter, keep original.
            return s;
        }
        consumed += line_end + 1;
        search = &search[line_end + 1..];
    }
}

/// A Markdown ATX heading line: 1–6 leading `#` then a space or end-of-line.
fn is_atx_heading(line: &str) -> bool {
    let hashes = line.bytes().take_while(|&b| b == b'#').count();
    if !(1..=6).contains(&hashes) {
        return false;
    }
    let rest = &line[hashes..];
    rest.is_empty() || rest.starts_with(' ') || rest.starts_with('\t')
}

/// Collapse all runs of ASCII/Unicode whitespace to a single space; trim ends.
fn collapse_ws(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Shared `chars/4` byte-length token estimate (`(len + 3) / 4`).
fn approx_tokens(byte_len: usize) -> usize {
    advance_shared_types::token_estimate::tokens_from_bytes(byte_len)
}

/// Truncate `s` so its token estimate is ≤ `max_tokens`. Prefers a trailing
/// word boundary; never splits a UTF-8 char. No ellipsis (so the byte budget
/// is honored exactly).
fn truncate_to_tokens(s: &str, max_tokens: usize) -> String {
    if approx_tokens(s.len()) <= max_tokens {
        return s.to_string();
    }
    // Largest byte budget whose estimate stays ≤ max_tokens: (n+3)/4 ≤ T → n ≤ 4T-3.
    let max_bytes = max_tokens.saturating_mul(4).saturating_sub(3);
    let mut end = max_bytes.min(s.len());
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    let cut = &s[..end];
    // Prefer the last word boundary if it doesn't discard more than half.
    let trimmed = match cut.rfind(char::is_whitespace) {
        Some(ws) if ws >= end / 2 => &cut[..ws],
        _ => cut,
    };
    trimmed.trim_end().to_string()
}

#[cfg(test)]
mod tests {
    //! White-box tests for the crate-private helpers. Black-box behavioral
    //! tests of the public `extract_skill_summary` live in `tests/summary.rs`.
    use super::*;

    #[test]
    fn is_atx_heading_requires_1_to_6_hashes_then_space_or_eol() {
        assert!(is_atx_heading("# h"));
        assert!(is_atx_heading("###### h"));
        assert!(is_atx_heading("#")); // bare hash, end-of-line
        assert!(!is_atx_heading("####### too many")); // 7 hashes
        assert!(!is_atx_heading("#tag")); // no space → not a heading
        assert!(!is_atx_heading("not a heading"));
    }

    #[test]
    fn strip_frontmatter_removes_well_formed_block_only() {
        assert_eq!(strip_frontmatter("---\na: 1\n---\nbody"), "body");
        // No closing fence → unchanged.
        assert_eq!(strip_frontmatter("---\na: 1\nbody"), "---\na: 1\nbody");
        // No leading `---` → unchanged.
        assert_eq!(strip_frontmatter("body\n---\n"), "body\n---\n");
    }

    #[test]
    fn approx_tokens_matches_workspace_rule() {
        // (len + 3) / 4, byte-identical to chars_to_tokens.
        assert_eq!(approx_tokens(0), 0);
        assert_eq!(approx_tokens(1), 1);
        assert_eq!(approx_tokens(4), 1);
        assert_eq!(approx_tokens(5), 2);
        assert_eq!(approx_tokens(397), 100);
        assert_eq!(approx_tokens(398), 100); // (398+3)/4 = 100 (integer)
    }

    #[test]
    fn truncate_respects_token_budget_at_word_boundary() {
        let long = (0..100)
            .map(|i| format!("word{i}"))
            .collect::<Vec<_>>()
            .join(" ");
        let s = truncate_to_tokens(&long, MAX_SKILL_SUMMARY_TOKENS);
        assert!(
            approx_tokens(s.len()) <= MAX_SKILL_SUMMARY_TOKENS,
            "len={}",
            s.len()
        );
        assert!(s.starts_with("word0 word1"));
        // Word-boundary cut → the tail is a complete token (no "wor…" fragment).
        assert!(!s.ends_with(' '));
        assert!(long.starts_with(&s));
    }

    #[test]
    fn truncate_keeps_short_input_verbatim() {
        assert_eq!(
            truncate_to_tokens("short", MAX_SKILL_SUMMARY_TOKENS),
            "short"
        );
    }

    #[test]
    fn huge_input_is_scan_bounded_and_capped() {
        // W3: a multi-MB single-paragraph body still yields a ≤100-token summary;
        // the extractor scans only MAX_SCAN_BYTES, never the whole input.
        let huge = "z".repeat(4 * 1024 * 1024);
        let s = extract_skill_summary(&huge);
        assert!(
            approx_tokens(s.len()) <= MAX_SKILL_SUMMARY_TOKENS,
            "len={}",
            s.len()
        );
        assert!(s.starts_with("zzz"));
    }
}

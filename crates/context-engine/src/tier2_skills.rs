//! Slice V1-c — Tier 2 ⑩ `# Available Skills` L0 skill-summary section (AC-15,
//! REQ-264; MODULE-017 AC-27 / PRD §12.4.4).
//!
//! Renders the visible skills' first-paragraph summaries (≤ 100 tokens each,
//! produced by cap-skills `extract_skill_summary`) into a Tier-2 markdown
//! section, capped at an aggregate token budget. This is the L0 leg of the
//! progressive-skill flow; the section is **distinct from** and **parallel to**
//! the AC-18 `# Available Tools` view (V1-b surface untouched).
//!
//! **Budget**: the caller passes `cap_tokens = min(skill_budget_tokens,
//! ⌊budget·0.05⌋, 10_000)` — AC-15's `min(budget·0.05, 10K)` is the hard
//! ceiling, `skill_budget_tokens` ([`SKILL_BUDGET_TOKENS_DEFAULT`]) the
//! in-ceiling soft target. When the aggregate would exceed the cap, the
//! lowest-`score` entries are dropped (AC-27 "truncate lowest-scoring first").

use crate::assembler::chars_to_tokens;
use crate::ports::SkillSummaryEntry;
use crate::tier2::sanitize_description;

/// MODULE-010 §2.10 `context.skill_budget_tokens` default — the in-ceiling soft
/// target for the aggregate L0 skill-summary section (AC-27). The effective cap
/// the assembler passes to [`format_available_skills_section`] is
/// `min(SKILL_BUDGET_TOKENS_DEFAULT, ⌊budget·0.05⌋, 10_000)` (the AC-15
/// `min(budget·0.05, 10K)` ceiling).
pub const SKILL_BUDGET_TOKENS_DEFAULT: u32 = 2000;

/// Per-summary token cap enforced AT THE FORMATTER (the injection trust
/// boundary). Defense-in-depth (adversarial round 1 W1): the formatter does NOT
/// trust the reader to have run cap-skills `extract_skill_summary` — a
/// forged / deserialized / non-extracted `SkillSummaryEntry` is re-bounded here
/// so no single oversized summary can starve the aggregate budget. Mirrors the
/// per-field caps the sibling Tier-2 sections enforce (AC-19 delegates
/// `MAX_SUMMARY_LEN`, AC-18 tools `MAX_TOOL_DESCRIPTION_BYTES`). Equals
/// cap-skills `MAX_SKILL_SUMMARY_TOKENS` (the two are independent constants by
/// the no-cross-crate-dep rule; both are 100 per AC-27).
pub const MAX_SKILL_SUMMARY_TOKENS: u32 = 100;

const HEADER: &str = "# Available Skills\n\n";

/// Build the Tier-2 ⑩ `# Available Skills` section from the visible skills'
/// L0 summaries, or `None` when there is nothing to inject.
///
/// - Entries are injected **highest-`score` first** (stable sort; equal scores
///   keep the reader's input order). When adding an entry would push the
///   section's token estimate over `cap_tokens`, that entry and every
///   lower-scoring one are dropped (AC-27 truncation).
/// - Each line is `- {name}: {summary}` with the shared Trojan-Source
///   [`sanitize_description`] applied to BOTH fields (skill content is
///   untrusted — same defense as the Tier-2 ⑬ delegate summaries).
/// - Returns `None` when `entries` is empty OR the cap admits zero entries —
///   the caller then emits **no** message (omit-when-empty), so an agent with no
///   visible skills produces byte-identical assembled output to pre-V1-c.
pub fn format_available_skills_section(
    entries: &[SkillSummaryEntry],
    cap_tokens: u32,
) -> Option<String> {
    if entries.is_empty() {
        return None;
    }

    // Highest score first (stable, so equal scores keep input order).
    // Defense-in-depth (adversarial round 1 W2): a non-finite `score` (±∞ / NaN)
    // is mapped to the lowest finite key so a malicious / forged value cannot
    // jump the truncation queue ahead of legitimate skills. `total_cmp` over the
    // sanitized finite keys is a panic-free total order.
    let mut ordered: Vec<&SkillSummaryEntry> = entries.iter().collect();
    ordered.sort_by(|a, b| finite_key(b.score).total_cmp(&finite_key(a.score)));

    let mut body = String::new();
    let mut any = false;
    for e in ordered {
        // Per-field trust-boundary caps: sanitize name + summary, then re-bound
        // the summary to ≤ MAX_SKILL_SUMMARY_TOKENS here (W1) — never trusting
        // the reader to have truncated, so one oversized summary cannot starve
        // the aggregate budget.
        let name = sanitize_description(&e.name);
        let summary =
            truncate_to_tokens(&sanitize_description(&e.summary), MAX_SKILL_SUMMARY_TOKENS);
        let line = format!("- {name}: {summary}\n");
        // Token estimate of the section content (header + accumulated body +
        // this candidate line). Counting the header is intentionally
        // conservative — the section never exceeds the assembler's allocated
        // skill budget.
        let candidate_len = HEADER.len() + body.len() + line.len();
        if chars_to_tokens(candidate_len) > cap_tokens {
            break; // drop this + every lower-scoring entry (AC-27)
        }
        body.push_str(&line);
        any = true;
    }

    if any {
        Some(format!("{HEADER}{body}"))
    } else {
        None
    }
}

/// Map a possibly-non-finite `score` to a finite ordering key (±∞ / NaN →
/// lowest priority) so the truncation sort is a deterministic total order an
/// attacker cannot hijack with `f32::INFINITY` (adversarial round 1 W2).
fn finite_key(score: f32) -> f32 {
    if score.is_finite() {
        score
    } else {
        f32::MIN
    }
}

/// Truncate `s` to ≤ `max_tokens` (chars/4 byte estimate) at a UTF-8 char
/// boundary, preferring a trailing word boundary; no ellipsis (keeps the byte
/// budget exact). Mirrors cap-skills `extract_skill_summary`'s truncation —
/// kept crate-local because context-engine cannot depend on cap-skills.
fn truncate_to_tokens(s: &str, max_tokens: u32) -> String {
    if chars_to_tokens(s.len()) <= max_tokens {
        return s.to_string();
    }
    // Largest byte budget whose estimate stays ≤ max_tokens: (n+3)/4 ≤ T → n ≤ 4T-3.
    let max_bytes = (max_tokens as usize).saturating_mul(4).saturating_sub(3);
    let mut end = max_bytes.min(s.len());
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    let cut = &s[..end];
    let trimmed = match cut.rfind(char::is_whitespace) {
        Some(ws) if ws >= end / 2 => &cut[..ws],
        _ => cut,
    };
    trimmed.trim_end().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, summary: &str, score: f32) -> SkillSummaryEntry {
        SkillSummaryEntry {
            name: name.into(),
            summary: summary.into(),
            score,
        }
    }

    #[test]
    fn empty_entries_yields_none() {
        assert_eq!(format_available_skills_section(&[], 2000), None);
    }

    #[test]
    fn renders_header_and_lines_under_cap() {
        let e = vec![
            entry("a", "alpha skill", 0.5),
            entry("b", "beta skill", 0.4),
        ];
        let s = format_available_skills_section(&e, 2000).expect("section");
        assert!(s.starts_with("# Available Skills\n\n"));
        assert!(s.contains("- a: alpha skill\n"));
        assert!(s.contains("- b: beta skill\n"));
        // Higher score first.
        assert!(s.find("- a:").unwrap() < s.find("- b:").unwrap());
    }

    #[test]
    fn highest_score_kept_first_on_truncation() {
        // Cap admits only the header + one line. The highest-score entry wins.
        let e = vec![
            entry("low", "x".repeat(40).as_str(), 0.1),
            entry("high", "y".repeat(40).as_str(), 0.9),
            entry("mid", "z".repeat(40).as_str(), 0.5),
        ];
        // header (20B) + one ~46B line → ~17 tokens; two lines → ~28. Cap at 20.
        let s = format_available_skills_section(&e, 20).expect("one fits");
        assert!(s.contains("- high:"), "highest score kept: {s}");
        assert!(!s.contains("- low:"), "lowest dropped: {s}");
        assert!(!s.contains("- mid:"), "mid dropped: {s}");
    }

    #[test]
    fn zero_cap_yields_none() {
        let e = vec![entry("a", "alpha", 1.0)];
        assert_eq!(format_available_skills_section(&e, 0), None);
    }

    #[test]
    fn untrusted_name_and_summary_are_sanitized() {
        // A BiDi override + newline in the summary must be neutralized.
        let e = vec![entry("nm", "line1\nline2\u{202E}evil", 1.0)];
        let s = format_available_skills_section(&e, 2000).expect("section");
        assert!(!s.contains('\u{202E}'), "BiDi override sanitized");
        // The interior newline is collapsed to a space (no mid-line break).
        assert_eq!(s.matches('\n').count(), 3); // 2 header newlines + 1 line terminator
    }

    #[test]
    fn oversized_summary_is_capped_at_the_formatter() {
        // W1: a reader/forged entry supplies a 1000-char summary (NOT run through
        // extract_skill_summary). The formatter must re-bound it to ≤100 tokens.
        let e = vec![entry("a", &"x".repeat(1000), 1.0)];
        let s = format_available_skills_section(&e, 2000).expect("section");
        let x_count = s.matches('x').count();
        assert!(
            x_count <= 4 * MAX_SKILL_SUMMARY_TOKENS as usize,
            "summary re-bounded to ≤100 tok (≤400 bytes), got {x_count} x's"
        );
        assert!(x_count > 0, "still renders the (truncated) summary");
    }

    #[test]
    fn non_finite_score_does_not_jump_the_truncation_queue() {
        // W2: an attacker sets score = +∞ to force top placement. finite_key maps
        // it to the LOWEST priority, so under a 1-line cap the finite-score skill
        // wins and the ∞-score one is dropped.
        let e = vec![
            entry("fin", "s", 0.5),
            entry("inf", "s", f32::INFINITY),
            entry("nan", "s", f32::NAN),
        ];
        // header(20B≈5tok) + one "- fin: s\n" (9B) → candidate (29B)=8 tok.
        let s = format_available_skills_section(&e, 8).expect("one fits");
        assert!(s.contains("- fin:"), "finite-score skill kept: {s}");
        assert!(
            !s.contains("- inf:"),
            "∞-score skill does NOT jump ahead: {s}"
        );
        assert!(
            !s.contains("- nan:"),
            "NaN-score skill does NOT jump ahead: {s}"
        );
    }
}

//! Slice V1-c — `extract_skill_summary` public-API behavioral tests
//! (MODULE-017 AC-27 / T29: first-paragraph ≤ 100-token summary extractor for
//! L0 progressive-skill injection). White-box helper tests live inline in
//! `src/summary.rs`.

use cap_skills::{extract_skill_summary, MAX_SKILL_SUMMARY_TOKENS};

/// Mirror of the crate's `chars/4` token estimate for the budget assertion.
fn approx_tokens(byte_len: usize) -> usize {
    byte_len.saturating_add(3) / 4
}

#[test]
fn first_paragraph_after_frontmatter_and_heading() {
    let md = "---\nname: web-search\ndescription: x\n---\n\n# Web Search\n\n\
              Search the web for papers using cap-http; writes results with cap-fs.\n\n\
              A second paragraph that must NOT appear in the L0 summary.\n";
    assert_eq!(
        extract_skill_summary(md),
        "Search the web for papers using cap-http; writes results with cap-fs."
    );
}

#[test]
fn skips_multiple_leading_headings() {
    let md = "# Title\n## Subtitle\nThe actual summary line.\n";
    assert_eq!(extract_skill_summary(md), "The actual summary line.");
}

#[test]
fn collapses_multiline_paragraph_to_single_spaces() {
    let md = "alpha\nbeta   gamma\n\nnext para";
    assert_eq!(extract_skill_summary(md), "alpha beta gamma");
}

#[test]
fn plain_prose_without_frontmatter() {
    assert_eq!(extract_skill_summary("just one line"), "just one line");
}

#[test]
fn empty_headings_only_or_frontmatter_only_yields_empty() {
    assert_eq!(extract_skill_summary(""), "");
    assert_eq!(extract_skill_summary("# only a heading\n"), "");
    assert_eq!(extract_skill_summary("---\nname: x\n---\n"), "");
}

#[test]
fn summary_is_capped_at_100_tokens() {
    // A 100-word paragraph is far over 100 tokens; the summary must be ≤ cap.
    let long = (0..100)
        .map(|i| format!("word{i}"))
        .collect::<Vec<_>>()
        .join(" ");
    let md = format!("# H\n\n{long}\n");
    let s = extract_skill_summary(&md);
    assert!(
        approx_tokens(s.len()) <= MAX_SKILL_SUMMARY_TOKENS,
        "summary len={} exceeds {MAX_SKILL_SUMMARY_TOKENS}-token budget",
        s.len()
    );
    assert!(!s.is_empty() && s.starts_with("word0 word1"));
}

#[test]
fn short_summary_passes_through_unchanged() {
    let md = "# Skill\n\nA short one-line summary.\n";
    assert_eq!(extract_skill_summary(md), "A short one-line summary.");
}

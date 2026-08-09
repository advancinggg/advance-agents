//! AC-05 — 4-tier cache-aware structure with exactly 2 cache breakpoints.

#[path = "common/mod.rs"]
mod common;

use advance_shared_types::context::ContextAssembler;
use common::*;

#[tokio::test]
async fn assemble_emits_two_cache_breakpoints_and_four_tier_counts() {
    let asm = build_assembler_with_empty_inventories();
    let result = asm.assemble(stub_ctx()).await.unwrap();

    let breakpoints: Vec<_> = result
        .messages
        .iter()
        .filter(|m| m.content.starts_with("<!-- ctx-cache-breakpoint:"))
        .collect();
    assert_eq!(
        breakpoints.len(),
        2,
        "expected 2 cache breakpoints (1b->2, 2->3); got {} (full messages: {:?})",
        breakpoints.len(),
        result
            .messages
            .iter()
            .map(|m| &m.content)
            .collect::<Vec<_>>(),
    );
    assert!(
        breakpoints[0].content.contains("1b->2"),
        "first breakpoint should be 1b->2, got: {:?}",
        breakpoints[0].content
    );
    assert!(
        breakpoints[1].content.contains("2->3"),
        "second breakpoint should be 2->3, got: {:?}",
        breakpoints[1].content
    );

    // TierTokenCounts has all four named fields populated as u32 (compile-time check).
    let tc = result.tier_token_counts;
    let _ = (tc.tier1a, tc.tier1b, tc.tier2, tc.tier3);

    // Tier-2 section is always emitted (header present even when empty).
    let section = find_tier2_section(&result.messages);
    assert!(section.contains("# Available Tools"));
}

#[tokio::test]
async fn tier_counts_include_cache_breakpoint_marker_tokens() {
    // The two breakpoint markers are attributed to the tier that precedes
    // them: marker 1 (1b->2) → tier1b's count, marker 2 (2->3) → tier 2's
    // count. So when tier 1a and tier 1b have NO content of their own, the
    // tier1b count is purely the marker's tokens — non-zero. Likewise tier 2
    // count must exceed `format_available_tools_section(&[])`'s tokens by
    // the second marker's tokens.
    let asm = build_assembler_with_empty_inventories();
    let result = asm.assemble(stub_ctx()).await.unwrap();
    let tc = &result.tier_token_counts;

    // tier1a empty (no content, no trailing breakpoint).
    assert_eq!(tc.tier1a, 0, "tier1a must be 0 when empty");
    // tier1b empty content + 1b->2 breakpoint marker → non-zero count.
    assert!(
        tc.tier1b > 0,
        "tier1b count must include the 1b->2 marker tokens; got {}",
        tc.tier1b
    );
    // tier2 includes the empty `# Available Tools\n\n` header plus the
    // 2->3 breakpoint marker.
    assert!(
        tc.tier2 > 0,
        "tier2 count must be non-zero (header + 2->3 marker)"
    );

    // The sum of all four tier counts should be roughly the total bytes of
    // the assembled messages (each tier's bytes / 4, summed). Validate the
    // sum is reasonable — equal to `total_bytes` chars/4 rule of thumb.
    let total_bytes: usize = result
        .messages
        .iter()
        .map(|m| m.role.len() + m.content.len())
        .sum();
    let expected = ((total_bytes + 3) / 4) as u32;
    let actual: u32 = tc.tier1a + tc.tier1b + tc.tier2 + tc.tier3;
    // The per-tier division can lose 1 token per tier due to integer math,
    // so the sum can be slightly less than the global computation. Assert
    // the actual sum is within 4 tokens of the expected (i.e. ≤ 4 lost
    // tokens, one per tier max).
    let diff = expected.abs_diff(actual);
    assert!(
        diff <= 4,
        "tier-count sum {actual} should be within ±4 of global {expected} \
         (bytes={total_bytes}); breakpoint tokens MUST be accounted for"
    );
}

//! AC-16 — Tier 1b ⑨ knowledge-map section (§1.3.3 ⑨ / §2.10 / §2.11).
//!
//! **Spec boundary**: the spec mandates *only three caps* — ≤ 500 tokens
//! (§1.3.3 ⑨ / §2.10 `knowledge_map_max_tokens`, hard), ≤ 10 topics, ≤ 5
//! task_syntheses (§2.11). It does NOT prescribe a drop-order when the token
//! cap binds against the count caps. The drop-order below is a **documented
//! Slice-B implementation choice** (MODULE-010 §3.8), not a spec mandate —
//! the AC only requires the three caps hold + determinism.
//!
//! Algorithm:
//! 1. `effective_cap = min(budget_tokens, KNOWLEDGE_MAP_MAX_TOKENS)` — 500 is
//!    the §1.3.3 ⑨ hard ceiling; a tighter caller budget wins.
//! 2. Count caps first (keep head = producer priority order): topics → ≤ 10,
//!    syntheses → ≤ 5.
//! 3. Token cap second: render header, then topics, then syntheses, greedily
//!    adding a piece only while the cumulative `chars/4` estimate stays ≤
//!    `effective_cap`. **Syntheses are processed AFTER topics**, so a tight
//!    budget drops syntheses before topics (topics are short navigational
//!    anchors; syntheses are long-form, reconstructable from L5). If the
//!    FIRST topic alone would exceed the cap, its text is hard-truncated at
//!    the token boundary so output is NEVER > cap.
//! 4. A trailing `… (knowledge-map truncated)` marker is appended when
//!    anything was dropped or clipped (cache-stability observability).
//!
//! Every rendered topic/synthesis string is routed through the shared
//! `pub(crate)` [`crate::tier2::sanitize_description`] BEFORE token
//! accumulation — knowledge-map content is untrusted (MODULE-011-authored
//! from agent turns), and the cap math must count post-sanitization bytes.
//!
//! Pure + deterministic: same input → byte-identical output (T20 asserts
//! this; it is the actual precedence proof).

use crate::assembler::chars_to_tokens;
use crate::ports::KnowledgeMap;
use crate::tier2::sanitize_description;

/// §1.3.3 ⑨ / §2.10 hard token ceiling for the knowledge-map section.
pub const KNOWLEDGE_MAP_MAX_TOKENS: usize = 500;

/// §2.11 max topics.
pub const MAX_TOPICS: usize = 10;

/// §2.11 max task syntheses.
pub const MAX_TASK_SYNTHESES: usize = 5;

const HEADER: &str = "# Knowledge Map\n";
const TRUNCATION_MARKER: &str = "\n… (knowledge-map truncated)";

/// Build the Tier 1b ⑨ knowledge-map section. Returns `(section, truncated)`
/// where `truncated` is `true` iff any entry was dropped (count-cap or
/// token-cap) or clipped. The section's `chars/4` token estimate is
/// guaranteed `<= min(budget_tokens, KNOWLEDGE_MAP_MAX_TOKENS)`.
pub fn build_knowledge_map_section(km: &KnowledgeMap, budget_tokens: usize) -> (String, bool) {
    let effective_cap = budget_tokens.min(KNOWLEDGE_MAP_MAX_TOKENS);

    // Reserve the truncation marker UP FRONT so the final string (content +
    // marker, when truncated) is ALWAYS <= effective_cap — the "output is
    // never > cap" invariant must hold INCLUDING the marker.
    let header_tokens = chars_to_tokens(HEADER.len()) as usize;
    let marker_tokens = chars_to_tokens(TRUNCATION_MARKER.len()) as usize;

    // **Small-budget escape hatch** (round-6 AUDIT Warning 1): if
    // `effective_cap` is too small to fit even the header, emit nothing.
    // Returning an empty string preserves the "never > cap" invariant for
    // ANY caller budget (including 0) without invalidating the AC-16
    // criterion (which is bounded by the §1.3.3⑨ hard 500-token cap,
    // never <header_tokens in practice — but `build_knowledge_map_section`
    // is `pub` and a future caller may pass a tighter progressive-load
    // budget). `truncated=true` signals the caller that the section was
    // squelched.
    if effective_cap < header_tokens {
        return (String::new(), true);
    }

    // After the header fits, `content_cap` reserves room for the marker too
    // — but only if `effective_cap` is large enough to fit BOTH header and
    // marker. If not, `content_cap` falls back to `effective_cap -
    // header_tokens` and we will conditionally suppress the marker at append
    // time so the output never exceeds the cap.
    let content_cap = effective_cap.saturating_sub(marker_tokens);

    // ── Step 2: count caps first (keep head). Track whether they bit.
    let count_truncated =
        km.topics.len() > MAX_TOPICS || km.task_syntheses.len() > MAX_TASK_SYNTHESES;
    let topics = &km.topics[..km.topics.len().min(MAX_TOPICS)];
    let syntheses = &km.task_syntheses[..km.task_syntheses.len().min(MAX_TASK_SYNTHESES)];

    // ── Step 3: token cap. Header always fits past the escape hatch above;
    // content greedily added while it fits within `content_cap`.
    let mut out = String::from(HEADER);
    let mut token_truncated = false;
    let mut first_content = true;

    // Topics before syntheses → syntheses naturally dropped first under a
    // tight budget (documented drop-order).
    for t in topics {
        let line = format!(
            "- {}: {}\n",
            sanitize_description(&t.name),
            sanitize_description(&t.body)
        );
        if chars_to_tokens(out.len() + line.len()) as usize <= content_cap {
            out.push_str(&line);
        } else if first_content {
            // Hard-truncate the FIRST content piece at the token boundary so
            // output is never > cap (clip, don't drop, the first entry).
            let header_tokens = chars_to_tokens(out.len()) as usize;
            let remaining_tokens = content_cap.saturating_sub(header_tokens);
            // chars/4 ⇒ keep ~ remaining_tokens*4 chars; back off to a char
            // boundary so the surviving string is valid UTF-8.
            let mut keep = remaining_tokens.saturating_mul(4).min(line.len());
            while keep > 0 && !line.is_char_boundary(keep) {
                keep -= 1;
            }
            out.push_str(&line[..keep]);
            token_truncated = true;
            break;
        } else {
            token_truncated = true;
            break;
        }
        first_content = false;
    }

    // Syntheses only if topics did not exhaust the budget.
    if !token_truncated {
        for s in syntheses {
            let line = format!(
                "- [{}] {}\n",
                sanitize_description(&s.task_id),
                sanitize_description(&s.body)
            );
            if chars_to_tokens(out.len() + line.len()) as usize <= content_cap {
                out.push_str(&line);
            } else {
                token_truncated = true;
                break;
            }
        }
    }

    let truncated = count_truncated || token_truncated;
    if truncated {
        // The marker is appended only when its bytes fit under `effective_cap`
        // (large budgets: `content_cap` reservation guarantees room; small
        // budgets where header+marker doesn't fit: marker is silently dropped
        // rather than overshooting the cap). The `truncated` flag is still
        // returned for caller observability either way.
        if (chars_to_tokens(out.len() + TRUNCATION_MARKER.len()) as usize) <= effective_cap {
            out.push_str(TRUNCATION_MARKER);
        }
    }

    (out, truncated)
}

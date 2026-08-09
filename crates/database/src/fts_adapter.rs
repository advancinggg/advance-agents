//! FTS5 keyword extraction + MATCH expression construction + rank-to-similarity
//! mapping for MODULE-004 Slice C. Used by the recall pipeline (`recall.rs`)
//! when building the sparse-path query against `content_fts`.
//!
//! - [`extract_keywords`]: tokenize a free-text query into searchable keywords
//!   (ASCII-lowercase, split on whitespace + ASCII punctuation, drop short tokens).
//! - [`build_match_expression`]: assemble an FTS5 `MATCH` expression that ORs
//!   the keywords (per AC-12 OR semantics).
//! - [`score_from_fts_rank`]: monotone-non-decreasing map of FTS5 BM25 rank
//!   (more-negative = more relevant) to similarity score in `[0, 1)`.

use std::collections::HashSet;

const MAX_KEYWORDS: usize = 16;
const MIN_KEYWORD_LEN: usize = 2;
/// Maximum bytes of any single keyword. Round-14 (adversarial) finding:
/// without this cap, a single very long token (gigabytes of input) would
/// be lowercased + cloned into the keyword Vec then concatenated into the
/// FTS5 MATCH expression, giving a caller-controlled memory/parse-cost
/// DoS path. 128 bytes is more than ample for any natural-language token.
const MAX_KEYWORD_LEN: usize = 128;

/// Extract searchable keywords from a free-text query.
///
/// - ASCII-lowercase
/// - Split on whitespace + ASCII punctuation
/// - Drop tokens shorter than [`MIN_KEYWORD_LEN`]
/// - De-duplicate while preserving first-seen order
/// - Truncate to at most [`MAX_KEYWORDS`] tokens
pub fn extract_keywords(query: &str) -> Vec<String> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut out: Vec<String> = Vec::new();
    for raw in query.split(|c: char| c.is_whitespace() || c.is_ascii_punctuation()) {
        if raw.is_empty() || raw.len() > MAX_KEYWORD_LEN {
            // Round-14 hardening: drop oversized tokens BEFORE allocating the
            // owned String — to_ascii_lowercase clones, so checking after
            // would already have paid the alloc cost.
            continue;
        }
        let kw = raw.to_ascii_lowercase();
        if kw.len() < MIN_KEYWORD_LEN {
            continue;
        }
        if seen.insert(kw.clone()) {
            out.push(kw);
            if out.len() >= MAX_KEYWORDS {
                break;
            }
        }
    }
    out
}

/// Build an FTS5 `MATCH` expression that ORs the keywords. Each keyword is
/// double-quoted (FTS5 escape rule for tokens that may contain punctuation).
/// Empty input → returns empty string; the caller is responsible for skipping
/// the sparse path when this returns empty.
///
/// FTS5 double-quoting rules: a literal `"` inside a quoted token is escaped
/// by doubling (`""`). [`extract_keywords`] strips ASCII punctuation, so this
/// is a defense-in-depth path for callers that bypass the standard tokenizer.
pub fn build_match_expression(keywords: &[String]) -> String {
    if keywords.is_empty() {
        return String::new();
    }
    let escaped: Vec<String> = keywords
        .iter()
        .map(|kw| format!("\"{}\"", kw.replace('"', "\"\"")))
        .collect();
    escaped.join(" OR ")
}

/// Map an FTS5 BM25 rank to a similarity score in `[0, 1)`. FTS5 ranks are
/// monotone-decreasing-with-relevance: the most-relevant row has the
/// most-negative rank. Mapping: `r / (1 + r)` where `r = max(0, -rank)`.
///
/// - rank = 0   → 0.0     (no/weak match — sub-r-zero ranks clamp to zero)
/// - rank = -1  → 0.5
/// - rank = -10 → ~0.91
/// - rank = -100 → ~0.99
/// - rank = +1 (anomaly)  → 0.0  (defense-in-depth; clamp positive ranks)
pub fn score_from_fts_rank(rank: f64) -> f32 {
    let r = (-rank).max(0.0) as f32;
    if !r.is_finite() {
        return 0.0;
    }
    r / (1.0 + r)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_keywords_basic() {
        let kws = extract_keywords("Apple Banana Cherry");
        assert_eq!(kws, vec!["apple", "banana", "cherry"]);
    }

    #[test]
    fn extract_keywords_dedupes() {
        let kws = extract_keywords("apple apple banana");
        assert_eq!(kws, vec!["apple", "banana"]);
    }

    #[test]
    fn extract_keywords_drops_short_tokens() {
        let kws = extract_keywords("a apple bb banana");
        assert_eq!(kws, vec!["apple", "bb", "banana"]);
    }

    #[test]
    fn extract_keywords_splits_on_punctuation() {
        let kws = extract_keywords("apple,banana;cherry.dragon");
        assert_eq!(kws, vec!["apple", "banana", "cherry", "dragon"]);
    }

    #[test]
    fn extract_keywords_empty() {
        assert!(extract_keywords("").is_empty());
        assert!(extract_keywords("  ,.;  ").is_empty());
    }

    #[test]
    fn build_match_expression_or_semantics() {
        let kws = vec!["apple".into(), "banana".into()];
        assert_eq!(build_match_expression(&kws), "\"apple\" OR \"banana\"");
    }

    #[test]
    fn build_match_expression_single() {
        let kws = vec!["apple".into()];
        assert_eq!(build_match_expression(&kws), "\"apple\"");
    }

    #[test]
    fn build_match_expression_empty() {
        let kws: Vec<String> = vec![];
        assert_eq!(build_match_expression(&kws), "");
    }

    #[test]
    fn score_from_fts_rank_monotone() {
        let s_minus_1 = score_from_fts_rank(-1.0);
        let s_minus_10 = score_from_fts_rank(-10.0);
        let s_minus_100 = score_from_fts_rank(-100.0);
        assert!((s_minus_1 - 0.5).abs() < 1e-6);
        assert!(s_minus_10 > s_minus_1);
        assert!(s_minus_100 > s_minus_10);
        assert!(s_minus_100 < 1.0);
    }

    #[test]
    fn score_from_fts_rank_clamps_positive() {
        assert_eq!(score_from_fts_rank(0.0), 0.0);
        assert_eq!(score_from_fts_rank(1.0), 0.0);
        assert_eq!(score_from_fts_rank(100.0), 0.0);
    }

    #[test]
    fn score_from_fts_rank_handles_nan_inf() {
        assert_eq!(score_from_fts_rank(f64::NAN), 0.0);
        assert_eq!(score_from_fts_rank(f64::NEG_INFINITY), 0.0);
        assert_eq!(score_from_fts_rank(f64::INFINITY), 0.0);
    }

    #[test]
    fn extract_keywords_drops_oversized_tokens() {
        // Round-14 (adversarial): a single very long token must be dropped,
        // not lowercased + cloned + emitted. We craft a 200-byte token plus
        // a 5-byte token and assert only the short one is returned.
        let big = "a".repeat(200);
        let q = format!("{big} apple");
        let kws = extract_keywords(&q);
        assert_eq!(kws, vec!["apple"]);
    }
}

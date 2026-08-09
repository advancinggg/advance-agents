//! Wave-13 Lane C — the omit-when-empty recall renderer (MODULE-010 §3.8
//! Wave-13 Lane C). Renders a [`UnifiedSearchResult`] into a single Tier-3
//! `# Recalled Context` section, boundary-marked exactly like the SAT-E
//! untrusted-digest precedent (`assembler::render_multilevel_digest`).
//!
//! **Omit-when-empty**: returns `None` when all 4 result vecs are empty, so the
//! caller emits NO message and the assembled output for the no-recall path is
//! byte-identical (the flip-zero linchpin; same convention as `tier2_skills` /
//! `tier2_decomposition`). Recalled ids are producer-derived but routed through
//! the shared Trojan-Source [`sanitize_description`] + a module-local byte-cap as
//! defense-in-depth, and the whole section body is wrapped via the canonical
//! CONTRACT-114 [`layer2_wrap`] (`TrustLevel::Untrusted`) — so the §3.6
//! Layer-2-marking sub-clause is genuinely closed and future text-snippet
//! enrichment inherits a hardened envelope.

use advance_shared_types::security_validator::{PromptInjectionHelpers, TrustLevel};

use crate::boundary_marker::layer2_wrap;
use crate::ports::UnifiedSearchResult;
use crate::tier2::{neutralize_cache_breakpoint_markers, sanitize_description};

/// Per-field byte cap before sanitization (defense-in-depth; mirrors
/// `tier2_decomposition::MAX_FIELD_LEN`, which is module-private and so
/// re-created locally). Bounds an adversarial-length id; UTF-8 char-boundary
/// truncation, no suffix.
const MAX_FIELD_LEN: usize = 128;

/// CONTRACT-114 boundary `source` tag for the recall section.
const RECALL_SOURCE: &str = "memory:recall";

/// Render the unified-search recall hits into a single Tier-3 `# Recalled
/// Context` section, or `None` when there are no hits (omit-when-empty →
/// byte-identical empty-state). Each id is byte-capped + `sanitize_description`'d;
/// the whole body is `layer2_wrap`'d (Untrusted) + cache-breakpoint-neutralized
/// (so the envelope is present only when a content-bearing `helpers` is
/// injected — production holds the real `DefaultPromptInjectionHelpers`).
pub(crate) fn format_recall_section(
    result: &UnifiedSearchResult,
    helpers: &dyn PromptInjectionHelpers,
) -> Option<String> {
    if result.tasks.is_empty()
        && result.turns.is_empty()
        && result.contents.is_empty()
        && result.memories.is_empty()
    {
        return None;
    }

    let mut body = String::from("# Recalled Context\n\n");
    if !result.contents.is_empty() {
        body.push_str("## Files\n");
        for h in &result.contents {
            body.push_str(&format!(
                "- {} ({:.3})\n",
                clean_id(&h.id),
                h.adjusted_score
            ));
        }
    }
    if !result.memories.is_empty() {
        body.push_str("## Memory\n");
        for h in &result.memories {
            body.push_str(&format!(
                "- {} ({:.3})\n",
                clean_id(&h.id),
                h.adjusted_score
            ));
        }
    }
    if !result.tasks.is_empty() {
        body.push_str("## Related Tasks\n");
        for h in &result.tasks {
            body.push_str(&format!(
                "- {} ({:.3})\n",
                clean_id(&h.task_id),
                h.similarity
            ));
        }
    }
    if !result.turns.is_empty() {
        body.push_str("## Related Turns\n");
        for h in &result.turns {
            body.push_str(&format!("- {} ({:.3})\n", clean_id(&h.id), h.similarity));
        }
    }

    // Boundary-mark the whole untrusted body (CONTRACT-114), then preserve the
    // cache-breakpoint defense — exact SAT-E `render_multilevel_digest` precedent.
    let wrapped = neutralize_cache_breakpoint_markers(&layer2_wrap(
        &body,
        RECALL_SOURCE,
        TrustLevel::Untrusted,
        helpers,
    ));
    Some(wrapped)
}

/// Byte-cap then sanitize a producer-derived id (defense-in-depth).
fn clean_id(id: &str) -> String {
    sanitize_description(&truncate_to(id, MAX_FIELD_LEN))
}

/// UTF-8-safe truncation to at most `max` bytes (steps back to a char boundary).
/// Module-local — `tier2_decomposition`'s `truncate_to` is not `pub`.
fn truncate_to(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut keep = max;
    while keep > 0 && !s.is_char_boundary(keep) {
        keep -= 1;
    }
    s[..keep].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::{ContentHit, MemoryHit, TaskHit, TurnHit};
    use advance_shared_types::security_validator::InjectionFlag;
    use std::time::SystemTime;

    // Content-bearing fake CONTRACT-114 helper (mirrors
    // `injection_ingress::FakeWrapHelper`): proves the renderer routes the body
    // through `wrap_with_boundary` with the right source + trust.
    struct FakeWrapHelper;
    impl PromptInjectionHelpers for FakeWrapHelper {
        fn flag_injection_patterns(&self, _content: &str) -> Vec<InjectionFlag> {
            Vec::new()
        }
        fn wrap_with_boundary(&self, content: &str, source: &str, trust: TrustLevel) -> String {
            let t = match trust {
                TrustLevel::Trusted => "trusted",
                TrustLevel::Untrusted => "untrusted",
            };
            format!("[[WRAP src={source} trust={t}]]{content}[[/WRAP]]")
        }
    }

    #[test]
    fn empty_returns_none() {
        assert!(format_recall_section(&UnifiedSearchResult::default(), &FakeWrapHelper).is_none());
    }

    #[test]
    fn renders_all_four_arms_inside_untrusted_envelope() {
        let result = UnifiedSearchResult {
            tasks: vec![TaskHit {
                task_id: "task-1".into(),
                similarity: 0.5,
                last_turn_at: None,
            }],
            turns: vec![TurnHit {
                id: "turn-1".into(),
                task_id: "task-9".into(),
                similarity: 0.4,
                timestamp: SystemTime::UNIX_EPOCH,
            }],
            contents: vec![ContentHit {
                id: "file-1".into(),
                adjusted_score: 0.91,
            }],
            memories: vec![MemoryHit {
                id: "mem-1".into(),
                adjusted_score: 0.88,
            }],
        };
        let s = format_recall_section(&result, &FakeWrapHelper).expect("non-empty ⇒ Some");
        assert!(
            s.starts_with("[[WRAP src=memory:recall trust=untrusted]]"),
            "wrap envelope: {s}"
        );
        assert!(s.ends_with("[[/WRAP]]"));
        assert!(s.contains("# Recalled Context"));
        assert!(s.contains("## Files"));
        assert!(s.contains("- file-1 (0.910)"));
        assert!(s.contains("## Memory"));
        assert!(s.contains("- mem-1 (0.880)"));
        assert!(s.contains("## Related Tasks"));
        assert!(s.contains("- task-1 (0.500)"));
        assert!(s.contains("## Related Turns"));
        assert!(s.contains("- turn-1 (0.400)"));
    }

    #[test]
    fn sanitizes_trojan_source_in_id() {
        let result = UnifiedSearchResult {
            memories: vec![MemoryHit {
                id: "evil\u{202E}id\u{200B}".into(),
                adjusted_score: 0.5,
            }],
            ..Default::default()
        };
        let s = format_recall_section(&result, &FakeWrapHelper).expect("Some");
        assert!(!s.contains('\u{202E}'), "BiDi override must be stripped");
        assert!(!s.contains('\u{200B}'), "zero-width must be stripped");
    }

    #[test]
    fn renders_only_non_empty_kinds() {
        let result = UnifiedSearchResult {
            memories: vec![MemoryHit {
                id: "mem-1".into(),
                adjusted_score: 0.7,
            }],
            ..Default::default()
        };
        let s = format_recall_section(&result, &FakeWrapHelper).expect("Some");
        assert!(s.contains("## Memory"));
        assert!(!s.contains("## Files"));
        assert!(!s.contains("## Related Tasks"));
        assert!(!s.contains("## Related Turns"));
    }
}

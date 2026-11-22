//! Wave-13 Lane C — the omit-when-empty recall renderers (MODULE-010 §3.8
//! Wave-13 Lane C), split by where PRD §11.3.2 puts each source:
//!
//! - ⑮ `# Recalled Context` ([`format_recall_section`]): the contents and
//!   memories recall found;
//! - ⑭ `# Related Task Briefs` ([`format_related_task_briefs`]): the briefs of
//!   other tasks the message resembles (§11.3.1 L5);
//! - ⑯ the lines of `# Related Turns` ([`related_turn_lines`]): other tasks'
//!   turns, which the assembler sets in Tier 3 with the ones it loads whole.
//!
//! **Omit-when-empty**: a section with nothing to show is `None`, so the caller
//! emits NO message (the flip-zero linchpin; same convention as `tier2_skills` /
//! `tier2_decomposition`). Recalled ids are producer-derived but routed through
//! the shared Trojan-Source [`sanitize_description`] + a module-local byte-cap as
//! defense-in-depth, and every body is wrapped via the canonical CONTRACT-114
//! [`layer2_wrap`] (`TrustLevel::Untrusted`).

use advance_shared_types::security_validator::{PromptInjectionHelpers, TrustLevel};

use crate::boundary_marker::layer2_wrap;
use crate::ports::{TaskHit, TurnHit, UnifiedSearchResult};
use crate::tier2::{neutralize_cache_breakpoint_markers, sanitize_description};

/// Per-field byte cap before sanitization (defense-in-depth; mirrors
/// `tier2_decomposition::MAX_FIELD_LEN`, which is module-private and so
/// re-created locally). Bounds an adversarial-length id; UTF-8 char-boundary
/// truncation, no suffix.
const MAX_FIELD_LEN: usize = 128;

/// Byte cap for a producer-supplied snippet (digest / brief / preview). A turn
/// digest is a one-sentence summary; this bounds an adversarial producer.
const MAX_SNIPPET_LEN: usize = 320;

/// CONTRACT-114 boundary `source` tag for the recall section.
const RECALL_SOURCE: &str = "memory:recall";

/// CONTRACT-114 boundary `source` tag for the related task briefs.
const RELATED_TASK_BRIEFS_SOURCE: &str = "memory:related_task_briefs";

/// PRD §11.3.1 `RELATED_TASK_MIN_THRESHOLD`: a task's brief is shown as related
/// only from this similarity up ("防止弱查询噪音").
pub const RELATED_TASK_MIN_THRESHOLD: f32 = 0.3;

/// PRD §11.3.1 L5: at most this many related task briefs.
pub const MAX_RELATED_TASK_BRIEFS: usize = 3;

/// The heading of the ⑭ related task briefs section.
pub(crate) const RELATED_TASK_BRIEFS_HEADER: &str =
    "# Related Task Briefs\nOther tasks of this agent the message resembles, with what each is about.";

/// ⑮ (PRD §11.3.2): the contents and memories recall found, in one `# Recalled
/// Context` section, or `None` when there are none (omit-when-empty →
/// byte-identical empty-state). Each id is byte-capped + `sanitize_description`'d;
/// the whole body is `layer2_wrap`'d (Untrusted) + cache-breakpoint-neutralized
/// (so the envelope is present only when a content-bearing `helpers` is
/// injected — production holds the real `DefaultPromptInjectionHelpers`).
pub(crate) fn format_recall_section(
    result: &UnifiedSearchResult,
    helpers: &dyn PromptInjectionHelpers,
) -> Option<String> {
    if result.contents.is_empty() && result.memories.is_empty() {
        return None;
    }
    let mut body = String::from("# Recalled Context\n\n");
    if !result.contents.is_empty() {
        body.push_str("## Files\n");
        for h in &result.contents {
            body.push_str(&line(&h.id, h.adjusted_score, h.snippet.as_deref()));
        }
    }
    if !result.memories.is_empty() {
        body.push_str("## Memory\n");
        for h in &result.memories {
            body.push_str(&line(&h.id, h.adjusted_score, h.snippet.as_deref()));
        }
    }
    // Boundary-mark the whole untrusted body (CONTRACT-114), then preserve the
    // cache-breakpoint defense — exact SAT-E `render_multilevel_digest` precedent.
    Some(wrap(&body, RECALL_SOURCE, helpers))
}

/// ⑭ L5 (PRD §11.3.1): of `tasks` (other tasks than the turn's own: the coordinator
/// drops it), the up to [`MAX_RELATED_TASK_BRIEFS`] whose similarity to the message
/// is at least [`RELATED_TASK_MIN_THRESHOLD`], in the order recall ranked them. A task
/// with no brief has nothing to show and takes no place.
pub(crate) fn related_task_briefs(tasks: &[TaskHit]) -> Vec<&TaskHit> {
    tasks
        .iter()
        .filter(|t| t.similarity.is_finite() && t.similarity >= RELATED_TASK_MIN_THRESHOLD)
        .filter(|t| {
            t.snippet
                .as_deref()
                .is_some_and(|brief| !brief.trim().is_empty())
        })
        .take(MAX_RELATED_TASK_BRIEFS)
        .collect()
}

/// ⑭ L5: the `# Related Task Briefs` section of `briefs` ([`related_task_briefs`]), or
/// `None` when there are none.
pub(crate) fn format_related_task_briefs(
    briefs: &[&TaskHit],
    helpers: &dyn PromptInjectionHelpers,
) -> Option<String> {
    let lines: String = briefs
        .iter()
        .map(|t| line(&t.task_id, t.similarity, t.snippet.as_deref()))
        .collect();
    if lines.is_empty() {
        return None;
    }
    Some(format!(
        "{RELATED_TASK_BRIEFS_HEADER}\n{}",
        wrap(&lines, RELATED_TASK_BRIEFS_SOURCE, helpers)
    ))
}

/// ⑯ (PRD §11.3.5 "跨 Task 历史"): one line per turn of another task loaded as its
/// digest — `- {task}#turn-{n} ({similarity:.3}) — {digest}` — for the assembler to
/// wrap with the turns it loads whole.
pub(crate) fn related_turn_lines(turns: &[&TurnHit]) -> String {
    turns
        .iter()
        .map(|h| line(&h.id, h.similarity, h.snippet.as_deref()))
        .collect()
}

/// `body` boundary-marked as untrusted (CONTRACT-114) from `source`, with the
/// cache-breakpoint defense.
fn wrap(body: &str, source: &str, helpers: &dyn PromptInjectionHelpers) -> String {
    neutralize_cache_breakpoint_markers(&layer2_wrap(body, source, TrustLevel::Untrusted, helpers))
}

/// One recall line: `- {id} ({score:.3})`, plus ` — {snippet}` when the
/// producer supplied a non-blank snippet (byte-capped + sanitized; the shared
/// sanitizer flattens newlines so a multi-line digest stays one list item).
fn line(id: &str, score: f32, snippet: Option<&str>) -> String {
    let mut s = format!("- {} ({:.3})", clean_id(id), score);
    if let Some(text) = snippet {
        let cleaned = sanitize_description(&truncate_to(text, MAX_SNIPPET_LEN));
        if !cleaned.trim().is_empty() {
            s.push_str(" — ");
            s.push_str(cleaned.trim());
        }
    }
    s.push('\n');
    s
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

    fn turn(id: &str, task: &str, similarity: f32, snippet: Option<&str>) -> TurnHit {
        TurnHit {
            id: id.into(),
            task_id: task.into(),
            similarity,
            timestamp: SystemTime::UNIX_EPOCH,
            snippet: snippet.map(str::to_string),
            turn: None,
            retention: None,
        }
    }

    fn task(id: &str, similarity: f32, brief: Option<&str>) -> TaskHit {
        TaskHit {
            task_id: id.into(),
            similarity,
            last_turn_at: None,
            snippet: brief.map(str::to_string),
        }
    }

    #[test]
    fn empty_returns_none() {
        assert!(format_recall_section(&UnifiedSearchResult::default(), &FakeWrapHelper).is_none());
        // Tasks and turns have sections of their own (⑭, ⑯): ⑮ shows neither.
        let elsewhere = UnifiedSearchResult {
            tasks: vec![task("task-1", 0.9, Some("a brief"))],
            turns: vec![turn("task-9#turn-1", "task-9", 0.8, Some("a digest"))],
            ..Default::default()
        };
        assert!(format_recall_section(&elsewhere, &FakeWrapHelper).is_none());
    }

    #[test]
    fn renders_contents_and_memories_inside_untrusted_envelope() {
        let result = UnifiedSearchResult {
            tasks: vec![task("task-1", 0.5, None)],
            turns: vec![turn("turn-1", "task-9", 0.4, None)],
            contents: vec![ContentHit {
                id: "file-1".into(),
                adjusted_score: 0.91,
                snippet: None,
            }],
            memories: vec![MemoryHit {
                id: "mem-1".into(),
                adjusted_score: 0.88,
                snippet: None,
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
        assert!(!s.contains("task-1"));
        assert!(!s.contains("turn-1"));
    }

    #[test]
    fn renders_snippets_single_line_and_capped() {
        let result = UnifiedSearchResult {
            memories: vec![MemoryHit {
                id: "mem-7".into(),
                adjusted_score: 0.73,
                snippet: Some("prefers the\nshort form".into()),
            }],
            contents: vec![ContentHit {
                id: "file-2".into(),
                adjusted_score: 0.6,
                snippet: Some("x".repeat(MAX_SNIPPET_LEN + 40)),
            }],
            ..Default::default()
        };
        let s = format_recall_section(&result, &FakeWrapHelper).expect("Some");
        assert!(
            s.contains("- mem-7 (0.730) — prefers the short form"),
            "snippet is appended single-line: {s}"
        );
        assert!(!s.contains(&"x".repeat(MAX_SNIPPET_LEN + 1)));
        assert!(s.contains(&"x".repeat(MAX_SNIPPET_LEN)));
        // A blank snippet adds nothing after the score.
        let blank = UnifiedSearchResult {
            memories: vec![MemoryHit {
                id: "m".into(),
                adjusted_score: 0.5,
                snippet: Some("   ".into()),
            }],
            ..Default::default()
        };
        let s = format_recall_section(&blank, &FakeWrapHelper).expect("Some");
        assert!(s.contains("- m (0.500)\n"));
    }

    #[test]
    fn sanitizes_trojan_source_in_id() {
        let result = UnifiedSearchResult {
            memories: vec![MemoryHit {
                id: "evil\u{202E}id\u{200B}".into(),
                adjusted_score: 0.5,
                snippet: None,
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
                snippet: None,
            }],
            ..Default::default()
        };
        let s = format_recall_section(&result, &FakeWrapHelper).expect("Some");
        assert!(s.contains("## Memory"));
        assert!(!s.contains("## Files"));
    }

    /// PRD §11.3.1 L5: at most three other tasks, from 0.3 up, each with its brief, in the
    /// order recall ranked them; the heading is the runtime's, the briefs are wrapped.
    #[test]
    fn related_task_briefs_keep_three_tasks_from_the_threshold_up() {
        let tasks = vec![
            task("task-a", 0.81, Some("plans the spring garden")),
            task("task-b", 0.62, None),
            task("task-c", 0.55, Some("   ")),
            task("task-d", 0.47, Some("orders seed packets")),
            task("task-e", 0.30, Some("waters the\nseedlings")),
            task("task-f", 0.29, Some("below the threshold")),
            task("task-g", f32::NAN, Some("not a score")),
        ];
        let s = format_related_task_briefs(&related_task_briefs(&tasks), &FakeWrapHelper)
            .expect("Some");
        assert!(s.starts_with(RELATED_TASK_BRIEFS_HEADER), "{s}");
        assert!(s.contains("[[WRAP src=memory:related_task_briefs trust=untrusted]]"));
        assert!(s.contains("- task-a (0.810) — plans the spring garden\n"));
        assert!(s.contains("- task-d (0.470) — orders seed packets\n"));
        assert!(s.contains("- task-e (0.300) — waters the seedlings\n"));
        for left_out in ["task-b", "task-c", "task-f", "task-g"] {
            assert!(!s.contains(left_out), "{left_out}: {s}");
        }
        assert!(s.find("task-a") < s.find("task-d") && s.find("task-d") < s.find("task-e"));

        let four = vec![
            task("task-1", 0.9, Some("one")),
            task("task-2", 0.8, Some("two")),
            task("task-3", 0.7, Some("three")),
            task("task-4", 0.6, Some("four")),
        ];
        let s =
            format_related_task_briefs(&related_task_briefs(&four), &FakeWrapHelper).expect("Some");
        assert!(s.contains("task-3") && !s.contains("task-4"), "{s}");

        let none = vec![task("task-x", 0.2, Some("weak")), task("task-y", 0.9, None)];
        assert!(format_related_task_briefs(&related_task_briefs(&none), &FakeWrapHelper).is_none());
        assert!(format_related_task_briefs(&[], &FakeWrapHelper).is_none());
    }

    #[test]
    fn related_turn_lines_are_single_line_and_capped() {
        let a = turn(
            "task-9#turn-7",
            "task-9",
            0.73,
            Some("deployed the\nservice"),
        );
        let b = turn(
            "task-8#turn-2",
            "task-8",
            0.41,
            Some(&"y".repeat(MAX_SNIPPET_LEN + 9)),
        );
        let c = turn("task-7#turn-1", "task-7", 0.35, None);
        let s = related_turn_lines(&[&a, &b, &c]);
        assert!(
            s.contains("- task-9#turn-7 (0.730) — deployed the service\n"),
            "{s}"
        );
        assert!(
            s.contains(&"y".repeat(MAX_SNIPPET_LEN))
                && !s.contains(&"y".repeat(MAX_SNIPPET_LEN + 1))
        );
        assert!(s.ends_with("- task-7#turn-1 (0.350)\n"), "{s}");
    }
}

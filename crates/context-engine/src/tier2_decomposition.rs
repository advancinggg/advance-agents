//! Tier 2 ⑭ — "Active Task Decomposition" (PRD §4.2.2 / MODULE-010 §1.4.3 ⑭).
//!
//! Renders the active task's **non-orphaned** subtasks (id / title / status) as a
//! standalone `# Active Task Decomposition` section — the decomposition sub-part of
//! the §1.4.3 ⑭ "Task Summary + Related Task Briefs + Decomposition state" item
//! (Task Summary + L5 briefs sub-parts remain a future slice). This is the consumer
//! half of the SYS-J-54 decomposition journey: MODULE-005 produces the decomposition
//! state (`DefaultDecompositionStore`); the cli adapter (`CapDecompositionReader`)
//! reads + filters it into [`SubtaskView`]s; this formatter renders them.
//!
//! **Omit-when-empty (Wave-12 Lane C)**: returns `None` when there are no
//! non-orphaned subtasks (no active task, or an empty decomposition), so the caller
//! emits NO message and the assembled output for the no-decomposition path is
//! **byte-identical** to pre-Wave-12 — the same convention as the `tier2_skills` ⑩
//! section. Empty/inactive turns therefore never grow the prompt.
//!
//! **Sanitization**: a subtask's `title` is attacker-controlled free text (and the
//! `subtask_id` / `status` are producer-derived but routed through the same path as
//! defense-in-depth). All three fields go through the shared `pub(crate)`
//! [`crate::tier2::sanitize_description`] Trojan-Source sanitizer (the only place
//! this module's output is structurally guaranteed safe — do NOT skip the sanitizer
//! based on assumed upstream validation) and are byte-bounded at [`MAX_FIELD_LEN`]
//! (UTF-8 char-boundary truncation) to bound an adversarial-length title.

use crate::ports::SubtaskView;
use crate::tier2::sanitize_description;

/// Per-field byte cap before sanitization (defense-in-depth, mirrors
/// `tier2_delegates::MAX_CAP_ID_LEN`). A single monster title cannot bloat the
/// section; UTF-8 char-boundary truncation, no suffix.
const MAX_FIELD_LEN: usize = 128;

/// Build the Tier 2 ⑭ "Active Task Decomposition" section from the active task's
/// non-orphaned subtasks. Returns `None` when `views` is empty (caller emits NO
/// message — omit-when-empty, so empty-state output is byte-identical, same
/// convention as `format_available_skills_section`). Each subtask renders as
/// `- {subtask_id} — {title} [{status}]`, every field truncated at
/// [`MAX_FIELD_LEN`] then routed through the shared `sanitize_description`. The
/// non-orphaned filter is applied UPSTREAM (the cli `CapDecompositionReader`), so
/// this formatter renders exactly what it is given.
pub fn format_active_decomposition_section(views: &[SubtaskView]) -> Option<String> {
    if views.is_empty() {
        return None;
    }
    let mut s = String::from("# Active Task Decomposition\n\n");
    for v in views {
        let id = sanitize_description(&truncate_to(&v.subtask_id, MAX_FIELD_LEN));
        let title = sanitize_description(&truncate_to(&v.title, MAX_FIELD_LEN));
        let status = sanitize_description(&truncate_to(&v.status, MAX_FIELD_LEN));
        s.push_str(&format!("- {id} — {title} [{status}]\n"));
    }
    Some(s)
}

/// UTF-8-safe truncation to at most `max` bytes (steps back to a char boundary).
/// No ellipsis suffix — the section is a soft-bounded list, not a hard contract.
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

    fn view(id: &str, title: &str, status: &str) -> SubtaskView {
        SubtaskView {
            subtask_id: id.to_string(),
            title: title.to_string(),
            status: status.to_string(),
        }
    }

    #[test]
    fn empty_returns_none() {
        assert!(format_active_decomposition_section(&[]).is_none());
    }

    #[test]
    fn renders_header_and_entries() {
        let s = format_active_decomposition_section(&[
            view("st-1", "Design schema", "in-progress"),
            view("st-2", "Write tests", "pending"),
        ])
        .expect("non-empty ⇒ Some");
        assert!(s.starts_with("# Active Task Decomposition"));
        assert!(s.contains("- st-1 — Design schema [in-progress]"));
        assert!(s.contains("- st-2 — Write tests [pending]"));
    }

    #[test]
    fn sanitizes_trojan_source_in_title() {
        // A BiDi override / zero-width char in an attacker-controlled title must be
        // stripped by the shared sanitizer.
        let s = format_active_decomposition_section(&[view(
            "st-1",
            "evil\u{202E}title\u{200B}",
            "failed",
        )])
        .expect("Some");
        assert!(!s.contains('\u{202E}'), "BiDi override must be stripped");
        assert!(!s.contains('\u{200B}'), "zero-width must be stripped");
    }

    #[test]
    fn truncates_overlong_field_at_char_boundary() {
        let long_title = "x".repeat(MAX_FIELD_LEN + 50);
        let s = format_active_decomposition_section(&[view("st-1", &long_title, "pending")])
            .expect("Some");
        // The rendered title segment must not exceed the field cap.
        assert!(!s.contains(&"x".repeat(MAX_FIELD_LEN + 1)));
        assert!(s.contains(&"x".repeat(MAX_FIELD_LEN)));
    }
}

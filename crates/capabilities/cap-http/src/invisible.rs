//! Pre-scan strip of invisible / bidi-control Unicode codepoints so attackers
//! can't smuggle patterns past `\s`-based regexes. See MODULE-012 §3.6 for
//! the round-3 + round-5 evaluator findings that prompted this helper.
//!
//! Rust regex 1.x `\s` is Unicode-aware (matches `\p{White_Space}`) but does
//! NOT match U+200B / U+202D / U+2066 etc. — those codepoints are Unicode
//! General_Category=Cf (Format), not Zs/Zl/Zp (Separator/whitespace). The
//! pre-strip is required because LLM tokenizers DO treat these Cf characters
//! as zero-width / invisible (or reorder rendering at the lexer layer). The
//! threat model: attacker injects
//! `<\u{200B}|system|>` or `<\u{202D}|system|>` into untrusted content.
//! Without a pre-strip, our regex `(?i)<\s*\|?\s*system\s*\|?\s*>` fails to
//! match (because `\s` ≠ U+200B), so the injection-pattern flag never fires,
//! neutralization no-ops, and the body is rendered to the LLM with invisibles
//! intact — and the LLM lexer sees `<|system|>`.
//!
//! The strip set covers (a) all widely-deployed zero-width invisibles and
//! (b) the full Trojan Source bidi-control family (CVE-2021-42574; Boucher &
//! Anderson 2021).
//!
//! | Codepoint | Name                                     | Class                  |
//! |-----------|------------------------------------------|------------------------|
//! | U+200B    | ZERO WIDTH SPACE                         | invisibles             |
//! | U+200C    | ZERO WIDTH NON-JOINER                    | invisibles             |
//! | U+200D    | ZERO WIDTH JOINER                        | invisibles             |
//! | U+2060    | WORD JOINER                              | invisibles             |
//! | U+2061    | FUNCTION APPLICATION                     | invisibles (math)      |
//! | U+2062    | INVISIBLE TIMES                          | invisibles (math)      |
//! | U+2063    | INVISIBLE SEPARATOR                      | invisibles (math)      |
//! | U+2064    | INVISIBLE PLUS                           | invisibles (math)      |
//! | U+FEFF    | ZERO WIDTH NO-BREAK SPACE (BOM)          | invisibles             |
//! | U+180E    | MONGOLIAN VOWEL SEPARATOR                | invisibles             |
//! | U+200E    | LEFT-TO-RIGHT MARK (LRM)                 | bidi-controls          |
//! | U+200F    | RIGHT-TO-LEFT MARK (RLM)                 | bidi-controls          |
//! | U+202A    | LEFT-TO-RIGHT EMBEDDING (LRE)            | bidi-controls          |
//! | U+202B    | RIGHT-TO-LEFT EMBEDDING (RLE)            | bidi-controls          |
//! | U+202C    | POP DIRECTIONAL FORMATTING (PDF)         | bidi-controls          |
//! | U+202D    | LEFT-TO-RIGHT OVERRIDE (LRO)             | bidi-controls (Trojan) |
//! | U+202E    | RIGHT-TO-LEFT OVERRIDE (RLO)             | bidi-controls (Trojan) |
//! | U+2066    | LEFT-TO-RIGHT ISOLATE (LRI)              | bidi-controls          |
//! | U+2067    | RIGHT-TO-LEFT ISOLATE (RLI)              | bidi-controls          |
//! | U+2068    | FIRST STRONG ISOLATE (FSI)               | bidi-controls          |
//! | U+2069    | POP DIRECTIONAL ISOLATE (PDI)            | bidi-controls          |
//!
//! 21 codepoints total.
//!
//! NOT stripped: regular whitespace (covered by `\s`); variation selectors
//! U+FE00..=U+FE0F (legitimate emoji presentation, deferred to a future
//! tokenizer-aware slice — see MODULE-012 §3.6); tag chars
//! U+E0000..=U+E007F (deprecated in modern Unicode and not a viable
//! tokenizer-side vector at this time).
//!
//! MODULE-012-AC-24 (CONTRACT-112 scanned-content derivative): matching also
//! drops Unicode General_Category ∈ {Mn, Me, Cf} so a leak pattern's literal
//! anchor still matches when a combining mark / format character is spliced
//! inside it (`B` + U+0301 + `earer`). NFC/NFKC alone is not the fix — there
//! is no precomposed form for that case. The historical `is_invisible` set
//! (zero-width / Default_Ignorable / bidi) is kept as a union; Hangul fillers
//! are `Lo` and would otherwise survive a GC-only drop. Mc is not dropped.

use std::sync::OnceLock;

pub fn strip_invisibles(text: &str) -> String {
    text.chars().filter(|c| !is_invisible(*c)).collect()
}

/// Filter used by the CONTRACT-112 scanned-content derivative: historical
/// invisibles **or** General_Category ∈ {Mn, Me, Cf}.
pub(crate) fn is_dropped_from_scan_derivative(c: char) -> bool {
    is_invisible(c) || is_mark_or_format(c)
}

fn strip_scan_derivative(text: &str) -> String {
    text.chars()
        .filter(|c| !is_dropped_from_scan_derivative(*c))
        .collect()
}

/// Unicode General_Category ∈ {Mn, Me, Cf}. Cached from the same
/// `regex-syntax` tables the leak regexes use (`[\p{Mn}\p{Me}\p{Cf}]`).
fn is_mark_or_format(c: char) -> bool {
    // No Mn/Me/Cf in ASCII. `is_invisible` is also non-ASCII (U+00AD is 0xAD).
    if c <= '\u{007F}' {
        return false;
    }
    let ranges = mark_format_ranges();
    let i = ranges.partition_point(|&(start, _)| start <= c);
    i > 0 && c <= ranges[i - 1].1
}

fn mark_format_ranges() -> &'static [(char, char)] {
    static RANGES: OnceLock<Vec<(char, char)>> = OnceLock::new();
    RANGES
        .get_or_init(|| {
            let hir =
                regex_syntax::parse(r"[\p{Mn}\p{Me}\p{Cf}]").expect("static Mn/Me/Cf class parses");
            match hir.kind() {
                regex_syntax::hir::HirKind::Class(regex_syntax::hir::Class::Unicode(u)) => {
                    u.ranges().iter().map(|r| (r.start(), r.end())).collect()
                }
                other => panic!("expected Unicode class for Mn/Me/Cf, got {other:?}"),
            }
        })
        .as_slice()
}

/// Apply Unicode NFKC (Compatibility Composition) normalization to
/// canonicalize all ASCII-equivalent compatibility decompositions —
/// fullwidth (U+FF01..U+FF5E), CJK compatibility small forms
/// (U+FE50..U+FE6F including U+FE64 SMALL LESS-THAN ﹤, U+FE65 SMALL
/// GREATER-THAN ﹥), letterlike symbols, math symbols, and other
/// codepoints that NFKC-decompose to ASCII counterparts. Defeats the
/// general class of bypass attacks where LLM tokenizers normalize
/// before tokenization, recovering ASCII metas / words from visually
/// distinct Unicode forms.
///
/// Adversarial round 3 (Claude Critical): the round-2 R2 fix covered
/// only U+FF01..U+FF5E; CJK Compatibility Forms small-form `<` (U+FE64)
/// and `>` (U+FE65) bypassed both `system_tag` and `data_close_tag`.
/// NFKC is the right canonicalization for this entire bypass class.
///
/// Trade-off: legitimate Unicode compatibility-form content (rare in
/// practice but possible — e.g. stylistic fullwidth Latin `Ｈｅｌｌｏ`
/// in CJK contexts, or letterlike symbols like ℋ for `H`) gets
/// canonicalized to ASCII. For NFKC-normalizing LLM tokenizers (most
/// modern transformer models) this matches downstream behavior; for
/// non-normalizing tokenizers there is a content semantic shift.
/// See MODULE-012 §3.6 known-gap row.
pub(crate) fn nfkc_normalize(text: &str) -> String {
    use unicode_normalization::UnicodeNormalization;
    text.nfkc().collect()
}

/// Compose the CONTRACT-112 scanned-content derivative: drop Mn/Me/Cf
/// and the historical invisible/zero-width set, NFKC-normalize, then
/// drop again so a compatibility decomposition cannot re-introduce a
/// mark before matching.
///
/// Applied at the upstream entry of every match-or-emit security
/// primitive (`LeakDetector::scan`,
/// `PromptInjectionHelpers::flag_injection_patterns`, and
/// `PromptInjectionHelpers::wrap_with_boundary`).
///
/// Order matters: strip first so spliced Mn (`B` + U+0301 + `earer`) is
/// gone before NFKC (NFC/NFKC alone leaves that splice intact). The
/// second strip is T32-U6 (`U+FF9E` Lm → U+3099 Mn).
pub fn canonical_scan_text(text: &str) -> String {
    strip_scan_derivative(&nfkc_normalize(&strip_scan_derivative(text)))
}

/// Pre-AC-24 pipeline (strip historical invisibles, then NFKC). T32
/// mutation: spliced Mn/Me/residual-Cf samples that `canonical_scan_text`
/// catches must miss on this function.
#[cfg(test)]
pub(crate) fn canonical_scan_text_without_mark_drop(text: &str) -> String {
    nfkc_normalize(&strip_invisibles(text))
}

#[inline]
pub(crate) fn is_invisible(c: char) -> bool {
    let cp = c as u32;
    // Adversarial round 4 (Claude Critical): the strip set now
    // covers Unicode's Default_Ignorable_Code_Point property — the
    // canonical "characters that LLM tokenizers may ignore". Goes
    // well beyond the round-3 set (Cf invisibles + bidi + VS + tag
    // chars). U+00AD (SHY), U+034F (CGJ), Hangul fillers, etc. would
    // otherwise allow `sk-pr<U+00AD>oj-...` style bypasses identical
    // in shape to the original ZWSP attack.
    matches!(c,
        // Original Slice B set: Cf invisibles + bidi + VS + tag.
        '\u{200B}' | '\u{200C}' | '\u{200D}'
        | '\u{2060}' | '\u{2061}' | '\u{2062}' | '\u{2063}' | '\u{2064}'
        | '\u{FEFF}'
        | '\u{180E}'
        | '\u{200E}' | '\u{200F}'
        | '\u{202A}' | '\u{202B}' | '\u{202C}' | '\u{202D}' | '\u{202E}'
        | '\u{2066}' | '\u{2067}' | '\u{2068}' | '\u{2069}'
        // Default_Ignorable_Code_Point additions (R4):
        | '\u{00AD}'                      // SOFT HYPHEN
        | '\u{034F}'                      // COMBINING GRAPHEME JOINER
        | '\u{061C}'                      // ARABIC LETTER MARK
        | '\u{115F}' | '\u{1160}'         // HANGUL CHOSEONG / JUNGSEONG FILLER
        | '\u{17B4}' | '\u{17B5}'         // KHMER deprecated
        | '\u{3164}'                      // HANGUL FILLER
        | '\u{FFA0}'                      // HALFWIDTH HANGUL FILLER
    )
        // Variation selectors VS-1..VS-16 (Slice B R3).
        || (0xFE00..=0xFE0F).contains(&cp)
        // Variation selectors VS-17..VS-256 (Slice B R3).
        || (0xE0100..=0xE01EF).contains(&cp)
        // Tag chars + extended tag range (R4 expanded from R3 0xE0000..=0xE007F):
        // Default_Ignorable_Code_Point covers U+E0000..U+E0FFF entirely.
        || (0xE0000..=0xE0FFF).contains(&cp)
        // Mongolian free variation selectors (R4 — Default_Ignorable).
        || (0x180B..=0x180D).contains(&cp)
        // Remaining U+2060..U+206F not in the explicit list above.
        || (0x2065..=0x206F).contains(&cp)
        // Various reserved / specials block (R4 — Default_Ignorable).
        || (0xFFF0..=0xFFF8).contains(&cp)
        // Shorthand format controls (R4 — Default_Ignorable).
        || (0x1BCA0..=0x1BCA3).contains(&cp)
        // Musical symbols (R4 — Default_Ignorable).
        || (0x1D173..=0x1D17A).contains(&cp)
}

/// T32 spliced samples keyed by `pattern_name`. Crate tests only.
#[cfg(test)]
pub(crate) fn t32_spliced_samples() -> Vec<(&'static str, String)> {
    let openai_body = "A".repeat(20);
    let anthropic_body = "a".repeat(90);
    let github_body = "abcdefghijklmnopqrstuvwxyz0123456789AB";
    vec![
        (
            "bearer_token",
            "B\u{0301}earer eyJhbGciOiJIUzI1NiJ9".to_string(),
        ),
        ("openai_api_key", format!("sk\u{20DD}-proj-{openai_body}")),
        (
            "anthropic_api_key",
            format!("sk-ant\u{FFF9}-api{anthropic_body}"),
        ),
        ("aws_access_key", "A\u{0600}KIA0123456789ABCDEF".to_string()),
        ("github_token", format!("g\u{0301}hp_{github_body}")),
        (
            "pem_private_key",
            "-----BE\u{20DD}GIN PRIVATE KEY-----".to_string(),
        ),
        (
            "auth_header_basic",
            "Author\u{FFF9}ization: Basic QUJDREVGRw==".to_string(),
        ),
    ]
}

#[cfg(test)]
mod t32_derivative {
    use super::*;
    use crate::patterns::LEAK_PATTERNS;
    use advance_shared_types::security_validator::Action;
    use regex::Regex;
    use unicode_normalization::UnicodeNormalization;

    fn nfc(s: &str) -> String {
        s.chars().nfc().collect()
    }
    fn nfkc(s: &str) -> String {
        s.chars().nfkc().collect()
    }

    fn spliced_samples() -> Vec<(&'static str, String)> {
        t32_spliced_samples()
    }

    fn row(name: &str) -> &'static crate::patterns::PatternSpec {
        LEAK_PATTERNS
            .iter()
            .find(|p| p.name == name)
            .unwrap_or_else(|| panic!("missing live LEAK_PATTERNS row {name}"))
    }

    #[test]
    fn drop_predicate_covers_ac24_classes() {
        assert!(is_dropped_from_scan_derivative('\u{0301}'), "Mn U+0301");
        assert!(is_dropped_from_scan_derivative('\u{20DD}'), "Me U+20DD");
        assert!(is_dropped_from_scan_derivative('\u{0600}'), "Cf U+0600");
        assert!(is_dropped_from_scan_derivative('\u{FFF9}'), "Cf U+FFF9");
        assert!(
            is_dropped_from_scan_derivative('\u{200B}'),
            "ZWSP via is_invisible"
        );
        assert!(
            is_dropped_from_scan_derivative('\u{00AD}'),
            "SOFT HYPHEN via is_invisible"
        );
        assert!(
            is_dropped_from_scan_derivative('\u{115F}'),
            "Hangul filler Lo via is_invisible"
        );
        assert!(!is_dropped_from_scan_derivative('A'));
        assert!(!is_mark_or_format('\u{200B}') || is_invisible('\u{200B}'));
        assert!(!is_invisible('\u{0301}'));
        assert!(!is_invisible('\u{20DD}'));
        assert!(!is_invisible('\u{0600}'));
        assert!(!is_invisible('\u{FFF9}'));
        assert!(!is_invisible('\u{FF9E}'));
        assert_eq!(
            mark_format_ranges().len(),
            368,
            "Unicode 16 Mn∪Me∪Cf range count drifted — re-check the GC source"
        );
    }

    #[test]
    fn t32_u1_nfc_nfkc_alone_leave_b_acute_splice() {
        let spliced = "B\u{0301}earer";
        assert_eq!(nfc(spliced), spliced);
        assert_eq!(nfkc(spliced), spliced);
        assert_eq!(canonical_scan_text(spliced), "Bearer");
        assert_ne!(canonical_scan_text_without_mark_drop(spliced), "Bearer");
    }

    #[test]
    fn t32_u2_mutation_all_block_redact_rows() {
        let rows: Vec<_> = LEAK_PATTERNS
            .iter()
            .filter(|p| matches!(p.action, Action::Block | Action::Redact))
            .collect();
        assert_eq!(rows.len(), 7, "LEAK_PATTERNS Block/Redact count drifted");
        let samples = spliced_samples();
        assert_eq!(samples.len(), 7);
        for (name, sample) in &samples {
            let spec = row(name);
            let re = Regex::new(spec.regex).expect("static regex compiles");
            assert!(
                re.find(&canonical_scan_text(sample)).is_some(),
                "{name}: derivative must match spliced sample {sample:?}"
            );
            assert!(
                re.find(&canonical_scan_text_without_mark_drop(sample))
                    .is_none(),
                "{name}: mutation (no mark-drop) must miss spliced sample {sample:?}"
            );
        }
    }

    #[test]
    fn t32_u6_post_nfkc_drop_ff9e_and_acute_accent() {
        let spliced = "B\u{FF9E}earer eyJhbGciOiJIUzI1NiJ9";
        let first_only = nfkc_normalize(&strip_scan_derivative(spliced));
        assert!(
            first_only.contains('\u{3099}'),
            "first-drop-only must leave U+3099 in the haystack, got {first_only:?}"
        );
        assert_eq!(
            canonical_scan_text(spliced),
            "Bearer eyJhbGciOiJIUzI1NiJ9",
            "second drop reconstitutes Bearer"
        );
        let acute = "x\u{00B4}y";
        assert!(
            !canonical_scan_text(acute).contains('\u{0301}'),
            "U+00B4 NFKC Mn must not survive matching"
        );
    }
}

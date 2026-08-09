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

pub fn strip_invisibles(text: &str) -> String {
    text.chars().filter(|c| !is_invisible(*c)).collect()
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

/// Compose `strip_invisibles` and `nfkc_normalize` into a single
/// canonical scan-text derivative. Applied at the upstream entry of
/// every match-or-emit security primitive (`LeakDetector::scan`,
/// `PromptInjectionHelpers::flag_injection_patterns`, and
/// `PromptInjectionHelpers::wrap_with_boundary`).
///
/// Order matters: strip Cf-category invisibles FIRST so they're
/// removed before NFKC processing (some invisibles have NFKC
/// decompositions, but the threat model treats them as zero-width
/// regardless of NFKC behavior; explicit strip is more conservative).
pub fn canonical_scan_text(text: &str) -> String {
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

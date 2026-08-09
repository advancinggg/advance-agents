//! LEAK_PATTERNS (8 from MODULE-012 §1.4.2 verbatim) + INJECTION_PATTERNS
//! (canonical 5 from MODULE-012 §1.4.4a). The `PatternSpec` struct +
//! constants are crate-private; only the compiled `DefaultLeakDetector` /
//! `DefaultPromptInjectionHelpers` are public.

use advance_shared_types::security_validator::{Action, Severity};

pub(crate) struct PatternSpec {
    pub name: &'static str,
    pub regex: &'static str,
    pub severity: Severity,
    pub action: Action,
}

/// LeakDetector patterns — verbatim from MODULE-012 §1.4.2 BUILTIN_PATTERNS (8 rows).
pub fn bounded_pattern_window() -> usize {
    // Derived from min guaranteed match length over LEAK_PATTERNS (≥99 per S3 audit).
    // For S4 facade (visibility-only).
    99
}

pub(crate) const LEAK_PATTERNS: &[PatternSpec] = &[
    // (?i): the AC builder uses ascii_case_insensitive(true), so the AC
    // seed match is case-insensitive. Without (?i) on the regex, AC
    // would fire on uppercase variants but regex confirmation rejects —
    // silent bypass for typo-cased credentials in user-pasted text or
    // logs. Adversarial round 3 (Claude Warning 2) finding.
    PatternSpec {
        name: "openai_api_key",
        regex: r"(?i)sk-proj-[A-Za-z0-9_-]{20,}",
        severity: Severity::Critical,
        action: Action::Block,
    },
    PatternSpec {
        name: "anthropic_api_key",
        regex: r"(?i)sk-ant-api[A-Za-z0-9_-]{90,}",
        severity: Severity::Critical,
        action: Action::Block,
    },
    PatternSpec {
        name: "aws_access_key",
        regex: r"(?i)AKIA[0-9A-Z]{16}",
        severity: Severity::Critical,
        action: Action::Block,
    },
    PatternSpec {
        name: "github_token",
        regex: r"(?i)gh[ps]_[A-Za-z0-9]{36,}",
        severity: Severity::Critical,
        action: Action::Block,
    },
    // (?i)-prefixed: AC is built with ascii_case_insensitive(true), so AC
    // seed `-----BEGIN ` matches lowercase variants too. Adversarial round 1
    // (Claude Warning 8) found that without (?i) on the regex, AC fired on
    // `-----begin ...` but regex confirmation rejected, silent bypass. Now
    // both AC and regex are case-insensitive.
    PatternSpec {
        name: "pem_private_key",
        regex: r"(?i)-----BEGIN [A-Z ]*PRIVATE KEY-----",
        severity: Severity::Critical,
        action: Action::Block,
    },
    PatternSpec {
        name: "bearer_token",
        regex: r"(?i)Bearer\s+eyJ[A-Za-z0-9_-]+",
        severity: Severity::High,
        action: Action::Redact,
    },
    PatternSpec {
        name: "auth_header_basic",
        regex: r"(?i)Authorization:\s*Basic\s+[A-Za-z0-9+/=]+",
        severity: Severity::High,
        action: Action::Redact,
    },
    PatternSpec {
        name: "high_entropy_hex",
        regex: r"(?i)[a-f0-9]{64}",
        severity: Severity::Medium,
        action: Action::Warn,
    },
];

/// Prompt-injection patterns — CANONICAL 5 from MODULE-012 §1.4.4a.
pub(crate) const INJECTION_PATTERNS: &[PatternSpec] = &[
    PatternSpec {
        name: "ignore_previous_instructions",
        regex: r"(?i)ignore\s+(all\s+)?previous\s+instructions",
        severity: Severity::High,
        action: Action::Warn,
    },
    PatternSpec {
        name: "forget_everything",
        regex: r"(?i)forget\s+everything\s+(above|prior)",
        severity: Severity::High,
        action: Action::Warn,
    },
    PatternSpec {
        name: "system_tag",
        regex: r"(?i)<\s*\|?\s*system\s*\|?\s*>",
        severity: Severity::Critical,
        action: Action::Block,
    },
    PatternSpec {
        name: "you_are_now",
        regex: r"(?i)you\s+are\s+now\s+(a\s+)?(?:[a-z]+\s+){0,3}(assistant|agent|admin|developer|jailbroken)",
        severity: Severity::High,
        action: Action::Warn,
    },
    // Spec text §1.4.4a says "base64 encoded payloads exceeding 64 chars" without
    // prescribing severity; canonical Severity has no Low, so Medium is the lowest
    // available. Severity::Medium + Action::Warn means findings only log; legitimate
    // base64 content (image data, JWT signatures, fingerprints) commonly exceeds 64
    // chars. Refinement deferred per §3.6 known-gap row.
    PatternSpec {
        name: "base64_payload",
        regex: r"[A-Za-z0-9+/]{64,}={0,2}",
        severity: Severity::Medium,
        action: Action::Warn,
    },
    // Adversarial round 1 (Codex Critical): the ZWSP-injection escape used
    // by `wrap_with_boundary::escape_data_close` is logically defeated by
    // the very threat model `strip_invisibles` is built on — LLM lexers
    // that ignore zero-width chars treat `<\u{200B}/data>` as equivalent
    // to `</data>` and recover the closer-tag. Defense is to flag the
    // literal `</data>` token with Severity::Critical so the
    // severity-based neutralization path in `neutralize_by_severity_stripped`
    // replaces it with `[NEUTRALIZED]` (which an LLM cannot interpret as
    // a closer) BEFORE escape_data_close runs as defense-in-depth.
    //
    // Adversarial round 2 (Claude Warning 4): Action::Warn (not Block)
    // because the load-bearing defense is the SEVERITY-driven neutralize
    // step (Critical → always replace, regardless of trust level). Block
    // would over-trigger external consumers that gate on Action — e.g.
    // legitimate user content discussing XML or this very security doc
    // would be rejected outright. Severity::Critical preserves the
    // neutralize-on-emit semantic without forcing external consumers to
    // reject the entire message.
    PatternSpec {
        name: "data_close_tag",
        regex: r"(?i)<\s*/\s*data\s*>",
        severity: Severity::Critical,
        action: Action::Warn,
    },
];

// Compile-time bound check (PromptInjectionHelpers invariant: ≤ 1024 patterns).
const _: () = {
    assert!(LEAK_PATTERNS.len() <= 1024);
};
const _: () = {
    assert!(INJECTION_PATTERNS.len() <= 1024);
};

#[cfg(test)]
mod combining_class_invariant {
    //! Guards the safety condition MODULE-009 §2.7 invariant 6 Δ5's released-region bound
    //! depends on.
    //!
    //! The bound compares a finding's canonical START offset against the shadow's own
    //! canonical length. NFKC is not only composition — it also canonically REORDERS, and
    //! reordering could displace a match's characters across that bound. The Canonical
    //! Ordering Algorithm (UAX #15) permutes only NON-STARTERS — characters with a
    //! non-zero canonical combining class — so the bound is safe exactly while no shipped
    //! Block/Redact pattern can admit one.
    //!
    //! WHAT THIS TEST PROVES, and why the earlier versions did not:
    //!
    //! * Round 7's first attempt argued the condition in prose as "every class is
    //!   ASCII-only". That is FALSE — `bearer_token`/`auth_header_basic` use `\s` and the
    //!   `regex` crate runs in Unicode mode, so U+1680/U+2028 match. (Those are starters,
    //!   so the conclusion held; the reason did not. `build_hold_matchers()` in
    //!   `streaming.rs` and MODULE-012 §2.9 already recorded this.)
    //! * Round 8 replaced the prose with a sweep that inserted every combining mark into
    //!   a registered SAMPLE string. Round 9 refuted that too: perturbing one fixed
    //!   sample proves only a local neighbourhood property of that string, NOT the
    //!   universal property about the pattern's match language. Widening an EXISTING row
    //!   by alternation — e.g. adding GitHub's real `ghu_` prefix family with a
    //!   mark-admitting class — left the sweep passing, because no single insertion into
    //!   the old sample can reach the new branch.
    //! * This version decides the question on the PATTERN, not on any sample: it parses
    //!   each regex to its HIR and inspects every character class and literal the
    //!   pattern can ever match.
    //!
    //! SCOPE (audit round 10). The Δ5 bound depends on the `LeakDetector` ONLY, so
    //! `shipped_block_redact_patterns_admit_no_combining_mark` is scoped to
    //! `LEAK_PATTERNS`' Block/Redact rows — the same scoping `cap-llm/src/stream.rs`'s
    //! guard comment states. Round 10 showed the
    //! earlier UNQUALIFIED phrasing ("no shipped Block/Redact pattern") was false:
    //! `INJECTION_PATTERNS` also has a `Block` row (`system_tag`), and widening it with
    //! `\p{M}*` left the check green. No streaming caller of `PromptInjectionHelpers`
    //! exists today and `streaming.rs` references only `LEAK_PATTERNS`, so that was a
    //! false CLAIM rather than a live hole — but it is a trap for the first streaming
    //! caller, so `injection_patterns_neutralisable_rows_admit_no_combining_mark` closes
    //! it, using that table's OWN predicate. A third test,
    //! `the_analyser_detects_a_mark_in_every_structural_position`, is a positive control
    //! on the shared `admitted()` walk that both invariants rely on. (Audit round 11:
    //! these are named rather than numbered — an earlier revision said "the first test
    //! below" and the ordinals stopped matching when the positive control was added.) `(?i)` case folding is already expanded by
    //!   the parser, so the analysis covers it. A row widened in ANY way — new branch,
    //!   new class, new literal — is re-analysed automatically, because the rows come from
    //!   the real `LEAK_PATTERNS` static rather than a copied list.

    use super::{Action, Severity, LEAK_PATTERNS};
    use regex_syntax::hir::{Class, Hir, HirKind};
    use unicode_normalization::char::canonical_combining_class as ccc;

    /// Every codepoint that canonical reordering can move.
    fn non_starters() -> Vec<char> {
        (0u32..=0x10FFFF)
            .filter_map(char::from_u32)
            .filter(|c| ccc(*c) != 0)
            .collect()
    }

    /// Collect every char a pattern can match, as class ranges plus literal chars.
    fn admitted(hir: &Hir, ranges: &mut Vec<(char, char)>, lits: &mut Vec<char>) {
        match hir.kind() {
            HirKind::Literal(l) => {
                if let Ok(sx) = std::str::from_utf8(&l.0) {
                    lits.extend(sx.chars());
                }
            }
            HirKind::Class(Class::Unicode(cls)) => {
                ranges.extend(cls.ranges().iter().map(|r| (r.start(), r.end())));
            }
            HirKind::Class(Class::Bytes(cls)) => {
                for r in cls.ranges() {
                    ranges.push((r.start() as char, r.end() as char));
                }
            }
            HirKind::Repetition(rep) => admitted(&rep.sub, ranges, lits),
            HirKind::Capture(cap) => admitted(&cap.sub, ranges, lits),
            HirKind::Concat(subs) | HirKind::Alternation(subs) => {
                for sub in subs {
                    admitted(sub, ranges, lits);
                }
            }
            HirKind::Empty | HirKind::Look(_) => {}
        }
    }

    /// POSITIVE CONTROL for the analyser itself (audit round 10).
    ///
    /// The two invariant tests below are only as good as `admitted()`'s HIR walk. A MISSING
    /// arm is a compile error — `HirKind`/`Class` are not `#[non_exhaustive]` in the pinned
    /// `regex-syntax =0.8.10` — but an arm that is present and EMPTY is not, and a mutation
    /// showed that neutering the `Alternation` arm makes a mark-admitting alternation branch
    /// invisible while both invariant tests stay green. This test plants a combining mark in
    /// each structural position the walk must reach, so hollowing out any arm fails HERE.
    /// Assert the walk reaches every structural position. Called BY the invariant tests
    /// before they trust `admitted()`'s output, not only as a standalone row.
    ///
    /// The merge gate showed why that coupling matters: neutering just the `Alternation`
    /// half of the combined `Concat | Alternation` arm left BOTH invariant tests green
    /// while the analysis no longer looked inside any alternation branch — the exact
    /// structural position this module's own history says was used to hide a
    /// mark-admitting class. Only this control caught it, and only because it happened to
    /// run. An invariant that depends on a sibling test having run is not an invariant, so
    /// each one now self-checks the analyser first and cannot pass on a blinded walk.
    #[test]
    fn the_analyser_detects_a_mark_in_every_structural_position() {
        assert_analyser_reaches_every_structural_position();
    }

    fn assert_analyser_reaches_every_structural_position() {
        let mark = '\u{0301}'; // ccc = 230
        let cases: [(&str, &str); 5] = [
            ("bare literal", "ab\u{0301}c"),
            ("explicit class", "ab[\u{0300}-\u{0302}]c"),
            ("unicode property class", r"ab\p{Mn}c"),
            ("inside an alternation branch", r"(abc|de\p{Mn}f)"),
            ("inside a repetition body", r"(?:x\p{Mn}){2,}"),
        ];
        for (label, pattern) in cases {
            let hir = regex_syntax::parse(pattern).expect("control pattern must parse");
            let (mut ranges, mut lits) = (Vec::new(), Vec::new());
            admitted(&hir, &mut ranges, &mut lits);
            let seen = ranges.iter().any(|&(lo, hi)| mark >= lo && mark <= hi)
                || lits.contains(&mark)
                || ranges.iter().any(|&(lo, hi)| {
                    (lo..=hi)
                        .any(|c| unicode_normalization::char::canonical_combining_class(c) != 0)
                })
                || lits
                    .iter()
                    .any(|c| unicode_normalization::char::canonical_combining_class(*c) != 0);
            assert!(
                seen,
                "the HIR walk failed to reach a combining mark planted {label}                  (pattern {pattern:?}) — an arm of `admitted()` is hollow, so the                  invariant tests below are not actually analysing the whole pattern"
            );
        }
    }

    /// Companion to the test below, guarding the OTHER table under the same shared
    /// `canonical_scan_text` NFKC pass.
    ///
    /// The predicate here is deliberately NOT the Block/Redact one: injection findings are
    /// neutralised by SEVERITY, not by `Action` (`prompt_injection.rs`'s
    /// `neutralize_by_severity_stripped` targets `Critical` unconditionally and `High` under
    /// `TrustLevel::Untrusted`). Audit round 10 flagged that reusing the leak table's
    /// `Action` filter here would miss `data_close_tag` (`Warn`/`Critical`) and the three
    /// `Warn`/`High` rows — real neutralisation targets an `Action`-only filter cannot see.
    ///
    /// This does not guard a live Δ5 path: `PromptInjectionHelpers` is only ever called on
    /// complete, already-buffered strings today. It exists so the injection table cannot
    /// silently acquire a mark-admitting class that a FUTURE streaming caller would inherit.
    #[test]
    fn injection_patterns_neutralisable_rows_admit_no_combining_mark() {
        // Trust `admitted()` only after proving it still sees every structural position.
        assert_analyser_reaches_every_structural_position();
        let rows: Vec<&super::PatternSpec> = super::INJECTION_PATTERNS
            .iter()
            .filter(|p| matches!(p.severity, Severity::Critical | Severity::High))
            .collect();
        // EXACT, not a floor: a floor cannot see a row being DELETED, which shrinks
        // coverage exactly as silently as adding an unanalysed one (audit round 11).
        assert_eq!(
            rows.len(),
            5,
            "INJECTION_PATTERNS' Critical/High row count changed; update this test \
             deliberately — coverage of the neutralisable set must not drift"
        );
        let marks = non_starters();
        let mut offenders: Vec<(&str, u32)> = Vec::new();
        for row in &rows {
            let hir = regex_syntax::parse(row.regex).expect("shipped pattern must parse");
            let (mut ranges, mut lits) = (Vec::new(), Vec::new());
            admitted(&hir, &mut ranges, &mut lits);
            for &m in &marks {
                if ranges.iter().any(|&(lo, hi)| m >= lo && m <= hi) || lits.contains(&m) {
                    offenders.push((row.name, m as u32));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "{} (pattern, mark) pairs are admissible by a neutralisable INJECTION_PATTERNS \
             row, e.g. {:04X?} — a future streaming caller of PromptInjectionHelpers would \
             inherit the reordering hazard the Δ5 bound rules out for the leak table.",
            offenders.len(),
            &offenders[..offenders.len().min(8)]
        );
    }

    #[test]
    fn shipped_block_redact_patterns_admit_no_combining_mark() {
        // Trust `admitted()` only after proving it still sees every structural position.
        assert_analyser_reaches_every_structural_position();
        let rows: Vec<&super::PatternSpec> = LEAK_PATTERNS
            .iter()
            .filter(|p| matches!(p.action, Action::Block | Action::Redact))
            .collect();
        // EXACT, not a floor — see the sibling test: a floor is blind to deletions.
        assert_eq!(
            rows.len(),
            7,
            "LEAK_PATTERNS' Block/Redact row count changed; update this test \
             deliberately — the Δ5 bound's safety condition is quantified over ALL of them"
        );

        let marks = non_starters();
        assert!(
            marks.len() > 800,
            "the mark repertoire looks wrong, saw {}",
            marks.len()
        );

        let mut offenders: Vec<(&str, u32)> = Vec::new();
        for row in &rows {
            let hir = regex_syntax::parse(row.regex).expect("shipped pattern must parse");
            let (mut ranges, mut lits) = (Vec::new(), Vec::new());
            admitted(&hir, &mut ranges, &mut lits);
            assert!(
                !ranges.is_empty() || !lits.is_empty(),
                "analysed nothing for {:?} — the HIR walk missed a node kind",
                row.name
            );
            for &m in &marks {
                let in_class = ranges.iter().any(|&(lo, hi)| m >= lo && m <= hi);
                let in_lit = lits.contains(&m);
                if in_class || in_lit {
                    offenders.push((row.name, m as u32));
                }
            }
        }

        assert!(
            offenders.is_empty(),
            "{} (pattern, mark) pairs are admissible by a shipped Block/Redact pattern, \
             e.g. {:04X?} — canonical reordering can then move a match's own character \
             across the Δ5 released-region bound. Re-derive that bound before widening \
             the pattern table.",
            offenders.len(),
            &offenders[..offenders.len().min(8)]
        );
    }
}

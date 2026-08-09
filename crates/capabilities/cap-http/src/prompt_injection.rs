//! `DefaultPromptInjectionHelpers` — concrete impl of the trait declared in
//! `crates/shared-types/src/security_validator.rs`. Layer 1 sanitization
//! primitive (`flag_injection_patterns`) + Layer 2 boundary-marking helper
//! (`wrap_with_boundary`). See MODULE-012 §1.4.4a.

use advance_shared_types::security_validator::{
    InjectionFlag, PromptInjectionHelpers, Severity, TrustLevel,
};
use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use regex::Regex;

use crate::invisible::canonical_scan_text;
use crate::patterns::{PatternSpec, INJECTION_PATTERNS};

const MAX_INJECTION_BYTES: usize = 1024 * 1024;
/// Adversarial round 2 (Claude Warning 3): bound `source` parameter so
/// an attacker-controlled `source` (e.g. URL, filename) cannot drive
/// proportional `String` allocation in `escape_attr`. 512 bytes mirrors
/// the secret-name length bound in cap-secrets (commit 1bb794a).
const MAX_SOURCE_BYTES: usize = 512;
const TRUNCATION_MARKER: &str = "[...truncated for size...]";
/// (Note: scan_headers count cap lives in leak_detector.rs::scan_headers
/// since that's where it's enforced. Removed dead-code copy from this
/// module per Adversarial round 3 Warning 5.)

pub struct DefaultPromptInjectionHelpers {
    /// AC built from non-empty seeds. Empty-seed patterns route through
    /// `regex_only` (avoids the empty-seed-O(n²) pathological case).
    ac: Option<AhoCorasick>,
    ac_indexed: Vec<usize>,
    regex_only: Vec<usize>,
    compiled: Vec<CompiledInjection>,
    /// Case-insensitive + ASCII-whitespace-tolerant regex that matches any
    /// `</data>` closer attempt in body content. Used by
    /// `escape_data_close` to ZWSP-injection any attacker-controlled closer.
    /// Zero-width Unicode chars (ZWSP/ZWJ/etc) are stripped from the body
    /// upstream by `strip_invisibles`, so this regex only needs to handle
    /// the ASCII-whitespace + case variants.
    data_close_re: Regex,
}

struct CompiledInjection {
    spec: &'static PatternSpec,
    regex: Regex,
}

impl DefaultPromptInjectionHelpers {
    pub fn new() -> Self {
        let compiled: Vec<CompiledInjection> = INJECTION_PATTERNS
            .iter()
            .map(|p| CompiledInjection {
                spec: p,
                regex: Regex::new(p.regex).expect("static regex compiles"),
            })
            .collect();
        let mut ac_seeds: Vec<&'static str> = Vec::new();
        let mut ac_indexed: Vec<usize> = Vec::new();
        let mut regex_only: Vec<usize> = Vec::new();
        for (i, p) in INJECTION_PATTERNS.iter().enumerate() {
            let seed = Self::ac_seed(p);
            if seed.is_empty() {
                regex_only.push(i);
            } else {
                ac_seeds.push(seed);
                ac_indexed.push(i);
            }
        }
        let ac = if ac_seeds.is_empty() {
            None
        } else {
            Some(
                AhoCorasickBuilder::new()
                    .ascii_case_insensitive(true)
                    .match_kind(MatchKind::LeftmostFirst)
                    .build(&ac_seeds)
                    .expect("static AC seeds compile"),
            )
        };
        let data_close_re = Regex::new(r"(?i)<\s*/\s*data\s*>").expect("static regex compiles");
        Self {
            ac,
            ac_indexed,
            regex_only,
            compiled,
            data_close_re,
        }
    }

    /// AC seed selection — REDoS-defensive AND start-anchored: each AC
    /// seed must be SELECTIVE (low-frequency in normal text) AND must
    /// match the LITERAL PREFIX of the regex (so the strict
    /// `rm.start() == m.start()` confirmation check accepts the regex
    /// match anchored at the AC seed's start position).
    ///
    /// Adversarial round 1 (Claude Critical) showed bare seeds like
    /// `<` for system_tag and `you` for you_are_now produce quadratic
    /// blowup on adversarial input.
    ///
    /// Patterns whose regex starts with a non-literal expression (e.g.
    /// `system_tag = (?i)<\s*\|?\s*system\s*\|?\s*>` where the regex
    /// prefix is `<` followed by optional whitespace + optional `|`)
    /// route to regex_only. Tightening the AC seed to `system` would
    /// match an INTERIOR position of the regex match, and the strict
    /// equality check would reject the match (regex.find_at searches
    /// forward from `m.start()` and returns the first match at or
    /// after — but the actual match starts BEFORE the seed position).
    /// regex_only path is linear-time per regex (regex 1.x is O(n)
    /// guaranteed for non-backtracking patterns), so dropping the AC
    /// fast-path for these cases is acceptable.
    fn ac_seed(pat: &PatternSpec) -> &'static str {
        match pat.name {
            // Regex starts with literal `ignore`; AC seed matches that prefix.
            "ignore_previous_instructions" => "ignore",
            // Regex starts with literal `forget`; same.
            "forget_everything" => "forget",
            // Interior-matching pattern — regex_only path.
            "system_tag" => "",
            // Interior-matching pattern — regex_only path.
            "you_are_now" => "",
            // base64_payload: regex-only.
            "base64_payload" => "",
            // data_close_tag: regex-only (interior `<` matching).
            "data_close_tag" => "",
            _ => "",
        }
    }
}

impl Default for DefaultPromptInjectionHelpers {
    fn default() -> Self {
        Self::new()
    }
}

impl PromptInjectionHelpers for DefaultPromptInjectionHelpers {
    fn flag_injection_patterns(&self, content: &str) -> Vec<InjectionFlag> {
        // Invariant 5: DoS cap, fail-CLOSED. Inputs over MAX_INJECTION_BYTES
        // return a synthetic input_overflow InjectionFlag (Critical) so
        // consumers can DISTINGUISH overflow from clean input. Cap measured
        // against raw caller input BEFORE strip — same as LeakDetector
        // invariant 4 to deny strip-amplification attacks.
        if content.len() > MAX_INJECTION_BYTES {
            return vec![InjectionFlag {
                offset: 0,
                length: 0,
                pattern_name: "input_overflow".to_string(),
                severity: Severity::Critical,
            }];
        }
        // Pre-strip invisibles BEFORE matching. Offsets in returned
        // InjectionFlags are byte offsets into the stripped string per the
        // InjectionFlag rustdoc amendment ("implementation-defined
        // scanned-content derivative"; this impl's derivative is
        // strip_invisibles(content)).
        let scan_text = canonical_scan_text(content);
        let mut flags = Vec::new();
        if let Some(ac) = &self.ac {
            for m in ac.find_iter(&scan_text) {
                let pat_idx = self.ac_indexed[m.pattern().as_usize()];
                let pat = &self.compiled[pat_idx];
                if let Some(rm) = pat.regex.find_at(&scan_text, m.start()) {
                    if rm.start() == m.start() {
                        flags.push(InjectionFlag {
                            offset: rm.start(),
                            length: rm.end() - rm.start(),
                            pattern_name: pat.spec.name.to_string(),
                            severity: pat.spec.severity.clone(),
                        });
                    }
                }
            }
        }
        // Regex-only patterns (e.g. base64_payload) — direct find_iter.
        for &pat_idx in &self.regex_only {
            let pat = &self.compiled[pat_idx];
            for rm in pat.regex.find_iter(&scan_text) {
                flags.push(InjectionFlag {
                    offset: rm.start(),
                    length: rm.end() - rm.start(),
                    pattern_name: pat.spec.name.to_string(),
                    severity: pat.spec.severity.clone(),
                });
            }
        }
        flags
    }

    fn wrap_with_boundary(&self, content: &str, source: &str, trust: TrustLevel) -> String {
        // Invariant 5: DoS cap. On overflow, truncate the body content (NOT
        // silently drop) so the caller still receives a wrapped <data>
        // block — but with the body bounded. Truncation marker is plain
        // prose so an LLM consuming the wrapped output sees a human-readable
        // indication that content was cut.
        let bounded: &str = if content.len() > MAX_INJECTION_BYTES {
            // Find the largest UTF-8-aligned slice <= MAX_INJECTION_BYTES.
            let mut cut = MAX_INJECTION_BYTES;
            while !content.is_char_boundary(cut) && cut > 0 {
                cut -= 1;
            }
            &content[..cut]
        } else {
            content
        };
        let truncated = content.len() > MAX_INJECTION_BYTES;
        // Strip invisibles ONCE at the entry point. All downstream steps
        // (neutralize, escape_data_close, format) operate on the stripped
        // string. This collapses any per-step strip into a single canonical
        // pass — essential for offset semantics consistency.
        let stripped = canonical_scan_text(bounded);
        let neutralized = self.neutralize_by_severity_stripped(&stripped, &trust);
        let mut body = self.escape_data_close(&neutralized);
        if truncated {
            body.push('\n');
            body.push_str(TRUNCATION_MARKER);
        }
        let trust_attr = match trust {
            TrustLevel::Trusted => "trusted",
            TrustLevel::Untrusted => "untrusted",
        };
        // Adversarial R2 W3: bound source length before allocating in
        // escape_attr. UTF-8-aligned truncation, `[truncated]` suffix
        // marker so consumers can detect over-bound source.
        // Adversarial R3 W3: also apply canonical_scan_text to source
        // (strip Cf-invisibles + NFKC) so attacker-controlled URL/
        // filename / topic carrying RLO override or fullwidth chars
        // doesn't survive into the attribute and confuse log/UI
        // rendering (Trojan Source CVE-2021-42574 in audit logs) or
        // desynchronize byte-equality vs lexer-equality comparisons.
        let source_canonical = canonical_scan_text(source);
        let source_bounded: &str = if source_canonical.len() > MAX_SOURCE_BYTES {
            let mut cut = MAX_SOURCE_BYTES;
            while !source_canonical.is_char_boundary(cut) && cut > 0 {
                cut -= 1;
            }
            &source_canonical[..cut]
        } else {
            &source_canonical
        };
        let source_attr = if source_canonical.len() > MAX_SOURCE_BYTES {
            format!("{}[truncated]", escape_attr(source_bounded))
        } else {
            escape_attr(source_bounded)
        };
        format!("<data source=\"{source_attr}\" trust=\"{trust_attr}\">\n{body}\n</data>")
    }
}

impl DefaultPromptInjectionHelpers {
    /// Build a new string with each flagged-and-neutralization-eligible
    /// span replaced by `[NEUTRALIZED]`. Ranges are sorted ascending,
    /// merged on overlap, then emitted via a walk-and-rebuild — robust
    /// against overlapping flags (e.g. patterns whose regexes match
    /// overlapping byte spans). Operates on the ALREADY-STRIPPED string
    /// from `wrap_with_boundary`; offsets returned by
    /// `flag_injection_patterns` are byte offsets into that stripped form.
    ///
    /// Cost: O(k log k + n) where k = flag count (sort-bounded), n =
    /// `stripped.len()` (walk-rebuild). For typical k ≤ 5 and n ≤ 1 MiB
    /// the n-term dominates; treat as effectively linear.
    ///
    /// **Defensive char-boundary safety**: offsets coming from regex
    /// matches on `stripped` are guaranteed char-aligned, but a
    /// misbehaving caller passing a manually-constructed `InjectionFlag`
    /// would otherwise panic in slicing. Each merged range is aligned to
    /// the nearest char boundary so the slice operations are panic-safe.
    fn neutralize_by_severity_stripped(&self, stripped: &str, trust: &TrustLevel) -> String {
        let flags = self.flag_injection_patterns(stripped);
        let stripped_len = stripped.len();
        // Use checked_add so an adversarial InjectionFlag (e.g. via
        // deserialized JSON) doesn't panic under workspace
        // overflow-checks = true. Saturating to stripped.len() collapses
        // the range to a no-op suffix that the walk-rebuild guard
        // handles. Adversarial round 1 (Claude Warning 6) finding.
        let mut targets: Vec<(usize, usize)> = flags
            .iter()
            .filter(|f| match (&f.severity, trust) {
                (Severity::Critical, _) => true,
                (Severity::High, TrustLevel::Untrusted) => true,
                _ => false,
            })
            .map(|f| {
                let end = f.offset.checked_add(f.length).unwrap_or(stripped_len);
                (f.offset.min(stripped_len), end.min(stripped_len))
            })
            .collect();
        targets.sort_by_key(|(start, _)| *start);
        let mut merged: Vec<(usize, usize)> = Vec::with_capacity(targets.len());
        for (start, end) in targets {
            match merged.last_mut() {
                Some(last) if start <= last.1 => {
                    last.1 = last.1.max(end);
                }
                _ => merged.push((start, end)),
            }
        }
        let mut out = String::with_capacity(stripped.len());
        let mut cursor = 0usize;
        for (start, end) in merged {
            let s = align_floor(stripped, start);
            let e = align_ceil(stripped, end);
            if s < cursor {
                cursor = cursor.max(e);
                continue;
            }
            if cursor < s {
                out.push_str(&stripped[cursor..s]);
            }
            out.push_str("[NEUTRALIZED]");
            cursor = e;
        }
        if cursor < stripped.len() {
            out.push_str(&stripped[cursor..]);
        }
        out
    }

    /// Rewrite any (?i)<\s*/\s*data\s*> match by injecting U+200B between `<`
    /// and `/`, so the LLM lexer no longer recognizes them as a closer.
    /// (Invisibles already stripped upstream by `wrap_with_boundary` —
    /// this function's input is invisibles-free.)
    fn escape_data_close(&self, body: &str) -> String {
        self.data_close_re
            .replace_all(body, "<\u{200B}/data>")
            .into_owned()
    }
}

/// Floor `pos` to the largest char boundary ≤ `pos` (or 0). Used by
/// `neutralize_by_severity_stripped` for defensive char-boundary safety
/// against hand-constructed InjectionFlag offsets.
fn align_floor(text: &str, pos: usize) -> usize {
    let mut p = pos.min(text.len());
    while p > 0 && !text.is_char_boundary(p) {
        p -= 1;
    }
    p
}

/// Ceil `pos` to the smallest char boundary ≥ `pos` (or `text.len()`).
fn align_ceil(text: &str, pos: usize) -> usize {
    let mut p = pos.min(text.len());
    while p < text.len() && !text.is_char_boundary(p) {
        p += 1;
    }
    p
}

/// Escape `"`, `<`, `>`, `&`, AND C0 control characters (U+0000..U+001F
/// + U+007F) for safe insertion into XML-ish attribute values. Other
/// characters pass through.
///
/// Adversarial round 1 (Claude Critical 2): unescaped control characters
/// in `source` (e.g. `\n`, `\r`, `\t`) allowed attribute-line forgery
/// in the wrapped output — an LLM consuming the wrapped text reads the
/// post-newline characters as a fresh prose directive. This function
/// now replaces all C0 controls with `&#xNN;` numeric character
/// references so they cannot break the attribute line or be interpreted
/// as line-structuring tokens by a downstream parser/lexer.
fn escape_attr(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("&quot;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            // C0 controls (U+0000..U+001F) + DEL (U+007F): replace with
            // numeric character reference. This neutralizes \n, \r, \t,
            // NUL, etc. without losing their textual identity.
            c if (c as u32) < 0x20 || c == '\u{007F}' => {
                out.push_str(&format!("&#x{:02X};", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

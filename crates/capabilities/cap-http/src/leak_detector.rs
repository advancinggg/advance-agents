//! `DefaultLeakDetector` — Aho-Corasick + Regex two-pass engine over the 8
//! `LEAK_PATTERNS` from MODULE-012 §1.4.2. Combines findings into
//! `Block / Redact / Warn` per the per-pattern action; supports a
//! `scan_headers` method with the Slice B canonical signature
//! `&[(String, String)]` (see MODULE-012 §2.3 + §3.6).

use advance_shared_types::security_validator::{
    Action, Finding, LeakDetector, ScanContext, ScanResult,
};
use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use regex::Regex;
use std::sync::Arc;

use crate::invisible::canonical_scan_text;
use crate::patterns::{PatternSpec, LEAK_PATTERNS};

/// Compile-time default scan cap (1 MiB). Used when no live source is wired —
/// MODULE-012 §2.10 `security.leak_detector.max_scan_bytes` default.
pub const MAX_SCAN_BYTES: usize = 1024 * 1024;

/// Live per-scan cap source (Wave-16 Lane-4, MODULE-012 AC-17 hot-reload). The
/// cli composition root injects a closure reading
/// `provider.current().security.leak_detector.max_scan_bytes`, so a hot-reloaded
/// value takes effect without restart. cap-http stays `crates/runtime`-dep-free
/// (the runtime config is read entirely on the cli side of the closure).
pub type ScanCapSource = Arc<dyn Fn() -> usize + Send + Sync>;

pub struct DefaultLeakDetector {
    /// Aho-Corasick automaton built from NON-EMPTY seeds. Patterns with no
    /// useful prefix (empty seed) are routed through the `regex_only` path
    /// instead — running them through AC with an empty seed degenerates to
    /// "match at every byte" (O(n²) when paired with regex confirmation).
    ac: Option<AhoCorasick>,
    /// `LEAK_PATTERNS` indices for AC-eligible patterns (parallel to the
    /// AC's pattern_idx). `ac_indexed[m.pattern().as_usize()]` gives the
    /// index into `compiled`.
    ac_indexed: Vec<usize>,
    /// `LEAK_PATTERNS` indices for regex-only patterns. Slice B uses
    /// `regex.find_iter` directly for these.
    regex_only: Vec<usize>,
    compiled: Vec<CompiledPattern>,
    /// Optional live scan-cap source (MODULE-012 AC-17 hot-reload). `None` →
    /// the compile-time `MAX_SCAN_BYTES` default (prior behaviour).
    scan_cap_source: Option<ScanCapSource>,
}

struct CompiledPattern {
    spec: &'static PatternSpec,
    regex: Regex,
}

impl DefaultLeakDetector {
    pub fn new() -> Self {
        let compiled: Vec<CompiledPattern> = LEAK_PATTERNS
            .iter()
            .map(|p| CompiledPattern {
                spec: p,
                regex: Regex::new(p.regex).expect("static regex compiles"),
            })
            .collect();
        let mut ac_seeds: Vec<&'static str> = Vec::new();
        let mut ac_indexed: Vec<usize> = Vec::new();
        let mut regex_only: Vec<usize> = Vec::new();
        for (i, p) in LEAK_PATTERNS.iter().enumerate() {
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
        Self {
            ac,
            ac_indexed,
            regex_only,
            compiled,
            scan_cap_source: None,
        }
    }

    /// Wire a live scan-cap source (MODULE-012 AC-17 hot-reload). Builder-style,
    /// additive — `new()` / `default()` keep the compile-time `MAX_SCAN_BYTES`.
    pub fn with_scan_cap_source(mut self, source: ScanCapSource) -> Self {
        self.scan_cap_source = Some(source);
        self
    }

    /// Effective per-scan byte cap: the live source if wired, else the
    /// compile-time default. Read at the point of use so a hot-reloaded value
    /// takes effect on the next scan without restart.
    fn scan_cap(&self) -> usize {
        match &self.scan_cap_source {
            Some(f) => f(),
            None => MAX_SCAN_BYTES,
        }
    }

    /// High-confidence ASCII prefix per pattern that the AC table searches
    /// for before invoking the regex. Empty seed routes the pattern through
    /// the `regex_only` path (regex.find_iter).
    /// AC seed selection — must match a SUBSTRING that appears at the START
    /// of the regex's match (not just within it) AND must NOT include
    /// trailing whitespace literals (the regex's own `\s+` / `\s*` handles
    /// any whitespace, but a literal space in the AC seed only matches a
    /// single ASCII space and misses tab / newline / CR variants).
    ///
    /// Adversarial round 2 (Claude Critical 1): seeds `"Bearer "` and
    /// `"-----BEGIN "` (with trailing literal space) missed `Bearer\t...`
    /// and `-----BEGIN\trsa PRIVATE KEY-----` because AC seed match
    /// requires the literal space character. RFC 7235 OWS allows `\t`
    /// between header tokens, so this was a real-world bypass for tab/
    /// newline-separated bearer tokens. Fix: drop the trailing space from
    /// these seeds; the regex's `\s+` / leading whitespace handles all
    /// whitespace variants.
    fn ac_seed(pat: &PatternSpec) -> &'static str {
        match pat.name {
            "openai_api_key" => "sk-proj-",
            "anthropic_api_key" => "sk-ant-api",
            "aws_access_key" => "AKIA",
            "github_token" => "gh",            // matches both ghp_ and ghs_
            "pem_private_key" => "-----BEGIN", // no trailing space (R2 fix)
            "bearer_token" => "Bearer",        // no trailing space (R2 fix)
            "auth_header_basic" => "Authorization:",
            "high_entropy_hex" => "",
            _ => "",
        }
    }
}

impl Default for DefaultLeakDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl LeakDetector for DefaultLeakDetector {
    fn scan(&self, text: &str, _context: ScanContext) -> ScanResult {
        // Invariant 4: overflow fail-CLOSED. Cap measured against raw caller
        // input BEFORE strip — denies pre-strip-amplification attacks.
        // AC-17: `scan_cap()` reads the live `security.leak_detector.max_scan_bytes`
        // when wired (hot-reload), else the compile-time default.
        if text.len() > self.scan_cap() {
            return ScanResult::Blocked {
                findings: vec![Finding {
                    pattern_name: "scan_overflow".to_string(),
                    offset: 0,
                    length: 0,
                    action: Action::Block,
                }],
            };
        }
        // Invariant 2: pre-strip invisible Unicode codepoints so attackers
        // can't smuggle patterns past `\s`-based regexes by interspersing
        // zero-width chars that LLM lexers ignore. Offsets in returned
        // findings are byte offsets into THIS stripped string.
        let scan_text = canonical_scan_text(text);
        let mut findings = Vec::new();
        // AC-eligible patterns: AC fast-path → regex confirmation anchored
        // at the AC start position. The strict `rm.start() == m.start()`
        // check filters out skip-ahead matches (where regex.find_at scans
        // forward past the AC offset).
        if let Some(ac) = &self.ac {
            for m in ac.find_iter(&scan_text) {
                let pat_idx = self.ac_indexed[m.pattern().as_usize()];
                let pat = &self.compiled[pat_idx];
                if let Some(rm) = pat.regex.find_at(&scan_text, m.start()) {
                    if rm.start() == m.start() {
                        findings.push(Finding {
                            pattern_name: pat.spec.name.to_string(),
                            offset: rm.start(),
                            length: rm.end() - rm.start(),
                            action: pat.spec.action.clone(),
                        });
                    }
                }
            }
        }
        // Regex-only patterns: direct find_iter (no AC fast path because
        // the pattern has no useful ASCII prefix, e.g. `high_entropy_hex`).
        // Linear time per pattern.
        for &pat_idx in &self.regex_only {
            let pat = &self.compiled[pat_idx];
            for rm in pat.regex.find_iter(&scan_text) {
                findings.push(Finding {
                    pattern_name: pat.spec.name.to_string(),
                    offset: rm.start(),
                    length: rm.end() - rm.start(),
                    action: pat.spec.action.clone(),
                });
            }
        }
        if findings.is_empty() {
            return ScanResult::Clean;
        }
        // Combine actions: any Block → Blocked; any Redact → Redacted; else Warn.
        if findings.iter().any(|f| matches!(f.action, Action::Block)) {
            return ScanResult::Blocked { findings };
        }
        if findings.iter().any(|f| matches!(f.action, Action::Redact)) {
            let redacted = redact_at_offsets(&scan_text, &findings);
            return ScanResult::Redacted { redacted, findings };
        }
        ScanResult::Warned { findings }
    }

    fn scan_headers(&self, headers: &[(String, String)]) -> ScanResult {
        // Adversarial round 2 (Codex Warning 1): cap the headers count so
        // many empty/tiny pairs can't drive proportional `combined`
        // allocation before the raw_bytes overflow check fires.
        const MAX_HEADERS_COUNT: usize = 1024;
        if headers.len() > MAX_HEADERS_COUNT {
            return ScanResult::Blocked {
                findings: vec![Finding {
                    pattern_name: "scan_overflow".to_string(),
                    offset: 0,
                    length: 0,
                    action: Action::Block,
                }],
            };
        }
        // Invariant 4 cap is measured against RAW caller input (sum of
        // key + value byte lengths), NOT the synthesized stream — so
        // attacker-controlled headers don't get auto-blocked just because
        // the ": " + "\n" delimiters push them above the cap.
        //
        // **Overflow safety**: `usize` arithmetic on adversarial input
        // (e.g. `Vec::with_capacity(usize::MAX / 2)` of String pairs) could
        // wrap. Using `checked_add` on each step keeps the gate
        // deterministically fail-CLOSED — any arithmetic overflow returns
        // the same synthetic `scan_overflow` Block as a >MAX_SCAN_BYTES
        // input would. Workspace release profile sets
        // `overflow-checks = true`, so panics WOULD occur in adversarial
        // wrap-around without checked_add. Returns the same synthetic
        // `scan_overflow` Finding on overflow as `scan`.
        let mut raw_bytes: usize = 0;
        let mut overflow_detected = false;
        for (k, v) in headers {
            match k
                .len()
                .checked_add(v.len())
                .and_then(|pair| raw_bytes.checked_add(pair))
            {
                Some(next) => raw_bytes = next,
                None => {
                    overflow_detected = true;
                    break;
                }
            }
        }
        if overflow_detected || raw_bytes > self.scan_cap() {
            return ScanResult::Blocked {
                findings: vec![Finding {
                    pattern_name: "scan_overflow".to_string(),
                    offset: 0,
                    length: 0,
                    action: Action::Block,
                }],
            };
        }
        let combined: String = headers
            .iter()
            .map(|(k, v)| {
                format!(
                    "{}: {}\n",
                    sanitize_header_field(k),
                    sanitize_header_field(v)
                )
            })
            .collect();
        // Combined size is bounded by raw_bytes + (": " + "\n") * headers.len(),
        // so if raw_bytes ≤ the effective `scan_cap()` (AC-17: the live source when
        // wired, else the compile-time MAX_SCAN_BYTES) the combined stream is bounded
        // by a small additive overhead. The inner scan() re-checks the SAME live
        // `scan_cap()`, so if combined.len() somehow exceeds it (e.g. headers.len()
        // is unbounded), `scan` returns Blocked which is fail-CLOSED — the correct
        // behavior.
        self.scan(&combined, ScanContext::HttpOutbound)
    }
}

/// Build a new string with each `Action::Redact` finding's byte range
/// replaced by `[REDACTED]`. Robust against overlapping findings: ranges
/// are sorted ascending by start, then merged with the running cursor
/// (so a finding that overlaps an already-emitted redaction is absorbed
/// into the same `[REDACTED]` token rather than producing nested or
/// shifted replacements). Cost: O(k log k + n) where k = finding count
/// (sort-bounded), n = `text.len()` (walk-rebuild). For typical k ≤ 8 and
/// n ≤ 1 MiB the n-term dominates; treat as effectively linear.
///
/// **Defensive char-boundary safety**: offsets coming from `regex.find_*`
/// on `text` are guaranteed char-aligned, but a misbehaving caller
/// passing a manually-constructed `Finding` with mid-codepoint offset
/// would panic in `&text[..]` slicing. Each merged range is clamped to
/// `text.len()` AND stepped forward to the nearest char boundary so the
/// slicing is panic-safe even on adversarial inputs.
fn redact_at_offsets(text: &str, findings: &[Finding]) -> String {
    // Use checked_add so an adversarial Finding (e.g. deserialized JSON
    // with offset = usize::MAX) doesn't panic under workspace
    // overflow-checks = true. Saturating to text.len() means the range
    // is clamped to a no-op suffix, which align_floor/align_ceil + the
    // walk-rebuild guard handle gracefully (skip-already-emitted branch).
    // Adversarial round 1 (Claude Warning 6) finding.
    let text_len = text.len();
    let mut redact_ranges: Vec<(usize, usize)> = findings
        .iter()
        .filter(|f| matches!(f.action, Action::Redact))
        .map(|f| {
            let end = f.offset.checked_add(f.length).unwrap_or(text_len);
            (f.offset.min(text_len), end.min(text_len))
        })
        .collect();
    redact_ranges.sort_by_key(|(start, _)| *start);
    // Merge overlapping / adjacent ranges so each becomes a single token.
    let mut merged: Vec<(usize, usize)> = Vec::with_capacity(redact_ranges.len());
    for (start, end) in redact_ranges {
        match merged.last_mut() {
            Some(last) if start <= last.1 => {
                last.1 = last.1.max(end);
            }
            _ => merged.push((start, end)),
        }
    }
    // Walk the input, emitting unredacted spans + `[REDACTED]` per merged range.
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0usize;
    for (start, end) in merged {
        let s = align_to_char_boundary_floor(text, start);
        let e = align_to_char_boundary_ceil(text, end);
        // Skip degenerate ranges that align to the cursor or before it
        // (e.g. start = end = 0 with empty text, or overlap absorbed by
        // a prior emit).
        if s < cursor {
            cursor = cursor.max(e);
            continue;
        }
        if cursor < s {
            out.push_str(&text[cursor..s]);
        }
        out.push_str("[REDACTED]");
        cursor = e;
    }
    if cursor < text.len() {
        out.push_str(&text[cursor..]);
    }
    out
}

/// Replace `\r` and `\n` in a header key or value with a single space.
/// Defends against attacker-controlled CRLF injection that would
/// otherwise bridge a regex match across what would have been unrelated
/// headers. This matches the spirit of `http::HeaderName` /
/// `http::HeaderValue` validation (which forbid CR/LF) without adding a
/// transitive `http` crate dep.
///
/// Exposed as `pub(crate)` so the cap-http test suite can lock the
/// sanitization semantic directly (T07h) — independent of the
/// `scan_headers` regex outcome variant.
pub(crate) fn sanitize_header_field(field: &str) -> String {
    field
        .chars()
        .map(|c| if c == '\r' || c == '\n' { ' ' } else { c })
        .collect()
}

/// Floor `pos` to the largest char boundary ≤ `pos` (or 0).
fn align_to_char_boundary_floor(text: &str, pos: usize) -> usize {
    let mut p = pos.min(text.len());
    while p > 0 && !text.is_char_boundary(p) {
        p -= 1;
    }
    p
}

/// Ceil `pos` to the smallest char boundary ≥ `pos` (or `text.len()`).
fn align_to_char_boundary_ceil(text: &str, pos: usize) -> usize {
    let mut p = pos.min(text.len());
    while p < text.len() && !text.is_char_boundary(p) {
        p += 1;
    }
    p
}

#[cfg(test)]
mod tests {
    use super::sanitize_header_field;

    /// T07h — direct unit test for `sanitize_header_field` (Slice B audit R5).
    /// Locks the `\r`/`\n` → space substitution semantic IN ISOLATION,
    /// independent of regex match outcomes — ensures any future regression
    /// in the substitution is caught regardless of which `ScanResult`
    /// variant `scan_headers` produces on the bridging-attack fixture.
    #[test]
    fn t07h_sanitize_header_field_direct() {
        assert_eq!(sanitize_header_field(""), "");
        assert_eq!(sanitize_header_field("plain"), "plain");
        assert_eq!(sanitize_header_field("a\rb"), "a b");
        assert_eq!(sanitize_header_field("a\nb"), "a b");
        assert_eq!(sanitize_header_field("a\r\nb"), "a  b");
        assert_eq!(
            sanitize_header_field("benign\r\nAuthorization: Basic AAA="),
            "benign  Authorization: Basic AAA="
        );
        assert_eq!(sanitize_header_field("中文\r\n中文"), "中文  中文");
    }
}

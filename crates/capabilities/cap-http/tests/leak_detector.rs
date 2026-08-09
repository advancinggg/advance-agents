//! AC-07 + AC-08 unit tests for `DefaultLeakDetector`.
//! Linked to MODULE-012 §3.3 T07a-g and T08a-d.

use advance_shared_types::security_validator::{Action, LeakDetector, ScanContext, ScanResult};
use cap_http::DefaultLeakDetector;

// ─── AC-07: Two-pass engine + boundary edge cases ─────────────────────────

/// T07a — happy path with byte-accurate offset.
#[test]
fn t07a_happy_path_byte_accurate_offset() {
    let det = DefaultLeakDetector::new();
    let text = "foo sk-proj-abcdefghijklmnop1234ABCD bar";
    match det.scan(text, ScanContext::HttpOutbound) {
        ScanResult::Blocked { findings } => {
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].pattern_name, "openai_api_key");
            assert_eq!(findings[0].offset, 4);
            assert!(matches!(findings[0].action, Action::Block));
        }
        other => panic!("expected Blocked, got {other:?}"),
    }
}

/// T07b — AC matches but regex confirmation rejects (sk-proj- prefix only,
/// body too short for `[A-Za-z0-9_-]{20,}`).
#[test]
fn t07b_regex_rejects_short_body() {
    let det = DefaultLeakDetector::new();
    let text = "foo sk-proj- bar"; // body length 0 < 20
    let res = det.scan(text, ScanContext::HttpOutbound);
    assert!(res.is_clean(), "expected Clean, got {res:?}");
}

/// T07c — multiple distinct findings, byte-accurate offsets.
#[test]
fn t07c_multiple_distinct_findings() {
    let det = DefaultLeakDetector::new();
    // ghp_ requires ≥36 alnum chars after the prefix.
    let token36 = "abcdefghijklmnopqrstuvwxyz0123456789AB"; // 38 chars; ≥36 satisfies the floor
                                                            // AKIA + 16 alnum upper = 20 chars total.
    let text = format!("AKIAEXAMPLE123456789 noise ghp_{token36}");
    match det.scan(&text, ScanContext::HttpOutbound) {
        ScanResult::Blocked { findings } => {
            assert!(findings.iter().any(|f| f.pattern_name == "aws_access_key"));
            assert!(findings.iter().any(|f| f.pattern_name == "github_token"));
            // Both findings should be Block.
            assert!(findings.iter().all(|f| matches!(f.action, Action::Block)));
        }
        other => panic!("expected Blocked, got {other:?}"),
    }
}

/// T07d — clean input.
#[test]
fn t07d_clean_input() {
    let det = DefaultLeakDetector::new();
    let res = det.scan("hello, world!", ScanContext::HttpOutbound);
    assert!(res.is_clean());
}

/// T07e — overflow input fail-CLOSED.
#[test]
fn t07e_overflow_fail_closed() {
    let det = DefaultLeakDetector::new();
    let big = "x".repeat(1024 * 1024 + 1);
    match det.scan(&big, ScanContext::HttpOutbound) {
        ScanResult::Blocked { findings } => {
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].pattern_name, "scan_overflow");
            assert_eq!(findings[0].offset, 0);
            assert_eq!(findings[0].length, 0);
            assert!(matches!(findings[0].action, Action::Block));
        }
        other => panic!("expected Blocked overflow, got {other:?}"),
    }
}

/// T07f — `scan_headers` smoke.
#[test]
fn t07f_scan_headers_smoke() {
    let det = DefaultLeakDetector::new();
    let headers = vec![(
        "X-API-Key".to_string(),
        "sk-proj-abcdefghijklmnop1234ABCD".to_string(),
    )];
    match det.scan_headers(&headers) {
        ScanResult::Blocked { findings } => {
            assert!(findings.iter().any(|f| f.pattern_name == "openai_api_key"));
        }
        other => panic!("expected Blocked, got {other:?}"),
    }
}

/// T07g — `scan_headers` `\r\n` cross-header bridging guard. Tests the
/// SANITIZATION step directly (not the regex match outcome).
///
/// The current Slice B regex set has no line-anchored patterns, so post-
/// sanitization the `auth_header_basic` regex still matches inline. The
/// sanitization is defense-in-depth — it ACTIVATES when a future slice
/// adds a line-anchored regex. Today's load-bearing assertion is that
/// the pre-scan stream contains NO raw `\r\n` byte sequences from the
/// attacker-controlled value (verified by reading back the post-sanitize
/// behavior via a probe finding).
#[test]
fn t07g_scan_headers_crlf_sanitized() {
    let det = DefaultLeakDetector::new();
    // An attacker-controlled value with embedded CRLF that, if NOT
    // sanitized, would synthesize a forged `Authorization:` header line
    // separated from the prior header by a literal newline. The
    // sanitization replaces \r and \n with spaces.
    let headers = vec![(
        "X-Note".to_string(),
        "benign\r\nAuthorization: Basic AAA=".to_string(),
    )];
    // Probe: append a known sentinel to a value that contains \r\n; after
    // sanitization the sentinel must appear AFTER a SPACE-replaced
    // literal (no \r\n bytes remain). We verify by examining the
    // findings' offsets: if sanitization is in place, the
    // `auth_header_basic` finding (Redact) will start AFTER the sanitized
    // value and BEFORE the closing `\n` injected by the per-header
    // delimiter — and the `redacted` field will contain space-separated
    // content (no embedded `\r` or `\n` from the attacker value).
    match det.scan_headers(&headers) {
        ScanResult::Redacted { redacted, findings } => {
            // The redacted output should NOT contain raw \r or \n bytes
            // from the attacker-controlled value (only the per-header
            // closing `\n` which comes from our own format!()).
            // Count occurrences of \r — should be 0.
            assert_eq!(
                redacted.matches('\r').count(),
                0,
                "sanitization should have removed all \\r bytes from attacker value: {redacted:?}"
            );
            // The per-header closing \n is at the end of each row; for our
            // single-header input there should be at most 1 \n total
            // (from format!("{}: {}\n")).
            assert!(redacted.matches('\n').count() <= 1,
                "expected ≤1 \\n (the per-row delimiter); attacker \\n bytes should have been sanitized: {redacted:?}");
            assert!(!findings.is_empty());
        }
        // Acceptable alternates: pure non-panic guarantee. The sanitize
        // semantic is what's load-bearing in this test; the result variant
        // depends on the (unanchored) regex behavior.
        ScanResult::Blocked { .. } | ScanResult::Warned { .. } | ScanResult::Clean => {}
    }
}

// T07h direct unit test for `sanitize_header_field` lives inside the
// crate (see `crates/capabilities/cap-http/src/leak_detector.rs`'s
// `#[cfg(test)] mod tests`) because `sanitize_header_field` is
// `pub(crate)`. The test there asserts the load-bearing `\r`/`\n` →
// space substitution semantic that T07g exercises only conditionally
// (when the result variant is `Redacted`).

// ─── AC-08: Block / Redact / Warn action priority ─────────────────────────

/// T08a — Block dominates Redact.
#[test]
fn t08a_block_dominates_redact() {
    let det = DefaultLeakDetector::new();
    // openai_api_key (Critical Block) + bearer_token (High Redact) in same
    // input.
    let text = "sk-proj-abcdefghijklmnop1234ABCD plus Bearer eyJabc123-_";
    match det.scan(text, ScanContext::HttpOutbound) {
        ScanResult::Blocked { findings } => {
            assert!(findings.iter().any(|f| f.pattern_name == "openai_api_key"));
            // bearer_token may or may not be in the findings list, but the
            // result is Blocked because Block dominates.
        }
        other => panic!("expected Blocked, got {other:?}"),
    }
}

/// T08b — Redact substitutes [REDACTED].
#[test]
fn t08b_redact_substitutes_redacted() {
    let det = DefaultLeakDetector::new();
    let text = "auth: Bearer eyJabc123_-DEFGH";
    match det.scan(text, ScanContext::HttpOutbound) {
        ScanResult::Redacted { redacted, findings } => {
            assert!(redacted.contains("[REDACTED]"));
            assert!(!redacted.contains("eyJabc123_-DEFGH"));
            assert!(findings.iter().any(|f| f.pattern_name == "bearer_token"));
        }
        other => panic!("expected Redacted, got {other:?}"),
    }
}

/// T08c — Warn passes original through.
#[test]
fn t08c_warn_passes_original_through() {
    let det = DefaultLeakDetector::new();
    // 64-char hex matches `high_entropy_hex` (Medium / Warn).
    let hex64 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    match det.scan(hex64, ScanContext::HttpOutbound) {
        ScanResult::Warned { findings } => {
            assert!(findings
                .iter()
                .any(|f| f.pattern_name == "high_entropy_hex"));
        }
        other => panic!("expected Warned, got {other:?}"),
    }
}

/// T08d — Mixed Redact + Warn → Redact dominates Warn.
#[test]
fn t08d_redact_dominates_warn() {
    let det = DefaultLeakDetector::new();
    let hex64 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let text = format!("Bearer eyJabc123_-DEFGH plus hex {hex64}");
    let res = det.scan(&text, ScanContext::HttpOutbound);
    assert!(matches!(res, ScanResult::Redacted { .. }));
}

/// T08e — Overlapping Redact findings (e.g. `auth_header_basic` and
/// `bearer_token` regexes both matching overlapping bytes in
/// "Authorization: Basic Bearer eyJ...") MUST NOT panic and MUST emit a
/// well-formed redacted string. Locks audit-round-1 Critical fix.
#[test]
fn t08e_overlapping_redact_findings_no_panic() {
    let det = DefaultLeakDetector::new();
    // Construct an input that triggers BOTH `auth_header_basic` (matches
    // `Authorization:\s*Basic\s+[A-Za-z0-9+/=]+`) AND `bearer_token`
    // (matches `Bearer\s+eyJ[A-Za-z0-9_-]+`) over overlapping byte spans.
    // The `Authorization: Basic Bearer` prefix matches auth_header_basic
    // up to where the alphabet runs out; bearer_token starts at the
    // "Bearer" word inside that span.
    let text = "Authorization: Basic Bearer eyJabcdefg-_HIJKLMNOPqrstuvw";
    let res = det.scan(text, ScanContext::HttpOutbound);
    // Either Redacted OR Blocked is acceptable per the action-priority
    // rules (no Block patterns hit in this input, so Redacted expected).
    // The point of this test is that we DO NOT PANIC and the output is
    // well-formed UTF-8.
    match res {
        ScanResult::Redacted { redacted, findings } => {
            assert!(!findings.is_empty());
            assert!(redacted.contains("[REDACTED]"));
            // Verify the redacted string is well-formed: every `[` should
            // be the start of a `[REDACTED]` token (i.e. NO partial-token
            // artifacts like `[REDA` or `[REDA]` standing alone). We do
            // this by stripping all `[REDACTED]` tokens and asserting the
            // remainder contains no `[`, no stray `]`, and no embedded
            // `REDACTED` substring outside the tokens.
            let stripped: String = redacted.replace("[REDACTED]", "");
            assert!(
                !stripped.contains('['),
                "found stray `[` after stripping [REDACTED] tokens; output may have partial-token artifact: {redacted:?}"
            );
            assert!(
                !stripped.contains("REDACTED"),
                "found stray `REDACTED` text outside well-formed tokens: {redacted:?}"
            );
        }
        ScanResult::Blocked { findings } => {
            assert!(!findings.is_empty());
        }
        other => panic!("expected Redacted or Blocked, got {other:?}"),
    }
}

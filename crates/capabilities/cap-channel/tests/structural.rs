//! Structural / tripwire tests for cap-channel.
//!
//! - T03 (AC-08 tripwire): cargo-metadata check that cap-channel has no
//!   MODULE-006 crate dep (currently passes trivially — no such crate exists).
//! - T04 (AC-08 tripwire): source grep for forbidden MODULE-006 symbols
//!   (IdentityResolver / MessageTrace / unified_user_id).
//! - T08 (AC-08): source grep for `notify_agent(...)`, `notify_channel(...)`,
//!   `MailboxDispatcher::*` call sites (word-boundary regex avoids false
//!   positives on `NotifyError` enum / kebab-case doc strings).
//! - `wit_method_set_frozen`: pins the 3 WIT method names in order.
//! - `send_raw_routes_through_dispatcher`: pins SendRawHandler → dispatcher
//!   invariant.
//! - `dispatcher_is_sole_security_chain_consumer`: pins
//!   `security_chain.execute` to one src/ location.

use std::fs;
use std::path::{Path, PathBuf};

use cap_channel::{CHANNEL_HOST_METHODS, CHANNEL_HOST_NAMESPACE};

fn crate_root() -> PathBuf {
    let manifest = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest)
}

fn src_dir() -> PathBuf {
    crate_root().join("src")
}

fn read_all_src() -> Vec<(PathBuf, String)> {
    let mut out = Vec::new();
    collect_rs_files(&src_dir(), &mut out);
    out
}

fn collect_rs_files(dir: &Path, out: &mut Vec<(PathBuf, String)>) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                collect_rs_files(&path, out);
            } else if path.extension().map(|e| e == "rs").unwrap_or(false) {
                if let Ok(content) = fs::read_to_string(&path) {
                    out.push((path, content));
                }
            }
        }
    }
}

fn strip_line_comments_and_strings(line: &str) -> String {
    // Best-effort: drop the contents of `// ...` line comments and `"..."`
    // string literals so structural regexes don't match identifiers that
    // only appear in comments or doc-strings. Multi-line string literals
    // and `/* */` blocks are out of scope for this lightweight scrubber —
    // identifiers in those locations would produce false positives, but
    // cap-channel doesn't use them in a way that conflicts with these
    // regexes (verified by hand at write-time).
    let mut result = String::new();
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'/' {
            break;
        }
        if bytes[i] == b'"' {
            // Skip to closing quote (best-effort; doesn't handle escaped
            // quotes — false positives on `\"` inside strings are
            // tolerable for the scan's purpose).
            i += 1;
            while i < bytes.len() && bytes[i] != b'"' {
                if bytes[i] == b'\\' && i + 1 < bytes.len() {
                    i += 2;
                    continue;
                }
                i += 1;
            }
            i += 1;
            continue;
        }
        result.push(bytes[i] as char);
        i += 1;
    }
    result
}

/// Search for occurrences of `needle` in cap-channel sources, returning a list
/// of `(path, line_number, raw_line)` matches. Skips comment-only and
/// string-literal matches.
fn grep_src(needle: &str) -> Vec<(PathBuf, usize, String)> {
    let mut hits = Vec::new();
    for (path, contents) in read_all_src() {
        for (lineno, line) in contents.lines().enumerate() {
            let stripped = strip_line_comments_and_strings(line);
            if stripped.contains(needle) {
                hits.push((path.clone(), lineno + 1, line.to_string()));
            }
        }
    }
    hits
}

// ============================================================================
// T03 (AC-08 tripwire): no MODULE-006 / messaging crate as a dependency
// ============================================================================

#[test]
fn t03_cargo_manifest_has_no_messaging_dep() {
    let manifest = fs::read_to_string(crate_root().join("Cargo.toml")).unwrap();
    let forbidden = ["cap-messaging", "advance-messaging"];
    for name in forbidden {
        // Match dependency declarations of the form `name = ...` (at line
        // start, allowing leading whitespace). Avoid false positives on
        // comments that happen to mention these crate names.
        for line in manifest.lines() {
            let stripped = strip_line_comments_and_strings(line);
            let trimmed = stripped.trim_start();
            assert!(
                !trimmed.starts_with(&format!("{name} =")),
                "cap-channel must not depend on {name}; found line {line:?}"
            );
        }
    }
}

// ============================================================================
// T04 (AC-08 tripwire): no MODULE-006 internal symbols in cap-channel sources
// ============================================================================

#[test]
fn t04_source_has_no_identity_resolver_symbols() {
    let forbidden_symbols = ["IdentityResolver", "MessageTrace", "unified_user_id"];
    for symbol in forbidden_symbols {
        let hits = grep_src(symbol);
        assert!(
            hits.is_empty(),
            "cap-channel must not reference MODULE-006 symbol {symbol:?}; found: {hits:?}"
        );
    }
}

// ============================================================================
// T08 (AC-08): no `notify_agent(...)` / `notify_channel(...)` /
// `MailboxDispatcher::*` call sites
// ============================================================================

#[test]
fn t08_no_notify_agent_call_sites() {
    // Use precise patterns: identifier followed by `(`, not bare substring,
    // to avoid false positives on `NotifyError` enum and kebab-case doc
    // strings (already filtered out by the comment-stripper).
    let forbidden_patterns = ["notify_agent(", "notify_channel(", "MailboxDispatcher::"];
    for pattern in forbidden_patterns {
        let hits = grep_src(pattern);
        assert!(
            hits.is_empty(),
            "cap-channel must not contain {pattern:?}; found: {hits:?}"
        );
    }
}

// ============================================================================
// WIT-frozen schema (Plan Eval R1 Warning #5)
// ============================================================================

#[test]
fn wit_method_set_frozen() {
    assert_eq!(CHANNEL_HOST_METHODS.len(), 3);
    assert_eq!(CHANNEL_HOST_METHODS[0], "subscribe");
    assert_eq!(CHANNEL_HOST_METHODS[1], "poll-raw");
    assert_eq!(CHANNEL_HOST_METHODS[2], "send-raw");
    assert_eq!(CHANNEL_HOST_NAMESPACE, "advance:runtime/channel-host@0.1.0");
}

// ============================================================================
// AC-09 invariants (Plan Eval R1 Critical #3 + R9 Warning #3)
// ============================================================================

#[test]
fn send_raw_routes_through_dispatcher() {
    // SendRawHandler::call must reference `dispatcher.dispatch` (or
    // equivalent — Slice B uses `outbound.dispatch`) and MUST NOT reference
    // `security_chain.execute` directly. That latter symbol may appear only
    // through the dispatcher.
    let wit_impl_path = src_dir().join("wit_impl.rs");
    let contents = fs::read_to_string(&wit_impl_path).expect("wit_impl.rs exists");

    // Must call into the dispatcher.
    assert!(
        contents.contains("outbound.dispatch") || contents.contains("dispatcher.dispatch"),
        "wit_impl.rs must reference outbound.dispatch or dispatcher.dispatch"
    );

    // Must NOT directly call security_chain.execute.
    let mut found_direct = false;
    for line in contents.lines() {
        let stripped = strip_line_comments_and_strings(line);
        if stripped.contains("security_chain.execute") {
            found_direct = true;
        }
    }
    assert!(
        !found_direct,
        "wit_impl.rs must not call security_chain.execute directly; that path lives in egress.rs (via OutboundDispatcher → HttpEgress)"
    );
}

#[test]
fn dispatcher_is_sole_security_chain_consumer() {
    // `security_chain.execute` should appear in exactly one src/ location.
    // Phase-2 Step-3 moved the single call site from outbound.rs into
    // egress.rs (`HttpEgress::send`) — `OutboundDispatcher::dispatch` is now a
    // thin delegator to `HttpEgress`, and the in-host channel pump reaches the
    // chain ONLY through `OutboundTransport`. AC-09 sole-consumer invariant is
    // re-established at the new location. Test helpers / tests/ are out of scope
    // (we only scan src/).
    let hits = grep_src("security_chain.execute");
    let egress_path = src_dir().join("egress.rs");
    assert_eq!(
        hits.len(),
        1,
        "expected exactly 1 src/ occurrence of security_chain.execute, got {}: {hits:?}",
        hits.len()
    );
    assert_eq!(
        hits[0].0, egress_path,
        "security_chain.execute must live only in egress.rs (HttpEgress::send)"
    );
}

// ============================================================================
// AC-02 supplementary: no Gateway / Proxy / Bridge type names in public API
// ============================================================================

#[test]
fn no_gateway_proxy_bridge_types_in_public_surface() {
    // `pub struct Gateway` / `pub enum Proxy` / etc. would falsely suggest
    // cap-channel implements a "gateway class" — which AC-02 forbids.
    let forbidden = [
        "pub struct Gateway",
        "pub enum Gateway",
        "pub struct Proxy",
        "pub enum Proxy",
        "pub struct Bridge",
        "pub enum Bridge",
    ];
    for needle in forbidden {
        let hits = grep_src(needle);
        assert!(
            hits.is_empty(),
            "cap-channel public surface must not declare {needle:?}; found: {hits:?}"
        );
    }
}

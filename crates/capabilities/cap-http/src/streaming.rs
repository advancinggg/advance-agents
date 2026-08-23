//! CONTRACT-233 `HttpStreamingChain` implementation (ADR 2026-07-22 slice S3).
//!
//! `DefaultHttpSecurityChain::execute_streaming` = the shared outbound steps
//! 1–6 (byte-identical with the buffered path — one helper, one step-4
//! credential-injection site), then the cap-http-owned `HttpStreamExecutor`
//! transport, then TWO head-header scans (injected policy plus a crate-static
//! baseline, so injection cannot subtract `LEAK_PATTERNS` coverage; buffered
//! step-9 semantics for the Blocked arm, but DIVERGING on Redacted: audit round
//! 8 extends the sanctioned
//! Redact→Block degrade to the head, because value-only header-granular
//! remediation provably cannot neutralise a match that spans the synthesized
//! join or whose payload sits in a header NAME — see `execute_streaming`), then
//! a
//! [`ScanningWireStream`] wrapping the raw wire chunks in the MODULE-012 §2.9
//! streaming scan contract:
//!
//! - per-chunk scan over the REJOINED raw bytes `overlap ++ held ++ chunk`
//!   lossy-decoded ONCE (never decode-then-concatenate: a multi-byte code
//!   point split across chunks would shatter into U+FFFD and evade the match);
//! - overlap window `W = max(min-guaranteed-match-length over LEAK_PATTERNS) - 1`
//!   COMPUTED from the live pattern table (T29 pins ≥ 99, anthropic-driven) —
//!   the detection belt for prefix-closed patterns;
//! - all four `ScanResult` arms, with the Redact→Block SANCTIONED divergence
//!   (splicing `[REDACTED]` into live frames is impossible; ADR 2026-07-22
//!   approves the degrade — locked in the Block direction by T28). Audit round
//!   8 applies the same degrade to the HEAD after two attempts to salvage a
//!   Redacted head were each defeated;
//! - hold-and-don't-emit for EVERY Block/Redact pattern (audit round 1
//!   widened this from the greedy-Redact pair): a suspected in-progress match
//!   — prefix-viability walked over the CANONICAL (invisible-stripped +
//!   per-char-NFKC) feed with a raw-offset map, using anchored dense DFAs
//!   built in the SAME Unicode syntax the detector regex uses (audit round 2:
//!   `\s`/`(?i)` fold identically, so Unicode whitespace that NFKC does NOT
//!   fold to ASCII — U+1680, U+2028 — cannot slip the hold; case-fold-to-ASCII
//!   variants such as long-s U+017F are NFKC-subsumed before the DFA sees them
//!   and were never part of that vector) — is withheld until resolved. A walk
//!   that ENTERS a match state reports `Matched`, not `Dead` (audit round 5),
//!   so a completed credential is held even when the detector's whole-string
//!   canonicalization disagrees with this per-char feed. This closes the
//!   unbounded-interior Block evasion (`pem_private_key`'s `[A-Z ]*` defeats
//!   any finite window), gives uniform "no partial credential bytes emit" for
//!   Block patterns, and defeats invisible-inflation of a forming credential.
//!   The emitted-stream overlap is retained in CANONICAL-byte width
//!   (best-effort — raw retention is capped at 8 KiB, so it is
//!   defense-in-depth for the per-char-NFKC residual, NOT a guarantee; the
//!   hold, not the overlap, is the primary guard). A hold crossing
//!   [`MAX_HOLD_BYTES`] fails CLOSED (T27); [`MAX_CHAIN_STREAM_BYTES`] caps
//!   cumulative raw bytes over ANY executor before scan-buffer duplication; a
//!   count-only NFKC preflight runs before detector allocation, and the
//!   canonical projection + one-`usize`-per-byte map are capped by
//!   [`MAX_CANONICAL_SCAN_BYTES`]. The checked-`u128` re-scan debt/credit ledger
//!   ([`MAX_SCAN_DEBT_BYTES`] + [`SCAN_CREDIT_PER_WIRE_BYTE`]) fails CLOSED
//!   against invisible-inflation and hold-retention drips, and
//!   [`MAX_CONSECUTIVE_EMPTY_CHUNKS`] bounds a zero-progress (empty-frame)
//!   flood. The availability property these buy is narrow and worth stating
//!   exactly (audit round 7): an ORDINARY stream — one whose canonical
//!   projection tracks its raw length — is not cut however finely chunked, not
//!   even at one byte per frame. Credential-free traffic can still be cut when
//!   it is pathological in shape rather than in content: an invisible-dense
//!   stream pins the belt and fails CLOSED on the ledger, a hold-viable drip
//!   (e.g. an endless `pem_private_key` `[A-Z ]*` interior) is cut by the hold
//!   cap, and a candidate-dense tail can exhaust the EOF sweep budget. All
//!   fail CLOSED, none leak — but "never cuts a clean stream" would be false.
//!   EOF flushes an outstanding hold ONLY when a non-short-circuiting sweep of
//!   the whole held region finds no completed match — otherwise it fails
//!   CLOSED. One chain-entry deadline wraps the arbitrary executor head future
//!   and every pull with timer + post-poll precedence checks. The shared
//!   outbound helper also gates after each bounded synchronous collaborator,
//!   including nested secret resolutions and redirect URL/header/SSRF stages,
//!   before dispatching the next callback or future; the HEAD path gates
//!   request/response telemetry before head scanning. A HEAD-specific wrapper
//!   owns late-success output before discarding it. Every absorbing terminal clears retained allocations and
//!   synchronously drops the boxed inner response, then re-arbitrates the
//!   deadline. CONTRACT-233 streaming is opt-in under one transitive
//!   composition precondition: synchronous callbacks, future cancellation/drop,
//!   and object `Drop` for every reachable collaborator (secret backend,
//!   detector, SSRF guard, rate limiter, tracer, event sink, executor/nested
//!   redirect callback, and wire stream) are bounded, non-blocking, panic-free,
//!   and perform no network/progress wait during cancellation or destruction.
//!   The executor seam rules are specializations of that precondition. No
//!   detached cleanup worker, thread, or queue is created.
//!
//! Residual: the viability feed still applies NFKC per source char. Mn/Me/Cf
//! and the historical invisible set are dropped by the same
//! `is_dropped_from_scan_derivative` predicate the detector uses
//! (MODULE-012-AC-24), so a spliced combining mark no longer splits the two
//! paths. Remaining per-char vs whole-string NFKC disagreement is Hangul jamo
//! / Mc composition, not the leak-anchor splice. A completed match that then
//! dies on a **non-dropped** killer byte is still held (`Matched`-before-`Dead`).
//! A first-letter whose raw encoding splits across a chunk boundary is
//! withheld via the trailing-incomplete-sequence rule rather than
//! canonicalized early.

use crate::executor::{DefaultRedirectCheck, ExecutorError, WireChunkStream};
use crate::leak_detector::DefaultLeakDetector;
use crate::patterns::LEAK_PATTERNS;
use crate::security_chain::{
    ensure_stream_stage_deadline, method_label, redacted_host_scheme, DefaultHttpSecurityChain,
    STEP_EXECUTE, STEP_REDACT_ERROR_MESSAGE,
};
use advance_shared_types::event::Event;
use advance_shared_types::security_validator::{
    Action, Finding, HttpBodyStream, HttpCapability, HttpError, HttpRequest, HttpResponseHead,
    HttpStreamingChain, LeakDetector, RedirectCheck, ScanContext, ScanResult, TransportErrorKind,
};
use advance_shared_types::traits::EventBusEmit;
use async_trait::async_trait;
use regex_automata::dfa::{dense, Automaton};
use regex_automata::{Anchored, Input};
use serde_json::json;
use std::sync::{Arc, OnceLock};

/// Hold accumulator cap (MODULE-012 §2.9 term 4): a suspected in-progress
/// match withheld past this many bytes fails CLOSED.
pub const MAX_HOLD_BYTES: usize = 256 * 1024;

/// Maximum canonical projection retained for one viability decision. NFKC can
/// expand one raw scalar into many canonical bytes, and `canonical_map` stores
/// one raw-offset `usize` per canonical byte. A raw wire cap alone therefore
/// does not bound scan memory when a weak injected detector allows a large
/// compatibility-character chunk through. Crossing this cap fails CLOSED as
/// the existing `stream_scan_budget` terminal.
const MAX_CANONICAL_SCAN_BYTES: usize = 8 * 1024 * 1024;

/// Chain-owned cumulative raw-wire cap applied to every `HttpStreamExecutor`,
/// including custom implementations that do not use `ReqwestChunkStream`.
/// Checked before `scan_buf` duplicates a chunk.
const MAX_CHAIN_STREAM_BYTES: usize = 8 * 1024 * 1024;

/// Fixed re-scan allowance for work that FRESH wire bytes did not pay for
/// (audit rounds 1/3/4/5). Every round re-processes the retained
/// `overlap ++ held`, so an adversarial drip-feed can do work super-linear in
/// the wire bytes. The guard is a DEBT/CREDIT ledger, checked per round:
///
/// - checked `u128` **debt** += `overlap.len() + held.len() + 1`;
/// - checked `u128` **credit** += `chunk.len() * SCAN_CREDIT_PER_WIRE_BYTE`;
/// - fail CLOSED on arithmetic overflow or when
///   `debt − credit > MAX_SCAN_DEBT_BYTES`.
///
/// Audit round 12 replaced saturating `usize` counters: on 32-bit, credit could
/// reach `usize::MAX` first and permanently force `saturating_sub` to zero even
/// after debt saturated. Checked `u128` preserves banked credit without making
/// saturation a guard bypass.
///
/// Accepted-round retained-byte re-processing is bounded by
/// `MAX_SCAN_DEBT_BYTES + SCAN_CREDIT_PER_WIRE_BYTE × wire_bytes`. Because the
/// ledger is charged after scanning, the rejecting round can add one more
/// bounded scan (`overlap ≤ 8 KiB`, `held ≤ 256 KiB`, fresh bytes still under
/// [`MAX_CHAIN_STREAM_BYTES`]); the total remains linear in delivered bytes,
/// but the shorter formula alone is not a bound that includes that terminal
/// round.
///
/// Why a ledger and not a flat charge (the round-3 ↔ round-4 pendulum):
/// - charging the FULL retained buffer against a flat cap (round 3) bounded
///   the work but cut LEGITIMATE finely-chunked streams at ~339 K rounds;
/// - charging only the overlap EXCESS beyond `window` (round 4) freed clean
///   streams but bounded the round COUNT rather than the WORK — and empty
///   HTTP/2 DATA frames cost 0 wire bytes (so never trip `max_response_bytes`)
///   while still driving a full detector pass over the pinned belt, grinding
///   ~3.3 GB of canonicalize+regex work for free.
/// The ledger keeps both properties: an ORDINARY stream — one whose canonical
/// projection tracks its raw length — nets NEGATIVE every round (≈100 debt vs
/// ≥128 credit even at 1-byte frames) so this ledger never cuts it (the hold cap
/// and the EOF sweep budget are separate terminals, and credential-free traffic
/// that is pathological in SHAPE can still be cut), and an
/// invisible-inflation drip (belt pinned at 8 KiB, 3-byte frames: ~8193 debt
/// vs 384 credit) fails CLOSED in a few thousand rounds.
///
/// Two honest bounds this does NOT provide, each covered elsewhere:
/// - a zero-progress flood is bounded by [`MAX_CONSECUTIVE_EMPTY_CHUNKS`], not
///   by this ledger: with `overlap` and `held` both empty the per-round debt is
///   ~1, so the allowance alone would tolerate 33.5 M rounds (audit round 6 —
///   an earlier version of this comment claimed "~335 K rounds ≈ sub-second",
///   which silently assumed a pre-filled belt);
/// - the WORST-CASE work bound is `MAX_SCAN_DEBT_BYTES + SCAN_CREDIT_PER_WIRE_BYTE
///   × wire_bytes` ≈ 1 GiB of canonicalize+scan at the 8-MiB default
///   `max_response_bytes` — roughly 32× looser than a flat charge would give.
///   That constant IS the price of supporting 1-byte frames (credit must
///   exceed the ~100-byte per-round baseline or a legitimate finely-chunked
///   stream is cut); it stays bounded, fail-safe and linear in delivered
///   bytes, and is further bounded by the wire cap, the per-frame idle
///   timeout, the 300 s stream deadline and the chain's step-6 rate limiter.
pub const MAX_SCAN_DEBT_BYTES: usize = 32 * 1024 * 1024;

/// Re-scan credit granted per FRESH wire byte. Must exceed
/// `window + 1` (≈100) so that even a 1-byte-per-frame legitimate stream nets
/// negative and is never cut BY THIS LEDGER (the hold cap and the EOF sweep
/// budget are separate terminals). Larger values only widen the margin for
/// legitimate traffic; they do not weaken flood containment, because
/// zero-progress floods are bounded by [`MAX_CONSECUTIVE_EMPTY_CHUNKS`] and NOT
/// by this ledger (audit round 7 — this comment previously mis-attributed that
/// bound to [`MAX_SCAN_DEBT_BYTES`], contradicting the ledger's own doc 18
/// lines above).
pub const SCAN_CREDIT_PER_WIRE_BYTE: usize = 128;

/// Consecutive zero-length upstream chunks tolerated before failing CLOSED
/// (audit round 6). Empty frames carry no wire bytes, so neither
/// `max_response_bytes` nor the byte ledger (which charges ~1 per round while
/// `overlap` and `held` are empty) bounds a leading empty-frame flood in
/// useful time — 33.5 M rounds of allocate-scan-yield would otherwise run to
/// the 300 s stream deadline. A legitimate upstream never emits this many
/// consecutive payload-free frames; keep-alives arrive far apart in time, not
/// thousands back-to-back.
pub const MAX_CONSECUTIVE_EMPTY_CHUNKS: usize = 1024;

/// Minimum guaranteed match length (bytes) of a LEAK_PATTERNS regex, computed
/// from its parsed HIR. `0` for an unparseable pattern (static patterns are
/// pinned by tests; a shrunk value only ever ENLARGES nothing — the max over
/// the table drives the window and T29 pins the floor).
pub(crate) fn pattern_min_len(regex: &str) -> usize {
    regex_syntax::Parser::new()
        .parse(regex)
        .ok()
        .and_then(|hir| hir.properties().minimum_len())
        .unwrap_or(0)
}

/// Overlap window `W = (max min-guaranteed-match-length over LEAK_PATTERNS) - 1`
/// (MODULE-012 §2.9 term 2). Any cross-chunk match whose start lies more than
/// W bytes before the boundary already had its full minimum-length match
/// inside previously-scanned bytes, so it fired there. Retaining W canonical
/// bytes supplies that boundary belt when the raw 8-KiB cap can represent it;
/// under invisible inflation the belt is only best-effort, and the viability
/// hold is the actual no-partial-emission guard. Pinned ≥ 99
/// (anthropic_api_key-driven) by T29.
pub(crate) fn overlap_window_bytes() -> usize {
    static W: OnceLock<usize> = OnceLock::new();
    *W.get_or_init(|| {
        LEAK_PATTERNS
            .iter()
            .map(|p| pattern_min_len(p.regex))
            .max()
            .unwrap_or(1)
            .saturating_sub(1)
    })
}

/// Anchored prefix-viability matcher for one held LEAK_PATTERNS row.
struct HoldMatcher {
    dfa: dense::DFA<Vec<u32>>,
    /// Bytes that can begin a match (derived from the DFA start state, so
    /// case-insensitivity comes from the pattern itself — no hand-coded table).
    first_bytes: [bool; 256],
}

/// Build one matcher per `Action::Block` / `Action::Redact` row of
/// LEAK_PATTERNS — derived from the live table, not hand-listed. The hold
/// covers BOTH classes (audit round 1): Block patterns with an unbounded
/// interior before a required suffix (`pem_private_key`'s `[A-Z ]*`) defeat
/// any finite overlap window, and even prefix-closed Block patterns would
/// otherwise emit up to min-match-1 credential bytes before the detecting
/// chunk arrives. Holding every viable in-progress Block/Redact prefix makes
/// "no partial credential bytes emit" uniform. `Action::Warn` rows
/// (e.g. 64-hex) are deliberately EXCLUDED — Warn passes content anyway, and
/// holding would withhold legitimate hash-dense LLM output indefinitely.
///
/// Returns `Err(())` if any pattern fails to build within the size limits so
/// the caller fails CLOSED (enum-coded), rather than panicking on the first
/// request (audit round 2).
///
/// **Implementer invariant (audit round 5).** This matcher set is derived from
/// the crate-static `LEAK_PATTERNS`, while the scan it runs alongside is an
/// INJECTED `Arc<dyn LeakDetector>` chosen by the composition root — the two
/// pattern sets are not mechanically tied. That is tolerable only because the
/// hold is self-contained: since round 5 a completed match on THIS pattern set
/// holds and fail-closes on its own (see `viable_from`'s `Matched` arm), so a
/// chain wired with a weaker/no-op detector still cannot emit a
/// `LEAK_PATTERNS` credential through the streaming BODY. The HEAD uses a
/// separate crate-static `DefaultLeakDetector` baseline beside the injected
/// scan (audit round 12), so weak injection cannot subtract the static guarantee
/// there either. A composition root
/// that injects a detector with ADDITIONAL patterns, however, gets hold
/// coverage only for the static set; wire the same pattern source into both if
/// that ever matters.
fn build_hold_matchers() -> Result<Vec<HoldMatcher>, ()> {
    let mut out = Vec::new();
    for p in LEAK_PATTERNS
        .iter()
        .filter(|p| matches!(p.action, Action::Block | Action::Redact))
    {
        // ANCHORED-only + explicit size limits is what keeps the build linear
        // (audit round 1 root cause: the DEFAULT StartKind also builds
        // UNANCHORED start states, whose subset construction over counted
        // repetitions `{90,}` tracks every candidate start's counter at once —
        // a combinatorial blowup that hung the build for minutes; viability
        // only ever walks anchored starts, which determinize linearly). Syntax
        // stays UNICODE (audit round 2): the detector runs the `regex` crate
        // in default Unicode mode, so `\s`/`(?i)` MUST fold the same way here.
        // The load-bearing case is Unicode WHITESPACE — U+1680 (Ogham) / U+2028
        // (line separator) are `\p{White_Space}` but NFKC does NOT fold them to
        // ASCII space, so an ASCII-only `\s` DFA declared them dead and let a
        // crafted `Bearer<U+1680>eyJ...` forming credential slip the hold
        // (round-2 consensus Critical). Case-fold-to-ASCII variants (long-s
        // U+017F to s, etc.) are already folded by the canonical feed's NFKC
        // before the DFA sees them, so they are NOT what drives the Unicode
        // requirement — whitespace is. Unicode + anchored + bounded builds all
        // 7 rows in <=12 ms (measured). `utf8`
        // stays off — the canonical feed is valid UTF-8 but the byte DFA must
        // not restrict matches to UTF-8 boundaries. The size limits turn any
        // future pathological table edit into a fail-CLOSED build error.
        let dfa = dense::Builder::new()
            .syntax(regex_automata::util::syntax::Config::new().utf8(false))
            .configure(
                dense::Config::new()
                    .start_kind(regex_automata::dfa::StartKind::Anchored)
                    .determinize_size_limit(Some(16 * 1024 * 1024))
                    .dfa_size_limit(Some(8 * 1024 * 1024)),
            )
            .build(p.regex)
            .map_err(|_| ())?;
        let input = Input::new(&[] as &[u8]).anchored(Anchored::Yes);
        let start = dfa.start_state_forward(&input).map_err(|_| ())?;
        let mut first_bytes = [false; 256];
        for b in 0..=255u8 {
            if !dfa.is_dead_state(dfa.next_state(start, b)) {
                first_bytes[b as usize] = true;
            }
        }
        out.push(HoldMatcher { dfa, first_bytes });
    }
    Ok(out)
}

/// Process-cached hold matchers. `Err(())` ⇒ a pattern exceeded the build size
/// limits; the caller (`execute_streaming` begin-site) fails CLOSED.
fn hold_matchers() -> Result<&'static [HoldMatcher], ()> {
    static M: OnceLock<Result<Vec<HoldMatcher>, ()>> = OnceLock::new();
    match M.get_or_init(build_hold_matchers) {
        Ok(v) => Ok(v.as_slice()),
        Err(()) => Err(()),
    }
}

/// Crate-static baseline for response heads. The injected detector may add
/// patterns or policy, but cannot subtract the `LEAK_PATTERNS` baseline by
/// returning `Clean` from a reduced/no-op implementation.
fn baseline_head_detector() -> &'static DefaultLeakDetector {
    static DETECTOR: OnceLock<DefaultLeakDetector> = OnceLock::new();
    DETECTOR.get_or_init(DefaultLeakDetector::new)
}

/// Canonical viability feed with a raw-offset map (audit round 1: viability
/// walked RAW bytes, so invisible-codepoint interleaving or NFKC-variant
/// lettering inside a forming credential defeated the hold). Per SOURCE char:
/// skip `is_dropped_from_scan_derivative` (Mn/Me/Cf ∪ historical invisibles),
/// NFKC-normalize that single char, skip dropped NFKC output — the same
/// drop → NFKC → drop pipeline as `canonical_scan_text`, applied char-locally
/// so every canonical byte can be traced to the raw offset of its source char.
///
/// MODULE-012-AC-24: spliced Mn/Me/Cf no longer reach this feed, so the old
/// `a` + U+0301 detector-Clean / per-char-`a`-then-dead split is gone. The
/// `Matched`-before-`Dead` ordering in `viable_from` plus the EOF fail-close
/// in `next_chunk` remain load-bearing for **non-dropped** killer bytes.
///
/// Returns `(canonical bytes, map canonical-byte-index → raw byte offset of
/// its source char, raw offset of a trailing INCOMPLETE UTF-8 sequence)`.
/// Returns `Err(())` before the canonical projection exceeds
/// [`MAX_CANONICAL_SCAN_BYTES`]. Invalid interior bytes feed U+FFFD (mirroring
/// lossy decode); a trailing
/// incomplete sequence is EXCLUDED from the feed and reported so the caller
/// withholds those raw bytes until the next chunk completes the char.
pub fn canonical_len_with_limit(buf: &[u8], max_canonical_bytes: usize) -> Result<usize, ()> {
    fn add_char(c: char, total: &mut usize, max_canonical_bytes: usize) -> Result<(), ()> {
        if crate::invisible::is_dropped_from_scan_derivative(c) {
            return Ok(());
        }
        use unicode_normalization::UnicodeNormalization;
        for nc in std::iter::once(c).nfkc() {
            if crate::invisible::is_dropped_from_scan_derivative(nc) {
                continue;
            }
            *total = (*total).checked_add(nc.len_utf8()).ok_or(())?;
            if *total > max_canonical_bytes {
                return Err(());
            }
        }
        Ok(())
    }

    let mut total = 0usize;
    let mut rest = buf;
    while !rest.is_empty() {
        match std::str::from_utf8(rest) {
            Ok(s) => {
                for c in s.chars() {
                    add_char(c, &mut total, max_canonical_bytes)?;
                }
                rest = &[];
            }
            Err(e) => {
                let valid = e.valid_up_to();
                // SAFETY: `from_utf8` reported this prefix as valid.
                let s = std::str::from_utf8(&rest[..valid]).unwrap();
                for c in s.chars() {
                    add_char(c, &mut total, max_canonical_bytes)?;
                }
                match e.error_len() {
                    Some(bad) => {
                        add_char('\u{FFFD}', &mut total, max_canonical_bytes)?;
                        rest = &rest[valid + bad..];
                    }
                    // A trailing incomplete sequence is withheld from the
                    // canonical feed, exactly as `canonical_map` does.
                    None => rest = &[],
                }
            }
        }
    }
    Ok(total)
}

#[cfg(test)]
fn canonical_map(buf: &[u8]) -> Result<(Vec<u8>, Vec<usize>, Option<usize>), ()> {
    canonical_map_with_limit(buf, MAX_CANONICAL_SCAN_BYTES)
}

pub fn canonical_map_with_limit(
    buf: &[u8],
    max_canonical_bytes: usize,
) -> Result<(Vec<u8>, Vec<usize>, Option<usize>), ()> {
    let initial = buf.len().min(max_canonical_bytes);
    let mut canon: Vec<u8> = Vec::with_capacity(initial);
    let mut map: Vec<usize> = Vec::with_capacity(initial);
    let mut tail_partial: Option<usize> = None;

    fn push_char(
        c: char,
        raw_off: usize,
        max_canonical_bytes: usize,
        canon: &mut Vec<u8>,
        map: &mut Vec<usize>,
    ) -> Result<(), ()> {
        if crate::invisible::is_dropped_from_scan_derivative(c) {
            return Ok(());
        }
        use unicode_normalization::UnicodeNormalization;
        for nc in std::iter::once(c).nfkc() {
            if crate::invisible::is_dropped_from_scan_derivative(nc) {
                continue;
            }
            let mut b = [0u8; 4];
            let encoded = nc.encode_utf8(&mut b).as_bytes();
            let next_len = canon.len().checked_add(encoded.len()).ok_or(())?;
            if next_len > max_canonical_bytes {
                return Err(());
            }
            for &byte in encoded {
                canon.push(byte);
                map.push(raw_off);
            }
        }
        Ok(())
    }

    let mut raw = 0usize;
    let mut rest = buf;
    while !rest.is_empty() {
        match std::str::from_utf8(rest) {
            Ok(s) => {
                for (off, c) in s.char_indices() {
                    push_char(c, raw + off, max_canonical_bytes, &mut canon, &mut map)?;
                }
                raw += s.len();
                rest = &[];
            }
            Err(e) => {
                let valid = e.valid_up_to();
                // SAFETY of unwrap: from_utf8 said the first `valid` bytes are valid.
                let s = std::str::from_utf8(&rest[..valid]).unwrap();
                for (off, c) in s.char_indices() {
                    push_char(c, raw + off, max_canonical_bytes, &mut canon, &mut map)?;
                }
                match e.error_len() {
                    Some(bad) => {
                        // Invalid interior bytes → U+FFFD (as lossy decode would).
                        push_char(
                            '\u{FFFD}',
                            raw + valid,
                            max_canonical_bytes,
                            &mut canon,
                            &mut map,
                        )?;
                        raw += valid + bad;
                        rest = &rest[valid + bad..];
                    }
                    None => {
                        // Trailing incomplete multi-byte sequence: withhold it
                        // (the next chunk completes the char; feeding FFFD now
                        // would let a split canonical first-letter slip past
                        // the hold).
                        tail_partial = Some(raw + valid);
                        rest = &[];
                    }
                }
            }
        }
    }
    Ok((canon, map, tail_partial))
}

enum Viability {
    Viable,
    /// A match state was entered during the walk: this position holds a
    /// COMPLETED credential match. Hold it — and never EOF-flush it.
    Matched,
    Dead,
}

/// Walk `hay` through the anchored DFA.
/// - `Matched` = a match state was entered ⇒ a COMPLETE credential match starts
///   here (hold, and fail CLOSED at EOF rather than flushing).
/// - `Viable` = alive but no match yet — an extension could still complete one.
/// - `Dead` = the walk died without ever matching ⇒ no future chunk can revive
///   a match starting here (dead states are absorbing), so the byte may emit.
///
/// `None` = step budget exhausted (caller fails CLOSED). Quit/start-error
/// states count as Viable (fail-closed direction: hold rather than emit).
///
/// **Audit round 5 (Critical)**: the match check MUST precede the dead check.
/// A DFA that completes a match and is then killed by a non-class byte passes
/// THROUGH a match state on its way to dead; the previous code observed only
/// the dead state and reported `Dead`, so the hold released the bytes.
/// MODULE-012-AC-24 drops Mn/Me/Cf before this walk, so U+0301 is no longer a
/// killer. The pin is a **non-dropped** class miss (e.g. `!` after `Bearer eyJabc`).
/// Treating "matched" as hold-worthy keeps the hold a SELF-CONTAINED guard
/// (see also the injected-detector note on `hold_matchers`).
fn viable_from(dfa: &dense::DFA<Vec<u32>>, hay: &[u8], budget: &mut usize) -> Option<Viability> {
    let input = Input::new(hay).anchored(Anchored::Yes);
    let mut state = match dfa.start_state_forward(&input) {
        Ok(s) => s,
        Err(_) => return Some(Viability::Viable),
    };
    // NOTE (audit round 8): round 7 added an `is_match_state(state)` check here
    // as a claimed runtime backstop for a zero-length-matching row. It was DEAD
    // CODE — `dense::DFA` reports matches with a one-byte delay (which is why
    // the EOI transition below is needed at all), so an anchored start state is
    // never a match state. The premise was wrong too: for an empty-matching row
    // every `next_state(start, b)` would be a MATCH state, hence non-dead, so
    // `first_bytes` would be all-true rather than blind and the per-byte check
    // below would fire after one byte. Removed rather than kept as a comforting
    // no-op; the REAL guarantee is T29's `min_len > 0` pin over the table.
    for &b in hay {
        if *budget == 0 {
            return None;
        }
        *budget -= 1;
        state = dfa.next_state(state, b);
        if dfa.is_match_state(state) {
            return Some(Viability::Matched);
        }
        if dfa.is_dead_state(state) {
            return Some(Viability::Dead);
        }
        if dfa.is_quit_state(state) {
            return Some(Viability::Viable);
        }
    }
    // A match ending exactly at the buffer end is only reported after EOI
    // (regex-automata reports matches with a one-byte delay).
    if dfa.is_match_state(dfa.next_eoi_state(state)) {
        return Some(Viability::Matched);
    }
    Some(Viability::Viable)
}

/// Earliest RAW offset in the unemitted buffer from which bytes must be HELD
/// (a viable in-progress — or already COMPLETED — Block/Redact match starts
/// there in the CANONICAL feed), or `raw_len` when everything may emit. A
/// trailing incomplete UTF-8 sequence is always withheld.
///
/// `Err(())` = defensive step budget exhausted (fail CLOSED).
///
/// This returns ONLY the split point. Whether the held region contains a
/// COMPLETED match is decided separately by [`held_contains_completed_match`]
/// at EOF (audit round 6): this walk short-circuits at the FIRST non-dead
/// candidate, so it cannot answer that question — a completed match sitting
/// behind an earlier merely-viable prefix (e.g. `sk-ant-apiAKIA…`, where
/// `anthropic_api_key` is viable at 0 while a complete `aws_access_key` sits
/// at 10) is never walked here. Round 5 wrongly derived the EOF guard from
/// this loop's first-candidate verdict, which silently re-opened the
/// hold→emit path the round-5 Critical had closed.
///
/// Soundness of emitting `buf[..split]`: every canonical first-byte candidate
/// before the split was walked to the END of the canonical feed and found
/// DEAD **without ever entering a match state** — dead DFA states are
/// absorbing, so no future chunk can revive a match starting there; and a
/// walk that DID match is now reported as `Matched`, not `Dead`, so it holds.
/// Non-candidate positions cannot start a match at all.
fn hold_split_point(
    matchers: &[HoldMatcher],
    canon: &[u8],
    map: &[usize],
    raw_len: usize,
    tail_partial: Option<usize>,
) -> Result<usize, ()> {
    let mut budget = canon.len().saturating_mul(8).saturating_add(4096);
    let mut split_raw = raw_len;
    'outer: for (i, &b) in canon.iter().enumerate() {
        for m in matchers {
            if !m.first_bytes[b as usize] {
                continue;
            }
            match viable_from(&m.dfa, &canon[i..], &mut budget) {
                None => return Err(()),
                // Matched and Viable both HOLD from here; the distinction only
                // matters at EOF and is re-derived there over the whole region.
                Some(Viability::Matched) | Some(Viability::Viable) => {
                    split_raw = map[i];
                    break 'outer;
                }
                Some(Viability::Dead) => {}
            }
        }
    }
    if let Some(tp) = tail_partial {
        split_raw = split_raw.min(tp);
    }
    Ok(split_raw)
}

/// Does the held region contain a COMPLETED Block/Redact match ANYWHERE?
///
/// Run ONCE, at EOF, over the whole held region — unlike [`hold_split_point`]
/// this does NOT short-circuit at the first non-dead candidate, because the
/// question is existential over every position, not a property of the earliest
/// one (audit round 6: two independent reviewers built the same counterexample,
/// `sk-ant-apiAKIA…`, where the earliest candidate is merely viable and a
/// COMPLETE `aws_access_key` sits behind it).
///
/// Deciding this at EOF rather than per round is what keeps the cost sane: the
/// full non-short-circuiting sweep happens once per stream instead of once per
/// chunk, and it removes the cross-round `held_has_match` state that round 5
/// recomputed (and could therefore flip true→false while the matched bytes
/// were still held).
///
/// `Err(())` (budget exhausted) is treated by the caller exactly like `true`:
/// fail CLOSED.
fn held_contains_completed_match(matchers: &[HoldMatcher], canon: &[u8]) -> Result<bool, ()> {
    // Audit round 7: this sweep does NOT short-circuit, so its cost is
    // `positions × matchers × walk`, not the split walk's "stop at the first
    // non-dead candidate". Sizing it like the split walk (`8n + 4096`) made a
    // legitimate candidate-dense hold (a tail full of `-`, `sk-`, `gh` or `A`
    // starts) exhaust the budget and fail closed. It runs ONCE per stream, so
    // a generous allowance is affordable; exhaustion is still fail-CLOSED, and
    // the caller reports it as a BUDGET terminal rather than as a match.
    // Audit round 8: the cost model is `positions × matchers × walk`, so the
    // allowance carries a MATCHER factor — sizing it as `64n` alone silently
    // shrank the per-matcher budget ~14% for every Block/Redact row a future
    // table edit adds, with no test to notice.
    let mut budget = canon
        .len()
        .saturating_mul(16)
        .saturating_mul(matchers.len().max(1))
        .saturating_add(1024 * 1024);
    for (i, &b) in canon.iter().enumerate() {
        for m in matchers {
            if !m.first_bytes[b as usize] {
                continue;
            }
            match viable_from(&m.dfa, &canon[i..], &mut budget) {
                None => return Err(()),
                Some(Viability::Matched) => return Ok(true),
                Some(Viability::Viable) | Some(Viability::Dead) => {}
            }
        }
    }
    Ok(false)
}

/// Checked cumulative scan ledger. `u128` preserves banked credit across
/// 32-bit/64-bit targets; any arithmetic overflow fails CLOSED instead of
/// saturating one side and disabling the subtraction predicate.
/// S4 decoded-layer facade (see `crate::canonical_facade`): the largest raw
/// offset into `buf` that can be released without emitting any byte of a
/// Block/Redact pattern that is still viable — i.e. the wire layer's own hold
/// split, computed over the same canonical feed and pattern table.
///
/// `Err(())` means fail CLOSED (matcher build failure, canonical overflow, or an
/// exhausted viability budget): the caller must release nothing.
pub fn decoded_hold_split(buf: &[u8], max_canonical_bytes: usize) -> Result<usize, ()> {
    let matchers = hold_matchers()?;
    let (canon, map, tail_partial) = canonical_map_with_limit(buf, max_canonical_bytes)?;
    hold_split_point(matchers, &canon, &map, buf.len(), tail_partial)
}

/// S4 decoded-layer facade: does `buf` contain a COMPLETED Block/Redact match?
/// Non-short-circuiting sweep over the whole region (the wire layer's EOF rule).
/// `Err(())` = fail CLOSED.
pub fn decoded_region_has_completed_match(
    buf: &[u8],
    max_canonical_bytes: usize,
) -> Result<bool, ()> {
    let matchers = hold_matchers()?;
    let (canon, _map, _tail) = canonical_map_with_limit(buf, max_canonical_bytes)?;
    held_contains_completed_match(matchers, &canon)
}

fn checked_scan_ledger(
    debt: u128,
    credit: u128,
    retained_bytes: usize,
    fresh_bytes: usize,
) -> Result<(u128, u128, bool), ()> {
    let round_debt = (retained_bytes as u128).checked_add(1).ok_or(())?;
    let round_credit = (fresh_bytes as u128)
        .checked_mul(SCAN_CREDIT_PER_WIRE_BYTE as u128)
        .ok_or(())?;
    let debt = debt.checked_add(round_debt).ok_or(())?;
    let credit = credit.checked_add(round_credit).ok_or(())?;
    let exceeded = debt.saturating_sub(credit) > MAX_SCAN_DEBT_BYTES as u128;
    Ok((debt, credit, exceeded))
}

/// Map executor-layer errors to the chain-level `HttpError` — the same arms as
/// the buffered step-7 mapping (enum-coded static reasons; CONTRACT-111 Inv 7).
fn map_executor_err(e: ExecutorError) -> HttpError {
    match e {
        ExecutorError::RedirectRejected { reason, target } => {
            HttpError::RedirectRejected { reason, target }
        }
        ExecutorError::Transport => HttpError::Transport(TransportErrorKind::Other),
        ExecutorError::Timeout => HttpError::Transport(TransportErrorKind::Timeout),
    }
}

/// Await an operation against the chain deadline and make the deadline the
/// terminal of record even when the future is non-cooperative. Tokio's
/// `timeout_at` cannot pre-empt a future that blocks inside one poll and may
/// therefore return `Ok(output)` after the deadline; the explicit post-poll
/// check closes that precedence gap for outbound work and every body pull.
/// Executor HEAD work uses the ownership-aware wrapper below.
async fn complete_before_deadline<T>(
    deadline: tokio::time::Instant,
    future: impl std::future::Future<Output = T>,
) -> Result<T, ()> {
    match tokio::time::timeout_at(deadline, future).await {
        Ok(output) if tokio::time::Instant::now() < deadline => Ok(output),
        Ok(_) | Err(_) => Err(()),
    }
}

/// HEAD-specific deadline wrapper. A generic `Ok(_)` late-result guard would
/// implicitly discard `(head, wire)` and therefore run executor-owned cleanup
/// outside the chain's guarded ownership path. Take that output apart here so
/// the wire is destroyed explicitly before the late result becomes Timeout.
///
/// Timer cancellation relies on the transitive CONTRACT-233 streaming
/// composition precondition documented by `with_stream_executor`; the
/// `HttpStreamExecutor` future and any nested redirect future are specialized
/// instances of that bound.
async fn complete_stream_head_before_deadline(
    deadline: tokio::time::Instant,
    future: impl std::future::Future<
        Output = Result<(HttpResponseHead, Box<dyn WireChunkStream>), ExecutorError>,
    >,
) -> Result<Result<(HttpResponseHead, Box<dyn WireChunkStream>), ExecutorError>, ()> {
    match tokio::time::timeout_at(deadline, future).await {
        Ok(output) if tokio::time::Instant::now() < deadline => Ok(output),
        Ok(Ok((_head, wire))) => {
            drop_wire_safely(Some(wire));
            Err(())
        }
        Ok(Err(_)) | Err(_) => Err(()),
    }
}

/// Accept the result of one bounded synchronous stage only while the shared
/// chain deadline is still live. The stage is deliberately evaluated before
/// this call; detector/canonical/DFA/ledger work cannot be pre-empted, but a
/// late result must never regain precedence over `Timeout`.
fn complete_sync_before_deadline<T>(deadline: tokio::time::Instant, output: T) -> Result<T, ()> {
    if tokio::time::Instant::now() < deadline {
        Ok(output)
    } else {
        Err(())
    }
}

/// Destroy executor-owned stream state synchronously. The transitive streaming
/// composition precondition (specialized by the cap-http wire seam) requires
/// this destructor to be bounded, non-blocking, panic-free and free of
/// network/progress waits; no in-process mechanism can safely reclaim a
/// destructor that never returns. `catch_unwind` is defense in depth for a
/// non-conforming panicking implementation, while the caller's post-cleanup
/// deadline check owns terminal classification.
fn drop_wire_safely(wire: Option<Box<dyn WireChunkStream>>) {
    if let Some(wire) = wire {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(wire)));
    }
}

/// Post-scan body stream: wraps raw wire chunks in the §2.9 per-chunk scan +
/// greedy hold. Terminal is absorbing (invariant 2 of `HttpBodyStream`). Its
/// final destruction also releases detector/event-sink trait objects, so their
/// object `Drop` implementations are explicitly covered by the transitive
/// streaming composition precondition accepted at `with_stream_executor`.
struct ScanningWireStream {
    /// `None` after any absorbing terminal so the underlying response,
    /// connection and transport buffers are released immediately.
    inner: Option<Box<dyn WireChunkStream>>,
    leak_detector: Arc<dyn LeakDetector>,
    event_bus: Option<Arc<dyn EventBusEmit>>,
    agent_id: String,
    /// The resolved Block/Redact viability matchers (built once, fail-closed at
    /// begin-site — never rebuilt here, so `next_chunk` cannot panic).
    holds: &'static [HoldMatcher],
    /// Trailing raw bytes of the EMITTED stream, retained so that their
    /// CANONICAL projection TARGETS ≥ `window` bytes (scan-window overlap; the
    /// belt to the hold's suspenders: a cross-boundary
    /// window for Block/Redact rows). Best-effort only: raw retention is hard-capped at
    /// `MAX_OVERLAP_RAW`, so an all-invisible stream can leave the projection
    /// below `window` — the hold, not this belt, is the primary guard.
    /// (The belt has no telemetry role on this path: `ScanResult::Warned` is a
    /// silent no-op here, so a cross-boundary `high_entropy_hex` produces no
    /// event either way — audit round 6 corrected an earlier claim that the
    /// belt served "Warn-telemetry"; round 9 briefly falsified this comment by
    /// adding Warn emission, and round 10 reverted that, restoring it.)
    overlap: Vec<u8>,
    /// Scanned-clean bytes withheld because a viable in-progress Block/Redact
    /// match suffix starts there (never emitted until resolved / EOF).
    held: Vec<u8>,
    window: usize,
    /// Cumulative re-scan work charge — retained bytes re-processed each round
    /// plus one unit per round (see [`MAX_SCAN_DEBT_BYTES`]).
    scan_debt: u128,
    /// Credit earned by FRESH wire bytes, at [`SCAN_CREDIT_PER_WIRE_BYTE`] each:
    /// checked `u128` accounting preserves banked credit without 32-bit
    /// saturation disabling the guard.
    scan_credit: u128,
    /// Chain-owned cumulative wire count over every executor implementation.
    wire_total: usize,
    /// Per-stream canonical projection limit; production uses the fixed
    /// `MAX_CANONICAL_SCAN_BYTES`, tests may lower it to exercise the real path.
    max_canonical_bytes: usize,
    /// One chain-entry deadline shared by the arbitrary executor head future,
    /// each raw pull, and the post-scan output gate.
    deadline: tokio::time::Instant,
    /// Consecutive zero-length upstream chunks (audit round 6). Empty frames
    /// cost 0 wire bytes (so `max_response_bytes` never trips) and, when the
    /// belt is also empty, only ~1 debt each — 33.5 M rounds before the ledger
    /// fires. This counter bounds that shape directly at
    /// [`MAX_CONSECUTIVE_EMPTY_CHUNKS`]; any chunk carrying bytes resets it.
    consecutive_empty: usize,
    done: bool,
}

impl Drop for ScanningWireStream {
    fn drop(&mut self) {
        // Caller-driven drop is also a terminal resource path. The cap-http
        // executor seam requires this synchronous cleanup to be bounded and
        // non-blocking; no background worker/thread/queue is created.
        self.finish();
    }
}

impl ScanningWireStream {
    fn new(
        inner: Box<dyn WireChunkStream>,
        leak_detector: Arc<dyn LeakDetector>,
        event_bus: Option<Arc<dyn EventBusEmit>>,
        agent_id: String,
        holds: &'static [HoldMatcher],
        deadline: tokio::time::Instant,
    ) -> Self {
        Self {
            inner: Some(inner),
            leak_detector,
            event_bus,
            agent_id,
            holds,
            overlap: Vec::new(),
            held: Vec::new(),
            window: overlap_window_bytes(),
            scan_debt: 0,
            scan_credit: 0,
            wire_total: 0,
            max_canonical_bytes: MAX_CANONICAL_SCAN_BYTES,
            deadline,
            consecutive_empty: 0,
            done: false,
        }
    }

    fn emit_leak_event(&self, finding_count: usize) {
        if let Some(bus) = &self.event_bus {
            bus.emit(Event::observability(
                "security.leak_detected",
                &self.agent_id,
                json!({"scan_context": "http_inbound", "finding_count": finding_count}),
                None,
            ));
        }
    }

    fn take_terminal_wire(&mut self) -> Option<Box<dyn WireChunkStream>> {
        self.done = true;
        // Assignment, not `clear()`: drop credential-bearing allocations and
        // their capacity. The boxed executor/response is returned for guarded
        // synchronous destruction under the cap-http seam invariant.
        self.held = Vec::new();
        self.overlap = Vec::new();
        self.inner.take()
    }

    fn finish(&mut self) {
        let wire = self.take_terminal_wire();
        drop_wire_safely(wire);
    }

    fn terminate_timeout(&mut self) -> Option<Result<Vec<u8>, HttpError>> {
        self.finish();
        Some(Err(HttpError::Transport(TransportErrorKind::Timeout)))
    }

    fn terminate_block(&mut self, findings: Vec<Finding>) -> Option<Result<Vec<u8>, HttpError>> {
        // Final common arbitration guard: every synchronous security/budget
        // terminal funnels through this method. Cleanup and event dispatch are
        // stages too: a custom stream destructor or event sink cannot make a
        // late Block outrank Timeout.
        if tokio::time::Instant::now() >= self.deadline {
            return self.terminate_timeout();
        }
        self.finish();
        if tokio::time::Instant::now() >= self.deadline {
            return self.terminate_timeout();
        }
        self.emit_leak_event(findings.len());
        if tokio::time::Instant::now() >= self.deadline {
            return self.terminate_timeout();
        }
        Some(Err(HttpError::InboundLeakBlocked(findings)))
    }

    /// Fail-closed terminal for hold-cap breaches (§2.9 term 4). Synthetic
    /// finding mirrors the `scan_overflow` precedent — enum-coded, no
    /// upstream bytes.
    fn terminate_hold_overflow(&mut self) -> Option<Result<Vec<u8>, HttpError>> {
        self.terminate_block(vec![Finding {
            pattern_name: "stream_hold_overflow".to_string(),
            offset: 0,
            length: 0,
            action: Action::Block,
        }])
    }

    /// Fail-closed terminal for re-scan-ledger / viability-step budget
    /// exhaustion (drip-feed and zero-progress-flood defense).
    fn terminate_scan_budget(&mut self) -> Option<Result<Vec<u8>, HttpError>> {
        self.terminate_block(vec![Finding {
            pattern_name: "stream_scan_budget".to_string(),
            offset: 0,
            length: 0,
            action: Action::Block,
        }])
    }

    /// Retain a trailing raw suffix of the emitted stream, TARGETING a
    /// CANONICAL projection of `window` bytes (audit round 2: a raw-byte
    /// window let an invisible flood push a genuine match-start out of the
    /// retained bytes; the belt must be measured in canonical bytes — the
    /// space the detector actually matches over). Raw retention is hard-capped
    /// at `MAX_OVERLAP_RAW` FIRST, so an all-invisible stream can still leave
    /// the projection below `window`: the belt is best-effort
    /// defense-in-depth for the per-char-NFKC residual (NOT for Warn: Warn is
    /// silent on this path — see the `overlap` field doc), and
    /// the hold — not this belt — is the primary guard.
    fn push_overlap(&mut self, emitted: &[u8]) -> Result<(), ()> {
        const MAX_OVERLAP_RAW: usize = 8 * 1024;
        self.overlap.extend_from_slice(emitted);
        if self.overlap.len() > MAX_OVERLAP_RAW {
            // NOTE: unlike every other cut in this file, this one is a raw
            // byte offset and may land mid-codepoint, leaving invalid leading
            // bytes in the belt. Harmless — both `from_utf8_lossy` and
            // `canonical_map` tolerate them, and the belt is defense-in-depth
            // only (a leading U+FFFD cannot create a match, only break one,
            // and the hold is the primary guard).
            let cut = self.overlap.len() - MAX_OVERLAP_RAW;
            self.overlap.drain(..cut);
        }
        let (canon, map, _tail) =
            canonical_map_with_limit(&self.overlap, self.max_canonical_bytes)?;
        // `self.window > 0` guard (audit round 3): a degenerate future pattern
        // table could yield window == 0 (`overlap_window_bytes` floors at 0),
        // in which case `canon.len() - self.window == canon.len()` would index
        // `map` out of bounds. T29 pins window ≥ 99, but that is a test not a
        // runtime invariant — keep the whole (8-KiB-capped) overlap if window
        // is 0 rather than panic.
        if self.window > 0 && canon.len() > self.window {
            // Keep the last `window` canonical bytes: drop leading raw bytes up
            // to the raw offset of the first canonical byte we retain.
            let drop_to = map[canon.len() - self.window];
            self.overlap.drain(..drop_to);
        }
        Ok(())
    }
}

#[async_trait]
impl HttpBodyStream for ScanningWireStream {
    async fn next_chunk(&mut self) -> Option<Result<Vec<u8>, HttpError>> {
        if self.done {
            return None;
        }
        loop {
            let next = {
                let inner = self.inner.as_mut()?;
                match complete_before_deadline(self.deadline, inner.next()).await {
                    Ok(next) => next,
                    Err(()) => return self.terminate_timeout(),
                }
            };
            let chunk = match next {
                None => {
                    // Audit round 6: ask the completed-match question HERE,
                    // over the WHOLE held region (round 5 wrongly inherited it
                    // from `hold_split_point`'s first-candidate short-circuit).
                    let held = std::mem::take(&mut self.held);
                    self.finish();
                    if tokio::time::Instant::now() >= self.deadline {
                        return self.terminate_timeout();
                    }
                    if held.is_empty() {
                        return None;
                    }
                    let mapped = canonical_map_with_limit(&held, self.max_canonical_bytes);
                    let mapped = match complete_sync_before_deadline(self.deadline, mapped) {
                        Ok(mapped) => mapped,
                        Err(()) => return self.terminate_timeout(),
                    };
                    let (canon, _map, _tail) = match mapped {
                        Ok(mapped) => mapped,
                        Err(()) => return self.terminate_scan_budget(),
                    };
                    let completed = held_contains_completed_match(self.holds, &canon);
                    let completed = match complete_sync_before_deadline(self.deadline, completed) {
                        Ok(completed) => completed,
                        Err(()) => return self.terminate_timeout(),
                    };
                    match completed {
                        Ok(false) => {
                            if tokio::time::Instant::now() >= self.deadline {
                                return self.terminate_timeout();
                            }
                            return Some(Ok(held));
                        }
                        Ok(true) => {
                            return self.terminate_block(vec![Finding {
                                pattern_name: "stream_hold_unresolved_match".to_string(),
                                offset: 0,
                                length: 0,
                                action: Action::Block,
                            }]);
                        }
                        // Audit round 7: budget exhaustion is fail-CLOSED too,
                        // but it is NOT a match — report the budget terminal so
                        // the operator-visible reason is the real one.
                        Err(()) => return self.terminate_scan_budget(),
                    }
                }
                Some(Err(e)) => {
                    let mapped = map_executor_err(e);
                    let mapped = match complete_sync_before_deadline(self.deadline, mapped) {
                        Ok(mapped) => mapped,
                        Err(()) => return self.terminate_timeout(),
                    };
                    self.finish();
                    if tokio::time::Instant::now() >= self.deadline {
                        return self.terminate_timeout();
                    }
                    return Some(Err(mapped));
                }
                Some(Ok(c)) => c,
            };

            self.wire_total = match self.wire_total.checked_add(chunk.len()) {
                Some(total) if total <= MAX_CHAIN_STREAM_BYTES => total,
                _ => return self.terminate_scan_budget(),
            };

            // Zero-progress bound (audit round 6). An empty frame costs no wire
            // bytes and, with an empty belt, ~1 debt — so neither
            // `max_response_bytes` nor the byte ledger bounds a leading
            // empty-frame flood in useful time. Bound the shape directly.
            if chunk.is_empty() {
                self.consecutive_empty = self.consecutive_empty.saturating_add(1);
                if self.consecutive_empty > MAX_CONSECUTIVE_EMPTY_CHUNKS {
                    return self.terminate_scan_budget();
                }
            } else {
                self.consecutive_empty = 0;
            }

            // ── §2.9 term 2: scan the REJOINED raw bytes, lossy-decoded ONCE.
            // (`leak_detector.scan` runs `canonical_scan_text` internally, so
            // invisible-codepoint stripping happens on the rejoined text.)
            let scan_capacity = match self
                .overlap
                .len()
                .checked_add(self.held.len())
                .and_then(|n| n.checked_add(chunk.len()))
            {
                Some(capacity) => capacity,
                None => return self.terminate_scan_budget(),
            };
            let mut scan_buf = Vec::with_capacity(scan_capacity);
            scan_buf.extend_from_slice(&self.overlap);
            scan_buf.extend_from_slice(&self.held);
            scan_buf.extend_from_slice(&chunk);
            // Count-only per-char-NFKC preflight BEFORE lossy-string and detector
            // allocation. Per-char normalization is an upper bound for this
            // feed's whole-string composition (composition can contract it).
            let canonical_preflight = canonical_len_with_limit(&scan_buf, self.max_canonical_bytes);
            let canonical_preflight =
                match complete_sync_before_deadline(self.deadline, canonical_preflight) {
                    Ok(preflight) => preflight,
                    Err(()) => return self.terminate_timeout(),
                };
            if canonical_preflight.is_err() {
                return self.terminate_scan_budget();
            }
            let scan_text = String::from_utf8_lossy(&scan_buf).into_owned();
            let scan_text = match complete_sync_before_deadline(self.deadline, scan_text) {
                Ok(text) => text,
                Err(()) => return self.terminate_timeout(),
            };
            let scan_result = self
                .leak_detector
                .scan(&scan_text, ScanContext::HttpInbound);
            let scan_result = match complete_sync_before_deadline(self.deadline, scan_result) {
                Ok(result) => result,
                Err(()) => return self.terminate_timeout(),
            };
            match scan_result {
                // MODULE-012 S3-slice audit round 10 REVERTED that slice's round-9
                // per-chunk Warn emission (those are the S3 transport lane's own
                // round numbers, not the S4 gateway lane's).
                // `scan_buf` is `overlap + held + chunk`, re-scanned IN FULL
                // every round by design, so one Warn-matching region fires once
                // per chunk for as long as it stays in scope: 160 KiB of hex in
                // 1 KiB frames = 160 events, and at 1-byte frames up to one
                // event per wire byte — while the debt ledger's stated purpose
                // is to guarantee exactly such a stream is NEVER cut. Warn is
                // therefore silent again on the wire path; the resulting
                // no-telemetry gap is the pre-existing residual recorded in
                // §3.6, not a new debt. Re-adding emission needs a per-stream
                // latch and an `action` discriminator, which is a NEW mechanism
                // and out of this slice.
                ScanResult::Clean | ScanResult::Warned { .. } => {}
                ScanResult::Blocked { findings } => {
                    return self.terminate_block(findings);
                }
                // §2.9 term 5 — wire-layer Redact→Block SANCTIONED divergence:
                // splicing [REDACTED] into live frames is impossible, so a
                // Redact finding terminates enum-coded (never pass-through).
                ScanResult::Redacted { findings, .. } => {
                    return self.terminate_block(findings);
                }
            }
            if tokio::time::Instant::now() >= self.deadline {
                return self.terminate_timeout();
            }

            // Re-scan work LEDGER (audit rounds 1/3/4/5; see
            // MAX_SCAN_DEBT_BYTES). DEBT = the retained bytes this round
            // re-processed (`overlap + held`) plus one unit for the round
            // itself; CREDIT = SCAN_CREDIT_PER_WIRE_BYTE per FRESH wire byte.
            // A stream that actually delivers content funds its own re-scan
            // context and is never cut (round-4's availability goal), while a
            // zero-progress flood earns nothing and exhausts the fixed
            // allowance (round-3's work bound restored — round 4's excess-only
            // charge let empty HTTP/2 DATA frames, which cost 0 wire bytes and
            // so never trip the wire cap, grind ~3.3 GB of scan work for free).
            // Charged AFTER the scan so a credential-bearing chunk records its
            // TRUE finding rather than a budget terminal; the one round of
            // overrun is bounded by overlap ≤ 8 KiB + held ≤ 256 KiB + chunk.
            let retained = match self.overlap.len().checked_add(self.held.len()) {
                Some(retained) => retained,
                None => return self.terminate_scan_budget(),
            };
            let ledger =
                checked_scan_ledger(self.scan_debt, self.scan_credit, retained, chunk.len());
            let ledger = match complete_sync_before_deadline(self.deadline, ledger) {
                Ok(ledger) => ledger,
                Err(()) => return self.terminate_timeout(),
            };
            let (debt, credit, exceeded) = match ledger {
                Ok(state) => state,
                Err(()) => return self.terminate_scan_budget(),
            };
            self.scan_debt = debt;
            self.scan_credit = credit;
            if exceeded {
                return self.terminate_scan_budget();
            }

            // ── §2.9 term 4: emission with the Block/Redact viability hold.
            let mut buf = std::mem::take(&mut self.held);
            buf.extend_from_slice(&chunk);
            let mapped = canonical_map_with_limit(&buf, self.max_canonical_bytes);
            let mapped = match complete_sync_before_deadline(self.deadline, mapped) {
                Ok(mapped) => mapped,
                Err(()) => return self.terminate_timeout(),
            };
            let (canon, map, tail_partial) = match mapped {
                Ok(mapped) => mapped,
                Err(()) => return self.terminate_scan_budget(),
            };
            let split = hold_split_point(self.holds, &canon, &map, buf.len(), tail_partial);
            let split = match complete_sync_before_deadline(self.deadline, split) {
                Ok(split) => split,
                Err(()) => return self.terminate_timeout(),
            };
            let split = match split {
                Ok(s) => s,
                Err(()) => return self.terminate_scan_budget(),
            };
            self.held = buf.split_off(split);
            let emit = buf;
            if self.held.len() > MAX_HOLD_BYTES {
                return self.terminate_hold_overflow();
            }
            if tokio::time::Instant::now() >= self.deadline {
                return self.terminate_timeout();
            }
            if emit.is_empty() {
                // Whole buffer withheld — pull more upstream rather than
                // emitting an empty chunk. Yield first (audit round 5): this
                // branch does not return to the caller, and `inner.next()`
                // resolves synchronously when frames are already buffered, so
                // without a yield a burst of queued empty/tiny frames could
                // occupy a tokio worker for the whole stream deadline.
                tokio::task::yield_now().await;
                continue;
            }
            let overlap_result = self.push_overlap(&emit);
            let overlap_result = match complete_sync_before_deadline(self.deadline, overlap_result)
            {
                Ok(result) => result,
                Err(()) => return self.terminate_timeout(),
            };
            if overlap_result.is_err() {
                return self.terminate_scan_budget();
            }
            if tokio::time::Instant::now() >= self.deadline {
                return self.terminate_timeout();
            }
            return Some(Ok(emit));
        }
    }
}

#[async_trait]
impl HttpStreamingChain for DefaultHttpSecurityChain {
    async fn execute_streaming(
        &self,
        agent_id: &str,
        req: HttpRequest,
        cap: &HttpCapability,
    ) -> Result<(HttpResponseHead, Box<dyn HttpBodyStream>), HttpError> {
        // FIRST-OPERATION composition gate (audit round 22): an unwired chain
        // has not accepted CONTRACT-233's streaming-only transitive callback,
        // future-cancellation and object-Drop precondition. Fail CLOSED before
        // deadline construction, outbound steps, matcher initialization,
        // tracing/events, or any injected collaborator can run.
        let stream_executor = match self.stream_executor.as_ref() {
            Some(stream_executor) => stream_executor,
            None => return Err(HttpError::Transport(TransportErrorKind::Other)),
        };
        let deadline = tokio::time::Instant::now() + self.stream_duration;
        let mut req = req;

        // Pre-step-1 URL guard + steps 1–6 — the SAME helper the buffered
        // `execute` runs (§2.9 term 1 byte-identical reuse; single step-4
        // credential-injection site). The chain-owned deadline begins before
        // these steps so a custom executor cannot redefine the lifetime bound.
        let host = match complete_before_deadline(
            deadline,
            self.outbound_steps(agent_id, &mut req, cap, Some(deadline)),
        )
        .await
        {
            Ok(result) => result?,
            Err(()) => return Err(HttpError::Transport(TransportErrorKind::Timeout)),
        };

        // Resolve the viability matchers at BEGIN-SITE (audit round 2): a
        // pattern-table edit that exceeds the DFA build limits fails CLOSED
        // here — before dialing upstream — instead of panicking mid-stream.
        let holds = hold_matchers();
        let holds = complete_sync_before_deadline(deadline, holds)
            .map_err(|_| HttpError::Transport(TransportErrorKind::Timeout))?;
        let holds = holds.map_err(|_| HttpError::Transport(TransportErrorKind::Other))?;

        // ── Step 7 (streaming): execute with per-hop redirect revalidation ──
        self.trace(STEP_EXECUTE);
        ensure_stream_stage_deadline(Some(deadline))?;
        let redirect_check: Arc<dyn RedirectCheck> = Arc::new(
            DefaultRedirectCheck {
                allowlist: cap.allowlist.clone(),
                leak_detector: self.leak_detector.clone(),
                ssrf_guard: self.ssrf_guard.clone(),
            }
            .with_deadline(deadline),
        );
        ensure_stream_stage_deadline(Some(deadline))?;
        let (_h, scheme) = redacted_host_scheme(&req.url);
        let method = method_label(&req.method);
        let request_payload = json!({"host": host, "scheme": scheme, "method": method});
        ensure_stream_stage_deadline(Some(deadline))?;
        self.emit(agent_id, "http.request", request_payload, None);
        ensure_stream_stage_deadline(Some(deadline))?;
        let started = std::time::Instant::now();
        // `head` is no longer mutable: audit round 8 removed the per-header
        // remediation, so the head is either returned as received or the call
        // fails CLOSED — the scan never rewrites it.
        let head_result = match complete_stream_head_before_deadline(
            deadline,
            crate::ssrf::with_stream_ssrf_deadline(
                deadline,
                stream_executor.execute_stream(&req, redirect_check),
            ),
        )
        .await
        {
            Ok(result) => result,
            Err(()) => return Err(HttpError::Transport(TransportErrorKind::Timeout)),
        };
        let (head, wire) = match head_result {
            Ok(hw) => hw,
            Err(ExecutorError::RedirectRejected { reason, target }) => {
                let payload = json!({"host": host, "reason": "redirect-rejected"});
                ensure_stream_stage_deadline(Some(deadline))?;
                self.emit(agent_id, "http.blocked", payload, None);
                ensure_stream_stage_deadline(Some(deadline))?;
                return Err(HttpError::RedirectRejected { reason, target });
            }
            Err(ExecutorError::Transport) => {
                ensure_stream_stage_deadline(Some(deadline))?;
                return Err(HttpError::Transport(TransportErrorKind::Other));
            }
            Err(ExecutorError::Timeout) => {
                return Err(HttpError::Transport(TransportErrorKind::Timeout));
            }
        };
        // http.response at HEAD receipt — body length is unknowable on a live
        // stream, so the payload carries `streamed: true` instead of
        // `body_bytes`; duration_ms measures time-to-head.
        let dur = started.elapsed().as_millis() as u64;
        let response_payload = json!({
            "host": host,
            "method": method,
            "status": head.status,
            "headers_count": head.headers.len(),
            "streamed": true,
        });
        if ensure_stream_stage_deadline(Some(deadline)).is_err() {
            drop_wire_safely(Some(wire));
            return Err(HttpError::Transport(TransportErrorKind::Timeout));
        }
        self.emit(agent_id, "http.response", response_payload, Some(dur));
        if ensure_stream_stage_deadline(Some(deadline)).is_err() {
            drop_wire_safely(Some(wire));
            return Err(HttpError::Transport(TransportErrorKind::Timeout));
        }

        // ── Head-header scan — head-first error gating: a Blocked OR Redacted
        // head returns Err HERE, before any body stream object exists.
        //
        // DIVERGENCE FROM BUFFERED step 9 (declared, deliberate): this path
        // never rewrites the head. Buffered `execute` still attempts value-only
        // per-header redaction and returns the response; that pre-existing
        // CONTRACT-111 hazard (a match spanning the synthesized join, or a
        // payload carried in a header NAME, survives its remediation) is
        // recorded in MODULE-012 §3.6 and needs its own slice, because closing
        // it changes buffered observable behaviour.
        //
        // Audit round 12 closes the round-9 injection dependency: evaluate the
        // injected policy AND a crate-static baseline. Injection may add
        // patterns, but a reduced/no-op implementation cannot subtract the
        // `LEAK_PATTERNS` Block/Redact guarantee.
        self.trace(STEP_REDACT_ERROR_MESSAGE);
        if ensure_stream_stage_deadline(Some(deadline)).is_err() {
            drop_wire_safely(Some(wire));
            return Err(HttpError::Transport(TransportErrorKind::Timeout));
        }
        let baseline_detector =
            match complete_sync_before_deadline(deadline, baseline_head_detector()) {
                Ok(detector) => detector,
                Err(()) => {
                    drop_wire_safely(Some(wire));
                    return Err(HttpError::Transport(TransportErrorKind::Timeout));
                }
            };
        for detector in [
            self.leak_detector.as_ref(),
            baseline_detector as &dyn LeakDetector,
        ] {
            let header_scan = detector.scan_headers(&head.headers);
            let header_scan = match complete_sync_before_deadline(deadline, header_scan) {
                Ok(result) => result,
                Err(()) => {
                    drop_wire_safely(Some(wire));
                    return Err(HttpError::Transport(TransportErrorKind::Timeout));
                }
            };
            match header_scan {
                // Same S3-slice reversal on the head path (again: MODULE-012's own
                // audit round numbering, not S4's). Head
                // scans are bounded and non-repeating, but emitting only here would
                // still have made `security.leak_detected`
                // ambiguous between "credential withheld" and "hash-dense content
                // delivered" with no field to discriminate them — a degradation of
                // an unambiguous Block signal. Warn on the head passes SILENTLY;
                // §3.6 records the gap.
                ScanResult::Clean | ScanResult::Warned { .. } => {}
                ScanResult::Blocked { findings } => {
                    drop_wire_safely(Some(wire));
                    if ensure_stream_stage_deadline(Some(deadline)).is_err() {
                        return Err(HttpError::Transport(TransportErrorKind::Timeout));
                    }
                    let payload =
                        json!({"scan_context": "http_inbound", "finding_count": findings.len()});
                    ensure_stream_stage_deadline(Some(deadline))?;
                    self.emit(agent_id, "security.leak_detected", payload, None);
                    ensure_stream_stage_deadline(Some(deadline))?;
                    return Err(HttpError::InboundLeakBlocked(findings));
                }
                // §2.9 term 5, applied to the HEAD: Redact degrades to BLOCK.
                //
                // Audit round 8 (Critical). Rounds 6 and 7 each tried to SALVAGE a
                // Redacted head by rewriting header values and then proving the
                // rewrite worked. Both proofs were cheap proxies for the property
                // actually required — "every flagged credential byte is gone":
                //   round 6: "did anything get redacted?" (existential) — defeated
                //            by adding one self-contained decoy header;
                //   round 7: "does the mutated head still match?" — defeated by a
                //            match whose ANCHOR lives in the redacted header while
                //            its PAYLOAD lives in the next header's NAME. Redacting
                //            H1's value deletes `Bearer`, so `bearer_token` stops
                //            matching and the re-scan reports Clean, while the JWT
                //            survives verbatim in H2's name — and `remediated_any`
                //            made the audit trail say "found and remediated" on the
                //            run that leaked.
                // The proofs kept failing because remediation is header-granular
                // and value-only (names are unwritable) while matching is over the
                // JOINED stream, so a match can always be killed by deleting bytes
                // that are not the credential.
                //
                // Stop discharging the proof obligation; remove it. A Redacted head
                // fails CLOSED, exactly as the body does. ADR D3 explicitly
                // sanctions that rule for live BODY wire frames; applying it at
                // header granularity is the round-8 implementation-level security
                // correction, because splicing is also provably impossible for
                // spanning and name-borne matches there. True `[REDACTED]` splicing
                // stays the buffered path's behaviour (whose own spanning-match
                // pass-through is recorded, unfixed, in MODULE-012 §3.6).
                ScanResult::Redacted { findings, .. } => {
                    drop_wire_safely(Some(wire));
                    if ensure_stream_stage_deadline(Some(deadline)).is_err() {
                        return Err(HttpError::Transport(TransportErrorKind::Timeout));
                    }
                    let payload =
                        json!({"scan_context": "http_inbound", "finding_count": findings.len()});
                    ensure_stream_stage_deadline(Some(deadline))?;
                    self.emit(agent_id, "security.leak_detected", payload, None);
                    ensure_stream_stage_deadline(Some(deadline))?;
                    return Err(HttpError::InboundLeakBlocked(findings));
                }
            }
        }
        if ensure_stream_stage_deadline(Some(deadline)).is_err() {
            drop_wire_safely(Some(wire));
            return Err(HttpError::Transport(TransportErrorKind::Timeout));
        }

        let mut stream = Box::new(ScanningWireStream::new(
            wire,
            self.leak_detector.clone(),
            self.event_bus.clone(),
            agent_id.to_string(),
            holds,
            deadline,
        ));
        // `new` computes the live pattern-derived overlap window and allocates
        // the boxed wrapper. Arbitrate after that final synchronous stage; on
        // timeout the wrapper performs guarded synchronous cleanup before the
        // terminal is returned.
        if tokio::time::Instant::now() >= deadline {
            let _ = stream.terminate_timeout();
            return Err(HttpError::Transport(TransportErrorKind::Timeout));
        }
        let stream: Box<dyn HttpBodyStream> = stream;
        Ok((head, stream))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// MODULE-012-T29 — the overlap window is COMPUTED from the live
    /// LEAK_PATTERNS table and pinned: a pattern-table change that silently
    /// shrinks the guaranteed cross-chunk match window fails this test.
    #[test]
    fn t29_overlap_window_pinned() {
        let w = overlap_window_bytes();
        assert!(
            w >= 99,
            "overlap window W = {w} shrank below the pinned floor of 99"
        );
        // Driven by anthropic_api_key (sk-ant-api + {90,} = 100 min bytes).
        let anthropic_min = LEAK_PATTERNS
            .iter()
            .find(|p| p.name == "anthropic_api_key")
            .map(|p| pattern_min_len(p.regex))
            .expect("anthropic_api_key present in LEAK_PATTERNS");
        let max_min = LEAK_PATTERNS
            .iter()
            .map(|p| pattern_min_len(p.regex))
            .max()
            .unwrap();
        assert_eq!(
            max_min, anthropic_min,
            "W is expected to be driven by anthropic_api_key's minimum match length"
        );
        assert_eq!(w, max_min - 1);
    }

    /// The hold-matcher set derives from the live table's Block + Redact rows
    /// (Warn rows deliberately excluded — audit round 1 widening).
    #[test]
    fn t29b_hold_matchers_derived_from_table() {
        let expected = LEAK_PATTERNS
            .iter()
            .filter(|p| matches!(p.action, Action::Block | Action::Redact))
            .count();
        assert_eq!(hold_matchers().unwrap().len(), expected);
        assert!(
            expected >= 7,
            "5 Block + 2 Redact rows expected in the current table"
        );
        let warn_held = LEAK_PATTERNS
            .iter()
            .filter(|p| matches!(p.action, Action::Warn))
            .count();
        assert!(warn_held >= 1, "table sanity: at least one Warn row exists");
    }

    /// Drive the PRODUCTION `next_chunk` path with a weak detector and a
    /// test-small projection cap. The count-only preflight must terminate before
    /// lossy-string/detector allocation; the direct map helper shares the bound.
    #[tokio::test]
    async fn t29h_canonical_expansion_is_bounded() {
        let expanding = "\u{FDFA}";
        let mut stream = test_scanning_stream_with_detector(
            vec![Ok(expanding.as_bytes().to_vec())],
            Arc::new(CleanDetector),
        );
        stream.max_canonical_bytes = 8;
        match stream.next_chunk().await {
            Some(Err(HttpError::InboundLeakBlocked(findings))) => assert!(findings
                .iter()
                .any(|finding| finding.pattern_name == "stream_scan_budget")),
            other => panic!("canonical expansion must fail CLOSED, got {other:?}"),
        }
        assert!(stream.inner.is_none());
        assert!(canonical_map_with_limit(expanding.as_bytes(), 8).is_err());
        let (canon, map, tail) = canonical_map_with_limit(b"ordinary", 8).unwrap();
        assert_eq!(canon, b"ordinary");
        assert_eq!(map.len(), canon.len());
        assert_eq!(tail, None);
    }

    struct TestWireStream(std::collections::VecDeque<Result<Vec<u8>, ExecutorError>>);

    #[async_trait]
    impl WireChunkStream for TestWireStream {
        async fn next(&mut self) -> Option<Result<Vec<u8>, ExecutorError>> {
            self.0.pop_front()
        }
    }

    struct ImmediateHeadExecutor {
        execute_calls: Arc<std::sync::atomic::AtomicUsize>,
    }

    #[async_trait]
    impl crate::executor::HttpStreamExecutor for ImmediateHeadExecutor {
        async fn execute_stream(
            &self,
            _req: &HttpRequest,
            _redirect_check: Arc<dyn RedirectCheck>,
        ) -> Result<(HttpResponseHead, Box<dyn WireChunkStream>), ExecutorError> {
            self.execute_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok((
                HttpResponseHead {
                    status: 200,
                    headers: vec![],
                },
                Box::new(TestWireStream(std::collections::VecDeque::new())),
            ))
        }
    }

    struct RedirectingHeadExecutor {
        execute_calls: Arc<std::sync::atomic::AtomicUsize>,
    }

    #[async_trait]
    impl crate::executor::HttpStreamExecutor for RedirectingHeadExecutor {
        async fn execute_stream(
            &self,
            _req: &HttpRequest,
            redirect_check: Arc<dyn RedirectCheck>,
        ) -> Result<(HttpResponseHead, Box<dyn WireChunkStream>), ExecutorError> {
            self.execute_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let target = "https://redirect.example.com/final".to_string();
            redirect_check.check(&target, &[]).await.map_err(|reason| {
                ExecutorError::RedirectRejected {
                    reason,
                    target: target.clone(),
                }
            })?;
            Ok((
                HttpResponseHead {
                    status: 200,
                    headers: vec![],
                },
                Box::new(TestWireStream(std::collections::VecDeque::new())),
            ))
        }
    }

    /// Deliberately non-cooperative future: one poll blocks past the deadline
    /// and then returns Ready. Tokio's timer cannot pre-empt this shape, so it
    /// exercises the explicit post-poll deadline precedence check.
    struct BlockingWireStream {
        delay: std::time::Duration,
        output: Option<Result<Vec<u8>, ExecutorError>>,
    }

    #[async_trait]
    impl WireChunkStream for BlockingWireStream {
        async fn next(&mut self) -> Option<Result<Vec<u8>, ExecutorError>> {
            std::thread::sleep(self.delay);
            self.output.take()
        }
    }

    /// Deliberately NON-CONFORMING executor fixture: the pull is immediately
    /// ready, but destruction blocks. Production implementers must obey the
    /// bounded/non-blocking Drop invariant; this fixture exists only to prove
    /// that a cleanup stage completing after the deadline is reclassified as
    /// Timeout and that late-success HEAD ownership is explicit.
    struct BlockingDropWireStream {
        delay: std::time::Duration,
        output: Option<Result<Vec<u8>, ExecutorError>>,
        pull_called: Arc<std::sync::atomic::AtomicBool>,
        drop_called: Arc<std::sync::atomic::AtomicBool>,
    }

    #[async_trait]
    impl WireChunkStream for BlockingDropWireStream {
        async fn next(&mut self) -> Option<Result<Vec<u8>, ExecutorError>> {
            self.pull_called
                .store(true, std::sync::atomic::Ordering::SeqCst);
            self.output.take()
        }
    }

    impl Drop for BlockingDropWireStream {
        fn drop(&mut self) {
            std::thread::sleep(self.delay);
            self.drop_called
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    /// Deliberately non-conforming destruction fixture. The production helper
    /// catches this panic as defense in depth; a generic late-result discard
    /// would propagate it, so T29p discriminates the ownership-aware HEAD path
    /// from ordinary RAII result disposal.
    struct PanickingDropWireStream {
        drop_called: Arc<std::sync::atomic::AtomicBool>,
    }

    #[async_trait]
    impl WireChunkStream for PanickingDropWireStream {
        async fn next(&mut self) -> Option<Result<Vec<u8>, ExecutorError>> {
            None
        }
    }

    impl Drop for PanickingDropWireStream {
        fn drop(&mut self) {
            self.drop_called
                .store(true, std::sync::atomic::Ordering::SeqCst);
            panic!("intentional non-conforming wire Drop witness");
        }
    }

    /// Deliberately non-cooperative but bounded executor future. It returns a
    /// successful HEAD after the test-short chain deadline so the production
    /// `execute_streaming` call site must take ownership of the late wire.
    struct LateHeadExecutor {
        delay: std::time::Duration,
        execute_called: Arc<std::sync::atomic::AtomicBool>,
        drop_called: Arc<std::sync::atomic::AtomicBool>,
    }

    #[async_trait]
    impl crate::executor::HttpStreamExecutor for LateHeadExecutor {
        async fn execute_stream(
            &self,
            _req: &HttpRequest,
            _redirect_check: Arc<dyn RedirectCheck>,
        ) -> Result<(HttpResponseHead, Box<dyn WireChunkStream>), ExecutorError> {
            self.execute_called
                .store(true, std::sync::atomic::Ordering::SeqCst);
            std::thread::sleep(self.delay);
            Ok((
                HttpResponseHead {
                    status: 200,
                    headers: vec![],
                },
                Box::new(PanickingDropWireStream {
                    drop_called: self.drop_called.clone(),
                }),
            ))
        }
    }

    struct CleanDetector;

    impl LeakDetector for CleanDetector {
        fn scan(&self, _text: &str, _context: ScanContext) -> ScanResult {
            ScanResult::Clean
        }

        fn scan_headers(&self, _headers: &[(String, String)]) -> ScanResult {
            ScanResult::Clean
        }
    }

    struct CountingCleanDetector {
        delayed_scan_call: Option<usize>,
        scan_delay: std::time::Duration,
        scan_calls: Arc<std::sync::atomic::AtomicUsize>,
        header_scan_calls: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl LeakDetector for CountingCleanDetector {
        fn scan(&self, _text: &str, _context: ScanContext) -> ScanResult {
            let call = self
                .scan_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if self.delayed_scan_call == Some(call) {
                std::thread::sleep(self.scan_delay);
            }
            ScanResult::Clean
        }

        fn scan_headers(&self, _headers: &[(String, String)]) -> ScanResult {
            self.header_scan_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            ScanResult::Clean
        }
    }

    struct AllowSsrf;

    #[async_trait]
    impl advance_shared_types::security_validator::SsrfGuard for AllowSsrf {
        async fn check(
            &self,
            _url: &str,
        ) -> Result<(), advance_shared_types::security_validator::SsrfError> {
            Ok(())
        }
    }

    struct CountingSsrf {
        calls: Arc<std::sync::atomic::AtomicUsize>,
    }

    #[async_trait]
    impl advance_shared_types::security_validator::SsrfGuard for CountingSsrf {
        async fn check(
            &self,
            _url: &str,
        ) -> Result<(), advance_shared_types::security_validator::SsrfError> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
    }

    struct CountingPublicResolver {
        calls: Arc<std::sync::atomic::AtomicUsize>,
    }

    #[async_trait]
    impl crate::ssrf::Resolver for CountingPublicResolver {
        async fn resolve(
            &self,
            _host: &str,
        ) -> Result<Vec<std::net::IpAddr>, advance_shared_types::security_validator::SsrfError>
        {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(vec![std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                93, 184, 216, 34,
            ))])
        }
    }

    struct CountingRateLimiter {
        calls: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl crate::rate_limit::RateLimiter for CountingRateLimiter {
        fn check(&self, _agent_id: &str, _host: &str) -> Result<(), u64> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
    }

    struct BlockingResponseEmitter {
        delay: std::time::Duration,
        response_calls: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl EventBusEmit for BlockingResponseEmitter {
        fn emit(&self, event: Event) {
            if event.event_type == "http.response" {
                self.response_calls
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                std::thread::sleep(self.delay);
            }
        }
    }

    struct BlockingGetStorage {
        inner: cap_secrets::InMemorySecretStorage,
        delay: std::time::Duration,
        get_calls: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl cap_secrets::SecretStorage for BlockingGetStorage {
        fn put(
            &self,
            name: &str,
            stored: cap_secrets::StoredSecret,
        ) -> Result<(), cap_secrets::StorageError> {
            cap_secrets::SecretStorage::put(&self.inner, name, stored)
        }

        fn get(
            &self,
            name: &str,
        ) -> Result<Option<cap_secrets::StoredSecret>, cap_secrets::StorageError> {
            self.get_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            std::thread::sleep(self.delay);
            cap_secrets::SecretStorage::get(&self.inner, name)
        }

        fn exists(&self, name: &str) -> Result<bool, cap_secrets::StorageError> {
            cap_secrets::SecretStorage::exists(&self.inner, name)
        }
    }

    struct BlockingDetector {
        delay: std::time::Duration,
        scan_called: Arc<std::sync::atomic::AtomicBool>,
        head_scan_called: Arc<std::sync::atomic::AtomicBool>,
    }

    impl BlockingDetector {
        fn blocked() -> ScanResult {
            ScanResult::Blocked {
                findings: vec![Finding {
                    pattern_name: "blocking_detector".to_string(),
                    offset: 0,
                    length: 0,
                    action: Action::Block,
                }],
            }
        }
    }

    impl LeakDetector for BlockingDetector {
        fn scan(&self, _text: &str, _context: ScanContext) -> ScanResult {
            self.scan_called
                .store(true, std::sync::atomic::Ordering::SeqCst);
            std::thread::sleep(self.delay);
            Self::blocked()
        }

        fn scan_headers(&self, _headers: &[(String, String)]) -> ScanResult {
            self.head_scan_called
                .store(true, std::sync::atomic::Ordering::SeqCst);
            std::thread::sleep(self.delay);
            Self::blocked()
        }
    }

    fn test_scanning_stream_with_detector(
        items: Vec<Result<Vec<u8>, ExecutorError>>,
        detector: Arc<dyn LeakDetector>,
    ) -> ScanningWireStream {
        ScanningWireStream::new(
            Box::new(TestWireStream(items.into())),
            detector,
            None,
            "test-agent".to_string(),
            hold_matchers().unwrap(),
            tokio::time::Instant::now() + crate::executor::MAX_STREAM_DURATION,
        )
    }

    fn test_scanning_stream(items: Vec<Result<Vec<u8>, ExecutorError>>) -> ScanningWireStream {
        test_scanning_stream_with_detector(
            items,
            Arc::new(crate::leak_detector::DefaultLeakDetector::new()),
        )
    }

    fn assert_released(stream: &ScanningWireStream) {
        assert!(stream.done);
        assert!(stream.inner.is_none());
        assert_eq!(stream.overlap.len(), 0);
        assert_eq!(stream.overlap.capacity(), 0);
        assert_eq!(stream.held.len(), 0);
        assert_eq!(stream.held.capacity(), 0);
    }

    /// Clean EOF, executor error and the shared security-terminal helper all
    /// release vector allocations plus the boxed inner response.
    #[tokio::test]
    async fn t29i_terminal_paths_release_resources() {
        let mut clean_eof = test_scanning_stream(vec![]);
        clean_eof.overlap = Vec::with_capacity(4096);
        clean_eof.overlap.extend_from_slice(b"overlap");
        clean_eof.held = Vec::with_capacity(4096);
        clean_eof.held.extend_from_slice(b"ordinary held bytes");
        assert!(matches!(
            clean_eof.next_chunk().await,
            Some(Ok(bytes)) if bytes == b"ordinary held bytes"
        ));
        assert_released(&clean_eof);

        let mut executor_error = test_scanning_stream(vec![Err(ExecutorError::Transport)]);
        executor_error.overlap = Vec::with_capacity(4096);
        executor_error.overlap.extend_from_slice(b"overlap");
        executor_error.held = Vec::with_capacity(4096);
        executor_error.held.extend_from_slice(b"held");
        assert!(matches!(
            executor_error.next_chunk().await,
            Some(Err(HttpError::Transport(TransportErrorKind::Other)))
        ));
        assert_released(&executor_error);

        let mut security_terminal = test_scanning_stream(vec![Ok(b"unused".to_vec())]);
        security_terminal.overlap = Vec::with_capacity(4096);
        security_terminal.overlap.extend_from_slice(b"overlap");
        security_terminal.held = Vec::with_capacity(4096);
        security_terminal
            .held
            .extend_from_slice(b"credential prefix");
        assert!(matches!(
            security_terminal.terminate_scan_budget(),
            Some(Err(HttpError::InboundLeakBlocked(_)))
        ));
        assert_released(&security_terminal);
    }

    #[test]
    fn t29j_checked_ledger_survives_32bit_credit_threshold() {
        let credit = u32::MAX as u128;
        let debt = credit + MAX_SCAN_DEBT_BYTES as u128 + 2;
        let (_debt, _credit, exceeded) = checked_scan_ledger(debt, credit, 0, 0).unwrap();
        assert!(exceeded, "banked credit must not disable the debt guard");
        assert!(checked_scan_ledger(u128::MAX, 0, 0, 0).is_err());
    }

    #[tokio::test]
    async fn t29k_chain_deadline_blocks_custom_executor_output() {
        let mut stream = test_scanning_stream(vec![Ok(b"late".to_vec())]);
        stream.deadline = tokio::time::Instant::now() - std::time::Duration::from_millis(1);
        assert!(matches!(
            stream.next_chunk().await,
            Some(Err(HttpError::Transport(TransportErrorKind::Timeout)))
        ));
        assert_released(&stream);
    }

    #[tokio::test]
    async fn t29l_deadline_wins_after_non_cooperative_pull_returns() {
        for output in [None, Some(Err(ExecutorError::Transport))] {
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(1);
            let mut stream = ScanningWireStream::new(
                Box::new(BlockingWireStream {
                    delay: std::time::Duration::from_millis(5),
                    output,
                }),
                Arc::new(CleanDetector),
                None,
                "test-agent".to_string(),
                hold_matchers().unwrap(),
                deadline,
            );
            assert!(matches!(
                stream.next_chunk().await,
                Some(Err(HttpError::Transport(TransportErrorKind::Timeout)))
            ));
            assert_released(&stream);
        }

        // The same helper wraps the arbitrary executor HEAD future. Pin that a
        // late Ready(Error) cannot regain precedence over the chain deadline.
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(1);
        let late_head_error = complete_before_deadline(deadline, async {
            std::thread::sleep(std::time::Duration::from_millis(5));
            Err::<(), ExecutorError>(ExecutorError::Transport)
        })
        .await;
        assert!(late_head_error.is_err());
    }

    #[tokio::test]
    async fn t29m_deadline_wins_after_blocking_body_detector_returns() {
        let scan_called = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut stream = test_scanning_stream_with_detector(
            vec![Ok(b"ordinary body".to_vec())],
            Arc::new(BlockingDetector {
                delay: std::time::Duration::from_millis(400),
                scan_called: scan_called.clone(),
                head_scan_called: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            }),
        );
        stream.deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(200);

        assert!(matches!(
            stream.next_chunk().await,
            Some(Err(HttpError::Transport(TransportErrorKind::Timeout)))
        ));
        assert!(
            scan_called.load(std::sync::atomic::Ordering::SeqCst),
            "the synchronous detector must run so this is not an async-pull timeout"
        );
        assert_released(&stream);
    }

    #[test]
    fn t29n_common_sync_arbiter_rejects_late_head_and_eof_results() {
        let head_scan_called = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let detector = BlockingDetector {
            delay: std::time::Duration::from_millis(5),
            scan_called: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            head_scan_called: head_scan_called.clone(),
        };
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(1);
        let late_head = complete_sync_before_deadline(deadline, detector.scan_headers(&[]));
        assert!(late_head.is_err());
        assert!(head_scan_called.load(std::sync::atomic::Ordering::SeqCst));

        let held = b"sk-ant-apiAKIA0123456789ABCDEF";
        let (canon, _map, _tail) = canonical_map(held).unwrap();
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(1);
        let late_eof = complete_sync_before_deadline(deadline, {
            std::thread::sleep(std::time::Duration::from_millis(5));
            held_contains_completed_match(hold_matchers().unwrap(), &canon)
        });
        assert!(late_eof.is_err());
    }

    #[tokio::test]
    async fn t29o_terminal_cleanup_result_is_rearbitrated_on_real_body_paths() {
        // Resolve the once-built DFA set before any per-case deadline starts;
        // matcher construction must not be able to satisfy the timeout arm.
        let holds = hold_matchers().unwrap();
        let cases = [
            (None, Arc::new(CleanDetector) as Arc<dyn LeakDetector>),
            (
                Some(Err(ExecutorError::Transport)),
                Arc::new(CleanDetector) as Arc<dyn LeakDetector>,
            ),
            (
                Some(Ok(b"AKIAIOSFODNN7EXAMPLE".to_vec())),
                Arc::new(crate::leak_detector::DefaultLeakDetector::new()) as Arc<dyn LeakDetector>,
            ),
        ];

        for (output, detector) in cases {
            let pull_called = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let drop_called = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(250);
            let mut stream = ScanningWireStream::new(
                Box::new(BlockingDropWireStream {
                    delay: std::time::Duration::from_millis(300),
                    output,
                    pull_called: pull_called.clone(),
                    drop_called: drop_called.clone(),
                }),
                detector,
                None,
                "test-agent".to_string(),
                holds,
                deadline,
            );
            assert!(matches!(
                stream.next_chunk().await,
                Some(Err(HttpError::Transport(TransportErrorKind::Timeout)))
            ));
            assert!(
                pull_called.load(std::sync::atomic::Ordering::SeqCst),
                "the real BODY pull must run before delayed cleanup crosses the deadline"
            );
            assert!(
                drop_called.load(std::sync::atomic::Ordering::SeqCst),
                "the real BODY terminal must destroy the owned wire stream"
            );
            assert_released(&stream);
        }
    }

    #[tokio::test]
    async fn t29p_late_success_head_output_is_guarded_before_discard() {
        use cap_secrets::{InMemorySecretStorage, SecretStorage, SecretStore};

        let execute_called = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let drop_called = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let storage: Arc<dyn SecretStorage> = Arc::new(InMemorySecretStorage::new());
        let secret_store = Arc::new(SecretStore::new(
            zeroize::Zeroizing::new([0xab; 32]),
            storage,
        ));
        let buffered_executor: Arc<dyn crate::executor::HttpExecutor> =
            Arc::new(crate::executor::MockHttpExecutor::new());
        let stream_executor: Arc<dyn crate::executor::HttpStreamExecutor> =
            Arc::new(LateHeadExecutor {
                delay: std::time::Duration::from_millis(500),
                execute_called: execute_called.clone(),
                drop_called: drop_called.clone(),
            });
        let chain = DefaultHttpSecurityChain::new(
            secret_store,
            Arc::new(CleanDetector),
            Arc::new(AllowSsrf),
            Arc::new(crate::rate_limit::AlwaysAllow),
            buffered_executor,
        )
        .with_stream_executor(stream_executor)
        .with_stream_duration_for_test(std::time::Duration::from_millis(250));
        let request = HttpRequest {
            method: advance_shared_types::security_validator::HttpMethod::Get,
            url: "https://api.example.com/stream".to_string(),
            headers: vec![],
            body: vec![],
        };
        let capability = HttpCapability {
            allowlist: advance_shared_types::security_validator::Allowlist {
                patterns: vec!["api.example.com".to_string()],
            },
            credentials: vec![],
            component_id: "test-component".to_string(),
        };

        let result = chain
            .execute_streaming("test-agent", request, &capability)
            .await;
        assert!(matches!(
            result,
            Err(HttpError::Transport(TransportErrorKind::Timeout))
        ));
        assert!(
            execute_called.load(std::sync::atomic::Ordering::SeqCst),
            "the production execute_streaming call site must invoke the executor"
        );
        assert!(
            drop_called.load(std::sync::atomic::Ordering::SeqCst),
            "the production HEAD wrapper must own and guard late-success wire destruction"
        );
    }

    #[tokio::test]
    async fn t29q_outbound_deadline_stops_later_collaborators() {
        use cap_secrets::{InMemorySecretStorage, SecretStorage, SecretStore};

        let scan_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let header_scan_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let ssrf_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let rate_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let execute_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let traces = Arc::new(std::sync::Mutex::new(Vec::new()));

        let detector: Arc<dyn LeakDetector> = Arc::new(CountingCleanDetector {
            delayed_scan_call: Some(0),
            scan_delay: std::time::Duration::from_millis(500),
            scan_calls: scan_calls.clone(),
            header_scan_calls: header_scan_calls.clone(),
        });
        let ssrf: Arc<dyn advance_shared_types::security_validator::SsrfGuard> =
            Arc::new(CountingSsrf {
                calls: ssrf_calls.clone(),
            });
        let rate_limiter: Arc<dyn crate::rate_limit::RateLimiter> = Arc::new(CountingRateLimiter {
            calls: rate_calls.clone(),
        });
        let stream_executor: Arc<dyn crate::executor::HttpStreamExecutor> =
            Arc::new(ImmediateHeadExecutor {
                execute_calls: execute_calls.clone(),
            });
        let storage: Arc<dyn SecretStorage> = Arc::new(InMemorySecretStorage::new());
        let secret_store = Arc::new(SecretStore::new(
            zeroize::Zeroizing::new([0xab; 32]),
            storage,
        ));
        let buffered_executor: Arc<dyn crate::executor::HttpExecutor> =
            Arc::new(crate::executor::MockHttpExecutor::new());
        let trace_sink = traces.clone();
        let chain = DefaultHttpSecurityChain::new(
            secret_store,
            detector,
            ssrf,
            rate_limiter,
            buffered_executor,
        )
        .with_step_tracer(Arc::new(move |step| trace_sink.lock().unwrap().push(step)))
        .with_stream_executor(stream_executor)
        .with_stream_duration_for_test(std::time::Duration::from_millis(250));
        let request = HttpRequest {
            method: advance_shared_types::security_validator::HttpMethod::Get,
            url: "https://api.example.com/stream".to_string(),
            headers: vec![],
            body: vec![],
        };
        let capability = HttpCapability {
            allowlist: advance_shared_types::security_validator::Allowlist {
                patterns: vec!["api.example.com".to_string()],
            },
            credentials: vec![],
            component_id: "test-component".to_string(),
        };

        let result = chain
            .execute_streaming("test-agent", request, &capability)
            .await;
        assert!(matches!(
            result,
            Err(HttpError::Transport(TransportErrorKind::Timeout))
        ));
        assert_eq!(scan_calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(
            header_scan_calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "a late URL scan must gate the later header/body scans"
        );
        assert_eq!(ssrf_calls.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(rate_calls.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(execute_calls.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(
            traces.lock().unwrap().as_slice(),
            [
                crate::security_chain::STEP_ALLOWLIST,
                crate::security_chain::STEP_OUTBOUND_LEAK_SCAN
            ]
        );
    }

    #[tokio::test]
    async fn t29r_response_event_deadline_stops_head_gate() {
        use cap_secrets::{InMemorySecretStorage, SecretStorage, SecretStore};

        let scan_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let header_scan_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let execute_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let response_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let traces = Arc::new(std::sync::Mutex::new(Vec::new()));

        let detector: Arc<dyn LeakDetector> = Arc::new(CountingCleanDetector {
            delayed_scan_call: None,
            scan_delay: std::time::Duration::ZERO,
            scan_calls,
            header_scan_calls: header_scan_calls.clone(),
        });
        let stream_executor: Arc<dyn crate::executor::HttpStreamExecutor> =
            Arc::new(ImmediateHeadExecutor {
                execute_calls: execute_calls.clone(),
            });
        let event_bus: Arc<dyn EventBusEmit> = Arc::new(BlockingResponseEmitter {
            delay: std::time::Duration::from_millis(500),
            response_calls: response_calls.clone(),
        });
        let storage: Arc<dyn SecretStorage> = Arc::new(InMemorySecretStorage::new());
        let secret_store = Arc::new(SecretStore::new(
            zeroize::Zeroizing::new([0xab; 32]),
            storage,
        ));
        let buffered_executor: Arc<dyn crate::executor::HttpExecutor> =
            Arc::new(crate::executor::MockHttpExecutor::new());
        let trace_sink = traces.clone();
        let chain = DefaultHttpSecurityChain::new(
            secret_store,
            detector,
            Arc::new(AllowSsrf),
            Arc::new(crate::rate_limit::AlwaysAllow),
            buffered_executor,
        )
        .with_step_tracer(Arc::new(move |step| trace_sink.lock().unwrap().push(step)))
        .with_event_bus(event_bus)
        .with_stream_executor(stream_executor)
        .with_stream_duration_for_test(std::time::Duration::from_millis(250));
        let request = HttpRequest {
            method: advance_shared_types::security_validator::HttpMethod::Get,
            url: "https://api.example.com/stream".to_string(),
            headers: vec![],
            body: vec![],
        };
        let capability = HttpCapability {
            allowlist: advance_shared_types::security_validator::Allowlist {
                patterns: vec!["api.example.com".to_string()],
            },
            credentials: vec![],
            component_id: "test-component".to_string(),
        };

        let result = chain
            .execute_streaming("test-agent", request, &capability)
            .await;
        assert!(matches!(
            result,
            Err(HttpError::Transport(TransportErrorKind::Timeout))
        ));
        assert_eq!(execute_calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(response_calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(
            header_scan_calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "only the outbound header scan may run after the response event crosses the deadline"
        );
        assert!(
            !traces
                .lock()
                .unwrap()
                .contains(&crate::security_chain::STEP_REDACT_ERROR_MESSAGE),
            "late response telemetry must gate the head trace and detectors"
        );
    }

    #[tokio::test]
    async fn t29s_redirect_deadline_stops_nested_collaborators() {
        use cap_secrets::{InMemorySecretStorage, SecretStorage, SecretStore};

        let scan_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let header_scan_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let ssrf_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let rate_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let execute_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        // Calls 0 and 1 are the shared outbound URL/body scans. Call 2 is the
        // nested redirect URL scan and deliberately crosses the deadline.
        let detector: Arc<dyn LeakDetector> = Arc::new(CountingCleanDetector {
            delayed_scan_call: Some(2),
            scan_delay: std::time::Duration::from_millis(500),
            scan_calls: scan_calls.clone(),
            header_scan_calls: header_scan_calls.clone(),
        });
        let ssrf: Arc<dyn advance_shared_types::security_validator::SsrfGuard> =
            Arc::new(CountingSsrf {
                calls: ssrf_calls.clone(),
            });
        let rate_limiter: Arc<dyn crate::rate_limit::RateLimiter> = Arc::new(CountingRateLimiter {
            calls: rate_calls.clone(),
        });
        let stream_executor: Arc<dyn crate::executor::HttpStreamExecutor> =
            Arc::new(RedirectingHeadExecutor {
                execute_calls: execute_calls.clone(),
            });
        let storage: Arc<dyn SecretStorage> = Arc::new(InMemorySecretStorage::new());
        let secret_store = Arc::new(SecretStore::new(
            zeroize::Zeroizing::new([0xab; 32]),
            storage,
        ));
        let buffered_executor: Arc<dyn crate::executor::HttpExecutor> =
            Arc::new(crate::executor::MockHttpExecutor::new());
        let chain = DefaultHttpSecurityChain::new(
            secret_store,
            detector,
            ssrf,
            rate_limiter,
            buffered_executor,
        )
        .with_stream_executor(stream_executor)
        .with_stream_duration_for_test(std::time::Duration::from_millis(250));
        let request = HttpRequest {
            method: advance_shared_types::security_validator::HttpMethod::Get,
            url: "https://api.example.com/stream".to_string(),
            headers: vec![],
            body: vec![],
        };
        let capability = HttpCapability {
            allowlist: advance_shared_types::security_validator::Allowlist {
                patterns: vec![
                    "api.example.com".to_string(),
                    "redirect.example.com".to_string(),
                ],
            },
            credentials: vec![],
            component_id: "test-component".to_string(),
        };

        let result = chain
            .execute_streaming("test-agent", request, &capability)
            .await;
        assert!(matches!(
            result,
            Err(HttpError::Transport(TransportErrorKind::Timeout))
        ));
        assert_eq!(scan_calls.load(std::sync::atomic::Ordering::SeqCst), 3);
        assert_eq!(
            header_scan_calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "a late redirect URL scan must gate the nested redirect header scan"
        );
        assert_eq!(
            ssrf_calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "only the top-level outbound SSRF check may run"
        );
        assert_eq!(rate_calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(execute_calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn t29t_secret_deadline_stops_nested_resolutions() {
        use advance_shared_types::security_validator::{CredentialBinding, CredentialPosition};
        use cap_secrets::{SecretStorage, SecretStore};

        for request_body in [b"{first}-{second}".to_vec(), Vec::new()] {
            let get_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let ssrf_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let rate_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let execute_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let storage = Arc::new(BlockingGetStorage {
                inner: cap_secrets::InMemorySecretStorage::new(),
                delay: std::time::Duration::from_millis(500),
                get_calls: get_calls.clone(),
            });
            let storage_trait: Arc<dyn SecretStorage> = storage;
            let secret_store = Arc::new(SecretStore::new(
                zeroize::Zeroizing::new([0xab; 32]),
                storage_trait,
            ));
            secret_store.store("first", "first-value").unwrap();
            secret_store.store("second", "second-value").unwrap();

            let ssrf: Arc<dyn advance_shared_types::security_validator::SsrfGuard> =
                Arc::new(CountingSsrf {
                    calls: ssrf_calls.clone(),
                });
            let rate_limiter: Arc<dyn crate::rate_limit::RateLimiter> =
                Arc::new(CountingRateLimiter {
                    calls: rate_calls.clone(),
                });
            let buffered_executor: Arc<dyn crate::executor::HttpExecutor> =
                Arc::new(crate::executor::MockHttpExecutor::new());
            let stream_executor: Arc<dyn crate::executor::HttpStreamExecutor> =
                Arc::new(ImmediateHeadExecutor {
                    execute_calls: execute_calls.clone(),
                });
            let chain = DefaultHttpSecurityChain::new(
                secret_store,
                Arc::new(CleanDetector),
                ssrf,
                rate_limiter,
                buffered_executor,
            )
            .with_stream_executor(stream_executor)
            .with_stream_duration_for_test(std::time::Duration::from_millis(250));
            let request = HttpRequest {
                method: advance_shared_types::security_validator::HttpMethod::Post,
                url: "https://api.example.com/stream".to_string(),
                headers: vec![],
                body: request_body.clone(),
            };
            let capability = HttpCapability {
                allowlist: advance_shared_types::security_validator::Allowlist {
                    patterns: vec!["api.example.com".to_string()],
                },
                credentials: vec![
                    CredentialBinding {
                        position: CredentialPosition::CustomHeader {
                            key: "X-First".to_string(),
                        },
                        secret_name: "first".to_string(),
                    },
                    CredentialBinding {
                        position: CredentialPosition::CustomHeader {
                            key: "X-Second".to_string(),
                        },
                        secret_name: "second".to_string(),
                    },
                ],
                component_id: "test-component".to_string(),
            };

            let result = chain
                .execute_streaming("test-agent", request, &capability)
                .await;
            assert!(matches!(
                result,
                Err(HttpError::Transport(TransportErrorKind::Timeout))
            ));
            assert_eq!(
                get_calls.load(std::sync::atomic::Ordering::SeqCst),
                1,
                "a late secret resolution must gate the second nested storage callback"
            );
            assert_eq!(ssrf_calls.load(std::sync::atomic::Ordering::SeqCst), 0);
            assert_eq!(rate_calls.load(std::sync::atomic::Ordering::SeqCst), 0);
            assert_eq!(execute_calls.load(std::sync::atomic::Ordering::SeqCst), 0);
        }
    }

    #[tokio::test]
    async fn t29u_live_dns_tunable_deadline_stops_nested_dns_work() {
        use crate::ssrf::Resolver;
        use advance_shared_types::security_validator::SsrfGuard;
        use cap_secrets::{InMemorySecretStorage, SecretStorage, SecretStore};

        // Production DefaultSsrfGuard compound boundary: warm one cache entry,
        // then make the live TTL callback cross the chain deadline while
        // expiring that entry. No second resolver invocation may begin.
        let resolver_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let guard =
            crate::ssrf::DefaultSsrfGuard::with_resolver(Box::new(CountingPublicResolver {
                calls: resolver_calls.clone(),
            }));
        guard.check("https://api.example.com/warm").await.unwrap();
        let guard = guard.with_cache_ttl_source(Arc::new(|| {
            std::thread::sleep(std::time::Duration::from_millis(500));
            0
        }));

        let rate_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let execute_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let storage: Arc<dyn SecretStorage> = Arc::new(InMemorySecretStorage::new());
        let secret_store = Arc::new(SecretStore::new(
            zeroize::Zeroizing::new([0xab; 32]),
            storage,
        ));
        let chain = DefaultHttpSecurityChain::new(
            secret_store,
            Arc::new(CleanDetector),
            Arc::new(guard),
            Arc::new(CountingRateLimiter {
                calls: rate_calls.clone(),
            }),
            Arc::new(crate::executor::MockHttpExecutor::new()),
        )
        .with_stream_executor(Arc::new(ImmediateHeadExecutor {
            execute_calls: execute_calls.clone(),
        }))
        .with_stream_duration_for_test(std::time::Duration::from_millis(250));
        let request = HttpRequest {
            method: advance_shared_types::security_validator::HttpMethod::Get,
            url: "https://api.example.com/stream".to_string(),
            headers: vec![],
            body: vec![],
        };
        let capability = HttpCapability {
            allowlist: advance_shared_types::security_validator::Allowlist {
                patterns: vec!["api.example.com".to_string()],
            },
            credentials: vec![],
            component_id: "test-component".to_string(),
        };
        let result = chain
            .execute_streaming("test-agent", request, &capability)
            .await;
        assert!(matches!(
            result,
            Err(HttpError::Transport(TransportErrorKind::Timeout))
        ));
        assert_eq!(
            resolver_calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "a late live cache-TTL callback must not start a second resolver future"
        );
        assert_eq!(rate_calls.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(execute_calls.load(std::sync::atomic::Ordering::SeqCst), 0);

        // The redirect validator owns a separate SSRF call site. Repeat the
        // warmed-cache witness there so deleting its task-scope cannot hide
        // behind the initial outbound path's coverage.
        let redirect_resolver_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let redirect_guard =
            crate::ssrf::DefaultSsrfGuard::with_resolver(Box::new(CountingPublicResolver {
                calls: redirect_resolver_calls.clone(),
            }));
        redirect_guard
            .check("https://redirect.example.com/warm")
            .await
            .unwrap();
        let redirect_guard = redirect_guard.with_cache_ttl_source(Arc::new(|| {
            std::thread::sleep(std::time::Duration::from_millis(500));
            0
        }));
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(250);
        let redirect_check = crate::executor::DefaultRedirectCheck {
            allowlist: advance_shared_types::security_validator::Allowlist {
                patterns: vec!["redirect.example.com".to_string()],
            },
            leak_detector: Arc::new(CleanDetector),
            ssrf_guard: Arc::new(redirect_guard),
        }
        .with_deadline(deadline);
        let redirect_result = complete_before_deadline(
            deadline,
            redirect_check.check("https://redirect.example.com/final", &[]),
        )
        .await;
        assert!(
            redirect_result.is_err(),
            "the redirect SSRF call site must preserve deadline precedence"
        );
        assert_eq!(
            redirect_resolver_calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "a late redirect cache-TTL callback must not start a second resolver future"
        );

        // Production RealResolver compound boundary: install the same scoped
        // deadline as both production call sites, but deliberately omit an
        // outer timeout. The inner checkpoint itself must return DnsTimeout;
        // old code proceeds to a successful numeric lookup and fails this.
        let real = crate::ssrf::RealResolver::new().with_timeout_source(Arc::new(|| {
            std::thread::sleep(std::time::Duration::from_millis(500));
            crate::ssrf::DEFAULT_DNS_TIMEOUT_MS
        }));
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(250);
        let real_result =
            crate::ssrf::with_stream_ssrf_deadline(deadline, real.resolve("93.184.216.34")).await;
        assert!(
            matches!(
                real_result,
                Err(advance_shared_types::security_validator::SsrfError::DnsTimeout)
            ),
            "a late live DNS-timeout callback must not poll lookup_host"
        );
    }

    /// Task-local semantics used by the production DNS compound gates: nested
    /// scopes restore correctly, explicit concurrent scopes stay isolated, a
    /// spawned task does not accidentally inherit authority, and no-context
    /// buffered callers retain the historical fallback.
    #[tokio::test]
    async fn t29w_stream_ssrf_deadline_scope_is_isolated() {
        assert_eq!(crate::ssrf::current_stream_ssrf_deadline(), None);
        let outer = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
        let inner = outer - std::time::Duration::from_secs(10);
        crate::ssrf::with_stream_ssrf_deadline(outer, async {
            assert_eq!(crate::ssrf::current_stream_ssrf_deadline(), Some(outer));
            let unscoped_child =
                tokio::spawn(async { crate::ssrf::current_stream_ssrf_deadline() })
                    .await
                    .unwrap();
            assert_eq!(unscoped_child, None);
            crate::ssrf::with_stream_ssrf_deadline(inner, async {
                assert_eq!(crate::ssrf::current_stream_ssrf_deadline(), Some(inner));
            })
            .await;
            assert_eq!(crate::ssrf::current_stream_ssrf_deadline(), Some(outer));
        })
        .await;
        assert_eq!(crate::ssrf::current_stream_ssrf_deadline(), None);

        let left = tokio::time::Instant::now() + std::time::Duration::from_secs(40);
        let right = left + std::time::Duration::from_secs(1);
        let (seen_left, seen_right) = tokio::join!(
            crate::ssrf::with_stream_ssrf_deadline(left, async {
                tokio::task::yield_now().await;
                crate::ssrf::current_stream_ssrf_deadline()
            }),
            crate::ssrf::with_stream_ssrf_deadline(right, async {
                tokio::task::yield_now().await;
                crate::ssrf::current_stream_ssrf_deadline()
            })
        );
        assert_eq!(seen_left, Some(left));
        assert_eq!(seen_right, Some(right));
        assert_eq!(crate::ssrf::current_stream_ssrf_deadline(), None);
    }

    #[tokio::test]
    async fn s3_custom_executor_oversized_chunk_fails_before_scan_copy() {
        let mut stream = test_scanning_stream_with_detector(
            vec![Ok(vec![b'x'; MAX_CHAIN_STREAM_BYTES + 1])],
            Arc::new(CleanDetector),
        );
        match stream.next_chunk().await {
            Some(Err(HttpError::InboundLeakBlocked(findings))) => assert!(findings
                .iter()
                .any(|finding| finding.pattern_name == "stream_scan_budget")),
            other => panic!("oversized custom chunk must fail CLOSED, got {other:?}"),
        }
        assert_released(&stream);
    }

    fn split_of(buf: &[u8]) -> usize {
        let (canon, map, tail) = canonical_map(buf).unwrap();
        hold_split_point(hold_matchers().unwrap(), &canon, &map, buf.len(), tail).unwrap()
    }

    /// `(split, does the HELD region contain a completed match)` — the two
    /// questions the production path asks at different times (per round vs at
    /// EOF), combined here for test convenience.
    fn split_and_match(buf: &[u8]) -> (usize, bool) {
        let split = split_of(buf);
        let (held_canon, _m, _t) = canonical_map(&buf[split..]).unwrap();
        let matched = held_contains_completed_match(hold_matchers().unwrap(), &held_canon).unwrap();
        (split, matched)
    }

    /// Prefix-viability unit checks: viable in-progress prefixes hold, dead
    /// suffixes emit, case-insensitivity and canonicalization come from the
    /// pattern + the canonical feed.
    #[test]
    fn t29c_hold_split_point_semantics() {
        // In-progress bearer prefix at the tail → held from position of 'B'.
        assert_eq!(split_of(b"hello world Bearer ey"), 12);
        // Lowercase variant ((?i)) also held.
        assert_eq!(split_of(b"hello world bearer ey"), 12);
        // Resolved-dead lookalike emits fully.
        assert_eq!(split_of(b"hello world Bearing up"), 22);
        // No candidates at all emits fully.
        assert_eq!(split_of(b"0123456789 nothing here"), 23);
        // Partial literal prefix at the very end is held ("Bea" could become
        // "Bearer eyJ...").
        assert_eq!(split_of(b"xxxxBea"), 4);
        // Block-pattern in-progress prefixes are now held too (audit round 1):
        // a forming anthropic key…
        assert_eq!(split_of(b"data: sk-ant-apiAbc"), 6);
        // …and a pem header with its unbounded [A-Z ]* interior still open.
        assert_eq!(split_of(b"log: -----BEGIN RSA PRIVATE"), 5);
        // Invisible-inflated forming credential: ZWSP interleave no longer
        // defeats the hold (canonical feed strips it).
        let buf = "x B\u{200B}\u{200B}earer ey".as_bytes();
        assert_eq!(split_of(buf), 2);
        // Unicode-whitespace between `Bearer` and the token (audit round 2:
        // the hold DFA is Unicode-mode now, so `\s` matches U+1680/U+2028 the
        // same way the detector regex does — the forming match is held, not
        // dropped to an ASCII-`\s` dead state).
        let buf = "y Bearer\u{1680}ey".as_bytes();
        assert_eq!(split_of(buf), 2);
        let buf = "z Bearer\u{2028}ey".as_bytes();
        assert_eq!(split_of(buf), 2);
        // Long-s after the github `gh` seed. NOTE (audit round 3): this case is
        // SUBSUMED by NFKC — `canonical_map` folds ſ→s before the DFA sees it,
        // so an ASCII-only DFA would hold it too. It is NOT a discriminator for
        // the Unicode-syntax fix (the U+1680/U+2028 whitespace cases above are —
        // NFKC does not fold those). Kept as a valid hold check.
        let buf = "q gh\u{017F}_abc".as_bytes();
        assert_eq!(split_of(buf), 2);
        // A resolved pem lookalike (interior char outside [A-Z ]) emits up to
        // its trailing '-' — which is itself a viable NEW pem-match start (it
        // could be `-----BEGIN …` split across the chunk boundary) and is
        // correctly held.
        assert_eq!(split_of(b"-----BEGIN CERTIFICATE-"), 22);
        // Without the trailing dash the lookalike emits fully.
        assert_eq!(split_of(b"-----BEGIN CERTIFICATE:"), 23);
        // Trailing incomplete UTF-8 sequence is withheld even with no
        // pattern candidate.
        let mut buf = b"plain ".to_vec();
        buf.extend_from_slice(&"\u{4E2D}".as_bytes()[..2]);
        assert_eq!(split_of(&buf), 6);
    }

    /// AUDIT ROUND 5 (Critical regression pin) — a COMPLETED match that the
    /// DFA then walks out of must report `Matched` (⇒ hold), never `Dead`
    /// (⇒ emit). MODULE-012-AC-24 drops Mn, so U+0301 is no longer a DFA killer;
    /// the pin is a non-dropped class miss (`!`). Keep a non-match prefix so
    /// the split is not 0.
    #[test]
    fn t29e_completed_match_then_dead_is_held_not_emitted() {
        let exploit = "data: Bearer eyJabc!";
        let (split, saw_match) = split_and_match(exploit.as_bytes());
        assert!(
            saw_match,
            "a completed bearer_token match must be reported as Matched"
        );
        assert_eq!(
            split, 6,
            "everything from `Bearer` on must be HELD, not emitted (got split {split})"
        );

        let basic = "Authorization: Basic QUJDREVGRw==!";
        let (bsplit, bmatch) = split_and_match(basic.as_bytes());
        assert!(bmatch, "auth_header_basic completed match must be Matched");
        assert_eq!(bsplit, 0, "held from the `Authorization:` literal");
    }

    /// AUDIT ROUND 5 — the excess/credit arithmetic silently degrades if a
    /// future pattern table pushes `window` past the raw overlap cap, so pin
    /// the coupling the formulas assume.
    #[test]
    fn t29f_window_below_overlap_raw_cap() {
        // `MAX_OVERLAP_RAW` is function-local; mirror its value and pin the
        // relation the ledger + belt trimming depend on.
        const MAX_OVERLAP_RAW_MIRROR: usize = 8 * 1024;
        assert!(
            overlap_window_bytes() < MAX_OVERLAP_RAW_MIRROR,
            "window must stay below the raw overlap cap or the canonical trim never fires"
        );
        // Audit round 6: this previously pinned only `> window / 2` (≈49),
        // which ADMITS values that invert the invariant the constant's own doc
        // states — at 50, a clean 1-byte-per-frame stream nets +50/round and is
        // cut at ~671 K rounds. Pin the real relation: credit must exceed the
        // per-round baseline debt (`overlap ≈ window`, `held ≈ 0`, plus the
        // per-round unit) or a legitimate finely-chunked stream fails closed.
        // Audit round 7: a row admitting a ZERO-LENGTH match would be invisible
        // to `first_bytes` (built from non-dead successors only) and would make
        // `pattern_min_len` report 0, which `overlap_window_bytes`'s `.max()`
        // silently absorbs. round 8 REMOVED the round-7 start-state
        // check as dead code (delayed match semantics), so this pin is now the
        // WHOLE guarantee, not a belt beside a brace — do not weaken it.
        for p in LEAK_PATTERNS
            .iter()
            .filter(|p| matches!(p.action, Action::Block | Action::Redact))
        {
            assert!(
                pattern_min_len(p.regex) > 0,
                "held pattern {} admits a zero-length match; the hold cannot see it",
                p.name
            );
        }
        assert!(
            SCAN_CREDIT_PER_WIRE_BYTE > overlap_window_bytes() + 1,
            "credit per wire byte ({}) must exceed the per-round baseline debt \
             (window {} + 1) or a 1-byte-per-frame clean stream is cut",
            SCAN_CREDIT_PER_WIRE_BYTE,
            overlap_window_bytes()
        );
    }

    /// AUDIT ROUND 6 (Critical regression pin) — `hold_split_point`
    /// short-circuits at the FIRST non-dead candidate, so it cannot answer
    /// "does the held region contain a completed match?". That question is
    /// `held_contains_completed_match`'s, and it must NOT short-circuit: here
    /// the earliest candidate (`anthropic_api_key` at 0, needing {90,}) is
    /// merely Viable while a COMPLETE `aws_access_key` sits at index 10.
    /// Round 5 derived the EOF guard from the first-candidate verdict and so
    /// would have flushed this credential.
    #[test]
    fn t29g_completed_match_behind_viable_prefix_is_detected() {
        let buf = b"sk-ant-apiAKIA0123456789ABCDEF";
        let (canon, _map, _tail) = canonical_map(buf).unwrap();

        // The split-point walk stops at the viable prefix and reports 0 …
        assert_eq!(split_of(buf), 0, "held from the earliest viable candidate");

        // … but the EOF question must still find the completed AWS key at 10.
        assert!(
            held_contains_completed_match(hold_matchers().unwrap(), &canon).unwrap(),
            "a completed match behind a merely-viable prefix must be detected"
        );

        // Control: the same viable prefix with no completed match behind it.
        let clean = b"sk-ant-apiabcdefghij";
        let (ccanon, _m, _t) = canonical_map(clean).unwrap();
        assert!(
            !held_contains_completed_match(hold_matchers().unwrap(), &ccanon).unwrap(),
            "a merely-viable prefix alone must NOT be reported as completed"
        );
    }

    /// The canonical feed maps offsets back to source chars and withholds a
    /// trailing incomplete sequence.
    #[test]
    fn t29d_canonical_map_offsets() {
        let s = "a\u{200B}B\u{FF25}c"; // a + ZWSP + B + fullwidth E + c
        let (canon, map, tail) = canonical_map(s.as_bytes()).unwrap();
        assert_eq!(canon, b"aBEc", "strip ZWSP, NFKC fullwidth E to E");
        assert_eq!(tail, None);
        // 'B' canonical byte maps back to its raw offset (after 3-byte ZWSP).
        assert_eq!(map[1], 4);
        // Fullwidth E (3 raw bytes at offset 5) canonicalizes to one byte
        // mapping to raw 5.
        assert_eq!(map[2], 5);
    }
}

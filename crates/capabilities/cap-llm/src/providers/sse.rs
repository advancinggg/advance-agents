//! Shared SSE plumbing for the three provider backends (ADR 2026-07-22 D4;
//! MODULE-009 §2.3 `FrameSplitter`).
//!
//! [`FrameSplitter`] is a pure incremental splitter: raw transport chunks
//! in, completed SSE frames out. It owns the generic wire concerns — the
//! one-time UTF-8 BOM strip, `event:`/`data:` field assembly, blank-line
//! dispatch, CRLF tolerance, comment lines — so the per-backend
//! `parse_sse_frame` impls only ever see whole frames. No IO, no async:
//! unit-witnessable today (S2) and consumed live by the S4 slice.
//!
//! Frame boundaries are ASCII newlines, so a multi-byte UTF-8 code point can
//! never straddle two frames; the lossy decode inside [`SseFrame`] assembly
//! therefore only mangles genuinely invalid upstream bytes. (The security
//! wire-scan's rejoin-before-decode discipline is CONTRACT-233/S3 territory
//! and happens BEFORE bytes reach this splitter.)

// Build-ahead-of-wiring (ADR 2026-07-22): this whole SSE surface is the S2
// deliverable — built + unit-tested here, but its PRODUCTION consumer is the
// S4 live-stream slice (`stream_begin_live`), which is out of scope for this
// task. Until S4 wires it, only the tests exercise it, so rustc's dead-code
// lint fires on the non-test build. Intentional boundary, not orphaned code.
#![allow(dead_code)]

use crate::error::LlmError;

/// Upper bound on a SINGLE frame's accumulated bytes. A cooperating upstream
/// sends kilobyte-scale frames; a runaway or malicious one must not grow one
/// frame unboundedly. Exceeding it is an enum-coded STATIC error
/// (CONTRACT-111 Invariant 7 — no upstream bytes in the reason).
///
/// SCOPE NOTE (for the S4 live-stream wiring): this caps PER FRAME, not the
/// aggregate per push. `push` also front-drains completed frames one at a
/// time (`Vec::drain` — O(remaining) each), so a single push delivering very
/// many small complete frames is O(n²) CPU and the returned Vec is bounded
/// only by the input chunk. S4 must bound the input chunk size fed per push
/// (real transports already deliver bounded chunks); a cursor/`VecDeque`
/// drain would remove the O(n²) if that ever matters.
const MAX_FRAME_BYTES: usize = 512 * 1024;

/// One complete SSE frame: optional `event:` name + `data:` payload
/// (multiple `data:` lines joined with `\n` per the SSE spec).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SseFrame {
    pub event: Option<String>,
    pub data: String,
}

/// Per-frame usage counters AS REPORTED BY THAT FRAME. Cross-frame
/// semantics live in [`SseUsageFold`]: every counter is a snapshot with
/// last-write-wins folding — Anthropic's `message_delta.output_tokens` is a
/// cumulative snapshot (never an increment), and OpenAI Chat / Responses
/// report totals exactly once on the terminal frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SseUsage {
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
}

/// Normalized per-frame parse result (MODULE-009 §2.3 `SseEvent`).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SseEvent {
    /// Incremental text fragment. NEVER `Some("")` — empty and keep-alive
    /// frames normalize to [`SseEvent::IGNORE`] (MODULE-009-AC-21).
    pub delta: Option<String>,
    /// Usage counters reported by this frame (see [`SseUsage`]).
    pub usage: Option<SseUsage>,
    /// Finish/stop reason when this frame carries one (closed passthrough
    /// set per backend; never free-form upstream error text).
    pub finish_reason: Option<String>,
    /// True exactly when this frame ends the stream.
    pub terminal: bool,
}

impl SseEvent {
    /// The ignorable frame: no delta, no usage, no finish, non-terminal.
    pub const IGNORE: SseEvent = SseEvent {
        delta: None,
        usage: None,
        finish_reason: None,
        terminal: false,
    };

    pub fn is_ignore(&self) -> bool {
        *self == Self::IGNORE
    }
}

/// Cross-frame usage folding (MODULE-009-AC-21 witness surface): counters
/// are snapshots folded LAST-WRITE-WINS — NEVER summed. Anthropic reporting
/// cumulative `output_tokens` of 10, 50, 120 folds to 120 (not 180); the
/// terminal-only totals of OpenAI Chat / Responses fold trivially the same
/// way. Clamping of the FINAL cumulative value (never per-frame) is the
/// caller's job (gateway `MAX_TOKENS_PER_ATTEMPT` discipline, S4).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SseUsageFold {
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
}

impl SseUsageFold {
    pub fn apply(&mut self, event: &SseEvent) {
        if let Some(usage) = event.usage {
            if let Some(input) = usage.input_tokens {
                self.input_tokens = Some(input);
            }
            if let Some(output) = usage.output_tokens {
                self.output_tokens = Some(output);
            }
        }
    }

    /// True iff ANY usage counter was ever observed across the folded frames.
    ///
    /// COARSE presence predicate — a convenience for S4, NOT the whole floor.
    /// The backends report the two counters in SEPARATE frames (Anthropic
    /// sends `input_tokens` early via `message_start` and `output_tokens` late
    /// via `message_delta`), so `any_usage_seen()` can be `true` on
    /// `input_tokens` alone while `output_tokens` never arrived. The S4
    /// accounting loop (ADR 2026-07-22 D2) MUST therefore floor PER COUNTER
    /// via the public `input_tokens` / `output_tokens` fields — a terminal
    /// with output deltas delivered but `output_tokens == None` is fail-CLOSED
    /// (bill a conservative byte-derived upper bound, never coerce to 0).
    /// Exposed here (S2) so the S4 consumer cannot silently skip the floor.
    pub fn any_usage_seen(&self) -> bool {
        self.input_tokens.is_some() || self.output_tokens.is_some()
    }
}

/// Incremental SSE frame splitter. Push raw transport chunks; completed
/// frames come back in arrival order. Pure and synchronous.
pub struct FrameSplitter {
    buf: Vec<u8>,
    bom_checked: bool,
}

impl FrameSplitter {
    pub fn new() -> Self {
        Self {
            buf: Vec::new(),
            bom_checked: false,
        }
    }

    /// Push one transport chunk; returns every frame COMPLETED by it.
    ///
    /// The one-time BOM strip waits until 3 bytes have arrived so a BOM
    /// split across chunks is still caught. Oversized frames fail CLOSED
    /// with a static reason.
    pub fn push(&mut self, chunk: &[u8]) -> Result<Vec<SseFrame>, LlmError> {
        self.buf.extend_from_slice(chunk);
        if !self.bom_checked && self.buf.len() >= 3 {
            if self.buf.starts_with(&[0xEF, 0xBB, 0xBF]) {
                self.buf.drain(..3);
            }
            self.bom_checked = true;
        }
        let mut frames = Vec::new();
        while let Some((block_end, dispatch_end)) = find_frame_boundary(&self.buf) {
            // Enforce the cap on the COMPLETED frame block BEFORE assembling
            // it — a terminated frame larger than the cap must fail CLOSED,
            // not be assembled into one giant `SseFrame` (heap-amplification
            // vector if a live transport hands us a ≥cap single chunk).
            if block_end > MAX_FRAME_BYTES {
                // Fail CLOSED and DROP the oversized bytes — do not retain a
                // multi-hundred-KiB attacker-controlled buffer past the error.
                self.buf.clear();
                return Err(LlmError::ProviderError(
                    "sse frame exceeds size limit".into(),
                ));
            }
            let raw: Vec<u8> = self.buf.drain(..dispatch_end).collect();
            if let Some(frame) = assemble(&raw[..block_end]) {
                frames.push(frame);
            }
        }
        // Unterminated accumulation across pushes is bounded by the same cap.
        if self.buf.len() > MAX_FRAME_BYTES {
            self.buf.clear();
            return Err(LlmError::ProviderError(
                "sse frame exceeds size limit".into(),
            ));
        }
        Ok(frames)
    }
}

impl Default for FrameSplitter {
    fn default() -> Self {
        Self::new()
    }
}

/// Find the earliest blank-line dispatch point: returns
/// `(block_end, dispatch_end)` where `buf[..block_end]` is the frame block
/// and `buf[..dispatch_end]` consumes the blank line too. Tolerates `\n\n`,
/// `\n\r\n`, and `\r\n\r\n` (the middle of which is `\n\r\n`).
fn find_frame_boundary(buf: &[u8]) -> Option<(usize, usize)> {
    let mut i = 0;
    while i < buf.len() {
        if buf[i] == b'\n' {
            let mut j = i + 1;
            if j < buf.len() && buf[j] == b'\r' {
                j += 1;
            }
            if j < buf.len() && buf[j] == b'\n' {
                return Some((i, j + 1));
            }
        }
        i += 1;
    }
    None
}

/// Assemble one frame block into an [`SseFrame`]. Comment lines (leading
/// `:`) and unknown fields (`id:`, `retry:`, …) are ignored per the SSE
/// spec; multiple `data:` lines join with `\n`; an all-comment/empty block
/// yields `None` (nothing to dispatch).
fn assemble(block: &[u8]) -> Option<SseFrame> {
    let text = String::from_utf8_lossy(block);
    let mut event: Option<String> = None;
    let mut data_lines: Vec<&str> = Vec::new();
    for raw_line in text.split('\n') {
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        if line.is_empty() || line.starts_with(':') {
            continue;
        }
        if let Some(value) = line.strip_prefix("event:") {
            event = Some(value.strip_prefix(' ').unwrap_or(value).to_string());
        } else if let Some(value) = line.strip_prefix("data:") {
            data_lines.push(value.strip_prefix(' ').unwrap_or(value));
        }
    }
    if event.is_none() && data_lines.is_empty() {
        return None;
    }
    Some(SseFrame {
        event,
        data: data_lines.join("\n"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frames_of(splitter: &mut FrameSplitter, chunk: &[u8]) -> Vec<SseFrame> {
        splitter.push(chunk).expect("push must succeed")
    }

    /// MODULE-009-T117 (splitter leg) — BOM stripped once, even split
    /// across the first two chunks.
    #[test]
    fn t117_bom_stripped_across_chunk_boundary() {
        let mut s = FrameSplitter::new();
        assert!(frames_of(&mut s, &[0xEF, 0xBB]).is_empty());
        let frames = frames_of(&mut s, b"\xBFdata: hi\n\n");
        assert_eq!(
            frames,
            vec![SseFrame {
                event: None,
                data: "hi".into()
            }]
        );
    }

    /// MODULE-009-T117 (splitter leg) — event:/data: assembly, multi-data
    /// join, comment lines ignored, CRLF tolerated, frames split across
    /// arbitrary chunk boundaries.
    #[test]
    fn t117_event_data_assembly_and_chunk_splits() {
        let mut s = FrameSplitter::new();
        let mut all = Vec::new();
        for chunk in [
            &b"event: message_start\r\ndata: {\"a\":"[..],
            &b"1}\r\n\r\n: keep-alive comment\n\ndata: line1\ndata: line2\n"[..],
            &b"\n"[..],
        ] {
            all.extend(frames_of(&mut s, chunk));
        }
        assert_eq!(
            all,
            vec![
                SseFrame {
                    event: Some("message_start".into()),
                    data: "{\"a\":1}".into()
                },
                SseFrame {
                    event: None,
                    data: "line1\nline2".into()
                },
            ]
        );
    }

    /// MODULE-009-T117 (splitter leg) — an unterminated frame larger than
    /// the cap fails CLOSED with the static reason (no upstream bytes).
    #[test]
    fn t117_oversized_frame_fails_closed_static() {
        let mut s = FrameSplitter::new();
        let big = vec![b'a'; MAX_FRAME_BYTES + 1];
        match s.push(&big) {
            Err(LlmError::ProviderError(msg)) => {
                assert_eq!(msg, "sse frame exceeds size limit");
            }
            other => panic!("expected static ProviderError, got {other:?}"),
        }
    }

    /// MODULE-009-T117 (splitter leg) — a COMPLETED (blank-line-terminated)
    /// frame larger than the cap in a single push ALSO fails CLOSED before
    /// assembly, not just the unterminated path (audit round-1 fix).
    #[test]
    fn t117_completed_oversized_frame_fails_closed() {
        let mut s = FrameSplitter::new();
        let mut chunk = Vec::with_capacity(MAX_FRAME_BYTES + 16);
        chunk.extend_from_slice(b"data: ");
        chunk.extend(std::iter::repeat(b'a').take(MAX_FRAME_BYTES + 1));
        chunk.extend_from_slice(b"\n\n"); // terminates the frame in ONE push
        match s.push(&chunk) {
            Err(LlmError::ProviderError(msg)) => {
                assert_eq!(msg, "sse frame exceeds size limit");
            }
            other => panic!("expected fail-closed on completed oversized frame, got {other:?}"),
        }
    }

    /// MODULE-009-T117 — cumulative usage folds LAST-WRITE-WINS, never
    /// summed: 10, 50, 120 → 120 (the Anthropic message_delta shape).
    #[test]
    fn t117_usage_fold_last_write_wins_never_summed() {
        let mut fold = SseUsageFold::default();
        for cumulative in [10u64, 50, 120] {
            fold.apply(&SseEvent {
                usage: Some(SseUsage {
                    input_tokens: None,
                    output_tokens: Some(cumulative),
                }),
                ..SseEvent::IGNORE
            });
        }
        assert_eq!(fold.output_tokens, Some(120), "must replace, never sum");
        // input_tokens set once (message_start shape) survives later frames.
        let mut fold2 = SseUsageFold::default();
        fold2.apply(&SseEvent {
            usage: Some(SseUsage {
                input_tokens: Some(7),
                output_tokens: None,
            }),
            ..SseEvent::IGNORE
        });
        fold2.apply(&SseEvent {
            usage: Some(SseUsage {
                input_tokens: None,
                output_tokens: Some(3),
            }),
            ..SseEvent::IGNORE
        });
        assert_eq!(
            (fold2.input_tokens, fold2.output_tokens),
            (Some(7), Some(3))
        );
    }

    /// MODULE-009-T117 (adversarial round-7) — the usage-floor guard: a fold
    /// that never saw usage reports `any_usage_seen() == false` (S4 must
    /// fail-closed, never bill zero); any observed counter flips it true.
    #[test]
    fn t117_usage_floor_guard() {
        let mut fold = SseUsageFold::default();
        assert!(
            !fold.any_usage_seen(),
            "empty fold must report no usage seen"
        );
        // deltas without usage do not flip the floor
        fold.apply(&SseEvent {
            delta: Some("hi".into()),
            ..SseEvent::IGNORE
        });
        assert!(!fold.any_usage_seen());
        // one output counter flips it
        fold.apply(&SseEvent {
            usage: Some(SseUsage {
                input_tokens: None,
                output_tokens: Some(5),
            }),
            ..SseEvent::IGNORE
        });
        assert!(fold.any_usage_seen());
    }

    /// MODULE-009-T117 (adversarial round-7) — an oversized frame error DROPS
    /// the buffered bytes (no multi-hundred-KiB retention past the error).
    #[test]
    fn t117_oversized_error_clears_buffer() {
        let mut s = FrameSplitter::new();
        let big = vec![b'a'; MAX_FRAME_BYTES + 1];
        assert!(s.push(&big).is_err());
        assert_eq!(
            s.buf.len(),
            0,
            "buffer must be cleared on the size-cap error"
        );
    }

    /// SseEvent::IGNORE round-trip sanity: default == IGNORE, is_ignore.
    #[test]
    fn t117_ignore_is_default_and_detectable() {
        assert!(SseEvent::default().is_ignore());
        assert!(SseEvent::IGNORE.is_ignore());
        assert!(!SseEvent {
            terminal: true,
            ..SseEvent::IGNORE
        }
        .is_ignore());
    }
}

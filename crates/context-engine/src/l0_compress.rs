//! AC-07 — L0 pure compression (§1.3.4 / PRD §11.3.3).
//!
//! Runs after each LLM call, in-TurnBuffer. Pure function: no I/O, no deps,
//! deterministic. Three ordered steps over a `&[L0Entry]`:
//!
//! - **Step A — Dedup**: the same file read twice → the *older* read is
//!   annotated `Superseded`.
//! - **Step B — Invalidate**: a `Write(path)` invalidates every *prior*
//!   still-`Keep` `Read(path)` (its observed content is stale after the
//!   write). The read AFTER the write stays `Keep` (current).
//! - **Step C — Skeleton extract**: an `Invalid` entry that has a same-turn
//!   `Assistant` conclusion is collapsed to `Skeleton { tool, args,
//!   conclusion }` (`tool(key_args)` + the assistant's first sentence). An
//!   `Invalid` entry with NO same-turn assistant stays `Invalid` (we cannot
//!   build a meaningful skeleton without the conclusion; keep the demotion
//!   marker so the loader drops it to digest-only). This same-turn-assistant
//!   gate is the documented Slice-B reading of §1.3.4 Step C — it makes T09
//!   (`Invalid`, no assistant) and T10 (`Skeleton`, assistant present) both
//!   well-defined.
//!
//! **Turn-boundary signal**: [`L0Entry`] carries an explicit `turn_id: u64`.
//! Skeleton-extract sources its `conclusion` from the *same `turn_id`*
//! assistant entry — turn membership is data, NOT inferred from buffer
//! interleaving.

/// One TurnBuffer entry handed to [`l0_compress`].
#[derive(Clone, Debug, PartialEq)]
pub struct L0Entry {
    /// Explicit turn-boundary signal. Skeleton-extract pairs an `Invalid`
    /// entry with the `Assistant` entry of the SAME `turn_id`.
    pub turn_id: u64,
    pub kind: L0Kind,
}

/// The shape of a single buffer entry.
#[derive(Clone, Debug, PartialEq)]
pub enum L0Kind {
    /// A file read (canonically the `fs.read` tool). `Superseded`/`Invalid`
    /// candidates are `Read` entries.
    Read { path: String },
    /// A file write. Invalidates prior same-path `Read`s.
    Write { path: String },
    /// A generic tool call (non-read/write). Carried for skeleton rendering
    /// of invalidated tool calls.
    ToolUse {
        name: String,
        /// `(key, value)` pairs; rendered as `k=v` joined by `, ` in the
        /// skeleton, sorted by key for determinism.
        args: Vec<(String, String)>,
    },
    /// An assistant message. Its first sentence is the skeleton `conclusion`
    /// for same-`turn_id` invalid entries.
    Assistant { text: String },
}

/// Per-entry compression verdict (parallel to the input slice by index).
#[derive(Clone, Debug, PartialEq)]
pub enum L0Action {
    /// Retain verbatim.
    Keep,
    /// Older duplicate read — superseded by a later read of the same path.
    Superseded,
    /// Read whose content is stale (a later `Write` to the same path
    /// occurred) and which has no same-turn assistant conclusion to collapse.
    Invalid,
    /// Collapsed form of an invalidated entry that DOES have a same-turn
    /// assistant conclusion.
    Skeleton {
        tool: String,
        args: String,
        conclusion: String,
    },
}

/// Compute the per-entry [`L0Action`] vector for `entries`. Output length ==
/// input length; `out[i]` is the verdict for `entries[i]`.
pub fn l0_compress(entries: &[L0Entry]) -> Vec<L0Action> {
    let mut actions = vec![L0Action::Keep; entries.len()];

    // ── Step B FIRST — Invalidate: each Write(path) invalidates every PRIOR
    // still-Keep Read(path) (its observed content is stale after the write).
    // Invalidate runs before dedup so that `Read(a), Write(a), Read(a)`
    // resolves idx0 → Invalid (stale across a write) rather than Superseded
    // (a redundant re-read) — the write is the stronger, more specific
    // reason. The read AFTER the write stays Keep (current content).
    for (i, e) in entries.iter().enumerate() {
        if let L0Kind::Write { path } = &e.kind {
            for (j, prior) in entries.iter().enumerate().take(i) {
                if let L0Kind::Read { path: rp } = &prior.kind {
                    if rp == path && actions[j] == L0Action::Keep {
                        actions[j] = L0Action::Invalid;
                    }
                }
            }
        }
    }

    // ── Step A SECOND — Dedup: a later Read(path) supersedes the most-recent
    // prior Read(path) ONLY IF that prior read is still `Keep` (a true
    // redundant re-read with no intervening write). A prior read already
    // `Invalid` (Step B) is left alone — it is dropped for the stronger
    // "stale across a write" reason, not the weaker "duplicate" one. This is
    // what makes `Read(a),Read(b),Read(a)` (no write) → idx0 Superseded but
    // `Read(a),Write(a),Read(a)` → idx0 Invalid.
    {
        use std::collections::HashMap;
        let mut last_keep_read: HashMap<&str, usize> = HashMap::new();
        for (i, e) in entries.iter().enumerate() {
            if let L0Kind::Read { path } = &e.kind {
                if let Some(&prev) = last_keep_read.get(path.as_str()) {
                    if actions[prev] == L0Action::Keep {
                        actions[prev] = L0Action::Superseded;
                    }
                }
                // Only track THIS read as the dedup anchor if it is itself
                // still Keep (an Invalid current-read can't be superseded by
                // a future read anyway, and shouldn't anchor one).
                if actions[i] == L0Action::Keep {
                    last_keep_read.insert(path.as_str(), i);
                } else {
                    last_keep_read.remove(path.as_str());
                }
            }
        }
    }

    // ── Step C — Skeleton extract: an Invalid entry with a same-turn_id
    // Assistant conclusion collapses to Skeleton{tool,args,conclusion}.
    // Without a same-turn assistant it stays Invalid.
    for i in 0..entries.len() {
        if actions[i] != L0Action::Invalid {
            continue;
        }
        let turn_id = entries[i].turn_id;
        let conclusion = entries
            .iter()
            .find(|e| e.turn_id == turn_id && matches!(e.kind, L0Kind::Assistant { .. }))
            .and_then(|e| match &e.kind {
                L0Kind::Assistant { text } => Some(first_sentence(text)),
                _ => None,
            });
        let Some(conclusion) = conclusion else {
            continue; // no same-turn assistant → stays Invalid
        };
        let (tool, args) = match &entries[i].kind {
            L0Kind::Read { path } => ("fs.read".to_string(), format!("path={path}")),
            L0Kind::ToolUse { name, args } => {
                let mut kv: Vec<(String, String)> = args.clone();
                kv.sort_by(|a, b| a.0.cmp(&b.0)); // deterministic ordering
                let joined = kv
                    .iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect::<Vec<_>>()
                    .join(", ");
                (name.clone(), joined)
            }
            // Write/Assistant are never marked Invalid by Step B, so these
            // arms are unreachable in practice; render defensively rather
            // than panic.
            L0Kind::Write { path } => ("fs.write".to_string(), format!("path={path}")),
            L0Kind::Assistant { .. } => ("assistant".to_string(), String::new()),
        };
        actions[i] = L0Action::Skeleton {
            tool,
            args,
            conclusion,
        };
    }

    actions
}

/// First sentence of `text`: everything up to and including the first ASCII
/// `.`/`!`/`?`, trimmed. If there is no terminator, the whole trimmed string.
/// Bounded per-turn scope — never reads beyond one entry's text.
fn first_sentence(text: &str) -> String {
    let trimmed = text.trim();
    for (idx, ch) in trimmed.char_indices() {
        if matches!(ch, '.' | '!' | '?') {
            // include the terminator
            let end = idx + ch.len_utf8();
            return trimmed[..end].trim().to_string();
        }
    }
    trimmed.to_string()
}

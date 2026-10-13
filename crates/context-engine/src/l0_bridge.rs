//! L0 bridge — maps `AssemblyContext.turn_buffer` (`LlmMessage { role, content }`)
//! onto [`L0Entry`]s, runs the AC-07 [`l0_compress`] pass and applies the
//! verdicts back onto the history slice the assembler renders in Tier 3.
//!
//! `LlmMessage` carries no tool typing, so the mapping is a conservative
//! heuristic over the two shapes a host-side turn buffer can carry:
//!
//! - `role == "assistant"` → [`L0Kind::Assistant`] (its first sentence is the
//!   skeleton conclusion for same-turn invalidated reads).
//! - `role == "tool"` whose content is EITHER a JSON object
//!   `{"tool": "fs.read", "path": "…"}` / `{"tool": "<name>", "args": {…}}`
//!   OR a first line `fs.read <path>` / `fs.write <path>` / `<name> k=v …` →
//!   the matching [`L0Kind`]. Anything else is NOT an entry (left verbatim).
//! - `role == "user"` starts a new turn (`turn_id` increments); other roles are
//!   carried verbatim.
//!
//! Applying the verdicts: `Superseded` / `Invalid` entries are DROPPED from the
//! rendered history (their content is stale or redundant); a `Skeleton` entry is
//! REPLACED by its one-line skeleton (`[tool(args)] → conclusion`); `Keep`
//! entries and unmapped messages pass through unchanged. Pure, deterministic.

use advance_shared_types::context::LlmMessage;

use crate::l0_compress::{l0_compress, L0Action, L0Entry, L0Kind};

/// Max bytes of a tool message inspected for the heuristic (bounds the parse).
const MAX_TOOL_PARSE_BYTES: usize = 4096;

/// Map `messages` onto `(message_index, L0Entry)` pairs. Messages that do not
/// map to an entry are absent from the output (they pass through untouched).
pub fn l0_entries_from_messages(messages: &[LlmMessage]) -> Vec<(usize, L0Entry)> {
    let mut out = Vec::new();
    let mut turn_id: u64 = 0;
    for (idx, m) in messages.iter().enumerate() {
        match m.role.as_str() {
            "user" => turn_id = turn_id.saturating_add(1),
            "assistant" => out.push((
                idx,
                L0Entry {
                    turn_id,
                    kind: L0Kind::Assistant {
                        text: m.content.clone(),
                    },
                },
            )),
            "tool" | "function" => {
                if let Some(kind) = parse_tool_message(&m.content) {
                    out.push((idx, L0Entry { turn_id, kind }));
                }
            }
            _ => {}
        }
    }
    out
}

/// Run [`l0_compress`] over the mapped entries and apply the verdicts to
/// `messages`. Returns the compressed history plus the number of entries
/// L0 dropped or collapsed (telemetry).
pub fn compress_turn_buffer(messages: &[LlmMessage]) -> (Vec<LlmMessage>, usize) {
    let mapped = l0_entries_from_messages(messages);
    if mapped.is_empty() {
        return (messages.to_vec(), 0);
    }
    let entries: Vec<L0Entry> = mapped.iter().map(|(_, e)| e.clone()).collect();
    let actions = l0_compress(&entries);
    let mut verdict: Vec<Option<&L0Action>> = vec![None; messages.len()];
    for ((idx, _), action) in mapped.iter().zip(actions.iter()) {
        verdict[*idx] = Some(action);
    }
    let mut compressed = 0usize;
    let mut out = Vec::with_capacity(messages.len());
    for (idx, m) in messages.iter().enumerate() {
        match verdict[idx] {
            None | Some(L0Action::Keep) => out.push(m.clone()),
            Some(L0Action::Superseded) | Some(L0Action::Invalid) => compressed += 1,
            Some(L0Action::Skeleton {
                tool,
                args,
                conclusion,
            }) => {
                compressed += 1;
                out.push(LlmMessage {
                    role: m.role.clone(),
                    content: format!("[{tool}({args})] → {conclusion}"),
                });
            }
        }
    }
    (out, compressed)
}

/// Heuristic tool-message parser (see module docs). `None` → not an L0 entry.
fn parse_tool_message(content: &str) -> Option<L0Kind> {
    let head = if content.len() > MAX_TOOL_PARSE_BYTES {
        let mut end = MAX_TOOL_PARSE_BYTES;
        while end > 0 && !content.is_char_boundary(end) {
            end -= 1;
        }
        &content[..end]
    } else {
        content
    };
    let trimmed = head.trim_start();
    if trimmed.starts_with('{') {
        return parse_tool_json(head);
    }
    let first_line = trimmed.lines().next()?.trim();
    let mut parts = first_line.split_whitespace();
    let name = parts.next()?;
    // A tool name is an identifier (`fs.read`, `web_search`, `mcp:server__tool`);
    // prose never is.
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ':' | '-'))
    {
        return None;
    }
    let rest: Vec<&str> = parts.collect();
    let kv = kv_pairs(&rest);
    if is_read_write_name(name) {
        // `fs.read <path>` / `fs.write path=<path>` — exactly one argument.
        if rest.len() != 1 {
            return None;
        }
    } else if rest.is_empty() || kv.len() != rest.len() {
        // A generic call needs `k=v` arguments only — a bare word or free prose
        // (`free text that …`) is not a tool call.
        return None;
    }
    tool_kind(name, rest.first().copied(), &kv)
}

fn is_read_write_name(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "fs.read"
            | "read"
            | "read_file"
            | "fs.read_file"
            | "fs.write"
            | "write"
            | "write_file"
            | "fs.write_file"
    )
}

fn parse_tool_json(content: &str) -> Option<L0Kind> {
    let v: serde_json::Value = serde_json::from_str(content.trim()).ok()?;
    let obj = v.as_object()?;
    let name = obj
        .get("tool")
        .or_else(|| obj.get("name"))
        .and_then(|t| t.as_str())?;
    let path = obj.get("path").and_then(|p| p.as_str());
    let mut args: Vec<(String, String)> = Vec::new();
    if let Some(a) = obj.get("args").and_then(|a| a.as_object()) {
        for (k, val) in a {
            let s = match val {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            args.push((k.clone(), s));
        }
    }
    let path = path.or_else(|| {
        args.iter()
            .find(|(k, _)| k == "path")
            .map(|(_, v)| v.as_str())
    });
    tool_kind(name, path, &args)
}

fn kv_pairs(tokens: &[&str]) -> Vec<(String, String)> {
    tokens
        .iter()
        .filter_map(|t| t.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn tool_kind(name: &str, path: Option<&str>, args: &[(String, String)]) -> Option<L0Kind> {
    let lname = name.to_ascii_lowercase();
    let path = path
        .map(|p| p.trim_start_matches("path=").to_string())
        .filter(|p| !p.is_empty());
    match lname.as_str() {
        "fs.read" | "read" | "read_file" | "fs.read_file" => Some(L0Kind::Read { path: path? }),
        "fs.write" | "write" | "write_file" | "fs.write_file" => {
            Some(L0Kind::Write { path: path? })
        }
        _ if lname.is_empty() => None,
        _ => Some(L0Kind::ToolUse {
            name: name.to_string(),
            args: args.to_vec(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(role: &str, content: &str) -> LlmMessage {
        LlmMessage {
            role: role.into(),
            content: content.into(),
        }
    }

    #[test]
    fn plain_chat_history_passes_through_unchanged() {
        let history = vec![
            msg("user", "hi"),
            msg("assistant", "hello."),
            msg("user", "more"),
        ];
        let (out, n) = compress_turn_buffer(&history);
        assert_eq!(out, history);
        assert_eq!(n, 0);
    }

    #[test]
    fn maps_json_and_line_tool_messages() {
        let entries = l0_entries_from_messages(&[
            msg("user", "q"),
            msg("tool", r#"{"tool":"fs.read","path":"a.rs"}"#),
            msg("tool", "fs.write a.rs"),
            msg("tool", "search q=rust limit=3"),
            msg("tool", "free text that is not a tool call"),
            msg("assistant", "Done. More."),
        ]);
        assert_eq!(entries.len(), 4);
        assert_eq!(
            entries[0].1.kind,
            L0Kind::Read {
                path: "a.rs".into()
            }
        );
        assert_eq!(
            entries[1].1.kind,
            L0Kind::Write {
                path: "a.rs".into()
            }
        );
        assert!(
            matches!(&entries[2].1.kind, L0Kind::ToolUse { name, args } if name == "search" && args.len() == 2)
        );
        assert!(matches!(entries[3].1.kind, L0Kind::Assistant { .. }));
        assert!(entries.iter().all(|(_, e)| e.turn_id == 1));
    }

    #[test]
    fn superseded_read_is_dropped_and_invalid_read_becomes_skeleton() {
        let history = vec![
            msg("user", "q"),
            msg("tool", "fs.read a.rs"), // superseded by the later re-read → dropped
            msg("tool", "fs.read b.rs"), // invalidated by the write below, same turn → skeleton
            msg("tool", "fs.write b.rs"),
            msg("tool", "fs.read a.rs"), // the current read → kept
            msg("assistant", "Edited b. Then more."),
        ];
        let (out, n) = compress_turn_buffer(&history);
        assert_eq!(n, 2, "one dropped + one skeleton");
        let contents: Vec<&str> = out.iter().map(|m| m.content.as_str()).collect();
        assert_eq!(
            contents,
            vec![
                "q",
                "[fs.read(path=b.rs)] → Edited b.",
                "fs.write b.rs",
                "fs.read a.rs",
                "Edited b. Then more.",
            ]
        );
    }

    #[test]
    fn turn_id_increments_per_user_message() {
        let entries = l0_entries_from_messages(&[
            msg("user", "1"),
            msg("assistant", "a"),
            msg("user", "2"),
            msg("assistant", "b"),
        ]);
        assert_eq!(entries[0].1.turn_id, 1);
        assert_eq!(entries[1].1.turn_id, 2);
    }
}

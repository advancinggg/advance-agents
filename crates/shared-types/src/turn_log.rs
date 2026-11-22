//! The turn log and the L0 annotation of a turn transcript (MODULE-010 / MODULE-011, PRD §11.2,
//! §11.3.3, §11.4).
//!
//! - **The transcript** ([`TranscriptMessage`]) is what the host recorded of one turn: the
//!   model's replies, the tool calls they carry and the results of those calls (ADR 2026-10-24
//!   D4). The gateway that recorded it hands it to the post-processor through
//!   [`TurnTranscriptSource`].
//! - **The turn log** (`llm-turns.jsonl`, [`TURN_LOG_FILENAME`]) is the task's append-only raw
//!   record of every turn, one [`TurnLogLine`] per message. It is never loaded into a context as
//!   it stands: every load goes through the L0 view (PRD §11.3.3 "所有加载都经过 L0 处理").
//! - **The L0 annotation** ([`annotate_transcript`]) is pure and rule-based (PRD §11.3.3):
//!   Step A marks an older read of a file a later read replaces; Step B marks a read a later
//!   write of the same file made stale; Step C collapses a stale read to `tool(key_args)` plus
//!   the model's next conclusion. A message keeps its role and its tool-call id in every view,
//!   so a provider never sees an orphan tool result.

use std::borrow::Cow;
use std::collections::HashMap;
use std::io::Read;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};

use crate::workspace_path::normalize_workspace_path;

/// The file each task directory logs its turns in (PRD §11.2).
pub const TURN_LOG_FILENAME: &str = "llm-turns.jsonl";

/// The longest content one log line keeps, in bytes. A longer message is cut at a character
/// boundary and the line is marked [`TurnLogLine::truncated`].
pub const MAX_LOGGED_CONTENT_BYTES: usize = 256 * 1024;

/// The most bytes of a conclusion a skeleton keeps.
const MAX_CONCLUSION_BYTES: usize = 240;

/// A file larger than this is not hashed: no version of it is recorded, and a recorded one
/// no longer matches.
pub const MAX_VERSIONED_FILE_BYTES: u64 = 16 * 1024 * 1024;

/// One message of a turn transcript.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranscriptMessage {
    /// `user` | `assistant` | `tool` | `system`.
    pub role: String,
    #[serde(default)]
    pub content: String,
    /// The calls an assistant message makes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tool_calls: Vec<TranscriptToolCall>,
    /// The call a `tool` message answers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
    /// A `tool` message is the result of a call that failed: the dispatcher refused it, or it
    /// ended in an error. Such a call read and changed nothing, so the L0 rules pass it by.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub is_error: bool,
}

impl TranscriptMessage {
    pub fn new(role: &str, content: impl Into<String>) -> Self {
        Self {
            role: role.to_string(),
            content: content.into(),
            ..Default::default()
        }
    }
}

/// One tool call of an assistant message.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranscriptToolCall {
    pub id: String,
    pub name: String,
    /// The arguments as the model sent them (a JSON object, as text).
    #[serde(default)]
    pub arguments: String,
}

/// The transcript of the turn that just ran, for the post-processor (PRD §11.4: the turn log
/// is written as soon as `handle-message` returns).
pub trait TurnTranscriptSource: Send + Sync {
    /// The messages `agent_id`'s last turn recorded on the host, oldest first: the model's
    /// replies with their tool calls, and the results of those calls (a failed call's marked
    /// [`TranscriptMessage::is_error`]). The inbound prompt is there only when the guest sent
    /// it as a prompt the context did not already carry. Taking it empties it: a turn is
    /// logged once.
    fn take_turn_transcript(&self, agent_id: &str) -> Vec<TranscriptMessage>;
}

/// What a tool call does to a file, as the L0 rules see it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FileTouch {
    Read(String),
    Write(String),
}

/// The file a tool call reads or writes. The host fs callables the model sees are named `read`,
/// `write` and `delete` and take a workspace `path` (runtime-compose `register_fs_callables`);
/// the `fs.` / `fs_` spellings are accepted too. A call with no string `path`, or any other
/// call, touches no file. The path is the one the callables read ([`touch_path`]), so
/// `notes/a.md` and `/notes/a.md` are one file.
pub fn file_touch(call: &TranscriptToolCall) -> Option<FileTouch> {
    let name = call
        .name
        .strip_prefix("fs.")
        .or_else(|| call.name.strip_prefix("fs_"))
        .unwrap_or(&call.name);
    let path = touch_path(
        serde_json::from_str::<serde_json::Value>(&call.arguments)
            .ok()?
            .get("path")?
            .as_str()?,
    )?;
    match name {
        "read" => Some(FileTouch::Read(path)),
        "write" | "delete" => Some(FileTouch::Write(path)),
        _ => None,
    }
}

/// The workspace path `raw` names, as the L0 rules compare it: trimmed, without the leading
/// `/` the fs callables read as the workspace root, in the NFC form every workspace path takes
/// ([`normalize_workspace_path`]). A path the callables would refuse is compared as written
/// (its call failed, so it touches nothing anyway). `None` for a blank path.
fn touch_path(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.trim_start_matches('/').is_empty() {
        return None;
    }
    Some(
        normalize_workspace_path(raw.trim_start_matches('/'), false)
            .unwrap_or_else(|_| raw.to_string()),
    )
}

/// The call each message of a turn answers, index for index: a `tool` message answers the
/// first call of the nearest assistant message before it that carries its `tool_call_id` and
/// that no earlier result answered — the pairing the gateway records a result with — and every
/// other message answers none. Call ids are a provider's: some number them afresh in every
/// reply, so an id names a call only within its assistant message.
pub fn answered_calls(messages: &[TranscriptMessage]) -> Vec<Option<&TranscriptToolCall>> {
    // The calls of the latest assistant message, and whether a result answered each yet.
    let mut open: Vec<(&TranscriptToolCall, bool)> = Vec::new();
    messages
        .iter()
        .map(|m| match m.role.as_str() {
            "assistant" => {
                open = m.tool_calls.iter().map(|c| (c, false)).collect();
                None
            }
            "tool" => {
                let id = m.tool_call_id.as_deref()?;
                let (call, answered) = open
                    .iter_mut()
                    .find(|(call, answered)| !*answered && call.id == id)?;
                *answered = true;
                Some(*call)
            }
            _ => None,
        })
        .collect()
}

/// The L0 verdict on one transcript message (PRD §11.3.3).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum L0Mark {
    /// Loaded as it stands.
    #[default]
    Keep,
    /// Step A: an older read of `path` a later read in the same turn replaces.
    Superseded { path: String },
    /// Step B: a read of `path` a later write in the same turn made stale, with no conclusion
    /// after it to collapse to.
    Invalid { path: String },
    /// Step C: a stale read collapsed to its call and the model's next conclusion.
    Skeleton { view: String },
}

impl L0Mark {
    pub fn is_keep(&self) -> bool {
        matches!(self, L0Mark::Keep)
    }
}

/// The L0 verdict on every message of a turn, in order (`out[i]` is `messages[i]`'s).
///
/// Only the result of a file read is ever marked; every other message is `Keep`. A result
/// belongs to the call [`answered_calls`] pairs it with, and the result of a call that failed
/// ([`TranscriptMessage::is_error`]) neither reads nor writes: a refused write leaves the read
/// before it alone, and a failed read replaces nothing.
/// 1. Step B first: a write (or delete) of a file marks every earlier still-kept read of it
///    `Invalid` — the stronger reason, so `read a, write a, read a` leaves the first read stale
///    rather than superseded, and the read after the write is kept.
/// 2. Step A: a read of a file marks the previous still-kept read of it `Superseded`.
/// 3. Step C: an `Invalid` read with an assistant message after it that says something becomes
///    a `Skeleton`: `tool(path=…) → <the first sentence of that message>`.
pub fn annotate_transcript(messages: &[TranscriptMessage]) -> Vec<L0Mark> {
    // The file each tool result touches: none for a call that failed.
    let touches: Vec<Option<(FileTouch, &TranscriptToolCall)>> = messages
        .iter()
        .zip(answered_calls(messages))
        .map(|(m, call)| {
            let call = call.filter(|_| !m.is_error)?;
            file_touch(call).map(|t| (t, call))
        })
        .collect();
    let mut marks = vec![L0Mark::Keep; messages.len()];

    // Step B.
    for (i, touch) in touches.iter().enumerate() {
        let Some((FileTouch::Write(written), _)) = touch else {
            continue;
        };
        for j in 0..i {
            if let Some((FileTouch::Read(read), _)) = &touches[j] {
                if read == written && marks[j].is_keep() {
                    marks[j] = L0Mark::Invalid { path: read.clone() };
                }
            }
        }
    }
    // Step A.
    let mut last_kept_read: HashMap<&str, usize> = HashMap::new();
    for (i, touch) in touches.iter().enumerate() {
        let Some((FileTouch::Read(path), _)) = touch else {
            continue;
        };
        if let Some(prev) = last_kept_read.get(path.as_str()) {
            if marks[*prev].is_keep() {
                marks[*prev] = L0Mark::Superseded { path: path.clone() };
            }
        }
        if marks[i].is_keep() {
            last_kept_read.insert(path.as_str(), i);
        } else {
            last_kept_read.remove(path.as_str());
        }
    }
    // Step C.
    for i in 0..messages.len() {
        let L0Mark::Invalid { path } = &marks[i] else {
            continue;
        };
        let conclusion = messages[i + 1..]
            .iter()
            .filter(|m| m.role == "assistant")
            .map(|m| first_sentence(&m.content))
            .find(|s| !s.is_empty());
        if let (Some(conclusion), Some((_, call))) = (conclusion, &touches[i]) {
            let view = format!("{}(path={path}) → {conclusion}", call.name);
            marks[i] = L0Mark::Skeleton { view };
        }
    }
    marks
}

/// The content a message carries in the L0 view: its own for `Keep`, else the short text that
/// stands in for it (the message keeps its role and tool-call id).
pub fn l0_content<'a>(message: &'a TranscriptMessage, mark: &'a L0Mark) -> Cow<'a, str> {
    match l0_replacement(mark) {
        Some(text) => Cow::Owned(text),
        None => Cow::Borrowed(message.content.as_str()),
    }
}

/// The short text that stands in for a message in the L0 view, or `None` for a message the view
/// carries as it stands (`Keep`).
pub fn l0_replacement(mark: &L0Mark) -> Option<String> {
    match mark {
        L0Mark::Keep => None,
        L0Mark::Superseded { path } => Some(format!(
            "[superseded: a later read of {path} replaces this result]"
        )),
        L0Mark::Invalid { path } => Some(format!("[stale: {path} was written after this read]")),
        L0Mark::Skeleton { view } => Some(format!("[collapsed] {view}")),
    }
}

/// The first sentence of `text`, trimmed and capped at a character boundary. A `.`, `!` or `?`
/// ends it only before a space or the end of the text, so `notes.md` or `3.5` does not.
pub fn first_sentence(text: &str) -> String {
    let text = text.trim();
    let mut chars = text.char_indices().peekable();
    let mut end = text.len();
    while let Some((i, c)) = chars.next() {
        let ends = match c {
            '\n' | '。' | '！' | '？' => true,
            '.' | '!' | '?' => chars.peek().is_none_or(|(_, next)| next.is_whitespace()),
            _ => false,
        };
        if ends {
            end = i + c.len_utf8();
            break;
        }
    }
    let sentence = text[..end].trim();
    truncate_at_char(sentence, MAX_CONCLUSION_BYTES).to_string()
}

/// `text` cut to at most `max` bytes at a character boundary.
pub fn truncate_at_char(text: &str, max: usize) -> &str {
    if text.len() <= max {
        return text;
    }
    let mut end = max;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// One line of `llm-turns.jsonl`: one message of one turn.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TurnLogLine {
    pub turn: u32,
    /// The message's position in the turn, from 0.
    pub seq: u32,
    /// UTC, RFC 3339.
    pub ts: String,
    #[serde(flatten)]
    pub message: TranscriptMessage,
    #[serde(default, skip_serializing_if = "L0Mark::is_keep")]
    pub l0: L0Mark,
    /// The content was cut at [`MAX_LOGGED_CONTENT_BYTES`].
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub truncated: bool,
}

/// The git blob id of `bytes` (what `git hash-object` prints): the `read_file_versions[*]
/// .blob_id` a turn records for a file it read, and what the stale check compares it with
/// (PRD §11.2.1, §11.3.3 跨 Turn 失效传播).
pub fn git_blob_id(bytes: &[u8]) -> String {
    let mut hasher = Sha1::new();
    hasher.update(format!("blob {}\0", bytes.len()).as_bytes());
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The git blob id of the workspace file `raw` names, as it is now: what a turn records for a
/// file it read, and what the stale check compares that record with. `None` when the path is
/// not a valid workspace path (a leading `/` is the workspace root, as the fs callables read
/// it), the file is missing, is not a regular file (a symlink included), resolves outside
/// `root`, or is larger than [`MAX_VERSIONED_FILE_BYTES`].
pub fn workspace_blob_id(root: &Path, raw: &str) -> Option<String> {
    let rel = normalize_workspace_path(raw.trim_start_matches('/'), false).ok()?;
    let path = root.join(&rel);
    let meta = std::fs::symlink_metadata(&path).ok()?;
    if !meta.file_type().is_file() || meta.len() > MAX_VERSIONED_FILE_BYTES {
        return None;
    }
    let (canon_root, canon) = (root.canonicalize().ok()?, path.canonicalize().ok()?);
    if !canon.starts_with(&canon_root) {
        return None;
    }
    let mut bytes = Vec::new();
    std::fs::File::open(&canon)
        .ok()?
        .take(MAX_VERSIONED_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() as u64 > MAX_VERSIONED_FILE_BYTES {
        return None;
    }
    Some(git_blob_id(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_workspace_file_is_hashed_only_inside_the_workspace() {
        let ws = tempfile::tempdir().unwrap();
        std::fs::write(ws.path().join("a.txt"), b"hello\n").unwrap();
        let hello = Some("ce013625030ba8dba906f756967f9e9ca394464a".to_string());
        assert_eq!(workspace_blob_id(ws.path(), "a.txt"), hello);
        assert_eq!(
            workspace_blob_id(ws.path(), "/a.txt"),
            hello,
            "a leading slash is the workspace root"
        );
        assert_eq!(workspace_blob_id(ws.path(), "missing.txt"), None);
        assert_eq!(workspace_blob_id(ws.path(), "../a.txt"), None);
        assert_eq!(workspace_blob_id(ws.path(), ""), None);
        std::fs::create_dir(ws.path().join("dir")).unwrap();
        assert_eq!(
            workspace_blob_id(ws.path(), "dir"),
            None,
            "a directory has no blob"
        );
        #[cfg(unix)]
        {
            let outside = tempfile::tempdir().unwrap();
            std::fs::write(outside.path().join("s.txt"), b"secret").unwrap();
            std::os::unix::fs::symlink(outside.path().join("s.txt"), ws.path().join("l.txt"))
                .unwrap();
            assert_eq!(
                workspace_blob_id(ws.path(), "l.txt"),
                None,
                "a symlink is not followed"
            );
        }
    }

    fn call(id: &str, name: &str, path: &str) -> TranscriptToolCall {
        TranscriptToolCall {
            id: id.into(),
            name: name.into(),
            arguments: serde_json::json!({ "path": path }).to_string(),
        }
    }

    fn assistant(text: &str, calls: Vec<TranscriptToolCall>) -> TranscriptMessage {
        TranscriptMessage {
            role: "assistant".into(),
            content: text.into(),
            tool_calls: calls,
            ..Default::default()
        }
    }

    fn result(id: &str, content: &str) -> TranscriptMessage {
        TranscriptMessage {
            role: "tool".into(),
            content: content.into(),
            tool_call_id: Some(id.into()),
            ..Default::default()
        }
    }

    /// The result of a call that failed.
    fn failed(id: &str, content: &str) -> TranscriptMessage {
        TranscriptMessage {
            is_error: true,
            ..result(id, content)
        }
    }

    #[test]
    fn a_call_that_failed_reads_and_writes_nothing() {
        let t = vec![
            assistant("", vec![call("c1", "read", "a.md")]),
            result("c1", "A v1"),
            assistant("", vec![call("c2", "write", "a.md")]),
            failed("c2", "[invoke-callable error: permission-denied] read-only"),
            assistant("", vec![call("c3", "read", "a.md")]),
            failed("c3", "[invoke-callable error: io] busy"),
            assistant("The file is unchanged. Done.", vec![]),
        ];
        let marks = annotate_transcript(&t);
        assert!(
            marks.iter().all(L0Mark::is_keep),
            "a refused write stales nothing and a failed read supersedes nothing: {marks:?}"
        );
        // The same write, done: the read before it is stale and collapses.
        let mut done = t.clone();
        done[3] = result("c2", "ok");
        assert_eq!(
            annotate_transcript(&done)[1],
            L0Mark::Skeleton {
                view: "read(path=a.md) → The file is unchanged.".into()
            }
        );
        let line = serde_json::to_string(&t[3]).unwrap();
        assert!(line.contains(r#""is_error":true"#), "{line}");
        assert!(!serde_json::to_string(&t[1]).unwrap().contains("is_error"));
    }

    #[test]
    fn a_result_answers_the_call_of_the_assistant_message_before_it() {
        // A server that numbers its calls afresh in every reply sends three calls `call_0`.
        let t = vec![
            assistant("", vec![call("call_0", "read", "a.md")]),
            result("call_0", "A"),
            assistant("", vec![call("call_0", "write", "b.md")]),
            result("call_0", "ok"),
            assistant("", vec![call("call_0", "read", "b.md")]),
            result("call_0", "B"),
        ];
        let marks = annotate_transcript(&t);
        assert!(marks.iter().all(L0Mark::is_keep), "{marks:?}");
        let answered = answered_calls(&t);
        assert_eq!(answered[0], None);
        assert!(answered[1].is_some_and(|c| c.arguments.contains("a.md")));
        assert!(answered[3].is_some_and(|c| c.name == "write"));
        assert!(answered[5].is_some_and(|c| c.arguments.contains("b.md")));
        // Two calls with one id in one reply: each result answers the next of them, and a
        // result after a reply with no calls answers none.
        let twice = vec![
            assistant("", vec![call("", "read", "a.md"), call("", "read", "c.md")]),
            result("", "A"),
            result("", "C"),
            assistant("Both read.", vec![]),
            result("", "late"),
        ];
        let answered = answered_calls(&twice);
        assert!(answered[1].is_some_and(|c| c.arguments.contains("a.md")));
        assert!(answered[2].is_some_and(|c| c.arguments.contains("c.md")));
        assert_eq!(answered[4], None);
    }

    #[test]
    fn a_path_with_a_leading_slash_names_the_same_file() {
        let t = vec![
            assistant("", vec![call("c1", "read", "notes/a.md")]),
            result("c1", "old"),
            assistant("", vec![call("c2", "write", "/notes/a.md")]),
            result("c2", "ok"),
            assistant("", vec![call("c3", "read", " /notes/a.md ")]),
            result("c3", "new"),
        ];
        let marks = annotate_transcript(&t);
        assert_eq!(
            marks[1],
            L0Mark::Invalid {
                path: "notes/a.md".into()
            }
        );
        assert!(marks[5].is_keep());
        assert_eq!(
            file_touch(&call("x", "read", "/n.md")),
            Some(FileTouch::Read("n.md".into()))
        );
        assert_eq!(file_touch(&call("y", "read", "/")), None);
    }

    #[test]
    fn a_later_read_supersedes_and_a_write_invalidates_then_collapses() {
        let t = vec![
            assistant(
                "Reading.",
                vec![call("c1", "read", "a.md"), call("c2", "read", "b.md")],
            ),
            result("c1", "A v1"),
            result("c2", "B v1"),
            assistant("", vec![call("c3", "read", "a.md")]),
            result("c3", "A v1 again"),
            assistant("", vec![call("c4", "write", "b.md")]),
            result("c4", "ok"),
            assistant("B now holds the summary. Done.", vec![]),
        ];
        let marks = annotate_transcript(&t);
        assert_eq!(
            marks[1],
            L0Mark::Superseded {
                path: "a.md".into()
            }
        );
        assert_eq!(
            marks[2],
            L0Mark::Skeleton {
                view: "read(path=b.md) → B now holds the summary.".into()
            }
        );
        assert!(marks[4].is_keep(), "the latest read of a.md is kept");
        assert!(marks[6].is_keep(), "a write result is never marked");
        assert!(marks[0].is_keep() && marks[7].is_keep());
        assert_eq!(
            l0_content(&t[1], &marks[1]),
            "[superseded: a later read of a.md replaces this result]"
        );
        assert_eq!(l0_content(&t[4], &marks[4]), "A v1 again");
    }

    #[test]
    fn a_stale_read_with_no_later_conclusion_stays_invalid_and_the_read_after_a_write_is_kept() {
        let t = vec![
            assistant("", vec![call("c1", "fs.read", "a.md")]),
            result("c1", "old"),
            assistant("", vec![call("c2", "fs_delete", "a.md")]),
            result("c2", "deleted"),
            assistant("", vec![call("c3", "read", "a.md")]),
            result("c3", "missing"),
        ];
        let marks = annotate_transcript(&t);
        assert_eq!(
            marks[1],
            L0Mark::Invalid {
                path: "a.md".into()
            }
        );
        assert!(marks[5].is_keep());
        assert_eq!(
            l0_content(&t[1], &marks[1]),
            "[stale: a.md was written after this read]"
        );
    }

    #[test]
    fn calls_without_a_path_and_unknown_calls_touch_nothing() {
        let bad = TranscriptToolCall {
            id: "x".into(),
            name: "read".into(),
            arguments: "{".into(),
        };
        assert_eq!(file_touch(&bad), None);
        assert_eq!(file_touch(&call("y", "list", "docs")), None);
        assert_eq!(file_touch(&call("z", "read", "  ")), None);
        assert_eq!(
            file_touch(&call("w", "write", "n.md")),
            Some(FileTouch::Write("n.md".into()))
        );
        // An orphan result (no call) is kept.
        assert_eq!(
            annotate_transcript(&[result("nobody", "x")]),
            vec![L0Mark::Keep]
        );
    }

    #[test]
    fn a_log_line_round_trips_and_omits_the_defaults() {
        let line = TurnLogLine {
            turn: 2,
            seq: 1,
            ts: "2026-11-18T10:00:00Z".into(),
            message: result("c1", "x"),
            l0: L0Mark::Keep,
            truncated: false,
        };
        let text = serde_json::to_string(&line).unwrap();
        assert_eq!(
            text,
            r#"{"turn":2,"seq":1,"ts":"2026-11-18T10:00:00Z","role":"tool","content":"x","tool_call_id":"c1"}"#
        );
        assert_eq!(serde_json::from_str::<TurnLogLine>(&text).unwrap(), line);
        let marked = TurnLogLine {
            l0: L0Mark::Invalid { path: "a".into() },
            truncated: true,
            ..line
        };
        let text = serde_json::to_string(&marked).unwrap();
        assert!(
            text.contains(r#""l0":{"action":"invalid","path":"a"}"#),
            "{text}"
        );
        assert!(text.contains(r#""truncated":true"#), "{text}");
        assert_eq!(serde_json::from_str::<TurnLogLine>(&text).unwrap(), marked);
    }

    #[test]
    fn the_blob_id_is_gits_and_sentences_are_cut_on_char_boundaries() {
        // `printf 'hello\n' | git hash-object --stdin`
        assert_eq!(
            git_blob_id(b"hello\n"),
            "ce013625030ba8dba906f756967f9e9ca394464a"
        );
        assert_eq!(git_blob_id(b""), "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391");
        assert_eq!(first_sentence("  完成了。然后继续"), "完成了。");
        assert_eq!(first_sentence("no stop"), "no stop");
        assert_eq!(
            first_sentence("Saved notes.md as v3.5. Next, the index."),
            "Saved notes.md as v3.5."
        );
        assert_eq!(first_sentence("Done!Then"), "Done!Then");
        assert_eq!(truncate_at_char("日本語", 4), "日");
    }
}

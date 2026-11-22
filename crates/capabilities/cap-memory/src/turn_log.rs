//! Step 0 of the post-processor and the turn features Step 7 records (MODULE-011; PRD §11.2,
//! §11.2.1, §11.4).
//!
//! Step 0 is the PRD's precondition of the post-processing: the turn is logged to the task's
//! `llm-turns.jsonl` as soon as `handle-message` returns — the inbound message, then what the
//! host recorded of the turn (the model's replies, their tool calls and the results), one
//! [`TurnLogLine`] per message with its L0 annotation. The log is append-only: a line number,
//! once given, always names the same message (PRD §11.2.1 "后续追加不影响已有行号"), so a
//! turn-index entry locates its turn by a 1-based inclusive line range.
//!
//! The features Step 7 derives from the logged turn are rule-based (no model call): the
//! boolean features, the L0 collapsed view, the content identifiers, the git blob id of every
//! file the turn read (what makes a turn stale once a file it read changes), the token counts,
//! and the reference counts of the older turns this turn refers to (7b.iv).

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use advance_shared_types::mailbox::Message;
use advance_shared_types::token_estimate::tokens_from_bytes_u32;
use advance_shared_types::turn_log::{
    annotate_transcript, file_touch, first_sentence, l0_content, truncate_at_char,
    workspace_blob_id, FileTouch, L0Mark, TranscriptMessage, TranscriptToolCall, TurnLogLine,
    MAX_LOGGED_CONTENT_BYTES,
};

use crate::turn_index::{LogOffset, ReadFileVersion, TurnEntry};

/// The most bytes of an inbound payload read as the turn's prompt (the scheduler reads the
/// assembly prompt with the same cap).
pub const MAX_PROMPT_BYTES: usize = 64 * 1024;
/// A turn records at most this many content identifiers.
pub const MAX_CONTENT_IDENTIFIERS: usize = 16;
/// The longest path a turn records as a content identifier, in bytes. A longer one is left out,
/// and a read file's version has the same bound (`workspace_blob_id` refuses a path over the
/// workspace path cap, `MAX_WORKSPACE_PATH_BYTES`, also 1 KiB). So a turn-index entry stays far
/// below the index's read cap.
pub const MAX_RECORDED_PATH_BYTES: usize = 1024;
/// A turn records the version of at most this many of the files it read.
pub const MAX_READ_FILE_VERSIONS: usize = 32;
/// The longest collapsed view a turn records, in bytes.
pub const MAX_COLLAPSED_VIEW_BYTES: usize = 600;
/// The most tool calls a collapsed view lists.
const MAX_COLLAPSED_CALLS: usize = 8;
/// The most bytes of the prompt a collapsed view quotes.
const MAX_COLLAPSED_PROMPT_BYTES: usize = 160;

/// The directory that holds an agent's task directories (PRD §11.2):
/// `<workspace>/.agent/tasks/active`.
pub fn tasks_root(workspace: &Path) -> PathBuf {
    workspace.join(".agent").join("tasks").join("active")
}

/// Where a release before MODULE-010 B1 kept an agent's task directories:
/// `<workspace>/.agent/memory/tasks`.
pub fn legacy_tasks_root(workspace: &Path) -> PathBuf {
    workspace.join(".agent").join("memory").join("tasks")
}

/// The note Step 0 logs after the messages of a turn that failed — its guest trapped or
/// returned an error, or its actions could not be dispatched (`PostProcessorHook::turn_failed`).
/// Such a turn gets no index entry.
pub const FAILED_TURN_NOTE: &str = "[this turn failed before it completed]";

/// Move the task directories a release before MODULE-010 B1 kept in [`legacy_tasks_root`] to
/// [`tasks_root`], so that each task goes on where it stopped. Its index moves with it, so its
/// turns go on numbering where they were: an index row is named by its task and turn number,
/// and a task that started again at turn 1 would overwrite its old rows. Its summary moves too.
///
/// - A task directory the new root lacks is renamed into it whole (both roots are in one
///   workspace).
/// - A task directory the new root has already — made by another component, such as the
///   decomposition store — takes each entry of the old one it lacks. An entry whose name it
///   has stays where it was, and so does the old directory then.
/// - Links are neither followed nor moved. Nothing is done when `.agent`, `.agent/memory` or
///   the legacy root is a link or not a directory, or when `.agent/tasks` or the new root is.
///   A linked task directory or entry stays.
/// - What cannot be moved stays where it was, and stderr says why. An emptied legacy directory
///   is removed.
///
/// Returns how many entries moved. Once nothing is left to move, it does nothing.
pub fn adopt_legacy_tasks(workspace: &Path) -> usize {
    let agent = workspace.join(".agent");
    let legacy = legacy_tasks_root(workspace);
    let root = tasks_root(workspace);
    if !(is_real_dir(&agent) && is_real_dir(&agent.join("memory")) && is_real_dir(&legacy)) {
        return 0;
    }
    for path in [agent.join("tasks"), root.clone()] {
        if std::fs::symlink_metadata(&path).is_ok_and(|m| !m.file_type().is_dir()) {
            eprintln!(
                "cap-memory: not moving the task directories in {legacy:?}: {path:?} is not a directory"
            );
            return 0;
        }
    }
    if let Err(e) = std::fs::create_dir_all(&root) {
        eprintln!("cap-memory: not moving the task directories in {legacy:?}: {e}");
        return 0;
    }
    let Ok(entries) = std::fs::read_dir(&legacy) else {
        return 0;
    };
    let mut moved = 0;
    for entry in entries.flatten() {
        let from = entry.path();
        let name = entry.file_name();
        let safe = name.to_str().is_some_and(|name| {
            crate::post_processor::sanitize_task_segment(name).as_deref() == Some(name)
        });
        if !safe || !is_real_dir(&from) {
            continue;
        }
        let to = root.join(&name);
        match std::fs::symlink_metadata(&to) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                match std::fs::rename(&from, &to) {
                    Ok(()) => moved += 1,
                    Err(e) => eprintln!("cap-memory: moving {from:?} to {to:?} failed: {e}"),
                }
            }
            Ok(meta) if meta.file_type().is_dir() => {
                moved += merge_task_dir(&from, &to);
                let _ = std::fs::remove_dir(&from);
            }
            _ => eprintln!("cap-memory: not moving {from:?}: {to:?} is not a directory"),
        }
    }
    let _ = std::fs::remove_dir(&legacy);
    moved
}

/// `path` is a directory, not a link to one.
fn is_real_dir(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_dir())
}

/// Move each entry of the old task directory `from` that `to` lacks into `to`
/// ([`adopt_legacy_tasks`]); a link stays.
fn merge_task_dir(from: &Path, to: &Path) -> usize {
    let Ok(entries) = std::fs::read_dir(from) else {
        return 0;
    };
    let mut moved = 0;
    for entry in entries.flatten() {
        let source = entry.path();
        match std::fs::symlink_metadata(&source) {
            Ok(meta) if !meta.file_type().is_symlink() => {}
            _ => continue,
        }
        let target = to.join(entry.file_name());
        if std::fs::symlink_metadata(&target).is_ok() {
            eprintln!("cap-memory: {target:?} exists; leaving {source:?} where it is");
            continue;
        }
        match std::fs::rename(&source, &target) {
            Ok(()) => moved += 1,
            Err(e) => eprintln!("cap-memory: moving {source:?} to {target:?} failed: {e}"),
        }
    }
    moved
}

/// What Step 0 logged of a turn, for Step 7.
#[derive(Clone, Debug)]
pub struct LoggedTurn {
    pub task_id: String,
    pub task_dir: PathBuf,
    pub turn: u32,
    /// The lines the turn occupies in the log; `0..=0` when nothing could be logged.
    pub log_offset: LogOffset,
    /// The inbound message's text.
    pub prompt: String,
    /// The turn as logged: the inbound message, then the transcript.
    pub messages: Vec<TranscriptMessage>,
    /// The L0 annotation of `messages`, index for index.
    pub marks: Vec<L0Mark>,
}

impl LoggedTurn {
    /// The turn's messages and their marks; the marks are computed from the messages.
    pub fn new(
        task_id: String,
        task_dir: PathBuf,
        turn: u32,
        prompt: String,
        transcript: Vec<TranscriptMessage>,
    ) -> Self {
        let messages = turn_messages(&prompt, transcript);
        let marks = annotate_transcript(&messages);
        Self {
            task_id,
            task_dir,
            turn,
            log_offset: LogOffset {
                start_line: 0,
                end_line: 0,
            },
            prompt,
            messages,
            marks,
        }
    }
}

/// The inbound message's text: its payload as UTF-8 (lossy), cut to [`MAX_PROMPT_BYTES`] at a
/// character boundary.
pub fn prompt_from_payload(payload: &[u8]) -> String {
    let head = &payload[..payload.len().min(MAX_PROMPT_BYTES)];
    let text = String::from_utf8_lossy(head);
    truncate_at_char(&text, MAX_PROMPT_BYTES).to_string()
}

/// The turn as it is logged: the inbound message when it has text, then the transcript —
/// without the transcript's first message when that repeats the inbound text (a guest that
/// sent it as a prompt the context did not already carry).
pub fn turn_messages(prompt: &str, transcript: Vec<TranscriptMessage>) -> Vec<TranscriptMessage> {
    let mut messages = Vec::with_capacity(transcript.len() + 1);
    let echoes = !prompt.is_empty()
        && transcript
            .first()
            .is_some_and(|m| m.role == "user" && m.content == prompt);
    if !prompt.is_empty() {
        messages.push(TranscriptMessage::new("user", prompt));
    }
    messages.extend(transcript.into_iter().skip(usize::from(echoes)));
    messages
}

/// Append the messages of a turn to the log at `path`, one line each, in one write followed by
/// an fsync. The turn is numbered `turn_floor`, or one past the last turn the log holds when
/// that is higher (a turn logged but never indexed keeps its number). Returns the turn number
/// and the 1-based inclusive range of lines the messages occupy (`0..=0` for no message). A
/// last line with no newline — an append that was cut short — is ended first and counts as a
/// line (a reader skips a line it cannot parse). A content or tool-call argument over
/// [`MAX_LOGGED_CONTENT_BYTES`] is cut and its line marked truncated. A log that is a symlink
/// or not a regular file is refused. The log is read from its first byte to count its lines;
/// [`append_turn_log_known`] starts from what the last append left instead.
pub fn append_turn_log(
    path: &Path,
    turn_floor: u32,
    ts: &str,
    messages: &[TranscriptMessage],
    marks: &[L0Mark],
) -> std::io::Result<(u32, LogOffset)> {
    append_turn_log_known(&KnownLogs::default(), path, turn_floor, ts, messages, marks)
}

/// What the appends of one post-processor last left of each turn log they wrote: the log's
/// length and (on unix) inode, its lines and its last turn. An append to a log that is still
/// as the last one left it starts from there, so it costs the turn it writes rather than a
/// read of the whole log, which only grows. A log that changed in between is read again.
#[derive(Debug, Default)]
pub struct KnownLogs(std::sync::Mutex<std::collections::HashMap<PathBuf, KnownLog>>);

/// What [`KnownLogs`] holds of one log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct KnownLog {
    identity: (u64, u64),
    lines: u32,
    last_turn: Option<u32>,
}

impl KnownLogs {
    fn get(&self, path: &Path) -> Option<KnownLog> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(path)
            .copied()
    }

    fn put(&self, path: &Path, log: KnownLog) {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(path.to_path_buf(), log);
    }
}

/// What tells a log apart from the one an append left: its length and, on unix, its inode.
fn log_identity(meta: &std::fs::Metadata) -> (u64, u64) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        (meta.len(), meta.ino())
    }
    #[cfg(not(unix))]
    {
        (meta.len(), 0)
    }
}

/// [`append_turn_log`], starting from what `known` holds of the log when the log is still as
/// the last append left it ([`KnownLogs`]), and noting there what this append leaves.
pub fn append_turn_log_known(
    known: &KnownLogs,
    path: &Path,
    turn_floor: u32,
    ts: &str,
    messages: &[TranscriptMessage],
    marks: &[L0Mark],
) -> std::io::Result<(u32, LogOffset)> {
    if std::fs::symlink_metadata(path).is_ok_and(|m| !m.file_type().is_file()) {
        return Err(std::io::Error::other(format!(
            "refusing a turn log that is not a regular file: {path:?}"
        )));
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true).append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(std::io::Error::other(format!(
            "refusing a turn log that is not a regular file: {path:?}"
        )));
    }
    let identity = log_identity(&meta);
    let scan = match known.get(path).filter(|log| log.identity == identity) {
        Some(log) => LogScan {
            lines: log.lines,
            torn: false,
            last_turn: log.last_turn,
        },
        None => scan_log(&mut file)?,
    };
    let turn = match scan.last_turn {
        Some(last) => turn_floor.max(last.saturating_add(1)),
        None => turn_floor,
    };
    if messages.is_empty() {
        if !scan.torn {
            known.put(
                path,
                KnownLog {
                    identity,
                    lines: scan.lines,
                    last_turn: scan.last_turn,
                },
            );
        }
        return Ok((
            turn,
            LogOffset {
                start_line: 0,
                end_line: 0,
            },
        ));
    }
    let mut lines = scan.lines;
    let mut buf = Vec::new();
    if scan.torn {
        buf.push(b'\n');
        lines = lines.saturating_add(1);
    }
    for (seq, message) in messages.iter().enumerate() {
        let mark = marks.get(seq).cloned().unwrap_or_default();
        let (message, truncated) = capped(message);
        let line = TurnLogLine {
            turn,
            seq: u32::try_from(seq).unwrap_or(u32::MAX),
            ts: ts.to_string(),
            message,
            l0: mark,
            truncated,
        };
        serde_json::to_writer(&mut buf, &line).map_err(std::io::Error::other)?;
        buf.push(b'\n');
    }
    file.write_all(&buf)?;
    file.sync_data()?;
    let n = u32::try_from(messages.len()).unwrap_or(u32::MAX);
    let start_line = lines.saturating_add(1);
    if let Ok(meta) = file.metadata() {
        known.put(
            path,
            KnownLog {
                identity: log_identity(&meta),
                lines: lines.saturating_add(n),
                last_turn: Some(turn),
            },
        );
    }
    Ok((
        turn,
        LogOffset {
            start_line,
            end_line: start_line.saturating_add(n - 1),
        },
    ))
}

/// What a scan of the log found.
struct LogScan {
    /// Its newline-terminated lines.
    lines: u32,
    /// Its last line lacks its newline.
    torn: bool,
    /// The turn its last complete line belongs to.
    last_turn: Option<u32>,
}

fn scan_log(file: &mut std::fs::File) -> std::io::Result<LogScan> {
    file.seek(SeekFrom::Start(0))?;
    let mut buf = vec![0u8; 64 * 1024];
    let (mut lines, mut offset) = (0u32, 0u64);
    // Where the line being read starts, and where the last complete one started.
    let (mut line_start, mut last_complete) = (0u64, None);
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        for (i, byte) in buf[..n].iter().enumerate() {
            if *byte == b'\n' {
                lines = lines.saturating_add(1);
                last_complete = Some(line_start);
                line_start = offset + i as u64 + 1;
            }
        }
        offset += n as u64;
    }
    let last_turn = match last_complete {
        Some(start) => {
            file.seek(SeekFrom::Start(start))?;
            let mut head = Vec::with_capacity(32);
            (&mut *file).take(32).read_to_end(&mut head)?;
            leading_turn(&head)
        }
        None => None,
    };
    Ok(LogScan {
        lines,
        torn: line_start < offset,
        last_turn,
    })
}

/// The turn number a log line opens with — `{"turn":N,`, as [`TurnLogLine`] serializes it.
fn leading_turn(line: &[u8]) -> Option<u32> {
    let rest = line.strip_prefix(b"{\"turn\":")?;
    let digits = rest.iter().take_while(|b| b.is_ascii_digit()).count();
    std::str::from_utf8(&rest[..digits]).ok()?.parse().ok()
}

/// `message` with its content and tool-call arguments cut to the logged cap, and whether
/// anything was cut.
fn capped(message: &TranscriptMessage) -> (TranscriptMessage, bool) {
    let mut out = message.clone();
    let mut truncated = false;
    if out.content.len() > MAX_LOGGED_CONTENT_BYTES {
        out.content = truncate_at_char(&out.content, MAX_LOGGED_CONTENT_BYTES).to_string();
        truncated = true;
    }
    for call in &mut out.tool_calls {
        if call.arguments.len() > MAX_LOGGED_CONTENT_BYTES {
            call.arguments =
                truncate_at_char(&call.arguments, MAX_LOGGED_CONTENT_BYTES).to_string();
            truncated = true;
        }
    }
    (out, truncated)
}

/// The lines `range` of the log at `path` that parse, reading at most `max_bytes` of the file.
/// A missing log, a symlink or a non-regular file reads as no lines.
pub fn read_turn_log(path: &Path, range: LogOffset, max_bytes: u64) -> Vec<TurnLogLine> {
    use std::io::BufRead;
    if range.start_line == 0 || range.validate().is_err() {
        return Vec::new();
    }
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return Vec::new();
    };
    if !meta.file_type().is_file() {
        return Vec::new();
    }
    let Ok(file) = std::fs::File::open(path) else {
        return Vec::new();
    };
    let reader = std::io::BufReader::new(file.take(max_bytes));
    let mut out = Vec::new();
    for (i, line) in reader.split(b'\n').enumerate() {
        let Ok(line) = line else { break };
        let number = u32::try_from(i + 1).unwrap_or(u32::MAX);
        if number < range.start_line {
            continue;
        }
        if number > range.end_line {
            break;
        }
        if let Ok(parsed) = serde_json::from_slice::<TurnLogLine>(&line) {
            out.push(parsed);
        }
    }
    out
}

/// How much of a log a read of its last turns reads backwards at most.
const TAIL_CHUNK_BYTES: u64 = 64 * 1024;

/// The lines of the turns `turns` from the log at `path`, each turn's in order, reading the log
/// from its end backwards — the turns a context loads are its last ones — and at most
/// `max_bytes` of it. A turn is found by the turn number its lines carry (the lines its
/// `log_offset` names); reading stops at the first line of a turn older than any asked for. A
/// missing log, a symlink or a non-regular file reads as nothing; a line that does not parse
/// (a torn last line, say) is skipped, and so is a line cut by `max_bytes`. A turn whose lines
/// do not run from its first on without a gap is left out — its first lines lie past
/// `max_bytes`, or a line before its last does not parse. A turn that lacks its last lines comes
/// back short: only its `log_offset` says how many it has, so the caller checks the count (a
/// turn is loaded whole or not at all).
pub fn read_turns_from_tail(
    path: &Path,
    turns: &BTreeSet<u32>,
    max_bytes: u64,
) -> BTreeMap<u32, Vec<TurnLogLine>> {
    let mut out: BTreeMap<u32, Vec<TurnLogLine>> = BTreeMap::new();
    let Some(&oldest) = turns.iter().next() else {
        return out;
    };
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return out;
    };
    if !meta.file_type().is_file() {
        return out;
    }
    let Ok(mut file) = std::fs::File::open(path) else {
        return out;
    };
    let len = meta.len();
    let floor = len.saturating_sub(max_bytes);
    // Newest first, as read.
    let mut found: Vec<TurnLogLine> = Vec::new();
    // The bytes after the last newline seen so far: the end of a line whose start lies before.
    let mut partial: Vec<u8> = Vec::new();
    let mut pos = len;
    let mut done = false;
    while pos > floor && !done {
        let start = pos.saturating_sub(TAIL_CHUNK_BYTES).max(floor);
        let mut chunk = vec![0u8; (pos - start) as usize];
        if file.seek(SeekFrom::Start(start)).is_err() || file.read_exact(&mut chunk).is_err() {
            return out;
        }
        chunk.extend_from_slice(&partial);
        // Every segment but the first is a whole line; the first may begin before `start`.
        let first_newline = chunk.iter().position(|b| *b == b'\n');
        let whole_from = first_newline.map_or(chunk.len(), |i| i + 1);
        for line in chunk[whole_from..].split(|b| *b == b'\n').rev() {
            if !take_line(line, turns, oldest, &mut found) {
                done = true;
                break;
            }
        }
        partial = chunk[..first_newline.unwrap_or(chunk.len())].to_vec();
        pos = start;
    }
    // At the start of the file, what is left is its first line (cut, when the read stopped at
    // `max_bytes` instead).
    if !done && pos == 0 {
        take_line(&partial, turns, oldest, &mut found);
    }
    for line in found.into_iter().rev() {
        out.entry(line.turn).or_default().push(line);
    }
    out.retain(|_, lines| {
        lines
            .iter()
            .enumerate()
            .all(|(i, line)| usize::try_from(line.seq).is_ok_and(|seq| seq == i))
    });
    out
}

/// Keep `line` when it is one of `turns`'; `false` once it belongs to a turn older than
/// `oldest`, so the backward read can stop.
fn take_line(
    line: &[u8],
    turns: &BTreeSet<u32>,
    oldest: u32,
    found: &mut Vec<TurnLogLine>,
) -> bool {
    if line.is_empty() {
        return true;
    }
    let Ok(parsed) = serde_json::from_slice::<TurnLogLine>(line) else {
        return true;
    };
    if parsed.turn < oldest {
        return false;
    }
    if turns.contains(&parsed.turn) {
        found.push(parsed);
    }
    true
}

/// Fill the turn-index fields Step 7 derives from the logged turn (PRD §11.2.1): the log range,
/// `has_user_instruction` (the inbound message is a user's and has text), `has_tool_use`, the
/// collapsed view, the content identifiers (the paths the turn's tool calls name), the git blob
/// id of each file the turn read as it is now (a file missing, outside `workspace_root`, a
/// symlink or too large is not recorded, and nor is a read whose result answers its call
/// and failed: it read nothing), and the token counts of the collapsed view and of the
/// L0-processed turn. A path over [`MAX_RECORDED_PATH_BYTES`] is recorded neither way.
/// `tokens_digest` goes with the digest.
pub fn fill_turn_features(
    entry: &mut TurnEntry,
    logged: &LoggedTurn,
    msg: &Message,
    workspace_root: Option<&Path>,
) {
    entry.log_offset = logged.log_offset;
    entry.has_user_instruction = msg.from.starts_with("user:") && !logged.prompt.trim().is_empty();
    entry.has_tool_use = logged.messages.iter().any(|m| !m.tool_calls.is_empty());
    entry.collapsed_view = collapsed_view(logged);
    let calls: Vec<&TranscriptToolCall> = logged
        .messages
        .iter()
        .flat_map(|m| m.tool_calls.iter())
        .collect();
    let mut seen = BTreeSet::new();
    entry.content_identifiers = calls
        .iter()
        .filter_map(|c| call_path(c))
        .filter(|p| p.len() <= MAX_RECORDED_PATH_BYTES && seen.insert(p.clone()))
        .take(MAX_CONTENT_IDENTIFIERS)
        .collect();
    // The calls whose results failed (MODULE-010 B1): such a read read nothing, so its file gets
    // no version, and its change does not make the turn stale. A call that got no result, or
    // whose result went in as a note (MODULE-009: it answered no pending call), is not paired
    // with one, and its file keeps its version: the safe side, as the turn then loads as its
    // digest once that file changes.
    let failed: Vec<&TranscriptToolCall> =
        advance_shared_types::turn_log::answered_calls(&logged.messages)
            .into_iter()
            .zip(&logged.messages)
            .filter_map(|(call, m)| call.filter(|_| m.is_error))
            .collect();
    let mut read_seen = BTreeSet::new();
    entry.read_file_versions = match workspace_root {
        Some(root) => calls
            .iter()
            .filter(|c| !failed.iter().any(|f| std::ptr::eq(*f, **c)))
            .filter_map(|c| match file_touch(c) {
                Some(FileTouch::Read(path)) => Some(path),
                _ => None,
            })
            .filter(|p| read_seen.insert(p.clone()))
            .filter_map(|path| {
                workspace_blob_id(root, &path).map(|blob_id| ReadFileVersion { path, blob_id })
            })
            .take(MAX_READ_FILE_VERSIONS)
            .collect(),
        None => Vec::new(),
    };
    entry.tokens_collapse_excerpt = tokens_from_bytes_u32(entry.collapsed_view.len());
    let l0_bytes: usize = logged
        .messages
        .iter()
        .zip(&logged.marks)
        .map(|(m, mark)| {
            l0_content(m, mark).len()
                + m.tool_calls
                    .iter()
                    .map(|c| c.name.len() + c.arguments.len())
                    .sum::<usize>()
        })
        .sum();
    entry.tokens_l0_processed = tokens_from_bytes_u32(l0_bytes);
}

/// The `path` argument of a tool call, if it has one.
fn call_path(call: &TranscriptToolCall) -> Option<String> {
    let path = serde_json::from_str::<serde_json::Value>(&call.arguments)
        .ok()?
        .get("path")?
        .as_str()?
        .trim()
        .to_string();
    (!path.is_empty()).then_some(path)
}

/// The L0 collapsed view of a turn (PRD §11.2.1):
///
/// ```text
/// [user] "<the prompt>"
/// [assistant] read("data/pricing.csv") → write("reports/a.md")
/// → "<the first sentence of the last reply>"
/// ```
///
/// A line with nothing to show is left out; the view is capped at [`MAX_COLLAPSED_VIEW_BYTES`].
pub fn collapsed_view(logged: &LoggedTurn) -> String {
    let mut lines = Vec::new();
    let prompt = logged.prompt.trim();
    if !prompt.is_empty() {
        let quoted = truncate_at_char(prompt, MAX_COLLAPSED_PROMPT_BYTES).replace('\n', " ");
        lines.push(format!("[user] \"{quoted}\""));
    }
    let calls: Vec<String> = logged
        .messages
        .iter()
        .flat_map(|m| m.tool_calls.iter())
        .map(|c| match call_path(c) {
            Some(path) => format!("{}(\"{path}\")", c.name),
            None => format!("{}(…)", c.name),
        })
        .collect();
    if !calls.is_empty() {
        let mut shown: Vec<String> = calls.iter().take(MAX_COLLAPSED_CALLS).cloned().collect();
        if calls.len() > MAX_COLLAPSED_CALLS {
            shown.push(format!("… ({} more)", calls.len() - MAX_COLLAPSED_CALLS));
        }
        lines.push(format!("[assistant] {}", shown.join(" → ")));
    }
    if let Some(reply) = logged
        .messages
        .iter()
        .rev()
        .filter(|m| m.role == "assistant")
        .map(|m| first_sentence(&m.content))
        .find(|s| !s.is_empty())
    {
        lines.push(format!("→ \"{}\"", reply.replace('\n', " ")));
    }
    truncate_at_char(&lines.join("\n"), MAX_COLLAPSED_VIEW_BYTES).to_string()
}

/// PRD §11.4 7b.iv: an older turn this turn refers to — one of whose content identifiers this
/// turn names, as an identifier of its own or in its prompt — gains a reference. Pure string
/// matching. Returns the turns that gained one.
pub fn bump_references(older: &mut [TurnEntry], this: &TurnEntry, prompt: &str) -> Vec<u32> {
    let named: BTreeSet<&str> = this
        .content_identifiers
        .iter()
        .map(String::as_str)
        .collect();
    let mut bumped = Vec::new();
    for old in older.iter_mut() {
        let referred = old.content_identifiers.iter().any(|id| {
            named.contains(id.as_str()) || (!id.is_empty() && prompt.contains(id.as_str()))
        });
        if referred {
            old.reference_count = old.reference_count.saturating_add(1);
            bumped.push(old.turn);
        }
    }
    bumped
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use advance_shared_types::mailbox::MessageKind;
    use serde_json::json;

    use super::*;
    use crate::turn_index::Importance;

    fn user(text: &str) -> TranscriptMessage {
        TranscriptMessage::new("user", text)
    }

    fn assistant(text: &str) -> TranscriptMessage {
        TranscriptMessage::new("assistant", text)
    }

    fn call(id: &str, name: &str, arguments: serde_json::Value) -> TranscriptMessage {
        TranscriptMessage {
            role: "assistant".into(),
            content: String::new(),
            tool_calls: vec![TranscriptToolCall {
                id: id.into(),
                name: name.into(),
                arguments: arguments.to_string(),
            }],
            tool_call_id: None,
            is_error: false,
        }
    }

    fn result(id: &str, text: &str) -> TranscriptMessage {
        TranscriptMessage {
            role: "tool".into(),
            content: text.into(),
            tool_calls: Vec::new(),
            tool_call_id: Some(id.into()),
            is_error: false,
        }
    }

    fn range(start_line: u32, end_line: u32) -> LogOffset {
        LogOffset {
            start_line,
            end_line,
        }
    }

    fn append(path: &Path, floor: u32, messages: &[TranscriptMessage]) -> (u32, LogOffset) {
        let marks = annotate_transcript(messages);
        append_turn_log(path, floor, "2026-11-18T10:00:00Z", messages, &marks).expect("append")
    }

    fn logged(prompt: &str, transcript: Vec<TranscriptMessage>) -> LoggedTurn {
        LoggedTurn::new(
            "t1".into(),
            PathBuf::from("/nowhere"),
            1,
            prompt.into(),
            transcript,
        )
    }

    fn message_from(from: &str) -> Message {
        Message {
            id: "m1".into(),
            kind: MessageKind::User,
            from: from.into(),
            to: "agent:root".into(),
            payload: Vec::new(),
            context: None,
            timestamp: SystemTime::UNIX_EPOCH,
            origin: None,
        }
    }

    fn entry(turn: u32, identifiers: &[&str]) -> TurnEntry {
        TurnEntry {
            turn,
            timestamp: String::new(),
            agent_id: "a".into(),
            task_id: "t1".into(),
            log_offset: range(0, 0),
            has_user_instruction: false,
            has_user_correction: false,
            has_tool_use: false,
            has_decision: false,
            importance: Importance::Normal,
            digest: String::new(),
            collapsed_view: String::new(),
            git_commit: String::new(),
            git_diff_summary: String::new(),
            git_checkpoints: Vec::new(),
            reference_count: 0,
            content_identifiers: identifiers.iter().map(|s| s.to_string()).collect(),
            read_file_versions: Vec::new(),
            tokens_digest: 0,
            tokens_collapse_excerpt: 0,
            tokens_l0_processed: 0,
        }
    }

    #[test]
    fn lines_are_numbered_from_one_and_never_rewritten() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir
            .path()
            .join(advance_shared_types::turn_log::TURN_LOG_FILENAME);
        assert_eq!(
            append(&log, 1, &[user("a"), assistant("b")]),
            (1, range(1, 2))
        );
        let before = std::fs::read(&log).unwrap();
        let second = [
            user("c"),
            call("c1", "read", json!({ "path": "x" })),
            result("c1", "x!"),
        ];
        assert_eq!(append(&log, 2, &second), (2, range(3, 5)));
        assert!(
            std::fs::read(&log).unwrap().starts_with(&before),
            "the earlier lines are untouched"
        );
        let lines = read_turn_log(&log, range(3, 5), u64::MAX);
        let ids: Vec<(u32, u32)> = lines.iter().map(|l| (l.turn, l.seq)).collect();
        assert_eq!(ids, [(2, 0), (2, 1), (2, 2)]);
        assert_eq!(lines[2].message, second[2]);
        assert!(
            read_turn_log(&log, range(4, 3), u64::MAX).is_empty(),
            "an inverted range"
        );
    }

    #[test]
    fn the_last_turns_are_read_from_the_end_of_the_log() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("llm-turns.jsonl");
        // Lines longer than a read chunk, so a line spans chunks.
        let long = "x".repeat(TAIL_CHUNK_BYTES as usize + 10);
        for turn in 1..=6 {
            append(
                &log,
                turn,
                &[user(&format!("prompt {turn}")), assistant(&long)],
            );
        }
        let wanted: BTreeSet<u32> = [4, 6].into_iter().collect();
        let read = read_turns_from_tail(&log, &wanted, u64::MAX);
        assert_eq!(read.keys().copied().collect::<Vec<_>>(), [4, 6]);
        for (turn, lines) in &read {
            let seqs: Vec<u32> = lines.iter().map(|l| l.seq).collect();
            assert_eq!(seqs, [0, 1], "turn {turn}");
            assert_eq!(lines[0].message.content, format!("prompt {turn}"));
            assert_eq!(lines[1].message.content, long);
        }
        // The first line of the file is read too.
        let first: BTreeSet<u32> = [1].into_iter().collect();
        assert_eq!(read_turns_from_tail(&log, &first, u64::MAX)[&1].len(), 2);
        // A byte cap that ends inside turn 5 keeps turn 6 whole and nothing of turn 4.
        let size = std::fs::metadata(&log).unwrap().len();
        let one_turn = size / 6;
        let capped = read_turns_from_tail(&log, &wanted, one_turn + one_turn / 2);
        assert_eq!(capped.keys().copied().collect::<Vec<_>>(), [6]);
        // A torn last line is skipped.
        let mut file = std::fs::OpenOptions::new().append(true).open(&log).unwrap();
        file.write_all(b"{\"turn\":7,\"seq\"").unwrap();
        drop(file);
        let last: BTreeSet<u32> = [6, 7].into_iter().collect();
        assert_eq!(
            read_turns_from_tail(&log, &last, u64::MAX)
                .keys()
                .copied()
                .collect::<Vec<_>>(),
            [6]
        );
        // Nothing asked, no log, or a log that is no regular file: nothing.
        assert!(read_turns_from_tail(&log, &BTreeSet::new(), u64::MAX).is_empty());
        assert!(read_turns_from_tail(&dir.path().join("none"), &wanted, u64::MAX).is_empty());
        assert!(read_turns_from_tail(dir.path(), &wanted, u64::MAX).is_empty());
    }

    #[test]
    fn a_torn_last_line_is_ended_and_counted() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("llm-turns.jsonl");
        append(&log, 1, &[user("a")]);
        // An append cut short: no newline, and not a line a reader can parse.
        let mut file = std::fs::OpenOptions::new().append(true).open(&log).unwrap();
        file.write_all(b"{\"turn\":2,\"seq\":0,\"ts\"").unwrap();
        drop(file);
        // The torn line is no complete line: the log's last turn is still 1.
        assert_eq!(append(&log, 2, &[user("b")]), (2, range(3, 3)));
        let all = read_turn_log(&log, range(1, 3), u64::MAX);
        let contents: Vec<&str> = all.iter().map(|l| l.message.content.as_str()).collect();
        assert_eq!(contents, ["a", "b"], "the torn line is skipped");
    }

    #[test]
    fn a_turn_logged_but_never_indexed_keeps_its_number() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("llm-turns.jsonl");
        append(&log, 1, &[user("a")]);
        append(&log, 2, &[user("b")]);
        // The index stopped at turn 1 (its write of turn 2 failed): the next turn is 3.
        assert_eq!(append(&log, 2, &[user("c")]), (3, range(3, 3)));
        // An index ahead of the log wins.
        assert_eq!(append(&log, 9, &[user("d")]), (9, range(4, 4)));
        // A turn with nothing to log takes the next number and no line.
        assert_eq!(append(&log, 1, &[]), (10, range(0, 0)));
    }

    #[test]
    fn an_empty_turn_occupies_no_line() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("llm-turns.jsonl");
        assert_eq!(append(&log, 1, &[]), (1, range(0, 0)));
        assert_eq!(std::fs::read(&log).unwrap(), b"");
        assert!(read_turn_log(&log, range(0, 0), u64::MAX).is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn a_log_that_is_a_symlink_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let outside = dir.path().join("outside.txt");
        std::fs::write(&outside, b"keep").unwrap();
        let log = dir.path().join("llm-turns.jsonl");
        std::os::unix::fs::symlink(&outside, &log).unwrap();
        assert!(append_turn_log(&log, 1, "ts", &[user("a")], &[L0Mark::Keep]).is_err());
        assert_eq!(std::fs::read(&outside).unwrap(), b"keep");
        assert!(
            read_turn_log(&log, range(1, 1), u64::MAX).is_empty(),
            "a symlinked log reads as nothing"
        );
    }

    #[test]
    fn long_contents_and_arguments_are_cut_at_a_character_and_marked() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("llm-turns.jsonl");
        // Two bytes a character, so the cap falls inside one unless it is moved back.
        let long = format!("a{}", "é".repeat(MAX_LOGGED_CONTENT_BYTES));
        let mut big = call("c1", "write", json!({ "path": "p", "content": long }));
        big.content = long.clone();
        append(&log, 1, &[user("short"), big]);
        let lines = read_turn_log(&log, range(1, 2), u64::MAX);
        assert!(!lines[0].truncated);
        assert!(lines[1].truncated);
        assert!(lines[1].message.content.len() <= MAX_LOGGED_CONTENT_BYTES);
        assert!(long.starts_with(&lines[1].message.content));
        assert!(lines[1].message.tool_calls[0].arguments.len() <= MAX_LOGGED_CONTENT_BYTES);
    }

    #[test]
    fn the_inbound_prompt_is_logged_once() {
        // The guest sent the prompt as its own: the transcript's first message repeats it.
        assert_eq!(
            turn_messages("hi", vec![user("hi"), assistant("yo")]),
            [user("hi"), assistant("yo")]
        );
        // A different first message is the guest's own.
        assert_eq!(
            turn_messages("hi", vec![user("hi there"), assistant("yo")]),
            [user("hi"), user("hi there"), assistant("yo")]
        );
        // No inbound text: the transcript as it stands.
        assert_eq!(turn_messages("", vec![assistant("yo")]), [assistant("yo")]);
    }

    #[test]
    fn the_prompt_is_the_payload_cut_at_a_character() {
        assert_eq!(prompt_from_payload(b"hello"), "hello");
        assert_eq!(prompt_from_payload(&[0xff, b'a']), "\u{fffd}a");
        let odd = format!("a{}", "é".repeat(MAX_PROMPT_BYTES));
        let prompt = prompt_from_payload(odd.as_bytes());
        assert!(prompt.len() <= MAX_PROMPT_BYTES, "{}", prompt.len());
        assert!(
            odd.starts_with(&prompt),
            "no character is split or replaced"
        );
    }

    #[test]
    fn a_turn_records_its_tool_use_the_paths_it_named_and_the_files_it_read() {
        let ws = tempfile::tempdir().unwrap();
        std::fs::write(ws.path().join("a.txt"), b"hello\n").unwrap();
        let turn = logged(
            "check a.txt",
            vec![
                call("c1", "read", json!({ "path": "a.txt" })),
                result("c1", "hello"),
                call("c2", "write", json!({ "path": "b.txt", "content": "x" })),
                result("c2", "ok"),
                call("c3", "read", json!({ "path": "missing.txt" })),
                result("c3", "not found"),
                call("c4", "read", json!({ "path": "a.txt" })),
                result("c4", "hello"),
                assistant("Both files are handled. Nothing else changed."),
            ],
        );
        let mut indexed = entry(1, &[]);
        fill_turn_features(
            &mut indexed,
            &turn,
            &message_from("user:client-api"),
            Some(ws.path()),
        );
        assert!(indexed.has_user_instruction);
        assert!(indexed.has_tool_use);
        assert_eq!(
            indexed.content_identifiers,
            ["a.txt", "b.txt", "missing.txt"]
        );
        // `git hash-object` of "hello\n"; a missing file has no version.
        assert_eq!(
            indexed.read_file_versions,
            [ReadFileVersion {
                path: "a.txt".into(),
                blob_id: "ce013625030ba8dba906f756967f9e9ca394464a".into(),
            }]
        );
        assert_eq!(
            indexed.collapsed_view,
            "[user] \"check a.txt\"\n[assistant] read(\"a.txt\") → write(\"b.txt\") → read(\"missing.txt\") → read(\"a.txt\")\n→ \"Both files are handled.\""
        );
        assert!(indexed.tokens_collapse_excerpt > 0);
        assert!(indexed.tokens_l0_processed > 0);
        assert_eq!(indexed.log_offset, range(0, 0), "the range Step 0 noted");

        // Another agent's message is no user instruction; without a workspace no version
        // is recorded.
        let mut indexed = entry(1, &[]);
        fill_turn_features(&mut indexed, &turn, &message_from("agent:helper"), None);
        assert!(!indexed.has_user_instruction);
        assert!(indexed.read_file_versions.is_empty());
    }

    #[test]
    fn a_failed_read_and_an_overlong_path_are_not_recorded() {
        let ws = tempfile::tempdir().unwrap();
        std::fs::write(ws.path().join("a.txt"), b"hello\n").unwrap();
        std::fs::write(ws.path().join("b.txt"), b"hello\n").unwrap();
        let mut refused = result("c1", "refused: over the read bound");
        refused.is_error = true;
        let long = "d/".repeat(MAX_RECORDED_PATH_BYTES);
        let turn = logged(
            "check a.txt and b.txt",
            vec![
                call("c1", "read", json!({ "path": "a.txt" })),
                refused,
                call("c2", "read", json!({ "path": "b.txt" })),
                result("c2", "hello"),
                call("c3", "read", json!({ "path": long })),
                result("c3", "not found"),
            ],
        );
        let mut indexed = entry(1, &[]);
        fill_turn_features(
            &mut indexed,
            &turn,
            &message_from("user:client-api"),
            Some(ws.path()),
        );
        // The failed read still names its file; it read nothing, so it records no version.
        assert_eq!(indexed.content_identifiers, ["a.txt", "b.txt"]);
        assert_eq!(
            indexed.read_file_versions,
            [ReadFileVersion {
                path: "b.txt".into(),
                blob_id: "ce013625030ba8dba906f756967f9e9ca394464a".into(),
            }]
        );
    }

    #[test]
    fn the_collapsed_view_is_capped() {
        let calls: Vec<TranscriptMessage> = (0..20)
            .map(|i| {
                call(
                    &format!("c{i}"),
                    "read",
                    json!({ "path": format!("dir/file-{i}.txt") }),
                )
            })
            .collect();
        let view = collapsed_view(&logged(&"x".repeat(1000), calls));
        assert!(view.len() <= MAX_COLLAPSED_VIEW_BYTES, "{}", view.len());
        assert!(view.contains("… (12 more)"), "{view}");
        // Nothing to show: no view.
        assert_eq!(collapsed_view(&logged("", Vec::new())), "");
    }

    #[test]
    fn an_older_turn_this_one_names_gains_a_reference() {
        let mut older = vec![
            entry(1, &["a.txt"]),
            entry(2, &["b.txt"]),
            entry(3, &["c.txt"]),
        ];
        let this = entry(4, &["a.txt"]);
        // a.txt by identifier, c.txt by the prompt.
        assert_eq!(
            bump_references(&mut older, &this, "compare with c.txt"),
            [1, 3]
        );
        let counts: Vec<u32> = older.iter().map(|t| t.reference_count).collect();
        assert_eq!(counts, [1, 0, 1]);
    }

    /// MODULE-010 B1: the task directories an older release kept in `.agent/memory/tasks/`
    /// move to `.agent/tasks/active/`, so each task goes on where it stopped. A directory the
    /// new root has already takes what it lacks; an entry whose name it has stays where it was.
    #[test]
    fn the_task_directories_of_an_older_release_move_over() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path();
        let (legacy, root) = (legacy_tasks_root(ws), tasks_root(ws));
        // No `.agent`: nothing to do.
        assert_eq!(adopt_legacy_tasks(ws), 0);
        std::fs::create_dir_all(legacy.join("t1")).unwrap();
        std::fs::write(legacy.join("t1/turn-index.yaml"), "turns: []\n").unwrap();
        std::fs::write(legacy.join("t1/llm-turns.jsonl"), "").unwrap();
        std::fs::create_dir_all(legacy.join("t2")).unwrap();
        std::fs::write(legacy.join("t2/summary.yaml"), "old summary").unwrap();
        std::fs::write(legacy.join("t2/decomposition.yaml"), "old plan").unwrap();
        // The new root has t2 already, with a decomposition of its own.
        std::fs::create_dir_all(root.join("t2")).unwrap();
        std::fs::write(root.join("t2/decomposition.yaml"), "new plan").unwrap();
        // A name that is no task id stays.
        std::fs::create_dir_all(legacy.join(".hidden")).unwrap();

        // t1 whole, and t2's summary.
        assert_eq!(adopt_legacy_tasks(ws), 2);
        assert_eq!(
            std::fs::read_to_string(root.join("t1/turn-index.yaml")).unwrap(),
            "turns: []\n"
        );
        assert!(root.join("t1/llm-turns.jsonl").is_file());
        assert!(!legacy.join("t1").exists());
        assert_eq!(
            std::fs::read_to_string(root.join("t2/summary.yaml")).unwrap(),
            "old summary"
        );
        assert_eq!(
            std::fs::read_to_string(root.join("t2/decomposition.yaml")).unwrap(),
            "new plan",
            "a name the new directory has is not overwritten"
        );
        assert_eq!(
            std::fs::read_to_string(legacy.join("t2/decomposition.yaml")).unwrap(),
            "old plan",
            "and stays where it was"
        );
        assert!(legacy.join(".hidden").is_dir());
        // Once nothing is left to move, nothing moves.
        assert_eq!(adopt_legacy_tasks(ws), 0);

        // A legacy root left empty is removed.
        let other = tempfile::tempdir().unwrap();
        let old = legacy_tasks_root(other.path());
        std::fs::create_dir_all(old.join("t3")).unwrap();
        std::fs::write(old.join("t3/summary.yaml"), "s").unwrap();
        assert_eq!(adopt_legacy_tasks(other.path()), 1);
        assert!(!old.exists());
        assert!(tasks_root(other.path()).join("t3/summary.yaml").is_file());
    }

    /// Links are neither followed nor moved: a linked task directory stays, and nothing moves
    /// when `.agent/tasks` is a link.
    #[cfg(unix)]
    #[test]
    fn adopting_follows_and_moves_no_link() {
        let outside = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(outside.path().join("t9")).unwrap();

        let dir = tempfile::tempdir().unwrap();
        let legacy = legacy_tasks_root(dir.path());
        std::fs::create_dir_all(&legacy).unwrap();
        std::os::unix::fs::symlink(outside.path().join("t9"), legacy.join("t9")).unwrap();
        assert_eq!(adopt_legacy_tasks(dir.path()), 0);
        assert!(std::fs::symlink_metadata(legacy.join("t9"))
            .unwrap()
            .file_type()
            .is_symlink());
        assert!(!tasks_root(dir.path()).join("t9").exists());

        let linked = tempfile::tempdir().unwrap();
        let old = legacy_tasks_root(linked.path());
        std::fs::create_dir_all(old.join("t1")).unwrap();
        std::os::unix::fs::symlink(outside.path(), linked.path().join(".agent/tasks")).unwrap();
        assert_eq!(adopt_legacy_tasks(linked.path()), 0);
        assert!(old.join("t1").is_dir());
        assert!(!outside.path().join("active").exists());
    }

    /// An append through [`KnownLogs`] starts from what the last one left while the log is
    /// still as it left it (same length and inode), and reads the log again once it changed.
    #[test]
    fn a_known_log_is_read_again_only_once_it_changed() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("llm-turns.jsonl");
        let known = KnownLogs::default();
        let put = |known: &KnownLogs, text: &str| {
            let messages = [user(text)];
            let marks = annotate_transcript(&messages);
            append_turn_log_known(known, &log, 1, "2026-11-21T10:00:00Z", &messages, &marks)
                .expect("append")
        };
        assert_eq!(put(&known, "a"), (1, range(1, 1)));
        assert_eq!(put(&known, "b"), (2, range(2, 2)));
        // Rewritten in place — same length, same inode — its last line now says turn 7. The
        // known state is used: the next turn is 3, so the log was not read again.
        let text = std::fs::read_to_string(&log).unwrap();
        let rewritten = text.replacen("{\"turn\":2,", "{\"turn\":7,", 1);
        assert_eq!(rewritten.len(), text.len());
        let mut file = std::fs::OpenOptions::new().write(true).open(&log).unwrap();
        file.write_all(rewritten.as_bytes()).unwrap();
        drop(file);
        assert_eq!(put(&known, "c"), (3, range(3, 3)));
        // Another writer appends a line of turn 9: the length changed, so the log is read
        // again and the next turn follows it.
        let mut file = std::fs::OpenOptions::new().append(true).open(&log).unwrap();
        file.write_all(
            b"{\"turn\":9,\"seq\":0,\"ts\":\"t\",\"role\":\"user\",\"content\":\"x\"}\n",
        )
        .unwrap();
        drop(file);
        assert_eq!(put(&known, "d"), (10, range(5, 5)));
        // A state that knows nothing reads the log from its first byte.
        assert_eq!(put(&KnownLogs::default(), "e"), (11, range(6, 6)));
    }

    /// A turn is read whole or not at all: one whose first lines lie past the byte cap, or one
    /// of whose lines does not parse, is left out.
    #[test]
    fn a_turn_the_read_did_not_get_whole_is_left_out() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("llm-turns.jsonl");
        for turn in 1..=3 {
            append(
                &log,
                turn,
                &[
                    user(&format!("prompt {turn}")),
                    assistant("first"),
                    assistant("second"),
                ],
            );
        }
        let wanted: BTreeSet<u32> = [2, 3].into_iter().collect();
        let keys = |read: BTreeMap<u32, Vec<TurnLogLine>>| read.keys().copied().collect::<Vec<_>>();
        assert_eq!(keys(read_turns_from_tail(&log, &wanted, u64::MAX)), [2, 3]);
        // A cap that ends inside turn 2's first line: its other two lines are read, and it is
        // left out; turn 3 is whole.
        let text = std::fs::read_to_string(&log).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        let cap: u64 = lines[4..].iter().map(|l| l.len() as u64 + 1).sum::<u64>() + 1;
        assert_eq!(keys(read_turns_from_tail(&log, &wanted, cap)), [3]);
        // Turn 3's middle line does not parse: turn 3 is left out, turn 2 is whole.
        let mut broken = lines.clone();
        broken[7] = "{\"turn\":3,\"seq\":1,";
        std::fs::write(&log, format!("{}\n", broken.join("\n"))).unwrap();
        let read = read_turns_from_tail(&log, &wanted, u64::MAX);
        assert_eq!(read.keys().copied().collect::<Vec<_>>(), [2]);
        assert_eq!(read[&2].len(), 3);
    }
}

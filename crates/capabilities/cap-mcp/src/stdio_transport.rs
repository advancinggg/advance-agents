//! `StdioMcpTransport` — the stdio MCP transport (MODULE-017 AC-17).
//!
//! Spawns the server as a subprocess with stdin/stdout/stderr piped and speaks
//! newline-delimited JSON-RPC 2.0 over stdin/stdout. Every line in either
//! direction passes the configured `Arc<dyn LeakDetector>` before it is
//! written or decoded.
//!
//! ## Lifecycle + cleanup
//!
//! - The subprocess runs with a cleared environment (only the explicit `env`
//!   map, which is the child's whole environment), in the working directory
//!   [`StdioOptions::cwd`] (default `/`), and leads its own process group, so
//!   one signal reaches every process it starts (wrappers such as `npx` or `uvx`
//!   start grandchildren). A working directory that is not a directory fails the
//!   spawn with an error naming it. A `command` that is a bare name (no `/`) is
//!   looked up on the `PATH` of that environment (the system's default search
//!   path when it sets none).
//! - The child is spawned, and its reader / writer / stderr tasks run, on the
//!   runtime named by [`StdioOptions::runtime`] (default: the current one). The
//!   transport therefore keeps working after the runtime of the call that
//!   created it has shut down.
//! - The transport closes when the server's stdout ends, a stdout line overflows
//!   the line cap, a read fails, stdin cannot be written, or its owner closes it
//!   ([`StdioMcpTransport::close`]). Closing records when it happened
//!   ([`McpTransport::closed_at`]), fails every pending call, makes later calls
//!   fail fast, turns [`McpTransport::is_closed`] true and kills the process
//!   group.
//! - `Drop` aborts the tasks, kills the process group while the child is still
//!   unreaped (so the group id cannot name a recycled group), then kills the
//!   child; `kill_on_drop(true)` covers a panic between spawn and return.
//!
//! ## Server-to-client traffic
//!
//! A line carrying `method` comes from the server and never resolves a pending
//! call, whatever its `id`. A `ping` request is answered with an empty result,
//! any other request with JSON-RPC error -32601 (method not found), and
//! notifications are dropped. Only a request whose id is a number or a string of
//! at most `MAX_SERVER_REQUEST_ID_BYTES` is answered; one with a longer string
//! id is dropped unanswered, so the replies queued for a server that does not
//! read its stdin stay small. A response is read only when it answers a call
//! still waiting; one for an id that was never issued, was already answered or
//! was abandoned is dropped unread. A JSON array line is read as a batch of
//! messages.
//!
//! ## Bounds
//!
//! - `MAX_STDIO_REQ_BYTES = 4 MiB` — outgoing message cap.
//! - [`StdioOptions::max_line_bytes`] (default `MAX_STDIO_LINE_BYTES = 4 MiB`) —
//!   stdout line cap, enforced while reading: no more than the cap is buffered.
//! - [`StdioOptions::request_timeout`] (default `MAX_STDIO_WALL_CLOCK = 30 s`) —
//!   per-call budget over sending the request and receiving its answer.
//! - Host log. stderr is never delivered to a caller: it is read line by line,
//!   keeping at most `MAX_STDERR_LINE_BYTES` of each line. stderr lines and the
//!   message of a JSON-RPC error answering a waiting call (at most
//!   `MAX_LOGGED_ERROR_BYTES` of it) go to the host log with control, invisible
//!   and bidi characters replaced. They share one budget per transport: at most
//!   `LOG_LINES_PER_WINDOW` lines per `LOG_WINDOW`. Lines over the budget are
//!   dropped and counted; the count is logged with the first line of a later
//!   window, or when stderr ends or the transport closes.

use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use advance_shared_types::mcp::is_tool_name_safe;
use advance_shared_types::process_policy::{ProcessPolicy, SpawnSite};
use advance_shared_types::security_validator::{LeakDetector, ScanContext, ScanResult};
use async_trait::async_trait;
use serde_json::Value;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command};
use tokio::runtime::Handle;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::client::McpTransport;
use crate::error::McpError;
use crate::jsonrpc::{JsonRpcNotification, JsonRpcRequest};

#[cfg(test)]
use crate::error::McpErrorKind;

pub const MAX_STDIO_REQ_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_STDIO_LINE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_STDIO_WALL_CLOCK: Duration = Duration::from_secs(30);

/// Longest part of one stderr line that is kept and logged, in bytes. The rest
/// of a longer line is read and dropped.
pub const MAX_STDERR_LINE_BYTES: usize = 2048;

/// Host log lines one transport may write within one [`LOG_WINDOW`]: its stderr
/// lines and the error messages of its JSON-RPC answers together. Further lines
/// in the window are counted and reported in one line.
pub const LOG_LINES_PER_WINDOW: u32 = 100;

/// Length of the host logging window.
pub const LOG_WINDOW: Duration = Duration::from_secs(60);

/// Messages queued for the writer task before senders wait.
const WRITER_QUEUE: usize = 64;

/// JSON-RPC error code for a method the receiver does not implement.
const METHOD_NOT_FOUND: i64 = -32601;

/// Longest server-supplied error message copied into the host log, in bytes.
const MAX_LOGGED_ERROR_BYTES: usize = 512;

/// Longest string id of a server request that is answered, in bytes. A request
/// with a longer string id is dropped unanswered: echoing such ids would let a
/// server that never reads its stdin fill the writer queue with large replies.
const MAX_SERVER_REQUEST_ID_BYTES: usize = 128;

/// How a stdio transport runs.
#[derive(Clone, Debug)]
pub struct StdioOptions {
    /// Budget for one call: sending the request and receiving its answer.
    pub request_timeout: Duration,
    /// Longest stdout line accepted, in bytes (terminator excluded). A longer
    /// line closes the transport without being buffered past this cap.
    pub max_line_bytes: usize,
    /// Runtime that spawns the child and runs the transport's tasks. `None`:
    /// the runtime current when the transport is spawned.
    pub runtime: Option<Handle>,
    /// Whether this composition may start child processes. Under
    /// [`ProcessPolicy::Forbid`] the spawn answers a typed refusal
    /// (`stdio: process_forbidden: … (MCP stdio server)`) and nothing is started.
    pub process_policy: ProcessPolicy,
    /// The child's working directory. `None`: `/`.
    pub cwd: Option<PathBuf>,
}

impl Default for StdioOptions {
    fn default() -> Self {
        Self {
            request_timeout: MAX_STDIO_WALL_CLOCK,
            max_line_bytes: MAX_STDIO_LINE_BYTES,
            runtime: None,
            process_policy: ProcessPolicy::Allow,
            cwd: None,
        }
    }
}

/// Slot in the `pending` map — the invoke caller's oneshot sender for the
/// response of a particular JSON-RPC id.
type PendingSlot = oneshot::Sender<Result<Vec<u8>, McpError>>;

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

struct Inner {
    /// JSON-RPC id → invoke caller's response channel.
    pending: Mutex<HashMap<u64, PendingSlot>>,
    next_id: AtomicU64,
    leak_detector: Arc<dyn LeakDetector>,
    server_id: String,
    /// Set, under the `pending` lock and after `close_record`, once the
    /// transport can carry no more calls; a call registering afterwards sees it
    /// and fails fast.
    closed: AtomicBool,
    /// Why and when the transport closed.
    close_record: Mutex<Option<CloseRecord>>,
    /// The budget of host log lines this transport may write (see the module
    /// docs).
    log_budget: Mutex<LogBudget>,
    group: ProcessGroup,
}

/// Why and when a transport closed.
struct CloseRecord {
    /// The error later calls get.
    reason: String,
    /// When the transport closed.
    at: Instant,
}

impl Inner {
    fn new(server_id: String, leak_detector: Arc<dyn LeakDetector>, group: ProcessGroup) -> Self {
        Self {
            pending: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
            leak_detector,
            server_id,
            closed: AtomicBool::new(false),
            close_record: Mutex::new(None),
            log_budget: Mutex::new(LogBudget::new(Instant::now())),
            group,
        }
    }

    /// Register a pending call, unless the transport has closed.
    fn register(&self, id: u64, slot: PendingSlot) -> Result<(), McpError> {
        let mut pending = lock(&self.pending);
        if self.closed.load(Ordering::SeqCst) {
            return Err(self.closed_error());
        }
        pending.insert(id, slot);
        Ok(())
    }

    /// The error a call gets once the transport has closed.
    fn closed_error(&self) -> McpError {
        let reason = lock(&self.close_record)
            .as_ref()
            .map(|record| record.reason.clone());
        McpError::transport(reason.unwrap_or_else(|| "subprocess channel closed".to_string()))
    }

    /// When the transport closed; `None` while it is open.
    fn closed_at(&self) -> Option<Instant> {
        lock(&self.close_record).as_ref().map(|record| record.at)
    }

    /// Close the transport: record the first reason and when it happened, fail
    /// every pending call with it (in id order), kill the process group and log
    /// the count of suppressed log lines.
    fn close(&self, reason: &str) {
        let drained: Vec<(u64, PendingSlot)> = {
            let mut pending = lock(&self.pending);
            {
                let mut record = lock(&self.close_record);
                if record.is_none() {
                    *record = Some(CloseRecord {
                        reason: reason.to_string(),
                        at: Instant::now(),
                    });
                }
            }
            self.closed.store(true, Ordering::SeqCst);
            let mut entries: Vec<(u64, PendingSlot)> = pending.drain().collect();
            entries.sort_by_key(|(id, _)| *id);
            entries
        };
        self.group.kill();
        self.flush_log();
        let error = self.closed_error();
        for (_, tx) in drained {
            let _ = tx.send(Err(error.clone()));
        }
    }

    /// Write one line about this server to the host log, unless the
    /// transport's log budget for the current window is spent. `line` is built
    /// only when the line is written.
    fn log(&self, line: impl FnOnce() -> String) {
        let (admitted, suppressed) = lock(&self.log_budget).admit(Instant::now());
        if let Some(count) = suppressed {
            self.log_suppressed(count);
        }
        if admitted {
            eprintln!("[cap_mcp stdio:{}] {}", self.server_id, line());
        }
    }

    /// Log how many lines the budget has suppressed in its current window, if
    /// any.
    fn flush_log(&self) {
        let suppressed = lock(&self.log_budget).take_suppressed();
        if let Some(count) = suppressed {
            self.log_suppressed(count);
        }
    }

    fn log_suppressed(&self, count: u64) {
        eprintln!(
            "[cap_mcp stdio:{}] {count} log lines suppressed",
            self.server_id
        );
    }
}

/// The child's process group. The child leads it (`process_group(0)`), so the
/// group id is the child's pid. The id is signalled only while the transport
/// still owns the unreaped child, which keeps the id from being reused.
struct ProcessGroup {
    pgid: Mutex<Option<i32>>,
}

impl ProcessGroup {
    fn new(pid: Option<u32>) -> Self {
        // A group id of 0 or 1 would address this process's own group or every
        // process; a child never has either pid.
        let pgid = pid.and_then(|p| i32::try_from(p).ok()).filter(|p| *p > 1);
        Self {
            pgid: Mutex::new(pgid),
        }
    }

    /// SIGKILL every process in the group.
    fn kill(&self) {
        if let Some(pgid) = *lock(&self.pgid) {
            kill_group(pgid);
        }
    }

    /// Kill the group and forget its id: called right before the child is
    /// released, after which it may be reaped and its id reused.
    fn kill_and_release(&self) {
        if let Some(pgid) = lock(&self.pgid).take() {
            kill_group(pgid);
        }
    }
}

#[cfg(unix)]
fn kill_group(pgid: i32) {
    // SAFETY: a plain syscall on the group the child leads; `pgid > 1` (see
    // `ProcessGroup::new`), so it never addresses this process's group or `-1`.
    unsafe {
        libc::kill(-pgid, libc::SIGKILL);
    }
}

#[cfg(not(unix))]
fn kill_group(_pgid: i32) {}

/// A message for the writer task.
enum Outbound {
    /// A request; a failure to send it is delivered to its pending slot.
    Request(JsonRpcRequest),
    /// A notification and the channel that learns whether it was written.
    Notification(JsonRpcNotification, oneshot::Sender<Result<(), McpError>>),
    /// The answer to a server request.
    Reply(Value),
}

/// Who learns the outcome of writing one [`Outbound`] message.
enum Completion {
    Request(u64),
    Notification(oneshot::Sender<Result<(), McpError>>),
    Reply,
}

impl Completion {
    fn fail(self, inner: &Inner, error: McpError) {
        match self {
            Completion::Request(id) => send_pending(inner, id, Err(error)),
            Completion::Notification(ack) => {
                let _ = ack.send(Err(error));
            }
            Completion::Reply => {}
        }
    }

    fn written(self) {
        if let Completion::Notification(ack) = self {
            let _ = ack.send(Ok(()));
        }
    }
}

struct TaskHandles {
    reader: JoinHandle<()>,
    writer: JoinHandle<()>,
    stderr: JoinHandle<()>,
}

pub struct StdioMcpTransport {
    inner: Arc<Inner>,
    writer_tx: mpsc::Sender<Outbound>,
    task_handles: TaskHandles,
    /// Stored as Option so Drop can `.take()` and call `start_kill(&mut self)`.
    child: Option<Child>,
    wall_clock: Duration,
}

impl std::fmt::Debug for StdioMcpTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StdioMcpTransport")
            .field("server_id", &self.inner.server_id)
            .field("wall_clock", &self.wall_clock)
            .finish_non_exhaustive()
    }
}

impl StdioMcpTransport {
    /// Spawn the subprocess and start the reader / writer / stderr tasks on the
    /// current runtime, with the default limits. Returns a transport ready for
    /// `invoke`; it does not run the MCP `initialize` handshake.
    pub fn spawn(
        server_id: impl Into<String>,
        command: &str,
        args: &[String],
        env: &BTreeMap<String, String>,
        leak_detector: Arc<dyn LeakDetector>,
    ) -> Result<Self, McpError> {
        Self::spawn_with_options(
            server_id,
            command,
            args,
            env,
            leak_detector,
            StdioOptions::default(),
        )
    }

    /// [`spawn`](Self::spawn) with a different per-call budget.
    pub fn spawn_with_wall_clock(
        server_id: impl Into<String>,
        command: &str,
        args: &[String],
        env: &BTreeMap<String, String>,
        leak_detector: Arc<dyn LeakDetector>,
        wall_clock: Duration,
    ) -> Result<Self, McpError> {
        Self::spawn_with_options(
            server_id,
            command,
            args,
            env,
            leak_detector,
            StdioOptions {
                request_timeout: wall_clock,
                ..StdioOptions::default()
            },
        )
    }

    /// [`spawn`](Self::spawn) with explicit limits, runtime and working
    /// directory. A working directory that does not exist or is not a directory
    /// fails the spawn with an error naming it.
    pub fn spawn_with_options(
        server_id: impl Into<String>,
        command: &str,
        args: &[String],
        env: &BTreeMap<String, String>,
        leak_detector: Arc<dyn LeakDetector>,
        options: StdioOptions,
    ) -> Result<Self, McpError> {
        if command.is_empty() {
            return Err(McpError::transport("stdio: empty command"));
        }
        if let Err(refusal) = options.process_policy.admit(SpawnSite::McpStdio) {
            return Err(McpError::transport(format!("stdio: {refusal}")));
        }
        let runtime = match options.runtime {
            Some(runtime) => runtime,
            None => Handle::try_current()
                .map_err(|_| McpError::transport("stdio: no tokio runtime to run the transport"))?,
        };
        // The subprocess does not inherit the host's working directory: it runs
        // in the configured one, or in `/`. Checked here, so a directory that
        // cannot serve is named in the error (a failed spawn would not say
        // whether the command or the directory was missing).
        let cwd = options.cwd.as_deref().unwrap_or(Path::new("/"));
        match std::fs::metadata(cwd) {
            Ok(meta) if meta.is_dir() => {}
            Ok(_) => {
                return Err(McpError::transport(format!(
                    "stdio: working directory {} is not a directory",
                    cwd.display()
                )))
            }
            Err(e) => {
                return Err(McpError::transport(format!(
                    "stdio: working directory {} cannot be used: {e}",
                    cwd.display()
                )))
            }
        }
        // The child's pipes belong to the runtime that is current when it is
        // spawned, so spawn inside the transport's runtime.
        let _runtime_context = runtime.enter();

        let mut cmd = Command::new(command);
        cmd.args(args)
            // Only the explicit `env` map reaches the subprocess: the host's
            // environment (cloud credentials, API keys, service tokens) is not
            // inherited. A `command` that is a bare name is looked up on that
            // map's `PATH`, or on the system's default search path without one.
            .env_clear()
            .envs(env.iter())
            .current_dir(cwd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        // The child leads a new process group, so killing the group also stops
        // the processes it starts.
        #[cfg(unix)]
        {
            cmd.process_group(0);
        }

        let mut child = cmd
            .spawn()
            .map_err(|e| McpError::transport(format!("stdio: spawn failed: {e}")))?;
        let group = ProcessGroup::new(child.id());

        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| McpError::transport("stdio: stdin handle missing"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| McpError::transport("stdio: stdout handle missing"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| McpError::transport("stdio: stderr handle missing"))?;

        let inner = Arc::new(Inner::new(server_id.into(), leak_detector, group));

        let (writer_tx, writer_rx) = mpsc::channel::<Outbound>(WRITER_QUEUE);

        let reader = runtime.spawn(reader_task(
            Arc::clone(&inner),
            stdout,
            writer_tx.clone(),
            options.max_line_bytes,
        ));
        let writer = runtime.spawn(writer_task(Arc::clone(&inner), writer_rx, stdin));
        let stderr = runtime.spawn(stderr_task(Arc::clone(&inner), stderr));

        Ok(Self {
            inner,
            writer_tx,
            task_handles: TaskHandles {
                reader,
                writer,
                stderr,
            },
            child: Some(child),
            wall_clock: options.request_timeout,
        })
    }

    pub fn server_id(&self) -> &str {
        &self.inner.server_id
    }

    /// True once the transport has closed (see the module docs).
    pub fn is_closed(&self) -> bool {
        self.inner.closed.load(Ordering::SeqCst)
    }

    /// When the transport closed; `None` while it is open.
    pub fn closed_at(&self) -> Option<Instant> {
        self.inner.closed_at()
    }

    /// Close the transport now (see the module docs): the calls waiting on it
    /// fail, later calls fail fast and the server's process group is killed.
    /// A transport that has already closed keeps its first reason.
    pub fn close(&self) {
        self.inner.close("the transport was closed");
    }

    /// Invoke a JSON-RPC method. Allocates a fresh id, registers a oneshot
    /// channel into `pending`, sends the request to the writer task, and awaits
    /// the response; the per-call budget covers both the send and the wait.
    /// A closed transport fails at once. However the call ends (answer, error,
    /// timeout or the caller dropping it), its pending slot is removed.
    pub async fn invoke(&self, method: &str, params: Value) -> Result<Vec<u8>, McpError> {
        let id = self.inner.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.inner.register(id, tx)?;
        let _slot = PendingGuard {
            inner: &self.inner,
            id,
        };

        let request = Outbound::Request(JsonRpcRequest::new(id, method, params));
        let exchange = async {
            if self.writer_tx.send(request).await.is_err() {
                return Err(self.inner.closed_error());
            }
            match rx.await {
                Ok(result) => result,
                Err(_recv_err) => Err(self.inner.closed_error()),
            }
        };
        match tokio::time::timeout(self.wall_clock, exchange).await {
            Ok(result) => result,
            Err(_timeout) => Err(McpError::transport("wall-clock timeout")),
        }
    }

    /// Send a JSON-RPC notification (no id; the server never answers it). The
    /// call returns once the message is written to the server's stdin, within
    /// the per-call budget.
    pub async fn notify(&self, method: &str, params: Option<Value>) -> Result<(), McpError> {
        if self.is_closed() {
            return Err(self.inner.closed_error());
        }
        let (ack_tx, ack_rx) = oneshot::channel();
        let message = Outbound::Notification(JsonRpcNotification::new(method, params), ack_tx);
        let exchange = async {
            if self.writer_tx.send(message).await.is_err() {
                return Err(self.inner.closed_error());
            }
            match ack_rx.await {
                Ok(result) => result,
                Err(_recv_err) => Err(self.inner.closed_error()),
            }
        };
        match tokio::time::timeout(self.wall_clock, exchange).await {
            Ok(result) => result,
            Err(_timeout) => Err(McpError::transport("wall-clock timeout")),
        }
    }
}

/// Removes a call's pending slot when the call ends, however it ends.
struct PendingGuard<'a> {
    inner: &'a Inner,
    id: u64,
}

impl Drop for PendingGuard<'_> {
    fn drop(&mut self) {
        lock(&self.inner.pending).remove(&self.id);
    }
}

// A stdio server is a local process the host started: a call through it is
// attributed to no one, so `caller` is not used.
#[async_trait]
impl McpTransport for StdioMcpTransport {
    async fn invoke(
        &self,
        _caller: Option<&str>,
        method: &str,
        params: Value,
    ) -> Result<Vec<u8>, McpError> {
        StdioMcpTransport::invoke(self, method, params).await
    }

    async fn notify(&self, method: &str, params: Option<Value>) -> Result<(), McpError> {
        StdioMcpTransport::notify(self, method, params).await
    }

    fn server_id(&self) -> &str {
        &self.inner.server_id
    }

    fn closed_at(&self) -> Option<Instant> {
        StdioMcpTransport::closed_at(self)
    }

    fn is_closed(&self) -> bool {
        StdioMcpTransport::is_closed(self)
    }

    fn close(&self) {
        StdioMcpTransport::close(self);
    }
}

impl Drop for StdioMcpTransport {
    fn drop(&mut self) {
        self.task_handles.reader.abort();
        self.task_handles.writer.abort();
        self.task_handles.stderr.abort();
        self.inner.close("subprocess channel closed");
        // Kill the group while the child is still unreaped, then release the id:
        // once the child is dropped it may be reaped and the id reused.
        self.inner.group.kill_and_release();
        if let Some(mut child) = self.child.take() {
            // A failed SIGKILL delivery is reported for operators;
            // `kill_on_drop(true)` still fires when the child drops.
            if let Err(e) = child.start_kill() {
                eprintln!(
                    "[cap_mcp stdio:{}] start_kill failed: {}",
                    self.inner.server_id, e
                );
            }
        }
    }
}

/// Outcome of reading one stdout line.
#[derive(Debug, PartialEq, Eq)]
enum LineRead {
    /// A complete line is in the buffer (terminator removed).
    Line,
    /// The stream ended between lines.
    Eof,
    /// The stream ended inside a line.
    PartialAtEof,
    /// The line is longer than the cap; the read stopped at the cap.
    Overflow,
}

/// Read one `\n`-terminated line into `line` (terminator excluded), buffering
/// at most `max` bytes: a longer line stops the read with
/// [`LineRead::Overflow`] instead of being buffered whole.
async fn read_line_bounded<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    line: &mut Vec<u8>,
    max: usize,
) -> std::io::Result<LineRead> {
    line.clear();
    loop {
        let (used, complete) = {
            let available = reader.fill_buf().await?;
            if available.is_empty() {
                return Ok(if line.is_empty() {
                    LineRead::Eof
                } else {
                    LineRead::PartialAtEof
                });
            }
            match available.iter().position(|&b| b == b'\n') {
                Some(end) => {
                    if line.len() + end > max {
                        return Ok(LineRead::Overflow);
                    }
                    line.extend_from_slice(&available[..end]);
                    (end + 1, true)
                }
                None => {
                    if line.len() + available.len() > max {
                        return Ok(LineRead::Overflow);
                    }
                    line.extend_from_slice(available);
                    (available.len(), false)
                }
            }
        };
        reader.consume(used);
        if complete {
            return Ok(LineRead::Line);
        }
    }
}

/// Read one `\n`-terminated line, keeping at most `max` bytes of it in `line`
/// (terminator excluded); the rest of a longer line is read and dropped.
/// Returns `None` at the end of the stream, otherwise whether the line was cut.
async fn read_line_capped<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    line: &mut Vec<u8>,
    max: usize,
) -> std::io::Result<Option<bool>> {
    line.clear();
    let mut cut = false;
    let mut read_any = false;
    loop {
        let (used, complete) = {
            let available = reader.fill_buf().await?;
            if available.is_empty() {
                return Ok(read_any.then_some(cut));
            }
            read_any = true;
            let (chunk, used, complete) = match available.iter().position(|&b| b == b'\n') {
                Some(end) => (&available[..end], end + 1, true),
                None => (available, available.len(), false),
            };
            let keep = chunk.len().min(max.saturating_sub(line.len()));
            line.extend_from_slice(&chunk[..keep]);
            cut |= keep < chunk.len();
            (used, complete)
        };
        reader.consume(used);
        if complete {
            return Ok(Some(cut));
        }
    }
}

/// Reader task — reads newline-delimited JSON-RPC messages from stdout under
/// the line cap, leak-scans each line, routes responses to their pending calls
/// and answers server requests. Closes the transport when stdout ends, a line
/// overflows or a read fails.
async fn reader_task(
    inner: Arc<Inner>,
    stdout: ChildStdout,
    replies: mpsc::Sender<Outbound>,
    max_line_bytes: usize,
) {
    let mut reader = BufReader::new(stdout);
    let mut line: Vec<u8> = Vec::with_capacity(4096);
    loop {
        match read_line_bounded(&mut reader, &mut line, max_line_bytes).await {
            Ok(LineRead::Line) => {
                handle_line(&inner, &replies, &line);
                // Do not keep a buffer sized for one huge answer alive.
                if line.capacity() > 1024 * 1024 {
                    line = Vec::with_capacity(4096);
                }
            }
            Ok(LineRead::Eof) => return inner.close("subprocess closed"),
            Ok(LineRead::PartialAtEof) => return inner.close("subprocess exited mid-line"),
            Ok(LineRead::Overflow) => {
                return inner.close(&format!("response line exceeds {max_line_bytes} bytes"))
            }
            Err(io_err) => return inner.close(&format!("subprocess exited: {io_err}")),
        }
    }
}

/// Decode one stdout line (terminator removed) and act on each message in it.
fn handle_line(inner: &Inner, replies: &mpsc::Sender<Outbound>, raw: &[u8]) {
    let raw = raw.strip_suffix(b"\r").unwrap_or(raw);
    // A line that is not UTF-8 or not JSON answers nothing; a call waiting for
    // an answer times out.
    let Ok(text) = std::str::from_utf8(raw) else {
        return;
    };
    if text.trim().is_empty() {
        return;
    }
    // Leak scan before decoding.
    let scanned: Cow<'_, str> = match inner.leak_detector.scan(text, ScanContext::HttpInbound) {
        ScanResult::Clean | ScanResult::Warned { .. } => Cow::Borrowed(text),
        ScanResult::Redacted { redacted, .. } => Cow::Owned(redacted),
        ScanResult::Blocked { .. } => {
            // Fail the calls this line answers; server traffic in it is dropped.
            if let Ok(value) = serde_json::from_str::<Value>(text) {
                for message in into_messages(value) {
                    if let Some(id) = response_id(&message) {
                        send_pending(
                            inner,
                            id,
                            Err(McpError::invalid_response("inbound leak detected")),
                        );
                    }
                }
            }
            return;
        }
    };
    let Ok(value) = serde_json::from_str::<Value>(&scanned) else {
        return;
    };
    for message in into_messages(value) {
        match classify(message) {
            Incoming::Response { id, body } => {
                // Only the answer to a call still waiting is read. An answer for
                // an id that was never issued, was already answered or was
                // abandoned is dropped unread, so it never reaches the host log.
                if let Some(slot) = take_pending(inner, id) {
                    let _ = slot.send(response_outcome(inner, id, body));
                }
            }
            Incoming::Request { id, method } => {
                // A full writer queue drops the answer rather than stalling the
                // reader behind the writer.
                let _ = replies.try_send(Outbound::Reply(reply_to(id, &method)));
            }
            Incoming::Notification | Incoming::Invalid => {}
        }
    }
}

/// The messages in one decoded line: the elements of a batch, or the value.
fn into_messages(value: Value) -> Vec<Value> {
    match value {
        Value::Array(items) => items,
        other => vec![other],
    }
}

/// One decoded message, by what it is.
#[derive(Debug, PartialEq)]
enum Incoming {
    /// An answer to one of this client's requests.
    Response {
        id: u64,
        body: serde_json::Map<String, Value>,
    },
    /// A request from the server that gets an answer: it carries `method` and
    /// an id short enough to echo.
    Request { id: Value, method: String },
    /// A notification from the server (`method` without a usable id).
    Notification,
    /// Anything else, including a server request whose string id is too long
    /// to echo.
    Invalid,
}

/// Classify a message. A message carrying `method` is server traffic and never
/// a response, whatever its `id`; only an id this client can have issued (an
/// unsigned integer) makes a response. A server request is answerable when its
/// id is a number (a fixed-size value) or a string of at most
/// [`MAX_SERVER_REQUEST_ID_BYTES`].
fn classify(message: Value) -> Incoming {
    let Value::Object(mut body) = message else {
        return Incoming::Invalid;
    };
    if let Some(method) = body.remove("method") {
        let method = method.as_str().unwrap_or_default().to_string();
        return match body.remove("id") {
            Some(id @ Value::Number(_)) => Incoming::Request { id, method },
            Some(Value::String(id)) if id.len() <= MAX_SERVER_REQUEST_ID_BYTES => {
                Incoming::Request {
                    id: Value::String(id),
                    method,
                }
            }
            // Too long to echo back: the request is dropped unanswered.
            Some(Value::String(_)) => Incoming::Invalid,
            _ => Incoming::Notification,
        };
    }
    match body.get("id").and_then(Value::as_u64) {
        Some(id) => Incoming::Response { id, body },
        None => Incoming::Invalid,
    }
}

/// The id of a message that answers one of this client's requests.
fn response_id(message: &Value) -> Option<u64> {
    let body = message.as_object()?;
    if body.contains_key("method") {
        return None;
    }
    body.get("id").and_then(Value::as_u64)
}

/// The outcome of a response for the call it answers. A server-supplied error
/// message never reaches the caller (it could carry injected instructions or
/// exfiltrated data): the caller sees the JSON-RPC error code, and the message
/// goes to the host log, sanitized and within the transport's log budget.
fn response_outcome(
    inner: &Inner,
    id: u64,
    mut body: serde_json::Map<String, Value>,
) -> Result<Vec<u8>, McpError> {
    if let Some(error) = body.remove("error").filter(|e| !e.is_null()) {
        let code = error
            .get("code")
            .and_then(Value::as_i64)
            .map_or_else(|| "?".to_string(), |c| c.to_string());
        let message = error
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or_default();
        inner.log(|| {
            format!(
                "server error id={id} code={code} message={}",
                sanitize_log_text(message.as_bytes(), MAX_LOGGED_ERROR_BYTES)
            )
        });
        return Err(McpError::server_error(format!("jsonrpc error code {code}")));
    }
    match body.remove("result") {
        Some(result) => serde_json::to_vec(&result)
            .map_err(|e| McpError::invalid_response(format!("serialize result: {e}"))),
        None => Err(McpError::invalid_response(
            "jsonrpc response missing both result and error",
        )),
    }
}

/// The answer to a server request: an empty result for `ping`, error -32601
/// for anything else (this client offers no other server-callable method).
fn reply_to(id: Value, method: &str) -> Value {
    if method == "ping" {
        serde_json::json!({"jsonrpc": "2.0", "id": id, "result": {}})
    } else {
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {"code": METHOD_NOT_FOUND, "message": "Method not found"},
        })
    }
}

/// Writer task — receives requests, notifications and replies, serializes
/// them, enforces `MAX_STDIO_REQ_BYTES`, leak-scans them and writes each as one
/// line to stdin. A message refused before writing fails only its own caller;
/// a failed write closes the transport.
async fn writer_task(inner: Arc<Inner>, mut rx: mpsc::Receiver<Outbound>, mut stdin: ChildStdin) {
    while let Some(message) = rx.recv().await {
        let (body, completion) = match message {
            Outbound::Request(req) => {
                let id = req.id;
                (serde_json::to_vec(&req), Completion::Request(id))
            }
            Outbound::Notification(note, ack) => {
                (serde_json::to_vec(&note), Completion::Notification(ack))
            }
            Outbound::Reply(reply) => (serde_json::to_vec(&reply), Completion::Reply),
        };
        let line = match body
            .map_err(|e| McpError::invalid_response(format!("serialize request: {e}")))
            .and_then(|body| outbound_line(&inner, body))
        {
            Ok(line) => line,
            Err(error) => {
                completion.fail(&inner, error);
                continue;
            }
        };
        // Body and newline go out in one `write_all`. A write can still stop
        // part-way before EPIPE; the transport then closes, and the partial line
        // never gets a terminator.
        if let Err(e) = stdin.write_all(&line).await {
            let reason = format!("subprocess stdin write: {e}");
            completion.fail(&inner, McpError::transport(reason.clone()));
            inner.close(&reason);
            return;
        }
        if let Err(e) = stdin.flush().await {
            let reason = format!("subprocess stdin flush: {e}");
            completion.fail(&inner, McpError::transport(reason.clone()));
            inner.close(&reason);
            return;
        }
        completion.written();
    }
}

/// Check one serialized message against the size cap and the outbound leak
/// scan (redacting when the detector redacts), and terminate it with `\n`.
/// The scan covers what an agent might put in tool-call params, as the HTTP
/// transport's security chain does.
fn outbound_line(inner: &Inner, mut body: Vec<u8>) -> Result<Vec<u8>, McpError> {
    if body.len() > MAX_STDIO_REQ_BYTES {
        return Err(McpError::transport(format!(
            "request exceeds {MAX_STDIO_REQ_BYTES} bytes"
        )));
    }
    let body_str = std::str::from_utf8(&body)
        .map_err(|_| McpError::invalid_response("request body not utf-8"))?;
    match inner
        .leak_detector
        .scan(body_str, ScanContext::HttpOutbound)
    {
        ScanResult::Clean | ScanResult::Warned { .. } => {}
        ScanResult::Blocked { .. } => {
            return Err(McpError::permission_denied("outbound leak detected"));
        }
        ScanResult::Redacted { redacted, .. } => {
            body = redacted.into_bytes();
        }
    }
    body.push(b'\n');
    Ok(body)
}

/// Stderr task — logs the subprocess's stderr for host-side diagnostics,
/// sanitized and within the transport's log budget (see the module docs).
/// Never delivered to a caller.
async fn stderr_task(inner: Arc<Inner>, stderr: ChildStderr) {
    let mut reader = BufReader::new(stderr);
    let mut line: Vec<u8> = Vec::with_capacity(256);
    while let Ok(Some(cut)) = read_line_capped(&mut reader, &mut line, MAX_STDERR_LINE_BYTES).await
    {
        let raw = line.strip_suffix(b"\r").unwrap_or(&line);
        let ellipsis = if cut { " …" } else { "" };
        inner.log(|| {
            format!(
                "{}{ellipsis}",
                sanitize_log_text(raw, MAX_STDERR_LINE_BYTES)
            )
        });
    }
    inner.flush_log();
}

/// Rate limit for one transport's host log lines: at most
/// [`LOG_LINES_PER_WINDOW`] lines per [`LOG_WINDOW`].
pub(crate) struct LogBudget {
    window_start: Instant,
    logged: u32,
    suppressed: u64,
}

impl LogBudget {
    pub(crate) fn new(now: Instant) -> Self {
        Self {
            window_start: now,
            logged: 0,
            suppressed: 0,
        }
    }

    /// Whether one more line may be logged at `now`, and, when a window that
    /// suppressed lines has just ended, how many it suppressed.
    pub(crate) fn admit(&mut self, now: Instant) -> (bool, Option<u64>) {
        let mut ended = None;
        if now.saturating_duration_since(self.window_start) >= LOG_WINDOW {
            ended = (self.suppressed > 0).then_some(self.suppressed);
            self.window_start = now;
            self.logged = 0;
            self.suppressed = 0;
        }
        if self.logged < LOG_LINES_PER_WINDOW {
            self.logged += 1;
            (true, ended)
        } else {
            self.suppressed += 1;
            (false, ended)
        }
    }

    /// The lines suppressed in the current window so far, if any; the count
    /// starts again from zero.
    fn take_suppressed(&mut self) -> Option<u64> {
        (self.suppressed > 0).then(|| std::mem::take(&mut self.suppressed))
    }
}

/// Server-supplied text made safe for one host log line: invalid UTF-8 becomes
/// U+FFFD, control, invisible and bidi characters (and line separators) become
/// `?`, a tab becomes a space, and the result is cut at `max_bytes` (marked
/// with `…`).
pub(crate) fn sanitize_log_text(raw: &[u8], max_bytes: usize) -> String {
    let text = String::from_utf8_lossy(raw);
    let mut out = String::with_capacity(text.len().min(max_bytes));
    for c in text.chars() {
        let c = match c {
            '\t' => ' ',
            c if is_loggable(c) => c,
            _ => '?',
        };
        if out.len() + c.len_utf8() > max_bytes {
            out.push('…');
            break;
        }
        out.push(c);
    }
    out
}

/// Whether `c` may appear as itself in a log line.
fn is_loggable(c: char) -> bool {
    // Line and paragraph separators, and the Arabic letter mark (a bidi mark),
    // on top of the characters a tool name may not hold.
    if matches!(c, '\u{2028}' | '\u{2029}' | '\u{061C}') {
        return false;
    }
    let mut buf = [0u8; 4];
    is_tool_name_safe(c.encode_utf8(&mut buf))
}

/// Remove the pending slot of call `id`, if the call is still waiting.
fn take_pending(inner: &Inner, id: u64) -> Option<PendingSlot> {
    lock(&inner.pending).remove(&id)
}

fn send_pending(inner: &Inner, id: u64, outcome: Result<Vec<u8>, McpError>) {
    // No pending slot: the caller already timed out or dropped the call.
    if let Some(tx) = take_pending(inner, id) {
        let _ = tx.send(outcome);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    fn _assert_send_sync()
    where
        StdioMcpTransport: Send + Sync,
    {
    }

    #[test]
    fn spawn_rejects_empty_command() {
        let detector = Arc::new(NoOpDetector);
        let env = BTreeMap::new();
        let err = StdioMcpTransport::spawn("srv", "", &[], &env, detector).expect_err("empty cmd");
        assert_eq!(err.kind, McpErrorKind::TransportError);
        assert!(err.message.contains("empty command"));
    }

    // The cap holds while reading: an endless line stops at the cap instead of
    // being buffered until a newline that never comes.
    #[tokio::test]
    async fn bounded_read_stops_an_endless_line_at_the_cap() {
        let mut reader = BufReader::new(tokio::io::repeat(b'x'));
        let mut line = Vec::new();
        let outcome = read_line_bounded(&mut reader, &mut line, 64 * 1024)
            .await
            .unwrap();
        assert_eq!(outcome, LineRead::Overflow);
        assert!(line.len() <= 64 * 1024, "buffered {} bytes", line.len());
    }

    #[tokio::test]
    async fn bounded_read_returns_lines_then_a_partial_line_then_eof() {
        // A tiny buffer makes every line span several fills.
        let data: &[u8] = b"first\nsecond line\n\nlast-no-newline";
        let mut reader = BufReader::with_capacity(4, data);
        let mut line = Vec::new();
        let mut seen = Vec::new();
        loop {
            let outcome = read_line_bounded(&mut reader, &mut line, 64).await.unwrap();
            seen.push((outcome, String::from_utf8(line.clone()).unwrap()));
            if !matches!(seen.last().unwrap().0, LineRead::Line) {
                break;
            }
        }
        assert_eq!(
            seen,
            vec![
                (LineRead::Line, "first".to_string()),
                (LineRead::Line, "second line".to_string()),
                (LineRead::Line, String::new()),
                (LineRead::PartialAtEof, "last-no-newline".to_string()),
            ]
        );
        let mut reader = BufReader::new(&b"exactly8\n"[..]);
        assert_eq!(
            read_line_bounded(&mut reader, &mut line, 8).await.unwrap(),
            LineRead::Line
        );
        assert_eq!(
            read_line_bounded(&mut reader, &mut line, 8).await.unwrap(),
            LineRead::Eof
        );
        let mut reader = BufReader::new(&b"ninebytes\n"[..]);
        assert_eq!(
            read_line_bounded(&mut reader, &mut line, 8).await.unwrap(),
            LineRead::Overflow
        );
    }

    #[tokio::test]
    async fn capped_read_keeps_the_head_of_a_long_line_and_drops_the_rest() {
        let long = tokio::io::repeat(b'e').take(1024 * 1024);
        let rest: &[u8] = b"\nnext\ntail";
        let mut reader = BufReader::with_capacity(512, long.chain(rest));
        let mut line = Vec::new();
        assert_eq!(
            read_line_capped(&mut reader, &mut line, 100).await.unwrap(),
            Some(true)
        );
        assert_eq!(line, vec![b'e'; 100]);
        assert_eq!(
            read_line_capped(&mut reader, &mut line, 100).await.unwrap(),
            Some(false)
        );
        assert_eq!(line, b"next");
        assert_eq!(
            read_line_capped(&mut reader, &mut line, 100).await.unwrap(),
            Some(false)
        );
        assert_eq!(line, b"tail");
        assert_eq!(
            read_line_capped(&mut reader, &mut line, 100).await.unwrap(),
            None
        );
    }

    #[test]
    fn log_text_replaces_control_invisible_and_bidi_characters_and_is_capped() {
        let raw = "ok\x1b[31mred\u{202E}evil\u{200B}x\u{2028}y\tz\u{7}".as_bytes();
        assert_eq!(sanitize_log_text(raw, 1024), "ok?[31mred?evil?x?y z?");
        assert_eq!(
            sanitize_log_text(b"bad \xff byte", 1024),
            "bad \u{FFFD} byte"
        );
        assert_eq!(sanitize_log_text(b"abcdef", 4), "abcd…");
        // A multi-byte character is never split.
        assert_eq!(sanitize_log_text("aé".as_bytes(), 2), "a…");
    }

    #[test]
    fn log_budget_admits_one_window_then_reports_what_it_suppressed() {
        let start = Instant::now();
        let mut budget = LogBudget::new(start);
        for _ in 0..LOG_LINES_PER_WINDOW {
            assert_eq!(budget.admit(start), (true, None));
        }
        assert_eq!(budget.admit(start), (false, None));
        assert_eq!(budget.admit(start), (false, None));
        let next_window = start + LOG_WINDOW;
        assert_eq!(budget.admit(next_window), (true, Some(2)));
        assert_eq!(budget.take_suppressed(), None);
        for _ in 1..LOG_LINES_PER_WINDOW {
            budget.admit(next_window);
        }
        assert_eq!(budget.admit(next_window), (false, None));
        assert_eq!(budget.take_suppressed(), Some(1));
        assert_eq!(budget.take_suppressed(), None);
    }

    fn test_inner() -> Inner {
        Inner::new(
            "srv".to_string(),
            Arc::new(NoOpDetector),
            ProcessGroup::new(None),
        )
    }

    fn error_answers(ids: std::ops::Range<u64>) -> Vec<u8> {
        let answers: Vec<Value> = ids
            .map(|id| {
                serde_json::json!({"jsonrpc": "2.0", "id": id, "error": {"code": 1, "message": "x"}})
            })
            .collect();
        serde_json::to_vec(&answers).unwrap()
    }

    // Only the answer to a waiting call is read: a batch of unsolicited error
    // answers writes no log line, and the error answer to a waiting call writes
    // one and fails that call with the code alone.
    #[test]
    fn only_answers_to_waiting_calls_are_read_and_logged() {
        let inner = test_inner();
        let (replies, _queued) = mpsc::channel(WRITER_QUEUE);
        let flood = error_answers(100..1100);
        handle_line(&inner, &replies, &flood);
        assert_eq!(lock(&inner.log_budget).logged, 0);

        let (tx, mut rx) = oneshot::channel();
        inner.register(100, tx).unwrap();
        handle_line(&inner, &replies, &flood);
        let err = rx
            .try_recv()
            .expect("the waiting call is answered")
            .expect_err("with an error");
        assert_eq!(err.kind, McpErrorKind::ServerError);
        assert_eq!(err.message, "jsonrpc error code 1");
        assert_eq!(lock(&inner.log_budget).logged, 1);
        assert!(lock(&inner.pending).is_empty());
    }

    // stderr lines and the error messages of answers draw on one budget: once
    // stderr has spent it, an error answer still fails its call, but its log
    // line is suppressed.
    #[test]
    fn stderr_lines_and_error_answers_share_one_log_budget() {
        let inner = test_inner();
        for _ in 0..LOG_LINES_PER_WINDOW {
            inner.log(|| "stderr line".to_string());
        }
        let (replies, _queued) = mpsc::channel(WRITER_QUEUE);
        let (tx, mut rx) = oneshot::channel();
        inner.register(7, tx).unwrap();
        handle_line(&inner, &replies, &error_answers(7..8));
        let err = rx.try_recv().unwrap().expect_err("an error answer");
        assert_eq!(err.kind, McpErrorKind::ServerError);
        let budget = lock(&inner.log_budget);
        assert_eq!(
            (budget.logged, budget.suppressed),
            (LOG_LINES_PER_WINDOW, 1)
        );
    }

    // A server request is answered only when its id is a number or a short
    // string: echoing longer ids would let a server that does not read pin
    // large replies in the writer queue.
    #[test]
    fn server_requests_with_an_overlong_string_id_go_unanswered() {
        let ping = |id: Value| serde_json::json!({"jsonrpc": "2.0", "id": id, "method": "ping"});
        let longest = "i".repeat(MAX_SERVER_REQUEST_ID_BYTES);
        assert!(matches!(
            classify(ping(Value::String(longest.clone()))),
            Incoming::Request { .. }
        ));
        assert_eq!(
            classify(ping(Value::String(format!("{longest}i")))),
            Incoming::Invalid
        );
        assert!(matches!(
            classify(ping(serde_json::json!(u64::MAX))),
            Incoming::Request { .. }
        ));

        let inner = test_inner();
        let (replies, mut queued) = mpsc::channel(WRITER_QUEUE);
        let long = serde_json::to_vec(&ping(Value::String("i".repeat(1 << 20)))).unwrap();
        handle_line(&inner, &replies, &long);
        assert!(queued.try_recv().is_err(), "the long id is not echoed");
        handle_line(
            &inner,
            &replies,
            br#"{"jsonrpc":"2.0","id":"s-1","method":"ping"}"#,
        );
        match queued.try_recv() {
            Ok(Outbound::Reply(reply)) => assert_eq!(reply["id"], "s-1"),
            _ => panic!("the short id is answered"),
        }
    }

    // Closing records the first reason and when it happened; a later close
    // keeps both.
    #[test]
    fn closing_records_the_first_reason_and_when() {
        let inner = test_inner();
        assert_eq!(inner.closed_at(), None);
        let before = Instant::now();
        inner.close("first");
        let at = inner.closed_at().expect("closed");
        assert!(before <= at && at <= Instant::now());
        assert!(inner.closed.load(Ordering::SeqCst));
        inner.close("second");
        assert_eq!(inner.closed_at(), Some(at));
        assert_eq!(inner.closed_error().message, "first");
        let (tx, _rx) = oneshot::channel();
        assert_eq!(inner.register(1, tx).unwrap_err().message, "first");
    }

    #[test]
    fn method_lines_are_never_responses() {
        let json = |s: &str| serde_json::from_str::<Value>(s).unwrap();
        assert!(matches!(
            classify(json(r#"{"jsonrpc":"2.0","id":1,"result":{}}"#)),
            Incoming::Response { id: 1, .. }
        ));
        assert_eq!(
            classify(json(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#)),
            Incoming::Request {
                id: json("1"),
                method: "ping".into()
            }
        );
        assert_eq!(
            classify(json(r#"{"id":"s-1","method":"roots/list","result":{}}"#)),
            Incoming::Request {
                id: json(r#""s-1""#),
                method: "roots/list".into()
            }
        );
        assert_eq!(
            classify(json(
                r#"{"jsonrpc":"2.0","method":"notifications/message"}"#
            )),
            Incoming::Notification
        );
        assert_eq!(
            classify(json(r#"{"id":null,"method":"ping"}"#)),
            Incoming::Notification
        );
        // Only an id this client can have issued names a response.
        assert_eq!(
            classify(json(r#"{"id":"1","result":{}}"#)),
            Incoming::Invalid
        );
        assert_eq!(
            classify(json(r#"{"id":-1,"result":{}}"#)),
            Incoming::Invalid
        );
        assert_eq!(classify(json("[]")), Incoming::Invalid);
        assert_eq!(response_id(&json(r#"{"id":3,"method":"ping"}"#)), None);
        assert_eq!(response_id(&json(r#"{"id":3,"error":{}}"#)), Some(3));
    }

    #[test]
    fn server_requests_get_pong_or_method_not_found() {
        assert_eq!(
            reply_to(serde_json::json!(7), "ping"),
            serde_json::json!({"jsonrpc": "2.0", "id": 7, "result": {}})
        );
        let reply = reply_to(serde_json::json!("s-1"), "sampling/createMessage");
        assert_eq!(reply["id"], "s-1");
        assert_eq!(reply["error"]["code"], METHOD_NOT_FOUND);
        assert!(reply.get("result").is_none());
    }

    // A call that ends without an answer (here: the caller gives up) leaves no
    // pending slot behind.
    #[tokio::test]
    async fn an_abandoned_call_releases_its_pending_slot() {
        let args = vec!["-c".to_string(), "read -r line; sleep 5".to_string()];
        let transport = StdioMcpTransport::spawn(
            "srv",
            "bash",
            &args,
            &BTreeMap::new(),
            Arc::new(NoOpDetector),
        )
        .expect("spawn");
        let abandoned = tokio::time::timeout(
            Duration::from_millis(100),
            transport.invoke("x", serde_json::json!({})),
        )
        .await;
        assert!(abandoned.is_err(), "the call should still be waiting");
        assert!(lock(&transport.inner.pending).is_empty());
    }

    struct NoOpDetector;

    impl LeakDetector for NoOpDetector {
        fn scan(&self, _text: &str, _ctx: ScanContext) -> ScanResult {
            ScanResult::Clean
        }
        fn scan_headers(&self, _headers: &[(String, String)]) -> ScanResult {
            ScanResult::Clean
        }
    }
}

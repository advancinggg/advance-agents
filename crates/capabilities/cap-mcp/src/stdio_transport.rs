//! `StdioMcpTransport` — MODULE-017 Slice D stdio MCP transport (AC-17).
//!
//! Spawns a subprocess via `tokio::process::Command` with `stdin/stdout/stderr`
//! piped, sends JSON-RPC 2.0 requests as newline-delimited frames on stdin,
//! reads matching responses from stdout, and routes each response through an
//! `Arc<dyn LeakDetector>` before delivering bytes to the invoke caller.
//!
//! ## Lifecycle + cleanup
//!
//! - `kill_on_drop(true)` on the spawned `Command` so a mid-setup panic
//!   between `spawn()` and `Self` return terminates the child.
//! - 3 spawned tasks (reader / writer / stderr) — each task handle stored in
//!   `task_handles` so `Drop` can `.abort()` them deterministically.
//! - `Drop` calls `child.start_kill()` (Unix SIGKILL via tokio 1.x
//!   `Child::start_kill(&mut self) -> io::Result<()>`).
//! - Pending invokes are drained on EOF / read-error / partial line / Drop.
//!
//! ## Bounds (mirror http_transport.rs symmetry)
//!
//! - `MAX_STDIO_REQ_BYTES = 4 MiB` — request body cap.
//! - `MAX_STDIO_LINE_BYTES = 4 MiB` — per-response-line cap.
//! - `MAX_STDIO_WALL_CLOCK = 30 s` — overall response-read budget.

use std::collections::HashMap;
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use advance_shared_types::security_validator::{LeakDetector, ScanContext, ScanResult};
use async_trait::async_trait;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::client::McpTransport;
use crate::error::McpError;
use crate::jsonrpc::{JsonRpcRequest, JsonRpcResponse};

#[cfg(test)]
use crate::error::McpErrorKind;

pub const MAX_STDIO_REQ_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_STDIO_LINE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_STDIO_WALL_CLOCK: Duration = Duration::from_secs(30);

/// Slot in the `pending` map — the invoke caller's oneshot sender for the
/// response of a particular JSON-RPC id.
type PendingSlot = oneshot::Sender<Result<Vec<u8>, McpError>>;

struct Inner {
    /// JSON-RPC id → invoke caller's response channel.
    pending: Mutex<HashMap<u64, PendingSlot>>,
    next_id: AtomicU64,
    leak_detector: Arc<dyn LeakDetector>,
    server_id: String,
}

struct TaskHandles {
    reader: JoinHandle<()>,
    writer: JoinHandle<()>,
    stderr: JoinHandle<()>,
}

pub struct StdioMcpTransport {
    inner: Arc<Inner>,
    writer_tx: mpsc::Sender<JsonRpcRequest>,
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
    /// Spawn the subprocess + start the reader/writer/stderr tasks. Returns a
    /// fully-initialized transport ready for `invoke`.
    pub fn spawn(
        server_id: impl Into<String>,
        command: &str,
        args: &[String],
        env: &std::collections::BTreeMap<String, String>,
        leak_detector: Arc<dyn LeakDetector>,
    ) -> Result<Self, McpError> {
        Self::spawn_with_wall_clock(
            server_id,
            command,
            args,
            env,
            leak_detector,
            MAX_STDIO_WALL_CLOCK,
        )
    }

    /// Internal constructor that allows overriding the wall-clock budget — used
    /// by tests to drive timeout cases without sleeping 30s.
    pub fn spawn_with_wall_clock(
        server_id: impl Into<String>,
        command: &str,
        args: &[String],
        env: &std::collections::BTreeMap<String, String>,
        leak_detector: Arc<dyn LeakDetector>,
        wall_clock: Duration,
    ) -> Result<Self, McpError> {
        if command.is_empty() {
            return Err(McpError::transport("stdio: empty command"));
        }
        let server_id = server_id.into();

        let mut cmd = Command::new(command);
        cmd.args(args)
            // Adversarial round 1 C1 fix: env_clear BEFORE envs() so the
            // subprocess does NOT inherit the host process's env vars
            // (which may contain AWS_ACCESS_KEY_ID, OPENAI_API_KEY,
            // DATABASE_URL, container service-account JWTs, etc.). Only
            // the explicit `env` map passed to spawn() reaches the
            // subprocess. Closes the env-leak vector to MCP subprocesses.
            .env_clear()
            .envs(env.iter())
            // Adversarial round 1 I3 fix: pin subprocess CWD to root so
            // it does NOT inherit the host's working directory (which
            // could be sensitive in deployment and would also affect
            // any relative-path resolutions inside the subprocess).
            .current_dir("/")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        let mut child = cmd
            .spawn()
            .map_err(|e| McpError::transport(format!("stdio: spawn failed: {e}")))?;

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

        let inner = Arc::new(Inner {
            pending: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
            leak_detector,
            server_id: server_id.clone(),
        });

        let (writer_tx, writer_rx) = mpsc::channel::<JsonRpcRequest>(64);

        let reader = tokio::spawn(reader_task(Arc::clone(&inner), stdout));
        let writer = tokio::spawn(writer_task(Arc::clone(&inner), writer_rx, stdin));
        let stderr = tokio::spawn(stderr_task(server_id, stderr));

        Ok(Self {
            inner,
            writer_tx,
            task_handles: TaskHandles {
                reader,
                writer,
                stderr,
            },
            child: Some(child),
            wall_clock,
        })
    }

    pub fn server_id(&self) -> &str {
        &self.inner.server_id
    }

    /// Invoke a JSON-RPC method. Allocates a fresh id, registers a oneshot
    /// channel into `pending`, sends the request to the writer task, and
    /// awaits the response under the wall-clock budget.
    ///
    /// Audit round 1 W6 fix: the wall-clock budget now wraps BOTH the
    /// `writer_tx.send().await` AND the `oneshot.recv().await`. Previously
    /// only the recv was bounded; a stuck writer (e.g. full mpsc due to slow
    /// `stdin.write_all`) could block invokes past MAX_STDIO_WALL_CLOCK.
    pub async fn invoke(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<Vec<u8>, McpError> {
        let id = self.inner.next_id.fetch_add(1, Ordering::Relaxed);
        let req = JsonRpcRequest::new(id, method, params);

        let (tx, rx) = oneshot::channel();
        {
            let mut pending = self.inner.pending.lock().expect("pending lock poisoned");
            pending.insert(id, tx);
        }

        let writer_tx = self.writer_tx.clone();
        let combined = async move {
            if writer_tx.send(req).await.is_err() {
                return Err(McpError::transport("subprocess channel closed"));
            }
            match rx.await {
                Ok(result) => result,
                Err(_recv_err) => Err(McpError::transport("subprocess channel closed")),
            }
        };

        match tokio::time::timeout(self.wall_clock, combined).await {
            Ok(result) => result.map_err(|e| {
                // Remove pending on transport-error too so the reader doesn't
                // later try to send into a dropped receiver.
                self.inner.pending.lock().expect("poison").remove(&id);
                e
            }),
            Err(_timeout) => {
                self.inner.pending.lock().expect("poison").remove(&id);
                Err(McpError::transport("wall-clock timeout"))
            }
        }
    }
}

#[async_trait]
impl McpTransport for StdioMcpTransport {
    async fn invoke(&self, method: &str, params: serde_json::Value) -> Result<Vec<u8>, McpError> {
        StdioMcpTransport::invoke(self, method, params).await
    }

    fn server_id(&self) -> &str {
        &self.inner.server_id
    }
}

impl Drop for StdioMcpTransport {
    fn drop(&mut self) {
        self.task_handles.reader.abort();
        self.task_handles.writer.abort();
        self.task_handles.stderr.abort();
        if let Some(mut child) = self.child.take() {
            // Audit round 1 Info: surface start_kill failures so operators
            // have a diagnostic signal when SIGKILL delivery itself fails.
            // The kill_on_drop(true) safety net still fires on Drop too.
            if let Err(e) = child.start_kill() {
                eprintln!(
                    "[cap_mcp stdio:{}] start_kill failed: {}",
                    self.inner.server_id, e
                );
            }
        }
        if let Ok(mut pending) = self.inner.pending.lock() {
            pending.clear();
        }
    }
}

/// Reader task — reads newline-delimited JSON-RPC responses from stdout,
/// per-line-bounded by `MAX_STDIO_LINE_BYTES`, leak-scanned via the configured
/// `LeakDetector`. Drains `pending` on EOF / partial / read-error with
/// deterministic error messages.
async fn reader_task(inner: Arc<Inner>, stdout: tokio::process::ChildStdout) {
    let mut reader = BufReader::new(stdout);
    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    loop {
        buf.clear();
        match reader.read_until(b'\n', &mut buf).await {
            Ok(0) => {
                // Clean EOF.
                drain_pending(&inner, "subprocess closed");
                return;
            }
            Ok(n) => {
                if n > MAX_STDIO_LINE_BYTES {
                    drain_pending(
                        &inner,
                        &format!("response line exceeds {MAX_STDIO_LINE_BYTES} bytes"),
                    );
                    return;
                }
                if !buf.ends_with(b"\n") {
                    // Partial line at EOF: MCP stdio mandates newline-terminated
                    // frames; treat as protocol violation.
                    drain_pending(&inner, "subprocess exited mid-line");
                    return;
                }
                // Strip trailing \n (and \r if present) for parsing.
                let line_end = buf.len()
                    - 1
                    - (if buf.len() >= 2 && buf[buf.len() - 2] == b'\r' {
                        1
                    } else {
                        0
                    });
                let line_bytes = &buf[..line_end];

                let line_str = match std::str::from_utf8(line_bytes) {
                    Ok(s) => s,
                    Err(_) => {
                        // Single bad-utf8 line: deliver an error per-pending so
                        // the in-flight invokes see something concrete. Don't
                        // exit — let the next line try to recover.
                        // (Conservative: keep going. Caller will time out if
                        // nothing valid arrives.)
                        continue;
                    }
                };

                // Leak scan BEFORE parsing — mirror security_chain.rs:228-237.
                let scan = inner.leak_detector.scan(line_str, ScanContext::HttpInbound);
                let bytes_for_parse: Vec<u8> = match scan {
                    ScanResult::Clean | ScanResult::Warned { .. } => line_bytes.to_vec(),
                    ScanResult::Blocked { .. } => {
                        // Find the response's id (best-effort) and deliver an
                        // error to that pending slot; if id can't be extracted,
                        // we can't address a specific pending — log nothing
                        // and let the caller time out.
                        if let Ok(resp) = serde_json::from_slice::<JsonRpcResponse>(line_bytes) {
                            send_pending(
                                &inner,
                                resp.id,
                                Err(McpError::invalid_response("inbound leak detected")),
                            );
                        }
                        continue;
                    }
                    ScanResult::Redacted { redacted, .. } => redacted.into_bytes(),
                };

                let resp = match serde_json::from_slice::<JsonRpcResponse>(&bytes_for_parse) {
                    Ok(r) => r,
                    Err(_) => {
                        // Unparseable line — skip; caller will time out.
                        continue;
                    }
                };

                let result = extract_result(resp);
                let id = match &result {
                    Ok((id, _)) => *id,
                    Err((id, _)) => *id,
                };
                let outcome: Result<Vec<u8>, McpError> = match result {
                    Ok((_, bytes)) => Ok(bytes),
                    Err((_, err)) => Err(err),
                };
                send_pending(&inner, id, outcome);
            }
            Err(io_err) => {
                drain_pending(&inner, &format!("subprocess exited: {io_err}"));
                return;
            }
        }
    }
}

/// Writer task — receives JSON-RPC requests over the mpsc channel, serializes
/// them, enforces `MAX_STDIO_REQ_BYTES`, writes the line + `\n` to stdin. On
/// per-request bound failure, delivers the error directly to the request's
/// pending slot rather than failing the whole writer task.
async fn writer_task(
    inner: Arc<Inner>,
    mut rx: mpsc::Receiver<JsonRpcRequest>,
    mut stdin: tokio::process::ChildStdin,
) {
    while let Some(req) = rx.recv().await {
        let id = req.id;
        let mut body = match serde_json::to_vec(&req) {
            Ok(b) => b,
            Err(e) => {
                send_pending(
                    &inner,
                    id,
                    Err(McpError::invalid_response(format!(
                        "serialize request: {e}"
                    ))),
                );
                continue;
            }
        };
        if body.len() > MAX_STDIO_REQ_BYTES {
            send_pending(
                &inner,
                id,
                Err(McpError::transport(format!(
                    "request exceeds {MAX_STDIO_REQ_BYTES} bytes"
                ))),
            );
            continue;
        }
        // Adversarial round 1 W1 fix: outbound LeakDetector scan on the
        // request body BEFORE writing to the subprocess. Symmetric with the
        // inbound scan in reader_task — closes the asymmetry vs HTTP
        // transport (which routes outbound through HttpSecurityChain). An
        // agent that inadvertently embeds a credential into tool-call
        // params would otherwise leak it to the subprocess unscanned.
        // Match all 4 ScanResult arms per the security_chain.rs precedent.
        let body_str = match std::str::from_utf8(&body) {
            Ok(s) => s,
            Err(_) => {
                send_pending(
                    &inner,
                    id,
                    Err(McpError::invalid_response("request body not utf-8")),
                );
                continue;
            }
        };
        match inner
            .leak_detector
            .scan(body_str, ScanContext::HttpOutbound)
        {
            ScanResult::Clean | ScanResult::Warned { .. } => {}
            ScanResult::Blocked { .. } => {
                send_pending(
                    &inner,
                    id,
                    Err(McpError::permission_denied("outbound leak detected")),
                );
                continue;
            }
            ScanResult::Redacted { redacted, .. } => {
                body = redacted.into_bytes();
            }
        }
        // Audit round 1 W7 fix: combine body + b'\n' into a single write_all
        // so the writer-task does not split body and newline across two
        // write calls. NOTE per adversarial round 1 Info-2: tokio's
        // `write_all` can still partial-write before EPIPE, so a mid-write
        // EPIPE can leave the subprocess with a partial body. The writer
        // task then exits; subprocess sees garbage that won't parse but
        // never gets a terminator. Transport tears down cleanly.
        body.push(b'\n');
        if let Err(e) = stdin.write_all(&body).await {
            send_pending(
                &inner,
                id,
                Err(McpError::transport(format!("subprocess stdin write: {e}"))),
            );
            return;
        }
        if let Err(e) = stdin.flush().await {
            send_pending(
                &inner,
                id,
                Err(McpError::transport(format!("subprocess stdin flush: {e}"))),
            );
            return;
        }
    }
}

/// Stderr task — drains the subprocess stderr stream into `eprintln!` lines for
/// host-side diagnostics. Never delivered to invoke callers (AC-17 SD-10).
async fn stderr_task(server_id: String, stderr: tokio::process::ChildStderr) {
    let mut reader = BufReader::new(stderr).lines();
    while let Ok(Some(line)) = reader.next_line().await {
        eprintln!("[cap_mcp stdio:{server_id}] {line}");
    }
}

/// Extract `(id, result_bytes)` from a JsonRpcResponse, or `(id, error)`. Used
/// by the reader task to dispatch to the right pending slot.
fn extract_result(resp: JsonRpcResponse) -> Result<(u64, Vec<u8>), (u64, McpError)> {
    let id = resp.id;
    if let Some(err) = resp.error {
        // Audit round 1 W9 fix: do NOT inline the server-supplied error.message
        // into the agent-facing error string — the server is untrusted and the
        // message could be a prompt-injection payload or exfil channel. Surface
        // only the JSON-RPC error code as a stable, fixed-class identifier; the
        // raw message stays in host-side eprintln! tracing for operator debug.
        eprintln!(
            "[cap_mcp jsonrpc:{}] server error code={} message={}",
            id, err.code, err.message
        );
        return Err((
            id,
            McpError::server_error(format!("jsonrpc error code {}", err.code)),
        ));
    }
    match resp.result {
        Some(v) => match serde_json::to_vec(&v) {
            Ok(b) => Ok((id, b)),
            Err(e) => Err((
                id,
                McpError::invalid_response(format!("serialize result: {e}")),
            )),
        },
        None => Err((
            id,
            McpError::invalid_response("jsonrpc response missing both result and error"),
        )),
    }
}

fn send_pending(inner: &Arc<Inner>, id: u64, outcome: Result<Vec<u8>, McpError>) {
    let sender = {
        let mut pending = match inner.pending.lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        pending.remove(&id)
    };
    if let Some(tx) = sender {
        let _ = tx.send(outcome);
    }
    // No pending slot → invoke caller already timed out / dropped receiver.
    // Silent drop is correct here.
}

/// Drain ALL pending entries with the same error message. Used on EOF /
/// read-error / partial-line / Drop. Iterates by sorted id for deterministic
/// test assertions.
fn drain_pending(inner: &Arc<Inner>, message: &str) {
    let drained: Vec<(u64, PendingSlot)> = {
        let mut pending = match inner.pending.lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        let mut entries: Vec<(u64, PendingSlot)> = pending.drain().collect();
        entries.sort_by_key(|(id, _)| *id);
        entries
    };
    for (_, tx) in drained {
        let _ = tx.send(Err(McpError::transport(message.to_string())));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn _assert_send_sync()
    where
        StdioMcpTransport: Send + Sync,
    {
    }

    #[test]
    fn spawn_rejects_empty_command() {
        let detector = Arc::new(NoOpDetector);
        let env = std::collections::BTreeMap::new();
        let err = StdioMcpTransport::spawn("srv", "", &[], &env, detector).expect_err("empty cmd");
        assert_eq!(err.kind, McpErrorKind::TransportError);
        assert!(err.message.contains("empty command"));
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

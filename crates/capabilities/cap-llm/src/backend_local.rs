//! OSS supervised-sidecar C236 client (MODULE-009-AC-23).

use std::io::{BufReader, Read, Write};
use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::AtomicBool;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use advance_shared_types::inference::{
    InferenceBackendError, InferenceBackendPort, InferenceChatRequest, InferenceChatResponse,
    InferenceEmbedRequest, InferenceEmbedResponse, InferenceStream, InferenceStreamClass,
    InferenceStreamHead, InferenceTextDelta, LocalHttpRequest, LocalInferenceTransportPolicy,
    NormalizedUsage, SidecarHandoff,
};
use async_trait::async_trait;
use serde_json::{json, Value};

use crate::error::LlmError;
use crate::providers::openai::OpenAiAdapter;
use crate::providers::sse::FrameSplitter;
use crate::providers::ProviderAdapter;

#[async_trait]
pub trait SidecarSupervisor: Send + Sync {
    async fn handoff(&self, provider_id: &str) -> Result<SidecarHandoff, InferenceBackendError>;
}

/// Test/in-process supervisor: returns a pre-bound loopback address.
pub struct StaticHandoffSupervisor {
    pub handoff: SidecarHandoff,
}

#[async_trait]
impl SidecarSupervisor for StaticHandoffSupervisor {
    async fn handoff(&self, _provider_id: &str) -> Result<SidecarHandoff, InferenceBackendError> {
        Ok(self.handoff.clone())
    }
}

/// Production supervisor: same loopback as spawn, refused if the child has died.
pub struct OwnedHandoffSupervisor {
    pub handoff: SidecarHandoff,
    pub child: Arc<SupervisedChild>,
}

#[async_trait]
impl SidecarSupervisor for OwnedHandoffSupervisor {
    async fn handoff(&self, _provider_id: &str) -> Result<SidecarHandoff, InferenceBackendError> {
        if self.child.exited() {
            return Err(InferenceBackendError::local_transport(
                "sidecar process exited (stale hand-off)",
            ));
        }
        Ok(self.handoff.clone())
    }
}

/// Fail-closed port that carries the spawn/handshake error (not a bare Unwired).
pub struct FailedSpawnBackend {
    pub reason: String,
}

#[async_trait]
impl InferenceBackendPort for FailedSpawnBackend {
    async fn chat(
        &self,
        _req: InferenceChatRequest,
    ) -> Result<InferenceChatResponse, InferenceBackendError> {
        Err(InferenceBackendError::Provider(self.reason.clone()))
    }
    async fn embed(
        &self,
        _req: InferenceEmbedRequest,
    ) -> Result<InferenceEmbedResponse, InferenceBackendError> {
        Err(InferenceBackendError::Provider(self.reason.clone()))
    }
    async fn start_stream(
        &self,
        _req: InferenceChatRequest,
    ) -> Result<(InferenceStreamHead, Box<dyn InferenceStream>), InferenceBackendError> {
        Err(InferenceBackendError::Provider(self.reason.clone()))
    }
    fn is_wired(&self) -> bool {
        false
    }
}

/// Spawns `command` and reads `PORT=<n>` from stdout.
pub struct ProcessSupervisor {
    pub command: String,
    pub args: Vec<String>,
}

/// RAII owner of a sidecar OS process. `Sync` so the composition root can
/// hold `Arc<SupervisedChild>` on `LlmGateway` for the daemon lifetime.
pub struct SupervisedChild {
    child: Mutex<Option<Child>>,
    pid: u32,
    dead: std::sync::atomic::AtomicBool,
}

impl SupervisedChild {
    /// OS pid of the spawned sidecar (process-group leader).
    pub fn pid(&self) -> u32 {
        self.pid
    }

    fn reap_group(&self) {
        #[cfg(unix)]
        unsafe {
            libc::kill(-(self.pid as i32), libc::SIGKILL);
        }
    }

    /// Peek whether the child has exited WITHOUT reaping. A zombie still
    /// holds its PGID, so a later `kill(-pid)` cannot land on a recycled group.
    /// `Err(errno)` is a `waitid` failure — the caller must not reap.
    #[cfg(unix)]
    fn exited_unreaped(pid: u32) -> Result<bool, i32> {
        unsafe {
            let mut info: libc::siginfo_t = std::mem::zeroed();
            let rc = libc::waitid(
                libc::P_PID,
                pid as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            );
            if rc != 0 {
                return Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(-1));
            }
            Ok(info.si_pid() != 0)
        }
    }

    /// True if the OS process has already exited. Sticky: a reaped pid is
    /// never treated as live, and the process group is signalled once, while
    /// the zombie still owns the PGID.
    pub fn exited(&self) -> bool {
        if self.dead.load(std::sync::atomic::Ordering::SeqCst) {
            return true;
        }
        let mut guard = self.child.lock().unwrap_or_else(|p| p.into_inner());
        if self.dead.load(std::sync::atomic::Ordering::SeqCst) {
            return true;
        }
        if guard.as_ref().is_none() {
            self.dead.store(true, std::sync::atomic::Ordering::SeqCst);
            return true;
        }

        #[cfg(unix)]
        {
            match Self::exited_unreaped(self.pid) {
                Ok(false) => false,
                Ok(true) => {
                    self.reap_group();
                    self.dead.store(true, std::sync::atomic::Ordering::SeqCst);
                    if let Some(mut child) = guard.take() {
                        let _ = child.wait();
                    }
                    true
                }
                Err(errno) => {
                    // Never try_wait here: that reaps a zombie leader and then
                    // Drop skips killpg, leaving any remaining group members.
                    // ECHILD: kernel has nothing to wait on — mark dead, no killpg.
                    // EINTR / other: leave the child owned; retry on the next poll.
                    if errno == libc::ECHILD {
                        let _ = guard.take();
                        self.dead.store(true, std::sync::atomic::Ordering::SeqCst);
                        true
                    } else {
                        false
                    }
                }
            }
        }

        #[cfg(not(unix))]
        {
            let dead = match guard.as_mut() {
                Some(child) => match child.try_wait() {
                    Ok(None) => false,
                    Ok(Some(_)) | Err(_) => true,
                },
                None => true,
            };
            if dead {
                let _ = guard.take();
                self.dead.store(true, std::sync::atomic::Ordering::SeqCst);
            }
            dead
        }
    }
}

impl Drop for SupervisedChild {
    fn drop(&mut self) {
        let mut guard = self.child.lock().unwrap_or_else(|p| p.into_inner());
        if !self.dead.load(std::sync::atomic::Ordering::SeqCst) {
            self.reap_group();
            self.dead.store(true, std::sync::atomic::Ordering::SeqCst);
        }
        if let Some(mut child) = guard.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

const PORT_HANDOFF_TIMEOUT: Duration = Duration::from_secs(20);

impl ProcessSupervisor {
    pub fn spawn(&self) -> Result<(SidecarHandoff, SupervisedChild), InferenceBackendError> {
        if !std::path::Path::new(&self.command).is_absolute() {
            return Err(InferenceBackendError::local_transport(
                "sidecar.command must be an absolute path",
            ));
        }
        let mut cmd = Command::new(&self.command);
        cmd.args(&self.args)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .current_dir("/")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            cmd.process_group(0);
        }
        let mut child = cmd
            .spawn()
            .map_err(|e| InferenceBackendError::local_transport(format!("spawn: {e}")))?;
        let stdout = match child.stdout.take() {
            Some(s) => s,
            None => {
                let pid = child.id();
                let _keep = SupervisedChild {
                    child: Mutex::new(Some(child)),
                    pid,
                    dead: std::sync::atomic::AtomicBool::new(false),
                };
                return Err(InferenceBackendError::local_transport("no stdout"));
            }
        };
        // Own the Child before the handshake so any later Err kills it.
        let pid = child.id();
        let keep = SupervisedChild {
            child: Mutex::new(Some(child)),
            pid,
            dead: std::sync::atomic::AtomicBool::new(false),
        };
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            let mut line = Vec::new();
            let r = (|| {
                loop {
                    let mut b = [0u8; 1];
                    match reader.read(&mut b) {
                        Ok(0) => break,
                        Ok(_) => {
                            if b[0] == b'\n' {
                                break;
                            }
                            if line.len() >= 64 {
                                return Err(std::io::Error::new(
                                    std::io::ErrorKind::InvalidData,
                                    "PORT line too long",
                                ));
                            }
                            line.push(b[0]);
                        }
                        Err(e) => return Err(e),
                    }
                }
                String::from_utf8(line)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
            })();
            let _ = tx.send(r);
            // Keep the pipe open so a chatty sidecar is not killed by SIGPIPE.
            let mut buf = [0u8; 4096];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
        });
        let line = match rx.recv_timeout(PORT_HANDOFF_TIMEOUT) {
            Ok(Ok(l)) => l,
            Ok(Err(e)) => {
                return Err(InferenceBackendError::local_transport(format!(
                    "read PORT: {e}"
                )));
            }
            Err(_) => {
                // Do not try_wait here: reaping the leader then Drop-killpg
                // races PID/PGID reuse. SupervisedChild Drop still owns the
                // child and killpg's the live group.
                return Err(InferenceBackendError::local_transport(
                    "PORT hand-off timed out",
                ));
            }
        };
        let port: u16 = line
            .trim()
            .strip_prefix("PORT=")
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| {
                InferenceBackendError::local_transport(format!("expected PORT=<n>, got {line:?}"))
            })?;
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        Ok((
            SidecarHandoff {
                pid,
                loopback: addr,
            },
            keep,
        ))
    }
}

#[async_trait]
impl SidecarSupervisor for ProcessSupervisor {
    async fn handoff(&self, _provider_id: &str) -> Result<SidecarHandoff, InferenceBackendError> {
        // Production composition calls `spawn()` once and injects
        // `StaticHandoffSupervisor` so the `SupervisedChild` has a Drop owner.
        // Calling this trait method would otherwise orphan the child.
        Err(InferenceBackendError::local_transport(
            "ProcessSupervisor::handoff is not a production path; spawn() then OwnedHandoffSupervisor",
        ))
    }
}

pub struct SidecarClient {
    pub policy: Arc<dyn LocalInferenceTransportPolicy>,
    pub supervisor: Arc<dyn SidecarSupervisor>,
    pub provider_id: String,
    pub embedding_model: Option<String>,
}

fn oai_chat_body(req: &InferenceChatRequest) -> Value {
    let messages: Vec<Value> = req
        .messages
        .iter()
        .map(|m| json!({"role": m.role, "content": m.content}))
        .collect();
    let mut body = json!({
        "model": req.model,
        "messages": messages,
    });
    if let Some(t) = req.temperature {
        body["temperature"] = json!(t);
    }
    if let Some(m) = req.max_tokens {
        body["max_tokens"] = json!(m);
    }
    if let Some(stop) = &req.stop_sequences {
        body["stop"] = json!(stop);
    }
    if let Some(tools) = &req.tools {
        body["tools"] = json!(tools
            .iter()
            .map(|t| json!({
                "type": "function",
                "function": {
                    "name": t.name,
                    "description": t.description,
                    "parameters": t.parameters,
                }
            }))
            .collect::<Vec<_>>());
    }
    body
}

fn status_class(status: u16) -> InferenceStreamClass {
    match status {
        200..=299 => InferenceStreamClass::Success,
        401 | 403 => InferenceStreamClass::Auth,
        404 => InferenceStreamClass::NotFound,
        429 => InferenceStreamClass::RateLimited,
        500..=599 => InferenceStreamClass::Provider5xx,
        _ => InferenceStreamClass::Unexpected,
    }
}

fn map_parse(err: LlmError) -> InferenceBackendError {
    match err {
        LlmError::ModelNotAvailable(s) => InferenceBackendError::ModelNotAvailable(s),
        LlmError::RateLimited(s) => InferenceBackendError::RateLimited(s),
        LlmError::ContextTooLong(s) => InferenceBackendError::ContextTooLong(s),
        LlmError::ProviderError(s) => InferenceBackendError::Provider(s),
        other => InferenceBackendError::Provider(other.to_string()),
    }
}

struct ClientStream {
    body: Box<dyn advance_shared_types::inference::LocalBodyStream>,
    splitter: FrameSplitter,
    adapter: OpenAiAdapter,
    cancel: Arc<AtomicBool>,
    pending: Vec<InferenceTextDelta>,
    saw_terminal: bool,
}

#[async_trait]
impl InferenceStream for ClientStream {
    async fn next_chunk(&mut self) -> Option<Result<InferenceTextDelta, InferenceBackendError>> {
        if !self.pending.is_empty() {
            return Some(Ok(self.pending.remove(0)));
        }
        if self.saw_terminal {
            return None;
        }
        loop {
            let raw = match self.body.next_chunk().await {
                None => {
                    if self.saw_terminal {
                        return None;
                    }
                    return Some(Err(InferenceBackendError::local_transport(
                        "stream eof before terminal",
                    )));
                }
                Some(Err(e)) => return Some(Err(e.into())),
                Some(Ok(b)) => b,
            };
            let frames = match self.splitter.push(&raw) {
                Ok(f) => f,
                Err(e) => return Some(Err(map_parse(e))),
            };
            for frame in frames {
                let ev = match self.adapter.parse_sse_frame(&frame) {
                    Ok(e) => e,
                    Err(e) => return Some(Err(map_parse(e))),
                };
                if ev.terminal {
                    self.saw_terminal = true;
                    self.pending.push(InferenceTextDelta {
                        text: String::new(),
                        usage: None,
                        terminal: true,
                        finish_reason: ev.finish_reason,
                    });
                    continue;
                }
                let usage = ev.usage.map(|u| NormalizedUsage {
                    input_tokens: u.input_tokens.unwrap_or(0),
                    output_tokens: u.output_tokens.unwrap_or(0),
                    cached_tokens: 0,
                });
                if ev.delta.is_none() && usage.is_none() && ev.finish_reason.is_none() {
                    continue;
                }
                self.pending.push(InferenceTextDelta {
                    text: ev.delta.unwrap_or_default(),
                    usage,
                    terminal: false,
                    finish_reason: ev.finish_reason,
                });
            }
            if !self.pending.is_empty() {
                return Some(Ok(self.pending.remove(0)));
            }
        }
    }

    fn cancel(&mut self) {
        self.cancel.store(true, std::sync::atomic::Ordering::SeqCst);
        self.body.cancel();
    }
}

impl Drop for ClientStream {
    fn drop(&mut self) {
        self.cancel();
    }
}

#[async_trait]
impl InferenceBackendPort for SidecarClient {
    async fn chat(
        &self,
        req: InferenceChatRequest,
    ) -> Result<InferenceChatResponse, InferenceBackendError> {
        let handoff = self.supervisor.handoff(&self.provider_id).await?;
        let body = serde_json::to_vec(&oai_chat_body(&req))
            .map_err(|e| InferenceBackendError::local_transport(format!("serialize: {e}")))?;
        let http = LocalHttpRequest {
            path: "/v1/chat/completions".into(),
            headers: vec![("Content-Type".into(), "application/json".into())],
            body,
            deadline: req.deadline,
            cancel: req.cancel,
        };
        let resp = self.policy.execute(&handoff, http).await?;
        let outcome = OpenAiAdapter
            .parse_chat_response(resp.status, &resp.body)
            .map_err(map_parse)?;
        Ok(InferenceChatResponse {
            text: outcome.text,
            model: outcome.model,
            input_tokens: outcome.input_tokens,
            output_tokens: outcome.output_tokens,
            finish_reason: outcome.finish_reason,
        })
    }

    async fn embed(
        &self,
        req: InferenceEmbedRequest,
    ) -> Result<InferenceEmbedResponse, InferenceBackendError> {
        let model = if req.model.is_empty() {
            self.embedding_model.clone().ok_or_else(|| {
                InferenceBackendError::ModelNotAvailable("no embedding_model".into())
            })?
        } else {
            req.model.clone()
        };
        let handoff = self.supervisor.handoff(&self.provider_id).await?;
        let body = serde_json::to_vec(&json!({"model": model, "input": req.text}))
            .map_err(|e| InferenceBackendError::local_transport(format!("serialize: {e}")))?;
        let http = LocalHttpRequest {
            path: "/v1/embeddings".into(),
            headers: vec![("Content-Type".into(), "application/json".into())],
            body,
            deadline: req.deadline,
            cancel: req.cancel,
        };
        let resp = self.policy.execute(&handoff, http).await?;
        let vector = OpenAiAdapter
            .parse_embed_response(resp.status, &resp.body)
            .map_err(map_parse)?;
        Ok(InferenceEmbedResponse { vector, model })
    }

    async fn start_stream(
        &self,
        req: InferenceChatRequest,
    ) -> Result<(InferenceStreamHead, Box<dyn InferenceStream>), InferenceBackendError> {
        let handoff = self.supervisor.handoff(&self.provider_id).await?;
        let mut body_v = oai_chat_body(&req);
        body_v["stream"] = json!(true);
        body_v["stream_options"] = json!({ "include_usage": true });
        let body = serde_json::to_vec(&body_v)
            .map_err(|e| InferenceBackendError::local_transport(format!("serialize: {e}")))?;
        let cancel = req.cancel.clone();
        let http = LocalHttpRequest {
            path: "/v1/chat/completions".into(),
            headers: vec![
                ("Content-Type".into(), "application/json".into()),
                ("Accept".into(), "text/event-stream".into()),
            ],
            body,
            deadline: req.deadline,
            cancel: req.cancel,
        };
        let (head, body) = self.policy.execute_streaming(&handoff, http).await?;
        let class = status_class(head.status);
        let stream: Box<dyn InferenceStream> = Box::new(ClientStream {
            body,
            splitter: FrameSplitter::new(),
            adapter: OpenAiAdapter,
            cancel,
            pending: Vec::new(),
            saw_terminal: false,
        });
        Ok((
            InferenceStreamHead {
                class,
                snapshot_only: false,
            },
            stream,
        ))
    }

    fn is_wired(&self) -> bool {
        true
    }
}

/// In-process OAI stub for T128/T132 (not the fixture binary).
pub async fn spawn_inprocess_fixture(
    block_pattern: bool,
) -> Result<(SidecarHandoff, tokio::task::JoinHandle<()>), std::io::Error> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            let mut buf = vec![0u8; 8192];
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let _ = sock.read(&mut buf).await;
            let req = String::from_utf8_lossy(&buf);
            let is_embed = req.contains("/v1/embeddings");
            let is_stream = req.contains("\"stream\":true") || req.contains("\"stream\": true");
            let body = if is_embed {
                br#"{"data":[{"embedding":[0.1,0.2]}],"model":"nomic-embed"}"#.to_vec()
            } else if is_stream {
                let content = if block_pattern {
                    format!("sk-ant-api{}", "A".repeat(95))
                } else {
                    "pong".to_string()
                };
                format!(
                    "data: {{\"choices\":[{{\"delta\":{{\"content\":\"{content}\"}}}}]}}\n\n\
                     data: {{\"usage\":{{\"prompt_tokens\":1,\"completion_tokens\":1}}}}\n\n\
                     data: [DONE]\n\n"
                )
                .into_bytes()
            } else {
                br#"{"choices":[{"message":{"content":"pong"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1},"model":"llama"}"#.to_vec()
            };
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                if is_stream { "text/event-stream" } else { "application/json" },
                body.len()
            );
            let _ = sock.write_all(header.as_bytes()).await;
            let _ = sock.write_all(&body).await;
        }
    });
    Ok((
        SidecarHandoff {
            pid: 0,
            loopback: addr,
        },
        handle,
    ))
}

// Silence unused import if Write is only for docs.
#[allow(dead_code)]
fn _write_unused(w: &mut dyn Write) {
    let _ = w;
}

#[cfg(test)]
mod spawn_tests {
    use super::*;
    use advance_shared_types::inference::{InferenceMessage, InferenceTool};
    use std::time::Instant;

    #[test]
    fn spawn_non_port_handshake_is_err() {
        let sup = ProcessSupervisor {
            command: "/bin/echo".into(),
            args: vec!["nope".into()],
        };
        assert!(sup.spawn().is_err());
    }

    #[test]
    fn spawn_relative_command_is_err() {
        let sup = ProcessSupervisor {
            command: "echo".into(),
            args: vec!["nope".into()],
        };
        match sup.spawn() {
            Err(err) => assert!(err.to_string().contains("absolute path"), "got {err}"),
            Ok(_) => panic!("relative command must fail"),
        }
    }

    #[test]
    fn t129_native_tools_serialized_in_sidecar_body() {
        let req = InferenceChatRequest {
            provider_id: "local".into(),
            model: "llama".into(),
            messages: vec![InferenceMessage {
                role: "user".into(),
                content: "hi".into(),
            }],
            temperature: None,
            max_tokens: None,
            stop_sequences: None,
            tools: Some(vec![InferenceTool {
                name: "search".into(),
                description: "d".into(),
                parameters: serde_json::json!({"type": "object"}),
            }]),
            output_schema: None,
            deadline: Instant::now() + Duration::from_secs(1),
            cancel: Arc::new(AtomicBool::new(false)),
        };
        let body = oai_chat_body(&req);
        assert!(body["tools"].is_array(), "{body}");
        assert_eq!(body["tools"][0]["function"]["name"], "search");
    }
}

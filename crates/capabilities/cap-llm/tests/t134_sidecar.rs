//! MODULE-009-T134 — spawn the fixture binary, hand-off, chat, kill.

use std::net::TcpStream;
use std::sync::Arc;
use std::time::{Duration, Instant};

use advance_shared_types::inference::{
    InferenceBackendPort, InferenceChatRequest, InferenceMessage,
};
use cap_http::DefaultLocalInferenceTransport;
use cap_llm::backend_local::{ProcessSupervisor, SidecarClient, StaticHandoffSupervisor};

#[test]
fn t134_spawn_handoff_chat_kill() {
    let bin = env!("CARGO_BIN_EXE_local-sidecar-fixture");
    // Cold first-exec of the fixture (macOS code-signing) can exceed the
    // PORT handshake. Drain one PORT= line so ProcessSupervisor is warm.
    {
        use std::io::{BufRead, BufReader};
        use std::process::{Command, Stdio};
        if let Ok(mut child) = Command::new(bin)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
        {
            if let Some(out) = child.stdout.take() {
                let mut line = String::new();
                let _ = BufReader::new(out).read_line(&mut line);
            }
            let _ = child.kill();
            let _ = child.wait();
        }
    }
    let sup = ProcessSupervisor {
        command: bin.into(),
        args: vec![],
    };
    let (handoff, child) = sup.spawn().expect("ProcessSupervisor spawn");
    let addr = handoff.loopback;

    let client = SidecarClient {
        policy: Arc::new(DefaultLocalInferenceTransport),
        supervisor: Arc::new(StaticHandoffSupervisor { handoff }),
        provider_id: "local".into(),
        embedding_model: None,
    };
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
        tools: None,
        output_schema: None,
        deadline: Instant::now() + Duration::from_secs(5),
        cancel: Arc::new(std::sync::atomic::AtomicBool::new(false)),
    };
    let resp = tokio::runtime::Runtime::new()
        .expect("rt")
        .block_on(client.chat(req))
        .expect("chat against fixture");
    assert_eq!(resp.text, "pong");
    drop(child);
    assert!(
        TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_err(),
        "sidecar must die when SupervisedChild drops"
    );
}

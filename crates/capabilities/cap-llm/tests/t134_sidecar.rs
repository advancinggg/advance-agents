//! MODULE-009-T134 — spawn the fixture binary, hand-off, chat, kill.

use std::net::TcpStream;
use std::sync::Arc;
use std::time::{Duration, Instant};

use advance_shared_types::inference::{
    InferenceBackendPort, InferenceChatRequest, InferenceMessage,
};
use cap_http::DefaultLocalInferenceTransport;
use cap_llm::backend_local::{ProcessSupervisor, SidecarClient, StaticHandoffSupervisor};

#[tokio::test]
async fn t134_spawn_handoff_chat_kill() {
    let bin = env!("CARGO_BIN_EXE_local-sidecar-fixture");
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
    let resp = client.chat(req).await.expect("chat against fixture");
    assert_eq!(resp.text, "pong");
    drop(child);
    assert!(
        TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_err(),
        "sidecar must die when SupervisedChild drops"
    );
}

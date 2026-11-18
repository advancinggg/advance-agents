//! B1 backbone — `GatewayEmbedding` adapter test over the real cap-llm gateway.
//!
//! `GatewayEmbedding` (cli `context_wiring`) wraps the gateway's per-agent
//! embedding (`LlmGateway::embed_for_agent` → `/v1/embeddings`) as the
//! context-engine `EmbeddingPort`: an agent's text is embedded only by the
//! provider that agent chats with. This test exercises it directly against the
//! harness loopback gateway (the real `LlmGateway` over a loopback
//! `/v1/embeddings` endpoint — only the external HTTP peer is doubled), proving
//! the wrapper forwards `embed` + maps the result, for the agent it is built for.

use advance_cli::context_wiring::{live_embedding_model, EmbeddingPort, GatewayEmbedding};
use system_acceptance::llm_loopback::ScriptedResponse;
use system_acceptance::llm_loopback::LOOPBACK_EMBEDDING_MODEL;
use system_acceptance::{Cap, LlmMode, SystemUnderTest};

const HELLO_LLM_CORE: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-hello-llm.core.wasm");

#[tokio::test(flavor = "multi_thread")]
async fn gateway_embedding_forwards_to_loopback_embeddings() {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Llm])
        // One scripted chat is irrelevant here — we drive `embed`, which the
        // loopback serves from its `/v1/embeddings` route (deterministic vector).
        .llm(LlmMode::LoopbackScripted(vec![ScriptedResponse::ok_chat(
            "unused", 1, 1,
        )]))
        .build(HELLO_LLM_CORE)
        .await;

    let gateway = sut
        .llm_gateway()
        .expect("loopback registered an LlmGateway");
    // The agent chats with the loopback entry, which names an embedding model:
    // that entry is the agent's embedding route.
    assert_eq!(
        live_embedding_model(&gateway, sut.agent_id()).as_deref(),
        Some(LOOPBACK_EMBEDDING_MODEL)
    );
    let port = GatewayEmbedding::new(gateway, sut.agent_id());

    let v = port
        .embed("a short embedding input")
        .await
        .expect("GatewayEmbedding forwards to the agent's embedding route on the loopback");

    // The loopback `/v1/embeddings` handler returns a FIXED deterministic vector
    // (`[0.1, 0.2]`); the adapter must surface it VERBATIM (no transform/truncate,
    // no error mapping on the happy path). Assert the exact value.
    assert_eq!(
        v,
        vec![0.1_f32, 0.2_f32],
        "GatewayEmbedding surfaces the loopback embedding vector verbatim (got {v:?})"
    );
}

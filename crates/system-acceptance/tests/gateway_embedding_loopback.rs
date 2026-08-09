//! B1 backbone — `GatewayEmbedding` adapter test over the real cap-llm gateway.
//!
//! `GatewayEmbedding` (cli `context_wiring`) wraps `LlmGateway::embed`
//! (`/v1/embeddings`, CONTRACT-081) as the context-engine `EmbeddingPort`. It is
//! built this slice but deliberately NOT injected into the live assembler
//! (hermeticity — see MODULE-010 §3.6 B1 row), so it has no e2e turn path. This
//! test exercises it directly against the harness loopback gateway (the real
//! `LlmGateway` over a loopback `/v1/embeddings` endpoint — only the external HTTP
//! peer is doubled), proving the wrapper forwards `embed` + maps the result.

use advance_cli::context_wiring::{EmbeddingPort, GatewayEmbedding};
use system_acceptance::llm_loopback::ScriptedResponse;
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
    let port = GatewayEmbedding::new(gateway);

    let v = port
        .embed("a short embedding input")
        .await
        .expect("GatewayEmbedding forwards to LlmGateway::embed against the loopback");

    // The loopback `/v1/embeddings` handler returns a FIXED deterministic vector
    // (`[0.1, 0.2]`); the adapter must surface it VERBATIM (no transform/truncate,
    // no error mapping on the happy path). Assert the exact value.
    assert_eq!(
        v,
        vec![0.1_f32, 0.2_f32],
        "GatewayEmbedding surfaces the loopback embedding vector verbatim (got {v:?})"
    );
}

//! Mode smoke (Slice S2): a deterministic LLM turn through the REAL cap-llm gateway
//! + cap-http `DefaultHttpSecurityChain` (all 10 chain steps) reaching a loopback
//! mock via the `dns_overrides` seam — WITHOUT weakening production SSRF and with
//! ZERO cap-http edits. Witnesses the seam by driving the gateway directly (the
//! guest-through-injector path is a track concern; the seam is what this proves).

use system_acceptance::llm_loopback::LoopbackScript;
use system_acceptance::{Cap, LlmMode, SystemUnderTest};

use cap_llm::{ChatMessage, ChatParams, ChatRole, LlmGatewayInternal};

const CORE_BYTES: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-j01-skeleton.core.wasm");

#[tokio::test(flavor = "multi_thread")]
async fn deterministic_llm_turn_through_loopback_seam() {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Fs, Cap::Llm])
        .llm(LlmMode::Loopback(LoopbackScript::reply(
            "hello-from-loopback",
        )))
        .build(CORE_BYTES)
        .await;

    let gateway = sut.llm_gateway().expect("loopback gateway registered");
    let resp = gateway
        .chat(
            vec![ChatMessage {
                role: ChatRole::User,
                content: "hi".into(),
            }],
            ChatParams::default(),
        )
        .await
        .expect("loopback chat round-trips through the real chain + executor");

    assert_eq!(
        resp.text, "hello-from-loopback",
        "the scripted loopback reply reached the caller through the real gateway+chain"
    );
    assert_eq!(resp.input_tokens, 1);
    assert_eq!(resp.output_tokens, 1);

    // Credential-injection witness: the REAL cap-http chain injected the seeded secret
    // as an Authorization: Bearer header onto the outbound request (the mock observed
    // it on the wire). The plaintext secret never appears in the caller-visible reply.
    let auth = sut
        .llm_recorded_authorization()
        .expect("the loopback mock recorded an Authorization header");
    assert_eq!(
        auth, "Bearer test-secret-value",
        "the chain injected the seeded api-key-secret as a Bearer credential"
    );
    assert!(
        !resp.text.contains("test-secret-value"),
        "the plaintext secret never surfaces in the caller-visible reply"
    );
}

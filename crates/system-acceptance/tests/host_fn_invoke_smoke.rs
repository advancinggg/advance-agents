//! HF fast-follow smoke (2026-06-03): the generic host-fn primitive.
//!
//! `call_host_fn` looks up a registered `HostFunctionHandler` and invokes it
//! DIRECTLY (linker-bypass) — no guest component, no namespace-version match.
//! Witnessed against cap-channel (an unversioned namespace the guest path can't
//! reach): enumerate the 3 registered channel host fns, then drive `poll-raw`
//! through the full `Val-decode → PollRawHandler → SubscriptionManager → Val-encode`
//! boundary and confirm it returns a result Val.

use system_acceptance::SystemUnderTest;
use wasmtime::component::Val;

const CORE_BYTES: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-j01-skeleton.core.wasm");

#[tokio::test]
async fn call_host_fn_drives_a_registered_handler_without_a_guest() {
    let sut = SystemUnderTest::builder()
        .with_channel_capture()
        .build(CORE_BYTES)
        .await;

    // The primitive can enumerate registered host fns via the live registry
    // (cap-channel registers exactly subscribe/poll-raw/send-raw).
    let specs = sut.host_registry().lookup("channel");
    assert_eq!(specs.len(), 3, "channel cap registers 3 host fns");
    assert!(specs.iter().any(|s| s.name == "poll-raw"));
    assert!(specs.iter().any(|s| s.name == "send-raw"));

    // Invoke `poll-raw` directly on the pre-created subscription — exercises the
    // real host-fn boundary with NO component linker. Empty buffer → Ok(None).
    let sub_id = sut.channel_subscription_id().expect("channel sub id").0;
    let out = sut
        .call_host_fn(
            "channel",
            cap_channel::CHANNEL_HOST_NAMESPACE,
            "poll-raw",
            vec![Val::String(sub_id)],
        )
        .await
        .expect("poll-raw via the host-fn primitive succeeds");
    assert_eq!(out.len(), 1, "poll-raw returns one result Val");
    assert!(
        matches!(out[0], Val::Result(Ok(_))),
        "poll-raw on an empty buffer returns result::ok, got {:?}",
        out[0]
    );

    // A missing host fn surfaces a clean HandlerError (not a panic).
    let err = sut
        .call_host_fn(
            "channel",
            cap_channel::CHANNEL_HOST_NAMESPACE,
            "no-such-fn",
            vec![],
        )
        .await
        .expect_err("unknown host fn must error");
    assert!(format!("{err}").contains("no host fn registered"));
}

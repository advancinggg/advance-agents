//! MODULE-006-AC-02 INFRA witness (Wave-18 Lane-3) — the `notify-channel` host-fn
//! is callable end-to-end through the SUT and DELIVERS a `ChannelDelivery`
//! envelope to the resolved channel-adapter mailbox.
//!
//! **This witness by itself was NOT a SYS-AC flip and did NOT flip
//! MODULE-006-AC-02.** Production notify was not yet proven through the cli
//! composition root when this witness landed. notify21 later closes AC-02 and
//! keeps `notify-channel` registered even without a channel adapter so
//! notify-importing guests can link; this test still proves the adapter-backed
//! delivery path and the no-adapter `channel_unknown` failure mode.
//!
//! Witness surface: driven through the REAL `notify-channel` host-fn
//! (`advance:runtime/notify@0.1.0`), registered into the SUT registry by the
//! Wave-18 `register_notify_channel_host_fn` wiring, over the real
//! `MailboxDispatcherImpl::notify_channel` (channel resolution → `ChannelDelivery`
//! envelope → `deliver_notify` → `emit_delivery_event`). Every load-bearing
//! assertion binds to PRODUCT output:
//! the host-fn's returned `Val` (product `encode_notify_error`), the real
//! `msg.received` event, and the real `ChannelDelivery` envelope decoded from the
//! adapter's `MailboxStore` message.

use advance_messaging::{ChannelDelivery, NOTIFY_CAPABILITY, NOTIFY_NAMESPACE};
use system_acceptance::{Cap, SystemUnderTest};
use wasmtime::component::Val;

const CORE_BYTES: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-j01-skeleton.core.wasm");
/// The SUT's sole tree node (`OneAgentTree`) — used here as the channel adapter so
/// `deliver_notify`'s `agent_exists(adapter)` check passes.
const ADAPTER: &str = "agent:harness";
const CHANNEL: &str = "telegram-main";
const NOTIFY_CHANNEL_FN: &str = "notify-channel";

fn payload_val(bytes: &[u8]) -> Val {
    Val::List(bytes.iter().map(|b| Val::U8(*b)).collect())
}

fn msg_received_count(sut: &SystemUnderTest) -> usize {
    sut.events()
        .iter()
        .filter(|e| e.event_type == "msg.received")
        .count()
}

/// TNC-01 — a `notify-channel` to a REGISTERED channel resolves the adapter agent,
/// delivers a `ChannelDelivery` envelope into its mailbox, returns `Ok`, and emits
/// exactly one `msg.received`. The delivered envelope is decoded to bind the
/// channel-routing data (channel_id / user_id / body) — anti-fake-green: a stub
/// that fabricated `Ok(None)` without delivering would fail the envelope decode.
#[tokio::test(flavor = "multi_thread")]
async fn tnc_01_notify_channel_resolves_adapter_and_delivers_envelope() {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Fs])
        .with_channel_adapter(CHANNEL, ADAPTER)
        .build(CORE_BYTES)
        .await;

    let out = sut
        .call_host_fn_as_agent(
            "user:alice",
            NOTIFY_CAPABILITY,
            NOTIFY_NAMESPACE,
            NOTIFY_CHANNEL_FN,
            vec![
                Val::String(CHANNEL.to_string()),
                Val::String("user:bob".to_string()),
                payload_val(b"hello-chan"),
                Val::Option(None),
            ],
        )
        .await
        .expect("notify-channel host-fn call");

    // Product return: single-level result<_, notify-error> → Val::Result(Ok(None)).
    assert!(
        matches!(out.as_slice(), [Val::Result(Ok(None))]),
        "notify-channel success must lower to Val::Result(Ok(None)), got {out:?}"
    );

    // Exactly one msg.received, recipient = the resolved adapter agent (PRODUCT
    // emit_delivery_event).
    let received: Vec<_> = sut
        .events()
        .into_iter()
        .filter(|e| e.event_type == "msg.received")
        .collect();
    assert_eq!(received.len(), 1, "exactly one msg.received");
    assert_eq!(
        received[0].agent_id, ADAPTER,
        "delivered to the resolved channel-adapter mailbox"
    );
    assert_eq!(
        received[0].payload["from"].as_str(),
        Some("user:alice"),
        "sender derives from ctx.agent_id"
    );

    // Anti-fake-green: decode the delivered envelope from the adapter's REAL
    // mailbox. The product `notify_channel` JSON-serialized a ChannelDelivery; if
    // the handler had faked `Ok` without delivering, this poll/decode would fail.
    let mb = sut
        .mailbox_store()
        .get(ADAPTER)
        .expect("adapter mailbox exists after delivery");
    let msg = mb
        .poll()
        .expect("one ChannelDelivery message in the adapter mailbox");
    let env: ChannelDelivery =
        serde_json::from_slice(&msg.payload).expect("payload is a ChannelDelivery envelope");
    assert_eq!(
        env.channel_id, CHANNEL,
        "envelope carries the routed channel id"
    );
    assert_eq!(
        env.user_id, "user:bob",
        "envelope carries the unified user id"
    );
    assert_eq!(
        env.body, b"hello-chan",
        "envelope carries the original payload body"
    );
}

/// TNC-02 — a `notify-channel` to an UNREGISTERED channel returns
/// `invalid-target("channel_unknown")` and delivers nothing (no `msg.received`).
/// Proves the `StaticChannelAdapterRegistry` resolution is load-bearing — not
/// fake-green: a stub that always returned `Ok` would have delivered here.
#[tokio::test(flavor = "multi_thread")]
async fn tnc_02_notify_channel_unknown_channel_rejects_and_delivers_nothing() {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Fs])
        .with_channel_adapter(CHANNEL, ADAPTER)
        .build(CORE_BYTES)
        .await;

    let out = sut
        .call_host_fn_as_agent(
            "user:alice",
            NOTIFY_CAPABILITY,
            NOTIFY_NAMESPACE,
            NOTIFY_CHANNEL_FN,
            vec![
                Val::String("no-such-channel".to_string()),
                Val::String("user:bob".to_string()),
                payload_val(b"orphan"),
                Val::Option(None),
            ],
        )
        .await
        .expect("notify-channel host-fn call");

    assert!(
        matches!(out.as_slice(),
            [Val::Result(Err(Some(b)))]
                if matches!(b.as_ref(),
                    Val::Variant(case, Some(p))
                        if case.as_str() == "invalid-target"
                        && matches!(p.as_ref(), Val::String(s) if s.as_str() == "channel_unknown"))),
        "unknown channel must lower to invalid-target(\"channel_unknown\"), got {out:?}"
    );
    assert_eq!(
        msg_received_count(&sut),
        0,
        "nothing delivered for an unknown channel — no msg.received"
    );
}

/// TNC-02b — a `notify-channel` to a REGISTERED channel but a NON-`user:`-prefixed
/// recipient returns `invalid-target("user_id_invalid")` and delivers nothing. Re-
/// witnesses the unified-form `user_id` contract at the host-fn ingress boundary.
/// The channel id IS registered/resolvable (contrast with TNC-02's unknown channel),
/// and `user_id` validation runs before channel resolution — so this reject is
/// provably the `user_id` gate (`user_id_invalid`), distinct from `channel_unknown`.
#[tokio::test(flavor = "multi_thread")]
async fn tnc_02b_notify_channel_non_user_recipient_rejects() {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Fs])
        .with_channel_adapter(CHANNEL, ADAPTER)
        .build(CORE_BYTES)
        .await;

    let out = sut
        .call_host_fn_as_agent(
            "user:alice",
            NOTIFY_CAPABILITY,
            NOTIFY_NAMESPACE,
            NOTIFY_CHANNEL_FN,
            vec![
                Val::String(CHANNEL.to_string()),
                Val::String("agent:bob".to_string()), // NOT user: — violates the unified-form contract
                payload_val(b"x"),
                Val::Option(None),
            ],
        )
        .await
        .expect("notify-channel host-fn call");

    assert!(
        matches!(out.as_slice(),
            [Val::Result(Err(Some(b)))]
                if matches!(b.as_ref(),
                    Val::Variant(case, Some(p))
                        if case.as_str() == "invalid-target"
                        && matches!(p.as_ref(), Val::String(s) if s.as_str() == "user_id_invalid"))),
        "non-user: recipient must lower to invalid-target(\"user_id_invalid\"), got {out:?}"
    );
    assert_eq!(
        msg_received_count(&sut),
        0,
        "nothing delivered for an invalid recipient — no msg.received"
    );
}

/// TNC-03 — no-adapter invariant: a SUT built WITHOUT `.with_channel_adapter`
/// still registers `notify-channel` so a notify-importing guest can link, but the
/// dispatcher returns `channel_unknown` and delivers nothing.
#[tokio::test(flavor = "multi_thread")]
async fn tnc_03_no_adapter_notify_channel_returns_channel_unknown() {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Fs])
        .build(CORE_BYTES)
        .await;

    let specs = sut.host_registry().lookup(NOTIFY_CAPABILITY);
    assert!(
        specs.iter().any(|s| s.name == "notify-agent"),
        "notify-agent is always registered (control: the registry IS populated)"
    );
    assert!(
        specs.iter().any(|s| s.name == "notify-channel"),
        "notify-channel stays registered without .with_channel_adapter so full notify imports link"
    );

    let out = sut
        .call_host_fn_as_agent(
            "user:alice",
            NOTIFY_CAPABILITY,
            NOTIFY_NAMESPACE,
            NOTIFY_CHANNEL_FN,
            vec![
                Val::String(CHANNEL.to_string()),
                Val::String("user:bob".to_string()),
                payload_val(b"no-adapter"),
                Val::Option(None),
            ],
        )
        .await
        .expect("notify-channel host-fn call");

    assert!(
        matches!(out.as_slice(),
            [Val::Result(Err(Some(b)))]
                if matches!(b.as_ref(),
                    Val::Variant(case, Some(p))
                        if case.as_str() == "invalid-target"
                        && matches!(p.as_ref(), Val::String(s) if s.as_str() == "channel_unknown"))),
        "no channel adapter must lower to invalid-target(\"channel_unknown\"), got {out:?}"
    );
    assert_eq!(
        msg_received_count(&sut),
        0,
        "nothing delivered for an unmapped channel — no msg.received"
    );
}

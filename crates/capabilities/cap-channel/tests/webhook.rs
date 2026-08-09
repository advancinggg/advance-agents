//! Integration tests for the webhook receiver (T10 AC-08 provenance keys).

use std::sync::Arc;

use cap_channel::{
    AdapterType, ChannelConfig, RawEvent, SecretBytes, SubscriptionManager, WebhookReceiver,
    WebhookResponse,
};
use hmac::{Hmac, Mac};
use sha2::Sha256;

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let hi = b >> 4;
        let lo = b & 0xf;
        out.push(hex_char(hi));
        out.push(hex_char(lo));
    }
    out
}

fn hex_char(n: u8) -> char {
    if n < 10 {
        (b'0' + n) as char
    } else {
        (b'a' + n - 10) as char
    }
}

fn hmac_sig(secret: &[u8], body: &[u8]) -> String {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(secret).unwrap();
    mac.update(body);
    let bytes = mac.finalize().into_bytes();
    format!("sha256={}", hex_encode(&bytes))
}

fn webhook_config() -> ChannelConfig {
    ChannelConfig {
        adapter_type: AdapterType::Webhook,
        params: vec![],
        outbound: None,
    }
}

/// T10 (AC-08): raw-event provenance keys — POST a webhook body with HMAC,
/// then poll the resulting RawEvent: assert all 5 required `channel.*` keys
/// exist with non-empty, non-bare-`webhook`-literal values.
#[test]
fn t10_webhook_provenance_keys() {
    let mgr = Arc::new(SubscriptionManager::new());
    let sub_id = mgr.subscribe("test-agent", webhook_config()).unwrap();
    let secret = b"shared-webhook-secret"; // 21 bytes, meets MIN_WEBHOOK_SECRET_BYTES
    mgr.set_webhook_secret(&sub_id, SecretBytes::new(secret.to_vec()).unwrap())
        .unwrap();

    let recv = WebhookReceiver::new(mgr.clone());
    recv.register_path("github", sub_id.clone()).unwrap();

    let body = br#"{"event":"push","sender":{"login":"octocat"}}"#;
    let sig = hmac_sig(secret, body);
    let headers = vec![
        ("X-Signature-256".into(), sig),
        (
            "X-Hub-Signature-Key-Id".into(),
            "key-installation-42".into(),
        ),
        ("User-Agent".into(), "GitHub-Hookshot".into()),
    ];
    let response = recv.handle_request("github", &headers, body);
    assert_eq!(response, WebhookResponse::OK);

    let event = mgr
        .poll_raw("test-agent", &sub_id)
        .unwrap()
        .expect("poll-raw must yield the enqueued event");
    assert_eq!(event.data, body);

    let pairs: std::collections::HashMap<String, String> = event
        .metadata
        .iter()
        .map(|p| (p.key.clone(), p.value.clone()))
        .collect();

    // All 5 required §2.5 keys present.
    for required in [
        "channel.adapter",
        "channel.subscription_id",
        "channel.sender_id",
        "channel.conversation_id",
        "channel.timestamp",
    ] {
        assert!(
            pairs.contains_key(required),
            "missing required key {required}; got {pairs:?}"
        );
        let v = pairs.get(required).unwrap();
        assert!(!v.is_empty(), "key {required} is empty");
    }

    // channel.adapter = "webhook".
    assert_eq!(pairs["channel.adapter"], "webhook");
    // channel.subscription_id = subscription id.
    assert_eq!(pairs["channel.subscription_id"], sub_id.as_str());
    // channel.conversation_id = path (so each webhook path is a distinct
    // conversation).
    assert_eq!(pairs["channel.conversation_id"], "github");
    // channel.sender_id resolves to the X-Hub-Signature-Key-Id rung — NEVER
    // the bare literal "webhook" (which would collapse all webhook events to
    // a single synthetic sender, breaking MODULE-006 IdentityResolver's
    // distinct-user promise).
    assert_eq!(pairs["channel.sender_id"], "key-installation-42");
    assert_ne!(pairs["channel.sender_id"], "webhook");

    // channel.timestamp is parseable as a non-zero u64.
    let ts: u64 = pairs["channel.timestamp"]
        .parse()
        .expect("timestamp parses");
    assert!(
        ts > 1_700_000_000,
        "timestamp should be a recent unix epoch"
    );
}

/// Distinct webhook paths produce distinct sender_id fallbacks (when no
/// signer header is present), preserving the distinct-sender invariant.
#[test]
fn distinct_paths_yield_distinct_fallback_sender_ids() {
    let mgr = Arc::new(SubscriptionManager::new());
    let sub_a = mgr.subscribe("test-agent", webhook_config()).unwrap();
    let sub_b = mgr.subscribe("test-agent", webhook_config()).unwrap();
    let secret = b"hunter2-padded-min-len!"; // 23 bytes, meets MIN_WEBHOOK_SECRET_BYTES
    mgr.set_webhook_secret(&sub_a, SecretBytes::new(secret.to_vec()).unwrap())
        .unwrap();
    mgr.set_webhook_secret(&sub_b, SecretBytes::new(secret.to_vec()).unwrap())
        .unwrap();

    let recv = WebhookReceiver::new(mgr.clone());
    recv.register_path("path-a", sub_a.clone()).unwrap();
    recv.register_path("path-b", sub_b.clone()).unwrap();

    let body = b"x";
    let sig = hmac_sig(secret, body);

    recv.handle_request("path-a", &[("X-Signature-256".into(), sig.clone())], body);
    recv.handle_request("path-b", &[("X-Signature-256".into(), sig)], body);

    let event_a = mgr.poll_raw("test-agent", &sub_a).unwrap().unwrap();
    let event_b = mgr.poll_raw("test-agent", &sub_b).unwrap().unwrap();

    let sender_a = event_a
        .metadata
        .iter()
        .find(|p| p.key == "channel.sender_id")
        .unwrap()
        .value
        .clone();
    let sender_b = event_b
        .metadata
        .iter()
        .find(|p| p.key == "channel.sender_id")
        .unwrap()
        .value
        .clone();
    assert_ne!(
        sender_a, sender_b,
        "distinct webhook paths must yield distinct fallback sender_id values"
    );
}

/// Buffered events are NOT lost when `set_webhook_secret` is called after
/// some events were enqueued (regression guard for the swap-buffer logic).
#[test]
fn set_webhook_secret_preserves_buffered_events() {
    let mgr = Arc::new(SubscriptionManager::new());
    let sub_id = mgr.subscribe("test-agent", webhook_config()).unwrap();
    let event = RawEvent {
        data: b"pre-secret".to_vec(),
        metadata: vec![],
    };
    mgr.enqueue_event(&sub_id, event.clone()).unwrap();
    mgr.set_webhook_secret(
        &sub_id,
        SecretBytes::new(b"hunter2-padded-min-len!".to_vec()).unwrap(),
    )
    .unwrap();
    assert_eq!(mgr.poll_raw("test-agent", &sub_id).unwrap(), Some(event));
}

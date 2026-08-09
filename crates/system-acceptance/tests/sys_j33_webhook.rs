//! SYS-J-33 webhook journey witnesses (SYS-AC-105, SYS-AC-106, SYS-AC-107).
//!
//! Real product: `verify_webhook` / `compute_signature_hex` (scheduler
//! `webhook_hmac.rs`) — the HMAC-SHA256 + size-cap admission decision (MODULE-014).
//! These are pure product functions with no harness state, exercised DIRECTLY as the
//! system-acceptance e2e witness (the witness lives in this crate and drives the real
//! M014 product — no mock substitutes for the HMAC/size logic).
//!
//! SYS-AC-105 (valid HMAC POST → the subscribed component's `run(config)` executes)
//! is now FULLY witnessed (MAINLINE Wave-5 harvest 2026-06-21): the prior deferral
//! ("no production component.started emitter / no real guest-run runnable path") was
//! retired by the Stage-F obs `WebhookListener` (a real axum `WebhookSource`) plus the
//! already-shipped emitter-aware unified watcher path. `sys_ac_105_live_webhook_post_
//! runs_real_guest` drives the FULL chain end-to-end: a real external HTTP POST with a
//! valid HMAC lands on the live `WebhookListener` (bound on an ephemeral port), which
//! verifies the signature and fires a `TriggerFireEvent{event_type:"webhook"}` into the
//! production `WatcherDriver::run_with_trigger_source_with_emitter`, materializing a real
//! `WasmRunnableHook` over the SUT's guest → `component.started`/`component.finished`,
//! and the guest echoes the webhook trigger-context into `result.bin` (so a context-
//! dropping path cannot pass). The walk's emitter-less variant emits no component events
//! (materializer.rs:375 / watcher.rs:214) — this witness uses the emitter-aware path
//! (the same one SYS-AC-098/101 observe), the cli `EventBusNotifySink`-equivalent the
//! daemon wires. No product source is edited.

use std::sync::Arc;
use std::time::Duration;

use advance_cli::webhook_listener::WebhookListener;
use advance_scheduler::trigger_source::WebhookTriggerSource;
use advance_scheduler::types::WebhookConfig;
use advance_scheduler::watcher::WatcherDriver;
use advance_scheduler::webhook_hmac::{
    compute_signature_hex, verify_webhook, WebhookRejection, WEBHOOK_MAX_BODY_BYTES,
};
use advance_shared_types::event::Event;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

use system_acceptance::SystemUnderTest;

const J01_SKELETON: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-j01-skeleton.core.wasm");

/// A ≥16-byte secret (`MIN_WEBHOOK_SECRET_BYTES`) — below that, verify fails closed (401).
const GOOD_SECRET: &str = "this-is-a-strong-enough-secret";

fn cfg() -> WebhookConfig {
    WebhookConfig {
        path: "/hooks/test".into(),
        secret: Some(GOOD_SECRET.into()),
    }
}

// SYS-AC-105 (admission leg) — a valid HMAC-SHA256 signature ADMITS the webhook POST.
// The full POST→guest-run leg is witnessed e2e by sys_ac_105_live_webhook_post_runs_real_guest.
#[test]
fn sys_ac_105_valid_hmac_is_admitted() {
    let body = br#"{"event":"push"}"#;
    let sig = compute_signature_hex(GOOD_SECRET.as_bytes(), body);
    assert!(
        verify_webhook(&cfg(), body, Some(&sig), WEBHOOK_MAX_BODY_BYTES).is_ok(),
        "a valid HMAC-SHA256 signature admits the webhook POST"
    );
}

// SYS-AC-106 — a webhook POST with missing or mismatched HMAC is rejected with HTTP 401
// (the subscribed component does not run — nothing is admitted).
#[test]
fn sys_ac_106_missing_or_wrong_hmac_is_401() {
    // Missing signature → 401.
    let rej = verify_webhook(&cfg(), b"body", None, WEBHOOK_MAX_BODY_BYTES).unwrap_err();
    assert_eq!(rej, WebhookRejection::Unauthorized);
    assert_eq!(rej.http_status(), 401);

    // Mismatched signature (valid sig for a DIFFERENT body) → 401.
    let sig = compute_signature_hex(GOOD_SECRET.as_bytes(), b"original");
    let rej2 = verify_webhook(&cfg(), b"tampered", Some(&sig), WEBHOOK_MAX_BODY_BYTES).unwrap_err();
    assert_eq!(rej2, WebhookRejection::Unauthorized);
    assert_eq!(rej2.http_status(), 401);
}

// SYS-AC-107 — a body exceeding the 1 MiB cap (channels.webhook_max_body_bytes) is
// rejected with HTTP 413 BEFORE HMAC is computed (an oversize body with an otherwise
// VALID signature is still 413 — the size gate runs first).
#[test]
fn sys_ac_107_oversize_body_is_413_before_hmac() {
    assert_eq!(
        WEBHOOK_MAX_BODY_BYTES, 1_048_576,
        "the cap is the 1 MiB channels bound"
    );
    let body = vec![b'a'; WEBHOOK_MAX_BODY_BYTES + 1];
    // A *valid* signature for the oversize body — must STILL be rejected 413.
    let sig = compute_signature_hex(GOOD_SECRET.as_bytes(), &body);
    let rej = verify_webhook(&cfg(), &body, Some(&sig), WEBHOOK_MAX_BODY_BYTES).unwrap_err();
    assert_eq!(
        rej,
        WebhookRejection::PayloadTooLarge {
            len: WEBHOOK_MAX_BODY_BYTES + 1,
            cap: WEBHOOK_MAX_BODY_BYTES,
        },
        "oversize body rejected by the size gate before any HMAC work"
    );
    assert_eq!(rej.http_status(), 413);
}

// ── SYS-AC-105 (full e2e) — external POST /hooks HMAC → real guest run ────────
//
// An external HTTP POST with a valid HMAC-SHA256 signature lands on the live
// production `WebhookListener` (real axum, ephemeral port), is verified by the
// real `verify_webhook`, fires a `TriggerFireEvent{event_type:"webhook"}` into
// the production `WatcherDriver::run_with_trigger_source_with_emitter`, and runs
// a real `WasmRunnableHook` over the SUT's guest → `component.started`/
// `component.finished` (emitter-aware path) + the guest echoes the webhook
// trigger-context into `{output_dir}/result.bin`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sys_ac_105_live_webhook_post_runs_real_guest() {
    let sut = SystemUnderTest::builder()
        .with_triggers()
        .build(J01_SKELETON)
        .await;
    let outdir = tempfile::tempdir().expect("outdir");

    // The PRODUCTION runnable bridge over THIS SUT's real guest component.
    let hook = sut.wasm_runnable_hook("wh-105");

    // The live production axum listener on an ephemeral port + a ready signal so
    // we learn its bound addr. Direct, secret-bearing WebhookConfig (a persisted
    // registry row would have its secret redacted → the listener would refuse).
    const SECRET: &str = "this-is-a-strong-enough-secret";
    let cfg = WebhookConfig {
        path: "/hooks/wh105".into(),
        secret: Some(SECRET.into()),
    };
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let listener = WebhookListener::new("127.0.0.1:0".parse().unwrap()).with_ready_signal(ready_tx);
    let source = WebhookTriggerSource {
        cfg: cfg.clone(),
        source: Arc::new(listener),
    };

    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();
    let emitter = sut.event_emitter();
    let out_path = outdir.path().to_path_buf();
    let watcher = tokio::spawn(async move {
        WatcherDriver::run_with_trigger_source_with_emitter(
            "wh-105",
            Box::new(source),
            hook,
            Some(out_path),
            Some(emitter),
            cancel_clone,
        )
        .await
    });

    // Wait for the listener to bind, then learn the ephemeral port.
    let addr = tokio::time::timeout(Duration::from_secs(5), ready_rx)
        .await
        .expect("webhook listener bound within 5s")
        .expect("ready signal");

    // A real external HTTP POST with a VALID HMAC over the body.
    let body = br#"{"event":"push","ref":"refs/heads/main"}"#;
    let sig = compute_signature_hex(SECRET.as_bytes(), body);
    let req = format!(
        "POST /hooks/wh105 HTTP/1.1\r\nHost: {addr}\r\nx-signature: {sig}\r\n\
         Content-Type: application/json\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n",
        len = body.len()
    );
    let mut stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("connect to webhook listener");
    stream.write_all(req.as_bytes()).await.expect("write head");
    stream.write_all(body).await.expect("write body");
    stream.flush().await.expect("flush");
    let mut resp = Vec::new();
    stream.read_to_end(&mut resp).await.expect("read response");
    let resp = String::from_utf8_lossy(&resp);
    assert!(
        resp.starts_with("HTTP/1.1 200"),
        "valid-HMAC POST is admitted (200); got: {}",
        resp.lines().next().unwrap_or("")
    );

    // Poll for the real guest run to complete (component.finished, attributed to
    // the webhook component).
    let finished_for_id = |e: &Event| {
        e.event_type == "component.finished"
            && e.payload.get("id").and_then(|v| v.as_str()) == Some("wh-105")
    };
    let mut completed = false;
    for _ in 0..400u32 {
        if sut.events().iter().any(finished_for_id) {
            completed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(
        completed,
        "the valid-HMAC POST drove a real guest run to completion (component.finished)"
    );
    cancel.cancel();
    let _ = watcher.await;

    // component.started strictly precedes component.finished (sink emit order).
    let events = sut.events();
    let started_pos = events
        .iter()
        .position(|e| {
            e.event_type == "component.started"
                && e.payload.get("id").and_then(|v| v.as_str()) == Some("wh-105")
        })
        .expect("component.started for wh-105 captured");
    let finished_pos = events
        .iter()
        .position(finished_for_id)
        .expect("component.finished pos");
    assert!(
        started_pos < finished_pos,
        "component.started precedes component.finished in sink emit order"
    );

    // THE run-proof: the guest echoed the webhook trigger-context it RECEIVED
    // into result.bin (event_type|chain_id|depth) — a synthetic event without a
    // real guest run, or a context-dropping path, cannot produce this.
    let echoed = std::fs::read(outdir.path().join("result.bin"))
        .expect("the real guest run wrote {output_dir}/result.bin");
    let echoed = String::from_utf8(echoed).expect("utf8 echo");
    let parts: Vec<&str> = echoed.split('|').collect();
    assert_eq!(
        parts.len(),
        3,
        "echo shape event_type|chain_id|depth; got {echoed:?}"
    );
    assert_eq!(
        parts[0], "webhook",
        "the guest received the webhook trigger event_type from the real POST"
    );
}

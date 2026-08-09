//! Stage-F obs SLICE 2 — T10-T12 (SYS-AC-105): the production `WebhookListener`
//! (axum `WebhookSource`) witnessed end-to-end at the listener half: a real HTTP
//! POST → HMAC verify → `TriggerFireEvent`. Valid HMAC → 200 + fire; bad/missing
//! sig → 401 + no fire; oversized → 413 + no fire; malformed path / bind-in-use →
//! `HookError::Failure` (never a panic).
//!
//! The HTTP client is a blocking `std::net::TcpStream` (cli's tokio has neither
//! the `io-util` nor `time` feature) driven on `spawn_blocking` — no new dep.

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use advance_cli::webhook_listener::WebhookListener;
use advance_scheduler::hook::WebhookSource;
use advance_scheduler::trigger_source::TriggerFireEvent;
use advance_scheduler::types::WebhookConfig;
use advance_scheduler::webhook_hmac::{compute_signature_hex, WEBHOOK_MAX_BODY_BYTES};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

const SECRET: &str = "0123456789abcdef0123456789abcdef"; // 32 bytes (>= 16)
const HTTP_IO_TIMEOUT: Duration = Duration::from_secs(5);

/// Blocking HTTP/1.1 POST; returns the response status code.
fn http_post(addr: SocketAddr, path: &str, sig: Option<&str>, body: &[u8]) -> u16 {
    http_post_declaring(addr, path, sig, body, body.len())
}

/// Like [`http_post`] but permits an explicit `Content-Length`. Socket I/O is
/// bounded, the body is written concurrently with the response read, and only
/// the response status line is read. After that line is captured, the reader
/// closes the socket to unblock any writer stopped by an early response.
/// Deliberately do not half-close the writer first: hyper HTTP/1 treats that EOF
/// as a closed connection unless server-side half-close support is enabled.
fn http_post_declaring(
    addr: SocketAddr,
    path: &str,
    sig: Option<&str>,
    body: &[u8],
    declared_len: usize,
) -> u16 {
    let mut stream = std::net::TcpStream::connect(addr).expect("connect");
    stream
        .set_write_timeout(Some(HTTP_IO_TIMEOUT))
        .expect("set write timeout");
    stream
        .set_read_timeout(Some(HTTP_IO_TIMEOUT))
        .expect("set read timeout");
    let mut req = format!(
        "POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: {declared_len}\r\nConnection: close\r\n",
    );
    if let Some(s) = sig {
        req.push_str(&format!("X-Signature: {s}\r\n"));
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes()).expect("write head");

    let (resp, body_write) = std::thread::scope(|scope| {
        let mut writer = stream.try_clone().expect("clone request stream");
        let body_writer = scope.spawn(move || writer.write_all(body).and_then(|_| writer.flush()));

        let mut resp = Vec::new();
        let mut chunk = [0_u8; 512];
        while !resp.windows(2).any(|window| window == b"\r\n") {
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(read) => {
                    resp.extend_from_slice(&chunk[..read]);
                    assert!(resp.len() <= 8 * 1024, "response status head is too large");
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    panic!("timed out waiting for HTTP response status");
                }
                Err(_error) if !resp.is_empty() => break,
                Err(error) => panic!("read HTTP response status failed: {error}"),
            }
        }
        let _ = stream.shutdown(Shutdown::Both);
        (resp, body_writer.join().expect("body writer thread"))
    });

    let text = String::from_utf8_lossy(&resp);
    let status_line = text.lines().next().unwrap_or("");
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    assert_ne!(
        status, 0,
        "missing HTTP response status; body write: {body_write:?}; response: {text:?}"
    );
    status
}

/// Start a `WebhookListener` on an ephemeral port; return its bound addr, the
/// `TriggerFireEvent` receiver, the cancel token, and the serve join handle.
async fn start_listener(
    secret: Option<String>,
) -> (
    SocketAddr,
    mpsc::Receiver<TriggerFireEvent>,
    CancellationToken,
    tokio::task::JoinHandle<()>,
) {
    let (tx, rx) = mpsc::channel::<TriggerFireEvent>(64);
    let (ready_tx, ready_rx) = oneshot::channel::<SocketAddr>();
    let listener =
        Arc::new(WebhookListener::new("127.0.0.1:0".parse().unwrap()).with_ready_signal(ready_tx));
    let cancel = CancellationToken::new();
    let cfg = WebhookConfig {
        path: "/wh".to_string(),
        secret,
    };
    let l = Arc::clone(&listener);
    let c = cancel.clone();
    let handle = tokio::spawn(async move {
        let _ = l.run(cfg, tx, c).await;
    });
    let addr = ready_rx.await.expect("listener bound + reported its addr");
    (addr, rx, cancel, handle)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t10_valid_hmac_returns_200_and_fires_trigger() {
    let (addr, mut rx, cancel, handle) = start_listener(Some(SECRET.to_string())).await;
    let body = b"hello-webhook".to_vec();
    let sig = compute_signature_hex(SECRET.as_bytes(), &body);

    let status = tokio::task::spawn_blocking(move || http_post(addr, "/wh", Some(&sig), &body))
        .await
        .unwrap();
    assert_eq!(status, 200, "valid HMAC POST must return 200");

    // The handler sends the trigger BEFORE returning 200, so it is already queued.
    let evt = rx.recv().await.expect("a TriggerFireEvent must be fired");
    assert_eq!(evt.trigger_type, "webhook");
    assert!(
        evt.trigger_context.is_some(),
        "webhook trigger carries context"
    );

    cancel.cancel();
    let _ = handle.await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t11_bad_or_missing_signature_returns_401_no_fire() {
    let (addr, mut rx, cancel, handle) = start_listener(Some(SECRET.to_string())).await;
    let body = b"hello-webhook".to_vec();

    // Missing signature.
    let b1 = body.clone();
    let s_missing = tokio::task::spawn_blocking(move || http_post(addr, "/wh", None, &b1))
        .await
        .unwrap();
    assert_eq!(s_missing, 401, "missing X-Signature must 401");

    // Wrong signature.
    let b2 = body.clone();
    let s_bad =
        tokio::task::spawn_blocking(move || http_post(addr, "/wh", Some(&"00".repeat(32)), &b2))
            .await
            .unwrap();
    assert_eq!(s_bad, 401, "wrong signature must 401");

    assert!(
        rx.try_recv().is_err(),
        "a rejected webhook must NOT fire any TriggerFireEvent"
    );
    cancel.cancel();
    let _ = handle.await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t12_oversized_413_and_malformed_path_and_bind_in_use_error() {
    // --- oversized body → 413 (axum DefaultBodyLimit) + no fire ---
    let (addr, mut rx, cancel, handle) = start_listener(Some(SECRET.to_string())).await;
    let body = vec![0x61_u8; WEBHOOK_MAX_BODY_BYTES + 1];
    let sig = compute_signature_hex(SECRET.as_bytes(), &body);
    // Send exactly one byte beyond the limit: the extractor consumes the real
    // body up to its boundary, returns 413, and has no large unread tail whose
    // TCP reset could discard the response under load.
    let status = tokio::task::spawn_blocking(move || http_post(addr, "/wh", Some(&sig), &body))
        .await
        .unwrap();
    assert_eq!(status, 413, "oversized body must 413");
    assert!(rx.try_recv().is_err(), "oversized webhook must NOT fire");
    cancel.cancel();
    let _ = handle.await;

    // --- malformed cfg.path → HookError::Failure (no Router::route panic) ---
    let (tx, _rx2) = mpsc::channel::<TriggerFireEvent>(8);
    let bad = WebhookListener::new("127.0.0.1:0".parse().unwrap());
    let res = bad
        .run(
            WebhookConfig {
                path: "bad-no-slash".to_string(),
                secret: None,
            },
            tx,
            CancellationToken::new(),
        )
        .await;
    assert!(
        res.is_err(),
        "a malformed cfg.path must return Err, not panic"
    );
    assert!(
        format!("{:?}", res.unwrap_err()).contains("invalid route path"),
        "the error must name the invalid route path"
    );

    // --- axum-0.8 capture/wildcard path forms must ALSO be rejected (no panic) ---
    for bad_path in ["/:id", "/*rest", "/a/{cap}", "/q?x"] {
        let (txp, _rxp) = mpsc::channel::<TriggerFireEvent>(8);
        let lp = WebhookListener::new("127.0.0.1:0".parse().unwrap());
        let rp = lp
            .run(
                WebhookConfig {
                    path: bad_path.to_string(),
                    secret: Some(SECRET.to_string()),
                },
                txp,
                CancellationToken::new(),
            )
            .await;
        assert!(
            rp.is_err() && format!("{:?}", rp.unwrap_err()).contains("invalid route path"),
            "axum-panic-grammar path {bad_path:?} must be rejected (not panic)"
        );
    }

    // --- fail-closed: a missing/weak secret must REFUSE to serve (eval Codex Critical) ---
    let (txs, _rxs) = mpsc::channel::<TriggerFireEvent>(8);
    let no_secret = WebhookListener::new("127.0.0.1:0".parse().unwrap());
    let rs = no_secret
        .run(
            WebhookConfig {
                path: "/wh".to_string(),
                secret: None,
            },
            txs,
            CancellationToken::new(),
        )
        .await;
    assert!(
        rs.is_err() && format!("{:?}", rs.unwrap_err()).contains("secret"),
        "a None secret must fail closed (no unauthenticated webhook)"
    );

    // --- bind-in-use → HookError::Failure (not a panic). Both listeners need a
    //     real secret now (fail-closed-on-None) so they reach the bind step. ---
    let (addr2, _rx3, cancel2, handle2) = start_listener(Some(SECRET.to_string())).await;
    let (tx2, _rx4) = mpsc::channel::<TriggerFireEvent>(8);
    let collide = WebhookListener::new(addr2); // already bound by the first listener
    let res2 = collide
        .run(
            WebhookConfig {
                path: "/wh2".to_string(),
                secret: Some(SECRET.to_string()),
            },
            tx2,
            CancellationToken::new(),
        )
        .await;
    assert!(
        res2.is_err(),
        "binding an in-use addr must return Err, not panic"
    );
    assert!(
        format!("{:?}", res2.unwrap_err()).contains("bind"),
        "the error must name the bind failure"
    );
    cancel2.cancel();
    let _ = handle2.await;
}

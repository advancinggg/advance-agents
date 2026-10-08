//! The proof that a Client API listener is still the one this process bound (ADR 2026-10-03
//! D3 foreground re-verification, [`SessionAdmission::InProcessOnly`] only).
//!
//! On a phone, loopback does not mean "this user": other apps share the interface. While the app
//! is suspended the OS may reclaim the listener's socket, and another app may then bind the port.
//! An HTTP answer on that port therefore proves nothing. The re-verification sends a fresh random
//! challenge, and no credential, and accepts only an HMAC of it under a key that exists only in
//! this process, inside the listener being verified ([`ListenerKey`]: never written, logged or
//! sent). The transport answers the challenge itself, before any dispatch, so the answer depends
//! on the listener (its socket and its key), not on the API's load.
//!
//! [`SessionAdmission::InProcessOnly`]: crate::SessionAdmission::InProcessOnly

use std::net::SocketAddr;
use std::time::Duration;

use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zeroize::Zeroizing;

use crate::routes::PATH_HEALTH;
use crate::transport::{LISTENER_CHALLENGE_HEADER, LISTENER_PROOF_HEADER};

type HmacSha256 = Hmac<Sha256>;

/// Domain separation of the proof MAC.
const PROOF_DOMAIN: &[u8] = b"advance client-api listener proof v1";
/// Bytes of a challenge nonce (sent as 64 hex characters).
const NONCE_LEN: usize = 32;
/// The longest response head a re-verification reads.
const MAX_RESPONSE_HEAD: usize = 8 * 1024;

/// One listener's re-verification key: 32 random bytes drawn when the listener is bound. It
/// stays in the listener and its router; nothing reads it out.
pub(crate) struct ListenerKey(Zeroizing<[u8; 32]>);

impl ListenerKey {
    pub(crate) fn generate() -> Self {
        let mut key = Zeroizing::new([0u8; 32]);
        rand::thread_rng().fill_bytes(&mut key[..]);
        Self(key)
    }

    fn mac(&self, nonce: &[u8]) -> Option<HmacSha256> {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&self.0[..]).ok()?;
        mac.update(PROOF_DOMAIN);
        mac.update(nonce);
        Some(mac)
    }

    /// The proof header value answering the challenge header value `challenge`; `None` unless
    /// it is a well-formed challenge (a 32-byte nonce in hex).
    pub(crate) fn answer(&self, challenge: &str) -> Option<String> {
        let nonce = decode_nonce(challenge)?;
        let mac = self.mac(&nonce)?;
        Some(hex::encode(mac.finalize().into_bytes()))
    }

    /// Whether `proof` (hex) is this key's answer to `nonce`. Constant-time.
    fn accepts(&self, nonce: &[u8], proof: &str) -> bool {
        let Ok(proof) = hex::decode(proof) else {
            return false;
        };
        self.mac(nonce)
            .is_some_and(|mac| mac.verify_slice(&proof).is_ok())
    }
}

impl std::fmt::Debug for ListenerKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ListenerKey(<redacted>)")
    }
}

fn decode_nonce(challenge: &str) -> Option<Vec<u8>> {
    if challenge.len() != NONCE_LEN * 2 {
        return None;
    }
    hex::decode(challenge).ok()
}

/// Whether the socket at `addr` answers a fresh challenge with `key`'s proof within `budget`.
/// The request carries the challenge and nothing else: no session, cookie or other credential.
pub(crate) async fn verify(addr: SocketAddr, key: &ListenerKey, budget: Duration) -> bool {
    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);
    match tokio::time::timeout(budget, request_proof(addr, &nonce)).await {
        Ok(Some(proof)) => key.accepts(&nonce, &proof),
        _ => false,
    }
}

async fn request_proof(addr: SocketAddr, nonce: &[u8]) -> Option<String> {
    let mut stream = tokio::net::TcpStream::connect(addr).await.ok()?;
    let request = format!(
        "GET {PATH_HEALTH} HTTP/1.1\r\nHost: {addr}\r\n{LISTENER_CHALLENGE_HEADER}: {}\r\nConnection: close\r\n\r\n",
        hex::encode(nonce)
    );
    stream.write_all(request.as_bytes()).await.ok()?;
    let mut head = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    while head_end(&head).is_none() && head.len() < MAX_RESPONSE_HEAD {
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            break;
        }
        head.extend_from_slice(&chunk[..n]);
    }
    proof_of(&head)
}

fn head_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}

/// The proof header value of a complete `204 No Content` response head; `None` for any other
/// status, an incomplete head, or a missing or repeated proof header.
fn proof_of(response: &[u8]) -> Option<String> {
    let end = head_end(response)?;
    let head = std::str::from_utf8(&response[..end]).ok()?;
    let mut lines = head.split("\r\n");
    let mut status = lines.next()?.split(' ');
    let version = status.next()?;
    let code = status.next()?;
    if !version.starts_with("HTTP/1.") || code != "204" {
        return None;
    }
    let mut proof = None;
    for line in lines {
        let (name, value) = line.split_once(':')?;
        if name.trim().eq_ignore_ascii_case(LISTENER_PROOF_HEADER) {
            if proof.is_some() {
                return None;
            }
            proof = Some(value.trim().to_owned());
        }
    }
    proof
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_001_ac32_a_listener_key_accepts_only_its_own_answer() {
        let key = ListenerKey::generate();
        let other = ListenerKey::generate();
        let nonce = [7u8; NONCE_LEN];
        let challenge = hex::encode(nonce);
        let proof = key
            .answer(&challenge)
            .expect("a well-formed challenge is answered");
        assert_eq!(proof.len(), 64);
        assert!(key.accepts(&nonce, &proof));
        assert!(
            !key.accepts(&[8u8; NONCE_LEN], &proof),
            "bound to the nonce"
        );
        assert!(
            !other.accepts(&nonce, &proof),
            "bound to the listener's key"
        );
        let other_proof = other.answer(&challenge).expect("answered");
        assert!(!key.accepts(&nonce, &other_proof));
        assert!(!key.accepts(&nonce, &challenge), "an echoed challenge");
        assert!(!key.accepts(&nonce, ""));
        assert!(!key.accepts(&nonce, "not hex"));
        assert_eq!(format!("{key:?}"), "ListenerKey(<redacted>)");
    }

    #[test]
    fn module_001_ac32_a_malformed_challenge_is_not_answered() {
        let key = ListenerKey::generate();
        assert!(key.answer("").is_none());
        assert!(key.answer(&"ab".repeat(NONCE_LEN - 1)).is_none());
        assert!(key.answer(&"ab".repeat(NONCE_LEN + 1)).is_none());
        assert!(key.answer(&"zz".repeat(NONCE_LEN)).is_none());
    }

    #[test]
    fn module_001_ac32_only_a_204_head_with_one_proof_header_carries_a_proof() {
        let proof = "ab".repeat(32);
        let ok = format!(
            "HTTP/1.1 204 No Content\r\nX-Advance-Listener-Proof: {proof}\r\ncache-control: no-store\r\n\r\n"
        );
        assert_eq!(proof_of(ok.as_bytes()).as_deref(), Some(proof.as_str()));
        let ok_status = format!("HTTP/1.1 200 OK\r\n{LISTENER_PROOF_HEADER}: {proof}\r\n\r\n");
        assert_eq!(
            proof_of(ok_status.as_bytes()),
            None,
            "a 200 is not an answer"
        );
        let twice = format!(
            "HTTP/1.1 204 No Content\r\n{LISTENER_PROOF_HEADER}: {proof}\r\n{LISTENER_PROOF_HEADER}: {proof}\r\n\r\n"
        );
        assert_eq!(proof_of(twice.as_bytes()), None, "a repeated proof header");
        assert_eq!(
            proof_of(b"HTTP/1.1 204 No Content\r\nconnection: close\r\n\r\n"),
            None
        );
        let unfinished = format!("HTTP/1.1 204 No Content\r\n{LISTENER_PROOF_HEADER}: {proof}\r\n");
        assert_eq!(proof_of(unfinished.as_bytes()), None, "an incomplete head");
    }
}

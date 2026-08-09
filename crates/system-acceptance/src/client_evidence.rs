//! CAPSTONE P3 — the ADR 2026-07-27 D5 one-shot client evidence envelope.
//!
//! "The evidence API returns a one-shot `BoundClientEnvelope { exact_bytes, attestation }`;
//! neither member can be constructed or consumed independently. The attestation binds the
//! challenge, case attempt, request digest, authenticated session, route, response status,
//! exact byte digest, and authority read revision. Criterion facts are parsed from those
//! exact bytes. Hand-built ClientApi DTOs receive no evidence credit."
//!
//! Structural enforcement, not convention:
//! - the ONLY constructor is [`BoundClientEnvelope::mint`], and its `exact_bytes` are the
//!   serde transport serialization of a REAL `ClientApi::handle` return — there is no
//!   `new(bytes, attestation)`;
//! - both fields are private and the ONLY read surface is [`BoundClientEnvelope::open`],
//!   which consumes `self` — one shot; the members leave together or not at all;
//! - the attestation's `exact_byte_digest` is computed INSIDE `mint` over the bytes it
//!   returns, so a swapped body is detectable by any verifier that recomputes it.
//!
//! SD-15 lineage: the fabricated DTO helpers this replaces built `ClientDeviceSummary`
//! values field-by-field in the harness and presented the TYPE as provenance. Here the
//! bytes come from `ClientApi::handle` over the PRODUCTION `MeshDeviceProviderAdapter`
//! (crates/cli/src/client_api_adapters.rs), and the witness parses its criterion facts
//! from those exact bytes.

use advance_client_api::{ClientApi, ClientRequest};
use sha2::{Digest, Sha256};

/// What the envelope attests. Every member is bound at mint time; none is settable after.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientEvidenceAttestation {
    /// Caller-chosen nonce naming this evidence attempt.
    pub challenge: [u8; 16],
    /// Which attempt of the case this is (re-runs get fresh attestations).
    pub case_attempt: u32,
    /// SHA-256 over `method || 0x00 || route || 0x00 || session_token`.
    pub request_digest: [u8; 32],
    /// SHA-256 of the session token (the authenticated session, never the raw token).
    pub session_digest: [u8; 32],
    /// The route the request was served on.
    pub route: String,
    /// Whether the envelope reported success (`ClientEnvelope::is_ok`).
    pub response_status_ok: bool,
    /// SHA-256 of `exact_bytes` — recompute over the opened bytes to verify.
    pub exact_byte_digest: [u8; 32],
    /// The caller-observed authority read revision at mint time (monotonic per rig).
    pub authority_read_revision: u64,
}

/// The one-shot evidence envelope. See the module docs for the structural guarantees.
#[derive(Debug)]
pub struct BoundClientEnvelope {
    exact_bytes: Vec<u8>,
    attestation: ClientEvidenceAttestation,
}

impl BoundClientEnvelope {
    /// Perform ONE authenticated `ClientApi::handle` GET on `route` and seal the result.
    /// This is the only constructor; the call happens inside so the bytes cannot be
    /// substituted between the surface and the seal.
    pub fn mint(
        api: &ClientApi,
        route: &str,
        session_token: &str,
        challenge: [u8; 16],
        case_attempt: u32,
        authority_read_revision: u64,
    ) -> Result<Self, String> {
        let envelope = api.handle(ClientRequest::get(route).with_session(session_token));
        let response_status_ok = envelope.is_ok();
        // The NORMAL transport serializer: what a socket would carry, byte for byte.
        let exact_bytes =
            serde_json::to_vec(&envelope).map_err(|e| format!("transport serialize: {e}"))?;
        let mut req = Sha256::new();
        req.update(b"GET");
        req.update([0u8]);
        req.update(route.as_bytes());
        req.update([0u8]);
        req.update(session_token.as_bytes());
        let attestation = ClientEvidenceAttestation {
            challenge,
            case_attempt,
            request_digest: req.finalize().into(),
            session_digest: Sha256::digest(session_token.as_bytes()).into(),
            route: route.to_string(),
            response_status_ok,
            exact_byte_digest: Sha256::digest(&exact_bytes).into(),
            authority_read_revision,
        };
        Ok(Self {
            exact_bytes,
            attestation,
        })
    }

    /// Consume the envelope: the ONLY read surface, and it takes both members out
    /// together. There is no second open.
    pub fn open(self) -> (Vec<u8>, ClientEvidenceAttestation) {
        (self.exact_bytes, self.attestation)
    }
}

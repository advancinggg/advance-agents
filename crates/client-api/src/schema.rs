//! CONTRACT-192 — the generated client SDK contract: a JSON schema derived (via schemars) from
//! the canonical DTOs, a schema-hash manifest, and conformance vectors.
//!
//! The schema is emitted from the same `#[derive(JsonSchema)]` types that carry `serde`, so it
//! is generated FROM the canonical contract (full type/enum/required/nested fidelity) rather
//! than hand-maintained. The artifacts are checked in under `sdk-artifacts/` and a drift
//! test asserts they byte-match the freshly generated output (the §1.6 "0 schema drift" NFR).

use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::config::ClientApiConfig;
use crate::envelope::{ClientEnvelope, ClientError, ClientErrorCode, ClientWarning, API_VERSION};
use crate::pagination::Cursor;
use crate::session::{Platform, Principal, Scope, SessionInfo};

/// The schema-hash manifest checked against by SDK generators and conformance suites.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientSdkManifest {
    pub api_version: String,
    pub schema_hash: String,
    pub targets: Vec<String>,
}

/// The full generated artifact set.
#[derive(Debug, Clone)]
pub struct SchemaArtifact {
    pub schema: Value,
    pub manifest: ClientSdkManifest,
    pub vectors: Value,
}

impl SchemaArtifact {
    /// Canonical (sorted-key, compact) serialization of the schema — the byte form written to
    /// disk and hashed.
    pub fn schema_json(&self) -> String {
        canonical_json(&self.schema)
    }

    pub fn manifest_json(&self) -> String {
        canonical_json(&serde_json::to_value(&self.manifest).expect("manifest serializes"))
    }

    pub fn vectors_json(&self) -> String {
        canonical_json(&self.vectors)
    }
}

/// Generate the deterministic CONTRACT-192 artifact set from the canonical DTOs.
pub fn generate_schema_artifact() -> SchemaArtifact {
    // schemars emits the structural envelope; the data-XOR-error invariant is a semantic
    // constraint it cannot derive, so inject an explicit `oneOf` (exactly one of data/error is
    // non-null) into the ClientEnvelope component so the schema encodes the §1.4.1 invariant.
    let mut envelope_schema = schema_value::<ClientEnvelope<Value>>();
    if let Value::Object(m) = &mut envelope_schema {
        m.insert(
            "$comment".to_string(),
            json!(
                "Envelope invariant: exactly one of `data`/`error` is non-null (data XOR error)."
            ),
        );
        // All five fields are always present on the wire (`data`/`error` serialize as `null` when
        // absent, never omitted), so require them all — this rejects an `error`-omitted shape that
        // the bare oneOf would otherwise permit.
        m.insert(
            "required".to_string(),
            json!(["api_version", "request_id", "data", "error", "warnings"]),
        );
        m.insert(
            "oneOf".to_string(),
            json!([
                { "properties": { "data": { "not": { "type": "null" } }, "error": { "type": "null" } } },
                { "properties": { "error": { "not": { "type": "null" } }, "data": { "type": "null" } } }
            ]),
        );
    }

    let mut components = json!({
        "ClientEnvelope": envelope_schema,
        "ClientError": schema_value::<ClientError>(),
        "ClientErrorCode": schema_value::<ClientErrorCode>(),
        "ClientWarning": schema_value::<ClientWarning>(),
        "Cursor": schema_value::<Cursor>(),
        "SessionInfo": schema_value::<SessionInfo>(),
        "Principal": schema_value::<Principal>(),
        "Platform": schema_value::<Platform>(),
        "Scope": schema_value::<Scope>(),
        // m020-s2 provider-family DTOs (additive).
        "ClientRunSummary": schema_value::<crate::runs::ClientRunSummary>(),
        "ClientRunMutation": schema_value::<crate::runs::ClientRunMutation>(),
        "ClientAgentTreeNode": schema_value::<crate::runs::ClientAgentTreeNode>(),
        "ClientSendMessageRequest": schema_value::<crate::messages::ClientSendMessageRequest>(),
        "ClientMessageAck": schema_value::<crate::messages::ClientMessageAck>(),
        "ClientMessageStatus": schema_value::<crate::messages::ClientMessageStatus>(),
        "ClientToolEntry": schema_value::<crate::tools::ClientToolEntry>(),
        "ClientMcpEntry": schema_value::<crate::tools::ClientMcpEntry>(),
        "ClientSkillEntry": schema_value::<crate::tools::ClientSkillEntry>(),
        "ClientToolInventory": schema_value::<crate::tools::ClientToolInventory>(),
        // m020-s3 CONTRACT-191 event DTOs (additive).
        "ClientEventPriority": schema_value::<crate::events::ClientEventPriority>(),
        "ClientScalar": schema_value::<crate::events::ClientScalar>(),
        "ClientEvent": schema_value::<crate::events::ClientEvent>(),
        "ClientEventCursor": schema_value::<crate::events::ClientEventCursor>(),
        "ClientEventFilter": schema_value::<crate::events::ClientEventFilter>(),
        "ClientEventsRequest": schema_value::<crate::events::ClientEventsRequest>(),
        "ClientEventStreamRequest": schema_value::<crate::events::ClientEventStreamRequest>(),
        "ClientEventPage": schema_value::<crate::events::ClientEventPage>(),
        // legacy-three bound grant/history DTOs.
        "ClientCapParam": schema_value::<crate::providers::grants::ClientCapParam>(),
        "ClientGrantTtl": schema_value::<crate::providers::grants::ClientGrantTtl>(),
        "ClientPendingGrant": schema_value::<crate::providers::grants::ClientPendingGrant>(),
        "ClientGrantApproveRequest": schema_value::<crate::providers::grants::ClientGrantApproveRequest>(),
        "ClientGrantDenyRequest": schema_value::<crate::providers::grants::ClientGrantDenyRequest>(),
        "ClientGrantNarrowRequest": schema_value::<crate::providers::grants::ClientGrantNarrowRequest>(),
        "ClientGrantRevokeRequest": schema_value::<crate::providers::grants::ClientGrantRevokeRequest>(),
        "ClientPresetApplyRequest": schema_value::<crate::providers::grants::ClientPresetApplyRequest>(),
        "ClientGrantDecision": schema_value::<crate::providers::grants::ClientGrantDecision>(),
        "ClientGrantRevokeResult": schema_value::<crate::providers::grants::ClientGrantRevokeResult>(),
        "ClientPresetApplyResult": schema_value::<crate::providers::grants::ClientPresetApplyResult>(),
        "ClientHistoryEntry": schema_value::<crate::providers::history::ClientHistoryEntry>(),
        "ClientHistoryResponse": schema_value::<crate::providers::history::ClientHistoryResponse>(),
    });

    // Tee T2 (CONTRACT-235) LLM delta-subscription DTO family (additive).
    // Inserted via map ops — the `json!` block above is near the macro recursion limit.
    if let Value::Object(m) = &mut components {
        m.insert(
            "LlmDeltaItem".to_string(),
            schema_value::<crate::deltas::LlmDeltaItem>(),
        );
        m.insert(
            "LlmDeltaUsage".to_string(),
            schema_value::<crate::deltas::LlmDeltaUsage>(),
        );
        m.insert(
            "LlmDeltaTerminal".to_string(),
            schema_value::<crate::deltas::LlmDeltaTerminal>(),
        );
        m.insert(
            "LlmDeltaCursor".to_string(),
            schema_value::<crate::deltas::LlmDeltaCursor>(),
        );
        m.insert(
            "LlmDeltaPage".to_string(),
            schema_value::<crate::deltas::LlmDeltaPage>(),
        );
        m.insert(
            "LlmDeltaWirePage".to_string(),
            schema_value::<crate::deltas::LlmDeltaWirePage>(),
        );
        m.insert(
            "LlmDeltaStreamRequest".to_string(),
            schema_value::<crate::deltas::LlmDeltaStreamRequest>(),
        );
    }

    let schema = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "advance client-api CONTRACT-192 schema",
        "api_version": API_VERSION,
        "components": components,
    });

    let schema_hash = sha256_hex(canonical_json(&schema).as_bytes());
    let default_targets = ClientApiConfig::default().sdk_targets;
    for t in &default_targets {
        if !is_safe_target(t) {
            panic!("unsafe sdk_target in default config: {:?}", t);
        }
    }
    let manifest = ClientSdkManifest {
        api_version: API_VERSION.to_string(),
        schema_hash,
        targets: default_targets,
    };
    let vectors = conformance_vectors();

    SchemaArtifact {
        schema,
        manifest,
        vectors,
    }
}

/// The conformance vectors a later per-platform SDK reuses (and this crate's reference
/// conformance test consumes). Each vector declares its `kind`: `data`, `error`, or `invalid`
/// (a vector that MUST be rejected by the envelope invariant checker).
pub fn conformance_vectors() -> Value {
    json!({
        "api_version": API_VERSION,
        "vectors": [
            {
                "name": "ok_data",
                "kind": "data",
                "envelope": {
                    "api_version": API_VERSION,
                    "request_id": "req_example_ok",
                    "data": { "status": "ok" },
                    "error": null,
                    "warnings": []
                }
            },
            {
                "name": "data_with_warning",
                "kind": "data",
                "envelope": {
                    "api_version": API_VERSION,
                    "request_id": "req_example_warn",
                    "data": { "runs": [] },
                    "error": null,
                    "warnings": [
                        { "code": "idempotent_replay", "message": "replayed prior outcome" }
                    ]
                }
            },
            {
                "name": "error_unsupported_version",
                "kind": "error",
                "envelope": {
                    "api_version": API_VERSION,
                    "request_id": "req_example_err",
                    "data": null,
                    "error": {
                        "code": "unsupported_api_version",
                        "message": "unsupported api_version",
                        "details": ["2026-06-30"]
                    },
                    "warnings": []
                }
            },
            {
                "name": "error_unauthenticated",
                "kind": "error",
                "envelope": {
                    "api_version": API_VERSION,
                    "request_id": "req_example_unauth",
                    "data": null,
                    "error": { "code": "unauthenticated", "message": "missing session" },
                    "warnings": []
                }
            },
            {
                "name": "error_session_expired",
                "kind": "error",
                "envelope": {
                    "api_version": API_VERSION,
                    "request_id": "req_example_expired",
                    "data": null,
                    "error": { "code": "session_expired", "message": "session expired" },
                    "warnings": []
                }
            },
            {
                "name": "error_forbidden",
                "kind": "error",
                "envelope": {
                    "api_version": API_VERSION,
                    "request_id": "req_example_forbidden",
                    "data": null,
                    "error": { "code": "forbidden", "message": "insufficient scope" },
                    "warnings": []
                }
            },
            {
                "name": "error_validation_invalid_state",
                "kind": "error",
                "envelope": {
                    "api_version": API_VERSION,
                    "request_id": "req_example_invalid_state",
                    "data": null,
                    "error": { "code": "invalid_state", "message": "invalid_run_state" },
                    "warnings": []
                }
            },
            {
                "name": "error_validation_projection_rejected",
                "kind": "error",
                "envelope": {
                    "api_version": API_VERSION,
                    "request_id": "req_example_projection",
                    "data": null,
                    "error": { "code": "projection_rejected", "message": "invalid history request" },
                    "warnings": []
                }
            },
            {
                "name": "error_not_found",
                "kind": "error",
                "envelope": {
                    "api_version": API_VERSION,
                    "request_id": "req_example_not_found",
                    "data": null,
                    "error": { "code": "not_found", "message": "run_not_found" },
                    "warnings": []
                }
            },
            {
                "name": "error_idempotency_required",
                "kind": "error",
                "envelope": {
                    "api_version": API_VERSION,
                    "request_id": "req_example_idem_required",
                    "data": null,
                    "error": { "code": "idempotency_required", "message": "missing idempotency key" },
                    "warnings": []
                }
            },
            {
                "name": "error_idempotency_conflict",
                "kind": "error",
                "envelope": {
                    "api_version": API_VERSION,
                    "request_id": "req_example_idem_conflict",
                    "data": null,
                    "error": {
                        "code": "idempotency_conflict",
                        "message": "idempotency key used for a different request"
                    },
                    "warnings": []
                }
            },
            {
                "name": "error_unknown_route",
                "kind": "error",
                "envelope": {
                    "api_version": API_VERSION,
                    "request_id": "req_example_unknown_route",
                    "data": null,
                    "error": { "code": "unknown_route", "message": "no route" },
                    "warnings": []
                }
            },
            {
                "name": "error_request_too_large",
                "kind": "error",
                "envelope": {
                    "api_version": API_VERSION,
                    "request_id": "req_example_too_large",
                    "data": null,
                    "error": { "code": "request_too_large", "message": "body exceeds max" },
                    "warnings": []
                }
            },
            {
                "name": "error_module_unavailable",
                "kind": "error",
                "envelope": {
                    "api_version": API_VERSION,
                    "request_id": "req_example_unavailable",
                    "data": null,
                    "error": { "code": "module_unavailable", "message": "run provider not wired" },
                    "warnings": []
                }
            },
            {
                "name": "invalid_both_data_and_error",
                "kind": "invalid",
                "envelope": {
                    "api_version": API_VERSION,
                    "request_id": "req_example_invalid",
                    "data": { "status": "ok" },
                    "error": { "code": "module_unavailable", "message": "both set" },
                    "warnings": []
                }
            }
        ]
    })
}

/// The checked-in CONTRACT-192 SDK artifacts directory (crate-local).
pub fn shared_sdk_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("sdk-artifacts")
}

pub fn schema_path() -> PathBuf {
    shared_sdk_dir().join("schema/client-api.schema.json")
}

pub fn manifest_path() -> PathBuf {
    shared_sdk_dir().join("schema/manifest.json")
}

pub fn vectors_path() -> PathBuf {
    shared_sdk_dir().join("conformance/vectors.json")
}

// ── internals ───────────────────────────────────────────────────────────────────────────

fn schema_value<T: schemars::JsonSchema>() -> Value {
    serde_json::to_value(schemars::schema_for!(T)).expect("schema serializes")
}

/// sha256 of `bytes`, hex-encoded (exposed for the drift/hash conformance test).
pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

/// Deterministic canonical JSON: object keys sorted recursively, compact separators. Normalizes
/// any map-ordering nondeterminism so the on-disk artifact + its hash are byte-stable.
pub fn canonical_json(v: &Value) -> String {
    let mut out = String::new();
    write_canonical(v, &mut out);
    out
}

fn write_canonical(v: &Value, out: &mut String) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::String(s) => out.push_str(&serde_json::to_string(s).expect("string escapes")),
        Value::Array(a) => {
            out.push('[');
            for (i, e) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(e, out);
            }
            out.push(']');
        }
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(k).expect("key escapes"));
                out.push(':');
                write_canonical(&m[*k], out);
            }
            out.push('}');
        }
    }
}

/// Enforce the CONTRACT-192 generation gate before any write of the canonical artifacts.
/// Computes the full set (schema + manifest + vectors) and aborts if any would differ
/// from the checked-in versions. Read failures are treated as FAIL (fail-closed).
/// This protects the entire CONTRACT-192 witness set.
pub fn enforce_schema_hash_gate() -> std::io::Result<()> {
    let art = generate_schema_artifact();

    let checks = [
        (schema_path(), art.schema_json(), "schema"),
        (manifest_path(), art.manifest_json(), "manifest"),
        (vectors_path(), art.vectors_json(), "vectors"),
    ];

    for (path, new_bytes, label) in checks {
        let disk = std::fs::read_to_string(&path).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                format!(
                    "SDK generation gate cannot read {} at {}: {}",
                    label,
                    path.display(),
                    e
                ),
            )
        })?;
        if disk != new_bytes {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!(
                    "SDK generation would change the {} ({} vs on-disk). \
                     This would invalidate the CONTRACT-192 / AC-02 witness. Aborting.",
                    label,
                    path.display()
                ),
            ));
        }
    }
    Ok(())
}

/// Pure (no fs) emitter for a single target's declarative surface. Used by bin (with real path)
/// and by tests (with temp dir) so the AC-12 witness can prove emitted == committed without
/// mutating the real tree during test.
pub fn platform_surface_json(target: &str) -> String {
    // Derive cursor logical fields from the actual JsonSchema of the types (not literals).
    let pag_schema = schema_value::<crate::pagination::Cursor>();
    let rec_schema = schema_value::<crate::events::ClientEventCursor>();

    let pag_fields = extract_property_keys(&pag_schema);
    let rec_fields = extract_property_keys(&rec_schema);
    let delta_cursor_fields =
        extract_property_keys(&schema_value::<crate::deltas::LlmDeltaCursor>());
    let delta_request_fields =
        extract_property_keys(&schema_value::<crate::deltas::LlmDeltaStreamRequest>());

    // Distinguish the two cursor kinds accurately:
    // - reconnect_cursor uses real AEAD opaque tokens (ClientEventCursor).
    // - pagination_cursor (list Cursor) is a base64url-encoded position token (not AEAD-protected).
    let surface = json!({
        "target": target,
        "error_codes": ClientErrorCode::known_codes(),
        "pagination_cursor": {
            "type": "base64url_position",
            "logical_fields": pag_fields,
            "note": "Plain (non-AEAD) position token. Treat as opaque value; do not construct."
        },
        "reconnect_cursor": {
            "type": "struct",
            "logical_fields": rec_fields,
            "note": "ClientEventCursor struct: stream_id (plaintext, must match filter), last_event_id (optional AEAD sealed token). Sent as separate fields in ClientEventStreamRequest (both or neither). Not a single opaque blob like list pagination cursor."
        },
        "example_idempotency_warnings": ["idempotent_replay"],
        "envelope_invariant": "exactly one of data/error is non-null (data XOR error)",
        // Tee T2 (CONTRACT-235): the LLM token-delta subscription surface.
        "llm_delta_stream": {
            "route": "/client/llm/deltas/stream",
            "scope": "read_llm_deltas",
            "request": {
                "logical_fields": delta_request_fields,
                "note": "WebSocket Text frame; stream selection rides this frame only (never the URL query string). from_cursor is the AEAD-sealed delta cursor from a prior page; its sealed body carries both {stream_key, seq} (both-or-neither) and must match the presented plaintext stream_key."
            },
            "cursor": {
                "type": "aead_sealed_delta_cursor",
                "logical_fields": delta_cursor_fields,
                "note": "Opaque sealed token minted only at wire-item boundaries, in its own independent domain: event cursors and delta cursors are mutually non-replayable. Treat as opaque; do not construct."
            },
            "note": crate::deltas::LLM_DELTA_ABSENT_NOTE
        },
        "notes": [
            "Treat all cursor values as opaque tokens. Pagination cursor is a non-cryptographic position; reconnect cursor is a composite (stream_id + AEAD last_event_id). Do not construct or deeply parse.",
            "Idempotency keys are scoped to (principal, method, family, key).",
            "Unknown error codes must be tolerated (forward-compat catch-all).",
            crate::deltas::LLM_DELTA_ABSENT_NOTE
        ]
    });
    canonical_json(&surface)
}

/// Extract sorted property keys from a schemars Value (for Cursor-like objects).
fn extract_property_keys(schema: &Value) -> Vec<String> {
    if let Some(props) = schema.get("properties").and_then(|v| v.as_object()) {
        let mut keys: Vec<String> = props.keys().cloned().collect();
        keys.sort();
        keys
    } else {
        vec![]
    }
}

/// Write surfaces for all targets under the given base (the conformance/ dir).
/// The caller is responsible for having passed the hash gate if schema artifacts are also touched.
/// Base is constructed internally from CARGO_MANIFEST_DIR (trusted); we strictly validate only the
/// per-target names to prevent traversal or bad names.
pub fn write_platform_surfaces(base: &std::path::Path) -> std::io::Result<()> {
    // Canonicalize to resolve .. and symlinks for the base (trusted construction from CARGO_MANIFEST_DIR).
    let base = base.canonicalize().map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("failed to canonicalize base for surfaces: {}", e),
        )
    })?;
    // Guard the "fixtures" component itself (after canonical base) against symlink
    let fixtures_base = base.join("fixtures");
    if let Ok(meta) = std::fs::symlink_metadata(&fixtures_base) {
        if meta.file_type().is_symlink() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "refusing to use symlinked 'fixtures' directory under conformance",
            ));
        }
    }
    for t in ClientApiConfig::default().sdk_targets {
        if !is_safe_target(&t) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("unsafe sdk_target {:?} — rejected to prevent path traversal or bad artifact names", t),
            ));
        }
        let dir = fixtures_base.join(&t);
        std::fs::create_dir_all(&dir)?;
        let target = dir.join("surface.json");
        let content = platform_surface_json(&t);
        safe_write(&target, &content)?;
    }
    Ok(())
}

/// Safe write for the core CONTRACT-192 artifacts (fail if target is symlink).
/// Uses temp + rename for atomicity. Uses create_new on tmp to reduce TOCTOU on the temp name.
pub fn safe_write(path: &std::path::Path, content: &str) -> std::io::Result<()> {
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("refusing to write through symlink at {:?}", path),
            ));
        }
    }
    let tmp = path.with_extension("tmp");
    if let Ok(meta) = std::fs::symlink_metadata(&tmp) {
        if meta.file_type().is_symlink() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("refusing to write tmp through symlink at {:?}", tmp),
            ));
        }
    }
    // create_new to avoid following or overwriting existing tmp
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)?
        .write_all(content.as_bytes())?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Reject targets that could cause path traversal, weird FS names, or bad identifiers
/// in generated client artifacts.
fn is_safe_target(t: &str) -> bool {
    if t.is_empty() || t.len() > 64 {
        return false;
    }
    // Allow only [a-z0-9_-]
    t.chars()
        .all(|c| matches!(c, 'a'..='z' | '0'..='9' | '_' | '-'))
}

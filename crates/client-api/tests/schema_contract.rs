//! MODULE-020-AC-02 (contract) — the CONTRACT-192 schema is generated (via schemars) from the
//! canonical DTOs, a schema-hash manifest matches, the checked-in artifacts do not drift, and
//! the conformance vectors satisfy the envelope invariants. (§3.3 MODULE-020-T02.)
//!
//! Per-platform SDK stubs + cross-platform parity are AC-12 (Wave-25, m020-s5) — out of scope.

use serde_json::Value;

use advance_client_api::envelope::{ClientEnvelope, ClientErrorCode, API_VERSION};
use advance_client_api::schema::{
    generate_schema_artifact, manifest_path, schema_path, sha256_hex, shared_sdk_dir, vectors_path,
};
use advance_client_api::version::check_version;

// ── T02a: deterministic generation ────────────────────────────────────────────────────────
#[test]
fn t02a_generation_is_deterministic() {
    let a = generate_schema_artifact();
    let b = generate_schema_artifact();
    assert_eq!(a.schema_json(), b.schema_json());
    assert_eq!(a.manifest_json(), b.manifest_json());
    assert_eq!(a.vectors_json(), b.vectors_json());
}

// ── T02b: manifest hash matches the canonical schema ──────────────────────────────────────
#[test]
fn t02b_manifest_hash_matches_schema() {
    let art = generate_schema_artifact();
    let recomputed = sha256_hex(art.schema_json().as_bytes());
    assert_eq!(
        art.manifest.schema_hash, recomputed,
        "manifest schema_hash must equal sha256 of the canonical schema"
    );
}

// ── T02c: zero drift vs checked-in artifacts ──────────────────────────────────────────────
#[test]
fn t02c_zero_drift_vs_checked_in() {
    let art = generate_schema_artifact();

    let schema_disk = std::fs::read_to_string(schema_path())
        .expect("client-api.schema.json missing — run `cargo run -p advance-client-api --bin gen_client_sdk`");
    assert_eq!(
        schema_disk,
        art.schema_json(),
        "schema drift — regenerate with gen_client_sdk"
    );

    let manifest_disk = std::fs::read_to_string(manifest_path()).expect("manifest.json missing");
    assert_eq!(manifest_disk, art.manifest_json(), "manifest drift");

    let vectors_disk = std::fs::read_to_string(vectors_path()).expect("vectors.json missing");
    assert_eq!(vectors_disk, art.vectors_json(), "vectors drift");
}

// ── T02d: conformance vectors satisfy envelope invariants ─────────────────────────────────
#[test]
fn t02d_conformance_vectors() {
    let art = generate_schema_artifact();
    let vectors = art.vectors["vectors"].as_array().expect("vectors array");
    assert!(!vectors.is_empty());

    for v in vectors {
        let name = v["name"].as_str().unwrap_or("?");
        let kind = v["kind"].as_str().expect("vector kind");
        let parsed: ClientEnvelope<Value> =
            serde_json::from_value(v["envelope"].clone()).expect("envelope parses");
        assert!(!parsed.request_id.is_empty(), "{name}: request_id present");

        match kind {
            "data" => {
                assert!(
                    parsed.is_ok(),
                    "{name}: data vector must be a valid ok envelope"
                );
                assert!(
                    check_version(&parsed.api_version).is_ok(),
                    "{name}: supported version"
                );
            }
            "error" => {
                assert!(
                    parsed.is_err(),
                    "{name}: error vector must be a valid error envelope"
                );
                assert!(parsed.error_code().is_some());
            }
            "invalid" => {
                // both data and error set → the invariant checker rejects it (neither ok nor err)
                assert!(
                    !parsed.is_ok() && !parsed.is_err(),
                    "{name}: invalid vector must be rejected by the data-XOR-error invariant"
                );
            }
            other => panic!("{name}: unknown vector kind {other}"),
        }
    }
}

// ── T02e: schema fidelity (schemars-derived; covers DTO fields + error-code enum) ─────────
#[test]
fn t02e_schema_fidelity() {
    let art = generate_schema_artifact();
    let comps = &art.schema["components"];

    for dto in [
        "ClientEnvelope",
        "ClientError",
        "ClientErrorCode",
        "ClientWarning",
        "Cursor",
        "SessionInfo",
        "Principal",
        "Platform",
        "Scope",
        // m020-s2 provider-family DTOs.
        "ClientRunSummary",
        "ClientRunMutation",
        "ClientAgentTreeNode",
        "ClientSendMessageRequest",
        "ClientMessageAck",
        "ClientMessageStatus",
        "ClientToolEntry",
        "ClientMcpEntry",
        "ClientSkillEntry",
        "ClientToolInventory",
        // m020-s3 CONTRACT-191 event DTOs.
        "ClientEventPriority",
        "ClientScalar",
        "ClientEvent",
        "ClientEventCursor",
        "ClientEventFilter",
        "ClientEventsRequest",
        "ClientEventStreamRequest",
        "ClientEventPage",
        // tee T2 (CONTRACT-235) LLM delta-subscription DTOs.
        "LlmDeltaItem",
        "LlmDeltaUsage",
        "LlmDeltaTerminal",
        "LlmDeltaCursor",
        "LlmDeltaPage",
        "LlmDeltaWirePage",
        "LlmDeltaStreamRequest",
    ] {
        assert!(comps.get(dto).is_some(), "schema missing DTO {dto}");
    }

    // Envelope declares its properties (schemars emits type-accurate structure).
    let env = &comps["ClientEnvelope"];
    for field in ["api_version", "request_id", "data", "error", "warnings"] {
        assert!(
            json_contains_string(env, field),
            "ClientEnvelope schema missing field {field}"
        );
    }

    // ClientErrorCode enum declares the full known (server-producible) code set.
    let code_schema = &comps["ClientErrorCode"];
    for code in ClientErrorCode::known_codes() {
        assert!(
            json_contains_string(code_schema, code),
            "ClientErrorCode schema missing code {code}"
        );
    }
}

// ── T02f: manifest metadata ───────────────────────────────────────────────────────────────
#[test]
fn t02f_manifest_metadata() {
    let art = generate_schema_artifact();
    assert_eq!(art.manifest.api_version, API_VERSION);
    assert_eq!(
        art.manifest.targets,
        vec!["web", "mac", "ios", "android", "windows"]
    );
}

/// Recursively true if any object key OR string value in `v` equals `needle`.
fn json_contains_string(v: &Value, needle: &str) -> bool {
    match v {
        Value::String(s) => s == needle,
        Value::Array(a) => a.iter().any(|e| json_contains_string(e, needle)),
        Value::Object(m) => {
            m.keys().any(|k| k == needle) || m.values().any(|e| json_contains_string(e, needle))
        }
        _ => false,
    }
}

// ── MODULE-020-AC-12 declaration-parity supplements (m020-s5): per-platform surface fixtures +
//    generator gate. These t12* checks prove the five committed fixtures are byte-identical to
//    the emitter and uniform across targets. The AC-12 witness of record — the SHARED error/
//    pagination/idempotency/reconnect contract suite EXERCISED against the real in-process core
//    and asserted against every fixture — lives in tests/sdk_conformance.rs (MODULE-020-T12). ──

#[test]
fn t12a_schema_hash_gate_exists_and_schema_untouched() {
    // The gate function exists and, on a clean tree, passes (no drift).
    assert!(advance_client_api::schema::enforce_schema_hash_gate().is_ok());
    // Re-generate the core artifacts; they must still match disk (AC-02).
    let art = generate_schema_artifact();
    let schema_disk = std::fs::read_to_string(schema_path()).unwrap();
    assert_eq!(schema_disk, art.schema_json());
}

#[test]
fn t12d_emitter_produces_committed_fixtures() {
    // Per plan D6 / SDK-T06: the emitter must be callable and produce exactly the committed bytes.
    let targets = ["web", "mac", "ios", "android", "windows"];
    for t in targets {
        let emitted = advance_client_api::schema::platform_surface_json(t);
        let committed_path = shared_sdk_dir()
            .join("conformance/fixtures")
            .join(t)
            .join("surface.json");
        let committed = std::fs::read_to_string(&committed_path).expect("committed surface");
        assert_eq!(
            emitted, committed,
            "emitter must produce byte-identical surface for {}",
            t
        );
    }
}

#[test]
fn t12b_five_surfaces_exist_and_are_uniform() {
    let art = generate_schema_artifact();
    let targets: Vec<String> = art.manifest.targets.clone();
    assert_eq!(
        targets.len(),
        5,
        "default targets web,mac,ios,android,windows"
    );

    let fixtures_dir = shared_sdk_dir().join("conformance/fixtures");
    // Detect stale or injected target directories (strict: only immediate subdirs, no symlinks, no extra files at top)
    let mut on_disk: Vec<String> = std::fs::read_dir(&fixtures_dir)
        .expect("fixtures dir")
        .filter_map(|e| e.ok())
        .filter(|e| {
            let p = e.path();
            p.is_dir()
                && !p
                    .symlink_metadata()
                    .map(|m| m.file_type().is_symlink())
                    .unwrap_or(true)
        })
        .map(|e| {
            e.file_name()
                .into_string()
                .expect("target dir names must be valid UTF-8")
        })
        .collect();
    on_disk.sort();
    let mut declared = targets.clone();
    declared.sort();
    assert_eq!(on_disk, declared, "fixtures directory must contain exactly the declared targets, no stale/injected dirs or symlinks");

    // Ensure no stray files directly in fixtures/
    for entry in std::fs::read_dir(&fixtures_dir).expect("read fixtures") {
        let e = entry.expect("entry");
        if e.path().is_file() {
            panic!("stray file directly in fixtures/: {:?}", e.path());
        }
    }

    let comps = &art.schema["components"];
    let mut expected_pag: Vec<String> = comps["Cursor"]["properties"]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect();
    expected_pag.sort();
    let mut expected_rec: Vec<String> = comps["ClientEventCursor"]["properties"]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect();
    expected_rec.sort();

    let mut surfaces = vec![];
    for t in &targets {
        let p = fixtures_dir.join(t).join("surface.json");
        let s = std::fs::read_to_string(&p).expect("surface must exist after gen");
        let v: Value = serde_json::from_str(&s).expect("valid json surface");

        let surf_codes: Vec<String> = v["error_codes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap().to_string())
            .collect();
        assert_eq!(
            surf_codes,
            ClientErrorCode::known_codes(),
            "surface error_codes must equal known_codes()"
        );

        let pag_log = v["pagination_cursor"]["logical_fields"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap().to_string())
            .collect::<Vec<_>>();
        let rec_log = v["reconnect_cursor"]["logical_fields"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap().to_string())
            .collect::<Vec<_>>();
        assert_eq!(
            pag_log, expected_pag,
            "pagination logical fields must match schema Cursor properties"
        );
        assert_eq!(
            rec_log, expected_rec,
            "reconnect logical fields must match schema ClientEventCursor properties"
        );

        surfaces.push(v);
    }

    let first = &surfaces[0];
    for s in &surfaces[1..] {
        assert_eq!(s["error_codes"], first["error_codes"]);
        assert_eq!(s["pagination_cursor"], first["pagination_cursor"]);
        assert_eq!(s["reconnect_cursor"], first["reconnect_cursor"]);
        assert_eq!(
            s["example_idempotency_warnings"],
            first["example_idempotency_warnings"]
        );
        assert_eq!(s["envelope_invariant"], first["envelope_invariant"]);
    }
}

#[test]
fn t12c_surfaces_exercise_shared_vectors() {
    let art = generate_schema_artifact();
    let vectors = &art.vectors["vectors"];
    for t in &art.manifest.targets {
        let p = shared_sdk_dir()
            .join("conformance/fixtures")
            .join(t)
            .join("surface.json");
        let s: Value = serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
        let allowed_errs: Vec<_> = s["error_codes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        let allowed_warns: Vec<_> = s["example_idempotency_warnings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        // Accurate types after adversarial review:
        // pagination_cursor = base64url_position (not AEAD)
        // reconnect_cursor  = struct (fields sent separately)
        assert_eq!(s["pagination_cursor"]["type"], "base64url_position");
        assert_eq!(s["reconnect_cursor"]["type"], "struct");

        for v in vectors.as_array().unwrap() {
            if let Some(err) = v["envelope"]["error"]["code"].as_str() {
                assert!(
                    allowed_errs.contains(&err),
                    "target {} must allow error code {} from shared vectors",
                    t,
                    err
                );
            }
            for w in v["envelope"]["warnings"].as_array().unwrap() {
                if let Some(code) = w["code"].as_str() {
                    if code.contains("idempotent") {
                        assert!(
                            allowed_warns.contains(&code),
                            "target {} must allow warning {} from vectors",
                            t,
                            code
                        );
                    }
                }
            }
            // Declaration containment (supplementary): every vector-declared code must be a
            // member of the surface's declared sets. This is NOT an execution witness — the
            // exercised four-semantics suite is tests/sdk_conformance.rs.
            let surf_err_codes: Vec<_> = s["error_codes"]
                .as_array()
                .unwrap()
                .iter()
                .map(|c| c.as_str().unwrap())
                .collect();
            if let Some(err) = v["envelope"]["error"]["code"].as_str() {
                assert!(
                    surf_err_codes.contains(&err),
                    "binding from surface must accept only declared error codes"
                );
            }
            for w in v["envelope"]["warnings"].as_array().unwrap() {
                if let Some(code) = w["code"].as_str() {
                    if code.contains("idempotent") {
                        let surf_warns: Vec<_> = s["example_idempotency_warnings"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .map(|c| c.as_str().unwrap())
                            .collect();
                        assert!(
                            surf_warns.contains(&code),
                            "binding must accept declared warnings"
                        );
                    }
                }
            }
            // Reconnect cursor: surface declares the struct fields; simulate building a request shape
            let rec_fields: Vec<_> = s["reconnect_cursor"]["logical_fields"]
                .as_array()
                .unwrap()
                .iter()
                .map(|f| f.as_str().unwrap())
                .collect();
            assert!(
                rec_fields.contains(&"stream_id") && rec_fields.contains(&"last_event_id"),
                "binding uses declared reconnect fields"
            );
            // Pagination: surface declares fields; simulate using as opaque position
            let pag_fields: Vec<_> = s["pagination_cursor"]["logical_fields"]
                .as_array()
                .unwrap()
                .iter()
                .map(|f| f.as_str().unwrap())
                .collect();
            assert!(
                pag_fields.contains(&"offset") || pag_fields.contains(&"last_id"),
                "binding uses declared pagination fields"
            );
        }
    }
}

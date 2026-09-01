//! MODULE-020-AC-02 (contract) — the CONTRACT-192 schema is generated (via schemars) from the
//! canonical DTOs, a schema-hash manifest matches, the checked-in artifacts do not drift, and
//! the conformance vectors satisfy the envelope invariants. (§3.3 MODULE-020-T02.)
//!
//! Per-platform SDK stubs + cross-platform parity are AC-12 (Wave-25, m020-s5) — out of scope.

use std::collections::BTreeMap;

use serde_json::Value;

use advance_client_api::compat::{
    check_response_compat, classify_cat_file_exists, classify_git_show, enforce_compat_gate,
    enforce_compat_gate_at, git_path_is_canonical, interpret_git_show, live_snapshot,
    normalize_parent_sha, parse_compat_parent_sha, prefer_merge_first_parent, resolve_parent_spec,
    response_field_inventory, CompatError, CompatMigration, CompatSnapshot, FieldMeta,
    GitShowOutput, BASELINE_REL, EXCLUDED_COMPONENTS, RESPONSE_COMPONENTS,
};
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

// ── T14: MODULE-020-AC-14 backward-compat gate ─────────────────────────────────────────────

fn t14_live() -> CompatSnapshot {
    live_snapshot().expect("live inventory")
}

fn t14_drop(mut snap: CompatSnapshot, component: &str, field: &str) -> CompatSnapshot {
    snap.fields
        .get_mut(component)
        .unwrap_or_else(|| panic!("component {component}"))
        .remove(field)
        .unwrap_or_else(|| panic!("field {component}.{field}"));
    snap
}

fn t14_covering(removed: &[&str]) -> CompatMigration {
    CompatMigration {
        from: API_VERSION.to_string(),
        to: "2026-09-01".into(),
        removed: removed.iter().map(|s| (*s).to_string()).collect(),
        notes: "intentional response-field removal".into(),
    }
}

fn assert_same_version(err: CompatError, field: &str) {
    match err {
        CompatError::FieldDroppedSameVersion { fields } => {
            assert!(
                fields.iter().any(|f| f == field),
                "expected {field} in {fields:?}"
            );
        }
        other => panic!("expected FieldDroppedSameVersion, got {other}"),
    }
}

fn assert_without_notes(err: CompatError, field: Option<&str>) {
    match err {
        CompatError::FieldDroppedWithoutNotes { fields } => {
            if let Some(field) = field {
                assert!(
                    fields.iter().any(|f| f == field),
                    "expected {field} in {fields:?}"
                );
            }
        }
        other => panic!("expected FieldDroppedWithoutNotes, got {other}"),
    }
}

#[test]
fn t14a_drop_required_field_same_version() {
    let prev = t14_live();
    let curr = t14_drop(prev.clone(), "ClientRunSummary", "updated_at");
    let err = check_response_compat(&prev, &curr, &[]).expect_err("T14");
    assert_same_version(err, "ClientRunSummary.updated_at");
}

#[test]
fn t14b_drop_later_date_no_notes() {
    let prev = t14_live();
    let mut curr = t14_drop(prev.clone(), "ClientRunSummary", "updated_at");
    curr.api_version = "2026-09-01".into();
    let err = check_response_compat(&prev, &curr, &[]).expect_err("T14-b");
    assert_without_notes(err, Some("ClientRunSummary.updated_at"));
}

#[test]
fn t14c_drop_increment_and_notes() {
    let prev = t14_live();
    let mut curr = t14_drop(prev.clone(), "ClientRunSummary", "updated_at");
    curr.api_version = "2026-09-01".into();
    check_response_compat(
        &prev,
        &curr,
        &[t14_covering(&["ClientRunSummary.updated_at"])],
    )
    .expect("covering migration");
}

#[test]
fn t14_cover_misses_removed() {
    let prev = t14_live();
    let mut curr = t14_drop(prev.clone(), "ClientRunSummary", "updated_at");
    curr.api_version = "2026-09-01".into();
    let notes = CompatMigration {
        from: API_VERSION.to_string(),
        to: "2026-09-01".into(),
        removed: vec!["ClientRunSummary.other".into()],
        notes: "notes exist but removed does not cover the drop".into(),
    };
    let err = check_response_compat(&prev, &curr, &[notes]).expect_err("T14-cover-miss");
    assert_without_notes(err, Some("ClientRunSummary.updated_at"));
}

#[test]
fn t14d_additive_same_version() {
    let prev = t14_live();
    let mut curr = prev.clone();
    curr.fields.get_mut("ClientRunSummary").unwrap().insert(
        "extra".into(),
        FieldMeta {
            type_token: "string".into(),
            required: false,
        },
    );
    check_response_compat(&prev, &curr, &[]).expect("additive");
}

#[test]
fn t14e_rename_same_version() {
    let prev = t14_live();
    let mut curr = t14_drop(prev.clone(), "ClientRunSummary", "updated_at");
    curr.fields.get_mut("ClientRunSummary").unwrap().insert(
        "updated_on".into(),
        FieldMeta {
            type_token: "string".into(),
            required: true,
        },
    );
    let err = check_response_compat(&prev, &curr, &[]).expect_err("T14-e");
    assert_same_version(err, "ClientRunSummary.updated_at");
}

#[test]
fn t14f_empty_or_whitespace_notes() {
    let prev = t14_live();
    let mut curr = t14_drop(prev.clone(), "ClientRunSummary", "updated_at");
    curr.api_version = "2026-09-01".into();
    for notes in ["", "   "] {
        let m = CompatMigration {
            from: API_VERSION.to_string(),
            to: "2026-09-01".into(),
            removed: vec!["ClientRunSummary.updated_at".into()],
            notes: notes.into(),
        };
        let err = check_response_compat(&prev, &curr, &[m]).expect_err("T14-f");
        assert_without_notes(err, Some("ClientRunSummary.updated_at"));
    }
}

#[test]
fn t14g_error_code_removal() {
    let prev = t14_live();
    assert!(
        prev.fields
            .get("ClientErrorCode")
            .and_then(|c| c.get("forbidden"))
            .is_some(),
        "extractor must emit forbidden (T14-p)"
    );
    let curr = t14_drop(prev.clone(), "ClientErrorCode", "forbidden");
    let err = check_response_compat(&prev, &curr, &[]).expect_err("T14-g");
    assert_same_version(err, "ClientErrorCode.forbidden");
}

#[test]
fn t14h_live_tree_gate() {
    enforce_compat_gate().expect("clean checkout compat gate");
}

#[test]
fn t14j_local_baseline_equals_live() {
    let live = t14_live();
    let disk = std::fs::read_to_string(
        advance_client_api::schema::schema_dir().join("compat-baseline.json"),
    )
    .expect("compat-baseline.json");
    let local: CompatSnapshot = serde_json::from_str(&disk).expect("baseline parses");
    assert_eq!(local.api_version, API_VERSION);
    assert_eq!(local.api_version, live.api_version);
    assert_eq!(local.fields, live.fields);
}

#[test]
fn t14k_partition() {
    let art = generate_schema_artifact();
    let components = art.schema["components"].as_object().expect("components");
    let live: std::collections::BTreeSet<_> = components.keys().cloned().collect();
    let response: std::collections::BTreeSet<_> = RESPONSE_COMPONENTS
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    let excluded: std::collections::BTreeSet<_> = EXCLUDED_COMPONENTS
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    assert!(response.is_disjoint(&excluded));
    assert_eq!(
        response
            .union(&excluded)
            .cloned()
            .collect::<std::collections::BTreeSet<_>>(),
        live
    );
    for name in RESPONSE_COMPONENTS {
        assert!(components.contains_key(*name), "missing RESPONSE {name}");
    }
    response_field_inventory(&art.schema).expect("partition inventory");
}

#[test]
fn t14l_missing_baseline_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let live = t14_live();
    let err = enforce_compat_gate_at(dir.path(), &live, None).expect_err("T14-l");
    assert!(
        matches!(err, CompatError::Io(_)),
        "missing baseline must be Io, got {err}"
    );
}

#[test]
fn t14n_disk_gate_sees_live_drop() {
    let art = generate_schema_artifact();
    let parent = CompatSnapshot {
        api_version: API_VERSION.to_string(),
        fields: response_field_inventory(&art.schema).unwrap(),
    };
    let mut schema = art.schema.clone();
    schema["components"]["ClientRunSummary"]["properties"]
        .as_object_mut()
        .unwrap()
        .remove("updated_at");
    let live2 = CompatSnapshot {
        api_version: API_VERSION.to_string(),
        fields: response_field_inventory(&schema).unwrap(),
    };
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("compat-migrations.json"),
        r#"{"migrations":[]}"#,
    )
    .unwrap();
    std::fs::write(
        dir.path().join("compat-baseline.json"),
        serde_json::to_string(&parent).unwrap(),
    )
    .unwrap();
    enforce_compat_gate_at(dir.path(), &parent, Some(&parent))
        .expect("T14-n equal parent must be Ok");
    std::fs::write(
        dir.path().join("compat-baseline.json"),
        serde_json::to_string(&live2).unwrap(),
    )
    .unwrap();
    let err = enforce_compat_gate_at(dir.path(), &live2, Some(&parent)).expect_err("T14-n");
    assert_same_version(err, "ClientRunSummary.updated_at");
}

#[test]
fn t14o_drop_optional_field() {
    let prev = t14_live();
    let curr = t14_drop(prev.clone(), "ClientRunSummary", "token_limit");
    let err = check_response_compat(&prev, &curr, &[]).expect_err("T14-o");
    assert_same_version(err, "ClientRunSummary.token_limit");
}

#[test]
fn t14p_extractor_fixtures() {
    let snap = t14_live();
    let get = |c: &str, f: &str| {
        snap.fields
            .get(c)
            .and_then(|m| m.get(f))
            .unwrap_or_else(|| panic!("missing {c}.{f}"))
    };
    assert!(get("ClientErrorCode", "forbidden")
        .type_token
        .contains("forbidden"));
    assert!(get("Scope", "read_events")
        .type_token
        .contains("read_events"));
    assert!(get("Scope", "read_llm_deltas")
        .type_token
        .contains("read_llm_deltas"));
    assert_eq!(get("ActionRef", "confirm.title").type_token, "string");
    assert!(get("ActionRef", "confirm.variant:danger")
        .type_token
        .contains("danger"));
    assert_eq!(get("ClientEnvelope", "data").type_token, "any");
    assert!(
        get("ClientEnvelope", "error")
            .type_token
            .starts_with("opt<"),
        "error token {}",
        get("ClientEnvelope", "error").type_token
    );
    let token_limit = &get("ClientRunSummary", "token_limit").type_token;
    assert_eq!(token_limit, "opt<integer+uint64+min0>");
    assert!(token_limit.contains("uint64"));
    assert_eq!(
        get("ComponentNode", "children").type_token,
        "array<ref:ComponentNode>"
    );
    assert!(
        snap.fields["ComponentNode"]
            .keys()
            .all(|k| !k.contains("children[]")),
        "unbounded children flatten"
    );
    let scalar = &snap.fields["ClientScalar"];
    assert!(
        scalar.contains_key("variant:integer+uint64+min0")
            || scalar.contains_key("variant:integer+uint64"),
        "ClientScalar variants: {:?}",
        scalar.keys().collect::<Vec<_>>()
    );
    let leaves: usize = snap.fields.values().map(BTreeMap::len).sum();
    assert!(leaves < 10_000, "inventory not finite: {leaves}");
}

#[test]
fn t14q_version_downgrade() {
    let prev = t14_live();
    let mut curr = t14_drop(prev.clone(), "ClientRunSummary", "updated_at");
    curr.api_version = "2026-01-01".into();
    let notes = CompatMigration {
        from: API_VERSION.to_string(),
        to: "2026-01-01".into(),
        removed: vec!["ClientRunSummary.updated_at".into()],
        notes: "looks covering but version went backwards".into(),
    };
    let err = check_response_compat(&prev, &curr, &[notes]).expect_err("T14-q");
    assert_same_version(err, "ClientRunSummary.updated_at");
}

#[test]
fn t14r_disk_parent_drop_no_env() {
    t14n_disk_gate_sees_live_drop();
}

#[test]
fn t14s_tagged_variant_drop() {
    let prev = t14_live();
    let curr = t14_drop(prev.clone(), "ClientGrantTtl", "variant:once");
    let err = check_response_compat(&prev, &curr, &[]).expect_err("T14-s");
    assert_same_version(err, "ClientGrantTtl.variant:once");
}

#[test]
fn t14t_parent_spec() {
    let main = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let head = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let before = "cccccccccccccccccccccccccccccccccccccccc";
    assert_eq!(
        resolve_parent_spec(head, Some(main), Some(before), true, true).unwrap(),
        Some(main.to_string())
    );
    assert_eq!(
        resolve_parent_spec(main, Some(main), Some(before), true, true).unwrap(),
        Some(before.to_string())
    );
    let push = resolve_parent_spec(main, Some(main), Some(before), true, true).unwrap();
    assert_ne!(push.as_deref(), Some(main));
    assert_ne!(push.as_deref(), Some(head));
    assert_eq!(
        resolve_parent_spec(head, Some(main), Some(before), false, false).unwrap(),
        None
    );
    assert_eq!(
        resolve_parent_spec(
            main,
            Some(main),
            Some("0000000000000000000000000000000000000000"),
            true,
            true
        )
        .unwrap(),
        None
    );
    let self_parent = resolve_parent_spec(main, Some(main), Some(main), true, true)
        .expect_err("push before==HEAD must not skip");
    assert!(
        matches!(self_parent, CompatError::Parent(_)),
        "got {self_parent}"
    );
    assert_eq!(
        resolve_parent_spec(head, None, Some(before), false, true).unwrap(),
        Some(before.to_string())
    );
    assert_eq!(
        resolve_parent_spec(head, None, Some(before), false, false).unwrap(),
        None
    );
}

#[test]
fn t14_merge_first_parent() {
    let head = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let base = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    assert_eq!(
        prefer_merge_first_parent(head, false, Some(base), true).unwrap(),
        None
    );
    assert_eq!(
        prefer_merge_first_parent(head, true, Some(base), true).unwrap(),
        Some(base.to_string())
    );
    assert_eq!(
        prefer_merge_first_parent(head, true, Some(base), false).unwrap(),
        None
    );
    let err = prefer_merge_first_parent(head, true, Some(head), true)
        .expect_err("merge first parent == HEAD");
    assert!(matches!(err, CompatError::Parent(_)), "got {err}");
}

#[test]
fn t14_baseline_rel_frozen() {
    assert_eq!(
        BASELINE_REL,
        "crates/client-api/sdk-artifacts/schema/compat-baseline.json"
    );
    assert!(git_path_is_canonical(BASELINE_REL));
}

#[test]
fn t14_git_path_canonical() {
    assert!(git_path_is_canonical(
        "crates/client-api/sdk-artifacts/schema/compat-baseline.json"
    ));
    assert!(!git_path_is_canonical(
        "crates/client-api/sdk-artifacts/schema/./compat-baseline.json"
    ));
    assert!(!git_path_is_canonical(
        "crates/client-api/sdk-artifacts/../client-api/sdk-artifacts/schema/compat-baseline.json"
    ));
    assert!(!git_path_is_canonical(
        "crates/client-api/sdk-artifacts/schema//compat-baseline.json"
    ));
    assert!(!git_path_is_canonical(
        "/crates/client-api/sdk-artifacts/schema/compat-baseline.json"
    ));
    assert!(!git_path_is_canonical("compat-baseline.json"));
}

#[test]
fn t14_req_required_to_optional() {
    let art = generate_schema_artifact();
    let prev = CompatSnapshot {
        api_version: API_VERSION.to_string(),
        fields: response_field_inventory(&art.schema).unwrap(),
    };
    let mut schema = art.schema.clone();
    let req = schema["components"]["ClientRunSummary"]["required"]
        .as_array_mut()
        .unwrap();
    req.retain(|v| v.as_str() != Some("run_id"));
    let curr = CompatSnapshot {
        api_version: API_VERSION.to_string(),
        fields: response_field_inventory(&schema).unwrap(),
    };
    assert!(prev.fields["ClientRunSummary"]["run_id"].required);
    assert!(!curr.fields["ClientRunSummary"]["run_id"].required);
    let err = check_response_compat(&prev, &curr, &[]).expect_err("T14-req");
    assert_same_version(err, "ClientRunSummary.run_id");
}

#[test]
fn t14_ty_type_change() {
    let art = generate_schema_artifact();
    let prev = CompatSnapshot {
        api_version: API_VERSION.to_string(),
        fields: response_field_inventory(&art.schema).unwrap(),
    };
    let mut schema = art.schema.clone();
    schema["components"]["ClientRunSummary"]["properties"]["run_id"]["type"] =
        Value::String("integer".into());
    let curr = CompatSnapshot {
        api_version: API_VERSION.to_string(),
        fields: response_field_inventory(&schema).unwrap(),
    };
    let err = check_response_compat(&prev, &curr, &[]).expect_err("T14-ty");
    assert_same_version(err, "ClientRunSummary.run_id");
}

#[test]
fn t14_closed_enum_add() {
    let prev = t14_live();
    let mut scope = prev.clone();
    scope.fields.get_mut("Scope").unwrap().insert(
        "not_a_scope".into(),
        FieldMeta {
            type_token: "const<not_a_scope>".into(),
            required: false,
        },
    );
    let err = check_response_compat(&prev, &scope, &[]).expect_err("T14-closed Scope");
    assert_same_version(err, "Scope.not_a_scope");

    let mut confirm = prev.clone();
    confirm.fields.get_mut("ActionRef").unwrap().insert(
        "confirm.variant:warning".into(),
        FieldMeta {
            type_token: "const<warning>".into(),
            required: false,
        },
    );
    let err = check_response_compat(&prev, &confirm, &[]).expect_err("T14-closed confirm");
    assert_same_version(err, "ActionRef.confirm.variant:warning");

    let mut tagged = prev.clone();
    tagged.fields.get_mut("GenUiError").unwrap().insert(
        "variant:new_code".into(),
        FieldMeta {
            type_token: "const<new_code>".into(),
            required: false,
        },
    );
    let err = check_response_compat(&prev, &tagged, &[]).expect_err("T14-closed tagged disc");
    assert_same_version(err, "GenUiError.variant:new_code");
}

#[test]
fn t14_closed_field_additive_on_tagged_union() {
    let prev = t14_live();
    let mut curr = prev.clone();
    curr.fields.get_mut("GenUiError").unwrap().insert(
        "variant:denied.message".into(),
        FieldMeta {
            type_token: "any".into(),
            required: false,
        },
    );
    check_response_compat(&prev, &curr, &[]).expect("additive field on closed component");
}

#[test]
fn t14_opt_tight() {
    let prev = t14_live();
    let mut curr = prev.clone();
    let csrf = curr
        .fields
        .get_mut("SessionInfo")
        .and_then(|m| m.get_mut("csrf_token"))
        .expect("csrf_token");
    assert!(
        csrf.type_token.starts_with("opt<"),
        "csrf_token token {}",
        csrf.type_token
    );
    csrf.type_token = csrf
        .type_token
        .strip_prefix("opt<")
        .and_then(|s| s.strip_suffix('>'))
        .unwrap()
        .to_string();
    check_response_compat(&prev, &curr, &[]).expect("opt<T> → T is not a drop");
}

#[test]
fn t14_opt_loosen() {
    let prev = t14_live();
    let mut curr = prev.clone();
    let run_id = curr
        .fields
        .get_mut("ClientRunSummary")
        .and_then(|m| m.get_mut("run_id"))
        .expect("run_id");
    assert_eq!(run_id.type_token, "string");
    run_id.type_token = format!("opt<{}>", run_id.type_token);
    let err = check_response_compat(&prev, &curr, &[]).expect_err("T → opt<T> is a drop");
    assert_same_version(err, "ClientRunSummary.run_id");
}

#[test]
fn t14_git_classify() {
    let live = t14_live();
    let json = serde_json::to_string(&live).unwrap();
    let parsed = classify_git_show(&GitShowOutput {
        stdout: json.into_bytes(),
        stderr: String::new(),
        status_code: 0,
    })
    .unwrap();
    assert_eq!(parsed.as_ref(), Some(&live));

    let absent = classify_git_show(&GitShowOutput {
        stdout: Vec::new(),
        stderr: "fatal: path 'crates/client-api/sdk-artifacts/schema/compat-baseline.json' does not exist in 'abc'".into(),
        status_code: 128,
    })
    .unwrap();
    assert_eq!(absent, None);

    let fail = classify_git_show(&GitShowOutput {
        stdout: Vec::new(),
        stderr: "fatal: not a git repository".into(),
        status_code: 128,
    })
    .expect_err("other fail");
    assert!(matches!(fail, CompatError::Parent(_)));

    assert_eq!(normalize_parent_sha(Some("")), None);
    assert_eq!(normalize_parent_sha(Some("   ")), None);
    assert_eq!(
        normalize_parent_sha(Some("0000000000000000000000000000000000000000")),
        None
    );
    assert!(parse_compat_parent_sha(Some("HEAD")).is_err());
    assert!(parse_compat_parent_sha(Some("--pretty=format:%H")).is_err());
    assert_eq!(
        parse_compat_parent_sha(Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")).unwrap(),
        Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    );

    let object_missing = classify_git_show(&GitShowOutput {
        stdout: Vec::new(),
        stderr: "error: object file .git/objects/ab/cd does not exist".into(),
        status_code: 128,
    })
    .expect_err("object-missing is not path-absent");
    assert!(matches!(object_missing, CompatError::Parent(_)));

    let alias_absent = GitShowOutput {
        stdout: Vec::new(),
        stderr: "fatal: path 'crates/client-api/sdk-artifacts/schema/./compat-baseline.json' exists on disk, but not in 'abc'".into(),
        status_code: 128,
    };
    assert_eq!(classify_git_show(&alias_absent).unwrap(), None);
    let skipped = interpret_git_show(&alias_absent, true).expect_err("frozen blob exists");
    assert!(
        matches!(skipped, CompatError::Parent(_)),
        "path-absent + frozen exists must be Err, got {skipped}"
    );
    assert_eq!(interpret_git_show(&alias_absent, false).unwrap(), None);

    assert!(classify_cat_file_exists(0, "").unwrap());
    let exit1 = classify_cat_file_exists(1, "").expect_err("exit 1 is not path-absent");
    assert!(matches!(exit1, CompatError::Parent(_)), "got {exit1}");
    assert!(!classify_cat_file_exists(
        128,
        "fatal: path 'crates/client-api/sdk-artifacts/schema/compat-baseline.json' exists on disk, but not in 'abc'"
    )
    .unwrap());
    let cat_fail = classify_cat_file_exists(128, "fatal: not a git repository").expect_err("other");
    assert!(matches!(cat_fail, CompatError::Parent(_)));
}

#[test]
fn t14_union_per_variant_field_drop() {
    let prev = t14_live();
    let curr = t14_drop(prev.clone(), "GenUiError", "variant:invalid_component.name");
    let err = check_response_compat(&prev, &curr, &[]).expect_err("T14-union");
    assert_same_version(err, "GenUiError.variant:invalid_component.name");
}

#[test]
fn t14_ver_version_only_bump() {
    let prev = t14_live();
    let mut curr = prev.clone();
    curr.api_version = "2026-09-01".into();
    let err = check_response_compat(&prev, &curr, &[]).expect_err("T14-ver");
    assert_without_notes(err, None);
}

#[test]
fn t14_ver_downgrade_no_drop() {
    let prev = t14_live();
    let mut curr = prev.clone();
    curr.api_version = "2026-01-01".into();
    let notes = CompatMigration {
        from: API_VERSION.to_string(),
        to: "2026-01-01".into(),
        removed: vec![],
        notes: "looks covering but version went backwards".into(),
    };
    let err = check_response_compat(&prev, &curr, &[notes]).expect_err("T14-ver-down");
    assert!(
        matches!(err, CompatError::Version(_)),
        "downgrade without drop must be Version, got {err}"
    );
}

#[test]
fn t14_opt_ref_tighten() {
    let art = generate_schema_artifact();
    let prev = CompatSnapshot {
        api_version: API_VERSION.to_string(),
        fields: response_field_inventory(&art.schema).unwrap(),
    };
    assert!(
        prev.fields["ActionRef"]["confirm"]
            .type_token
            .starts_with("opt<"),
        "confirm token {}",
        prev.fields["ActionRef"]["confirm"].type_token
    );
    let mut schema = art.schema.clone();
    schema["components"]["ActionRef"]["properties"]["confirm"] =
        serde_json::json!({ "$ref": "#/$defs/ConfirmMetadata" });
    let curr = CompatSnapshot {
        api_version: API_VERSION.to_string(),
        fields: response_field_inventory(&schema).unwrap(),
    };
    check_response_compat(&prev, &curr, &[]).expect("opt<$ref> → $ref is not a drop");
}

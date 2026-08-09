//! T-CGS-01..T-CGS-21 unit tests for the new Capability-first
//! `validate_capability_subset` entry (MODULE-013-AC-15 / MODULE-005-AC-06 —
//! m013-slice-e, 2026-05-23). Exercises every fail-closed projection path
//! plus the happy-path narrowing semantics inherited from
//! `SubsetValidatorImpl`.

use cap_grant::{validate_capability_subset, CapGrantError};
use serde_json::{json, Number, Value};

use advance_shared_types::agent_tree::Capability;
use advance_shared_types::capability::{CapParams, CapabilityId};

fn cap(id: &str, params: Value) -> Capability {
    Capability {
        id: CapabilityId::from(id),
        params: CapParams::new(params),
    }
}

/// Helper for asserting a `Err(SubsetViolation(_))` result without coupling
/// to the exact diagnostic message string.
fn expect_subset_violation(r: Result<(), CapGrantError>) {
    match r {
        Err(CapGrantError::SubsetViolation(_)) => {}
        Err(other) => panic!("expected SubsetViolation, got {other:?}"),
        Ok(()) => panic!("expected SubsetViolation, got Ok(())"),
    }
}

// =============================================================================
// T-CGS-01 — Identity (parent == child, single fs capability)
// =============================================================================
#[test]
fn t_cgs_01_identity_single_fs() {
    let parent = vec![cap("fs", json!({"read-paths": "/tmp"}))];
    let child = vec![cap("fs", json!({"read-paths": "/tmp"}))];
    validate_capability_subset(&parent, &child).expect("identity must Ok");
}

// =============================================================================
// T-CGS-02 — Path-prefix narrowing (fs `/a/*`-pattern semantics)
// =============================================================================
#[test]
fn t_cgs_02_path_prefix_narrowing() {
    let parent = vec![cap("fs", json!({"read-paths": "/a"}))];
    let child = vec![cap("fs", json!({"read-paths": "/a/b"}))];
    validate_capability_subset(&parent, &child).expect("/a/b ⊆ /a must Ok");
}

// =============================================================================
// T-CGS-03 — Parent has unknown param key (fictional `fs.symlink-paths`)
// =============================================================================
#[test]
fn t_cgs_03_parent_unrecognized_key_fails_closed() {
    let parent = vec![cap("fs", json!({"symlink-paths": "/etc/passwd"}))];
    let child = vec![cap("fs", json!({"read-paths": "/tmp"}))];
    expect_subset_violation(validate_capability_subset(&parent, &child));
}

// =============================================================================
// T-CGS-04 — Top-level params is JSON String (not object)
// =============================================================================
#[test]
fn t_cgs_04_top_level_string_fails_closed() {
    let parent = vec![cap("fs", json!("hello"))];
    let child = vec![cap("fs", json!({"read-paths": "/tmp"}))];
    expect_subset_violation(validate_capability_subset(&parent, &child));
}

// =============================================================================
// T-CGS-05 — Param value is a nested object
// =============================================================================
#[test]
fn t_cgs_05_nested_object_value_fails_closed() {
    let parent = vec![cap("fs", json!({"read-paths": {"nested": "object"}}))];
    let child = vec![cap("fs", json!({"read-paths": "/tmp"}))];
    expect_subset_violation(validate_capability_subset(&parent, &child));
}

// =============================================================================
// T-CGS-06 — Unknown capability id
// =============================================================================
#[test]
fn t_cgs_06_unknown_capability_id_fails_closed() {
    let parent = vec![cap("imaginary-cap", json!({}))];
    let child = vec![cap("imaginary-cap", json!({}))];
    expect_subset_violation(validate_capability_subset(&parent, &child));
}

// =============================================================================
// T-CGS-07 — Child requests capability parent does not grant
// =============================================================================
#[test]
fn t_cgs_07_missing_parent_capability_fails_closed() {
    let parent = vec![cap("fs", json!({"read-paths": "/tmp"}))];
    let child = vec![cap("http", json!({"allowlist": "https://example.com/*"}))];
    expect_subset_violation(validate_capability_subset(&parent, &child));
}

// =============================================================================
// T-CGS-08 — Null value for a known param key
// =============================================================================
#[test]
fn t_cgs_08_null_value_for_known_key_fails_closed() {
    let parent = vec![cap("fs", json!({"read-paths": Value::Null}))];
    let child = vec![cap("fs", json!({"read-paths": "/tmp"}))];
    expect_subset_violation(validate_capability_subset(&parent, &child));
}

// =============================================================================
// T-CGS-09 — Empty parent params (Value::Null) approves any child (whole-cap)
// =============================================================================
#[test]
fn t_cgs_09_null_parent_params_is_whole_capability() {
    let parent = vec![cap("fs", Value::Null)];
    let child = vec![cap("fs", json!({"read-paths": "/anything"}))];
    validate_capability_subset(&parent, &child)
        .expect("parent Null params = whole capability, any child Ok");
}

// =============================================================================
// T-CGS-10 — Array-of-scalars param value (CSV-join semantics)
// =============================================================================
#[test]
fn t_cgs_10_array_of_scalars_happy_path() {
    let parent = vec![cap("secrets", json!({"names": ["key-a", "key-b"]}))];
    let child = vec![cap("secrets", json!({"names": ["key-a"]}))];
    validate_capability_subset(&parent, &child).expect("[key-a] ⊆ [key-a, key-b] must Ok");
}

// =============================================================================
// T-CGS-11 — Array containing non-scalar
// =============================================================================
#[test]
fn t_cgs_11_array_with_nested_object_fails_closed() {
    let parent = vec![cap("secrets", json!({"names": ["key-a", {"k": "v"}]}))];
    let child = vec![cap("secrets", json!({"names": ["key-a"]}))];
    expect_subset_violation(validate_capability_subset(&parent, &child));
}

// =============================================================================
// T-CGS-12 — Multiple capabilities all subset
// =============================================================================
#[test]
fn t_cgs_12_multi_capabilities_all_subset() {
    let parent = vec![
        cap("fs", json!({"read-paths": "/a"})),
        cap("http", json!({"allowlist": "https://example.com/*"})),
    ];
    let child = vec![
        cap("fs", json!({"read-paths": "/a/b"})),
        cap("http", json!({"allowlist": "https://example.com/path/*"})),
    ];
    validate_capability_subset(&parent, &child).expect("multi cap all subset must Ok");
}

// =============================================================================
// T-CGS-13 — Multiple capabilities, one excessive
// =============================================================================
#[test]
fn t_cgs_13_multi_capabilities_one_excessive() {
    let parent = vec![
        cap("fs", json!({"read-paths": "/a"})),
        cap("http", json!({"allowlist": "https://example.com/*"})),
    ];
    let child = vec![
        cap("fs", json!({"read-paths": "/a/b"})),
        cap("http", json!({"allowlist": "https://evil.com/*"})),
    ];
    expect_subset_violation(validate_capability_subset(&parent, &child));
}

// =============================================================================
// T-CGS-14 — Duplicate parent capability id → SubsetViolation (determinism)
// =============================================================================
#[test]
fn t_cgs_14_duplicate_parent_id_fails_closed() {
    let parent = vec![
        cap("fs", json!({"read-paths": "/a"})),
        cap("fs", json!({"read-paths": "/b"})),
    ];
    let child = vec![cap("fs", json!({"read-paths": "/a"}))];
    expect_subset_violation(validate_capability_subset(&parent, &child));
}

// =============================================================================
// T-CGS-15 — Empty-object parent params (Value::Object({})) approves any child
// =============================================================================
#[test]
fn t_cgs_15_empty_object_parent_params_is_whole_capability() {
    let parent = vec![cap("fs", json!({}))];
    let child = vec![cap("fs", json!({"read-paths": "/anything"}))];
    validate_capability_subset(&parent, &child)
        .expect("parent {} params = whole capability, any child Ok");
}

// =============================================================================
// T-CGS-16 — Array element containing `,` (CSV-collision attack)
// =============================================================================
#[test]
fn t_cgs_16_array_element_with_comma_fails_closed() {
    // Concrete attack: parent ["/a,/etc/passwd"] would parse_csv into
    // ["/a", "/etc/passwd"]; a child requesting ["/etc/passwd"] would
    // then pass the path-prefix check against the spurious split element.
    let parent = vec![cap("fs", json!({"read-paths": ["/a,/etc/passwd"]}))];
    let child = vec![cap("fs", json!({"read-paths": ["/etc/passwd"]}))];
    expect_subset_violation(validate_capability_subset(&parent, &child));
}

// =============================================================================
// T-CGS-17 — Array element with leading/trailing whitespace
// =============================================================================
#[test]
fn t_cgs_17_array_element_whitespace_fails_closed() {
    let parent = vec![cap("secrets", json!({"names": ["  key-a  "]}))];
    let child = vec![cap("secrets", json!({"names": ["key-a"]}))];
    expect_subset_violation(validate_capability_subset(&parent, &child));
}

// =============================================================================
// T-CGS-18 — Empty-string array element
// =============================================================================
#[test]
fn t_cgs_18_empty_string_array_element_fails_closed() {
    let parent = vec![cap("secrets", json!({"names": ["key-a", ""]}))];
    let child = vec![cap("secrets", json!({"names": ["key-a"]}))];
    expect_subset_violation(validate_capability_subset(&parent, &child));
}

// =============================================================================
// T-CGS-19 — Non-integer JSON number (3.14) for messaging.max-fanout
// =============================================================================
#[test]
fn t_cgs_19_non_integer_number_fails_closed() {
    let parent = vec![cap(
        "messaging",
        json!({"max-fanout": Number::from_f64(3.14).expect("finite")}),
    )];
    let child = vec![cap("messaging", json!({"max-fanout": 3}))];
    expect_subset_violation(validate_capability_subset(&parent, &child));
}

// =============================================================================
// T-CGS-20 — u64-overflow JSON number (1e30)
// =============================================================================
#[test]
fn t_cgs_20_u64_overflow_number_fails_closed() {
    // serde_json::Number::from_f64 yields a non-u64 number for 1e30.
    // The projection's as_u64() returns None → SubsetViolation.
    let parent = vec![cap(
        "messaging",
        json!({"max-fanout": Number::from_f64(1e30).expect("finite")}),
    )];
    let child = vec![cap("messaging", json!({"max-fanout": 1}))];
    expect_subset_violation(validate_capability_subset(&parent, &child));
}

// =============================================================================
// T-CGS-21 — `channel` capability id → fail-closed
//
// `channel` is intentionally absent from both the projection whitelist AND
// cap-grant's SubsetValidatorImpl::validate dispatch. A future hardening
// slice may add it once cap-channel's grant shape is defined.
// =============================================================================
#[test]
fn t_cgs_21_channel_capability_fails_closed() {
    let parent = vec![cap("channel", json!({}))];
    let child = vec![cap("channel", json!({}))];
    expect_subset_violation(validate_capability_subset(&parent, &child));
}

// =============================================================================
// Round-2 adversarial fix tests — close the Value::String identity-loss
// asymmetry where top-level scalar strings did not enforce the same
// parse_csv-safe checks that array elements already enforced.
// =============================================================================

// T-CGS-22 — Top-level scalar string containing `,` on the CHILD side.
// Without the fix: child {"read-paths": "/a"} against parent {"read-paths": "/a"} passes
// trivially; this test exercises the parent-side risk where CSV-splitting
// silently widens. Parent has a comma-containing literal that splits into
// two paths; child requests the SECOND (split) path — should fail-closed.
#[test]
fn t_cgs_22_top_level_string_comma_parent_widening_fails_closed() {
    let parent = vec![cap("fs", json!({"read-paths": "/safe,/etc/passwd"}))];
    let child = vec![cap("fs", json!({"read-paths": "/safe"}))];
    // Parent value contains `,` — must reject the parent projection rather
    // than approve the child against the (CSV-split) widened parent set.
    expect_subset_violation(validate_capability_subset(&parent, &child));
}

// T-CGS-23 — Top-level scalar string is empty.
// Parent restriction is non-trivial; child supplies `""` which would parse_csv
// to an empty Vec, vacuously satisfying the subset check. Must reject.
#[test]
fn t_cgs_23_top_level_string_empty_child_fails_closed() {
    let parent = vec![cap("fs", json!({"read-paths": "/tmp"}))];
    let child = vec![cap("fs", json!({"read-paths": ""}))];
    expect_subset_violation(validate_capability_subset(&parent, &child));
}

// T-CGS-24 — Top-level scalar string has leading/trailing whitespace.
// Parent value is `"  /tmp  "` — parse_csv would trim to `"/tmp"`, an
// identity loss. Must reject.
#[test]
fn t_cgs_24_top_level_string_whitespace_parent_fails_closed() {
    let parent = vec![cap("fs", json!({"read-paths": "  /tmp  "}))];
    let child = vec![cap("fs", json!({"read-paths": "/tmp"}))];
    expect_subset_violation(validate_capability_subset(&parent, &child));
}

// T-CGS-25 — Top-level scalar string contains ASCII NUL byte.
// Defense-in-depth against downstream C-string consumers.
#[test]
fn t_cgs_25_top_level_string_nul_byte_fails_closed() {
    let parent = vec![cap("secrets", json!({"names": "foo\u{0000}bar"}))];
    let child = vec![cap("secrets", json!({"names": "foo"}))];
    expect_subset_violation(validate_capability_subset(&parent, &child));
}

// T-CGS-26 — Top-level scalar string contains LF (newline).
// Defense-in-depth against log-line forgery.
#[test]
fn t_cgs_26_top_level_string_newline_fails_closed() {
    let parent = vec![cap("secrets", json!({"names": "foo\nbar"}))];
    let child = vec![cap("secrets", json!({"names": "foo"}))];
    expect_subset_violation(validate_capability_subset(&parent, &child));
}

// T-CGS-27 — Array element contains ASCII control byte (NUL).
// Round-2 adversarial fix: array_element_to_string now applies the same
// control-byte rejection as the top-level Value::String arm via the shared
// check_parse_csv_safe helper.
#[test]
fn t_cgs_27_array_element_nul_byte_fails_closed() {
    let parent = vec![cap("secrets", json!({"names": ["foo"]}))];
    let child = vec![cap("secrets", json!({"names": ["foo\u{0000}bar"]}))];
    expect_subset_violation(validate_capability_subset(&parent, &child));
}

// T-CGS-28 — High-bit / Unicode characters MUST still be accepted in
// array elements + top-level strings (defense in depth excludes ASCII control
// only; the existing url-pattern URL gate is the only place where high-bit
// is also rejected, and that lives in subset.rs not the projection).
#[test]
fn t_cgs_28_unicode_in_string_value_allowed() {
    // tools.ids accepts arbitrary identifiers; a tool id with `é` must pass.
    let parent = vec![cap("tools", json!({"ids": ["tool-é"]}))];
    let child = vec![cap("tools", json!({"ids": ["tool-é"]}))];
    validate_capability_subset(&parent, &child)
        .expect("high-bit Unicode identifiers must be accepted");
}

// T-CGS-29 — MAX_CAPABILITIES_PER_CALL gate (parent oversize).
#[test]
fn t_cgs_29_oversize_parent_slice_fails_closed() {
    let parent: Vec<_> = (0..(cap_grant::capability_subset::MAX_CAPABILITIES_PER_CALL + 1))
        .map(|_| cap("fs", json!({"read-paths": "/tmp"})))
        .collect();
    let child = vec![cap("fs", json!({"read-paths": "/tmp"}))];
    expect_subset_violation(validate_capability_subset(&parent, &child));
}

// T-CGS-30 — MAX_CAPABILITIES_PER_CALL gate (child oversize).
#[test]
fn t_cgs_30_oversize_child_slice_fails_closed() {
    let parent = vec![cap("fs", json!({"read-paths": "/tmp"}))];
    let child: Vec<_> = (0..(cap_grant::capability_subset::MAX_CAPABILITIES_PER_CALL + 1))
        .map(|_| cap("fs", json!({"read-paths": "/tmp"})))
        .collect();
    expect_subset_violation(validate_capability_subset(&parent, &child));
}

// =============================================================================
// Round-2 adversarial fix tests — additional fail-closed paths
// =============================================================================

// T-CGS-31 — Pre-existing fail-OPEN in check_lifecycle (adversarial r2 C1):
// child requests `spawn-child: true` against a parent that has no
// `spawn-child` key at all. Previously the (Some, Some) `if let` was the
// only enforced branch; the (None, Some) case silently returned Ok.
// Round-2 fix changes the helper to fail-closed when child requests a
// key the parent does not grant.
#[test]
fn t_cgs_31_lifecycle_child_requests_missing_parent_key_fails_closed() {
    let parent = vec![cap("lifecycle", json!({"spawn-sub": true}))];
    let child = vec![cap("lifecycle", json!({"spawn-child": true}))];
    expect_subset_violation(validate_capability_subset(&parent, &child));
}

// T-CGS-32 — Same vector, opposite key combination.
#[test]
fn t_cgs_32_lifecycle_child_spawn_sub_missing_parent_fails_closed() {
    let parent = vec![cap("lifecycle", json!({"spawn-child": true}))];
    let child = vec![cap("lifecycle", json!({"spawn-sub": true}))];
    expect_subset_violation(validate_capability_subset(&parent, &child));
}

// T-CGS-33 — Even child=false for a missing parent key fails closed.
// The fix opts for strict "narrow strengthens" semantics: a child must
// not introduce keys the parent does not grant, regardless of value.
// (Parent must have at least one lifecycle key — otherwise empty parent
// params triggers the inner validator's `is_empty()` whole-cap fast-path
// at subset.rs:65 before check_lifecycle runs.)
#[test]
fn t_cgs_33_lifecycle_child_false_for_missing_parent_key_fails_closed() {
    let parent = vec![cap("lifecycle", json!({"spawn-sub": true}))];
    let child = vec![cap("lifecycle", json!({"spawn-child": false}))];
    expect_subset_violation(validate_capability_subset(&parent, &child));
}

// T-CGS-34 — Lifecycle happy path: parent has both, child requests narrower.
#[test]
fn t_cgs_34_lifecycle_happy_path_narrowing() {
    let parent = vec![cap(
        "lifecycle",
        json!({"spawn-child": true, "spawn-sub": true}),
    )];
    let child = vec![cap("lifecycle", json!({"spawn-child": true}))];
    validate_capability_subset(&parent, &child).expect("child narrower must Ok");
}

// T-CGS-35 — Per-Capability size cap (adversarial r2 W2): too many keys in
// the Object exceeds MAX_PARAMS_KEYS_PER_CAPABILITY.
#[test]
fn t_cgs_35_oversize_object_keys_fails_closed() {
    // Build a map with MAX_PARAMS_KEYS_PER_CAPABILITY + 1 entries. Note:
    // these are unrecognized keys, so the projection rejects on the FIRST
    // unrecognized key — but the size cap fires BEFORE the per-key check.
    // We use a Number value for each key to keep the value small.
    let mut obj = serde_json::Map::new();
    for i in 0..(cap_grant::capability_subset::MAX_PARAMS_KEYS_PER_CAPABILITY + 1) {
        obj.insert(
            format!("key-{i}"),
            Value::Number(serde_json::Number::from(i)),
        );
    }
    let parent = vec![cap("fs", Value::Object(obj.clone()))];
    let child = vec![cap("fs", Value::Object(obj))];
    expect_subset_violation(validate_capability_subset(&parent, &child));
}

// T-CGS-36 — Per-value Array length cap: too many elements exceeds
// MAX_PARAMS_ARRAY_LEN.
#[test]
fn t_cgs_36_oversize_array_value_fails_closed() {
    let arr: Vec<Value> = (0..(cap_grant::capability_subset::MAX_PARAMS_ARRAY_LEN + 1))
        .map(|i| Value::String(format!("tool-{i}")))
        .collect();
    let parent = vec![cap("tools", json!({"ids": arr.clone()}))];
    let child = vec![cap("tools", json!({"ids": ["tool-0"]}))];
    expect_subset_violation(validate_capability_subset(&parent, &child));
}

// T-CGS-37 — Per-value string length cap: top-level string exceeds
// MAX_PARAMS_STRING_BYTES.
#[test]
fn t_cgs_37_oversize_string_value_fails_closed() {
    let big = "x".repeat(cap_grant::capability_subset::MAX_PARAMS_STRING_BYTES + 1);
    let parent = vec![cap("secrets", json!({"names": big.clone()}))];
    let child = vec![cap("secrets", json!({"names": "x"}))];
    expect_subset_violation(validate_capability_subset(&parent, &child));
}

// T-CGS-38 — Per-value string length cap: array element exceeds
// MAX_PARAMS_STRING_BYTES.
#[test]
fn t_cgs_38_oversize_array_element_string_fails_closed() {
    let big = "x".repeat(cap_grant::capability_subset::MAX_PARAMS_STRING_BYTES + 1);
    let parent = vec![cap("secrets", json!({"names": [big.clone()]}))];
    let child = vec![cap("secrets", json!({"names": ["x"]}))];
    expect_subset_violation(validate_capability_subset(&parent, &child));
}

// =============================================================================
// Round-3 adversarial fix tests — Unicode confusable rejection (W1).
// The fix targets visually invisible / identifier-spoofing codepoints
// (zero-width, BiDi controls, variation selectors, tag chars, BOM,
// soft hyphen, invisible math ops). High-bit Latin / CJK / Cyrillic
// chars remain permitted (T-CGS-28 unaffected).
// =============================================================================

// T-CGS-39 — Zero-width space (U+200B) in a top-level string.
#[test]
fn t_cgs_39_zwsp_in_string_fails_closed() {
    let parent = vec![cap("secrets", json!({"names": "tool-evil\u{200B}"}))];
    let child = vec![cap("secrets", json!({"names": "tool-evil"}))];
    expect_subset_violation(validate_capability_subset(&parent, &child));
}

// T-CGS-40 — Zero-width space (U+200B) in an array element.
#[test]
fn t_cgs_40_zwsp_in_array_element_fails_closed() {
    let parent = vec![cap("tools", json!({"ids": ["tool-evil\u{200B}"]}))];
    let child = vec![cap("tools", json!({"ids": ["tool-evil"]}))];
    expect_subset_violation(validate_capability_subset(&parent, &child));
}

// T-CGS-41 — Right-to-Left Override (U+202E) in a string.
#[test]
fn t_cgs_41_bidi_override_in_string_fails_closed() {
    // U+202E flips visual direction; "/safe/\u{202E}drowssap" displays
    // as "/safe/password" (or similar reversed string), making operator
    // review unreliable.
    let parent = vec![cap("fs", json!({"read-paths": "/safe/\u{202E}drowssap"}))];
    let child = vec![cap("fs", json!({"read-paths": "/safe"}))];
    expect_subset_violation(validate_capability_subset(&parent, &child));
}

// T-CGS-42 — Soft hyphen (U+00AD) in a string.
#[test]
fn t_cgs_42_soft_hyphen_fails_closed() {
    let parent = vec![cap("secrets", json!({"names": "key\u{00AD}-a"}))];
    let child = vec![cap("secrets", json!({"names": "key-a"}))];
    expect_subset_violation(validate_capability_subset(&parent, &child));
}

// T-CGS-43 — Byte-order mark (U+FEFF).
#[test]
fn t_cgs_43_bom_fails_closed() {
    let parent = vec![cap("tools", json!({"ids": "\u{FEFF}tool"}))];
    let child = vec![cap("tools", json!({"ids": "tool"}))];
    expect_subset_violation(validate_capability_subset(&parent, &child));
}

// T-CGS-44 — Variation selector (U+FE0F).
#[test]
fn t_cgs_44_variation_selector_fails_closed() {
    let parent = vec![cap("notify", json!({"targets": "name\u{FE0F}"}))];
    let child = vec![cap("notify", json!({"targets": "name"}))];
    expect_subset_violation(validate_capability_subset(&parent, &child));
}

// T-CGS-45 — Word Joiner (U+2060).
#[test]
fn t_cgs_45_word_joiner_fails_closed() {
    let parent = vec![cap("notify", json!({"targets": "x\u{2060}y"}))];
    let child = vec![cap("notify", json!({"targets": "xy"}))];
    expect_subset_violation(validate_capability_subset(&parent, &child));
}

// T-CGS-46 — Legitimate high-bit Latin (regression test for T-CGS-28
// posture: the Unicode confusable filter must NOT reject `é`, Cyrillic,
// CJK, etc. Only the curated invisible / BiDi set is rejected.).
#[test]
fn t_cgs_46_legitimate_high_bit_latin_still_allowed() {
    let parent = vec![cap("tools", json!({"ids": ["café", "naïve"]}))];
    let child = vec![cap("tools", json!({"ids": ["café"]}))];
    validate_capability_subset(&parent, &child)
        .expect("legitimate Latin/Unicode identifiers must still be accepted");
}

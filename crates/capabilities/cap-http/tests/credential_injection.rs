//! T05a-f — credential-injection unit tests (AC-05).

use advance_shared_types::security_validator::{
    CredentialBinding, CredentialPosition, CredentialPositionTag, HttpError, HttpMethod,
    HttpRequest, SecretResolutionReason,
};
use base64::Engine;
use cap_http::{inject_credentials, substitute_placeholders};
use cap_secrets::{InMemorySecretStorage, SecretStorage, SecretStore};
use std::collections::HashSet;
use std::sync::Arc;
use zeroize::Zeroizing;

fn allowed(names: &[&str]) -> HashSet<String> {
    names.iter().map(|s| s.to_string()).collect()
}

fn test_store(secrets: &[(&str, &str)]) -> Arc<SecretStore> {
    let storage: Arc<dyn SecretStorage> = Arc::new(InMemorySecretStorage::new());
    let master = Zeroizing::new([0xab; 32]);
    let s = SecretStore::new(master, storage);
    for (name, value) in secrets {
        s.store(name, value).unwrap();
    }
    Arc::new(s)
}

fn req() -> HttpRequest {
    HttpRequest {
        method: HttpMethod::Get,
        url: "https://api.example.com/v1/x".to_string(),
        headers: vec![],
        body: vec![],
    }
}

fn header_value<'a>(req: &'a HttpRequest, name: &str) -> Option<&'a str> {
    let lc = name.to_ascii_lowercase();
    req.headers
        .iter()
        .find(|(n, _)| n.to_ascii_lowercase() == lc)
        .map(|(_, v)| v.as_str())
}

#[test]
fn t05a_bearer_token_position() {
    let store = test_store(&[("api_key", "xoxb-1234")]);
    let mut r = req();
    // Pre-existing Authorization should be overridden.
    r.headers
        .push(("Authorization".to_string(), "Bearer old-token".to_string()));
    let bindings = vec![CredentialBinding {
        position: CredentialPosition::BearerToken,
        secret_name: "api_key".to_string(),
    }];
    inject_credentials(&mut r, &bindings, &store).unwrap();
    assert_eq!(header_value(&r, "Authorization"), Some("Bearer xoxb-1234"));
}

#[test]
fn t05b_basic_auth_position_rfc7617_standard_base64() {
    let store = test_store(&[("api_key", "p@ss")]);
    let mut r = req();
    let bindings = vec![CredentialBinding {
        position: CredentialPosition::BasicAuth {
            username: "user".to_string(),
        },
        secret_name: "api_key".to_string(),
    }];
    inject_credentials(&mut r, &bindings, &store).unwrap();
    let auth = header_value(&r, "Authorization").unwrap();
    assert!(auth.starts_with("Basic "), "auth={}", auth);
    let encoded = &auth["Basic ".len()..];
    // RFC 7617 / RFC 4648 §4 — STANDARD alphabet (A-Za-z0-9+/), with `=` padding.
    // NOT URL-safe (which would use `-_`).
    assert!(
        !encoded.contains('-') && !encoded.contains('_'),
        "URL-safe alphabet leaked in: {}",
        encoded
    );
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .unwrap();
    let decoded_str = String::from_utf8(decoded).unwrap();
    assert_eq!(decoded_str, "user:p@ss", "round-trip mismatch");
}

#[test]
fn t05c_custom_header_position() {
    let store = test_store(&[("api_key", "v123")]);
    let mut r = req();
    // Pre-existing same-name header should be overridden.
    r.headers
        .push(("X-Custom-Header".to_string(), "old".to_string()));
    let bindings = vec![CredentialBinding {
        position: CredentialPosition::CustomHeader {
            key: "X-Custom-Header".to_string(),
        },
        secret_name: "api_key".to_string(),
    }];
    inject_credentials(&mut r, &bindings, &store).unwrap();
    assert_eq!(header_value(&r, "X-Custom-Header"), Some("v123"));
}

#[test]
fn t05d_query_param_position() {
    let store = test_store(&[("api_key", "a&b=c+d")]);
    let mut r = req();
    r.url = "https://api.example.com/v1/x?existing=1".to_string();
    let bindings = vec![CredentialBinding {
        position: CredentialPosition::QueryParam {
            key: "token".to_string(),
        },
        secret_name: "api_key".to_string(),
    }];
    inject_credentials(&mut r, &bindings, &store).unwrap();
    // Pre-existing query preserved.
    assert!(r.url.contains("existing=1"), "url={}", r.url);
    assert!(r.url.contains("token="), "url={}", r.url);
    // & / = / + must be percent-encoded.
    assert!(!r.url.contains("a&b"), "raw `&` leaked: {}", r.url);
    // Verify roundtrip.
    let parsed = url::Url::parse(&r.url).unwrap();
    let token_value = parsed
        .query_pairs()
        .find(|(k, _)| k == "token")
        .map(|(_, v)| v.into_owned())
        .unwrap();
    assert_eq!(token_value, "a&b=c+d");
}

#[test]
fn t05e_url_path_placeholder_substitution_and_missing() {
    let store = test_store(&[("path_secret", "abc123")]);
    let mut r = req();
    r.url = "https://api.example.com/v1/users/{user_id}/items".to_string();
    let bindings = vec![CredentialBinding {
        position: CredentialPosition::UrlPath {
            key: "user_id".to_string(),
        },
        secret_name: "path_secret".to_string(),
    }];
    inject_credentials(&mut r, &bindings, &store).unwrap();
    assert_eq!(r.url, "https://api.example.com/v1/users/abc123/items");

    // Missing placeholder in URL → PlaceholderNotInUrl
    let mut r2 = req();
    r2.url = "https://api.example.com/no-placeholder".to_string();
    let bindings2 = vec![CredentialBinding {
        position: CredentialPosition::UrlPath {
            key: "missing_key".to_string(),
        },
        secret_name: "path_secret".to_string(),
    }];
    let err = inject_credentials(&mut r2, &bindings2, &store).unwrap_err();
    assert!(
        matches!(
            err,
            HttpError::SecretResolution(SecretResolutionReason::PlaceholderNotInUrl)
        ),
        "expected PlaceholderNotInUrl, got {:?}",
        err
    );
}

#[test]
fn adv_r3_url_path_replace_scoped_to_path_only() {
    // Adversarial R3 fix regression lock: CredentialPosition::UrlPath replace
    // is now scoped to the path portion only (split on `?` and `#`). A
    // {key} appearing in BOTH path AND query/fragment should only have the
    // PATH occurrence substituted; the query/fragment occurrence remains
    // literal — preventing path-only secrets from leaking into more
    // loggable surfaces.
    let store = test_store(&[("doc_id", "secret-doc-id")]);
    let mut r = req();
    r.url = "https://api.example.com/docs/{doc_id}/view?copy={doc_id}".to_string();
    let bindings = vec![CredentialBinding {
        position: CredentialPosition::UrlPath {
            key: "doc_id".to_string(),
        },
        secret_name: "doc_id".to_string(),
    }];
    inject_credentials(&mut r, &bindings, &store).unwrap();
    // Path occurrence substituted.
    assert!(
        r.url.contains("/docs/secret-doc-id/view"),
        "path placeholder should be substituted: {}",
        r.url
    );
    // Query occurrence remains LITERAL — secret NOT copied to query.
    assert!(
        r.url.contains("?copy={doc_id}"),
        "query placeholder must NOT be substituted by UrlPath binding: {}",
        r.url
    );
    assert!(
        !r.url.contains("?copy=secret-doc-id"),
        "secret leaked from path to query: {}",
        r.url
    );
}

#[test]
fn substitute_placeholders_query_placeholder_tagged_as_query_param() {
    // R4-W3 regression lock: a placeholder in the URL QUERY portion (after `?`)
    // produces a MissingSecretFor(QueryParam) tag on missing-secret, NOT UrlPath.
    let store = test_store(&[]); // empty store
    let mut r = req();
    r.url = "https://api.example.com/path/x?token={my_token}".to_string();
    let err =
        substitute_placeholders(&mut r, &store, &allowed(&["my_token", "token"])).unwrap_err();
    match err {
        HttpError::SecretResolution(SecretResolutionReason::MissingSecretFor(tag)) => {
            assert_eq!(
                tag,
                CredentialPositionTag::QueryParam,
                "expected QueryParam tag for query-portion placeholder"
            );
        }
        other => panic!("expected MissingSecretFor(QueryParam), got {:?}", other),
    }

    // Path-portion placeholder still gets UrlPath tag.
    let mut r2 = req();
    r2.url = "https://api.example.com/users/{user_id}/items".to_string();
    let err2 =
        substitute_placeholders(&mut r2, &store, &allowed(&["my_token", "user_id"])).unwrap_err();
    match err2 {
        HttpError::SecretResolution(SecretResolutionReason::MissingSecretFor(tag)) => {
            assert_eq!(
                tag,
                CredentialPositionTag::UrlPath,
                "expected UrlPath tag for path-portion placeholder"
            );
        }
        other => panic!("expected MissingSecretFor(UrlPath), got {:?}", other),
    }
}

#[test]
fn adv_capability_scoped_placeholder_rejects_out_of_scope_secret() {
    // Adversarial R1 fix regression lock: a placeholder referencing a secret
    // OUTSIDE the capability's allowed_secret_names set is REJECTED, even if
    // the secret exists in the store. Closes the secret-exfiltration bypass.
    let store = test_store(&[
        ("granted_secret", "g-1234"),
        ("admin_master_key", "ADMIN_SECRET_DO_NOT_LEAK"),
    ]);
    let mut r = req();
    r.url = "https://api.example.com/x?leak={admin_master_key}".to_string();
    let cap_allowed = allowed(&["granted_secret"]);
    let err = substitute_placeholders(&mut r, &store, &cap_allowed).unwrap_err();
    match err {
        HttpError::SecretResolution(SecretResolutionReason::MissingSecretFor(_)) => {}
        other => panic!(
            "expected MissingSecretFor for out-of-scope placeholder, got {:?}",
            other
        ),
    }
    assert!(
        !r.url.contains("ADMIN_SECRET_DO_NOT_LEAK"),
        "admin secret leaked: {}",
        r.url
    );
}

#[test]
fn adv_inject_credentials_rejects_secret_with_crlf() {
    let store = test_store(&[("malformed", "val\r\nX-Forwarded-User: admin")]);
    let mut r = req();
    let bindings = vec![CredentialBinding {
        position: CredentialPosition::BearerToken,
        secret_name: "malformed".to_string(),
    }];
    let err = inject_credentials(&mut r, &bindings, &store).unwrap_err();
    match err {
        HttpError::SecretResolution(SecretResolutionReason::MissingSecretFor(_)) => {}
        other => panic!("expected MissingSecretFor for CRLF secret, got {:?}", other),
    }
    assert!(header_value(&r, "Authorization").is_none());
}

#[test]
fn adv_basic_auth_rejects_username_with_colon() {
    let store = test_store(&[("api_key", "p@ss")]);
    let mut r = req();
    let bindings = vec![CredentialBinding {
        position: CredentialPosition::BasicAuth {
            username: "user:malicious".to_string(),
        },
        secret_name: "api_key".to_string(),
    }];
    let err = inject_credentials(&mut r, &bindings, &store).unwrap_err();
    match err {
        HttpError::SecretResolution(SecretResolutionReason::MissingSecretFor(_)) => {}
        other => panic!(
            "expected MissingSecretFor for `:` in username, got {:?}",
            other
        ),
    }
}

#[test]
fn adv_custom_header_rejects_key_with_crlf() {
    let store = test_store(&[("api_key", "v123")]);
    let mut r = req();
    let bindings = vec![CredentialBinding {
        position: CredentialPosition::CustomHeader {
            key: "X-Foo\r\nX-Auth: BAD".to_string(),
        },
        secret_name: "api_key".to_string(),
    }];
    let err = inject_credentials(&mut r, &bindings, &store).unwrap_err();
    match err {
        HttpError::SecretResolution(SecretResolutionReason::MissingSecretFor(_)) => {}
        other => panic!("expected MissingSecretFor for CRLF in key, got {:?}", other),
    }
}

#[test]
fn adv_r2_substitute_placeholders_rejects_secret_with_crlf() {
    // Adversarial R2 fix regression lock: secret value containing CRLF
    // (header smuggling) must be rejected at step 3, just like step 4.
    let store = test_store(&[("malformed", "val\r\nX-Forwarded-User: admin")]);
    let mut r = req();
    r.headers
        .push(("X-Audit".to_string(), "trace={malformed}".to_string()));
    let cap_allowed = allowed(&["malformed"]);
    let err = substitute_placeholders(&mut r, &store, &cap_allowed).unwrap_err();
    match err {
        HttpError::SecretResolution(SecretResolutionReason::MissingSecretFor(_)) => {}
        other => panic!(
            "expected MissingSecretFor for CRLF secret in step 3, got {:?}",
            other
        ),
    }
    // Header value MUST NOT be modified (no smuggling).
    assert_eq!(
        header_value(&r, "X-Audit").unwrap(),
        "trace={malformed}",
        "header should not be substituted on CRLF reject"
    );
}

#[test]
fn substitute_placeholders_preserves_non_ascii_utf8() {
    // R2-C1 regression lock: non-ASCII content alongside a placeholder MUST
    // be preserved byte-for-byte (UTF-8-safe), NOT mojibake'd.
    let store = test_store(&[("token", "secret-value")]);
    let mut r = req();
    r.url = "https://api.example.com/héllo/{token}/世界".to_string();
    r.headers
        .push(("X-Tracker".to_string(), "id={token}&name=日本".to_string()));
    r.body = "prefix {token} 你好 emoji 🔥".as_bytes().to_vec();
    substitute_placeholders(&mut r, &store, &allowed(&["my_token", "token"])).unwrap();
    assert_eq!(r.url, "https://api.example.com/héllo/secret-value/世界");
    assert_eq!(
        header_value(&r, "X-Tracker"),
        Some("id=secret-value&name=日本")
    );
    assert_eq!(
        std::str::from_utf8(&r.body).unwrap(),
        "prefix secret-value 你好 emoji 🔥"
    );
}

#[test]
fn t05f_secret_not_found_per_position() {
    let store = test_store(&[]); // empty store
    let positions: &[(CredentialPosition, CredentialPositionTag)] = &[
        (
            CredentialPosition::BearerToken,
            CredentialPositionTag::BearerToken,
        ),
        (
            CredentialPosition::BasicAuth {
                username: "u".to_string(),
            },
            CredentialPositionTag::BasicAuth,
        ),
        (
            CredentialPosition::CustomHeader {
                key: "X-K".to_string(),
            },
            CredentialPositionTag::CustomHeader,
        ),
        (
            CredentialPosition::QueryParam {
                key: "q".to_string(),
            },
            CredentialPositionTag::QueryParam,
        ),
    ];
    for (pos, expected_tag) in positions {
        let mut r = req();
        let bindings = vec![CredentialBinding {
            position: pos.clone(),
            secret_name: "nonexistent".to_string(),
        }];
        let err = inject_credentials(&mut r, &bindings, &store).unwrap_err();
        match err {
            HttpError::SecretResolution(SecretResolutionReason::MissingSecretFor(tag)) => {
                assert_eq!(&tag, expected_tag, "position-tag mismatch for {:?}", pos);
            }
            other => panic!("expected MissingSecretFor, got {:?}", other),
        }
    }

    // UrlPath: when placeholder IS in URL, but secret missing → MissingSecretFor(UrlPath).
    let mut r = req();
    r.url = "https://api.example.com/{x}/y".to_string();
    let bindings = vec![CredentialBinding {
        position: CredentialPosition::UrlPath {
            key: "x".to_string(),
        },
        secret_name: "nonexistent".to_string(),
    }];
    let err = inject_credentials(&mut r, &bindings, &store).unwrap_err();
    match err {
        HttpError::SecretResolution(SecretResolutionReason::MissingSecretFor(tag)) => {
            assert_eq!(tag, CredentialPositionTag::UrlPath);
        }
        other => panic!("expected MissingSecretFor(UrlPath), got {:?}", other),
    }
}

#[test]
fn substitute_placeholders_replaces_and_passes_through() {
    let store = test_store(&[("token", "secret-value")]);
    let mut r = req();
    r.url = "https://api.example.com/v1/{token}/x".to_string();
    r.headers
        .push(("X-Tracker".to_string(), "id={token}".to_string()));
    r.body = b"prefix {token} suffix".to_vec();
    substitute_placeholders(&mut r, &store, &allowed(&["my_token", "token"])).unwrap();
    assert_eq!(r.url, "https://api.example.com/v1/secret-value/x");
    assert_eq!(header_value(&r, "X-Tracker"), Some("id=secret-value"));
    assert_eq!(r.body, b"prefix secret-value suffix");
}

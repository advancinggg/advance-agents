//! MODULE-020-T11 / MODULE-020-AC-11 storage audit.
//!
//! Witnesses OSS Web Console + in-repo client-accessible storage: a planted
//! plaintext runtime secret or provider key fails this auditor; production
//! console JS/HTML and `crates/client-api/src` must not write those stores.
//!
//! Does **not** witness T19 live browser DOM.
//! Does **not** witness Along Keychain / UserDefaults.
//! Does **not** restamp MODULE-020-AC-14.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

const HEX64: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const HEX32: &str = "0123456789abcdef0123456789abcdef";

const LEAF_KEYS: &[&str] = &[
    "token",
    "secret",
    "password",
    "authorization",
    "bearer",
    "csrf",
    "csrf_token",
    "bootstrap",
    "bootstrap_code",
    "api_key",
    "apikey",
    "api-key",
    "provider_key",
    "provider-key",
    "session_token",
    "private_key",
    "private-key",
];

const PROVIDER_PREFIXES: &[&str] = &["sk-", "xai-", "aiza", "ghp_", "ghs_", "github_pat_", "akia"];

const PERSIST_IDENTIFIERS: &[&str] = &[
    "localStorage",
    "sessionStorage",
    "indexedDB",
    "cookieStore",
    "caches.open",
    "caches",
    "document.cookie",
    "document['cookie']",
    "document[\"cookie\"]",
    "document[`cookie`]",
    "history.pushState",
    "history.replaceState",
    "location.hash",
    "location.search",
    "location.href",
    "location.assign",
    "location.replace",
    "location.pathname",
    "window.open",
    "window.location",
    "document.location",
    "window.name",
    "self.name",
    "top.name",
    "self.location",
    "top.location",
    "parent.location",
    "globalThis.location",
    "navigator.storage",
    "openDatabase",
    "showDirectoryPicker",
    "showSaveFilePicker",
    "showOpenFilePicker",
    "createWritable",
    "navigator.credentials",
    "PasswordCredential",
    "navigator.serviceWorker",
];

const TOKEN_PHRASES: &[&str] = &[
    "if (state.token)",
    "Bearer ${state.token}",
    "state.token = data.token",
    "advance.bearer.${state.token}",
    "headers[\"x-csrf-token\"] = state.csrf",
    "state.csrf = data.csrf_token || \"\"",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SecretClass {
    RuntimeSecret,
    ProviderKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StorageFinding {
    store: &'static str,
    key: String,
    class: SecretClass,
}

#[derive(Default)]
struct ClientStorageSnapshot {
    local_storage: BTreeMap<String, String>,
    session_storage: BTreeMap<String, String>,
    cookies: BTreeMap<String, String>,
    indexed_db: BTreeMap<String, String>,
}

fn last_segment(path: &str) -> &str {
    path.rsplit(['.', '['])
        .next()
        .unwrap_or(path)
        .trim_end_matches(']')
}

fn contains_hex64(s: &str) -> bool {
    let mut run = 0usize;
    for c in s.chars() {
        if c.is_ascii_hexdigit() {
            run += 1;
            if run >= 64 {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

fn is_hex32(s: &str) -> bool {
    let t = s.trim();
    t.len() == 32 && t.bytes().all(|c| c.is_ascii_hexdigit())
}

fn contains_assigned_hex32(s: &str) -> bool {
    s.split(['&', '?', '\n', ';'])
        .filter_map(|part| part.split_once('='))
        .any(|(_, v)| is_hex32(v))
}

fn left_bounded_provider_prefix(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    for prefix in PROVIDER_PREFIXES {
        let mut start = 0usize;
        while let Some(rel) = lower[start..].find(prefix) {
            let abs = start + rel;
            let ok = abs == 0 || !lower.as_bytes()[abs - 1].is_ascii_alphanumeric();
            if ok {
                return true;
            }
            start = abs + 1;
        }
    }
    false
}

fn is_pem(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    lower.contains("-----begin") && lower.contains("private key-----")
}

fn is_bearer_prefix(s: &str) -> bool {
    let t = s.trim();
    if t.len() < 8 || !t.get(..6).is_some_and(|h| h.eq_ignore_ascii_case("bearer")) {
        return false;
    }
    let mut chars = t[6..].chars();
    matches!(chars.next(), Some(c) if c.is_whitespace()) && chars.any(|c| !c.is_whitespace())
}

fn is_advance_bearer(s: &str) -> bool {
    let t = s.trim();
    let lower = t.to_ascii_lowercase();
    let Some(rest) = lower.strip_prefix("advance.bearer.") else {
        return false;
    };
    rest.len() == 64 && rest.bytes().all(|c| c.is_ascii_hexdigit())
}

fn classify_string(s: &str, leaf: &str) -> Option<SecretClass> {
    if left_bounded_provider_prefix(s) || is_pem(s) {
        return Some(SecretClass::ProviderKey);
    }
    if LEAF_KEYS.iter().any(|k| leaf.eq_ignore_ascii_case(k))
        || contains_hex64(s)
        || is_hex32(s)
        || contains_assigned_hex32(s)
        || is_bearer_prefix(s)
        || is_advance_bearer(s)
        || s.to_ascii_lowercase().contains("t11-plaintext")
    {
        return Some(SecretClass::RuntimeSecret);
    }
    None
}

fn push_finding(
    findings: &mut Vec<StorageFinding>,
    store: &'static str,
    key: &str,
    class: SecretClass,
) {
    findings.push(StorageFinding {
        store,
        key: key.to_string(),
        class,
    });
}

fn classify_pair(
    findings: &mut Vec<StorageFinding>,
    store: &'static str,
    path: &str,
    leaf: &str,
    s: &str,
) {
    if let Some(class) = classify_string(s, leaf) {
        push_finding(findings, store, path, class);
    }
}

fn inspect_value(
    findings: &mut Vec<StorageFinding>,
    store: &'static str,
    path: &str,
    leaf: &str,
    s: &str,
    unwrap_left: u8,
) {
    if unwrap_left > 0 {
        if let Ok(v) = serde_json::from_str::<Value>(s) {
            match v {
                Value::String(inner) => {
                    inspect_value(findings, store, path, leaf, &inner, unwrap_left - 1);
                    return;
                }
                Value::Object(map) => {
                    for (k, child) in map {
                        let child_path = format!("{path}.{k}");
                        classify_pair(findings, store, &child_path, &k, &k);
                        match child {
                            Value::String(inner) => {
                                inspect_value(
                                    findings,
                                    store,
                                    &child_path,
                                    &k,
                                    &inner,
                                    unwrap_left,
                                );
                            }
                            other => {
                                inspect_value(
                                    findings,
                                    store,
                                    &child_path,
                                    &k,
                                    &other.to_string(),
                                    unwrap_left,
                                );
                            }
                        }
                    }
                    return;
                }
                Value::Array(arr) => {
                    for (i, child) in arr.iter().enumerate() {
                        let child_path = format!("{path}[{i}]");
                        let child_leaf = last_segment(&child_path);
                        match child {
                            Value::String(inner) => {
                                inspect_value(
                                    findings,
                                    store,
                                    &child_path,
                                    child_leaf,
                                    inner,
                                    unwrap_left,
                                );
                            }
                            other => {
                                inspect_value(
                                    findings,
                                    store,
                                    &child_path,
                                    child_leaf,
                                    &other.to_string(),
                                    unwrap_left,
                                );
                            }
                        }
                    }
                    return;
                }
                _ => {}
            }
        }
    }
    classify_pair(findings, store, path, leaf, s);
}

fn audit_map(
    findings: &mut Vec<StorageFinding>,
    store: &'static str,
    map: &BTreeMap<String, String>,
) {
    for (key, value) in map {
        let leaf = last_segment(key);
        classify_pair(findings, store, key, leaf, key);
        let trimmed = value.trim();
        if trimmed.is_empty() {
            continue;
        }
        inspect_value(findings, store, key, leaf, trimmed, 2);
    }
}

fn audit_client_storage(snap: &ClientStorageSnapshot) -> Result<(), Vec<StorageFinding>> {
    let mut findings = Vec::new();
    audit_map(&mut findings, "localStorage", &snap.local_storage);
    audit_map(&mut findings, "sessionStorage", &snap.session_storage);
    audit_map(&mut findings, "cookie", &snap.cookies);
    audit_map(&mut findings, "indexedDB", &snap.indexed_db);
    if findings.is_empty() {
        Ok(())
    } else {
        Err(findings)
    }
}

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn console_dir() -> PathBuf {
    crate_root().join("../../clients/web-console")
}

fn collect_js_html(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = fs::read_dir(dir).unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display()));
    for entry in entries {
        let path = entry.expect("dirent").path();
        if path.is_dir() {
            collect_js_html(&path, out);
            continue;
        }
        match path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_ascii_lowercase())
            .as_deref()
        {
            Some("js" | "mjs" | "html") => out.push(path),
            _ => {}
        }
    }
}

fn src_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = fs::read_dir(dir).unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display()));
    for entry in entries {
        let path = entry.expect("dirent").path();
        if path.is_dir() {
            src_rs_files(&path, out);
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

fn include_str_literals(src: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = src;
    while let Some(i) = rest.find("include_str!") {
        let after = rest[i + "include_str!".len()..].trim_start();
        if let Some(after) = after.strip_prefix('(') {
            let after = after.trim_start();
            if let Some(after) = after.strip_prefix('"') {
                if let Some(end) = after.find('"') {
                    out.push(after[..end].to_string());
                }
            }
        }
        rest = &rest[i + 1..];
    }
    out
}

fn has_cookie_mint(s: &str) -> bool {
    if s.contains("CookieJar") {
        return true;
    }
    let lower = s.to_ascii_lowercase();
    lower.contains("set-cookie") || lower.contains("set_cookie") || lower.contains("setcookie")
}

fn persist_hits(text: &str) -> Vec<&'static str> {
    PERSIST_IDENTIFIERS
        .iter()
        .copied()
        .filter(|id| text.contains(id))
        .collect()
}

fn assert_err(
    snap: &ClientStorageSnapshot,
    store: &str,
    class: SecretClass,
    key_substr: Option<&str>,
) {
    let err = audit_client_storage(snap).expect_err("planted secret must fail T11");
    assert!(
        err.iter().any(|f| {
            f.store == store
                && f.class == class
                && key_substr.map(|s| f.key.contains(s)).unwrap_or(true)
        }),
        "missing {store:?} {class:?} {key_substr:?} in {err:?}"
    );
}

fn match_inside_phrase(haystack: &str, abs: usize, needle_len: usize, phrases: &[&str]) -> bool {
    phrases.iter().any(|phrase| {
        haystack
            .match_indices(phrase)
            .any(|(j, p)| abs >= j && abs + needle_len <= j + p.len())
    })
}

fn assert_needles_allowlisted(haystack: &str, needle: &str, phrases: &[&str]) {
    let mut start = 0usize;
    while let Some(rel) = haystack[start..].find(needle) {
        let abs = start + rel;
        assert!(
            match_inside_phrase(haystack, abs, needle.len(), phrases),
            "unallowlisted {needle:?} at byte {abs}"
        );
        start = abs + needle.len();
    }
}

fn first_call_arg(after_open_paren: &str) -> &str {
    let s = after_open_paren.trim_start();
    let bytes = s.as_bytes();
    let mut i = 0usize;
    let mut depth = 1i32;
    let mut quote: Option<u8> = None;
    while i < bytes.len() {
        let b = bytes[i];
        if let Some(q) = quote {
            if b == q {
                quote = None;
            } else if b == b'\\' {
                i += 1;
            }
            i += 1;
            continue;
        }
        match b {
            b'\'' | b'"' | b'`' => quote = Some(b),
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => {
                depth -= 1;
                if depth == 0 {
                    return s[..i].trim();
                }
            }
            b',' if depth == 1 => return s[..i].trim(),
            _ => {}
        }
        i += 1;
    }
    s.trim()
}

fn assert_call_first_args_have_no_secrets(src: &str, callee: &str) {
    let mut start = 0usize;
    while let Some(rel) = src[start..].find(callee) {
        let abs = start + rel + callee.len();
        let arg = first_call_arg(&src[abs..]);
        for secret in ["state.token", "state.csrf", "data.token", "data.csrf_token"] {
            assert!(
                !arg.contains(secret),
                "{callee} first arg contains {secret}: {arg:?}"
            );
        }
        start = abs + 1;
    }
}

#[test]
fn t11a_planted_runtime_secret_in_local_storage() {
    let mut snap = ClientStorageSnapshot::default();
    snap.local_storage.insert(
        "advance.session.token".into(),
        "T11-PLAINTEXT-runtime".into(),
    );
    assert_err(
        &snap,
        "localStorage",
        SecretClass::RuntimeSecret,
        Some("token"),
    );
}

#[test]
fn t11b_planted_provider_key_in_session_storage() {
    let mut snap = ClientStorageSnapshot::default();
    snap.session_storage.insert(
        "llm.provider_key".into(),
        "sk-test-KEY-T11-plaintext".into(),
    );
    assert_err(
        &snap,
        "sessionStorage",
        SecretClass::ProviderKey,
        Some("provider_key"),
    );
}

#[test]
fn t11c_planted_provider_key_in_cookie() {
    let mut snap = ClientStorageSnapshot::default();
    snap.cookies
        .insert("api_key".into(), "xai-T11-PLAINTEXT".into());
    assert_err(&snap, "cookie", SecretClass::ProviderKey, Some("api_key"));
}

#[test]
fn t11d_planted_hex64_in_indexed_db() {
    let mut snap = ClientStorageSnapshot::default();
    snap.indexed_db.insert("vault".into(), HEX64.into());
    assert_err(
        &snap,
        "indexedDB",
        SecretClass::RuntimeSecret,
        Some("vault"),
    );
}

#[test]
fn t11e_empty_snapshot_ok() {
    audit_client_storage(&ClientStorageSnapshot::default()).expect("empty");
}

#[test]
fn t11f_ui_pref_ok() {
    let mut snap = ClientStorageSnapshot::default();
    snap.local_storage
        .insert("history-kind".into(), "tasks".into());
    audit_client_storage(&snap).expect("ui pref");
}

#[test]
fn t11g_value_only_provider_key() {
    let mut snap = ClientStorageSnapshot::default();
    snap.local_storage
        .insert("cache".into(), "sk-ant-T11-PLAINTEXT".into());
    assert_err(
        &snap,
        "localStorage",
        SecretClass::ProviderKey,
        Some("cache"),
    );
}

#[test]
fn t11h_console_assets_have_no_persist_apis() {
    assert!(
        !PERSIST_IDENTIFIERS.is_empty(),
        "persist identifier list must stay non-empty"
    );
    let root = console_dir();
    let mut files = Vec::new();
    collect_js_html(&root, &mut files);
    assert!(!files.is_empty(), "console js/html listing empty");
    for path in &files {
        let text =
            fs::read_to_string(path).unwrap_or_else(|e| panic!("unread {}: {e}", path.display()));
        let hits = persist_hits(&text);
        assert!(
            hits.is_empty(),
            "{} contains persist identifiers {hits:?}",
            path.display()
        );
    }

    let transport = crate_root().join("src/transport.rs");
    let transport_text = fs::read_to_string(&transport).expect("transport.rs");
    let hits = persist_hits(&transport_text);
    assert!(
        hits.is_empty(),
        "transport.rs contains persist identifiers {hits:?}"
    );

    let src_dir = crate_root().join("src");
    let literals = include_str_literals(&transport_text);
    let mut js_html_embeds = 0usize;
    let collected: Vec<PathBuf> = files
        .iter()
        .map(|p| fs::canonicalize(p).expect("canonicalize collected"))
        .collect();
    for lit in literals {
        let resolved = fs::canonicalize(src_dir.join(&lit))
            .unwrap_or_else(|e| panic!("canonicalize include_str {lit:?}: {e}"));
        let ext = resolved.extension().and_then(|e| e.to_str());
        if matches!(ext, Some("js" | "html")) {
            js_html_embeds += 1;
            assert!(
                collected.iter().any(|c| c == &resolved),
                "embed {} not in T11-h collected set",
                resolved.display()
            );
        }
    }
    assert!(
        js_html_embeds > 0,
        "zero .js/.html include_str embeds resolved"
    );
}

#[test]
fn t11i_no_set_cookie_in_client_api_src() {
    let src = crate_root().join("src");
    let mut files = Vec::new();
    src_rs_files(&src, &mut files);
    assert!(!files.is_empty(), "zero .rs files under src/");
    for path in files {
        let text = fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        assert!(!has_cookie_mint(&text), "{} mints cookies", path.display());
    }
}

#[test]
fn t11j_session_secrets_stay_on_allowlist() {
    let app = fs::read_to_string(console_dir().join("app.js")).expect("app.js");
    for needle in ["state.token", "state.csrf", "data.token", "data.csrf_token"] {
        assert_needles_allowlisted(&app, needle, TOKEN_PHRASES);
        assert!(
            app.contains(needle),
            "expected production {needle} (RAM session)"
        );
    }
    assert_call_first_args_have_no_secrets(&app, "new WebSocket(");
    assert_call_first_args_have_no_secrets(&app, "fetch(");

    let html = fs::read_to_string(console_dir().join("index.html")).expect("index.html");
    assert!(
        html.contains(r#"<form id="login-form" method="post">"#),
        "login form must POST so a missed preventDefault cannot put the bootstrap code in location.search"
    );
    let input = html
        .split("<input id=\"bootstrap-code\"")
        .nth(1)
        .and_then(|s| s.split('>').next())
        .expect("bootstrap-code input");
    assert!(
        !input.to_ascii_lowercase().contains("name="),
        "bootstrap-code input must not have a name= (GET would serialize it)"
    );
    assert!(
        !input.contains("type=\"password\""),
        "bootstrap-code must not be type=password (Firefox password manager keys on that)"
    );
    assert!(
        input.contains(r#"autocomplete="off""#),
        "bootstrap-code must autocomplete=off so session restore does not snapshot the one-time code"
    );
    assert!(
        app.contains("input.value = \"\"") || app.contains("input.value=\"\""),
        "login must clear the bootstrap field before the login request"
    );
    let login_bind = r##"document.querySelector("#login-form").addEventListener("submit""##;
    let Some(i) = app.find(login_bind) else {
        panic!("login-form submit listener missing");
    };
    let window = &app[i..app.len().min(i + 400)];
    assert!(
        window.contains("preventDefault"),
        "login-form submit listener must call preventDefault"
    );
}

#[test]
fn t11l_csrf_in_session_storage() {
    let mut snap = ClientStorageSnapshot::default();
    snap.session_storage
        .insert("csrf".into(), "denied-reason".into());
    assert_err(
        &snap,
        "sessionStorage",
        SecretClass::RuntimeSecret,
        Some("csrf"),
    );
}

#[test]
fn t11m_nested_json_state() {
    let mut snap = ClientStorageSnapshot::default();
    let body = format!(r#"{{"token":"{HEX64}","csrf":"{HEX64}"}}"#);
    snap.local_storage
        .insert("advance.console.state".into(), body);
    let err = audit_client_storage(&snap).expect_err("nested");
    assert!(
        err.iter()
            .any(|f| { f.class == SecretClass::RuntimeSecret && f.key.contains(".token") }),
        "{err:?}"
    );
}

#[test]
fn t11n_session_cookie_hex64() {
    let mut snap = ClientStorageSnapshot::default();
    snap.cookies.insert("session".into(), HEX64.into());
    assert_err(&snap, "cookie", SecretClass::RuntimeSecret, Some("session"));
}

#[test]
fn t11o_bearer_tab_hex64() {
    let mut snap = ClientStorageSnapshot::default();
    snap.local_storage
        .insert("cache".into(), format!("Bearer\t{HEX64}"));
    assert_err(
        &snap,
        "localStorage",
        SecretClass::RuntimeSecret,
        Some("cache"),
    );
}

#[test]
fn t11p_api_hyphen_key() {
    let mut snap = ClientStorageSnapshot::default();
    snap.local_storage
        .insert("api-key".into(), "T11-PLAINTEXT-hyphen".into());
    assert_err(
        &snap,
        "localStorage",
        SecretClass::RuntimeSecret,
        Some("api-key"),
    );
}

#[test]
fn t11q_negatives() {
    let mut snap = ClientStorageSnapshot::default();
    snap.local_storage
        .insert("session_id".into(), format!("sess_{HEX32}"));
    snap.local_storage.insert(
        "run_id".into(),
        "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".into(),
    );
    snap.local_storage.insert("history-kind".into(), "".into());
    snap.local_storage.insert("cursor".into(), "AAAA".into());
    snap.local_storage.insert("task_id".into(), "task-1".into());
    audit_client_storage(&snap).expect("negatives");
}

#[test]
fn t11r_json_stringified_hex64() {
    let mut snap = ClientStorageSnapshot::default();
    snap.local_storage
        .insert("cache".into(), format!("\"{HEX64}\""));
    assert_err(
        &snap,
        "localStorage",
        SecretClass::RuntimeSecret,
        Some("cache"),
    );
}

#[test]
fn t11s_bootstrap_hex32() {
    let mut snap = ClientStorageSnapshot::default();
    snap.local_storage.insert("cache".into(), HEX32.into());
    assert_err(
        &snap,
        "localStorage",
        SecretClass::RuntimeSecret,
        Some("cache"),
    );
}

#[test]
fn t11s_json_stringified_hex32() {
    let mut snap = ClientStorageSnapshot::default();
    snap.local_storage
        .insert("cache".into(), format!("\"{HEX32}\""));
    assert_err(
        &snap,
        "localStorage",
        SecretClass::RuntimeSecret,
        Some("cache"),
    );
}

#[test]
fn t11s_nested_object_hex32() {
    let mut snap = ClientStorageSnapshot::default();
    snap.local_storage
        .insert("cache".into(), format!(r#"{{"code":"{HEX32}"}}"#));
    assert_err(
        &snap,
        "localStorage",
        SecretClass::RuntimeSecret,
        Some(".code"),
    );
}

#[test]
fn t11s_query_assigned_hex32() {
    let mut snap = ClientStorageSnapshot::default();
    snap.local_storage
        .insert("cache".into(), format!("bootstrap_code={HEX32}"));
    assert_err(
        &snap,
        "localStorage",
        SecretClass::RuntimeSecret,
        Some("cache"),
    );
}

#[test]
fn t11t_advance_bearer_form() {
    let mut snap = ClientStorageSnapshot::default();
    snap.local_storage
        .insert("cache".into(), format!("advance.bearer.{HEX64}"));
    assert_err(
        &snap,
        "localStorage",
        SecretClass::RuntimeSecret,
        Some("cache"),
    );
}

#[test]
fn t11u_comma_joined_protocols() {
    let mut snap = ClientStorageSnapshot::default();
    snap.local_storage.insert(
        "cache".into(),
        format!("advance.client.2026-06-30, advance.bearer.{HEX64}"),
    );
    assert_err(
        &snap,
        "localStorage",
        SecretClass::RuntimeSecret,
        Some("cache"),
    );
}

#[test]
fn t11v_authorization_bearer_hex64() {
    let mut snap = ClientStorageSnapshot::default();
    snap.local_storage
        .insert("cache".into(), format!("Authorization: Bearer {HEX64}"));
    assert_err(
        &snap,
        "localStorage",
        SecretClass::RuntimeSecret,
        Some("cache"),
    );
}

#[test]
fn t11w_json_array_ws_protocols() {
    let mut snap = ClientStorageSnapshot::default();
    let body = format!(r#"["advance.client.2026-06-30","advance.bearer.{HEX64}"]"#);
    snap.local_storage.insert("cache".into(), body);
    assert_err(
        &snap,
        "localStorage",
        SecretClass::RuntimeSecret,
        Some("cache"),
    );
}

#[test]
fn t11x_ghs_prefix() {
    let mut snap = ClientStorageSnapshot::default();
    snap.local_storage
        .insert("cache".into(), format!("ghs_{HEX32}"));
    assert_err(
        &snap,
        "localStorage",
        SecretClass::ProviderKey,
        Some("cache"),
    );
}

#[test]
fn t11y_pem_mixed_case() {
    let mut snap = ClientStorageSnapshot::default();
    snap.local_storage.insert(
        "cache".into(),
        "-----begin rsa private key-----\nMII\n-----end rsa private key-----".into(),
    );
    assert_err(
        &snap,
        "localStorage",
        SecretClass::ProviderKey,
        Some("cache"),
    );
}

#[test]
fn t11z_private_key_leaf() {
    let mut snap = ClientStorageSnapshot::default();
    snap.local_storage
        .insert("private_key".into(), "T11-PLAINTEXT-pem-leaf".into());
    assert_err(
        &snap,
        "localStorage",
        SecretClass::RuntimeSecret,
        Some("private_key"),
    );
}

#[test]
fn t11aa_secret_as_empty_key() {
    let mut snap = ClientStorageSnapshot::default();
    snap.local_storage.insert(HEX64.into(), "".into());
    assert_err(&snap, "localStorage", SecretClass::RuntimeSecret, None);
}

#[test]
fn t11ab_wrapped_provider_key() {
    let mut snap = ClientStorageSnapshot::default();
    snap.local_storage.insert(
        "cache".into(),
        "Authorization: Bearer sk-ant-T11-PLAINTEXT".into(),
    );
    assert_err(
        &snap,
        "localStorage",
        SecretClass::ProviderKey,
        Some("cache"),
    );
}

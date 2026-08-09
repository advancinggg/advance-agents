//! Credential injection (step 3 + step 4 of HttpSecurityChain).
//!
//! - `substitute_placeholders` — step 3: replaces `{name}` placeholders in
//!   URL/headers/body with `SecretStore::resolve(name)` values.
//! - `inject_credentials` — step 4: injects per-position credentials per the
//!   capability's `credentials: Vec<CredentialBinding>` list. 5 positions:
//!   Bearer / Basic (RFC 7617 standard base64) / CustomHeader / QueryParam
//!   (form-urlencoded) / UrlPath (placeholder substitution).
//!
//! Secret unwrap discipline: `SecretStore::resolve` returns `Secret<String>`;
//! `expose_secret()` is called ONLY at the single injection site below (no
//! logging, no Debug formatting of the unwrapped value, no clone, no
//! await-boundary holds). Drop-zeroize on scope exit.

use advance_shared_types::security_validator::{
    CredentialBinding, CredentialPosition, HttpError, HttpRequest, SecretResolutionReason,
};
use base64::Engine;
use cap_secrets::{SecretError, SecretStore};
use secrecy::ExposeSecret;

/// Step 3: substitute `{name}` placeholders in URL, headers, and body bytes
/// (best-effort lossy UTF-8 view of body) with secrets resolved from the store.
///
/// **Adversarial R1 hardening (capability-scoped resolution)**: a placeholder's
/// `name` MUST appear in `allowed_secret_names` (derived from the capability's
/// `credentials: Vec<CredentialBinding>`). A placeholder referencing a secret
/// outside the capability's binding list is REJECTED with
/// `MissingSecretFor` (no leak to the store-wide secret namespace). This
/// closes the secret-exfiltration vulnerability where a guest with capability
/// for SecretA could place `{SecretB}` in a URL and exfiltrate SecretB to an
/// allowlisted host.
///
/// Best-effort position-tag inference for error reporting:
/// - placeholder in URL path → UrlPath
/// - placeholder in URL query (after `?`) → QueryParam
/// - placeholder in header value → CustomHeader
/// - placeholder in body → BearerToken (fallback default; NOT load-bearing)
///
/// Returns `HttpError::SecretResolution(MissingSecretFor(...))` on missing secret
/// OR on out-of-capability-scope placeholder name.
pub fn substitute_placeholders(
    req: &mut HttpRequest,
    store: &SecretStore,
    allowed_secret_names: &std::collections::HashSet<String>,
) -> Result<(), HttpError> {
    let mut checkpoint = || Ok(());
    substitute_placeholders_with_checkpoint(req, store, allowed_secret_names, &mut checkpoint)
}

/// Streaming specialization of [`substitute_placeholders`]. The public
/// buffered API stays unchanged; CONTRACT-233 supplies a checkpoint that runs
/// immediately before and after each nested secret-store resolution so one
/// late backend callback cannot dispatch the next callback.
pub(crate) fn substitute_placeholders_with_checkpoint(
    req: &mut HttpRequest,
    store: &SecretStore,
    allowed_secret_names: &std::collections::HashSet<String>,
    checkpoint: &mut dyn FnMut() -> Result<(), HttpError>,
) -> Result<(), HttpError> {
    use advance_shared_types::security_validator::CredentialPositionTag;

    // URL — split into path-part and query-part to assign distinct position tags
    // for triage when a missing-secret fires. (R4-W3 fix: previously the entire
    // URL was tagged UrlPath even for query-string placeholders.)
    if has_placeholder(&req.url) {
        match req.url.split_once('?') {
            Some((path_part, query_part)) => {
                let new_path = substitute_in(
                    path_part,
                    store,
                    CredentialPositionTag::UrlPath,
                    allowed_secret_names,
                    checkpoint,
                )?;
                let new_query = substitute_in(
                    query_part,
                    store,
                    CredentialPositionTag::QueryParam,
                    allowed_secret_names,
                    checkpoint,
                )?;
                req.url = format!("{}?{}", new_path, new_query);
            }
            None => {
                req.url = substitute_in(
                    &req.url,
                    store,
                    CredentialPositionTag::UrlPath,
                    allowed_secret_names,
                    checkpoint,
                )?;
            }
        }
    }

    // Headers
    for (_, value) in req.headers.iter_mut() {
        if has_placeholder(value) {
            *value = substitute_in(
                value,
                store,
                CredentialPositionTag::CustomHeader,
                allowed_secret_names,
                checkpoint,
            )?;
        }
    }

    // Body — only if it's valid UTF-8 (else placeholder-substitution doesn't
    // apply; binary bodies are passed through as-is).
    if let Ok(body_str) = std::str::from_utf8(&req.body) {
        if has_placeholder(body_str) {
            let substituted = substitute_in(
                body_str,
                store,
                CredentialPositionTag::BearerToken,
                allowed_secret_names,
                checkpoint,
            )?;
            req.body = substituted.into_bytes();
        }
    }

    Ok(())
}

fn has_placeholder(s: &str) -> bool {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'{' {
            // Look for closing brace within reasonable distance
            for j in (i + 1)..bytes.len().min(i + 256) {
                if bytes[j] == b'}' {
                    if j > i + 1 {
                        return true;
                    }
                    break;
                }
            }
        }
        i += 1;
    }
    false
}

fn substitute_in(
    s: &str,
    store: &SecretStore,
    position_tag: advance_shared_types::security_validator::CredentialPositionTag,
    allowed_secret_names: &std::collections::HashSet<String>,
    checkpoint: &mut dyn FnMut() -> Result<(), HttpError>,
) -> Result<String, HttpError> {
    // Walk the string byte-by-byte to detect ASCII `{` boundaries (UTF-8
    // ASCII codepoints are single-byte and never appear as continuation bytes
    // inside multi-byte sequences, so byte-level `{` detection is UTF-8-safe).
    // For non-placeholder spans we COPY THE ORIGINAL UTF-8 SLICE — NOT
    // byte-by-byte casts — to preserve any non-ASCII content (R2-C1 fix:
    // prior `out.push(bytes[i] as char)` corrupted any non-ASCII byte
    // alongside a placeholder).
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    let mut copy_start = 0usize;

    while i < bytes.len() {
        if bytes[i] == b'{' {
            // Find the matching `}` within a 256-byte lookahead window.
            // (Documented limit: placeholder names are bounded — this prevents
            // pathological scans across megabyte-scale bodies.)
            let mut close: Option<usize> = None;
            for j in (i + 1)..bytes.len().min(i + 256) {
                if bytes[j] == b'}' {
                    close = Some(j);
                    break;
                }
            }
            if let Some(close_idx) = close {
                if close_idx > i + 1 {
                    let name = &s[i + 1..close_idx];
                    // Validate name is ASCII-sane (alphanumeric + - _ .)
                    if name
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
                    {
                        // Capability-scope check: the placeholder name MUST
                        // appear in the capability's allowed secret_name set.
                        // Out-of-scope names are REJECTED — preventing
                        // capability-bypass exfiltration of any secret in
                        // the store. (Adversarial R1 fix.)
                        if !allowed_secret_names.contains(name) {
                            return Err(HttpError::SecretResolution(
                                SecretResolutionReason::MissingSecretFor(position_tag.clone()),
                            ));
                        }
                        // Flush any pending pre-placeholder span (preserves UTF-8).
                        out.push_str(&s[copy_start..i]);
                        checkpoint()?;
                        let resolved = store.resolve(name);
                        checkpoint()?;
                        let secret = resolved.map_err(|e| match e {
                            SecretError::NotFound(_) => HttpError::SecretResolution(
                                SecretResolutionReason::MissingSecretFor(position_tag.clone()),
                            ),
                            // Other SecretError variants surface as
                            // SecretResolution with the same generic position
                            // tag — bodies/keys are not propagated.
                            _ => HttpError::SecretResolution(
                                SecretResolutionReason::MissingSecretFor(position_tag.clone()),
                            ),
                        })?;
                        // Adversarial R2 fix: validate the resolved secret
                        // for CRLF / control characters BEFORE substituting.
                        // Step 4's inject_credentials applies the same check;
                        // step 3 must too, otherwise an operator-stored
                        // secret with embedded `\r\nX-Forwarded-User: admin`
                        // smuggles a header via placeholder substitution.
                        let secret_value = secret.expose_secret();
                        if !is_legal_header_value(secret_value) {
                            return Err(HttpError::SecretResolution(
                                SecretResolutionReason::MissingSecretFor(position_tag.clone()),
                            ));
                        }
                        // Single expose_secret site — value flows directly into
                        // the output string, no logging / Debug / clone.
                        out.push_str(secret_value);
                        i = close_idx + 1;
                        copy_start = i;
                        continue;
                    }
                }
            }
        }
        i += 1;
    }
    // Flush trailing span.
    out.push_str(&s[copy_start..]);

    Ok(out)
}

/// Step 4: inject credentials into the request per the capability's
/// `credentials: Vec<CredentialBinding>` list. Each binding's
/// `CredentialPosition` variant carries the selector data; the `secret_name`
/// is resolved via `SecretStore::resolve` and injected at the single
/// `expose_secret()` site.
///
/// **Adversarial R1 hardening**:
/// - All header VALUES (Bearer / Basic / CustomHeader) are validated for
///   CRLF + control characters via `is_legal_header_value`; injection fails
///   with `HttpError::SecretResolution(MissingSecretFor)` if the resolved
///   secret contains forbidden bytes (defense against header smuggling
///   when an operator-stored secret has embedded `\r\n`).
/// - `BasicAuth.username` is validated via `is_legal_basic_username`:
///   rejects `:` (RFC 7617 violation) AND CR/LF/control chars.
/// - `CustomHeader.key` and `QueryParam.key` are validated via
///   `is_legal_header_name` / `is_legal_query_key` to reject CR/LF and
///   shape-defining metacharacters (`:` `=` `&` `?` etc.).
pub fn inject_credentials(
    req: &mut HttpRequest,
    bindings: &[CredentialBinding],
    store: &SecretStore,
) -> Result<(), HttpError> {
    let mut checkpoint = || Ok(());
    inject_credentials_with_checkpoint(req, bindings, store, &mut checkpoint)
}

/// Streaming specialization of [`inject_credentials`]. The checkpoint keeps
/// multiple credential bindings from issuing another nested storage callback
/// after the entry-anchored CONTRACT-233 deadline has expired.
pub(crate) fn inject_credentials_with_checkpoint(
    req: &mut HttpRequest,
    bindings: &[CredentialBinding],
    store: &SecretStore,
    checkpoint: &mut dyn FnMut() -> Result<(), HttpError>,
) -> Result<(), HttpError> {
    for binding in bindings {
        let position_tag = binding.position.tag();
        // Pre-validate operator-supplied selector fields (username/key) BEFORE
        // resolving the secret — these come from capability config, not from
        // the secret store, and are operator-trusted but not user-trusted.
        match &binding.position {
            CredentialPosition::BasicAuth { username } => {
                if !is_legal_basic_username(username) {
                    return Err(HttpError::SecretResolution(
                        SecretResolutionReason::MissingSecretFor(position_tag.clone()),
                    ));
                }
            }
            CredentialPosition::CustomHeader { key } => {
                if !is_legal_header_name(key) {
                    return Err(HttpError::SecretResolution(
                        SecretResolutionReason::MissingSecretFor(position_tag.clone()),
                    ));
                }
            }
            CredentialPosition::QueryParam { key } | CredentialPosition::UrlPath { key } => {
                if !is_legal_query_key(key) {
                    return Err(HttpError::SecretResolution(
                        SecretResolutionReason::MissingSecretFor(position_tag.clone()),
                    ));
                }
            }
            CredentialPosition::BearerToken => {}
        }

        checkpoint()?;
        let resolved = store.resolve(&binding.secret_name);
        checkpoint()?;
        let secret = resolved.map_err(|_| {
            HttpError::SecretResolution(SecretResolutionReason::MissingSecretFor(
                position_tag.clone(),
            ))
        })?;
        // Single expose_secret site for this position. The unwrapped value is
        // consumed immediately into the request shape (no clone, no await).
        let secret_value = secret.expose_secret();

        // Reject any secret containing CRLF or control characters that would
        // break HTTP header / URL semantics — this is an operator-storage
        // hygiene defense (legitimate secrets never contain these).
        if !is_legal_header_value(secret_value) {
            return Err(HttpError::SecretResolution(
                SecretResolutionReason::MissingSecretFor(position_tag.clone()),
            ));
        }

        match &binding.position {
            CredentialPosition::BearerToken => {
                set_header(
                    &mut req.headers,
                    "Authorization",
                    &format!("Bearer {}", secret_value),
                );
            }
            CredentialPosition::BasicAuth { username } => {
                let pair = format!("{}:{}", username, secret_value);
                let encoded = base64::engine::general_purpose::STANDARD.encode(pair.as_bytes());
                set_header(
                    &mut req.headers,
                    "Authorization",
                    &format!("Basic {}", encoded),
                );
            }
            CredentialPosition::CustomHeader { key } => {
                set_header(&mut req.headers, key, secret_value);
            }
            CredentialPosition::QueryParam { key } => {
                let encoded: String =
                    url::form_urlencoded::byte_serialize(secret_value.as_bytes()).collect();
                if req.url.contains('?') {
                    req.url = format!("{}&{}={}", req.url, key, encoded);
                } else {
                    req.url = format!("{}?{}={}", req.url, key, encoded);
                }
            }
            CredentialPosition::UrlPath { key } => {
                let placeholder = format!("{{{}}}", key);
                // Adversarial R3 fix: scope UrlPath replacement to the URL
                // PATH portion only — splitting on `?` (query separator)
                // and `#` (fragment separator) so a placeholder in the path
                // doesn't accidentally also substitute into a same-named
                // placeholder in query/fragment (which would copy a path-
                // only secret into more loggable surfaces). Reject if no
                // placeholder is found in the path portion.
                let (path_part, suffix) = split_url_path(&req.url);
                if !path_part.contains(&placeholder) {
                    return Err(HttpError::SecretResolution(
                        SecretResolutionReason::PlaceholderNotInUrl,
                    ));
                }
                let encoded: String =
                    url::form_urlencoded::byte_serialize(secret_value.as_bytes()).collect();
                let new_path = path_part.replace(&placeholder, &encoded);
                req.url = format!("{}{}", new_path, suffix);
            }
        }
    }
    Ok(())
}

/// RFC 7230 field-value safety: VCHAR + SP + HTAB only. Rejects CR, LF, NUL,
/// and any control chars. Allows non-ASCII for compatibility with obs-text
/// (some servers return UTF-8 in Set-Cookie etc.) — reject only the byte
/// values that materially affect HTTP framing.
fn is_legal_header_value(s: &str) -> bool {
    s.bytes()
        .all(|b| b == b' ' || b == b'\t' || (b >= 0x20 && b != 0x7f) || b >= 0x80)
}

/// Header name hygiene: ASCII printable, no `:` (delimiter), no CR/LF.
fn is_legal_header_name(s: &str) -> bool {
    !s.is_empty()
        && s.bytes().all(|b| {
            (b >= b'!' && b <= b'~')
                && b != b':'
                && b != b'('
                && b != b')'
                && b != b'<'
                && b != b'>'
                && b != b'@'
                && b != b','
                && b != b';'
                && b != b'\\'
                && b != b'"'
                && b != b'/'
                && b != b'['
                && b != b']'
                && b != b'?'
                && b != b'='
                && b != b'{'
                && b != b'}'
        })
}

/// BasicAuth username hygiene per RFC 7617 §2: MUST NOT contain `:`. Plus
/// CR/LF/NUL/control rejection for consistency with header value hygiene.
/// Empty username is allowed (RFC 7617 permits "" — many servers reject but
/// that's the upstream's call, not ours).
fn is_legal_basic_username(s: &str) -> bool {
    s.bytes().all(|b| {
        b != b':' && b != b'\r' && b != b'\n' && b != 0 && (b >= 0x20 || b == b'\t') && b != 0x7f
    })
}

/// Query-string key hygiene: alphanumeric + `-_.` only. Rejects CR/LF, `=`,
/// `&`, `?`, `#`, `{`, `}` and other shape-defining metacharacters.
fn is_legal_query_key(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
}

/// Split a URL string into `(path_portion, suffix)` where `suffix` includes
/// the query (`?...`) and/or fragment (`#...`). Used by `CredentialPosition::UrlPath`
/// to scope `{key}` replacement to the path portion only (R3 path-scope fix).
fn split_url_path(url: &str) -> (&str, &str) {
    let q = url.find('?');
    let f = url.find('#');
    let split_at = match (q, f) {
        (Some(qi), Some(fi)) => qi.min(fi),
        (Some(qi), None) => qi,
        (None, Some(fi)) => fi,
        (None, None) => return (url, ""),
    };
    (&url[..split_at], &url[split_at..])
}

/// Set or override a header by name (case-insensitive name match).
fn set_header(headers: &mut Vec<(String, String)>, name: &str, value: &str) {
    let lc = name.to_ascii_lowercase();
    headers.retain(|(n, _)| n.to_ascii_lowercase() != lc);
    headers.push((name.to_string(), value.to_string()));
}

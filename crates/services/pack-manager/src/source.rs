//! Pack source-type parser per §1.3.2 step ① (AC-05).
//!
//! Slice D: `SourceRef::GitUrl` is a struct variant `{url, git_ref}` so the parsed
//! ref is stored separately from the URL. `parse_source` enforces the strict
//! 0/1/2+ `@` rule on `git+` URLs: 0 `@` → no ref; 1 `@` → split + validate ref
//! grammar; 2+ `@` → reject for URL ambiguity (userinfo URL ambiguity with
//! `@<ref>` suffix). `validate()` re-applies every parse invariant on
//! resolver-injected SourceRef values (recursive-path defense-in-depth gate).
//! `source_form()` reconstructs the canonical string for trace-payload
//! presentation.

use std::path::PathBuf;

use crate::error::PackError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceRef {
    Local(PathBuf),
    /// Slice D: struct variant — `url` carries the `git_clone`-ready URL with no
    /// `git+` prefix; `git_ref` carries the optional tag/branch ref split from the
    /// `@<ref>` suffix at parse time.
    GitUrl {
        url: String,
        git_ref: Option<String>,
    },
    Tarball(PathBuf),
    Registry {
        name: String,
        version: String,
    },
}

impl SourceRef {
    pub fn kind_str(&self) -> &'static str {
        match self {
            SourceRef::Local(_) => "local",
            SourceRef::GitUrl { .. } => "git",
            SourceRef::Tarball(_) => "tarball",
            SourceRef::Registry { .. } => "registry",
        }
    }

    /// Presentation-only canonical reconstruction for trace payload `{"source":
    /// "..."}` continuity. NOT a parser round-trip (the recursive install path
    /// takes `&SourceRef` directly).
    ///
    /// Slice D `validate()` rejects `@` in `GitUrl.url` so resolver-injected
    /// userinfo URLs cannot reach `source_form()`. parse_source's strict 0/1/2+
    /// `@` rule similarly rejects multi-`@` URLs at parse time, so the only
    /// way userinfo URLs reach this method is via a top-level
    /// `Installer::install(source: &str)` whose top-level parse_source call
    /// already failed (the error path emits `{"source": source}` with the raw
    /// input). ADVERSARIAL round-1 Codex W3 documented: if URL is constructed
    /// with userinfo, the credential portion (`user:token`) leaks to trace
    /// sinks in the error-path payload only. Mitigation = admin trust model
    /// (admin-supplied source string is not adversarial; documented in §2.9).
    /// Production-grade redaction (e.g., parse URL and replace userinfo with
    /// `***`) deferred to Slice D+.
    pub fn source_form(&self) -> String {
        match self {
            SourceRef::Local(p) => p.display().to_string(),
            SourceRef::GitUrl { url, git_ref } => match git_ref {
                Some(r) => format!("git+{url}@{r}"),
                None => format!("git+{url}"),
            },
            SourceRef::Tarball(p) => p.display().to_string(),
            SourceRef::Registry { name, version } => format!("registry:{name}@{version}"),
        }
    }

    /// Defense-in-depth + recursive-path validation gate. Re-applies every
    /// `parse_source` invariant (scheme whitelist, ref grammar, SHA rejection,
    /// registry name/version shape). Called at the top of
    /// `Installer::install_with_context` after Step1ParseSource trace emission
    /// so AC-05 "each step emits a trace event" holds even when validate()
    /// rejects a resolver-injected invalid SourceRef.
    pub fn validate(&self) -> Result<(), PackError> {
        match self {
            SourceRef::Local(_) => Ok(()),
            SourceRef::GitUrl { url, git_ref } => {
                validate_git_url_scheme(url)?;
                // AUDIT round-3 Codex Diff W1 fix — recursive resolver-injection
                // defense: the URL field of a GitUrl SourceRef must NOT contain
                // `@` (any `@<ref>` would have been peeled off by parse_source
                // into git_ref; userinfo-style URLs with `@` are explicitly
                // rejected by parse_source's strict 0/1/2+ @ rule and must be
                // similarly rejected here for resolver-injected paths. Without
                // this gate, a buggy/hostile DependencyResolver could return
                // `SourceRef::GitUrl { url: "https://user:tok@host/r", git_ref:
                // None }` and bypass the parse-time userinfo rejection.
                if url.contains('@') {
                    return Err(PackError::InvalidManifest(format!(
                        "git URL field contains '@' which is reserved for the \
                         @<ref> suffix peel-off at parse time; userinfo-style \
                         URLs are not supported in Slice D: {url}"
                    )));
                }
                if let Some(r) = git_ref {
                    validate_git_ref(r)?;
                }
                Ok(())
            }
            SourceRef::Tarball(p) => {
                let s = p
                    .to_str()
                    .ok_or_else(|| PackError::InvalidManifest("non-UTF-8 tarball path".into()))?;
                if !(s.ends_with(".tar.gz") || s.ends_with(".tgz")) {
                    return Err(PackError::InvalidManifest(format!(
                        "tarball source must end in .tar.gz or .tgz: {s}"
                    )));
                }
                Ok(())
            }
            SourceRef::Registry { name, version } => validate_registry_segments(name, version),
        }
    }
}

pub fn parse_source(s: &str) -> Result<SourceRef, PackError> {
    if let Some(rest) = s.strip_prefix("git+") {
        if rest.is_empty() {
            return Err(PackError::InvalidManifest("git+ source missing URL".into()));
        }
        // Slice D: strict 0/1/2+ `@` rule.
        let at_count = rest.matches('@').count();
        let (url, git_ref) = match at_count {
            0 => (rest.to_string(), None),
            1 => {
                let (url_part, ref_part) = rest.split_once('@').unwrap();
                if url_part.is_empty() {
                    return Err(PackError::InvalidManifest(format!(
                        "git URL empty before @: {s}"
                    )));
                }
                if ref_part.is_empty() {
                    return Err(PackError::InvalidManifest(format!(
                        "empty git ref after @: {s}"
                    )));
                }
                validate_git_ref(ref_part)?;
                (url_part.to_string(), Some(ref_part.to_string()))
            }
            _ => {
                return Err(PackError::InvalidManifest(format!(
                    "git URL contains multiple @ — userinfo-style URLs \
                     (e.g. https://user@host) with @<ref> suffix are ambiguous \
                     and not supported in Slice D. Workarounds: \
                     (a) configure git credentials via the local credential \
                     helper before running `advance pack install` so the URL \
                     itself contains no userinfo, then append @<ref> for the \
                     version, OR (b) use a plain https:// URL with no @ at \
                     all (clones HEAD). Proper URL-parser-based userinfo \
                     disambiguation is deferred to Slice D+: {s}"
                )));
            }
        };
        validate_git_url_scheme(&url)?;
        return Ok(SourceRef::GitUrl { url, git_ref });
    }
    if let Some(rest) = s.strip_prefix("registry:") {
        let (name, version) = rest.split_once('@').ok_or_else(|| {
            PackError::InvalidManifest(format!("registry source missing @version: {s}"))
        })?;
        if name.is_empty() || version.is_empty() {
            return Err(PackError::InvalidManifest(format!(
                "registry source empty name or version: {s}"
            )));
        }
        validate_registry_segments(name, version)?;
        return Ok(SourceRef::Registry {
            name: name.into(),
            version: version.into(),
        });
    }
    if s.ends_with(".tar.gz") || s.ends_with(".tgz") {
        return Ok(SourceRef::Tarball(PathBuf::from(s)));
    }
    Ok(SourceRef::Local(PathBuf::from(s)))
}

/// Slice D: URL scheme whitelist — accept only `file://` and `https://` (per
/// M017 cap-skills slice-E precedent at import.rs:438-452; `http://` rejected
/// because transport must be authenticated or local).
fn validate_git_url_scheme(url: &str) -> Result<(), PackError> {
    const ALLOWED: &[&str] = &["file://", "https://"];
    let lower = url.to_ascii_lowercase();
    if ALLOWED.iter().any(|p| lower.starts_with(p)) {
        return Ok(());
    }
    Err(PackError::InvalidManifest(format!(
        "unsupported git URL scheme: {url} (allowed: file://, https://)"
    )))
}

/// Slice D: git ref grammar — subset of `git check-ref-format --branch` suitable
/// for the `--branch <ref>` flag. Allowed characters `[a-zA-Z0-9._+-]`; 1..=255
/// chars; no `/`, no `..`, no leading `-`, no leading/trailing `.`, no `.lock`
/// suffix, no metacharacters `^:?*[\~@/`; no whitespace, no control chars; reject
/// 40-char hex SHA strings (shallow clone limitation per
/// `uploadpack.allowReachableSHA1InWant`).
fn validate_git_ref(r: &str) -> Result<(), PackError> {
    if r.is_empty() {
        return Err(PackError::InvalidManifest(
            "git ref must not be empty".into(),
        ));
    }
    if r.len() > 255 {
        return Err(PackError::InvalidManifest(format!(
            "git ref exceeds 255 chars ({} chars)",
            r.len()
        )));
    }
    if r.starts_with('-') {
        return Err(PackError::InvalidManifest(format!(
            "git ref must not start with '-': {r}"
        )));
    }
    if r.starts_with('.') || r.ends_with('.') {
        return Err(PackError::InvalidManifest(format!(
            "git ref must not start or end with '.': {r}"
        )));
    }
    if r.contains("..") {
        return Err(PackError::InvalidManifest(format!(
            "git ref must not contain '..': {r}"
        )));
    }
    if r.ends_with(".lock") {
        return Err(PackError::InvalidManifest(format!(
            "git ref must not end with '.lock': {r}"
        )));
    }
    // SHA rejection: pure 40-char hex string (commit-SHA shaped). Slice D does
    // not support commit-SHA refs because `git clone --depth 1 --branch <sha>`
    // requires server-side `uploadpack.allowReachableSHA1InWant` (disabled by
    // default on GitHub and most servers).
    if r.len() == 40 && r.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(PackError::InvalidManifest(format!(
            "git ref looks like a commit SHA; only tags/branches supported in Slice D: {r}"
        )));
    }
    for c in r.chars() {
        if !c.is_ascii() {
            return Err(PackError::InvalidManifest(format!(
                "git ref must be ASCII: {r}"
            )));
        }
        if c.is_whitespace() || c.is_control() {
            return Err(PackError::InvalidManifest(format!(
                "git ref must not contain whitespace or control chars: {r:?}"
            )));
        }
        // Allowed: alphanumeric + `.` + `_` + `-` + `+`
        if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' || c == '+' {
            continue;
        }
        // Everything else (incl. `/`, `@`, `^`, `:`, `?`, `*`, `[`, `\`, `~`) is rejected.
        return Err(PackError::InvalidManifest(format!(
            "git ref contains forbidden character {c:?}: {r} \
             (allowed: [a-zA-Z0-9._+-]; slash-containing refs deferred to Slice D+)"
        )));
    }
    Ok(())
}

/// Slice A-era helper hoisted to module-level for Slice D `validate()` reuse.
fn validate_registry_segments(name: &str, version: &str) -> Result<(), PackError> {
    if name.is_empty() || version.is_empty() {
        return Err(PackError::InvalidManifest(format!(
            "registry source empty name or version: name={name:?}, version={version:?}"
        )));
    }
    for (label, segment) in [("name", name), ("version", version)] {
        if segment.contains('\0')
            || segment.contains('/')
            || segment.contains('\\')
            || segment.contains('@')
            || segment.starts_with('.')
            || segment.contains("..")
        {
            return Err(PackError::InvalidManifest(format!(
                "registry source {label} contains forbidden shape \
                 (null/traversal/separator/leading-dot/@): {segment}"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_local() {
        assert_eq!(
            parse_source("./pack").unwrap(),
            SourceRef::Local(PathBuf::from("./pack"))
        );
    }

    #[test]
    fn parse_git_url_with_ref() {
        assert_eq!(
            parse_source("git+https://example.com/repo@v1").unwrap(),
            SourceRef::GitUrl {
                url: "https://example.com/repo".into(),
                git_ref: Some("v1".into()),
            }
        );
    }

    #[test]
    fn parse_git_url_no_ref() {
        assert_eq!(
            parse_source("git+https://example.com/repo").unwrap(),
            SourceRef::GitUrl {
                url: "https://example.com/repo".into(),
                git_ref: None,
            }
        );
    }

    #[test]
    fn parse_tarball() {
        assert_eq!(
            parse_source("/tmp/pack.tar.gz").unwrap(),
            SourceRef::Tarball(PathBuf::from("/tmp/pack.tar.gz"))
        );
    }

    #[test]
    fn parse_registry() {
        assert_eq!(
            parse_source("registry:foo@1.0.0").unwrap(),
            SourceRef::Registry {
                name: "foo".into(),
                version: "1.0.0".into()
            }
        );
    }

    #[test]
    fn parse_registry_missing_at() {
        assert!(matches!(
            parse_source("registry:foo"),
            Err(PackError::InvalidManifest(_))
        ));
    }
}

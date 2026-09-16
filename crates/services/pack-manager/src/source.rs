//! Pack source-type parser per §1.3.2 step ① (AC-05).
//!
//! Slice D: `SourceRef::GitUrl` is a struct variant `{url, git_ref}` so the parsed
//! ref is stored separately from the URL. `validate()` re-applies every parse
//! invariant on resolver-injected SourceRef values (recursive-path
//! defense-in-depth gate). `source_form()` reconstructs the canonical string for
//! trace-payload presentation.
//!
//! PACK-GAP-CLOSURE P3 (§4.2, #13):
//! - a `git+` source is split into scheme / authority / path BEFORE the `@<ref>`
//!   suffix is peeled off. Any `@` inside the authority is userinfo and is
//!   rejected (credentials never belong in a source string — configure a git
//!   credential helper instead), so a `/`-bearing ref such as `release/1.x` no
//!   longer collides with the userinfo check. The strict 0/1/2+ `@` rule then
//!   applies to the path part only.
//! - the ref grammar is `[A-Za-z0-9._+/-]+` under the `git check-ref-format`
//!   rules (see [`validate_git_ref`]); a 40-hex commit SHA is accepted and pins
//!   the install to exactly that commit (`fetch.rs` fetches it by SHA).
//! - every error text, trace payload and `source_form()` that echoes a URL
//!   passes through [`redact_userinfo`] (`scheme://user[:pass]@host…` →
//!   `scheme://***@host…`), and `PackError::GitCloneFailed`'s Display does the
//!   same, so a credential-bearing URL never reaches a log in clear text.

use std::path::PathBuf;

use crate::error::PackError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceRef {
    Local(PathBuf),
    /// Slice D: struct variant — `url` carries the `git_clone`-ready URL with no
    /// `git+` prefix; `git_ref` carries the optional tag / branch / commit-SHA
    /// ref split from the `@<ref>` suffix at parse time.
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
    /// PACK-GAP-CLOSURE P3: the git URL is passed through [`redact_userinfo`],
    /// so a resolver-injected credential-bearing URL (which `validate()` rejects
    /// right after the Step-1 trace fires) presents as `git+https://***@host/…`
    /// in every trace sink.
    pub fn source_form(&self) -> String {
        match self {
            SourceRef::Local(p) => p.display().to_string(),
            SourceRef::GitUrl { url, git_ref } => {
                let url = redact_userinfo(url);
                match git_ref {
                    Some(r) => format!("git+{url}@{r}"),
                    None => format!("git+{url}"),
                }
            }
            SourceRef::Tarball(p) => p.display().to_string(),
            SourceRef::Registry { name, version } => format!("registry:{name}@{version}"),
        }
    }

    /// Defense-in-depth + recursive-path validation gate. Re-applies every
    /// `parse_source` invariant (scheme whitelist, no userinfo / un-peeled `@`
    /// in the URL field, ref grammar, registry name/version shape). Called at
    /// the top of `Installer::install_with_context` after Step1ParseSource
    /// trace emission so AC-05 "each step emits a trace event" holds even when
    /// validate() rejects a resolver-injected invalid SourceRef.
    pub fn validate(&self) -> Result<(), PackError> {
        match self {
            SourceRef::Local(_) => Ok(()),
            SourceRef::GitUrl { url, git_ref } => {
                validate_git_url_scheme(url)?;
                // The URL field of a parsed GitUrl never contains `@`: the
                // authority may not carry userinfo (rejected at parse time) and
                // an `@<ref>` suffix is peeled off into `git_ref`. A buggy /
                // hostile DependencyResolver could still hand us
                // `SourceRef::GitUrl { url: "https://user:tok@host/r", git_ref:
                // None }` — refuse it here, with the credential redacted.
                if url.contains('@') {
                    return Err(PackError::InvalidManifest(format!(
                        "git URL field contains '@' (userinfo-style URLs are not \
                         supported; the @<ref> suffix is peeled off at parse time): {}",
                        redact_userinfo(url)
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
        return parse_git_source(rest);
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

/// `git+<url>[@<ref>]` — `rest` is everything after the `git+` prefix.
///
/// Order of gates (each error text is userinfo-redacted):
/// 1. non-empty; scheme ∈ {`file://`, `https://`};
/// 2. the authority (`://` … first `/`) must not contain `@` (userinfo);
/// 3. strict 0/1/2+ `@` rule on the path part: 0 → no ref, 1 → split + ref
///    grammar, 2+ → ambiguous, rejected.
fn parse_git_source(rest: &str) -> Result<SourceRef, PackError> {
    if rest.is_empty() {
        return Err(PackError::InvalidManifest("git+ source missing URL".into()));
    }
    validate_git_url_scheme(rest)?;
    // The scheme gate guarantees a `://`.
    let after_scheme = rest.find("://").map(|i| i + 3).unwrap_or(0);
    let authority_end = rest[after_scheme..]
        .find('/')
        .map(|i| after_scheme + i)
        .unwrap_or(rest.len());
    if rest[after_scheme..authority_end].contains('@') {
        return Err(PackError::InvalidManifest(format!(
            "git URL carries userinfo (credentials in the URL are not supported — \
             configure a git credential helper and use a plain URL): git+{}",
            redact_userinfo(rest)
        )));
    }
    let path_part = &rest[authority_end..];
    let (url, git_ref) = match path_part.matches('@').count() {
        0 => (rest.to_string(), None),
        1 => {
            let at = authority_end + path_part.find('@').unwrap_or(0);
            let (url_part, ref_part) = (&rest[..at], &rest[at + 1..]);
            if ref_part.is_empty() {
                return Err(PackError::InvalidManifest(format!(
                    "empty git ref after @: git+{}",
                    redact_userinfo(rest)
                )));
            }
            validate_git_ref(ref_part)?;
            (url_part.to_string(), Some(ref_part.to_string()))
        }
        _ => {
            return Err(PackError::InvalidManifest(format!(
                "git source contains multiple @ after the host — at most one \
                 @<ref> suffix is allowed: git+{}",
                redact_userinfo(rest)
            )));
        }
    };
    Ok(SourceRef::GitUrl { url, git_ref })
}

/// Mask URL userinfo for presentation: `scheme://user[:pass]@host…` →
/// `scheme://***@host…`. Everything up to and including the LAST `@` of the
/// authority (`://` … first `/`) is replaced, so a password containing `@`
/// is masked in full; an input without a scheme masks the same way from its
/// start. A string whose authority carries no `@` is returned unchanged, so
/// the `@<ref>` suffix of a normal `git+` source (which sits in the path) is
/// never touched.
pub fn redact_userinfo(s: &str) -> String {
    let (prefix, rest) = match s.find("://") {
        Some(i) => (&s[..i + 3], &s[i + 3..]),
        None => ("", s),
    };
    let authority_end = rest.find('/').unwrap_or(rest.len());
    match rest[..authority_end].rfind('@') {
        Some(at) => format!("{prefix}***@{}", &rest[at + 1..]),
        None => s.to_string(),
    }
}

/// `true` when `r` is shaped like a full 40-hex commit SHA — such a ref pins
/// the install to exactly that commit (fetched by SHA rather than cloned by
/// branch; see `fetch.rs`).
pub fn is_commit_sha(r: &str) -> bool {
    r.len() == 40 && r.bytes().all(|b| b.is_ascii_hexdigit())
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
        "unsupported git URL scheme: {} (allowed: file://, https://)",
        redact_userinfo(url)
    )))
}

/// Git ref grammar (PACK-GAP-CLOSURE P3 §4.2): `[A-Za-z0-9._+/-]+`, 1..=255
/// chars, plus the `git check-ref-format` rules — must not start with `-`
/// (option injection into `--branch`) or `/`, must not end with `/`, `.` or
/// `.lock`, no `..`, no `//`, and no `/`-separated segment may start with `.`
/// or end with `.lock`. Metacharacters (`^ : ? * [ \ ~ @`), whitespace,
/// control and non-ASCII bytes are rejected. A 40-hex commit SHA passes (it is
/// a plain `[0-9a-f]+` word) and is treated as a commit pin by the fetcher.
pub(crate) fn validate_git_ref(r: &str) -> Result<(), PackError> {
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
        if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+' | '/') {
            continue;
        }
        return Err(PackError::InvalidManifest(format!(
            "git ref contains forbidden character {c:?}: {r} (allowed: [A-Za-z0-9._+/-])"
        )));
    }
    if r.starts_with('-') {
        return Err(PackError::InvalidManifest(format!(
            "git ref must not start with '-': {r}"
        )));
    }
    if r.starts_with('/') || r.ends_with('/') {
        return Err(PackError::InvalidManifest(format!(
            "git ref must not start or end with '/': {r}"
        )));
    }
    if r.ends_with('.') {
        return Err(PackError::InvalidManifest(format!(
            "git ref must not end with '.': {r}"
        )));
    }
    if r.contains("..") {
        return Err(PackError::InvalidManifest(format!(
            "git ref must not contain '..': {r}"
        )));
    }
    if r.contains("//") {
        return Err(PackError::InvalidManifest(format!(
            "git ref must not contain '//': {r}"
        )));
    }
    for seg in r.split('/') {
        if seg.starts_with('.') {
            return Err(PackError::InvalidManifest(format!(
                "git ref segment must not start with '.': {r}"
            )));
        }
        if seg.ends_with(".lock") {
            return Err(PackError::InvalidManifest(format!(
                "git ref segment must not end with '.lock': {r}"
            )));
        }
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
    fn parse_git_url_slash_ref_and_sha_pin() {
        assert_eq!(
            parse_source("git+https://example.com/org/repo.git@release/1.x").unwrap(),
            SourceRef::GitUrl {
                url: "https://example.com/org/repo.git".into(),
                git_ref: Some("release/1.x".into()),
            }
        );
        let sha = "0123456789abcdef0123456789abcdef01234567";
        match parse_source(&format!("git+file:///srv/repo.git@{sha}")).unwrap() {
            SourceRef::GitUrl { url, git_ref } => {
                assert_eq!(url, "file:///srv/repo.git");
                assert_eq!(git_ref.as_deref(), Some(sha));
                assert!(is_commit_sha(sha));
            }
            other => panic!("{other:?}"),
        }
        assert!(!is_commit_sha("v1.0"));
        assert!(!is_commit_sha(&"g".repeat(40)));
    }

    #[test]
    fn parse_git_url_rejects_userinfo_with_redacted_text() {
        for input in [
            "git+https://user:s3cr3t@example.com/org/repo.git",
            "git+https://user:s3cr3t@example.com/org/repo.git@v1",
            "git+https://user@host/r",
            "git+https://user:p@ss@host/r@release/1.x",
        ] {
            let err = parse_source(input).expect_err(input);
            let text = err.to_string();
            assert!(!text.contains("s3cr3t") && !text.contains("p@ss"), "{text}");
            assert!(text.contains("***@"), "{text}");
        }
    }

    #[test]
    fn redact_userinfo_masks_only_the_authority() {
        assert_eq!(
            redact_userinfo("https://user:pass@example.com/org/repo.git@v1"),
            "https://***@example.com/org/repo.git@v1"
        );
        assert_eq!(
            redact_userinfo("git+https://user:p@ss@host/r"),
            "git+https://***@host/r"
        );
        assert_eq!(
            redact_userinfo("https://example.com/repo@release/1.x"),
            "https://example.com/repo@release/1.x"
        );
        assert_eq!(
            redact_userinfo("file:///path/with@at/repo.git"),
            "file:///path/with@at/repo.git"
        );
        assert_eq!(redact_userinfo("user:tok@host/r"), "***@host/r");
        assert_eq!(redact_userinfo("plain"), "plain");
    }

    #[test]
    fn git_ref_grammar_check_ref_format_rules() {
        for ok in [
            "v1.0",
            "release/1.x",
            "feature/foo-bar_baz+1",
            "refs/heads/main",
            "0123456789abcdef0123456789abcdef01234567",
        ] {
            validate_git_ref(ok).unwrap_or_else(|e| panic!("{ok}: {e}"));
        }
        for bad in [
            "",
            "-rf",
            "/leading",
            "trailing/",
            "trailing.",
            ".hidden",
            "a/.hidden",
            "a..b",
            "a//b",
            "x.lock",
            "refs/heads/x.lock",
            "a@{1}",
            "v1^2",
            "v1:x",
            "v1?",
            "v1*",
            "v1[",
            "v1\\x",
            "v1~1",
            "v1 x",
            "v1\nx",
            "über",
        ] {
            assert!(validate_git_ref(bad).is_err(), "must reject {bad:?}");
        }
        assert!(validate_git_ref(&"a".repeat(255)).is_ok());
        assert!(validate_git_ref(&"a".repeat(256)).is_err());
    }

    #[test]
    fn source_form_and_validate_redact_injected_userinfo() {
        let injected = SourceRef::GitUrl {
            url: "https://user:s3cr3t@example.com/org/repo.git".into(),
            git_ref: None,
        };
        assert_eq!(
            injected.source_form(),
            "git+https://***@example.com/org/repo.git"
        );
        let text = injected.validate().unwrap_err().to_string();
        assert!(!text.contains("s3cr3t"), "{text}");
        assert!(text.contains("'@'"), "{text}");
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

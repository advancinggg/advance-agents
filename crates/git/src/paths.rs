//! User-addressable paths of the user commit lane (ADR 2026-10-15, CONTRACT-247;
//! MODULE-003-AC-36).
//!
//! Validation is shared-types `workspace_path`, the one grammar the Client API `files`
//! family, the fs core and this lane accept: NFC; no Cc and no bidi controls (ZWJ, ZWNJ and
//! U+00AD stay legal); ≤ 1024 bytes, ≤ 255 bytes per component, ≤ 32 components. A path
//! whose class is not Normal is refused: Private and Junk names (`.git`, `.meta.yaml`,
//! `.runtime`, `*.sqlite*`, …) are never addressable, and ReadOnly ones (`.agent/**`,
//! `.gitignore`, `.gitattributes`, `.gitmodules`) are never written by the user.
//!
//! A [`RepoPath`] keeps the spelling it was given (the on-disk name the provider resolved)
//! next to its NFC form; the worker stores the NFC form in the tree iff
//! `core.precomposeunicode`, else the given bytes (on APFS `init` sets it to `true`).

#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::arithmetic_side_effects
)]

use advance_shared_types::workspace_path::{
    classify_lexical, normalize_workspace_path, to_nfc, AccessClass, META_SIDECAR_NAME,
};

use crate::error::UserOpRefusal;

/// A user-addressable path (or the vault root, see [`RepoPath::root`]).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RepoPath {
    given: String,
    nfc: String,
}

impl RepoPath {
    /// Validate a user path: `normalize_workspace_path(given, false)` must succeed
    /// (otherwise [`UserOpRefusal::InvalidPath`]) and the path must classify Normal
    /// (Private or Junk → [`UserOpRefusal::PrivatePath`], ReadOnly →
    /// [`UserOpRefusal::ReadOnlyPath`]). The given spelling is kept.
    pub fn parse(given: &str) -> Result<Self, UserOpRefusal> {
        let nfc = normalize_workspace_path(given, false).map_err(|_| UserOpRefusal::InvalidPath)?;
        match classify_lexical(&nfc).access {
            AccessClass::Normal => Ok(Self {
                given: given.to_string(),
                nfc,
            }),
            AccessClass::ReadOnly(_) => Err(UserOpRefusal::ReadOnlyPath),
            AccessClass::Private { .. } | AccessClass::Junk { .. } => {
                Err(UserOpRefusal::PrivatePath)
            }
        }
    }

    /// Validate a runtime-maintained `<dir>/.meta.yaml` (or the root `.meta.yaml`): the
    /// lexical rules, a last component that is exactly `.meta.yaml`, and a directory part
    /// that classifies Normal (a sidecar inside `.agent/**` → `ReadOnlyPath`). Anything
    /// else is [`UserOpRefusal::InvalidPath`].
    pub fn parse_sidecar(given: &str) -> Result<Self, UserOpRefusal> {
        let nfc = normalize_workspace_path(given, false).map_err(|_| UserOpRefusal::InvalidPath)?;
        let (dir, name) = match nfc.rsplit_once('/') {
            Some((dir, name)) => (dir, name),
            None => ("", nfc.as_str()),
        };
        if name != META_SIDECAR_NAME {
            return Err(UserOpRefusal::InvalidPath);
        }
        match classify_lexical(dir).access {
            AccessClass::Normal => Ok(Self {
                given: given.to_string(),
                nfc,
            }),
            AccessClass::ReadOnly(_) => Err(UserOpRefusal::ReadOnlyPath),
            AccessClass::Private { .. } | AccessClass::Junk { .. } => {
                Err(UserOpRefusal::PrivatePath)
            }
        }
    }

    /// The vault root (`""`): valid only as a `PrepareTarget::Tree` or a whole-vault scope.
    pub fn root() -> Self {
        Self {
            given: String::new(),
            nfc: String::new(),
        }
    }

    /// The spelling the caller gave (the on-disk name).
    pub fn given(&self) -> &str {
        &self.given
    }

    /// The NFC form (API, events, journal records).
    pub fn nfc(&self) -> &str {
        &self.nfc
    }

    /// `true` for [`RepoPath::root`].
    pub fn is_root(&self) -> bool {
        self.nfc.is_empty()
    }

    /// `true` when the last component is `.meta.yaml` (only [`RepoPath::parse_sidecar`]
    /// produces one).
    pub fn is_sidecar(&self) -> bool {
        self.nfc
            .rsplit('/')
            .next()
            .is_some_and(|name| name == META_SIDECAR_NAME)
    }

    /// The spelling stored in trees and in the index: NFC iff `precompose`
    /// (`core.precomposeunicode`), otherwise the given bytes.
    pub(crate) fn tree_spelling(&self, precompose: bool) -> &str {
        if precompose {
            &self.nfc
        } else {
            &self.given
        }
    }
}

/// The collision fold used under `core.ignorecase` (MODULE-003-AC-36): `NFC(path)`, lowercased
/// per scalar. Canonically equivalent spellings and case variants fold equal; compatibility
/// forms (`Ａ` vs `A`) do not.
pub(crate) fn collision_fold(path: &str) -> String {
    to_nfc(path).to_lowercase()
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;

    #[test]
    fn repo_path_accepts_real_names() {
        let family = "notes/👨\u{200D}👩\u{200D}👧 family.md";
        assert_eq!(RepoPath::parse(family).unwrap().nfc(), family);
        let persian = "می\u{200C}خواهم.md";
        assert_eq!(RepoPath::parse(persian).unwrap().nfc(), persian);
        assert!(RepoPath::parse("a\u{00AD}b.md").is_ok());
        // A 600-byte CJK path: components of 240 + 240 + 120 bytes.
        let cjk = format!(
            "{}/{}/{}",
            "周".repeat(80),
            "报".repeat(80),
            "记".repeat(40)
        );
        assert_eq!(cjk.len(), 602);
        assert!(RepoPath::parse(&cjk).is_ok());
        // 255-byte names and 32 components (MODULE-003-AC-36: depth 32).
        assert!(RepoPath::parse(&"n".repeat(255)).is_ok());
        let deep = vec!["d"; 32].join("/");
        assert!(RepoPath::parse(&deep).is_ok());
        // Dotfiles other than the protected names are Normal.
        assert!(RepoPath::parse(".obsidian/workspace.json").is_ok());
        assert!(RepoPath::parse(".env").is_ok());
        // The given spelling is kept next to the NFC form.
        let nfd = "notes/cafe\u{301}.md";
        let path = RepoPath::parse(nfd).unwrap();
        assert_eq!(path.given(), nfd);
        assert_eq!(path.nfc(), "notes/caf\u{e9}.md");
        assert!(!path.is_root());
        assert!(!path.is_sidecar());
    }

    #[test]
    fn repo_path_refuses() {
        for private in [
            ".git/x",
            "a/.GIT/x",
            ".runtime/x",
            "x.sqlite-wal",
            ".meta.yaml",
        ] {
            assert_eq!(
                RepoPath::parse(private),
                Err(UserOpRefusal::PrivatePath),
                "{private:?}"
            );
        }
        for read_only in [".agent/x", ".gitignore", "a/.gitattributes"] {
            assert_eq!(
                RepoPath::parse(read_only),
                Err(UserOpRefusal::ReadOnlyPath),
                "{read_only:?}"
            );
        }
        let too_long = "a".repeat(1025);
        let long_name = "n".repeat(256);
        let too_deep = vec!["d"; 33].join("/");
        for invalid in [
            "a\u{202E}b",
            "a\u{FEFF}b",
            "a\rb",
            too_long.as_str(),
            long_name.as_str(),
            too_deep.as_str(),
            "",
            "/abs",
            "a/../b",
            "dir/",
        ] {
            assert_eq!(
                RepoPath::parse(invalid),
                Err(UserOpRefusal::InvalidPath),
                "{invalid:?}"
            );
        }

        let sidecar = RepoPath::parse_sidecar("d/.meta.yaml").unwrap();
        assert!(sidecar.is_sidecar());
        assert_eq!(sidecar.nfc(), "d/.meta.yaml");
        assert!(RepoPath::parse_sidecar(".meta.yaml").unwrap().is_sidecar());
        assert_eq!(
            RepoPath::parse_sidecar("d/x.md"),
            Err(UserOpRefusal::InvalidPath)
        );
        assert_eq!(
            RepoPath::parse_sidecar("d/.META.yaml"),
            Err(UserOpRefusal::InvalidPath)
        );
        assert_eq!(
            RepoPath::parse_sidecar(".agent/.meta.yaml"),
            Err(UserOpRefusal::ReadOnlyPath)
        );
        assert_eq!(
            RepoPath::parse_sidecar(".runtime/.meta.yaml"),
            Err(UserOpRefusal::PrivatePath)
        );

        let root = RepoPath::root();
        assert!(root.is_root());
        assert_eq!(root.nfc(), "");
        assert!(!root.is_sidecar());
    }

    #[test]
    fn tree_spelling_follows_precompose() {
        let nfd = "笔记/cafe\u{301}.md";
        let path = RepoPath::parse(nfd).unwrap();
        assert_eq!(path.tree_spelling(true), "笔记/caf\u{e9}.md");
        assert_eq!(path.tree_spelling(false).as_bytes(), nfd.as_bytes());
        let nfc = RepoPath::parse("笔记/caf\u{e9}.md").unwrap();
        assert_eq!(nfc.tree_spelling(false), nfc.tree_spelling(true));
    }

    #[test]
    fn collision_fold() {
        assert_eq!(
            super::collision_fold("Notes.md"),
            super::collision_fold("notes.md")
        );
        assert_eq!(super::collision_fold("Ä.md"), super::collision_fold("ä.md"));
        assert_eq!(
            super::collision_fold("a\u{308}.md"),
            super::collision_fold("\u{e4}.md")
        );
        assert_eq!(
            super::collision_fold("Dir/Sub/File.MD"),
            super::collision_fold("dir/sub/file.md")
        );
        assert_ne!(
            super::collision_fold("Ａ.md"),
            super::collision_fold("A.md")
        );
        assert_ne!(super::collision_fold("a.md"), super::collision_fold("b.md"));
    }
}

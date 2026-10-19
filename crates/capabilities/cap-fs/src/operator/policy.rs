//! Lexical create grammar, physical classes, H1 stored-name reclassify,
//! and per-operation predicates (INTEGRATED §3.6, oss-fs-core §2.2–§2.4).

use advance_shared_types::workspace_path::{
    classify_component, is_agent_dir_name, policy_skeleton, portable_name_key, AccessClass,
    ComponentClass, PathClassifier, PathDefect, ReadOnlyReason,
};
use unicode_normalization::UnicodeNormalization;

/// Subtree class: applies to the node and every descendant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubtreeClass {
    Hidden,
    Junk,
    AgentSystem,
    ForeignRepo,
    MountPoint,
    Symlink,
    Special,
    Normal,
}

/// Node self-protection: applies to the node only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeProtection {
    WorkspaceRoot,
    TerritoryRoot,
    VcsControl,
    Locked,
    Unversionable,
}

/// Combined physical facts used by the per-operation predicates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PhysicalFacts {
    pub subtree: SubtreeClass,
    pub protection: Option<NodeProtection>,
}

impl PhysicalFacts {
    pub const fn workspace_root() -> Self {
        Self {
            subtree: SubtreeClass::Normal,
            protection: Some(NodeProtection::WorkspaceRoot),
        }
    }

    pub const fn territory_root() -> Self {
        Self {
            subtree: SubtreeClass::Normal,
            protection: Some(NodeProtection::TerritoryRoot),
        }
    }

    pub const fn inner_territory() -> Self {
        Self {
            subtree: SubtreeClass::Normal,
            protection: None,
        }
    }

    pub const fn agent_system() -> Self {
        Self {
            subtree: SubtreeClass::AgentSystem,
            protection: None,
        }
    }

    pub const fn foreign_repo() -> Self {
        Self {
            subtree: SubtreeClass::ForeignRepo,
            protection: None,
        }
    }

    pub const fn mount_point() -> Self {
        Self {
            subtree: SubtreeClass::MountPoint,
            protection: None,
        }
    }

    /// Workspace root and territory roots stay child-writable; their subtree is Normal.
    pub const fn is_child_writable(self) -> bool {
        matches!(self.subtree, SubtreeClass::Normal)
    }
}

/// User-facing operations the predicates cover.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilesOp {
    Read,
    EditInPlace,
    CreateIn,
    Delete,
    MoveSource,
    MkdirIn,
}

/// Whether `op` is allowed against `facts` (oss-fs-core §2.3 table).
pub fn allows(op: FilesOp, facts: PhysicalFacts) -> bool {
    match op {
        FilesOp::Read => !matches!(facts.subtree, SubtreeClass::Hidden | SubtreeClass::Junk),
        FilesOp::EditInPlace => {
            facts.subtree == SubtreeClass::Normal
                && !matches!(
                    facts.protection,
                    Some(
                        NodeProtection::VcsControl
                            | NodeProtection::Locked
                            | NodeProtection::Unversionable
                            | NodeProtection::WorkspaceRoot
                    )
                )
        }
        FilesOp::CreateIn | FilesOp::MkdirIn => facts.is_child_writable(),
        FilesOp::Delete | FilesOp::MoveSource => {
            facts.subtree == SubtreeClass::Normal
                && !matches!(
                    facts.protection,
                    Some(
                        NodeProtection::WorkspaceRoot
                            | NodeProtection::TerritoryRoot
                            | NodeProtection::Locked
                    )
                )
        }
    }
}

/// Why a create-target name is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateRefusal {
    Defect(PathDefect),
    ReadOnly(ReadOnlyReason),
}

/// Create grammar on the final component (INTEGRATED §3.6 / F §2.2).
///
/// Refuses `.agent`, `_scope`, `:`, leading/trailing whitespace, Junk, VcsControl,
/// Private (`.~advance-*`, …). Sibling portable-key collisions are
/// [`portable_keys_collide`] — they need the sibling set.
pub fn check_create_name(name: &str) -> Result<(), CreateRefusal> {
    if name.is_empty()
        || name != name.trim()
        || name.chars().all(char::is_whitespace)
        || name.contains(':')
        || is_scope_name(name)
        || is_agent_dir_name(name)
    {
        return Err(CreateRefusal::Defect(PathDefect::CreateGrammar));
    }
    match classify_component(name, false) {
        ComponentClass::Private => Err(CreateRefusal::Defect(PathDefect::ReservedName)),
        ComponentClass::Junk => Err(CreateRefusal::Defect(PathDefect::JunkName)),
        ComponentClass::ReadOnly(reason) => Err(CreateRefusal::ReadOnly(reason)),
        ComponentClass::Normal => Ok(()),
    }
}

fn is_scope_name(name: &str) -> bool {
    name == "_scope" || policy_skeleton(name) == "_scope"
}

/// Portable sibling-collision key equality (`nfc(full_casefold(name))`).
pub fn portable_keys_collide(a: &str, b: &str) -> bool {
    portable_name_key(a) == portable_name_key(b)
}

/// NFC of a stored (on-disk) name. Used when comparing readdir spellings.
pub fn stored_nfc(name: &str) -> String {
    name.nfc().collect()
}

/// H1: the **stored** spelling, not the lookup spelling, drives the class.
///
/// Identity aliases (Linux casefold, vfat 8.3, Apple `F_GETPATH`) can open a
/// protected inode under a lookup name that would classify as Normal. The
/// walk re-classifies every opened component from the stored name taken by a
/// readdir `d_ino` match (or `F_GETPATH` on Apple).
pub fn classify_h1(lookup_name: &str, stored_name: &str, parent_is_agent: bool) -> ComponentClass {
    let _ = lookup_name;
    classify_component(stored_name, parent_is_agent)
}

/// Classify a path from **stored** component spellings (physical walk).
///
/// A directory named `.gitignore` / `.gitattributes` / `.gitmodules` makes
/// its subtree `ReadOnly(VcsControl)` — most-restrictive wins, matching
/// lexical `PathClassifier` (OSS-1 Q1).
pub fn classify_stored_path(stored_components: &[&str]) -> AccessClass {
    let mut classifier = PathClassifier::new();
    for name in stored_components {
        classifier.push(name);
    }
    classifier.class().access
}

/// After opening a VcsControl **directory**, descendants stay ReadOnly(VcsControl).
pub fn vcs_control_directory_covers_descendants(dir_stored_name: &str, descendant: &str) -> bool {
    matches!(
        classify_component(dir_stored_name, false),
        ComponentClass::ReadOnly(ReadOnlyReason::VcsControl)
    ) && matches!(
        classify_stored_path(&[dir_stored_name, descendant]),
        AccessClass::ReadOnly(ReadOnlyReason::VcsControl)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_grammar_reserved_names() {
        for name in [
            ".agent",
            "_scope",
            "a:b",
            " leading",
            "trailing ",
            "   ",
            ".~advance-x",
            ".DS_Store",
            ".gitignore",
            ".gitattributes",
            ".gitmodules",
        ] {
            assert!(
                check_create_name(name).is_err(),
                "{name:?} must be refused by the create grammar"
            );
        }
        assert_eq!(
            check_create_name(".agent"),
            Err(CreateRefusal::Defect(PathDefect::CreateGrammar))
        );
        assert_eq!(
            check_create_name("_scope"),
            Err(CreateRefusal::Defect(PathDefect::CreateGrammar))
        );
        assert_eq!(
            check_create_name(".~advance-x"),
            Err(CreateRefusal::Defect(PathDefect::ReservedName))
        );
        assert_eq!(
            check_create_name(".DS_Store"),
            Err(CreateRefusal::Defect(PathDefect::JunkName))
        );
        assert_eq!(
            check_create_name(".gitignore"),
            Err(CreateRefusal::ReadOnly(ReadOnlyReason::VcsControl))
        );
        assert_eq!(check_create_name("notes.md"), Ok(()));
        assert_eq!(check_create_name(".obsidian"), Ok(()));
    }

    #[test]
    fn portable_key_collisions() {
        assert!(portable_keys_collide("A.md", "a.md"));
        assert!(portable_keys_collide("Straße.md", "STRASSE.md"));
        assert!(!portable_keys_collide("A.md", "B.md"));
        assert_eq!(
            portable_name_key("A.md"),
            portable_name_key("a.md"),
            "portable key is nfc(full_casefold(name))"
        );
    }

    #[test]
    fn junk_includes_tempfile_pattern() {
        assert_eq!(
            classify_component(".tmpAbc123", false),
            ComponentClass::Junk
        );
        assert_eq!(
            check_create_name(".tmpAbc123"),
            Err(CreateRefusal::Defect(PathDefect::JunkName))
        );
        assert_ne!(
            classify_component(".tmpAb12", false),
            ComponentClass::Junk,
            "tempfile pattern is exactly .tmp + 6 ASCII alphanumerics"
        );
    }

    #[test]
    fn vcs_control_directory_is_subtree_readonly() {
        assert_eq!(
            classify_stored_path(&[".gitignore", "x"]),
            AccessClass::ReadOnly(ReadOnlyReason::VcsControl)
        );
        assert_eq!(
            classify_stored_path(&[".gitattributes", "nested", "file"]),
            AccessClass::ReadOnly(ReadOnlyReason::VcsControl)
        );
        assert_eq!(
            classify_stored_path(&[".gitmodules", "src"]),
            AccessClass::ReadOnly(ReadOnlyReason::VcsControl)
        );
        assert!(vcs_control_directory_covers_descendants(".gitignore", "x"));
        assert_eq!(classify_stored_path(&["notes", "x"]), AccessClass::Normal);
    }

    #[test]
    fn h1_stored_name_reclassifies_protected_aliases() {
        assert_eq!(
            classify_component("notes", false),
            ComponentClass::Normal,
            "lookup spelling alone would be Normal"
        );
        assert_eq!(
            classify_h1("notes", ".git", false),
            ComponentClass::Private,
            "H1: stored spelling drives class"
        );
        assert_eq!(classify_h1("GIT~1", ".git", false), ComponentClass::Private);
        assert_eq!(
            classify_h1("notes.sqlite", "notes.md", false),
            ComponentClass::Normal
        );
        assert_eq!(
            classify_h1("notes.md", "notes.sqlite", false),
            ComponentClass::Private
        );
        assert_eq!(
            classify_h1("visible", ".gitignore", false),
            ComponentClass::ReadOnly(ReadOnlyReason::VcsControl)
        );
        assert_eq!(
            classify_h1("_draft", "_draft", true),
            ComponentClass::Private
        );
    }

    #[test]
    fn per_operation_predicates_table() {
        let root = PhysicalFacts::workspace_root();
        let territory = PhysicalFacts::territory_root();
        let inner = PhysicalFacts::inner_territory();
        let agent = PhysicalFacts::agent_system();
        let foreign = PhysicalFacts::foreign_repo();
        let mount = PhysicalFacts::mount_point();

        assert!(allows(FilesOp::CreateIn, root), "root is child-writable");
        assert!(allows(FilesOp::MkdirIn, root));
        assert!(!allows(FilesOp::Delete, root));
        assert!(!allows(FilesOp::MoveSource, root));
        assert!(!allows(FilesOp::EditInPlace, root));

        assert!(
            allows(FilesOp::CreateIn, territory),
            "territory root is child-writable"
        );
        assert!(!allows(FilesOp::Delete, territory));
        assert!(!allows(FilesOp::MoveSource, territory));

        assert!(
            allows(FilesOp::EditInPlace, inner),
            "inner territory stays editable"
        );
        assert!(allows(FilesOp::CreateIn, inner));
        assert!(allows(FilesOp::Delete, inner));

        for blocked in [agent, foreign, mount] {
            assert!(
                !allows(FilesOp::EditInPlace, blocked),
                "{blocked:?} is not writable"
            );
            assert!(!allows(FilesOp::CreateIn, blocked));
            assert!(!allows(FilesOp::Delete, blocked));
            assert!(!allows(FilesOp::MkdirIn, blocked));
        }
        assert!(allows(FilesOp::Read, agent));
        assert!(allows(FilesOp::Read, foreign));
        assert!(allows(FilesOp::Read, mount));
    }

    #[test]
    fn stored_nfc_composes() {
        assert_eq!(stored_nfc("Cafe\u{301}"), "Café");
    }
}

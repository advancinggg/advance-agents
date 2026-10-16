//! Workspace path policy for the operator `files` family (ADR 2026-10-15 vault files;
//! CONTRACT-246; MODULE-002 §1.4.3 hidden set; MODULE-020 §2.8 detail-token registry).
//!
//! One lexical validator and one classifier shared by every layer that names a vault path:
//! client-api's `FilesPath` gate, advance-git's `RepoPath` (the user commit lane, CONTRACT-247)
//! and the cap-fs operator core, which re-applies [`classify_component`] to every on-disk
//! component of its fd walk (through [`PathClassifier`]). Pure functions: nothing here touches
//! the disk.
//!
//! - [`normalize_workspace_path`]: NFC, then the lexical rules (no leading or trailing `/`, no
//!   empty, `.` or `..` component, no `\`, no Cc, no bidi or deprecated format control; ZWJ and
//!   ZWNJ stay legal; ≤ [`MAX_WORKSPACE_PATH_BYTES`], ≤ [`MAX_WORKSPACE_NAME_BYTES`] per
//!   component, ≤ [`MAX_WORKSPACE_DEPTH`] components).
//! - [`policy_skeleton`]: the comparison form of a name. Case variants (`.GIT`), APFS case
//!   folding (`.ſub`, the Kelvin sign), compatibility forms (`．ｇｉｔ`, ligatures), decorated
//!   look-alikes (`.gït`) and HFS+-ignorable aliases (`.g\u{200D}it`) of a protected name classify
//!   like the name itself.
//! - [`classify_component`] / [`classify_lexical`] / [`PathClassifier`]: Private, Junk,
//!   ReadOnly(AgentSystem | VcsControl) or Normal per component skeleton, matched without trailing
//!   dots and spaces (FAT, exFAT and NTFS ignore them on lookup, so `x.sqlite.` can open
//!   `x.sqlite`); the most restrictive component wins.
//! - [`gate`]: the lexical answer per [`PathUse`]: Private and Junk read as
//!   absent, create targets get `invalid_path reason:reserved_name|junk_name`, ReadOnly writes get
//!   `read_only reason:<r>`.
//! - [`portable_name_key`]: `nfc(full_casefold(name))`, the sibling-collision key of the fs core's
//!   create grammar.
//! - [`is_dotfile_name`]: the per-entry `dotfile` flag; [`to_nfc`]: the one NFC normalizer for
//!   names read from disk and for free text such as search queries.
//!
//! The physical gate (fd-relative walk with `O_NOFOLLOW`, `(st_dev, st_ino)` alias identity
//! against [`PROTECTED_ROOT_NAMES`] / [`PROTECTED_ANY_LEVEL_NAMES`], `F_GETPATH` on Apple, mount
//! points) is normative and lives in the fs core; this module is its lexical half. Rendering of the
//! wire details (`invalid_path`, `read_only`, `not_found`) belongs to client-api; the reason tokens
//! are defined here so every layer speaks one vocabulary.
//!
//! Some aliases are not lexical, and only the physical gate's re-classification of every
//! component *as stored on disk* closes them: APFS's full folding of `ß`/`ẞ` to `ss` (no protected
//! name contains `ss`, which a test guards) and, off Apple, Linux casefold directories, which drop
//! every Default_Ignorable code point (U+200B, U+00AD, U+2060, …), and vfat 8.3 short names. The
//! identity checks cover only the protected names and `F_GETPATH` exists only on Apple, so on other
//! hosts the stored name of an opened component comes from a readdir `d_ino` match.

use std::fmt;

use icu_properties::props::GeneralCategory;
use icu_properties::{CodePointMapData, CodePointMapDataBorrowed};
use unicode_normalization::{is_nfc_quick, IsNormalized, UnicodeNormalization};

/// Maximum UTF-8 length of a workspace path after NFC.
pub const MAX_WORKSPACE_PATH_BYTES: usize = 1024;

/// Maximum UTF-8 length of one path component after NFC.
pub const MAX_WORKSPACE_NAME_BYTES: usize = 255;

/// Maximum number of components (matches cap-fs `MAX_PATH_DEPTH`, MODULE-002 §2.11).
pub const MAX_WORKSPACE_DEPTH: usize = 32;

/// NFC shrinks UTF-8 at most 3.5× (U+1FBE U+0308 U+0301, 7 bytes, composes into the 2-byte
/// U+0390; a Hangul L+V+T jamo triple shrinks 3×), so a raw input above this bound can never
/// normalize to a legal path. It is refused before normalization to bound the work spent on
/// hostile input; a bound below 3.5 × [`MAX_WORKSPACE_PATH_BYTES`] would refuse legal paths.
const MAX_RAW_PATH_BYTES: usize = 4 * MAX_WORKSPACE_PATH_BYTES;

/// The runtime-maintained per-directory sidecar (Private at any depth).
pub const META_SIDECAR_NAME: &str = ".meta.yaml";

/// An agent territory's system directory (ReadOnly(AgentSystem); its `_`-prefixed children are
/// Private).
pub const AGENT_DIR_NAME: &str = ".agent";

/// Names whose on-disk identity the fs core compares with every component it opens directly
/// below the workspace root: a component with the same `(st_dev, st_ino)`
/// takes that name's class whatever its spelling.
pub const PROTECTED_ROOT_NAMES: &[&str] = &[
    ".git",
    ".agent",
    ".advance",
    ".runtime",
    ".sub",
    ".triggers",
];

/// Names whose on-disk identity the fs core compares at every level of its walk.
pub const PROTECTED_ANY_LEVEL_NAMES: &[&str] = &[".git", ".agent"];

/// The repository directory and its 8.3 short name (libgit2 refuses both, `verify_dotgit_ntfs`):
/// Private at any depth.
const DOT_GIT_NAMES: &[&str] = &[".git", "git~1"];

/// Exact skeletons that are Private at any depth.
const PRIVATE_NAMES: &[&str] = &[".meta.yaml", ".runtime", ".advance", ".triggers", ".sub"];

/// Skeleton suffixes that are Private at any depth (SQLite databases and their side files).
const PRIVATE_SUFFIXES: &[&str] = &[".sqlite", ".sqlite-wal", ".sqlite-shm", ".sqlite-journal"];

/// Skeleton prefix of the files core's own scratch names.
const PRIVATE_PREFIX: &str = ".~advance-";

/// Exact skeletons of OS and editor litter (Junk at any depth).
const JUNK_NAMES: &[&str] = &[
    ".ds_store",
    ".localized",
    ".spotlight-v100",
    ".trashes",
    ".fseventsd",
    ".temporaryitems",
    ".documentrevisions-v100",
    "thumbs.db",
    "desktop.ini",
];

/// Skeleton prefixes of OS and editor litter: AppleDouble files and Office owner files.
const JUNK_PREFIXES: &[&str] = &["._", "~$"];

/// LibreOffice lock files: this prefix, then anything, then a final `#`.
const LOCK_FILE_PREFIX: &str = ".~lock.";

/// The `tempfile` crate's default name: this prefix and 6 ASCII alphanumerics.
const TEMPFILE_PREFIX: &str = ".tmp";

/// Skeletons that change what or how the vault repository records (ReadOnly(VcsControl) at every
/// depth, root included).
const VCS_CONTROL_NAMES: &[&str] = &[".gitignore", ".gitattributes", ".gitmodules"];

/// General_Category lookups for the skeleton's mark filter (compiled ICU4X data).
const GENERAL_CATEGORY: CodePointMapDataBorrowed<'static, GeneralCategory> =
    CodePointMapData::<GeneralCategory>::new();

/// Why a path or name is refused: rendered as `invalid_path reason:<r>` (the CONTRACT-246
/// detail-token registry, MODULE-020 §2.8).
///
/// [`normalize_workspace_path`] produces the first seven. [`gate`] produces `ReservedName` and
/// `JunkName` for create targets whose final component is Private or Junk. `CreateGrammar` is the
/// fs core's create-grammar refusal (`.agent`, `_scope`, `:`, leading or trailing whitespace).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PathDefect {
    /// A leading or trailing `/`, an empty component, or a `\`.
    Syntax,
    /// A `.` or `..` component.
    Traversal,
    /// A Cc character (NUL included) or a refused bidi / deprecated format control.
    ControlChar,
    /// More than [`MAX_WORKSPACE_PATH_BYTES`] after NFC.
    TooLong,
    /// More than [`MAX_WORKSPACE_DEPTH`] components.
    TooDeep,
    /// A component longer than [`MAX_WORKSPACE_NAME_BYTES`] after NFC.
    NameTooLong,
    /// The empty path where the root is not accepted.
    Missing,
    /// A create target whose final component is Private.
    ReservedName,
    /// A create target whose final component is Junk.
    JunkName,
    /// A create target refused by the fs core's create grammar.
    CreateGrammar,
}

impl PathDefect {
    /// Every defect, in registry order.
    pub const ALL: [PathDefect; 10] = [
        PathDefect::Syntax,
        PathDefect::Traversal,
        PathDefect::ControlChar,
        PathDefect::TooLong,
        PathDefect::TooDeep,
        PathDefect::NameTooLong,
        PathDefect::Missing,
        PathDefect::ReservedName,
        PathDefect::JunkName,
        PathDefect::CreateGrammar,
    ];

    /// The `reason:<r>` token value.
    pub const fn reason(self) -> &'static str {
        match self {
            PathDefect::Syntax => "syntax",
            PathDefect::Traversal => "traversal",
            PathDefect::ControlChar => "control_char",
            PathDefect::TooLong => "too_long",
            PathDefect::TooDeep => "too_deep",
            PathDefect::NameTooLong => "name_too_long",
            PathDefect::Missing => "missing",
            PathDefect::ReservedName => "reserved_name",
            PathDefect::JunkName => "junk_name",
            PathDefect::CreateGrammar => "create_grammar",
        }
    }
}

impl fmt::Display for PathDefect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.reason())
    }
}

impl std::error::Error for PathDefect {}

/// Why a listed path is read-only: rendered as `read_only reason:<r>` (the CONTRACT-246
/// detail-token registry, MODULE-020 §2.8).
///
/// Lexical classification only yields `AgentSystem` and `VcsControl`. The others are the fs
/// core's physical reasons; they live here so every layer renders one vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReadOnlyReason {
    /// Inside an `.agent` directory (edited through the agents family).
    AgentSystem,
    /// `.gitignore`, `.gitattributes` or `.gitmodules`.
    VcsControl,
    /// A territory root (a directory holding `.agent`) cannot be moved or deleted.
    TerritoryRoot,
    /// A recursive operation would carry a territory root.
    ContainsTerritory,
    /// Inside a nested repository (a directory holding `.git`).
    ForeignRepo,
    /// A recursive operation would carry a nested repository.
    ContainsForeignRepo,
    /// A recursive operation would carry runtime state (`.runtime`, `.advance`, `.triggers`,
    /// `.sub`).
    ContainsRuntimeState,
    /// Below a mount point (a child whose `st_dev` differs from its parent's).
    MountPoint,
    /// macOS immutable or append-only flags.
    Locked,
    /// The file system refused the operation.
    Permission,
    /// The volume is mounted read-only.
    ReadOnlyVolume,
    /// A symbolic link (never followed).
    Symlink,
    /// A FIFO, socket or device.
    Special,
    /// Two on-disk names share one NFC spelling.
    AmbiguousName,
    /// An existing name libgit2 would refuse.
    Unversionable,
}

impl ReadOnlyReason {
    /// Every reason, in registry order.
    pub const ALL: [ReadOnlyReason; 15] = [
        ReadOnlyReason::AgentSystem,
        ReadOnlyReason::VcsControl,
        ReadOnlyReason::TerritoryRoot,
        ReadOnlyReason::ContainsTerritory,
        ReadOnlyReason::ForeignRepo,
        ReadOnlyReason::ContainsForeignRepo,
        ReadOnlyReason::ContainsRuntimeState,
        ReadOnlyReason::MountPoint,
        ReadOnlyReason::Locked,
        ReadOnlyReason::Permission,
        ReadOnlyReason::ReadOnlyVolume,
        ReadOnlyReason::Symlink,
        ReadOnlyReason::Special,
        ReadOnlyReason::AmbiguousName,
        ReadOnlyReason::Unversionable,
    ];

    /// The `reason:<r>` token value.
    pub const fn reason(self) -> &'static str {
        match self {
            ReadOnlyReason::AgentSystem => "agent_system",
            ReadOnlyReason::VcsControl => "vcs_control",
            ReadOnlyReason::TerritoryRoot => "territory_root",
            ReadOnlyReason::ContainsTerritory => "contains_territory",
            ReadOnlyReason::ForeignRepo => "foreign_repo",
            ReadOnlyReason::ContainsForeignRepo => "contains_foreign_repo",
            ReadOnlyReason::ContainsRuntimeState => "contains_runtime_state",
            ReadOnlyReason::MountPoint => "mount_point",
            ReadOnlyReason::Locked => "locked",
            ReadOnlyReason::Permission => "permission",
            ReadOnlyReason::ReadOnlyVolume => "read_only_volume",
            ReadOnlyReason::Symlink => "symlink",
            ReadOnlyReason::Special => "special",
            ReadOnlyReason::AmbiguousName => "ambiguous_name",
            ReadOnlyReason::Unversionable => "unversionable",
        }
    }
}

/// The class of one name, decided on its [`policy_skeleton`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ComponentClass {
    /// Listed, readable and writable (dotfiles such as `.obsidian` and `.env` included).
    Normal,
    /// Listed and readable, never written by user operations.
    ReadOnly(ReadOnlyReason),
    /// Runtime-private state: never listed, read, written or committed by user operations.
    Private,
    /// OS and editor litter: never listed or committed; reads answer `not_found`.
    Junk,
}

/// The class of a path: the most restrictive component wins
/// (Private > Junk > ReadOnly(AgentSystem) > ReadOnly(VcsControl) > Normal).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AccessClass {
    /// Every component is Normal.
    Normal,
    /// Some component is read-only and none is Private or Junk.
    ReadOnly(ReadOnlyReason),
    /// Some component is Private. `at_final`: only the final component is hidden (no ancestor
    /// is Private or Junk), so a create target there is a reserved name rather than a missing
    /// parent.
    Private { at_final: bool },
    /// Some component is Junk and none is Private. `at_final` as for `Private`.
    Junk { at_final: bool },
}

impl AccessClass {
    /// `true` for Private and Junk: never listed, and every use answers as if absent.
    pub fn is_hidden(self) -> bool {
        matches!(self, AccessClass::Private { .. } | AccessClass::Junk { .. })
    }
}

/// Lexical facts about a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PathClass {
    /// Private / Junk / ReadOnly / Normal.
    pub access: AccessClass,
    /// Some component, as given (not its skeleton), starts with `.`: the path is a dot entry or
    /// lies inside one (`.env`, `.obsidian/workspace.json`). This is a path fact; a listed entry's
    /// own `dotfile` flag is [`is_dotfile_name`] of its name, so the children of `.obsidian` are
    /// not dotfiles.
    pub in_dot_path: bool,
}

/// NFC-normalize, then validate lexically.
///
/// `""` is the workspace root and is accepted only when `allow_root`. Checks run in this order
/// and the first failure wins:
///
/// 1. `""` → root or [`PathDefect::Missing`]; a raw input over 4 KiB → [`PathDefect::TooLong`]
///    before normalizing (NFC shrinks at most 3.5×, so nothing that could fit is refused);
/// 2. NFC; more than [`MAX_WORKSPACE_PATH_BYTES`] → [`PathDefect::TooLong`];
/// 3. in string order, `\` → [`PathDefect::Syntax`]; a Cc character or U+061C, U+200E, U+200F,
///    U+202A–U+202E, U+2066–U+2069, U+206A–U+206F, U+FEFF → [`PathDefect::ControlChar`]
///    (ZWJ U+200D and ZWNJ U+200C are legal: emoji sequences, Persian, Indic scripts);
/// 4. a leading or trailing `/` → [`PathDefect::Syntax`];
/// 5. per component, left to right: empty → [`PathDefect::Syntax`]; `.` or `..` →
///    [`PathDefect::Traversal`]; over [`MAX_WORKSPACE_NAME_BYTES`] → [`PathDefect::NameTooLong`];
///    the component past [`MAX_WORKSPACE_DEPTH`] → [`PathDefect::TooDeep`].
///
/// The result is the NFC path, the form every API path, event and journal record uses.
pub fn normalize_workspace_path(raw: &str, allow_root: bool) -> Result<String, PathDefect> {
    if raw.is_empty() {
        return if allow_root {
            Ok(String::new())
        } else {
            Err(PathDefect::Missing)
        };
    }
    if raw.len() > MAX_RAW_PATH_BYTES {
        return Err(PathDefect::TooLong);
    }
    let path = to_nfc(raw);
    if path.len() > MAX_WORKSPACE_PATH_BYTES {
        return Err(PathDefect::TooLong);
    }
    for c in path.chars() {
        if c == '\\' {
            return Err(PathDefect::Syntax);
        }
        if is_refused_char(c) {
            return Err(PathDefect::ControlChar);
        }
    }
    if path.starts_with('/') || path.ends_with('/') {
        return Err(PathDefect::Syntax);
    }
    for (index, component) in path.split('/').enumerate() {
        if component.is_empty() {
            return Err(PathDefect::Syntax);
        }
        if component == "." || component == ".." {
            return Err(PathDefect::Traversal);
        }
        if component.len() > MAX_WORKSPACE_NAME_BYTES {
            return Err(PathDefect::NameTooLong);
        }
        if index >= MAX_WORKSPACE_DEPTH {
            return Err(PathDefect::TooDeep);
        }
    }
    Ok(path)
}

/// The comparison form of one name for every policy decision, in order:
///
/// 1. strip the HFS+-ignorable code points U+200C–U+200F, U+202A–U+202E, U+206A–U+206F, U+FEFF
///    (the set libgit2 encodes for its HFS checks);
/// 2. NFKD;
/// 3. drop nonspacing marks (General_Category `Mn`; spacing and enclosing marks stay);
/// 4. per-scalar full lowercase mapping;
/// 5. map `ſ` (U+017F) to `s`;
/// 6. NFC.
///
/// The cost is that a few exotic names cannot be created and are hidden when found; only a name
/// whose skeleton is a protected name is affected. Emoji names keep their ZWJ on disk and on the
/// wire: the skeleton is only ever compared, never stored or returned.
pub fn policy_skeleton(name: &str) -> String {
    if name.is_ascii() {
        // ASCII has no ignorables, no compatibility forms and no marks.
        return name.to_ascii_lowercase();
    }
    let folded: String = name
        .chars()
        .filter(|c| !is_hfs_ignorable(*c))
        .nfkd()
        .filter(|c| GENERAL_CATEGORY.get(*c) != GeneralCategory::NonspacingMark)
        .flat_map(char::to_lowercase)
        .map(|c| if c == '\u{17F}' { 's' } else { c })
        .collect();
    folded.nfc().collect()
}

/// Classify one name on its [`policy_skeleton`]. `parent_is_agent` is whether the parent
/// directory's name is an [`AGENT_DIR_NAME`] (see [`is_agent_dir_name`]): its `_`-prefixed
/// children are Private.
///
/// Names are matched with the skeleton's trailing dots and spaces removed: FAT and exFAT ignore
/// trailing dots on lookup (Linux mounts included) and NTFS also ignores trailing spaces, so
/// `x.sqlite.` and `.gitignore ` can open `x.sqlite` and `.gitignore`. libgit2 refuses `.git` and
/// `git~1` spelled that way for the same reason (`verify_dotgit_ntfs`).
///
/// - Private: `.git` and `git~1`; `.meta.yaml`, `.runtime`, `.advance`, `.triggers`, `.sub`;
///   names ending in `.sqlite`, `.sqlite-wal`, `.sqlite-shm`, `.sqlite-journal`; names starting
///   with `.~advance-`.
/// - Junk: `.DS_Store`, `._*`, `.localized`, `.Spotlight-V100`, `.Trashes`, `.fseventsd`,
///   `.TemporaryItems`, `.DocumentRevisions-V100`, `Thumbs.db`, `desktop.ini`, `~$*`, `.~lock.*#`,
///   and the `tempfile` crate's default name `.tmp` + 6 ASCII alphanumerics (cap-fs
///   `atomic_write` leaves it next to `.meta.yaml` after a crash).
/// - ReadOnly(AgentSystem): `.agent`. ReadOnly(VcsControl): `.gitignore`, `.gitattributes`,
///   `.gitmodules`.
/// - Normal: everything else.
pub fn classify_component(name: &str, parent_is_agent: bool) -> ComponentClass {
    classify_stem(policy_stem(&policy_skeleton(name)), parent_is_agent)
}

/// `true` when `name` is an agent system directory: its skeleton, without trailing dots and
/// spaces, is [`AGENT_DIR_NAME`].
pub fn is_agent_dir_name(name: &str) -> bool {
    policy_stem(&policy_skeleton(name)) == AGENT_DIR_NAME
}

/// The `dotfile` flag of a listed entry (client-api's `ClientFileEntry.dotfile`): its own name
/// starts with `.` (`.obsidian`, `.env`). Clients hide such entries until the user shows hidden
/// files. Only the entry's name counts, so `workspace.json` inside `.obsidian` is not a dotfile;
/// [`PathClass::in_dot_path`] is the path fact.
pub fn is_dotfile_name(name: &str) -> bool {
    name.starts_with('.')
}

/// Classify a path that [`normalize_workspace_path`] accepted (`""` is the root: Normal). The
/// most restrictive component wins; never touches the disk.
pub fn classify_lexical(normalized: &str) -> PathClass {
    let mut classifier = PathClassifier::new();
    if !normalized.is_empty() {
        for component in normalized.split('/') {
            classifier.push(component);
        }
    }
    classifier.class()
}

/// Incremental [`classify_lexical`]: the fs core pushes each component as stored on disk while it
/// walks, so the physical gate classifies with exactly the lexical rules. Pushing every component
/// of a path yields the same [`PathClass`] as `classify_lexical` of that path.
#[derive(Debug, Clone, Default)]
pub struct PathClassifier {
    depth: usize,
    parent_is_agent: bool,
    /// Most restrictive hidden class among the components before the last one.
    hidden_ancestor: Option<Hidden>,
    last: Option<ComponentClass>,
    read_only: Option<ReadOnlyReason>,
    in_dot_path: bool,
}

/// Hidden classes, ordered by restrictiveness (Private wins).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Hidden {
    Junk,
    Private,
}

impl PathClassifier {
    /// A classifier positioned at the workspace root.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add the next component (any spelling: NFC, or the on-disk bytes as a `str`) and return
    /// its own class.
    pub fn push(&mut self, name: &str) -> ComponentClass {
        let skeleton = policy_skeleton(name);
        let stem = policy_stem(&skeleton);
        let class = classify_stem(stem, self.parent_is_agent);
        if let Some(previous) = self.last.and_then(hidden_of) {
            self.hidden_ancestor = Some(self.hidden_ancestor.map_or(previous, |h| h.max(previous)));
        }
        if let ComponentClass::ReadOnly(reason) = class {
            let keep = self
                .read_only
                .is_some_and(|current| read_only_rank(current) >= read_only_rank(reason));
            if !keep {
                self.read_only = Some(reason);
            }
        }
        self.parent_is_agent = stem == AGENT_DIR_NAME;
        self.in_dot_path |= is_dotfile_name(name);
        self.depth += 1;
        self.last = Some(class);
        class
    }

    /// The class of the path pushed so far (the root when nothing was pushed).
    pub fn class(&self) -> PathClass {
        let last_hidden = self.last.and_then(hidden_of);
        let access = match (self.hidden_ancestor, last_hidden) {
            (Some(ancestor), last) => {
                hidden_access(last.map_or(ancestor, |l| l.max(ancestor)), false)
            }
            (None, Some(last)) => hidden_access(last, true),
            (None, None) => self
                .read_only
                .map_or(AccessClass::Normal, AccessClass::ReadOnly),
        };
        PathClass {
            access,
            in_dot_path: self.in_dot_path,
        }
    }

    /// Number of components pushed.
    pub fn depth(&self) -> usize {
        self.depth
    }
}

/// How a path is used, for the lexical [`gate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PathUse {
    /// Listing, stat or a search scope.
    List,
    /// Reading bytes or metadata of an existing entry.
    Read,
    /// Edit, delete, move source, commit-external, upload over an existing file.
    WriteExisting,
    /// Create, new upload, mkdir, move destination, restore target.
    CreateTarget,
}

/// The lexical gate's refusal. Client-api renders it; the fs core's physical gate answers the
/// same way for the same name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GateRefusal {
    /// `not_found` with no details (reveals nothing about existence).
    NotFound,
    /// `not_found ["parent_not_found"]`: a create below a Private or Junk ancestor.
    ParentNotFound,
    /// `invalid_request ["invalid_path","reason:<r>"]`.
    InvalidPath(PathDefect),
    /// `forbidden ["read_only","reason:<r>"]`.
    ReadOnly(ReadOnlyReason),
}

/// The lexical gate:
///
/// | class | List / Read | WriteExisting | CreateTarget |
/// |---|---|---|---|
/// | Private or Junk at an ancestor | `NotFound` | `NotFound` | `ParentNotFound` |
/// | Private at the final component | `NotFound` | `NotFound` | `InvalidPath(ReservedName)` |
/// | Junk at the final component | `NotFound` | `NotFound` | `InvalidPath(JunkName)` |
/// | ReadOnly(r) | allowed | `ReadOnly(r)` | `ReadOnly(r)` |
/// | Normal | allowed | allowed | allowed (the fs core then applies its create grammar) |
///
/// The answer depends on the string alone, so it reveals nothing about what exists.
pub fn gate(class: AccessClass, use_: PathUse) -> Result<(), GateRefusal> {
    match class {
        AccessClass::Normal => Ok(()),
        AccessClass::ReadOnly(reason) => match use_ {
            PathUse::List | PathUse::Read => Ok(()),
            PathUse::WriteExisting | PathUse::CreateTarget => Err(GateRefusal::ReadOnly(reason)),
        },
        AccessClass::Private { at_final } | AccessClass::Junk { at_final } => match use_ {
            PathUse::List | PathUse::Read | PathUse::WriteExisting => Err(GateRefusal::NotFound),
            PathUse::CreateTarget if !at_final => Err(GateRefusal::ParentNotFound),
            PathUse::CreateTarget => Err(GateRefusal::InvalidPath(
                if matches!(class, AccessClass::Private { .. }) {
                    PathDefect::ReservedName
                } else {
                    PathDefect::JunkName
                },
            )),
        },
    }
}

/// The portable sibling-collision key `nfc(full_casefold(nfc(name)))`: the fs core's create
/// grammar refuses a new name whose key equals an existing sibling's, on every volume, so a vault
/// never holds `A.md` beside `a.md` and stays checkout-safe on case-insensitive APFS.
///
/// Full case folding is Unicode CaseFolding.txt status C + F (`ß` and `ẞ` → `ss`, `ﬃ` → `ffi`,
/// `ς` → `σ`, `ſ` → `s`, Cherokee lowercase → uppercase); the Turkic `T` mappings are not used,
/// so `ı` and `i` stay distinct. The input is normalized first so canonically equivalent spellings
/// (U+0345 included) fold alike.
pub fn portable_name_key(name: &str) -> String {
    let nfc = to_nfc(name);
    let mut folded = String::with_capacity(nfc.len());
    for c in nfc.chars() {
        push_full_casefold(c, &mut folded);
    }
    to_nfc(&folded)
}

/// Default full case folding of one scalar (CaseFolding.txt status C + F), derived from the std
/// full case mappings as `lower(upper(lower(c)))`. That composition reproduces the folding table
/// (checked over every assigned code point against CPython's `str.casefold`, Unicode 16) except
/// for two classes the table treats specially: dotless `ı` (only the Turkic `T` status folds it,
/// so it stays itself) and Cherokee, which folds to uppercase for stability.
fn push_full_casefold(c: char, out: &mut String) {
    if c == '\u{131}' {
        out.push(c);
        return;
    }
    if matches!(c, '\u{13A0}'..='\u{13F5}' | '\u{13F8}'..='\u{13FD}' | '\u{AB70}'..='\u{ABBF}') {
        out.extend(c.to_uppercase());
        return;
    }
    for lower in c.to_lowercase() {
        for upper in lower.to_uppercase() {
            out.extend(upper.to_lowercase());
        }
    }
}

/// NFC of any text, with no validation: a name read from disk, or free text such as a search
/// query (which may hold `/`, `..` or spaces that [`normalize_workspace_path`] refuses). Every
/// layer normalizes through this one function, so the server's names and the text compared with
/// them agree. Text that is already NFC is copied without decomposing it.
pub fn to_nfc(text: &str) -> String {
    match is_nfc_quick(text.chars()) {
        IsNormalized::Yes => text.to_owned(),
        IsNormalized::No | IsNormalized::Maybe => text.nfc().collect(),
    }
}

/// Cc, or a bidi or deprecated format control that can reorder or hide what a name displays.
fn is_refused_char(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{061C}'
                | '\u{200E}'
                | '\u{200F}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2066}'..='\u{2069}'
                | '\u{206A}'..='\u{206F}'
                | '\u{FEFF}'
        )
}

/// Code points HFS+ ignores when it compares names.
fn is_hfs_ignorable(c: char) -> bool {
    matches!(
        c,
        '\u{200C}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{206A}'..='\u{206F}' | '\u{FEFF}'
    )
}

/// The part of a skeleton that policy names are matched on: the skeleton without trailing dots
/// and spaces, which FAT, exFAT and NTFS ignore on lookup ([`classify_component`]). Trimming never
/// removes a character a protected name or pattern needs (each ends in another character; the
/// lock-file pattern ends in `#`), so the rule only ever widens a match.
fn policy_stem(skeleton: &str) -> &str {
    skeleton.trim_end_matches(['.', ' '])
}

fn classify_stem(stem: &str, parent_is_agent: bool) -> ComponentClass {
    if is_private_stem(stem, parent_is_agent) {
        ComponentClass::Private
    } else if is_junk_stem(stem) {
        ComponentClass::Junk
    } else if stem == AGENT_DIR_NAME {
        ComponentClass::ReadOnly(ReadOnlyReason::AgentSystem)
    } else if VCS_CONTROL_NAMES.contains(&stem) {
        ComponentClass::ReadOnly(ReadOnlyReason::VcsControl)
    } else {
        ComponentClass::Normal
    }
}

fn is_private_stem(stem: &str, parent_is_agent: bool) -> bool {
    DOT_GIT_NAMES.contains(&stem)
        || PRIVATE_NAMES.contains(&stem)
        || PRIVATE_SUFFIXES.iter().any(|suffix| stem.ends_with(suffix))
        || stem.starts_with(PRIVATE_PREFIX)
        || (parent_is_agent && stem.starts_with('_'))
}

fn is_junk_stem(stem: &str) -> bool {
    JUNK_NAMES.contains(&stem)
        || JUNK_PREFIXES.iter().any(|prefix| stem.starts_with(prefix))
        || (stem.starts_with(LOCK_FILE_PREFIX) && stem.ends_with('#'))
        || is_tempfile_name(stem)
}

/// `^\.tmp[A-Za-z0-9]{6}$` on the stem (already lowercase).
fn is_tempfile_name(stem: &str) -> bool {
    stem.len() == TEMPFILE_PREFIX.len() + 6
        && stem.starts_with(TEMPFILE_PREFIX)
        && stem.as_bytes()[TEMPFILE_PREFIX.len()..]
            .iter()
            .all(u8::is_ascii_alphanumeric)
}

fn hidden_of(class: ComponentClass) -> Option<Hidden> {
    match class {
        ComponentClass::Private => Some(Hidden::Private),
        ComponentClass::Junk => Some(Hidden::Junk),
        ComponentClass::Normal | ComponentClass::ReadOnly(_) => None,
    }
}

fn hidden_access(hidden: Hidden, at_final: bool) -> AccessClass {
    match hidden {
        Hidden::Private => AccessClass::Private { at_final },
        Hidden::Junk => AccessClass::Junk { at_final },
    }
}

/// Lexical read-only precedence: the territory reason wins over the VCS-control reason.
fn read_only_rank(reason: ReadOnlyReason) -> u8 {
    match reason {
        ReadOnlyReason::AgentSystem => 2,
        ReadOnlyReason::VcsControl => 1,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn class_of(raw: &str) -> PathClass {
        let normalized = normalize_workspace_path(raw, false)
            .unwrap_or_else(|defect| panic!("{raw:?} must be lexically valid, got {defect}"));
        classify_lexical(&normalized)
    }

    fn access_of(raw: &str) -> AccessClass {
        class_of(raw).access
    }

    fn assert_private(raw: &str) {
        assert!(
            matches!(access_of(raw), AccessClass::Private { .. }),
            "{raw:?} must be Private, got {:?}",
            access_of(raw)
        );
    }

    /// The detail-token grammar `^[a-z][a-z0-9_]{0,47}(:[0-9a-z_]{1,64})?$`.
    fn is_detail_token(token: &str) -> bool {
        let (key, param) = match token.split_once(':') {
            Some((key, param)) => (key, Some(param)),
            None => (token, None),
        };
        let key_ok = key.len() <= 48
            && key.bytes().next().is_some_and(|b| b.is_ascii_lowercase())
            && key
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
        let param_ok = param.is_none_or(|p| {
            (1..=64).contains(&p.len())
                && p.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        });
        key_ok && param_ok
    }

    #[test]
    fn nfc_normalizes_and_preserves_cjk_and_emoji() {
        assert_eq!(
            normalize_workspace_path("e\u{301}.md", false),
            Ok("\u{E9}.md".to_owned())
        );
        for kept in [
            "周报/计划.md",
            "\u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467}.md",
            "a\u{200D}b.md",
        ] {
            assert_eq!(normalize_workspace_path(kept, false).as_deref(), Ok(kept));
        }
    }

    #[test]
    fn lexical_refusals() {
        let name_204 = "n".repeat(204);
        let path_1025 = format!("{0}/{0}/{0}/{0}/{0}n", name_204);
        assert_eq!(path_1025.len(), 1025);
        let name_256 = "a".repeat(256);
        let depth_33 = vec!["d"; 33].join("/");
        let cases: Vec<(&str, PathDefect)> = vec![
            ("", PathDefect::Missing),
            ("/a", PathDefect::Syntax),
            ("a/", PathDefect::Syntax),
            ("/", PathDefect::Syntax),
            ("a//b", PathDefect::Syntax),
            ("a\\b", PathDefect::Syntax),
            ("a/./b", PathDefect::Traversal),
            ("a/../b", PathDefect::Traversal),
            (".", PathDefect::Traversal),
            ("..", PathDefect::Traversal),
            ("a\0b", PathDefect::ControlChar),
            ("a\u{1F}b", PathDefect::ControlChar),
            ("a\u{7F}b", PathDefect::ControlChar),
            ("a\u{85}b", PathDefect::ControlChar),
            ("a\u{202E}b", PathDefect::ControlChar),
            ("a\u{2066}b", PathDefect::ControlChar),
            ("a\u{206A}b", PathDefect::ControlChar),
            ("a\u{206F}b", PathDefect::ControlChar),
            ("a\u{FEFF}b", PathDefect::ControlChar),
            ("a\u{061C}b", PathDefect::ControlChar),
            (path_1025.as_str(), PathDefect::TooLong),
            (name_256.as_str(), PathDefect::NameTooLong),
            (depth_33.as_str(), PathDefect::TooDeep),
        ];
        for (raw, expected) in cases {
            assert_eq!(
                normalize_workspace_path(raw, false),
                Err(expected),
                "input {raw:?}"
            );
        }
    }

    #[test]
    fn limits_are_inclusive() {
        let name_204 = "n".repeat(204);
        let path_1024 = vec![name_204.as_str(); 5].join("/");
        assert_eq!(path_1024.len(), MAX_WORKSPACE_PATH_BYTES);
        assert_eq!(
            normalize_workspace_path(&path_1024, false).as_deref(),
            Ok(path_1024.as_str())
        );
        let name_255 = "a".repeat(MAX_WORKSPACE_NAME_BYTES);
        assert!(normalize_workspace_path(&name_255, false).is_ok());
        // Bytes, not scalars: 86 three-byte CJK scalars are 258 bytes.
        assert_eq!(
            normalize_workspace_path(&"计".repeat(86), false),
            Err(PathDefect::NameTooLong)
        );
        assert!(normalize_workspace_path(&"计".repeat(85), false).is_ok());
        let depth_32 = vec!["d"; MAX_WORKSPACE_DEPTH].join("/");
        assert!(normalize_workspace_path(&depth_32, false).is_ok());
        // A decomposed path above 1024 raw bytes whose NFC form fits is accepted: 85 Hangul
        // L+V+T jamo triples (765 raw bytes) compose into 85 syllables (255 bytes).
        let jamo_name = "\u{1100}\u{1161}\u{11A8}".repeat(85);
        let jamo_path = vec![jamo_name.as_str(); 4].join("/");
        assert!(jamo_path.len() > MAX_WORKSPACE_PATH_BYTES);
        let composed = normalize_workspace_path(&jamo_path, false).expect("NFC form fits");
        assert_eq!(composed.len(), 4 * 255 + 3);
        assert_eq!(composed.chars().next(), Some('\u{AC01}'));
        // The worst NFC shrink is 3.5×: U+1FBE U+0308 U+0301 (7 bytes) composes into U+0390
        // (2 bytes). This 3,574-byte path normalizes to exactly 1,024 bytes, so any raw bound
        // below 3.5 × 1024 would refuse it.
        let iota = "\u{1FBE}\u{308}\u{301}";
        let iota_name = iota.repeat(127);
        let iota_path = format!("{0}/{0}/{0}/{0}/{1}", iota_name, iota.repeat(2));
        assert_eq!(iota_path.len(), 3574);
        assert!(iota_path.len() > 3 * MAX_WORKSPACE_PATH_BYTES);
        let composed = normalize_workspace_path(&iota_path, false).expect("NFC form fits");
        assert_eq!(composed.len(), MAX_WORKSPACE_PATH_BYTES);
        assert_eq!(composed.chars().next(), Some('\u{390}'));
        // Raw inputs over 4 KiB are refused before normalization.
        assert_eq!(
            normalize_workspace_path(&"a".repeat(MAX_RAW_PATH_BYTES + 1), false),
            Err(PathDefect::TooLong)
        );
    }

    #[test]
    fn zwj_zwnj_legal_bidi_and_format_controls_refused() {
        for legal in [
            "a\u{200C}b",
            "a\u{200D}b",
            "\u{645}\u{200C}\u{6CC}.md",
            "word\u{2060}joiner",
            "soft\u{AD}hyphen",
            "\u{2764}\u{FE0F}.md",
        ] {
            assert!(
                normalize_workspace_path(legal, false).is_ok(),
                "{legal:?} must be legal"
            );
        }
        let refused = ['\u{061C}', '\u{200E}', '\u{200F}', '\u{FEFF}']
            .into_iter()
            .chain('\u{202A}'..='\u{202E}')
            .chain('\u{2066}'..='\u{2069}')
            .chain('\u{206A}'..='\u{206F}');
        for c in refused {
            assert_eq!(
                normalize_workspace_path(&format!("dir/a{c}b"), false),
                Err(PathDefect::ControlChar),
                "U+{:04X} must be refused",
                c as u32
            );
        }
    }

    #[test]
    fn decomposed_input_is_normalized_to_nfc() {
        assert_eq!(
            normalize_workspace_path("Cafe\u{301}/Re\u{301}sume\u{301}.md", false).as_deref(),
            Ok("Caf\u{E9}/R\u{E9}sum\u{E9}.md")
        );
        assert_eq!(
            normalize_workspace_path("\u{1100}\u{1161}\u{11A8}.md", false).as_deref(),
            Ok("\u{AC01}.md")
        );
        // Singleton decompositions are canonical: Ohm and Angstrom signs normalize too.
        assert_eq!(
            normalize_workspace_path("\u{2126}/\u{212B}", false).as_deref(),
            Ok("\u{3A9}/\u{C5}")
        );
        // `to_nfc` normalizes free text without validating it (a search query may hold `/`, `..`
        // and spaces).
        assert_eq!(to_nfc("a/../Cafe\u{301} b"), "a/../Caf\u{E9} b");
        assert_eq!(to_nfc("\u{1100}\u{1161}\u{11A8}"), "\u{AC01}");
        assert_eq!(to_nfc("\u{E9}t\u{E9}"), "\u{E9}t\u{E9}");
        assert_eq!(to_nfc(""), "");
    }

    #[test]
    fn root_only_when_allowed() {
        assert_eq!(normalize_workspace_path("", true), Ok(String::new()));
        assert_eq!(
            normalize_workspace_path("", false),
            Err(PathDefect::Missing)
        );
        assert_eq!(
            classify_lexical(""),
            PathClass {
                access: AccessClass::Normal,
                in_dot_path: false,
            }
        );
    }

    #[test]
    fn skeleton_vectors() {
        let cases = [
            ("\u{17F}", "s"),
            (".\u{17F}ub", ".sub"),
            ("\u{FF0E}\u{FF47}\u{FF49}\u{FF54}", ".git"),
            (".g\u{EF}t", ".git"),
            (".g\u{200D}it", ".git"),
            (".g\u{200C}it", ".git"),
            (".g\u{FEFF}it", ".git"),
            (".g\u{202A}it", ".git"),
            (".g\u{206A}it", ".git"),
            (
                "x.\u{FF53}\u{FF51}\u{FF4C}\u{FF49}\u{FF54}\u{FF45}",
                "x.sqlite",
            ),
            ("\u{130}", "i"),
            ("\u{212A}", "k"),
            (".DS_Store", ".ds_store"),
            (".g\u{2060}it", ".g\u{2060}it"),
            ("\u{1F468}\u{200D}\u{1F469}", "\u{1F468}\u{1F469}"),
            ("\u{3A3}\u{391}\u{3A3}", "\u{3C3}\u{3B1}\u{3C3}"),
        ];
        for (name, expected) in cases {
            assert_eq!(policy_skeleton(name), expected, "skeleton of {name:?}");
        }
    }

    #[test]
    fn skeleton_drops_only_nonspacing_marks() {
        // Mn: combining acute, variation selector 16.
        assert_eq!(policy_skeleton("a\u{301}"), "a");
        assert_eq!(policy_skeleton("a\u{FE0F}"), "a");
        // Mc (Devanagari visarga) and Me (combining enclosing keycap) are kept.
        assert_eq!(policy_skeleton("\u{915}\u{903}"), "\u{915}\u{903}");
        assert_eq!(policy_skeleton("1\u{20E3}"), "1\u{20E3}");
    }

    #[test]
    fn private_classification_is_fold_insensitive() {
        // The root `.gitignore` is not here: it is ReadOnly(VcsControl), listed and readable.
        for raw in [
            ".git/config",
            ".GIT/x",
            "\u{FF0E}git/x",
            ".g\u{200D}it/config",
            ".g\u{200C}it/x",
            ".ag\u{200D}ent/_x",
            ".runtime/index.db",
            ".advance/x",
            ".\u{17F}ub/x",
            ".triggers",
            ".triggers/components.db",
            ".TRIGGERS/x",
            ".trig\u{200C}gers/x",
            "x/.meta.yaml",
            "db.SQLITE-wal",
            ".agent/_drafts/a",
            ".AGENT/_x",
            ".~advance-1.tmp",
        ] {
            assert_private(raw);
        }
        assert_eq!(
            access_of(".triggers"),
            AccessClass::Private { at_final: true }
        );
        assert_eq!(
            access_of("x/.meta.yaml"),
            AccessClass::Private { at_final: true }
        );
        assert_eq!(
            access_of(".git/config"),
            AccessClass::Private { at_final: false }
        );
    }

    #[test]
    fn private_includes_libgit2_ntfs_aliases() {
        for raw in [
            ".git.",
            ".git ",
            "GIT~1",
            "git~1..",
            ".git. .",
            "git~1 ",
            "x/.GIT./y",
        ] {
            assert_private(raw);
        }
        for raw in [
            ".gitx", ".git-x", "git~10", "git~2", "git", ".gi t", "a.git",
        ] {
            assert_eq!(
                access_of(raw),
                AccessClass::Normal,
                "{raw:?} must stay Normal"
            );
        }
    }

    #[test]
    fn trailing_dots_and_spaces_alias_protected_names() {
        // FAT and exFAT (Linux mounts included) ignore trailing dots on lookup and NTFS also
        // trailing spaces, so every protected name spelled that way is that name.
        for raw in [
            "x.sqlite.",
            "x.sqlite-wal.",
            "db.SQLITE-shm ",
            "x.sqlite-journal. .",
            ".meta.yaml.",
            "notes/.meta.yaml ",
            ".runtime..",
            ".triggers./components.db",
            ".agent./_x",
        ] {
            assert_private(raw);
        }
        for raw in [
            ".gitignore.",
            ".gitmodules..",
            "p/.gitattributes ",
            ".GitIgnore. ",
        ] {
            assert_eq!(
                access_of(raw),
                AccessClass::ReadOnly(ReadOnlyReason::VcsControl),
                "{raw:?}"
            );
        }
        assert_eq!(
            access_of(".agent./x"),
            AccessClass::ReadOnly(ReadOnlyReason::AgentSystem)
        );
        assert!(is_agent_dir_name(".agent."));
        assert!(is_agent_dir_name(".AGENT "));
        for raw in [
            ".DS_Store.",
            "Thumbs.db ",
            "desktop.ini..",
            ".tmpAbc123.",
            ".~lock.a.odt#.",
        ] {
            assert!(
                matches!(access_of(raw), AccessClass::Junk { at_final: true }),
                "{raw:?} must be Junk, got {:?}",
                access_of(raw)
            );
        }
        // Only trailing dots and spaces are ignored: any other suffix keeps the name ordinary.
        for raw in [
            "x.sqlite.bak",
            "x.sqlite.md",
            ".gitignore.d/x",
            "notes.",
            "...",
            "a .",
            ".agents.",
        ] {
            assert_eq!(
                access_of(raw),
                AccessClass::Normal,
                "{raw:?} must stay Normal"
            );
        }
        // The gate still answers from the string alone.
        assert_eq!(
            gate(access_of("notes/x.sqlite."), PathUse::CreateTarget),
            Err(GateRefusal::InvalidPath(PathDefect::ReservedName))
        );
        assert_eq!(
            gate(access_of(".gitignore."), PathUse::WriteExisting),
            Err(GateRefusal::ReadOnly(ReadOnlyReason::VcsControl))
        );
        assert_eq!(
            gate(access_of("x.sqlite-wal."), PathUse::Read),
            Err(GateRefusal::NotFound)
        );
    }

    #[test]
    fn every_hfs_ignorable_is_stripped() {
        // HFS+ ignores exactly these 16 code points when it compares names. API paths refuse most
        // of them, so they reach the classifier as on-disk spellings in the fs core's walk.
        let ignorables: Vec<char> = ('\u{200C}'..='\u{200F}')
            .chain('\u{202A}'..='\u{202E}')
            .chain('\u{206A}'..='\u{206F}')
            .chain(['\u{FEFF}'])
            .collect();
        assert_eq!(ignorables.len(), 16);
        for c in ignorables {
            let code = c as u32;
            assert_eq!(policy_skeleton(&format!(".g{c}it")), ".git", "U+{code:04X}");
            assert_eq!(
                PathClassifier::new().push(&format!(".g{c}it")),
                ComponentClass::Private,
                "U+{code:04X}"
            );
            assert_eq!(
                classify_component(&format!("x.sqlite{c}"), false),
                ComponentClass::Private,
                "U+{code:04X}"
            );
            assert_eq!(
                classify_component(&format!("{c}_inbox"), true),
                ComponentClass::Private,
                "U+{code:04X}"
            );
            assert!(is_agent_dir_name(&format!(".age{c}nt")), "U+{code:04X}");
        }
        // Their neighbours are not HFS+-ignorable and stay in the skeleton.
        for c in [
            '\u{200B}', '\u{2010}', '\u{2029}', '\u{202F}', '\u{2069}', '\u{2070}', '\u{FEFE}',
            '\u{FF00}',
        ] {
            assert_ne!(
                policy_skeleton(&format!(".g{c}it")),
                ".git",
                "U+{:04X}",
                c as u32
            );
        }
    }

    /// Every literal a protected name or pattern is built from.
    fn protected_literals() -> Vec<&'static str> {
        let mut literals = vec![
            AGENT_DIR_NAME,
            META_SIDECAR_NAME,
            PRIVATE_PREFIX,
            LOCK_FILE_PREFIX,
            TEMPFILE_PREFIX,
        ];
        literals.extend(
            DOT_GIT_NAMES
                .iter()
                .chain(PRIVATE_NAMES)
                .chain(PRIVATE_SUFFIXES)
                .chain(JUNK_NAMES)
                .chain(JUNK_PREFIXES)
                .chain(VCS_CONTROL_NAMES)
                .chain(PROTECTED_ROOT_NAMES)
                .chain(PROTECTED_ANY_LEVEL_NAMES),
        );
        literals
    }

    #[test]
    fn apfs_full_folds_the_skeleton_misses_touch_no_protected_name() {
        // APFS compares names under full case folding. The skeleton reproduces every folding of
        // a scalar to ASCII except the ones collected here (`ß` and `ẞ` fold to `ss`), so no
        // protected name may contain them: `.seßions` would alias a `.sessions` unseen.
        let mut gaps: Vec<String> = Vec::new();
        let mut buffer = [0u8; 4];
        for c in (0..=0x10_FFFF).filter_map(char::from_u32) {
            if c.is_ascii() {
                continue;
            }
            let name: &str = c.encode_utf8(&mut buffer);
            let folded = portable_name_key(name);
            if folded.is_ascii() && policy_skeleton(name) != folded {
                gaps.push(folded);
            }
        }
        gaps.sort_unstable();
        gaps.dedup();
        assert!(gaps.iter().any(|gap| gap == "ss"), "{gaps:?}");
        for literal in protected_literals() {
            assert_eq!(
                policy_skeleton(literal),
                literal,
                "{literal:?} is a skeleton"
            );
            for gap in &gaps {
                assert!(
                    !literal.contains(gap.as_str()),
                    "{literal:?} contains {gap:?}, which APFS folds from a scalar the skeleton keeps"
                );
            }
        }
    }

    #[test]
    fn agent_children() {
        assert_eq!(
            access_of(".agent/_x"),
            AccessClass::Private { at_final: true }
        );
        assert_eq!(
            access_of(".agent/x"),
            AccessClass::ReadOnly(ReadOnlyReason::AgentSystem)
        );
        assert_eq!(
            access_of(".agent"),
            AccessClass::ReadOnly(ReadOnlyReason::AgentSystem)
        );
        // Only direct children of `.agent` are Private.
        assert_eq!(
            access_of(".agent/memory/_x"),
            AccessClass::ReadOnly(ReadOnlyReason::AgentSystem)
        );
        assert_eq!(
            access_of("p/.agent/_drafts/a"),
            AccessClass::Private { at_final: false }
        );
        assert_eq!(access_of("_x"), AccessClass::Normal);
        assert_eq!(access_of("p/_x"), AccessClass::Normal);
        assert!(is_agent_dir_name(".AGENT"));
        assert!(is_agent_dir_name(".ag\u{200D}ent"));
        assert!(!is_agent_dir_name(".agents"));
    }

    #[test]
    fn readonly_classification() {
        for raw in [
            ".agent/AGENTS.md",
            ".ag\u{200D}ent/x",
            "p/.agent/memory/m.md",
        ] {
            assert_eq!(
                access_of(raw),
                AccessClass::ReadOnly(ReadOnlyReason::AgentSystem),
                "{raw:?}"
            );
        }
        for raw in [
            "p/.gitignore",
            ".gitattributes",
            "p/.gitmodules",
            ".gitignore",
            ".GitIgnore",
        ] {
            assert_eq!(
                access_of(raw),
                AccessClass::ReadOnly(ReadOnlyReason::VcsControl),
                "{raw:?}"
            );
        }
    }

    #[test]
    fn junk_classification() {
        for raw in [
            ".DS_Store",
            "._a.md",
            "~$q3.xlsx",
            ".~lock.a.odt#",
            "Thumbs.db",
            ".tmpAbc123",
            "._foo",
            "desktop.ini",
            ".localized",
            ".Spotlight-V100",
            ".Trashes",
            ".fseventsd",
            ".TemporaryItems",
            ".DocumentRevisions-V100",
            "x/.DS_Store",
        ] {
            assert!(
                matches!(access_of(raw), AccessClass::Junk { at_final: true }),
                "{raw:?} must be Junk, got {:?}",
                access_of(raw)
            );
        }
        for raw in [
            ".tmpAbc12",
            ".tmpAbc1234",
            ".tmpAbc_12",
            "tmpAbc1234",
            ".~lock.a.odt",
        ] {
            assert_eq!(
                access_of(raw),
                AccessClass::Normal,
                "{raw:?} must stay Normal"
            );
        }
    }

    #[test]
    fn sqlite_appledouble_and_dotfile_flag() {
        assert_eq!(
            class_of("a.sqlite-wal"),
            PathClass {
                access: AccessClass::Private { at_final: true },
                in_dot_path: false,
            }
        );
        assert_eq!(access_of("._foo"), AccessClass::Junk { at_final: true });
        assert_eq!(
            class_of(".obsidian/x"),
            PathClass {
                access: AccessClass::Normal,
                in_dot_path: true,
            }
        );
        assert_eq!(
            class_of(".env"),
            PathClass {
                access: AccessClass::Normal,
                in_dot_path: true,
            }
        );
        assert_eq!(class_of("notes/.draft.md").access, AccessClass::Normal);
        assert!(class_of("notes/.draft.md").in_dot_path);
        assert_eq!(
            class_of("notes/a.md"),
            PathClass {
                access: AccessClass::Normal,
                in_dot_path: false,
            }
        );
        // The listed entry's `dotfile` flag is its own name: `.obsidian` is a dotfile, its
        // children are not, although their paths lie in a dot directory.
        for dotfile in [".obsidian", ".env", ".draft.md", ".gitignore", "..."] {
            assert!(is_dotfile_name(dotfile), "{dotfile:?}");
        }
        for name in ["workspace.json", "a.md", "\u{FF0E}env", "a.", ""] {
            assert!(!is_dotfile_name(name), "{name:?}");
        }
        assert!(class_of(".obsidian/workspace.json").in_dot_path);
    }

    #[test]
    fn lookalikes_that_are_not_aliases_stay_visible() {
        for raw in [
            "notes/.github/x.md",
            "git/a",
            ".obsidian/x",
            ".g\u{2060}it/x",
            ".gitkeep",
            ".agents/x",
            "agent/_x",
            "x.sqlite.bak",
        ] {
            assert_eq!(
                access_of(raw),
                AccessClass::Normal,
                "{raw:?} must stay Normal"
            );
        }
    }

    #[test]
    fn most_restrictive_component_wins() {
        assert_eq!(
            access_of("._x/.git"),
            AccessClass::Private { at_final: false }
        );
        assert_eq!(
            access_of(".git/._x"),
            AccessClass::Private { at_final: false }
        );
        assert_eq!(
            access_of(".DS_Store/x"),
            AccessClass::Junk { at_final: false }
        );
        assert_eq!(
            access_of(".agent/x.sqlite"),
            AccessClass::Private { at_final: true }
        );
        assert_eq!(
            access_of(".agent/.DS_Store"),
            AccessClass::Junk { at_final: true }
        );
        assert_eq!(
            access_of(".agent/.gitignore"),
            AccessClass::ReadOnly(ReadOnlyReason::AgentSystem)
        );
        assert_eq!(
            access_of(".gitignore/.agent/x"),
            AccessClass::ReadOnly(ReadOnlyReason::AgentSystem)
        );
        assert_eq!(
            access_of(".gitignore/x"),
            AccessClass::ReadOnly(ReadOnlyReason::VcsControl)
        );
        assert!(access_of(".git/x").is_hidden());
        assert!(!access_of(".agent/x").is_hidden());
    }

    #[test]
    fn classifier_matches_lexical_and_disk_spellings() {
        for raw in [
            "notes/a.md",
            ".git/config",
            "p/.agent/_drafts/a",
            ".agent/.gitignore",
            "._x/.git",
            ".obsidian/workspace.json",
            "a/b/c/.DS_Store",
        ] {
            let mut classifier = PathClassifier::new();
            for component in raw.split('/') {
                classifier.push(component);
            }
            assert_eq!(classifier.class(), classify_lexical(raw), "{raw:?}");
            assert_eq!(classifier.depth(), raw.split('/').count());
        }
        // On-disk spellings (NFD from HFS+, other case) classify like the NFC form.
        let mut disk = PathClassifier::new();
        assert_eq!(
            disk.push(".AGENT"),
            ComponentClass::ReadOnly(ReadOnlyReason::AgentSystem)
        );
        assert_eq!(disk.push("_dra\u{301}ft"), ComponentClass::Private);
        assert_eq!(disk.class(), classify_lexical(".agent/_dr\u{E1}ft"));
        // Decorated and case variants of a protected name are that name.
        assert_eq!(
            classify_component(".Me\u{301}ta.yaml", false),
            ComponentClass::Private
        );
        assert_eq!(
            classify_component(".Meta.YAML", false),
            ComponentClass::Private
        );
        assert_eq!(PathClassifier::new().class(), classify_lexical(""));
    }

    #[test]
    fn protected_names_classify_as_documented() {
        for name in PROTECTED_ROOT_NAMES.iter().chain(PROTECTED_ANY_LEVEL_NAMES) {
            let class = classify_component(name, false);
            assert!(
                class == ComponentClass::Private
                    || class == ComponentClass::ReadOnly(ReadOnlyReason::AgentSystem),
                "{name:?} classified {class:?}"
            );
        }
        assert_eq!(
            classify_component(META_SIDECAR_NAME, false),
            ComponentClass::Private
        );
        assert_eq!(
            classify_component(AGENT_DIR_NAME, false),
            ComponentClass::ReadOnly(ReadOnlyReason::AgentSystem)
        );
        assert_eq!(classify_component("_x", true), ComponentClass::Private);
        assert_eq!(classify_component("_x", false), ComponentClass::Normal);
    }

    #[test]
    fn path_use_mapping() {
        use GateRefusal::{InvalidPath, NotFound, ParentNotFound, ReadOnly};
        let agent = ReadOnlyReason::AgentSystem;
        let vcs = ReadOnlyReason::VcsControl;
        // (class, [List, Read, WriteExisting, CreateTarget])
        let table: [(AccessClass, [Result<(), GateRefusal>; 4]); 7] = [
            (
                AccessClass::Private { at_final: false },
                [
                    Err(NotFound),
                    Err(NotFound),
                    Err(NotFound),
                    Err(ParentNotFound),
                ],
            ),
            (
                AccessClass::Junk { at_final: false },
                [
                    Err(NotFound),
                    Err(NotFound),
                    Err(NotFound),
                    Err(ParentNotFound),
                ],
            ),
            (
                AccessClass::Private { at_final: true },
                [
                    Err(NotFound),
                    Err(NotFound),
                    Err(NotFound),
                    Err(InvalidPath(PathDefect::ReservedName)),
                ],
            ),
            (
                AccessClass::Junk { at_final: true },
                [
                    Err(NotFound),
                    Err(NotFound),
                    Err(NotFound),
                    Err(InvalidPath(PathDefect::JunkName)),
                ],
            ),
            (
                AccessClass::ReadOnly(agent),
                [Ok(()), Ok(()), Err(ReadOnly(agent)), Err(ReadOnly(agent))],
            ),
            (
                AccessClass::ReadOnly(vcs),
                [Ok(()), Ok(()), Err(ReadOnly(vcs)), Err(ReadOnly(vcs))],
            ),
            (AccessClass::Normal, [Ok(()), Ok(()), Ok(()), Ok(())]),
        ];
        let uses = [
            PathUse::List,
            PathUse::Read,
            PathUse::WriteExisting,
            PathUse::CreateTarget,
        ];
        for (class, expected) in table {
            for (use_, want) in uses.into_iter().zip(expected) {
                assert_eq!(gate(class, use_), want, "{class:?} × {use_:?}");
            }
        }
        // The same answers from real paths.
        let create = |raw: &str| gate(access_of(raw), PathUse::CreateTarget);
        assert_eq!(create(".git/x"), Err(ParentNotFound));
        assert_eq!(
            create("notes/.meta.yaml"),
            Err(InvalidPath(PathDefect::ReservedName))
        );
        assert_eq!(
            create("notes/.DS_Store"),
            Err(InvalidPath(PathDefect::JunkName))
        );
        assert_eq!(create(".agent/notes.md"), Err(ReadOnly(agent)));
        assert_eq!(create("notes/new.md"), Ok(()));
        assert_eq!(gate(access_of(".triggers"), PathUse::Read), Err(NotFound));
    }

    #[test]
    fn reason_tokens_match_registry() {
        let defects: Vec<&str> = PathDefect::ALL.iter().map(|d| d.reason()).collect();
        assert_eq!(
            defects,
            [
                "syntax",
                "traversal",
                "control_char",
                "too_long",
                "too_deep",
                "name_too_long",
                "missing",
                "reserved_name",
                "junk_name",
                "create_grammar",
            ]
        );
        let reasons: Vec<&str> = ReadOnlyReason::ALL.iter().map(|r| r.reason()).collect();
        assert_eq!(
            reasons,
            [
                "agent_system",
                "vcs_control",
                "territory_root",
                "contains_territory",
                "foreign_repo",
                "contains_foreign_repo",
                "contains_runtime_state",
                "mount_point",
                "locked",
                "permission",
                "read_only_volume",
                "symlink",
                "special",
                "ambiguous_name",
                "unversionable",
            ]
        );
        let mut all: Vec<&str> = defects.iter().chain(&reasons).copied().collect();
        for token in &all {
            assert!(is_detail_token(&format!("reason:{token}")), "{token}");
        }
        all.sort_unstable();
        all.dedup();
        assert_eq!(
            all.len(),
            defects.len() + reasons.len(),
            "tokens are unique"
        );
        assert_eq!(PathDefect::TooDeep.to_string(), "too_deep");
        assert!(!is_detail_token("reason:Bad"));
    }

    #[test]
    fn portable_name_key_folds_case_and_normalization() {
        let key = portable_name_key;
        assert_eq!(key("A.md"), key("a.md"));
        assert_eq!(key("Stra\u{DF}e.md"), key("STRASSE.md"));
        assert_eq!(key("Stra\u{DF}e.md"), key("strasse.md"));
        assert_eq!(key("\u{1E9E}"), key("ss"));
        assert_eq!(key("\u{E9}.md"), key("e\u{301}.md"));
        assert_eq!(key("\u{E9}.md"), key("\u{C9}.md"));
        assert_eq!(key("\u{FB01}le"), key("FILE"));
        // Three-scalar foldings keep their order (`ﬃ` is `ffi`, not `iff`).
        assert_eq!(key("\u{FB03}le"), "ffile");
        assert_eq!(key("\u{FB03}le"), key("FFILE"));
        assert_eq!(key("\u{390}"), "\u{390}");
        assert_eq!(key("\u{1FB7}"), "\u{1FB6}\u{3B9}");
        assert_eq!(key("\u{212A}"), key("k"));
        assert_eq!(key("\u{13A0}"), key("\u{AB70}"));
        assert_eq!(key("\u{3C2}"), key("\u{3C3}"));
        assert_eq!(key("\u{3A3}"), key("\u{3C3}"));
        // Canonically equivalent spellings with U+0345 fold alike.
        assert_eq!(key("\u{3B1}\u{345}\u{301}"), key("\u{3B1}\u{301}\u{345}"));
        assert_ne!(key("\u{131}"), key("i"));
        assert_ne!(key("\u{E9}"), key("e"));
        assert_ne!(key("a.md"), key("a.MD.txt"));
        assert!(unicode_normalization::is_nfc(&key("A\u{30A}")));
        assert_eq!(key("A\u{30A}"), "\u{E5}");
    }
}

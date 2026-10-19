//! Deterministic labels of user-lane commits (ADR 2026-10-15 D3, R5, R6; MODULE-003 §1.4.1
//! "Labels", §1.7 and AC-29).
//!
//! advance-git is the **one** generator and the **one** parser of these labels: the
//! worker renders a canonical-English subject and a percent-escaped `Advance-*` trailer
//! block from a typed [`CommitLabel`]; the history reader parses the block back, but only
//! from commits that carry the lane's signatures ([`label_of`]). Clients render the
//! structured label with their own string tables and never parse the English subject.
//!
//! ```text
//! [user] [user:advance] Rename notes/［draft］ a.md → notes/b.md
//!
//! Advance-Op: rename
//! Advance-Path: notes/[draft] a.md
//! Advance-To: notes/b.md
//! Advance-Count: 1
//! Advance-Client: macos
//! Advance-Session: 0123456789abcdef
//! ```
//!
//! - **Subjects** come from a closed set of templates ([`LabelTemplate`], one per row of
//!   the MODULE-003 §1.4.1 "Labels" table, with R5 and R6). Interpolated values show
//!   `[ ] < > "` as the look-alikes `［ ］ ‹ › ＂` and Cc, U+2028, U+2029 and the bidi
//!   controls as `_`, so `sanitize_audit_field(subject) == subject`. At most
//!   [`MAX_SUBJECT_CHARS`] scalars: paths are elided ([`elide_path`]), then a title or
//!   checkpoint is end-truncated.
//! - **Trailers** are written literally except Cc, U+2028, U+2029, the bidi controls and
//!   `%`, which are percent-encoded as uppercase `%XX` UTF-8 bytes; values are never
//!   trimmed, so [`parse_trailers`] round-trips them exactly.
//! - **Golden**: [`golden_cases`] holds a literal subject for every template row; it is
//!   the source of `sdk-artifacts/conformance/labels.json`.
//!
//! Rendering runs while the coord mutex is held, so it is panic-free: a panic there
//! poisons coord and stops every later commit.

#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::arithmetic_side_effects
)]

use std::collections::HashSet;
use std::fmt::Write as _;
use std::time::SystemTime;

use chrono::{Datelike, Timelike};
use unicode_normalization::char::is_combining_mark;
use unicode_normalization::UnicodeNormalization;

use crate::commit_queue::{sanitize_audit_field, CommitType};
use crate::error::UserOpRefusal;
use crate::user_lane::{
    is_valid_handle, Provenance, ADOPT_INITIATOR, RUNTIME_EMAIL, RUNTIME_NAME, USER_EMAIL,
    USER_NAMESPACE,
};

/// Op tokens (closed; shared by the `Advance-Op` trailer, `git.commit.op` and
/// `ClientGitCommitLabel.op`).
pub const OP_EDIT: &str = "edit";
pub const OP_CREATE: &str = "create";
pub const OP_CREATE_FOLDER: &str = "create-folder";
pub const OP_RENAME: &str = "rename";
pub const OP_MOVE: &str = "move";
pub const OP_COPY: &str = "copy";
pub const OP_DELETE: &str = "delete";
pub const OP_RESTORE: &str = "restore";
pub const OP_UPLOAD: &str = "upload";
pub const OP_SAVE_VERSION: &str = "save-version";
pub const OP_EDIT_EXTERNAL: &str = "edit-external";
/// Runtime bookkeeping only (`[micro] [runtime:adopt]`).
pub const OP_ADOPT: &str = "adopt";
/// Every op token, in registry order.
pub const OP_TOKENS: [&str; 12] = [
    OP_EDIT,
    OP_CREATE,
    OP_CREATE_FOLDER,
    OP_RENAME,
    OP_MOVE,
    OP_COPY,
    OP_DELETE,
    OP_RESTORE,
    OP_UPLOAD,
    OP_SAVE_VERSION,
    OP_EDIT_EXTERNAL,
    OP_ADOPT,
];

/// Change kinds of the `Advance-Change` trailer (R5).
pub const CHANGE_ADDED: &str = "added";
pub const CHANGE_MODIFIED: &str = "modified";
pub const CHANGE_DELETED: &str = "deleted";
pub const CHANGE_REPLACED: &str = "replaced";
/// Every change token.
pub const CHANGE_TOKENS: [&str; 4] = [
    CHANGE_ADDED,
    CHANGE_MODIFIED,
    CHANGE_DELETED,
    CHANGE_REPLACED,
];

/// Subject budget, in Unicode scalars after the `[type] [initiator] ` prefix.
pub const MAX_SUBJECT_CHARS: usize = 120;
/// The smallest budget a path is elided to.
pub const MIN_PATH_BUDGET: usize = 16;
/// `Advance-Path` lines per commit (`count` carries the full number).
pub const MAX_LABEL_PATHS: usize = 64;
/// Longest version title, in scalars after [`normalize_title`].
pub const MAX_TITLE_CHARS: usize = 80;
/// No line stat when a side is larger than this; the size `S` is shown instead.
pub const MAX_STAT_BYTES: u64 = 1024 * 1024;
/// Longest version-label slug.
pub const MAX_SLUG_CHARS: usize = 40;
/// A slug shorter than this is dropped from the version label.
pub const MIN_SLUG_CHARS: usize = 3;
/// Last collision suffix of a version label (`-2` … `-99`).
pub const MAX_VERSION_SUFFIX: u32 = 99;

const KEY_OP: &str = "Advance-Op";
const KEY_PATH: &str = "Advance-Path";
const KEY_TO: &str = "Advance-To";
const KEY_COUNT: &str = "Advance-Count";
const KEY_CHANGE: &str = "Advance-Change";
const KEY_LINES: &str = "Advance-Lines";
const KEY_SIZE: &str = "Advance-Size";
const KEY_VERSIONED: &str = "Advance-Versioned";
const KEY_FROM: &str = "Advance-From";
const KEY_CHECKPOINT: &str = "Advance-Checkpoint";
const KEY_TITLE: &str = "Advance-Title";
const KEY_CLIENT: &str = "Advance-Client";
const KEY_SESSION: &str = "Advance-Session";

/// The structured label of a user-lane (or adopt) commit: what the subject was rendered
/// from and what [`parse_trailers`] gives back. `paths` and `to` are display values:
/// folders end with `/` and the vault root is `/`.
///
/// | op | `paths` | `to` | `count` | other fields |
/// |---|---|---|---|---|
/// | `edit`, `create` | the file | — | 1 | lines or size; `versioned: false` + size when not versioned |
/// | `create-folder` | the deepest folder created | — | levels created | — |
/// | `rename` | the source | the new path | 1 | — |
/// | `move` | the sources | the destination folder | N | — |
/// | `copy` | the sources | one item: the new path (a file for a file, a folder for a folder); more: the destination folder | N | `change` (`added`) |
/// | `delete` | the paths | — | N | — |
/// | `restore` | the file, the folder, the items, or empty (whole scope) | — | items | `from_sha`; `checkpoint` + `title` for a user version, `checkpoint` alone for an agent checkpoint; `change` only when exactly one file is restored |
/// | `upload` | the file(s) | more than one: the destination folder | N | size (total), `change` |
/// | `save-version` | the version's paths (empty: whole vault) | — | paths | `title`, `checkpoint` |
/// | `edit-external` | the file | — | 1 | `change`, lines or size |
/// | `adopt` | the adopted paths | — | N | — |
///
/// `paths` holds at most [`MAX_LABEL_PATHS`] entries; `count` is always the full count.
/// `lines_added` and `lines_removed` are set together or not at all.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct CommitLabel {
    /// The op token ([`OP_TOKENS`]); an open string on the wire.
    pub op: String,
    pub paths: Vec<String>,
    pub to: Option<String>,
    pub count: u32,
    pub lines_added: Option<u64>,
    pub lines_removed: Option<u64>,
    pub size_bytes: Option<u64>,
    /// `Some(false)` when an item is not versioned.
    pub versioned: Option<bool>,
    /// The restored commit, 40 hex.
    pub from_sha: Option<String>,
    /// `user/<label>` or `<agent>/<label>`.
    pub checkpoint: Option<String>,
    /// The exact version title.
    pub title: Option<String>,
    /// [`CHANGE_TOKENS`] (R5). Set for `upload` (`added`, `replaced`), `edit-external`
    /// (`added`, `modified`, `deleted`) and `copy` (always `added`); for `restore` only when
    /// the label names exactly one restored file (`added`, `modified`, `deleted`). A
    /// folder, multi-item, vault, version or checkpoint restore has none: its items differ
    /// in kind and no restore template depends on it.
    pub change: Option<String>,
}

/// One row of the subject template table (MODULE-003 §1.4.1 "Labels", with R5 and R6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LabelTemplate {
    EditLines,
    EditSize,
    EditNotVersioned,
    EditPlain,
    Create,
    CreateNotVersioned,
    CreateFolder,
    RenameFile,
    RenameFolder,
    MoveOne,
    MoveMany,
    CopyOne,
    Duplicate,
    CopyMany,
    DeleteOne,
    DeleteManyIn,
    DeleteMany,
    RestoreFileSha,
    RestoreFileTitle,
    RestoreFolderSha,
    RestoreFolderTitle,
    RestoreManySha,
    RestoreManyTitle,
    RestoreVault,
    RestoreVersion,
    RestoreCheckpoint,
    Upload,
    Replace,
    UploadNotVersioned,
    ReplaceNotVersioned,
    UploadMany,
    SaveVersion,
    SaveVersionPath,
    SaveVersionMany,
    ExternalEditLines,
    ExternalEditSize,
    ExternalEditNotVersioned,
    ExternalAdd,
    ExternalAddNotVersioned,
    ExternalDelete,
    AdoptOne,
    AdoptManyIn,
    AdoptMany,
}

impl LabelTemplate {
    /// Every row, in table order.
    pub const ALL: [LabelTemplate; 43] = [
        LabelTemplate::EditLines,
        LabelTemplate::EditSize,
        LabelTemplate::EditNotVersioned,
        LabelTemplate::EditPlain,
        LabelTemplate::Create,
        LabelTemplate::CreateNotVersioned,
        LabelTemplate::CreateFolder,
        LabelTemplate::RenameFile,
        LabelTemplate::RenameFolder,
        LabelTemplate::MoveOne,
        LabelTemplate::MoveMany,
        LabelTemplate::CopyOne,
        LabelTemplate::Duplicate,
        LabelTemplate::CopyMany,
        LabelTemplate::DeleteOne,
        LabelTemplate::DeleteManyIn,
        LabelTemplate::DeleteMany,
        LabelTemplate::RestoreFileSha,
        LabelTemplate::RestoreFileTitle,
        LabelTemplate::RestoreFolderSha,
        LabelTemplate::RestoreFolderTitle,
        LabelTemplate::RestoreManySha,
        LabelTemplate::RestoreManyTitle,
        LabelTemplate::RestoreVault,
        LabelTemplate::RestoreVersion,
        LabelTemplate::RestoreCheckpoint,
        LabelTemplate::Upload,
        LabelTemplate::Replace,
        LabelTemplate::UploadNotVersioned,
        LabelTemplate::ReplaceNotVersioned,
        LabelTemplate::UploadMany,
        LabelTemplate::SaveVersion,
        LabelTemplate::SaveVersionPath,
        LabelTemplate::SaveVersionMany,
        LabelTemplate::ExternalEditLines,
        LabelTemplate::ExternalEditSize,
        LabelTemplate::ExternalEditNotVersioned,
        LabelTemplate::ExternalAdd,
        LabelTemplate::ExternalAddNotVersioned,
        LabelTemplate::ExternalDelete,
        LabelTemplate::AdoptOne,
        LabelTemplate::AdoptManyIn,
        LabelTemplate::AdoptMany,
    ];

    /// A stable kebab-case id (golden row ids, client string-table keys).
    pub fn id(self) -> &'static str {
        match self {
            LabelTemplate::EditLines => "edit-lines",
            LabelTemplate::EditSize => "edit-size",
            LabelTemplate::EditNotVersioned => "edit-not-versioned",
            LabelTemplate::EditPlain => "edit-plain",
            LabelTemplate::Create => "create",
            LabelTemplate::CreateNotVersioned => "create-not-versioned",
            LabelTemplate::CreateFolder => "create-folder",
            LabelTemplate::RenameFile => "rename-file",
            LabelTemplate::RenameFolder => "rename-folder",
            LabelTemplate::MoveOne => "move-one",
            LabelTemplate::MoveMany => "move-many",
            LabelTemplate::CopyOne => "copy-one",
            LabelTemplate::Duplicate => "duplicate",
            LabelTemplate::CopyMany => "copy-many",
            LabelTemplate::DeleteOne => "delete-one",
            LabelTemplate::DeleteManyIn => "delete-many-in",
            LabelTemplate::DeleteMany => "delete-many",
            LabelTemplate::RestoreFileSha => "restore-file-sha",
            LabelTemplate::RestoreFileTitle => "restore-file-title",
            LabelTemplate::RestoreFolderSha => "restore-folder-sha",
            LabelTemplate::RestoreFolderTitle => "restore-folder-title",
            LabelTemplate::RestoreManySha => "restore-many-sha",
            LabelTemplate::RestoreManyTitle => "restore-many-title",
            LabelTemplate::RestoreVault => "restore-vault",
            LabelTemplate::RestoreVersion => "restore-version",
            LabelTemplate::RestoreCheckpoint => "restore-checkpoint",
            LabelTemplate::Upload => "upload",
            LabelTemplate::Replace => "replace",
            LabelTemplate::UploadNotVersioned => "upload-not-versioned",
            LabelTemplate::ReplaceNotVersioned => "replace-not-versioned",
            LabelTemplate::UploadMany => "upload-many",
            LabelTemplate::SaveVersion => "save-version",
            LabelTemplate::SaveVersionPath => "save-version-path",
            LabelTemplate::SaveVersionMany => "save-version-many",
            LabelTemplate::ExternalEditLines => "external-edit-lines",
            LabelTemplate::ExternalEditSize => "external-edit-size",
            LabelTemplate::ExternalEditNotVersioned => "external-edit-not-versioned",
            LabelTemplate::ExternalAdd => "external-add",
            LabelTemplate::ExternalAddNotVersioned => "external-add-not-versioned",
            LabelTemplate::ExternalDelete => "external-delete",
            LabelTemplate::AdoptOne => "adopt-one",
            LabelTemplate::AdoptManyIn => "adopt-many-in",
            LabelTemplate::AdoptMany => "adopt-many",
        }
    }

    /// The op token the row belongs to.
    pub fn op(self) -> &'static str {
        use LabelTemplate as T;
        match self {
            T::EditLines | T::EditSize | T::EditNotVersioned | T::EditPlain => OP_EDIT,
            T::Create | T::CreateNotVersioned => OP_CREATE,
            T::CreateFolder => OP_CREATE_FOLDER,
            T::RenameFile | T::RenameFolder => OP_RENAME,
            T::MoveOne | T::MoveMany => OP_MOVE,
            T::CopyOne | T::Duplicate | T::CopyMany => OP_COPY,
            T::DeleteOne | T::DeleteManyIn | T::DeleteMany => OP_DELETE,
            T::RestoreFileSha
            | T::RestoreFileTitle
            | T::RestoreFolderSha
            | T::RestoreFolderTitle
            | T::RestoreManySha
            | T::RestoreManyTitle
            | T::RestoreVault
            | T::RestoreVersion
            | T::RestoreCheckpoint => OP_RESTORE,
            T::Upload
            | T::Replace
            | T::UploadNotVersioned
            | T::ReplaceNotVersioned
            | T::UploadMany => OP_UPLOAD,
            T::SaveVersion | T::SaveVersionPath | T::SaveVersionMany => OP_SAVE_VERSION,
            T::ExternalEditLines
            | T::ExternalEditSize
            | T::ExternalEditNotVersioned
            | T::ExternalAdd
            | T::ExternalAddNotVersioned
            | T::ExternalDelete => OP_EDIT_EXTERNAL,
            T::AdoptOne | T::AdoptManyIn | T::AdoptMany => OP_ADOPT,
        }
    }

    /// The row in the notation of the MODULE-003 §1.4.1 "Labels" table: `P` path,
    /// `P2`/`Q` second path, `D/` folder, `N` count, `S` size, `+a −d` line stat, `T`
    /// title, `A/L` checkpoint, `sha7`.
    pub fn pattern(self) -> &'static str {
        use LabelTemplate as T;
        match self {
            T::EditLines => "Edit P (+a −d)",
            T::EditSize => "Edit P (S)",
            T::EditNotVersioned => "Edit P (S, not versioned)",
            T::EditPlain => "Edit P",
            T::Create => "Create P",
            T::CreateNotVersioned => "Create P (S, not versioned)",
            T::CreateFolder => "Create folder D/",
            T::RenameFile => "Rename P → P2",
            T::RenameFolder => "Rename D/ → D2/",
            T::MoveOne => "Move P → D/",
            T::MoveMany => "Move N items → D/",
            T::CopyOne => "Copy P → D/",
            T::Duplicate => "Duplicate P → Q",
            T::CopyMany => "Copy N items → D/",
            T::DeleteOne => "Delete P",
            T::DeleteManyIn => "Delete N items in D/",
            T::DeleteMany => "Delete N items",
            T::RestoreFileSha => "Restore P from sha7",
            T::RestoreFileTitle => "Restore P from “T”",
            T::RestoreFolderSha => "Restore D/ from sha7 (N items)",
            T::RestoreFolderTitle => "Restore D/ from “T” (N items)",
            T::RestoreManySha => "Restore N items from sha7",
            T::RestoreManyTitle => "Restore N items from “T”",
            T::RestoreVault => "Restore vault from sha7 (N items)",
            T::RestoreVersion => "Restore version “T” (N items)",
            T::RestoreCheckpoint => "Restore checkpoint A/L (N items)",
            T::Upload => "Upload P (S)",
            T::Replace => "Replace P (S)",
            T::UploadNotVersioned => "Upload P (S, not versioned)",
            T::ReplaceNotVersioned => "Replace P (S, not versioned)",
            T::UploadMany => "Upload N items → D/ (S)",
            T::SaveVersion => "Save version “T”",
            T::SaveVersionPath => "Save version “T” · P",
            T::SaveVersionMany => "Save version “T” · N items",
            T::ExternalEditLines => "Edit P in external app (+a −d)",
            T::ExternalEditSize => "Edit P in external app (S)",
            T::ExternalEditNotVersioned => "Edit P in external app (S, not versioned)",
            T::ExternalAdd => "Add P from external app (S)",
            T::ExternalAddNotVersioned => "Add P from external app (S, not versioned)",
            T::ExternalDelete => "Delete P in external app",
            T::AdoptOne => "Record uncommitted change to P",
            T::AdoptManyIn => "Record uncommitted changes to N items in D/",
            T::AdoptMany => "Record uncommitted changes to N items",
        }
    }
}

/// One golden row: the label, the template it renders with, its literal subject and the
/// full commit message (initiator `user:advance` with fixed provenance; adopt rows use
/// `runtime:adopt` and no provenance).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoldenLabel {
    /// Stable row id.
    pub id: &'static str,
    pub template: LabelTemplate,
    pub label: CommitLabel,
    pub subject: String,
    pub message: String,
}

// ── subject rendering ─────────────────────────────────────────────────────────────

/// The bidi controls (MODULE-003 §1.7): U+061C, U+200E, U+200F, U+202A–U+202E,
/// U+2066–U+2069.
fn is_bidi_control(c: char) -> bool {
    matches!(
        c,
        '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
    )
}

/// Characters that may never appear raw in a subject or a trailer value.
fn is_line_breaking_or_hidden(c: char) -> bool {
    c.is_control() || c == '\u{2028}' || c == '\u{2029}' || is_bidi_control(c)
}

/// An interpolated value as the subject shows it.
fn subject_safe(value: &str) -> String {
    value
        .chars()
        .map(|c| match c {
            '[' => '\u{FF3B}',
            ']' => '\u{FF3D}',
            '<' => '\u{2039}',
            '>' => '\u{203A}',
            '"' => '\u{FF02}',
            c if is_line_breaking_or_hidden(c) => '_',
            c => c,
        })
        .collect()
}

fn char_len(s: &str) -> usize {
    s.chars().count()
}

/// One piece of a subject: fixed text, an elidable path, or a truncatable text.
enum Part {
    Lit(String),
    Path(String),
    Text(String),
}

impl Part {
    fn text(&self) -> &str {
        match self {
            Part::Lit(s) | Part::Path(s) | Part::Text(s) => s,
        }
    }
}

fn lit(s: impl Into<String>) -> Part {
    Part::Lit(s.into())
}

fn path_part(s: &str) -> Part {
    Part::Path(subject_safe(s))
}

fn text_part(s: &str) -> Part {
    Part::Text(subject_safe(s))
}

fn is_dir_display(p: &str) -> bool {
    p.ends_with('/')
}

/// The parent folder of a display path, without its trailing `/`; `None` at the root.
fn parent_of(display: &str) -> Option<&str> {
    let body = display.strip_suffix('/').unwrap_or(display);
    body.rsplit_once('/').map(|(dir, _)| dir)
}

/// A folder as the subject shows it (`None` = the vault root, `/`).
fn dir_display(dir: Option<&str>) -> String {
    match dir {
        Some(dir) => format!("{dir}/"),
        None => "/".to_string(),
    }
}

/// The shared non-root parent folder of every path, when the label lists them all.
fn shared_parent(label: &CommitLabel) -> Option<String> {
    if label.count as usize != label.paths.len() || label.paths.len() < 2 {
        return None;
    }
    let mut paths = label.paths.iter();
    let first = parent_of(paths.next()?)?;
    if first.is_empty() {
        return None;
    }
    paths
        .all(|p| parent_of(p) == Some(first))
        .then(|| format!("{first}/"))
}

fn sha7(label: &CommitLabel) -> Option<String> {
    let sha = label.from_sha.as_deref()?;
    Some(subject_safe(&sha.chars().take(7).collect::<String>()))
}

fn items(n: u32) -> String {
    if n == 1 {
        "1 item".to_string()
    } else {
        format!("{n} items")
    }
}

/// The template and the parts of a label's subject; `None` for an unknown op or a missing
/// field the template needs.
fn plan(label: &CommitLabel) -> Option<(LabelTemplate, Vec<Part>)> {
    use LabelTemplate as T;
    let n = label.count;
    let p0 = label.paths.first().map(String::as_str);
    let to = label.to.as_deref();
    let size = label.size_bytes.map(format_size);
    let lines = match (label.lines_added, label.lines_removed) {
        (Some(added), Some(removed)) => Some((added, removed)),
        _ => None,
    };
    let not_versioned = label.versioned == Some(false);
    let change = label.change.as_deref();
    let title = label.title.as_deref();
    let planned = match label.op.as_str() {
        OP_EDIT => {
            let p = p0?;
            if not_versioned {
                (
                    T::EditNotVersioned,
                    vec![
                        lit("Edit "),
                        path_part(p),
                        lit(format!(" ({}, not versioned)", size?)),
                    ],
                )
            } else if let Some((added, removed)) = lines {
                if added == 0 && removed == 0 {
                    (T::EditPlain, vec![lit("Edit "), path_part(p)])
                } else {
                    (
                        T::EditLines,
                        vec![
                            lit("Edit "),
                            path_part(p),
                            lit(format!(" (+{added} −{removed})")),
                        ],
                    )
                }
            } else if let Some(size) = size {
                (
                    T::EditSize,
                    vec![lit("Edit "), path_part(p), lit(format!(" ({size})"))],
                )
            } else {
                (T::EditPlain, vec![lit("Edit "), path_part(p)])
            }
        }
        OP_CREATE => {
            let p = p0?;
            if not_versioned {
                (
                    T::CreateNotVersioned,
                    vec![
                        lit("Create "),
                        path_part(p),
                        lit(format!(" ({}, not versioned)", size?)),
                    ],
                )
            } else {
                (T::Create, vec![lit("Create "), path_part(p)])
            }
        }
        OP_CREATE_FOLDER => (T::CreateFolder, vec![lit("Create folder "), path_part(p0?)]),
        OP_RENAME => {
            let p = p0?;
            let template = if is_dir_display(p) {
                T::RenameFolder
            } else {
                T::RenameFile
            };
            (
                template,
                vec![lit("Rename "), path_part(p), lit(" → "), path_part(to?)],
            )
        }
        OP_MOVE => match n {
            0 => return None,
            1 => (
                T::MoveOne,
                vec![lit("Move "), path_part(p0?), lit(" → "), path_part(to?)],
            ),
            _ => (
                T::MoveMany,
                vec![lit(format!("Move {n} items → ")), path_part(to?)],
            ),
        },
        OP_COPY => match n {
            0 => return None,
            1 => {
                let p = p0?;
                let target = to?;
                // `to` is the new path, so a copy keeps the item's kind; a folder `to` for
                // a file (or the reverse) is not a label this lane writes.
                if is_dir_display(target) != is_dir_display(p) {
                    return None;
                }
                if parent_of(target) == parent_of(p) {
                    (
                        T::Duplicate,
                        vec![
                            lit("Duplicate "),
                            path_part(p),
                            lit(" → "),
                            path_part(target),
                        ],
                    )
                } else {
                    (
                        T::CopyOne,
                        vec![
                            lit("Copy "),
                            path_part(p),
                            lit(" → "),
                            path_part(&dir_display(parent_of(target))),
                        ],
                    )
                }
            }
            _ => (
                T::CopyMany,
                vec![lit(format!("Copy {n} items → ")), path_part(to?)],
            ),
        },
        OP_DELETE => match n {
            0 => return None,
            1 => (T::DeleteOne, vec![lit("Delete "), path_part(p0?)]),
            _ => match shared_parent(label) {
                Some(dir) => (
                    T::DeleteManyIn,
                    vec![lit(format!("Delete {n} items in ")), path_part(&dir)],
                ),
                None => (T::DeleteMany, vec![lit(format!("Delete {n} items"))]),
            },
        },
        OP_RESTORE => match p0 {
            None => match (label.checkpoint.as_deref(), title) {
                (Some(_), Some(title)) => (
                    T::RestoreVersion,
                    vec![
                        lit("Restore version “"),
                        text_part(title),
                        lit(format!("” ({})", items(n))),
                    ],
                ),
                (Some(checkpoint), None) => (
                    T::RestoreCheckpoint,
                    vec![
                        lit("Restore checkpoint "),
                        text_part(checkpoint),
                        lit(format!(" ({})", items(n))),
                    ],
                ),
                (None, _) => (
                    T::RestoreVault,
                    vec![lit(format!(
                        "Restore vault from {} ({})",
                        sha7(label)?,
                        items(n)
                    ))],
                ),
            },
            Some(p) if label.paths.len() == 1 && is_dir_display(p) => match title {
                Some(title) => (
                    T::RestoreFolderTitle,
                    vec![
                        lit("Restore "),
                        path_part(p),
                        lit(" from “"),
                        text_part(title),
                        lit(format!("” ({})", items(n))),
                    ],
                ),
                None => (
                    T::RestoreFolderSha,
                    vec![
                        lit("Restore "),
                        path_part(p),
                        lit(format!(" from {} ({})", sha7(label)?, items(n))),
                    ],
                ),
            },
            Some(p) if n == 1 => match title {
                Some(title) => (
                    T::RestoreFileTitle,
                    vec![
                        lit("Restore "),
                        path_part(p),
                        lit(" from “"),
                        text_part(title),
                        lit("”"),
                    ],
                ),
                None => (
                    T::RestoreFileSha,
                    vec![
                        lit("Restore "),
                        path_part(p),
                        lit(format!(" from {}", sha7(label)?)),
                    ],
                ),
            },
            Some(_) if n >= 2 => match title {
                Some(title) => (
                    T::RestoreManyTitle,
                    vec![
                        lit(format!("Restore {n} items from “")),
                        text_part(title),
                        lit("”"),
                    ],
                ),
                None => (
                    T::RestoreManySha,
                    vec![lit(format!("Restore {n} items from {}", sha7(label)?))],
                ),
            },
            Some(_) => return None,
        },
        OP_UPLOAD => match n {
            0 => return None,
            1 => {
                let p = p0?;
                let size = size?;
                let verb = if change == Some(CHANGE_REPLACED) {
                    "Replace "
                } else {
                    "Upload "
                };
                let template = match (change == Some(CHANGE_REPLACED), not_versioned) {
                    (false, false) => T::Upload,
                    (true, false) => T::Replace,
                    (false, true) => T::UploadNotVersioned,
                    (true, true) => T::ReplaceNotVersioned,
                };
                let tail = if not_versioned {
                    format!(" ({size}, not versioned)")
                } else {
                    format!(" ({size})")
                };
                (template, vec![lit(verb), path_part(p), lit(tail)])
            }
            _ => (
                T::UploadMany,
                vec![
                    lit(format!("Upload {n} items → ")),
                    path_part(to?),
                    lit(format!(" ({})", size?)),
                ],
            ),
        },
        OP_SAVE_VERSION => {
            let title = title?;
            match n {
                0 => (
                    T::SaveVersion,
                    vec![lit("Save version “"), text_part(title), lit("”")],
                ),
                1 => (
                    T::SaveVersionPath,
                    vec![
                        lit("Save version “"),
                        text_part(title),
                        lit("” · "),
                        path_part(p0?),
                    ],
                ),
                _ => (
                    T::SaveVersionMany,
                    vec![
                        lit("Save version “"),
                        text_part(title),
                        lit(format!("” · {n} items")),
                    ],
                ),
            }
        }
        OP_EDIT_EXTERNAL => {
            let p = p0?;
            match change {
                Some(CHANGE_DELETED) => (
                    T::ExternalDelete,
                    vec![lit("Delete "), path_part(p), lit(" in external app")],
                ),
                Some(CHANGE_ADDED) => {
                    let size = size?;
                    if not_versioned {
                        (
                            T::ExternalAddNotVersioned,
                            vec![
                                lit("Add "),
                                path_part(p),
                                lit(format!(" from external app ({size}, not versioned)")),
                            ],
                        )
                    } else {
                        (
                            T::ExternalAdd,
                            vec![
                                lit("Add "),
                                path_part(p),
                                lit(format!(" from external app ({size})")),
                            ],
                        )
                    }
                }
                _ => {
                    if not_versioned {
                        (
                            T::ExternalEditNotVersioned,
                            vec![
                                lit("Edit "),
                                path_part(p),
                                lit(format!(" in external app ({}, not versioned)", size?)),
                            ],
                        )
                    } else if let Some((added, removed)) = lines {
                        (
                            T::ExternalEditLines,
                            vec![
                                lit("Edit "),
                                path_part(p),
                                lit(format!(" in external app (+{added} −{removed})")),
                            ],
                        )
                    } else {
                        (
                            T::ExternalEditSize,
                            vec![
                                lit("Edit "),
                                path_part(p),
                                lit(format!(" in external app ({})", size?)),
                            ],
                        )
                    }
                }
            }
        }
        OP_ADOPT => match n {
            0 => return None,
            1 => (
                T::AdoptOne,
                vec![lit("Record uncommitted change to "), path_part(p0?)],
            ),
            _ => match shared_parent(label) {
                Some(dir) => (
                    T::AdoptManyIn,
                    vec![
                        lit(format!("Record uncommitted changes to {n} items in ")),
                        path_part(&dir),
                    ],
                ),
                None => (
                    T::AdoptMany,
                    vec![lit(format!("Record uncommitted changes to {n} items"))],
                ),
            },
        },
        _ => return None,
    };
    Some(planned)
}

/// Fit the parts into [`MAX_SUBJECT_CHARS`]: paths share what the fixed text and the
/// titles leave (at least [`MIN_PATH_BUDGET`] each), then a title or checkpoint takes what
/// is left and is end-truncated with `…`.
fn layout(parts: Vec<Part>) -> String {
    let total = parts.iter().fold(0usize, |acc, part| {
        acc.saturating_add(char_len(part.text()))
    });
    if total <= MAX_SUBJECT_CHARS {
        return parts.iter().map(Part::text).collect();
    }
    let mut fixed = 0usize;
    let mut path_slots = 0usize;
    let mut text_slots = 0usize;
    let mut text_len = 0usize;
    for part in &parts {
        match part {
            Part::Lit(s) => fixed = fixed.saturating_add(char_len(s)),
            Part::Path(_) => path_slots = path_slots.saturating_add(1),
            Part::Text(s) => {
                text_slots = text_slots.saturating_add(1);
                text_len = text_len.saturating_add(char_len(s));
            }
        }
    }
    let path_budget = MAX_SUBJECT_CHARS
        .saturating_sub(fixed.saturating_add(text_len))
        .checked_div(path_slots)
        .unwrap_or(0)
        .max(MIN_PATH_BUDGET);
    let parts: Vec<Part> = parts
        .into_iter()
        .map(|part| match part {
            Part::Path(s) => Part::Path(elide_path(&s, path_budget)),
            other => other,
        })
        .collect();
    let paths_len = parts.iter().fold(0usize, |acc, part| match part {
        Part::Path(s) => acc.saturating_add(char_len(s)),
        _ => acc,
    });
    let text_budget = MAX_SUBJECT_CHARS
        .saturating_sub(fixed.saturating_add(paths_len))
        .checked_div(text_slots)
        .unwrap_or(0);
    parts
        .into_iter()
        .map(|part| match part {
            Part::Text(s) => truncate_text(&s, text_budget),
            Part::Lit(s) | Part::Path(s) => s,
        })
        .collect()
}

fn truncate_text(text: &str, budget: usize) -> String {
    if char_len(text) <= budget {
        return text.to_string();
    }
    if budget == 0 {
        return String::new();
    }
    let mut out: String = text.chars().take(budget.saturating_sub(1)).collect();
    out.push('…');
    out
}

/// The row a label renders with; `None` when [`render_subject`] would be `None`.
pub fn template_of(label: &CommitLabel) -> Option<LabelTemplate> {
    plan(label).map(|(template, _)| template)
}

/// The canonical-English subject (without the `[type] [initiator] ` prefix): at most
/// [`MAX_SUBJECT_CHARS`] scalars and invariant under the legacy audit sanitizer. `None`
/// for an unknown op or when a field the template needs is missing (a label the lane
/// never builds).
pub fn render_subject(label: &CommitLabel) -> Option<String> {
    plan(label).map(|(_, parts)| layout(parts))
}

/// A size `S` in SI units (1000), integer arithmetic, half-up rounding: `999 B`,
/// `1.0 KB`, `10 KB`, `1.2 MB`, `18446744 TB`.
pub fn format_size(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["KB", "MB", "GB", "TB"];
    if bytes < 1000 {
        return format!("{bytes} B");
    }
    let n = u128::from(bytes);
    let mut unit = 0usize;
    let mut divisor: u128 = 1000;
    while unit < 3 && n >= divisor.saturating_mul(1000) {
        unit = unit.saturating_add(1);
        divisor = divisor.saturating_mul(1000);
    }
    loop {
        let half = divisor.checked_div(2).unwrap_or(0);
        let name = UNITS.get(unit).copied().unwrap_or("TB");
        let tenths = n
            .saturating_mul(10)
            .saturating_add(half)
            .checked_div(divisor)
            .unwrap_or(0);
        if tenths < 100 {
            let whole = tenths.checked_div(10).unwrap_or(0);
            let tenth = tenths.checked_rem(10).unwrap_or(0);
            return format!("{whole}.{tenth} {name}");
        }
        let whole = n.saturating_add(half).checked_div(divisor).unwrap_or(0);
        if whole >= 1000 && unit < 3 {
            unit = unit.saturating_add(1);
            divisor = divisor.saturating_mul(1000);
            continue;
        }
        return format!("{whole} {name}");
    }
}

/// Elide a display path to at most `max(budget, 16)` scalars, deterministically, trying in
/// order: the path; `first/…/last` (three or more components); `…/last`;
/// `…/<head>…<ext>` (the extension is kept when it has 1–8 characters; a folder keeps its
/// `/`). Works on scalars, never on bytes.
pub fn elide_path(path: &str, budget: usize) -> String {
    let budget = budget.max(MIN_PATH_BUDGET);
    if char_len(path) <= budget {
        return path.to_string();
    }
    let (body, is_dir) = match path.strip_suffix('/') {
        Some(body) if !body.is_empty() => (body, true),
        _ => (path, false),
    };
    let components: Vec<&str> = body.split('/').collect();
    let first = components.first().copied().unwrap_or_default();
    let last = components.last().copied().unwrap_or_default();
    let tail = if is_dir {
        format!("{last}/")
    } else {
        last.to_string()
    };
    if components.len() >= 3 {
        let candidate = format!("{first}/…/{tail}");
        if char_len(&candidate) <= budget {
            return candidate;
        }
    }
    if components.len() >= 2 {
        let candidate = format!("…/{tail}");
        if char_len(&candidate) <= budget {
            return candidate;
        }
    }
    let prefix = if components.len() >= 2 { "…/" } else { "" };
    let (stem, suffix) = if is_dir {
        (last, "/".to_string())
    } else {
        split_extension(last)
    };
    let room = budget
        .saturating_sub(char_len(prefix))
        .saturating_sub(char_len(&suffix))
        .saturating_sub(1);
    let head: String = stem.chars().take(room).collect();
    format!("{prefix}{head}…{suffix}")
}

/// `("report", ".pdf")` for `report.pdf`; no extension when it is longer than 8 characters
/// or the name starts with its only dot.
fn split_extension(name: &str) -> (&str, String) {
    match name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() && (1..=8).contains(&char_len(ext)) => {
            (stem, format!(".{ext}"))
        }
        _ => (name, String::new()),
    }
}

// ── trailers ──────────────────────────────────────────────────────────────────────

fn escape_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        if c == '%' || is_line_breaking_or_hidden(c) {
            let mut buf = [0u8; 4];
            for byte in c.encode_utf8(&mut buf).bytes() {
                let _ = write!(out, "%{byte:02X}");
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => byte.checked_sub(b'0'),
        b'A'..=b'F' => byte.checked_sub(b'A').and_then(|v| v.checked_add(10)),
        b'a'..=b'f' => byte.checked_sub(b'a').and_then(|v| v.checked_add(10)),
        _ => None,
    }
}

/// Percent-decode a trailer value; `None` for a malformed escape or non-UTF-8 bytes.
fn unescape_value(value: &str) -> Option<String> {
    if !value.contains('%') {
        return Some(value.to_string());
    }
    let mut bytes = Vec::with_capacity(value.len());
    let mut iter = value.bytes();
    while let Some(byte) = iter.next() {
        if byte == b'%' {
            let high = hex_digit(iter.next()?)?;
            let low = hex_digit(iter.next()?)?;
            bytes.push(high.checked_mul(16)?.checked_add(low)?);
        } else {
            bytes.push(byte);
        }
    }
    String::from_utf8(bytes).ok()
}

fn push_trailer(out: &mut String, key: &str, value: &str) {
    out.push_str(key);
    out.push_str(": ");
    out.push_str(&escape_value(value));
    out.push('\n');
}

/// The `Advance-*` trailer block, one `Key: value` line each, newline-terminated, in a
/// fixed order: Op, Path (≤ 64), To, Count, Change, Lines (`+a -d`, only when both counts
/// are set), Size, Versioned, From, Checkpoint, Title, then the provenance pair.
pub fn render_trailers(label: &CommitLabel, provenance: Option<&Provenance>) -> String {
    let mut out = String::new();
    push_trailer(&mut out, KEY_OP, &label.op);
    for path in label.paths.iter().take(MAX_LABEL_PATHS) {
        push_trailer(&mut out, KEY_PATH, path);
    }
    if let Some(to) = &label.to {
        push_trailer(&mut out, KEY_TO, to);
    }
    push_trailer(&mut out, KEY_COUNT, &label.count.to_string());
    if let Some(change) = &label.change {
        push_trailer(&mut out, KEY_CHANGE, change);
    }
    if let (Some(added), Some(removed)) = (label.lines_added, label.lines_removed) {
        push_trailer(&mut out, KEY_LINES, &format!("+{added} -{removed}"));
    }
    if let Some(size) = label.size_bytes {
        push_trailer(&mut out, KEY_SIZE, &size.to_string());
    }
    if let Some(versioned) = label.versioned {
        push_trailer(
            &mut out,
            KEY_VERSIONED,
            if versioned { "true" } else { "false" },
        );
    }
    if let Some(from) = &label.from_sha {
        push_trailer(&mut out, KEY_FROM, from);
    }
    if let Some(checkpoint) = &label.checkpoint {
        push_trailer(&mut out, KEY_CHECKPOINT, checkpoint);
    }
    if let Some(title) = &label.title {
        push_trailer(&mut out, KEY_TITLE, title);
    }
    if let Some(provenance) = provenance {
        push_trailer(&mut out, KEY_CLIENT, &provenance.client);
        push_trailer(&mut out, KEY_SESSION, &provenance.session);
    }
    out
}

/// The full commit message `[<type>] [<initiator>] <subject>\n\n<trailers>`: type `micro`
/// for the `adopt` op, `user` otherwise. `None` when the subject cannot be rendered.
pub fn render_message(
    label: &CommitLabel,
    initiator: &str,
    provenance: Option<&Provenance>,
) -> Option<String> {
    let subject = render_subject(label)?;
    let commit_type = if label.op == OP_ADOPT {
        CommitType::Micro
    } else {
        CommitType::User
    };
    Some(format!(
        "[{commit_type}] [{}] {subject}\n\n{}",
        sanitize_audit_field(initiator),
        render_trailers(label, provenance)
    ))
}

fn is_trailer_key(key: &str) -> bool {
    key.strip_prefix("Advance-").is_some_and(|rest| {
        !rest.is_empty()
            && rest
                .split('-')
                .all(|word| !word.is_empty() && word.chars().all(|c| c.is_ascii_alphabetic()))
    })
}

/// The `(key, raw value)` pairs of the message's last paragraph, when every line of it is
/// an `Advance-*` trailer.
fn trailer_block(message: &str) -> Option<Vec<(&str, &str)>> {
    let body = message.strip_suffix('\n').unwrap_or(message);
    let (_, block) = body.rsplit_once("\n\n")?;
    if block.is_empty() {
        return None;
    }
    let mut pairs = Vec::new();
    for line in block.split('\n') {
        let (key, value) = line.split_once(": ")?;
        if !is_trailer_key(key) {
            return None;
        }
        pairs.push((key, value));
    }
    Some(pairs)
}

fn parse_decimal<T: std::str::FromStr>(raw: &str) -> Option<T> {
    if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    raw.parse().ok()
}

fn parse_lines(raw: &str) -> Option<(u64, u64)> {
    let (added, removed) = raw.strip_prefix('+')?.split_once(" -")?;
    Some((parse_decimal(added)?, parse_decimal(removed)?))
}

/// Parse the trailer block back into a label. The last paragraph must consist of
/// `Advance-*` lines only; exactly one `Advance-Op` with a known token and one decimal
/// `Advance-Count` are required. A single-valued key keeps its first occurrence; a
/// malformed escape or number drops that field (a malformed `Advance-Path` entry is
/// skipped); at most [`MAX_LABEL_PATHS`] paths are kept; unknown keys and the provenance
/// pair are ignored.
///
/// This parses any message. Trust comes from [`label_of`], which only parses commits that
/// carry the lane's signatures.
pub fn parse_trailers(message: &str) -> Option<CommitLabel> {
    let pairs = trailer_block(message)?;
    let mut label = CommitLabel::default();
    let mut op: Option<String> = None;
    let mut ops = 0usize;
    let mut count: Option<u32> = None;
    let mut seen: HashSet<&str> = HashSet::new();
    for (key, raw) in pairs {
        match key {
            KEY_OP => {
                ops = ops.saturating_add(1);
                op = unescape_value(raw);
            }
            KEY_PATH => {
                if label.paths.len() < MAX_LABEL_PATHS {
                    if let Some(path) = unescape_value(raw) {
                        label.paths.push(path);
                    }
                }
            }
            _ if !seen.insert(key) => {}
            KEY_TO => label.to = unescape_value(raw),
            KEY_COUNT => count = parse_decimal(raw),
            KEY_CHANGE => {
                label.change =
                    unescape_value(raw).filter(|change| CHANGE_TOKENS.contains(&change.as_str()));
            }
            KEY_LINES => {
                if let Some((added, removed)) = parse_lines(raw) {
                    label.lines_added = Some(added);
                    label.lines_removed = Some(removed);
                }
            }
            KEY_SIZE => label.size_bytes = parse_decimal(raw),
            KEY_VERSIONED => {
                label.versioned = match raw {
                    "true" => Some(true),
                    "false" => Some(false),
                    _ => None,
                };
            }
            KEY_FROM => label.from_sha = unescape_value(raw),
            KEY_CHECKPOINT => label.checkpoint = unescape_value(raw),
            KEY_TITLE => label.title = unescape_value(raw),
            _ => {}
        }
    }
    if ops != 1 {
        return None;
    }
    let op = op?;
    if !OP_TOKENS.contains(&op.as_str()) {
        return None;
    }
    label.op = op;
    label.count = count?;
    Some(label)
}

/// The `Advance-Client` / `Advance-Session` pair of a trailer block (MODULE-003 §1.7), when
/// both are present and decode.
pub fn parse_provenance(message: &str) -> Option<Provenance> {
    let pairs = trailer_block(message)?;
    let value = |key: &str| {
        pairs
            .iter()
            .find(|(k, _)| *k == key)
            .and_then(|(_, raw)| unescape_value(raw))
    };
    Some(Provenance {
        client: value(KEY_CLIENT)?,
        session: value(KEY_SESSION)?,
    })
}

/// The label of a commit, parsed only when it carries the lane's signatures (MODULE-003
/// §1.7):
///
/// - first line `[user] [user:<h>] …`, author `user:<h> <user@advance-agents>` with the same
///   handle, committer `runtime <runtime@advance-agents>`, and an op other than `adopt`;
/// - first line `[micro] [runtime:adopt] …`, author == committer ==
///   `runtime <runtime@advance-agents>`, and the `adopt` op.
///
/// Every other commit (legacy, CLI or IDE commits, a trailer block without these
/// signatures) gets `None`. Git signatures are not authenticated: this is best-effort
/// attribution against writers outside the runtime; inside it the legacy lane flattens
/// newlines, so no legacy caller can produce a trailer block.
pub(crate) fn label_of(commit: &git2::Commit<'_>) -> Option<CommitLabel> {
    let message = commit.message()?;
    let first_line = message.split('\n').next().unwrap_or_default();
    let author = commit.author();
    let committer = commit.committer();
    let is_runtime = |signature: &git2::Signature<'_>| {
        signature.name() == Some(RUNTIME_NAME) && signature.email() == Some(RUNTIME_EMAIL)
    };
    if let Some(rest) = first_line.strip_prefix("[user] [") {
        let (initiator, _) = rest.split_once("] ")?;
        let handle = initiator
            .strip_prefix(USER_NAMESPACE)
            .and_then(|r| r.strip_prefix(':'))?;
        if !is_valid_handle(handle)
            || author.name() != Some(initiator)
            || author.email() != Some(USER_EMAIL)
            || !is_runtime(&committer)
        {
            return None;
        }
        parse_trailers(message).filter(|label| label.op != OP_ADOPT)
    } else if first_line.starts_with(&format!("[micro] [{ADOPT_INITIATOR}] ")) {
        if !is_runtime(&author) || !is_runtime(&committer) {
            return None;
        }
        parse_trailers(message).filter(|label| label.op == OP_ADOPT)
    } else {
        None
    }
}

// ── titles and version labels ─────────────────────────────────────────────────────

/// Normalize a version title (MODULE-003 §1.4.3): every run of Unicode whitespace (U+3000 and
/// line breaks included) becomes one space; Cc, U+2028, U+2029 and the bidi controls are
/// dropped; the ends are trimmed. 1–80 scalars, else [`UserOpRefusal::InvalidTitle`].
/// `[ ] < > "` stay: the subject shows look-alikes and `Advance-Title` keeps them exactly.
pub fn normalize_title(raw: &str) -> Result<String, UserOpRefusal> {
    let mut out = String::with_capacity(raw.len());
    let mut space = false;
    for c in raw.chars() {
        if c.is_whitespace() {
            space = !out.is_empty();
            continue;
        }
        if is_line_breaking_or_hidden(c) {
            continue;
        }
        if space {
            out.push(' ');
            space = false;
        }
        out.push(c);
    }
    let len = char_len(&out);
    if len == 0 || len > MAX_TITLE_CHARS {
        return Err(UserOpRefusal::InvalidTitle);
    }
    Ok(out)
}

/// `YYYYMMDD-HHMMSS` in UTC (clamped to the years 1970–9999).
fn utc_stamp(at: SystemTime) -> String {
    const MAX_SECONDS: i64 = 253_402_300_799; // 9999-12-31T23:59:59Z
    let seconds = match at.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(elapsed) => i64::try_from(elapsed.as_secs())
            .unwrap_or(MAX_SECONDS)
            .min(MAX_SECONDS),
        Err(_) => 0,
    };
    let at = chrono::DateTime::from_timestamp(seconds, 0).unwrap_or_default();
    format!(
        "{:04}{:02}{:02}-{:02}{:02}{:02}",
        at.year(),
        at.month(),
        at.day(),
        at.hour(),
        at.minute(),
        at.second()
    )
}

/// The title's ASCII slug: NFKD with combining marks skipped, runs of `[A-Za-z0-9]`
/// lowercased and joined with `-`, at most 40 characters cut on a `-` boundary (a first
/// run longer than that is cut to 40).
fn slug_of(title: &str) -> String {
    let mut runs: Vec<String> = Vec::new();
    let mut current = String::new();
    for c in title.nfkd() {
        if is_combining_mark(c) {
            continue;
        }
        if c.is_ascii_alphanumeric() {
            current.push(c.to_ascii_lowercase());
        } else if !current.is_empty() {
            runs.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        runs.push(current);
    }
    let mut slug = String::new();
    for run in runs {
        let needed = if slug.is_empty() {
            run.len()
        } else {
            slug.len().saturating_add(1).saturating_add(run.len())
        };
        if needed > MAX_SLUG_CHARS {
            if slug.is_empty() {
                slug = run.chars().take(MAX_SLUG_CHARS).collect();
            }
            break;
        }
        if !slug.is_empty() {
            slug.push('-');
        }
        slug.push_str(&run);
    }
    slug
}

/// A free version label for `title` at `at` (MODULE-003 §1.4.3): `YYYYMMDD-HHMMSS` in UTC,
/// plus `-<slug>` when the slug has at least 3 characters; on a collision with `existing`
/// (compared case-insensitively, as loose refs share a directory on a case-insensitive
/// volume) `-2` … `-99` is appended; past that [`UserOpRefusal::VersionLabelExhausted`].
/// Every result is a valid ref component and matches `[A-Za-z0-9._-]{1,128}`.
pub fn version_label<'a, I>(
    title: &str,
    at: SystemTime,
    existing: I,
) -> Result<String, UserOpRefusal>
where
    I: IntoIterator<Item = &'a str>,
{
    let taken: HashSet<String> = existing.into_iter().map(str::to_lowercase).collect();
    let stamp = utc_stamp(at);
    let slug = slug_of(title);
    let stem = if slug.len() >= MIN_SLUG_CHARS {
        format!("{stamp}-{slug}")
    } else {
        stamp
    };
    if !taken.contains(&stem.to_lowercase()) {
        return Ok(stem);
    }
    for suffix in 2..=MAX_VERSION_SUFFIX {
        let candidate = format!("{stem}-{suffix}");
        if !taken.contains(&candidate.to_lowercase()) {
            return Ok(candidate);
        }
    }
    Err(UserOpRefusal::VersionLabelExhausted)
}

// ── golden ────────────────────────────────────────────────────────────────────────

/// The initiator of the golden user rows.
pub const GOLDEN_INITIATOR: &str = "user:advance";
/// The provenance of the golden user rows.
pub fn golden_provenance() -> Provenance {
    Provenance {
        client: "macos".to_string(),
        session: "0123456789abcdef".to_string(),
    }
}

const GOLDEN_SHA: &str = "3f9c2a1b5d7e9f0a1b2c3d4e5f6a7b8c9d0e1f2a";

fn golden_label(op: &str, paths: &[&str], count: u32) -> CommitLabel {
    CommitLabel {
        op: op.to_string(),
        paths: paths.iter().map(|p| p.to_string()).collect(),
        count,
        ..CommitLabel::default()
    }
}

fn golden_row(
    id: &'static str,
    template: LabelTemplate,
    label: CommitLabel,
    subject: &str,
) -> GoldenLabel {
    let adopt = label.op == OP_ADOPT;
    let initiator = if adopt {
        ADOPT_INITIATOR
    } else {
        GOLDEN_INITIATOR
    };
    let provenance = (!adopt).then(golden_provenance);
    let message = render_message(&label, initiator, provenance.as_ref()).unwrap_or_default();
    GoldenLabel {
        id,
        template,
        label,
        subject: subject.to_string(),
        message,
    }
}

/// The label golden (source of `sdk-artifacts/conformance/labels.json`): a literal subject
/// for every [`LabelTemplate`] row, plus CJK, emoji-ZWJ, sanitizer, `%`-escaping, elision,
/// vault-root, `count > paths` and one-item rows. Clients check their renderers against
/// the rows whose subject has no `…`.
pub fn golden_cases() -> Vec<GoldenLabel> {
    use LabelTemplate as T;
    let sha = || Some(GOLDEN_SHA.to_string());
    let s = |value: &str| Some(value.to_string());
    let drafts: Vec<String> = (0..MAX_LABEL_PATHS)
        .map(|i| format!("drafts/note-{i:02}.md"))
        .collect();
    let drafts: Vec<&str> = drafts.iter().map(String::as_str).collect();
    vec![
        golden_row(
            "edit-lines",
            T::EditLines,
            CommitLabel {
                lines_added: Some(12),
                lines_removed: Some(3),
                ..golden_label(OP_EDIT, &["notes/plan.md"], 1)
            },
            "Edit notes/plan.md (+12 −3)",
        ),
        golden_row(
            "edit-size",
            T::EditSize,
            CommitLabel {
                size_bytes: Some(1_234_567),
                ..golden_label(OP_EDIT, &["images/logo.png"], 1)
            },
            "Edit images/logo.png (1.2 MB)",
        ),
        golden_row(
            "edit-not-versioned",
            T::EditNotVersioned,
            CommitLabel {
                size_bytes: Some(11_534_336),
                versioned: Some(false),
                ..golden_label(OP_EDIT, &["media/demo.mov"], 1)
            },
            "Edit media/demo.mov (12 MB, not versioned)",
        ),
        golden_row(
            "edit-plain",
            T::EditPlain,
            CommitLabel {
                lines_added: Some(0),
                lines_removed: Some(0),
                ..golden_label(OP_EDIT, &["scripts/run.sh"], 1)
            },
            "Edit scripts/run.sh",
        ),
        golden_row(
            "create",
            T::Create,
            CommitLabel {
                lines_added: Some(3),
                lines_removed: Some(0),
                ..golden_label(OP_CREATE, &["notes/Untitled.md"], 1)
            },
            "Create notes/Untitled.md",
        ),
        golden_row(
            "create-not-versioned",
            T::CreateNotVersioned,
            CommitLabel {
                size_bytes: Some(11_000_000),
                versioned: Some(false),
                ..golden_label(OP_CREATE, &["media/big.bin"], 1)
            },
            "Create media/big.bin (11 MB, not versioned)",
        ),
        golden_row(
            "create-folder",
            T::CreateFolder,
            golden_label(OP_CREATE_FOLDER, &["research/q4/"], 2),
            "Create folder research/q4/",
        ),
        golden_row(
            "rename-file",
            T::RenameFile,
            CommitLabel {
                to: s("notes/b.md"),
                ..golden_label(OP_RENAME, &["notes/a.md"], 1)
            },
            "Rename notes/a.md → notes/b.md",
        ),
        golden_row(
            "rename-folder",
            T::RenameFolder,
            CommitLabel {
                to: s("archive-2026/"),
                ..golden_label(OP_RENAME, &["drafts/"], 1)
            },
            "Rename drafts/ → archive-2026/",
        ),
        golden_row(
            "move-one",
            T::MoveOne,
            CommitLabel {
                to: s("archive/"),
                ..golden_label(OP_MOVE, &["notes/a.md"], 1)
            },
            "Move notes/a.md → archive/",
        ),
        golden_row(
            "move-one-to-root",
            T::MoveOne,
            CommitLabel {
                to: s("/"),
                ..golden_label(OP_MOVE, &["notes/a.md"], 1)
            },
            "Move notes/a.md → /",
        ),
        golden_row(
            "move-many",
            T::MoveMany,
            CommitLabel {
                to: s("archive/"),
                ..golden_label(OP_MOVE, &["notes/a.md", "notes/b.md", "todo.md"], 3)
            },
            "Move 3 items → archive/",
        ),
        golden_row(
            "copy-one",
            T::CopyOne,
            CommitLabel {
                to: s("archive/plan.md"),
                change: s(CHANGE_ADDED),
                ..golden_label(OP_COPY, &["notes/plan.md"], 1)
            },
            "Copy notes/plan.md → archive/",
        ),
        golden_row(
            "duplicate",
            T::Duplicate,
            CommitLabel {
                to: s("notes/plan copy.md"),
                change: s(CHANGE_ADDED),
                ..golden_label(OP_COPY, &["notes/plan.md"], 1)
            },
            "Duplicate notes/plan.md → notes/plan copy.md",
        ),
        golden_row(
            "duplicate-folder",
            T::Duplicate,
            CommitLabel {
                to: s("research/q4 copy/"),
                change: s(CHANGE_ADDED),
                ..golden_label(OP_COPY, &["research/q4/"], 1)
            },
            "Duplicate research/q4/ → research/q4 copy/",
        ),
        golden_row(
            "copy-many",
            T::CopyMany,
            CommitLabel {
                to: s("archive/"),
                change: s(CHANGE_ADDED),
                ..golden_label(OP_COPY, &["notes/a.md", "notes/b.md"], 2)
            },
            "Copy 2 items → archive/",
        ),
        golden_row(
            "delete-one",
            T::DeleteOne,
            golden_label(OP_DELETE, &["drafts/x.md"], 1),
            "Delete drafts/x.md",
        ),
        golden_row(
            "delete-one-folder",
            T::DeleteOne,
            golden_label(OP_DELETE, &["drafts/old/"], 1),
            "Delete drafts/old/",
        ),
        golden_row(
            "delete-many-in",
            T::DeleteManyIn,
            golden_label(OP_DELETE, &["drafts/a.md", "drafts/b.md", "drafts/c.md"], 3),
            "Delete 3 items in drafts/",
        ),
        golden_row(
            "delete-many",
            T::DeleteMany,
            golden_label(OP_DELETE, &["a.md", "notes/b.md"], 2),
            "Delete 2 items",
        ),
        golden_row(
            "delete-many-beyond-path-cap",
            T::DeleteMany,
            golden_label(OP_DELETE, &drafts, 70),
            "Delete 70 items",
        ),
        golden_row(
            "restore-file-sha",
            T::RestoreFileSha,
            CommitLabel {
                from_sha: sha(),
                change: s(CHANGE_MODIFIED),
                ..golden_label(OP_RESTORE, &["plan.md"], 1)
            },
            "Restore plan.md from 3f9c2a1",
        ),
        golden_row(
            "restore-file-title",
            T::RestoreFileTitle,
            CommitLabel {
                from_sha: sha(),
                checkpoint: s("user/20261015-143210-q4-draft-v2"),
                title: s("Q4 draft v2"),
                change: s(CHANGE_MODIFIED),
                ..golden_label(OP_RESTORE, &["notes/plan.md"], 1)
            },
            "Restore notes/plan.md from “Q4 draft v2”",
        ),
        golden_row(
            "restore-folder-sha",
            T::RestoreFolderSha,
            CommitLabel {
                from_sha: sha(),
                ..golden_label(OP_RESTORE, &["notes/"], 4)
            },
            "Restore notes/ from 3f9c2a1 (4 items)",
        ),
        golden_row(
            "restore-folder-one-item",
            T::RestoreFolderSha,
            CommitLabel {
                from_sha: sha(),
                ..golden_label(OP_RESTORE, &["notes/"], 1)
            },
            "Restore notes/ from 3f9c2a1 (1 item)",
        ),
        golden_row(
            "restore-folder-title",
            T::RestoreFolderTitle,
            CommitLabel {
                from_sha: sha(),
                checkpoint: s("user/20261015-143210"),
                title: s("周报初稿"),
                ..golden_label(OP_RESTORE, &["notes/"], 4)
            },
            "Restore notes/ from “周报初稿” (4 items)",
        ),
        golden_row(
            "restore-many-sha",
            T::RestoreManySha,
            CommitLabel {
                from_sha: sha(),
                ..golden_label(OP_RESTORE, &["a.md", "b.md", "c.md"], 3)
            },
            "Restore 3 items from 3f9c2a1",
        ),
        golden_row(
            "restore-many-title",
            T::RestoreManyTitle,
            CommitLabel {
                from_sha: sha(),
                checkpoint: s("user/20261015-143210-q4"),
                title: s("Q4"),
                ..golden_label(OP_RESTORE, &["a.md", "b.md"], 2)
            },
            "Restore 2 items from “Q4”",
        ),
        golden_row(
            "restore-vault",
            T::RestoreVault,
            CommitLabel {
                from_sha: sha(),
                ..golden_label(OP_RESTORE, &[], 40)
            },
            "Restore vault from 3f9c2a1 (40 items)",
        ),
        golden_row(
            "restore-version",
            T::RestoreVersion,
            CommitLabel {
                from_sha: sha(),
                checkpoint: s("user/20261015-143210"),
                title: s("周报初稿"),
                ..golden_label(OP_RESTORE, &[], 40)
            },
            "Restore version “周报初稿” (40 items)",
        ),
        golden_row(
            "restore-checkpoint",
            T::RestoreCheckpoint,
            CommitLabel {
                from_sha: sha(),
                checkpoint: s("writer/pre-turn"),
                ..golden_label(OP_RESTORE, &[], 12)
            },
            "Restore checkpoint writer/pre-turn (12 items)",
        ),
        golden_row(
            "upload",
            T::Upload,
            CommitLabel {
                size_bytes: Some(1_234_567),
                change: s(CHANGE_ADDED),
                ..golden_label(OP_UPLOAD, &["report.pdf"], 1)
            },
            "Upload report.pdf (1.2 MB)",
        ),
        golden_row(
            "replace",
            T::Replace,
            CommitLabel {
                size_bytes: Some(1_234_567),
                change: s(CHANGE_REPLACED),
                ..golden_label(OP_UPLOAD, &["report.pdf"], 1)
            },
            "Replace report.pdf (1.2 MB)",
        ),
        golden_row(
            "upload-not-versioned",
            T::UploadNotVersioned,
            CommitLabel {
                size_bytes: Some(11_534_336),
                versioned: Some(false),
                change: s(CHANGE_ADDED),
                ..golden_label(OP_UPLOAD, &["media/demo.mov"], 1)
            },
            "Upload media/demo.mov (12 MB, not versioned)",
        ),
        golden_row(
            "replace-not-versioned",
            T::ReplaceNotVersioned,
            CommitLabel {
                size_bytes: Some(11_534_336),
                versioned: Some(false),
                change: s(CHANGE_REPLACED),
                ..golden_label(OP_UPLOAD, &["media/demo.mov"], 1)
            },
            "Replace media/demo.mov (12 MB, not versioned)",
        ),
        golden_row(
            "upload-many",
            T::UploadMany,
            CommitLabel {
                to: s("reports/"),
                size_bytes: Some(4_200_000),
                change: s(CHANGE_ADDED),
                ..golden_label(
                    OP_UPLOAD,
                    &["reports/a.pdf", "reports/b.pdf", "reports/c.pdf"],
                    3,
                )
            },
            "Upload 3 items → reports/ (4.2 MB)",
        ),
        golden_row(
            "save-version",
            T::SaveVersion,
            CommitLabel {
                checkpoint: s("user/20261015-143210-q4-draft"),
                title: s("Q4 draft"),
                ..golden_label(OP_SAVE_VERSION, &[], 0)
            },
            "Save version “Q4 draft”",
        ),
        golden_row(
            "save-version-path",
            T::SaveVersionPath,
            CommitLabel {
                checkpoint: s("user/20261015-143210-q4-draft"),
                title: s("Q4 draft"),
                ..golden_label(OP_SAVE_VERSION, &["notes/plan.md"], 1)
            },
            "Save version “Q4 draft” · notes/plan.md",
        ),
        golden_row(
            "save-version-many",
            T::SaveVersionMany,
            CommitLabel {
                checkpoint: s("user/20261015-143210"),
                title: s("Q4"),
                ..golden_label(OP_SAVE_VERSION, &["a.md", "b.md", "c.md"], 3)
            },
            "Save version “Q4” · 3 items",
        ),
        golden_row(
            "external-edit-lines",
            T::ExternalEditLines,
            CommitLabel {
                lines_added: Some(3),
                lines_removed: Some(1),
                change: s(CHANGE_MODIFIED),
                ..golden_label(OP_EDIT_EXTERNAL, &["notes/plan.md"], 1)
            },
            "Edit notes/plan.md in external app (+3 −1)",
        ),
        golden_row(
            "external-edit-size",
            T::ExternalEditSize,
            CommitLabel {
                size_bytes: Some(52_000),
                change: s(CHANGE_MODIFIED),
                ..golden_label(OP_EDIT_EXTERNAL, &["report.docx"], 1)
            },
            "Edit report.docx in external app (52 KB)",
        ),
        golden_row(
            "external-edit-not-versioned",
            T::ExternalEditNotVersioned,
            CommitLabel {
                size_bytes: Some(11_534_336),
                versioned: Some(false),
                change: s(CHANGE_MODIFIED),
                ..golden_label(OP_EDIT_EXTERNAL, &["media/demo.mov"], 1)
            },
            "Edit media/demo.mov in external app (12 MB, not versioned)",
        ),
        golden_row(
            "external-add",
            T::ExternalAdd,
            CommitLabel {
                size_bytes: Some(1_234),
                change: s(CHANGE_ADDED),
                ..golden_label(OP_EDIT_EXTERNAL, &["notes/new.md"], 1)
            },
            "Add notes/new.md from external app (1.2 KB)",
        ),
        golden_row(
            "external-add-not-versioned",
            T::ExternalAddNotVersioned,
            CommitLabel {
                size_bytes: Some(11_000_000),
                versioned: Some(false),
                change: s(CHANGE_ADDED),
                ..golden_label(OP_EDIT_EXTERNAL, &["media/big.bin"], 1)
            },
            "Add media/big.bin from external app (11 MB, not versioned)",
        ),
        golden_row(
            "external-delete",
            T::ExternalDelete,
            CommitLabel {
                change: s(CHANGE_DELETED),
                ..golden_label(OP_EDIT_EXTERNAL, &["notes/old.md"], 1)
            },
            "Delete notes/old.md in external app",
        ),
        golden_row(
            "adopt-one",
            T::AdoptOne,
            golden_label(OP_ADOPT, &["notes/plan.md"], 1),
            "Record uncommitted change to notes/plan.md",
        ),
        golden_row(
            "adopt-many-in",
            T::AdoptManyIn,
            golden_label(OP_ADOPT, &["notes/a.md", "notes/b.md"], 2),
            "Record uncommitted changes to 2 items in notes/",
        ),
        golden_row(
            "adopt-many",
            T::AdoptMany,
            golden_label(OP_ADOPT, &["a.md", "notes/b.md"], 2),
            "Record uncommitted changes to 2 items",
        ),
        golden_row(
            "cjk",
            T::EditLines,
            CommitLabel {
                lines_added: Some(12),
                lines_removed: Some(3),
                ..golden_label(OP_EDIT, &["笔记/周报.md"], 1)
            },
            "Edit 笔记/周报.md (+12 −3)",
        ),
        golden_row(
            "emoji-zwj",
            T::Create,
            golden_label(OP_CREATE, &["notes/👨\u{200D}👩\u{200D}👧 family.md"], 1),
            "Create notes/👨\u{200D}👩\u{200D}👧 family.md",
        ),
        golden_row(
            "sanitizer",
            T::RenameFile,
            CommitLabel {
                to: s("notes/<b> \"final\".md"),
                ..golden_label(OP_RENAME, &["notes/[draft] a.md"], 1)
            },
            "Rename notes/［draft］ a.md → notes/‹b› ＂final＂.md",
        ),
        golden_row(
            "escaping",
            T::SaveVersionPath,
            CommitLabel {
                checkpoint: s("user/20261015-143210-sale-50-off-v2"),
                title: s("Sale 50% off [v2]"),
                ..golden_label(OP_SAVE_VERSION, &["notes/100% done.md"], 1)
            },
            "Save version “Sale 50% off ［v2］” · notes/100% done.md",
        ),
        golden_row(
            "elision",
            T::EditLines,
            CommitLabel {
                lines_added: Some(1),
                lines_removed: Some(0),
                ..golden_label(
                    OP_EDIT,
                    &["projects/2026/q4/research/very-long-folder-name-for-the-elision-test/another-quite-long-directory-name/final-report-draft.md"],
                    1,
                )
            },
            "Edit projects/…/final-report-draft.md (+1 −0)",
        ),
    ]
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
    use std::collections::HashMap;
    use std::time::Duration;

    fn label(op: &str, paths: &[&str], count: u32) -> CommitLabel {
        golden_label(op, paths, count)
    }

    fn subject(label: &CommitLabel) -> String {
        render_subject(label).unwrap()
    }

    fn first_line(label: &CommitLabel) -> String {
        render_message(label, GOLDEN_INITIATOR, None)
            .unwrap()
            .lines()
            .next()
            .unwrap()
            .to_string()
    }

    // MODULE-003 §1.4.1: the owner's seven examples, byte-exact with the prefix, plus rows
    // whose rule is easy to get wrong.
    #[test]
    fn templates_render_canonically() {
        let golden: HashMap<&str, GoldenLabel> =
            golden_cases().into_iter().map(|g| (g.id, g)).collect();
        for (id, expected) in [
            (
                "edit-lines",
                "[user] [user:advance] Edit notes/plan.md (+12 −3)",
            ),
            (
                "rename-file",
                "[user] [user:advance] Rename notes/a.md → notes/b.md",
            ),
            (
                "create-folder",
                "[user] [user:advance] Create folder research/q4/",
            ),
            ("delete-one", "[user] [user:advance] Delete drafts/x.md"),
            ("move-many", "[user] [user:advance] Move 3 items → archive/"),
            (
                "restore-file-sha",
                "[user] [user:advance] Restore plan.md from 3f9c2a1",
            ),
            ("upload", "[user] [user:advance] Upload report.pdf (1.2 MB)"),
        ] {
            assert_eq!(first_line(&golden[id].label), expected, "{id}");
        }
        assert_eq!(
            golden["adopt-one"].message.lines().next().unwrap(),
            "[micro] [runtime:adopt] Record uncommitted change to notes/plan.md"
        );

        // A copy into the same folder is a duplicate, into another folder a copy, and a
        // copy at the root shows the root as `/`.
        let copy = |to: &str| CommitLabel {
            to: Some(to.into()),
            ..label(OP_COPY, &["a.md"], 1)
        };
        assert_eq!(subject(&copy("b.md")), "Duplicate a.md → b.md");
        assert_eq!(subject(&copy("x/a.md")), "Copy a.md → x/");
        let copy_up = CommitLabel {
            to: Some("a.md".into()),
            ..label(OP_COPY, &["x/a.md"], 1)
        };
        assert_eq!(subject(&copy_up), "Copy x/a.md → /");
        // A shared root-level parent is not named.
        assert_eq!(
            subject(&label(OP_DELETE, &["a.md", "b.md"], 2)),
            "Delete 2 items"
        );
        // Restore aggregates are plural-aware; a folder restore takes the folder row
        // whatever its count.
        let vault = CommitLabel {
            from_sha: Some(GOLDEN_SHA.into()),
            ..label(OP_RESTORE, &[], 1)
        };
        assert_eq!(subject(&vault), "Restore vault from 3f9c2a1 (1 item)");
        // Unknown ops and missing fields render nothing.
        assert_eq!(render_subject(&label("bogus", &["a.md"], 1)), None);
        assert_eq!(render_subject(&label(OP_EDIT, &[], 1)), None);
        assert_eq!(render_subject(&label(OP_MOVE, &["a.md"], 1)), None);
        assert_eq!(render_subject(&label(OP_UPLOAD, &["a.md"], 1)), None);
        assert_eq!(render_subject(&label(OP_DELETE, &[], 0)), None);
        assert_eq!(render_subject(&label(OP_SAVE_VERSION, &[], 0)), None);
        assert_eq!(template_of(&label("bogus", &["a.md"], 1)), None);
    }

    // A single copy's `to` is the new path, so it has the source's kind. A destination
    // folder there (the other reading of a one-item copy) renders nothing instead of a
    // wrong subject such as `Copy notes/plan.md → /`.
    #[test]
    fn copy_one_keeps_the_items_kind() {
        let copy = |from: &str, to: &str| CommitLabel {
            to: Some(to.into()),
            change: Some(CHANGE_ADDED.into()),
            ..label(OP_COPY, &[from], 1)
        };
        for (from, to) in [
            ("notes/plan.md", "archive/"),
            ("notes/plan.md", "notes/"),
            ("research/q4/", "archive/q4.md"),
        ] {
            assert_eq!(render_subject(&copy(from, to)), None, "{from} → {to}");
            assert_eq!(template_of(&copy(from, to)), None, "{from} → {to}");
        }
        assert_eq!(
            subject(&copy("notes/plan.md", "archive/plan.md")),
            "Copy notes/plan.md → archive/"
        );
        assert_eq!(
            subject(&copy("research/q4/", "archive/q4/")),
            "Copy research/q4/ → archive/"
        );
        assert_eq!(
            subject(&copy("research/q4/", "research/q4 copy/")),
            "Duplicate research/q4/ → research/q4 copy/"
        );
        let many = CommitLabel {
            to: Some("archive/".into()),
            ..label(OP_COPY, &["a.md", "b/"], 2)
        };
        assert_eq!(subject(&many), "Copy 2 items → archive/");
    }

    // The `change` rule of `CommitLabel` (R5): upload, edit-external and copy always carry
    // it (copy: `added`), a restore only when the label names one restored file, and the
    // golden sets it nowhere else.
    #[test]
    fn golden_change_follows_the_documented_rule() {
        use LabelTemplate as T;
        for golden in golden_cases() {
            let change = golden.label.change.as_deref();
            let allowed: &[&str] = match golden.template {
                T::RestoreFileSha | T::RestoreFileTitle => {
                    &[CHANGE_ADDED, CHANGE_MODIFIED, CHANGE_DELETED]
                }
                _ => match golden.template.op() {
                    OP_UPLOAD => &[CHANGE_ADDED, CHANGE_REPLACED],
                    OP_EDIT_EXTERNAL => &[CHANGE_ADDED, CHANGE_MODIFIED, CHANGE_DELETED],
                    OP_COPY => &[CHANGE_ADDED],
                    _ => &[],
                },
            };
            if allowed.is_empty() {
                assert_eq!(change, None, "{}", golden.id);
            } else {
                assert!(
                    change.is_some_and(|c| allowed.contains(&c)),
                    "{}: {change:?}",
                    golden.id
                );
            }
        }
    }

    #[test]
    fn size_format_boundaries() {
        for (bytes, expected) in [
            (0, "0 B"),
            (999, "999 B"),
            (1_000, "1.0 KB"),
            (1_234, "1.2 KB"),
            (9_949, "9.9 KB"),
            (9_950, "10 KB"),
            (999_499, "999 KB"),
            (999_950, "1.0 MB"),
            (1_234_567, "1.2 MB"),
            (11_534_336, "12 MB"),
            (1_000_000_000_000, "1.0 TB"),
            (10_000_000_000_000_000, "10000 TB"),
            (u64::MAX, "18446744 TB"),
        ] {
            assert_eq!(format_size(bytes), expected, "{bytes}");
        }
    }

    #[test]
    fn elision_is_deterministic_and_bounded() {
        let long = format!("{}/{}.md", "资料".repeat(75), "周报".repeat(75));
        assert_eq!(long.chars().count(), 304);
        let edit = CommitLabel {
            lines_added: Some(1),
            lines_removed: Some(0),
            ..label(OP_EDIT, &[&long], 1)
        };
        let first = subject(&edit);
        assert!(first.chars().count() <= MAX_SUBJECT_CHARS, "{first}");
        assert!(first.ends_with(".md (+1 −0)"), "{first}");
        assert!(first.starts_with("Edit …/周报"), "{first}");
        assert_eq!(subject(&edit), first, "identical inputs, identical outputs");

        // Every stage of the elision ladder.
        let path = "alpha/beta/gamma/delta/epsilon-zeta-eta-theta.md";
        assert_eq!(elide_path(path, 100), path);
        assert_eq!(elide_path(path, 40), "alpha/…/epsilon-zeta-eta-theta.md");
        assert_eq!(elide_path(path, 30), "…/epsilon-zeta-eta-theta.md");
        assert_eq!(elide_path(path, 20), "…/epsilon-zeta-e….md");
        assert_eq!(elide_path("a/b/", 0), "a/b/");
        assert_eq!(
            elide_path("projects/very-long-folder-name-number-one/", 16),
            "…/very-long-fo…/"
        );
        assert_eq!(
            elide_path("averyveryverylongname.tar.gz", 16),
            "averyveryver….gz"
        );
        assert_eq!(
            elide_path("averyveryverylongname.extension", 16),
            "averyveryverylo…"
        );
        // The minimum budget is 16, whatever is asked.
        assert_eq!(elide_path(path, 3).chars().count(), 16);

        // A two-path template splits the budget; titles are cut after the paths.
        let rename = CommitLabel {
            to: Some(format!("{}/b.md", "y".repeat(150))),
            ..label(OP_RENAME, &[&format!("{}/a.md", "x".repeat(150))], 1)
        };
        let rendered = subject(&rename);
        assert!(rendered.chars().count() <= MAX_SUBJECT_CHARS, "{rendered}");
        assert!(rendered.contains("/a.md → "), "{rendered}");
        let restore = CommitLabel {
            from_sha: Some(GOLDEN_SHA.into()),
            title: Some("t".repeat(80)),
            checkpoint: Some("user/x".into()),
            ..label(OP_RESTORE, &[&format!("{}/", "d".repeat(90))], u32::MAX)
        };
        let rendered = subject(&restore);
        assert_eq!(
            template_of(&restore),
            Some(LabelTemplate::RestoreFolderTitle)
        );
        assert!(rendered.chars().count() <= MAX_SUBJECT_CHARS, "{rendered}");
        assert!(rendered.contains("…” (4294967295 items)"), "{rendered}");
    }

    #[test]
    fn subject_is_sanitizer_invariant() {
        let tricky = CommitLabel {
            to: Some("x/<y>\"z\".md".into()),
            ..label(OP_RENAME, &["a/[x]\r\u{202E}\u{2028}b.md"], 1)
        };
        let rendered = subject(&tricky);
        assert_eq!(rendered, "Rename a/［x］___b.md → x/‹y›＂z＂.md");
        assert_eq!(sanitize_audit_field(&rendered), rendered);
        let trailers = render_trailers(&tricky, None);
        assert!(trailers.contains("Advance-Path: a/[x]%0D%E2%80%AE%E2%80%A8b.md\n"));
        assert!(trailers.contains("Advance-To: x/<y>\"z\".md\n"));
        for golden in golden_cases() {
            assert_eq!(sanitize_audit_field(&golden.subject), golden.subject);
            let first = golden.message.lines().next().unwrap();
            assert!(first.ends_with(&format!("] {}", golden.subject)), "{first}");
        }
        // ZWJ, variation selectors and tag characters stay so emoji render.
        let emoji = label(
            OP_CREATE,
            &["🏳\u{FE0F}\u{200D}🌈 \u{1F3F4}\u{E0067}\u{E007F}.md"],
            1,
        );
        assert_eq!(
            subject(&emoji),
            "Create 🏳\u{FE0F}\u{200D}🌈 \u{1F3F4}\u{E0067}\u{E007F}.md"
        );
    }

    fn round_trip(label: &CommitLabel) -> CommitLabel {
        let message = format!(
            "[user] [user:advance] subject\n\n{}",
            render_trailers(label, Some(&golden_provenance()))
        );
        parse_trailers(&message).unwrap()
    }

    #[test]
    fn trailers_round_trip_with_escaping() {
        for op in OP_TOKENS {
            let full = CommitLabel {
                op: op.to_string(),
                paths: vec!["a/b.md".into(), "c/".into()],
                to: Some("d/".into()),
                count: 7,
                lines_added: Some(12),
                lines_removed: Some(0),
                size_bytes: Some(u64::MAX),
                versioned: Some(true),
                from_sha: Some(GOLDEN_SHA.into()),
                checkpoint: Some("user/20261015-143210".into()),
                title: Some("Q4".into()),
                change: Some(CHANGE_REPLACED.into()),
            };
            assert_eq!(round_trip(&full), full, "{op}");
            let bare = label(op, &[], 0);
            assert_eq!(round_trip(&bare), bare, "{op}");
        }
        let escaped = CommitLabel {
            paths: vec![
                "line\nbreak.md".into(),
                "carriage\rreturn.md".into(),
                "bidi\u{202E}x.md".into(),
                "sep\u{2028}x.md".into(),
                "100% done.md".into(),
                "trailing spaces.md   ".into(),
                "   leading.md".into(),
                "%41 is not A.md".into(),
                "nul\u{0}.md".into(),
            ],
            title: Some("t\n\nAdvance-Op: delete".into()),
            versioned: Some(false),
            ..label(OP_SAVE_VERSION, &[], 9)
        };
        let trailers = render_trailers(&escaped, None);
        assert!(!trailers.contains('\r'));
        assert_eq!(trailers.matches('\n').count(), 13, "{trailers}");
        assert!(trailers.contains("Advance-Path: 100%25 done.md\n"));
        assert!(trailers.contains("Advance-Path: trailing spaces.md   \n"));
        assert!(trailers.contains("Advance-Title: t%0A%0AAdvance-Op: delete\n"));
        assert_eq!(round_trip(&escaped), escaped);
        // The 64-path cap: 70 listed, 64 kept, the count stays.
        let many: Vec<String> = (0..70).map(|i| format!("p{i}.md")).collect();
        let many_refs: Vec<&str> = many.iter().map(String::as_str).collect();
        let big = label(OP_DELETE, &many_refs, 70);
        let parsed = round_trip(&big);
        assert_eq!(parsed.paths.len(), MAX_LABEL_PATHS);
        assert_eq!(parsed.paths[..], big.paths[..MAX_LABEL_PATHS]);
        assert_eq!(parsed.count, 70);
        // Provenance rides along and stays out of the label.
        let message = render_message(
            &golden_cases()[0].label,
            GOLDEN_INITIATOR,
            Some(&golden_provenance()),
        )
        .unwrap();
        assert_eq!(parse_provenance(&message), Some(golden_provenance()));
        assert_eq!(parse_trailers(&message).unwrap(), golden_cases()[0].label);
        assert!(!message.lines().next().unwrap().contains("macos"));
        let tricky = Provenance {
            client: "mac\nos".into(),
            session: "%%".into(),
        };
        let message = format!(
            "s\n\n{}",
            render_trailers(&label(OP_EDIT, &["a"], 1), Some(&tricky))
        );
        assert_eq!(parse_provenance(&message), Some(tricky));
        assert_eq!(
            parse_provenance("s\n\nAdvance-Op: edit\nAdvance-Count: 1\n"),
            None
        );
    }

    #[test]
    fn parse_trailers_rejects_foreign_bodies() {
        let ok = "x\n\nAdvance-Op: edit\nAdvance-Path: a.md\nAdvance-Count: 1\n";
        assert_eq!(parse_trailers(ok).unwrap().paths, vec!["a.md".to_string()]);
        assert!(
            parse_trailers(ok.trim_end()).is_some(),
            "trailing newline optional"
        );
        for bad in [
            "Advance-Op: edit\nAdvance-Count: 1", // no blank line
            "x\n\nAdvance-Op: edit\nAdvance-Count: 1\nnot a trailer", // mixed paragraph
            "x\n\nAdvance-Op: edit\nAdvance-Count: 1\n\nplain text\n", // last paragraph prose
            "x\n\nAdvance-Op: bogus\nAdvance-Count: 1\n", // unknown op
            "x\n\nAdvance-Op: edit\nAdvance-Op: edit\nAdvance-Count: 1\n", // two ops
            "x\n\nAdvance-Path: a.md\nAdvance-Count: 1\n", // no op
            "x\n\nAdvance-Op: edit\nAdvance-Path: a.md\n", // no count
            "x\n\nAdvance-Op: edit\nAdvance-Count: -1\n", // bad count
            "x\n\nAdvance-Op: edit\nAdvance-Count: +1\n", // signed count
            "x\n\nAdvance-Op:edit\nAdvance-Count: 1\n", // no ": "
            "x\n\nAdvance-: edit\nAdvance-Count: 1\n", // empty key word
            "x\n\nAdvance-Op--x: y\nAdvance-Op: edit\nAdvance-Count: 1\n", // bad key
            "x\n\nadvance-op: edit\nAdvance-Count: 1\n", // lowercase key
            "x\n\nAdvance-Op: ed%ZZit\nAdvance-Count: 1\n", // malformed op escape
            "x\n\nAdvance-Op: edit\nAdvance-Count: 1\n\n", // trailing blank line
            "",
            "\n\n",
        ] {
            assert_eq!(parse_trailers(bad), None, "{bad:?}");
        }
        // Unknown keys (cap-data's included) are ignored; bad numbers and escapes drop
        // only their field; the first single-valued key wins.
        let lenient = "x\n\nAdvance-Op: edit\nAdvance-Data-Op: upsert\nAdvance-Path: a.md\n\
                       Advance-Path: b%ZZ.md\nAdvance-Path: c%2.md\nAdvance-Count: 3\n\
                       Advance-Size: 12kb\nAdvance-Lines: +1 -x\nAdvance-Versioned: maybe\n\
                       Advance-Change: exploded\nAdvance-To: first\nAdvance-To: second\n\
                       Advance-Title: %FF%FE\n";
        let parsed = parse_trailers(lenient).unwrap();
        assert_eq!(
            parsed,
            CommitLabel {
                to: Some("first".into()),
                ..label(OP_EDIT, &["a.md"], 3)
            }
        );
    }

    fn commit_with(
        repo: &git2::Repository,
        author: (&str, &str),
        committer: (&str, &str),
        message: &str,
    ) -> git2::Oid {
        let when = git2::Time::new(1_700_000_000, 0);
        let author = git2::Signature::new(author.0, author.1, &when).unwrap();
        let committer = git2::Signature::new(committer.0, committer.1, &when).unwrap();
        let tree = repo.treebuilder(None).unwrap().write().unwrap();
        let tree = repo.find_tree(tree).unwrap();
        repo.commit(None, &author, &committer, message, &tree, &[])
            .unwrap()
    }

    #[test]
    fn label_of_requires_lane_signatures() {
        let td = tempfile::TempDir::new().unwrap();
        let repo = git2::Repository::init(td.path()).unwrap();
        let golden = golden_cases();
        let user_row = golden.iter().find(|g| g.id == "rename-file").unwrap();
        let adopt_row = golden.iter().find(|g| g.id == "adopt-many-in").unwrap();
        let user = ("user:advance", USER_EMAIL);
        let runtime = (RUNTIME_NAME, RUNTIME_EMAIL);
        let label_at = |oid: git2::Oid| label_of(&repo.find_commit(oid).unwrap());

        assert_eq!(
            label_at(commit_with(&repo, user, runtime, &user_row.message)),
            Some(user_row.label.clone())
        );
        assert_eq!(
            label_at(commit_with(&repo, runtime, runtime, &adopt_row.message)),
            Some(adopt_row.label.clone())
        );

        for (author, committer, message) in [
            // Foreign author or committer.
            (("someone", "x@y"), runtime, user_row.message.as_str()),
            (("user:advance", "x@y"), runtime, &user_row.message),
            (user, ("runtime", "x@y"), &user_row.message),
            (user, user, &user_row.message),
            // The prefix handle must be the author's.
            (("user:other", USER_EMAIL), runtime, &user_row.message),
            // An adopt label on a user commit and a user label on an adopt commit.
            (
                user,
                runtime,
                &adopt_row
                    .message
                    .replace("[micro] [runtime:adopt]", "[user] [user:advance]"),
            ),
            (
                runtime,
                runtime,
                &user_row
                    .message
                    .replace("[user] [user:advance]", "[micro] [runtime:adopt]"),
            ),
            // Adopt commits need runtime on both sides.
            (user, runtime, &adopt_row.message),
            // A legacy commit, even one whose message carried a trailer block (the legacy
            // lane flattens it), and a legacy-shaped prefix with a real block.
            (
                ("agent:a", RUNTIME_EMAIL),
                ("agent:a", RUNTIME_EMAIL),
                "[turn] [agent:a] x__Advance-Op: edit_Advance-Path: a.md",
            ),
            (
                ("agent:a", RUNTIME_EMAIL),
                ("agent:a", RUNTIME_EMAIL),
                "[turn] [agent:a] x\n\nAdvance-Op: edit\nAdvance-Count: 1\n",
            ),
            // Lane signatures but no trailer block.
            (user, runtime, "[user] [user:advance] Edit a.md"),
        ] {
            assert_eq!(
                label_at(commit_with(&repo, author, committer, message)),
                None,
                "{author:?} {committer:?} {message:?}"
            );
        }
    }

    #[test]
    fn title_normalization() {
        assert_eq!(
            normalize_title("  Q4\u{3000}draft \n v2 ").unwrap(),
            "Q4 draft v2"
        );
        assert_eq!(normalize_title("a\u{202E}b\u{2066}c").unwrap(), "abc");
        assert_eq!(normalize_title("a \u{7} b").unwrap(), "a b");
        assert_eq!(normalize_title("a\u{2028}b").unwrap(), "a b");
        assert_eq!(
            normalize_title("👨\u{200D}👩\u{200D}👧 plan").unwrap(),
            "👨\u{200D}👩\u{200D}👧 plan"
        );
        assert_eq!(
            normalize_title("[v2] <draft> \"x\"").unwrap(),
            "[v2] <draft> \"x\""
        );
        assert_eq!(normalize_title(&"字".repeat(80)).unwrap(), "字".repeat(80));
        for bad in ["", "   ", "\u{3000}\n", "\u{202E}\u{7}"] {
            assert_eq!(
                normalize_title(bad),
                Err(UserOpRefusal::InvalidTitle),
                "{bad:?}"
            );
        }
        assert_eq!(
            normalize_title(&"字".repeat(81)),
            Err(UserOpRefusal::InvalidTitle)
        );
    }

    fn at(seconds: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(seconds)
    }

    #[test]
    fn version_label_rules() {
        // 2026-10-15T14:32:10Z
        let t = at(1_792_074_730);
        let none: [&str; 0] = [];
        assert_eq!(
            version_label("Q4 draft v2", t, none).unwrap(),
            "20261015-143210-q4-draft-v2"
        );
        assert_eq!(
            version_label("周报初稿", t, none).unwrap(),
            "20261015-143210"
        );
        assert_eq!(version_label("ab", t, none).unwrap(), "20261015-143210");
        assert_eq!(
            version_label("naïve café", t, none).unwrap(),
            "20261015-143210-naive-cafe"
        );
        assert_eq!(
            version_label("Ｑ４ ﬁnal", t, none).unwrap(),
            "20261015-143210-q4-final"
        );
        let long = "alpha beta gamma delta epsilon zeta eta theta";
        let label = version_label(long, t, none).unwrap();
        // `-eta` still fits the 40-character cap; `-theta` does not.
        assert_eq!(
            label,
            "20261015-143210-alpha-beta-gamma-delta-epsilon-zeta-eta"
        );
        let unbroken = "x".repeat(60);
        assert_eq!(
            version_label(&unbroken, t, none).unwrap(),
            format!("20261015-143210-{}", "x".repeat(40))
        );
        // Collisions append -2 …, case-insensitively.
        assert_eq!(
            version_label("Q4 draft", t, ["20261015-143210-q4-draft"]).unwrap(),
            "20261015-143210-q4-draft-2"
        );
        assert_eq!(
            version_label(
                "Q4 draft",
                t,
                ["20261015-143210-Q4-DRAFT", "20261015-143210-q4-draft-2"]
            )
            .unwrap(),
            "20261015-143210-q4-draft-3"
        );
        let mut taken = vec!["20261015-143210".to_string()];
        taken.extend((2..=99).map(|n| format!("20261015-143210-{n}")));
        assert_eq!(
            version_label("x", t, taken.iter().map(String::as_str)),
            Err(UserOpRefusal::VersionLabelExhausted)
        );
        // Pre-epoch and far-future clocks are clamped, never panic.
        assert_eq!(
            version_label("x", SystemTime::UNIX_EPOCH - Duration::from_secs(5), none).unwrap(),
            "19700101-000000"
        );
        assert_eq!(
            version_label("x", at(u64::MAX / 4), none).unwrap(),
            "99991231-235959"
        );
        // Every label is a valid checkpoint ref component and Client API label.
        for title in ["Q4 draft v2", "周报初稿", long, &unbroken, "a.b..c", "---"] {
            let label = version_label(title, t, none).unwrap();
            crate::checkpoint::validate_ref_component(&label, "label").unwrap();
            assert!(crate::checkpoint::probe_tag_name_valid(&format!(
                "checkpoint/user/{label}"
            )));
            assert!(
                (1..=128).contains(&label.len())
                    && label
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')),
                "{label}"
            );
        }
    }

    /// xorshift64*: a deterministic generator (the workspace has no proptest).
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }

        fn below(&mut self, n: u64) -> u64 {
            self.next() % n.max(1)
        }

        fn chance(&mut self, percent: u64) -> bool {
            self.below(100) < percent
        }

        fn pick<'a>(&mut self, items: &[&'a str]) -> &'a str {
            items[self.below(items.len() as u64) as usize]
        }

        fn text(&mut self, max_pieces: u64) -> String {
            const PIECES: &[&str] = &[
                "a",
                "Z",
                "0",
                "/",
                "/",
                "-",
                ".",
                " ",
                "md",
                "周",
                "报",
                "👨\u{200D}👩\u{200D}👧",
                "e\u{301}",
                "\u{200C}",
                "\u{200D}",
                "\n",
                "\r",
                "\u{1}",
                "\u{0}",
                "\u{7F}",
                "\u{85}",
                "\u{202E}",
                "\u{2066}",
                "\u{200E}",
                "\u{61C}",
                "\u{2028}",
                "\u{2029}",
                "[",
                "]",
                "<",
                ">",
                "\"",
                "%",
                "%2",
                "%ZZ",
                "…",
                "→",
                "Ａ",
                "ſ",
                "\u{FE0F}",
                "\u{E0061}",
                ": ",
                "Advance-Op: ",
            ];
            let pieces = self.below(max_pieces + 1);
            (0..pieces).map(|_| self.pick(PIECES)).collect()
        }

        fn opt_text(&mut self, max_pieces: u64) -> Option<String> {
            self.chance(50).then(|| self.text(max_pieces))
        }
    }

    // MODULE-003-AC-29: 10 000 seeded inputs — no panic, the subject bound and sanitizer
    // invariance, an exact trailer round trip, the elision bound, the size shape.
    #[test]
    fn corpus_never_panics() {
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
        for _ in 0..10_000 {
            let op = if rng.chance(90) {
                rng.pick(&OP_TOKENS).to_string()
            } else {
                rng.text(3)
            };
            let path_count = if rng.chance(5) {
                rng.below(71)
            } else {
                rng.below(4)
            };
            let paths: Vec<String> = (0..path_count)
                .map(|_| {
                    if rng.chance(3) {
                        "長".repeat(1024)
                    } else {
                        let mut p = rng.text(12);
                        if rng.chance(20) {
                            p.push('/');
                        }
                        p
                    }
                })
                .collect();
            let lines = rng.chance(40).then(|| (rng.next(), rng.below(10)));
            let label = CommitLabel {
                op,
                paths,
                to: rng.opt_text(8),
                count: if rng.chance(10) {
                    rng.next() as u32
                } else {
                    rng.below(5) as u32
                },
                lines_added: lines.map(|l| l.0),
                lines_removed: lines.map(|l| l.1),
                size_bytes: rng.chance(50).then(|| rng.next()),
                versioned: match rng.below(3) {
                    0 => None,
                    1 => Some(true),
                    _ => Some(false),
                },
                from_sha: rng.opt_text(10),
                checkpoint: rng.opt_text(6),
                title: if rng.chance(5) {
                    Some("題".repeat(200))
                } else {
                    rng.opt_text(10)
                },
                change: rng.chance(60).then(|| rng.pick(&CHANGE_TOKENS).to_string()),
            };

            if let Some(rendered) = render_subject(&label) {
                assert!(rendered.chars().count() <= MAX_SUBJECT_CHARS, "{label:?}");
                assert_eq!(sanitize_audit_field(&rendered), rendered, "{label:?}");
                assert_eq!(template_of(&label).is_some(), true);
            } else {
                assert_eq!(template_of(&label), None);
            }

            let message = format!("x\n\n{}", render_trailers(&label, None));
            let parsed = parse_trailers(&message);
            if OP_TOKENS.contains(&label.op.as_str()) {
                let mut expected = label.clone();
                expected.paths.truncate(MAX_LABEL_PATHS);
                assert_eq!(parsed.as_ref(), Some(&expected), "{message:?}");
            } else {
                assert_eq!(parsed, None, "{message:?}");
            }

            let budget = rng.below(200) as usize;
            for path in label.paths.iter().take(3) {
                let elided = elide_path(path, budget);
                assert!(elided.chars().count() <= budget.max(MIN_PATH_BUDGET));
            }

            let size = format_size(rng.next() >> rng.below(64));
            let (number, unit) = size.split_once(' ').unwrap();
            assert!(["B", "KB", "MB", "GB", "TB"].contains(&unit), "{size}");
            assert!(
                number.chars().all(|c| c.is_ascii_digit() || c == '.'),
                "{size}"
            );

            // Arbitrary text is never a panic for the parsers or the title rules.
            let garbage = format!("{}\n\n{}", rng.text(6), rng.text(20));
            let _ = parse_trailers(&garbage);
            let _ = parse_provenance(&garbage);
            let _ = normalize_title(&rng.text(30));
            let _ = version_label(&rng.text(30), at(rng.below(1 << 40)), ["x"]);
        }
    }

    #[test]
    fn golden_cases_match_renderer() {
        for golden in golden_cases() {
            assert_eq!(
                template_of(&golden.label),
                Some(golden.template),
                "{}",
                golden.id
            );
            assert_eq!(golden.template.op(), golden.label.op, "{}", golden.id);
            assert_eq!(
                render_subject(&golden.label).as_deref(),
                Some(golden.subject.as_str()),
                "{}",
                golden.id
            );
            assert!(golden.subject.chars().count() <= MAX_SUBJECT_CHARS);
            let adopt = golden.label.op == OP_ADOPT;
            let (initiator, provenance) = if adopt {
                (ADOPT_INITIATOR, None)
            } else {
                (GOLDEN_INITIATOR, Some(golden_provenance()))
            };
            let message = render_message(&golden.label, initiator, provenance.as_ref());
            assert_eq!(
                message.as_deref(),
                Some(golden.message.as_str()),
                "{}",
                golden.id
            );
            let prefix = if adopt {
                "[micro] [runtime:adopt] "
            } else {
                "[user] [user:advance] "
            };
            assert_eq!(
                golden.message.lines().next().unwrap(),
                format!("{prefix}{}", golden.subject),
                "{}",
                golden.id
            );
            assert_eq!(
                parse_trailers(&golden.message).as_ref(),
                Some(&{
                    let mut capped = golden.label.clone();
                    capped.paths.truncate(MAX_LABEL_PATHS);
                    capped
                }),
                "{}",
                golden.id
            );
            assert_eq!(
                parse_provenance(&golden.message),
                provenance,
                "{}",
                golden.id
            );
        }
        // One full message, pinned byte for byte.
        let sanitizer = golden_cases()
            .into_iter()
            .find(|g| g.id == "escaping")
            .unwrap();
        assert_eq!(
            sanitizer.message,
            "[user] [user:advance] Save version “Sale 50% off ［v2］” · notes/100% done.md\n\
             \n\
             Advance-Op: save-version\n\
             Advance-Path: notes/100%25 done.md\n\
             Advance-Count: 1\n\
             Advance-Checkpoint: user/20261015-143210-sale-50-off-v2\n\
             Advance-Title: Sale 50%25 off [v2]\n\
             Advance-Client: macos\n\
             Advance-Session: 0123456789abcdef\n"
        );
    }

    // MODULE-003-T80 (AC-29, R5): the golden covers every template row, every change
    // kind and the special rows the client renderers rely on.
    #[test]
    fn golden_cases_cover_every_template_row() {
        let golden = golden_cases();
        let ids: HashSet<&str> = golden.iter().map(|g| g.id).collect();
        assert_eq!(ids.len(), golden.len(), "row ids are unique");
        let templates: HashSet<LabelTemplate> = golden.iter().map(|g| g.template).collect();
        for template in LabelTemplate::ALL {
            assert!(
                templates.contains(&template),
                "no golden row for {template:?}"
            );
        }
        let template_ids: HashSet<&str> = LabelTemplate::ALL.iter().map(|t| t.id()).collect();
        assert_eq!(template_ids.len(), LabelTemplate::ALL.len());
        let ops: HashSet<&str> = golden.iter().map(|g| g.label.op.as_str()).collect();
        for op in OP_TOKENS {
            assert!(ops.contains(op), "no golden row for op {op}");
        }
        let changes: HashSet<&str> = golden
            .iter()
            .filter_map(|g| g.label.change.as_deref())
            .collect();
        for change in CHANGE_TOKENS {
            assert!(
                changes.contains(change),
                "no golden row for change {change}"
            );
        }
        for special in [
            "cjk",
            "emoji-zwj",
            "sanitizer",
            "escaping",
            "elision",
            "move-one-to-root",
            "delete-many-beyond-path-cap",
            "restore-folder-one-item",
        ] {
            assert!(ids.contains(special), "missing special row {special}");
        }
        assert!(golden
            .iter()
            .any(|g| g.label.paths.iter().any(|p| p.contains('\u{200D}'))));
        assert!(golden.iter().any(|g| g.subject.contains('…')));
        for template in LabelTemplate::ALL {
            assert!(!template.pattern().is_empty());
        }
    }
}

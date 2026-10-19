//! Intent journal for operator mutations (oss-fs-core §7.5–§7.6).
//!
//! Records live at `<files-state>/journal/<op_id>.json` (dir 0700, files 0600),
//! written with write + fsync + rename + directory fsync before the first
//! workspace mutation. Schema v2 is `deny_unknown_fields` and holds no subject
//! or title; save-version is never a [`TypedOp`]. Caps: 1 000 records, 1 MiB
//! each. Load re-validates owner/mode/paths and deletes anything else.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unimplemented)]
#![deny(clippy::todo)]

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use advance_shared_types::file_identity::FileIdentity;
use advance_shared_types::workspace_path::{
    classify_lexical, normalize_workspace_path, AccessClass,
};
use serde::{Deserialize, Serialize};
use tokio::sync::Notify;
use tokio::task::JoinHandle;

use super::{CapacityKind, FilesError, OperatorFiles};

/// `v` on every persisted record (oss-fs-core §7.5).
pub const JOURNAL_SCHEMA_VERSION: u32 = 2;
/// Fail-closed cap: new mutations are refused (`capacity kind:journal`).
pub const JOURNAL_RECORD_CAP: usize = 1_000;
/// Maximum encoded record size.
pub const JOURNAL_RECORD_MAX_BYTES: usize = 1_048_576;
/// `open()` recovery: records processed.
pub const OPEN_RECOVER_MAX_RECORDS: usize = 200;
/// `open()` recovery time budget.
pub const OPEN_RECOVER_BUDGET: Duration = Duration::from_secs(2);

const JOURNAL_DIR_NAME: &str = "journal";
const DIR_MODE: u32 = 0o700;
const FILE_MODE: u32 = 0o600;

/// Typed user op stored in the journal. There is no save-version variant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum TypedOp {
    Edit,
    Create,
    CreateFolder,
    Rename,
    Move,
    Copy,
    Delete,
    Restore { sha: String },
    Upload,
    EditExternal,
}

/// One workspace effect inside a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemKind {
    Write,
    Mkdir,
    Move,
    Trash,
}

/// `(st_dev, st_ino)` captured before a move/trash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevIno {
    pub dev: u64,
    pub ino: u64,
}

/// One item of a journaled mutation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalItem {
    pub kind: ItemKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_rel: Option<String>,
    pub to_rel: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dev_ino: Option<DevIno>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pre_identity: Option<FileIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pre_oid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub post_identity: Option<FileIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub post_oid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry_pre: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temp_location: Option<String>,
}

/// Sidecar oid captured after the op wrote `dir/.meta.yaml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalMeta {
    pub dir_rel: String,
    pub post_oid: String,
}

/// Intent record (oss-fs-core §7.5). No subject, title, or free text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalRecord {
    pub v: u32,
    pub op_id: String,
    pub created_ms: u64,
    pub actor_handle: String,
    pub op: TypedOp,
    pub items: Vec<JournalItem>,
    pub metas: Vec<JournalMeta>,
    pub disk_changed: bool,
}

/// Disk observation used by recovery classification (identities only; no hashing).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ItemObservation {
    pub matches_pre: bool,
    pub matches_post: bool,
    pub pre_was_absent: bool,
    pub target_absent: bool,
    pub temp_remains: bool,
    pub from_absent: bool,
    pub to_absent: bool,
    pub to_holds_dev_ino: bool,
    pub trash_exists: bool,
    pub dir_exists: bool,
}

/// Per-item progress derived from [`ItemObservation`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ItemProgress {
    Done,
    None,
    Other,
}

/// Recovery class for one record (oss-fs-core §7.5 steps 2–5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryClass {
    AllDone,
    Superseded,
    NoneDone,
    Overtaken,
    Partial,
}

/// Summary of bounded `open()` recovery.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RecoverSummary {
    pub processed: usize,
    pub kept: usize,
    pub rejected: usize,
    pub superseded: usize,
    pub deferred: usize,
}

impl JournalRecord {
    pub fn new(op_id: String, actor_handle: String, op: TypedOp) -> Self {
        Self {
            v: JOURNAL_SCHEMA_VERSION,
            op_id,
            created_ms: now_ms(),
            actor_handle,
            op,
            items: Vec::new(),
            metas: Vec::new(),
            disk_changed: false,
        }
    }
}

/// `<files-state>/journal`.
pub fn journal_dir(files_state: &Path) -> PathBuf {
    files_state.join(JOURNAL_DIR_NAME)
}

/// True when `record` names `path` (or a parent/child of it) in an item or sidecar.
pub fn record_touches_path(record: &JournalRecord, path: &str) -> bool {
    record.items.iter().any(|item| {
        related_rel(&item.to_rel, path)
            || item
                .from_rel
                .as_deref()
                .is_some_and(|from| related_rel(from, path))
    }) || record
        .metas
        .iter()
        .any(|meta| related_rel(&meta.dir_rel, path))
}

fn related_rel(a: &str, b: &str) -> bool {
    if a == b {
        return true;
    }
    if a.is_empty() || b.is_empty() {
        return false;
    }
    b.starts_with(a) && b.as_bytes().get(a.len()) == Some(&b'/')
        || a.starts_with(b) && a.as_bytes().get(b.len()) == Some(&b'/')
}

/// Delete a persisted record (Committed / Unchanged). Missing is success.
pub fn drop_record(files_state: &Path, op_id: &str) -> Result<(), FilesError> {
    let path = journal_dir(files_state).join(json_name(op_id));
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(io_err(e)),
    }
}

/// Persist `record` with write + fsync + rename + directory fsync.
///
/// At [`JOURNAL_RECORD_CAP`] existing `*.json` names, returns
/// [`FilesError::Capacity`] `{ kind: Journal }` (history_backlog).
pub fn persist(files_state: &Path, record: &JournalRecord) -> Result<(), FilesError> {
    validate_record(record)?;
    let dir = ensure_journal_dir(files_state)?;
    let dest_name = PathBuf::from(json_name(&record.op_id));
    let existing = json_names(&dir)?;
    let replacing = existing.iter().any(|n| n == &dest_name);
    if existing.len() >= JOURNAL_RECORD_CAP && !replacing {
        return Err(FilesError::Capacity {
            kind: CapacityKind::Journal,
        });
    }
    let bytes = encode_record(record)?;
    atomic_write_0600(&dir, &record.op_id, &bytes)
}

/// Load every valid record (no open() budget). Invalid files are deleted.
pub fn load_journal(files_state: &Path) -> Result<Vec<JournalRecord>, FilesError> {
    let dir = journal_dir(files_state);
    if !is_real_dir(&dir) {
        return Ok(Vec::new());
    }
    load_named(
        &dir,
        &json_names(&dir)?,
        usize::MAX,
        Duration::from_secs(u64::MAX),
    )
    .map(|part| part.records)
}

/// Bounded recovery used by [`OperatorFiles::open`]: ≤ 200 records or 2 s.
/// Forgeries are deleted; superseded single-file records are deleted.
pub fn recover_on_open(core: &OperatorFiles) -> Result<RecoverSummary, FilesError> {
    let dir = journal_dir(&core.files_state);
    if !is_real_dir(&dir) {
        return Ok(RecoverSummary::default());
    }
    let names = json_names(&dir)?;
    let loaded = load_named(&dir, &names, OPEN_RECOVER_MAX_RECORDS, OPEN_RECOVER_BUDGET)?;
    let mut summary = RecoverSummary {
        processed: loaded.processed,
        rejected: loaded.rejected,
        deferred: names.len().saturating_sub(loaded.processed),
        ..RecoverSummary::default()
    };
    let deleted = delete_superseded(&dir, &loaded.records)?;
    summary.superseded = deleted.len();
    summary.kept = loaded.records.len().saturating_sub(deleted.len());
    Ok(summary)
}

/// Spawn the retry pump: idle on `Notify`, holding `Weak<OperatorFiles>`.
/// Recovery/purge body lands with ops.rs; this compiles and exits when the
/// core is dropped.
pub async fn retry_pump_loop(core: Weak<OperatorFiles>, notify: Arc<Notify>) {
    loop {
        notify.notified().await;
        if core.upgrade().is_none() {
            break;
        }
    }
}

pub(crate) fn attach_retry_pump(core: &Arc<OperatorFiles>) {
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        return;
    };
    let weak = Arc::downgrade(core);
    let notify = Arc::clone(&core.retry_notify);
    let task = handle.spawn(retry_pump_loop(weak, notify));
    let mut slot = match core.retry_task.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    *slot = Some(task);
}

pub(crate) fn abort_retry_pump(notify: &Notify, task: &std::sync::Mutex<Option<JoinHandle<()>>>) {
    notify.notify_waiters();
    let mut slot = match task.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    if let Some(handle) = slot.take() {
        handle.abort();
    }
}

/// Derive one item's progress from disk observations (oss-fs-core §7.5 step 1).
pub fn item_progress(kind: ItemKind, obs: &ItemObservation) -> ItemProgress {
    match kind {
        ItemKind::Write => {
            if obs.matches_post && !obs.temp_remains {
                ItemProgress::Done
            } else if obs.matches_pre || (obs.pre_was_absent && obs.target_absent) {
                ItemProgress::None
            } else {
                ItemProgress::Other
            }
        }
        ItemKind::Move => {
            if obs.to_holds_dev_ino && obs.from_absent {
                ItemProgress::Done
            } else if !obs.from_absent && obs.to_absent {
                ItemProgress::None
            } else {
                ItemProgress::Other
            }
        }
        ItemKind::Trash => {
            if obs.trash_exists {
                ItemProgress::Done
            } else if !obs.target_absent {
                ItemProgress::None
            } else {
                ItemProgress::Other
            }
        }
        ItemKind::Mkdir => {
            if obs.dir_exists {
                ItemProgress::Done
            } else {
                ItemProgress::None
            }
        }
    }
}

/// Classify a record given per-item progress and whether a later record supersedes it.
pub fn classify_recovery(progress: &[ItemProgress], superseded: bool) -> RecoveryClass {
    if progress.iter().all(|p| *p == ItemProgress::Done) && !progress.is_empty() {
        return RecoveryClass::AllDone;
    }
    if superseded {
        return RecoveryClass::Superseded;
    }
    if progress.is_empty() || progress.iter().all(|p| *p == ItemProgress::None) {
        return RecoveryClass::NoneDone;
    }
    if progress.len() == 1 {
        RecoveryClass::Overtaken
    } else {
        RecoveryClass::Partial
    }
}

/// Later pending record for the same path has `pre_oid == this.post_oid`.
pub fn is_superseded(record: &JournalRecord, later: &[JournalRecord]) -> bool {
    if record.items.len() != 1 {
        return false;
    }
    let Some(item) = record.items.first() else {
        return false;
    };
    let Some(post) = item.post_oid.as_deref() else {
        return false;
    };
    let path = item.to_rel.as_str();
    later.iter().any(|next| {
        next.items
            .iter()
            .any(|it| it.to_rel == path && it.pre_oid.as_deref() == Some(post))
    })
}

/// Delete earlier single-file records superseded by a later record on the same path.
pub fn delete_superseded(
    journal_dir: &Path,
    records: &[JournalRecord],
) -> Result<Vec<String>, FilesError> {
    let mut deleted = Vec::new();
    for (i, rec) in records.iter().enumerate() {
        let later = records.get(i.saturating_add(1)..).unwrap_or(&[]);
        if !is_superseded(rec, later) {
            continue;
        }
        let path = journal_dir.join(json_name(&rec.op_id));
        match std::fs::remove_file(&path) {
            Ok(()) => deleted.push(rec.op_id.clone()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                deleted.push(rec.op_id.clone());
            }
            Err(e) => return Err(io_err(e)),
        }
    }
    Ok(deleted)
}

fn encode_record(record: &JournalRecord) -> Result<Vec<u8>, FilesError> {
    let bytes = serde_json::to_vec(record).map_err(|e| io_err(e))?;
    if bytes.len() > JOURNAL_RECORD_MAX_BYTES {
        return Err(FilesError::Io("journal record exceeds 1 MiB".into()));
    }
    Ok(bytes)
}

fn validate_record(record: &JournalRecord) -> Result<(), FilesError> {
    if record.v != JOURNAL_SCHEMA_VERSION {
        return Err(FilesError::Io("journal schema version".into()));
    }
    if !op_id_ok(&record.op_id) {
        return Err(FilesError::Io("journal op_id".into()));
    }
    for item in &record.items {
        if !rel_ok(&item.to_rel, false) {
            return Err(FilesError::Io("journal item path".into()));
        }
        if let Some(from) = &item.from_rel {
            if !rel_ok(from, false) {
                return Err(FilesError::Io("journal item path".into()));
            }
        }
        if let Some(temp) = &item.temp_location {
            if !temp_ok(temp) {
                return Err(FilesError::Io("journal temp_location".into()));
            }
        }
    }
    for meta in &record.metas {
        if !rel_ok(&meta.dir_rel, true) {
            return Err(FilesError::Io("journal meta path".into()));
        }
    }
    Ok(())
}

fn rel_ok(rel: &str, allow_root: bool) -> bool {
    let Ok(nfc) = normalize_workspace_path(rel, allow_root) else {
        return false;
    };
    if nfc != rel {
        return false;
    }
    matches!(classify_lexical(&nfc).access, AccessClass::Normal)
}

fn temp_ok(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('/')
        && !name.contains('\0')
        && !name.split('/').any(|c| c == "." || c == "..")
}

fn op_id_ok(id: &str) -> bool {
    let n = id.len();
    (1..=64).contains(&n)
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn json_name(op_id: &str) -> String {
    let mut name = String::with_capacity(op_id.len().saturating_add(5));
    name.push_str(op_id);
    name.push_str(".json");
    name
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

fn io_err(err: impl std::fmt::Display) -> FilesError {
    FilesError::Io(err.to_string())
}

fn is_real_dir(path: &Path) -> bool {
    match std::fs::symlink_metadata(path) {
        Ok(m) => m.file_type().is_dir(),
        Err(_) => false,
    }
}

fn ensure_journal_dir(files_state: &Path) -> Result<PathBuf, FilesError> {
    if let Some(parent) = files_state.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent).map_err(io_err)?;
        }
    }
    ensure_dir_mode(files_state, DIR_MODE)?;
    let dir = journal_dir(files_state);
    ensure_dir_mode(&dir, DIR_MODE)?;
    Ok(dir)
}

fn ensure_dir_mode(path: &Path, mode: u32) -> Result<(), FilesError> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_dir() => {
            chmod(path, mode)?;
            Ok(())
        }
        Ok(_) => Err(FilesError::Io("files-state path is not a directory".into())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir(path).map_err(io_err)?;
            chmod(path, mode)?;
            Ok(())
        }
        Err(e) => Err(io_err(e)),
    }
}

fn chmod(path: &Path, mode: u32) -> Result<(), FilesError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).map_err(io_err)
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
        Ok(())
    }
}

fn json_names(dir: &Path) -> Result<Vec<PathBuf>, FilesError> {
    let mut names = Vec::new();
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(names),
        Err(e) => return Err(io_err(e)),
    };
    for ent in rd {
        let ent = ent.map_err(io_err)?;
        let name = ent.file_name();
        let Some(s) = name.to_str() else {
            continue;
        };
        if s.starts_with('.') || !s.ends_with(".json") {
            continue;
        }
        names.push(PathBuf::from(s));
    }
    names.sort();
    Ok(names)
}

struct LoadedBatch {
    records: Vec<JournalRecord>,
    processed: usize,
    rejected: usize,
}

fn load_named(
    dir: &Path,
    names: &[PathBuf],
    max_records: usize,
    budget: Duration,
) -> Result<LoadedBatch, FilesError> {
    let start = Instant::now();
    let expected_uid = dir_uid(dir)?;
    let mut records = Vec::new();
    let mut processed: usize = 0;
    let mut rejected: usize = 0;
    for name in names {
        if processed >= max_records || start.elapsed() >= budget {
            break;
        }
        processed = processed.saturating_add(1);
        match load_one(dir, name, expected_uid) {
            LoadOne::Record(rec) => records.push(rec),
            LoadOne::Rejected => rejected = rejected.saturating_add(1),
        }
    }
    Ok(LoadedBatch {
        records,
        processed,
        rejected,
    })
}

enum LoadOne {
    Record(JournalRecord),
    Rejected,
}

fn load_one(dir: &Path, name: &Path, expected_uid: Option<u32>) -> LoadOne {
    let path = dir.join(name);
    if !record_file_ok(&path, expected_uid) {
        let _ = std::fs::remove_file(&path);
        return LoadOne::Rejected;
    }
    let mut file = match File::open(&path) {
        Ok(f) => f,
        Err(_) => {
            let _ = std::fs::remove_file(&path);
            return LoadOne::Rejected;
        }
    };
    let mut buf = Vec::new();
    let cap = JOURNAL_RECORD_MAX_BYTES.saturating_add(1);
    let read_ok = {
        let mut limited = Read::take(&mut file, cap as u64);
        limited.read_to_end(&mut buf)
    };
    if read_ok.is_err() || buf.len() > JOURNAL_RECORD_MAX_BYTES {
        drop(file);
        let _ = std::fs::remove_file(&path);
        return LoadOne::Rejected;
    }
    let rec = match serde_json::from_slice::<JournalRecord>(&buf) {
        Ok(r) => r,
        Err(_) => {
            drop(file);
            let _ = std::fs::remove_file(&path);
            return LoadOne::Rejected;
        }
    };
    let stem = name.file_stem().and_then(|s| s.to_str()).unwrap_or("");
    if stem != rec.op_id || validate_record(&rec).is_err() {
        drop(file);
        let _ = std::fs::remove_file(&path);
        return LoadOne::Rejected;
    }
    LoadOne::Record(rec)
}

fn record_file_ok(path: &Path, expected_uid: Option<u32>) -> bool {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(_) => return false,
    };
    if !meta.file_type().is_file() {
        return false;
    }
    if meta.len() > JOURNAL_RECORD_MAX_BYTES as u64 {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let Some(uid) = expected_uid {
            if meta.uid() != uid {
                return false;
            }
        }
        if meta.mode() & 0o777 != FILE_MODE {
            return false;
        }
    }
    #[cfg(not(unix))]
    {
        let _ = expected_uid;
    }
    true
}

fn dir_uid(dir: &Path) -> Result<Option<u32>, FilesError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::symlink_metadata(dir).map_err(io_err)?;
        Ok(Some(meta.uid()))
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Ok(None)
    }
}

fn atomic_write_0600(dir: &Path, op_id: &str, bytes: &[u8]) -> Result<(), FilesError> {
    let dest = dir.join(json_name(op_id));
    let mut tmp_name = String::from(".");
    tmp_name.push_str(op_id);
    tmp_name.push_str(".json.tmp");
    let tmp = dir.join(&tmp_name);
    match std::fs::remove_file(&tmp) {
        Ok(()) | Err(_) => {}
    }
    let written = write_tmp(&tmp, bytes);
    if let Err(e) = written {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    if let Err(e) = std::fs::rename(&tmp, &dest) {
        let _ = std::fs::remove_file(&tmp);
        return Err(io_err(e));
    }
    if let Ok(dirf) = File::open(dir) {
        let _ = dirf.sync_all();
    }
    Ok(())
}

fn write_tmp(tmp: &Path, bytes: &[u8]) -> Result<(), FilesError> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(FILE_MODE);
    }
    let mut file = opts.open(tmp).map_err(io_err)?;
    chmod(tmp, FILE_MODE)?;
    file.write_all(bytes).map_err(io_err)?;
    file.sync_all().map_err(io_err)?;
    Ok(())
}

impl OperatorFiles {
    /// Wake the retry pump (Pending/Failed outcomes; no-op if the task is gone).
    pub fn notify_retry(&self) {
        self.retry_notify.notify_one();
    }

    /// Persist an intent record, refusing at the 1 000-record cap.
    pub fn journal_intent(&self, record: &JournalRecord) -> Result<(), FilesError> {
        persist(&self.files_state, record)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn sample(op_id: &str, path: &str, post_oid: &str, pre_oid: Option<&str>) -> JournalRecord {
        let mut rec = JournalRecord::new(op_id.to_string(), "user:h".into(), TypedOp::Edit);
        rec.disk_changed = true;
        rec.items.push(JournalItem {
            kind: ItemKind::Write,
            from_rel: None,
            to_rel: path.to_string(),
            dev_ino: None,
            pre_identity: None,
            pre_oid: pre_oid.map(str::to_string),
            post_identity: None,
            post_oid: Some(post_oid.to_string()),
            entry_pre: None,
            temp_location: None,
        });
        rec
    }

    fn chmod_path(path: &Path, mode: u32) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn save_version_is_not_a_typed_op() {
        let json = r#"{"v":2,"op_id":"01ARZ3NDEKTSV4RRFFQ69G5FAV","created_ms":1,"actor_handle":"user:h","op":{"type":"save_version"},"items":[],"metas":[],"disk_changed":false}"#;
        assert!(serde_json::from_str::<JournalRecord>(json).is_err());
        let titled = r#"{"v":2,"op_id":"01ARZ3NDEKTSV4RRFFQ69G5FAV","created_ms":1,"actor_handle":"user:h","op":{"type":"edit"},"items":[],"metas":[],"disk_changed":false,"title":"nope"}"#;
        assert!(serde_json::from_str::<JournalRecord>(titled).is_err());
    }

    #[test]
    fn journal_record_forgery_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path().join("files");
        let good = sample("01ARZ3NDEKTSV4RRFFQ69G5FAV", "notes.md", "aa", None);
        persist(&state, &good).unwrap();
        let loaded = load_journal(&state).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].op_id, good.op_id);

        let dir = journal_dir(&state);
        let forged_mode = dir.join("01ARZ3NDEKTSV4RRFFQ69G5FAW.json");
        std::fs::write(
            &forged_mode,
            serde_json::to_vec(&sample(
                "01ARZ3NDEKTSV4RRFFQ69G5FAW",
                "notes.md",
                "bb",
                None,
            ))
            .unwrap(),
        )
        .unwrap();
        chmod_path(&forged_mode, 0o644);
        let forged_schema = dir.join("01ARZ3NDEKTSV4RRFFQ69G5FAX.json");
        std::fs::write(
            &forged_schema,
            br#"{"v":2,"op_id":"01ARZ3NDEKTSV4RRFFQ69G5FAX","created_ms":1,"actor_handle":"user:h","op":{"type":"edit"},"items":[],"metas":[],"disk_changed":false,"subject":"forged"}"#,
        )
        .unwrap();
        chmod_path(&forged_schema, FILE_MODE);
        let forged_path = dir.join("01ARZ3NDEKTSV4RRFFQ69G5FAY.json");
        let mut bad_path = sample("01ARZ3NDEKTSV4RRFFQ69G5FAY", "notes.md", "cc", None);
        bad_path.items[0].to_rel = "../escape.md".into();
        std::fs::write(&forged_path, serde_json::to_vec(&bad_path).unwrap()).unwrap();
        chmod_path(&forged_path, FILE_MODE);

        let left = load_journal(&state).unwrap();
        assert_eq!(left.len(), 1, "only the authentic record remains");
        assert!(!forged_mode.exists());
        assert!(!forged_schema.exists());
        assert!(!forged_path.exists());
    }

    #[test]
    fn journal_backlog_cap_refuses_new_mutations() {
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path().join("files");
        let dir = ensure_journal_dir(&state).unwrap();
        for i in 0..JOURNAL_RECORD_CAP {
            let name = dir.join(format!("cap{i:04}.json"));
            std::fs::write(&name, b"{}").unwrap();
        }
        let rec = sample("01ARZ3NDEKTSV4RRFFQ69G5FAV", "notes.md", "aa", None);
        let err = persist(&state, &rec).unwrap_err();
        assert_eq!(
            err,
            FilesError::Capacity {
                kind: CapacityKind::Journal
            }
        );
        assert_eq!(err.to_string(), "capacity kind:journal");
    }

    #[test]
    fn journal_supersede_deletes_earlier_same_path() {
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path().join("files");
        let first = sample("01ARZ3NDEKTSV4RRFFQ69G5FAA", "notes.md", "aaa111", None);
        let second = sample(
            "01ARZ3NDEKTSV4RRFFQ69G5FAB",
            "notes.md",
            "bbb222",
            Some("aaa111"),
        );
        persist(&state, &first).unwrap();
        persist(&state, &second).unwrap();
        let dir = journal_dir(&state);
        let recs = load_journal(&state).unwrap();
        assert_eq!(recs.len(), 2);
        let deleted = delete_superseded(&dir, &recs).unwrap();
        assert_eq!(deleted, vec![first.op_id.clone()]);
        let left = load_journal(&state).unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].op_id, second.op_id);
        assert!(!dir.join(json_name(&first.op_id)).exists());
    }

    #[test]
    fn recovery_classes_match_disk_progress() {
        let write_done = item_progress(
            ItemKind::Write,
            &ItemObservation {
                matches_post: true,
                ..ItemObservation::default()
            },
        );
        assert_eq!(write_done, ItemProgress::Done);
        assert_eq!(
            classify_recovery(&[ItemProgress::Done], false),
            RecoveryClass::AllDone
        );
        assert_eq!(
            classify_recovery(&[ItemProgress::None], false),
            RecoveryClass::NoneDone
        );
        assert_eq!(
            classify_recovery(&[ItemProgress::Other], false),
            RecoveryClass::Overtaken
        );
        assert_eq!(
            classify_recovery(&[ItemProgress::Done, ItemProgress::None], false),
            RecoveryClass::Partial
        );
        assert_eq!(
            classify_recovery(&[ItemProgress::Other], true),
            RecoveryClass::Superseded
        );
    }
}

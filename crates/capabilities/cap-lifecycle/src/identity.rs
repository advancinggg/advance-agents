//! Agent identity persistence: the immutable tree id (a UUID) lives in the agent's own
//! `.agent/config.yaml` under the top-level `id` key.
//!
//! Three names, three jobs (see MODULE-005):
//! - **id** (`AgentId`): immutable persistence key — the tree key, the cap-layer
//!   `HostCallContext.agent_id`, the grant grantee, the memory bucket, the cost-ledger
//!   `agent_id`. Generated once (UUID v4) and never re-derived.
//! - **handle**: the addressable, human-typed name (`research`, mailbox `agent:research`);
//!   derived from the display name at creation, renameable without touching any store.
//! - **display name**: free text for people (`display-name` key of the same document).

use std::fs;
use std::io;
use std::path::Path;

use serde_yml::{Mapping, Value};

/// Top-level YAML key carrying the immutable id.
pub const ID_KEY: &str = "id";
/// Fixed handle of the workspace root agent.
pub const ROOT_HANDLE: &str = "root";
/// Bound on the config document read here (the lifecycle atomic-write cap).
const MAX_CONFIG_BYTES: u64 = 64 * 1024;

/// Mint a fresh immutable agent id.
pub fn new_agent_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

fn config_path(workspace: &Path) -> std::path::PathBuf {
    workspace.join(".agent").join("config.yaml")
}

fn read_document(path: &Path) -> io::Result<Mapping> {
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Mapping::new()),
        Err(e) => return Err(e),
    };
    if !meta.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "config.yaml is not a regular file",
        ));
    }
    if meta.len() > MAX_CONFIG_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "config.yaml exceeds bound",
        ));
    }
    let raw = fs::read_to_string(path)?;
    match serde_yml::from_str::<Value>(&raw) {
        Ok(Value::Mapping(m)) => Ok(m),
        Ok(Value::Null) => Ok(Mapping::new()),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "config.yaml is not a mapping",
        )),
        Err(e) => Err(io::Error::new(io::ErrorKind::InvalidData, e.to_string())),
    }
}

/// The persisted `id` of the agent whose territory is `workspace`, if any.
pub fn read_agent_id(workspace: &Path) -> Option<String> {
    let doc = read_document(&config_path(workspace)).ok()?;
    let value = doc.get(Value::String(ID_KEY.to_string()))?.as_str()?.trim();
    if value.is_empty() || value.len() > 64 {
        None
    } else {
        Some(value.to_string())
    }
}

/// Set (or replace) one top-level string key of `<workspace>/.agent/config.yaml`, keeping every
/// other key intact. The document is created when absent; the write is atomic (tmp + rename).
pub fn upsert_config_key(workspace: &Path, key: &str, value: &str) -> io::Result<()> {
    let path = config_path(workspace);
    let mut doc = read_document(&path)?;
    doc.insert(
        Value::String(key.to_string()),
        Value::String(value.to_string()),
    );
    let text = serde_yml::to_string(&Value::Mapping(doc))
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    crate::atomic::atomic_write(&path, text.as_bytes()).map_err(|e| io::Error::other(e.to_string()))
}

/// Persist `id` into `<workspace>/.agent/config.yaml` while keeping the document's bytes
/// otherwise VERBATIM: when the document is a mapping (or empty) without an `id` key, the
/// line `id: <id>` is appended textually (a template manifest stays byte-identical apart from
/// that line); when the key already exists, the document is rewritten with the key replaced.
pub fn persist_agent_id(workspace: &Path, id: &str) -> io::Result<()> {
    let path = config_path(workspace);
    let doc = read_document(&path)?;
    if doc.contains_key(Value::String(ID_KEY.to_string())) {
        return upsert_config_key(workspace, ID_KEY, id);
    }
    let mut text = match fs::symlink_metadata(&path) {
        Ok(_) => fs::read_to_string(&path)?,
        Err(e) if e.kind() == io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e),
    };
    if !text.is_empty() && !text.ends_with('\n') {
        text.push('\n');
    }
    text.push_str(&format!("{ID_KEY}: {id}\n"));
    crate::atomic::atomic_write(&path, text.as_bytes()).map_err(|e| io::Error::other(e.to_string()))
}

/// The agent id persisted under `workspace`, minting and writing one when absent.
pub fn ensure_agent_id(workspace: &Path) -> io::Result<String> {
    if let Some(id) = read_agent_id(workspace) {
        return Ok(id);
    }
    let id = new_agent_id();
    persist_agent_id(workspace, &id)?;
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ensure_is_stable_and_keeps_other_keys() {
        let tmp = tempfile::tempdir().unwrap();
        let ws = tmp.path();
        fs::create_dir_all(ws.join(".agent")).unwrap();
        fs::write(
            ws.join(".agent/config.yaml"),
            "capabilities:\n  fs: true\ndisplay-name: Atlas\n",
        )
        .unwrap();
        assert_eq!(read_agent_id(ws), None);
        let first = ensure_agent_id(ws).unwrap();
        assert_eq!(uuid::Uuid::parse_str(&first).unwrap().get_version_num(), 4);
        let second = ensure_agent_id(ws).unwrap();
        assert_eq!(first, second);
        let text = fs::read_to_string(ws.join(".agent/config.yaml")).unwrap();
        assert!(text.contains("display-name: Atlas"), "{text}");
        assert!(text.contains("  fs: true"), "{text}");
        assert!(text.contains(&format!("id: {first}")), "{text}");
        assert_eq!(
            text.matches("\nid:").count() + usize::from(text.starts_with("id:")),
            1
        );
    }

    #[test]
    fn persist_keeps_the_document_verbatim() {
        let tmp = tempfile::tempdir().unwrap();
        let ws = tmp.path();
        fs::create_dir_all(ws.join(".agent")).unwrap();
        let manifest = "name: \"researcher\"\nversion: 1.0.0\ndefault-model: \"sonnet\"\n";
        fs::write(ws.join(".agent/config.yaml"), manifest).unwrap();
        persist_agent_id(ws, "abc-123").unwrap();
        let text = fs::read_to_string(ws.join(".agent/config.yaml")).unwrap();
        assert_eq!(
            text,
            format!("{manifest}id: abc-123\n"),
            "only the id line is added"
        );
        assert_eq!(read_agent_id(ws).as_deref(), Some("abc-123"));
        // A second persist replaces the key (no duplicate line).
        persist_agent_id(ws, "def-456").unwrap();
        let text = fs::read_to_string(ws.join(".agent/config.yaml")).unwrap();
        assert_eq!(text.matches("id:").count(), 1, "{text}");
        assert_eq!(read_agent_id(ws).as_deref(), Some("def-456"));
        // A document without a trailing newline gets one before the id line.
        fs::write(ws.join(".agent/config.yaml"), "capabilities:\n  fs: true").unwrap();
        persist_agent_id(ws, "ghi-789").unwrap();
        assert_eq!(
            fs::read_to_string(ws.join(".agent/config.yaml")).unwrap(),
            "capabilities:\n  fs: true\nid: ghi-789\n"
        );
    }

    #[test]
    fn absent_document_is_created() {
        let tmp = tempfile::tempdir().unwrap();
        let ws = tmp.path();
        fs::create_dir_all(ws.join(".agent")).unwrap();
        let id = ensure_agent_id(ws).unwrap();
        assert_eq!(read_agent_id(ws).as_deref(), Some(id.as_str()));
    }

    #[test]
    fn non_mapping_document_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let ws = tmp.path();
        fs::create_dir_all(ws.join(".agent")).unwrap();
        fs::write(ws.join(".agent/config.yaml"), "- a\n- b\n").unwrap();
        assert!(ensure_agent_id(ws).is_err());
        assert_eq!(
            fs::read_to_string(ws.join(".agent/config.yaml")).unwrap(),
            "- a\n- b\n"
        );
    }
}

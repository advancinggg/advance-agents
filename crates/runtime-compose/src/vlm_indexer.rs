//! SAT-D (slice satD-vlm): the CLI-side `DescriptionIndexer` adapter — the VLM
//! half of the VLM-into-PostProcessor bridge.
//!
//! cap-memory has ZERO cap-llm/cap-fs dep, so the post-processor's Step-3
//! description-indexing seam ([`cap_memory::DescriptionIndexer`]) is implemented
//! here, at the composition root, exactly like the SAT-B `LlmBatchExtractor`
//! (CONTRACT-081) and the SAT-C `L6DispatchAdapter`. Given a changed file's
//! (raw, LLM-produced, UNTRUSTED) workspace-relative path, [`VlmDescriptionIndexer`]:
//!
//! 1. **confines + normalizes** the path — rejecting workspace-escape, symlink
//!    escape, oversize, AND any hidden/`.`-prefixed component (`.agent`,
//!    `.advance`, `.git`, `.env`, …) so a hallucinated/injected path can neither
//!    exfiltrate runtime-private state to the LLM/VLM nor write a stray
//!    `.meta.yaml`. Returns the canonical workspace-relative `vpath`.
//! 2. **sniffs MIME** by extension (text/image/pdf only; video/audio/binary →
//!    `application/octet-stream` → no-index, since the video-frame + audio-Whisper
//!    legs are deferred per SYS-AC-217).
//! 3. **routes** via MODULE-009 CONTRACT-082 [`cap_llm::dispatch_for_indexing`]:
//!    text → CONTRACT-081 `gateway.chat`; image/pdf → `vlm.extract_description`;
//!    binary/unknown → `Ok(None)` (SYS-AC-071 / SYS-AC-217 discriminator).
//! 4. **writes the description back** to the file's `.meta.yaml` entry via
//!    MODULE-002 CONTRACT-010/012 [`cap_fs::MetaMaintainer`] (SYS-AC-072 / the
//!    `.meta.yaml` half of SYS-AC-066 — fires on the text/LLM path too).
//!
//! The post-processor Step-3 then routes the returned description into the STORE
//! (a `FileRef`-sourced entry) so `MemoryStore::recall` surfaces it (SYS-AC-073).
//!
//! **Scope (SAT-D → Stage-C MAINLINE harvest pass-3, 2026-06-19):** this adapter is
//! NOW INSTALLED in production. `wiring.rs` builds the real `LlmGatewayVlm` into
//! `WiringHandles.vlm_extractor` (gated on `declares_llm`) and `build_live_post_processor`
//! installs this indexer via `with_description_indexer` whenever the live post-processor
//! is built. The e2e SYS-AC witnesses live in the system-acceptance harness
//! (`.with_vlm_indexer()`); AC-22 flips on the install + that e2e. AC-30 stays deferred
//! (its criterion's video→per-frame / audio→Whisper legs are unbuilt — `sniff_mime`
//! routes them to no-index; the criterion re-word is `/spec`-owned). See MODULE-011 §2.7/§2.9.

use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use cap_fs::{DefaultAtomicWriter, MetaMaintainer, MetaSchemaLoader};
use cap_llm::{dispatch_for_indexing, LlmGatewayInternal, VlmExtractor};
use cap_memory::{DescriptionIndexer, IndexedDescription};

/// Upper bound on bytes read from a changed file before MIME routing. Kept ≤
/// cap-llm's own dispatch caps (text 2 MiB / VLM 8 MiB) so an oversize input is
/// rejected here rather than buffered then rejected downstream.
const MAX_INDEX_BYTES: u64 = 8 * 1024 * 1024;
/// cap-fs `MetaMaintainer::update_entry_meta` rejects a description over 4 KiB;
/// truncate (char-boundary-safe) to stay within it.
const MAX_DESCRIPTION_BYTES: usize = 4096;

/// CLI-side [`cap_memory::DescriptionIndexer`]: routes a changed file by MIME to
/// the LLM/VLM, writes the description back to `.meta.yaml`, and returns the
/// normalized vpath + description for the store.
pub struct VlmDescriptionIndexer {
    // BARE `dyn` (no explicit `+ Send + Sync`): matches
    // `dispatch_for_indexing`'s params exactly (no re-bind), and the
    // `LlmGatewayInternal: Send + Sync` / `VlmExtractor: Send + Sync`
    // supertraits make the use-site `Send + Sync` (like `Components.l6_handler`).
    gateway: Arc<dyn LlmGatewayInternal>,
    vlm: Arc<dyn VlmExtractor>,
    meta: Arc<MetaMaintainer>,
    workspace_root: PathBuf,
}

impl VlmDescriptionIndexer {
    /// Build the adapter. The `.meta.yaml` writeback uses a `MetaMaintainer`
    /// rooted at `workspace_root` (default schema; `.meta-schema.yaml` is read
    /// from the workspace if present).
    pub fn new(
        gateway: Arc<dyn LlmGatewayInternal>,
        vlm: Arc<dyn VlmExtractor>,
        workspace_root: PathBuf,
    ) -> Self {
        let loader = Arc::new(MetaSchemaLoader::new_with_default(
            workspace_root.join(".meta-schema.yaml"),
        ));
        let meta = Arc::new(MetaMaintainer::new(loader, Arc::new(DefaultAtomicWriter)));
        Self {
            gateway,
            vlm,
            meta,
            workspace_root,
        }
    }

    /// Reference to the adapter's `MetaMaintainer` (tests read back `.meta.yaml`).
    pub fn meta(&self) -> &Arc<MetaMaintainer> {
        &self.meta
    }

    /// Write `description` back onto `abs`'s entry in its parent `.meta.yaml`.
    /// Best-effort: any failure is logged and swallowed (never fails the turn).
    /// Holds ONE `MetaMaintainer::acquire()` across the whole read-modify-write
    /// and does NOT call `ensure_dir_meta` (which re-acquires the same
    /// non-reentrant mutex → self-deadlock); `load` returns `Ok(None)` for an
    /// absent `.meta.yaml` and `add_entry_for_write(None, ..)` creates a fresh
    /// `MetaFile`, so the missing-file case is handled.
    async fn writeback_meta(&self, abs: &Path, bytes: &[u8], description: &str) {
        let (Some(parent), Some(file_name)) =
            (abs.parent(), abs.file_name().and_then(|n| n.to_str()))
        else {
            return;
        };
        let _guard = self.meta.acquire().await;
        let meta_pre = self.meta.load(parent).await.ok().flatten();
        let meta_file = match self.meta.add_entry_for_write(meta_pre, file_name, bytes) {
            Ok((mf, _)) => mf,
            Err(e) => {
                eprintln!("vlm-indexer: .meta.yaml ensure-entry failed ({e:?})");
                return;
            }
        };
        // Preserve the entry's existing (schema-default) tags rather than
        // clobbering them with `vec![]`.
        let cur_tags = meta_file
            .entries
            .get(file_name)
            .map(|e| e.tags.clone())
            .unwrap_or_default();
        let meta_file = match self.meta.update_entry_meta(
            meta_file,
            file_name,
            description.to_string(),
            cur_tags,
        ) {
            Ok((mf, _)) => mf,
            Err(e) => {
                eprintln!("vlm-indexer: .meta.yaml update failed ({e:?})");
                return;
            }
        };
        if let Err(e) = self.meta.write(parent, &meta_file).await {
            eprintln!("vlm-indexer: .meta.yaml write failed ({e:?})");
        }
    }
}

#[async_trait]
impl DescriptionIndexer for VlmDescriptionIndexer {
    async fn index_description(&self, _agent_id: &str, path: &str) -> Option<IndexedDescription> {
        let (abs, vpath) = confine(&self.workspace_root, path)?;
        let bytes = read_capped_bytes(&abs, MAX_INDEX_BYTES)?;
        let mime = sniff_mime(&vpath);
        // 071/217: text → chat, image/pdf → VLM, binary/unknown → None. A soft
        // LLM/VLM error also collapses to None (never fails the turn).
        let description = dispatch_for_indexing(&mime, &bytes, &self.gateway, &self.vlm)
            .await
            .ok()??;
        let description = description.trim();
        if description.is_empty() {
            // Empty output → skip (update_entry_meta rejects an empty description).
            return None;
        }
        let description = truncate_to_bytes(description, MAX_DESCRIPTION_BYTES);
        // 072 / 066: write the description back to `.meta.yaml` (best-effort).
        self.writeback_meta(&abs, &bytes, &description).await;
        Some(IndexedDescription { vpath, description })
    }
}

/// Confine an LLM-produced (UNTRUSTED) workspace-relative `rel` path under
/// `workspace_root`. Rejects (on the RELATIVE path, not the canonical-abs
/// ancestors — a dotted CI checkout root must not false-reject): absolute paths,
/// `..` traversal, and any `.`-prefixed component (`.agent`/`.advance`/`.git`/
/// `.env`/hidden). Then canonicalizes (resolving symlinks) and requires the
/// result to stay under the canonical workspace root (symlink-escape reject).
/// Returns `(abs, vpath)` where `vpath` is the canonical workspace-relative path
/// (alias-stable: `./a.png`, `a.png`, `dir//a.png` collapse to one key).
pub(crate) fn confine(workspace_root: &Path, rel: &str) -> Option<(PathBuf, String)> {
    let rel_path = Path::new(rel);
    for comp in rel_path.components() {
        match comp {
            Component::Normal(s) => {
                let s = s.to_str()?; // non-UTF-8 component → reject
                if s.starts_with('.') {
                    return None; // hidden / private (.agent/.advance/.git/.env/…)
                }
            }
            Component::CurDir => {} // "." — harmless, normalizes away
            // ParentDir ("..") / RootDir / Prefix → traversal or absolute → reject
            _ => return None,
        }
    }
    let candidate = workspace_root.join(rel_path);
    let abs = std::fs::canonicalize(&candidate).ok()?; // resolves symlinks; None if missing
    let canon_root = std::fs::canonicalize(workspace_root).ok()?;
    if !abs.starts_with(&canon_root) {
        return None; // symlink escape (target outside the workspace)
    }
    let rel_canon = abs.strip_prefix(&canon_root).ok()?;
    // Re-scan the CANONICAL (post-symlink-resolution) path for hidden
    // components. The literal-path scan above only sees the names the LLM typed;
    // a NON-hidden symlink whose target is inside `.agent`/`.git`/… (e.g.
    // `leak.png -> .agent/memory/knowledge.jsonl`) would otherwise pass the
    // literal scan AND the `starts_with(root)` check, letting private bytes be
    // read + shipped to the LLM/VLM and a `.meta.yaml` be written under the
    // private tree. After canonicalize, `rel_canon` is all `Normal` components.
    for comp in rel_canon.components() {
        if let Component::Normal(s) = comp {
            if s.to_str().is_none_or(|s| s.starts_with('.')) {
                return None; // hidden/private component after symlink resolution
            }
        }
    }
    let vpath = rel_canon.to_str()?.to_string();
    if vpath.is_empty() {
        return None; // the workspace root itself is not an indexable file
    }
    Some((abs, vpath))
}

/// Binary-safe bounded read of a REGULAR file. Stats the leaf via
/// `symlink_metadata` BEFORE opening — a plain `File::open` on a FIFO/socket/
/// device would BLOCK indefinitely before any `is_file()` check could run, so
/// any non-regular leaf (FIFO/socket/device/dir/symlink) or one larger than
/// `max` is refused up front (mirrors cap-fs `read_capped_yaml`'s pre-open
/// gate). The open then carries BOTH `O_NOFOLLOW` (a leaf swapped to a symlink
/// after the stat → `ELOOP`) AND `O_NONBLOCK` (a leaf swapped to a FIFO/device
/// after the stat opens immediately instead of blocking forever — `O_NONBLOCK`
/// is a no-op for regular files), after which the fd's own metadata is
/// re-checked and any non-regular fd is rejected. So the post-stat swap window
/// is closed for BOTH symlinks and FIFOs. A residual canonicalize→open TOCTOU
/// on the path's DIRECTORY components remains — full closure needs `openat2`/
/// `RESOLVE_NO_SYMLINKS`; accepted, matching the cap-fs/SAT-B memory write-path
/// residual.
pub(crate) fn read_capped_bytes(path: &Path, max: u64) -> Option<Vec<u8>> {
    let pre = std::fs::symlink_metadata(path).ok()?;
    if !pre.file_type().is_file() || pre.len() > max {
        return None; // FIFO/socket/device/dir/symlink/oversize — never opened
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // O_NOFOLLOW: reject a leaf swapped to a symlink. O_NONBLOCK: a leaf
        // swapped to a FIFO/device opens immediately (no hang) and is then
        // rejected by the fd re-check below; O_NONBLOCK is a no-op for the
        // regular-file happy path.
        opts.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = opts.open(path).ok()?;
    let post = file.metadata().ok()?;
    if !post.file_type().is_file() || post.len() > max {
        return None; // leaf changed between stat and open (symlink/FIFO/device)
    }
    let mut buf = Vec::new();
    file.take(max).read_to_end(&mut buf).ok()?;
    Some(buf)
}

/// Map a path's extension to a MIME type for [`dispatch_for_indexing`] routing.
/// Text-class extensions (MD/JSON/YAML/CSV/code) map to a `text/*` MIME (→ LLM
/// chat); images/PDF map to their type (→ VLM); EVERYTHING else — including
/// video/audio (frame-extraction + Whisper are deferred per SYS-AC-217) and
/// unknown/binary — maps to `application/octet-stream` (→ no-index). Magic-byte
/// sniffing is a documented refinement; the 217 discriminator needs only the
/// MIME *class*.
fn sniff_mime(vpath: &str) -> String {
    let ext = Path::new(vpath)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    match ext.as_str() {
        // text files (MD/JSON/YAML/CSV/code) → LLM generate (text/*)
        "md" | "markdown" => "text/markdown".to_string(),
        "csv" => "text/csv".to_string(),
        "html" | "htm" => "text/html".to_string(),
        "css" => "text/css".to_string(),
        "txt" | "text" | "json" | "yaml" | "yml" | "toml" | "ini" | "rs" | "py" | "js" | "ts"
        | "go" | "java" | "c" | "cc" | "cpp" | "h" | "hpp" | "rb" | "php" | "sh" | "bash"
        | "sql" | "xml" | "log" => "text/plain".to_string(),
        // images / PDF → VLM extract_description
        "png" => "image/png".to_string(),
        "jpg" | "jpeg" => "image/jpeg".to_string(),
        "gif" => "image/gif".to_string(),
        "webp" => "image/webp".to_string(),
        "bmp" => "image/bmp".to_string(),
        "tiff" | "tif" => "image/tiff".to_string(),
        "pdf" => "application/pdf".to_string(),
        // video / audio / binary / unknown → no-index (deferred per SYS-AC-217)
        _ => "application/octet-stream".to_string(),
    }
}

/// Truncate to at most `max` BYTES on a UTF-8 char boundary (a raw byte slice
/// would panic mid-codepoint; `update_entry_meta` checks the raw byte length).
fn truncate_to_bytes(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use cap_llm::{ChatDelta, ChatMessage, ChatParams, ChatResponse, FileContent, LlmError};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Mutex;

    // ── Mocks ──────────────────────────────────────────────────────────────

    struct MockGateway {
        reply: String,
        chat_calls: AtomicU64,
    }
    impl MockGateway {
        fn new(reply: &str) -> Arc<Self> {
            Arc::new(Self {
                reply: reply.to_string(),
                chat_calls: AtomicU64::new(0),
            })
        }
        fn chat_calls(&self) -> u64 {
            self.chat_calls.load(Ordering::SeqCst)
        }
    }
    #[async_trait]
    impl LlmGatewayInternal for MockGateway {
        async fn embed(&self, _text: &str) -> Result<Vec<f32>, LlmError> {
            Ok(vec![])
        }
        async fn chat(
            &self,
            _messages: Vec<ChatMessage>,
            _params: ChatParams,
        ) -> Result<ChatResponse, LlmError> {
            self.chat_calls.fetch_add(1, Ordering::SeqCst);
            Ok(ChatResponse {
                text: self.reply.clone(),
                model: "mock".into(),
                input_tokens: 0,
                output_tokens: 0,
                finish_reason: "stop".into(),
                parsed_output: None,
            })
        }
        async fn stream(
            &self,
            _messages: Vec<ChatMessage>,
            _params: ChatParams,
        ) -> Result<
            Box<dyn futures_core::Stream<Item = Result<ChatDelta, LlmError>> + Send + Unpin>,
            LlmError,
        > {
            Err(LlmError::ProviderError("stream unused".into()))
        }
    }

    struct MockVlm {
        reply: String,
        calls: Mutex<Vec<String>>, // the variant name per call
    }
    impl MockVlm {
        fn new(reply: &str) -> Arc<Self> {
            Arc::new(Self {
                reply: reply.to_string(),
                calls: Mutex::new(Vec::new()),
            })
        }
        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
    }
    #[async_trait]
    impl VlmExtractor for MockVlm {
        async fn extract_description(&self, content: &FileContent) -> Result<String, LlmError> {
            let variant = match content {
                FileContent::Pdf(_) => "Pdf",
                FileContent::Image { .. } => "Image",
                FileContent::VideoFrame { .. } => "VideoFrame",
                FileContent::Audio { .. } => "Audio",
            };
            self.calls.lock().unwrap().push(variant.to_string());
            Ok(self.reply.clone())
        }
    }

    fn write_file(dir: &Path, rel: &str, bytes: &[u8]) {
        let p = dir.join(rel);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(p, bytes).unwrap();
    }

    fn adapter(root: &Path, gateway: Arc<MockGateway>, vlm: Arc<MockVlm>) -> VlmDescriptionIndexer {
        VlmDescriptionIndexer::new(gateway, vlm, root.to_path_buf())
    }

    // ── satD-C1 — file-type routing discrimination (AC-30 / 217) ────────────

    #[tokio::test]
    async fn sat_d_c1_routing_text_image_pdf_binary() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write_file(root, "note.md", b"# hello\nsome notes");
        write_file(root, "pic.png", b"\x89PNG\r\n\x1a\nfake");
        write_file(root, "doc.pdf", b"%PDF-1.4 fake");
        write_file(root, "blob.bin", b"\x00\x01\x02\x03");

        let gw = MockGateway::new("text-desc");
        let vlm = MockVlm::new("vlm-desc");
        let a = adapter(root, Arc::clone(&gw), Arc::clone(&vlm));

        // text → gateway.chat, NOT vlm
        let r = a.index_description("agent", "note.md").await.unwrap();
        assert_eq!(r.description, "text-desc");
        assert_eq!(gw.chat_calls(), 1);
        assert!(vlm.calls().is_empty());

        // image → vlm (Image), NOT chat
        let r = a.index_description("agent", "pic.png").await.unwrap();
        assert_eq!(r.description, "vlm-desc");
        assert_eq!(gw.chat_calls(), 1, "chat not called for image");
        assert_eq!(vlm.calls(), vec!["Image".to_string()]);

        // pdf → vlm (Pdf)
        let r = a.index_description("agent", "doc.pdf").await.unwrap();
        assert_eq!(r.description, "vlm-desc");
        assert_eq!(vlm.calls(), vec!["Image".to_string(), "Pdf".to_string()]);

        // binary → neither, None
        assert!(a.index_description("agent", "blob.bin").await.is_none());
        assert_eq!(gw.chat_calls(), 1);
        assert_eq!(vlm.calls().len(), 2, "no vlm call for octet-stream");
    }

    // ── satD-C2 — .meta.yaml VLM writeback (AC-22 / 072) ────────────────────

    #[tokio::test]
    async fn sat_d_c2_meta_writeback_image_roundtrips() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write_file(root, "pic.png", b"\x89PNGfake");
        let gw = MockGateway::new("unused");
        let vlm = MockVlm::new("a UML class diagram");
        let a = adapter(root, gw, vlm);

        let r = a.index_description("agent", "pic.png").await.unwrap();
        assert_eq!(r.vpath, "pic.png");
        assert_eq!(r.description, "a UML class diagram");

        // Read back the on-disk .meta.yaml entry via the adapter's maintainer.
        let mf = a.meta().load(root).await.unwrap().expect("meta exists");
        let entry = mf.entries.get("pic.png").expect("entry written");
        assert_eq!(entry.description, "a UML class diagram");
    }

    // ── satD-C3 — .meta.yaml fires on the LLM/text path too (066 half) ──────

    #[tokio::test]
    async fn sat_d_c3_meta_writeback_text_path() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write_file(root, "config.yaml", b"key: value");
        let gw = MockGateway::new("a YAML config file");
        let vlm = MockVlm::new("unused");
        let a = adapter(root, gw, vlm);

        let r = a.index_description("agent", "config.yaml").await.unwrap();
        assert_eq!(r.description, "a YAML config file");
        let mf = a.meta().load(root).await.unwrap().expect("meta exists");
        assert_eq!(
            mf.entries.get("config.yaml").unwrap().description,
            "a YAML config file"
        );
    }

    // ── satD-C4 — empty output skips writeback; oversize truncates ──────────

    #[tokio::test]
    async fn sat_d_c4_empty_skips_writeback() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write_file(root, "pic.png", b"fake");
        let gw = MockGateway::new("unused");
        let vlm = MockVlm::new("   "); // whitespace-only → trimmed empty
        let a = adapter(root, gw, vlm);

        assert!(
            a.index_description("agent", "pic.png").await.is_none(),
            "empty VLM output → None, no writeback"
        );
        // No .meta.yaml entry was created (load is None or has no pic.png entry).
        let loaded = a.meta().load(root).await.unwrap();
        assert!(loaded.is_none() || !loaded.unwrap().entries.contains_key("pic.png"));
    }

    #[tokio::test]
    async fn sat_d_c4_oversize_description_truncated() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write_file(root, "pic.png", b"fake");
        let big = "x".repeat(10_000);
        let gw = MockGateway::new("unused");
        let vlm = MockVlm::new(&big);
        let a = adapter(root, gw, vlm);

        let r = a.index_description("agent", "pic.png").await.unwrap();
        assert!(r.description.len() <= MAX_DESCRIPTION_BYTES);
        // The .meta.yaml write succeeded (would have errored if > 4 KiB).
        let mf = a.meta().load(root).await.unwrap().expect("meta exists");
        assert!(mf.entries.get("pic.png").unwrap().description.len() <= MAX_DESCRIPTION_BYTES);
    }

    // ── satD-C5 — MIME sniffer table ────────────────────────────────────────

    #[test]
    fn sat_d_c5_sniff_mime_table() {
        assert!(sniff_mime("a.md").starts_with("text/"));
        assert!(sniff_mime("a.json").starts_with("text/"));
        assert!(sniff_mime("a.yaml").starts_with("text/"));
        assert!(sniff_mime("a.csv").starts_with("text/"));
        assert!(sniff_mime("a.rs").starts_with("text/"));
        assert_eq!(sniff_mime("a.png"), "image/png");
        assert_eq!(sniff_mime("a.jpeg"), "image/jpeg");
        assert_eq!(sniff_mime("a.pdf"), "application/pdf");
        // video / audio / unknown / no-extension → octet-stream (no-index)
        assert_eq!(sniff_mime("a.mp4"), "application/octet-stream");
        assert_eq!(sniff_mime("a.mp3"), "application/octet-stream");
        assert_eq!(sniff_mime("a.wav"), "application/octet-stream");
        assert_eq!(sniff_mime("a.exe"), "application/octet-stream");
        assert_eq!(sniff_mime("noext"), "application/octet-stream");
    }

    // ── satD-C6 — untrusted-path confinement (security) ─────────────────────

    #[tokio::test]
    async fn sat_d_c6_rejects_private_escape_oversize_paths() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        // A private file the LLM might try to exfiltrate, plus a real visible file.
        write_file(root, ".agent/memory/knowledge.jsonl", b"secret entry");
        write_file(root, ".env", b"API_KEY=topsecret");
        write_file(root, ".advance/x", b"private");
        write_file(root, "visible.md", b"ok");

        let gw = MockGateway::new("should-not-run");
        let vlm = MockVlm::new("should-not-run");
        let a = adapter(root, Arc::clone(&gw), Arc::clone(&vlm));

        for evil in [
            ".agent/memory/knowledge.jsonl",
            ".env",
            ".advance/x",
            "../escape",
            "../../etc/passwd",
            ".hidden",
        ] {
            assert!(
                a.index_description("agent", evil).await.is_none(),
                "private/escape path must be rejected: {evil}"
            );
        }
        // No LLM/VLM call happened for any rejected path.
        assert_eq!(gw.chat_calls(), 0);
        assert!(vlm.calls().is_empty());

        // confine() unit-level: rejects private/escape, accepts a visible file.
        assert!(confine(root, ".agent/x").is_none());
        assert!(confine(root, "../up").is_none());
        assert!(confine(root, "nope/missing.png").is_none()); // non-existent
        let (_abs, vpath) = confine(root, "visible.md").expect("visible file confined");
        assert_eq!(vpath, "visible.md");
        // Alias-stability: "./visible.md" normalizes to the same vpath.
        let (_a2, vpath2) = confine(root, "./visible.md").expect("alias confined");
        assert_eq!(vpath2, "visible.md");

        // Symlink ESCAPE (target outside the workspace) → reject.
        #[cfg(unix)]
        {
            let outside = tmp.path().parent().unwrap().join("outside.txt");
            std::fs::write(&outside, b"outside secret").unwrap();
            std::os::unix::fs::symlink(&outside, root.join("escape.png")).unwrap();
            assert!(
                confine(root, "escape.png").is_none(),
                "symlink escaping the workspace must be rejected"
            );

            // Symlink INTO a hidden/private tree (non-hidden link name, target
            // inside `.agent/`) → reject (post-canonicalization hidden-component
            // re-scan). This is the exfiltration path the literal-scan misses.
            std::os::unix::fs::symlink(
                root.join(".agent/memory/knowledge.jsonl"),
                root.join("leak.png"),
            )
            .unwrap();
            assert!(
                confine(root, "leak.png").is_none(),
                "symlink whose target is inside .agent must be rejected"
            );
            assert!(
                a.index_description("agent", "leak.png").await.is_none(),
                "private file behind a non-hidden symlink is NOT read/exfiltrated"
            );

            // FIFO leaf → rejected by the pre-open stat WITHOUT blocking (a plain
            // File::open on a FIFO would hang the turn forever). Create the FIFO
            // via `mkfifo(1)` to stay within the crate's `#![forbid(unsafe_code)]`.
            let fifo = root.join("pipe.png");
            let made_fifo = std::process::Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            if made_fifo {
                assert!(
                    read_capped_bytes(&fifo, MAX_INDEX_BYTES).is_none(),
                    "FIFO rejected by the pre-open stat (no hang)"
                );
                assert!(
                    a.index_description("agent", "pipe.png").await.is_none(),
                    "FIFO path does not hang the indexer"
                );
            }

            // Still no LLM/VLM call after the symlink + FIFO attempts.
            assert_eq!(gw.chat_calls(), 0);
            assert!(vlm.calls().is_empty());
        }

        // Oversize file → read_capped_bytes refuses (None), no LLM/VLM call.
        let big = vec![b'x'; (MAX_INDEX_BYTES + 1) as usize];
        write_file(root, "huge.png", &big);
        assert!(
            a.index_description("agent", "huge.png").await.is_none(),
            "oversize file rejected by the bounded read"
        );
        assert_eq!(gw.chat_calls(), 0);
        assert!(vlm.calls().is_empty());
    }

    // ── satD-I1 — full bridge through the PostProcessor (071/072/073/217) ────

    #[tokio::test]
    async fn sat_d_i1_full_bridge_recall() {
        use advance_shared_types::mailbox::{ActionResult, Message, MessageKind};
        use advance_shared_types::memory::PostProcessorHook;
        use cap_memory::{
            Components, DescriptionUpdate, Extraction, FailureCooldown, InMemorySimilarityIndex,
            MemorySource, MemoryStore, MutableClock, PostProcessor, Reconciler, StubBatchExtractor,
            DEFAULT_THRESHOLD,
        };
        use std::time::SystemTime;

        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write_file(root, "diagram.png", b"\x89PNGfake-image-bytes");
        write_file(root, "readme.md", b"# project\nsome text");
        write_file(root, "data.bin", b"\x00\x01\x02");

        let gw = MockGateway::new("the readme text summary");
        let vlm = MockVlm::new("an architecture diagram showing the gateway");
        let indexer = Arc::new(VlmDescriptionIndexer::new(
            Arc::clone(&gw) as Arc<dyn LlmGatewayInternal>,
            Arc::clone(&vlm) as Arc<dyn VlmExtractor>,
            root.to_path_buf(),
        ));

        let store = Arc::new(MemoryStore::new());
        let extraction = Extraction {
            descriptions: vec![
                DescriptionUpdate {
                    path: "diagram.png".into(),
                    description: "stub".into(),
                },
                DescriptionUpdate {
                    path: "readme.md".into(),
                    description: "stub".into(),
                },
                DescriptionUpdate {
                    path: "data.bin".into(),
                    description: "stub".into(),
                },
            ],
            knowledge: vec![],
            digest: None,
        };
        let extractor = Arc::new(StubBatchExtractor::with_extraction(extraction));
        let reconciler =
            Reconciler::from_concrete(Arc::new(InMemorySimilarityIndex::new()), DEFAULT_THRESHOLD);
        let cooldown = Arc::new(FailureCooldown::new(600));
        let clock = Arc::new(MutableClock::new(SystemTime::UNIX_EPOCH));
        let components = Components::with_l6_defaults(
            extractor,
            reconciler,
            Arc::clone(&store),
            cooldown,
            clock,
        )
        .with_description_indexer(indexer);
        let pp = PostProcessor::with_components(components);

        pp.run("agent-x", &message_user(), &result_empty())
            .await
            .expect("run Ok");

        // 071 + 073: the image → VLM, and its description is recall-able.
        assert_eq!(vlm.calls(), vec!["Image".to_string()]);
        let img_hits = store.recall("agent-x", "architecture diagram", 0);
        assert_eq!(img_hits.len(), 1, "image description recall-able (073)");
        assert!(img_hits[0].sources.iter().any(|s| matches!(
            s,
            MemorySource::FileRef { vpath, .. } if vpath == "diagram.png"
        )));

        // 066: text → LLM, recall-able too.
        assert_eq!(gw.chat_calls(), 1);
        assert_eq!(store.recall("agent-x", "readme text", 0).len(), 1);

        // 217: binary → no index (no store entry, no .meta.yaml entry).
        assert!(store.recall("agent-x", "data.bin", 0).is_empty());

        // 072: both indexed files have a .meta.yaml description on disk.
        let mf = indexer_meta(&pp, root).await;
        assert_eq!(
            mf.entries.get("diagram.png").unwrap().description,
            "an architecture diagram showing the gateway"
        );
        assert_eq!(
            mf.entries.get("readme.md").unwrap().description,
            "the readme text summary"
        );
        assert!(
            !mf.entries.contains_key("data.bin"),
            "binary file gets no .meta.yaml description"
        );

        // helpers local to this test
        fn message_user() -> Message {
            Message {
                id: "m".into(),
                kind: MessageKind::User,
                from: "u".into(),
                to: "a".into(),
                payload: vec![],
                context: None,
                timestamp: SystemTime::UNIX_EPOCH,
                origin: None,
            }
        }
        fn result_empty() -> ActionResult {
            ActionResult {
                new_state: vec![],
                actions: vec![],
            }
        }
        async fn indexer_meta(_pp: &PostProcessor, root: &Path) -> cap_fs::MetaFile {
            // Re-open the on-disk .meta.yaml with a fresh maintainer (the write
            // already flushed to disk under the workspace root).
            let loader = Arc::new(MetaSchemaLoader::new_with_default(
                root.join(".meta-schema.yaml"),
            ));
            let m = MetaMaintainer::new(loader, Arc::new(DefaultAtomicWriter));
            m.load(root).await.unwrap().expect("meta exists")
        }
    }
}

//! Sealed file-ticket body (INTEGRATED X28) and helpers.
//!
//! Layout (max 1186 B):
//! `ver1 | mode1 | flags1 | intent1 | nonce16 | expires8 | oid20 | base20 | rev20 |
//!  size8 | identity32 | digest32 | pathlen2 | path`.

use sha2::{Digest, Sha256};

use advance_shared_types::file_identity::{FileIdentity, FILE_IDENTITY_LEN};

use crate::cursor::{ClientCursorCodec, OpenedSeal, SealPurpose};
use crate::envelope::ClientError;
use crate::files::detail::{FilesFailure, Oid40};
use crate::files::WriteIntent;

/// Cursor codec stream id for every file ticket.
pub const STREAM_ID: &str = "files/raw/v1";
/// Domain separator for identity-fingerprint ETags.
pub const ETAG_DOMAIN: &[u8] = b"advance.files.etag.v1\0";

const VERSION: u8 = 1;
const MODE_READ: u8 = 1;
const MODE_WRITE: u8 = 2;
const FLAG_REV: u8 = 1 << 0;
const FLAG_BASE: u8 = 1 << 1;
const FLAG_ATTACHMENT: u8 = 1 << 2;
const FLAG_OID: u8 = 1 << 3;
const FLAG_IDENTITY: u8 = 1 << 4;
const FLAG_BATCH: u8 = 1 << 5;
const FIXED_LEN: usize = 162;
/// Path (1024) + fixed (162) + optional batch (1+64).
const MAX_BODY: usize = 1251;
const MAX_BATCH_ID: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TicketMode {
    Read,
    Write,
}

impl TicketMode {
    fn byte(self) -> u8 {
        match self {
            TicketMode::Read => MODE_READ,
            TicketMode::Write => MODE_WRITE,
        }
    }

    fn parse(b: u8) -> Option<Self> {
        match b {
            MODE_READ => Some(TicketMode::Read),
            MODE_WRITE => Some(TicketMode::Write),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TicketIntent {
    None,
    Edit,
    Create,
    Upload,
}

impl TicketIntent {
    fn byte(self) -> u8 {
        match self {
            TicketIntent::None => 0,
            TicketIntent::Edit => 1,
            TicketIntent::Create => 2,
            TicketIntent::Upload => 3,
        }
    }

    fn parse(b: u8) -> Option<Self> {
        match b {
            0 => Some(TicketIntent::None),
            1 => Some(TicketIntent::Edit),
            2 => Some(TicketIntent::Create),
            3 => Some(TicketIntent::Upload),
            _ => None,
        }
    }

    pub fn write_intent(self) -> Option<WriteIntent> {
        match self {
            TicketIntent::Edit => Some(WriteIntent::Edit),
            TicketIntent::Create => Some(WriteIntent::Create),
            TicketIntent::Upload => Some(WriteIntent::Upload),
            TicketIntent::None => None,
        }
    }
}

/// Decoded ticket grant (after AEAD open + body parse + expiry).
#[derive(Debug, Clone)]
pub struct FileTicketGrant {
    pub mode: TicketMode,
    pub intent: TicketIntent,
    pub attachment: bool,
    pub nonce: [u8; 16],
    pub expires_at_ms: u64,
    pub oid: Option<Oid40>,
    pub base_oid: Option<Oid40>,
    pub rev: Option<Oid40>,
    pub size: u64,
    pub identity: Option<FileIdentity>,
    pub session_digest: [u8; 32],
    pub path: String,
    pub batch: Option<String>,
}

/// The sealed body before AEAD.
#[derive(Debug, Clone)]
pub struct FileTicketBody {
    pub mode: TicketMode,
    pub intent: TicketIntent,
    pub attachment: bool,
    pub nonce: [u8; 16],
    pub expires_at_ms: u64,
    pub oid: Option<Oid40>,
    pub base_oid: Option<Oid40>,
    pub rev: Option<Oid40>,
    pub size: u64,
    pub identity: Option<FileIdentity>,
    pub session_digest: [u8; 32],
    pub path: String,
    pub batch: Option<String>,
}

impl FileTicketBody {
    #[allow(clippy::too_many_arguments)]
    pub fn read(
        path: &str,
        session_digest: [u8; 32],
        expires_at_ms: u64,
        oid: Option<Oid40>,
        rev: Option<Oid40>,
        identity: Option<FileIdentity>,
        size: u64,
        attachment: bool,
    ) -> Self {
        Self {
            mode: TicketMode::Read,
            intent: TicketIntent::None,
            attachment,
            nonce: random_nonce(),
            expires_at_ms,
            oid,
            base_oid: None,
            rev,
            size,
            identity,
            session_digest,
            path: path.to_string(),
            batch: None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn write(
        path: &str,
        session_digest: [u8; 32],
        expires_at_ms: u64,
        oid: Oid40,
        base_oid: Option<Oid40>,
        identity: Option<FileIdentity>,
        size: u64,
        intent: TicketIntent,
    ) -> Self {
        Self {
            mode: TicketMode::Write,
            intent,
            attachment: false,
            nonce: random_nonce(),
            expires_at_ms,
            oid: Some(oid),
            base_oid,
            rev: None,
            size,
            identity,
            session_digest,
            path: path.to_string(),
            batch: None,
        }
    }

    pub fn with_batch(mut self, batch: Option<String>) -> Self {
        self.batch = batch;
        self
    }

    pub fn encode(&self) -> Result<Vec<u8>, ()> {
        let path = self.path.as_bytes();
        let batch = self.batch.as_deref().unwrap_or("").as_bytes();
        if self.batch.is_some() && (batch.is_empty() || batch.len() > MAX_BATCH_ID) {
            return Err(());
        }
        let extra = if self.batch.is_some() {
            1 + batch.len()
        } else {
            0
        };
        if path.len() > 1024 || FIXED_LEN + path.len() + extra > MAX_BODY {
            return Err(());
        }
        let mut flags = 0u8;
        if self.rev.is_some() {
            flags |= FLAG_REV;
        }
        if self.base_oid.is_some() {
            flags |= FLAG_BASE;
        }
        if self.attachment {
            flags |= FLAG_ATTACHMENT;
        }
        if self.oid.is_some() {
            flags |= FLAG_OID;
        }
        if self.identity.is_some() {
            flags |= FLAG_IDENTITY;
        }
        if self.batch.is_some() {
            flags |= FLAG_BATCH;
        }
        let mut out = vec![0u8; FIXED_LEN + path.len() + extra];
        out[0] = VERSION;
        out[1] = self.mode.byte();
        out[2] = flags;
        out[3] = self.intent.byte();
        out[4..20].copy_from_slice(&self.nonce);
        out[20..28].copy_from_slice(&self.expires_at_ms.to_be_bytes());
        if let Some(oid) = &self.oid {
            out[28..48].copy_from_slice(&oid.to_bytes());
        }
        if let Some(base) = &self.base_oid {
            out[48..68].copy_from_slice(&base.to_bytes());
        }
        if let Some(rev) = &self.rev {
            out[68..88].copy_from_slice(&rev.to_bytes());
        }
        out[88..96].copy_from_slice(&self.size.to_be_bytes());
        if let Some(identity) = &self.identity {
            out[96..128].copy_from_slice(&identity.to_bytes());
        }
        out[128..160].copy_from_slice(&self.session_digest);
        out[160..162].copy_from_slice(&(path.len() as u16).to_be_bytes());
        out[162..162 + path.len()].copy_from_slice(path);
        if self.batch.is_some() {
            let at = 162 + path.len();
            out[at] = batch.len() as u8;
            out[at + 1..].copy_from_slice(batch);
        }
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < FIXED_LEN || bytes.len() > MAX_BODY {
            return None;
        }
        if bytes[0] != VERSION {
            return None;
        }
        let mode = TicketMode::parse(bytes[1])?;
        let flags = bytes[2];
        let intent = TicketIntent::parse(bytes[3])?;
        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(&bytes[4..20]);
        let mut exp = [0u8; 8];
        exp.copy_from_slice(&bytes[20..28]);
        let expires_at_ms = u64::from_be_bytes(exp);
        let oid = if flags & FLAG_OID != 0 {
            Some(oid20(&bytes[28..48])?)
        } else {
            None
        };
        let base_oid = if flags & FLAG_BASE != 0 {
            Some(oid20(&bytes[48..68])?)
        } else {
            None
        };
        let rev = if flags & FLAG_REV != 0 {
            Some(oid20(&bytes[68..88])?)
        } else {
            None
        };
        let mut size_buf = [0u8; 8];
        size_buf.copy_from_slice(&bytes[88..96]);
        let size = u64::from_be_bytes(size_buf);
        let identity = if flags & FLAG_IDENTITY != 0 {
            let mut id = [0u8; FILE_IDENTITY_LEN];
            id.copy_from_slice(&bytes[96..128]);
            Some(FileIdentity::from_bytes(&id))
        } else {
            None
        };
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&bytes[128..160]);
        let path_len = u16::from_be_bytes([bytes[160], bytes[161]]) as usize;
        let path_end = FIXED_LEN + path_len;
        if bytes.len() < path_end {
            return None;
        }
        let path = std::str::from_utf8(&bytes[162..path_end]).ok()?.to_string();
        let batch = if flags & FLAG_BATCH != 0 {
            if bytes.len() < path_end + 1 {
                return None;
            }
            let blen = bytes[path_end] as usize;
            if blen == 0 || blen > MAX_BATCH_ID || bytes.len() != path_end + 1 + blen {
                return None;
            }
            Some(
                std::str::from_utf8(&bytes[path_end + 1..])
                    .ok()?
                    .to_string(),
            )
        } else if bytes.len() != path_end {
            return None;
        } else {
            None
        };
        Some(Self {
            mode,
            intent,
            attachment: flags & FLAG_ATTACHMENT != 0,
            nonce,
            expires_at_ms,
            oid,
            base_oid,
            rev,
            size,
            identity,
            session_digest: digest,
            path,
            batch,
        })
    }
}

fn oid20(bytes: &[u8]) -> Option<Oid40> {
    let mut arr = [0u8; 20];
    arr.copy_from_slice(bytes);
    Some(Oid40::from_bytes(&arr))
}

fn random_nonce() -> [u8; 16] {
    use rand::RngCore;
    let mut n = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut n);
    n
}

/// Strong ETag: the 40-hex oid, or `id-` plus the first 32 hex of the identity fingerprint.
pub fn etag_for(oid: Option<&Oid40>, identity: Option<&FileIdentity>) -> String {
    if let Some(oid) = oid {
        return oid.as_str().to_string();
    }
    let mut hasher = Sha256::new();
    hasher.update(ETAG_DOMAIN);
    if let Some(identity) = identity {
        hasher.update(identity.to_bytes());
    }
    let digest = hasher.finalize();
    format!("id-{}", hex::encode(&digest[..16]))
}

/// Open a sealed ticket. `now == expires` is accepted; `now > expires` is expired.
pub fn open_file_ticket(
    codec: &dyn ClientCursorCodec,
    token: &str,
    now_ms: u64,
) -> Result<FileTicketGrant, ClientError> {
    if token.len() > 2048
        || !token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err(FilesFailure::TicketInvalid.into_client_error());
    }
    let opened = codec
        .open(SealPurpose::FileTicket, STREAM_ID, token)
        .map_err(|_| FilesFailure::TicketInvalid.into_client_error())?;
    let OpenedSeal::FileTicket(body) = opened else {
        return Err(FilesFailure::TicketInvalid.into_client_error());
    };
    let parsed = FileTicketBody::decode(&body)
        .ok_or_else(|| FilesFailure::TicketInvalid.into_client_error())?;
    if now_ms > parsed.expires_at_ms {
        return Err(FilesFailure::TicketExpired.into_client_error());
    }
    Ok(FileTicketGrant {
        mode: parsed.mode,
        intent: parsed.intent,
        attachment: parsed.attachment,
        nonce: parsed.nonce,
        expires_at_ms: parsed.expires_at_ms,
        oid: parsed.oid,
        base_oid: parsed.base_oid,
        rev: parsed.rev,
        size: parsed.size,
        identity: parsed.identity,
        session_digest: parsed.session_digest,
        path: parsed.path,
        batch: parsed.batch,
    })
}

impl FileTicketGrant {
    pub fn nonce_hex(&self) -> String {
        hex::encode(self.nonce)
    }

    pub fn etag(&self) -> String {
        etag_for(self.oid.as_ref(), self.identity.as_ref())
    }
}

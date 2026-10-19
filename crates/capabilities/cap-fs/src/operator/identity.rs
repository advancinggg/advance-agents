//! Identity cache and streaming git-blob hash over an already-opened fd (Δ12).

use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

use advance_git::{BlobHasher, BlobLengthMismatch};
use advance_shared_types::file_identity::FileIdentity;
use rustix::fs::{fstat, FileType};

/// Default identity → oid slots (oss-fs-core §3.2).
pub const OID_CACHE_CAPACITY: usize = 4096;

/// Why hashing an opened descriptor failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityError {
    NotRegularFile,
    LengthMismatch { declared: u64, fed: u64 },
    Io(String),
}

impl std::fmt::Display for IdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotRegularFile => f.write_str("opened descriptor is not a regular file"),
            Self::LengthMismatch { declared, fed } => {
                write!(f, "blob length mismatch: declared {declared}, fed {fed}")
            }
            Self::Io(msg) => write!(f, "identity io: {msg}"),
        }
    }
}

impl std::error::Error for IdentityError {}

impl From<BlobLengthMismatch> for IdentityError {
    fn from(err: BlobLengthMismatch) -> Self {
        Self::LengthMismatch {
            declared: err.declared,
            fed: err.fed,
        }
    }
}

/// LRU of stable [`FileIdentity`] → git blob oid (40 lowercase hex).
pub struct OidCache {
    cap: usize,
    map: HashMap<FileIdentity, String>,
    order: VecDeque<FileIdentity>,
}

impl OidCache {
    pub fn new(cap: usize) -> Self {
        let cap = cap.max(1);
        Self {
            cap,
            map: HashMap::with_capacity(cap.min(64)),
            order: VecDeque::with_capacity(cap.min(64)),
        }
    }

    pub fn with_default_capacity() -> Self {
        Self::new(OID_CACHE_CAPACITY)
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn get(&mut self, identity: &FileIdentity) -> Option<&str> {
        if self.map.contains_key(identity) {
            if let Some(pos) = self.order.iter().position(|k| k == identity) {
                self.order.remove(pos);
                self.order.push_back(*identity);
            }
            self.map.get(identity).map(String::as_str)
        } else {
            None
        }
    }

    pub fn insert(&mut self, identity: FileIdentity, oid: String) {
        if self.map.contains_key(&identity) {
            if let Some(pos) = self.order.iter().position(|k| k == &identity) {
                self.order.remove(pos);
            }
        } else if self.map.len() >= self.cap {
            if let Some(oldest) = self.order.pop_front() {
                self.map.remove(&oldest);
            }
        }
        self.order.push_back(identity);
        self.map.insert(identity, oid);
    }
}

/// `fstat` the opened descriptor, refuse non-regular files, then stream
/// `sha1("blob <len>\\0" ‖ content)` through [`BlobHasher`]. Never hashes by path.
pub fn hash_opened_file(file: &File) -> Result<String, IdentityError> {
    let stat = fstat(file).map_err(|e| IdentityError::Io(e.to_string()))?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
        return Err(IdentityError::NotRegularFile);
    }
    let meta = file
        .metadata()
        .map_err(|e| IdentityError::Io(e.to_string()))?;
    let identity = FileIdentity::from_metadata(&meta);
    hash_opened_file_known_len(file, identity.size)
}

/// Stream an already-opened regular file whose size is `declared` (the `fstat`
/// size taken on this descriptor).
pub fn hash_opened_file_known_len(file: &File, declared: u64) -> Result<String, IdentityError> {
    let mut clone = file
        .try_clone()
        .map_err(|e| IdentityError::Io(e.to_string()))?;
    clone
        .seek(SeekFrom::Start(0))
        .map_err(|e| IdentityError::Io(e.to_string()))?;
    let mut hasher = BlobHasher::new(declared);
    let mut buf = [0u8; 65_536];
    loop {
        let n = clone
            .read(&mut buf)
            .map_err(|e| IdentityError::Io(e.to_string()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    hasher.finish().map_err(IdentityError::from)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use advance_git::blob_oid_of_bytes;
    use std::io::Write;

    #[test]
    fn oid_cache_evicts_oldest() {
        let mut cache = OidCache::new(2);
        let a = FileIdentity::from_stat_parts(1, 1, 1, 0, 0);
        let b = FileIdentity::from_stat_parts(1, 2, 1, 0, 0);
        let c = FileIdentity::from_stat_parts(1, 3, 1, 0, 0);
        cache.insert(a, "aa".into());
        cache.insert(b, "bb".into());
        assert_eq!(cache.get(&a), Some("aa"));
        cache.insert(c, "cc".into());
        assert_eq!(cache.get(&a), Some("aa"), "recent get refreshes LRU");
        assert_eq!(cache.get(&c), Some("cc"));
        assert_eq!(cache.get(&b), None, "least-recent b is evicted");
    }

    #[test]
    fn hash_opened_file_matches_bytes() {
        let mut tmp = tempfile::NamedTempFile::new().expect("tmp");
        tmp.write_all(b"hello world\n").expect("write");
        tmp.flush().expect("flush");
        let file = tmp.reopen().expect("reopen");
        let got = hash_opened_file(&file).expect("hash");
        assert_eq!(got, blob_oid_of_bytes(b"hello world\n"));
    }
}

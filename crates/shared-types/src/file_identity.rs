//! `FileIdentity` — the stat identity of a regular vault file (ADR 2026-10-15 vault files;
//! CONTRACT-246).
//!
//! `(dev, ino, size, mtime_ns)` keys the fs core's oid cache, sealed read tickets (a 32-byte
//! block), identity-fingerprint ETags and the under-lock re-checks between `prepare` and publish.
//! ctime is deliberately absent: writing an xattr (Finder tags, quarantine, the LaunchServices
//! last-used date on "open in default app") bumps ctime on APFS without changing content.
//! advance-git's `IndexStat` keeps ctime because the index format needs it.

use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Byte length of [`FileIdentity::to_bytes`] (the ticket identity block).
pub const FILE_IDENTITY_LEN: usize = 32;

/// A file is "stable" once its mtime is at least this old (3 s, which also covers the 2-second
/// FAT/exFAT timestamp granularity): a later write then gets a later mtime and cannot leave the
/// identity unchanged, so an oid remembered for a stable identity cannot go stale unnoticed.
/// Stability decides only what the fs core may cache; it never refuses a read on its own
/// (`file_busy` is reserved for a file that changed while it was being hashed).
pub const STABLE_AFTER_NS: i64 = 3_000_000_000;

const NANOS_PER_SECOND: i64 = 1_000_000_000;

/// The identity of one regular file, taken by `fstat` on the descriptor that was read or hashed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FileIdentity {
    /// `st_dev`.
    pub dev: u64,
    /// `st_ino`.
    pub ino: u64,
    /// `st_size`.
    pub size: u64,
    /// `st_mtime` in nanoseconds since the Unix epoch (negative before it; saturating).
    pub mtime_ns: i64,
}

impl FileIdentity {
    /// Build from `stat` fields; the mtime saturates at the `i64` nanosecond range.
    pub fn from_stat_parts(dev: u64, ino: u64, size: u64, mtime_sec: i64, mtime_nsec: i64) -> Self {
        let mtime_ns = mtime_sec
            .saturating_mul(NANOS_PER_SECOND)
            .saturating_add(mtime_nsec);
        Self {
            dev,
            ino,
            size,
            mtime_ns,
        }
    }

    /// Build from `std::fs::Metadata` (obtain it with `File::metadata` on the opened descriptor,
    /// never by path).
    #[cfg(unix)]
    pub fn from_metadata(meta: &std::fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt;
        Self::from_stat_parts(
            meta.dev(),
            meta.ino(),
            meta.size(),
            meta.mtime(),
            meta.mtime_nsec(),
        )
    }

    /// Big-endian `dev ‖ ino ‖ size ‖ mtime_ns`.
    pub fn to_bytes(&self) -> [u8; FILE_IDENTITY_LEN] {
        let mut bytes = [0u8; FILE_IDENTITY_LEN];
        bytes[0..8].copy_from_slice(&self.dev.to_be_bytes());
        bytes[8..16].copy_from_slice(&self.ino.to_be_bytes());
        bytes[16..24].copy_from_slice(&self.size.to_be_bytes());
        bytes[24..32].copy_from_slice(&self.mtime_ns.to_be_bytes());
        bytes
    }

    /// Inverse of [`FileIdentity::to_bytes`].
    pub fn from_bytes(bytes: &[u8; FILE_IDENTITY_LEN]) -> Self {
        let word = |at: usize| {
            let mut word = [0u8; 8];
            word.copy_from_slice(&bytes[at..at + 8]);
            word
        };
        Self {
            dev: u64::from_be_bytes(word(0)),
            ino: u64::from_be_bytes(word(8)),
            size: u64::from_be_bytes(word(16)),
            mtime_ns: i64::from_be_bytes(word(24)),
        }
    }

    /// `now − mtime ≥ 3 s`. An mtime in the future (archive extraction, a skewed camera or host
    /// clock) stays unstable until the clock has passed it by 3 s: a write made when the clock
    /// reaches that mtime could reproduce the identity, and git likewise treats such index entries
    /// as racily clean. Such a file is hashed instead of served from the cache; nothing else
    /// changes.
    pub fn is_stable_at(&self, now_ns: i64) -> bool {
        now_ns.saturating_sub(self.mtime_ns) >= STABLE_AFTER_NS
    }
}

/// Nanoseconds since the Unix epoch (negative before it), saturating at the `i64` range.
pub fn unix_time_ns(time: SystemTime) -> i64 {
    match time.duration_since(UNIX_EPOCH) {
        Ok(after) => i64::try_from(after.as_nanos()).unwrap_or(i64::MAX),
        Err(before) => i64::try_from(before.duration().as_nanos())
            .map(|nanos| -nanos)
            .unwrap_or(i64::MIN),
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn bytes_round_trip_big_endian() {
        let identity = FileIdentity {
            dev: 0x0102_0304_0506_0708,
            ino: 0x1112_1314_1516_1718,
            size: 42,
            mtime_ns: -5,
        };
        let bytes = identity.to_bytes();
        assert_eq!(bytes.len(), FILE_IDENTITY_LEN);
        assert_eq!(bytes[0..8], identity.dev.to_be_bytes());
        assert_eq!(bytes[8..16], identity.ino.to_be_bytes());
        assert_eq!(bytes[16..24], 42u64.to_be_bytes());
        assert_eq!(bytes[24..32], (-5i64).to_be_bytes());
        assert_eq!(FileIdentity::from_bytes(&bytes), identity);
    }

    #[test]
    fn stable_after_three_seconds() {
        let identity = FileIdentity::from_stat_parts(1, 2, 3, 10, 0);
        let mtime = 10 * NANOS_PER_SECOND;
        assert!(!identity.is_stable_at(mtime));
        assert!(!identity.is_stable_at(mtime + STABLE_AFTER_NS - 1));
        assert!(identity.is_stable_at(mtime + STABLE_AFTER_NS));
        assert!(
            !identity.is_stable_at(mtime - 1),
            "a future mtime is not stable"
        );
        // A far-future mtime stays unstable until the clock has passed it by 3 s.
        let year_ns = 365 * 24 * 3600 * NANOS_PER_SECOND;
        let future = FileIdentity {
            mtime_ns: mtime + year_ns,
            ..identity
        };
        assert!(!future.is_stable_at(mtime));
        assert!(!future.is_stable_at(mtime + year_ns + STABLE_AFTER_NS - 1));
        assert!(future.is_stable_at(mtime + year_ns + STABLE_AFTER_NS));
        let ancient = FileIdentity {
            mtime_ns: i64::MIN,
            ..identity
        };
        assert!(ancient.is_stable_at(0));
    }

    #[test]
    fn from_stat_parts_saturates() {
        assert_eq!(
            FileIdentity::from_stat_parts(0, 0, 0, 1, 5).mtime_ns,
            1_000_000_005
        );
        assert_eq!(
            FileIdentity::from_stat_parts(0, 0, 0, -2, 500).mtime_ns,
            -1_999_999_500
        );
        assert_eq!(
            FileIdentity::from_stat_parts(0, 0, 0, i64::MAX, 999).mtime_ns,
            i64::MAX
        );
        assert_eq!(
            FileIdentity::from_stat_parts(0, 0, 0, i64::MIN, 0).mtime_ns,
            i64::MIN
        );
        assert_eq!(unix_time_ns(UNIX_EPOCH), 0);
        assert_eq!(
            unix_time_ns(UNIX_EPOCH + Duration::from_millis(1500)),
            1_500_000_000
        );
        assert_eq!(unix_time_ns(UNIX_EPOCH - Duration::from_nanos(1)), -1);
    }

    #[cfg(unix)]
    #[test]
    fn from_metadata_reads_fstat() {
        use std::io::Write;
        use std::os::unix::fs::MetadataExt;

        let mut file = tempfile::NamedTempFile::new().expect("temp file");
        file.write_all(b"vault bytes").expect("write");
        file.flush().expect("flush");
        let meta = file.as_file().metadata().expect("fstat");
        let identity = FileIdentity::from_metadata(&meta);
        assert_eq!(identity.size, 11);
        assert_eq!(identity.ino, meta.ino());
        assert_eq!(identity.dev, meta.dev());
        assert_eq!(
            identity.mtime_ns,
            meta.mtime() * NANOS_PER_SECOND + meta.mtime_nsec()
        );
        // Just written: not stable yet. Ten seconds later: stable.
        let now = unix_time_ns(SystemTime::now());
        assert!(!identity.is_stable_at(now));
        assert!(identity.is_stable_at(now + 10 * NANOS_PER_SECOND));
        // Backdating the mtime makes the same file stable now.
        file.as_file()
            .set_modified(SystemTime::now() - Duration::from_secs(10))
            .expect("set mtime");
        let backdated = FileIdentity::from_metadata(&file.as_file().metadata().expect("fstat"));
        assert_eq!(backdated.ino, identity.ino);
        assert!(backdated.is_stable_at(unix_time_ns(SystemTime::now())));
    }
}

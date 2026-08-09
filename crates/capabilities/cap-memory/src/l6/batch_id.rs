//! `BatchIdSource` — per-L6-run `l6_batch_id` source (Slice C). Internal
//! cap-memory seam, NOT promoted to `shared-types`. Mirrors the Slice B
//! `Clock` injection pattern.
//!
//! The batch id is threaded into (a) `L6ClassificationInput.batch_id`,
//! (b) the `cluster_id` suffix (`cl-{slug}-{batch_id[..8]}`), and (c) the
//! `l6_batch:{id}` reserved tag stamped on consolidated-preference entries
//! (AC-32 retry-idempotency linkage). Production wires `UuidBatchIdSource`;
//! tests pin a known id via `FixedBatchIdSource` so AC-32 / AC-34 assertions
//! reference a deterministic value with no getter or regex.

use uuid::Uuid;

pub trait BatchIdSource: Send + Sync {
    fn next(&self) -> String;
}

/// Production source — `Uuid::new_v4().simple()` truncated to 16 hex chars.
#[derive(Clone, Debug, Default)]
pub struct UuidBatchIdSource;

impl BatchIdSource for UuidBatchIdSource {
    fn next(&self) -> String {
        let full = Uuid::new_v4().simple().to_string();
        full[..16].to_string()
    }
}

/// Test source — always returns the pinned id (must be lowercase hex so the
/// AC-34 `cluster_id` regex `^cl-[a-z0-9][a-z0-9-]*-[0-9a-f]{1,16}$` holds for
/// the `batch_id[..8]` suffix).
#[derive(Clone, Debug)]
pub struct FixedBatchIdSource(pub String);

impl BatchIdSource for FixedBatchIdSource {
    fn next(&self) -> String {
        self.0.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuid_source_is_16_hex_chars() {
        let s = UuidBatchIdSource;
        let a = s.next();
        let b = s.next();
        assert_eq!(a.len(), 16);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b, "two draws must differ (v4 entropy)");
    }

    #[test]
    fn fixed_source_is_deterministic() {
        let s = FixedBatchIdSource("b0c1d2e3".into());
        assert_eq!(s.next(), "b0c1d2e3");
        assert_eq!(s.next(), "b0c1d2e3");
    }
}

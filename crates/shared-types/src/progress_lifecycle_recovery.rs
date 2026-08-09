//! Boot-stable, anti-rollback recovery journal shared by CONTRACT-215/216.
//!
//! This module deliberately exports one concrete journal and two linear role
//! handles.  It does **not** export a storage trait or a generic mutation API.
//! Provider-facing, typed operations are layered on the role handles by the
//! authority modules; the byte codec, external-anchor comparison, logical row
//! maps, four-step transaction protocol, recovery, and checkpoint machinery
//! remain private here.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{Key, Tag, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::turn_attribution::TurnAuthorityInitError;

type HmacSha256 = Hmac<Sha256>;

const SEGMENT_MAGIC: &[u8; 8] = b"ADVJSEG1";
const ANCHOR_ENVELOPE_MAGIC: &[u8; 8] = b"ADVJAE01";
const ANCHOR_PLAINTEXT_MAGIC: &[u8; 8] = b"ADVJANC1";
const FORMAT_VERSION: u16 = 1;

const PROTECTED_SEGMENT: u8 = 0x01;
const RECOVERY_SEGMENT: u8 = 0x02;
const SEGMENT_HEADER_LEN: usize = 44;
const PROTECTED_FILE: &str = "protected-v1.log";
const RECOVERY_FILE: &str = "recovery-v1.log";

const FRAME_PREPARED: u8 = 0xf0;
const FRAME_COMMITTED: u8 = 0xf1;
const FRAME_CHECKPOINT: u8 = 0xf2;
const FRAME_FIXED_LEN: usize = 45;
const TRANSACTION_PAYLOAD_FIXED_LEN: usize = 184;

const MAX_DELTA_BYTES: usize = 8_388_608;
const SOFT_LOG_BYTES: u64 = 46_137_344;
const HARD_LOG_BYTES: u64 = 67_108_864;
const SOFT_LOG_FRAMES: u64 = 196_608;
const HARD_LOG_FRAMES: u64 = 262_144;
const MAX_PROTECTED_ROW_BYTES: u64 = 16_777_216;
const MAX_RECOVERY_ROW_BYTES: u64 = 16_777_216;
const MAX_CARD_ROWS: u64 = 4_096;
const MAX_AUTHORITY_ROWS: u64 = 65_536;
const MAX_AUTHORITY_BYTES: u64 = 8_388_608;
const MAX_RECOVERY_LIFECYCLE_ROWS: u64 = 16_384;
const MAX_ROUTE_REFS: usize = 250_000;

const DOMAIN_SEGMENT_HEADER: &[u8] = b"advance.progress-journal.segment-header.v1";
const DOMAIN_ANCHOR_KEY: &[u8] = b"advance.progress-journal.anchor-aead.xchacha20poly1305.v1";
const DOMAIN_FRAME_SALT: &[u8] = b"advance.progress-journal.frame-hkdf-salt.v1";
const DOMAIN_FRAME_PROTECTED: &[u8] = b"advance.progress-journal.frame-mac.protected.v1";
const DOMAIN_FRAME_RECOVERY: &[u8] = b"advance.progress-journal.frame-mac.recovery.v1";
const DOMAIN_STATE_ROOT: &[u8] = b"advance.progress-journal.state-root.v1";
const DOMAIN_GENESIS_HEAD: &[u8] = b"advance.progress-journal.genesis-head.v1";
const DOMAIN_HEAD: &[u8] = b"advance.progress-journal.head.v1";
const DOMAIN_ANCHOR_REVISION: &[u8] = b"advance.progress-journal.anchor-revision.v1";
const DOMAIN_RUNTIME_MARKER: &[u8] = b"advance.progress-lifecycle.runtime-marker.v1";
const DOMAIN_LOCK_EVIDENCE: &[u8] = b"advance.progress-lifecycle.lock-evidence.v1";
const DOMAIN_RETIRED_REFS: &[u8] = b"advance.contract215.retired-route-refs.v1";
const DOMAIN_CLOSE_TARGET: &[u8] = b"advance.contract215.close-target.v1";

/// Composition-only configuration for the concrete recovery journal.
///
/// `key_epoch` is explicit and non-zero.  Codec v1 fixes it for the lifetime
/// of a journal instance; opening an existing anchor with another epoch fails
/// closed.  The anchor must be placed outside `journal_dir`; the composition
/// root is additionally responsible for selecting an anchor parent outside
/// the workspace snapshot domain.
pub struct RecoveryJournalConfig {
    journal_dir: PathBuf,
    external_anchor_path: PathBuf,
    key_epoch: NonZeroU32,
    integrity_key: Zeroizing<[u8; 32]>,
}

impl RecoveryJournalConfig {
    pub fn new_at_composition(
        journal_dir: PathBuf,
        external_anchor_path: PathBuf,
        key_epoch: NonZeroU32,
        integrity_key: Zeroizing<[u8; 32]>,
    ) -> Result<Self, TurnAuthorityInitError> {
        if journal_dir.as_os_str().is_empty()
            || external_anchor_path.as_os_str().is_empty()
            || external_anchor_path.file_name().is_none()
            || journal_dir == external_anchor_path
            || external_anchor_path.starts_with(&journal_dir)
        {
            return Err(TurnAuthorityInitError::RecoveryKeyUnavailable);
        }
        Ok(Self {
            journal_dir,
            external_anchor_path,
            key_epoch,
            integrity_key,
        })
    }
}

impl std::fmt::Debug for RecoveryJournalConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecoveryJournalConfig")
            .field("journal_dir", &self.journal_dir)
            .field("external_anchor_path", &self.external_anchor_path)
            .field("key_epoch", &self.key_epoch)
            .field("integrity_key", &"<redacted>")
            .finish()
    }
}

/// Concrete journal.  Consuming `split_at_composition` is the only way to
/// obtain its two authority roles, so a value can be split at most once.
pub struct ProgressLifecycleRecoveryJournal {
    core: Arc<Mutex<JournalCore>>,
}

/// Linear CONTRACT-216 half of the shared journal.
///
/// Intentionally non-Clone, non-Serialize, and non-Debug.
pub struct TurnRecoveryJournalRole {
    core: Arc<Mutex<JournalCore>>,
}

/// Linear CONTRACT-215 half of the shared journal.
///
/// Intentionally non-Clone, non-Serialize, and non-Debug.
pub struct ProgressRecoveryJournalRole {
    core: Arc<Mutex<JournalCore>>,
}

#[derive(Clone, Copy)]
pub(crate) struct TurnActiveSourceInput {
    pub(crate) source_digest: [u8; 32],
    pub(crate) expected_agent_digest: [u8; 32],
    pub(crate) generation: u64,
    pub(crate) created_at_ms: u64,
}

#[derive(Clone, Copy)]
pub(crate) struct TurnSourceExpectation {
    pub(crate) source_digest: [u8; 32],
    pub(crate) expected_agent_digest: [u8; 32],
    pub(crate) generation: u64,
}

#[derive(Clone, Copy)]
pub(crate) enum TurnStoreEvidence {
    Drained {
        store_incarnation: [u8; 16],
        store_epoch: u64,
        evidence_digest: [u8; 32],
    },
    StoreDestroyed {
        store_incarnation: [u8; 16],
        evidence_digest: [u8; 32],
    },
}

#[derive(Clone, Copy)]
pub(crate) struct TurnQuiescedSourceRecord {
    pub(crate) origin_runtime: [u8; 16],
    pub(crate) source_digest: [u8; 32],
    pub(crate) expected_agent_digest: [u8; 32],
    pub(crate) generation: u64,
    pub(crate) progress_key_digest: [u8; 32],
    pub(crate) store_incarnation: [u8; 16],
    pub(crate) evidence_digest: [u8; 32],
    #[allow(dead_code)]
    // persisted-record layout completeness: decoded from the journal even though no reader consumes it yet
    pub(crate) committed_at_ms: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TurnJournalWriteError {
    Capacity,
    Conflict,
    Unavailable,
    Rollback,
    Corrupt,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ProgressAttemptKind {
    InitialSend,
    Edit(i64),
    FallbackSend(i64),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ProgressProtectedCardRow {
    TerminalTombstone {
        generation: u64,
        terminal_fingerprint: [u8; 32],
        delivered_at_ms: u64,
    },
    IndeterminateSend {
        generation: u64,
        attempt_id: [u8; 16],
        delivery_fingerprint: [u8; 32],
        phase: u8,
        attempt_kind: ProgressAttemptKind,
        first_attempted_at_ms: u64,
    },
    FallbackExhausted {
        generation: u64,
        delivery_fingerprint: [u8; 32],
        definitively_lost_message_id: i64,
        reconciled_at_ms: u64,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProgressRouteRefKind {
    Action,
    Retry,
    Replay,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ProgressRouteArmInput {
    pub(crate) key_digest: [u8; 32],
    pub(crate) source_digest: [u8; 32],
    pub(crate) expected_agent_digest: [u8; 32],
    pub(crate) armed_at_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProgressRouteBindingRecord {
    pub(crate) key_digest: [u8; 32],
    pub(crate) source_digest: [u8; 32],
    pub(crate) expected_agent_digest: [u8; 32],
    pub(crate) origin_runtime: [u8; 16],
    pub(crate) turn_generation: u64,
    pub(crate) lifecycle_generation: u64,
    pub(crate) route_seal_generation: u64,
    pub(crate) armed_at_ms: u64,
    pub(crate) action_refs: u32,
    pub(crate) retry_refs: u32,
    pub(crate) replay_refs: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ProgressRouteExpectation {
    pub(crate) key_digest: [u8; 32],
    pub(crate) source_digest: [u8; 32],
    pub(crate) lifecycle_generation: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ProgressRouteRefExpectation {
    pub(crate) key_digest: [u8; 32],
    pub(crate) source_digest: [u8; 32],
    pub(crate) ref_id: [u8; 16],
    pub(crate) kind: ProgressRouteRefKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProgressRouteRefRecord {
    pub(crate) binding: ProgressRouteBindingRecord,
    pub(crate) ref_id: [u8; 16],
    pub(crate) kind: ProgressRouteRefKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ProgressRouteSealInput {
    pub(crate) key_digest: [u8; 32],
    pub(crate) source_digest: [u8; 32],
    pub(crate) source_receipt_digest: [u8; 32],
    pub(crate) sealed_at_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProgressSealedRouteRecord {
    pub(crate) binding: ProgressRouteBindingRecord,
    pub(crate) runtime_retired: bool,
    pub(crate) retired_action_refs: u32,
    pub(crate) retired_retry_refs: u32,
    pub(crate) retired_replay_refs: u32,
    pub(crate) retired_ref_digest: Option<[u8; 32]>,
    pub(crate) seal_evidence_digest: [u8; 32],
    pub(crate) source_receipt_digest: [u8; 32],
    pub(crate) sealed_at_ms: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ProgressLiveSnapshot {
    pub(crate) generation: u64,
    pub(crate) telegram_message_id: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum ProgressCloseTargetKind {
    NoCard = 0x00,
    Live = 0x01,
    TerminalTombstone = 0x02,
    IndeterminateSend = 0x03,
    FallbackExhausted = 0x04,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProgressCloseSnapshot {
    pub(crate) key_digest: [u8; 32],
    pub(crate) source_digest: [u8; 32],
    pub(crate) lifecycle_generation: u64,
    pub(crate) target_kind: ProgressCloseTargetKind,
    pub(crate) target_fingerprint: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProgressAuthorityState {
    Live,
    Cancelled { at_ms: u64 },
    Consumed { at_ms: u64 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProgressAuthorityEnvelope {
    pub(crate) state: ProgressAuthorityState,
    pub(crate) authority_id: [u8; 16],
    pub(crate) issued_ms: u64,
    pub(crate) expires_ms: u64,
    pub(crate) retain_until_ms: u64,
    pub(crate) mac: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ProgressAuthorityRow {
    RouteSealReceipt {
        key_digest: [u8; 32],
        nonce: [u8; 16],
        source_digest: [u8; 32],
        source_quiesced_receipt_digest: [u8; 32],
        route_seal_generation: u64,
        action_refs: u32,
        retry_refs: u32,
        replay_refs: u32,
        envelope: ProgressAuthorityEnvelope,
    },
    SourceCloseChallenge {
        key_digest: [u8; 32],
        nonce: [u8; 16],
        source_digest: [u8; 32],
        record_generation: u64,
        record_kind: ProgressCloseTargetKind,
        record_fingerprint: [u8; 32],
        envelope: ProgressAuthorityEnvelope,
    },
    SourceCloseAttestation {
        challenge_digest: [u8; 32],
        nonce: [u8; 16],
        key_digest: [u8; 32],
        source_digest: [u8; 32],
        source_receipt_digest: [u8; 32],
        route_receipt_digest: [u8; 32],
        envelope: ProgressAuthorityEnvelope,
    },
    AttemptReconciliationChallenge {
        key_digest: [u8; 32],
        nonce: [u8; 16],
        record_generation: u64,
        attempt_id: [u8; 16],
        attempt_kind: ProgressAttemptKind,
        delivery_fingerprint: [u8; 32],
        phase: u8,
        envelope: ProgressAuthorityEnvelope,
    },
    TrustedAttemptOutcomeReceipt {
        challenge_digest: [u8; 32],
        nonce: [u8; 16],
        key_digest: [u8; 32],
        record_generation: u64,
        attempt_id: [u8; 16],
        attempt_kind: ProgressAttemptKind,
        delivery_fingerprint: [u8; 32],
        delivered_message_id: Option<i64>,
        evidence_source: u8,
        evidence_id: [u8; 16],
        evidence_digest: [u8; 32],
        envelope: ProgressAuthorityEnvelope,
    },
    AttemptReconciliationProof {
        challenge_digest: [u8; 32],
        nonce: [u8; 16],
        key_digest: [u8; 32],
        record_generation: u64,
        attempt_id: [u8; 16],
        attempt_kind: ProgressAttemptKind,
        delivery_fingerprint: [u8; 32],
        delivered_message_id: Option<i64>,
        evidence_source: u8,
        evidence_id: [u8; 16],
        evidence_digest: [u8; 32],
        envelope: ProgressAuthorityEnvelope,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProgressAuthorityExpectation {
    pub(crate) expected: ProgressAuthorityRow,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProgressAuthorityTerminal {
    Cancelled { at_ms: u64 },
    Consumed { at_ms: u64 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProgressAttemptCommit {
    pub(crate) key_digest: [u8; 32],
    pub(crate) expected_indeterminate: ProgressProtectedCardRow,
    pub(crate) next_card: Option<ProgressProtectedCardRow>,
    pub(crate) challenge: ProgressAuthorityExpectation,
    pub(crate) proof: ProgressAuthorityExpectation,
    pub(crate) committed_at_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProgressSourceCloseCommit {
    pub(crate) expected_snapshot: ProgressCloseSnapshot,
    pub(crate) source_receipt_digest: [u8; 32],
    pub(crate) route_receipt_digest: [u8; 32],
    pub(crate) route_authority: ProgressAuthorityExpectation,
    pub(crate) challenge_authority: ProgressAuthorityExpectation,
    pub(crate) attestation_authority: ProgressAuthorityExpectation,
    pub(crate) committed_at_ms: u64,
    pub(crate) retain_until_ms: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProgressJournalError {
    Capacity,
    Conflict,
    Unavailable,
    Rollback,
    Corrupt,
    GenerationExhausted,
}

impl ProgressLifecycleRecoveryJournal {
    /// Opens, bootstraps or fully recovers both segments and the external
    /// anchor before returning.  Runtime-marker retirement is completed before
    /// this value can be split or any authority can be constructed.
    pub fn open_at_composition(
        config: RecoveryJournalConfig,
    ) -> Result<Self, TurnAuthorityInitError> {
        let mut rng = rand::rngs::OsRng;
        Self::open_with_rng(config, &mut rng)
    }

    fn open_with_rng<R: RngCore + CryptoRng>(
        config: RecoveryJournalConfig,
        rng: &mut R,
    ) -> Result<Self, TurnAuthorityInitError> {
        JournalCore::open(config, rng)
            .map(|core| Self {
                core: Arc::new(Mutex::new(core)),
            })
            .map_err(JournalError::into_init_error)
    }

    /// One consuming split; both roles retain the same private transaction
    /// engine and journal lineage.
    pub fn split_at_composition(self) -> (TurnRecoveryJournalRole, ProgressRecoveryJournalRole) {
        let progress = ProgressRecoveryJournalRole {
            core: Arc::clone(&self.core),
        };
        let turn = TurnRecoveryJournalRole { core: self.core };
        (turn, progress)
    }
}

impl TurnRecoveryJournalRole {
    pub(crate) fn insert_active_source(
        &self,
        input: TurnActiveSourceInput,
    ) -> Result<(), TurnJournalWriteError> {
        if input.generation == 0 {
            return Err(TurnJournalWriteError::Conflict);
        }
        let mut core = JournalCore::lock(&self.core).map_err(TurnJournalWriteError::from)?;
        let runtime = published_runtime(&core).map_err(TurnJournalWriteError::from)?;
        let mut value = Vec::with_capacity(97);
        value.extend_from_slice(&runtime);
        value.extend_from_slice(&input.expected_agent_digest);
        value.extend_from_slice(&input.generation.to_be_bytes());
        value.push(0); // progress_key_digest=None
        value.extend_from_slice(&input.created_at_ms.to_be_bytes());
        let mut rng = rand::rngs::OsRng;
        core.transact(
            &[Operation::insert(
                RECOVERY_SEGMENT,
                0x01,
                input.source_digest.to_vec(),
                value,
            )],
            &mut rng,
        )
        .map_err(TurnJournalWriteError::from)
    }

    pub(crate) fn retire_unbound_source(
        &self,
        expectation: TurnSourceExpectation,
    ) -> Result<(), TurnJournalWriteError> {
        let mut core = JournalCore::lock(&self.core).map_err(TurnJournalWriteError::from)?;
        let runtime = published_runtime(&core).map_err(TurnJournalWriteError::from)?;
        let key = RowKey {
            tag: 0x01,
            key: expectation.source_digest.to_vec(),
        };
        let before = core
            .state
            .recovery
            .get(&key)
            .cloned()
            .ok_or(TurnJournalWriteError::Conflict)?;
        let ParsedRecoveryRow::Active(active) =
            parse_recovery_row(&key, &before).map_err(TurnJournalWriteError::from)?
        else {
            return Err(TurnJournalWriteError::Conflict);
        };
        if active.runtime != runtime
            || active.expected_agent != expectation.expected_agent_digest
            || active.generation != expectation.generation
            || active.progress_key.is_some()
        {
            return Err(TurnJournalWriteError::Conflict);
        }
        let mut rng = rand::rngs::OsRng;
        core.transact(
            &[Operation::delete(
                RECOVERY_SEGMENT,
                0x01,
                expectation.source_digest.to_vec(),
                before,
            )],
            &mut rng,
        )
        .map_err(TurnJournalWriteError::from)
    }

    pub(crate) fn commit_store_quiescence(
        &self,
        expectation: TurnSourceExpectation,
        evidence: TurnStoreEvidence,
        committed_at_ms: u64,
    ) -> Result<Option<TurnQuiescedSourceRecord>, TurnJournalWriteError> {
        let mut core = JournalCore::lock(&self.core).map_err(TurnJournalWriteError::from)?;
        let runtime = published_runtime(&core).map_err(TurnJournalWriteError::from)?;
        let active_key = RowKey {
            tag: 0x01,
            key: expectation.source_digest.to_vec(),
        };
        let before = core
            .state
            .recovery
            .get(&active_key)
            .cloned()
            .ok_or(TurnJournalWriteError::Conflict)?;
        let ParsedRecoveryRow::Active(active) =
            parse_recovery_row(&active_key, &before).map_err(TurnJournalWriteError::from)?
        else {
            return Err(TurnJournalWriteError::Conflict);
        };
        if active.runtime != runtime
            || active.expected_agent != expectation.expected_agent_digest
            || active.generation != expectation.generation
        {
            return Err(TurnJournalWriteError::Conflict);
        }
        let mut rng = rand::rngs::OsRng;
        let Some(progress_key_digest) = active.progress_key else {
            core.transact(
                &[Operation::delete(
                    RECOVERY_SEGMENT,
                    0x01,
                    expectation.source_digest.to_vec(),
                    before,
                )],
                &mut rng,
            )
            .map_err(TurnJournalWriteError::from)?;
            return Ok(None);
        };
        let (store_incarnation, evidence_tag, evidence_bytes, evidence_digest) = match evidence {
            TurnStoreEvidence::Drained {
                store_incarnation,
                store_epoch,
                evidence_digest,
            } => {
                if store_incarnation == [0; 16] {
                    return Err(TurnJournalWriteError::Conflict);
                }
                (
                    store_incarnation,
                    0x00,
                    store_epoch.to_be_bytes().to_vec(),
                    evidence_digest,
                )
            }
            TurnStoreEvidence::StoreDestroyed {
                store_incarnation,
                evidence_digest,
            } => {
                if store_incarnation == [0; 16] {
                    return Err(TurnJournalWriteError::Conflict);
                }
                (
                    store_incarnation,
                    0x01,
                    store_incarnation.to_vec(),
                    evidence_digest,
                )
            }
        };
        let mut after = Vec::with_capacity(153 + evidence_bytes.len());
        after.extend_from_slice(&runtime);
        after.extend_from_slice(&expectation.expected_agent_digest);
        after.extend_from_slice(&expectation.generation.to_be_bytes());
        after.extend_from_slice(&progress_key_digest);
        after.extend_from_slice(&store_incarnation);
        after.push(evidence_tag);
        after.extend_from_slice(&evidence_bytes);
        after.extend_from_slice(&evidence_digest);
        after.extend_from_slice(&committed_at_ms.to_be_bytes());
        let operations = [
            Operation::delete(
                RECOVERY_SEGMENT,
                0x01,
                expectation.source_digest.to_vec(),
                before,
            ),
            Operation::insert(
                RECOVERY_SEGMENT,
                0x02,
                expectation.source_digest.to_vec(),
                after,
            ),
        ];
        core.transact(&operations, &mut rng)
            .map_err(TurnJournalWriteError::from)?;
        Ok(Some(TurnQuiescedSourceRecord {
            origin_runtime: runtime,
            source_digest: expectation.source_digest,
            expected_agent_digest: expectation.expected_agent_digest,
            generation: expectation.generation,
            progress_key_digest,
            store_incarnation,
            evidence_digest,
            committed_at_ms,
        }))
    }

    /// Return every unconsumed quiesced source in canonical journal order.
    /// This is the bounded boot-recovery enumeration seam: callers receive
    /// typed records only, never generic row keys or journal bytes.
    pub(crate) fn read_pending_quiesced_sources(
        &self,
    ) -> Result<Vec<TurnQuiescedSourceRecord>, TurnJournalWriteError> {
        let core = JournalCore::lock(&self.core).map_err(TurnJournalWriteError::from)?;
        let count = core
            .state
            .recovery
            .keys()
            .filter(|key| key.tag == 0x02)
            .count();
        let mut records = Vec::new();
        records
            .try_reserve_exact(count)
            .map_err(|_| TurnJournalWriteError::Capacity)?;
        for (key, value) in core
            .state
            .recovery
            .iter()
            .filter(|(key, _)| key.tag == 0x02)
        {
            records.push(
                decode_turn_quiesced_record(key, value).map_err(TurnJournalWriteError::from)?,
            );
        }
        Ok(records)
    }

    pub(crate) fn current_runtime_incarnation(&self) -> Result<[u8; 16], TurnJournalWriteError> {
        let core = JournalCore::lock(&self.core).map_err(TurnJournalWriteError::from)?;
        published_runtime(&core).map_err(TurnJournalWriteError::from)
    }
}

impl ProgressRecoveryJournalRole {
    /// Test-support failpoint for proving callers retain move-only settlement
    /// authority when the durable transaction fails after its prepared frame.
    #[cfg(feature = "test-support")]
    pub(crate) fn test_fail_next_transaction_after_prepared_fsync(
        &self,
    ) -> Result<(), ProgressJournalError> {
        let mut core = JournalCore::lock(&self.core).map_err(ProgressJournalError::from)?;
        core.failpoint = Some(TxFailpoint::AfterPreparedFsync);
        Ok(())
    }

    /// Test-only terminality audit for one opaque source-bound progress key.
    /// Production consumers never receive a generic authority-row reader.
    #[cfg(feature = "test-support")]
    pub(crate) fn test_live_authority_count_for_key(
        &self,
        key_digest: [u8; 32],
    ) -> Result<usize, ProgressJournalError> {
        let core = JournalCore::lock(&self.core).map_err(ProgressJournalError::from)?;
        cancel_live_authorities_for_key(&core.state, key_digest, 0)
            .map(|operations| operations.len())
            .map_err(ProgressJournalError::from)
    }

    pub(crate) fn load_protected_cards(
        &self,
    ) -> Result<BTreeMap<[u8; 32], ProgressProtectedCardRow>, ProgressJournalError> {
        let core = JournalCore::lock(&self.core).map_err(ProgressJournalError::from)?;
        let mut cards = BTreeMap::new();
        for (key, value) in core
            .state
            .protected
            .iter()
            .filter(|(key, _)| (0x01..=0x03).contains(&key.tag))
        {
            let digest: [u8; 32] = key
                .key
                .as_slice()
                .try_into()
                .map_err(|_| ProgressJournalError::Corrupt)?;
            let row = decode_progress_card(key, value).map_err(ProgressJournalError::from)?;
            if cards.insert(digest, row).is_some() {
                return Err(ProgressJournalError::Corrupt);
            }
        }
        Ok(cards)
    }

    pub(crate) fn replace_protected_card(
        &self,
        key_digest: [u8; 32],
        expected: Option<ProgressProtectedCardRow>,
        next: Option<ProgressProtectedCardRow>,
    ) -> Result<(), ProgressJournalError> {
        let mut core = JournalCore::lock(&self.core).map_err(ProgressJournalError::from)?;
        let mut operations = card_transition_operations(&core.state, key_digest, expected, next)
            .map_err(ProgressJournalError::from)?;
        if operations.is_empty() {
            return Ok(());
        }
        sort_operations(&mut operations);
        let mut rng = rand::rngs::OsRng;
        core.transact(&operations, &mut rng)
            .map_err(ProgressJournalError::from)
    }

    pub(crate) fn arm_source_routes(
        &self,
        input: ProgressRouteArmInput,
    ) -> Result<ProgressRouteBindingRecord, ProgressJournalError> {
        let mut core = JournalCore::lock(&self.core).map_err(ProgressJournalError::from)?;
        let runtime = published_runtime(&core).map_err(ProgressJournalError::from)?;
        let active_key = RowKey {
            tag: 0x01,
            key: input.source_digest.to_vec(),
        };
        let active_before = core
            .state
            .recovery
            .get(&active_key)
            .cloned()
            .ok_or(ProgressJournalError::Conflict)?;
        let ParsedRecoveryRow::Active(active) =
            parse_recovery_row(&active_key, &active_before).map_err(ProgressJournalError::from)?
        else {
            return Err(ProgressJournalError::Conflict);
        };
        if active.runtime != runtime || active.expected_agent != input.expected_agent_digest {
            return Err(ProgressJournalError::Conflict);
        }
        let close_key = RowKey {
            tag: 0x03,
            key: input.key_digest.to_vec(),
        };
        if active.progress_key == Some(input.key_digest) {
            let close_value = core
                .state
                .recovery
                .get(&close_key)
                .ok_or(ProgressJournalError::Conflict)?;
            let details = decode_close_details(close_value).map_err(ProgressJournalError::from)?;
            return binding_for_open(&core.state, input.key_digest, input.source_digest, &details)
                .map_err(ProgressJournalError::from);
        }
        if active.progress_key.is_some() || core.state.recovery.contains_key(&close_key) {
            return Err(ProgressJournalError::Conflict);
        }
        let created_at_ms =
            decode_active_created_at(&active_before).map_err(ProgressJournalError::from)?;
        let active_after = encode_active_source(
            runtime,
            input.expected_agent_digest,
            active.generation,
            Some(input.key_digest),
            created_at_ms,
        );
        let close_after = encode_open_close(
            input.source_digest,
            input.expected_agent_digest,
            runtime,
            1,
            1,
            input.armed_at_ms,
            &[],
            &[],
            &[],
        )?;
        let mut operations = vec![
            Operation::replace(
                RECOVERY_SEGMENT,
                0x01,
                input.source_digest.to_vec(),
                active_before,
                active_after,
            ),
            Operation::insert(
                RECOVERY_SEGMENT,
                0x03,
                input.key_digest.to_vec(),
                close_after,
            ),
        ];
        sort_operations(&mut operations);
        let mut rng = rand::rngs::OsRng;
        core.transact(&operations, &mut rng)
            .map_err(ProgressJournalError::from)?;
        Ok(ProgressRouteBindingRecord {
            key_digest: input.key_digest,
            source_digest: input.source_digest,
            expected_agent_digest: input.expected_agent_digest,
            origin_runtime: runtime,
            turn_generation: active.generation,
            lifecycle_generation: 1,
            route_seal_generation: 1,
            armed_at_ms: input.armed_at_ms,
            action_refs: 0,
            retry_refs: 0,
            replay_refs: 0,
        })
    }

    pub(crate) fn acquire_route_ref(
        &self,
        expected: ProgressRouteExpectation,
        kind: ProgressRouteRefKind,
    ) -> Result<ProgressRouteRefRecord, ProgressJournalError> {
        let mut core = JournalCore::lock(&self.core).map_err(ProgressJournalError::from)?;
        let close_key = RowKey {
            tag: 0x03,
            key: expected.key_digest.to_vec(),
        };
        let before = core
            .state
            .recovery
            .get(&close_key)
            .cloned()
            .ok_or(ProgressJournalError::Conflict)?;
        let mut details = decode_close_details(&before).map_err(ProgressJournalError::from)?;
        if details.source != expected.source_digest
            || details.lifecycle_generation != expected.lifecycle_generation
            || details.sealed.is_some()
        {
            return Err(ProgressJournalError::Conflict);
        }
        let total = details
            .action
            .len()
            .checked_add(details.retry.len())
            .and_then(|n| n.checked_add(details.replay.len()))
            .ok_or(ProgressJournalError::Capacity)?;
        if total >= MAX_ROUTE_REFS {
            return Err(ProgressJournalError::Capacity);
        }
        let mut rng = rand::rngs::OsRng;
        let ref_id =
            generate_unique_route_ref(&details, &mut rng).map_err(ProgressJournalError::from)?;
        route_set_mut(&mut details, kind).push(ref_id);
        route_set_mut(&mut details, kind).sort_unstable();
        details.lifecycle_generation = details
            .lifecycle_generation
            .checked_add(1)
            .ok_or(ProgressJournalError::GenerationExhausted)?;
        let after = encode_close_details(&details).map_err(ProgressJournalError::from)?;
        core.transact(
            &[Operation::replace(
                RECOVERY_SEGMENT,
                0x03,
                expected.key_digest.to_vec(),
                before,
                after,
            )],
            &mut rng,
        )
        .map_err(ProgressJournalError::from)?;
        let binding = binding_for_open(
            &core.state,
            expected.key_digest,
            expected.source_digest,
            &details,
        )
        .map_err(ProgressJournalError::from)?;
        Ok(ProgressRouteRefRecord {
            binding,
            ref_id,
            kind,
        })
    }

    pub(crate) fn settle_route_ref(
        &self,
        expected: ProgressRouteRefExpectation,
    ) -> Result<ProgressRouteBindingRecord, ProgressJournalError> {
        let mut core = JournalCore::lock(&self.core).map_err(ProgressJournalError::from)?;
        let close_key = RowKey {
            tag: 0x03,
            key: expected.key_digest.to_vec(),
        };
        let before = core
            .state
            .recovery
            .get(&close_key)
            .cloned()
            .ok_or(ProgressJournalError::Conflict)?;
        let mut details = decode_close_details(&before).map_err(ProgressJournalError::from)?;
        if details.source != expected.source_digest || details.sealed.is_some() {
            return Err(ProgressJournalError::Conflict);
        }
        let set = route_set_mut(&mut details, expected.kind);
        let position = set
            .binary_search(&expected.ref_id)
            .map_err(|_| ProgressJournalError::Conflict)?;
        set.remove(position);
        details.lifecycle_generation = details
            .lifecycle_generation
            .checked_add(1)
            .ok_or(ProgressJournalError::GenerationExhausted)?;
        let after = encode_close_details(&details).map_err(ProgressJournalError::from)?;
        let mut rng = rand::rngs::OsRng;
        core.transact(
            &[Operation::replace(
                RECOVERY_SEGMENT,
                0x03,
                expected.key_digest.to_vec(),
                before,
                after,
            )],
            &mut rng,
        )
        .map_err(ProgressJournalError::from)?;
        binding_for_open(
            &core.state,
            expected.key_digest,
            expected.source_digest,
            &details,
        )
        .map_err(ProgressJournalError::from)
    }

    pub(crate) fn verify_route_ref_live(
        &self,
        expected: ProgressRouteRefExpectation,
    ) -> Result<ProgressRouteBindingRecord, ProgressJournalError> {
        let core = JournalCore::lock(&self.core).map_err(ProgressJournalError::from)?;
        let close_key = RowKey {
            tag: 0x03,
            key: expected.key_digest.to_vec(),
        };
        let value = core
            .state
            .recovery
            .get(&close_key)
            .ok_or(ProgressJournalError::Conflict)?;
        let details = decode_close_details(value).map_err(ProgressJournalError::from)?;
        if details.source != expected.source_digest || details.sealed.is_some() {
            return Err(ProgressJournalError::Conflict);
        }
        let set = match expected.kind {
            ProgressRouteRefKind::Action => &details.action,
            ProgressRouteRefKind::Retry => &details.retry,
            ProgressRouteRefKind::Replay => &details.replay,
        };
        if set.binary_search(&expected.ref_id).is_err() {
            return Err(ProgressJournalError::Conflict);
        }
        binding_for_open(
            &core.state,
            expected.key_digest,
            expected.source_digest,
            &details,
        )
        .map_err(ProgressJournalError::from)
    }

    pub(crate) fn seal_routes(
        &self,
        input: ProgressRouteSealInput,
    ) -> Result<ProgressSealedRouteRecord, ProgressJournalError> {
        if input.source_receipt_digest == [0; 32] {
            return Err(ProgressJournalError::Conflict);
        }
        let mut core = JournalCore::lock(&self.core).map_err(ProgressJournalError::from)?;
        let close_key = RowKey {
            tag: 0x03,
            key: input.key_digest.to_vec(),
        };
        let before = core
            .state
            .recovery
            .get(&close_key)
            .cloned()
            .ok_or(ProgressJournalError::Conflict)?;
        let mut details = decode_close_details(&before).map_err(ProgressJournalError::from)?;
        if details.source != input.source_digest
            || details.sealed.is_some()
            || !details.action.is_empty()
            || !details.retry.is_empty()
            || !details.replay.is_empty()
        {
            return Err(ProgressJournalError::Conflict);
        }
        details.lifecycle_generation = details
            .lifecycle_generation
            .checked_add(1)
            .ok_or(ProgressJournalError::GenerationExhausted)?;
        details.route_seal_generation = details
            .route_seal_generation
            .checked_add(1)
            .ok_or(ProgressJournalError::GenerationExhausted)?;
        details.sealed = Some(SealedCloseDetails {
            runtime_retired: false,
            retired_action: 0,
            retired_retry: 0,
            retired_replay: 0,
            retired_digest: None,
            evidence_digest: input.source_receipt_digest,
            sealed_at_ms: input.sealed_at_ms,
        });
        let after = encode_close_details(&details).map_err(ProgressJournalError::from)?;
        let mut rng = rand::rngs::OsRng;
        core.transact(
            &[Operation::replace(
                RECOVERY_SEGMENT,
                0x03,
                input.key_digest.to_vec(),
                before,
                after,
            )],
            &mut rng,
        )
        .map_err(ProgressJournalError::from)?;
        sealed_record_from_details(
            &core.state,
            input.key_digest,
            input.source_digest,
            input.source_receipt_digest,
            &details,
        )
        .map_err(ProgressJournalError::from)
    }

    pub(crate) fn reissue_sealed_routes(
        &self,
        key_digest: [u8; 32],
        source_digest: [u8; 32],
        source_receipt_digest: [u8; 32],
    ) -> Result<ProgressSealedRouteRecord, ProgressJournalError> {
        if source_receipt_digest == [0; 32] {
            return Err(ProgressJournalError::Conflict);
        }
        let core = JournalCore::lock(&self.core).map_err(ProgressJournalError::from)?;
        let close_key = RowKey {
            tag: 0x03,
            key: key_digest.to_vec(),
        };
        let value = core
            .state
            .recovery
            .get(&close_key)
            .ok_or(ProgressJournalError::Conflict)?;
        let details = decode_close_details(value).map_err(ProgressJournalError::from)?;
        sealed_record_from_details(
            &core.state,
            key_digest,
            source_digest,
            source_receipt_digest,
            &details,
        )
        .map_err(ProgressJournalError::from)
    }

    pub(crate) fn read_close_snapshot(
        &self,
        key_digest: [u8; 32],
        live: Option<ProgressLiveSnapshot>,
    ) -> Result<ProgressCloseSnapshot, ProgressJournalError> {
        let core = JournalCore::lock(&self.core).map_err(ProgressJournalError::from)?;
        close_snapshot(&core, key_digest, live).map_err(ProgressJournalError::from)
    }

    pub(crate) fn insert_authority(
        &self,
        row: ProgressAuthorityRow,
    ) -> Result<(), ProgressJournalError> {
        if authority_envelope(&row).state != ProgressAuthorityState::Live {
            return Err(ProgressJournalError::Conflict);
        }
        let mut core = JournalCore::lock(&self.core).map_err(ProgressJournalError::from)?;
        let (key, value) = encode_authority_row(&row).map_err(ProgressJournalError::from)?;
        let primary = &key.key[..32];
        if core.state.protected.iter().any(|(existing, value)| {
            existing.tag == key.tag
                && existing.key.get(..32) == Some(primary)
                && value.first() == Some(&0x00)
        }) {
            return Err(ProgressJournalError::Conflict);
        }
        let mut rng = rand::rngs::OsRng;
        core.transact(
            &[Operation::insert(
                PROTECTED_SEGMENT,
                key.tag,
                key.key,
                value,
            )],
            &mut rng,
        )
        .map_err(ProgressJournalError::from)
    }

    pub(crate) fn consume_or_cancel_authority(
        &self,
        expected: ProgressAuthorityExpectation,
        terminal: ProgressAuthorityTerminal,
    ) -> Result<(), ProgressJournalError> {
        let mut core = JournalCore::lock(&self.core).map_err(ProgressJournalError::from)?;
        let operation = authority_terminal_operation(&core.state, expected, terminal)
            .map_err(ProgressJournalError::from)?;
        let mut rng = rand::rngs::OsRng;
        core.transact(&[operation], &mut rng)
            .map_err(ProgressJournalError::from)
    }

    pub(crate) fn replace_authority_with(
        &self,
        expected: ProgressAuthorityExpectation,
        next: ProgressAuthorityRow,
        consumed_at_ms: u64,
    ) -> Result<(), ProgressJournalError> {
        if authority_row_tag(&expected.expected) != 0x14
            || authority_row_tag(&next) != 0x15
            || authority_envelope(&next).state != ProgressAuthorityState::Live
        {
            return Err(ProgressJournalError::Conflict);
        }
        let mut core = JournalCore::lock(&self.core).map_err(ProgressJournalError::from)?;
        let consumed = authority_terminal_operation(
            &core.state,
            expected,
            ProgressAuthorityTerminal::Consumed {
                at_ms: consumed_at_ms,
            },
        )
        .map_err(ProgressJournalError::from)?;
        let (next_key, next_value) =
            encode_authority_row(&next).map_err(ProgressJournalError::from)?;
        if core.state.protected.contains_key(&next_key) {
            return Err(ProgressJournalError::Conflict);
        }
        let mut operations = vec![
            consumed,
            Operation::insert(PROTECTED_SEGMENT, next_key.tag, next_key.key, next_value),
        ];
        sort_operations(&mut operations);
        let mut rng = rand::rngs::OsRng;
        core.transact(&operations, &mut rng)
            .map_err(ProgressJournalError::from)
    }

    pub(crate) fn commit_attempt_reconciliation(
        &self,
        commit: ProgressAttemptCommit,
    ) -> Result<(), ProgressJournalError> {
        if !matches!(
            commit.expected_indeterminate,
            ProgressProtectedCardRow::IndeterminateSend { .. }
        ) || authority_row_tag(&commit.challenge.expected) != 0x13
            || authority_row_tag(&commit.proof.expected) != 0x15
        {
            return Err(ProgressJournalError::Conflict);
        }
        let mut core = JournalCore::lock(&self.core).map_err(ProgressJournalError::from)?;
        let mut operations = card_transition_operations(
            &core.state,
            commit.key_digest,
            Some(commit.expected_indeterminate),
            commit.next_card,
        )
        .map_err(ProgressJournalError::from)?;
        operations.push(
            authority_terminal_operation(
                &core.state,
                commit.challenge,
                ProgressAuthorityTerminal::Consumed {
                    at_ms: commit.committed_at_ms,
                },
            )
            .map_err(ProgressJournalError::from)?,
        );
        operations.push(
            authority_terminal_operation(
                &core.state,
                commit.proof,
                ProgressAuthorityTerminal::Consumed {
                    at_ms: commit.committed_at_ms,
                },
            )
            .map_err(ProgressJournalError::from)?,
        );
        sort_operations(&mut operations);
        let mut rng = rand::rngs::OsRng;
        core.transact(&operations, &mut rng)
            .map_err(ProgressJournalError::from)
    }

    pub(crate) fn commit_source_close(
        &self,
        commit: ProgressSourceCloseCommit,
    ) -> Result<(), ProgressJournalError> {
        if commit.committed_at_ms > commit.retain_until_ms
            || authority_row_tag(&commit.route_authority.expected) != 0x10
            || authority_row_tag(&commit.challenge_authority.expected) != 0x11
            || authority_row_tag(&commit.attestation_authority.expected) != 0x12
        {
            return Err(ProgressJournalError::Conflict);
        }
        let mut core = JournalCore::lock(&self.core).map_err(ProgressJournalError::from)?;
        validate_source_close_authorities(&commit).map_err(ProgressJournalError::from)?;
        let key_digest = commit.expected_snapshot.key_digest;
        let source_digest = commit.expected_snapshot.source_digest;
        let close_key = RowKey {
            tag: 0x03,
            key: key_digest.to_vec(),
        };
        let close_before = core
            .state
            .recovery
            .get(&close_key)
            .cloned()
            .ok_or(ProgressJournalError::Conflict)?;
        let close = decode_close_details(&close_before).map_err(ProgressJournalError::from)?;
        if close.source != source_digest
            || close.lifecycle_generation != commit.expected_snapshot.lifecycle_generation
            || close.sealed.is_none()
        {
            return Err(ProgressJournalError::Conflict);
        }
        validate_close_snapshot_for_commit(&core, &commit.expected_snapshot)
            .map_err(ProgressJournalError::from)?;
        let source_key = RowKey {
            tag: 0x02,
            key: source_digest.to_vec(),
        };
        let source_before = core
            .state
            .recovery
            .get(&source_key)
            .cloned()
            .ok_or(ProgressJournalError::Conflict)?;
        let ParsedRecoveryRow::Quiesced(source) =
            parse_recovery_row(&source_key, &source_before).map_err(ProgressJournalError::from)?
        else {
            return Err(ProgressJournalError::Conflict);
        };
        if source.progress_key != key_digest
            || source.expected_agent != close.expected_agent
            || source.runtime != close.runtime
        {
            return Err(ProgressJournalError::Conflict);
        }
        let consumed_key = RowKey {
            tag: 0x04,
            key: key_digest.to_vec(),
        };
        if core.state.recovery.contains_key(&consumed_key) {
            return Err(ProgressJournalError::Conflict);
        }

        let mut operations = Vec::with_capacity(8);
        if let Some((tag, _, before)) =
            find_progress_card(&core.state, key_digest).map_err(ProgressJournalError::from)?
        {
            operations.push(Operation::delete(
                PROTECTED_SEGMENT,
                tag,
                key_digest.to_vec(),
                before,
            ));
        }
        for authority in [
            commit.route_authority,
            commit.challenge_authority,
            commit.attestation_authority,
        ] {
            operations.push(
                authority_terminal_operation(
                    &core.state,
                    authority,
                    ProgressAuthorityTerminal::Consumed {
                        at_ms: commit.committed_at_ms,
                    },
                )
                .map_err(ProgressJournalError::from)?,
            );
        }
        operations.push(Operation::delete(
            RECOVERY_SEGMENT,
            0x02,
            source_digest.to_vec(),
            source_before,
        ));
        operations.push(Operation::delete(
            RECOVERY_SEGMENT,
            0x03,
            key_digest.to_vec(),
            close_before,
        ));
        let mut consumed = Vec::with_capacity(153);
        consumed.extend_from_slice(&source_digest);
        consumed.extend_from_slice(&commit.expected_snapshot.lifecycle_generation.to_be_bytes());
        consumed.push(commit.expected_snapshot.target_kind as u8);
        consumed.extend_from_slice(&commit.expected_snapshot.target_fingerprint);
        consumed.extend_from_slice(&commit.source_receipt_digest);
        consumed.extend_from_slice(&commit.route_receipt_digest);
        consumed.extend_from_slice(&commit.committed_at_ms.to_be_bytes());
        consumed.extend_from_slice(&commit.retain_until_ms.to_be_bytes());
        operations.push(Operation::insert(
            RECOVERY_SEGMENT,
            0x04,
            key_digest.to_vec(),
            consumed,
        ));
        sort_operations(&mut operations);
        let mut rng = rand::rngs::OsRng;
        core.transact(&operations, &mut rng)
            .map_err(ProgressJournalError::from)
    }
}

#[derive(Debug)]
enum JournalError {
    Configuration,
    Io,
    AnchorUnavailable,
    AnchorConflict,
    AnchorMismatch,
    Corrupt,
    Rollback,
    Capacity,
    SequenceExhausted,
    Unhealthy,
    InjectedFailure,
}

impl JournalError {
    fn into_init_error(self) -> TurnAuthorityInitError {
        match self {
            Self::Configuration => TurnAuthorityInitError::RecoveryKeyUnavailable,
            Self::Io | Self::AnchorUnavailable | Self::Unhealthy | Self::InjectedFailure => {
                TurnAuthorityInitError::AnchorUnavailable
            }
            Self::AnchorConflict | Self::AnchorMismatch => TurnAuthorityInitError::AnchorMismatch,
            Self::Rollback => TurnAuthorityInitError::RollbackDetected,
            Self::Capacity => TurnAuthorityInitError::RecoveryCapacityInvalid,
            Self::SequenceExhausted => TurnAuthorityInitError::SequenceExhausted,
            Self::Corrupt => TurnAuthorityInitError::RecoveryJournalCorrupt,
        }
    }
}

impl From<std::io::Error> for JournalError {
    fn from(_: std::io::Error) -> Self {
        Self::Io
    }
}

impl From<JournalError> for TurnJournalWriteError {
    fn from(error: JournalError) -> Self {
        match error {
            JournalError::Capacity | JournalError::SequenceExhausted => Self::Capacity,
            JournalError::AnchorConflict => Self::Conflict,
            JournalError::Io
            | JournalError::AnchorUnavailable
            | JournalError::Unhealthy
            | JournalError::InjectedFailure
            | JournalError::Configuration => Self::Unavailable,
            JournalError::AnchorMismatch | JournalError::Rollback => Self::Rollback,
            JournalError::Corrupt => Self::Corrupt,
        }
    }
}

impl From<JournalError> for ProgressJournalError {
    fn from(error: JournalError) -> Self {
        match error {
            JournalError::Capacity => Self::Capacity,
            JournalError::SequenceExhausted => Self::GenerationExhausted,
            JournalError::AnchorConflict => Self::Conflict,
            JournalError::Io
            | JournalError::AnchorUnavailable
            | JournalError::Unhealthy
            | JournalError::InjectedFailure
            | JournalError::Configuration => Self::Unavailable,
            JournalError::AnchorMismatch | JournalError::Rollback => Self::Rollback,
            JournalError::Corrupt => Self::Corrupt,
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
struct PendingAnchor {
    previous_head: [u8; 32],
    previous_state_root: [u8; 32],
    next_sequence: u64,
    next_head: [u8; 32],
    next_state_root: [u8; 32],
}

#[derive(Clone, PartialEq, Eq)]
enum AnchorState {
    BootstrapPending {
        instance_id: [u8; 16],
        bootstrap_nonce: [u8; 16],
        protected_header_digest: [u8; 32],
        recovery_header_digest: [u8; 32],
    },
    Committed {
        instance_id: [u8; 16],
        protected_header_digest: [u8; 32],
        recovery_header_digest: [u8; 32],
        sequence: u64,
        head: [u8; 32],
        root: [u8; 32],
        pending: Option<PendingAnchor>,
    },
}

#[derive(Clone)]
struct DecodedAnchor {
    key_epoch: NonZeroU32,
    kdf_salt: [u8; 32],
    state: AnchorState,
}

#[derive(Clone)]
struct AnchorSnapshot {
    bytes: Vec<u8>,
    revision: [u8; 32],
    decoded: DecodedAnchor,
}

struct ExternalAnchor {
    path: PathBuf,
    parent: PathBuf,
    _lock: File,
    key_epoch: NonZeroU32,
    key: Arc<Zeroizing<[u8; 32]>>,
}

impl ExternalAnchor {
    fn acquire(
        path: PathBuf,
        key_epoch: NonZeroU32,
        key: Arc<Zeroizing<[u8; 32]>>,
    ) -> Result<Self, JournalError> {
        let parent = path
            .parent()
            .ok_or(JournalError::Configuration)?
            .to_path_buf();
        create_owner_directory(&parent)?;
        let lock_path = sibling_suffix(&path, ".lock")?;
        let lock = open_owner_file(&lock_path, true, false)?;
        lock.try_lock()
            .map_err(|_| JournalError::AnchorUnavailable)?;
        reject_symlink(&path)?;
        Ok(Self {
            path,
            parent,
            _lock: lock,
            key_epoch,
            key,
        })
    }

    fn load(&self) -> Result<Option<AnchorSnapshot>, JournalError> {
        reject_symlink(&self.path)?;
        let bytes = match read_bounded_file(&self.path, 1_024)? {
            Some(bytes) => bytes,
            None => return Ok(None),
        };
        ensure_owner_file(&self.path)?;
        let decoded = decode_anchor_envelope(&bytes, self.key_epoch, &self.key)?;
        Ok(Some(AnchorSnapshot {
            revision: anchor_revision(&bytes),
            bytes,
            decoded,
        }))
    }

    fn compare_and_swap<R: RngCore + CryptoRng>(
        &self,
        expected: Option<&AnchorSnapshot>,
        kdf_salt: [u8; 32],
        state: &AnchorState,
        rng: &mut R,
    ) -> Result<AnchorSnapshot, JournalError> {
        let observed = self.load()?;
        match (expected, observed.as_ref()) {
            (None, None) => {}
            (Some(left), Some(right))
                if left.bytes.len() == right.bytes.len()
                    && bool::from(left.bytes.ct_eq(&right.bytes))
                    && bool::from(left.revision.ct_eq(&right.revision)) => {}
            _ => return Err(JournalError::AnchorConflict),
        }

        let bytes = encode_anchor_envelope(self.key_epoch, kdf_salt, state, &self.key, rng)?;
        if expected.is_none() {
            atomic_create_no_replace(&self.path, &bytes)?;
        } else {
            atomic_replace(&self.path, &bytes)?;
        }
        fsync_dir(&self.parent)?;
        let decoded = decode_anchor_envelope(&bytes, self.key_epoch, &self.key)?;
        Ok(AnchorSnapshot {
            revision: anchor_revision(&bytes),
            bytes,
            decoded,
        })
    }
}

fn encode_anchor_envelope<R: RngCore + CryptoRng>(
    key_epoch: NonZeroU32,
    kdf_salt: [u8; 32],
    state: &AnchorState,
    master_key: &[u8; 32],
    rng: &mut R,
) -> Result<Vec<u8>, JournalError> {
    let plaintext = encode_anchor_plaintext(state);
    if !matches!(plaintext.len(), 107 | 164 | 300) {
        return Err(JournalError::Corrupt);
    }
    let mut nonce = [0u8; 24];
    rng.fill_bytes(&mut nonce);
    let mut prefix = Vec::with_capacity(74);
    prefix.extend_from_slice(ANCHOR_ENVELOPE_MAGIC);
    prefix.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
    prefix.extend_from_slice(&key_epoch.get().to_be_bytes());
    prefix.extend_from_slice(&kdf_salt);
    prefix.extend_from_slice(&nonce);
    prefix.extend_from_slice(&(plaintext.len() as u32).to_be_bytes());
    debug_assert_eq!(prefix.len(), 74);

    let anchor_key = derive_anchor_key(master_key, &kdf_salt, key_epoch.get())?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&anchor_key));
    let mut ciphertext = plaintext;
    let tag = cipher
        .encrypt_in_place_detached(XNonce::from_slice(&nonce), &prefix, &mut ciphertext)
        .map_err(|_| JournalError::Corrupt)?;
    prefix.extend_from_slice(&ciphertext);
    prefix.extend_from_slice(tag.as_slice());
    Ok(prefix)
}

fn decode_anchor_envelope(
    bytes: &[u8],
    expected_epoch: NonZeroU32,
    master_key: &[u8; 32],
) -> Result<DecodedAnchor, JournalError> {
    if bytes.len() < 90 || bytes.get(..8) != Some(ANCHOR_ENVELOPE_MAGIC) {
        return Err(JournalError::AnchorMismatch);
    }
    let mut c = Cursor::new(bytes);
    c.expect(ANCHOR_ENVELOPE_MAGIC)?;
    if c.u16()? != FORMAT_VERSION {
        return Err(JournalError::AnchorMismatch);
    }
    let epoch = NonZeroU32::new(c.u32()?).ok_or(JournalError::AnchorMismatch)?;
    if epoch != expected_epoch {
        return Err(JournalError::AnchorMismatch);
    }
    let salt = c.b32()?;
    let nonce = c.take_array::<24>()?;
    let ciphertext_len = c.u32()? as usize;
    if !matches!(ciphertext_len, 107 | 164 | 300)
        || c.remaining()
            != ciphertext_len
                .checked_add(16)
                .ok_or(JournalError::Corrupt)?
    {
        return Err(JournalError::AnchorMismatch);
    }
    let aad = &bytes[..74];
    let mut ciphertext = c.take(ciphertext_len)?.to_vec();
    let tag = c.take_array::<16>()?;
    c.finish()?;
    let key = derive_anchor_key(master_key, &salt, epoch.get())?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
    cipher
        .decrypt_in_place_detached(
            XNonce::from_slice(&nonce),
            aad,
            &mut ciphertext,
            Tag::from_slice(&tag),
        )
        .map_err(|_| JournalError::AnchorMismatch)?;
    let state = decode_anchor_plaintext(&ciphertext)?;
    Ok(DecodedAnchor {
        key_epoch: epoch,
        kdf_salt: salt,
        state,
    })
}

fn encode_anchor_plaintext(state: &AnchorState) -> Vec<u8> {
    let mut out = Vec::with_capacity(300);
    out.extend_from_slice(ANCHOR_PLAINTEXT_MAGIC);
    out.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
    match state {
        AnchorState::BootstrapPending {
            instance_id,
            bootstrap_nonce,
            protected_header_digest,
            recovery_header_digest,
        } => {
            out.push(0x01);
            out.extend_from_slice(instance_id);
            out.extend_from_slice(bootstrap_nonce);
            out.extend_from_slice(protected_header_digest);
            out.extend_from_slice(recovery_header_digest);
        }
        AnchorState::Committed {
            instance_id,
            protected_header_digest,
            recovery_header_digest,
            sequence,
            head,
            root,
            pending,
        } => {
            out.push(0x02);
            out.extend_from_slice(instance_id);
            out.extend_from_slice(protected_header_digest);
            out.extend_from_slice(recovery_header_digest);
            out.extend_from_slice(&sequence.to_be_bytes());
            out.extend_from_slice(head);
            out.extend_from_slice(root);
            match pending {
                None => out.push(0x00),
                Some(pending) => {
                    out.push(0x01);
                    out.extend_from_slice(&pending.previous_head);
                    out.extend_from_slice(&pending.previous_state_root);
                    out.extend_from_slice(&pending.next_sequence.to_be_bytes());
                    out.extend_from_slice(&pending.next_head);
                    out.extend_from_slice(&pending.next_state_root);
                }
            }
        }
    }
    out
}

fn decode_anchor_plaintext(bytes: &[u8]) -> Result<AnchorState, JournalError> {
    let mut c = Cursor::new(bytes);
    c.expect(ANCHOR_PLAINTEXT_MAGIC)?;
    if c.u16()? != FORMAT_VERSION {
        return Err(JournalError::AnchorMismatch);
    }
    let state = match c.u8()? {
        0x01 if bytes.len() == 107 => AnchorState::BootstrapPending {
            instance_id: c.b16()?,
            bootstrap_nonce: c.b16()?,
            protected_header_digest: c.b32()?,
            recovery_header_digest: c.b32()?,
        },
        0x02 if matches!(bytes.len(), 164 | 300) => {
            let instance_id = c.b16()?;
            let protected_header_digest = c.b32()?;
            let recovery_header_digest = c.b32()?;
            let sequence = c.u64()?;
            let head = c.b32()?;
            let root = c.b32()?;
            let pending = match c.u8()? {
                0x00 if bytes.len() == 164 => None,
                0x01 if bytes.len() == 300 => Some(PendingAnchor {
                    previous_head: c.b32()?,
                    previous_state_root: c.b32()?,
                    next_sequence: c.u64()?,
                    next_head: c.b32()?,
                    next_state_root: c.b32()?,
                }),
                _ => return Err(JournalError::AnchorMismatch),
            };
            AnchorState::Committed {
                instance_id,
                protected_header_digest,
                recovery_header_digest,
                sequence,
                head,
                root,
                pending,
            }
        }
        _ => return Err(JournalError::AnchorMismatch),
    };
    c.finish()?;
    Ok(state)
}

fn derive_anchor_key(
    master_key: &[u8; 32],
    salt: &[u8; 32],
    epoch: u32,
) -> Result<[u8; 32], JournalError> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), master_key);
    let mut info = Vec::with_capacity(DOMAIN_ANCHOR_KEY.len() + 5);
    info.extend_from_slice(DOMAIN_ANCHOR_KEY);
    info.push(0);
    info.extend_from_slice(&epoch.to_be_bytes());
    let mut out = [0u8; 32];
    hkdf.expand(&info, &mut out)
        .map_err(|_| JournalError::Configuration)?;
    Ok(out)
}

fn derive_frame_key(
    master_key: &[u8; 32],
    instance_id: &[u8; 16],
    epoch: u32,
    segment: u8,
) -> Result<[u8; 32], JournalError> {
    let mut salt_input = Vec::with_capacity(DOMAIN_FRAME_SALT.len() + 21);
    salt_input.extend_from_slice(DOMAIN_FRAME_SALT);
    salt_input.push(0);
    salt_input.extend_from_slice(instance_id);
    salt_input.extend_from_slice(&epoch.to_be_bytes());
    let frame_salt: [u8; 32] = Sha256::digest(&salt_input).into();
    let hkdf = Hkdf::<Sha256>::new(Some(&frame_salt), master_key);
    let label = match segment {
        PROTECTED_SEGMENT => DOMAIN_FRAME_PROTECTED,
        RECOVERY_SEGMENT => DOMAIN_FRAME_RECOVERY,
        _ => return Err(JournalError::Corrupt),
    };
    let mut info = Vec::with_capacity(label.len() + 21);
    info.extend_from_slice(label);
    info.push(0);
    info.extend_from_slice(instance_id);
    info.extend_from_slice(&epoch.to_be_bytes());
    let mut out = [0u8; 32];
    hkdf.expand(&info, &mut out)
        .map_err(|_| JournalError::Configuration)?;
    Ok(out)
}

fn anchor_revision(bytes: &[u8]) -> [u8; 32] {
    domain_hash(DOMAIN_ANCHOR_REVISION, &[bytes])
}

fn domain_hash(domain: &[u8], fields: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(domain);
    h.update([0]);
    for field in fields {
        h.update(field);
    }
    h.finalize().into()
}

fn create_owner_directory(path: &Path) -> Result<(), JournalError> {
    if path.exists() {
        reject_symlink(path)?;
        if !path.is_dir() {
            return Err(JournalError::Configuration);
        }
    } else {
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            let mut builder = fs::DirBuilder::new();
            builder.recursive(true).mode(0o700);
            builder.create(path)?;
        }
        #[cfg(not(unix))]
        fs::create_dir_all(path)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(path)?.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(JournalError::Configuration);
        }
    }
    Ok(())
}

fn reject_symlink(path: &Path) -> Result<(), JournalError> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => Err(JournalError::Configuration),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(JournalError::Io),
    }
}

fn ensure_owner_file(path: &Path) -> Result<(), JournalError> {
    reject_symlink(path)?;
    let metadata = fs::metadata(path)?;
    if !metadata.is_file() {
        return Err(JournalError::Corrupt);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(JournalError::Corrupt);
        }
    }
    Ok(())
}

fn sibling_suffix(path: &Path, suffix: &str) -> Result<PathBuf, JournalError> {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or(JournalError::Configuration)?;
    Ok(path.with_file_name(format!("{name}{suffix}")))
}

fn open_owner_file(path: &Path, create: bool, truncate: bool) -> Result<File, JournalError> {
    reject_symlink(path)?;
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create(create)
        .truncate(truncate);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path)?;
    ensure_owner_file(path)?;
    Ok(file)
}

fn create_owner_file_exclusive(path: &Path) -> Result<File, JournalError> {
    reject_symlink(path)?;
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path)?;
    ensure_owner_file(path)?;
    Ok(file)
}

fn temp_path(path: &Path) -> Result<PathBuf, JournalError> {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or(JournalError::Configuration)?;
    let mut random = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut random);
    let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
    Ok(path.with_file_name(format!(".{name}.{suffix}.tmp")))
}

fn atomic_create_no_replace(path: &Path, bytes: &[u8]) -> Result<(), JournalError> {
    let parent = path.parent().ok_or(JournalError::Configuration)?;
    let temp = temp_path(path)?;
    let result = (|| {
        let mut file = create_owner_file_exclusive(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        // A same-directory hard-link is an atomic no-replace publication.  The
        // temp inode is then unlinked; the final link remains durable after the
        // directory fsync.
        fs::hard_link(&temp, path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                JournalError::AnchorConflict
            } else {
                JournalError::Io
            }
        })?;
        fs::remove_file(&temp)?;
        fsync_dir(parent)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

fn atomic_replace(path: &Path, bytes: &[u8]) -> Result<(), JournalError> {
    let parent = path.parent().ok_or(JournalError::Configuration)?;
    let temp = temp_path(path)?;
    let result = (|| {
        let mut file = create_owner_file_exclusive(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temp, path)?;
        fsync_dir(parent)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

fn fsync_dir(path: &Path) -> Result<(), JournalError> {
    File::open(path)?.sync_all()?;
    Ok(())
}

fn read_bounded_file(path: &Path, maximum: u64) -> Result<Option<Vec<u8>>, JournalError> {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(JournalError::Io),
    };
    if metadata.len() > maximum {
        return Err(JournalError::Corrupt);
    }
    let mut file = File::open(path)?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes)?;
    if bytes.len() as u64 != metadata.len() {
        return Err(JournalError::Corrupt);
    }
    Ok(Some(bytes))
}

fn segment_header(instance_id: [u8; 16], bootstrap_nonce: [u8; 16], tag: u8) -> [u8; 44] {
    let mut header = [0u8; 44];
    header[..8].copy_from_slice(SEGMENT_MAGIC);
    header[8..10].copy_from_slice(&FORMAT_VERSION.to_be_bytes());
    header[10] = tag;
    header[11] = 0;
    header[12..28].copy_from_slice(&instance_id);
    header[28..44].copy_from_slice(&bootstrap_nonce);
    header
}

fn validate_segment_header(
    header: &[u8],
    expected_instance: [u8; 16],
    expected_tag: u8,
) -> Result<[u8; 32], JournalError> {
    if header.len() != SEGMENT_HEADER_LEN
        || header.get(..8) != Some(SEGMENT_MAGIC)
        || u16::from_be_bytes([header[8], header[9]]) != FORMAT_VERSION
        || header[10] != expected_tag
        || header[11] != 0
        || header[12..28] != expected_instance
    {
        return Err(JournalError::Corrupt);
    }
    Ok(segment_header_digest(header))
}

fn segment_header_digest(header: &[u8]) -> [u8; 32] {
    domain_hash(DOMAIN_SEGMENT_HEADER, &[header])
}

#[derive(Clone)]
struct PhysicalFrame {
    tag: u8,
    payload: Vec<u8>,
    start: u64,
    end: u64,
}

#[derive(Clone)]
struct SegmentScan {
    tag: u8,
    #[allow(dead_code)]
    // raw header bytes retained alongside header_digest for forensic replay; digest is the consumed form
    header: [u8; SEGMENT_HEADER_LEN],
    header_digest: [u8; 32],
    frames: Vec<PhysicalFrame>,
    trailing_partial_at: Option<u64>,
    file_len: u64,
}

fn encode_frame(
    frame_tag: u8,
    epoch: u32,
    payload: &[u8],
    header_digest: &[u8; 32],
    frame_key: &[u8; 32],
) -> Result<Vec<u8>, JournalError> {
    if !matches!(
        frame_tag,
        FRAME_PREPARED | FRAME_COMMITTED | FRAME_CHECKPOINT
    ) {
        return Err(JournalError::Corrupt);
    }
    let mut out = Vec::with_capacity(FRAME_FIXED_LEN + payload.len());
    out.push(frame_tag);
    out.extend_from_slice(&epoch.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    out.extend_from_slice(payload);
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(frame_key).map_err(|_| JournalError::Configuration)?;
    mac.update(header_digest);
    mac.update(&[frame_tag]);
    mac.update(&epoch.to_be_bytes());
    mac.update(&(payload.len() as u64).to_be_bytes());
    mac.update(payload);
    out.extend_from_slice(&mac.finalize().into_bytes());
    Ok(out)
}

fn scan_segment(
    path: &Path,
    expected_tag: u8,
    instance_id: [u8; 16],
    epoch: u32,
    master_key: &[u8; 32],
) -> Result<SegmentScan, JournalError> {
    ensure_owner_file(path)?;
    let bytes = read_bounded_file(path, HARD_LOG_BYTES)?.ok_or(JournalError::Corrupt)?;
    if bytes.len() < SEGMENT_HEADER_LEN {
        return Err(JournalError::Corrupt);
    }
    let header: [u8; SEGMENT_HEADER_LEN] = bytes[..SEGMENT_HEADER_LEN]
        .try_into()
        .map_err(|_| JournalError::Corrupt)?;
    let header_digest = validate_segment_header(&header, instance_id, expected_tag)?;
    let frame_key = derive_frame_key(master_key, &instance_id, epoch, expected_tag)?;
    let mut offset = SEGMENT_HEADER_LEN;
    let mut frames = Vec::new();
    let mut trailing_partial_at = None;
    while offset < bytes.len() {
        let start = offset;
        if bytes.len() - offset < 13 {
            trailing_partial_at = Some(start as u64);
            break;
        }
        let tag = bytes[offset];
        if !matches!(tag, FRAME_PREPARED | FRAME_COMMITTED | FRAME_CHECKPOINT) {
            return Err(JournalError::Corrupt);
        }
        let frame_epoch = u32::from_be_bytes(
            bytes[offset + 1..offset + 5]
                .try_into()
                .map_err(|_| JournalError::Corrupt)?,
        );
        if frame_epoch != epoch {
            return Err(JournalError::Corrupt);
        }
        let payload_len = u64::from_be_bytes(
            bytes[offset + 5..offset + 13]
                .try_into()
                .map_err(|_| JournalError::Corrupt)?,
        );
        let frame_len = 13u64
            .checked_add(payload_len)
            .and_then(|value| value.checked_add(32))
            .ok_or(JournalError::Corrupt)?;
        if frame_len > HARD_LOG_BYTES || start as u64 + frame_len > bytes.len() as u64 {
            trailing_partial_at = Some(start as u64);
            break;
        }
        let payload_start = offset + 13;
        let payload_end = payload_start + payload_len as usize;
        let payload = &bytes[payload_start..payload_end];
        let supplied_mac = &bytes[payload_end..payload_end + 32];
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&frame_key)
            .map_err(|_| JournalError::Configuration)?;
        mac.update(&header_digest);
        mac.update(&[tag]);
        mac.update(&frame_epoch.to_be_bytes());
        mac.update(&payload_len.to_be_bytes());
        mac.update(payload);
        let expected_mac = mac.finalize().into_bytes();
        if !bool::from(expected_mac.as_slice().ct_eq(supplied_mac)) {
            return Err(JournalError::Corrupt);
        }
        offset += frame_len as usize;
        frames.push(PhysicalFrame {
            tag,
            payload: payload.to_vec(),
            start: start as u64,
            end: offset as u64,
        });
        if frames.len() as u64 > HARD_LOG_FRAMES {
            return Err(JournalError::Capacity);
        }
    }
    Ok(SegmentScan {
        tag: expected_tag,
        header,
        header_digest,
        frames,
        trailing_partial_at,
        file_len: bytes.len() as u64,
    })
}

fn append_frame(path: &Path, bytes: &[u8]) -> Result<(), JournalError> {
    let mut file = open_owner_file(path, false, false)?;
    file.seek(SeekFrom::End(0))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
struct RowKey {
    tag: u8,
    key: Vec<u8>,
}

#[derive(Clone, Default)]
struct LogicalState {
    protected: BTreeMap<RowKey, Vec<u8>>,
    recovery: BTreeMap<RowKey, Vec<u8>>,
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
struct ProtectedCounters {
    row_count: u64,
    rows_encoded_bytes: u64,
    protected_card_rows: u64,
    authority_rows: u64,
    authority_encoded_bytes: u64,
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
struct RecoveryCounters {
    row_count: u64,
    rows_encoded_bytes: u64,
    active_source_rows: u64,
    quiesced_source_rows: u64,
    close_lifecycle_rows: u64,
    consumed_close_rows: u64,
    runtime_marker_rows: u64,
}

fn encode_row(key: &RowKey, value: &[u8]) -> Result<Vec<u8>, JournalError> {
    let key_len = u32::try_from(key.key.len()).map_err(|_| JournalError::Capacity)?;
    let value_len = u32::try_from(value.len()).map_err(|_| JournalError::Capacity)?;
    let mut out = Vec::with_capacity(9 + key.key.len() + value.len());
    out.push(key.tag);
    out.extend_from_slice(&key_len.to_be_bytes());
    out.extend_from_slice(&key.key);
    out.extend_from_slice(&value_len.to_be_bytes());
    out.extend_from_slice(value);
    Ok(out)
}

fn protected_counters(state: &LogicalState) -> Result<ProtectedCounters, JournalError> {
    let mut counters = ProtectedCounters::default();
    for (key, value) in &state.protected {
        validate_row(PROTECTED_SEGMENT, key, value)?;
        let encoded = 9u64
            .checked_add(key.key.len() as u64)
            .and_then(|n| n.checked_add(value.len() as u64))
            .ok_or(JournalError::Capacity)?;
        counters.row_count = counters
            .row_count
            .checked_add(1)
            .ok_or(JournalError::Capacity)?;
        counters.rows_encoded_bytes = counters
            .rows_encoded_bytes
            .checked_add(encoded)
            .ok_or(JournalError::Capacity)?;
        match key.tag {
            0x01..=0x03 => {
                counters.protected_card_rows = counters
                    .protected_card_rows
                    .checked_add(1)
                    .ok_or(JournalError::Capacity)?;
            }
            0x10..=0x15 => {
                counters.authority_rows = counters
                    .authority_rows
                    .checked_add(1)
                    .ok_or(JournalError::Capacity)?;
                counters.authority_encoded_bytes = counters
                    .authority_encoded_bytes
                    .checked_add(encoded)
                    .ok_or(JournalError::Capacity)?;
            }
            _ => return Err(JournalError::Corrupt),
        }
    }
    if counters.protected_card_rows > MAX_CARD_ROWS
        || counters.authority_rows > MAX_AUTHORITY_ROWS
        || counters.authority_encoded_bytes > MAX_AUTHORITY_BYTES
        || counters.rows_encoded_bytes > MAX_PROTECTED_ROW_BYTES
        || counters.row_count
            != counters
                .protected_card_rows
                .checked_add(counters.authority_rows)
                .ok_or(JournalError::Capacity)?
    {
        return Err(JournalError::Capacity);
    }
    Ok(counters)
}

fn recovery_counters(state: &LogicalState) -> Result<RecoveryCounters, JournalError> {
    let mut counters = RecoveryCounters::default();
    for (key, value) in &state.recovery {
        validate_row(RECOVERY_SEGMENT, key, value)?;
        let encoded = 9u64
            .checked_add(key.key.len() as u64)
            .and_then(|n| n.checked_add(value.len() as u64))
            .ok_or(JournalError::Capacity)?;
        counters.row_count = counters
            .row_count
            .checked_add(1)
            .ok_or(JournalError::Capacity)?;
        counters.rows_encoded_bytes = counters
            .rows_encoded_bytes
            .checked_add(encoded)
            .ok_or(JournalError::Capacity)?;
        let slot = match key.tag {
            0x01 => &mut counters.active_source_rows,
            0x02 => &mut counters.quiesced_source_rows,
            0x03 => &mut counters.close_lifecycle_rows,
            0x04 => &mut counters.consumed_close_rows,
            0x05 => &mut counters.runtime_marker_rows,
            _ => return Err(JournalError::Corrupt),
        };
        *slot = slot.checked_add(1).ok_or(JournalError::Capacity)?;
    }
    let lifecycle = counters
        .active_source_rows
        .checked_add(counters.quiesced_source_rows)
        .and_then(|n| n.checked_add(counters.close_lifecycle_rows))
        .and_then(|n| n.checked_add(counters.consumed_close_rows))
        .ok_or(JournalError::Capacity)?;
    if lifecycle > MAX_RECOVERY_LIFECYCLE_ROWS
        || counters.runtime_marker_rows > 1
        || counters.rows_encoded_bytes > MAX_RECOVERY_ROW_BYTES
        || counters.row_count
            != lifecycle
                .checked_add(counters.runtime_marker_rows)
                .ok_or(JournalError::Capacity)?
    {
        return Err(JournalError::Capacity);
    }
    Ok(counters)
}

fn canonical_protected(state: &LogicalState) -> Result<Vec<u8>, JournalError> {
    let counters = protected_counters(state)?;
    let mut out = Vec::with_capacity(41 + counters.rows_encoded_bytes as usize);
    out.push(PROTECTED_SEGMENT);
    out.extend_from_slice(&counters.row_count.to_be_bytes());
    out.extend_from_slice(&counters.rows_encoded_bytes.to_be_bytes());
    out.extend_from_slice(&counters.protected_card_rows.to_be_bytes());
    out.extend_from_slice(&counters.authority_rows.to_be_bytes());
    out.extend_from_slice(&counters.authority_encoded_bytes.to_be_bytes());
    for (key, value) in &state.protected {
        out.extend_from_slice(&encode_row(key, value)?);
    }
    Ok(out)
}

fn canonical_recovery(state: &LogicalState) -> Result<Vec<u8>, JournalError> {
    let counters = recovery_counters(state)?;
    let mut out = Vec::with_capacity(57 + counters.rows_encoded_bytes as usize);
    out.push(RECOVERY_SEGMENT);
    out.extend_from_slice(&counters.row_count.to_be_bytes());
    out.extend_from_slice(&counters.rows_encoded_bytes.to_be_bytes());
    out.extend_from_slice(&counters.active_source_rows.to_be_bytes());
    out.extend_from_slice(&counters.quiesced_source_rows.to_be_bytes());
    out.extend_from_slice(&counters.close_lifecycle_rows.to_be_bytes());
    out.extend_from_slice(&counters.consumed_close_rows.to_be_bytes());
    out.extend_from_slice(&counters.runtime_marker_rows.to_be_bytes());
    for (key, value) in &state.recovery {
        out.extend_from_slice(&encode_row(key, value)?);
    }
    Ok(out)
}

fn state_root(
    instance_id: [u8; 16],
    sequence: u64,
    state: &LogicalState,
) -> Result<[u8; 32], JournalError> {
    let protected = canonical_protected(state)?;
    let recovery = canonical_recovery(state)?;
    let mut h = Sha256::new();
    h.update(DOMAIN_STATE_ROOT);
    h.update([0]);
    h.update(instance_id);
    h.update(sequence.to_be_bytes());
    h.update(2u32.to_be_bytes());
    h.update(protected);
    h.update(recovery);
    Ok(h.finalize().into())
}

fn genesis_head(instance_id: [u8; 16], root: [u8; 32]) -> [u8; 32] {
    domain_hash(DOMAIN_GENESIS_HEAD, &[&instance_id, &root])
}

fn next_head(
    instance_id: [u8; 16],
    next_sequence: u64,
    previous_head: [u8; 32],
    previous_root: [u8; 32],
    next_root: [u8; 32],
    delta_digest: [u8; 32],
) -> [u8; 32] {
    domain_hash(
        DOMAIN_HEAD,
        &[
            &instance_id,
            &next_sequence.to_be_bytes(),
            &previous_head,
            &previous_root,
            &next_root,
            &delta_digest,
        ],
    )
}

#[derive(Clone, Copy)]
struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn remaining(self) -> usize {
        self.bytes.len().saturating_sub(self.position)
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], JournalError> {
        let end = self
            .position
            .checked_add(len)
            .filter(|end| *end <= self.bytes.len())
            .ok_or(JournalError::Corrupt)?;
        let value = &self.bytes[self.position..end];
        self.position = end;
        Ok(value)
    }

    fn take_array<const N: usize>(&mut self) -> Result<[u8; N], JournalError> {
        self.take(N)?.try_into().map_err(|_| JournalError::Corrupt)
    }

    fn expect(&mut self, expected: &[u8]) -> Result<(), JournalError> {
        let observed = self.take(expected.len())?;
        if observed != expected {
            return Err(JournalError::Corrupt);
        }
        Ok(())
    }

    fn u8(&mut self) -> Result<u8, JournalError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, JournalError> {
        Ok(u16::from_be_bytes(self.take_array()?))
    }

    fn u32(&mut self) -> Result<u32, JournalError> {
        Ok(u32::from_be_bytes(self.take_array()?))
    }

    fn u64(&mut self) -> Result<u64, JournalError> {
        Ok(u64::from_be_bytes(self.take_array()?))
    }

    fn i64(&mut self) -> Result<i64, JournalError> {
        Ok(i64::from_be_bytes(self.take_array()?))
    }

    fn b16(&mut self) -> Result<[u8; 16], JournalError> {
        self.take_array()
    }

    fn b32(&mut self) -> Result<[u8; 32], JournalError> {
        self.take_array()
    }

    fn finish(self) -> Result<(), JournalError> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(JournalError::Corrupt)
        }
    }
}

fn nonzero<const N: usize>(bytes: &[u8; N]) -> Result<(), JournalError> {
    if bytes.iter().all(|byte| *byte == 0) {
        Err(JournalError::Corrupt)
    } else {
        Ok(())
    }
}

fn parse_option_b16(c: &mut Cursor<'_>) -> Result<Option<[u8; 16]>, JournalError> {
    match c.u8()? {
        0 => Ok(None),
        1 => Ok(Some(c.b16()?)),
        _ => Err(JournalError::Corrupt),
    }
}

fn parse_option_b32(c: &mut Cursor<'_>) -> Result<Option<[u8; 32]>, JournalError> {
    match c.u8()? {
        0 => Ok(None),
        1 => Ok(Some(c.b32()?)),
        _ => Err(JournalError::Corrupt),
    }
}

fn parse_option_i64(c: &mut Cursor<'_>) -> Result<Option<i64>, JournalError> {
    match c.u8()? {
        0 => Ok(None),
        1 => Ok(Some(c.i64()?)),
        _ => Err(JournalError::Corrupt),
    }
}

fn parse_option_u64(c: &mut Cursor<'_>) -> Result<Option<u64>, JournalError> {
    match c.u8()? {
        0 => Ok(None),
        1 => Ok(Some(c.u64()?)),
        _ => Err(JournalError::Corrupt),
    }
}

fn parse_phase(c: &mut Cursor<'_>) -> Result<u8, JournalError> {
    let phase = c.u8()?;
    if phase <= 0x03 {
        Ok(phase)
    } else {
        Err(JournalError::Corrupt)
    }
}

fn parse_attempt_kind(c: &mut Cursor<'_>) -> Result<(), JournalError> {
    match c.u8()? {
        0x00 => Ok(()),
        0x01 | 0x02 => {
            if c.i64()? <= 0 {
                return Err(JournalError::Corrupt);
            }
            Ok(())
        }
        _ => Err(JournalError::Corrupt),
    }
}

fn parse_authority_tail(c: &mut Cursor<'_>, state: u8) -> Result<(), JournalError> {
    let issued = c.u64()?;
    let expires = c.u64()?;
    let retain = c.u64()?;
    if issued > expires || expires > retain {
        return Err(JournalError::Corrupt);
    }
    let mac = c.b32()?;
    nonzero(&mac)?;
    let consumed = parse_option_u64(c)?;
    match (state, consumed) {
        (0x00, None) => Ok(()),
        (0x01 | 0x02, Some(at)) if at >= issued && at <= retain => Ok(()),
        _ => Err(JournalError::Corrupt),
    }
}

fn parse_authority_prefix(c: &mut Cursor<'_>) -> Result<u8, JournalError> {
    let state = c.u8()?;
    if state > 0x02 {
        return Err(JournalError::Corrupt);
    }
    let authority_id = c.b16()?;
    nonzero(&authority_id)?;
    Ok(state)
}

fn parse_ref_set(c: &mut Cursor<'_>) -> Result<Vec<[u8; 16]>, JournalError> {
    let count = c.u32()? as usize;
    if count > MAX_ROUTE_REFS || count > c.remaining() / 16 {
        return Err(JournalError::Capacity);
    }
    let mut values = Vec::with_capacity(count);
    let mut previous: Option<[u8; 16]> = None;
    for _ in 0..count {
        let value = c.b16()?;
        nonzero(&value)?;
        if previous.as_ref().is_some_and(|prior| prior >= &value) {
            return Err(JournalError::Corrupt);
        }
        previous = Some(value);
        values.push(value);
    }
    Ok(values)
}

#[derive(Clone)]
struct ActiveSourceView {
    runtime: [u8; 16],
    expected_agent: [u8; 32],
    generation: u64,
    progress_key: Option<[u8; 32]>,
}

#[derive(Clone)]
struct QuiescedSourceView {
    runtime: [u8; 16],
    expected_agent: [u8; 32],
    generation: u64,
    progress_key: [u8; 32],
    runtime_retired: bool,
}

#[derive(Clone)]
struct CloseLifecycleView {
    source: [u8; 32],
    expected_agent: [u8; 32],
    runtime: [u8; 16],
    open: bool,
    runtime_retired: bool,
}

#[derive(Clone)]
struct RuntimeMarkerView {
    current: [u8; 16],
    retired: Option<[u8; 16]>,
    evidence: [u8; 32],
    booted_at_ms: u64,
}

enum ParsedRecoveryRow {
    Active(ActiveSourceView),
    Quiesced(QuiescedSourceView),
    Close(CloseLifecycleView),
    Consumed,
    Marker(RuntimeMarkerView),
}

fn validate_row(segment: u8, key: &RowKey, value: &[u8]) -> Result<(), JournalError> {
    match segment {
        PROTECTED_SEGMENT => validate_protected_row(key, value),
        RECOVERY_SEGMENT => parse_recovery_row(key, value).map(|_| ()),
        _ => Err(JournalError::Corrupt),
    }
}

fn validate_protected_row(key: &RowKey, value: &[u8]) -> Result<(), JournalError> {
    let expected_key_len = match key.tag {
        0x01..=0x03 => 32,
        0x10..=0x15 => 48,
        _ => return Err(JournalError::Corrupt),
    };
    if key.key.len() != expected_key_len {
        return Err(JournalError::Corrupt);
    }
    let mut c = Cursor::new(value);
    match key.tag {
        0x01 => {
            if c.u64()? == 0 {
                return Err(JournalError::Corrupt);
            }
            c.b32()?;
            c.u64()?;
        }
        0x02 => {
            if c.u64()? == 0 {
                return Err(JournalError::Corrupt);
            }
            let attempt = c.b16()?;
            nonzero(&attempt)?;
            c.b32()?;
            parse_phase(&mut c)?;
            parse_attempt_kind(&mut c)?;
            c.u64()?;
        }
        0x03 => {
            if c.u64()? == 0 {
                return Err(JournalError::Corrupt);
            }
            c.b32()?;
            if c.i64()? <= 0 {
                return Err(JournalError::Corrupt);
            }
            c.u64()?;
        }
        0x10 => {
            let state = parse_authority_prefix(&mut c)?;
            c.b32()?;
            c.b32()?;
            if c.u64()? == 0 || c.u32()? != 0 || c.u32()? != 0 || c.u32()? != 0 {
                return Err(JournalError::Corrupt);
            }
            parse_authority_tail(&mut c, state)?;
        }
        0x11 => {
            let state = parse_authority_prefix(&mut c)?;
            c.b32()?;
            if c.u64()? == 0 || c.u8()? > 0x04 {
                return Err(JournalError::Corrupt);
            }
            c.b32()?;
            parse_authority_tail(&mut c, state)?;
        }
        0x12 => {
            let state = parse_authority_prefix(&mut c)?;
            c.b32()?;
            c.b32()?;
            c.b32()?;
            c.b32()?;
            parse_authority_tail(&mut c, state)?;
        }
        0x13 => {
            let state = parse_authority_prefix(&mut c)?;
            if c.u64()? == 0 {
                return Err(JournalError::Corrupt);
            }
            let attempt = c.b16()?;
            nonzero(&attempt)?;
            parse_attempt_kind(&mut c)?;
            c.b32()?;
            parse_phase(&mut c)?;
            parse_authority_tail(&mut c, state)?;
        }
        0x14 | 0x15 => {
            let state = parse_authority_prefix(&mut c)?;
            c.b32()?;
            if c.u64()? == 0 {
                return Err(JournalError::Corrupt);
            }
            let attempt = c.b16()?;
            nonzero(&attempt)?;
            parse_attempt_kind(&mut c)?;
            c.b32()?;
            let outcome = c.u8()?;
            if outcome > 1 {
                return Err(JournalError::Corrupt);
            }
            let telegram_id = parse_option_i64(&mut c)?;
            match (outcome, telegram_id) {
                (0, Some(id)) if id > 0 => {}
                (1, None) => {}
                _ => return Err(JournalError::Corrupt),
            }
            let evidence_source = c.u8()?;
            if evidence_source > 1 || (evidence_source == 0 && outcome == 1) {
                return Err(JournalError::Corrupt);
            }
            let evidence_id = c.b16()?;
            nonzero(&evidence_id)?;
            c.b32()?;
            parse_authority_tail(&mut c, state)?;
        }
        _ => return Err(JournalError::Corrupt),
    }
    c.finish()
}

fn parse_recovery_row(key: &RowKey, value: &[u8]) -> Result<ParsedRecoveryRow, JournalError> {
    let expected_key_len = match key.tag {
        0x01..=0x04 => 32,
        0x05 => 0,
        _ => return Err(JournalError::Corrupt),
    };
    if key.key.len() != expected_key_len {
        return Err(JournalError::Corrupt);
    }
    let mut c = Cursor::new(value);
    let parsed = match key.tag {
        0x01 => {
            let runtime = c.b16()?;
            nonzero(&runtime)?;
            let expected_agent = c.b32()?;
            let generation = c.u64()?;
            if generation == 0 {
                return Err(JournalError::Corrupt);
            }
            let progress_key = parse_option_b32(&mut c)?;
            c.u64()?;
            ParsedRecoveryRow::Active(ActiveSourceView {
                runtime,
                expected_agent,
                generation,
                progress_key,
            })
        }
        0x02 => {
            let runtime = c.b16()?;
            nonzero(&runtime)?;
            let expected_agent = c.b32()?;
            let generation = c.u64()?;
            if generation == 0 {
                return Err(JournalError::Corrupt);
            }
            let progress_key = c.b32()?;
            let store_incarnation = c.b16()?;
            let runtime_retired = match c.u8()? {
                0x00 => {
                    c.u64()?;
                    nonzero(&store_incarnation)?;
                    false
                }
                0x01 => {
                    let embedded = c.b16()?;
                    nonzero(&store_incarnation)?;
                    if embedded != store_incarnation {
                        return Err(JournalError::Corrupt);
                    }
                    false
                }
                0x02 => {
                    c.b32()?;
                    if store_incarnation != [0; 16] {
                        return Err(JournalError::Corrupt);
                    }
                    true
                }
                _ => return Err(JournalError::Corrupt),
            };
            c.b32()?;
            c.u64()?;
            ParsedRecoveryRow::Quiesced(QuiescedSourceView {
                runtime,
                expected_agent,
                generation,
                progress_key,
                runtime_retired,
            })
        }
        0x03 => {
            let source = c.b32()?;
            let expected_agent = c.b32()?;
            let runtime = c.b16()?;
            nonzero(&runtime)?;
            if c.u64()? == 0 || c.u64()? == 0 {
                return Err(JournalError::Corrupt);
            }
            c.u64()?;
            let route_tag = c.u8()?;
            let (open, runtime_retired) = match route_tag {
                0x00 => {
                    let action = parse_ref_set(&mut c)?;
                    let retry = parse_ref_set(&mut c)?;
                    let replay = parse_ref_set(&mut c)?;
                    let total = action
                        .len()
                        .checked_add(retry.len())
                        .and_then(|n| n.checked_add(replay.len()))
                        .ok_or(JournalError::Capacity)?;
                    if total > MAX_ROUTE_REFS {
                        return Err(JournalError::Capacity);
                    }
                    let mut all = BTreeSet::new();
                    for value in action.iter().chain(&retry).chain(&replay) {
                        if !all.insert(*value) {
                            return Err(JournalError::Corrupt);
                        }
                    }
                    (true, false)
                }
                0x01 => {
                    let reason = c.u8()?;
                    if reason > 1 {
                        return Err(JournalError::Corrupt);
                    }
                    let retired = match c.u8()? {
                        0 => None,
                        1 => {
                            let action = c.u32()? as usize;
                            let retry = c.u32()? as usize;
                            let replay = c.u32()? as usize;
                            let total = action
                                .checked_add(retry)
                                .and_then(|n| n.checked_add(replay))
                                .ok_or(JournalError::Capacity)?;
                            if total > MAX_ROUTE_REFS {
                                return Err(JournalError::Capacity);
                            }
                            c.b32()?;
                            Some(())
                        }
                        _ => return Err(JournalError::Corrupt),
                    };
                    if (reason == 0 && retired.is_some()) || (reason == 1 && retired.is_none()) {
                        return Err(JournalError::Corrupt);
                    }
                    c.b32()?;
                    c.u64()?;
                    (false, reason == 1)
                }
                _ => return Err(JournalError::Corrupt),
            };
            ParsedRecoveryRow::Close(CloseLifecycleView {
                source,
                expected_agent,
                runtime,
                open,
                runtime_retired,
            })
        }
        0x04 => {
            c.b32()?;
            if c.u64()? == 0 || c.u8()? > 0x04 {
                return Err(JournalError::Corrupt);
            }
            c.b32()?;
            c.b32()?;
            c.b32()?;
            let committed = c.u64()?;
            let retain = c.u64()?;
            if committed > retain {
                return Err(JournalError::Corrupt);
            }
            ParsedRecoveryRow::Consumed
        }
        0x05 => {
            let current = c.b16()?;
            nonzero(&current)?;
            let retired = parse_option_b16(&mut c)?;
            if let Some(old) = retired {
                nonzero(&old)?;
                if old == current {
                    return Err(JournalError::Corrupt);
                }
            }
            let evidence = c.b32()?;
            nonzero(&evidence)?;
            let booted_at_ms = c.u64()?;
            ParsedRecoveryRow::Marker(RuntimeMarkerView {
                current,
                retired,
                evidence,
                booted_at_ms,
            })
        }
        _ => return Err(JournalError::Corrupt),
    };
    c.finish()?;
    Ok(parsed)
}

fn decode_canonical_segment(bytes: &[u8], expected_tag: u8) -> Result<LogicalState, JournalError> {
    let mut c = Cursor::new(bytes);
    if c.u8()? != expected_tag {
        return Err(JournalError::Corrupt);
    }
    let mut stored_protected = None;
    let mut stored_recovery = None;
    if expected_tag == PROTECTED_SEGMENT {
        stored_protected = Some(ProtectedCounters {
            row_count: c.u64()?,
            rows_encoded_bytes: c.u64()?,
            protected_card_rows: c.u64()?,
            authority_rows: c.u64()?,
            authority_encoded_bytes: c.u64()?,
        });
    } else if expected_tag == RECOVERY_SEGMENT {
        stored_recovery = Some(RecoveryCounters {
            row_count: c.u64()?,
            rows_encoded_bytes: c.u64()?,
            active_source_rows: c.u64()?,
            quiesced_source_rows: c.u64()?,
            close_lifecycle_rows: c.u64()?,
            consumed_close_rows: c.u64()?,
            runtime_marker_rows: c.u64()?,
        });
    } else {
        return Err(JournalError::Corrupt);
    }

    let mut rows = BTreeMap::new();
    let mut previous: Option<RowKey> = None;
    while c.remaining() != 0 {
        let tag = c.u8()?;
        let key_len = c.u32()? as usize;
        if key_len > c.remaining() {
            return Err(JournalError::Corrupt);
        }
        let key = c.take(key_len)?.to_vec();
        let value_len = c.u32()? as usize;
        if value_len > c.remaining() {
            return Err(JournalError::Corrupt);
        }
        let value = c.take(value_len)?.to_vec();
        let row_key = RowKey { tag, key };
        if previous.as_ref().is_some_and(|prior| prior >= &row_key) {
            return Err(JournalError::Corrupt);
        }
        validate_row(expected_tag, &row_key, &value)?;
        previous = Some(row_key.clone());
        if rows.insert(row_key, value).is_some() {
            return Err(JournalError::Corrupt);
        }
    }
    let mut state = LogicalState::default();
    if expected_tag == PROTECTED_SEGMENT {
        state.protected = rows;
        if Some(protected_counters(&state)?) != stored_protected {
            return Err(JournalError::Corrupt);
        }
    } else {
        state.recovery = rows;
        if Some(recovery_counters(&state)?) != stored_recovery {
            return Err(JournalError::Corrupt);
        }
    }
    Ok(state)
}

fn merge_segment_states(
    protected: LogicalState,
    recovery: LogicalState,
) -> Result<LogicalState, JournalError> {
    if !protected.recovery.is_empty() || !recovery.protected.is_empty() {
        return Err(JournalError::Corrupt);
    }
    let state = LogicalState {
        protected: protected.protected,
        recovery: recovery.recovery,
    };
    protected_counters(&state)?;
    recovery_counters(&state)?;
    Ok(state)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OperationKind {
    Insert,
    Replace,
    Delete,
}

impl OperationKind {
    fn tag(self) -> u8 {
        match self {
            Self::Insert => 0x01,
            Self::Replace => 0x02,
            Self::Delete => 0x03,
        }
    }

    fn parse(tag: u8) -> Result<Self, JournalError> {
        match tag {
            0x01 => Ok(Self::Insert),
            0x02 => Ok(Self::Replace),
            0x03 => Ok(Self::Delete),
            _ => Err(JournalError::Corrupt),
        }
    }
}

#[derive(Clone)]
struct Operation {
    segment: u8,
    key: RowKey,
    kind: OperationKind,
    before: Vec<u8>,
    after: Vec<u8>,
}

impl Operation {
    fn insert(segment: u8, tag: u8, key: Vec<u8>, after: Vec<u8>) -> Self {
        Self {
            segment,
            key: RowKey { tag, key },
            kind: OperationKind::Insert,
            before: Vec::new(),
            after,
        }
    }

    fn replace(segment: u8, tag: u8, key: Vec<u8>, before: Vec<u8>, after: Vec<u8>) -> Self {
        Self {
            segment,
            key: RowKey { tag, key },
            kind: OperationKind::Replace,
            before,
            after,
        }
    }

    fn delete(segment: u8, tag: u8, key: Vec<u8>, before: Vec<u8>) -> Self {
        Self {
            segment,
            key: RowKey { tag, key },
            kind: OperationKind::Delete,
            before,
            after: Vec::new(),
        }
    }
}

fn canonical_delta(operations: &[Operation]) -> Result<Vec<u8>, JournalError> {
    let count = u32::try_from(operations.len()).map_err(|_| JournalError::Capacity)?;
    let mut out = Vec::new();
    out.extend_from_slice(&count.to_be_bytes());
    let mut previous: Option<(u8, u8, &[u8])> = None;
    for operation in operations {
        if !matches!(operation.segment, PROTECTED_SEGMENT | RECOVERY_SEGMENT) {
            return Err(JournalError::Corrupt);
        }
        let ordering = (
            operation.segment,
            operation.key.tag,
            operation.key.key.as_slice(),
        );
        if previous.is_some_and(|prior| prior >= ordering) {
            return Err(JournalError::Corrupt);
        }
        previous = Some(ordering);
        match operation.kind {
            OperationKind::Insert if !operation.before.is_empty() || operation.after.is_empty() => {
                return Err(JournalError::Corrupt)
            }
            OperationKind::Replace if operation.before.is_empty() || operation.after.is_empty() => {
                return Err(JournalError::Corrupt)
            }
            OperationKind::Delete if operation.before.is_empty() || !operation.after.is_empty() => {
                return Err(JournalError::Corrupt)
            }
            _ => {}
        }
        if !operation.before.is_empty() {
            validate_row(operation.segment, &operation.key, &operation.before)?;
        }
        if !operation.after.is_empty() {
            validate_row(operation.segment, &operation.key, &operation.after)?;
        }
        let key_len = u32::try_from(operation.key.key.len()).map_err(|_| JournalError::Capacity)?;
        let before_len =
            u32::try_from(operation.before.len()).map_err(|_| JournalError::Capacity)?;
        let after_len = u32::try_from(operation.after.len()).map_err(|_| JournalError::Capacity)?;
        out.push(operation.segment);
        out.push(operation.key.tag);
        out.extend_from_slice(&key_len.to_be_bytes());
        out.extend_from_slice(&operation.key.key);
        out.push(operation.kind.tag());
        out.extend_from_slice(&before_len.to_be_bytes());
        out.extend_from_slice(&operation.before);
        out.extend_from_slice(&after_len.to_be_bytes());
        out.extend_from_slice(&operation.after);
        if out.len() > MAX_DELTA_BYTES {
            return Err(JournalError::Capacity);
        }
    }
    if out.len() > MAX_DELTA_BYTES {
        return Err(JournalError::Capacity);
    }
    Ok(out)
}

fn decode_delta(bytes: &[u8]) -> Result<Vec<Operation>, JournalError> {
    if bytes.len() > MAX_DELTA_BYTES {
        return Err(JournalError::Capacity);
    }
    let mut c = Cursor::new(bytes);
    let count = c.u32()? as usize;
    if count > bytes.len().saturating_sub(4) / 16 {
        return Err(JournalError::Corrupt);
    }
    let mut operations = Vec::with_capacity(count);
    for _ in 0..count {
        let segment = c.u8()?;
        let tag = c.u8()?;
        let key_len = c.u32()? as usize;
        if key_len > c.remaining() {
            return Err(JournalError::Corrupt);
        }
        let key = c.take(key_len)?.to_vec();
        let kind = OperationKind::parse(c.u8()?)?;
        let before_len = c.u32()? as usize;
        if before_len > c.remaining() {
            return Err(JournalError::Corrupt);
        }
        let before = c.take(before_len)?.to_vec();
        let after_len = c.u32()? as usize;
        if after_len > c.remaining() {
            return Err(JournalError::Corrupt);
        }
        let after = c.take(after_len)?.to_vec();
        operations.push(Operation {
            segment,
            key: RowKey { tag, key },
            kind,
            before,
            after,
        });
    }
    c.finish()?;
    if canonical_delta(&operations)? != bytes {
        return Err(JournalError::Corrupt);
    }
    Ok(operations)
}

fn apply_operations(
    state: &LogicalState,
    operations: &[Operation],
    enforce_cross_rows: bool,
) -> Result<LogicalState, JournalError> {
    // Re-encoding here pins strict ordering, operation class, complete row
    // canonicality, and the exact 8 MiB bound before any state is changed.
    canonical_delta(operations)?;
    let mut next = state.clone();
    for operation in operations {
        let rows = match operation.segment {
            PROTECTED_SEGMENT => &mut next.protected,
            RECOVERY_SEGMENT => &mut next.recovery,
            _ => return Err(JournalError::Corrupt),
        };
        let observed = rows.get(&operation.key);
        match operation.kind {
            OperationKind::Insert => {
                if observed.is_some() || !operation.before.is_empty() {
                    return Err(JournalError::AnchorConflict);
                }
                rows.insert(operation.key.clone(), operation.after.clone());
            }
            OperationKind::Replace => {
                let observed = observed.ok_or(JournalError::AnchorConflict)?;
                if !bool::from(observed.as_slice().ct_eq(&operation.before)) {
                    return Err(JournalError::AnchorConflict);
                }
                rows.insert(operation.key.clone(), operation.after.clone());
            }
            OperationKind::Delete => {
                let observed = observed.ok_or(JournalError::AnchorConflict)?;
                if !bool::from(observed.as_slice().ct_eq(&operation.before)) {
                    return Err(JournalError::AnchorConflict);
                }
                rows.remove(&operation.key);
            }
        }
    }
    protected_counters(&next)?;
    recovery_counters(&next)?;
    if enforce_cross_rows {
        validate_cross_rows(&next)?;
    }
    Ok(next)
}

fn validate_cross_rows(state: &LogicalState) -> Result<(), JournalError> {
    let mut active: BTreeMap<[u8; 32], ActiveSourceView> = BTreeMap::new();
    let mut quiesced: BTreeMap<[u8; 32], QuiescedSourceView> = BTreeMap::new();
    let mut closes: BTreeMap<[u8; 32], CloseLifecycleView> = BTreeMap::new();
    for (key, value) in &state.recovery {
        let digest: [u8; 32] = if key.key.len() == 32 {
            key.key
                .as_slice()
                .try_into()
                .map_err(|_| JournalError::Corrupt)?
        } else {
            [0; 32]
        };
        match parse_recovery_row(key, value)? {
            ParsedRecoveryRow::Active(view) => {
                if active.insert(digest, view).is_some() || quiesced.contains_key(&digest) {
                    return Err(JournalError::Corrupt);
                }
            }
            ParsedRecoveryRow::Quiesced(view) => {
                if quiesced.insert(digest, view).is_some() || active.contains_key(&digest) {
                    return Err(JournalError::Corrupt);
                }
            }
            ParsedRecoveryRow::Close(view) => {
                if closes.insert(digest, view).is_some() {
                    return Err(JournalError::Corrupt);
                }
            }
            ParsedRecoveryRow::Consumed | ParsedRecoveryRow::Marker(_) => {}
        }
    }

    for (source_digest, source) in &active {
        if let Some(key_digest) = source.progress_key {
            let close = closes.get(&key_digest).ok_or(JournalError::Corrupt)?;
            if close.source != *source_digest
                || close.expected_agent != source.expected_agent
                || close.runtime != source.runtime
                || !close.open
            {
                return Err(JournalError::Corrupt);
            }
        }
    }
    for (source_digest, source) in &quiesced {
        let close = closes
            .get(&source.progress_key)
            .ok_or(JournalError::Corrupt)?;
        if close.source != *source_digest
            || close.expected_agent != source.expected_agent
            || close.runtime != source.runtime
            || (source.runtime_retired && !close.runtime_retired)
        {
            return Err(JournalError::Corrupt);
        }
    }
    for (key_digest, close) in &closes {
        let source = active.get(&close.source);
        let tombstone = quiesced.get(&close.source);
        let linked = source.is_some_and(|source| {
            source.progress_key == Some(*key_digest)
                && source.expected_agent == close.expected_agent
                && source.runtime == close.runtime
                && close.open
        }) || tombstone.is_some_and(|source| {
            source.progress_key == *key_digest
                && source.expected_agent == close.expected_agent
                && source.runtime == close.runtime
                && (!close.runtime_retired || source.runtime_retired)
        });
        if !linked {
            return Err(JournalError::Corrupt);
        }
    }

    // A durable card row is legal only behind the exact positive close-lifecycle
    // fact. `NoCard` and `Live` never appear here.
    for key in state
        .protected
        .keys()
        .filter(|key| (0x01..=0x03).contains(&key.tag))
    {
        let digest: [u8; 32] = key
            .key
            .as_slice()
            .try_into()
            .map_err(|_| JournalError::Corrupt)?;
        if !closes.contains_key(&digest) {
            return Err(JournalError::Corrupt);
        }
    }
    Ok(())
}

#[derive(Clone)]
struct TransactionPayload {
    sequence: u64,
    previous_head: [u8; 32],
    previous_root: [u8; 32],
    next_sequence: u64,
    next_head: [u8; 32],
    next_root: [u8; 32],
    delta_digest: [u8; 32],
    canonical_delta: Vec<u8>,
}

impl TransactionPayload {
    fn encode(&self) -> Result<Vec<u8>, JournalError> {
        if self.canonical_delta.len() > MAX_DELTA_BYTES {
            return Err(JournalError::Capacity);
        }
        let mut out =
            Vec::with_capacity(TRANSACTION_PAYLOAD_FIXED_LEN + self.canonical_delta.len());
        out.extend_from_slice(&self.sequence.to_be_bytes());
        out.extend_from_slice(&self.previous_head);
        out.extend_from_slice(&self.previous_root);
        out.extend_from_slice(&self.next_sequence.to_be_bytes());
        out.extend_from_slice(&self.next_head);
        out.extend_from_slice(&self.next_root);
        out.extend_from_slice(&self.delta_digest);
        out.extend_from_slice(&(self.canonical_delta.len() as u64).to_be_bytes());
        out.extend_from_slice(&self.canonical_delta);
        Ok(out)
    }

    fn decode(bytes: &[u8]) -> Result<Self, JournalError> {
        if bytes.len() < TRANSACTION_PAYLOAD_FIXED_LEN
            || bytes.len() > TRANSACTION_PAYLOAD_FIXED_LEN + MAX_DELTA_BYTES
        {
            return Err(JournalError::Corrupt);
        }
        let mut c = Cursor::new(bytes);
        let sequence = c.u64()?;
        let previous_head = c.b32()?;
        let previous_root = c.b32()?;
        let next_sequence = c.u64()?;
        let next_head = c.b32()?;
        let next_root = c.b32()?;
        let delta_digest = c.b32()?;
        let delta_len = c.u64()?;
        if delta_len > MAX_DELTA_BYTES as u64 || delta_len as usize != c.remaining() {
            return Err(JournalError::Corrupt);
        }
        let canonical_delta = c.take(delta_len as usize)?.to_vec();
        c.finish()?;
        let actual_digest: [u8; 32] = Sha256::digest(&canonical_delta).into();
        if !bool::from(actual_digest.ct_eq(&delta_digest)) {
            return Err(JournalError::Corrupt);
        }
        decode_delta(&canonical_delta)?;
        if next_sequence
            != sequence
                .checked_add(1)
                .ok_or(JournalError::SequenceExhausted)?
        {
            return Err(JournalError::Corrupt);
        }
        Ok(Self {
            sequence,
            previous_head,
            previous_root,
            next_sequence,
            next_head,
            next_root,
            delta_digest,
            canonical_delta,
        })
    }

    fn operations(&self) -> Result<Vec<Operation>, JournalError> {
        decode_delta(&self.canonical_delta)
    }

    fn affected_segments(&self, zero_op_checkpoint: bool) -> Result<Vec<u8>, JournalError> {
        let operations = self.operations()?;
        let mut segments = BTreeSet::new();
        for operation in operations {
            segments.insert(operation.segment);
        }
        if segments.is_empty() {
            if !zero_op_checkpoint {
                return Err(JournalError::Corrupt);
            }
            segments.insert(PROTECTED_SEGMENT);
            segments.insert(RECOVERY_SEGMENT);
        }
        Ok(segments.into_iter().collect())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TxFailpoint {
    AfterPreparedFsync,
    AfterPendingAnchor,
    AfterCommittedFsync,
    AfterFinalAnchor,
}

struct JournalCore {
    journal_dir: PathBuf,
    protected_path: PathBuf,
    recovery_path: PathBuf,
    _journal_lock: File,
    anchor: ExternalAnchor,
    anchor_snapshot: AnchorSnapshot,
    key: Arc<Zeroizing<[u8; 32]>>,
    key_epoch: NonZeroU32,
    instance_id: [u8; 16],
    protected_header: [u8; SEGMENT_HEADER_LEN],
    recovery_header: [u8; SEGMENT_HEADER_LEN],
    protected_header_digest: [u8; 32],
    recovery_header_digest: [u8; 32],
    sequence: u64,
    head: [u8; 32],
    root: [u8; 32],
    state: LogicalState,
    protected_frames: u64,
    recovery_frames: u64,
    healthy: bool,
    failpoint: Option<TxFailpoint>,
}

impl JournalCore {
    fn open<R: RngCore + CryptoRng>(
        config: RecoveryJournalConfig,
        rng: &mut R,
    ) -> Result<Self, JournalError> {
        create_owner_directory(&config.journal_dir)?;
        let journal_dir = fs::canonicalize(&config.journal_dir)?;
        let anchor_parent = config
            .external_anchor_path
            .parent()
            .ok_or(JournalError::Configuration)?;
        create_owner_directory(anchor_parent)?;
        let anchor_parent = fs::canonicalize(anchor_parent)?;
        let anchor_name = config
            .external_anchor_path
            .file_name()
            .ok_or(JournalError::Configuration)?;
        let external_anchor_path = anchor_parent.join(anchor_name);
        if external_anchor_path.starts_with(&journal_dir) {
            return Err(JournalError::Configuration);
        }

        let key = Arc::new(config.integrity_key);
        // Fixed lock order: external anchor first, journal directory second.
        let anchor =
            ExternalAnchor::acquire(external_anchor_path, config.key_epoch, Arc::clone(&key))?;
        let journal_lock_path = journal_dir.join(".progress-journal.lock");
        let journal_lock = open_owner_file(&journal_lock_path, true, false)?;
        journal_lock
            .try_lock()
            .map_err(|_| JournalError::AnchorUnavailable)?;

        let protected_path = journal_dir.join(PROTECTED_FILE);
        let recovery_path = journal_dir.join(RECOVERY_FILE);
        let anchor_snapshot = match anchor.load()? {
            None => {
                if protected_path.exists() || recovery_path.exists() {
                    return Err(JournalError::AnchorMismatch);
                }
                bootstrap_fresh(&anchor, &journal_dir, &protected_path, &recovery_path, rng)?
            }
            Some(snapshot) => match &snapshot.decoded.state {
                AnchorState::BootstrapPending { .. } => resume_bootstrap(
                    &anchor,
                    &journal_dir,
                    &protected_path,
                    &recovery_path,
                    snapshot,
                    rng,
                )?,
                AnchorState::Committed { .. } => snapshot,
            },
        };
        if anchor_snapshot.decoded.key_epoch != config.key_epoch {
            return Err(JournalError::AnchorMismatch);
        }
        let (instance_id, protected_header_digest, recovery_header_digest, _, _, _, _) =
            committed_fields(&anchor_snapshot.decoded.state)?;
        let protected_header = read_exact_header(&protected_path)?;
        let recovery_header = read_exact_header(&recovery_path)?;
        if validate_segment_header(&protected_header, instance_id, PROTECTED_SEGMENT)?
            != protected_header_digest
            || validate_segment_header(&recovery_header, instance_id, RECOVERY_SEGMENT)?
                != recovery_header_digest
            || protected_header[28..44] != recovery_header[28..44]
        {
            return Err(JournalError::AnchorMismatch);
        }

        let protected_scan = scan_segment(
            &protected_path,
            PROTECTED_SEGMENT,
            instance_id,
            config.key_epoch.get(),
            &key,
        )?;
        let recovery_scan = scan_segment(
            &recovery_path,
            RECOVERY_SEGMENT,
            instance_id,
            config.key_epoch.get(),
            &key,
        )?;
        if protected_scan.header_digest != protected_header_digest
            || recovery_scan.header_digest != recovery_header_digest
        {
            return Err(JournalError::AnchorMismatch);
        }

        let recovered = recover_physical_logs(
            &anchor,
            anchor_snapshot,
            &protected_path,
            &recovery_path,
            &protected_scan,
            &recovery_scan,
            instance_id,
            config.key_epoch,
            &key,
            rng,
        )?;
        let mut core = Self {
            journal_dir,
            protected_path,
            recovery_path,
            _journal_lock: journal_lock,
            anchor,
            anchor_snapshot: recovered.anchor_snapshot,
            key,
            key_epoch: config.key_epoch,
            instance_id,
            protected_header,
            recovery_header,
            protected_header_digest,
            recovery_header_digest,
            sequence: recovered.sequence,
            head: recovered.head,
            root: recovered.root,
            state: recovered.state,
            protected_frames: recovered.protected_frames,
            recovery_frames: recovered.recovery_frames,
            healthy: true,
            failpoint: None,
        };
        core.complete_runtime_marker(rng)?;
        Ok(core)
    }

    fn lock(role: &Arc<Mutex<Self>>) -> Result<MutexGuard<'_, Self>, JournalError> {
        role.lock().map_err(|_| JournalError::Unhealthy)
    }

    fn transact<R: RngCore + CryptoRng>(
        &mut self,
        operations: &[Operation],
        rng: &mut R,
    ) -> Result<(), JournalError> {
        if operations.is_empty() {
            return Err(JournalError::Corrupt);
        }
        let delta = canonical_delta(operations)?;
        // Admission and every complete postimage are checked before checkpoint
        // or the first durable frame. A checkpoint leaves rows byte-identical,
        // so exact before-values remain valid afterwards.
        apply_operations(&self.state, operations, true)?;
        let affected = affected_segments(operations, false)?;
        if self.normal_transaction_crosses_soft(delta.len(), &affected)? {
            self.checkpoint(rng)?;
        }
        self.transact_inner(operations, false, rng)
    }

    fn normal_transaction_crosses_soft(
        &self,
        delta_len: usize,
        affected: &[u8],
    ) -> Result<bool, JournalError> {
        let frame_len = transaction_frame_len(delta_len)?;
        for segment in affected {
            let (path, frame_count) = self.segment_path_and_frames(*segment)?;
            let projected_bytes = fs::metadata(path)?
                .len()
                .checked_add(frame_len.checked_mul(2).ok_or(JournalError::Capacity)?)
                .ok_or(JournalError::Capacity)?;
            let projected_frames = frame_count.checked_add(2).ok_or(JournalError::Capacity)?;
            if projected_bytes > SOFT_LOG_BYTES || projected_frames > SOFT_LOG_FRAMES {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn segment_path_and_frames(&self, segment: u8) -> Result<(&Path, u64), JournalError> {
        match segment {
            PROTECTED_SEGMENT => Ok((&self.protected_path, self.protected_frames)),
            RECOVERY_SEGMENT => Ok((&self.recovery_path, self.recovery_frames)),
            _ => Err(JournalError::Corrupt),
        }
    }

    fn preflight_frame_pair(&self, frame_len: u64, affected: &[u8]) -> Result<(), JournalError> {
        for segment in affected {
            let (path, frame_count) = self.segment_path_and_frames(*segment)?;
            let projected_bytes = fs::metadata(path)?
                .len()
                .checked_add(frame_len.checked_mul(2).ok_or(JournalError::Capacity)?)
                .ok_or(JournalError::Capacity)?;
            let projected_frames = frame_count.checked_add(2).ok_or(JournalError::Capacity)?;
            if projected_bytes > HARD_LOG_BYTES || projected_frames > HARD_LOG_FRAMES {
                return Err(JournalError::Capacity);
            }
        }
        Ok(())
    }

    fn transact_inner<R: RngCore + CryptoRng>(
        &mut self,
        operations: &[Operation],
        zero_op_checkpoint: bool,
        rng: &mut R,
    ) -> Result<(), JournalError> {
        if !self.healthy {
            return Err(JournalError::Unhealthy);
        }
        if operations.is_empty() != zero_op_checkpoint {
            return Err(JournalError::Corrupt);
        }
        let (_, dp, dr, sequence, head, root, pending) =
            committed_fields(&self.anchor_snapshot.decoded.state)?;
        if sequence != self.sequence
            || head != self.head
            || root != self.root
            || dp != self.protected_header_digest
            || dr != self.recovery_header_digest
            || pending.is_some()
        {
            return Err(JournalError::Unhealthy);
        }

        let canonical_delta = canonical_delta(operations)?;
        let delta_digest: [u8; 32] = Sha256::digest(&canonical_delta).into();
        let next_sequence = self
            .sequence
            .checked_add(1)
            .ok_or(JournalError::SequenceExhausted)?;
        let next_state = apply_operations(&self.state, operations, true)?;
        let next_root = state_root(self.instance_id, next_sequence, &next_state)?;
        let next_head = next_head(
            self.instance_id,
            next_sequence,
            self.head,
            self.root,
            next_root,
            delta_digest,
        );
        let payload = TransactionPayload {
            sequence: self.sequence,
            previous_head: self.head,
            previous_root: self.root,
            next_sequence,
            next_head,
            next_root,
            delta_digest,
            canonical_delta,
        };
        let payload_bytes = payload.encode()?;
        let affected = payload.affected_segments(zero_op_checkpoint)?;
        let frame_len = u64::try_from(FRAME_FIXED_LEN + payload_bytes.len())
            .map_err(|_| JournalError::Capacity)?;
        self.preflight_frame_pair(frame_len, &affected)?;

        let mut prepared_frames = BTreeMap::new();
        let mut committed_frames = BTreeMap::new();
        for segment in &affected {
            let header_digest = match *segment {
                PROTECTED_SEGMENT => self.protected_header_digest,
                RECOVERY_SEGMENT => self.recovery_header_digest,
                _ => return Err(JournalError::Corrupt),
            };
            let key =
                derive_frame_key(&self.key, &self.instance_id, self.key_epoch.get(), *segment)?;
            prepared_frames.insert(
                *segment,
                encode_frame(
                    FRAME_PREPARED,
                    self.key_epoch.get(),
                    &payload_bytes,
                    &header_digest,
                    &key,
                )?,
            );
            committed_frames.insert(
                *segment,
                encode_frame(
                    FRAME_COMMITTED,
                    self.key_epoch.get(),
                    &payload_bytes,
                    &header_digest,
                    &key,
                )?,
            );
        }

        let result = (|| {
            // 1. Prepared in segment-tag order; append_frame fsyncs the file.
            for segment in &affected {
                let path = self.segment_path_and_frames(*segment)?.0;
                append_frame(
                    path,
                    prepared_frames.get(segment).ok_or(JournalError::Corrupt)?,
                )?;
            }
            self.inject_failure(TxFailpoint::AfterPreparedFsync)?;

            // 2. External anchor publishes the sole pending successor.
            let pending_state = AnchorState::Committed {
                instance_id: self.instance_id,
                protected_header_digest: self.protected_header_digest,
                recovery_header_digest: self.recovery_header_digest,
                sequence: self.sequence,
                head: self.head,
                root: self.root,
                pending: Some(PendingAnchor {
                    previous_head: self.head,
                    previous_state_root: self.root,
                    next_sequence,
                    next_head,
                    next_state_root: next_root,
                }),
            };
            self.anchor_snapshot = self.anchor.compare_and_swap(
                Some(&self.anchor_snapshot),
                self.anchor_snapshot.decoded.kdf_salt,
                &pending_state,
                rng,
            )?;
            self.inject_failure(TxFailpoint::AfterPendingAnchor)?;

            // 3. Matching Committed frames in segment-tag order.
            for segment in &affected {
                let path = self.segment_path_and_frames(*segment)?.0;
                append_frame(
                    path,
                    committed_frames.get(segment).ok_or(JournalError::Corrupt)?,
                )?;
            }
            self.inject_failure(TxFailpoint::AfterCommittedFsync)?;

            // 4. Final external CAS is the publication point.
            let final_state = AnchorState::Committed {
                instance_id: self.instance_id,
                protected_header_digest: self.protected_header_digest,
                recovery_header_digest: self.recovery_header_digest,
                sequence: next_sequence,
                head: next_head,
                root: next_root,
                pending: None,
            };
            self.anchor_snapshot = self.anchor.compare_and_swap(
                Some(&self.anchor_snapshot),
                self.anchor_snapshot.decoded.kdf_salt,
                &final_state,
                rng,
            )?;
            self.inject_failure(TxFailpoint::AfterFinalAnchor)?;
            Ok(())
        })();
        if let Err(error) = result {
            self.healthy = false;
            return Err(error);
        }

        self.sequence = next_sequence;
        self.head = next_head;
        self.root = next_root;
        self.state = next_state;
        for segment in affected {
            match segment {
                PROTECTED_SEGMENT => {
                    self.protected_frames = self
                        .protected_frames
                        .checked_add(2)
                        .ok_or(JournalError::Capacity)?;
                }
                RECOVERY_SEGMENT => {
                    self.recovery_frames = self
                        .recovery_frames
                        .checked_add(2)
                        .ok_or(JournalError::Capacity)?;
                }
                _ => return Err(JournalError::Corrupt),
            }
        }
        Ok(())
    }

    fn inject_failure(&mut self, point: TxFailpoint) -> Result<(), JournalError> {
        if self.failpoint == Some(point) {
            self.failpoint = None;
            Err(JournalError::InjectedFailure)
        } else {
            Ok(())
        }
    }

    fn checkpoint<R: RngCore + CryptoRng>(&mut self, rng: &mut R) -> Result<(), JournalError> {
        self.transact_inner(&[], true, rng)?;
        let protected_postimage = canonical_protected(&self.state)?;
        let recovery_postimage = canonical_recovery(&self.state)?;
        let protected_digest: [u8; 32] = Sha256::digest(&protected_postimage).into();
        let recovery_digest: [u8; 32] = Sha256::digest(&recovery_postimage).into();
        let protected_payload = CheckpointPayload {
            sequence: self.sequence,
            head: self.head,
            root: self.root,
            protected_digest,
            recovery_digest,
            postimage: protected_postimage,
        }
        .encode()?;
        let recovery_payload = CheckpointPayload {
            sequence: self.sequence,
            head: self.head,
            root: self.root,
            protected_digest,
            recovery_digest,
            postimage: recovery_postimage,
        }
        .encode()?;
        let protected_key = derive_frame_key(
            &self.key,
            &self.instance_id,
            self.key_epoch.get(),
            PROTECTED_SEGMENT,
        )?;
        let recovery_key = derive_frame_key(
            &self.key,
            &self.instance_id,
            self.key_epoch.get(),
            RECOVERY_SEGMENT,
        )?;
        let protected_frame = encode_frame(
            FRAME_CHECKPOINT,
            self.key_epoch.get(),
            &protected_payload,
            &self.protected_header_digest,
            &protected_key,
        )?;
        let recovery_frame = encode_frame(
            FRAME_CHECKPOINT,
            self.key_epoch.get(),
            &recovery_payload,
            &self.recovery_header_digest,
            &recovery_key,
        )?;
        for (path, count, frame) in [
            (
                &self.protected_path,
                self.protected_frames,
                &protected_frame,
            ),
            (&self.recovery_path, self.recovery_frames, &recovery_frame),
        ] {
            if fs::metadata(path)?
                .len()
                .checked_add(frame.len() as u64)
                .is_none_or(|len| len > HARD_LOG_BYTES)
                || count
                    .checked_add(1)
                    .is_none_or(|frames| frames > HARD_LOG_FRAMES)
            {
                self.healthy = false;
                return Err(JournalError::Capacity);
            }
        }

        let result = (|| {
            append_frame(&self.protected_path, &protected_frame)?;
            append_frame(&self.recovery_path, &recovery_frame)?;
            fsync_dir(&self.journal_dir)?;

            let mut protected_image =
                Vec::with_capacity(SEGMENT_HEADER_LEN + protected_frame.len());
            protected_image.extend_from_slice(&self.protected_header);
            protected_image.extend_from_slice(&protected_frame);
            atomic_replace(&self.protected_path, &protected_image)?;
            fsync_dir(&self.journal_dir)?;

            let mut recovery_image = Vec::with_capacity(SEGMENT_HEADER_LEN + recovery_frame.len());
            recovery_image.extend_from_slice(&self.recovery_header);
            recovery_image.extend_from_slice(&recovery_frame);
            atomic_replace(&self.recovery_path, &recovery_image)?;
            fsync_dir(&self.journal_dir)?;
            Ok(())
        })();
        if let Err(error) = result {
            self.healthy = false;
            return Err(error);
        }
        self.protected_frames = 1;
        self.recovery_frames = 1;
        Ok(())
    }
}

fn transaction_frame_len(delta_len: usize) -> Result<u64, JournalError> {
    let payload = TRANSACTION_PAYLOAD_FIXED_LEN
        .checked_add(delta_len)
        .ok_or(JournalError::Capacity)?;
    u64::try_from(
        FRAME_FIXED_LEN
            .checked_add(payload)
            .ok_or(JournalError::Capacity)?,
    )
    .map_err(|_| JournalError::Capacity)
}

fn affected_segments(
    operations: &[Operation],
    zero_op_checkpoint: bool,
) -> Result<Vec<u8>, JournalError> {
    let mut segments = BTreeSet::new();
    for operation in operations {
        if !matches!(operation.segment, PROTECTED_SEGMENT | RECOVERY_SEGMENT) {
            return Err(JournalError::Corrupt);
        }
        segments.insert(operation.segment);
    }
    if segments.is_empty() {
        if !zero_op_checkpoint {
            return Err(JournalError::Corrupt);
        }
        segments.insert(PROTECTED_SEGMENT);
        segments.insert(RECOVERY_SEGMENT);
    }
    Ok(segments.into_iter().collect())
}

fn committed_fields(
    state: &AnchorState,
) -> Result<
    (
        [u8; 16],
        [u8; 32],
        [u8; 32],
        u64,
        [u8; 32],
        [u8; 32],
        Option<PendingAnchor>,
    ),
    JournalError,
> {
    match state {
        AnchorState::Committed {
            instance_id,
            protected_header_digest,
            recovery_header_digest,
            sequence,
            head,
            root,
            pending,
        } => Ok((
            *instance_id,
            *protected_header_digest,
            *recovery_header_digest,
            *sequence,
            *head,
            *root,
            pending.clone(),
        )),
        AnchorState::BootstrapPending { .. } => Err(JournalError::Corrupt),
    }
}

fn bootstrap_fresh<R: RngCore + CryptoRng>(
    anchor: &ExternalAnchor,
    journal_dir: &Path,
    protected_path: &Path,
    recovery_path: &Path,
    rng: &mut R,
) -> Result<AnchorSnapshot, JournalError> {
    let mut instance_id = [0u8; 16];
    let mut bootstrap_nonce = [0u8; 16];
    let mut salt = [0u8; 32];
    rng.fill_bytes(&mut instance_id);
    rng.fill_bytes(&mut bootstrap_nonce);
    rng.fill_bytes(&mut salt);
    nonzero(&instance_id)?;
    nonzero(&bootstrap_nonce)?;
    let protected_header = segment_header(instance_id, bootstrap_nonce, PROTECTED_SEGMENT);
    let recovery_header = segment_header(instance_id, bootstrap_nonce, RECOVERY_SEGMENT);
    let protected_digest = segment_header_digest(&protected_header);
    let recovery_digest = segment_header_digest(&recovery_header);
    let pending = AnchorState::BootstrapPending {
        instance_id,
        bootstrap_nonce,
        protected_header_digest: protected_digest,
        recovery_header_digest: recovery_digest,
    };
    let snapshot = anchor.compare_and_swap(None, salt, &pending, rng)?;
    create_segment_header_no_replace(protected_path, &protected_header)?;
    fsync_dir(journal_dir)?;
    create_segment_header_no_replace(recovery_path, &recovery_header)?;
    fsync_dir(journal_dir)?;
    finish_bootstrap(anchor, snapshot, protected_path, recovery_path, rng)
}

fn resume_bootstrap<R: RngCore + CryptoRng>(
    anchor: &ExternalAnchor,
    journal_dir: &Path,
    protected_path: &Path,
    recovery_path: &Path,
    snapshot: AnchorSnapshot,
    rng: &mut R,
) -> Result<AnchorSnapshot, JournalError> {
    let AnchorState::BootstrapPending {
        instance_id,
        bootstrap_nonce,
        protected_header_digest,
        recovery_header_digest,
    } = snapshot.decoded.state.clone()
    else {
        return Err(JournalError::Corrupt);
    };
    let protected_header = segment_header(instance_id, bootstrap_nonce, PROTECTED_SEGMENT);
    let recovery_header = segment_header(instance_id, bootstrap_nonce, RECOVERY_SEGMENT);
    if segment_header_digest(&protected_header) != protected_header_digest
        || segment_header_digest(&recovery_header) != recovery_header_digest
    {
        return Err(JournalError::AnchorMismatch);
    }
    ensure_or_create_empty_segment(protected_path, &protected_header)?;
    fsync_dir(journal_dir)?;
    ensure_or_create_empty_segment(recovery_path, &recovery_header)?;
    fsync_dir(journal_dir)?;
    finish_bootstrap(anchor, snapshot, protected_path, recovery_path, rng)
}

fn finish_bootstrap<R: RngCore + CryptoRng>(
    anchor: &ExternalAnchor,
    snapshot: AnchorSnapshot,
    protected_path: &Path,
    recovery_path: &Path,
    rng: &mut R,
) -> Result<AnchorSnapshot, JournalError> {
    let AnchorState::BootstrapPending {
        instance_id,
        protected_header_digest,
        recovery_header_digest,
        ..
    } = snapshot.decoded.state.clone()
    else {
        return Err(JournalError::Corrupt);
    };
    if fs::metadata(protected_path)?.len() != SEGMENT_HEADER_LEN as u64
        || fs::metadata(recovery_path)?.len() != SEGMENT_HEADER_LEN as u64
    {
        return Err(JournalError::Corrupt);
    }
    let empty = LogicalState::default();
    let root = state_root(instance_id, 0, &empty)?;
    let head = genesis_head(instance_id, root);
    let committed = AnchorState::Committed {
        instance_id,
        protected_header_digest,
        recovery_header_digest,
        sequence: 0,
        head,
        root,
        pending: None,
    };
    anchor.compare_and_swap(Some(&snapshot), snapshot.decoded.kdf_salt, &committed, rng)
}

fn create_segment_header_no_replace(path: &Path, header: &[u8; 44]) -> Result<(), JournalError> {
    atomic_create_no_replace(path, header).map_err(|error| match error {
        JournalError::AnchorConflict => JournalError::Corrupt,
        other => other,
    })
}

fn ensure_or_create_empty_segment(path: &Path, header: &[u8; 44]) -> Result<(), JournalError> {
    match read_bounded_file(path, SEGMENT_HEADER_LEN as u64)? {
        None => create_segment_header_no_replace(path, header),
        Some(observed) if observed == header => Ok(()),
        Some(_) => Err(JournalError::Corrupt),
    }
}

fn read_exact_header(path: &Path) -> Result<[u8; SEGMENT_HEADER_LEN], JournalError> {
    ensure_owner_file(path)?;
    let mut file = File::open(path)?;
    let mut header = [0u8; SEGMENT_HEADER_LEN];
    file.read_exact(&mut header)?;
    Ok(header)
}

#[derive(Clone)]
struct CheckpointPayload {
    sequence: u64,
    head: [u8; 32],
    root: [u8; 32],
    protected_digest: [u8; 32],
    recovery_digest: [u8; 32],
    postimage: Vec<u8>,
}

impl CheckpointPayload {
    fn encode(&self) -> Result<Vec<u8>, JournalError> {
        let len = u64::try_from(self.postimage.len()).map_err(|_| JournalError::Capacity)?;
        let mut out = Vec::with_capacity(144 + self.postimage.len());
        out.extend_from_slice(&self.sequence.to_be_bytes());
        out.extend_from_slice(&self.head);
        out.extend_from_slice(&self.root);
        out.extend_from_slice(&self.protected_digest);
        out.extend_from_slice(&self.recovery_digest);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&self.postimage);
        Ok(out)
    }

    fn decode(bytes: &[u8]) -> Result<Self, JournalError> {
        let mut c = Cursor::new(bytes);
        let sequence = c.u64()?;
        let head = c.b32()?;
        let root = c.b32()?;
        let protected_digest = c.b32()?;
        let recovery_digest = c.b32()?;
        let len = c.u64()?;
        if len > MAX_RECOVERY_ROW_BYTES + 57 || len as usize != c.remaining() {
            return Err(JournalError::Corrupt);
        }
        let postimage = c.take(len as usize)?.to_vec();
        c.finish()?;
        Ok(Self {
            sequence,
            head,
            root,
            protected_digest,
            recovery_digest,
            postimage,
        })
    }

    fn key(&self) -> ([u8; 32], [u8; 32], [u8; 32], [u8; 32], u64) {
        (
            self.head,
            self.root,
            self.protected_digest,
            self.recovery_digest,
            self.sequence,
        )
    }
}

struct RecoveryResult {
    anchor_snapshot: AnchorSnapshot,
    sequence: u64,
    head: [u8; 32],
    root: [u8; 32],
    state: LogicalState,
    protected_frames: u64,
    recovery_frames: u64,
}

#[derive(Default)]
struct ObservedTransaction {
    payload_bytes: Option<Vec<u8>>,
    payload: Option<TransactionPayload>,
    prepared: BTreeMap<u8, u64>,
    committed: BTreeMap<u8, u64>,
    first_offsets: BTreeMap<u8, u64>,
}

fn recover_physical_logs<R: RngCore + CryptoRng>(
    anchor: &ExternalAnchor,
    mut anchor_snapshot: AnchorSnapshot,
    protected_path: &Path,
    recovery_path: &Path,
    protected_scan: &SegmentScan,
    recovery_scan: &SegmentScan,
    instance_id: [u8; 16],
    key_epoch: NonZeroU32,
    master_key: &[u8; 32],
    rng: &mut R,
) -> Result<RecoveryResult, JournalError> {
    let (_, dp, dr, committed_sequence, committed_head, committed_root, pending) =
        committed_fields(&anchor_snapshot.decoded.state)?;
    if dp != protected_scan.header_digest || dr != recovery_scan.header_digest {
        return Err(JournalError::AnchorMismatch);
    }

    let mut protected_checkpoints = Vec::new();
    let mut recovery_checkpoints = Vec::new();
    for frame in &protected_scan.frames {
        if frame.tag == FRAME_CHECKPOINT {
            protected_checkpoints.push((frame, CheckpointPayload::decode(&frame.payload)?));
        }
    }
    for frame in &recovery_scan.frames {
        if frame.tag == FRAME_CHECKPOINT {
            recovery_checkpoints.push((frame, CheckpointPayload::decode(&frame.payload)?));
        }
    }

    let mut selected: Option<(
        &PhysicalFrame,
        CheckpointPayload,
        &PhysicalFrame,
        CheckpointPayload,
    )> = None;
    for (pf, pp) in &protected_checkpoints {
        for (rf, rp) in &recovery_checkpoints {
            if pp.key() == rp.key()
                && pp.sequence <= committed_sequence
                && selected
                    .as_ref()
                    .is_none_or(|(_, old, _, _)| old.sequence < pp.sequence)
            {
                selected = Some((pf, pp.clone(), rf, rp.clone()));
            }
        }
    }

    let (mut sequence, mut head, mut root, mut state, protected_base_end, recovery_base_end) =
        if let Some((pf, pp, rf, rp)) = selected {
            if Sha256::digest(&pp.postimage).as_slice() != pp.protected_digest
                || Sha256::digest(&rp.postimage).as_slice() != rp.recovery_digest
                || pp.postimage.first() != Some(&PROTECTED_SEGMENT)
                || rp.postimage.first() != Some(&RECOVERY_SEGMENT)
            {
                return Err(JournalError::Corrupt);
            }
            let protected = decode_canonical_segment(&pp.postimage, PROTECTED_SEGMENT)?;
            let recovery = decode_canonical_segment(&rp.postimage, RECOVERY_SEGMENT)?;
            let state = merge_segment_states(protected, recovery)?;
            if state_root(instance_id, pp.sequence, &state)? != pp.root {
                return Err(JournalError::Rollback);
            }
            (pp.sequence, pp.head, pp.root, state, pf.end, rf.end)
        } else {
            // A checkpoint-only image without a mutually cross-bound pair has
            // no retained history from which to prove the anchor.
            let p_only = protected_scan
                .frames
                .first()
                .is_some_and(|frame| frame.tag == FRAME_CHECKPOINT);
            let r_only = recovery_scan
                .frames
                .first()
                .is_some_and(|frame| frame.tag == FRAME_CHECKPOINT);
            if p_only || r_only {
                return Err(JournalError::Corrupt);
            }
            let state = LogicalState::default();
            let root = state_root(instance_id, 0, &state)?;
            (
                0,
                genesis_head(instance_id, root),
                root,
                state,
                SEGMENT_HEADER_LEN as u64,
                SEGMENT_HEADER_LEN as u64,
            )
        };

    let mut transactions: BTreeMap<u64, ObservedTransaction> = BTreeMap::new();
    collect_transactions(protected_scan, protected_base_end, &mut transactions)?;
    collect_transactions(recovery_scan, recovery_base_end, &mut transactions)?;
    if transactions
        .first_key_value()
        .is_some_and(|(next_sequence, _)| *next_sequence <= sequence)
    {
        return Err(JournalError::Corrupt);
    }

    while sequence < committed_sequence {
        let next_sequence = sequence
            .checked_add(1)
            .ok_or(JournalError::SequenceExhausted)?;
        let observed = transactions
            .get(&next_sequence)
            .ok_or(JournalError::Rollback)?;
        let payload = observed.payload.as_ref().ok_or(JournalError::Corrupt)?;
        require_complete_transaction(observed, payload, true)?;
        let next_state = replay_payload(instance_id, sequence, head, root, &state, payload)?;
        state = next_state;
        sequence = payload.next_sequence;
        head = payload.next_head;
        root = payload.next_root;
    }
    if sequence != committed_sequence
        || head != committed_head
        || root != committed_root
        || state_root(instance_id, sequence, &state)? != root
    {
        return Err(JournalError::Rollback);
    }

    if let Some(pending) = pending {
        if pending.previous_head != head
            || pending.previous_state_root != root
            || pending.next_sequence
                != sequence
                    .checked_add(1)
                    .ok_or(JournalError::SequenceExhausted)?
        {
            return Err(JournalError::Rollback);
        }
        let observed = transactions
            .get(&pending.next_sequence)
            .ok_or(JournalError::Rollback)?;
        let payload = observed.payload.as_ref().ok_or(JournalError::Corrupt)?;
        if payload.previous_head != pending.previous_head
            || payload.previous_root != pending.previous_state_root
            || payload.next_head != pending.next_head
            || payload.next_root != pending.next_state_root
        {
            return Err(JournalError::Rollback);
        }
        require_complete_transaction(observed, payload, false)?;
        if let Some(first_after_pending) = pending.next_sequence.checked_add(1) {
            if let Some((_, extra)) = transactions.range(first_after_pending..).next() {
                return Err(if extra.committed.is_empty() {
                    JournalError::Corrupt
                } else {
                    JournalError::Rollback
                });
            }
        }
        truncate_partial_suffixes(
            protected_path,
            recovery_path,
            protected_scan,
            recovery_scan,
            observed,
        )?;
        append_missing_committed(
            protected_path,
            recovery_path,
            protected_scan,
            recovery_scan,
            observed,
            payload,
            key_epoch,
            instance_id,
            master_key,
        )?;
        let next_state = replay_payload(instance_id, sequence, head, root, &state, payload)?;
        state = next_state;
        sequence = payload.next_sequence;
        head = payload.next_head;
        root = payload.next_root;
        let final_state = AnchorState::Committed {
            instance_id,
            protected_header_digest: dp,
            recovery_header_digest: dr,
            sequence,
            head,
            root,
            pending: None,
        };
        anchor_snapshot = anchor.compare_and_swap(
            Some(&anchor_snapshot),
            anchor_snapshot.decoded.kdf_salt,
            &final_state,
            rng,
        )?;
    } else {
        if let Some(first_uncommitted) = committed_sequence.checked_add(1) {
            for (tx_sequence, observed) in transactions.range(first_uncommitted..) {
                if !observed.committed.is_empty() {
                    return Err(JournalError::Rollback);
                }
                if *tx_sequence != first_uncommitted {
                    return Err(JournalError::Corrupt);
                }
            }
        }
        truncate_unanchored_suffixes(
            protected_path,
            recovery_path,
            protected_scan,
            recovery_scan,
            &transactions,
            committed_sequence,
            protected_base_end,
            recovery_base_end,
        )?;
    }
    validate_cross_rows(&state).or_else(|error| {
        // Sequence zero is the only legal pre-marker/pre-provider empty image.
        if sequence == 0 && state.protected.is_empty() && state.recovery.is_empty() {
            Ok(())
        } else {
            Err(error)
        }
    })?;

    let protected_rescan = scan_segment(
        protected_path,
        PROTECTED_SEGMENT,
        instance_id,
        key_epoch.get(),
        master_key,
    )?;
    let recovery_rescan = scan_segment(
        recovery_path,
        RECOVERY_SEGMENT,
        instance_id,
        key_epoch.get(),
        master_key,
    )?;
    Ok(RecoveryResult {
        anchor_snapshot,
        sequence,
        head,
        root,
        state,
        protected_frames: protected_rescan.frames.len() as u64,
        recovery_frames: recovery_rescan.frames.len() as u64,
    })
}

fn collect_transactions(
    scan: &SegmentScan,
    base_end: u64,
    transactions: &mut BTreeMap<u64, ObservedTransaction>,
) -> Result<(), JournalError> {
    let mut last_sequence = None;
    let mut last_tag = None;
    for frame in &scan.frames {
        if frame.end <= base_end || frame.tag == FRAME_CHECKPOINT {
            continue;
        }
        if frame.start < base_end {
            return Err(JournalError::Corrupt);
        }
        let payload = TransactionPayload::decode(&frame.payload)?;
        let next_sequence = payload.next_sequence;
        match (last_sequence, last_tag) {
            (None, _) if frame.tag != FRAME_PREPARED => return Err(JournalError::Corrupt),
            (Some(prior), _) if next_sequence < prior => return Err(JournalError::Corrupt),
            (Some(prior), Some(FRAME_PREPARED))
                if next_sequence == prior && frame.tag == FRAME_COMMITTED => {}
            (Some(prior), _) if next_sequence == prior => return Err(JournalError::Corrupt),
            (Some(_), _) if frame.tag != FRAME_PREPARED => return Err(JournalError::Corrupt),
            _ => {}
        }
        last_sequence = Some(next_sequence);
        last_tag = Some(frame.tag);
        let observed = transactions.entry(next_sequence).or_default();
        if let Some(prior) = observed.payload_bytes.as_ref() {
            if prior.len() != frame.payload.len()
                || !bool::from(prior.as_slice().ct_eq(&frame.payload))
            {
                return Err(JournalError::Corrupt);
            }
        } else {
            observed.payload_bytes = Some(frame.payload.clone());
            observed.payload = Some(payload);
        }
        observed
            .first_offsets
            .entry(scan.tag)
            .and_modify(|offset| *offset = (*offset).min(frame.start))
            .or_insert(frame.start);
        let destination = match frame.tag {
            FRAME_PREPARED => &mut observed.prepared,
            FRAME_COMMITTED => &mut observed.committed,
            _ => return Err(JournalError::Corrupt),
        };
        if destination.insert(scan.tag, frame.end).is_some() {
            return Err(JournalError::Corrupt);
        }
    }
    Ok(())
}

fn require_complete_transaction(
    observed: &ObservedTransaction,
    payload: &TransactionPayload,
    committed_required: bool,
) -> Result<(), JournalError> {
    let zero_op = payload.canonical_delta == [0, 0, 0, 0];
    let affected: BTreeSet<u8> = payload.affected_segments(zero_op)?.into_iter().collect();
    for segment in observed
        .prepared
        .keys()
        .chain(observed.committed.keys())
        .chain(observed.first_offsets.keys())
    {
        if !affected.contains(segment) {
            return Err(JournalError::Corrupt);
        }
    }
    if observed.prepared.keys().copied().collect::<BTreeSet<_>>() != affected {
        return Err(JournalError::Rollback);
    }
    if !observed
        .committed
        .keys()
        .all(|segment| affected.contains(segment) && observed.prepared.contains_key(segment))
    {
        return Err(JournalError::Corrupt);
    }
    let frame_len = u64::try_from(
        FRAME_FIXED_LEN
            .checked_add(
                observed
                    .payload_bytes
                    .as_ref()
                    .ok_or(JournalError::Corrupt)?
                    .len(),
            )
            .ok_or(JournalError::Capacity)?,
    )
    .map_err(|_| JournalError::Capacity)?;
    for segment in &affected {
        if let (Some(prepared_end), Some(committed_end)) = (
            observed.prepared.get(segment),
            observed.committed.get(segment),
        ) {
            let committed_start = committed_end
                .checked_sub(frame_len)
                .ok_or(JournalError::Corrupt)?;
            if committed_start < *prepared_end {
                return Err(JournalError::Corrupt);
            }
        }
    }
    if committed_required && observed.committed.keys().copied().collect::<BTreeSet<_>>() != affected
    {
        return Err(JournalError::Rollback);
    }
    Ok(())
}

fn replay_payload(
    instance_id: [u8; 16],
    sequence: u64,
    head: [u8; 32],
    root: [u8; 32],
    state: &LogicalState,
    payload: &TransactionPayload,
) -> Result<LogicalState, JournalError> {
    if payload.sequence != sequence
        || payload.previous_head != head
        || payload.previous_root != root
        || payload.next_sequence
            != sequence
                .checked_add(1)
                .ok_or(JournalError::SequenceExhausted)?
    {
        return Err(JournalError::Rollback);
    }
    let operations = payload.operations()?;
    let next = apply_operations(state, &operations, true)?;
    let computed_root = state_root(instance_id, payload.next_sequence, &next)?;
    let computed_head = next_head(
        instance_id,
        payload.next_sequence,
        head,
        root,
        computed_root,
        payload.delta_digest,
    );
    if computed_root != payload.next_root || computed_head != payload.next_head {
        return Err(JournalError::Corrupt);
    }
    Ok(next)
}

fn authoritative_end(
    scan: &SegmentScan,
    base_end: u64,
    maximum_sequence: u64,
) -> Result<u64, JournalError> {
    let mut end = base_end;
    for frame in &scan.frames {
        if frame.end <= base_end {
            continue;
        }
        if matches!(frame.tag, FRAME_PREPARED | FRAME_COMMITTED) {
            let payload = TransactionPayload::decode(&frame.payload)?;
            if payload.next_sequence <= maximum_sequence {
                end = end.max(frame.end);
            }
        }
    }
    Ok(end)
}

fn truncate_file_to(path: &Path, len: u64) -> Result<(), JournalError> {
    let file = open_owner_file(path, false, false)?;
    if file.metadata()?.len() != len {
        file.set_len(len)?;
        file.sync_all()?;
        fsync_dir(path.parent().ok_or(JournalError::Configuration)?)?;
    }
    Ok(())
}

fn truncate_partial_suffixes(
    protected_path: &Path,
    recovery_path: &Path,
    protected_scan: &SegmentScan,
    recovery_scan: &SegmentScan,
    observed: &ObservedTransaction,
) -> Result<(), JournalError> {
    let payload = observed.payload.as_ref().ok_or(JournalError::Corrupt)?;
    let protected_base = observed
        .first_offsets
        .get(&PROTECTED_SEGMENT)
        .copied()
        .unwrap_or_else(|| {
            protected_scan
                .trailing_partial_at
                .unwrap_or(protected_scan.file_len)
        });
    let recovery_base = observed
        .first_offsets
        .get(&RECOVERY_SEGMENT)
        .copied()
        .unwrap_or_else(|| {
            recovery_scan
                .trailing_partial_at
                .unwrap_or(recovery_scan.file_len)
        });
    // Retain every complete frame through the pending transaction and remove
    // an incomplete next frame or an isolated checkpoint suffix before repair.
    let protected_end = authoritative_end(protected_scan, protected_base, payload.next_sequence)?
        .max(
            observed
                .prepared
                .get(&PROTECTED_SEGMENT)
                .copied()
                .unwrap_or(protected_base),
        )
        .max(
            observed
                .committed
                .get(&PROTECTED_SEGMENT)
                .copied()
                .unwrap_or(protected_base),
        );
    let recovery_end = authoritative_end(recovery_scan, recovery_base, payload.next_sequence)?
        .max(
            observed
                .prepared
                .get(&RECOVERY_SEGMENT)
                .copied()
                .unwrap_or(recovery_base),
        )
        .max(
            observed
                .committed
                .get(&RECOVERY_SEGMENT)
                .copied()
                .unwrap_or(recovery_base),
        );
    truncate_file_to(protected_path, protected_end)?;
    truncate_file_to(recovery_path, recovery_end)
}

#[allow(clippy::too_many_arguments)]
fn append_missing_committed(
    protected_path: &Path,
    recovery_path: &Path,
    protected_scan: &SegmentScan,
    recovery_scan: &SegmentScan,
    observed: &ObservedTransaction,
    payload: &TransactionPayload,
    key_epoch: NonZeroU32,
    instance_id: [u8; 16],
    master_key: &[u8; 32],
) -> Result<(), JournalError> {
    let payload_bytes = payload.encode()?;
    for (segment, path, scan) in [
        (PROTECTED_SEGMENT, protected_path, protected_scan),
        (RECOVERY_SEGMENT, recovery_path, recovery_scan),
    ] {
        if !observed.prepared.contains_key(&segment) || observed.committed.contains_key(&segment) {
            continue;
        }
        let key = derive_frame_key(master_key, &instance_id, key_epoch.get(), segment)?;
        let frame = encode_frame(
            FRAME_COMMITTED,
            key_epoch.get(),
            &payload_bytes,
            &scan.header_digest,
            &key,
        )?;
        let current_len = fs::metadata(path)?.len();
        if current_len
            .checked_add(frame.len() as u64)
            .is_none_or(|len| len > HARD_LOG_BYTES)
        {
            return Err(JournalError::Capacity);
        }
        let retained_frames = scan
            .frames
            .iter()
            .filter(|candidate| candidate.end <= current_len)
            .count() as u64;
        if retained_frames
            .checked_add(1)
            .is_none_or(|count| count > HARD_LOG_FRAMES)
        {
            return Err(JournalError::Capacity);
        }
        append_frame(path, &frame)?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn truncate_unanchored_suffixes(
    protected_path: &Path,
    recovery_path: &Path,
    protected_scan: &SegmentScan,
    recovery_scan: &SegmentScan,
    _transactions: &BTreeMap<u64, ObservedTransaction>,
    committed_sequence: u64,
    protected_base_end: u64,
    recovery_base_end: u64,
) -> Result<(), JournalError> {
    let protected_end = authoritative_end(protected_scan, protected_base_end, committed_sequence)?;
    let recovery_end = authoritative_end(recovery_scan, recovery_base_end, committed_sequence)?;
    truncate_file_to(protected_path, protected_end)?;
    truncate_file_to(recovery_path, recovery_end)
}

impl JournalCore {
    fn complete_runtime_marker<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Result<(), JournalError> {
        let marker_key = RowKey {
            tag: 0x05,
            key: Vec::new(),
        };
        let existing = self.state.recovery.get(&marker_key).cloned();
        let (marker_value, marker) = match existing {
            None => {
                // Marker absence is legal only at the exact empty genesis.
                if self.sequence != 0
                    || !self.state.protected.is_empty()
                    || !self.state.recovery.is_empty()
                {
                    return Err(JournalError::Corrupt);
                }
                let current = random_nonzero_b16(rng)?;
                let booted_at_ms = unix_time_ms()?;
                let evidence = lock_evidence_digest(
                    &self.anchor_snapshot.revision,
                    current,
                    None,
                    booted_at_ms,
                    rng,
                )?;
                let value = encode_runtime_marker(current, None, evidence, booted_at_ms);
                self.transact(
                    &[Operation::insert(RECOVERY_SEGMENT, 0x05, Vec::new(), value)],
                    rng,
                )?;
                return Ok(());
            }
            Some(before) => {
                let ParsedRecoveryRow::Marker(existing_marker) =
                    parse_recovery_row(&marker_key, &before)?
                else {
                    return Err(JournalError::Corrupt);
                };
                if existing_marker.retired.is_some() {
                    (before, existing_marker)
                } else {
                    let current = random_nonzero_b16_excluding(rng, existing_marker.current)?;
                    let booted_at_ms = unix_time_ms()?;
                    let evidence = lock_evidence_digest(
                        &self.anchor_snapshot.revision,
                        current,
                        Some(existing_marker.current),
                        booted_at_ms,
                        rng,
                    )?;
                    let after = encode_runtime_marker(
                        current,
                        Some(existing_marker.current),
                        evidence,
                        booted_at_ms,
                    );
                    self.transact(
                        &[Operation::replace(
                            RECOVERY_SEGMENT,
                            0x05,
                            Vec::new(),
                            before,
                            after.clone(),
                        )],
                        rng,
                    )?;
                    let ParsedRecoveryRow::Marker(marker) =
                        parse_recovery_row(&marker_key, &after)?
                    else {
                        return Err(JournalError::Corrupt);
                    };
                    (after, marker)
                }
            }
        };

        let old = marker.retired.ok_or(JournalError::Corrupt)?;
        reject_unpublished_runtime_rows(&self.state, marker.current)?;
        let marker_digest = runtime_marker_digest(&marker_value)?;

        // A single source (or bound source+close pair) is one indivisible,
        // ascending transaction. This always fits the proved 8 MiB bound.
        loop {
            let candidate = self
                .state
                .recovery
                .iter()
                .filter(|(key, _)| key.tag == 0x01)
                .find_map(|(key, value)| match parse_recovery_row(key, value) {
                    Ok(ParsedRecoveryRow::Active(view)) if view.runtime == old => {
                        Some(Ok((key.clone(), value.clone(), view)))
                    }
                    Ok(ParsedRecoveryRow::Active(_)) => None,
                    Ok(_) => Some(Err(JournalError::Corrupt)),
                    Err(error) => Some(Err(error)),
                })
                .transpose()?;
            let Some((source_key, active_value, active)) = candidate else {
                break;
            };
            let source_digest: [u8; 32] = source_key
                .key
                .as_slice()
                .try_into()
                .map_err(|_| JournalError::Corrupt)?;
            match active.progress_key {
                None => {
                    self.transact(
                        &[Operation::delete(
                            RECOVERY_SEGMENT,
                            0x01,
                            source_key.key,
                            active_value,
                        )],
                        rng,
                    )?;
                }
                Some(progress_key) => {
                    let close_key = RowKey {
                        tag: 0x03,
                        key: progress_key.to_vec(),
                    };
                    let close_value = self
                        .state
                        .recovery
                        .get(&close_key)
                        .cloned()
                        .ok_or(JournalError::Corrupt)?;
                    let ParsedRecoveryRow::Close(close) =
                        parse_recovery_row(&close_key, &close_value)?
                    else {
                        return Err(JournalError::Corrupt);
                    };
                    if close.source != source_digest
                        || close.expected_agent != active.expected_agent
                        || close.runtime != old
                        || !close.open
                    {
                        return Err(JournalError::Corrupt);
                    }
                    let quiesced = encode_runtime_retired_source(
                        &active,
                        progress_key,
                        marker_digest,
                        marker.booted_at_ms,
                    );
                    let sealed = retire_open_close(
                        &close_value,
                        source_digest,
                        active.expected_agent,
                        old,
                        marker_digest,
                        marker.booted_at_ms,
                    )?;
                    let mut operations = vec![
                        Operation::delete(
                            RECOVERY_SEGMENT,
                            0x01,
                            source_key.key.clone(),
                            active_value,
                        ),
                        Operation::insert(RECOVERY_SEGMENT, 0x02, source_key.key, quiesced),
                        Operation::replace(
                            RECOVERY_SEGMENT,
                            0x03,
                            progress_key.to_vec(),
                            close_value,
                            sealed,
                        ),
                    ];
                    operations.extend(cancel_live_authorities_for_key(
                        &self.state,
                        progress_key,
                        marker.booted_at_ms,
                    )?);
                    sort_operations(&mut operations);
                    self.transact(&operations, rng)?;
                }
            }
        }

        // A process may retire after C216 has already committed quiescence and
        // after C215 has opened or even sealed the close lifecycle. Those rows
        // are no longer ActiveSource rows, but their old-runtime authority is
        // equally unrecoverable because composition creates fresh role keys.
        // Convert each exact pair to RuntimeRetired and cancel every stale live
        // authority for the bound key before the new runtime is published.
        loop {
            let candidate = self
                .state
                .recovery
                .iter()
                .filter(|(key, _)| key.tag == 0x02)
                .find_map(|(key, value)| match parse_recovery_row(key, value) {
                    Ok(ParsedRecoveryRow::Quiesced(view))
                        if view.runtime == old && !view.runtime_retired =>
                    {
                        Some(Ok((key.clone(), value.clone(), view)))
                    }
                    Ok(ParsedRecoveryRow::Quiesced(_)) => None,
                    Ok(_) => Some(Err(JournalError::Corrupt)),
                    Err(error) => Some(Err(error)),
                })
                .transpose()?;
            let Some((source_key, source_before, source)) = candidate else {
                break;
            };
            let source_digest: [u8; 32] = source_key
                .key
                .as_slice()
                .try_into()
                .map_err(|_| JournalError::Corrupt)?;
            let close_key = RowKey {
                tag: 0x03,
                key: source.progress_key.to_vec(),
            };
            let close_before = self
                .state
                .recovery
                .get(&close_key)
                .cloned()
                .ok_or(JournalError::Corrupt)?;
            let ParsedRecoveryRow::Close(close) = parse_recovery_row(&close_key, &close_before)?
            else {
                return Err(JournalError::Corrupt);
            };
            if close.source != source_digest
                || close.expected_agent != source.expected_agent
                || close.runtime != old
                || close.runtime_retired
            {
                return Err(JournalError::Corrupt);
            }
            let source_after = encode_runtime_retired_source(
                &ActiveSourceView {
                    runtime: source.runtime,
                    expected_agent: source.expected_agent,
                    generation: source.generation,
                    progress_key: Some(source.progress_key),
                },
                source.progress_key,
                marker_digest,
                marker.booted_at_ms,
            );
            let close_after = if close.open {
                retire_open_close(
                    &close_before,
                    source_digest,
                    source.expected_agent,
                    old,
                    marker_digest,
                    marker.booted_at_ms,
                )?
            } else {
                retire_already_sealed_close(
                    &close_before,
                    source_digest,
                    source.expected_agent,
                    old,
                    marker_digest,
                    marker.booted_at_ms,
                )?
            };
            let mut operations = vec![
                Operation::replace(
                    RECOVERY_SEGMENT,
                    0x02,
                    source_key.key,
                    source_before,
                    source_after,
                ),
                Operation::replace(
                    RECOVERY_SEGMENT,
                    0x03,
                    source.progress_key.to_vec(),
                    close_before,
                    close_after,
                ),
            ];
            operations.extend(cancel_live_authorities_for_key(
                &self.state,
                source.progress_key,
                marker.booted_at_ms,
            )?);
            sort_operations(&mut operations);
            self.transact(&operations, rng)?;
        }

        if self.state.recovery.iter().any(|(key, value)| {
            matches!(
                parse_recovery_row(key, value),
                Ok(ParsedRecoveryRow::Active(ActiveSourceView { runtime, .. })) if runtime == old
            ) || matches!(
                parse_recovery_row(key, value),
                Ok(ParsedRecoveryRow::Close(CloseLifecycleView {
                    runtime,
                    open: true,
                    ..
                })) if runtime == old
            ) || matches!(
                parse_recovery_row(key, value),
                Ok(ParsedRecoveryRow::Quiesced(QuiescedSourceView {
                    runtime,
                    runtime_retired: false,
                    ..
                })) if runtime == old
            ) || matches!(
                parse_recovery_row(key, value),
                Ok(ParsedRecoveryRow::Close(CloseLifecycleView {
                    runtime,
                    runtime_retired: false,
                    ..
                })) if runtime == old
            )
        }) {
            return Err(JournalError::Corrupt);
        }
        reject_unpublished_runtime_rows(&self.state, marker.current)?;
        let clear =
            encode_runtime_marker(marker.current, None, marker.evidence, marker.booted_at_ms);
        self.transact(
            &[Operation::replace(
                RECOVERY_SEGMENT,
                0x05,
                Vec::new(),
                marker_value,
                clear,
            )],
            rng,
        )
    }
}

fn random_nonzero_b16<R: RngCore + CryptoRng>(rng: &mut R) -> Result<[u8; 16], JournalError> {
    for _ in 0..4 {
        let mut value = [0u8; 16];
        rng.fill_bytes(&mut value);
        if value != [0; 16] {
            return Ok(value);
        }
    }
    Err(JournalError::Io)
}

fn random_nonzero_b16_excluding<R: RngCore + CryptoRng>(
    rng: &mut R,
    excluded: [u8; 16],
) -> Result<[u8; 16], JournalError> {
    for _ in 0..4 {
        let candidate = random_nonzero_b16(rng)?;
        if candidate != excluded {
            return Ok(candidate);
        }
    }
    Err(JournalError::Io)
}

fn unix_time_ms() -> Result<u64, JournalError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| JournalError::Io)?;
    u64::try_from(duration.as_millis()).map_err(|_| JournalError::SequenceExhausted)
}

fn lock_evidence_digest<R: RngCore + CryptoRng>(
    anchor_revision: &[u8; 32],
    current: [u8; 16],
    retired: Option<[u8; 16]>,
    booted_at_ms: u64,
    rng: &mut R,
) -> Result<[u8; 32], JournalError> {
    for _ in 0..4 {
        let mut nonce = [0u8; 32];
        rng.fill_bytes(&mut nonce);
        let mut retired_bytes = [0u8; 17];
        if let Some(old) = retired {
            retired_bytes[0] = 1;
            retired_bytes[1..].copy_from_slice(&old);
        }
        let digest = domain_hash(
            DOMAIN_LOCK_EVIDENCE,
            &[
                anchor_revision,
                &current,
                &retired_bytes,
                &booted_at_ms.to_be_bytes(),
                &nonce,
            ],
        );
        if digest != [0; 32] {
            return Ok(digest);
        }
    }
    Err(JournalError::Io)
}

fn encode_runtime_marker(
    current: [u8; 16],
    retired: Option<[u8; 16]>,
    evidence: [u8; 32],
    booted_at_ms: u64,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(if retired.is_some() { 73 } else { 57 });
    out.extend_from_slice(&current);
    match retired {
        None => out.push(0),
        Some(old) => {
            out.push(1);
            out.extend_from_slice(&old);
        }
    }
    out.extend_from_slice(&evidence);
    out.extend_from_slice(&booted_at_ms.to_be_bytes());
    out
}

fn runtime_marker_digest(value: &[u8]) -> Result<[u8; 32], JournalError> {
    let key = RowKey {
        tag: 0x05,
        key: Vec::new(),
    };
    validate_row(RECOVERY_SEGMENT, &key, value)?;
    let row = encode_row(&key, value)?;
    Ok(domain_hash(DOMAIN_RUNTIME_MARKER, &[&row]))
}

fn reject_unpublished_runtime_rows(
    state: &LogicalState,
    unpublished: [u8; 16],
) -> Result<(), JournalError> {
    for (key, value) in &state.recovery {
        match parse_recovery_row(key, value)? {
            ParsedRecoveryRow::Active(view) if view.runtime == unpublished => {
                return Err(JournalError::Corrupt)
            }
            ParsedRecoveryRow::Close(view) if view.open && view.runtime == unpublished => {
                return Err(JournalError::Corrupt)
            }
            _ => {}
        }
    }
    Ok(())
}

fn encode_runtime_retired_source(
    active: &ActiveSourceView,
    progress_key: [u8; 32],
    marker_digest: [u8; 32],
    quiesced_at_ms: u64,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(161);
    out.extend_from_slice(&active.runtime);
    out.extend_from_slice(&active.expected_agent);
    out.extend_from_slice(&active.generation.to_be_bytes());
    out.extend_from_slice(&progress_key);
    out.extend_from_slice(&[0; 16]);
    out.push(0x02);
    out.extend_from_slice(&marker_digest);
    out.extend_from_slice(&marker_digest);
    out.extend_from_slice(&quiesced_at_ms.to_be_bytes());
    out
}

fn retire_open_close(
    before: &[u8],
    expected_source: [u8; 32],
    expected_agent: [u8; 32],
    expected_runtime: [u8; 16],
    marker_digest: [u8; 32],
    sealed_at_ms: u64,
) -> Result<Vec<u8>, JournalError> {
    let mut c = Cursor::new(before);
    let source = c.b32()?;
    let agent = c.b32()?;
    let runtime = c.b16()?;
    let lifecycle_generation = c.u64()?;
    let route_generation = c.u64()?;
    let armed_at_ms = c.u64()?;
    if source != expected_source
        || agent != expected_agent
        || runtime != expected_runtime
        || lifecycle_generation == 0
        || route_generation == 0
        || c.u8()? != 0x00
    {
        return Err(JournalError::Corrupt);
    }
    let refs_start = c.position;
    let action = parse_ref_set(&mut c)?;
    let retry = parse_ref_set(&mut c)?;
    let replay = parse_ref_set(&mut c)?;
    let refs_end = c.position;
    c.finish()?;
    let total = action
        .len()
        .checked_add(retry.len())
        .and_then(|n| n.checked_add(replay.len()))
        .ok_or(JournalError::Capacity)?;
    if total > MAX_ROUTE_REFS {
        return Err(JournalError::Capacity);
    }
    let retired_digest = domain_hash(DOMAIN_RETIRED_REFS, &[&before[refs_start..refs_end]]);
    let next_lifecycle = lifecycle_generation
        .checked_add(1)
        .ok_or(JournalError::SequenceExhausted)?;
    let next_route = route_generation
        .checked_add(1)
        .ok_or(JournalError::SequenceExhausted)?;
    let action_count = u32::try_from(action.len()).map_err(|_| JournalError::Capacity)?;
    let retry_count = u32::try_from(retry.len()).map_err(|_| JournalError::Capacity)?;
    let replay_count = u32::try_from(replay.len()).map_err(|_| JournalError::Capacity)?;
    let mut out = Vec::with_capacity(206);
    out.extend_from_slice(&source);
    out.extend_from_slice(&agent);
    out.extend_from_slice(&runtime);
    out.extend_from_slice(&next_lifecycle.to_be_bytes());
    out.extend_from_slice(&next_route.to_be_bytes());
    out.extend_from_slice(&armed_at_ms.to_be_bytes());
    out.push(0x01); // SealedRoutes
    out.push(0x01); // RuntimeRetired
    out.push(0x01); // Some(RetiredRefs)
    out.extend_from_slice(&action_count.to_be_bytes());
    out.extend_from_slice(&retry_count.to_be_bytes());
    out.extend_from_slice(&replay_count.to_be_bytes());
    out.extend_from_slice(&retired_digest);
    out.extend_from_slice(&marker_digest);
    out.extend_from_slice(&sealed_at_ms.to_be_bytes());
    Ok(out)
}

fn retire_already_sealed_close(
    before: &[u8],
    expected_source: [u8; 32],
    expected_agent: [u8; 32],
    expected_runtime: [u8; 16],
    marker_digest: [u8; 32],
    sealed_at_ms: u64,
) -> Result<Vec<u8>, JournalError> {
    let mut details = decode_close_details(before)?;
    if details.source != expected_source
        || details.expected_agent != expected_agent
        || details.runtime != expected_runtime
        || details.sealed.is_none()
    {
        return Err(JournalError::Corrupt);
    }
    details.lifecycle_generation = details
        .lifecycle_generation
        .checked_add(1)
        .ok_or(JournalError::SequenceExhausted)?;
    details.action.clear();
    details.retry.clear();
    details.replay.clear();
    details.sealed = Some(SealedCloseDetails {
        runtime_retired: true,
        retired_action: 0,
        retired_retry: 0,
        retired_replay: 0,
        retired_digest: Some(domain_hash(DOMAIN_RETIRED_REFS, &[&[0u8; 12]])),
        evidence_digest: marker_digest,
        sealed_at_ms,
    });
    encode_close_details(&details)
}

fn cancel_live_authorities_for_key(
    state: &LogicalState,
    progress_key: [u8; 32],
    retired_at_ms: u64,
) -> Result<Vec<Operation>, JournalError> {
    let mut operations = Vec::new();
    for (key, before) in state
        .protected
        .iter()
        .filter(|(key, value)| (0x10..=0x15).contains(&key.tag) && value.first() == Some(&0))
    {
        let bound = match key.tag {
            0x10 | 0x11 | 0x13 => key.key.get(..32) == Some(progress_key.as_slice()),
            0x12 | 0x14 | 0x15 => before.get(17..49) == Some(progress_key.as_slice()),
            _ => false,
        };
        if !bound {
            continue;
        }
        if before.len() < 57 || before.last() != Some(&0) {
            return Err(JournalError::Corrupt);
        }
        let tail = before.len() - 57;
        let issued_at_ms = u64::from_be_bytes(
            before[tail..tail + 8]
                .try_into()
                .map_err(|_| JournalError::Corrupt)?,
        );
        let retain_until_ms = u64::from_be_bytes(
            before[tail + 16..tail + 24]
                .try_into()
                .map_err(|_| JournalError::Corrupt)?,
        );
        if issued_at_ms > retain_until_ms {
            return Err(JournalError::Corrupt);
        }
        let cancelled_at_ms = retired_at_ms.clamp(issued_at_ms, retain_until_ms);
        let mut after = before[..before.len() - 1].to_vec();
        after[0] = 0x01;
        after.push(1);
        after.extend_from_slice(&cancelled_at_ms.to_be_bytes());
        validate_protected_row(key, &after)?;
        operations.push(Operation::replace(
            PROTECTED_SEGMENT,
            key.tag,
            key.key.clone(),
            before.clone(),
            after,
        ));
    }
    Ok(operations)
}

fn published_runtime(core: &JournalCore) -> Result<[u8; 16], JournalError> {
    let key = RowKey {
        tag: 0x05,
        key: Vec::new(),
    };
    let value = core.state.recovery.get(&key).ok_or(JournalError::Corrupt)?;
    let ParsedRecoveryRow::Marker(marker) = parse_recovery_row(&key, value)? else {
        return Err(JournalError::Corrupt);
    };
    if marker.retired.is_some() {
        return Err(JournalError::Unhealthy);
    }
    Ok(marker.current)
}

fn decode_turn_quiesced_record(
    key: &RowKey,
    value: &[u8],
) -> Result<TurnQuiescedSourceRecord, JournalError> {
    let ParsedRecoveryRow::Quiesced(_) = parse_recovery_row(key, value)? else {
        return Err(JournalError::Corrupt);
    };
    let source_digest: [u8; 32] = key
        .key
        .as_slice()
        .try_into()
        .map_err(|_| JournalError::Corrupt)?;
    let mut c = Cursor::new(value);
    let origin_runtime = c.b16()?;
    let expected_agent_digest = c.b32()?;
    let generation = c.u64()?;
    let progress_key_digest = c.b32()?;
    let store_incarnation = c.b16()?;
    match c.u8()? {
        0x00 => {
            c.u64()?;
        }
        0x01 => {
            c.b16()?;
        }
        0x02 => {
            c.b32()?;
        }
        _ => return Err(JournalError::Corrupt),
    }
    let evidence_digest = c.b32()?;
    let committed_at_ms = c.u64()?;
    c.finish()?;
    Ok(TurnQuiescedSourceRecord {
        origin_runtime,
        source_digest,
        expected_agent_digest,
        generation,
        progress_key_digest,
        store_incarnation,
        evidence_digest,
        committed_at_ms,
    })
}

fn sort_operations(operations: &mut [Operation]) {
    operations.sort_by(|left, right| {
        (left.segment, left.key.tag, left.key.key.as_slice()).cmp(&(
            right.segment,
            right.key.tag,
            right.key.key.as_slice(),
        ))
    });
}

fn encode_attempt_kind(kind: &ProgressAttemptKind, out: &mut Vec<u8>) -> Result<(), JournalError> {
    match kind {
        ProgressAttemptKind::InitialSend => out.push(0x00),
        ProgressAttemptKind::Edit(id) if *id > 0 => {
            out.push(0x01);
            out.extend_from_slice(&id.to_be_bytes());
        }
        ProgressAttemptKind::FallbackSend(id) if *id > 0 => {
            out.push(0x02);
            out.extend_from_slice(&id.to_be_bytes());
        }
        _ => return Err(JournalError::Corrupt),
    }
    Ok(())
}

fn decode_attempt_kind(c: &mut Cursor<'_>) -> Result<ProgressAttemptKind, JournalError> {
    match c.u8()? {
        0x00 => Ok(ProgressAttemptKind::InitialSend),
        0x01 => {
            let id = c.i64()?;
            if id <= 0 {
                return Err(JournalError::Corrupt);
            }
            Ok(ProgressAttemptKind::Edit(id))
        }
        0x02 => {
            let id = c.i64()?;
            if id <= 0 {
                return Err(JournalError::Corrupt);
            }
            Ok(ProgressAttemptKind::FallbackSend(id))
        }
        _ => Err(JournalError::Corrupt),
    }
}

fn encode_progress_card(row: &ProgressProtectedCardRow) -> Result<(u8, Vec<u8>), JournalError> {
    let (tag, value) = match row {
        ProgressProtectedCardRow::TerminalTombstone {
            generation,
            terminal_fingerprint,
            delivered_at_ms,
        } if *generation != 0 => {
            let mut value = Vec::with_capacity(48);
            value.extend_from_slice(&generation.to_be_bytes());
            value.extend_from_slice(terminal_fingerprint);
            value.extend_from_slice(&delivered_at_ms.to_be_bytes());
            (0x01, value)
        }
        ProgressProtectedCardRow::IndeterminateSend {
            generation,
            attempt_id,
            delivery_fingerprint,
            phase,
            attempt_kind,
            first_attempted_at_ms,
        } if *generation != 0 && *attempt_id != [0; 16] && *phase <= 0x03 => {
            let mut value = Vec::with_capacity(74);
            value.extend_from_slice(&generation.to_be_bytes());
            value.extend_from_slice(attempt_id);
            value.extend_from_slice(delivery_fingerprint);
            value.push(*phase);
            encode_attempt_kind(attempt_kind, &mut value)?;
            value.extend_from_slice(&first_attempted_at_ms.to_be_bytes());
            (0x02, value)
        }
        ProgressProtectedCardRow::FallbackExhausted {
            generation,
            delivery_fingerprint,
            definitively_lost_message_id,
            reconciled_at_ms,
        } if *generation != 0 && *definitively_lost_message_id > 0 => {
            let mut value = Vec::with_capacity(56);
            value.extend_from_slice(&generation.to_be_bytes());
            value.extend_from_slice(delivery_fingerprint);
            value.extend_from_slice(&definitively_lost_message_id.to_be_bytes());
            value.extend_from_slice(&reconciled_at_ms.to_be_bytes());
            (0x03, value)
        }
        _ => return Err(JournalError::Corrupt),
    };
    let key = RowKey {
        tag,
        key: vec![0; 32],
    };
    validate_protected_row(&key, &value)?;
    Ok((tag, value))
}

fn decode_progress_card(
    key: &RowKey,
    value: &[u8],
) -> Result<ProgressProtectedCardRow, JournalError> {
    validate_protected_row(key, value)?;
    let mut c = Cursor::new(value);
    let row = match key.tag {
        0x01 => ProgressProtectedCardRow::TerminalTombstone {
            generation: c.u64()?,
            terminal_fingerprint: c.b32()?,
            delivered_at_ms: c.u64()?,
        },
        0x02 => ProgressProtectedCardRow::IndeterminateSend {
            generation: c.u64()?,
            attempt_id: c.b16()?,
            delivery_fingerprint: c.b32()?,
            phase: c.u8()?,
            attempt_kind: decode_attempt_kind(&mut c)?,
            first_attempted_at_ms: c.u64()?,
        },
        0x03 => ProgressProtectedCardRow::FallbackExhausted {
            generation: c.u64()?,
            delivery_fingerprint: c.b32()?,
            definitively_lost_message_id: c.i64()?,
            reconciled_at_ms: c.u64()?,
        },
        _ => return Err(JournalError::Corrupt),
    };
    c.finish()?;
    Ok(row)
}

fn find_progress_card(
    state: &LogicalState,
    key_digest: [u8; 32],
) -> Result<Option<(u8, ProgressProtectedCardRow, Vec<u8>)>, JournalError> {
    let mut found = None;
    for tag in 0x01..=0x03 {
        let key = RowKey {
            tag,
            key: key_digest.to_vec(),
        };
        if let Some(value) = state.protected.get(&key) {
            if found.is_some() {
                return Err(JournalError::Corrupt);
            }
            found = Some((tag, decode_progress_card(&key, value)?, value.clone()));
        }
    }
    Ok(found)
}

fn card_transition_operations(
    state: &LogicalState,
    key_digest: [u8; 32],
    expected: Option<ProgressProtectedCardRow>,
    next: Option<ProgressProtectedCardRow>,
) -> Result<Vec<Operation>, JournalError> {
    let observed = find_progress_card(state, key_digest)?;
    if observed.as_ref().map(|(_, row, _)| row) != expected.as_ref() {
        return Err(JournalError::AnchorConflict);
    }
    if expected == next {
        return Ok(Vec::new());
    }
    match (observed, next) {
        (None, None) => Ok(Vec::new()),
        (None, Some(row)) => {
            let (tag, value) = encode_progress_card(&row)?;
            Ok(vec![Operation::insert(
                PROTECTED_SEGMENT,
                tag,
                key_digest.to_vec(),
                value,
            )])
        }
        (Some((tag, _, before)), None) => Ok(vec![Operation::delete(
            PROTECTED_SEGMENT,
            tag,
            key_digest.to_vec(),
            before,
        )]),
        (Some((before_tag, _, before)), Some(row)) => {
            let (after_tag, after) = encode_progress_card(&row)?;
            if before_tag == after_tag {
                Ok(vec![Operation::replace(
                    PROTECTED_SEGMENT,
                    before_tag,
                    key_digest.to_vec(),
                    before,
                    after,
                )])
            } else {
                Ok(vec![
                    Operation::delete(PROTECTED_SEGMENT, before_tag, key_digest.to_vec(), before),
                    Operation::insert(PROTECTED_SEGMENT, after_tag, key_digest.to_vec(), after),
                ])
            }
        }
    }
}

fn encode_active_source(
    runtime: [u8; 16],
    expected_agent: [u8; 32],
    generation: u64,
    progress_key: Option<[u8; 32]>,
    created_at_ms: u64,
) -> Vec<u8> {
    let mut value = Vec::with_capacity(if progress_key.is_some() { 97 } else { 65 });
    value.extend_from_slice(&runtime);
    value.extend_from_slice(&expected_agent);
    value.extend_from_slice(&generation.to_be_bytes());
    match progress_key {
        None => value.push(0),
        Some(key) => {
            value.push(1);
            value.extend_from_slice(&key);
        }
    }
    value.extend_from_slice(&created_at_ms.to_be_bytes());
    value
}

fn decode_active_created_at(value: &[u8]) -> Result<u64, JournalError> {
    let mut c = Cursor::new(value);
    c.b16()?;
    c.b32()?;
    c.u64()?;
    parse_option_b32(&mut c)?;
    let created = c.u64()?;
    c.finish()?;
    Ok(created)
}

#[derive(Clone)]
struct SealedCloseDetails {
    runtime_retired: bool,
    retired_action: u32,
    retired_retry: u32,
    retired_replay: u32,
    retired_digest: Option<[u8; 32]>,
    evidence_digest: [u8; 32],
    sealed_at_ms: u64,
}

#[derive(Clone)]
struct CloseDetails {
    source: [u8; 32],
    expected_agent: [u8; 32],
    runtime: [u8; 16],
    lifecycle_generation: u64,
    route_seal_generation: u64,
    armed_at_ms: u64,
    action: Vec<[u8; 16]>,
    retry: Vec<[u8; 16]>,
    replay: Vec<[u8; 16]>,
    sealed: Option<SealedCloseDetails>,
}

fn decode_close_details(value: &[u8]) -> Result<CloseDetails, JournalError> {
    let mut c = Cursor::new(value);
    let source = c.b32()?;
    let expected_agent = c.b32()?;
    let runtime = c.b16()?;
    nonzero(&runtime)?;
    let lifecycle_generation = c.u64()?;
    let route_seal_generation = c.u64()?;
    if lifecycle_generation == 0 || route_seal_generation == 0 {
        return Err(JournalError::Corrupt);
    }
    let armed_at_ms = c.u64()?;
    let (action, retry, replay, sealed) = match c.u8()? {
        0x00 => (
            parse_ref_set(&mut c)?,
            parse_ref_set(&mut c)?,
            parse_ref_set(&mut c)?,
            None,
        ),
        0x01 => {
            let reason = c.u8()?;
            let (retired_action, retired_retry, retired_replay, retired_digest) = match c.u8()? {
                0 if reason == 0 => (0, 0, 0, None),
                1 if reason == 1 => (c.u32()?, c.u32()?, c.u32()?, Some(c.b32()?)),
                _ => return Err(JournalError::Corrupt),
            };
            let total = (retired_action as usize)
                .checked_add(retired_retry as usize)
                .and_then(|n| n.checked_add(retired_replay as usize))
                .ok_or(JournalError::Capacity)?;
            if total > MAX_ROUTE_REFS {
                return Err(JournalError::Capacity);
            }
            let evidence_digest = c.b32()?;
            let sealed_at_ms = c.u64()?;
            (
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Some(SealedCloseDetails {
                    runtime_retired: reason == 1,
                    retired_action,
                    retired_retry,
                    retired_replay,
                    retired_digest,
                    evidence_digest,
                    sealed_at_ms,
                }),
            )
        }
        _ => return Err(JournalError::Corrupt),
    };
    c.finish()?;
    let total = action
        .len()
        .checked_add(retry.len())
        .and_then(|n| n.checked_add(replay.len()))
        .ok_or(JournalError::Capacity)?;
    if total > MAX_ROUTE_REFS {
        return Err(JournalError::Capacity);
    }
    Ok(CloseDetails {
        source,
        expected_agent,
        runtime,
        lifecycle_generation,
        route_seal_generation,
        armed_at_ms,
        action,
        retry,
        replay,
        sealed,
    })
}

fn encode_ref_set(values: &[[u8; 16]], out: &mut Vec<u8>) -> Result<(), JournalError> {
    if values.len() > MAX_ROUTE_REFS {
        return Err(JournalError::Capacity);
    }
    out.extend_from_slice(
        &u32::try_from(values.len())
            .map_err(|_| JournalError::Capacity)?
            .to_be_bytes(),
    );
    let mut previous = None;
    for value in values {
        nonzero(value)?;
        if previous.is_some_and(|prior| prior >= *value) {
            return Err(JournalError::Corrupt);
        }
        previous = Some(*value);
        out.extend_from_slice(value);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn encode_open_close(
    source: [u8; 32],
    expected_agent: [u8; 32],
    runtime: [u8; 16],
    lifecycle_generation: u64,
    route_seal_generation: u64,
    armed_at_ms: u64,
    action: &[[u8; 16]],
    retry: &[[u8; 16]],
    replay: &[[u8; 16]],
) -> Result<Vec<u8>, JournalError> {
    encode_close_details(&CloseDetails {
        source,
        expected_agent,
        runtime,
        lifecycle_generation,
        route_seal_generation,
        armed_at_ms,
        action: action.to_vec(),
        retry: retry.to_vec(),
        replay: replay.to_vec(),
        sealed: None,
    })
}

fn encode_close_details(details: &CloseDetails) -> Result<Vec<u8>, JournalError> {
    let mut out = Vec::new();
    out.extend_from_slice(&details.source);
    out.extend_from_slice(&details.expected_agent);
    out.extend_from_slice(&details.runtime);
    out.extend_from_slice(&details.lifecycle_generation.to_be_bytes());
    out.extend_from_slice(&details.route_seal_generation.to_be_bytes());
    out.extend_from_slice(&details.armed_at_ms.to_be_bytes());
    match &details.sealed {
        None => {
            out.push(0x00);
            encode_ref_set(&details.action, &mut out)?;
            encode_ref_set(&details.retry, &mut out)?;
            encode_ref_set(&details.replay, &mut out)?;
            let mut all = BTreeSet::new();
            for value in details
                .action
                .iter()
                .chain(&details.retry)
                .chain(&details.replay)
            {
                if !all.insert(*value) {
                    return Err(JournalError::Corrupt);
                }
            }
            if all.len() > MAX_ROUTE_REFS {
                return Err(JournalError::Capacity);
            }
        }
        Some(sealed) => {
            if !details.action.is_empty() || !details.retry.is_empty() || !details.replay.is_empty()
            {
                return Err(JournalError::Corrupt);
            }
            out.push(0x01);
            out.push(u8::from(sealed.runtime_retired));
            if sealed.runtime_retired {
                let digest = sealed.retired_digest.ok_or(JournalError::Corrupt)?;
                out.push(1);
                out.extend_from_slice(&sealed.retired_action.to_be_bytes());
                out.extend_from_slice(&sealed.retired_retry.to_be_bytes());
                out.extend_from_slice(&sealed.retired_replay.to_be_bytes());
                out.extend_from_slice(&digest);
            } else {
                if sealed.retired_digest.is_some()
                    || sealed.retired_action != 0
                    || sealed.retired_retry != 0
                    || sealed.retired_replay != 0
                {
                    return Err(JournalError::Corrupt);
                }
                out.push(0);
            }
            out.extend_from_slice(&sealed.evidence_digest);
            out.extend_from_slice(&sealed.sealed_at_ms.to_be_bytes());
        }
    }
    let key = RowKey {
        tag: 0x03,
        key: vec![0; 32],
    };
    parse_recovery_row(&key, &out)?;
    Ok(out)
}

fn route_set_mut(details: &mut CloseDetails, kind: ProgressRouteRefKind) -> &mut Vec<[u8; 16]> {
    match kind {
        ProgressRouteRefKind::Action => &mut details.action,
        ProgressRouteRefKind::Retry => &mut details.retry,
        ProgressRouteRefKind::Replay => &mut details.replay,
    }
}

fn generate_unique_route_ref<R: RngCore + CryptoRng>(
    details: &CloseDetails,
    rng: &mut R,
) -> Result<[u8; 16], JournalError> {
    for _ in 0..8 {
        let candidate = random_nonzero_b16(rng)?;
        if !details
            .action
            .iter()
            .chain(&details.retry)
            .chain(&details.replay)
            .any(|value| *value == candidate)
        {
            return Ok(candidate);
        }
    }
    Err(JournalError::Io)
}

fn binding_for_open(
    state: &LogicalState,
    key_digest: [u8; 32],
    source_digest: [u8; 32],
    details: &CloseDetails,
) -> Result<ProgressRouteBindingRecord, JournalError> {
    if details.source != source_digest || details.sealed.is_some() {
        return Err(JournalError::AnchorConflict);
    }
    let source_key = RowKey {
        tag: 0x01,
        key: source_digest.to_vec(),
    };
    let source_value = state
        .recovery
        .get(&source_key)
        .ok_or(JournalError::AnchorConflict)?;
    let ParsedRecoveryRow::Active(source) = parse_recovery_row(&source_key, source_value)? else {
        return Err(JournalError::Corrupt);
    };
    if source.progress_key != Some(key_digest)
        || source.expected_agent != details.expected_agent
        || source.runtime != details.runtime
    {
        return Err(JournalError::Corrupt);
    }
    Ok(ProgressRouteBindingRecord {
        key_digest,
        source_digest,
        expected_agent_digest: details.expected_agent,
        origin_runtime: details.runtime,
        turn_generation: source.generation,
        lifecycle_generation: details.lifecycle_generation,
        route_seal_generation: details.route_seal_generation,
        armed_at_ms: details.armed_at_ms,
        action_refs: u32::try_from(details.action.len()).map_err(|_| JournalError::Capacity)?,
        retry_refs: u32::try_from(details.retry.len()).map_err(|_| JournalError::Capacity)?,
        replay_refs: u32::try_from(details.replay.len()).map_err(|_| JournalError::Capacity)?,
    })
}

fn sealed_record_from_details(
    state: &LogicalState,
    key_digest: [u8; 32],
    source_digest: [u8; 32],
    source_receipt_digest: [u8; 32],
    details: &CloseDetails,
) -> Result<ProgressSealedRouteRecord, JournalError> {
    if details.source != source_digest {
        return Err(JournalError::AnchorConflict);
    }
    let sealed = details
        .sealed
        .as_ref()
        .ok_or(JournalError::AnchorConflict)?;
    if !sealed.runtime_retired && sealed.evidence_digest != source_receipt_digest {
        return Err(JournalError::AnchorConflict);
    }
    let source_key = RowKey {
        tag: 0x02,
        key: source_digest.to_vec(),
    };
    let source_value = state
        .recovery
        .get(&source_key)
        .ok_or(JournalError::AnchorConflict)?;
    let ParsedRecoveryRow::Quiesced(source) = parse_recovery_row(&source_key, source_value)? else {
        return Err(JournalError::Corrupt);
    };
    if source.progress_key != key_digest
        || source.expected_agent != details.expected_agent
        || source.runtime != details.runtime
        || (sealed.runtime_retired && !source.runtime_retired)
    {
        return Err(JournalError::Corrupt);
    }
    Ok(ProgressSealedRouteRecord {
        binding: ProgressRouteBindingRecord {
            key_digest,
            source_digest,
            expected_agent_digest: details.expected_agent,
            origin_runtime: details.runtime,
            turn_generation: source.generation,
            lifecycle_generation: details.lifecycle_generation,
            route_seal_generation: details.route_seal_generation,
            armed_at_ms: details.armed_at_ms,
            action_refs: 0,
            retry_refs: 0,
            replay_refs: 0,
        },
        runtime_retired: sealed.runtime_retired,
        retired_action_refs: sealed.retired_action,
        retired_retry_refs: sealed.retired_retry,
        retired_replay_refs: sealed.retired_replay,
        retired_ref_digest: sealed.retired_digest,
        seal_evidence_digest: sealed.evidence_digest,
        source_receipt_digest,
        sealed_at_ms: sealed.sealed_at_ms,
    })
}

fn close_snapshot(
    core: &JournalCore,
    key_digest: [u8; 32],
    live: Option<ProgressLiveSnapshot>,
) -> Result<ProgressCloseSnapshot, JournalError> {
    let close_key = RowKey {
        tag: 0x03,
        key: key_digest.to_vec(),
    };
    let close_value = core
        .state
        .recovery
        .get(&close_key)
        .ok_or(JournalError::AnchorConflict)?;
    let close = decode_close_details(close_value)?;
    let complete_close_row = encode_row(&close_key, close_value)?;
    let durable = find_progress_card(&core.state, key_digest)?;
    let (target_kind, snapshot) = match (live, durable) {
        (Some(_), Some(_)) => return Err(JournalError::Corrupt),
        (
            Some(ProgressLiveSnapshot {
                generation,
                telegram_message_id,
            }),
            None,
        ) if generation != 0 && telegram_message_id > 0 => {
            let runtime = published_runtime(core)?;
            let mut bytes = Vec::with_capacity(32);
            bytes.extend_from_slice(&runtime);
            bytes.extend_from_slice(&generation.to_be_bytes());
            bytes.extend_from_slice(&telegram_message_id.to_be_bytes());
            (ProgressCloseTargetKind::Live, bytes)
        }
        (Some(_), None) => return Err(JournalError::Corrupt),
        (None, None) => (ProgressCloseTargetKind::NoCard, Vec::new()),
        (None, Some((tag, _, value))) => {
            let row_key = RowKey {
                tag,
                key: key_digest.to_vec(),
            };
            let kind = match tag {
                0x01 => ProgressCloseTargetKind::TerminalTombstone,
                0x02 => ProgressCloseTargetKind::IndeterminateSend,
                0x03 => ProgressCloseTargetKind::FallbackExhausted,
                _ => return Err(JournalError::Corrupt),
            };
            (kind, encode_row(&row_key, &value)?)
        }
    };
    let close_len = u32::try_from(complete_close_row.len()).map_err(|_| JournalError::Capacity)?;
    let snapshot_len = u32::try_from(snapshot.len()).map_err(|_| JournalError::Capacity)?;
    let target_fingerprint = domain_hash(
        DOMAIN_CLOSE_TARGET,
        &[
            &close_len.to_be_bytes(),
            &complete_close_row,
            &[target_kind as u8],
            &snapshot_len.to_be_bytes(),
            &snapshot,
        ],
    );
    Ok(ProgressCloseSnapshot {
        key_digest,
        source_digest: close.source,
        lifecycle_generation: close.lifecycle_generation,
        target_kind,
        target_fingerprint,
    })
}

fn validate_close_snapshot_for_commit(
    core: &JournalCore,
    expected: &ProgressCloseSnapshot,
) -> Result<(), JournalError> {
    match expected.target_kind {
        ProgressCloseTargetKind::Live => {
            if find_progress_card(&core.state, expected.key_digest)?.is_some()
                || expected.target_fingerprint == [0; 32]
            {
                return Err(JournalError::AnchorConflict);
            }
            let close_key = RowKey {
                tag: 0x03,
                key: expected.key_digest.to_vec(),
            };
            let close = decode_close_details(
                core.state
                    .recovery
                    .get(&close_key)
                    .ok_or(JournalError::AnchorConflict)?,
            )?;
            if close.source != expected.source_digest
                || close.lifecycle_generation != expected.lifecycle_generation
            {
                return Err(JournalError::AnchorConflict);
            }
        }
        _ => {
            let observed = close_snapshot(core, expected.key_digest, None)?;
            if &observed != expected {
                return Err(JournalError::AnchorConflict);
            }
        }
    }
    Ok(())
}

fn authority_envelope(row: &ProgressAuthorityRow) -> &ProgressAuthorityEnvelope {
    match row {
        ProgressAuthorityRow::RouteSealReceipt { envelope, .. }
        | ProgressAuthorityRow::SourceCloseChallenge { envelope, .. }
        | ProgressAuthorityRow::SourceCloseAttestation { envelope, .. }
        | ProgressAuthorityRow::AttemptReconciliationChallenge { envelope, .. }
        | ProgressAuthorityRow::TrustedAttemptOutcomeReceipt { envelope, .. }
        | ProgressAuthorityRow::AttemptReconciliationProof { envelope, .. } => envelope,
    }
}

fn authority_envelope_mut(row: &mut ProgressAuthorityRow) -> &mut ProgressAuthorityEnvelope {
    match row {
        ProgressAuthorityRow::RouteSealReceipt { envelope, .. }
        | ProgressAuthorityRow::SourceCloseChallenge { envelope, .. }
        | ProgressAuthorityRow::SourceCloseAttestation { envelope, .. }
        | ProgressAuthorityRow::AttemptReconciliationChallenge { envelope, .. }
        | ProgressAuthorityRow::TrustedAttemptOutcomeReceipt { envelope, .. }
        | ProgressAuthorityRow::AttemptReconciliationProof { envelope, .. } => envelope,
    }
}

fn authority_row_tag(row: &ProgressAuthorityRow) -> u8 {
    match row {
        ProgressAuthorityRow::RouteSealReceipt { .. } => 0x10,
        ProgressAuthorityRow::SourceCloseChallenge { .. } => 0x11,
        ProgressAuthorityRow::SourceCloseAttestation { .. } => 0x12,
        ProgressAuthorityRow::AttemptReconciliationChallenge { .. } => 0x13,
        ProgressAuthorityRow::TrustedAttemptOutcomeReceipt { .. } => 0x14,
        ProgressAuthorityRow::AttemptReconciliationProof { .. } => 0x15,
    }
}

fn encode_authority_prefix(
    envelope: &ProgressAuthorityEnvelope,
    out: &mut Vec<u8>,
) -> Result<(), JournalError> {
    let state = match envelope.state {
        ProgressAuthorityState::Live => 0x00,
        ProgressAuthorityState::Cancelled { .. } => 0x01,
        ProgressAuthorityState::Consumed { .. } => 0x02,
    };
    nonzero(&envelope.authority_id)?;
    out.push(state);
    out.extend_from_slice(&envelope.authority_id);
    Ok(())
}

fn encode_authority_tail(
    envelope: &ProgressAuthorityEnvelope,
    out: &mut Vec<u8>,
) -> Result<(), JournalError> {
    if envelope.issued_ms > envelope.expires_ms
        || envelope.expires_ms > envelope.retain_until_ms
        || envelope.mac == [0; 32]
    {
        return Err(JournalError::Corrupt);
    }
    out.extend_from_slice(&envelope.issued_ms.to_be_bytes());
    out.extend_from_slice(&envelope.expires_ms.to_be_bytes());
    out.extend_from_slice(&envelope.retain_until_ms.to_be_bytes());
    out.extend_from_slice(&envelope.mac);
    match envelope.state {
        ProgressAuthorityState::Live => out.push(0),
        ProgressAuthorityState::Cancelled { at_ms }
        | ProgressAuthorityState::Consumed { at_ms }
            if at_ms >= envelope.issued_ms && at_ms <= envelope.retain_until_ms =>
        {
            out.push(1);
            out.extend_from_slice(&at_ms.to_be_bytes());
        }
        _ => return Err(JournalError::Corrupt),
    }
    Ok(())
}

fn authority_key(primary: [u8; 32], nonce: [u8; 16], tag: u8) -> Result<RowKey, JournalError> {
    nonzero(&nonce)?;
    let mut key = Vec::with_capacity(48);
    key.extend_from_slice(&primary);
    key.extend_from_slice(&nonce);
    Ok(RowKey { tag, key })
}

fn encode_authority_row(row: &ProgressAuthorityRow) -> Result<(RowKey, Vec<u8>), JournalError> {
    let tag = authority_row_tag(row);
    let envelope = authority_envelope(row);
    let (key, mut value) = match row {
        ProgressAuthorityRow::RouteSealReceipt {
            key_digest,
            nonce,
            source_digest,
            source_quiesced_receipt_digest,
            route_seal_generation,
            action_refs,
            retry_refs,
            replay_refs,
            ..
        } => {
            if *route_seal_generation == 0 {
                return Err(JournalError::Corrupt);
            }
            let mut value = Vec::new();
            encode_authority_prefix(envelope, &mut value)?;
            value.extend_from_slice(source_digest);
            value.extend_from_slice(source_quiesced_receipt_digest);
            value.extend_from_slice(&route_seal_generation.to_be_bytes());
            value.extend_from_slice(&action_refs.to_be_bytes());
            value.extend_from_slice(&retry_refs.to_be_bytes());
            value.extend_from_slice(&replay_refs.to_be_bytes());
            (authority_key(*key_digest, *nonce, tag)?, value)
        }
        ProgressAuthorityRow::SourceCloseChallenge {
            key_digest,
            nonce,
            source_digest,
            record_generation,
            record_kind,
            record_fingerprint,
            ..
        } => {
            if *record_generation == 0 {
                return Err(JournalError::Corrupt);
            }
            let mut value = Vec::new();
            encode_authority_prefix(envelope, &mut value)?;
            value.extend_from_slice(source_digest);
            value.extend_from_slice(&record_generation.to_be_bytes());
            value.push(*record_kind as u8);
            value.extend_from_slice(record_fingerprint);
            (authority_key(*key_digest, *nonce, tag)?, value)
        }
        ProgressAuthorityRow::SourceCloseAttestation {
            challenge_digest,
            nonce,
            key_digest,
            source_digest,
            source_receipt_digest,
            route_receipt_digest,
            ..
        } => {
            let mut value = Vec::new();
            encode_authority_prefix(envelope, &mut value)?;
            value.extend_from_slice(key_digest);
            value.extend_from_slice(source_digest);
            value.extend_from_slice(source_receipt_digest);
            value.extend_from_slice(route_receipt_digest);
            (authority_key(*challenge_digest, *nonce, tag)?, value)
        }
        ProgressAuthorityRow::AttemptReconciliationChallenge {
            key_digest,
            nonce,
            record_generation,
            attempt_id,
            attempt_kind,
            delivery_fingerprint,
            phase,
            ..
        } => {
            if *record_generation == 0 || *attempt_id == [0; 16] || *phase > 0x03 {
                return Err(JournalError::Corrupt);
            }
            let mut value = Vec::new();
            encode_authority_prefix(envelope, &mut value)?;
            value.extend_from_slice(&record_generation.to_be_bytes());
            value.extend_from_slice(attempt_id);
            encode_attempt_kind(attempt_kind, &mut value)?;
            value.extend_from_slice(delivery_fingerprint);
            value.push(*phase);
            (authority_key(*key_digest, *nonce, tag)?, value)
        }
        ProgressAuthorityRow::TrustedAttemptOutcomeReceipt {
            challenge_digest,
            nonce,
            key_digest,
            record_generation,
            attempt_id,
            attempt_kind,
            delivery_fingerprint,
            delivered_message_id,
            evidence_source,
            evidence_id,
            evidence_digest,
            ..
        }
        | ProgressAuthorityRow::AttemptReconciliationProof {
            challenge_digest,
            nonce,
            key_digest,
            record_generation,
            attempt_id,
            attempt_kind,
            delivery_fingerprint,
            delivered_message_id,
            evidence_source,
            evidence_id,
            evidence_digest,
            ..
        } => {
            if *record_generation == 0
                || *attempt_id == [0; 16]
                || *evidence_id == [0; 16]
                || *evidence_source > 1
            {
                return Err(JournalError::Corrupt);
            }
            let mut value = Vec::new();
            encode_authority_prefix(envelope, &mut value)?;
            value.extend_from_slice(key_digest);
            value.extend_from_slice(&record_generation.to_be_bytes());
            value.extend_from_slice(attempt_id);
            encode_attempt_kind(attempt_kind, &mut value)?;
            value.extend_from_slice(delivery_fingerprint);
            match delivered_message_id {
                Some(id) if *id > 0 => {
                    value.push(0x00); // Delivered
                    value.push(1);
                    value.extend_from_slice(&id.to_be_bytes());
                }
                None if *evidence_source == 1 => {
                    value.push(0x01); // DefinitelyNotDelivered
                    value.push(0);
                }
                _ => return Err(JournalError::Corrupt),
            }
            value.push(*evidence_source);
            value.extend_from_slice(evidence_id);
            value.extend_from_slice(evidence_digest);
            (authority_key(*challenge_digest, *nonce, tag)?, value)
        }
    };
    encode_authority_tail(envelope, &mut value)?;
    validate_protected_row(&key, &value)?;
    Ok((key, value))
}

fn authority_terminal_operation(
    state: &LogicalState,
    expectation: ProgressAuthorityExpectation,
    terminal: ProgressAuthorityTerminal,
) -> Result<Operation, JournalError> {
    if authority_envelope(&expectation.expected).state != ProgressAuthorityState::Live {
        return Err(JournalError::AnchorConflict);
    }
    let (key, before) = encode_authority_row(&expectation.expected)?;
    let observed = state
        .protected
        .get(&key)
        .ok_or(JournalError::AnchorConflict)?;
    if observed.len() != before.len() || !bool::from(observed.as_slice().ct_eq(&before)) {
        return Err(JournalError::AnchorConflict);
    }
    let mut next = expectation.expected;
    authority_envelope_mut(&mut next).state = match terminal {
        ProgressAuthorityTerminal::Cancelled { at_ms } => {
            ProgressAuthorityState::Cancelled { at_ms }
        }
        ProgressAuthorityTerminal::Consumed { at_ms } => ProgressAuthorityState::Consumed { at_ms },
    };
    let (next_key, after) = encode_authority_row(&next)?;
    if next_key != key {
        return Err(JournalError::Corrupt);
    }
    Ok(Operation::replace(
        PROTECTED_SEGMENT,
        key.tag,
        key.key,
        before,
        after,
    ))
}

fn validate_source_close_authorities(
    commit: &ProgressSourceCloseCommit,
) -> Result<(), JournalError> {
    let snapshot = &commit.expected_snapshot;
    match &commit.route_authority.expected {
        ProgressAuthorityRow::RouteSealReceipt {
            key_digest,
            source_digest,
            source_quiesced_receipt_digest,
            action_refs,
            retry_refs,
            replay_refs,
            envelope,
            ..
        } if *key_digest == snapshot.key_digest
            && *source_digest == snapshot.source_digest
            && *source_quiesced_receipt_digest == commit.source_receipt_digest
            && *action_refs == 0
            && *retry_refs == 0
            && *replay_refs == 0
            && envelope.state == ProgressAuthorityState::Live => {}
        _ => return Err(JournalError::AnchorConflict),
    }
    match &commit.challenge_authority.expected {
        ProgressAuthorityRow::SourceCloseChallenge {
            key_digest,
            source_digest,
            record_generation,
            record_kind,
            record_fingerprint,
            envelope,
            ..
        } if *key_digest == snapshot.key_digest
            && *source_digest == snapshot.source_digest
            && *record_generation == snapshot.lifecycle_generation
            && *record_kind == snapshot.target_kind
            && *record_fingerprint == snapshot.target_fingerprint
            && envelope.state == ProgressAuthorityState::Live => {}
        _ => return Err(JournalError::AnchorConflict),
    }
    match &commit.attestation_authority.expected {
        ProgressAuthorityRow::SourceCloseAttestation {
            key_digest,
            source_digest,
            source_receipt_digest,
            route_receipt_digest,
            envelope,
            ..
        } if *key_digest == snapshot.key_digest
            && *source_digest == snapshot.source_digest
            && *source_receipt_digest == commit.source_receipt_digest
            && *route_receipt_digest == commit.route_receipt_digest
            && envelope.state == ProgressAuthorityState::Live => {}
        _ => return Err(JournalError::AnchorConflict),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

    struct TestLayout {
        root: PathBuf,
        journal: PathBuf,
        anchor: PathBuf,
        key: [u8; 32],
        epoch: NonZeroU32,
    }

    impl TestLayout {
        fn new(label: &str) -> Self {
            let serial = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "advance-progress-journal-{label}-{}-{serial}",
                std::process::id()
            ));
            let journal = root.join("workspace-state").join("journal");
            let anchor = root.join("platform-state").join("anchor.bin");
            Self {
                root,
                journal,
                anchor,
                key: [0x42; 32],
                epoch: NonZeroU32::new(7).unwrap(),
            }
        }

        fn config(&self) -> RecoveryJournalConfig {
            RecoveryJournalConfig::new_at_composition(
                self.journal.clone(),
                self.anchor.clone(),
                self.epoch,
                Zeroizing::new(self.key),
            )
            .unwrap()
        }
    }

    impl Drop for TestLayout {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn hex32(value: &str) -> [u8; 32] {
        assert_eq!(value.len(), 64);
        let mut out = [0; 32];
        for (index, slot) in out.iter_mut().enumerate() {
            *slot = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).unwrap();
        }
        out
    }

    fn consumed_operation(key_byte: u8) -> Operation {
        let mut value = Vec::with_capacity(153);
        value.extend_from_slice(&[0x21; 32]);
        value.extend_from_slice(&1u64.to_be_bytes());
        value.push(0x00);
        value.extend_from_slice(&[0x31; 32]);
        value.extend_from_slice(&[0x41; 32]);
        value.extend_from_slice(&[0x51; 32]);
        value.extend_from_slice(&10u64.to_be_bytes());
        value.extend_from_slice(&20u64.to_be_bytes());
        Operation::insert(RECOVERY_SEGMENT, 0x04, vec![key_byte; 32], value)
    }

    #[test]
    fn normative_kdf_root_head_and_delta_vectors() {
        let master: [u8; 32] = std::array::from_fn(|index| index as u8);
        let salt: [u8; 32] = std::array::from_fn(|index| 0x20 + index as u8);
        let instance: [u8; 16] = std::array::from_fn(|index| index as u8);
        assert_eq!(
            derive_anchor_key(&master, &salt, 7).unwrap(),
            hex32("f1d0376a712c6c075fabc0219b2aa9aeabb95ae92809d6db622b9efbd784f9d2")
        );
        assert_eq!(
            derive_frame_key(&master, &instance, 7, PROTECTED_SEGMENT).unwrap(),
            hex32("304af20306b86a688c4b8ef4f5f6f87357730efd791114d6c35369487bd574b6")
        );
        assert_eq!(
            derive_frame_key(&master, &instance, 7, RECOVERY_SEGMENT).unwrap(),
            hex32("ea1855c84d2ec5153c5f644512741d06ce5a36138c3b5f2c12494249b60cddc6")
        );

        let empty = LogicalState::default();
        let r0 = state_root(instance, 0, &empty).unwrap();
        let h0 = genesis_head(instance, r0);
        assert_eq!(
            r0,
            hex32("140a8ef3a135237a33898713319ca7026097409bb9604af653d1680da400c761")
        );
        assert_eq!(
            h0,
            hex32("4b3602c3f7291f58edd764432b10884e0c27c1633fa91d6d2e76726f7521ccd8")
        );

        let close_key = [0x11; 32];
        let close_v1 =
            encode_open_close([0x22; 32], [0x33; 32], [0x44; 16], 1, 1, 0, &[], &[], &[]).unwrap();
        let w1_ops = vec![Operation::insert(
            RECOVERY_SEGMENT,
            0x03,
            close_key.to_vec(),
            close_v1.clone(),
        )];
        let w1 = canonical_delta(&w1_ops).unwrap();
        let d1: [u8; 32] = Sha256::digest(&w1).into();
        assert_eq!(w1.len(), 168);
        assert_eq!(
            d1,
            hex32("210fd492ec2bafc7f6c6c01c6ff6f9cbfc9decf2753c1a03ebdea1b4024b41fb")
        );
        let state1 = apply_operations(&empty, &w1_ops, false).unwrap();
        let r1 = state_root(instance, 1, &state1).unwrap();
        let h1 = next_head(instance, 1, h0, r0, r1, d1);
        assert_eq!(
            r1,
            hex32("74fbbc48853454f77c322b43f3ec10de4225b52dd05f54cc5144c8f71e382de0")
        );
        assert_eq!(
            h1,
            hex32("a97d85f55f20f9e97e02235524d6eaae998f03783728727404bded872aa97c13")
        );

        let mut terminal = Vec::with_capacity(48);
        terminal.extend_from_slice(&1u64.to_be_bytes());
        terminal.extend_from_slice(&[0x77; 32]);
        terminal.extend_from_slice(&1u64.to_be_bytes());
        let mut close = decode_close_details(&close_v1).unwrap();
        close.lifecycle_generation = 2;
        close.route_seal_generation = 2;
        close.sealed = Some(SealedCloseDetails {
            runtime_retired: false,
            retired_action: 0,
            retired_retry: 0,
            retired_replay: 0,
            retired_digest: None,
            evidence_digest: [0x55; 32],
            sealed_at_ms: 1,
        });
        let close_v2 = encode_close_details(&close).unwrap();
        let w2_ops = vec![
            Operation::insert(PROTECTED_SEGMENT, 0x01, close_key.to_vec(), terminal),
            Operation::replace(
                RECOVERY_SEGMENT,
                0x03,
                close_key.to_vec(),
                close_v1,
                close_v2,
            ),
        ];
        let w2 = canonical_delta(&w2_ops).unwrap();
        let d2: [u8; 32] = Sha256::digest(&w2).into();
        assert_eq!(w2.len(), 410);
        assert_eq!(
            d2,
            hex32("bca456e637f7824d02dbd768fd7bad225b02f418c477513de5f8ff384b009f23")
        );
        let state2 = apply_operations(&state1, &w2_ops, false).unwrap();
        let r2 = state_root(instance, 2, &state2).unwrap();
        let h2 = next_head(instance, 2, h1, r1, r2, d2);
        assert_eq!(
            r2,
            hex32("312500705c59ef08b42b92343adb655a7e5682993ec614fbf1f085c02bf913a8")
        );
        assert_eq!(
            h2,
            hex32("4accf17e65a58fe0793a17f0951b7b2571304b979f9e0a5286793ffcdfec21bd")
        );
    }

    #[test]
    fn bootstrap_resumes_from_zero_one_or_two_exact_headers() {
        for present in 0..=2 {
            let layout = TestLayout::new(&format!("bootstrap-{present}"));
            create_owner_directory(&layout.journal).unwrap();
            create_owner_directory(layout.anchor.parent().unwrap()).unwrap();
            let key = Arc::new(Zeroizing::new(layout.key));
            let anchor =
                ExternalAnchor::acquire(layout.anchor.clone(), layout.epoch, Arc::clone(&key))
                    .unwrap();
            let instance = [present as u8 + 1; 16];
            let nonce = [0x80 + present as u8; 16];
            let protected = segment_header(instance, nonce, PROTECTED_SEGMENT);
            let recovery = segment_header(instance, nonce, RECOVERY_SEGMENT);
            let pending = AnchorState::BootstrapPending {
                instance_id: instance,
                bootstrap_nonce: nonce,
                protected_header_digest: segment_header_digest(&protected),
                recovery_header_digest: segment_header_digest(&recovery),
            };
            let mut rng = rand::rngs::OsRng;
            anchor
                .compare_and_swap(None, [0x61; 32], &pending, &mut rng)
                .unwrap();
            if present >= 1 {
                create_segment_header_no_replace(&layout.journal.join(PROTECTED_FILE), &protected)
                    .unwrap();
            }
            if present >= 2 {
                create_segment_header_no_replace(&layout.journal.join(RECOVERY_FILE), &recovery)
                    .unwrap();
            }
            drop(anchor);
            drop(key);
            let journal =
                ProgressLifecycleRecoveryJournal::open_at_composition(layout.config()).unwrap();
            let core = journal.core.lock().unwrap();
            assert_eq!(core.instance_id, instance);
            assert_eq!(core.sequence, 1); // first RuntimeMarker is anchored
            assert!(matches!(
                core.anchor_snapshot.decoded.state,
                AnchorState::Committed { pending: None, .. }
            ));
        }

        let orphan = TestLayout::new("orphan-segment");
        create_owner_directory(&orphan.journal).unwrap();
        let header = segment_header([1; 16], [2; 16], PROTECTED_SEGMENT);
        create_segment_header_no_replace(&orphan.journal.join(PROTECTED_FILE), &header).unwrap();
        assert!(matches!(
            ProgressLifecycleRecoveryJournal::open_at_composition(orphan.config()),
            Err(TurnAuthorityInitError::AnchorMismatch)
        ));
    }

    #[test]
    fn role_split_is_one_shot_and_shares_one_private_core() {
        let layout = TestLayout::new("role-split");
        let journal =
            ProgressLifecycleRecoveryJournal::open_at_composition(layout.config()).unwrap();
        let (turn, progress) = journal.split_at_composition();
        assert!(Arc::ptr_eq(&turn.core, &progress.core));
        assert_eq!(
            turn.current_runtime_incarnation().unwrap(),
            published_runtime(&progress.core.lock().unwrap()).unwrap()
        );
    }

    #[test]
    fn every_four_step_failpoint_recovers_to_the_anchor_decision() {
        for point in [
            TxFailpoint::AfterPreparedFsync,
            TxFailpoint::AfterPendingAnchor,
            TxFailpoint::AfterCommittedFsync,
            TxFailpoint::AfterFinalAnchor,
        ] {
            let layout = TestLayout::new(&format!("tx-{point:?}"));
            let journal =
                ProgressLifecycleRecoveryJournal::open_at_composition(layout.config()).unwrap();
            let (turn, progress) = journal.split_at_composition();
            {
                let mut core = progress.core.lock().unwrap();
                core.failpoint = Some(point);
                let mut rng = rand::rngs::OsRng;
                assert!(matches!(
                    core.transact(&[consumed_operation(0x70)], &mut rng),
                    Err(JournalError::InjectedFailure)
                ));
            }
            drop(turn);
            drop(progress);

            let reopened =
                ProgressLifecycleRecoveryJournal::open_at_composition(layout.config()).unwrap();
            let present = reopened
                .core
                .lock()
                .unwrap()
                .state
                .recovery
                .contains_key(&RowKey {
                    tag: 0x04,
                    key: vec![0x70; 32],
                });
            assert_eq!(present, point != TxFailpoint::AfterPreparedFsync);
        }
    }

    #[test]
    fn restoring_whole_older_logs_is_detected_by_external_anchor() {
        let layout = TestLayout::new("rollback");
        let journal =
            ProgressLifecycleRecoveryJournal::open_at_composition(layout.config()).unwrap();
        let protected_path = layout.journal.join(PROTECTED_FILE);
        let recovery_path = layout.journal.join(RECOVERY_FILE);
        let old_protected = fs::read(&protected_path).unwrap();
        let old_recovery = fs::read(&recovery_path).unwrap();
        {
            let mut core = journal.core.lock().unwrap();
            let mut rng = rand::rngs::OsRng;
            core.transact(&[consumed_operation(0x71)], &mut rng)
                .unwrap();
        }
        drop(journal);
        fs::write(&protected_path, old_protected).unwrap();
        fs::write(&recovery_path, old_recovery).unwrap();
        assert!(matches!(
            ProgressLifecycleRecoveryJournal::open_at_composition(layout.config()),
            Err(TurnAuthorityInitError::RollbackDetected)
        ));
    }

    #[test]
    fn mutually_bound_checkpoint_recovers_mixed_compacted_and_full_images() {
        let layout = TestLayout::new("checkpoint-mixed");
        let journal =
            ProgressLifecycleRecoveryJournal::open_at_composition(layout.config()).unwrap();
        let protected_path = layout.journal.join(PROTECTED_FILE);
        let recovery_path = layout.journal.join(RECOVERY_FILE);
        {
            let mut core = journal.core.lock().unwrap();
            let mut rng = rand::rngs::OsRng;
            core.transact(&[consumed_operation(0x72)], &mut rng)
                .unwrap();
        }
        let old_protected = fs::read(&protected_path).unwrap();
        {
            let mut core = journal.core.lock().unwrap();
            let mut rng = rand::rngs::OsRng;
            core.checkpoint(&mut rng).unwrap();
            assert_eq!(core.protected_frames, 1);
            assert_eq!(core.recovery_frames, 1);
        }
        let compacted_protected = fs::read(&protected_path).unwrap();
        drop(journal);
        let mut mixed_protected = old_protected;
        mixed_protected.extend_from_slice(&compacted_protected[SEGMENT_HEADER_LEN..]);
        fs::write(&protected_path, mixed_protected).unwrap();

        let reopened =
            ProgressLifecycleRecoveryJournal::open_at_composition(layout.config()).unwrap();
        assert!(reopened
            .core
            .lock()
            .unwrap()
            .state
            .recovery
            .contains_key(&RowKey {
                tag: 0x04,
                key: vec![0x72; 32],
            }));
        assert!(fs::metadata(recovery_path).unwrap().len() <= HARD_LOG_BYTES);
    }

    #[test]
    fn repeated_boot_reuses_unpublished_marker_and_finishes_old_runtime_retirement() {
        let layout = TestLayout::new("repeated-boot");
        let journal =
            ProgressLifecycleRecoveryJournal::open_at_composition(layout.config()).unwrap();
        let (turn, progress) = journal.split_at_composition();
        let old;
        let new = [0xb1; 16];
        let evidence = [0xe1; 32];
        let marker_some;
        {
            let mut core = progress.core.lock().unwrap();
            old = published_runtime(&core).unwrap();
            let source_bound = [0x10; 32];
            let source_unbound = [0x20; 32];
            let key_digest = [0x30; 32];
            let close = encode_open_close(
                source_bound,
                [0x40; 32],
                old,
                1,
                1,
                50,
                &[[1; 16]],
                &[[2; 16]],
                &[],
            )
            .unwrap();
            let mut seed = vec![
                Operation::insert(
                    RECOVERY_SEGMENT,
                    0x01,
                    source_bound.to_vec(),
                    encode_active_source(old, [0x40; 32], 1, Some(key_digest), 40),
                ),
                Operation::insert(
                    RECOVERY_SEGMENT,
                    0x01,
                    source_unbound.to_vec(),
                    encode_active_source(old, [0x41; 32], 2, None, 41),
                ),
                Operation::insert(RECOVERY_SEGMENT, 0x03, key_digest.to_vec(), close),
            ];
            sort_operations(&mut seed);
            let mut rng = rand::rngs::OsRng;
            core.transact(&seed, &mut rng).unwrap();

            let marker_key = RowKey {
                tag: 0x05,
                key: Vec::new(),
            };
            let marker_before = core.state.recovery.get(&marker_key).unwrap().clone();
            marker_some = encode_runtime_marker(new, Some(old), evidence, 777);
            core.transact(
                &[Operation::replace(
                    RECOVERY_SEGMENT,
                    0x05,
                    Vec::new(),
                    marker_before,
                    marker_some.clone(),
                )],
                &mut rng,
            )
            .unwrap();
            core.failpoint = Some(TxFailpoint::AfterPendingAnchor);
            assert!(matches!(
                core.complete_runtime_marker(&mut rng),
                Err(JournalError::InjectedFailure)
            ));
        }
        drop(turn);
        drop(progress);

        let reopened =
            ProgressLifecycleRecoveryJournal::open_at_composition(layout.config()).unwrap();
        let core = reopened.core.lock().unwrap();
        let marker_key = RowKey {
            tag: 0x05,
            key: Vec::new(),
        };
        let ParsedRecoveryRow::Marker(marker) =
            parse_recovery_row(&marker_key, core.state.recovery.get(&marker_key).unwrap()).unwrap()
        else {
            panic!("marker row changed kind")
        };
        assert_eq!(marker.current, new);
        assert_eq!(marker.retired, None);
        assert_eq!(marker.evidence, evidence);
        assert_eq!(marker.booted_at_ms, 777);
        assert!(!core.state.recovery.contains_key(&RowKey {
            tag: 0x01,
            key: vec![0x20; 32],
        }));
        let quiesced_key = RowKey {
            tag: 0x02,
            key: vec![0x10; 32],
        };
        assert!(matches!(
            parse_recovery_row(
                &quiesced_key,
                core.state.recovery.get(&quiesced_key).unwrap()
            )
            .unwrap(),
            ParsedRecoveryRow::Quiesced(QuiescedSourceView {
                runtime_retired: true,
                runtime,
                ..
            }) if runtime == old
        ));
        let close = decode_close_details(
            core.state
                .recovery
                .get(&RowKey {
                    tag: 0x03,
                    key: vec![0x30; 32],
                })
                .unwrap(),
        )
        .unwrap();
        let sealed = close.sealed.unwrap();
        assert!(sealed.runtime_retired);
        assert_eq!(
            (
                sealed.retired_action,
                sealed.retired_retry,
                sealed.retired_replay
            ),
            (1, 1, 0)
        );
        assert_eq!(
            sealed.evidence_digest,
            runtime_marker_digest(&marker_some).unwrap()
        );
    }

    #[test]
    fn retiring_normally_sealed_close_preserves_route_seal_generation() {
        let source = [0x11; 32];
        let agent = [0x22; 32];
        let runtime = [0x33; 16];
        let marker_digest = [0x44; 32];
        let before = encode_close_details(&CloseDetails {
            source,
            expected_agent: agent,
            runtime,
            lifecycle_generation: 7,
            route_seal_generation: 5,
            armed_at_ms: 101,
            action: Vec::new(),
            retry: Vec::new(),
            replay: Vec::new(),
            sealed: Some(SealedCloseDetails {
                runtime_retired: false,
                retired_action: 0,
                retired_retry: 0,
                retired_replay: 0,
                retired_digest: None,
                evidence_digest: [0x55; 32],
                sealed_at_ms: 202,
            }),
        })
        .unwrap();

        let after =
            retire_already_sealed_close(&before, source, agent, runtime, marker_digest, 303)
                .unwrap();
        let details = decode_close_details(&after).unwrap();
        let sealed = details.sealed.unwrap();

        assert_eq!(details.lifecycle_generation, 8);
        assert_eq!(details.route_seal_generation, 5);
        assert!(sealed.runtime_retired);
        assert_eq!(
            (
                sealed.retired_action,
                sealed.retired_retry,
                sealed.retired_replay
            ),
            (0, 0, 0)
        );
        assert_eq!(
            sealed.retired_digest,
            Some(domain_hash(DOMAIN_RETIRED_REFS, &[&[0u8; 12]]))
        );
        assert_eq!(sealed.evidence_digest, marker_digest);
        assert_eq!(sealed.sealed_at_ms, 303);
    }

    #[test]
    fn route_ref_cap_accepts_exact_limit_and_rejects_one_more_before_allocation() {
        let mut bytes = Vec::with_capacity(4 + MAX_ROUTE_REFS * 16);
        bytes.extend_from_slice(&(MAX_ROUTE_REFS as u32).to_be_bytes());
        for value in 1..=MAX_ROUTE_REFS as u128 {
            bytes.extend_from_slice(&value.to_be_bytes());
        }
        let mut cursor = Cursor::new(&bytes);
        assert_eq!(parse_ref_set(&mut cursor).unwrap().len(), MAX_ROUTE_REFS);
        cursor.finish().unwrap();

        let over = ((MAX_ROUTE_REFS + 1) as u32).to_be_bytes();
        assert!(matches!(
            parse_ref_set(&mut Cursor::new(&over)),
            Err(JournalError::Capacity)
        ));
    }
}

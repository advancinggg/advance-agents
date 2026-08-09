//! Durable CONTRACT-190 idempotency repository.
//!
//! The repository owns the SQLite phase machine and pairs every postimage with an external,
//! compare-and-swap protected manifest.  The protected record is intentionally abstract: the CLI
//! composition supplies a platform-state implementation outside the workspace backup domain,
//! while tests use an in-memory CAS implementation.

use std::collections::BTreeMap;
use std::num::NonZeroU32;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::{CryptoRng, RngCore};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::providers::grants::{ProviderClientDoneReceipt, ProviderMutationRecovery};

type HmacSha256 = Hmac<Sha256>;

pub const PHASE_PENDING: u8 = 1;
pub const PHASE_PROVIDER_PREPARED: u8 = 2;
pub const PHASE_RECOVERING: u8 = 3;
pub const PHASE_DONE: u8 = 4;

pub const MAX_LIVE_GLOBAL: u64 = 256;
pub const MAX_LIVE_PER_PRINCIPAL: u64 = 32;
pub const MAX_RECORDS: u64 = 10_000;
pub const MAX_ACCOUNTED_BYTES: u64 = 268_435_456;
pub const FUTURE_OUTCOME_BYTES: u64 = 1_048_576;
pub const DONE_TTL_MS: u64 = 86_400_000;

const SCHEMA_VERSION: u32 = 1;
const BOOTSTRAP_LEN: usize = 190;
const MANIFEST_COMMITTED_LEN: usize = 195;
const MANIFEST_PENDING_LEN: usize = 364;
const DONE_RECEIPT_LEN: usize = 283;

const DOMAIN_LOCATION: &[u8] = b"advance.contract190.idempotency-sqlite-location.v1\0";
const DOMAIN_GENESIS: &[u8] = b"advance.contract190.idempotency-genesis.v1\0";
const INFO_BOOTSTRAP_KEY: &[u8] = b"advance.contract190.idempotency-bootstrap-key.v1\0";
const DOMAIN_BOOTSTRAP: &[u8] = b"advance.contract190.idempotency-bootstrap-intent.v1\0";
const INFO_MANIFEST_KEY: &[u8] = b"advance.contract190.idempotency-manifest-key.v1\0";
const DOMAIN_MANIFEST: &[u8] = b"advance.contract190.idempotency-manifest.v1\0";
const INFO_SCOPE_KEY: &[u8] = b"advance.contract190.idempotency-scope-key.v1\0";
const DOMAIN_SCOPE: &[u8] = b"advance.contract190.idempotency-scope.v1\0";
const DOMAIN_PRINCIPAL: &[u8] = b"advance.contract190.idempotency-principal.v1\0";
const DOMAIN_KEY: &[u8] = b"advance.contract190.idempotency-key.v1\0";
const INFO_PAYLOAD_KEY: &[u8] = b"advance.contract190.idempotency-payload-key.v1\0";
const DOMAIN_MUTATION_ID: &[u8] = b"advance.contract190.mutation-id.v1\0";
const DOMAIN_OUTCOME: &[u8] = b"advance.contract190.idempotency-outcome.v1\0";
const DOMAIN_STATE_ROOT: &[u8] = b"advance.contract190.idempotency-state-root.v1\0";
const DOMAIN_HEAD: &[u8] = b"advance.contract190.idempotency-head.v1\0";
const DOMAIN_WRITE_SET: &[u8] = b"advance.contract190.idempotency-write-set.v1\0";
const INFO_DONE_RECEIPT_KEY: &[u8] = b"advance.contract190.client-done-receipt-key.v1\0";
const DOMAIN_DONE_RECEIPT: &[u8] = b"advance.contract190.client-done-receipt.v1\0";

const SCHEMA: &str = r#"
CREATE TABLE client_idempotency_records (
    scope_digest BLOB PRIMARY KEY CHECK(typeof(scope_digest)='blob' AND length(scope_digest)=32),
    principal_digest BLOB NOT NULL CHECK(typeof(principal_digest)='blob' AND length(principal_digest)=32),
    idempotency_key_digest BLOB NOT NULL CHECK(typeof(idempotency_key_digest)='blob' AND length(idempotency_key_digest)=32),
    request_fingerprint BLOB NOT NULL CHECK(typeof(request_fingerprint)='blob' AND length(request_fingerprint)=32),
    mutation_id BLOB NOT NULL UNIQUE CHECK(typeof(mutation_id)='blob' AND length(mutation_id)=32),
    provider_tag INTEGER NOT NULL CHECK(provider_tag BETWEEN 1 AND 5),
    operation_tag INTEGER NOT NULL CHECK(operation_tag BETWEEN 1 AND 5),
    phase INTEGER NOT NULL CHECK(phase BETWEEN 1 AND 4),
    provider_entry_started INTEGER NOT NULL CHECK(provider_entry_started IN (0,1)),
    reservation_token BLOB NOT NULL CHECK(typeof(reservation_token)='blob' AND length(reservation_token)=32 AND reservation_token != zeroblob(32)),
    original_request_id TEXT NOT NULL CHECK(typeof(original_request_id)='text' AND length(CAST(original_request_id AS BLOB)) BETWEEN 1 AND 128),
    payload_key_epoch INTEGER NOT NULL CHECK(payload_key_epoch BETWEEN 1 AND 4294967295),
    payload_nonce BLOB NOT NULL CHECK(typeof(payload_nonce)='blob' AND length(payload_nonce)=24 AND payload_nonce != zeroblob(24)),
    mutation_payload_ciphertext BLOB NOT NULL CHECK(typeof(mutation_payload_ciphertext)='blob' AND length(mutation_payload_ciphertext) BETWEEN 17 AND 1048592),
    recovery_ticket BLOB CHECK(recovery_ticket IS NULL OR (typeof(recovery_ticket)='blob' AND length(recovery_ticket)=167)),
    outcome_blob BLOB CHECK(outcome_blob IS NULL OR (typeof(outcome_blob)='blob' AND length(outcome_blob) BETWEEN 1 AND 1048576)),
    outcome_digest BLOB CHECK(outcome_digest IS NULL OR (typeof(outcome_digest)='blob' AND length(outcome_digest)=32)),
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= created_at_ms),
    terminal_at_ms INTEGER CHECK(terminal_at_ms IS NULL OR terminal_at_ms >= created_at_ms),
    expires_at_ms INTEGER CHECK(expires_at_ms IS NULL OR expires_at_ms >= terminal_at_ms),
    metadata_encoded_bytes INTEGER NOT NULL CHECK(metadata_encoded_bytes BETWEEN 1 AND 1049600),
    future_metadata_bytes INTEGER NOT NULL CHECK(future_metadata_bytes IN (0,85,256)),
    actual_outcome_bytes INTEGER NOT NULL CHECK(actual_outcome_bytes BETWEEN 0 AND 1048576),
    future_outcome_bytes INTEGER NOT NULL CHECK(future_outcome_bytes IN (0,1048576)),
    done_slot_reserved INTEGER NOT NULL CHECK(done_slot_reserved IN (0,1)),
    CHECK((provider_tag=1 AND operation_tag BETWEEN 1 AND 5) OR
          (provider_tag=2 AND operation_tag BETWEEN 1 AND 3) OR
          (provider_tag IN (3,4,5) AND operation_tag=1)),
    CHECK((phase=1 AND recovery_ticket IS NULL AND outcome_blob IS NULL AND outcome_digest IS NULL AND
           terminal_at_ms IS NULL AND expires_at_ms IS NULL AND future_metadata_bytes=256 AND
           actual_outcome_bytes=0 AND future_outcome_bytes=1048576 AND done_slot_reserved=1) OR
          (phase IN (2,3) AND provider_entry_started=1 AND recovery_ticket IS NOT NULL AND
           outcome_blob IS NULL AND outcome_digest IS NULL AND terminal_at_ms IS NULL AND
           expires_at_ms IS NULL AND future_metadata_bytes=85 AND actual_outcome_bytes=0 AND
           future_outcome_bytes=1048576 AND done_slot_reserved=1) OR
          (phase=4 AND provider_entry_started=1 AND recovery_ticket IS NULL AND outcome_blob IS NOT NULL AND
           outcome_digest IS NOT NULL AND terminal_at_ms IS NOT NULL AND expires_at_ms=terminal_at_ms+86400000 AND
           future_metadata_bytes=0 AND actual_outcome_bytes=length(outcome_blob) AND
           future_outcome_bytes=0 AND done_slot_reserved=0))
) STRICT;
CREATE TABLE client_idempotency_capacity (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    record_count INTEGER NOT NULL CHECK(record_count BETWEEN 0 AND 10000),
    live_count INTEGER NOT NULL CHECK(live_count BETWEEN 0 AND 256),
    done_count INTEGER NOT NULL CHECK(done_count BETWEEN 0 AND 10000),
    actual_metadata_bytes INTEGER NOT NULL CHECK(actual_metadata_bytes BETWEEN 0 AND 268435456),
    future_metadata_bytes INTEGER NOT NULL CHECK(future_metadata_bytes BETWEEN 0 AND 268435456),
    actual_outcome_bytes INTEGER NOT NULL CHECK(actual_outcome_bytes BETWEEN 0 AND 268435456),
    future_outcome_bytes INTEGER NOT NULL CHECK(future_outcome_bytes BETWEEN 0 AND 268435456),
    CHECK(record_count=live_count+done_count),
    CHECK(actual_metadata_bytes+future_metadata_bytes <= 268435456),
    CHECK(actual_outcome_bytes+future_outcome_bytes <= 268435456)
) STRICT;
CREATE TABLE client_idempotency_ledger (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    store_instance_id BLOB NOT NULL CHECK(typeof(store_instance_id)='blob' AND length(store_instance_id)=16),
    committed_sequence INTEGER NOT NULL CHECK(committed_sequence >= 0),
    committed_head_digest BLOB NOT NULL CHECK(typeof(committed_head_digest)='blob' AND length(committed_head_digest)=32),
    committed_state_root BLOB NOT NULL CHECK(typeof(committed_state_root)='blob' AND length(committed_state_root)=32)
) STRICT;
"#;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DurableIdempotencyError {
    Configuration,
    AnchorUnavailable,
    AnchorConflict,
    Corrupt,
    Capacity,
    NotFound,
    InvalidTransition,
    Crypto,
    Storage,
}

impl std::fmt::Display for DurableIdempotencyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Configuration => "invalid durable idempotency configuration",
            Self::AnchorUnavailable => "idempotency anchor unavailable",
            Self::AnchorConflict => "idempotency anchor conflict",
            Self::Corrupt => "durable idempotency state corrupt",
            Self::Capacity => "durable idempotency capacity exhausted",
            Self::NotFound => "durable idempotency record not found",
            Self::InvalidTransition => "invalid durable idempotency phase transition",
            Self::Crypto => "durable idempotency cryptographic failure",
            Self::Storage => "durable idempotency storage failure",
        })
    }
}

impl std::error::Error for DurableIdempotencyError {}

impl From<rusqlite::Error> for DurableIdempotencyError {
    fn from(_: rusqlite::Error) -> Self {
        Self::Storage
    }
}

/// Protected state CAS. Implementations must persist outside the SQLite/workspace backup domain.
pub trait IdempotencyAnchor: Send + Sync {
    fn load(&self) -> Result<Option<Vec<u8>>, DurableIdempotencyError>;
    fn compare_and_swap(
        &self,
        expected: Option<&[u8]>,
        replacement: &[u8],
    ) -> Result<(), DurableIdempotencyError>;
}

pub struct DurableIdempotencyConfig {
    pub database_path: PathBuf,
    pub confined_relative_path: String,
    pub workspace_master_key: Zeroizing<[u8; 32]>,
    pub key_epoch: NonZeroU32,
    pub scope_key_epoch: NonZeroU32,
    pub payload_key_epoch: NonZeroU32,
}

#[derive(Clone)]
struct Manifest {
    key_epoch: NonZeroU32,
    scope_key_epoch: NonZeroU32,
    store_instance_id: [u8; 16],
    genesis_head: [u8; 32],
    sqlite_location_digest: [u8; 32],
    committed_sequence: u64,
    committed_head_digest: [u8; 32],
    committed_state_root: [u8; 32],
    pending: Option<PendingManifest>,
}

#[derive(Clone)]
struct PendingManifest {
    previous_head: [u8; 32],
    previous_state_root: [u8; 32],
    next_sequence: u64,
    next_head: [u8; 32],
    next_state_root: [u8; 32],
    operation_tag: u8,
    write_set_digest: [u8; 32],
}

pub struct DurableIdempotencyRepository {
    connection: Mutex<Connection>,
    anchor: Arc<dyn IdempotencyAnchor>,
    master_key: Arc<Zeroizing<[u8; 32]>>,
    payload_key_epoch: NonZeroU32,
    manifest: Mutex<(Vec<u8>, Manifest)>,
}

pub struct DurableReserveInput {
    pub principal: String,
    pub method: String,
    pub family: String,
    pub idempotency_key: String,
    pub request_fingerprint: [u8; 32],
    pub canonical_request: Vec<u8>,
    pub provider_tag: u8,
    pub operation_tag: u8,
    pub original_request_id: String,
    pub now_ms: u64,
}

#[derive(Clone)]
pub struct DurableReservation {
    pub scope_digest: [u8; 32],
    pub mutation_id: [u8; 32],
    pub request_fingerprint: [u8; 32],
    pub reservation_token: [u8; 32],
    pub provider_tag: u8,
    pub operation_tag: u8,
}

pub struct DurableDone {
    pub original_request_id: String,
    pub outcome_blob: Vec<u8>,
}

pub enum DurableBegin {
    Reserved(DurableReservation),
    Replay(DurableDone),
    InProgress,
    Conflict,
    Capacity,
}

pub struct DurableRecoveryRow {
    pub reservation: DurableReservation,
    pub phase: u8,
    pub provider_entry_started: bool,
    pub canonical_request: Zeroizing<Vec<u8>>,
    pub recovery_ticket: Option<ProviderMutationRecovery>,
    pub original_request_id: String,
}

impl DurableIdempotencyRepository {
    pub fn open(
        config: DurableIdempotencyConfig,
        anchor: Arc<dyn IdempotencyAnchor>,
    ) -> Result<Arc<Self>, DurableIdempotencyError> {
        validate_confined_path(&config.confined_relative_path)?;
        if config.database_path.is_symlink() {
            return Err(DurableIdempotencyError::Configuration);
        }
        let location_digest = sqlite_location_digest(&config.confined_relative_path)?;
        let master_key = Arc::new(config.workspace_master_key.clone());
        let observed = anchor.load()?;
        let (connection, manifest_bytes, manifest) = match observed {
            None => {
                if config.database_path.exists() {
                    return Err(DurableIdempotencyError::Corrupt);
                }
                bootstrap(
                    &config,
                    anchor.as_ref(),
                    master_key.as_ref(),
                    location_digest,
                )?
            }
            Some(bytes) => open_existing(
                &config,
                anchor.as_ref(),
                master_key.as_ref(),
                location_digest,
                bytes,
            )?,
        };
        let repository = Arc::new(Self {
            connection: Mutex::new(connection),
            anchor,
            master_key,
            payload_key_epoch: config.payload_key_epoch,
            manifest: Mutex::new((manifest_bytes, manifest)),
        });
        repository.verify_complete_postimage()?;
        Ok(repository)
    }

    pub fn store_instance_id(&self) -> [u8; 16] {
        self.manifest
            .lock()
            .expect("manifest lock")
            .1
            .store_instance_id
    }

    pub fn committed_sequence(&self) -> u64 {
        self.manifest
            .lock()
            .expect("manifest lock")
            .1
            .committed_sequence
    }

    pub fn reserve(
        &self,
        input: DurableReserveInput,
    ) -> Result<DurableBegin, DurableIdempotencyError> {
        validate_provider_operation(input.provider_tag, input.operation_tag)?;
        if input.principal.is_empty()
            || input.method.is_empty()
            || input.family.is_empty()
            || input.idempotency_key.is_empty()
            || input.original_request_id.is_empty()
            || input.original_request_id.len() > 128
            || input.canonical_request.is_empty()
            || input.canonical_request.len() > 1_048_576
        {
            return Err(DurableIdempotencyError::Configuration);
        }
        let manifest = self
            .manifest
            .lock()
            .map_err(|_| DurableIdempotencyError::Storage)?;
        let instance = manifest.1.store_instance_id;
        let scope_key = derive_key(
            self.master_key.as_ref(),
            &instance,
            INFO_SCOPE_KEY,
            manifest.1.scope_key_epoch,
        )?;
        drop(manifest);
        let canonical_scope = canonical_scope(
            &input.principal,
            &input.method,
            &input.family,
            &input.idempotency_key,
        )?;
        let scope_digest = hmac(&scope_key, DOMAIN_SCOPE, &canonical_scope)?;
        let principal_digest = hmac(
            &scope_key,
            DOMAIN_PRINCIPAL,
            &length_prefixed(input.principal.as_bytes())?,
        )?;
        let key_digest = hmac(
            &scope_key,
            DOMAIN_KEY,
            &length_prefixed(input.idempotency_key.as_bytes())?,
        )?;

        {
            let connection = self
                .connection
                .lock()
                .map_err(|_| DurableIdempotencyError::Storage)?;
            let existing = connection
                .query_row(
                    "SELECT request_fingerprint, phase, original_request_id, outcome_blob,
                            outcome_digest, mutation_id
                     FROM client_idempotency_records WHERE scope_digest=?1",
                    params![scope_digest.as_slice()],
                    |row| {
                        Ok((
                            row.get::<_, Vec<u8>>(0)?,
                            row.get::<_, i64>(1)? as u8,
                            row.get::<_, String>(2)?,
                            row.get::<_, Option<Vec<u8>>>(3)?,
                            row.get::<_, Option<Vec<u8>>>(4)?,
                            row.get::<_, Vec<u8>>(5)?,
                        ))
                    },
                )
                .optional()?;
            if let Some((fingerprint, phase, original, outcome, digest, mutation)) = existing {
                if !ct_eq(&fingerprint, &input.request_fingerprint) {
                    return Ok(DurableBegin::Conflict);
                }
                if phase != PHASE_DONE {
                    return Ok(DurableBegin::InProgress);
                }
                let outcome = outcome.ok_or(DurableIdempotencyError::Corrupt)?;
                let digest = digest.ok_or(DurableIdempotencyError::Corrupt)?;
                let mutation: [u8; 32] = mutation
                    .try_into()
                    .map_err(|_| DurableIdempotencyError::Corrupt)?;
                if !ct_eq(&digest, &outcome_digest(scope_digest, mutation, &outcome)) {
                    return Err(DurableIdempotencyError::Corrupt);
                }
                return Ok(DurableBegin::Replay(DurableDone {
                    original_request_id: original,
                    outcome_blob: outcome,
                }));
            }
        }

        let mut reservation_token = [0u8; 32];
        let mut nonce = [0u8; 24];
        let mut rng = rand::thread_rng();
        fill_nonzero(&mut rng, &mut reservation_token);
        fill_nonzero(&mut rng, &mut nonce);
        let mutation_id = mutation_id(
            instance,
            scope_digest,
            input.request_fingerprint,
            reservation_token,
            input.provider_tag,
            input.operation_tag,
        );
        let ciphertext = encrypt_payload(
            self.master_key.as_ref(),
            instance,
            scope_digest,
            mutation_id,
            input.request_fingerprint,
            input.provider_tag,
            input.operation_tag,
            self.payload_key_epoch,
            nonce,
            &input.canonical_request,
        )?;
        let reservation = DurableReservation {
            scope_digest,
            mutation_id,
            request_fingerprint: input.request_fingerprint,
            reservation_token,
            provider_tag: input.provider_tag,
            operation_tag: input.operation_tag,
        };
        let inserted = self.anchored_transaction(1, |transaction| {
            if transaction
                .query_row(
                    "SELECT 1 FROM client_idempotency_records WHERE scope_digest=?1",
                    params![scope_digest.as_slice()],
                    |_| Ok(()),
                )
                .optional()?
                .is_some()
            {
                return Err(DurableIdempotencyError::AnchorConflict);
            }
            let capacity = read_capacity(transaction)?;
            let per_principal: u64 = transaction.query_row(
                "SELECT count(*) FROM client_idempotency_records WHERE principal_digest=?1 AND phase<4",
                params![principal_digest.as_slice()],
                |row| Ok(row.get::<_, i64>(0)? as u64),
            )?;
            if capacity[0] >= MAX_RECORDS
                || capacity[1] >= MAX_LIVE_GLOBAL
                || per_principal >= MAX_LIVE_PER_PRINCIPAL
                || capacity[5]
                    .checked_add(capacity[6])
                    .and_then(|value| value.checked_add(FUTURE_OUTCOME_BYTES))
                    .is_none_or(|value| value > MAX_ACCOUNTED_BYTES)
            {
                return Err(DurableIdempotencyError::Capacity);
            }
            transaction.execute(
                "INSERT INTO client_idempotency_records(
                    scope_digest,principal_digest,idempotency_key_digest,request_fingerprint,
                    mutation_id,provider_tag,operation_tag,phase,provider_entry_started,
                    reservation_token,original_request_id,payload_key_epoch,payload_nonce,
                    mutation_payload_ciphertext,recovery_ticket,outcome_blob,outcome_digest,
                    created_at_ms,updated_at_ms,terminal_at_ms,expires_at_ms,
                    metadata_encoded_bytes,future_metadata_bytes,actual_outcome_bytes,
                    future_outcome_bytes,done_slot_reserved)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,1,0,?8,?9,?10,?11,?12,NULL,NULL,NULL,
                        ?13,?13,NULL,NULL,1,256,0,1048576,1)",
                params![
                    scope_digest.as_slice(),
                    principal_digest.as_slice(),
                    key_digest.as_slice(),
                    input.request_fingerprint.as_slice(),
                    mutation_id.as_slice(),
                    input.provider_tag as i64,
                    input.operation_tag as i64,
                    reservation_token.as_slice(),
                    input.original_request_id,
                    self.payload_key_epoch.get() as i64,
                    nonce.as_slice(),
                    ciphertext,
                    to_i64(input.now_ms)?,
                ],
            )?;
            let metadata = record_encoded_len(transaction, scope_digest)?;
            if capacity[3]
                .checked_add(capacity[4])
                .and_then(|value| value.checked_add(metadata))
                .and_then(|value| value.checked_add(256))
                .is_none_or(|value| value > MAX_ACCOUNTED_BYTES)
            {
                return Err(DurableIdempotencyError::Capacity);
            }
            transaction.execute(
                "UPDATE client_idempotency_records SET metadata_encoded_bytes=?2 WHERE scope_digest=?1",
                params![scope_digest.as_slice(), to_i64(metadata)?],
            )?;
            recompute_capacity(transaction)?;
            Ok(())
        });
        match inserted {
            Ok(()) => Ok(DurableBegin::Reserved(reservation)),
            Err(DurableIdempotencyError::Capacity) => Ok(DurableBegin::Capacity),
            Err(error) => Err(error),
        }
    }

    pub fn mark_provider_entry(
        &self,
        reservation: &DurableReservation,
        now_ms: u64,
    ) -> Result<(), DurableIdempotencyError> {
        self.anchored_transaction(2, |transaction| {
            require_reservation(transaction, reservation, PHASE_PENDING, Some(false))?;
            transaction.execute(
                "UPDATE client_idempotency_records SET provider_entry_started=1,updated_at_ms=?2 WHERE scope_digest=?1",
                params![reservation.scope_digest.as_slice(), to_i64(now_ms)?],
            )?;
            recompute_metadata_and_capacity(transaction, reservation.scope_digest)
        })
    }

    pub fn store_prepared_ticket(
        &self,
        reservation: &DurableReservation,
        ticket: &ProviderMutationRecovery,
        now_ms: u64,
    ) -> Result<(), DurableIdempotencyError> {
        self.anchored_transaction(3, |transaction| {
            require_reservation(transaction, reservation, PHASE_PENDING, Some(true))?;
            transaction.execute(
                "UPDATE client_idempotency_records SET phase=2,recovery_ticket=?2,
                        future_metadata_bytes=85,updated_at_ms=?3 WHERE scope_digest=?1",
                params![
                    reservation.scope_digest.as_slice(),
                    ticket.as_provider_bytes().as_slice(),
                    to_i64(now_ms)?,
                ],
            )?;
            recompute_metadata_and_capacity(transaction, reservation.scope_digest)
        })
    }

    pub fn mark_recovering(
        &self,
        reservation: &DurableReservation,
        replacement: Option<&ProviderMutationRecovery>,
        now_ms: u64,
    ) -> Result<(), DurableIdempotencyError> {
        self.anchored_transaction(4, |transaction| {
            let phase = require_reservation_any_live(transaction, reservation)?;
            if !matches!(phase, PHASE_PROVIDER_PREPARED | PHASE_RECOVERING) {
                return Err(DurableIdempotencyError::InvalidTransition);
            }
            match replacement {
                Some(ticket) => transaction.execute(
                    "UPDATE client_idempotency_records SET phase=3,recovery_ticket=?2,updated_at_ms=?3 WHERE scope_digest=?1",
                    params![reservation.scope_digest.as_slice(), ticket.as_provider_bytes().as_slice(), to_i64(now_ms)?],
                )?,
                None => transaction.execute(
                    "UPDATE client_idempotency_records SET phase=3,updated_at_ms=?2 WHERE scope_digest=?1",
                    params![reservation.scope_digest.as_slice(), to_i64(now_ms)?],
                )?,
            };
            recompute_metadata_and_capacity(transaction, reservation.scope_digest)
        })
    }

    pub fn finish_done(
        &self,
        reservation: &DurableReservation,
        outcome_blob: &[u8],
        now_ms: u64,
    ) -> Result<ProviderClientDoneReceipt, DurableIdempotencyError> {
        if outcome_blob.is_empty() || outcome_blob.len() > 1_048_576 {
            return Err(DurableIdempotencyError::Configuration);
        }
        let digest = outcome_digest(
            reservation.scope_digest,
            reservation.mutation_id,
            outcome_blob,
        );
        self.anchored_transaction(5, |transaction| {
            let phase = require_reservation_any_live(transaction, reservation)?;
            let marker: i64 = transaction.query_row(
                "SELECT provider_entry_started FROM client_idempotency_records WHERE scope_digest=?1",
                params![reservation.scope_digest.as_slice()],
                |row| row.get(0),
            )?;
            if marker != 1 || !matches!(phase, PHASE_PENDING | PHASE_PROVIDER_PREPARED | PHASE_RECOVERING) {
                return Err(DurableIdempotencyError::InvalidTransition);
            }
            let expires = now_ms
                .checked_add(DONE_TTL_MS)
                .ok_or(DurableIdempotencyError::Storage)?;
            transaction.execute(
                "UPDATE client_idempotency_records SET phase=4,recovery_ticket=NULL,
                        outcome_blob=?2,outcome_digest=?3,terminal_at_ms=?4,expires_at_ms=?5,
                        updated_at_ms=?4,future_metadata_bytes=0,actual_outcome_bytes=?6,
                        future_outcome_bytes=0,done_slot_reserved=0 WHERE scope_digest=?1",
                params![
                    reservation.scope_digest.as_slice(),
                    outcome_blob,
                    digest.as_slice(),
                    to_i64(now_ms)?,
                    to_i64(expires)?,
                    to_i64(outcome_blob.len() as u64)?,
                ],
            )?;
            recompute_metadata_and_capacity(transaction, reservation.scope_digest)
        })?;
        self.issue_done_receipt(reservation, digest)
    }

    pub fn release_before_provider(
        &self,
        reservation: &DurableReservation,
    ) -> Result<(), DurableIdempotencyError> {
        self.anchored_transaction(6, |transaction| {
            require_reservation(transaction, reservation, PHASE_PENDING, Some(false))?;
            transaction.execute(
                "DELETE FROM client_idempotency_records WHERE scope_digest=?1",
                params![reservation.scope_digest.as_slice()],
            )?;
            recompute_capacity(transaction)
        })
    }

    pub fn prune_expired_done(
        &self,
        scope_digest: [u8; 32],
        now_ms: u64,
    ) -> Result<(), DurableIdempotencyError> {
        self.anchored_transaction(7, |transaction| {
            let eligible: Option<i64> = transaction
                .query_row(
                    "SELECT expires_at_ms FROM client_idempotency_records WHERE scope_digest=?1 AND phase=4",
                    params![scope_digest.as_slice()],
                    |row| row.get(0),
                )
                .optional()?;
            if eligible.is_none_or(|expires| expires < 0 || now_ms < expires as u64) {
                return Err(DurableIdempotencyError::InvalidTransition);
            }
            transaction.execute(
                "DELETE FROM client_idempotency_records WHERE scope_digest=?1",
                params![scope_digest.as_slice()],
            )?;
            recompute_capacity(transaction)
        })
    }

    pub fn recovery_rows(&self) -> Result<Vec<DurableRecoveryRow>, DurableIdempotencyError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| DurableIdempotencyError::Storage)?;
        let manifest = self
            .manifest
            .lock()
            .map_err(|_| DurableIdempotencyError::Storage)?;
        let instance = manifest.1.store_instance_id;
        let mut statement = connection.prepare(
            "SELECT scope_digest,mutation_id,request_fingerprint,reservation_token,provider_tag,
                    operation_tag,phase,payload_key_epoch,payload_nonce,mutation_payload_ciphertext,
                    recovery_ticket,original_request_id,provider_entry_started
             FROM client_idempotency_records WHERE phase<4 ORDER BY scope_digest",
        )?;
        let mapped = statement.query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, i64>(4)? as u8,
                row.get::<_, i64>(5)? as u8,
                row.get::<_, i64>(6)? as u8,
                row.get::<_, i64>(7)? as u32,
                row.get::<_, Vec<u8>>(8)?,
                row.get::<_, Vec<u8>>(9)?,
                row.get::<_, Option<Vec<u8>>>(10)?,
                row.get::<_, String>(11)?,
                row.get::<_, i64>(12)? != 0,
            ))
        })?;
        let mut output = Vec::new();
        for row in mapped {
            let (
                scope,
                mutation,
                fingerprint,
                token,
                provider,
                operation,
                phase,
                epoch,
                nonce,
                ciphertext,
                ticket,
                original,
                provider_entry_started,
            ) = row?;
            let reservation = DurableReservation {
                scope_digest: scope
                    .try_into()
                    .map_err(|_| DurableIdempotencyError::Corrupt)?,
                mutation_id: mutation
                    .try_into()
                    .map_err(|_| DurableIdempotencyError::Corrupt)?,
                request_fingerprint: fingerprint
                    .try_into()
                    .map_err(|_| DurableIdempotencyError::Corrupt)?,
                reservation_token: token
                    .try_into()
                    .map_err(|_| DurableIdempotencyError::Corrupt)?,
                provider_tag: provider,
                operation_tag: operation,
            };
            let epoch = NonZeroU32::new(epoch).ok_or(DurableIdempotencyError::Corrupt)?;
            if epoch != self.payload_key_epoch {
                return Err(DurableIdempotencyError::Corrupt);
            }
            let nonce: [u8; 24] = nonce
                .try_into()
                .map_err(|_| DurableIdempotencyError::Corrupt)?;
            let canonical_request = decrypt_payload(
                self.master_key.as_ref(),
                instance,
                &reservation,
                epoch,
                nonce,
                &ciphertext,
            )?;
            let recovery_ticket = match ticket {
                None => None,
                Some(bytes) => Some(
                    ProviderMutationRecovery::from_provider_bytes(
                        bytes
                            .try_into()
                            .map_err(|_| DurableIdempotencyError::Corrupt)?,
                    )
                    .map_err(|_| DurableIdempotencyError::Corrupt)?,
                ),
            };
            if matches!(phase, PHASE_PROVIDER_PREPARED | PHASE_RECOVERING)
                != recovery_ticket.is_some()
            {
                return Err(DurableIdempotencyError::Corrupt);
            }
            output.push(DurableRecoveryRow {
                reservation,
                phase,
                provider_entry_started,
                canonical_request: Zeroizing::new(canonical_request),
                recovery_ticket,
                original_request_id: original,
            });
        }
        Ok(output)
    }

    /// Reissue acknowledgement receipts for already-anchored Done rows. Boot calls this before
    /// exposing provider-backed routes so a lost acknowledgement cannot strand provider journal
    /// state. The outcome digest is recomputed from the retained replay bytes; Done rows never
    /// consult a provider recovery ticket.
    pub fn done_receipts(
        &self,
        provider_tag: u8,
    ) -> Result<Vec<ProviderClientDoneReceipt>, DurableIdempotencyError> {
        if !(1..=5).contains(&provider_tag) {
            return Err(DurableIdempotencyError::Configuration);
        }
        let rows = {
            let connection = self
                .connection
                .lock()
                .map_err(|_| DurableIdempotencyError::Storage)?;
            let mut statement = connection.prepare(
                "SELECT scope_digest,mutation_id,request_fingerprint,reservation_token,
                        operation_tag,outcome_blob,outcome_digest
                 FROM client_idempotency_records
                 WHERE phase=4 AND provider_tag=?1 ORDER BY scope_digest",
            )?;
            let mapped = statement.query_map(params![provider_tag], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, i64>(4)? as u8,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                ))
            })?;
            mapped.collect::<Result<Vec<_>, _>>()?
        };

        let mut receipts = Vec::with_capacity(rows.len());
        for (scope, mutation, fingerprint, token, operation_tag, outcome_blob, stored_digest) in
            rows
        {
            validate_provider_operation(provider_tag, operation_tag)?;
            let reservation = DurableReservation {
                scope_digest: scope
                    .try_into()
                    .map_err(|_| DurableIdempotencyError::Corrupt)?,
                mutation_id: mutation
                    .try_into()
                    .map_err(|_| DurableIdempotencyError::Corrupt)?,
                request_fingerprint: fingerprint
                    .try_into()
                    .map_err(|_| DurableIdempotencyError::Corrupt)?,
                reservation_token: token
                    .try_into()
                    .map_err(|_| DurableIdempotencyError::Corrupt)?,
                provider_tag,
                operation_tag,
            };
            let expected = outcome_digest(
                reservation.scope_digest,
                reservation.mutation_id,
                &outcome_blob,
            );
            if stored_digest.len() != 32 || !ct_eq(&expected, &stored_digest) {
                return Err(DurableIdempotencyError::Corrupt);
            }
            receipts.push(self.issue_done_receipt(&reservation, expected)?);
        }
        Ok(receipts)
    }

    fn issue_done_receipt(
        &self,
        reservation: &DurableReservation,
        outcome_digest: [u8; 32],
    ) -> Result<ProviderClientDoneReceipt, DurableIdempotencyError> {
        let manifest = self
            .manifest
            .lock()
            .map_err(|_| DurableIdempotencyError::Storage)?;
        let current = &manifest.1;
        let mut nonce = [0u8; 32];
        fill_nonzero(&mut rand::thread_rng(), &mut nonce);
        let mut bytes = [0u8; DONE_RECEIPT_LEN];
        bytes[0] = 1;
        bytes[1] = reservation.provider_tag;
        bytes[2] = reservation.operation_tag;
        bytes[3..19].copy_from_slice(&current.store_instance_id);
        bytes[19..27].copy_from_slice(&current.committed_sequence.to_be_bytes());
        bytes[27..59].copy_from_slice(&current.committed_head_digest);
        bytes[59..91].copy_from_slice(&current.committed_state_root);
        bytes[91..123].copy_from_slice(&reservation.scope_digest);
        bytes[123..155].copy_from_slice(&reservation.mutation_id);
        bytes[155..187].copy_from_slice(&reservation.request_fingerprint);
        bytes[187..219].copy_from_slice(&outcome_digest);
        bytes[219..251].copy_from_slice(&nonce);
        let key = derive_key_without_epoch(
            self.master_key.as_ref(),
            &current.store_instance_id,
            INFO_DONE_RECEIPT_KEY,
            reservation.provider_tag,
        )?;
        let receipt_mac = hmac(&key, DOMAIN_DONE_RECEIPT, &bytes[..251])?;
        bytes[251..283].copy_from_slice(&receipt_mac);
        Ok(ProviderClientDoneReceipt::from_repository_bytes(bytes))
    }

    fn anchored_transaction<T>(
        &self,
        operation_tag: u8,
        mutation: impl FnOnce(&Transaction<'_>) -> Result<T, DurableIdempotencyError>,
    ) -> Result<T, DurableIdempotencyError> {
        let mut manifest_guard = self
            .manifest
            .lock()
            .map_err(|_| DurableIdempotencyError::Storage)?;
        if manifest_guard.1.pending.is_some() {
            return Err(DurableIdempotencyError::AnchorUnavailable);
        }
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| DurableIdempotencyError::Storage)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let ledger = read_ledger(&transaction)?;
        if ledger.1 != manifest_guard.1.committed_sequence
            || !ct_eq(&ledger.2, &manifest_guard.1.committed_head_digest)
            || !ct_eq(&ledger.3, &manifest_guard.1.committed_state_root)
            || !ct_eq(&compute_state_root(&transaction)?, &ledger.3)
        {
            return Err(DurableIdempotencyError::Corrupt);
        }
        let before = scan_write_rows(&transaction)?;
        let result = mutation(&transaction)?;
        verify_capacity(&transaction)?;
        let next_root = compute_state_root(&transaction)?;
        let after = scan_write_rows(&transaction)?;
        let write_set = write_set_digest(&before, &after)?;
        let next_sequence = manifest_guard
            .1
            .committed_sequence
            .checked_add(1)
            .filter(|value| *value <= i64::MAX as u64)
            .ok_or(DurableIdempotencyError::Storage)?;
        let next_head = next_head(
            manifest_guard.1.store_instance_id,
            next_sequence,
            manifest_guard.1.committed_head_digest,
            manifest_guard.1.committed_state_root,
            next_root,
            operation_tag,
            write_set,
        );
        let pending = PendingManifest {
            previous_head: manifest_guard.1.committed_head_digest,
            previous_state_root: manifest_guard.1.committed_state_root,
            next_sequence,
            next_head,
            next_state_root: next_root,
            operation_tag,
            write_set_digest: write_set,
        };
        let mut pending_manifest = manifest_guard.1.clone();
        pending_manifest.pending = Some(pending);
        let pending_bytes = encode_manifest(&pending_manifest, self.master_key.as_ref())?;
        self.anchor
            .compare_and_swap(Some(&manifest_guard.0), &pending_bytes)?;
        manifest_guard.0 = pending_bytes.clone();
        manifest_guard.1 = pending_manifest;
        transaction.execute(
            "UPDATE client_idempotency_ledger SET committed_sequence=?1,
                    committed_head_digest=?2,committed_state_root=?3 WHERE singleton=1",
            params![
                to_i64(next_sequence)?,
                next_head.as_slice(),
                next_root.as_slice()
            ],
        )?;
        transaction.commit()?;
        let mut promoted = manifest_guard.1.clone();
        promoted.committed_sequence = next_sequence;
        promoted.committed_head_digest = next_head;
        promoted.committed_state_root = next_root;
        promoted.pending = None;
        let promoted_bytes = encode_manifest(&promoted, self.master_key.as_ref())?;
        self.anchor
            .compare_and_swap(Some(&pending_bytes), &promoted_bytes)?;
        manifest_guard.0 = promoted_bytes;
        manifest_guard.1 = promoted;
        Ok(result)
    }

    fn verify_complete_postimage(&self) -> Result<(), DurableIdempotencyError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| DurableIdempotencyError::Storage)?;
        let (_, manifest) = &*self
            .manifest
            .lock()
            .map_err(|_| DurableIdempotencyError::Storage)?;
        if manifest.pending.is_some() {
            return Err(DurableIdempotencyError::Corrupt);
        }
        let (instance, sequence, head, root) = read_ledger(&connection)?;
        if !ct_eq(&instance, &manifest.store_instance_id)
            || sequence != manifest.committed_sequence
            || !ct_eq(&head, &manifest.committed_head_digest)
            || !ct_eq(&root, &manifest.committed_state_root)
            || !ct_eq(&compute_state_root(&connection)?, &root)
        {
            return Err(DurableIdempotencyError::Corrupt);
        }
        verify_capacity(&connection)
    }
}

fn validate_provider_operation(provider: u8, operation: u8) -> Result<(), DurableIdempotencyError> {
    if matches!((provider, operation), (1, 1..=5) | (2, 1..=3) | (3..=5, 1)) {
        Ok(())
    } else {
        Err(DurableIdempotencyError::Configuration)
    }
}

fn canonical_scope(
    principal: &str,
    method: &str,
    family: &str,
    key: &str,
) -> Result<Vec<u8>, DurableIdempotencyError> {
    let mut output = vec![1];
    for value in [principal, method, family, key] {
        let len = u32::try_from(value.len()).map_err(|_| DurableIdempotencyError::Configuration)?;
        output.extend_from_slice(&len.to_be_bytes());
        output.extend_from_slice(value.as_bytes());
    }
    Ok(output)
}

fn length_prefixed(value: &[u8]) -> Result<Vec<u8>, DurableIdempotencyError> {
    let mut output = Vec::with_capacity(value.len() + 4);
    output.extend_from_slice(
        &u32::try_from(value.len())
            .map_err(|_| DurableIdempotencyError::Configuration)?
            .to_be_bytes(),
    );
    output.extend_from_slice(value);
    Ok(output)
}

fn mutation_id(
    instance: [u8; 16],
    scope: [u8; 32],
    fingerprint: [u8; 32],
    reservation_token: [u8; 32],
    provider: u8,
    operation: u8,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_MUTATION_ID);
    hasher.update(instance);
    hasher.update(scope);
    hasher.update(fingerprint);
    hasher.update(reservation_token);
    hasher.update([provider, operation]);
    hasher.finalize().into()
}

fn payload_associated_data(
    instance: [u8; 16],
    scope: [u8; 32],
    mutation: [u8; 32],
    fingerprint: [u8; 32],
    provider: u8,
    operation: u8,
    epoch: NonZeroU32,
) -> Vec<u8> {
    let mut output = Vec::with_capacity(118);
    output.extend_from_slice(&instance);
    output.extend_from_slice(&scope);
    output.extend_from_slice(&mutation);
    output.extend_from_slice(&fingerprint);
    output.extend_from_slice(&[provider, operation]);
    output.extend_from_slice(&epoch.get().to_be_bytes());
    output
}

#[allow(clippy::too_many_arguments)]
fn encrypt_payload(
    master: &[u8; 32],
    instance: [u8; 16],
    scope: [u8; 32],
    mutation: [u8; 32],
    fingerprint: [u8; 32],
    provider: u8,
    operation: u8,
    epoch: NonZeroU32,
    nonce: [u8; 24],
    plaintext: &[u8],
) -> Result<Vec<u8>, DurableIdempotencyError> {
    let key = derive_key(master, &instance, INFO_PAYLOAD_KEY, epoch)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
        .map_err(|_| DurableIdempotencyError::Crypto)?;
    cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &payload_associated_data(
                    instance,
                    scope,
                    mutation,
                    fingerprint,
                    provider,
                    operation,
                    epoch,
                ),
            },
        )
        .map_err(|_| DurableIdempotencyError::Crypto)
}

fn decrypt_payload(
    master: &[u8; 32],
    instance: [u8; 16],
    reservation: &DurableReservation,
    epoch: NonZeroU32,
    nonce: [u8; 24],
    ciphertext: &[u8],
) -> Result<Vec<u8>, DurableIdempotencyError> {
    let key = derive_key(master, &instance, INFO_PAYLOAD_KEY, epoch)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
        .map_err(|_| DurableIdempotencyError::Crypto)?;
    cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: ciphertext,
                aad: &payload_associated_data(
                    instance,
                    reservation.scope_digest,
                    reservation.mutation_id,
                    reservation.request_fingerprint,
                    reservation.provider_tag,
                    reservation.operation_tag,
                    epoch,
                ),
            },
        )
        .map_err(|_| DurableIdempotencyError::Corrupt)
}

fn outcome_digest(scope: [u8; 32], mutation: [u8; 32], outcome: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_OUTCOME);
    hasher.update(scope);
    hasher.update(mutation);
    hasher.update(outcome);
    hasher.finalize().into()
}

fn require_reservation(
    transaction: &Transaction<'_>,
    reservation: &DurableReservation,
    expected_phase: u8,
    marker: Option<bool>,
) -> Result<(), DurableIdempotencyError> {
    let row = transaction
        .query_row(
            "SELECT mutation_id,request_fingerprint,reservation_token,provider_tag,operation_tag,
                    phase,provider_entry_started FROM client_idempotency_records WHERE scope_digest=?1",
            params![reservation.scope_digest.as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)? as u8,
                    row.get::<_, i64>(4)? as u8,
                    row.get::<_, i64>(5)? as u8,
                    row.get::<_, i64>(6)? != 0,
                ))
            },
        )
        .optional()?
        .ok_or(DurableIdempotencyError::NotFound)?;
    if !ct_eq(&row.0, &reservation.mutation_id)
        || !ct_eq(&row.1, &reservation.request_fingerprint)
        || !ct_eq(&row.2, &reservation.reservation_token)
        || row.3 != reservation.provider_tag
        || row.4 != reservation.operation_tag
        || row.5 != expected_phase
        || marker.is_some_and(|expected| expected != row.6)
    {
        return Err(DurableIdempotencyError::InvalidTransition);
    }
    Ok(())
}

fn require_reservation_any_live(
    transaction: &Transaction<'_>,
    reservation: &DurableReservation,
) -> Result<u8, DurableIdempotencyError> {
    let phase: u8 = transaction
        .query_row(
            "SELECT phase FROM client_idempotency_records WHERE scope_digest=?1",
            params![reservation.scope_digest.as_slice()],
            |row| Ok(row.get::<_, i64>(0)? as u8),
        )
        .optional()?
        .ok_or(DurableIdempotencyError::NotFound)?;
    require_reservation(transaction, reservation, phase, None)?;
    if phase == PHASE_DONE {
        return Err(DurableIdempotencyError::InvalidTransition);
    }
    Ok(phase)
}

fn record_encoded_len(
    connection: &Connection,
    scope: [u8; 32],
) -> Result<u64, DurableIdempotencyError> {
    let mut statement = connection.prepare(
        "SELECT scope_digest, principal_digest, idempotency_key_digest, request_fingerprint,
                mutation_id, provider_tag, operation_tag, phase, provider_entry_started,
                reservation_token, original_request_id, payload_key_epoch, payload_nonce,
                mutation_payload_ciphertext, recovery_ticket, outcome_blob, outcome_digest,
                created_at_ms, updated_at_ms, terminal_at_ms, expires_at_ms,
                metadata_encoded_bytes, future_metadata_bytes, actual_outcome_bytes,
                future_outcome_bytes, done_slot_reserved
         FROM client_idempotency_records WHERE scope_digest=?1",
    )?;
    let (_, encoded) = statement.query_row(params![scope.as_slice()], encode_record_row)?;
    Ok(encoded.len() as u64)
}

fn recompute_metadata_and_capacity(
    transaction: &Transaction<'_>,
    scope: [u8; 32],
) -> Result<(), DurableIdempotencyError> {
    let metadata = record_encoded_len(transaction, scope)?;
    transaction.execute(
        "UPDATE client_idempotency_records SET metadata_encoded_bytes=?2 WHERE scope_digest=?1",
        params![scope.as_slice(), to_i64(metadata)?],
    )?;
    recompute_capacity(transaction)
}

fn recompute_capacity(transaction: &Transaction<'_>) -> Result<(), DurableIdempotencyError> {
    let values = transaction.query_row(
        "SELECT count(*),
                COALESCE(sum(CASE WHEN phase<4 THEN 1 ELSE 0 END),0),
                COALESCE(sum(CASE WHEN phase=4 THEN 1 ELSE 0 END),0),
                COALESCE(sum(metadata_encoded_bytes),0),
                COALESCE(sum(future_metadata_bytes),0),
                COALESCE(sum(actual_outcome_bytes),0),
                COALESCE(sum(future_outcome_bytes),0)
         FROM client_idempotency_records",
        [],
        |row| {
            Ok([
                row.get::<_, i64>(0)? as u64,
                row.get::<_, i64>(1)? as u64,
                row.get::<_, i64>(2)? as u64,
                row.get::<_, i64>(3)? as u64,
                row.get::<_, i64>(4)? as u64,
                row.get::<_, i64>(5)? as u64,
                row.get::<_, i64>(6)? as u64,
            ])
        },
    )?;
    if values[0] > MAX_RECORDS
        || values[1] > MAX_LIVE_GLOBAL
        || values[3]
            .checked_add(values[4])
            .is_none_or(|value| value > MAX_ACCOUNTED_BYTES)
        || values[5]
            .checked_add(values[6])
            .is_none_or(|value| value > MAX_ACCOUNTED_BYTES)
    {
        return Err(DurableIdempotencyError::Capacity);
    }
    transaction.execute(
        "UPDATE client_idempotency_capacity SET record_count=?1,live_count=?2,done_count=?3,
                actual_metadata_bytes=?4,future_metadata_bytes=?5,actual_outcome_bytes=?6,
                future_outcome_bytes=?7 WHERE singleton=1",
        params![
            to_i64(values[0])?,
            to_i64(values[1])?,
            to_i64(values[2])?,
            to_i64(values[3])?,
            to_i64(values[4])?,
            to_i64(values[5])?,
            to_i64(values[6])?,
        ],
    )?;
    Ok(())
}

fn scan_write_rows(
    connection: &Connection,
) -> Result<BTreeMap<(u8, Vec<u8>), Vec<u8>>, DurableIdempotencyError> {
    let mut output = BTreeMap::new();
    let mut statement = connection.prepare(
        "SELECT scope_digest, principal_digest, idempotency_key_digest, request_fingerprint,
                mutation_id, provider_tag, operation_tag, phase, provider_entry_started,
                reservation_token, original_request_id, payload_key_epoch, payload_nonce,
                mutation_payload_ciphertext, recovery_ticket, outcome_blob, outcome_digest,
                created_at_ms, updated_at_ms, terminal_at_ms, expires_at_ms,
                metadata_encoded_bytes, future_metadata_bytes, actual_outcome_bytes,
                future_outcome_bytes, done_slot_reserved
         FROM client_idempotency_records ORDER BY scope_digest",
    )?;
    for row in statement.query_map([], encode_record_row)? {
        let (key, value) = row?;
        if output.insert((1, key), value).is_some() {
            return Err(DurableIdempotencyError::Corrupt);
        }
    }
    output.insert(
        (2, vec![1]),
        encode_capacity_row(read_capacity(connection)?),
    );
    Ok(output)
}

fn write_set_digest(
    before: &BTreeMap<(u8, Vec<u8>), Vec<u8>>,
    after: &BTreeMap<(u8, Vec<u8>), Vec<u8>>,
) -> Result<[u8; 32], DurableIdempotencyError> {
    let mut keys = before
        .keys()
        .chain(after.keys())
        .cloned()
        .collect::<Vec<_>>();
    keys.sort();
    keys.dedup();
    let changed = keys
        .into_iter()
        .filter(|key| before.get(key) != after.get(key))
        .collect::<Vec<_>>();
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_WRITE_SET);
    hasher.update(
        u32::try_from(changed.len())
            .map_err(|_| DurableIdempotencyError::Storage)?
            .to_be_bytes(),
    );
    for (tag, key) in changed {
        hasher.update([tag]);
        hasher.update(
            u32::try_from(key.len())
                .map_err(|_| DurableIdempotencyError::Storage)?
                .to_be_bytes(),
        );
        hasher.update(&key);
        for value in [
            before.get(&(tag, key.clone())),
            after.get(&(tag, key.clone())),
        ] {
            match value {
                None => hasher.update(0u32.to_be_bytes()),
                Some(value) => {
                    hasher.update(
                        u32::try_from(value.len())
                            .map_err(|_| DurableIdempotencyError::Storage)?
                            .to_be_bytes(),
                    );
                    hasher.update(value);
                }
            }
        }
    }
    Ok(hasher.finalize().into())
}

fn next_head(
    instance: [u8; 16],
    sequence: u64,
    previous_head: [u8; 32],
    previous_root: [u8; 32],
    next_root: [u8; 32],
    operation: u8,
    write_set: [u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_HEAD);
    hasher.update(instance);
    hasher.update(sequence.to_be_bytes());
    hasher.update(previous_head);
    hasher.update(previous_root);
    hasher.update(next_root);
    hasher.update([operation]);
    hasher.update(write_set);
    hasher.finalize().into()
}

fn derive_key_without_epoch(
    master: &[u8; 32],
    salt: &[u8],
    info_domain: &[u8],
    provider: u8,
) -> Result<Zeroizing<[u8; 32]>, DurableIdempotencyError> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), master);
    let mut info = Vec::with_capacity(info_domain.len() + 1);
    info.extend_from_slice(info_domain);
    info.push(provider);
    let mut key = Zeroizing::new([0u8; 32]);
    hkdf.expand(&info, key.as_mut())
        .map_err(|_| DurableIdempotencyError::Crypto)?;
    Ok(key)
}

fn to_i64(value: u64) -> Result<i64, DurableIdempotencyError> {
    i64::try_from(value).map_err(|_| DurableIdempotencyError::Storage)
}

fn bootstrap(
    config: &DurableIdempotencyConfig,
    anchor: &dyn IdempotencyAnchor,
    master_key: &[u8; 32],
    location_digest: [u8; 32],
) -> Result<(Connection, Vec<u8>, Manifest), DurableIdempotencyError> {
    if let Some(parent) = config.database_path.parent() {
        std::fs::create_dir_all(parent).map_err(|_| DurableIdempotencyError::Storage)?;
    }
    let mut rng = rand::thread_rng();
    let mut instance = [0u8; 16];
    let mut nonce = [0u8; 32];
    fill_nonzero(&mut rng, &mut instance);
    fill_nonzero(&mut rng, &mut nonce);
    let empty_root = empty_state_root();
    let genesis = genesis_head(
        instance,
        empty_root,
        location_digest,
        config.scope_key_epoch,
    );
    let intent = encode_bootstrap_intent(
        master_key,
        config.key_epoch,
        config.scope_key_epoch,
        instance,
        genesis,
        empty_root,
        location_digest,
        nonce,
    )?;
    anchor.compare_and_swap(None, &intent)?;
    let connection = create_database(&config.database_path, instance, genesis, empty_root)?;
    let manifest = Manifest {
        key_epoch: config.key_epoch,
        scope_key_epoch: config.scope_key_epoch,
        store_instance_id: instance,
        genesis_head: genesis,
        sqlite_location_digest: location_digest,
        committed_sequence: 0,
        committed_head_digest: genesis,
        committed_state_root: empty_root,
        pending: None,
    };
    let bytes = encode_manifest(&manifest, master_key)?;
    anchor.compare_and_swap(Some(&intent), &bytes)?;
    Ok((connection, bytes, manifest))
}

fn open_existing(
    config: &DurableIdempotencyConfig,
    anchor: &dyn IdempotencyAnchor,
    master_key: &[u8; 32],
    location_digest: [u8; 32],
    bytes: Vec<u8>,
) -> Result<(Connection, Vec<u8>, Manifest), DurableIdempotencyError> {
    match bytes.get(1).copied() {
        Some(1) => {
            let intent = decode_bootstrap_intent(&bytes, master_key)?;
            if intent.key_epoch != config.key_epoch
                || intent.scope_key_epoch != config.scope_key_epoch
                || !ct_eq(&intent.sqlite_location_digest, &location_digest)
            {
                return Err(DurableIdempotencyError::Corrupt);
            }
            let connection = if config.database_path.exists() {
                Connection::open(&config.database_path)?
            } else {
                create_database(
                    &config.database_path,
                    intent.store_instance_id,
                    intent.genesis_head,
                    intent.empty_state_root,
                )?
            };
            verify_schema(&connection)?;
            let ledger = read_ledger(&connection)?;
            if !ct_eq(&ledger.0, &intent.store_instance_id)
                || ledger.1 != 0
                || !ct_eq(&ledger.2, &intent.genesis_head)
                || !ct_eq(&ledger.3, &intent.empty_state_root)
                || !ct_eq(&compute_state_root(&connection)?, &intent.empty_state_root)
            {
                return Err(DurableIdempotencyError::Corrupt);
            }
            let manifest = Manifest {
                key_epoch: intent.key_epoch,
                scope_key_epoch: intent.scope_key_epoch,
                store_instance_id: intent.store_instance_id,
                genesis_head: intent.genesis_head,
                sqlite_location_digest: intent.sqlite_location_digest,
                committed_sequence: 0,
                committed_head_digest: intent.genesis_head,
                committed_state_root: intent.empty_state_root,
                pending: None,
            };
            let manifest_bytes = encode_manifest(&manifest, master_key)?;
            anchor.compare_and_swap(Some(&bytes), &manifest_bytes)?;
            Ok((connection, manifest_bytes, manifest))
        }
        Some(2) => {
            if !config.database_path.exists() {
                return Err(DurableIdempotencyError::Corrupt);
            }
            let mut manifest = decode_manifest(&bytes, master_key)?;
            if manifest.key_epoch != config.key_epoch
                || manifest.scope_key_epoch != config.scope_key_epoch
                || !ct_eq(&manifest.sqlite_location_digest, &location_digest)
                || !ct_eq(
                    &manifest.genesis_head,
                    &genesis_head(
                        manifest.store_instance_id,
                        empty_state_root(),
                        location_digest,
                        manifest.scope_key_epoch,
                    ),
                )
            {
                return Err(DurableIdempotencyError::Corrupt);
            }
            let connection = Connection::open(&config.database_path)?;
            configure_connection(&connection)?;
            verify_schema(&connection)?;
            if let Some(pending) = manifest.pending.clone() {
                let ledger = read_ledger(&connection)?;
                let old = ledger.1 == manifest.committed_sequence
                    && ct_eq(&ledger.2, &pending.previous_head)
                    && ct_eq(&ledger.3, &pending.previous_state_root);
                let new = ledger.1 == pending.next_sequence
                    && ct_eq(&ledger.2, &pending.next_head)
                    && ct_eq(&ledger.3, &pending.next_state_root);
                if new {
                    manifest.committed_sequence = pending.next_sequence;
                    manifest.committed_head_digest = pending.next_head;
                    manifest.committed_state_root = pending.next_state_root;
                } else if !old {
                    return Err(DurableIdempotencyError::Corrupt);
                }
                manifest.pending = None;
                let promoted = encode_manifest(&manifest, master_key)?;
                anchor.compare_and_swap(Some(&bytes), &promoted)?;
                return Ok((connection, promoted, manifest));
            }
            Ok((connection, bytes, manifest))
        }
        _ => Err(DurableIdempotencyError::Corrupt),
    }
}

fn create_database(
    path: &Path,
    instance: [u8; 16],
    genesis: [u8; 32],
    empty_root: [u8; 32],
) -> Result<Connection, DurableIdempotencyError> {
    let connection = Connection::open(path)?;
    configure_connection(&connection)?;
    connection.execute_batch(SCHEMA)?;
    connection.execute(
        "INSERT INTO client_idempotency_capacity VALUES(1,0,0,0,0,0,0,0)",
        [],
    )?;
    connection.execute(
        "INSERT INTO client_idempotency_ledger VALUES(1,?1,0,?2,?3)",
        params![
            instance.as_slice(),
            genesis.as_slice(),
            empty_root.as_slice()
        ],
    )?;
    Ok(connection)
}

fn configure_connection(connection: &Connection) -> Result<(), DurableIdempotencyError> {
    connection.pragma_update(None, "journal_mode", "WAL")?;
    connection.pragma_update(None, "synchronous", "FULL")?;
    connection.pragma_update(None, "foreign_keys", "ON")?;
    Ok(())
}

fn verify_schema(connection: &Connection) -> Result<(), DurableIdempotencyError> {
    let tables: i64 = connection.query_row(
        "SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN ('client_idempotency_records','client_idempotency_capacity','client_idempotency_ledger')",
        [],
        |row| row.get(0),
    )?;
    if tables != 3 {
        return Err(DurableIdempotencyError::Corrupt);
    }
    Ok(())
}

fn validate_confined_path(path: &str) -> Result<(), DurableIdempotencyError> {
    if path.is_empty() || path.len() > 1_024 || path.as_bytes().contains(&0) {
        return Err(DurableIdempotencyError::Configuration);
    }
    let path = Path::new(path);
    if path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(DurableIdempotencyError::Configuration);
    }
    Ok(())
}

fn sqlite_location_digest(path: &str) -> Result<[u8; 32], DurableIdempotencyError> {
    validate_confined_path(path)?;
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_LOCATION);
    hasher.update((path.len() as u32).to_be_bytes());
    hasher.update(path.as_bytes());
    Ok(hasher.finalize().into())
}

fn genesis_head(
    instance: [u8; 16],
    empty_root: [u8; 32],
    location: [u8; 32],
    scope_epoch: NonZeroU32,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_GENESIS);
    hasher.update(instance);
    hasher.update(SCHEMA_VERSION.to_be_bytes());
    hasher.update(empty_root);
    hasher.update(location);
    hasher.update(scope_epoch.get().to_be_bytes());
    hasher.finalize().into()
}

#[allow(clippy::too_many_arguments)]
fn encode_bootstrap_intent(
    master_key: &[u8; 32],
    key_epoch: NonZeroU32,
    scope_epoch: NonZeroU32,
    instance: [u8; 16],
    genesis: [u8; 32],
    empty_root: [u8; 32],
    location: [u8; 32],
    nonce: [u8; 32],
) -> Result<Vec<u8>, DurableIdempotencyError> {
    let mut bytes = Vec::with_capacity(BOOTSTRAP_LEN);
    bytes.extend_from_slice(&[1, 1]);
    bytes.extend_from_slice(&key_epoch.get().to_be_bytes());
    bytes.extend_from_slice(&scope_epoch.get().to_be_bytes());
    bytes.extend_from_slice(&instance);
    bytes.extend_from_slice(&SCHEMA_VERSION.to_be_bytes());
    bytes.extend_from_slice(&genesis);
    bytes.extend_from_slice(&empty_root);
    bytes.extend_from_slice(&location);
    bytes.extend_from_slice(&nonce);
    let key = derive_key(master_key, &instance, INFO_BOOTSTRAP_KEY, key_epoch)?;
    bytes.extend_from_slice(&hmac(&key, DOMAIN_BOOTSTRAP, &bytes)?);
    debug_assert_eq!(bytes.len(), BOOTSTRAP_LEN);
    Ok(bytes)
}

struct BootstrapIntent {
    key_epoch: NonZeroU32,
    scope_key_epoch: NonZeroU32,
    store_instance_id: [u8; 16],
    genesis_head: [u8; 32],
    empty_state_root: [u8; 32],
    sqlite_location_digest: [u8; 32],
}

fn decode_bootstrap_intent(
    bytes: &[u8],
    master_key: &[u8; 32],
) -> Result<BootstrapIntent, DurableIdempotencyError> {
    if bytes.len() != BOOTSTRAP_LEN || bytes[..2] != [1, 1] {
        return Err(DurableIdempotencyError::Corrupt);
    }
    let key_epoch = nonzero_u32(&bytes[2..6])?;
    let scope_key_epoch = nonzero_u32(&bytes[6..10])?;
    let instance = array(&bytes[10..26])?;
    if u32::from_be_bytes(array(&bytes[26..30])?) != SCHEMA_VERSION {
        return Err(DurableIdempotencyError::Corrupt);
    }
    let key = derive_key(master_key, &instance, INFO_BOOTSTRAP_KEY, key_epoch)?;
    let expected = hmac(&key, DOMAIN_BOOTSTRAP, &bytes[..158])?;
    if !ct_eq(&expected, &bytes[158..190]) || bytes[126..158] == [0; 32] {
        return Err(DurableIdempotencyError::Corrupt);
    }
    Ok(BootstrapIntent {
        key_epoch,
        scope_key_epoch,
        store_instance_id: instance,
        genesis_head: array(&bytes[30..62])?,
        empty_state_root: array(&bytes[62..94])?,
        sqlite_location_digest: array(&bytes[94..126])?,
    })
}

fn encode_manifest(
    manifest: &Manifest,
    master_key: &[u8; 32],
) -> Result<Vec<u8>, DurableIdempotencyError> {
    let mut bytes = Vec::with_capacity(if manifest.pending.is_some() {
        MANIFEST_PENDING_LEN
    } else {
        MANIFEST_COMMITTED_LEN
    });
    bytes.extend_from_slice(&[1, 2]);
    bytes.extend_from_slice(&manifest.key_epoch.get().to_be_bytes());
    bytes.extend_from_slice(&manifest.scope_key_epoch.get().to_be_bytes());
    bytes.extend_from_slice(&manifest.store_instance_id);
    bytes.extend_from_slice(&manifest.genesis_head);
    bytes.extend_from_slice(&manifest.sqlite_location_digest);
    bytes.extend_from_slice(&manifest.committed_sequence.to_be_bytes());
    bytes.extend_from_slice(&manifest.committed_head_digest);
    bytes.extend_from_slice(&manifest.committed_state_root);
    match &manifest.pending {
        None => bytes.push(0),
        Some(pending) => {
            bytes.push(1);
            bytes.extend_from_slice(&pending.previous_head);
            bytes.extend_from_slice(&pending.previous_state_root);
            bytes.extend_from_slice(&pending.next_sequence.to_be_bytes());
            bytes.extend_from_slice(&pending.next_head);
            bytes.extend_from_slice(&pending.next_state_root);
            bytes.push(pending.operation_tag);
            bytes.extend_from_slice(&pending.write_set_digest);
        }
    }
    let key = derive_key(
        master_key,
        &manifest.store_instance_id,
        INFO_MANIFEST_KEY,
        manifest.key_epoch,
    )?;
    bytes.extend_from_slice(&hmac(&key, DOMAIN_MANIFEST, &bytes)?);
    Ok(bytes)
}

fn decode_manifest(
    bytes: &[u8],
    master_key: &[u8; 32],
) -> Result<Manifest, DurableIdempotencyError> {
    if !matches!(bytes.len(), MANIFEST_COMMITTED_LEN | MANIFEST_PENDING_LEN) || bytes[..2] != [1, 2]
    {
        return Err(DurableIdempotencyError::Corrupt);
    }
    let key_epoch = nonzero_u32(&bytes[2..6])?;
    let scope_key_epoch = nonzero_u32(&bytes[6..10])?;
    let instance = array(&bytes[10..26])?;
    let mac_at = bytes.len() - 32;
    let key = derive_key(master_key, &instance, INFO_MANIFEST_KEY, key_epoch)?;
    if !ct_eq(
        &hmac(&key, DOMAIN_MANIFEST, &bytes[..mac_at])?,
        &bytes[mac_at..],
    ) {
        return Err(DurableIdempotencyError::Corrupt);
    }
    let pending = match bytes[162] {
        0 if bytes.len() == MANIFEST_COMMITTED_LEN => None,
        1 if bytes.len() == MANIFEST_PENDING_LEN => Some(PendingManifest {
            previous_head: array(&bytes[163..195])?,
            previous_state_root: array(&bytes[195..227])?,
            next_sequence: u64::from_be_bytes(array(&bytes[227..235])?),
            next_head: array(&bytes[235..267])?,
            next_state_root: array(&bytes[267..299])?,
            operation_tag: bytes[299],
            write_set_digest: array(&bytes[300..332])?,
        }),
        _ => return Err(DurableIdempotencyError::Corrupt),
    };
    Ok(Manifest {
        key_epoch,
        scope_key_epoch,
        store_instance_id: instance,
        genesis_head: array(&bytes[26..58])?,
        sqlite_location_digest: array(&bytes[58..90])?,
        committed_sequence: u64::from_be_bytes(array(&bytes[90..98])?),
        committed_head_digest: array(&bytes[98..130])?,
        committed_state_root: array(&bytes[130..162])?,
        pending,
    })
}

fn empty_state_root() -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_STATE_ROOT);
    hasher.update([2]);
    hasher.update([1]);
    hasher.update(0u64.to_be_bytes());
    hasher.update([2]);
    hasher.update(1u64.to_be_bytes());
    let key = [1u8];
    let row = encode_capacity_row([0; 7]);
    hasher.update((key.len() as u32).to_be_bytes());
    hasher.update(key);
    hasher.update((row.len() as u32).to_be_bytes());
    hasher.update(row);
    hasher.finalize().into()
}

fn compute_state_root(connection: &Connection) -> Result<[u8; 32], DurableIdempotencyError> {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_STATE_ROOT);
    hasher.update([2]);
    hasher.update([1]);
    let mut statement = connection.prepare(
        "SELECT scope_digest, principal_digest, idempotency_key_digest, request_fingerprint,
                mutation_id, provider_tag, operation_tag, phase, provider_entry_started,
                reservation_token, original_request_id, payload_key_epoch, payload_nonce,
                mutation_payload_ciphertext, recovery_ticket, outcome_blob, outcome_digest,
                created_at_ms, updated_at_ms, terminal_at_ms, expires_at_ms,
                metadata_encoded_bytes, future_metadata_bytes, actual_outcome_bytes,
                future_outcome_bytes, done_slot_reserved
         FROM client_idempotency_records ORDER BY scope_digest",
    )?;
    let rows = statement.query_map([], encode_record_row)?;
    let mut records = Vec::new();
    for row in rows {
        records.push(row?);
    }
    hasher.update((records.len() as u64).to_be_bytes());
    for (key, row) in records {
        hasher.update((key.len() as u32).to_be_bytes());
        hasher.update(key);
        hasher.update((row.len() as u32).to_be_bytes());
        hasher.update(row);
    }
    hasher.update([2]);
    hasher.update(1u64.to_be_bytes());
    let capacity = read_capacity(connection)?;
    let row = encode_capacity_row(capacity);
    hasher.update(1u32.to_be_bytes());
    hasher.update([1]);
    hasher.update((row.len() as u32).to_be_bytes());
    hasher.update(row);
    Ok(hasher.finalize().into())
}

fn encode_record_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<(Vec<u8>, Vec<u8>)> {
    let key: Vec<u8> = row.get(0)?;
    let mut out = Vec::new();
    for index in 0..5 {
        put_blob(&mut out, &row.get::<_, Vec<u8>>(index)?);
    }
    for index in 5..9 {
        put_u64(&mut out, row.get::<_, i64>(index)? as u64);
    }
    put_blob(&mut out, &row.get::<_, Vec<u8>>(9)?);
    put_text(&mut out, &row.get::<_, String>(10)?);
    put_u64(&mut out, row.get::<_, i64>(11)? as u64);
    put_blob(&mut out, &row.get::<_, Vec<u8>>(12)?);
    put_blob(&mut out, &row.get::<_, Vec<u8>>(13)?);
    put_option_blob(&mut out, row.get::<_, Option<Vec<u8>>>(14)?.as_deref());
    let outcome: Option<Vec<u8>> = row.get(15)?;
    match outcome {
        None => out.push(0),
        Some(value) => {
            out.push(1);
            out.extend_from_slice(&(value.len() as u32).to_be_bytes());
        }
    }
    put_option_blob(&mut out, row.get::<_, Option<Vec<u8>>>(16)?.as_deref());
    for index in 17..19 {
        put_u64(&mut out, row.get::<_, i64>(index)? as u64);
    }
    put_option_u64(&mut out, row.get::<_, Option<i64>>(19)?.map(|v| v as u64));
    put_option_u64(&mut out, row.get::<_, Option<i64>>(20)?.map(|v| v as u64));
    for index in 21..26 {
        put_u64(&mut out, row.get::<_, i64>(index)? as u64);
    }
    Ok((key, out))
}

fn read_capacity(connection: &Connection) -> Result<[u64; 7], DurableIdempotencyError> {
    connection
        .query_row(
            "SELECT record_count,live_count,done_count,actual_metadata_bytes,future_metadata_bytes,actual_outcome_bytes,future_outcome_bytes FROM client_idempotency_capacity WHERE singleton=1",
            [],
            |row| {
                Ok([
                    row.get::<_, i64>(0)? as u64,
                    row.get::<_, i64>(1)? as u64,
                    row.get::<_, i64>(2)? as u64,
                    row.get::<_, i64>(3)? as u64,
                    row.get::<_, i64>(4)? as u64,
                    row.get::<_, i64>(5)? as u64,
                    row.get::<_, i64>(6)? as u64,
                ])
            },
        )
        .map_err(Into::into)
}

fn encode_capacity_row(values: [u64; 7]) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    put_u64(&mut out, 1);
    for value in values {
        put_u64(&mut out, value);
    }
    out
}

fn verify_capacity(connection: &Connection) -> Result<(), DurableIdempotencyError> {
    let cached = read_capacity(connection)?;
    let scanned = connection.query_row(
        "SELECT count(*),
                COALESCE(sum(CASE WHEN phase<4 THEN 1 ELSE 0 END),0),
                COALESCE(sum(CASE WHEN phase=4 THEN 1 ELSE 0 END),0),
                COALESCE(sum(metadata_encoded_bytes),0),
                COALESCE(sum(future_metadata_bytes),0),
                COALESCE(sum(actual_outcome_bytes),0),
                COALESCE(sum(future_outcome_bytes),0)
         FROM client_idempotency_records",
        [],
        |row| {
            Ok([
                row.get::<_, i64>(0)? as u64,
                row.get::<_, i64>(1)? as u64,
                row.get::<_, i64>(2)? as u64,
                row.get::<_, i64>(3)? as u64,
                row.get::<_, i64>(4)? as u64,
                row.get::<_, i64>(5)? as u64,
                row.get::<_, i64>(6)? as u64,
            ])
        },
    )?;
    if cached != scanned
        || cached[0] > MAX_RECORDS
        || cached[1] > MAX_LIVE_GLOBAL
        || cached[3]
            .checked_add(cached[4])
            .is_none_or(|v| v > MAX_ACCOUNTED_BYTES)
        || cached[5]
            .checked_add(cached[6])
            .is_none_or(|v| v > MAX_ACCOUNTED_BYTES)
    {
        return Err(DurableIdempotencyError::Corrupt);
    }
    Ok(())
}

fn read_ledger(
    connection: &Connection,
) -> Result<([u8; 16], u64, [u8; 32], [u8; 32]), DurableIdempotencyError> {
    connection
        .query_row(
            "SELECT store_instance_id, committed_sequence, committed_head_digest, committed_state_root FROM client_idempotency_ledger WHERE singleton=1",
            [],
            |row| {
                let instance: Vec<u8> = row.get(0)?;
                let head: Vec<u8> = row.get(2)?;
                let root: Vec<u8> = row.get(3)?;
                Ok((
                    instance.try_into().map_err(|_| rusqlite::Error::InvalidQuery)?,
                    row.get::<_, i64>(1)? as u64,
                    head.try_into().map_err(|_| rusqlite::Error::InvalidQuery)?,
                    root.try_into().map_err(|_| rusqlite::Error::InvalidQuery)?,
                ))
            },
        )
        .map_err(Into::into)
}

fn derive_key(
    master: &[u8; 32],
    salt: &[u8],
    info_domain: &[u8],
    epoch: NonZeroU32,
) -> Result<Zeroizing<[u8; 32]>, DurableIdempotencyError> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), master);
    let mut info = Vec::with_capacity(info_domain.len() + 4);
    info.extend_from_slice(info_domain);
    info.extend_from_slice(&epoch.get().to_be_bytes());
    let mut key = Zeroizing::new([0u8; 32]);
    hkdf.expand(&info, key.as_mut())
        .map_err(|_| DurableIdempotencyError::Crypto)?;
    Ok(key)
}

fn hmac(
    key: &[u8; 32],
    domain: &[u8],
    payload: &[u8],
) -> Result<[u8; 32], DurableIdempotencyError> {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(key).map_err(|_| DurableIdempotencyError::Crypto)?;
    mac.update(domain);
    mac.update(payload);
    Ok(mac.finalize().into_bytes().into())
}

fn nonzero_u32(bytes: &[u8]) -> Result<NonZeroU32, DurableIdempotencyError> {
    NonZeroU32::new(u32::from_be_bytes(array(bytes)?)).ok_or(DurableIdempotencyError::Corrupt)
}

fn array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], DurableIdempotencyError> {
    bytes
        .try_into()
        .map_err(|_| DurableIdempotencyError::Corrupt)
}

fn ct_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len() && bool::from(left.ct_eq(right))
}

fn fill_nonzero<R: RngCore + CryptoRng, const N: usize>(rng: &mut R, bytes: &mut [u8; N]) {
    while bytes.iter().all(|byte| *byte == 0) {
        rng.fill_bytes(bytes);
    }
}

fn put_blob(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value);
}

fn put_text(out: &mut Vec<u8>, value: &str) {
    put_blob(out, value.as_bytes());
}

fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_option_blob(out: &mut Vec<u8>, value: Option<&[u8]>) {
    match value {
        None => out.push(0),
        Some(value) => {
            out.push(1);
            put_blob(out, value);
        }
    }
}

fn put_option_u64(out: &mut Vec<u8>, value: Option<u64>) {
    match value {
        None => out.push(0),
        Some(value) => {
            out.push(1);
            put_u64(out, value);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct MemoryAnchor {
        bytes: Mutex<Option<Vec<u8>>>,
    }

    impl IdempotencyAnchor for MemoryAnchor {
        fn load(&self) -> Result<Option<Vec<u8>>, DurableIdempotencyError> {
            Ok(self.bytes.lock().unwrap().clone())
        }

        fn compare_and_swap(
            &self,
            expected: Option<&[u8]>,
            replacement: &[u8],
        ) -> Result<(), DurableIdempotencyError> {
            let mut current = self.bytes.lock().unwrap();
            let matches = match (expected, current.as_deref()) {
                (None, None) => true,
                (Some(expected), Some(observed)) => ct_eq(expected, observed),
                _ => false,
            };
            if !matches {
                return Err(DurableIdempotencyError::AnchorConflict);
            }
            *current = Some(replacement.to_vec());
            Ok(())
        }
    }

    fn config(path: PathBuf) -> DurableIdempotencyConfig {
        DurableIdempotencyConfig {
            database_path: path,
            confined_relative_path: "idempotency.db".into(),
            workspace_master_key: Zeroizing::new([0x51; 32]),
            key_epoch: NonZeroU32::new(1).unwrap(),
            scope_key_epoch: NonZeroU32::new(2).unwrap(),
            payload_key_epoch: NonZeroU32::new(3).unwrap(),
        }
    }

    fn reserve_input(fingerprint: [u8; 32]) -> DurableReserveInput {
        DurableReserveInput {
            principal: "operator".into(),
            method: "POST".into(),
            family: "grants".into(),
            idempotency_key: "key-1".into(),
            request_fingerprint: fingerprint,
            canonical_request: b"canonical-request".to_vec(),
            provider_tag: 1,
            operation_tag: 1,
            original_request_id: "request-original".into(),
            now_ms: 10,
        }
    }

    fn ticket(reservation: &DurableReservation) -> ProviderMutationRecovery {
        let mut bytes = [0u8; 167];
        bytes[0] = 1;
        bytes[1] = reservation.provider_tag;
        bytes[2] = reservation.operation_tag;
        bytes[3..7].copy_from_slice(&1u32.to_be_bytes());
        bytes[7..39].copy_from_slice(&reservation.mutation_id);
        bytes[39..71].copy_from_slice(&reservation.request_fingerprint);
        bytes[71..103].fill(0x61);
        bytes[103..135].fill(0x62);
        bytes[135..167].fill(0x63);
        ProviderMutationRecovery::from_provider_bytes(bytes).unwrap()
    }

    #[test]
    fn bootstrap_literal_kat() {
        let literal = hex::decode("0101000000020000000301010101010101010101010101010101000000011ce22239755ce096778c8ad318155dff84f52039ad89a77d5176602ae8a0c2c502020202020202020202020202020202020202020202020202020202020202029b943de764445049407a2b2020a3fc17b41845f97c6c523e0dfb89353d8fbb410404040404040404040404040404040404040404040404040404040404040404b74d257f130d79eeccd5218422fa2b81947da9d88526c94183069b0f364d9db6").unwrap();
        let master = [0u8; 32];
        let decoded = decode_bootstrap_intent(&literal, &master).unwrap();
        assert_eq!(decoded.store_instance_id, [1; 16]);
        assert_eq!(decoded.empty_state_root, [2; 32]);
        assert_eq!(decoded.key_epoch.get(), 2);
        assert_eq!(decoded.scope_key_epoch.get(), 3);
        let location = sqlite_location_digest("idempotency.db").unwrap();
        assert_eq!(
            hex::encode(location),
            "9b943de764445049407a2b2020a3fc17b41845f97c6c523e0dfb89353d8fbb41"
        );
        let genesis = genesis_head([1; 16], [2; 32], location, NonZeroU32::new(3).unwrap());
        assert_eq!(
            hex::encode(genesis),
            "1ce22239755ce096778c8ad318155dff84f52039ad89a77d5176602ae8a0c2c5"
        );
        let key = derive_key(
            &master,
            &[1; 16],
            INFO_BOOTSTRAP_KEY,
            NonZeroU32::new(2).unwrap(),
        )
        .unwrap();
        assert_eq!(
            hex::encode(key.as_ref()),
            "c2f47371863ad2984b0fd10abb9021c65ff906ade8f8ba06db9eaf112229c6b1"
        );
        let encoded = encode_bootstrap_intent(
            &master,
            NonZeroU32::new(2).unwrap(),
            NonZeroU32::new(3).unwrap(),
            [1; 16],
            genesis,
            [2; 32],
            location,
            [4; 32],
        )
        .unwrap();
        assert_eq!(encoded, literal);
    }

    #[test]
    fn durable_phase_machine_reopens_and_replays_without_provider_state() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("idempotency.db");
        let anchor = Arc::new(MemoryAnchor::default());
        let repository = DurableIdempotencyRepository::open(config(path.clone()), anchor.clone())
            .expect("bootstrap repository");
        assert_eq!(repository.committed_sequence(), 0);
        let reservation = match repository.reserve(reserve_input([0x71; 32])).unwrap() {
            DurableBegin::Reserved(reservation) => reservation,
            _ => panic!("expected reservation"),
        };
        assert_eq!(repository.committed_sequence(), 1);
        assert!(matches!(
            repository.reserve(reserve_input([0x71; 32])).unwrap(),
            DurableBegin::InProgress
        ));
        assert!(matches!(
            repository.reserve(reserve_input([0x72; 32])).unwrap(),
            DurableBegin::Conflict
        ));
        let recovery = repository.recovery_rows().unwrap();
        assert_eq!(recovery.len(), 1);
        assert_eq!(recovery[0].phase, PHASE_PENDING);
        assert_eq!(
            recovery[0].canonical_request.as_slice(),
            b"canonical-request"
        );

        repository.mark_provider_entry(&reservation, 11).unwrap();
        let ticket = ticket(&reservation);
        repository
            .store_prepared_ticket(&reservation, &ticket, 12)
            .unwrap();
        repository.mark_recovering(&reservation, None, 13).unwrap();
        let rows = repository.recovery_rows().unwrap();
        assert_eq!(rows[0].phase, PHASE_RECOVERING);
        assert!(rows[0].recovery_ticket.is_some());
        let receipt = repository
            .finish_done(&reservation, br#"{"terminal":"approved"}"#, 14)
            .unwrap();
        assert_eq!(receipt.as_provider_bytes().len(), DONE_RECEIPT_LEN);
        assert!(repository.recovery_rows().unwrap().is_empty());
        match repository.reserve(reserve_input([0x71; 32])).unwrap() {
            DurableBegin::Replay(done) => {
                assert_eq!(done.original_request_id, "request-original");
                assert_eq!(done.outcome_blob, br#"{"terminal":"approved"}"#);
            }
            _ => panic!("expected replay"),
        }
        let sequence = repository.committed_sequence();
        drop(repository);

        let reopened = DurableIdempotencyRepository::open(config(path), anchor).unwrap();
        assert_eq!(reopened.committed_sequence(), sequence);
        assert!(matches!(
            reopened.reserve(reserve_input([0x71; 32])).unwrap(),
            DurableBegin::Replay(_)
        ));
    }

    #[test]
    fn per_principal_live_capacity_rejects_before_the_thirty_third_reservation() {
        let dir = tempfile::tempdir().unwrap();
        let repository = DurableIdempotencyRepository::open(
            config(dir.path().join("idempotency.db")),
            Arc::new(MemoryAnchor::default()),
        )
        .unwrap();
        for index in 0..MAX_LIVE_PER_PRINCIPAL {
            let mut input = reserve_input([index as u8; 32]);
            input.idempotency_key = format!("key-{index}");
            assert!(matches!(
                repository.reserve(input).unwrap(),
                DurableBegin::Reserved(_)
            ));
        }
        let mut overflow = reserve_input([0xf0; 32]);
        overflow.idempotency_key = "key-overflow".into();
        assert!(matches!(
            repository.reserve(overflow).unwrap(),
            DurableBegin::Capacity
        ));
        assert_eq!(repository.committed_sequence(), MAX_LIVE_PER_PRINCIPAL);
    }

    #[test]
    fn sqlite_postimage_tamper_is_rejected_against_the_retained_anchor() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("idempotency.db");
        let anchor = Arc::new(MemoryAnchor::default());
        let repository =
            DurableIdempotencyRepository::open(config(path.clone()), anchor.clone()).unwrap();
        let reservation = match repository.reserve(reserve_input([0xa1; 32])).unwrap() {
            DurableBegin::Reserved(reservation) => reservation,
            _ => panic!("reserved"),
        };
        repository.mark_provider_entry(&reservation, 11).unwrap();
        drop(repository);
        let connection = Connection::open(&path).unwrap();
        connection
            .execute(
                "UPDATE client_idempotency_records SET updated_at_ms=updated_at_ms+1",
                [],
            )
            .unwrap();
        drop(connection);
        assert!(matches!(
            DurableIdempotencyRepository::open(config(path), anchor),
            Err(DurableIdempotencyError::Corrupt)
        ));
    }
}

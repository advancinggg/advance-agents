//! Named T47/T50 evidence kept separate from the lifecycle-state witnesses.
//!
//! The carrier/keyring fixture below is deliberately a second implementation
//! of the wire format.  It writes the ratified fields directly and computes
//! expected roots itself; no production encoder is used to manufacture an
//! expected value.

use super::*;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex as StdMutex};

use advance_scheduler::observation_anchor::{
    classify_recovery, persisted_keyring_file_root, registry_marker_root,
    role_allocation_file_root, PreparedLegacyRegistryMigration, PreparedPersistedKeyringMutation,
    RegistryRecoveryDecision, VerifiedLegacyRegistryMigrationGenesis,
};
#[cfg(feature = "test-support")]
use advance_scheduler::sensitive_params::{
    CarrierMigrationRecoveryPhase, CarrierMigrationStore, ObservationMutationFailpointStage,
    VerifiedLegacyMigrationComplete,
};
use advance_shared_types::contract218_previsible::{
    CustodySignedPersistedIdentity, PersistedIdentityKeyCapabilityBinding,
    PersistedIdentityKeyStatus, PersistedIdentityKeyringBinding, PersistedIdentityKeyringProvider,
    PersistedIdentityKeyringRole, PersistedIdentitySigningRequest,
    PersistedIdentityVerificationRequest, PersistedKeyRetirementScanSet,
    VerifiedPersistedKeyRetirementScanSet,
};
use advance_shared_types::observation_identity::{
    ObservationIdentityClass, ObservationIdentityPersistenceSealer, PersistedObservationBinding,
    PersistedObservationIdentity, SensitiveParamDeclaration, TrustedObservationIdentity,
};
use advance_shared_types::test_support::persisted_key_retirement_scans;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

const REGISTRY_INSTANCE: [u8; 16] = [0x11; 16];
const BOOT: [u8; 16] = [0x22; 16];
const ROLE_ROOT: [u8; 32] = [0x55; 32];
const KEYRING_SALT: [u8; 32] = [0x66; 32];
const KEYRING_ROOT_DOMAIN: &[u8] = b"advance.contract218.persisted-keyring-file.v1\0";
const CARRIER_MAC_DOMAIN: &[u8] = b"advance.contract218.persisted-identity.v1\0";
const ROLE_ALLOCATION_ROOT_DOMAIN: &[u8] = b"advance.contract218.role-allocation-file.v1\0";
const LEGACY_INVENTORY_DOMAIN: &[u8] = b"advance.contract218.legacy-registry-inventory.v1\0";
const LEGACY_PROJECTION_DOMAIN: &[u8] = b"advance.contract218.legacy-registry-projection.v1\0";
const REGISTRY_STATE_ROOT_DOMAIN: &[u8] = b"advance.contract218.registry-state-root.v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FixtureKeyStatus {
    Signing,
    VerifyOnly,
    Retired,
}

impl FixtureKeyStatus {
    fn wire(self) -> u8 {
        match self {
            Self::Signing => 1,
            Self::VerifyOnly => 2,
            Self::Retired => 3,
        }
    }

    fn shared(self) -> PersistedIdentityKeyStatus {
        match self {
            Self::Signing => PersistedIdentityKeyStatus::Signing,
            Self::VerifyOnly => PersistedIdentityKeyStatus::VerifyOnly,
            Self::Retired => PersistedIdentityKeyStatus::Retired,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FixtureScan {
    sqlite_sequence: u64,
    jsonl_inventory_digest: [u8; 32],
    jsonl_segment_count: u64,
    jsonl_byte_count: u64,
    retention_high_water: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FixtureKeyEntry {
    key_id: u32,
    status: FixtureKeyStatus,
    master_key_epoch: u32,
    last_issued_at_ms: u64,
    scan: Option<FixtureScan>,
    key: [u8; 32],
}

#[derive(Clone)]
struct FixtureKeyringImage {
    generation: u64,
    signing_key_id: u32,
    next_key_id: u64,
    entries: BTreeMap<u32, FixtureKeyEntry>,
    bytes: Vec<u8>,
}

impl FixtureKeyringImage {
    fn binding(&self) -> PersistedIdentityKeyringBinding {
        PersistedIdentityKeyringBinding::from_authenticated_keyring(
            REGISTRY_INSTANCE,
            independent_keyring_root(&self.bytes),
            self.generation,
        )
        .unwrap()
    }
}

struct FixtureKeyringState {
    current: FixtureKeyringImage,
    pending: Option<FixtureKeyringImage>,
    fail_promote_once: bool,
}

impl FixtureKeyringState {
    fn new() -> Self {
        let entry = FixtureKeyEntry {
            key_id: 1,
            status: FixtureKeyStatus::Signing,
            master_key_epoch: 1,
            last_issued_at_ms: 0,
            scan: None,
            key: fixture_key(1, 1),
        };
        let entries = BTreeMap::from([(1, entry)]);
        let bytes = encode_keyring_file(0, [0; 32], 1, 2, &entries);
        Self {
            current: FixtureKeyringImage {
                generation: 0,
                signing_key_id: 1,
                next_key_id: 2,
                entries,
                bytes,
            },
            pending: None,
            fail_promote_once: false,
        }
    }
}

fn fixture_key(key_id: u32, epoch: u32) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"advance.contract218.scheduler-test-carrier-key.v1\0");
    hasher.update(key_id.to_be_bytes());
    hasher.update(epoch.to_be_bytes());
    hasher.finalize().into()
}

fn independent_keyring_root(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(KEYRING_ROOT_DOMAIN);
    hasher.update(bytes);
    hasher.finalize().into()
}

fn encode_keyring_file(
    generation: u64,
    previous_root: [u8; 32],
    signing_key_id: u32,
    next_key_id: u64,
    entries: &BTreeMap<u32, FixtureKeyEntry>,
) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.push(1);
    bytes.extend_from_slice(&1_u32.to_be_bytes());
    bytes.extend_from_slice(&REGISTRY_INSTANCE);
    bytes.extend_from_slice(&generation.to_be_bytes());
    bytes.extend_from_slice(&previous_root);
    bytes.extend_from_slice(&KEYRING_SALT);
    bytes.extend_from_slice(&next_key_id.to_be_bytes());
    bytes.extend_from_slice(&signing_key_id.to_be_bytes());
    bytes.extend_from_slice(&(entries.len() as u32).to_be_bytes());
    for entry in entries.values() {
        bytes.extend_from_slice(&entry.key_id.to_be_bytes());
        bytes.push(entry.status.wire());
        bytes.extend_from_slice(&entry.master_key_epoch.to_be_bytes());
        bytes.extend_from_slice(&entry.last_issued_at_ms.to_be_bytes());
        match &entry.scan {
            None => bytes.push(0),
            Some(scan) => {
                bytes.push(1);
                bytes.extend_from_slice(&scan.sqlite_sequence.to_be_bytes());
                bytes.extend_from_slice(&scan.jsonl_inventory_digest);
                bytes.extend_from_slice(&scan.jsonl_segment_count.to_be_bytes());
                bytes.extend_from_slice(&scan.jsonl_byte_count.to_be_bytes());
                bytes.extend_from_slice(&scan.retention_high_water.to_be_bytes());
            }
        }
    }
    let nonce_byte = u8::try_from(generation % 251 + 1).unwrap();
    bytes.extend_from_slice(&[nonce_byte; 32]);
    let mut mac = HmacSha256::new_from_slice(&[0xa5; 32]).unwrap();
    mac.update(&bytes);
    bytes.extend_from_slice(&mac.finalize().into_bytes());
    bytes
}

fn carrier_mac(key: &[u8; 32], canonical: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).unwrap();
    mac.update(CARRIER_MAC_DOMAIN);
    mac.update(canonical);
    mac.finalize().into_bytes().into()
}

#[derive(Clone)]
struct FixtureCarrierProvider {
    state: Arc<StdMutex<FixtureKeyringState>>,
}

impl FixtureCarrierProvider {
    fn capability(
        state: &FixtureKeyringState,
        key_id: u32,
    ) -> Result<PersistedIdentityKeyCapabilityBinding, SensitiveParamCatalogError> {
        let entry = state
            .current
            .entries
            .get(&key_id)
            .ok_or(SensitiveParamCatalogError::UnknownIdentity)?;
        PersistedIdentityKeyCapabilityBinding::from_authenticated_keyring(
            state.current.binding(),
            key_id,
            entry.master_key_epoch,
            entry.status.shared(),
        )
    }
}

impl PersistedIdentityKeyringProvider for FixtureCarrierProvider {
    fn current_keyring_binding(
        &self,
    ) -> Result<PersistedIdentityKeyringBinding, SensitiveParamCatalogError> {
        Ok(self.state.lock().unwrap().current.binding())
    }

    fn signing_key_binding(
        &self,
    ) -> Result<PersistedIdentityKeyCapabilityBinding, SensitiveParamCatalogError> {
        let state = self.state.lock().unwrap();
        Self::capability(&state, state.current.signing_key_id)
    }

    fn verification_key_binding(
        &self,
        key_id: u32,
    ) -> Result<PersistedIdentityKeyCapabilityBinding, SensitiveParamCatalogError> {
        let state = self.state.lock().unwrap();
        let entry = state
            .current
            .entries
            .get(&key_id)
            .ok_or(SensitiveParamCatalogError::UnknownIdentity)?;
        if entry.status == FixtureKeyStatus::Retired {
            return Err(SensitiveParamCatalogError::UnknownIdentity);
        }
        Self::capability(&state, key_id)
    }

    fn sign_persisted_identity(
        &self,
        request: &PersistedIdentitySigningRequest,
    ) -> Result<CustodySignedPersistedIdentity, SensitiveParamCatalogError> {
        let state = self.state.lock().unwrap();
        let expected = Self::capability(&state, state.current.signing_key_id)?;
        if request.key_binding() != expected {
            return Err(SensitiveParamCatalogError::InvalidCarrier);
        }
        let entry = state
            .current
            .entries
            .get(&state.current.signing_key_id)
            .unwrap();
        let mut canonical = request.canonical_preceding_bytes().to_vec();
        let mac = carrier_mac(&entry.key, &canonical);
        canonical.extend_from_slice(&mac);
        Ok(CustodySignedPersistedIdentity::from_typed_signing_operation(canonical))
    }

    fn verify_persisted_identity(
        &self,
        request: &PersistedIdentityVerificationRequest,
    ) -> Result<(), SensitiveParamCatalogError> {
        let state = self.state.lock().unwrap();
        let key_id = request.key_binding().key_id();
        let expected = Self::capability(&state, key_id)?;
        let entry = state
            .current
            .entries
            .get(&key_id)
            .ok_or(SensitiveParamCatalogError::UnknownIdentity)?;
        if entry.status == FixtureKeyStatus::Retired || request.key_binding() != expected {
            return Err(SensitiveParamCatalogError::InvalidCarrier);
        }
        let canonical = request.canonical_bytes();
        if canonical.len() < 32 {
            return Err(SensitiveParamCatalogError::InvalidCarrier);
        }
        let split = canonical.len() - 32;
        let expected_mac = carrier_mac(&entry.key, &canonical[..split]);
        if expected_mac.as_slice() == &canonical[split..] {
            Ok(())
        } else {
            Err(SensitiveParamCatalogError::InvalidCarrier)
        }
    }
}

enum FixtureKeyringChange {
    LastIssued { key_id: u32, issued_at_ms: u64 },
    Rotate { master_key_epoch: u32 },
    Retire { key_id: u32, scan: FixtureScan },
}

#[derive(Clone)]
struct FixtureKeyringCustody {
    state: Arc<StdMutex<FixtureKeyringState>>,
    anchor: Arc<dyn RegistryAnchorTransaction>,
}

impl FixtureKeyringCustody {
    fn prepare(
        &self,
        change: FixtureKeyringChange,
        head_context: RegistryHeadContext,
    ) -> Result<Box<dyn PreparedPersistedKeyringCustodyMutation>, RegistryAnchorError> {
        let current_tuple = match self.anchor.observe()? {
            RegistryAnchorWorld::CompactCurrent { current, .. } => current,
            _ => {
                return Err(RegistryAnchorError::RecoveryRequired(
                    "keyring preparation requires a compact anchor".into(),
                ))
            }
        };
        let mut state = self.state.lock().unwrap();
        if state.pending.is_some() {
            return Err(RegistryAnchorError::CompareAndSwapFailed);
        }
        let previous = state.current.clone();
        let previous_root = independent_keyring_root(&previous.bytes);
        if previous_root != current_tuple.keyring_root
            || persisted_keyring_file_root(&previous.bytes) != previous_root
        {
            return Err(RegistryAnchorError::AuthenticationFailed);
        }

        let mut entries = previous.entries.clone();
        let mut signing_key_id = previous.signing_key_id;
        let mut next_key_id = previous.next_key_id;
        match change {
            FixtureKeyringChange::LastIssued {
                key_id,
                issued_at_ms,
            } => {
                let entry = entries
                    .get_mut(&key_id)
                    .ok_or(RegistryAnchorError::InvalidTransition)?;
                if entry.status != FixtureKeyStatus::Signing {
                    return Err(RegistryAnchorError::InvalidTransition);
                }
                entry.last_issued_at_ms = entry.last_issued_at_ms.max(issued_at_ms);
            }
            FixtureKeyringChange::Rotate { master_key_epoch } => {
                if master_key_epoch == 0 {
                    return Err(RegistryAnchorError::InvalidTransition);
                }
                let old = entries
                    .get_mut(&signing_key_id)
                    .ok_or(RegistryAnchorError::InvalidTransition)?;
                old.status = FixtureKeyStatus::VerifyOnly;
                let allocated = u32::try_from(next_key_id)
                    .map_err(|_| RegistryAnchorError::InvalidTransition)?;
                entries.insert(
                    allocated,
                    FixtureKeyEntry {
                        key_id: allocated,
                        status: FixtureKeyStatus::Signing,
                        master_key_epoch,
                        last_issued_at_ms: 0,
                        scan: None,
                        key: fixture_key(allocated, master_key_epoch),
                    },
                );
                signing_key_id = allocated;
                next_key_id = next_key_id
                    .checked_add(1)
                    .ok_or(RegistryAnchorError::GenerationExhausted)?;
            }
            FixtureKeyringChange::Retire { key_id, scan } => {
                let entry = entries
                    .get_mut(&key_id)
                    .ok_or(RegistryAnchorError::InvalidTransition)?;
                if entry.status != FixtureKeyStatus::VerifyOnly {
                    return Err(RegistryAnchorError::InvalidTransition);
                }
                entry.status = FixtureKeyStatus::Retired;
                entry.scan = Some(scan);
            }
        }

        let generation = previous
            .generation
            .checked_add(1)
            .ok_or(RegistryAnchorError::GenerationExhausted)?;
        let bytes = encode_keyring_file(
            generation,
            previous_root,
            signing_key_id,
            next_key_id,
            &entries,
        );
        let next = FixtureKeyringImage {
            generation,
            signing_key_id,
            next_key_id,
            entries,
            bytes,
        };
        let previous_binding = previous.binding();
        let next_binding = next.binding();
        let prepared = PreparedPersistedKeyringMutation::fixture_for_test(
            self.anchor.as_ref(),
            current_tuple,
            head_context,
            &previous.bytes,
            &next.bytes,
        )?;
        let expected_anchor = prepared.next().clone();
        state.pending = Some(next.clone());
        Ok(Box::new(FixturePreparedCustodyMutation {
            state: Arc::clone(&self.state),
            previous_binding,
            next_binding,
            prepared: Some(prepared),
            expected_anchor,
            next,
        }))
    }

    fn recover_promoted_pending(&self) -> Result<(), RegistryAnchorError> {
        let anchored = match self.anchor.observe()? {
            RegistryAnchorWorld::CompactCurrent { current, .. } => current,
            _ => return Err(RegistryAnchorError::InvalidTransition),
        };
        let mut state = self.state.lock().unwrap();
        let pending = state
            .pending
            .take()
            .ok_or(RegistryAnchorError::InvalidTransition)?;
        if independent_keyring_root(&pending.bytes) != anchored.keyring_root {
            state.pending = Some(pending);
            return Err(RegistryAnchorError::RecoveryRequired(
                "pending keyring is not the anchored successor".into(),
            ));
        }
        state.current = pending;
        Ok(())
    }
}

impl PersistedKeyringCustody for FixtureKeyringCustody {
    fn authenticated_current_file(
        &self,
        expected_registry_instance: [u8; 16],
    ) -> Result<Vec<u8>, RegistryAnchorError> {
        if expected_registry_instance != REGISTRY_INSTANCE {
            return Err(RegistryAnchorError::AuthenticationFailed);
        }
        Ok(self.state.lock().unwrap().current.bytes.clone())
    }

    fn prepare_last_issued_replacement(
        &self,
        key_id: u32,
        issued_at_ms: u64,
        head_context: RegistryHeadContext,
    ) -> Result<Box<dyn PreparedPersistedKeyringCustodyMutation>, RegistryAnchorError> {
        self.prepare(
            FixtureKeyringChange::LastIssued {
                key_id,
                issued_at_ms,
            },
            head_context,
        )
    }

    fn prepare_signing_rotation(
        &self,
        new_signing_master_key_epoch: u32,
        head_context: RegistryHeadContext,
    ) -> Result<Box<dyn PreparedPersistedKeyringCustodyMutation>, RegistryAnchorError> {
        self.prepare(
            FixtureKeyringChange::Rotate {
                master_key_epoch: new_signing_master_key_epoch,
            },
            head_context,
        )
    }

    fn prepare_retirement(
        &self,
        verified_scans: VerifiedPersistedKeyRetirementScanSet,
        head_context: RegistryHeadContext,
    ) -> Result<Box<dyn PreparedPersistedKeyringCustodyMutation>, RegistryAnchorError> {
        let metadata = verified_scans.metadata();
        self.prepare(
            FixtureKeyringChange::Retire {
                key_id: metadata.key_id,
                scan: FixtureScan {
                    sqlite_sequence: metadata.sqlite.high_water,
                    jsonl_inventory_digest: metadata.jsonl.inventory_digest,
                    jsonl_segment_count: metadata.jsonl.segment_count,
                    jsonl_byte_count: metadata.jsonl.byte_count,
                    retention_high_water: metadata.jsonl.retention_high_water,
                },
            },
            head_context,
        )
    }
}

struct FixturePreparedCustodyMutation {
    state: Arc<StdMutex<FixtureKeyringState>>,
    previous_binding: PersistedIdentityKeyringBinding,
    next_binding: PersistedIdentityKeyringBinding,
    prepared: Option<PreparedPersistedKeyringMutation>,
    expected_anchor: RegistryAnchorTuple,
    next: FixtureKeyringImage,
}

impl PreparedPersistedKeyringCustodyMutation for FixturePreparedCustodyMutation {
    fn previous_binding(&self) -> PersistedIdentityKeyringBinding {
        self.previous_binding
    }

    fn next_binding(&self) -> PersistedIdentityKeyringBinding {
        self.next_binding
    }

    fn take_scheduler_preparation(
        &mut self,
    ) -> Result<PreparedPersistedKeyringMutation, RegistryAnchorError> {
        self.prepared
            .take()
            .ok_or(RegistryAnchorError::InvalidTransition)
    }

    fn promote_after_anchor(
        self: Box<Self>,
        anchored: &RegistryAnchorTuple,
    ) -> Result<(), RegistryAnchorError> {
        if anchored != &self.expected_anchor
            || anchored.keyring_root != independent_keyring_root(&self.next.bytes)
        {
            return Err(RegistryAnchorError::RecoveryRequired(
                "scheduler promoted a different keyring tuple".into(),
            ));
        }
        let mut state = self.state.lock().unwrap();
        if state.fail_promote_once {
            state.fail_promote_once = false;
            return Err(RegistryAnchorError::Unavailable(
                "fixture failpoint: owner promotion acknowledgement".into(),
            ));
        }
        if state.pending.as_ref().map(|image| image.bytes.as_slice())
            != Some(self.next.bytes.as_slice())
        {
            return Err(RegistryAnchorError::CompareAndSwapFailed);
        }
        state.current = self.next;
        state.pending = None;
        Ok(())
    }
}

fn install_fixture_keyring(
    verifier: &mut PrevisibleProofVerifierRole,
    state: Arc<StdMutex<FixtureKeyringState>>,
) -> PersistedIdentityKeyringRole {
    verifier
        .take_persisted_identity_keyring_installer()
        .unwrap()
        .install_authenticated_custody(Box::new(FixtureCarrierProvider { state }))
        .unwrap()
}

async fn open_fixture_provider(
    registry: Arc<ComponentRegistry>,
    anchor: MemoryAnchor,
    state: Arc<StdMutex<FixtureKeyringState>>,
) -> (
    Arc<RegistrySensitiveParamProvider>,
    Arc<FixtureKeyringCustody>,
) {
    open_fixture_provider_with_anchor(registry, Arc::new(anchor), state).await
}

async fn open_fixture_provider_with_anchor(
    registry: Arc<ComponentRegistry>,
    anchor: Arc<dyn RegistryAnchorTransaction>,
    state: Arc<StdMutex<FixtureKeyringState>>,
) -> (
    Arc<RegistrySensitiveParamProvider>,
    Arc<FixtureKeyringCustody>,
) {
    let (_issuer, mut verifier, termination, _cleanup_issuer, cleanup_verifier) = roles();
    let current = state.lock().unwrap().current.clone();
    assert_eq!(
        persisted_keyring_file_root(&current.bytes),
        independent_keyring_root(&current.bytes),
        "the independent literal fixture must agree with the production root verifier"
    );
    let mut config = ObservationProviderConfig::greenfield(
        REGISTRY_INSTANCE,
        BOOT,
        ROLE_ROOT,
        current.bytes.clone(),
    )
    .unwrap();
    config.signing_key_id = current.signing_key_id;
    config.master_key_epoch = current
        .entries
        .get(&current.signing_key_id)
        .unwrap()
        .master_key_epoch;
    let keyring = install_fixture_keyring(&mut verifier, Arc::clone(&state));
    let custody = Arc::new(FixtureKeyringCustody {
        state,
        anchor: Arc::clone(&anchor),
    });
    let provider = RegistrySensitiveParamProvider::open(
        registry,
        anchor,
        config,
        verifier,
        keyring,
        custody.clone(),
        termination,
        cleanup_verifier,
    )
    .await
    .unwrap();
    (provider, custody)
}

fn register_runtime_identity(
    provider: &RegistrySensitiveParamProvider,
) -> TrustedObservationIdentity {
    let source = provider.register_host(HostEmitterId::Runtime).unwrap();
    provider.mint_live_identity(source.handle()).unwrap()
}

#[derive(Debug, Eq, PartialEq)]
struct ParsedCarrierPrefix {
    key_id: u32,
    event_id: String,
    cursor: String,
    exact_id: String,
    class_tag: u8,
    incarnation: u64,
    declaration_digest: [u8; 32],
    safe_event_digest: [u8; 32],
}

fn parse_text(bytes: &[u8], offset: &mut usize) -> String {
    let end = offset.checked_add(4).unwrap();
    let len = u32::from_be_bytes(bytes[*offset..end].try_into().unwrap()) as usize;
    *offset = end;
    let end = offset.checked_add(len).unwrap();
    let value = std::str::from_utf8(&bytes[*offset..end])
        .unwrap()
        .to_owned();
    *offset = end;
    value
}

fn parse_carrier_prefix(carrier: &PersistedObservationIdentity) -> ParsedCarrierPrefix {
    let bytes = carrier.canonical_bytes();
    assert_eq!(bytes[0], 1);
    let key_id = u32::from_be_bytes(bytes[1..5].try_into().unwrap());
    let mut offset = 5;
    let event_id = parse_text(bytes, &mut offset);
    let cursor = parse_text(bytes, &mut offset);
    let exact_id = parse_text(bytes, &mut offset);
    let class_tag = bytes[offset];
    offset += 1;
    let incarnation = u64::from_be_bytes(bytes[offset..offset + 8].try_into().unwrap());
    offset += 8;
    let declaration_digest = bytes[offset..offset + 32].try_into().unwrap();
    offset += 32;
    let safe_event_digest = bytes[offset..offset + 32].try_into().unwrap();
    offset += 32;
    assert_eq!(
        offset + 32,
        bytes.len(),
        "only the MAC may trail the prefix"
    );
    ParsedCarrierPrefix {
        key_id,
        event_id,
        cursor,
        exact_id,
        class_tag,
        incarnation,
        declaration_digest,
        safe_event_digest,
    }
}

fn literal_tuple(instance: [u8; 16], sequence: u64, discriminator: u8) -> RegistryAnchorTuple {
    RegistryAnchorTuple {
        registry_instance: instance,
        sequence,
        head: [discriminator; 32],
        state_root: [discriminator.wrapping_add(1); 32],
        keyring_root: [discriminator.wrapping_add(2); 32],
        role_allocation_root: [discriminator.wrapping_add(3); 32],
        migration_digest: [0x7f; 32],
    }
}

fn literal_successor(previous: &RegistryAnchorTuple, discriminator: u8) -> RegistryAnchorTuple {
    let mut next = literal_tuple(
        previous.registry_instance,
        previous.sequence + 1,
        discriminator,
    );
    next.migration_digest = previous.migration_digest;
    next
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InjectedAnchorFailure {
    PrepareCurrent,
    DatabaseCommitted,
    SelectNext,
    Compact,
}

fn consume_failure(
    slot: &StdMutex<Option<InjectedAnchorFailure>>,
    expected: InjectedAnchorFailure,
) -> bool {
    let mut armed = slot.lock().unwrap();
    if *armed == Some(expected) {
        *armed = None;
        true
    } else {
        false
    }
}

#[derive(Clone, Default)]
struct FailpointAnchor {
    inner: MemoryAnchor,
    fail_once: Arc<StdMutex<Option<InjectedAnchorFailure>>>,
}

impl FailpointAnchor {
    fn arm(&self, failure: InjectedAnchorFailure) {
        *self.fail_once.lock().unwrap() = Some(failure);
    }

    fn hit(&self, failure: InjectedAnchorFailure) -> bool {
        consume_failure(&self.fail_once, failure)
    }

    fn world(&self) -> RegistryAnchorWorld {
        self.inner.observe().unwrap()
    }
}

impl RegistryAnchorTransaction for FailpointAnchor {
    fn observe(&self) -> Result<RegistryAnchorWorld, RegistryAnchorError> {
        self.inner.observe()
    }

    fn anchor_lease_tag(&self, challenge: [u8; 32]) -> Result<[u8; 32], RegistryAnchorError> {
        self.inner.anchor_lease_tag(challenge)
    }

    fn authenticate_role_allocation_artifacts(
        &self,
        current: &RegistryAnchorTuple,
        context: &RegistryHeadContext,
        previous: &[u8],
        next: &[u8],
    ) -> Result<(), RegistryAnchorError> {
        self.inner
            .authenticate_role_allocation_artifacts(current, context, previous, next)
    }

    fn authenticate_persisted_keyring_artifacts(
        &self,
        current: &RegistryAnchorTuple,
        context: &RegistryHeadContext,
        previous: &[u8],
        next: &[u8],
    ) -> Result<(), RegistryAnchorError> {
        self.inner
            .authenticate_persisted_keyring_artifacts(current, context, previous, next)
    }

    fn initialize_compact(
        &self,
        genesis: VerifiedEmptyRegistryGenesis,
    ) -> Result<(), RegistryAnchorError> {
        self.inner.initialize_compact(genesis)
    }

    fn prepare_current(
        &self,
        mutation: RegistryAnchorMutation,
    ) -> Result<Box<dyn PreparedCurrent>, RegistryAnchorError> {
        if self.hit(InjectedAnchorFailure::PrepareCurrent) {
            return Err(RegistryAnchorError::Unavailable(
                "fixture failpoint: prepare-current".into(),
            ));
        }
        Ok(Box::new(FailpointPrepared {
            inner: self.inner.prepare_current(mutation)?,
            fail_once: Arc::clone(&self.fail_once),
        }))
    }

    fn recover(&self, capability: RegistryRecoveryCapability) -> Result<(), RegistryAnchorError> {
        self.inner.recover(capability)
    }
}

struct FailpointPrepared {
    inner: Box<dyn PreparedCurrent>,
    fail_once: Arc<StdMutex<Option<InjectedAnchorFailure>>>,
}

impl PreparedCurrent for FailpointPrepared {
    fn database_committed(
        self: Box<Self>,
        committed: RegistryDatabaseCommitProof,
    ) -> Result<Box<dyn DatabaseCommitted>, RegistryAnchorError> {
        if consume_failure(&self.fail_once, InjectedAnchorFailure::DatabaseCommitted) {
            return Err(RegistryAnchorError::Unavailable(
                "fixture failpoint: database-committed acknowledgement".into(),
            ));
        }
        Ok(Box::new(FailpointCommitted {
            inner: self.inner.database_committed(committed)?,
            fail_once: self.fail_once,
        }))
    }
}

struct FailpointCommitted {
    inner: Box<dyn DatabaseCommitted>,
    fail_once: Arc<StdMutex<Option<InjectedAnchorFailure>>>,
}

impl DatabaseCommitted for FailpointCommitted {
    fn select_next(self: Box<Self>) -> Result<Box<dyn SelectedNext>, RegistryAnchorError> {
        if consume_failure(&self.fail_once, InjectedAnchorFailure::SelectNext) {
            return Err(RegistryAnchorError::Unavailable(
                "fixture failpoint: select-next".into(),
            ));
        }
        Ok(Box::new(FailpointSelected {
            inner: self.inner.select_next()?,
            fail_once: self.fail_once,
        }))
    }
}

struct FailpointSelected {
    inner: Box<dyn SelectedNext>,
    fail_once: Arc<StdMutex<Option<InjectedAnchorFailure>>>,
}

impl SelectedNext for FailpointSelected {
    fn compact(self: Box<Self>) -> Result<Box<dyn Compacted>, RegistryAnchorError> {
        if consume_failure(&self.fail_once, InjectedAnchorFailure::Compact) {
            return Err(RegistryAnchorError::Unavailable(
                "fixture failpoint: compact".into(),
            ));
        }
        self.inner.compact()
    }
}

fn independent_role_allocation_root(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ROLE_ALLOCATION_ROOT_DOMAIN);
    hasher.update(bytes);
    hasher.finalize().into()
}

fn empty_role_allocation_file() -> Vec<u8> {
    let mut bytes = Vec::with_capacity(105);
    bytes.push(1);
    bytes.extend_from_slice(&1_u32.to_be_bytes());
    bytes.extend_from_slice(&REGISTRY_INSTANCE);
    bytes.extend_from_slice(&0_u64.to_be_bytes());
    bytes.extend_from_slice(&1_u64.to_be_bytes());
    bytes.extend_from_slice(&0_u32.to_be_bytes());
    bytes.extend_from_slice(&[0x71; 32]);
    // Authentication is owned by the external custody fixture.  The
    // scheduler intentionally parses only the complete canonical framing.
    bytes.extend_from_slice(&[0x72; 32]);
    assert_eq!(bytes.len(), 105);
    bytes
}

fn put_test_frame(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn put_test_text(out: &mut Vec<u8>, value: &str) {
    put_test_frame(out, value.as_bytes());
}

fn put_test_blob(out: &mut Vec<u8>, value: &[u8]) {
    put_test_frame(out, value);
}

fn canonical_sensitive_tail(names: &[String]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(names.len() as u32).to_be_bytes());
    for name in names {
        put_test_text(&mut bytes, name);
    }
    bytes
}

fn independent_legacy_projection_root(
    id: &str,
    source_json: &str,
    submitter: &str,
    submitted_at_ms: u64,
) -> [u8; 32] {
    let mut row = Vec::new();
    row.extend_from_slice(&1_u64.to_be_bytes());
    put_test_text(&mut row, id);
    put_test_text(&mut row, "task");
    put_test_text(&mut row, source_json);
    put_test_text(&mut row, submitter);
    row.extend_from_slice(&submitted_at_ms.to_be_bytes());
    row.extend_from_slice(&[0, 0, 0]);

    let mut projection = Sha256::new();
    projection.update(LEGACY_PROJECTION_DOMAIN);
    projection.update([1, 1]);
    projection.update(1_u64.to_be_bytes());
    projection.update((id.len() as u32).to_be_bytes());
    projection.update(id.as_bytes());
    projection.update((row.len() as u32).to_be_bytes());
    projection.update(row);
    projection.finalize().into()
}

fn independent_legacy_inventory_digest(path: &std::path::Path) -> [u8; 32] {
    let bytes = std::fs::read(path).unwrap();
    let file_name = path.file_name().unwrap().to_str().unwrap();
    let mut exact = Sha256::new();
    exact.update(&bytes);

    let mut inventory = Sha256::new();
    inventory.update(LEGACY_INVENTORY_DOMAIN);
    inventory.update(1_u32.to_be_bytes());
    inventory.update((file_name.len() as u32).to_be_bytes());
    inventory.update(file_name.as_bytes());
    inventory.update((bytes.len() as u64).to_be_bytes());
    inventory.update(exact.finalize());
    inventory.finalize().into()
}

fn update_test_table(state: &mut Sha256, tag: u8, rows: &[(Vec<u8>, Vec<u8>)]) {
    state.update([tag]);
    state.update((rows.len() as u64).to_be_bytes());
    for (key, row) in rows {
        state.update((key.len() as u32).to_be_bytes());
        state.update(key);
        state.update((row.len() as u32).to_be_bytes());
        state.update(row);
    }
}

fn independent_migrated_state_root(id: &str, names: &[String]) -> [u8; 32] {
    let declaration = SensitiveParamDeclaration::component(names.to_vec()).unwrap();
    let canonical_names = declaration.names();
    let declaration_digest = declaration
        .digest_for(id, ObservationIdentityClass::Component, 1)
        .unwrap();
    let sensitive_tail = canonical_sensitive_tail(&canonical_names);

    let mut key = Vec::new();
    put_test_text(&mut key, id);

    let mut component = Vec::new();
    put_test_text(&mut component, id);
    put_test_blob(&mut component, &sensitive_tail);
    component.extend_from_slice(&1_u64.to_be_bytes());
    put_test_blob(&mut component, declaration_digest.as_bytes());
    put_test_text(&mut component, "live");
    component.extend_from_slice(&1_u64.to_be_bytes());
    component.extend_from_slice(&[0, 0, 0]);

    let mut identity = Vec::new();
    put_test_text(&mut identity, id);
    put_test_text(&mut identity, "component");
    identity.extend_from_slice(&1_u64.to_be_bytes());
    put_test_blob(&mut identity, declaration_digest.as_bytes());
    put_test_text(&mut identity, "live");
    identity.extend_from_slice(&1_u64.to_be_bytes());
    identity.extend_from_slice(&[0, 0, 0]);

    let mut authority = Vec::new();
    put_test_text(&mut authority, id);
    put_test_text(&mut authority, "component");
    authority.extend_from_slice(&1_u64.to_be_bytes());
    put_test_blob(&mut authority, declaration_digest.as_bytes());

    let singleton_key = 1_u64.to_be_bytes().to_vec();
    let mut zero_capacity = Vec::new();
    zero_capacity.extend_from_slice(&1_u64.to_be_bytes());
    zero_capacity.extend_from_slice(&0_u64.to_be_bytes());
    zero_capacity.extend_from_slice(&0_u64.to_be_bytes());
    zero_capacity.extend_from_slice(&0_u64.to_be_bytes());

    let component_rows = vec![(key.clone(), component)];
    let identity_rows = vec![(key.clone(), identity)];
    let authority_rows = vec![(key, authority)];
    let capacity_rows = vec![(singleton_key, zero_capacity)];
    let mut state = Sha256::new();
    state.update(REGISTRY_STATE_ROOT_DOMAIN);
    state.update([11]);
    update_test_table(&mut state, 1, &component_rows);
    update_test_table(&mut state, 2, &[]);
    update_test_table(&mut state, 3, &identity_rows);
    update_test_table(&mut state, 4, &authority_rows);
    update_test_table(&mut state, 5, &[]);
    update_test_table(&mut state, 6, &[]);
    update_test_table(&mut state, 7, &capacity_rows);
    update_test_table(&mut state, 8, &[]);
    update_test_table(&mut state, 9, &capacity_rows);
    update_test_table(&mut state, 10, &[]);
    update_test_table(&mut state, 11, &[]);
    state.finalize().into()
}

fn legacy_marker(block: &[u8; 228], phase: u8) -> Vec<u8> {
    let mut marker = Vec::with_capacity(298);
    marker.push(1);
    marker.extend_from_slice(&1_u32.to_be_bytes());
    marker.extend_from_slice(block);
    marker.push(phase);
    marker.extend_from_slice(&[0x80_u8.wrapping_add(phase); 32]);
    // This fixture represents bytes already authenticated by the external
    // owner.  Scheduler framing tests must not claim to authenticate this MAC.
    marker.extend_from_slice(&[0x90_u8.wrapping_add(phase); 32]);
    assert_eq!(marker.len(), 298);
    marker
}

struct LegacyPlanFixture {
    block: [u8; 228],
    prepared: Vec<u8>,
    installed: Vec<u8>,
    complete: Vec<u8>,
    keyring: Vec<u8>,
    roles: Vec<u8>,
}

impl LegacyPlanFixture {
    fn new(
        file_identity_digest: [u8; 32],
        projection_root: [u8; 32],
        target_state_root: [u8; 32],
    ) -> Self {
        let keyring = FixtureKeyringState::new().current.bytes;
        let roles = empty_role_allocation_file();
        assert_eq!(
            persisted_keyring_file_root(&keyring),
            independent_keyring_root(&keyring)
        );
        assert_eq!(
            role_allocation_file_root(&roles),
            independent_role_allocation_root(&roles)
        );

        let mut block = Vec::with_capacity(228);
        block.extend_from_slice(&[0xa1; 16]);
        block.extend_from_slice(&REGISTRY_INSTANCE);
        block.extend_from_slice(&file_identity_digest);
        block.extend_from_slice(&projection_root);
        block.extend_from_slice(&1_u32.to_be_bytes());
        block.extend_from_slice(&target_state_root);
        block.extend_from_slice(&independent_keyring_root(&keyring));
        block.extend_from_slice(&independent_role_allocation_root(&roles));
        block.extend_from_slice(&[0xa2; 32]);
        let block: [u8; 228] = block.try_into().unwrap();
        Self {
            prepared: legacy_marker(&block, 1),
            installed: legacy_marker(&block, 2),
            complete: legacy_marker(&block, 3),
            block,
            keyring,
            roles,
        }
    }

    fn scheduler_artifacts(&self) -> PreparedLegacyRegistryMigration {
        PreparedLegacyRegistryMigration::fixture_for_test(
            &self.block,
            &self.prepared,
            &self.installed,
            &self.complete,
            &self.keyring,
            &self.roles,
        )
        .unwrap()
    }
}

fn create_legacy_database(path: &std::path::Path, extra_column: bool) -> String {
    let connection = rusqlite::Connection::open(path).unwrap();
    if extra_column {
        connection
            .execute_batch(
                "CREATE TABLE components (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    id TEXT NOT NULL UNIQUE,
                    component_type TEXT NOT NULL,
                    submit_config_json TEXT NOT NULL,
                    submitter TEXT NOT NULL,
                    submitted_at_ms INTEGER NOT NULL,
                    interval_ms INTEGER,
                    expected_next_fire_at_ms INTEGER,
                    last_fire_at_ms INTEGER,
                    legacy_extra TEXT
                 );",
            )
            .unwrap();
    } else {
        connection
            .execute_batch(
                "CREATE TABLE components (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    id TEXT NOT NULL UNIQUE,
                    component_type TEXT NOT NULL,
                    submit_config_json TEXT NOT NULL,
                    submitter TEXT NOT NULL,
                    submitted_at_ms INTEGER NOT NULL,
                    interval_ms INTEGER,
                    expected_next_fire_at_ms INTEGER,
                    last_fire_at_ms INTEGER
                 );",
            )
            .unwrap();
    }
    let source = component(
        "legacy-component",
        vec!["api_key".to_owned(), "token".to_owned()],
    );
    let source_json = serde_json::to_string(&source).unwrap();
    let sql = if extra_column {
        "INSERT INTO components
           (id,component_type,submit_config_json,submitter,submitted_at_ms,
            interval_ms,expected_next_fire_at_ms,last_fire_at_ms,legacy_extra)
         VALUES (?1,'task',?2,'legacy-owner',123,NULL,NULL,NULL,'unexpected')"
    } else {
        "INSERT INTO components
           (id,component_type,submit_config_json,submitter,submitted_at_ms,
            interval_ms,expected_next_fire_at_ms,last_fire_at_ms)
         VALUES (?1,'task',?2,'legacy-owner',123,NULL,NULL,NULL)"
    };
    connection
        .execute(sql, rusqlite::params!["legacy-component", source_json])
        .unwrap();
    source_json
}

fn checkpoint_legacy_database(path: &std::path::Path) {
    rusqlite::Connection::open(path)
        .unwrap()
        .execute_batch("PRAGMA wal_checkpoint(FULL);")
        .unwrap();
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MarkerLockedReauthenticationAdversary {
    RejectSecondPhysicalAuthentication,
    DriftLeaseAfterSecondPhysicalAuthentication,
}

#[derive(Default)]
struct MarkerAuthenticationControl {
    total_calls: u64,
    calls_since_arm: u64,
    adversary: Option<MarkerLockedReauthenticationAdversary>,
    lease_drifted: bool,
}

#[derive(Clone)]
struct LegacyMigrationAnchor {
    inner: MemoryAnchor,
    fail_initialize_once: Arc<StdMutex<bool>>,
    authentication_count: Arc<StdMutex<u64>>,
    marker_authentication: Arc<StdMutex<MarkerAuthenticationControl>>,
}

impl LegacyMigrationAnchor {
    fn fail_first_initialize() -> Self {
        Self {
            inner: MemoryAnchor::default(),
            fail_initialize_once: Arc::new(StdMutex::new(true)),
            authentication_count: Arc::new(StdMutex::new(0)),
            marker_authentication: Arc::new(StdMutex::new(MarkerAuthenticationControl::default())),
        }
    }

    fn authentication_count(&self) -> u64 {
        *self.authentication_count.lock().unwrap()
    }

    fn marker_authentication_count(&self) -> u64 {
        self.marker_authentication.lock().unwrap().total_calls
    }

    fn arm_marker_locked_reauthentication_adversary(
        &self,
        adversary: MarkerLockedReauthenticationAdversary,
    ) {
        let mut control = self.marker_authentication.lock().unwrap();
        assert!(control.adversary.is_none());
        control.calls_since_arm = 0;
        control.lease_drifted = false;
        control.adversary = Some(adversary);
    }

    fn marker_authentication_calls_since_arm(&self) -> u64 {
        self.marker_authentication.lock().unwrap().calls_since_arm
    }

    fn clear_marker_locked_reauthentication_adversary(&self) {
        let mut control = self.marker_authentication.lock().unwrap();
        control.calls_since_arm = 0;
        control.lease_drifted = false;
        control.adversary = None;
    }
}

impl RegistryAnchorTransaction for LegacyMigrationAnchor {
    fn observe(&self) -> Result<RegistryAnchorWorld, RegistryAnchorError> {
        self.inner
            .state
            .lock()
            .unwrap()
            .world
            .clone()
            .ok_or(RegistryAnchorError::Uninitialized)
    }

    fn anchor_lease_tag(&self, challenge: [u8; 32]) -> Result<[u8; 32], RegistryAnchorError> {
        let mut tag = self.inner.anchor_lease_tag(challenge)?;
        if self.marker_authentication.lock().unwrap().lease_drifted {
            tag[0] ^= 1;
        }
        Ok(tag)
    }

    fn authenticate_legacy_migration_artifacts(
        &self,
        _block: &[u8],
        _prepared: &[u8],
        _installed: &[u8],
        _complete: &[u8],
        _keyring: &[u8],
        _roles: &[u8],
    ) -> Result<(), RegistryAnchorError> {
        let mut count = self.authentication_count.lock().unwrap();
        *count = count.checked_add(1).unwrap();
        Ok(())
    }

    fn authenticate_legacy_marker_transition_artifacts(
        &self,
        previous: &RegistryAnchorTuple,
        next: &RegistryAnchorTuple,
        context: &RegistryHeadContext,
        previous_marker: &[u8],
        next_marker: &[u8],
    ) -> Result<(), RegistryAnchorError> {
        if previous.registry_instance != next.registry_instance
            || previous.sequence.checked_add(1) != Some(next.sequence)
            || registry_marker_root(previous_marker)? != context.previous_marker_root
            || registry_marker_root(next_marker)? != context.next_marker_root
        {
            return Err(RegistryAnchorError::AuthenticationFailed);
        }
        let mut control = self.marker_authentication.lock().unwrap();
        control.total_calls = control.total_calls.checked_add(1).unwrap();
        if let Some(adversary) = control.adversary {
            control.calls_since_arm = control.calls_since_arm.checked_add(1).unwrap();
            if control.calls_since_arm == 2 {
                match adversary {
                    MarkerLockedReauthenticationAdversary::RejectSecondPhysicalAuthentication => {
                        return Err(RegistryAnchorError::AuthenticationFailed)
                    }
                    MarkerLockedReauthenticationAdversary::DriftLeaseAfterSecondPhysicalAuthentication => {
                        control.lease_drifted = true;
                    }
                }
            }
        }
        Ok(())
    }

    fn initialize_compact(
        &self,
        genesis: VerifiedEmptyRegistryGenesis,
    ) -> Result<(), RegistryAnchorError> {
        self.inner.initialize_compact(genesis)
    }

    fn initialize_migrated_compact(
        &self,
        genesis: VerifiedLegacyRegistryMigrationGenesis,
        artifacts: PreparedLegacyRegistryMigration,
    ) -> Result<(), RegistryAnchorError> {
        let tuple = genesis.tuple().clone();
        if tuple.sequence != 0
            || tuple.registry_instance != artifacts.registry_instance()
            || tuple.state_root != artifacts.target_state_root()
            || tuple.keyring_root != artifacts.target_keyring_root()
            || tuple.role_allocation_root != artifacts.target_role_allocation_root()
            || tuple.migration_digest != artifacts.migration_digest()
            || genesis.marker_root() != artifacts.prepared_marker_root()
            || genesis.manifest_key_epoch() != artifacts.manifest_key_epoch()
            || genesis.migration_id() != artifacts.migration_id()
        {
            return Err(RegistryAnchorError::AuthenticationFailed);
        }
        let mut fail = self.fail_initialize_once.lock().unwrap();
        if *fail {
            *fail = false;
            return Err(RegistryAnchorError::Unavailable(
                "fixture failpoint: database committed before migration anchor".into(),
            ));
        }
        drop(fail);
        let mut state = self.inner.state.lock().unwrap();
        if state.world.is_some() {
            return Err(RegistryAnchorError::CompareAndSwapFailed);
        }
        state.world = Some(RegistryAnchorWorld::CompactCurrent {
            generation: 1,
            current: tuple,
        });
        Ok(())
    }

    fn prepare_current(
        &self,
        mutation: RegistryAnchorMutation,
    ) -> Result<Box<dyn PreparedCurrent>, RegistryAnchorError> {
        self.inner.prepare_current(mutation)
    }

    fn recover(&self, capability: RegistryRecoveryCapability) -> Result<(), RegistryAnchorError> {
        self.inner.recover(capability)
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn exact_nine_column_legacy_migration_db_before_anchor_recovers() {
    let temp = tempfile::tempdir().unwrap();
    let database_path = temp.path().join("components.db");
    let source_json = create_legacy_database(&database_path, false);
    let registry = Arc::new(
        ComponentRegistry::open_in(temp.path(), "components.db")
            .await
            .unwrap(),
    );
    checkpoint_legacy_database(&database_path);

    let file_identity_digest = independent_legacy_inventory_digest(&database_path);
    let projection_root =
        independent_legacy_projection_root("legacy-component", &source_json, "legacy-owner", 123);
    let target_state_root = independent_migrated_state_root(
        "legacy-component",
        &["api_key".to_owned(), "token".to_owned()],
    );
    let plan = LegacyPlanFixture::new(file_identity_digest, projection_root, target_state_root);
    let first_artifacts = plan.scheduler_artifacts();
    let config = ObservationProviderConfig::authenticated_legacy_migration(
        BOOT,
        &first_artifacts,
        plan.keyring.clone(),
    )
    .unwrap();
    let anchor = Arc::new(LegacyMigrationAnchor::fail_first_initialize());

    assert!(matches!(
        RegistrySensitiveParamProvider::migrate_legacy_registry(
            Arc::clone(&registry),
            anchor.clone(),
            config.clone(),
            first_artifacts,
        )
        .await,
        Err(ObservationProviderError::Anchor(
            RegistryAnchorError::Unavailable(_)
        ))
    ));
    assert_eq!(anchor.observe(), Err(RegistryAnchorError::Uninitialized));
    assert_eq!(anchor.authentication_count(), 1);

    let inspection = rusqlite::Connection::open(&database_path).unwrap();
    let target_columns: i64 = inspection
        .query_row(
            "SELECT COUNT(*) FROM pragma_table_xinfo('components')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let ledger_rows: i64 = inspection
        .query_row(
            "SELECT COUNT(*) FROM observation_identity_ledger",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(target_columns, 17);
    assert_eq!(
        ledger_rows, 1,
        "SQLite committed before the anchor failpoint"
    );
    drop(inspection);

    let recovered = RegistrySensitiveParamProvider::migrate_legacy_registry(
        registry,
        anchor.clone(),
        config,
        plan.scheduler_artifacts(),
    )
    .await
    .unwrap();
    assert_eq!(
        anchor.authentication_count(),
        2,
        "existing-ledger recovery must reauthenticate the complete migration plan"
    );
    let recovered_artifacts = plan.scheduler_artifacts();
    let recovered_tuple = recovered.verify_for(&recovered_artifacts).unwrap().clone();
    assert_eq!(recovered_tuple.sequence, 0);
    assert_eq!(recovered_tuple.registry_instance, REGISTRY_INSTANCE);
    assert_eq!(recovered_tuple.state_root, target_state_root);
    assert_eq!(
        anchor.observe().unwrap(),
        RegistryAnchorWorld::CompactCurrent {
            generation: 1,
            current: recovered_tuple,
        }
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn initialized_migration_anchor_without_ledger_rejects_before_any_sqlite_mutation() {
    let temp = tempfile::tempdir().unwrap();
    let database_path = temp.path().join("components.db");
    let source_json = create_legacy_database(&database_path, false);
    let registry = Arc::new(
        ComponentRegistry::open_in(temp.path(), "components.db")
            .await
            .unwrap(),
    );
    checkpoint_legacy_database(&database_path);

    let target_state_root = independent_migrated_state_root(
        "legacy-component",
        &["api_key".to_owned(), "token".to_owned()],
    );
    let plan = LegacyPlanFixture::new(
        independent_legacy_inventory_digest(&database_path),
        independent_legacy_projection_root("legacy-component", &source_json, "legacy-owner", 123),
        target_state_root,
    );
    let artifacts = plan.scheduler_artifacts();
    let config = ObservationProviderConfig::authenticated_legacy_migration(
        BOOT,
        &artifacts,
        plan.keyring.clone(),
    )
    .unwrap();
    let anchor = Arc::new(LegacyMigrationAnchor::fail_first_initialize());
    let initial_world = RegistryAnchorWorld::CompactCurrent {
        generation: 9,
        current: literal_tuple(REGISTRY_INSTANCE, 0, 0x6a),
    };
    anchor.inner.state.lock().unwrap().world = Some(initial_world.clone());
    let database_before = std::fs::read(&database_path).unwrap();

    let error = RegistrySensitiveParamProvider::migrate_legacy_registry(
        registry,
        anchor.clone(),
        config,
        artifacts,
    )
    .await
    .unwrap_err();
    assert!(matches!(
        error,
        ObservationProviderError::RecoveryRequired(ref message)
            if message.contains("no matching durable SQLite ledger")
    ));
    assert_eq!(anchor.authentication_count(), 1);
    assert_eq!(anchor.observe().unwrap(), initial_world);
    assert_eq!(
        std::fs::read(&database_path).unwrap(),
        database_before,
        "initialized-anchor rejection must not checkpoint, migrate, or rewrite SQLite"
    );

    let inspection = rusqlite::Connection::open(&database_path).unwrap();
    let target_tables: i64 = inspection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='observation_identity_ledger'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let source_columns: i64 = inspection
        .query_row(
            "SELECT COUNT(*) FROM pragma_table_xinfo('components')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(target_tables, 0);
    assert_eq!(source_columns, 9);
}

#[tokio::test(flavor = "multi_thread")]
async fn exact_committed_marker_and_both_recovery_retries_reject_schema_tamper_before_return() {
    let temp = tempfile::tempdir().unwrap();
    let database_path = temp.path().join("components.db");
    let source_json = create_legacy_database(&database_path, false);
    let registry = Arc::new(
        ComponentRegistry::open_in(temp.path(), "components.db")
            .await
            .unwrap(),
    );
    checkpoint_legacy_database(&database_path);
    let target_state_root = independent_migrated_state_root(
        "legacy-component",
        &["api_key".to_owned(), "token".to_owned()],
    );
    let plan = LegacyPlanFixture::new(
        independent_legacy_inventory_digest(&database_path),
        independent_legacy_projection_root("legacy-component", &source_json, "legacy-owner", 123),
        target_state_root,
    );
    let migration = plan.scheduler_artifacts();
    let config = ObservationProviderConfig::authenticated_legacy_migration(
        BOOT,
        &migration,
        plan.keyring.clone(),
    )
    .unwrap();
    let anchor = Arc::new(LegacyMigrationAnchor::fail_first_initialize());
    *anchor.fail_initialize_once.lock().unwrap() = false;
    let installed = RegistrySensitiveParamProvider::migrate_legacy_registry(
        Arc::clone(&registry),
        anchor.clone(),
        config,
        migration,
    )
    .await
    .unwrap();
    let retained = plan.scheduler_artifacts();
    let prepared = installed
        .prepare_installed_marker_transition(anchor.as_ref(), &retained)
        .unwrap();
    let committed = RegistrySensitiveParamProvider::commit_legacy_marker_transition(
        Arc::clone(&registry),
        anchor.clone(),
        &prepared,
    )
    .await
    .unwrap();
    committed.verify_installed_for(&retained).unwrap();
    let anchor_before = anchor.observe().unwrap();
    let inspection = rusqlite::Connection::open(&database_path).unwrap();
    let ledger_before: (i64, Vec<u8>, Vec<u8>) = inspection
        .query_row(
            "SELECT committed_sequence,committed_head_digest,committed_state_root
             FROM observation_identity_ledger WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    drop(inspection);

    RegistrySensitiveParamProvider::inject_next_marker_retry_schema_adversary(
        &registry,
        REGISTRY_INSTANCE,
    )
    .unwrap();
    assert!(matches!(
        RegistrySensitiveParamProvider::commit_legacy_marker_transition(
            Arc::clone(&registry),
            anchor.clone(),
            &prepared,
        )
        .await,
        Err(ObservationProviderError::Registry(_))
            | Err(ObservationProviderError::RecoveryRequired(_))
    ));
    assert_eq!(anchor.observe().unwrap(), anchor_before);
    let inspection = rusqlite::Connection::open(&database_path).unwrap();
    let ledger_after: (i64, Vec<u8>, Vec<u8>) = inspection
        .query_row(
            "SELECT committed_sequence,committed_head_digest,committed_state_root
             FROM observation_identity_ledger WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    let injected_trigger_count: i64 = inspection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master
             WHERE type='trigger' AND name='__test_marker_retry_schema_boundary_tamper'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(ledger_after, ledger_before);
    assert_eq!(injected_trigger_count, 0);

    RegistrySensitiveParamProvider::inject_next_marker_retry_schema_adversary(
        &registry,
        REGISTRY_INSTANCE,
    )
    .unwrap();
    assert!(matches!(
        RegistrySensitiveParamProvider::recover_legacy_installed_marker_transition(
            Arc::clone(&registry),
            anchor.clone(),
            &retained,
        )
        .await,
        Err(ObservationProviderError::Registry(_))
            | Err(ObservationProviderError::RecoveryRequired(_))
    ));
    let inspection = rusqlite::Connection::open(&database_path).unwrap();
    let injected_trigger_count: i64 = inspection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master
             WHERE type='trigger' AND name='__test_marker_retry_schema_boundary_tamper'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(injected_trigger_count, 0);
    drop(inspection);
    RegistrySensitiveParamProvider::recover_legacy_installed_marker_transition(
        Arc::clone(&registry),
        anchor.clone(),
        &retained,
    )
    .await
    .unwrap()
    .verify_installed_for(&retained)
    .unwrap();

    let complete = VerifiedLegacyMigrationComplete::fixture_for_test(&retained);
    let prepared_complete = complete
        .prepare_complete_marker_transition(anchor.as_ref(), &retained)
        .unwrap();
    RegistrySensitiveParamProvider::commit_legacy_marker_transition(
        Arc::clone(&registry),
        anchor.clone(),
        &prepared_complete,
    )
    .await
    .unwrap()
    .verify_complete_for(&retained)
    .unwrap();

    RegistrySensitiveParamProvider::inject_next_marker_retry_schema_adversary(
        &registry,
        REGISTRY_INSTANCE,
    )
    .unwrap();
    assert!(matches!(
        RegistrySensitiveParamProvider::recover_legacy_complete_marker_transition(
            Arc::clone(&registry),
            anchor.clone(),
            &retained,
        )
        .await,
        Err(ObservationProviderError::Registry(_))
            | Err(ObservationProviderError::RecoveryRequired(_))
    ));
    let inspection = rusqlite::Connection::open(&database_path).unwrap();
    let injected_trigger_count: i64 = inspection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master
             WHERE type='trigger' AND name='__test_marker_retry_schema_boundary_tamper'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(injected_trigger_count, 0);
    drop(inspection);
    RegistrySensitiveParamProvider::recover_legacy_complete_marker_transition(
        Arc::clone(&registry),
        anchor,
        &retained,
    )
    .await
    .unwrap()
    .verify_complete_for(&retained)
    .unwrap();
}

type CommittedMarkerDurableSnapshot = (
    Vec<u8>,
    i64,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    i64,
);

fn committed_marker_durable_snapshot(
    database_path: &std::path::Path,
) -> CommittedMarkerDurableSnapshot {
    rusqlite::Connection::open(database_path)
        .unwrap()
        .query_row(
            "SELECT l.registry_instance_id,l.committed_sequence,l.committed_head_digest,
                    l.committed_state_root,l.committed_keyring_root,
                    l.committed_role_allocation_root,l.migration_digest,
                    h.current_marker_root,h.current_manifest_key_epoch
             FROM observation_identity_ledger AS l
             JOIN observation_registry_head_context AS h ON h.singleton=l.singleton
             WHERE l.singleton=1",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                ))
            },
        )
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn exact_committed_marker_retry_reauthenticates_physical_artifacts_and_lease_inside_immediate_boundary(
) {
    let temp = tempfile::tempdir().unwrap();
    let database_path = temp.path().join("components.db");
    let source_json = create_legacy_database(&database_path, false);
    let registry = Arc::new(
        ComponentRegistry::open_in(temp.path(), "components.db")
            .await
            .unwrap(),
    );
    checkpoint_legacy_database(&database_path);
    let target_state_root = independent_migrated_state_root(
        "legacy-component",
        &["api_key".to_owned(), "token".to_owned()],
    );
    let plan = LegacyPlanFixture::new(
        independent_legacy_inventory_digest(&database_path),
        independent_legacy_projection_root("legacy-component", &source_json, "legacy-owner", 123),
        target_state_root,
    );
    let migration = plan.scheduler_artifacts();
    let config = ObservationProviderConfig::authenticated_legacy_migration(
        BOOT,
        &migration,
        plan.keyring.clone(),
    )
    .unwrap();
    let anchor = Arc::new(LegacyMigrationAnchor::fail_first_initialize());
    *anchor.fail_initialize_once.lock().unwrap() = false;
    let installed = RegistrySensitiveParamProvider::migrate_legacy_registry(
        Arc::clone(&registry),
        anchor.clone(),
        config,
        migration,
    )
    .await
    .unwrap();
    let retained = plan.scheduler_artifacts();
    let prepared = installed
        .prepare_installed_marker_transition(anchor.as_ref(), &retained)
        .unwrap();

    let initial_commit_authentication_count = anchor.marker_authentication_count();
    RegistrySensitiveParamProvider::commit_legacy_marker_transition(
        Arc::clone(&registry),
        anchor.clone(),
        &prepared,
    )
    .await
    .unwrap()
    .verify_installed_for(&retained)
    .unwrap();
    assert_eq!(
        anchor.marker_authentication_count(),
        initial_commit_authentication_count + 2,
        "initial commit must use preauthentication plus the locked reconstruction"
    );

    let anchor_before = anchor.observe().unwrap();
    let durable_before = committed_marker_durable_snapshot(&database_path);
    for adversary in [
        MarkerLockedReauthenticationAdversary::RejectSecondPhysicalAuthentication,
        MarkerLockedReauthenticationAdversary::DriftLeaseAfterSecondPhysicalAuthentication,
    ] {
        let authentication_count_before = anchor.marker_authentication_count();
        anchor.arm_marker_locked_reauthentication_adversary(adversary);
        let error = RegistrySensitiveParamProvider::commit_legacy_marker_transition(
            Arc::clone(&registry),
            anchor.clone(),
            &prepared,
        )
        .await
        .unwrap_err();
        assert!(matches!(
            error,
            ObservationProviderError::Anchor(RegistryAnchorError::AuthenticationFailed)
        ));
        assert_eq!(
            anchor.marker_authentication_calls_since_arm(),
            2,
            "{adversary:?} must fail only after the production retry calls physical authentication inside BEGIN IMMEDIATE"
        );
        assert_eq!(
            anchor.marker_authentication_count(),
            authentication_count_before + 2
        );
        assert_eq!(anchor.observe().unwrap(), anchor_before);
        assert_eq!(
            committed_marker_durable_snapshot(&database_path),
            durable_before,
            "{adversary:?} must not change the ledger, roots, marker head, epoch, or counters"
        );
        anchor.clear_marker_locked_reauthentication_adversary();
    }

    let clean_retry_authentication_count = anchor.marker_authentication_count();
    RegistrySensitiveParamProvider::commit_legacy_marker_transition(
        registry,
        anchor.clone(),
        &prepared,
    )
    .await
    .unwrap()
    .verify_installed_for(&retained)
    .unwrap();
    assert_eq!(
        anchor.marker_authentication_count(),
        clean_retry_authentication_count + 2
    );
    assert_eq!(anchor.observe().unwrap(), anchor_before);
    assert_eq!(
        committed_marker_durable_snapshot(&database_path),
        durable_before
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn legacy_migration_partial_artifacts_schema_and_framing_tamper_reject() {
    let fixture = LegacyPlanFixture::new([0xb1; 32], [0xb2; 32], [0xb3; 32]);
    fixture.scheduler_artifacts();

    let mut wrong_phase = fixture.installed.clone();
    wrong_phase[233] = 3;
    assert!(matches!(
        PreparedLegacyRegistryMigration::fixture_for_test(
            &fixture.block,
            &fixture.prepared,
            &wrong_phase,
            &fixture.complete,
            &fixture.keyring,
            &fixture.roles,
        ),
        Err(RegistryAnchorError::InvalidTransition)
    ));

    let partial_complete = &fixture.complete[..fixture.complete.len() - 1];
    assert!(matches!(
        PreparedLegacyRegistryMigration::fixture_for_test(
            &fixture.block,
            &fixture.prepared,
            &fixture.installed,
            partial_complete,
            &fixture.keyring,
            &fixture.roles,
        ),
        Err(RegistryAnchorError::InvalidTransition)
    ));

    let mut duplicate_nonce = fixture.installed.clone();
    duplicate_nonce[234..266].copy_from_slice(&fixture.prepared[234..266]);
    assert!(matches!(
        PreparedLegacyRegistryMigration::fixture_for_test(
            &fixture.block,
            &fixture.prepared,
            &duplicate_nonce,
            &fixture.complete,
            &fixture.keyring,
            &fixture.roles,
        ),
        Err(RegistryAnchorError::InvalidTransition)
    ));

    let mut crossed_block = fixture.block;
    crossed_block[0] ^= 1;
    assert!(matches!(
        PreparedLegacyRegistryMigration::fixture_for_test(
            &crossed_block,
            &fixture.prepared,
            &fixture.installed,
            &fixture.complete,
            &fixture.keyring,
            &fixture.roles,
        ),
        Err(RegistryAnchorError::InvalidTransition)
    ));

    let mut malformed_keyring = fixture.keyring.clone();
    malformed_keyring.push(0);
    assert!(matches!(
        PreparedLegacyRegistryMigration::fixture_for_test(
            &fixture.block,
            &fixture.prepared,
            &fixture.installed,
            &fixture.complete,
            &malformed_keyring,
            &fixture.roles,
        ),
        Err(RegistryAnchorError::InvalidTransition)
    ));

    let mut malformed_roles = fixture.roles.clone();
    malformed_roles.push(0);
    assert!(matches!(
        PreparedLegacyRegistryMigration::fixture_for_test(
            &fixture.block,
            &fixture.prepared,
            &fixture.installed,
            &fixture.complete,
            &fixture.keyring,
            &malformed_roles,
        ),
        Err(RegistryAnchorError::InvalidTransition)
    ));

    let temp = tempfile::tempdir().unwrap();
    let database_path = temp.path().join("components.db");
    create_legacy_database(&database_path, true);
    let registry = Arc::new(
        ComponentRegistry::open_in(temp.path(), "components.db")
            .await
            .unwrap(),
    );
    checkpoint_legacy_database(&database_path);
    let schema_fixture = LegacyPlanFixture::new(
        independent_legacy_inventory_digest(&database_path),
        [0xc1; 32],
        [0xc2; 32],
    );
    let artifacts = schema_fixture.scheduler_artifacts();
    let config = ObservationProviderConfig::authenticated_legacy_migration(
        BOOT,
        &artifacts,
        schema_fixture.keyring.clone(),
    )
    .unwrap();
    let error = RegistrySensitiveParamProvider::migrate_legacy_registry(
        registry,
        Arc::new(LegacyMigrationAnchor::fail_first_initialize()),
        config,
        artifacts,
    )
    .await
    .unwrap_err();
    assert!(matches!(
        error,
        ObservationProviderError::RecoveryRequired(ref message)
            if message.contains("exact nine-column schema")
    ));

    let inspection = rusqlite::Connection::open(&database_path).unwrap();
    let source_columns: i64 = inspection
        .query_row(
            "SELECT COUNT(*) FROM pragma_table_xinfo('components')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let ledger_rows: i64 = inspection
        .query_row(
            "SELECT COUNT(*) FROM observation_identity_ledger",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(source_columns, 10);
    assert_eq!(
        ledger_rows, 0,
        "schema rejection installs no migration ledger"
    );
}

#[test]
fn all_four_anchor_worlds_recover() {
    let previous = literal_tuple(REGISTRY_INSTANCE, 7, 0x21);
    let next = literal_successor(&previous, 0x31);
    assert_eq!(
        classify_recovery(
            &RegistryAnchorWorld::PendingCurrent {
                generation: 8,
                previous: previous.clone(),
                next: next.clone(),
            },
            &previous,
        ),
        Ok(RegistryRecoveryDecision::RollBackPending)
    );
    assert_eq!(
        classify_recovery(
            &RegistryAnchorWorld::PendingCurrent {
                generation: 8,
                previous: previous.clone(),
                next: next.clone(),
            },
            &next,
        ),
        Ok(RegistryRecoveryDecision::FinishPendingPromotion)
    );
    assert_eq!(
        classify_recovery(
            &RegistryAnchorWorld::SelectedNext {
                generation: 9,
                next: next.clone(),
            },
            &next,
        ),
        Ok(RegistryRecoveryDecision::CompactSelectedNext)
    );
    assert_eq!(
        classify_recovery(
            &RegistryAnchorWorld::CompactCurrent {
                generation: 10,
                current: next.clone(),
            },
            &next,
        ),
        Ok(RegistryRecoveryDecision::Clean)
    );
}

#[test]
fn valid_old_snapshot_same_sequence_fork_and_cross_instance_reject() {
    let current = literal_tuple(REGISTRY_INSTANCE, 9, 0x41);
    let world = RegistryAnchorWorld::CompactCurrent {
        generation: 12,
        current: current.clone(),
    };

    let mut old = current.clone();
    old.sequence -= 1;
    assert!(matches!(
        classify_recovery(&world, &old),
        Err(RegistryAnchorError::RecoveryRequired(_))
    ));

    let mut fork = current.clone();
    fork.head[0] ^= 1;
    assert!(matches!(
        classify_recovery(&world, &fork),
        Err(RegistryAnchorError::RecoveryRequired(_))
    ));

    let mut crossed = current;
    crossed.registry_instance = [0x12; 16];
    assert!(matches!(
        classify_recovery(&world, &crossed),
        Err(RegistryAnchorError::RecoveryRequired(_))
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn every_anchor_and_sqlite_failpoint_restarts_deterministically() {
    for failure in [
        InjectedAnchorFailure::PrepareCurrent,
        InjectedAnchorFailure::DatabaseCommitted,
        InjectedAnchorFailure::SelectNext,
        InjectedAnchorFailure::Compact,
    ] {
        let temp = tempfile::tempdir().unwrap();
        let registry = Arc::new(
            ComponentRegistry::open_in(temp.path(), "components.db")
                .await
                .unwrap(),
        );
        let anchor = FailpointAnchor::default();
        let state = Arc::new(StdMutex::new(FixtureKeyringState::new()));
        let (provider, _) = open_fixture_provider_with_anchor(
            Arc::clone(&registry),
            Arc::new(anchor.clone()),
            Arc::clone(&state),
        )
        .await;
        anchor.arm(failure);
        assert!(
            matches!(
                provider.register_host(HostEmitterId::Runtime),
                Err(SensitiveParamCatalogError::StorageUnavailable)
            ),
            "injected stage: {failure:?}"
        );
        assert!(!provider.is_ready());
        let committed = failure != InjectedAnchorFailure::PrepareCurrent;
        drop(provider);
        drop(registry);

        let restarted_registry = Arc::new(
            ComponentRegistry::open_in(temp.path(), "components.db")
                .await
                .unwrap(),
        );
        let (restarted, _) =
            open_fixture_provider_with_anchor(restarted_registry, Arc::new(anchor.clone()), state)
                .await;
        assert_eq!(
            restarted
                .lookup(HostEmitterId::Runtime.canonical_id())
                .is_ok(),
            committed,
            "restart must choose the only durable side at {failure:?}"
        );
        assert!(matches!(
            anchor.world(),
            RegistryAnchorWorld::CompactCurrent { .. }
        ));
    }

    // A real SQLite abort is injected at the ledger write.  The transaction
    // must roll back all preceding identity writes and leave the external
    // anchor at its prior compact tuple.
    let temp = tempfile::tempdir().unwrap();
    let registry = Arc::new(
        ComponentRegistry::open_in(temp.path(), "components.db")
            .await
            .unwrap(),
    );
    let anchor = FailpointAnchor::default();
    let state = Arc::new(StdMutex::new(FixtureKeyringState::new()));
    let (provider, _) = open_fixture_provider_with_anchor(
        Arc::clone(&registry),
        Arc::new(anchor.clone()),
        Arc::clone(&state),
    )
    .await;
    let failpoint = rusqlite::Connection::open(temp.path().join("components.db")).unwrap();
    failpoint
        .execute_batch(
            "CREATE TRIGGER t47_fail_ledger_update
             BEFORE UPDATE ON observation_identity_ledger
             BEGIN SELECT RAISE(ABORT, 't47 sqlite failpoint'); END;",
        )
        .unwrap();
    assert!(matches!(
        provider.register_host(HostEmitterId::PackManager),
        Err(SensitiveParamCatalogError::StorageUnavailable)
    ));
    failpoint
        .execute_batch("DROP TRIGGER t47_fail_ledger_update;")
        .unwrap();
    drop(failpoint);
    drop(provider);
    drop(registry);

    let restarted_registry = Arc::new(
        ComponentRegistry::open_in(temp.path(), "components.db")
            .await
            .unwrap(),
    );
    let (restarted, _) =
        open_fixture_provider_with_anchor(restarted_registry, Arc::new(anchor.clone()), state)
            .await;
    assert_eq!(
        restarted.lookup(HostEmitterId::PackManager.canonical_id()),
        Err(SensitiveParamCatalogError::UnknownIdentity)
    );
    assert!(matches!(
        anchor.world(),
        RegistryAnchorWorld::CompactCurrent { .. }
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn every_provider_mutation_invokes_anchor_port() {
    let temp = tempfile::tempdir().unwrap();
    let registry = Arc::new(
        ComponentRegistry::open_in(temp.path(), "components.db")
            .await
            .unwrap(),
    );
    let anchor = MemoryAnchor::default();
    let state = Arc::new(StdMutex::new(FixtureKeyringState::new()));
    let (provider, _) = open_fixture_provider(registry, anchor.clone(), state).await;

    assert!(anchor.operation_tags().is_empty());
    let live = register_runtime_identity(&provider);
    assert_eq!(anchor.operation_tags(), vec![6]);

    let binding =
        PersistedObservationBinding::new("evt-anchor".into(), "evt-anchor".into(), [0x91; 32])
            .unwrap();
    provider.seal_persisted_identity(&live, &binding).unwrap();
    assert_eq!(anchor.operation_tags(), vec![6, 6]);

    provider.rotate_persisted_identity_signing_key(2).unwrap();
    assert_eq!(anchor.operation_tags(), vec![6, 6, 6]);
    assert!(matches!(
        anchor.observe().unwrap(),
        RegistryAnchorWorld::CompactCurrent { .. }
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn capacity_minus_one_exact_and_plus_one() {
    let temp = tempfile::tempdir().unwrap();
    let registry = Arc::new(
        ComponentRegistry::open_in(temp.path(), "components.db")
            .await
            .unwrap(),
    );
    let anchor = MemoryAnchor::default();
    let state = Arc::new(StdMutex::new(FixtureKeyringState::new()));
    let (provider, _) = open_fixture_provider(registry, anchor.clone(), state).await;

    let minus_one: Vec<String> = (0..63).map(|index| format!("p{index:02}")).collect();
    let exact: Vec<String> = (0..64).map(|index| format!("p{index:02}")).collect();
    let plus_one: Vec<String> = (0..65).map(|index| format!("p{index:02}")).collect();
    assert!(SensitiveParamDeclaration::component(minus_one).is_ok());
    assert!(SensitiveParamDeclaration::component(exact.clone()).is_ok());
    assert_eq!(
        SensitiveParamDeclaration::component(plus_one),
        Err(SensitiveParamCatalogError::CapacityExceeded)
    );

    let before = anchor.operation_tags();
    let mut rejected = component("cap-plus-one", Vec::new());
    rejected.sensitive_params = (0..65).map(|index| format!("p{index:02}")).collect();
    assert!(matches!(
        provider
            .commit_component_unpublished("cap-plus-one-op".into(), "test".into(), rejected, None,)
            .await,
        Err(ObservationProviderError::Catalog(
            SensitiveParamCatalogError::CapacityExceeded
        )) | Err(ObservationProviderError::CapacityExceeded(_))
    ));
    assert_eq!(
        anchor.operation_tags(),
        before,
        "N+1 rejects before anchor mutation"
    );

    let mut accepted = component("cap-exact", Vec::new());
    accepted.sensitive_params = exact;
    provider
        .commit_component_unpublished("cap-exact-op".into(), "test".into(), accepted, None)
        .await
        .unwrap();
    assert_eq!(anchor.operation_tags().len(), before.len() + 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn carrier_binds_event_cursor_safe_digest_and_exact_identity() {
    let temp = tempfile::tempdir().unwrap();
    let registry = Arc::new(
        ComponentRegistry::open_in(temp.path(), "components.db")
            .await
            .unwrap(),
    );
    let anchor = MemoryAnchor::default();
    let state = Arc::new(StdMutex::new(FixtureKeyringState::new()));
    let (provider, _) = open_fixture_provider(registry, anchor, state).await;
    let live = register_runtime_identity(&provider);
    let expected_claims = live.claims_for_persistence();
    let binding =
        PersistedObservationBinding::new("evt-0007".into(), "evt-0007".into(), [0x39; 32]).unwrap();

    let carrier = provider.seal_persisted_identity(&live, &binding).unwrap();
    let parsed = parse_carrier_prefix(&carrier);
    assert_eq!(parsed.key_id, 1);
    assert_eq!(parsed.event_id, "evt-0007");
    assert_eq!(parsed.cursor, "evt-0007");
    assert_eq!(parsed.safe_event_digest, [0x39; 32]);
    assert_eq!(parsed.exact_id, expected_claims.exact_id);
    assert_eq!(parsed.incarnation, expected_claims.incarnation);
    assert_eq!(
        parsed.declaration_digest.as_slice(),
        expected_claims.declaration_digest.as_bytes()
    );

    let restored = provider.rehydrate_persisted_identity(&carrier).unwrap();
    assert_eq!(
        provider
            .verify_persisted_binding(&restored, &carrier, &binding)
            .unwrap()
            .claims(),
        expected_claims
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn cross_event_cursor_safe_digest_key_and_carrier_swaps_reject() {
    assert_eq!(
        PersistedObservationBinding::new("event-a".into(), "cursor-b".into(), [1; 32]),
        Err(SensitiveParamCatalogError::ScopeMismatch)
    );

    let temp = tempfile::tempdir().unwrap();
    let registry = Arc::new(
        ComponentRegistry::open_in(temp.path(), "components.db")
            .await
            .unwrap(),
    );
    let anchor = MemoryAnchor::default();
    let state = Arc::new(StdMutex::new(FixtureKeyringState::new()));
    let (provider, _) = open_fixture_provider(registry, anchor, state).await;
    let live = register_runtime_identity(&provider);
    let binding_a =
        PersistedObservationBinding::new("event-a".into(), "event-a".into(), [0xa1; 32]).unwrap();
    let binding_b =
        PersistedObservationBinding::new("event-b".into(), "event-b".into(), [0xb2; 32]).unwrap();
    let carrier_a = provider.seal_persisted_identity(&live, &binding_a).unwrap();
    let carrier_b = provider.seal_persisted_identity(&live, &binding_b).unwrap();
    let restored_a = provider.rehydrate_persisted_identity(&carrier_a).unwrap();
    let restored_b = provider.rehydrate_persisted_identity(&carrier_b).unwrap();

    assert_eq!(
        provider.verify_persisted_binding(&restored_a, &carrier_a, &binding_b),
        Err(SensitiveParamCatalogError::ScopeMismatch)
    );
    assert_eq!(
        provider.verify_persisted_binding(&restored_a, &carrier_b, &binding_b),
        Err(SensitiveParamCatalogError::ScopeMismatch)
    );
    assert_eq!(
        provider.verify_persisted_binding(&restored_b, &carrier_a, &binding_a),
        Err(SensitiveParamCatalogError::ScopeMismatch)
    );

    provider.rotate_persisted_identity_signing_key(2).unwrap();
    let carrier_key_two = provider
        .reseal_persisted_identity(&carrier_a, &binding_a)
        .unwrap();
    assert_eq!(carrier_key_two.key_id(), 2);
    assert_eq!(
        provider.verify_persisted_binding(&restored_b, &carrier_key_two, &binding_a),
        Err(SensitiveParamCatalogError::ScopeMismatch)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn reseal_rotates_to_signing_key_and_old_key_stays_verify_only() {
    let temp = tempfile::tempdir().unwrap();
    let registry = Arc::new(
        ComponentRegistry::open_in(temp.path(), "components.db")
            .await
            .unwrap(),
    );
    let anchor = MemoryAnchor::default();
    let state = Arc::new(StdMutex::new(FixtureKeyringState::new()));
    let (provider, _) = open_fixture_provider(registry, anchor, Arc::clone(&state)).await;
    let live = register_runtime_identity(&provider);
    let old_binding =
        PersistedObservationBinding::new("rotate-old".into(), "rotate-old".into(), [0x41; 32])
            .unwrap();
    let old_carrier = provider
        .seal_persisted_identity(&live, &old_binding)
        .unwrap();
    assert_eq!(old_carrier.key_id(), 1);

    let rotated = provider.rotate_persisted_identity_signing_key(2).unwrap();
    assert_eq!(
        rotated.keyring_root,
        state.lock().unwrap().current.binding().keyring_root()
    );
    assert_eq!(
        state
            .lock()
            .unwrap()
            .current
            .entries
            .get(&1)
            .unwrap()
            .status,
        FixtureKeyStatus::VerifyOnly
    );
    provider.rehydrate_persisted_identity(&old_carrier).unwrap();

    let resealed = provider
        .reseal_persisted_identity(&old_carrier, &old_binding)
        .unwrap();
    assert_eq!(resealed.key_id(), 2);
    let restored = provider.rehydrate_persisted_identity(&resealed).unwrap();
    provider
        .verify_persisted_binding(&restored, &resealed, &old_binding)
        .unwrap();
}

fn exact_retirement_scans(
    challenge: &advance_shared_types::contract218_previsible::PersistedKeyRetirementChallenge,
) -> PersistedKeyRetirementScanSet {
    // The external owners are independent from the provider.  Test-support
    // recreates their authenticated fixture roots; the returned value still
    // contains all three distinct opaque owner receipt types.
    let (_issuer, verifier, _termination, _cleanup_issuer, _cleanup_verifier) = roles();
    persisted_key_retirement_scans(
        &verifier,
        challenge,
        ([0x61; 16], 17, [0x62; 32]),
        ([0x63; 16], [0x64; 32], 3, 4096, 55),
        ([0x65; 16], 19, [0x66; 32]),
    )
    .unwrap()
}

async fn rotated_provider_for_retirement() -> (
    tempfile::TempDir,
    Arc<RegistrySensitiveParamProvider>,
    Arc<StdMutex<FixtureKeyringState>>,
    PersistedObservationIdentity,
) {
    let temp = tempfile::tempdir().unwrap();
    let registry = Arc::new(
        ComponentRegistry::open_in(temp.path(), "components.db")
            .await
            .unwrap(),
    );
    let anchor = MemoryAnchor::default();
    let state = Arc::new(StdMutex::new(FixtureKeyringState::new()));
    let (provider, _) = open_fixture_provider(registry, anchor, Arc::clone(&state)).await;
    let live = register_runtime_identity(&provider);
    let binding =
        PersistedObservationBinding::new("retire-old".into(), "retire-old".into(), [0x51; 32])
            .unwrap();
    let old = provider.seal_persisted_identity(&live, &binding).unwrap();
    provider.rotate_persisted_identity_signing_key(2).unwrap();
    (temp, provider, state, old)
}

#[tokio::test(flavor = "multi_thread")]
async fn key_retirement_blocks_without_complete_sqlite_jsonl_migration_reference_scans() {
    let (_temp, provider, state, old_carrier) = rotated_provider_for_retirement().await;
    let challenge_a = provider
        .issue_persisted_identity_key_retirement_challenge("retire-a".into(), 1, 9)
        .unwrap();
    let scans_a = exact_retirement_scans(&challenge_a);
    let challenge_b = provider
        .issue_persisted_identity_key_retirement_challenge("retire-b".into(), 1, 9)
        .unwrap();

    assert!(matches!(
        provider.retire_persisted_identity_key(challenge_b, scans_a),
        Err(ObservationProviderError::Catalog(
            SensitiveParamCatalogError::InvalidCarrier
        ))
    ));
    assert_eq!(
        state
            .lock()
            .unwrap()
            .current
            .entries
            .get(&1)
            .unwrap()
            .status,
        FixtureKeyStatus::VerifyOnly
    );
    provider.rehydrate_persisted_identity(&old_carrier).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn key_retirement_completes_after_exact_typed_owner_scan_proofs() {
    let (_temp, provider, state, old_carrier) = rotated_provider_for_retirement().await;
    let challenge = provider
        .issue_persisted_identity_key_retirement_challenge("retire-complete".into(), 1, 9)
        .unwrap();
    let scans = exact_retirement_scans(&challenge);
    let retired = provider
        .retire_persisted_identity_key(challenge, scans)
        .unwrap();
    assert_eq!(
        retired.keyring_root,
        state.lock().unwrap().current.binding().keyring_root()
    );
    let entry = state
        .lock()
        .unwrap()
        .current
        .entries
        .get(&1)
        .unwrap()
        .clone();
    assert_eq!(entry.status, FixtureKeyStatus::Retired);
    assert_eq!(
        entry.scan,
        Some(FixtureScan {
            sqlite_sequence: 17,
            jsonl_inventory_digest: [0x64; 32],
            jsonl_segment_count: 3,
            jsonl_byte_count: 4096,
            retention_high_water: 55,
        })
    );
    assert!(matches!(
        provider.rehydrate_persisted_identity(&old_carrier),
        Err(SensitiveParamCatalogError::InvalidCarrier)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn keyring_owner_promotion_failpoint_recovers() {
    let temp = tempfile::tempdir().unwrap();
    let registry = Arc::new(
        ComponentRegistry::open_in(temp.path(), "components.db")
            .await
            .unwrap(),
    );
    let anchor = MemoryAnchor::default();
    let state = Arc::new(StdMutex::new(FixtureKeyringState::new()));
    let (provider, custody) =
        open_fixture_provider(registry, anchor.clone(), Arc::clone(&state)).await;
    state.lock().unwrap().fail_promote_once = true;

    assert!(matches!(
        provider.rotate_persisted_identity_signing_key(2),
        Err(ObservationProviderError::Anchor(
            RegistryAnchorError::Unavailable(_)
        ))
    ));
    assert!(
        !provider.is_ready(),
        "an owner promotion failure gates the old provider"
    );
    assert!(state.lock().unwrap().pending.is_some());
    assert!(matches!(
        anchor.observe().unwrap(),
        RegistryAnchorWorld::CompactCurrent { .. }
    ));

    custody.recover_promoted_pending().unwrap();
    assert!(state.lock().unwrap().pending.is_none());
    drop(provider);

    let restarted_registry = Arc::new(
        ComponentRegistry::open_in(temp.path(), "components.db")
            .await
            .unwrap(),
    );
    let (restarted, _) = open_fixture_provider(restarted_registry, anchor, state).await;
    assert!(restarted.is_ready());
    assert_eq!(restarted.current_anchor_tuple().await.unwrap().sequence, 1);
}

#[cfg(feature = "test-support")]
const CARRIER_MUTATION_FAILPOINTS: [ObservationMutationFailpointStage; 9] = [
    ObservationMutationFailpointStage::BeforeMutation,
    ObservationMutationFailpointStage::AfterMutationBeforeValidation,
    ObservationMutationFailpointStage::AfterValidationBeforeAnchorPrepare,
    ObservationMutationFailpointStage::AfterAnchorPrepareBeforeDatabaseCommit,
    ObservationMutationFailpointStage::AfterDatabaseCommitBeforeSync,
    ObservationMutationFailpointStage::AfterSyncBeforeAnchorCommit,
    ObservationMutationFailpointStage::AfterAnchorCommitBeforeSelect,
    ObservationMutationFailpointStage::AfterSelectBeforeCompact,
    ObservationMutationFailpointStage::AfterCompact,
];

#[cfg(feature = "test-support")]
fn carrier_failpoint_crosses_anchor_prepare(stage: ObservationMutationFailpointStage) -> bool {
    matches!(
        stage,
        ObservationMutationFailpointStage::AfterAnchorPrepareBeforeDatabaseCommit
            | ObservationMutationFailpointStage::AfterDatabaseCommitBeforeSync
            | ObservationMutationFailpointStage::AfterSyncBeforeAnchorCommit
            | ObservationMutationFailpointStage::AfterAnchorCommitBeforeSelect
            | ObservationMutationFailpointStage::AfterSelectBeforeCompact
            | ObservationMutationFailpointStage::AfterCompact
    )
}

#[cfg(feature = "test-support")]
struct CarrierHarness {
    temp: tempfile::TempDir,
    registry: Option<Arc<ComponentRegistry>>,
    anchor: MemoryAnchor,
    state: Arc<StdMutex<FixtureKeyringState>>,
    provider: Option<Arc<RegistrySensitiveParamProvider>>,
}

#[cfg(feature = "test-support")]
impl CarrierHarness {
    async fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let registry = Arc::new(
            ComponentRegistry::open_in(temp.path(), "components.db")
                .await
                .unwrap(),
        );
        let anchor = MemoryAnchor::default();
        let state = Arc::new(StdMutex::new(FixtureKeyringState::new()));
        let (provider, _) =
            open_fixture_provider(Arc::clone(&registry), anchor.clone(), Arc::clone(&state)).await;
        Self {
            temp,
            registry: Some(registry),
            anchor,
            state,
            provider: Some(provider),
        }
    }

    fn provider(&self) -> &Arc<RegistrySensitiveParamProvider> {
        self.provider.as_ref().unwrap()
    }

    fn database_path(&self) -> std::path::PathBuf {
        self.temp.path().join("components.db")
    }

    async fn restart(&mut self) {
        drop(self.provider.take());
        drop(self.registry.take());
        let registry = Arc::new(
            ComponentRegistry::open_in(self.temp.path(), "components.db")
                .await
                .unwrap(),
        );
        let (provider, _) = open_fixture_provider(
            Arc::clone(&registry),
            self.anchor.clone(),
            Arc::clone(&self.state),
        )
        .await;
        self.registry = Some(registry);
        self.provider = Some(provider);
    }

    fn assert_only_tag_six_mutations(&self) {
        let tags = self.anchor.operation_tags();
        assert!(!tags.is_empty());
        assert!(tags.iter().all(|tag| *tag == 6), "observed tags: {tags:?}");
    }
}

#[cfg(feature = "test-support")]
fn assert_failpoint_readiness(
    provider: &RegistrySensitiveParamProvider,
    stage: ObservationMutationFailpointStage,
) {
    assert_eq!(
        provider.is_ready(),
        !carrier_failpoint_crosses_anchor_prepare(stage),
        "closed failpoint readiness at {stage:?}"
    );
}

#[cfg(feature = "test-support")]
async fn assert_carrier_reservation_failpoint(stage: ObservationMutationFailpointStage, seed: u64) {
    let mut harness = CarrierHarness::new().await;
    let fixture = harness
        .provider()
        .carrier_migration_test_fixture(seed, 1)
        .unwrap();
    let plan = fixture.plan();
    harness
        .provider()
        .inject_next_observation_mutation_failpoint(stage)
        .unwrap();
    assert!(harness.provider().reserve_carrier_migration(&plan).is_err());
    assert_failpoint_readiness(harness.provider(), stage);
    harness.restart().await;
    let reservation = harness.provider().reserve_carrier_migration(&plan).unwrap();
    assert_eq!(
        harness
            .provider()
            .recover_carrier_migration(&reservation)
            .unwrap(),
        CarrierMigrationRecoveryPhase::Issuing
    );
    harness.assert_only_tag_six_mutations();
}

#[cfg(feature = "test-support")]
async fn assert_carrier_prepare_failpoint(
    stage: ObservationMutationFailpointStage,
    seed: u64,
    store: CarrierMigrationStore,
) {
    let mut harness = CarrierHarness::new().await;
    let fixture = harness
        .provider()
        .carrier_migration_test_fixture(seed, 1)
        .unwrap();
    let reservation = harness
        .provider()
        .reserve_carrier_migration(&fixture.plan())
        .unwrap();
    let owner_intent = fixture
        .prepared_owner_intent(&reservation, 0, store)
        .unwrap();
    harness
        .provider()
        .inject_next_observation_mutation_failpoint(stage)
        .unwrap();
    assert!(harness
        .provider()
        .prepare_carrier_migration_row(&reservation, &owner_intent)
        .is_err());
    assert_failpoint_readiness(harness.provider(), stage);
    harness.restart().await;
    harness
        .provider()
        .prepare_carrier_migration_row(&reservation, &owner_intent)
        .unwrap();
    assert_eq!(
        harness
            .provider()
            .recover_carrier_migration(&reservation)
            .unwrap(),
        CarrierMigrationRecoveryPhase::OwnerReady
    );
    harness.assert_only_tag_six_mutations();
}

#[cfg(feature = "test-support")]
async fn assert_carrier_finalize_failpoint(
    stage: ObservationMutationFailpointStage,
    seed: u64,
    store: CarrierMigrationStore,
) {
    let mut harness = CarrierHarness::new().await;
    let fixture = harness
        .provider()
        .carrier_migration_test_fixture(seed, 1)
        .unwrap();
    let reservation = harness
        .provider()
        .reserve_carrier_migration(&fixture.plan())
        .unwrap();
    let owner_intent = fixture
        .prepared_owner_intent(&reservation, 0, store)
        .unwrap();
    let prepared = harness
        .provider()
        .prepare_carrier_migration_row(&reservation, &owner_intent)
        .unwrap();
    let owner_commit = fixture.owner_commit(&prepared).unwrap();
    harness
        .provider()
        .inject_next_observation_mutation_failpoint(stage)
        .unwrap();
    assert!(harness
        .provider()
        .finalize_carrier_migration_row(&prepared, &owner_commit)
        .is_err());
    assert_failpoint_readiness(harness.provider(), stage);
    harness.restart().await;
    harness
        .provider()
        .finalize_carrier_migration_row(&prepared, &owner_commit)
        .unwrap();
    assert_eq!(
        harness
            .provider()
            .recover_carrier_migration(&reservation)
            .unwrap(),
        CarrierMigrationRecoveryPhase::Verifying
    );
    harness.assert_only_tag_six_mutations();
}

#[cfg(feature = "test-support")]
async fn assert_carrier_verify_failpoint(
    stage: ObservationMutationFailpointStage,
    seed: u64,
    store: CarrierMigrationStore,
) {
    let mut harness = CarrierHarness::new().await;
    let fixture = harness
        .provider()
        .carrier_migration_test_fixture(seed, 1)
        .unwrap();
    let reservation = harness
        .provider()
        .reserve_carrier_migration(&fixture.plan())
        .unwrap();
    let owner_intent = fixture
        .prepared_owner_intent(&reservation, 0, store)
        .unwrap();
    let prepared = harness
        .provider()
        .prepare_carrier_migration_row(&reservation, &owner_intent)
        .unwrap();
    let owner_commit = fixture.owner_commit(&prepared).unwrap();
    harness
        .provider()
        .finalize_carrier_migration_row(&prepared, &owner_commit)
        .unwrap();
    let owner_finalized = fixture.owner_finalized(&reservation).unwrap();
    harness
        .provider()
        .inject_next_observation_mutation_failpoint(stage)
        .unwrap();
    assert!(harness
        .provider()
        .verify_carrier_migration_owner_finalized(&reservation, &owner_finalized)
        .is_err());
    assert_failpoint_readiness(harness.provider(), stage);
    harness.restart().await;
    harness
        .provider()
        .verify_carrier_migration_owner_finalized(&reservation, &owner_finalized)
        .unwrap();
    assert_eq!(
        harness
            .provider()
            .recover_carrier_migration(&reservation)
            .unwrap(),
        CarrierMigrationRecoveryPhase::Verified
    );
    harness.assert_only_tag_six_mutations();
}

#[cfg(feature = "test-support")]
#[tokio::test(flavor = "multi_thread")]
async fn migration_zero_one_cap_and_plus_one_reservations() {
    const CAP: u64 = 4_194_304;

    let zero = CarrierHarness::new().await;
    let zero_fixture = zero
        .provider()
        .carrier_migration_test_fixture(10_001, 0)
        .unwrap();
    let zero_reservation = zero
        .provider()
        .reserve_carrier_migration(&zero_fixture.plan())
        .unwrap();
    assert_eq!(
        zero.provider()
            .recover_carrier_migration(&zero_reservation)
            .unwrap(),
        CarrierMigrationRecoveryPhase::Verified
    );
    assert!(zero_fixture
        .prepared_owner_intent(&zero_reservation, 0, CarrierMigrationStore::Sqlite)
        .is_err());

    let one = CarrierHarness::new().await;
    let one_fixture = one
        .provider()
        .carrier_migration_test_fixture(10_002, 1)
        .unwrap();
    let one_reservation = one
        .provider()
        .reserve_carrier_migration(&one_fixture.plan())
        .unwrap();
    assert_eq!(
        one.provider()
            .recover_carrier_migration(&one_reservation)
            .unwrap(),
        CarrierMigrationRecoveryPhase::Issuing
    );

    let cap = CarrierHarness::new().await;
    let cap_fixture = cap
        .provider()
        .carrier_migration_test_fixture(10_003, CAP)
        .unwrap();
    let cap_reservation = cap
        .provider()
        .reserve_carrier_migration(&cap_fixture.plan())
        .unwrap();
    assert_eq!(
        cap.provider()
            .recover_carrier_migration(&cap_reservation)
            .unwrap(),
        CarrierMigrationRecoveryPhase::Issuing
    );
    cap_fixture
        .prepared_owner_intent(&cap_reservation, CAP - 1, CarrierMigrationStore::Jsonl)
        .unwrap();
    let inspection = rusqlite::Connection::open(cap.database_path()).unwrap();
    let header: (i64, i64, i64, String) = inspection
        .query_row(
            "SELECT planned_row_count,actual_encoded_bytes,future_reserved_bytes,phase
             FROM observation_carrier_migrations",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    let allocated_rows: i64 = inspection
        .query_row(
            "SELECT COUNT(*) FROM observation_carrier_migration_rows",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(header, (CAP as i64, 0, 8_589_934_592, "issuing".into()));
    assert_eq!(allocated_rows, 0, "cap fixture must stay compact");

    let plus_one = CarrierHarness::new().await;
    let plus_fixture = plus_one
        .provider()
        .carrier_migration_test_fixture(10_004, CAP + 1)
        .unwrap();
    let tags_before = plus_one.anchor.operation_tags();
    assert!(matches!(
        plus_one
            .provider()
            .reserve_carrier_migration(&plus_fixture.plan()),
        Err(ObservationProviderError::CapacityExceeded(_))
    ));
    assert_eq!(plus_one.anchor.operation_tags(), tags_before);
    let inspection = rusqlite::Connection::open(plus_one.database_path()).unwrap();
    let headers: i64 = inspection
        .query_row(
            "SELECT COUNT(*) FROM observation_carrier_migrations",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(headers, 0, "cap+1 rejects before durable exposure");
}

#[cfg(feature = "test-support")]
#[tokio::test(flavor = "multi_thread")]
async fn every_prepared_owner_commit_finalized_failpoint_recovers() {
    // First prove both closed owner kinds advance through every durable phase.
    let happy = CarrierHarness::new().await;
    let fixture = happy
        .provider()
        .carrier_migration_test_fixture(20_001, 2)
        .unwrap();
    let reservation = happy
        .provider()
        .reserve_carrier_migration(&fixture.plan())
        .unwrap();
    assert_eq!(
        happy
            .provider()
            .recover_carrier_migration(&reservation)
            .unwrap(),
        CarrierMigrationRecoveryPhase::Issuing
    );
    let sqlite_owner = fixture
        .prepared_owner_intent(&reservation, 0, CarrierMigrationStore::Sqlite)
        .unwrap();
    let sqlite_prepared = happy
        .provider()
        .prepare_carrier_migration_row(&reservation, &sqlite_owner)
        .unwrap();
    assert_eq!(
        happy
            .provider()
            .recover_carrier_migration(&reservation)
            .unwrap(),
        CarrierMigrationRecoveryPhase::Issuing
    );
    let jsonl_owner = fixture
        .prepared_owner_intent(&reservation, 1, CarrierMigrationStore::Jsonl)
        .unwrap();
    let jsonl_prepared = happy
        .provider()
        .prepare_carrier_migration_row(&reservation, &jsonl_owner)
        .unwrap();
    assert_eq!(
        happy
            .provider()
            .recover_carrier_migration(&reservation)
            .unwrap(),
        CarrierMigrationRecoveryPhase::OwnerReady
    );
    happy
        .provider()
        .finalize_carrier_migration_row(
            &sqlite_prepared,
            &fixture.owner_commit(&sqlite_prepared).unwrap(),
        )
        .unwrap();
    assert_eq!(
        happy
            .provider()
            .recover_carrier_migration(&reservation)
            .unwrap(),
        CarrierMigrationRecoveryPhase::OwnerReady
    );
    happy
        .provider()
        .finalize_carrier_migration_row(
            &jsonl_prepared,
            &fixture.owner_commit(&jsonl_prepared).unwrap(),
        )
        .unwrap();
    assert_eq!(
        happy
            .provider()
            .recover_carrier_migration(&reservation)
            .unwrap(),
        CarrierMigrationRecoveryPhase::Verifying
    );
    happy
        .provider()
        .verify_carrier_migration_owner_finalized(
            &reservation,
            &fixture.owner_finalized(&reservation).unwrap(),
        )
        .unwrap();
    assert_eq!(
        happy
            .provider()
            .recover_carrier_migration(&reservation)
            .unwrap(),
        CarrierMigrationRecoveryPhase::Verified
    );
    happy.assert_only_tag_six_mutations();

    // Every closed runner boundary is exercised independently for reservation,
    // per-row prepare, per-row finalization, and whole-owner verification.
    for (index, stage) in CARRIER_MUTATION_FAILPOINTS.into_iter().enumerate() {
        let seed = 21_000 + (index as u64 * 10);
        let store = if index % 2 == 0 {
            CarrierMigrationStore::Sqlite
        } else {
            CarrierMigrationStore::Jsonl
        };
        assert_carrier_reservation_failpoint(stage, seed + 1).await;
        assert_carrier_prepare_failpoint(stage, seed + 2, store).await;
        assert_carrier_finalize_failpoint(stage, seed + 3, store).await;
        assert_carrier_verify_failpoint(stage, seed + 4, store).await;
    }
}

#[cfg(feature = "test-support")]
#[tokio::test(flavor = "multi_thread")]
async fn carrier_migration_replay_cross_plan_order_and_tamper_reject() {
    let first = CarrierHarness::new().await;
    let second = CarrierHarness::new().await;
    let first_fixture = first
        .provider()
        .carrier_migration_test_fixture(30_001, 2)
        .unwrap();
    let second_fixture = second
        .provider()
        .carrier_migration_test_fixture(30_002, 1)
        .unwrap();
    let first_reservation = first
        .provider()
        .reserve_carrier_migration(&first_fixture.plan())
        .unwrap();
    let second_reservation = second
        .provider()
        .reserve_carrier_migration(&second_fixture.plan())
        .unwrap();

    assert!(first_fixture
        .prepared_owner_intent(&second_reservation, 0, CarrierMigrationStore::Sqlite)
        .is_err());
    assert!(second_fixture
        .prepared_owner_intent(&first_reservation, 0, CarrierMigrationStore::Sqlite)
        .is_err());
    let second_owner = second_fixture
        .prepared_owner_intent(&second_reservation, 0, CarrierMigrationStore::Sqlite)
        .unwrap();
    assert!(first
        .provider()
        .prepare_carrier_migration_row(&first_reservation, &second_owner)
        .is_err());

    let ordinal_one_early = first_fixture
        .prepared_owner_intent(&first_reservation, 1, CarrierMigrationStore::Jsonl)
        .unwrap();
    assert!(matches!(
        first
            .provider()
            .prepare_carrier_migration_row(&first_reservation, &ordinal_one_early),
        Err(ObservationProviderError::InvalidState(_))
    ));
    let first_owner = first_fixture
        .prepared_owner_intent(&first_reservation, 0, CarrierMigrationStore::Jsonl)
        .unwrap();
    let first_prepared = first
        .provider()
        .prepare_carrier_migration_row(&first_reservation, &first_owner)
        .unwrap();
    assert!(second_fixture.owner_commit(&first_prepared).is_err());

    let crossed_store = first_fixture
        .prepared_owner_intent(&first_reservation, 1, CarrierMigrationStore::Sqlite)
        .unwrap();
    assert!(matches!(
        first
            .provider()
            .prepare_carrier_migration_row(&first_reservation, &crossed_store),
        Err(ObservationProviderError::InvalidState(_))
    ));
    let second_first_plan_owner = first_fixture
        .prepared_owner_intent(&first_reservation, 1, CarrierMigrationStore::Jsonl)
        .unwrap();
    let second_first_plan_prepared = first
        .provider()
        .prepare_carrier_migration_row(&first_reservation, &second_first_plan_owner)
        .unwrap();

    let second_prepared = second
        .provider()
        .prepare_carrier_migration_row(&second_reservation, &second_owner)
        .unwrap();
    let second_commit = second_fixture.owner_commit(&second_prepared).unwrap();
    assert!(first
        .provider()
        .finalize_carrier_migration_row(&first_prepared, &second_commit)
        .is_err());

    let first_commit = first_fixture.owner_commit(&first_prepared).unwrap();
    let first_commit_replay = first_fixture.owner_commit(&first_prepared).unwrap();
    let second_first_plan_commit = first_fixture
        .owner_commit(&second_first_plan_prepared)
        .unwrap();
    assert!(first
        .provider()
        .finalize_carrier_migration_row(&first_prepared, &second_first_plan_commit)
        .is_err());
    first
        .provider()
        .finalize_carrier_migration_row(&first_prepared, &first_commit)
        .unwrap();
    first
        .provider()
        .finalize_carrier_migration_row(&first_prepared, &first_commit_replay)
        .unwrap();
    assert_eq!(
        first
            .provider()
            .recover_carrier_migration(&first_reservation)
            .unwrap(),
        CarrierMigrationRecoveryPhase::OwnerReady
    );
    assert!(first
        .provider()
        .prepare_carrier_migration_row(&first_reservation, &first_owner)
        .is_err());
    first
        .provider()
        .finalize_carrier_migration_row(&second_first_plan_prepared, &second_first_plan_commit)
        .unwrap();
    assert_eq!(
        first
            .provider()
            .recover_carrier_migration(&first_reservation)
            .unwrap(),
        CarrierMigrationRecoveryPhase::Verifying
    );

    let crossed_finalized = second_fixture.owner_finalized(&second_reservation).unwrap();
    assert!(first
        .provider()
        .verify_carrier_migration_owner_finalized(&first_reservation, &crossed_finalized)
        .is_err());
    let finalized = first_fixture.owner_finalized(&first_reservation).unwrap();
    first
        .provider()
        .verify_carrier_migration_owner_finalized(&first_reservation, &finalized)
        .unwrap();
    first
        .provider()
        .verify_carrier_migration_owner_finalized(&first_reservation, &finalized)
        .unwrap();
    assert_eq!(
        first
            .provider()
            .recover_carrier_migration(&first_reservation)
            .unwrap(),
        CarrierMigrationRecoveryPhase::Verified
    );

    // Durable bytes remain independently adversarial: changing one bound row
    // byte without the anchored ledger must fail the recovery read.
    let tamper = rusqlite::Connection::open(first.database_path()).unwrap();
    assert_eq!(
        tamper
            .execute(
                "UPDATE observation_carrier_migration_rows
                 SET event_cursor_digest=?1",
                rusqlite::params![[0xee_u8; 32].as_slice()],
            )
            .unwrap(),
        2
    );
    assert!(matches!(
        first
            .provider()
            .recover_carrier_migration(&first_reservation),
        Err(ObservationProviderError::RecoveryRequired(_))
    ));
}

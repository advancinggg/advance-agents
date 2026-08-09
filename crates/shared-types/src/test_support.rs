//! Fixture-only constructors for opaque provider authority.
//!
//! This module exists only behind the non-default `test-support` feature.  It
//! is intentionally absent from production builds; no production crate may
//! enable the feature.

use crate::contract218_previsible::{
    C123Purpose2ZeroToken, Contract218RoleRootMaterial, CustodySignedPersistedIdentity,
    PersistedIdentityKeyCapabilityBinding, PersistedIdentityKeyStatus,
    PersistedIdentityKeyringBinding, PersistedIdentityKeyringProvider,
    PersistedIdentityKeyringRole, PersistedIdentitySigningRequest,
    PersistedIdentityVerificationRequest, PersistedKeyRetirementChallenge,
    PersistedKeyRetirementScanSet, PrevisibleAbortReceiptSet, PrevisibleObservationActivation,
    PrevisibleProofIssuerRole, PrevisibleProofVerifierRole, PrevisibleReadyReceiptSet,
    RetainedTombstoneGcChallenge, RetainedTombstoneGcReceiptSet, SourceEmissionReceiptIssuer,
    TerminationCleanupReceiptIssuerRole, TerminationCleanupReceiptSet,
    TerminationCleanupReceiptVerifierRole, TerminationGrantSubjectDrainReceiptSet,
    TerminationOperationRecord, TerminationSourceEmissionQuiesceReceiptSet,
    TerminationStateMachineRole,
};
use crate::observation_identity::{
    compute_hmac, ObservationIdentityClaims, PersistedObservationBinding,
    PersistedObservationIdentity, SensitiveParamCatalogError, TrustedObservationIdentity,
    VerifiedGrantSubjectDrainToken, VerifiedSourceEmissionQuiesceReceipt,
};
use crate::sensitive_observation::{
    self, BoundObservationDocument, Contract123ObservationSubject, ObservationAssociationError,
    ObservationAssociationRoleFactory, ObservationAssociationRoleParts, ObservationDocument,
    ObservationEmissionLease, ObservationEventAssociationIssuer, ObservationNode,
    ObservationProviderDtoAssociationIssuer, ObservationSchemaManifest, ObservationScope,
    OBSERVATION_ASSOCIATION_PROOF_LEN,
};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub type Contract218TestRoles = (
    PrevisibleProofIssuerRole,
    PrevisibleProofVerifierRole,
    TerminationStateMachineRole,
    TerminationCleanupReceiptIssuerRole,
    TerminationCleanupReceiptVerifierRole,
);

/// Build deterministic test roles.  Raw key material is accepted nowhere
/// outside this feature-gated fixture module.
pub fn contract218_roles(
    registry_instance: [u8; 16],
    boot: [u8; 16],
    _persistence_key_id: u32,
    previsible_root: [u8; 32],
    termination_root: [u8; 32],
) -> Result<Contract218TestRoles, SensitiveParamCatalogError> {
    Contract218RoleRootMaterial::from_authenticated_custody(
        registry_instance,
        boot,
        Zeroizing::new(previsible_root),
        Zeroizing::new(termination_root),
    )?
    .into_lifecycle_factory()
    .split_once()
    .map(|roles| roles.move_to_composition())
}

/// Install deterministic raw-key custody only for tests.  Production obtains
/// the installer from the same verifier but supplies its authenticated CLI
/// keyring provider; no production raw-key constructor exists.
pub fn persisted_identity_keyring_role(
    verifier: &mut PrevisibleProofVerifierRole,
    registry_instance: [u8; 16],
    signing_key_id: u32,
    master_key: [u8; 32],
    kdf_salt: [u8; 32],
) -> Result<PersistedIdentityKeyringRole, SensitiveParamCatalogError> {
    let provider = FixturePersistedIdentityKeyring::new(
        registry_instance,
        signing_key_id,
        master_key,
        kdf_salt,
    )?;
    verifier
        .take_persisted_identity_keyring_installer()?
        .install_authenticated_custody(Box::new(provider))
}

/// Exact-root fixture for scheduler/CLI composition tests.  The binding must
/// be the root and generation computed from the authenticated fixture file;
/// raw key material remains confined to test-support.
#[allow(clippy::too_many_arguments)]
pub fn persisted_identity_keyring_role_for_binding(
    verifier: &mut PrevisibleProofVerifierRole,
    registry_instance: [u8; 16],
    keyring_root: [u8; 32],
    keyring_generation: u64,
    signing_key_id: u32,
    master_key: [u8; 32],
    kdf_salt: [u8; 32],
) -> Result<PersistedIdentityKeyringRole, SensitiveParamCatalogError> {
    let binding = PersistedIdentityKeyringBinding::from_authenticated_keyring(
        registry_instance,
        keyring_root,
        keyring_generation,
    )?;
    let provider = FixturePersistedIdentityKeyring::new_for_binding(
        binding,
        signing_key_id,
        master_key,
        kdf_salt,
    )?;
    verifier
        .take_persisted_identity_keyring_installer()?
        .install_authenticated_custody(Box::new(provider))
}

struct FixturePersistedIdentityKeyring {
    binding: PersistedIdentityKeyringBinding,
    signing_key_id: u32,
    master_key: Zeroizing<[u8; 32]>,
    kdf_salt: [u8; 32],
}

impl FixturePersistedIdentityKeyring {
    fn new(
        registry_instance: [u8; 16],
        signing_key_id: u32,
        master_key: [u8; 32],
        kdf_salt: [u8; 32],
    ) -> Result<Self, SensitiveParamCatalogError> {
        if signing_key_id == 0 || kdf_salt == [0; 32] {
            return Err(SensitiveParamCatalogError::InvalidIdentity);
        }
        let mut root = Sha256::new();
        root.update(b"advance.contract218.test-keyring-root.v1\0");
        root.update(registry_instance);
        root.update(signing_key_id.to_be_bytes());
        root.update(kdf_salt);
        let binding = PersistedIdentityKeyringBinding::from_authenticated_keyring(
            registry_instance,
            root.finalize().into(),
            u64::from(signing_key_id - 1),
        )?;
        Self::new_for_binding(binding, signing_key_id, master_key, kdf_salt)
    }

    fn new_for_binding(
        binding: PersistedIdentityKeyringBinding,
        signing_key_id: u32,
        master_key: [u8; 32],
        kdf_salt: [u8; 32],
    ) -> Result<Self, SensitiveParamCatalogError> {
        if signing_key_id == 0 || kdf_salt == [0; 32] {
            return Err(SensitiveParamCatalogError::InvalidIdentity);
        }
        Ok(Self {
            binding,
            signing_key_id,
            master_key: Zeroizing::new(master_key),
            kdf_salt,
        })
    }

    fn capability_binding(
        &self,
        key_id: u32,
    ) -> Result<PersistedIdentityKeyCapabilityBinding, SensitiveParamCatalogError> {
        if key_id == 0 || key_id > self.signing_key_id {
            return Err(SensitiveParamCatalogError::UnknownIdentity);
        }
        PersistedIdentityKeyCapabilityBinding::from_authenticated_keyring(
            self.binding,
            key_id,
            1,
            if key_id == self.signing_key_id {
                PersistedIdentityKeyStatus::Signing
            } else {
                PersistedIdentityKeyStatus::VerifyOnly
            },
        )
    }

    fn derive_key(&self, key_id: u32) -> Result<Zeroizing<[u8; 32]>, SensitiveParamCatalogError> {
        self.capability_binding(key_id)?;
        let mut info = b"advance.contract218.persisted-identity-key.v1\0".to_vec();
        info.extend_from_slice(&key_id.to_be_bytes());
        let hkdf = Hkdf::<Sha256>::new(Some(&self.kdf_salt), self.master_key.as_ref());
        let mut key = Zeroizing::new([0; 32]);
        hkdf.expand(&info, key.as_mut())
            .map_err(|_| SensitiveParamCatalogError::InvalidCarrier)?;
        Ok(key)
    }
}

impl PersistedIdentityKeyringProvider for FixturePersistedIdentityKeyring {
    fn current_keyring_binding(
        &self,
    ) -> Result<PersistedIdentityKeyringBinding, SensitiveParamCatalogError> {
        Ok(self.binding)
    }

    fn signing_key_binding(
        &self,
    ) -> Result<PersistedIdentityKeyCapabilityBinding, SensitiveParamCatalogError> {
        self.capability_binding(self.signing_key_id)
    }

    fn verification_key_binding(
        &self,
        key_id: u32,
    ) -> Result<PersistedIdentityKeyCapabilityBinding, SensitiveParamCatalogError> {
        self.capability_binding(key_id)
    }

    fn sign_persisted_identity(
        &self,
        request: &PersistedIdentitySigningRequest,
    ) -> Result<CustodySignedPersistedIdentity, SensitiveParamCatalogError> {
        let binding = request.key_binding();
        if binding != self.capability_binding(self.signing_key_id)? {
            return Err(SensitiveParamCatalogError::InvalidCarrier);
        }
        let key = self.derive_key(binding.key_id())?;
        let mac = compute_hmac(
            &key,
            b"advance.contract218.persisted-identity.v1\0",
            request.canonical_preceding_bytes(),
        )?;
        let mut canonical = request.canonical_preceding_bytes().to_vec();
        canonical.extend_from_slice(&mac);
        Ok(CustodySignedPersistedIdentity::from_typed_signing_operation(canonical))
    }

    fn verify_persisted_identity(
        &self,
        request: &PersistedIdentityVerificationRequest,
    ) -> Result<(), SensitiveParamCatalogError> {
        let binding = request.key_binding();
        if binding != self.capability_binding(binding.key_id())? {
            return Err(SensitiveParamCatalogError::InvalidCarrier);
        }
        let canonical = request.canonical_bytes();
        if canonical.len() < 32 {
            return Err(SensitiveParamCatalogError::InvalidCarrier);
        }
        let mac_offset = canonical.len() - 32;
        let observed: [u8; 32] = canonical[mac_offset..]
            .try_into()
            .map_err(|_| SensitiveParamCatalogError::InvalidCarrier)?;
        let key = self.derive_key(binding.key_id())?;
        let expected = compute_hmac(
            &key,
            b"advance.contract218.persisted-identity.v1\0",
            &canonical[..mac_offset],
        )?;
        if bool::from(expected.ct_eq(&observed)) {
            Ok(())
        } else {
            Err(SensitiveParamCatalogError::InvalidCarrier)
        }
    }
}

pub fn previsible_ready_receipts(
    issuer: &PrevisibleProofIssuerRole,
    activation: &PrevisibleObservationActivation,
) -> Result<PrevisibleReadyReceiptSet, SensitiveParamCatalogError> {
    issuer.issue_test_ready_receipts(activation)
}

pub fn previsible_abort_receipts(
    issuer: &PrevisibleProofIssuerRole,
    activation: &PrevisibleObservationActivation,
) -> Result<PrevisibleAbortReceiptSet, SensitiveParamCatalogError> {
    issuer.issue_test_abort_receipts(activation)
}

pub fn termination_cleanup_receipts(
    issuer: &TerminationCleanupReceiptIssuerRole,
    record: &TerminationOperationRecord,
    members: &[ObservationIdentityClaims],
    high_water: u64,
) -> Result<TerminationCleanupReceiptSet, SensitiveParamCatalogError> {
    issuer.issue_test_cleanup_receipt_set(record, members, high_water)
}

pub fn termination_prepare_receipts(
    source_issuer: &SourceEmissionReceiptIssuer,
    cleanup_issuer: &TerminationCleanupReceiptIssuerRole,
    record: &TerminationOperationRecord,
    members: &[ObservationIdentityClaims],
    handle_table_generation: u64,
    high_water: u64,
) -> Result<
    (
        TerminationGrantSubjectDrainReceiptSet,
        TerminationSourceEmissionQuiesceReceiptSet,
    ),
    SensitiveParamCatalogError,
> {
    let grants = cleanup_issuer.issue_test_grant_subject_drain_set(record, members, high_water)?;
    let emissions = members
        .iter()
        .cloned()
        .map(|member| {
            source_issuer.issue_quiesce_receipt(
                record.clone(),
                member,
                handle_table_generation,
                high_water,
                high_water,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok((
        grants,
        TerminationSourceEmissionQuiesceReceiptSet::new(emissions),
    ))
}

pub fn termination_prepare_receipt_vectors(
    source_issuer: &SourceEmissionReceiptIssuer,
    cleanup_issuer: &TerminationCleanupReceiptIssuerRole,
    record: &TerminationOperationRecord,
    members: &[ObservationIdentityClaims],
    handle_table_generation: u64,
    high_water: u64,
) -> Result<
    (
        Vec<VerifiedGrantSubjectDrainToken>,
        Vec<VerifiedSourceEmissionQuiesceReceipt>,
    ),
    SensitiveParamCatalogError,
> {
    let (grants, emissions) = termination_prepare_receipts(
        source_issuer,
        cleanup_issuer,
        record,
        members,
        handle_table_generation,
        high_water,
    )?;
    Ok((grants.into_test_receipts(), emissions.into_test_receipts()))
}

pub fn retained_tombstone_gc_inputs(
    provider: &PrevisibleProofVerifierRole,
    challenge: &RetainedTombstoneGcChallenge,
    owners: [([u8; 16], u64, [u8; 32]); 5],
) -> Result<(C123Purpose2ZeroToken, RetainedTombstoneGcReceiptSet), SensitiveParamCatalogError> {
    provider.issue_test_retained_gc_inputs(challenge, owners)
}

#[allow(clippy::too_many_arguments)]
pub fn persisted_key_retirement_scans(
    provider: &PrevisibleProofVerifierRole,
    challenge: &PersistedKeyRetirementChallenge,
    sqlite: ([u8; 16], u64, [u8; 32]),
    jsonl: ([u8; 16], [u8; 32], u64, u64, u64),
    migration: ([u8; 16], u64, [u8; 32]),
) -> Result<PersistedKeyRetirementScanSet, SensitiveParamCatalogError> {
    provider.issue_test_persisted_key_retirement_scans(challenge, sqlite, jsonl, migration)
}

pub fn observation_association_roles(
    association_key: [u8; 32],
    boot_instance_id: [u8; 16],
    schemas: Vec<ObservationSchemaManifest>,
) -> Result<ObservationAssociationRoleParts, ObservationAssociationError> {
    ObservationAssociationRoleFactory::new_at_composition(
        Zeroizing::new(association_key),
        boot_instance_id,
        schemas,
    )?
    .split_once()
}

/// Provider fixture for one exact LiveIngress emission.  `None` selects the explicit structural
/// event discriminator; a manifest must exactly match one registered at role composition.
pub fn live_ingress_observation_fixture(
    issuer: &ObservationEventAssociationIssuer,
    identity: &TrustedObservationIdentity,
    manifest: Option<&ObservationSchemaManifest>,
    envelope: ObservationNode,
    payload: ObservationNode,
) -> Result<(ObservationEmissionLease, ObservationDocument), ObservationAssociationError> {
    issuer.issue_test_live_event(
        identity,
        ObservationScope::LiveIngress,
        manifest,
        envelope,
        payload,
    )
}

/// Provider fixture for one exact LiveFinalEvent emission.
pub fn live_final_observation_fixture(
    issuer: &ObservationEventAssociationIssuer,
    identity: &TrustedObservationIdentity,
    manifest: Option<&ObservationSchemaManifest>,
    envelope: ObservationNode,
    payload: ObservationNode,
) -> Result<(ObservationEmissionLease, ObservationDocument), ObservationAssociationError> {
    issuer.issue_test_live_event(
        identity,
        ObservationScope::LiveFinalEvent,
        manifest,
        envelope,
        payload,
    )
}

/// Provider fixture for the exact persisted carrier/binding document provenance.
pub fn persisted_event_observation_fixture(
    issuer: &ObservationEventAssociationIssuer,
    persisted: &PersistedObservationIdentity,
    observed: &PersistedObservationBinding,
    manifest: Option<&ObservationSchemaManifest>,
    envelope: ObservationNode,
    payload: ObservationNode,
) -> Result<ObservationDocument, ObservationAssociationError> {
    issuer.issue_test_persisted_event_document(persisted, observed, manifest, envelope, payload)
}

/// Exact CONTRACT-123 provider fixture.  Production has no equivalent raw-identity constructor;
/// Order 4 supplies `GrantSubjectAuthorityHandle` instead.
pub fn provider_dto_observation_fixture(
    issuer: &ObservationProviderDtoAssociationIssuer,
    identity: &TrustedObservationIdentity,
    manifest: Option<&ObservationSchemaManifest>,
    root: ObservationNode,
) -> Result<(Contract123ObservationSubject, ObservationDocument), ObservationAssociationError> {
    issuer.issue_test_provider_dto(identity, manifest, root)
}

pub fn association_proof_bytes(
    bound: &BoundObservationDocument,
) -> [u8; OBSERVATION_ASSOCIATION_PROOF_LEN] {
    sensitive_observation::test_association_proof_bytes(bound)
}

pub fn swap_bound_documents(
    left: &mut BoundObservationDocument,
    right: &mut BoundObservationDocument,
) {
    sensitive_observation::test_swap_bound_documents(left, right);
}

pub fn swap_bound_safe_digests(
    left: &mut BoundObservationDocument,
    right: &mut BoundObservationDocument,
) {
    sensitive_observation::test_swap_bound_safe_digests(left, right);
}

pub fn swap_bound_authorities(
    left: &mut BoundObservationDocument,
    right: &mut BoundObservationDocument,
) {
    sensitive_observation::test_swap_bound_authorities(left, right);
}

pub fn swap_bound_proofs(
    left: &mut BoundObservationDocument,
    right: &mut BoundObservationDocument,
) {
    sensitive_observation::test_swap_bound_proofs(left, right);
}

pub fn corrupt_bound_proof_byte(bound: &mut BoundObservationDocument, index: usize) {
    sensitive_observation::test_corrupt_bound_proof_byte(bound, index);
}

pub fn set_bound_proof_byte(bound: &mut BoundObservationDocument, index: usize, value: u8) {
    sensitive_observation::test_set_bound_proof_byte(bound, index, value);
}

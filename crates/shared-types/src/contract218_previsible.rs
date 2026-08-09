//! CONTRACT-218 move-only role split and previsible activation primitives.
//!
//! This module supplies concrete host capabilities, not another CONTRACT-218
//! port.  A factory consumes two independent role roots and can be split only
//! once because both factory and resulting role set are move-only.  The five
//! roles returned by [`Contract218LifecycleRoleSet::move_to_composition`] are
//! the exact five destinations described by MODULE-014; there is no aggregate
//! registrar, generic signer, upcast, or raw-key accessor.

use crate::observation_identity::{
    compute_hmac, put_text, verify_hmac, AuthenticatedObservationSourceHandle,
    CommittedComponentSourceReceipt, CompletedIdentityHydrationReceipt,
    DecodedPersistedObservationIdentity, IssuedObservationSourceHandle, ObservationAuthorityScope,
    ObservationIdentityClaims, ObservationIdentityClass, PersistedObservationBinding,
    PersistedObservationIdentity, SensitiveParamCatalogError, SensitiveParamSnapshot,
    SourceBindingDigest, TrustedObservationIdentity,
};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::fmt;
use std::sync::Arc;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

macro_rules! opaque_debug {
    ($name:ty) => {
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "(<opaque>)"))
            }
        }
    };
}

const SOURCE_HANDLE_DOMAIN: &[u8] = b"advance.contract218.live-source-handle.v1\0";
const TRUSTED_IDENTITY_DOMAIN: &[u8] = b"advance.contract218.trusted-identity.v1\0";
const COMPONENT_RECEIPT_DOMAIN: &[u8] = b"advance.contract218.component-commit-receipt.v1\0";
const HYDRATION_RECEIPT_DOMAIN: &[u8] = b"advance.contract218.hydration-receipt.v1\0";
const ACTIVATION_DOMAIN: &[u8] = b"advance.contract218.previsible-activation.v1\0";
const READY_DOMAIN: &[u8] = b"advance.contract218.previsible-ready.v1\0";
const ABORT_DOMAIN: &[u8] = b"advance.contract218.previsible-abort.v1\0";
const READY_RECOVERY_NONCE_DOMAIN: &[u8] = b"advance.contract218.publication-recovery-nonce.v1\0";
const READY_REJECTION_NONCE_DOMAIN: &[u8] = b"advance.contract218.publication-rejection-nonce.v1\0";
const ABORT_RECOVERY_NONCE_DOMAIN: &[u8] = b"advance.contract218.abort-recovery-nonce.v1\0";
const PUBLICATION_ACK_DOMAIN: &[u8] = b"advance.contract218.publication-ack.v1\0";
const READY_SUBJECT_RECEIPT_DOMAIN: &[u8] =
    b"advance.contract218.previsible-ready-subject-receipt.v1\0";
const READY_TABLE_RECEIPT_DOMAIN: &[u8] =
    b"advance.contract218.previsible-ready-table-receipt.v1\0";
const READY_LIFECYCLE_RECEIPT_DOMAIN: &[u8] =
    b"advance.contract218.previsible-ready-lifecycle-receipt.v1\0";
const ABORT_SUBJECT_RECEIPT_DOMAIN: &[u8] =
    b"advance.contract218.previsible-abort-subject-receipt.v1\0";
const ABORT_TABLE_RECEIPT_DOMAIN: &[u8] =
    b"advance.contract218.previsible-abort-table-receipt.v1\0";
const ABORT_LIFECYCLE_RECEIPT_DOMAIN: &[u8] =
    b"advance.contract218.previsible-abort-lifecycle-receipt.v1\0";
const SOURCE_EMISSION_RECEIPT_DOMAIN: &[u8] =
    b"advance.contract218.source-emission-quiesce-receipt.v1\0";
const TERMINATION_CLEANUP_COMPLETE_DOMAIN: &[u8] = b"advance.contract218.termination-cleanup.v1\0";
const RETAINED_GC_CHALLENGE_DOMAIN: &[u8] =
    b"advance.contract218.retained-tombstone-gc-challenge.v1\0";
const RETAINED_GC_OWNER_RECEIPT_DOMAIN: &[u8] =
    b"advance.contract218.retained-tombstone-gc-owner-zero-scan.v1\0";
const C123_PURPOSE2_ZERO_DOMAIN: &[u8] = b"advance.contract218.c123-purpose2-zero-token.v1\0";
const KEY_RETIREMENT_CHALLENGE_DOMAIN: &[u8] =
    b"advance.contract218.persisted-key-retirement-challenge.v1\0";
const KEY_RETIREMENT_OWNER_SCAN_DOMAIN: &[u8] =
    b"advance.contract218.persisted-key-retirement-owner-scan.v1\0";

/// Two independent unwrapped roots handed over by the platform custody layer.
/// The root bytes are zeroized on every drop and are never exposed again.
///
/// ```compile_fail
/// use advance_shared_types::contract218_previsible::Contract218RoleRootMaterial;
/// use zeroize::Zeroizing;
/// let _ = Contract218RoleRootMaterial::from_custody(
///     [1; 16], [2; 16], Zeroizing::new([3; 32]), Zeroizing::new([4; 32]),
/// );
/// ```
pub struct Contract218RoleRootMaterial {
    registry_instance: [u8; 16],
    boot: [u8; 16],
    previsible_root: Zeroizing<[u8; 32]>,
    termination_root: Zeroizing<[u8; 32]>,
}

impl Contract218RoleRootMaterial {
    /// Host-only construction boundary used after the external allocation
    /// manifest has authenticated and unwrapped both roots.
    /// Consume roots that have already been authenticated and unwrapped by the
    /// platform custody owner.  This constructor is public solely because the
    /// custody owner lives in the top-level CLI crate; callers receive no root
    /// getter and the returned value remains move-only and zeroizing.
    pub fn from_authenticated_custody(
        registry_instance: [u8; 16],
        boot: [u8; 16],
        previsible_root: Zeroizing<[u8; 32]>,
        termination_root: Zeroizing<[u8; 32]>,
    ) -> Result<Self, SensitiveParamCatalogError> {
        if registry_instance == [0; 16]
            || boot == [0; 16]
            || previsible_root.as_ref() == &[0; 32]
            || termination_root.as_ref() == &[0; 32]
            || bool::from(previsible_root.as_ref().ct_eq(termination_root.as_ref()))
        {
            return Err(SensitiveParamCatalogError::InvalidIdentity);
        }
        Ok(Self {
            registry_instance,
            boot,
            previsible_root,
            termination_root,
        })
    }

    /// Move the authenticated material into its one-shot lifecycle factory.
    pub fn into_lifecycle_factory(self) -> Contract218LifecycleRoleFactory {
        Contract218LifecycleRoleFactory::new(self)
    }
}

impl fmt::Debug for Contract218RoleRootMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Contract218RoleRootMaterial(<zeroizing>)")
    }
}

/// Move-only, one-shot lifecycle role factory.
///
/// ```compile_fail
/// use advance_shared_types::contract218_previsible::Contract218LifecycleRoleFactory;
/// fn require_clone<T: Clone>() {}
/// require_clone::<Contract218LifecycleRoleFactory>();
/// ```
pub struct Contract218LifecycleRoleFactory {
    roots: Contract218RoleRootMaterial,
}

impl Contract218LifecycleRoleFactory {
    pub(crate) fn new(roots: Contract218RoleRootMaterial) -> Self {
        Self { roots }
    }

    /// Consumes the factory.  Rust ownership makes a second split
    /// unrepresentable, while external custody prevents a second factory for
    /// the same `(registry, boot, family)` allocation.
    pub fn split_once(self) -> Result<Contract218LifecycleRoleSet, SensitiveParamCatalogError> {
        let salt = role_salt(self.roots.registry_instance, self.roots.boot);
        let ready_key = derive_key(
            &self.roots.previsible_root,
            &salt,
            b"advance.contract218.previsible-proof-key.v1\0",
        )?;
        let identity_key = derive_key(
            &self.roots.previsible_root,
            &salt,
            b"advance.contract218.identity-authority-key.v1\0",
        )?;
        let source_emission_key = derive_key(
            &self.roots.previsible_root,
            &salt,
            b"advance.contract218.source-emission-quiesce-receipt-key.v1\0",
        )?;
        let termination_key = derive_key(
            &self.roots.termination_root,
            &salt,
            b"advance.contract218.termination-state-key.v1\0",
        )?;
        let cleanup_key = derive_key(
            &self.roots.termination_root,
            &salt,
            b"advance.contract218.cleanup-receipt-key.v1\0",
        )?;
        let retained_gc_key = derive_key(
            &self.roots.termination_root,
            &salt,
            b"advance.contract218.retained-tombstone-gc-key.v1\0",
        )?;
        let key_retirement_scan_key = derive_key(
            &self.roots.termination_root,
            &salt,
            b"advance.contract218.persisted-key-retirement-scan-key.v1\0",
        )?;

        Ok(Contract218LifecycleRoleSet {
            issuer: PrevisibleProofIssuerRole {
                registry_instance: self.roots.registry_instance,
                boot: self.roots.boot,
                ready_key: Zeroizing::new(ready_key),
                source_emission_issuer: Some(SourceEmissionReceiptIssuer {
                    registry_instance: self.roots.registry_instance,
                    boot: self.roots.boot,
                    key: Zeroizing::new(source_emission_key),
                }),
            },
            verifier: PrevisibleProofVerifierRole {
                registry_instance: self.roots.registry_instance,
                boot: self.roots.boot,
                ready_key: Zeroizing::new(ready_key),
                identity_key: Zeroizing::new(identity_key),
                keyring_installer: Some(PersistedIdentityKeyringInstaller {
                    registry_instance: self.roots.registry_instance,
                    boot: self.roots.boot,
                    identity_key: Zeroizing::new(identity_key),
                }),
                retained_gc_key: Zeroizing::new(retained_gc_key),
                key_retirement_scan_key: Zeroizing::new(key_retirement_scan_key),
            },
            termination_state: TerminationStateMachineRole {
                registry_instance: self.roots.registry_instance,
                boot: self.roots.boot,
                key: Zeroizing::new(termination_key),
                source_emission_key: Zeroizing::new(source_emission_key),
                owner_receipt_key: Zeroizing::new(cleanup_key),
            },
            cleanup_issuer: TerminationCleanupReceiptIssuerRole {
                registry_instance: self.roots.registry_instance,
                boot: self.roots.boot,
                key: Zeroizing::new(cleanup_key),
                prepare_key: Zeroizing::new(termination_key),
            },
            cleanup_verifier: TerminationCleanupReceiptVerifierRole {
                registry_instance: self.roots.registry_instance,
                boot: self.roots.boot,
                key: Zeroizing::new(cleanup_key),
            },
        })
    }
}

impl fmt::Debug for Contract218LifecycleRoleFactory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Contract218LifecycleRoleFactory(<unsplit>)")
    }
}

/// Move-only unsplit role set.  It exposes exactly one destination method.
pub struct Contract218LifecycleRoleSet {
    issuer: PrevisibleProofIssuerRole,
    verifier: PrevisibleProofVerifierRole,
    termination_state: TerminationStateMachineRole,
    cleanup_issuer: TerminationCleanupReceiptIssuerRole,
    cleanup_verifier: TerminationCleanupReceiptVerifierRole,
}

impl Contract218LifecycleRoleSet {
    pub fn move_to_composition(
        self,
    ) -> (
        PrevisibleProofIssuerRole,
        PrevisibleProofVerifierRole,
        TerminationStateMachineRole,
        TerminationCleanupReceiptIssuerRole,
        TerminationCleanupReceiptVerifierRole,
    ) {
        (
            self.issuer,
            self.verifier,
            self.termination_state,
            self.cleanup_issuer,
            self.cleanup_verifier,
        )
    }
}

impl fmt::Debug for Contract218LifecycleRoleSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Contract218LifecycleRoleSet(<unsplit-destinations>)")
    }
}

/// CLI/composition-only issuer half.
///
/// The halves are not interchangeable or upcastable:
///
/// ```compile_fail
/// use advance_shared_types::contract218_previsible::{
///     PrevisibleProofIssuerRole, PrevisibleProofVerifierRole,
/// };
/// fn verifier_only(_: PrevisibleProofVerifierRole) {}
/// fn crossed(role: PrevisibleProofIssuerRole) { verifier_only(role); }
/// ```
pub struct PrevisibleProofIssuerRole {
    registry_instance: [u8; 16],
    boot: [u8; 16],
    ready_key: Zeroizing<[u8; 32]>,
    source_emission_issuer: Option<SourceEmissionReceiptIssuer>,
}

/// M014-only verifier and typed provider-stamping half.  Its public methods
/// are typed operations, never a generic MAC/codec/key API.
pub struct PrevisibleProofVerifierRole {
    registry_instance: [u8; 16],
    boot: [u8; 16],
    ready_key: Zeroizing<[u8; 32]>,
    identity_key: Zeroizing<[u8; 32]>,
    keyring_installer: Option<PersistedIdentityKeyringInstaller>,
    retained_gc_key: Zeroizing<[u8; 32]>,
    key_retirement_scan_key: Zeroizing<[u8; 32]>,
}

impl fmt::Debug for PrevisibleProofIssuerRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrevisibleProofIssuerRole(<opaque>)")
    }
}

impl fmt::Debug for PrevisibleProofVerifierRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrevisibleProofVerifierRole(<opaque>)")
    }
}

/// Authenticated status of one persisted-identity keyring entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PersistedIdentityKeyStatus {
    Signing,
    VerifyOnly,
    Retired,
}

/// Exact anchored keyring world selected before C218 composition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PersistedIdentityKeyringBinding {
    registry_instance: [u8; 16],
    keyring_root: [u8; 32],
    keyring_generation: u64,
}

impl PersistedIdentityKeyringBinding {
    pub fn from_authenticated_keyring(
        registry_instance: [u8; 16],
        keyring_root: [u8; 32],
        keyring_generation: u64,
    ) -> Result<Self, SensitiveParamCatalogError> {
        if registry_instance == [0; 16]
            || keyring_root == [0; 32]
            || keyring_generation > i64::MAX as u64
        {
            return Err(SensitiveParamCatalogError::InvalidIdentity);
        }
        Ok(Self {
            registry_instance,
            keyring_root,
            keyring_generation,
        })
    }

    pub fn registry_instance(&self) -> [u8; 16] {
        self.registry_instance
    }

    pub fn keyring_root(&self) -> [u8; 32] {
        self.keyring_root
    }

    pub fn keyring_generation(&self) -> u64 {
        self.keyring_generation
    }
}

/// Authenticated projection of exactly one keyring entry.  This carries no
/// key bytes and is useful only through the opaque capability wrappers below.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PersistedIdentityKeyCapabilityBinding {
    keyring: PersistedIdentityKeyringBinding,
    key_id: u32,
    master_key_epoch: u32,
    status: PersistedIdentityKeyStatus,
}

impl PersistedIdentityKeyCapabilityBinding {
    pub fn from_authenticated_keyring(
        keyring: PersistedIdentityKeyringBinding,
        key_id: u32,
        master_key_epoch: u32,
        status: PersistedIdentityKeyStatus,
    ) -> Result<Self, SensitiveParamCatalogError> {
        if key_id == 0 || master_key_epoch == 0 {
            return Err(SensitiveParamCatalogError::InvalidIdentity);
        }
        Ok(Self {
            keyring,
            key_id,
            master_key_epoch,
            status,
        })
    }

    pub fn keyring_binding(&self) -> PersistedIdentityKeyringBinding {
        self.keyring
    }

    pub fn key_id(&self) -> u32 {
        self.key_id
    }

    pub fn master_key_epoch(&self) -> u32 {
        self.master_key_epoch
    }

    pub fn status(&self) -> PersistedIdentityKeyStatus {
        self.status
    }
}

/// One typed signing request.  The bytes are the canonical carrier prefix,
/// not a caller-reported digest, and are produced only by the shared codec.
pub struct PersistedIdentitySigningRequest {
    binding: PersistedIdentityKeyCapabilityBinding,
    canonical_preceding: Vec<u8>,
}

impl PersistedIdentitySigningRequest {
    pub fn key_binding(&self) -> PersistedIdentityKeyCapabilityBinding {
        self.binding
    }

    pub fn canonical_preceding_bytes(&self) -> &[u8] {
        &self.canonical_preceding
    }
}

opaque_debug!(PersistedIdentitySigningRequest);

/// Complete signed carrier returned by trusted host custody.  Shared-types
/// parses it again and requires byte-exact equality with its request.
pub struct CustodySignedPersistedIdentity {
    canonical: Vec<u8>,
}

impl CustodySignedPersistedIdentity {
    pub fn from_typed_signing_operation(canonical: Vec<u8>) -> Self {
        Self { canonical }
    }
}

opaque_debug!(CustodySignedPersistedIdentity);

/// One typed verification request over a complete canonical carrier.
pub struct PersistedIdentityVerificationRequest {
    binding: PersistedIdentityKeyCapabilityBinding,
    canonical: Vec<u8>,
}

impl PersistedIdentityVerificationRequest {
    pub fn key_binding(&self) -> PersistedIdentityKeyCapabilityBinding {
        self.binding
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }
}

opaque_debug!(PersistedIdentityVerificationRequest);

/// Trusted host keyring seam.  It exposes only typed whole-carrier sign and
/// verify operations plus the exact authenticated entry selected for them.
/// There is no raw-key getter, generic MAC API, entry-list API, or derive-by-id
/// operation.
pub trait PersistedIdentityKeyringProvider: Send + Sync + 'static {
    fn current_keyring_binding(
        &self,
    ) -> Result<PersistedIdentityKeyringBinding, SensitiveParamCatalogError>;

    fn signing_key_binding(
        &self,
    ) -> Result<PersistedIdentityKeyCapabilityBinding, SensitiveParamCatalogError>;

    fn verification_key_binding(
        &self,
        key_id: u32,
    ) -> Result<PersistedIdentityKeyCapabilityBinding, SensitiveParamCatalogError>;

    fn sign_persisted_identity(
        &self,
        request: &PersistedIdentitySigningRequest,
    ) -> Result<CustodySignedPersistedIdentity, SensitiveParamCatalogError>;

    fn verify_persisted_identity(
        &self,
        request: &PersistedIdentityVerificationRequest,
    ) -> Result<(), SensitiveParamCatalogError>;
}

/// Move-only one-use installer split from the C218 lifecycle factory.  It is
/// the sole production constructor for an installed keyring role.
pub struct PersistedIdentityKeyringInstaller {
    registry_instance: [u8; 16],
    boot: [u8; 16],
    identity_key: Zeroizing<[u8; 32]>,
}

impl PersistedIdentityKeyringInstaller {
    #[cfg(any(test, feature = "test-support"))]
    pub fn fixture_for_test(
        registry_instance: [u8; 16],
        boot: [u8; 16],
    ) -> Result<Self, SensitiveParamCatalogError> {
        if registry_instance == [0; 16] || boot == [0; 16] {
            return Err(SensitiveParamCatalogError::InvalidIdentity);
        }
        Ok(Self {
            registry_instance,
            boot,
            identity_key: Zeroizing::new(fresh_nonzero_32()?),
        })
    }

    pub fn install_authenticated_custody(
        self,
        provider: Box<dyn PersistedIdentityKeyringProvider>,
    ) -> Result<PersistedIdentityKeyringRole, SensitiveParamCatalogError> {
        let binding = provider.current_keyring_binding()?;
        if binding.registry_instance != self.registry_instance {
            return Err(SensitiveParamCatalogError::StaleIdentity);
        }
        Ok(PersistedIdentityKeyringRole {
            registry_instance: self.registry_instance,
            boot: self.boot,
            binding,
            provider: Arc::from(provider),
            identity_key: self.identity_key,
        })
    }
}

opaque_debug!(PersistedIdentityKeyringInstaller);

/// Move-only signing authority bound to one anchored Signing entry.
pub struct SigningKeyCapability {
    binding: PersistedIdentityKeyCapabilityBinding,
    provider: Arc<dyn PersistedIdentityKeyringProvider>,
}

/// Move-only verification authority bound to one anchored Signing or
/// VerifyOnly entry.  A Retired tombstone can never construct this type.
pub struct VerificationKeyCapability {
    binding: PersistedIdentityKeyCapabilityBinding,
    provider: Arc<dyn PersistedIdentityKeyringProvider>,
}

/// Move-only proof that an anchored keyring entry is currently VerifyOnly and
/// can therefore enter the retirement scan protocol.  Signing and Retired
/// entries cannot construct this carrier.
pub struct PersistedKeyRetirementCandidate {
    binding: PersistedIdentityKeyCapabilityBinding,
    provider: Arc<dyn PersistedIdentityKeyringProvider>,
}

opaque_debug!(SigningKeyCapability);
opaque_debug!(VerificationKeyCapability);
opaque_debug!(PersistedKeyRetirementCandidate);

/// Installed carrier codec + keyring authority.  This role is independent of
/// the previsible verifier; lifecycle roots never derive carrier keys.
pub struct PersistedIdentityKeyringRole {
    registry_instance: [u8; 16],
    boot: [u8; 16],
    binding: PersistedIdentityKeyringBinding,
    provider: Arc<dyn PersistedIdentityKeyringProvider>,
    identity_key: Zeroizing<[u8; 32]>,
}

impl fmt::Debug for PersistedIdentityKeyringRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PersistedIdentityKeyringRole(<opaque>)")
    }
}

impl PersistedIdentityKeyringRole {
    /// Consume and advance the installed role only across the exact successor
    /// that authenticated custody already exposes after anchor promotion.
    /// Capabilities issued under the previous root remain bound to that root
    /// and therefore fail against the returned role.
    pub fn advance_authenticated_binding(
        mut self,
        expected_previous: PersistedIdentityKeyringBinding,
        expected_next: PersistedIdentityKeyringBinding,
    ) -> Result<Self, SensitiveParamCatalogError> {
        let provider_next = self.provider.current_keyring_binding()?;
        if self.binding != expected_previous
            || provider_next != expected_next
            || expected_previous.registry_instance != self.registry_instance
            || expected_next.registry_instance != self.registry_instance
            || expected_previous.keyring_root == expected_next.keyring_root
            || expected_previous.keyring_generation.checked_add(1)
                != Some(expected_next.keyring_generation)
        {
            return Err(SensitiveParamCatalogError::StaleIdentity);
        }
        self.binding = expected_next;
        Ok(self)
    }

    pub fn verify_provider_binding(
        &self,
        registry_instance: [u8; 16],
        keyring_root: [u8; 32],
    ) -> Result<(), SensitiveParamCatalogError> {
        self.require_current_binding()?;
        if self.registry_instance == registry_instance && self.binding.keyring_root == keyring_root
        {
            Ok(())
        } else {
            Err(SensitiveParamCatalogError::StaleIdentity)
        }
    }

    pub fn signing_key_capability(
        &self,
    ) -> Result<SigningKeyCapability, SensitiveParamCatalogError> {
        self.require_current_binding()?;
        let binding = self.provider.signing_key_binding()?;
        self.require_capability_binding(binding)?;
        if binding.status != PersistedIdentityKeyStatus::Signing {
            return Err(SensitiveParamCatalogError::InvalidCarrier);
        }
        Ok(SigningKeyCapability {
            binding,
            provider: Arc::clone(&self.provider),
        })
    }

    pub fn verification_key_capability(
        &self,
        key_id: u32,
    ) -> Result<VerificationKeyCapability, SensitiveParamCatalogError> {
        self.require_current_binding()?;
        let binding = self.provider.verification_key_binding(key_id)?;
        self.require_capability_binding(binding)?;
        if binding.key_id != key_id
            || !matches!(
                binding.status,
                PersistedIdentityKeyStatus::Signing | PersistedIdentityKeyStatus::VerifyOnly
            )
        {
            return Err(SensitiveParamCatalogError::InvalidCarrier);
        }
        Ok(VerificationKeyCapability {
            binding,
            provider: Arc::clone(&self.provider),
        })
    }

    pub fn persisted_key_retirement_candidate(
        &self,
        key_id: u32,
    ) -> Result<PersistedKeyRetirementCandidate, SensitiveParamCatalogError> {
        self.require_current_binding()?;
        let binding = self.provider.verification_key_binding(key_id)?;
        self.require_capability_binding(binding)?;
        if binding.key_id != key_id || binding.status != PersistedIdentityKeyStatus::VerifyOnly {
            return Err(SensitiveParamCatalogError::InvalidCarrier);
        }
        Ok(PersistedKeyRetirementCandidate {
            binding,
            provider: Arc::clone(&self.provider),
        })
    }

    pub fn seal_persisted_identity(
        &self,
        signing: &SigningKeyCapability,
        live_identity: &TrustedObservationIdentity,
        binding: &PersistedObservationBinding,
    ) -> Result<PersistedObservationIdentity, SensitiveParamCatalogError> {
        self.verify_trusted_identity(live_identity)?;
        match live_identity.scope {
            ObservationAuthorityScope::Live { boot } if boot == self.boot => {}
            _ => return Err(SensitiveParamCatalogError::ScopeMismatch),
        }
        self.sign_claims(signing, &live_identity.claims, binding)
    }

    pub fn reseal_persisted_identity(
        &self,
        signing: &SigningKeyCapability,
        verification: &VerificationKeyCapability,
        existing: &PersistedObservationIdentity,
        binding: &PersistedObservationBinding,
    ) -> Result<PersistedObservationIdentity, SensitiveParamCatalogError> {
        let decoded = self.verify_persisted_carrier(verification, existing)?;
        if decoded.binding != *binding {
            return Err(SensitiveParamCatalogError::ScopeMismatch);
        }
        self.sign_claims(signing, &decoded.claims, binding)
    }

    pub fn decode_persisted_identity(
        &self,
        verification: &VerificationKeyCapability,
        canonical: &[u8],
    ) -> Result<PersistedObservationIdentity, SensitiveParamCatalogError> {
        let decoded = PersistedObservationIdentity::decode_provider_parts(canonical)?;
        self.require_verification_capability(verification, decoded.key_id)?;
        verification
            .provider
            .verify_persisted_identity(&PersistedIdentityVerificationRequest {
                binding: verification.binding,
                canonical: canonical.to_vec(),
            })?;
        Ok(PersistedObservationIdentity {
            key_id: decoded.key_id,
            binding: decoded.binding,
            claims: decoded.claims,
            mac: decoded.mac,
            canonical: canonical.to_vec(),
        })
    }

    pub fn rehydrate_persisted_identity(
        &self,
        verification: &VerificationKeyCapability,
        persisted: &PersistedObservationIdentity,
    ) -> Result<TrustedObservationIdentity, SensitiveParamCatalogError> {
        let decoded = self.verify_persisted_carrier(verification, persisted)?;
        self.stamp_trusted_identity(
            decoded.claims,
            ObservationAuthorityScope::Persisted {
                event_id: decoded.binding.event_id,
                cursor: decoded.binding.cursor,
                safe_event_digest: decoded.binding.safe_event_digest,
            },
        )
    }

    pub fn verify_persisted_identity(
        &self,
        verification: &VerificationKeyCapability,
        identity: &TrustedObservationIdentity,
        persisted: &PersistedObservationIdentity,
        observed: &PersistedObservationBinding,
        expected: &ObservationIdentityClaims,
    ) -> Result<(), SensitiveParamCatalogError> {
        self.verify_trusted_identity(identity)?;
        let decoded = self.verify_persisted_carrier(verification, persisted)?;
        observed.validate()?;
        if decoded.claims != *expected
            || identity.claims != *expected
            || decoded.binding != *observed
        {
            return Err(SensitiveParamCatalogError::ScopeMismatch);
        }
        match &identity.scope {
            ObservationAuthorityScope::Persisted {
                event_id,
                cursor,
                safe_event_digest,
            } if event_id == &observed.event_id
                && cursor == &observed.cursor
                && safe_event_digest == &observed.safe_event_digest =>
            {
                Ok(())
            }
            _ => Err(SensitiveParamCatalogError::ScopeMismatch),
        }
    }

    fn sign_claims(
        &self,
        signing: &SigningKeyCapability,
        claims: &ObservationIdentityClaims,
        binding: &PersistedObservationBinding,
    ) -> Result<PersistedObservationIdentity, SensitiveParamCatalogError> {
        self.require_signing_capability(signing)?;
        let preceding = PersistedObservationIdentity::encode_provider_unsigned_parts(
            signing.binding.key_id,
            binding,
            claims,
        )?;
        let signed =
            signing
                .provider
                .sign_persisted_identity(&PersistedIdentitySigningRequest {
                    binding: signing.binding,
                    canonical_preceding: preceding.clone(),
                })?;
        if signed.canonical.len() != preceding.len() + 32
            || signed.canonical.get(..preceding.len()) != Some(preceding.as_slice())
        {
            return Err(SensitiveParamCatalogError::InvalidCarrier);
        }
        let decoded = PersistedObservationIdentity::decode_provider_parts(&signed.canonical)?;
        if decoded.key_id != signing.binding.key_id
            || decoded.binding != *binding
            || decoded.claims != *claims
            || decoded.mac_input_len != preceding.len()
        {
            return Err(SensitiveParamCatalogError::InvalidCarrier);
        }
        signing
            .provider
            .verify_persisted_identity(&PersistedIdentityVerificationRequest {
                binding: signing.binding,
                canonical: signed.canonical.clone(),
            })?;
        Ok(PersistedObservationIdentity {
            key_id: decoded.key_id,
            binding: decoded.binding,
            claims: decoded.claims,
            mac: decoded.mac,
            canonical: signed.canonical,
        })
    }

    fn verify_persisted_carrier(
        &self,
        verification: &VerificationKeyCapability,
        persisted: &PersistedObservationIdentity,
    ) -> Result<DecodedPersistedObservationIdentity, SensitiveParamCatalogError> {
        let decoded = PersistedObservationIdentity::decode_provider_parts(&persisted.canonical)?;
        if persisted.key_id != decoded.key_id
            || persisted.claims != decoded.claims
            || persisted.binding != decoded.binding
            || !bool::from(persisted.mac.ct_eq(&decoded.mac))
        {
            return Err(SensitiveParamCatalogError::InvalidCarrier);
        }
        self.require_verification_capability(verification, decoded.key_id)?;
        verification
            .provider
            .verify_persisted_identity(&PersistedIdentityVerificationRequest {
                binding: verification.binding,
                canonical: persisted.canonical.clone(),
            })?;
        Ok(decoded)
    }

    fn require_signing_capability(
        &self,
        capability: &SigningKeyCapability,
    ) -> Result<(), SensitiveParamCatalogError> {
        self.require_current_binding()?;
        self.require_capability_binding(capability.binding)?;
        if capability.binding.status != PersistedIdentityKeyStatus::Signing
            || !Arc::ptr_eq(&self.provider, &capability.provider)
        {
            return Err(SensitiveParamCatalogError::InvalidCarrier);
        }
        Ok(())
    }

    fn require_verification_capability(
        &self,
        capability: &VerificationKeyCapability,
        expected_key_id: u32,
    ) -> Result<(), SensitiveParamCatalogError> {
        self.require_current_binding()?;
        self.require_capability_binding(capability.binding)?;
        if capability.binding.key_id != expected_key_id
            || !matches!(
                capability.binding.status,
                PersistedIdentityKeyStatus::Signing | PersistedIdentityKeyStatus::VerifyOnly
            )
            || !Arc::ptr_eq(&self.provider, &capability.provider)
        {
            return Err(SensitiveParamCatalogError::InvalidCarrier);
        }
        Ok(())
    }

    fn stamp_trusted_identity(
        &self,
        claims: ObservationIdentityClaims,
        scope: ObservationAuthorityScope,
    ) -> Result<TrustedObservationIdentity, SensitiveParamCatalogError> {
        let payload = trusted_identity_payload(self.registry_instance, &claims, &scope)?;
        let mac = compute_hmac(&self.identity_key, TRUSTED_IDENTITY_DOMAIN, &payload)?;
        Ok(TrustedObservationIdentity {
            claims,
            registry_instance: self.registry_instance,
            scope,
            mac,
        })
    }

    fn verify_trusted_identity(
        &self,
        identity: &TrustedObservationIdentity,
    ) -> Result<(), SensitiveParamCatalogError> {
        if identity.registry_instance != self.registry_instance {
            return Err(SensitiveParamCatalogError::StaleIdentity);
        }
        let payload = trusted_identity_payload(
            identity.registry_instance,
            &identity.claims,
            &identity.scope,
        )?;
        verify_hmac(
            &self.identity_key,
            TRUSTED_IDENTITY_DOMAIN,
            &payload,
            &identity.mac,
        )
    }

    fn require_current_binding(&self) -> Result<(), SensitiveParamCatalogError> {
        if self.provider.current_keyring_binding()? == self.binding {
            Ok(())
        } else {
            Err(SensitiveParamCatalogError::StaleIdentity)
        }
    }

    fn require_capability_binding(
        &self,
        binding: PersistedIdentityKeyCapabilityBinding,
    ) -> Result<(), SensitiveParamCatalogError> {
        if binding.keyring == self.binding {
            Ok(())
        } else {
            Err(SensitiveParamCatalogError::StaleIdentity)
        }
    }
}

impl PrevisibleProofIssuerRole {
    /// Issue the one ready proof only after the three closed adapters have
    /// returned their exact move-only success receipts.
    pub fn issue_ready_proof(
        &self,
        activation: &PrevisibleObservationActivation,
        receipts: PrevisibleReadyReceiptSet,
    ) -> Result<PrevisibleActivationReadyProof, SensitiveParamCatalogError> {
        activation.verify_origin(self.registry_instance, self.boot, &self.ready_key)?;
        let activation_digest: [u8; 32] = Sha256::digest(activation.canonical_bytes()?).into();
        receipts.verify(&self.ready_key, activation_digest)?;
        let subject_receipt_digest = receipts.subject.carrier_digest();
        let table_receipt_digest = receipts.table.carrier_digest();
        let lifecycle_receipt_digest = receipts.lifecycle.carrier_digest();
        let nonce = fresh_nonzero_32()?;
        let mut payload = Vec::with_capacity(32 * 5);
        payload.extend_from_slice(&activation_digest);
        payload.extend_from_slice(&subject_receipt_digest);
        payload.extend_from_slice(&table_receipt_digest);
        payload.extend_from_slice(&lifecycle_receipt_digest);
        payload.extend_from_slice(&nonce);
        let mac = compute_hmac(&self.ready_key, READY_DOMAIN, &payload)?;
        Ok(PrevisibleActivationReadyProof {
            activation_digest,
            subject_receipt_digest,
            table_receipt_digest,
            lifecycle_receipt_digest,
            nonce,
            mac,
        })
    }

    /// Composition-root ready barrier for the three owners that are activated
    /// atomically in the daemon (subject, live-handle table, and lifecycle).
    ///
    /// The returned receipts are move-only and are bound to the exact hidden
    /// activation.  Keeping their construction on this non-clone issuer means
    /// an arbitrary downstream consumer still cannot mint a ready proof.
    pub fn issue_composition_ready_receipts(
        &self,
        activation: &PrevisibleObservationActivation,
    ) -> Result<PrevisibleReadyReceiptSet, SensitiveParamCatalogError> {
        activation.verify_origin(self.registry_instance, self.boot, &self.ready_key)?;
        let digest: [u8; 32] = Sha256::digest(activation.canonical_bytes()?).into();
        Ok(PrevisibleReadyReceiptSet::new(
            PrevisibleSubjectReadyReceipt(PrevisibleOwnerReceipt::issue(
                &self.ready_key,
                READY_SUBJECT_RECEIPT_DOMAIN,
                digest,
            )?),
            PrevisibleHandleTableReadyReceipt(PrevisibleOwnerReceipt::issue(
                &self.ready_key,
                READY_TABLE_RECEIPT_DOMAIN,
                digest,
            )?),
            PrevisibleLifecycleReadyReceipt(PrevisibleOwnerReceipt::issue(
                &self.ready_key,
                READY_LIFECYCLE_RECEIPT_DOMAIN,
                digest,
            )?),
        ))
    }

    /// Abort is an independently-domain-separated proof over three exact
    /// move-only absence receipts; success receipts cannot substitute.
    pub fn issue_abort_proof(
        &self,
        activation: &PrevisibleObservationActivation,
        receipts: PrevisibleAbortReceiptSet,
    ) -> Result<PrevisibleActivationAbortProof, SensitiveParamCatalogError> {
        activation.verify_origin(self.registry_instance, self.boot, &self.ready_key)?;
        let activation_digest: [u8; 32] = Sha256::digest(activation.canonical_bytes()?).into();
        receipts.verify(&self.ready_key, activation_digest)?;
        let subject_absence_digest = receipts.subject.carrier_digest();
        let table_absence_digest = receipts.table.carrier_digest();
        let lifecycle_absence_digest = receipts.lifecycle.carrier_digest();
        let nonce = fresh_nonzero_32()?;
        let mut payload = Vec::with_capacity(32 * 5);
        payload.extend_from_slice(&activation_digest);
        payload.extend_from_slice(&subject_absence_digest);
        payload.extend_from_slice(&table_absence_digest);
        payload.extend_from_slice(&lifecycle_absence_digest);
        payload.extend_from_slice(&nonce);
        let mac = compute_hmac(&self.ready_key, ABORT_DOMAIN, &payload)?;
        Ok(PrevisibleActivationAbortProof {
            activation_digest,
            subject_absence_digest,
            table_absence_digest,
            lifecycle_absence_digest,
            nonce,
            mac,
        })
    }

    /// Moves the sole source-emission issuer into the live-handle table.
    /// A second extraction is rejected and no raw key is exposed.
    pub fn take_source_emission_receipt_issuer(
        &mut self,
    ) -> Result<SourceEmissionReceiptIssuer, SensitiveParamCatalogError> {
        self.source_emission_issuer
            .take()
            .ok_or(SensitiveParamCatalogError::InvalidCarrier)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn issue_test_ready_receipts(
        &self,
        activation: &PrevisibleObservationActivation,
    ) -> Result<PrevisibleReadyReceiptSet, SensitiveParamCatalogError> {
        activation.verify_origin(self.registry_instance, self.boot, &self.ready_key)?;
        let digest: [u8; 32] = Sha256::digest(activation.canonical_bytes()?).into();
        Ok(PrevisibleReadyReceiptSet::new(
            PrevisibleSubjectReadyReceipt(PrevisibleOwnerReceipt::issue(
                &self.ready_key,
                READY_SUBJECT_RECEIPT_DOMAIN,
                digest,
            )?),
            PrevisibleHandleTableReadyReceipt(PrevisibleOwnerReceipt::issue(
                &self.ready_key,
                READY_TABLE_RECEIPT_DOMAIN,
                digest,
            )?),
            PrevisibleLifecycleReadyReceipt(PrevisibleOwnerReceipt::issue(
                &self.ready_key,
                READY_LIFECYCLE_RECEIPT_DOMAIN,
                digest,
            )?),
        ))
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn issue_test_abort_receipts(
        &self,
        activation: &PrevisibleObservationActivation,
    ) -> Result<PrevisibleAbortReceiptSet, SensitiveParamCatalogError> {
        activation.verify_origin(self.registry_instance, self.boot, &self.ready_key)?;
        let digest: [u8; 32] = Sha256::digest(activation.canonical_bytes()?).into();
        Ok(PrevisibleAbortReceiptSet::new(
            PrevisibleSubjectAbsenceReceipt(PrevisibleOwnerReceipt::issue(
                &self.ready_key,
                ABORT_SUBJECT_RECEIPT_DOMAIN,
                digest,
            )?),
            PrevisibleHandleTableAbsenceReceipt(PrevisibleOwnerReceipt::issue(
                &self.ready_key,
                ABORT_TABLE_RECEIPT_DOMAIN,
                digest,
            )?),
            PrevisibleLifecycleAbsenceReceipt(PrevisibleOwnerReceipt::issue(
                &self.ready_key,
                ABORT_LIFECYCLE_RECEIPT_DOMAIN,
                digest,
            )?),
        ))
    }
}

impl PrevisibleProofVerifierRole {
    /// Fail-closed composition check without exposing any bound value.
    pub fn verify_provider_binding(
        &self,
        registry_instance: [u8; 16],
        boot: [u8; 16],
    ) -> Result<(), SensitiveParamCatalogError> {
        if self.registry_instance == registry_instance && self.boot == boot {
            Ok(())
        } else {
            Err(SensitiveParamCatalogError::StaleIdentity)
        }
    }

    /// Move the one production keyring installer to trusted host composition.
    /// A second extraction is rejected; no lifecycle or carrier key is exposed.
    pub fn take_persisted_identity_keyring_installer(
        &mut self,
    ) -> Result<PersistedIdentityKeyringInstaller, SensitiveParamCatalogError> {
        self.keyring_installer
            .take()
            .ok_or(SensitiveParamCatalogError::InvalidCarrier)
    }

    pub fn issue_retained_tombstone_gc_challenge(
        &self,
        record: TerminationOperationRecord,
        tombstone_state_root: [u8; 32],
        gc_generation: u64,
    ) -> Result<RetainedTombstoneGcChallenge, SensitiveParamCatalogError> {
        if tombstone_state_root == [0; 32] || gc_generation == 0 || gc_generation > i64::MAX as u64
        {
            return Err(SensitiveParamCatalogError::InvalidIdentity);
        }
        let payload = retained_gc_challenge_payload(
            self.registry_instance,
            self.boot,
            &record,
            tombstone_state_root,
            gc_generation,
        )?;
        Ok(RetainedTombstoneGcChallenge {
            registry_instance: self.registry_instance,
            operation_boot: self.boot,
            record,
            tombstone_state_root,
            gc_generation,
            token: issue_private_token(
                &self.retained_gc_key,
                RETAINED_GC_CHALLENGE_DOMAIN,
                &payload,
            )?,
        })
    }

    /// Authenticate and expose only the journal-safe identity of a retained
    /// tombstone GC challenge.  Callers never receive the authority token.
    pub fn inspect_retained_tombstone_gc_challenge(
        &self,
        challenge: &RetainedTombstoneGcChallenge,
    ) -> Result<RetainedTombstoneGcChallengeMetadata, SensitiveParamCatalogError> {
        self.verify_retained_gc_challenge(challenge)?;
        Ok(RetainedTombstoneGcChallengeMetadata {
            registry_instance: challenge.registry_instance,
            operation_boot: challenge.operation_boot,
            operation_id: challenge.record.operation_id.clone(),
            member_set_digest: challenge.record.member_set_digest,
            tombstone_state_root: challenge.tombstone_state_root,
            gc_generation: challenge.gc_generation,
            gc_registry_sequence: challenge.record.registry_sequence,
            challenge_nonce: challenge.token.nonce,
        })
    }

    /// Rehydrate the exact anchor-protected challenge after restart without
    /// allocating a replacement nonce or generation.
    pub fn rehydrate_retained_tombstone_gc_challenge(
        &self,
        record: TerminationOperationRecord,
        tombstone_state_root: [u8; 32],
        gc_generation: u64,
        challenge_nonce: [u8; 32],
    ) -> Result<RetainedTombstoneGcChallenge, SensitiveParamCatalogError> {
        if tombstone_state_root == [0; 32]
            || gc_generation == 0
            || gc_generation > i64::MAX as u64
            || challenge_nonce == [0; 32]
        {
            return Err(SensitiveParamCatalogError::InvalidIdentity);
        }
        let payload = retained_gc_challenge_payload(
            self.registry_instance,
            self.boot,
            &record,
            tombstone_state_root,
            gc_generation,
        )?;
        Ok(RetainedTombstoneGcChallenge {
            registry_instance: self.registry_instance,
            operation_boot: self.boot,
            record,
            tombstone_state_root,
            gc_generation,
            token: issue_private_token_with_nonce(
                &self.retained_gc_key,
                RETAINED_GC_CHALLENGE_DOMAIN,
                &payload,
                challenge_nonce,
            )?,
        })
    }

    pub fn verify_retained_tombstone_gc_set(
        &self,
        challenge: RetainedTombstoneGcChallenge,
        purpose2: C123Purpose2ZeroToken,
        receipts: RetainedTombstoneGcReceiptSet,
    ) -> Result<VerifiedRetainedTombstoneGcSet, SensitiveParamCatalogError> {
        self.verify_retained_gc_challenge(&challenge)?;
        let challenge_nonce = challenge.token.nonce;
        let purpose_payload = c123_purpose2_zero_payload(
            purpose2.registry_instance,
            purpose2.operation_boot,
            &purpose2.record,
            purpose2.tombstone_state_root,
            purpose2.gc_generation,
            purpose2.challenge_nonce,
            purpose2.store_instance_id,
            purpose2.high_water,
            purpose2.state_root,
        )?;
        if purpose2.registry_instance != self.registry_instance
            || purpose2.operation_boot != self.boot
            || purpose2.record != challenge.record
            || purpose2.tombstone_state_root != challenge.tombstone_state_root
            || purpose2.gc_generation != challenge.gc_generation
            || !bool::from(purpose2.challenge_nonce.ct_eq(&challenge_nonce))
        {
            return Err(SensitiveParamCatalogError::InvalidCarrier);
        }
        verify_private_token(
            &self.retained_gc_key,
            C123_PURPOSE2_ZERO_DOMAIN,
            &purpose_payload,
            &purpose2.token,
        )?;

        let owner_receipts = receipts.receipts();
        let mut owner_metadata = Vec::with_capacity(5);
        let mut aggregate = Sha256::new();
        aggregate.update(b"advance.contract218.retained-tombstone-gc-set.v1\0");
        aggregate.update(challenge_nonce);
        let purpose2_digest = private_token_carrier_digest(
            b"advance.contract218.c123-purpose2-zero-digest.v1\0",
            &purpose_payload,
            &purpose2.token,
        );
        aggregate.update(purpose2_digest);
        for (index, receipt) in owner_receipts.into_iter().enumerate() {
            let expected_tag = (index + 1) as u8;
            if receipt.tag != expected_tag
                || receipt.registry_instance != self.registry_instance
                || receipt.operation_boot != self.boot
                || receipt.record != challenge.record
                || receipt.tombstone_state_root != challenge.tombstone_state_root
                || receipt.gc_generation != challenge.gc_generation
                || !bool::from(receipt.challenge_nonce.ct_eq(&challenge_nonce))
            {
                return Err(SensitiveParamCatalogError::InvalidCarrier);
            }
            let payload = retained_gc_owner_payload(
                receipt.tag,
                receipt.registry_instance,
                receipt.operation_boot,
                &receipt.record,
                receipt.tombstone_state_root,
                receipt.gc_generation,
                receipt.challenge_nonce,
                receipt.store_instance_id,
                receipt.high_water,
                receipt.state_root,
            )?;
            verify_private_token(
                &self.retained_gc_key,
                RETAINED_GC_OWNER_RECEIPT_DOMAIN,
                &payload,
                &receipt.token,
            )?;
            aggregate.update([receipt.tag]);
            aggregate.update(private_token_carrier_digest(
                b"advance.contract218.retained-tombstone-gc-owner-digest.v1\0",
                &payload,
                &receipt.token,
            ));
            owner_metadata.push(RetainedTombstoneGcOwnerMetadata {
                store_instance_id: receipt.store_instance_id,
                high_water: receipt.high_water,
                state_root: receipt.state_root,
            });
        }
        if owner_metadata[2]
            != (RetainedTombstoneGcOwnerMetadata {
                store_instance_id: purpose2.store_instance_id,
                high_water: purpose2.high_water,
                state_root: purpose2.state_root,
            })
        {
            return Err(SensitiveParamCatalogError::InvalidCarrier);
        }
        let metadata = RetainedTombstoneGcMetadata {
            registry_instance: self.registry_instance,
            operation_boot: self.boot,
            operation_id: challenge.record.operation_id,
            member_set_digest: challenge.record.member_set_digest,
            tombstone_state_root: challenge.tombstone_state_root,
            gc_generation: challenge.gc_generation,
            gc_registry_sequence: challenge.record.registry_sequence,
            challenge_nonce,
            purpose2_digest,
            purpose2: RetainedTombstoneGcOwnerMetadata {
                store_instance_id: purpose2.store_instance_id,
                high_water: purpose2.high_water,
                state_root: purpose2.state_root,
            },
            m009: owner_metadata[0].clone(),
            m019: owner_metadata[1].clone(),
            c123: owner_metadata[2].clone(),
            role_allocation: owner_metadata[3].clone(),
            registry: owner_metadata[4].clone(),
            aggregate_digest: aggregate.finalize().into(),
        };
        Ok(VerifiedRetainedTombstoneGcSet { metadata })
    }

    fn verify_retained_gc_challenge(
        &self,
        challenge: &RetainedTombstoneGcChallenge,
    ) -> Result<(), SensitiveParamCatalogError> {
        if challenge.registry_instance != self.registry_instance
            || challenge.operation_boot != self.boot
            || challenge.tombstone_state_root == [0; 32]
            || challenge.gc_generation == 0
            || challenge.gc_generation > i64::MAX as u64
        {
            return Err(SensitiveParamCatalogError::InvalidCarrier);
        }
        let payload = retained_gc_challenge_payload(
            challenge.registry_instance,
            challenge.operation_boot,
            &challenge.record,
            challenge.tombstone_state_root,
            challenge.gc_generation,
        )?;
        verify_private_token(
            &self.retained_gc_key,
            RETAINED_GC_CHALLENGE_DOMAIN,
            &payload,
            &challenge.token,
        )
    }

    pub fn issue_persisted_key_retirement_challenge(
        &self,
        operation_id: String,
        candidate: &PersistedKeyRetirementCandidate,
        migration_generation: u64,
    ) -> Result<PersistedKeyRetirementChallenge, SensitiveParamCatalogError> {
        let keyring = candidate.binding.keyring;
        if candidate.binding.status != PersistedIdentityKeyStatus::VerifyOnly
            || candidate.binding.key_id == 0
            || keyring.registry_instance != self.registry_instance
            || candidate.provider.current_keyring_binding()? != keyring
            || migration_generation == 0
            || migration_generation > i64::MAX as u64
        {
            return Err(SensitiveParamCatalogError::InvalidIdentity);
        }
        let payload = key_retirement_challenge_payload(
            self.registry_instance,
            self.boot,
            &operation_id,
            keyring.keyring_root,
            keyring.keyring_generation,
            candidate.binding.key_id,
            migration_generation,
        )?;
        Ok(PersistedKeyRetirementChallenge {
            registry_instance: self.registry_instance,
            boot: self.boot,
            operation_id,
            keyring_root: keyring.keyring_root,
            keyring_generation: keyring.keyring_generation,
            key_id: candidate.binding.key_id,
            migration_generation,
            token: issue_private_token(
                &self.key_retirement_scan_key,
                KEY_RETIREMENT_CHALLENGE_DOMAIN,
                &payload,
            )?,
        })
    }

    pub fn inspect_persisted_key_retirement_challenge(
        &self,
        challenge: &PersistedKeyRetirementChallenge,
    ) -> Result<PersistedKeyRetirementChallengeMetadata, SensitiveParamCatalogError> {
        self.verify_key_retirement_challenge(challenge)?;
        Ok(PersistedKeyRetirementChallengeMetadata {
            registry_instance: challenge.registry_instance,
            boot: challenge.boot,
            operation_id: challenge.operation_id.clone(),
            keyring_root: challenge.keyring_root,
            keyring_generation: challenge.keyring_generation,
            key_id: challenge.key_id,
            migration_generation: challenge.migration_generation,
            challenge_nonce: challenge.token.nonce,
        })
    }

    pub fn verify_persisted_key_retirement_scan_set(
        &self,
        challenge: PersistedKeyRetirementChallenge,
        scans: PersistedKeyRetirementScanSet,
    ) -> Result<VerifiedPersistedKeyRetirementScanSet, SensitiveParamCatalogError> {
        self.verify_key_retirement_challenge(&challenge)?;
        let challenge_nonce = challenge.token.nonce;
        let receipts = scans.receipts();
        let mut aggregate = Sha256::new();
        aggregate.update(b"advance.contract218.persisted-key-retirement-scan-set.v1\0");
        aggregate.update(challenge_nonce);
        let mut metadata = Vec::with_capacity(3);
        for (index, receipt) in receipts.into_iter().enumerate() {
            let expected_tag = (index + 1) as u8;
            if receipt.tag != expected_tag
                || receipt.registry_instance != self.registry_instance
                || receipt.boot != self.boot
                || receipt.operation_id != challenge.operation_id
                || receipt.keyring_root != challenge.keyring_root
                || receipt.keyring_generation != challenge.keyring_generation
                || receipt.key_id != challenge.key_id
                || receipt.migration_generation != challenge.migration_generation
                || !bool::from(receipt.challenge_nonce.ct_eq(&challenge_nonce))
            {
                return Err(SensitiveParamCatalogError::InvalidCarrier);
            }
            let payload = key_retirement_owner_scan_payload(receipt)?;
            verify_private_token(
                &self.key_retirement_scan_key,
                KEY_RETIREMENT_OWNER_SCAN_DOMAIN,
                &payload,
                &receipt.token,
            )?;
            aggregate.update([receipt.tag]);
            aggregate.update(private_token_carrier_digest(
                b"advance.contract218.persisted-key-retirement-owner-scan-digest.v1\0",
                &payload,
                &receipt.token,
            ));
            metadata.push(PersistedKeyOwnerScanMetadata {
                store_instance_id: receipt.store_instance_id,
                high_water: receipt.high_water,
                state_root: receipt.state_root,
            });
        }
        let jsonl = &scans.jsonl.0;
        Ok(VerifiedPersistedKeyRetirementScanSet {
            metadata: VerifiedPersistedKeyRetirementScanMetadata {
                registry_instance: self.registry_instance,
                boot: self.boot,
                operation_id: challenge.operation_id,
                keyring_root: challenge.keyring_root,
                keyring_generation: challenge.keyring_generation,
                key_id: challenge.key_id,
                migration_generation: challenge.migration_generation,
                challenge_nonce,
                sqlite: metadata[0].clone(),
                jsonl: JsonlPersistedKeyScanMetadata {
                    store_instance_id: jsonl.store_instance_id,
                    inventory_digest: jsonl.inventory_digest,
                    segment_count: jsonl.segment_count,
                    byte_count: jsonl.byte_count,
                    retention_high_water: jsonl.retention_high_water,
                },
                migration: metadata[2].clone(),
                aggregate_digest: aggregate.finalize().into(),
            },
        })
    }

    fn verify_key_retirement_challenge(
        &self,
        challenge: &PersistedKeyRetirementChallenge,
    ) -> Result<(), SensitiveParamCatalogError> {
        if challenge.registry_instance != self.registry_instance
            || challenge.boot != self.boot
            || challenge.key_id == 0
            || challenge.keyring_root == [0; 32]
            || challenge.keyring_generation > i64::MAX as u64
        {
            return Err(SensitiveParamCatalogError::InvalidCarrier);
        }
        let payload = key_retirement_challenge_payload(
            challenge.registry_instance,
            challenge.boot,
            &challenge.operation_id,
            challenge.keyring_root,
            challenge.keyring_generation,
            challenge.key_id,
            challenge.migration_generation,
        )?;
        verify_private_token(
            &self.key_retirement_scan_key,
            KEY_RETIREMENT_CHALLENGE_DOMAIN,
            &payload,
            &challenge.token,
        )
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn issue_test_retained_gc_inputs(
        &self,
        challenge: &RetainedTombstoneGcChallenge,
        owners: [([u8; 16], u64, [u8; 32]); 5],
    ) -> Result<(C123Purpose2ZeroToken, RetainedTombstoneGcReceiptSet), SensitiveParamCatalogError>
    {
        self.verify_retained_gc_challenge(challenge)?;
        let challenge_nonce = challenge.token.nonce;
        let issue_owner = |tag: u8, owner: ([u8; 16], u64, [u8; 32])| {
            RetainedGcOwnerReceipt::issue(
                &self.retained_gc_key,
                tag,
                challenge.registry_instance,
                challenge.operation_boot,
                challenge.record.clone(),
                challenge.tombstone_state_root,
                challenge.gc_generation,
                challenge_nonce,
                owner.0,
                owner.1,
                owner.2,
            )
        };
        let c123_owner = owners[2];
        let purpose_payload = c123_purpose2_zero_payload(
            challenge.registry_instance,
            challenge.operation_boot,
            &challenge.record,
            challenge.tombstone_state_root,
            challenge.gc_generation,
            challenge_nonce,
            c123_owner.0,
            c123_owner.1,
            c123_owner.2,
        )?;
        let purpose2 = C123Purpose2ZeroToken {
            registry_instance: challenge.registry_instance,
            operation_boot: challenge.operation_boot,
            record: challenge.record.clone(),
            tombstone_state_root: challenge.tombstone_state_root,
            gc_generation: challenge.gc_generation,
            challenge_nonce,
            store_instance_id: c123_owner.0,
            high_water: c123_owner.1,
            state_root: c123_owner.2,
            token: issue_private_token(
                &self.retained_gc_key,
                C123_PURPOSE2_ZERO_DOMAIN,
                &purpose_payload,
            )?,
        };
        Ok((
            purpose2,
            RetainedTombstoneGcReceiptSet::new(
                M009GcZeroScanReceipt(issue_owner(1, owners[0])?),
                M019GcZeroScanReceipt(issue_owner(2, owners[1])?),
                C123GcZeroScanReceipt(issue_owner(3, owners[2])?),
                RoleAllocationGcZeroScanReceipt(issue_owner(4, owners[3])?),
                RegistryGcZeroScanReceipt(issue_owner(5, owners[4])?),
            ),
        ))
    }

    #[cfg(any(test, feature = "test-support"))]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn issue_test_persisted_key_retirement_scans(
        &self,
        challenge: &PersistedKeyRetirementChallenge,
        sqlite: ([u8; 16], u64, [u8; 32]),
        jsonl: ([u8; 16], [u8; 32], u64, u64, u64),
        migration: ([u8; 16], u64, [u8; 32]),
    ) -> Result<PersistedKeyRetirementScanSet, SensitiveParamCatalogError> {
        self.verify_key_retirement_challenge(challenge)?;
        let nonce = challenge.token.nonce;
        Ok(PersistedKeyRetirementScanSet::new(
            SqlitePersistedKeyScanReceipt(PersistedKeyOwnerScanReceipt::issue(
                &self.key_retirement_scan_key,
                1,
                challenge,
                nonce,
                sqlite.0,
                sqlite.1,
                sqlite.2,
                [0; 32],
                0,
                0,
                0,
            )?),
            JsonlPersistedKeyScanReceipt(PersistedKeyOwnerScanReceipt::issue(
                &self.key_retirement_scan_key,
                2,
                challenge,
                nonce,
                jsonl.0,
                jsonl.4,
                jsonl.1,
                jsonl.1,
                jsonl.2,
                jsonl.3,
                jsonl.4,
            )?),
            MigrationReferenceScanReceipt(PersistedKeyOwnerScanReceipt::issue(
                &self.key_retirement_scan_key,
                3,
                challenge,
                nonce,
                migration.0,
                migration.1,
                migration.2,
                [0; 32],
                0,
                0,
                0,
            )?),
        ))
    }

    /// Construct a bounded snapshot only from already-authenticated provider
    /// row data.  This keeps callers from directly constructing inconsistent
    /// class/name combinations.
    pub fn issue_snapshot(
        &self,
        claims: ObservationIdentityClaims,
        names: Vec<String>,
        revision: u64,
    ) -> Result<SensitiveParamSnapshot, SensitiveParamCatalogError> {
        claims.validate()?;
        let snapshot = SensitiveParamSnapshot {
            canonical_component_id: claims.exact_id,
            identity_class: claims.expected_class,
            incarnation: claims.incarnation,
            declaration_digest: claims.declaration_digest,
            names: names.into(),
            revision,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub fn issue_committed_component_receipt(
        &self,
        claims: ObservationIdentityClaims,
        operation_id: String,
        registry_sequence: u64,
    ) -> Result<CommittedComponentSourceReceipt, SensitiveParamCatalogError> {
        if claims.expected_class != ObservationIdentityClass::Component
            || operation_id.is_empty()
            || operation_id.len() > 256
            || registry_sequence == 0
            || registry_sequence > i64::MAX as u64
        {
            return Err(SensitiveParamCatalogError::InvalidIdentity);
        }
        claims.validate()?;
        let payload = committed_receipt_payload(&claims, &operation_id, registry_sequence)?;
        let mac = compute_hmac(&self.identity_key, COMPONENT_RECEIPT_DOMAIN, &payload)?;
        Ok(CommittedComponentSourceReceipt {
            claims,
            operation_id,
            registry_sequence,
            mac,
        })
    }

    pub fn issue_completed_hydration_receipt(
        &self,
        registry_sequence: u64,
        state_root: [u8; 32],
    ) -> Result<CompletedIdentityHydrationReceipt, SensitiveParamCatalogError> {
        if registry_sequence == 0 || registry_sequence > i64::MAX as u64 {
            return Err(SensitiveParamCatalogError::InvalidIdentity);
        }
        let payload = hydration_receipt_payload(
            self.registry_instance,
            self.boot,
            registry_sequence,
            state_root,
        );
        let mac = compute_hmac(&self.identity_key, HYDRATION_RECEIPT_DOMAIN, &payload)?;
        Ok(CompletedIdentityHydrationReceipt {
            registry_instance: self.registry_instance,
            boot: self.boot,
            registry_sequence,
            state_root,
            mac,
        })
    }

    pub fn verify_completed_hydration_receipt(
        &self,
        receipt: &CompletedIdentityHydrationReceipt,
        expected_registry_sequence: u64,
        expected_state_root: [u8; 32],
    ) -> Result<(), SensitiveParamCatalogError> {
        if receipt.registry_instance != self.registry_instance
            || receipt.boot != self.boot
            || receipt.registry_sequence != expected_registry_sequence
            || !bool::from(receipt.state_root.ct_eq(&expected_state_root))
        {
            return Err(SensitiveParamCatalogError::StaleIdentity);
        }
        let payload = hydration_receipt_payload(
            receipt.registry_instance,
            receipt.boot,
            receipt.registry_sequence,
            receipt.state_root,
        );
        verify_hmac(
            &self.identity_key,
            HYDRATION_RECEIPT_DOMAIN,
            &payload,
            &receipt.mac,
        )
    }

    pub fn begin_component_activation(
        &self,
        receipt: &CommittedComponentSourceReceipt,
    ) -> Result<PrevisibleObservationActivation, SensitiveParamCatalogError> {
        let payload = committed_receipt_payload(
            &receipt.claims,
            &receipt.operation_id,
            receipt.registry_sequence,
        )?;
        verify_hmac(
            &self.identity_key,
            COMPONENT_RECEIPT_DOMAIN,
            &payload,
            &receipt.mac,
        )?;
        self.issue_activation(
            PrevisibleActivationKind::Component,
            receipt.operation_id.clone(),
            receipt.claims.clone(),
            receipt.registry_sequence,
        )
    }

    pub fn begin_agent_activation(
        &self,
        operation_id: String,
        claims: ObservationIdentityClaims,
        registry_sequence: u64,
    ) -> Result<PrevisibleObservationActivation, SensitiveParamCatalogError> {
        if claims.expected_class != ObservationIdentityClass::Agent {
            return Err(SensitiveParamCatalogError::InvalidIdentity);
        }
        self.issue_activation(
            PrevisibleActivationKind::Agent,
            operation_id,
            claims,
            registry_sequence,
        )
    }

    /// Rehydrate the exact hidden Component activation selected by durable
    /// recovery.  The persisted nonce is retained byte-for-byte; this method
    /// never allocates a replacement operation identity.
    pub fn rehydrate_component_activation(
        &self,
        record: &ProviderActivationRecord,
    ) -> Result<PrevisibleObservationActivation, SensitiveParamCatalogError> {
        self.rehydrate_activation(record, PrevisibleActivationKind::Component)
    }

    /// Agent-typed sibling of [`Self::rehydrate_component_activation`].
    pub fn rehydrate_agent_activation(
        &self,
        record: &ProviderActivationRecord,
    ) -> Result<PrevisibleObservationActivation, SensitiveParamCatalogError> {
        self.rehydrate_activation(record, PrevisibleActivationKind::Agent)
    }

    fn rehydrate_activation(
        &self,
        record: &ProviderActivationRecord,
        expected: PrevisibleActivationKind,
    ) -> Result<PrevisibleObservationActivation, SensitiveParamCatalogError> {
        record.claims.validate()?;
        if record.kind != expected
            || record.activation_nonce == [0; 32]
            || record.operation_id.is_empty()
            || record.operation_id.len() > 256
            || record.registry_sequence == 0
            || record.registry_sequence > i64::MAX as u64
            || !matches!(
                (expected, record.claims.expected_class),
                (
                    PrevisibleActivationKind::Component,
                    ObservationIdentityClass::Component
                ) | (
                    PrevisibleActivationKind::Agent,
                    ObservationIdentityClass::Agent
                )
            )
        {
            return Err(SensitiveParamCatalogError::InvalidIdentity);
        }
        let mut activation = PrevisibleObservationActivation {
            registry_instance: self.registry_instance,
            boot: self.boot,
            role: record.kind,
            activation_nonce: record.activation_nonce,
            operation_id: record.operation_id.clone(),
            claims: record.claims.clone(),
            registry_sequence: record.registry_sequence,
            mac: [0; 32],
        };
        activation.mac = compute_hmac(
            &self.ready_key,
            ACTIVATION_DOMAIN,
            &activation.canonical_bytes()?,
        )?;
        Ok(activation)
    }

    /// Component-typed ready verification.  A bad proof returns a typed
    /// rejection that still owns the activation, so the provider can persist
    /// `Rejected` and later route it through the component rollback path.
    pub fn verify_component_ready(
        &self,
        activation: PrevisibleObservationActivation,
        proof: PrevisibleActivationReadyProof,
    ) -> ComponentReadyVerification {
        if activation.role == PrevisibleActivationKind::Component
            && self
                .verify_ready_proof_borrowed(&activation, &proof)
                .is_ok()
        {
            if let (Ok((ack, source_handle)), Ok(proof_metadata)) = (
                self.prepare_publication(&activation),
                proof.metadata(&self.ready_key),
            ) {
                return ComponentReadyVerification::Verified(
                    VerifiedComponentPrevisibleActivation {
                        prepared: Box::new(PreparedPublication {
                            activation,
                            ack,
                            source_handle,
                            proof_metadata,
                        }),
                    },
                );
            }
        }
        ComponentReadyVerification::Rejected(RejectedComponentPublication { activation })
    }

    /// Agent-typed sibling of [`Self::verify_component_ready`].
    pub fn verify_agent_ready(
        &self,
        activation: PrevisibleObservationActivation,
        proof: PrevisibleActivationReadyProof,
    ) -> AgentReadyVerification {
        if activation.role == PrevisibleActivationKind::Agent
            && self
                .verify_ready_proof_borrowed(&activation, &proof)
                .is_ok()
        {
            if let (Ok((ack, source_handle)), Ok(proof_metadata)) = (
                self.prepare_publication(&activation),
                proof.metadata(&self.ready_key),
            ) {
                return AgentReadyVerification::Verified(VerifiedAgentPrevisibleActivation {
                    prepared: Box::new(PreparedPublication {
                        activation,
                        ack,
                        source_handle,
                        proof_metadata,
                    }),
                });
            }
        }
        AgentReadyVerification::Rejected(RejectedAgentPublication { activation })
    }

    fn verify_ready_proof_borrowed(
        &self,
        activation: &PrevisibleObservationActivation,
        proof: &PrevisibleActivationReadyProof,
    ) -> Result<(), SensitiveParamCatalogError> {
        activation.verify_origin(self.registry_instance, self.boot, &self.ready_key)?;
        let actual_digest: [u8; 32] = Sha256::digest(activation.canonical_bytes()?).into();
        if !bool::from(actual_digest.ct_eq(&proof.activation_digest)) {
            return Err(SensitiveParamCatalogError::InvalidCarrier);
        }
        let mut payload = Vec::with_capacity(32 * 5);
        payload.extend_from_slice(&proof.activation_digest);
        payload.extend_from_slice(&proof.subject_receipt_digest);
        payload.extend_from_slice(&proof.table_receipt_digest);
        payload.extend_from_slice(&proof.lifecycle_receipt_digest);
        payload.extend_from_slice(&proof.nonce);
        verify_hmac(&self.ready_key, READY_DOMAIN, &payload, &proof.mac)?;
        Ok(())
    }

    pub fn inspect_component_activation(
        &self,
        activation: &PrevisibleObservationActivation,
    ) -> Result<ProviderActivationRecord, SensitiveParamCatalogError> {
        self.require_activation_kind(activation, PrevisibleActivationKind::Component)?;
        Ok(activation.provider_record())
    }

    pub fn inspect_agent_activation(
        &self,
        activation: &PrevisibleObservationActivation,
    ) -> Result<ProviderActivationRecord, SensitiveParamCatalogError> {
        self.require_activation_kind(activation, PrevisibleActivationKind::Agent)?;
        Ok(activation.provider_record())
    }

    pub fn verify_abort_proof(
        &self,
        activation: PrevisibleObservationActivation,
        proof: PrevisibleActivationAbortProof,
    ) -> Result<PrevisibleAbortBundle, SensitiveParamCatalogError> {
        activation.verify_origin(self.registry_instance, self.boot, &self.ready_key)?;
        let actual_digest: [u8; 32] = Sha256::digest(activation.canonical_bytes()?).into();
        if !bool::from(actual_digest.ct_eq(&proof.activation_digest)) {
            return Err(SensitiveParamCatalogError::InvalidCarrier);
        }
        let mut payload = Vec::with_capacity(32 * 5);
        payload.extend_from_slice(&proof.activation_digest);
        payload.extend_from_slice(&proof.subject_absence_digest);
        payload.extend_from_slice(&proof.table_absence_digest);
        payload.extend_from_slice(&proof.lifecycle_absence_digest);
        payload.extend_from_slice(&proof.nonce);
        verify_hmac(&self.ready_key, ABORT_DOMAIN, &payload, &proof.mac)?;
        let proof_metadata = proof.metadata(&self.ready_key)?;
        match activation.role {
            PrevisibleActivationKind::Component => {
                Ok(PrevisibleAbortBundle::Component(ComponentAbortBundle {
                    activation,
                    proof_metadata,
                }))
            }
            PrevisibleActivationKind::Agent => Ok(PrevisibleAbortBundle::Agent(AgentAbortBundle {
                activation,
                proof_metadata,
            })),
        }
    }

    /// Construct a Component Published result only from a verified Component
    /// activation.  The provider calls this after its anchored database commit.
    pub fn complete_component_publication(
        &self,
        verified: VerifiedComponentPrevisibleActivation,
    ) -> (ComponentPublicationResult, IssuedObservationSourceHandle) {
        let (ack, handle) = complete_publication(verified.prepared);
        (ComponentPublicationResult::Published(ack), handle)
    }

    /// Agent-typed sibling of [`Self::complete_component_publication`].
    pub fn complete_agent_publication(
        &self,
        verified: VerifiedAgentPrevisibleActivation,
    ) -> (AgentPublicationResult, IssuedObservationSourceHandle) {
        let (ack, handle) = complete_publication(verified.prepared);
        (AgentPublicationResult::Published(ack), handle)
    }

    pub fn verify_publication_ack(
        &self,
        ack: &ObservationCatalogPublicationAck,
    ) -> Result<ProviderActivationRecord, SensitiveParamCatalogError> {
        let payload = publication_ack_payload(&ack.record)?;
        verify_hmac(&self.ready_key, PUBLICATION_ACK_DOMAIN, &payload, &ack.mac)?;
        Ok(ack.record.clone())
    }

    pub fn reject_component_publication(
        &self,
        verified: VerifiedComponentPrevisibleActivation,
    ) -> ComponentPublicationResult {
        ComponentPublicationResult::Rejected(RejectedComponentPublication {
            activation: verified.prepared.activation,
        })
    }

    pub fn reject_agent_publication(
        &self,
        verified: VerifiedAgentPrevisibleActivation,
    ) -> AgentPublicationResult {
        AgentPublicationResult::Rejected(RejectedAgentPublication {
            activation: verified.prepared.activation,
        })
    }

    pub fn component_publication_outcome_unknown(
        &self,
        verified: VerifiedComponentPrevisibleActivation,
    ) -> ComponentPublicationResult {
        ComponentPublicationResult::OutcomeUnknown(ComponentPublicationRecoveryHandle {
            prepared: verified.prepared,
        })
    }

    pub fn agent_publication_outcome_unknown(
        &self,
        verified: VerifiedAgentPrevisibleActivation,
    ) -> AgentPublicationResult {
        AgentPublicationResult::OutcomeUnknown(AgentPublicationRecoveryHandle {
            prepared: verified.prepared,
        })
    }

    pub fn inspect_component_recovery(
        &self,
        recovery: &ComponentPublicationRecoveryHandle,
    ) -> Result<ProviderActivationRecord, SensitiveParamCatalogError> {
        self.require_activation_kind(
            &recovery.prepared.activation,
            PrevisibleActivationKind::Component,
        )?;
        Ok(recovery.prepared.activation.provider_record())
    }

    pub fn inspect_agent_recovery(
        &self,
        recovery: &AgentPublicationRecoveryHandle,
    ) -> Result<ProviderActivationRecord, SensitiveParamCatalogError> {
        self.require_activation_kind(
            &recovery.prepared.activation,
            PrevisibleActivationKind::Agent,
        )?;
        Ok(recovery.prepared.activation.provider_record())
    }

    pub fn resume_component_publication(
        &self,
        recovery: ComponentPublicationRecoveryHandle,
    ) -> VerifiedComponentPrevisibleActivation {
        VerifiedComponentPrevisibleActivation {
            prepared: recovery.prepared,
        }
    }

    pub fn resume_agent_publication(
        &self,
        recovery: AgentPublicationRecoveryHandle,
    ) -> VerifiedAgentPrevisibleActivation {
        VerifiedAgentPrevisibleActivation {
            prepared: recovery.prepared,
        }
    }

    pub fn rejected_component_into_activation(
        &self,
        rejected: RejectedComponentPublication,
    ) -> PrevisibleObservationActivation {
        rejected.activation
    }

    pub fn inspect_rejected_component(
        &self,
        rejected: &RejectedComponentPublication,
    ) -> Result<ProviderActivationRecord, SensitiveParamCatalogError> {
        self.require_activation_kind(&rejected.activation, PrevisibleActivationKind::Component)?;
        Ok(rejected.activation.provider_record())
    }

    pub fn inspect_rejected_agent(
        &self,
        rejected: &RejectedAgentPublication,
    ) -> Result<ProviderActivationRecord, SensitiveParamCatalogError> {
        self.require_activation_kind(&rejected.activation, PrevisibleActivationKind::Agent)?;
        Ok(rejected.activation.provider_record())
    }

    pub fn component_rejected_result(
        &self,
        rejected: RejectedComponentPublication,
    ) -> ComponentPublicationResult {
        ComponentPublicationResult::Rejected(rejected)
    }

    pub fn agent_rejected_result(
        &self,
        rejected: RejectedAgentPublication,
    ) -> AgentPublicationResult {
        AgentPublicationResult::Rejected(rejected)
    }

    pub fn rejected_agent_into_activation(
        &self,
        rejected: RejectedAgentPublication,
    ) -> PrevisibleObservationActivation {
        rejected.activation
    }

    pub fn consume_component_abort(
        &self,
        bundle: ComponentAbortBundle,
    ) -> Result<ProviderActivationRecord, SensitiveParamCatalogError> {
        self.require_activation_kind(&bundle.activation, PrevisibleActivationKind::Component)?;
        Ok(bundle.activation.provider_record())
    }

    pub fn inspect_component_abort(
        &self,
        bundle: &ComponentAbortBundle,
    ) -> Result<
        (ProviderActivationRecord, VerifiedPrevisibleProofMetadata),
        SensitiveParamCatalogError,
    > {
        self.require_activation_kind(&bundle.activation, PrevisibleActivationKind::Component)?;
        Ok((
            bundle.activation.provider_record(),
            bundle.proof_metadata.clone(),
        ))
    }

    pub fn consume_agent_abort(
        &self,
        bundle: AgentAbortBundle,
    ) -> Result<ProviderActivationRecord, SensitiveParamCatalogError> {
        self.require_activation_kind(&bundle.activation, PrevisibleActivationKind::Agent)?;
        Ok(bundle.activation.provider_record())
    }

    pub fn inspect_agent_abort(
        &self,
        bundle: &AgentAbortBundle,
    ) -> Result<
        (ProviderActivationRecord, VerifiedPrevisibleProofMetadata),
        SensitiveParamCatalogError,
    > {
        self.require_activation_kind(&bundle.activation, PrevisibleActivationKind::Agent)?;
        Ok((
            bundle.activation.provider_record(),
            bundle.proof_metadata.clone(),
        ))
    }

    /// Stamp the opaque runtime source capability from a durable exact tuple.
    pub fn issue_live_source(
        &self,
        claims: ObservationIdentityClaims,
    ) -> Result<AuthenticatedObservationSourceHandle, SensitiveParamCatalogError> {
        claims.validate()?;
        if claims.expected_class == ObservationIdentityClass::Host
            && !matches!(
                claims.exact_id.as_str(),
                "__sys:runtime" | "__sys:retention_sweeper" | "__sys:pack-manager"
            )
        {
            return Err(SensitiveParamCatalogError::InvalidIdentity);
        }
        let payload = source_handle_payload(self.registry_instance, self.boot, &claims)?;
        let mac = compute_hmac(&self.identity_key, SOURCE_HANDLE_DOMAIN, &payload)?;
        Ok(AuthenticatedObservationSourceHandle {
            claims,
            registry_instance: self.registry_instance,
            boot: self.boot,
            mac,
        })
    }

    pub fn issue_named_live_source(
        &self,
        claims: ObservationIdentityClaims,
    ) -> Result<IssuedObservationSourceHandle, SensitiveParamCatalogError> {
        Ok(IssuedObservationSourceHandle::from_provider(
            self.issue_live_source(claims)?,
        ))
    }

    pub fn mint_live_identity(
        &self,
        source: &AuthenticatedObservationSourceHandle,
    ) -> Result<TrustedObservationIdentity, SensitiveParamCatalogError> {
        self.verify_source_handle(source)?;
        self.stamp_trusted_identity(
            source.claims.clone(),
            ObservationAuthorityScope::Live { boot: self.boot },
        )
    }

    pub fn verify_live_identity(
        &self,
        identity: &TrustedObservationIdentity,
        expected: &ObservationIdentityClaims,
    ) -> Result<(), SensitiveParamCatalogError> {
        self.verify_trusted_identity(identity)?;
        if identity.claims != *expected {
            return Err(SensitiveParamCatalogError::StaleIdentity);
        }
        match identity.scope {
            ObservationAuthorityScope::Live { boot } if boot == self.boot => Ok(()),
            _ => Err(SensitiveParamCatalogError::ScopeMismatch),
        }
    }

    pub fn source_binding_digest(
        &self,
        claims: &ObservationIdentityClaims,
    ) -> Result<SourceBindingDigest, SensitiveParamCatalogError> {
        SourceBindingDigest::for_claims(claims)
    }

    fn issue_activation(
        &self,
        role: PrevisibleActivationKind,
        operation_id: String,
        claims: ObservationIdentityClaims,
        registry_sequence: u64,
    ) -> Result<PrevisibleObservationActivation, SensitiveParamCatalogError> {
        claims.validate()?;
        if operation_id.is_empty()
            || operation_id.len() > 256
            || registry_sequence == 0
            || registry_sequence > i64::MAX as u64
            || !matches!(
                (role, claims.expected_class),
                (
                    PrevisibleActivationKind::Component,
                    ObservationIdentityClass::Component
                ) | (
                    PrevisibleActivationKind::Agent,
                    ObservationIdentityClass::Agent
                )
            )
        {
            return Err(SensitiveParamCatalogError::InvalidIdentity);
        }
        let mut activation = PrevisibleObservationActivation {
            registry_instance: self.registry_instance,
            boot: self.boot,
            role,
            activation_nonce: fresh_nonzero_32()?,
            operation_id,
            claims,
            registry_sequence,
            mac: [0; 32],
        };
        activation.mac = compute_hmac(
            &self.ready_key,
            ACTIVATION_DOMAIN,
            &activation.canonical_bytes()?,
        )?;
        Ok(activation)
    }

    fn verify_source_handle(
        &self,
        source: &AuthenticatedObservationSourceHandle,
    ) -> Result<(), SensitiveParamCatalogError> {
        if source.registry_instance != self.registry_instance || source.boot != self.boot {
            return Err(SensitiveParamCatalogError::StaleIdentity);
        }
        let payload = source_handle_payload(source.registry_instance, source.boot, &source.claims)?;
        verify_hmac(
            &self.identity_key,
            SOURCE_HANDLE_DOMAIN,
            &payload,
            &source.mac,
        )
    }

    fn stamp_trusted_identity(
        &self,
        claims: ObservationIdentityClaims,
        scope: ObservationAuthorityScope,
    ) -> Result<TrustedObservationIdentity, SensitiveParamCatalogError> {
        let payload = trusted_identity_payload(self.registry_instance, &claims, &scope)?;
        let mac = compute_hmac(&self.identity_key, TRUSTED_IDENTITY_DOMAIN, &payload)?;
        Ok(TrustedObservationIdentity {
            claims,
            registry_instance: self.registry_instance,
            scope,
            mac,
        })
    }

    fn verify_trusted_identity(
        &self,
        identity: &TrustedObservationIdentity,
    ) -> Result<(), SensitiveParamCatalogError> {
        if identity.registry_instance != self.registry_instance {
            return Err(SensitiveParamCatalogError::StaleIdentity);
        }
        let payload = trusted_identity_payload(
            identity.registry_instance,
            &identity.claims,
            &identity.scope,
        )?;
        verify_hmac(
            &self.identity_key,
            TRUSTED_IDENTITY_DOMAIN,
            &payload,
            &identity.mac,
        )
    }

    fn require_activation_kind(
        &self,
        activation: &PrevisibleObservationActivation,
        expected: PrevisibleActivationKind,
    ) -> Result<(), SensitiveParamCatalogError> {
        activation.verify_origin(self.registry_instance, self.boot, &self.ready_key)?;
        if activation.role == expected {
            Ok(())
        } else {
            Err(SensitiveParamCatalogError::InvalidIdentity)
        }
    }

    fn prepare_publication(
        &self,
        activation: &PrevisibleObservationActivation,
    ) -> Result<
        (
            ObservationCatalogPublicationAck,
            IssuedObservationSourceHandle,
        ),
        SensitiveParamCatalogError,
    > {
        let record = activation.provider_record();
        let handle = self.issue_named_live_source(record.claims.clone())?;
        let payload = publication_ack_payload(&record)?;
        let mac = compute_hmac(&self.ready_key, PUBLICATION_ACK_DOMAIN, &payload)?;
        Ok((ObservationCatalogPublicationAck { record, mac }, handle))
    }
}

fn complete_publication(
    prepared: Box<PreparedPublication>,
) -> (
    ObservationCatalogPublicationAck,
    IssuedObservationSourceHandle,
) {
    let PreparedPublication {
        activation: _,
        ack,
        source_handle,
        proof_metadata: _,
    } = *prepared;
    (ack, source_handle)
}

/// A provider-only successful Component ready-proof verification result.
/// All fallible cryptographic and width checks complete before this value is
/// constructed, so post-commit conversion cannot consume recovery authority on
/// an error path.
pub struct VerifiedComponentPrevisibleActivation {
    prepared: Box<PreparedPublication>,
}

/// Agent-typed sibling of [`VerifiedComponentPrevisibleActivation`].
pub struct VerifiedAgentPrevisibleActivation {
    prepared: Box<PreparedPublication>,
}

struct PreparedPublication {
    activation: PrevisibleObservationActivation,
    ack: ObservationCatalogPublicationAck,
    source_handle: IssuedObservationSourceHandle,
    proof_metadata: VerifiedPrevisibleProofMetadata,
}

impl VerifiedComponentPrevisibleActivation {
    pub fn claims(&self) -> &ObservationIdentityClaims {
        &self.prepared.activation.claims
    }

    pub fn provider_record(&self) -> ProviderActivationRecord {
        self.prepared.activation.provider_record()
    }

    pub fn proof_metadata(&self) -> &VerifiedPrevisibleProofMetadata {
        &self.prepared.proof_metadata
    }
}

impl VerifiedAgentPrevisibleActivation {
    pub fn claims(&self) -> &ObservationIdentityClaims {
        &self.prepared.activation.claims
    }

    pub fn provider_record(&self) -> ProviderActivationRecord {
        self.prepared.activation.provider_record()
    }

    pub fn proof_metadata(&self) -> &VerifiedPrevisibleProofMetadata {
        &self.prepared.proof_metadata
    }
}

impl fmt::Debug for VerifiedComponentPrevisibleActivation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VerifiedComponentPrevisibleActivation(<opaque>)")
    }
}

impl fmt::Debug for VerifiedAgentPrevisibleActivation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VerifiedAgentPrevisibleActivation(<opaque>)")
    }
}

pub enum ComponentReadyVerification {
    Verified(VerifiedComponentPrevisibleActivation),
    Rejected(RejectedComponentPublication),
}

pub enum AgentReadyVerification {
    Verified(VerifiedAgentPrevisibleActivation),
    Rejected(RejectedAgentPublication),
}

impl fmt::Debug for ComponentReadyVerification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Verified(_) => f.write_str("ComponentReadyVerification::Verified(<opaque>)"),
            Self::Rejected(_) => f.write_str("ComponentReadyVerification::Rejected(<opaque>)"),
        }
    }
}

impl fmt::Debug for AgentReadyVerification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Verified(_) => f.write_str("AgentReadyVerification::Verified(<opaque>)"),
            Self::Rejected(_) => f.write_str("AgentReadyVerification::Rejected(<opaque>)"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrevisibleActivationKind {
    Component = 1,
    Agent = 2,
}

/// Non-authorizing provider view returned only after the role verifies the
/// opaque activation or recovery handle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderActivationRecord {
    pub kind: PrevisibleActivationKind,
    pub activation_nonce: [u8; 32],
    pub operation_id: String,
    pub claims: ObservationIdentityClaims,
    pub registry_sequence: u64,
}

/// Hidden, move-only activation guard.
pub struct PrevisibleObservationActivation {
    registry_instance: [u8; 16],
    boot: [u8; 16],
    role: PrevisibleActivationKind,
    activation_nonce: [u8; 32],
    operation_id: String,
    claims: ObservationIdentityClaims,
    registry_sequence: u64,
    mac: [u8; 32],
}

impl PrevisibleObservationActivation {
    fn canonical_bytes(&self) -> Result<Vec<u8>, SensitiveParamCatalogError> {
        let mut bytes =
            Vec::with_capacity(128 + self.operation_id.len() + self.claims.exact_id.len());
        bytes.push(1);
        bytes.extend_from_slice(&self.boot);
        bytes.extend_from_slice(&self.registry_instance);
        bytes.push(self.role as u8);
        bytes.extend_from_slice(&self.activation_nonce);
        put_text(&mut bytes, &self.operation_id)?;
        put_claims(&mut bytes, &self.claims)?;
        bytes.extend_from_slice(&self.registry_sequence.to_be_bytes());
        Ok(bytes)
    }

    fn verify_origin(
        &self,
        registry_instance: [u8; 16],
        boot: [u8; 16],
        key: &[u8; 32],
    ) -> Result<(), SensitiveParamCatalogError> {
        if self.registry_instance != registry_instance || self.boot != boot {
            return Err(SensitiveParamCatalogError::StaleIdentity);
        }
        verify_hmac(key, ACTIVATION_DOMAIN, &self.canonical_bytes()?, &self.mac)
    }

    fn provider_record(&self) -> ProviderActivationRecord {
        ProviderActivationRecord {
            kind: self.role,
            activation_nonce: self.activation_nonce,
            operation_id: self.operation_id.clone(),
            claims: self.claims.clone(),
            registry_sequence: self.registry_sequence,
        }
    }
}

impl fmt::Debug for PrevisibleObservationActivation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrevisibleObservationActivation(<opaque>)")
    }
}

/// Authenticated receipt body shared only internally by the six closed
/// previsible owner types.  The public wrappers are deliberately distinct and
/// move-only, so a subject receipt cannot fill the table/lifecycle slot.
struct PrevisibleOwnerReceipt {
    activation_digest: [u8; 32],
    token: PrivateToken,
}

impl PrevisibleOwnerReceipt {
    fn issue(
        key: &[u8; 32],
        domain: &[u8],
        activation_digest: [u8; 32],
    ) -> Result<Self, SensitiveParamCatalogError> {
        Ok(Self {
            activation_digest,
            token: issue_private_token(key, domain, &activation_digest)?,
        })
    }

    fn verify(
        &self,
        key: &[u8; 32],
        domain: &[u8],
        expected_activation_digest: [u8; 32],
    ) -> Result<(), SensitiveParamCatalogError> {
        if !bool::from(self.activation_digest.ct_eq(&expected_activation_digest)) {
            return Err(SensitiveParamCatalogError::InvalidCarrier);
        }
        verify_private_token(key, domain, &self.activation_digest, &self.token)
    }

    fn carrier_digest(&self, domain: &[u8]) -> [u8; 32] {
        private_token_carrier_digest(domain, &self.activation_digest, &self.token)
    }
}

macro_rules! previsible_receipt_type {
    ($name:ident, $domain:ident) => {
        pub struct $name(PrevisibleOwnerReceipt);

        impl $name {
            fn verify(
                &self,
                key: &[u8; 32],
                activation_digest: [u8; 32],
            ) -> Result<(), SensitiveParamCatalogError> {
                self.0.verify(key, $domain, activation_digest)
            }

            fn carrier_digest(&self) -> [u8; 32] {
                self.0.carrier_digest($domain)
            }
        }

        opaque_debug!($name);
    };
}

previsible_receipt_type!(PrevisibleSubjectReadyReceipt, READY_SUBJECT_RECEIPT_DOMAIN);
previsible_receipt_type!(
    PrevisibleHandleTableReadyReceipt,
    READY_TABLE_RECEIPT_DOMAIN
);
previsible_receipt_type!(
    PrevisibleLifecycleReadyReceipt,
    READY_LIFECYCLE_RECEIPT_DOMAIN
);
previsible_receipt_type!(
    PrevisibleSubjectAbsenceReceipt,
    ABORT_SUBJECT_RECEIPT_DOMAIN
);
previsible_receipt_type!(
    PrevisibleHandleTableAbsenceReceipt,
    ABORT_TABLE_RECEIPT_DOMAIN
);
previsible_receipt_type!(
    PrevisibleLifecycleAbsenceReceipt,
    ABORT_LIFECYCLE_RECEIPT_DOMAIN
);

/// Exact three-owner ready set.  Construction consumes one receipt of every
/// distinct owner type; missing, duplicate, and success/absence substitution
/// are therefore unrepresentable.
pub struct PrevisibleReadyReceiptSet {
    subject: PrevisibleSubjectReadyReceipt,
    table: PrevisibleHandleTableReadyReceipt,
    lifecycle: PrevisibleLifecycleReadyReceipt,
}

impl PrevisibleReadyReceiptSet {
    pub fn new(
        subject: PrevisibleSubjectReadyReceipt,
        table: PrevisibleHandleTableReadyReceipt,
        lifecycle: PrevisibleLifecycleReadyReceipt,
    ) -> Self {
        Self {
            subject,
            table,
            lifecycle,
        }
    }

    fn verify(
        &self,
        key: &[u8; 32],
        activation_digest: [u8; 32],
    ) -> Result<(), SensitiveParamCatalogError> {
        self.subject.verify(key, activation_digest)?;
        self.table.verify(key, activation_digest)?;
        self.lifecycle.verify(key, activation_digest)
    }
}

opaque_debug!(PrevisibleReadyReceiptSet);

/// Exact three-owner absence set for rollback.
pub struct PrevisibleAbortReceiptSet {
    subject: PrevisibleSubjectAbsenceReceipt,
    table: PrevisibleHandleTableAbsenceReceipt,
    lifecycle: PrevisibleLifecycleAbsenceReceipt,
}

impl PrevisibleAbortReceiptSet {
    pub fn new(
        subject: PrevisibleSubjectAbsenceReceipt,
        table: PrevisibleHandleTableAbsenceReceipt,
        lifecycle: PrevisibleLifecycleAbsenceReceipt,
    ) -> Self {
        Self {
            subject,
            table,
            lifecycle,
        }
    }

    fn verify(
        &self,
        key: &[u8; 32],
        activation_digest: [u8; 32],
    ) -> Result<(), SensitiveParamCatalogError> {
        self.subject.verify(key, activation_digest)?;
        self.table.verify(key, activation_digest)?;
        self.lifecycle.verify(key, activation_digest)
    }
}

opaque_debug!(PrevisibleAbortReceiptSet);

/// Move-only success proof.
pub struct PrevisibleActivationReadyProof {
    activation_digest: [u8; 32],
    subject_receipt_digest: [u8; 32],
    table_receipt_digest: [u8; 32],
    lifecycle_receipt_digest: [u8; 32],
    nonce: [u8; 32],
    mac: [u8; 32],
}

/// Move-only absence proof with a distinct MAC domain.
pub struct PrevisibleActivationAbortProof {
    activation_digest: [u8; 32],
    subject_absence_digest: [u8; 32],
    table_absence_digest: [u8; 32],
    lifecycle_absence_digest: [u8; 32],
    nonce: [u8; 32],
    mac: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifiedPrevisibleProofKind {
    Ready,
    Abort,
}

/// Non-authorizing journal projection emitted only after the corresponding
/// proof MAC and exact activation association have verified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedPrevisibleProofMetadata {
    pub kind: VerifiedPrevisibleProofKind,
    pub subject_receipt_digest: [u8; 32],
    pub table_receipt_digest: [u8; 32],
    pub lifecycle_receipt_digest: [u8; 32],
    pub proof_nonce: [u8; 32],
    pub proof_digest: [u8; 32],
    /// Provider-authenticated publication or abort recovery nonce.  Scheduler
    /// journals this value directly and must never synthesize a replacement.
    pub recovery_nonce: [u8; 32],
    /// Present only for a Ready proof's typed rejection path.
    pub rejection_nonce: Option<[u8; 32]>,
}

impl PrevisibleActivationReadyProof {
    fn metadata(
        &self,
        key: &[u8; 32],
    ) -> Result<VerifiedPrevisibleProofMetadata, SensitiveParamCatalogError> {
        let mut bytes = Vec::with_capacity(32 * 6 + 1);
        bytes.push(1);
        bytes.extend_from_slice(&self.activation_digest);
        bytes.extend_from_slice(&self.subject_receipt_digest);
        bytes.extend_from_slice(&self.table_receipt_digest);
        bytes.extend_from_slice(&self.lifecycle_receipt_digest);
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&self.mac);
        let proof_digest = sha256_with_domain(
            b"advance.contract218.previsible-ready-proof-digest.v1\0",
            &bytes,
        );
        let recovery_nonce = compute_hmac(key, READY_RECOVERY_NONCE_DOMAIN, &proof_digest)?;
        let rejection_nonce = compute_hmac(key, READY_REJECTION_NONCE_DOMAIN, &proof_digest)?;
        if recovery_nonce == [0; 32] || rejection_nonce == [0; 32] {
            return Err(SensitiveParamCatalogError::InvalidCarrier);
        }
        Ok(VerifiedPrevisibleProofMetadata {
            kind: VerifiedPrevisibleProofKind::Ready,
            subject_receipt_digest: self.subject_receipt_digest,
            table_receipt_digest: self.table_receipt_digest,
            lifecycle_receipt_digest: self.lifecycle_receipt_digest,
            proof_nonce: self.nonce,
            proof_digest,
            recovery_nonce,
            rejection_nonce: Some(rejection_nonce),
        })
    }
}

impl PrevisibleActivationAbortProof {
    fn metadata(
        &self,
        key: &[u8; 32],
    ) -> Result<VerifiedPrevisibleProofMetadata, SensitiveParamCatalogError> {
        let mut bytes = Vec::with_capacity(32 * 6 + 1);
        bytes.push(2);
        bytes.extend_from_slice(&self.activation_digest);
        bytes.extend_from_slice(&self.subject_absence_digest);
        bytes.extend_from_slice(&self.table_absence_digest);
        bytes.extend_from_slice(&self.lifecycle_absence_digest);
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&self.mac);
        let proof_digest = sha256_with_domain(
            b"advance.contract218.previsible-abort-proof-digest.v1\0",
            &bytes,
        );
        let recovery_nonce = compute_hmac(key, ABORT_RECOVERY_NONCE_DOMAIN, &proof_digest)?;
        if recovery_nonce == [0; 32] {
            return Err(SensitiveParamCatalogError::InvalidCarrier);
        }
        Ok(VerifiedPrevisibleProofMetadata {
            kind: VerifiedPrevisibleProofKind::Abort,
            subject_receipt_digest: self.subject_absence_digest,
            table_receipt_digest: self.table_absence_digest,
            lifecycle_receipt_digest: self.lifecycle_absence_digest,
            proof_nonce: self.nonce,
            proof_digest,
            recovery_nonce,
            rejection_nonce: None,
        })
    }
}

opaque_debug!(PrevisibleActivationReadyProof);
opaque_debug!(PrevisibleActivationAbortProof);

/// Typed publication results.  Wrong-role recovery/abort cannot be passed to
/// the sibling port because the Rust types are distinct.
pub struct ObservationCatalogPublicationAck {
    record: ProviderActivationRecord,
    mac: [u8; 32],
}
pub struct RejectedComponentPublication {
    activation: PrevisibleObservationActivation,
}
pub struct RejectedAgentPublication {
    activation: PrevisibleObservationActivation,
}
pub struct ComponentPublicationRecoveryHandle {
    prepared: Box<PreparedPublication>,
}
pub struct AgentPublicationRecoveryHandle {
    prepared: Box<PreparedPublication>,
}

pub enum ComponentPublicationResult {
    Published(ObservationCatalogPublicationAck),
    Rejected(RejectedComponentPublication),
    OutcomeUnknown(ComponentPublicationRecoveryHandle),
}

pub enum AgentPublicationResult {
    Published(ObservationCatalogPublicationAck),
    Rejected(RejectedAgentPublication),
    OutcomeUnknown(AgentPublicationRecoveryHandle),
}

pub struct ComponentAbortBundle {
    activation: PrevisibleObservationActivation,
    proof_metadata: VerifiedPrevisibleProofMetadata,
}
pub struct AgentAbortBundle {
    activation: PrevisibleObservationActivation,
    proof_metadata: VerifiedPrevisibleProofMetadata,
}
pub enum PrevisibleAbortBundle {
    Component(ComponentAbortBundle),
    Agent(AgentAbortBundle),
}

opaque_debug!(ObservationCatalogPublicationAck);
opaque_debug!(RejectedComponentPublication);
opaque_debug!(RejectedAgentPublication);
opaque_debug!(ComponentPublicationRecoveryHandle);
opaque_debug!(AgentPublicationRecoveryHandle);
opaque_debug!(ComponentAbortBundle);
opaque_debug!(AgentAbortBundle);

/// Sole source-emission receipt issuer embedded in the previsible issuer and
/// moved once into the live-handle table.
pub struct SourceEmissionReceiptIssuer {
    registry_instance: [u8; 16],
    boot: [u8; 16],
    key: Zeroizing<[u8; 32]>,
}

/// Exact, move-only source-emission quiescence receipt.  It binds the complete
/// operation, member tuple, boot, handle-table generation and settled lease
/// high-water; it is no longer an uninhabited placeholder.
pub struct VerifiedSourceEmissionQuiesceReceipt {
    registry_instance: [u8; 16],
    boot: [u8; 16],
    record: TerminationOperationRecord,
    member: ObservationIdentityClaims,
    handle_table_generation: u64,
    borrowed_high_water: u64,
    settled_high_water: u64,
    token: PrivateToken,
}

struct TerminationOwnerReceipt {
    tag: u8,
    registry_instance: [u8; 16],
    boot: [u8; 16],
    record: TerminationOperationRecord,
    member: ObservationIdentityClaims,
    store_instance_id: [u8; 16],
    high_water: u64,
    token: PrivateToken,
}

macro_rules! termination_owner_receipt_type {
    ($name:ident, $tag:expr) => {
        pub struct $name(TerminationOwnerReceipt);
        opaque_debug!($name);
    };
}

termination_owner_receipt_type!(VerifiedLiveHandleAbsenceReceipt, 1);
termination_owner_receipt_type!(VerifiedRunStoppedReceipt, 2);
termination_owner_receipt_type!(VerifiedMailboxClosedAndEmptyReceipt, 3);
termination_owner_receipt_type!(VerifiedGrantSubjectDrainToken, 4);
termination_owner_receipt_type!(VerifiedWorkspaceDispositionReceipt, 5);
termination_owner_receipt_type!(VerifiedTreeNodeRemovedReceipt, 6);

/// Exact grant-subject drain family consumed by termination prepare.  The
/// verifier still enforces the complete, duplicate-free member set.
pub struct TerminationGrantSubjectDrainReceiptSet {
    receipts: Vec<VerifiedGrantSubjectDrainToken>,
}

impl TerminationGrantSubjectDrainReceiptSet {
    pub fn new(receipts: Vec<VerifiedGrantSubjectDrainToken>) -> Self {
        Self { receipts }
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn into_test_receipts(self) -> Vec<VerifiedGrantSubjectDrainToken> {
        self.receipts
    }
}

/// Exact live-source emission quiescence family consumed by termination
/// prepare.  It is intentionally distinct from the grant-subject family.
pub struct TerminationSourceEmissionQuiesceReceiptSet {
    receipts: Vec<VerifiedSourceEmissionQuiesceReceipt>,
}

impl TerminationSourceEmissionQuiesceReceiptSet {
    pub fn new(receipts: Vec<VerifiedSourceEmissionQuiesceReceipt>) -> Self {
        Self { receipts }
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn into_test_receipts(self) -> Vec<VerifiedSourceEmissionQuiesceReceipt> {
        self.receipts
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedTerminationPrepareMemberReceiptMetadata {
    pub member: ObservationIdentityClaims,
    pub grant_subject_drain_receipt_digest: [u8; 32],
    pub source_emission_quiesce_receipt_digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedTerminationPrepareReceiptMetadata {
    pub registry_instance: [u8; 16],
    pub boot: [u8; 16],
    pub operation_id: String,
    pub member_set_digest: [u8; 32],
    pub registry_sequence: u64,
    pub member_count: u32,
    pub grant_subject_drain_receipt_set_digest: [u8; 32],
    pub source_emission_quiesce_receipt_set_digest: [u8; 32],
    pub aggregate_receipt_set_digest: [u8; 32],
    pub members: Vec<VerifiedTerminationPrepareMemberReceiptMetadata>,
}

pub struct VerifiedTerminationPrepareReceiptSet {
    metadata: VerifiedTerminationPrepareReceiptMetadata,
}

impl VerifiedTerminationPrepareReceiptSet {
    pub fn metadata(&self) -> &VerifiedTerminationPrepareReceiptMetadata {
        &self.metadata
    }
}

opaque_debug!(TerminationGrantSubjectDrainReceiptSet);
opaque_debug!(TerminationSourceEmissionQuiesceReceiptSet);
opaque_debug!(VerifiedTerminationPrepareReceiptSet);

/// Exact non-authorizing projection required by the rooted termination
/// finalization journal.  Every field is taken from an already authenticated
/// move-only carrier; the scheduler never invents recovery nonces or receipt
/// digests.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedTerminationFinalizeJournalMetadata {
    pub prepare_ack_digest: [u8; 32],
    pub prepare_ack_nonce: [u8; 32],
    pub cleanup_receipt_digest: [u8; 32],
    pub cleanup_high_water_digest: [u8; 32],
    pub cleanup_receipt_set_digest: [u8; 32],
    pub cleanup_nonce: [u8; 32],
    pub finalize_recovery_nonce: [u8; 32],
    pub finalize_ack_digest: [u8; 32],
}

/// One member's complete six-owner set.  The distinct field types make
/// missing/duplicate/unknown tags unrepresentable at the public boundary.
pub struct TerminationMemberCleanupReceiptSet {
    live_handle: VerifiedLiveHandleAbsenceReceipt,
    run: VerifiedRunStoppedReceipt,
    mailbox: VerifiedMailboxClosedAndEmptyReceipt,
    grant: VerifiedGrantSubjectDrainToken,
    workspace: VerifiedWorkspaceDispositionReceipt,
    tree: VerifiedTreeNodeRemovedReceipt,
}

impl TerminationMemberCleanupReceiptSet {
    pub fn new(
        live_handle: VerifiedLiveHandleAbsenceReceipt,
        run: VerifiedRunStoppedReceipt,
        mailbox: VerifiedMailboxClosedAndEmptyReceipt,
        grant: VerifiedGrantSubjectDrainToken,
        workspace: VerifiedWorkspaceDispositionReceipt,
        tree: VerifiedTreeNodeRemovedReceipt,
    ) -> Self {
        Self {
            live_handle,
            run,
            mailbox,
            grant,
            workspace,
            tree,
        }
    }

    fn receipts(&self) -> [&TerminationOwnerReceipt; 6] {
        [
            &self.live_handle.0,
            &self.run.0,
            &self.mailbox.0,
            &self.grant.0,
            &self.workspace.0,
            &self.tree.0,
        ]
    }
}

opaque_debug!(TerminationMemberCleanupReceiptSet);

/// Complete member collection consumed by the cleanup coordinator.
pub struct TerminationCleanupReceiptSet {
    members: Vec<TerminationMemberCleanupReceiptSet>,
}

impl TerminationCleanupReceiptSet {
    pub fn new(members: Vec<TerminationMemberCleanupReceiptSet>) -> Self {
        Self { members }
    }
}

opaque_debug!(TerminationCleanupReceiptSet);

/// Provider-issued purpose-1 retained-tombstone GC challenge.
pub struct RetainedTombstoneGcChallenge {
    registry_instance: [u8; 16],
    operation_boot: [u8; 16],
    record: TerminationOperationRecord,
    tombstone_state_root: [u8; 32],
    gc_generation: u64,
    token: PrivateToken,
}

/// C123's independently typed purpose-2 zero-reference proof.
pub struct C123Purpose2ZeroToken {
    registry_instance: [u8; 16],
    operation_boot: [u8; 16],
    record: TerminationOperationRecord,
    tombstone_state_root: [u8; 32],
    gc_generation: u64,
    challenge_nonce: [u8; 32],
    store_instance_id: [u8; 16],
    high_water: u64,
    state_root: [u8; 32],
    token: PrivateToken,
}

struct RetainedGcOwnerReceipt {
    tag: u8,
    registry_instance: [u8; 16],
    operation_boot: [u8; 16],
    record: TerminationOperationRecord,
    tombstone_state_root: [u8; 32],
    gc_generation: u64,
    challenge_nonce: [u8; 32],
    store_instance_id: [u8; 16],
    high_water: u64,
    state_root: [u8; 32],
    token: PrivateToken,
}

macro_rules! retained_gc_owner_type {
    ($name:ident, $tag:expr) => {
        pub struct $name(RetainedGcOwnerReceipt);
        opaque_debug!($name);
    };
}

retained_gc_owner_type!(M009GcZeroScanReceipt, 1);
retained_gc_owner_type!(M019GcZeroScanReceipt, 2);
retained_gc_owner_type!(C123GcZeroScanReceipt, 3);
retained_gc_owner_type!(RoleAllocationGcZeroScanReceipt, 4);
retained_gc_owner_type!(RegistryGcZeroScanReceipt, 5);

pub struct RetainedTombstoneGcReceiptSet {
    m009: M009GcZeroScanReceipt,
    m019: M019GcZeroScanReceipt,
    c123: C123GcZeroScanReceipt,
    role_allocation: RoleAllocationGcZeroScanReceipt,
    registry: RegistryGcZeroScanReceipt,
}

impl RetainedTombstoneGcReceiptSet {
    pub fn new(
        m009: M009GcZeroScanReceipt,
        m019: M019GcZeroScanReceipt,
        c123: C123GcZeroScanReceipt,
        role_allocation: RoleAllocationGcZeroScanReceipt,
        registry: RegistryGcZeroScanReceipt,
    ) -> Self {
        Self {
            m009,
            m019,
            c123,
            role_allocation,
            registry,
        }
    }

    fn receipts(&self) -> [&RetainedGcOwnerReceipt; 5] {
        [
            &self.m009.0,
            &self.m019.0,
            &self.c123.0,
            &self.role_allocation.0,
            &self.registry.0,
        ]
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetainedTombstoneGcOwnerMetadata {
    pub store_instance_id: [u8; 16],
    pub high_water: u64,
    pub state_root: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetainedTombstoneGcChallengeMetadata {
    pub registry_instance: [u8; 16],
    pub operation_boot: [u8; 16],
    pub operation_id: String,
    pub member_set_digest: [u8; 32],
    pub tombstone_state_root: [u8; 32],
    pub gc_generation: u64,
    pub gc_registry_sequence: u64,
    pub challenge_nonce: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetainedTombstoneGcMetadata {
    pub registry_instance: [u8; 16],
    pub operation_boot: [u8; 16],
    pub operation_id: String,
    pub member_set_digest: [u8; 32],
    pub tombstone_state_root: [u8; 32],
    pub gc_generation: u64,
    pub gc_registry_sequence: u64,
    pub challenge_nonce: [u8; 32],
    pub purpose2_digest: [u8; 32],
    pub purpose2: RetainedTombstoneGcOwnerMetadata,
    pub m009: RetainedTombstoneGcOwnerMetadata,
    pub m019: RetainedTombstoneGcOwnerMetadata,
    pub c123: RetainedTombstoneGcOwnerMetadata,
    pub role_allocation: RetainedTombstoneGcOwnerMetadata,
    pub registry: RetainedTombstoneGcOwnerMetadata,
    pub aggregate_digest: [u8; 32],
}

pub struct VerifiedRetainedTombstoneGcSet {
    metadata: RetainedTombstoneGcMetadata,
}

impl VerifiedRetainedTombstoneGcSet {
    pub fn metadata(&self) -> &RetainedTombstoneGcMetadata {
        &self.metadata
    }
}

opaque_debug!(RetainedTombstoneGcChallenge);
opaque_debug!(C123Purpose2ZeroToken);
opaque_debug!(RetainedTombstoneGcReceiptSet);
opaque_debug!(VerifiedRetainedTombstoneGcSet);

/// Provider-issued scan challenge for retiring one persisted carrier key.
pub struct PersistedKeyRetirementChallenge {
    registry_instance: [u8; 16],
    boot: [u8; 16],
    operation_id: String,
    keyring_root: [u8; 32],
    keyring_generation: u64,
    key_id: u32,
    migration_generation: u64,
    token: PrivateToken,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PersistedKeyRetirementChallengeMetadata {
    pub registry_instance: [u8; 16],
    pub boot: [u8; 16],
    pub operation_id: String,
    pub keyring_root: [u8; 32],
    pub keyring_generation: u64,
    pub key_id: u32,
    pub migration_generation: u64,
    pub challenge_nonce: [u8; 32],
}

struct PersistedKeyOwnerScanReceipt {
    tag: u8,
    registry_instance: [u8; 16],
    boot: [u8; 16],
    operation_id: String,
    keyring_root: [u8; 32],
    keyring_generation: u64,
    key_id: u32,
    migration_generation: u64,
    challenge_nonce: [u8; 32],
    store_instance_id: [u8; 16],
    high_water: u64,
    state_root: [u8; 32],
    inventory_digest: [u8; 32],
    segment_count: u64,
    byte_count: u64,
    retention_high_water: u64,
    token: PrivateToken,
}

macro_rules! key_retirement_owner_type {
    ($name:ident, $tag:expr) => {
        pub struct $name(PersistedKeyOwnerScanReceipt);
        opaque_debug!($name);
    };
}

key_retirement_owner_type!(SqlitePersistedKeyScanReceipt, 1);
key_retirement_owner_type!(JsonlPersistedKeyScanReceipt, 2);
key_retirement_owner_type!(MigrationReferenceScanReceipt, 3);

pub struct PersistedKeyRetirementScanSet {
    sqlite: SqlitePersistedKeyScanReceipt,
    jsonl: JsonlPersistedKeyScanReceipt,
    migration: MigrationReferenceScanReceipt,
}

impl PersistedKeyRetirementScanSet {
    pub fn new(
        sqlite: SqlitePersistedKeyScanReceipt,
        jsonl: JsonlPersistedKeyScanReceipt,
        migration: MigrationReferenceScanReceipt,
    ) -> Self {
        Self {
            sqlite,
            jsonl,
            migration,
        }
    }

    fn receipts(&self) -> [&PersistedKeyOwnerScanReceipt; 3] {
        [&self.sqlite.0, &self.jsonl.0, &self.migration.0]
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PersistedKeyOwnerScanMetadata {
    pub store_instance_id: [u8; 16],
    pub high_water: u64,
    pub state_root: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JsonlPersistedKeyScanMetadata {
    pub store_instance_id: [u8; 16],
    pub inventory_digest: [u8; 32],
    pub segment_count: u64,
    pub byte_count: u64,
    pub retention_high_water: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedPersistedKeyRetirementScanMetadata {
    pub registry_instance: [u8; 16],
    pub boot: [u8; 16],
    pub operation_id: String,
    pub keyring_root: [u8; 32],
    pub keyring_generation: u64,
    pub key_id: u32,
    pub migration_generation: u64,
    pub challenge_nonce: [u8; 32],
    pub sqlite: PersistedKeyOwnerScanMetadata,
    pub jsonl: JsonlPersistedKeyScanMetadata,
    pub migration: PersistedKeyOwnerScanMetadata,
    pub aggregate_digest: [u8; 32],
}

pub struct VerifiedPersistedKeyRetirementScanSet {
    metadata: VerifiedPersistedKeyRetirementScanMetadata,
}

impl VerifiedPersistedKeyRetirementScanSet {
    pub fn metadata(&self) -> &VerifiedPersistedKeyRetirementScanMetadata {
        &self.metadata
    }
}

opaque_debug!(PersistedKeyRetirementChallenge);
opaque_debug!(PersistedKeyRetirementScanSet);
opaque_debug!(VerifiedPersistedKeyRetirementScanSet);

pub struct TerminationCleanupCompleteReceipt {
    record: TerminationOperationRecord,
    prepare_ack_digest: [u8; 32],
    cleanup_high_water_digest: [u8; 32],
    receipt_set_digest: [u8; 32],
    token: PrivateToken,
}
pub struct TerminationPrepareCommitAck {
    record: TerminationOperationRecord,
    token: PrivateToken,
}
pub struct UncommittedTerminationPrepareProof {
    subject: UncommittedPrepareRejectionSubject,
    token: PrivateToken,
}
pub struct TerminationPrepareRecoveryHandle {
    record: TerminationOperationRecord,
    token: PrivateToken,
}
pub struct TerminationFinalizeCommitAck {
    record: TerminationOperationRecord,
    token: PrivateToken,
}
pub struct TerminationFinalizeRecoveryHandle {
    verified: Box<VerifiedTerminationFinalizeInputs>,
}
pub struct VerifiedTerminationFinalizeInputs {
    prepared: TerminationPrepareCommitAck,
    cleanup: TerminationCleanupCompleteReceipt,
    committed_ack: TerminationFinalizeCommitAck,
    recovery_token: PrivateToken,
}

/// Non-authorizing, exact provider journal key for termination helpers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TerminationOperationRecord {
    pub operation_id: String,
    pub member_set_digest: [u8; 32],
    pub registry_sequence: u64,
}

impl TerminationOperationRecord {
    fn canonical_bytes(&self) -> Result<Vec<u8>, SensitiveParamCatalogError> {
        if self.operation_id.is_empty()
            || self.operation_id.len() > 256
            || self.registry_sequence == 0
            || self.registry_sequence > i64::MAX as u64
        {
            return Err(SensitiveParamCatalogError::InvalidIdentity);
        }
        let mut bytes = Vec::with_capacity(44 + self.operation_id.len());
        put_text(&mut bytes, &self.operation_id)?;
        bytes.extend_from_slice(&self.member_set_digest);
        bytes.extend_from_slice(&self.registry_sequence.to_be_bytes());
        Ok(bytes)
    }
}

enum UncommittedPrepareRejectionSubject {
    Operation(TerminationOperationRecord),
    InvalidRequest(InvalidTerminationPrepareRequestRecord),
}

struct InvalidTerminationPrepareRequestRecord {
    operation_id_digest: [u8; 32],
    request_digest: [u8; 32],
    current_sequence: u64,
}

impl InvalidTerminationPrepareRequestRecord {
    fn canonical_bytes(&self) -> [u8; 72] {
        let mut bytes = [0; 72];
        bytes[..32].copy_from_slice(&self.operation_id_digest);
        bytes[32..64].copy_from_slice(&self.request_digest);
        bytes[64..].copy_from_slice(&self.current_sequence.to_be_bytes());
        bytes
    }
}

pub enum TerminationPrepareFailure {
    Rejected(UncommittedTerminationPrepareProof),
    OutcomeUnknown(TerminationPrepareRecoveryHandle),
}

impl fmt::Debug for TerminationPrepareFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rejected(_) => f.write_str("TerminationPrepareFailure::Rejected(<opaque>)"),
            Self::OutcomeUnknown(_) => {
                f.write_str("TerminationPrepareFailure::OutcomeUnknown(<opaque>)")
            }
        }
    }
}

pub enum TerminationFinalizeResult {
    Committed(TerminationFinalizeCommitAck),
    Rejected {
        prepared: TerminationPrepareCommitAck,
        cleanup: TerminationCleanupCompleteReceipt,
    },
    OutcomeUnknown(TerminationFinalizeRecoveryHandle),
}

pub enum TerminationFinalizeInputVerification {
    Verified(VerifiedTerminationFinalizeInputs),
    Rejected {
        prepared: TerminationPrepareCommitAck,
        cleanup: TerminationCleanupCompleteReceipt,
    },
}

opaque_debug!(VerifiedSourceEmissionQuiesceReceipt);
opaque_debug!(SourceEmissionReceiptIssuer);
opaque_debug!(TerminationCleanupCompleteReceipt);
opaque_debug!(TerminationPrepareCommitAck);
opaque_debug!(UncommittedTerminationPrepareProof);
opaque_debug!(TerminationPrepareRecoveryHandle);
opaque_debug!(TerminationFinalizeCommitAck);
opaque_debug!(TerminationFinalizeRecoveryHandle);
opaque_debug!(VerifiedTerminationFinalizeInputs);

impl fmt::Debug for TerminationFinalizeInputVerification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Verified(_) => {
                f.write_str("TerminationFinalizeInputVerification::Verified(<opaque>)")
            }
            Self::Rejected { .. } => {
                f.write_str("TerminationFinalizeInputVerification::Rejected(<opaque>)")
            }
        }
    }
}

/// Exact M014-only termination state-machine role.
pub struct TerminationStateMachineRole {
    registry_instance: [u8; 16],
    boot: [u8; 16],
    key: Zeroizing<[u8; 32]>,
    source_emission_key: Zeroizing<[u8; 32]>,
    owner_receipt_key: Zeroizing<[u8; 32]>,
}
/// Exact M005-only cleanup issuer role.
pub struct TerminationCleanupReceiptIssuerRole {
    registry_instance: [u8; 16],
    boot: [u8; 16],
    key: Zeroizing<[u8; 32]>,
    prepare_key: Zeroizing<[u8; 32]>,
}
/// Exact M014-only cleanup verifier role.
pub struct TerminationCleanupReceiptVerifierRole {
    registry_instance: [u8; 16],
    boot: [u8; 16],
    key: Zeroizing<[u8; 32]>,
}

opaque_debug!(TerminationStateMachineRole);
opaque_debug!(TerminationCleanupReceiptIssuerRole);
opaque_debug!(TerminationCleanupReceiptVerifierRole);

impl SourceEmissionReceiptIssuer {
    pub fn issue_quiesce_receipt(
        &self,
        record: TerminationOperationRecord,
        member: ObservationIdentityClaims,
        handle_table_generation: u64,
        borrowed_high_water: u64,
        settled_high_water: u64,
    ) -> Result<VerifiedSourceEmissionQuiesceReceipt, SensitiveParamCatalogError> {
        if handle_table_generation == 0
            || borrowed_high_water == 0
            || borrowed_high_water != settled_high_water
        {
            return Err(SensitiveParamCatalogError::InvalidIdentity);
        }
        member.validate()?;
        if member.expected_class == ObservationIdentityClass::Host {
            return Err(SensitiveParamCatalogError::InvalidIdentity);
        }
        let payload = source_emission_receipt_payload(
            self.registry_instance,
            self.boot,
            &record,
            &member,
            handle_table_generation,
            borrowed_high_water,
            settled_high_water,
        )?;
        Ok(VerifiedSourceEmissionQuiesceReceipt {
            registry_instance: self.registry_instance,
            boot: self.boot,
            record,
            member,
            handle_table_generation,
            borrowed_high_water,
            settled_high_water,
            token: issue_private_token(&self.key, SOURCE_EMISSION_RECEIPT_DOMAIN, &payload)?,
        })
    }
}

impl TerminationStateMachineRole {
    pub fn verify_provider_binding(
        &self,
        registry_instance: [u8; 16],
        boot: [u8; 16],
    ) -> Result<(), SensitiveParamCatalogError> {
        if self.registry_instance == registry_instance && self.boot == boot {
            Ok(())
        } else {
            Err(SensitiveParamCatalogError::StaleIdentity)
        }
    }

    pub fn verify_source_emission_quiesce_receipt(
        &self,
        receipt: &VerifiedSourceEmissionQuiesceReceipt,
        expected_record: &TerminationOperationRecord,
        expected_member: &ObservationIdentityClaims,
    ) -> Result<(), SensitiveParamCatalogError> {
        if receipt.registry_instance != self.registry_instance
            || receipt.boot != self.boot
            || receipt.record != *expected_record
            || receipt.member != *expected_member
            || receipt.handle_table_generation == 0
            || receipt.borrowed_high_water == 0
            || receipt.borrowed_high_water != receipt.settled_high_water
        {
            return Err(SensitiveParamCatalogError::InvalidCarrier);
        }
        let payload = source_emission_receipt_payload(
            receipt.registry_instance,
            receipt.boot,
            &receipt.record,
            &receipt.member,
            receipt.handle_table_generation,
            receipt.borrowed_high_water,
            receipt.settled_high_water,
        )?;
        verify_private_token(
            &self.source_emission_key,
            SOURCE_EMISSION_RECEIPT_DOMAIN,
            &payload,
            &receipt.token,
        )
    }

    pub fn verify_grant_subject_drain_token(
        &self,
        receipt: &VerifiedGrantSubjectDrainToken,
        expected_record: &TerminationOperationRecord,
        expected_member: &ObservationIdentityClaims,
    ) -> Result<(), SensitiveParamCatalogError> {
        let receipt = &receipt.0;
        if receipt.tag != 4
            || receipt.registry_instance != self.registry_instance
            || receipt.boot != self.boot
            || receipt.record != *expected_record
            || receipt.member != *expected_member
            || receipt.store_instance_id == [0; 16]
            || receipt.high_water == 0
            || receipt.high_water > i64::MAX as u64
        {
            return Err(SensitiveParamCatalogError::InvalidCarrier);
        }
        let payload = termination_owner_receipt_payload(
            receipt.tag,
            receipt.registry_instance,
            receipt.boot,
            &receipt.record,
            &receipt.member,
            receipt.store_instance_id,
            receipt.high_water,
        )?;
        verify_private_token(
            &self.owner_receipt_key,
            b"advance.contract218.termination-owner-receipt.v1\0",
            &payload,
            &receipt.token,
        )
    }

    /// Verify both mandatory termination-prepare receipt families against the
    /// exact member set and return only authenticated journal metadata.
    pub fn verify_termination_prepare_receipt_sets(
        &self,
        record: &TerminationOperationRecord,
        expected_members: &[ObservationIdentityClaims],
        grants: TerminationGrantSubjectDrainReceiptSet,
        emissions: TerminationSourceEmissionQuiesceReceiptSet,
    ) -> Result<VerifiedTerminationPrepareReceiptSet, SensitiveParamCatalogError> {
        verify_termination_prepare_receipt_sets(
            &self.owner_receipt_key,
            &self.source_emission_key,
            self.registry_instance,
            self.boot,
            record,
            expected_members,
            grants,
            emissions,
        )
    }

    pub fn prepare_committed(
        &self,
        record: TerminationOperationRecord,
    ) -> Result<TerminationPrepareCommitAck, SensitiveParamCatalogError> {
        let bytes = record.canonical_bytes()?;
        Ok(TerminationPrepareCommitAck {
            record,
            token: issue_private_token(
                &self.key,
                b"advance.contract218.termination-prepare-ack.v1\0",
                &bytes,
            )?,
        })
    }

    pub fn prepare_rejected(
        &self,
        record: TerminationOperationRecord,
    ) -> Result<TerminationPrepareFailure, SensitiveParamCatalogError> {
        let bytes = record.canonical_bytes()?;
        Ok(TerminationPrepareFailure::Rejected(
            UncommittedTerminationPrepareProof {
                subject: UncommittedPrepareRejectionSubject::Operation(record),
                token: issue_private_token(
                    &self.key,
                    b"advance.contract218.termination-prepare-rejected.v1\0",
                    &bytes,
                )?,
            },
        ))
    }

    /// Reject an invalid prepare request without manufacturing a committed
    /// operation record.  The raw, potentially empty or over-limit operation
    /// id is reduced to a fixed digest and never retained in the proof.  This
    /// conversion is deliberately infallible so the registrar's typed failure
    /// channel remains total even for malformed caller input.
    pub fn reject_invalid_prepare_request(
        &self,
        operation_id: &str,
        request_digest: [u8; 32],
        current_sequence: u64,
    ) -> TerminationPrepareFailure {
        let subject = InvalidTerminationPrepareRequestRecord {
            operation_id_digest: Sha256::digest(operation_id.as_bytes()).into(),
            request_digest,
            current_sequence,
        };
        let bytes = subject.canonical_bytes();
        TerminationPrepareFailure::Rejected(UncommittedTerminationPrepareProof {
            subject: UncommittedPrepareRejectionSubject::InvalidRequest(subject),
            token: issue_deterministic_private_token(
                &self.key,
                b"advance.contract218.termination-prepare-invalid-request.v1\0",
                &bytes,
            ),
        })
    }

    pub fn prepare_outcome_unknown(
        &self,
        record: TerminationOperationRecord,
    ) -> Result<TerminationPrepareFailure, SensitiveParamCatalogError> {
        let bytes = record.canonical_bytes()?;
        Ok(TerminationPrepareFailure::OutcomeUnknown(
            TerminationPrepareRecoveryHandle {
                record,
                token: issue_private_token(
                    &self.key,
                    b"advance.contract218.termination-prepare-recovery.v1\0",
                    &bytes,
                )?,
            },
        ))
    }

    pub fn inspect_prepare_recovery(
        &self,
        recovery: &TerminationPrepareRecoveryHandle,
    ) -> Result<TerminationOperationRecord, SensitiveParamCatalogError> {
        let bytes = recovery.record.canonical_bytes()?;
        verify_private_token(
            &self.key,
            b"advance.contract218.termination-prepare-recovery.v1\0",
            &bytes,
            &recovery.token,
        )?;
        Ok(recovery.record.clone())
    }

    pub fn resume_prepare(
        &self,
        recovery: TerminationPrepareRecoveryHandle,
    ) -> TerminationOperationRecord {
        recovery.record
    }

    pub fn verify_prepare_ack(
        &self,
        prepared: &TerminationPrepareCommitAck,
    ) -> Result<TerminationOperationRecord, SensitiveParamCatalogError> {
        let bytes = prepared.record.canonical_bytes()?;
        verify_private_token(
            &self.key,
            b"advance.contract218.termination-prepare-ack.v1\0",
            &bytes,
            &prepared.token,
        )?;
        Ok(prepared.record.clone())
    }

    /// Authenticated, non-authorizing digest for binding a durable journal row
    /// to this exact typed prepare acknowledgement.
    pub fn prepare_ack_digest(
        &self,
        prepared: &TerminationPrepareCommitAck,
    ) -> Result<[u8; 32], SensitiveParamCatalogError> {
        let record = self.verify_prepare_ack(prepared)?;
        let bytes = record.canonical_bytes()?;
        Ok(private_token_carrier_digest(
            b"advance.contract218.termination-prepare-ack-carrier.v1\0",
            &bytes,
            &prepared.token,
        ))
    }

    pub fn prepare_ack_nonce(
        &self,
        prepared: &TerminationPrepareCommitAck,
    ) -> Result<[u8; 32], SensitiveParamCatalogError> {
        self.verify_prepare_ack(prepared)?;
        if prepared.token.nonce == [0; 32] {
            return Err(SensitiveParamCatalogError::InvalidCarrier);
        }
        Ok(prepared.token.nonce)
    }

    /// Rehydrate the exact durable prepare acknowledgement after restart.
    /// The caller supplies only the anchor-protected nonce; this role
    /// recomputes the authority MAC under the current operation/boot key.
    pub fn rehydrate_prepare_ack(
        &self,
        record: TerminationOperationRecord,
        prepare_ack_nonce: [u8; 32],
    ) -> Result<TerminationPrepareCommitAck, SensitiveParamCatalogError> {
        let bytes = record.canonical_bytes()?;
        Ok(TerminationPrepareCommitAck {
            record,
            token: issue_private_token_with_nonce(
                &self.key,
                b"advance.contract218.termination-prepare-ack.v1\0",
                &bytes,
                prepare_ack_nonce,
            )?,
        })
    }

    pub fn verify_uncommitted_prepare_rejection(
        &self,
        proof: &UncommittedTerminationPrepareProof,
    ) -> Result<TerminationOperationRecord, SensitiveParamCatalogError> {
        let UncommittedPrepareRejectionSubject::Operation(record) = &proof.subject else {
            return Err(SensitiveParamCatalogError::InvalidIdentity);
        };
        let bytes = record.canonical_bytes()?;
        verify_private_token(
            &self.key,
            b"advance.contract218.termination-prepare-rejected.v1\0",
            &bytes,
            &proof.token,
        )?;
        Ok(record.clone())
    }

    pub fn verify_invalid_prepare_request_rejection(
        &self,
        proof: &UncommittedTerminationPrepareProof,
        operation_id: &str,
        request_digest: [u8; 32],
        current_sequence: u64,
    ) -> Result<(), SensitiveParamCatalogError> {
        let UncommittedPrepareRejectionSubject::InvalidRequest(subject) = &proof.subject else {
            return Err(SensitiveParamCatalogError::InvalidIdentity);
        };
        let expected_operation_id_digest: [u8; 32] = Sha256::digest(operation_id.as_bytes()).into();
        if !bool::from(
            subject
                .operation_id_digest
                .ct_eq(&expected_operation_id_digest),
        ) || !bool::from(subject.request_digest.ct_eq(&request_digest))
            || subject.current_sequence != current_sequence
        {
            return Err(SensitiveParamCatalogError::InvalidIdentity);
        }
        let bytes = subject.canonical_bytes();
        verify_private_token(
            &self.key,
            b"advance.contract218.termination-prepare-invalid-request.v1\0",
            &bytes,
            &proof.token,
        )
    }

    /// Consume both finalize inputs into a sealed, role-verified value before
    /// any database mutation.  Rejection returns both original move-only
    /// values, while success precomputes every token needed by the post-commit
    /// conversions below.
    pub fn verify_finalize_inputs(
        &self,
        prepared: TerminationPrepareCommitAck,
        cleanup: TerminationCleanupCompleteReceipt,
        cleanup_verifier: &TerminationCleanupReceiptVerifierRole,
    ) -> TerminationFinalizeInputVerification {
        let prepared_record = match self.verify_prepare_ack(&prepared) {
            Ok(record) => record,
            Err(_) => return TerminationFinalizeInputVerification::Rejected { prepared, cleanup },
        };
        if cleanup_verifier
            .verify_cleanup_complete(&cleanup, &prepared_record)
            .is_err()
        {
            return TerminationFinalizeInputVerification::Rejected { prepared, cleanup };
        }
        let bytes = match prepared_record.canonical_bytes() {
            Ok(bytes) => bytes,
            Err(_) => return TerminationFinalizeInputVerification::Rejected { prepared, cleanup },
        };
        let committed_token = match issue_private_token(
            &self.key,
            b"advance.contract218.termination-finalize-ack.v1\0",
            &bytes,
        ) {
            Ok(token) => token,
            Err(_) => return TerminationFinalizeInputVerification::Rejected { prepared, cleanup },
        };
        let recovery_token = match issue_private_token(
            &self.key,
            b"advance.contract218.termination-finalize-recovery.v1\0",
            &bytes,
        ) {
            Ok(token) => token,
            Err(_) => return TerminationFinalizeInputVerification::Rejected { prepared, cleanup },
        };
        TerminationFinalizeInputVerification::Verified(VerifiedTerminationFinalizeInputs {
            prepared,
            cleanup,
            committed_ack: TerminationFinalizeCommitAck {
                record: prepared_record,
                token: committed_token,
            },
            recovery_token,
        })
    }

    pub fn finalize_committed(
        &self,
        verified: VerifiedTerminationFinalizeInputs,
    ) -> TerminationFinalizeResult {
        TerminationFinalizeResult::Committed(verified.committed_ack)
    }

    pub fn finalize_rejected(
        &self,
        verified: VerifiedTerminationFinalizeInputs,
    ) -> TerminationFinalizeResult {
        TerminationFinalizeResult::Rejected {
            prepared: verified.prepared,
            cleanup: verified.cleanup,
        }
    }

    pub fn finalize_outcome_unknown(
        &self,
        verified: VerifiedTerminationFinalizeInputs,
    ) -> TerminationFinalizeResult {
        TerminationFinalizeResult::OutcomeUnknown(TerminationFinalizeRecoveryHandle {
            verified: Box::new(verified),
        })
    }

    pub fn finalize_journal_metadata(
        &self,
        verified: &VerifiedTerminationFinalizeInputs,
        cleanup_verifier: &TerminationCleanupReceiptVerifierRole,
    ) -> Result<VerifiedTerminationFinalizeJournalMetadata, SensitiveParamCatalogError> {
        let record = self.verify_prepare_ack(&verified.prepared)?;
        cleanup_verifier.verify_cleanup_complete(&verified.cleanup, &record)?;
        let finalize_record = self.verify_finalize_ack(&verified.committed_ack)?;
        if finalize_record != record {
            return Err(SensitiveParamCatalogError::InvalidCarrier);
        }
        let bytes = record.canonical_bytes()?;
        verify_private_token(
            &self.key,
            b"advance.contract218.termination-finalize-recovery.v1\0",
            &bytes,
            &verified.recovery_token,
        )?;
        let prepare_ack_digest = self.prepare_ack_digest(&verified.prepared)?;
        let prepare_ack_nonce = self.prepare_ack_nonce(&verified.prepared)?;
        let cleanup_receipt_digest =
            cleanup_verifier.cleanup_receipt_digest(&verified.cleanup, &record)?;
        let finalize_ack_digest = private_token_carrier_digest(
            b"advance.contract218.termination-finalize-ack-carrier.v1\0",
            &bytes,
            &verified.committed_ack.token,
        );
        let metadata = VerifiedTerminationFinalizeJournalMetadata {
            prepare_ack_digest,
            prepare_ack_nonce,
            cleanup_receipt_digest,
            cleanup_high_water_digest: verified.cleanup.cleanup_high_water_digest,
            cleanup_receipt_set_digest: verified.cleanup.receipt_set_digest,
            cleanup_nonce: verified.cleanup.token.nonce,
            finalize_recovery_nonce: verified.recovery_token.nonce,
            finalize_ack_digest,
        };
        if metadata.prepare_ack_digest == [0; 32]
            || metadata.prepare_ack_nonce == [0; 32]
            || metadata.cleanup_receipt_digest == [0; 32]
            || metadata.cleanup_high_water_digest == [0; 32]
            || metadata.cleanup_receipt_set_digest == [0; 32]
            || metadata.cleanup_nonce == [0; 32]
            || metadata.finalize_recovery_nonce == [0; 32]
            || metadata.finalize_ack_digest == [0; 32]
        {
            return Err(SensitiveParamCatalogError::InvalidCarrier);
        }
        Ok(metadata)
    }

    pub fn inspect_finalize_recovery(
        &self,
        recovery: &TerminationFinalizeRecoveryHandle,
    ) -> Result<TerminationOperationRecord, SensitiveParamCatalogError> {
        let record = self.verify_prepare_ack(&recovery.verified.prepared)?;
        let bytes = record.canonical_bytes()?;
        verify_private_token(
            &self.key,
            b"advance.contract218.termination-finalize-recovery.v1\0",
            &bytes,
            &recovery.verified.recovery_token,
        )?;
        if recovery.verified.committed_ack.record != record {
            return Err(SensitiveParamCatalogError::InvalidIdentity);
        }
        self.verify_finalize_ack(&recovery.verified.committed_ack)?;
        Ok(record)
    }

    pub fn inspect_finalize_recovery_journal_metadata(
        &self,
        recovery: &TerminationFinalizeRecoveryHandle,
        cleanup_verifier: &TerminationCleanupReceiptVerifierRole,
    ) -> Result<VerifiedTerminationFinalizeJournalMetadata, SensitiveParamCatalogError> {
        self.inspect_finalize_recovery(recovery)?;
        self.finalize_journal_metadata(&recovery.verified, cleanup_verifier)
    }

    pub fn resume_finalize(
        &self,
        recovery: TerminationFinalizeRecoveryHandle,
    ) -> VerifiedTerminationFinalizeInputs {
        *recovery.verified
    }

    pub fn verify_finalize_ack(
        &self,
        ack: &TerminationFinalizeCommitAck,
    ) -> Result<TerminationOperationRecord, SensitiveParamCatalogError> {
        let bytes = ack.record.canonical_bytes()?;
        verify_private_token(
            &self.key,
            b"advance.contract218.termination-finalize-ack.v1\0",
            &bytes,
            &ack.token,
        )?;
        Ok(ack.record.clone())
    }
}

impl TerminationCleanupReceiptIssuerRole {
    pub fn verify_provider_binding(
        &self,
        registry_instance: [u8; 16],
        boot: [u8; 16],
    ) -> Result<(), SensitiveParamCatalogError> {
        if self.registry_instance == registry_instance && self.boot == boot {
            Ok(())
        } else {
            Err(SensitiveParamCatalogError::StaleIdentity)
        }
    }

    /// Consume an exact prepare acknowledgement and the complete six-owner
    /// receipt set.  All owner MACs, operation/boot/member associations,
    /// cardinality, ordering and high-water bindings are verified here before
    /// any cleanup authority is returned.
    pub fn issue_cleanup_complete(
        &self,
        prepared: &TerminationPrepareCommitAck,
        receipts: TerminationCleanupReceiptSet,
    ) -> Result<TerminationCleanupCompleteReceipt, SensitiveParamCatalogError> {
        let record_bytes = prepared.record.canonical_bytes()?;
        verify_private_token(
            &self.prepare_key,
            b"advance.contract218.termination-prepare-ack.v1\0",
            &record_bytes,
            &prepared.token,
        )?;
        let prepare_ack_digest = private_token_carrier_digest(
            b"advance.contract218.termination-prepare-ack-carrier.v1\0",
            &record_bytes,
            &prepared.token,
        );
        let (cleanup_high_water_digest, receipt_set_digest) = verify_cleanup_receipt_set(
            &self.key,
            self.registry_instance,
            self.boot,
            &prepared.record,
            &receipts,
        )?;
        let payload = cleanup_complete_payload(
            self.registry_instance,
            self.boot,
            &prepared.record,
            prepare_ack_digest,
            cleanup_high_water_digest,
            receipt_set_digest,
        )?;
        Ok(TerminationCleanupCompleteReceipt {
            record: prepared.record.clone(),
            prepare_ack_digest,
            cleanup_high_water_digest,
            receipt_set_digest,
            token: issue_private_token(&self.key, TERMINATION_CLEANUP_COMPLETE_DOMAIN, &payload)?,
        })
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn issue_test_cleanup_receipt_set(
        &self,
        record: &TerminationOperationRecord,
        members: &[ObservationIdentityClaims],
        high_water: u64,
    ) -> Result<TerminationCleanupReceiptSet, SensitiveParamCatalogError> {
        if high_water == 0 {
            return Err(SensitiveParamCatalogError::InvalidIdentity);
        }
        let mut sets = Vec::with_capacity(members.len());
        for member in members {
            let issue = |tag: u8| {
                TerminationOwnerReceipt::issue(
                    &self.key,
                    tag,
                    self.registry_instance,
                    self.boot,
                    record.clone(),
                    member.clone(),
                    [tag; 16],
                    high_water,
                )
            };
            sets.push(TerminationMemberCleanupReceiptSet::new(
                VerifiedLiveHandleAbsenceReceipt(issue(1)?),
                VerifiedRunStoppedReceipt(issue(2)?),
                VerifiedMailboxClosedAndEmptyReceipt(issue(3)?),
                VerifiedGrantSubjectDrainToken(issue(4)?),
                VerifiedWorkspaceDispositionReceipt(issue(5)?),
                VerifiedTreeNodeRemovedReceipt(issue(6)?),
            ));
        }
        Ok(TerminationCleanupReceiptSet::new(sets))
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn issue_test_grant_subject_drain_set(
        &self,
        record: &TerminationOperationRecord,
        members: &[ObservationIdentityClaims],
        high_water: u64,
    ) -> Result<TerminationGrantSubjectDrainReceiptSet, SensitiveParamCatalogError> {
        if high_water == 0 || high_water > i64::MAX as u64 {
            return Err(SensitiveParamCatalogError::InvalidIdentity);
        }
        let mut receipts = Vec::with_capacity(members.len());
        for member in members {
            receipts.push(VerifiedGrantSubjectDrainToken(
                TerminationOwnerReceipt::issue(
                    &self.key,
                    4,
                    self.registry_instance,
                    self.boot,
                    record.clone(),
                    member.clone(),
                    [4; 16],
                    high_water,
                )?,
            ));
        }
        Ok(TerminationGrantSubjectDrainReceiptSet::new(receipts))
    }
}

impl TerminationCleanupReceiptVerifierRole {
    pub fn verify_provider_binding(
        &self,
        registry_instance: [u8; 16],
        boot: [u8; 16],
    ) -> Result<(), SensitiveParamCatalogError> {
        if self.registry_instance == registry_instance && self.boot == boot {
            Ok(())
        } else {
            Err(SensitiveParamCatalogError::StaleIdentity)
        }
    }

    pub fn verify_cleanup_complete(
        &self,
        receipt: &TerminationCleanupCompleteReceipt,
        expected: &TerminationOperationRecord,
    ) -> Result<(), SensitiveParamCatalogError> {
        if self.registry_instance == [0; 16] || self.boot == [0; 16] || receipt.record != *expected
        {
            return Err(SensitiveParamCatalogError::InvalidCarrier);
        }
        let payload = cleanup_complete_payload(
            self.registry_instance,
            self.boot,
            &receipt.record,
            receipt.prepare_ack_digest,
            receipt.cleanup_high_water_digest,
            receipt.receipt_set_digest,
        )?;
        verify_private_token(
            &self.key,
            TERMINATION_CLEANUP_COMPLETE_DOMAIN,
            &payload,
            &receipt.token,
        )
    }

    /// Authenticated, non-authorizing digest for binding a durable journal row
    /// to this exact cleanup receipt.
    pub fn cleanup_receipt_digest(
        &self,
        receipt: &TerminationCleanupCompleteReceipt,
        expected: &TerminationOperationRecord,
    ) -> Result<[u8; 32], SensitiveParamCatalogError> {
        self.verify_cleanup_complete(receipt, expected)?;
        let payload = cleanup_complete_payload(
            self.registry_instance,
            self.boot,
            &receipt.record,
            receipt.prepare_ack_digest,
            receipt.cleanup_high_water_digest,
            receipt.receipt_set_digest,
        )?;
        Ok(private_token_carrier_digest(
            b"advance.contract218.termination-cleanup-digest.v1\0",
            &payload,
            &receipt.token,
        ))
    }
}

/// Private authenticated nonce/MAC carrier used by every opaque receipt.
struct PrivateToken {
    nonce: [u8; 32],
    mac: [u8; 32],
}

impl TerminationOwnerReceipt {
    #[allow(clippy::too_many_arguments)]
    fn issue(
        key: &[u8; 32],
        tag: u8,
        registry_instance: [u8; 16],
        boot: [u8; 16],
        record: TerminationOperationRecord,
        member: ObservationIdentityClaims,
        store_instance_id: [u8; 16],
        high_water: u64,
    ) -> Result<Self, SensitiveParamCatalogError> {
        if !(1..=6).contains(&tag)
            || registry_instance == [0; 16]
            || boot == [0; 16]
            || store_instance_id == [0; 16]
            || high_water == 0
            || high_water > i64::MAX as u64
            || member.expected_class == ObservationIdentityClass::Host
        {
            return Err(SensitiveParamCatalogError::InvalidIdentity);
        }
        member.validate()?;
        let payload = termination_owner_receipt_payload(
            tag,
            registry_instance,
            boot,
            &record,
            &member,
            store_instance_id,
            high_water,
        )?;
        Ok(Self {
            tag,
            registry_instance,
            boot,
            record,
            member,
            store_instance_id,
            high_water,
            token: issue_private_token(
                key,
                b"advance.contract218.termination-owner-receipt.v1\0",
                &payload,
            )?,
        })
    }
}

impl RetainedGcOwnerReceipt {
    #[allow(clippy::too_many_arguments)]
    fn issue(
        key: &[u8; 32],
        tag: u8,
        registry_instance: [u8; 16],
        operation_boot: [u8; 16],
        record: TerminationOperationRecord,
        tombstone_state_root: [u8; 32],
        gc_generation: u64,
        challenge_nonce: [u8; 32],
        store_instance_id: [u8; 16],
        high_water: u64,
        state_root: [u8; 32],
    ) -> Result<Self, SensitiveParamCatalogError> {
        let payload = retained_gc_owner_payload(
            tag,
            registry_instance,
            operation_boot,
            &record,
            tombstone_state_root,
            gc_generation,
            challenge_nonce,
            store_instance_id,
            high_water,
            state_root,
        )?;
        Ok(Self {
            tag,
            registry_instance,
            operation_boot,
            record,
            tombstone_state_root,
            gc_generation,
            challenge_nonce,
            store_instance_id,
            high_water,
            state_root,
            token: issue_private_token(key, RETAINED_GC_OWNER_RECEIPT_DOMAIN, &payload)?,
        })
    }
}

impl PersistedKeyOwnerScanReceipt {
    #[allow(clippy::too_many_arguments)]
    fn issue(
        key: &[u8; 32],
        tag: u8,
        challenge: &PersistedKeyRetirementChallenge,
        challenge_nonce: [u8; 32],
        store_instance_id: [u8; 16],
        high_water: u64,
        state_root: [u8; 32],
        inventory_digest: [u8; 32],
        segment_count: u64,
        byte_count: u64,
        retention_high_water: u64,
    ) -> Result<Self, SensitiveParamCatalogError> {
        let mut receipt = Self {
            tag,
            registry_instance: challenge.registry_instance,
            boot: challenge.boot,
            operation_id: challenge.operation_id.clone(),
            keyring_root: challenge.keyring_root,
            keyring_generation: challenge.keyring_generation,
            key_id: challenge.key_id,
            migration_generation: challenge.migration_generation,
            challenge_nonce,
            store_instance_id,
            high_water,
            state_root,
            inventory_digest,
            segment_count,
            byte_count,
            retention_high_water,
            token: PrivateToken {
                nonce: [0; 32],
                mac: [0; 32],
            },
        };
        let payload = key_retirement_owner_scan_payload(&receipt)?;
        receipt.token = issue_private_token(key, KEY_RETIREMENT_OWNER_SCAN_DOMAIN, &payload)?;
        Ok(receipt)
    }
}

fn validate_owner_scan_fields(
    tag: u8,
    store_instance_id: [u8; 16],
    high_water: u64,
    state_root: [u8; 32],
) -> Result<(), SensitiveParamCatalogError> {
    if store_instance_id == [0; 16]
        || high_water == 0
        || high_water > i64::MAX as u64
        || state_root == [0; 32]
        || tag == 0
    {
        return Err(SensitiveParamCatalogError::InvalidIdentity);
    }
    Ok(())
}

fn retained_gc_challenge_payload(
    registry_instance: [u8; 16],
    operation_boot: [u8; 16],
    record: &TerminationOperationRecord,
    tombstone_state_root: [u8; 32],
    gc_generation: u64,
) -> Result<Vec<u8>, SensitiveParamCatalogError> {
    if registry_instance == [0; 16]
        || operation_boot == [0; 16]
        || tombstone_state_root == [0; 32]
        || gc_generation == 0
        || gc_generation > i64::MAX as u64
    {
        return Err(SensitiveParamCatalogError::InvalidIdentity);
    }
    let record_bytes = record.canonical_bytes()?;
    let mut payload = Vec::with_capacity(record_bytes.len() + 77);
    payload.push(1);
    payload.extend_from_slice(&registry_instance);
    payload.extend_from_slice(&operation_boot);
    payload.extend_from_slice(&(record_bytes.len() as u32).to_be_bytes());
    payload.extend_from_slice(&record_bytes);
    payload.extend_from_slice(&tombstone_state_root);
    payload.extend_from_slice(&gc_generation.to_be_bytes());
    Ok(payload)
}

#[allow(clippy::too_many_arguments)]
fn c123_purpose2_zero_payload(
    registry_instance: [u8; 16],
    operation_boot: [u8; 16],
    record: &TerminationOperationRecord,
    tombstone_state_root: [u8; 32],
    gc_generation: u64,
    challenge_nonce: [u8; 32],
    store_instance_id: [u8; 16],
    high_water: u64,
    state_root: [u8; 32],
) -> Result<Vec<u8>, SensitiveParamCatalogError> {
    validate_owner_scan_fields(2, store_instance_id, high_water, state_root)?;
    if challenge_nonce == [0; 32] {
        return Err(SensitiveParamCatalogError::InvalidIdentity);
    }
    let mut payload = retained_gc_challenge_payload(
        registry_instance,
        operation_boot,
        record,
        tombstone_state_root,
        gc_generation,
    )?;
    payload.push(2);
    payload.extend_from_slice(&challenge_nonce);
    payload.extend_from_slice(&store_instance_id);
    payload.extend_from_slice(&high_water.to_be_bytes());
    payload.extend_from_slice(&state_root);
    // The C123 purpose-2 reference count is fixed to authenticated zero.
    payload.extend_from_slice(&0u64.to_be_bytes());
    Ok(payload)
}

#[allow(clippy::too_many_arguments)]
fn retained_gc_owner_payload(
    tag: u8,
    registry_instance: [u8; 16],
    operation_boot: [u8; 16],
    record: &TerminationOperationRecord,
    tombstone_state_root: [u8; 32],
    gc_generation: u64,
    challenge_nonce: [u8; 32],
    store_instance_id: [u8; 16],
    high_water: u64,
    state_root: [u8; 32],
) -> Result<Vec<u8>, SensitiveParamCatalogError> {
    if !(1..=5).contains(&tag) || challenge_nonce == [0; 32] {
        return Err(SensitiveParamCatalogError::InvalidIdentity);
    }
    validate_owner_scan_fields(tag, store_instance_id, high_water, state_root)?;
    let mut payload = retained_gc_challenge_payload(
        registry_instance,
        operation_boot,
        record,
        tombstone_state_root,
        gc_generation,
    )?;
    payload.push(tag);
    payload.extend_from_slice(&challenge_nonce);
    payload.extend_from_slice(&store_instance_id);
    payload.extend_from_slice(&high_water.to_be_bytes());
    payload.extend_from_slice(&state_root);
    // Every owner receipt proves an exhaustive zero-reference result.
    payload.extend_from_slice(&0u64.to_be_bytes());
    Ok(payload)
}

fn key_retirement_challenge_payload(
    registry_instance: [u8; 16],
    boot: [u8; 16],
    operation_id: &str,
    keyring_root: [u8; 32],
    keyring_generation: u64,
    key_id: u32,
    migration_generation: u64,
) -> Result<Vec<u8>, SensitiveParamCatalogError> {
    if registry_instance == [0; 16]
        || boot == [0; 16]
        || keyring_root == [0; 32]
        || keyring_generation > i64::MAX as u64
        || key_id == 0
        || migration_generation == 0
        || migration_generation > i64::MAX as u64
    {
        return Err(SensitiveParamCatalogError::InvalidIdentity);
    }
    let mut payload = Vec::with_capacity(operation_id.len() + 89);
    payload.push(1);
    payload.extend_from_slice(&registry_instance);
    payload.extend_from_slice(&boot);
    put_text(&mut payload, operation_id)?;
    payload.extend_from_slice(&keyring_root);
    payload.extend_from_slice(&keyring_generation.to_be_bytes());
    payload.extend_from_slice(&key_id.to_be_bytes());
    payload.extend_from_slice(&migration_generation.to_be_bytes());
    Ok(payload)
}

fn key_retirement_owner_scan_payload(
    receipt: &PersistedKeyOwnerScanReceipt,
) -> Result<Vec<u8>, SensitiveParamCatalogError> {
    if !(1..=3).contains(&receipt.tag) || receipt.challenge_nonce == [0; 32] {
        return Err(SensitiveParamCatalogError::InvalidIdentity);
    }
    validate_owner_scan_fields(
        receipt.tag,
        receipt.store_instance_id,
        receipt.high_water,
        receipt.state_root,
    )?;
    match receipt.tag {
        1 | 3
            if receipt.inventory_digest != [0; 32]
                || receipt.segment_count != 0
                || receipt.byte_count != 0
                || receipt.retention_high_water != 0 =>
        {
            return Err(SensitiveParamCatalogError::InvalidIdentity)
        }
        2 if receipt.inventory_digest == [0; 32]
            || receipt.retention_high_water == 0
            || (receipt.segment_count == 0) != (receipt.byte_count == 0) =>
        {
            return Err(SensitiveParamCatalogError::InvalidIdentity)
        }
        _ => {}
    }
    let mut payload = key_retirement_challenge_payload(
        receipt.registry_instance,
        receipt.boot,
        &receipt.operation_id,
        receipt.keyring_root,
        receipt.keyring_generation,
        receipt.key_id,
        receipt.migration_generation,
    )?;
    payload.push(receipt.tag);
    payload.extend_from_slice(&receipt.challenge_nonce);
    payload.extend_from_slice(&receipt.store_instance_id);
    payload.extend_from_slice(&receipt.high_water.to_be_bytes());
    payload.extend_from_slice(&receipt.state_root);
    payload.extend_from_slice(&receipt.inventory_digest);
    payload.extend_from_slice(&receipt.segment_count.to_be_bytes());
    payload.extend_from_slice(&receipt.byte_count.to_be_bytes());
    payload.extend_from_slice(&receipt.retention_high_water.to_be_bytes());
    // Complete scans carry an authenticated zero matching-reference count.
    payload.extend_from_slice(&0u64.to_be_bytes());
    Ok(payload)
}

fn canonical_termination_member(
    member: &ObservationIdentityClaims,
) -> Result<Vec<u8>, SensitiveParamCatalogError> {
    member.validate()?;
    if member.expected_class == ObservationIdentityClass::Host {
        return Err(SensitiveParamCatalogError::InvalidIdentity);
    }
    let mut bytes = Vec::with_capacity(member.exact_id.len() + 45);
    put_text(&mut bytes, &member.exact_id)?;
    bytes.push(member.expected_class.tag());
    bytes.extend_from_slice(&member.incarnation.to_be_bytes());
    bytes.extend_from_slice(member.declaration_digest.as_bytes());
    Ok(bytes)
}

/// Canonical non-authorizing member-set digest used to build a termination
/// operation record.  Supplying this digest alone never creates authority.
pub fn termination_member_set_digest(
    members: &[ObservationIdentityClaims],
) -> Result<[u8; 32], SensitiveParamCatalogError> {
    if members.is_empty() || members.len() > 4096 {
        return Err(SensitiveParamCatalogError::CapacityExceeded);
    }
    let mut canonical = members
        .iter()
        .map(canonical_termination_member)
        .collect::<Result<Vec<_>, _>>()?;
    canonical.sort();
    if canonical.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(SensitiveParamCatalogError::InvalidIdentity);
    }
    Ok(termination_member_set_digest_from_sorted(&canonical))
}

fn termination_member_set_digest_from_sorted(canonical: &[Vec<u8>]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"advance.contract123.member-set.v1\0");
    digest.update((canonical.len() as u32).to_be_bytes());
    for member in canonical {
        digest.update(member);
    }
    digest.finalize().into()
}

fn termination_owner_receipt_payload(
    tag: u8,
    registry_instance: [u8; 16],
    boot: [u8; 16],
    record: &TerminationOperationRecord,
    member: &ObservationIdentityClaims,
    store_instance_id: [u8; 16],
    high_water: u64,
) -> Result<Vec<u8>, SensitiveParamCatalogError> {
    let record_bytes = record.canonical_bytes()?;
    let member_bytes = canonical_termination_member(member)?;
    let mut bytes = Vec::with_capacity(record_bytes.len() + member_bytes.len() + 61);
    bytes.push(1);
    bytes.push(tag);
    bytes.extend_from_slice(&registry_instance);
    bytes.extend_from_slice(&boot);
    bytes.extend_from_slice(&(record_bytes.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&record_bytes);
    bytes.extend_from_slice(&(member_bytes.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&member_bytes);
    bytes.extend_from_slice(&store_instance_id);
    bytes.extend_from_slice(&high_water.to_be_bytes());
    Ok(bytes)
}

fn source_emission_receipt_payload(
    registry_instance: [u8; 16],
    boot: [u8; 16],
    record: &TerminationOperationRecord,
    member: &ObservationIdentityClaims,
    handle_table_generation: u64,
    borrowed_high_water: u64,
    settled_high_water: u64,
) -> Result<Vec<u8>, SensitiveParamCatalogError> {
    let record_bytes = record.canonical_bytes()?;
    let member_bytes = canonical_termination_member(member)?;
    let mut bytes = Vec::with_capacity(record_bytes.len() + member_bytes.len() + 73);
    bytes.push(1);
    bytes.extend_from_slice(&boot);
    bytes.extend_from_slice(&registry_instance);
    bytes.extend_from_slice(&(record_bytes.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&record_bytes);
    bytes.extend_from_slice(&(member_bytes.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&member_bytes);
    bytes.extend_from_slice(&handle_table_generation.to_be_bytes());
    bytes.extend_from_slice(&borrowed_high_water.to_be_bytes());
    bytes.extend_from_slice(&settled_high_water.to_be_bytes());
    // `live_lease_count` is fixed at zero and is authenticated explicitly.
    bytes.extend_from_slice(&0u64.to_be_bytes());
    Ok(bytes)
}

#[allow(clippy::too_many_arguments)]
fn verify_termination_prepare_receipt_sets(
    owner_receipt_key: &[u8; 32],
    source_emission_key: &[u8; 32],
    registry_instance: [u8; 16],
    boot: [u8; 16],
    record: &TerminationOperationRecord,
    expected_members: &[ObservationIdentityClaims],
    grants: TerminationGrantSubjectDrainReceiptSet,
    emissions: TerminationSourceEmissionQuiesceReceiptSet,
) -> Result<VerifiedTerminationPrepareReceiptSet, SensitiveParamCatalogError> {
    let record_bytes = record.canonical_bytes()?;
    let expected_member_set_digest = termination_member_set_digest(expected_members)?;
    if !bool::from(expected_member_set_digest.ct_eq(&record.member_set_digest))
        || grants.receipts.len() != expected_members.len()
        || emissions.receipts.len() != expected_members.len()
    {
        return Err(SensitiveParamCatalogError::InvalidCarrier);
    }
    let mut expected = expected_members
        .iter()
        .map(|member| Ok((canonical_termination_member(member)?, member.clone())))
        .collect::<Result<Vec<_>, _>>()?;
    expected.sort_by(|left, right| left.0.cmp(&right.0));

    let mut verified_grants = Vec::with_capacity(grants.receipts.len());
    for grant in grants.receipts {
        let receipt = grant.0;
        if receipt.tag != 4
            || receipt.registry_instance != registry_instance
            || receipt.boot != boot
            || receipt.record != *record
            || receipt.store_instance_id == [0; 16]
            || receipt.high_water == 0
            || receipt.high_water > i64::MAX as u64
        {
            return Err(SensitiveParamCatalogError::InvalidCarrier);
        }
        let canonical = canonical_termination_member(&receipt.member)?;
        let payload = termination_owner_receipt_payload(
            receipt.tag,
            receipt.registry_instance,
            receipt.boot,
            &receipt.record,
            &receipt.member,
            receipt.store_instance_id,
            receipt.high_water,
        )?;
        verify_private_token(
            owner_receipt_key,
            b"advance.contract218.termination-owner-receipt.v1\0",
            &payload,
            &receipt.token,
        )?;
        verified_grants.push((
            canonical,
            private_token_carrier_digest(
                b"advance.contract218.termination-grant-subject-drain-digest.v1\0",
                &payload,
                &receipt.token,
            ),
        ));
    }

    let mut verified_emissions = Vec::with_capacity(emissions.receipts.len());
    for receipt in emissions.receipts {
        if receipt.registry_instance != registry_instance
            || receipt.boot != boot
            || receipt.record != *record
            || receipt.handle_table_generation == 0
            || receipt.borrowed_high_water == 0
            || receipt.borrowed_high_water != receipt.settled_high_water
        {
            return Err(SensitiveParamCatalogError::InvalidCarrier);
        }
        let canonical = canonical_termination_member(&receipt.member)?;
        let payload = source_emission_receipt_payload(
            receipt.registry_instance,
            receipt.boot,
            &receipt.record,
            &receipt.member,
            receipt.handle_table_generation,
            receipt.borrowed_high_water,
            receipt.settled_high_water,
        )?;
        verify_private_token(
            source_emission_key,
            SOURCE_EMISSION_RECEIPT_DOMAIN,
            &payload,
            &receipt.token,
        )?;
        verified_emissions.push((
            canonical,
            private_token_carrier_digest(
                b"advance.contract218.termination-source-emission-digest.v1\0",
                &payload,
                &receipt.token,
            ),
        ));
    }

    verified_grants.sort_by(|left, right| left.0.cmp(&right.0));
    verified_emissions.sort_by(|left, right| left.0.cmp(&right.0));
    if verified_grants
        .windows(2)
        .any(|pair| pair[0].0 == pair[1].0)
        || verified_emissions
            .windows(2)
            .any(|pair| pair[0].0 == pair[1].0)
        || verified_grants
            .iter()
            .map(|item| &item.0)
            .ne(expected.iter().map(|item| &item.0))
        || verified_emissions
            .iter()
            .map(|item| &item.0)
            .ne(expected.iter().map(|item| &item.0))
    {
        return Err(SensitiveParamCatalogError::InvalidCarrier);
    }

    let family_digest = |domain: &[u8], verified: &[(Vec<u8>, [u8; 32])]| {
        let mut hasher = Sha256::new();
        hasher.update(domain);
        hasher.update(registry_instance);
        hasher.update(boot);
        hasher.update((record_bytes.len() as u32).to_be_bytes());
        hasher.update(&record_bytes);
        hasher.update((verified.len() as u32).to_be_bytes());
        for (member, receipt_digest) in verified {
            hasher.update((member.len() as u32).to_be_bytes());
            hasher.update(member);
            hasher.update(receipt_digest);
        }
        <[u8; 32]>::from(hasher.finalize())
    };
    let grant_subject_drain_receipt_set_digest = family_digest(
        b"advance.contract218.termination-grant-subject-drain-set.v1\0",
        &verified_grants,
    );
    let source_emission_quiesce_receipt_set_digest = family_digest(
        b"advance.contract218.termination-source-emission-set.v1\0",
        &verified_emissions,
    );
    let mut aggregate = Sha256::new();
    aggregate.update(b"advance.contract218.termination-prepare-receipt-set.v1\0");
    aggregate.update(&record_bytes);
    aggregate.update(grant_subject_drain_receipt_set_digest);
    aggregate.update(source_emission_quiesce_receipt_set_digest);
    let member_count =
        u32::try_from(expected.len()).map_err(|_| SensitiveParamCatalogError::CapacityExceeded)?;
    let members = expected
        .into_iter()
        .zip(verified_grants.iter().zip(verified_emissions.iter()))
        .map(|((_, member), ((_, grant_digest), (_, emission_digest)))| {
            VerifiedTerminationPrepareMemberReceiptMetadata {
                member,
                grant_subject_drain_receipt_digest: *grant_digest,
                source_emission_quiesce_receipt_digest: *emission_digest,
            }
        })
        .collect();
    Ok(VerifiedTerminationPrepareReceiptSet {
        metadata: VerifiedTerminationPrepareReceiptMetadata {
            registry_instance,
            boot,
            operation_id: record.operation_id.clone(),
            member_set_digest: record.member_set_digest,
            registry_sequence: record.registry_sequence,
            member_count,
            grant_subject_drain_receipt_set_digest,
            source_emission_quiesce_receipt_set_digest,
            aggregate_receipt_set_digest: aggregate.finalize().into(),
            members,
        },
    })
}

fn cleanup_complete_payload(
    registry_instance: [u8; 16],
    boot: [u8; 16],
    record: &TerminationOperationRecord,
    prepare_ack_digest: [u8; 32],
    cleanup_high_water_digest: [u8; 32],
    receipt_set_digest: [u8; 32],
) -> Result<Vec<u8>, SensitiveParamCatalogError> {
    let mut bytes = Vec::with_capacity(record.operation_id.len() + 177);
    bytes.push(1);
    bytes.extend_from_slice(&boot);
    bytes.extend_from_slice(&registry_instance);
    put_text(&mut bytes, &record.operation_id)?;
    bytes.extend_from_slice(&prepare_ack_digest);
    bytes.extend_from_slice(&record.member_set_digest);
    bytes.extend_from_slice(&cleanup_high_water_digest);
    bytes.extend_from_slice(&receipt_set_digest);
    bytes.extend_from_slice(&record.registry_sequence.to_be_bytes());
    Ok(bytes)
}

fn verify_cleanup_receipt_set(
    key: &[u8; 32],
    registry_instance: [u8; 16],
    boot: [u8; 16],
    record: &TerminationOperationRecord,
    receipt_set: &TerminationCleanupReceiptSet,
) -> Result<([u8; 32], [u8; 32]), SensitiveParamCatalogError> {
    if receipt_set.members.is_empty() || receipt_set.members.len() > 4096 {
        return Err(SensitiveParamCatalogError::CapacityExceeded);
    }

    struct VerifiedMember {
        canonical: Vec<u8>,
        receipt_digests: [[u8; 32]; 6],
        high_waters: [([u8; 16], u64); 6],
    }

    let mut verified_members = Vec::with_capacity(receipt_set.members.len());
    for member_set in &receipt_set.members {
        let receipts = member_set.receipts();
        let expected_member = &receipts[0].member;
        let canonical = canonical_termination_member(expected_member)?;
        let mut receipt_digests = [[0u8; 32]; 6];
        let mut high_waters = [([0u8; 16], 0u64); 6];
        for (index, receipt) in receipts.into_iter().enumerate() {
            let expected_tag = (index + 1) as u8;
            if receipt.tag != expected_tag
                || receipt.registry_instance != registry_instance
                || receipt.boot != boot
                || receipt.record != *record
                || receipt.member != *expected_member
                || receipt.store_instance_id == [0; 16]
                || receipt.high_water == 0
                || receipt.high_water > i64::MAX as u64
            {
                return Err(SensitiveParamCatalogError::InvalidCarrier);
            }
            let payload = termination_owner_receipt_payload(
                receipt.tag,
                receipt.registry_instance,
                receipt.boot,
                &receipt.record,
                &receipt.member,
                receipt.store_instance_id,
                receipt.high_water,
            )?;
            verify_private_token(
                key,
                b"advance.contract218.termination-owner-receipt.v1\0",
                &payload,
                &receipt.token,
            )?;
            receipt_digests[index] = private_token_carrier_digest(
                b"advance.contract218.termination-owner-receipt-digest.v1\0",
                &payload,
                &receipt.token,
            );
            high_waters[index] = (receipt.store_instance_id, receipt.high_water);
        }
        verified_members.push(VerifiedMember {
            canonical,
            receipt_digests,
            high_waters,
        });
    }

    verified_members.sort_by(|left, right| left.canonical.cmp(&right.canonical));
    if verified_members
        .windows(2)
        .any(|pair| pair[0].canonical == pair[1].canonical)
    {
        return Err(SensitiveParamCatalogError::InvalidIdentity);
    }
    let canonical_members = verified_members
        .iter()
        .map(|member| member.canonical.clone())
        .collect::<Vec<_>>();
    let member_set_digest = termination_member_set_digest_from_sorted(&canonical_members);
    if !bool::from(member_set_digest.ct_eq(&record.member_set_digest)) {
        return Err(SensitiveParamCatalogError::InvalidCarrier);
    }

    let mut receipt_set_bytes = Vec::new();
    receipt_set_bytes
        .extend_from_slice(b"advance.contract218.termination-cleanup-receipt-set.v1\0");
    receipt_set_bytes.extend_from_slice(&(verified_members.len() as u32).to_be_bytes());
    let mut high_water_bytes = Vec::new();
    high_water_bytes.extend_from_slice(b"advance.contract218.termination-cleanup-high-waters.v1\0");
    high_water_bytes.extend_from_slice(&(verified_members.len() as u32).to_be_bytes());
    for member in &verified_members {
        let member_len = u32::try_from(member.canonical.len())
            .map_err(|_| SensitiveParamCatalogError::CapacityExceeded)?;
        receipt_set_bytes.extend_from_slice(&member_len.to_be_bytes());
        receipt_set_bytes.extend_from_slice(&member.canonical);
        receipt_set_bytes.push(6);
        high_water_bytes.extend_from_slice(&member_len.to_be_bytes());
        high_water_bytes.extend_from_slice(&member.canonical);
        for index in 0..6 {
            let tag = (index + 1) as u8;
            receipt_set_bytes.push(tag);
            receipt_set_bytes.extend_from_slice(&member.receipt_digests[index]);
            high_water_bytes.push(tag);
            high_water_bytes.extend_from_slice(&member.high_waters[index].0);
            high_water_bytes.extend_from_slice(&member.high_waters[index].1.to_be_bytes());
        }
    }
    Ok((
        Sha256::digest(high_water_bytes).into(),
        Sha256::digest(receipt_set_bytes).into(),
    ))
}

fn role_salt(registry_instance: [u8; 16], boot: [u8; 16]) -> [u8; 32] {
    let mut salt = [0; 32];
    // MODULE-014 pins previsible-family derivation to boot || registry.
    salt[..16].copy_from_slice(&boot);
    salt[16..].copy_from_slice(&registry_instance);
    salt
}

fn derive_key(
    root: &[u8; 32],
    salt: &[u8; 32],
    info: &[u8],
) -> Result<[u8; 32], SensitiveParamCatalogError> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), root);
    let mut key = [0; 32];
    hkdf.expand(info, &mut key)
        .map_err(|_| SensitiveParamCatalogError::InvalidIdentity)?;
    Ok(key)
}

fn fresh_nonzero_32() -> Result<[u8; 32], SensitiveParamCatalogError> {
    for _ in 0..8 {
        let mut value = [0; 32];
        OsRng.fill_bytes(&mut value);
        if value != [0; 32] {
            return Ok(value);
        }
    }
    Err(SensitiveParamCatalogError::StorageUnavailable)
}

fn issue_private_token(
    key: &[u8; 32],
    domain: &[u8],
    payload: &[u8],
) -> Result<PrivateToken, SensitiveParamCatalogError> {
    let nonce = fresh_nonzero_32()?;
    issue_private_token_with_nonce(key, domain, payload, nonce)
}

fn issue_private_token_with_nonce(
    key: &[u8; 32],
    domain: &[u8],
    payload: &[u8],
    nonce: [u8; 32],
) -> Result<PrivateToken, SensitiveParamCatalogError> {
    if nonce == [0; 32] {
        return Err(SensitiveParamCatalogError::InvalidCarrier);
    }
    let mut authenticated = Vec::with_capacity(payload.len() + nonce.len());
    authenticated.extend_from_slice(payload);
    authenticated.extend_from_slice(&nonce);
    let mac = compute_hmac(key, domain, &authenticated)?;
    Ok(PrivateToken { nonce, mac })
}

fn issue_deterministic_private_token(
    key: &[u8; 32],
    domain: &[u8],
    payload: &[u8],
) -> PrivateToken {
    let mut nonce_hasher = Sha256::new();
    nonce_hasher.update(b"advance.contract218.deterministic-proof-nonce.v1\0");
    nonce_hasher.update(domain);
    nonce_hasher.update(payload);
    let mut nonce: [u8; 32] = nonce_hasher.finalize().into();
    nonce[0] |= 1;

    let mut authenticated = Vec::with_capacity(payload.len() + nonce.len());
    authenticated.extend_from_slice(payload);
    authenticated.extend_from_slice(&nonce);
    let mac = fixed_key_hmac_sha256(key, domain, &authenticated);
    PrivateToken { nonce, mac }
}

/// HMAC-SHA256 for an exact 32-byte key.  Its fixed key width makes the
/// construction infallible; the zero padding below is the standard HMAC key
/// normalization for a key shorter than SHA-256's 64-byte block.
fn fixed_key_hmac_sha256(key: &[u8; 32], domain: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut inner_pad = [0x36; 64];
    let mut outer_pad = [0x5c; 64];
    for (index, byte) in key.iter().enumerate() {
        inner_pad[index] ^= byte;
        outer_pad[index] ^= byte;
    }

    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(domain);
    inner.update(payload);
    let inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner_digest);
    outer.finalize().into()
}

fn sha256_with_domain(domain: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(payload);
    digest.finalize().into()
}

fn private_token_carrier_digest(domain: &[u8], payload: &[u8], token: &PrivateToken) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update((payload.len() as u64).to_be_bytes());
    digest.update(payload);
    digest.update(token.nonce);
    digest.update(token.mac);
    digest.finalize().into()
}

fn verify_private_token(
    key: &[u8; 32],
    domain: &[u8],
    payload: &[u8],
    token: &PrivateToken,
) -> Result<(), SensitiveParamCatalogError> {
    let mut authenticated = Vec::with_capacity(payload.len() + token.nonce.len());
    authenticated.extend_from_slice(payload);
    authenticated.extend_from_slice(&token.nonce);
    verify_hmac(key, domain, &authenticated, &token.mac)
}

fn put_claims(
    out: &mut Vec<u8>,
    claims: &ObservationIdentityClaims,
) -> Result<(), SensitiveParamCatalogError> {
    claims.validate()?;
    put_text(out, &claims.exact_id)?;
    out.push(claims.expected_class.tag());
    out.extend_from_slice(&claims.incarnation.to_be_bytes());
    out.extend_from_slice(claims.declaration_digest.as_bytes());
    Ok(())
}

fn source_handle_payload(
    registry_instance: [u8; 16],
    boot: [u8; 16],
    claims: &ObservationIdentityClaims,
) -> Result<Vec<u8>, SensitiveParamCatalogError> {
    let mut payload = Vec::with_capacity(96 + claims.exact_id.len());
    payload.extend_from_slice(&registry_instance);
    payload.extend_from_slice(&boot);
    put_claims(&mut payload, claims)?;
    Ok(payload)
}

fn trusted_identity_payload(
    registry_instance: [u8; 16],
    claims: &ObservationIdentityClaims,
    scope: &ObservationAuthorityScope,
) -> Result<Vec<u8>, SensitiveParamCatalogError> {
    let mut payload = Vec::with_capacity(160 + claims.exact_id.len());
    payload.extend_from_slice(&registry_instance);
    put_claims(&mut payload, claims)?;
    match scope {
        ObservationAuthorityScope::Live { boot } => {
            payload.push(1);
            payload.extend_from_slice(boot);
        }
        ObservationAuthorityScope::Persisted {
            event_id,
            cursor,
            safe_event_digest,
        } => {
            payload.push(2);
            put_text(&mut payload, event_id)?;
            put_text(&mut payload, cursor)?;
            payload.extend_from_slice(safe_event_digest);
        }
    }
    Ok(payload)
}

fn committed_receipt_payload(
    claims: &ObservationIdentityClaims,
    operation_id: &str,
    registry_sequence: u64,
) -> Result<Vec<u8>, SensitiveParamCatalogError> {
    let mut payload = Vec::with_capacity(96 + claims.exact_id.len() + operation_id.len());
    put_text(&mut payload, operation_id)?;
    put_claims(&mut payload, claims)?;
    payload.extend_from_slice(&registry_sequence.to_be_bytes());
    Ok(payload)
}

fn publication_ack_payload(
    record: &ProviderActivationRecord,
) -> Result<Vec<u8>, SensitiveParamCatalogError> {
    let mut payload =
        Vec::with_capacity(64 + record.operation_id.len() + record.claims.exact_id.len());
    payload.push(record.kind as u8);
    payload.extend_from_slice(&record.activation_nonce);
    put_text(&mut payload, &record.operation_id)?;
    put_claims(&mut payload, &record.claims)?;
    payload.extend_from_slice(&record.registry_sequence.to_be_bytes());
    Ok(payload)
}

fn hydration_receipt_payload(
    registry_instance: [u8; 16],
    boot: [u8; 16],
    registry_sequence: u64,
    state_root: [u8; 32],
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(72);
    payload.extend_from_slice(&registry_instance);
    payload.extend_from_slice(&boot);
    payload.extend_from_slice(&registry_sequence.to_be_bytes());
    payload.extend_from_slice(&state_root);
    payload
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observation_identity::{HostEmitterId, SensitiveParamDeclaration};

    fn roles() -> (
        PrevisibleProofIssuerRole,
        PrevisibleProofVerifierRole,
        TerminationStateMachineRole,
        TerminationCleanupReceiptIssuerRole,
        TerminationCleanupReceiptVerifierRole,
    ) {
        Contract218LifecycleRoleFactory::new(
            Contract218RoleRootMaterial::from_authenticated_custody(
                [1; 16],
                [2; 16],
                Zeroizing::new([3; 32]),
                Zeroizing::new([4; 32]),
            )
            .unwrap(),
        )
        .split_once()
        .unwrap()
        .move_to_composition()
    }

    fn component_claims() -> ObservationIdentityClaims {
        let declaration = SensitiveParamDeclaration::component(vec!["token".into()]).unwrap();
        ObservationIdentityClaims {
            exact_id: "comp-a".into(),
            expected_class: ObservationIdentityClass::Component,
            incarnation: 1,
            declaration_digest: declaration
                .digest_for("comp-a", ObservationIdentityClass::Component, 1)
                .unwrap(),
        }
    }

    #[test]
    fn factory_splits_once_and_moves_exact_roles() {
        let (_issuer, verifier, _termination, _cleanup_issuer, _cleanup_verifier) = roles();
        let host = HostEmitterId::Runtime;
        let declaration = SensitiveParamDeclaration::host(host);
        let claims = ObservationIdentityClaims {
            exact_id: host.canonical_id().into(),
            expected_class: ObservationIdentityClass::Host,
            incarnation: 1,
            declaration_digest: declaration
                .digest_for(host.canonical_id(), ObservationIdentityClass::Host, 1)
                .unwrap(),
        };
        assert_eq!(
            verifier
                .issue_named_live_source(claims)
                .unwrap()
                .canonical_id(),
            "__sys:runtime"
        );
    }

    #[test]
    fn live_and_persisted_authority_cross_scope_rejects() {
        let (_issuer, mut verifier, _, _, _) = roles();
        let keyring = crate::test_support::persisted_identity_keyring_role(
            &mut verifier,
            [1; 16],
            1,
            [5; 32],
            [6; 32],
        )
        .unwrap();
        let signing = keyring.signing_key_capability().unwrap();
        let verification = keyring.verification_key_capability(1).unwrap();
        let claims = component_claims();
        let handle = verifier.issue_live_source(claims.clone()).unwrap();
        let live = verifier.mint_live_identity(&handle).unwrap();
        verifier.verify_live_identity(&live, &claims).unwrap();

        let binding =
            PersistedObservationBinding::new("evt".into(), "evt".into(), [9; 32]).unwrap();
        let carrier = keyring
            .seal_persisted_identity(&signing, &live, &binding)
            .unwrap();
        let persisted = keyring
            .rehydrate_persisted_identity(&verification, &carrier)
            .unwrap();
        assert_eq!(
            verifier.verify_live_identity(&persisted, &claims),
            Err(SensitiveParamCatalogError::ScopeMismatch)
        );
        keyring
            .verify_persisted_identity(&verification, &persisted, &carrier, &binding, &claims)
            .unwrap();
    }

    #[test]
    fn persisted_carrier_each_truncation_and_extension_rejects() {
        let (_issuer, mut verifier, _, _, _) = roles();
        let keyring = crate::test_support::persisted_identity_keyring_role(
            &mut verifier,
            [1; 16],
            1,
            [5; 32],
            [6; 32],
        )
        .unwrap();
        let signing = keyring.signing_key_capability().unwrap();
        let verification = keyring.verification_key_capability(1).unwrap();
        let claims = component_claims();
        let handle = verifier.issue_live_source(claims).unwrap();
        let live = verifier.mint_live_identity(&handle).unwrap();
        let binding =
            PersistedObservationBinding::new("evt".into(), "evt".into(), [9; 32]).unwrap();
        let carrier = keyring
            .seal_persisted_identity(&signing, &live, &binding)
            .unwrap();
        let bytes = carrier.canonical_bytes();
        for len in 0..bytes.len() {
            assert!(keyring
                .decode_persisted_identity(&verification, &bytes[..len])
                .is_err());
        }
        let mut extended = bytes.to_vec();
        extended.push(0);
        assert!(keyring
            .decode_persisted_identity(&verification, &extended)
            .is_err());
    }

    #[test]
    fn ready_and_abort_domains_do_not_cross() {
        let (issuer, verifier, _, _, _) = roles();
        let receipt = verifier
            .issue_committed_component_receipt(component_claims(), "op".into(), 1)
            .unwrap();
        let activation = verifier.begin_component_activation(&receipt).unwrap();
        let ready_receipts = issuer.issue_test_ready_receipts(&activation).unwrap();
        let ready = issuer
            .issue_ready_proof(&activation, ready_receipts)
            .unwrap();
        assert!(matches!(
            verifier.verify_component_ready(activation, ready),
            ComponentReadyVerification::Verified(_)
        ));

        let activation = verifier.begin_component_activation(&receipt).unwrap();
        let abort_receipts = issuer.issue_test_abort_receipts(&activation).unwrap();
        let abort = issuer
            .issue_abort_proof(&activation, abort_receipts)
            .unwrap();
        assert!(matches!(
            verifier.verify_abort_proof(activation, abort).unwrap(),
            PrevisibleAbortBundle::Component(_)
        ));
    }

    #[test]
    fn verified_publication_transitions_are_infallible_after_ready() {
        let (issuer, verifier, _, _, cleanup_verifier) = roles();
        cleanup_verifier
            .verify_provider_binding([1; 16], [2; 16])
            .unwrap();
        assert_eq!(
            cleanup_verifier.verify_provider_binding([9; 16], [2; 16]),
            Err(SensitiveParamCatalogError::StaleIdentity)
        );

        let receipt = verifier
            .issue_committed_component_receipt(component_claims(), "op-publish".into(), 7)
            .unwrap();
        let activation = verifier.begin_component_activation(&receipt).unwrap();
        let ready_receipts = issuer.issue_test_ready_receipts(&activation).unwrap();
        let ready = issuer
            .issue_ready_proof(&activation, ready_receipts)
            .unwrap();
        let ComponentReadyVerification::Verified(verified) =
            verifier.verify_component_ready(activation, ready)
        else {
            panic!("valid component Ready proof must verify");
        };
        let expected = verified.provider_record();
        let (published, handle) = verifier.complete_component_publication(verified);
        let ComponentPublicationResult::Published(ack) = published else {
            panic!("verified publication must complete");
        };
        assert_eq!(verifier.verify_publication_ack(&ack).unwrap(), expected);
        assert_eq!(handle.canonical_id(), "comp-a");

        let activation = verifier.begin_component_activation(&receipt).unwrap();
        let ready_receipts = issuer.issue_test_ready_receipts(&activation).unwrap();
        let ready = issuer
            .issue_ready_proof(&activation, ready_receipts)
            .unwrap();
        let ComponentReadyVerification::Verified(verified) =
            verifier.verify_component_ready(activation, ready)
        else {
            panic!("valid component Ready proof must verify");
        };
        let unknown = verifier.component_publication_outcome_unknown(verified);
        let ComponentPublicationResult::OutcomeUnknown(recovery) = unknown else {
            panic!("typed recovery handle must be returned");
        };
        verifier.inspect_component_recovery(&recovery).unwrap();
        let verified = verifier.resume_component_publication(recovery);
        let (published, _) = verifier.complete_component_publication(verified);
        assert!(matches!(
            published,
            ComponentPublicationResult::Published(_)
        ));
    }

    #[test]
    fn invalid_prepare_rejection_and_receipt_digests_are_typed_and_bound() {
        let (_, _, termination, cleanup_issuer, cleanup_verifier) = roles();
        let request_digest = [0x31; 32];
        let TerminationPrepareFailure::Rejected(invalid) =
            termination.reject_invalid_prepare_request("", request_digest, 0)
        else {
            panic!("invalid request must have a typed rejection proof");
        };
        termination
            .verify_invalid_prepare_request_rejection(&invalid, "", request_digest, 0)
            .unwrap();
        assert!(termination
            .verify_invalid_prepare_request_rejection(&invalid, "different", request_digest, 0)
            .is_err());
        assert!(termination
            .verify_uncommitted_prepare_rejection(&invalid)
            .is_err());

        let member = component_claims();
        let record = TerminationOperationRecord {
            operation_id: "terminate-7".into(),
            member_set_digest: termination_member_set_digest(&[member.clone()]).unwrap(),
            registry_sequence: 9,
        };
        let prepared = termination.prepare_committed(record.clone()).unwrap();
        let prepare_digest = termination.prepare_ack_digest(&prepared).unwrap();
        assert_ne!(prepare_digest, [0; 32]);

        let owner_receipts = cleanup_issuer
            .issue_test_cleanup_receipt_set(&record, &[member], 11)
            .unwrap();
        let cleanup = cleanup_issuer
            .issue_cleanup_complete(&prepared, owner_receipts)
            .unwrap();
        let cleanup_digest = cleanup_verifier
            .cleanup_receipt_digest(&cleanup, &record)
            .unwrap();
        assert_ne!(cleanup_digest, [0; 32]);
        assert_ne!(prepare_digest, cleanup_digest);

        let expected = record.clone();
        let mut wrong = record;
        wrong.registry_sequence += 1;
        assert!(cleanup_verifier
            .cleanup_receipt_digest(&cleanup, &wrong)
            .is_err());

        let key = [0x55; 32];
        let domain = b"fixed-hmac-test\0";
        let payload = b"payload";
        assert_eq!(
            fixed_key_hmac_sha256(&key, domain, payload),
            compute_hmac(&key, domain, payload).unwrap()
        );

        let TerminationFinalizeInputVerification::Verified(verified) =
            termination.verify_finalize_inputs(prepared, cleanup, &cleanup_verifier)
        else {
            panic!("matching typed finalize inputs must seal");
        };
        let TerminationFinalizeResult::OutcomeUnknown(recovery) =
            termination.finalize_outcome_unknown(verified)
        else {
            panic!("verified inputs must produce recovery authority");
        };
        assert_eq!(
            termination.inspect_finalize_recovery(&recovery).unwrap(),
            expected
        );
        let verified = termination.resume_finalize(recovery);
        let TerminationFinalizeResult::Committed(finalized) =
            termination.finalize_committed(verified)
        else {
            panic!("resumed verified inputs must commit infallibly");
        };
        assert_eq!(
            termination.verify_finalize_ack(&finalized).unwrap(),
            expected
        );
    }
}

//! CONTRACT-218 shared identity, declaration, carrier, and port boundary.
//!
//! The values in this module deliberately separate non-authorizing data
//! ([`SensitiveParamSnapshot`], [`ObservationIdentityClaims`]) from authority
//! ([`AuthenticatedObservationSourceHandle`], [`TrustedObservationIdentity`],
//! and [`PersistedObservationIdentity`]).  Authority values have private
//! fields, do not implement `Clone` or Serde, and can only be stamped by the
//! provider role defined in [`crate::contract218_previsible`].
//!
//! CONTRACT-218 has exactly six object-safe host ports.  The external
//! monotonic-anchor transaction is scheduler-internal and is intentionally not
//! declared here.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::fmt;
use std::sync::Arc;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// Maximum canonical identity string length, in UTF-8 bytes.
pub const MAX_OBSERVATION_ID_BYTES: usize = 256;
/// Maximum number of distinct declared sensitive parameter names.
pub const MAX_SENSITIVE_PARAM_NAMES: usize = 64;
/// Maximum UTF-8 byte length of one declared sensitive parameter name.
pub const MAX_SENSITIVE_PARAM_NAME_BYTES: usize = 128;
/// Minimum canonical persisted-identity carrier length.
pub const MIN_PERSISTED_IDENTITY_BYTES: usize = 125;
/// Maximum canonical persisted-identity carrier length.
pub const MAX_PERSISTED_IDENTITY_BYTES: usize = 890;

const DECLARATION_DOMAIN: &[u8] = b"advance.contract218.declaration.v1\0";
const SOURCE_BINDING_DOMAIN: &[u8] = b"advance.contract218.source-binding.v1\0";

/// Closed identity classes.  The tags are canonical and never caller-chosen
/// through an authority API.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ObservationIdentityClass {
    Component,
    Agent,
    Host,
}

impl ObservationIdentityClass {
    pub(crate) const fn tag(self) -> u8 {
        match self {
            Self::Component => 1,
            Self::Agent => 2,
            Self::Host => 3,
        }
    }

    pub(crate) fn from_tag(tag: u8) -> Result<Self, SensitiveParamCatalogError> {
        match tag {
            1 => Ok(Self::Component),
            2 => Ok(Self::Agent),
            3 => Ok(Self::Host),
            _ => Err(SensitiveParamCatalogError::InvalidIdentity),
        }
    }
}

/// The exact, closed host-emitter inventory.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HostEmitterId {
    Runtime,
    RetentionSweeper,
    PackManager,
}

impl HostEmitterId {
    /// The canonical permanent identity.  There is intentionally no inverse
    /// parser from a free-form string.
    pub const fn canonical_id(self) -> &'static str {
        match self {
            Self::Runtime => "__sys:runtime",
            Self::RetentionSweeper => "__sys:retention_sweeper",
            Self::PackManager => "__sys:pack-manager",
        }
    }

    pub(crate) const fn declaration_tag(self) -> u8 {
        match self {
            Self::Runtime => 3,
            Self::RetentionSweeper => 4,
            Self::PackManager => 5,
        }
    }
}

/// Fail-closed errors shared by all six CONTRACT-218 ports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SensitiveParamCatalogError {
    UnknownIdentity,
    InvalidIdentity,
    ScopeMismatch,
    InvalidCarrier,
    StaleIdentity,
    CapacityExceeded,
    RecoveryRequired,
    StorageUnavailable,
}

impl fmt::Display for SensitiveParamCatalogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::UnknownIdentity => "unknown observation identity",
            Self::InvalidIdentity => "invalid observation identity",
            Self::ScopeMismatch => "observation authority scope mismatch",
            Self::InvalidCarrier => "invalid persisted observation carrier",
            Self::StaleIdentity => "stale observation identity",
            Self::CapacityExceeded => "observation identity capacity exceeded",
            Self::RecoveryRequired => "observation identity recovery required",
            Self::StorageUnavailable => "observation identity storage unavailable",
        };
        f.write_str(message)
    }
}

impl std::error::Error for SensitiveParamCatalogError {}

/// Opaque SHA-256 declaration digest.  The bytes are readable for durable
/// storage and equality checks, but no public constructor can forge a digest.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct DeclarationDigest([u8; 32]);

impl DeclarationDigest {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn constant_time_eq(&self, other: &Self) -> bool {
        bool::from(self.0.ct_eq(&other.0))
    }

    pub(crate) const fn from_provider_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for DeclarationDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DeclarationDigest(<opaque>)")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum DeclarationKind {
    Component,
    AgentKnownEmpty,
    Host(HostEmitterId),
}

/// A validated declaration whose component names have set semantics and are
/// stored in stable unsigned UTF-8 byte order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SensitiveParamDeclaration {
    kind: DeclarationKind,
    names: Arc<[String]>,
}

impl SensitiveParamDeclaration {
    /// Validate a component declaration before any registry mutation.
    pub fn component(mut names: Vec<String>) -> Result<Self, SensitiveParamCatalogError> {
        if names.len() > MAX_SENSITIVE_PARAM_NAMES {
            return Err(SensitiveParamCatalogError::CapacityExceeded);
        }
        if names.iter().any(|name| {
            name.is_empty()
                || name.len() > MAX_SENSITIVE_PARAM_NAME_BYTES
                || name.chars().any(char::is_control)
        }) {
            return Err(SensitiveParamCatalogError::InvalidIdentity);
        }
        names.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        if names
            .windows(2)
            .any(|pair| pair[0].as_bytes() == pair[1].as_bytes())
        {
            return Err(SensitiveParamCatalogError::InvalidIdentity);
        }
        Ok(Self {
            kind: DeclarationKind::Component,
            names: names.into(),
        })
    }

    pub fn agent_known_empty() -> Self {
        Self {
            kind: DeclarationKind::AgentKnownEmpty,
            names: Arc::from([]),
        }
    }

    pub fn host(emitter: HostEmitterId) -> Self {
        Self {
            kind: DeclarationKind::Host(emitter),
            names: Arc::from([]),
        }
    }

    pub fn names(&self) -> Arc<[String]> {
        Arc::clone(&self.names)
    }

    /// Compute the exact canonical declaration digest from the spec.  This is
    /// non-authorizing; the provider still checks it against durable state.
    pub fn digest_for(
        &self,
        exact_id: &str,
        class: ObservationIdentityClass,
        incarnation: u64,
    ) -> Result<DeclarationDigest, SensitiveParamCatalogError> {
        validate_identity_id(exact_id)?;
        if incarnation == 0 || incarnation > i64::MAX as u64 {
            return Err(SensitiveParamCatalogError::InvalidIdentity);
        }
        match (&self.kind, class) {
            (DeclarationKind::Component, ObservationIdentityClass::Component)
            | (DeclarationKind::AgentKnownEmpty, ObservationIdentityClass::Agent) => {}
            (DeclarationKind::Host(host), ObservationIdentityClass::Host)
                if host.canonical_id() == exact_id => {}
            _ => return Err(SensitiveParamCatalogError::InvalidIdentity),
        }

        let canonical = self.canonical_bytes(exact_id, class, incarnation)?;
        Ok(DeclarationDigest(Sha256::digest(canonical).into()))
    }

    pub(crate) fn canonical_bytes(
        &self,
        exact_id: &str,
        class: ObservationIdentityClass,
        incarnation: u64,
    ) -> Result<Vec<u8>, SensitiveParamCatalogError> {
        validate_identity_id(exact_id)?;
        let mut bytes = Vec::with_capacity(
            DECLARATION_DOMAIN.len()
                + exact_id.len()
                + 18
                + self.names.iter().map(|n| n.len() + 4).sum::<usize>(),
        );
        bytes.extend_from_slice(DECLARATION_DOMAIN);
        put_text(&mut bytes, exact_id)?;
        bytes.push(class.tag());
        bytes.extend_from_slice(&incarnation.to_be_bytes());
        match &self.kind {
            DeclarationKind::Component => {
                bytes.push(1);
                put_u32_len(&mut bytes, self.names.len())?;
                for name in self.names.iter() {
                    put_text(&mut bytes, name)?;
                }
            }
            DeclarationKind::AgentKnownEmpty => bytes.push(2),
            DeclarationKind::Host(host) => bytes.push(host.declaration_tag()),
        }
        Ok(bytes)
    }
}

/// Non-authorizing exact tuple projection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservationIdentityClaims {
    pub exact_id: String,
    pub expected_class: ObservationIdentityClass,
    pub incarnation: u64,
    pub declaration_digest: DeclarationDigest,
}

impl ObservationIdentityClaims {
    pub fn validate(&self) -> Result<(), SensitiveParamCatalogError> {
        validate_identity_id(&self.exact_id)?;
        if self.incarnation == 0 || self.incarnation > i64::MAX as u64 {
            return Err(SensitiveParamCatalogError::InvalidIdentity);
        }
        if self.expected_class != ObservationIdentityClass::Host
            && self.exact_id.starts_with("__sys:")
        {
            return Err(SensitiveParamCatalogError::InvalidIdentity);
        }
        Ok(())
    }
}

/// Domain-separated, non-authorizing source tuple digest.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SourceBindingDigest([u8; 32]);

impl SourceBindingDigest {
    pub fn for_claims(
        claims: &ObservationIdentityClaims,
    ) -> Result<Self, SensitiveParamCatalogError> {
        claims.validate()?;
        let mut bytes =
            Vec::with_capacity(SOURCE_BINDING_DOMAIN.len() + claims.exact_id.len() + 45);
        bytes.extend_from_slice(SOURCE_BINDING_DOMAIN);
        put_text(&mut bytes, &claims.exact_id)?;
        bytes.push(claims.expected_class.tag());
        bytes.extend_from_slice(&claims.incarnation.to_be_bytes());
        bytes.extend_from_slice(claims.declaration_digest.as_bytes());
        Ok(Self(Sha256::digest(bytes).into()))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for SourceBindingDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SourceBindingDigest(<opaque>)")
    }
}

/// Bounded, non-authorizing catalog result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SensitiveParamSnapshot {
    pub canonical_component_id: String,
    pub identity_class: ObservationIdentityClass,
    pub incarnation: u64,
    pub declaration_digest: DeclarationDigest,
    pub names: Arc<[String]>,
    pub revision: u64,
}

impl SensitiveParamSnapshot {
    pub fn validate(&self) -> Result<(), SensitiveParamCatalogError> {
        let claims = ObservationIdentityClaims {
            exact_id: self.canonical_component_id.clone(),
            expected_class: self.identity_class,
            incarnation: self.incarnation,
            declaration_digest: self.declaration_digest,
        };
        claims.validate()?;
        if self.names.len() > MAX_SENSITIVE_PARAM_NAMES
            || self.names.iter().any(|name| {
                name.is_empty()
                    || name.len() > MAX_SENSITIVE_PARAM_NAME_BYTES
                    || name.chars().any(char::is_control)
            })
            || self
                .names
                .windows(2)
                .any(|pair| pair[0].as_bytes() >= pair[1].as_bytes())
        {
            return Err(SensitiveParamCatalogError::InvalidIdentity);
        }
        if self.identity_class != ObservationIdentityClass::Component && !self.names.is_empty() {
            return Err(SensitiveParamCatalogError::InvalidIdentity);
        }
        if self.revision == 0 || self.revision > i64::MAX as u64 {
            return Err(SensitiveParamCatalogError::InvalidIdentity);
        }

        // The names are security policy, not advisory catalog metadata.  Bind
        // them back to the exact id/class/incarnation tuple instead of merely
        // trusting a provider-returned digest beside an unrelated name list.
        let declaration = match self.identity_class {
            ObservationIdentityClass::Component => {
                SensitiveParamDeclaration::component(self.names.to_vec())?
            }
            ObservationIdentityClass::Agent => SensitiveParamDeclaration::agent_known_empty(),
            ObservationIdentityClass::Host => {
                let host = match self.canonical_component_id.as_str() {
                    "__sys:runtime" => HostEmitterId::Runtime,
                    "__sys:retention_sweeper" => HostEmitterId::RetentionSweeper,
                    "__sys:pack-manager" => HostEmitterId::PackManager,
                    _ => return Err(SensitiveParamCatalogError::InvalidIdentity),
                };
                SensitiveParamDeclaration::host(host)
            }
        };
        let expected = declaration.digest_for(
            &self.canonical_component_id,
            self.identity_class,
            self.incarnation,
        )?;
        if !self.declaration_digest.constant_time_eq(&expected) {
            return Err(SensitiveParamCatalogError::InvalidIdentity);
        }
        Ok(())
    }

    pub fn claims(&self) -> ObservationIdentityClaims {
        ObservationIdentityClaims {
            exact_id: self.canonical_component_id.clone(),
            expected_class: self.identity_class,
            incarnation: self.incarnation,
            declaration_digest: self.declaration_digest,
        }
    }
}

/// Opaque live source capability.  No public constructor, decomposition,
/// `Clone`, or Serde implementation exists.
///
/// ```compile_fail
/// use advance_shared_types::observation_identity::AuthenticatedObservationSourceHandle;
/// fn require_clone<T: Clone>() {}
/// require_clone::<AuthenticatedObservationSourceHandle>();
/// ```
///
/// ```compile_fail
/// use advance_shared_types::observation_identity::AuthenticatedObservationSourceHandle;
/// fn require_serde<T: serde::Serialize>() {}
/// require_serde::<AuthenticatedObservationSourceHandle>();
/// ```
pub struct AuthenticatedObservationSourceHandle {
    pub(crate) claims: ObservationIdentityClaims,
    pub(crate) registry_instance: [u8; 16],
    pub(crate) boot: [u8; 16],
    pub(crate) mac: [u8; 32],
}

impl fmt::Debug for AuthenticatedObservationSourceHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthenticatedObservationSourceHandle(<opaque>)")
    }
}

/// Provider-stamped handle plus its non-authorizing table key.
pub struct IssuedObservationSourceHandle {
    canonical_id: String,
    handle: AuthenticatedObservationSourceHandle,
}

impl IssuedObservationSourceHandle {
    pub fn canonical_id(&self) -> &str {
        &self.canonical_id
    }

    pub fn handle(&self) -> &AuthenticatedObservationSourceHandle {
        &self.handle
    }

    pub fn into_handle(self) -> AuthenticatedObservationSourceHandle {
        self.handle
    }

    pub(crate) fn from_provider(handle: AuthenticatedObservationSourceHandle) -> Self {
        Self {
            canonical_id: handle.claims.exact_id.clone(),
            handle,
        }
    }
}

impl fmt::Debug for IssuedObservationSourceHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IssuedObservationSourceHandle")
            .field("canonical_id", &self.canonical_id)
            .field("handle", &"<opaque>")
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ObservationAuthorityScope {
    Live {
        boot: [u8; 16],
    },
    Persisted {
        event_id: String,
        cursor: String,
        safe_event_digest: [u8; 32],
    },
}

/// Opaque live or persisted authority token.
///
/// ```compile_fail
/// use advance_shared_types::observation_identity::TrustedObservationIdentity;
/// fn require_clone<T: Clone>() {}
/// require_clone::<TrustedObservationIdentity>();
/// ```
pub struct TrustedObservationIdentity {
    pub(crate) claims: ObservationIdentityClaims,
    pub(crate) registry_instance: [u8; 16],
    pub(crate) scope: ObservationAuthorityScope,
    pub(crate) mac: [u8; 32],
}

impl TrustedObservationIdentity {
    pub fn claims_for_persistence(&self) -> ObservationIdentityClaims {
        self.claims.clone()
    }

    pub(crate) fn duplicate_for_contract219(&self) -> Self {
        Self {
            claims: self.claims.clone(),
            registry_instance: self.registry_instance,
            scope: self.scope.clone(),
            mac: self.mac,
        }
    }

    pub(crate) fn contract219_source_binding_digest(&self) -> [u8; 32] {
        SourceBindingDigest::for_claims(&self.claims)
            .expect("provider-stamped identity claims are valid")
            .0
    }
}

impl fmt::Debug for TrustedObservationIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TrustedObservationIdentity(<opaque>)")
    }
}

/// Non-authorizing event/cursor/safe-event binding presented to the sealer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PersistedObservationBinding {
    pub event_id: String,
    pub cursor: String,
    pub safe_event_digest: [u8; 32],
}

impl PersistedObservationBinding {
    pub fn new(
        event_id: String,
        cursor: String,
        safe_event_digest: [u8; 32],
    ) -> Result<Self, SensitiveParamCatalogError> {
        validate_binding_text(&event_id)?;
        validate_binding_text(&cursor)?;
        if event_id != cursor {
            return Err(SensitiveParamCatalogError::ScopeMismatch);
        }
        Ok(Self {
            event_id,
            cursor,
            safe_event_digest,
        })
    }

    pub fn validate(&self) -> Result<(), SensitiveParamCatalogError> {
        validate_binding_text(&self.event_id)?;
        validate_binding_text(&self.cursor)?;
        if self.event_id != self.cursor {
            return Err(SensitiveParamCatalogError::ScopeMismatch);
        }
        Ok(())
    }

    #[allow(dead_code)]
    pub(crate) fn contract219_canonical_bytes(
        &self,
    ) -> Result<Vec<u8>, SensitiveParamCatalogError> {
        self.validate()?;
        let mut bytes = Vec::with_capacity(self.event_id.len() + self.cursor.len() + 40);
        put_text(&mut bytes, &self.event_id)?;
        put_text(&mut bytes, &self.cursor)?;
        bytes.extend_from_slice(&self.safe_event_digest);
        Ok(bytes)
    }

    pub(crate) const fn contract219_safe_event_digest(&self) -> &[u8; 32] {
        &self.safe_event_digest
    }
}

/// Opaque canonical persisted authority carrier.  It is move-only and
/// serde-free; storage uses the single strict canonical codec.
///
/// ```compile_fail
/// use advance_shared_types::observation_identity::PersistedObservationIdentity;
/// fn require_serde<T: serde::Serialize>() {}
/// require_serde::<PersistedObservationIdentity>();
/// ```
pub struct PersistedObservationIdentity {
    pub(crate) key_id: u32,
    pub(crate) binding: PersistedObservationBinding,
    pub(crate) claims: ObservationIdentityClaims,
    pub(crate) mac: [u8; 32],
    pub(crate) canonical: Vec<u8>,
}

impl PersistedObservationIdentity {
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }

    pub fn key_id(&self) -> u32 {
        self.key_id
    }

    /// Decode the sole canonical storage carrier without granting authority.
    /// Callers must pass the result back through
    /// `ObservationIdentityAuthority::rehydrate_persisted_identity` and exact
    /// binding verification before it can authorize an observation.
    pub fn decode_unverified_canonical(
        canonical: &[u8],
    ) -> Result<Self, SensitiveParamCatalogError> {
        let decoded = Self::decode_provider_parts(canonical)?;
        Ok(Self {
            key_id: decoded.key_id,
            binding: decoded.binding,
            claims: decoded.claims,
            mac: decoded.mac,
            canonical: canonical.to_vec(),
        })
    }

    /// Non-authorizing event/cursor/digest binding carried by this envelope.
    pub fn persisted_binding(&self) -> PersistedObservationBinding {
        self.binding.clone()
    }

    pub(crate) fn contract219_canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }

    /// Build the one canonical MAC-preceding carrier body.  The keyring
    /// custody provider signs this typed body; no caller-selected digest or
    /// alternate carrier representation crosses the custody interface.
    pub(crate) fn encode_provider_unsigned_parts(
        key_id: u32,
        binding: &PersistedObservationBinding,
        claims: &ObservationIdentityClaims,
    ) -> Result<Vec<u8>, SensitiveParamCatalogError> {
        if key_id == 0 {
            return Err(SensitiveParamCatalogError::InvalidCarrier);
        }
        binding.validate()?;
        claims.validate()?;
        let mut bytes = Vec::with_capacity(
            MIN_PERSISTED_IDENTITY_BYTES
                + binding.event_id.len()
                + binding.cursor.len()
                + claims.exact_id.len()
                - 3,
        );
        bytes.push(1);
        bytes.extend_from_slice(&key_id.to_be_bytes());
        put_text(&mut bytes, &binding.event_id)?;
        put_text(&mut bytes, &binding.cursor)?;
        put_text(&mut bytes, &claims.exact_id)?;
        bytes.push(claims.expected_class.tag());
        bytes.extend_from_slice(&claims.incarnation.to_be_bytes());
        bytes.extend_from_slice(claims.declaration_digest.as_bytes());
        bytes.extend_from_slice(&binding.safe_event_digest);
        if !(MIN_PERSISTED_IDENTITY_BYTES - 32..=MAX_PERSISTED_IDENTITY_BYTES - 32)
            .contains(&bytes.len())
        {
            return Err(SensitiveParamCatalogError::InvalidCarrier);
        }
        Ok(bytes)
    }

    pub(crate) fn decode_provider_parts(
        canonical: &[u8],
    ) -> Result<DecodedPersistedObservationIdentity, SensitiveParamCatalogError> {
        if !(MIN_PERSISTED_IDENTITY_BYTES..=MAX_PERSISTED_IDENTITY_BYTES).contains(&canonical.len())
        {
            return Err(SensitiveParamCatalogError::InvalidCarrier);
        }
        let mut cursor = CanonicalCursor::new(canonical);
        if cursor.take_u8()? != 1 {
            return Err(SensitiveParamCatalogError::InvalidCarrier);
        }
        let key_id = cursor.take_u32()?;
        if key_id == 0 {
            return Err(SensitiveParamCatalogError::InvalidCarrier);
        }
        let event_id = cursor.take_text(MAX_OBSERVATION_ID_BYTES)?;
        let event_cursor = cursor.take_text(MAX_OBSERVATION_ID_BYTES)?;
        let exact_id = cursor.take_text(MAX_OBSERVATION_ID_BYTES)?;
        let expected_class = ObservationIdentityClass::from_tag(cursor.take_u8()?)
            .map_err(|_| SensitiveParamCatalogError::InvalidCarrier)?;
        let incarnation = cursor.take_u64()?;
        if incarnation == 0 || incarnation > i64::MAX as u64 {
            return Err(SensitiveParamCatalogError::InvalidCarrier);
        }
        let declaration_digest = DeclarationDigest::from_provider_bytes(cursor.take_array::<32>()?);
        let safe_event_digest = cursor.take_array::<32>()?;
        let mac_offset = cursor.position();
        let mac = cursor.take_array::<32>()?;
        if !cursor.is_exhausted() {
            return Err(SensitiveParamCatalogError::InvalidCarrier);
        }
        let binding = PersistedObservationBinding::new(event_id, event_cursor, safe_event_digest)
            .map_err(|_| SensitiveParamCatalogError::InvalidCarrier)?;
        let claims = ObservationIdentityClaims {
            exact_id,
            expected_class,
            incarnation,
            declaration_digest,
        };
        claims
            .validate()
            .map_err(|_| SensitiveParamCatalogError::InvalidCarrier)?;
        Ok(DecodedPersistedObservationIdentity {
            key_id,
            binding,
            claims,
            mac,
            mac_input_len: mac_offset,
        })
    }
}

impl fmt::Debug for PersistedObservationIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PersistedObservationIdentity(<opaque>)")
    }
}

pub(crate) struct DecodedPersistedObservationIdentity {
    pub(crate) key_id: u32,
    pub(crate) binding: PersistedObservationBinding,
    pub(crate) claims: ObservationIdentityClaims,
    pub(crate) mac: [u8; 32],
    pub(crate) mac_input_len: usize,
}

/// Opaque receipt proving a component row/tuple committed while still hidden.
pub struct CommittedComponentSourceReceipt {
    pub(crate) claims: ObservationIdentityClaims,
    pub(crate) operation_id: String,
    pub(crate) registry_sequence: u64,
    pub(crate) mac: [u8; 32],
}

impl fmt::Debug for CommittedComponentSourceReceipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CommittedComponentSourceReceipt(<opaque>)")
    }
}

/// Opaque receipt emitted only after complete boot reconciliation.
pub struct CompletedIdentityHydrationReceipt {
    pub(crate) registry_instance: [u8; 16],
    pub(crate) boot: [u8; 16],
    pub(crate) registry_sequence: u64,
    pub(crate) state_root: [u8; 32],
    pub(crate) mac: [u8; 32],
}

impl fmt::Debug for CompletedIdentityHydrationReceipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CompletedIdentityHydrationReceipt(<opaque>)")
    }
}

/// Port 1/6 — bounded catalog lookup and token verification.
pub trait SensitiveParamCatalog: Send + Sync {
    fn lookup(
        &self,
        canonical_component_id: &str,
    ) -> Result<SensitiveParamSnapshot, SensitiveParamCatalogError>;

    fn verify(
        &self,
        identity: &TrustedObservationIdentity,
    ) -> Result<SensitiveParamSnapshot, SensitiveParamCatalogError>;

    fn subscribe(&self) -> tokio::sync::watch::Receiver<u64>;
}

/// Port 2/6 — sole live-token mint and retained-carrier reconstruction path.
pub trait ObservationIdentityAuthority: Send + Sync {
    fn mint_live_identity(
        &self,
        source: &AuthenticatedObservationSourceHandle,
    ) -> Result<TrustedObservationIdentity, SensitiveParamCatalogError>;

    fn rehydrate_persisted_identity(
        &self,
        persisted: &PersistedObservationIdentity,
    ) -> Result<TrustedObservationIdentity, SensitiveParamCatalogError>;

    fn verify_persisted_binding(
        &self,
        identity: &TrustedObservationIdentity,
        persisted: &PersistedObservationIdentity,
        observed: &PersistedObservationBinding,
    ) -> Result<SensitiveParamSnapshot, SensitiveParamCatalogError>;

    fn resolve_retained_source_binding(
        &self,
        digest: &SourceBindingDigest,
    ) -> Result<ObservationIdentityClaims, SensitiveParamCatalogError>;
}

/// Port 3/6 — M019-only persisted carrier sealing/rotation surface.
pub trait ObservationIdentityPersistenceSealer: Send + Sync {
    fn seal_persisted_identity(
        &self,
        live_identity: &TrustedObservationIdentity,
        binding: &PersistedObservationBinding,
    ) -> Result<PersistedObservationIdentity, SensitiveParamCatalogError>;

    fn reseal_persisted_identity(
        &self,
        existing: &PersistedObservationIdentity,
        binding: &PersistedObservationBinding,
    ) -> Result<PersistedObservationIdentity, SensitiveParamCatalogError>;
}

// The lifecycle DTOs below are declared in the sibling module.  Keeping the
// imports explicit makes the six-port inventory mechanically visible here.
pub use crate::contract218_previsible::{
    AgentAbortBundle, AgentPublicationRecoveryHandle, AgentPublicationResult, ComponentAbortBundle,
    ComponentPublicationRecoveryHandle, ComponentPublicationResult, PrevisibleActivationReadyProof,
    PrevisibleObservationActivation, TerminationCleanupCompleteReceipt,
    TerminationFinalizeRecoveryHandle, TerminationFinalizeResult, TerminationPrepareCommitAck,
    TerminationPrepareFailure, TerminationPrepareRecoveryHandle, VerifiedGrantSubjectDrainToken,
    VerifiedSourceEmissionQuiesceReceipt,
};

/// Port 4/6 — component-only hidden activation/publication surface.
pub trait ComponentObservationSourceIssuer: Send + Sync {
    fn issue_component_source(
        &self,
        receipt: &CommittedComponentSourceReceipt,
    ) -> Result<PrevisibleObservationActivation, SensitiveParamCatalogError>;

    fn publish_component_source(
        &self,
        activation: PrevisibleObservationActivation,
        ready: PrevisibleActivationReadyProof,
    ) -> ComponentPublicationResult;

    fn recover_component_publication(
        &self,
        recovery: ComponentPublicationRecoveryHandle,
    ) -> ComponentPublicationResult;

    fn abort_component_source(
        &self,
        clean: ComponentAbortBundle,
    ) -> Result<(), SensitiveParamCatalogError>;
}

/// Port 5/6 — agent-only journaled registration/termination surface.
pub trait AgentObservationIdentityRegistrar: Send + Sync {
    fn begin_agent_registration(
        &self,
        operation_id: &str,
        exact_agent_id: &str,
    ) -> Result<(), SensitiveParamCatalogError>;

    fn activate_agent_unpublished(
        &self,
        operation_id: &str,
    ) -> Result<PrevisibleObservationActivation, SensitiveParamCatalogError>;

    fn publish_agent_activation(
        &self,
        activation: PrevisibleObservationActivation,
        ready: PrevisibleActivationReadyProof,
    ) -> AgentPublicationResult;

    fn recover_agent_publication(
        &self,
        recovery: AgentPublicationRecoveryHandle,
    ) -> AgentPublicationResult;

    fn abort_agent_registration(
        &self,
        clean: AgentAbortBundle,
        retain_until_ms: u64,
    ) -> Result<(), SensitiveParamCatalogError>;

    fn prepare_agent_termination(
        &self,
        operation_id: &str,
        exact_agent_ids: &[String],
        retain_until_ms: u64,
        subject_drains: Vec<VerifiedGrantSubjectDrainToken>,
        emission_drains: Vec<VerifiedSourceEmissionQuiesceReceipt>,
    ) -> Result<TerminationPrepareCommitAck, TerminationPrepareFailure>;

    fn recover_agent_termination_prepare(
        &self,
        recovery: TerminationPrepareRecoveryHandle,
    ) -> Result<TerminationPrepareCommitAck, TerminationPrepareFailure>;

    fn finalize_agent_termination(
        &self,
        prepared: TerminationPrepareCommitAck,
        cleanup: TerminationCleanupCompleteReceipt,
    ) -> TerminationFinalizeResult;

    fn recover_agent_termination(
        &self,
        recovery: TerminationFinalizeRecoveryHandle,
    ) -> TerminationFinalizeResult;
}

/// Port 6/6 — closed host inventory and boot-hydration reissue surface.
pub trait HostObservationIdentityRegistrar: Send + Sync {
    fn register_host(
        &self,
        emitter: HostEmitterId,
    ) -> Result<IssuedObservationSourceHandle, SensitiveParamCatalogError>;

    fn reissue_boot_sources(
        &self,
        receipt: &CompletedIdentityHydrationReceipt,
    ) -> Result<Vec<IssuedObservationSourceHandle>, SensitiveParamCatalogError>;
}

pub(crate) fn validate_identity_id(id: &str) -> Result<(), SensitiveParamCatalogError> {
    if id.is_empty() || id.len() > MAX_OBSERVATION_ID_BYTES {
        return Err(SensitiveParamCatalogError::InvalidIdentity);
    }
    Ok(())
}

fn validate_binding_text(text: &str) -> Result<(), SensitiveParamCatalogError> {
    if text.is_empty() || text.len() > MAX_OBSERVATION_ID_BYTES {
        return Err(SensitiveParamCatalogError::InvalidCarrier);
    }
    Ok(())
}

pub(crate) fn put_u32_len(out: &mut Vec<u8>, len: usize) -> Result<(), SensitiveParamCatalogError> {
    let len = u32::try_from(len).map_err(|_| SensitiveParamCatalogError::CapacityExceeded)?;
    out.extend_from_slice(&len.to_be_bytes());
    Ok(())
}

pub(crate) fn put_text(out: &mut Vec<u8>, text: &str) -> Result<(), SensitiveParamCatalogError> {
    put_u32_len(out, text.len())?;
    out.extend_from_slice(text.as_bytes());
    Ok(())
}

pub(crate) fn compute_hmac(
    key: &[u8; 32],
    domain: &[u8],
    payload: &[u8],
) -> Result<[u8; 32], SensitiveParamCatalogError> {
    let mut mac =
        HmacSha256::new_from_slice(key).map_err(|_| SensitiveParamCatalogError::InvalidCarrier)?;
    mac.update(domain);
    mac.update(payload);
    Ok(mac.finalize().into_bytes().into())
}

pub(crate) fn verify_hmac(
    key: &[u8; 32],
    domain: &[u8],
    payload: &[u8],
    expected: &[u8; 32],
) -> Result<(), SensitiveParamCatalogError> {
    let actual = compute_hmac(key, domain, payload)?;
    if bool::from(actual.ct_eq(expected)) {
        Ok(())
    } else {
        Err(SensitiveParamCatalogError::InvalidCarrier)
    }
}

struct CanonicalCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> CanonicalCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn position(&self) -> usize {
        self.offset
    }

    fn is_exhausted(&self) -> bool {
        self.offset == self.bytes.len()
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], SensitiveParamCatalogError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(SensitiveParamCatalogError::InvalidCarrier)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(SensitiveParamCatalogError::InvalidCarrier)?;
        self.offset = end;
        Ok(value)
    }

    fn take_u8(&mut self) -> Result<u8, SensitiveParamCatalogError> {
        Ok(self.take(1)?[0])
    }

    fn take_u32(&mut self) -> Result<u32, SensitiveParamCatalogError> {
        Ok(u32::from_be_bytes(self.take_array::<4>()?))
    }

    fn take_u64(&mut self) -> Result<u64, SensitiveParamCatalogError> {
        Ok(u64::from_be_bytes(self.take_array::<8>()?))
    }

    fn take_array<const N: usize>(&mut self) -> Result<[u8; N], SensitiveParamCatalogError> {
        self.take(N)?
            .try_into()
            .map_err(|_| SensitiveParamCatalogError::InvalidCarrier)
    }

    fn take_text(&mut self, max: usize) -> Result<String, SensitiveParamCatalogError> {
        let len = usize::try_from(self.take_u32()?)
            .map_err(|_| SensitiveParamCatalogError::InvalidCarrier)?;
        if len == 0 || len > max {
            return Err(SensitiveParamCatalogError::InvalidCarrier);
        }
        let bytes = self.take(len)?;
        let text =
            std::str::from_utf8(bytes).map_err(|_| SensitiveParamCatalogError::InvalidCarrier)?;
        Ok(text.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push(DIGITS[(byte >> 4) as usize] as char);
            out.push(DIGITS[(byte & 0x0f) as usize] as char);
        }
        out
    }

    #[test]
    fn declaration_digest_literal_kat() {
        let declaration =
            SensitiveParamDeclaration::component(vec!["token".to_owned(), "api_key".to_owned()])
                .unwrap();
        let canonical = declaration
            .canonical_bytes("comp-a", ObservationIdentityClass::Component, 7)
            .unwrap();
        assert_eq!(
            hex(&canonical),
            "616476616e63652e636f6e74726163743231382e6465636c61726174696f6e2e76310000000006636f6d702d610100000000000000070100000002000000076170695f6b657900000005746f6b656e"
        );
        assert_eq!(
            hex(declaration
                .digest_for("comp-a", ObservationIdentityClass::Component, 7)
                .unwrap()
                .as_bytes()),
            "61740ecea4d91975079b8cd0e44b6896849833c0af7c4a9cac1f976dcc67a5bb"
        );
    }

    #[test]
    fn declaration_bounds_reject_before_digest() {
        assert_eq!(
            SensitiveParamDeclaration::component(vec![String::new()]),
            Err(SensitiveParamCatalogError::InvalidIdentity)
        );
        assert_eq!(
            SensitiveParamDeclaration::component(vec!["dup".into(), "dup".into()]),
            Err(SensitiveParamCatalogError::InvalidIdentity)
        );
        assert_eq!(
            SensitiveParamDeclaration::component(vec!["x".repeat(129)]),
            Err(SensitiveParamCatalogError::InvalidIdentity)
        );
        assert_eq!(
            SensitiveParamDeclaration::component(
                (0..65).map(|index| format!("name-{index}")).collect()
            ),
            Err(SensitiveParamCatalogError::CapacityExceeded)
        );
    }

    #[test]
    fn host_inventory_is_closed_and_exact() {
        assert_eq!(HostEmitterId::Runtime.canonical_id(), "__sys:runtime");
        assert_eq!(
            HostEmitterId::RetentionSweeper.canonical_id(),
            "__sys:retention_sweeper"
        );
        assert_eq!(
            HostEmitterId::PackManager.canonical_id(),
            "__sys:pack-manager"
        );
    }
}

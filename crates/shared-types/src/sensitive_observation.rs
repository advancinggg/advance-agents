//! Sealed CONTRACT-219 association values and canonical observation codec.
//!
//! This module deliberately contains no production composition.  It provides the move-only
//! association roles and the checked, duplicate-preserving document representation consumed by
//! MODULE-012.  EventBus/CONTRACT-123 ownership of the issuer halves is activated in a later wave.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::Arc;

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::observation_identity::{
    ObservationAuthorityScope, ObservationIdentityAuthority, PersistedObservationBinding,
    PersistedObservationIdentity, SensitiveParamCatalog, SensitiveParamCatalogError,
    SensitiveParamSnapshot, TrustedObservationIdentity,
};

type HmacSha256 = Hmac<Sha256>;

const DOCUMENT_DOMAIN: &[u8] = b"advance.contract219.document.v1\0";
const ASSOCIATION_DOMAIN: &[u8] = b"advance.contract219.association.v1\0";
const INGRESS_DOCUMENT_DOMAIN: &[u8] = b"advance.contract219.ingress-document.v1\0";
const PROVIDER_DOCUMENT_DOMAIN: &[u8] = b"advance.contract219.provider-document.v1\0";
const PERSISTED_AUTHORITY_DOMAIN: &[u8] = b"advance.contract219.persisted-authority.v1\0";
const DOCUMENT_PROVENANCE_DOMAIN: &[u8] = b"advance.contract219.document-provenance.v1\0";

pub const OBSERVATION_ASSOCIATION_PROOF_LEN: usize = 146;
pub const PERSISTED_BINDING_MIN_LEN: usize = 43;
pub const PERSISTED_BINDING_MAX_LEN: usize = 553;
pub const MAX_OBSERVATION_DEPTH: usize = 32;
pub const MAX_OBSERVATION_NODES: usize = 4_096;
pub const MAX_EVENT_ENVELOPE_BYTES: usize = 4_096;
pub const MAX_EVENT_PAYLOAD_BYTES: usize = 65_536;
pub const MAX_EVENT_DOCUMENT_BYTES: usize = 69_632;
pub const MAX_PROVIDER_DTO_BYTES: usize = 65_536;

const DOCUMENT_VERSION: u8 = 1;
const DOCUMENT_EVENT_KIND: u8 = 1;
const DOCUMENT_PROVIDER_KIND: u8 = 2;
const REDACTED: &str = "[REDACTED]";
pub const STRUCTURAL_EVENT_SCHEMA_ID: &str = "advance.structural-event.v1";
pub const STRUCTURAL_PROVIDER_SCHEMA_ID: &str = "advance.structural-provider.v1";
const MAX_SCHEMA_ID_BYTES: usize = 128;
const MAX_SCHEMA_DECLARATIONS: usize = MAX_OBSERVATION_NODES;

/// Duplicate-preserving canonical observation tree.  Tags are fixed at `0..=7`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ObservationNode {
    Null,
    Bool(bool),
    Number(String),
    String(String),
    Array(Vec<ObservationNode>),
    Object(Vec<(String, ObservationNode)>),
    CanonicalNamedParams(Vec<(String, ObservationNode)>),
    CanonicalCapParams(Vec<CanonicalCapParam>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalCapParam {
    pub key: String,
    pub value: ObservationNode,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ObservationSchemaDocumentKind {
    Event,
    ProviderDto,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ObservationSchemaRoot {
    EventEnvelope,
    EventPayload,
    ProviderRoot,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ObservationPathSegment {
    Member(String),
    Index(u32),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CanonicalContainerKind {
    NamedParams,
    CapParams,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalContainerDeclaration {
    root: ObservationSchemaRoot,
    path: Arc<[ObservationPathSegment]>,
    kind: CanonicalContainerKind,
    exact_keys: Arc<[String]>,
}

impl CanonicalContainerDeclaration {
    pub fn new(
        root: ObservationSchemaRoot,
        path: Vec<ObservationPathSegment>,
        kind: CanonicalContainerKind,
        exact_keys: Vec<String>,
    ) -> Result<Self, ObservationCodecError> {
        if path.len() >= MAX_OBSERVATION_DEPTH
            || exact_keys.len() > MAX_OBSERVATION_NODES
            || exact_keys.iter().any(|key| !valid_schema_text(key))
            || exact_keys
                .windows(2)
                .any(|pair| pair[0].as_bytes() >= pair[1].as_bytes())
            || path.iter().any(|segment| match segment {
                ObservationPathSegment::Member(name) => !valid_schema_text(name),
                ObservationPathSegment::Index(index) => *index as usize >= MAX_OBSERVATION_NODES,
            })
        {
            return Err(ObservationCodecError::ShapeMismatch);
        }
        Ok(Self {
            root,
            path: path.into(),
            kind,
            exact_keys: exact_keys.into(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservationSchemaManifest {
    id: String,
    kind: ObservationSchemaDocumentKind,
    declarations: Arc<[CanonicalContainerDeclaration]>,
}

impl ObservationSchemaManifest {
    pub fn new(
        id: String,
        kind: ObservationSchemaDocumentKind,
        declarations: Vec<CanonicalContainerDeclaration>,
    ) -> Result<Self, ObservationCodecError> {
        if !valid_schema_id(&id) || declarations.len() > MAX_SCHEMA_DECLARATIONS {
            return Err(ObservationCodecError::ShapeMismatch);
        }
        let mut paths = HashSet::with_capacity(declarations.len());
        for declaration in &declarations {
            let root_matches_kind = matches!(
                (kind, declaration.root),
                (
                    ObservationSchemaDocumentKind::Event,
                    ObservationSchemaRoot::EventEnvelope | ObservationSchemaRoot::EventPayload
                ) | (
                    ObservationSchemaDocumentKind::ProviderDto,
                    ObservationSchemaRoot::ProviderRoot
                )
            );
            if !root_matches_kind || !paths.insert((declaration.root, declaration.path.to_vec())) {
                return Err(ObservationCodecError::ShapeMismatch);
            }
        }
        Ok(Self {
            id,
            kind,
            declarations: declarations.into(),
        })
    }

    pub fn id(&self) -> &str {
        &self.id
    }
}

fn valid_schema_text(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}

fn valid_schema_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_SCHEMA_ID_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':'))
}

struct ObservationSchemaRegistry {
    manifests: HashMap<String, ObservationSchemaManifest>,
}

impl ObservationSchemaRegistry {
    fn new(manifests: Vec<ObservationSchemaManifest>) -> Result<Self, ObservationAssociationError> {
        let structural_event = ObservationSchemaManifest::new(
            STRUCTURAL_EVENT_SCHEMA_ID.to_owned(),
            ObservationSchemaDocumentKind::Event,
            Vec::new(),
        )?;
        let structural_provider = ObservationSchemaManifest::new(
            STRUCTURAL_PROVIDER_SCHEMA_ID.to_owned(),
            ObservationSchemaDocumentKind::ProviderDto,
            Vec::new(),
        )?;
        let mut by_id = HashMap::with_capacity(manifests.len() + 2);
        for manifest in std::iter::once(structural_event)
            .chain(std::iter::once(structural_provider))
            .chain(manifests)
        {
            if by_id.insert(manifest.id.clone(), manifest).is_some() {
                return Err(ObservationAssociationError::Codec(
                    ObservationCodecError::ShapeMismatch,
                ));
            }
        }
        Ok(Self { manifests: by_id })
    }

    fn manifest_for(
        &self,
        document: &ObservationDocument,
    ) -> Result<&ObservationSchemaManifest, RedactionBlockReason> {
        self.manifests
            .get(document.schema_id())
            .ok_or(RedactionBlockReason::SchemaMismatch)
    }

    #[cfg(feature = "test-support")]
    fn fixture_schema_id(
        &self,
        kind: ObservationSchemaDocumentKind,
        manifest: Option<&ObservationSchemaManifest>,
    ) -> Result<String, ObservationAssociationError> {
        let schema_id = match (kind, manifest) {
            (ObservationSchemaDocumentKind::Event, None) => STRUCTURAL_EVENT_SCHEMA_ID,
            (ObservationSchemaDocumentKind::ProviderDto, None) => STRUCTURAL_PROVIDER_SCHEMA_ID,
            (_, Some(manifest)) => manifest.id(),
        };
        let registered =
            self.manifests
                .get(schema_id)
                .ok_or(ObservationAssociationError::Codec(
                    ObservationCodecError::ShapeMismatch,
                ))?;
        if registered.kind != kind || manifest.is_some_and(|expected| expected != registered) {
            return Err(ObservationAssociationError::Codec(
                ObservationCodecError::ShapeMismatch,
            ));
        }
        Ok(schema_id.to_owned())
    }
}

/// A typed complete observation document.  Event envelope and payload remain separate so the
/// non-borrowable 4,096/65,536 partition can be measured exactly.  Callers cannot select a
/// declared schema; provider-stamped discriminators own that choice.
///
/// ```compile_fail
/// use advance_shared_types::sensitive_observation::{ObservationDocument, ObservationNode};
/// let _ = ObservationDocument::event_with_schema(
///     "caller.chosen.v1".to_owned(), ObservationNode::Null, ObservationNode::Null,
/// );
/// ```
///
/// ```compile_fail
/// use advance_shared_types::sensitive_observation::{ObservationDocument, ObservationNode};
/// let _ = ObservationDocument::provider_dto_with_schema(
///     "caller.chosen.v1".to_owned(), ObservationNode::Null,
/// );
/// ```
#[derive(Clone)]
pub struct ObservationDocument {
    schema_id: String,
    body: ObservationDocumentBody,
    permit: ObservationDocumentPermit,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ObservationDocumentBody {
    Event {
        envelope: ObservationNode,
        payload: ObservationNode,
    },
    ProviderDto {
        root: ObservationNode,
    },
}

#[derive(Clone, Debug)]
enum ObservationDocumentPermit {
    /// Public structural constructors and the canonical decoder create codec values only.  They
    /// cannot cross an association issuer until a provider stamps the exact document.
    Unsealed,
    /// Pass-B outputs deliberately cannot be rebound as fresh provider observations.
    DerivedOutput,
    #[cfg_attr(not(feature = "test-support"), allow(dead_code))]
    ProviderStamped(DocumentProvenancePermit),
}

#[derive(Clone, Debug)]
struct DocumentProvenancePermit {
    scope: ObservationScope,
    schema_id: String,
    authority_digest: [u8; 32],
    document_digest: [u8; 32],
    mac: [u8; 32],
}

impl PartialEq for ObservationDocument {
    fn eq(&self, other: &Self) -> bool {
        self.schema_id == other.schema_id && self.body == other.body
    }
}

impl Eq for ObservationDocument {}

impl fmt::Debug for ObservationDocument {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObservationDocument")
            .field("schema_id", &self.schema_id)
            .field("body", &self.body)
            .field("permit", &"<sealed>")
            .finish()
    }
}

impl ObservationDocument {
    pub fn event(envelope: ObservationNode, payload: ObservationNode) -> Self {
        Self {
            schema_id: STRUCTURAL_EVENT_SCHEMA_ID.to_owned(),
            body: ObservationDocumentBody::Event { envelope, payload },
            permit: ObservationDocumentPermit::Unsealed,
        }
    }

    pub fn provider_dto(root: ObservationNode) -> Self {
        Self {
            schema_id: STRUCTURAL_PROVIDER_SCHEMA_ID.to_owned(),
            body: ObservationDocumentBody::ProviderDto { root },
            permit: ObservationDocumentPermit::Unsealed,
        }
    }

    pub fn schema_id(&self) -> &str {
        &self.schema_id
    }

    pub fn replace_event_parts(
        &self,
        envelope: ObservationNode,
        payload: ObservationNode,
    ) -> Option<Self> {
        self.event_parts()?;
        Some(Self {
            schema_id: self.schema_id.clone(),
            body: ObservationDocumentBody::Event { envelope, payload },
            permit: ObservationDocumentPermit::DerivedOutput,
        })
    }

    pub fn replace_provider_root(&self, root: ObservationNode) -> Option<Self> {
        self.provider_root()?;
        Some(Self {
            schema_id: self.schema_id.clone(),
            body: ObservationDocumentBody::ProviderDto { root },
            permit: ObservationDocumentPermit::DerivedOutput,
        })
    }

    pub fn event_parts(&self) -> Option<(&ObservationNode, &ObservationNode)> {
        match &self.body {
            ObservationDocumentBody::Event { envelope, payload } => Some((envelope, payload)),
            ObservationDocumentBody::ProviderDto { .. } => None,
        }
    }

    pub fn provider_root(&self) -> Option<&ObservationNode> {
        match &self.body {
            ObservationDocumentBody::ProviderDto { root } => Some(root),
            ObservationDocumentBody::Event { .. } => None,
        }
    }

    fn roots(&self) -> DocumentRoots<'_> {
        match &self.body {
            ObservationDocumentBody::Event { envelope, payload } => {
                DocumentRoots::Event { envelope, payload }
            }
            ObservationDocumentBody::ProviderDto { root } => DocumentRoots::Provider(root),
        }
    }

    #[cfg(feature = "test-support")]
    fn provider_event(
        schema_id: String,
        envelope: ObservationNode,
        payload: ObservationNode,
    ) -> Self {
        Self {
            schema_id,
            body: ObservationDocumentBody::Event { envelope, payload },
            permit: ObservationDocumentPermit::Unsealed,
        }
    }

    #[cfg(feature = "test-support")]
    fn provider_dto_document(schema_id: String, root: ObservationNode) -> Self {
        Self {
            schema_id,
            body: ObservationDocumentBody::ProviderDto { root },
            permit: ObservationDocumentPermit::Unsealed,
        }
    }
}

enum DocumentRoots<'a> {
    Event {
        envelope: &'a ObservationNode,
        payload: &'a ObservationNode,
    },
    Provider(&'a ObservationNode),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObservationScope {
    LiveIngress,
    LiveFinalEvent,
    PersistedEvent,
    LiveProviderDto,
}

impl ObservationScope {
    pub const fn tag(self) -> u8 {
        match self {
            Self::LiveIngress => 1,
            Self::LiveFinalEvent => 2,
            Self::PersistedEvent => 3,
            Self::LiveProviderDto => 4,
        }
    }

    fn from_tag(tag: u8) -> Result<Self, ObservationAssociationError> {
        match tag {
            1 => Ok(Self::LiveIngress),
            2 => Ok(Self::LiveFinalEvent),
            3 => Ok(Self::PersistedEvent),
            4 => Ok(Self::LiveProviderDto),
            _ => Err(ObservationAssociationError::UnknownScope),
        }
    }

    const fn is_event(self) -> bool {
        !matches!(self, Self::LiveProviderDto)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObservationCodecError {
    InvalidVersion,
    InvalidTag,
    InvalidBoolean,
    InvalidNumber,
    InvalidUtf8,
    InvalidLength,
    TrailingBytes,
    LimitExceeded,
    ShapeMismatch,
}

impl fmt::Display for ObservationCodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidVersion => "invalid observation document version",
            Self::InvalidTag => "invalid observation node tag",
            Self::InvalidBoolean => "invalid observation boolean",
            Self::InvalidNumber => "invalid canonical number",
            Self::InvalidUtf8 => "invalid UTF-8",
            Self::InvalidLength => "invalid or truncated length",
            Self::TrailingBytes => "trailing bytes",
            Self::LimitExceeded => "observation bound exceeded",
            Self::ShapeMismatch => "document shape does not match scope",
        })
    }
}

impl std::error::Error for ObservationCodecError {}

#[derive(Debug, PartialEq, Eq)]
pub enum ObservationAssociationError {
    InvalidCompositionKey,
    InvalidBootInstance,
    UnknownScope,
    ScopeMismatch,
    InvalidProof,
    InvalidBinding,
    Codec(ObservationCodecError),
}

impl fmt::Display for ObservationAssociationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidCompositionKey => "invalid association key",
            Self::InvalidBootInstance => "invalid boot instance",
            Self::UnknownScope => "unknown association scope",
            Self::ScopeMismatch => "association scope mismatch",
            Self::InvalidProof => "invalid observation association proof",
            Self::InvalidBinding => "invalid persisted observation binding",
            Self::Codec(_) => "invalid observation document",
        })
    }
}

impl std::error::Error for ObservationAssociationError {}

impl From<ObservationCodecError> for ObservationAssociationError {
    fn from(value: ObservationCodecError) -> Self {
        Self::Codec(value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RedactionBlockReason {
    AssociationMismatch,
    ScopeMismatch,
    SchemaMismatch,
    UnknownIdentity,
    MalformedShape,
    LimitExceeded,
    OutputTooLarge,
    AuthorityUnavailable,
}

#[derive(Debug, PartialEq, Eq)]
pub enum RedactionDisposition {
    Redacted(ObservationDocument),
    Blocked { reason: RedactionBlockReason },
}

#[derive(Clone, Copy)]
struct EncodeLimits {
    max_depth: usize,
    max_nodes: usize,
    max_bytes: usize,
}

enum EncodeTask<'a> {
    Node(&'a ObservationNode, usize),
    Key(&'a str),
}

fn extend_checked(
    output: &mut Vec<u8>,
    bytes: &[u8],
    max_bytes: usize,
) -> Result<(), ObservationCodecError> {
    let next = output
        .len()
        .checked_add(bytes.len())
        .ok_or(ObservationCodecError::LimitExceeded)?;
    if next > max_bytes {
        return Err(ObservationCodecError::LimitExceeded);
    }
    output.extend_from_slice(bytes);
    Ok(())
}

fn push_u32(
    output: &mut Vec<u8>,
    value: usize,
    max_bytes: usize,
) -> Result<(), ObservationCodecError> {
    let value = u32::try_from(value).map_err(|_| ObservationCodecError::LimitExceeded)?;
    extend_checked(output, &value.to_be_bytes(), max_bytes)
}

fn push_len_prefixed(
    output: &mut Vec<u8>,
    value: &str,
    max_bytes: usize,
) -> Result<(), ObservationCodecError> {
    push_u32(output, value.len(), max_bytes)?;
    extend_checked(output, value.as_bytes(), max_bytes)
}

fn is_canonical_number(value: &str) -> bool {
    if value.is_empty() || value.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return false;
    }
    serde_json::from_str::<serde_json::Number>(value).is_ok()
}

fn encode_nodes<'a, I>(roots: I, limits: EncodeLimits) -> Result<Vec<u8>, ObservationCodecError>
where
    I: IntoIterator<Item = &'a ObservationNode>,
{
    let roots: Vec<_> = roots.into_iter().collect();
    let mut tasks = Vec::with_capacity(roots.len());
    for root in roots.into_iter().rev() {
        tasks.push(EncodeTask::Node(root, 1));
    }

    let mut output = Vec::new();
    let mut visited = 0usize;
    while let Some(task) = tasks.pop() {
        match task {
            EncodeTask::Key(key) => {
                push_len_prefixed(&mut output, key, limits.max_bytes)?;
            }
            EncodeTask::Node(node, depth) => {
                if depth > limits.max_depth {
                    return Err(ObservationCodecError::LimitExceeded);
                }
                visited = visited
                    .checked_add(1)
                    .ok_or(ObservationCodecError::LimitExceeded)?;
                if visited > limits.max_nodes {
                    return Err(ObservationCodecError::LimitExceeded);
                }
                match node {
                    ObservationNode::Null => extend_checked(&mut output, &[0], limits.max_bytes)?,
                    ObservationNode::Bool(value) => {
                        extend_checked(&mut output, &[1, u8::from(*value)], limits.max_bytes)?
                    }
                    ObservationNode::Number(value) => {
                        if !is_canonical_number(value) {
                            return Err(ObservationCodecError::InvalidNumber);
                        }
                        extend_checked(&mut output, &[2], limits.max_bytes)?;
                        push_len_prefixed(&mut output, value, limits.max_bytes)?;
                    }
                    ObservationNode::String(value) => {
                        extend_checked(&mut output, &[3], limits.max_bytes)?;
                        push_len_prefixed(&mut output, value, limits.max_bytes)?;
                    }
                    ObservationNode::Array(values) => {
                        if values.len() > limits.max_nodes.saturating_sub(visited) {
                            return Err(ObservationCodecError::LimitExceeded);
                        }
                        extend_checked(&mut output, &[4], limits.max_bytes)?;
                        push_u32(&mut output, values.len(), limits.max_bytes)?;
                        for value in values.iter().rev() {
                            tasks.push(EncodeTask::Node(value, depth + 1));
                        }
                    }
                    ObservationNode::Object(values)
                    | ObservationNode::CanonicalNamedParams(values) => {
                        if values.len() > limits.max_nodes.saturating_sub(visited) {
                            return Err(ObservationCodecError::LimitExceeded);
                        }
                        let tag = if matches!(node, ObservationNode::Object(_)) {
                            5
                        } else {
                            6
                        };
                        extend_checked(&mut output, &[tag], limits.max_bytes)?;
                        push_u32(&mut output, values.len(), limits.max_bytes)?;
                        for (key, value) in values.iter().rev() {
                            tasks.push(EncodeTask::Node(value, depth + 1));
                            tasks.push(EncodeTask::Key(key));
                        }
                    }
                    ObservationNode::CanonicalCapParams(values) => {
                        if values.len() > limits.max_nodes.saturating_sub(visited) {
                            return Err(ObservationCodecError::LimitExceeded);
                        }
                        extend_checked(&mut output, &[7], limits.max_bytes)?;
                        push_u32(&mut output, values.len(), limits.max_bytes)?;
                        for value in values.iter().rev() {
                            tasks.push(EncodeTask::Node(&value.value, depth + 1));
                            tasks.push(EncodeTask::Key(&value.key));
                        }
                    }
                }
            }
        }
    }
    Ok(output)
}

/// Canonically encode one node with the contract depth/node limits and a bounded allocation.
pub fn encode_canonical_node(node: &ObservationNode) -> Result<Vec<u8>, ObservationCodecError> {
    encode_nodes(
        [node],
        EncodeLimits {
            max_depth: MAX_OBSERVATION_DEPTH,
            max_nodes: MAX_OBSERVATION_NODES,
            max_bytes: MAX_EVENT_DOCUMENT_BYTES,
        },
    )
}

struct DecodeCursor<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> DecodeCursor<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], ObservationCodecError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(ObservationCodecError::InvalidLength)?;
        let value = self
            .input
            .get(self.offset..end)
            .ok_or(ObservationCodecError::InvalidLength)?;
        self.offset = end;
        Ok(value)
    }

    fn byte(&mut self) -> Result<u8, ObservationCodecError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<usize, ObservationCodecError> {
        let bytes: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| ObservationCodecError::InvalidLength)?;
        Ok(u32::from_be_bytes(bytes) as usize)
    }

    fn string(&mut self) -> Result<String, ObservationCodecError> {
        let len = self.u32()?;
        String::from_utf8(self.take(len)?.to_vec()).map_err(|_| ObservationCodecError::InvalidUtf8)
    }
}

enum DecodeFrame {
    Array {
        remaining: usize,
        values: Vec<ObservationNode>,
    },
    Object {
        tag: u8,
        remaining: usize,
        values: Vec<(String, ObservationNode)>,
        next_key: Option<String>,
    },
    CapParams {
        remaining: usize,
        values: Vec<CanonicalCapParam>,
        next_key: Option<String>,
    },
}

impl DecodeFrame {
    fn remaining(&self) -> usize {
        match self {
            Self::Array { remaining, .. }
            | Self::Object { remaining, .. }
            | Self::CapParams { remaining, .. } => *remaining,
        }
    }

    fn needs_key(&self) -> bool {
        match self {
            Self::Object { next_key, .. } | Self::CapParams { next_key, .. } => next_key.is_none(),
            Self::Array { .. } => false,
        }
    }

    fn set_key(&mut self, key: String) {
        match self {
            Self::Object { next_key, .. } | Self::CapParams { next_key, .. } => {
                *next_key = Some(key)
            }
            Self::Array { .. } => unreachable!("array frames have no keys"),
        }
    }

    fn attach(&mut self, node: ObservationNode) {
        match self {
            Self::Array { remaining, values } => {
                values.push(node);
                *remaining -= 1;
            }
            Self::Object {
                remaining,
                values,
                next_key,
                ..
            } => {
                values.push((next_key.take().expect("key read before child"), node));
                *remaining -= 1;
            }
            Self::CapParams {
                remaining,
                values,
                next_key,
            } => {
                values.push(CanonicalCapParam {
                    key: next_key.take().expect("key read before child"),
                    value: node,
                });
                *remaining -= 1;
            }
        }
    }

    fn finish(self) -> ObservationNode {
        match self {
            Self::Array { values, .. } => ObservationNode::Array(values),
            Self::Object { tag: 5, values, .. } => ObservationNode::Object(values),
            Self::Object { tag: 6, values, .. } => ObservationNode::CanonicalNamedParams(values),
            Self::Object { .. } => unreachable!("only tags five and six create object frames"),
            Self::CapParams { values, .. } => ObservationNode::CanonicalCapParams(values),
        }
    }
}

fn decode_one_node(
    cursor: &mut DecodeCursor<'_>,
    shared_node_count: &mut usize,
) -> Result<ObservationNode, ObservationCodecError> {
    let mut frames: Vec<DecodeFrame> = Vec::new();
    let mut completed: Option<ObservationNode> = None;

    loop {
        if let Some(mut node) = completed.take() {
            loop {
                match frames.last_mut() {
                    Some(frame) => {
                        frame.attach(node);
                        if frame.remaining() != 0 {
                            break;
                        }
                        node = frames.pop().expect("frame exists").finish();
                    }
                    None => return Ok(node),
                }
            }
        }

        if let Some(frame) = frames.last_mut() {
            if frame.needs_key() {
                frame.set_key(cursor.string()?);
            }
        }

        let depth = frames
            .len()
            .checked_add(1)
            .ok_or(ObservationCodecError::LimitExceeded)?;
        if depth > MAX_OBSERVATION_DEPTH {
            return Err(ObservationCodecError::LimitExceeded);
        }
        *shared_node_count = shared_node_count
            .checked_add(1)
            .ok_or(ObservationCodecError::LimitExceeded)?;
        if *shared_node_count > MAX_OBSERVATION_NODES {
            return Err(ObservationCodecError::LimitExceeded);
        }

        let tag = cursor.byte()?;
        completed = match tag {
            0 => Some(ObservationNode::Null),
            1 => match cursor.byte()? {
                0 => Some(ObservationNode::Bool(false)),
                1 => Some(ObservationNode::Bool(true)),
                _ => return Err(ObservationCodecError::InvalidBoolean),
            },
            2 => {
                let number = cursor.string()?;
                if !is_canonical_number(&number) {
                    return Err(ObservationCodecError::InvalidNumber);
                }
                Some(ObservationNode::Number(number))
            }
            3 => Some(ObservationNode::String(cursor.string()?)),
            4 => {
                let count = cursor.u32()?;
                if count == 0 {
                    Some(ObservationNode::Array(Vec::new()))
                } else {
                    frames.push(DecodeFrame::Array {
                        remaining: count,
                        values: Vec::with_capacity(count.min(MAX_OBSERVATION_NODES)),
                    });
                    None
                }
            }
            5 | 6 => {
                let count = cursor.u32()?;
                if count == 0 {
                    Some(if tag == 5 {
                        ObservationNode::Object(Vec::new())
                    } else {
                        ObservationNode::CanonicalNamedParams(Vec::new())
                    })
                } else {
                    frames.push(DecodeFrame::Object {
                        tag,
                        remaining: count,
                        values: Vec::with_capacity(count.min(MAX_OBSERVATION_NODES)),
                        next_key: None,
                    });
                    None
                }
            }
            7 => {
                let count = cursor.u32()?;
                if count == 0 {
                    Some(ObservationNode::CanonicalCapParams(Vec::new()))
                } else {
                    frames.push(DecodeFrame::CapParams {
                        remaining: count,
                        values: Vec::with_capacity(count.min(MAX_OBSERVATION_NODES)),
                        next_key: None,
                    });
                    None
                }
            }
            _ => return Err(ObservationCodecError::InvalidTag),
        };
    }
}

pub fn decode_canonical_node(bytes: &[u8]) -> Result<ObservationNode, ObservationCodecError> {
    if bytes.len() > MAX_EVENT_DOCUMENT_BYTES {
        return Err(ObservationCodecError::LimitExceeded);
    }
    let mut cursor = DecodeCursor {
        input: bytes,
        offset: 0,
    };
    let mut nodes = 0usize;
    let node = decode_one_node(&mut cursor, &mut nodes)?;
    if cursor.offset != bytes.len() {
        return Err(ObservationCodecError::TrailingBytes);
    }
    Ok(node)
}

fn encode_document_for_scope(
    document: &ObservationDocument,
    scope: ObservationScope,
) -> Result<Vec<u8>, ObservationCodecError> {
    match (document.roots(), scope.is_event()) {
        (DocumentRoots::Event { envelope, payload }, true) => {
            // First enforce the complete depth/node budget across both partitions.  The two
            // following encodes then enforce the non-borrowable byte partition independently.
            let _ = encode_nodes(
                [envelope, payload],
                EncodeLimits {
                    max_depth: MAX_OBSERVATION_DEPTH,
                    max_nodes: MAX_OBSERVATION_NODES,
                    max_bytes: MAX_EVENT_DOCUMENT_BYTES,
                },
            )?;
            let envelope_bytes = encode_nodes(
                [envelope],
                EncodeLimits {
                    max_depth: MAX_OBSERVATION_DEPTH,
                    max_nodes: MAX_OBSERVATION_NODES,
                    // version + kind + both u32 lengths are charged to the envelope.
                    max_bytes: MAX_EVENT_ENVELOPE_BYTES.saturating_sub(10),
                },
            )?;
            let payload_bytes = encode_nodes(
                [payload],
                EncodeLimits {
                    max_depth: MAX_OBSERVATION_DEPTH,
                    max_nodes: MAX_OBSERVATION_NODES,
                    max_bytes: MAX_EVENT_PAYLOAD_BYTES,
                },
            )?;

            let total = 10usize
                .checked_add(envelope_bytes.len())
                .and_then(|value| value.checked_add(payload_bytes.len()))
                .ok_or(ObservationCodecError::LimitExceeded)?;
            if total > MAX_EVENT_DOCUMENT_BYTES {
                return Err(ObservationCodecError::LimitExceeded);
            }
            let mut output = Vec::with_capacity(total);
            output.extend_from_slice(&[DOCUMENT_VERSION, DOCUMENT_EVENT_KIND]);
            push_u32(&mut output, envelope_bytes.len(), MAX_EVENT_DOCUMENT_BYTES)?;
            output.extend_from_slice(&envelope_bytes);
            push_u32(&mut output, payload_bytes.len(), MAX_EVENT_DOCUMENT_BYTES)?;
            output.extend_from_slice(&payload_bytes);
            Ok(output)
        }
        (DocumentRoots::Provider(root), false) => {
            let root_bytes = encode_nodes(
                [root],
                EncodeLimits {
                    max_depth: MAX_OBSERVATION_DEPTH,
                    max_nodes: MAX_OBSERVATION_NODES,
                    max_bytes: MAX_PROVIDER_DTO_BYTES.saturating_sub(2),
                },
            )?;
            let mut output = Vec::with_capacity(root_bytes.len() + 2);
            output.extend_from_slice(&[DOCUMENT_VERSION, DOCUMENT_PROVIDER_KIND]);
            output.extend_from_slice(&root_bytes);
            Ok(output)
        }
        _ => Err(ObservationCodecError::ShapeMismatch),
    }
}

fn association_document_bytes(
    document: &ObservationDocument,
    scope: ObservationScope,
) -> Result<Vec<u8>, ObservationCodecError> {
    if !valid_schema_id(document.schema_id()) {
        return Err(ObservationCodecError::ShapeMismatch);
    }
    encode_document_for_scope(document, scope)
}

pub fn encode_canonical_document(
    document: &ObservationDocument,
) -> Result<Vec<u8>, ObservationCodecError> {
    let scope = match document.roots() {
        DocumentRoots::Event { .. } => ObservationScope::LiveIngress,
        DocumentRoots::Provider(_) => ObservationScope::LiveProviderDto,
    };
    encode_document_for_scope(document, scope)
}

pub fn decode_canonical_document(
    bytes: &[u8],
) -> Result<ObservationDocument, ObservationCodecError> {
    if bytes.len() > MAX_EVENT_DOCUMENT_BYTES || bytes.len() < 3 {
        return Err(ObservationCodecError::LimitExceeded);
    }
    let mut cursor = DecodeCursor {
        input: bytes,
        offset: 0,
    };
    if cursor.byte()? != DOCUMENT_VERSION {
        return Err(ObservationCodecError::InvalidVersion);
    }
    let kind = cursor.byte()?;
    let mut nodes = 0usize;
    let document = match kind {
        DOCUMENT_EVENT_KIND => {
            let envelope_len = cursor.u32()?;
            let envelope_end = cursor
                .offset
                .checked_add(envelope_len)
                .ok_or(ObservationCodecError::InvalidLength)?;
            let envelope_slice = bytes
                .get(cursor.offset..envelope_end)
                .ok_or(ObservationCodecError::InvalidLength)?;
            let mut envelope_cursor = DecodeCursor {
                input: envelope_slice,
                offset: 0,
            };
            let envelope = decode_one_node(&mut envelope_cursor, &mut nodes)?;
            if envelope_cursor.offset != envelope_slice.len() {
                return Err(ObservationCodecError::TrailingBytes);
            }
            cursor.offset = envelope_end;
            let payload_len = cursor.u32()?;
            let payload_end = cursor
                .offset
                .checked_add(payload_len)
                .ok_or(ObservationCodecError::InvalidLength)?;
            let payload_slice = bytes
                .get(cursor.offset..payload_end)
                .ok_or(ObservationCodecError::InvalidLength)?;
            let mut payload_cursor = DecodeCursor {
                input: payload_slice,
                offset: 0,
            };
            let payload = decode_one_node(&mut payload_cursor, &mut nodes)?;
            if payload_cursor.offset != payload_slice.len() {
                return Err(ObservationCodecError::TrailingBytes);
            }
            cursor.offset = payload_end;
            ObservationDocument::event(envelope, payload)
        }
        DOCUMENT_PROVIDER_KIND => {
            let root = decode_one_node(&mut cursor, &mut nodes)?;
            ObservationDocument::provider_dto(root)
        }
        _ => return Err(ObservationCodecError::InvalidTag),
    };
    if cursor.offset != bytes.len() {
        return Err(ObservationCodecError::TrailingBytes);
    }
    let scope = if kind == DOCUMENT_EVENT_KIND {
        ObservationScope::LiveIngress
    } else {
        ObservationScope::LiveProviderDto
    };
    encode_document_for_scope(&document, scope)?;
    Ok(document)
}

pub fn encode_persisted_observation_binding(
    binding: &PersistedObservationBinding,
) -> Result<Vec<u8>, ObservationAssociationError> {
    if binding.event_id.is_empty()
        || binding.event_id.len() > 256
        || binding.cursor.is_empty()
        || binding.cursor.len() > 256
        || binding.cursor != binding.event_id
    {
        return Err(ObservationAssociationError::InvalidBinding);
    }
    let total = 1usize
        .checked_add(4)
        .and_then(|value| value.checked_add(binding.event_id.len()))
        .and_then(|value| value.checked_add(4))
        .and_then(|value| value.checked_add(binding.cursor.len()))
        .and_then(|value| value.checked_add(32))
        .ok_or(ObservationAssociationError::InvalidBinding)?;
    if !(PERSISTED_BINDING_MIN_LEN..=PERSISTED_BINDING_MAX_LEN).contains(&total) {
        return Err(ObservationAssociationError::InvalidBinding);
    }
    let mut output = Vec::with_capacity(total);
    output.push(1);
    output.extend_from_slice(&(binding.event_id.len() as u32).to_be_bytes());
    output.extend_from_slice(binding.event_id.as_bytes());
    output.extend_from_slice(&(binding.cursor.len() as u32).to_be_bytes());
    output.extend_from_slice(binding.cursor.as_bytes());
    output.extend_from_slice(&binding.safe_event_digest);
    Ok(output)
}

pub fn decode_persisted_observation_binding(
    bytes: &[u8],
) -> Result<PersistedObservationBinding, ObservationAssociationError> {
    if !(PERSISTED_BINDING_MIN_LEN..=PERSISTED_BINDING_MAX_LEN).contains(&bytes.len()) {
        return Err(ObservationAssociationError::InvalidBinding);
    }
    let mut cursor = DecodeCursor {
        input: bytes,
        offset: 0,
    };
    if cursor.byte().map_err(ObservationAssociationError::Codec)? != 1 {
        return Err(ObservationAssociationError::InvalidBinding);
    }
    let event_id = cursor
        .string()
        .map_err(|_| ObservationAssociationError::InvalidBinding)?;
    let cursor_value = cursor
        .string()
        .map_err(|_| ObservationAssociationError::InvalidBinding)?;
    if event_id.is_empty()
        || event_id.len() > 256
        || cursor_value.is_empty()
        || cursor_value.len() > 256
        || event_id != cursor_value
    {
        return Err(ObservationAssociationError::InvalidBinding);
    }
    let safe_event_digest: [u8; 32] = cursor
        .take(32)
        .map_err(|_| ObservationAssociationError::InvalidBinding)?
        .try_into()
        .map_err(|_| ObservationAssociationError::InvalidBinding)?;
    if cursor.offset != bytes.len() {
        return Err(ObservationAssociationError::InvalidBinding);
    }
    Ok(PersistedObservationBinding {
        event_id,
        cursor: cursor_value,
        safe_event_digest,
    })
}

fn sha256_domain(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    hasher.finalize().into()
}

fn validate_pass_a_node(root: &ObservationNode) -> Result<(), RedactionBlockReason> {
    let mut stack = vec![(root, 1usize)];
    let mut visited = 0usize;
    while let Some((node, depth)) = stack.pop() {
        if depth > MAX_OBSERVATION_DEPTH {
            return Err(RedactionBlockReason::LimitExceeded);
        }
        visited = visited
            .checked_add(1)
            .ok_or(RedactionBlockReason::LimitExceeded)?;
        if visited > MAX_OBSERVATION_NODES {
            return Err(RedactionBlockReason::LimitExceeded);
        }
        match node {
            ObservationNode::Number(value) if !is_canonical_number(value) => {
                return Err(RedactionBlockReason::MalformedShape)
            }
            ObservationNode::Array(values) => {
                for value in values.iter().rev() {
                    stack.push((value, depth + 1));
                }
            }
            ObservationNode::Object(values) | ObservationNode::CanonicalNamedParams(values) => {
                let mut names = HashSet::with_capacity(values.len());
                for (name, value) in values {
                    if name.is_empty() || !names.insert(name.as_str()) {
                        return Err(RedactionBlockReason::MalformedShape);
                    }
                    stack.push((value, depth + 1));
                }
            }
            ObservationNode::CanonicalCapParams(values) => {
                let mut names = HashSet::with_capacity(values.len());
                for value in values {
                    if value.key.is_empty() || !names.insert(value.key.as_str()) {
                        return Err(RedactionBlockReason::MalformedShape);
                    }
                    stack.push((&value.value, depth + 1));
                }
            }
            ObservationNode::Null
            | ObservationNode::Bool(_)
            | ObservationNode::Number(_)
            | ObservationNode::String(_) => {}
        }
    }
    Ok(())
}

fn validate_pass_a_document(document: &ObservationDocument) -> Result<(), RedactionBlockReason> {
    // Duplicate checks are intentionally performed over every original subtree before any
    // declaration lookup or replacement.  Bounds are remeasured over the complete document.
    match document.roots() {
        DocumentRoots::Event { envelope, payload } => {
            validate_pass_a_node(envelope)?;
            validate_pass_a_node(payload)?;
        }
        DocumentRoots::Provider(root) => validate_pass_a_node(root)?,
    }
    Ok(())
}

fn validate_schema_document(
    document: &ObservationDocument,
    manifest: &ObservationSchemaManifest,
) -> Result<(), RedactionBlockReason> {
    let kind_matches = matches!(
        (&document.body, manifest.kind),
        (
            ObservationDocumentBody::Event { .. },
            ObservationSchemaDocumentKind::Event
        ) | (
            ObservationDocumentBody::ProviderDto { .. },
            ObservationSchemaDocumentKind::ProviderDto
        )
    );
    if !kind_matches || document.schema_id() != manifest.id {
        return Err(RedactionBlockReason::SchemaMismatch);
    }

    let declarations = manifest
        .declarations
        .iter()
        .map(|declaration| ((declaration.root, declaration.path.to_vec()), declaration))
        .collect::<HashMap<_, _>>();
    let mut seen = HashSet::with_capacity(declarations.len());
    let mut stack: Vec<(
        ObservationSchemaRoot,
        Vec<ObservationPathSegment>,
        &ObservationNode,
    )> = match document.roots() {
        DocumentRoots::Event { envelope, payload } => vec![
            (ObservationSchemaRoot::EventPayload, Vec::new(), payload),
            (ObservationSchemaRoot::EventEnvelope, Vec::new(), envelope),
        ],
        DocumentRoots::Provider(root) => {
            vec![(ObservationSchemaRoot::ProviderRoot, Vec::new(), root)]
        }
    };

    while let Some((root, path, node)) = stack.pop() {
        let key = (root, path.clone());
        let declaration = declarations.get(&key).copied();
        match (declaration, node) {
            (Some(declaration), ObservationNode::CanonicalNamedParams(values))
                if declaration.kind == CanonicalContainerKind::NamedParams =>
            {
                if values.len() != declaration.exact_keys.len()
                    || values
                        .iter()
                        .zip(declaration.exact_keys.iter())
                        .any(|((actual, _), expected)| actual != expected)
                {
                    return Err(RedactionBlockReason::SchemaMismatch);
                }
                seen.insert(key);
            }
            (Some(declaration), ObservationNode::CanonicalCapParams(values))
                if declaration.kind == CanonicalContainerKind::CapParams =>
            {
                if values.len() != declaration.exact_keys.len()
                    || values
                        .iter()
                        .zip(declaration.exact_keys.iter())
                        .any(|(actual, expected)| &actual.key != expected)
                {
                    return Err(RedactionBlockReason::SchemaMismatch);
                }
                seen.insert(key);
            }
            (Some(_), _) => return Err(RedactionBlockReason::SchemaMismatch),
            (
                None,
                ObservationNode::CanonicalNamedParams(_) | ObservationNode::CanonicalCapParams(_),
            ) => return Err(RedactionBlockReason::SchemaMismatch),
            (None, _) => {}
        }

        match node {
            ObservationNode::Array(values) => {
                for (index, value) in values.iter().enumerate().rev() {
                    let mut child = path.clone();
                    child.push(ObservationPathSegment::Index(index as u32));
                    stack.push((root, child, value));
                }
            }
            ObservationNode::Object(values) | ObservationNode::CanonicalNamedParams(values) => {
                for (name, value) in values.iter().rev() {
                    let mut child = path.clone();
                    child.push(ObservationPathSegment::Member(name.clone()));
                    stack.push((root, child, value));
                }
            }
            ObservationNode::CanonicalCapParams(values) => {
                for value in values.iter().rev() {
                    let mut child = path.clone();
                    child.push(ObservationPathSegment::Member(value.key.clone()));
                    stack.push((root, child, &value.value));
                }
            }
            ObservationNode::Null
            | ObservationNode::Bool(_)
            | ObservationNode::Number(_)
            | ObservationNode::String(_) => {}
        }
    }

    if seen.len() != declarations.len() {
        return Err(RedactionBlockReason::SchemaMismatch);
    }
    Ok(())
}

fn map_catalog_error(error: SensitiveParamCatalogError) -> RedactionBlockReason {
    match error {
        SensitiveParamCatalogError::UnknownIdentity
        | SensitiveParamCatalogError::InvalidIdentity
        | SensitiveParamCatalogError::StaleIdentity => RedactionBlockReason::UnknownIdentity,
        SensitiveParamCatalogError::ScopeMismatch => RedactionBlockReason::ScopeMismatch,
        SensitiveParamCatalogError::CapacityExceeded => RedactionBlockReason::LimitExceeded,
        SensitiveParamCatalogError::InvalidCarrier => RedactionBlockReason::AssociationMismatch,
        SensitiveParamCatalogError::RecoveryRequired
        | SensitiveParamCatalogError::StorageUnavailable => {
            RedactionBlockReason::AuthorityUnavailable
        }
    }
}

struct AssociationSecrets {
    key: Zeroizing<[u8; 32]>,
    boot_instance_id: [u8; 16],
    schemas: Arc<ObservationSchemaRegistry>,
}

/// One-shot association role allocation.
///
/// Role capabilities are intentionally not cloneable or cross-castable:
///
/// ```compile_fail
/// use advance_shared_types::sensitive_observation::ObservationAssociationRoleFactory;
/// use zeroize::Zeroizing;
/// let factory = ObservationAssociationRoleFactory::new_at_composition(
///     Zeroizing::new([7; 32]), [8; 16], Vec::new(),
/// ).unwrap();
/// let _parts = factory.split_once().unwrap();
/// let _second_split = factory.split_once();
/// ```
///
/// ```compile_fail
/// use advance_shared_types::sensitive_observation::ObservationEventAssociationIssuer;
/// fn duplicate(role: ObservationEventAssociationIssuer) {
///     let _second = role.clone();
/// }
/// ```
///
/// ```compile_fail
/// use advance_shared_types::sensitive_observation::{
///     ObservationEventAssociationIssuer, ObservationProviderDtoAssociationIssuer,
/// };
/// fn cross_role(role: ObservationProviderDtoAssociationIssuer) {
///     let _event: ObservationEventAssociationIssuer = role;
/// }
/// ```
pub struct ObservationAssociationRoleFactory {
    inner: Arc<AssociationSecrets>,
}

pub struct ObservationEventAssociationIssuer {
    inner: Arc<AssociationSecrets>,
}

pub struct ObservationProviderDtoAssociationIssuer {
    inner: Arc<AssociationSecrets>,
}

pub struct ObservationAssociationVerifierRole {
    inner: Arc<AssociationSecrets>,
}

pub struct Contract219ProviderRole {
    inner: Arc<AssociationSecrets>,
}

pub struct ObservationAssociationRoleParts {
    pub event_issuer: ObservationEventAssociationIssuer,
    pub provider_issuer: ObservationProviderDtoAssociationIssuer,
    pub verifier: ObservationAssociationVerifierRole,
    pub provider: Contract219ProviderRole,
}

macro_rules! opaque_debug {
    ($name:ty) => {
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "(<opaque>)"))
            }
        }
    };
}

opaque_debug!(ObservationAssociationRoleFactory);
opaque_debug!(ObservationEventAssociationIssuer);
opaque_debug!(ObservationProviderDtoAssociationIssuer);
opaque_debug!(ObservationAssociationVerifierRole);
opaque_debug!(Contract219ProviderRole);

/// Provider-sealed authority for one exact live event document issuance.  It is deliberately
/// move-only and serde-free, and the Event issuer borrows it so M019 can retain the lease through
/// commit or proved rejection.
///
/// Compile-fail evidence `raw_identity_cannot_bind_live_observation`: a raw CONTRACT-218 identity
/// is not an emission lease.
///
/// ```compile_fail
/// use advance_shared_types::observation_identity::TrustedObservationIdentity;
/// use advance_shared_types::sensitive_observation::{
///     ObservationDocument, ObservationEventAssociationIssuer,
/// };
/// fn cannot_bind_identity(
///     issuer: &ObservationEventAssociationIssuer,
///     identity: &TrustedObservationIdentity,
///     document: ObservationDocument,
/// ) {
///     let _ = issuer.bind_live_ingress(identity, document);
/// }
/// ```
///
/// ```compile_fail
/// use advance_shared_types::sensitive_observation::ObservationEmissionLease;
/// fn cannot_clone(lease: ObservationEmissionLease) {
///     let _duplicate = lease.clone();
/// }
/// ```
///
/// ```compile_fail
/// use advance_shared_types::sensitive_observation::ObservationEmissionLease;
/// fn require_serde<T: serde::Serialize>() {}
/// require_serde::<ObservationEmissionLease>();
/// ```
pub struct ObservationEmissionLease {
    identity: TrustedObservationIdentity,
    permit: DocumentProvenancePermit,
}

opaque_debug!(ObservationEmissionLease);

impl ObservationAssociationRoleFactory {
    /// Construct the one-shot role factory at the top-level composition root.
    /// The key is consumed into zeroizing storage and no role exposes it.
    pub fn new_at_composition(
        association_key: Zeroizing<[u8; 32]>,
        boot_instance_id: [u8; 16],
        schemas: Vec<ObservationSchemaManifest>,
    ) -> Result<Self, ObservationAssociationError> {
        if association_key.as_ref() == &[0; 32] {
            return Err(ObservationAssociationError::InvalidCompositionKey);
        }
        if boot_instance_id == [0; 16] {
            return Err(ObservationAssociationError::InvalidBootInstance);
        }
        Ok(Self {
            inner: Arc::new(AssociationSecrets {
                key: association_key,
                boot_instance_id,
                schemas: Arc::new(ObservationSchemaRegistry::new(schemas)?),
            }),
        })
    }

    /// Consuming split: Rust ownership makes a second split or crossed role allocation
    /// unrepresentable.  The provider role is moved with the verifier only at composition.
    pub fn split_once(
        self,
    ) -> Result<ObservationAssociationRoleParts, ObservationAssociationError> {
        Ok(ObservationAssociationRoleParts {
            event_issuer: ObservationEventAssociationIssuer {
                inner: Arc::clone(&self.inner),
            },
            provider_issuer: ObservationProviderDtoAssociationIssuer {
                inner: Arc::clone(&self.inner),
            },
            verifier: ObservationAssociationVerifierRole {
                inner: Arc::clone(&self.inner),
            },
            provider: Contract219ProviderRole { inner: self.inner },
        })
    }
}

/// Fixed-size opaque proof.  Callers cannot construct or serialize it.
///
/// ```compile_fail
/// use advance_shared_types::sensitive_observation::ObservationAssociationProof;
/// let _forged = ObservationAssociationProof { bytes: [0; 146] };
/// ```
pub struct ObservationAssociationProof {
    bytes: [u8; OBSERVATION_ASSOCIATION_PROOF_LEN],
}

impl ObservationAssociationProof {
    pub const ENCODED_LEN: usize = OBSERVATION_ASSOCIATION_PROOF_LEN;

    fn scope(&self) -> Result<ObservationScope, ObservationAssociationError> {
        ObservationScope::from_tag(self.bytes[17])
    }
}

impl fmt::Debug for ObservationAssociationProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ObservationAssociationProof(<opaque 146 bytes>)")
    }
}

enum BoundObservationAuthority {
    Live(TrustedObservationIdentity),
    Persisted {
        persisted: PersistedObservationIdentity,
        observed: PersistedObservationBinding,
    },
}

/// Move-only document/authority association.
///
/// ```compile_fail
/// use advance_shared_types::sensitive_observation::BoundObservationDocument;
/// fn duplicate(input: BoundObservationDocument) {
///     let _second = input.clone();
/// }
/// ```
///
/// ```compile_fail
/// use advance_shared_types::sensitive_observation::BoundObservationDocument;
/// fn serialize(input: &BoundObservationDocument) {
///     let _ = serde_json::to_vec(input).unwrap();
/// }
/// ```
pub struct BoundObservationDocument {
    document: ObservationDocument,
    authority: BoundObservationAuthority,
    safe_event_digest: [u8; 32],
    association: ObservationAssociationProof,
}

impl BoundObservationDocument {
    /// Structural evidence only; proof bytes and bound authority remain non-decomposable.
    pub const fn association_proof_len(&self) -> usize {
        OBSERVATION_ASSOCIATION_PROOF_LEN
    }
}

impl fmt::Debug for BoundObservationDocument {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BoundObservationDocument(<opaque association>)")
    }
}

/// Compile-fail evidence `provider_issuer_cannot_mint_contract123_subject`: the provider issuer
/// cannot manufacture a subject from a raw identity.  Order 4 moves the only production
/// constructor to `GrantSubjectAuthorityHandle`; Order-2 tests use the feature-gated provider
/// fixture.
///
/// ```compile_fail
/// use advance_shared_types::observation_identity::TrustedObservationIdentity;
/// use advance_shared_types::sensitive_observation::ObservationProviderDtoAssociationIssuer;
/// fn cannot_seal(
///     issuer: &ObservationProviderDtoAssociationIssuer,
///     identity: &TrustedObservationIdentity,
/// ) {
///     let _ = issuer.seal_observation_subject(identity);
/// }
/// ```
pub struct Contract123ObservationSubject {
    identity: TrustedObservationIdentity,
    permit: DocumentProvenancePermit,
}

opaque_debug!(Contract123ObservationSubject);

fn association_mac(key: &[u8; 32], prefix: &[u8]) -> Result<[u8; 32], ObservationAssociationError> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|_| ObservationAssociationError::InvalidCompositionKey)?;
    mac.update(ASSOCIATION_DOMAIN);
    mac.update(prefix);
    Ok(mac.finalize().into_bytes().into())
}

fn authority_digest(
    authority: &BoundObservationAuthority,
) -> Result<[u8; 32], ObservationAssociationError> {
    match authority {
        BoundObservationAuthority::Live(identity) => Ok(live_authority_digest(identity)),
        BoundObservationAuthority::Persisted {
            persisted,
            observed,
        } => persisted_authority_digest(persisted, observed),
    }
}

fn live_authority_digest(identity: &TrustedObservationIdentity) -> [u8; 32] {
    identity.contract219_source_binding_digest()
}

fn persisted_authority_digest(
    persisted: &PersistedObservationIdentity,
    observed: &PersistedObservationBinding,
) -> Result<[u8; 32], ObservationAssociationError> {
    let binding = encode_persisted_observation_binding(observed)?;
    let mut hasher = Sha256::new();
    hasher.update(PERSISTED_AUTHORITY_DOMAIN);
    hasher.update(persisted.contract219_canonical_bytes());
    hasher.update(binding);
    Ok(hasher.finalize().into())
}

fn document_provenance_mac(
    secrets: &AssociationSecrets,
    scope: ObservationScope,
    schema_id: &str,
    authority_digest: &[u8; 32],
    document_digest: &[u8; 32],
) -> Result<[u8; 32], ObservationAssociationError> {
    let schema_len = u32::try_from(schema_id.len())
        .map_err(|_| ObservationAssociationError::Codec(ObservationCodecError::ShapeMismatch))?;
    let mut mac = HmacSha256::new_from_slice(secrets.key.as_ref())
        .map_err(|_| ObservationAssociationError::InvalidCompositionKey)?;
    mac.update(DOCUMENT_PROVENANCE_DOMAIN);
    mac.update(&secrets.boot_instance_id);
    mac.update(&[scope.tag()]);
    mac.update(&schema_len.to_be_bytes());
    mac.update(schema_id.as_bytes());
    mac.update(authority_digest);
    mac.update(document_digest);
    Ok(mac.finalize().into_bytes().into())
}

fn permits_match(left: &DocumentProvenancePermit, right: &DocumentProvenancePermit) -> bool {
    left.scope == right.scope
        && left.schema_id == right.schema_id
        && bool::from(left.authority_digest.ct_eq(&right.authority_digest))
        && bool::from(left.document_digest.ct_eq(&right.document_digest))
        && bool::from(left.mac.ct_eq(&right.mac))
}

fn validate_document_provenance(
    secrets: &AssociationSecrets,
    scope: ObservationScope,
    document: &ObservationDocument,
    expected_authority_digest: &[u8; 32],
    companion: Option<&DocumentProvenancePermit>,
    canonical_document: &[u8],
) -> Result<(), ObservationAssociationError> {
    let ObservationDocumentPermit::ProviderStamped(permit) = &document.permit else {
        return Err(ObservationAssociationError::InvalidProof);
    };
    let document_digest = sha256_domain(DOCUMENT_DOMAIN, canonical_document);
    let expected_mac = document_provenance_mac(
        secrets,
        scope,
        document.schema_id(),
        expected_authority_digest,
        &document_digest,
    )?;
    if permit.scope != scope
        || permit.schema_id != document.schema_id()
        || !bool::from(permit.authority_digest.ct_eq(expected_authority_digest))
        || !bool::from(permit.document_digest.ct_eq(&document_digest))
        || !bool::from(permit.mac.ct_eq(&expected_mac))
        || companion.is_some_and(|expected| !permits_match(permit, expected))
    {
        return Err(ObservationAssociationError::InvalidProof);
    }
    Ok(())
}

#[cfg(feature = "test-support")]
fn stamp_fixture_document(
    secrets: &AssociationSecrets,
    scope: ObservationScope,
    authority_digest: [u8; 32],
    mut document: ObservationDocument,
) -> Result<(DocumentProvenancePermit, ObservationDocument), ObservationAssociationError> {
    let canonical_document = association_document_bytes(&document, scope)?;
    let document_digest = sha256_domain(DOCUMENT_DOMAIN, &canonical_document);
    let permit = DocumentProvenancePermit {
        scope,
        schema_id: document.schema_id.clone(),
        authority_digest,
        document_digest,
        mac: document_provenance_mac(
            secrets,
            scope,
            document.schema_id(),
            &authority_digest,
            &document_digest,
        )?,
    };
    document.permit = ObservationDocumentPermit::ProviderStamped(permit.clone());
    Ok((permit, document))
}

fn stamp_owned_document(
    secrets: &AssociationSecrets,
    scope: ObservationScope,
    authority_digest: [u8; 32],
    mut document: ObservationDocument,
) -> Result<(DocumentProvenancePermit, ObservationDocument), ObservationAssociationError> {
    let canonical_document = association_document_bytes(&document, scope)?;
    let document_digest = sha256_domain(DOCUMENT_DOMAIN, &canonical_document);
    let permit = DocumentProvenancePermit {
        scope,
        schema_id: document.schema_id.clone(),
        authority_digest,
        document_digest,
        mac: document_provenance_mac(
            secrets,
            scope,
            document.schema_id(),
            &authority_digest,
            &document_digest,
        )?,
    };
    document.permit = ObservationDocumentPermit::ProviderStamped(permit.clone());
    Ok((permit, document))
}

fn safe_digest_for_document(
    scope: ObservationScope,
    canonical_document: &[u8],
    supplied: [u8; 32],
) -> [u8; 32] {
    match scope {
        ObservationScope::LiveIngress => sha256_domain(INGRESS_DOCUMENT_DOMAIN, canonical_document),
        ObservationScope::LiveProviderDto => {
            sha256_domain(PROVIDER_DOCUMENT_DOMAIN, canonical_document)
        }
        ObservationScope::LiveFinalEvent | ObservationScope::PersistedEvent => supplied,
    }
}

fn issue_bound(
    secrets: &AssociationSecrets,
    scope: ObservationScope,
    supplied_safe_event_digest: [u8; 32],
    document: ObservationDocument,
    authority: BoundObservationAuthority,
    companion_permit: Option<&DocumentProvenancePermit>,
) -> Result<BoundObservationDocument, ObservationAssociationError> {
    let canonical_document = association_document_bytes(&document, scope)?;
    match (&authority, scope) {
        (BoundObservationAuthority::Live(_), ObservationScope::LiveIngress)
        | (BoundObservationAuthority::Live(_), ObservationScope::LiveFinalEvent)
        | (BoundObservationAuthority::Live(_), ObservationScope::LiveProviderDto)
        | (BoundObservationAuthority::Persisted { .. }, ObservationScope::PersistedEvent) => {}
        _ => return Err(ObservationAssociationError::ScopeMismatch),
    }
    let safe_event_digest =
        safe_digest_for_document(scope, &canonical_document, supplied_safe_event_digest);
    if let BoundObservationAuthority::Persisted { observed, .. } = &authority {
        if !bool::from(safe_event_digest.ct_eq(observed.contract219_safe_event_digest())) {
            return Err(ObservationAssociationError::InvalidBinding);
        }
    }

    let document_digest = sha256_domain(DOCUMENT_DOMAIN, &canonical_document);
    let authority_digest = authority_digest(&authority)?;
    validate_document_provenance(
        secrets,
        scope,
        &document,
        &authority_digest,
        companion_permit,
        &canonical_document,
    )?;
    let mut bytes = [0u8; OBSERVATION_ASSOCIATION_PROOF_LEN];
    bytes[0] = 1;
    bytes[1..17].copy_from_slice(&secrets.boot_instance_id);
    bytes[17] = scope.tag();
    bytes[18..50].copy_from_slice(&safe_event_digest);
    bytes[50..82].copy_from_slice(&document_digest);
    bytes[82..114].copy_from_slice(&authority_digest);
    let mac = association_mac(&secrets.key, &bytes[..114])?;
    bytes[114..146].copy_from_slice(&mac);

    Ok(BoundObservationDocument {
        document,
        authority,
        safe_event_digest,
        association: ObservationAssociationProof { bytes },
    })
}

impl ObservationEventAssociationIssuer {
    /// Stamp one typed live Event owned by MODULE-019.  The schema id must have
    /// been registered when this role factory was created; callers cannot add a
    /// schema or reuse this document under a different authority.
    pub fn stamp_live_event(
        &self,
        identity: TrustedObservationIdentity,
        schema_id: &str,
        envelope: ObservationNode,
        payload: ObservationNode,
    ) -> Result<(ObservationEmissionLease, ObservationDocument), ObservationAssociationError> {
        if !matches!(&identity.scope, ObservationAuthorityScope::Live { .. }) {
            return Err(ObservationAssociationError::ScopeMismatch);
        }
        let manifest = self.inner.schemas.manifests.get(schema_id).ok_or(
            ObservationAssociationError::Codec(ObservationCodecError::ShapeMismatch),
        )?;
        if manifest.kind != ObservationSchemaDocumentKind::Event {
            return Err(ObservationAssociationError::Codec(
                ObservationCodecError::ShapeMismatch,
            ));
        }
        let authority_digest = live_authority_digest(&identity);
        let document = ObservationDocument {
            schema_id: schema_id.to_owned(),
            body: ObservationDocumentBody::Event { envelope, payload },
            permit: ObservationDocumentPermit::Unsealed,
        };
        let (permit, document) = stamp_owned_document(
            &self.inner,
            ObservationScope::LiveFinalEvent,
            authority_digest,
            document,
        )?;
        Ok((ObservationEmissionLease { identity, permit }, document))
    }

    pub fn bind_live_ingress(
        &self,
        source: &ObservationEmissionLease,
        document: ObservationDocument,
    ) -> Result<BoundObservationDocument, ObservationAssociationError> {
        issue_bound(
            &self.inner,
            ObservationScope::LiveIngress,
            [0; 32],
            document,
            BoundObservationAuthority::Live(source.identity.duplicate_for_contract219()),
            Some(&source.permit),
        )
    }

    pub fn bind_live_final_event(
        &self,
        source: &ObservationEmissionLease,
        safe_event_digest: [u8; 32],
        document: ObservationDocument,
    ) -> Result<BoundObservationDocument, ObservationAssociationError> {
        issue_bound(
            &self.inner,
            ObservationScope::LiveFinalEvent,
            safe_event_digest,
            document,
            BoundObservationAuthority::Live(source.identity.duplicate_for_contract219()),
            Some(&source.permit),
        )
    }

    pub fn bind_persisted_event(
        &self,
        persisted: PersistedObservationIdentity,
        observed: PersistedObservationBinding,
        document: ObservationDocument,
    ) -> Result<BoundObservationDocument, ObservationAssociationError> {
        let safe_event_digest = *observed.contract219_safe_event_digest();
        issue_bound(
            &self.inner,
            ObservationScope::PersistedEvent,
            safe_event_digest,
            document,
            BoundObservationAuthority::Persisted {
                persisted,
                observed,
            },
            None,
        )
    }

    /// Stamp a typed historical Event against the exact persisted authority
    /// carrier and its non-authorizing event/cursor binding. The subsequent
    /// `bind_persisted_event` call and sealed redactor still perform MAC,
    /// source, scope, schema, and safe-digest verification.
    pub fn stamp_persisted_event(
        &self,
        persisted: &PersistedObservationIdentity,
        observed: &PersistedObservationBinding,
        schema_id: &str,
        envelope: ObservationNode,
        payload: ObservationNode,
    ) -> Result<ObservationDocument, ObservationAssociationError> {
        let manifest = self.inner.schemas.manifests.get(schema_id).ok_or(
            ObservationAssociationError::Codec(ObservationCodecError::ShapeMismatch),
        )?;
        if manifest.kind != ObservationSchemaDocumentKind::Event {
            return Err(ObservationAssociationError::Codec(
                ObservationCodecError::ShapeMismatch,
            ));
        }
        let document = ObservationDocument {
            schema_id: schema_id.to_owned(),
            body: ObservationDocumentBody::Event { envelope, payload },
            permit: ObservationDocumentPermit::Unsealed,
        };
        let (_, document) = stamp_owned_document(
            &self.inner,
            ObservationScope::PersistedEvent,
            persisted_authority_digest(persisted, observed)?,
            document,
        )?;
        Ok(document)
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn issue_test_live_event(
        &self,
        identity: &TrustedObservationIdentity,
        scope: ObservationScope,
        manifest: Option<&ObservationSchemaManifest>,
        envelope: ObservationNode,
        payload: ObservationNode,
    ) -> Result<(ObservationEmissionLease, ObservationDocument), ObservationAssociationError> {
        if !matches!(
            scope,
            ObservationScope::LiveIngress | ObservationScope::LiveFinalEvent
        ) || !matches!(&identity.scope, ObservationAuthorityScope::Live { .. })
        {
            return Err(ObservationAssociationError::ScopeMismatch);
        }
        let schema_id = self
            .inner
            .schemas
            .fixture_schema_id(ObservationSchemaDocumentKind::Event, manifest)?;
        let authority_digest = live_authority_digest(identity);
        let (permit, document) = stamp_fixture_document(
            &self.inner,
            scope,
            authority_digest,
            ObservationDocument::provider_event(schema_id, envelope, payload),
        )?;
        Ok((
            ObservationEmissionLease {
                identity: identity.duplicate_for_contract219(),
                permit,
            },
            document,
        ))
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn issue_test_persisted_event_document(
        &self,
        persisted: &PersistedObservationIdentity,
        observed: &PersistedObservationBinding,
        manifest: Option<&ObservationSchemaManifest>,
        envelope: ObservationNode,
        payload: ObservationNode,
    ) -> Result<ObservationDocument, ObservationAssociationError> {
        let schema_id = self
            .inner
            .schemas
            .fixture_schema_id(ObservationSchemaDocumentKind::Event, manifest)?;
        let (_, document) = stamp_fixture_document(
            &self.inner,
            ObservationScope::PersistedEvent,
            persisted_authority_digest(persisted, observed)?,
            ObservationDocument::provider_event(schema_id, envelope, payload),
        )?;
        Ok(document)
    }
}

impl ObservationProviderDtoAssociationIssuer {
    /// Stamp one live provider DTO owned by CONTRACT-123.  Like the Event
    /// sibling, this consumes the exact trusted identity and only accepts a
    /// schema registered by the composition root.
    pub fn stamp_live_provider_dto(
        &self,
        identity: TrustedObservationIdentity,
        schema_id: &str,
        root: ObservationNode,
    ) -> Result<(Contract123ObservationSubject, ObservationDocument), ObservationAssociationError>
    {
        if !matches!(&identity.scope, ObservationAuthorityScope::Live { .. }) {
            return Err(ObservationAssociationError::ScopeMismatch);
        }
        let manifest = self.inner.schemas.manifests.get(schema_id).ok_or(
            ObservationAssociationError::Codec(ObservationCodecError::ShapeMismatch),
        )?;
        if manifest.kind != ObservationSchemaDocumentKind::ProviderDto {
            return Err(ObservationAssociationError::Codec(
                ObservationCodecError::ShapeMismatch,
            ));
        }
        let authority_digest = live_authority_digest(&identity);
        let document = ObservationDocument {
            schema_id: schema_id.to_owned(),
            body: ObservationDocumentBody::ProviderDto { root },
            permit: ObservationDocumentPermit::Unsealed,
        };
        let (permit, document) = stamp_owned_document(
            &self.inner,
            ObservationScope::LiveProviderDto,
            authority_digest,
            document,
        )?;
        Ok((Contract123ObservationSubject { identity, permit }, document))
    }

    pub fn bind_live_provider_dto(
        &self,
        subject: Contract123ObservationSubject,
        document: ObservationDocument,
    ) -> Result<BoundObservationDocument, ObservationAssociationError> {
        let Contract123ObservationSubject { identity, permit } = subject;
        issue_bound(
            &self.inner,
            ObservationScope::LiveProviderDto,
            [0; 32],
            document,
            BoundObservationAuthority::Live(identity),
            Some(&permit),
        )
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn issue_test_provider_dto(
        &self,
        identity: &TrustedObservationIdentity,
        manifest: Option<&ObservationSchemaManifest>,
        root: ObservationNode,
    ) -> Result<(Contract123ObservationSubject, ObservationDocument), ObservationAssociationError>
    {
        if !matches!(&identity.scope, ObservationAuthorityScope::Live { .. }) {
            return Err(ObservationAssociationError::ScopeMismatch);
        }
        let schema_id = self
            .inner
            .schemas
            .fixture_schema_id(ObservationSchemaDocumentKind::ProviderDto, manifest)?;
        let authority_digest = live_authority_digest(identity);
        let (permit, document) = stamp_fixture_document(
            &self.inner,
            ObservationScope::LiveProviderDto,
            authority_digest,
            ObservationDocument::provider_dto_document(schema_id, root),
        )?;
        Ok((
            Contract123ObservationSubject {
                identity: identity.duplicate_for_contract219(),
                permit,
            },
            document,
        ))
    }
}

fn verify_association(
    secrets: &AssociationSecrets,
    input: BoundObservationDocument,
) -> Result<VerifiedBoundObservationDocument, ObservationAssociationError> {
    let proof = &input.association.bytes;
    if proof[0] != 1 || !bool::from(proof[1..17].ct_eq(&secrets.boot_instance_id)) {
        return Err(ObservationAssociationError::InvalidProof);
    }
    let scope = input.association.scope()?;
    let canonical_document = association_document_bytes(&input.document, scope)?;
    let expected_safe =
        safe_digest_for_document(scope, &canonical_document, input.safe_event_digest);
    let expected_document = sha256_domain(DOCUMENT_DOMAIN, &canonical_document);
    let expected_authority = authority_digest(&input.authority)?;
    let expected_mac = association_mac(&secrets.key, &proof[..114])?;
    if !bool::from(proof[18..50].ct_eq(&expected_safe))
        || !bool::from(input.safe_event_digest.ct_eq(&expected_safe))
        || !bool::from(proof[50..82].ct_eq(&expected_document))
        || !bool::from(proof[82..114].ct_eq(&expected_authority))
        || !bool::from(proof[114..146].ct_eq(&expected_mac))
    {
        return Err(ObservationAssociationError::InvalidProof);
    }
    match (&input.authority, scope) {
        (BoundObservationAuthority::Live(_), ObservationScope::LiveIngress)
        | (BoundObservationAuthority::Live(_), ObservationScope::LiveFinalEvent)
        | (BoundObservationAuthority::Live(_), ObservationScope::LiveProviderDto)
        | (BoundObservationAuthority::Persisted { .. }, ObservationScope::PersistedEvent) => {}
        _ => return Err(ObservationAssociationError::ScopeMismatch),
    }
    Ok(VerifiedBoundObservationDocument {
        scope,
        document: input.document,
        authority: input.authority,
        schemas: Arc::clone(&secrets.schemas),
    })
}

pub struct VerifiedBoundObservationDocument {
    scope: ObservationScope,
    document: ObservationDocument,
    authority: BoundObservationAuthority,
    schemas: Arc<ObservationSchemaRegistry>,
}

opaque_debug!(VerifiedBoundObservationDocument);

impl VerifiedBoundObservationDocument {
    /// Mandatory complete-tree Pass A.  No catalog/declaration lookup is available on the input
    /// typestate, so authority selection cannot move before this operation.
    pub fn validate_pass_a(self) -> Result<PassAValidatedObservation, RedactionBlockReason> {
        encode_document_for_scope(&self.document, self.scope).map_err(|error| match error {
            ObservationCodecError::LimitExceeded => RedactionBlockReason::LimitExceeded,
            ObservationCodecError::ShapeMismatch => RedactionBlockReason::ScopeMismatch,
            _ => RedactionBlockReason::MalformedShape,
        })?;
        validate_pass_a_document(&self.document)?;
        let manifest = self.schemas.manifest_for(&self.document)?;
        validate_schema_document(&self.document, manifest)?;
        Ok(PassAValidatedObservation {
            scope: self.scope,
            document: self.document,
            authority: self.authority,
        })
    }
}

pub struct PassAValidatedObservation {
    scope: ObservationScope,
    document: ObservationDocument,
    authority: BoundObservationAuthority,
}

opaque_debug!(PassAValidatedObservation);

impl PassAValidatedObservation {
    pub fn verify_authority(
        self,
        catalog: &dyn SensitiveParamCatalog,
        authority_port: &dyn ObservationIdentityAuthority,
    ) -> Result<AuthorityValidatedObservation, RedactionBlockReason> {
        let snapshot = match &self.authority {
            BoundObservationAuthority::Live(identity) => {
                catalog.verify(identity).map_err(map_catalog_error)?
            }
            BoundObservationAuthority::Persisted {
                persisted,
                observed,
            } => {
                let identity = authority_port
                    .rehydrate_persisted_identity(persisted)
                    .map_err(map_catalog_error)?;
                authority_port
                    .verify_persisted_binding(&identity, persisted, observed)
                    .map_err(map_catalog_error)?
            }
        };
        snapshot.validate().map_err(map_catalog_error)?;
        Ok(AuthorityValidatedObservation {
            scope: self.scope,
            document: self.document,
            snapshot,
        })
    }
}

pub struct AuthorityValidatedObservation {
    scope: ObservationScope,
    document: ObservationDocument,
    snapshot: SensitiveParamSnapshot,
}

opaque_debug!(AuthorityValidatedObservation);

impl AuthorityValidatedObservation {
    pub fn scope(&self) -> ObservationScope {
        self.scope
    }

    pub fn document(&self) -> &ObservationDocument {
        &self.document
    }

    pub fn sensitive_names(&self) -> &[String] {
        &self.snapshot.names
    }

    pub fn into_document(self) -> ObservationDocument {
        self.document
    }
}

type RedactorImplementation =
    dyn Fn(VerifiedBoundObservationDocument) -> RedactionDisposition + Send + Sync + 'static;

pub struct SensitiveObservationRedactor {
    verifier: ObservationAssociationVerifierRole,
    implementation: Box<RedactorImplementation>,
}

impl fmt::Debug for SensitiveObservationRedactor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SensitiveObservationRedactor(<sealed callable>)")
    }
}

impl Contract219ProviderRole {
    pub fn bind_once<F>(
        self,
        verifier: ObservationAssociationVerifierRole,
        implementation: F,
    ) -> Result<SensitiveObservationRedactor, ObservationAssociationError>
    where
        F: Fn(VerifiedBoundObservationDocument) -> RedactionDisposition + Send + Sync + 'static,
    {
        if !Arc::ptr_eq(&self.inner, &verifier.inner) {
            return Err(ObservationAssociationError::InvalidProof);
        }
        Ok(SensitiveObservationRedactor {
            verifier,
            implementation: Box::new(implementation),
        })
    }
}

impl SensitiveObservationRedactor {
    pub fn redact_bound_observation(
        &self,
        input: BoundObservationDocument,
    ) -> RedactionDisposition {
        match verify_association(&self.verifier.inner, input) {
            Ok(verified) => (self.implementation)(verified),
            Err(ObservationAssociationError::ScopeMismatch) => RedactionDisposition::Blocked {
                reason: RedactionBlockReason::ScopeMismatch,
            },
            Err(ObservationAssociationError::Codec(ObservationCodecError::LimitExceeded)) => {
                RedactionDisposition::Blocked {
                    reason: RedactionBlockReason::LimitExceeded,
                }
            }
            Err(_) => RedactionDisposition::Blocked {
                reason: RedactionBlockReason::AssociationMismatch,
            },
        }
    }
}

/// Re-measure a Pass-B clone using the exact original scope.  Provider code maps every overflow
/// to `OutputTooLarge` and never returns a partially redacted document.
pub fn validate_redacted_output(
    document: &ObservationDocument,
    scope: ObservationScope,
) -> Result<(), RedactionBlockReason> {
    encode_document_for_scope(document, scope)
        .map(|_| ())
        .map_err(|error| match error {
            ObservationCodecError::ShapeMismatch => RedactionBlockReason::ScopeMismatch,
            _ => RedactionBlockReason::OutputTooLarge,
        })
}

pub fn redacted_marker() -> &'static str {
    REDACTED
}

#[cfg(feature = "test-support")]
pub(crate) fn test_association_proof_bytes(
    bound: &BoundObservationDocument,
) -> [u8; OBSERVATION_ASSOCIATION_PROOF_LEN] {
    bound.association.bytes
}

#[cfg(feature = "test-support")]
pub(crate) fn test_swap_bound_documents(
    left: &mut BoundObservationDocument,
    right: &mut BoundObservationDocument,
) {
    std::mem::swap(&mut left.document, &mut right.document);
}

#[cfg(feature = "test-support")]
pub(crate) fn test_swap_bound_safe_digests(
    left: &mut BoundObservationDocument,
    right: &mut BoundObservationDocument,
) {
    std::mem::swap(&mut left.safe_event_digest, &mut right.safe_event_digest);
}

#[cfg(feature = "test-support")]
pub(crate) fn test_swap_bound_authorities(
    left: &mut BoundObservationDocument,
    right: &mut BoundObservationDocument,
) {
    std::mem::swap(&mut left.authority, &mut right.authority);
}

#[cfg(feature = "test-support")]
pub(crate) fn test_swap_bound_proofs(
    left: &mut BoundObservationDocument,
    right: &mut BoundObservationDocument,
) {
    std::mem::swap(&mut left.association, &mut right.association);
}

#[cfg(feature = "test-support")]
pub(crate) fn test_corrupt_bound_proof_byte(bound: &mut BoundObservationDocument, index: usize) {
    bound.association.bytes[index] ^= 1;
}

#[cfg(feature = "test-support")]
pub(crate) fn test_set_bound_proof_byte(
    bound: &mut BoundObservationDocument,
    index: usize,
    value: u8,
) {
    bound.association.bytes[index] = value;
}

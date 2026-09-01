//! Live CONTRACT-123 grant adapter: list + prepare/execute/recover journal.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
#[cfg(feature = "test-support")]
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use advance_client_api::{
    BoundGrantApprovalPort, BoundGrantMutation, BoundMutationOutcome, ClientCapParam,
    ProviderClientDoneReceipt, ProviderError, ProviderMutationRecovery, ProviderPrepareOutcome,
};
use advance_shared_types::security_validator::{LeakDetector, ScanContext, ScanResult};
use advance_shared_types::sensitive_observation::{
    encode_canonical_document, BoundObservationDocument, CanonicalCapParam, ObservationDocument,
    ObservationNode,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use cap_grant::{
    CapGrantError, CapParam, GrantApprovalIntake, GrantProvenance, GrantStatus, GrantTtl,
    RequestInspect,
};
use cap_http::canonical_facade::canonical_scan_text;
use cap_http::DefaultLeakDetector;
use chrono::SecondsFormat;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::observation_projection::Contract219EventProjector;

const JOURNAL_MAGIC: &[u8; 8] = b"C123GJ01";
const HEADER_MAC_DOMAIN: &[u8] = b"advance.m020.grant-journal-header.v1\0";
const TICKET_MAC_DOMAIN: &[u8] = b"advance.contract190.provider-recovery.v1\0";
const TICKET_KEY_INFO: &[u8] = b"advance.contract190.provider-recovery-key.v1\0";
const REVISION_MAC_DOMAIN: &[u8] = b"advance.contract123.pending-decision-revision.v1\0";
const REQUEST_ID_DOMAIN: &[u8] = b"advance.contract123.pending-request-id.v1\0";
const REQUEST_FP_DOMAIN: &[u8] = b"advance.contract123.pending-request.v1\0";
const DOCUMENT_DOMAIN: &[u8] = b"advance.contract219.document.v1\0";
const DONE_RECEIPT_KEY_INFO: &[u8] = b"advance.contract190.client-done-receipt-key.v1\0";
const DONE_RECEIPT_MAC_DOMAIN: &[u8] = b"advance.contract190.client-done-receipt.v1\0";
const TICKET_LEN: usize = 167;
const REVISION_LEN: usize = 185;
const DONE_RECEIPT_LEN: usize = 283;
const HEADER_LEN: usize = 105;
const PROVIDER_TAG: u8 = 1;
const MAX_JOURNAL_BYTES: u64 = 8 * 1024 * 1024;

#[cfg(feature = "test-support")]
static JOURNAL_BYTES_READ: AtomicU64 = AtomicU64::new(0);

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
enum TerminalKind {
    Decision {
        request_id: String,
        status: String,
    },
    Revoke {
        grant_id: String,
        revoked_count: u64,
    },
    Preset {
        preset: String,
        target: String,
        created_grant_ids: Vec<String>,
    },
}

struct JournalRow {
    intent: Vec<u8>,
    nonce: [u8; 32],
    subject_id: Option<String>,
    fingerprint: [u8; 32],
    operation_tag: u8,
    digest: [u8; 32],
    mutation: BoundGrantMutation,
    terminal: Option<TerminalKind>,
}

impl Clone for JournalRow {
    fn clone(&self) -> Self {
        Self {
            intent: self.intent.clone(),
            nonce: self.nonce,
            subject_id: self.subject_id.clone(),
            fingerprint: self.fingerprint,
            operation_tag: self.operation_tag,
            digest: self.digest,
            mutation: clone_mutation(&self.mutation),
            terminal: self.terminal.clone(),
        }
    }
}

fn clone_mutation(mutation: &BoundGrantMutation) -> BoundGrantMutation {
    match mutation {
        BoundGrantMutation::Approve {
            request_id,
            decision_revision,
        } => BoundGrantMutation::Approve {
            request_id: request_id.clone(),
            decision_revision: decision_revision.clone(),
        },
        BoundGrantMutation::Deny {
            request_id,
            decision_revision,
            reason,
        } => BoundGrantMutation::Deny {
            request_id: request_id.clone(),
            decision_revision: decision_revision.clone(),
            reason: reason.clone(),
        },
        BoundGrantMutation::Narrow {
            request_id,
            decision_revision,
            params,
        } => BoundGrantMutation::Narrow {
            request_id: request_id.clone(),
            decision_revision: decision_revision.clone(),
            params: params.clone(),
        },
        BoundGrantMutation::Revoke { grant_id } => BoundGrantMutation::Revoke {
            grant_id: grant_id.clone(),
        },
        BoundGrantMutation::ApplyPreset {
            target_agent_id,
            preset,
        } => BoundGrantMutation::ApplyPreset {
            target_agent_id: target_agent_id.clone(),
            preset: preset.clone(),
        },
    }
}

struct JournalState {
    rows: HashMap<[u8; 32], JournalRow>,
}

struct RecoveryKeys {
    store_instance_id: [u8; 16],
    workspace_master_key: Zeroizing<[u8; 32]>,
}

/// Live CONTRACT-123 + CONTRACT-219 grant port.
pub struct Contract219GrantAdapter {
    intake: Arc<GrantApprovalIntake>,
    projector: Arc<Contract219EventProjector>,
    journal_path: Option<PathBuf>,
    boot: [u8; 16],
    persist_instance: [u8; 16],
    persist_ikm: [u8; 32],
    revision_mac_key: [u8; 32],
    ticket_key: [u8; 32],
    recovery: Option<RecoveryKeys>,
    compact_on_commit: bool,
    state: Mutex<JournalState>,
    execute_gate: Mutex<()>,
}

impl Contract219GrantAdapter {
    pub fn new(
        intake: Arc<GrantApprovalIntake>,
        projector: Arc<Contract219EventProjector>,
    ) -> Self {
        let persist_ikm = random_nonzero_32();
        let persist_instance = random_nonzero_16();
        Self {
            intake,
            projector,
            journal_path: None,
            boot: random_nonzero_16(),
            persist_instance,
            persist_ikm,
            revision_mac_key: random_nonzero_32(),
            ticket_key: derive_ticket_key(&persist_ikm, &persist_instance),
            recovery: None,
            compact_on_commit: true,
            state: Mutex::new(JournalState {
                rows: HashMap::new(),
            }),
            execute_gate: Mutex::new(()),
        }
    }

    pub fn with_recovery(
        intake: Arc<GrantApprovalIntake>,
        projector: Arc<Contract219EventProjector>,
        journal_path: PathBuf,
        ticket_ikm: [u8; 32],
        store_instance_id: [u8; 16],
        workspace_master_key: Zeroizing<[u8; 32]>,
    ) -> Result<Self, String> {
        let (boot, persist_instance, revision_mac_key, rows) =
            open_or_init_journal(&journal_path, &ticket_ikm)?;
        Ok(Self {
            intake,
            projector,
            journal_path: Some(journal_path),
            boot,
            persist_instance,
            persist_ikm: ticket_ikm,
            revision_mac_key,
            ticket_key: derive_ticket_key(&ticket_ikm, &persist_instance),
            recovery: Some(RecoveryKeys {
                store_instance_id,
                workspace_master_key,
            }),
            compact_on_commit: false,
            state: Mutex::new(JournalState { rows }),
            execute_gate: Mutex::new(()),
        })
    }

    /// MAC-valid revision whose generation matches `target` but whose
    /// `request_id_digest` is `foreign`. T17-rev-stale uses this so a
    /// generation+MAC-only verifier cannot stay green on cross-swap.
    #[cfg(feature = "test-support")]
    pub fn test_revision_binding_foreign_request(
        &self,
        target_request_id: &str,
        foreign_request_id: &str,
    ) -> Result<String, ProviderError> {
        let pending = match self.intake.inspect_request(target_request_id) {
            Some(RequestInspect::Pending {
                caller,
                generation,
                capability,
                params,
                ttl,
                justification,
            }) => PendingSnapshot {
                caller,
                generation,
                capability,
                params,
                ttl,
                justification,
            },
            _ => return Err(invalid_state("target request is not pending")),
        };
        let mut bytes = self.encode_revision_bytes(target_request_id, &pending)?;
        bytes[25..57].copy_from_slice(&request_id_digest(foreign_request_id));
        let mac = hmac_sha256(&self.revision_mac_key, REVISION_MAC_DOMAIN, &bytes[..153]);
        bytes[153..185].copy_from_slice(&mac);
        Ok(URL_SAFE_NO_PAD.encode(bytes))
    }

    /// MAC-valid revision that keeps request_id + generation but flips one
    /// admitted byte and remacs. Offsets: boot=1, source=57, fingerprint=89,
    /// document=121. T17-rev-stale uses this so a subset of
    /// request_id+generation+document+MAC is not enough.
    #[cfg(feature = "test-support")]
    pub fn test_revision_tampered_field(
        &self,
        target_request_id: &str,
        flip_offset: usize,
    ) -> Result<String, ProviderError> {
        if !(1..153).contains(&flip_offset) {
            return Err(invalid_state("flip offset must be an admitted field byte"));
        }
        let pending = match self.intake.inspect_request(target_request_id) {
            Some(RequestInspect::Pending {
                caller,
                generation,
                capability,
                params,
                ttl,
                justification,
            }) => PendingSnapshot {
                caller,
                generation,
                capability,
                params,
                ttl,
                justification,
            },
            _ => return Err(invalid_state("target request is not pending")),
        };
        let mut bytes = self.encode_revision_bytes(target_request_id, &pending)?;
        bytes[flip_offset] ^= 1;
        let mac = hmac_sha256(&self.revision_mac_key, REVISION_MAC_DOMAIN, &bytes[..153]);
        bytes[153..185].copy_from_slice(&mac);
        Ok(URL_SAFE_NO_PAD.encode(bytes))
    }

    /// MAC-valid revision that keeps request_id + generation but flips
    /// `document_digest`.
    #[cfg(feature = "test-support")]
    pub fn test_revision_tampered_document_digest(
        &self,
        target_request_id: &str,
    ) -> Result<String, ProviderError> {
        self.test_revision_tampered_field(target_request_id, 121)
    }

    /// Ticket that keeps admitted fields and a valid overlay MAC after the
    /// provider-record digest is flipped. T23-ticket-neg uses this so the
    /// `SHA-256(row.intent) == digest` step is witnessed independently of MAC.
    #[cfg(feature = "test-support")]
    pub fn test_recovery_mac_valid_digest_tamper(
        &self,
        recovery: &ProviderMutationRecovery,
    ) -> ProviderMutationRecovery {
        let mut bytes = *recovery.as_provider_bytes();
        bytes[71] ^= 1;
        let mac = hmac_sha256(&self.ticket_key, TICKET_MAC_DOMAIN, &bytes[..135]);
        bytes[135..167].copy_from_slice(&mac);
        ProviderMutationRecovery::from_provider_bytes(bytes)
            .expect("reminted digest-tampered ticket")
    }

    #[cfg(feature = "test-support")]
    pub fn test_journal_row_count(&self) -> usize {
        self.lock_state().rows.len()
    }

    #[cfg(feature = "test-support")]
    pub fn test_journal_tmp_path(path: &Path) -> PathBuf {
        journal_tmp_path(path)
    }

    #[cfg(feature = "test-support")]
    pub fn test_reset_journal_bytes_read() {
        JOURNAL_BYTES_READ.store(0, Ordering::SeqCst);
    }

    #[cfg(feature = "test-support")]
    pub fn test_journal_bytes_read() -> u64 {
        JOURNAL_BYTES_READ.load(Ordering::SeqCst)
    }

    fn lock_state(&self) -> std::sync::MutexGuard<'_, JournalState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn persist_all(&self, state: &JournalState) -> Result<(), std::io::Error> {
        let Some(path) = self.journal_path.as_ref() else {
            return Ok(());
        };
        persist_journal(
            path,
            &self.persist_ikm,
            &self.boot,
            &self.persist_instance,
            &self.revision_mac_key,
            state,
        )
    }

    fn mint_ticket(
        &self,
        mutation_id: [u8; 32],
        fingerprint: [u8; 32],
        operation_tag: u8,
        digest: [u8; 32],
        nonce: [u8; 32],
    ) -> Result<ProviderMutationRecovery, ProviderError> {
        let mut bytes = [0u8; TICKET_LEN];
        bytes[0] = 1;
        bytes[1] = PROVIDER_TAG;
        bytes[2] = operation_tag;
        bytes[3..7].copy_from_slice(&1u32.to_be_bytes());
        bytes[7..39].copy_from_slice(&mutation_id);
        bytes[39..71].copy_from_slice(&fingerprint);
        bytes[71..103].copy_from_slice(&digest);
        bytes[103..135].copy_from_slice(&nonce);
        let mac = hmac_sha256(&self.ticket_key, TICKET_MAC_DOMAIN, &bytes[..135]);
        bytes[135..167].copy_from_slice(&mac);
        ProviderMutationRecovery::from_provider_bytes(bytes)
    }

    fn apply_prepared(&self, mutation_id: [u8; 32]) -> BoundMutationOutcome {
        let _execute = self
            .execute_gate
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let (row, ticket) = {
            let state = self.lock_state();
            let Some(row) = state.rows.get(&mutation_id).cloned() else {
                return BoundMutationOutcome::Rejected(ProviderError::NotFound(
                    "grant journal row not found".to_owned(),
                ));
            };
            let ticket = match self.mint_ticket(
                mutation_id,
                row.fingerprint,
                row.operation_tag,
                row.digest,
                row.nonce,
            ) {
                Ok(ticket) => ticket,
                Err(error) => return BoundMutationOutcome::Rejected(error),
            };
            (row, ticket)
        };

        if let Some(terminal) = row.terminal.as_ref() {
            return self.bind_terminal(row.subject_id.as_deref(), terminal, ticket);
        }

        let outcome = match &row.mutation {
            BoundGrantMutation::Approve {
                request_id,
                decision_revision,
            } => self.execute_decide(request_id, decision_revision, DecideOp::Approve),
            BoundGrantMutation::Deny {
                request_id,
                decision_revision,
                reason,
            } => self.execute_decide(
                request_id,
                decision_revision,
                DecideOp::Deny { reason },
            ),
            BoundGrantMutation::Narrow {
                request_id,
                decision_revision,
                params,
            } => self.execute_decide(
                request_id,
                decision_revision,
                DecideOp::Narrow { params },
            ),
            BoundGrantMutation::Revoke { grant_id } => self.execute_revoke(grant_id),
            BoundGrantMutation::ApplyPreset {
                target_agent_id,
                preset,
            } => self.execute_preset(target_agent_id, preset),
        };

        match outcome {
            Ok((live_subject, terminal)) => {
                {
                    let mut state = self.lock_state();
                    if let Some(row) = state.rows.get_mut(&mutation_id) {
                        row.subject_id = Some(live_subject.clone());
                        row.terminal = Some(terminal.clone());
                    }
                    let _ = self.persist_all(&state);
                }
                let bind = self.bind_terminal(Some(&live_subject), &terminal, ticket);
                if matches!(bind, BoundMutationOutcome::Committed(_))
                    && self.compact_on_commit
                    && !matches!(terminal, TerminalKind::Preset { .. })
                {
                    let mut state = self.lock_state();
                    state.rows.remove(&mutation_id);
                }
                bind
            }
            Err(error) => {
                if self.compact_on_commit {
                    let mut state = self.lock_state();
                    if state
                        .rows
                        .get(&mutation_id)
                        .is_some_and(|row| row.terminal.is_none())
                    {
                        state.rows.remove(&mutation_id);
                    }
                }
                BoundMutationOutcome::Rejected(error)
            }
        }
    }

    fn bind_terminal(
        &self,
        subject_id: Option<&str>,
        terminal: &TerminalKind,
        ticket: ProviderMutationRecovery,
    ) -> BoundMutationOutcome {
        match self
            .projector
            .bind_grant_result(subject_id, terminal_root(terminal))
        {
            Ok(document) => BoundMutationOutcome::Committed(document),
            Err(_) => BoundMutationOutcome::OutcomeUnknown(ticket),
        }
    }

    fn execute_decide(
        &self,
        request_id: &str,
        decision_revision: &str,
        op: DecideOp<'_>,
    ) -> Result<(String, TerminalKind), ProviderError> {
        let pending = match self.intake.inspect_request(request_id) {
            None => {
                return Err(ProviderError::NotFound(
                    "pending grant request not found".to_owned(),
                ))
            }
            Some(RequestInspect::Decided) => {
                return Err(map_cap_error(CapGrantError::PermissionDenied(format!(
                    "grant-approval-intake: request {request_id} already decided"
                ))))
            }
            Some(RequestInspect::Pending {
                caller,
                generation,
                capability,
                params,
                ttl,
                justification,
            }) => PendingSnapshot {
                caller,
                generation,
                capability,
                params,
                ttl,
                justification,
            },
        };
        self.projector
            .require_live_source(&pending.caller)
            .map_err(ProviderError::Unavailable)?;
        self.verify_revision(request_id, decision_revision, &pending)?;
        if !matches!(op, DecideOp::Deny { .. }) {
            if params_contain_sensitive(pending.params.as_deref(), true) {
                return Err(invalid_state(
                    "sensitive pending params cannot be approved or narrowed",
                ));
            }
            if params_contain_noncanonical(pending.params.as_deref()) {
                return Err(invalid_state(
                    "pending params contain characters dropped by leak-scan canonicalization",
                ));
            }
        }
        match op {
            DecideOp::Approve => self
                .intake
                .approve_if_generation(request_id, pending.generation)
                .map_err(map_cap_error)?,
            DecideOp::Deny { reason } => self
                .intake
                .deny_if_generation(request_id, pending.generation, reason)
                .map_err(map_cap_error)?,
            DecideOp::Narrow { params } => {
                let mapped: Vec<CapParam> = params
                    .iter()
                    .map(|param| CapParam {
                        key: param.key.clone(),
                        value: param.value.clone(),
                    })
                    .collect();
                if params_contain_sensitive(Some(&mapped), false) {
                    return Err(invalid_state(
                        "sensitive narrow params cannot be applied",
                    ));
                }
                if params_contain_noncanonical(Some(&mapped)) {
                    return Err(invalid_state(
                        "narrow params contain characters dropped by leak-scan canonicalization",
                    ));
                }
                self.intake
                    .narrow_if_generation(request_id, pending.generation, mapped)
                    .map_err(map_cap_error)?;
            }
        }
        let status = match op {
            DecideOp::Approve => "approved",
            DecideOp::Deny { .. } => "denied",
            DecideOp::Narrow { .. } => "narrowed",
        };
        Ok((
            pending.caller,
            TerminalKind::Decision {
                request_id: request_id.to_owned(),
                status: status.to_owned(),
            },
        ))
    }

    fn execute_revoke(&self, grant_id: &str) -> Result<(String, TerminalKind), ProviderError> {
        let grant = self.intake.snapshot_grant(grant_id).ok_or_else(|| {
            ProviderError::NotFound("grant not found".to_owned())
        })?;
        if grant.status != GrantStatus::Active
            || matches!(grant.provenance, GrantProvenance::StaticConfig)
        {
            return Err(ProviderError::NotFound(
                "grant not found".to_owned(),
            ));
        }
        self.projector
            .require_live_source(&grant.grantee)
            .map_err(ProviderError::Unavailable)?;
        let revoked_count = self.intake.revoke(grant_id).map_err(map_cap_error)? as u64;
        Ok((
            grant.grantee,
            TerminalKind::Revoke {
                grant_id: grant_id.to_owned(),
                revoked_count,
            },
        ))
    }

    fn execute_preset(
        &self,
        target_agent_id: &str,
        preset: &str,
    ) -> Result<(String, TerminalKind), ProviderError> {
        self.projector
            .require_live_source(target_agent_id)
            .map_err(ProviderError::Unavailable)?;
        let created = self
            .intake
            .apply_preset(target_agent_id, preset)
            .map_err(map_cap_error)?;
        Ok((
            target_agent_id.to_owned(),
            TerminalKind::Preset {
                preset: preset.to_owned(),
                target: target_agent_id.to_owned(),
                created_grant_ids: created.into_iter().map(|id| id.to_string()).collect(),
            },
        ))
    }

    fn verify_revision(
        &self,
        request_id: &str,
        revision: &str,
        pending: &PendingSnapshot,
    ) -> Result<(), ProviderError> {
        let decoded = URL_SAFE_NO_PAD
            .decode(revision)
            .map_err(|_| invalid_state("invalid decision revision"))?;
        if decoded.len() != REVISION_LEN || URL_SAFE_NO_PAD.encode(&decoded) != revision {
            return Err(invalid_state("invalid decision revision"));
        }
        let expected = self.encode_revision_bytes(request_id, pending)?;
        if bool::from(decoded.ct_eq(&expected)) {
            Ok(())
        } else {
            Err(invalid_state("stale or swapped decision revision"))
        }
    }

    fn encode_revision_bytes(
        &self,
        request_id: &str,
        pending: &PendingSnapshot,
    ) -> Result<[u8; REVISION_LEN], ProviderError> {
        let source = self
            .projector
            .live_source_binding_digest(&pending.caller)
            .map_err(ProviderError::Unavailable)?;
        let fingerprint = request_fingerprint(pending);
        let document = document_digest(request_id, pending)?;
        let mut bytes = [0u8; REVISION_LEN];
        bytes[0] = 1;
        bytes[1..17].copy_from_slice(&self.boot);
        bytes[17..25].copy_from_slice(&pending.generation.to_be_bytes());
        bytes[25..57].copy_from_slice(&request_id_digest(request_id));
        bytes[57..89].copy_from_slice(&source);
        bytes[89..121].copy_from_slice(&fingerprint);
        bytes[121..153].copy_from_slice(&document);
        let mac = hmac_sha256(&self.revision_mac_key, REVISION_MAC_DOMAIN, &bytes[..153]);
        bytes[153..185].copy_from_slice(&mac);
        Ok(bytes)
    }

    fn encode_revision(
        &self,
        request_id: &str,
        pending: &PendingSnapshot,
    ) -> Result<String, ProviderError> {
        Ok(URL_SAFE_NO_PAD.encode(self.encode_revision_bytes(request_id, pending)?))
    }

    fn prepare_subject(&self, mutation: &BoundGrantMutation) -> Option<String> {
        match mutation {
            BoundGrantMutation::Approve { request_id, .. }
            | BoundGrantMutation::Deny { request_id, .. }
            | BoundGrantMutation::Narrow { request_id, .. } => {
                match self.intake.inspect_request(request_id) {
                    Some(RequestInspect::Pending { caller, .. }) => Some(caller),
                    _ => None,
                }
            }
            BoundGrantMutation::Revoke { grant_id } => self
                .intake
                .snapshot_grant(grant_id)
                .filter(|grant| grant.status == GrantStatus::Active)
                .map(|grant| grant.grantee),
            BoundGrantMutation::ApplyPreset { target_agent_id, .. } => {
                Some(target_agent_id.clone())
            }
        }
    }
}

enum DecideOp<'a> {
    Approve,
    Deny { reason: &'a str },
    Narrow { params: &'a [ClientCapParam] },
}

struct PendingSnapshot {
    caller: String,
    generation: u64,
    capability: String,
    params: Option<Vec<CapParam>>,
    ttl: GrantTtl,
    justification: Option<String>,
}

impl BoundGrantApprovalPort for Contract219GrantAdapter {
    fn list_pending_bound(&self) -> Result<Vec<BoundObservationDocument>, ProviderError> {
        let mut documents = Vec::new();
        for pending in self.intake.list_pending() {
            let snapshot = PendingSnapshot {
                caller: pending.caller.clone(),
                generation: pending.generation,
                capability: pending.capability.clone(),
                params: pending.params.clone(),
                ttl: pending.ttl.clone(),
                justification: pending.justification.clone(),
            };
            let Ok(revision) = self.encode_revision(&pending.request_id, &snapshot) else {
                continue;
            };
            let display = PendingSnapshot {
                caller: snapshot.caller.clone(),
                generation: snapshot.generation,
                capability: snapshot.capability.clone(),
                params: redact_sensitive_param_values(snapshot.params.as_deref()),
                ttl: snapshot.ttl.clone(),
                justification: snapshot.justification.clone(),
            };
            let root = pending_root(&pending.request_id, Some(&revision), &display);
            if let Ok(bound) = self.projector.bind_pending_grant(&pending.caller, root) {
                documents.push(bound);
            }
        }
        Ok(documents)
    }

    fn prepare_mutation_bound(
        &self,
        mutation_id: [u8; 32],
        request_fingerprint: [u8; 32],
        mutation: BoundGrantMutation,
    ) -> ProviderPrepareOutcome {
        let operation_tag = mutation.operation_tag();
        let subject_id = self.prepare_subject(&mutation);
        let intent = encode_intent(
            mutation_id,
            request_fingerprint,
            operation_tag,
            subject_id.as_deref(),
            &mutation,
        );
        let digest: [u8; 32] = Sha256::digest(&intent).into();

        let mut state = self.lock_state();
        if let Some(existing) = state.rows.get(&mutation_id) {
            if existing.fingerprint == request_fingerprint && existing.operation_tag == operation_tag
            {
                if !bool::from(existing.digest.ct_eq(&digest)) {
                    return ProviderPrepareOutcome::Rejected(invalid_state(
                        "grant journal mutation_id reused with a different intent",
                    ));
                }
                return match self.mint_ticket(
                    mutation_id,
                    existing.fingerprint,
                    existing.operation_tag,
                    existing.digest,
                    existing.nonce,
                ) {
                    Ok(ticket) => ProviderPrepareOutcome::Prepared(ticket),
                    Err(error) => ProviderPrepareOutcome::Rejected(error),
                };
            }
            return ProviderPrepareOutcome::Rejected(invalid_state(
                "grant journal mutation_id reused with a different fingerprint",
            ));
        }

        let nonce = random_nonzero_32();
        state.rows.insert(
            mutation_id,
            JournalRow {
                intent,
                nonce,
                subject_id,
                fingerprint: request_fingerprint,
                operation_tag,
                digest,
                mutation,
                terminal: None,
            },
        );
        if let Err(error) = self.persist_all(&state) {
            state.rows.remove(&mutation_id);
            return ProviderPrepareOutcome::Rejected(ProviderError::Unavailable(format!(
                "grant journal persist: {error}"
            )));
        }
        match self.mint_ticket(
            mutation_id,
            request_fingerprint,
            operation_tag,
            digest,
            nonce,
        ) {
            Ok(ticket) => ProviderPrepareOutcome::Prepared(ticket),
            Err(error) => {
                state.rows.remove(&mutation_id);
                ProviderPrepareOutcome::Rejected(error)
            }
        }
    }

    fn verify_recovery_ticket_bound(
        &self,
        mutation_id: [u8; 32],
        request_fingerprint: [u8; 32],
        operation_tag: u8,
        recovery: &ProviderMutationRecovery,
    ) -> Result<(), ProviderError> {
        let bytes = *recovery.as_provider_bytes();
        let parsed = ProviderMutationRecovery::from_provider_bytes(bytes)?;
        let parsed_bytes = parsed.as_provider_bytes();
        if parsed_bytes[7..39] != mutation_id
            || parsed_bytes[39..71] != request_fingerprint
            || parsed_bytes[2] != operation_tag
        {
            return Err(invalid_state("recovery ticket field mismatch"));
        }
        let expected_mac = hmac_sha256(&self.ticket_key, TICKET_MAC_DOMAIN, &parsed_bytes[..135]);
        if !bool::from(expected_mac.ct_eq(&parsed_bytes[135..167])) {
            return Err(invalid_state("recovery ticket MAC mismatch"));
        }
        let state = self.lock_state();
        let row = state
            .rows
            .get(&mutation_id)
            .ok_or_else(|| invalid_state("recovery ticket has no journal row"))?;
        let digest: [u8; 32] = Sha256::digest(&row.intent).into();
        if !bool::from(digest.ct_eq(&parsed_bytes[71..103])) {
            return Err(invalid_state("recovery ticket digest mismatch"));
        }
        Ok(())
    }

    fn execute_prepared_bound(&self, recovery: &ProviderMutationRecovery) -> BoundMutationOutcome {
        let bytes = recovery.as_provider_bytes();
        let mut mutation_id = [0u8; 32];
        mutation_id.copy_from_slice(&bytes[7..39]);
        self.apply_prepared(mutation_id)
    }

    fn recover_mutation_bound(&self, recovery: &ProviderMutationRecovery) -> BoundMutationOutcome {
        self.execute_prepared_bound(recovery)
    }

    fn acknowledge_client_done_bound(
        &self,
        done: &ProviderClientDoneReceipt,
    ) -> Result<(), ProviderError> {
        let bytes = *done.as_provider_bytes();
        if bytes.len() != DONE_RECEIPT_LEN
            || bytes[0] != 1
            || bytes[1] != PROVIDER_TAG
            || !(1..=5).contains(&bytes[2])
            || bytes[219..251].iter().all(|byte| *byte == 0)
        {
            return Err(invalid_state("invalid client done receipt"));
        }
        let mut mutation_id = [0u8; 32];
        mutation_id.copy_from_slice(&bytes[123..155]);
        if let Some(recovery) = self.recovery.as_ref() {
            if !bool::from(bytes[3..19].ct_eq(&recovery.store_instance_id)) {
                return Err(invalid_state("done receipt store instance mismatch"));
            }
            let key = derive_done_receipt_key(
                &*recovery.workspace_master_key,
                &recovery.store_instance_id,
            );
            let mac = hmac_sha256(&key, DONE_RECEIPT_MAC_DOMAIN, &bytes[..251]);
            if !bool::from(mac.ct_eq(&bytes[251..283])) {
                return Err(invalid_state("done receipt MAC mismatch"));
            }
            let state = self.lock_state();
            if let Some(row) = state.rows.get(&mutation_id) {
                if !bool::from(bytes[155..187].ct_eq(&row.fingerprint)) {
                    return Err(invalid_state("done receipt fingerprint mismatch"));
                }
            }
        }
        let mut state = self.lock_state();
        state.rows.remove(&mutation_id);
        let _ = self.persist_all(&state);
        Ok(())
    }
}

fn value_is_sensitive(value: &str) -> bool {
    matches!(
        DefaultLeakDetector::new().scan(value, ScanContext::LogOutput),
        ScanResult::Blocked { .. } | ScanResult::Redacted { .. }
    )
}

fn params_contain_sensitive(params: Option<&[CapParam]>, skip_api_key: bool) -> bool {
    let Some(params) = params else {
        return false;
    };
    params.iter().any(|param| {
        (!skip_api_key || param.key != "api_key") && value_is_sensitive(&param.value)
    })
}

fn redact_sensitive_param_values(params: Option<&[CapParam]>) -> Option<Vec<CapParam>> {
    params.map(|params| {
        params
            .iter()
            .map(|param| {
                if param.key != "api_key" && value_is_sensitive(&param.value) {
                    CapParam {
                        key: param.key.clone(),
                        value: "[REDACTED]".to_owned(),
                    }
                } else {
                    param.clone()
                }
            })
            .collect()
    })
}

fn params_contain_noncanonical(params: Option<&[CapParam]>) -> bool {
    let Some(params) = params else {
        return false;
    };
    params
        .iter()
        .any(|param| canonical_scan_text(&param.value) != param.value)
}

fn pending_root(
    request_id: &str,
    revision: Option<&str>,
    pending: &PendingSnapshot,
) -> ObservationNode {
    let mut fields = vec![
        (
            "kind".to_owned(),
            ObservationNode::String("pending_grant".to_owned()),
        ),
        (
            "request_id".to_owned(),
            ObservationNode::String(request_id.to_owned()),
        ),
    ];
    if let Some(revision) = revision {
        fields.push((
            "decision_revision".to_owned(),
            ObservationNode::String(revision.to_owned()),
        ));
    }
    fields.extend([
        (
            "caller_id".to_owned(),
            ObservationNode::String(pending.caller.clone()),
        ),
        (
            "capability".to_owned(),
            ObservationNode::String(pending.capability.clone()),
        ),
        ("params".to_owned(), params_node(pending.params.as_deref())),
        ("ttl".to_owned(), ttl_node(&pending.ttl)),
        (
            "justification".to_owned(),
            pending
                .justification
                .as_ref()
                .map(|value| ObservationNode::String(value.clone()))
                .unwrap_or(ObservationNode::Null),
        ),
    ]);
    ObservationNode::Object(fields)
}

fn params_node(params: Option<&[CapParam]>) -> ObservationNode {
    match params {
        None => ObservationNode::Null,
        Some(params) => {
            let mut values: Vec<CanonicalCapParam> = params
                .iter()
                .map(|param| CanonicalCapParam {
                    key: param.key.clone(),
                    value: ObservationNode::String(param.value.clone()),
                })
                .collect();
            values.sort_by(|left, right| left.key.cmp(&right.key));
            ObservationNode::CanonicalCapParams(values)
        }
    }
}

fn ttl_node(ttl: &GrantTtl) -> ObservationNode {
    match ttl {
        GrantTtl::Once => ObservationNode::Object(vec![(
            "kind".to_owned(),
            ObservationNode::String("once".to_owned()),
        )]),
        GrantTtl::Lifecycle => ObservationNode::Object(vec![(
            "kind".to_owned(),
            ObservationNode::String("lifecycle".to_owned()),
        )]),
        GrantTtl::Persistent => ObservationNode::Object(vec![(
            "kind".to_owned(),
            ObservationNode::String("persistent".to_owned()),
        )]),
        GrantTtl::Duration(milliseconds) => ObservationNode::Object(vec![
            (
                "kind".to_owned(),
                ObservationNode::String("duration".to_owned()),
            ),
            (
                "milliseconds_u64".to_owned(),
                ObservationNode::String(milliseconds.to_string()),
            ),
        ]),
        GrantTtl::Until(at) => ObservationNode::Object(vec![
            (
                "kind".to_owned(),
                ObservationNode::String("until".to_owned()),
            ),
            (
                "at".to_owned(),
                ObservationNode::String(at.to_rfc3339_opts(SecondsFormat::Secs, true)),
            ),
        ]),
    }
}

fn terminal_root(terminal: &TerminalKind) -> ObservationNode {
    match terminal {
        TerminalKind::Decision {
            request_id,
            status,
        } => ObservationNode::Object(vec![
            (
                "kind".to_owned(),
                ObservationNode::String("grant_decision".to_owned()),
            ),
            (
                "request_id".to_owned(),
                ObservationNode::String(request_id.clone()),
            ),
            (
                "status".to_owned(),
                ObservationNode::String(status.clone()),
            ),
        ]),
        TerminalKind::Revoke {
            grant_id,
            revoked_count,
        } => ObservationNode::Object(vec![
            (
                "kind".to_owned(),
                ObservationNode::String("grant_revoke".to_owned()),
            ),
            (
                "grant_id".to_owned(),
                ObservationNode::String(grant_id.clone()),
            ),
            (
                "status".to_owned(),
                ObservationNode::String("revoked".to_owned()),
            ),
            (
                "revoked_count".to_owned(),
                ObservationNode::Number(revoked_count.to_string()),
            ),
        ]),
        TerminalKind::Preset {
            preset,
            target,
            created_grant_ids,
        } => ObservationNode::Object(vec![
            (
                "kind".to_owned(),
                ObservationNode::String("preset_apply".to_owned()),
            ),
            (
                "preset".to_owned(),
                ObservationNode::String(preset.clone()),
            ),
            (
                "target_agent_id".to_owned(),
                ObservationNode::String(target.clone()),
            ),
            (
                "status".to_owned(),
                ObservationNode::String("applied".to_owned()),
            ),
            (
                "created_grant_ids".to_owned(),
                ObservationNode::Array(
                    created_grant_ids
                        .iter()
                        .map(|id| ObservationNode::String(id.clone()))
                        .collect(),
                ),
            ),
        ]),
    }
}

fn request_id_digest(request_id: &str) -> [u8; 32] {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(REQUEST_ID_DOMAIN);
    put_text(&mut bytes, request_id);
    Sha256::digest(bytes).into()
}

fn request_fingerprint(pending: &PendingSnapshot) -> [u8; 32] {
    let mut canonical = vec![1u8];
    put_text(&mut canonical, &pending.caller);
    put_text(&mut canonical, &pending.capability);
    match pending.params.as_ref() {
        None => canonical.push(0),
        Some(params) => {
            canonical.push(1);
            canonical.extend_from_slice(&(params.len() as u32).to_be_bytes());
            for param in params {
                put_text(&mut canonical, &param.key);
                put_text(&mut canonical, &param.value);
            }
        }
    }
    match &pending.ttl {
        GrantTtl::Once => canonical.push(1),
        GrantTtl::Lifecycle => canonical.push(2),
        GrantTtl::Persistent => canonical.push(3),
        GrantTtl::Duration(milliseconds) => {
            canonical.push(4);
            canonical.extend_from_slice(&milliseconds.to_be_bytes());
        }
        GrantTtl::Until(at) => {
            canonical.push(5);
            put_text(
                &mut canonical,
                &at.to_rfc3339_opts(SecondsFormat::Secs, true),
            );
        }
    }
    match pending.justification.as_ref() {
        None => canonical.push(0),
        Some(justification) => {
            canonical.push(1);
            put_text(&mut canonical, justification);
        }
    }
    let mut bytes = Vec::new();
    bytes.extend_from_slice(REQUEST_FP_DOMAIN);
    bytes.extend_from_slice(&canonical);
    Sha256::digest(bytes).into()
}

fn document_digest(
    request_id: &str,
    pending: &PendingSnapshot,
) -> Result<[u8; 32], ProviderError> {
    let root = pending_root(request_id, None, pending);
    let document = ObservationDocument::provider_dto(root);
    let encoded = encode_canonical_document(&document).map_err(|error| {
        ProviderError::Unavailable(format!("pending document encode: {error}"))
    })?;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(DOCUMENT_DOMAIN);
    bytes.extend_from_slice(&encoded);
    Ok(Sha256::digest(bytes).into())
}

fn encode_intent(
    mutation_id: [u8; 32],
    fingerprint: [u8; 32],
    operation_tag: u8,
    subject_id: Option<&str>,
    mutation: &BoundGrantMutation,
) -> Vec<u8> {
    let mut bytes = vec![1u8];
    bytes.extend_from_slice(&mutation_id);
    bytes.extend_from_slice(&fingerprint);
    bytes.push(operation_tag);
    put_text(&mut bytes, subject_id.unwrap_or(""));
    match mutation {
        BoundGrantMutation::Approve {
            request_id,
            decision_revision,
        } => {
            put_text(&mut bytes, request_id);
            put_text(&mut bytes, decision_revision);
        }
        BoundGrantMutation::Deny {
            request_id,
            decision_revision,
            reason,
        } => {
            put_text(&mut bytes, request_id);
            put_text(&mut bytes, decision_revision);
            put_text(&mut bytes, reason);
        }
        BoundGrantMutation::Narrow {
            request_id,
            decision_revision,
            params,
        } => {
            put_text(&mut bytes, request_id);
            put_text(&mut bytes, decision_revision);
            bytes.extend_from_slice(&(params.len() as u32).to_be_bytes());
            for param in params {
                put_text(&mut bytes, &param.key);
                put_text(&mut bytes, &param.value);
            }
        }
        BoundGrantMutation::Revoke { grant_id } => put_text(&mut bytes, grant_id),
        BoundGrantMutation::ApplyPreset {
            preset,
            target_agent_id,
        } => {
            put_text(&mut bytes, preset);
            put_text(&mut bytes, target_agent_id);
        }
    }
    bytes
}

fn decode_intent(bytes: &[u8]) -> Result<(JournalRow, usize), String> {
    let mut cursor = DecodeCursor { input: bytes, offset: 0 };
    if cursor.byte()? != 1 {
        return Err("invalid prepared-intent version".to_owned());
    }
    let mutation_id = cursor.array::<32>()?;
    let fingerprint = cursor.array::<32>()?;
    let operation_tag = cursor.byte()?;
    let subject = cursor.text()?;
    let subject_id = if subject.is_empty() {
        None
    } else {
        Some(subject)
    };
    let mutation = match operation_tag {
        1 => BoundGrantMutation::Approve {
            request_id: cursor.text()?,
            decision_revision: cursor.text()?,
        },
        2 => BoundGrantMutation::Deny {
            request_id: cursor.text()?,
            decision_revision: cursor.text()?,
            reason: cursor.text()?,
        },
        3 => {
            let request_id = cursor.text()?;
            let decision_revision = cursor.text()?;
            let declared = cursor.u32()?;
            let count = cursor.bounded_count(declared, 8)?;
            let mut params = Vec::with_capacity(count);
            for _ in 0..count {
                params.push(ClientCapParam {
                    key: cursor.text()?,
                    value: cursor.text()?,
                });
            }
            BoundGrantMutation::Narrow {
                request_id,
                decision_revision,
                params,
            }
        }
        4 => BoundGrantMutation::Revoke {
            grant_id: cursor.text()?,
        },
        5 => BoundGrantMutation::ApplyPreset {
            preset: cursor.text()?,
            target_agent_id: cursor.text()?,
        },
        _ => return Err("invalid operation tag".to_owned()),
    };
    let _ = mutation_id;
    let consumed = cursor.offset;
    let digest: [u8; 32] = Sha256::digest(&bytes[..consumed]).into();
    Ok((
        JournalRow {
            intent: bytes[..consumed].to_vec(),
            nonce: [0; 32],
            subject_id,
            fingerprint,
            operation_tag,
            digest,
            mutation,
            terminal: None,
        },
        consumed,
    ))
}

struct DecodeCursor<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> DecodeCursor<'a> {
    fn byte(&mut self) -> Result<u8, String> {
        let value = *self.input.get(self.offset).ok_or("truncated journal")?;
        self.offset += 1;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], String> {
        let end = self
            .offset
            .checked_add(N)
            .ok_or_else(|| "truncated journal".to_owned())?;
        let slice = self.input.get(self.offset..end).ok_or("truncated journal")?;
        self.offset = end;
        Ok(slice.try_into().expect("checked length"))
    }

    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn bounded_count(&self, count: u32, min_item_bytes: usize) -> Result<usize, String> {
        let remaining = self.input.len().saturating_sub(self.offset);
        let count = count as usize;
        let max = remaining / min_item_bytes.max(1);
        if count > max {
            return Err("journal count exceeds remaining bytes".to_owned());
        }
        Ok(count)
    }

    fn text(&mut self) -> Result<String, String> {
        let len = self.u32()? as usize;
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| "truncated journal".to_owned())?;
        let slice = self.input.get(self.offset..end).ok_or("truncated journal")?;
        self.offset = end;
        String::from_utf8(slice.to_vec()).map_err(|_| "invalid utf-8".to_owned())
    }

}

fn open_or_init_journal(
    path: &Path,
    ticket_ikm: &[u8; 32],
) -> Result<
    (
        [u8; 16],
        [u8; 16],
        [u8; 32],
        HashMap<[u8; 32], JournalRow>,
    ),
    String,
> {
    match std::fs::metadata(path) {
        Err(error) if error.kind() == ErrorKind::NotFound => init_empty_journal(path, ticket_ikm),
        Err(error) => Err(format!("read grant journal: {error}")),
        Ok(meta) if !meta.is_file() => Err("grant journal is not a regular file".to_owned()),
        Ok(meta) if meta.len() == 0 => init_empty_journal(path, ticket_ikm),
        Ok(_) => {
            let bytes = read_journal_capped(path)?;
            if bytes.is_empty() {
                init_empty_journal(path, ticket_ikm)
            } else {
                load_journal(&bytes, ticket_ikm)
            }
        }
    }
}

struct CountingRead<R> {
    inner: R,
}

impl<R: Read> Read for CountingRead<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        #[cfg(feature = "test-support")]
        JOURNAL_BYTES_READ.fetch_add(n as u64, Ordering::SeqCst);
        Ok(n)
    }
}

fn read_journal_capped(path: &Path) -> Result<Vec<u8>, String> {
    let file = File::open(path).map_err(|error| format!("read grant journal: {error}"))?;
    let mut bytes = Vec::new();
    CountingRead { inner: file }
        .take(MAX_JOURNAL_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read grant journal: {error}"))?;
    if (bytes.len() as u64) > MAX_JOURNAL_BYTES {
        return Err("grant journal exceeds size limit".to_owned());
    }
    Ok(bytes)
}

fn init_empty_journal(
    path: &Path,
    ticket_ikm: &[u8; 32],
) -> Result<
    (
        [u8; 16],
        [u8; 16],
        [u8; 32],
        HashMap<[u8; 32], JournalRow>,
    ),
    String,
> {
    let boot = random_nonzero_16();
    let instance = random_nonzero_16();
    let revision_mac_key = random_nonzero_32();
    persist_journal(
        path,
        ticket_ikm,
        &boot,
        &instance,
        &revision_mac_key,
        &JournalState {
            rows: HashMap::new(),
        },
    )
    .map_err(|error| format!("init grant journal: {error}"))?;
    Ok((boot, instance, revision_mac_key, HashMap::new()))
}

fn journal_tmp_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(std::ffi::OsStr::to_os_string)
        .unwrap_or_else(|| "journal".into());
    name.push(".tmp");
    path.with_file_name(name)
}

fn persist_journal(
    path: &Path,
    ticket_ikm: &[u8; 32],
    boot: &[u8; 16],
    instance: &[u8; 16],
    revision_mac_key: &[u8; 32],
    state: &JournalState,
) -> Result<(), std::io::Error> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(JOURNAL_MAGIC);
    header.push(1);
    header.extend_from_slice(boot);
    header.extend_from_slice(instance);
    header.extend_from_slice(revision_mac_key);
    let mac = hmac_sha256(ticket_ikm, HEADER_MAC_DOMAIN, &header);
    header.extend_from_slice(&mac);

    let mut payload = Vec::new();
    payload.extend_from_slice(&(state.rows.len() as u32).to_be_bytes());
    let mut keys: Vec<[u8; 32]> = state.rows.keys().copied().collect();
    keys.sort();
    for key in keys {
        let row = &state.rows[&key];
        let body = encode_row(row);
        let tag = if row.terminal.is_some() { 2u8 } else { 1u8 };
        payload.push(tag);
        payload.extend_from_slice(&(body.len() as u32).to_be_bytes());
        payload.extend_from_slice(&body);
    }

    let mut frame = header;
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&payload);
    if (frame.len() as u64) > MAX_JOURNAL_BYTES {
        return Err(std::io::Error::new(
            ErrorKind::InvalidInput,
            "grant journal exceeds size limit",
        ));
    }

    let tmp = journal_tmp_path(path);
    {
        let mut file = create_exclusive_journal_tmp(&tmp)?;
        file.write_all(&frame)?;
        file.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn create_exclusive_journal_tmp(tmp: &Path) -> Result<std::fs::File, std::io::Error> {
    match std::fs::symlink_metadata(tmp) {
        Ok(meta) if meta.file_type().is_dir() => {
            return Err(std::io::Error::new(
                ErrorKind::AlreadyExists,
                "journal tmp path is a directory",
            ));
        }
        Ok(_) => {
            std::fs::remove_file(tmp)?;
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    OpenOptions::new().write(true).create_new(true).open(tmp)
}

fn encode_row(row: &JournalRow) -> Vec<u8> {
    let mut bytes = row.intent.clone();
    bytes.extend_from_slice(&row.nonce);
    if let Some(terminal) = row.terminal.as_ref() {
        match terminal {
            TerminalKind::Decision {
                request_id,
                status,
            } => {
                bytes.push(1);
                put_text(&mut bytes, request_id);
                put_text(&mut bytes, status);
            }
            TerminalKind::Revoke {
                grant_id,
                revoked_count,
            } => {
                bytes.push(2);
                put_text(&mut bytes, grant_id);
                bytes.extend_from_slice(&revoked_count.to_be_bytes());
            }
            TerminalKind::Preset {
                preset,
                target,
                created_grant_ids,
            } => {
                bytes.push(3);
                put_text(&mut bytes, preset);
                put_text(&mut bytes, target);
                bytes.extend_from_slice(&(created_grant_ids.len() as u32).to_be_bytes());
                for id in created_grant_ids {
                    put_text(&mut bytes, id);
                }
            }
        }
    }
    bytes
}

fn load_journal(
    bytes: &[u8],
    ticket_ikm: &[u8; 32],
) -> Result<
    (
        [u8; 16],
        [u8; 16],
        [u8; 32],
        HashMap<[u8; 32], JournalRow>,
    ),
    String,
> {
    if bytes.len() < HEADER_LEN + 4 {
        return Err("grant journal truncated".to_owned());
    }
    if &bytes[..8] != JOURNAL_MAGIC || bytes[8] != 1 {
        return Err("grant journal magic/version mismatch".to_owned());
    }
    let expected = hmac_sha256(ticket_ikm, HEADER_MAC_DOMAIN, &bytes[..73]);
    if !bool::from(expected.ct_eq(&bytes[73..105])) {
        return Err("grant journal header MAC mismatch".to_owned());
    }
    let boot: [u8; 16] = bytes[9..25].try_into().expect("boot");
    let instance: [u8; 16] = bytes[25..41].try_into().expect("instance");
    let revision_mac_key: [u8; 32] = bytes[41..73].try_into().expect("revision key");
    let payload_len = u32::from_be_bytes(bytes[105..109].try_into().expect("len")) as usize;
    let payload = bytes
        .get(109..109 + payload_len)
        .ok_or("grant journal payload truncated")?;
    if payload.len() < 4 {
        return Err("grant journal payload truncated".to_owned());
    }
    let row_count = {
        let declared = u32::from_be_bytes(payload[..4].try_into().expect("count")) as usize;
        let remaining = payload.len().saturating_sub(4);
        if declared > remaining {
            return Err("journal row count exceeds remaining bytes".to_owned());
        }
        declared
    };
    let mut cursor = DecodeCursor {
        input: payload,
        offset: 4,
    };
    let mut rows = HashMap::new();
    for _ in 0..row_count {
        let tag = cursor.byte()?;
        let n = cursor.u32()? as usize;
        let end = cursor
            .offset
            .checked_add(n)
            .ok_or_else(|| "truncated journal row".to_owned())?;
        let body = payload
            .get(cursor.offset..end)
            .ok_or("truncated journal row")?;
        cursor.offset = end;
        let (mut row, consumed) = decode_intent(body)?;
        if body.len() < consumed + 32 {
            return Err("journal row missing nonce".to_owned());
        }
        row.nonce
            .copy_from_slice(&body[consumed..consumed + 32]);
        if tag == 2 {
            let mut rest = DecodeCursor {
                input: body,
                offset: consumed + 32,
            };
            row.terminal = Some(decode_terminal(&mut rest)?);
        } else if tag != 1 {
            return Err("unknown journal row tag".to_owned());
        }
        let mutation_id: [u8; 32] = row.intent[1..33].try_into().expect("mutation id");
        rows.insert(mutation_id, row);
    }
    Ok((boot, instance, revision_mac_key, rows))
}

fn decode_terminal(cursor: &mut DecodeCursor<'_>) -> Result<TerminalKind, String> {
    match cursor.byte()? {
        1 => Ok(TerminalKind::Decision {
            request_id: cursor.text()?,
            status: cursor.text()?,
        }),
        2 => Ok(TerminalKind::Revoke {
            grant_id: cursor.text()?,
            revoked_count: u64::from_be_bytes(cursor.array()?),
        }),
        3 => {
            let preset = cursor.text()?;
            let target = cursor.text()?;
            let declared = cursor.u32()?;
            let count = cursor.bounded_count(declared, 4)?;
            let mut ids = Vec::with_capacity(count);
            for _ in 0..count {
                ids.push(cursor.text()?);
            }
            Ok(TerminalKind::Preset {
                preset,
                target,
                created_grant_ids: ids,
            })
        }
        _ => Err("unknown terminal kind".to_owned()),
    }
}

fn derive_ticket_key(ikm: &[u8; 32], journal_instance: &[u8; 16]) -> [u8; 32] {
    let mut salt = [0u8; 17];
    salt[..16].copy_from_slice(journal_instance);
    salt[16] = PROVIDER_TAG;
    let mut info = Vec::from(TICKET_KEY_INFO);
    info.extend_from_slice(&1u32.to_be_bytes());
    let hk = Hkdf::<Sha256>::new(Some(&salt), ikm);
    let mut key = [0u8; 32];
    hk.expand(&info, &mut key)
        .expect("HKDF expand ticket key");
    key
}

fn derive_done_receipt_key(master: &[u8; 32], store_instance_id: &[u8; 16]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(store_instance_id), master);
    let mut info = Vec::from(DONE_RECEIPT_KEY_INFO);
    info.push(PROVIDER_TAG);
    let mut key = [0u8; 32];
    hk.expand(&info, &mut key)
        .expect("HKDF expand done-receipt key");
    key
}

fn hmac_sha256(key: &[u8; 32], domain: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC key");
    mac.update(domain);
    mac.update(payload);
    mac.finalize().into_bytes().into()
}

fn put_text(output: &mut Vec<u8>, value: &str) {
    output.extend_from_slice(&(value.len() as u32).to_be_bytes());
    output.extend_from_slice(value.as_bytes());
}

fn random_nonzero_16() -> [u8; 16] {
    let mut bytes = [0u8; 16];
    fill_nonzero(&mut bytes);
    bytes
}

fn random_nonzero_32() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    fill_nonzero(&mut bytes);
    bytes
}

fn fill_nonzero(bytes: &mut [u8]) {
    loop {
        OsRng.fill_bytes(bytes);
        if bytes.iter().any(|byte| *byte != 0) {
            return;
        }
    }
}

fn map_cap_error(error: CapGrantError) -> ProviderError {
    match error {
        CapGrantError::NotFound(_) | CapGrantError::PresetNotFound(_) => {
            ProviderError::NotFound(error.to_string())
        }
        CapGrantError::SubsetViolation(_)
        | CapGrantError::PermissionDenied(_)
        | CapGrantError::InvalidConfig(_) => ProviderError::InvalidState(error.to_string()),
        CapGrantError::Db(_) | CapGrantError::Yaml(_) => {
            ProviderError::Unavailable(error.to_string())
        }
    }
}

fn invalid_state(message: &str) -> ProviderError {
    ProviderError::InvalidState(message.to_owned())
}

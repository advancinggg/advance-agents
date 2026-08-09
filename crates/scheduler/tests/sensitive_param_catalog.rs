//! CONTRACT-218 scheduler provider foundation witness.

#[path = "sensitive_param_catalog/t43_t46_t48_t49_t51.rs"]
mod t43_t46_t48_t49_t51;
// T47/T50 uses deliberately synthetic owner/custody artifacts. Those raw
// fixture constructors are absent from production/default builds, so the
// entire fixture module is compiled only under the explicit test-support
// feature rather than weakening the opaque production boundary.
#[cfg(feature = "test-support")]
#[path = "sensitive_param_catalog/t47_t50.rs"]
mod t47_t50;

use std::sync::{Arc, Mutex};

use advance_scheduler::observation_anchor::{
    persisted_keyring_file_root, Compacted, DatabaseCommitted, PreparedCurrent,
    RegistryAnchorError, RegistryAnchorMutation, RegistryAnchorTransaction, RegistryAnchorTuple,
    RegistryAnchorWorld, RegistryDatabaseCommitProof, RegistryHeadContext,
    RegistryRecoveryCapability, RegistryRecoveryDecision, SelectedNext,
    VerifiedEmptyRegistryGenesis,
};
use advance_scheduler::sensitive_params::{
    ObservationProviderConfig, ObservationProviderError, PersistedKeyringCustody,
    PreparedPersistedKeyringCustodyMutation, RegistrySensitiveParamProvider,
};
use advance_scheduler::{ComponentRegistry, ComponentSubmitConfig};
use advance_shared_types::component::ComponentType;
use advance_shared_types::contract218_previsible::{
    AgentPublicationResult, ComponentPublicationResult, PrevisibleProofIssuerRole,
    PrevisibleProofVerifierRole, TerminationCleanupReceiptIssuerRole,
    TerminationCleanupReceiptVerifierRole, TerminationStateMachineRole,
    VerifiedPersistedKeyRetirementScanSet,
};
use advance_shared_types::observation_identity::{
    AgentObservationIdentityRegistrar, ComponentObservationSourceIssuer, HostEmitterId,
    HostObservationIdentityRegistrar, ObservationIdentityAuthority, SensitiveParamCatalog,
    SensitiveParamCatalogError,
};
use advance_shared_types::test_support::{
    contract218_roles, persisted_identity_keyring_role_for_binding, previsible_ready_receipts,
};

struct StaticKeyringCustody {
    instance: [u8; 16],
    bytes: Vec<u8>,
}

impl PersistedKeyringCustody for StaticKeyringCustody {
    fn authenticated_current_file(
        &self,
        expected_registry_instance: [u8; 16],
    ) -> Result<Vec<u8>, RegistryAnchorError> {
        if expected_registry_instance != self.instance {
            return Err(RegistryAnchorError::AuthenticationFailed);
        }
        Ok(self.bytes.clone())
    }

    fn prepare_last_issued_replacement(
        &self,
        _key_id: u32,
        _issued_at_ms: u64,
        _head_context: RegistryHeadContext,
    ) -> Result<Box<dyn PreparedPersistedKeyringCustodyMutation>, RegistryAnchorError> {
        Err(RegistryAnchorError::Unavailable(
            "static test custody has no mutation authority".into(),
        ))
    }

    fn prepare_signing_rotation(
        &self,
        _new_signing_master_key_epoch: u32,
        _head_context: RegistryHeadContext,
    ) -> Result<Box<dyn PreparedPersistedKeyringCustodyMutation>, RegistryAnchorError> {
        Err(RegistryAnchorError::Unavailable(
            "static test custody has no mutation authority".into(),
        ))
    }

    fn prepare_retirement(
        &self,
        _verified_scans: VerifiedPersistedKeyRetirementScanSet,
        _head_context: RegistryHeadContext,
    ) -> Result<Box<dyn PreparedPersistedKeyringCustodyMutation>, RegistryAnchorError> {
        Err(RegistryAnchorError::Unavailable(
            "static test custody has no mutation authority".into(),
        ))
    }
}

fn install_test_keyring(
    verifier: &mut PrevisibleProofVerifierRole,
    instance: [u8; 16],
    bytes: Vec<u8>,
) -> (
    advance_shared_types::contract218_previsible::PersistedIdentityKeyringRole,
    Arc<dyn PersistedKeyringCustody>,
) {
    let root = persisted_keyring_file_root(&bytes);
    let role = persisted_identity_keyring_role_for_binding(
        verifier, instance, root, 0, 1, [0x91; 32], [0x92; 32],
    )
    .unwrap();
    let custody: Arc<dyn PersistedKeyringCustody> =
        Arc::new(StaticKeyringCustody { instance, bytes });
    (role, custody)
}

#[derive(Default)]
struct AnchorState {
    world: Option<RegistryAnchorWorld>,
    operation_tags: Vec<u8>,
}

#[derive(Clone, Default)]
struct MemoryAnchor {
    state: Arc<Mutex<AnchorState>>,
}

impl MemoryAnchor {
    fn operation_tags(&self) -> Vec<u8> {
        self.state.lock().unwrap().operation_tags.clone()
    }

    fn force_same_sequence_fork(&self) {
        let mut state = self.state.lock().unwrap();
        let (generation, mut current) = match state.world.clone().unwrap() {
            RegistryAnchorWorld::CompactCurrent {
                generation,
                current,
            } => (generation, current),
            _ => panic!("test fork requires compact-current"),
        };
        current.head[0] ^= 1;
        state.world = Some(RegistryAnchorWorld::CompactCurrent {
            generation: generation + 1,
            current,
        });
    }
}

impl RegistryAnchorTransaction for MemoryAnchor {
    fn observe(&self) -> Result<RegistryAnchorWorld, RegistryAnchorError> {
        self.state
            .lock()
            .unwrap()
            .world
            .clone()
            .ok_or(RegistryAnchorError::Uninitialized)
    }

    fn anchor_lease_tag(&self, challenge: [u8; 32]) -> Result<[u8; 32], RegistryAnchorError> {
        use sha2::{Digest, Sha256};

        let mut tag = Sha256::new();
        tag.update(b"advance.contract218.memory-anchor-lease.test.v1\0");
        tag.update((Arc::as_ptr(&self.state) as usize).to_be_bytes());
        tag.update(challenge);
        Ok(tag.finalize().into())
    }

    fn authenticate_role_allocation_artifacts(
        &self,
        _current: &RegistryAnchorTuple,
        _context: &advance_scheduler::observation_anchor::RegistryHeadContext,
        _previous: &[u8],
        _next: &[u8],
    ) -> Result<(), RegistryAnchorError> {
        Ok(())
    }

    fn authenticate_persisted_keyring_artifacts(
        &self,
        _current: &RegistryAnchorTuple,
        _context: &advance_scheduler::observation_anchor::RegistryHeadContext,
        _previous: &[u8],
        _next: &[u8],
    ) -> Result<(), RegistryAnchorError> {
        Ok(())
    }

    fn initialize_compact(
        &self,
        genesis: VerifiedEmptyRegistryGenesis,
    ) -> Result<(), RegistryAnchorError> {
        let genesis = genesis.tuple();
        let mut state = self.state.lock().unwrap();
        if state.world.is_some() {
            return Err(RegistryAnchorError::CompareAndSwapFailed);
        }
        state.world = Some(RegistryAnchorWorld::CompactCurrent {
            generation: 1,
            current: genesis.clone(),
        });
        Ok(())
    }

    fn prepare_current(
        &self,
        mutation: RegistryAnchorMutation,
    ) -> Result<Box<dyn PreparedCurrent>, RegistryAnchorError> {
        mutation.verify_anchor_lease(self)?;
        let mut state = self.state.lock().unwrap();
        let generation = match state.world.as_ref() {
            Some(RegistryAnchorWorld::CompactCurrent {
                generation,
                current,
            }) if current == mutation.previous() => generation
                .checked_add(1)
                .ok_or(RegistryAnchorError::GenerationExhausted)?,
            _ => return Err(RegistryAnchorError::CompareAndSwapFailed),
        };
        state.operation_tags.push(mutation.operation_tag());
        state.world = Some(RegistryAnchorWorld::PendingCurrent {
            generation,
            previous: mutation.previous().clone(),
            next: mutation.next().clone(),
        });
        Ok(Box::new(MemoryPrepared {
            state: Arc::clone(&self.state),
            mutation,
        }))
    }

    fn recover(&self, capability: RegistryRecoveryCapability) -> Result<(), RegistryAnchorError> {
        capability.verify_anchor_lease(self)?;
        if self.observe()? != *capability.external() {
            return Err(RegistryAnchorError::CompareAndSwapFailed);
        }
        match capability.decision() {
            RegistryRecoveryDecision::RollBackPending => {
                let mut state = self.state.lock().unwrap();
                let generation = match state.world.as_ref() {
                    Some(RegistryAnchorWorld::PendingCurrent {
                        generation,
                        previous,
                        ..
                    }) if previous == capability.ledger() => generation
                        .checked_add(1)
                        .ok_or(RegistryAnchorError::GenerationExhausted)?,
                    _ => return Err(RegistryAnchorError::CompareAndSwapFailed),
                };
                state.world = Some(RegistryAnchorWorld::CompactCurrent {
                    generation,
                    current: capability.ledger().clone(),
                });
                Ok(())
            }
            RegistryRecoveryDecision::FinishPendingPromotion => {
                select_next(&self.state, capability.ledger())?;
                compact_next(&self.state, capability.ledger())
            }
            RegistryRecoveryDecision::CompactSelectedNext => {
                compact_next(&self.state, capability.ledger())
            }
            RegistryRecoveryDecision::Clean => Ok(()),
        }
    }
}

struct MemoryPrepared {
    state: Arc<Mutex<AnchorState>>,
    mutation: RegistryAnchorMutation,
}

impl PreparedCurrent for MemoryPrepared {
    fn database_committed(
        self: Box<Self>,
        committed: RegistryDatabaseCommitProof,
    ) -> Result<Box<dyn DatabaseCommitted>, RegistryAnchorError> {
        committed.verify_for(&self.mutation)?;
        committed.verify_anchor_lease(&MemoryAnchor {
            state: Arc::clone(&self.state),
        })?;
        Ok(Box::new(MemoryCommitted {
            state: self.state,
            next: self.mutation.next().clone(),
        }))
    }
}

struct MemoryCommitted {
    state: Arc<Mutex<AnchorState>>,
    next: RegistryAnchorTuple,
}

impl DatabaseCommitted for MemoryCommitted {
    fn select_next(self: Box<Self>) -> Result<Box<dyn SelectedNext>, RegistryAnchorError> {
        select_next(&self.state, &self.next)?;
        Ok(Box::new(MemorySelected {
            state: self.state,
            next: self.next,
        }))
    }
}

struct MemorySelected {
    state: Arc<Mutex<AnchorState>>,
    next: RegistryAnchorTuple,
}

impl SelectedNext for MemorySelected {
    fn compact(self: Box<Self>) -> Result<Box<dyn Compacted>, RegistryAnchorError> {
        compact_next(&self.state, &self.next)?;
        Ok(Box::new(MemoryCompacted { current: self.next }))
    }
}

struct MemoryCompacted {
    current: RegistryAnchorTuple,
}

impl Compacted for MemoryCompacted {
    fn current(&self) -> &RegistryAnchorTuple {
        &self.current
    }
}

fn select_next(
    state: &Arc<Mutex<AnchorState>>,
    expected_next: &RegistryAnchorTuple,
) -> Result<(), RegistryAnchorError> {
    let mut state = state.lock().unwrap();
    let generation = match state.world.as_ref() {
        Some(RegistryAnchorWorld::PendingCurrent {
            generation, next, ..
        }) if next == expected_next => generation
            .checked_add(1)
            .ok_or(RegistryAnchorError::GenerationExhausted)?,
        _ => return Err(RegistryAnchorError::CompareAndSwapFailed),
    };
    state.world = Some(RegistryAnchorWorld::SelectedNext {
        generation,
        next: expected_next.clone(),
    });
    Ok(())
}

fn compact_next(
    state: &Arc<Mutex<AnchorState>>,
    expected_next: &RegistryAnchorTuple,
) -> Result<(), RegistryAnchorError> {
    let mut state = state.lock().unwrap();
    let generation = match state.world.as_ref() {
        Some(RegistryAnchorWorld::SelectedNext { generation, next }) if next == expected_next => {
            generation
                .checked_add(1)
                .ok_or(RegistryAnchorError::GenerationExhausted)?
        }
        _ => return Err(RegistryAnchorError::CompareAndSwapFailed),
    };
    state.world = Some(RegistryAnchorWorld::CompactCurrent {
        generation,
        current: expected_next.clone(),
    });
    Ok(())
}

#[cfg(feature = "test-support")]
#[test]
fn cross_database_and_workspace_recovery_capability_rejects() {
    let source_database_anchor = MemoryAnchor::default();
    let target_workspace_anchor = MemoryAnchor::default();
    let current = RegistryAnchorTuple {
        registry_instance: [0x31; 16],
        sequence: 7,
        head: [0x32; 32],
        state_root: [0x33; 32],
        keyring_root: [0x34; 32],
        role_allocation_root: [0x35; 32],
        migration_digest: [0x36; 32],
    };
    let world = RegistryAnchorWorld::CompactCurrent {
        generation: 9,
        current: current.clone(),
    };
    source_database_anchor.state.lock().unwrap().world = Some(world.clone());
    target_workspace_anchor.state.lock().unwrap().world = Some(world.clone());
    let capability =
        RegistryRecoveryCapability::fixture_for_test(&source_database_anchor, world, current)
            .unwrap();

    assert_eq!(
        target_workspace_anchor.recover(capability),
        Err(RegistryAnchorError::AuthenticationFailed)
    );
}

fn component(id: &str, sensitive_params: Vec<String>) -> ComponentSubmitConfig {
    ComponentSubmitConfig {
        id: id.into(),
        component_type: ComponentType::Task,
        binary: Vec::new(),
        capabilities: Vec::new(),
        output_dir: None,
        trigger: None,
        restart_policy: None,
        delay: None,
        initial_grants: None,
        preset: None,
        retry: None,
        sensitive_params,
    }
}

type Roles = (
    PrevisibleProofIssuerRole,
    PrevisibleProofVerifierRole,
    TerminationStateMachineRole,
    TerminationCleanupReceiptIssuerRole,
    TerminationCleanupReceiptVerifierRole,
);

fn roles() -> Roles {
    contract218_roles([0x11; 16], [0x22; 16], 1, [0x33; 32], [0x44; 32]).unwrap()
}

fn greenfield_keyring_file(instance: [u8; 16]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(191);
    bytes.push(1);
    bytes.extend_from_slice(&1_u32.to_be_bytes());
    bytes.extend_from_slice(&instance);
    bytes.extend_from_slice(&0_u64.to_be_bytes());
    bytes.extend_from_slice(&[0; 32]);
    bytes.extend_from_slice(&[0x66; 32]);
    bytes.extend_from_slice(&2_u64.to_be_bytes());
    bytes.extend_from_slice(&1_u32.to_be_bytes());
    bytes.extend_from_slice(&1_u32.to_be_bytes());
    bytes.extend_from_slice(&1_u32.to_be_bytes());
    bytes.push(1);
    bytes.extend_from_slice(&1_u32.to_be_bytes());
    bytes.extend_from_slice(&0_u64.to_be_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&[0x77; 32]);
    bytes.extend_from_slice(&[0x88; 32]);
    assert_eq!(bytes.len(), 191);
    bytes
}

#[tokio::test(flavor = "multi_thread")]
async fn provider_keeps_hidden_rows_invisible_and_publishes_exact_typed_sources() {
    let temp = tempfile::tempdir().unwrap();
    let registry = Arc::new(
        ComponentRegistry::open_in(temp.path(), "components.db")
            .await
            .unwrap(),
    );
    let anchor = Arc::new(MemoryAnchor::default());
    let (issuer, mut verifier, termination, _cleanup_issuer, cleanup_verifier) = roles();
    let config = ObservationProviderConfig::greenfield(
        [0x11; 16],
        [0x22; 16],
        [0x55; 32],
        greenfield_keyring_file([0x11; 16]),
    )
    .unwrap();
    let (keyring, keyring_custody) = install_test_keyring(
        &mut verifier,
        config.registry_instance,
        config.authenticated_persisted_keyring_file.clone(),
    );
    let provider = RegistrySensitiveParamProvider::open(
        Arc::clone(&registry),
        anchor.clone(),
        config.clone(),
        verifier,
        keyring,
        keyring_custody,
        termination,
        cleanup_verifier,
    )
    .await
    .unwrap();

    let tags_before_invalid = anchor.operation_tags();
    assert!(matches!(
        provider
            .commit_component_unpublished(
                "bad-component".into(),
                "test".into(),
                component("bad", vec!["duplicate".into(), "duplicate".into()]),
                None,
            )
            .await,
        Err(ObservationProviderError::IdentityConflict)
            | Err(ObservationProviderError::InvalidInput(_))
    ));
    assert_eq!(anchor.operation_tags(), tags_before_invalid);

    let receipt = provider
        .commit_component_unpublished(
            "component-admit".into(),
            "test".into(),
            component("comp-a", vec!["token".into(), "api_key".into()]),
            None,
        )
        .await
        .unwrap();
    assert!(registry.get("comp-a").await.unwrap().is_none());
    assert_eq!(
        provider.lookup("comp-a"),
        Err(SensitiveParamCatalogError::UnknownIdentity)
    );

    let activation = provider.issue_component_source(&receipt).unwrap();
    assert!(registry.get("comp-a").await.unwrap().is_none());
    let ready = issuer
        .issue_ready_proof(
            &activation,
            previsible_ready_receipts(&issuer, &activation).unwrap(),
        )
        .unwrap();
    assert!(matches!(
        provider.publish_component_source(activation, ready),
        ComponentPublicationResult::Published(_)
    ));
    assert!(registry.get("comp-a").await.unwrap().is_some());
    assert_eq!(
        provider.lookup("comp-a").unwrap().names.as_ref(),
        &["api_key".to_owned(), "token".to_owned()]
    );

    provider
        .begin_agent_registration("agent-register", "agent-a")
        .unwrap();
    assert_eq!(
        provider.lookup("agent-a"),
        Err(SensitiveParamCatalogError::UnknownIdentity)
    );
    let activation = provider
        .activate_agent_unpublished("agent-register")
        .unwrap();
    let ready = issuer
        .issue_ready_proof(
            &activation,
            previsible_ready_receipts(&issuer, &activation).unwrap(),
        )
        .unwrap();
    assert!(matches!(
        provider.publish_agent_activation(activation, ready),
        AgentPublicationResult::Published(_)
    ));
    assert!(provider.lookup("agent-a").unwrap().names.is_empty());

    let host = provider.register_host(HostEmitterId::Runtime).unwrap();
    let live = provider.mint_live_identity(host.handle()).unwrap();
    provider.verify(&live).unwrap();
    // Mutable-custody carrier sealing, rehydration, binding, rotation, and
    // restart are exercised by the independent `t47_t50` witnesses. This
    // bootstrap fixture intentionally has no keyring mutation authority.

    let anchored = provider.current_anchor_tuple().await.unwrap();
    let retained = provider
        .issue_retained_role_dependency_receipt([0x22; 16], 1)
        .await
        .unwrap();
    assert_eq!(
        retained
            .verify_for_recovery_open([0x22; 16], 1, &anchored, anchored.sequence)
            .unwrap(),
        anchored.sequence
    );
    let zero = provider
        .issue_zero_role_dependency_receipt([0x99; 16], 1)
        .await
        .unwrap();
    assert_eq!(
        zero.verify_for_erase([0x99; 16], 1, &anchored, anchored.sequence)
            .unwrap(),
        anchored.sequence
    );

    let (_issuer2, mut verifier2, termination2, _cleanup_issuer2, cleanup_verifier2) = roles();
    let (keyring2, keyring_custody2) = install_test_keyring(
        &mut verifier2,
        config.registry_instance,
        config.authenticated_persisted_keyring_file.clone(),
    );
    assert!(matches!(
        RegistrySensitiveParamProvider::open(
            Arc::clone(&registry),
            anchor.clone(),
            config,
            verifier2,
            keyring2,
            keyring_custody2,
            termination2,
            cleanup_verifier2,
        )
        .await,
        Err(ObservationProviderError::Registry(_))
    ));

    assert_eq!(
        anchor.operation_tags(),
        vec![1, 3, 3, 3, 3, 2, 3, 3, 3, 3, 6]
    );
    anchor.force_same_sequence_fork();
    assert!(matches!(
        provider.current_anchor_tuple().await,
        Err(ObservationProviderError::Anchor(_))
    ));
    assert!(!provider.is_ready());
    drop(provider);
    assert!(matches!(
        registry
            .insert("test", &component("raw", Vec::new()), None)
            .await,
        Err(advance_scheduler::RegistryError::ObservationState(_))
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn missing_anchor_cannot_re_greenfield_a_nonempty_registry() {
    let temp = tempfile::tempdir().unwrap();
    let registry = Arc::new(
        ComponentRegistry::open_in(temp.path(), "components.db")
            .await
            .unwrap(),
    );
    registry
        .insert("legacy", &component("legacy", Vec::new()), None)
        .await
        .unwrap();
    let anchor = Arc::new(MemoryAnchor::default());
    let (_issuer, mut verifier, termination, _cleanup_issuer, cleanup_verifier) = roles();
    let config = ObservationProviderConfig::greenfield(
        [0x11; 16],
        [0x22; 16],
        [0x55; 32],
        greenfield_keyring_file([0x11; 16]),
    )
    .unwrap();
    let (keyring, keyring_custody) = install_test_keyring(
        &mut verifier,
        config.registry_instance,
        config.authenticated_persisted_keyring_file.clone(),
    );

    assert!(matches!(
        RegistrySensitiveParamProvider::open(
            registry,
            anchor.clone(),
            config,
            verifier,
            keyring,
            keyring_custody,
            termination,
            cleanup_verifier,
        )
        .await,
        Err(ObservationProviderError::Registry(
            advance_scheduler::RegistryError::ObservationRecoveryRequired(_)
        ))
    ));
    assert!(matches!(
        anchor.observe(),
        Err(RegistryAnchorError::Uninitialized)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn initialized_anchor_without_matching_ledger_rejects_before_sqlite_mutation() {
    let temp = tempfile::tempdir().unwrap();
    let database_path = temp.path().join("components.db");
    let registry = Arc::new(
        ComponentRegistry::open_in(temp.path(), "components.db")
            .await
            .unwrap(),
    );
    let anchor = Arc::new(MemoryAnchor::default());
    let anchored = RegistryAnchorTuple {
        registry_instance: [0x11; 16],
        sequence: 7,
        head: [0xa1; 32],
        state_root: [0xa2; 32],
        keyring_root: [0xa3; 32],
        role_allocation_root: [0xa4; 32],
        migration_digest: [0xa5; 32],
    };
    anchor.state.lock().unwrap().world = Some(RegistryAnchorWorld::CompactCurrent {
        generation: 9,
        current: anchored.clone(),
    });

    let (_issuer, mut verifier, termination, _cleanup_issuer, cleanup_verifier) = roles();
    let config = ObservationProviderConfig::greenfield(
        [0x11; 16],
        [0x22; 16],
        [0x55; 32],
        greenfield_keyring_file([0x11; 16]),
    )
    .unwrap();
    let (keyring, keyring_custody) = install_test_keyring(
        &mut verifier,
        config.registry_instance,
        config.authenticated_persisted_keyring_file.clone(),
    );

    let snapshot = |path: &std::path::Path| {
        let connection = rusqlite::Connection::open(path).unwrap();
        let schema_version: i64 = connection
            .query_row("PRAGMA schema_version", [], |row| row.get(0))
            .unwrap();
        let mut statement = connection
            .prepare(
                "SELECT type,name,tbl_name,COALESCE(sql,'')
                 FROM sqlite_master ORDER BY type,name,tbl_name,sql",
            )
            .unwrap();
        let sqlite_master: Vec<(String, String, String, String)> = statement
            .query_map([], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })
            .unwrap()
            .map(Result::unwrap)
            .collect();
        let ledger_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM observation_identity_ledger",
                [],
                |row| row.get(0),
            )
            .unwrap();
        (
            std::fs::read(path).unwrap(),
            schema_version,
            sqlite_master,
            ledger_count,
        )
    };
    let before = snapshot(&database_path);
    assert_eq!(before.3, 0);

    assert!(matches!(
        RegistrySensitiveParamProvider::open(
            Arc::clone(&registry),
            anchor.clone(),
            config,
            verifier,
            keyring,
            keyring_custody,
            termination,
            cleanup_verifier,
        )
        .await,
        Err(ObservationProviderError::RecoveryRequired(_))
    ));

    assert_eq!(snapshot(&database_path), before);
    assert_eq!(
        anchor.observe().unwrap(),
        RegistryAnchorWorld::CompactCurrent {
            generation: 9,
            current: anchored,
        }
    );
}

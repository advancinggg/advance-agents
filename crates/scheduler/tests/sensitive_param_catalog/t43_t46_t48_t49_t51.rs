//! Independent MODULE-014-T43..T46/T48/T49/T51 provider witnesses.
//!
//! These tests intentionally drive only public, typed provider ports. They do
//! not open a second database seam or manufacture owner evidence.

use super::*;

#[cfg(feature = "test-support")]
use advance_scheduler::sensitive_params::{
    GreenfieldSchemaAdversaryStage, ObservationMutationFailpointStage, OperationEffectAdversary,
    PrevisibleAdmissionCapacityBoundary, TerminationFinalizeCapacityBoundary,
};
#[cfg(feature = "test-support")]
use advance_shared_types::contract218_previsible::PrevisibleAbortBundle;
use advance_shared_types::contract218_previsible::{
    termination_member_set_digest, TerminationCleanupReceiptSet, TerminationFinalizeCommitAck,
    TerminationFinalizeResult, TerminationOperationRecord, TerminationPrepareCommitAck,
    TerminationPrepareFailure,
};
use advance_shared_types::observation_identity::{
    IssuedObservationSourceHandle, ObservationIdentityClass, MAX_SENSITIVE_PARAM_NAMES,
};
#[cfg(feature = "test-support")]
use advance_shared_types::test_support::previsible_abort_receipts;
use advance_shared_types::test_support::{
    retained_tombstone_gc_inputs, termination_cleanup_receipts, termination_prepare_receipt_vectors,
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tempfile::TempDir;

struct Harness {
    _temp: TempDir,
    registry: Arc<ComponentRegistry>,
    anchor: Arc<MemoryAnchor>,
    provider: Arc<RegistrySensitiveParamProvider>,
    issuer: PrevisibleProofIssuerRole,
    cleanup_issuer: TerminationCleanupReceiptIssuerRole,
    config: ObservationProviderConfig,
    seed: u8,
}

async fn open_provider(
    registry: Arc<ComponentRegistry>,
    anchor: Arc<MemoryAnchor>,
    config: ObservationProviderConfig,
    seed: u8,
) -> (
    Arc<RegistrySensitiveParamProvider>,
    PrevisibleProofIssuerRole,
    TerminationCleanupReceiptIssuerRole,
) {
    try_open_provider(registry, anchor, config, seed)
        .await
        .unwrap()
}

async fn try_open_provider(
    registry: Arc<ComponentRegistry>,
    anchor: Arc<MemoryAnchor>,
    config: ObservationProviderConfig,
    seed: u8,
) -> Result<
    (
        Arc<RegistrySensitiveParamProvider>,
        PrevisibleProofIssuerRole,
        TerminationCleanupReceiptIssuerRole,
    ),
    ObservationProviderError,
> {
    let (issuer, mut verifier, termination, cleanup_issuer, cleanup_verifier) = contract218_roles(
        config.registry_instance,
        config.boot,
        1,
        [seed.wrapping_add(3); 32],
        [seed.wrapping_add(4); 32],
    )
    .unwrap();
    let (keyring, keyring_custody) = install_test_keyring(
        &mut verifier,
        config.registry_instance,
        config.authenticated_persisted_keyring_file.clone(),
    );
    let provider = RegistrySensitiveParamProvider::open(
        registry,
        anchor,
        config,
        verifier,
        keyring,
        keyring_custody,
        termination,
        cleanup_verifier,
    )
    .await?;
    Ok((provider, issuer, cleanup_issuer))
}

async fn harness(seed: u8) -> Harness {
    assert!((1..=240).contains(&seed));
    let temp = tempfile::tempdir().unwrap();
    let registry = Arc::new(
        ComponentRegistry::open_in(temp.path(), "components.db")
            .await
            .unwrap(),
    );
    let anchor = Arc::new(MemoryAnchor::default());
    let config = ObservationProviderConfig::greenfield(
        [seed; 16],
        [seed.wrapping_add(1); 16],
        [seed.wrapping_add(2); 32],
        greenfield_keyring_file([seed; 16]),
    )
    .unwrap();
    let (provider, issuer, cleanup_issuer) = open_provider(
        Arc::clone(&registry),
        Arc::clone(&anchor),
        config.clone(),
        seed,
    )
    .await;
    Harness {
        _temp: temp,
        registry,
        anchor,
        provider,
        issuer,
        cleanup_issuer,
        config,
        seed,
    }
}

async fn restart_harness(harness: Harness) -> Harness {
    let Harness {
        _temp,
        registry,
        anchor,
        provider,
        issuer: _,
        cleanup_issuer: _,
        config,
        seed,
    } = harness;
    drop(provider);
    let (provider, issuer, cleanup_issuer) = open_provider(
        Arc::clone(&registry),
        Arc::clone(&anchor),
        config.clone(),
        seed,
    )
    .await;
    Harness {
        _temp,
        registry,
        anchor,
        provider,
        issuer,
        cleanup_issuer,
        config,
        seed,
    }
}

async fn publish_component(harness: &Harness, operation: &str, id: &str, names: Vec<String>) {
    let receipt = harness
        .provider
        .commit_component_unpublished(
            operation.to_owned(),
            "test".to_owned(),
            component(id, names),
            None,
        )
        .await
        .unwrap();
    let activation = harness.provider.issue_component_source(&receipt).unwrap();
    let ready = harness
        .issuer
        .issue_ready_proof(
            &activation,
            previsible_ready_receipts(&harness.issuer, &activation).unwrap(),
        )
        .unwrap();
    assert!(matches!(
        harness.provider.publish_component_source(activation, ready),
        ComponentPublicationResult::Published(_)
    ));
}

fn publish_agent(harness: &Harness, operation: &str, id: &str) {
    harness
        .provider
        .begin_agent_registration(operation, id)
        .unwrap();
    let activation = harness
        .provider
        .activate_agent_unpublished(operation)
        .unwrap();
    let ready = harness
        .issuer
        .issue_ready_proof(
            &activation,
            previsible_ready_receipts(&harness.issuer, &activation).unwrap(),
        )
        .unwrap();
    assert!(matches!(
        harness.provider.publish_agent_activation(activation, ready),
        AgentPublicationResult::Published(_)
    ));
}

async fn reissued_source(
    provider: &RegistrySensitiveParamProvider,
    id: &str,
) -> IssuedObservationSourceHandle {
    let hydration = provider.issue_completed_hydration_receipt().await.unwrap();
    provider
        .reissue_boot_sources(&hydration)
        .unwrap()
        .into_iter()
        .find(|source| source.canonical_id() == id)
        .unwrap_or_else(|| panic!("missing reissued source {id}"))
}

async fn termination_record(
    harness: &Harness,
    operation_id: &str,
    members: &[advance_shared_types::observation_identity::ObservationIdentityClaims],
) -> TerminationOperationRecord {
    let current = harness.provider.current_anchor_tuple().await.unwrap();
    TerminationOperationRecord {
        operation_id: operation_id.to_owned(),
        member_set_digest: termination_member_set_digest(members).unwrap(),
        registry_sequence: current.sequence + 1,
    }
}

fn fixture_verifier(harness: &Harness) -> PrevisibleProofVerifierRole {
    let (_issuer, verifier, _termination, _cleanup_issuer, _cleanup_verifier) = contract218_roles(
        harness.config.registry_instance,
        harness.config.boot,
        1,
        [harness.seed.wrapping_add(3); 32],
        [harness.seed.wrapping_add(4); 32],
    )
    .unwrap();
    verifier
}

async fn finalize_published_agent(
    harness: &mut Harness,
    operation_id: &str,
    agent_id: &str,
) -> (TerminationFinalizeCommitAck, u64) {
    let member = harness.provider.lookup(agent_id).unwrap().claims();
    let record = termination_record(harness, operation_id, std::slice::from_ref(&member)).await;
    let source_issuer = harness
        .issuer
        .take_source_emission_receipt_issuer()
        .unwrap();
    let (grants, emissions) = termination_prepare_receipt_vectors(
        &source_issuer,
        &harness.cleanup_issuer,
        &record,
        std::slice::from_ref(&member),
        1,
        1,
    )
    .unwrap();
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    // 100ms was too tight on loaded GHA runners (finalize saw retain_until < now).
    let retain_until_ms = now_ms + 2_000;
    let prepared = harness
        .provider
        .prepare_agent_termination(
            operation_id,
            &[agent_id.to_owned()],
            retain_until_ms,
            grants,
            emissions,
        )
        .unwrap();
    let cleanup_set = termination_cleanup_receipts(
        &harness.cleanup_issuer,
        &record,
        std::slice::from_ref(&member),
        2,
    )
    .unwrap();
    let cleanup = harness
        .cleanup_issuer
        .issue_cleanup_complete(&prepared, cleanup_set)
        .unwrap();
    let finalized = harness
        .provider
        .finalize_agent_termination(prepared, cleanup);
    let result = match finalized {
        TerminationFinalizeResult::Committed(ack) => (ack, member.incarnation),
        TerminationFinalizeResult::Rejected { .. } => panic!("exact cleanup was rejected"),
        TerminationFinalizeResult::OutcomeUnknown(_) => panic!("exact cleanup outcome unknown"),
    };
    let remaining = retain_until_ms.saturating_sub(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64,
    );
    tokio::time::sleep(Duration::from_millis(remaining + 2)).await;
    result
}

fn gc_owner_projections(
    harness: &Harness,
    current: &RegistryAnchorTuple,
) -> [([u8; 16], u64, [u8; 32]); 5] {
    [
        ([0xa1; 16], 11, [0xb1; 32]),
        ([0xa2; 16], 12, [0xb2; 32]),
        ([0xa3; 16], 13, [0xb3; 32]),
        ([0xa4; 16], 14, [0xb4; 32]),
        (
            harness.config.registry_instance,
            current.sequence,
            current.state_root,
        ),
    ]
}

fn recover_component_prepare(
    provider: &RegistrySensitiveParamProvider,
    result: Result<TerminationPrepareCommitAck, TerminationPrepareFailure>,
) -> TerminationPrepareCommitAck {
    match result {
        Ok(prepared) => prepared,
        Err(TerminationPrepareFailure::OutcomeUnknown(recovery)) => provider
            .recover_component_termination_prepare(recovery)
            .unwrap(),
        Err(TerminationPrepareFailure::Rejected(_)) => {
            panic!("exact component termination prepare was rejected")
        }
    }
}

#[cfg(feature = "test-support")]
const MUTATION_FAILPOINT_STAGES: [ObservationMutationFailpointStage; 9] = [
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
fn failpoint_commits_database(stage: ObservationMutationFailpointStage) -> bool {
    matches!(
        stage,
        ObservationMutationFailpointStage::AfterDatabaseCommitBeforeSync
            | ObservationMutationFailpointStage::AfterSyncBeforeAnchorCommit
            | ObservationMutationFailpointStage::AfterAnchorCommitBeforeSelect
            | ObservationMutationFailpointStage::AfterSelectBeforeCompact
            | ObservationMutationFailpointStage::AfterCompact
    )
}

#[cfg(feature = "test-support")]
fn failpoint_crosses_anchor_prepare(stage: ObservationMutationFailpointStage) -> bool {
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
async fn assert_component_commit_failpoint(stage: ObservationMutationFailpointStage, seed: u8) {
    let harness = harness(seed).await;
    harness
        .provider
        .inject_next_observation_mutation_failpoint(stage)
        .unwrap();
    assert!(harness
        .provider
        .commit_component_unpublished(
            "fail-component-admit".to_owned(),
            "test".to_owned(),
            component("fail-component", vec!["token".to_owned()]),
            None,
        )
        .await
        .is_err());
    assert!(harness
        .registry
        .get("fail-component")
        .await
        .unwrap()
        .is_none());
    let harness = restart_harness(harness).await;
    assert!(harness.provider.is_ready());
    assert_eq!(
        harness.provider.lookup("fail-component"),
        Err(SensitiveParamCatalogError::UnknownIdentity)
    );
    assert!(harness
        .registry
        .get("fail-component")
        .await
        .unwrap()
        .is_none());
    let retry = harness
        .provider
        .commit_component_unpublished(
            "fail-component-retry".to_owned(),
            "test".to_owned(),
            component("fail-component", vec!["token".to_owned()]),
            None,
        )
        .await;
    if failpoint_commits_database(stage) {
        assert!(matches!(
            retry,
            Err(ObservationProviderError::IdentityConflict)
        ));
    } else {
        assert!(retry.is_ok());
    }
}

#[cfg(feature = "test-support")]
async fn assert_component_publish_failpoint(stage: ObservationMutationFailpointStage, seed: u8) {
    let harness = harness(seed).await;
    let receipt = harness
        .provider
        .commit_component_unpublished(
            "fail-component-publish".to_owned(),
            "test".to_owned(),
            component("fail-publish", vec!["credential".to_owned()]),
            None,
        )
        .await
        .unwrap();
    let activation = harness.provider.issue_component_source(&receipt).unwrap();
    let ready = harness
        .issuer
        .issue_ready_proof(
            &activation,
            previsible_ready_receipts(&harness.issuer, &activation).unwrap(),
        )
        .unwrap();
    harness
        .provider
        .inject_next_observation_mutation_failpoint(stage)
        .unwrap();
    let outcome = harness.provider.publish_component_source(activation, ready);
    if !failpoint_crosses_anchor_prepare(stage) {
        assert!(matches!(&outcome, ComponentPublicationResult::Rejected(_)));
        let harness = restart_harness(harness).await;
        assert_eq!(
            harness.provider.lookup("fail-publish"),
            Err(SensitiveParamCatalogError::UnknownIdentity)
        );
        assert!(harness
            .registry
            .get("fail-publish")
            .await
            .unwrap()
            .is_none());
        return;
    }
    let recovery = match outcome {
        ComponentPublicationResult::OutcomeUnknown(recovery) => recovery,
        ComponentPublicationResult::Published(_) => {
            panic!("armed failpoint returned a synchronous publication acknowledgement")
        }
        ComponentPublicationResult::Rejected(_) => {
            panic!("closed crash boundary was misclassified as a proven rejection")
        }
    };
    let harness = restart_harness(harness).await;
    assert!(matches!(
        harness.provider.recover_component_publication(recovery),
        ComponentPublicationResult::Published(_)
    ));
    assert!(harness
        .registry
        .get("fail-publish")
        .await
        .unwrap()
        .is_some());
    assert_eq!(
        harness
            .provider
            .lookup("fail-publish")
            .unwrap()
            .names
            .as_ref(),
        &["credential".to_owned()]
    );
}

#[cfg(feature = "test-support")]
async fn attempt_exact_agent_prepare(
    harness: &mut Harness,
    operation_id: &str,
    agent_id: &str,
    counter: u64,
    failpoint: Option<ObservationMutationFailpointStage>,
) -> (
    TerminationOperationRecord,
    advance_shared_types::observation_identity::ObservationIdentityClaims,
    Result<TerminationPrepareCommitAck, TerminationPrepareFailure>,
) {
    let member = harness.provider.lookup(agent_id).unwrap().claims();
    let record = termination_record(harness, operation_id, std::slice::from_ref(&member)).await;
    let source = harness
        .issuer
        .take_source_emission_receipt_issuer()
        .unwrap();
    let (grants, emissions) = termination_prepare_receipt_vectors(
        &source,
        &harness.cleanup_issuer,
        &record,
        std::slice::from_ref(&member),
        counter,
        counter,
    )
    .unwrap();
    if let Some(stage) = failpoint {
        harness
            .provider
            .inject_next_observation_mutation_failpoint(stage)
            .unwrap();
    }
    let result = harness.provider.prepare_agent_termination(
        operation_id,
        &[agent_id.to_owned()],
        i64::MAX as u64,
        grants,
        emissions,
    );
    (record, member, result)
}

#[cfg(feature = "test-support")]
async fn retry_exact_agent_prepare(
    harness: &mut Harness,
    operation_id: &str,
    agent_id: &str,
    counter: u64,
) -> (
    TerminationOperationRecord,
    advance_shared_types::observation_identity::ObservationIdentityClaims,
    TerminationPrepareCommitAck,
) {
    let (record, member, result) =
        attempt_exact_agent_prepare(harness, operation_id, agent_id, counter, None).await;
    let prepared = match result {
        Ok(prepared) => prepared,
        Err(TerminationPrepareFailure::Rejected(_)) => {
            panic!("exact prepare retry was rejected")
        }
        Err(TerminationPrepareFailure::OutcomeUnknown(_)) => {
            panic!("exact prepare retry returned outcome-unknown")
        }
    };
    (record, member, prepared)
}

#[cfg(feature = "test-support")]
fn exact_agent_cleanup(
    harness: &Harness,
    record: &TerminationOperationRecord,
    member: &advance_shared_types::observation_identity::ObservationIdentityClaims,
    prepared: &TerminationPrepareCommitAck,
    counter: u64,
) -> advance_shared_types::contract218_previsible::TerminationCleanupCompleteReceipt {
    let receipts = termination_cleanup_receipts(
        &harness.cleanup_issuer,
        record,
        std::slice::from_ref(member),
        counter,
    )
    .unwrap();
    harness
        .cleanup_issuer
        .issue_cleanup_complete(prepared, receipts)
        .unwrap()
}

#[cfg(feature = "test-support")]
async fn assert_termination_prepare_failpoint(stage: ObservationMutationFailpointStage, seed: u8) {
    let mut harness = harness(seed).await;
    let operation_id = "fail-agent-prepare";
    let agent_id = "fail-agent-prepare";
    publish_agent(&harness, "register-fail-agent-prepare", agent_id);
    let (initial_record, initial_member, outcome) =
        attempt_exact_agent_prepare(&mut harness, operation_id, agent_id, 41, Some(stage)).await;

    let mut harness = restart_harness(harness).await;
    assert!(harness.provider.is_ready());
    let (record, member, prepared) = match outcome {
        Ok(_) => panic!("armed prepare failpoint returned a synchronous acknowledgement"),
        Err(TerminationPrepareFailure::Rejected(_)) => {
            assert!(
                !failpoint_crosses_anchor_prepare(stage),
                "post-prepare crash boundary was misclassified as rejected: {stage:?}"
            );
            retry_exact_agent_prepare(&mut harness, operation_id, agent_id, 42).await
        }
        Err(TerminationPrepareFailure::OutcomeUnknown(recovery)) => {
            assert!(
                failpoint_crosses_anchor_prepare(stage),
                "pre-prepare rollback was misclassified as outcome-unknown: {stage:?}"
            );
            match harness.provider.recover_agent_termination_prepare(recovery) {
                Ok(prepared) => {
                    assert!(
                        failpoint_commits_database(stage),
                        "uncommitted prepare recovered as committed: {stage:?}"
                    );
                    (initial_record, initial_member, prepared)
                }
                Err(TerminationPrepareFailure::Rejected(_)) => {
                    assert!(
                        !failpoint_commits_database(stage),
                        "committed prepare recovered as rejected: {stage:?}"
                    );
                    retry_exact_agent_prepare(&mut harness, operation_id, agent_id, 43).await
                }
                Err(TerminationPrepareFailure::OutcomeUnknown(_)) => {
                    panic!("restart could not resolve prepare outcome at {stage:?}")
                }
            }
        }
    };

    let cleanup = exact_agent_cleanup(&harness, &record, &member, &prepared, 44);
    assert!(matches!(
        harness
            .provider
            .finalize_agent_termination(prepared, cleanup),
        TerminationFinalizeResult::Committed(_)
    ));
    assert_eq!(harness.provider.lookup(agent_id).unwrap().claims(), member);
}

#[cfg(feature = "test-support")]
async fn assert_termination_finalize_failpoint(stage: ObservationMutationFailpointStage, seed: u8) {
    let mut harness = harness(seed).await;
    let operation_id = "fail-agent-finalize";
    let agent_id = "fail-agent-finalize";
    publish_agent(&harness, "register-fail-agent-finalize", agent_id);
    let (record, member, prepared) =
        retry_exact_agent_prepare(&mut harness, operation_id, agent_id, 51).await;
    let cleanup = exact_agent_cleanup(&harness, &record, &member, &prepared, 52);
    harness
        .provider
        .inject_next_observation_mutation_failpoint(stage)
        .unwrap();
    let outcome = harness
        .provider
        .finalize_agent_termination(prepared, cleanup);

    let harness = restart_harness(harness).await;
    assert!(harness.provider.is_ready());
    let finalized = match outcome {
        TerminationFinalizeResult::Committed(_) => {
            panic!("armed finalize failpoint returned a synchronous acknowledgement")
        }
        TerminationFinalizeResult::Rejected { prepared, cleanup } => {
            assert!(
                !failpoint_crosses_anchor_prepare(stage),
                "post-prepare finalize crash was misclassified as rejected: {stage:?}"
            );
            harness
                .provider
                .finalize_agent_termination(prepared, cleanup)
        }
        TerminationFinalizeResult::OutcomeUnknown(recovery) => {
            assert!(
                failpoint_crosses_anchor_prepare(stage),
                "pre-prepare finalize rollback was misclassified as unknown: {stage:?}"
            );
            match harness.provider.recover_agent_termination(recovery) {
                TerminationFinalizeResult::Committed(ack) => {
                    assert!(
                        failpoint_commits_database(stage),
                        "uncommitted finalize recovered as committed: {stage:?}"
                    );
                    TerminationFinalizeResult::Committed(ack)
                }
                TerminationFinalizeResult::Rejected { prepared, cleanup } => {
                    assert!(
                        !failpoint_commits_database(stage),
                        "committed finalize recovered as rejected: {stage:?}"
                    );
                    harness
                        .provider
                        .finalize_agent_termination(prepared, cleanup)
                }
                TerminationFinalizeResult::OutcomeUnknown(_) => {
                    panic!("restart could not resolve finalize outcome at {stage:?}")
                }
            }
        }
    };
    assert!(matches!(finalized, TerminationFinalizeResult::Committed(_)));
    assert_eq!(harness.provider.lookup(agent_id).unwrap().claims(), member);
}

#[cfg(feature = "test-support")]
async fn assert_termination_capacity_boundary(
    boundary: TerminationFinalizeCapacityBoundary,
    seed: u8,
) {
    let mut harness = harness(seed).await;
    let operation_id = "capacity-agent-termination";
    let agent_id = "capacity-agent";
    publish_agent(&harness, "register-capacity-agent", agent_id);
    let member = harness.provider.lookup(agent_id).unwrap().claims();
    let record = termination_record(&harness, operation_id, std::slice::from_ref(&member)).await;
    let source = harness
        .issuer
        .take_source_emission_receipt_issuer()
        .unwrap();
    let (grants, emissions) = termination_prepare_receipt_vectors(
        &source,
        &harness.cleanup_issuer,
        &record,
        std::slice::from_ref(&member),
        61,
        61,
    )
    .unwrap();
    harness
        .provider
        .seed_next_termination_finalize_capacity_boundary(boundary)
        .unwrap();
    let outcome = harness.provider.prepare_agent_termination(
        operation_id,
        &[agent_id.to_owned()],
        i64::MAX as u64,
        grants,
        emissions,
    );

    if boundary == TerminationFinalizeCapacityBoundary::CapMinusOne {
        assert!(matches!(
            outcome,
            Err(TerminationPrepareFailure::Rejected(_))
        ));
        assert_eq!(harness.provider.lookup(agent_id).unwrap().claims(), member);
        return;
    }

    let prepared = match outcome {
        Ok(prepared) => prepared,
        Err(TerminationPrepareFailure::Rejected(_)) => {
            panic!("at/above exact terminal reservation was rejected: {boundary:?}")
        }
        Err(TerminationPrepareFailure::OutcomeUnknown(_)) => {
            panic!("capacity-only prepare returned outcome-unknown: {boundary:?}")
        }
    };
    let cleanup = exact_agent_cleanup(&harness, &record, &member, &prepared, 62);
    assert!(matches!(
        harness
            .provider
            .finalize_agent_termination(prepared, cleanup),
        TerminationFinalizeResult::Committed(_)
    ));
    assert_eq!(harness.provider.lookup(agent_id).unwrap().claims(), member);
}

#[cfg(feature = "test-support")]
async fn collected_agent_for_reuse(seed: u8, agent_id: &str) -> (Harness, u64) {
    let mut harness = harness(seed).await;
    publish_agent(&harness, "register-before-reuse-failpoint", agent_id);
    let (finalized, old_incarnation) =
        finalize_published_agent(&mut harness, "terminate-before-reuse-failpoint", agent_id).await;
    let challenge = harness
        .provider
        .prepare_retained_tombstone_gc(&finalized)
        .unwrap();
    let current = harness.provider.current_anchor_tuple().await.unwrap();
    let verifier = fixture_verifier(&harness);
    let (purpose2, receipts) = retained_tombstone_gc_inputs(
        &verifier,
        &challenge,
        gc_owner_projections(&harness, &current),
    )
    .unwrap();
    harness
        .provider
        .collect_retained_tombstone_gc(challenge, purpose2, receipts)
        .unwrap();
    assert_eq!(
        harness.provider.lookup(agent_id),
        Err(SensitiveParamCatalogError::UnknownIdentity)
    );
    (harness, old_incarnation)
}

#[cfg(feature = "test-support")]
async fn assert_agent_allocation_failpoint(stage: ObservationMutationFailpointStage, seed: u8) {
    let agent_id = "allocation-failpoint-agent";
    let operation_id = "allocation-failpoint-operation";
    let (harness, old_incarnation) = collected_agent_for_reuse(seed, agent_id).await;
    harness
        .provider
        .inject_next_observation_mutation_failpoint(stage)
        .unwrap();
    assert!(harness
        .provider
        .begin_agent_registration(operation_id, agent_id)
        .is_err());

    let harness = restart_harness(harness).await;
    assert_eq!(
        harness.provider.lookup(agent_id),
        Err(SensitiveParamCatalogError::UnknownIdentity)
    );
    if failpoint_commits_database(stage) {
        assert!(harness
            .provider
            .begin_agent_registration("allocation-conflicting-operation", agent_id)
            .is_err());
    } else {
        harness
            .provider
            .begin_agent_registration(operation_id, agent_id)
            .unwrap();
    }
    let activation = harness
        .provider
        .activate_agent_unpublished(operation_id)
        .unwrap();
    let ready = harness
        .issuer
        .issue_ready_proof(
            &activation,
            previsible_ready_receipts(&harness.issuer, &activation).unwrap(),
        )
        .unwrap();
    assert!(matches!(
        harness.provider.publish_agent_activation(activation, ready),
        AgentPublicationResult::Published(_)
    ));
    assert_eq!(
        harness.provider.lookup(agent_id).unwrap().incarnation,
        old_incarnation + 1
    );
}

#[cfg(feature = "test-support")]
async fn assert_agent_publish_failpoint(stage: ObservationMutationFailpointStage, seed: u8) {
    let agent_id = "publish-failpoint-agent";
    let operation_id = "publish-failpoint-operation";
    let (harness, old_incarnation) = collected_agent_for_reuse(seed, agent_id).await;
    harness
        .provider
        .begin_agent_registration(operation_id, agent_id)
        .unwrap();
    let activation = harness
        .provider
        .activate_agent_unpublished(operation_id)
        .unwrap();
    let ready = harness
        .issuer
        .issue_ready_proof(
            &activation,
            previsible_ready_receipts(&harness.issuer, &activation).unwrap(),
        )
        .unwrap();
    harness
        .provider
        .inject_next_observation_mutation_failpoint(stage)
        .unwrap();
    let outcome = harness.provider.publish_agent_activation(activation, ready);

    let harness = restart_harness(harness).await;
    match outcome {
        AgentPublicationResult::Published(_) => {
            panic!("armed publish failpoint returned a synchronous acknowledgement")
        }
        AgentPublicationResult::OutcomeUnknown(recovery) => {
            assert!(
                failpoint_crosses_anchor_prepare(stage),
                "pre-prepare publish rollback was misclassified as unknown: {stage:?}"
            );
            assert!(matches!(
                harness.provider.recover_agent_publication(recovery),
                AgentPublicationResult::Published(_)
            ));
            assert_eq!(
                harness.provider.lookup(agent_id).unwrap().incarnation,
                old_incarnation + 1
            );
        }
        AgentPublicationResult::Rejected(rejected) => {
            assert!(
                !failpoint_crosses_anchor_prepare(stage),
                "post-prepare publish crash was misclassified as rejected: {stage:?}"
            );
            let verifier = fixture_verifier(&harness);
            let activation = verifier.rejected_agent_into_activation(rejected);
            let proof = harness
                .issuer
                .issue_abort_proof(
                    &activation,
                    previsible_abort_receipts(&harness.issuer, &activation).unwrap(),
                )
                .unwrap();
            let clean = match verifier.verify_abort_proof(activation, proof).unwrap() {
                PrevisibleAbortBundle::Agent(clean) => clean,
                PrevisibleAbortBundle::Component(_) => {
                    panic!("agent rejection produced a component abort bundle")
                }
            };
            harness
                .provider
                .abort_agent_registration(clean, i64::MAX as u64)
                .unwrap();
            assert_eq!(
                harness.provider.lookup(agent_id),
                Err(SensitiveParamCatalogError::UnknownIdentity)
            );

            publish_agent(&harness, "register-after-rejected-publish", agent_id);
            assert_eq!(
                harness.provider.lookup(agent_id).unwrap().incarnation,
                old_incarnation + 2,
                "aborted allocation was reused after {stage:?}"
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn one_arc_hydrates_one_view_and_one_watch_revision() {
    let harness = harness(0x31).await;
    #[cfg(feature = "test-support")]
    assert!(Arc::ptr_eq(harness.provider.registry(), &harness.registry));
    let mut revision = harness.provider.subscribe();
    let before = *revision.borrow_and_update();

    let receipt = harness
        .provider
        .commit_component_unpublished(
            "one-view-admit".to_owned(),
            "test".to_owned(),
            component("one-view", vec!["token".to_owned()]),
            None,
        )
        .await
        .unwrap();
    assert_eq!(*revision.borrow(), before);
    assert!(!revision.has_changed().unwrap());
    let activation = harness.provider.issue_component_source(&receipt).unwrap();
    assert_eq!(*revision.borrow(), before);
    let ready = harness
        .issuer
        .issue_ready_proof(
            &activation,
            previsible_ready_receipts(&harness.issuer, &activation).unwrap(),
        )
        .unwrap();
    assert!(matches!(
        harness.provider.publish_component_source(activation, ready),
        ComponentPublicationResult::Published(_)
    ));
    assert!(revision.changed().await.is_ok());
    assert_eq!(*revision.borrow_and_update(), before + 1);
    assert!(!revision.has_changed().unwrap());
    assert_eq!(harness.registry.list().await.unwrap().len(), 1);
    assert_eq!(
        harness.provider.lookup("one-view").unwrap().names.as_ref(),
        &["token".to_owned()]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn pending_rows_are_invisible_until_anchored_publish() {
    let harness = harness(0x32).await;
    let mut revision = harness.provider.subscribe();
    let before = *revision.borrow_and_update();
    let receipt = harness
        .provider
        .commit_component_unpublished(
            "pending-admit".to_owned(),
            "test".to_owned(),
            component("pending-component", vec!["secret".to_owned()]),
            None,
        )
        .await
        .unwrap();
    assert!(harness
        .registry
        .get("pending-component")
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        harness.provider.lookup("pending-component"),
        Err(SensitiveParamCatalogError::UnknownIdentity)
    );
    assert_eq!(*revision.borrow(), before);

    let activation = harness.provider.issue_component_source(&receipt).unwrap();
    assert!(harness
        .registry
        .get("pending-component")
        .await
        .unwrap()
        .is_none());
    assert_eq!(*revision.borrow(), before);
    let ready = harness
        .issuer
        .issue_ready_proof(
            &activation,
            previsible_ready_receipts(&harness.issuer, &activation).unwrap(),
        )
        .unwrap();
    assert!(matches!(
        harness.provider.publish_component_source(activation, ready),
        ComponentPublicationResult::Published(_)
    ));
    assert!(harness
        .registry
        .get("pending-component")
        .await
        .unwrap()
        .is_some());
    assert_eq!(*revision.borrow(), before + 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn restart_reconciles_before_first_read() {
    let harness = harness(0x33).await;
    publish_component(
        &harness,
        "restart-admit",
        "restart-component",
        vec!["credential".to_owned()],
    )
    .await;
    let before = harness.provider.lookup("restart-component").unwrap();
    let anchored = harness.provider.current_anchor_tuple().await.unwrap();
    let Harness {
        _temp,
        registry,
        anchor,
        provider,
        issuer: _,
        cleanup_issuer: _,
        config,
        seed,
    } = harness;
    drop(provider);
    let (provider, issuer, cleanup_issuer) =
        open_provider(Arc::clone(&registry), Arc::clone(&anchor), config, seed).await;
    let _keep_roles = (issuer, cleanup_issuer);

    assert!(provider.is_ready());
    assert_eq!(provider.current_anchor_tuple().await.unwrap(), anchored);
    let after = provider.lookup("restart-component").unwrap();
    assert_eq!(after.claims(), before.claims());
    assert_eq!(after.names, before.names);
}

#[tokio::test(flavor = "multi_thread")]
async fn component_pending_hidden_publish_and_tombstone_transactions() {
    let mut harness = harness(0x34).await;
    publish_component(
        &harness,
        "component-lifecycle",
        "component-lifecycle",
        vec!["token".to_owned()],
    )
    .await;
    assert!(harness
        .registry
        .get("component-lifecycle")
        .await
        .unwrap()
        .is_some());
    let visible = harness.provider.lookup("component-lifecycle").unwrap();
    let source = reissued_source(&harness.provider, "component-lifecycle").await;
    let live = harness
        .provider
        .mint_live_identity(source.handle())
        .unwrap();
    assert_eq!(visible.names.as_ref(), &["token".to_owned()]);

    let claims = visible.claims();
    let record =
        termination_record(&harness, "terminate-component-lifecycle", &[claims.clone()]).await;
    let source_issuer = harness
        .issuer
        .take_source_emission_receipt_issuer()
        .unwrap();
    let (grants, emissions) = termination_prepare_receipt_vectors(
        &source_issuer,
        &harness.cleanup_issuer,
        &record,
        &[claims.clone()],
        21,
        22,
    )
    .unwrap();
    let prepared = recover_component_prepare(
        &harness.provider,
        harness.provider.prepare_component_termination(
            "terminate-component-lifecycle",
            &live,
            i64::MAX as u64,
            grants,
            emissions,
        ),
    );
    assert!(harness
        .registry
        .get("component-lifecycle")
        .await
        .unwrap()
        .is_none());
    let terminating = harness.provider.lookup("component-lifecycle").unwrap();
    assert_eq!(terminating.claims(), claims);
    assert_eq!(terminating.names, visible.names);
    assert_eq!(
        harness.provider.verify(&live),
        Err(SensitiveParamCatalogError::StaleIdentity)
    );

    let receipts =
        termination_cleanup_receipts(&harness.cleanup_issuer, &record, &[claims.clone()], 23)
            .unwrap();
    let cleanup = harness
        .cleanup_issuer
        .issue_cleanup_complete(&prepared, receipts)
        .unwrap();
    assert!(matches!(
        harness
            .provider
            .finalize_component_termination(prepared, cleanup),
        TerminationFinalizeResult::Committed(_)
    ));
    assert!(harness
        .registry
        .get("component-lifecycle")
        .await
        .unwrap()
        .is_none());
    let tombstoned = harness.provider.lookup("component-lifecycle").unwrap();
    assert_eq!(tombstoned.claims(), claims);
    assert_eq!(tombstoned.names, visible.names);
    assert!(matches!(
        harness.registry.delete("component-lifecycle").await,
        Err(advance_scheduler::RegistryError::ObservationState(_))
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn component_commit_register_table_lifecycle_publish_failpoints() {
    let mut harness = harness(0x35).await;
    let tags_before = harness.anchor.operation_tags();
    assert!(harness
        .provider
        .commit_component_unpublished(
            "invalid-component".to_owned(),
            "test".to_owned(),
            component("__sys:forged", vec!["token".to_owned()]),
            None,
        )
        .await
        .is_err());
    assert_eq!(harness.anchor.operation_tags(), tags_before);

    publish_component(
        &harness,
        "complete-component",
        "complete-component",
        vec!["token".to_owned()],
    )
    .await;
    assert_eq!(harness.registry.list().await.unwrap().len(), 1);
    let snapshot = harness.provider.lookup("complete-component").unwrap();
    let claims = snapshot.claims();
    let source = reissued_source(&harness.provider, "complete-component").await;
    let live = harness
        .provider
        .mint_live_identity(source.handle())
        .unwrap();
    let source_issuer = harness
        .issuer
        .take_source_emission_receipt_issuer()
        .unwrap();

    assert!(harness
        .provider
        .prepare_component_termination(
            "component-missing-receipts",
            &live,
            i64::MAX as u64,
            Vec::new(),
            Vec::new(),
        )
        .is_err());
    assert!(harness.provider.verify(&live).is_ok());
    assert!(harness
        .registry
        .get("complete-component")
        .await
        .unwrap()
        .is_some());

    let cross_record =
        termination_record(&harness, "component-receipt-operation-a", &[claims.clone()]).await;
    let (grants, emissions) = termination_prepare_receipt_vectors(
        &source_issuer,
        &harness.cleanup_issuer,
        &cross_record,
        &[claims.clone()],
        31,
        31,
    )
    .unwrap();
    assert!(harness
        .provider
        .prepare_component_termination(
            "component-receipt-operation-b",
            &live,
            i64::MAX as u64,
            grants,
            emissions,
        )
        .is_err());
    assert!(harness.provider.verify(&live).is_ok());

    let duplicate_record =
        termination_record(&harness, "component-duplicate-receipts", &[claims.clone()]).await;
    let duplicate_members = vec![claims.clone(), claims.clone()];
    let (grants, emissions) = termination_prepare_receipt_vectors(
        &source_issuer,
        &harness.cleanup_issuer,
        &duplicate_record,
        &duplicate_members,
        32,
        32,
    )
    .unwrap();
    assert!(harness
        .provider
        .prepare_component_termination(
            "component-duplicate-receipts",
            &live,
            i64::MAX as u64,
            grants,
            emissions,
        )
        .is_err());
    assert!(harness.provider.verify(&live).is_ok());

    let wrong_boot_record =
        termination_record(&harness, "component-old-boot-receipts", &[claims.clone()]).await;
    let (mut wrong_issuer, _wrong_verifier, _wrong_state, wrong_cleanup, _wrong_cleanup_verifier) =
        contract218_roles(
            harness.config.registry_instance,
            [0xee; 16],
            1,
            [harness.seed.wrapping_add(3); 32],
            [harness.seed.wrapping_add(4); 32],
        )
        .unwrap();
    let wrong_source = wrong_issuer.take_source_emission_receipt_issuer().unwrap();
    let (grants, emissions) = termination_prepare_receipt_vectors(
        &wrong_source,
        &wrong_cleanup,
        &wrong_boot_record,
        &[claims.clone()],
        33,
        33,
    )
    .unwrap();
    assert!(harness
        .provider
        .prepare_component_termination(
            "component-old-boot-receipts",
            &live,
            i64::MAX as u64,
            grants,
            emissions,
        )
        .is_err());
    assert!(harness.provider.verify(&live).is_ok());

    let record =
        termination_record(&harness, "component-exact-termination", &[claims.clone()]).await;
    let (grants, emissions) = termination_prepare_receipt_vectors(
        &source_issuer,
        &harness.cleanup_issuer,
        &record,
        &[claims.clone()],
        34,
        34,
    )
    .unwrap();
    let prepared = recover_component_prepare(
        &harness.provider,
        harness.provider.prepare_component_termination(
            "component-exact-termination",
            &live,
            i64::MAX as u64,
            grants,
            emissions,
        ),
    );
    assert!(harness
        .cleanup_issuer
        .issue_cleanup_complete(&prepared, TerminationCleanupReceiptSet::new(Vec::new()))
        .is_err());
    let receipts =
        termination_cleanup_receipts(&harness.cleanup_issuer, &record, &[claims], 35).unwrap();
    let cleanup = harness
        .cleanup_issuer
        .issue_cleanup_complete(&prepared, receipts)
        .unwrap();
    assert!(matches!(
        harness
            .provider
            .finalize_component_termination(prepared, cleanup),
        TerminationFinalizeResult::Committed(_)
    ));
    assert!(matches!(
        harness
            .registry
            .insert("raw", &component("raw", vec![]), None)
            .await,
        Err(advance_scheduler::RegistryError::ObservationState(_))
    ));

    #[cfg(feature = "test-support")]
    for (index, stage) in MUTATION_FAILPOINT_STAGES.into_iter().enumerate() {
        assert_component_commit_failpoint(stage, 0x60 + index as u8).await;
        assert_component_publish_failpoint(stage, 0x70 + index as u8).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn declaration_empty_duplicate_malformed_and_plus_one_reject_before_mutation() {
    let harness = harness(0x36).await;
    publish_component(&harness, "empty-declaration", "empty-declaration", vec![]).await;
    assert!(harness
        .provider
        .lookup("empty-declaration")
        .unwrap()
        .names
        .is_empty());

    for (operation, id, names) in [
        (
            "duplicate-declaration",
            "duplicate-declaration",
            vec!["duplicate".to_owned(), "duplicate".to_owned()],
        ),
        (
            "empty-name-declaration",
            "empty-name-declaration",
            vec![String::new()],
        ),
        (
            "control-name-declaration",
            "control-name-declaration",
            vec!["bad\nname".to_owned()],
        ),
        (
            "plus-one-declaration",
            "plus-one-declaration",
            (0..=MAX_SENSITIVE_PARAM_NAMES)
                .map(|index| format!("name-{index}"))
                .collect(),
        ),
    ] {
        let tags_before = harness.anchor.operation_tags();
        assert!(harness
            .provider
            .commit_component_unpublished(
                operation.to_owned(),
                "test".to_owned(),
                component(id, names),
                None,
            )
            .await
            .is_err());
        assert_eq!(harness.anchor.operation_tags(), tags_before);
        assert_eq!(
            harness.provider.lookup(id),
            Err(SensitiveParamCatalogError::UnknownIdentity)
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn agent_and_three_hosts_known_empty_unknown_rejects() {
    let harness = harness(0x37).await;
    harness
        .provider
        .begin_agent_registration("known-agent", "agent:alpha")
        .unwrap();
    assert_eq!(
        harness.provider.lookup("agent:alpha"),
        Err(SensitiveParamCatalogError::UnknownIdentity)
    );
    let activation = harness
        .provider
        .activate_agent_unpublished("known-agent")
        .unwrap();
    assert_eq!(
        harness.provider.lookup("agent:alpha"),
        Err(SensitiveParamCatalogError::UnknownIdentity)
    );
    let ready = harness
        .issuer
        .issue_ready_proof(
            &activation,
            previsible_ready_receipts(&harness.issuer, &activation).unwrap(),
        )
        .unwrap();
    assert!(matches!(
        harness.provider.publish_agent_activation(activation, ready),
        AgentPublicationResult::Published(_)
    ));
    let agent = harness.provider.lookup("agent:alpha").unwrap();
    assert_eq!(agent.identity_class, ObservationIdentityClass::Agent);
    assert!(agent.names.is_empty());

    for emitter in [
        HostEmitterId::Runtime,
        HostEmitterId::RetentionSweeper,
        HostEmitterId::PackManager,
    ] {
        let source = harness.provider.register_host(emitter).unwrap();
        assert_eq!(source.canonical_id(), emitter.canonical_id());
        let snapshot = harness.provider.lookup(emitter.canonical_id()).unwrap();
        assert_eq!(snapshot.identity_class, ObservationIdentityClass::Host);
        assert!(snapshot.names.is_empty());
    }
    assert_eq!(
        harness.provider.lookup("agent:unknown"),
        Err(SensitiveParamCatalogError::UnknownIdentity)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn reserved_namespace_class_collision_and_string_mint_reject() {
    let harness = harness(0x38).await;
    assert!(harness
        .provider
        .commit_component_unpublished(
            "reserved-component".to_owned(),
            "test".to_owned(),
            component("__sys:reserved", vec![]),
            None,
        )
        .await
        .is_err());
    assert_eq!(
        harness
            .provider
            .begin_agent_registration("reserved-agent", "__sys:reserved"),
        Err(SensitiveParamCatalogError::InvalidIdentity)
    );

    publish_agent(&harness, "collision-agent", "collision-id");
    assert!(matches!(
        harness
            .provider
            .commit_component_unpublished(
                "collision-component".to_owned(),
                "test".to_owned(),
                component("collision-id", vec![]),
                None,
            )
            .await,
        Err(ObservationProviderError::IdentityConflict)
    ));
    let snapshot = harness.provider.lookup("collision-id").unwrap();
    assert_eq!(snapshot.identity_class, ObservationIdentityClass::Agent);
    let source = reissued_source(&harness.provider, "collision-id").await;
    let identity = harness
        .provider
        .mint_live_identity(source.handle())
        .unwrap();
    assert_eq!(harness.provider.verify(&identity).unwrap(), snapshot);
}

#[tokio::test(flavor = "multi_thread")]
async fn cross_registry_stale_and_component_downgrade_authority_reject() {
    let first = harness(0x39).await;
    let second = harness(0x49).await;
    let first_host = first
        .provider
        .register_host(HostEmitterId::Runtime)
        .unwrap();
    let identity = first
        .provider
        .mint_live_identity(first_host.handle())
        .unwrap();
    assert!(matches!(
        second.provider.verify(&identity),
        Err(SensitiveParamCatalogError::InvalidCarrier)
            | Err(SensitiveParamCatalogError::StaleIdentity)
            | Err(SensitiveParamCatalogError::UnknownIdentity)
    ));

    publish_component(
        &first,
        "no-downgrade",
        "no-downgrade",
        vec!["token".to_owned()],
    )
    .await;
    assert!(first
        .provider
        .begin_agent_registration("downgrade-agent", "no-downgrade")
        .is_err());
    let source = reissued_source(&first.provider, "no-downgrade").await;
    let identity = first.provider.mint_live_identity(source.handle()).unwrap();
    let snapshot = first.provider.verify(&identity).unwrap();
    assert_eq!(snapshot.identity_class, ObservationIdentityClass::Component);
    assert_eq!(snapshot.names.as_ref(), &["token".to_owned()]);
}

#[tokio::test(flavor = "multi_thread")]
async fn termination_holds_while_any_subject_or_emission_lease_exists() {
    let mut harness = harness(0x3d).await;
    publish_agent(&harness, "register-held-agent", "held-agent");
    let source = reissued_source(&harness.provider, "held-agent").await;
    let live = harness
        .provider
        .mint_live_identity(source.handle())
        .unwrap();
    let member = harness.provider.lookup("held-agent").unwrap().claims();
    let record = termination_record(
        &harness,
        "terminate-held-agent",
        std::slice::from_ref(&member),
    )
    .await;
    let source_issuer = harness
        .issuer
        .take_source_emission_receipt_issuer()
        .unwrap();

    let (grants, emissions) = termination_prepare_receipt_vectors(
        &source_issuer,
        &harness.cleanup_issuer,
        &record,
        std::slice::from_ref(&member),
        1,
        1,
    )
    .unwrap();
    drop(emissions);
    assert!(harness
        .provider
        .prepare_agent_termination(
            "terminate-held-agent",
            &["held-agent".to_owned()],
            i64::MAX as u64,
            grants,
            Vec::new(),
        )
        .is_err());
    assert!(harness.provider.verify(&live).is_ok());

    let (grants, emissions) = termination_prepare_receipt_vectors(
        &source_issuer,
        &harness.cleanup_issuer,
        &record,
        std::slice::from_ref(&member),
        2,
        2,
    )
    .unwrap();
    drop(grants);
    assert!(harness
        .provider
        .prepare_agent_termination(
            "terminate-held-agent",
            &["held-agent".to_owned()],
            i64::MAX as u64,
            Vec::new(),
            emissions,
        )
        .is_err());
    assert!(harness.provider.verify(&live).is_ok());

    let (grants, emissions) = termination_prepare_receipt_vectors(
        &source_issuer,
        &harness.cleanup_issuer,
        &record,
        std::slice::from_ref(&member),
        3,
        3,
    )
    .unwrap();
    assert!(harness
        .provider
        .prepare_agent_termination(
            "terminate-held-agent",
            &["held-agent".to_owned()],
            i64::MAX as u64,
            grants,
            emissions,
        )
        .is_ok());
    assert_eq!(
        harness.provider.verify(&live),
        Err(SensitiveParamCatalogError::StaleIdentity)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn six_exact_typed_receipts_finalize_complete_member_set() {
    let mut harness = harness(0x3e).await;
    publish_agent(&harness, "register-six-a", "six-a");
    publish_agent(&harness, "register-six-b", "six-b");
    let members = vec![
        harness.provider.lookup("six-a").unwrap().claims(),
        harness.provider.lookup("six-b").unwrap().claims(),
    ];
    let record = termination_record(&harness, "terminate-six", &members).await;
    let source_issuer = harness
        .issuer
        .take_source_emission_receipt_issuer()
        .unwrap();
    let (grants, emissions) = termination_prepare_receipt_vectors(
        &source_issuer,
        &harness.cleanup_issuer,
        &record,
        &members,
        11,
        12,
    )
    .unwrap();
    let prepared = harness
        .provider
        .prepare_agent_termination(
            "terminate-six",
            &["six-b".to_owned(), "six-a".to_owned()],
            i64::MAX as u64,
            grants,
            emissions,
        )
        .unwrap();
    let receipts =
        termination_cleanup_receipts(&harness.cleanup_issuer, &record, &members, 13).unwrap();
    let cleanup = harness
        .cleanup_issuer
        .issue_cleanup_complete(&prepared, receipts)
        .unwrap();
    assert!(matches!(
        harness
            .provider
            .finalize_agent_termination(prepared, cleanup),
        TerminationFinalizeResult::Committed(_)
    ));
    for id in ["six-a", "six-b"] {
        let retained = harness.provider.lookup(id).unwrap();
        assert_eq!(retained.identity_class, ObservationIdentityClass::Agent);
        assert!(retained.names.is_empty());
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn missing_duplicate_extra_cross_operation_and_stale_receipts_reject() {
    let mut harness = harness(0x3f).await;
    publish_agent(&harness, "register-receipt-a", "receipt-a");
    publish_agent(&harness, "register-receipt-b", "receipt-b");
    let first = harness.provider.lookup("receipt-a").unwrap().claims();
    let second = harness.provider.lookup("receipt-b").unwrap().claims();
    let source_issuer = harness
        .issuer
        .take_source_emission_receipt_issuer()
        .unwrap();

    assert!(harness
        .provider
        .prepare_agent_termination(
            "terminate-missing",
            &["receipt-a".to_owned()],
            i64::MAX as u64,
            Vec::new(),
            Vec::new(),
        )
        .is_err());

    let record = TerminationOperationRecord {
        operation_id: "terminate-duplicate".to_owned(),
        member_set_digest: termination_member_set_digest(std::slice::from_ref(&first)).unwrap(),
        registry_sequence: harness
            .provider
            .current_anchor_tuple()
            .await
            .unwrap()
            .sequence
            + 1,
    };
    let duplicate_members = vec![first.clone(), first.clone()];
    let (grants, emissions) = termination_prepare_receipt_vectors(
        &source_issuer,
        &harness.cleanup_issuer,
        &record,
        &duplicate_members,
        2,
        2,
    )
    .unwrap();
    assert!(harness
        .provider
        .prepare_agent_termination(
            "terminate-duplicate",
            &["receipt-a".to_owned()],
            i64::MAX as u64,
            grants,
            emissions,
        )
        .is_err());

    let record =
        termination_record(&harness, "terminate-extra", std::slice::from_ref(&first)).await;
    let (grants, emissions) = termination_prepare_receipt_vectors(
        &source_issuer,
        &harness.cleanup_issuer,
        &record,
        &[first.clone(), second],
        3,
        3,
    )
    .unwrap();
    assert!(harness
        .provider
        .prepare_agent_termination(
            "terminate-extra",
            &["receipt-a".to_owned()],
            i64::MAX as u64,
            grants,
            emissions,
        )
        .is_err());

    let record = termination_record(
        &harness,
        "receipt-operation-a",
        std::slice::from_ref(&first),
    )
    .await;
    let (grants, emissions) = termination_prepare_receipt_vectors(
        &source_issuer,
        &harness.cleanup_issuer,
        &record,
        std::slice::from_ref(&first),
        4,
        4,
    )
    .unwrap();
    assert!(harness
        .provider
        .prepare_agent_termination(
            "receipt-operation-b",
            &["receipt-a".to_owned()],
            i64::MAX as u64,
            grants,
            emissions,
        )
        .is_err());

    let record =
        termination_record(&harness, "terminate-stale", std::slice::from_ref(&first)).await;
    let (grants, emissions) = termination_prepare_receipt_vectors(
        &source_issuer,
        &harness.cleanup_issuer,
        &record,
        std::slice::from_ref(&first),
        5,
        5,
    )
    .unwrap();
    harness
        .provider
        .register_host(HostEmitterId::RetentionSweeper)
        .unwrap();
    assert!(harness
        .provider
        .prepare_agent_termination(
            "terminate-stale",
            &["receipt-a".to_owned()],
            i64::MAX as u64,
            grants,
            emissions,
        )
        .is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn old_boot_reissue_requires_rescan_and_reproduces_owner_high_waters() {
    let mut harness = harness(0x40).await;
    publish_agent(&harness, "register-old-boot", "old-boot-agent");
    let member = harness.provider.lookup("old-boot-agent").unwrap().claims();
    let record = termination_record(
        &harness,
        "terminate-old-boot",
        std::slice::from_ref(&member),
    )
    .await;

    let (mut wrong_issuer, _wrong_verifier, _wrong_state, wrong_cleanup, _wrong_cleanup_verifier) =
        contract218_roles(
            harness.config.registry_instance,
            [0xee; 16],
            1,
            [harness.seed.wrapping_add(3); 32],
            [harness.seed.wrapping_add(4); 32],
        )
        .unwrap();
    let wrong_source = wrong_issuer.take_source_emission_receipt_issuer().unwrap();
    let (grants, emissions) = termination_prepare_receipt_vectors(
        &wrong_source,
        &wrong_cleanup,
        &record,
        std::slice::from_ref(&member),
        7,
        7,
    )
    .unwrap();
    assert!(harness
        .provider
        .prepare_agent_termination(
            "terminate-old-boot",
            &["old-boot-agent".to_owned()],
            i64::MAX as u64,
            grants,
            emissions,
        )
        .is_err());

    // An unrelated anchored mutation makes the prior complete-store scan
    // sequence stale.  Even correctly authenticated receipts over that old
    // operation record must fail until restart hydration performs a new scan.
    harness
        .provider
        .register_host(HostEmitterId::RetentionSweeper)
        .unwrap();
    let source = harness
        .issuer
        .take_source_emission_receipt_issuer()
        .unwrap();
    let (grants, emissions) = termination_prepare_receipt_vectors(
        &source,
        &harness.cleanup_issuer,
        &record,
        std::slice::from_ref(&member),
        7,
        7,
    )
    .unwrap();
    assert!(harness
        .provider
        .prepare_agent_termination(
            "terminate-old-boot",
            &["old-boot-agent".to_owned()],
            i64::MAX as u64,
            grants,
            emissions,
        )
        .is_err());

    let mut harness = restart_harness(harness).await;
    let rescanned_member = harness.provider.lookup("old-boot-agent").unwrap().claims();
    assert_eq!(rescanned_member, member);
    let rescanned_record = termination_record(
        &harness,
        "terminate-old-boot",
        std::slice::from_ref(&rescanned_member),
    )
    .await;
    assert!(rescanned_record.registry_sequence > record.registry_sequence);
    let source = harness
        .issuer
        .take_source_emission_receipt_issuer()
        .unwrap();
    let (grants, emissions) = termination_prepare_receipt_vectors(
        &source,
        &harness.cleanup_issuer,
        &rescanned_record,
        std::slice::from_ref(&rescanned_member),
        8,
        8,
    )
    .unwrap();
    assert!(harness
        .provider
        .prepare_agent_termination(
            "terminate-old-boot",
            &["old-boot-agent".to_owned()],
            i64::MAX as u64,
            grants,
            emissions,
        )
        .is_ok());
}

#[tokio::test(flavor = "multi_thread")]
async fn finalize_capacity_and_every_prepare_finalize_failpoint_recover() {
    let mut harness = harness(0x41).await;
    publish_agent(&harness, "register-finalize", "finalize-agent");
    let member = harness.provider.lookup("finalize-agent").unwrap().claims();
    let record = termination_record(
        &harness,
        "terminate-finalize",
        std::slice::from_ref(&member),
    )
    .await;
    let source = harness
        .issuer
        .take_source_emission_receipt_issuer()
        .unwrap();
    let (grants, emissions) = termination_prepare_receipt_vectors(
        &source,
        &harness.cleanup_issuer,
        &record,
        std::slice::from_ref(&member),
        8,
        8,
    )
    .unwrap();
    let prepared = harness
        .provider
        .prepare_agent_termination(
            "terminate-finalize",
            &["finalize-agent".to_owned()],
            i64::MAX as u64,
            grants,
            emissions,
        )
        .unwrap();
    assert!(harness
        .cleanup_issuer
        .issue_cleanup_complete(&prepared, TerminationCleanupReceiptSet::new(Vec::new()))
        .is_err());
    let receipts = termination_cleanup_receipts(
        &harness.cleanup_issuer,
        &record,
        std::slice::from_ref(&member),
        9,
    )
    .unwrap();
    let cleanup = harness
        .cleanup_issuer
        .issue_cleanup_complete(&prepared, receipts)
        .unwrap();
    assert!(matches!(
        harness
            .provider
            .finalize_agent_termination(prepared, cleanup),
        TerminationFinalizeResult::Committed(_)
    ));

    #[cfg(feature = "test-support")]
    {
        for (index, stage) in MUTATION_FAILPOINT_STAGES.into_iter().enumerate() {
            assert_termination_prepare_failpoint(stage, 0x80 + index as u8).await;
            assert_termination_finalize_failpoint(stage, 0x90 + index as u8).await;
        }
        for (index, boundary) in [
            TerminationFinalizeCapacityBoundary::CapMinusOne,
            TerminationFinalizeCapacityBoundary::AtCap,
            TerminationFinalizeCapacityBoundary::CapPlusOne,
        ]
        .into_iter()
        .enumerate()
        {
            assert_termination_capacity_boundary(boundary, 0xa0 + index as u8).await;
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn purpose_two_gc_blocks_while_m009_m019_c123_reference_exists() {
    let mut harness = harness(0x42).await;
    publish_agent(&harness, "register-gc-blocked", "gc-blocked-agent");
    let (finalized, _) =
        finalize_published_agent(&mut harness, "terminate-gc-blocked", "gc-blocked-agent").await;
    let challenge = harness
        .provider
        .prepare_retained_tombstone_gc(&finalized)
        .unwrap();
    let current = harness.provider.current_anchor_tuple().await.unwrap();
    let verifier = fixture_verifier(&harness);
    let mut owners = gc_owner_projections(&harness, &current);
    // A stale registry scan means the complete five-owner zero-reference
    // proof is absent; no external owner count is accepted as raw authority.
    owners[4].1 -= 1;
    let (purpose2, receipts) = retained_tombstone_gc_inputs(&verifier, &challenge, owners).unwrap();
    assert!(harness
        .provider
        .collect_retained_tombstone_gc(challenge, purpose2, receipts)
        .is_err());
    assert!(harness.provider.lookup("gc-blocked-agent").is_ok());
}

#[tokio::test(flavor = "multi_thread")]
async fn purpose_two_gc_collects_after_exact_zero_scans_and_preserves_high_water() {
    let mut harness = harness(0x43).await;
    publish_agent(&harness, "register-gc-collect", "gc-collect-agent");
    let (finalized, incarnation) =
        finalize_published_agent(&mut harness, "terminate-gc-collect", "gc-collect-agent").await;
    let challenge = harness
        .provider
        .prepare_retained_tombstone_gc(&finalized)
        .unwrap();
    let current = harness.provider.current_anchor_tuple().await.unwrap();
    let verifier = fixture_verifier(&harness);
    let (purpose2, receipts) = retained_tombstone_gc_inputs(
        &verifier,
        &challenge,
        gc_owner_projections(&harness, &current),
    )
    .unwrap();
    harness
        .provider
        .collect_retained_tombstone_gc(challenge, purpose2, receipts)
        .unwrap();
    assert_eq!(
        harness.provider.lookup("gc-collect-agent"),
        Err(SensitiveParamCatalogError::UnknownIdentity)
    );

    publish_agent(&harness, "register-gc-collect-reuse", "gc-collect-agent");
    assert_eq!(
        harness
            .provider
            .lookup("gc-collect-agent")
            .unwrap()
            .incarnation,
        incarnation + 1
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn gc_challenge_receipt_mac_nonce_and_kats_reject_tamper_replay() {
    let mut first = harness(0x44).await;
    let mut second = harness(0x54).await;
    publish_agent(&first, "register-gc-proof-a", "gc-proof-a");
    publish_agent(&second, "register-gc-proof-b", "gc-proof-b");
    let (first_finalized, _) =
        finalize_published_agent(&mut first, "terminate-gc-proof-a", "gc-proof-a").await;
    let (second_finalized, _) =
        finalize_published_agent(&mut second, "terminate-gc-proof-b", "gc-proof-b").await;
    let first_challenge = first
        .provider
        .prepare_retained_tombstone_gc(&first_finalized)
        .unwrap();
    let second_challenge = second
        .provider
        .prepare_retained_tombstone_gc(&second_finalized)
        .unwrap();
    let first_verifier = fixture_verifier(&first);
    let second_verifier = fixture_verifier(&second);
    let first_metadata = first_verifier
        .inspect_retained_tombstone_gc_challenge(&first_challenge)
        .unwrap();
    let second_metadata = second_verifier
        .inspect_retained_tombstone_gc_challenge(&second_challenge)
        .unwrap();
    assert_ne!(first_metadata.challenge_nonce, [0; 32]);
    assert_ne!(second_metadata.challenge_nonce, [0; 32]);
    assert_ne!(
        first_metadata.challenge_nonce,
        second_metadata.challenge_nonce
    );

    let second_current = second.provider.current_anchor_tuple().await.unwrap();
    let (cross_purpose2, cross_receipts) = retained_tombstone_gc_inputs(
        &second_verifier,
        &second_challenge,
        gc_owner_projections(&second, &second_current),
    )
    .unwrap();
    assert!(first
        .provider
        .collect_retained_tombstone_gc(first_challenge, cross_purpose2, cross_receipts)
        .is_err());

    let first_challenge = first
        .provider
        .prepare_retained_tombstone_gc(&first_finalized)
        .unwrap();
    let first_current = first.provider.current_anchor_tuple().await.unwrap();
    let (purpose2, receipts) = retained_tombstone_gc_inputs(
        &first_verifier,
        &first_challenge,
        gc_owner_projections(&first, &first_current),
    )
    .unwrap();
    first
        .provider
        .collect_retained_tombstone_gc(first_challenge, purpose2, receipts)
        .unwrap();
    assert!(first
        .provider
        .prepare_retained_tombstone_gc(&first_finalized)
        .is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn closed_host_inventory_round_trips_only_three_ids() {
    let harness = harness(0x3a).await;
    let expected = [
        HostEmitterId::Runtime,
        HostEmitterId::RetentionSweeper,
        HostEmitterId::PackManager,
    ];
    for emitter in expected {
        harness.provider.register_host(emitter).unwrap();
    }
    let receipt = harness
        .provider
        .issue_completed_hydration_receipt()
        .await
        .unwrap();
    let mut actual = harness
        .provider
        .reissue_boot_sources(&receipt)
        .unwrap()
        .into_iter()
        .map(|source| source.canonical_id().to_owned())
        .collect::<Vec<_>>();
    actual.sort();
    let mut expected = expected
        .into_iter()
        .map(|emitter| emitter.canonical_id().to_owned())
        .collect::<Vec<_>>();
    expected.sort();
    assert_eq!(actual, expected);
}

#[tokio::test(flavor = "multi_thread")]
async fn legacy_raw_host_aliases_and_manifest_conflicts_reject() {
    let harness = harness(0x3b).await;
    for alias in ["runtime", "retention_sweeper", "pack-manager"] {
        let tags_before = harness.anchor.operation_tags();
        assert!(harness
            .provider
            .commit_component_unpublished(
                format!("legacy-component-{alias}"),
                "test".to_owned(),
                component(alias, vec![]),
                None,
            )
            .await
            .is_err());
        assert!(harness
            .provider
            .begin_agent_registration(&format!("legacy-agent-{alias}"), alias)
            .is_err());
        assert_eq!(harness.anchor.operation_tags(), tags_before);
    }
    harness
        .provider
        .register_host(HostEmitterId::Runtime)
        .unwrap();
    assert!(harness
        .provider
        .begin_agent_registration("host-class-conflict", "__sys:runtime")
        .is_err());
    assert!(harness
        .provider
        .commit_component_unpublished(
            "host-component-conflict".to_owned(),
            "test".to_owned(),
            component("__sys:runtime", vec![]),
            None,
        )
        .await
        .is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn restart_preserves_incarnation_digest_and_ignores_watch_revision() {
    let harness = harness(0x3c).await;
    publish_component(
        &harness,
        "restart-authority",
        "restart-authority",
        vec!["token".to_owned(), "credential".to_owned()],
    )
    .await;
    // A second visible mutation makes the pre-restart volatile revision differ
    // from the fresh boot's revision without changing component authority.
    harness
        .provider
        .register_host(HostEmitterId::Runtime)
        .unwrap();
    let before = harness.provider.lookup("restart-authority").unwrap();
    assert!(before.revision > 1);
    let Harness {
        _temp,
        registry,
        anchor,
        provider,
        issuer: _,
        cleanup_issuer: _,
        config,
        seed,
    } = harness;
    drop(provider);
    let (provider, issuer, cleanup_issuer) =
        open_provider(Arc::clone(&registry), Arc::clone(&anchor), config, seed).await;
    let _keep_roles = (issuer, cleanup_issuer);
    let after = provider.lookup("restart-authority").unwrap();
    assert_eq!(after.claims(), before.claims());
    assert_eq!(after.names, before.names);
    assert_ne!(after.revision, before.revision);
}

#[tokio::test(flavor = "multi_thread")]
async fn reuse_after_authenticated_gc_advances_high_water() {
    let mut harness = harness(0x45).await;
    publish_agent(&harness, "register-reuse", "reuse-agent");
    let source = reissued_source(&harness.provider, "reuse-agent").await;
    let old_live = harness
        .provider
        .mint_live_identity(source.handle())
        .unwrap();
    let (finalized, old_incarnation) =
        finalize_published_agent(&mut harness, "terminate-reuse", "reuse-agent").await;
    let challenge = harness
        .provider
        .prepare_retained_tombstone_gc(&finalized)
        .unwrap();
    let current = harness.provider.current_anchor_tuple().await.unwrap();
    let verifier = fixture_verifier(&harness);
    let (purpose2, receipts) = retained_tombstone_gc_inputs(
        &verifier,
        &challenge,
        gc_owner_projections(&harness, &current),
    )
    .unwrap();
    harness
        .provider
        .collect_retained_tombstone_gc(challenge, purpose2, receipts)
        .unwrap();
    publish_agent(&harness, "register-reuse-next", "reuse-agent");
    let next = harness.provider.lookup("reuse-agent").unwrap();
    assert_eq!(next.incarnation, old_incarnation + 1);
    assert_eq!(
        harness.provider.verify(&old_live),
        Err(SensitiveParamCatalogError::StaleIdentity)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn allocation_insert_publish_failpoints_never_reuse_incarnation() {
    let mut harness = harness(0x46).await;
    publish_agent(&harness, "register-allocation", "allocation-agent");
    let (finalized, old_incarnation) =
        finalize_published_agent(&mut harness, "terminate-allocation", "allocation-agent").await;
    let challenge = harness
        .provider
        .prepare_retained_tombstone_gc(&finalized)
        .unwrap();
    let current = harness.provider.current_anchor_tuple().await.unwrap();
    let verifier = fixture_verifier(&harness);
    let (purpose2, receipts) = retained_tombstone_gc_inputs(
        &verifier,
        &challenge,
        gc_owner_projections(&harness, &current),
    )
    .unwrap();
    harness
        .provider
        .collect_retained_tombstone_gc(challenge, purpose2, receipts)
        .unwrap();

    let mut revision = harness.provider.subscribe();
    let before = *revision.borrow_and_update();
    harness
        .provider
        .begin_agent_registration("allocation-pending", "allocation-agent")
        .unwrap();
    assert_eq!(*revision.borrow(), before);
    assert_eq!(
        harness.provider.lookup("allocation-agent"),
        Err(SensitiveParamCatalogError::UnknownIdentity)
    );
    assert!(harness
        .provider
        .begin_agent_registration("allocation-duplicate", "allocation-agent")
        .is_err());
    let activation = harness
        .provider
        .activate_agent_unpublished("allocation-pending")
        .unwrap();
    assert_eq!(*revision.borrow(), before);
    let ready = harness
        .issuer
        .issue_ready_proof(
            &activation,
            previsible_ready_receipts(&harness.issuer, &activation).unwrap(),
        )
        .unwrap();
    assert!(matches!(
        harness.provider.publish_agent_activation(activation, ready),
        AgentPublicationResult::Published(_)
    ));
    assert_eq!(*revision.borrow(), before + 1);
    assert_eq!(
        harness
            .provider
            .lookup("allocation-agent")
            .unwrap()
            .incarnation,
        old_incarnation + 1
    );

    #[cfg(feature = "test-support")]
    for (index, stage) in MUTATION_FAILPOINT_STAGES.into_iter().enumerate() {
        assert_agent_allocation_failpoint(stage, 0xb0 + index as u8).await;
        assert_agent_publish_failpoint(stage, 0xc0 + index as u8).await;
    }
}

#[cfg(feature = "test-support")]
#[tokio::test(flavor = "multi_thread")]
async fn termination_succeeds_at_identity_and_authority_cap() {
    let mut harness = harness(0xb1).await;
    publish_agent(&harness, "register-cap-drain-agent", "cap-drain-agent");
    harness
        .provider
        .seed_identity_and_authority_at_capacity()
        .unwrap();
    let (_ack, _) =
        finalize_published_agent(&mut harness, "terminate-cap-drain-agent", "cap-drain-agent")
            .await;
    assert!(harness
        .provider
        .operation_history_test_fixture("terminate-cap-drain-agent")
        .unwrap());
}

#[cfg(feature = "test-support")]
#[tokio::test(flavor = "multi_thread")]
async fn same_id_reuse_succeeds_at_authority_cap() {
    let (harness, previous_incarnation) =
        collected_agent_for_reuse(0xb2, "authority-cap-reuse").await;
    harness.provider.seed_authority_at_capacity().unwrap();
    publish_agent(
        &harness,
        "register-authority-cap-reuse",
        "authority-cap-reuse",
    );
    assert_eq!(
        harness
            .provider
            .lookup("authority-cap-reuse")
            .unwrap()
            .claims()
            .incarnation,
        previous_incarnation + 1
    );
}

#[cfg(feature = "test-support")]
#[tokio::test(flavor = "multi_thread")]
async fn host_registration_succeeds_at_active_operation_cap() {
    let harness = harness(0xb3).await;
    harness
        .provider
        .begin_agent_registration("active-cap-held", "active-cap-held-agent")
        .unwrap();
    harness
        .provider
        .seed_active_operation_at_capacity()
        .unwrap();
    let host = harness
        .provider
        .register_host(HostEmitterId::Runtime)
        .unwrap();
    assert_eq!(host.canonical_id(), HostEmitterId::Runtime.canonical_id());
    assert!(harness
        .provider
        .operation_history_test_fixture("active-cap-held")
        .unwrap());
}

#[cfg(feature = "test-support")]
#[tokio::test(flavor = "multi_thread")]
async fn committed_operation_and_member_cap_minus_one_cap_plus_one() {
    let harness = harness(0xb4).await;
    harness
        .provider
        .seed_committed_history_capacity_remaining(2)
        .unwrap();

    // First insert leaves both bounded histories at cap-1; the second reaches
    // the exact cap, and the third prospective insert is cap+1 and rejects.
    harness
        .provider
        .begin_agent_registration("history-cap-minus-one", "history-cap-agent-a")
        .unwrap();
    harness
        .provider
        .begin_agent_registration("history-cap-exact", "history-cap-agent-b")
        .unwrap();
    assert!(matches!(
        harness
            .provider
            .begin_agent_registration("history-cap-plus-one", "history-cap-agent-c"),
        Err(SensitiveParamCatalogError::CapacityExceeded)
    ));
    assert!(!harness
        .provider
        .operation_history_test_fixture("history-cap-plus-one")
        .unwrap());
}

#[cfg(feature = "test-support")]
#[tokio::test(flavor = "multi_thread")]
async fn tag_one_and_tag_two_reserve_real_previsible_row_and_bytes_before_tag_three() {
    // Tag 1: leave two complete byte envelopes but only one real row slot.
    // The second operation therefore fails on row pressure, while the first
    // reservation remains rooted and survives restart into tag 3.
    let mut component_harness = harness(0xb7).await;
    let component_before = component_harness
        .provider
        .observation_capacity_test_fixture()
        .unwrap();
    component_harness
        .provider
        .seed_previsible_admission_capacity_boundary(
            PrevisibleAdmissionCapacityBoundary::OneRowRemaining,
        )
        .unwrap();
    let receipt = component_harness
        .provider
        .commit_component_unpublished(
            "row-cap-component".to_owned(),
            "test".to_owned(),
            component("row-cap-component-id", vec![]),
            None,
        )
        .await
        .unwrap();
    let component_reserved = component_harness
        .provider
        .observation_capacity_test_fixture()
        .unwrap();
    assert_eq!(
        component_reserved.previsible_rows,
        component_before.previsible_rows + 1
    );
    assert_eq!(
        component_reserved.previsible_actual_bytes,
        component_before.previsible_actual_bytes
    );
    assert_eq!(
        component_reserved.previsible_future_bytes,
        component_before.previsible_future_bytes + 4_096
    );
    let component_reserved_root = component_harness
        .provider
        .current_anchor_tuple()
        .await
        .unwrap();
    assert!(matches!(
        component_harness
            .provider
            .commit_component_unpublished(
                "row-cap-rejected".to_owned(),
                "test".to_owned(),
                component("row-cap-rejected-id", vec![]),
                None,
            )
            .await,
        Err(ObservationProviderError::CapacityExceeded(_))
    ));
    assert_eq!(
        component_harness
            .provider
            .observation_capacity_test_fixture()
            .unwrap(),
        component_reserved
    );
    assert_eq!(
        component_harness
            .provider
            .current_anchor_tuple()
            .await
            .unwrap(),
        component_reserved_root
    );
    component_harness = restart_harness(component_harness).await;
    assert_eq!(
        component_harness
            .provider
            .observation_capacity_test_fixture()
            .unwrap(),
        component_reserved
    );
    assert_eq!(
        component_harness
            .provider
            .current_anchor_tuple()
            .await
            .unwrap(),
        component_reserved_root
    );
    let activation = component_harness
        .provider
        .issue_component_source(&receipt)
        .unwrap();
    let component_tag_three = component_harness
        .provider
        .observation_capacity_test_fixture()
        .unwrap();
    assert_eq!(
        component_tag_three.previsible_rows,
        component_reserved.previsible_rows
    );
    assert!(
        component_tag_three.previsible_actual_bytes > component_reserved.previsible_actual_bytes
    );
    assert_eq!(
        component_tag_three.previsible_actual_bytes + component_tag_three.previsible_future_bytes,
        component_reserved.previsible_actual_bytes + component_reserved.previsible_future_bytes
    );
    let ready = component_harness
        .issuer
        .issue_ready_proof(
            &activation,
            previsible_ready_receipts(&component_harness.issuer, &activation).unwrap(),
        )
        .unwrap();
    assert!(matches!(
        component_harness
            .provider
            .publish_component_source(activation, ready),
        ComponentPublicationResult::Published(_)
    ));
    assert_eq!(
        component_harness
            .provider
            .observation_capacity_test_fixture()
            .unwrap()
            .previsible_future_bytes,
        component_before.previsible_future_bytes + 8
    );

    // Tag 2: leave two row slots but one complete byte envelope. The second
    // operation fails only on combined-byte pressure. Restart then consumes
    // the first operation's exact reservation without a second charge.
    let mut agent_harness = harness(0xb8).await;
    let agent_before = agent_harness
        .provider
        .observation_capacity_test_fixture()
        .unwrap();
    agent_harness
        .provider
        .seed_previsible_admission_capacity_boundary(
            PrevisibleAdmissionCapacityBoundary::OneReservationRemaining,
        )
        .unwrap();
    agent_harness
        .provider
        .begin_agent_registration("byte-cap-agent", "byte-cap-agent-id")
        .unwrap();
    let agent_reserved = agent_harness
        .provider
        .observation_capacity_test_fixture()
        .unwrap();
    assert_eq!(
        agent_reserved.previsible_rows,
        agent_before.previsible_rows + 1
    );
    assert_eq!(
        agent_reserved.previsible_actual_bytes,
        agent_before.previsible_actual_bytes
    );
    assert_eq!(
        agent_reserved.previsible_future_bytes,
        agent_before.previsible_future_bytes + 4_096
    );
    let agent_reserved_root = agent_harness.provider.current_anchor_tuple().await.unwrap();
    assert!(matches!(
        agent_harness
            .provider
            .begin_agent_registration("byte-cap-rejected", "byte-cap-rejected-id"),
        Err(SensitiveParamCatalogError::CapacityExceeded)
    ));
    assert_eq!(
        agent_harness
            .provider
            .observation_capacity_test_fixture()
            .unwrap(),
        agent_reserved
    );
    agent_harness = restart_harness(agent_harness).await;
    assert_eq!(
        agent_harness.provider.current_anchor_tuple().await.unwrap(),
        agent_reserved_root
    );
    let activation = agent_harness
        .provider
        .activate_agent_unpublished("byte-cap-agent")
        .unwrap();
    let agent_tag_three = agent_harness
        .provider
        .observation_capacity_test_fixture()
        .unwrap();
    assert_eq!(
        agent_tag_three.previsible_rows,
        agent_reserved.previsible_rows
    );
    assert!(agent_tag_three.previsible_actual_bytes > agent_reserved.previsible_actual_bytes);
    assert_eq!(
        agent_tag_three.previsible_actual_bytes + agent_tag_three.previsible_future_bytes,
        agent_reserved.previsible_actual_bytes + agent_reserved.previsible_future_bytes
    );
    let ready = agent_harness
        .issuer
        .issue_ready_proof(
            &activation,
            previsible_ready_receipts(&agent_harness.issuer, &activation).unwrap(),
        )
        .unwrap();
    assert!(matches!(
        agent_harness
            .provider
            .publish_agent_activation(activation, ready),
        AgentPublicationResult::Published(_)
    ));
    assert_eq!(
        agent_harness
            .provider
            .observation_capacity_test_fixture()
            .unwrap()
            .previsible_future_bytes,
        agent_before.previsible_future_bytes + 8
    );
}

#[cfg(feature = "test-support")]
#[tokio::test(flavor = "multi_thread")]
async fn tag_three_consumes_one_reservation_across_every_restart_boundary_and_abort() {
    for (index, stage) in MUTATION_FAILPOINT_STAGES.into_iter().enumerate() {
        let mut failed = harness(0xe8 + index as u8).await;
        let operation = format!("tag-three-reservation-{index}");
        let identity = format!("tag-three-reservation-agent-{index}");
        let before = failed.provider.observation_capacity_test_fixture().unwrap();
        failed
            .provider
            .begin_agent_registration(&operation, &identity)
            .unwrap();
        let reserved = failed.provider.observation_capacity_test_fixture().unwrap();
        assert_eq!(reserved.previsible_rows, before.previsible_rows + 1);
        assert_eq!(
            reserved.previsible_actual_bytes,
            before.previsible_actual_bytes
        );
        assert_eq!(
            reserved.previsible_future_bytes,
            before.previsible_future_bytes + 4_096
        );
        let reserved_root = failed.provider.current_anchor_tuple().await.unwrap();

        failed
            .provider
            .inject_next_observation_mutation_failpoint(stage)
            .unwrap();
        assert!(failed
            .provider
            .activate_agent_unpublished(&operation)
            .is_err());
        failed = restart_harness(failed).await;

        let restart_capacity = failed.provider.observation_capacity_test_fixture().unwrap();
        if failpoint_commits_database(stage) {
            assert_eq!(restart_capacity.previsible_rows, reserved.previsible_rows);
            assert!(restart_capacity.previsible_actual_bytes > reserved.previsible_actual_bytes);
            assert_eq!(
                restart_capacity.previsible_actual_bytes + restart_capacity.previsible_future_bytes,
                reserved.previsible_actual_bytes + reserved.previsible_future_bytes
            );
            assert_ne!(
                failed.provider.current_anchor_tuple().await.unwrap(),
                reserved_root
            );
        } else {
            assert_eq!(restart_capacity, reserved);
            assert_eq!(
                failed.provider.current_anchor_tuple().await.unwrap(),
                reserved_root
            );
        }

        // A committed tag-3 row rehydrates; an uncommitted one consumes the
        // reservation now. A second rehydrate must not move any counters or
        // advance the root again.
        let _first = failed
            .provider
            .activate_agent_unpublished(&operation)
            .unwrap();
        let consumed = failed.provider.observation_capacity_test_fixture().unwrap();
        assert_eq!(consumed.previsible_rows, reserved.previsible_rows);
        assert!(consumed.previsible_actual_bytes > reserved.previsible_actual_bytes);
        assert_eq!(
            consumed.previsible_actual_bytes + consumed.previsible_future_bytes,
            reserved.previsible_actual_bytes + reserved.previsible_future_bytes
        );
        let consumed_root = failed.provider.current_anchor_tuple().await.unwrap();
        let activation = failed
            .provider
            .activate_agent_unpublished(&operation)
            .unwrap();
        assert_eq!(
            failed.provider.observation_capacity_test_fixture().unwrap(),
            consumed
        );
        assert_eq!(
            failed.provider.current_anchor_tuple().await.unwrap(),
            consumed_root
        );

        let proof = failed
            .issuer
            .issue_abort_proof(
                &activation,
                previsible_abort_receipts(&failed.issuer, &activation).unwrap(),
            )
            .unwrap();
        let verifier = fixture_verifier(&failed);
        let clean = match verifier.verify_abort_proof(activation, proof).unwrap() {
            PrevisibleAbortBundle::Agent(clean) => clean,
            PrevisibleAbortBundle::Component(_) => {
                panic!("agent activation produced a component abort bundle")
            }
        };
        failed
            .provider
            .abort_agent_registration(clean, i64::MAX as u64)
            .unwrap();
        let terminal = failed.provider.observation_capacity_test_fixture().unwrap();
        assert_eq!(terminal.previsible_rows, reserved.previsible_rows);
        assert_eq!(
            terminal.previsible_future_bytes,
            before.previsible_future_bytes + 8
        );
        assert_ne!(
            failed.provider.current_anchor_tuple().await.unwrap(),
            consumed_root
        );
        let terminal_root = failed.provider.current_anchor_tuple().await.unwrap();
        failed = restart_harness(failed).await;
        assert_eq!(
            failed.provider.observation_capacity_test_fixture().unwrap(),
            terminal
        );
        assert_eq!(
            failed.provider.current_anchor_tuple().await.unwrap(),
            terminal_root
        );
        assert_eq!(
            failed.provider.lookup(&identity),
            Err(SensitiveParamCatalogError::UnknownIdentity)
        );
    }
}

#[cfg(feature = "test-support")]
#[tokio::test(flavor = "multi_thread")]
async fn audit_checkpoint_moves_reserved_headroom_at_full_cap_across_every_restart_boundary() {
    let future_audit_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
        + 32 * 24 * 60 * 60 * 1_000;
    for (index, stage) in MUTATION_FAILPOINT_STAGES.into_iter().enumerate() {
        let mut failed = harness(0xd0 + index as u8).await;
        let registration = format!("checkpoint-cap-registration-{index}");
        let identity = format!("checkpoint-cap-agent-{index}");
        let termination = format!("checkpoint-cap-termination-{index}");
        publish_agent(&failed, &registration, &identity);
        finalize_published_agent(&mut failed, &termination, &identity).await;
        let before = failed.provider.observation_capacity_test_fixture().unwrap();
        assert_eq!(before.previsible_rows, 1);
        assert_eq!(before.previsible_future_bytes, 8);
        assert_eq!(before.finalization_rows, 1);
        assert_eq!(before.finalization_future_bytes, 8);
        let before_root = failed.provider.current_anchor_tuple().await.unwrap();
        failed
            .provider
            .seed_audit_checkpoint_capacity_at_current_usage()
            .unwrap();
        let checkpoint = failed
            .provider
            .audit_checkpoint_test_fixture(future_audit_time)
            .unwrap();
        failed
            .provider
            .inject_next_observation_mutation_failpoint(stage)
            .unwrap();
        assert!(failed
            .provider
            .compact_checkpointed_terminal_prefix(checkpoint)
            .is_err());
        failed = restart_harness(failed).await;

        let mut after = failed.provider.observation_capacity_test_fixture().unwrap();
        if !failpoint_commits_database(stage) {
            assert_eq!(after, before);
            assert_eq!(
                failed.provider.current_anchor_tuple().await.unwrap(),
                before_root
            );
            failed
                .provider
                .seed_audit_checkpoint_capacity_at_current_usage()
                .unwrap();
            let checkpoint = failed
                .provider
                .audit_checkpoint_test_fixture(future_audit_time)
                .unwrap();
            let installed = failed
                .provider
                .compact_checkpointed_terminal_prefix(checkpoint)
                .unwrap();
            assert_eq!(installed.checkpointed_journals, 2);
            after = failed.provider.observation_capacity_test_fixture().unwrap();
        }
        assert_eq!(after.previsible_rows, before.previsible_rows);
        assert_eq!(
            after.previsible_actual_bytes,
            before.previsible_actual_bytes + 8
        );
        assert_eq!(
            after.previsible_future_bytes,
            before.previsible_future_bytes - 8
        );
        assert_eq!(after.finalization_rows, before.finalization_rows);
        assert_eq!(
            after.finalization_actual_bytes,
            before.finalization_actual_bytes + 8
        );
        assert_eq!(
            after.finalization_future_bytes,
            before.finalization_future_bytes - 8
        );
        assert_eq!(
            after.previsible_actual_bytes + after.previsible_future_bytes,
            before.previsible_actual_bytes + before.previsible_future_bytes
        );
        assert_eq!(
            after.finalization_actual_bytes + after.finalization_future_bytes,
            before.finalization_actual_bytes + before.finalization_future_bytes
        );
        let installed_root = failed.provider.current_anchor_tuple().await.unwrap();
        assert_ne!(installed_root, before_root);
        failed = restart_harness(failed).await;
        assert_eq!(
            failed.provider.observation_capacity_test_fixture().unwrap(),
            after
        );
        assert_eq!(
            failed.provider.current_anchor_tuple().await.unwrap(),
            installed_root
        );
    }
}

#[cfg(feature = "test-support")]
#[tokio::test(flavor = "multi_thread")]
async fn tag_seven_compacts_only_checkpointed_terminal_prefix() {
    let mut harness = harness(0xb5).await;
    publish_agent(&harness, "compact-first", "compact-first-agent");
    publish_agent(&harness, "compact-middle-register", "compact-middle-agent");
    let (middle_ack, _middle_incarnation) = finalize_published_agent(
        &mut harness,
        "compact-middle-termination",
        "compact-middle-agent",
    )
    .await;
    publish_agent(&harness, "compact-third", "compact-third-agent");

    let future_audit_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
        + 32 * 24 * 60 * 60 * 1_000;
    let checkpoint = harness
        .provider
        .audit_checkpoint_test_fixture(future_audit_time)
        .unwrap();
    let installed = harness
        .provider
        .compact_checkpointed_terminal_prefix(checkpoint)
        .unwrap();
    assert_eq!(installed.checkpointed_journals, 4);
    assert_eq!(installed.compacted_operations, 0);

    let checkpoint = harness
        .provider
        .audit_checkpoint_test_fixture(future_audit_time)
        .unwrap();
    let first_prefix = harness
        .provider
        .compact_checkpointed_terminal_prefix(checkpoint)
        .unwrap();
    assert_eq!(first_prefix.compacted_operations, 2);
    assert!(!harness
        .provider
        .operation_history_test_fixture("compact-first")
        .unwrap());
    assert!(harness
        .provider
        .operation_history_test_fixture("compact-middle-termination")
        .unwrap());
    assert!(harness
        .provider
        .operation_history_test_fixture("compact-third")
        .unwrap());
    assert!(harness.provider.lookup("compact-first-agent").is_ok());

    let challenge = harness
        .provider
        .prepare_retained_tombstone_gc(&middle_ack)
        .unwrap();
    let current = harness.provider.current_anchor_tuple().await.unwrap();
    let verifier = fixture_verifier(&harness);
    let (purpose2, receipts) = retained_tombstone_gc_inputs(
        &verifier,
        &challenge,
        gc_owner_projections(&harness, &current),
    )
    .unwrap();
    harness
        .provider
        .collect_retained_tombstone_gc(challenge, purpose2, receipts)
        .unwrap();

    let checkpoint = harness
        .provider
        .audit_checkpoint_test_fixture(future_audit_time)
        .unwrap();
    let second_prefix = harness
        .provider
        .compact_checkpointed_terminal_prefix(checkpoint)
        .unwrap();
    assert_eq!(second_prefix.compacted_operations, 2);
    assert!(!harness
        .provider
        .operation_history_test_fixture("compact-middle-termination")
        .unwrap());
    assert!(!harness
        .provider
        .operation_history_test_fixture("compact-third")
        .unwrap());

    for (index, stage) in MUTATION_FAILPOINT_STAGES.into_iter().enumerate() {
        let mut failed = self::harness(0xc0 + index as u8).await;
        let operation_id = format!("compact-failpoint-{index}");
        let identity_id = format!("compact-failpoint-agent-{index}");
        publish_agent(&failed, &operation_id, &identity_id);
        let checkpoint = failed
            .provider
            .audit_checkpoint_test_fixture(future_audit_time)
            .unwrap();
        let installed = failed
            .provider
            .compact_checkpointed_terminal_prefix(checkpoint)
            .unwrap();
        assert_eq!(installed.checkpointed_journals, 1);
        let checkpoint = failed
            .provider
            .audit_checkpoint_test_fixture(future_audit_time)
            .unwrap();
        failed
            .provider
            .inject_next_observation_mutation_failpoint(stage)
            .unwrap();
        assert!(failed
            .provider
            .compact_checkpointed_terminal_prefix(checkpoint)
            .is_err());
        failed = restart_harness(failed).await;
        while failed
            .provider
            .operation_history_test_fixture(&operation_id)
            .unwrap()
        {
            let checkpoint = failed
                .provider
                .audit_checkpoint_test_fixture(future_audit_time)
                .unwrap();
            failed
                .provider
                .compact_checkpointed_terminal_prefix(checkpoint)
                .unwrap();
        }
        assert!(failed.provider.lookup(&identity_id).is_ok());
    }
}

#[cfg(feature = "test-support")]
#[tokio::test(flavor = "multi_thread")]
async fn operation_tag_gc_and_compaction_field_transitions_are_closed() {
    let harness = harness(0xb6).await;
    publish_agent(&harness, "closed-operation-effects", "closed-effects-agent");
    let before = harness.provider.current_anchor_tuple().await.unwrap();
    for adversary in [
        OperationEffectAdversary::NonGcTagChangesGcFields,
        OperationEffectAdversary::GcTagSkipsFirstGeneration,
        OperationEffectAdversary::CompactionTagChangesNonCheckpointField,
    ] {
        assert!(harness
            .provider
            .operation_effect_adversary_test_fixture("closed-operation-effects", adversary)
            .is_err());
        assert_eq!(
            harness.provider.current_anchor_tuple().await.unwrap(),
            before
        );
    }
    assert!(harness
        .provider
        .operation_history_test_fixture("closed-operation-effects")
        .unwrap());
}

#[cfg(feature = "test-support")]
#[tokio::test(flavor = "multi_thread")]
async fn greenfield_schema_is_rechecked_inside_immediate_boundary_and_on_final_postimage() {
    for (index, stage) in [
        GreenfieldSchemaAdversaryStage::BeforeLockedPreimageValidation,
        GreenfieldSchemaAdversaryStage::BeforeFinalPostimageValidation,
    ]
    .into_iter()
    .enumerate()
    {
        let seed = 0xe0 + index as u8;
        let temp = tempfile::tempdir().unwrap();
        let registry = Arc::new(
            ComponentRegistry::open_in(temp.path(), "components.db")
                .await
                .unwrap(),
        );
        let anchor = Arc::new(MemoryAnchor::default());
        let config = ObservationProviderConfig::greenfield(
            [seed; 16],
            [seed.wrapping_add(1); 16],
            [seed.wrapping_add(2); 32],
            greenfield_keyring_file([seed; 16]),
        )
        .unwrap();
        RegistrySensitiveParamProvider::inject_next_greenfield_schema_adversary(
            config.registry_instance,
            stage,
        )
        .unwrap();
        assert!(matches!(
            try_open_provider(
                Arc::clone(&registry),
                Arc::clone(&anchor),
                config.clone(),
                seed,
            )
            .await,
            Err(ObservationProviderError::Registry(_))
                | Err(ObservationProviderError::RecoveryRequired(_))
        ));
        drop(registry);

        // The adversarial DDL and every partial genesis write share the failed
        // transaction, so a clean retry must observe neither and may install
        // one exact genesis root.
        let registry = Arc::new(
            ComponentRegistry::open_in(temp.path(), "components.db")
                .await
                .unwrap(),
        );
        let (provider, _issuer, _cleanup_issuer) =
            open_provider(registry, Arc::clone(&anchor), config, seed).await;
        assert!(provider.is_ready());
        assert_eq!(provider.current_anchor_tuple().await.unwrap().sequence, 0);
    }
}

#[cfg(feature = "test-support")]
#[tokio::test(flavor = "multi_thread")]
async fn restart_rejects_rogue_sqlite_schema_object_before_ready() {
    let harness = harness(0xb7).await;
    let Harness {
        _temp,
        registry,
        anchor: _,
        provider,
        issuer: _,
        cleanup_issuer: _,
        config: _,
        seed: _,
    } = harness;
    let database_path = _temp.path().join("components.db");
    drop(provider);
    drop(registry);
    let connection = rusqlite::Connection::open(&database_path).unwrap();
    connection
        .execute_batch(
            "CREATE TRIGGER rogue_observation_trigger
             AFTER UPDATE ON observation_identity_authority
             BEGIN SELECT 1; END;",
        )
        .unwrap();
    drop(connection);

    assert!(ComponentRegistry::open_in(_temp.path(), "components.db")
        .await
        .is_err());
}

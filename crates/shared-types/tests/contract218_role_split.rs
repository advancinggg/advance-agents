//! CONTRACT-218 structural/KAT boundary tests.

use advance_shared_types::contract218_previsible::{
    termination_member_set_digest, PersistedIdentityKeyringRole, PrevisibleAbortBundle,
    PrevisibleProofIssuerRole, PrevisibleProofVerifierRole, SigningKeyCapability,
    TerminationCleanupReceiptIssuerRole, TerminationOperationRecord, VerificationKeyCapability,
};
use advance_shared_types::observation_identity::{
    AgentObservationIdentityRegistrar, AuthenticatedObservationSourceHandle,
    ComponentObservationSourceIssuer, HostEmitterId, HostObservationIdentityRegistrar,
    ObservationIdentityAuthority, ObservationIdentityClaims, ObservationIdentityClass,
    ObservationIdentityPersistenceSealer, PersistedObservationBinding,
    PersistedObservationIdentity, SensitiveParamCatalog, SensitiveParamCatalogError,
    SensitiveParamDeclaration, SourceBindingDigest, TrustedObservationIdentity,
};
use advance_shared_types::test_support::{
    contract218_roles, persisted_identity_keyring_role, persisted_key_retirement_scans,
    previsible_abort_receipts, previsible_ready_receipts, retained_tombstone_gc_inputs,
    termination_cleanup_receipts, termination_prepare_receipts,
};

macro_rules! assert_not_impl {
    ($type:ty: $trait:path) => {
        const _: fn() = || {
            trait AmbiguousIfImpl<A> {
                fn marker() {}
            }
            impl<T: ?Sized> AmbiguousIfImpl<()> for T {}
            struct Invalid;
            impl<T: ?Sized + $trait> AmbiguousIfImpl<Invalid> for T {}
            let _ = <$type as AmbiguousIfImpl<_>>::marker;
        };
    };
}

assert_not_impl!(AuthenticatedObservationSourceHandle: Clone);
assert_not_impl!(AuthenticatedObservationSourceHandle: serde::Serialize);
assert_not_impl!(TrustedObservationIdentity: Clone);
assert_not_impl!(TrustedObservationIdentity: serde::Serialize);
assert_not_impl!(PersistedObservationIdentity: Clone);
assert_not_impl!(PersistedObservationIdentity: serde::Serialize);
assert_not_impl!(PrevisibleProofIssuerRole: Clone);
assert_not_impl!(PrevisibleProofVerifierRole: Clone);
assert_not_impl!(TerminationCleanupReceiptIssuerRole: Clone);
assert_not_impl!(PrevisibleProofIssuerRole: Into<PrevisibleProofVerifierRole>);
assert_not_impl!(PersistedIdentityKeyringRole: Clone);
assert_not_impl!(PersistedIdentityKeyringRole: serde::Serialize);
assert_not_impl!(SigningKeyCapability: Clone);
assert_not_impl!(SigningKeyCapability: serde::Serialize);
assert_not_impl!(VerificationKeyCapability: Clone);
assert_not_impl!(VerificationKeyCapability: serde::Serialize);

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

fn decode_hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |byte: u8| match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                b'A'..=b'F' => byte - b'A' + 10,
                _ => panic!("non-hex fixture"),
            };
            (digit(pair[0]) << 4) | digit(pair[1])
        })
        .collect()
}

fn termination_member(exact_id: &str, incarnation: u64) -> ObservationIdentityClaims {
    let declaration = SensitiveParamDeclaration::component(vec!["token".into()]).unwrap();
    ObservationIdentityClaims {
        exact_id: exact_id.into(),
        expected_class: ObservationIdentityClass::Component,
        incarnation,
        declaration_digest: declaration
            .digest_for(exact_id, ObservationIdentityClass::Component, incarnation)
            .unwrap(),
    }
}

fn termination_record(
    operation_id: &str,
    registry_sequence: u64,
    members: &[ObservationIdentityClaims],
) -> TerminationOperationRecord {
    TerminationOperationRecord {
        operation_id: operation_id.into(),
        member_set_digest: termination_member_set_digest(members).unwrap(),
        registry_sequence,
    }
}

#[test]
fn factory_splits_once_and_moves_exact_roles() {
    let (_issuer, verifier, _termination, _cleanup_issuer, _cleanup_verifier) =
        contract218_roles([0x11; 16], [0x22; 16], 1, [0x33; 32], [0x44; 32]).unwrap();

    let declaration = SensitiveParamDeclaration::host(HostEmitterId::Runtime);
    let claims = ObservationIdentityClaims {
        exact_id: HostEmitterId::Runtime.canonical_id().into(),
        expected_class: ObservationIdentityClass::Host,
        incarnation: 1,
        declaration_digest: declaration
            .digest_for(
                HostEmitterId::Runtime.canonical_id(),
                ObservationIdentityClass::Host,
                1,
            )
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
fn six_host_ports_are_separate_and_object_safe() {
    fn catalog(_: &dyn SensitiveParamCatalog) {}
    fn authority(_: &dyn ObservationIdentityAuthority) {}
    fn sealer(_: &dyn ObservationIdentityPersistenceSealer) {}
    fn component(_: &dyn ComponentObservationSourceIssuer) {}
    fn agent(_: &dyn AgentObservationIdentityRegistrar) {}
    fn host(_: &dyn HostObservationIdentityRegistrar) {}

    let _ = (catalog, authority, sealer, component, agent, host);
    let source = include_str!("../src/observation_identity.rs");
    assert_eq!(
        source.matches("pub trait SensitiveParamCatalog:").count(),
        1
    );
    assert_eq!(
        source
            .matches("pub trait ObservationIdentityAuthority:")
            .count(),
        1
    );
    assert_eq!(
        source
            .matches("pub trait ObservationIdentityPersistenceSealer:")
            .count(),
        1
    );
    assert_eq!(
        source
            .matches("pub trait ComponentObservationSourceIssuer:")
            .count(),
        1
    );
    assert_eq!(
        source
            .matches("pub trait AgentObservationIdentityRegistrar:")
            .count(),
        1
    );
    assert_eq!(
        source
            .matches("pub trait HostObservationIdentityRegistrar:")
            .count(),
        1
    );
    assert!(!source.contains("AggregateObservation"));
}

#[test]
fn declaration_and_source_digest_kats() {
    let declaration =
        SensitiveParamDeclaration::component(vec!["token".to_owned(), "api_key".to_owned()])
            .unwrap();
    let digest = declaration
        .digest_for("comp-a", ObservationIdentityClass::Component, 7)
        .unwrap();
    assert_eq!(
        hex(digest.as_bytes()),
        "61740ecea4d91975079b8cd0e44b6896849833c0af7c4a9cac1f976dcc67a5bb"
    );

    let claims = ObservationIdentityClaims {
        exact_id: "comp-a".into(),
        expected_class: ObservationIdentityClass::Component,
        incarnation: 7,
        declaration_digest: digest,
    };
    assert_eq!(
        hex(SourceBindingDigest::for_claims(&claims).unwrap().as_bytes()),
        "b15f7c082d0c879c25221f854d83d1050418df5148fce89fcce8b8f9ae989dab"
    );
}

#[test]
fn declaration_empty_control_duplicate_and_plus_one_reject_before_mutation() {
    assert_eq!(
        SensitiveParamDeclaration::component(vec![String::new()]),
        Err(SensitiveParamCatalogError::InvalidIdentity)
    );
    assert_eq!(
        SensitiveParamDeclaration::component(vec!["line\nbreak".into()]),
        Err(SensitiveParamCatalogError::InvalidIdentity)
    );
    assert_eq!(
        SensitiveParamDeclaration::component(vec!["x".into(), "x".into()]),
        Err(SensitiveParamCatalogError::InvalidIdentity)
    );
    assert_eq!(
        SensitiveParamDeclaration::component(
            (0..65).map(|index| format!("param-{index}")).collect()
        ),
        Err(SensitiveParamCatalogError::CapacityExceeded)
    );
    assert_eq!(
        SensitiveParamDeclaration::component(vec!["x".repeat(129)]),
        Err(SensitiveParamCatalogError::InvalidIdentity)
    );
}

#[test]
fn closed_host_inventory_round_trips_only_three_ids() {
    let ids = [
        HostEmitterId::Runtime.canonical_id(),
        HostEmitterId::RetentionSweeper.canonical_id(),
        HostEmitterId::PackManager.canonical_id(),
    ];
    assert_eq!(
        ids,
        [
            "__sys:runtime",
            "__sys:retention_sweeper",
            "__sys:pack-manager"
        ]
    );
}

#[test]
fn carrier_binds_event_cursor_safe_digest_and_exact_identity() {
    let (_, mut verifier, _, _, _) =
        contract218_roles([0x11; 16], [0x22; 16], 1, [0x33; 32], [0x44; 32]).unwrap();
    let keyring =
        persisted_identity_keyring_role(&mut verifier, [0x11; 16], 1, [0x44; 32], [1; 32]).unwrap();
    let signing = keyring.signing_key_capability().unwrap();
    let verification = keyring.verification_key_capability(1).unwrap();
    let declaration = SensitiveParamDeclaration::component(vec!["secret".into()]).unwrap();
    let claims = ObservationIdentityClaims {
        exact_id: "a".into(),
        expected_class: ObservationIdentityClass::Component,
        incarnation: 1,
        declaration_digest: declaration
            .digest_for("a", ObservationIdentityClass::Component, 1)
            .unwrap(),
    };
    let source = verifier.issue_live_source(claims.clone()).unwrap();
    let live = verifier.mint_live_identity(&source).unwrap();
    let binding = PersistedObservationBinding::new("E".into(), "E".into(), [0x11; 32]).unwrap();
    let carrier = keyring
        .seal_persisted_identity(&signing, &live, &binding)
        .unwrap();
    assert_eq!(carrier.canonical_bytes().len(), 125);

    let bytes = carrier.canonical_bytes().to_vec();
    for index in 0..bytes.len() {
        let mut changed = bytes.clone();
        changed[index] ^= 1;
        assert!(
            keyring
                .decode_persisted_identity(&verification, &changed)
                .is_err(),
            "byte {index} mutation unexpectedly verified"
        );
    }
}

#[test]
fn persisted_carrier_exact_125_byte_literal_kat_decodes_without_encoder_fixture() {
    // Independent MODULE-014 literal: master=00x32, salt=01x32, key id=1.
    // The expected bytes are fixed here and are never generated by the
    // production carrier encoder.
    let literal = decode_hex(concat!(
        "0100000001000000014500000001450000000161020000000000000001",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "1111111111111111111111111111111111111111111111111111111111111111",
        "ed21dcd5361b922744c981fcfe7e557a7c7608855bec10a2de260334620219e9"
    ));
    assert_eq!(literal.len(), 125);

    let (_, mut verifier, _, _, _) =
        contract218_roles([0x11; 16], [0x22; 16], 1, [0x33; 32], [0x44; 32]).unwrap();
    let keyring =
        persisted_identity_keyring_role(&mut verifier, [0x11; 16], 1, [0; 32], [1; 32]).unwrap();
    let verification = keyring.verification_key_capability(1).unwrap();
    let carrier = keyring
        .decode_persisted_identity(&verification, &literal)
        .unwrap();
    assert_eq!(carrier.key_id(), 1);
    assert_eq!(carrier.canonical_bytes(), literal);

    let persisted = keyring
        .rehydrate_persisted_identity(&verification, &carrier)
        .unwrap();
    let claims = persisted.claims_for_persistence();
    assert_eq!(claims.exact_id, "a");
    assert_eq!(claims.expected_class, ObservationIdentityClass::Agent);
    assert_eq!(claims.incarnation, 1);
    assert_eq!(claims.declaration_digest.as_bytes(), &[0; 32]);

    for index in [1usize, 5, 10, 15, 20, 60, 92] {
        let mut changed = literal.clone();
        changed[index] ^= 1;
        assert!(keyring
            .decode_persisted_identity(&verification, &changed)
            .is_err());
    }
}

#[test]
fn reseal_rotates_to_signing_key_and_old_key_stays_verifiable() {
    fn roles(
        key_id: u32,
    ) -> (
        advance_shared_types::contract218_previsible::PrevisibleProofVerifierRole,
        PersistedIdentityKeyringRole,
    ) {
        let (_, mut verifier, _, _, _) =
            contract218_roles([0x11; 16], [0x22; 16], key_id, [0x33; 32], [0x44; 32]).unwrap();
        let keyring =
            persisted_identity_keyring_role(&mut verifier, [0x11; 16], key_id, [0x44; 32], [1; 32])
                .unwrap();
        (verifier, keyring)
    }

    let (old, old_keyring) = roles(1);
    let old_signing = old_keyring.signing_key_capability().unwrap();
    let declaration = SensitiveParamDeclaration::agent_known_empty();
    let claims = ObservationIdentityClaims {
        exact_id: "agent:a".into(),
        expected_class: ObservationIdentityClass::Agent,
        incarnation: 1,
        declaration_digest: declaration
            .digest_for("agent:a", ObservationIdentityClass::Agent, 1)
            .unwrap(),
    };
    let source = old.issue_live_source(claims).unwrap();
    let live = old.mint_live_identity(&source).unwrap();
    let binding = PersistedObservationBinding::new("evt".into(), "evt".into(), [7; 32]).unwrap();
    let carrier_v1 = old_keyring
        .seal_persisted_identity(&old_signing, &live, &binding)
        .unwrap();
    assert_eq!(carrier_v1.key_id(), 1);

    let (_current_verifier, current) = roles(2);
    let verify_old = current.verification_key_capability(1).unwrap();
    let current_signing = current.signing_key_capability().unwrap();
    let old_under_verify_only = current
        .decode_persisted_identity(&verify_old, carrier_v1.canonical_bytes())
        .unwrap();
    let carrier_v2 = current
        .reseal_persisted_identity(
            &current_signing,
            &verify_old,
            &old_under_verify_only,
            &binding,
        )
        .unwrap();
    assert_eq!(carrier_v2.key_id(), 2);
    let verify_current = current.verification_key_capability(2).unwrap();
    assert!(current
        .decode_persisted_identity(&verify_current, carrier_v2.canonical_bytes())
        .is_ok());
}

#[test]
fn cross_role_calls_do_not_compile() {
    use std::any::TypeId;
    assert_ne!(
        TypeId::of::<PrevisibleProofIssuerRole>(),
        TypeId::of::<PrevisibleProofVerifierRole>()
    );
    // The module-level negative trait assertion additionally proves there is
    // no `Into<PrevisibleProofVerifierRole>` conversion from the issuer.
}

#[test]
fn authority_carriers_are_non_clone_non_serde() {
    // Module-level ambiguity assertions make this test target fail to compile
    // if any authority carrier gains Clone or Serialize.
    assert!(std::mem::needs_drop::<AuthenticatedObservationSourceHandle>());
    assert!(std::mem::needs_drop::<TrustedObservationIdentity>());
    assert!(std::mem::needs_drop::<PersistedObservationIdentity>());
}

#[test]
fn snapshot_names_recompute_declaration_digest() {
    let (_, verifier, _, _, _) =
        contract218_roles([0x11; 16], [0x22; 16], 1, [0x33; 32], [0x44; 32]).unwrap();
    let declaration = SensitiveParamDeclaration::component(vec!["api_key".into()]).unwrap();
    let claims = ObservationIdentityClaims {
        exact_id: "component-snapshot".into(),
        expected_class: ObservationIdentityClass::Component,
        incarnation: 3,
        declaration_digest: declaration
            .digest_for("component-snapshot", ObservationIdentityClass::Component, 3)
            .unwrap(),
    };
    let mut snapshot = verifier
        .issue_snapshot(claims, vec!["api_key".into()], 1)
        .unwrap();
    snapshot.names = std::sync::Arc::from(["wrong".to_owned()]);
    assert_eq!(
        snapshot.validate(),
        Err(SensitiveParamCatalogError::InvalidIdentity)
    );
}

#[test]
fn typed_ready_source_emission_and_six_owner_cleanup_reject_cross_operation() {
    let (mut proof_issuer, verifier, termination, cleanup_issuer, cleanup_verifier) =
        contract218_roles([0x11; 16], [0x22; 16], 1, [0x33; 32], [0x44; 32]).unwrap();
    let declaration = SensitiveParamDeclaration::component(vec!["token".into()]).unwrap();
    let claims = ObservationIdentityClaims {
        exact_id: "component-cleanup".into(),
        expected_class: ObservationIdentityClass::Component,
        incarnation: 5,
        declaration_digest: declaration
            .digest_for("component-cleanup", ObservationIdentityClass::Component, 5)
            .unwrap(),
    };
    let committed = verifier
        .issue_committed_component_receipt(claims.clone(), "activate-a".into(), 7)
        .unwrap();
    let activation_a = verifier.begin_component_activation(&committed).unwrap();
    let ready_for_a = previsible_ready_receipts(&proof_issuer, &activation_a).unwrap();
    let activation_b = verifier.begin_component_activation(&committed).unwrap();
    assert!(proof_issuer
        .issue_ready_proof(&activation_b, ready_for_a)
        .is_err());

    let record_a = TerminationOperationRecord {
        operation_id: "terminate-a".into(),
        member_set_digest:
            advance_shared_types::contract218_previsible::termination_member_set_digest(&[
                claims.clone()
            ])
            .unwrap(),
        registry_sequence: 11,
    };
    let record_b = TerminationOperationRecord {
        operation_id: "terminate-b".into(),
        member_set_digest: record_a.member_set_digest,
        registry_sequence: 12,
    };
    let prepared_a = termination.prepare_committed(record_a.clone()).unwrap();
    let prepared_b = termination.prepare_committed(record_b.clone()).unwrap();
    let receipts_a =
        termination_cleanup_receipts(&cleanup_issuer, &record_a, &[claims.clone()], 19).unwrap();
    assert!(cleanup_issuer
        .issue_cleanup_complete(&prepared_b, receipts_a)
        .is_err());

    let receipts_a =
        termination_cleanup_receipts(&cleanup_issuer, &record_a, &[claims.clone()], 19).unwrap();
    let cleanup = cleanup_issuer
        .issue_cleanup_complete(&prepared_a, receipts_a)
        .unwrap();
    cleanup_verifier
        .verify_cleanup_complete(&cleanup, &record_a)
        .unwrap();
    assert!(cleanup_verifier
        .verify_cleanup_complete(&cleanup, &record_b)
        .is_err());

    let source_issuer = proof_issuer.take_source_emission_receipt_issuer().unwrap();
    assert!(proof_issuer.take_source_emission_receipt_issuer().is_err());
    let quiesced = source_issuer
        .issue_quiesce_receipt(record_a.clone(), claims.clone(), 2, 23, 23)
        .unwrap();
    termination
        .verify_source_emission_quiesce_receipt(&quiesced, &record_a, &claims)
        .unwrap();
    assert!(termination
        .verify_source_emission_quiesce_receipt(&quiesced, &record_b, &claims)
        .is_err());
}

#[test]
fn termination_prepare_exact_two_family_receipt_sets_verify_to_metadata() {
    let (mut proof_issuer, _, termination, cleanup_issuer, _) =
        contract218_roles([0x11; 16], [0x22; 16], 1, [0x33; 32], [0x44; 32]).unwrap();
    let source_issuer = proof_issuer.take_source_emission_receipt_issuer().unwrap();
    let members = vec![
        termination_member("component:a", 1),
        termination_member("component:b", 2),
    ];
    let record = termination_record("terminate-exact", 41, &members);
    let (grants, emissions) =
        termination_prepare_receipts(&source_issuer, &cleanup_issuer, &record, &members, 7, 43)
            .unwrap();
    let verified = termination
        .verify_termination_prepare_receipt_sets(&record, &members, grants, emissions)
        .unwrap();
    let metadata = verified.metadata();
    assert_eq!(metadata.operation_id, "terminate-exact");
    assert_eq!(metadata.member_count, 2);
    assert_ne!(metadata.grant_subject_drain_receipt_set_digest, [0; 32]);
    assert_ne!(metadata.source_emission_quiesce_receipt_set_digest, [0; 32]);
    assert_ne!(metadata.aggregate_receipt_set_digest, [0; 32]);
}

#[test]
fn termination_prepare_missing_grant_member_rejects_before_metadata() {
    let (mut proof_issuer, _, termination, cleanup_issuer, _) =
        contract218_roles([0x11; 16], [0x22; 16], 1, [0x33; 32], [0x44; 32]).unwrap();
    let source_issuer = proof_issuer.take_source_emission_receipt_issuer().unwrap();
    let members = vec![
        termination_member("component:a", 1),
        termination_member("component:b", 2),
    ];
    let record = termination_record("terminate-missing", 42, &members);
    let (_, emissions) =
        termination_prepare_receipts(&source_issuer, &cleanup_issuer, &record, &members, 8, 44)
            .unwrap();
    let (missing_grants, _) = termination_prepare_receipts(
        &source_issuer,
        &cleanup_issuer,
        &record,
        &members[..1],
        8,
        44,
    )
    .unwrap();
    assert!(termination
        .verify_termination_prepare_receipt_sets(&record, &members, missing_grants, emissions,)
        .is_err());
}

#[test]
fn termination_prepare_duplicate_grant_member_rejects_before_metadata() {
    let (mut proof_issuer, _, termination, cleanup_issuer, _) =
        contract218_roles([0x11; 16], [0x22; 16], 1, [0x33; 32], [0x44; 32]).unwrap();
    let source_issuer = proof_issuer.take_source_emission_receipt_issuer().unwrap();
    let members = vec![
        termination_member("component:a", 1),
        termination_member("component:b", 2),
    ];
    let record = termination_record("terminate-duplicate", 43, &members);
    let (_, emissions) =
        termination_prepare_receipts(&source_issuer, &cleanup_issuer, &record, &members, 9, 45)
            .unwrap();
    let duplicate_members = vec![members[0].clone(), members[0].clone()];
    let (duplicate_grants, _) = termination_prepare_receipts(
        &source_issuer,
        &cleanup_issuer,
        &record,
        &duplicate_members,
        9,
        45,
    )
    .unwrap();
    assert!(termination
        .verify_termination_prepare_receipt_sets(&record, &members, duplicate_grants, emissions,)
        .is_err());
}

#[test]
fn termination_prepare_cross_operation_emission_set_rejects() {
    let (mut proof_issuer, _, termination, cleanup_issuer, _) =
        contract218_roles([0x11; 16], [0x22; 16], 1, [0x33; 32], [0x44; 32]).unwrap();
    let source_issuer = proof_issuer.take_source_emission_receipt_issuer().unwrap();
    let members = vec![termination_member("component:a", 1)];
    let record_a = termination_record("terminate-a", 44, &members);
    let record_b = termination_record("terminate-b", 45, &members);
    let (grants_a, _) =
        termination_prepare_receipts(&source_issuer, &cleanup_issuer, &record_a, &members, 10, 46)
            .unwrap();
    let (_, emissions_b) =
        termination_prepare_receipts(&source_issuer, &cleanup_issuer, &record_b, &members, 10, 46)
            .unwrap();
    assert!(termination
        .verify_termination_prepare_receipt_sets(&record_a, &members, grants_a, emissions_b,)
        .is_err());
}

#[test]
fn prepared_recovery_rehydrates_exact_activation_nonce_and_role() {
    let (_, verifier, _, _, _) =
        contract218_roles([0x11; 16], [0x22; 16], 1, [0x33; 32], [0x44; 32]).unwrap();
    let claims = termination_member("component:recover", 1);
    let committed = verifier
        .issue_committed_component_receipt(claims, "activate-recover".into(), 31)
        .unwrap();
    let activation = verifier.begin_component_activation(&committed).unwrap();
    let record = verifier.inspect_component_activation(&activation).unwrap();
    let recovered = verifier.rehydrate_component_activation(&record).unwrap();
    assert_eq!(
        verifier.inspect_component_activation(&recovered).unwrap(),
        record
    );
    assert!(verifier.rehydrate_agent_activation(&record).is_err());
}

#[test]
fn verified_ready_and_abort_metadata_supply_provider_authenticated_nonces() {
    let (proof_issuer, verifier, _, _, _) =
        contract218_roles([0x11; 16], [0x22; 16], 1, [0x33; 32], [0x44; 32]).unwrap();
    let claims = termination_member("component:nonce", 1);
    let committed = verifier
        .issue_committed_component_receipt(claims, "activate-nonce".into(), 32)
        .unwrap();

    let ready_activation = verifier.begin_component_activation(&committed).unwrap();
    let ready_receipts = previsible_ready_receipts(&proof_issuer, &ready_activation).unwrap();
    let ready_proof = proof_issuer
        .issue_ready_proof(&ready_activation, ready_receipts)
        .unwrap();
    let ready_metadata = match verifier.verify_component_ready(ready_activation, ready_proof) {
        advance_shared_types::contract218_previsible::ComponentReadyVerification::Verified(
            verified,
        ) => verified.proof_metadata().clone(),
        advance_shared_types::contract218_previsible::ComponentReadyVerification::Rejected(_) => {
            panic!("authenticated ready proof rejected")
        }
    };
    let rejection_nonce = ready_metadata.rejection_nonce.unwrap();
    assert_ne!(ready_metadata.recovery_nonce, [0; 32]);
    assert_ne!(rejection_nonce, [0; 32]);
    assert_ne!(ready_metadata.recovery_nonce, rejection_nonce);

    let abort_activation = verifier.begin_component_activation(&committed).unwrap();
    let abort_receipts = previsible_abort_receipts(&proof_issuer, &abort_activation).unwrap();
    let abort_proof = proof_issuer
        .issue_abort_proof(&abort_activation, abort_receipts)
        .unwrap();
    let abort_bundle = verifier
        .verify_abort_proof(abort_activation, abort_proof)
        .unwrap();
    let PrevisibleAbortBundle::Component(abort_bundle) = abort_bundle else {
        panic!("component abort changed role")
    };
    let (_, abort_metadata) = verifier.inspect_component_abort(&abort_bundle).unwrap();
    assert_eq!(abort_metadata.rejection_nonce, None);
    assert_ne!(abort_metadata.recovery_nonce, [0; 32]);
    assert_ne!(abort_metadata.recovery_nonce, ready_metadata.recovery_nonce);
}

#[test]
fn retained_tombstone_gc_exact_generation_and_six_owner_proofs_verify() {
    let (_, verifier, _, _, _) =
        contract218_roles([0x11; 16], [0x22; 16], 1, [0x33; 32], [0x44; 32]).unwrap();
    let members = vec![termination_member("component:gc", 1)];
    let record = termination_record("retained-gc", 51, &members);
    let challenge = verifier
        .issue_retained_tombstone_gc_challenge(record, [0x71; 32], 9)
        .unwrap();
    let challenge_metadata = verifier
        .inspect_retained_tombstone_gc_challenge(&challenge)
        .unwrap();
    assert_eq!(challenge_metadata.gc_generation, 9);
    assert_eq!(challenge_metadata.gc_registry_sequence, 51);
    let owners = [
        ([1; 16], 11, [0x81; 32]),
        ([2; 16], 12, [0x82; 32]),
        ([3; 16], 13, [0x83; 32]),
        ([4; 16], 14, [0x84; 32]),
        ([5; 16], 15, [0x85; 32]),
    ];
    let (purpose2, receipts) = retained_tombstone_gc_inputs(&verifier, &challenge, owners).unwrap();
    let verified = verifier
        .verify_retained_tombstone_gc_set(challenge, purpose2, receipts)
        .unwrap();
    assert_eq!(verified.metadata().gc_generation, 9);
    assert_eq!(verified.metadata().purpose2, verified.metadata().c123);
    assert_ne!(verified.metadata().aggregate_digest, [0; 32]);
}

#[test]
fn retained_tombstone_gc_cross_generation_receipts_reject() {
    let (_, verifier, _, _, _) =
        contract218_roles([0x11; 16], [0x22; 16], 1, [0x33; 32], [0x44; 32]).unwrap();
    let members = vec![termination_member("component:gc", 1)];
    let record = termination_record("retained-gc", 52, &members);
    let challenge_a = verifier
        .issue_retained_tombstone_gc_challenge(record.clone(), [0x72; 32], 9)
        .unwrap();
    let challenge_b = verifier
        .issue_retained_tombstone_gc_challenge(record, [0x72; 32], 10)
        .unwrap();
    let owners = [
        ([1; 16], 11, [0x81; 32]),
        ([2; 16], 12, [0x82; 32]),
        ([3; 16], 13, [0x83; 32]),
        ([4; 16], 14, [0x84; 32]),
        ([5; 16], 15, [0x85; 32]),
    ];
    let (purpose2_a, receipts_a) =
        retained_tombstone_gc_inputs(&verifier, &challenge_a, owners).unwrap();
    assert!(verifier
        .verify_retained_tombstone_gc_set(challenge_b, purpose2_a, receipts_a)
        .is_err());
}

#[test]
fn persisted_key_retirement_requires_verify_only_candidate_and_three_scans() {
    let (_, mut verifier, _, _, _) =
        contract218_roles([0x11; 16], [0x22; 16], 2, [0x33; 32], [0x44; 32]).unwrap();
    let keyring =
        persisted_identity_keyring_role(&mut verifier, [0x11; 16], 2, [0x44; 32], [1; 32]).unwrap();
    assert!(keyring.persisted_key_retirement_candidate(2).is_err());
    let candidate = keyring.persisted_key_retirement_candidate(1).unwrap();
    let challenge = verifier
        .issue_persisted_key_retirement_challenge("retire-key-1".into(), &candidate, 3)
        .unwrap();
    let challenge_metadata = verifier
        .inspect_persisted_key_retirement_challenge(&challenge)
        .unwrap();
    assert_eq!(challenge_metadata.key_id, 1);
    assert_eq!(challenge_metadata.migration_generation, 3);
    let scans = persisted_key_retirement_scans(
        &verifier,
        &challenge,
        ([1; 16], 21, [0x91; 32]),
        ([2; 16], [0x92; 32], 2, 128, 22),
        ([3; 16], 23, [0x93; 32]),
    )
    .unwrap();
    let verified = verifier
        .verify_persisted_key_retirement_scan_set(challenge, scans)
        .unwrap();
    assert_eq!(verified.metadata().key_id, 1);
    assert_eq!(
        verified.metadata().keyring_root,
        challenge_metadata.keyring_root
    );
    assert_ne!(verified.metadata().aggregate_digest, [0; 32]);
}

#[test]
fn persisted_key_retirement_cross_challenge_scans_reject() {
    let (_, mut verifier, _, _, _) =
        contract218_roles([0x11; 16], [0x22; 16], 2, [0x33; 32], [0x44; 32]).unwrap();
    let keyring =
        persisted_identity_keyring_role(&mut verifier, [0x11; 16], 2, [0x44; 32], [1; 32]).unwrap();
    let candidate = keyring.persisted_key_retirement_candidate(1).unwrap();
    let challenge_a = verifier
        .issue_persisted_key_retirement_challenge("retire-key-1-a".into(), &candidate, 3)
        .unwrap();
    let challenge_b = verifier
        .issue_persisted_key_retirement_challenge("retire-key-1-b".into(), &candidate, 4)
        .unwrap();
    let scans_a = persisted_key_retirement_scans(
        &verifier,
        &challenge_a,
        ([1; 16], 21, [0x91; 32]),
        ([2; 16], [0x92; 32], 2, 128, 22),
        ([3; 16], 23, [0x93; 32]),
    )
    .unwrap();
    assert!(verifier
        .verify_persisted_key_retirement_scan_set(challenge_b, scans_a)
        .is_err());
}

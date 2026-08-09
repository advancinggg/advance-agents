use advance_shared_types::contract218_previsible::{
    PersistedIdentityKeyringRole, PrevisibleProofVerifierRole, SigningKeyCapability,
    VerificationKeyCapability,
};
use advance_shared_types::observation_identity::{
    ObservationIdentityClaims, ObservationIdentityClass, PersistedObservationBinding,
    SensitiveParamDeclaration, TrustedObservationIdentity,
};
use advance_shared_types::sensitive_observation::{
    decode_canonical_node, decode_persisted_observation_binding, encode_canonical_document,
    encode_canonical_node, CanonicalContainerDeclaration, CanonicalContainerKind,
    ObservationAssociationError, ObservationAssociationProof, ObservationDocument, ObservationNode,
    ObservationSchemaDocumentKind, ObservationSchemaManifest, ObservationSchemaRoot,
    ObservationScope, RedactionBlockReason, RedactionDisposition,
};
use advance_shared_types::test_support::{
    association_proof_bytes, contract218_roles, live_final_observation_fixture,
    live_ingress_observation_fixture, observation_association_roles,
    persisted_identity_keyring_role, provider_dto_observation_fixture, set_bound_proof_byte,
    swap_bound_authorities, swap_bound_documents, swap_bound_proofs, swap_bound_safe_digests,
};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

const EVENT_PARAMS_SCHEMA: &str = "test.event.params.v1";

fn decode_hex(literal: &str) -> Vec<u8> {
    assert_eq!(literal.len() % 2, 0);
    literal
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |byte: u8| match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                b'A'..=b'F' => byte - b'A' + 10,
                _ => panic!("non-hex fixture byte"),
            };
            (digit(pair[0]) << 4) | digit(pair[1])
        })
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

fn c218_fixture() -> (PrevisibleProofVerifierRole, TrustedObservationIdentity) {
    let (_, verifier, _, _, _) =
        contract218_roles([0x11; 16], [0x22; 16], 1, [0x33; 32], [0x44; 32]).unwrap();
    let identity = mint_identity(&verifier, "component-a", 1);
    (verifier, identity)
}

fn c218_persisted_fixture() -> (
    PrevisibleProofVerifierRole,
    PersistedIdentityKeyringRole,
    SigningKeyCapability,
    VerificationKeyCapability,
    TrustedObservationIdentity,
) {
    let (_, mut verifier, _, _, _) =
        contract218_roles([0x11; 16], [0x22; 16], 1, [0x33; 32], [0x44; 32]).unwrap();
    let identity = mint_identity(&verifier, "component-a", 1);
    let keyring =
        persisted_identity_keyring_role(&mut verifier, [0x11; 16], 1, [0x44; 32], [1; 32]).unwrap();
    let signing = keyring.signing_key_capability().unwrap();
    let verification = keyring.verification_key_capability(1).unwrap();
    (verifier, keyring, signing, verification, identity)
}

fn mint_identity(
    verifier: &PrevisibleProofVerifierRole,
    exact_id: &str,
    incarnation: u64,
) -> TrustedObservationIdentity {
    let declaration = SensitiveParamDeclaration::component(vec!["api_key".into()]).unwrap();
    let claims = ObservationIdentityClaims {
        exact_id: exact_id.into(),
        expected_class: ObservationIdentityClass::Component,
        incarnation,
        declaration_digest: declaration
            .digest_for(exact_id, ObservationIdentityClass::Component, incarnation)
            .unwrap(),
    };
    let handle = verifier.issue_live_source(claims).unwrap();
    verifier.mint_live_identity(&handle).unwrap()
}

fn event_nodes(value: &str) -> (ObservationNode, ObservationNode) {
    (
        ObservationNode::Object(vec![
            ("id".into(), ObservationNode::String("evt-1".into())),
            (
                "event_type".into(),
                ObservationNode::String("test.event".into()),
            ),
        ]),
        ObservationNode::CanonicalNamedParams(vec![(
            "api_key".into(),
            ObservationNode::String(value.into()),
        )]),
    )
}

fn ingress_fixture(
    issuer: &advance_shared_types::sensitive_observation::ObservationEventAssociationIssuer,
    identity: &TrustedObservationIdentity,
    value: &str,
) -> (
    advance_shared_types::sensitive_observation::ObservationEmissionLease,
    ObservationDocument,
) {
    let (envelope, payload) = event_nodes(value);
    live_ingress_observation_fixture(issuer, identity, Some(&event_schema()), envelope, payload)
        .unwrap()
}

fn final_fixture(
    issuer: &advance_shared_types::sensitive_observation::ObservationEventAssociationIssuer,
    identity: &TrustedObservationIdentity,
    value: &str,
) -> (
    advance_shared_types::sensitive_observation::ObservationEmissionLease,
    ObservationDocument,
) {
    let (envelope, payload) = event_nodes(value);
    live_final_observation_fixture(issuer, identity, Some(&event_schema()), envelope, payload)
        .unwrap()
}

fn event_schema() -> ObservationSchemaManifest {
    ObservationSchemaManifest::new(
        EVENT_PARAMS_SCHEMA.into(),
        ObservationSchemaDocumentKind::Event,
        vec![CanonicalContainerDeclaration::new(
            ObservationSchemaRoot::EventPayload,
            vec![],
            CanonicalContainerKind::NamedParams,
            vec!["api_key".into()],
        )
        .unwrap()],
    )
    .unwrap()
}

fn association_parts(
    key: u8,
    boot: u8,
) -> advance_shared_types::sensitive_observation::ObservationAssociationRoleParts {
    observation_association_roles([key; 32], [boot; 16], vec![event_schema()]).unwrap()
}

#[test]
fn proof_is_exactly_146_bytes() {
    let (_, identity) = c218_fixture();
    let roles = association_parts(0x55, 0x66);
    let (lease, document) = ingress_fixture(&roles.event_issuer, &identity, "secret");
    let bound = roles
        .event_issuer
        .bind_live_ingress(&lease, document)
        .unwrap();
    assert_eq!(ObservationAssociationProof::ENCODED_LEN, 146);
    assert_eq!(bound.association_proof_len(), 146);
    let bytes = association_proof_bytes(&bound);
    assert_eq!(bytes.len(), 146);
    assert_eq!(bytes[0], 1);
    assert_eq!(&bytes[1..17], &[0x66; 16]);
    assert_eq!(bytes[17], ObservationScope::LiveIngress.tag());
    assert_ne!(&bytes[18..], &[0; 128]);
}

#[test]
fn proof_v1_digest_segments_match_normative_literals() {
    const FIXTURE_ASSOCIATION_KEY: [u8; 32] = [0x55; 32];
    const FIXTURE_BOOT_INSTANCE: [u8; 16] = [0x66; 16];
    const NORMATIVE_ASSOCIATION_DOMAIN: &[u8] = b"advance.contract219.association.v1\0";

    // This is a test-owned canonical LiveIngress document literal.  The expected proof digests
    // below never call the private association encoder or live-authority digest helper.
    let canonical_document = decode_hex(
        "010100000032050000000200000002696403000000056576742d310000000a6576656e745f74797065030000000a746573742e6576656e740000001b0600000001000000076170695f6b65790300000006736563726574",
    );
    assert_eq!(canonical_document.len(), 87);

    let expected_safe: [u8; 32] =
        decode_hex("bda9e28f293bad14b2682b46f07c328e6bde73125bd0b316cc56a9a12bad7ec3")
            .try_into()
            .unwrap();
    let expected_document: [u8; 32] =
        decode_hex("d75bea66ae6a7f6a7b6ca3a841c9a447942f4fed1f49feafa399f65e7219df12")
            .try_into()
            .unwrap();
    let expected_authority: [u8; 32] =
        decode_hex("4fd237806d73e546e66685463e9700fb1dc6d0c8dbb0fb5d89dba7fed4a0276c")
            .try_into()
            .unwrap();
    let expected_mac: [u8; 32] =
        decode_hex("da23693ae4eb88f71f788ae88e70ac8bb1649af8c9f062f2b65f0ada9ab8e115")
            .try_into()
            .unwrap();

    // Independently prove the fixed document KATs from the literal bytes.
    let mut safe_preimage = b"advance.contract219.ingress-document.v1\0".to_vec();
    safe_preimage.extend_from_slice(&canonical_document);
    assert_eq!(
        <[u8; 32]>::from(Sha256::digest(safe_preimage)),
        expected_safe
    );
    let mut document_preimage = b"advance.contract219.document.v1\0".to_vec();
    document_preimage.extend_from_slice(&canonical_document);
    assert_eq!(
        <[u8; 32]>::from(Sha256::digest(document_preimage)),
        expected_document
    );

    // Independent C218 exact source-binding KAT for
    // (component-a, Component, incarnation 1, declaration digest below).
    let declaration_digest =
        decode_hex("5b12d8b137e3a4210e930bc3f6b16406b5d6700d8173796c0d317b68697b65be");
    let mut source_binding = b"advance.contract218.source-binding.v1\0".to_vec();
    source_binding.extend_from_slice(&11u32.to_be_bytes());
    source_binding.extend_from_slice(b"component-a");
    source_binding.push(1);
    source_binding.extend_from_slice(&1u64.to_be_bytes());
    source_binding.extend_from_slice(&declaration_digest);
    assert_eq!(
        <[u8; 32]>::from(Sha256::digest(source_binding)),
        expected_authority
    );

    let (_, identity) = c218_fixture();
    let roles = observation_association_roles(
        FIXTURE_ASSOCIATION_KEY,
        FIXTURE_BOOT_INSTANCE,
        vec![event_schema()],
    )
    .unwrap();
    let (lease, document) = ingress_fixture(&roles.event_issuer, &identity, "secret");
    assert_eq!(
        encode_canonical_document(&document).unwrap(),
        canonical_document
    );
    let bound = roles
        .event_issuer
        .bind_live_ingress(&lease, document)
        .unwrap();
    let proof = association_proof_bytes(&bound);
    assert_eq!(proof.len(), 146);
    assert_eq!(proof[0], 1);
    assert_eq!(&proof[1..17], &FIXTURE_BOOT_INSTANCE);
    assert_eq!(proof[17], 1);
    assert_eq!(&proof[18..50], &expected_safe);
    assert_eq!(&proof[50..82], &expected_document);
    assert_eq!(&proof[82..114], &expected_authority);

    // Independent test-owned RFC 2104 oracle.  This does not call the production association
    // MAC helper or import its private domain constant: the normative preimage is exactly the
    // literal domain followed by proof-v1's fixed 114-byte prefix.
    let mut independent_hmac = Hmac::<Sha256>::new_from_slice(&FIXTURE_ASSOCIATION_KEY).unwrap();
    independent_hmac.update(NORMATIVE_ASSOCIATION_DOMAIN);
    independent_hmac.update(&proof[..114]);
    let independently_computed_mac: [u8; 32] = independent_hmac.finalize().into_bytes().into();
    assert_eq!(independently_computed_mac, expected_mac);
    assert_eq!(&proof[114..146], &expected_mac);

    // Keep the production verifier as a second, non-oracle compatibility check.
    let redactor = roles
        .provider
        .bind_once(roles.verifier, |_| RedactionDisposition::Blocked {
            reason: RedactionBlockReason::UnknownIdentity,
        })
        .unwrap();
    assert_eq!(
        redactor.redact_bound_observation(bound),
        RedactionDisposition::Blocked {
            reason: RedactionBlockReason::UnknownIdentity,
        }
    );
}

#[test]
fn cross_authority_document_permits_reject_before_catalog() {
    let (provider, identity_a) = c218_fixture();
    let identity_b = mint_identity(&provider, "component-b", 2);
    let roles = association_parts(0x57, 0x68);
    let (lease_a, document_a) = ingress_fixture(&roles.event_issuer, &identity_a, "secret-a");
    let (lease_b, document_b) = ingress_fixture(&roles.event_issuer, &identity_b, "secret-b");

    assert!(matches!(
        roles.event_issuer.bind_live_ingress(&lease_a, document_b),
        Err(ObservationAssociationError::InvalidProof)
    ));
    assert!(matches!(
        roles.event_issuer.bind_live_ingress(&lease_b, document_a),
        Err(ObservationAssociationError::InvalidProof)
    ));
}

#[test]
fn scope_tags_one_through_four_only() {
    assert_eq!(ObservationScope::LiveIngress.tag(), 1);
    assert_eq!(ObservationScope::LiveFinalEvent.tag(), 2);
    assert_eq!(ObservationScope::PersistedEvent.tag(), 3);
    assert_eq!(ObservationScope::LiveProviderDto.tag(), 4);
    for tag in [0u8, 5, 0xff] {
        assert!(![1, 2, 3, 4].contains(&tag));
        let (_, identity) = c218_fixture();
        let roles = association_parts(0x55, 0x66);
        let (lease, document) = ingress_fixture(&roles.event_issuer, &identity, "secret");
        let mut bound = roles
            .event_issuer
            .bind_live_ingress(&lease, document)
            .unwrap();
        set_bound_proof_byte(&mut bound, 17, tag);
        let redactor = roles
            .provider
            .bind_once(roles.verifier, |_| RedactionDisposition::Blocked {
                reason: RedactionBlockReason::UnknownIdentity,
            })
            .unwrap();
        assert_eq!(
            redactor.redact_bound_observation(bound),
            RedactionDisposition::Blocked {
                reason: RedactionBlockReason::AssociationMismatch
            }
        );
    }
}

#[test]
fn boot_document_safe_authority_cross_swaps_reject() {
    let (provider, identity) = c218_fixture();
    let other_identity = mint_identity(&provider, "component-b", 2);
    let issuer_roles = association_parts(0x55, 0x66);
    let (lease, document) = final_fixture(&issuer_roles.event_issuer, &identity, "secret-a");
    let bound = issuer_roles
        .event_issuer
        .bind_live_final_event(&lease, [0x77; 32], document)
        .unwrap();

    // A different boot/key cannot open even a structurally valid bound document.
    let verifier_roles = association_parts(0x56, 0x67);
    let redactor = verifier_roles
        .provider
        .bind_once(verifier_roles.verifier, |_| RedactionDisposition::Blocked {
            reason: RedactionBlockReason::UnknownIdentity,
        })
        .unwrap();
    assert_eq!(
        redactor.redact_bound_observation(bound),
        RedactionDisposition::Blocked {
            reason: RedactionBlockReason::AssociationMismatch
        }
    );

    // Provider/verifier halves from different factories cannot be crossed either.
    let left = association_parts(0x61, 0x71);
    let right = association_parts(0x62, 0x72);
    assert!(matches!(
        left.provider.bind_once(right.verifier, |_| {
            RedactionDisposition::Blocked {
                reason: RedactionBlockReason::UnknownIdentity,
            }
        }),
        Err(ObservationAssociationError::InvalidProof)
    ));

    let assert_mismatch = |disposition| {
        assert_eq!(
            disposition,
            RedactionDisposition::Blocked {
                reason: RedactionBlockReason::AssociationMismatch,
            }
        );
    };

    // Cross only the document while retaining each proof/safe digest/authority.
    let roles = association_parts(0x63, 0x73);
    let (first_lease, first_document) = final_fixture(&roles.event_issuer, &identity, "document-a");
    let mut first = roles
        .event_issuer
        .bind_live_final_event(&first_lease, [0x11; 32], first_document)
        .unwrap();
    let (second_lease, second_document) =
        final_fixture(&roles.event_issuer, &identity, "document-b");
    let mut second = roles
        .event_issuer
        .bind_live_final_event(&second_lease, [0x22; 32], second_document)
        .unwrap();
    swap_bound_documents(&mut first, &mut second);
    let redactor = roles
        .provider
        .bind_once(roles.verifier, |_| RedactionDisposition::Blocked {
            reason: RedactionBlockReason::UnknownIdentity,
        })
        .unwrap();
    assert_mismatch(redactor.redact_bound_observation(first));
    assert_mismatch(redactor.redact_bound_observation(second));

    // Cross only the supplied safe-event digest.
    let roles = association_parts(0x64, 0x74);
    let (first_lease, first_document) = final_fixture(&roles.event_issuer, &identity, "safe-a");
    let mut first = roles
        .event_issuer
        .bind_live_final_event(&first_lease, [0x31; 32], first_document)
        .unwrap();
    let (second_lease, second_document) = final_fixture(&roles.event_issuer, &identity, "safe-b");
    let mut second = roles
        .event_issuer
        .bind_live_final_event(&second_lease, [0x32; 32], second_document)
        .unwrap();
    swap_bound_safe_digests(&mut first, &mut second);
    let redactor = roles
        .provider
        .bind_once(roles.verifier, |_| RedactionDisposition::Blocked {
            reason: RedactionBlockReason::UnknownIdentity,
        })
        .unwrap();
    assert_mismatch(redactor.redact_bound_observation(first));
    assert_mismatch(redactor.redact_bound_observation(second));

    // Cross only the exact C218 authority.
    let roles = association_parts(0x65, 0x75);
    let (first_lease, first_document) =
        final_fixture(&roles.event_issuer, &identity, "authority-a");
    let mut first = roles
        .event_issuer
        .bind_live_final_event(&first_lease, [0x41; 32], first_document)
        .unwrap();
    let (second_lease, second_document) =
        final_fixture(&roles.event_issuer, &other_identity, "authority-b");
    let mut second = roles
        .event_issuer
        .bind_live_final_event(&second_lease, [0x42; 32], second_document)
        .unwrap();
    swap_bound_authorities(&mut first, &mut second);
    let redactor = roles
        .provider
        .bind_once(roles.verifier, |_| RedactionDisposition::Blocked {
            reason: RedactionBlockReason::UnknownIdentity,
        })
        .unwrap();
    assert_mismatch(redactor.redact_bound_observation(first));
    assert_mismatch(redactor.redact_bound_observation(second));

    // Cross only the fixed proof carrier.
    let roles = association_parts(0x66, 0x76);
    let (first_lease, first_document) = final_fixture(&roles.event_issuer, &identity, "proof-a");
    let mut first = roles
        .event_issuer
        .bind_live_final_event(&first_lease, [0x51; 32], first_document)
        .unwrap();
    let (second_lease, second_document) = final_fixture(&roles.event_issuer, &identity, "proof-b");
    let mut second = roles
        .event_issuer
        .bind_live_final_event(&second_lease, [0x52; 32], second_document)
        .unwrap();
    swap_bound_proofs(&mut first, &mut second);
    let redactor = roles
        .provider
        .bind_once(roles.verifier, |_| RedactionDisposition::Blocked {
            reason: RedactionBlockReason::UnknownIdentity,
        })
        .unwrap();
    assert_mismatch(redactor.redact_bound_observation(first));
    assert_mismatch(redactor.redact_bound_observation(second));
}

#[test]
fn literal_51_byte_binding_hashes_to_270471102e256c60578c325a1dc378d81f77e90111fd676a46acd076b16b0ffa_without_encoder(
) {
    // Independent literal: this test intentionally never calls the production encoder.
    let literal = decode_hex(
        "01000000056576742d31000000056576742d312222222222222222222222222222222222222222222222222222222222222222",
    );
    assert_eq!(literal.len(), 51);
    let decoded = decode_persisted_observation_binding(&literal).unwrap();
    assert_eq!(decoded.event_id, "evt-1");
    assert_eq!(decoded.cursor, "evt-1");
    assert_eq!(decoded.safe_event_digest, [0x22; 32]);
    assert_eq!(
        hex(&Sha256::digest(&literal)),
        "270471102e256c60578c325a1dc378d81f77e90111fd676a46acd076b16b0ffa"
    );
}

#[test]
fn binding_version_lengths_utf8_cursor_and_trailing_bytes_reject() {
    let literal = decode_hex(
        "01000000056576742d31000000056576742d312222222222222222222222222222222222222222222222222222222222222222",
    );
    let mut bad_version = literal.clone();
    bad_version[0] = 2;
    assert!(decode_persisted_observation_binding(&bad_version).is_err());

    let mut bad_length = literal.clone();
    bad_length[4] = 6;
    assert!(decode_persisted_observation_binding(&bad_length).is_err());

    let mut bad_utf8 = literal.clone();
    bad_utf8[5] = 0xff;
    assert!(decode_persisted_observation_binding(&bad_utf8).is_err());

    let mut crossed_cursor = literal.clone();
    crossed_cursor[18] = b'2';
    assert!(decode_persisted_observation_binding(&crossed_cursor).is_err());

    let mut trailing = literal;
    trailing.push(0);
    assert!(decode_persisted_observation_binding(&trailing).is_err());
}

#[test]
fn binding_each_byte_mutation_truncation_and_extension_reject() {
    let literal = decode_hex(
        "01000000056576742d31000000056576742d312222222222222222222222222222222222222222222222222222222222222222",
    );
    let original_binding = decode_persisted_observation_binding(&literal).unwrap();
    let (_provider, keyring, signing, verification, live_identity) = c218_persisted_fixture();
    let carrier = keyring
        .seal_persisted_identity(&signing, &live_identity, &original_binding)
        .unwrap();
    let expected_claims = live_identity.claims_for_persistence();
    let original_hash = Sha256::digest(&literal);
    for index in 0..literal.len() {
        let mut mutated = literal.clone();
        mutated[index] ^= 1;
        match decode_persisted_observation_binding(&mutated) {
            Err(_) => {}
            Ok(decoded) => {
                // Safe-digest bytes remain structurally legal data, but the original opaque
                // carrier cannot be rebound to them.  This is the persisted authority check that
                // CONTRACT-219 invokes after Pass A.
                assert_ne!(decoded.safe_event_digest, [0x22; 32]);
                assert_ne!(Sha256::digest(&mutated), original_hash);
                let rehydrated = keyring
                    .rehydrate_persisted_identity(&verification, &carrier)
                    .unwrap();
                assert!(keyring
                    .verify_persisted_identity(
                        &verification,
                        &rehydrated,
                        &carrier,
                        &decoded,
                        &expected_claims,
                    )
                    .is_err());
            }
        }
    }
    for length in 0..literal.len() {
        assert!(decode_persisted_observation_binding(&literal[..length]).is_err());
    }
    let mut extension = literal;
    extension.push(0);
    assert!(decode_persisted_observation_binding(&extension).is_err());
}

#[test]
fn node_tags_zero_through_seven_round_trip_tag_eight_rejects() {
    let nodes = [
        ObservationNode::Null,
        ObservationNode::Bool(true),
        ObservationNode::Number("1".into()),
        ObservationNode::String("s".into()),
        ObservationNode::Array(vec![]),
        ObservationNode::Object(vec![]),
        ObservationNode::CanonicalNamedParams(vec![]),
        ObservationNode::CanonicalCapParams(vec![]),
    ];
    for (tag, node) in nodes.into_iter().enumerate() {
        let bytes = encode_canonical_node(&node).unwrap();
        assert_eq!(bytes[0], tag as u8);
        assert_eq!(decode_canonical_node(&bytes).unwrap(), node);
    }
    assert!(decode_canonical_node(&[8]).is_err());
}

#[test]
fn crossed_tag_scope_role_and_trailing_bytes_reject() {
    let named = ObservationNode::CanonicalNamedParams(vec![(
        "api_key".into(),
        ObservationNode::String("secret".into()),
    )]);
    let named_bytes = encode_canonical_node(&named).unwrap();
    let mut crossed = named_bytes.clone();
    crossed[0] = 7;
    let crossed_node = decode_canonical_node(&crossed).unwrap();
    assert_ne!(crossed_node, named);
    assert_ne!(Sha256::digest(&crossed), Sha256::digest(&named_bytes));

    let mut trailing = named_bytes;
    trailing.push(0);
    assert!(decode_canonical_node(&trailing).is_err());

    let (_, identity) = c218_fixture();
    let roles = association_parts(0x55, 0x66);
    let (subject, _) = provider_dto_observation_fixture(
        &roles.provider_issuer,
        &identity,
        None,
        ObservationNode::Null,
    )
    .unwrap();
    let (_, event_document) = ingress_fixture(&roles.event_issuer, &identity, "secret");
    assert!(matches!(
        roles
            .provider_issuer
            .bind_live_provider_dto(subject, event_document),
        Err(ObservationAssociationError::Codec(_)) | Err(ObservationAssociationError::InvalidProof)
    ));
}

#[test]
fn persisted_binding_constructor_still_requires_cursor_equality() {
    assert!(PersistedObservationBinding::new("evt-a".into(), "evt-b".into(), [0; 32]).is_err());
}

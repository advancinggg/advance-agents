use advance_cli::contract218_anchor::{
    FilePlatformMonotonicAnchorStore, FileTestPlatformMonotonicRecord, HmacPlatformAnchorSeal,
    HmacRegistryManifestSeal,
};
use advance_cli::contract218_keyring::{
    test_only_keyring_file_exists, FilePersistedIdentityKeyringCustody, KeyringFailpoint,
    PersistedKeyStatus, PersistedKeyringCustodyError, PersistedKeyringRecovery,
};
use advance_scheduler::observation_anchor::{
    RegistryAnchorError, RegistryAnchorTransaction, RegistryAnchorTuple, RegistryHeadContext,
    VerifiedEmptyRegistryGenesis,
};
use advance_scheduler::sensitive_params::PersistedKeyringCustody;
use advance_shared_types::contract218_previsible::{
    PersistedIdentityKeyringInstaller, PersistedIdentityKeyringProvider,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use subtle::ConstantTimeEq;
use tempfile::TempDir;
use zeroize::{Zeroize, Zeroizing};

type HmacSha256 = Hmac<Sha256>;

#[cfg(unix)]
fn create_fifo(path: &std::path::Path) {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let path = CString::new(path.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
}

struct Fixture {
    _root: TempDir,
    workspace: PathBuf,
    platform: PathBuf,
    registry: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let workspace = root.path().join("workspace");
        let platform = root.path().join("platform");
        fs::create_dir_all(&workspace).unwrap();
        fs::create_dir_all(&platform).unwrap();
        let registry = workspace.join("component-registry.sqlite");
        fs::write(&registry, []).unwrap();
        Self {
            _root: root,
            workspace,
            platform,
            registry,
        }
    }

    fn seal(&self) -> Arc<HmacPlatformAnchorSeal> {
        Arc::new(
            HmacPlatformAnchorSeal::consume_platform_key(7, Zeroizing::new([0xA5; 32])).unwrap(),
        )
    }

    fn anchor(&self) -> FilePlatformMonotonicAnchorStore {
        let record = Arc::new(
            FileTestPlatformMonotonicRecord::open_for_test(
                self.platform.join("contract218.platform-record.test-only"),
            )
            .unwrap(),
        );
        let manifest =
            Arc::new(HmacRegistryManifestSeal::consume_host_master_keys(keys()).unwrap());
        FilePlatformMonotonicAnchorStore::acquire(
            &self.platform,
            &self.workspace,
            record,
            self.seal(),
            manifest,
        )
        .unwrap()
    }
}

fn tuple(sequence: u64, keyring_root: [u8; 32]) -> RegistryAnchorTuple {
    RegistryAnchorTuple {
        registry_instance: [0x11; 16],
        sequence,
        head: [0x21; 32],
        state_root: [0x22; 32],
        keyring_root,
        role_allocation_root: advance_scheduler::observation_anchor::role_allocation_file_root(
            &minimal_role_artifact(),
        ),
        migration_digest: greenfield_digest(),
    }
}

fn minimal_role_artifact() -> Vec<u8> {
    let mut bytes = vec![1];
    bytes.extend_from_slice(&1u32.to_be_bytes());
    bytes.extend_from_slice(&[0x11; 16]);
    bytes.push(0x52);
    bytes
}

fn greenfield_digest() -> [u8; 32] {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"advance.contract218.registry-migration-digest.v1\0");
    hasher.update([1]);
    hasher.update(0u16.to_be_bytes());
    hasher.finalize().into()
}

fn greenfield_marker_root() -> [u8; 32] {
    advance_scheduler::observation_anchor::registry_marker_root(&[]).unwrap()
}

fn keys() -> Vec<(u32, Zeroizing<[u8; 32]>)> {
    vec![
        (1, Zeroizing::new([0x71; 32])),
        (2, Zeroizing::new([0x72; 32])),
    ]
}

fn initialize(
    fixture: &Fixture,
) -> (
    FilePlatformMonotonicAnchorStore,
    FilePersistedIdentityKeyringCustody,
    RegistryAnchorTuple,
) {
    let anchor = fixture.anchor();
    let keyring = FilePersistedIdentityKeyringCustody::from_anchor_store(&anchor, keys()).unwrap();
    let root = keyring
        .initialize_genesis([0x11; 16], 1, 1)
        .unwrap()
        .into_bytes();
    let genesis = tuple(0, root);
    fs::write(
        fixture.platform.join("contract218.roles.current"),
        minimal_role_artifact(),
    )
    .unwrap();
    let witness = VerifiedEmptyRegistryGenesis::fixture_for_test(
        genesis.clone(),
        &fixture.workspace,
        &fixture.registry,
    )
    .unwrap();
    anchor.initialize_compact(witness).unwrap();
    (anchor, keyring, genesis)
}

fn unchanged_context() -> RegistryHeadContext {
    RegistryHeadContext::unchanged(greenfield_marker_root(), 1).unwrap()
}

fn rotated_manifest_context() -> RegistryHeadContext {
    RegistryHeadContext {
        previous_marker_root: greenfield_marker_root(),
        next_marker_root: greenfield_marker_root(),
        manifest_key_epoch: 1,
        next_manifest_key_epoch: 2,
    }
}

#[test]
fn generation_zero_round_trip_and_second_keyring_custody_rejects() {
    let fixture = Fixture::new();
    let (anchor, keyring, genesis) = initialize(&fixture);
    assert_eq!(
        keyring.current_root().unwrap().into_bytes(),
        genesis.keyring_root
    );
    assert_eq!(keyring.signing_key_id().unwrap(), 1);
    assert_eq!(
        keyring.entries().unwrap(),
        vec![advance_cli::contract218_keyring::PersistedKeyEntryView {
            key_id: 1,
            status: PersistedKeyStatus::Signing,
            master_key_epoch: 1,
            last_issued_at_ms: 0,
            has_complete_retirement_scan: false,
        }]
    );
    assert!(matches!(
        FilePersistedIdentityKeyringCustody::from_anchor_store(&anchor, keys()),
        Err(PersistedKeyringCustodyError::RecoveryRequired(_))
    ));
}

#[test]
fn rotation_demotes_old_and_allocates_one_new_signing_id() {
    let fixture = Fixture::new();
    let (anchor, keyring, _) = initialize(&fixture);
    let mut update = keyring.prepare_rotate(1, unchanged_context()).unwrap();
    let next = update.anchor_next().clone();
    let preparation = update.take_anchor_preparation().unwrap();
    let proof = preparation.database_commit_proof_for_test(&anchor).unwrap();
    let prepared = preparation.prepare_external_anchor(&anchor).unwrap();
    let committed = prepared.database_committed(proof).unwrap();
    let selected = committed.select_next().unwrap();
    selected.compact().unwrap();
    update.commit_anchored(&next).unwrap();
    assert_eq!(keyring.signing_key_id().unwrap(), 2);
    let entries = keyring.entries().unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].status, PersistedKeyStatus::VerifyOnly);
    assert_eq!(entries[1].status, PersistedKeyStatus::Signing);
}

#[test]
fn standalone_host_master_rotation_rejects_mixed_epoch_artifact_set() {
    let fixture = Fixture::new();
    let (anchor, keyring, genesis) = initialize(&fixture);
    let mut update = keyring
        .prepare_rotate(2, rotated_manifest_context())
        .unwrap();
    let preparation = update.take_anchor_preparation().unwrap();
    assert!(matches!(
        preparation.prepare_external_anchor(&anchor),
        Err(RegistryAnchorError::AuthenticationFailed)
    ));
    assert_eq!(keyring.retained_master_epochs_for_test(), vec![1, 2]);
    assert_eq!(
        keyring.recover_against(&genesis).unwrap(),
        PersistedKeyringRecovery::RolledBackPending
    );
    assert_eq!(keyring.signing_key_id().unwrap(), 1);
    assert_eq!(keyring.retained_master_epochs_for_test(), vec![1, 2]);
    drop(update);
    drop(keyring);
    drop(anchor);
    let anchor = fixture.anchor();
    let reopened = FilePersistedIdentityKeyringCustody::from_anchor_store(&anchor, keys()).unwrap();
    reopened
        .retire_unreferenced_master_epochs_after_restart(&genesis)
        .unwrap();
    assert_eq!(reopened.retained_master_epochs_for_test(), vec![1]);
}

#[test]
fn pending_fsync_failpoint_rolls_back_against_old_anchor() {
    let fixture = Fixture::new();
    let (_anchor, keyring, genesis) = initialize(&fixture);
    keyring.set_failpoint_for_test(KeyringFailpoint::AfterPendingFsync);
    assert!(matches!(
        keyring.prepare_rotate(1, unchanged_context()),
        Err(PersistedKeyringCustodyError::Failpoint(
            KeyringFailpoint::AfterPendingFsync
        ))
    ));
    assert_eq!(
        keyring.recover_against(&genesis).unwrap(),
        PersistedKeyringRecovery::RolledBackPending
    );
    assert_eq!(keyring.signing_key_id().unwrap(), 1);
}

#[test]
fn crash_before_file_promotion_finishes_against_new_anchor() {
    let fixture = Fixture::new();
    let (anchor, keyring, _) = initialize(&fixture);
    let mut update = keyring.prepare_rotate(1, unchanged_context()).unwrap();
    let next = update.anchor_next().clone();
    let preparation = update.take_anchor_preparation().unwrap();
    let proof = preparation.database_commit_proof_for_test(&anchor).unwrap();
    let prepared = preparation.prepare_external_anchor(&anchor).unwrap();
    let committed = prepared.database_committed(proof).unwrap();
    let selected = committed.select_next().unwrap();
    selected.compact().unwrap();
    keyring.set_failpoint_for_test(KeyringFailpoint::BeforePendingPromotion);
    assert!(matches!(
        update.commit_anchored(&next),
        Err(PersistedKeyringCustodyError::Failpoint(
            KeyringFailpoint::BeforePendingPromotion
        ))
    ));
    assert_eq!(
        keyring.recover_against(&next).unwrap(),
        PersistedKeyringRecovery::PromotedPending
    );
    assert_eq!(keyring.signing_key_id().unwrap(), 2);
}

#[test]
fn tampered_current_file_rejects_before_key_use() {
    let fixture = Fixture::new();
    let (anchor, keyring, _) = initialize(&fixture);
    drop(keyring);
    drop(anchor);
    let path = fixture.platform.join("contract218.keyring.current");
    let mut bytes = fs::read(&path).unwrap();
    bytes[100] ^= 1;
    fs::write(&path, bytes).unwrap();
    let anchor = fixture.anchor();
    assert!(matches!(
        FilePersistedIdentityKeyringCustody::from_anchor_store(&anchor, keys()),
        Err(PersistedKeyringCustodyError::AuthenticationFailed)
    ));
}

#[test]
fn initialization_rejects_current_and_pending_temp_artifacts() {
    for artifact in [
        ".contract218.keyring.current.tmp",
        ".contract218.keyring.pending.tmp",
    ] {
        let fixture = Fixture::new();
        let anchor = fixture.anchor();
        let keyring =
            FilePersistedIdentityKeyringCustody::from_anchor_store(&anchor, keys()).unwrap();
        fs::write(fixture.platform.join(artifact), b"torn keyring").unwrap();
        assert!(matches!(
            keyring.initialize_genesis([0x11; 16], 1, 1),
            Err(PersistedKeyringCustodyError::RecoveryRequired(_))
        ));
        assert!(!fixture
            .platform
            .join("contract218.keyring.current")
            .exists());
    }
}

#[cfg(unix)]
#[test]
fn keyring_custody_rejects_symlink_fifo_device_hardlink_and_temp_collisions() {
    use std::os::unix::fs::symlink;

    #[derive(Clone, Copy, Debug)]
    enum Attack {
        Symlink,
        Fifo,
        Hardlink,
        TempCollision,
    }

    let artifacts = [
        "contract218.keyring.current",
        "contract218.keyring.pending",
        ".contract218.keyring.current.tmp",
        ".contract218.keyring.pending.tmp",
    ];
    for artifact in artifacts {
        assert!(
            test_only_keyring_file_exists(std::path::Path::new("/dev/null")).is_err(),
            "accepted keyring character device at {artifact}"
        );
        for attack in [
            Attack::Symlink,
            Attack::Fifo,
            Attack::Hardlink,
            Attack::TempCollision,
        ] {
            let fixture = Fixture::new();
            let anchor = fixture.anchor();
            let keyring =
                FilePersistedIdentityKeyringCustody::from_anchor_store(&anchor, keys()).unwrap();
            let leaf = fixture.platform.join(artifact);
            let target = fixture.workspace.join(format!(
                "outside-keyring-{}-{attack:?}",
                artifact.replace('.', "_")
            ));
            match attack {
                Attack::Symlink => {
                    fs::write(&target, b"keyring sentinel").unwrap();
                    symlink(&target, &leaf).unwrap();
                }
                Attack::Fifo => create_fifo(&leaf),
                Attack::Hardlink => {
                    fs::write(&target, b"keyring sentinel").unwrap();
                    fs::hard_link(&target, &leaf).unwrap();
                }
                Attack::TempCollision => fs::create_dir(&leaf).unwrap(),
            }
            assert!(
                keyring.initialize_genesis([0x11; 16], 1, 1).is_err(),
                "accepted keyring {attack:?} at {artifact}"
            );
            if matches!(attack, Attack::Symlink | Attack::Hardlink) {
                assert_eq!(fs::read(&target).unwrap(), b"keyring sentinel");
            }
        }
    }
}

#[test]
fn persisted_identity_key_literal_kat() {
    let mut info = b"advance.contract218.persisted-identity-key.v1\0".to_vec();
    info.extend_from_slice(&1u32.to_be_bytes());
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(&[1; 32]), &[0; 32])
        .expand(&info, key.as_mut())
        .unwrap();
    assert_eq!(
        hex::encode(key.as_ref()),
        "bf8f52ac21c5e9b48d5b389a04acd72bf7438a0b35da2771f718a097d7580e07"
    );
    key.zeroize();
}

#[test]
fn verify_carrier_uses_explicit_key_id_without_exporting_key() {
    let fixture = Fixture::new();
    let (_anchor, keyring, _) = initialize(&fixture);
    let bytes = fs::read(fixture.platform.join("contract218.keyring.current")).unwrap();
    let salt: [u8; 32] = bytes[61..93].try_into().unwrap();
    let mut info = b"advance.contract218.persisted-identity-key.v1\0".to_vec();
    info.extend_from_slice(&1u32.to_be_bytes());
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(&salt), &[0x71; 32])
        .expand(&info, key.as_mut())
        .unwrap();
    let preceding = b"canonical persisted carrier prefix";
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key.as_ref()).unwrap();
    mac.update(b"advance.contract218.persisted-identity.v1\0");
    mac.update(preceding);
    let tag: [u8; 32] = mac.finalize().into_bytes().into();
    assert!(keyring.verify_carrier_mac(1, preceding, &tag).is_ok());
    let mut tampered = tag;
    tampered[0] ^= 1;
    assert!(matches!(
        keyring.verify_carrier_mac(1, preceding, &tampered),
        Err(PersistedKeyringCustodyError::AuthenticationFailed)
    ));
    assert!(matches!(
        keyring.verify_carrier_mac(2, preceding, &tag),
        Err(PersistedKeyringCustodyError::KeyUnavailable)
    ));
    assert_eq!(tag.ct_eq(&tampered).unwrap_u8(), 0);
}

#[test]
fn typed_role_and_scheduler_custody_advance_exactly_one_generation() {
    let fixture = Fixture::new();
    let (anchor, keyring, _) = initialize(&fixture);
    let installer =
        PersistedIdentityKeyringInstaller::fixture_for_test([0x11; 16], [0xB1; 16]).unwrap();
    let role = installer
        .install_authenticated_custody(Box::new(keyring.clone()))
        .unwrap();
    let previous = PersistedIdentityKeyringProvider::current_keyring_binding(&keyring).unwrap();
    role.verify_provider_binding([0x11; 16], previous.keyring_root())
        .unwrap();
    let _old_signing = role.signing_key_capability().unwrap();
    let _old_verification = role.verification_key_capability(1).unwrap();

    let custody: &dyn PersistedKeyringCustody = &keyring;
    let mut prepared = custody
        .prepare_signing_rotation(1, unchanged_context())
        .unwrap();
    assert_eq!(prepared.previous_binding(), previous);
    assert_eq!(
        prepared.next_binding().keyring_generation(),
        previous.keyring_generation() + 1
    );
    let next_binding = prepared.next_binding();
    let scheduler = prepared.take_scheduler_preparation().unwrap();
    let next_anchor = scheduler.next().clone();
    let proof = scheduler.database_commit_proof_for_test(&anchor).unwrap();
    let selected_current = scheduler.prepare_external_anchor(&anchor).unwrap();
    let database_committed = selected_current.database_committed(proof).unwrap();
    let selected_next = database_committed.select_next().unwrap();
    selected_next.compact().unwrap();
    prepared.promote_after_anchor(&next_anchor).unwrap();

    assert!(role.signing_key_capability().is_err());
    let advanced = role
        .advance_authenticated_binding(previous, next_binding)
        .unwrap();
    advanced
        .verify_provider_binding([0x11; 16], next_anchor.keyring_root)
        .unwrap();
    let _new_signing = advanced.signing_key_capability().unwrap();
    let _old_verify_only = advanced.verification_key_capability(1).unwrap();
}

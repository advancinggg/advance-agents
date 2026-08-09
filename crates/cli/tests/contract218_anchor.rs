use advance_cli::contract218_anchor::{
    test_only_anchor_file_exists, AnchorFailpoint, FilePlatformMonotonicAnchorStore,
    FileTestPlatformMonotonicRecord, HmacPlatformAnchorSeal, HmacRegistryManifestSeal,
    MemoryPlatformMonotonicRecord, PlatformMonotonicRecord, PLATFORM_SELECTOR_LEN,
};
use advance_cli::contract218_roles::{
    test_only_role_file_exists, FileContract218RoleRootCustody, MemoryProtection,
    RoleRootCustodyError,
};
use advance_scheduler::observation_anchor::{
    classify_recovery, PreparedCurrent, PreparedRoleAllocationMutation, RegistryAnchorError,
    RegistryAnchorMutation, RegistryAnchorTransaction, RegistryAnchorTuple, RegistryAnchorWorld,
    RegistryDatabaseCommitProof, RegistryHeadContext, RegistryRecoveryCapability,
    RegistryRecoveryDecision, RetainedRoleDependencyReceipt, VerifiedEmptyRegistryGenesis,
    ZeroRoleDependencyReceipt,
};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use tempfile::TempDir;
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

#[cfg(unix)]
fn create_fifo(path: &std::path::Path) {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let path = CString::new(path.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
}

struct FakeCapabilityAnchor;

impl RegistryAnchorTransaction for FakeCapabilityAnchor {
    fn observe(&self) -> Result<RegistryAnchorWorld, RegistryAnchorError> {
        Err(RegistryAnchorError::Uninitialized)
    }

    fn anchor_lease_tag(&self, _challenge: [u8; 32]) -> Result<[u8; 32], RegistryAnchorError> {
        Ok([0xe1; 32])
    }

    fn initialize_compact(
        &self,
        _genesis: VerifiedEmptyRegistryGenesis,
    ) -> Result<(), RegistryAnchorError> {
        Err(RegistryAnchorError::InvalidTransition)
    }

    fn prepare_current(
        &self,
        _mutation: RegistryAnchorMutation,
    ) -> Result<Box<dyn PreparedCurrent>, RegistryAnchorError> {
        Err(RegistryAnchorError::InvalidTransition)
    }

    fn recover(&self, _capability: RegistryRecoveryCapability) -> Result<(), RegistryAnchorError> {
        Err(RegistryAnchorError::InvalidTransition)
    }
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
        let platform = root.path().join("platform-anchor");
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

    fn store(&self) -> FilePlatformMonotonicAnchorStore {
        open_test_store(&self.platform, &self.workspace, self.seal()).unwrap()
    }

    fn initialize(&self, store: &FilePlatformMonotonicAnchorStore, tuple: &RegistryAnchorTuple) {
        store.install_minimal_artifacts_for_test(tuple, 1).unwrap();
        let witness = VerifiedEmptyRegistryGenesis::fixture_for_test(
            tuple.clone(),
            &self.workspace,
            &self.registry,
        )
        .unwrap();
        store.initialize_compact(witness).unwrap();
    }
}

fn manifest_seal() -> Arc<HmacRegistryManifestSeal> {
    Arc::new(
        HmacRegistryManifestSeal::consume_host_master_keys(vec![
            (1, Zeroizing::new([0x71; 32])),
            (2, Zeroizing::new([0x72; 32])),
            (3, Zeroizing::new([0x73; 32])),
        ])
        .unwrap(),
    )
}

fn open_test_store(
    platform: impl AsRef<std::path::Path>,
    workspace: impl AsRef<std::path::Path>,
    selector_seal: Arc<HmacPlatformAnchorSeal>,
) -> Result<FilePlatformMonotonicAnchorStore, RegistryAnchorError> {
    let platform = platform.as_ref();
    fs::create_dir_all(platform).unwrap();
    let record = Arc::new(
        FileTestPlatformMonotonicRecord::open_for_test(
            platform.join("contract218.platform-record.test-only"),
        )
        .unwrap(),
    );
    FilePlatformMonotonicAnchorStore::acquire(
        platform,
        workspace,
        record,
        selector_seal,
        manifest_seal(),
    )
}

fn open_store_with_record(
    platform: impl AsRef<std::path::Path>,
    workspace: impl AsRef<std::path::Path>,
    record: Arc<dyn PlatformMonotonicRecord>,
    selector_seal: Arc<HmacPlatformAnchorSeal>,
) -> Result<FilePlatformMonotonicAnchorStore, RegistryAnchorError> {
    fs::create_dir_all(platform.as_ref()).unwrap();
    FilePlatformMonotonicAnchorStore::acquire(
        platform,
        workspace,
        record,
        selector_seal,
        manifest_seal(),
    )
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

fn minimal_artifact(discriminator: u8) -> Vec<u8> {
    let mut bytes = vec![1];
    bytes.extend_from_slice(&1u32.to_be_bytes());
    bytes.extend_from_slice(&[0x11; 16]);
    bytes.push(discriminator);
    bytes
}

fn authenticated_complete_marker(block: [u8; 228]) -> Vec<u8> {
    let epoch = 1u32;
    let mut preceding = Vec::new();
    preceding.push(1);
    preceding.extend_from_slice(&epoch.to_be_bytes());
    preceding.extend_from_slice(&block);
    preceding.push(3);
    preceding.extend_from_slice(&[0x36; 32]);
    let mut info = b"advance.contract218.registry-migration-marker-key.v1\0".to_vec();
    info.extend_from_slice(&epoch.to_be_bytes());
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(&[0x11; 16]), &[0x71; 32])
        .expand(&info, key.as_mut())
        .unwrap();
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key.as_ref()).unwrap();
    mac.update(b"advance.contract218.registry-migration-marker.v1\0");
    mac.update(&preceding);
    preceding.extend_from_slice(&mac.finalize().into_bytes());
    preceding
}

fn tuple(sequence: u64, marker: u8) -> RegistryAnchorTuple {
    RegistryAnchorTuple {
        registry_instance: [0x11; 16],
        sequence,
        head: [marker; 32],
        state_root: [marker.wrapping_add(1); 32],
        keyring_root: advance_scheduler::observation_anchor::persisted_keyring_file_root(
            &minimal_artifact(0x4b),
        ),
        role_allocation_root: advance_scheduler::observation_anchor::role_allocation_file_root(
            &minimal_artifact(0x52),
        ),
        migration_digest: greenfield_digest(),
    }
}

fn mutation(
    anchor: &dyn RegistryAnchorTransaction,
    previous: &RegistryAnchorTuple,
    next: &RegistryAnchorTuple,
) -> RegistryAnchorMutation {
    let write_set_digest = [0x66; 32];
    let head_context = unchanged_head_context();
    let mut next = next.clone();
    next.head = [0; 32];
    RegistryAnchorMutation::fixture_for_test(
        anchor,
        previous.clone(),
        next,
        head_context,
        6,
        write_set_digest,
    )
    .unwrap()
}

fn database_commit_proof(
    store: &dyn RegistryAnchorTransaction,
    mutation: &RegistryAnchorMutation,
) -> RegistryDatabaseCommitProof {
    RegistryDatabaseCommitProof::fixture_for_test(store, mutation).unwrap()
}

fn recover_exact(
    store: &FilePlatformMonotonicAnchorStore,
    ledger: &RegistryAnchorTuple,
) -> Result<(), RegistryAnchorError> {
    let world = store.observe()?;
    let capability = RegistryRecoveryCapability::fixture_for_test(store, world, ledger.clone())?;
    store.recover(capability)
}

fn unchanged_head_context() -> RegistryHeadContext {
    RegistryHeadContext::unchanged(greenfield_marker_root(), 1).unwrap()
}

fn assert_compact(world: RegistryAnchorWorld, expected: &RegistryAnchorTuple) {
    assert!(matches!(
        world,
        RegistryAnchorWorld::CompactCurrent { current, .. } if current == *expected
    ));
}

fn role_custody(anchor: &FilePlatformMonotonicAnchorStore) -> FileContract218RoleRootCustody {
    FileContract218RoleRootCustody::from_anchor_store(anchor, 1, Zeroizing::new([0x71; 32]))
        .unwrap()
}

fn initialize_roles_and_anchor(
    fixture: &Fixture,
) -> (
    FilePlatformMonotonicAnchorStore,
    FileContract218RoleRootCustody,
    RegistryAnchorTuple,
) {
    let anchor = fixture.store();
    let roles = role_custody(&anchor);
    let root = roles.initialize_empty([0x11; 16], 1).unwrap();
    let mut genesis = tuple(0, 1);
    genesis.role_allocation_root = root.into_bytes();
    fixture.initialize(&anchor, &genesis);
    (anchor, roles, genesis)
}

fn anchor_role_update(
    anchor: &FilePlatformMonotonicAnchorStore,
    preparation: PreparedRoleAllocationMutation,
) -> RegistryAnchorTuple {
    let next = preparation.next().clone();
    let proof = preparation.database_commit_proof_for_test(anchor).unwrap();
    let prepared = preparation.prepare_external_anchor(anchor).unwrap();
    let committed = prepared.database_committed(proof).unwrap();
    let selected = committed.select_next().unwrap();
    let compacted = selected.compact().unwrap();
    assert_eq!(compacted.current(), &next);
    next
}

#[test]
fn compact_no_next_clean_restart() {
    let fixture = Fixture::new();
    let genesis = tuple(0, 1);
    {
        let store = fixture.store();
        fixture.initialize(&store, &genesis);
        assert_eq!(PLATFORM_SELECTOR_LEN, 151);
    }
    let reopened = fixture.store();
    assert_compact(reopened.observe().unwrap(), &genesis);
}

#[test]
fn invalid_platform_key_inputs_and_partial_initialization_reject() {
    assert!(matches!(
        HmacPlatformAnchorSeal::consume_platform_key(0, Zeroizing::new([0xA5; 32])),
        Err(RegistryAnchorError::InvalidTransition)
    ));
    assert!(matches!(
        HmacPlatformAnchorSeal::consume_platform_key(1, Zeroizing::new([0; 32])),
        Err(RegistryAnchorError::InvalidTransition)
    ));

    let fixture = Fixture::new();
    let store = fixture.store();
    fs::write(
        fixture.platform.join(".contract218.bundle-a.tmp"),
        b"torn initialization",
    )
    .unwrap();
    let witness = VerifiedEmptyRegistryGenesis::fixture_for_test(
        tuple(0, 1),
        &fixture.workspace,
        &fixture.registry,
    )
    .unwrap();
    assert!(matches!(
        store.initialize_compact(witness),
        Err(RegistryAnchorError::RecoveryRequired(_))
    ));
    assert!(!fixture.platform.join("contract218.bundle-a").exists());
}

#[test]
fn role_initialization_rejects_current_and_pending_temporary_artifacts() {
    for artifact in [
        ".contract218.roles.current.tmp",
        ".contract218.roles.pending.tmp",
    ] {
        let fixture = Fixture::new();
        let anchor = fixture.store();
        let roles = role_custody(&anchor);
        fs::write(fixture.platform.join(artifact), b"torn role manifest").unwrap();
        assert!(matches!(
            roles.initialize_empty([0x11; 16], 1),
            Err(RoleRootCustodyError::RecoveryRequired(_))
        ));
        assert!(!fixture.platform.join("contract218.roles.current").exists());
    }
}

#[test]
fn xchacha_root_wrap_literal_kat() {
    let master_key = [0x42; 32];
    let registry_instance = [0x33; 16];
    let boot_id = [0x44; 16];
    let mut salt = [0u8; 32];
    salt[..16].copy_from_slice(&registry_instance);
    salt[16..].copy_from_slice(&boot_id);
    let mut info = b"advance.contract218.role-root-wrap.v1\0".to_vec();
    info.extend_from_slice(&1u32.to_be_bytes());
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(&salt), &master_key)
        .expand(&info, key.as_mut())
        .unwrap();
    assert_eq!(
        hex::encode(key.as_ref()),
        "853c122827a58101b9f54d47b516743a1fb0cfd6d744b3161ae58c2c95f5c4ad"
    );

    let mut aad = Vec::new();
    aad.extend_from_slice(&boot_id);
    aad.extend_from_slice(&1u32.to_be_bytes());
    aad.extend_from_slice(&7u64.to_be_bytes());
    aad.push(1);
    aad.extend_from_slice(&9u32.to_be_bytes());
    aad.extend_from_slice(&11u64.to_be_bytes());
    aad.extend_from_slice(&0u64.to_be_bytes());
    let ciphertext = XChaCha20Poly1305::new_from_slice(key.as_ref())
        .unwrap()
        .encrypt(
            XNonce::from_slice(&[0x24; 24]),
            Payload {
                msg: &[0x11; 32],
                aad: &aad,
            },
        )
        .unwrap();
    assert_eq!(
        hex::encode(ciphertext),
        "19b8a84256e56f1257105b07d79b52cec329452943e38ad11b17041c7589a43e1a78f066091638510d14aa53abf21727"
    );
}

#[test]
fn pending_current_previous_ledger_rolls_back() {
    let fixture = Fixture::new();
    let previous = tuple(4, 4);
    let store = fixture.store();
    let transition = mutation(&store, &previous, &tuple(5, 5));
    store
        .initialize_compact_at_generation_for_test(&previous, 1)
        .unwrap();
    let _prepared = store.prepare_current(transition).unwrap();
    let world = store.observe().unwrap();
    assert_eq!(
        classify_recovery(&world, &previous).unwrap(),
        RegistryRecoveryDecision::RollBackPending
    );
    recover_exact(&store, &previous).unwrap();
    assert_compact(store.observe().unwrap(), &previous);
}

#[test]
fn pending_current_next_ledger_promotes() {
    let fixture = Fixture::new();
    let previous = tuple(8, 8);
    let store = fixture.store();
    let transition = mutation(&store, &previous, &tuple(9, 9));
    let next = transition.next().clone();
    store
        .initialize_compact_at_generation_for_test(&previous, 1)
        .unwrap();
    let _prepared = store.prepare_current(transition).unwrap();
    let world = store.observe().unwrap();
    assert_eq!(
        classify_recovery(&world, &next).unwrap(),
        RegistryRecoveryDecision::FinishPendingPromotion
    );
    recover_exact(&store, &next).unwrap();
    assert_compact(store.observe().unwrap(), &next);
}

#[test]
fn selected_next_next_ledger_compacts() {
    let fixture = Fixture::new();
    let previous = tuple(10, 10);
    let store = fixture.store();
    let transition = mutation(&store, &previous, &tuple(11, 11));
    let next = transition.next().clone();
    store
        .initialize_compact_at_generation_for_test(&previous, 1)
        .unwrap();
    let proof = database_commit_proof(&store, &transition);
    let prepared = store.prepare_current(transition).unwrap();
    let committed = prepared.database_committed(proof).unwrap();
    let _selected = committed.select_next().unwrap();
    let world = store.observe().unwrap();
    assert_eq!(
        classify_recovery(&world, &next).unwrap(),
        RegistryRecoveryDecision::CompactSelectedNext
    );
    recover_exact(&store, &next).unwrap();
    assert_compact(store.observe().unwrap(), &next);
}

#[test]
fn all_illegal_selector_ledger_cross_products_reject() {
    let previous = tuple(20, 20);
    let next = tuple(21, 21);
    let unrelated = tuple(99, 99);
    let worlds = [
        RegistryAnchorWorld::PendingCurrent {
            generation: 2,
            previous,
            next: next.clone(),
        },
        RegistryAnchorWorld::SelectedNext {
            generation: 3,
            next: next.clone(),
        },
        RegistryAnchorWorld::CompactCurrent {
            generation: 4,
            current: next,
        },
    ];
    for world in worlds {
        assert!(matches!(
            classify_recovery(&world, &unrelated),
            Err(RegistryAnchorError::RecoveryRequired(_))
        ));
    }
}

#[test]
fn valid_old_bundle_below_selector_rejects() {
    let fixture = Fixture::new();
    let previous = tuple(1, 1);
    let store = fixture.store();
    let transition = mutation(&store, &previous, &tuple(2, 2));
    let next = transition.next().clone();
    store
        .initialize_compact_at_generation_for_test(&previous, 1)
        .unwrap();
    let proof = database_commit_proof(&store, &transition);
    let prepared = store.prepare_current(transition).unwrap();
    let committed = prepared.database_committed(proof).unwrap();
    let selected = committed.select_next().unwrap();
    let compacted = selected.compact().unwrap();
    assert_eq!(compacted.current(), &next);
    drop(store);

    // The selector now authenticates bundle-a (G+3).  Replacing it with the
    // valid older bundle-b simulates a restored external artifact below the
    // monotonic selector and must fail its digest binding.
    fs::copy(
        fixture.platform.join("contract218.bundle-b"),
        fixture.platform.join("contract218.bundle-a"),
    )
    .unwrap();
    let reopened = fixture.store();
    assert!(matches!(
        reopened.observe(),
        Err(RegistryAnchorError::AuthenticationFailed)
    ));
}

#[test]
fn same_sequence_fork_rejects() {
    let selected = tuple(31, 31);
    let fork = tuple(31, 32);
    let world = RegistryAnchorWorld::CompactCurrent {
        generation: 9,
        current: selected,
    };
    assert!(matches!(
        classify_recovery(&world, &fork),
        Err(RegistryAnchorError::RecoveryRequired(_))
    ));
}

#[test]
fn db_commit_and_each_selector_failpoint_recovers() {
    let fixture = Fixture::new();
    let previous = tuple(40, 40);
    let store = fixture.store();
    let transition = mutation(&store, &previous, &tuple(41, 41));
    let next = transition.next().clone();
    store
        .initialize_compact_at_generation_for_test(&previous, 1)
        .unwrap();

    store.set_failpoint_for_test(AnchorFailpoint::AfterBundleFsync);
    assert!(store.prepare_current(transition).is_err());
    assert_compact(store.observe().unwrap(), &previous);

    let transition = mutation(&store, &previous, &tuple(41, 41));
    store.set_failpoint_for_test(AnchorFailpoint::AfterSelectorFsync);
    assert!(store.prepare_current(transition).is_err());
    let pending = store.observe().unwrap();
    assert_eq!(
        classify_recovery(&pending, &previous).unwrap(),
        RegistryRecoveryDecision::RollBackPending
    );
    // A simulated SQLite commit changes only the ledger relation; external
    // recovery now finishes promotion, then compacts.
    assert_eq!(
        classify_recovery(&pending, &next).unwrap(),
        RegistryRecoveryDecision::FinishPendingPromotion
    );
    recover_exact(&store, &next).unwrap();
    assert_compact(store.observe().unwrap(), &next);
}

#[test]
fn missing_anchor_or_key_is_not_greenfield() {
    let fixture = Fixture::new();
    {
        let store = fixture.store();
        assert!(matches!(
            store.observe(),
            Err(RegistryAnchorError::Uninitialized)
        ));
        fixture.initialize(&store, &tuple(0, 1));
    }
    let wrong_seal = Arc::new(
        HmacPlatformAnchorSeal::consume_platform_key(7, Zeroizing::new([0x5A; 32])).unwrap(),
    );
    let reopened = open_test_store(&fixture.platform, &fixture.workspace, wrong_seal).unwrap();
    assert!(matches!(
        reopened.observe(),
        Err(RegistryAnchorError::AuthenticationFailed)
    ));
}

#[test]
fn uninitialized_requires_exact_absence_of_every_anchor_and_temporary_file() {
    for artifact in [
        "contract218.bundle-a",
        "contract218.bundle-b",
        ".contract218.bundle-a.tmp",
        ".contract218.bundle-b.tmp",
    ] {
        let fixture = Fixture::new();
        let store = fixture.store();
        fs::write(fixture.platform.join(artifact), b"partial anchor state").unwrap();
        assert!(matches!(
            store.observe(),
            Err(RegistryAnchorError::RecoveryRequired(_))
        ));
    }

    let fixture = Fixture::new();
    let store = fixture.store();
    fixture.initialize(&store, &tuple(0, 1));
    fs::remove_file(fixture.platform.join("contract218.bundle-a")).unwrap();
    assert!(matches!(
        store.observe(),
        Err(RegistryAnchorError::RecoveryRequired(_))
    ));
}

#[test]
fn prepared_anchor_cannot_advance_without_database_commit_capability() {
    let fixture = Fixture::new();
    let previous = tuple(0, 0x31);
    let store = fixture.store();
    let transition = mutation(&store, &previous, &tuple(1, 0x32));
    let next = transition.next().clone();
    fixture.initialize(&store, &previous);

    let prepared = store.prepare_current(transition).unwrap();
    drop(prepared);
    assert!(matches!(
        store.observe().unwrap(),
        RegistryAnchorWorld::PendingCurrent {
            previous: ref observed_previous,
            next: ref observed_next,
            ..
        } if observed_previous == &previous && observed_next == &next
    ));

    recover_exact(&store, &previous).unwrap();
    assert_compact(store.observe().unwrap(), &previous);
}

#[test]
fn fake_anchor_cannot_mint_or_consume_scheduler_capability() {
    let fixture = Fixture::new();
    let previous = tuple(0, 0x39);
    let store = fixture.store();
    let transition = mutation(&store, &previous, &tuple(1, 0x3a));
    fixture.initialize(&store, &previous);
    assert!(matches!(
        RegistryDatabaseCommitProof::fixture_for_test(&FakeCapabilityAnchor, &transition),
        Err(RegistryAnchorError::AuthenticationFailed)
    ));
    assert_compact(store.observe().unwrap(), &previous);
}

#[test]
fn cross_anchor_database_commit_capability_rejects() {
    let source = Fixture::new();
    let target = Fixture::new();
    let previous = tuple(0, 0x41);
    let source_store = source.store();
    let target_store = target.store();
    source.initialize(&source_store, &previous);
    target.initialize(&target_store, &previous);

    let source_world = source_store.observe().unwrap();
    let recovery =
        RegistryRecoveryCapability::fixture_for_test(&source_store, source_world, previous.clone())
            .unwrap();
    assert_eq!(
        target_store.recover(recovery),
        Err(RegistryAnchorError::AuthenticationFailed)
    );

    let source_bound = mutation(&source_store, &previous, &tuple(1, 0x42));
    assert!(matches!(
        target_store.prepare_current(source_bound),
        Err(RegistryAnchorError::AuthenticationFailed)
    ));
    assert_compact(target_store.observe().unwrap(), &previous);

    let source_bound = mutation(&source_store, &previous, &tuple(1, 0x42));
    let _source_prepared = source_store.prepare_current(source_bound).unwrap();
}

#[test]
fn anchor_lease_tags_bind_exact_challenge_and_workspace_identity() {
    let first = Fixture::new();
    let second = Fixture::new();
    let first_store = first.store();
    let first_clone = first_store.clone();
    let second_store = second.store();
    let challenge = [0x73; 32];
    let first_tag = first_store.anchor_lease_tag(challenge).unwrap();

    assert_eq!(first_clone.anchor_lease_tag(challenge).unwrap(), first_tag);
    assert_ne!(first_store.anchor_lease_tag([0x74; 32]).unwrap(), first_tag);
    assert_ne!(second_store.anchor_lease_tag(challenge).unwrap(), first_tag);
}

#[test]
fn stale_prepared_mutation_capability_rejects() {
    let fixture = Fixture::new();
    let previous = tuple(0, 0x51);
    let store = fixture.store();
    let transition = mutation(&store, &previous, &tuple(1, 0x52));
    fixture.initialize(&store, &previous);
    let stale = RegistryRecoveryCapability::fixture_for_test(
        &store,
        store.observe().unwrap(),
        previous.clone(),
    )
    .unwrap();
    let _prepared = store.prepare_current(transition).unwrap();

    assert_eq!(
        store.recover(stale),
        Err(RegistryAnchorError::CompareAndSwapFailed)
    );
    recover_exact(&store, &previous).unwrap();
}

#[cfg(unix)]
#[test]
fn anchor_custody_rejects_symlink_fifo_device_hardlink_and_temp_collisions() {
    use std::os::unix::fs::symlink;

    #[derive(Clone, Copy, Debug)]
    enum Attack {
        Symlink,
        Fifo,
        Hardlink,
        TempCollision,
    }

    fn plant(leaf: &std::path::Path, target: &std::path::Path, attack: Attack) {
        match attack {
            Attack::Symlink => {
                fs::write(target, b"anchor sentinel").unwrap();
                symlink(target, leaf).unwrap();
            }
            Attack::Fifo => create_fifo(leaf),
            Attack::Hardlink => {
                fs::write(target, b"anchor sentinel").unwrap();
                fs::hard_link(target, leaf).unwrap();
            }
            Attack::TempCollision => fs::create_dir(leaf).unwrap(),
        }
    }

    let attacks = [
        Attack::Symlink,
        Attack::Fifo,
        Attack::Hardlink,
        Attack::TempCollision,
    ];
    for artifact in [
        "contract218.bundle-a",
        "contract218.bundle-b",
        ".contract218.bundle-a.tmp",
        ".contract218.bundle-b.tmp",
    ] {
        assert!(
            test_only_anchor_file_exists(std::path::Path::new("/dev/null")).is_err(),
            "accepted anchor character device at {artifact}"
        );
        for attack in attacks {
            let fixture = Fixture::new();
            let store = fixture.store();
            let leaf = fixture.platform.join(artifact);
            let target = fixture.workspace.join(format!(
                "outside-anchor-{}-{attack:?}",
                artifact.replace('.', "_")
            ));
            plant(&leaf, &target, attack);
            assert!(
                store.observe().is_err(),
                "accepted anchor {attack:?} at {artifact}"
            );
            if matches!(attack, Attack::Symlink | Attack::Hardlink) {
                assert_eq!(fs::read(&target).unwrap(), b"anchor sentinel");
            }
        }
    }

    for artifact in [
        "contract218.platform-record.test-only",
        "contract218.custody.lock",
    ] {
        assert!(
            test_only_anchor_file_exists(std::path::Path::new("/dev/null")).is_err(),
            "accepted anchor character device at {artifact}"
        );
        for attack in attacks {
            let fixture = Fixture::new();
            let leaf = fixture.platform.join(artifact);
            let target = fixture.workspace.join(format!(
                "outside-anchor-{}-{attack:?}",
                artifact.replace('.', "_")
            ));
            plant(&leaf, &target, attack);
            let rejected = if artifact == "contract218.platform-record.test-only" {
                FileTestPlatformMonotonicRecord::open_for_test(&leaf).is_err()
            } else {
                open_test_store(&fixture.platform, &fixture.workspace, fixture.seal()).is_err()
            };
            assert!(rejected, "accepted anchor {attack:?} at {artifact}");
            if matches!(attack, Attack::Symlink | Attack::Hardlink) {
                assert_eq!(fs::read(&target).unwrap(), b"anchor sentinel");
            }
        }
    }
}

#[cfg(unix)]
#[test]
fn role_custody_rejects_symlink_fifo_device_hardlink_and_temp_collisions() {
    use std::os::unix::fs::symlink;

    #[derive(Clone, Copy, Debug)]
    enum Attack {
        Symlink,
        Fifo,
        Hardlink,
        TempCollision,
    }

    let artifacts = [
        "contract218.roles.current",
        "contract218.roles.pending",
        ".contract218.roles.current.tmp",
        ".contract218.roles.pending.tmp",
    ];
    for artifact in artifacts {
        assert!(
            test_only_role_file_exists(std::path::Path::new("/dev/null")).is_err(),
            "accepted role character device at {artifact}"
        );
        for attack in [
            Attack::Symlink,
            Attack::Fifo,
            Attack::Hardlink,
            Attack::TempCollision,
        ] {
            let fixture = Fixture::new();
            let anchor = fixture.store();
            let roles = role_custody(&anchor);
            let leaf = fixture.platform.join(artifact);
            let target = fixture.workspace.join(format!(
                "outside-role-{}-{attack:?}",
                artifact.replace('.', "_")
            ));
            match attack {
                Attack::Symlink => {
                    fs::write(&target, b"role sentinel").unwrap();
                    symlink(&target, &leaf).unwrap();
                }
                Attack::Fifo => create_fifo(&leaf),
                Attack::Hardlink => {
                    fs::write(&target, b"role sentinel").unwrap();
                    fs::hard_link(&target, &leaf).unwrap();
                }
                Attack::TempCollision => fs::create_dir(&leaf).unwrap(),
            }
            assert!(
                roles.initialize_empty([0x11; 16], 1).is_err(),
                "accepted role {attack:?} at {artifact}"
            );
            if matches!(attack, Attack::Symlink | Attack::Hardlink) {
                assert_eq!(fs::read(&target).unwrap(), b"role sentinel");
            }
        }
    }
}

#[test]
fn cas_max_minus_three_succeeds_later_values_preserve_state() {
    let fixture = Fixture::new();
    let previous = tuple(50, 50);
    let store = fixture.store();
    let transition = mutation(&store, &previous, &tuple(51, 51));
    let next = transition.next().clone();
    store
        .initialize_compact_at_generation_for_test(&previous, u64::MAX - 3)
        .unwrap();
    let proof = database_commit_proof(&store, &transition);
    let prepared = store.prepare_current(transition).unwrap();
    let committed = prepared.database_committed(proof).unwrap();
    let selected = committed.select_next().unwrap();
    selected.compact().unwrap();
    assert_compact(store.observe().unwrap(), &next);

    let after = mutation(&store, &next, &tuple(52, 52));
    assert!(matches!(
        store.prepare_current(after),
        Err(RegistryAnchorError::GenerationExhausted)
    ));
    assert_compact(store.observe().unwrap(), &next);

    for generation in [u64::MAX - 2, u64::MAX - 1, u64::MAX] {
        let fixture = Fixture::new();
        let previous = tuple(60, 60);
        let store = fixture.store();
        let transition = mutation(&store, &previous, &tuple(61, 61));
        store
            .initialize_compact_at_generation_for_test(&previous, generation)
            .unwrap();
        assert!(matches!(
            store.prepare_current(transition),
            Err(RegistryAnchorError::GenerationExhausted)
        ));
        assert_compact(store.observe().unwrap(), &previous);
    }
}

#[test]
fn protected_record_defeats_whole_sqlite_and_both_bundle_slot_rollback() {
    let fixture = Fixture::new();
    let record: Arc<dyn PlatformMonotonicRecord> =
        Arc::new(MemoryPlatformMonotonicRecord::deterministic_for_test([0xa1; 16]).unwrap());
    let store = open_store_with_record(
        &fixture.platform,
        &fixture.workspace,
        Arc::clone(&record),
        fixture.seal(),
    )
    .unwrap();
    let genesis = tuple(0, 1);
    fixture.initialize(&store, &genesis);
    let first = mutation(&store, &genesis, &tuple(1, 2));
    let first_next = first.next().clone();
    let proof = database_commit_proof(&store, &first);
    let prepared = store.prepare_current(first).unwrap();
    let committed = prepared.database_committed(proof).unwrap();
    committed.select_next().unwrap().compact().unwrap();
    fs::write(&fixture.registry, b"snapshot-at-generation-four").unwrap();
    let snapshot_a = fs::read(fixture.platform.join("contract218.bundle-a")).unwrap();
    let snapshot_b = fs::read(fixture.platform.join("contract218.bundle-b")).unwrap();
    let snapshot_db = fs::read(&fixture.registry).unwrap();

    let second = mutation(&store, &first_next, &tuple(2, 3));
    let proof = database_commit_proof(&store, &second);
    let prepared = store.prepare_current(second).unwrap();
    let committed = prepared.database_committed(proof).unwrap();
    committed.select_next().unwrap().compact().unwrap();
    fs::write(&fixture.registry, b"newer-sqlite-world").unwrap();
    drop(store);

    fs::write(fixture.platform.join("contract218.bundle-a"), snapshot_a).unwrap();
    fs::write(fixture.platform.join("contract218.bundle-b"), snapshot_b).unwrap();
    fs::write(&fixture.registry, snapshot_db).unwrap();
    let reopened = open_store_with_record(
        &fixture.platform,
        &fixture.workspace,
        record,
        fixture.seal(),
    )
    .unwrap();
    assert!(matches!(
        reopened.observe(),
        Err(RegistryAnchorError::AuthenticationFailed)
    ));
}

#[test]
fn cross_install_clone_of_selector_bundles_and_workspace_rejects() {
    let source = Fixture::new();
    let source_record: Arc<dyn PlatformMonotonicRecord> =
        Arc::new(MemoryPlatformMonotonicRecord::deterministic_for_test([0xa2; 16]).unwrap());
    let source_store = open_store_with_record(
        &source.platform,
        &source.workspace,
        Arc::clone(&source_record),
        source.seal(),
    )
    .unwrap();
    let genesis = tuple(0, 1);
    source.initialize(&source_store, &genesis);
    let cloned_selector = source_record.read_selector().unwrap().unwrap();
    let nonce: [u8; 32] = cloned_selector[87..119].try_into().unwrap();
    drop(source_store);

    let clone_root = tempfile::tempdir().unwrap();
    let clone_workspace = clone_root.path().join("workspace");
    let clone_platform = clone_root.path().join("platform");
    fs::create_dir_all(&clone_workspace).unwrap();
    fs::create_dir_all(&clone_platform).unwrap();
    fs::copy(
        &source.registry,
        clone_workspace.join("component-registry.sqlite"),
    )
    .unwrap();
    for file in [
        "contract218.bundle-a",
        "contract218.keyring.current",
        "contract218.roles.current",
    ] {
        fs::copy(source.platform.join(file), clone_platform.join(file)).unwrap();
    }
    let clone_record: Arc<dyn PlatformMonotonicRecord> =
        Arc::new(MemoryPlatformMonotonicRecord::deterministic_for_test([0xb2; 16]).unwrap());
    let uninitialized_clone = open_store_with_record(
        &clone_platform,
        &clone_workspace,
        Arc::clone(&clone_record),
        source.seal(),
    )
    .unwrap();
    assert!(matches!(
        uninitialized_clone.observe(),
        Err(RegistryAnchorError::RecoveryRequired(_))
    ));
    drop(uninitialized_clone);
    clone_record
        .compare_and_swap(None, &cloned_selector, 1, nonce)
        .unwrap();
    let cloned = open_store_with_record(
        &clone_platform,
        &clone_workspace,
        clone_record,
        source.seal(),
    )
    .unwrap();
    assert!(matches!(
        cloned.observe(),
        Err(RegistryAnchorError::AuthenticationFailed)
    ));
}

#[test]
fn protected_installation_record_cannot_rebind_to_another_workspace() {
    let first = Fixture::new();
    let second = Fixture::new();
    let record: Arc<dyn PlatformMonotonicRecord> =
        Arc::new(MemoryPlatformMonotonicRecord::deterministic_for_test([0xc2; 16]).unwrap());
    let first_store = open_store_with_record(
        &first.platform,
        &first.workspace,
        Arc::clone(&record),
        first.seal(),
    )
    .unwrap();
    drop(first_store);
    assert!(matches!(
        open_store_with_record(&second.platform, &second.workspace, record, second.seal()),
        Err(RegistryAnchorError::AuthenticationFailed)
    ));
}

#[test]
fn initialization_rejects_missing_mixed_and_pending_owner_artifact_sets() {
    for pending in [
        "contract218.keyring.pending",
        "contract218.roles.pending",
        "contract218.migration-marker.pending",
    ] {
        let fixture = Fixture::new();
        let store = fixture.store();
        let genesis = tuple(0, 1);
        store
            .install_minimal_artifacts_for_test(&genesis, 1)
            .unwrap();
        fs::write(fixture.platform.join(pending), b"unnamed pending world").unwrap();
        let witness = VerifiedEmptyRegistryGenesis::fixture_for_test(
            genesis,
            &fixture.workspace,
            &fixture.registry,
        )
        .unwrap();
        assert!(matches!(
            store.initialize_compact(witness),
            Err(RegistryAnchorError::RecoveryRequired(_))
        ));
    }

    let fixture = Fixture::new();
    let store = fixture.store();
    let genesis = tuple(0, 1);
    store
        .install_minimal_artifacts_for_test(&genesis, 1)
        .unwrap();
    fs::remove_file(fixture.platform.join("contract218.keyring.current")).unwrap();
    let witness = VerifiedEmptyRegistryGenesis::fixture_for_test(
        genesis,
        &fixture.workspace,
        &fixture.registry,
    )
    .unwrap();
    assert!(matches!(
        store.initialize_compact(witness),
        Err(RegistryAnchorError::RecoveryRequired(_))
    ));

    let fixture = Fixture::new();
    let store = fixture.store();
    let genesis = tuple(0, 1);
    store
        .install_minimal_artifacts_for_test(&genesis, 1)
        .unwrap();
    let mut mixed = minimal_artifact(0x52);
    mixed[1..5].copy_from_slice(&2u32.to_be_bytes());
    fs::write(fixture.platform.join("contract218.roles.current"), mixed).unwrap();
    let witness = VerifiedEmptyRegistryGenesis::fixture_for_test(
        genesis,
        &fixture.workspace,
        &fixture.registry,
    )
    .unwrap();
    assert!(matches!(
        store.initialize_compact(witness),
        Err(RegistryAnchorError::AuthenticationFailed)
    ));
}

#[test]
fn optional_complete_298_marker_is_inside_selected_artifact_set_on_restart() {
    let fixture = Fixture::new();
    let store = fixture.store();
    let mut migrated = tuple(0, 1);
    let mut block = [0u8; 228];
    block[..16].copy_from_slice(&[0x10; 16]);
    block[16..32].copy_from_slice(&migrated.registry_instance);
    block[32..64].copy_from_slice(&[0x20; 32]);
    block[64..96].copy_from_slice(&[0x21; 32]);
    block[96..100].copy_from_slice(&1u32.to_be_bytes());
    block[100..132].copy_from_slice(&migrated.state_root);
    block[132..164].copy_from_slice(&migrated.keyring_root);
    block[164..196].copy_from_slice(&migrated.role_allocation_root);
    block[196..228].copy_from_slice(&[0x22; 32]);
    migrated.migration_digest =
        advance_scheduler::observation_anchor::legacy_registry_migration_digest(&block);
    store
        .install_minimal_artifacts_for_test(&migrated, 1)
        .unwrap();
    fs::write(
        fixture
            .platform
            .join("contract218.migration-marker.current"),
        authenticated_complete_marker(block),
    )
    .unwrap();
    store
        .initialize_compact_at_generation_for_test(&migrated, 1)
        .unwrap();
    drop(store);
    let reopened = fixture.store();
    assert_compact(reopened.observe().unwrap(), &migrated);
}

#[test]
fn complete_manifest_epoch_rotation_is_one_full_artifact_set() {
    let fixture = Fixture::new();
    let store = fixture.store();
    let previous = tuple(0, 1);
    fixture.initialize(&store, &previous);
    let next_keyring = {
        let mut bytes = minimal_artifact(0x4b);
        bytes[1..5].copy_from_slice(&2u32.to_be_bytes());
        bytes
    };
    let next_roles = {
        let mut bytes = minimal_artifact(0x52);
        bytes[1..5].copy_from_slice(&2u32.to_be_bytes());
        bytes
    };
    fs::write(
        fixture.platform.join("contract218.keyring.pending"),
        &next_keyring,
    )
    .unwrap();
    fs::write(
        fixture.platform.join("contract218.roles.pending"),
        &next_roles,
    )
    .unwrap();
    let context = RegistryHeadContext {
        previous_marker_root: greenfield_marker_root(),
        next_marker_root: greenfield_marker_root(),
        manifest_key_epoch: 1,
        next_manifest_key_epoch: 2,
    };
    let mut next = previous.clone();
    next.sequence = 1;
    next.keyring_root =
        advance_scheduler::observation_anchor::persisted_keyring_file_root(&next_keyring);
    next.role_allocation_root =
        advance_scheduler::observation_anchor::role_allocation_file_root(&next_roles);
    let write_set = [0x81; 32];
    next.head = [0; 32];
    let mutation = RegistryAnchorMutation::fixture_for_test(
        &store,
        previous,
        next.clone(),
        context,
        6,
        write_set,
    )
    .unwrap();
    let next = mutation.next().clone();
    store.set_failpoint_for_test(AnchorFailpoint::AfterSelectorFsync);
    assert!(matches!(
        store.prepare_current(mutation),
        Err(RegistryAnchorError::Unavailable(_))
    ));
    assert!(matches!(
        store.observe().unwrap(),
        RegistryAnchorWorld::PendingCurrent { .. }
    ));
    drop(store);
    let reopened = fixture.store();
    assert!(matches!(
        reopened.observe().unwrap(),
        RegistryAnchorWorld::PendingCurrent { .. }
    ));
    recover_exact(&reopened, &next).unwrap();
    assert_compact(reopened.observe().unwrap(), &next);
}

#[test]
fn selector_key_rotation_verifies_old_then_retires_after_new_selector() {
    let fixture = Fixture::new();
    let genesis = tuple(0, 1);
    {
        let store = fixture.store();
        fixture.initialize(&store, &genesis);
    }
    let rotated = Arc::new(
        HmacPlatformAnchorSeal::consume_platform_key(8, Zeroizing::new([0xa8; 32]))
            .unwrap()
            .retain_verify_only_key(7, Zeroizing::new([0xa5; 32]))
            .unwrap(),
    );
    let store = open_test_store(&fixture.platform, &fixture.workspace, rotated).unwrap();
    assert_compact(store.observe().unwrap(), &genesis);
    let transition = mutation(&store, &genesis, &tuple(1, 2));
    let next = transition.next().clone();
    let proof = database_commit_proof(&store, &transition);
    let prepared = store.prepare_current(transition).unwrap();
    let committed = prepared.database_committed(proof).unwrap();
    committed.select_next().unwrap().compact().unwrap();
    drop(store);

    let epoch8_only = Arc::new(
        HmacPlatformAnchorSeal::consume_platform_key(8, Zeroizing::new([0xa8; 32])).unwrap(),
    );
    let reopened = open_test_store(&fixture.platform, &fixture.workspace, epoch8_only).unwrap();
    assert_compact(reopened.observe().unwrap(), &next);
}

#[test]
fn second_custody_acquire_rejects() {
    let fixture = Fixture::new();
    let first = fixture.store();
    let second = open_test_store(&fixture.platform, &fixture.workspace, fixture.seal());
    assert!(matches!(
        second,
        Err(RegistryAnchorError::RecoveryRequired(_))
    ));
    drop(first);
    assert!(open_test_store(&fixture.platform, &fixture.workspace, fixture.seal()).is_ok());
}

#[test]
fn cross_process_custody_child_helper() {
    let Ok(platform) = std::env::var("ADVANCE_C218_CHILD_PLATFORM") else {
        return;
    };
    let workspace = std::env::var("ADVANCE_C218_CHILD_WORKSPACE").unwrap();
    let ready = PathBuf::from(std::env::var("ADVANCE_C218_CHILD_READY").unwrap());
    let release = PathBuf::from(std::env::var("ADVANCE_C218_CHILD_RELEASE").unwrap());
    let seal = Arc::new(
        HmacPlatformAnchorSeal::consume_platform_key(7, Zeroizing::new([0xA5; 32])).unwrap(),
    );
    let _store = open_test_store(platform, workspace, seal).unwrap();
    fs::write(&ready, b"ready").unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    while !release.exists() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    assert!(
        release.exists(),
        "parent did not release child custody in time"
    );
}

#[test]
fn second_process_custody_acquire_rejects_same_workspace() {
    let fixture = Fixture::new();
    let ready = fixture._root.path().join("custody-child.ready");
    let release = fixture._root.path().join("custody-child.release");
    let alternate_platform = fixture._root.path().join("platform-anchor-alternate");
    let mut child = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("cross_process_custody_child_helper")
        .arg("--test-threads=1")
        .env("ADVANCE_C218_CHILD_PLATFORM", &fixture.platform)
        .env("ADVANCE_C218_CHILD_WORKSPACE", &fixture.workspace)
        .env("ADVANCE_C218_CHILD_READY", &ready)
        .env("ADVANCE_C218_CHILD_RELEASE", &release)
        .spawn()
        .unwrap();

    let deadline = Instant::now() + Duration::from_secs(10);
    while !ready.exists() && Instant::now() < deadline {
        assert!(
            child.try_wait().unwrap().is_none(),
            "custody child exited early"
        );
        thread::sleep(Duration::from_millis(10));
    }
    if !ready.exists() {
        let _ = child.kill();
        let _ = child.wait();
        panic!("custody child did not acquire the OS lock");
    }

    let same_platform = open_test_store(&fixture.platform, &fixture.workspace, fixture.seal());
    let alternate_platform_same_workspace =
        open_test_store(&alternate_platform, &fixture.workspace, fixture.seal());
    fs::write(&release, b"release").unwrap();
    let status = child.wait().unwrap();

    assert!(status.success());
    assert!(matches!(
        same_platform,
        Err(RegistryAnchorError::RecoveryRequired(_))
    ));
    assert!(matches!(
        alternate_platform_same_workspace,
        Err(RegistryAnchorError::RecoveryRequired(_))
    ));
}

#[test]
fn same_workspace_different_platform_directories_reject() {
    let fixture = Fixture::new();
    let first = fixture.store();
    let alternate_platform = fixture._root.path().join("platform-anchor-alternate");

    let second = open_test_store(&alternate_platform, &fixture.workspace, fixture.seal());
    assert!(matches!(
        second,
        Err(RegistryAnchorError::RecoveryRequired(_))
    ));
    assert!(
        !fixture.workspace.join("contract218.custody.lock").exists(),
        "workspace custody must lock the canonical directory without creating snapshot artifacts"
    );

    drop(first);
    assert!(open_test_store(&alternate_platform, &fixture.workspace, fixture.seal()).is_ok());
}

#[test]
fn active_manifest_round_trip() {
    let fixture = Fixture::new();
    let (anchor, roles, genesis) = initialize_roles_and_anchor(&fixture);
    let boot = [0xB1; 16];
    let mut prepared = roles
        .prepare_create_once(boot, 1, unchanged_head_context())
        .unwrap();
    assert_eq!(prepared.anchor_previous(), &genesis);
    let expected_next = prepared.anchor_next().clone();
    let anchor_preparation = prepared.take_anchor_preparation().unwrap();
    let next = anchor_role_update(&anchor, anchor_preparation);
    assert_eq!(next, expected_next);
    let opened = prepared.commit_anchored(&next).unwrap();
    assert_eq!(opened.memory_protection(), MemoryProtection::Unsupported);
    drop(opened);

    let dependency =
        RetainedRoleDependencyReceipt::fixture_for_test(&next, boot, 1, next.sequence).unwrap();
    let reopened = roles
        .open_for_recovery(boot, 1, Some(dependency), &next)
        .unwrap();
    assert_eq!(reopened.memory_protection(), MemoryProtection::Unsupported);
}

#[test]
fn role_manifest_mac_nonce_root_and_phase_tamper_reject() {
    enum Tamper {
        Mac,
        Nonce,
        Root,
        Phase,
    }

    for tamper in [Tamper::Mac, Tamper::Nonce, Tamper::Root, Tamper::Phase] {
        let fixture = Fixture::new();
        let (anchor, roles, _) = initialize_roles_and_anchor(&fixture);
        let mut prepared = roles
            .prepare_create_once([0xD1; 16], 1, unchanged_head_context())
            .unwrap();
        let scheduler = prepared.take_anchor_preparation().unwrap();
        let current_path = fixture.platform.join("contract218.roles.current");
        let pending_path = fixture.platform.join("contract218.roles.pending");
        match tamper {
            Tamper::Mac => {
                let mut bytes = fs::read(&pending_path).unwrap();
                let last = bytes.len() - 1;
                bytes[last] ^= 1;
                fs::write(&pending_path, bytes).unwrap();
            }
            Tamper::Nonce => {
                let mut bytes = fs::read(&pending_path).unwrap();
                let nonce = bytes.len() - 64;
                bytes[nonce] ^= 1;
                fs::write(&pending_path, bytes).unwrap();
            }
            Tamper::Root => {
                let mut bytes = fs::read(&current_path).unwrap();
                let last = bytes.len() - 1;
                bytes[last] ^= 1;
                fs::write(&current_path, bytes).unwrap();
            }
            Tamper::Phase => {
                let mut bytes = fs::read(&pending_path).unwrap();
                // Canonical first-entry tag: 41-byte header + 20-byte key +
                // 8-byte allocation sequence.
                bytes[69] = 0x7f;
                fs::write(&pending_path, bytes).unwrap();
            }
        }
        assert!(matches!(
            scheduler.prepare_external_anchor(&anchor),
            Err(RegistryAnchorError::AuthenticationFailed)
        ));
    }
}

#[test]
fn second_factory_split_recovery_without_row_and_early_erase_reject() {
    let fixture = Fixture::new();
    let (anchor, roles, _genesis) = initialize_roles_and_anchor(&fixture);
    assert!(matches!(
        FileContract218RoleRootCustody::from_anchor_store(&anchor, 1, Zeroizing::new([0x71; 32])),
        Err(RoleRootCustodyError::RecoveryRequired(_))
    ));

    // Dependency receipts bind to a non-zero durable scan high-water. Advance
    // the real anchor with an unrelated role while leaving `missing_boot`
    // absent from both exact role manifests.
    let mut unrelated = roles
        .prepare_create_once([0xD3; 16], 1, unchanged_head_context())
        .unwrap();
    let preparation = unrelated.take_anchor_preparation().unwrap();
    let active = anchor_role_update(&anchor, preparation);
    drop(unrelated.commit_anchored(&active).unwrap());

    let missing_boot = [0xD2; 16];
    let retained =
        RetainedRoleDependencyReceipt::fixture_for_test(&active, missing_boot, 1, active.sequence)
            .unwrap();
    assert!(matches!(
        roles.open_for_recovery(missing_boot, 1, Some(retained), &active),
        Err(RoleRootCustodyError::NotFound)
    ));

    let zero =
        ZeroRoleDependencyReceipt::fixture_for_test(&active, missing_boot, 1, active.sequence)
            .unwrap();
    assert!(matches!(
        roles.prepare_erase(
            missing_boot,
            1,
            zero,
            2,
            Zeroizing::new([0x72; 32]),
            unchanged_head_context(),
        ),
        Err(RoleRootCustodyError::NotFound)
    ));
}

#[test]
fn recovery_open_requires_retained_dependency() {
    let fixture = Fixture::new();
    let (anchor, roles, genesis) = initialize_roles_and_anchor(&fixture);
    let boot = [0xB2; 16];
    let mut prepared = roles
        .prepare_create_once(boot, 1, unchanged_head_context())
        .unwrap();
    assert_eq!(prepared.anchor_previous(), &genesis);
    let expected_next = prepared.anchor_next().clone();
    let anchor_preparation = prepared.take_anchor_preparation().unwrap();
    let next = anchor_role_update(&anchor, anchor_preparation);
    assert_eq!(next, expected_next);
    drop(prepared.commit_anchored(&next).unwrap());

    assert!(matches!(
        roles.open_for_recovery(boot, 1, None, &next),
        Err(RoleRootCustodyError::RetainedDependencyRequired)
    ));
    let wrong =
        RetainedRoleDependencyReceipt::fixture_for_test(&next, [0xC2; 16], 1, next.sequence)
            .unwrap();
    assert!(matches!(
        roles.open_for_recovery(boot, 1, Some(wrong), &next),
        Err(RoleRootCustodyError::RetainedDependencyRequired)
    ));
}

#[test]
fn standalone_manifest_epoch_rewrap_is_rejected_as_mixed_artifact_set() {
    let fixture = Fixture::new();
    let (anchor, roles, genesis) = initialize_roles_and_anchor(&fixture);
    let boot = [0xB3; 16];
    let mut create = roles
        .prepare_create_once(boot, 1, unchanged_head_context())
        .unwrap();
    assert_eq!(create.anchor_previous(), &genesis);
    let expected_active = create.anchor_next().clone();
    let create_anchor = create.take_anchor_preparation().unwrap();
    let active_tuple = anchor_role_update(&anchor, create_anchor);
    assert_eq!(active_tuple, expected_active);
    drop(create.commit_anchored(&active_tuple).unwrap());

    assert!(matches!(
        roles.prepare_rewrap(2, Zeroizing::new([0x72; 32]), unchanged_head_context()),
        Err(RoleRootCustodyError::RecoveryRequired(_))
    ));
    assert_compact(anchor.observe().unwrap(), &active_tuple);
    assert_eq!(roles.retained_key_epochs_for_test(), vec![1]);
    roles.recover_against(&active_tuple).unwrap();
    assert_eq!(roles.retained_key_epochs_for_test(), vec![1]);
    assert!(!fixture.platform.join("contract218.roles.pending").exists());
}

#[test]
fn rewrap_rejects_nonadvancing_and_duplicate_epochs_without_key_mutation() {
    let fixture = Fixture::new();
    let anchor = fixture.store();
    let roles = FileContract218RoleRootCustody::from_anchor_store_with_keys(
        &anchor,
        vec![
            (1, Zeroizing::new([0x71; 32])),
            (2, Zeroizing::new([0x72; 32])),
        ],
        Arc::new(advance_cli::contract218_roles::UnsupportedMemoryCustody),
    )
    .unwrap();
    let root = roles.initialize_empty([0x11; 16], 1).unwrap();
    let mut genesis = tuple(0, 1);
    genesis.role_allocation_root = root.into_bytes();
    fixture.initialize(&anchor, &genesis);

    assert!(matches!(
        roles.prepare_rewrap(1, Zeroizing::new([0x91; 32]), unchanged_head_context()),
        Err(RoleRootCustodyError::Invalid(_))
    ));
    assert!(matches!(
        roles.prepare_rewrap(2, Zeroizing::new([0x92; 32]), unchanged_head_context()),
        Err(RoleRootCustodyError::Invalid(_))
    ));
    assert!(roles.wrapping_key_matches_for_test(1, &[0x71; 32]));
    assert!(roles.wrapping_key_matches_for_test(2, &[0x72; 32]));
    assert!(!fixture.platform.join("contract218.roles.pending").exists());
}

#[test]
fn erase_requires_zero_dependency_scan() {
    let fixture = Fixture::new();
    let (anchor, roles, genesis) = initialize_roles_and_anchor(&fixture);
    let boot = [0xB4; 16];
    let mut create = roles
        .prepare_create_once(boot, 1, unchanged_head_context())
        .unwrap();
    assert_eq!(create.anchor_previous(), &genesis);
    let expected_active = create.anchor_next().clone();
    let create_anchor = create.take_anchor_preparation().unwrap();
    let active_tuple = anchor_role_update(&anchor, create_anchor);
    assert_eq!(active_tuple, expected_active);
    drop(create.commit_anchored(&active_tuple).unwrap());

    // `fixture_for_test` is deliberately the only consumer-side construction
    // seam and is absent without scheduler `test-support`.  Even that fixture
    // cannot be rebound to a different boot after issuance.
    let wrong_boot_receipt = ZeroRoleDependencyReceipt::fixture_for_test(
        &active_tuple,
        [0xC4; 16],
        1,
        active_tuple.sequence,
    )
    .unwrap();
    assert_eq!(
        format!("{wrong_boot_receipt:?}"),
        "ZeroRoleDependencyReceipt(<opaque>)"
    );
    assert!(matches!(
        roles.prepare_erase(
            boot,
            1,
            wrong_boot_receipt,
            2,
            Zeroizing::new([0x73; 32]),
            unchanged_head_context(),
        ),
        Err(RoleRootCustodyError::DependenciesRemain)
    ));

    let receipt =
        ZeroRoleDependencyReceipt::fixture_for_test(&active_tuple, boot, 1, active_tuple.sequence)
            .unwrap();
    assert!(matches!(
        roles.prepare_erase(
            boot,
            1,
            receipt,
            2,
            Zeroizing::new([0x73; 32]),
            unchanged_head_context(),
        ),
        Err(RoleRootCustodyError::RecoveryRequired(_))
    ));
    assert_compact(anchor.observe().unwrap(), &active_tuple);
    roles.recover_against(&active_tuple).unwrap();
    assert!(!roles.allocation_is_erased_for_test(boot, 1).unwrap());
    assert_eq!(roles.retained_key_epochs_for_test(), vec![1]);
}

#[test]
fn erased_manifest_tombstone_never_reuses_sequence() {
    let fixture = Fixture::new();
    let (anchor, roles, genesis) = initialize_roles_and_anchor(&fixture);
    let boot = [0xB5; 16];
    let mut create = roles
        .prepare_create_once(boot, 1, unchanged_head_context())
        .unwrap();
    assert_eq!(create.anchor_previous(), &genesis);
    let expected_active = create.anchor_next().clone();
    let create_anchor = create.take_anchor_preparation().unwrap();
    let active_tuple = anchor_role_update(&anchor, create_anchor);
    assert_eq!(active_tuple, expected_active);
    drop(create.commit_anchored(&active_tuple).unwrap());
    let receipt =
        ZeroRoleDependencyReceipt::fixture_for_test(&active_tuple, boot, 1, active_tuple.sequence)
            .unwrap();
    assert!(matches!(
        roles.prepare_erase(
            boot,
            1,
            receipt,
            2,
            Zeroizing::new([0x74; 32]),
            unchanged_head_context(),
        ),
        Err(RoleRootCustodyError::RecoveryRequired(_))
    ));
    roles.recover_against(&active_tuple).unwrap();

    assert!(matches!(
        roles.prepare_create_once(boot, 1, unchanged_head_context()),
        Err(RoleRootCustodyError::AlreadyAllocated)
    ));
}

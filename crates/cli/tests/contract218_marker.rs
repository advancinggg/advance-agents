use advance_cli::contract218_anchor::{
    FilePlatformMonotonicAnchorStore, FileTestPlatformMonotonicRecord, HmacPlatformAnchorSeal,
    HmacRegistryManifestSeal,
};
use advance_cli::contract218_keyring::FilePersistedIdentityKeyringCustody;
use advance_cli::contract218_marker::{
    test_only_marker_file_exists, FileLegacyMigrationMarkerCustody, LegacyMigrationMarkerError,
    LegacyMigrationMarkerFailpoint, LegacyMigrationMarkerPhase, LegacyMigrationMarkerRecovery,
    LegacyMigrationOperatorAuthority,
};
use advance_cli::contract218_roles::FileContract218RoleRootCustody;
use advance_scheduler::observation_anchor::{
    registry_marker_root, PreparedCurrent, PreparedLegacyRegistryMigration, RegistryAnchorError,
    RegistryAnchorMutation, RegistryAnchorTransaction, RegistryAnchorTuple, RegistryAnchorWorld,
    RegistryRecoveryCapability, VerifiedEmptyRegistryGenesis,
};
use advance_scheduler::registry::ComponentRegistry;
use advance_scheduler::sensitive_params::{
    legacy_migration_block_fixture_for_test, CarrierMigrationRecoveryPhase,
    InstalledCarrierMigrationCoordinator, ObservationProviderConfig, PersistedKeyringCustody,
    RegistrySensitiveParamProvider, VerifiedLegacyAnchorInstalled,
    VerifiedLegacyMarkerTransitionCommitted,
};
use advance_scheduler::types::ComponentSubmitConfig;
use advance_shared_types::component::ComponentType;
use advance_shared_types::test_support::{
    contract218_roles, persisted_identity_keyring_role_for_binding,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rusqlite::params;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use subtle::ConstantTimeEq;
use tempfile::TempDir;
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

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

#[cfg(unix)]
fn create_fifo(path: &std::path::Path) {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let path = CString::new(path.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
}

struct ForeignLeaseAnchor;

impl RegistryAnchorTransaction for ForeignLeaseAnchor {
    fn observe(&self) -> Result<RegistryAnchorWorld, RegistryAnchorError> {
        Err(RegistryAnchorError::Uninitialized)
    }

    fn anchor_lease_tag(&self, _challenge: [u8; 32]) -> Result<[u8; 32], RegistryAnchorError> {
        Ok([0xd7; 32])
    }

    fn initialize_compact(
        &self,
        _genesis: VerifiedEmptyRegistryGenesis,
    ) -> Result<(), RegistryAnchorError> {
        Err(RegistryAnchorError::Unavailable(
            "foreign fixture".to_owned(),
        ))
    }

    fn prepare_current(
        &self,
        _mutation: RegistryAnchorMutation,
    ) -> Result<Box<dyn PreparedCurrent>, RegistryAnchorError> {
        Err(RegistryAnchorError::Unavailable(
            "foreign fixture".to_owned(),
        ))
    }

    fn recover(&self, _capability: RegistryRecoveryCapability) -> Result<(), RegistryAnchorError> {
        Err(RegistryAnchorError::Unavailable(
            "foreign fixture".to_owned(),
        ))
    }
}

struct Fixture {
    _root: TempDir,
    workspace: PathBuf,
    platform: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let workspace = root.path().join("workspace");
        let platform = root.path().join("platform");
        fs::create_dir_all(workspace.join(".runtime")).unwrap();
        fs::create_dir_all(&platform).unwrap();
        fs::write(
            workspace.join(".runtime/runtime.lock"),
            b"exclusive test lock",
        )
        .unwrap();
        Self {
            _root: root,
            workspace,
            platform,
        }
    }

    fn anchor(&self) -> FilePlatformMonotonicAnchorStore {
        let seal = Arc::new(
            HmacPlatformAnchorSeal::consume_platform_key(9, Zeroizing::new([0xA5; 32])).unwrap(),
        );
        let record = Arc::new(
            FileTestPlatformMonotonicRecord::open_for_test(
                self.platform.join("contract218.platform-record.test-only"),
            )
            .unwrap(),
        );
        let manifest = Arc::new(
            HmacRegistryManifestSeal::consume_host_master_keys(vec![(
                1,
                Zeroizing::new([0x71; 32]),
            )])
            .unwrap(),
        );
        FilePlatformMonotonicAnchorStore::acquire(
            &self.platform,
            &self.workspace,
            record,
            seal,
            manifest,
        )
        .unwrap()
    }
}

struct TestAuthority {
    workspace: PathBuf,
    operator: [u8; 32],
}

impl LegacyMigrationOperatorAuthority for TestAuthority {
    fn verify_exclusive_runtime_and_operator(
        &self,
        workspace_root: &Path,
        registry_instance: [u8; 16],
        operator_principal_digest: [u8; 32],
    ) -> Result<(), String> {
        if workspace_root == self.workspace
            && workspace_root.join(".runtime/runtime.lock").is_file()
            && registry_instance == [0x11; 16]
            && operator_principal_digest == self.operator
        {
            Ok(())
        } else {
            Err("runtime/operator binding mismatch".to_owned())
        }
    }
}

struct Initialized {
    fixture: Fixture,
    anchor: FilePlatformMonotonicAnchorStore,
    keyring: FilePersistedIdentityKeyringCustody,
    roles: FileContract218RoleRootCustody,
    marker: FileLegacyMigrationMarkerCustody,
    block: [u8; 228],
}

fn test_authority(fixture: &Fixture) -> Arc<dyn LegacyMigrationOperatorAuthority> {
    Arc::new(TestAuthority {
        workspace: fs::canonicalize(&fixture.workspace).unwrap(),
        operator: [0x24; 32],
    })
}

fn open_marker(
    fixture: &Fixture,
    anchor: &FilePlatformMonotonicAnchorStore,
    keyring: &FilePersistedIdentityKeyringCustody,
    roles: &FileContract218RoleRootCustody,
) -> FileLegacyMigrationMarkerCustody {
    FileLegacyMigrationMarkerCustody::from_anchor_store(
        anchor,
        keyring,
        roles,
        test_authority(fixture),
    )
    .unwrap()
}

fn initialized() -> Initialized {
    let fixture = Fixture::new();
    let anchor = fixture.anchor();
    let keyring = FilePersistedIdentityKeyringCustody::from_anchor_store(
        &anchor,
        vec![(1, Zeroizing::new([0x71; 32]))],
    )
    .unwrap();
    let roles =
        FileContract218RoleRootCustody::from_anchor_store(&anchor, 1, Zeroizing::new([0x71; 32]))
            .unwrap();
    let keyring_root = keyring
        .initialize_genesis([0x11; 16], 1, 1)
        .unwrap()
        .into_bytes();
    let role_root = roles.initialize_empty([0x11; 16], 1).unwrap().into_bytes();
    let mut block = [0_u8; 228];
    block[0..16].copy_from_slice(&[0x10; 16]);
    block[16..32].copy_from_slice(&[0x11; 16]);
    block[32..64].copy_from_slice(&[0x21; 32]);
    block[64..96].copy_from_slice(&[0x22; 32]);
    block[96..100].copy_from_slice(&1_u32.to_be_bytes());
    block[100..132].copy_from_slice(&[0x23; 32]);
    block[132..164].copy_from_slice(&keyring_root);
    block[164..196].copy_from_slice(&role_root);
    block[196..228].copy_from_slice(&[0x24; 32]);
    let marker = open_marker(&fixture, &anchor, &keyring, &roles);
    Initialized {
        fixture,
        anchor,
        keyring,
        roles,
        marker,
        block,
    }
}

fn migration_target_tuple(artifacts: &PreparedLegacyRegistryMigration) -> RegistryAnchorTuple {
    let mut head = Sha256::new();
    head.update(b"advance.contract218.registry-genesis.v1\0");
    head.update(artifacts.registry_instance());
    head.update(artifacts.target_state_root());
    head.update(artifacts.target_keyring_root());
    head.update(artifacts.target_role_allocation_root());
    head.update(artifacts.migration_digest());
    RegistryAnchorTuple {
        registry_instance: artifacts.registry_instance(),
        sequence: 0,
        head: head.finalize().into(),
        state_root: artifacts.target_state_root(),
        keyring_root: artifacts.target_keyring_root(),
        role_allocation_root: artifacts.target_role_allocation_root(),
        migration_digest: artifacts.migration_digest(),
    }
}

fn install_prepared_target_anchor(
    setup: &Initialized,
    artifacts: &PreparedLegacyRegistryMigration,
) -> RegistryAnchorTuple {
    let target = migration_target_tuple(artifacts);
    setup
        .anchor
        .initialize_compact_at_generation_for_test(&target, 1)
        .unwrap();
    target
}

fn create_exact_legacy_database(path: &Path) {
    let connection = rusqlite::Connection::open(path).unwrap();
    connection
        .execute_batch(
            "CREATE TABLE components (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                id TEXT NOT NULL UNIQUE,
                component_type TEXT NOT NULL,
                submit_config_json TEXT NOT NULL,
                submitter TEXT NOT NULL,
                submitted_at_ms INTEGER NOT NULL,
                interval_ms INTEGER,
                expected_next_fire_at_ms INTEGER,
                last_fire_at_ms INTEGER
             );",
        )
        .unwrap();
    let source = ComponentSubmitConfig {
        id: "legacy-component".to_owned(),
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
        sensitive_params: vec!["api_key".to_owned(), "token".to_owned()],
    };
    let source_json = serde_json::to_string(&source).unwrap();
    connection
        .execute(
            "INSERT INTO components
               (id,component_type,submit_config_json,submitter,submitted_at_ms,
                interval_ms,expected_next_fire_at_ms,last_fire_at_ms)
             VALUES (?1,'task',?2,'legacy-owner',123,NULL,NULL,NULL)",
            params!["legacy-component", source_json],
        )
        .unwrap();
}

fn carrier_fixture_migration_id(seed: u64) -> [u8; 16] {
    let mut digest = Sha256::new();
    digest.update(b"advance.contract218.carrier-migration-test-fixture.v1\0");
    digest.update(seed.to_be_bytes());
    digest.update(9_u64.to_be_bytes());
    digest.update(b"migration");
    digest.update(0_u64.to_be_bytes());
    digest.finalize()[..16].try_into().unwrap()
}

#[test]
fn exact_228_block_and_298_marker_flow_into_scheduler_opaque_artifact() {
    let setup = initialized();
    let mut plan = setup.marker.initialize_prepared(setup.block, 1).unwrap();
    assert_eq!(
        setup.marker.current_phase().unwrap(),
        LegacyMigrationMarkerPhase::Prepared
    );
    let artifacts = plan.take_scheduler_artifacts().unwrap();
    assert_eq!(artifacts.registry_instance(), [0x11; 16]);
    assert_eq!(artifacts.migration_id(), [0x10; 16]);
    assert_eq!(artifacts.target_state_root(), [0x23; 32]);
    assert_eq!(artifacts.prepared_marker_bytes().len(), 298);
    assert_eq!(artifacts.installed_marker_bytes().len(), 298);
    assert_eq!(artifacts.complete_marker_bytes().len(), 298);
    assert_ne!(
        &artifacts.prepared_marker_bytes()[234..266],
        &artifacts.installed_marker_bytes()[234..266]
    );
    assert_ne!(
        &artifacts.prepared_marker_bytes()[234..266],
        &artifacts.complete_marker_bytes()[234..266]
    );
    assert_ne!(
        &artifacts.installed_marker_bytes()[234..266],
        &artifacts.complete_marker_bytes()[234..266]
    );
    plan.promote_installed_for_test().unwrap();
    assert_eq!(
        setup.marker.current_phase().unwrap(),
        LegacyMigrationMarkerPhase::Installed
    );
    plan.promote_complete_for_test().unwrap();
    assert_eq!(
        setup.marker.current_phase().unwrap(),
        LegacyMigrationMarkerPhase::Complete
    );
    let retained = fs::read(
        setup
            .fixture
            .platform
            .join("contract218.migration-marker.current"),
    )
    .unwrap();
    assert_eq!(
        registry_marker_root(&retained).unwrap(),
        artifacts.complete_marker_root()
    );
}

#[test]
fn marker_commit_witness_rejects_stale_and_cross_anchor_lease() {
    let setup = initialized();
    let mut plan = setup.marker.initialize_prepared(setup.block, 1).unwrap();
    let artifacts = plan.take_scheduler_artifacts().unwrap();
    let previous = install_prepared_target_anchor(&setup, &artifacts);
    let installed = VerifiedLegacyAnchorInstalled::fixture_for_test(&artifacts);
    let staged = plan.stage_installed(installed).unwrap();

    assert_eq!(
        fs::read(
            setup
                .fixture
                .platform
                .join("contract218.migration-marker.current")
        )
        .unwrap(),
        artifacts.prepared_marker_bytes()
    );
    assert_eq!(
        fs::read(
            setup
                .fixture
                .platform
                .join("contract218.migration-marker.pending")
        )
        .unwrap(),
        artifacts.installed_marker_bytes()
    );
    let mut plausible_next = previous.clone();
    plausible_next.sequence = 1;
    plausible_next.head = [0x91; 32];
    let committed = VerifiedLegacyMarkerTransitionCommitted::installed_fixture_for_test(
        &setup.anchor,
        &artifacts,
        previous,
        plausible_next,
    )
    .unwrap();
    assert!(matches!(
        staged.finish_installed(committed),
        Err(LegacyMigrationMarkerError::Invalid(_))
    ));
    assert_eq!(
        fs::read(
            setup
                .fixture
                .platform
                .join("contract218.migration-marker.current")
        )
        .unwrap(),
        artifacts.prepared_marker_bytes()
    );

    let setup = initialized();
    let mut plan = setup.marker.initialize_prepared(setup.block, 1).unwrap();
    let artifacts = plan.take_scheduler_artifacts().unwrap();
    install_prepared_target_anchor(&setup, &artifacts);
    let installed = VerifiedLegacyAnchorInstalled::fixture_for_test(&artifacts);
    let mut staged = plan.stage_installed(installed).unwrap();
    let scheduler_transition = staged.take_scheduler_transition().unwrap();
    let previous = scheduler_transition.previous().clone();
    let next = scheduler_transition.next().clone();
    drop(scheduler_transition);
    let committed = VerifiedLegacyMarkerTransitionCommitted::installed_fixture_for_test(
        &setup.anchor,
        &artifacts,
        previous,
        next,
    )
    .unwrap();
    assert!(matches!(
        staged.finish_installed(committed),
        Err(LegacyMigrationMarkerError::AuthenticationFailed)
    ));
    assert_eq!(
        fs::read(
            setup
                .fixture
                .platform
                .join("contract218.migration-marker.current")
        )
        .unwrap(),
        artifacts.prepared_marker_bytes()
    );
    assert_eq!(
        fs::read(
            setup
                .fixture
                .platform
                .join("contract218.migration-marker.pending")
        )
        .unwrap(),
        artifacts.installed_marker_bytes()
    );
}

#[test]
fn marker_commit_witness_from_foreign_anchor_cannot_transfer_owner() {
    let setup = initialized();
    let mut plan = setup.marker.initialize_prepared(setup.block, 1).unwrap();
    let artifacts = plan.take_scheduler_artifacts().unwrap();
    install_prepared_target_anchor(&setup, &artifacts);
    let installed = VerifiedLegacyAnchorInstalled::fixture_for_test(&artifacts);
    let mut staged = plan.stage_installed(installed).unwrap();
    let scheduler_transition = staged.take_scheduler_transition().unwrap();
    let previous = scheduler_transition.previous().clone();
    let next = scheduler_transition.next().clone();
    drop(scheduler_transition);
    let foreign = ForeignLeaseAnchor;
    let committed = VerifiedLegacyMarkerTransitionCommitted::installed_fixture_for_test(
        &foreign, &artifacts, previous, next,
    )
    .unwrap();

    assert!(matches!(
        staged.finish_installed(committed),
        Err(LegacyMigrationMarkerError::AuthenticationFailed)
    ));
    assert_eq!(
        fs::read(
            setup
                .fixture
                .platform
                .join("contract218.migration-marker.current")
        )
        .unwrap(),
        artifacts.prepared_marker_bytes()
    );
    assert_eq!(
        fs::read(
            setup
                .fixture
                .platform
                .join("contract218.migration-marker.pending")
        )
        .unwrap(),
        artifacts.installed_marker_bytes()
    );
}

#[cfg(unix)]
#[test]
fn marker_custody_rejects_symlink_fifo_device_hardlink_and_temp_collisions() {
    use std::os::unix::fs::symlink;

    #[derive(Clone, Copy, Debug)]
    enum Attack {
        Symlink,
        Fifo,
        Hardlink,
        TempCollision,
    }

    let artifacts = [
        "contract218.migration-marker.current",
        "contract218.migration-marker.pending",
        "contract218.migration-marker.plan",
        ".contract218.migration-marker.current.tmp",
        ".contract218.migration-marker.pending.tmp",
        ".contract218.migration-marker.plan.tmp",
    ];
    for artifact in artifacts {
        assert!(
            test_only_marker_file_exists(Path::new("/dev/null")).is_err(),
            "accepted marker character device at {artifact}"
        );
        for attack in [
            Attack::Symlink,
            Attack::Fifo,
            Attack::Hardlink,
            Attack::TempCollision,
        ] {
            let setup = initialized();
            let leaf = setup.fixture.platform.join(artifact);
            let target = setup.fixture.workspace.join(format!(
                "outside-marker-{}-{attack:?}",
                artifact.replace('.', "_")
            ));
            match attack {
                Attack::Symlink => {
                    fs::write(&target, b"marker sentinel").unwrap();
                    symlink(&target, &leaf).unwrap();
                }
                Attack::Fifo => create_fifo(&leaf),
                Attack::Hardlink => {
                    fs::write(&target, b"marker sentinel").unwrap();
                    fs::hard_link(&target, &leaf).unwrap();
                }
                Attack::TempCollision => fs::create_dir(&leaf).unwrap(),
            }
            assert!(
                setup.marker.initialize_prepared(setup.block, 1).is_err(),
                "accepted marker {attack:?} at {artifact}"
            );
            if matches!(attack, Attack::Symlink | Attack::Hardlink) {
                assert_eq!(fs::read(&target).unwrap(), b"marker sentinel");
            }
        }
    }
}

#[test]
fn staged_installed_restart_reuses_exact_plan_for_scheduler_commit_recovery() {
    let Initialized {
        fixture,
        anchor,
        keyring,
        roles,
        marker,
        block,
    } = initialized();
    let mut plan = marker.initialize_prepared(block, 1).unwrap();
    let artifacts = plan.take_scheduler_artifacts().unwrap();
    let target = migration_target_tuple(&artifacts);
    anchor
        .initialize_compact_at_generation_for_test(&target, 1)
        .unwrap();
    let installed = VerifiedLegacyAnchorInstalled::fixture_for_test(&artifacts);
    let mut staged = plan.stage_installed(installed).unwrap();
    let scheduler_transition = staged.take_scheduler_transition().unwrap();
    let previous = scheduler_transition.previous().clone();
    let next = scheduler_transition.next().clone();
    drop(scheduler_transition);
    drop(staged);
    drop(marker);

    let marker = open_marker(&fixture, &anchor, &keyring, &roles);
    let recovery = marker.resume_staged_installed().unwrap();
    assert_eq!(
        recovery
            .scheduler_recovery_artifacts()
            .installed_marker_bytes(),
        artifacts.installed_marker_bytes()
    );
    assert_eq!(
        recovery
            .scheduler_recovery_artifacts()
            .complete_marker_bytes(),
        artifacts.complete_marker_bytes()
    );
    let installed =
        VerifiedLegacyAnchorInstalled::fixture_for_test(recovery.scheduler_recovery_artifacts());
    let mut restaged = recovery.restage_installed(installed).unwrap();
    let replay = restaged.take_scheduler_transition().unwrap();
    assert_eq!(replay.previous(), &previous);
    assert_eq!(replay.next(), &next);
    drop(replay);
    let committed = VerifiedLegacyMarkerTransitionCommitted::installed_fixture_for_test(
        &anchor, &artifacts, previous, next,
    )
    .unwrap();
    assert!(matches!(
        restaged.finish_installed(committed),
        Err(LegacyMigrationMarkerError::AuthenticationFailed)
    ));
    assert_eq!(
        fs::read(
            fixture
                .platform
                .join("contract218.migration-marker.current")
        )
        .unwrap(),
        artifacts.prepared_marker_bytes()
    );
    assert_eq!(
        fs::read(
            fixture
                .platform
                .join("contract218.migration-marker.pending")
        )
        .unwrap(),
        artifacts.installed_marker_bytes()
    );
}

#[test]
fn complete_commit_witness_cannot_finish_an_installed_transition() {
    let setup = initialized();
    let mut plan = setup.marker.initialize_prepared(setup.block, 1).unwrap();
    let artifacts = plan.take_scheduler_artifacts().unwrap();
    install_prepared_target_anchor(&setup, &artifacts);
    let installed = VerifiedLegacyAnchorInstalled::fixture_for_test(&artifacts);
    let mut staged = plan.stage_installed(installed).unwrap();
    let scheduler_transition = staged.take_scheduler_transition().unwrap();
    let previous = scheduler_transition.previous().clone();
    let next = scheduler_transition.next().clone();
    drop(scheduler_transition);
    let wrong_phase = VerifiedLegacyMarkerTransitionCommitted::complete_fixture_for_test(
        &setup.anchor,
        &artifacts,
        previous,
        next,
    )
    .unwrap();
    assert!(matches!(
        staged.finish_installed(wrong_phase),
        Err(LegacyMigrationMarkerError::AuthenticationFailed)
    ));
    assert_eq!(
        fs::read(
            setup
                .fixture
                .platform
                .join("contract218.migration-marker.current")
        )
        .unwrap(),
        artifacts.prepared_marker_bytes()
    );
    assert_eq!(
        fs::read(
            setup
                .fixture
                .platform
                .join("contract218.migration-marker.pending")
        )
        .unwrap(),
        artifacts.installed_marker_bytes()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn installed_restart_returns_only_move_only_carrier_coordinator() {
    const CARRIER_SEED: u64 = 0x218;
    let fixture = Fixture::new();
    let database_path = fixture.workspace.join("components.db");
    create_exact_legacy_database(&database_path);
    let registry = Arc::new(
        ComponentRegistry::open_in(&fixture.workspace, "components.db")
            .await
            .unwrap(),
    );

    let anchor = fixture.anchor();
    let keyring = FilePersistedIdentityKeyringCustody::from_anchor_store(
        &anchor,
        vec![(1, Zeroizing::new([0x71; 32]))],
    )
    .unwrap();
    let roles =
        FileContract218RoleRootCustody::from_anchor_store(&anchor, 1, Zeroizing::new([0x71; 32]))
            .unwrap();
    keyring.initialize_genesis([0x11; 16], 1, 1).unwrap();
    let role_root = roles.initialize_empty([0x11; 16], 1).unwrap().into_bytes();
    let initial_keyring_file =
        fs::read(fixture.platform.join("contract218.keyring.current")).unwrap();
    let block = legacy_migration_block_fixture_for_test(
        &database_path,
        carrier_fixture_migration_id(CARRIER_SEED),
        [0x11; 16],
        &initial_keyring_file,
        role_root,
        [0x24; 32],
    )
    .unwrap();
    let marker = open_marker(&fixture, &anchor, &keyring, &roles);
    let mut prepared_plan = marker.initialize_prepared(block, 1).unwrap();
    let artifacts = prepared_plan.take_scheduler_artifacts().unwrap();
    let prepared_bytes = artifacts.prepared_marker_bytes().to_vec();
    let installed_bytes = artifacts.installed_marker_bytes().to_vec();
    let complete_bytes = artifacts.complete_marker_bytes().to_vec();
    assert_eq!(
        fs::read(
            fixture
                .platform
                .join("contract218.migration-marker.current")
        )
        .unwrap(),
        prepared_bytes
    );

    let config = ObservationProviderConfig::authenticated_legacy_migration(
        [0x31; 16],
        &artifacts,
        initial_keyring_file,
    )
    .unwrap();
    let open_config = config.clone();
    let anchor_transaction: Arc<dyn RegistryAnchorTransaction> = Arc::new(anchor.clone());
    let anchor_installed = RegistrySensitiveParamProvider::migrate_legacy_registry(
        Arc::clone(&registry),
        Arc::clone(&anchor_transaction),
        config,
        artifacts.clone(),
    )
    .await
    .unwrap();
    assert_eq!(anchor_installed.verify_for(&artifacts).unwrap().sequence, 0);
    assert!(matches!(
        anchor.observe().unwrap(),
        RegistryAnchorWorld::CompactCurrent { current, .. } if current.sequence == 0
    ));
    assert_eq!(
        fs::read(
            fixture
                .platform
                .join("contract218.migration-marker.current")
        )
        .unwrap(),
        prepared_bytes,
        "anchor genesis must retain physical Prepared"
    );

    let mut staged_installed = prepared_plan.stage_installed(anchor_installed).unwrap();
    assert_eq!(
        fs::read(
            fixture
                .platform
                .join("contract218.migration-marker.current")
        )
        .unwrap(),
        prepared_bytes
    );
    assert_eq!(
        fs::read(
            fixture
                .platform
                .join("contract218.migration-marker.pending")
        )
        .unwrap(),
        installed_bytes
    );
    let installed_mutation = staged_installed.take_scheduler_transition().unwrap();
    let installed_committed = RegistrySensitiveParamProvider::commit_legacy_marker_transition(
        Arc::clone(&registry),
        Arc::clone(&anchor_transaction),
        &installed_mutation,
    )
    .await
    .unwrap();
    let retry_anchor_before = anchor.observe().unwrap();
    let retry_ledger_before: (i64, Vec<u8>, Vec<u8>) = rusqlite::Connection::open(&database_path)
        .unwrap()
        .query_row(
            "SELECT committed_sequence,committed_head_digest,committed_state_root
                 FROM observation_identity_ledger WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    RegistrySensitiveParamProvider::inject_next_marker_retry_schema_adversary(
        &registry, [0x11; 16],
    )
    .unwrap();
    let retry_error = RegistrySensitiveParamProvider::commit_legacy_marker_transition(
        Arc::clone(&registry),
        Arc::clone(&anchor_transaction),
        &installed_mutation,
    )
    .await
    .unwrap_err();
    assert!(matches!(
        retry_error,
        advance_scheduler::sensitive_params::ObservationProviderError::Registry(_)
            | advance_scheduler::sensitive_params::ObservationProviderError::RecoveryRequired(_)
    ));
    assert_eq!(anchor.observe().unwrap(), retry_anchor_before);
    let retry_inspection = rusqlite::Connection::open(&database_path).unwrap();
    let retry_ledger_after: (i64, Vec<u8>, Vec<u8>) = retry_inspection
        .query_row(
            "SELECT committed_sequence,committed_head_digest,committed_state_root
             FROM observation_identity_ledger WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    let injected_trigger_count: i64 = retry_inspection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master
             WHERE type='trigger' AND name='__test_marker_retry_schema_boundary_tamper'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(retry_ledger_after, retry_ledger_before);
    assert_eq!(injected_trigger_count, 0);
    assert!(matches!(
        anchor.observe().unwrap(),
        RegistryAnchorWorld::CompactCurrent { current, .. } if current.sequence == 1
    ));
    assert_eq!(
        fs::read(
            fixture
                .platform
                .join("contract218.migration-marker.current")
        )
        .unwrap(),
        prepared_bytes,
        "scheduler commit cannot rename the marker owner artifact"
    );
    assert_eq!(
        fs::read(
            fixture
                .platform
                .join("contract218.migration-marker.pending")
        )
        .unwrap(),
        installed_bytes
    );
    drop(installed_mutation);
    let installed_plan = staged_installed
        .finish_installed(installed_committed)
        .unwrap();
    assert_eq!(
        installed_plan.marker_root(),
        artifacts.installed_marker_root()
    );
    assert_eq!(
        fs::read(
            fixture
                .platform
                .join("contract218.migration-marker.current")
        )
        .unwrap(),
        installed_bytes
    );
    assert!(!fixture
        .platform
        .join("contract218.migration-marker.pending")
        .exists());

    // Restart at the exact Installed boundary. The durable plan must rebuild
    // byte-identically and cannot mint new Complete bytes or roots.
    drop(installed_plan);
    drop(marker);
    let marker = open_marker(&fixture, &anchor, &keyring, &roles);
    let installed_plan = marker.resume_installed().unwrap();
    assert_eq!(
        installed_plan.marker_root(),
        artifacts.installed_marker_root()
    );
    let (
        _rejected_issuer,
        mut rejected_verifier,
        rejected_termination,
        _rejected_cleanup_issuer,
        rejected_cleanup_verifier,
    ) = contract218_roles([0x11; 16], [0x31; 16], 1, [0x61; 32], [0x62; 32]).unwrap();
    let rejected_keyring = persisted_identity_keyring_role_for_binding(
        &mut rejected_verifier,
        [0x11; 16],
        artifacts.target_keyring_root(),
        0,
        1,
        [0x95; 32],
        [0x96; 32],
    )
    .unwrap();
    let rejected_keyring_custody: Arc<dyn PersistedKeyringCustody> = Arc::new(keyring.clone());
    let ordinary_open = RegistrySensitiveParamProvider::open(
        Arc::clone(&registry),
        Arc::clone(&anchor_transaction),
        open_config.clone(),
        rejected_verifier,
        rejected_keyring,
        rejected_keyring_custody,
        rejected_termination,
        rejected_cleanup_verifier,
    )
    .await;
    assert!(matches!(
        ordinary_open,
        Err(advance_scheduler::sensitive_params::ObservationProviderError::RecoveryRequired(
            ref message
        )) if message.contains("move-only carrier coordinator")
    ));

    let (
        _installed_issuer,
        mut installed_verifier,
        installed_termination,
        _installed_cleanup_issuer,
        installed_cleanup_verifier,
    ) = contract218_roles([0x11; 16], [0x31; 16], 1, [0x51; 32], [0x52; 32]).unwrap();
    let installed_keyring = persisted_identity_keyring_role_for_binding(
        &mut installed_verifier,
        [0x11; 16],
        artifacts.target_keyring_root(),
        0,
        1,
        [0x93; 32],
        [0x94; 32],
    )
    .unwrap();
    let installed_keyring_custody: Arc<dyn PersistedKeyringCustody> = Arc::new(keyring.clone());
    let installed_coordinator = InstalledCarrierMigrationCoordinator::open(
        Arc::clone(&registry),
        Arc::clone(&anchor_transaction),
        open_config.clone(),
        installed_verifier,
        installed_keyring,
        installed_keyring_custody,
        installed_termination,
        installed_cleanup_verifier,
    )
    .await
    .unwrap();
    // `InstalledLegacyMigrationPlan::stage_complete` requires the opaque
    // production completion witness, so there is no callable pre-ack staging
    // API. The remaining restart seam also fails: without a real carrier ack
    // there is no Complete pending state to recover or promote.
    let before_carrier = anchor.observe().unwrap();
    assert!(matches!(
        before_carrier,
        RegistryAnchorWorld::CompactCurrent { ref current, .. } if current.sequence == 1
    ));
    assert!(matches!(
        marker.resume_staged_complete(),
        Err(LegacyMigrationMarkerError::RecoveryRequired(_))
    ));
    assert_eq!(anchor.observe().unwrap(), before_carrier);
    assert_eq!(
        fs::read(
            fixture
                .platform
                .join("contract218.migration-marker.current")
        )
        .unwrap(),
        installed_bytes
    );
    assert!(!fixture
        .platform
        .join("contract218.migration-marker.pending")
        .exists());
    let carrier_fixture = installed_coordinator
        .carrier_migration_test_fixture(CARRIER_SEED, 0)
        .unwrap();
    let carrier_reservation = installed_coordinator
        .reserve_carrier_migration(&carrier_fixture.plan())
        .unwrap();
    assert_eq!(
        installed_coordinator
            .recover_carrier_migration(&carrier_reservation)
            .unwrap(),
        CarrierMigrationRecoveryPhase::Verified
    );
    let owner_finalized = carrier_fixture
        .owner_finalized(&carrier_reservation)
        .unwrap();
    let finalized_ack = installed_coordinator
        .verify_carrier_migration_owner_finalized(&carrier_reservation, &owner_finalized)
        .unwrap();
    let carrier_complete = tokio::task::block_in_place(|| {
        installed_coordinator.authorize_legacy_migration_completion(&artifacts, finalized_ack)
    })
    .unwrap();
    assert!(matches!(
        anchor.observe().unwrap(),
        RegistryAnchorWorld::CompactCurrent { current, .. } if current.sequence == 2
    ));
    assert_eq!(
        fs::read(
            fixture
                .platform
                .join("contract218.migration-marker.current")
        )
        .unwrap(),
        installed_bytes,
        "verified carrier completion must not bypass the Complete marker transition"
    );
    drop(registry);
    let registry = Arc::new(
        ComponentRegistry::open_in(&fixture.workspace, "components.db")
            .await
            .unwrap(),
    );

    let mut staged_complete = installed_plan.stage_complete(carrier_complete).unwrap();
    assert_eq!(
        fs::read(
            fixture
                .platform
                .join("contract218.migration-marker.current")
        )
        .unwrap(),
        installed_bytes
    );
    assert_eq!(
        fs::read(
            fixture
                .platform
                .join("contract218.migration-marker.pending")
        )
        .unwrap(),
        complete_bytes
    );
    let complete_mutation = staged_complete.take_scheduler_transition().unwrap();
    let complete_committed = RegistrySensitiveParamProvider::commit_legacy_marker_transition(
        Arc::clone(&registry),
        Arc::clone(&anchor_transaction),
        &complete_mutation,
    )
    .await
    .unwrap();
    assert!(matches!(
        anchor.observe().unwrap(),
        RegistryAnchorWorld::CompactCurrent { current, .. } if current.sequence == 3
    ));
    assert_eq!(
        fs::read(
            fixture
                .platform
                .join("contract218.migration-marker.current")
        )
        .unwrap(),
        installed_bytes,
        "Complete remains pending until its exact commit witness returns"
    );
    drop(complete_mutation);
    let complete_plan = staged_complete.finish_complete(complete_committed).unwrap();
    assert_eq!(
        complete_plan.marker_root(),
        artifacts.complete_marker_root()
    );
    assert_eq!(
        fs::read(
            fixture
                .platform
                .join("contract218.migration-marker.current")
        )
        .unwrap(),
        complete_bytes
    );
    assert!(!fixture
        .platform
        .join("contract218.migration-marker.pending")
        .exists());
    let durable_marker_root: Vec<u8> = rusqlite::Connection::open(&database_path)
        .unwrap()
        .query_row(
            "SELECT current_marker_root FROM observation_registry_head_context WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        durable_marker_root,
        artifacts.complete_marker_root(),
        "normal open must see Complete in the SQLite head context"
    );

    // A normal provider open (not a migration/recovery constructor) must now
    // accept the exact seq-3 ledger/anchor and physical Complete root.
    let (_issuer, mut verifier, termination, _cleanup_issuer, cleanup_verifier) =
        contract218_roles([0x11; 16], [0x31; 16], 1, [0x41; 32], [0x42; 32]).unwrap();
    let persisted_keyring = persisted_identity_keyring_role_for_binding(
        &mut verifier,
        [0x11; 16],
        artifacts.target_keyring_root(),
        0,
        1,
        [0x91; 32],
        [0x92; 32],
    )
    .unwrap();
    let keyring_custody: Arc<dyn PersistedKeyringCustody> = Arc::new(keyring.clone());
    let provider = RegistrySensitiveParamProvider::open(
        Arc::clone(&registry),
        anchor_transaction,
        open_config,
        verifier,
        persisted_keyring,
        keyring_custody,
        termination,
        cleanup_verifier,
    )
    .await
    .unwrap();
    assert!(provider.is_ready());
    assert_eq!(
        registry_marker_root(
            &fs::read(
                fixture
                    .platform
                    .join("contract218.migration-marker.current")
            )
            .unwrap()
        )
        .unwrap(),
        artifacts.complete_marker_root()
    );
}

#[test]
fn installed_marker_cannot_construct_normal_provider() {
    assert_not_impl!(InstalledCarrierMigrationCoordinator: Clone);
    assert_not_impl!(InstalledCarrierMigrationCoordinator: serde::Serialize);
    assert_not_impl!(InstalledCarrierMigrationCoordinator: serde::de::DeserializeOwned);
    assert_not_impl!(InstalledCarrierMigrationCoordinator: std::ops::Deref);
    assert_not_impl!(InstalledCarrierMigrationCoordinator: Into<RegistrySensitiveParamProvider>);
    assert_not_impl!(InstalledCarrierMigrationCoordinator: advance_shared_types::observation_identity::SensitiveParamCatalog);
    assert_not_impl!(InstalledCarrierMigrationCoordinator: advance_shared_types::observation_identity::ObservationIdentityAuthority);
    assert_not_impl!(InstalledCarrierMigrationCoordinator: advance_shared_types::observation_identity::AgentObservationIdentityRegistrar);
    assert_not_impl!(InstalledCarrierMigrationCoordinator: advance_shared_types::observation_identity::HostObservationIdentityRegistrar);
    assert_not_impl!(InstalledCarrierMigrationCoordinator: advance_shared_types::observation_identity::ComponentObservationSourceIssuer);
    assert_not_impl!(InstalledCarrierMigrationCoordinator: advance_shared_types::observation_identity::ObservationIdentityPersistenceSealer);
}

#[test]
fn exact_marker_mac_is_independently_verified() {
    let setup = initialized();
    let mut plan = setup.marker.initialize_prepared(setup.block, 1).unwrap();
    let artifacts = plan.take_scheduler_artifacts().unwrap();
    let marker = artifacts.prepared_marker_bytes();
    assert_eq!(marker.len(), 298);
    assert_eq!(marker[0], 1);
    assert_eq!(&marker[1..5], &1_u32.to_be_bytes());
    assert_eq!(&marker[5..233], &setup.block);
    assert_eq!(marker[233], LegacyMigrationMarkerPhase::Prepared as u8);
    assert_ne!(&marker[234..266], &[0; 32]);
    let mut info = b"advance.contract218.registry-migration-marker-key.v1\0".to_vec();
    info.extend_from_slice(&1_u32.to_be_bytes());
    let hkdf = Hkdf::<Sha256>::new(Some(&[0x11; 16]), &[0x71; 32]);
    let mut key = Zeroizing::new([0_u8; 32]);
    hkdf.expand(&info, key.as_mut()).unwrap();
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key.as_ref()).unwrap();
    mac.update(b"advance.contract218.registry-migration-marker.v1\0");
    mac.update(&marker[..266]);
    let expected: [u8; 32] = mac.finalize().into_bytes().into();
    assert_eq!(expected.ct_eq(&marker[266..]).unwrap_u8(), 1);
}

#[test]
fn pending_fsync_can_roll_back_or_forward_recover() {
    let setup = initialized();
    let plan = setup.marker.initialize_prepared(setup.block, 1).unwrap();
    setup
        .marker
        .set_failpoint_for_test(LegacyMigrationMarkerFailpoint::AfterPendingFsync);
    assert!(matches!(
        plan.promote_installed_for_test(),
        Err(LegacyMigrationMarkerError::Failpoint(
            LegacyMigrationMarkerFailpoint::AfterPendingFsync
        ))
    ));
    assert_eq!(
        setup
            .marker
            .recover_expected_phase(LegacyMigrationMarkerPhase::Prepared)
            .unwrap(),
        LegacyMigrationMarkerRecovery::RolledBackPending
    );

    setup
        .marker
        .set_failpoint_for_test(LegacyMigrationMarkerFailpoint::BeforePendingPromotion);
    assert!(matches!(
        plan.promote_installed_for_test(),
        Err(LegacyMigrationMarkerError::Failpoint(
            LegacyMigrationMarkerFailpoint::BeforePendingPromotion
        ))
    ));
    assert_eq!(
        setup
            .marker
            .recover_expected_phase(LegacyMigrationMarkerPhase::Installed)
            .unwrap(),
        LegacyMigrationMarkerRecovery::PromotedPending
    );
    plan.promote_complete_for_test().unwrap();
}

#[test]
fn torn_pending_temporary_rolls_back_only_to_current_phase() {
    let setup = initialized();
    let plan = setup.marker.initialize_prepared(setup.block, 1).unwrap();
    setup
        .marker
        .set_failpoint_for_test(LegacyMigrationMarkerFailpoint::AfterPendingTemporaryFsync);
    assert!(matches!(
        plan.promote_installed_for_test(),
        Err(LegacyMigrationMarkerError::Failpoint(
            LegacyMigrationMarkerFailpoint::AfterPendingTemporaryFsync
        ))
    ));
    assert!(matches!(
        setup
            .marker
            .recover_expected_phase(LegacyMigrationMarkerPhase::Installed),
        Err(LegacyMigrationMarkerError::RecoveryRequired(_))
    ));
    assert_eq!(
        setup
            .marker
            .recover_expected_phase(LegacyMigrationMarkerPhase::Prepared)
            .unwrap(),
        LegacyMigrationMarkerRecovery::RolledBackPending
    );
}

#[test]
fn resume_preserves_retained_installed_marker_and_finishes() {
    let setup = initialized();
    let plan = setup.marker.initialize_prepared(setup.block, 1).unwrap();
    plan.promote_installed_for_test().unwrap();
    drop(plan);
    let resumed = setup
        .marker
        .resume_plan(LegacyMigrationMarkerPhase::Installed)
        .unwrap();
    resumed.promote_complete_for_test().unwrap();
    assert_eq!(
        setup.marker.current_phase().unwrap(),
        LegacyMigrationMarkerPhase::Complete
    );
}

#[test]
fn crash_resume_preserves_original_installed_and_complete_bytes_and_roots() {
    let Initialized {
        fixture,
        anchor,
        keyring,
        roles,
        marker,
        block,
    } = initialized();
    let mut original_plan = marker.initialize_prepared(block, 1).unwrap();
    let original = original_plan.take_scheduler_artifacts().unwrap();
    let original_installed = original.installed_marker_bytes().to_vec();
    let original_complete = original.complete_marker_bytes().to_vec();
    let original_installed_root = registry_marker_root(&original_installed).unwrap();
    let original_complete_root = registry_marker_root(&original_complete).unwrap();

    marker.set_failpoint_for_test(LegacyMigrationMarkerFailpoint::AfterPendingFsync);
    assert!(matches!(
        original_plan.promote_installed_for_test(),
        Err(LegacyMigrationMarkerError::Failpoint(
            LegacyMigrationMarkerFailpoint::AfterPendingFsync
        ))
    ));
    drop(original_plan);
    drop(marker);

    let marker = open_marker(&fixture, &anchor, &keyring, &roles);
    let mut installed_plan = marker
        .resume_plan(LegacyMigrationMarkerPhase::Installed)
        .unwrap();
    let installed_resume = installed_plan.take_scheduler_artifacts().unwrap();
    assert_eq!(
        installed_resume.installed_marker_bytes(),
        original_installed
    );
    assert_eq!(installed_resume.complete_marker_bytes(), original_complete);
    assert_eq!(
        registry_marker_root(installed_resume.installed_marker_bytes()).unwrap(),
        original_installed_root
    );
    assert_eq!(
        installed_resume.complete_marker_root(),
        original_complete_root
    );

    marker.set_failpoint_for_test(LegacyMigrationMarkerFailpoint::AfterPendingFsync);
    assert!(matches!(
        installed_plan.promote_complete_for_test(),
        Err(LegacyMigrationMarkerError::Failpoint(
            LegacyMigrationMarkerFailpoint::AfterPendingFsync
        ))
    ));
    drop(installed_plan);
    drop(marker);

    let marker = open_marker(&fixture, &anchor, &keyring, &roles);
    let mut complete_plan = marker
        .resume_plan(LegacyMigrationMarkerPhase::Complete)
        .unwrap();
    let complete_resume = complete_plan.take_scheduler_artifacts().unwrap();
    assert_eq!(complete_resume.installed_marker_bytes(), original_installed);
    assert_eq!(complete_resume.complete_marker_bytes(), original_complete);
    assert_eq!(
        registry_marker_root(complete_resume.installed_marker_bytes()).unwrap(),
        original_installed_root
    );
    assert_eq!(
        complete_resume.complete_marker_root(),
        original_complete_root
    );
    assert_eq!(
        marker.current_phase().unwrap(),
        LegacyMigrationMarkerPhase::Complete
    );
}

#[test]
fn authenticated_phase_plan_tamper_rejects_fresh_resume() {
    let Initialized {
        fixture,
        anchor,
        keyring,
        roles,
        marker,
        block,
    } = initialized();
    let plan = marker.initialize_prepared(block, 1).unwrap();
    drop(plan);
    drop(marker);

    let path = fixture.platform.join("contract218.migration-marker.plan");
    let mut bytes = fs::read(&path).unwrap();
    bytes[1 + (2 * 298) + 234] ^= 1;
    fs::write(path, bytes).unwrap();
    assert!(matches!(
        FileLegacyMigrationMarkerCustody::from_anchor_store(
            &anchor,
            &keyring,
            &roles,
            test_authority(&fixture),
        ),
        Err(LegacyMigrationMarkerError::AuthenticationFailed)
    ));
}

#[test]
fn marker_tamper_rejects_before_phase_or_scheduler_use() {
    let setup = initialized();
    let _plan = setup.marker.initialize_prepared(setup.block, 1).unwrap();
    let path = setup
        .fixture
        .platform
        .join("contract218.migration-marker.current");
    let mut bytes = fs::read(&path).unwrap();
    bytes[100] ^= 1;
    fs::write(path, bytes).unwrap();
    assert!(matches!(
        setup.marker.current_phase(),
        Err(LegacyMigrationMarkerError::AuthenticationFailed)
    ));
}

#[test]
fn second_marker_custody_and_wrong_operator_are_rejected() {
    let setup = initialized();
    let second = FileLegacyMigrationMarkerCustody::from_anchor_store(
        &setup.anchor,
        &setup.keyring,
        &setup.roles,
        Arc::new(TestAuthority {
            workspace: fs::canonicalize(&setup.fixture.workspace).unwrap(),
            operator: [0x24; 32],
        }),
    );
    assert!(matches!(
        second,
        Err(LegacyMigrationMarkerError::RecoveryRequired(_))
    ));
    drop(setup.marker);
    let wrong = FileLegacyMigrationMarkerCustody::from_anchor_store(
        &setup.anchor,
        &setup.keyring,
        &setup.roles,
        Arc::new(TestAuthority {
            workspace: fs::canonicalize(&setup.fixture.workspace).unwrap(),
            operator: [0x25; 32],
        }),
    )
    .unwrap();
    assert!(matches!(
        wrong.initialize_prepared(setup.block, 1),
        Err(LegacyMigrationMarkerError::Unauthorized(_))
    ));
}

#[test]
fn interrupted_initial_current_write_fails_closed() {
    let setup = initialized();
    setup
        .marker
        .set_failpoint_for_test(LegacyMigrationMarkerFailpoint::AfterCurrentTemporaryFsync);
    assert!(matches!(
        setup.marker.initialize_prepared(setup.block, 1),
        Err(LegacyMigrationMarkerError::Failpoint(
            LegacyMigrationMarkerFailpoint::AfterCurrentTemporaryFsync
        ))
    ));
    assert!(matches!(
        setup.marker.initialize_prepared(setup.block, 1),
        Err(LegacyMigrationMarkerError::RecoveryRequired(_))
    ));
    assert!(!setup
        .fixture
        .platform
        .join("contract218.migration-marker.current")
        .exists());
}

#[test]
fn interrupted_initial_plan_write_never_releases_scheduler_artifacts() {
    let setup = initialized();
    setup
        .marker
        .set_failpoint_for_test(LegacyMigrationMarkerFailpoint::AfterPlanTemporaryFsync);
    assert!(matches!(
        setup.marker.initialize_prepared(setup.block, 1),
        Err(LegacyMigrationMarkerError::Failpoint(
            LegacyMigrationMarkerFailpoint::AfterPlanTemporaryFsync
        ))
    ));
    assert!(!setup
        .fixture
        .platform
        .join("contract218.migration-marker.plan")
        .exists());
    assert!(setup
        .fixture
        .platform
        .join(".contract218.migration-marker.plan.tmp")
        .exists());
    assert!(!setup
        .fixture
        .platform
        .join("contract218.migration-marker.current")
        .exists());
    assert!(matches!(
        setup.marker.initialize_prepared(setup.block, 1),
        Err(LegacyMigrationMarkerError::RecoveryRequired(_))
    ));
}

#[test]
fn durable_plan_only_crash_forward_recovers_exact_phase_bytes() {
    let Initialized {
        fixture,
        anchor,
        keyring,
        roles,
        marker,
        block,
    } = initialized();
    marker.set_failpoint_for_test(LegacyMigrationMarkerFailpoint::AfterPlanFsync);
    assert!(matches!(
        marker.initialize_prepared(block, 1),
        Err(LegacyMigrationMarkerError::Failpoint(
            LegacyMigrationMarkerFailpoint::AfterPlanFsync
        ))
    ));
    let plan_bytes = fs::read(fixture.platform.join("contract218.migration-marker.plan")).unwrap();
    let expected_prepared = plan_bytes[1..299].to_vec();
    let expected_installed = plan_bytes[299..597].to_vec();
    let expected_complete = plan_bytes[597..895].to_vec();
    assert!(!fixture
        .platform
        .join("contract218.migration-marker.current")
        .exists());
    drop(marker);

    let marker = open_marker(&fixture, &anchor, &keyring, &roles);
    let mut recovered = marker.initialize_prepared(block, 1).unwrap();
    let artifacts = recovered.take_scheduler_artifacts().unwrap();
    assert_eq!(artifacts.prepared_marker_bytes(), expected_prepared);
    assert_eq!(artifacts.installed_marker_bytes(), expected_installed);
    assert_eq!(artifacts.complete_marker_bytes(), expected_complete);
    assert_eq!(
        marker.current_phase().unwrap(),
        LegacyMigrationMarkerPhase::Prepared
    );
}

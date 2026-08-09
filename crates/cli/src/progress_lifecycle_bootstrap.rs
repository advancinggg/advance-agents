//! Private, fail-closed bootstrap for the joint CONTRACT-216/215 lifecycle.
//!
//! This module deliberately stops at move-only staging. It derives the
//! journal-only integrity subkey, selects and validates the two persistence
//! domains, opens/splits the shared recovery journal exactly once, and stages
//! CONTRACT-216 before CONTRACT-215. Injection and publication belong to the
//! later composition barrier.

use std::env;
use std::fmt;
use std::fs;
use std::num::NonZeroU32;
use std::path::{Component, Path, PathBuf};

use advance_shared_types::progress_card::{
    ProgressCardAuthorityFactory, ProgressCardAuthorityParts,
};
use advance_shared_types::progress_lifecycle_recovery::{
    ProgressLifecycleRecoveryJournal, ProgressRecoveryJournalRole, RecoveryJournalConfig,
    TurnRecoveryJournalRole,
};
use advance_shared_types::turn_attribution::{
    MailboxAdmissionIssuer, MailboxDequeueIssuer, MailboxPublishVerifier, MailboxRemovalIssuer,
    SourceQuiescenceRecoveryIssuer, StoreQuiescenceIssuer, TurnAttributionAuthorityFactory,
    TurnAttributionAuthorityParts, TurnAttributionVerifier, TurnRegistryIssuer,
};
use hkdf::Hkdf;
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// The only composition-root domain used to derive the journal integrity
/// subkey from the operator master key. Derivation is HKDF-Extract-SHA256 with
/// an empty salt followed by HKDF-Expand-SHA256 with this exact value as
/// `info` and `L=32`. The trailing NUL is part of the v1 contract and prevents
/// extension/concatenation ambiguity.
const JOURNAL_INTEGRITY_SUBKEY_DOMAIN: &[u8] =
    b"advance.progress-lifecycle.journal-integrity-subkey.v1\0";
const WORKSPACE_ID_DOMAIN: &[u8] = b"advance.progress-lifecycle.workspace-id.v1";
const JOURNAL_RELATIVE_PATH: [&str; 2] = [".runtime", "progress-lifecycle"];
const ANCHOR_RELATIVE_PATH: [&str; 3] = [".advance", "platform-state", "progress-lifecycle"];
const ANCHOR_SUFFIX: &str = ".anchor";
const RECOVERY_KEY_EPOCH: NonZeroU32 = NonZeroU32::MIN;

/// Stable, non-sensitive bootstrap failures. No variant stores an underlying
/// error, path, environment value, or key material.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProgressLifecycleBootstrapError {
    WorkspaceUnavailable,
    HomeUnavailable,
    UnsafePath,
    KeyDerivationFailed,
    JournalUnavailable,
    Contract216Unavailable,
    Contract215Unavailable,
    InjectedFailure,
}

impl ProgressLifecycleBootstrapError {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::WorkspaceUnavailable => "progress-lifecycle-workspace-unavailable",
            Self::HomeUnavailable => "progress-lifecycle-platform-state-unavailable",
            Self::UnsafePath => "progress-lifecycle-path-policy-rejected",
            Self::KeyDerivationFailed => "progress-lifecycle-key-derivation-failed",
            Self::JournalUnavailable => "progress-lifecycle-recovery-unavailable",
            Self::Contract216Unavailable => "progress-lifecycle-contract216-unavailable",
            Self::Contract215Unavailable => "progress-lifecycle-contract215-unavailable",
            Self::InjectedFailure => "progress-lifecycle-bootstrap-failpoint",
        }
    }
}

impl fmt::Display for ProgressLifecycleBootstrapError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for ProgressLifecycleBootstrapError {}

/// The eight CONTRACT-216 roles which remain after the one-shot joint
/// activation staging proof and source verifier are consumed by the
/// CONTRACT-215 factory. No role is cloned or made visible outside this crate.
pub(crate) struct StagedTurnAttributionParts {
    pub(crate) registry_issuer: TurnRegistryIssuer,
    pub(crate) mailbox_admission_issuer: MailboxAdmissionIssuer,
    pub(crate) mailbox_removal_issuer: MailboxRemovalIssuer,
    pub(crate) mailbox_dequeue_issuer: MailboxDequeueIssuer,
    pub(crate) mailbox_publish_verifier: MailboxPublishVerifier,
    pub(crate) store_quiescence_issuer: StoreQuiescenceIssuer,
    pub(crate) source_quiescence_recovery_issuer: SourceQuiescenceRecoveryIssuer,
    pub(crate) verifier: TurnAttributionVerifier,
}

/// Private move-only result of bootstrap. Construction does not inject a role,
/// publish the joint activation authority, or start a background task.
pub(crate) struct ProgressLifecycleBootstrapStaging {
    pub(crate) contract216: StagedTurnAttributionParts,
    pub(crate) contract215: ProgressCardAuthorityParts,
}

struct ProgressLifecyclePaths {
    canonical_workspace: PathBuf,
    canonical_home: PathBuf,
    journal_dir: PathBuf,
    anchor_parent: PathBuf,
    external_anchor_path: PathBuf,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FactoryStage {
    Contract216,
    Contract215,
}

/// Crate-private factory boundaries used by MODULE-001-T101's composition
/// harness. They are checked while every product is still private staging.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProgressLifecycleBootstrapFailpoint {
    Contract216Factory,
    Contract215Factory,
}

/// Production entry point. `canonical_workspace` must already be the exact
/// canonical directory selected by `advance start`.
pub(crate) fn bootstrap_progress_lifecycle(
    master_key: &[u8; 32],
    canonical_workspace: &Path,
) -> Result<ProgressLifecycleBootstrapStaging, ProgressLifecycleBootstrapError> {
    let home = env::var_os("HOME").ok_or(ProgressLifecycleBootstrapError::HomeUnavailable)?;
    bootstrap_progress_lifecycle_with_home(
        master_key,
        canonical_workspace,
        Some(Path::new(&home)),
        None,
    )
}

/// Injectable path seam used by tests and composition witnesses. Passing
/// `None` models an unavailable HOME without mutating process-global state.
pub(crate) fn bootstrap_progress_lifecycle_with_home(
    master_key: &[u8; 32],
    canonical_workspace: &Path,
    home: Option<&Path>,
    failpoint: Option<ProgressLifecycleBootstrapFailpoint>,
) -> Result<ProgressLifecycleBootstrapStaging, ProgressLifecycleBootstrapError> {
    let mut rng = rand::rngs::OsRng;
    bootstrap_progress_lifecycle_with_home_and_rng(
        master_key,
        canonical_workspace,
        home,
        &mut rng,
        failpoint,
        |_| {},
    )
}

fn bootstrap_progress_lifecycle_with_home_and_rng<R, F>(
    master_key: &[u8; 32],
    canonical_workspace: &Path,
    home: Option<&Path>,
    rng: &mut R,
    failpoint: Option<ProgressLifecycleBootstrapFailpoint>,
    observe_factory: F,
) -> Result<ProgressLifecycleBootstrapStaging, ProgressLifecycleBootstrapError>
where
    R: RngCore + CryptoRng,
    F: FnMut(FactoryStage),
{
    let paths = resolve_paths(canonical_workspace, home)?;
    prepare_persistence_directories(&paths)?;
    let integrity_key = derive_journal_integrity_subkey(master_key)?;
    let config = RecoveryJournalConfig::new_at_composition(
        paths.journal_dir,
        paths.external_anchor_path,
        RECOVERY_KEY_EPOCH,
        integrity_key,
    )
    .map_err(|_| ProgressLifecycleBootstrapError::JournalUnavailable)?;
    let journal = ProgressLifecycleRecoveryJournal::open_at_composition(config)
        .map_err(|_| ProgressLifecycleBootstrapError::JournalUnavailable)?;
    let (turn_recovery, progress_recovery) = journal.split_at_composition();
    stage_authorities(
        rng,
        turn_recovery,
        progress_recovery,
        failpoint,
        observe_factory,
    )
}

fn stage_authorities<R, F>(
    rng: &mut R,
    turn_recovery: TurnRecoveryJournalRole,
    progress_recovery: ProgressRecoveryJournalRole,
    failpoint: Option<ProgressLifecycleBootstrapFailpoint>,
    mut observe_factory: F,
) -> Result<ProgressLifecycleBootstrapStaging, ProgressLifecycleBootstrapError>
where
    R: RngCore + CryptoRng,
    F: FnMut(FactoryStage),
{
    observe_factory(FactoryStage::Contract216);
    if failpoint == Some(ProgressLifecycleBootstrapFailpoint::Contract216Factory) {
        return Err(ProgressLifecycleBootstrapError::InjectedFailure);
    }
    let turn = TurnAttributionAuthorityFactory::new_at_composition(rng, turn_recovery)
        .map_err(|_| ProgressLifecycleBootstrapError::Contract216Unavailable)?;
    let TurnAttributionAuthorityParts {
        activation_staging,
        registry_issuer,
        mailbox_admission_issuer,
        mailbox_removal_issuer,
        mailbox_dequeue_issuer,
        mailbox_publish_verifier,
        store_quiescence_issuer,
        source_quiescence_recovery_issuer,
        source_quiescence_verifier,
        verifier,
    } = turn;

    observe_factory(FactoryStage::Contract215);
    if failpoint == Some(ProgressLifecycleBootstrapFailpoint::Contract215Factory) {
        return Err(ProgressLifecycleBootstrapError::InjectedFailure);
    }
    let contract215 = ProgressCardAuthorityFactory::new_at_composition(
        rng,
        activation_staging,
        source_quiescence_verifier,
        progress_recovery,
    )
    .map_err(|_| ProgressLifecycleBootstrapError::Contract215Unavailable)?;

    Ok(ProgressLifecycleBootstrapStaging {
        contract216: StagedTurnAttributionParts {
            registry_issuer,
            mailbox_admission_issuer,
            mailbox_removal_issuer,
            mailbox_dequeue_issuer,
            mailbox_publish_verifier,
            store_quiescence_issuer,
            source_quiescence_recovery_issuer,
            verifier,
        },
        contract215,
    })
}

fn derive_journal_integrity_subkey(
    master_key: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, ProgressLifecycleBootstrapError> {
    let hkdf = Hkdf::<Sha256>::new(None, master_key);
    let mut subkey = Zeroizing::new([0u8; 32]);
    hkdf.expand(JOURNAL_INTEGRITY_SUBKEY_DOMAIN, subkey.as_mut())
        .map_err(|_| ProgressLifecycleBootstrapError::KeyDerivationFailed)?;
    Ok(subkey)
}

fn resolve_paths(
    workspace: &Path,
    home: Option<&Path>,
) -> Result<ProgressLifecyclePaths, ProgressLifecycleBootstrapError> {
    let canonical_workspace = exact_canonical_directory(
        workspace,
        ProgressLifecycleBootstrapError::WorkspaceUnavailable,
    )?;
    let home = home.ok_or(ProgressLifecycleBootstrapError::HomeUnavailable)?;
    let canonical_home =
        exact_canonical_directory(home, ProgressLifecycleBootstrapError::HomeUnavailable)?;

    validate_relative_path(&canonical_workspace, &JOURNAL_RELATIVE_PATH)?;
    validate_relative_path(&canonical_home, &ANCHOR_RELATIVE_PATH)?;

    let journal_dir = join_components(&canonical_workspace, &JOURNAL_RELATIVE_PATH);
    let anchor_parent = join_components(&canonical_home, &ANCHOR_RELATIVE_PATH);
    if !journal_dir.starts_with(&canonical_workspace)
        || anchor_parent.starts_with(&canonical_workspace)
    {
        return Err(ProgressLifecycleBootstrapError::UnsafePath);
    }

    let workspace_id = workspace_identity(&canonical_workspace)?;
    let external_anchor_path = anchor_parent.join(format!("{workspace_id}{ANCHOR_SUFFIX}"));
    Ok(ProgressLifecyclePaths {
        canonical_workspace,
        canonical_home,
        journal_dir,
        anchor_parent,
        external_anchor_path,
    })
}

fn exact_canonical_directory(
    path: &Path,
    unavailable: ProgressLifecycleBootstrapError,
) -> Result<PathBuf, ProgressLifecycleBootstrapError> {
    if !path.is_absolute() {
        return Err(unavailable);
    }
    let canonical = fs::canonicalize(path).map_err(|_| unavailable)?;
    if canonical != path || !canonical.is_dir() {
        return Err(unavailable);
    }
    Ok(canonical)
}

fn validate_relative_path(
    base: &Path,
    components: &[&str],
) -> Result<(), ProgressLifecycleBootstrapError> {
    let mut cursor = base.to_path_buf();
    for component in components {
        if Path::new(component).components().count() != 1
            || !matches!(
                Path::new(component).components().next(),
                Some(Component::Normal(_))
            )
        {
            return Err(ProgressLifecycleBootstrapError::UnsafePath);
        }
        cursor.push(component);
        match fs::symlink_metadata(&cursor) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(ProgressLifecycleBootstrapError::UnsafePath)
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(ProgressLifecycleBootstrapError::UnsafePath),
        }
    }
    Ok(())
}

fn join_components(base: &Path, components: &[&str]) -> PathBuf {
    components
        .iter()
        .fold(base.to_path_buf(), |path, component| path.join(component))
}

fn workspace_identity(
    canonical_workspace: &Path,
) -> Result<String, ProgressLifecycleBootstrapError> {
    let mut digest = Sha256::new();
    digest.update(WORKSPACE_ID_DOMAIN);
    digest.update([0]);
    update_digest_with_path(&mut digest, canonical_workspace)?;
    Ok(hex::encode(digest.finalize()))
}

#[cfg(unix)]
fn update_digest_with_path(
    digest: &mut Sha256,
    path: &Path,
) -> Result<(), ProgressLifecycleBootstrapError> {
    use std::os::unix::ffi::OsStrExt;
    digest.update(path.as_os_str().as_bytes());
    Ok(())
}

#[cfg(not(unix))]
fn update_digest_with_path(
    digest: &mut Sha256,
    path: &Path,
) -> Result<(), ProgressLifecycleBootstrapError> {
    let value = path
        .to_str()
        .ok_or(ProgressLifecycleBootstrapError::UnsafePath)?;
    digest.update(value.as_bytes());
    Ok(())
}

fn prepare_persistence_directories(
    paths: &ProgressLifecyclePaths,
) -> Result<(), ProgressLifecycleBootstrapError> {
    create_confined_owner_directory(
        &paths.canonical_workspace,
        &JOURNAL_RELATIVE_PATH,
        &paths.journal_dir,
    )?;
    create_confined_owner_directory(
        &paths.canonical_home,
        &ANCHOR_RELATIVE_PATH,
        &paths.anchor_parent,
    )?;

    let journal = fs::canonicalize(&paths.journal_dir)
        .map_err(|_| ProgressLifecycleBootstrapError::UnsafePath)?;
    let anchor_parent = fs::canonicalize(&paths.anchor_parent)
        .map_err(|_| ProgressLifecycleBootstrapError::UnsafePath)?;
    if journal != paths.journal_dir
        || !journal.starts_with(&paths.canonical_workspace)
        || anchor_parent != paths.anchor_parent
        || anchor_parent.starts_with(&paths.canonical_workspace)
    {
        return Err(ProgressLifecycleBootstrapError::UnsafePath);
    }
    Ok(())
}

fn create_confined_owner_directory(
    base: &Path,
    components: &[&str],
    expected: &Path,
) -> Result<(), ProgressLifecycleBootstrapError> {
    let mut cursor = base.to_path_buf();
    for component in components {
        cursor.push(component);
        match fs::symlink_metadata(&cursor) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(ProgressLifecycleBootstrapError::UnsafePath)
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                create_owner_directory(&cursor)?;
            }
            Err(_) => return Err(ProgressLifecycleBootstrapError::UnsafePath),
        }
    }
    if cursor != expected {
        return Err(ProgressLifecycleBootstrapError::UnsafePath);
    }
    require_owner_only_directory(expected)
}

fn create_owner_directory(path: &Path) -> Result<(), ProgressLifecycleBootstrapError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        builder
            .create(path)
            .map_err(|_| ProgressLifecycleBootstrapError::UnsafePath)
    }
    #[cfg(not(unix))]
    {
        fs::create_dir(path).map_err(|_| ProgressLifecycleBootstrapError::UnsafePath)
    }
}

fn require_owner_only_directory(path: &Path) -> Result<(), ProgressLifecycleBootstrapError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| ProgressLifecycleBootstrapError::UnsafePath)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ProgressLifecycleBootstrapError::UnsafePath);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(ProgressLifecycleBootstrapError::UnsafePath);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use advance_shared_types::progress_card::ProgressCardAuthorityParts;
    use rand::rngs::OsRng;
    use std::fs;

    fn canonical_dir(path: &Path) -> PathBuf {
        fs::create_dir(path).expect("create fixture directory");
        fs::canonicalize(path).expect("canonical fixture directory")
    }

    fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let root = tempfile::tempdir().expect("tempdir");
        let workspace = canonical_dir(&root.path().join("workspace"));
        let home = canonical_dir(&root.path().join("home"));
        (root, workspace, home)
    }

    #[test]
    fn path_selection_is_stable_and_domain_separated() {
        let (_root, workspace, home) = fixture();
        let first = resolve_paths(&workspace, Some(&home)).expect("paths resolve");
        let second = resolve_paths(&workspace, Some(&home)).expect("paths remain stable");
        assert_eq!(first.journal_dir, second.journal_dir);
        assert_eq!(first.external_anchor_path, second.external_anchor_path);
        assert_eq!(
            first.journal_dir,
            workspace.join(".runtime/progress-lifecycle")
        );
        let expected_anchor_parent = home.join(".advance/platform-state/progress-lifecycle");
        assert_eq!(
            first.external_anchor_path.parent(),
            Some(expected_anchor_parent.as_path())
        );
        let anchor_name = first
            .external_anchor_path
            .file_name()
            .and_then(|name| name.to_str())
            .expect("ASCII anchor name");
        assert_eq!(anchor_name.len(), 64 + ANCHOR_SUFFIX.len());
        assert!(anchor_name.ends_with(ANCHOR_SUFFIX));
        assert!(anchor_name[..64]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit()));
        assert!(!first.external_anchor_path.starts_with(&workspace));
    }

    #[test]
    fn anchor_domain_inside_workspace_is_rejected() {
        let root = tempfile::tempdir().expect("tempdir");
        let workspace = canonical_dir(&root.path().join("workspace"));
        let nested_home = canonical_dir(&workspace.join("home"));
        assert_eq!(
            resolve_paths(&workspace, Some(&nested_home)).err(),
            Some(ProgressLifecycleBootstrapError::UnsafePath)
        );
    }

    #[test]
    fn missing_home_and_noncanonical_workspace_are_rejected() {
        let (_root, workspace, home) = fixture();
        assert_eq!(
            resolve_paths(&workspace, None).err(),
            Some(ProgressLifecycleBootstrapError::HomeUnavailable)
        );
        assert_eq!(
            bootstrap_progress_lifecycle_with_home(&[0x33; 32], &workspace, None, None).err(),
            Some(ProgressLifecycleBootstrapError::HomeUnavailable)
        );
        let noncanonical = workspace.join("..").join("workspace");
        assert_eq!(
            resolve_paths(&noncanonical, Some(&home)).err(),
            Some(ProgressLifecycleBootstrapError::WorkspaceUnavailable)
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_storage_ancestor_is_rejected() {
        use std::os::unix::fs::symlink;

        let (root, workspace, home) = fixture();
        let redirect = canonical_dir(&root.path().join("redirect"));
        symlink(&redirect, home.join(".advance")).expect("create symlink fixture");
        assert_eq!(
            resolve_paths(&workspace, Some(&home)).err(),
            Some(ProgressLifecycleBootstrapError::UnsafePath)
        );
    }

    #[test]
    fn integrity_subkey_is_deterministic_separated_and_zeroized_owner() {
        let master = [0x5au8; 32];
        let first = derive_journal_integrity_subkey(&master).expect("derive subkey");
        let second = derive_journal_integrity_subkey(&master).expect("derive subkey again");
        assert_eq!(&*first, &*second);
        assert_ne!(&*first, &master);
        assert_ne!(&*first, &[0u8; 32]);
    }

    #[test]
    fn bootstrap_stages_contract216_before_contract215_and_keeps_every_role() {
        let (_root, workspace, home) = fixture();
        let paths = resolve_paths(&workspace, Some(&home)).expect("paths resolve");
        let mut observed = Vec::new();
        let staging = bootstrap_progress_lifecycle_with_home_and_rng(
            &[0x8bu8; 32],
            &workspace,
            Some(&home),
            &mut OsRng,
            None,
            |stage| observed.push(stage),
        )
        .expect("joint bootstrap succeeds");
        assert_eq!(
            observed,
            vec![FactoryStage::Contract216, FactoryStage::Contract215]
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for path in [
                &paths.journal_dir,
                &paths.anchor_parent,
                &paths.external_anchor_path,
            ] {
                let mode = fs::metadata(path)
                    .expect("bootstrap artifact exists")
                    .permissions()
                    .mode();
                assert_eq!(mode & 0o077, 0, "artifact must be owner-only");
            }
        }

        let ProgressLifecycleBootstrapStaging {
            contract216,
            contract215,
        } = staging;
        let StagedTurnAttributionParts {
            registry_issuer: _,
            mailbox_admission_issuer: _,
            mailbox_removal_issuer: _,
            mailbox_dequeue_issuer: _,
            mailbox_publish_verifier: _,
            store_quiescence_issuer: _,
            source_quiescence_recovery_issuer: _,
            verifier: _,
        } = contract216;
        let ProgressCardAuthorityParts {
            protected_state_issuer: _,
            coordinator_challenge_issuer: _,
            outbound_route_seal_issuer: _,
            source_close_attestation_issuer: _,
            transport_outcome_receipt_issuer: _,
            reconciliation_proof_issuer: _,
            verifier: _,
            joint_activation_authority: _,
        } = contract215;
    }

    #[test]
    fn factory_failpoints_fire_in_order_before_any_staging_escapes() {
        for (failpoint, expected) in [
            (
                ProgressLifecycleBootstrapFailpoint::Contract216Factory,
                vec![FactoryStage::Contract216],
            ),
            (
                ProgressLifecycleBootstrapFailpoint::Contract215Factory,
                vec![FactoryStage::Contract216, FactoryStage::Contract215],
            ),
        ] {
            let (_root, workspace, home) = fixture();
            let mut observed = Vec::new();
            let result = bootstrap_progress_lifecycle_with_home_and_rng(
                &[0x71u8; 32],
                &workspace,
                Some(&home),
                &mut OsRng,
                Some(failpoint),
                |stage| observed.push(stage),
            );
            assert_eq!(
                result.err(),
                Some(ProgressLifecycleBootstrapError::InjectedFailure)
            );
            assert_eq!(observed, expected);
        }
    }

    #[test]
    fn failures_are_fixed_codes_without_key_or_path_payloads() {
        let secret_path = "/tmp/do-not-disclose-workspace-name";
        let error = resolve_paths(Path::new(secret_path), None)
            .err()
            .expect("must fail");
        assert_eq!(
            error.to_string(),
            "progress-lifecycle-workspace-unavailable"
        );
        assert!(!error.to_string().contains(secret_path));
        assert!(!format!("{error:?}").contains(secret_path));
    }
}

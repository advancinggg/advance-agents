//! The process-local registry of homes a runtime is composed in.
//!
//! One process runs at most one runtime per home. The registry is keyed by the
//! canonical home path and is shared by every in-process entry point (the
//! embedded runtime bridge reserves through it as well), so a second in-process
//! start on the same home is refused before the cross-process runtime lock is
//! even tried.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};

/// Launch claims older than this are stale, matching `.runtime/launch.lock`.
pub(crate) const LAUNCH_CLAIM_STALE: Duration = Duration::from_secs(2);

#[derive(Default)]
struct Registry {
    homes: HashMap<PathBuf, Entry>,
    launch_claims: HashMap<PathBuf, Instant>,
}

#[derive(Default)]
struct Entry {
    attach: Option<AttachInfo>,
}

/// Published by `compose()` once the composition is up (MODULE-001-AC-34).
#[derive(Clone)]
pub(crate) struct AttachInfo {
    pub(crate) view: Weak<crate::composition::RuntimeView>,
    pub(crate) shutdown: crate::api::ShutdownHandle,
    pub(crate) platform: advance_client_api::Platform,
}

pub(crate) enum Lookup {
    Free,
    Reserved(Option<AttachInfo>),
}

static REGISTRY: OnceLock<Mutex<Registry>> = OnceLock::new();

fn registry() -> &'static Mutex<Registry> {
    REGISTRY.get_or_init(|| Mutex::new(Registry::default()))
}

/// Why a home could not be reserved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReserveError {
    /// The home is already reserved in this process.
    AlreadyReserved,
    /// The registry's lock is poisoned.
    Poisoned,
}

/// Reserve `home` (a canonical path); fails if it is already reserved.
pub fn reserve(home: PathBuf) -> Result<(), ReserveError> {
    reserve_in(registry(), home)
}

/// Release a reservation of `home`. A no-op when `home` is not reserved or the
/// registry's lock is poisoned.
pub fn release(home: &Path) {
    release_in(registry(), home);
}

fn reserve_in(registry: &Mutex<Registry>, home: PathBuf) -> Result<(), ReserveError> {
    let mut reserved = registry.lock().map_err(|_| ReserveError::Poisoned)?;
    if reserved.homes.contains_key(&home) {
        return Err(ReserveError::AlreadyReserved);
    }
    reserved.homes.insert(home, Entry::default());
    Ok(())
}

fn release_in(registry: &Mutex<Registry>, home: &Path) {
    if let Ok(mut reserved) = registry.lock() {
        reserved.homes.remove(home);
    }
}

/// Record attach info for a reserved home. `false` when `home` is not reserved.
pub(crate) fn publish_attach(home: &Path, info: AttachInfo) -> bool {
    let mut reserved = registry().lock().unwrap_or_else(|p| p.into_inner());
    match reserved.homes.get_mut(home) {
        Some(entry) => {
            entry.attach = Some(info);
            true
        }
        None => false,
    }
}

/// Snapshot of whether `home` is reserved and, if so, its attach info.
pub(crate) fn lookup(home: &Path) -> Lookup {
    let reserved = registry().lock().unwrap_or_else(|p| p.into_inner());
    match reserved.homes.get(home) {
        None => Lookup::Free,
        Some(entry) => Lookup::Reserved(entry.attach.clone()),
    }
}

/// Take the per-home launch claim. `true` when absent or stale (≥ 2 s).
pub(crate) fn claim_launch(home: &Path, now: Instant) -> bool {
    let mut reserved = registry().lock().unwrap_or_else(|p| p.into_inner());
    match reserved.launch_claims.get(home) {
        Some(held) if now.duration_since(*held) < LAUNCH_CLAIM_STALE => false,
        _ => {
            reserved.launch_claims.insert(home.to_path_buf(), now);
            true
        }
    }
}

/// Release the launch claim. Idempotent.
pub(crate) fn release_launch(home: &Path) {
    let mut reserved = registry().lock().unwrap_or_else(|p| p.into_inner());
    reserved.launch_claims.remove(home);
}

/// A reservation released when dropped, unless [`HomeReservation::persist`] hands
/// its ownership to a longer-lived holder (who then calls [`release`]).
#[must_use]
pub struct HomeReservation {
    path: Option<PathBuf>,
}

impl HomeReservation {
    /// Reserve `home` (a canonical path).
    pub fn acquire(home: PathBuf) -> Result<Self, ReserveError> {
        reserve(home.clone())?;
        Ok(Self { path: Some(home) })
    }

    /// Keep the reservation past this value's drop.
    pub fn persist(mut self) {
        self.path = None;
    }
}

impl Drop for HomeReservation {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            release(&path);
        }
    }
}

/// Every reserved home, sorted.
#[cfg(feature = "test-support")]
pub fn reserved_homes_for_test() -> Vec<PathBuf> {
    let reserved = registry().lock().unwrap_or_else(|p| p.into_inner());
    let mut homes: Vec<PathBuf> = reserved.homes.keys().cloned().collect();
    homes.sort();
    homes
}

/// Every in-memory launch claim, sorted.
#[cfg(feature = "test-support")]
pub fn launch_claims_for_test() -> Vec<PathBuf> {
    let reserved = registry().lock().unwrap_or_else(|p| p.into_inner());
    let mut homes: Vec<PathBuf> = reserved.launch_claims.keys().cloned().collect();
    homes.sort();
    homes
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A poisoned registry refuses every reservation with `Poisoned` (which `compose`
    /// reports as `Lock(RegistryPoisoned)` and the embedded bridge as its internal
    /// error) and ignores a release, keeping its entries. A registry of the test's own:
    /// the process-wide one is shared by every test of this binary.
    #[test]
    fn module_001_ac30_registry_poison_answers_unchanged() {
        let registry = Mutex::new(Registry::default());
        let home = PathBuf::from("/tmp/runtime-compose-registry-test-poison");
        reserve_in(&registry, home.clone()).unwrap();
        let poisoner = std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    let _held = registry.lock().unwrap();
                    panic!("poison the registry");
                })
                .join()
        });
        assert!(poisoner.is_err() && registry.is_poisoned());

        assert_eq!(
            reserve_in(
                &registry,
                PathBuf::from("/tmp/runtime-compose-registry-test-other")
            ),
            Err(ReserveError::Poisoned)
        );
        assert_eq!(
            reserve_in(&registry, home.clone()),
            Err(ReserveError::Poisoned)
        );
        release_in(&registry, &home);
        assert!(
            registry
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .homes
                .contains_key(&home),
            "a release on a poisoned registry changes nothing"
        );
    }

    #[test]
    fn module_001_ac34_registry_publishes_attach_info_only_for_reserved_homes() {
        let home = PathBuf::from("/tmp/runtime-compose-registry-test-publish-ac34");
        release(&home);
        assert!(matches!(lookup(&home), Lookup::Free));
        let info = AttachInfo {
            view: Weak::new(),
            shutdown: crate::api::ShutdownHandle::new(advance_client_api::ExtensionRouteGate::new()),
            platform: advance_client_api::Platform::Ios,
        };
        assert!(!publish_attach(&home, info.clone()));
        reserve(home.clone()).unwrap();
        assert!(matches!(lookup(&home), Lookup::Reserved(None)));
        assert!(publish_attach(&home, info));
        assert!(matches!(lookup(&home), Lookup::Reserved(Some(_))));
        release(&home);
        assert!(matches!(lookup(&home), Lookup::Free));
    }

    #[test]
    fn module_001_ac34_launch_claim_is_exclusive_and_stale_after_two_seconds() {
        let home = PathBuf::from("/tmp/runtime-compose-registry-test-claim-ac34");
        release(&home);
        release_launch(&home);
        let t0 = Instant::now();
        assert!(claim_launch(&home, t0));
        assert!(!claim_launch(&home, t0 + Duration::from_secs(1)));
        assert!(claim_launch(
            &home,
            t0 + Duration::from_secs(2) + Duration::from_millis(1)
        ));
        release_launch(&home);
        assert!(claim_launch(&home, t0));
        reserve(home.clone()).unwrap();
        release(&home);
        release_launch(&home);
    }

    #[test]
    fn a_home_is_reserved_once_until_released() {
        let home = PathBuf::from("/tmp/runtime-compose-registry-test-reserve");
        release(&home);
        reserve(home.clone()).unwrap();
        assert_eq!(reserve(home.clone()), Err(ReserveError::AlreadyReserved));
        assert!(reserved_homes_for_test().contains(&home));
        release(&home);
        assert!(!reserved_homes_for_test().contains(&home));
        reserve(home.clone()).unwrap();
        release(&home);
    }

    #[test]
    fn a_reservation_releases_on_drop_unless_persisted() {
        let home = PathBuf::from("/tmp/runtime-compose-registry-test-raii");
        release(&home);
        {
            let _held = HomeReservation::acquire(home.clone()).unwrap();
            assert!(matches!(
                HomeReservation::acquire(home.clone()),
                Err(ReserveError::AlreadyReserved)
            ));
        }
        let held = HomeReservation::acquire(home.clone()).expect("released on drop");
        held.persist();
        assert_eq!(reserve(home.clone()), Err(ReserveError::AlreadyReserved));
        release(&home);
        reserve(home.clone()).unwrap();
        release(&home);
    }
}

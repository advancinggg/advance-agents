//! The process-local registry of homes a runtime is composed in.
//!
//! One process runs at most one runtime per home. The registry is keyed by the
//! canonical home path and is shared by every in-process entry point (the
//! embedded runtime bridge reserves through it as well), so a second in-process
//! start on the same home is refused before the cross-process runtime lock is
//! even tried.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

static REGISTRY: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();

fn registry() -> &'static Mutex<HashSet<PathBuf>> {
    REGISTRY.get_or_init(|| Mutex::new(HashSet::new()))
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

fn reserve_in(registry: &Mutex<HashSet<PathBuf>>, home: PathBuf) -> Result<(), ReserveError> {
    let mut reserved = registry.lock().map_err(|_| ReserveError::Poisoned)?;
    if !reserved.insert(home) {
        return Err(ReserveError::AlreadyReserved);
    }
    Ok(())
}

fn release_in(registry: &Mutex<HashSet<PathBuf>>, home: &Path) {
    if let Ok(mut reserved) = registry.lock() {
        reserved.remove(home);
    }
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
    let mut homes: Vec<PathBuf> = reserved.iter().cloned().collect();
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
        let registry = Mutex::new(HashSet::new());
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
                .contains(&home),
            "a release on a poisoned registry changes nothing"
        );
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

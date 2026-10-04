//! Process-local multi-start registry (workspace key).
//!
//! The registry itself is the composition's ([`advance_runtime_compose::registry`]),
//! so the bridge and an in-process composition refuse each other's home; this
//! module keeps the bridge's answers.

use std::path::PathBuf;

use advance_runtime_compose::registry::{self as shared, ReserveError};

use crate::error::BridgeError;

fn bridge_error(error: ReserveError) -> BridgeError {
    match error {
        ReserveError::AlreadyReserved => BridgeError::AlreadyRunning,
        ReserveError::Poisoned => BridgeError::Internal("registry lock poisoned".into()),
    }
}

/// Reserve a workspace path; fails if already reserved.
pub fn reserve(workspace: PathBuf) -> Result<(), BridgeError> {
    shared::reserve(workspace).map_err(bridge_error)
}

/// Release a previously reserved workspace.
pub(crate) fn release(workspace: &PathBuf) {
    shared::release(workspace);
}

/// RAII reservation: released on drop unless [`Reservation::persist`] is called.
/// Cancel of `start_async` after reserve therefore cannot leak the slot.
pub(crate) struct Reservation {
    path: Option<PathBuf>,
}

impl Reservation {
    pub(crate) fn acquire(workspace: PathBuf) -> Result<Self, BridgeError> {
        reserve(workspace.clone())?;
        Ok(Self {
            path: Some(workspace),
        })
    }

    /// Transfer ownership to [`crate::handle::BridgeInner`]; Drop will not release.
    pub(crate) fn persist(mut self) {
        self.path = None;
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if let Some(p) = self.path.take() {
            release(&p);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn multi_start_same_key() {
        let p = PathBuf::from("/tmp/bridge-registry-test-unique-c210");
        release(&p);
        reserve(p.clone()).unwrap();
        assert!(matches!(
            reserve(p.clone()),
            Err(BridgeError::AlreadyRunning)
        ));
        release(&p);
        reserve(p.clone()).unwrap();
        release(&p);
    }

    #[test]
    fn shared_registry_answers_keep_the_bridge_errors() {
        assert!(matches!(
            bridge_error(ReserveError::AlreadyReserved),
            BridgeError::AlreadyRunning
        ));
        match bridge_error(ReserveError::Poisoned) {
            BridgeError::Internal(text) => assert_eq!(text, "registry lock poisoned"),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn a_home_reserved_by_the_composition_is_refused_to_the_bridge() {
        let p = PathBuf::from("/tmp/bridge-registry-test-shared-c210");
        release(&p);
        let held = advance_runtime_compose::registry::HomeReservation::acquire(p.clone()).unwrap();
        assert!(matches!(
            Reservation::acquire(p.clone()),
            Err(BridgeError::AlreadyRunning)
        ));
        drop(held);
        let mine = Reservation::acquire(p.clone()).unwrap();
        mine.persist();
        assert!(matches!(
            reserve(p.clone()),
            Err(BridgeError::AlreadyRunning)
        ));
        release(&p);
    }
}

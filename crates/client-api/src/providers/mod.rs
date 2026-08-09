//! Legacy-three bound provider adapters.
//!
//! Upstream ports return only move-only [`BoundObservationDocument`] values.  The wrapper below is
//! crate-private so composition cannot manufacture a projectable DTO or pair a value with a
//! different authority.  Every item is consumed by CONTRACT-219 before a family decoder sees it.

use std::marker::PhantomData;

use advance_shared_types::sensitive_observation::{
    BoundObservationDocument, ObservationDocument, RedactionDisposition,
    SensitiveObservationRedactor,
};

use crate::envelope::{ClientError, ClientErrorCode};

pub mod grants;
pub mod history;

pub(crate) struct Projectable<T> {
    bound: BoundObservationDocument,
    schema: PhantomData<fn() -> T>,
}

impl<T> Projectable<T> {
    pub(crate) fn from_bound(bound: BoundObservationDocument) -> Self {
        Self {
            bound,
            schema: PhantomData,
        }
    }

    pub(crate) fn redact(
        self,
        redactor: &SensitiveObservationRedactor,
    ) -> Result<ObservationDocument, ClientError> {
        match redactor.redact_bound_observation(self.bound) {
            RedactionDisposition::Redacted(document) => Ok(document),
            RedactionDisposition::Blocked { .. } => Err(ClientError::new(
                ClientErrorCode::ProjectionRejected,
                "bound observation projection rejected",
            )),
        }
    }
}

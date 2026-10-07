//! CONTRACT-244 D2(b): inference contributions, containment, and holds.

pub(crate) mod contained;
pub(crate) mod hold;
mod plan;
mod preflight;
mod validate;

pub(crate) use hold::ExtensionHold;
pub(crate) use plan::{run_inference_phase, InferenceOutcome};
pub(crate) use preflight::{ClaimedPreflightStopper, ComposedClaimedPreflight};

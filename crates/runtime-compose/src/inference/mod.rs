//! CONTRACT-244 D2(b): inference contributions, containment, and holds.

pub(crate) mod contained;
pub(crate) mod hold;
mod plan;
mod validate;

pub(crate) use hold::ExtensionHold;
pub(crate) use plan::{run_inference_phase, InferenceOutcome};

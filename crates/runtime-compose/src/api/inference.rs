//! CONTRACT-244 D2(b): what extensions add to the LLM gateway.
//!
//! The composer creates one [`InferenceContribution`] per composition, only on a
//! home that declares `llm`, and hands it to each extension's `inference`
//! callback in turn. Records are checked as they are made; the first refused
//! record fails `compose` with [`ComposeError::InferenceClaim`] once the
//! callback returns (a claim never silently overrides a binding). Records of a
//! callback that returns `Err` or panics are discarded, except holds. After the
//! phase the backend registry is fixed for the composition's life.
//!
//! Every port and dispatch recorded here is wrapped at once in a containment
//! adapter: a panic in it becomes that call's typed error, the next call
//! reaches it again, and a panicking `Drop` is caught. The structured log line
//! never carries the panic payload; std's default panic hook still prints the
//! panic to stderr (not this crate's code).
//!
//! ```compile_fail
//! use advance_runtime_compose::InferenceContribution;
//! let _ = InferenceContribution::new();
//! ```
//!
//! ```compile_fail
//! use advance_runtime_compose::InferenceContribution;
//! let _ = InferenceContribution::default();
//! ```

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use advance_runtime::config::RuntimeConfig;
use advance_shared_types::inference::{InferenceBackendPort, MeshInferenceDispatch};

use super::options::ProcessPolicy;
use crate::compose_log::LogHandle;
use crate::inference::hold::ExtensionHold;

/// CONTRACT-244 D2(b): what extensions add to the LLM gateway.
pub struct InferenceContribution {
    pub(crate) boot: Arc<RuntimeConfig>,
    pub(crate) log: LogHandle,
    pub(crate) current: Option<(&'static str, ProcessPolicy)>,
    pub(crate) claimable: Vec<String>,
    pub(crate) staged: Staged,
    pub(crate) committed: Committed,
    pub(crate) holds: Vec<ExtensionHold>,
}

#[derive(Default)]
pub(crate) struct Staged {
    pub(crate) claims: Vec<(String, Arc<dyn InferenceBackendPort>)>,
    pub(crate) profiles: Vec<String>,
    pub(crate) catalog: Option<cap_llm::ModelProfileCatalog>,
    pub(crate) dispatches: Vec<Arc<dyn MeshInferenceDispatch>>,
    pub(crate) holds: usize,
    pub(crate) serves_local: bool,
    pub(crate) first_refusal: Option<(
        super::error::InferenceSubject,
        super::error::InferenceRefusal,
    )>,
}

#[derive(Default)]
pub(crate) struct Committed {
    pub(crate) claims: BTreeMap<String, (&'static str, Arc<dyn InferenceBackendPort>)>,
    pub(crate) profile_owner: BTreeMap<String, &'static str>,
    pub(crate) catalog: cap_llm::ModelProfileCatalog,
    pub(crate) mesh: Option<(&'static str, Arc<dyn MeshInferenceDispatch>)>,
    pub(crate) contributed: bool,
}

impl fmt::Debug for InferenceContribution {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let staged_claims: Vec<&str> = self
            .staged
            .claims
            .iter()
            .map(|(id, _)| id.as_str())
            .collect();
        let committed_claims: Vec<&str> =
            self.committed.claims.keys().map(String::as_str).collect();
        f.debug_struct("InferenceContribution")
            .field("extension", &self.current.map(|(id, _)| id))
            .field("claimable", &self.claimable)
            .field("staged_claims", &staged_claims)
            .field("staged_profiles", &self.staged.profiles)
            .field("staged_dispatches", &self.staged.dispatches.len())
            .field("staged_holds", &self.staged.holds)
            .field("serves_local", &self.staged.serves_local)
            .field("committed_claims", &committed_claims)
            .field(
                "committed_profiles",
                &self.committed.profile_owner.keys().collect::<Vec<_>>(),
            )
            .field(
                "committed_mesh",
                &self.committed.mesh.as_ref().map(|(id, _)| *id),
            )
            .field("holds", &self.holds.len())
            .finish()
    }
}

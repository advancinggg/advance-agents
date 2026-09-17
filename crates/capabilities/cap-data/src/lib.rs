//! `cap-data` — the structured-data capability behind the `data` host tool (the internal
//! entity-data lane plan §2.6).
//!
//! Structured data lives ONLY in frontmatter; SQLite is a derived projection. This crate is
//! the operations layer on top of cap-fs's representation (frontmatter codec, meta-schema v2,
//! entity projection) and the [`EntityIndex`] port:
//!
//! - [`DataStore`]: `describe` / `query` / `get` / `create` / `patch` / `promote` / `demote` /
//!   `history` / `apply`, every write running the ONE host-owned transaction — lock the path →
//!   read → compute the new document → `normalize` (types, enums, transitions, derived fields,
//!   `ensure`) → canonical write + commit → index → one `data.entity_changed` event. Any failure
//!   leaves the file untouched and emits nothing.
//! - `apply`: a pack's pure WASM tool turns `{ op, self, parent, args, now, ids }` into an
//!   effect list (`set` / `unset` / `create` / `promote` / `demote`) the host applies atomically;
//!   the reducer never touches storage and runs under a frozen clock + seed.
//! - [`DataTool`]: the [`cap_tools::HostTool`] registered under id `data`, so agents reach all
//!   of it through the ordinary `tool-invoke` switchboard (there is deliberately NO WIT
//!   interface and NO new `KNOWN_CAPABILITIES` entry).

#![forbid(unsafe_code)]

pub mod effects;
pub mod store;
pub mod tool;

#[cfg(any(test, feature = "test-support"))]
pub mod test_support;

pub use cap_fs::frontmatter::MAX_ITEMS_PER_FILE;
pub use cap_tools::DeterministicCtx;
pub use effects::{
    Effect, MAX_EFFECTS_PER_APPLY, MAX_REDUCER_INPUT_BYTES, MAX_REDUCER_OUTPUT_BYTES,
};
pub use store::{
    ApplyResult, AspectDescription, Clock, DataError, DataStore, EntityIds, FieldDescription,
    FileVersion, IdempotencyKey, OperationDescription, PatchOp, PureReducer, QueryDescription,
    QueryRequest, ReceiptKind, Record, RecordVersion, SchemaDescription, SystemClock, Target, Tier,
    UlidEntityIds, ViewDescription, WorkspaceFs, WriteReceipt, IDS_PER_APPLY,
    MAX_IDEMPOTENCY_ENTRIES,
};
pub use tool::DataTool;

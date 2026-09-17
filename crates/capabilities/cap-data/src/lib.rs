//! `cap-data` — the structured-data capability behind the `data` host tool.
//!
//! Skeleton crate reserved by `the internal entity-data lane plan` (v2). Lane E1 fills it with:
//! - `DataStore`: `describe` / `query` / `get` / `create` / `patch` / `promote` / `demote` /
//!   `history` / `apply` over the workspace filesystem, the `EntityIndex` port and the workspace
//!   meta-schema, every write running the one host-owned transaction (lock → validate →
//!   canonical write → one commit → index → one `data.entity_changed` event);
//! - `apply`: a pack tool (pure WASM) turns `{ self, args, now, ids }` into an effect list the
//!   host applies atomically — the reducer never touches storage;
//! - `DataTool`: the `HostTool` registered under id `data` (cap-tools P2 seat), so agents reach
//!   all of it through the ordinary `tool-invoke` switchboard and clients through `/client/entities`.
//!
//! There is deliberately NO WIT interface and NO new `KNOWN_CAPABILITIES` entry: `data` is a tool.
//! The entity model (one record shape across file frontmatter, inline `items[]` and `index.md`),
//! the three storage tiers, the `agenda` aspect and the schema-v2 invariants are the contract;
//! see the plan §1–§2. Until lane E1 lands this crate intentionally exports nothing.

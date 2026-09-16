//! `cap-data` — the structured-data capability (`data`).
//!
//! Skeleton crate reserved for the structured-data lane. Lane E1 fills it with:
//! - [`DataStore`]-style operations (`create` / `patch` / `get` / `query` / `promote` /
//!   `demote` / `history`) over the workspace filesystem, the `EntityIndex` port and the
//!   workspace meta-schema;
//! - the `agent-data` WIT host functions registered under capability `"data"`.
//!
//! The entity model (one record shape across file frontmatter, inline `items[]` and
//! `index.md`), the three storage tiers and the host-owned canonical frontmatter rules are the
//! contract; see the plan §1–§2. Until lane E1 lands this crate intentionally exports nothing.

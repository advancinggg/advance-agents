//! MODULE-023 GenUI — A2UI document model, vetted component catalog, and validation gate.
//!
//! Protocol version pin: **A2UI v0.9.1** (v1.0-RC tracked; pinned at first slice per
//! ADR 2026-07-16-genui-a2ui-adoption).

pub mod catalog;
pub mod corpus;
pub mod degrade;
pub mod document;
pub mod error;
pub mod seed;

pub use catalog::{
    ActionEntry, ActionRef, CatalogEntry, ComponentCatalog, ConfirmMetadata, ConfirmVariant,
    DefaultCatalog, GenUiGate, ValidationOutcome,
};
pub use document::{A2uiVersion, ComponentNode, DocumentId, GenUiDocument};
pub use error::GenUiError;
pub use seed::seed_catalog;

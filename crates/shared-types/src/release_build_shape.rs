//! Release build-shape facts for a future ship job (H2 — memo only).
//!
//! This module holds no items. It exists so the facts stay in-tree next to
//! the rest of the OSS engineering notes (crate rustdoc). Do **not** add a
//! `release-dist` Cargo profile until a real ship CI job exists.
//!
//! The current `[profile.release]` (overflow-checks, thin LTO, codegen-units
//! = 1, strip = true) is unchanged by this lane. `panic = "unwind"` stays
//! (Round-4 rollback is binding; recorded in the workspace `Cargo.toml`
//! comment at the start of the release-profile hardening notes, currently
//! around the `ulid` workspace pin).
//!
//! When a ship job is added it must:
//!
//! 1. Extract `.debug` / `.dSYM` **before** the final strip, and archive
//!    those symbols with the release (post-crash backtraces on mesh/cloud
//!    nodes).
//! 2. Enable full RELRO + `noexecstack` (platform equivalents) on every
//!    ship target.
//! 3. Treat `RUSTFLAGS` as **not additive** across layers — the ship job
//!    sets the final flag set in one place.
//! 4. Keep `panic = "unwind"`. Do not reopen `abort`.
//! 5. Not invent a `release-dist` profile until that job exists.

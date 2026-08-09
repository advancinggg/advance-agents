// Process-global lifecycle trade-off: `sqlite3_auto_extension` is the
// upstream-blessed integration pattern for sqlite-vec (see
// alexgarcia.xyz/sqlite-vec/rust.html). Once registered, EVERY subsequent
// `sqlite3_open*` call in the process (including connections opened by
// unrelated crates that may later land in this workspace, or direct rusqlite
// users in tests) will auto-load the vec0 module. We accept this as the
// least-bad option because:
//   - Per-connection load via `sqlite3_load_extension` requires
//     `SQLITE_LOAD_EXTENSION` to be enabled, widening the runtime's attack
//     surface for arbitrary extension load.
//   - sqlite-vec is statically linked (the C source is bundled into the
//     `sqlite-vec` Rust crate and compiled in), so no external `.dylib`
//     filesystem lookup happens; the registered fn pointer is process-local
//     code, not externally controllable.
//   - `Once::call_once` ensures we register exactly once, eliminating
//     re-registration races across parallel test threads.
// If a future sqlite-vec API exposes per-connection registration, prefer it.
//
// ABI fragility: `sqlite-vec = =0.1.7-alpha.2` is exact-pinned. The transmute
// below relies on `sqlite3_vec_init`'s C ABI matching the
// `sqlite3_auto_extension` callback shape (the SQLite extension entry-point
// convention). A silent ABI change in a future sqlite-vec publish would turn
// this transmute into UB — exact-pin is the gating defense, plus the
// `cargo audit` / `cargo deny` CI gate tracked as a follow-up in the
// workspace `Cargo.toml` SUPPLY CHAIN FOLLOW-UP comment.

use std::sync::OnceLock;

use crate::error::DbError;

// `OnceLock<Result<(), String>>` instead of `Once<()>` so the status code from
// `sqlite3_auto_extension` is captured and surfaced to the caller. A failed
// registration would otherwise be silently latched as "done" (Once never
// retries), and subsequent migrations would crash on `CREATE VIRTUAL TABLE
// ... USING vec0` with no actionable diagnostic. Capturing the status lets us
// fail fast at handle construction time.
static REGISTRATION: OnceLock<Result<(), String>> = OnceLock::new();

#[allow(unsafe_code)]
// clippy 1.91+ flags this transmute under `clippy::missing_transmute_annotations`,
// but the upstream sqlite-vec integration pattern (alexgarcia.xyz/sqlite-vec/rust.html)
// relies on the inline form so Rust target-infers the function-pointer signature
// from `sqlite3_auto_extension`'s parameter type. Spelling the type explicitly
// would re-import private libsqlite3-sys symbols that aren't part of rusqlite's
// public re-export surface. The lint is silenced here scope-locally.
#[allow(clippy::missing_transmute_annotations)]
pub(crate) fn register_sqlite_vec_extension() -> Result<(), DbError> {
    let result = REGISTRATION.get_or_init(|| unsafe {
        let rc = rusqlite::ffi::sqlite3_auto_extension(Some(std::mem::transmute(
            sqlite_vec::sqlite3_vec_init as *const (),
        )));
        if rc == 0 {
            Ok(())
        } else {
            Err(format!(
                "sqlite3_auto_extension returned non-zero status: {rc}"
            ))
        }
    });

    match result {
        Ok(()) => Ok(()),
        Err(msg) => Err(DbError::InvalidConfig(format!(
            "sqlite-vec extension registration failed: {msg}"
        ))),
    }
}

//! CONTRACT-190 — API version negotiation. An unknown `api_version` fails closed with
//! `unsupported_api_version` **before any provider call** (§1.4.1).

use crate::envelope::{ClientError, ClientErrorCode, API_VERSION};

/// Every `api_version` this build accepts. A date string outside this set is rejected.
pub const SUPPORTED_VERSIONS: &[&str] = &[API_VERSION];

/// Upper bound on the accepted `api_version` string length. A date string is ~10 chars; this
/// bounds adversarial input before any comparison (defense-in-depth, cheap fail-closed).
pub const MAX_API_VERSION_LEN: usize = 32;

/// Returns `Ok(())` if `api_version` is supported, else a fail-closed
/// `unsupported_api_version` error carrying the supported range in `details`.
pub fn check_version(api_version: &str) -> Result<(), ClientError> {
    if api_version.len() <= MAX_API_VERSION_LEN && SUPPORTED_VERSIONS.contains(&api_version) {
        return Ok(());
    }
    Err(ClientError::new(
        ClientErrorCode::UnsupportedApiVersion,
        "unsupported api_version",
    )
    .with_details(
        SUPPORTED_VERSIONS
            .iter()
            .map(|v| (*v).to_string())
            .collect(),
    ))
}

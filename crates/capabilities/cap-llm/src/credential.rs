//! Credential freshness seam for provider entries whose credential is not an API key the
//! operator entered.
//!
//! The gateway never renews a credential itself. Before a cloud dispatch for such an entry it
//! asks the installed [`ProviderCredentialSource`] to make sure the secret stored under the
//! entry's `api-key-secret` name is usable for the next request. The egress chain resolves that
//! secret on every request, so a value the source has just stored is the one the request carries.
//!
//! Failures are a closed set of fixed reasons: nothing an identity provider answered and no
//! credential material ever travels through this seam.

use async_trait::async_trait;

/// Why an entry's credential cannot be used right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialFailure {
    /// There is no usable sign-in for the entry: never signed in, signed out, or the renewable
    /// session ended and the user has to sign in again.
    NotSignedIn,
    /// A sign-in exists but it does not carry the permission inference needs.
    NotAuthorized,
    /// The credential expired and could not be renewed right now (network or identity-provider
    /// trouble). The stored session is kept; a later call may succeed.
    RefreshUnavailable,
    /// The source cannot serve this entry at all (for example no live secret store).
    Unavailable,
}

impl CredentialFailure {
    /// The fixed token for this failure.
    pub fn as_str(self) -> &'static str {
        match self {
            CredentialFailure::NotSignedIn => "not-signed-in",
            CredentialFailure::NotAuthorized => "not-authorized",
            CredentialFailure::RefreshUnavailable => "refresh-unavailable",
            CredentialFailure::Unavailable => "unavailable",
        }
    }
}

/// The port the gateway consults before a cloud dispatch for an entry whose
/// `auth-source` is not `api-key`. Implementations own the secret store handle and the renewal
/// protocol; they must serialize renewals for the same secret name.
#[async_trait]
pub trait ProviderCredentialSource: Send + Sync {
    /// Make sure the secret under `secret_name` holds a credential that is valid for the next
    /// request of provider entry `provider_id`, renewing it first when it is about to expire.
    async fn ensure_fresh(
        &self,
        provider_id: &str,
        secret_name: &str,
    ) -> Result<(), CredentialFailure>;

    /// The upstream refused the credential the last request carried (an authentication failure
    /// on the entry). The source should renew on the next [`Self::ensure_fresh`] regardless of
    /// the recorded expiry. The default does nothing.
    async fn credential_rejected(&self, provider_id: &str, secret_name: &str) {
        let _ = (provider_id, secret_name);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failure_tokens_are_fixed_and_distinct() {
        let all = [
            CredentialFailure::NotSignedIn,
            CredentialFailure::NotAuthorized,
            CredentialFailure::RefreshUnavailable,
            CredentialFailure::Unavailable,
        ];
        let tokens: Vec<&str> = all.iter().map(|f| f.as_str()).collect();
        assert_eq!(
            tokens,
            vec![
                "not-signed-in",
                "not-authorized",
                "refresh-unavailable",
                "unavailable"
            ]
        );
    }
}

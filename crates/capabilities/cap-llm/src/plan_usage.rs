//! The closed vocabulary of failures specific to a provider entry whose credential is a
//! Sign in with ChatGPT session (`auth-source: chatgpt-oauth`).
//!
//! Every reason is a fixed string of the form `"chatgpt-plan: <fixed words>"`, carried as an
//! [`LlmError::ProviderError`] payload. Nothing the upstream answered is ever copied into a
//! reason: an upstream `code` only SELECTS one of the fixed reasons through a closed table, and
//! an unknown code selects none.
//!
//! All of these failures are non-retryable (none is on the transport whitelist of
//! [`crate::retry::classify_retryable`]) and all of them let the placement walker move on to
//! the next endpoint while no token has been spent
//! ([`crate::placement::is_pre_token_failover`]).

use serde_json::Value;

use crate::credential::CredentialFailure;
use crate::error::LlmError;

/// Prefix shared by every reason in this module.
pub const PLAN_USAGE_PREFIX: &str = "chatgpt-plan:";

/// There is no usable sign-in for the entry (never signed in, signed out, or the session ended).
pub const NOT_SIGNED_IN: &str = "chatgpt-plan: not signed in";
/// A sign-in exists but does not carry the permission to use the plan for inference.
pub const NOT_AUTHORIZED: &str = "chatgpt-plan: plan usage not authorized";
/// The credential expired and could not be renewed right now.
pub const REFRESH_UNAVAILABLE: &str = "chatgpt-plan: credential refresh unavailable";
/// No credential source can serve the entry in this process.
pub const SOURCE_NOT_WIRED: &str = "chatgpt-plan: credential source not wired";
/// The upstream refused the credential the request carried.
pub const SIGN_IN_REJECTED: &str = "chatgpt-plan: sign-in rejected";
/// The upstream refused the request for a policy or permission reason.
pub const REQUEST_NOT_PERMITTED: &str = "chatgpt-plan: request not permitted";
/// The plan's (or this app's) usage limit is reached.
pub const USAGE_LIMIT_REACHED: &str = "chatgpt-plan: usage limit reached";
/// Plan usage is unavailable for the signed-in account, workspace or policy.
pub const ACCOUNT_NOT_ELIGIBLE: &str = "chatgpt-plan: account not eligible";
/// The request used an input, tool, model or option the plan route does not accept.
pub const UNSUPPORTED_CAPABILITY: &str = "chatgpt-plan: unsupported capability";
/// The request targeted a method or endpoint the plan route does not serve.
pub const ROUTE_NOT_SUPPORTED: &str = "chatgpt-plan: route not supported";
/// The entry only accepts streamed requests and the call site offered an unstreamed one.
pub const STREAMED_TRANSPORT_REQUIRED: &str = "chatgpt-plan: streamed transport required";

/// Whether a `ProviderError` message is one of this module's reasons.
pub fn is_plan_usage_error(message: &str) -> bool {
    message.starts_with(PLAN_USAGE_PREFIX)
}

/// The error value for one of this module's reasons.
pub(crate) fn plan_error(reason: &'static str) -> LlmError {
    LlmError::ProviderError(reason.to_string())
}

/// Whether `err` is the "sign-in rejected" outcome — the one the credential source is told
/// about so its next freshness check renews regardless of the recorded expiry.
pub(crate) fn is_sign_in_rejected(err: &LlmError) -> bool {
    matches!(err, LlmError::ProviderError(msg) if msg == SIGN_IN_REJECTED)
}

/// The reason for a failed freshness check.
pub(crate) fn reason_for_credential_failure(failure: CredentialFailure) -> &'static str {
    match failure {
        CredentialFailure::NotSignedIn => NOT_SIGNED_IN,
        CredentialFailure::NotAuthorized => NOT_AUTHORIZED,
        CredentialFailure::RefreshUnavailable => REFRESH_UNAVAILABLE,
        CredentialFailure::Unavailable => SOURCE_NOT_WIRED,
    }
}

/// The reason an upstream error `code` selects, if it is one of the plan-usage codes.
///
/// The two temporary-unavailability codes are deliberately absent: they arrive with a 5xx
/// status and stay an ordinary upstream failure, which is retried with backoff.
pub(crate) fn reason_for_upstream_code(code: &str) -> Option<&'static str> {
    match code {
        "subscription_sharing_usage_limit_exceeded" => Some(USAGE_LIMIT_REACHED),
        "subscription_sharing_user_not_eligible" => Some(ACCOUNT_NOT_ELIGIBLE),
        "subscription_sharing_unsupported_capability" => Some(UNSUPPORTED_CAPABILITY),
        "subscription_sharing_route_not_supported" => Some(ROUTE_NOT_SUPPORTED),
        "subscription_sharing_invalid_user" => Some(SIGN_IN_REJECTED),
        "chatpass_v2_scope_not_authorized" | "chatpass_v2_invalid_authorization_context" => {
            Some(NOT_AUTHORIZED)
        }
        _ => None,
    }
}

/// Best-effort lookup of a plan-usage code in a non-200 response body
/// (`{"error": {"code": ..}}`). A body that is not JSON, or one without a string code — such
/// as the `{"detail": ..}` shape — selects nothing.
pub(crate) fn reason_for_error_body(body: &[u8]) -> Option<&'static str> {
    let value: Value = serde_json::from_slice(body).ok()?;
    reason_for_upstream_code(value.get("error")?.get("code")?.as_str()?)
}

/// Best-effort lookup of a plan-usage code in the data of an in-band error or failed-response
/// stream event. The code may sit at `response.error.code`, `error.code` or top-level `code`.
pub(crate) fn reason_for_event_data(data: &str) -> Option<&'static str> {
    let value: Value = serde_json::from_str(data).ok()?;
    for code in [
        &value["response"]["error"]["code"],
        &value["error"]["code"],
        &value["code"],
    ] {
        if let Some(reason) = code.as_str().and_then(reason_for_upstream_code) {
            return Some(reason);
        }
    }
    None
}

/// The reason for an authentication (401) or permission (403) refusal that carried no
/// plan-usage code, on an entry whose credential is a sign-in session. Other statuses keep
/// their ordinary classification.
pub(crate) fn reason_for_refused_status(status: u16) -> Option<&'static str> {
    match status {
        401 => Some(SIGN_IN_REJECTED),
        403 => Some(REQUEST_NOT_PERMITTED),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_REASONS: [&str; 11] = [
        NOT_SIGNED_IN,
        NOT_AUTHORIZED,
        REFRESH_UNAVAILABLE,
        SOURCE_NOT_WIRED,
        SIGN_IN_REJECTED,
        REQUEST_NOT_PERMITTED,
        USAGE_LIMIT_REACHED,
        ACCOUNT_NOT_ELIGIBLE,
        UNSUPPORTED_CAPABILITY,
        ROUTE_NOT_SUPPORTED,
        STREAMED_TRANSPORT_REQUIRED,
    ];

    #[test]
    fn every_reason_is_prefixed_fixed_and_distinct() {
        let mut seen = std::collections::HashSet::new();
        for reason in ALL_REASONS {
            assert!(is_plan_usage_error(reason), "{reason}");
            let words = reason
                .strip_prefix(PLAN_USAGE_PREFIX)
                .and_then(|rest| rest.strip_prefix(' '))
                .unwrap_or_else(|| panic!("{reason} must be \"<prefix> <words>\""));
            assert!(!words.is_empty() && words == words.trim(), "{reason}");
            assert!(seen.insert(reason), "duplicate reason {reason}");
            assert_eq!(
                plan_error(reason),
                LlmError::ProviderError(reason.to_string())
            );
        }
        assert_eq!(
            ALL_REASONS,
            [
                "chatgpt-plan: not signed in",
                "chatgpt-plan: plan usage not authorized",
                "chatgpt-plan: credential refresh unavailable",
                "chatgpt-plan: credential source not wired",
                "chatgpt-plan: sign-in rejected",
                "chatgpt-plan: request not permitted",
                "chatgpt-plan: usage limit reached",
                "chatgpt-plan: account not eligible",
                "chatgpt-plan: unsupported capability",
                "chatgpt-plan: route not supported",
                "chatgpt-plan: streamed transport required",
            ]
        );
    }

    #[test]
    fn prefix_predicate_matches_only_this_vocabulary() {
        assert!(is_plan_usage_error("chatgpt-plan: usage limit reached"));
        assert!(is_plan_usage_error("chatgpt-plan:"));
        for other in [
            "",
            "auth failed",
            "rate limited",
            "upstream 503",
            "agent-cli: not signed in",
            "stream-partial: chatgpt-plan: sign-in rejected",
            " chatgpt-plan: not signed in",
            "chatgpt-plan",
            "ChatGPT-plan: not signed in",
        ] {
            assert!(!is_plan_usage_error(other), "{other:?}");
        }
    }

    #[test]
    fn upstream_code_table_is_closed() {
        let table = [
            (
                "subscription_sharing_usage_limit_exceeded",
                USAGE_LIMIT_REACHED,
            ),
            (
                "subscription_sharing_user_not_eligible",
                ACCOUNT_NOT_ELIGIBLE,
            ),
            (
                "subscription_sharing_unsupported_capability",
                UNSUPPORTED_CAPABILITY,
            ),
            (
                "subscription_sharing_route_not_supported",
                ROUTE_NOT_SUPPORTED,
            ),
            ("subscription_sharing_invalid_user", SIGN_IN_REJECTED),
            ("chatpass_v2_scope_not_authorized", NOT_AUTHORIZED),
            ("chatpass_v2_invalid_authorization_context", NOT_AUTHORIZED),
        ];
        for (code, reason) in table {
            assert_eq!(reason_for_upstream_code(code), Some(reason), "{code}");
        }
        // Temporary unavailability stays an ordinary (retried) upstream failure; anything
        // else — including near-misses — selects nothing.
        for code in [
            "subscription_sharing_usage_unavailable",
            "subscription_sharing_user_unavailable",
            "",
            "rate_limit_exceeded",
            "invalid_api_key",
            "SUBSCRIPTION_SHARING_USAGE_LIMIT_EXCEEDED",
            "subscription_sharing_usage_limit_exceeded ",
            "subscription_sharing_",
        ] {
            assert_eq!(reason_for_upstream_code(code), None, "{code:?}");
        }
    }

    #[test]
    fn credential_failures_map_to_fixed_reasons() {
        let table = [
            (CredentialFailure::NotSignedIn, NOT_SIGNED_IN),
            (CredentialFailure::NotAuthorized, NOT_AUTHORIZED),
            (CredentialFailure::RefreshUnavailable, REFRESH_UNAVAILABLE),
            (CredentialFailure::Unavailable, SOURCE_NOT_WIRED),
        ];
        for (failure, reason) in table {
            assert_eq!(reason_for_credential_failure(failure), reason);
            assert!(is_plan_usage_error(reason_for_credential_failure(failure)));
        }
    }

    #[test]
    fn body_and_event_lookups_are_best_effort() {
        assert_eq!(
            reason_for_error_body(
                br#"{"error":{"code":"subscription_sharing_usage_limit_exceeded","message":"m"}}"#
            ),
            Some(USAGE_LIMIT_REACHED)
        );
        for body in [
            &br#"{"detail":"subscription_sharing_usage_limit_exceeded"}"#[..],
            br#"{"error":{"code":429}}"#,
            br#"{"error":{"type":"subscription_sharing_usage_limit_exceeded"}}"#,
            br#"{"error":"subscription_sharing_usage_limit_exceeded"}"#,
            br#"{"code":"subscription_sharing_usage_limit_exceeded"}"#,
            b"subscription_sharing_usage_limit_exceeded",
            b"",
        ] {
            assert_eq!(reason_for_error_body(body), None);
        }

        for data in [
            r#"{"type":"response.failed","response":{"error":{"code":"subscription_sharing_invalid_user"}}}"#,
            r#"{"type":"error","error":{"code":"subscription_sharing_invalid_user"}}"#,
            r#"{"type":"error","code":"subscription_sharing_invalid_user","message":"m"}"#,
        ] {
            assert_eq!(
                reason_for_event_data(data),
                Some(SIGN_IN_REJECTED),
                "{data}"
            );
        }
        for data in [
            r#"{"type":"response.failed","response":{"error":{"code":"server_error"}}}"#,
            r#"{"type":"error","message":"subscription_sharing_invalid_user"}"#,
            "[DONE]",
            "",
        ] {
            assert_eq!(reason_for_event_data(data), None, "{data}");
        }
    }

    #[test]
    fn refused_statuses_and_the_rejection_predicate() {
        assert_eq!(reason_for_refused_status(401), Some(SIGN_IN_REJECTED));
        assert_eq!(reason_for_refused_status(403), Some(REQUEST_NOT_PERMITTED));
        for status in [200, 400, 404, 429, 500, 503] {
            assert_eq!(reason_for_refused_status(status), None, "{status}");
        }
        assert!(is_sign_in_rejected(&plan_error(SIGN_IN_REJECTED)));
        assert!(!is_sign_in_rejected(&plan_error(REQUEST_NOT_PERMITTED)));
        assert!(!is_sign_in_rejected(&LlmError::RateLimited(
            SIGN_IN_REJECTED.into()
        )));
        assert!(!is_sign_in_rejected(&LlmError::ProviderError(
            "auth failed".into()
        )));
    }

    #[test]
    fn plan_errors_are_never_retried_and_always_fail_over_before_tokens() {
        for reason in ALL_REASONS {
            let err = plan_error(reason);
            assert!(!crate::retry::classify_retryable(&err), "{reason}");
            assert!(crate::placement::is_pre_token_failover(&err), "{reason}");
        }
    }
}

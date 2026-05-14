use serde::{Deserialize, Serialize};

// ── Short-lived token response ────────────────────────────────────────────────

/// A single entry inside the `data` array returned by
/// `POST https://api.instagram.com/oauth/access_token`.
///
/// This token is **short-lived** (valid for 1 hour). Exchange it for a
/// [`LongLivedToken`] using [`InstagramOAuthClient::exchange_for_long_lived`].
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ShortLivedToken {
    /// Bearer token valid for **1 hour**.
    pub access_token: String,

    /// The Instagram-scoped user ID for your app user.
    ///
    /// This is the stable per-user, per-app identity — store it alongside the
    /// tokens and use it to identify the linked Instagram account.
    pub user_id: String,

    /// Comma-separated list of permissions the app user granted.
    pub permissions: Option<String>,
}

/// The outer envelope returned by `POST https://api.instagram.com/oauth/access_token`.
///
/// On success the `data` array contains exactly one [`ShortLivedToken`].
/// On error the `error_type`, `code`, and `error_message` fields are populated.
#[derive(Debug, Deserialize)]
pub(crate) struct ShortLivedTokenEnvelope {
    /// Present on success; contains the issued token data.
    pub data: Option<Vec<ShortLivedToken>>,

    /// Present on error.
    pub error_type: Option<String>,
    /// HTTP-style status code on error.
    pub code: Option<u16>,
    /// Human-readable error description.
    pub error_message: Option<String>,
}

// ── Long-lived token response ─────────────────────────────────────────────────

/// The response from:
/// - `GET https://graph.instagram.com/access_token` (short → long exchange), and
/// - `GET https://graph.instagram.com/refresh_access_token` (long-lived refresh).
///
/// Long-lived tokens are valid for **60 days** and must be refreshed before
/// they expire using [`InstagramOAuthClient::refresh_long_lived`].
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LongLivedToken {
    /// Bearer token valid for approximately **60 days**.
    pub access_token: String,

    /// Always `"bearer"`.
    pub token_type: String,

    /// Seconds until this token expires.
    pub expires_in: u64,
}

// ── Error response ────────────────────────────────────────────────────────────

/// Error body returned by Graph API token endpoints.
#[derive(Debug, Deserialize)]
pub(crate) struct GraphApiError {
    pub error: Option<GraphApiErrorBody>,

    // Long-lived / refresh endpoints can also return flat error fields.
    pub error_type: Option<String>,
    pub code: Option<u16>,
    pub error_message: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct GraphApiErrorBody {
    pub message: String,
    pub r#type: Option<String>,
    pub code: Option<u16>,
}

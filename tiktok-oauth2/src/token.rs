use serde::{Deserialize, Serialize};

/// The inner `data` payload from a successful TikTok token response.
///
/// TikTok wraps all token responses in a `{ data: {…}, error: {…} }` envelope.
/// This struct represents the `data` field when `error.code == "ok"`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TikTokTokenData {
    /// Bearer token used to authenticate API requests.
    pub access_token: String,

    /// Token type — always `"Bearer"` for TikTok OAuth 2.
    pub token_type: String,

    /// Seconds until the access token expires.
    pub expires_in: u64,

    /// TikTok's stable per-user, per-app identifier.
    ///
    /// This is the canonical user identity for TikTok — store it alongside
    /// the tokens and use it to identify the linked TikTok account.
    pub open_id: String,

    /// Seconds until the refresh token expires.
    pub refresh_expires_in: Option<u64>,

    /// Refresh token (use to obtain a new access token before expiry).
    pub refresh_token: Option<String>,

    /// Comma-separated list of scopes actually granted.
    pub scope: Option<String>,
}

/// The outer envelope returned by TikTok's `/v2/oauth/token/` endpoint.
///
/// Success is indicated by `error.code == "ok"`. On failure `data` will be
/// empty and `error` will carry the reason.
#[derive(Debug, Deserialize)]
pub(crate) struct TikTokTokenEnvelope {
    /// Token payload — populated on success, empty on error.
    #[serde(default)]
    pub data: Option<TikTokTokenData>,

    /// Error descriptor — always present; `code == "ok"` means success.
    pub error: TikTokTokenErrorBody,
}

/// The `error` sub-object inside every TikTok token response.
#[derive(Debug, Deserialize)]
pub(crate) struct TikTokTokenErrorBody {
    /// `"ok"` on success; an error code string on failure.
    pub code: String,
    /// Human-readable message accompanying the error code.
    #[serde(default)]
    pub message: String,
}

/// PKCE proof-key pair generated locally before the authorization request.
#[derive(Debug, Clone)]
pub struct TikTokPkceChallenge {
    /// The random secret sent to the token endpoint.
    pub(crate) code_verifier: String,
    /// SHA-256 hash of `code_verifier`, base64url-encoded (sent in the auth URL).
    pub(crate) code_challenge: String,
}

impl TikTokPkceChallenge {
    /// Returns the `code_challenge` value to embed in the authorization URL.
    pub fn challenge(&self) -> &str {
        &self.code_challenge
    }

    /// Returns the `code_verifier` to send to the token endpoint.
    pub fn verifier(&self) -> &str {
        &self.code_verifier
    }
}

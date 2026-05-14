use serde::{Deserialize, Serialize};

/// Successful token response from X's `/2/oauth2/token` endpoint.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TokenResponse {
    /// Bearer token used to authenticate API requests.
    pub access_token: String,

    /// Token type — always `"bearer"` for X OAuth 2.
    pub token_type: String,

    /// Seconds until the access token expires (present when `offline.access`
    /// scope is NOT requested).
    pub expires_in: Option<u64>,

    /// Refresh token (only present when `offline.access` scope was requested).
    pub refresh_token: Option<String>,

    /// Space-separated list of scopes that were actually granted.
    pub scope: Option<String>,
}

/// Refreshed token response — structurally identical to [`TokenResponse`].
#[allow(dead_code)]
pub type RefreshedTokenResponse = TokenResponse;

/// Error body returned by X's token endpoint on failure.
#[derive(Debug, Deserialize)]
pub(crate) struct TokenErrorResponse {
    pub error: String,
    #[serde(default)]
    pub error_description: String,
}

/// PKCE proof-key pair generated locally before the authorization request.
#[derive(Debug, Clone)]
pub struct PkceChallenge {
    /// The random secret sent to the token endpoint.
    pub(crate) code_verifier: String,
    /// SHA-256 hash of `code_verifier`, base64url-encoded (sent in the auth URL).
    pub(crate) code_challenge: String,
}

impl PkceChallenge {
    /// Returns the `code_challenge` value to embed in the authorization URL.
    pub fn challenge(&self) -> &str {
        &self.code_challenge
    }

    /// Returns the `code_verifier` to send to the token endpoint.
    pub fn verifier(&self) -> &str {
        &self.code_verifier
    }
}

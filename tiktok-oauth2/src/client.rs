//! TikTok LoginKit OAuth 2.0 + PKCE client implementation.
//!
//! See [`TikTokOAuthClient`] for the entry point and the crate-level docs for
//! an end-to-end usage example.
//!
//! ## Key differences from the X (Twitter) client
//!
//! | Aspect | X | TikTok |
//! |---|---|---|
//! | Client identity param | `client_id` | `client_key` |
//! | Auth credentials placement | HTTP Basic auth | POST body |
//! | Scope separator | space | comma |
//! | Token response shape | flat JSON | `{ data: {…}, error: {…} }` |
//! | User identity field | none (use auth session) | `open_id` |
//! | Secret required | optional (public clients) | always required |

use std::collections::HashMap;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::Rng;
use sha2::{Digest, Sha256};
use url::Url;

use crate::{
    error::{Result, TikTokOAuthError},
    token::{TikTokPkceChallenge, TikTokTokenData, TikTokTokenEnvelope},
};

// TikTok LoginKit v2 OAuth 2.0 endpoints
const AUTH_URL: &str = "https://www.tiktok.com/v2/auth/authorize/";
const TOKEN_URL: &str = "https://open.tiktokapis.com/v2/oauth/token/";
const REVOKE_URL: &str = "https://open.tiktokapis.com/v2/oauth/revoke/";

/// Configuration for the TikTok LoginKit OAuth 2.0 client.
///
/// TikTok requires a `client_secret` for all server-side OAuth flows — there
/// is no public (secret-less) variant for the Authorization Code grant.
#[derive(Debug, Clone)]
pub struct TikTokOAuthConfig {
    /// Your app's Client Key from the TikTok Developer Portal.
    ///
    /// Note: TikTok calls this `client_key`, not `client_id`.
    pub client_key: String,
    /// Your app's Client Secret from the TikTok Developer Portal.
    pub client_secret: String,
    /// The redirect URI registered in the TikTok Developer Portal.
    pub redirect_uri: String,
    /// Requested OAuth 2.0 scopes (e.g. `["user.info.basic", "user.info.stats"]`).
    ///
    /// Scopes are sent to TikTok as a comma-separated string.
    pub scopes: Vec<String>,
}

impl TikTokOAuthConfig {
    /// Create a new TikTok OAuth configuration.
    pub fn new(
        client_key: impl Into<String>,
        client_secret: impl Into<String>,
        redirect_uri: impl Into<String>,
        scopes: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            client_key: client_key.into(),
            client_secret: client_secret.into(),
            redirect_uri: redirect_uri.into(),
            scopes: scopes.into_iter().map(Into::into).collect(),
        }
    }
}

/// Main OAuth 2.0 client for TikTok LoginKit.
///
/// # Typical PKCE flow
///
/// 1. Call [`TikTokOAuthClient::authorization_url`] to get the URL and PKCE state.
/// 2. Redirect the user to that URL.
/// 3. TikTok redirects back to your `redirect_uri` with `?code=…&state=…`.
/// 4. Call [`TikTokOAuthClient::exchange_code`] with the returned code, state,
///    and the original PKCE state from step 1.
/// 5. Store the returned [`TikTokTokenData`], including `open_id` as the stable
///    user identity for TikTok.
/// 6. Call [`TikTokOAuthClient::refresh_token`] before the access token expires.
#[derive(Debug, Clone)]
pub struct TikTokOAuthClient {
    config: TikTokOAuthConfig,
    http: reqwest::Client,
}

impl TikTokOAuthClient {
    /// Create a new client with the given configuration.
    #[must_use]
    pub fn new(config: TikTokOAuthConfig) -> Self {
        Self {
            config,
            http: reqwest::Client::new(),
        }
    }

    /// Generate a random PKCE code verifier + challenge pair.
    ///
    /// The challenge method is always `S256` (SHA-256), as required by TikTok.
    #[must_use]
    pub fn generate_pkce() -> TikTokPkceChallenge {
        let verifier: String = rand::thread_rng()
            .sample_iter(rand::distributions::Alphanumeric)
            .take(64)
            .map(char::from)
            .collect();

        let hash = Sha256::digest(verifier.as_bytes());
        let challenge = URL_SAFE_NO_PAD.encode(hash);

        TikTokPkceChallenge {
            code_verifier: verifier,
            code_challenge: challenge,
        }
    }

    /// Build the authorization URL the user must visit plus the PKCE state.
    ///
    /// The returned `state` string is a random value that **must** be stored
    /// and verified when TikTok calls back to your redirect URI.
    ///
    /// TikTok's authorization URL uses `client_key` (not `client_id`) and
    /// joins scopes with commas (not spaces).
    ///
    /// # Returns
    /// `(authorization_url, state_string, pkce_challenge)`
    ///
    /// # Errors
    ///
    /// Returns [`TikTokOAuthError::UrlParse`] if the base auth URL is invalid.
    pub fn authorization_url(&self) -> Result<(String, String, TikTokPkceChallenge)> {
        let state = Self::random_state();
        let pkce = Self::generate_pkce();

        let mut url = Url::parse(AUTH_URL)?;
        url.query_pairs_mut()
            .append_pair("client_key", &self.config.client_key)
            .append_pair("response_type", "code")
            // TikTok requires comma-separated scopes, not space-separated
            .append_pair("scope", &self.config.scopes.join(","))
            .append_pair("redirect_uri", &self.config.redirect_uri)
            .append_pair("state", &state)
            .append_pair("code_challenge", pkce.challenge())
            .append_pair("code_challenge_method", "S256");

        Ok((url.to_string(), state, pkce))
    }

    /// Exchange an authorization `code` for access / refresh tokens.
    ///
    /// TikTok credentials are sent in the POST body (not as HTTP Basic auth).
    ///
    /// # Parameters
    /// - `code` – the `code` query parameter from TikTok's callback.
    /// - `returned_state` – the `state` query parameter from TikTok's callback.
    /// - `original_state` – the state string returned by [`authorization_url`].
    /// - `pkce` – the [`TikTokPkceChallenge`] returned by [`authorization_url`].
    ///
    /// # Errors
    ///
    /// Returns [`TikTokOAuthError::StateMismatch`] if the state values don't
    /// match, or [`TikTokOAuthError::TokenEndpoint`] if TikTok returns a
    /// non-`ok` error code.
    ///
    /// [`authorization_url`]: TikTokOAuthClient::authorization_url
    pub async fn exchange_code(
        &self,
        code: &str,
        returned_state: &str,
        original_state: &str,
        pkce: &TikTokPkceChallenge,
    ) -> Result<TikTokTokenData> {
        if returned_state != original_state {
            return Err(TikTokOAuthError::StateMismatch {
                expected: original_state.to_owned(),
                got: returned_state.to_owned(),
            });
        }

        let mut params = HashMap::new();
        params.insert("grant_type", "authorization_code");
        params.insert("code", code);
        params.insert("redirect_uri", &self.config.redirect_uri);
        params.insert("code_verifier", pkce.verifier());
        // TikTok uses client_key/client_secret in the body, not HTTP Basic auth
        params.insert("client_key", &self.config.client_key);
        params.insert("client_secret", &self.config.client_secret);

        self.post_token(params).await
    }

    /// Use a refresh token to obtain a new access token.
    ///
    /// # Errors
    ///
    /// Returns [`TikTokOAuthError::TokenEndpoint`] if TikTok returns a non-`ok`
    /// error code.
    pub async fn refresh_token(&self, refresh_token: &str) -> Result<TikTokTokenData> {
        let mut params = HashMap::new();
        params.insert("grant_type", "refresh_token");
        params.insert("refresh_token", refresh_token);
        params.insert("client_key", &self.config.client_key);
        params.insert("client_secret", &self.config.client_secret);

        self.post_token(params).await
    }

    /// Revoke an access or refresh token.
    ///
    /// # Errors
    ///
    /// Returns [`TikTokOAuthError::TokenEndpoint`] if TikTok rejects the
    /// revocation request.
    pub async fn revoke_token(&self, token: &str) -> Result<()> {
        let mut params = HashMap::new();
        params.insert("token", token);
        params.insert("client_key", &self.config.client_key);
        params.insert("client_secret", &self.config.client_secret);

        let resp = self.http.post(REVOKE_URL).form(&params).send().await?;

        let envelope: TikTokTokenEnvelope = resp.json().await?;
        if envelope.error.code == "ok" {
            Ok(())
        } else {
            Err(TikTokOAuthError::TokenEndpoint {
                error: envelope.error.code,
                message: envelope.error.message,
            })
        }
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    /// POST to the token endpoint, unwrap TikTok's envelope, and return the
    /// inner [`TikTokTokenData`] on success.
    async fn post_token(&self, params: HashMap<&str, &str>) -> Result<TikTokTokenData> {
        let resp = self.http.post(TOKEN_URL).form(&params).send().await?;
        let envelope: TikTokTokenEnvelope = resp.json().await?;

        if envelope.error.code == "ok" {
            envelope.data.ok_or_else(|| TikTokOAuthError::TokenEndpoint {
                error: "empty_data".to_owned(),
                message: "TikTok returned ok but data payload was missing".to_owned(),
            })
        } else {
            Err(TikTokOAuthError::TokenEndpoint {
                error: envelope.error.code,
                message: envelope.error.message,
            })
        }
    }

    /// Generate a cryptographically random state parameter.
    fn random_state() -> String {
        rand::thread_rng()
            .sample_iter(rand::distributions::Alphanumeric)
            .take(32)
            .map(char::from)
            .collect()
    }
}

// ── callback parser ───────────────────────────────────────────────────────────

/// Parse the query parameters from TikTok's redirect callback URI.
///
/// Returns `(code, state)` or a [`TikTokOAuthError::InvalidCallback`] if either
/// parameter is absent. TikTok also sends `scopes` and `error` parameters which
/// are ignored here but may be inspected via the raw URL if needed.
///
/// # Errors
///
/// Returns [`TikTokOAuthError::InvalidCallback`] when `code` or `state` is
/// absent, or when TikTok includes an `error` parameter in the callback.
pub fn parse_callback(callback_url: &str) -> Result<(String, String)> {
    let url = Url::parse(callback_url)?;

    let mut code = None;
    let mut state = None;

    for (k, v) in url.query_pairs() {
        match k.as_ref() {
            "code" => code = Some(v.into_owned()),
            "state" => state = Some(v.into_owned()),
            "error" => {
                return Err(TikTokOAuthError::InvalidCallback(v.into_owned()));
            }
            _ => {}
        }
    }

    match (code, state) {
        (Some(c), Some(s)) => Ok((c, s)),
        (None, _) => Err(TikTokOAuthError::InvalidCallback(
            "missing `code` parameter".to_owned(),
        )),
        (_, None) => Err(TikTokOAuthError::InvalidCallback(
            "missing `state` parameter".to_owned(),
        )),
    }
}

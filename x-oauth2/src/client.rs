use std::collections::HashMap;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::Rng;
use sha2::{Digest, Sha256};
use url::Url;

use crate::{
    error::{Result, XOAuthError},
    token::{PkceChallenge, TokenErrorResponse, TokenResponse},
};

// X (Twitter) OAuth 2.0 endpoints
const AUTH_URL: &str = "https://twitter.com/i/oauth2/authorize";
const TOKEN_URL: &str = "https://api.twitter.com/2/oauth2/token";
const REVOKE_URL: &str = "https://api.twitter.com/2/oauth2/revoke";

/// Configuration for the X OAuth 2.0 client.
#[derive(Debug, Clone)]
pub struct XOAuthConfig {
    /// Your app's Client ID from the X Developer Portal.
    pub client_id: String,
    /// Your app's Client Secret (required for confidential clients / refresh).
    pub client_secret: Option<String>,
    /// The redirect URI registered in the X Developer Portal.
    pub redirect_uri: String,
    /// Requested OAuth 2.0 scopes (e.g. `["tweet.read", "users.read"]`).
    pub scopes: Vec<String>,
}

impl XOAuthConfig {
    /// Create a config for a public (PKCE-only) client.
    pub fn public(
        client_id: impl Into<String>,
        redirect_uri: impl Into<String>,
        scopes: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            client_id: client_id.into(),
            client_secret: None,
            redirect_uri: redirect_uri.into(),
            scopes: scopes.into_iter().map(Into::into).collect(),
        }
    }

    /// Create a config for a confidential client (has a client secret).
    pub fn confidential(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        redirect_uri: impl Into<String>,
        scopes: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            client_id: client_id.into(),
            client_secret: Some(client_secret.into()),
            redirect_uri: redirect_uri.into(),
            scopes: scopes.into_iter().map(Into::into).collect(),
        }
    }
}

/// Main OAuth 2.0 client for X.
///
/// # Typical PKCE flow
///
/// 1. Call [`XOAuthClient::authorization_url`] to get the URL and PKCE state.
/// 2. Redirect the user to that URL.
/// 3. X redirects back to your `redirect_uri` with `?code=…&state=…`.
/// 4. Call [`XOAuthClient::exchange_code`] with the returned code, state, and
///    the original PKCE state from step 1.
/// 5. Store the returned [`TokenResponse`].
/// 6. When the access token expires, call [`XOAuthClient::refresh_token`].
#[derive(Debug, Clone)]
pub struct XOAuthClient {
    config: XOAuthConfig,
    http: reqwest::Client,
}

impl XOAuthClient {
    /// Create a new client with the given configuration.
    pub fn new(config: XOAuthConfig) -> Self {
        Self {
            config,
            http: reqwest::Client::new(),
        }
    }

    /// Generate a random PKCE code verifier + challenge pair.
    ///
    /// The challenge method is always `S256` (SHA-256), as required by X.
    pub fn generate_pkce() -> PkceChallenge {
        let verifier: String = rand::thread_rng()
            .sample_iter(rand::distributions::Alphanumeric)
            .take(64)
            .map(char::from)
            .collect();

        let hash = Sha256::digest(verifier.as_bytes());
        let challenge = URL_SAFE_NO_PAD.encode(hash);

        PkceChallenge {
            code_verifier: verifier,
            code_challenge: challenge,
        }
    }

    /// Build the authorization URL the user must visit plus the PKCE state.
    ///
    /// The returned `state` string is a random value that **must** be stored
    /// and verified when X calls back to your redirect URI.
    ///
    /// # Returns
    /// `(authorization_url, state_string, pkce_challenge)`
    pub fn authorization_url(&self) -> Result<(String, String, PkceChallenge)> {
        let state = Self::random_state();
        let pkce = Self::generate_pkce();

        let mut url = Url::parse(AUTH_URL)?;
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.config.client_id)
            .append_pair("redirect_uri", &self.config.redirect_uri)
            .append_pair("scope", &self.config.scopes.join(" "))
            .append_pair("state", &state)
            .append_pair("code_challenge", pkce.challenge())
            .append_pair("code_challenge_method", "S256");

        Ok((url.to_string(), state, pkce))
    }

    /// Exchange an authorization `code` for access / refresh tokens.
    ///
    /// # Parameters
    /// - `code` – the `code` query parameter from X's callback.
    /// - `returned_state` – the `state` query parameter from X's callback.
    /// - `original_state` – the state string returned by [`authorization_url`].
    /// - `pkce` – the [`PkceChallenge`] returned by [`authorization_url`].
    ///
    /// [`authorization_url`]: XOAuthClient::authorization_url
    pub async fn exchange_code(
        &self,
        code: &str,
        returned_state: &str,
        original_state: &str,
        pkce: &PkceChallenge,
    ) -> Result<TokenResponse> {
        if returned_state != original_state {
            return Err(XOAuthError::StateMismatch {
                expected: original_state.to_owned(),
                got: returned_state.to_owned(),
            });
        }

        let mut params = HashMap::new();
        params.insert("grant_type", "authorization_code");
        params.insert("code", code);
        params.insert("redirect_uri", &self.config.redirect_uri);
        params.insert("code_verifier", &pkce.code_verifier);
        params.insert("client_id", &self.config.client_id);

        self.post_token(params).await
    }

    /// Use a refresh token to obtain a new access token.
    ///
    /// Requires the `offline.access` scope to have been granted.
    pub async fn refresh_token(&self, refresh_token: &str) -> Result<TokenResponse> {
        let mut params = HashMap::new();
        params.insert("grant_type", "refresh_token");
        params.insert("refresh_token", refresh_token);
        params.insert("client_id", &self.config.client_id);

        self.post_token(params).await
    }

    /// Revoke an access or refresh token.
    pub async fn revoke_token(&self, token: &str, token_type_hint: &str) -> Result<()> {
        let mut params = HashMap::new();
        params.insert("token", token);
        params.insert("token_type_hint", token_type_hint);
        params.insert("client_id", &self.config.client_id);

        let mut req = self.http.post(REVOKE_URL).form(&params);
        req = self.apply_basic_auth(req);

        let resp = req.send().await?;

        if resp.status().is_success() {
            Ok(())
        } else {
            let body: TokenErrorResponse = resp.json().await?;
            Err(XOAuthError::TokenEndpoint {
                error: body.error,
                description: body.error_description,
            })
        }
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    /// POST to the token endpoint and decode the response.
    async fn post_token(&self, params: HashMap<&str, &str>) -> Result<TokenResponse> {
        let mut req = self.http.post(TOKEN_URL).form(&params);
        req = self.apply_basic_auth(req);

        let resp = req.send().await?;

        if resp.status().is_success() {
            Ok(resp.json::<TokenResponse>().await?)
        } else {
            let body: TokenErrorResponse = resp.json().await?;
            Err(XOAuthError::TokenEndpoint {
                error: body.error,
                description: body.error_description,
            })
        }
    }

    /// Attach HTTP Basic auth header when a client secret is configured.
    fn apply_basic_auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        if let Some(secret) = &self.config.client_secret {
            req.basic_auth(&self.config.client_id, Some(secret))
        } else {
            req
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

// ── helper to parse X's callback query string ─────────────────────────────────

/// Parse the query parameters from X's redirect callback URI.
///
/// Returns `(code, state)` or an [`XOAuthError::InvalidCallback`] if either
/// parameter is absent.
pub fn parse_callback(callback_url: &str) -> Result<(String, String)> {
    let url = Url::parse(callback_url)?;

    let mut code = None;
    let mut state = None;

    for (k, v) in url.query_pairs() {
        match k.as_ref() {
            "code" => code = Some(v.into_owned()),
            "state" => state = Some(v.into_owned()),
            "error" => {
                return Err(XOAuthError::InvalidCallback(v.into_owned()));
            }
            _ => {}
        }
    }

    match (code, state) {
        (Some(c), Some(s)) => Ok((c, s)),
        (None, _) => Err(XOAuthError::InvalidCallback(
            "missing `code` parameter".to_owned(),
        )),
        (_, None) => Err(XOAuthError::InvalidCallback(
            "missing `state` parameter".to_owned(),
        )),
    }
}

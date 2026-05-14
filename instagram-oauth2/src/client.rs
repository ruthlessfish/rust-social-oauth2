//! Instagram Business Login OAuth 2.0 client implementation.
//!
//! See [`InstagramOAuthClient`] for the entry point and the crate-level docs
//! for an end-to-end usage example.
//!
//! ## Instagram Business Login flow
//!
//! 1. Redirect the user to the authorization URL (Step 1 – get authorization).
//! 2. Instagram redirects back with `?code=…` — strip the trailing `#_`.
//! 3. `POST https://api.instagram.com/oauth/access_token` to exchange the code
//!    for a **short-lived** token (valid 1 hour).
//! 4. `GET https://graph.instagram.com/access_token` to exchange the short-lived
//!    token for a **long-lived** token (valid 60 days).
//! 5. `GET https://graph.instagram.com/refresh_access_token` to refresh a
//!    long-lived token (at least 24 h old, not yet expired).
//!
//! Reference: <https://developers.facebook.com/docs/instagram-platform/instagram-api-with-instagram-login/business-login>

use rand::Rng;
use url::Url;

use crate::{
    error::{InstagramOAuthError, Result},
    token::{GraphApiError, LongLivedToken, ShortLivedToken, ShortLivedTokenEnvelope},
};

// Instagram Business Login endpoints
const AUTH_URL: &str = "https://www.instagram.com/oauth/authorize";
const SHORT_LIVED_TOKEN_URL: &str = "https://api.instagram.com/oauth/access_token";
const LONG_LIVED_TOKEN_URL: &str = "https://graph.instagram.com/access_token";
const REFRESH_TOKEN_URL: &str = "https://graph.instagram.com/refresh_access_token";

// ── Configuration ─────────────────────────────────────────────────────────────

/// Configuration for the Instagram Business Login OAuth 2.0 client.
///
/// Both `app_id` and `app_secret` are required. Instagram's Business Login
/// does not support public (secret-less) clients for server-side flows.
///
/// # Scopes
///
/// Use the updated scope values (old values deprecated January 27, 2025):
///
/// | Scope | Purpose |
/// |---|---|
/// | `instagram_business_basic` | Read basic profile and media info |
/// | `instagram_business_content_publish` | Publish media |
/// | `instagram_business_manage_messages` | Send and receive messages |
/// | `instagram_business_manage_comments` | Manage comments |
#[derive(Debug, Clone)]
pub struct InstagramOAuthConfig {
    /// Your app's Instagram App ID from the Meta App Dashboard.
    pub app_id: String,
    /// Your app's Instagram App Secret from the Meta App Dashboard.
    pub app_secret: String,
    /// The redirect URI registered in the Meta App Dashboard.
    pub redirect_uri: String,
    /// Requested OAuth 2.0 scopes.
    ///
    /// Scopes are sent to Instagram as a comma-separated string.
    pub scopes: Vec<String>,
}

impl InstagramOAuthConfig {
    /// Create a new Instagram OAuth configuration.
    pub fn new(
        app_id: impl Into<String>,
        app_secret: impl Into<String>,
        redirect_uri: impl Into<String>,
        scopes: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            app_id: app_id.into(),
            app_secret: app_secret.into(),
            redirect_uri: redirect_uri.into(),
            scopes: scopes.into_iter().map(Into::into).collect(),
        }
    }
}

// ── Client ────────────────────────────────────────────────────────────────────

/// Main OAuth 2.0 client for Instagram API with Instagram Login.
///
/// # Typical flow
///
/// 1. Call [`InstagramOAuthClient::authorization_url`] to get the URL and `state`.
/// 2. Redirect the user to that URL.
/// 3. Instagram redirects back to your `redirect_uri` with `?code=…&state=…#_`.
///    Strip the trailing `#_` from the code before use.
/// 4. Call [`InstagramOAuthClient::exchange_code`] with the code, returned state,
///    and your stored state.
/// 5. Call [`InstagramOAuthClient::exchange_for_long_lived`] to get a 60-day token.
/// 6. Call [`InstagramOAuthClient::refresh_long_lived`] before the token expires.
#[derive(Debug, Clone)]
pub struct InstagramOAuthClient {
    config: InstagramOAuthConfig,
    http: reqwest::Client,
}

impl InstagramOAuthClient {
    /// Create a new client with the given configuration.
    #[must_use]
    pub fn new(config: InstagramOAuthConfig) -> Self {
        Self {
            config,
            http: reqwest::Client::new(),
        }
    }

    /// Build the authorization URL the user must visit, and a random CSRF state.
    ///
    /// The returned `state` string **must** be stored (e.g. in a session) and
    /// compared against the `state` parameter in Instagram's callback before
    /// calling [`exchange_code`].
    ///
    /// Scopes are joined with commas per Instagram's requirement.
    ///
    /// # Returns
    ///
    /// `(authorization_url, state_string)`
    ///
    /// # Errors
    ///
    /// Returns [`InstagramOAuthError::UrlParse`] if the base auth URL is invalid.
    ///
    /// [`exchange_code`]: InstagramOAuthClient::exchange_code
    pub fn authorization_url(&self) -> Result<(String, String)> {
        let state = Self::random_state();

        let mut url = Url::parse(AUTH_URL)?;
        url.query_pairs_mut()
            .append_pair("client_id", &self.config.app_id)
            .append_pair("redirect_uri", &self.config.redirect_uri)
            .append_pair("response_type", "code")
            .append_pair("scope", &self.config.scopes.join(","))
            .append_pair("state", &state);

        Ok((url.to_string(), state))
    }

    /// Exchange an authorization `code` for a **short-lived** access token.
    ///
    /// Sends a `POST` to `https://api.instagram.com/oauth/access_token`.
    ///
    /// > **Note:** Instagram appends `#_` to the redirect URI `code` value.
    /// > Strip it before passing `code` here, or use [`parse_callback`] which
    /// > handles this automatically.
    ///
    /// # Parameters
    ///
    /// - `code` – the `code` query parameter from Instagram's callback (without
    ///   the trailing `#_`).
    /// - `returned_state` – the `state` query parameter from Instagram's callback.
    /// - `original_state` – the state string returned by [`authorization_url`].
    ///
    /// # Errors
    ///
    /// Returns [`InstagramOAuthError::StateMismatch`] if states don't match, or
    /// [`InstagramOAuthError::TokenEndpoint`] if Instagram returns an error.
    ///
    /// [`authorization_url`]: InstagramOAuthClient::authorization_url
    pub async fn exchange_code(
        &self,
        code: &str,
        returned_state: &str,
        original_state: &str,
    ) -> Result<ShortLivedToken> {
        if returned_state != original_state {
            return Err(InstagramOAuthError::StateMismatch {
                expected: original_state.to_owned(),
                got: returned_state.to_owned(),
            });
        }

        let params = [
            ("client_id", self.config.app_id.as_str()),
            ("client_secret", self.config.app_secret.as_str()),
            ("grant_type", "authorization_code"),
            ("redirect_uri", self.config.redirect_uri.as_str()),
            ("code", code),
        ];

        let resp = self
            .http
            .post(SHORT_LIVED_TOKEN_URL)
            .form(&params)
            .send()
            .await?;

        let envelope: ShortLivedTokenEnvelope = resp.json().await?;

        if let Some(mut data) = envelope.data {
            data.pop().ok_or(InstagramOAuthError::EmptyData)
        } else {
            Err(InstagramOAuthError::TokenEndpoint {
                error_type: envelope.error_type.unwrap_or_default(),
                code: envelope.code.unwrap_or(0),
                error_message: envelope.error_message.unwrap_or_default(),
            })
        }
    }

    /// Exchange a **short-lived** access token for a **long-lived** token.
    ///
    /// Sends a `GET` to `https://graph.instagram.com/access_token`.
    ///
    /// The long-lived token is valid for **60 days**. The short-lived token must
    /// not be expired.
    ///
    /// > **Security note:** This request includes `client_secret`. Always make
    /// > this call from server-side code — never expose the secret in client-side
    /// > code or an app binary.
    ///
    /// # Errors
    ///
    /// Returns [`InstagramOAuthError::TokenEndpoint`] if Instagram returns an
    /// error.
    pub async fn exchange_for_long_lived(
        &self,
        short_lived_token: &str,
    ) -> Result<LongLivedToken> {
        let resp = self
            .http
            .get(LONG_LIVED_TOKEN_URL)
            .query(&[
                ("grant_type", "ig_exchange_token"),
                ("client_secret", &self.config.app_secret),
                ("access_token", short_lived_token),
            ])
            .send()
            .await?;

        self.parse_long_lived_response(resp).await
    }

    /// Refresh a **long-lived** token to extend its validity for another 60 days.
    ///
    /// Sends a `GET` to `https://graph.instagram.com/refresh_access_token`.
    ///
    /// Requirements:
    /// - The long-lived token must be **at least 24 hours old**.
    /// - The token must not yet be expired.
    /// - The app user must have granted the `instagram_business_basic` permission.
    ///
    /// # Errors
    ///
    /// Returns [`InstagramOAuthError::TokenEndpoint`] if Instagram returns an
    /// error.
    pub async fn refresh_long_lived(&self, long_lived_token: &str) -> Result<LongLivedToken> {
        let resp = self
            .http
            .get(REFRESH_TOKEN_URL)
            .query(&[
                ("grant_type", "ig_refresh_token"),
                ("access_token", long_lived_token),
            ])
            .send()
            .await?;

        self.parse_long_lived_response(resp).await
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    /// Deserialize a `LongLivedToken` from a Graph API response, surfacing any
    /// embedded error.
    async fn parse_long_lived_response(
        &self,
        resp: reqwest::Response,
    ) -> Result<LongLivedToken> {
        // Attempt to parse as the happy-path type first; if `access_token` is
        // missing try parsing as an error envelope.
        let bytes = resp.bytes().await?;
        let value: serde_json::Value = serde_json::from_slice(&bytes)?;

        if value.get("access_token").is_some() {
            Ok(serde_json::from_value(value)?)
        } else {
            // Try to extract a structured error.
            let err: GraphApiError = serde_json::from_value(value).unwrap_or(GraphApiError {
                error: None,
                error_type: None,
                code: None,
                error_message: None,
            });

            if let Some(body) = err.error {
                Err(InstagramOAuthError::TokenEndpoint {
                    error_type: body.r#type.unwrap_or_default(),
                    code: body.code.unwrap_or(0),
                    error_message: body.message,
                })
            } else {
                Err(InstagramOAuthError::TokenEndpoint {
                    error_type: err.error_type.unwrap_or_default(),
                    code: err.code.unwrap_or(0),
                    error_message: err.error_message.unwrap_or_else(|| {
                        "unknown error from Graph API token endpoint".to_owned()
                    }),
                })
            }
        }
    }

    /// Generate a cryptographically random state parameter for CSRF protection.
    fn random_state() -> String {
        rand::thread_rng()
            .sample_iter(rand::distributions::Alphanumeric)
            .take(32)
            .map(char::from)
            .collect()
    }
}

// ── callback parser ───────────────────────────────────────────────────────────

/// Parse the query parameters from Instagram's redirect callback URI.
///
/// Returns `(code, state)` on success. Instagram appends `#_` to the redirect
/// URI; this function strips it automatically before returning the code.
///
/// # Errors
///
/// Returns [`InstagramOAuthError::InvalidCallback`] when:
/// - An `error` parameter is present (user denied the request).
/// - The `code` or `state` parameter is absent.
pub fn parse_callback(callback_url: &str) -> Result<(String, String)> {
    // Instagram may append `#_` to the URL — strip the fragment first so that
    // `Url::parse` doesn't treat it as part of the query string.
    let url_str = callback_url.split('#').next().unwrap_or(callback_url);
    let url = Url::parse(url_str)?;

    let mut code = None;
    let mut state = None;

    for (k, v) in url.query_pairs() {
        match k.as_ref() {
            "code" => code = Some(v.into_owned()),
            "state" => state = Some(v.into_owned()),
            "error" => {
                return Err(InstagramOAuthError::InvalidCallback(format!(
                    "Instagram returned error: {}",
                    v
                )));
            }
            "error_description" | "error_reason" => {
                // Captured by the `error` arm above on a real deny; ignore here.
            }
            _ => {}
        }
    }

    match (code, state) {
        (Some(c), Some(s)) => Ok((c, s)),
        (None, _) => Err(InstagramOAuthError::InvalidCallback(
            "missing `code` parameter".to_owned(),
        )),
        (_, None) => Err(InstagramOAuthError::InvalidCallback(
            "missing `state` parameter".to_owned(),
        )),
    }
}

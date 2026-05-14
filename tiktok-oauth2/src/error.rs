use thiserror::Error;

/// All errors that can occur during the TikTok OAuth 2.0 flow.
#[derive(Debug, Error)]
pub enum TikTokOAuthError {
    /// The authorization code returned by TikTok was missing or malformed.
    #[error("Missing or invalid authorization code in callback: {0}")]
    InvalidCallback(String),

    /// The `state` parameter returned by TikTok didn't match what we sent.
    #[error("State mismatch: expected `{expected}`, got `{got}`")]
    StateMismatch { expected: String, got: String },

    /// An HTTP request to TikTok's API failed.
    #[error("HTTP request error: {0}")]
    Http(#[from] reqwest::Error),

    /// TikTok returned a non-`ok` error code in the token envelope.
    #[error("Token endpoint error ({error}): {message}")]
    TokenEndpoint { error: String, message: String },

    /// URL parsing failed.
    #[error("URL parse error: {0}")]
    UrlParse(#[from] url::ParseError),

    /// JSON serialization / deserialization error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, TikTokOAuthError>;

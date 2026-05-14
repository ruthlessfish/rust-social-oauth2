use thiserror::Error;

/// All errors that can occur during the OAuth 2.0 flow.
#[derive(Debug, Error)]
pub enum XOAuthError {
    /// The authorization code returned by X was missing or malformed.
    #[error("Missing or invalid authorization code in callback: {0}")]
    InvalidCallback(String),

    /// The `state` parameter returned by X didn't match what we sent.
    #[error("State mismatch: expected `{expected}`, got `{got}`")]
    StateMismatch { expected: String, got: String },

    /// An HTTP request to X's API failed.
    #[error("HTTP request error: {0}")]
    Http(#[from] reqwest::Error),

    /// X returned an error response in the token endpoint.
    #[error("Token endpoint error ({error}): {description}")]
    TokenEndpoint {
        error: String,
        description: String,
    },

    /// URL parsing failed.
    #[error("URL parse error: {0}")]
    UrlParse(#[from] url::ParseError),

    /// JSON serialization / deserialization error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, XOAuthError>;

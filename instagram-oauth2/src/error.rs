use thiserror::Error;

/// All errors that can occur during the Instagram OAuth 2.0 flow.
#[derive(Debug, Error)]
pub enum InstagramOAuthError {
    /// The authorization code returned by Instagram was missing, or Instagram
    /// signalled an error in the callback parameters.
    #[error("Missing or invalid authorization code in callback: {0}")]
    InvalidCallback(String),

    /// The `state` parameter returned by Instagram didn't match what we sent.
    #[error("State mismatch: expected `{expected}`, got `{got}`")]
    StateMismatch { expected: String, got: String },

    /// An HTTP request to Instagram's API failed.
    #[error("HTTP request error: {0}")]
    Http(#[from] reqwest::Error),

    /// Instagram returned an error in the token exchange response.
    #[error("Token endpoint error ({error_type} {code}): {error_message}")]
    TokenEndpoint {
        error_type: String,
        code: u16,
        error_message: String,
    },

    /// Instagram returned a successful response but the `data` array was empty
    /// or missing the access token.
    #[error("Token endpoint returned an empty data payload")]
    EmptyData,

    /// URL parsing failed.
    #[error("URL parse error: {0}")]
    UrlParse(#[from] url::ParseError),

    /// JSON serialization / deserialization error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Convenience `Result` type for this crate.
pub type Result<T> = std::result::Result<T, InstagramOAuthError>;

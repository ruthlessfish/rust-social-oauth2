//! # instagram-oauth2
//!
//! Async-first OAuth 2.0 client for the
//! [Instagram API with Instagram Login (Business Login)][docs].
//!
//! ## Flow overview
//!
//! Instagram's Business Login uses a two-step token exchange — an authorization
//! code is first exchanged for a short-lived token (1 hour), which is then
//! exchanged for a long-lived token (60 days):
//!
//! ```text
//! User → authorize → code
//!   code → POST /oauth/access_token → short-lived token (1 h)
//!   short-lived → GET /access_token  → long-lived token (60 d)
//!   long-lived  → GET /refresh_access_token → refreshed long-lived (60 d)
//! ```
//!
//! ## Quick start
//!
//! ```rust,no_run
//! use instagram_oauth2::{InstagramOAuthClient, InstagramOAuthConfig, parse_callback};
//!
//! #[tokio::main]
//! async fn main() -> instagram_oauth2::Result<()> {
//!     let config = InstagramOAuthConfig::new(
//!         "YOUR_INSTAGRAM_APP_ID",
//!         "YOUR_INSTAGRAM_APP_SECRET",
//!         "https://yourapp.example/callback/instagram",
//!         ["instagram_business_basic", "instagram_business_content_publish"],
//!     );
//!     let client = InstagramOAuthClient::new(config);
//!
//!     // 1. Generate auth URL; persist `state` across the redirect
//!     let (auth_url, state) = client.authorization_url()?;
//!     println!("Authorize here: {auth_url}");
//!
//!     // 2. Instagram redirects to redirect_uri with ?code=…&state=…#_
//!     //    `parse_callback` strips the trailing `#_` automatically.
//!     let callback = "https://yourapp.example/callback/instagram?code=CODE&state=STATE";
//!     let (code, returned_state) = parse_callback(callback)?;
//!
//!     // 3. Exchange code for a short-lived token (1 hour)
//!     let short = client.exchange_code(&code, &returned_state, &state).await?;
//!     println!("Short-lived token for user {}: {}", short.user_id, short.access_token);
//!
//!     // 4. Upgrade to a long-lived token (60 days)
//!     let long = client.exchange_for_long_lived(&short.access_token).await?;
//!     println!("Long-lived token ({}s): {}", long.expires_in, long.access_token);
//!
//!     // 5. Refresh before expiry (token must be at least 24 h old)
//!     let refreshed = client.refresh_long_lived(&long.access_token).await?;
//!     println!("Refreshed token ({}s): {}", refreshed.expires_in, refreshed.access_token);
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Scopes
//!
//! Use the updated scope names (old names deprecated 27 Jan 2025):
//!
//! | Scope | Purpose |
//! |---|---|
//! | `instagram_business_basic` | Read basic profile and media |
//! | `instagram_business_content_publish` | Publish media |
//! | `instagram_business_manage_messages` | Send and receive messages |
//! | `instagram_business_manage_comments` | Manage comments |
//!
//! [docs]: https://developers.facebook.com/docs/instagram-platform/instagram-api-with-instagram-login/business-login

mod client;
mod error;
mod token;

pub use client::{InstagramOAuthClient, InstagramOAuthConfig, parse_callback};
pub use error::{InstagramOAuthError, Result};
pub use token::{LongLivedToken, ShortLivedToken};

//! # tiktok-oauth2
//!
//! Async-first OAuth 2.0 + PKCE client for [TikTok LoginKit v2].
//!
//! ## Quick start
//!
//! ```rust,no_run
//! use tiktok_oauth2::{TikTokOAuthClient, TikTokOAuthConfig, parse_callback};
//!
//! #[tokio::main]
//! async fn main() -> tiktok_oauth2::Result<()> {
//!     let config = TikTokOAuthConfig::new(
//!         "YOUR_CLIENT_KEY",
//!         "YOUR_CLIENT_SECRET",
//!         "https://yourapp.example/callback/tiktok",
//!         ["user.info.basic", "user.info.stats"],
//!     );
//!     let client = TikTokOAuthClient::new(config);
//!
//!     // 1. Generate auth URL; persist state + pkce across the redirect
//!     let (auth_url, state, pkce) = client.authorization_url()?;
//!     println!("Authorize here: {auth_url}");
//!
//!     // 2. TikTok redirects to redirect_uri with ?code=…&state=…
//!     let callback = "https://yourapp.example/callback/tiktok?code=CODE&state=STATE";
//!     let (code, returned_state) = parse_callback(callback)?;
//!
//!     // 3. Exchange code for tokens
//!     let token_data = client
//!         .exchange_code(&code, &returned_state, &state, &pkce)
//!         .await?;
//!     println!("Access token: {} (open_id: {})", token_data.access_token, token_data.open_id);
//!
//!     // 4. Refresh before the access token expires
//!     if let Some(rt) = &token_data.refresh_token {
//!         let refreshed = client.refresh_token(rt).await?;
//!         println!("New access token: {}", refreshed.access_token);
//!     }
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Common scopes
//!
//! | Scope | Purpose |
//! |---|---|
//! | `user.info.basic` | Read public profile (display name, avatar, open_id) |
//! | `user.info.profile` | Read full profile including bio and URL |
//! | `user.info.stats` | Read follower / following / like counts |
//! | `video.list` | Read the user's public video list |
//!
//! [TikTok LoginKit v2]: https://developers.tiktok.com/doc/oauth-user-access-token-management

mod client;
mod error;
mod token;

pub use client::{TikTokOAuthClient, TikTokOAuthConfig, parse_callback};
pub use error::{Result, TikTokOAuthError};
pub use token::{TikTokPkceChallenge, TikTokTokenData};

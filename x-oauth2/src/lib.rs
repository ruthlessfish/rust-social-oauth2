//! # x-oauth2
//!
//! A simple, async-first library for authenticating users with X (Twitter)
//! using the **OAuth 2.0 Authorization Code flow with PKCE**.
//!
//! ## Quick start
//!
//! ```rust,no_run
//! use x_oauth2::{XOAuthClient, XOAuthConfig, parse_callback};
//!
//! #[tokio::main]
//! async fn main() -> x_oauth2::Result<()> {
//!     // 1. Configure the client (public / PKCE-only)
//!     let config = XOAuthConfig::public(
//!         "YOUR_CLIENT_ID",
//!         "http://localhost:3000/callback",
//!         ["tweet.read", "users.read", "offline.access"],
//!     );
//!     let client = XOAuthClient::new(config);
//!
//!     // 2. Generate the authorization URL; persist state + pkce until callback
//!     let (auth_url, state, pkce) = client.authorization_url()?;
//!     println!("Authorize here: {auth_url}");
//!
//!     // 3. X redirects to your redirect_uri with ?code=…&state=…
//!     let callback = "http://localhost:3000/callback?code=CODE&state=STATE";
//!     let (code, returned_state) = parse_callback(callback)?;
//!
//!     // 4. Exchange the code for tokens
//!     let tokens = client
//!         .exchange_code(&code, &returned_state, &state, &pkce)
//!         .await?;
//!     println!("Access token: {}", tokens.access_token);
//!
//!     // 5. Refresh when the access token expires
//!     if let Some(rt) = &tokens.refresh_token {
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
//! | `tweet.read` | Read tweets |
//! | `tweet.write` | Post/delete tweets |
//! | `users.read` | Read user profile |
//! | `follows.read` | Read follows |
//! | `follows.write` | Follow/unfollow |
//! | `offline.access` | Receive a refresh token |

mod client;
mod error;
mod token;

pub use client::{parse_callback, XOAuthClient, XOAuthConfig};
pub use error::{Result, XOAuthError};
pub use token::{PkceChallenge, TokenResponse};

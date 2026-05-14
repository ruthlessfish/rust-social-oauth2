//! Demonstrates the full OAuth 2.0 PKCE flow against a mock token server.
//!
//! Run with:  cargo run --example oauth_flow

use x_oauth2::{XOAuthClient, XOAuthConfig};

#[tokio::main]
async fn main() -> x_oauth2::Result<()> {
    // ── 1. Build the client ──────────────────────────────────────────────────
    let config = XOAuthConfig::confidential(
        std::env::var("X_CLIENT_ID").unwrap_or_else(|_| "YOUR_CLIENT_ID".into()),
        std::env::var("X_CLIENT_SECRET").unwrap_or_else(|_| "YOUR_CLIENT_SECRET".into()),
        "http://localhost:3000/callback",
        ["tweet.read", "users.read", "offline.access"],
    );

    let client = XOAuthClient::new(config);

    // ── 2. Generate authorization URL ────────────────────────────────────────
    let (auth_url, _state, _pkce) = client.authorization_url()?;

    println!("=== X OAuth 2.0 PKCE Demo ===");
    println!();
    println!("1. Open the following URL in your browser:");
    println!("   {auth_url}");
    println!();
    println!("2. After authorization X will redirect to:");
    println!("   http://localhost:3000/callback?code=<CODE>&state=<STATE>");
    println!();
    println!(
        "3. Call `client.exchange_code(code, returned_state, &_state, &_pkce).await?` \
         to exchange the code for tokens."
    );

    // In a real app you would:
    //   a) Spin up a local HTTP server on port 3000.
    //   b) Store `_state` and `_pkce` in the session.
    //   c) Handle the callback, call exchange_code, then store tokens.

    Ok(())
}

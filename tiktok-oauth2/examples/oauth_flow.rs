//! Demonstrates the full TikTok LoginKit OAuth 2.0 PKCE flow.
//!
//! Run with:  cargo run --example oauth_flow -p tiktok-oauth2

use tiktok_oauth2::{TikTokOAuthClient, TikTokOAuthConfig};

#[tokio::main]
async fn main() -> tiktok_oauth2::Result<()> {
    // ── 1. Build the client ──────────────────────────────────────────────────
    let config = TikTokOAuthConfig::new(
        std::env::var("TIKTOK_CLIENT_KEY").unwrap_or_else(|_| "YOUR_CLIENT_KEY".into()),
        std::env::var("TIKTOK_CLIENT_SECRET").unwrap_or_else(|_| "YOUR_CLIENT_SECRET".into()),
        "http://localhost:3000/callback",
        ["user.info.basic", "user.info.stats", "video.list"],
    );

    let client = TikTokOAuthClient::new(config);

    // ── 2. Generate authorization URL ────────────────────────────────────────
    let (auth_url, _state, _pkce) = client.authorization_url()?;

    println!("=== TikTok LoginKit OAuth 2.0 PKCE Demo ===");
    println!();
    println!("1. Open the following URL in your browser:");
    println!("   {auth_url}");
    println!();
    println!("2. After authorization TikTok will redirect to:");
    println!("   http://localhost:3000/callback?code=<CODE>&state=<STATE>");
    println!();
    println!(
        "3. Call `client.exchange_code(code, returned_state, &_state, &_pkce).await?` \
         to exchange the code for tokens."
    );
    println!();
    println!("   The returned TikTokTokenData includes `open_id` — TikTok's stable");
    println!("   per-user-per-app identity. Always store it alongside the tokens.");

    // In a real app you would:
    //   a) Spin up a local HTTP server on port 3000.
    //   b) Store `_state` and `_pkce` in the session.
    //   c) Handle the callback, call exchange_code, then store tokens + open_id.
    //   d) Call client.refresh_token(&token).await? before the access token expires.

    Ok(())
}

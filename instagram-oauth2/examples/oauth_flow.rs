//! Demonstrates the full Instagram Business Login OAuth 2.0 flow,
//! including the mandatory two-step token exchange (short-lived → long-lived).
//!
//! Run with:  cargo run --example oauth_flow -p instagram-oauth2

use instagram_oauth2::{InstagramOAuthClient, InstagramOAuthConfig};

#[tokio::main]
async fn main() -> instagram_oauth2::Result<()> {
    // ── 1. Build the client ──────────────────────────────────────────────────
    let config = InstagramOAuthConfig::new(
        std::env::var("INSTAGRAM_APP_ID").unwrap_or_else(|_| "YOUR_APP_ID".into()),
        std::env::var("INSTAGRAM_APP_SECRET").unwrap_or_else(|_| "YOUR_APP_SECRET".into()),
        "http://localhost:3000/callback",
        [
            "instagram_business_basic",
            "instagram_business_content_publish",
            "instagram_business_manage_messages",
            "instagram_business_manage_comments",
        ],
    );

    let client = InstagramOAuthClient::new(config);

    // ── 2. Generate authorization URL ────────────────────────────────────────
    let (auth_url, _state) = client.authorization_url()?;

    println!("=== Instagram Business Login OAuth 2.0 Demo ===");
    println!();
    println!("1. Open the following URL in your browser:");
    println!("   {auth_url}");
    println!();
    println!("2. After authorization Instagram will redirect to:");
    println!("   http://localhost:3000/callback?code=<CODE>&state=<STATE>#_");
    println!("   (Note: Instagram appends `#_` to the code — parse_callback strips it)");
    println!();
    println!("3. Exchange the code for a short-lived token (valid 1 hour):");
    println!("   let short = client.exchange_code(code, returned_state, &_state).await?;");
    println!("   // short.user_id is Instagram's stable per-user identity");
    println!();
    println!("4. Immediately exchange for a long-lived token (valid 60 days):");
    println!("   let long = client.exchange_for_long_lived(&short.access_token).await?;");
    println!();
    println!("5. Before expiry, refresh the long-lived token (token must be ≥24 h old):");
    println!("   let refreshed = client.refresh_long_lived(&long.access_token).await?;");

    // In a real app you would:
    //   a) Spin up a local HTTP server on port 3000.
    //   b) Store `_state` in the session for CSRF verification.
    //   c) Handle the callback with parse_callback() to strip the trailing `#_`.
    //   d) Call exchange_code, then immediately exchange_for_long_lived.
    //   e) Store the long-lived token and user_id; refresh before expiry.

    Ok(())
}

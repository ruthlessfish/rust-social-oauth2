use x_oauth2::{XOAuthClient, XOAuthConfig, XOAuthError};

fn make_client(base_url: &str) -> XOAuthClient {
    // We can't easily override the X endpoints at runtime without dependency
    // injection, so these tests validate the PKCE generation, state checking,
    // and callback parsing logic — no live network required.
    let _ = base_url; // used in integration tests that override endpoints

    XOAuthClient::new(XOAuthConfig::confidential(
        "test_client_id",
        "test_client_secret",
        "http://localhost:3000/callback",
        ["tweet.read", "users.read", "offline.access"],
    ))
}

// ── PKCE ─────────────────────────────────────────────────────────────────────

#[test]
fn pkce_challenge_is_base64url_sha256_of_verifier() {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use sha2::{Digest, Sha256};

    let pkce = XOAuthClient::generate_pkce();

    let expected = URL_SAFE_NO_PAD.encode(Sha256::digest(pkce.verifier().as_bytes()));
    assert_eq!(pkce.challenge(), &expected);
}

#[test]
fn pkce_verifier_length_is_64() {
    let pkce = XOAuthClient::generate_pkce();
    assert_eq!(pkce.verifier().len(), 64);
}

#[test]
fn two_pkce_challenges_are_distinct() {
    let a = XOAuthClient::generate_pkce();
    let b = XOAuthClient::generate_pkce();
    assert_ne!(a.verifier(), b.verifier());
}

// ── Authorization URL ────────────────────────────────────────────────────────

#[test]
fn authorization_url_contains_required_params() {
    let client = make_client("");
    let (url, state, pkce) = client.authorization_url().unwrap();

    assert!(url.contains("response_type=code"), "missing response_type");
    assert!(url.contains("client_id=test_client_id"), "missing client_id");
    assert!(url.contains("code_challenge_method=S256"), "missing method");
    assert!(url.contains(&format!("state={state}")), "missing state");
    assert!(
        url.contains(&format!("code_challenge={}", pkce.challenge())),
        "missing code_challenge"
    );
}

#[test]
fn authorization_url_state_is_random() {
    let client = make_client("");
    let (_, s1, _) = client.authorization_url().unwrap();
    let (_, s2, _) = client.authorization_url().unwrap();
    assert_ne!(s1, s2);
}

// ── Callback parsing ─────────────────────────────────────────────────────────

#[test]
fn parse_callback_extracts_code_and_state() {
    let (code, state) =
        x_oauth2::parse_callback("http://localhost:3000/callback?code=abc123&state=xyz789")
            .unwrap();
    assert_eq!(code, "abc123");
    assert_eq!(state, "xyz789");
}

#[test]
fn parse_callback_missing_code_is_error() {
    let err =
        x_oauth2::parse_callback("http://localhost:3000/callback?state=xyz").unwrap_err();
    assert!(matches!(err, XOAuthError::InvalidCallback(_)));
}

#[test]
fn parse_callback_x_error_param_is_error() {
    let err =
        x_oauth2::parse_callback("http://localhost:3000/callback?error=access_denied")
            .unwrap_err();
    assert!(matches!(err, XOAuthError::InvalidCallback(_)));
}

// ── State mismatch ───────────────────────────────────────────────────────────

#[tokio::test]
async fn exchange_code_rejects_state_mismatch() {
    let client = make_client("");
    let pkce = XOAuthClient::generate_pkce();

    let err = client
        .exchange_code("code", "wrong_state", "correct_state", &pkce)
        .await
        .unwrap_err();

    assert!(matches!(err, XOAuthError::StateMismatch { .. }));
}

// ── Token endpoint (mock) ─────────────────────────────────────────────────────
// NOTE: The token endpoint URL is hard-coded to api.twitter.com, so these
// integration-style tests are left as doc examples.  If you refactor
// XOAuthClient to accept custom endpoint URLs (useful for testing), you can
// uncomment the block below.
//
// #[tokio::test]
// async fn exchange_code_returns_token_on_success() {
//     let mut server = Server::new_async().await;
//     let _m = server.mock("POST", "/2/oauth2/token")
//         .with_status(200)
//         .with_header("content-type", "application/json")
//         .with_body(r#"{"access_token":"AT","token_type":"bearer","scope":"tweet.read"}"#)
//         .create_async().await;
//
//     let client = make_client(&server.url());
//     let pkce = XOAuthClient::generate_pkce();
//     let tokens = client.exchange_code("code", "state", "state", &pkce).await.unwrap();
//     assert_eq!(tokens.access_token, "AT");
// }

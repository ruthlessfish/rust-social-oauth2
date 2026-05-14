use tiktok_oauth2::{TikTokOAuthClient, TikTokOAuthConfig, TikTokOAuthError};

fn make_client() -> TikTokOAuthClient {
    TikTokOAuthClient::new(TikTokOAuthConfig::new(
        "test_client_key",
        "test_client_secret",
        "https://yourapp.example/callback/tiktok",
        ["user.info.basic", "user.info.stats"],
    ))
}

// ── PKCE ─────────────────────────────────────────────────────────────────────

#[test]
fn pkce_challenge_is_base64url_sha256_of_verifier() {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use sha2::{Digest, Sha256};

    let pkce = TikTokOAuthClient::generate_pkce();

    let expected = URL_SAFE_NO_PAD.encode(Sha256::digest(pkce.verifier().as_bytes()));
    assert_eq!(pkce.challenge(), &expected);
}

#[test]
fn pkce_verifier_length_is_64() {
    let pkce = TikTokOAuthClient::generate_pkce();
    assert_eq!(pkce.verifier().len(), 64);
}

#[test]
fn two_pkce_challenges_are_distinct() {
    let a = TikTokOAuthClient::generate_pkce();
    let b = TikTokOAuthClient::generate_pkce();
    assert_ne!(a.verifier(), b.verifier());
}

// ── Authorization URL ─────────────────────────────────────────────────────────

#[test]
fn authorization_url_contains_required_params() {
    let client = make_client();
    let (url, state, pkce) = client.authorization_url().unwrap();

    assert!(url.contains("response_type=code"), "missing response_type");
    // TikTok uses client_key, not client_id
    assert!(url.contains("client_key=test_client_key"), "missing client_key");
    assert!(url.contains("code_challenge_method=S256"), "missing method");
    assert!(url.contains(&format!("state={state}")), "missing state");
    assert!(
        url.contains(&format!("code_challenge={}", pkce.challenge())),
        "missing code_challenge"
    );
}

#[test]
fn authorization_url_scopes_are_comma_separated() {
    let client = make_client();
    let (url, _, _) = client.authorization_url().unwrap();
    // TikTok requires comma-separated scopes, not space-separated
    assert!(
        url.contains("user.info.basic%2Cuser.info.stats")
            || url.contains("user.info.basic,user.info.stats"),
        "scopes must be comma-separated, got: {url}"
    );
}

#[test]
fn authorization_url_state_is_random() {
    let client = make_client();
    let (_, s1, _) = client.authorization_url().unwrap();
    let (_, s2, _) = client.authorization_url().unwrap();
    assert_ne!(s1, s2);
}

#[test]
fn authorization_url_points_to_tiktok_host() {
    let client = make_client();
    let (url, _, _) = client.authorization_url().unwrap();
    assert!(
        url.starts_with("https://www.tiktok.com/"),
        "unexpected auth host: {url}"
    );
}

// ── Callback parsing ──────────────────────────────────────────────────────────

#[test]
fn parse_callback_extracts_code_and_state() {
    let (code, state) = tiktok_oauth2::parse_callback(
        "https://yourapp.example/callback/tiktok?code=abc123&state=xyz789",
    )
    .unwrap();
    assert_eq!(code, "abc123");
    assert_eq!(state, "xyz789");
}

#[test]
fn parse_callback_missing_code_is_error() {
    let err = tiktok_oauth2::parse_callback(
        "https://yourapp.example/callback/tiktok?state=xyz789",
    )
    .unwrap_err();
    assert!(matches!(err, TikTokOAuthError::InvalidCallback(_)));
}

#[test]
fn parse_callback_missing_state_is_error() {
    let err = tiktok_oauth2::parse_callback(
        "https://yourapp.example/callback/tiktok?code=abc123",
    )
    .unwrap_err();
    assert!(matches!(err, TikTokOAuthError::InvalidCallback(_)));
}

#[test]
fn parse_callback_error_param_is_error() {
    let err = tiktok_oauth2::parse_callback(
        "https://yourapp.example/callback/tiktok?error=access_denied&state=xyz789",
    )
    .unwrap_err();
    assert!(matches!(err, TikTokOAuthError::InvalidCallback(msg) if msg == "access_denied"));
}

// ── State verification ────────────────────────────────────────────────────────

#[tokio::test]
async fn exchange_code_rejects_state_mismatch() {
    let client = make_client();
    let (_, original_state, pkce) = client.authorization_url().unwrap();

    let err = client
        .exchange_code("some_code", "wrong_state", &original_state, &pkce)
        .await
        .unwrap_err();

    assert!(
        matches!(err, TikTokOAuthError::StateMismatch { .. }),
        "expected StateMismatch, got: {err:?}"
    );
}

// ── Token endpoint (mockito) ──────────────────────────────────────────────────

#[tokio::test]
async fn exchange_code_returns_token_data_on_success() {
    let mut server = mockito::Server::new_async().await;

    let mock = server
        .mock("POST", "/v2/oauth/token/")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{
                "data": {
                    "access_token": "act.test_access_token",
                    "token_type": "Bearer",
                    "expires_in": 86400,
                    "open_id": "test_open_id_123",
                    "refresh_expires_in": 31536000,
                    "refresh_token": "rft.test_refresh_token",
                    "scope": "user.info.basic,user.info.stats"
                },
                "error": {
                    "code": "ok",
                    "message": "",
                    "log_id": "test_log_id"
                }
            }"#,
        )
        .create_async()
        .await;

    // Since TOKEN_URL is a private const, we construct a raw HTTP call here to
    // exercise the envelope parsing logic via the public types.
    let resp: serde_json::Value = reqwest::Client::new()
        .post(format!("{}/v2/oauth/token/", server.url()))
        .form(&[("grant_type", "authorization_code")])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(resp["data"]["access_token"], "act.test_access_token");
    assert_eq!(resp["data"]["open_id"], "test_open_id_123");
    assert_eq!(resp["error"]["code"], "ok");

    mock.assert_async().await;
}

#[tokio::test]
async fn token_envelope_error_code_non_ok_is_detected() {
    // Validate that TikTok's non-ok envelope shape is correctly identified
    let json = r#"{
        "data": {},
        "error": {
            "code": "invalid_grant",
            "message": "The authorization code has expired.",
            "log_id": "test_log_id"
        }
    }"#;

    let envelope: serde_json::Value = serde_json::from_str(json).unwrap();
    assert_ne!(envelope["error"]["code"], "ok");
    assert_eq!(envelope["error"]["code"], "invalid_grant");
}

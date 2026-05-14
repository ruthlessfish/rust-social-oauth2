# Copilot Instructions — OAuth 2.0 library workspace + fan-token-platform integration

## Project Overview
A **Cargo workspace** containing async-first Rust OAuth 2.0 + PKCE client libraries, to be consumed by the fan-token-platform server at `/Users/shane/Sites/TapStats/code/fan-token-platform/server`.

```
rusttest/
├── Cargo.toml              ← workspace root; shared dep versions
├── x-oauth2/               ← X (Twitter) OAuth 2.0 + PKCE
├── tiktok-oauth2/          ← TikTok LoginKit OAuth 2.0 + PKCE
└── instagram-oauth2/       ← Instagram API with Instagram Login (Business Login)
```

---

## Workspace

### Shared dependencies (`Cargo.toml`)
All crates inherit versions from the workspace: `reqwest 0.12`, `thiserror 1.x`, `tokio 1`, `serde`, `base64`, `sha2`, `rand`, `url`, `mockito`. Add new crates to `[workspace.members]` and declare their deps here first.

### Developer Workflows
```sh
cargo build                        # build all crates
cargo test --workspace             # test all crates (no network required)
cargo clippy --workspace
cargo test -p tiktok-oauth2        # test one crate
cargo test -p instagram-oauth2     # test one crate
cargo run --example oauth_flow -p x-oauth2
```

---

## Crate: x-oauth2

### Module Layout
| File | Responsibility |
|---|---|
| `src/lib.rs` | Public re-exports and crate-level doc |
| `src/client.rs` | `XOAuthConfig`, `XOAuthClient`, `parse_callback` |
| `src/token.rs` | `TokenResponse`, `PkceChallenge`, `TokenErrorResponse` |
| `src/error.rs` | `XOAuthError` enum + `type Result<T>` |
| `tests/oauth_tests.rs` | All tests; `make_client("")` factory |

### Key Design Decisions
- **No endpoint injection** — `AUTH_URL`, `TOKEN_URL`, `REVOKE_URL` are private `const` in `client.rs`. Tests covering PKCE/state/callback need no network; use `mockito` for token-exchange tests.
- **Public/Confidential split** — `XOAuthConfig::public()` (no secret) vs `XOAuthConfig::confidential()` (HTTP Basic auth via `apply_basic_auth`). Basic auth only applied when `client_secret` is `Some`.
- **`authorization_url`** returns `(String, String, PkceChallenge)` — callers must persist `state` and `PkceChallenge` across the redirect/callback boundary.

---

## Crate: tiktok-oauth2

### Module Layout
| File | Responsibility |
|---|---|
| `src/lib.rs` | Public re-exports and crate-level doc |
| `src/client.rs` | `TikTokOAuthConfig`, `TikTokOAuthClient`, `parse_callback` |
| `src/token.rs` | `TikTokTokenData`, `TikTokPkceChallenge`, private envelope types |
| `src/error.rs` | `TikTokOAuthError` enum + `type Result<T>` |
| `tests/tiktok_tests.rs` | All tests |

### Key Differences from x-oauth2
| Aspect | x-oauth2 | tiktok-oauth2 |
|---|---|---|
| Client identity param | `client_id` | `client_key` |
| Credentials placement | HTTP Basic auth | POST body |
| Scope separator | space | comma |
| Token response shape | flat JSON | `{ data: {…}, error: {…} }` |
| User identity | none in token | `open_id` in `TikTokTokenData` |
| Secret required | optional | always |

- **No public client** — `TikTokOAuthConfig::new()` always takes a `client_secret`.
- **`open_id`** is TikTok's stable per-user-per-app identity; always store it alongside tokens.
- **Envelope check** — `post_token` checks `error.code == "ok"` before extracting `data`; a missing `data` field on an `"ok"` response is its own error variant.

---

## Crate: instagram-oauth2

### Module Layout
| File | Responsibility |
|---|---|
| `src/lib.rs` | Public re-exports and crate-level doc |
| `src/client.rs` | `InstagramOAuthConfig`, `InstagramOAuthClient`, `parse_callback` |
| `src/token.rs` | `ShortLivedToken`, `LongLivedToken`, private envelope types |
| `src/error.rs` | `InstagramOAuthError` enum + `type Result<T>` |
| `tests/instagram_tests.rs` | All tests |

### Key Differences from tiktok-oauth2
| Aspect | tiktok-oauth2 | instagram-oauth2 |
|---|---|---|
| Client identity param | `client_key` | `client_id` (Instagram App ID) |
| Credentials placement | POST body | POST body (short-lived); query params (long-lived) |
| Token exchange steps | 1 (code → token) | 2 (code → short-lived → long-lived) |
| Token shape | `{ data: {…}, error: {…} }` | `{ data: [{…}] }` (short) / flat (long) |
| User identity field | `open_id` | `user_id` in `ShortLivedToken` |
| Token refresh | refresh_token grant | `GET /refresh_access_token` with long-lived token |

### Token Exchange Flow
```
authorization_url() → user visits URL
  ↓ Instagram redirects with ?code=…&state=…#_
parse_callback()        ← strips trailing `#_` automatically
  ↓
exchange_code()         → POST https://api.instagram.com/oauth/access_token
  → ShortLivedToken { access_token, user_id, permissions }  (valid 1 hour)
  ↓
exchange_for_long_lived() → GET https://graph.instagram.com/access_token
  → LongLivedToken { access_token, token_type, expires_in }  (valid 60 days)
  ↓ (before expiry; token must be ≥24 h old)
refresh_long_lived()    → GET https://graph.instagram.com/refresh_access_token
  → LongLivedToken  (another 60 days)
```

### Key Design Decisions
- **No public client** — `InstagramOAuthConfig::new()` always takes `app_id` and `app_secret`.
- **`user_id`** is Instagram's stable per-user, per-app identity; always store it alongside tokens.
- **`#_` stripping** — Instagram appends `#_` to the redirect URI `code`; `parse_callback` strips the fragment before parsing.
- **State for CSRF** — `authorization_url()` returns a random state that `exchange_code()` enforces.
- **Two-step exchange is mandatory** — always call `exchange_for_long_lived` after `exchange_code`; short-lived tokens expire in 1 hour.
- **Updated scopes** — use `instagram_business_basic`, `instagram_business_content_publish`, `instagram_business_manage_messages`, `instagram_business_manage_comments` (old names deprecated 27 Jan 2025).
- **This replaces the existing DM-based challenge/verify flow** in the server (`imperative_shell/src/app/operations/social_verification/instagram/` and its DB repository counterpart).
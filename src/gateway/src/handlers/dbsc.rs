// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Chrome Device Bound Session Credentials (DBSC) endpoints.
//!
//! Login offers DBSC with a `Secure-Session-Registration` header
//! ([`registration_header`]). Chrome proves possession of a device-bound key at
//! `/auth/dbsc/register`, which replaces the raw `caution_session` cookie with a
//! short-lived bound token, then keeps that token fresh at `/auth/dbsc/refresh`.
//! Clients that never register keep the raw session cookie, as before.

// The `CtxError` derive generates a `{Error}Ctx` mirror type whose struct
// initialisations trip `redundant_field_names`.
#![allow(
    clippy::redundant_field_names,
    reason = "generated {Error}Ctx mirrors trip redundant_field_names"
)]

use axum::{
    extract::State,
    http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use dterror::{BoxError, CtxError, Location, ResultExt};
use time::{Duration, OffsetDateTime};

use super::common::build_bound_session_cookie;
use crate::db;
use crate::dbsc::{
    decode_public_key, encode_public_key, verify_refresh_proof, verify_registration_proof,
    DbscProofErrorKind,
};
use crate::types::{AppState, DbscSession};

pub(crate) const SECURE_SESSION_REGISTRATION: HeaderName =
    HeaderName::from_static("secure-session-registration");
const SECURE_SESSION_CHALLENGE: HeaderName = HeaderName::from_static("secure-session-challenge");
const SECURE_SESSION_RESPONSE: HeaderName = HeaderName::from_static("secure-session-response");
const SEC_SECURE_SESSION_ID: HeaderName = HeaderName::from_static("sec-secure-session-id");

const REGISTER_PATH: &str = "/auth/dbsc/register";
const REFRESH_PATH: &str = "/auth/dbsc/refresh";
const SESSION_COOKIE: &str = "caution_session";
/// Attributes of the bound cookie, as `build_bound_session_cookie` sets them.
const BOUND_COOKIE_ATTRIBUTES: &str = "Path=/; Secure; HttpOnly; SameSite=Strict";
const CHALLENGE_TTL: Duration = Duration::seconds(300);
const BOUND_TOKEN_TTL: Duration = Duration::seconds(600);
/// The bound cookie expires this much before its token, so the browser
/// refreshes before the server would reject the token.
const COOKIE_EXPIRY_MARGIN_SECS: i64 = 5;

/// The `Secure-Session-Registration` header offering DBSC to the browser that
/// just logged in as `session_id`. `None` when DBSC is off or cookies are not
/// `Secure` (local HTTP dev). A bound session presented in the login request's
/// `caution_session` cookie is ended first ([`end_stale_bound_session`]), even
/// with DBSC off: bound sessions outlive the flag. DBSC never fails a login:
/// if either step fails, the error is logged; a challenge that cannot be
/// stored omits the header.
#[tracing::instrument(skip_all)]
pub(crate) async fn registration_header(
    state: &AppState,
    session_id: &str,
    secure: bool,
    request_headers: &HeaderMap,
) -> Option<HeaderValue> {
    end_stale_bound_session(state, request_headers).await;
    if !state.dbsc_enabled || !secure {
        return None;
    }
    let challenge = db::generate_session_id();
    let expires_at = OffsetDateTime::now_utc() + CHALLENGE_TTL;
    if let Err(error) = db::set_dbsc_challenge(&state.db, session_id, &challenge, expires_at).await
    {
        tracing::warn!(
            ?error,
            "DBSC challenge not stored; omitting registration header"
        );
        return None;
    }
    match HeaderValue::from_str(&registration_value(&challenge)) {
        Ok(value) => Some(value),
        Err(error) => {
            tracing::warn!(?error, "DBSC registration header invalid; omitting it");
            None
        }
    }
}

/// A browser that logs in again while it holds a bound session would keep two
/// DBSC sessions refreshing the same cookie: CSRF flips between them and the
/// old one undoes logout. Delete the old session so its next refresh gets
/// `{"continue": false}`. Only a bound session is ever deleted, so clients that
/// never register behave as before. Best-effort: an error is only logged.
async fn end_stale_bound_session(state: &AppState, request_headers: &HeaderMap) {
    let Some(presented) = crate::csrf::get_cookie(request_headers, SESSION_COOKIE) else {
        return;
    };
    match db::delete_bound_session_by_token(&state.db, &presented).await {
        Ok(true) => tracing::info!("Ended the bound DBSC session presented at login"),
        Ok(false) => {}
        Err(error) => tracing::warn!(
            ?error,
            "Stale bound DBSC session not ended; continuing login"
        ),
    }
}

fn registration_value(challenge: &str) -> String {
    format!(r#"(ES256);path="{REGISTER_PATH}";challenge="{challenge}""#)
}

/// The session instructions JSON returned by register and refresh.
pub(crate) fn session_instructions(dbsc_id: &str) -> serde_json::Value {
    serde_json::json!({
        "session_identifier": dbsc_id,
        "refresh_url": REFRESH_PATH,
        "scope": { "include_site": false },
        "credentials": [{
            "type": "cookie",
            "name": SESSION_COOKIE,
            "attributes": BOUND_COOKIE_ATTRIBUTES,
        }],
    })
}

/// `Secure-Session-Challenge: "<challenge>";id="<dbsc_id>"`. Both values come
/// from `db::generate_session_id` (base64url), so the header is always valid.
pub(crate) fn challenge_header(challenge: &str, dbsc_id: &str) -> HeaderValue {
    HeaderValue::from_str(&format!(r#""{challenge}";id="{dbsc_id}""#))
        .expect("base64url challenge and DBSC id form a valid header value")
}

/// Bound token expiry, `min(now + 600 s, session expiry)`, and the cookie
/// `Max-Age` in seconds: 5 s less, but at least 1 (0 would delete the cookie).
fn bound_token_expiry(
    now: OffsetDateTime,
    session_expires_at: OffsetDateTime,
) -> (OffsetDateTime, i64) {
    let expires_at = (now + BOUND_TOKEN_TTL).min(session_expires_at);
    let max_age_secs = ((expires_at - now).whole_seconds() - COOKIE_EXPIRY_MARGIN_SECS).max(1);
    (expires_at, max_age_secs)
}

/// The session's outstanding challenge, unless it has expired.
fn live_challenge(session: &DbscSession, now: OffsetDateTime) -> Option<&str> {
    match (&session.dbsc_challenge, session.dbsc_challenge_expires_at) {
        (Some(challenge), Some(expires_at)) if expires_at > now => Some(challenge),
        _ => None,
    }
}

/// The `Secure-Session-Response` proof, if sent. A value that is not visible
/// ASCII cannot be a compact JWS and is an invalid proof.
fn proof_header(headers: &HeaderMap) -> Result<Option<&str>, DbscError> {
    use DbscErrorCtx as Ctx;

    headers
        .get(SECURE_SESSION_RESPONSE)
        .map(|v| v.to_str().map(unquote_sf_string))
        .transpose()
        .with_context(Ctx::invalid_proof())
}

/// `Secure-Session-Response` and `Sec-Secure-Session-Id` are sf-strings in the
/// W3C draft; Chromium sends them unquoted today. Strip one optional pair of
/// surrounding double quotes. The values (compact JWS, base64url ids) never
/// contain quotes or backslashes, so there is nothing to unescape.
fn unquote_sf_string(value: &str) -> &str {
    value
        .strip_prefix('"')
        .and_then(|inner| inner.strip_suffix('"'))
        .unwrap_or(value)
}

/// The `Sec-Secure-Session-Id` sent to refresh, if it is visible ASCII.
fn presented_session_id(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(SEC_SECURE_SESSION_ID)
        .and_then(|v| v.to_str().ok())
        .map(unquote_sf_string)
}

/// Cookies are `Secure` except in local HTTP development, as in the login
/// handlers.
fn secure_cookies() -> bool {
    std::env::var("ENVIRONMENT")
        .map(|e| e != "development")
        .unwrap_or(true)
}

/// 200 with the bound cookie and the session instructions.
fn bound_response(token: &str, max_age_secs: i64, dbsc_id: &str) -> Response {
    let cookie = build_bound_session_cookie(token, max_age_secs, secure_cookies());
    (
        StatusCode::OK,
        [(header::SET_COOKIE, cookie)],
        Json(session_instructions(dbsc_id)),
    )
        .into_response()
}

/// Handler error for the DBSC endpoints. Bodies are generic; the detail is
/// logged.
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum DbscError {
    #[error("DBSC is disabled (DBSC_ENABLED is off) [{location}]")]
    Disabled {
        #[location]
        location: Location,
    },

    #[error("no live, unbound session for the presented cookie [{location}]")]
    NoSession {
        #[location]
        location: Location,
    },

    #[error("no live DBSC challenge for the session [{location}]")]
    NoChallenge {
        #[location]
        location: Location,
    },

    #[error("DBSC proof is missing [{location}]")]
    MissingProof {
        #[location]
        location: Location,
    },

    #[error("DBSC proof is invalid [{location}]")]
    InvalidProof {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("session is already bound to a DBSC key [{location}]")]
    AlreadyBound {
        #[location]
        location: Location,
    },

    #[error("DBSC binding was not applied (lost a race, or expired meanwhile) [{location}]")]
    BindRejected {
        #[location]
        location: Location,
    },

    #[error("stored DBSC public key is unusable [{location}]")]
    StoredKey {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("DBSC database operation failed [{location}]")]
    Database {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for DbscError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            Self::Disabled { .. }
            | Self::NoSession { .. }
            | Self::NoChallenge { .. }
            | Self::MissingProof { .. } => {
                tracing::debug!(?self, "DBSC request rejected");
                (StatusCode::UNAUTHORIZED, "authentication required")
            }
            Self::InvalidProof { .. } => {
                tracing::warn!(?self, "DBSC proof rejected");
                (StatusCode::UNAUTHORIZED, "authentication required")
            }
            Self::AlreadyBound { .. } | Self::BindRejected { .. } => {
                tracing::warn!(?self, "DBSC binding refused");
                (StatusCode::CONFLICT, "session already bound")
            }
            Self::StoredKey { .. } | Self::Database { .. } => {
                tracing::error!(?self, "DBSC request failed");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "An internal error occurred",
                )
            }
        };
        sentry_middleware::error_response(status, body, self)
    }
}

/// `POST /auth/dbsc/register`: bind the session in the raw `caution_session`
/// cookie to the key in the proof, and swap the cookie for a bound token.
#[tracing::instrument(skip_all)]
pub(crate) async fn dbsc_register_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    register(&state, &headers)
        .await
        .unwrap_or_else(IntoResponse::into_response)
}

async fn register(state: &AppState, headers: &HeaderMap) -> Result<Response, DbscError> {
    use DbscErrorCtx as Ctx;

    // Flag off: no new bindings, even from a challenge issued before the
    // switch. Refresh stays open so already-bound sessions keep working.
    if !state.dbsc_enabled {
        return Err(DbscError::Disabled {
            location: std::panic::Location::caller(),
        });
    }

    // Only the raw id of a live session can register. A bound token never
    // matches a `session_id`.
    let session_id =
        crate::csrf::get_cookie(headers, SESSION_COOKIE).ok_or_else(|| DbscError::NoSession {
            location: std::panic::Location::caller(),
        })?;
    let session = db::get_dbsc_session_by_session_id(&state.db, &session_id)
        .await
        .with_context(Ctx::database())?
        .ok_or_else(|| DbscError::NoSession {
            location: std::panic::Location::caller(),
        })?;
    let now = OffsetDateTime::now_utc();
    if session.expires_at <= now {
        return Err(DbscError::NoSession {
            location: std::panic::Location::caller(),
        });
    }
    if session.dbsc_public_key.is_some() {
        return Err(DbscError::AlreadyBound {
            location: std::panic::Location::caller(),
        });
    }
    let challenge = live_challenge(&session, now).ok_or_else(|| DbscError::NoChallenge {
        location: std::panic::Location::caller(),
    })?;
    let proof = proof_header(headers)?.ok_or_else(|| DbscError::MissingProof {
        location: std::panic::Location::caller(),
    })?;
    // Every proof failure is a 401 here, a stale challenge included: the key
    // is self-asserted, so a mismatch carries no trust worth re-challenging.
    let key = verify_registration_proof(proof, challenge).with_context(Ctx::invalid_proof())?;

    let dbsc_id = db::generate_session_id();
    let token = db::generate_session_id();
    let (token_expires_at, max_age_secs) = bound_token_expiry(now, session.expires_at);
    let bound = db::bind_dbsc_session(
        &state.db,
        &session.session_id,
        challenge,
        &dbsc_id,
        &encode_public_key(&key),
        &db::hash_bound_token(&token),
        token_expires_at,
    )
    .await
    .with_context(Ctx::database())?;
    if !bound {
        return Err(DbscError::BindRejected {
            location: std::panic::Location::caller(),
        });
    }

    tracing::info!("DBSC session bound");
    Ok(bound_response(&token, max_age_secs, &dbsc_id))
}

/// `POST /auth/dbsc/refresh`: challenge, then rotate the bound token on a
/// valid proof from the registered key.
#[tracing::instrument(skip_all)]
pub(crate) async fn dbsc_refresh_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    refresh(&state, &headers)
        .await
        .unwrap_or_else(IntoResponse::into_response)
}

async fn refresh(state: &AppState, headers: &HeaderMap) -> Result<Response, DbscError> {
    use DbscErrorCtx as Ctx;

    let presented_id = presented_session_id(headers);
    let session = match presented_id {
        Some(dbsc_id) => db::get_dbsc_session_by_dbsc_id(&state.db, dbsc_id)
            .await
            .with_context(Ctx::database())?,
        None => None,
    };
    let now = OffsetDateTime::now_utc();
    // Unknown, or past the session's absolute expiry: Chrome ends its DBSC
    // session and the user logs in again.
    let Some(session) = session.filter(|s| s.expires_at > now) else {
        return Ok(end_session(presented_id));
    };
    let (Some(dbsc_id), Some(public_key)) = (
        session.dbsc_id.as_deref(),
        session.dbsc_public_key.as_deref(),
    ) else {
        return Ok(end_session(presented_id));
    };

    let live = live_challenge(&session, now);
    let (Some(proof), Some(challenge)) = (proof_header(headers)?, live) else {
        return send_challenge(state, &session.session_id, dbsc_id, live).await;
    };
    let key = decode_public_key(public_key).with_context(Ctx::stored_key())?;
    if let Err(error) = verify_refresh_proof(proof, challenge, &key) {
        if error.kind() == DbscProofErrorKind::ChallengeMismatch {
            return send_challenge(state, &session.session_id, dbsc_id, live).await;
        }
        return Err(error).with_context(Ctx::invalid_proof());
    }

    let token = db::generate_session_id();
    let (token_expires_at, max_age_secs) = bound_token_expiry(now, session.expires_at);
    let rotated = db::rotate_bound_token(
        &state.db,
        dbsc_id,
        challenge,
        &db::hash_bound_token(&token),
        token_expires_at,
    )
    .await
    .with_context(Ctx::database())?;
    if !rotated {
        // A concurrent refresh consumed the challenge first: mint a new one.
        return send_challenge(state, &session.session_id, dbsc_id, None).await;
    }

    Ok(bound_response(&token, max_age_secs, dbsc_id))
}

/// `200 {"continue": false}`: Chrome ends its DBSC session. Chromium matches
/// `session_identifier` before reading `continue`, so the presented id is
/// echoed; it is omitted only when none was presented.
fn end_session(presented_id: Option<&str>) -> Response {
    let mut body = serde_json::json!({ "continue": false });
    if let Some(id) = presented_id {
        body["session_identifier"] = serde_json::Value::from(id);
    }
    Json(body).into_response()
}

/// Send the challenge with a 403. A still-live challenge is resent as is, so
/// proof-less refreshes (anyone holding the `dbsc_id`) cannot keep replacing
/// the one Chrome is about to sign; a new one is minted and stored only when
/// none is live.
async fn send_challenge(
    state: &AppState,
    session_id: &str,
    dbsc_id: &str,
    live: Option<&str>,
) -> Result<Response, DbscError> {
    use DbscErrorCtx as Ctx;

    let challenge = match live {
        Some(challenge) => challenge.to_string(),
        None => {
            let challenge = db::generate_session_id();
            db::set_dbsc_challenge(
                &state.db,
                session_id,
                &challenge,
                OffsetDateTime::now_utc() + CHALLENGE_TTL,
            )
            .await
            .with_context(Ctx::database())?;
            challenge
        }
    };
    tracing::debug!("DBSC refresh challenged");
    Ok((
        StatusCode::FORBIDDEN,
        [(
            SECURE_SESSION_CHALLENGE,
            challenge_header(&challenge, dbsc_id),
        )],
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        middleware,
        routing::post,
        Router,
    };
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};
    use serde_json::{json, Value};
    use sqlx::PgPool;
    use time::Duration;
    use tower::Service;
    use uuid::Uuid;

    use super::super::common::build_bound_session_cookie;
    use crate::db;
    use crate::handlers::build_auth_cookies;

    const CSRF_SECRET: &str = "test-secret";

    /// `AppState` as in `webauthn::login`'s `test_app_state`, around `db`.
    fn app_state(db: PgPool, dbsc_enabled: bool) -> AppState {
        use std::collections::HashMap;
        use std::sync::Arc;
        use tokio::sync::RwLock;
        use webauthn_rs::prelude::{Url, WebauthnBuilder};

        let rp_origin = Url::parse("https://example.com").unwrap();
        let webauthn = WebauthnBuilder::new("example.com", &rp_origin)
            .unwrap()
            .rp_name("Test RP")
            .build()
            .unwrap();
        AppState {
            db,
            webauthn,
            relying_party_id: "example.com".to_string(),
            api_service_url: "http://localhost:3000".to_string(),
            metering_service_url: String::new(),
            http_client: reqwest::Client::new(),
            reg_states: Arc::new(RwLock::new(HashMap::new())),
            passkey_reg_states: Arc::new(RwLock::new(HashMap::new())),
            recovery_verifications: Arc::new(RwLock::new(HashMap::new())),
            auth_states: Arc::new(RwLock::new(HashMap::new())),
            sign_challenges: Arc::new(RwLock::new(HashMap::new())),
            session_timeout_hours: 24,
            internal_service_secret: None,
            csrf_secret: CSRF_SECRET.to_string(),
            login_allow_broadcast: true,
            scoped_begin_limiter: crate::rate_limit::RateLimiter::new(1000, 60),
            username_begin_limiter: crate::rate_limit::RateLimiter::new(1000, 60),
            dbsc_enabled,
        }
    }

    /// Request headers carrying `caution_session=<value>`.
    fn cookie(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_str(&format!("caution_session={value}")).unwrap(),
        );
        headers
    }

    /// A pool whose every query fails fast (nothing listens on port 1).
    fn offline_state(dbsc_enabled: bool) -> AppState {
        let db = sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(std::time::Duration::from_millis(500))
            .connect_lazy("postgres://user:pass@127.0.0.1:1/nonexistent")
            .expect("connect_lazy does not actually connect");
        app_state(db, dbsc_enabled)
    }

    #[test]
    fn registration_header_format() {
        assert_eq!(
            registration_value("c-1_x"),
            r#"(ES256);path="/auth/dbsc/register";challenge="c-1_x""#
        );
    }

    #[test]
    fn challenge_header_format() {
        assert_eq!(
            challenge_header("c-1", "id-1").to_str().unwrap(),
            r#""c-1";id="id-1""#
        );
    }

    #[test]
    fn instructions_json_exact() {
        let instructions = session_instructions("id-1");
        assert_eq!(
            instructions,
            json!({
                "session_identifier": "id-1",
                "refresh_url": "/auth/dbsc/refresh",
                "scope": { "include_site": false },
                "credentials": [{
                    "type": "cookie",
                    "name": "caution_session",
                    "attributes": "Path=/; Secure; HttpOnly; SameSite=Strict",
                }],
            })
        );
        assert_eq!(instructions["scope"]["include_site"], json!(false));
        assert_eq!(instructions["credentials"][0]["name"], "caution_session");
        assert_eq!(
            instructions["credentials"][0]["attributes"],
            "Path=/; Secure; HttpOnly; SameSite=Strict"
        );
    }

    #[test]
    fn bound_cookie_attributes() {
        let raw = build_bound_session_cookie("tok", 600, true);
        let cookie = cookie::Cookie::parse(raw.as_str()).unwrap();
        assert_eq!((cookie.name(), cookie.value()), ("caution_session", "tok"));
        assert_eq!(cookie.max_age(), Some(cookie::time::Duration::seconds(600)));
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.secure(), Some(true));
        assert_eq!(cookie.same_site(), Some(cookie::SameSite::Strict));
        assert_eq!(cookie.path(), Some("/"));
        assert!(raw.contains("Max-Age=600"), "{raw}");
        // The login session cookie's attributes, with only Max-Age changed.
        let (login, _) = build_auth_cookies("tok", "csrf", 1, true);
        assert_eq!(login.replace("Max-Age=3600", "Max-Age=600"), raw);
    }

    #[test]
    fn bound_expiry_capped_at_session_expiry() {
        // The cookie's Max-Age stays 5 s below the token's server-side TTL, so
        // the browser refreshes before the server rejects the token.
        let now = OffsetDateTime::now_utc();
        assert_eq!(
            bound_token_expiry(now, now + Duration::hours(24)),
            (now + Duration::seconds(600), 595)
        );
        assert_eq!(
            bound_token_expiry(now, now + Duration::seconds(90)),
            (now + Duration::seconds(90), 85)
        );
        // Near the session's end, Max-Age never drops below 1 s (0 would
        // delete the cookie outright).
        assert_eq!(
            bound_token_expiry(now, now + Duration::seconds(3)),
            (now + Duration::seconds(3), 1)
        );
    }

    #[test]
    fn sf_string_quotes_are_optional() {
        assert_eq!(unquote_sf_string(r#""a.b.c""#), "a.b.c");
        assert_eq!(unquote_sf_string("a.b.c"), "a.b.c");
        assert_eq!(unquote_sf_string(r#""""#), "");
        // Not a quoted pair: left as is.
        assert_eq!(unquote_sf_string(r#"""#), r#"""#);
        assert_eq!(unquote_sf_string(r#""a.b"#), r#""a.b"#);
        assert_eq!(unquote_sf_string(r#"a.b""#), r#"a.b""#);
    }

    #[test]
    fn dbsc_request_headers_accept_both_forms() {
        for (proof, id) in [("a.b.c", "id-1"), (r#""a.b.c""#, r#""id-1""#)] {
            let mut headers = HeaderMap::new();
            headers.insert(SECURE_SESSION_RESPONSE, HeaderValue::from_static(proof));
            headers.insert(SEC_SECURE_SESSION_ID, HeaderValue::from_static(id));
            assert_eq!(proof_header(&headers).unwrap(), Some("a.b.c"), "{proof}");
            assert_eq!(presented_session_id(&headers), Some("id-1"), "{id}");
        }
        assert_eq!(proof_header(&HeaderMap::new()).unwrap(), None);
        assert_eq!(presented_session_id(&HeaderMap::new()), None);
    }

    #[tokio::test]
    async fn no_header_when_disabled_or_insecure() {
        for (enabled, secure) in [(false, true), (true, false), (false, false)] {
            assert!(
                registration_header(&offline_state(enabled), "sid", secure, &HeaderMap::new())
                    .await
                    .is_none(),
                "enabled={enabled} secure={secure}"
            );
        }
    }

    #[tokio::test]
    async fn db_error_omits_header() {
        // DBSC never fails a login: a stale session that cannot be ended or a
        // challenge that cannot be stored only drops the header.
        assert!(
            registration_header(&offline_state(true), "sid", true, &cookie("old"))
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn register_refused_when_disabled() {
        // Refused before any DB access, so the offline pool is never touched.
        let app = router(offline_state(false));
        let reply = register(&app, RAW, Some("any-proof")).await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    }

    // --- Flow tests against a disposable Postgres ------------------------

    const MIGRATION: &str = include_str!("../../../api/migrations/060_dbsc.sql");
    const RAW: &str = "raw-session-id";

    /// Minimal `auth_sessions` (as in `db/dbsc_tests.rs`) plus `060_dbsc.sql`,
    /// holding one live, unbound session `RAW`.
    async fn fixture(pool: &PgPool) {
        sqlx::raw_sql(
            "CREATE TABLE auth_sessions (
                session_id TEXT PRIMARY KEY, credential_id BYTEA,
                user_id UUID NOT NULL,
                created_at TIMESTAMPTZ, expires_at TIMESTAMPTZ, last_used_at TIMESTAMPTZ);",
        )
        .execute(pool)
        .await
        .unwrap();
        sqlx::raw_sql(MIGRATION).execute(pool).await.unwrap();
        db::create_auth_session(
            pool,
            RAW,
            b"cred",
            Uuid::new_v4(),
            OffsetDateTime::now_utc() + Duration::hours(24),
        )
        .await
        .unwrap();
    }

    /// The DBSC endpoints and logout, plus `POST /probe` behind the session
    /// middleware that guards every protected route.
    fn router(state: AppState) -> Router {
        let probe = Router::new()
            .route("/probe", post(|| async { "ok" }))
            .layer(middleware::from_fn_with_state(
                state.clone(),
                crate::auth_middleware::fido2_auth_middleware,
            ));
        Router::new()
            .route("/auth/dbsc/register", post(dbsc_register_handler))
            .route("/auth/dbsc/refresh", post(dbsc_refresh_handler))
            .route("/auth/logout", post(crate::handlers::logout_handler))
            .with_state(state)
            .merge(probe)
    }

    struct Reply {
        status: StatusCode,
        headers: HeaderMap,
        body: Vec<u8>,
    }

    impl Reply {
        fn header(&self, name: &str) -> &str {
            self.headers
                .get(name)
                .unwrap_or_else(|| panic!("missing {name}"))
                .to_str()
                .unwrap()
        }

        fn json(&self) -> Value {
            serde_json::from_slice(&self.body).unwrap()
        }

        /// The new `caution_session` value, checking the bound-cookie TTL: 5 s
        /// under the 600 s token, so the cookie never outlives it.
        fn session_cookie(&self) -> String {
            let cookie = cookie::Cookie::parse(self.header("set-cookie").to_string()).unwrap();
            assert_eq!(cookie.name(), "caution_session");
            assert_eq!(cookie.max_age(), Some(cookie::time::Duration::seconds(595)));
            cookie.value().to_string()
        }

        /// The challenge from `Secure-Session-Challenge: "<c>";id="<id>"`.
        fn challenge(&self) -> String {
            let value = self.header("secure-session-challenge");
            value.split('"').nth(1).unwrap().to_string()
        }
    }

    async fn send(app: &Router, uri: &str, headers: &[(&str, &str)]) -> Reply {
        let mut request = Request::builder().method("POST").uri(uri);
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let response = app
            .clone()
            .call(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap()
            .to_vec();
        Reply {
            status,
            headers,
            body,
        }
    }

    /// Browser transport: the cookie plus an `X-CSRF-Token` derived from `csrf_of`.
    async fn probe_with_csrf(app: &Router, cookie_value: &str, csrf_of: &str) -> StatusCode {
        let cookie = format!("caution_session={cookie_value}");
        let csrf = crate::csrf::derive_csrf_token(csrf_of, CSRF_SECRET);
        send(
            app,
            "/probe",
            &[("cookie", cookie.as_str()), ("x-csrf-token", csrf.as_str())],
        )
        .await
        .status
    }

    /// Browser transport with the CSRF token of the canonical session id.
    async fn probe_cookie(app: &Router, cookie_value: &str) -> StatusCode {
        probe_with_csrf(app, cookie_value, RAW).await
    }

    /// CLI transport.
    async fn probe_header(app: &Router, session: &str) -> StatusCode {
        send(app, "/probe", &[("x-session-id", session)])
            .await
            .status
    }

    async fn register(app: &Router, cookie_value: &str, proof: Option<&str>) -> Reply {
        let cookie = format!("caution_session={cookie_value}");
        let mut headers = vec![("cookie", cookie.as_str())];
        headers.extend(proof.map(|p| ("secure-session-response", p)));
        send(app, "/auth/dbsc/register", &headers).await
    }

    async fn refresh(app: &Router, dbsc_id: &str, proof: Option<&str>) -> Reply {
        let mut headers = vec![("sec-secure-session-id", dbsc_id)];
        headers.extend(proof.map(|p| ("secure-session-response", p)));
        send(app, "/auth/dbsc/refresh", &headers).await
    }

    fn new_key() -> SigningKey {
        SigningKey::random(&mut rand::thread_rng())
    }

    /// A DBSC proof as Chrome signs it. Registration proofs carry the `jwk`.
    fn proof(key: &SigningKey, jti: &str, with_jwk: bool) -> String {
        let mut header = json!({"typ": "dbsc+jwt", "alg": "ES256"});
        if with_jwk {
            let public = p256::PublicKey::from(key.verifying_key());
            header["jwk"] = serde_json::from_str(&public.to_jwk_string()).unwrap();
        }
        let payload = json!({"jti": jti, "iat": OffsetDateTime::now_utc().unix_timestamp()});
        let signing_input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(payload.to_string())
        );
        let signature: Signature = key.sign(signing_input.as_bytes());
        format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        )
    }

    /// Login over HTTPS: the challenge in the registration header.
    async fn login(state: &AppState) -> String {
        let header = registration_header(state, RAW, true, &HeaderMap::new())
            .await
            .expect("DBSC offered");
        let header = header.to_str().unwrap();
        let prefix = r#"(ES256);path="/auth/dbsc/register";challenge=""#;
        assert!(header.starts_with(prefix), "{header}");
        header[prefix.len()..].trim_end_matches('"').to_string()
    }

    /// Login, then register `key`. Returns the bound token and the `dbsc_id`.
    async fn bind(state: &AppState, app: &Router, key: &SigningKey) -> (String, String) {
        let challenge = login(state).await;
        let reply = register(app, RAW, Some(&proof(key, &challenge, true))).await;
        assert_eq!(reply.status, StatusCode::OK);
        let token = reply.session_cookie();
        let dbsc_id = reply.json()["session_identifier"]
            .as_str()
            .unwrap()
            .to_string();
        (token, dbsc_id)
    }

    /// End the previous credential's grace, as if it had elapsed.
    async fn end_grace(pool: &PgPool) {
        sqlx::query(
            "UPDATE auth_sessions SET prev_credential_expires_at = NOW() - INTERVAL '1 second'",
        )
        .execute(pool)
        .await
        .unwrap();
    }

    async fn dbsc_state(pool: &PgPool) -> crate::types::DbscSession {
        db::get_dbsc_session_by_session_id(pool, RAW)
            .await
            .unwrap()
            .unwrap()
    }

    #[sqlx::test(migrations = false)]
    #[ignore = "requires DATABASE_URL pointing to disposable Postgres"]
    async fn unregistered_client_keeps_working(pool: PgPool) {
        fixture(&pool).await;
        let state = app_state(pool.clone(), true);

        // Plain-HTTP dev: no offer, and nothing is stored.
        assert!(registration_header(&state, RAW, false, &HeaderMap::new())
            .await
            .is_none());
        assert_eq!(dbsc_state(&pool).await.dbsc_challenge, None);

        // Offered over HTTPS; Firefox, Safari and the CLI never register.
        let before = OffsetDateTime::now_utc();
        let challenge = login(&state).await;
        let stored = dbsc_state(&pool).await;
        assert_eq!(stored.dbsc_challenge.as_deref(), Some(challenge.as_str()));
        let expires_at = stored.dbsc_challenge_expires_at.unwrap();
        assert!(
            expires_at >= before + Duration::seconds(299),
            "{expires_at}"
        );
        assert!(
            expires_at <= OffsetDateTime::now_utc() + Duration::seconds(300),
            "{expires_at}"
        );

        let app = router(state);
        assert_eq!(probe_cookie(&app, RAW).await, StatusCode::OK);
        assert_eq!(probe_header(&app, RAW).await, StatusCode::OK);

        // Logout by the raw id still ends the session.
        let reply = send(&app, "/auth/logout", &[("x-session-id", RAW)]).await;
        assert_eq!(reply.status, StatusCode::OK);
        assert_eq!(probe_header(&app, RAW).await, StatusCode::UNAUTHORIZED);
    }

    #[sqlx::test(migrations = false)]
    #[ignore = "requires DATABASE_URL pointing to disposable Postgres"]
    async fn register_then_refresh_flow(pool: PgPool) {
        fixture(&pool).await;
        let state = app_state(pool.clone(), true);
        let app = router(state.clone());
        let key = new_key();

        let challenge = login(&state).await;
        let reply = register(&app, RAW, Some(&proof(&key, &challenge, true))).await;
        assert_eq!(reply.status, StatusCode::OK);
        assert_eq!(reply.header("content-type"), "application/json");
        let token = reply.session_cookie();
        assert_ne!(token, RAW);
        let dbsc_id = reply.json()["session_identifier"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(reply.json(), session_instructions(&dbsc_id));
        assert_eq!(probe_cookie(&app, &token).await, StatusCode::OK);

        // Chrome's first refresh carries no proof: it is challenged.
        let reply = refresh(&app, &dbsc_id, None).await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN);
        let first = reply.challenge();
        assert_eq!(
            reply.header("secure-session-challenge"),
            format!(r#""{first}";id="{dbsc_id}""#)
        );

        // A stale jti is challenged again with the live challenge, not rejected.
        let reply = refresh(&app, &dbsc_id, Some(&proof(&key, &challenge, false))).await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN);
        let second = reply.challenge();
        assert_eq!(second, first);

        let reply = refresh(&app, &dbsc_id, Some(&proof(&key, &second, false))).await;
        assert_eq!(reply.status, StatusCode::OK);
        assert_eq!(reply.json(), session_instructions(&dbsc_id));
        let new_token = reply.session_cookie();
        assert_ne!(new_token, token);
        assert_eq!(probe_cookie(&app, &new_token).await, StatusCode::OK);
        // Requests in flight with the old token survive the rotation briefly.
        assert_eq!(probe_cookie(&app, &token).await, StatusCode::OK);
        end_grace(&pool).await;
        assert_eq!(probe_cookie(&app, &token).await, StatusCode::UNAUTHORIZED);
        assert_eq!(probe_cookie(&app, &new_token).await, StatusCode::OK);

        // The challenge is single-use.
        let reply = refresh(&app, &dbsc_id, Some(&proof(&key, &second, false))).await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN);

        // Logout with the bound cookie ends the DBSC session too.
        let cookie = format!("caution_session={new_token}");
        let reply = send(&app, "/auth/logout", &[("cookie", cookie.as_str())]).await;
        assert_eq!(reply.status, StatusCode::OK);
        let reply = refresh(&app, &dbsc_id, None).await;
        assert_eq!(reply.status, StatusCode::OK);
        assert_eq!(
            reply.json(),
            json!({"session_identifier": dbsc_id, "continue": false})
        );
    }

    #[sqlx::test(migrations = false)]
    #[ignore = "requires DATABASE_URL pointing to disposable Postgres"]
    async fn flag_off_refuses_registration_but_keeps_refresh(pool: PgPool) {
        fixture(&pool).await;
        let on = app_state(pool.clone(), true);
        let on_app = router(on.clone());
        let off_app = router(app_state(pool.clone(), false));
        let key = new_key();

        // A challenge issued before the flag went off cannot bind...
        let challenge = login(&on).await;
        let signed = proof(&key, &challenge, true);
        let reply = register(&off_app, RAW, Some(&signed)).await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
        assert_eq!(dbsc_state(&pool).await.dbsc_public_key, None);

        // ...though the very same proof binds with the flag on.
        let reply = register(&on_app, RAW, Some(&signed)).await;
        assert_eq!(reply.status, StatusCode::OK);
        let dbsc_id = reply.json()["session_identifier"]
            .as_str()
            .unwrap()
            .to_string();

        // A session bound while on still refreshes once off.
        let next = refresh(&off_app, &dbsc_id, None).await.challenge();
        let reply = refresh(&off_app, &dbsc_id, Some(&proof(&key, &next, false))).await;
        assert_eq!(reply.status, StatusCode::OK);
        let token = reply.session_cookie();
        assert_eq!(probe_cookie(&off_app, &token).await, StatusCode::OK);
    }

    #[sqlx::test(migrations = false)]
    #[ignore = "requires DATABASE_URL pointing to disposable Postgres"]
    async fn proofless_refreshes_reuse_the_live_challenge(pool: PgPool) {
        fixture(&pool).await;
        let state = app_state(pool.clone(), true);
        let app = router(state.clone());
        let key = new_key();
        let (_, dbsc_id) = bind(&state, &app, &key).await;

        // Anyone holding the dbsc_id can spam refresh, but the challenge
        // Chrome is about to sign stays put.
        let first = refresh(&app, &dbsc_id, None).await.challenge();
        for _ in 0..3 {
            assert_eq!(refresh(&app, &dbsc_id, None).await.challenge(), first);
        }
        let reply = refresh(&app, &dbsc_id, Some(&proof(&key, &first, false))).await;
        assert_eq!(reply.status, StatusCode::OK);

        // Consumed by the rotation: the next challenge is new.
        let second = refresh(&app, &dbsc_id, None).await.challenge();
        assert_ne!(second, first);

        // Expired: a new one is minted instead of resending it.
        sqlx::query(
            "UPDATE auth_sessions SET dbsc_challenge_expires_at = NOW() - INTERVAL '1 second'",
        )
        .execute(&pool)
        .await
        .unwrap();
        let third = refresh(&app, &dbsc_id, None).await.challenge();
        assert_ne!(third, second);
        let reply = refresh(&app, &dbsc_id, Some(&proof(&key, &third, false))).await;
        assert_eq!(reply.status, StatusCode::OK);
    }

    #[sqlx::test(migrations = false)]
    #[ignore = "requires DATABASE_URL pointing to disposable Postgres"]
    async fn bound_cookie_passes_csrf_with_canonical_session_id(pool: PgPool) {
        fixture(&pool).await;
        let state = app_state(pool.clone(), true);
        let app = router(state.clone());
        let (token, _) = bind(&state, &app, &new_key()).await;

        assert_eq!(probe_cookie(&app, &token).await, StatusCode::OK);
        // CSRF stays bound to the canonical id, not the presented token.
        assert_eq!(
            probe_with_csrf(&app, &token, &token).await,
            StatusCode::FORBIDDEN
        );
        // Requests in flight with the raw id survive the bind briefly.
        assert_eq!(probe_cookie(&app, RAW).await, StatusCode::OK);
        assert_eq!(probe_header(&app, RAW).await, StatusCode::OK);
        // After that grace, the raw id is rejected on both transports.
        end_grace(&pool).await;
        assert_eq!(probe_cookie(&app, RAW).await, StatusCode::UNAUTHORIZED);
        assert_eq!(probe_header(&app, RAW).await, StatusCode::UNAUTHORIZED);
    }

    #[sqlx::test(migrations = false)]
    #[ignore = "requires DATABASE_URL pointing to disposable Postgres"]
    async fn register_twice_is_409(pool: PgPool) {
        fixture(&pool).await;
        let state = app_state(pool.clone(), true);
        let app = router(state.clone());
        let key = new_key();
        let (token, dbsc_id) = bind(&state, &app, &key).await;

        // A second registration with the raw id (e.g. a thief who stole it
        // before the binding) cannot rebind the session.
        let reply = register(&app, RAW, Some(&proof(&new_key(), "any", true))).await;
        assert_eq!(reply.status, StatusCode::CONFLICT);
        assert!(reply.headers.get("set-cookie").is_none());

        let stored = dbsc_state(&pool).await;
        assert_eq!(stored.dbsc_id.as_deref(), Some(dbsc_id.as_str()));
        assert_eq!(
            stored.dbsc_public_key.as_deref(),
            Some(crate::dbsc::encode_public_key(key.verifying_key()).as_slice())
        );
        assert_eq!(probe_cookie(&app, &token).await, StatusCode::OK);
    }

    #[sqlx::test(migrations = false)]
    #[ignore = "requires DATABASE_URL pointing to disposable Postgres"]
    async fn register_rejects_with_401(pool: PgPool) {
        fixture(&pool).await;
        let state = app_state(pool.clone(), true);
        let app = router(state.clone());
        let key = new_key();
        let challenge = login(&state).await;
        let good = proof(&key, &challenge, true);

        // No session cookie, or an unknown one.
        let reply = send(
            &app,
            "/auth/dbsc/register",
            &[("secure-session-response", good.as_str())],
        )
        .await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
        let reply = register(&app, "unknown", Some(&good)).await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
        // No proof.
        assert_eq!(
            register(&app, RAW, None).await.status,
            StatusCode::UNAUTHORIZED
        );
        // A wrong challenge is a plain 401: the key is self-asserted, so
        // there is nothing to re-challenge.
        let reply = register(&app, RAW, Some(&proof(&key, "stale", true))).await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
        assert!(reply.headers.get("secure-session-challenge").is_none());
        // A refresh-style proof without the jwk.
        let reply = register(&app, RAW, Some(&proof(&key, &challenge, false))).await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
        // An expired challenge.
        sqlx::query(
            "UPDATE auth_sessions SET dbsc_challenge_expires_at = NOW() - INTERVAL '1 second'",
        )
        .execute(&pool)
        .await
        .unwrap();
        assert_eq!(
            register(&app, RAW, Some(&good)).await.status,
            StatusCode::UNAUTHORIZED
        );

        // Nothing was bound: the raw id keeps working.
        assert_eq!(dbsc_state(&pool).await.dbsc_public_key, None);
        assert_eq!(probe_header(&app, RAW).await, StatusCode::OK);
    }

    #[sqlx::test(migrations = false)]
    #[ignore = "requires DATABASE_URL pointing to disposable Postgres"]
    async fn refresh_unknown_or_expired_session_continue_false(pool: PgPool) {
        fixture(&pool).await;
        let state = app_state(pool.clone(), true);
        let app = router(state.clone());
        let key = new_key();
        // Chromium matches `session_identifier` before reading `continue`, so
        // the presented id is echoed; it is omitted only when none was sent.
        let stop = |id: &str| json!({"session_identifier": id, "continue": false});

        let reply = refresh(&app, "unknown", None).await;
        assert_eq!(
            (reply.status, reply.json()),
            (StatusCode::OK, stop("unknown"))
        );
        let reply = refresh(&app, r#""unknown""#, None).await;
        assert_eq!(
            (reply.status, reply.json()),
            (StatusCode::OK, stop("unknown"))
        );
        let reply = send(&app, "/auth/dbsc/refresh", &[]).await;
        assert_eq!(
            (reply.status, reply.json()),
            (StatusCode::OK, json!({"continue": false}))
        );

        // Past the 24h session expiry, even a valid proof cannot refresh.
        let (_, dbsc_id) = bind(&state, &app, &key).await;
        let challenge = refresh(&app, &dbsc_id, None).await.challenge();
        sqlx::query("UPDATE auth_sessions SET expires_at = NOW() - INTERVAL '1 second'")
            .execute(&pool)
            .await
            .unwrap();
        let reply = refresh(&app, &dbsc_id, Some(&proof(&key, &challenge, false))).await;
        assert_eq!(
            (reply.status, reply.json()),
            (StatusCode::OK, stop(&dbsc_id))
        );
        assert!(reply.headers.get("set-cookie").is_none());
        let reply = refresh(&app, &dbsc_id, None).await;
        assert_eq!(
            (reply.status, reply.json()),
            (StatusCode::OK, stop(&dbsc_id))
        );
    }

    #[sqlx::test(migrations = false)]
    #[ignore = "requires DATABASE_URL pointing to disposable Postgres"]
    async fn refresh_of_unbound_row_continue_false(pool: PgPool) {
        fixture(&pool).await;
        let state = app_state(pool.clone(), true);
        let app = router(state.clone());
        let (_, dbsc_id) = bind(&state, &app, &new_key()).await;
        // A row with a `dbsc_id` but no key cannot refresh (defensive branch).
        sqlx::query("UPDATE auth_sessions SET dbsc_public_key = NULL")
            .execute(&pool)
            .await
            .unwrap();
        let reply = refresh(&app, &dbsc_id, None).await;
        assert_eq!(
            (reply.status, reply.json()),
            (
                StatusCode::OK,
                json!({"session_identifier": dbsc_id, "continue": false})
            )
        );
    }

    #[sqlx::test(migrations = false)]
    #[ignore = "requires DATABASE_URL pointing to disposable Postgres"]
    async fn quoted_sf_string_headers_accepted(pool: PgPool) {
        fixture(&pool).await;
        let state = app_state(pool.clone(), true);
        let app = router(state.clone());
        let key = new_key();

        // Register and refresh with the W3C draft's sf-string quoting.
        let challenge = login(&state).await;
        let quoted = format!(r#""{}""#, proof(&key, &challenge, true));
        let reply = register(&app, RAW, Some(&quoted)).await;
        assert_eq!(reply.status, StatusCode::OK);
        let dbsc_id = reply.json()["session_identifier"]
            .as_str()
            .unwrap()
            .to_string();
        let quoted_id = format!(r#""{dbsc_id}""#);
        let challenge = refresh(&app, &quoted_id, None).await.challenge();
        let quoted = format!(r#""{}""#, proof(&key, &challenge, false));
        let reply = refresh(&app, &quoted_id, Some(&quoted)).await;
        assert_eq!(reply.status, StatusCode::OK);
        assert_eq!(reply.json(), session_instructions(&dbsc_id));
        let token = reply.session_cookie();
        assert_eq!(probe_cookie(&app, &token).await, StatusCode::OK);
    }

    #[sqlx::test(migrations = false)]
    #[ignore = "requires DATABASE_URL pointing to disposable Postgres"]
    async fn dbsc_off_or_insecure_stores_no_challenge(pool: PgPool) {
        fixture(&pool).await;
        // The kill switch, and local HTTP dev: no offer and no DB write.
        for (enabled, secure) in [(false, true), (true, false)] {
            let state = app_state(pool.clone(), enabled);
            assert!(
                registration_header(&state, RAW, secure, &HeaderMap::new())
                    .await
                    .is_none(),
                "enabled={enabled} secure={secure}"
            );
            let stored = dbsc_state(&pool).await;
            assert_eq!(stored.dbsc_challenge, None);
            assert_eq!(stored.dbsc_challenge_expires_at, None);
        }
    }

    #[sqlx::test(migrations = false)]
    #[ignore = "requires DATABASE_URL pointing to disposable Postgres"]
    async fn refresh_wrong_key_is_401(pool: PgPool) {
        fixture(&pool).await;
        let state = app_state(pool.clone(), true);
        let app = router(state.clone());
        let key = new_key();
        let (_, dbsc_id) = bind(&state, &app, &key).await;
        let challenge = refresh(&app, &dbsc_id, None).await.challenge();

        // Signed by another key.
        let reply = refresh(&app, &dbsc_id, Some(&proof(&new_key(), &challenge, false))).await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
        assert!(reply.headers.get("set-cookie").is_none());
        // A refresh proof must not carry a jwk, even the right one.
        let reply = refresh(&app, &dbsc_id, Some(&proof(&key, &challenge, true))).await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);

        // The rejections did not consume the challenge: the real key refreshes.
        let reply = refresh(&app, &dbsc_id, Some(&proof(&key, &challenge, false))).await;
        assert_eq!(reply.status, StatusCode::OK);
    }

    const NEW: &str = "new-session-id";

    /// A second login in the same browser: a fresh session `NEW` whose login
    /// request presents `presented` as its `caution_session` cookie.
    async fn relogin(state: &AppState, secure: bool, presented: &str) -> Option<HeaderValue> {
        db::create_auth_session(
            &state.db,
            NEW,
            b"cred",
            Uuid::new_v4(),
            OffsetDateTime::now_utc() + Duration::hours(24),
        )
        .await
        .unwrap();
        registration_header(state, NEW, secure, &cookie(presented)).await
    }

    #[sqlx::test(migrations = false)]
    #[ignore = "requires DATABASE_URL pointing to disposable Postgres"]
    async fn relogin_ends_stale_bound_session(pool: PgPool) {
        fixture(&pool).await;
        let state = app_state(pool.clone(), true);
        let app = router(state.clone());
        let (token, dbsc_id) = bind(&state, &app, &new_key()).await;

        assert!(relogin(&state, true, &token).await.is_some());
        // The old session is gone, so its DBSC session ends at the next refresh
        // instead of fighting the new one over the cookie.
        assert!(db::get_dbsc_session_by_session_id(&pool, RAW)
            .await
            .unwrap()
            .is_none());
        assert_eq!(probe_cookie(&app, &token).await, StatusCode::UNAUTHORIZED);
        let reply = refresh(&app, &dbsc_id, None).await;
        assert_eq!(reply.status, StatusCode::OK);
        assert_eq!(reply.json()["continue"], json!(false));
        // The new session was offered DBSC as usual.
        let new = db::get_dbsc_session_by_session_id(&pool, NEW)
            .await
            .unwrap()
            .unwrap();
        assert!(new.dbsc_challenge.is_some());
    }

    #[sqlx::test(migrations = false)]
    #[ignore = "requires DATABASE_URL pointing to disposable Postgres"]
    async fn relogin_spares_unbound_session(pool: PgPool) {
        fixture(&pool).await;
        let state = app_state(pool.clone(), true);
        let app = router(state.clone());

        // A non-DBSC browser logs in again with its raw cookie: unchanged.
        assert!(relogin(&state, true, RAW).await.is_some());
        assert_eq!(probe_cookie(&app, RAW).await, StatusCode::OK);
        assert_eq!(probe_header(&app, RAW).await, StatusCode::OK);
    }

    #[sqlx::test(migrations = false)]
    #[ignore = "requires DATABASE_URL pointing to disposable Postgres"]
    async fn relogin_with_dbsc_off_still_ends_stale_bound_session(pool: PgPool) {
        fixture(&pool).await;
        let state = app_state(pool.clone(), true);
        let app = router(state.clone());
        let (token, dbsc_id) = bind(&state, &app, &new_key()).await;

        // The kill switch flipped after binding: no offer, but the old bound
        // session still ends instead of fighting the new one over the cookie.
        let off = app_state(pool.clone(), false);
        assert!(relogin(&off, true, &token).await.is_none());
        assert!(db::get_dbsc_session_by_session_id(&pool, RAW)
            .await
            .unwrap()
            .is_none());
        let reply = refresh(&app, &dbsc_id, None).await;
        assert_eq!(reply.status, StatusCode::OK);
        assert_eq!(reply.json()["continue"], json!(false));
    }
}
